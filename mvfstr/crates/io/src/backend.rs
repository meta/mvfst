/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The backend traits and transmit capabilities.

use std::io;
use std::net::SocketAddr;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ClockEpoch;
use mvfstr_proto::ConnKey;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::TxReport;

/// What a socket can do, probed once at bind and fixed afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxCaps {
    /// The most segments one GSO send may carry; 1 without UDP GSO.
    pub max_segments: u16,
    /// The largest datagram the backend sends.
    pub max_datagram: u16,
    /// Whether the socket coalesces received datagrams (UDP GRO).
    pub gro: bool,
    /// Whether the socket reports the received ECN codepoint and can set it on sends.
    pub ecn: bool,
    /// Whether the socket reports the local destination address and can choose the source
    /// address per send (IP_PKTINFO, IPV6_RECVPKTINFO).
    pub pktinfo: bool,
    /// Whether, and how far ahead, the backend holds a datagram until its release.
    pub release: ReleaseSupport,
    /// The socket's send buffer (SO_SNDBUF) in bytes, as the kernel reports it, its bookkeeping
    /// included: every byte handed to the kernel and not yet sent is charged to it.
    pub send_buffer: usize,
}

/// How a backend honours [`Release::At`](mvfstr_proto::Release::At).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseSupport {
    /// Every datagram leaves when flushed, so connections do not build ahead: their build
    /// horizon is 0.
    None,
    /// The kernel holds each datagram until its release (SO_TXTIME), written in the clock of
    /// `epoch`, for releases up to `horizon` ahead.
    Kernel {
        /// The furthest ahead of now a release may be.
        horizon: Duration,
        /// The instant and the kernel clock's reading at it, sampled at bind.
        epoch: ClockEpoch,
    },
}

impl ReleaseSupport {
    /// Returns the furthest ahead of now a release may be; zero without release support.
    pub fn horizon(&self) -> Duration {
        match self {
            Self::None => Duration::ZERO,
            Self::Kernel { horizon, .. } => *horizon,
        }
    }

    /// Returns the clock that releases are written in; `None` without release support.
    pub fn epoch(&self) -> Option<ClockEpoch> {
        match self {
            Self::None => None,
            Self::Kernel { epoch, .. } => Some(*epoch),
        }
    }
}

/// The result of [`TxBackend::flush`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushOutcome {
    /// Datagrams handed to the kernel.
    pub datagrams: u32,
    /// Whether accepted runs are still queued behind an EAGAIN; the driver waits for
    /// [`TxBackend::poll_writable`].
    pub blocked: bool,
}

/// Counters of a backend's transmit half, from [`TxBackend::take_counters`]. Each event costs one
/// add. The only clock read is the one after a call that hands the kernel a message with a
/// release.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TxCounters {
    /// `sendmmsg` calls, those that failed included.
    pub calls: u64,
    /// Messages the kernel accepted: GSO sends and single datagrams.
    pub messages: u64,
    /// Calls whose accepted messages came from more than one connection.
    pub multi_connection_calls: u64,
    /// GSO sends the kernel refused with EIO or EINVAL, whose datagrams went again as single
    /// messages.
    pub gso_retries: u64,
    /// Sockets that stopped using GSO after refused GSO sends whose datagrams the kernel then took
    /// alone: at most one per socket.
    pub gso_disabled: u64,
    /// Accepted messages with a [`Release::At`](mvfstr_proto::Release::At), by how late they
    /// reached the kernel: the clock reading taken once after their call, less their release.
    /// Buckets, in µs, each upper edge inclusive: 0 or less (early), 10, 25, 50, 100, 250, 1,000,
    /// and over 1,000.
    pub release_lateness: [u64; 8],
    /// Calls by the messages the kernel accepted: 1, 2-3, 4-7, 8-15, 16-31, 32-63, 64-127, and
    /// 128 or more. Only calls that accepted a message are counted.
    pub messages_per_call: [u64; 8],
    /// Calls whose first message the kernel refused with ENOBUFS, which on a socket with
    /// IP_RECVERR is how a qdisc drop shows, and otherwise a failed allocation; that message's
    /// datagrams are reported dropped.
    pub tx_enobufs: u64,
    /// Calls that returned fewer messages than they were given, because a later message failed and
    /// `sendmmsg` lost its error; the backend sends again from the failed message.
    pub tx_partial: u64,
}

/// The transmit half of a backend.
///
/// A backend flushes on its own when its slot pool or system-call vector fills, so a refused
/// segment means only an EAGAIN backlog or a connection at its limit of built but unsent bytes,
/// or an exhausted urgent quota or pool. A connection refused at its limit may try again once a
/// flush has sent its runs.
pub trait TxBackend {
    /// The backend's view for one connection.
    type Sink<'a>: SegmentSink
    where
        Self: 'a;

    /// Returns the socket's capabilities.
    fn caps(&self) -> &TxCaps;

    /// Lends slots to the connection stored under `conn`.
    fn sink(&mut self, conn: ConnKey) -> Self::Sink<'_>;

    /// Sends every queued run it can.
    fn flush(&mut self, now: Instant) -> FlushOutcome;

    /// Returns the datagrams queued and not yet handed to the kernel, each segment of a GSO send
    /// counted and those held behind an EAGAIN included, saturating at `u32::MAX`.
    fn queued_datagrams(&self) -> u32;

    /// Returns `Ready` once the socket is writable again after an EAGAIN backlog.
    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()>;

    /// Hands every pending report to `f`, with the connection that built the datagrams.
    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport));

    /// Returns the counters since the last call and starts them again from zero. A backend
    /// that does not count returns zeros.
    fn take_counters(&mut self) -> TxCounters {
        TxCounters::default()
    }
}

/// The receive half of a backend.
pub trait RxBackend {
    /// Receives a batch. `Ready(Ok(n))` makes `n` buffers available through
    /// [`buffers`](Self::buffers) until the next call; `Pending` registers `cx` for readability.
    /// A batch that fills fewer buffers than the backend has ends at the socket's last datagram or
    /// at an ICMP error, and the backend may then stop reading: the next call is `Pending` without
    /// a system call, until the socket is readable again.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>>;

    /// Makes one receive call now, whatever readiness the backend has cached, and leaves that
    /// cache as it is. Call it only after [`poll_recv`](Self::poll_recv) returned `Pending` in the
    /// same task poll, which registered `cx`. `Ready(Ok(n))` makes `n` buffers available, possibly
    /// 0 when every datagram was discarded; `Pending` means that the socket was empty or the
    /// task's budget is spent, and the registration stands. It never wakes a task. Backends
    /// without a readiness cache keep this default, which is always `Pending`.
    fn poll_recv_now(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let _ = cx;
        Poll::Pending
    }

    /// Returns whether the last receive call filled every buffer. The default is `false`.
    fn last_full(&self) -> bool {
        false
    }

    /// Returns the buffers of the last batch with their metadata. A buffer holds one datagram or a
    /// GRO run of datagrams of `meta.stride` bytes, the last possibly shorter.
    fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])>;
}

/// A backend on one UDP socket, as the driver opens it: on the server socket, and by default on a
/// connected socket per client connection. The driver is built for one backend type and
/// monomorphized for it.
pub trait Backend: TxBackend + RxBackend + Sized + 'static {
    /// Socket settings for every backend the driver opens, such as buffer sizes.
    type Options: Default;

    /// Opens a backend on a socket bound to `addr` with SO_REUSEPORT, so each worker binds its
    /// own. Runs on the worker's thread.
    fn bind(addr: SocketAddr, options: &Self::Options) -> io::Result<Self>;

    /// Opens a backend on a socket connected to `remote`, for one client connection. Runs on the
    /// worker's thread.
    fn connect(remote: SocketAddr, options: &Self::Options) -> io::Result<Self>;

    /// Returns the local address the socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
