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
use std::time::Instant;

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

    /// Returns `Ready` once the socket is writable again after an EAGAIN backlog.
    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()>;

    /// Hands every pending report to `f`, with the connection that built the datagrams.
    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport));
}

/// The receive half of a backend.
pub trait RxBackend {
    /// Receives a batch. `Ready(Ok(n))` makes `n` buffers available through
    /// [`buffers`](Self::buffers) until the next call; `Pending` registers `cx` for readability.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>>;

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
