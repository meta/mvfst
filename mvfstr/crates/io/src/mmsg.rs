/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `MmsgBackend`: the `sendmmsg` and `recvmmsg` backend on one UDP socket.

use std::future::Future;
use std::future::poll_fn;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::pin::pin;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ConnKey;
use mvfstr_proto::RxMeta;
use mvfstr_proto::TxReport;
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::task::coop;

use crate::Backend;
use crate::FlushOutcome;
use crate::RxBackend;
use crate::SocketOptions;
use crate::TxBackend;
use crate::TxCaps;
use crate::TxCounters;
use crate::rx::Rx;
use crate::socket;
use crate::tx::MmsgSink;
use crate::tx::Tx;
use crate::tx::TxConfig;

/// The longest [`MmsgOptions::txtime_horizon`].
const MAX_TXTIME_HORIZON: Duration = Duration::from_secs(1);

/// Settings for every [`MmsgBackend`] a driver opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmsgOptions {
    /// Socket settings.
    pub socket: SocketOptions,
    /// The largest datagram the backend sends, and the size of each transmit slot. Default
    /// 1,500 bytes, which holds mvfstr's default 1,452-byte packets.
    pub max_datagram: u16,
    /// Transmit slots in the pool. Default 512.
    pub tx_slots: u32,
    /// Messages per `sendmmsg` call; the backend flushes on its own when this many runs are
    /// queued. 1 to 1,024. Default 64.
    pub tx_batch: u16,
    /// Slots only urgent segments may take. The pool keeps this many free for the urgent segments
    /// of every connection; the reserve is shared, so one connection can use it up. While data is
    /// refused to a connection, after an EAGAIN or at `max_unsent`, it may still take this many
    /// urgent slots; that caps its share but does not reserve slots for it. Default 4.
    pub urgent_slots: u16,
    /// The most bytes one connection may have built but not yet handed to the kernel. At the limit
    /// the connection's data segments are refused until a flush sends its runs, and its urgent
    /// segments draw on its urgent quota. At least `max_datagram`. Default 128 KiB.
    pub max_unsent: u32,
    /// Buffers per `recvmmsg` call. Default 32.
    pub rx_batch: u16,
    /// Bytes per receive buffer. Datagrams that do not fit are discarded; 65,536 holds any
    /// datagram or GRO run. Default 65,536.
    pub rx_buffer: u32,
    /// Kernel release: the socket gets SO_TXTIME on CLOCK_MONOTONIC, opening the backend fails if
    /// the kernel refuses it, every run with a [`Release::At`](mvfstr_proto::Release::At) carries
    /// its release as an SCM_TXTIME stamp, and the backend reports
    /// [`ReleaseSupport::Kernel`](crate::ReleaseSupport::Kernel). Sockets opened by
    /// [`Backend::connect`] never set it.
    ///
    /// The operator must make sure that an fq qdisc honours the stamps on the sending device: the
    /// setsockopt also succeeds where the qdisc ignores them, and built-ahead datagrams then leave
    /// at once. The backend does not set IP_RECVERR, so a datagram the qdisc drops, beyond its
    /// horizon or a flow's packet limit, is reported flushed; loss detection recovers it, and the
    /// controller counts it as congestion rather than as a local drop. Production use needs
    /// IP_RECVERR and an error-queue drain. Every byte waiting in fq stays charged to the socket's
    /// send buffer, which must hold the connections' built-ahead bytes. Default off.
    pub txtime: bool,
    /// With `txtime`, the furthest ahead of now a release may be, which bounds every
    /// connection's build horizon; at most 1 s, far inside fq's 10 s drop horizon. Default
    /// 100 ms.
    pub txtime_horizon: Duration,
}

impl Default for MmsgOptions {
    fn default() -> Self {
        Self {
            socket: SocketOptions::default(),
            max_datagram: 1500,
            tx_slots: 512,
            tx_batch: 64,
            urgent_slots: 4,
            max_unsent: 128 * 1024,
            rx_batch: 32,
            rx_buffer: 65_536,
            txtime: false,
            txtime_horizon: Duration::from_millis(100),
        }
    }
}

impl MmsgOptions {
    pub(crate) fn validate(&self) -> io::Result<()> {
        let problem = if !(1..=65_527).contains(&self.max_datagram) {
            "max_datagram must be 1 to 65,527 bytes"
        } else if self.tx_slots <= u32::from(self.urgent_slots) {
            "tx_slots must exceed urgent_slots"
        } else if self.max_unsent < u32::from(self.max_datagram) {
            "max_unsent must be at least max_datagram"
        } else if !(1..=1024).contains(&self.tx_batch) {
            // UIO_MAXIOV caps the messages of one sendmmsg call.
            "tx_batch must be 1 to 1,024"
        } else if self.rx_batch == 0 || self.rx_buffer == 0 {
            "rx_batch and rx_buffer must be positive"
        } else if self.txtime_horizon > MAX_TXTIME_HORIZON {
            // fq drops a packet stamped beyond its own horizon, 10 s by default.
            "txtime_horizon must be at most 1 s"
        } else {
            return Ok(());
        };
        Err(io::Error::new(io::ErrorKind::InvalidInput, problem))
    }
}

/// The `sendmmsg`/`recvmmsg` backend on one UDP socket, with GSO and GRO.
///
/// Without [`MmsgOptions::txtime`] it does not support timed release: every datagram leaves when
/// flushed, so connections do not build ahead. With it, the kernel holds each run until its
/// release. Readiness comes from tokio's `AsyncFd`, so a backend must be opened on a thread running
/// a tokio runtime with I/O enabled, such as a Roxygen worker.
pub struct MmsgBackend {
    io: AsyncFd<Socket>,
    tx: Tx,
    rx: Rx,
}

impl MmsgBackend {
    /// Opens a backend on an existing socket, probing its capabilities. Like [`socket::open`],
    /// it makes the socket non-blocking, forbids fragmentation, zeroes its TOS and turns on the
    /// receive control messages the backend parses. A datagram whose control data does not fit
    /// the backend's buffer is discarded, so the socket must not have other receive control
    /// messages turned on.
    ///
    /// Fails with `InvalidInput` when `options` are invalid, and with an error when the thread is
    /// not running a tokio runtime. Panics if the thread's runtime does not have I/O enabled.
    pub fn from_socket(socket: Socket, options: &MmsgOptions) -> io::Result<Self> {
        options.validate()?;
        // Registering with the reactor panics without a runtime, so return an error instead. A
        // runtime without I/O enabled still panics, and tokio does not offer a way to test for it.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "MmsgBackend needs a tokio runtime with I/O enabled on this thread",
            ));
        }
        let (tx, rx) = ready(&socket, options)?;
        // SAFETY: the socket owns its descriptor, which stays open until the `AsyncFd` drops it,
        // and `as_raw_fd` always returns that descriptor.
        let io = unsafe { AsyncFd::register(socket) }.map_err(io::Error::from)?;
        Ok(Self { io, tx, rx })
    }

    /// Returns the local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io
            .get_ref()
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "not an IP socket"))
    }
}

impl TxBackend for MmsgBackend {
    type Sink<'a> = MmsgSink<'a>;

    fn caps(&self) -> &TxCaps {
        self.tx.caps()
    }

    fn sink(&mut self, conn: ConnKey) -> MmsgSink<'_> {
        MmsgSink::new(&mut self.tx, self.io.get_ref().as_fd(), conn)
    }

    fn flush(&mut self, _now: Instant) -> FlushOutcome {
        let datagrams = self.tx.send(self.io.get_ref().as_fd());
        FlushOutcome {
            datagrams,
            blocked: self.tx.blocked(),
        }
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if !self.tx.blocked() {
            return Poll::Ready(());
        }
        let tx = &mut self.tx;
        // An error here means the reactor is gone; it surfaces at the driver's next flush.
        let _ = ready!(poll_io(&self.io, cx, Interest::WRITABLE, |fd| {
            tx.send(fd);
            if tx.blocked() {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(((), false))
            }
        }));
        Poll::Ready(())
    }

    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport)) {
        self.tx.drain_reports(f);
    }

    fn take_counters(&mut self) -> TxCounters {
        self.tx.take_counters()
    }
}

impl RxBackend for MmsgBackend {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        // A batch that fills every buffer reads on, also when every datagram in it was discarded;
        // a shorter one ends the reads. Each batch spends budget, so a flood of datagrams that
        // are all discarded still yields.
        let rx = &mut self.rx;
        loop {
            let n = ready!(poll_io(&self.io, cx, Interest::READABLE, |fd| {
                let n = rx.recv(fd.as_raw_fd())?;
                Ok((n, rx.drained()))
            }))?;
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
        }
    }

    fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])> {
        self.rx.buffers()
    }
}

/// Runs `op` when the socket is ready for `interest`, with the coop pattern of Roxygen's TCP reads:
/// readiness is polled outside tokio's coop budget so it is not charged twice, a task already out
/// of budget yields first, and each successful call spends one unit, so a socket that stays ready
/// cannot starve the worker's other tasks. `op` returns its result and whether it left the socket
/// not ready, as a receive that emptied it does, or `WouldBlock` when the socket was not ready
/// after all. Both clear the readiness, so the next call waits for the next edge without trying
/// the socket; tokio clears only the readiness this call observed, so an edge during `op` is kept.
fn poll_io<R>(
    io: &AsyncFd<Socket>,
    cx: &mut Context<'_>,
    interest: Interest,
    mut op: impl FnMut(BorrowedFd<'_>) -> io::Result<(R, bool)>,
) -> Poll<io::Result<R>> {
    loop {
        if !coop::has_budget_remaining() {
            drop(ready!(coop::poll_proceed(cx)));
        }
        let mut guard = ready!(
            pin!(coop::unconstrained(poll_fn(|cx| {
                if interest.is_writable() {
                    io.poll_write_ready(cx)
                } else {
                    io.poll_read_ready(cx)
                }
            })))
            .poll(cx)
        )?;
        if let Ok(result) = guard.try_io(|io| op(io.get_ref().as_fd())) {
            let result = result.map(|(value, drained)| {
                if drained {
                    guard.clear_ready();
                }
                value
            });
            if result.is_ok()
                && let Poll::Ready(spent) = coop::poll_proceed(cx)
            {
                spent.made_progress();
            }
            return Poll::Ready(result);
        }
    }
}

/// Readies a socket for a backend opened with valid `options`, as
/// [`MmsgBackend::from_socket`] describes, and builds the backend's transmit and receive halves
/// for its capabilities.
pub(crate) fn ready(socket: &Socket, options: &MmsgOptions) -> io::Result<(Tx, Rx)> {
    socket.set_nonblocking(true)?;
    socket::prepare(socket, options.socket.gro);
    let mut caps = socket::probe(socket, options.max_datagram);
    if options.txtime {
        caps.release = socket::kernel_release(socket, options.txtime_horizon)?;
    }
    let config = TxConfig {
        slots: options.tx_slots,
        urgent_slots: options.urgent_slots,
        max_unsent: options.max_unsent,
        batch: usize::from(options.tx_batch),
        connected: socket.peer_addr().is_ok(),
        ipv6: socket.local_addr()?.is_ipv6(),
    };
    Ok((
        Tx::new(caps, config),
        Rx::new(options.rx_batch as usize, options.rx_buffer as usize),
    ))
}

/// Opens the socket of a client connection to `remote`, on an ephemeral port, and returns it with
/// the options to open its backend with.
pub(crate) fn open_connected(
    remote: SocketAddr,
    options: &MmsgOptions,
) -> io::Result<(Socket, MmsgOptions)> {
    let local = match remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    // An ephemeral port is never shared.
    let socket_options = SocketOptions {
        reuse_port: false,
        ..options.socket.clone()
    };
    // Kernel release is the server socket's: a client connection's endpoint cannot give it a
    // horizon, so its runs are never stamped.
    let options = MmsgOptions {
        txtime: false,
        ..options.clone()
    };
    Ok((socket::open(local, Some(remote), &socket_options)?, options))
}

impl Backend for MmsgBackend {
    type Options = MmsgOptions;

    fn bind(addr: SocketAddr, options: &MmsgOptions) -> io::Result<Self> {
        Self::from_socket(socket::open(addr, None, &options.socket)?, options)
    }

    fn connect(remote: SocketAddr, options: &MmsgOptions) -> io::Result<Self> {
        let (socket, options) = open_connected(remote, options)?;
        Self::from_socket(socket, &options)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        MmsgBackend::local_addr(self)
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::ops::Range;

    use tokio::runtime::Runtime;

    use super::*;

    /// Fails a test that would otherwise hang; passing runs never reach it.
    const HANG_GUARD: Duration = Duration::from_secs(20);

    fn runtime() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
    }

    /// Binds a backend to an IPv4 loopback port, with `rx_batch` receive buffers.
    fn bind(rx_batch: u16) -> MmsgBackend {
        let options = MmsgOptions {
            rx_batch,
            ..MmsgOptions::default()
        };
        MmsgBackend::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &options).unwrap()
    }

    /// Sends one datagram per id in `ids` to `backend`, each of its own length, and returns them.
    fn send(sender: &UdpSocket, backend: &MmsgBackend, ids: Range<u8>) -> Vec<Vec<u8>> {
        let to = backend.local_addr().unwrap();
        ids.map(|id| {
            let datagram = vec![id; 10 + usize::from(id)];
            sender.send_to(&datagram, to).unwrap();
            datagram
        })
        .collect()
    }

    /// Sends `count` empty datagrams to `backend`.
    fn send_empty(sender: &UdpSocket, backend: &MmsgBackend, count: usize) {
        let to = backend.local_addr().unwrap();
        for _ in 0..count {
            sender.send_to(&[], to).unwrap();
        }
    }

    /// Runs one task that polls `backend` until it has a batch, calling `on_pending` after each
    /// pending poll. Returns the batch's datagrams and how many times the task was polled.
    fn recv(
        rt: &Runtime,
        backend: &mut MmsgBackend,
        mut on_pending: impl FnMut(&MmsgBackend),
    ) -> (Vec<Vec<u8>>, usize) {
        let mut polls = 0;
        let task = poll_fn(|cx| {
            polls += 1;
            let poll = backend.poll_recv(cx);
            if poll.is_pending() {
                on_pending(backend);
            }
            poll
        });
        let n = rt
            .block_on(tokio::time::timeout(HANG_GUARD, task))
            .expect("hang guard")
            .unwrap();
        let got: Vec<Vec<u8>> = backend.buffers().map(|(_, data)| data.to_vec()).collect();
        assert_eq!(got.len(), n);
        (got, polls)
    }

    /// Polls `backend` once in a task of its own, and returns whether the poll was pending.
    fn pending(rt: &Runtime, backend: &mut MmsgBackend) -> bool {
        rt.block_on(poll_fn(|cx| {
            Poll::Ready(backend.poll_recv(cx).is_pending())
        }))
    }

    #[test]
    fn a_short_batch_clears_readiness_so_the_next_poll_is_pending_without_a_receive() {
        let rt = runtime();
        let _guard = rt.enter();
        let mut backend = bind(32);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sent = send(&sender, &backend, 0..3);
        assert_eq!(recv(&rt, &mut backend, |_| {}).0, sent);
        assert!(pending(&rt, &mut backend));
        assert_eq!(
            backend.rx.calls, 1,
            "3 datagrams in 32 buffers emptied the socket, so the poll after them reads nothing"
        );
    }

    #[test]
    fn datagrams_that_arrive_after_a_short_batch_wake_the_task_and_are_delivered() {
        let rt = runtime();
        let _guard = rt.enter();
        let mut backend = bind(32);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sent = send(&sender, &backend, 0..3);
        assert_eq!(recv(&rt, &mut backend, |_| {}).0, sent);

        // Datagrams that arrive before the next poll wait for the reactor to report the socket.
        let late = send(&sender, &backend, 3..5);
        let (got, polls) = recv(&rt, &mut backend, |_| {});
        assert_eq!(got, late);
        assert_eq!(
            polls, 2,
            "the poll after the short batch is pending until the task is woken"
        );

        // So do datagrams that arrive after a pending poll, which registered the task.
        let mut later = Vec::new();
        let (got, polls) = recv(&rt, &mut backend, |backend| {
            if later.is_empty() {
                later = send(&sender, backend, 5..7);
            }
        });
        assert_eq!(got, later);
        assert_eq!(polls, 2);
        assert_eq!(
            backend.rx.calls, 3,
            "one receive per batch, and none that found the socket empty"
        );
    }

    #[test]
    fn a_full_batch_reads_on_without_a_wake_and_the_short_batch_after_it_ends_the_reads() {
        let rt = runtime();
        let _guard = rt.enter();
        let mut backend = bind(4);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sent = send(&sender, &backend, 0..6);
        assert_eq!(recv(&rt, &mut backend, |_| {}).0, sent[..4]);
        let (got, polls) = recv(&rt, &mut backend, |_| {});
        assert_eq!(got, sent[4..]);
        assert_eq!(
            polls, 1,
            "a full batch leaves the socket readable, so the poll reads on"
        );
        assert!(pending(&rt, &mut backend));
        assert_eq!(backend.rx.calls, 2, "the batch of 2 was short");
    }

    #[test]
    fn a_full_batch_of_only_discarded_datagrams_reads_on_and_a_short_one_ends_the_reads() {
        let rt = runtime();
        let _guard = rt.enter();
        let mut backend = bind(4);
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        send_empty(&sender, &backend, 4);
        let sent = send(&sender, &backend, 7..8);
        assert_eq!(
            recv(&rt, &mut backend, |_| {}).0,
            sent,
            "4 empty datagrams fill the batch, so the same poll reads on"
        );
        assert_eq!(backend.rx.calls, 2);
        assert!(pending(&rt, &mut backend));
        assert_eq!(backend.rx.calls, 2, "the batch of 1 was short");

        // A short batch whose every datagram is discarded also ends the reads: the poll that
        // takes it is pending without another receive. A datagram sent after that ends the task.
        send_empty(&sender, &backend, 2);
        let mut last = Vec::new();
        let (got, _) = recv(&rt, &mut backend, |backend| {
            if last.is_empty() && backend.rx.calls > 2 {
                last = send(&sender, backend, 8..9);
            }
        });
        assert_eq!(got, last);
        assert_eq!(
            backend.rx.calls, 4,
            "one receive for the empty datagrams, one for the last"
        );
    }
}
