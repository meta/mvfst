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
use crate::rx::Rx;
use crate::socket;
use crate::tx::MmsgSink;
use crate::tx::Tx;
use crate::tx::TxConfig;

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
        }
    }
}

impl MmsgOptions {
    fn validate(&self) -> io::Result<()> {
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
        } else {
            return Ok(());
        };
        Err(io::Error::new(io::ErrorKind::InvalidInput, problem))
    }
}

/// The `sendmmsg`/`recvmmsg` backend on one UDP socket, with GSO and GRO.
///
/// The backend does not support timed release: a flush passes queued datagrams to the kernel at
/// once, until the socket would block. Readiness comes from tokio's `AsyncFd`, so a backend must be
/// opened on a thread running a tokio runtime with I/O enabled, such as a Roxygen worker.
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
        socket.set_nonblocking(true)?;
        socket::prepare(&socket, options.socket.gro);
        let caps = socket::probe(&socket, options.max_datagram);
        let local = socket.local_addr()?;
        let config = TxConfig {
            slots: options.tx_slots,
            urgent_slots: options.urgent_slots,
            max_unsent: options.max_unsent,
            batch: usize::from(options.tx_batch),
            connected: socket.peer_addr().is_ok(),
            ipv6: local.is_ipv6(),
        };
        // SAFETY: the socket owns its descriptor, which stays open until the `AsyncFd` drops it,
        // and `as_raw_fd` always returns that descriptor.
        let io = unsafe { AsyncFd::register(socket) }.map_err(io::Error::from)?;
        Ok(Self {
            io,
            tx: Tx::new(caps, config),
            rx: Rx::new(options.rx_batch as usize, options.rx_buffer as usize),
        })
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
                Ok(())
            }
        }));
        Poll::Ready(())
    }

    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport)) {
        self.tx.drain_reports(f);
    }
}

impl RxBackend for MmsgBackend {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        // When every datagram of a batch was discarded, read on, since only EAGAIN from the kernel
        // means that the socket is empty. Each batch spends budget, so a flood of datagrams that
        // are all discarded still yields.
        loop {
            let n = ready!(poll_io(&self.io, cx, Interest::READABLE, |fd| {
                self.rx.recv(fd.as_raw_fd())
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
/// cannot starve the worker's other tasks. `op` returns `WouldBlock` when the socket was not ready
/// after all, which clears the readiness and waits for the next edge.
fn poll_io<R>(
    io: &AsyncFd<Socket>,
    cx: &mut Context<'_>,
    interest: Interest,
    mut op: impl FnMut(BorrowedFd<'_>) -> io::Result<R>,
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
            if result.is_ok()
                && let Poll::Ready(spent) = coop::poll_proceed(cx)
            {
                spent.made_progress();
            }
            return Poll::Ready(result);
        }
    }
}

impl Backend for MmsgBackend {
    type Options = MmsgOptions;

    fn bind(addr: SocketAddr, options: &MmsgOptions) -> io::Result<Self> {
        Self::from_socket(socket::open(addr, None, &options.socket)?, options)
    }

    fn connect(remote: SocketAddr, options: &MmsgOptions) -> io::Result<Self> {
        let local = match remote {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        // An ephemeral port is never shared.
        let socket_options = SocketOptions {
            reuse_port: false,
            ..options.socket.clone()
        };
        Self::from_socket(socket::open(local, Some(remote), &socket_options)?, options)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        MmsgBackend::local_addr(self)
    }
}
