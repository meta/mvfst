/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The server: once a connection is up it opens `--num_streams` unidirectional streams and
//! writes to each forever, or `--bytes_per_stream` bytes and then a FIN and a replacement
//! stream, as mvfst's tperf server does.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use mvfstr_driver::Conn;
use mvfstr_driver::ConnHandle;
use mvfstr_driver::ConnInfo;
use mvfstr_driver::EndpointHandle;
use mvfstr_driver::QuicApplication;
use mvfstr_driver::QuicSession;
use mvfstr_driver::Refusal;
use mvfstr_driver::SendSink;
use mvfstr_io::Backend;
use mvfstr_proto::Bytes;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::Dir;
use mvfstr_proto::SendOrder;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TlsConnId;
use mvfstr_proto::TlsHost;
use mvfstr_proto::TlsPoll;
use mvfstr_tls::testing::RustlsHost;

use crate::flags::Flags;

/// The wire order of every stream: one incremental bucket at the default urgency, so streams
/// share the connection round-robin, as mvfst's default priority does.
const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: true,
    order: 0,
};

/// A connection that closed, as the server reports it under `--stats`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Closed {
    /// The connection's counters.
    pub(crate) stats: ConnStats,
    /// The transmit attempts the server socket has refused so far, over every connection.
    pub(crate) socket_stops: u64,
    /// The pacing wakes the server's transmit phases have taken so far, over every connection.
    pub(crate) phase_pacing_wakes: u64,
}

/// The ID of a session's connection to its own TLS host.
const HOSTED: TlsConnId = TlsConnId(0);

/// How long a session whose handshake runs on its own TLS host waits before it polls the host
/// again. The driver does not report when the client's next flight arrives, and polling on every
/// driver turn would keep the worker busy until the client answers or times out.
const TLS_POLL: Duration = Duration::from_millis(1);

/// The settings every connection of a server shares.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    num_streams: u32,
    bytes_per_stream: u64,
    /// One block of `--block_size` zeros, which every push shares rather than copies.
    block: Bytes,
    stats: bool,
    /// Where closed connections go under `--stats`.
    closed: mpsc::Sender<Closed>,
    /// The driver's work budget per poll, from `--work_budget_us`.
    pub(crate) work_budget: Option<Duration>,
    /// The rustls config of each connection's TLS host under `--tls_backend=external`.
    host_tls: Option<Arc<rustls::ServerConfig>>,
}

impl Settings {
    /// Creates the settings from `flags`, with closed connections reported to `closed` and, under
    /// `--tls_backend=external`, the handshakes run on TLS hosts with `host_tls`.
    pub(crate) fn new(
        flags: &Flags,
        closed: mpsc::Sender<Closed>,
        host_tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            num_streams: flags.num_streams,
            bytes_per_stream: flags.bytes_per_stream,
            block: Bytes::from(vec![0; flags.block_size]),
            stats: flags.stats,
            closed,
            work_budget: (flags.work_budget_us > 0)
                .then(|| Duration::from_micros(u64::from(flags.work_budget_us))),
            host_tls,
        }
    }
}

/// The server's driver on backend `B`, set once it runs, which keeps the counters of the server
/// socket.
pub(crate) type Driver<B> = Rc<OnceCell<EndpointHandle<ServerApp<B>, B>>>;

/// The server application: it takes every connection.
#[derive(Debug)]
pub(crate) struct ServerApp<B: Backend> {
    settings: Settings,
    driver: Driver<B>,
}

impl<B: Backend> ServerApp<B> {
    /// Creates an application whose connections run with `settings` on `driver`.
    pub(crate) fn new(settings: Settings, driver: Driver<B>) -> Self {
        Self { settings, driver }
    }
}

impl<B: Backend> QuicApplication for ServerApp<B> {
    type Session = ServerSession<B>;

    fn accept(
        &mut self,
        _info: &ConnInfo,
        _options: &mut ConnOptions,
    ) -> Result<ServerSession<B>, Refusal> {
        Ok(ServerSession {
            tls_host: self.settings.host_tls.clone().map(|tls| Hosted {
                host: RustlsHost::server(tls),
                poll_at: None,
            }),
            settings: self.settings.clone(),
            driver: Rc::clone(&self.driver),
            producers: HashMap::new(),
            to_open: 0,
            handle: None,
        })
    }
}

/// One connection of the server.
#[derive(Debug)]
pub(crate) struct ServerSession<B: Backend> {
    settings: Settings,
    driver: Driver<B>,
    producers: HashMap<StreamId, Producer>,
    /// Streams not opened yet, for want of stream credit or of a `Conn` to open them on.
    to_open: u32,
    /// The handle that wakes the session to replace a finished stream, set once connected.
    handle: Option<ConnHandle>,
    /// Under `--tls_backend=external`, the TLS host of the connection's handshake, until the
    /// handshake completes or the connection closes.
    tls_host: Option<Hosted>,
}

/// A connection's TLS host, rustls behind the External interface, and when the session polls
/// it next.
struct Hosted {
    host: RustlsHost,
    poll_at: Option<Instant>,
}

impl fmt::Debug for Hosted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hosted")
            .field("poll_at", &self.poll_at)
            .finish_non_exhaustive()
    }
}

impl<B: Backend> ServerSession<B> {
    /// Hands the connection's TLS inputs to its host and delivers each step, or cancels the
    /// host's work once the connection has closed.
    fn run_tls(&mut self, conn: &mut Conn<'_>) {
        let Some(Hosted { host, .. }) = &mut self.tls_host else {
            return;
        };
        if conn.take_tls_cancel() {
            host.cancel(HOSTED);
            return;
        }
        let now = conn.now();
        while let Some(input) = conn.tls_input() {
            // The rustls host answers every input at once.
            let TlsPoll::Ready(step) = host.handle(HOSTED, input) else {
                return;
            };
            if conn.tls_deliver(now, step).is_err() {
                return;
            }
        }
    }

    /// Opens the pending streams while the client's stream limit allows.
    fn open_streams(&mut self, conn: &mut Conn<'_>) {
        while self.to_open > 0 {
            let Ok(id) = conn.open_stream(Dir::Uni, ORDER) else {
                return;
            };
            self.to_open -= 1;
            self.producers
                .insert(id, Producer::new(self.settings.bytes_per_stream));
            conn.stream_waker(id).wake();
        }
    }
}

impl<B: Backend> QuicSession for ServerSession<B> {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        match event {
            ConnEvent::Connected => {
                // The step that completed the handshake was followed by the ticket and `Finish`.
                self.tls_host = None;
                self.handle = Some(conn.handle());
                self.to_open = self.settings.num_streams;
                self.open_streams(conn);
            }
            ConnEvent::StreamsAvailable { dir: Dir::Uni } => self.open_streams(conn),
            ConnEvent::Closed { .. } => {
                self.run_tls(conn);
                self.tls_host = None;
                if self.settings.stats {
                    let endpoint = self.driver.get().map(|driver| driver.stats());
                    let _ = self.settings.closed.send(Closed {
                        stats: conn.stats(),
                        socket_stops: endpoint.as_ref().map_or(0, |stats| stats.socket_stops),
                        phase_pacing_wakes: endpoint.map_or(0, |stats| stats.phase_pacing_wakes),
                    });
                }
            }
            _ => {}
        }
    }

    fn on_stream(&mut self, _conn: &mut Conn<'_>, _id: StreamId, _ready: StreamReady) {}

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        let Some(producer) = self.producers.get_mut(&id) else {
            return Poll::Pending;
        };
        let len = producer.next_chunk(sink.allowance(), self.settings.block.len());
        if len == 0 {
            // The producer always has data: it is ready again as soon as the stream has room.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if sink.push(self.settings.block.slice(..len)).is_err() {
            self.producers.remove(&id);
            return Poll::Pending;
        }
        producer.pushed(len);
        if producer.is_done() {
            let _ = sink.finish();
            self.producers.remove(&id);
            self.to_open += 1;
            if let Some(handle) = &self.handle {
                let _ = handle.wake();
            }
        }
        Poll::Ready(())
    }

    fn poll_session(&mut self, _cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        self.run_tls(conn);
        if let Some(hosted) = &mut self.tls_host {
            hosted.poll_at = Some(conn.now() + TLS_POLL);
        }
        self.open_streams(conn);
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.tls_host.as_ref()?.poll_at
    }
}

/// The bytes one stream has sent, and its byte limit if it has one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Producer {
    sent: u64,
    limit: Option<u64>,
}

impl Producer {
    /// Creates a producer that sends `bytes_per_stream` bytes, or sends forever if that is 0.
    pub(crate) fn new(bytes_per_stream: u64) -> Self {
        Self {
            sent: 0,
            limit: (bytes_per_stream > 0).then_some(bytes_per_stream),
        }
    }

    /// Returns the bytes to push now: at most the allowance, one block and the rest of the limit.
    pub(crate) fn next_chunk(&self, allowance: usize, block_size: usize) -> usize {
        let owed = self.limit.map_or(usize::MAX, |limit| {
            usize::try_from(limit - self.sent).unwrap_or(usize::MAX)
        });
        allowance.min(block_size).min(owed)
    }

    /// Records that `len` bytes were pushed.
    pub(crate) fn pushed(&mut self, len: usize) {
        self.sent += len as u64;
    }

    /// Returns whether the stream has sent its whole limit, so it gets its FIN.
    pub(crate) fn is_done(&self) -> bool {
        self.limit.is_some_and(|limit| self.sent >= limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_work_budget_flag_gives_the_driver_a_slice_per_poll_unless_zero() {
        let (closed, _) = mpsc::channel();
        let flags = Flags::parse(["--work_budget_us=250".to_owned()]).unwrap();
        assert_eq!(
            Settings::new(&flags, closed.clone(), None).work_budget,
            Some(Duration::from_micros(250))
        );
        assert_eq!(
            Settings::new(&Flags::default(), closed, None).work_budget,
            None
        );
    }

    #[test]
    fn a_stream_sends_blocks_within_its_allowance_up_to_its_byte_limit() {
        let endless = Producer::new(0);
        assert_eq!(endless.next_chunk(65_536, 1 << 20), 65_536);
        assert_eq!(
            endless.next_chunk(3 << 20, 1 << 20),
            1 << 20,
            "one block at most"
        );
        assert!(!endless.is_done());

        let mut limited = Producer::new(100_000);
        assert_eq!(limited.next_chunk(65_536, 1 << 20), 65_536);
        limited.pushed(65_536);
        assert!(!limited.is_done());
        assert_eq!(limited.next_chunk(65_536, 1 << 20), 100_000 - 65_536);
        limited.pushed(100_000 - 65_536);
        assert!(limited.is_done());
        assert_eq!(limited.next_chunk(65_536, 1 << 20), 0);
    }
}
