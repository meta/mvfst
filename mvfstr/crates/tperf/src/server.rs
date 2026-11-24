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
use std::rc::Rc;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;

use mvfstr_driver::Conn;
use mvfstr_driver::ConnHandle;
use mvfstr_driver::ConnInfo;
use mvfstr_driver::EndpointHandle;
use mvfstr_driver::QuicApplication;
use mvfstr_driver::QuicSession;
use mvfstr_driver::Refusal;
use mvfstr_driver::SendSink;
use mvfstr_io::MmsgBackend;
use mvfstr_proto::Bytes;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::Dir;
use mvfstr_proto::SendOrder;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;

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
}

impl Settings {
    /// Creates the settings from `flags`, with closed connections reported to `closed`.
    pub(crate) fn new(flags: &Flags, closed: mpsc::Sender<Closed>) -> Self {
        Self {
            num_streams: flags.num_streams,
            bytes_per_stream: flags.bytes_per_stream,
            block: Bytes::from(vec![0; flags.block_size]),
            stats: flags.stats,
            closed,
        }
    }
}

/// The server's driver, set once it runs, which keeps the counters of the server socket.
pub(crate) type Driver = Rc<OnceCell<EndpointHandle<ServerApp, MmsgBackend>>>;

/// The server application: it takes every connection.
#[derive(Debug)]
pub(crate) struct ServerApp {
    settings: Settings,
    driver: Driver,
}

impl ServerApp {
    /// Creates an application whose connections run with `settings` on `driver`.
    pub(crate) fn new(settings: Settings, driver: Driver) -> Self {
        Self { settings, driver }
    }
}

impl QuicApplication for ServerApp {
    type Session = ServerSession;

    fn accept(
        &mut self,
        _info: &ConnInfo,
        _options: &mut ConnOptions,
    ) -> Result<ServerSession, Refusal> {
        Ok(ServerSession {
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
pub(crate) struct ServerSession {
    settings: Settings,
    driver: Driver,
    producers: HashMap<StreamId, Producer>,
    /// Streams not opened yet, for want of stream credit or of a `Conn` to open them on.
    to_open: u32,
    /// The handle that wakes the session to replace a finished stream, set once connected.
    handle: Option<ConnHandle>,
}

impl ServerSession {
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

impl QuicSession for ServerSession {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        match event {
            ConnEvent::Connected => {
                self.handle = Some(conn.handle());
                self.to_open = self.settings.num_streams;
                self.open_streams(conn);
            }
            ConnEvent::StreamsAvailable { dir: Dir::Uni } => self.open_streams(conn),
            ConnEvent::Closed { .. } if self.settings.stats => {
                let endpoint = self.driver.get().map(|driver| driver.stats());
                let _ = self.settings.closed.send(Closed {
                    stats: conn.stats(),
                    socket_stops: endpoint.as_ref().map_or(0, |stats| stats.socket_stops),
                    phase_pacing_wakes: endpoint.map_or(0, |stats| stats.phase_pacing_wakes),
                });
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
        self.open_streams(conn);
        Poll::Pending
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
