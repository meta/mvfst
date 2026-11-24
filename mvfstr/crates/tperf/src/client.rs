/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The client: it reads and discards what the server sends and measures from the first stream
//! for `--duration` seconds, then closes with an application CONNECTION_CLOSE of code 0, as
//! mvfst's tperf client does.

use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use mvfstr_driver::Conn;
use mvfstr_driver::ConnInfo;
use mvfstr_driver::QuicApplication;
use mvfstr_driver::QuicSession;
use mvfstr_driver::Refusal;
use mvfstr_driver::SendSink;
use mvfstr_proto::AppCode;
use mvfstr_proto::Bytes;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;

use crate::report::Measurement;

/// What the client's connection reports to the thread running the client.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The window closed and the client closed the connection: what it measured and the
    /// connection's counters at that point.
    Measured {
        /// What was measured.
        measurement: Measurement,
        /// The connection's counters.
        stats: ConnStats,
    },
    /// The connection closed before the window did.
    Closed(CloseReason),
    /// The connection is drained.
    Drained,
}

/// The client application; it only opens connections.
#[derive(Debug)]
pub(crate) struct ClientApp;

impl QuicApplication for ClientApp {
    type Session = ClientSession;

    fn accept(
        &mut self,
        _info: &ConnInfo,
        _options: &mut ConnOptions,
    ) -> Result<ClientSession, Refusal> {
        Err(Refusal::Refuse)
    }
}

/// The client's connection.
#[derive(Debug)]
pub(crate) struct ClientSession {
    meter: Meter,
    outcomes: mpsc::Sender<Outcome>,
    /// Whether the measurement, or the connection's early close, has been reported.
    reported: bool,
}

impl ClientSession {
    /// Returns a connection that measures for `duration_secs` seconds and reports to `outcomes`.
    pub(crate) fn new(duration_secs: u32, outcomes: mpsc::Sender<Outcome>) -> Self {
        Self {
            meter: Meter::new(duration_secs),
            outcomes,
            reported: false,
        }
    }

    /// Closes the connection and reports the measurement once the window has closed.
    fn close_if_over(&mut self, conn: &mut Conn<'_>) {
        let now = conn.now();
        if self.reported || !self.meter.is_over(now) {
            return;
        }
        self.reported = true;
        conn.close(now, AppCode::from_u32(0), Bytes::new());
        let _ = self.outcomes.send(Outcome::Measured {
            measurement: self.meter.measurement(),
            stats: conn.stats(),
        });
    }
}

impl QuicSession for ClientSession {
    fn on_event(&mut self, _conn: &mut Conn<'_>, event: ConnEvent) {
        match event {
            ConnEvent::Closed { reason, .. } if !self.reported => {
                self.reported = true;
                let _ = self.outcomes.send(Outcome::Closed(reason));
            }
            ConnEvent::Drained => {
                let _ = self.outcomes.send(Outcome::Drained);
            }
            _ => {}
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        let now = conn.now();
        if ready == StreamReady::Opened {
            self.meter.stream_opened(now);
        }
        if let Ok(mut stream) = conn.stream(id) {
            let len = stream.readable().chain_length();
            if len > 0 && stream.consume(len).is_ok() {
                self.meter.received(now, len as u64);
            }
        }
        self.close_if_over(conn);
    }

    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        _id: StreamId,
        _sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        self.close_if_over(conn);
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.meter.deadline().filter(|_| !self.reported)
    }
}

/// The measured window: it opens when the server's first stream arrives and lasts the duration.
#[derive(Clone, Debug)]
pub(crate) struct Meter {
    duration_secs: u32,
    deadline: Option<Instant>,
    bytes: u64,
    streams: u64,
}

impl Meter {
    /// Returns a meter for a window of `duration_secs` seconds that has not opened.
    pub(crate) fn new(duration_secs: u32) -> Self {
        Self {
            duration_secs,
            deadline: None,
            bytes: 0,
            streams: 0,
        }
    }

    /// Counts a stream the server opened at `now`; the first one opens the window.
    pub(crate) fn stream_opened(&mut self, now: Instant) {
        self.streams += 1;
        self.deadline
            .get_or_insert(now + Duration::from_secs(u64::from(self.duration_secs)));
    }

    /// Counts `len` stream bytes that arrived at `now`, if the window is open.
    pub(crate) fn received(&mut self, now: Instant, len: u64) {
        if self.deadline.is_some_and(|deadline| now < deadline) {
            self.bytes += len;
        }
    }

    /// Returns when the window closes, once it has opened.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Returns whether the window has closed by `now`.
    pub(crate) fn is_over(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Returns what was measured.
    pub(crate) fn measurement(&self) -> Measurement {
        Measurement {
            bytes: self.bytes,
            duration_secs: self.duration_secs,
            streams: self.streams,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_opens_with_the_first_stream_and_counts_only_bytes_inside_it() {
        let t0 = Instant::now();
        let mut meter = Meter::new(2);
        assert_eq!(meter.deadline(), None);
        assert!(
            !meter.is_over(t0 + Duration::from_secs(100)),
            "not opened yet"
        );

        meter.stream_opened(t0);
        let end = t0 + Duration::from_secs(2);
        assert_eq!(meter.deadline(), Some(end));
        meter.stream_opened(t0 + Duration::from_secs(1));
        assert_eq!(
            meter.deadline(),
            Some(end),
            "later streams leave the window alone"
        );

        meter.received(t0 + Duration::from_millis(500), 100);
        meter.received(end - Duration::from_nanos(1), 7);
        assert!(!meter.is_over(end - Duration::from_nanos(1)));
        assert!(meter.is_over(end));
        meter.received(end, 50);
        assert_eq!(
            meter.measurement(),
            Measurement {
                bytes: 107,
                duration_secs: 2,
                streams: 2,
            }
        );
    }
}
