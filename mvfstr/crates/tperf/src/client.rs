/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The client: each of its connections reads and discards what the server sends and measures from
//! its first stream for `--duration` seconds, then closes with an application CONNECTION_CLOSE of
//! code 0, as mvfst's tperf client does. It counts each stream's bytes. Under `--object_rate`, set
//! to the server's, it also reads each stream's objects of `--object_size` bytes, and counts each
//! object's latency and the objects that do not match those flags.

use std::mem;
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
use mvfstr_proto::BufQueue;
use mvfstr_proto::Bytes;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;

use crate::object::Found;
use crate::object::ObjectReader;
use crate::object::monotonic_ns;
use crate::report::ConnTally;
use crate::report::Measurement;

/// What the client's connection reports to the thread running the client.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The window closed and the client closed the connection.
    Measured(ConnReport),
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

/// What a connection reports once its window has closed and it has closed.
#[derive(Clone, Debug)]
pub(crate) struct ConnReport {
    /// The connection's place among the client's connections.
    pub(crate) index: usize,
    /// What was measured.
    pub(crate) measurement: Measurement,
    /// What each stream received.
    pub(crate) received: ConnTally,
    /// The connection's counters at that point.
    pub(crate) stats: ConnStats,
}

/// The client's connection.
#[derive(Debug)]
pub(crate) struct ClientSession {
    index: usize,
    meter: Meter,
    streams: Streams,
    outcomes: mpsc::Sender<Outcome>,
    /// Whether the measurement, or the connection's early close, has been reported.
    reported: bool,
}

impl ClientSession {
    /// Returns connection `index` of a client, which measures for `duration_secs` seconds,
    /// reads objects of `object_size` bytes under `--object_rate`, and reports to `outcomes`.
    pub(crate) fn new(
        index: usize,
        duration_secs: u32,
        object_size: Option<u32>,
        outcomes: mpsc::Sender<Outcome>,
    ) -> Self {
        Self {
            index,
            meter: Meter::new(duration_secs),
            streams: Streams::new(object_size),
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
        let _ = self.outcomes.send(Outcome::Measured(ConnReport {
            index: self.index,
            measurement: self.meter.measurement(),
            received: self.streams.received(),
            stats: conn.stats(),
        }));
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
            self.streams.opened(id);
        }
        if let Ok(mut stream) = conn.stream(id) {
            let len = stream.readable().chain_length();
            if len > 0 {
                self.streams
                    .read(id, stream.readable(), self.meter.counts(now));
                if stream.consume(len).is_ok() {
                    self.meter.received(now, len as u64);
                }
            }
        }
        if ready == StreamReady::Finished {
            self.streams.finished(id, self.meter.counts(now));
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
        if self.counts(now) {
            self.bytes += len;
        }
    }

    /// Returns whether the window is open at `now`, so that what arrives counts.
    pub(crate) fn counts(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now < deadline)
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

/// What a connection reads from each of the server's streams.
#[derive(Clone, Debug)]
struct Streams {
    /// The length of the objects the streams carry, under `--object_rate`.
    object_size: Option<u32>,
    /// Each stream by its index among the server's unidirectional streams.
    streams: Vec<StreamTally>,
    /// The latency of each object completed in the window, in µs.
    latencies_us: Vec<u64>,
    /// The bad objects found in the window: of another length than `object_size`, or that their
    /// stream's FIN cut short.
    bad_objects: u64,
}

/// What one stream received.
#[derive(Clone, Debug)]
struct StreamTally {
    /// Whether the stream has arrived. A later stream can arrive first, and its index makes room
    /// for this one.
    arrived: bool,
    /// Bytes in the window.
    bytes: u64,
    /// The stream's objects, under `--object_rate`.
    reader: Option<ObjectReader>,
}

/// Returns stream `id` of `streams`, which holds each stream by its index, and counts it as
/// arrived. A stream carries objects of `object_size` bytes, if given.
fn stream_of(
    streams: &mut Vec<StreamTally>,
    id: StreamId,
    object_size: Option<u32>,
) -> &mut StreamTally {
    let index = usize::try_from(id.index()).unwrap_or(usize::MAX);
    if index >= streams.len() {
        streams.resize_with(index + 1, || StreamTally {
            arrived: false,
            bytes: 0,
            reader: object_size.map(ObjectReader::new),
        });
    }
    let stream = &mut streams[index];
    stream.arrived = true;
    stream
}

impl Streams {
    /// Creates the streams of a connection, which carry objects of `object_size` bytes under
    /// `--object_rate`.
    fn new(object_size: Option<u32>) -> Self {
        Self {
            object_size,
            streams: Vec::new(),
            latencies_us: Vec::new(),
            bad_objects: 0,
        }
    }

    /// Counts stream `id`, which the server opened.
    fn opened(&mut self, id: StreamId) {
        stream_of(&mut self.streams, id, self.object_size);
    }

    /// Reads `readable`, the next bytes of stream `id`, and counts them and the objects they
    /// complete if `counted`. The latency of an object runs from the send time in its header to
    /// when its last byte is read, on the clock that both sides read on one host.
    fn read(&mut self, id: StreamId, readable: &BufQueue, counted: bool) {
        let stream = stream_of(&mut self.streams, id, self.object_size);
        if counted {
            stream.bytes += readable.chain_length() as u64;
        }
        let Some(reader) = &mut stream.reader else {
            return;
        };
        let mut now_ns = None;
        for segment in readable.segments() {
            reader.feed(segment, |found| {
                if !counted {
                    return;
                }
                match found {
                    Found::Object(header) => {
                        let now = *now_ns.get_or_insert_with(monotonic_ns);
                        self.latencies_us
                            .push(now.saturating_sub(header.sent_ns) / 1000);
                    }
                    Found::Bad => self.bad_objects += 1,
                }
            });
        }
    }

    /// Counts the end of stream `id`, whose FIN arrived, if `counted`: a FIN inside an object
    /// makes that object bad.
    fn finished(&mut self, id: StreamId, counted: bool) {
        let stream = stream_of(&mut self.streams, id, self.object_size);
        if counted
            && stream
                .reader
                .as_ref()
                .is_some_and(ObjectReader::inside_object)
        {
            self.bad_objects += 1;
        }
    }

    /// Returns what the streams that arrived received, and moves the latencies out.
    fn received(&mut self) -> ConnTally {
        ConnTally {
            stream_bytes: self
                .streams
                .iter()
                .filter(|stream| stream.arrived)
                .map(|stream| stream.bytes)
                .collect(),
            latencies_us: mem::take(&mut self.latencies_us),
            bad_objects: self.bad_objects,
        }
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::Dir;
    use mvfstr_proto::Side;

    use super::*;
    use crate::object::ObjectHeader;

    /// Returns the server's unidirectional stream `index`.
    fn id(index: u64) -> StreamId {
        StreamId::new(Side::Server, Dir::Uni, index).unwrap()
    }

    /// Returns `bytes` as a stream's readable bytes.
    fn readable(bytes: &[u8]) -> BufQueue {
        BufQueue::copy_from_slice(bytes, usize::MAX).unwrap()
    }

    /// Returns an object of `len` bytes, at least a header, with sequence number `seq`.
    fn object(len: u32, seq: u32) -> Vec<u8> {
        let mut bytes = ObjectHeader {
            len,
            seq,
            sent_ns: 1,
        }
        .encode()
        .to_vec();
        bytes.resize(len as usize, 0);
        bytes
    }

    #[test]
    fn a_replacement_whose_data_comes_before_its_predecessors_fin_counts_as_a_stream_of_its_own() {
        let mut streams = Streams::new(None);
        streams.opened(id(0));
        streams.read(id(0), &readable(&[0; 100]), true);
        streams.opened(id(1));
        streams.read(id(1), &readable(&[0; 100]), true);
        // Stream 2 replaces stream 0.
        streams.opened(id(2));
        streams.read(id(2), &readable(&[0; 50]), true);
        streams.finished(id(0), true);
        assert_eq!(streams.received().stream_bytes, [100, 100, 50]);
    }

    #[test]
    fn a_stream_that_ends_before_the_others_open_still_counts() {
        let mut streams = Streams::new(None);
        streams.opened(id(0));
        streams.read(id(0), &readable(&[0; 100]), true);
        streams.finished(id(0), true);
        streams.opened(id(1));
        streams.read(id(1), &readable(&[0; 100]), true);
        streams.finished(id(1), true);
        streams.opened(id(2));
        assert_eq!(streams.received().stream_bytes, [100, 100, 0]);
    }

    #[test]
    fn a_stream_counts_once_it_arrives_even_after_a_later_stream() {
        let mut streams = Streams::new(None);
        streams.opened(id(0));
        streams.read(id(0), &readable(&[0; 100]), true);
        // Stream 2's first bytes arrive before stream 1's.
        streams.opened(id(2));
        streams.read(id(2), &readable(&[0; 30]), true);
        assert_eq!(
            streams.received().stream_bytes,
            [100, 30],
            "stream 1 has not arrived"
        );
    }

    #[test]
    fn a_client_without_an_object_rate_reads_no_objects_whatever_its_streams_carry() {
        let mut streams = Streams::new(None);
        streams.opened(id(0));
        let objects = [object(1200, 0), object(1200, 1)].concat();
        streams.read(id(0), &readable(&objects[..1800]), true);
        streams.finished(id(0), true);
        let tally = streams.received();
        assert_eq!((tally.latencies_us, tally.bad_objects), (vec![], 0));
    }

    #[test]
    fn a_paced_stream_counts_an_object_of_another_length_as_bad_and_reads_no_further() {
        let mut streams = Streams::new(Some(1200));
        streams.opened(id(0));
        let objects = [object(1200, 0), object(1000, 1), object(1200, 2)].concat();
        streams.read(id(0), &readable(&objects), true);
        // A saturating server's zeros.
        streams.opened(id(1));
        streams.read(id(1), &readable(&[0; 1200]), true);
        // A bad object outside the window does not count.
        streams.opened(id(2));
        streams.read(id(2), &readable(&[0; 1200]), false);
        let tally = streams.received();
        assert_eq!(tally.latencies_us.len(), 1, "stream 0's first object");
        assert_eq!(
            tally.bad_objects, 2,
            "the first bad object of streams 0 and 1"
        );
    }

    #[test]
    fn a_paced_stream_whose_fin_comes_inside_an_object_counts_that_object_as_bad() {
        let mut streams = Streams::new(Some(1200));
        let objects = [object(1200, 0), object(1200, 1)].concat();
        streams.opened(id(0));
        streams.read(id(0), &readable(&objects[..1800]), true);
        streams.finished(id(0), true);
        // A FIN on an object boundary.
        streams.opened(id(1));
        streams.read(id(1), &readable(&objects), true);
        streams.finished(id(1), true);
        // A FIN outside the window does not count.
        streams.opened(id(2));
        streams.read(id(2), &readable(&objects[..100]), true);
        streams.finished(id(2), false);
        let tally = streams.received();
        assert_eq!(
            tally.bad_objects, 1,
            "stream 0 ended inside its second object"
        );
        assert_eq!(tally.latencies_us.len(), 3);
    }

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
