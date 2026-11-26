/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The server: once a connection is up it opens `--num_streams` unidirectional streams and
//! writes to each forever, or `--bytes_per_stream` bytes and then a FIN and a replacement
//! stream, as mvfst's tperf server does.
//!
//! By default each stream's producer pushes a block whenever the driver polls it, and the driver's
//! wire order shares the connection among the streams. Under `--object_rate` the connection
//! writes objects on a clock instead: on each tick it queues an object on every stream, and pushes
//! the queued objects itself, round robin.

use std::cell::Cell;
use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
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
use crate::object::HEADER_LEN;
use crate::object::ObjectHeader;
use crate::object::ObjectQueue;
use crate::object::monotonic_ns;
use crate::report::ServerTally;

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
    /// What the server has done, for its summary line.
    counters: Arc<ServerCounters>,
    /// Objects per second per stream under `--object_rate`, else 0.
    object_rate: u32,
    /// The length of each object, header included.
    object_size: u32,
    /// The payload after each object's header: zeros that every object shares, under
    /// `--object_rate`.
    payload: Bytes,
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
            counters: Arc::default(),
            object_rate: flags.object_rate,
            object_size: flags.object_size,
            payload: if flags.object_rate > 0 {
                Bytes::from(vec![
                    0;
                    (flags.object_size as usize).saturating_sub(HEADER_LEN)
                ])
            } else {
                Bytes::new()
            },
        }
    }

    /// Returns what the server's connections count, for its summary line.
    pub(crate) fn counters(&self) -> Arc<ServerCounters> {
        Arc::clone(&self.counters)
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
    /// Under `--object_rate`, what the connections share, with ticks from the server's start.
    pace: Option<Rc<Pace>>,
}

impl<B: Backend> ServerApp<B> {
    /// Creates an application whose connections run with `settings` on `driver`.
    pub(crate) fn new(settings: Settings, driver: Driver<B>) -> Self {
        let pace = (settings.object_rate > 0).then(|| {
            let ticks = Ticks::new(Instant::now(), monotonic_ns(), settings.object_rate);
            Rc::new(Pace::new(ticks, settings.counters()))
        });
        Self {
            settings,
            driver,
            pace,
        }
    }
}

impl<B: Backend> QuicApplication for ServerApp<B> {
    type Session = ServerSession<B>;

    fn accept(
        &mut self,
        _info: &ConnInfo,
        _options: &mut ConnOptions,
    ) -> Result<ServerSession<B>, Refusal> {
        self.settings.counters.conns.fetch_add(1, Ordering::Relaxed);
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
            paced: self
                .pace
                .as_ref()
                .map(|pace| PacedWriter::new(Rc::clone(pace), self.settings.num_streams)),
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
    /// Under `--object_rate`, the writer of the connection's streams.
    paced: Option<PacedWriter>,
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
                if let Some(paced) = &mut self.paced {
                    paced.start(conn.now());
                    paced.pump(conn, &self.settings);
                } else {
                    self.to_open = self.settings.num_streams;
                    self.open_streams(conn);
                }
            }
            ConnEvent::StreamsAvailable { dir: Dir::Uni } => match &mut self.paced {
                Some(paced) => paced.pump(conn, &self.settings),
                None => self.open_streams(conn),
            },
            ConnEvent::Closed { .. } => {
                if let Some(paced) = &mut self.paced {
                    paced.stop();
                }
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

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if ready == StreamReady::Writable
            && let Some(paced) = &mut self.paced
        {
            paced.writable(id);
            paced.pump(conn, &self.settings);
        }
    }

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
        match &mut self.paced {
            Some(paced) => {
                let now = conn.now();
                paced.run_due(conn, now, &self.settings);
            }
            None => self.open_streams(conn),
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        let tls = self.tls_host.as_ref().and_then(|hosted| hosted.poll_at);
        match &self.paced {
            None => tls,
            Some(paced) => tls.into_iter().chain(paced.deadline()).min(),
        }
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

/// The streams of a connection, as a [`PacedWriter`] writes them.
trait PacedStreams {
    /// Opens a unidirectional stream in the wire order every data stream shares, or returns
    /// `None` while the peer's stream limit allows none.
    fn open(&mut self) -> Option<StreamId>;

    /// Stages the longest prefix of `data` that stream `id` accepts and leaves the rest in `data`;
    /// fails if the stream accepts no more bytes, because the peer ended it or the connection
    /// closed.
    fn send(&mut self, id: StreamId, data: &mut Bytes) -> Result<(), StreamGone>;

    /// Ends stream `id` after its staged bytes.
    fn finish(&mut self, id: StreamId);
}

/// A stream that accepts no more bytes.
#[derive(Clone, Copy, Debug)]
struct StreamGone;

impl PacedStreams for Conn<'_> {
    fn open(&mut self) -> Option<StreamId> {
        self.open_stream(Dir::Uni, ORDER).ok()
    }

    fn send(&mut self, id: StreamId, data: &mut Bytes) -> Result<(), StreamGone> {
        let mut stream = self.stream(id).map_err(|_| StreamGone)?;
        stream.send(data).map(drop).map_err(|_| StreamGone)
    }

    fn finish(&mut self, id: StreamId) {
        if let Ok(mut stream) = self.stream(id) {
            let _ = stream.finish();
        }
    }
}

/// The writer of one connection under `--object_rate`. On each tick it queues an object on every
/// stream slot, then writes the queued objects round robin, one object per stream per turn,
/// skipping streams that are blocked. A stream that refuses bytes is blocked until its allowance
/// returns (`Writable`), and keeps its queue meanwhile. Every object shares one payload.
#[derive(Debug)]
struct PacedWriter {
    pace: Rc<Pace>,
    slots: Vec<Slot>,
    stripe: Stripe,
    /// The next tick and when it starts, from the handshake until the connection closes.
    next: Option<(u64, Instant)>,
}

/// One of a paced connection's `--num_streams` stream slots: the stream it writes, which a
/// replacement takes over after a FIN under `--bytes_per_stream`, and the objects queued on it.
#[derive(Debug, Default)]
struct Slot {
    stream: SlotStream,
    /// What is left of the object being written: its header and its payload.
    current: Option<(Bytes, Bytes)>,
    /// The objects not started yet.
    queue: ObjectQueue,
    /// Bytes written to the stream.
    sent: u64,
    /// The sequence number of the stream's next object.
    seq: u32,
    /// Whether the stream refused bytes and waits for `Writable`.
    blocked: bool,
}

/// The stream of a [`Slot`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SlotStream {
    /// Not opened yet, for want of stream credit.
    #[default]
    Unopened,
    /// Open for writing.
    Open(StreamId),
    /// Ended by the peer; the slot takes no more objects.
    Gone,
}

impl Slot {
    /// Returns whether the slot has an object to write and a stream that takes bytes.
    fn ready(&self) -> bool {
        matches!(self.stream, SlotStream::Open(_))
            && !self.blocked
            && (self.current.is_some() || self.queue.len() > 0)
    }

    /// Returns the objects queued, the one being written included.
    fn queued(&self) -> u64 {
        self.queue.len() as u64 + u64::from(self.current.is_some())
    }

    /// Gives up the slot, whose stream the peer ended, and the objects queued on it.
    fn give_up(&mut self) {
        *self = Slot {
            stream: SlotStream::Gone,
            ..Slot::default()
        };
    }
}

impl PacedWriter {
    /// Creates the writer of a connection with `streams` stream slots.
    fn new(pace: Rc<Pace>, streams: u32) -> Self {
        let slots = usize::try_from(streams).unwrap_or(usize::MAX);
        Self {
            pace,
            slots: (0..slots).map(|_| Slot::default()).collect(),
            stripe: Stripe::new(slots),
            next: None,
        }
    }

    /// Starts the ticks, from the first that starts at or after `now`.
    fn start(&mut self, now: Instant) {
        let tick = self.pace.ticks.first_from(now);
        self.next = Some((tick, self.pace.ticks.at(tick)));
    }

    /// Stops the ticks, and forgets the slots and their queued objects, for a connection that
    /// closed.
    fn stop(&mut self) {
        self.next = None;
        self.slots.clear();
        self.stripe = Stripe::new(0);
    }

    /// Returns when the next tick starts.
    fn deadline(&self) -> Option<Instant> {
        self.next.map(|(_, at)| at)
    }

    /// Unblocks the slot of stream `id`, whose allowance returned.
    fn writable(&mut self, id: StreamId) {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.stream == SlotStream::Open(id))
        {
            slot.blocked = false;
        }
    }

    /// Runs every tick that has started by `now`: each queues an object on every slot and writes
    /// what the streams take before the next starts, so a tick is late only if objects wait on a
    /// stream, not when one timer wake runs several. An object's send time is when its tick
    /// started, so the latency the client measures includes a wake that came late.
    fn run_due(&mut self, conn: &mut impl PacedStreams, now: Instant, settings: &Settings) {
        while let Some((tick, at)) = self.next
            && at <= now
        {
            let object = ObjectHeader {
                len: settings.object_size,
                seq: 0,
                sent_ns: self.pace.ticks.sent_ns(tick),
            };
            let backlog = self.slots.iter().map(Slot::queued).sum();
            self.pace.begin(tick, backlog);
            for slot in self
                .slots
                .iter_mut()
                .filter(|slot| slot.stream != SlotStream::Gone)
            {
                if slot.queue.push(object).is_some() {
                    self.pace.dropped();
                }
            }
            self.next = Some((tick + 1, self.pace.ticks.at(tick + 1)));
            self.pump(conn, settings);
        }
    }

    /// Writes queued objects round robin until every slot is empty or blocked, and opens a stream
    /// for each slot that lacks one while the peer's limit allows.
    fn pump(&mut self, conn: &mut impl PacedStreams, settings: &Settings) {
        loop {
            while let Some(index) = self.stripe.next(|slot| self.slots[slot].ready()) {
                self.write_one(conn, index, settings);
            }
            if !self.open(conn) {
                return;
            }
        }
    }

    /// Opens a stream for each slot that lacks one while the peer's limit allows, and returns
    /// whether it opened any.
    fn open(&mut self, conn: &mut impl PacedStreams) -> bool {
        let mut opened = false;
        for slot in self
            .slots
            .iter_mut()
            .filter(|slot| slot.stream == SlotStream::Unopened)
        {
            let Some(id) = conn.open() else {
                break;
            };
            slot.stream = SlotStream::Open(id);
            slot.sent = 0;
            slot.seq = 0;
            slot.blocked = false;
            opened = true;
        }
        opened
    }

    /// Writes the next object of slot `index`, or as much of it as the stream takes. Under
    /// `--bytes_per_stream`, a stream that has carried that many bytes ends after the object, so
    /// a stream ends on an object boundary.
    fn write_one(&mut self, conn: &mut impl PacedStreams, index: usize, settings: &Settings) {
        let slot = &mut self.slots[index];
        let SlotStream::Open(id) = slot.stream else {
            return;
        };
        if slot.current.is_none() {
            let Some(mut object) = slot.queue.pop() else {
                return;
            };
            object.seq = slot.seq;
            slot.seq = slot.seq.wrapping_add(1);
            let header = Bytes::copy_from_slice(&object.encode());
            slot.current = Some((header, settings.payload.clone()));
        }
        let Some((header, payload)) = &mut slot.current else {
            return;
        };
        let before = header.len() + payload.len();
        let pushed = conn.send(id, header).and_then(|()| {
            if header.is_empty() {
                conn.send(id, payload)
            } else {
                Ok(())
            }
        });
        let left = header.len() + payload.len();
        slot.sent += (before - left) as u64;
        if pushed.is_err() {
            slot.give_up();
            return;
        }
        if left > 0 {
            slot.blocked = true;
            return;
        }
        slot.current = None;
        self.pace.written();
        if settings.bytes_per_stream > 0 && slot.sent >= settings.bytes_per_stream {
            conn.finish(id);
            slot.stream = SlotStream::Unopened;
        }
    }
}

/// A round-robin cursor over a connection's stream slots, which gives each slot that can take a
/// write one turn before any slot gets a second.
#[derive(Clone, Debug)]
pub(crate) struct Stripe {
    slots: usize,
    /// The slot after the one returned last.
    next: usize,
}

impl Stripe {
    /// Creates a cursor over slots `0..slots` that starts at slot 0.
    pub(crate) fn new(slots: usize) -> Self {
        Self { slots, next: 0 }
    }

    /// Returns the first slot after the one returned last, wrapping around, that `ready` accepts,
    /// and moves past it; `None` if `ready` accepts none, which leaves the cursor where it was.
    pub(crate) fn next(&mut self, mut ready: impl FnMut(usize) -> bool) -> Option<usize> {
        let slot = (0..self.slots)
            .map(|step| (self.next + step) % self.slots)
            .find(|&slot| ready(slot))?;
        self.next = (slot + 1) % self.slots;
        Some(slot)
    }
}

/// Nanoseconds per second.
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// When paced mode's ticks start, for every connection of a server: tick `k` starts `k / rate`
/// seconds after the epoch.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ticks {
    epoch: Instant,
    /// The epoch on the host's CLOCK_MONOTONIC, in nanoseconds.
    epoch_ns: u64,
    rate: u32,
}

impl Ticks {
    /// Creates the clock of `rate` ticks per second, which must not be 0, from `epoch`, which
    /// is `epoch_ns` on the host's CLOCK_MONOTONIC.
    pub(crate) fn new(epoch: Instant, epoch_ns: u64, rate: u32) -> Self {
        Self {
            epoch,
            epoch_ns,
            rate,
        }
    }

    /// Returns when tick `tick` starts.
    pub(crate) fn at(&self, tick: u64) -> Instant {
        self.epoch + Duration::from_nanos(u64::try_from(self.offset(tick)).unwrap_or(u64::MAX))
    }

    /// Returns when tick `tick` starts on the host's CLOCK_MONOTONIC, in nanoseconds: the send
    /// time of its objects.
    pub(crate) fn sent_ns(&self, tick: u64) -> u64 {
        u64::try_from(u128::from(self.epoch_ns) + self.offset(tick)).unwrap_or(u64::MAX)
    }

    /// Returns the nanoseconds from the epoch to the start of tick `tick`, rounded down.
    fn offset(&self, tick: u64) -> u128 {
        u128::from(tick) * NANOS_PER_SEC / u128::from(self.rate)
    }

    /// Returns the first tick that starts at or after `now`.
    pub(crate) fn first_from(&self, now: Instant) -> u64 {
        let since = now.saturating_duration_since(self.epoch).as_nanos();
        let tick = (since * u128::from(self.rate)).div_ceil(NANOS_PER_SEC);
        u64::try_from(tick).unwrap_or(u64::MAX)
    }
}

/// What a server has done, which its paced connections count on its worker and its summary line
/// reads from another thread.
#[derive(Debug, Default)]
pub(crate) struct ServerCounters {
    conns: AtomicU64,
    objects_sent: AtomicU64,
    objects_dropped: AtomicU64,
    late_ticks: AtomicU64,
}

impl ServerCounters {
    /// Returns the counts so far.
    pub(crate) fn tally(&self) -> ServerTally {
        ServerTally {
            conns: self.conns.load(Ordering::Relaxed),
            objects_sent: self.objects_sent.load(Ordering::Relaxed),
            objects_dropped: self.objects_dropped.load(Ordering::Relaxed),
            late_ticks: self.late_ticks.load(Ordering::Relaxed),
        }
    }
}

/// How many recent ticks [`Pace`] remembers counting late. A connection that starts a tick more
/// than this many ticks after another counted it may count it again; connections differ by the
/// ticks of one driver turn, far fewer.
const LATE_TICKS_KEPT: usize = 4096;

/// What the paced connections of one server share: the tick clock, and the ticks counted late.
#[derive(Debug)]
pub(crate) struct Pace {
    ticks: Ticks,
    counters: Arc<ServerCounters>,
    /// The ticks counted late lately, each at its number modulo [`LATE_TICKS_KEPT`].
    late: Box<[Cell<Option<u64>>]>,
}

impl Pace {
    /// Creates the shared state of a server whose ticks follow `ticks` and whose counts go to
    /// `counters`.
    pub(crate) fn new(ticks: Ticks, counters: Arc<ServerCounters>) -> Self {
        Self {
            ticks,
            counters,
            late: (0..LATE_TICKS_KEPT).map(|_| Cell::new(None)).collect(),
        }
    }

    /// Starts `tick` on a connection whose streams still hold `backlog` objects of earlier ticks
    /// not wholly written. A tick is late if any connection starts it with a backlog, and counts
    /// once. Each connection runs its own ticks, so one may start a tick after another has
    /// started later ones.
    pub(crate) fn begin(&self, tick: u64, backlog: u64) {
        if backlog == 0 {
            return;
        }
        let kept = &self.late[(tick % LATE_TICKS_KEPT as u64) as usize];
        if kept.get() == Some(tick) {
            return;
        }
        kept.set(Some(tick));
        self.counters.late_ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts an object whose last byte was written.
    pub(crate) fn written(&self) {
        self.counters.objects_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a queued object dropped for a newer one.
    pub(crate) fn dropped(&self) {
        self.counters
            .objects_dropped
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::Side;

    use super::*;
    use crate::object::Found;
    use crate::object::ObjectReader;

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

    #[test]
    fn tick_k_starts_k_over_the_rate_seconds_after_the_epoch_without_drift() {
        let epoch = Instant::now();
        let ticks = Ticks::new(epoch, 5_000_000_000, 3);
        let ns = Duration::from_nanos;
        assert_eq!(ticks.at(0), epoch);
        assert_eq!(ticks.at(1), epoch + ns(333_333_333), "rounded down");
        assert_eq!(ticks.at(3), epoch + Duration::from_secs(1));
        assert_eq!(ticks.at(300), epoch + Duration::from_secs(100));
        assert_eq!(
            [0, 1, 3, 300].map(|tick| ticks.sent_ns(tick)),
            [5_000_000_000, 5_333_333_333, 6_000_000_000, 105_000_000_000],
            "the same starts on CLOCK_MONOTONIC"
        );
        assert_eq!(ticks.first_from(epoch), 0);
        assert_eq!(ticks.first_from(epoch + ns(1)), 1);
        assert_eq!(ticks.first_from(ticks.at(1)), 1);
        assert_eq!(ticks.first_from(ticks.at(1) + ns(1)), 2);
        assert_eq!(ticks.first_from(epoch + Duration::from_millis(999)), 3);
        let early = epoch.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(ticks.first_from(early), 0, "before the epoch");
        let fifty = Ticks::new(epoch, 0, 50);
        assert_eq!(fifty.at(1), epoch + Duration::from_millis(20));
        assert_eq!(fifty.first_from(epoch + Duration::from_millis(30)), 2);
    }

    #[test]
    fn a_tick_is_late_once_if_any_connection_starts_it_with_objects_still_queued() {
        let counters = Arc::new(ServerCounters::default());
        let pace = Pace::new(Ticks::new(Instant::now(), 0, 50), Arc::clone(&counters));
        let late = || counters.tally().late_ticks;
        pace.begin(0, 0);
        pace.begin(0, 0);
        assert_eq!(late(), 0, "no connection had an object queued");
        pace.begin(1, 0);
        pace.begin(1, 2);
        assert_eq!(
            late(),
            1,
            "the second connection still had two objects queued"
        );
        pace.begin(1, 1);
        assert_eq!(late(), 1, "a tick counts once");
        pace.begin(2, 0);
        pace.begin(3, 0);
        pace.begin(2, 1);
        assert_eq!(
            late(),
            2,
            "a connection that starts a tick after another started a later one"
        );
        pace.begin(5, 1);
        pace.begin(4, 1);
        pace.begin(5, 1);
        assert_eq!(late(), 4, "ticks count however the connections interleave");
        pace.written();
        pace.written();
        pace.dropped();
        assert_eq!(
            counters.tally(),
            ServerTally {
                conns: 0,
                objects_sent: 2,
                objects_dropped: 1,
                late_ticks: 4,
            }
        );
    }

    /// The CLOCK_MONOTONIC reading of the paced tests' epoch.
    const EPOCH_NS: u64 = 7_000_000_000;

    /// A connection's streams as a paced writer sees them, each of which accepts up to the room
    /// it was opened with.
    #[derive(Debug)]
    struct FakeStreams {
        /// The room of each stream opened from now on.
        room: usize,
        /// Each stream, in the order they opened.
        streams: Vec<FakeStream>,
    }

    /// One stream of [`FakeStreams`].
    #[derive(Debug)]
    struct FakeStream {
        bytes: Vec<u8>,
        room: usize,
        finished: bool,
    }

    impl FakeStreams {
        fn with_room(room: usize) -> Self {
            Self {
                room,
                streams: Vec::new(),
            }
        }

        /// Returns the headers of the objects of `size` bytes each stream carries, and whether
        /// it ended.
        fn objects(&self, size: u32) -> Vec<(Vec<ObjectHeader>, bool)> {
            self.streams
                .iter()
                .map(|stream| {
                    let mut reader = ObjectReader::new(size);
                    let mut headers = Vec::new();
                    reader.feed(&stream.bytes, |found| match found {
                        Found::Object(header) => headers.push(header),
                        Found::Bad => panic!("a bad object in {stream:?}"),
                    });
                    (headers, stream.finished)
                })
                .collect()
        }
    }

    impl PacedStreams for FakeStreams {
        fn open(&mut self) -> Option<StreamId> {
            let id = StreamId::new(Side::Server, Dir::Uni, self.streams.len() as u64)?;
            self.streams.push(FakeStream {
                bytes: Vec::new(),
                room: self.room,
                finished: false,
            });
            Some(id)
        }

        fn send(&mut self, id: StreamId, data: &mut Bytes) -> Result<(), StreamGone> {
            let stream = self
                .streams
                .get_mut(id.index() as usize)
                .filter(|stream| !stream.finished)
                .ok_or(StreamGone)?;
            let taken = data.split_to(data.len().min(stream.room));
            stream.room -= taken.len();
            stream.bytes.extend_from_slice(&taken);
            Ok(())
        }

        fn finish(&mut self, id: StreamId) {
            if let Some(stream) = self.streams.get_mut(id.index() as usize) {
                stream.finished = true;
            }
        }
    }

    /// Returns the settings of a server with `args`, and the pace its connections share, with
    /// ticks from `epoch`.
    fn paced_server(args: &[&str], epoch: Instant) -> (Settings, Rc<Pace>) {
        let flags = Flags::parse(args.iter().map(|arg| (*arg).to_owned())).unwrap();
        let (closed, _) = mpsc::channel();
        let settings = Settings::new(&flags, closed, None);
        let ticks = Ticks::new(epoch, EPOCH_NS, flags.object_rate);
        let pace = Rc::new(Pace::new(ticks, settings.counters()));
        (settings, pace)
    }

    #[test]
    fn each_stream_numbers_its_objects_from_zero_and_so_does_a_replacement() {
        // A stream ends after the object that takes it to 250 bytes, its third.
        let epoch = Instant::now();
        let (settings, pace) = paced_server(
            &[
                "--num_streams=2",
                "--object_rate=50",
                "--object_size=100",
                "--bytes_per_stream=250",
            ],
            epoch,
        );
        let mut writer = PacedWriter::new(pace, 2);
        let mut conn = FakeStreams::with_room(usize::MAX);
        writer.start(epoch);
        for tick in 0..7 {
            writer.run_due(
                &mut conn,
                epoch + Duration::from_millis(20 * tick),
                &settings,
            );
        }
        let seqs: Vec<(Vec<u32>, bool)> = conn
            .objects(100)
            .into_iter()
            .map(|(headers, finished)| {
                (headers.iter().map(|header| header.seq).collect(), finished)
            })
            .collect();
        assert_eq!(
            seqs,
            [
                (vec![0, 1, 2], true),
                (vec![0, 1, 2], true),
                (vec![0, 1, 2], true),
                (vec![0, 1, 2], true),
                (vec![0], false),
                (vec![0], false),
            ],
            "two streams, their replacements, and theirs"
        );
    }

    #[test]
    fn a_wake_that_comes_late_runs_every_tick_it_missed() {
        let epoch = Instant::now();
        let (settings, pace) = paced_server(&["--object_rate=50", "--object_size=100"], epoch);
        let mut writer = PacedWriter::new(pace, 1);
        let mut conn = FakeStreams::with_room(usize::MAX);
        let objects = |conn: &FakeStreams| conn.objects(100)[0].0.len();
        writer.start(epoch);
        // Ticks 0 to 3 start at 0, 20, 40 and 60 ms.
        writer.run_due(&mut conn, epoch + Duration::from_millis(70), &settings);
        assert_eq!(objects(&conn), 4);
        assert_eq!(writer.deadline(), Some(epoch + Duration::from_millis(80)));
        writer.run_due(&mut conn, epoch + Duration::from_millis(79), &settings);
        assert_eq!(objects(&conn), 4, "tick 4 has not started");
        writer.run_due(&mut conn, epoch + Duration::from_millis(80), &settings);
        assert_eq!(objects(&conn), 5);
    }

    #[test]
    fn an_object_carries_the_start_of_its_tick_however_late_the_wake_runs_it() {
        let epoch = Instant::now();
        let (settings, pace) = paced_server(&["--object_rate=50", "--object_size=100"], epoch);
        let mut writer = PacedWriter::new(pace, 1);
        let mut conn = FakeStreams::with_room(usize::MAX);
        writer.start(epoch);
        writer.run_due(&mut conn, epoch + Duration::from_millis(70), &settings);
        writer.run_due(&mut conn, epoch + Duration::from_millis(85), &settings);
        let sent: Vec<u64> = conn.objects(100)[0]
            .0
            .iter()
            .map(|header| header.sent_ns)
            .collect();
        assert_eq!(
            sent,
            [0, 20, 40, 60, 80].map(|ms| EPOCH_NS + ms * 1_000_000),
            "on the host's CLOCK_MONOTONIC, from the epoch"
        );
    }

    #[test]
    fn a_connection_that_runs_its_ticks_after_another_still_counts_its_backlog_late() {
        // One wake runs ticks 0 to 9 on two connections of one stream each: first on one whose
        // stream takes every object, then on one whose stream takes nothing.
        let epoch = Instant::now();
        let (settings, pace) = paced_server(&["--object_rate=1000", "--object_size=100"], epoch);
        let counters = settings.counters();
        let mut open = PacedWriter::new(Rc::clone(&pace), 1);
        let mut stuck = PacedWriter::new(pace, 1);
        let mut open_conn = FakeStreams::with_room(usize::MAX);
        let mut stuck_conn = FakeStreams::with_room(0);
        open.start(epoch);
        stuck.start(epoch);
        let wake = epoch + Duration::from_millis(9);
        open.run_due(&mut open_conn, wake, &settings);
        assert_eq!(counters.tally().late_ticks, 0, "every object left");
        stuck.run_due(&mut stuck_conn, wake, &settings);
        assert_eq!(
            counters.tally().late_ticks,
            9,
            "ticks 1 to 9 each found the stuck stream's earlier objects queued"
        );
        let next = epoch + Duration::from_millis(10);
        open.run_due(&mut open_conn, next, &settings);
        stuck.run_due(&mut stuck_conn, next, &settings);
        assert_eq!(counters.tally().late_ticks, 10);
    }

    #[test]
    fn a_blocked_stream_keeps_its_objects_without_holding_up_the_other_and_drains_once_writable() {
        // Stream 0 comes first in every round, so a writer that stopped at a blocked stream would
        // hold up stream 1.
        let epoch = Instant::now();
        let (settings, pace) = paced_server(
            &["--num_streams=2", "--object_rate=50", "--object_size=100"],
            epoch,
        );
        let mut writer = PacedWriter::new(pace, 2);
        let mut conn = FakeStreams::with_room(usize::MAX);
        let tick = |k: u64| epoch + Duration::from_millis(20 * k);
        let seqs = |conn: &FakeStreams| -> Vec<Vec<u32>> {
            conn.objects(100)
                .into_iter()
                .map(|(headers, _)| headers.iter().map(|header| header.seq).collect())
                .collect()
        };
        writer.start(epoch);
        writer.run_due(&mut conn, tick(0), &settings);
        assert_eq!(seqs(&conn), [vec![0], vec![0]]);

        conn.streams[0].room = 0;
        for k in 1..=3 {
            writer.run_due(&mut conn, tick(k), &settings);
            assert_eq!(
                seqs(&conn)[1],
                (0..=k as u32).collect::<Vec<_>>(),
                "stream 1 takes the object of tick {k} on that tick"
            );
        }
        assert_eq!(
            seqs(&conn)[0],
            [0],
            "stream 0 holds the objects of ticks 1 to 3"
        );

        conn.streams[0].room = usize::MAX;
        writer.writable(StreamId::new(Side::Server, Dir::Uni, 0).unwrap());
        writer.pump(&mut conn, &settings);
        let stream_0: Vec<(u32, u64)> = conn.objects(100)[0]
            .0
            .iter()
            .map(|header| (header.seq, header.sent_ns))
            .collect();
        assert_eq!(
            stream_0,
            [0, 1, 2, 3].map(|k| (k, EPOCH_NS + u64::from(k) * 20_000_000)),
            "one pump writes stream 0's whole backlog, in order"
        );
        assert_eq!(settings.counters().tally().objects_dropped, 0);
    }

    #[test]
    fn the_stripe_gives_every_slot_one_turn_per_round_in_order() {
        let mut stripe = Stripe::new(4);
        let turns: Vec<usize> = (0..12).filter_map(|_| stripe.next(|_| true)).collect();
        assert_eq!(turns, [0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3]);
        assert_eq!(
            Stripe::new(0).next(|_| true),
            None,
            "a connection without streams"
        );
        let mut one = Stripe::new(1);
        assert_eq!([one.next(|_| true), one.next(|_| true)], [Some(0), Some(0)]);
    }

    #[test]
    fn the_stripe_skips_blocked_slots_and_resumes_after_the_last_turn() {
        let mut stripe = Stripe::new(4);
        assert_eq!(stripe.next(|_| true), Some(0));
        assert_eq!(stripe.next(|slot| slot != 1), Some(2), "slot 1 is blocked");
        assert_eq!(stripe.next(|_| false), None, "every slot is blocked");
        assert_eq!(
            stripe.next(|_| true),
            Some(3),
            "a pass without a turn leaves the cursor alone"
        );
        assert_eq!(stripe.next(|slot| slot == 2), Some(2), "wraps around");
        let mut asked = Vec::new();
        assert_eq!(
            stripe.next(|slot| {
                asked.push(slot);
                slot == 1
            }),
            Some(1)
        );
        assert_eq!(asked, [3, 0, 1], "from the slot after the last turn");
    }

    #[test]
    fn the_stripe_does_not_starve_a_slot_with_less_credit() {
        // Each turn takes one unit of the slot's credit; a slot without credit is blocked.
        let mut credit = [5, 1, 3, 0];
        let mut stripe = Stripe::new(credit.len());
        let mut turns = Vec::new();
        while let Some(slot) = stripe.next(|slot| credit[slot] > 0) {
            credit[slot] -= 1;
            turns.push(slot);
        }
        assert_eq!(turns, [0, 1, 2, 0, 2, 0, 2, 0, 0]);
        assert_eq!(credit, [0; 4]);

        // A slot whose credit comes back gets its turn in the round under way.
        let mut credit = [3, 3, 0];
        let mut stripe = Stripe::new(credit.len());
        assert_eq!(stripe.next(|slot| credit[slot] > 0), Some(0));
        credit[0] -= 1;
        credit[2] = 1;
        let turns: Vec<usize> = std::iter::from_fn(|| {
            let slot = stripe.next(|slot| credit[slot] > 0)?;
            credit[slot] -= 1;
            Some(slot)
        })
        .collect();
        assert_eq!(turns, [1, 2, 0, 1, 0, 1]);
    }
}
