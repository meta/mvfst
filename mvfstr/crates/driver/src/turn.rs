/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The endpoint task: the connection slab and the turn that runs it.
//!
//! Every piece of state sits in its own `RefCell`. The state that an
//! [`EndpointHandle`](crate::EndpointHandle) method uses is never borrowed across a session or
//! application callback, so callbacks may call into the handle. A connection's slot stays
//! borrowed while its session runs, so a callback reaches only other connections.

use std::any::Any;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::TxCaps;
use mvfstr_io::TxCounters;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ClientTls;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::Connection;
use mvfstr_proto::Endpoint;
use mvfstr_proto::EndpointEvent;
use mvfstr_proto::Incoming;
use mvfstr_proto::InlineSealer;
use mvfstr_proto::Inputs;
use mvfstr_proto::PathId;
use mvfstr_proto::Random;
use mvfstr_proto::Release;
use mvfstr_proto::Route;
use mvfstr_proto::RxDatagram;
use mvfstr_proto::RxDropReason;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::ServerTls;
use mvfstr_proto::SrcPortBlocklist;
use mvfstr_proto::SrcPortDrops;
use mvfstr_proto::StatelessReply;
use mvfstr_proto::Stop;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TlsConnId;
use mvfstr_proto::TlsHost;
use mvfstr_proto::TlsPoll;
use mvfstr_proto::TransportErrorCode;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxLimits;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxOutcome;
use mvfstr_proto::TxReport;
use mvfstr_proto::TxSeqRange;
use roxygen_runtime::panic::discard_panic;
use roxygen_runtime::worker::ContainedPanicScope;
use roxygen_runtime::worker::WorkerContext;
use roxygen_runtime::worker::WorkerQuiescing;
use rustls::crypto::SecureRandom;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;

use crate::Conn;
use crate::ConnHandle;
use crate::ConnInfo;
use crate::DatagramSink;
use crate::DriverConnectError;
use crate::PollOutcome;
use crate::QuicApplication;
use crate::QuicSession;
use crate::Refusal;
use crate::SendSink;
use crate::Steering;
use crate::UnitKind;
use crate::WorkBudget;
use crate::budget::FlushCost;
use crate::slab::Slab;
use crate::steer::Member;
use crate::steer::Steer;
use crate::steer::handoff_lifetime;
use crate::timers::HostTimers;
use crate::timers::HostWake;
use crate::timers::Kind;
use crate::timers::Timers;
use crate::wake;
use crate::wake::Close;
use crate::wake::ConnWake;
use crate::wake::Shared;

/// Turns per poll before the task yields to the worker.
const TURN_BUDGET: usize = 4;

/// Receive batches per socket per turn.
pub(crate) const RX_BATCHES: usize = 4;

/// Transmit attempts that may go back to the tail of one transmit phase after filling their
/// batch; later full batches wait for the next phase.
const REQUEUES_PER_PHASE: u64 = 1024;

/// How long after a quiesce's grace period the connections still open are aborted.
const QUIESCE_FORCE_AFTER: Duration = Duration::from_secs(1);

/// The grace period of a quiesce that the worker starts by draining.
const WORKER_QUIESCE_GRACE: Duration = Duration::from_secs(5);

/// The backend key stateless replies are sent under; the slab never hands out its index.
const STATELESS: ConnKey = ConnKey {
    index: u32::MAX,
    generation: 0,
};

/// The bytes one connection's pull steps may stage in a turn, so the connection leaves the rest of
/// the turn to the others on its worker: sixteen polls at the 64 KiB per-stream cap, as many as
/// Roxygen's owned HTTP/2 driver makes of a connection per turn.
pub(crate) const TURN_STAGING: u64 = 16 * 64 * 1024;

/// The least a poll counts against [`TURN_STAGING`], whatever it staged: 16 KiB, the low-water mark
/// a stream's allowance must reach before the stream is polled, unless its share or stream credit
/// is smaller. A turn so makes at most 64 polls of a connection, as many as h2load's window of 64
/// streams.
pub(crate) const POLL_CHARGE: u64 = 16 * 1024;

/// Connections the intake takes from the timers and the ready queue per turn.
const INTAKE_PER_TURN: usize = 256;

/// `poll_send` and `poll_datagrams` calls per turn across all connections.
const POLLS_PER_TURN: usize = 1024;

/// Connection attempts handled per turn; later Initials wait for the next turn. It also caps,
/// apart from the attempts, the handshakes the driver starts on its TLS host per turn.
const HANDSHAKES_PER_TURN: usize = 8;

/// The bytes of the Initials kept for a later turn once a turn's connection attempts run out,
/// counted by datagram length; an Initial past them is dropped, and its client sends it again.
/// 4 MiB holds the first flights of about 1,700 clients whose ClientHello takes two datagrams.
const WAITING_INITIAL_BYTES: usize = 4 * 1024 * 1024;

/// The per-turn caps and the transmit batch limit; tests lower them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// The most datagrams of one transmit attempt, below the backend's own limit.
    pub(crate) max_segments: u16,
    /// Transmit attempts that may go back to the tail of one transmit phase.
    pub(crate) requeues: u64,
    /// Connections the intake takes from the timers and the ready queue per turn.
    pub(crate) intake: usize,
    /// `poll_send` and `poll_datagrams` calls per turn across all connections.
    pub(crate) polls: usize,
    /// Bytes one connection's pull steps may stage per turn, each poll counted at least
    /// [`POLL_CHARGE`].
    pub(crate) turn_staging: u64,
    /// Connection attempts handled per turn, and apart from them, handshakes started on the TLS
    /// host per turn.
    pub(crate) handshakes: usize,
    /// The most bytes of the Initials kept for a later turn once a turn's connection attempts
    /// run out, and of the datagrams other workers may hand to this one's inbox.
    pub(crate) waiting_initial_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_segments: u16::MAX,
            requeues: REQUEUES_PER_PHASE,
            intake: INTAKE_PER_TURN,
            polls: POLLS_PER_TURN,
            turn_staging: TURN_STAGING,
            handshakes: HANDSHAKES_PER_TURN,
            waiting_initial_bytes: WAITING_INITIAL_BYTES,
        }
    }
}

/// The most datagrams of one transmit attempt, and of one receive chunk, under a work budget.
const BUDGET_BATCH: usize = 64;

/// The most stale transmit slots one unit of work skips, slab entries one walks in a quiesce
/// sweep, and parked connections one marks for another attempt, under a work budget.
const BUDGET_STEP: usize = 64;

/// The most slab entries the quiesce sweeps walk in one turn, under a work budget.
const SWEEP_PER_TURN: u32 = 1024;

/// The phases of a turn, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Intake,
    FirstApp,
    FirstTransmit,
    Receive,
    /// The calls into the TLS host for the connections due one. A driver without a TLS host
    /// skips it, and a turn that would resume at it resumes after it unless a connection is due.
    Tls,
    SecondApp,
    SecondTransmit,
}

impl Phase {
    const ALL: [Phase; 7] = [
        Phase::Intake,
        Phase::FirstApp,
        Phase::FirstTransmit,
        Phase::Receive,
        Phase::Tls,
        Phase::SecondApp,
        Phase::SecondTransmit,
    ];

    /// Returns the phase after this one; a turn ends after its second transmit phase.
    fn next(self) -> Phase {
        match self {
            Phase::Intake => Phase::FirstApp,
            Phase::FirstApp => Phase::FirstTransmit,
            Phase::FirstTransmit => Phase::Receive,
            Phase::Receive => Phase::Tls,
            Phase::Tls => Phase::SecondApp,
            Phase::SecondApp => Phase::SecondTransmit,
            Phase::SecondTransmit => Phase::Intake,
        }
    }
}

/// The endpoint: what the driver task and the [`EndpointHandle`](crate::EndpointHandle) share.
pub(crate) struct Core<A: QuicApplication, B: Backend> {
    worker: WorkerContext,
    shared: Arc<Shared>,
    endpoint: RefCell<Endpoint>,
    slab: RefCell<Slab<Entry<A::Session, B>>>,
    app: RefCell<A>,
    server: Option<Server<B>>,
    options: B::Options,
    limits: Limits,
    sched: RefCell<Sched>,
    /// Turns run so far.
    turns: Cell<u64>,
    /// `poll_send` and `poll_datagrams` calls in this turn.
    turn_polls: Cell<usize>,
    /// Connection attempts handled in this turn.
    turn_handshakes: Cell<usize>,
    /// `poll_send` calls that returned `Ready` without pushing a byte or finishing.
    empty_ready_polls: Cell<u64>,
    requeues: Cell<u64>,
    socket_stops: Cell<u64>,
    contained_panics: Cell<u64>,
    dropped_initials: Cell<u64>,
    steered_out: Cell<u64>,
    steered_in: Cell<u64>,
    sent_packets: Cell<u64>,
    sent_datagrams: Cell<u64>,
    phase_pacing_wakes: Cell<u64>,
    /// The sockets' transmit counters, taken after each flush.
    tx_counters: Cell<TxCounters>,
    recv_batch_calls: Cell<u64>,
    receive_passes: Cell<u64>,
    deadline_rearms: Cell<u64>,
    /// The endpoint's count of datagrams dropped for their source port, read without borrowing
    /// the endpoint, because a certificate resolver running inside it may read the counters.
    src_port_drops: SrcPortDrops,
    /// The counters as the driver ends, for its handles to read afterwards.
    last: Rc<Cell<EndpointStats>>,
    /// Set by [`EndpointHandle::abort`](crate::EndpointHandle::abort): the next turn ends the
    /// driver.
    aborted: Cell<bool>,
    /// The woken streams of the connection being polled, then the streams its pull steps polled.
    pull_ids: RefCell<Vec<StreamId>>,
    rx_scratch: RefCell<RxScratch>,
    /// The driver's place in the group that steers new connections over the workers sharing its
    /// server address.
    steering: Option<Member>,
    /// The work budget the driver's polls run under, if any.
    budget: Option<WorkBudget>,
    /// The TLS host that runs the handshakes of connections with an External TLS backend, if any.
    tls: Option<TlsHosting>,
    /// The phase the next turn starts at: the intake, or the phase after the one a check stopped.
    resume: Cell<Phase>,
    /// Whether a transmit phase has stopped since the last receive phase began.
    rx_owed: Cell<bool>,
    /// Whether a check has stopped the running poll.
    stopped: Cell<bool>,
    /// Whether the transmit queue has the turn under a work budget: while it holds slots, its next
    /// slot goes before a due pacing wake. Serves and pops take turns, across stops.
    queue_turn: Cell<bool>,
    /// Under a work budget, the leftover wait being measured: the reading of the stop that began
    /// it, and the transmit queue's pop count at which the last slot the stop left pops.
    leftover: Cell<Option<(Instant, u64)>>,
    /// Under a work budget, what the end-of-phase flush of the server socket has cost per
    /// datagram, from which a transmit phase predicts the cost of flushing what it has staged.
    flush_cost: Cell<FlushCost>,
    /// Makes the next turn panic outside every connection's guard.
    #[cfg(test)]
    fail_turn: Cell<bool>,
    /// The connection IDs issued after each connection's first, in the order the endpoint routes
    /// them.
    #[cfg(test)]
    issued: RefCell<Vec<mvfstr_proto::ConnectionId>>,
    #[cfg(test)]
    record: RefCell<TxRecord>,
}

/// The server socket and what accepting needs.
pub(crate) struct Server<B> {
    socket: RefCell<B>,
    addr: SocketAddr,
    config: Arc<ServerConfig>,
    /// Whether the socket holds datagrams until their release (kernel release), as probed at bind.
    release: bool,
}

impl<B: Backend> Server<B> {
    pub(crate) fn new(socket: B, config: Arc<ServerConfig>) -> std::io::Result<Self> {
        Ok(Self {
            addr: socket.local_addr()?,
            release: socket.caps().release.epoch().is_some(),
            socket: RefCell::new(socket),
            config,
        })
    }

    pub(crate) fn config(&self) -> &Arc<ServerConfig> {
        &self.config
    }

    /// Returns the server socket's capabilities, fixed at bind.
    pub(crate) fn caps(&self) -> TxCaps {
        *self.socket.borrow().caps()
    }
}

/// The driver's TLS host and the connections due a call into it.
struct TlsHosting {
    host: RefCell<Box<dyn TlsHost>>,
    /// The connections whose handshakes have started that may have an input for the host, oldest
    /// first.
    due: RefCell<VecDeque<ConnKey>>,
    /// The connections that may have their first input for the host, oldest first.
    waiting: RefCell<VecDeque<ConnKey>>,
    ready: Arc<TlsReady>,
}

impl TlsHosting {
    /// Returns whether a connection is due a call.
    fn has_due(&self) -> bool {
        !self.due.borrow().is_empty() || !self.waiting.borrow().is_empty()
    }

    /// Returns the list a connection due a call waits on: the list of handshakes under way if
    /// `started` is true, else the list of handshakes waiting to start.
    fn list(&self, started: bool) -> &RefCell<VecDeque<ConnKey>> {
        if started { &self.due } else { &self.waiting }
    }

    /// Returns whether a connection is due a call, or the host may hold completed steps the
    /// driver has not taken.
    fn has_work(&self) -> bool {
        self.has_due() || self.ready.flagged.load(Ordering::SeqCst)
    }
}

/// The state a TLS phase keeps from one connection to the next.
struct TlsPass {
    /// The phase's reading, which its steps are delivered at.
    now: Instant,
    /// The phase's reading until its first check takes it.
    reading: Option<Instant>,
    /// The number of handshakes the phase has started.
    starts: usize,
}

/// The waker of a TLS host's completed steps: it flags them for the next intake and wakes the
/// driver task.
struct TlsReady {
    shared: Arc<Shared>,
    /// Whether the host may hold steps that `poll_ready` has not returned.
    flagged: AtomicBool,
}

impl Wake for TlsReady {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.flagged.store(true, Ordering::SeqCst);
        self.shared.wake_task();
    }
}

/// Returns the ID of a connection at the driver's TLS host: its slab key's generation in the high
/// 32 bits and its index in the low 32.
fn tls_id(key: ConnKey) -> TlsConnId {
    TlsConnId(u64::from(key.generation) << 32 | u64::from(key.index))
}

/// Returns the slab key of the connection with TLS host ID `id`.
fn tls_key(id: TlsConnId) -> ConnKey {
    ConnKey {
        index: id.0 as u32,
        generation: (id.0 >> 32) as u32,
    }
}

/// The receive path's reused vectors, empty between batches, so they are not allocated again for
/// each batch. They hold borrows of a socket's buffers during a batch only, so they are kept here
/// with `'static` element types and [`recycle`]d to the batch's lifetimes and back.
#[derive(Default)]
struct RxScratch {
    routed: Vec<Routed<'static>>,
    datagrams: Vec<RxDatagram<'static>>,
}

/// A datagram routed to a connection: the connection, the datagram's place in its batch, its
/// metadata and its bytes.
type Routed<'a> = (ConnKey, usize, &'a RxMeta, &'a mut [u8]);

/// Sorts routed datagrams by connection, each connection's in arrival order. The sort is in
/// place: a stable sort would allocate scratch for large batches.
fn by_connection(routed: &mut [Routed<'_>]) {
    routed.sort_unstable_by_key(|&(key, place, ..)| (key.index, key.generation, place));
}

/// An Initial kept for a later turn, or a datagram another worker handed over: a copy of the
/// datagram, routed again when its turn comes, since by then it may belong to a connection that
/// an Initial ahead of it created.
pub(crate) struct Waiting {
    pub(crate) meta: RxMeta,
    pub(crate) datagram: Vec<u8>,
}

/// Datagrams kept to be routed again later, oldest first, and the bytes they hold, counted by
/// datagram length.
#[derive(Default)]
pub(crate) struct WaitingQueue {
    datagrams: VecDeque<Waiting>,
    bytes: usize,
}

impl WaitingQueue {
    /// Returns whether a datagram of `len` bytes fits beside those queued within `bound` bytes.
    pub(crate) fn fits(&self, len: usize, bound: usize) -> bool {
        len <= bound.saturating_sub(self.bytes)
    }

    pub(crate) fn push_back(&mut self, waiting: Waiting) {
        self.bytes += waiting.datagram.len();
        self.datagrams.push_back(waiting);
    }

    fn pop_front(&mut self) -> Option<Waiting> {
        let waiting = self.datagrams.pop_front()?;
        self.bytes -= waiting.datagram.len();
        Some(waiting)
    }

    /// Puts back first a datagram that [`pop_front`](Self::pop_front) took.
    fn push_front(&mut self, waiting: Waiting) {
        self.bytes += waiting.datagram.len();
        self.datagrams.push_front(waiting);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Empties the queue, yielding its datagrams oldest first.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = Waiting> + '_ {
        self.bytes = 0;
        self.datagrams.drain(..)
    }
}

/// A connection's own connected socket, with the wakers for its receive and writable polls.
struct OwnSocket<B> {
    socket: B,
    rx_waker: Waker,
    tx_waker: Waker,
}

/// One connection and its session.
struct Entry<S, B> {
    conn: Connection,
    session: S,
    wake: Arc<ConnWake>,
    /// The connection's own connected socket; `None` on the server socket.
    socket: Option<Box<OwnSocket<B>>>,
    app_waker: Waker,
    /// The connection's own socket holds runs behind an EAGAIN until it is writable.
    tx_blocked: bool,
    /// On the list of connections the server socket refused.
    parked: bool,
    /// Queued for a transmit attempt, with a live slot.
    dirty: bool,
    /// The generation of the connection's transmit slot. A pacing serve bumps it, and a slot pushed
    /// with an older one is stale.
    slot_generation: u32,
    /// Queued for an application phase.
    app_queued: bool,
    /// `poll_session` is due.
    app_due: bool,
    /// `on_quiesce` is due.
    quiesce_due: bool,
    /// The connection's handshake runs on the driver's TLS host.
    tls_hosted: bool,
    /// On one of the TLS host's lists of connections due a call.
    tls_queued: bool,
    /// The TLS host has been handed the connection's first input.
    tls_started: bool,
    /// The connection's entry in the deadline timers: the earlier of its own deadline and its
    /// session's.
    deadline: Option<Instant>,
    /// The session's deadline, from [`QuicSession::deadline`] after its last callback.
    session_deadline: Option<Instant>,
    /// The session deadline `poll_session` last ran for; the same deadline again is not re-armed.
    served_deadline: Option<Instant>,
    /// The connection's entry in the pacing timers.
    pacing: Option<Instant>,
    /// Which pacing timers hold `pacing`, from the connection's build horizon.
    pacing_kind: Kind,
    /// Whether the connection's transport config turns pacing on.
    paces: bool,
    /// The reading the connection's last transmit attempt ran at, to assert that its attempts and
    /// reports do not go back in time.
    #[cfg(debug_assertions)]
    attempted_at: Option<Instant>,
    /// The waker handed to each stream's producer.
    stream_wakers: HashMap<StreamId, Waker>,
    /// The turn of `pull_work`.
    pull_turn: u64,
    /// What the pull steps of turn `pull_turn` counted against `Limits::turn_staging`.
    pull_work: u64,
    /// The waker handed to the datagram producer, made for its first poll.
    datagram_waker: Option<Waker>,
    /// The datagram producer's waker has fired and the producer has not returned `Pending` since.
    datagrams_ready: bool,
}

/// The queues of the turn.
struct Sched {
    /// The slots of the connections due a transmit attempt in the next transmit phase.
    dirty: Vec<Slot>,
    /// Connections due an application phase.
    app: KeyQueue,
    /// Connections due an application phase in the next turn: streams stayed pull-ready after
    /// their pull step.
    app_next: Vec<ConnKey>,
    /// Connections with pull-ready streams that the turn's poll cap left without a poll; the next
    /// turn serves them before every other. Each keeps its `app_queued` flag meanwhile.
    app_first: Vec<ConnKey>,
    /// Connections whose own socket may be readable.
    rx: KeyQueue,
    /// The server socket may hold more datagrams than the turn took.
    rx_more: bool,
    /// Initials for new connections that came after their turn's connection attempts ran out,
    /// oldest first.
    waiting: WaitingQueue,
    /// Connections whose attempt the server socket refused, waiting for it to take runs again,
    /// oldest first.
    parked: VecDeque<ConnKey>,
    /// The server socket holds runs behind an EAGAIN until it is writable.
    server_blocked: bool,
    reports: Vec<(ConnKey, TxReport)>,
    /// The transmit phase's queue, empty between phases unless a stop left the rest of it for the
    /// next transmit phase.
    tx_queue: SlotQueue,
    /// An empty list whose allocation the next list taken whole reuses.
    spare: Vec<ConnKey>,
    timers: Timers,
    host_wake: HostWake,
    /// Fires when the worker starts shutting down; `None` once it has.
    quiescing: Option<WorkerQuiescing>,
    /// A quiesce requested through the handle, with its grace period.
    quiesce_request: Option<Duration>,
    quiesce: Option<Quiesce>,
    /// Under a work budget, the quiesce sweeps not finished.
    sweeps: Sweeps,
    /// Connections taken from the ready queue and not yet served, oldest first, each with the
    /// time the intake took it.
    ready: VecDeque<(Instant, ConnKey)>,
    /// The connections the intake takes from the ready queue at once, empty between turns.
    fresh: Vec<ConnKey>,
    /// Where a stop left the server socket's last batch; the next receive phase routes the rest
    /// before it reads the socket again.
    rx_resume: Option<BatchCursor>,
    /// The connection attempt a stop came before, which the next receive phase takes up before
    /// its other work.
    kept_accept: Option<Incoming>,
    /// The connection a stop left at the head of `rx` inside the batch of its own socket, and its
    /// place there; the connection's next receive delivers the rest before it reads the socket.
    own_resume: Option<(ConnKey, BatchCursor)>,
}

/// A place in a socket's last batch, from which routing or delivery goes on without stepping over
/// the datagrams before it.
#[derive(Clone, Copy, Debug, Default)]
struct BatchCursor {
    /// The number of datagrams handled, counted from the batch's first.
    handled: usize,
    /// The number of buffers whose datagrams have all been handled.
    buffers: usize,
    /// The number of datagrams of the next buffer that have been handled.
    within: usize,
}

/// Counters of one endpoint driver, from [`EndpointHandle::stats`](crate::EndpointHandle::stats).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointStats {
    /// Turns run.
    pub turns: u64,
    /// `poll_send` calls that returned `Ready` without pushing a byte or finishing, each treated
    /// as `Pending`.
    pub empty_ready_polls: u64,
    /// Transmit attempts that filled their batch and went back to the tail of the phase.
    pub requeues: u64,
    /// Transmit attempts a socket refused; each connection gets another attempt once the socket
    /// takes runs again.
    pub socket_stops: u64,
    /// Panics contained without ending the driver: in a connection's session or transport, which
    /// tore that connection down, and in the application's `accept` or `quiesce`, a session's
    /// `Drop`, or the creation of a connection.
    pub contained_panics: u64,
    /// Initials for new connections dropped because they did not fit the bytes left in the queue
    /// of those waiting for a later turn, or in the inbox of the worker they were steered to.
    pub dropped_initials: u64,
    /// Datagrams of new connections handed to another worker's driver (worker steering).
    pub steered_out: u64,
    /// Datagrams other workers' drivers handed to this one.
    pub steered_in: u64,
    /// Packets the connections sent: the sum of their `ConnStats::sent_packets`.
    pub sent_packets: u64,
    /// UDP datagrams the connections sent, each segment of a GSO send counted.
    pub sent_datagrams: u64,
    /// Pacing wakes taken inside transmit phases, between attempts.
    pub phase_pacing_wakes: u64,
    /// Datagrams dropped without a reply for a blocklisted source port: those for unknown
    /// connections, and those that would have moved a server connection to a blocked port
    /// (mvfst's `INVALID_SRC_PORT`).
    pub invalid_src_port: u64,
    /// `sendmmsg` calls on the driver's sockets, those that failed included.
    pub sendmmsg_calls: u64,
    /// Messages of those calls that the kernel accepted: GSO sends and single datagrams. A failed
    /// call does not add to it, and a partial call adds only its accepted prefix.
    pub sendmmsg_messages: u64,
    /// `sendmmsg` calls whose accepted messages carried the runs of more than one connection, so a
    /// failed call does not count and a partial call counts by its accepted prefix alone.
    pub multi_connection_calls: u64,
    /// GSO sends the kernel refused with EIO or EINVAL, whose datagrams went again as single
    /// messages.
    pub gso_retries: u64,
    /// Sockets that stopped using GSO after the kernel refused three GSO sends whose datagrams it
    /// then took alone.
    pub gso_disabled: u64,
    /// `recv_batch` calls the driver makes on its connections. The call inside `Endpoint::accept`
    /// on a new server connection's first datagram is not counted.
    pub recv_batch_calls: u64,
    /// Passes over a connection after one or more of those calls, which queue its application,
    /// TLS and transmit work and resync its deadline.
    pub receive_passes: u64,
    /// Moves of a connection's deadline timer.
    pub deadline_rearms: u64,
}

/// A graceful shutdown in progress. A step's time is `None` once the step is taken, or when it lies
/// past the clock's range.
#[derive(Clone, Copy, Debug)]
struct Quiesce {
    /// When the connections still open are closed with NO_ERROR.
    close_at: Option<Instant>,
    /// When the connections still open are aborted.
    abort_at: Option<Instant>,
}

/// The action a quiesce sweep takes on each connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SweepKind {
    /// Notifies the connection's session of the quiesce.
    Notify,
    /// Closes the connection with NO_ERROR.
    Close,
    /// Aborts the connection.
    Abort,
}

impl SweepKind {
    const ALL: [SweepKind; 3] = [SweepKind::Notify, SweepKind::Close, SweepKind::Abort];

    fn bit(self) -> u8 {
        match self {
            SweepKind::Notify => 1,
            SweepKind::Close => 2,
            SweepKind::Abort => 4,
        }
    }
}

/// The quiesce sweeps not finished under a work budget. A quiesce starts each kind at most once,
/// in the order of [`SweepKind::ALL`], so the sweeps walk in that order and only the first has
/// walked any of the slab.
#[derive(Clone, Copy, Debug, Default)]
struct Sweeps {
    /// The kinds not finished, as [`SweepKind::bit`]s.
    pending: u8,
    /// The next slab index the first of them walks.
    next: u32,
}

impl Sweeps {
    fn push(&mut self, kind: SweepKind) {
        debug_assert!(
            self.pending < kind.bit(),
            "a quiesce starts its sweeps in kind order, each once"
        );
        self.pending |= kind.bit();
    }

    /// Returns the first sweep not finished, with the next slab index it walks.
    fn front(&self) -> Option<(SweepKind, u32)> {
        SweepKind::ALL
            .into_iter()
            .find(|kind| self.pending & kind.bit() != 0)
            .map(|kind| (kind, self.next))
    }

    /// Finishes the first sweep not finished.
    fn pop_front(&mut self) {
        self.pending &= self.pending.wrapping_sub(1);
        self.next = 0;
    }

    fn is_empty(&self) -> bool {
        self.pending == 0
    }
}

/// Which source of intake work waited longest.
enum Due {
    Deadline,
    /// A pacing wake, of either pacing kind.
    Pacing(Kind),
    Wake,
}

/// What a check between the attempts of a transmit phase took.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Take {
    /// The check, if one ran, did not find a due pacing wake.
    Nothing,
    /// A wake whose connection makes the next attempt. A slot of the connection that waits in the
    /// phase's queue or in [`Sched::dirty`] is retired.
    Serve(ConnKey),
    /// A wake whose slot is empty, as its connection was freed.
    Deferred,
}

/// What the task does after a turn.
enum Next {
    /// Wait for a wake.
    Park,
    /// Run another turn.
    Again,
    /// A check of the work budget stopped the poll; the next poll continues the turn.
    Stop,
    /// The driver has finished.
    Done,
}

/// The random source of a TLS config.
struct SecureRng(&'static dyn SecureRandom);

impl Random for SecureRng {
    fn fill(&mut self, dest: &mut [u8]) {
        self.0
            .fill(dest)
            .expect("the crypto provider's random source works");
    }
}

impl<A: QuicApplication, B: Backend> Core<A, B> {
    pub(crate) fn new(
        worker: &WorkerContext,
        endpoint: Endpoint,
        app: A,
        server: Option<Server<B>>,
        options: B::Options,
        limits: Limits,
        steering: Option<(Arc<Steering>, u16)>,
        timers: HostTimers,
    ) -> Self {
        let shared = Arc::new(Shared::default());
        let lifetime = server
            .as_ref()
            .and_then(|server| handoff_lifetime(server.config().transport()));
        let steering = steering.map(|(group, index)| {
            group.join(
                index,
                Arc::clone(&shared),
                lifetime,
                limits.waiting_initial_bytes,
            )
        });
        let src_port_drops = endpoint.src_port_drops();
        Self {
            worker: worker.clone(),
            shared,
            endpoint: RefCell::new(endpoint),
            slab: RefCell::new(Slab::new()),
            app: RefCell::new(app),
            server,
            options,
            limits,
            sched: RefCell::new(Sched {
                dirty: Vec::new(),
                app: KeyQueue::default(),
                app_next: Vec::new(),
                app_first: Vec::new(),
                rx: KeyQueue::default(),
                rx_more: false,
                waiting: WaitingQueue::default(),
                parked: VecDeque::new(),
                server_blocked: false,
                reports: Vec::new(),
                tx_queue: SlotQueue::default(),
                spare: Vec::new(),
                timers: Timers::default(),
                host_wake: HostWake::new(worker.host(), timers),
                quiescing: Some(worker.quiescing()),
                quiesce_request: None,
                quiesce: None,
                sweeps: Sweeps::default(),
                ready: VecDeque::new(),
                fresh: Vec::new(),
                rx_resume: None,
                kept_accept: None,
                own_resume: None,
            }),
            turns: Cell::new(0),
            turn_polls: Cell::new(0),
            turn_handshakes: Cell::new(0),
            empty_ready_polls: Cell::new(0),
            requeues: Cell::new(0),
            socket_stops: Cell::new(0),
            contained_panics: Cell::new(0),
            dropped_initials: Cell::new(0),
            steered_out: Cell::new(0),
            steered_in: Cell::new(0),
            sent_packets: Cell::new(0),
            sent_datagrams: Cell::new(0),
            phase_pacing_wakes: Cell::new(0),
            tx_counters: Cell::new(TxCounters::default()),
            recv_batch_calls: Cell::new(0),
            receive_passes: Cell::new(0),
            deadline_rearms: Cell::new(0),
            src_port_drops,
            last: Rc::default(),
            aborted: Cell::new(false),
            pull_ids: RefCell::new(Vec::new()),
            rx_scratch: RefCell::default(),
            steering,
            budget: None,
            tls: None,
            resume: Cell::new(Phase::Intake),
            rx_owed: Cell::new(false),
            stopped: Cell::new(false),
            queue_turn: Cell::new(false),
            leftover: Cell::new(None),
            flush_cost: Cell::default(),
            #[cfg(test)]
            fail_turn: Cell::new(false),
            #[cfg(test)]
            issued: RefCell::default(),
            #[cfg(test)]
            record: RefCell::default(),
        }
    }

    /// Runs the driver's polls under `budget`, which also caps every transmit attempt at
    /// [`BUDGET_BATCH`] datagrams.
    pub(crate) fn with_budget(mut self, budget: Option<WorkBudget>) -> Self {
        if budget.is_some() {
            self.limits.max_segments = self.limits.max_segments.min(BUDGET_BATCH as u16);
        }
        self.budget = budget;
        self
    }

    /// Runs the handshakes of the connections with an External TLS backend on `host`.
    pub(crate) fn with_tls_host(mut self, host: Option<Box<dyn TlsHost>>) -> Self {
        self.tls = host.map(|host| TlsHosting {
            host: RefCell::new(host),
            due: RefCell::default(),
            waiting: RefCell::default(),
            ready: Arc::new(TlsReady {
                shared: Arc::clone(&self.shared),
                flagged: AtomicBool::new(false),
            }),
        });
        self
    }

    /// Returns the waker the TLS host wakes when it completes a step, if the driver has a host.
    pub(crate) fn tls_waker(&self) -> Option<Waker> {
        let tls = self.tls.as_ref()?;
        Some(Waker::from(Arc::clone(&tls.ready)))
    }

    /// Makes the next turn panic outside every connection's guard.
    #[cfg(test)]
    pub(crate) fn fail_next_turn(&self) {
        self.fail_turn.set(true);
        self.shared.wake_task();
    }

    /// Returns the number of connections that wait for the server socket to take runs again.
    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.sched.borrow().parked.len()
    }

    /// Returns the slab indices of the connections parked on the server socket, in order.
    #[cfg(test)]
    pub(crate) fn parked_indices(&self) -> Vec<u32> {
        self.sched
            .borrow()
            .parked
            .iter()
            .map(|key| key.index)
            .collect()
    }

    /// Returns one past the highest slab index handed out so far.
    #[cfg(test)]
    pub(crate) fn slots(&self) -> u32 {
        self.slab.borrow().end()
    }

    /// Returns the connection IDs issued after each connection's first, in the order the endpoint
    /// routed them.
    #[cfg(test)]
    pub(crate) fn issued_cids(&self) -> Vec<mvfstr_proto::ConnectionId> {
        self.issued.borrow().clone()
    }

    /// Returns every connection's counters, in slot order.
    #[cfg(test)]
    pub(crate) fn conn_stats(&self) -> Vec<mvfstr_proto::ConnStats> {
        let slab = self.slab.borrow();
        (0..slab.end())
            .filter_map(|index| {
                let key = slab.key_at(index)?;
                let slot = slab.slot(index)?;
                let mut slot = slot.borrow_mut();
                slot.get(key).map(|entry| entry.conn.stats())
            })
            .collect()
    }

    /// Returns every connection's build horizon and the timers that hold its pacing wakes, in
    /// slot order.
    #[cfg(test)]
    pub(crate) fn build_horizons(&self) -> Vec<(Duration, Kind)> {
        let slab = self.slab.borrow();
        (0..slab.end())
            .filter_map(|index| {
                let key = slab.key_at(index)?;
                let slot = slab.slot(index)?;
                let mut slot = slot.borrow_mut();
                slot.get(key)
                    .map(|entry| (entry.conn.build_horizon(), entry.pacing_kind))
            })
            .collect()
    }

    /// Returns how many times the host wake chose the timerfd for a pacing wake.
    #[cfg(test)]
    pub(crate) fn fine_plans(&self) -> u32 {
        self.sched.borrow().host_wake.fine_plans()
    }

    /// Returns what the transmit phases have done so far.
    #[cfg(test)]
    pub(crate) fn tx_record(&self) -> TxRecord {
        self.record.borrow().clone()
    }

    /// Returns the lengths of the application queue and of the transmit queue.
    #[cfg(test)]
    pub(crate) fn queued_keys(&self) -> (usize, usize) {
        let sched = self.sched.borrow();
        (sched.app.len(), sched.tx_queue.len())
    }

    /// Marks the connection in slot `index` dirty, as receive or application work does, and wakes
    /// the driver.
    #[cfg(test)]
    pub(crate) fn mark_dirty_at(&self, index: u32) {
        let key = self.slab.borrow().key_at(index);
        if let Some(key) = key {
            self.with_entry(key, "test", |entry| self.mark_dirty(key, entry));
        }
        self.shared.wake_task();
    }

    /// Arms the pacing wake of the connection in slot `index` for `at`, as its last attempt
    /// would, and wakes the driver.
    #[cfg(test)]
    pub(crate) fn arm_pacing_at(&self, index: u32, at: Instant) {
        let key = self.slab.borrow().key_at(index);
        if let Some(key) = key {
            self.with_entry(key, "test", |entry| self.set_pacing(key, entry, Some(at)));
        }
        self.shared.wake_task();
    }

    /// Returns how many slots in the transmit queue and the dirty list carry the current slot
    /// generation of the connection in slot `index`.
    #[cfg(test)]
    pub(crate) fn live_slots(&self, index: u32) -> usize {
        let Some(key) = self.slab.borrow().key_at(index) else {
            return 0;
        };
        let Some(generation) = self.with_entry(key, "test", |entry| entry.slot_generation) else {
            return 0;
        };
        let sched = self.sched.borrow();
        let live = Slot { key, generation };
        sched
            .tx_queue
            .slots
            .iter()
            .chain(&sched.dirty)
            .filter(|&&slot| slot == live)
            .count()
    }

    /// Returns the slab indices of the transmit queue's slots, from its head.
    #[cfg(test)]
    pub(crate) fn tx_queue_indices(&self) -> Vec<u32> {
        let sched = self.sched.borrow();
        sched
            .tx_queue
            .slots
            .iter()
            .map(|slot| slot.key.index)
            .collect()
    }

    /// Returns how many Initials wait for a later turn, and whether a connection attempt is kept
    /// for the next receive phase.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> (usize, bool) {
        let sched = self.sched.borrow();
        (sched.waiting.datagrams.len(), sched.kept_accept.is_some())
    }

    /// Returns the bytes of the Initials that wait for a later turn.
    #[cfg(test)]
    pub(crate) fn waiting_bytes(&self) -> usize {
        self.sched.borrow().waiting.bytes
    }

    /// Returns the endpoint's counters.
    pub(crate) fn stats(&self) -> EndpointStats {
        let tx = self.tx_counters.get();
        EndpointStats {
            turns: self.turns.get(),
            empty_ready_polls: self.empty_ready_polls.get(),
            requeues: self.requeues.get(),
            socket_stops: self.socket_stops.get(),
            contained_panics: self.contained_panics.get(),
            dropped_initials: self.dropped_initials.get(),
            steered_out: self.steered_out.get(),
            steered_in: self.steered_in.get(),
            sent_packets: self.sent_packets.get(),
            sent_datagrams: self.sent_datagrams.get(),
            phase_pacing_wakes: self.phase_pacing_wakes.get(),
            invalid_src_port: self.src_port_drops.get(),
            sendmmsg_calls: tx.calls,
            sendmmsg_messages: tx.messages,
            multi_connection_calls: tx.multi_connection_calls,
            gso_retries: tx.gso_retries,
            gso_disabled: tx.gso_disabled,
            recv_batch_calls: self.recv_batch_calls.get(),
            receive_passes: self.receive_passes.get(),
            deadline_rearms: self.deadline_rearms.get(),
        }
    }

    /// Adds the transmit counters a socket kept since they were last taken.
    fn add_tx_counters(&self, counted: TxCounters) {
        let mut total = self.tx_counters.get();
        total.calls += counted.calls;
        total.messages += counted.messages;
        total.multi_connection_calls += counted.multi_connection_calls;
        total.gso_retries += counted.gso_retries;
        total.gso_disabled += counted.gso_disabled;
        self.tx_counters.set(total);
    }

    /// Replaces the source ports the endpoint refuses.
    pub(crate) fn set_src_port_blocklist(&self, blocklist: Option<Arc<SrcPortBlocklist>>) {
        self.endpoint.borrow_mut().set_src_port_blocklist(blocklist);
    }

    /// Returns where the counters are kept once the driver has ended.
    pub(crate) fn last_stats(&self) -> Rc<Cell<EndpointStats>> {
        Rc::clone(&self.last)
    }

    /// Returns the server socket's address.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(|server| server.addr)
    }

    /// Returns the server socket's capabilities.
    pub(crate) fn server_caps(&self) -> Option<TxCaps> {
        self.server.as_ref().map(Server::caps)
    }

    /// Opens a client connection on its own connected socket. A connect that fails drops
    /// `session` under a guard, as a failed server attempt does.
    pub(crate) fn connect(
        &self,
        remote: SocketAddr,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
        options: ConnOptions,
        session: A::Session,
    ) -> Result<ConnHandle, DriverConnectError> {
        let paces = options
            .transport
            .as_ref()
            .unwrap_or_else(|| config.transport())
            .pacing();
        match self.create_client(remote, server_name, &config, options) {
            Ok((key, conn, socket)) => {
                let hosted = matches!(config.tls(), ClientTls::External);
                let wake = self.insert(key, conn, session, Some(socket), paces, hosted);
                // The call may come from outside the driver's own poll.
                self.shared.wake_task();
                Ok(ConnHandle::new(wake))
            }
            Err(error) => {
                self.drop_guarded(session);
                Err(error)
            }
        }
    }

    /// Creates a client connection, and its socket, under a key the slab has reserved for it.
    fn create_client(
        &self,
        remote: SocketAddr,
        server_name: ServerName<'static>,
        config: &Arc<ClientConfig>,
        options: ConnOptions,
    ) -> Result<(ConnKey, Connection, B), DriverConnectError> {
        if remote.ip().is_unspecified() || remote.port() == 0 {
            return Err(mvfstr_proto::ConnectError::InvalidRemoteAddress(remote).into());
        }
        let quiescing = {
            let sched = self.sched.borrow();
            sched.quiesce.is_some() || sched.quiesce_request.is_some()
        };
        if quiescing {
            // A connection opened now could miss the quiesce's close and abort passes.
            return Err(DriverConnectError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "the endpoint driver is shutting down",
            )));
        }
        let socket = B::connect(remote, &self.options)?;
        let key = self.slab.borrow_mut().reserve();
        let mut rng = SecureRng(config.tls().secure_random());
        let mut inputs = Inputs {
            now: self.clock(),
            unix_now: UnixTime::now(),
            rng: &mut rng,
        };
        // The new connection writes its ClientHello here, through TLS and the application's TLS
        // config; a panic ends this attempt alone, and the endpoint does not route to a
        // connection it has not returned.
        let created = catch_unwind(AssertUnwindSafe(|| {
            self.endpoint.borrow_mut().connect(
                &mut inputs,
                key,
                remote,
                server_name,
                config,
                options,
            )
        }));
        let error = match created {
            Ok(Ok(conn)) => return Ok((key, conn, socket)),
            Ok(Err(error)) => error.into(),
            Err(payload) => {
                self.contain(ContainedPanicScope::Connection, "connect", payload);
                DriverConnectError::Io(io::Error::other("creating the connection panicked"))
            }
        };
        self.slab.borrow_mut().cancel(key);
        Err(error)
    }

    /// Requests a graceful shutdown with `grace`; a quiesce already running keeps its own.
    pub(crate) fn quiesce(&self, grace: Duration) {
        let mut sched = self.sched.borrow_mut();
        if sched.quiesce.is_none() && sched.quiesce_request.is_none() {
            sched.quiesce_request = Some(grace);
        }
        drop(sched);
        self.shared.wake_task();
    }

    /// Ends the driver at its next turn.
    pub(crate) fn abort(&self) {
        self.aborted.set(true);
        self.shared.wake_task();
    }

    /// Polls the driver task. With a work budget, a poll the budget does not admit does not run a
    /// turn and wakes the task again, unless the driver is ending.
    pub(crate) fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.shared.register(cx.waker());
        #[cfg(test)]
        self.record.borrow_mut().marks.push(Mark::Poll);
        let mut entry = None;
        if let Some(budget) = &self.budget {
            let now = self.clock();
            if !budget.enter(now) && !self.aborted.get() && !self.worker.is_cancelled() {
                budget.finish(PollOutcome::Deferred);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            entry = Some(now);
        }
        for _ in 0..TURN_BUDGET {
            // A panic outside every connection's own guard leaves state that cannot be trusted,
            // so the driver ends with every connection in it.
            match catch_unwind(AssertUnwindSafe(|| self.turn(cx, entry.take()))) {
                Ok(Next::Park) => {
                    self.finish_poll(PollOutcome::Ran);
                    return Poll::Pending;
                }
                Ok(Next::Again) => {}
                Ok(Next::Stop) => {
                    self.finish_poll(PollOutcome::Stopped);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Ok(Next::Done) => {
                    self.finish_poll(PollOutcome::Ran);
                    return Poll::Ready(());
                }
                Err(payload) => {
                    self.contain(ContainedPanicScope::Driver, "turn", payload);
                    self.abort_all();
                    self.finish_poll(PollOutcome::Ran);
                    return Poll::Ready(());
                }
            }
        }
        self.finish_poll(PollOutcome::Ran);
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Ends the poll on the work budget, if any, with `outcome`.
    fn finish_poll(&self, outcome: PollOutcome) {
        if let Some(budget) = &self.budget {
            budget.finish(outcome);
        }
    }

    /// Runs one turn: intake, application phase, transmit, receive, the TLS host's calls,
    /// application phase and transmit, then decides between another turn, waiting for a wake and
    /// finishing. `entry` is the reading a poll with a work budget took as it began, which its
    /// first turn runs at.
    ///
    /// After a check stops a turn, the next turn starts at the phase after the one that stopped,
    /// and only a turn that starts at the intake counts as a new turn. After a transmit phase
    /// stops, turns skip their first transmit phase until a receive phase has begun, so a receive
    /// phase runs before the next transmit phase.
    fn turn(&self, cx: &mut Context<'_>, entry: Option<Instant>) -> Next {
        if self.stopping(cx) || self.aborted.get() {
            self.abort_all();
            return Next::Done;
        }
        #[cfg(test)]
        if self.fail_turn.take() {
            panic!("an injected driver bug");
        }
        // A TLS phase has work only while a connection is due a call, so otherwise a turn that
        // would resume there resumes at the phase after it, which then runs at the turn's reading.
        let start = match self.resume.replace(Phase::Intake) {
            Phase::Tls if !self.tls.as_ref().is_some_and(TlsHosting::has_due) => Phase::SecondApp,
            phase => phase,
        };
        let now = entry.unwrap_or_else(|| self.clock());
        if start == Phase::Intake {
            #[cfg(test)]
            self.record.borrow_mut().marks.push(Mark::Turn);
            self.turns.set(self.turns.get() + 1);
            self.turn_polls.set(0);
            self.turn_handshakes.set(0);
        }
        for phase in Phase::ALL.into_iter().skip_while(|&phase| phase != start) {
            if phase == Phase::FirstTransmit && self.rx_owed.get() {
                continue;
            }
            if phase == Phase::Tls && self.tls.is_none() {
                continue;
            }
            #[cfg(test)]
            self.record.borrow_mut().enter(phase);
            // The phase a turn starts at runs at the turn's reading, as the first application
            // phase does after the intake.
            let at = || if phase == start { now } else { self.clock() };
            match phase {
                Phase::Intake => {
                    self.quiesce_steps(now);
                    if !self.stopped.get() {
                        self.intake(now, cx);
                    }
                    if let Some(tls) = &self.tls
                        && !self.stopped.get()
                    {
                        self.drain_tls(tls, now);
                    }
                }
                Phase::FirstApp => self.app_phase(now),
                Phase::FirstTransmit | Phase::SecondTransmit => self.transmit_phase(at(), cx),
                Phase::Receive => {
                    self.rx_owed.set(false);
                    self.receive(cx);
                }
                Phase::Tls => {
                    if let Some(tls) = &self.tls {
                        self.tls_phase(tls, (phase == start).then_some(now));
                    }
                }
                Phase::SecondApp => self.app_phase(at()),
            }
            if self.stopped.take() {
                #[cfg(test)]
                self.record.borrow_mut().marks.push(Mark::Stop(phase));
                if matches!(phase, Phase::FirstTransmit | Phase::SecondTransmit) {
                    self.rx_owed.set(true);
                }
                self.resume.set(phase.next());
                return Next::Stop;
            }
        }
        // A turn that resumed after its intake has not taken the wakes, which only the intake
        // takes, so another turn runs before the task may wait.
        if start != Phase::Intake {
            return Next::Again;
        }
        self.park(cx)
    }

    /// Returns whether a unit of `kind` may run. Without a work budget, and for a poll's first
    /// unit, it may; otherwise the budget is checked at `reading`, a reading the caller took after
    /// the previous unit, or at a fresh reading if `reading` is `None`. A unit that may not run
    /// stops the poll.
    fn gate(&self, kind: UnitKind, reading: Option<Instant>) -> bool {
        self.gate_staged(kind, reading, 0)
    }

    /// Returns whether a unit of `kind` may run, as [`gate`](Self::gate) does, for a transmit phase
    /// that has built `staged` datagrams on the server socket for its end-of-phase flush. The check
    /// also stops the poll when less time is left than the predicted cost of flushing them, capped
    /// at half the budget's slice.
    fn gate_staged(&self, kind: UnitKind, reading: Option<Instant>, staged: u32) -> bool {
        let Some(budget) = &self.budget else {
            return true;
        };
        if !budget.begun() {
            budget.first(kind);
            #[cfg(test)]
            self.record.borrow_mut().unit(kind);
            return true;
        }
        let now = reading.unwrap_or_else(|| self.clock());
        let reserve = self.flush_cost.get().predict(staged);
        if budget.check_reserving(now, kind, reserve) {
            #[cfg(test)]
            self.record.borrow_mut().unit(kind);
            return true;
        }
        self.stopped.set(true);
        false
    }

    /// Returns the host's time. A turn reads it once for its quiesce steps, intake and first
    /// application phase, then again for each later application or transmit phase, for a TLS phase
    /// with connections due a call, and after each batch is received, so packet times and RTT
    /// samples do not lag by earlier work. A transmit phase also reads it for each attempt on a
    /// socket with kernel release and each attempt of a paced connection, and before each pop from
    /// its queue while a pacing wake is armed, until the phase's requeue cap is spent; under a work
    /// budget, only before the pops on the wakes' turn, and once per 64 pops inside a run of stale
    /// slots. Under a work budget, a poll also reads it as it begins, for the budget and its first
    /// turn, and a check reads it only when it cannot reuse one of these. Under a work budget, a
    /// transmit phase also reads it after its end-of-phase flush, and before the flush unless a
    /// check stopped the phase.
    fn clock(&self) -> Instant {
        #[cfg(test)]
        self.record.borrow_mut().clock_read();
        self.worker.host().now()
    }

    /// Takes the list `pick` chooses whole, leaving the spare allocation in its place.
    fn take_list(&self, pick: impl FnOnce(&mut Sched) -> &mut Vec<ConnKey>) -> Vec<ConnKey> {
        let mut sched = self.sched.borrow_mut();
        let spare = mem::take(&mut sched.spare);
        mem::replace(pick(&mut sched), spare)
    }

    /// Keeps the allocation of a list taken with [`take_list`](Self::take_list).
    fn give_back(&self, mut list: Vec<ConnKey>) {
        list.clear();
        let mut sched = self.sched.borrow_mut();
        if list.capacity() > sched.spare.capacity() {
            sched.spare = list;
        }
    }

    /// Returns whether the worker is shutting down.
    fn stopping(&self, cx: &mut Context<'_>) -> bool {
        let mut sched = self.sched.borrow_mut();
        if let Some(quiescing) = sched.quiescing.as_mut()
            && Pin::new(quiescing).poll(cx).is_ready()
        {
            sched.quiescing = None;
            if sched.quiesce.is_none() && sched.quiesce_request.is_none() {
                sched.quiesce_request = Some(WORKER_QUIESCE_GRACE);
            }
        }
        drop(sched);
        self.worker.is_cancelled()
    }

    /// Ends every connection at once and drops its session.
    fn abort_all(&self) {
        let end = self.slab.borrow().end();
        for index in 0..end {
            let Some(key) = self.slab.borrow().key_at(index) else {
                continue;
            };
            let Some(entry) = self.slab.borrow_mut().remove(key) else {
                continue;
            };
            entry.wake.close();
            self.drop_guarded(entry);
        }
    }

    /// Starts a requested quiesce, and closes or aborts what is left once its times come.
    fn quiesce_steps(&self, now: Instant) {
        let request = self.sched.borrow_mut().quiesce_request.take();
        if let Some(grace) = request {
            // A grace too long for the clock, such as `Duration::MAX`, never forces a close.
            let close_at = now.checked_add(grace);
            self.sched.borrow_mut().quiesce = Some(Quiesce {
                close_at,
                abort_at: close_at.and_then(|at| at.checked_add(QUIESCE_FORCE_AFTER)),
            });
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.app.borrow_mut().quiesce()))
            {
                self.contain(ContainedPanicScope::Connection, "quiesce", payload);
            }
            self.sweep(SweepKind::Notify, now);
        }
        let Some(mut quiesce) = self.sched.borrow().quiesce else {
            return;
        };
        if quiesce.close_at.is_some_and(|at| now >= at) {
            quiesce.close_at = None;
            self.sweep(SweepKind::Close, now);
        }
        if quiesce.abort_at.is_some_and(|at| now >= at) {
            quiesce.abort_at = None;
            self.sweep(SweepKind::Abort, now);
        }
        self.sched.borrow_mut().quiesce = Some(quiesce);
        self.walk_sweeps(now);
    }

    /// Sweeps every connection with `kind`. Under a work budget the sweep is queued, and
    /// [`walk_sweeps`](Self::walk_sweeps) walks it over as many turns as it takes.
    fn sweep(&self, kind: SweepKind, now: Instant) {
        if self.budget.is_some() {
            self.sched.borrow_mut().sweeps.push(kind);
        } else {
            self.for_each_entry("quiesce", |key, entry| {
                self.sweep_entry(kind, now, key, entry);
            });
        }
    }

    /// Walks the queued quiesce sweeps on from their cursor, oldest first: at most
    /// [`SWEEP_PER_TURN`] slab entries a turn, in steps of [`BUDGET_STEP`] that are units of work.
    #[cold]
    fn walk_sweeps(&self, now: Instant) {
        let mut walked = 0;
        while walked < SWEEP_PER_TURN {
            let Some((kind, next)) = self.sched.borrow().sweeps.front() else {
                return;
            };
            let end = self.slab.borrow().end();
            if next >= end {
                self.sched.borrow_mut().sweeps.pop_front();
                continue;
            }
            if !self.gate(UnitKind::Sweep, None) {
                return;
            }
            let stop = end.min(next + (BUDGET_STEP as u32).min(SWEEP_PER_TURN - walked));
            for index in next..stop {
                let Some(key) = self.slab.borrow().key_at(index) else {
                    continue;
                };
                self.with_entry(key, "quiesce", |entry| {
                    self.sweep_entry(kind, now, key, entry);
                });
            }
            walked += stop - next;
            self.sched.borrow_mut().sweeps.next = stop;
        }
    }

    fn sweep_entry(
        &self,
        kind: SweepKind,
        now: Instant,
        key: ConnKey,
        entry: &mut Entry<A::Session, B>,
    ) {
        #[cfg(test)]
        self.record.borrow_mut().marks.push(Mark::Swept(key));
        match kind {
            SweepKind::Notify => {
                entry.quiesce_due = true;
                self.queue_app(key, entry);
            }
            SweepKind::Close => {
                entry
                    .conn
                    .close_transport(now, TransportErrorCode::NO_ERROR, Bytes::new());
                self.mark_dirty(key, entry);
                self.queue_app(key, entry);
                self.after_transport(key, entry);
            }
            SweepKind::Abort => {
                entry.conn.abort();
                self.queue_app(key, entry);
                self.after_transport(key, entry);
            }
        }
    }

    /// Runs `f` on every connection.
    fn for_each_entry(
        &self,
        site: &'static str,
        mut f: impl FnMut(ConnKey, &mut Entry<A::Session, B>),
    ) {
        let end = self.slab.borrow().end();
        for index in 0..end {
            let Some(key) = self.slab.borrow().key_at(index) else {
                continue;
            };
            self.with_entry(key, site, |entry| f(key, entry));
        }
    }

    /// Counts a contained panic and disposes of its payload.
    fn contain(
        &self,
        scope: ContainedPanicScope,
        site: &'static str,
        payload: Box<dyn Any + Send>,
    ) {
        self.worker
            .record_contained_panic(scope, site, None, &*payload);
        if scope == ContainedPanicScope::Connection {
            self.contained_panics.set(self.contained_panics.get() + 1);
        }
        discard_panic(payload);
    }

    /// Drops a connection or a session; a panic in the session's `Drop` is contained.
    fn drop_guarded<T>(&self, value: T) {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(move || drop(value))) {
            self.contain(ContainedPanicScope::Connection, "drop", payload);
        }
    }

    /// Cancels the TLS host's state for a connection being torn down, outside the connection's own
    /// guards; a panic in the call is contained, as one in the session's `Drop` is.
    fn cancel_guarded(&self, tls: &TlsHosting, key: ConnKey) {
        let cancel = || self.call_host(tls, |host| host.cancel(tls_id(key)));
        if let Err(payload) = catch_unwind(AssertUnwindSafe(cancel)) {
            self.contain(ContainedPanicScope::Connection, "tls", payload);
        }
    }

    /// Tears down a connection whose session, transport or TLS host call panicked: its routes,
    /// timers and handles go, it does not send again, the TLS host drops any state it holds for
    /// it, and the panic is counted. On the server socket, the endpoint answers the peer's next
    /// packet with a stateless reset, since its connection ID no longer routes.
    fn poison(&self, key: ConnKey, site: &'static str, payload: Box<dyn Any + Send>) {
        self.contain(ContainedPanicScope::Connection, site, payload);
        self.endpoint
            .borrow_mut()
            .handle_event(key, EndpointEvent::Drained);
        let Some(entry) = self.slab.borrow_mut().remove(key) else {
            return;
        };
        // The connection's own record of the host's state may be torn by the panic.
        if entry.tls_hosted
            && let Some(tls) = &self.tls
        {
            self.cancel_guarded(tls, key);
        }
        let mut sched = self.sched.borrow_mut();
        sched
            .timers
            .set(Kind::Deadline, key.index, entry.deadline, None);
        sched
            .timers
            .set(entry.pacing_kind, key.index, entry.pacing, None);
        drop(sched);
        entry.wake.close();
        self.drop_guarded(entry);
    }

    /// Takes the wakes and the timers that came due.
    fn intake(&self, now: Instant, cx: &mut Context<'_>) {
        self.server_writable(now, cx);
        if self.stopped.get() {
            return;
        }
        {
            // What the poll cap passed over goes ahead of what the last transmit phase queued, so
            // the connections polled in one turn cannot take the cap again in the next.
            let mut sched = self.sched.borrow_mut();
            let sched = &mut *sched;
            while let Some(key) = sched.app_first.pop() {
                sched.app.push_front(key);
            }
        }
        let next = self.take_list(|sched| &mut sched.app_next);
        for &key in &next {
            self.with_entry(key, "intake", |entry| self.queue_app(key, entry));
        }
        self.give_back(next);
        {
            let mut sched = self.sched.borrow_mut();
            let sched = &mut *sched;
            self.shared.take_ready(&mut sched.fresh);
            sched
                .ready
                .extend(sched.fresh.drain(..).map(|key| (now, key)));
        }
        // What the cap leaves waits in age order, a timer since it came due and a wake since the
        // intake took it, so timers that come due in every turn cannot starve the wakes, nor a
        // full ready queue the timers. Under a work budget, the transmit phases take the pacing
        // wakes, in turn with their queue.
        let pacing = self.budget.is_none();
        for _ in 0..self.limits.intake {
            let next = {
                let sched = self.sched.borrow();
                let due = |kind| sched.timers.next(kind).filter(|&at| at <= now);
                let paced = |kind| due(kind).filter(|_| pacing);
                [
                    due(Kind::Deadline).map(|at| (at, Due::Deadline)),
                    paced(Kind::Pacing).map(|at| (at, Due::Pacing(Kind::Pacing))),
                    paced(Kind::Coarse).map(|at| (at, Due::Pacing(Kind::Coarse))),
                    sched.ready.front().map(|&(at, _)| (at, Due::Wake)),
                ]
                .into_iter()
                .flatten()
                .min_by_key(|&(at, _)| at)
            };
            let Some((_, due)) = next else {
                return;
            };
            if !self.gate(UnitKind::IntakeServe, None) {
                return;
            }
            match due {
                Due::Deadline => self.serve_deadline(now),
                Due::Pacing(kind) => self.serve_pacing(kind, now),
                Due::Wake => self.serve_wake(now),
            }
        }
    }

    /// Serves the connection whose deadline came due first.
    fn serve_deadline(&self, now: Instant) {
        let Some(index) = self.sched.borrow_mut().timers.pop_due(Kind::Deadline, now) else {
            return;
        };
        let Some(key) = self.slab.borrow().key_at(index) else {
            return;
        };
        self.with_entry(key, "deadline", |entry| {
            entry.deadline = None;
            if let Some(at) = entry.session_deadline.filter(|&at| at <= now) {
                entry.served_deadline = Some(at);
                entry.app_due = true;
                self.queue_app(key, entry);
            }
            if entry.conn.next_deadline().is_some_and(|at| at <= now) {
                entry.conn.on_deadline(now);
                self.mark_dirty(key, entry);
                self.queue_app(key, entry);
            }
            self.after_transport(key, entry);
        });
    }

    /// Serves the connection whose pacing wake of `kind` came due first.
    fn serve_pacing(&self, kind: Kind, now: Instant) {
        #[cfg(test)]
        let due = self.sched.borrow().timers.next(kind);
        let Some(index) = self.sched.borrow_mut().timers.pop_due(kind, now) else {
            return;
        };
        #[cfg(test)]
        if let Some(due) = due {
            self.record.borrow_mut().wake(index, due, now, false, false);
        }
        let Some(key) = self.slab.borrow().key_at(index) else {
            return;
        };
        self.with_entry(key, "pacing", |entry| {
            entry.pacing = None;
            self.mark_dirty(key, entry);
        });
    }

    /// Serves the connection that has waited longest on the ready queue. The wake bits of those
    /// still waiting accumulate until they are served.
    fn serve_wake(&self, now: Instant) {
        let Some((_, key)) = self.sched.borrow_mut().ready.pop_front() else {
            return;
        };
        self.with_entry(key, "intake", |entry| {
            let bits = entry.wake.take();
            if bits & wake::APP != 0 {
                entry.app_due = true;
                self.queue_app(key, entry);
            }
            if bits & wake::RX != 0 {
                self.sched.borrow_mut().rx.push_back(key);
            }
            if bits & wake::CMD != 0 {
                if let Some(Close { code, reason }) = entry.wake.take_close() {
                    entry.conn.close(now, code, reason);
                }
                self.mark_dirty(key, entry);
                self.queue_app(key, entry);
                self.after_transport(key, entry);
            }
            if bits & wake::TX != 0 && entry.tx_blocked {
                entry.tx_blocked = false;
                self.flush_own(key, entry, now, false);
                self.mark_dirty(key, entry);
            }
            if bits & wake::STREAM != 0 {
                self.queue_app(key, entry);
            }
            if bits & wake::DATAGRAM != 0 {
                entry.datagrams_ready = true;
                self.queue_app(key, entry);
            }
        });
    }

    /// Runs the sessions of the connections queued as the application phase starts, from the
    /// front of the queue; those queued during the phase wait for the next.
    fn app_phase(&self, now: Instant) {
        let queued = self.sched.borrow().app.len();
        for _ in 0..queued {
            if !self.gate(UnitKind::AppVisit, None) {
                return;
            }
            let Some(key) = self.sched.borrow_mut().app.pop_front() else {
                return;
            };
            let drained = self.with_entry(key, "session", |entry| {
                entry.app_queued = false;
                self.run_app(now, key, entry)
            });
            if drained == Some(true) {
                self.free(key);
            }
        }
    }

    /// Delivers a connection's events and readiness edges, runs `poll_session` if due, and
    /// polls its pull producers. Returns whether the session has received `Drained`.
    fn run_app(&self, now: Instant, key: ConnKey, entry: &mut Entry<A::Session, B>) -> bool {
        let mut dirty = false;
        let turn = self.turns.get();
        if entry.pull_turn != turn {
            entry.pull_turn = turn;
            entry.pull_work = 0;
        }
        let Entry {
            conn,
            session,
            wake,
            app_waker,
            app_queued,
            app_due,
            quiesce_due,
            stream_wakers,
            pull_work,
            datagram_waker,
            datagrams_ready,
            ..
        } = entry;
        if deliver(conn, session, wake, stream_wakers, now, &mut dirty) {
            return true;
        }
        if mem::take(quiesce_due) {
            session.on_quiesce(&mut Conn::new(conn, now, wake, &mut dirty));
            if deliver(conn, session, wake, stream_wakers, now, &mut dirty) {
                return true;
            }
        }
        if mem::take(app_due) {
            let mut cx = Context::from_waker(app_waker);
            let _ = session.poll_session(&mut cx, &mut Conn::new(conn, now, wake, &mut dirty));
            if deliver(conn, session, wake, stream_wakers, now, &mut dirty) {
                return true;
            }
        }
        // Stream wakers fired since the last pull step, including from the callbacks above,
        // make their producers ready before this one.
        let mut ids = mem::take(&mut *self.pull_ids.borrow_mut());
        ids.clear();
        wake.take_streams(&mut ids);
        for &id in &ids {
            if let Ok(mut stream) = conn.stream(id) {
                stream.wake_producer();
            }
        }
        // The datagram pull step: poll the ready producer while it pushes and the connection has a
        // datagram allowance. While streams are pull-ready, the step does at most half of the
        // connection's turn work, and its sink takes no more than that work has left, so that the
        // pull steps below poll them in this phase too. A producer still ready is polled in the
        // next turn when the turn's work or polls stopped it, or when that work left its sink
        // short of the longest datagram's frame and it pushed nothing. One that the connection's
        // allowance stopped waits for an application phase that finds an allowance, as the one
        // after the next receive or after a transmit attempt that sends a packet or drops expired
        // datagrams. One that pushed nothing with room for any datagram waits for the connection's
        // next application phase.
        let mut datagrams_capped = false;
        if *datagrams_ready {
            let waker = datagram_waker.get_or_insert_with(|| wake.waker(wake::DATAGRAM));
            let limit = if conn.pull_ready().next().is_some() {
                self.limits.turn_staging / 2
            } else {
                self.limits.turn_staging
            };
            let mut sink = DatagramSink::new(conn, now);
            let cut =
                sink.limit(usize::try_from(limit.saturating_sub(*pull_work)).unwrap_or(usize::MAX));
            loop {
                if sink.allowance() == 0 {
                    // The connection's allowance is not used up if the step's work cut it.
                    datagrams_capped = cut;
                    break;
                }
                if *pull_work >= limit || self.turn_polls.get() >= self.limits.polls {
                    datagrams_capped = true;
                    break;
                }
                self.turn_polls.set(self.turn_polls.get() + 1);
                let staged = sink.staged();
                let poll = session.poll_datagrams(&mut Context::from_waker(waker), &mut sink);
                let progressed = sink.take_progressed();
                *pull_work += (sink.staged() - staged).max(POLL_CHARGE);
                dirty |= progressed;
                if poll.is_pending() {
                    *datagrams_ready = false;
                    break;
                }
                if !progressed {
                    datagrams_capped = cut && !sink.fits_longest();
                    break;
                }
            }
        }
        // Pull steps: poll the pull-ready streams in wire order, then list them again, since
        // finished streams and pending producers leave their share of the staging budget to later
        // streams, and poll the new ones, each at most once per application phase. The steps end
        // when every listed stream has been polled, the connection has done its turn's work, or the
        // turn's polls run out. `ids` holds the streams polled so far, then the step's new ones.
        ids.clear();
        let waiting = loop {
            let polled = ids.len();
            let mut listed = false;
            for (id, _) in conn.pull_ready() {
                listed = true;
                if !ids[..polled].contains(&id) {
                    ids.push(id);
                }
            }
            if ids.len() == polled {
                break listed;
            }
            let mut capped = false;
            for index in polled..ids.len() {
                if *pull_work >= self.limits.turn_staging
                    || self.turn_polls.get() >= self.limits.polls
                {
                    capped = true;
                    ids.truncate(index);
                    break;
                }
                let id = ids[index];
                let Ok(stream) = conn.stream(id) else {
                    continue;
                };
                self.turn_polls.set(self.turn_polls.get() + 1);
                let waker = stream_wakers
                    .entry(id)
                    .or_insert_with(|| wake.stream_waker(id));
                let mut sink = SendSink::new(stream);
                let poll = session.poll_send(&mut Context::from_waker(waker), id, &mut sink);
                let progressed = sink.progressed();
                *pull_work += sink.staged().max(POLL_CHARGE);
                dirty |= progressed;
                if poll.is_ready() && !progressed {
                    self.empty_ready_polls.set(self.empty_ready_polls.get() + 1);
                }
                if poll.is_pending() || !progressed {
                    sink.park_producer();
                }
            }
            if capped {
                break conn.pull_ready().next().is_some();
            }
        };
        *self.pull_ids.borrow_mut() = ids;
        // Streams still pull-ready, because the turn's work or polls ran out or because they were
        // polled in this application phase already, are polled in the next turn, as is a datagram
        // producer the turn's work or polls cut short. A connection the turn's poll cap left
        // without a single poll goes first then.
        if waiting || datagrams_capped {
            let mut sched = self.sched.borrow_mut();
            if *pull_work == 0 {
                *app_queued = true;
                sched.app_first.push(key);
            } else {
                sched.app_next.push(key);
            }
        }
        if deliver(conn, session, wake, stream_wakers, now, &mut dirty) {
            return true;
        }
        if dirty {
            self.mark_dirty(key, entry);
        }
        self.resync(key, entry);
        false
    }

    /// Frees the slot of a drained connection: its routes, timers and handles go, its session is
    /// dropped, and the TLS host drops any state it holds for it.
    fn free(&self, key: ConnKey) {
        let Some(mut entry) = self.slab.borrow_mut().remove(key) else {
            return;
        };
        if let Some(tls) = &self.tls
            && entry.conn.take_tls_cancel()
        {
            self.cancel_guarded(tls, key);
        }
        while let Some(event) = entry.conn.poll_endpoint_event() {
            self.endpoint.borrow_mut().handle_event(key, event);
        }
        self.endpoint
            .borrow_mut()
            .handle_event(key, EndpointEvent::Drained);
        let mut sched = self.sched.borrow_mut();
        sched
            .timers
            .set(Kind::Deadline, key.index, entry.deadline, None);
        sched
            .timers
            .set(entry.pacing_kind, key.index, entry.pacing, None);
        drop(sched);
        entry.wake.close();
        self.drop_guarded(entry);
    }

    /// Makes one transmit attempt for each dirty connection, re-queueing full batches at the
    /// tail, then flushes the sockets used and takes their reports. Under a work budget, a stop
    /// before an attempt leaves that connection and the rest of the queue for the next transmit
    /// phase. The server socket is still flushed then, but if the phase re-queued a connection
    /// after a full batch without flushing its own socket, that batch waits for a later phase. The
    /// check before an attempt also stops the phase when less time is left than the predicted cost
    /// of flushing what the phase has built on the server socket, capped at half the budget's slice
    /// (see [`Self::phase_flush`]).
    ///
    /// Attempts run at `now`, read as the phase starts. A connection's own socket is flushed after
    /// its last attempt of the phase, and the server socket, which the other connections share, at
    /// the end of the phase. An attempt on a socket with kernel release, or of a paced connection,
    /// runs instead at a reading taken just before it, and its socket is also flushed right after
    /// it (without kernel release, only if the attempt built a run), so its runs do not wait in the
    /// pool behind a stale reading; these flushes of the server socket stop once one meets EAGAIN.
    /// While a pacing wake is armed, the phase checks before each pop from its queue, including any
    /// pop that finds it empty, whether a wake has come due; the earliest due wake's connection
    /// makes the next attempt at the check's reading, so a wake is late by about an attempt rather
    /// than a turn. A serve retires the connection's slot wherever it waits by bumping its slot
    /// generation, and a popped slot with an older generation, or of a connection since freed, is
    /// skipped without an attempt. A pop that finds the queue empty ends the phase unless the check
    /// before it took the wake of a freed connection. Serves count against `limits.requeues` with
    /// full-batch requeues, and the checks stop once that cap is spent.
    ///
    /// Under a work budget, while the queue holds slots, a serve and a pop take turns, and the
    /// turn carries across stops; the pacing check runs only on the wakes' turn, and a due wake is
    /// taken only once the budget lets its attempt run. A skip does not change the turn, and each
    /// 64 skips in a row are a unit of work. Inside such a run the pacing check runs only with each
    /// unit's check, which shares its reading.
    // Inlining it into `turn`, its one caller, slows paced tperf by about 3% at equal instruction
    // counts.
    #[inline(never)]
    fn transmit_phase(&self, now: Instant, cx: &mut Context<'_>) {
        #[cfg(test)]
        self.record.borrow_mut().begin_phase();
        let mut queue = {
            let mut sched = self.sched.borrow_mut();
            let sched = &mut *sched;
            let mut queue = mem::take(&mut sched.tx_queue);
            queue.extend(sched.dirty.drain(..));
            queue
        };
        let server_release = self.server.as_ref().is_some_and(|server| server.release);
        let mut latest = now;
        let mut flush_server = false;
        // Per-attempt flushes of the server socket stop once one meets an EAGAIN; the end of the
        // phase still flushes it and waits for it to be writable.
        let mut server_flushes = true;
        let mut requeues = 0;
        // Serves plus full-batch requeues, at most `limits.requeues`.
        let mut spent = 0;
        let budgeted = self.budget.is_some();
        // Stale slots popped since the last attempt.
        let mut skips = 0;
        // Datagrams built on the server socket that wait for the end-of-phase flush.
        let mut staged = 0;
        loop {
            let mut reading = None;
            let mut take = Take::Nothing;
            // Under a work budget, while the queue holds slots, the wakes are checked on their
            // turn, and inside a run of stale slots only with each step's check, as an attempt has
            // not run since the previous check.
            let check_wakes = !(budgeted
                && !queue.is_empty()
                && (self.queue_turn.get() || skips % BUDGET_STEP != 0));
            if check_wakes
                && spent < self.limits.requeues
                && self.sched.borrow().timers.next_pacing().is_some()
            {
                let at = self.clock();
                latest = at;
                reading = Some(at);
                // Under a work budget, a due wake is taken only once its attempt may run, so a
                // stop leaves it armed and its connection where it waits.
                if budgeted
                    && self
                        .sched
                        .borrow()
                        .timers
                        .next_pacing()
                        .is_some_and(|wake| wake <= at)
                    && !self.gate_staged(UnitKind::Attempt, reading, staged)
                {
                    break;
                }
                take = self.take_pacing_wake(at, &queue);
            }
            let served = matches!(take, Take::Serve(_));
            let next = match take {
                Take::Serve(key) => {
                    spent += 1;
                    Some((key, None))
                }
                Take::Deferred | Take::Nothing => queue
                    .pop_front()
                    .map(|slot| (slot.key, Some(slot.generation))),
            };
            let Some((key, generation)) = next else {
                if take == Take::Deferred {
                    continue;
                }
                break;
            };
            let mut stopped = None;
            let mut ran = false;
            let mut stale = None;
            let found = self.with_entry(key, "transmit", |entry| {
                if let Some(generation) =
                    generation.filter(|&generation| generation != entry.slot_generation)
                {
                    stale = Some(generation);
                    return;
                }
                let release = entry.socket.as_deref().map_or(server_release, |own| {
                    own.socket.caps().release.epoch().is_some()
                });
                // Only paced connections arm pacing wakes, so a served attempt runs at its
                // check's reading.
                let at = match reading {
                    _ if !release && !entry.paces => now,
                    Some(at) => at,
                    None => {
                        latest = self.clock();
                        latest
                    }
                };
                let check = if release || entry.paces {
                    Some(at)
                } else {
                    reading
                };
                if !(budgeted && served) && !self.gate_staged(UnitKind::Attempt, check, staged) {
                    // The connection stays dirty and goes back to the head of the queue.
                    entry.dirty = true;
                    stopped = Some(entry.slot_generation);
                    return;
                }
                ran = true;
                entry.dirty = false;
                #[cfg(debug_assertions)]
                {
                    debug_assert!(
                        entry.attempted_at.is_none_or(|last| last <= at),
                        "a connection's attempt times went back"
                    );
                    entry.attempted_at = Some(at);
                }
                #[cfg(test)]
                self.record.borrow_mut().attempt(key, at);
                let sent_before = entry.conn.sent_packets();
                let allowance = entry
                    .datagrams_ready
                    .then(|| entry.conn.datagram_allowance());
                let outcome = match entry.socket.as_deref_mut() {
                    Some(own) => attempt(
                        &mut entry.conn,
                        &mut own.socket,
                        key,
                        at,
                        self.limits.max_segments,
                    ),
                    None => {
                        let Some(server) = &self.server else {
                            return;
                        };
                        flush_server = true;
                        attempt(
                            &mut entry.conn,
                            &mut *server.socket.borrow_mut(),
                            key,
                            at,
                            self.limits.max_segments,
                        )
                    }
                };
                if entry.socket.is_none() {
                    staged += u32::from(outcome.datagrams);
                }
                // Read once per attempt, off the per-packet path.
                let sent = entry.conn.sent_packets() - sent_before;
                self.sent_packets.set(self.sent_packets.get() + sent);
                self.sent_datagrams
                    .set(self.sent_datagrams.get() + u64::from(outcome.datagrams));
                let requeued = outcome.stop == Stop::BatchFull && spent < self.limits.requeues;
                match outcome.stop {
                    Stop::BatchFull if requeued => {
                        requeues += 1;
                        spent += 1;
                        entry.dirty = true;
                        queue.push_back(Slot {
                            key,
                            generation: entry.slot_generation,
                        });
                    }
                    Stop::BatchFull => self.mark_dirty(key, entry),
                    Stop::Socket => {
                        self.socket_stops.set(self.socket_stops.get() + 1);
                        if entry.socket.is_none() && !entry.parked {
                            entry.parked = true;
                            self.sched.borrow_mut().parked.push_back(key);
                        }
                    }
                    _ => {}
                }
                let flush = release || (entry.paces && outcome.datagrams > 0);
                if entry.socket.is_some() && (!requeued || flush) {
                    self.flush_own(key, entry, at, outcome.stop == Stop::Socket);
                } else if entry.socket.is_none()
                    && flush
                    && server_flushes
                    && let Some(server) = &self.server
                {
                    server_flushes = !server.socket.borrow_mut().flush(at).blocked;
                    if server_flushes {
                        staged = 0;
                    }
                }
                self.set_pacing(key, entry, outcome.pacing_at);
                // A ready datagram producer is polled again once the attempt frees allowance,
                // which it does without sending when it drops expired or oversize datagrams.
                if outcome.datagrams > 0
                    || allowance.is_some_and(|before| entry.conn.datagram_allowance() > before)
                {
                    self.queue_app(key, entry);
                }
                self.after_transport(key, entry);
            });
            if found.is_none() && !ran {
                stale = generation;
            }
            if let Some(generation) = stale {
                // A serve retired the slot, or its connection is gone, so the slot is skipped
                // without an attempt and the queue keeps its turn. Each 64 skips in a row are a
                // unit, checked before the next at the wakes' reading if they took one; a run that
                // begins a poll is the poll's first unit.
                let step = if skips == 0 {
                    self.budget.as_ref().is_some_and(|budget| !budget.begun())
                } else {
                    skips % BUDGET_STEP == 0
                };
                if step && !self.gate(UnitKind::Skips, reading) {
                    queue.unpop(Slot { key, generation });
                    break;
                }
                skips += 1;
                #[cfg(test)]
                self.record.borrow_mut().marks.push(Mark::Skip(key));
                self.end_leftover(queue.pops, latest);
                continue;
            }
            skips = 0;
            if let Some(generation) = stopped {
                queue.unpop(Slot { key, generation });
                break;
            }
            if budgeted && ran {
                self.queue_turn.set(served);
            }
            if budgeted && generation.is_some() {
                self.end_leftover(queue.pops, latest);
            }
        }
        if budgeted && self.stopped.get() && !queue.is_empty() {
            self.begin_leftover(&queue);
        }
        self.sched.borrow_mut().tx_queue = queue;
        self.requeues.set(self.requeues.get() + requeues);
        if flush_server {
            #[cfg(test)]
            self.record.borrow_mut().marks.push(Mark::Flush);
            self.phase_flush(latest, cx);
        }
        #[cfg(test)]
        self.record.borrow_mut().end_phase();
    }

    /// Makes a transmit phase's end-of-phase flush of the server socket at `now`. Under a work
    /// budget the flush is a unit of its own kind, not preceded by a check. It is timed from the
    /// reading of the check that stopped the phase, or else from a fresh reading, to a reading
    /// after it, and its time per datagram sent feeds the driver's running average.
    fn phase_flush(&self, now: Instant, cx: &mut Context<'_>) {
        let Some(budget) = &self.budget else {
            self.flush_server(now, cx);
            return;
        };
        let before = self
            .stopped
            .get()
            .then(|| budget.checked_at())
            .flatten()
            .unwrap_or_else(|| self.clock());
        budget.begin_flush(before);
        let flushed = self.send_server(now, cx);
        let after = self.clock();
        let datagrams = flushed.map_or(0, |flushed| flushed.datagrams);
        budget.end_flush(before, after, datagrams);
        let mut cost = self.flush_cost.get();
        cost.record(after.saturating_duration_since(before), datagrams);
        self.flush_cost.set(cost);
        if flushed.is_some_and(|flushed| !flushed.blocked) {
            self.remark_parked();
        }
    }

    /// Begins measuring the leftover wait of the slots a transmit stop left in `queue`, at the
    /// reading of the check that stopped, unless one is already being measured.
    #[cold]
    fn begin_leftover(&self, queue: &SlotQueue) {
        if self.leftover.get().is_none()
            && let Some(at) = self.budget.as_ref().and_then(WorkBudget::checked_at)
        {
            self.leftover
                .set(Some((at, queue.pops + queue.len() as u64)));
        }
    }

    /// Ends the leftover wait being measured if `pops`, the transmit queue's pop count, has reached
    /// the count at which the last slot its stop left pops.
    #[inline]
    fn end_leftover(&self, pops: u64, latest: Instant) {
        if let Some((stop, last)) = self.leftover.get()
            && pops >= last
        {
            self.record_leftover(stop, latest);
        }
    }

    /// Records the leftover wait that began at `stop` and ends at the later of the poll's last
    /// check's reading and `latest`.
    #[cold]
    fn record_leftover(&self, stop: Instant, latest: Instant) {
        self.leftover.set(None);
        let Some(budget) = &self.budget else {
            return;
        };
        let at = budget
            .checked_at()
            .map_or(latest, |checked| checked.max(latest));
        budget.leftover(at.saturating_duration_since(stop));
    }

    /// Takes the pacing wake due earliest at `at`, of either kind, inside a transmit phase whose
    /// queue is `queue`.
    #[cfg_attr(not(test), expect(unused_variables, reason = "only tests read it"))]
    fn take_pacing_wake(&self, at: Instant, queue: &SlotQueue) -> Take {
        #[cfg(test)]
        let due = self.sched.borrow().timers.next_pacing();
        let Some(index) = self.sched.borrow_mut().timers.pop_due_pacing(at) else {
            return Take::Nothing;
        };
        self.phase_pacing_wakes
            .set(self.phase_pacing_wakes.get() + 1);
        let key = self.slab.borrow().key_at(index);
        #[cfg(test)]
        let queued = key.is_some_and(|key| queue.contains(&key));
        let next = key.and_then(|key| {
            self.with_entry(key, "pacing", |entry| {
                entry.pacing = None;
                if entry.dirty {
                    // Retires the connection's slot wherever it waits.
                    entry.slot_generation = entry.slot_generation.wrapping_add(1);
                }
                key
            })
        });
        #[cfg(test)]
        if let Some(due) = due {
            self.record
                .borrow_mut()
                .wake(index, due, at, queued, next.is_some());
        }
        next.map_or(Take::Deferred, Take::Serve)
    }

    /// Flushes the server socket, applies its reports, and gives the connections it refused
    /// another attempt once it takes runs again.
    fn flush_server(&self, now: Instant, cx: &mut Context<'_>) {
        if self
            .send_server(now, cx)
            .is_some_and(|flushed| !flushed.blocked)
        {
            self.remark_parked();
        }
    }

    /// Flushes the server socket, if there is one, and applies its reports. Returns the datagrams
    /// the flush sent and whether runs still wait behind an EAGAIN with the socket not writable.
    fn send_server(&self, now: Instant, cx: &mut Context<'_>) -> Option<FlushOutcome> {
        let server = self.server.as_ref()?;
        let mut socket = server.socket.borrow_mut();
        let flushed = socket.flush(now);
        let blocked = flushed.blocked && socket.poll_writable(cx).is_pending();
        self.add_tx_counters(socket.take_counters());
        let mut reports = mem::take(&mut self.sched.borrow_mut().reports);
        // Only the reports of dropped datagrams change a connection, so the others are not applied.
        socket.drain_reports(|key, report| {
            if matches!(report, TxReport::Dropped { .. }) {
                reports.push((key, report));
            }
        });
        drop(socket);
        for (key, report) in reports.drain(..) {
            self.with_entry(key, "tx report", |entry| {
                #[cfg(debug_assertions)]
                debug_assert!(
                    entry.attempted_at.is_none_or(|last| last <= now),
                    "a connection's reports came before its last attempt"
                );
                entry.conn.on_tx_report(now, report);
                self.mark_dirty(key, entry);
            });
        }
        let mut sched = self.sched.borrow_mut();
        sched.reports = reports;
        sched.server_blocked = blocked;
        Some(FlushOutcome {
            datagrams: flushed.datagrams,
            blocked,
        })
    }

    /// Marks the connections parked on the writable server socket for another attempt, oldest
    /// first, in steps of [`BUDGET_STEP`] that are units of work. A stop leaves the rest parked.
    #[cold]
    fn remark_parked(&self) {
        while !self.sched.borrow().parked.is_empty() {
            if !self.gate(UnitKind::Remark, None) {
                return;
            }
            for _ in 0..BUDGET_STEP {
                let Some(key) = self.sched.borrow_mut().parked.pop_front() else {
                    break;
                };
                #[cfg(test)]
                self.record.borrow_mut().marks.push(Mark::Remarked(key));
                self.with_entry(key, "transmit", |entry| {
                    entry.parked = false;
                    self.mark_dirty(key, entry);
                });
            }
        }
    }

    /// Retries the server socket's backlog once it is writable.
    fn server_writable(&self, now: Instant, cx: &mut Context<'_>) {
        let Some(server) = &self.server else {
            return;
        };
        if !self.sched.borrow().server_blocked {
            // Under a work budget, a stop can leave connections parked on the writable socket.
            if self.budget.is_some() {
                self.remark_parked();
            }
            return;
        }
        if server.socket.borrow_mut().poll_writable(cx).is_pending() {
            return;
        }
        self.flush_server(now, cx);
    }

    /// Flushes a connection's own socket and applies its reports. A connection the socket
    /// refused (`refused`) gets another attempt in the next transmit phase, or once the socket is
    /// writable again if the flush left runs behind an EAGAIN.
    fn flush_own(
        &self,
        key: ConnKey,
        entry: &mut Entry<A::Session, B>,
        now: Instant,
        refused: bool,
    ) {
        #[cfg(debug_assertions)]
        debug_assert!(
            entry.attempted_at.is_none_or(|last| last <= now),
            "a connection's reports came before its last attempt"
        );
        let Entry {
            conn,
            socket: Some(own),
            tx_blocked,
            ..
        } = entry
        else {
            return;
        };
        let OwnSocket {
            socket, tx_waker, ..
        } = &mut **own;
        let mut dropped = false;
        *tx_blocked = socket.flush(now).blocked
            && socket
                .poll_writable(&mut Context::from_waker(tx_waker))
                .is_pending();
        self.add_tx_counters(socket.take_counters());
        socket.drain_reports(|_, report| {
            conn.on_tx_report(now, report);
            dropped |= matches!(report, TxReport::Dropped { .. });
        });
        if dropped || (refused && !entry.tx_blocked) {
            self.mark_dirty(key, entry);
        }
    }

    /// Receives from the server socket and from the connections' own sockets that may be
    /// readable.
    fn receive(&self, cx: &mut Context<'_>) {
        if let Some(server) = &self.server {
            self.receive_server(server, cx);
            if self.stopped.get() {
                return;
            }
        }
        let queued = self.sched.borrow().rx.len();
        for _ in 0..queued {
            let Some(key) = self.sched.borrow_mut().rx.pop_front() else {
                return;
            };
            self.with_entry(key, "receive", |entry| self.receive_own(key, entry));
            if self.stopped.get() {
                return;
            }
        }
    }

    /// Receives up to [`RX_BATCHES`] batches from the server socket.
    fn receive_server(&self, server: &Server<B>, cx: &mut Context<'_>) {
        let mut replies = Vec::new();
        self.receive_batches(server, cx, &mut replies);
        if replies.is_empty() {
            return;
        }
        let mut socket = server.socket.borrow_mut();
        for reply in &replies {
            send_stateless(&mut *socket, reply);
        }
        drop(socket);
        self.flush_server(self.clock(), cx);
    }

    /// Receives up to [`RX_BATCHES`] batches from the server socket, collecting the stateless
    /// replies due.
    fn receive_batches(
        &self,
        server: &Server<B>,
        cx: &mut Context<'_>,
        replies: &mut Vec<StatelessReply>,
    ) {
        self.accept_kept(server, replies);
        if self.stopped.get() {
            return;
        }
        self.serve_waiting(server, replies);
        if self.stopped.get() {
            return;
        }
        let mut batches = 0;
        let mut resume = self.sched.borrow_mut().rx_resume.take();
        loop {
            let start = match resume.take() {
                Some(start) => start,
                None => {
                    if batches == RX_BATCHES {
                        self.sched.borrow_mut().rx_more = true;
                        return;
                    }
                    batches += 1;
                    match server.socket.borrow_mut().poll_recv(cx) {
                        Poll::Ready(Ok(_)) => BatchCursor::default(),
                        Poll::Ready(Err(_)) => continue,
                        Poll::Pending => return,
                    }
                }
            };
            let now = self.clock();
            if !self.gate(UnitKind::ReceiveChunk, Some(now)) {
                self.sched.borrow_mut().rx_resume = Some(start);
                return;
            }
            let (stopped_at, incoming, more) = self.route_batch(server, now, start, replies);
            let Some(incoming) = incoming else {
                if more {
                    resume = Some(stopped_at);
                }
                continue;
            };
            if !self.gate(UnitKind::Accept, None) {
                let mut sched = self.sched.borrow_mut();
                sched.rx_resume = Some(stopped_at);
                sched.kept_accept = Some(incoming);
                return;
            }
            self.turn_handshakes.set(self.turn_handshakes.get() + 1);
            replies.extend(self.accept(server, now, incoming));
            resume = Some(stopped_at);
        }
    }

    /// Takes up the connection attempt a stop came before, if any. It comes before the receive
    /// phase's other work, as it would have without the stop, so the Initials routed after it
    /// find its connection, and it is the phase's first attempt, within the turn's cap.
    fn accept_kept(&self, server: &Server<B>, replies: &mut Vec<StatelessReply>) {
        let Some(incoming) = self.sched.borrow_mut().kept_accept.take() else {
            return;
        };
        // A blocklist posted since the attempt was routed applies to it.
        let Some(incoming) = self.endpoint.borrow().recheck_src_port(incoming) else {
            return;
        };
        let now = self.clock();
        if !self.gate(UnitKind::Accept, Some(now)) {
            self.sched.borrow_mut().kept_accept = Some(incoming);
            return;
        }
        debug_assert!(
            self.turn_handshakes.get() < self.limits.handshakes,
            "a turn's first connection attempt is within its cap"
        );
        self.turn_handshakes.set(self.turn_handshakes.get() + 1);
        replies.extend(self.accept(server, now, incoming));
    }

    /// Takes the Initials kept from earlier turns, oldest first, while this turn's connection
    /// attempts last. Each is routed again: one may now belong to a connection an earlier one
    /// created, as the second datagram of a client's first flight does. A stop before an accept
    /// keeps the attempt for the next receive phase.
    fn serve_waiting(&self, server: &Server<B>, replies: &mut Vec<StatelessReply>) {
        if let Some(steering) = &self.steering {
            steering.take(|waiting| {
                self.steered_in.set(self.steered_in.get() + 1);
                self.queue_waiting(waiting);
            });
        }
        if self.sched.borrow().waiting.is_empty() {
            return;
        }
        let now = self.clock();
        let mut reading = Some(now);
        while self.turn_handshakes.get() < self.limits.handshakes {
            let Some(mut waiting) = self.sched.borrow_mut().waiting.pop_front() else {
                return;
            };
            if !self.gate(UnitKind::WaitingDatagram, reading.take()) {
                self.sched.borrow_mut().waiting.push_front(waiting);
                return;
            }
            let route = self
                .endpoint
                .borrow_mut()
                .route(now, &waiting.meta, &waiting.datagram);
            match route {
                Route::Existing(key) => {
                    self.with_entry(key, "receive", |entry| {
                        let datagram = RxDatagram {
                            meta: &waiting.meta,
                            data: &mut waiting.datagram,
                        };
                        let summary = entry.conn.recv_batch(now, &mut [datagram]);
                        self.recv_batch_calls.set(self.recv_batch_calls.get() + 1);
                        self.after_receive(key, entry, summary.tls_due);
                    });
                }
                Route::Accept(incoming) => {
                    if !self.gate(UnitKind::Accept, None) {
                        self.sched.borrow_mut().kept_accept = Some(incoming);
                        return;
                    }
                    self.turn_handshakes.set(self.turn_handshakes.get() + 1);
                    replies.extend(self.accept(server, now, incoming));
                }
                Route::Stateless(reply) => replies.push(reply),
                Route::Drop(_) => {}
            }
        }
    }

    /// Keeps for a later turn an Initial that came after this turn's connection attempts ran out,
    /// or drops it when it does not fit the bytes left for waiting Initials; its client sends it
    /// again.
    fn keep_waiting(&self, meta: &RxMeta, datagram: &[u8]) {
        let bound = self.limits.waiting_initial_bytes;
        if !self.sched.borrow().waiting.fits(datagram.len(), bound) {
            self.dropped_initials.set(self.dropped_initials.get() + 1);
            return;
        }
        self.queue_waiting(Waiting {
            meta: *meta,
            datagram: datagram.to_vec(),
        });
    }

    /// Queues `waiting` to be routed again in a later turn, or drops it when it does not fit the
    /// bytes left for waiting Initials.
    fn queue_waiting(&self, waiting: Waiting) {
        let bound = self.limits.waiting_initial_bytes;
        let mut sched = self.sched.borrow_mut();
        if !sched.waiting.fits(waiting.datagram.len(), bound) {
            self.dropped_initials.set(self.dropped_initials.get() + 1);
            return;
        }
        sched.waiting.push_back(waiting);
    }

    /// Routes the server socket's last batch from `start` on, and hands each connection its
    /// datagrams in one `recv_batch`. Under a work budget a call routes at most [`BUDGET_BATCH`]
    /// datagrams. Stops at an Initial for a new connection while this turn's connection attempts
    /// last, so the datagrams after it route to that connection once it exists. Later Initials
    /// wait for a later turn, and the rest of the batch goes on to the connections it is for.
    /// Returns where it stopped, the Initial, and whether the cap stopped it with datagrams left.
    fn route_batch(
        &self,
        server: &Server<B>,
        now: Instant,
        start: BatchCursor,
        replies: &mut Vec<StatelessReply>,
    ) -> (BatchCursor, Option<Incoming>, bool) {
        let mut socket = server.socket.borrow_mut();
        let mut endpoint = self.endpoint.borrow_mut();
        let mut scratch = mem::take(&mut *self.rx_scratch.borrow_mut());
        let mut routed: Vec<Routed<'_>> = recycle(mem::take(&mut scratch.routed));
        let end = match self.budget {
            Some(_) => start.handled.saturating_add(BUDGET_BATCH),
            None => usize::MAX,
        };
        let mut at = start;
        let mut incoming = None;
        let mut more = false;
        #[cfg(test)]
        let mut walked = 0;
        'buffers: for (meta, buffer) in socket.buffers().skip(start.buffers) {
            let stride = usize::from(meta.stride).max(1);
            let rest = buffer.get_mut(at.within * stride..).unwrap_or_default();
            for datagram in rest.chunks_mut(stride) {
                if at.handled == end {
                    more = true;
                    break 'buffers;
                }
                #[cfg(test)]
                {
                    walked += 1;
                }
                at.handled += 1;
                at.within += 1;
                match endpoint.route(now, meta, datagram) {
                    Route::Existing(key) => routed.push((key, at.handled, meta, datagram)),
                    Route::Accept(new) => {
                        if self.steer(now, meta, datagram, true) {
                            continue;
                        }
                        if self.turn_handshakes.get() < self.limits.handshakes {
                            incoming = Some(new);
                            break 'buffers;
                        }
                        self.keep_waiting(meta, datagram);
                    }
                    Route::Stateless(reply) => replies.push(reply),
                    Route::Drop(RxDropReason::UnknownConnection) => {
                        self.steer(now, meta, datagram, false);
                    }
                    Route::Drop(_) => {}
                }
            }
            at.buffers += 1;
            at.within = 0;
        }
        drop(endpoint);
        by_connection(&mut routed);
        let mut datagrams: Vec<RxDatagram<'_>> = recycle(mem::take(&mut scratch.datagrams));
        for group in routed.chunk_by_mut(|a, b| a.0 == b.0) {
            let key = group[0].0;
            datagrams.clear();
            datagrams.extend(
                group
                    .iter_mut()
                    .map(|(_, _, meta, data)| RxDatagram { meta, data }),
            );
            self.with_entry(key, "receive", |entry| {
                let summary = entry.conn.recv_batch(now, &mut datagrams);
                self.recv_batch_calls.set(self.recv_batch_calls.get() + 1);
                self.after_receive(key, entry, summary.tls_due);
            });
        }
        scratch.datagrams = recycle(datagrams);
        scratch.routed = recycle(routed);
        *self.rx_scratch.borrow_mut() = scratch;
        #[cfg(test)]
        self.record.borrow_mut().marks.push(Mark::Route {
            start: start.handled,
            end: at.handled,
            walked,
        });
        (at, incoming, more)
    }

    /// Hands a datagram to the worker steering picks for it: a datagram of a new connection
    /// (`new`), or a long header for an unknown connection. Returns whether this worker is done
    /// with it.
    fn steer(&self, now: Instant, meta: &RxMeta, datagram: &[u8], new: bool) -> bool {
        let Some(steering) = &self.steering else {
            return false;
        };
        let steered = if new {
            steering.steer_new(now, meta, datagram)
        } else {
            steering.steer_known(now, meta, datagram)
        };
        match steered {
            Steer::Keep => false,
            Steer::HandedOff => {
                self.steered_out.set(self.steered_out.get() + 1);
                true
            }
            Steer::Dropped => {
                self.dropped_initials.set(self.dropped_initials.get() + 1);
                true
            }
        }
    }

    /// Passes a new connection attempt to the application's `accept` and creates the connection,
    /// or returns the refusal to send.
    fn accept(
        &self,
        server: &Server<B>,
        now: Instant,
        incoming: Incoming,
    ) -> Option<StatelessReply> {
        #[cfg(test)]
        self.record
            .borrow_mut()
            .marks
            .push(Mark::Accept(incoming.remote_address()));
        let info = ConnInfo {
            remote: incoming.remote_address(),
            local_ip: incoming.local_ip(),
            version: incoming.version(),
        };
        if self.sched.borrow().quiesce.is_some() {
            return self.endpoint.borrow_mut().refuse(
                now,
                incoming,
                TransportErrorCode::CONNECTION_REFUSED,
            );
        }
        let mut options = ConnOptions::default();
        let decision = catch_unwind(AssertUnwindSafe(|| {
            self.app.borrow_mut().accept(&info, &mut options)
        }));
        let session = match decision {
            Ok(Ok(session)) => session,
            Ok(Err(Refusal::Refuse)) => {
                return self.endpoint.borrow_mut().refuse(
                    now,
                    incoming,
                    TransportErrorCode::CONNECTION_REFUSED,
                );
            }
            Ok(Err(Refusal::Ignore)) => return None,
            Ok(Err(Refusal::VersionNegotiation)) => {
                return self
                    .endpoint
                    .borrow_mut()
                    .refuse_by_negotiation(now, incoming);
            }
            Err(payload) => {
                self.contain(ContainedPanicScope::Connection, "accept", payload);
                return None;
            }
        };
        let transport = options
            .transport
            .as_ref()
            .unwrap_or_else(|| server.config.transport());
        if let Some(steering) = &self.steering {
            steering.accepted(transport);
        }
        let paces = transport.pacing();
        let key = self.slab.borrow_mut().reserve();
        let mut rng = SecureRng(server.config.tls().secure_random());
        let mut inputs = Inputs {
            now,
            unix_now: UnixTime::now(),
            rng: &mut rng,
        };
        // The new connection reads the client's first flight here, through TLS and the
        // application's certificate resolver; a panic ends this attempt alone, and the endpoint
        // does not route to a connection it has not returned.
        let created = catch_unwind(AssertUnwindSafe(|| {
            self.endpoint
                .borrow_mut()
                .accept(&mut inputs, key, incoming, &server.config, options)
        }));
        match created {
            Ok(Ok(conn)) => {
                let hosted = matches!(server.config.tls(), ServerTls::External);
                self.insert(key, conn, session, None, paces, hosted);
                return None;
            }
            Ok(Err(_)) => {}
            Err(payload) => self.contain(ContainedPanicScope::Connection, "accept", payload),
        }
        self.slab.borrow_mut().cancel(key);
        self.drop_guarded(session);
        None
    }

    /// Receives from a connection's own socket. Under a work budget, a receive with the first
    /// [`BUDGET_BATCH`] datagrams of its batch is a unit of work, and so is each later chunk of
    /// that many. A stop leaves the connection at the head of the receive queue. A stop inside a
    /// batch also keeps the place in it, and the connection's next receive delivers the rest of
    /// the batch before it reads the socket again.
    fn receive_own(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        let Entry {
            conn,
            socket: Some(own),
            ..
        } = entry
        else {
            return;
        };
        let OwnSocket {
            socket, rx_waker, ..
        } = &mut **own;
        let mut cx = Context::from_waker(rx_waker);
        let mut received = false;
        let mut tls_due = false;
        let mut drained = false;
        let mut stopped = false;
        let mut spare = mem::take(&mut self.rx_scratch.borrow_mut().datagrams);
        let mut resume = self.take_own_resume(key);
        let mut batches = 0;
        loop {
            let (start, now) = match resume.take() {
                Some(start) => {
                    let now = self.clock();
                    if !self.gate(UnitKind::ReceiveChunk, Some(now)) {
                        self.sched.borrow_mut().own_resume = Some((key, start));
                        stopped = true;
                        break;
                    }
                    (start, now)
                }
                None => {
                    if batches == RX_BATCHES {
                        break;
                    }
                    if !self.gate(UnitKind::ReceiveChunk, None) {
                        stopped = true;
                        break;
                    }
                    batches += 1;
                    match socket.poll_recv(&mut cx) {
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(_)) => continue,
                        Poll::Pending => {
                            drained = true;
                            break;
                        }
                    }
                    (BatchCursor::default(), self.clock())
                }
            };
            let end = match self.budget {
                Some(_) => start.handled.saturating_add(BUDGET_BATCH),
                None => usize::MAX,
            };
            let mut datagrams: Vec<RxDatagram<'_>> = recycle(spare);
            let (at, more) = take_chunk(socket.buffers(), start, end, &mut datagrams);
            #[cfg(test)]
            self.record.borrow_mut().marks.push(Mark::Receive {
                key,
                start: start.handled,
                end: at.handled,
            });
            tls_due = conn.recv_batch(now, &mut datagrams).tls_due;
            self.recv_batch_calls.set(self.recv_batch_calls.get() + 1);
            spare = recycle(datagrams);
            received = true;
            if more {
                resume = Some(at);
            }
        }
        self.rx_scratch.borrow_mut().datagrams = spare;
        if stopped {
            self.sched.borrow_mut().rx.push_front(key);
        } else if !drained {
            self.sched.borrow_mut().rx.push_back(key);
        }
        if received {
            self.after_receive(key, entry, tls_due);
        }
    }

    /// Takes the place a stop left in the batch of `key`'s own socket, if any. A place kept for
    /// another connection is dropped: that connection was at the head of the receive queue, so it
    /// has been freed.
    fn take_own_resume(&self, key: ConnKey) -> Option<BatchCursor> {
        self.budget.as_ref()?;
        match self.sched.borrow_mut().own_resume.take() {
            Some((kept, at)) if kept == key => Some(at),
            _ => None,
        }
    }

    /// Queues the work a receive batch makes. `tls_due` is whether the batch left the connection
    /// work for its TLS host.
    fn after_receive(&self, key: ConnKey, entry: &mut Entry<A::Session, B>, tls_due: bool) {
        self.receive_passes.set(self.receive_passes.get() + 1);
        self.mark_dirty(key, entry);
        self.queue_app(key, entry);
        if tls_due {
            self.queue_tls(key, entry);
        }
        self.after_transport(key, entry);
    }

    /// Puts the connection on one of the TLS host's lists of connections due a call, if the driver
    /// has a host and the connection is not on either list yet.
    fn queue_tls(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        if let Some(tls) = &self.tls
            && !entry.tls_queued
        {
            entry.tls_queued = true;
            tls.list(entry.tls_started).borrow_mut().push_back(key);
        }
    }

    /// Applies the connection's endpoint events and resyncs its deadline. If the connection has
    /// closed while the TLS host held state for it, that state is cancelled first, so the cancel
    /// does not wait for the end of the closing period. For a connection still due a call, the TLS
    /// phase makes the cancel, after a check as for every call there; for any other connection the
    /// cancel is part of the unit that closed it.
    fn after_transport(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        if entry.tls_hosted
            && !entry.tls_queued
            && let Some(tls) = &self.tls
            && entry.conn.take_tls_cancel()
        {
            self.call_host(tls, |host| host.cancel(tls_id(key)));
        }
        while let Some(event) = entry.conn.poll_endpoint_event() {
            #[cfg(test)]
            if let EndpointEvent::NewLocalCid { cid, .. } = event {
                self.issued.borrow_mut().push(cid);
            }
            self.endpoint.borrow_mut().handle_event(key, event);
        }
        self.resync(key, entry);
    }

    /// Hands the TLS host the inputs of the connections due a call and delivers the steps it
    /// answers at once, so that what they write leaves in the transmit phase that follows: first
    /// the handshakes under way, oldest first, then those waiting to start, oldest first, up to
    /// the cap on handshakes per turn, which counts the starts apart from the turn's accepts. The
    /// phase runs once per turn, and the handshakes past the cap wait, untouched, for a later
    /// turn. `now` is the turn's reading if the turn starts at this phase, and `None` otherwise,
    /// when the phase reads the clock itself; either reading also serves its first check. A stop
    /// leaves the connection it came in at the head of its list, and the rest behind it in order.
    fn tls_phase(&self, tls: &TlsHosting, now: Option<Instant>) {
        if !tls.has_due() {
            return;
        }
        let now = now.unwrap_or_else(|| self.clock());
        let mut pass = TlsPass {
            now,
            reading: Some(now),
            starts: 0,
        };
        let under_way = tls.due.borrow().len();
        for _ in 0..under_way {
            if !self.serve_next(tls, &tls.due, &mut pass) {
                return;
            }
        }
        let waiting = tls.waiting.borrow().len();
        for _ in 0..waiting {
            if pass.starts >= self.limits.handshakes {
                return;
            }
            if !self.serve_next(tls, &tls.waiting, &mut pass) {
                return;
            }
        }
    }

    /// Serves the connection at the head of `list` in the TLS phase `pass`. Returns `false` if a
    /// check stopped the poll; the connection is then back at the head of its list.
    fn serve_next(
        &self,
        tls: &TlsHosting,
        list: &RefCell<VecDeque<ConnKey>>,
        pass: &mut TlsPass,
    ) -> bool {
        let Some(key) = list.borrow_mut().pop_front() else {
            return true;
        };
        #[cfg(test)]
        self.record.borrow_mut().marks.push(Mark::TlsTaken(key));
        let served = self.with_entry(key, "tls", |entry| {
            let served = self.serve_tls(tls, key, entry, pass);
            if !served {
                tls.list(entry.tls_started).borrow_mut().push_front(key);
            }
            served
        });
        served != Some(false)
    }

    /// Delivers the steps the TLS host has completed and not returned yet, and puts their
    /// connections on the lists of connections due a call, since a step may leave another input.
    /// A stop leaves the rest with the host, for the next intake.
    fn drain_tls(&self, tls: &TlsHosting, now: Instant) {
        // The load spares an atomic read-modify-write in the turns that find the flag clear.
        if !tls.ready.flagged.load(Ordering::SeqCst)
            || !tls.ready.flagged.swap(false, Ordering::SeqCst)
        {
            return;
        }
        loop {
            if !self.gate(UnitKind::TlsHostCall, None) {
                tls.ready.flagged.store(true, Ordering::SeqCst);
                return;
            }
            let Some((id, step)) = self.call_host(tls, |host| host.poll_ready()) else {
                return;
            };
            let key = tls_key(id);
            self.with_entry(key, "tls", |entry| {
                // Queued first, so a step that closes the connection leaves the cancel to the TLS
                // phase's check.
                self.queue_tls(key, entry);
                if entry.conn.tls_deliver(now, step).is_ok() {
                    self.after_tls(key, entry);
                }
            });
        }
    }

    /// Hands the TLS host the inputs of one connection for as long as the host answers each at
    /// once, delivering each step, or cancels the host's state for a connection that has closed.
    /// Under a work budget, a check runs before each input is taken, since the connection's next
    /// input cannot be inspected without taking it. A first input counts against the phase's
    /// starts. Returns `false` if a check stopped the poll; the connection then stays due a call.
    fn serve_tls(
        &self,
        tls: &TlsHosting,
        key: ConnKey,
        entry: &mut Entry<A::Session, B>,
        pass: &mut TlsPass,
    ) -> bool {
        let id = tls_id(key);
        let mut delivered = false;
        let mut stopped = false;
        loop {
            if !self.gate(UnitKind::TlsHostCall, pass.reading.take()) {
                stopped = true;
                break;
            }
            let Some(input) = entry.conn.tls_input() else {
                if entry.conn.take_tls_cancel() {
                    self.call_host(tls, |host| host.cancel(id));
                }
                break;
            };
            if !entry.tls_started {
                entry.tls_started = true;
                pass.starts += 1;
            }
            let TlsPoll::Ready(step) = self.call_host(tls, |host| host.handle(id, input)) else {
                break;
            };
            delivered |= entry.conn.tls_deliver(pass.now, step).is_ok();
        }
        entry.tls_queued = stopped;
        if delivered {
            self.after_tls(key, entry);
        }
        !stopped
    }

    /// Makes one call into the TLS host.
    fn call_host<R>(&self, tls: &TlsHosting, call: impl FnOnce(&mut dyn TlsHost) -> R) -> R {
        #[cfg(test)]
        self.record.borrow_mut().tls_call();
        call(&mut **tls.host.borrow_mut())
    }

    /// Queues the work a TLS step makes.
    fn after_tls(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        self.mark_dirty(key, entry);
        self.queue_app(key, entry);
        self.after_transport(key, entry);
    }

    /// Decides between another turn, waiting for a wake and finishing, and arms the host wake
    /// before waiting.
    fn park(&self, cx: &mut Context<'_>) -> Next {
        let now = self.clock();
        if let Some(budget) = &self.budget {
            budget.observe(now);
        }
        let mut sched = self.sched.borrow_mut();
        let sched = &mut *sched;
        if !sched.dirty.is_empty()
            || !sched.tx_queue.is_empty()
            || sched.rx_resume.is_some()
            || sched.kept_accept.is_some()
            || !sched.app.is_empty()
            || !sched.app_next.is_empty()
            || !sched.app_first.is_empty()
            || !sched.rx.is_empty()
            || !sched.ready.is_empty()
            || !sched.waiting.is_empty()
            || mem::take(&mut sched.rx_more)
            || sched.quiesce_request.is_some()
            || !sched.sweeps.is_empty()
            || (!sched.parked.is_empty() && !sched.server_blocked)
            || self.tls.as_ref().is_some_and(TlsHosting::has_work)
        {
            return Next::Again;
        }
        if sched.quiesce.is_some() && self.slab.borrow().len() == 0 {
            return Next::Done;
        }
        let quiesce_at = sched
            .quiesce
            .and_then(|quiesce| quiesce.close_at.or(quiesce.abort_at));
        let deadline = sched
            .timers
            .next(Kind::Deadline)
            .into_iter()
            .chain(quiesce_at)
            .min();
        let pacing = sched.timers.next(Kind::Pacing);
        let coarse = sched.timers.next(Kind::Coarse);
        match sched.host_wake.arm(now, deadline, pacing, coarse, cx) {
            Poll::Ready(()) => Next::Again,
            Poll::Pending => Next::Park,
        }
    }

    /// Stores a new connection, due a transmit attempt and a first `poll_session`. `paces` is
    /// whether its transport config turns pacing on, and `hosted` whether its TLS backend is
    /// External, which puts its handshake on the driver's TLS host if the driver has one.
    fn insert(
        &self,
        key: ConnKey,
        conn: Connection,
        session: A::Session,
        socket: Option<B>,
        paces: bool,
        hosted: bool,
    ) -> Arc<ConnWake> {
        let wake = ConnWake::new(Arc::clone(&self.shared), key);
        let mut sched = self.sched.borrow_mut();
        sched.dirty.push(Slot { key, generation: 0 });
        sched.app.push_back(key);
        if socket.is_some() {
            sched.rx.push_back(key);
        }
        drop(sched);
        let tls_queued = match &self.tls {
            Some(tls) if hosted => {
                tls.waiting.borrow_mut().push_back(key);
                true
            }
            _ => false,
        };
        let pacing_kind = self
            .sched
            .borrow()
            .host_wake
            .pacing_kind(conn.build_horizon());
        let entry = Entry {
            conn,
            session,
            app_waker: wake.waker(wake::APP),
            socket: socket.map(|socket| {
                Box::new(OwnSocket {
                    socket,
                    rx_waker: wake.waker(wake::RX),
                    tx_waker: wake.waker(wake::TX),
                })
            }),
            tx_blocked: false,
            parked: false,
            wake: Arc::clone(&wake),
            dirty: true,
            slot_generation: 0,
            app_queued: true,
            app_due: true,
            quiesce_due: self.sched.borrow().quiesce.is_some(),
            tls_hosted: tls_queued,
            tls_queued,
            tls_started: false,
            deadline: None,
            session_deadline: None,
            served_deadline: None,
            pacing: None,
            pacing_kind,
            paces,
            #[cfg(debug_assertions)]
            attempted_at: None,
            stream_wakers: HashMap::new(),
            pull_turn: 0,
            pull_work: 0,
            datagram_waker: None,
            datagrams_ready: false,
        };
        self.slab.borrow_mut().insert(key, entry);
        wake
    }

    /// Runs `f` on the connection stored under `key`, if it is still there. A panic in `f`
    /// tears down that connection alone; `site` names the work for the panic count.
    fn with_entry<R>(
        &self,
        key: ConnKey,
        site: &'static str,
        f: impl FnOnce(&mut Entry<A::Session, B>) -> R,
    ) -> Option<R> {
        let slot = self.slab.borrow().slot(key.index)?;
        match catch_unwind(AssertUnwindSafe(|| slot.borrow_mut().get(key).map(f))) {
            Ok(result) => result,
            Err(payload) => {
                self.poison(key, site, payload);
                None
            }
        }
    }

    fn mark_dirty(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        if !entry.dirty {
            entry.dirty = true;
            self.sched.borrow_mut().dirty.push(Slot {
                key,
                generation: entry.slot_generation,
            });
        }
    }

    fn queue_app(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        if !entry.app_queued {
            entry.app_queued = true;
            self.sched.borrow_mut().app.push_back(key);
        }
    }

    /// Moves the connection's deadline timer to the earlier of its own deadline and its
    /// session's.
    fn resync(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        entry.session_deadline = entry
            .session
            .deadline()
            .filter(|&at| Some(at) != entry.served_deadline);
        let at = entry
            .conn
            .next_deadline()
            .into_iter()
            .chain(entry.session_deadline)
            .min();
        if at != entry.deadline {
            self.deadline_rearms.set(self.deadline_rearms.get() + 1);
            self.sched
                .borrow_mut()
                .timers
                .set(Kind::Deadline, key.index, entry.deadline, at);
            entry.deadline = at;
        }
    }

    /// Moves the connection's pacing timer to `at`.
    fn set_pacing(&self, key: ConnKey, entry: &mut Entry<A::Session, B>, at: Option<Instant>) {
        if at != entry.pacing {
            self.sched
                .borrow_mut()
                .timers
                .set(entry.pacing_kind, key.index, entry.pacing, at);
            entry.pacing = at;
        }
    }
}

impl<A: QuicApplication, B: Backend> Drop for Core<A, B> {
    fn drop(&mut self) {
        self.last.set(self.stats());
    }
}

/// Hands the session the connection's events and stream readiness edges until both run out or the
/// session has received `Drained`, the last event; returns whether it has.
fn deliver<S: QuicSession>(
    conn: &mut Connection,
    session: &mut S,
    wake: &Arc<ConnWake>,
    stream_wakers: &mut HashMap<StreamId, Waker>,
    now: Instant,
    dirty: &mut bool,
) -> bool {
    loop {
        if let Some(event) = conn.poll_event() {
            let drained = event == ConnEvent::Drained;
            session.on_event(&mut Conn::new(conn, now, wake, dirty), event);
            if drained {
                return true;
            }
        } else if let Some((id, ready)) = conn.readiness().next() {
            if ready == StreamReady::Closed {
                stream_wakers.remove(&id);
            }
            session.on_stream(&mut Conn::new(conn, now, wake, dirty), id, ready);
        } else {
            return false;
        }
    }
}

/// Queues a stateless reply on `socket` as a one-datagram run.
fn send_stateless<B: Backend>(socket: &mut B, reply: &StatelessReply) {
    let data = reply.datagram();
    let Ok(len) = u16::try_from(data.len()) else {
        return;
    };
    let mut sink = socket.sink(STATELESS);
    let Some((_, slot)) = sink.next_segment(len, TxClass::Urgent) else {
        return;
    };
    if slot.len() < data.len() {
        sink.end_segment(0);
        return;
    }
    slot[..data.len()].copy_from_slice(data);
    sink.end_segment(len);
    sink.end_run(TxMeta {
        path: PathId(0),
        dst: reply.dst(),
        src_ip: reply.src_ip(),
        tos: 0,
        segment_size: len,
        segments: 1,
        release: Release::Asap,
        class: TxClass::Urgent,
        tx: TxSeqRange { start: 0, end: 1 },
        sealed: true,
    });
}

/// Makes one transmit attempt of `conn` into `backend`.
fn attempt<B: Backend>(
    conn: &mut Connection,
    backend: &mut B,
    key: ConnKey,
    now: Instant,
    max_segments: u16,
) -> TxOutcome {
    let caps = *backend.caps();
    let limits = TxLimits {
        now,
        max_segments: caps.max_segments.min(max_segments),
        max_datagram: caps.max_datagram,
        max_bytes: u32::MAX,
        epoch: caps.release.epoch(),
    };
    let mut sink = backend.sink(key);
    conn.poll_transmit(&limits, &mut sink, &mut InlineSealer)
}

/// What the transmit phases of a driver did, for tests.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct TxRecord {
    /// Transmit phases begun.
    pub(crate) phases: u64,
    /// The transmit phase running, if any.
    phase: Option<u64>,
    /// Clock reads inside transmit phases.
    pub(crate) phase_clock_reads: u64,
    /// Clock reads.
    pub(crate) clock_reads: u64,
    /// The count of clock reads when the running phase of a turn began.
    entered_at_read: u64,
    /// For each call into the TLS host, the clock reads since its phase began.
    pub(crate) tls_call_reads: Vec<u64>,
    /// Every transmit attempt, in order.
    pub(crate) attempts: Vec<AttemptRecord>,
    /// Every pacing wake taken, in order.
    pub(crate) wakes: Vec<WakeRecord>,
    /// The steps of the driver's polls, in order.
    pub(crate) marks: Vec<Mark>,
    /// Units of work the budget let run.
    pub(crate) units: u64,
}

/// A step of a driver's poll, as tests record it.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mark {
    /// A poll began.
    Poll,
    /// A phase began.
    Phase(Phase),
    /// A check stopped the poll in this phase.
    Stop(Phase),
    /// A transmit attempt of this connection.
    Attempt(ConnKey),
    /// A transmit phase flushed the server socket at its end.
    Flush,
    /// The server socket's batch was routed from datagram `start` to datagram `end`, counted
    /// from 0, stepping over `walked` datagrams.
    Route {
        start: usize,
        end: usize,
        walked: usize,
    },
    /// The driver took up a connection attempt from this address.
    Accept(SocketAddr),
    /// The budget let a unit of this kind run.
    Unit(UnitKind),
    /// A transmit phase popped a slot of this connection that a serve had retired, or that outlived
    /// the connection, and skipped it.
    Skip(ConnKey),
    /// A turn began at its intake.
    Turn,
    /// A quiesce sweep walked this connection.
    Swept(ConnKey),
    /// The connection, parked on the server socket, was marked for another attempt.
    Remarked(ConnKey),
    /// The batch of this connection's own socket was delivered from datagram `start` to datagram
    /// `end`, counted from 0.
    Receive {
        key: ConnKey,
        start: usize,
        end: usize,
    },
    /// A call into the TLS host.
    TlsCall,
    /// The TLS phase took this connection from a list of connections due a call.
    TlsTaken(ConnKey),
}

/// A transmit attempt: its connection, its transmit phase, and the clock reading it ran at.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct AttemptRecord {
    pub(crate) key: ConnKey,
    pub(crate) phase: u64,
    pub(crate) at: Instant,
}

/// A pacing wake taken: its connection's slot, when it was due and when it was taken, the
/// transmit phase that took it (`None` for the intake), whether its connection waited in that
/// phase's queue, and, if its connection made the next attempt, that attempt's place in
/// [`TxRecord::attempts`].
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct WakeRecord {
    pub(crate) index: u32,
    pub(crate) due: Instant,
    pub(crate) taken: Instant,
    pub(crate) phase: Option<u64>,
    pub(crate) queued: bool,
    pub(crate) next: Option<usize>,
}

#[cfg(test)]
impl TxRecord {
    fn begin_phase(&mut self) {
        self.phases += 1;
        self.phase = Some(self.phases);
    }

    fn end_phase(&mut self) {
        self.phase = None;
    }

    fn clock_read(&mut self) {
        self.clock_reads += 1;
        if self.phase.is_some() {
            self.phase_clock_reads += 1;
        }
    }

    fn enter(&mut self, phase: Phase) {
        self.marks.push(Mark::Phase(phase));
        self.entered_at_read = self.clock_reads;
    }

    fn tls_call(&mut self) {
        self.marks.push(Mark::TlsCall);
        self.tls_call_reads
            .push(self.clock_reads - self.entered_at_read);
    }

    fn unit(&mut self, kind: UnitKind) {
        self.units += 1;
        self.marks.push(Mark::Unit(kind));
    }

    fn attempt(&mut self, key: ConnKey, at: Instant) {
        let phase = self.phase.expect("attempts run inside transmit phases");
        self.attempts.push(AttemptRecord { key, phase, at });
        self.marks.push(Mark::Attempt(key));
    }

    /// Records a wake of slot `index` due at `due` and taken at `taken`; `queued` if its
    /// connection waited in the phase's queue, and `attempts` if it makes the next attempt.
    fn wake(&mut self, index: u32, due: Instant, taken: Instant, queued: bool, attempts: bool) {
        self.wakes.push(WakeRecord {
            index,
            due,
            taken,
            phase: self.phase,
            queued,
            next: attempts.then_some(self.attempts.len()),
        });
    }
}

/// A queue of connection keys that counts, in tests, the keys it moves.
#[derive(Default)]
pub(crate) struct KeyQueue(VecDeque<ConnKey>);

impl KeyQueue {
    fn push_back(&mut self, key: ConnKey) {
        moved(1);
        self.0.push_back(key);
    }

    fn push_front(&mut self, key: ConnKey) {
        moved(1);
        self.0.push_front(key);
    }

    fn pop_front(&mut self) -> Option<ConnKey> {
        let key = self.0.pop_front();
        moved(usize::from(key.is_some()));
        key
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A connection's place in the transmit queue or in [`Sched::dirty`], with the connection's slot
/// generation when it was pushed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    key: ConnKey,
    generation: u32,
}

/// The transmit queue: slots oldest first.
#[derive(Default)]
struct SlotQueue {
    slots: VecDeque<Slot>,
    /// The number of slots popped and not put back.
    pops: u64,
}

impl SlotQueue {
    fn push_back(&mut self, slot: Slot) {
        moved(1);
        self.slots.push_back(slot);
    }

    fn pop_front(&mut self) -> Option<Slot> {
        let slot = self.slots.pop_front();
        moved(usize::from(slot.is_some()));
        self.pops += u64::from(slot.is_some());
        slot
    }

    /// Puts back at the head the slot popped last.
    fn unpop(&mut self, slot: Slot) {
        moved(1);
        self.slots.push_front(slot);
        self.pops -= 1;
    }

    fn extend(&mut self, slots: impl ExactSizeIterator<Item = Slot>) {
        moved(slots.len());
        self.slots.extend(slots);
    }

    #[cfg(test)]
    fn contains(&self, key: &ConnKey) -> bool {
        self.slots.iter().any(|slot| slot.key == *key)
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
thread_local! {
    /// The number of connection keys moved into or out of queues on this thread, in tests.
    pub(crate) static KEYS_MOVED: Cell<u64> = const { Cell::new(0) };
}

/// Counts `keys` moved into or out of a queue, in tests.
#[cfg_attr(not(test), expect(unused_variables, reason = "only tests count"))]
fn moved(keys: usize) {
    #[cfg(test)]
    KEYS_MOVED.with(|moved| moved.set(moved.get() + keys as u64));
}

/// Empties `v` and hands back its allocation for elements of another lifetime, so scratch
/// vectors of borrowed datagrams outlive the borrows of each batch.
fn recycle<T, U>(mut v: Vec<T>) -> Vec<U> {
    v.clear();
    // Collecting a vector's own iterator into a type of the same layout, as here where only
    // the lifetimes differ, reuses its buffer; the vector is empty, so the closure never runs.
    v.into_iter()
        .map(|_| -> U { unreachable!("the vector is empty") })
        .collect()
}

/// Pushes onto `datagrams` the datagrams of a received batch from `start` up to, but not including,
/// datagram `end`, counted from 0. Returns where it stopped and whether the batch holds more.
fn take_chunk<'a>(
    buffers: impl Iterator<Item = (&'a RxMeta, &'a mut [u8])>,
    start: BatchCursor,
    end: usize,
    datagrams: &mut Vec<RxDatagram<'a>>,
) -> (BatchCursor, bool) {
    let mut at = start;
    for (meta, buffer) in buffers.skip(start.buffers) {
        let stride = usize::from(meta.stride).max(1);
        let rest = buffer.get_mut(at.within * stride..).unwrap_or_default();
        let left = end - at.handled;
        let count = rest.len().div_ceil(stride);
        if count > left {
            let chunk = &mut rest[..left * stride];
            datagrams.extend(
                chunk
                    .chunks_mut(stride)
                    .map(|data| RxDatagram { meta, data }),
            );
            at.handled += left;
            at.within += left;
            return (at, true);
        }
        datagrams.extend(
            rest.chunks_mut(stride)
                .map(|data| RxDatagram { meta, data }),
        );
        at.handled += count;
        at.buffers += 1;
        at.within = 0;
    }
    (at, false)
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::Ecn;

    use super::*;
    use crate::lab::Bulk;
    use crate::lab::MemBackend;

    /// The bytes an [`Entry`] holds besides its connection and its session, in a build without
    /// debug assertions. Both of those are inline, and the test subtracts their sizes.
    const ENTRY_OWN: usize = 192;

    #[test]
    fn an_entry_keeps_the_own_socket_wakers_in_the_socket_box() {
        let entry = size_of::<Entry<Bulk, MemBackend>>();
        let (conn, session) = (size_of::<Connection>(), size_of::<Bulk>());
        // The reading of the connection's last attempt is kept with debug assertions only.
        let expected = if cfg!(debug_assertions) {
            ENTRY_OWN + size_of::<Option<Instant>>()
        } else {
            ENTRY_OWN
        };
        assert_eq!(
            entry - conn - session,
            expected,
            "an entry of {entry} bytes, with a connection of {conn} and a session of {session}, \
             aligned to {}",
            align_of::<Entry<Bulk, MemBackend>>()
        );
    }

    #[test]
    fn a_recycled_vector_keeps_its_allocation() {
        let meta = RxMeta {
            src: SocketAddr::from(([127, 0, 0, 1], 1)),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride: 4,
            rx_time: Instant::now(),
        };
        let mut data = [0u8; 4];
        let mut full: Vec<RxDatagram<'_>> = Vec::with_capacity(8);
        full.push(RxDatagram {
            meta: &meta,
            data: &mut data,
        });
        let empty: Vec<RxDatagram<'static>> = recycle(full);
        assert!(empty.is_empty());
        assert_eq!(empty.capacity(), 8, "the allocation is reused");
    }

    /// Takes a batch in chunks of `size` datagrams and returns, for each chunk, the first bytes of
    /// its datagrams and the place and flag that `take_chunk` returned.
    fn chunks_of(
        batch: &mut [(RxMeta, Vec<u8>)],
        size: usize,
    ) -> Vec<(Vec<u8>, (usize, usize, usize), bool)> {
        let mut chunks = Vec::new();
        let mut start = BatchCursor::default();
        loop {
            let mut datagrams = Vec::new();
            let buffers = batch.iter_mut().map(|(meta, data)| (&*meta, &mut data[..]));
            let (at, more) = take_chunk(
                buffers,
                start,
                start.handled.saturating_add(size),
                &mut datagrams,
            );
            let firsts = datagrams.iter().map(|datagram| datagram.data[0]).collect();
            chunks.push((firsts, (at.handled, at.buffers, at.within), more));
            if !more {
                return chunks;
            }
            assert!(chunks.len() < 20, "the batch does not end: {chunks:?}");
            start = at;
        }
    }

    #[test]
    fn a_batch_taken_in_chunks_resumes_inside_and_across_buffers() {
        let meta = |stride| RxMeta {
            src: SocketAddr::from(([127, 0, 0, 1], 1)),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride,
            rx_time: Instant::now(),
        };
        // Datagram n starts with byte n: three of 10 bytes and a short one of 4, two of 5, three
        // of 1.
        let mut first: Vec<u8> = (0..34).map(|i| (i / 10) as u8).collect();
        first[30..].fill(3);
        let mut batch = vec![
            (meta(10), first),
            (meta(5), vec![4, 4, 4, 4, 4, 5, 5, 5, 5, 5]),
            (meta(1), vec![6, 7, 8]),
        ];
        assert_eq!(
            chunks_of(&mut batch, usize::MAX),
            [((0..9).collect::<Vec<u8>>(), (9, 3, 0), false)],
            "without a cap, the whole batch"
        );
        assert_eq!(
            chunks_of(&mut batch, 4),
            [
                (vec![0, 1, 2, 3], (4, 1, 0), true),
                (vec![4, 5, 6, 7], (8, 2, 2), true),
                (vec![8], (9, 3, 0), false),
            ],
            "a chunk that ends with its buffer leaves the next buffer's first for the next chunk"
        );
        assert_eq!(
            chunks_of(&mut batch, 3),
            [
                (vec![0, 1, 2], (3, 0, 3), true),
                (vec![3, 4, 5], (6, 2, 0), true),
                (vec![6, 7, 8], (9, 3, 0), false),
            ],
            "a chunk that ends inside a buffer goes on from there, short datagram included"
        );
        let ones: Vec<Vec<u8>> = chunks_of(&mut batch, 1)
            .into_iter()
            .map(|(firsts, ..)| firsts)
            .collect();
        assert_eq!(ones, (0..9_u8).map(|n| vec![n]).collect::<Vec<_>>());
    }

    #[test]
    fn routed_datagrams_group_by_connection_in_arrival_order() {
        let meta = RxMeta {
            src: SocketAddr::from(([127, 0, 0, 1], 1)),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride: 1,
            rx_time: Instant::now(),
        };
        let key = |index| ConnKey {
            index,
            generation: 1,
        };
        // Enough datagrams, interleaved over a few connections, that an unstable sort on the
        // connection alone would reorder some.
        let mut bytes = [0u8; 300];
        let mut routed: Vec<Routed<'_>> = bytes
            .chunks_mut(1)
            .enumerate()
            .map(|(place, data)| (key((place * 7 % 6) as u32), place, &meta, data))
            .collect();
        by_connection(&mut routed);
        let order: Vec<(u32, usize)> = routed
            .iter()
            .map(|&(key, place, ..)| (key.index, place))
            .collect();
        let mut expected = order.clone();
        expected.sort();
        assert_eq!(
            order, expected,
            "each connection's datagrams in arrival order"
        );
    }
}
