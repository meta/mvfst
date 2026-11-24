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
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_io::Backend;
use mvfstr_proto::ClientConfig;
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
use mvfstr_proto::StatelessReply;
use mvfstr_proto::Stop;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
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
use crate::DriverConnectError;
use crate::QuicApplication;
use crate::QuicSession;
use crate::Refusal;
use crate::SendSink;
use crate::Steering;
use crate::slab::Slab;
use crate::steer::Member;
use crate::steer::Steer;
use crate::steer::handoff_lifetime;
use crate::timers::HostWake;
use crate::timers::Kind;
use crate::timers::Timers;
use crate::wake;
use crate::wake::Command;
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

/// `poll_send` calls per turn across all connections.
const POLLS_PER_TURN: usize = 1024;

/// Connection attempts handled per turn; later Initials wait for the next turn.
const HANDSHAKES_PER_TURN: usize = 8;

/// Initials kept for a later turn once a turn's connection attempts run out; more are dropped,
/// and their clients send them again.
const WAITING_INITIALS: usize = 256;

/// The per-turn caps and the transmit batch limit; tests lower them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// The most datagrams of one transmit attempt, below the backend's own limit.
    pub(crate) max_segments: u16,
    /// Transmit attempts that may go back to the tail of one transmit phase.
    pub(crate) requeues: u64,
    /// Connections the intake takes from the timers and the ready queue per turn.
    pub(crate) intake: usize,
    /// `poll_send` calls per turn across all connections.
    pub(crate) polls: usize,
    /// Bytes one connection's pull steps may stage per turn, each poll counted at least
    /// [`POLL_CHARGE`].
    pub(crate) turn_staging: u64,
    /// Connection attempts handled per turn.
    pub(crate) handshakes: usize,
    /// Initials kept for a later turn once a turn's connection attempts run out.
    pub(crate) waiting_initials: usize,
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
            waiting_initials: WAITING_INITIALS,
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
    /// `poll_send` calls in this turn.
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
}

impl<B: Backend> Server<B> {
    pub(crate) fn new(socket: B, config: Arc<ServerConfig>) -> std::io::Result<Self> {
        Ok(Self {
            addr: socket.local_addr()?,
            socket: RefCell::new(socket),
            config,
        })
    }

    pub(crate) fn config(&self) -> &Arc<ServerConfig> {
        &self.config
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

/// One connection and its session.
struct Entry<S, B> {
    conn: Connection,
    session: S,
    wake: Arc<ConnWake>,
    /// The connection's own connected socket; `None` on the server socket.
    socket: Option<Box<B>>,
    app_waker: Waker,
    rx_waker: Waker,
    tx_waker: Waker,
    /// The connection's own socket holds runs behind an EAGAIN until it is writable.
    tx_blocked: bool,
    /// On the list of connections the server socket refused.
    parked: bool,
    /// Queued for a transmit attempt.
    dirty: bool,
    /// Queued for an application phase.
    app_queued: bool,
    /// `poll_session` is due.
    app_due: bool,
    /// `on_quiesce` is due.
    quiesce_due: bool,
    /// The connection's entry in the deadline timers: the earlier of its own deadline and its
    /// session's.
    deadline: Option<Instant>,
    /// The session's deadline, from [`QuicSession::deadline`] after its last callback.
    session_deadline: Option<Instant>,
    /// The session deadline `poll_session` last ran for; the same deadline again is not re-armed.
    served_deadline: Option<Instant>,
    /// The connection's entry in the pacing timers.
    pacing: Option<Instant>,
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
}

/// The queues of the turn.
struct Sched {
    /// Connections due a transmit attempt in the next transmit phase.
    dirty: Vec<ConnKey>,
    /// Connections due an application phase.
    app: Vec<ConnKey>,
    /// Connections due an application phase in the next turn: streams stayed pull-ready after
    /// their pull step.
    app_next: Vec<ConnKey>,
    /// Connections with pull-ready streams that the turn's poll cap left without a poll; the next
    /// turn serves them before every other. Each keeps its `app_queued` flag meanwhile.
    app_first: Vec<ConnKey>,
    /// Connections whose own socket may be readable.
    rx: Vec<ConnKey>,
    /// The server socket may hold more datagrams than the turn took.
    rx_more: bool,
    /// Initials for new connections that came after their turn's connection attempts ran out,
    /// oldest first.
    waiting: VecDeque<Waiting>,
    /// Connections whose attempt the server socket refused, waiting for it to take runs again.
    parked: Vec<ConnKey>,
    /// The server socket holds runs behind an EAGAIN until it is writable.
    server_blocked: bool,
    reports: Vec<(ConnKey, TxReport)>,
    /// The transmit phase's queue, empty between phases.
    tx_queue: VecDeque<ConnKey>,
    /// An empty list whose allocation the next list taken whole reuses.
    spare: Vec<ConnKey>,
    timers: Timers,
    host_wake: HostWake,
    /// Fires when the worker starts shutting down; `None` once it has.
    quiescing: Option<WorkerQuiescing>,
    /// A quiesce requested through the handle, with its grace period.
    quiesce_request: Option<Duration>,
    quiesce: Option<Quiesce>,
    /// Connections taken from the ready queue and not yet served, oldest first, each with the
    /// time the intake took it.
    ready: VecDeque<(Instant, ConnKey)>,
    /// The connections the intake takes from the ready queue at once, empty between turns.
    fresh: Vec<ConnKey>,
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
    /// Initials for new connections dropped because the queue of those waiting for a later turn,
    /// or the inbox of the worker they were steered to, was full.
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

/// Which source of intake work waited longest.
enum Due {
    Deadline,
    Pacing,
    Wake,
}

/// What a check between the attempts of a transmit phase took.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Take {
    /// The check, if one ran, did not find a due pacing wake.
    Nothing,
    /// A wake whose connection makes the next attempt, out of the phase's queue if it waited
    /// there.
    Serve(ConnKey),
    /// A wake whose connection waits in [`Sched::dirty`] for the next phase, dirtied again after
    /// its attempt in this one, or whose slot is empty.
    Deferred,
}

/// What the task does after a turn.
enum Next {
    /// Wait for a wake.
    Park,
    /// Run another turn.
    Again,
    /// The driver has finished.
    Done,
}

/// The random source of a TLS config's crypto provider.
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
    ) -> Self {
        let shared = Arc::new(Shared::default());
        let lifetime = server
            .as_ref()
            .and_then(|server| handoff_lifetime(server.config().transport()));
        let steering =
            steering.map(|(group, index)| group.join(index, Arc::clone(&shared), lifetime));
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
                app: Vec::new(),
                app_next: Vec::new(),
                app_first: Vec::new(),
                rx: Vec::new(),
                rx_more: false,
                waiting: VecDeque::new(),
                parked: Vec::new(),
                server_blocked: false,
                reports: Vec::new(),
                tx_queue: VecDeque::new(),
                spare: Vec::new(),
                timers: Timers::default(),
                host_wake: HostWake::new(worker.host()),
                quiescing: Some(worker.quiescing()),
                quiesce_request: None,
                quiesce: None,
                ready: VecDeque::new(),
                fresh: Vec::new(),
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
            last: Rc::default(),
            aborted: Cell::new(false),
            pull_ids: RefCell::new(Vec::new()),
            rx_scratch: RefCell::default(),
            steering,
            #[cfg(test)]
            fail_turn: Cell::new(false),
            #[cfg(test)]
            issued: RefCell::default(),
            #[cfg(test)]
            record: RefCell::default(),
        }
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

    /// Returns what the transmit phases have done so far.
    #[cfg(test)]
    pub(crate) fn tx_record(&self) -> TxRecord {
        self.record.borrow().clone()
    }

    /// Returns the endpoint's counters.
    pub(crate) fn stats(&self) -> EndpointStats {
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
        }
    }

    /// Returns where the counters are kept once the driver has ended.
    pub(crate) fn last_stats(&self) -> Rc<Cell<EndpointStats>> {
        Rc::clone(&self.last)
    }

    /// Returns the server socket's address.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(|server| server.addr)
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
                let wake = self.insert(key, conn, session, Some(Box::new(socket)), paces);
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
        let mut rng = SecureRng(config.tls().crypto_provider().secure_random);
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

    /// Polls the driver task.
    pub(crate) fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.shared.register(cx.waker());
        for _ in 0..TURN_BUDGET {
            // A panic outside every connection's own guard leaves state that cannot be trusted,
            // so the driver ends with every connection in it.
            match catch_unwind(AssertUnwindSafe(|| self.turn(cx))) {
                Ok(Next::Park) => return Poll::Pending,
                Ok(Next::Again) => {}
                Ok(Next::Done) => return Poll::Ready(()),
                Err(payload) => {
                    self.contain(ContainedPanicScope::Driver, "turn", payload);
                    self.abort_all();
                    return Poll::Ready(());
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Runs one turn: intake, application phase, transmit, receive, application phase and
    /// transmit, then decides between another turn, waiting for a wake and finishing.
    fn turn(&self, cx: &mut Context<'_>) -> Next {
        if self.stopping(cx) || self.aborted.get() {
            self.abort_all();
            return Next::Done;
        }
        #[cfg(test)]
        if self.fail_turn.take() {
            panic!("an injected driver bug");
        }
        self.turns.set(self.turns.get() + 1);
        self.turn_polls.set(0);
        self.turn_handshakes.set(0);
        let now = self.clock();
        self.quiesce_steps(now);
        self.intake(now, cx);
        self.app_phase(now);
        self.transmit_phase(self.clock(), cx);
        self.receive(cx);
        self.app_phase(self.clock());
        self.transmit_phase(self.clock(), cx);
        self.park(cx)
    }

    /// Returns the host's time. A turn reads it once for its quiesce steps, intake and first
    /// application phase, then again for each later application or transmit phase and after each
    /// batch is received, so packet times and RTT samples do not lag by earlier work. A transmit
    /// phase also reads it for each attempt of a paced connection, and before each pop from its
    /// queue while a pacing wake is armed, until the phase's requeue cap is spent.
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
            self.for_each_entry("quiesce", |key, entry| {
                entry.quiesce_due = true;
                self.queue_app(key, entry);
            });
        }
        let Some(mut quiesce) = self.sched.borrow().quiesce else {
            return;
        };
        if quiesce.close_at.is_some_and(|at| now >= at) {
            quiesce.close_at = None;
            self.for_each_entry("quiesce", |key, entry| {
                entry
                    .conn
                    .close_transport(now, TransportErrorCode::NO_ERROR, Bytes::new());
                self.mark_dirty(key, entry);
                self.queue_app(key, entry);
                self.after_transport(key, entry);
            });
        }
        if quiesce.abort_at.is_some_and(|at| now >= at) {
            quiesce.abort_at = None;
            self.for_each_entry("quiesce", |key, entry| {
                entry.conn.abort();
                self.queue_app(key, entry);
                self.after_transport(key, entry);
            });
        }
        self.sched.borrow_mut().quiesce = Some(quiesce);
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

    /// Tears down a connection whose session or transport panicked: its routes, timers and
    /// handles go, it does not send again, and the panic is counted. On the server socket, the
    /// endpoint answers the peer's next packet with a stateless reset, since its connection ID no
    /// longer routes.
    fn poison(&self, key: ConnKey, site: &'static str, payload: Box<dyn Any + Send>) {
        self.contain(ContainedPanicScope::Connection, site, payload);
        self.endpoint
            .borrow_mut()
            .handle_event(key, EndpointEvent::Drained);
        let Some(entry) = self.slab.borrow_mut().remove(key) else {
            return;
        };
        let mut sched = self.sched.borrow_mut();
        sched
            .timers
            .set(Kind::Deadline, key.index, entry.deadline, None);
        sched
            .timers
            .set(Kind::Pacing, key.index, entry.pacing, None);
        drop(sched);
        entry.wake.close();
        self.drop_guarded(entry);
    }

    /// Takes the wakes and the timers that came due.
    fn intake(&self, now: Instant, cx: &mut Context<'_>) {
        self.server_writable(now, cx);
        {
            // What the poll cap passed over goes ahead of what the last transmit phase queued, so
            // the connections polled in one turn cannot take the cap again in the next.
            let mut sched = self.sched.borrow_mut();
            let sched = &mut *sched;
            let mut first = mem::take(&mut sched.app_first);
            first.append(&mut sched.app);
            sched.app_first = mem::replace(&mut sched.app, first);
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
        // full ready queue the timers.
        for _ in 0..self.limits.intake {
            let next = {
                let sched = self.sched.borrow();
                let due = |kind| sched.timers.next(kind).filter(|&at| at <= now);
                [
                    due(Kind::Deadline).map(|at| (at, Due::Deadline)),
                    due(Kind::Pacing).map(|at| (at, Due::Pacing)),
                    sched.ready.front().map(|&(at, _)| (at, Due::Wake)),
                ]
                .into_iter()
                .flatten()
                .min_by_key(|&(at, _)| at)
            };
            match next {
                Some((_, Due::Deadline)) => self.serve_deadline(now),
                Some((_, Due::Pacing)) => self.serve_pacing(now),
                Some((_, Due::Wake)) => self.serve_wake(now),
                None => return,
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

    /// Serves the connection whose pacing release came due first.
    fn serve_pacing(&self, now: Instant) {
        #[cfg(test)]
        let due = self.sched.borrow().timers.next(Kind::Pacing);
        let Some(index) = self.sched.borrow_mut().timers.pop_due(Kind::Pacing, now) else {
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
                self.sched.borrow_mut().rx.push(key);
            }
            if bits & wake::CMD != 0 {
                while let Some(command) = entry.wake.take_command() {
                    match command {
                        Command::Close { code, reason } => entry.conn.close(now, code, reason),
                    }
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
        });
    }

    /// Runs the sessions of the connections queued for the application phase.
    fn app_phase(&self, now: Instant) {
        let queue = self.take_list(|sched| &mut sched.app);
        for &key in &queue {
            let drained = self.with_entry(key, "session", |entry| {
                entry.app_queued = false;
                self.run_app(now, key, entry)
            });
            if drained == Some(true) {
                self.free(key);
            }
        }
        self.give_back(queue);
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
        // polled in this application phase already, are polled in the next turn. A connection the
        // turn's poll cap left without a single poll goes first then.
        if waiting {
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

    /// Frees the slot of a drained connection: its routes, timers and handles go, and its
    /// session is dropped.
    fn free(&self, key: ConnKey) {
        let Some(mut entry) = self.slab.borrow_mut().remove(key) else {
            return;
        };
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
            .set(Kind::Pacing, key.index, entry.pacing, None);
        drop(sched);
        entry.wake.close();
        self.drop_guarded(entry);
    }

    /// Makes one transmit attempt for each dirty connection, re-queueing full batches at the
    /// tail, then flushes the sockets used and takes their reports.
    ///
    /// Attempts run at `now`, read as the phase starts. A connection's own socket is flushed after
    /// its last attempt of the phase, and the server socket, which the other connections share, at
    /// the end of the phase. A paced connection's attempt runs instead at a reading taken just
    /// before it, and its socket is also flushed right after it if the attempt built a run, so its
    /// runs do not wait in the pool behind a stale reading; these flushes of the server socket stop
    /// once one meets EAGAIN. While a pacing wake is armed, the phase checks before each pop from
    /// its queue, including any pop that finds it empty, whether a wake has come due; the earliest
    /// due wake's connection makes the next attempt at the check's reading unless it waits for the
    /// next phase, so a wake is late by about an attempt rather than a turn. A pop that finds the
    /// queue empty ends the phase unless the check before it took a wake that does not give an
    /// attempt. Serves that give an attempt count against `limits.requeues` with full-batch
    /// requeues, and the checks stop once that cap is spent.
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
        let mut latest = now;
        let mut flush_server = false;
        // Per-attempt flushes of the server socket stop once one meets an EAGAIN; the end of the
        // phase still flushes it and waits for it to be writable.
        let mut server_flushes = true;
        let mut requeues = 0;
        // Serves that gave an attempt plus full-batch requeues, at most `limits.requeues`.
        let mut spent = 0;
        loop {
            let mut reading = None;
            let mut take = Take::Nothing;
            if spent < self.limits.requeues
                && self.sched.borrow().timers.next(Kind::Pacing).is_some()
            {
                let at = self.clock();
                latest = at;
                reading = Some(at);
                take = self.take_pacing_wake(at, &mut queue);
            }
            let next = match take {
                Take::Serve(key) => {
                    spent += 1;
                    Some(key)
                }
                Take::Deferred | Take::Nothing => queue.pop_front(),
            };
            let Some(key) = next else {
                if take == Take::Deferred {
                    continue;
                }
                break;
            };
            self.with_entry(key, "transmit", |entry| {
                entry.dirty = false;
                // Only paced connections arm pacing wakes, so a served attempt runs at its
                // check's reading.
                let at = match reading {
                    _ if !entry.paces => now,
                    Some(at) => at,
                    None => {
                        latest = self.clock();
                        latest
                    }
                };
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
                let sent_before = entry.conn.stats().sent_packets;
                let outcome = match entry.socket.as_deref_mut() {
                    Some(socket) => {
                        attempt(&mut entry.conn, socket, key, at, self.limits.max_segments)
                    }
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
                // Read once per attempt, off the per-packet path.
                let sent = entry.conn.stats().sent_packets - sent_before;
                self.sent_packets.set(self.sent_packets.get() + sent);
                self.sent_datagrams
                    .set(self.sent_datagrams.get() + u64::from(outcome.datagrams));
                let requeued = outcome.stop == Stop::BatchFull && spent < self.limits.requeues;
                match outcome.stop {
                    Stop::BatchFull if requeued => {
                        requeues += 1;
                        spent += 1;
                        entry.dirty = true;
                        queue.push_back(key);
                    }
                    Stop::BatchFull => self.mark_dirty(key, entry),
                    Stop::Socket => {
                        self.socket_stops.set(self.socket_stops.get() + 1);
                        if entry.socket.is_none() && !entry.parked {
                            entry.parked = true;
                            self.sched.borrow_mut().parked.push(key);
                        }
                    }
                    _ => {}
                }
                let flush = entry.paces && outcome.datagrams > 0;
                if entry.socket.is_some() && (!requeued || flush) {
                    self.flush_own(key, entry, at, outcome.stop == Stop::Socket);
                } else if entry.socket.is_none()
                    && flush
                    && server_flushes
                    && let Some(server) = &self.server
                {
                    server_flushes = !server.socket.borrow_mut().flush(at).blocked;
                }
                self.set_pacing(key, entry, outcome.pacing_at);
                if outcome.datagrams > 0 {
                    self.queue_app(key, entry);
                }
                self.after_transport(key, entry);
            });
        }
        self.sched.borrow_mut().tx_queue = queue;
        self.requeues.set(self.requeues.get() + requeues);
        if flush_server {
            self.flush_server(latest, cx);
        }
        #[cfg(test)]
        self.record.borrow_mut().end_phase();
    }

    /// Takes the pacing wake due earliest at `at` inside a transmit phase.
    fn take_pacing_wake(&self, at: Instant, queue: &mut VecDeque<ConnKey>) -> Take {
        #[cfg(test)]
        let due = self.sched.borrow().timers.next(Kind::Pacing);
        let Some(index) = self.sched.borrow_mut().timers.pop_due(Kind::Pacing, at) else {
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
                    let place = queue.iter().position(|&queued| queued == key)?;
                    queue.remove(place);
                }
                Some(key)
            })?
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
        let Some(server) = &self.server else {
            return;
        };
        let mut socket = server.socket.borrow_mut();
        let blocked = socket.flush(now).blocked && socket.poll_writable(cx).is_pending();
        let mut reports = mem::take(&mut self.sched.borrow_mut().reports);
        socket.drain_reports(|key, report| reports.push((key, report)));
        drop(socket);
        for (key, report) in reports.drain(..) {
            self.with_entry(key, "tx report", |entry| {
                #[cfg(debug_assertions)]
                debug_assert!(
                    entry.attempted_at.is_none_or(|last| last <= now),
                    "a connection's reports came before its last attempt"
                );
                entry.conn.on_tx_report(now, report);
                if matches!(report, TxReport::Dropped { .. }) {
                    self.mark_dirty(key, entry);
                }
            });
        }
        let mut sched = self.sched.borrow_mut();
        sched.reports = reports;
        sched.server_blocked = blocked;
        drop(sched);
        if blocked {
            return;
        }
        let parked = self.take_list(|sched| &mut sched.parked);
        for &key in &parked {
            self.with_entry(key, "transmit", |entry| {
                entry.parked = false;
                self.mark_dirty(key, entry);
            });
        }
        self.give_back(parked);
    }

    /// Retries the server socket's backlog once it is writable.
    fn server_writable(&self, now: Instant, cx: &mut Context<'_>) {
        let Some(server) = &self.server else {
            return;
        };
        if !self.sched.borrow().server_blocked
            || server.socket.borrow_mut().poll_writable(cx).is_pending()
        {
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
            socket: Some(socket),
            tx_waker,
            tx_blocked,
            ..
        } = entry
        else {
            return;
        };
        let mut dropped = false;
        *tx_blocked = socket.flush(now).blocked
            && socket
                .poll_writable(&mut Context::from_waker(tx_waker))
                .is_pending();
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
        }
        let own = self.take_list(|sched| &mut sched.rx);
        for &key in &own {
            self.with_entry(key, "receive", |entry| self.receive_own(key, entry));
        }
        self.give_back(own);
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
        self.serve_waiting(server, replies);
        let mut batches = 0;
        let mut resume = None;
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
                        Poll::Ready(Ok(_)) => 0,
                        Poll::Ready(Err(_)) => continue,
                        Poll::Pending => return,
                    }
                }
            };
            let now = self.clock();
            let (handled, incoming) = self.route_batch(server, now, start, replies);
            let Some(incoming) = incoming else {
                continue;
            };
            self.turn_handshakes.set(self.turn_handshakes.get() + 1);
            replies.extend(self.accept(server, now, incoming));
            resume = Some(handled);
        }
    }

    /// Takes the Initials kept from earlier turns, oldest first, while this turn's connection
    /// attempts last. Each is routed again: one may now belong to a connection an earlier one
    /// created, as the second datagram of a client's first flight does.
    fn serve_waiting(&self, server: &Server<B>, replies: &mut Vec<StatelessReply>) {
        if let Some(steering) = &self.steering {
            steering.take(|waiting| {
                self.steered_in.set(self.steered_in.get() + 1);
                self.queue_waiting(waiting);
            });
        }
        let now = self.clock();
        while self.turn_handshakes.get() < self.limits.handshakes {
            let Some(mut waiting) = self.sched.borrow_mut().waiting.pop_front() else {
                return;
            };
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
                        entry.conn.recv_batch(now, &mut [datagram]);
                        self.after_receive(key, entry);
                    });
                }
                Route::Accept(incoming) => {
                    self.turn_handshakes.set(self.turn_handshakes.get() + 1);
                    replies.extend(self.accept(server, now, incoming));
                }
                Route::Stateless(reply) => replies.push(reply),
                Route::Drop(_) => {}
            }
        }
    }

    /// Keeps for a later turn an Initial that came after this turn's connection attempts ran out,
    /// or drops it when too many wait already; its client sends it again.
    fn keep_waiting(&self, meta: &RxMeta, datagram: &[u8]) {
        if self.sched.borrow().waiting.len() >= self.limits.waiting_initials {
            self.dropped_initials.set(self.dropped_initials.get() + 1);
            return;
        }
        self.queue_waiting(Waiting {
            meta: *meta,
            datagram: datagram.to_vec(),
        });
    }

    /// Queues `waiting` to be routed again in a later turn, or drops it when too many wait
    /// already.
    fn queue_waiting(&self, waiting: Waiting) {
        let mut sched = self.sched.borrow_mut();
        if sched.waiting.len() >= self.limits.waiting_initials {
            self.dropped_initials.set(self.dropped_initials.get() + 1);
            return;
        }
        sched.waiting.push_back(waiting);
    }

    /// Routes the server socket's last batch from datagram `start` on, and hands each connection
    /// its datagrams in one `recv_batch`. Stops at an Initial for a new connection while this
    /// turn's connection attempts last, so the datagrams after it route to that connection once it
    /// exists; returns the datagrams handled and the Initial. Later Initials wait for a later turn,
    /// and the rest of the batch goes on to the connections it is for.
    fn route_batch(
        &self,
        server: &Server<B>,
        now: Instant,
        start: usize,
        replies: &mut Vec<StatelessReply>,
    ) -> (usize, Option<Incoming>) {
        let mut socket = server.socket.borrow_mut();
        let mut endpoint = self.endpoint.borrow_mut();
        let mut scratch = mem::take(&mut *self.rx_scratch.borrow_mut());
        let mut routed: Vec<Routed<'_>> = recycle(mem::take(&mut scratch.routed));
        let mut handled = 0;
        let mut incoming = None;
        'buffers: for (meta, buffer) in socket.buffers() {
            for datagram in buffer.chunks_mut(usize::from(meta.stride).max(1)) {
                handled += 1;
                if handled <= start {
                    continue;
                }
                match endpoint.route(now, meta, datagram) {
                    Route::Existing(key) => routed.push((key, handled, meta, datagram)),
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
                entry.conn.recv_batch(now, &mut datagrams);
                self.after_receive(key, entry);
            });
        }
        scratch.datagrams = recycle(datagrams);
        scratch.routed = recycle(routed);
        *self.rx_scratch.borrow_mut() = scratch;
        (handled, incoming)
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
        let mut rng = SecureRng(server.config.tls().crypto_provider().secure_random);
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
                self.insert(key, conn, session, None, paces);
                return None;
            }
            Ok(Err(_)) => {}
            Err(payload) => self.contain(ContainedPanicScope::Connection, "accept", payload),
        }
        self.slab.borrow_mut().cancel(key);
        self.drop_guarded(session);
        None
    }

    /// Receives from a connection's own socket.
    fn receive_own(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        let Entry {
            conn,
            socket: Some(socket),
            rx_waker,
            ..
        } = entry
        else {
            return;
        };
        let mut cx = Context::from_waker(rx_waker);
        let mut received = false;
        let mut drained = false;
        let mut spare = mem::take(&mut self.rx_scratch.borrow_mut().datagrams);
        for _ in 0..RX_BATCHES {
            match socket.poll_recv(&mut cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(_)) => continue,
                Poll::Pending => {
                    drained = true;
                    break;
                }
            }
            let now = self.clock();
            let mut datagrams: Vec<RxDatagram<'_>> = recycle(spare);
            for (meta, buffer) in socket.buffers() {
                for data in buffer.chunks_mut(usize::from(meta.stride).max(1)) {
                    datagrams.push(RxDatagram { meta, data });
                }
            }
            conn.recv_batch(now, &mut datagrams);
            spare = recycle(datagrams);
            received = true;
        }
        self.rx_scratch.borrow_mut().datagrams = spare;
        if !drained {
            self.sched.borrow_mut().rx.push(key);
        }
        if received {
            self.after_receive(key, entry);
        }
    }

    /// Queues the work a receive batch makes.
    fn after_receive(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        self.mark_dirty(key, entry);
        self.queue_app(key, entry);
        self.after_transport(key, entry);
    }

    /// Applies the connection's endpoint events and resyncs its deadline.
    fn after_transport(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        while let Some(event) = entry.conn.poll_endpoint_event() {
            #[cfg(test)]
            if let EndpointEvent::NewLocalCid { cid, .. } = event {
                self.issued.borrow_mut().push(cid);
            }
            self.endpoint.borrow_mut().handle_event(key, event);
        }
        self.resync(key, entry);
    }

    /// Decides between another turn, waiting for a wake and finishing, and arms the host wake
    /// before waiting.
    fn park(&self, cx: &mut Context<'_>) -> Next {
        let now = self.clock();
        let mut sched = self.sched.borrow_mut();
        let sched = &mut *sched;
        if !sched.dirty.is_empty()
            || !sched.app.is_empty()
            || !sched.app_next.is_empty()
            || !sched.app_first.is_empty()
            || !sched.rx.is_empty()
            || !sched.ready.is_empty()
            || !sched.waiting.is_empty()
            || mem::take(&mut sched.rx_more)
            || sched.quiesce_request.is_some()
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
        match sched.host_wake.arm(now, deadline, pacing, cx) {
            Poll::Ready(()) => Next::Again,
            Poll::Pending => Next::Park,
        }
    }

    /// Stores a new connection, due a transmit attempt and a first `poll_session`. `paces` is
    /// whether its transport config turns pacing on.
    fn insert(
        &self,
        key: ConnKey,
        conn: Connection,
        session: A::Session,
        socket: Option<Box<B>>,
        paces: bool,
    ) -> Arc<ConnWake> {
        let wake = ConnWake::new(Arc::clone(&self.shared), key);
        let mut sched = self.sched.borrow_mut();
        sched.dirty.push(key);
        sched.app.push(key);
        if socket.is_some() {
            sched.rx.push(key);
        }
        drop(sched);
        let entry = Entry {
            conn,
            session,
            app_waker: wake.waker(wake::APP),
            rx_waker: wake.waker(wake::RX),
            tx_waker: wake.waker(wake::TX),
            tx_blocked: false,
            parked: false,
            wake: Arc::clone(&wake),
            socket,
            dirty: true,
            app_queued: true,
            app_due: true,
            quiesce_due: self.sched.borrow().quiesce.is_some(),
            deadline: None,
            session_deadline: None,
            served_deadline: None,
            pacing: None,
            paces,
            #[cfg(debug_assertions)]
            attempted_at: None,
            stream_wakers: HashMap::new(),
            pull_turn: 0,
            pull_work: 0,
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
            self.sched.borrow_mut().dirty.push(key);
        }
    }

    fn queue_app(&self, key: ConnKey, entry: &mut Entry<A::Session, B>) {
        if !entry.app_queued {
            entry.app_queued = true;
            self.sched.borrow_mut().app.push(key);
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
                .set(Kind::Pacing, key.index, entry.pacing, at);
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
    /// Every transmit attempt, in order.
    pub(crate) attempts: Vec<AttemptRecord>,
    /// Every pacing wake taken, in order.
    pub(crate) wakes: Vec<WakeRecord>,
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
        if self.phase.is_some() {
            self.phase_clock_reads += 1;
        }
    }

    fn attempt(&mut self, key: ConnKey, at: Instant) {
        let phase = self.phase.expect("attempts run inside transmit phases");
        self.attempts.push(AttemptRecord { key, phase, at });
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

#[cfg(test)]
mod tests {
    use mvfstr_proto::Ecn;

    use super::*;

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
