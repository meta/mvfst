/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end tests: endpoint drivers on Roxygen workers over loopback UDP, or in the lab where a
//! scenario needs exact timing.

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_io::Backend;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_io::SocketOptions;
use mvfstr_io::TimerFd;
use mvfstr_io::TxCaps;
use mvfstr_proto::AckPolicy;
use mvfstr_proto::AppCode;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConfigError;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnectError;
use mvfstr_proto::Connection;
use mvfstr_proto::DatagramError;
use mvfstr_proto::Dir;
use mvfstr_proto::Endpoint;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::Initiator;
use mvfstr_proto::InlineSealer;
use mvfstr_proto::Inputs;
use mvfstr_proto::PathEvent;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::SrcPortBlocklist;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::TxLimits;
use mvfstr_proto::datagram::datagram_frame_len;
use mvfstr_proto::testing::TestRng;
use mvfstr_proto::testing::VecSink;
use roxygen_runtime::managed::RuntimeConfig;
use roxygen_runtime::managed::RuntimeOwner;
use roxygen_runtime::tokio_host::ManagedWorker;
use rustls::NamedGroup;
use rustls::client::ClientSessionStore;
use rustls::client::Resumption;
use rustls::client::Tls12ClientSessionValue;
use rustls::client::Tls13ClientSessionValue;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

use crate::Conn;
use crate::ConnHandle;
use crate::ConnInfo;
use crate::DatagramSink;
use crate::DriverConnectError;
use crate::DriverError;
use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::FineTimer;
use crate::HostTimers;
use crate::QuicApplication;
use crate::QuicSession;
use crate::Refusal;
use crate::SendSink;
use crate::Steering;
use crate::gated::Event;
use crate::gated::Gated;
use crate::gated::GatedOptions;
use crate::gated::Run;
use crate::gated::Valve;
use crate::gated::Valves;
use crate::lab::Bulk as LabBulk;
use crate::lab::Costs;
use crate::lab::Lab;
use crate::lab::LabApp;
use crate::lab::MemBackend;
use crate::lab::MemOptions;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::transport as lab_transport;
use crate::steer::handoff_lifetime;
use crate::test_support::ORDER;
use crate::test_support::configs;
use crate::test_support::mmsg_options;
use crate::test_support::reset_key;
use crate::timers::Kind;
use crate::turn::Limits;
use crate::turn::Mark;
use crate::turn::POLL_CHARGE;
use crate::turn::RX_BATCHES;
use crate::turn::TURN_STAGING;
use crate::turn::TxRecord;
use crate::turn::WakeRecord;

/// How long a test waits for something that should happen in milliseconds.
const WAIT: Duration = Duration::from_secs(20);

/// Well within the 16 s for which [`sluggish`] peers send only when prompted and their timers stay
/// quiet: a driver that waits for a wake with work left resumes only when one of those fires.
const STALL: Duration = Duration::from_secs(8);

/// An application whose sessions come from a closure.
struct App<S> {
    accept: Box<dyn FnMut(&ConnInfo) -> Result<S, Refusal>>,
    /// Where the application reports its `quiesce`.
    quiesced: Option<mpsc::Sender<Report>>,
    /// Whether the application panics in `quiesce`.
    quiesce_panics: bool,
    /// Transport settings for every accepted connection.
    transport: Option<Arc<TransportConfig>>,
}

impl<S: QuicSession> App<S> {
    fn new(accept: impl FnMut(&ConnInfo) -> Result<S, Refusal> + 'static) -> Self {
        Self {
            accept: Box::new(accept),
            quiesced: None,
            quiesce_panics: false,
            transport: None,
        }
    }

    /// Returns an application that only opens connections.
    fn client() -> Self {
        Self::new(|_| Err(Refusal::Ignore))
    }
}

impl<S: QuicSession> QuicApplication for App<S> {
    type Session = S;

    fn accept(&mut self, info: &ConnInfo, options: &mut ConnOptions) -> Result<S, Refusal> {
        options.transport = self.transport.clone();
        (self.accept)(info)
    }

    fn quiesce(&mut self) {
        if let Some(reports) = &self.quiesced {
            let _ = reports.send(Report::AppQuiesced);
        }
        if self.quiesce_panics {
            panic!("an application bug in quiesce");
        }
    }
}

type Handle<S, B = MmsgBackend> = EndpointHandle<App<S>, B>;

thread_local! {
    /// The handles of the drivers running on this worker thread.
    static HANDLES: RefCell<Vec<Box<dyn Any>>> = const { RefCell::new(Vec::new()) };
}

/// Runs `f` with the first driver of session type `S` on [`MmsgBackend`] on this worker thread.
fn with_handle<S: QuicSession, R>(f: impl FnOnce(&Handle<S>) -> R) -> R {
    with_backend_handle::<S, MmsgBackend, R>(f)
}

/// Runs `f` with the first driver of session type `S` on backend `B` on this worker thread.
fn with_backend_handle<S: QuicSession, B: Backend, R>(f: impl FnOnce(&Handle<S, B>) -> R) -> R {
    HANDLES.with(|handles| {
        let handles = handles.borrow();
        let handle = handles
            .iter()
            .find_map(|handle| handle.downcast_ref::<Handle<S, B>>())
            .expect("a driver runs on this worker");
        f(handle)
    })
}

/// Returns the turn the driver for sessions of type `S` on this worker thread is in.
fn current_turn<S: QuicSession>() -> u64 {
    with_handle::<S, _>(|handle| handle.stats().turns)
}

/// Starts a client driver for sessions of type `S` on backend `B` on this worker thread, unless
/// one runs.
fn ensure_client<S: QuicSession, B: Backend>(
    worker: &roxygen_runtime::worker::WorkerContext,
    endpoint: Arc<EndpointConfig>,
    options: B::Options,
    limits: Limits,
) {
    let running = HANDLES.with(|handles| {
        handles
            .borrow()
            .iter()
            .any(|handle| handle.is::<Handle<S, B>>())
    });
    if running {
        return;
    }
    let handle = EndpointDriver::<_, B>::builder(endpoint, App::<S>::client())
        .backend_options(options)
        .limits(limits)
        .spawn(worker)
        .expect("the client driver starts");
    HANDLES.with(|handles| handles.borrow_mut().push(Box::new(handle)));
}

/// Opens a connection to `addr` from the client driver for sessions of type `S` on backend `B`
/// on this worker thread.
fn open<S: QuicSession, B: Backend>(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    options: ConnOptions,
    session: S,
) -> ConnHandle {
    with_backend_handle::<S, B, _>(|handle| {
        handle.connect(
            addr,
            ServerName::try_from("localhost").expect("a DNS name"),
            config,
            options,
            session,
        )
    })
    .expect("the connection starts")
}

/// A server worker and a client worker with matching configs, whose drivers run on backend `B`.
struct Harness<B: Backend = MmsgBackend> {
    server: ManagedWorker,
    client: ManagedWorker,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    endpoint: Arc<EndpointConfig>,
    /// The per-turn caps and the transmit batch limit of both sides.
    limits: Limits,
    /// The socket settings of both sides.
    options: B::Options,
    /// The worker index and count the server driver is built with, if any.
    worker: Option<(u16, u16)>,
    /// A function, run on the server worker, that makes the server driver's timers in place of the
    /// default ones, if any.
    server_timers: Option<Arc<dyn Fn() -> HostTimers + Send + Sync>>,
}

impl Harness {
    fn new() -> Self {
        Self::with_options(mmsg_options())
    }

    /// Blocks `worker`'s thread in a command until the returned sender is dropped.
    fn block(worker: &ManagedWorker) -> mpsc::Sender<()> {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        worker
            .handle()
            .submit(move |_| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            })
            .expect("the worker takes commands");
        started_rx.recv_timeout(WAIT).expect("the worker blocks");
        release_tx
    }
}

impl<B: Backend> Harness<B>
where
    B::Options: Clone + Send,
{
    fn with_options(options: B::Options) -> Self {
        let (client_config, server_config, endpoint) = configs();
        Self {
            server: ManagedWorker::new(64).expect("a server worker"),
            client: ManagedWorker::new(64).expect("a client worker"),
            client_config,
            server_config,
            endpoint,
            limits: Limits::default(),
            options,
            worker: None,
            server_timers: None,
        }
    }

    /// Starts a server driver on the server worker with the application `make` builds there, and
    /// returns its address.
    fn serve<S: QuicSession>(&self, make: impl FnOnce() -> App<S> + Send + 'static) -> SocketAddr {
        let (tx, rx) = mpsc::channel();
        let (endpoint, config) = (self.endpoint.clone(), self.server_config.clone());
        let (limits, options, index) = (self.limits, self.options.clone(), self.worker);
        let timers = self.server_timers.clone();
        self.server
            .handle()
            .submit(move |worker| {
                let mut builder = EndpointDriver::<_, B>::builder(endpoint, make())
                    .bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config)
                    .backend_options(options)
                    .limits(limits);
                if let Some((index, count)) = index {
                    builder = builder.worker(index, count);
                }
                if let Some(timers) = timers {
                    builder = builder.host_timers(timers());
                }
                let handle = builder.spawn(worker).expect("the server driver starts");
                let _ = tx.send(handle.local_addr().expect("the server is bound"));
                HANDLES.with(|handles| handles.borrow_mut().push(Box::new(handle)));
            })
            .expect("the server worker takes commands");
        rx.recv_timeout(WAIT).expect("the server driver starts")
    }

    /// Opens a connection from the client worker to `addr` with the session `make` builds there,
    /// starting the client's driver on first use.
    fn connect<S: QuicSession>(
        &self,
        addr: SocketAddr,
        make: impl FnOnce() -> S + Send + 'static,
    ) -> ConnHandle {
        self.connect_with(addr, ConnOptions::default(), make)
    }

    /// Like [`connect`](Self::connect), with `options` for the connection.
    fn connect_with<S: QuicSession>(
        &self,
        addr: SocketAddr,
        options: ConnOptions,
        make: impl FnOnce() -> S + Send + 'static,
    ) -> ConnHandle {
        let (tx, rx) = mpsc::channel();
        let (endpoint, config) = (self.endpoint.clone(), self.client_config.clone());
        let (limits, socket) = (self.limits, self.options.clone());
        self.client
            .handle()
            .submit(move |worker| {
                ensure_client::<S, B>(worker, endpoint, socket, limits);
                let _ = tx.send(open::<S, B>(addr, config, options, make()));
            })
            .expect("the client worker takes commands");
        rx.recv_timeout(WAIT).expect("the connection starts")
    }

    /// Opens `count` connections to `addr` from the client worker in one go, so the client's
    /// next turn sends all their Initials, and returns them with the client driver's turn count
    /// at that point.
    fn connect_all<S: QuicSession>(
        &self,
        addr: SocketAddr,
        count: usize,
        make: impl Fn() -> S + Send + 'static,
    ) -> (Vec<ConnHandle>, u64) {
        let (tx, rx) = mpsc::channel();
        let (endpoint, config) = (self.endpoint.clone(), self.client_config.clone());
        let (limits, socket) = (self.limits, self.options.clone());
        self.client
            .handle()
            .submit(move |worker| {
                ensure_client::<S, B>(worker, endpoint, socket, limits);
                let conns = (0..count)
                    .map(|_| open::<S, B>(addr, config.clone(), ConnOptions::default(), make()))
                    .collect();
                let turn = with_backend_handle::<S, B, _>(|handle| handle.stats().turns);
                let _ = tx.send((conns, turn));
            })
            .expect("the client worker takes commands");
        rx.recv_timeout(WAIT).expect("the connections start")
    }

    /// Waits until the client driver for sessions of type `S` has finished turn `turn`.
    fn await_client_turn<S: QuicSession>(&self, turn: u64) {
        // A command runs between the driver's polls, so a turn counted when it runs has finished.
        let deadline = Instant::now() + WAIT;
        while self.client_stats::<S>().turns < turn {
            assert!(Instant::now() < deadline, "the client driver never ran");
        }
    }

    /// Waits until the server driver for sessions of type `S` has finished.
    fn await_server_finished<S: QuicSession>(&self) {
        let deadline = Instant::now() + WAIT;
        loop {
            let (tx, rx) = mpsc::channel();
            self.server
                .handle()
                .submit(move |_| {
                    let _ = tx.send(with_backend_handle::<S, B, _>(|handle| handle.local_addr()));
                })
                .expect("the server worker takes commands");
            if rx
                .recv_timeout(WAIT)
                .expect("the server worker answers")
                .is_none()
            {
                return;
            }
            assert!(Instant::now() < deadline, "the driver kept running");
            std::thread::yield_now();
        }
    }

    /// Returns the counters of the client worker's driver for sessions of type `S`.
    fn client_stats<S: QuicSession>(&self) -> crate::EndpointStats {
        Self::stats::<S>(&self.client)
    }

    /// Returns the counters of the server worker's driver for sessions of type `S`.
    fn server_stats<S: QuicSession>(&self) -> crate::EndpointStats {
        Self::stats::<S>(&self.server)
    }

    fn stats<S: QuicSession>(worker: &ManagedWorker) -> crate::EndpointStats {
        let (tx, rx) = mpsc::channel();
        worker
            .handle()
            .submit(move |_| {
                let _ = tx.send(with_backend_handle::<S, B, _>(|handle| handle.stats()));
            })
            .expect("the worker takes commands");
        rx.recv_timeout(WAIT).expect("the worker answers")
    }

    /// Returns the build horizon of every connection of the driver for sessions of type `S` on
    /// `worker`, with the timers that hold its pacing wakes.
    fn build_horizons<S: QuicSession>(worker: &ManagedWorker) -> Vec<(Duration, Kind)> {
        let (tx, rx) = mpsc::channel();
        worker
            .handle()
            .submit(move |_| {
                let _ = tx.send(with_backend_handle::<S, B, _>(|handle| {
                    handle.build_horizons()
                }));
            })
            .expect("the worker takes commands");
        rx.recv_timeout(WAIT).expect("the worker answers")
    }

    /// Returns how many times the server worker's driver for sessions of type `S` chose the
    /// timerfd for a pacing wake.
    fn server_fine_plans<S: QuicSession>(&self) -> u32 {
        let (tx, rx) = mpsc::channel();
        self.server
            .handle()
            .submit(move |_| {
                let _ = tx.send(with_backend_handle::<S, B, _>(|handle| handle.fine_plans()));
            })
            .expect("the worker takes commands");
        rx.recv_timeout(WAIT).expect("the worker answers")
    }

    /// Returns the server socket's capabilities as the driver for sessions of type `S` on
    /// `worker` reports them.
    fn server_caps<S: QuicSession>(worker: &ManagedWorker) -> Option<TxCaps> {
        let (tx, rx) = mpsc::channel();
        worker
            .handle()
            .submit(move |_| {
                let _ = tx.send(with_backend_handle::<S, B, _>(|handle| {
                    handle.server_caps()
                }));
            })
            .expect("the worker takes commands");
        rx.recv_timeout(WAIT).expect("the worker answers")
    }

    /// Shuts both workers down, which must stop their drivers.
    fn shutdown(self) {
        let Self { server, client, .. } = self;
        client
            .shutdown()
            .expect("the client worker shuts down cleanly");
        server
            .shutdown()
            .expect("the server worker shuts down cleanly");
    }
}

/// A report from a session or an application to the test thread.
#[derive(Debug, PartialEq)]
enum Report {
    Event(&'static str, ConnEvent),
    /// The peer opened a stream.
    Opened(&'static str, StreamId),
    /// A stream's echo came back whole; `true` if it matched what was sent.
    Echoed(StreamId, bool),
    /// A stream was reaped.
    Closed(&'static str, StreamId),
    /// A unidirectional stream ended after this many bytes.
    Received(StreamId, usize),
    /// The pull producer's streams were each polled this many times before it released them.
    PolledBeforeRelease(usize),
    /// `poll_session` ran and read this token.
    Polled(usize),
    /// `poll_session` ran at the session's deadline, by both the driver's clock and the real one.
    DeadlineMet(bool),
    /// A session is about to panic.
    Panicking,
    /// The application's `quiesce` ran.
    AppQuiesced,
    /// A session's `on_quiesce` ran.
    SessionQuiesced,
    /// A producer or a session ran in this turn of its driver.
    PolledInTurn(u64),
    /// The server application accepted a connection in this turn of its driver.
    Accepted(u64),
    /// The echo of the one stream a crowded connection produced came back whole.
    LastEchoed(bool),
    /// A session's first `poll_session` read a clock no earlier than the end of its accept.
    FreshClock(bool),
    /// A client opened a stream after the server's `shutdown`.
    OpenedAfterShutdown(bool),
    /// The server application's `accept` ran for its connection attempt with this number, from 1.
    Attempt(usize),
    /// The named connection's producer was polled in this turn of its driver.
    Produced(&'static str, u64),
    /// A server session first read its peer's stream in this turn of its driver.
    Heard(u64),
    /// A session started keeping a deadline due in every turn.
    Spinning,
    /// The client session got this event in this turn of its driver.
    HeardInTurn(ConnEvent, u64),
    /// A client had declared this many packets lost when its handshake completed.
    LostByConnected(u64),
    /// The named session was dropped.
    Dropped(&'static str),
    /// The server application of this worker accepted a connection from this address.
    AcceptedOn(u16, SocketAddr),
    /// A connection had sent this many packets when it drained.
    SentPackets(u64),
    /// The server driver's counters as the first stream of a burst opened.
    Counters(crate::EndpointStats),
    /// In this turn of its driver, a producer staged this many bytes.
    Staged(u64, usize),
    /// A datagram sink took or refused a datagram.
    DatagramPushed(Result<(), DatagramError>),
    /// A session had read this many datagrams; `true` if one was stale.
    DatagramsRead(usize, bool),
    /// A stream's producer was first polled while its session had this many datagrams left to
    /// push, this many turns of its driver after the session first pushed one.
    StreamFirstPolled(usize, Option<u64>),
    /// A datagram producer found this allowance in its sink on its first poll after its stream
    /// sent.
    DatagramAllowance(usize),
    /// A datagram producer that stays ready found these allowances in its sink, one per poll,
    /// until a while after its waker fired.
    DatagramPolls(Vec<usize>),
}

/// Reads and consumes every readable byte of stream `id`.
fn read_all(conn: &mut Conn<'_>, id: StreamId) -> Vec<Bytes> {
    let Ok(mut stream) = conn.stream(id) else {
        return Vec::new();
    };
    let segments: Vec<Bytes> = stream.readable().segments().cloned().collect();
    let len = segments.iter().map(Bytes::len).sum();
    stream.consume(len).expect("the bytes are readable");
    segments
}

/// Pushes as much of `queue` as stream `id` takes, then the FIN once `fin` is set and the queue
/// is empty; returns whether the FIN went out.
fn push_all(conn: &mut Conn<'_>, id: StreamId, queue: &mut VecDeque<Bytes>, fin: bool) -> bool {
    let Ok(mut stream) = conn.stream(id) else {
        return true;
    };
    while let Some(front) = queue.front_mut() {
        stream.send(front).expect("the stream takes data");
        if !front.is_empty() {
            return false;
        }
        queue.pop_front();
    }
    fin && stream.finish().is_ok()
}

/// A server session that echoes every stream through the push path.
struct Echo {
    reports: mpsc::Sender<Report>,
    /// Per stream: bytes not yet pushed, and whether the peer's FIN arrived.
    streams: HashMap<StreamId, (VecDeque<Bytes>, bool)>,
    /// Bytes read per unidirectional stream, which cannot carry an echo back.
    uni: HashMap<StreamId, usize>,
}

impl Echo {
    fn new(reports: mpsc::Sender<Report>) -> Self {
        Self {
            reports,
            streams: HashMap::new(),
            uni: HashMap::new(),
        }
    }
}

impl QuicSession for Echo {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        match ready {
            StreamReady::Opened => {
                let _ = self.reports.send(Report::Opened("server", id));
            }
            StreamReady::Readable | StreamReady::Finished if id.dir() == Dir::Uni => {
                let len = self.uni.entry(id).or_default();
                *len += read_all(conn, id).iter().map(Bytes::len).sum::<usize>();
                if ready == StreamReady::Finished {
                    let _ = self.reports.send(Report::Received(id, *len));
                }
            }
            StreamReady::Readable | StreamReady::Finished | StreamReady::Writable => {
                let (queue, fin) = self.streams.entry(id).or_default();
                queue.extend(read_all(conn, id));
                *fin |= ready == StreamReady::Finished;
                if push_all(conn, id, queue, *fin) {
                    self.streams.remove(&id);
                }
            }
            StreamReady::Closed => {
                let _ = self.reports.send(Report::Closed("server", id));
            }
            StreamReady::Progress | StreamReady::Stopped { .. } | StreamReady::Reset { .. } => {}
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that sends `payload` on `streams` bidirectional streams through the push
/// path once connected, and checks each echo.
struct PushClient {
    streams: usize,
    payload: Bytes,
    reports: mpsc::Sender<Report>,
    unsent: HashMap<StreamId, VecDeque<Bytes>>,
    received: HashMap<StreamId, Vec<u8>>,
}

impl PushClient {
    fn new(streams: usize, payload: Bytes, reports: mpsc::Sender<Report>) -> Self {
        Self {
            streams,
            payload,
            reports,
            unsent: HashMap::new(),
            received: HashMap::new(),
        }
    }
}

impl QuicSession for PushClient {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        for _ in 0..self.streams {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([self.payload.clone()]);
            if !push_all(conn, id, &mut queue, true) {
                self.unsent.insert(id, queue);
            }
            self.received.insert(id, Vec::new());
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        match ready {
            StreamReady::Writable => {
                if let Some(queue) = self.unsent.get_mut(&id)
                    && push_all(conn, id, queue, true)
                {
                    self.unsent.remove(&id);
                }
            }
            StreamReady::Readable | StreamReady::Finished => {
                let received = self.received.entry(id).or_default();
                for segment in read_all(conn, id) {
                    received.extend_from_slice(&segment);
                }
                if ready == StreamReady::Finished {
                    let _ = self
                        .reports
                        .send(Report::Echoed(id, received[..] == self.payload[..]));
                }
            }
            StreamReady::Closed => {
                let _ = self.reports.send(Report::Closed("client", id));
            }
            StreamReady::Opened
            | StreamReady::Progress
            | StreamReady::Stopped { .. }
            | StreamReady::Reset { .. } => {}
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// The stream wakers of a pending producer, woken together from another thread.
#[derive(Default)]
struct Release {
    released: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

/// A client session that, once connected, opens `bidi` bidirectional streams and one
/// unidirectional stream, wakes their producers, and produces `payload` on each through the pull
/// path. Its producer stays pending until every stream has been polled once; then a thread
/// releases them through their stream wakers. It checks each echo.
struct PullClient {
    bidi: usize,
    payload: Bytes,
    reports: mpsc::Sender<Report>,
    unsent: HashMap<StreamId, Bytes>,
    received: HashMap<StreamId, Vec<u8>>,
    release: Arc<Release>,
    polls_before_release: usize,
}

impl PullClient {
    fn new(bidi: usize, payload: Bytes, reports: mpsc::Sender<Report>) -> Self {
        Self {
            bidi,
            payload,
            reports,
            unsent: HashMap::new(),
            received: HashMap::new(),
            release: Arc::default(),
            polls_before_release: 0,
        }
    }
}

impl QuicSession for PullClient {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        for dir in std::iter::repeat_n(Dir::Bi, self.bidi).chain([Dir::Uni]) {
            let id = conn.open_stream(dir, ORDER).expect("a stream opens");
            self.unsent.insert(id, self.payload.clone());
            conn.stream_waker(id).wake();
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            let received = self.received.entry(id).or_default();
            for segment in read_all(conn, id) {
                received.extend_from_slice(&segment);
            }
            if ready == StreamReady::Finished {
                let _ = self
                    .reports
                    .send(Report::Echoed(id, received[..] == self.payload[..]));
            }
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        let Some(unsent) = self.unsent.get_mut(&id) else {
            return Poll::Pending;
        };
        if !self.release.released.load(Ordering::SeqCst) {
            self.polls_before_release += 1;
            let mut wakers = self.release.wakers.lock().unwrap();
            wakers.push(cx.waker().clone());
            if wakers.len() == self.bidi + 1 {
                let _ = self.reports.send(Report::PolledBeforeRelease(
                    self.polls_before_release / (self.bidi + 1),
                ));
                let release = Arc::clone(&self.release);
                std::thread::spawn(move || {
                    release.released.store(true, Ordering::SeqCst);
                    for waker in release.wakers.lock().unwrap().drain(..) {
                        waker.wake();
                    }
                });
            }
            return Poll::Pending;
        }
        let len = unsent.len().min(sink.allowance());
        sink.push(unsent.split_to(len))
            .expect("within the allowance");
        if unsent.is_empty() {
            sink.finish().expect("the stream is open");
            self.unsent.remove(&id);
        }
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that opens a bidirectional stream once connected and leaves its producer
/// unwoken until the next `poll_session`, which a handle wake brings after the pull step of the
/// run that opened the stream. That `poll_session` reports how often the producer was polled so
/// far and fires the stream's waker; the producer then sends `hello` and the FIN.
struct WokenLater {
    reports: mpsc::Sender<Report>,
    waker: Option<Waker>,
    woken: bool,
    polls: usize,
    received: Vec<u8>,
}

impl WokenLater {
    fn new(reports: mpsc::Sender<Report>) -> Self {
        Self {
            reports,
            waker: None,
            woken: false,
            polls: 0,
            received: Vec::new(),
        }
    }
}

impl QuicSession for WokenLater {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
        self.waker = Some(conn.stream_waker(id));
        conn.handle().wake().expect("the connection is live");
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            for segment in read_all(conn, id) {
                self.received.extend_from_slice(&segment);
            }
            if ready == StreamReady::Finished {
                let _ = self
                    .reports
                    .send(Report::Echoed(id, self.received == b"hello"));
            }
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        if !self.woken {
            self.polls += 1;
            return Poll::Pending;
        }
        sink.push(Bytes::from_static(b"hello"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        if let Some(waker) = self.waker.take() {
            let _ = self.reports.send(Report::PolledBeforeRelease(self.polls));
            self.woken = true;
            waker.wake();
        }
        Poll::Pending
    }
}

/// A client session that wakes the producer of the stream it opens once connected. The producer
/// stages `first` on its first poll, returns `Pending` (or, with `ready_first`, `Ready`) and
/// keeps the stream's waker. Three later `poll_session`s pass, each brought by a handle wake and
/// each followed by a pull step; the third reports how often the producer was polled so far and
/// fires that waker. The producer then sends the rest of `hello` and the FIN.
struct Parked {
    reports: mpsc::Sender<Report>,
    first: &'static [u8],
    ready_first: bool,
    handle: Option<ConnHandle>,
    waker: Option<Waker>,
    sessions: usize,
    released: bool,
    polls: usize,
    received: Vec<u8>,
}

impl Parked {
    fn new(first: &'static [u8], reports: mpsc::Sender<Report>) -> Self {
        Self {
            reports,
            first,
            ready_first: false,
            handle: None,
            waker: None,
            sessions: 0,
            released: false,
            polls: 0,
            received: Vec::new(),
        }
    }

    /// Creates a producer whose first poll returns `Ready` without producing anything.
    fn empty_ready(reports: mpsc::Sender<Report>) -> Self {
        Self {
            ready_first: true,
            ..Self::new(b"", reports)
        }
    }

    fn wake_session(&self) {
        self.handle
            .as_ref()
            .expect("the session is connected")
            .wake()
            .expect("the connection is live");
    }
}

impl QuicSession for Parked {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
        conn.stream_waker(id).wake();
        self.handle = Some(conn.handle());
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            for segment in read_all(conn, id) {
                self.received.extend_from_slice(&segment);
            }
            if ready == StreamReady::Finished {
                let _ = self
                    .reports
                    .send(Report::Echoed(id, self.received == b"hello"));
            }
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        _: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        if self.released {
            sink.push(Bytes::from_static(&b"hello"[self.first.len()..]))
                .expect("within the allowance");
            sink.finish().expect("the stream is open");
            return Poll::Ready(());
        }
        self.polls += 1;
        if self.waker.is_none() {
            sink.push(Bytes::from_static(self.first))
                .expect("within the allowance");
            self.waker = Some(cx.waker().clone());
            self.wake_session();
        }
        if self.ready_first {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        if self.released || self.waker.is_none() {
            return Poll::Pending;
        }
        self.sessions += 1;
        if self.sessions < 3 {
            self.wake_session();
            return Poll::Pending;
        }
        let _ = self.reports.send(Report::PolledBeforeRelease(self.polls));
        self.released = true;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        Poll::Pending
    }
}

/// A client session that reports its events, and each `poll_session` with the token the test
/// thread set before waking it.
struct Waking {
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
}

impl QuicSession for Waking {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        let token = self.token.load(Ordering::SeqCst);
        let _ = self.reports.send(Report::Polled(token));
        Poll::Pending
    }
}

/// A client session whose `deadline` is 50 ms after it connects.
struct Timed {
    reports: mpsc::Sender<Report>,
    deadline: Option<Instant>,
}

impl QuicSession for Timed {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            self.deadline = Some(conn.now() + Duration::from_millis(50));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if let Some(at) = self.deadline
            && conn.now() >= at
        {
            self.deadline = None;
            let _ = self.reports.send(Report::DeadlineMet(Instant::now() >= at));
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// A server session: an echo, or one that panics when the peer opens a stream.
enum MaybePanic {
    Echo(Echo),
    Panic(mpsc::Sender<Report>),
}

impl QuicSession for MaybePanic {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if let Self::Echo(echo) = self {
            echo.on_event(conn, event);
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        match self {
            Self::Echo(echo) => echo.on_stream(conn, id, ready),
            Self::Panic(reports) => {
                let _ = reports.send(Report::Panicking);
                panic!("a session bug");
            }
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        match self {
            Self::Echo(echo) => echo.poll_send(cx, id, sink),
            Self::Panic(_) => Poll::Pending,
        }
    }

    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        match self {
            Self::Echo(echo) => echo.poll_session(cx, conn),
            Self::Panic(_) => Poll::Pending,
        }
    }
}

/// A server session that reports its events and its `on_quiesce`.
struct Quiet {
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Quiet {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("server", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn on_quiesce(&mut self, _: &mut Conn<'_>) {
        let _ = self.reports.send(Report::SessionQuiesced);
    }
}

/// A client session that works only through what `Conn` lends: once connected it wakes itself
/// through `Conn::handle` from another thread, and opens a unidirectional stream whose producer
/// waits for the `Conn::stream_waker` that `poll_session` fires on that wake.
struct Helpers {
    stream: Option<(StreamId, Waker)>,
    polls: usize,
    ready: bool,
}

impl QuicSession for Helpers {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        let id = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
        self.stream = Some((id, conn.stream_waker(id)));
        let handle = conn.handle();
        std::thread::spawn(move || handle.wake().expect("the connection is live"));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        if !self.ready {
            return Poll::Pending;
        }
        sink.push(Bytes::from_static(b"hi"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        self.polls += 1;
        // The first poll comes with the connection; a later one needs the handle's wake.
        if self.polls > 1
            && let Some((_, waker)) = self.stream.take()
        {
            self.ready = true;
            waker.wake();
        }
        Poll::Pending
    }
}

/// Returns a payload of `len` bytes that differ from stream offset to offset.
fn payload(len: usize) -> Bytes {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Returns the ID of the `n`th client-initiated bidirectional stream.
fn client_bidi(n: u32) -> StreamId {
    StreamId::from_varint(mvfstr_proto::VarInt::from_u32(4 * n))
}

/// A session that only reports its events.
struct Recorder {
    name: &'static str,
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Recorder {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event(self.name, event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// Waits until every report in `expected` has arrived, in any order, and returns the others.
fn await_reports(rx: &mpsc::Receiver<Report>, expected: Vec<Report>) -> Vec<Report> {
    gather(rx, expected, || WAIT)
}

/// Like [`await_reports`], for at most `within` in all.
fn await_reports_within(
    rx: &mpsc::Receiver<Report>,
    expected: Vec<Report>,
    within: Duration,
) -> Vec<Report> {
    let deadline = Instant::now() + within;
    gather(rx, expected, || {
        deadline.saturating_duration_since(Instant::now())
    })
}

/// Waits for each report in `expected` for at most what `wait` returns before it.
fn gather(
    rx: &mpsc::Receiver<Report>,
    mut expected: Vec<Report>,
    wait: impl Fn() -> Duration,
) -> Vec<Report> {
    let mut others = Vec::new();
    while !expected.is_empty() {
        let report = rx
            .recv_timeout(wait())
            .unwrap_or_else(|_| panic!("still waiting for {expected:?}; saw {others:?}"));
        match expected.iter().position(|wanted| *wanted == report) {
            Some(i) => {
                expected.swap_remove(i);
            }
            None => others.push(report),
        }
    }
    others
}

#[test]
fn two_harnesses_get_different_reset_keys() {
    // Otherwise a client accepts a stateless reset from another test's server.
    let (first, second) = (Harness::new(), Harness::new());
    assert_ne!(first.endpoint.reset_key(), second.endpoint.reset_key());
    first.shutdown();
    second.shutdown();
}

#[test]
fn endpoint_configs_that_tests_set_in_place_of_the_harness_ones_get_their_own_reset_keys() {
    let configs = [
        zero_length_cids(),
        zero_length_cids(),
        building_ahead(Duration::ZERO),
        building_ahead(Duration::ZERO),
    ];
    let keys: BTreeSet<[u8; 32]> = configs.iter().map(|config| *config.reset_key()).collect();
    assert_eq!(keys.len(), configs.len(), "{keys:?}");
}

#[test]
fn a_client_and_a_server_on_two_workers_complete_a_handshake() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(
        &rx,
        vec![
            Report::Event("client", ConnEvent::Connected),
            Report::Event("server", ConnEvent::Connected),
            Report::Event("client", ConnEvent::Confirmed),
            Report::Event("server", ConnEvent::Confirmed),
        ],
    );
    harness.shutdown();
}

#[test]
fn streams_echo_through_the_push_path_with_every_readiness_edge() {
    const STREAMS: u32 = 4;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || {
        PushClient::new(STREAMS as usize, payload(200_000), tx)
    });
    let ids = (0..STREAMS).map(client_bidi);
    await_reports(
        &rx,
        ids.flat_map(|id| {
            [
                Report::Opened("server", id),
                Report::Echoed(id, true),
                Report::Closed("server", id),
                Report::Closed("client", id),
            ]
        })
        .collect(),
    );
    harness.shutdown();
}

#[test]
fn streams_produced_through_the_pull_path_resume_on_their_stream_wakers() {
    const BIDI: u32 = 3;
    const LEN: usize = 300_000;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || {
        PullClient::new(BIDI as usize, payload(LEN), tx)
    });
    let uni = StreamId::from_varint(mvfstr_proto::VarInt::from_u32(2));
    let mut expected: Vec<Report> = (0..BIDI)
        .map(|n| Report::Echoed(client_bidi(n), true))
        .collect();
    expected.extend([Report::Received(uni, LEN), Report::PolledBeforeRelease(1)]);
    await_reports(&rx, expected);
    harness.shutdown();
}

#[test]
fn a_ready_without_progress_counts_and_waits_for_the_stream_waker() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Parked::empty_ready(tx));
    await_reports(
        &rx,
        vec![
            Report::PolledBeforeRelease(1),
            Report::Echoed(client_bidi(0), true),
        ],
    );
    assert_eq!(harness.client_stats::<Parked>().empty_ready_polls, 1);
    harness.shutdown();
}

#[test]
fn a_new_stream_is_not_polled_until_its_waker_fires() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || WokenLater::new(tx));
    await_reports(
        &rx,
        vec![
            Report::PolledBeforeRelease(0),
            Report::Echoed(client_bidi(0), true),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_pending_producer_is_not_polled_again_until_its_waker_fires() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Parked::new(b"", tx));
    await_reports(
        &rx,
        vec![
            Report::PolledBeforeRelease(1),
            Report::Echoed(client_bidi(0), true),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_producer_that_returns_pending_after_staging_bytes_waits_for_its_waker() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Parked::new(b"hel", tx));
    await_reports(
        &rx,
        vec![
            Report::PolledBeforeRelease(1),
            Report::Echoed(client_bidi(0), true),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_bulk_echo_in_both_directions_requeues_full_batches() {
    const LEN: usize = 4_000_000;
    let mut harness = Harness::new();
    harness.limits.max_segments = 2;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || PushClient::new(1, payload(LEN), tx));
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    let client = harness.client_stats::<PushClient>();
    let server = harness.server_stats::<Echo>();
    assert!(
        client.requeues > 0,
        "the client never re-queued: {client:?}"
    );
    assert!(
        server.requeues > 0,
        "the server never re-queued: {server:?}"
    );
    harness.shutdown();
}

#[test]
fn bulk_echoes_finish_while_the_sockets_refuse_most_attempts() {
    const LEN: usize = 2_000_000;
    let mut harness = Harness::new();
    // Four datagrams of built but unsent bytes per connection: most attempts hit the limit.
    harness.options.max_unsent = 4 * 1500;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || PushClient::new(1, payload(LEN), tx));
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    let client = harness.client_stats::<PushClient>();
    let server = harness.server_stats::<Echo>();
    assert!(
        client.socket_stops > 0,
        "the client socket never refused: {client:?}"
    );
    assert!(
        server.socket_stops > 0,
        "the server socket never refused: {server:?}"
    );
    harness.shutdown();
}

#[test]
fn many_connections_with_many_streams_echo_concurrently() {
    const CONNECTIONS: usize = 8;
    const STREAMS: u32 = 16;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let mut conns = Vec::new();
    for _ in 0..CONNECTIONS {
        let tx = tx.clone();
        conns.push(harness.connect(addr, move || {
            PushClient::new(STREAMS as usize, payload(50_000), tx)
        }));
    }
    let expected = (0..CONNECTIONS)
        .flat_map(|_| (0..STREAMS).map(|n| Report::Echoed(client_bidi(n), true)))
        .collect();
    await_reports(&rx, expected);
    harness.shutdown();
}

#[test]
fn a_handle_wakes_and_closes_its_connection_from_another_thread() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let token = Arc::new(AtomicUsize::new(0));
    let session_token = Arc::clone(&token);
    let conn = harness.connect(addr, move || Waking {
        reports: tx,
        token: session_token,
    });
    conn.wake().expect("the connection is live");
    await_reports(
        &rx,
        vec![
            Report::Polled(0),
            Report::Event("client", ConnEvent::Connected),
            Report::Event("server", ConnEvent::Connected),
        ],
    );

    token.store(1, Ordering::SeqCst);
    let waker = conn.clone();
    std::thread::spawn(move || waker.wake())
        .join()
        .expect("the waking thread finishes")
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Polled(1)]);

    let code = mvfstr_proto::AppCode::from_u32(42);
    let reason = Bytes::from_static(b"done");
    conn.close(code, reason.clone())
        .expect("the connection is live");
    let closed = |initiator| ConnEvent::Closed {
        reason: CloseReason::Application {
            code,
            reason: reason.clone(),
        },
        initiator,
    };
    await_reports(
        &rx,
        vec![
            Report::Event("client", closed(Initiator::Local)),
            Report::Event("server", closed(Initiator::Peer)),
            Report::Event("client", ConnEvent::Drained),
        ],
    );
    let gone = Instant::now() + WAIT;
    while conn.wake().is_ok() {
        assert!(Instant::now() < gone, "the handle outlived its connection");
        std::thread::yield_now();
    }
    assert_eq!(conn.wake(), Err(crate::SubmitError::Closed));
    harness.shutdown();
}

#[test]
fn a_session_deadline_runs_poll_session_no_earlier_than_asked() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let _conn = harness.connect(addr, move || Timed {
        reports: tx,
        deadline: None,
    });
    await_reports(&rx, vec![Report::DeadlineMet(true)]);
    harness.shutdown();
}

#[test]
fn a_session_panic_tears_down_only_its_own_connection() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut accepted = 0;
        App::new(move |_| {
            accepted += 1;
            Ok(if accepted == 1 {
                MaybePanic::Panic(server_reports.clone())
            } else {
                MaybePanic::Echo(Echo::new(server_reports.clone()))
            })
        })
    });
    let first = tx.clone();
    let _doomed = harness.connect(addr, move || PushClient::new(1, payload(1000), first));
    await_reports(&rx, vec![Report::Panicking]);
    let _healthy = harness.connect(addr, move || PushClient::new(1, payload(100_000), tx));
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    let stats = harness.server.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1);
    assert_eq!(stats.contained_driver_panics, 0);
    assert_eq!(harness.server_stats::<MaybePanic>().contained_panics, 1);
    harness.shutdown();
}

#[test]
fn a_refused_connection_attempt_hears_connection_refused() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(|| App::<Recorder>::new(|_| Err(Refusal::Refuse)));
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(
        &rx,
        vec![Report::Event(
            "client",
            ConnEvent::Closed {
                reason: CloseReason::Transport {
                    code: mvfstr_proto::TransportErrorCode::CONNECTION_REFUSED,
                    frame_type: Some(mvfstr_proto::VarInt::ZERO),
                    reason: Bytes::new(),
                },
                initiator: Initiator::Peer,
            },
        )],
    );
    harness.shutdown();
}

#[test]
fn a_connection_attempt_refused_by_version_negotiation_finds_no_common_version() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(|| App::<Recorder>::new(|_| Err(Refusal::VersionNegotiation)));
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(
        &rx,
        vec![Report::Event(
            "client",
            ConnEvent::Closed {
                reason: CloseReason::NoCommonVersion,
                initiator: Initiator::Peer,
            },
        )],
    );
    harness.shutdown();
}

#[test]
fn a_source_port_blocklist_applies_from_the_next_connection_attempt() {
    let harness = Harness::new();
    let addr = harness.serve(|| App::<Recorder>::new(|_| Err(Refusal::Refuse)));
    let (_client, initial) = client_initial(&harness, addr, |_| true);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let port = peer.local_addr().expect("a bound socket").port();
    assert!(
        answers(&harness, addr, &peer, &initial),
        "no list blocks the port yet"
    );
    set_src_port_blocklist::<Recorder>(&harness, Some(SrcPortBlocklist::new(0, [port])));
    assert!(
        !answers(&harness, addr, &peer, &initial),
        "the new list blocks the port"
    );
    set_src_port_blocklist::<Recorder>(&harness, None);
    assert!(
        answers(&harness, addr, &peer, &initial),
        "the port is let in again once the list is cleared"
    );
    harness.shutdown();
}

#[test]
fn datagrams_dropped_for_their_source_port_are_counted() {
    let harness = Harness::new();
    let addr = harness.serve(|| App::<Recorder>::new(|_| Err(Refusal::Refuse)));
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let port = peer.local_addr().expect("a bound socket").port();
    set_src_port_blocklist::<Recorder>(&harness, Some(SrcPortBlocklist::new(0, [port])));
    for datagram in [forged_initial(), unknown_version(), short_header(0xee, 100)] {
        assert!(!answers(&harness, addr, &peer, &datagram), "{datagram:?}");
    }
    assert_eq!(harness.server_stats::<Recorder>().invalid_src_port, 3);
    harness.shutdown();
}

/// Gives the server driver for sessions of type `S` the source port blocklist `blocklist`.
fn set_src_port_blocklist<S: QuicSession>(harness: &Harness, blocklist: Option<SrcPortBlocklist>) {
    let (tx, rx) = mpsc::channel();
    harness
        .server
        .handle()
        .submit(move |_| {
            with_handle::<S, _>(|handle| handle.set_src_port_blocklist(blocklist.map(Arc::new)));
            let _ = tx.send(());
        })
        .expect("the server worker takes commands");
    rx.recv_timeout(WAIT).expect("the server worker answers");
}

/// Sends `datagram` to the `Recorder` server at `addr` from `peer`, and returns whether the server
/// answered it. Any answer has gone out once the server has answered a later probe from another
/// socket and ended that turn.
fn answers(harness: &Harness, addr: SocketAddr, peer: &UdpSocket, datagram: &[u8]) -> bool {
    peer.send_to(datagram, addr).expect("the datagram goes out");
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    probe.set_read_timeout(Some(WAIT)).expect("a read timeout");
    probe
        .send_to(&unknown_version(), addr)
        .expect("the probe goes out");
    probe
        .recv_from(&mut [0; 1500])
        .expect("the probe is answered");
    // A command runs between the driver's turns.
    let _ = harness.server_stats::<Recorder>();
    peer.set_nonblocking(true).expect("a nonblocking socket");
    let answered = peer.recv_from(&mut [0; 1500]).is_ok();
    peer.set_nonblocking(false).expect("a blocking socket");
    answered
}

#[test]
fn a_quiesced_server_refuses_newcomers_and_closes_the_rest_after_its_grace() {
    const GRACE: Duration = Duration::from_millis(500);
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let quiesced = server_reports.clone();
        let mut app = App::new(move |_| {
            Ok(Quiet {
                reports: server_reports.clone(),
            })
        });
        app.quiesced = Some(quiesced);
        app
    });
    for _ in 0..2 {
        let tx = tx.clone();
        harness.connect(addr, move || Recorder {
            name: "client",
            reports: tx,
        });
    }
    let connected = Report::Event("server", ConnEvent::Connected);
    await_reports(
        &rx,
        vec![connected, Report::Event("server", ConnEvent::Connected)],
    );

    let started = Instant::now();
    harness
        .server
        .handle()
        .submit(|_| with_handle::<Quiet, _>(|handle| handle.quiesce(GRACE)))
        .expect("the server worker takes commands");
    await_reports(
        &rx,
        vec![
            Report::AppQuiesced,
            Report::SessionQuiesced,
            Report::SessionQuiesced,
        ],
    );
    let late = tx.clone();
    harness.connect(addr, move || Recorder {
        name: "late",
        reports: late,
    });
    let transport_close = |code, frame_type, initiator| ConnEvent::Closed {
        reason: CloseReason::Transport {
            code,
            frame_type,
            reason: Bytes::new(),
        },
        initiator,
    };
    let no_error = mvfstr_proto::TransportErrorCode::NO_ERROR;
    let peer = Initiator::Peer;
    let zero = Some(mvfstr_proto::VarInt::ZERO);
    let closed = transport_close(no_error, zero, peer);
    await_reports(
        &rx,
        vec![
            Report::Event(
                "late",
                transport_close(
                    mvfstr_proto::TransportErrorCode::CONNECTION_REFUSED,
                    zero,
                    peer,
                ),
            ),
            Report::Event("client", closed.clone()),
            Report::Event("client", closed),
            Report::Event("server", ConnEvent::Drained),
            Report::Event("server", ConnEvent::Drained),
        ],
    );
    assert!(
        started.elapsed() >= GRACE,
        "the connections closed before the grace ended"
    );

    harness.await_server_finished::<Quiet>();
    harness.shutdown();
}

#[test]
fn a_session_reaches_its_connection_through_what_conn_lends() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(tx.clone()))));
    let _conn = harness.connect(addr, || Helpers {
        stream: None,
        polls: 0,
        ready: false,
    });
    let uni = StreamId::from_varint(mvfstr_proto::VarInt::from_u32(2));
    await_reports(&rx, vec![Report::Received(uni, 2)]);
    harness.shutdown();
}

/// Polls a connection gets per turn in the crowded tests, whose producers stay pending: each such
/// poll counts [`POLL_CHARGE`] against the connection's staging per turn.
const OWNER_POLLS: usize = 16;

/// Turns of polls a [`Crowded`] session's streams need beyond the last; more than the turns its own
/// wakes and its deadline's expiry bring by themselves.
const CROWDED_TURNS: usize = 4;

/// A place in the wire order whose streams share the staging budget equally, so many are
/// pull-ready at once.
const INCREMENTAL: SendOrder = SendOrder {
    incremental: true,
    ..ORDER
};

/// A client session that, 200 ms after it connects, when the connection has gone quiet, opens one
/// stream more than a connection may poll in [`CROWDED_TURNS`] turns at `order` and wakes them
/// all. The producers polled first stay pending, and the last one sends `hello` and the FIN.
/// Each poll reports its driver turn.
struct Crowded {
    reports: mpsc::Sender<Report>,
    order: SendOrder,
    at: Option<Instant>,
    polls: usize,
    pending: Vec<Waker>,
    sent: Option<StreamId>,
    received: Vec<u8>,
}

impl Crowded {
    fn new(order: SendOrder, reports: mpsc::Sender<Report>) -> Self {
        Self {
            reports,
            order,
            at: None,
            polls: 0,
            pending: Vec::new(),
            sent: None,
            received: Vec::new(),
        }
    }
}

impl QuicSession for Crowded {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            self.at = Some(conn.now() + Duration::from_millis(200));
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if Some(id) != self.sent || !matches!(ready, StreamReady::Readable | StreamReady::Finished)
        {
            return;
        }
        for segment in read_all(conn, id) {
            self.received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self
                .reports
                .send(Report::LastEchoed(self.received == b"hello"));
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::PolledInTurn(current_turn::<Crowded>()));
        self.polls += 1;
        if self.polls <= CROWDED_TURNS * OWNER_POLLS || self.sent.is_some() {
            self.pending.push(cx.waker().clone());
            return Poll::Pending;
        }
        sink.push(Bytes::from_static(b"hello"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        self.sent = Some(id);
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.at.is_some_and(|at| conn.now() >= at) {
            self.at = None;
            for _ in 0..=CROWDED_TURNS * OWNER_POLLS {
                let id = conn
                    .open_stream(Dir::Bi, self.order)
                    .expect("a stream opens");
                conn.stream_waker(id).wake();
            }
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.at
    }
}

/// A client session that reports its events and, once the test thread has set `token`, the
/// driver turn of each `poll_session`.
struct TurnWaking {
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
}

impl QuicSession for TurnWaking {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 1 {
            let _ = self
                .reports
                .send(Report::PolledInTurn(current_turn::<TurnWaking>()));
        }
        Poll::Pending
    }
}

/// A client session that opens `streams` incremental bidirectional streams once connected and
/// wakes them all. Each producer reports the driver turn it was polled in and sends `hello` and
/// the FIN; the session checks each echo.
struct Burst {
    streams: usize,
    reports: mpsc::Sender<Report>,
    received: HashMap<StreamId, Vec<u8>>,
}

impl QuicSession for Burst {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        for _ in 0..self.streams {
            let id = conn
                .open_stream(Dir::Bi, INCREMENTAL)
                .expect("a stream opens");
            conn.stream_waker(id).wake();
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let received = self.received.entry(id).or_default();
        for segment in read_all(conn, id) {
            received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self.reports.send(Report::Echoed(id, received == b"hello"));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::PolledInTurn(current_turn::<Burst>()));
        sink.push(Bytes::from_static(b"hello"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A server session that reports whether its first `poll_session`, which comes in the
/// application phase after its accept, reads a clock no earlier than the end of that accept.
struct Stamped {
    reports: mpsc::Sender<Report>,
    accepted_at: Instant,
    polled: bool,
}

impl QuicSession for Stamped {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if !self.polled {
            self.polled = true;
            let _ = self
                .reports
                .send(Report::FreshClock(conn.now() >= self.accepted_at));
        }
        Poll::Pending
    }
}

/// A client session that reports its events and closes its connection through `Conn` once the
/// handshake is confirmed.
struct Closer {
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Closer {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        let confirmed = event == ConnEvent::Confirmed;
        let _ = self.reports.send(Report::Event("client", event));
        if confirmed {
            let now = conn.now();
            conn.close(now, AppCode::from_u32(7), Bytes::from_static(b"bye"));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A server session that shuts its connection down through `Conn` once connected. It echoes the
/// client's first stream and, once that stream is reaped, sends `x` on the client's second.
struct Frozen {
    echo: Echo,
}

impl QuicSession for Frozen {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            let now = conn.now();
            conn.shutdown(now);
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if id == client_bidi(0) {
            self.echo.on_stream(conn, id, ready);
            if ready == StreamReady::Closed {
                let mut x = VecDeque::from([Bytes::from_static(b"x")]);
                push_all(conn, client_bidi(1), &mut x, false);
            }
        } else if ready == StreamReady::Readable {
            read_all(conn, id);
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session for [`Frozen`]: it sends `a` and the FIN on its first stream and `w` on its
/// second, and when `x` comes back on the second, reports whether it may open a third.
struct AfterFreeze {
    reports: mpsc::Sender<Report>,
}

impl QuicSession for AfterFreeze {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        for (data, fin) in [(b"a", true), (b"w", false)] {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([Bytes::from_static(data)]);
            assert!(
                push_all(conn, id, &mut queue, fin) || !fin,
                "the stream takes it"
            );
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let read = read_all(conn, id);
        if id == client_bidi(1) && !read.is_empty() {
            let opened = conn.open_stream(Dir::Bi, ORDER).is_ok();
            let _ = self.reports.send(Report::OpenedAfterShutdown(opened));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that produces a stream as a header part and a shared payload part through the
/// pull path, and checks the echo.
struct Parts {
    reports: mpsc::Sender<Report>,
    payload: Bytes,
    sent: bool,
    received: Vec<u8>,
}

impl QuicSession for Parts {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            conn.stream_waker(id).wake();
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        for segment in read_all(conn, id) {
            self.received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let expected = [&b"hd:"[..], &self.payload].concat();
            let _ = self
                .reports
                .send(Report::Echoed(id, self.received == expected));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        if self.sent {
            return Poll::Pending;
        }
        sink.push_parts(Bytes::from_static(b"hd:"), self.payload.clone())
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        self.sent = true;
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that opens a stream once connected and wakes its producer 200 ms later,
/// when the handshake's traffic is over. The producer's only poll sets the session's deadline
/// 50 ms on without staging bytes, so a transport operation does not follow to pick it up.
struct TimedPull {
    reports: mpsc::Sender<Report>,
    stream: Option<StreamId>,
    deadline: Option<Instant>,
    armed: bool,
}

impl TimedPull {
    fn new(reports: mpsc::Sender<Report>) -> Self {
        Self {
            reports,
            stream: None,
            deadline: None,
            armed: false,
        }
    }
}

impl QuicSession for TimedPull {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            self.stream = Some(conn.open_stream(Dir::Bi, ORDER).expect("a stream opens"));
            self.deadline = Some(conn.now() + Duration::from_millis(200));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        if !self.armed {
            self.armed = true;
            self.deadline = Some(Instant::now() + Duration::from_millis(50));
        }
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        let Some(at) = self.deadline.filter(|&at| conn.now() >= at) else {
            return Poll::Pending;
        };
        self.deadline = None;
        match self.stream.take() {
            Some(id) => conn.stream_waker(id).wake(),
            None => {
                let _ = self.reports.send(Report::DeadlineMet(Instant::now() >= at));
            }
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// Returns transport settings under which a connection takes DATAGRAM frames.
fn datagram_transport() -> Arc<TransportConfig> {
    TransportConfig::builder()
        .max_datagram_frame_size(65535)
        .build()
        .expect("a transport config")
}

/// A client session whose datagram producer pushes `left` datagrams of `len` bytes, as many as its
/// allowance takes on each poll up to `per_poll`; its first poll also pushes one whose expiry is
/// the driver's reading, and reports how the sink took it.
struct DatagramProducer {
    reports: mpsc::Sender<Report>,
    left: usize,
    len: usize,
    per_poll: usize,
    polled: bool,
}

impl DatagramProducer {
    fn new(reports: mpsc::Sender<Report>, left: usize, len: usize, per_poll: usize) -> Self {
        Self {
            reports,
            left,
            len,
            per_poll,
            polled: false,
        }
    }
}

impl QuicSession for DatagramProducer {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            conn.datagram_waker().wake();
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        if !mem::replace(&mut self.polled, true) {
            let stale = sink.push_parts(&[Bytes::from_static(b"stale")], ORDER, Some(sink.now()));
            let _ = self.reports.send(Report::DatagramPushed(stale));
        }
        let mut pushed = 0;
        while self.left > 0
            && pushed < self.per_poll
            && sink.allowance() >= datagram_frame_len(self.len)
        {
            sink.push_parts(&[payload(self.len)], ORDER, None)
                .expect("within the allowance");
            self.left -= 1;
            pushed += 1;
        }
        if self.left == 0 {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A server session that reads every datagram it receives and reports how many it has read, and
/// whether one of them was the stale datagram of [`DatagramProducer`].
struct DatagramReader {
    reports: mpsc::Sender<Report>,
    read: usize,
    stale: bool,
}

impl QuicSession for DatagramReader {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::DatagramsReadable {
            return;
        }
        while let Some(datagram) = conn.read_datagram() {
            self.read += 1;
            self.stale |= &datagram[..] == b"stale";
        }
        let _ = self
            .reports
            .send(Report::DatagramsRead(self.read, self.stale));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that wakes its datagram producer a while after the handshake. The producer's
/// first pull step pushes datagrams that expire before the connection's next transmit attempt;
/// a later pull step pushes `count` that do not expire.
struct ExpiringProducer {
    count: usize,
    deadline: Option<Instant>,
    /// The time of the first pull step.
    first: Option<Instant>,
}

impl QuicSession for ExpiringProducer {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            // Late enough that the handshake's last packets are out.
            self.deadline = Some(conn.now() + Duration::from_millis(100));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        let now = sink.now();
        match self.first {
            None => {
                self.first = Some(now);
                let expiry = now + Duration::from_millis(1);
                for _ in 0..4 {
                    sink.push_parts(&[Bytes::from_static(b"stale")], ORDER, Some(expiry))
                        .expect("a live datagram");
                }
                // A paced connection's attempt reads the clock after this, past the expiry.
                std::thread::sleep(Duration::from_millis(5));
                Poll::Ready(())
            }
            Some(first) if first == now => Poll::Ready(()),
            Some(_) => {
                for _ in 0..self.count {
                    sink.push_parts(&[Bytes::from_static(b"fresh")], ORDER, None)
                        .expect("within the allowance");
                }
                Poll::Pending
            }
        }
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.deadline.is_some_and(|at| conn.now() >= at) {
            self.deadline = None;
            conn.datagram_waker().wake();
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// A client session whose datagrams follow a stream at [`ORDER`]. A while after the handshake it
/// wakes its datagram producer. Until the stream's producer has sent `hello` and the FIN, a
/// datagram poll pushes nothing, the first waking the stream's producer. Later polls push `left`
/// datagrams of `len` bytes, as many as the allowance takes, and the first reports the allowance
/// it found.
struct DatagramsAfterStream {
    reports: mpsc::Sender<Report>,
    left: usize,
    len: usize,
    deadline: Option<Instant>,
    /// The stream's waker, until the first datagram poll wakes it.
    stream: Option<Waker>,
    sent: bool,
    reported: bool,
}

impl DatagramsAfterStream {
    fn new(reports: mpsc::Sender<Report>, left: usize, len: usize) -> Self {
        Self {
            reports,
            left,
            len,
            deadline: None,
            stream: None,
            sent: false,
            reported: false,
        }
    }
}

impl QuicSession for DatagramsAfterStream {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            self.stream = Some(conn.stream_waker(id));
            // Late enough that the handshake's last packets are out.
            self.deadline = Some(conn.now() + Duration::from_millis(100));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        if !mem::replace(&mut self.sent, true) {
            sink.push(Bytes::from_static(b"hello"))
                .expect("within the allowance");
            sink.finish().expect("the stream is open");
        }
        Poll::Pending
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        if !self.sent {
            if let Some(stream) = self.stream.take() {
                stream.wake();
            }
            return Poll::Ready(());
        }
        if !mem::replace(&mut self.reported, true) {
            let _ = self
                .reports
                .send(Report::DatagramAllowance(sink.allowance()));
        }
        while self.left > 0 && sink.allowance() >= datagram_frame_len(self.len) {
            sink.push_parts(&[payload(self.len)], ORDER, None)
                .expect("within the allowance");
            self.left -= 1;
        }
        if self.left == 0 {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.deadline.is_some_and(|at| conn.now() >= at) {
            self.deadline = None;
            conn.datagram_waker().wake();
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// A client session whose datagram producer, woken a while after the handshake, returns `Ready`
/// on every poll. With `keep` set, its first poll pushes datagrams until about `keep` bytes of the
/// allowance are left; otherwise, and on later polls, it pushes nothing. A further while after
/// the wake, the session reports the allowance of each poll.
struct StalledProducer {
    reports: mpsc::Sender<Report>,
    keep: Option<usize>,
    deadline: Option<Instant>,
    woken: bool,
    allowances: Vec<usize>,
}

impl StalledProducer {
    fn new(reports: mpsc::Sender<Report>, keep: Option<usize>) -> Self {
        Self {
            reports,
            keep,
            deadline: None,
            woken: false,
            allowances: Vec::new(),
        }
    }
}

impl QuicSession for StalledProducer {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            // Late enough that the handshake's last packets are out.
            self.deadline = Some(conn.now() + Duration::from_millis(100));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        self.allowances.push(sink.allowance());
        if let Some(keep) = self.keep.take() {
            const LEN: usize = 1000;
            let mut fill = sink.allowance().saturating_sub(keep);
            while fill >= datagram_frame_len(LEN) {
                sink.push_parts(&[payload(LEN)], ORDER, None)
                    .expect("within the allowance");
                fill -= datagram_frame_len(LEN);
            }
            if let Some(len) = (0..fill)
                .rev()
                .take(3)
                .find(|&len| datagram_frame_len(len) == fill)
            {
                sink.push_parts(&[payload(len)], ORDER, None)
                    .expect("within the allowance");
            }
        }
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if !self.deadline.is_some_and(|at| conn.now() >= at) {
            return Poll::Pending;
        }
        if mem::replace(&mut self.woken, true) {
            self.deadline = None;
            let _ = self
                .reports
                .send(Report::DatagramPolls(mem::take(&mut self.allowances)));
        } else {
            self.deadline = Some(conn.now() + Duration::from_millis(200));
            conn.datagram_waker().wake();
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// A place in the wire order ahead of [`ORDER`].
const URGENT: SendOrder = SendOrder {
    urgency: 0,
    ..ORDER
};

/// A client session whose datagram producer pushes `left` datagrams of `len` bytes at [`ORDER`], as
/// many as its allowance takes on each poll up to `per_poll`. Its first poll pushes nothing and
/// wakes the producer of a stream opened at [`URGENT`]. When first polled, that producer reports
/// how many datagrams are left and how many turns have passed since the first was pushed, and
/// sends `hello` and the FIN; the session checks the echo.
struct DatagramsAndStream {
    reports: mpsc::Sender<Report>,
    left: usize,
    len: usize,
    per_poll: usize,
    /// The stream's waker, until the first datagram poll wakes it.
    stream: Option<Waker>,
    /// The turn in which the first datagram was pushed.
    first_push: Option<u64>,
    sent: bool,
    received: Vec<u8>,
}

impl DatagramsAndStream {
    fn new(reports: mpsc::Sender<Report>, left: usize, len: usize, per_poll: usize) -> Self {
        Self {
            reports,
            left,
            len,
            per_poll,
            stream: None,
            first_push: None,
            sent: false,
            received: Vec::new(),
        }
    }
}

impl QuicSession for DatagramsAndStream {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            let id = conn.open_stream(Dir::Bi, URGENT).expect("a stream opens");
            self.stream = Some(conn.stream_waker(id));
            conn.datagram_waker().wake();
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        for segment in read_all(conn, id) {
            self.received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self
                .reports
                .send(Report::LastEchoed(self.received == b"hello"));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        if mem::replace(&mut self.sent, true) {
            return Poll::Pending;
        }
        let turn = current_turn::<Self>();
        let since = self.first_push.map(|first| turn - first);
        let _ = self
            .reports
            .send(Report::StreamFirstPolled(self.left, since));
        sink.push(Bytes::from_static(b"hello"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        if let Some(stream) = self.stream.take() {
            stream.wake();
            return Poll::Ready(());
        }
        let mut pushed = 0;
        while self.left > 0
            && pushed < self.per_poll
            && sink.allowance() >= datagram_frame_len(self.len)
        {
            sink.push_parts(&[payload(self.len)], ORDER, None)
                .expect("within the allowance");
            self.left -= 1;
            pushed += 1;
        }
        if pushed > 0 && self.first_push.is_none() {
            self.first_push = Some(current_turn::<Self>());
        }
        if self.left == 0 {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A server session that reports its events and, when `panics` is set, panics when dropped.
struct Fragile {
    recorder: Recorder,
    panics: bool,
}

impl Drop for Fragile {
    fn drop(&mut self) {
        if self.panics {
            panic!("a session bug in drop");
        }
    }
}

impl QuicSession for Fragile {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        self.recorder.on_event(conn, event);
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A certificate resolver that panics for the server name `doomed` and otherwise defers to `0`.
#[derive(Debug)]
struct DoomedResolver(Arc<dyn ResolvesServerCert>);

impl ResolvesServerCert for DoomedResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name() == Some("doomed") {
            panic!("an application bug in a certificate resolver");
        }
        self.0.resolve(hello)
    }
}

/// A certificate resolver that reads the counters of the driver for `Recorder` sessions on its
/// worker, as an application's resolver may, and then defers to the resolver it wraps.
#[derive(Debug)]
struct CountingResolver(Arc<dyn ResolvesServerCert>);

impl ResolvesServerCert for CountingResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        with_handle::<Recorder, _>(|handle| handle.stats());
        self.0.resolve(hello)
    }
}

/// A client session store that panics when a new connection reads from it.
#[derive(Debug)]
struct DoomedStore;

impl ClientSessionStore for DoomedStore {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        panic!("an application bug in a session store");
    }

    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        panic!("an application bug in a session store");
    }

    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, _: ServerName<'static>, _: Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        panic!("an application bug in a session store");
    }
}

/// A client session whose producer, once the test thread has set `token` and woken it, pushes
/// 2,000 bytes, two datagrams, per poll on a new stream, reporting the driver turn of each poll,
/// and finishes the stream on poll `polls`. The stream stays pull-ready until then.
struct Hog {
    name: &'static str,
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
    polls: usize,
    opened: bool,
}

impl QuicSession for Hog {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::Produced(self.name, current_turn::<Hog>()));
        sink.push(payload(2_000)).expect("within the allowance");
        self.polls -= 1;
        if self.polls == 0 {
            sink.finish().expect("the stream is open");
        }
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 1 && !self.opened {
            self.opened = true;
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            conn.stream_waker(id).wake();
        }
        Poll::Pending
    }
}

/// A client session that reports its events and, once the test thread has set `token` and woken
/// it, sends `ping` and the FIN on a new stream through the push path, reporting the driver turn
/// it did so in.
struct Pinger {
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
    sent: bool,
}

impl QuicSession for Pinger {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 1 && !self.sent {
            self.sent = true;
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut ping = VecDeque::from([Bytes::from_static(b"ping")]);
            assert!(push_all(conn, id, &mut ping, true), "the stream takes it");
            let _ = self
                .reports
                .send(Report::PolledInTurn(current_turn::<Pinger>()));
        }
        Poll::Pending
    }
}

/// A server session that reports the driver turn in which it first reads its peer's stream.
struct Heard {
    reports: mpsc::Sender<Report>,
    heard: bool,
}

impl QuicSession for Heard {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        read_all(conn, id);
        if !self.heard {
            self.heard = true;
            let _ = self.reports.send(Report::Heard(current_turn::<Heard>()));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that reports its events and, once the test thread has set `token` and woken
/// it, either keeps a session deadline due in every turn of its driver until `stop` is set
/// (`spin`), or reports the turn of that `poll_session`.
struct Contender {
    reports: mpsc::Sender<Report>,
    spin: bool,
    token: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    at: Option<Instant>,
}

impl QuicSession for Contender {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 0 {
            return Poll::Pending;
        }
        if !self.spin {
            let _ = self
                .reports
                .send(Report::PolledInTurn(current_turn::<Contender>()));
        } else if self.stop.load(Ordering::SeqCst) {
            self.at = None;
        } else {
            if self.at.is_none() {
                let _ = self.reports.send(Report::Spinning);
            }
            // The phase's clock: due in the next turn, and later than any earlier wake.
            self.at = Some(conn.now());
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.at
    }
}

/// Returns a version 1 Initial of 1,200 bytes for an unknown connection ID, with a payload that
/// is not encrypted: it routes as a new connection attempt, and its packet fails to open.
fn forged_initial() -> Vec<u8> {
    let mut out = vec![0xc0, 0, 0, 0, 1, 8];
    out.extend_from_slice(&[1; 8]);
    out.extend_from_slice(&[8, 2, 2, 2, 2, 2, 2, 2, 2, 0]);
    let rest = u16::try_from(1200 - out.len() - 2).expect("the length fits two bytes");
    out.extend_from_slice(&(0x4000 | rest).to_be_bytes());
    out.resize(1200, 0);
    out
}

/// Sends `count` forged Initials to `addr` from a new socket.
fn send_forged(addr: SocketAddr, count: usize) {
    let forger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    for _ in 0..count {
        forger
            .send_to(&forged_initial(), addr)
            .expect("the forged Initial goes out");
    }
}

/// Returns a long header of version 0x1a2a3a4a with connection IDs of eight 1s and eight 2s, as
/// long as an Initial must be: a server answers it with Version Negotiation.
fn unknown_version() -> Vec<u8> {
    let mut datagram = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    datagram.extend_from_slice(&[1; 8]);
    datagram.push(8);
    datagram.extend_from_slice(&[2; 8]);
    datagram.resize(1200, 0);
    datagram
}

/// Returns a short header of `len` bytes for an eight-byte connection ID that was never issued,
/// whose first byte, the one that names a worker, is `first`.
fn short_header(first: u8, len: usize) -> Vec<u8> {
    let mut datagram = vec![0x40, first];
    datagram.resize(len, 0xee);
    datagram
}

/// Returns a short header for a connection ID that was never issued, too short for a stateless
/// reset to answer: RFC 9000 requires a reset to be at least 21 bytes and shorter than the packet
/// it answers, so a server drops it silently.
fn too_small_for_a_reset() -> Vec<u8> {
    short_header(0xee, 21)
}

/// Returns an application close with `code` and an empty reason, as the receiving side gets it.
fn closed_by_peer(code: u32) -> ConnEvent {
    ConnEvent::Closed {
        reason: CloseReason::Application {
            code: AppCode::from_u32(code),
            reason: Bytes::new(),
        },
        initiator: Initiator::Peer,
    }
}

/// Returns a server application whose sessions report their events as `server`.
fn recording_server(reports: mpsc::Sender<Report>) -> App<Recorder> {
    App::new(move |_| {
        Ok(Recorder {
            name: "server",
            reports: reports.clone(),
        })
    })
}

/// Returns the most entries of `turns` that share one turn.
fn most_per_turn(turns: &[u64]) -> usize {
    let mut counts = HashMap::new();
    for &turn in turns {
        *counts.entry(turn).or_insert(0) += 1;
    }
    counts.into_values().max().unwrap_or(0)
}

/// Returns the turns of the `PolledInTurn` reports in `reports`.
fn polled_turns(reports: &[Report]) -> Vec<u64> {
    reports
        .iter()
        .filter_map(|report| match report {
            Report::PolledInTurn(turn) => Some(*turn),
            _ => None,
        })
        .collect()
}

/// Returns `count` reports of `report`.
fn times(count: usize, report: impl Fn() -> Report) -> Vec<Report> {
    (0..count).map(|_| report()).collect()
}

#[test]
fn a_connection_with_more_pull_ready_streams_than_its_polls_per_turn_gets_another_turn() {
    let mut harness = Harness::new();
    // Low enough that a connection may open a few turns' worth of streams under its stream limit.
    harness.limits.turn_staging = OWNER_POLLS as u64 * POLL_CHARGE;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Crowded::new(INCREMENTAL, tx));
    let polls = await_reports(&rx, vec![Report::LastEchoed(true)]);
    let turns = polled_turns(&polls);
    assert!(
        most_per_turn(&turns) <= OWNER_POLLS,
        "a turn polled the connection more than its cap: {turns:?}"
    );
    harness.shutdown();
}

#[test]
fn streams_later_in_wire_order_are_polled_once_earlier_producers_park() {
    // In a sequential bucket each woken stream reserves its whole room of the staging budget, so
    // only the first few are pull-ready until their producers are parked.
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Crowded::new(ORDER, tx));
    await_reports(&rx, vec![Report::LastEchoed(true)]);
    harness.shutdown();
}

#[test]
fn the_intake_takes_at_most_its_cap_of_connections_per_turn() {
    const CONNECTIONS: usize = 5;
    let mut harness = Harness::new();
    harness.limits.intake = 2;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let conns: Vec<ConnHandle> = (0..CONNECTIONS)
        .map(|_| {
            let (reports, token) = (tx.clone(), Arc::clone(&token));
            harness.connect(addr, move || TurnWaking { reports, token })
        })
        .collect();
    await_reports(
        &rx,
        times(CONNECTIONS, || {
            Report::Event("client", ConnEvent::Connected)
        }),
    );

    token.store(1, Ordering::SeqCst);
    // Every wake lands on the ready queue before the client's next turn.
    let blocked = Harness::block(&harness.client);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    drop(blocked);
    let mut turns = Vec::new();
    while turns.len() < CONNECTIONS {
        let report = rx.recv_timeout(WAIT).expect("every session is polled");
        turns.extend(polled_turns(&[report]));
    }
    assert!(
        most_per_turn(&turns) <= 2,
        "a turn took more connections than its cap: {turns:?}"
    );
    harness.shutdown();
}

#[test]
fn a_turn_makes_at_most_its_cap_of_poll_send_calls() {
    const STREAMS: u32 = 6;
    let mut harness = Harness::new();
    harness.limits.polls = 4;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Burst {
        streams: STREAMS as usize,
        reports: tx,
        received: HashMap::new(),
    });
    let others = await_reports(
        &rx,
        (0..STREAMS)
            .map(|n| Report::Echoed(client_bidi(n), true))
            .collect(),
    );
    let turns = polled_turns(&others);
    assert_eq!(turns.len(), STREAMS as usize, "{others:?}");
    assert!(
        most_per_turn(&turns) <= 4,
        "a turn polled more producers than its cap: {turns:?}"
    );
    harness.shutdown();
}

#[test]
fn a_turn_takes_at_most_its_cap_of_connection_attempts() {
    const CONNECTIONS: usize = 5;
    let mut harness = Harness::new();
    harness.limits.handshakes = 2;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            let _ = server_reports.send(Report::Accepted(current_turn::<Recorder>()));
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let blocked = Harness::block(&harness.server);
    let client_reports = tx.clone();
    let (_conns, turn) = harness.connect_all(addr, CONNECTIONS, move || Recorder {
        name: "client",
        reports: client_reports.clone(),
    });
    // Once the client has run a turn, every Initial waits on the server's socket.
    harness.await_client_turn::<Recorder>(turn + 1);
    drop(blocked);
    let others = await_reports(
        &rx,
        times(CONNECTIONS, || {
            Report::Event("client", ConnEvent::Connected)
        }),
    );
    let turns: Vec<u64> = others
        .iter()
        .filter_map(|report| match report {
            Report::Accepted(turn) => Some(*turn),
            _ => None,
        })
        .collect();
    assert_eq!(turns.len(), CONNECTIONS, "{others:?}");
    assert!(
        most_per_turn(&turns) <= 2,
        "a turn accepted more connections than its cap: {turns:?}"
    );
    harness.shutdown();
}

#[test]
fn sessions_see_a_clock_read_for_their_phase() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Stamped {
                reports: tx.clone(),
                accepted_at: Instant::now(),
                polled: false,
            })
        })
    });
    let (client_tx, _client_rx) = mpsc::channel();
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_tx,
    });
    await_reports(&rx, vec![Report::FreshClock(true)]);
    harness.shutdown();
}

#[test]
fn a_quiescing_driver_opens_no_new_connections() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let client_reports = tx.clone();
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);

    let (refused_tx, refused_rx) = mpsc::channel();
    let config = harness.client_config.clone();
    harness
        .client
        .handle()
        .submit(move |_| {
            let late = with_handle::<Recorder, _>(|handle| {
                handle.quiesce(Duration::from_millis(100));
                handle.connect(
                    addr,
                    ServerName::try_from("localhost").expect("a DNS name"),
                    config,
                    ConnOptions::default(),
                    Recorder {
                        name: "late",
                        reports: tx,
                    },
                )
            });
            let refused = matches!(
                late,
                Err(DriverConnectError::Io(ref error)) if error.kind() == io::ErrorKind::NotConnected
            );
            let _ = refused_tx.send(refused);
        })
        .expect("the client worker takes commands");
    assert!(
        refused_rx.recv_timeout(WAIT).expect("the client answers"),
        "a quiescing driver opened a connection"
    );
    harness.shutdown();
}

#[test]
fn a_quiesce_aborts_what_its_close_left_open_at_the_forced_deadline() {
    const GRACE: Duration = Duration::from_millis(200);
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Quiet {
                reports: server_reports.clone(),
            })
        })
    });
    // The longest ACK delay the client may advertise stretches the server's closing period to
    // about 49 s, so only the forced deadline frees the server's connection in time.
    let transport = TransportConfig::builder()
        .ack_policy(AckPolicy {
            max_ack_delay: Duration::from_millis((1 << 14) - 1),
            ..AckPolicy::default()
        })
        .build()
        .expect("a transport config");
    let client_reports = tx.clone();
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || Recorder {
            name: "client",
            reports: client_reports,
        },
    );
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);

    let started = Instant::now();
    harness
        .server
        .handle()
        .submit(|_| with_handle::<Quiet, _>(|handle| handle.quiesce(GRACE)))
        .expect("the server worker takes commands");
    let no_error = |frame_type, initiator| ConnEvent::Closed {
        reason: CloseReason::Transport {
            code: mvfstr_proto::TransportErrorCode::NO_ERROR,
            frame_type,
            reason: Bytes::new(),
        },
        initiator,
    };
    await_reports(
        &rx,
        vec![
            Report::Event("server", no_error(None, Initiator::Local)),
            Report::Event(
                "client",
                no_error(Some(mvfstr_proto::VarInt::ZERO), Initiator::Peer),
            ),
            Report::Event("server", ConnEvent::Drained),
        ],
    );
    assert!(
        started.elapsed() >= GRACE + Duration::from_secs(1),
        "the server's connection was freed before the forced deadline"
    );
    harness.await_server_finished::<Quiet>();
    harness.shutdown();
}

#[test]
fn a_panic_outside_every_connection_ends_the_driver_and_spares_the_worker() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    harness
        .server
        .handle()
        .submit(|_| with_handle::<Recorder, _>(|handle| handle.fail_next_turn()))
        .expect("the server worker takes commands");
    harness.await_server_finished::<Recorder>();
    let stats = harness.server.handle().poll_stats();
    assert_eq!(stats.contained_driver_panics, 1);
    assert_eq!(stats.contained_connection_panics, 0);
    harness.shutdown();
}

#[test]
fn a_panic_in_accept_drops_only_that_attempt() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut attempts = 0;
        App::new(move |_| {
            attempts += 1;
            if attempts == 1 {
                let _ = server_reports.send(Report::Panicking);
                panic!("an application bug in accept");
            }
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    // The client's next Initial, sent when its first goes unanswered, is accepted.
    await_reports(
        &rx,
        vec![
            Report::Panicking,
            Report::Event("client", ConnEvent::Connected),
        ],
    );
    let stats = harness.server.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1);
    assert_eq!(stats.contained_driver_panics, 0);
    harness.shutdown();
}

#[test]
fn a_panic_in_the_applications_quiesce_does_not_stop_the_quiesce() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(Quiet {
                reports: server_reports.clone(),
            })
        });
        app.quiesce_panics = true;
        app
    });
    let client_reports = tx.clone();
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    harness
        .server
        .handle()
        .submit(|_| with_handle::<Quiet, _>(|handle| handle.quiesce(Duration::from_millis(100))))
        .expect("the server worker takes commands");
    await_reports(
        &rx,
        vec![
            Report::SessionQuiesced,
            Report::Event("server", ConnEvent::Drained),
        ],
    );
    harness.await_server_finished::<Quiet>();
    let stats = harness.server.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1);
    assert_eq!(stats.contained_driver_panics, 0);
    harness.shutdown();
}

#[test]
fn a_panic_in_a_sessions_drop_is_contained() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut accepted = 0;
        App::new(move |_| {
            accepted += 1;
            Ok(Fragile {
                recorder: Recorder {
                    name: "server",
                    reports: server_reports.clone(),
                },
                panics: accepted == 1,
            })
        })
    });
    let first_reports = tx.clone();
    let first = harness.connect(addr, move || Recorder {
        name: "first",
        reports: first_reports,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    first
        .close(AppCode::from_u32(1), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Drained)]);
    let _second = harness.connect(addr, move || Recorder {
        name: "second",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("second", ConnEvent::Connected)]);
    let stats = harness.server.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1);
    assert_eq!(stats.contained_driver_panics, 0);
    assert_eq!(harness.server_stats::<Fragile>().contained_panics, 1);
    harness.shutdown();
}

#[test]
fn a_session_closes_its_connection_through_conn() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let _conn = harness.connect(addr, move || Closer { reports: tx });
    let closed = |initiator| ConnEvent::Closed {
        reason: CloseReason::Application {
            code: AppCode::from_u32(7),
            reason: Bytes::from_static(b"bye"),
        },
        initiator,
    };
    await_reports(
        &rx,
        vec![
            Report::Event("client", closed(Initiator::Local)),
            Report::Event("server", closed(Initiator::Peer)),
            Report::Event("client", ConnEvent::Drained),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_session_shuts_its_connection_down_through_conn() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let transport = TransportConfig::builder()
        .max_streams_bidi(2)
        .build()
        .expect("a transport config");
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(Frozen {
                echo: Echo::new(server_reports.clone()),
            })
        });
        app.transport = Some(transport);
        app
    });
    let _conn = harness.connect(addr, move || AfterFreeze { reports: tx });
    // Without the shutdown, reaping the first stream would have raised the client's limit to
    // three streams in the packet that carries `x`.
    await_reports(&rx, vec![Report::OpenedAfterShutdown(false)]);
    harness.shutdown();
}

#[test]
fn a_producer_stages_a_header_and_a_shared_payload_as_two_parts() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Parts {
        reports: tx,
        payload: payload(10_000),
        sent: false,
        received: Vec::new(),
    });
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    harness.shutdown();
}

#[test]
fn a_deadline_a_producer_sets_runs_poll_session() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || TimedPull::new(tx));
    await_reports(&rx, vec![Report::DeadlineMet(true)]);
    harness.shutdown();
}

#[test]
fn a_datagram_producer_is_pulled_as_the_window_opens_and_its_expired_datagram_is_refused() {
    // Thirty 1,000-byte datagrams take more than the initial congestion window of 12,000 bytes,
    // so the producer is pulled again as acknowledgments open it.
    const COUNT: usize = 30;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(DatagramReader {
                reports: server_reports.clone(),
                read: 0,
                stale: false,
            })
        });
        app.transport = Some(datagram_transport());
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(datagram_transport()),
        },
        move || DatagramProducer::new(tx, COUNT, 1000, usize::MAX),
    );
    let others = await_reports(
        &rx,
        vec![
            Report::DatagramPushed(Err(DatagramError::Expired)),
            Report::DatagramsRead(COUNT, false),
        ],
    );
    assert!(
        others
            .iter()
            .all(|report| matches!(report, Report::DatagramsRead(read, false) if *read < COUNT)),
        "{others:?}"
    );
    harness.shutdown();
}

#[test]
fn a_datagram_producer_cut_short_by_the_turns_work_is_polled_again_in_the_next_turn() {
    // Each poll pushes one datagram and uses up the connection's work for the turn. The peers
    // acknowledge nothing within the test, so only the driver's own requeue polls it again.
    const COUNT: usize = 8;
    let mut harness = Harness::new();
    harness.limits.turn_staging = POLL_CHARGE;
    let transport = TransportConfig::builder()
        .ack_policy(sluggish().ack_policy())
        .max_datagram_frame_size(65535)
        .build()
        .expect("a transport config");
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let server_transport = transport.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(DatagramReader {
                reports: server_reports.clone(),
                read: 0,
                stale: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || DatagramProducer::new(tx, COUNT, 10, 1),
    );
    await_reports_within(&rx, vec![Report::DatagramsRead(COUNT, false)], STALL);
    harness.shutdown();
}

#[test]
fn a_datagram_producer_whose_datagrams_expire_unsent_is_polled_again_without_input() {
    // The peers acknowledge nothing within the test, so the attempt that drops the expired
    // datagrams, sending nothing, is all that can get the producer polled again.
    const COUNT: usize = 4;
    let harness = Harness::new();
    let transport = |pacing| {
        TransportConfig::builder()
            .ack_policy(sluggish().ack_policy())
            .max_datagram_frame_size(65535)
            .pacing(pacing)
            .build()
            .expect("a transport config")
    };
    let (tx, rx) = mpsc::channel();
    let server_transport = transport(false);
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(DatagramReader {
                reports: tx.clone(),
                read: 0,
                stale: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport(true)),
        },
        move || ExpiringProducer {
            count: COUNT,
            deadline: None,
            first: None,
        },
    );
    await_reports_within(&rx, vec![Report::DatagramsRead(COUNT, false)], STALL);
    harness.shutdown();
}

/// Runs a [`StalledProducer`] client that keeps `keep` with `harness`'s limits against a server
/// that takes datagrams, with peers that acknowledge nothing within the test, and returns the
/// allowance of each of the producer's polls.
fn polls_of_a_stalled_producer(harness: Harness, keep: Option<usize>) -> Vec<usize> {
    let transport = TransportConfig::builder()
        .ack_policy(sluggish().ack_policy())
        .max_datagram_frame_size(65535)
        .build()
        .expect("a transport config");
    let (tx, rx) = mpsc::channel();
    // The server's reports go nowhere.
    let (server_reports, _) = mpsc::channel();
    let server_transport = transport.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(DatagramReader {
                reports: server_reports.clone(),
                read: 0,
                stale: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || StalledProducer::new(tx, keep),
    );
    let report = rx.recv_timeout(WAIT).expect("the producer's watch ends");
    harness.shutdown();
    let Report::DatagramPolls(allowances) = report else {
        panic!("unexpected {report:?}");
    };
    allowances
}

#[test]
fn a_datagram_producer_that_pushes_nothing_with_room_for_any_datagram_is_not_polled_every_turn() {
    // The turn's work is less than the window, so it cuts the sink, but leaves room for the
    // longest datagram.
    let mut harness = Harness::new();
    harness.limits.turn_staging = 4000;
    let allowances = polls_of_a_stalled_producer(harness, None);
    assert!(
        allowances == [4000],
        "polled {} times; first allowances {:?}",
        allowances.len(),
        &allowances[..allowances.len().min(10)]
    );
}

#[test]
fn a_datagram_producer_the_window_leaves_less_than_a_frame_is_not_polled_every_turn() {
    // The first poll fills the window but for 900 bytes, less than the longest datagram's frame,
    // and the packets that carry its datagrams take a little more of it.
    let allowances = polls_of_a_stalled_producer(Harness::new(), Some(900));
    assert!(
        allowances.len() < 10,
        "polled {} times; first allowances {:?}",
        allowances.len(),
        &allowances[..allowances.len().min(10)]
    );
    assert!(
        allowances
            .last()
            .is_some_and(|&last| last > 0 && last < 900),
        "{allowances:?}"
    );
}

#[test]
fn a_datagram_producer_the_turns_work_leaves_less_than_a_frame_is_polled_again_in_the_next_turn() {
    // The producer's poll that pushes nothing and the stream's poll after it each count the least
    // a poll counts, so in the application phase after the stream's packet is sent the turn's work
    // leaves the producer `SHORT` bytes, less than the frame of its next datagram. The peers
    // acknowledge nothing within the test, so only the driver's own requeue polls it again.
    const COUNT: usize = 4;
    const LEN: usize = 1000;
    const SHORT: usize = 500;
    let mut harness = Harness::new();
    harness.limits.turn_staging = 2 * POLL_CHARGE + SHORT as u64;
    let transport = TransportConfig::builder()
        .ack_policy(sluggish().ack_policy())
        .max_datagram_frame_size(65535)
        .build()
        .expect("a transport config");
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let server_transport = transport.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(DatagramReader {
                reports: server_reports.clone(),
                read: 0,
                stale: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || DatagramsAfterStream::new(tx, COUNT, LEN),
    );
    assert!(SHORT < datagram_frame_len(LEN));
    await_reports_within(
        &rx,
        vec![
            Report::DatagramAllowance(SHORT),
            Report::DatagramsRead(COUNT, false),
        ],
        STALL,
    );
    harness.shutdown();
}

/// Runs a [`DatagramsAndStream`] client with `transport` against an echo server that takes
/// datagrams, and returns what its stream's producer reported when first polled.
fn first_poll_beside_datagrams(
    harness: Harness,
    transport: Arc<TransportConfig>,
    session: impl FnOnce(mpsc::Sender<Report>) -> DatagramsAndStream + Send + 'static,
) -> (usize, Option<u64>) {
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| Ok(Echo::new(server_reports.clone())));
        app.transport = Some(datagram_transport());
        app
    });
    let _conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || session(tx),
    );
    let reports = await_reports(&rx, vec![Report::LastEchoed(true)]);
    harness.shutdown();
    reports
        .iter()
        .find_map(|report| match report {
            Report::StreamFirstPolled(left, since) => Some((*left, *since)),
            _ => None,
        })
        .expect("the stream's producer was polled")
}

#[test]
fn a_stream_woken_beside_a_datagram_producer_pushing_one_per_poll_is_polled_in_the_same_turn() {
    // Each poll pushes one datagram and counts the least a poll counts, and the producer has four
    // turns' worth of polls to push. The initial window takes them all, so only the turn's work
    // limits how often the producer is polled.
    const COUNT: usize = 4 * (TURN_STAGING / POLL_CHARGE) as usize;
    let (left, since) = first_poll_beside_datagrams(Harness::new(), datagram_transport(), |tx| {
        DatagramsAndStream::new(tx, COUNT, 10, 1)
    });
    assert!(
        left > 0 && since == Some(0),
        "the stream was first polled {since:?} turns after the first datagram, with {left} of \
         {COUNT} left"
    );
}

#[test]
fn a_stream_woken_beside_a_datagram_producer_pushing_in_bulk_is_polled_in_the_same_turn() {
    // Each poll pushes as many datagrams as the allowance takes, and one poll could push the
    // initial window of 32 datagrams, more than the turn's work of two polls' least counts.
    const COUNT: usize = 200;
    let mut harness = Harness::new();
    harness.limits.turn_staging = 2 * POLL_CHARGE;
    let transport = TransportConfig::builder()
        .max_datagram_frame_size(65535)
        .initial_window(32)
        .build()
        .expect("a transport config");
    let (left, since) = first_poll_beside_datagrams(harness, transport, |tx| {
        DatagramsAndStream::new(tx, COUNT, 1000, usize::MAX)
    });
    assert!(
        left > 0 && since == Some(0),
        "the stream was first polled {since:?} turns after the first datagram, with {left} of \
         {COUNT} left"
    );
}

#[test]
fn a_session_left_by_an_initial_that_does_not_open_panics_in_drop_alone() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let forger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let forged = forger.local_addr().expect("a bound socket");
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut attempts = 0;
        App::new(move |info| {
            attempts += 1;
            let _ = server_reports.send(Report::Attempt(attempts));
            Ok(Fragile {
                recorder: Recorder {
                    name: "server",
                    reports: server_reports.clone(),
                },
                panics: info.remote == forged,
            })
        })
    });
    let client_reports = tx.clone();
    let healthy = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(
        &rx,
        vec![
            Report::Attempt(1),
            Report::Event("server", ConnEvent::Connected),
        ],
    );

    forger
        .send_to(&forged_initial(), addr)
        .expect("the forged Initial goes out");
    await_reports(&rx, vec![Report::Attempt(2)]);
    // A command runs between the driver's polls, so the attempt is over once it answers.
    let contained = harness.server_stats::<Fragile>().contained_panics;
    let stats = harness.server.handle().poll_stats();
    assert_eq!(
        stats.contained_driver_panics, 0,
        "the failed attempt's session ended the driver when dropped"
    );
    assert_eq!(stats.contained_connection_panics, 1);
    assert_eq!(contained, 1);

    healthy
        .close(AppCode::from_u32(3), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", closed_by_peer(3))]);
    harness.shutdown();
}

#[test]
fn a_panic_while_an_initial_creates_its_connection_ends_only_that_attempt() {
    let mut harness = Harness::new();
    let mut tls = rustls::ServerConfig::clone(
        harness
            .server_config
            .tls()
            .rustls()
            .expect("a rustls server"),
    );
    tls.cert_resolver = Arc::new(DoomedResolver(Arc::clone(&tls.cert_resolver)));
    harness.server_config = ServerConfig::builder(Arc::new(tls))
        .build()
        .expect("a server config");
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut attempts = 0;
        App::new(move |_| {
            attempts += 1;
            let _ = server_reports.send(Report::Attempt(attempts));
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let client_reports = tx.clone();
    let healthy = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(
        &rx,
        vec![
            Report::Attempt(1),
            Report::Event("server", ConnEvent::Connected),
        ],
    );

    // The server's new connection reads the ClientHello, and calls the resolver, as it is created.
    let (endpoint, config) = (harness.endpoint.clone(), harness.client_config.clone());
    let (limits, options) = (harness.limits, harness.options.clone());
    let doomed_reports = tx.clone();
    harness
        .client
        .handle()
        .submit(move |worker| {
            ensure_client::<Recorder, MmsgBackend>(worker, endpoint, options, limits);
            with_handle::<Recorder, _>(|handle| {
                handle.connect(
                    addr,
                    ServerName::try_from("doomed").expect("a DNS name"),
                    config,
                    ConnOptions::default(),
                    Recorder {
                        name: "doomed",
                        reports: doomed_reports,
                    },
                )
            })
            .expect("the connection starts");
        })
        .expect("the client worker takes commands");
    await_reports(&rx, vec![Report::Attempt(2)]);
    let contained = harness.server_stats::<Recorder>().contained_panics;
    let stats = harness.server.handle().poll_stats();
    assert_eq!(
        stats.contained_driver_panics, 0,
        "the attempt's panic ended the driver"
    );
    // The client sends its Initial again, so later attempts may have panicked as well.
    assert!(stats.contained_connection_panics >= 1, "{stats:?}");
    assert!(contained >= 1, "{contained}");

    healthy
        .close(AppCode::from_u32(4), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", closed_by_peer(4))]);
    harness.shutdown();
}

#[test]
fn a_certificate_resolver_reads_the_endpoint_counters_while_a_connection_is_created() {
    let mut harness = Harness::new();
    let mut tls = rustls::ServerConfig::clone(
        harness
            .server_config
            .tls()
            .rustls()
            .expect("a rustls server"),
    );
    tls.cert_resolver = Arc::new(CountingResolver(Arc::clone(&tls.cert_resolver)));
    harness.server_config = ServerConfig::builder(Arc::new(tls))
        .build()
        .expect("a server config");
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    assert_eq!(harness.server_stats::<Recorder>().contained_panics, 0);
    harness.shutdown();
}

#[test]
fn connections_the_poll_cap_passes_over_are_polled_first_in_the_next_turn() {
    const POLLS: usize = 20;
    let mut harness = Harness::new();
    harness.limits.polls = 1;
    // Each transmit phase sends one datagram of a connection, so a connection polled in one turn
    // still sends in its second transmit phase and is queued for the next turn's application
    // phase.
    harness.limits.max_segments = 1;
    harness.limits.requeues = 0;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let conns: Vec<ConnHandle> = ["one", "two"]
        .into_iter()
        .map(|name| {
            let (reports, token) = (tx.clone(), Arc::clone(&token));
            harness.connect(addr, move || Hog {
                name,
                reports,
                token,
                polls: POLLS,
                opened: false,
            })
        })
        .collect();
    await_reports(
        &rx,
        times(2, || Report::Event("client", ConnEvent::Connected)),
    );

    token.store(1, Ordering::SeqCst);
    // Both wakes land on the ready queue before the client's next turn.
    let blocked = Harness::block(&harness.client);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    drop(blocked);
    let mut first_polls: HashMap<&'static str, u64> = HashMap::new();
    while first_polls.len() < 2 {
        let report = rx
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| panic!("a producer was never polled: {first_polls:?}"));
        if let Report::Produced(name, turn) = report {
            first_polls.entry(name).or_insert(turn);
        }
    }
    let (one, two) = (first_polls["one"], first_polls["two"]);
    assert!(
        one.abs_diff(two) <= 1,
        "one producer waited behind the other: first polled in turns {one} and {two}"
    );
    harness.shutdown();
}

#[test]
fn wakes_are_served_while_timers_come_due_beyond_the_intake_cap() {
    let mut harness = Harness::new();
    harness.limits.intake = 1;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let contender = |spin| {
        let (reports, token, stop) = (tx.clone(), Arc::clone(&token), Arc::clone(&stop));
        move || Contender {
            reports,
            spin,
            token,
            stop,
            at: None,
        }
    };
    let spinner = harness.connect(addr, contender(true));
    let woken = harness.connect(addr, contender(false));
    await_reports(
        &rx,
        times(2, || Report::Event("client", ConnEvent::Connected)),
    );

    token.store(1, Ordering::SeqCst);
    spinner.wake().expect("the connection is live");
    await_reports(&rx, vec![Report::Spinning]);
    // From here a session deadline comes due in every turn, and the intake takes one connection.
    woken.wake().expect("the connection is live");
    loop {
        let report = rx
            .recv_timeout(WAIT)
            .expect("a wake was served while a timer came due in every turn");
        if matches!(report, Report::PolledInTurn(_)) {
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    harness.shutdown();
}

#[test]
fn established_traffic_keeps_flowing_while_initials_over_the_handshake_cap_wait() {
    const FORGED: usize = 4;
    let mut harness = Harness::new();
    harness.limits.handshakes = 1;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            let _ = server_reports.send(Report::Accepted(current_turn::<Heard>()));
            Ok(Heard {
                reports: server_reports.clone(),
                heard: false,
            })
        })
    });
    let token = Arc::new(AtomicUsize::new(0));
    let conn = {
        let (reports, token) = (tx.clone(), Arc::clone(&token));
        harness.connect(addr, move || Pinger {
            reports,
            token,
            sent: false,
        })
    };
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);

    let blocked = Harness::block(&harness.server);
    send_forged(addr, FORGED);
    token.store(1, Ordering::SeqCst);
    conn.wake().expect("the connection is live");
    let sent_in = loop {
        let report = rx.recv_timeout(WAIT).expect("the client sends its ping");
        if let Report::PolledInTurn(turn) = report {
            break turn;
        }
    };
    // Once that turn is over, the ping waits on the server's socket behind the forged Initials.
    harness.await_client_turn::<Pinger>(sent_in);
    drop(blocked);

    let mut accepted = Vec::new();
    let mut heard = None;
    while accepted.len() < FORGED || heard.is_none() {
        let report = rx.recv_timeout(WAIT).unwrap_or_else(|_| {
            panic!("still waiting: attempts in turns {accepted:?}, ping heard in {heard:?}")
        });
        match report {
            Report::Accepted(turn) => accepted.push(turn),
            Report::Heard(turn) => heard = Some(turn),
            _ => {}
        }
    }
    let heard = heard.expect("the loop waits for it");
    let last = accepted
        .iter()
        .copied()
        .max()
        .expect("the loop waits for them");
    assert!(
        heard < last,
        "the ping waited for the Initials ahead of it: heard in turn {heard}, attempts in turns \
         {accepted:?}"
    );
    harness.shutdown();
}

#[test]
fn initials_beyond_those_a_turn_can_keep_are_dropped() {
    const FORGED: usize = 4;
    let mut harness = Harness::new();
    harness.limits.handshakes = 1;
    harness.limits.waiting_initial_bytes = forged_initial().len();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(move || {
        App::new(move |_| {
            let _ = tx.send(Report::Accepted(current_turn::<Recorder>()));
            Ok(Recorder {
                name: "server",
                reports: tx.clone(),
            })
        })
    });
    let blocked = Harness::block(&harness.server);
    send_forged(addr, FORGED);
    drop(blocked);
    // One attempt fits in the first turn and one waits for the next; the other two are dropped.
    let mut accepted = 0;
    while accepted < 2 {
        let report = rx.recv_timeout(WAIT).expect("two attempts are made");
        accepted += usize::from(matches!(report, Report::Accepted(_)));
    }
    let stats = harness.server_stats::<Recorder>();
    accepted += rx
        .try_iter()
        .filter(|report| matches!(report, Report::Accepted(_)))
        .count();
    assert_eq!(stats.dropped_initials, 2, "{stats:?}");
    assert_eq!(accepted, 2, "only the attempts kept were made");
    harness.shutdown();
}

#[test]
fn a_quiesce_whose_grace_runs_past_the_clock_never_forces_a_close() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let quiesced = server_reports.clone();
        let mut app = App::new(move |_| {
            Ok(Quiet {
                reports: server_reports.clone(),
            })
        });
        app.quiesced = Some(quiesced);
        app
    });
    let client_reports = tx.clone();
    let conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);

    harness
        .server
        .handle()
        .submit(|_| with_handle::<Quiet, _>(|handle| handle.quiesce(Duration::MAX)))
        .expect("the server worker takes commands");
    await_reports(&rx, vec![Report::AppQuiesced, Report::SessionQuiesced]);
    // Still open, so the client's close reaches the server's session.
    conn.close(AppCode::from_u32(5), Bytes::new())
        .expect("the connection is live");
    await_reports(
        &rx,
        vec![
            Report::Event("server", closed_by_peer(5)),
            Report::Event("server", ConnEvent::Drained),
        ],
    );
    harness.await_server_finished::<Quiet>();
    assert_eq!(
        harness.server.handle().poll_stats().contained_driver_panics,
        0
    );
    harness.shutdown();
}

/// Returns transport settings for peers that acknowledge only after 255 ack-eliciting packets or
/// 16 s. They leave a few datagrams unanswered, and each holds the other's PTO off about as long,
/// so within a test only the driver under test moves a stalled connection on.
fn sluggish() -> Arc<TransportConfig> {
    TransportConfig::builder()
        .ack_policy(AckPolicy {
            before_init: 255,
            after_init: 255,
            max_ack_delay: Duration::from_secs(16),
            rtt_timer: false,
            ..AckPolicy::default()
        })
        .build()
        .expect("a transport config")
}

/// Returns whether every `cause` in `events` is followed by an attempt before anything arrives:
/// each connection the socket refused, or whose run it dropped, got its next attempt without
/// waiting for input.
fn resumed_without_input(events: &[Event], cause: Event) -> bool {
    events
        .iter()
        .enumerate()
        .filter(|&(_, &event)| event == cause)
        .all(|(at, _)| {
            events[at + 1..]
                .iter()
                .find(|event| matches!(event, Event::Attempt | Event::Received))
                == Some(&Event::Attempt)
        })
}

/// Returns the first attempt or flush in `events`.
fn first_attempt_or_flush(events: &[Event]) -> Option<Event> {
    events
        .iter()
        .copied()
        .find(|event| matches!(event, Event::Attempt | Event::Flush))
}

/// The bytes of each [`Ping`] stream: one datagram, and so one run, apiece.
const PING: usize = 1_100;

/// The shortest datagram a valve drops in these tests: a [`PING`] stream or its echo fills one,
/// and a packet of acknowledgments alone is far shorter.
const DROP_AT: u16 = 1_000;

/// A client session that sends [`PING`] bytes and the FIN on a new bidirectional stream through
/// the push path each time the test thread raises `wanted` and wakes it, and checks each echo. It
/// reports each event twice, once with the driver turn it came in.
struct Ping {
    wanted: Arc<AtomicUsize>,
    sent: usize,
    reports: mpsc::Sender<Report>,
    received: HashMap<StreamId, Vec<u8>>,
}

impl QuicSession for Ping {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let turn = with_backend_handle::<Ping, Gated, _>(|handle| handle.stats().turns);
        let _ = self.reports.send(Report::HeardInTurn(event.clone(), turn));
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let received = self.received.entry(id).or_default();
        for segment in read_all(conn, id) {
            received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self
                .reports
                .send(Report::Echoed(id, received[..] == payload(PING)[..]));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        while self.sent < self.wanted.load(Ordering::SeqCst) {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([payload(PING)]);
            assert!(
                push_all(conn, id, &mut queue, true),
                "the stream takes the whole ping"
            );
            self.sent += 1;
        }
        Poll::Pending
    }
}

/// An [`Echo`] server and a [`Ping`] client connected over gated sockets, with sluggish peers.
struct GatedPing {
    harness: Harness<Gated>,
    valves: Arc<Valves>,
    conn: ConnHandle,
    wanted: Arc<AtomicUsize>,
    rx: mpsc::Receiver<Report>,
}

impl GatedPing {
    fn new() -> Self {
        let valves = Arc::new(Valves::default());
        let harness = Harness::<Gated>::with_options(GatedOptions {
            mmsg: mmsg_options(),
            valves: Arc::clone(&valves),
        });
        let transport = sluggish();
        let (tx, rx) = mpsc::channel();
        let server_reports = tx.clone();
        let server_transport = Arc::clone(&transport);
        let addr = harness.serve(move || {
            let mut app = App::new(move |_| Ok(Echo::new(server_reports.clone())));
            app.transport = Some(server_transport);
            app
        });
        let wanted = Arc::new(AtomicUsize::new(0));
        let session_wanted = Arc::clone(&wanted);
        let conn = harness.connect_with(
            addr,
            ConnOptions {
                transport: Some(transport),
            },
            move || Ping {
                wanted: session_wanted,
                sent: 0,
                reports: tx,
                received: HashMap::new(),
            },
        );
        // Once the client has the handshake confirmed, both sides send only when prompted.
        await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);
        Self {
            harness,
            valves,
            conn,
            wanted,
            rx,
        }
    }

    /// Has the client send another stream.
    fn ping(&self) {
        self.wanted.fetch_add(1, Ordering::SeqCst);
        self.conn.wake().expect("the connection is live");
    }

    /// Waits for the echo of the client's `n`th stream.
    fn await_echo(&self, n: u32) {
        await_reports(&self.rx, vec![Report::Echoed(client_bidi(n), true)]);
    }

    /// Waits until the driver behind `valve` waits for its blocked socket, and has finished the
    /// poll in which it began to wait.
    fn await_waiting(&self, valve: &Valve) {
        let deadline = Instant::now() + WAIT;
        while !valve.waiting() {
            assert!(
                Instant::now() < deadline,
                "the driver never waited for its socket"
            );
            std::thread::yield_now();
        }
        // A command runs between the driver's polls.
        self.harness.server_stats::<Echo>();
        self.harness.client_stats::<Ping>();
    }

    /// Waits until `valve`'s sockets have refused `count` segments.
    fn await_refused(valve: &Valve, count: usize) {
        let deadline = Instant::now() + WAIT;
        while valve
            .events()
            .iter()
            .filter(|&&event| event == Event::Refused)
            .count()
            < count
        {
            assert!(Instant::now() < deadline, "the socket refused too little");
            std::thread::yield_now();
        }
    }
}

/// A session that sends `len` bytes and the FIN on a new unidirectional stream, and reports each
/// unidirectional stream its peer finishes with the bytes it carried. The client sends once the
/// test thread sets `go` and wakes it, and the server once its peer's stream has finished.
struct Bulk {
    name: &'static str,
    len: usize,
    go: Option<Arc<AtomicBool>>,
    sent: bool,
    reports: mpsc::Sender<Report>,
    received: HashMap<StreamId, usize>,
}

impl Bulk {
    fn new(
        name: &'static str,
        len: usize,
        go: Option<Arc<AtomicBool>>,
        reports: mpsc::Sender<Report>,
    ) -> Self {
        Self {
            name,
            len,
            go,
            sent: false,
            reports,
            received: HashMap::new(),
        }
    }

    fn send(&mut self, conn: &mut Conn<'_>) {
        if self.sent {
            return;
        }
        self.sent = true;
        let id = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
        let mut queue = VecDeque::from([payload(self.len)]);
        assert!(
            push_all(conn, id, &mut queue, true),
            "the stream takes it all"
        );
    }
}

impl QuicSession for Bulk {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event(self.name, event));
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let read: usize = read_all(conn, id).iter().map(Bytes::len).sum();
        let len = *self
            .received
            .entry(id)
            .and_modify(|len| *len += read)
            .or_insert(read);
        if ready == StreamReady::Finished {
            let _ = self.reports.send(Report::Received(id, len));
            if self.go.is_none() {
                self.send(conn);
            }
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.go.as_ref().is_some_and(|go| go.load(Ordering::SeqCst)) {
            self.send(conn);
        }
        Poll::Pending
    }
}

/// Returns the ID of unidirectional stream `id`.
fn uni(id: u32) -> StreamId {
    StreamId::from_varint(mvfstr_proto::VarInt::from_u32(id))
}

/// A [`Bulk`] server and a [`Bulk`] client with sluggish peers. The client sends its stream on
/// unidirectional stream 2 once `go` is called, and the server answers on stream 3.
struct BulkPair {
    conn: ConnHandle,
    go: Arc<AtomicBool>,
    rx: mpsc::Receiver<Report>,
}

impl BulkPair {
    /// Connects a client that sends `client_len` bytes to a server that sends `server_len` back,
    /// and returns once the client has the handshake confirmed.
    fn new<B: Backend>(harness: &Harness<B>, client_len: usize, server_len: usize) -> Self
    where
        B::Options: Clone + Send,
    {
        Self::through(harness, client_len, server_len, sluggish(), |addr| addr)
    }

    /// Like [`new`](Self::new), with `transport` on both sides, and the client connecting to the
    /// address `route` gives for the server's.
    fn through<B: Backend>(
        harness: &Harness<B>,
        client_len: usize,
        server_len: usize,
        transport: Arc<TransportConfig>,
        route: impl FnOnce(SocketAddr) -> SocketAddr,
    ) -> Self
    where
        B::Options: Clone + Send,
    {
        let (tx, rx) = mpsc::channel();
        let server_reports = tx.clone();
        let server_transport = Arc::clone(&transport);
        let addr = harness.serve(move || {
            let mut app = App::new(move |_| {
                Ok(Bulk::new(
                    "server",
                    server_len,
                    None,
                    server_reports.clone(),
                ))
            });
            app.transport = Some(server_transport);
            app
        });
        let go = Arc::new(AtomicBool::new(false));
        let session_go = Arc::clone(&go);
        let conn = harness.connect_with(
            route(addr),
            ConnOptions {
                transport: Some(transport),
            },
            move || Bulk::new("client", client_len, Some(session_go), tx),
        );
        await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);
        Self { conn, go, rx }
    }

    /// Sets the client's `go` and wakes its connection, so that the client sends its stream.
    fn go(&self) {
        self.go.store(true, Ordering::SeqCst);
        self.conn.wake().expect("the connection is live");
    }
}

#[test]
fn connections_refused_by_a_full_socket_resume_once_it_flushes() {
    // Seven datagrams, within the initial congestion window, which sluggish peers never open.
    const LEN: usize = 8_000;
    let valves = Arc::new(Valves::default());
    // One datagram of built but unsent bytes per connection: each attempt with more to send is
    // refused after its first datagram.
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: MmsgOptions {
            max_unsent: 1500,
            ..mmsg_options()
        },
        valves: Arc::clone(&valves),
    });
    let pair = BulkPair::new(&harness, LEN, LEN);

    // The client sends its stream on its own socket, and once that has finished the server sends
    // its stream back on the server socket. The peers do not answer so few datagrams.
    valves.client.clear();
    valves.server.clear();
    pair.go();
    await_reports_within(
        &pair.rx,
        vec![Report::Received(uni(2), LEN), Report::Received(uni(3), LEN)],
        STALL,
    );
    for (name, valve) in [("client", &valves.client), ("server", &valves.server)] {
        let events = valve.events();
        assert!(
            events.contains(&Event::Refused),
            "the {name} socket never refused: {events:?}"
        );
        assert!(
            resumed_without_input(&events, Event::Refused),
            "a connection the {name} socket refused waited for input: {events:?}"
        );
    }
    harness.shutdown();
}

#[test]
fn a_server_socket_writable_again_sends_its_backlog_before_another_attempt() {
    let ping = GatedPing::new();
    // The flush of the echo meets an EAGAIN.
    ping.valves.server.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.server);
    ping.valves.server.open();
    ping.await_echo(0);
    let events = ping.valves.server.events();
    assert_eq!(
        first_attempt_or_flush(&events),
        Some(Event::Flush),
        "the backlog waited for another attempt: {events:?}"
    );
    ping.harness.shutdown();
}

#[test]
fn a_client_socket_writable_again_sends_its_backlog_before_another_attempt() {
    let ping = GatedPing::new();
    // The flush of the ping meets an EAGAIN.
    ping.valves.client.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.client);
    ping.valves.client.open();
    ping.await_echo(0);
    let events = ping.valves.client.events();
    assert_eq!(
        first_attempt_or_flush(&events),
        Some(Event::Flush),
        "the backlog waited for another attempt: {events:?}"
    );
    ping.harness.shutdown();
}

#[test]
fn a_run_the_server_socket_drops_is_sent_again_without_waiting_for_input() {
    let ping = GatedPing::new();
    ping.valves.server.drop_next_run_of(DROP_AT);
    ping.ping();
    ping.await_echo(0);
    let events = ping.valves.server.events();
    assert!(
        events.contains(&Event::Dropped),
        "nothing dropped: {events:?}"
    );
    assert!(
        resumed_without_input(&events, Event::Dropped),
        "the dropped echo waited for input: {events:?}"
    );
    ping.harness.shutdown();
}

#[test]
fn a_run_a_client_socket_drops_is_sent_again_without_waiting_for_input() {
    let ping = GatedPing::new();
    ping.valves.client.drop_next_run_of(DROP_AT);
    ping.ping();
    ping.await_echo(0);
    let events = ping.valves.client.events();
    assert!(
        events.contains(&Event::Dropped),
        "nothing dropped: {events:?}"
    );
    assert!(
        resumed_without_input(&events, Event::Dropped),
        "the dropped ping waited for input: {events:?}"
    );
    ping.harness.shutdown();
}

#[test]
fn a_connection_the_blocked_server_socket_refuses_again_is_parked_once() {
    let ping = GatedPing::new();
    // The first echo waits behind the EAGAIN, and each later one is refused.
    ping.valves.server.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.server);
    ping.valves.server.clear();
    for refused in 1..=3 {
        ping.ping();
        GatedPing::await_refused(&ping.valves.server, refused);
    }
    let (tx, rx) = mpsc::channel();
    ping.harness
        .server
        .handle()
        .submit(move |_| {
            let _ = tx.send(with_backend_handle::<Echo, Gated, _>(|handle| {
                handle.parked()
            }));
        })
        .expect("the server worker takes commands");
    let parked = rx.recv_timeout(WAIT).expect("the server worker answers");
    assert_eq!(parked, 1, "the connection was parked once per refusal");
    ping.valves.server.open();
    for n in 0..4 {
        ping.await_echo(n);
    }
    ping.harness.shutdown();
}

#[test]
fn a_worker_that_drains_quiesces_its_driver_and_waits_for_it() {
    let harness = Harness::new();
    let mut runtime = RuntimeOwner::start(RuntimeConfig {
        workers: 1,
        command_capacity: 64,
    })
    .expect("a runtime starts");
    let worker = runtime
        .handle()
        .worker(0)
        .expect("the runtime has a worker");
    let (tx, rx) = mpsc::channel();
    let (addr_tx, addr_rx) = mpsc::channel();
    let (endpoint, config) = (harness.endpoint.clone(), harness.server_config.clone());
    let server_reports = tx.clone();
    worker
        .submit(move |worker| {
            let quiesced = server_reports.clone();
            let mut app = App::new(move |_| {
                Ok(Quiet {
                    reports: server_reports.clone(),
                })
            });
            app.quiesced = Some(quiesced);
            let handle = EndpointDriver::<_, MmsgBackend>::builder(endpoint, app)
                .bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config)
                .backend_options(mmsg_options())
                .spawn(worker)
                .expect("the server driver starts");
            let _ = addr_tx.send(handle.local_addr().expect("the server is bound"));
            HANDLES.with(|handles| handles.borrow_mut().push(Box::new(handle)));
        })
        .expect("the runtime's worker takes commands");
    let addr = addr_rx
        .recv_timeout(WAIT)
        .expect("the server driver starts");
    let client_reports = tx.clone();
    let conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);

    // The runtime drains its worker without cancelling it, so the driver quiesces by itself.
    let mut drained = pin!(runtime.handle().quiesce(WAIT));
    await_reports(&rx, vec![Report::AppQuiesced, Report::SessionQuiesced]);
    conn.close(AppCode::from_u32(9), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Drained)]);
    let deadline = Instant::now() + WAIT;
    let mut cx = Context::from_waker(Waker::noop());
    let result = loop {
        if let Poll::Ready(result) = drained.as_mut().poll(&mut cx) {
            break result;
        }
        assert!(
            Instant::now() < deadline,
            "the driver kept its worker from draining"
        );
        std::thread::yield_now();
    };
    result.expect("the worker drained cleanly");
    let report = runtime.join().expect("the worker is joined");
    assert_eq!(report.workers_forced, 0, "the worker's grace ran out");
    harness.shutdown();
}

#[test]
fn a_datagram_of_an_unknown_version_hears_version_negotiation() {
    let harness = Harness::new();
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(move || recording_server(tx));
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert_eq!(from, addr);
    let reply = &reply[..len];
    // A Version Negotiation packet as RFC 9000 lays it out: a long header of version 0 with the
    // connection IDs swapped, then the versions the server accepts.
    assert!(reply.len() > 23, "{reply:?}");
    assert_eq!(reply[0] & 0x80, 0x80, "a long header");
    assert_eq!(reply[1..5], [0; 4], "version 0");
    assert_eq!(reply[5..15], [8, 2, 2, 2, 2, 2, 2, 2, 2, 8]);
    assert_eq!(reply[15..23], [1; 8]);
    assert!(
        reply[23..].chunks(4).any(|version| version == [0, 0, 0, 1]),
        "QUIC v1 is offered: {reply:?}"
    );
    harness.shutdown();
}

#[test]
fn a_session_left_by_a_connect_that_fails_panics_in_drop_alone() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let client_reports = tx.clone();
    let healthy = harness.connect(addr, move || Fragile {
        recorder: Recorder {
            name: "client",
            reports: client_reports,
        },
        panics: false,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);

    let (answer_tx, answer_rx) = mpsc::channel();
    let config = harness.client_config.clone();
    harness
        .client
        .handle()
        .submit(move |_| {
            let failed = with_handle::<Fragile, _>(|handle| {
                handle.connect(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    ServerName::try_from("localhost").expect("a DNS name"),
                    config,
                    ConnOptions::default(),
                    Fragile {
                        recorder: Recorder {
                            name: "doomed",
                            reports: tx,
                        },
                        panics: true,
                    },
                )
            });
            let _ = answer_tx.send(matches!(
                failed,
                Err(DriverConnectError::Endpoint(
                    ConnectError::InvalidRemoteAddress(_)
                ))
            ));
        })
        .expect("the client worker takes commands");
    assert!(
        answer_rx
            .recv_timeout(WAIT)
            .expect("the connect returns to its caller"),
        "the connect did not fail on its remote address"
    );
    let stats = harness.client.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1, "{stats:?}");
    assert_eq!(stats.contained_driver_panics, 0, "{stats:?}");

    healthy
        .close(AppCode::from_u32(6), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", closed_by_peer(6))]);
    harness.shutdown();
}

#[test]
fn a_panic_while_a_connect_creates_its_connection_fails_only_that_connect() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let client_reports = tx.clone();
    let healthy = harness.connect(addr, move || Recorder {
        name: "client",
        reports: client_reports,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);

    // The new connection writes its ClientHello as it is created, and reads the store first.
    let mut tls = rustls::ClientConfig::clone(
        harness
            .client_config
            .tls()
            .rustls()
            .expect("a rustls client"),
    );
    tls.resumption = Resumption::store(Arc::new(DoomedStore));
    let doomed = ClientConfig::builder(Arc::new(tls))
        .build()
        .expect("a client config");
    let (answer_tx, answer_rx) = mpsc::channel();
    harness
        .client
        .handle()
        .submit(move |_| {
            let failed = with_handle::<Recorder, _>(|handle| {
                handle.connect(
                    addr,
                    ServerName::try_from("localhost").expect("a DNS name"),
                    doomed,
                    ConnOptions::default(),
                    Recorder {
                        name: "doomed",
                        reports: tx,
                    },
                )
            });
            let _ = answer_tx.send(matches!(
                failed,
                Err(DriverConnectError::Io(ref error)) if error.kind() == io::ErrorKind::Other
            ));
        })
        .expect("the client worker takes commands");
    assert!(
        answer_rx
            .recv_timeout(WAIT)
            .expect("the connect returns to its caller"),
        "the connect did not fail with the panic's error"
    );
    let stats = harness.client.handle().poll_stats();
    assert_eq!(stats.contained_connection_panics, 1, "{stats:?}");
    assert_eq!(stats.contained_driver_panics, 0, "{stats:?}");
    assert_eq!(harness.client_stats::<Recorder>().contained_panics, 1);

    healthy
        .close(AppCode::from_u32(8), Bytes::new())
        .expect("the connection is live");
    await_reports(&rx, vec![Report::Event("server", closed_by_peer(8))]);
    harness.shutdown();
}

/// Waits until `valve`'s sockets have done `event`.
fn await_event(valve: &Valve, event: Event) {
    let deadline = Instant::now() + WAIT;
    while !valve.events().contains(&event) {
        assert!(Instant::now() < deadline, "the socket never did {event:?}");
        std::thread::yield_now();
    }
}

#[test]
fn an_endpoint_with_nothing_to_do_parks_and_attempts_no_clean_connection() {
    const WAKES: u64 = 8;
    let ping = GatedPing::new();
    // One exchange first, so that everything the handshake sent has arrived.
    ping.ping();
    ping.await_echo(0);
    // A command runs between the driver's polls, so the turns that carried the echo have ended.
    let client_start = ping.harness.client_stats::<Ping>().turns;
    let server_start = ping.harness.server_stats::<Echo>().turns;
    ping.valves.client.clear();
    ping.valves.server.clear();

    // Each wake runs the client's `poll_session`, which does not send.
    for _ in 0..WAKES {
        let before = ping.harness.client_stats::<Ping>().turns;
        ping.conn.wake().expect("the connection is live");
        ping.harness.await_client_turn::<Ping>(before + 1);
    }
    let client_turns = ping.harness.client_stats::<Ping>().turns - client_start;
    let server_turns = ping.harness.server_stats::<Echo>().turns - server_start;
    let events = ping.valves.client.events();
    assert!(
        !events.contains(&Event::Attempt),
        "a connection with nothing new to send was attempted: {events:?}"
    );
    // One turn serves each wake, and the driver waits for the next wake after it.
    assert!(
        client_turns <= 2 * WAKES,
        "the client took {client_turns} turns for {WAKES} wakes"
    );
    assert!(
        server_turns <= 1,
        "the server, which heard nothing, took {server_turns} turns"
    );
    ping.harness.shutdown();
}

/// A client session whose `deadline` is 20 ms after it connects and stays in place once it is
/// served, and that reports each `poll_session` with its number.
struct Lingering {
    reports: mpsc::Sender<Report>,
    deadline: Option<Instant>,
    polls: usize,
}

impl QuicSession for Lingering {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            self.deadline = Some(conn.now() + Duration::from_millis(20));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        self.polls += 1;
        let _ = self.reports.send(Report::Polled(self.polls));
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[test]
fn a_session_deadline_left_in_place_once_served_is_not_served_again() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let _conn = harness.connect(addr, move || Lingering {
        reports: tx,
        deadline: None,
        polls: 0,
    });
    // The first poll comes with the connection, and the second at the deadline: only these two
    // wake the session.
    await_reports(&rx, vec![Report::Polled(1), Report::Polled(2)]);
    // A command runs between the driver's polls, so the poll that served the deadline has ended.
    harness.client_stats::<Lingering>();
    let again: Vec<Report> = rx
        .try_iter()
        .filter(|report| matches!(report, Report::Polled(_)))
        .collect();
    assert!(
        again.is_empty(),
        "the served deadline was served again: {again:?}"
    );
    harness.shutdown();
}

/// Returns socket settings that read one datagram per receive batch.
fn one_datagram_per_batch() -> MmsgOptions {
    let mut options = mmsg_options();
    options.rx_batch = 1;
    options.socket.gro = false;
    options
}

#[test]
fn datagrams_past_a_turns_receive_batches_on_the_server_socket_wait_for_no_wake() {
    let harness = Harness::<MmsgBackend>::with_options(one_datagram_per_batch());
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(move || recording_server(tx));
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // Datagrams the server drops fill more than a turn's receive batches, and a datagram that needs
    // an answer waits behind them. Without a connection, the server is not woken by a timer.
    let blocked = Harness::block(&harness.server);
    for _ in 0..2 * RX_BATCHES {
        peer.send_to(&too_small_for_a_reset(), addr)
            .expect("the datagram goes out");
    }
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    drop(blocked);

    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert_eq!(from, addr);
    assert!(len > 5, "{:?}", &reply[..len]);
    assert_eq!(reply[1..5], [0; 4], "version 0");
    harness.shutdown();
}

#[test]
fn datagrams_past_a_turns_receive_batches_on_a_client_socket_wait_for_no_wake() {
    // Seven datagrams, more than a turn's receive batches.
    const LEN: usize = 8_000;
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: one_datagram_per_batch(),
        valves: Arc::clone(&valves),
    });
    let pair = BulkPair::new(&harness, 100, LEN);

    // The client sends its stream while the server's worker is blocked.
    let server_blocked = Harness::block(&harness.server);
    valves.client.clear();
    pair.go();
    await_event(&valves.client, Event::Flush);
    // A command runs between the driver's polls, so the flush has ended.
    harness.client_stats::<Bulk>();

    // The server answers while the client's worker is blocked. Sluggish peers do not answer
    // anything else, and the client's next timer is seconds away.
    let client_blocked = Harness::block(&harness.client);
    valves.server.clear();
    drop(server_blocked);
    await_event(&valves.server, Event::Flush);
    harness.server_stats::<Bulk>();
    drop(client_blocked);

    await_reports_within(
        &pair.rx,
        vec![Report::Received(uni(2), 100), Report::Received(uni(3), LEN)],
        STALL,
    );
    harness.shutdown();
}

#[test]
fn a_full_batch_goes_back_to_the_tail_of_its_phase_and_the_phase_flushes_once() {
    // Seven datagrams, within the initial congestion window, which sluggish peers never open.
    const LEN: usize = 8_000;
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    // Every attempt fills its batch with one datagram.
    harness.limits.max_segments = 1;
    let pair = BulkPair::new(&harness, LEN, LEN);

    valves.client.clear();
    valves.server.clear();
    pair.go();
    await_reports(
        &pair.rx,
        vec![Report::Received(uni(2), LEN), Report::Received(uni(3), LEN)],
    );
    for (name, valve) in [("client", &valves.client), ("server", &valves.server)] {
        let events = valve.events();
        let most = events
            .split(|&event| event == Event::Flush)
            .map(|phase| {
                phase
                    .iter()
                    .filter(|&&event| event == Event::Attempt)
                    .count()
            })
            .max();
        assert!(
            most >= Some(7),
            "the {name}'s stream did not go out in one phase with one flush: {events:?}"
        );
    }
    harness.shutdown();
}

#[test]
fn a_full_batch_past_the_requeue_cap_is_attempted_in_the_next_phase() {
    // Seven datagrams, within the initial congestion window, which sluggish peers never open.
    const LEN: usize = 8_000;
    let mut harness = Harness::new();
    // Every attempt fills its batch with one datagram and never goes back to its phase's tail.
    harness.limits.max_segments = 1;
    harness.limits.requeues = 0;
    let pair = BulkPair::new(&harness, LEN, LEN);

    pair.go();
    await_reports(
        &pair.rx,
        vec![Report::Received(uni(2), LEN), Report::Received(uni(3), LEN)],
    );
    assert_eq!(harness.client_stats::<Bulk>().requeues, 0);
    assert_eq!(harness.server_stats::<Bulk>().requeues, 0);
    harness.shutdown();
}

/// Returns a server application whose sessions report their events as `server` and whose peers
/// are sluggish: it does not answer what a client sends on a stream.
fn sluggish_recording_server(reports: mpsc::Sender<Report>) -> App<Recorder> {
    let mut app = recording_server(reports);
    app.transport = Some(sluggish());
    app
}

/// Returns connection options with [`sluggish`] transport settings.
fn sluggish_options() -> ConnOptions {
    ConnOptions {
        transport: Some(sluggish()),
    }
}

#[test]
fn a_panic_outside_every_connection_closes_every_handle_of_the_driver() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    harness
        .client
        .handle()
        .submit(|_| with_handle::<Recorder, _>(|handle| handle.fail_next_turn()))
        .expect("the client worker takes commands");
    let deadline = Instant::now() + WAIT;
    while conn.wake() != Err(crate::SubmitError::Closed) {
        assert!(Instant::now() < deadline, "the handle outlived its driver");
        std::thread::yield_now();
    }
    let stats = harness.client.handle().poll_stats();
    assert_eq!(stats.contained_driver_panics, 1, "{stats:?}");
    harness.shutdown();
}

#[test]
fn a_worker_that_stops_closes_every_handle_of_its_driver() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    harness.shutdown();
    assert_eq!(conn.wake(), Err(crate::SubmitError::Closed));
    // The connection ended with the worker, without waiting out a quiesce's grace and close.
    let closes: Vec<Report> = rx
        .try_iter()
        .filter(|report| matches!(report, Report::Event("client", ConnEvent::Closed { .. })))
        .collect();
    assert!(
        closes.is_empty(),
        "the connection waited for a quiesce to close it: {closes:?}"
    );
}

/// Returns an application close with `code` and an empty reason, as the sending side gets it.
fn closed_locally(code: u32) -> ConnEvent {
    ConnEvent::Closed {
        reason: CloseReason::Application {
            code: AppCode::from_u32(code),
            reason: Bytes::new(),
        },
        initiator: Initiator::Local,
    }
}

#[test]
fn a_close_by_handle_reaches_the_session_while_the_socket_holds_it_back() {
    let ping = GatedPing::new();
    // The flush of the ping meets an EAGAIN, and the client socket refuses everything after it.
    ping.valves.client.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.client);
    ping.conn
        .close(AppCode::from_u32(5), Bytes::new())
        .expect("the connection is live");
    await_reports_within(
        &ping.rx,
        vec![Report::Event("client", closed_locally(5))],
        STALL,
    );
    assert!(
        ping.valves.client.waiting(),
        "the close was heard only once the socket took it"
    );
    ping.valves.client.open();
    ping.harness.shutdown();
}

#[test]
fn many_closes_by_handle_close_the_connection_with_the_first_code() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Connected)]);
    // The closes go in from a command on the client worker, which runs between its driver's polls,
    // so the driver does not serve any of them before the last.
    let (answer_tx, answer_rx) = mpsc::channel();
    harness
        .client
        .handle()
        .submit(move |_| {
            let refused: Vec<(u32, crate::SubmitError)> = (1..=100)
                .filter_map(|code| {
                    conn.close(AppCode::from_u32(code), Bytes::new())
                        .err()
                        .map(|error| (code, error))
                })
                .collect();
            let _ = answer_tx.send(refused);
        })
        .expect("the client worker takes commands");
    let refused = answer_rx
        .recv_timeout(WAIT)
        .expect("the client worker answers");
    assert!(
        refused.is_empty(),
        "closes refused while the connection was live: {refused:?}"
    );
    await_reports(
        &rx,
        vec![
            Report::Event("client", closed_locally(1)),
            Report::Event("server", closed_by_peer(1)),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_quiesce_close_reaches_the_session_while_the_socket_holds_it_back() {
    let ping = GatedPing::new();
    // The flush of the ping meets an EAGAIN, and the client socket refuses everything after it.
    ping.valves.client.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.client);
    // The grace runs out in a later turn of its own, which closes the connection.
    ping.harness
        .client
        .handle()
        .submit(|_| {
            with_backend_handle::<Ping, Gated, _>(|handle| {
                handle.quiesce(Duration::from_millis(50));
            });
        })
        .expect("the client worker takes commands");
    let closed = ConnEvent::Closed {
        reason: CloseReason::Transport {
            code: mvfstr_proto::TransportErrorCode::NO_ERROR,
            frame_type: None,
            reason: Bytes::new(),
        },
        initiator: Initiator::Local,
    };
    // The socket holds the close back until the quiesce aborts the connection a second later.
    let mut closed_in = None;
    let drained_in = loop {
        match ping.rx.recv_timeout(WAIT).expect("the connection ends") {
            Report::HeardInTurn(event, turn) if event == closed => closed_in = Some(turn),
            Report::HeardInTurn(ConnEvent::Drained, turn) => break turn,
            _ => {}
        }
    };
    let closed_in = closed_in.expect("the close was heard before the connection drained");
    assert!(
        closed_in < drained_in,
        "the close was heard only when the quiesce aborted the connection, in turn {drained_in}"
    );
    ping.valves.client.open();
    ping.harness.shutdown();
}

/// A client session that, each time the test thread raises `wanted` and wakes it, opens a
/// bidirectional stream and hands its stream waker to the test thread without waking it. Once
/// woken, the stream's producer reports its driver turn and sends [`PING`] bytes and the FIN
/// through the pull path. The session checks each echo.
struct Remote {
    name: &'static str,
    wanted: Arc<AtomicUsize>,
    opened: usize,
    wakers: mpsc::Sender<(&'static str, Waker)>,
    reports: mpsc::Sender<Report>,
    received: HashMap<StreamId, Vec<u8>>,
}

impl Remote {
    fn new(
        name: &'static str,
        wanted: Arc<AtomicUsize>,
        wakers: mpsc::Sender<(&'static str, Waker)>,
        reports: mpsc::Sender<Report>,
    ) -> Self {
        Self {
            name,
            wanted,
            opened: 0,
            wakers,
            reports,
            received: HashMap::new(),
        }
    }
}

impl QuicSession for Remote {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let received = self.received.entry(id).or_default();
        for segment in read_all(conn, id) {
            received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self
                .reports
                .send(Report::Echoed(id, received[..] == payload(PING)[..]));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::Produced(self.name, current_turn::<Remote>()));
        sink.push(payload(PING)).expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        while self.opened < self.wanted.load(Ordering::SeqCst) {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let _ = self.wakers.send((self.name, conn.stream_waker(id)));
            self.opened += 1;
        }
        Poll::Pending
    }
}

#[test]
fn a_stream_waker_fired_from_another_thread_gets_its_producer_polled() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| Ok(Echo::new(server_reports.clone())));
        app.transport = Some(sluggish());
        app
    });
    let wanted = Arc::new(AtomicUsize::new(0));
    let (wakers_tx, wakers) = mpsc::channel();
    let session_wanted = Arc::clone(&wanted);
    let conn = harness.connect_with(addr, sluggish_options(), move || {
        Remote::new("client", session_wanted, wakers_tx, tx)
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);

    // The first exchange lets what the handshake sent arrive; after it only the second waker
    // reaches the client.
    for n in 0..2 {
        wanted.fetch_add(1, Ordering::SeqCst);
        conn.wake().expect("the connection is live");
        let (_, waker) = wakers.recv_timeout(WAIT).expect("a stream opens");
        // A command runs between the driver's polls, so the turn that opened the stream has
        // ended.
        harness.client_stats::<Remote>();
        waker.wake();
        await_reports_within(&rx, vec![Report::Echoed(client_bidi(n), true)], STALL);
    }
    harness.shutdown();
}

#[test]
fn a_connection_the_poll_cap_passes_over_gets_another_turn_without_a_wake() {
    let mut harness = Harness::new();
    harness.limits.polls = 1;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || sluggish_recording_server(tx)
    });
    let wanted = Arc::new(AtomicUsize::new(0));
    let (wakers_tx, wakers) = mpsc::channel();
    let conns: Vec<ConnHandle> = ["one", "two"]
        .into_iter()
        .map(|name| {
            let (wanted, wakers, reports) = (Arc::clone(&wanted), wakers_tx.clone(), tx.clone());
            harness.connect_with(addr, sluggish_options(), move || {
                Remote::new(name, wanted, wakers, reports)
            })
        })
        .collect();
    await_reports(
        &rx,
        times(2, || Report::Event("client", ConnEvent::Confirmed)),
    );
    wanted.store(1, Ordering::SeqCst);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    let stream_wakers: HashMap<&'static str, Waker> = (0..2)
        .map(|_| wakers.recv_timeout(WAIT).expect("a stream opens"))
        .collect();
    harness.client_stats::<Remote>();

    // Both stream wakers land on the ready queue before the client's next turn. Its one poll
    // goes to the first connection, whose stream the server does not answer, and its socket is
    // drained; only the passed-over second connection is left to do.
    let blocked = Harness::block(&harness.client);
    stream_wakers["one"].wake_by_ref();
    stream_wakers["two"].wake_by_ref();
    drop(blocked);
    let deadline = Instant::now() + STALL;
    let mut produced = HashMap::new();
    while produced.len() < 2 {
        let report = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("a producer was left unpolled: {produced:?}"));
        if let Report::Produced(name, turn) = report {
            produced.entry(name).or_insert(turn);
        }
    }
    assert!(
        produced["two"] > produced["one"],
        "the poll cap passed nothing over: {produced:?}"
    );
    harness.shutdown();
}

/// Returns the most transmit attempts in `events` between two flushes.
fn most_attempts_per_flush(events: &[Event]) -> usize {
    events
        .split(|&event| event == Event::Flush)
        .map(|phase| {
            phase
                .iter()
                .filter(|&&event| event == Event::Attempt)
                .count()
        })
        .max()
        .unwrap_or(0)
}

#[test]
fn a_connection_dirtied_twice_before_a_transmit_phase_is_attempted_once_in_it() {
    let ping = GatedPing::new();
    ping.valves.client.clear();
    ping.valves.server.clear();
    // The server both receives the ping and sends the echo through `Conn` before its next
    // transmit phase, which flushes the server socket once.
    ping.ping();
    ping.await_echo(0);
    // A command runs between the driver's polls, so the turns that carried the echo have ended.
    ping.harness.server_stats::<Echo>();
    let events = ping.valves.server.events();
    assert!(events.contains(&Event::Attempt), "{events:?}");
    assert_eq!(
        most_attempts_per_flush(&events),
        1,
        "a transmit phase attempted its one connection more than once: {events:?}"
    );
    ping.harness.shutdown();
}

/// Waits until the server driver for sessions of type `S` on backend `B` has finished a turn.
fn await_first_server_turn<S: QuicSession, B: Backend>(harness: &Harness<B>)
where
    B::Options: Clone + Send,
{
    let deadline = Instant::now() + WAIT;
    while harness.server_stats::<S>().turns == 0 {
        assert!(Instant::now() < deadline, "the server driver never ran");
        std::thread::yield_now();
    }
}

#[test]
fn a_stateless_reply_the_server_socket_holds_back_leaves_once_it_is_writable() {
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(move || recording_server(tx));
    await_first_server_turn::<Recorder, Gated>(&harness);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // The flush of the Version Negotiation packet meets an EAGAIN. Without a connection, the server
    // is woken again only by its socket turning writable.
    valves.server.block_next_flush();
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    let deadline = Instant::now() + WAIT;
    while !valves.server.waiting() {
        assert!(
            Instant::now() < deadline,
            "the server never waited for its socket"
        );
        std::thread::yield_now();
    }
    valves.server.open();
    let mut reply = [0; 1500];
    let (len, _) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert!(len > 5, "{:?}", &reply[..len]);
    assert_eq!(reply[1..5], [0; 4], "version 0");
    harness.shutdown();
}

#[test]
fn a_receive_error_on_the_server_socket_leaves_the_rest_of_the_receive_to_run() {
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(move || recording_server(tx));
    await_first_server_turn::<Recorder, Gated>(&harness);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // Without a connection, the server is woken only by the datagram, and its first receive fails.
    valves.server.fail_next_recv();
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    let mut reply = [0; 1500];
    let (len, _) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert!(len > 5, "{:?}", &reply[..len]);
    assert_eq!(reply[1..5], [0; 4], "version 0");
    harness.shutdown();
}

#[test]
fn a_connection_refused_while_its_socket_waits_to_be_writable_waits_with_it() {
    let ping = GatedPing::new();
    // The flush of the first ping meets an EAGAIN, and the socket refuses the second.
    ping.valves.client.block_next_flush();
    ping.ping();
    ping.await_waiting(&ping.valves.client);
    ping.valves.client.clear();
    ping.ping();
    GatedPing::await_refused(&ping.valves.client, 1);
    // A command runs between the driver's polls, so the turn of the refusal has ended.
    ping.harness.client_stats::<Ping>();
    let events = ping.valves.client.events();
    assert_eq!(
        events
            .iter()
            .filter(|&&event| event == Event::Attempt)
            .count(),
        1,
        "the connection was attempted again before its socket turned writable: {events:?}"
    );
    ping.valves.client.open();
    ping.await_echo(0);
    ping.await_echo(1);
    ping.harness.shutdown();
}

/// Returns an endpoint config whose connections use zero-length connection IDs.
fn zero_length_cids() -> Arc<EndpointConfig> {
    EndpointConfig::builder(reset_key())
        .local_cid_len(0)
        .build()
        .expect("an endpoint config")
}

#[test]
fn a_drained_connection_gives_up_its_routes() {
    let mut harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    // The client's connections take the one zero-length connection ID, so a second can open
    // only once the first has given up its route.
    harness.endpoint = zero_length_cids();
    for code in [1, 2] {
        let reports = tx.clone();
        let conn = harness.connect(addr, move || Recorder {
            name: "client",
            reports,
        });
        await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);
        conn.close(AppCode::from_u32(code), Bytes::new())
            .expect("the connection is live");
        await_reports(&rx, vec![Report::Event("client", ConnEvent::Drained)]);
    }
    harness.shutdown();
}

#[test]
fn wakes_the_intake_cap_leaves_are_served_without_another_wake() {
    let mut harness = Harness::new();
    harness.limits.intake = 1;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || sluggish_recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let conns: Vec<ConnHandle> = (0..2)
        .map(|_| {
            let (reports, token) = (tx.clone(), Arc::clone(&token));
            harness.connect_with(addr, sluggish_options(), move || Waking { reports, token })
        })
        .collect();
    await_reports(
        &rx,
        times(2, || Report::Event("client", ConnEvent::Confirmed)),
    );

    // Both wakes land on the ready queue before the client's next turn, which serves one.
    token.store(1, Ordering::SeqCst);
    let blocked = Harness::block(&harness.client);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    drop(blocked);
    await_reports_within(&rx, times(2, || Report::Polled(1)), STALL);
    harness.shutdown();
}

/// A client session that reports its events and each `poll_session` with its number, and in the
/// second sets its deadline to now.
struct Prompt {
    reports: mpsc::Sender<Report>,
    polls: usize,
    deadline: Option<Instant>,
}

impl QuicSession for Prompt {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        self.polls += 1;
        let _ = self.reports.send(Report::Polled(self.polls));
        if self.polls == 2 {
            self.deadline = Some(conn.now());
        }
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[test]
fn a_deadline_due_before_the_driver_parks_gets_another_turn() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || sluggish_recording_server(tx)
    });
    let conn = harness.connect_with(addr, sluggish_options(), move || Prompt {
        reports: tx,
        polls: 0,
        deadline: None,
    });
    await_reports(
        &rx,
        vec![
            Report::Polled(1),
            Report::Event("client", ConnEvent::Confirmed),
        ],
    );
    // A command runs between the driver's polls, so the turn that confirmed the handshake has
    // ended.
    harness.client_stats::<Prompt>();
    conn.wake().expect("the connection is live");
    await_reports_within(&rx, vec![Report::Polled(2), Report::Polled(3)], STALL);
    harness.shutdown();
}

/// Returns the order in which the client's close with `code` and its `poll_session` with token 1
/// reach the test thread.
fn close_and_poll_order(rx: &mpsc::Receiver<Report>, code: u32) -> Vec<Report> {
    let closed = Report::Event("client", closed_locally(code));
    let mut order = Vec::new();
    while order.len() < 2 {
        let report = rx
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| panic!("saw only {order:?}"));
        if report == closed || report == Report::Polled(1) {
            order.push(report);
        }
    }
    order
}

#[test]
fn a_session_hears_its_events_before_its_poll_session() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let session_token = Arc::clone(&token);
    let conn = harness.connect(addr, move || Waking {
        reports: tx,
        token: session_token,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);

    // The wake and the close are served in one turn.
    token.store(1, Ordering::SeqCst);
    let blocked = Harness::block(&harness.client);
    conn.wake().expect("the connection is live");
    conn.close(AppCode::from_u32(3), Bytes::new())
        .expect("the connection is live");
    drop(blocked);
    assert_eq!(
        close_and_poll_order(&rx, 3),
        vec![
            Report::Event("client", closed_locally(3)),
            Report::Polled(1)
        ]
    );
    harness.shutdown();
}

/// A client session that reports its events and, once the test thread has set `token`, each
/// `poll_session`, and that closes its connection with code 7 when the driver quiesces.
struct Leaving {
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
}

impl QuicSession for Leaving {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 1 {
            let _ = self.reports.send(Report::Polled(1));
        }
        Poll::Pending
    }

    fn on_quiesce(&mut self, conn: &mut Conn<'_>) {
        let now = conn.now();
        conn.close(now, AppCode::from_u32(7), Bytes::new());
    }
}

#[test]
fn a_session_hears_what_its_on_quiesce_did_before_its_poll_session() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let session_token = Arc::clone(&token);
    let conn = harness.connect(addr, move || Leaving {
        reports: tx,
        token: session_token,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);

    // The quiesce and the wake are served in one turn.
    token.store(1, Ordering::SeqCst);
    harness
        .client
        .handle()
        .submit(move |_| {
            with_handle::<Leaving, _>(|handle| handle.quiesce(WAIT));
            conn.wake().expect("the connection is live");
        })
        .expect("the client worker takes commands");
    assert_eq!(
        close_and_poll_order(&rx, 7),
        vec![
            Report::Event("client", closed_locally(7)),
            Report::Polled(1)
        ]
    );
    harness.shutdown();
}

/// A client session that reports how many packets its connection had declared lost when its
/// handshake completed.
struct Lossless {
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Lossless {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Connected {
            let _ = self
                .reports
                .send(Report::LostByConnected(conn.stats().lost_packets));
        }
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[test]
fn the_rest_of_a_first_flight_kept_behind_the_handshake_cap_reaches_its_new_connection() {
    let mut harness = Harness::new();
    harness.limits.handshakes = 1;
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    // A ClientHello that offers a long list of protocols takes two Initial datagrams. A client
    // whose second datagram the server dropped would have to declare it lost and send it again.
    let mut tls = rustls::ClientConfig::clone(
        harness
            .client_config
            .tls()
            .rustls()
            .expect("a rustls client"),
    );
    tls.alpn_protocols
        .extend((b'a'..b'i').map(|letter| vec![letter; 200]));
    harness.client_config = ClientConfig::builder(Arc::new(tls))
        .build()
        .expect("a client config");

    // Both first flights reach the server in one batch. Its turn takes the first connection
    // attempt and keeps both datagrams of the second, and the next turn takes the second attempt
    // and keeps the datagram after it once more.
    let blocked = Harness::block(&harness.server);
    let (_conns, turn) = harness.connect_all(addr, 2, move || Lossless {
        reports: tx.clone(),
    });
    harness.await_client_turn::<Lossless>(turn + 1);
    drop(blocked);
    await_reports(&rx, times(2, || Report::LostByConnected(0)));
    harness.shutdown();
}

/// The server's stream window in [`a_send_that_frees_staging_room_gets_its_producer_polled_again`]:
/// 1 KiB more than the 64 KiB a stream stages at most. A producer that fills that cap keeps 1 KiB
/// of stream credit, and its allowance reaches the low-water mark again once a send has freed
/// 1 KiB of staging room.
const REFILL_WINDOW: u64 = 65 * 1024;

/// A server session that echoes a bidirectional stream once its FIN has arrived and leaves every
/// stream unread until then, so a stream without a FIN does not draw an answer or credit.
struct EchoAtFin;

impl QuicSession for EchoAtFin {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if ready != StreamReady::Finished {
            return;
        }
        let mut queue = VecDeque::from(read_all(conn, id));
        assert!(
            push_all(conn, id, &mut queue, true),
            "the stream takes the whole echo"
        );
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that sends [`PING`] bytes and the FIN on a bidirectional stream through the
/// push path once the test thread sets `go` and wakes it. When the echo's FIN arrives, it opens a
/// second bidirectional stream and marks its producer ready through the stream rather than a
/// waker, so the producer is first polled in the application phase after the receive that brought
/// the echo, without a wake left behind. The producer reports the driver turn of each poll and
/// pushes its whole allowance, without a FIN.
struct Refill {
    go: Arc<AtomicBool>,
    pinged: bool,
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Refill {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        read_all(conn, id);
        if ready == StreamReady::Finished {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            conn.stream(id).expect("the stream is open").wake_producer();
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::PolledInTurn(current_turn::<Refill>()));
        let len = sink.allowance();
        sink.push(payload(len)).expect("within the allowance");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if !self.pinged && self.go.load(Ordering::SeqCst) {
            self.pinged = true;
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([payload(PING)]);
            assert!(
                push_all(conn, id, &mut queue, true),
                "the stream takes the whole ping"
            );
        }
        Poll::Pending
    }
}

/// Returns the turn of the next [`Report::PolledInTurn`] from `rx` within `within`, or `None`.
fn next_polled_turn(rx: &mpsc::Receiver<Report>, within: Duration) -> Option<u64> {
    let deadline = Instant::now() + within;
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Report::PolledInTurn(turn)) => return Some(turn),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

#[test]
fn a_send_that_frees_staging_room_gets_its_producer_polled_again() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve(|| {
        let mut app = App::new(|_| Ok(EchoAtFin));
        app.transport = Some(
            TransportConfig::builder()
                .ack_policy(sluggish().ack_policy())
                .max_stream_data_bidi_remote(REFILL_WINDOW)
                .build()
                .expect("a transport config"),
        );
        app
    });
    let go = Arc::new(AtomicBool::new(false));
    let session_go = Arc::clone(&go);
    let conn = harness.connect_with(addr, sluggish_options(), move || Refill {
        go: session_go,
        pinged: false,
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);
    go.store(true, Ordering::SeqCst);
    conn.wake().expect("the connection is live");

    // The receive of the echo brings the first poll, in the application phase after it, and the
    // producer fills the stream's cap. The transmit phase after that sends part of what it
    // staged, and the allowance that frees is all that is left to do: the server neither reads
    // the stream nor acknowledges, and the client's timers are 16 s away.
    let first = next_polled_turn(&rx, WAIT).expect("the producer is polled");
    let second = next_polled_turn(&rx, STALL)
        .expect("the producer was not polled again once a send freed its staging room");
    assert_eq!(
        second,
        first + 1,
        "the producer polled in turn {first} was polled again in turn {second}"
    );
    harness.shutdown();
}

#[test]
fn a_connection_attempt_the_application_ignores_draws_no_answer() {
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut attempts = 0;
        App::<Recorder>::new(move |_| {
            attempts += 1;
            let _ = server_reports.send(Report::Attempt(attempts));
            Err(Refusal::Ignore)
        })
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Attempt(1)]);
    // A command runs between the driver's polls, so the turn that ran the application's `accept`
    // has ended.
    harness.server_stats::<Recorder>();
    let events = valves.server.events();
    assert!(events.contains(&Event::Received), "{events:?}");
    assert_eq!(
        first_attempt_or_flush(&events),
        None,
        "the server answered an attempt its application ignored: {events:?}"
    );

    // Without an answer, the client sends its Initial again.
    let heard = await_reports(&rx, vec![Report::Attempt(2)]);
    assert!(
        !heard
            .iter()
            .any(|report| matches!(report, Report::Event("client", ConnEvent::Closed { .. }))),
        "the client heard its attempt end: {heard:?}"
    );
    harness.shutdown();
}

#[test]
fn a_datagram_the_endpoint_drops_leaves_the_rest_of_its_batch_routed() {
    let harness = Harness::new();
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(move || recording_server(tx));
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // A datagram the server drops and one that needs an answer reach it in one receive batch.
    // Without a connection, the server is not woken by a timer for what the batch left unrouted.
    let blocked = Harness::block(&harness.server);
    peer.send_to(&too_small_for_a_reset(), addr)
        .expect("the datagram goes out");
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    drop(blocked);

    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert_eq!(from, addr);
    assert!(len > 5, "{:?}", &reply[..len]);
    assert_eq!(reply[1..5], [0; 4], "version 0");
    harness.shutdown();
}

/// Returns how many slots the driver for sessions of type `S` on `worker` has handed out.
fn slots<S: QuicSession>(worker: &ManagedWorker) -> u32 {
    let (tx, rx) = mpsc::channel();
    worker
        .handle()
        .submit(move |_| {
            let _ = tx.send(with_handle::<S, _>(|handle| handle.slots()));
        })
        .expect("the worker takes commands");
    rx.recv_timeout(WAIT).expect("the worker answers")
}

#[test]
fn connections_that_fail_to_open_give_their_slots_back() {
    const FAILURES: usize = 3;
    let mut harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut attempts = 0;
        App::new(move |_| {
            attempts += 1;
            let _ = server_reports.send(Report::Attempt(attempts));
            Ok(Recorder {
                name: "server",
                reports: server_reports.clone(),
            })
        })
    });

    // The application accepts each forged Initial, whose connection then fails to open.
    send_forged(addr, FAILURES);
    await_reports(&rx, (1..=FAILURES).map(Report::Attempt).collect());
    assert_eq!(
        slots::<Recorder>(&harness.server),
        1,
        "connection attempts that failed kept their slots"
    );

    // The client's connections take the one zero-length connection ID, so every connect after
    // the first fails in the endpoint.
    harness.endpoint = zero_length_cids();
    let (endpoint, config) = (harness.endpoint.clone(), harness.client_config.clone());
    let (limits, options) = (harness.limits, harness.options.clone());
    let (failed_tx, failed_rx) = mpsc::channel();
    harness
        .client
        .handle()
        .submit(move |worker| {
            ensure_client::<Recorder, MmsgBackend>(worker, endpoint, options, limits);
            let _live = open::<Recorder, MmsgBackend>(
                addr,
                config.clone(),
                ConnOptions::default(),
                Recorder {
                    name: "client",
                    reports: tx.clone(),
                },
            );
            let failed = (0..FAILURES)
                .filter(|_| {
                    with_handle::<Recorder, _>(|handle| {
                        matches!(
                            handle.connect(
                                addr,
                                ServerName::try_from("localhost").expect("a DNS name"),
                                config.clone(),
                                ConnOptions::default(),
                                Recorder {
                                    name: "doomed",
                                    reports: tx.clone(),
                                },
                            ),
                            Err(DriverConnectError::Endpoint(ConnectError::NoConnectionId))
                        )
                    })
                })
                .count();
            let _ = failed_tx.send(failed);
        })
        .expect("the client worker takes commands");
    assert_eq!(
        failed_rx.recv_timeout(WAIT).expect("the connects return"),
        FAILURES
    );
    assert_eq!(
        slots::<Recorder>(&harness.client),
        2,
        "connects that failed kept their slots"
    );
    harness.shutdown();
}

#[test]
fn a_server_driver_for_one_of_several_workers_resets_only_its_own_connection_ids() {
    let mut harness = Harness::new();
    harness.worker = Some((1, 2));
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // The connection IDs of worker 0 of 2 start with an even byte and worker 1's with an odd one.
    // Both headers reach the server in one receive batch, so an answer to the first would come
    // back first.
    let blocked = Harness::block(&harness.server);
    peer.send_to(&short_header(0x10, 40), addr)
        .expect("the datagram goes out");
    peer.send_to(&short_header(0x11, 100), addr)
        .expect("the datagram goes out");
    drop(blocked);

    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a stateless reset comes back");
    assert_eq!(from, addr);
    // RFC 9000 requires a reset to be shorter than its trigger, and the endpoint sends one byte
    // less, up to 43 bytes: 39 would answer worker 0's 40-byte header, 43 worker 1's 100-byte one.
    assert_eq!(
        len,
        43,
        "the header for another worker drew an answer: {:?}",
        &reply[..len]
    );
    assert_eq!(reply[0] & 0xc0, 0x40, "a short header");

    // Connections to the worker still open.
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);
    harness.shutdown();
}

#[test]
fn a_driver_for_a_worker_outside_its_count_does_not_start() {
    let harness = Harness::new();
    let (endpoint, config) = (harness.endpoint.clone(), harness.server_config.clone());
    let (tx, rx) = mpsc::channel();
    harness
        .server
        .handle()
        .submit(move |worker| {
            let started =
                EndpointDriver::<_, MmsgBackend>::builder(endpoint, App::<Recorder>::client())
                    .bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config)
                    .worker(2, 2)
                    .spawn(worker);
            let _ = tx.send(matches!(
                started,
                Err(DriverError::Config(ConfigError::OutOfRange {
                    field: "worker"
                }))
            ));
        })
        .expect("the server worker takes commands");
    assert!(
        rx.recv_timeout(WAIT).expect("the worker answers"),
        "worker 2 of 2 started"
    );
    harness.shutdown();
}

/// A client session that reports its events, and sends [`PING`] bytes and the FIN on a new
/// bidirectional stream each time the test thread raises `wanted` and wakes it.
struct Talker {
    wanted: Arc<AtomicUsize>,
    sent: usize,
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Talker {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        while self.sent < self.wanted.load(Ordering::SeqCst) {
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([payload(PING)]);
            assert!(
                push_all(conn, id, &mut queue, true),
                "the stream takes the whole ping"
            );
            self.sent += 1;
        }
        Poll::Pending
    }
}

#[test]
fn the_peer_of_a_server_connection_a_panic_tore_down_hears_a_stateless_reset() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr =
        harness.serve(move || App::new(move |_| Ok(MaybePanic::Panic(server_reports.clone()))));
    let wanted = Arc::new(AtomicUsize::new(0));
    let conn = harness.connect(addr, {
        let wanted = Arc::clone(&wanted);
        move || Talker {
            wanted,
            sent: 0,
            reports: tx,
        }
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);

    // The server session panics when the client's stream opens, and its connection ends silently.
    wanted.store(1, Ordering::SeqCst);
    conn.wake().expect("the connection is live");
    await_reports(&rx, vec![Report::Panicking]);

    // The server no longer has the client's connection, so its endpoint answers the client's next
    // packet with a stateless reset that the client recognises, long before its 30 s idle timeout.
    wanted.store(2, Ordering::SeqCst);
    conn.wake().expect("the connection is live");
    await_reports_within(
        &rx,
        vec![Report::Event(
            "client",
            ConnEvent::Closed {
                reason: CloseReason::Silent,
                initiator: Initiator::StatelessReset,
            },
        )],
        STALL,
    );
    harness.shutdown();
}

/// How often a relay thread waiting to receive checks the relay's stop flag.
const RELAY_POLL: Duration = Duration::from_millis(10);

/// A datagram on a relay's delay line: when it leaves, the socket it leaves from, and where it
/// goes.
struct Hop {
    due: Instant,
    data: Vec<u8>,
    via: Arc<UdpSocket>,
    to: SocketAddr,
}

/// What the threads of a [`Relay`] share.
struct RelayShared {
    /// The socket the client sends to.
    front: Arc<UdpSocket>,
    server: SocketAddr,
    /// Where the client sends from, once it has sent.
    client: Mutex<Option<SocketAddr>>,
    /// The socket datagrams leave from for the server; a rebinding replaces it.
    outside: Mutex<Arc<UdpSocket>>,
    /// How long each datagram takes to pass, in either direction.
    delay: Duration,
    /// The delay line, while datagrams take time to pass.
    line: Mutex<Option<mpsc::Sender<Hop>>>,
    /// The number of datagrams from the server after which the client's next datagram leaves from a
    /// new outside socket.
    rebind_after: Option<usize>,
    /// Datagrams passed from the server to the client.
    passed_down: AtomicUsize,
    /// Where the relay sends the new outside address when it rebinds the client.
    rebound: Mutex<Option<mpsc::Sender<SocketAddr>>>,
    stop: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

/// A UDP relay between one client and a server, standing in for a NAT and a link: the client
/// sends to [`addr`](Self::addr), and the relay passes each datagram on from an outside socket
/// of its own, so the server takes that socket's address for the client's, and passes the
/// answers back.
struct Relay {
    addr: SocketAddr,
    outside: SocketAddr,
    shared: Arc<RelayShared>,
    rebound: mpsc::Receiver<SocketAddr>,
}

impl Relay {
    /// Creates a relay to `server` over a link that delays each datagram by `delay` each way.
    fn delayed(server: SocketAddr, delay: Duration) -> Self {
        Self::new(server, delay, None)
    }

    /// Creates a relay to `server` that, once it has passed `datagrams` datagrams from the server,
    /// moves the client to a new outside port as a NAT rebinding does: the client's next datagram
    /// leaves from there, and what the server sends to the old port is dropped.
    fn rebinding(server: SocketAddr, datagrams: usize) -> Self {
        Self::new(server, Duration::ZERO, Some(datagrams))
    }

    fn new(server: SocketAddr, delay: Duration, rebind_after: Option<usize>) -> Self {
        let front = relay_socket();
        let addr = front.local_addr().expect("a bound socket");
        let outside = Arc::new(relay_socket());
        let outside_addr = outside.local_addr().expect("a bound socket");
        let (line, hops) = mpsc::channel();
        let (rebound_tx, rebound) = mpsc::channel();
        let shared = Arc::new(RelayShared {
            front: Arc::new(front),
            server,
            client: Mutex::new(None),
            outside: Mutex::new(Arc::clone(&outside)),
            delay,
            line: Mutex::new((!delay.is_zero()).then_some(line)),
            rebind_after,
            passed_down: AtomicUsize::new(0),
            rebound: Mutex::new(Some(rebound_tx)),
            stop: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        });
        if !delay.is_zero() {
            shared.spawn(move || {
                for hop in hops {
                    std::thread::sleep(hop.due.saturating_duration_since(Instant::now()));
                    let _ = hop.via.send_to(&hop.data, hop.to);
                }
            });
        }
        let up = Arc::clone(&shared);
        shared.spawn(move || up.pass_up());
        shared.spawn_down(outside);
        Self {
            addr,
            outside: outside_addr,
            shared,
            rebound,
        }
    }

    /// Waits until the relay has moved the client to a new port, and returns that address.
    fn await_rebind(&self) -> SocketAddr {
        self.rebound
            .recv_timeout(WAIT)
            .expect("the relay rebinds the client")
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        relay_lock(&self.shared.line).take();
        loop {
            let threads = mem::take(&mut *relay_lock(&self.shared.threads));
            if threads.is_empty() {
                return;
            }
            for thread in threads {
                let _ = thread.join();
            }
        }
    }
}

impl RelayShared {
    fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        relay_lock(&self.threads).push(std::thread::spawn(f));
    }

    /// Passes the server's datagrams to `socket` on to the client, until `socket` is no longer
    /// the outside socket.
    fn spawn_down(self: &Arc<Self>, socket: Arc<UdpSocket>) {
        let shared = Arc::clone(self);
        self.spawn(move || {
            let mut buf = [0; 65_536];
            while !shared.stop.load(Ordering::SeqCst) {
                let Ok((len, _)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                // The mapping of a port the client was moved away from is gone.
                if !Arc::ptr_eq(&relay_lock(&shared.outside), &socket) {
                    continue;
                }
                let Some(client) = *relay_lock(&shared.client) else {
                    continue;
                };
                shared.pass(&buf[..len], &shared.front, client);
                shared.passed_down.fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    /// Passes the client's datagrams on to the server, moving the client to a new outside port
    /// once it is time.
    fn pass_up(self: &Arc<Self>) {
        let mut buf = [0; 65_536];
        while !self.stop.load(Ordering::SeqCst) {
            let Ok((len, from)) = self.front.recv_from(&mut buf) else {
                continue;
            };
            *relay_lock(&self.client) = Some(from);
            if self
                .rebind_after
                .is_some_and(|after| self.passed_down.load(Ordering::SeqCst) >= after)
                && let Some(rebound) = relay_lock(&self.rebound).take()
            {
                let socket = Arc::new(relay_socket());
                let _ = rebound.send(socket.local_addr().expect("a bound socket"));
                *relay_lock(&self.outside) = Arc::clone(&socket);
                self.spawn_down(socket);
            }
            let outside = Arc::clone(&relay_lock(&self.outside));
            self.pass(&buf[..len], &outside, self.server);
        }
    }

    /// Sends `data` from `via` to `to`, after the link's delay.
    fn pass(&self, data: &[u8], via: &Arc<UdpSocket>, to: SocketAddr) {
        if self.delay.is_zero() {
            let _ = via.send_to(data, to);
            return;
        }
        if let Some(line) = &*relay_lock(&self.line) {
            let _ = line.send(Hop {
                due: Instant::now() + self.delay,
                data: data.to_vec(),
                via: Arc::clone(via),
                to,
            });
        }
    }
}

/// Returns a loopback socket whose receives time out after [`RELAY_POLL`].
fn relay_socket() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    socket
        .set_read_timeout(Some(RELAY_POLL))
        .expect("a read timeout");
    socket
}

fn relay_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .expect("no relay thread panics while it holds a lock")
}

/// Returns transport settings for peers like [`sluggish`] ones that also pace: a window of ten
/// datagrams, which their acknowledgments do not open within a test, leaves at the pacer's rate.
fn sluggish_and_paced() -> Arc<TransportConfig> {
    TransportConfig::builder()
        .ack_policy(AckPolicy {
            before_init: 255,
            after_init: 255,
            max_ack_delay: Duration::from_secs(16),
            rtt_timer: false,
            ..AckPolicy::default()
        })
        .pacing(true)
        .pacing_min_burst(1)
        .build()
        .expect("a transport config")
}

#[test]
fn a_paced_sender_resumes_at_each_release_without_other_input() {
    // Eight datagrams each way, within the window, over a link with a round trip of 20 ms. At a
    // window per round trip and a minimum burst of 1, the pacer releases runs of one datagram
    // 1.6 ms apart, two of them at once after idle, and the sluggish peers do not acknowledge
    // them within the test, so only the pacing wake moves a sender on.
    const LEN: usize = 9_000;
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let mut relay = None;
    let pair = BulkPair::through(&harness, LEN, LEN, sluggish_and_paced(), |server| {
        let link = Relay::delayed(server, Duration::from_millis(10));
        let addr = link.addr;
        relay = Some(link);
        addr
    });
    let _link = relay.expect("the client connects through the relay");
    valves.client.clear();
    pair.go();
    await_reports_within(&pair.rx, vec![Report::Received(uni(2), LEN)], STALL);
    // A command runs between the driver's polls, so the client's last attempt has ended.
    harness.client_stats::<Bulk>();
    let attempts = valves
        .client
        .events()
        .iter()
        .filter(|&&event| event == Event::Attempt)
        .count();
    await_reports_within(&pair.rx, vec![Report::Received(uni(3), LEN)], STALL);
    // One attempt sends the burst and one each release; a driver that tried the client again
    // while its pacer held it back would make dozens.
    assert!(
        attempts <= 20,
        "the client made {attempts} transmit attempts for {LEN} paced bytes"
    );
    harness.shutdown();
}

/// A host's fine timer: a timerfd that counts its armings.
struct CountingFine {
    timer: TimerFd,
    arms: Arc<AtomicUsize>,
}

impl FineTimer for CountingFine {
    fn arm(&mut self, deadline: Instant) -> io::Result<()> {
        self.arms.fetch_add(1, Ordering::SeqCst);
        self.timer.arm(deadline)
    }

    fn disarm(&mut self) {
        let _ = self.timer.disarm();
    }

    fn deadline(&self) -> Option<Instant> {
        self.timer.deadline()
    }

    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.timer.poll_expired(cx)
    }
}

#[test]
fn a_paced_connections_wakes_reach_the_fine_timer_its_host_gives_the_driver() {
    // As in `a_paced_sender_resumes_at_each_release_without_other_input`, the server's releases
    // come 1.6 ms apart, inside the lead of a 1 ms wheel, so each ends on the fine timer.
    const LEN: usize = 9_000;
    let arms = Arc::new(AtomicUsize::new(0));
    let mut harness = Harness::new();
    let counted = Arc::clone(&arms);
    harness.server_timers = Some(Arc::new(move || {
        HostTimers::new(
            Duration::from_millis(1),
            Some(Box::new(CountingFine {
                timer: TimerFd::new().expect("a timerfd on the worker's reactor"),
                arms: Arc::clone(&counted),
            })),
        )
    }));
    let mut relay = None;
    let pair = BulkPair::through(&harness, 1, LEN, sluggish_and_paced(), |server| {
        let link = Relay::delayed(server, Duration::from_millis(10));
        let addr = link.addr;
        relay = Some(link);
        addr
    });
    let _link = relay.expect("the client connects through the relay");
    pair.go();
    await_reports_within(&pair.rx, vec![Report::Received(uni(3), LEN)], STALL);
    assert!(
        arms.load(Ordering::SeqCst) > 0,
        "the server's pacing wakes never reached its host's fine timer"
    );
    harness.shutdown();
}

/// An [`Echo`] server that also reports its connection's path events.
struct PathEcho(Echo);

impl QuicSession for PathEcho {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if matches!(event, ConnEvent::Path(_)) {
            let _ = self.0.reports.send(Report::Event("server", event.clone()));
        }
        self.0.on_event(conn, event);
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        self.0.on_stream(conn, id, ready);
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        self.0.poll_send(cx, id, sink)
    }

    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        self.0.poll_session(cx, conn)
    }
}

#[test]
fn an_echo_completes_across_a_nat_rebinding_of_its_client() {
    // About 870 datagrams each way, and the client moves to a new port once 200 have come back.
    const LEN: usize = 1_000_000;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr =
        harness.serve(move || App::new(move |_| Ok(PathEcho(Echo::new(server_reports.clone())))));
    let relay = Relay::rebinding(addr, 200);
    let _conn = harness.connect(relay.addr, move || PushClient::new(1, payload(LEN), tx));
    let moved_to = relay.await_rebind();
    assert_ne!(moved_to, relay.outside, "the client moved to another port");
    // The server validates the new address and sends there from then on.
    await_reports(
        &rx,
        vec![
            Report::Event(
                "server",
                ConnEvent::Path(PathEvent::Migrated { remote: moved_to }),
            ),
            Report::Echoed(client_bidi(0), true),
        ],
    );
    harness.shutdown();
}

#[test]
fn a_connect_through_the_handle_of_an_ended_driver_contains_a_panic_in_dropping_its_session() {
    let harness = Harness::new();
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve(|| App::<Fragile>::new(|_| Err(Refusal::Ignore)));
    harness
        .server
        .handle()
        .submit(|_| with_handle::<Fragile, _>(|handle| handle.quiesce(Duration::ZERO)))
        .expect("the server worker takes commands");
    harness.await_server_finished::<Fragile>();

    let (outcome_tx, outcome_rx) = mpsc::channel();
    let config = harness.client_config.clone();
    harness
        .server
        .handle()
        .submit(move |_| {
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                with_handle::<Fragile, _>(|handle| {
                    handle.connect(
                        addr,
                        ServerName::try_from("localhost").expect("a DNS name"),
                        config,
                        ConnOptions::default(),
                        Fragile {
                            recorder: Recorder {
                                name: "late",
                                reports: tx,
                            },
                            panics: true,
                        },
                    )
                })
            }));
            let outcome = match attempt {
                Ok(Err(DriverConnectError::Io(error))) => Ok(error.kind()),
                Ok(_) => Err("the connect did not fail with an I/O error"),
                Err(_) => Err("the session's drop panicked out of connect"),
            };
            let _ = outcome_tx.send(outcome);
        })
        .expect("the server worker takes commands");
    assert_eq!(
        outcome_rx.recv_timeout(WAIT).expect("the server answers"),
        Ok(io::ErrorKind::NotConnected)
    );
    harness.shutdown();
}

#[test]
fn a_connection_id_the_server_issues_after_the_handshake_routes_to_its_connection() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);
    let deadline = Instant::now() + WAIT;
    let issued = loop {
        let (ids_tx, ids_rx) = mpsc::channel();
        harness
            .server
            .handle()
            .submit(move |_| {
                let _ = ids_tx.send(with_handle::<Recorder, _>(|handle| handle.issued_cids()));
            })
            .expect("the server worker takes commands");
        if let Some(&cid) = ids_rx
            .recv_timeout(WAIT)
            .expect("the server answers")
            .first()
        {
            break cid;
        }
        assert!(
            Instant::now() < deadline,
            "the server issued no connection ID beyond the handshake's"
        );
        std::thread::yield_now();
    };
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");

    // The connection drops a probe to its own ID as undecryptable, and the endpoint answers the
    // control, an ID that was never issued, with a reset. Both reach the server in one receive
    // batch, so a reset for the probe, 29 bytes, would come back first; the control's is 43 bytes.
    let mut probe = vec![0x40];
    probe.extend_from_slice(&issued);
    probe.resize(30, 0xee);
    let blocked = Harness::block(&harness.server);
    peer.send_to(&probe, addr).expect("the datagram goes out");
    peer.send_to(&short_header(0xee, 100), addr)
        .expect("the datagram goes out");
    drop(blocked);

    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a stateless reset comes back");
    assert_eq!(from, addr);
    assert_eq!(
        len, 43,
        "the probe to an issued connection ID drew a reset: the ID does not route"
    );
    harness.shutdown();
}

#[test]
fn a_server_driver_accepts_on_a_socket_opened_before_it() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let (bound_tx, bound_rx) = mpsc::channel();
    let (endpoint, config) = (harness.endpoint.clone(), harness.server_config.clone());
    harness
        .server
        .handle()
        .submit(move |worker| {
            let backend =
                MmsgBackend::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &mmsg_options())
                    .expect("a server socket");
            let addr = Backend::local_addr(&backend).expect("the socket is bound");
            let handle = EndpointDriver::<_, MmsgBackend>::builder(
                endpoint,
                recording_server(server_reports),
            )
            .serve(backend, config)
            .spawn(worker)
            .expect("the server driver starts");
            let _ = bound_tx.send((addr, handle.local_addr()));
            HANDLES.with(|handles| handles.borrow_mut().push(Box::new(handle)));
        })
        .expect("the server worker takes commands");
    let (addr, served) = bound_rx
        .recv_timeout(WAIT)
        .expect("the server driver starts");
    assert_eq!(
        served,
        Some(addr),
        "the driver serves on the socket it was given"
    );
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(
        &rx,
        vec![
            Report::Event("client", ConnEvent::Connected),
            Report::Event("server", ConnEvent::Connected),
        ],
    );
    harness.shutdown();
}

/// A [`Recorder`] that also reports its drop.
struct DropReporting(Recorder);

impl Drop for DropReporting {
    fn drop(&mut self) {
        let _ = self.0.reports.send(Report::Dropped(self.0.name));
    }
}

impl QuicSession for DropReporting {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        self.0.on_event(conn, event);
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[test]
fn an_aborted_driver_drops_its_sessions_without_closing_and_finishes() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(DropReporting(Recorder {
                name: "server",
                reports: server_reports.clone(),
            }))
        })
    });
    let _conn = harness.connect(addr, move || Recorder {
        name: "client",
        reports: tx,
    });
    await_reports(&rx, vec![Report::Event("server", ConnEvent::Confirmed)]);
    harness
        .server
        .handle()
        .submit(|_| with_handle::<DropReporting, _>(|handle| handle.abort()))
        .expect("the server worker takes commands");
    let others = await_reports(&rx, vec![Report::Dropped("server")]);
    assert!(
        !others
            .iter()
            .any(|report| matches!(report, Report::Event("server", ConnEvent::Closed { .. }))),
        "an abort sends no close: {others:?}"
    );
    harness.await_server_finished::<DropReporting>();
    harness.shutdown();
}

/// Server drivers on workers of their own that share one loopback address and steer new
/// connections as one group: their sockets bound in worker order, so that index `i` of the
/// SO_REUSEPORT group is worker `i`, with the kernel's steering program attached.
struct Steered {
    workers: Vec<ManagedWorker>,
    addr: SocketAddr,
    group: Arc<Steering>,
}

impl Steered {
    /// Starts `count` drivers with the configs and limits of `harness`, each with the
    /// application `make` builds for its worker index.
    fn start<S: QuicSession>(
        harness: &Harness,
        count: u16,
        make: impl Fn(u16) -> App<S> + Clone + Send + 'static,
    ) -> Self {
        // The workers' sockets share one address, so they keep the default SO_REUSEPORT.
        let options = MmsgOptions::default();
        let open = |addr| mvfstr_io::socket::open(addr, None, &options.socket).expect("a socket");
        let first = open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let addr = first
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_socket())
            .expect("an IP address");
        let mut sockets = vec![first];
        sockets.extend((1..count).map(|_| open(addr)));
        mvfstr_io::socket::steer_by_connection_id(&sockets[0], count)
            .expect("the steering program attaches");
        let group = Steering::new(count);
        let (tx, rx) = mpsc::channel();
        let workers = sockets
            .into_iter()
            .zip(0..count)
            .map(|(socket, index)| {
                let worker = ManagedWorker::new(64).expect("a server worker");
                let (endpoint, config) = (harness.endpoint.clone(), harness.server_config.clone());
                let (limits, options, group) =
                    (harness.limits, options.clone(), Arc::clone(&group));
                let (make, tx) = (make.clone(), tx.clone());
                worker
                    .handle()
                    .submit(move |context| {
                        let backend =
                            MmsgBackend::from_socket(socket, &options).expect("a backend");
                        let handle =
                            EndpointDriver::<_, MmsgBackend>::builder(endpoint, make(index))
                                .serve(backend, config)
                                .worker(index, count)
                                .steering(group)
                                .backend_options(options)
                                .limits(limits)
                                .spawn(context)
                                .expect("the server driver starts");
                        HANDLES.with(|handles| handles.borrow_mut().push(Box::new(handle)));
                        let _ = tx.send(());
                    })
                    .expect("the server worker takes commands");
                worker
            })
            .collect();
        for _ in 0..count {
            rx.recv_timeout(WAIT).expect("every server driver starts");
        }
        Self {
            workers,
            addr,
            group,
        }
    }

    /// Returns the counters of worker `index`'s driver for sessions of type `S`.
    fn stats<S: QuicSession>(&self, index: usize) -> crate::EndpointStats {
        Harness::<MmsgBackend>::stats::<S>(&self.workers[index])
    }

    fn shutdown(self) {
        for worker in self.workers {
            worker
                .shutdown()
                .expect("the server worker shuts down cleanly");
        }
    }
}

/// Returns a server application for worker `index` that reports each connection it accepts, and
/// whose sessions report their events as `server`.
fn steered_app(index: u16, reports: mpsc::Sender<Report>) -> App<Recorder> {
    App::new(move |info| {
        let _ = reports.send(Report::AcceptedOn(index, info.remote));
        Ok(Recorder {
            name: "server",
            reports: reports.clone(),
        })
    })
}

/// Returns whether a socket that sets SO_REUSEPORT can bind `addr` too, which Linux allows only
/// when the socket that holds `addr` set it as well.
fn shares_its_port(addr: SocketAddr) -> bool {
    let options = SocketOptions {
        reuse_port: true,
        ..SocketOptions::default()
    };
    match mvfstr_io::socket::open(addr, None, &options) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => false,
        Err(error) => panic!("binding {addr} failed: {error}"),
    }
}

#[test]
fn only_test_servers_that_ask_for_so_reuseport_share_their_port() {
    let harness = Harness::new();
    let (tx, _rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    assert!(!shares_its_port(addr), "a harness server shares its port");

    let servers = Steered::start(&harness, 2, move |index| steered_app(index, tx.clone()));
    assert!(
        shares_its_port(servers.addr),
        "a steered group does not share its port"
    );
    servers.shutdown();
    harness.shutdown();
}

#[test]
fn socket_settings_that_tests_build_leave_so_reuseport_off() {
    for (what, options) in [
        ("one datagram per batch", one_datagram_per_batch()),
        ("kernel release", kernel_release(Duration::from_millis(5))),
    ] {
        assert!(!options.socket.reuse_port, "{what}");
    }
}

#[test]
fn new_connections_from_distinct_sockets_spread_exactly_evenly_over_steered_workers() {
    const WORKERS: u16 = 4;
    const CONNECTIONS: usize = 32;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let servers = Steered::start(&harness, WORKERS, {
        let tx = tx.clone();
        move |index| steered_app(index, tx.clone())
    });
    // Each connection has a connected socket of its own, and a first destination connection ID
    // that sends its Initial to a random worker.
    let (conns, _) = harness.connect_all(servers.addr, CONNECTIONS, move || Recorder {
        name: "client",
        reports: tx.clone(),
    });
    let others = await_reports(
        &rx,
        (0..CONNECTIONS)
            .flat_map(|_| {
                [
                    Report::Event("client", ConnEvent::Confirmed),
                    Report::Event("server", ConnEvent::Confirmed),
                ]
            })
            .collect(),
    );
    let mut accepted = [0; WORKERS as usize];
    for report in &others {
        if let Report::AcceptedOn(index, _) = report {
            accepted[usize::from(*index)] += 1;
        }
    }
    assert_eq!(
        accepted,
        [CONNECTIONS / usize::from(WORKERS); WORKERS as usize],
        "connections accepted per worker"
    );
    drop(conns);
    harness.shutdown();
    servers.shutdown();
}

/// Returns the datagrams one transmit attempt of `conn` builds at `now`.
fn transmit(conn: &mut Connection, now: Instant) -> Vec<Vec<u8>> {
    let mut sink = VecSink::new(1500);
    let limits = TxLimits {
        now,
        max_segments: 1,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: None,
    };
    conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    sink.take().into_iter().map(|sent| sent.data).collect()
}

/// Returns a client connection to `addr`, run by the test rather than a driver, whose first
/// destination connection ID starts with a byte for which `wanted` holds, and the datagram of its
/// first Initial.
fn client_initial(
    harness: &Harness,
    addr: SocketAddr,
    wanted: impl Fn(u8) -> bool,
) -> (Connection, Vec<u8>) {
    let now = Instant::now();
    (1..)
        .find_map(|seed| {
            let mut endpoint = Endpoint::new(harness.endpoint.clone(), None);
            let mut rng = TestRng::new(seed);
            let mut inputs = Inputs {
                now,
                unix_now: UnixTime::now(),
                rng: &mut rng,
            };
            let key = ConnKey {
                index: 0,
                generation: 0,
            };
            let server_name = ServerName::try_from("localhost").expect("a DNS name");
            let mut conn = endpoint
                .connect(
                    &mut inputs,
                    key,
                    addr,
                    server_name,
                    &harness.client_config,
                    ConnOptions::default(),
                )
                .expect("a client connection");
            let first = transmit(&mut conn, now).swap_remove(0);
            // A long header: the destination connection ID's length at offset 5, the ID from 6.
            wanted(first[6]).then_some((conn, first))
        })
        .expect("some seed gives a wanted ID")
}

/// Returns the datagram `conn` sends again when its first probe timeout fires.
fn retransmission(conn: &mut Connection) -> Vec<u8> {
    let at = conn.next_deadline().expect("a probe timeout");
    conn.on_deadline(at);
    transmit(conn, at).swap_remove(0)
}

/// Returns the first byte of the source connection ID of the long header that starts `datagram`.
fn source_cid_first_byte(datagram: &[u8]) -> u8 {
    let dcid_len = usize::from(datagram[5]);
    datagram[7 + dcid_len]
}

/// Waits until worker `index` of `servers` has taken `count` datagrams from other workers,
/// failing if any server application reports an accept before that turn of worker `index` ends.
fn await_steered_in(servers: &Steered, rx: &mpsc::Receiver<Report>, index: usize, count: u64) {
    let deadline = Instant::now() + WAIT;
    let accepted = || {
        rx.try_iter()
            .find(|report| matches!(report, Report::AcceptedOn(..)))
    };
    while servers.stats::<Recorder>(index).steered_in < count {
        if let Some(report) = accepted() {
            panic!("waiting for worker {index} to take {count} datagrams, saw {report:?}");
        }
        assert!(
            Instant::now() < deadline,
            "worker {index} never took {count} datagrams"
        );
        std::thread::yield_now();
    }
    // The stats command ran after the turn that took the last datagram, which routes what it
    // takes in the same turn, so an accept that datagram caused has been reported by now.
    if let Some(report) = accepted() {
        panic!("worker {index} took {count} datagrams and accepted again: {report:?}");
    }
}

#[test]
fn a_retransmitted_first_initial_reaches_the_worker_that_accepted_the_connection() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let servers = Steered::start(&harness, 2, move |index| steered_app(index, tx.clone()));
    // The kernel sends an Initial whose ID starts with an odd byte to worker 1, and the group's
    // first new connection goes to worker 0.
    let (mut client, first) = client_initial(&harness, servers.addr, |byte| byte % 2 == 1);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");
    let from = peer.local_addr().expect("a bound socket");
    peer.send_to(&first, servers.addr)
        .expect("the datagram goes out");
    assert_eq!(
        rx.recv_timeout(WAIT).expect("a server accepts"),
        Report::AcceptedOn(0, from)
    );
    let mut reply = [0; 1500];
    let (len, source) = peer.recv_from(&mut reply).expect("the server answers");
    assert_eq!(
        source, servers.addr,
        "the answer comes from the server address"
    );
    assert_eq!(
        source_cid_first_byte(&reply[..len]) % 2,
        0,
        "the answering connection's ID names worker 0"
    );

    let again = retransmission(&mut client);
    assert_eq!(
        again[1..14],
        first[1..14],
        "the same version and destination connection ID"
    );
    peer.send_to(&again, servers.addr)
        .expect("the datagram goes out");
    await_steered_in(&servers, &rx, 0, 2);
    assert_eq!(servers.stats::<Recorder>(1).steered_out, 2);
    harness.shutdown();
    servers.shutdown();
}

/// The length of a client's first Initial in these tests, which fills the smallest datagram that
/// may carry it.
const FIRST_INITIAL: usize = 1200;

#[test]
fn a_datagram_handed_to_a_full_inbox_is_dropped_and_counted() {
    const KEPT: usize = 3;
    let mut harness = Harness::new();
    harness.limits.waiting_initial_bytes = KEPT * FIRST_INITIAL;
    let (tx, rx) = mpsc::channel();
    let servers = Steered::start(&harness, 2, move |index| steered_app(index, tx.clone()));
    // Worker 0 does not run a turn while blocked, so what it is handed stays in its inbox.
    let blocked = Harness::block(&servers.workers[0]);
    let (_client, first) = client_initial(&harness, servers.addr, |byte| byte % 2 == 1);
    assert_eq!(first.len(), FIRST_INITIAL);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let from = peer.local_addr().expect("a bound socket");
    // The kernel delivers every copy to worker 1, which hands the first to worker 0, the group's
    // first new connection, and every copy after it to the same worker, whose inbox holds the
    // bytes of three.
    let capacity = KEPT as u64;
    for sent in 1..=capacity {
        peer.send_to(&first, servers.addr)
            .expect("the datagram goes out");
        let deadline = Instant::now() + WAIT;
        while servers.stats::<Recorder>(1).steered_out < sent {
            assert!(
                Instant::now() < deadline,
                "worker 1 never handed off copy {sent}"
            );
            std::thread::yield_now();
        }
    }
    peer.send_to(&first, servers.addr)
        .expect("the datagram goes out");
    // The group's next new connection goes to worker 1, which receives datagrams in order, so
    // once it accepts this one it has dealt with the copy sent before.
    let (_other, second) = client_initial(&harness, servers.addr, |byte| {
        byte % 2 == 1 && byte != first[6]
    });
    peer.send_to(&second, servers.addr)
        .expect("the datagram goes out");
    let deadline = Instant::now() + WAIT;
    while rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .expect("worker 1 accepts the second connection")
        != Report::AcceptedOn(1, from)
    {}
    let stats = servers.stats::<Recorder>(1);
    assert_eq!(
        (stats.steered_out, stats.dropped_initials),
        (capacity, 1),
        "the copy that finds worker 0's inbox full is dropped and counted"
    );
    drop(blocked);
    harness.shutdown();
    servers.shutdown();
}

#[test]
fn datagrams_handed_to_a_worker_beyond_those_it_can_keep_waiting_are_dropped_and_counted() {
    const KEPT: u64 = 4;
    const HANDED: u64 = 6;
    let mut harness = Harness::new();
    harness.limits.waiting_initial_bytes = KEPT as usize * FIRST_INITIAL;
    let (tx, _rx) = mpsc::channel();
    let servers = Steered::start(&harness, 2, move |index| steered_app(index, tx.clone()));
    let blocked = Harness::block(&servers.workers[0]);
    let (_client, first) = client_initial(&harness, servers.addr, |byte| byte % 2 == 1);
    assert_eq!(first.len(), FIRST_INITIAL);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    // Worker 1 hands every copy to worker 0, as above. Worker 0's inbox has the bound of its
    // waiting queue, so it takes the bytes of four copies, and worker 1 drops the rest.
    for sent in 1..=HANDED {
        peer.send_to(&first, servers.addr)
            .expect("the datagram goes out");
        let deadline = Instant::now() + WAIT;
        while {
            let stats = servers.stats::<Recorder>(1);
            stats.steered_out + stats.dropped_initials < sent
        } {
            assert!(
                Instant::now() < deadline,
                "worker 1 never dealt with copy {sent}"
            );
            std::thread::yield_now();
        }
    }
    let stats = servers.stats::<Recorder>(1);
    assert_eq!(
        (stats.steered_out, stats.dropped_initials),
        (KEPT, HANDED - KEPT),
        "the copies past the inbox's bytes are dropped and counted by the worker that hands off"
    );
    // Worker 0's next turn takes its whole inbox into its empty waiting queue, which has room for
    // all of it.
    drop(blocked);
    let deadline = Instant::now() + WAIT;
    let stats = loop {
        let stats = servers.stats::<Recorder>(0);
        if stats.steered_in >= KEPT {
            break stats;
        }
        assert!(Instant::now() < deadline, "worker 0 never took its inbox");
        std::thread::yield_now();
    };
    assert_eq!(
        (stats.steered_in, stats.dropped_initials),
        (KEPT, 0),
        "what fits the inbox fits the waiting queue"
    );
    harness.shutdown();
    servers.shutdown();
}

/// Builds a 0-RTT packet with the connection IDs of `initial`, a client's first Initial. Its
/// payload is not encrypted, since routing depends only on the header.
fn zero_rtt_like(initial: &[u8]) -> Vec<u8> {
    let dcid_len = usize::from(initial[5]);
    let scid_len = usize::from(initial[6 + dcid_len]);
    // Long header, fixed bit and type 0-RTT, then the Initial's version and connection IDs.
    let mut datagram = vec![0xd0];
    datagram.extend_from_slice(&initial[1..7 + dcid_len + scid_len]);
    // A two-byte Length of 40, a packet number and payload.
    datagram.extend_from_slice(&[0x40, 40]);
    datagram.resize(datagram.len() + 40, 0x33);
    datagram
}

#[test]
fn a_zero_rtt_packet_for_a_handed_off_id_follows_the_first_initial() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let servers = Steered::start(&harness, 2, move |index| steered_app(index, tx.clone()));
    // Worker 1 receives the Initial and hands it to worker 0, as above.
    let (_client, first) = client_initial(&harness, servers.addr, |byte| byte % 2 == 1);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let from = peer.local_addr().expect("a bound socket");
    peer.send_to(&first, servers.addr)
        .expect("the datagram goes out");
    assert_eq!(
        rx.recv_timeout(WAIT).expect("a server accepts"),
        Report::AcceptedOn(0, from)
    );
    // Sent before the server's first Initial reaches the client, 0-RTT carries the client's first
    // destination connection ID, as RFC 9000 requires.
    peer.send_to(&zero_rtt_like(&first), servers.addr)
        .expect("the datagram goes out");
    await_steered_in(&servers, &rx, 0, 2);
    harness.shutdown();
    servers.shutdown();
}

#[test]
fn handed_off_ids_are_remembered_as_long_as_the_transport_an_application_accepts_with_allows() {
    let harness = Harness::new();
    let (tx, _rx) = mpsc::channel();
    let idle = Duration::from_secs(120);
    let transport = Arc::new(
        TransportConfig::builder()
            .idle_timeout(Some(idle))
            .build()
            .expect("transport settings"),
    );
    let servers = Steered::start(&harness, 2, move |index| {
        let mut app = steered_app(index, tx.clone());
        app.transport = Some(Arc::clone(&transport));
        app
    });
    assert_eq!(
        servers.group.lifetime(),
        handoff_lifetime(harness.server_config.transport()),
        "before any connection, the servers' own settings decide"
    );
    let (_client, first) = client_initial(&harness, servers.addr, |_| true);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(WAIT)).expect("a read timeout");
    peer.send_to(&first, servers.addr)
        .expect("the datagram goes out");
    // The server answers once it has accepted the connection.
    peer.recv_from(&mut [0; 1500]).expect("the server answers");
    assert_eq!(
        servers.group.lifetime(),
        Some(idle),
        "the accepted connection can wait for its client as long as its own idle timeout"
    );
    harness.shutdown();
    servers.shutdown();
}

#[test]
fn a_steered_driver_that_is_not_a_server_worker_of_its_group_does_not_start() {
    let harness = Harness::new();
    let (endpoint, config) = (harness.endpoint.clone(), harness.server_config.clone());
    let (tx, rx) = mpsc::channel();
    harness
        .server
        .handle()
        .submit(move |worker| {
            let builder = || {
                EndpointDriver::<_, MmsgBackend>::builder(
                    endpoint.clone(),
                    App::<Recorder>::client(),
                )
            };
            let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let socket = || MmsgBackend::bind(server, &mmsg_options()).expect("a socket");
            let refused = [
                // Worker 0 of 2 in a group of 3.
                builder()
                    .serve(socket(), config.clone())
                    .worker(0, 2)
                    .steering(Steering::new(3))
                    .spawn(worker),
                // Without a worker index.
                builder()
                    .serve(socket(), config.clone())
                    .steering(Steering::new(2))
                    .spawn(worker),
                // Without a server socket.
                builder()
                    .worker(0, 2)
                    .steering(Steering::new(2))
                    .spawn(worker),
                // A server socket the driver binds by itself, which cannot have joined the
                // group in worker order with the steering program attached.
                builder()
                    .bind_server(server, config.clone())
                    .worker(0, 2)
                    .steering(Steering::new(2))
                    .spawn(worker),
            ]
            .map(|started| {
                matches!(
                    started,
                    Err(DriverError::Config(ConfigError::OutOfRange {
                        field: "steering"
                    }))
                )
            });
            let _ = tx.send(refused);
        })
        .expect("the server worker takes commands");
    assert_eq!(
        rx.recv_timeout(WAIT).expect("the worker answers"),
        [true; 4],
        "which drivers were refused"
    );
    harness.shutdown();
}

/// A server session that echoes as [`Echo`] does and reports, once its connection has drained,
/// how many packets the connection sent.
struct Counted {
    echo: Echo,
    reports: mpsc::Sender<Report>,
}

impl QuicSession for Counted {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event == ConnEvent::Drained {
            let _ = self
                .reports
                .send(Report::SentPackets(conn.stats().sent_packets));
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        self.echo.on_stream(conn, id, ready);
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[test]
fn the_driver_counts_the_packets_and_datagrams_its_connections_send() {
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        App::new(move |_| {
            Ok(Counted {
                echo: Echo::new(server_reports.clone()),
                reports: server_reports.clone(),
            })
        })
    });
    // Echoes long enough for GSO sends of several segments.
    let conn = harness.connect(addr, move || PushClient::new(2, payload(30_000), tx));
    await_reports(
        &rx,
        vec![
            Report::Echoed(client_bidi(0), true),
            Report::Echoed(client_bidi(1), true),
        ],
    );
    conn.close(AppCode::from_u32(0), Bytes::new())
        .expect("the connection is live");
    // The server's connection drains without sending, and its slot is freed in the application
    // phase that delivers `Drained`.
    let sent = loop {
        match rx.recv_timeout(WAIT) {
            Ok(Report::SentPackets(sent)) => break sent,
            Ok(_) => {}
            Err(_) => panic!("the server's connection never drained"),
        }
    };
    let stats = harness.server_stats::<Counted>();
    assert_eq!(
        stats.sent_packets, sent,
        "the packets of the server's one connection"
    );
    assert_eq!(
        stats.sent_datagrams,
        valves.server.datagrams() as u64,
        "the datagrams the server socket was handed"
    );
    assert!(
        stats.sent_datagrams > 0 && stats.sent_datagrams <= stats.sent_packets,
        "{stats:?}"
    );
    harness.shutdown();
}

/// Bytes an [`Answer`] session sends back, in one packet.
const ANSWER: usize = 100;

/// A server session that answers its peer's unidirectional stream, once it finishes, with
/// [`ANSWER`] bytes and the FIN on a unidirectional stream of its own, and then moves its own
/// deadline a second earlier. The deadline starts 10 s after the accept, before any of a sluggish
/// connection's, so it is the connection's.
struct Answer {
    deadline: Instant,
    answered: bool,
}

impl QuicSession for Answer {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        read_all(conn, id);
        if ready == StreamReady::Finished && !self.answered {
            self.answered = true;
            let reply = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
            let mut queue = VecDeque::from([payload(ANSWER)]);
            assert!(
                push_all(conn, reply, &mut queue, true),
                "the stream takes it all"
            );
            self.deadline -= Duration::from_secs(1);
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }
}

/// Returns, on the server worker, the counters of its driver for [`Answer`] sessions and the ACK
/// frames each of its connections has received.
fn answer_counters() -> (crate::EndpointStats, Vec<u64>) {
    with_backend_handle::<Answer, Gated, _>(|handle| {
        let acks = handle
            .conn_stats()
            .iter()
            .map(|stats| stats.acks_received)
            .collect();
        (handle.stats(), acks)
    })
}

#[test]
fn two_connections_whose_packets_leave_in_one_flush_move_each_counter_as_expected() {
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: MmsgOptions::default(),
        valves: Arc::clone(&valves),
    });
    let transport = sluggish();
    let server_transport = Arc::clone(&transport);
    let addr = harness.serve(move || {
        let mut app = App::new(|_| {
            Ok(Answer {
                deadline: Instant::now() + Duration::from_secs(10),
                answered: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let (tx, rx) = mpsc::channel();
    let go = Arc::new(AtomicBool::new(false));
    let conns: Vec<ConnHandle> = (0..2)
        .map(|_| {
            let (go, tx) = (Arc::clone(&go), tx.clone());
            harness.connect_with(
                addr,
                ConnOptions {
                    transport: Some(Arc::clone(&transport)),
                },
                move || Bulk::new("client", 50, Some(go), tx),
            )
        })
        .collect();
    await_reports(
        &rx,
        vec![
            Report::Event("client", ConnEvent::Confirmed),
            Report::Event("client", ConnEvent::Confirmed),
        ],
    );

    // The server worker reads the counters and then blocks, so that the clients' datagrams wait
    // for one turn on its socket.
    let (counted_tx, counted_rx) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    harness
        .server
        .handle()
        .submit(move |_| {
            let _ = counted_tx.send(answer_counters());
            let _ = released.recv();
        })
        .expect("the server worker takes commands");
    let (before, acks_before) = counted_rx.recv_timeout(WAIT).expect("the server blocks");
    let client_before = harness.client_stats::<Bulk>();
    let handed = valves.client.datagrams();
    go.store(true, Ordering::SeqCst);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    let deadline = Instant::now() + WAIT;
    while valves.client.datagrams() < handed + 2 {
        assert!(Instant::now() < deadline, "the clients never sent");
        std::thread::yield_now();
    }
    // A command runs between the client driver's turns, so the turn that sent has flushed.
    harness.client_stats::<Bulk>();
    drop(release);
    await_reports(
        &rx,
        vec![
            Report::Received(uni(3), ANSWER),
            Report::Received(uni(3), ANSWER),
        ],
    );

    let (counted_tx, counted_rx) = mpsc::channel();
    harness
        .server
        .handle()
        .submit(move |_| {
            let _ = counted_tx.send(answer_counters());
        })
        .expect("the server worker takes commands");
    let (after, acks_after) = counted_rx.recv_timeout(WAIT).expect("the server answers");
    let moved = |name, counter: fn(&crate::EndpointStats) -> u64| {
        (name, counter(&after) - counter(&before))
    };
    assert_eq!(
        [
            moved("sent_datagrams", |s| s.sent_datagrams),
            moved("sendmmsg_calls", |s| s.sendmmsg_calls),
            moved("sendmmsg_messages", |s| s.sendmmsg_messages),
            moved("multi_connection_calls", |s| s.multi_connection_calls),
            moved("gso_retries", |s| s.gso_retries),
            moved("gso_disabled", |s| s.gso_disabled),
            moved("recv_batch_calls", |s| s.recv_batch_calls),
            moved("receive_passes", |s| s.receive_passes),
            moved("deadline_rearms", |s| s.deadline_rearms),
        ],
        [
            ("sent_datagrams", 2),
            ("sendmmsg_calls", 1),
            ("sendmmsg_messages", 2),
            ("multi_connection_calls", 1),
            ("gso_retries", 0),
            ("gso_disabled", 0),
            ("recv_batch_calls", 2),
            ("receive_passes", 2),
            ("deadline_rearms", 2),
        ],
        "one receive batch with a datagram from each client, one pass over each connection, \
         each session's deadline moved once, and both answers in one call"
    );
    let acks: Vec<u64> = acks_after
        .iter()
        .zip(&acks_before)
        .map(|(after, before)| after - before)
        .collect();
    assert_eq!(
        acks,
        vec![1, 1],
        "each client's packet carried one ACK frame"
    );

    // Each client connection sends and receives on its own socket.
    let client_after = harness.client_stats::<Bulk>();
    let moved = |name, counter: fn(&crate::EndpointStats) -> u64| {
        (name, counter(&client_after) - counter(&client_before))
    };
    assert_eq!(
        [
            moved("sendmmsg_calls", |s| s.sendmmsg_calls),
            moved("sendmmsg_messages", |s| s.sendmmsg_messages),
            moved("multi_connection_calls", |s| s.multi_connection_calls),
            moved("recv_batch_calls", |s| s.recv_batch_calls),
            moved("receive_passes", |s| s.receive_passes),
        ],
        [
            ("sendmmsg_calls", 2),
            ("sendmmsg_messages", 2),
            ("multi_connection_calls", 0),
            ("recv_batch_calls", 2),
            ("receive_passes", 2),
        ],
        "each client's datagram in a call of its own, and each answer in a receive batch of its own"
    );
    harness.shutdown();
}

#[test]
fn a_backlog_the_server_socket_sends_when_polled_writable_is_counted_with_its_flush() {
    let ping = GatedPing::new();
    let before = ping.harness.server_stats::<Echo>();
    // The flush of the echo meets an EAGAIN, and the poll for writability right after it sends
    // the echo.
    ping.valves.server.block_next_flush_until_polled();
    ping.ping();
    ping.await_echo(0);
    // Nothing else makes the sluggish server flush again before this runs.
    let after = ping.harness.server_stats::<Echo>();
    let events = ping.valves.server.events();
    assert!(
        events.contains(&Event::SentAtPoll),
        "the poll sent nothing: {events:?}"
    );
    assert_eq!(
        (
            after.sendmmsg_calls - before.sendmmsg_calls,
            after.sendmmsg_messages - before.sendmmsg_messages,
        ),
        (1, 1),
        "the poll's call that sent the echo"
    );
    ping.harness.shutdown();
}

#[test]
fn the_gso_counts_of_the_server_socket_reach_the_endpoint_counters() {
    let ping = GatedPing::new();
    let before = ping.harness.server_stats::<Echo>();
    // The socket counts three GSO retries and one disable, which the flush of the echo takes.
    ping.valves.server.count_gso(3, 1);
    ping.ping();
    ping.await_echo(0);
    let after = ping.harness.server_stats::<Echo>();
    assert_eq!(
        (
            after.gso_retries - before.gso_retries,
            after.gso_disabled - before.gso_disabled,
        ),
        (3, 1),
        "the socket's retries and disable, each in its own counter"
    );
    ping.harness.shutdown();
}

#[test]
fn a_finished_drivers_handle_keeps_its_last_counters() {
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || PushClient::new(1, payload(1_000), tx));
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    let running = harness.server_stats::<Echo>();
    assert!(
        running.turns > 0 && running.sent_packets > 0 && running.sent_datagrams > 0,
        "{running:?}"
    );

    harness
        .server
        .handle()
        .submit(|_| with_handle::<Echo, _>(|handle| handle.quiesce(Duration::ZERO)))
        .expect("the server worker takes commands");
    harness.await_server_finished::<Echo>();
    let finished = harness.server_stats::<Echo>();
    assert!(
        finished.turns >= running.turns
            && finished.sent_packets >= running.sent_packets
            && finished.sent_datagrams >= running.sent_datagrams,
        "the counters once the driver finished: {finished:?}; while it ran: {running:?}"
    );
    harness.shutdown();
}

/// Requests that one client datagram carries, each a short GET.
const BURST: u32 = 21;

/// A 20-byte response, small enough that the responses to a whole burst fit in one packet.
const RESPONSE: &[u8] = b"twenty-byte response";

/// A server session that answers each request with [`RESPONSE`] and the FIN through the pull
/// path once the request's FIN arrives, as `respond_now` does in an HTTP/3 session: the end of
/// the request fires its stream's waker. It reports the driver's counters as the first request
/// opens, and the driver turn of each poll.
struct Responder {
    reports: mpsc::Sender<Report>,
    counted: bool,
}

impl QuicSession for Responder {
    fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        match ready {
            StreamReady::Opened if !self.counted => {
                self.counted = true;
                let stats = with_handle::<Responder, _>(|handle| handle.stats());
                let _ = self.reports.send(Report::Counters(stats));
            }
            StreamReady::Readable | StreamReady::Finished => {
                read_all(conn, id);
                if ready == StreamReady::Finished {
                    conn.stream_waker(id).wake();
                }
            }
            _ => {}
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::PolledInTurn(current_turn::<Responder>()));
        sink.push(Bytes::from_static(RESPONSE))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client session that, once the test thread sets `go` and wakes it, sends a short request
/// and the FIN on each of [`BURST`] new streams at once through the push path, so one datagram
/// carries them all, and reports each response that comes back whole.
struct Requester {
    reports: mpsc::Sender<Report>,
    go: Arc<AtomicBool>,
    sent: bool,
    received: HashMap<StreamId, Vec<u8>>,
}

impl QuicSession for Requester {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let received = self.received.entry(id).or_default();
        for segment in read_all(conn, id) {
            received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self.reports.send(Report::Echoed(id, received == RESPONSE));
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.go.load(Ordering::SeqCst) && !self.sent {
            self.sent = true;
            for _ in 0..BURST {
                let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
                let mut request = VecDeque::from([Bytes::from_static(b"GET /baseline2")]);
                assert!(
                    push_all(conn, id, &mut request, true),
                    "the stream takes the request"
                );
            }
        }
        Poll::Pending
    }
}

#[test]
fn a_burst_of_small_responses_leaves_in_one_packet_in_one_turn() {
    let harness = Harness::new();
    // Sluggish peers do not send an acknowledgment alone within the test, so the server sends only
    // its responses, with the acknowledgment of the requests riding along.
    let transport = sluggish();
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let server_transport = Arc::clone(&transport);
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| {
            Ok(Responder {
                reports: server_reports.clone(),
                counted: false,
            })
        });
        app.transport = Some(server_transport);
        app
    });
    let go = Arc::new(AtomicBool::new(false));
    let session_go = Arc::clone(&go);
    let conn = harness.connect_with(
        addr,
        ConnOptions {
            transport: Some(transport),
        },
        move || Requester {
            reports: tx,
            go: session_go,
            sent: false,
            received: HashMap::new(),
        },
    );
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Confirmed)]);

    go.store(true, Ordering::SeqCst);
    conn.wake().expect("the connection is live");
    let others = await_reports(
        &rx,
        (0..BURST)
            .map(|n| Report::Echoed(client_bidi(n), true))
            .collect(),
    );
    let after = harness.server_stats::<Responder>();
    let before = others
        .iter()
        .find_map(|report| match report {
            Report::Counters(stats) => Some(*stats),
            _ => None,
        })
        .expect("the server counted as the burst opened");
    let turns = polled_turns(&others);
    assert_eq!(turns.len(), BURST as usize, "{others:?}");
    assert_eq!(
        (
            most_per_turn(&turns),
            after.sent_packets - before.sent_packets,
            after.sent_datagrams - before.sent_datagrams,
        ),
        (BURST as usize, 1, 1),
        "responses produced in the busiest turn, then packets and datagrams sent for the burst; \
         turns of the polls: {turns:?}"
    );
    harness.shutdown();
}

#[test]
fn a_producer_that_stays_pull_ready_is_polled_once_per_application_phase() {
    const POLLS: usize = 20;
    let harness = Harness::new();
    let (tx, rx) = mpsc::channel();
    let addr = harness.serve({
        let tx = tx.clone();
        move || recording_server(tx)
    });
    let token = Arc::new(AtomicUsize::new(0));
    let conn = {
        let (reports, token) = (tx.clone(), Arc::clone(&token));
        harness.connect(addr, move || Hog {
            name: "hog",
            reports,
            token,
            polls: POLLS,
            opened: false,
        })
    };
    await_reports(&rx, vec![Report::Event("client", ConnEvent::Connected)]);

    token.store(1, Ordering::SeqCst);
    conn.wake().expect("the connection is live");
    let mut turns = Vec::new();
    while turns.len() < POLLS {
        if let Report::Produced(_, turn) = rx
            .recv_timeout(WAIT)
            .expect("the producer is polled to its end")
        {
            turns.push(turn);
        }
    }
    assert!(
        most_per_turn(&turns) <= 2,
        "a turn has two application phases, each polling the producer once: {turns:?}"
    );
    harness.shutdown();
}

/// A client session that, once the test thread has set `token` and woken it, opens `streams`
/// bidirectional streams and wakes them all. Each producer reports the driver turn it was polled
/// in and sends `hello` and the FIN.
struct Busy {
    name: &'static str,
    streams: usize,
    reports: mpsc::Sender<Report>,
    token: Arc<AtomicUsize>,
    opened: bool,
}

impl QuicSession for Busy {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        let _ = self.reports.send(Report::Event("client", event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, sink: &mut SendSink<'_>) -> Poll<()> {
        let _ = self
            .reports
            .send(Report::Produced(self.name, current_turn::<Busy>()));
        sink.push(Bytes::from_static(b"hello"))
            .expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        if self.token.load(Ordering::SeqCst) == 1 && !self.opened {
            self.opened = true;
            for _ in 0..self.streams {
                let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
                conn.stream_waker(id).wake();
            }
        }
        Poll::Pending
    }
}

#[test]
fn a_connections_pull_steps_leave_part_of_each_turn_to_the_others_on_its_worker() {
    // More streams than one connection may poll in a turn, and at most as many polls in a turn
    // across the worker's connections as one connection has streams: without its own bound, the
    // connection served first would take them all.
    const STREAMS: usize = 80;
    let per_turn = (TURN_STAGING / POLL_CHARGE) as usize;
    assert!(STREAMS > per_turn);
    let mut harness = Harness::new();
    harness.limits.polls = STREAMS;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let token = Arc::new(AtomicUsize::new(0));
    let conns: Vec<ConnHandle> = ["one", "two"]
        .into_iter()
        .map(|name| {
            let (reports, token) = (tx.clone(), Arc::clone(&token));
            harness.connect(addr, move || Busy {
                name,
                streams: STREAMS,
                reports,
                token,
                opened: false,
            })
        })
        .collect();
    await_reports(
        &rx,
        times(2, || Report::Event("client", ConnEvent::Connected)),
    );

    token.store(1, Ordering::SeqCst);
    // Both wakes land on the ready queue before the client's next turn, so both connections
    // open their streams in the same application phase.
    let blocked = Harness::block(&harness.client);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    drop(blocked);
    let mut polls: HashMap<(&'static str, u64), usize> = HashMap::new();
    let mut first: HashMap<&'static str, u64> = HashMap::new();
    for _ in 0..2 * STREAMS {
        loop {
            let report = rx.recv_timeout(WAIT).expect("every producer is polled");
            if let Report::Produced(name, turn) = report {
                *polls.entry((name, turn)).or_default() += 1;
                first.entry(name).or_insert(turn);
                break;
            }
        }
    }
    assert!(
        polls.values().all(|&count| count <= per_turn),
        "a connection was polled more than {per_turn} times in a turn: {polls:?}"
    );
    assert_eq!(
        first["one"], first["two"],
        "both connections are polled in the turn their streams opened: {polls:?}"
    );
    harness.shutdown();
}

/// The bytes each [`Bulky`] stream sends.
const BULKY: usize = 32 * 1024;

/// A client session that, once connected, opens `streams` incremental bidirectional streams and
/// wakes them all. Each producer sends [`BULKY`] bytes, as many per poll as its allowance takes,
/// and then the FIN, reporting the driver turn and the bytes of each poll. It checks each echo.
struct Bulky {
    streams: usize,
    reports: mpsc::Sender<Report>,
    unsent: HashMap<StreamId, Bytes>,
    received: HashMap<StreamId, Vec<u8>>,
}

impl QuicSession for Bulky {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        for _ in 0..self.streams {
            let id = conn
                .open_stream(Dir::Bi, INCREMENTAL)
                .expect("a stream opens");
            self.unsent.insert(id, payload(BULKY));
            conn.stream_waker(id).wake();
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let received = self.received.entry(id).or_default();
        for segment in read_all(conn, id) {
            received.extend_from_slice(&segment);
        }
        if ready == StreamReady::Finished {
            let _ = self
                .reports
                .send(Report::Echoed(id, received[..] == payload(BULKY)[..]));
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        let Some(unsent) = self.unsent.get_mut(&id) else {
            return Poll::Pending;
        };
        let len = unsent.len().min(sink.allowance());
        if len == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        sink.push(unsent.split_to(len))
            .expect("within the allowance");
        if unsent.is_empty() {
            sink.finish().expect("the stream is open");
            self.unsent.remove(&id);
        }
        let _ = self
            .reports
            .send(Report::Staged(current_turn::<Bulky>(), len));
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[test]
fn a_turn_counts_each_poll_by_the_bytes_it_staged() {
    const STREAMS: u32 = 8;
    let mut harness = Harness::new();
    // Two polls of a whole stream do a turn's work; four would fit at `POLL_CHARGE` each.
    harness.limits.turn_staging = 2 * BULKY as u64;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || Bulky {
        streams: STREAMS as usize,
        reports: tx,
        unsent: HashMap::new(),
        received: HashMap::new(),
    });
    let others = await_reports(
        &rx,
        (0..STREAMS)
            .map(|n| Report::Echoed(client_bidi(n), true))
            .collect(),
    );
    let mut per_turn: HashMap<u64, usize> = HashMap::new();
    for report in &others {
        if let Report::Staged(turn, len) = report {
            *per_turn.entry(*turn).or_default() += len;
        }
    }
    // The bound is checked before each poll, and a poll stages at most a stream's bytes.
    let most = harness.limits.turn_staging as usize + BULKY;
    assert!(
        per_turn.values().all(|&staged| staged <= most),
        "a turn staged more than {most} bytes: {per_turn:?}"
    );
    harness.shutdown();
}

/// Returns an endpoint config whose accepted connections may build up to `horizon` ahead.
fn building_ahead(horizon: Duration) -> Arc<EndpointConfig> {
    EndpointConfig::builder(reset_key())
        .build_horizon(horizon)
        .build()
        .expect("an endpoint config")
}

/// Returns socket settings with kernel release up to `horizon` ahead.
fn kernel_release(horizon: Duration) -> MmsgOptions {
    MmsgOptions {
        txtime: true,
        txtime_horizon: horizon,
        ..mmsg_options()
    }
}

#[test]
fn accepted_connections_build_within_the_server_sockets_horizon_and_client_connections_do_not() {
    let ms = Duration::from_millis;
    // The build horizons of the server's and the client's connections, with a 5 ms endpoint
    // setting, the server socket's `options` and the server connection's `max_ack_delay`.
    let horizons = |options: MmsgOptions, max_ack_delay: Duration| {
        let mut harness = Harness::<MmsgBackend>::with_options(options);
        harness.endpoint = building_ahead(ms(5));
        let (tx, rx) = mpsc::channel();
        let server_reports = tx.clone();
        let transport = TransportConfig::builder()
            .ack_policy(AckPolicy {
                max_ack_delay,
                ..AckPolicy::default()
            })
            .build()
            .expect("a transport config");
        let addr = harness.serve(move || {
            let mut app = App::new(move |_| Ok(Echo::new(server_reports.clone())));
            app.transport = Some(transport);
            app
        });
        let _conn = harness.connect(addr, move || PushClient::new(1, payload(1000), tx));
        await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
        let server = Harness::<MmsgBackend>::build_horizons::<Echo>(&harness.server);
        let client = Harness::<MmsgBackend>::build_horizons::<PushClient>(&harness.client);
        harness.shutdown();
        (server, client)
    };
    // A connection that builds at least two wheel ticks ahead has its pacing wakes on the wheel
    // (`Coarse`); any other keeps the timerfd for the last stretch of each wake (`Pacing`). This
    // depends on the connection's own horizon, not its endpoint's.
    let default_ack_delay = AckPolicy::default().max_ack_delay;
    assert_eq!(
        horizons(kernel_release(ms(100)), default_ack_delay),
        (
            vec![(ms(5), Kind::Coarse)],
            vec![(Duration::ZERO, Kind::Pacing)]
        ),
        "the endpoint's horizon, under the socket's; none for a client connection"
    );
    assert_eq!(
        horizons(kernel_release(ms(3)), default_ack_delay).0,
        vec![(ms(3), Kind::Coarse)],
        "the socket's horizon, under the endpoint's"
    );
    assert_eq!(
        horizons(mmsg_options(), default_ack_delay).0,
        vec![(Duration::ZERO, Kind::Pacing)],
        "nothing ahead without release support"
    );
    assert_eq!(
        horizons(kernel_release(ms(100)), ms(16_383)).0,
        vec![(Duration::ZERO, Kind::Pacing)],
        "a connection whose max_ack_delay leaves no room builds nothing ahead on a 5 ms endpoint, \
         and its pacing wakes keep the timerfd"
    );
}

#[test]
fn the_handle_reports_the_server_sockets_release_horizon_and_send_buffer() {
    let mut options = kernel_release(Duration::from_millis(3));
    options.socket.send_buffer = Some(150_000);
    let harness = Harness::<MmsgBackend>::with_options(options);
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || App::new(move |_| Ok(Echo::new(server_reports.clone()))));
    let _conn = harness.connect(addr, move || PushClient::new(1, payload(1000), tx));
    await_reports(&rx, vec![Report::Echoed(client_bidi(0), true)]);
    let caps = Harness::<MmsgBackend>::server_caps::<Echo>(&harness.server)
        .expect("the server driver has a server socket");
    assert_eq!(caps.release.horizon(), Duration::from_millis(3));
    // Linux doubles the value asked for, for its bookkeeping (socket(7)).
    assert_eq!(caps.send_buffer, 300_000);
    assert_eq!(
        Harness::<MmsgBackend>::server_caps::<PushClient>(&harness.client),
        None,
        "a driver without a server socket"
    );
    harness.shutdown();
}

#[test]
fn with_kernel_release_each_pacing_wake_comes_when_its_run_is_due_within_the_horizon() {
    // Eight datagrams from the server, within the window, over a link with a round trip of 20 ms.
    // At a window per round trip and a minimum burst of 1, the pacer releases one datagram every
    // 1.6 ms; with a 5 ms horizon a wake builds what is due within 5 ms, and the sluggish peers
    // do not acknowledge anything within the test, so only the pacing wakes move the server on.
    const LEN: usize = 9_000;
    let horizon = Duration::from_millis(5);
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: kernel_release(Duration::from_millis(100)),
        valves: Arc::clone(&valves),
    });
    harness.endpoint = building_ahead(horizon);
    let mut relay = None;
    let pair = BulkPair::through(&harness, 1, LEN, sluggish_and_paced(), |server| {
        let link = Relay::delayed(server, Duration::from_millis(10));
        let addr = link.addr;
        relay = Some(link);
        addr
    });
    let _link = relay.expect("the client connects through the relay");
    valves.server.clear();
    pair.go();
    await_reports_within(&pair.rx, vec![Report::Received(uni(3), LEN)], STALL);
    // A command runs between the driver's polls, so the server's last attempt has ended.
    harness.server_stats::<Bulk>();
    let runs = valves.server.runs();
    for run in &runs {
        let ahead = run
            .ahead
            .unwrap_or_else(|| panic!("an unstamped run: {runs:?}"));
        assert!(ahead <= horizon, "built beyond the horizon: {runs:?}");
    }
    let attempts = valves
        .server
        .events()
        .iter()
        .filter(|&&event| event == Event::Attempt)
        .count();
    let first = runs.first().map_or(attempts, |run| run.attempt);
    let empty: Vec<usize> = (first..attempts)
        .filter(|&attempt| !runs.iter().any(|run| run.attempt == attempt))
        .collect();
    // A wake before its run is due within the horizon, such as one at the release less twice
    // the horizon, does not build a run.
    assert!(
        empty.is_empty(),
        "attempts {empty:?} of {attempts} built no run: {runs:?}"
    );
    assert!(
        attempts - first >= 2,
        "the pacing wakes were not exercised: {runs:?}"
    );
    // Its only connection builds 5 ms ahead, so the wheel brings every pacing wake.
    assert_eq!(
        harness.server_fine_plans::<Bulk>(),
        0,
        "the server put a pacing wake on the timerfd: {runs:?}"
    );
    harness.shutdown();
}

/// Returns what the transmit phases of the driver for sessions of type `S` on gated sockets on
/// `worker` did, and what `read` returns, both read in one pause of that driver.
fn tx_record<S: QuicSession, T: Send + 'static>(
    worker: &ManagedWorker,
    read: impl FnOnce() -> T + Send + 'static,
) -> (TxRecord, T) {
    let (tx, rx) = mpsc::channel();
    worker
        .handle()
        .submit(move |_| {
            let record = with_backend_handle::<S, Gated, _>(|handle| handle.tx_record());
            let _ = tx.send((record, read()));
        })
        .expect("the worker takes commands");
    rx.recv_timeout(WAIT).expect("the worker answers")
}

/// How long the server's worker is held after each of its next [`BULK_STALLS`] attempts in
/// [`stalled_bulk`].
const BULK_STALL: Duration = Duration::from_millis(3);

/// The attempts after which [`stalled_bulk`] holds the server's worker.
const BULK_STALLS: usize = 6;

/// Has a [`Bulk`] server send seven datagrams, within the initial window, over gated sockets with
/// `mmsg` and at most two datagrams per attempt, so its connection makes several attempts in one
/// transmit phase, while the server's worker is held [`BULK_STALL`] after each of its next
/// [`BULK_STALLS`] attempts. With `horizon` the server's endpoint builds up to that far ahead.
/// Returns the server valve's events and runs from the client's request on, and the server
/// driver's record, read together.
fn stalled_bulk(mmsg: MmsgOptions, horizon: Option<Duration>) -> (Vec<Event>, Vec<Run>, TxRecord) {
    const LEN: usize = 8_000;
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg,
        valves: Arc::clone(&valves),
    });
    if let Some(horizon) = horizon {
        harness.endpoint = building_ahead(horizon);
    }
    harness.limits.max_segments = 2;
    let pair = BulkPair::new(&harness, 1, LEN);
    valves.server.clear();
    valves.server.stall(BULK_STALL, BULK_STALLS);
    pair.go();
    await_reports(&pair.rx, vec![Report::Received(uni(3), LEN)]);
    let (record, (events, runs)) = tx_record::<Bulk, _>(&harness.server, move || {
        (valves.server.events(), valves.server.runs())
    });
    // The driver debug-asserts that a connection's attempts and reports do not go back in time.
    let stats = harness.server_stats::<Bulk>();
    assert_eq!(stats.contained_panics, 0, "{stats:?}");
    harness.shutdown();
    (events, runs, record)
}

#[test]
fn with_kernel_release_an_attempt_after_a_stall_builds_against_a_fresh_clock() {
    let ms = Duration::from_millis;
    let (_, runs, ..) = stalled_bulk(kernel_release(ms(100)), Some(ms(5)));
    let behind: Vec<Duration> = runs
        .iter()
        .map(|run| {
            run.behind
                .unwrap_or_else(|| panic!("an unstamped run: {runs:?}"))
        })
        .collect();
    assert!(
        behind.len() >= 4,
        "seven datagrams at two per attempt take at least four runs: {runs:?}"
    );
    // Each stall is 3 ms, so a release taken from a reading before one lies at least that far
    // behind its attempt's start.
    assert!(
        behind
            .iter()
            .all(|&behind| behind <= Duration::from_micros(500)),
        "a release lay more than 0.5 ms behind its attempt's start: {behind:?}"
    );
}

#[test]
fn with_kernel_release_the_server_socket_is_flushed_after_each_attempt_and_for_an_unpaced_connection_without_it_once_per_phase()
 {
    let ms = Duration::from_millis;
    let (events, ..) = stalled_bulk(kernel_release(ms(100)), Some(ms(5)));
    assert!(events.contains(&Event::Attempt), "{events:?}");
    assert!(
        events
            .split(|&event| event == Event::Attempt)
            .skip(1)
            .all(|after| after.contains(&Event::Flush)),
        "with kernel release, an attempt was not flushed before the next: {events:?}"
    );

    // The bulk connection is unpaced, and without kernel release it keeps the phase's reading
    // and its one flush.
    let (events, _, record) = stalled_bulk(mmsg_options(), None);
    assert!(
        most_attempts_per_flush(&events) >= 2,
        "without kernel release, each attempt had its own flush: {events:?}"
    );
    let mut readings = HashMap::new();
    for attempt in &record.attempts {
        let reading = *readings.entry(attempt.phase).or_insert(attempt.at);
        assert_eq!(
            reading, attempt.at,
            "attempts of one phase ran at different readings: {:?}",
            record.attempts
        );
    }
    assert_eq!(record.phase_clock_reads, 0, "{record:?}");
    assert!(
        record.wakes.iter().all(|wake| wake.phase.is_none()),
        "a pacing wake was taken inside a transmit phase: {record:?}"
    );
}

#[test]
fn with_kernel_release_a_server_socket_behind_an_eagain_is_not_flushed_again_in_its_phase() {
    // Seven datagrams, within the initial congestion window, at two per attempt.
    const LEN: usize = 8_000;
    let ms = Duration::from_millis;
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: kernel_release(ms(100)),
        valves: Arc::clone(&valves),
    });
    harness.endpoint = building_ahead(ms(5));
    harness.limits.max_segments = 2;
    let pair = BulkPair::new(&harness, 1, LEN);
    valves.server.clear();
    valves.server.block_next_flush();
    pair.go();
    let deadline = Instant::now() + WAIT;
    while !valves.server.waiting() {
        assert!(
            Instant::now() < deadline,
            "the server never waited for its socket"
        );
        std::thread::yield_now();
    }
    // A command runs between the driver's polls, so the phase that met the EAGAIN has ended.
    harness.server_stats::<Bulk>();
    let events = valves.server.events();
    // The flush after the first attempt meets the EAGAIN, and the attempt after it is refused;
    // only the end of the phase flushes again.
    assert!(events.contains(&Event::Refused), "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|&&event| event == Event::Blocked)
            .count(),
        2,
        "the server socket was flushed again behind its EAGAIN: {events:?}"
    );
    valves.server.open();
    await_reports(&pair.rx, vec![Report::Received(uni(3), LEN)]);
    harness.shutdown();
}

/// How long the server's worker is held after each of its stalled attempts in [`stalled_paced`]:
/// less than the 1.6 ms between a paced connection's runs there.
const PACED_STALL: Duration = Duration::from_millis(1);

/// A transmit attempt on a gated server socket, with what the driver recorded of it.
#[derive(Debug)]
struct Joined {
    key: ConnKey,
    phase: u64,
    /// The reading it ran at.
    at: Instant,
    /// When the gated socket recorded its start.
    started: Instant,
    /// The runs it built.
    runs: usize,
}

/// What a server did in [`stalled_paced`] from its clients' requests on.
struct Paced {
    events: Vec<Event>,
    attempts: Vec<Joined>,
    /// The place in the driver's record of the first of `attempts`.
    first: usize,
    wakes: Vec<WakeRecord>,
    stats: crate::EndpointStats,
}

impl Paced {
    /// Returns the driver's attempt at place `place` in its record, if it is in `attempts`.
    fn joined(&self, place: usize) -> Option<&Joined> {
        self.attempts.get(place.checked_sub(self.first)?)
    }
}

/// Has three paced [`Bulk`] servers on one endpoint send eight datagrams each, within the window,
/// to their own sluggish client through a relay that delays each datagram 10 ms, while the
/// server's worker is held [`PACED_STALL`] after each of its next 40 attempts. At a window per
/// round trip and a minimum burst of 1, each connection releases a datagram every 1.6 ms, and
/// without kernel release does not build ahead.
fn stalled_paced() -> Paced {
    const CLIENTS: usize = 3;
    const LEN: usize = 9_000;
    const STALLS: usize = 40;
    let client = sluggish_and_paced();
    let valves = Arc::new(Valves::default());
    let harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| Ok(Bulk::new("server", LEN, None, server_reports.clone())));
        app.transport = Some(sluggish_and_paced());
        app
    });
    let go = Arc::new(AtomicBool::new(false));
    let links: Vec<Relay> = (0..CLIENTS)
        .map(|_| Relay::delayed(addr, Duration::from_millis(10)))
        .collect();
    let conns: Vec<ConnHandle> = links
        .iter()
        .map(|link| {
            let (go, tx) = (Arc::clone(&go), tx.clone());
            let options = ConnOptions {
                transport: Some(Arc::clone(&client)),
            };
            harness.connect_with(link.addr, options, move || {
                Bulk::new("client", 1, Some(go), tx)
            })
        })
        .collect();
    let confirmed = || Report::Event("client", ConnEvent::Confirmed);
    await_reports(&rx, (0..CLIENTS).map(|_| confirmed()).collect());
    valves.server.clear();
    valves.server.stall(PACED_STALL, STALLS);
    let asked = Instant::now();
    go.store(true, Ordering::SeqCst);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    let received = || Report::Received(uni(3), LEN);
    await_reports_within(&rx, (0..CLIENTS).map(|_| received()).collect(), STALL);
    let (record, (events, started, runs)) = tx_record::<Bulk, _>(&harness.server, move || {
        let valve = &valves.server;
        (valve.events(), valve.started(), valve.runs())
    });
    let stats = harness.server_stats::<Bulk>();
    harness.shutdown();
    let first = record
        .attempts
        .len()
        .checked_sub(started.len())
        .expect("the driver recorded every attempt the socket saw");
    let attempts = record.attempts[first..]
        .iter()
        .zip(&started)
        .enumerate()
        .map(|(n, (attempt, start))| {
            assert_eq!(
                attempt.key, start.conn,
                "the driver and the socket disagree"
            );
            Joined {
                key: attempt.key,
                phase: attempt.phase,
                at: attempt.at,
                started: start.at,
                runs: runs.iter().filter(|run| run.attempt == n).count(),
            }
        })
        .collect();
    let wakes = record
        .wakes
        .into_iter()
        .filter(|wake| wake.taken >= asked)
        .collect();
    Paced {
        events,
        attempts,
        first,
        wakes,
        stats,
    }
}

/// Returns whether every attempt in `events` that built a run is followed by a flush before
/// the next attempt.
fn each_run_flushed_before_the_next_attempt(events: &[Event]) -> bool {
    events
        .split(|&event| event == Event::Attempt)
        .skip(1)
        .all(|after| !after.contains(&Event::Run) || after.contains(&Event::Flush))
}

#[test]
fn without_kernel_release_a_paced_attempt_builds_at_a_fresh_reading_and_is_flushed_before_the_next_attempt()
 {
    let paced = stalled_paced();
    let events = &paced.events;
    assert!(
        each_run_flushed_before_the_next_attempt(events),
        "a paced attempt's runs waited past the next attempt: {events:?}"
    );
    // Each stall is 1 ms, so a reading from before one lies at least that far before the
    // attempt starts.
    let stale: Vec<&Joined> = paced
        .attempts
        .iter()
        .filter(|attempt| {
            attempt.started.saturating_duration_since(attempt.at) > Duration::from_micros(500)
        })
        .collect();
    assert!(
        stale.is_empty(),
        "attempts ran at readings more than 0.5 ms before they began: {stale:?}"
    );
    let served: Vec<usize> = paced.wakes.iter().filter_map(|wake| wake.next).collect();
    let ordinary_after_another = paced
        .attempts
        .iter()
        .enumerate()
        .skip(1)
        .any(|(n, attempt)| {
            attempt.runs > 0
                && attempt.phase == paced.attempts[n - 1].phase
                && !served.contains(&(paced.first + n))
        });
    assert!(
        ordinary_after_another,
        "no phase had an attempt that built a run after another attempt without a wake taken in \
         the phase: {:?}",
        paced.attempts
    );
}

#[test]
fn a_paced_attempt_requeued_on_a_full_batch_is_flushed_on_its_own_socket_before_the_next_attempt() {
    // Eight datagrams from the client, within the window, over a link with a round trip of 20 ms.
    // After idle the pacer releases its credit and one run, a datagram each, at once; with one
    // datagram per attempt, the second goes out in an attempt requeued behind the first.
    const LEN: usize = 9_000;
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    harness.limits.max_segments = 1;
    let mut relay = None;
    let pair = BulkPair::through(&harness, LEN, 1, sluggish_and_paced(), |server| {
        let link = Relay::delayed(server, Duration::from_millis(10));
        let addr = link.addr;
        relay = Some(link);
        addr
    });
    let _link = relay.expect("the client connects through the relay");
    let requeues = harness.client_stats::<Bulk>().requeues;
    valves.client.clear();
    pair.go();
    await_reports_within(&pair.rx, vec![Report::Received(uni(2), LEN)], STALL);
    // A command runs between the driver's polls, so the client's last attempt has ended.
    let client = harness.client_stats::<Bulk>();
    assert!(
        client.requeues > requeues,
        "no attempt was requeued: {client:?}"
    );
    let events = valves.client.events();
    assert!(
        each_run_flushed_before_the_next_attempt(&events),
        "a paced attempt's runs waited past the next attempt: {events:?}"
    );
    harness.shutdown();
}

#[test]
fn a_pacing_wake_that_comes_due_during_a_transmit_phase_is_served_before_the_next_attempt() {
    let paced = stalled_paced();
    // A wake that comes due during a stall waits at least for the stall's end. The margin
    // allows for a loaded host.
    let late: Vec<&WakeRecord> = paced
        .wakes
        .iter()
        .filter(|wake| {
            wake.phase.is_none()
                && wake.taken.saturating_duration_since(wake.due) > Duration::from_millis(1)
        })
        .collect();
    assert!(
        late.is_empty(),
        "wakes taken at the intake more than 1 ms late: {late:?}"
    );
    let served: Vec<(&WakeRecord, usize)> = paced
        .wakes
        .iter()
        .filter(|wake| wake.phase.is_some())
        .filter_map(|wake| Some((wake, wake.next?)))
        .collect();
    assert!(
        !served.is_empty(),
        "no wake was served inside a transmit phase: {:?}",
        paced.wakes
    );
    for &(wake, next) in &served {
        let attempt = paced
            .joined(next)
            .unwrap_or_else(|| panic!("the attempt after {wake:?} is not the socket's"));
        assert!(
            attempt.key.index == wake.index && attempt.at == wake.taken,
            "the attempt after {wake:?} is not its connection's at its reading: {attempt:?}"
        );
        // However late its wake, a served attempt builds at most the pacer's credit and one run.
        assert!(
            (1..=2).contains(&attempt.runs),
            "a served attempt built {} runs: {attempt:?}",
            attempt.runs
        );
    }
    let lumped = paced
        .events
        .split(|&event| event == Event::Flush)
        .any(|between| {
            between
                .split(|&event| event == Event::Attempt)
                .skip(1)
                .filter(|after| after.contains(&Event::Run))
                .count()
                > 1
        });
    assert!(
        !lumped,
        "the runs of two attempts left in one flush: {:?}",
        paced.events
    );
    let mut serves = HashMap::new();
    for (wake, _) in &served {
        *serves.entry((wake.phase, wake.index)).or_insert(0) += 1;
    }
    assert!(
        serves.values().any(|&count| count >= 2),
        "no connection was served twice in one transmit phase: {serves:?}"
    );
    assert!(paced.stats.phase_pacing_wakes > 0, "{:?}", paced.stats);
}

/// Returns the places in the driver's record of the attempts that the in-phase serves among
/// `wakes` gave.
fn served_attempts(wakes: &[WakeRecord]) -> Vec<usize> {
    wakes
        .iter()
        .filter(|wake| wake.phase.is_some())
        .filter_map(|wake| wake.next)
        .collect()
}

/// Starts in `lab` a server driver without a work budget, whose connections pace and send nothing,
/// and a client driver with `conns` connections to it, and runs until they are established and the
/// lab is quiet. The server's connections take its slots in accept order. Returns the server's
/// handle and task, and the client's handle.
fn lab_paced_server(
    lab: &Lab,
    conns: usize,
) -> (
    EndpointHandle<LabApp, MemBackend>,
    usize,
    EndpointHandle<LabApp, MemBackend>,
) {
    let (client_config, server_config, endpoint) = lab_configs();
    let sockets = MemOptions {
        net: Some(lab.net.clone()),
        ..MemOptions::default()
    };
    let probes = Rc::new(RefCell::new(Vec::new()));
    let (net, accepted) = (lab.net.clone(), Rc::clone(&probes));
    let app = LabApp::new(&lab.net, move |_, options| {
        options.transport = Some(lab_transport(true));
        let (session, probe) = LabBulk::new(&net, 0, Some(0));
        accepted.borrow_mut().push(probe);
        session
    });
    let socket = MemBackend::bind(SERVER, &sockets).expect("the lab binds");
    let server = EndpointDriver::builder(Arc::clone(&endpoint), app)
        .serve(socket, server_config)
        .backend_options(sockets.clone())
        .host_timers(Lab::timers())
        .spawn(lab.ctx())
        .expect("the server starts");
    let server_task = lab.last_spawned();
    let client = EndpointDriver::builder(endpoint, LabApp::client(&lab.net))
        .backend_options(sockets)
        .host_timers(Lab::timers())
        .spawn(lab.ctx())
        .expect("the client starts");
    for _ in 0..conns {
        let (session, probe) = LabBulk::new(&lab.net, 0, Some(0));
        let options = ConnOptions {
            transport: Some(lab_transport(false)),
        };
        let name = ServerName::try_from("localhost").expect("a name");
        client
            .connect(SERVER, name, Arc::clone(&client_config), options, session)
            .expect("the client connects");
        probes.borrow_mut().push(probe);
    }
    lab.run_until(|| {
        let probes = probes.borrow();
        probes.len() == 2 * conns && probes.iter().all(|probe| probe.connected.get())
    });
    lab.run_quiet(Duration::from_millis(500));
    (server, server_task, client)
}

#[test]
fn a_connection_served_while_it_waits_in_the_phase_queue_makes_one_attempt_for_both() {
    // Three paced server connections wait in the transmit queue in slot order, and the pacing wake
    // of the last comes due during the first one's attempt, so it is served at the check before the
    // next pop, while it still waits behind the second.
    const ATTEMPT: Duration = Duration::from_micros(100);
    let lab = Lab::new();
    let (server, server_task, _client) = lab_paced_server(&lab, 3);
    let core = server.core().expect("the server runs");
    for index in 0..3 {
        core.mark_dirty_at(index);
    }
    core.arm_pacing_at(2, lab.net.now() + ATTEMPT / 2);
    lab.net.set_costs(Costs {
        attempt: ATTEMPT,
        ..Costs::default()
    });
    let before = server.tx_record();
    assert!(lab.poll(server_task), "the server is woken");
    let record = server.tx_record();
    let [wake] = record.wakes[before.wakes.len()..] else {
        panic!("not one wake was taken: {:?}", record.wakes);
    };
    let (2, true, Some(phase), Some(next)) = (wake.index, wake.queued, wake.phase, wake.next)
    else {
        panic!("the wake was not served while its connection waited in the queue: {wake:?}");
    };
    assert_eq!(
        record.attempts[next].key.index, 2,
        "the serve gave another connection the attempt: {:?}",
        record.attempts
    );
    let slots: Vec<u32> = record.attempts[before.attempts.len()..]
        .iter()
        .filter(|attempt| attempt.phase == phase)
        .map(|attempt| attempt.key.index)
        .collect();
    assert_eq!(
        slots,
        [0, 2, 1],
        "the slots attempted in the phase of {wake:?}"
    );
}

/// Has a [`Bulk`] client connection for each of `transports` send 9,000 bytes, within the
/// window, to one server through its own relay that delays each datagram 10 ms, with the client's
/// worker held 5 ms after each of its attempts: more than the 1.6 ms between a paced connection's
/// runs. The connections are told to send in one turn of the client's driver, so their first
/// attempts share a transmit phase; with `drop_run`, the first data run is dropped. Returns the
/// client driver's record and counters, read together.
fn stalled_clients(
    limits: Limits,
    transports: &[Arc<TransportConfig>],
    drop_run: bool,
) -> (TxRecord, crate::EndpointStats) {
    const LEN: usize = 9_000;
    let valves = Arc::new(Valves::default());
    let mut harness = Harness::<Gated>::with_options(GatedOptions {
        mmsg: mmsg_options(),
        valves: Arc::clone(&valves),
    });
    harness.limits = limits;
    let (tx, rx) = mpsc::channel();
    let server_reports = tx.clone();
    let addr = harness.serve(move || {
        let mut app = App::new(move |_| Ok(Bulk::new("server", 1, None, server_reports.clone())));
        app.transport = Some(sluggish());
        app
    });
    let go = Arc::new(AtomicBool::new(false));
    let links: Vec<Relay> = transports
        .iter()
        .map(|_| Relay::delayed(addr, Duration::from_millis(10)))
        .collect();
    let conns: Vec<ConnHandle> = links
        .iter()
        .zip(transports)
        .map(|(link, transport)| {
            let (go, tx) = (Arc::clone(&go), tx.clone());
            let options = ConnOptions {
                transport: Some(Arc::clone(transport)),
            };
            harness.connect_with(link.addr, options, move || {
                Bulk::new("client", LEN, Some(go), tx)
            })
        })
        .collect();
    let each = |report: fn() -> Report| transports.iter().map(|_| report()).collect();
    await_reports(&rx, each(|| Report::Event("client", ConnEvent::Confirmed)));
    if drop_run {
        valves.client.drop_next_run_of(DROP_AT);
    }
    valves.client.stall(Duration::from_millis(5), usize::MAX);
    let blocked = Harness::block(&harness.client);
    go.store(true, Ordering::SeqCst);
    for conn in &conns {
        conn.wake().expect("the connection is live");
    }
    drop(blocked);
    await_reports_within(&rx, each(|| Report::Received(uni(2), LEN)), STALL);
    let (record, stats) = tx_record::<Bulk, _>(&harness.client, || {
        with_backend_handle::<Bulk, Gated, _>(|handle| handle.stats())
    });
    harness.shutdown();
    (record, stats)
}

#[test]
fn a_pacing_wake_taken_while_its_connection_waits_for_the_next_phase_gives_it_the_next_attempt() {
    // The first attempt's first run is dropped, which puts its connection on the dirty list for
    // the next phase, and that connection's pacing wake comes due in the stall after the attempt.
    // The serve retires the slot on the dirty list, which the next phase skips.
    let paced = sluggish_and_paced();
    let (record, stats) = stalled_clients(Limits::default(), &[Arc::clone(&paced), paced], true);
    let taken: Vec<&WakeRecord> = record
        .wakes
        .iter()
        .filter(|wake| wake.phase.is_some())
        .collect();
    for wake in &taken {
        let Some(next) = wake.next else {
            panic!("{wake:?} gave no attempt in its phase: {:?}", record.wakes);
        };
        let attempt = record.attempts[next];
        assert!(
            attempt.key.index == wake.index
                && Some(attempt.phase) == wake.phase
                && attempt.at == wake.taken,
            "the attempt after {wake:?} is not its connection's at its reading: {attempt:?}"
        );
    }
    let skipped = |index: u32| {
        record
            .marks
            .iter()
            .any(|mark| matches!(mark, Mark::Skip(key) if key.index == index))
    };
    let redirtied = taken.iter().any(|wake| {
        let earlier = wake.next.map_or(&[][..], |next| &record.attempts[..next]);
        !wake.queued
            && earlier
                .iter()
                .any(|attempt| Some(attempt.phase) == wake.phase && attempt.key.index == wake.index)
            && skipped(wake.index)
    });
    assert!(
        redirtied,
        "no wake was taken while its connection, which had attempted in the phase, waited on the \
         dirty list: {:?}",
        record.wakes
    );
    assert_eq!(
        stats.phase_pacing_wakes,
        taken.len() as u64,
        "not every take in a transmit phase counted: {:?}",
        record.wakes
    );
}

#[test]
fn the_serves_and_full_batch_requeues_of_a_transmit_phase_share_its_requeue_cap() {
    // The unpaced connection fills batches of two datagrams, and the paced one's wakes come due
    // in the stalls; with a cap of one, a phase serves or requeues once, not once each.
    let limits = Limits {
        max_segments: 2,
        requeues: 1,
        ..Limits::default()
    };
    let (record, _) = stalled_clients(limits, &[sluggish(), sluggish_and_paced()], false);
    let served = served_attempts(&record.wakes);
    // Per phase, the serves that gave an attempt and the other attempts of a connection that
    // already attempted in it: requeues.
    let mut spent: HashMap<u64, u64> = HashMap::new();
    let mut seen = Vec::new();
    for (n, attempt) in record.attempts.iter().enumerate() {
        if served.contains(&n) || seen.contains(&(attempt.phase, attempt.key)) {
            *spent.entry(attempt.phase).or_default() += 1;
        }
        seen.push((attempt.phase, attempt.key));
    }
    assert!(
        spent.values().all(|&count| count <= limits.requeues),
        "a phase served and requeued more than its cap: {spent:?}"
    );
    let contested = spent.keys().any(|&phase| {
        let mut attempts = record
            .attempts
            .iter()
            .filter(|attempt| attempt.phase == phase);
        attempts
            .next()
            .is_some_and(|first| attempts.any(|attempt| attempt.key != first.key))
    });
    assert!(
        contested,
        "no phase reached its cap with both connections attempting in it: {spent:?}"
    );
}
