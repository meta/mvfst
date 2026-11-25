/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of [`AlpnRouter`]: two applications on one endpoint over loopback UDP, and the routing of
//! one connection's calls in a pair harness.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_io::MmsgBackend;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::Dir;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::Initiator;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TransportErrorCode;
use mvfstr_proto::Version;
use mvfstr_proto::testing::Pair;
use roxygen_runtime::tokio_host::ManagedWorker;
use rustls::pki_types::ServerName;

use crate::AlpnRouter;
use crate::AlpnSession;
use crate::Conn;
use crate::ConnInfo;
use crate::DatagramSink;
use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::QuicApplication;
use crate::QuicSession;
use crate::Refusal;
use crate::SendSink;
use crate::test_support::ORDER;
use crate::test_support::configs_offering;
use crate::test_support::handshaken_pair_offering;
use crate::test_support::handshaken_pair_without_alpn;
use crate::wake;
use crate::wake::ConnWake;
use crate::wake::Shared;

/// How long a test waits for something that should happen at once.
const WAIT: Duration = Duration::from_secs(20);

const H3: &[u8] = b"h3";
const MOQT: &[u8] = b"moqt-16";

/// A report that a server application or a client session sends to the test thread.
#[derive(Debug, PartialEq, Eq)]
enum Report {
    /// The application named accepted a connection.
    Accepted(&'static str),
    /// A client that offered `alpn` read this whole stream of direction `dir`.
    Read {
        alpn: &'static str,
        dir: Dir,
        data: String,
    },
}

/// A server application that names itself in what its sessions send.
struct Named {
    name: &'static str,
    reports: mpsc::Sender<Report>,
}

impl QuicApplication for Named {
    type Session = Replier;

    fn accept(&mut self, _: &ConnInfo, _: &mut ConnOptions) -> Result<Replier, Refusal> {
        let _ = self.reports.send(Report::Accepted(self.name));
        Ok(Replier {
            name: self.name,
            uni: None,
            echo: Vec::new(),
        })
    }
}

/// A server session that, once connected, sends its application's name and the negotiated ALPN
/// protocol on a unidirectional stream through the pull path, and answers each bidirectional
/// stream with its application's name and what the stream carried, through the push path.
struct Replier {
    name: &'static str,
    /// The unidirectional stream and what it has left to send.
    uni: Option<(StreamId, Bytes)>,
    echo: Vec<u8>,
}

impl QuicSession for Replier {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        let alpn = String::from_utf8_lossy(conn.alpn().unwrap_or_default()).into_owned();
        let id = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
        self.uni = Some((id, Bytes::from(format!("{} {alpn}", self.name))));
        conn.stream_waker(id).wake();
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if id.dir() != Dir::Bi || !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let Ok(mut stream) = conn.stream(id) else {
            return;
        };
        for segment in stream.readable().segments() {
            self.echo.extend_from_slice(segment);
        }
        let len = stream.readable().chain_length();
        stream.consume(len).expect("the bytes are readable");
        if ready == StreamReady::Finished {
            let mut reply = Bytes::from(format!(
                "{}:{}",
                self.name,
                String::from_utf8_lossy(&self.echo)
            ));
            stream.send(&mut reply).expect("the stream takes the reply");
            assert!(reply.is_empty(), "the reply fits the stream's window");
            stream.finish().expect("the stream finishes");
        }
    }

    fn poll_send(
        &mut self,
        _: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        let Some((uni, data)) = self.uni.take_if(|(uni, _)| *uni == id) else {
            return Poll::Pending;
        };
        assert_eq!(uni, id);
        sink.push(data).expect("within the allowance");
        sink.finish().expect("the stream is open");
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// A client application that only opens connections.
struct Opener;

impl QuicApplication for Opener {
    type Session = Pinger;

    fn accept(&mut self, _: &ConnInfo, _: &mut ConnOptions) -> Result<Pinger, Refusal> {
        Err(Refusal::Ignore)
    }
}

/// A client session that, once connected, sends `ping` on a bidirectional stream, and reports
/// every stream it reads to its end.
struct Pinger {
    alpn: &'static str,
    reports: mpsc::Sender<Report>,
    read: Vec<(StreamId, Vec<u8>)>,
}

impl QuicSession for Pinger {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if event != ConnEvent::Connected {
            return;
        }
        let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
        let mut stream = conn.stream(id).expect("the stream is open");
        let mut ping = Bytes::from_static(b"ping");
        stream.send(&mut ping).expect("the stream takes data");
        stream.finish().expect("the stream finishes");
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if !matches!(ready, StreamReady::Readable | StreamReady::Finished) {
            return;
        }
        let Ok(mut stream) = conn.stream(id) else {
            return;
        };
        let at = match self.read.iter().position(|(read, _)| *read == id) {
            Some(at) => at,
            None => {
                self.read.push((id, Vec::new()));
                self.read.len() - 1
            }
        };
        for segment in stream.readable().segments() {
            self.read[at].1.extend_from_slice(segment);
        }
        let len = stream.readable().chain_length();
        stream.consume(len).expect("the bytes are readable");
        if ready == StreamReady::Finished {
            let (_, data) = self.read.swap_remove(at);
            let _ = self.reports.send(Report::Read {
                alpn: self.alpn,
                dir: id.dir(),
                data: String::from_utf8_lossy(&data).into_owned(),
            });
        }
    }

    fn poll_send(&mut self, _: &mut Context<'_>, _: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        Poll::Pending
    }
}

thread_local! {
    /// The client driver of this worker thread.
    static CLIENT: RefCell<Option<EndpointHandle<Opener, MmsgBackend>>> =
        const { RefCell::new(None) };
}

/// Starts a server driver on `worker` for the router `make` builds there, and returns its address.
fn serve<A: QuicApplication, B: QuicApplication>(
    worker: &ManagedWorker,
    endpoint: Arc<EndpointConfig>,
    config: Arc<ServerConfig>,
    make: impl FnOnce() -> AlpnRouter<A, B> + Send + 'static,
) -> SocketAddr {
    let (tx, rx) = mpsc::channel();
    worker
        .handle()
        .submit(move |worker| {
            let handle = EndpointDriver::<_, MmsgBackend>::builder(endpoint, make())
                .bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config)
                .spawn(worker)
                .expect("the server driver starts");
            let _ = tx.send(handle.local_addr().expect("the server is bound"));
        })
        .expect("the server worker takes commands");
    rx.recv_timeout(WAIT).expect("the server driver starts")
}

/// Opens a connection from `worker` to `addr` with `config`, whose session reports what it reads
/// as a client that offered `alpn`, starting the worker's client driver on first use.
fn ping(
    worker: &ManagedWorker,
    endpoint: Arc<EndpointConfig>,
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    alpn: &'static str,
    reports: mpsc::Sender<Report>,
) {
    let (tx, rx) = mpsc::channel();
    worker
        .handle()
        .submit(move |worker| {
            CLIENT.with(|client| {
                let mut client = client.borrow_mut();
                let handle = client.get_or_insert_with(|| {
                    EndpointDriver::<_, MmsgBackend>::builder(endpoint, Opener)
                        .spawn(worker)
                        .expect("the client driver starts")
                });
                let session = Pinger {
                    alpn,
                    reports,
                    read: Vec::new(),
                };
                let opened = handle.connect(
                    addr,
                    ServerName::try_from("localhost").expect("a DNS name"),
                    config,
                    ConnOptions::default(),
                    session,
                );
                let _ = tx.send(opened.is_ok());
            });
        })
        .expect("the client worker takes commands");
    assert!(
        rx.recv_timeout(WAIT).expect("the client worker answers"),
        "the connection starts"
    );
}

/// Waits until every message in `expected` has arrived, in any order, and returns the others that
/// arrived meanwhile.
fn await_reports(rx: &mpsc::Receiver<Report>, mut expected: Vec<Report>) -> Vec<Report> {
    let mut others = Vec::new();
    while !expected.is_empty() {
        let report = rx
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| panic!("still waiting for {expected:?}; others: {others:?}"));
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
fn an_h3_and_a_moqt_application_serve_their_own_clients_on_one_endpoint_and_port() {
    let (_, server_config, endpoint) = configs_offering(&[H3, MOQT], &[H3]);
    let (h3_client, _, _) = configs_offering(&[H3], &[H3]);
    let (moqt_client, _, _) = configs_offering(&[MOQT], &[MOQT]);
    let server = ManagedWorker::new(64).expect("a server worker");
    let client = ManagedWorker::new(64).expect("a client worker");
    let (tx, rx) = mpsc::channel();

    let apps = tx.clone();
    let addr = serve(&server, endpoint.clone(), server_config, move || {
        let h3 = Named {
            name: "h3 app",
            reports: apps.clone(),
        };
        let moqt = Named {
            name: "moqt app",
            reports: apps,
        };
        AlpnRouter::new([H3], h3, [MOQT, b"moqt-18"], moqt)
    });
    ping(&client, endpoint.clone(), addr, h3_client, "h3", tx.clone());
    ping(&client, endpoint, addr, moqt_client, "moqt-16", tx);

    let mut others = await_reports(
        &rx,
        vec![
            Report::Accepted("h3 app"),
            Report::Accepted("moqt app"),
            Report::Read {
                alpn: "h3",
                dir: Dir::Uni,
                data: "h3 app h3".to_owned(),
            },
            Report::Read {
                alpn: "h3",
                dir: Dir::Bi,
                data: "h3 app:ping".to_owned(),
            },
            Report::Read {
                alpn: "moqt-16",
                dir: Dir::Uni,
                data: "moqt app moqt-16".to_owned(),
            },
            Report::Read {
                alpn: "moqt-16",
                dir: Dir::Bi,
                data: "moqt app:ping".to_owned(),
            },
        ],
    );
    client
        .shutdown()
        .expect("the client worker shuts down cleanly");
    server
        .shutdown()
        .expect("the server worker shuts down cleanly");
    others.extend(rx.try_iter());
    assert_eq!(
        others,
        [],
        "each application accepts its own connection once, and each client reads only its replies"
    );
}

/// A call that a fake application or one of its sessions received, with the application's name.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Accept(&'static str, ConnInfo),
    Event(&'static str, ConnEvent),
    Stream(&'static str, StreamId, StreamReady),
    PollSend(&'static str, StreamId),
    PollDatagrams(&'static str),
    PollSession(&'static str),
    SessionQuiesce(&'static str),
    AppQuiesce(&'static str),
}

type Calls = Rc<RefCell<Vec<Call>>>;

/// An application that records the calls it and its sessions receive.
struct Fake {
    name: &'static str,
    calls: Calls,
    /// The deadline of its sessions.
    deadline: Option<Instant>,
    /// How it turns down every connection, if it does.
    refusal: Option<Refusal>,
}

impl Fake {
    fn new(name: &'static str, calls: &Calls) -> Self {
        Self {
            name,
            calls: Rc::clone(calls),
            deadline: None,
            refusal: None,
        }
    }

    fn session(&self) -> FakeSession {
        FakeSession {
            name: self.name,
            calls: Rc::clone(&self.calls),
            deadline: self.deadline,
        }
    }
}

impl QuicApplication for Fake {
    type Session = FakeSession;

    fn accept(&mut self, info: &ConnInfo, _: &mut ConnOptions) -> Result<FakeSession, Refusal> {
        self.calls.borrow_mut().push(Call::Accept(self.name, *info));
        match self.refusal {
            Some(refusal) => Err(refusal),
            None => Ok(self.session()),
        }
    }

    fn quiesce(&mut self) {
        self.calls.borrow_mut().push(Call::AppQuiesce(self.name));
    }
}

/// A session of a [`Fake`], whose polls are always ready.
struct FakeSession {
    name: &'static str,
    calls: Calls,
    deadline: Option<Instant>,
}

impl FakeSession {
    fn record(&self, call: Call) {
        self.calls.borrow_mut().push(call);
    }
}

impl QuicSession for FakeSession {
    fn on_event(&mut self, _: &mut Conn<'_>, event: ConnEvent) {
        self.record(Call::Event(self.name, event));
    }

    fn on_stream(&mut self, _: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        self.record(Call::Stream(self.name, id, ready));
    }

    fn poll_send(&mut self, _: &mut Context<'_>, id: StreamId, _: &mut SendSink<'_>) -> Poll<()> {
        self.record(Call::PollSend(self.name, id));
        Poll::Ready(())
    }

    fn poll_datagrams(&mut self, _: &mut Context<'_>, _: &mut DatagramSink<'_>) -> Poll<()> {
        self.record(Call::PollDatagrams(self.name));
        Poll::Ready(())
    }

    fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
        self.record(Call::PollSession(self.name));
        Poll::Ready(())
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn on_quiesce(&mut self, _: &mut Conn<'_>) {
        self.record(Call::SessionQuiesce(self.name));
    }
}

/// A router that gives `h3` connections to the fake `h3` and `moqt-16` and `moqt-18` ones to the
/// fake `moqt`.
fn fake_router(calls: &Calls) -> AlpnRouter<Fake, Fake> {
    AlpnRouter::new(
        [H3],
        Fake::new("h3", calls),
        [MOQT, b"moqt-18"],
        Fake::new("moqt", calls),
    )
}

/// The connection attempt the routers in these tests accept.
fn info() -> ConnInfo {
    ConnInfo {
        remote: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 50_000)),
        local_ip: None,
        version: Version::V1,
    }
}

/// Lends a pair's server connection to session calls, as the driver does.
struct Lender {
    wake: Arc<ConnWake>,
    dirty: bool,
}

impl Lender {
    fn new() -> Self {
        Self {
            wake: ConnWake::new(
                Arc::new(Shared::default()),
                ConnKey {
                    index: 0,
                    generation: 0,
                },
            ),
            dirty: false,
        }
    }

    fn lend<'a>(&'a mut self, pair: &'a mut Pair) -> Conn<'a> {
        Conn::new(
            pair.server.conn_mut(),
            pair.now,
            &self.wake,
            &mut self.dirty,
        )
    }

    /// Hands `session` the events `events` of the pair's server connection.
    fn deliver(
        &mut self,
        pair: &mut Pair,
        session: &mut impl QuicSession,
        events: impl IntoIterator<Item = ConnEvent>,
    ) {
        for event in events {
            session.on_event(&mut self.lend(pair), event);
        }
    }
}

/// Returns the session that `router` makes for the attempt of [`info`], as the driver has it made
/// when a client's first Initial arrives.
fn accepted<A: QuicApplication, B: QuicApplication>(
    mut router: AlpnRouter<A, B>,
) -> AlpnSession<A, B> {
    router
        .accept(&info(), &mut ConnOptions::default())
        .expect("the router accepts every attempt")
}

/// Returns the server's events of a pair whose handshake has completed, split before `Connected`.
fn split_at_connected(pair: &Pair) -> (Vec<ConnEvent>, Vec<ConnEvent>) {
    let mut early = pair.server.events.clone();
    let connected = early
        .iter()
        .position(|event| *event == ConnEvent::Connected)
        .expect("the server's handshake completed");
    let rest = early.split_off(connected);
    (early, rest)
}

#[test]
fn a_connection_goes_to_the_application_of_its_alpn_once_when_its_handshake_completes() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let (early, rest) = split_at_connected(&pair);
    assert!(
        !early.is_empty(),
        "events come before the handshake completes"
    );
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();

    lender.deliver(&mut pair, &mut session, early);
    assert_eq!(
        calls.borrow()[..],
        [],
        "the session is not routed before the handshake completes"
    );

    session.on_event(&mut lender.lend(&mut pair), ConnEvent::Connected);
    let routed = calls.take();
    assert_eq!(routed.first(), Some(&Call::Accept("moqt", info())));
    assert_eq!(
        routed.last(),
        Some(&Call::Event("moqt", ConnEvent::Connected))
    );
    assert_eq!(
        routed
            .iter()
            .filter(|call| matches!(call, Call::Accept(..)))
            .count(),
        1,
        "{routed:?}"
    );
    assert!(
        routed
            .iter()
            .all(|call| !matches!(call, Call::Accept("h3", _) | Call::Event("h3", _))),
        "{routed:?}"
    );

    let later = rest[1..].to_vec();
    assert!(later.contains(&ConnEvent::Confirmed));
    lender.deliver(&mut pair, &mut session, later.clone());
    assert_eq!(
        calls.take(),
        later
            .into_iter()
            .map(|event| Call::Event("moqt", event))
            .collect::<Vec<_>>(),
        "later events go to the routed session without routing again"
    );
}

#[test]
fn a_routed_session_receives_every_call_and_gives_its_answers() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[H3]);
    let calls = Calls::default();
    let at = pair.now + Duration::from_secs(3);
    let mut h3 = Fake::new("h3", &calls);
    h3.deadline = Some(at);
    let mut moqt = Fake::new("moqt", &calls);
    moqt.deadline = Some(at);
    let made = AlpnSession::<Fake, Fake>::second(moqt.session());
    let mut routed = accepted(AlpnRouter::new([H3], h3, [MOQT], moqt));
    let mut lender = Lender::new();
    let events = pair.server.events.clone();
    lender.deliver(&mut pair, &mut routed, events);

    for (mut session, name) in [(routed, "h3"), (made, "moqt")] {
        calls.take();
        let id = pair
            .server
            .conn_mut()
            .open_stream(Dir::Bi, ORDER)
            .expect("a stream opens");
        let mut cx = Context::from_waker(Waker::noop());
        session.on_stream(&mut lender.lend(&mut pair), id, StreamReady::Writable);
        let sent = session.poll_send(
            &mut cx,
            id,
            &mut SendSink::new(
                pair.server
                    .conn_mut()
                    .stream(id)
                    .expect("the stream is open"),
            ),
        );
        let now = pair.now;
        let datagrams =
            session.poll_datagrams(&mut cx, &mut DatagramSink::new(pair.server.conn_mut(), now));
        let polled = session.poll_session(&mut cx, &mut lender.lend(&mut pair));
        session.on_quiesce(&mut lender.lend(&mut pair));

        assert_eq!(
            [sent, datagrams, polled],
            [Poll::Ready(()); 3],
            "{name}: the session's answers come back"
        );
        assert_eq!(session.deadline(), Some(at), "{name}");
        assert_eq!(
            calls.take(),
            [
                Call::Stream(name, id, StreamReady::Writable),
                Call::PollSend(name, id),
                Call::PollDatagrams(name),
                Call::PollSession(name),
                Call::SessionQuiesce(name),
            ]
        );
    }
}

#[test]
fn a_routed_session_receives_the_events_from_before_the_handshake_completed_in_order() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let events = pair.server.events.clone();
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();
    lender.deliver(&mut pair, &mut session, events.clone());
    assert_eq!(
        calls.take(),
        std::iter::once(Call::Accept("moqt", info()))
            .chain(events.into_iter().map(|event| Call::Event("moqt", event)))
            .collect::<Vec<_>>(),
        "the session receives the events a session of its own endpoint receives"
    );
}

#[test]
fn a_routed_session_receives_the_stream_edges_from_before_the_handshake_completed_in_order() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let id = pair
        .client
        .conn_mut()
        .open_stream(Dir::Bi, ORDER)
        .expect("a stream opens");
    {
        let mut stream = pair
            .client
            .conn_mut()
            .stream(id)
            .expect("the stream is open");
        stream
            .send(&mut Bytes::from_static(b"ping"))
            .expect("the stream takes data");
        stream.finish().expect("the stream finishes");
    }
    let limit = pair.now + Duration::from_secs(1);
    pair.run(limit);
    let edges: Vec<_> = pair.server.conn_mut().readiness().collect();
    assert!(edges.iter().any(|(edge, _)| *edge == id), "{edges:?}");
    let (early, rest) = split_at_connected(&pair);
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();

    // The edges come among the events from before `Connected`, as 0-RTT stream data would.
    lender.deliver(&mut pair, &mut session, early[..1].to_vec());
    for &(id, ready) in &edges {
        session.on_stream(&mut lender.lend(&mut pair), id, ready);
    }
    lender.deliver(&mut pair, &mut session, [&early[1..], &rest].concat());

    let expected: Vec<Call> = std::iter::once(Call::Accept("moqt", info()))
        .chain(
            early[..1]
                .iter()
                .map(|event| Call::Event("moqt", event.clone())),
        )
        .chain(
            edges
                .iter()
                .map(|&(id, ready)| Call::Stream("moqt", id, ready)),
        )
        .chain(
            early[1..]
                .iter()
                .chain(&rest)
                .map(|event| Call::Event("moqt", event.clone())),
        )
        .collect();
    assert_eq!(
        calls.take(),
        expected,
        "the session receives the stream edges in their place among the events"
    );
}

#[test]
fn a_routed_session_is_polled_after_routing_as_a_new_session_is() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let (early, _) = split_at_connected(&pair);
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();
    lender.deliver(&mut pair, &mut session, early);
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        session.poll_session(&mut cx, &mut lender.lend(&mut pair)),
        Poll::Pending
    );
    assert_eq!(
        lender.wake.take(),
        0,
        "the session is not woken before it is routed"
    );

    session.on_event(&mut lender.lend(&mut pair), ConnEvent::Connected);
    assert_eq!(
        lender.wake.take(),
        wake::APP,
        "routing wakes the session, so the driver polls it as it polls a new one"
    );
}

#[test]
fn a_session_quiesced_before_it_is_routed_is_quiesced_once_routed() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let (early, rest) = split_at_connected(&pair);
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();
    lender.deliver(&mut pair, &mut session, early.clone());
    session.on_quiesce(&mut lender.lend(&mut pair));
    assert_eq!(calls.borrow()[..], []);

    lender.deliver(&mut pair, &mut session, rest.clone());
    let expected: Vec<Call> = std::iter::once(Call::Accept("moqt", info()))
        .chain(early.into_iter().map(|event| Call::Event("moqt", event)))
        .chain([
            Call::Event("moqt", ConnEvent::Connected),
            Call::SessionQuiesce("moqt"),
        ])
        .chain(
            rest[1..]
                .iter()
                .map(|event| Call::Event("moqt", event.clone())),
        )
        .collect();
    assert_eq!(calls.take(), expected);
}

#[test]
fn a_quiesce_of_the_router_reaches_both_applications() {
    let calls = Calls::default();
    fake_router(&calls).quiesce();
    assert_eq!(
        calls.take(),
        [Call::AppQuiesce("h3"), Call::AppQuiesce("moqt")]
    );
}

/// Returns whether the server closed the connection of `pair`'s client with CONNECTION_REFUSED,
/// after running the pair for a while.
fn refused_by_server(pair: &mut Pair) -> bool {
    let limit = pair.now + Duration::from_secs(5);
    pair.run(limit);
    pair.client.events.iter().any(|event| {
        matches!(
            event,
            ConnEvent::Closed {
                reason: CloseReason::Transport {
                    code: TransportErrorCode::CONNECTION_REFUSED,
                    ..
                },
                initiator: Initiator::Peer,
            }
        )
    })
}

#[test]
fn a_connection_whose_alpn_is_not_routed_closes_with_connection_refused() {
    const HQ: &[u8] = b"hq-interop";
    let mut pair = handshaken_pair_offering(&[H3, MOQT, HQ], &[HQ]);
    assert_eq!(pair.server.conn().alpn(), Some(HQ));
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();
    let events = pair.server.events.clone();
    lender.deliver(&mut pair, &mut session, events);

    assert_eq!(
        calls.borrow()[..],
        [],
        "the connection does not reach either application"
    );
    assert_eq!(
        lender.wake.take(),
        0,
        "a refused connection's session is not woken"
    );
    assert!(refused_by_server(&mut pair), "{:?}", pair.client.events);
}

#[test]
fn a_connection_its_application_refuses_closes_with_connection_refused() {
    for refusal in [Refusal::Refuse, Refusal::VersionNegotiation] {
        let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
        let calls = Calls::default();
        let mut moqt = Fake::new("moqt", &calls);
        moqt.refusal = Some(refusal);
        let mut session = accepted(AlpnRouter::new([H3], Fake::new("h3", &calls), [MOQT], moqt));
        let mut lender = Lender::new();
        let events = pair.server.events.clone();
        lender.deliver(&mut pair, &mut session, events);

        assert_eq!(calls.take(), [Call::Accept("moqt", info())], "{refusal:?}");
        assert_eq!(lender.wake.take(), 0, "{refusal:?}");
        assert!(
            refused_by_server(&mut pair),
            "{refusal:?}: {:?}",
            pair.client.events
        );
    }
}

#[test]
fn a_connection_its_application_ignores_ends_without_a_close() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let calls = Calls::default();
    let mut moqt = Fake::new("moqt", &calls);
    moqt.refusal = Some(Refusal::Ignore);
    let mut session = accepted(AlpnRouter::new([H3], Fake::new("h3", &calls), [MOQT], moqt));
    let mut lender = Lender::new();
    let events = pair.server.events.clone();
    lender.deliver(&mut pair, &mut session, events);

    assert_eq!(calls.take(), [Call::Accept("moqt", info())]);
    assert_eq!(
        pair.server.conn_mut().poll_event(),
        Some(ConnEvent::Closed {
            reason: CloseReason::Silent,
            initiator: Initiator::Local,
        }),
        "the server's connection ends at once"
    );
    // The client's next packets reach an endpoint without the connection, which may answer them
    // with a stateless reset.
    let limit = pair.now + Duration::from_secs(5);
    pair.run(limit);
    assert!(
        !pair.client.events.iter().any(|event| matches!(
            event,
            ConnEvent::Closed {
                initiator: Initiator::Peer,
                ..
            }
        )),
        "the client does not receive a CONNECTION_CLOSE: {:?}",
        pair.client.events
    );
}

#[test]
fn a_router_behind_a_router_serves_a_third_application() {
    const HQ: &[u8] = b"hq-interop";
    let mut pair = handshaken_pair_offering(&[H3, MOQT, HQ], &[HQ]);
    let events = pair.server.events.clone();
    let calls = Calls::default();
    let inner = AlpnRouter::new(
        [MOQT],
        Fake::new("moqt", &calls),
        [HQ],
        Fake::new("hq", &calls),
    );
    let mut session = accepted(AlpnRouter::new(
        [H3],
        Fake::new("h3", &calls),
        [MOQT, HQ],
        inner,
    ));
    let mut lender = Lender::new();
    lender.deliver(&mut pair, &mut session, events.clone());
    assert_eq!(
        calls.take(),
        std::iter::once(Call::Accept("hq", info()))
            .chain(events.into_iter().map(|event| Call::Event("hq", event)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_connection_without_a_negotiated_alpn_protocol_closes_with_connection_refused() {
    let mut pair = handshaken_pair_without_alpn();
    assert_eq!(pair.server.conn().alpn(), None);
    let calls = Calls::default();
    let mut session = accepted(fake_router(&calls));
    let mut lender = Lender::new();
    let events = pair.server.events.clone();
    lender.deliver(&mut pair, &mut session, events);

    assert_eq!(
        calls.borrow()[..],
        [],
        "the connection does not reach either application"
    );
    assert!(refused_by_server(&mut pair), "{:?}", pair.client.events);
}

#[test]
fn a_protocol_that_both_applications_list_goes_to_the_first() {
    let mut pair = handshaken_pair_offering(&[H3, MOQT], &[MOQT]);
    let calls = Calls::default();
    let mut session = accepted(AlpnRouter::new(
        [MOQT],
        Fake::new("first", &calls),
        [MOQT],
        Fake::new("second", &calls),
    ));
    let mut lender = Lender::new();
    let events = pair.server.events.clone();
    lender.deliver(&mut pair, &mut session, events);

    let calls = calls.take();
    assert_eq!(calls.first(), Some(&Call::Accept("first", info())));
    assert!(
        calls
            .iter()
            .all(|call| !matches!(call, Call::Accept("second", _) | Call::Event("second", _))),
        "{calls:?}"
    );
}
