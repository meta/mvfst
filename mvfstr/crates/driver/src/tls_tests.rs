/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the driver's TLS host loop: endpoint drivers in the lab, one of them running its
//! handshakes on a host that answers each input at once or later, and charges each call a set
//! cost on the test clock.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::mem;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

use bytes::Bytes;
use mvfstr_io::Backend;
use mvfstr_proto::AppCode;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ClientTls;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::ServerTls;
use mvfstr_proto::TlsConnId;
use mvfstr_proto::TlsHost;
use mvfstr_proto::TlsInput;
use mvfstr_proto::TlsPoll;
use mvfstr_proto::TlsStep;
use mvfstr_tls::Level;
use mvfstr_tls::testing::RustlsHost;
use rustls::pki_types::ServerName;

use crate::ConnHandle;
use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::UnitKind;
use crate::WorkBudget;
use crate::lab::Arrival;
use crate::lab::Bulk;
use crate::lab::Costs;
use crate::lab::DELAY;
use crate::lab::Lab;
use crate::lab::LabApp;
use crate::lab::MemBackend;
use crate::lab::MemOptions;
use crate::lab::Net;
use crate::lab::NetEvent;
use crate::lab::Probe;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::nth_socket;
use crate::lab::transport;
use crate::test_support::client_config_offering;
use crate::turn::Limits;
use crate::turn::Mark;
use crate::turn::Phase;

type Handle = EndpointHandle<LabApp, MemBackend>;

/// The slice of the tests' work budgets.
const SLICE: Duration = Duration::from_millis(1);

/// What each `poll_ready` call costs in the async drain's budget test.
const CALL: Duration = Duration::from_micros(300);

/// The TLS handshake_failure alert (RFC 8446).
const HANDSHAKE_FAILURE: u8 = 40;

/// Returns the phase a poll stopped in.
fn stop(marks: &[Mark]) -> Option<Phase> {
    marks.iter().find_map(|mark| match mark {
        Mark::Stop(phase) => Some(*phase),
        _ => None,
    })
}

/// The kind of an input a [`LabHost`] was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Start,
    Crypto(Level),
    Ticket,
    Finish,
}

impl Input {
    fn of(input: &TlsInput<'_>) -> Self {
        match input {
            TlsInput::Start { .. } => Self::Start,
            TlsInput::Crypto { level, .. } => Self::Crypto(*level),
            TlsInput::WriteTicket { .. } => Self::Ticket,
            TlsInput::Finish => Self::Finish,
        }
    }
}

/// A call into a [`LabHost`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Handle(TlsConnId, Input),
    /// A `poll_ready` call, with the connection of the step it returned.
    Ready(Option<TlsConnId>),
    Cancel(TlsConnId),
}

/// The settings, state and call log of a [`LabHost`], shared with its test.
#[derive(Default)]
struct HostLog {
    /// Whether each input's step waits for [`complete`](Self::complete) instead of coming back at
    /// once.
    deferred: Cell<bool>,
    /// Whether a deferred step completes inside the call that was handed its input.
    completes_in_call: Cell<bool>,
    /// The connection whose inputs the host panics on.
    panics_on: Cell<Option<TlsConnId>>,
    /// The connection whose cancel the host panics on.
    cancel_panics_on: Cell<Option<TlsConnId>>,
    /// The connection whose ClientHello the host refuses with a handshake_failure alert.
    refuses: Cell<Option<TlsConnId>>,
    /// What each call charges to the test clock.
    cost: Cell<Duration>,
    /// Each call, with the length the net's event log had when it came.
    calls: RefCell<Vec<(Call, usize)>>,
    /// Steps of inputs answered `Pending` and not completed yet.
    held: RefCell<Vec<(TlsConnId, TlsStep)>>,
    /// Steps completed and not returned by `poll_ready` yet, oldest first.
    ready: RefCell<VecDeque<(TlsConnId, TlsStep)>>,
    /// The driver's waker for completed steps.
    waker: RefCell<Option<Waker>>,
}

impl HostLog {
    /// Completes every held step, in the order their inputs came, and wakes the driver.
    fn complete(&self) {
        let held = mem::take(&mut *self.held.borrow_mut());
        self.ready.borrow_mut().extend(held);
        if let Some(waker) = self.waker.borrow().as_ref() {
            waker.wake_by_ref();
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls_since(0)
    }

    fn calls_since(&self, start: usize) -> Vec<Call> {
        self.calls.borrow()[start..]
            .iter()
            .map(|(call, _)| *call)
            .collect()
    }

    /// Returns the length the net's event log had when call `call` came.
    fn events_at(&self, call: usize) -> usize {
        self.calls.borrow()[call].1
    }

    fn len(&self) -> usize {
        self.calls.borrow().len()
    }
}

/// A TLS host for the lab: rustls behind the External interface, whose calls each charge a set
/// cost to the test clock and go into a log, and which can hold each step for later.
struct LabHost {
    inner: RustlsHost,
    net: Net,
    log: Rc<HostLog>,
}

impl LabHost {
    fn log(&self, call: Call) {
        let events = self.net.events().len();
        self.log.calls.borrow_mut().push((call, events));
    }
}

impl TlsHost for LabHost {
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        self.net.charge(self.log.cost.get());
        self.log(Call::Handle(conn, Input::of(&input)));
        if self.log.panics_on.get() == Some(conn) {
            panic!("an injected TLS host bug");
        }
        let refused =
            self.log.refuses.get() == Some(conn) && matches!(input, TlsInput::Crypto { .. });
        let step = if refused {
            TlsStep {
                alert: Some(HANDSHAKE_FAILURE),
                ..TlsStep::default()
            }
        } else {
            let TlsPoll::Ready(step) = self.inner.handle(conn, input) else {
                panic!("the rustls host answers each input at once");
            };
            step
        };
        if self.log.deferred.get() {
            self.log.held.borrow_mut().push((conn, step));
            if self.log.completes_in_call.get() {
                self.log.complete();
            }
            return TlsPoll::Pending;
        }
        TlsPoll::Ready(step)
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        self.net.charge(self.log.cost.get());
        let next = self.log.ready.borrow_mut().pop_front();
        self.log(Call::Ready(next.as_ref().map(|(conn, _)| *conn)));
        next
    }

    fn cancel(&mut self, conn: TlsConnId) {
        self.net.charge(self.log.cost.get());
        self.log(Call::Cancel(conn));
        if self.log.cancel_panics_on.get() == Some(conn) {
            panic!("an injected TLS host bug");
        }
        self.inner.cancel(conn);
        self.log.held.borrow_mut().retain(|(held, _)| *held != conn);
        self.log
            .ready
            .borrow_mut()
            .retain(|(ready, _)| *ready != conn);
    }
}

/// Which driver of a [`TlsScene`] runs its handshakes on its [`LabHost`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hosted {
    Server,
    Client,
}

/// A server driver and a client driver on one lab worker, one of them with a [`LabHost`] and,
/// if given, a work budget.
struct TlsScene {
    server: Handle,
    server_task: usize,
    client: Handle,
    client_task: usize,
    client_config: Arc<ClientConfig>,
    host: Rc<HostLog>,
    /// The server sessions' probes, in accept order.
    accepted: Rc<RefCell<Vec<Rc<Probe>>>>,
    /// The client sessions' probes, in connect order.
    clients: Vec<Rc<Probe>>,
    /// The client connections' handles, in connect order.
    conns: Vec<ConnHandle>,
    lab: Lab,
}

impl TlsScene {
    fn new(hosted: Hosted, budget: Option<WorkBudget>) -> Self {
        Self::with_limits(hosted, budget, Limits::default())
    }

    /// Returns a scene whose hosted driver runs with the per-turn caps `limits`.
    fn with_limits(hosted: Hosted, budget: Option<WorkBudget>, limits: Limits) -> Self {
        let lab = Lab::new();
        let (client_config, server_config, endpoint) = lab_configs();
        let host = Rc::new(HostLog::default());
        let lab_host = |inner| -> Box<dyn TlsHost> {
            Box::new(LabHost {
                inner,
                net: lab.net.clone(),
                log: Rc::clone(&host),
            })
        };
        let accepted: Rc<RefCell<Vec<Rc<Probe>>>> = Rc::default();
        let net = lab.net.clone();
        let probes = Rc::clone(&accepted);
        let app = LabApp::new(&lab.net, move |_, options| {
            options.transport = Some(transport(false));
            let (session, probe) = Bulk::new(&net, 0, Some(0));
            probes.borrow_mut().push(probe);
            session
        });
        let options = MemOptions {
            net: Some(lab.net.clone()),
            ..MemOptions::default()
        };
        let socket = MemBackend::bind(SERVER, &options).expect("the lab binds");
        let mut server = EndpointDriver::builder(Arc::clone(&endpoint), app);
        let mut server_config = server_config;
        if hosted == Hosted::Server {
            let tls = server_config.tls().rustls().expect("a rustls server");
            server = server.tls_host(lab_host(RustlsHost::server(Arc::clone(tls))));
            server_config = ServerConfig::builder(ServerTls::External)
                .build()
                .expect("an External server config");
            if let Some(budget) = &budget {
                server = server.work_budget(budget.clone());
            }
            server = server.limits(limits);
        }
        let server = server
            .serve(socket, server_config)
            .backend_options(options.clone())
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the server starts");
        let server_task = lab.last_spawned();
        let mut client = EndpointDriver::builder(Arc::clone(&endpoint), LabApp::client(&lab.net));
        let mut client_config = client_config;
        if hosted == Hosted::Client {
            let tls = client_config.tls().rustls().expect("a rustls client");
            client = client.tls_host(lab_host(RustlsHost::client(Arc::clone(tls))));
            client_config = ClientConfig::builder(ClientTls::External)
                .build()
                .expect("an External client config");
            if let Some(budget) = &budget {
                client = client.work_budget(budget.clone());
            }
            client = client.limits(limits);
        }
        let client = client
            .backend_options(options)
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the client starts");
        let client_task = lab.last_spawned();
        Self {
            server,
            server_task,
            client,
            client_task,
            client_config,
            host,
            accepted,
            clients: Vec::new(),
            conns: Vec::new(),
            lab,
        }
    }

    /// Opens a client connection to the server, with a session that does not send.
    fn connect(&mut self) -> Rc<Probe> {
        let (session, probe) = Bulk::new(&self.lab.net, 0, Some(0));
        let conn = self
            .client
            .connect(
                SERVER,
                ServerName::try_from("localhost").expect("a name"),
                Arc::clone(&self.client_config),
                ConnOptions {
                    transport: Some(transport(false)),
                },
                session,
            )
            .expect("the client connects");
        self.conns.push(conn);
        self.clients.push(Rc::clone(&probe));
        probe
    }

    /// Polls the server once and returns what the poll did.
    fn poll_server(&self) -> Vec<Mark> {
        let before = self.server.tx_record().marks.len();
        assert!(self.lab.poll(self.server_task), "the server is woken");
        self.server.tx_record().marks[before..].to_vec()
    }

    /// Polls the hosted driver once and returns, for each turn the poll began, the number of
    /// handshakes started on the host.
    fn starts_per_turn(&self, hosted: Hosted) -> Vec<usize> {
        let (driver, task) = match hosted {
            Hosted::Server => (&self.server, self.server_task),
            Hosted::Client => (&self.client, self.client_task),
        };
        let before = driver.tx_record().marks.len();
        let calls = self.host.len();
        assert!(self.lab.poll(task), "the hosted driver is woken");
        let mut calls = self.host.calls_since(calls).into_iter();
        let mut starts = Vec::new();
        for mark in &driver.tx_record().marks[before..] {
            match mark {
                Mark::Turn => starts.push(0),
                Mark::TlsCall => {
                    if let Some(Call::Handle(_, Input::Start)) = calls.next()
                        && let Some(turn) = starts.last_mut()
                    {
                        *turn += 1;
                    }
                }
                _ => {}
            }
        }
        starts
    }

    /// Returns the number of datagrams that the server built before its first flush since the
    /// events were last cleared, which that flush sent.
    fn first_server_flush(&self) -> usize {
        let events = self.lab.net.events();
        let flush = events
            .iter()
            .position(|event| *event == NetEvent::Flush(SERVER))
            .expect("the server flushed");
        events[..flush]
            .iter()
            .map(|event| match event {
                NetEvent::Built(addr, _, built) if *addr == SERVER => usize::from(*built),
                _ => 0,
            })
            .sum()
    }

    /// Hands the client's socket the first `datagrams` held for it, then polls every task but
    /// the server's while any of them is woken.
    fn deliver_held(&self, datagrams: usize) {
        for arrival in self.lab.net.take_held().into_iter().take(datagrams) {
            self.lab.net.inject(nth_socket(0), arrival);
        }
        self.lab.settle_except(Some(self.server_task));
    }
}

#[test]
fn with_a_sync_host_the_servers_flight_leaves_in_the_turn_that_read_the_client_hello() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    let client = scene.connect();
    scene.lab.settle();
    scene.lab.net.hold(nth_socket(0));
    scene.lab.advance(DELAY);
    scene.lab.net.clear_events();
    let marks = scene.poll_server();
    let accept = marks
        .iter()
        .position(|mark| matches!(mark, Mark::Accept(_)))
        .expect("the server accepts the connection");
    let flush = marks
        .iter()
        .position(|mark| *mark == Mark::Flush)
        .expect("a transmit phase flushes");
    assert!(
        accept < flush && !marks[accept..flush].contains(&Mark::Turn),
        "the first flush after the accept ends a phase of the accept's turn: {marks:?}"
    );
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
        ],
        "the host has the ClientHello and nothing more"
    );
    scene.deliver_held(scene.first_server_flush());
    assert!(
        client.connected.get(),
        "the client completes its handshake from what that flush sent"
    );
}

#[test]
fn the_host_has_the_input_a_receive_leaves_before_the_turn_transmits_again() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    let client = scene.connect();
    scene.lab.run_until(|| client.connected.get());
    scene.lab.net.clear_events();
    let before = scene.host.len();
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Handshake)),
            Call::Handle(TlsConnId(0), Input::Ticket),
            Call::Handle(TlsConnId(0), Input::Finish),
        ],
        "the host reads the client's Finished, writes a ticket and frees its state"
    );
    let events = scene.lab.net.events();
    let call = scene.host.events_at(before);
    let recv = events[..call]
        .iter()
        .rposition(|event| matches!(event, NetEvent::Recv(addr, _) if *addr == SERVER))
        .expect("the server received the client's Finished before the call");
    assert!(
        !events[recv..call].contains(&NetEvent::Flush(SERVER)),
        "no transmit phase ran between the receive and the call: {events:?}"
    );
    assert!(
        events[call..].contains(&NetEvent::Flush(SERVER)),
        "a transmit phase of the poll sent what the steps wrote: {events:?}"
    );
    assert!(
        scene.accepted.borrow()[0].connected.get(),
        "the server's handshake completes"
    );
}

#[test]
fn with_an_async_host_each_step_lands_in_a_later_turn_its_wake_runs() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    let client = scene.connect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "the host holds the start"
    );
    assert!(!scene.lab.queued(scene.server_task), "the server waits");
    scene.host.complete();
    let before = scene.host.len();
    scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Ready(Some(TlsConnId(0))),
            Call::Ready(None),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
        ],
        "the woken server takes the start's step and hands over the ClientHello"
    );
    assert!(!scene.lab.queued(scene.server_task), "the server waits");
    scene.lab.net.hold(nth_socket(0));
    scene.lab.net.clear_events();
    scene.host.complete();
    let before = scene.host.len();
    let marks = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [Call::Ready(Some(TlsConnId(0))), Call::Ready(None)],
        "the woken server takes the ClientHello's step"
    );
    let turn = marks
        .iter()
        .position(|mark| *mark == Mark::Turn)
        .expect("the poll runs a turn");
    let flush = marks
        .iter()
        .position(|mark| *mark == Mark::Flush)
        .expect("a transmit phase flushes");
    assert!(
        turn < flush && !marks[turn + 1..flush].contains(&Mark::Turn),
        "the turn that takes the step flushes: {marks:?}"
    );
    scene.deliver_held(scene.first_server_flush());
    assert!(
        client.connected.get(),
        "the client completes its handshake from what that flush sent"
    );
}

#[test]
fn a_step_the_host_completes_inside_its_call_lands_in_the_same_poll() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.deferred.set(true);
    scene.host.completes_in_call.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    let client = scene.connect();
    scene.lab.settle();
    scene.lab.net.hold(nth_socket(0));
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Ready(Some(TlsConnId(0))),
            Call::Ready(None),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
            Call::Ready(Some(TlsConnId(0))),
            Call::Ready(None),
        ],
        "the poll takes each step its call completed"
    );
    scene.deliver_held(usize::MAX);
    assert!(
        client.connected.get(),
        "the client completes its handshake from what the poll sent"
    );
}

#[test]
fn a_turn_starts_hosted_handshakes_up_to_its_handshake_cap_and_the_next_turn_the_rest() {
    let mut scene = TlsScene::new(Hosted::Client, None);
    let clients: Vec<_> = (0..10).map(|_| scene.connect()).collect();
    let starts: Vec<usize> = scene
        .starts_per_turn(Hosted::Client)
        .into_iter()
        .filter(|&starts| starts > 0)
        .collect();
    assert_eq!(
        starts,
        [8, 2],
        "the poll's turns start 8 handshakes, then 2"
    );
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// The host holds every step, so the turn that starts the first handshake does not leave anything
/// to send, and only the second handshake, held back by a cap of one per turn, is left to do.
#[test]
fn a_handshake_the_turns_cap_holds_back_starts_in_a_later_turn_of_the_same_poll() {
    let limits = Limits {
        handshakes: 1,
        ..Limits::default()
    };
    let mut scene = TlsScene::with_limits(Hosted::Client, None, limits);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.client.tls_waker();
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    let starts: Vec<usize> = scene
        .starts_per_turn(Hosted::Client)
        .into_iter()
        .filter(|&starts| starts > 0)
        .collect();
    assert_eq!(
        starts,
        [1, 1],
        "the poll runs another turn for the handshake still due a call"
    );
    scene.host.deferred.set(false);
    scene.host.complete();
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// The host holds every step, so a started handshake leaves the list, and under a cap of one
/// handshake per turn each turn starts one of four.
#[test]
fn a_turn_whose_handshake_cap_is_spent_leaves_the_handshakes_waiting_to_start_untouched() {
    let limits = Limits {
        handshakes: 1,
        ..Limits::default()
    };
    let mut scene = TlsScene::with_limits(Hosted::Client, None, limits);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.client.tls_waker();
    let clients: Vec<_> = (0..4).map(|_| scene.connect()).collect();
    let before = scene.client.tx_record().marks.len();
    while scene.lab.queued(scene.client_task) {
        scene.lab.poll(scene.client_task);
    }
    let mut taken: Vec<usize> = Vec::new();
    for mark in &scene.client.tx_record().marks[before..] {
        match mark {
            Mark::Turn => taken.push(0),
            Mark::TlsTaken(_) => *taken.last_mut().expect("inside a turn") += 1,
            _ => {}
        }
    }
    taken.retain(|&taken| taken > 0);
    assert_eq!(
        taken,
        [1, 1, 1, 1],
        "each turn takes from the lists only the handshake it starts"
    );
    assert_eq!(scene.host.len(), 4, "the host has the four starts");
    scene.host.deferred.set(false);
    scene.host.complete();
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Each client's ClientHello spans two datagrams, and a server's host does not get an input until
/// the whole ClientHello has arrived. Under a cap of one handshake per turn, the server accepts one
/// connection per poll from the first datagrams; the second datagrams then arrive together.
#[test]
fn a_handshake_accepted_in_an_earlier_turn_counts_against_the_cap_of_the_turn_it_starts() {
    let limits = Limits {
        handshakes: 1,
        ..Limits::default()
    };
    let mut scene = TlsScene::with_limits(Hosted::Server, None, limits);
    scene.client_config = client_config_offering(&[&[b'x'; 200][..]; 5]);
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.net.hold(SERVER);
    scene.lab.settle_except(Some(scene.server_task));
    let held = scene.lab.net.take_held();
    let sent = |n: u16| -> Vec<Arrival> {
        held.iter()
            .filter(|arrival| arrival.src == nth_socket(n))
            .cloned()
            .collect()
    };
    let (first, second) = (sent(0), sent(1));
    assert_eq!(
        (first.len(), second.len()),
        (2, 2),
        "each client sends its ClientHello in two datagrams"
    );
    for (accepts, arrival) in [&first[0], &second[0]].into_iter().enumerate() {
        scene.lab.net.inject(SERVER, arrival.clone());
        scene.poll_server();
        assert_eq!(
            scene.accepted.borrow().len(),
            accepts + 1,
            "the poll accepts the connection"
        );
    }
    assert_eq!(
        scene.host.calls(),
        [],
        "the host has no input before a whole ClientHello"
    );
    scene.lab.net.inject(SERVER, first[1].clone());
    scene.lab.net.inject(SERVER, second[1].clone());
    let starts: Vec<usize> = scene
        .starts_per_turn(Hosted::Server)
        .into_iter()
        .filter(|&starts| starts > 0)
        .collect();
    assert_eq!(
        starts,
        [1, 1],
        "the turn that completes both ClientHellos starts one handshake, and the next turn the \
         other"
    );
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Under a cap of one handshake per turn, the first client's ClientHello spans two datagrams and
/// the server accepts its connection from the first. The second then arrives with the Initials of
/// four new clients, which the server accepts one per turn.
#[test]
fn a_handshake_accepted_in_an_earlier_turn_starts_ahead_of_the_connections_later_turns_accept() {
    let limits = Limits {
        handshakes: 1,
        ..Limits::default()
    };
    let mut scene = TlsScene::with_limits(Hosted::Server, None, limits);
    let plain = mem::replace(
        &mut scene.client_config,
        client_config_offering(&[&[b'x'; 200][..]; 5]),
    );
    let mut clients = vec![scene.connect()];
    scene.client_config = plain;
    clients.extend((0..4).map(|_| scene.connect()));
    scene.lab.net.hold(SERVER);
    scene.lab.settle_except(Some(scene.server_task));
    let held = scene.lab.net.take_held();
    let sent = |n: u16| -> Vec<Arrival> {
        held.iter()
            .filter(|arrival| arrival.src == nth_socket(n))
            .cloned()
            .collect()
    };
    let first = sent(0);
    assert_eq!(
        first.len(),
        2,
        "the first client's ClientHello takes two datagrams"
    );
    scene.lab.net.inject(SERVER, first[0].clone());
    scene.poll_server();
    assert_eq!(scene.accepted.borrow().len(), 1, "the poll accepts it");
    scene.lab.net.inject(SERVER, first[1].clone());
    for n in 1..=4 {
        let initial = sent(n);
        assert_eq!(
            initial.len(),
            1,
            "a new client's ClientHello takes one datagram"
        );
        scene.lab.net.inject(SERVER, initial[0].clone());
    }
    while scene.lab.queued(scene.server_task) {
        scene.poll_server();
    }
    let starts: Vec<TlsConnId> = scene
        .host
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Handle(conn, Input::Start) => Some(conn),
            _ => None,
        })
        .collect();
    assert_eq!(
        starts,
        (0..5).map(TlsConnId).collect::<Vec<_>>(),
        "the handshake accepted first starts first, though each later turn accepts a new \
         connection"
    );
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Four handshakes, two calls each at 400 µs, under a 1 ms slice: the third call, the second
/// handshake's start, closes the slice 200 µs past its deadline, so the check before that
/// handshake's ClientHello stops the phase with two handshakes behind it.
#[test]
fn a_slice_that_closes_during_host_call_k_stops_the_due_list_before_call_k_plus_1() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget.clone()));
    let clients: Vec<_> = (0..4).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.host.cost.set(Duration::from_micros(400));
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(1), Input::Start),
        ],
        "{first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Tls), "{first:?}");
    assert_eq!(
        budget.stats().longest_past_us(UnitKind::TlsHostCall),
        200,
        "the third call began 200 µs before the deadline"
    );
    scene.host.cost.set(Duration::ZERO);
    let before = scene.host.len();
    let second = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(2), Input::Start),
            Call::Handle(TlsConnId(2), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(3), Input::Start),
            Call::Handle(TlsConnId(3), Input::Crypto(Level::Initial)),
        ],
        "the next poll hands over the stopped handshake's ClientHello first, then the two \
         behind it in order: {second:?}"
    );
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// The host holds every step. Three handshakes wait to start under a 1 ms slice, and the first
/// start's call, at 1.2 ms, closes the slice 200 µs past its deadline, so the check before the
/// second handshake's start stops the phase. The first start's step then completes, which puts
/// that handshake on the list of those under way.
#[test]
fn a_slice_that_closes_before_a_handshakes_start_leaves_it_first_of_those_waiting_to_start() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget.clone()));
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    let clients: Vec<_> = (0..3).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.host.cost.set(Duration::from_micros(1200));
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "{first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Tls), "{first:?}");
    assert_eq!(
        budget.stats().longest_past_us(UnitKind::TlsHostCall),
        200,
        "the first start's call ran 200 µs past the deadline"
    );
    scene.host.cost.set(Duration::ZERO);
    scene.host.complete();
    while scene.lab.queued(scene.server_task) {
        scene.poll_server();
    }
    assert_eq!(
        scene.host.calls_since(1),
        [
            Call::Ready(Some(TlsConnId(0))),
            Call::Ready(None),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(1), Input::Start),
            Call::Handle(TlsConnId(2), Input::Start),
        ],
        "a later TLS phase hands over the ClientHello of the handshake under way, then starts \
         the stopped handshake and the one behind it, in order"
    );
    scene.host.deferred.set(false);
    scene.host.complete();
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Five held starts completed together, each `poll_ready` call at 300 µs, under a 1 ms slice:
/// the fourth call closes the slice, 200 µs past its deadline.
#[test]
fn a_slice_that_closes_during_host_call_k_stops_the_async_drain_before_call_k_plus_1() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget.clone()));
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    let clients: Vec<_> = (0..5).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    let starts: Vec<Call> = (0..5)
        .map(|n| Call::Handle(TlsConnId(n), Input::Start))
        .collect();
    assert_eq!(scene.host.calls(), starts, "the host holds five starts");
    scene.host.cost.set(CALL);
    scene.host.complete();
    let before = scene.host.len();
    let first = scene.poll_server();
    let taken: Vec<Call> = (0..4).map(|n| Call::Ready(Some(TlsConnId(n)))).collect();
    assert_eq!(scene.host.calls_since(before), taken, "{first:?}");
    assert_eq!(stop(&first), Some(Phase::Intake), "{first:?}");
    assert_eq!(
        budget.stats().longest_past_us(UnitKind::TlsHostCall),
        200,
        "the fourth call began 100 µs before the deadline"
    );
    scene.host.cost.set(Duration::ZERO);
    let before = scene.host.len();
    let second = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(2), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(3), Input::Crypto(Level::Initial)),
            Call::Ready(Some(TlsConnId(4))),
            Call::Ready(None),
            Call::Handle(TlsConnId(4), Input::Crypto(Level::Initial)),
        ],
        "the next poll finishes the stopped turn, then its next intake takes the fifth step: \
         {second:?}"
    );
    scene.host.complete();
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Under a work budget, the server's TLS phase comes after the receive phase that accepted the
/// connection, so its first check is not the poll's first unit.
#[test]
fn a_tls_phase_after_others_in_its_turn_reads_the_clock_once_for_its_steps_and_first_check() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget));
    let client = scene.connect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    let marks = scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
        ],
        "{marks:?}"
    );
    assert_eq!(
        scene.server.tx_record().tls_call_reads,
        [1, 2],
        "the phase's own reading serves its first check, and the check before the second call \
         reads the clock again: {marks:?}"
    );
    scene.lab.run_until(|| client.connected.get());
}

/// Two clients' Initials reach the server in one batch, and each pass over it costs 600 µs under
/// a 1 ms slice: the second pass, after the first accept, closes the slice, so the check before
/// the second accept stops the receive phase.
#[test]
fn a_poll_resumed_after_a_receive_stop_starts_at_the_tls_phase_for_the_handshake_it_accepted() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget));
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.lab.net.set_costs(Costs {
        chunk: Duration::from_micros(600),
        ..Costs::default()
    });
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    assert_eq!(scene.accepted.borrow().len(), 1, "one accept: {first:?}");
    assert_eq!(
        scene.host.calls(),
        [],
        "the host has not had an input: {first:?}"
    );
    scene.lab.net.set_costs(Costs::default());
    let reads = scene.server.tx_record().tls_call_reads.len();
    let second = scene.poll_server();
    assert!(
        matches!(
            second[..],
            [
                Mark::Poll,
                Mark::Phase(Phase::Tls),
                Mark::TlsTaken(_),
                Mark::Unit(UnitKind::TlsHostCall),
                Mark::TlsCall,
                ..
            ]
        ),
        "the next poll resumes at the TLS phase, whose first unit is a call: {second:?}"
    );
    assert_eq!(
        scene.host.calls()[..2],
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
        ],
        "that phase hands the host the accepted handshake's ClientHello: {second:?}"
    );
    assert_eq!(
        scene.server.tx_record().tls_call_reads[reads..reads + 2],
        [0, 1],
        "the phase runs at the poll's reading, and the check before the second call reads the \
         clock: {second:?}"
    );
    scene
        .lab
        .run_until(|| clients.iter().all(|client| client.connected.get()));
}

/// Two handshakes, each call at 600 µs, under a 1 ms slice: the host refuses the first
/// ClientHello, which closes that connection, and the call closes the slice 200 µs past its
/// deadline.
#[test]
fn a_slice_that_closes_in_a_call_failing_its_handshake_stops_the_due_list_before_the_cancel() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget.clone()));
    scene.host.refuses.set(Some(TlsConnId(0)));
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.host.cost.set(Duration::from_micros(600));
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
        ],
        "no call follows the check that stops the phase: {first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Tls), "{first:?}");
    assert_eq!(
        budget.stats().longest_past_us(UnitKind::TlsHostCall),
        200,
        "the refused ClientHello's call ran 200 µs past the deadline"
    );
    scene.host.cost.set(Duration::ZERO);
    let before = scene.host.len();
    let second = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Cancel(TlsConnId(0)),
            Call::Handle(TlsConnId(1), Input::Start),
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
        ],
        "the next poll cancels the refused handshake's state, then starts the other: {second:?}"
    );
    scene.lab.run_until(|| clients[1].connected.get());
}

/// The host holds two handshakes' ClientHello steps and refuses the first. Both complete
/// together, and the call that takes the refused one, at 1.2 ms, closes the 1 ms slice 200 µs
/// past its deadline.
#[test]
fn a_slice_that_closes_in_a_call_failing_its_handshake_stops_the_async_drain_before_the_cancel() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = TlsScene::new(Hosted::Server, Some(budget.clone()));
    scene.host.deferred.set(true);
    scene.host.refuses.set(Some(TlsConnId(0)));
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    scene.host.complete();
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(1), Input::Start),
            Call::Ready(Some(TlsConnId(0))),
            Call::Ready(Some(TlsConnId(1))),
            Call::Ready(None),
            Call::Handle(TlsConnId(0), Input::Crypto(Level::Initial)),
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
        ],
        "the host holds both ClientHellos' steps"
    );
    scene.host.cost.set(Duration::from_micros(1200));
    scene.host.complete();
    let before = scene.host.len();
    let first = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [Call::Ready(Some(TlsConnId(0)))],
        "no call follows the check that stops the drain: {first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Intake), "{first:?}");
    assert_eq!(
        budget.stats().longest_past_us(UnitKind::TlsHostCall),
        200,
        "the call that took the refused step ran 200 µs past the deadline"
    );
    scene.host.cost.set(Duration::ZERO);
    let before = scene.host.len();
    let second = scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [
            Call::Cancel(TlsConnId(0)),
            Call::Ready(Some(TlsConnId(1))),
            Call::Ready(None),
        ],
        "the next poll finishes the stopped turn, whose TLS phase cancels the refused \
         handshake's state, then its next intake takes the other step: {second:?}"
    );
    scene.host.deferred.set(false);
    scene.host.complete();
    scene.lab.run_until(|| clients[1].connected.get());
}

#[test]
fn a_close_a_receive_brings_cancels_the_hosts_state_in_that_turn() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    scene.connect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "the host holds the start"
    );
    scene.conns[0]
        .close(AppCode::from_u32(1), Bytes::new())
        .expect("the client's connection is open");
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    let before = scene.host.len();
    scene.poll_server();
    assert_eq!(
        scene.host.calls_since(before),
        [Call::Cancel(TlsConnId(0))],
        "the poll that receives the close cancels the host's state"
    );
    assert!(
        scene.host.held.borrow().is_empty(),
        "the host drops the step it held"
    );
}

/// The client's host holds its start, so the connection has not sent or received anything.
#[test]
fn a_local_close_cancels_the_hosts_state_in_the_poll_that_closes() {
    let mut scene = TlsScene::new(Hosted::Client, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.client.tls_waker();
    scene.connect();
    scene.lab.settle();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "the host holds the start"
    );
    scene.conns[0]
        .close(AppCode::from_u32(1), Bytes::new())
        .expect("the connection is open");
    let before = scene.host.len();
    scene.lab.settle();
    assert_eq!(
        scene.host.calls_since(before),
        [Call::Cancel(TlsConnId(0))],
        "the close cancels the host's state at once, before its closing period ends"
    );
    assert!(
        scene.host.held.borrow().is_empty(),
        "the host drops the step it held"
    );
}

#[test]
fn a_connection_that_times_out_cancels_the_hosts_state_once() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.server.tls_waker();
    scene.connect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "the host holds the start"
    );
    scene.lab.net.hold(SERVER);
    scene.lab.run_quiet(Duration::from_secs(120));
    assert!(
        scene.accepted.borrow()[0].closed.get(),
        "the server's connection timed out"
    );
    assert_eq!(
        scene.host.calls_since(1),
        [Call::Cancel(TlsConnId(0))],
        "the timeout cancels the host's state, and freeing the connection does not again"
    );
}

/// The client's host holds its start, and its session then aborts the connection, which drains
/// at once and is freed in the same application phase.
#[test]
fn a_session_that_aborts_its_connection_cancels_the_hosts_state_when_it_is_freed() {
    let mut scene = TlsScene::new(Hosted::Client, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.client.tls_waker();
    let client = scene.connect();
    scene.lab.settle();
    assert_eq!(
        scene.host.calls(),
        [Call::Handle(TlsConnId(0), Input::Start)],
        "the host holds the start"
    );
    client.aborts.set(true);
    scene.conns[0].wake().expect("the connection is open");
    let before = scene.host.len();
    scene.lab.settle();
    assert!(client.closed.get(), "the session aborted its connection");
    assert_eq!(
        scene.host.calls_since(before),
        [Call::Cancel(TlsConnId(0))],
        "freeing the connection cancels the host's state"
    );
}

#[test]
fn a_host_that_panics_on_a_connections_input_loses_that_connection_alone_and_is_told_so() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.panics_on.set(Some(TlsConnId(0)));
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    scene.poll_server();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Cancel(TlsConnId(0)),
            Call::Handle(TlsConnId(1), Input::Start),
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
        ],
        "the host is told to drop what it holds for the lost connection"
    );
    scene.lab.run_until(|| clients[1].connected.get());
}

#[test]
fn a_host_that_panics_again_when_told_to_drop_a_lost_connections_state_loses_nothing_else() {
    let mut scene = TlsScene::new(Hosted::Server, None);
    scene.host.panics_on.set(Some(TlsConnId(0)));
    scene.host.cancel_panics_on.set(Some(TlsConnId(0)));
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    scene.lab.advance(DELAY);
    // A driver that ends drops its record, which `poll_server` reads.
    assert!(scene.lab.poll(scene.server_task), "the server is woken");
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Cancel(TlsConnId(0)),
            Call::Handle(TlsConnId(1), Input::Start),
            Call::Handle(TlsConnId(1), Input::Crypto(Level::Initial)),
        ],
        "the driver goes on with the other connection"
    );
    assert_eq!(
        scene.server.stats().contained_panics,
        2,
        "both panics count against the lost connection"
    );
    scene.lab.run_until(|| clients[1].connected.get());
}

/// The host holds both clients' starts; the first client's session then aborts its connection,
/// which is freed in the same application phase.
#[test]
fn a_host_that_panics_when_told_to_drop_a_freed_connections_state_loses_nothing_else() {
    let mut scene = TlsScene::new(Hosted::Client, None);
    scene.host.deferred.set(true);
    *scene.host.waker.borrow_mut() = scene.client.tls_waker();
    scene.host.cancel_panics_on.set(Some(TlsConnId(0)));
    let clients: Vec<_> = (0..2).map(|_| scene.connect()).collect();
    scene.lab.settle();
    assert_eq!(
        scene.host.calls(),
        [
            Call::Handle(TlsConnId(0), Input::Start),
            Call::Handle(TlsConnId(1), Input::Start),
        ],
        "the host holds both starts"
    );
    clients[0].aborts.set(true);
    scene.conns[0].wake().expect("the connection is open");
    scene.lab.settle();
    assert_eq!(
        scene.host.calls_since(2),
        [Call::Cancel(TlsConnId(0))],
        "freeing the aborted connection cancels the host's state"
    );
    assert_eq!(
        scene.client.stats().contained_panics,
        1,
        "the cancel's panic counts against the freed connection, and the driver goes on"
    );
    scene.host.deferred.set(false);
    scene.host.complete();
    scene.lab.run_until(|| clients[1].connected.get());
}
