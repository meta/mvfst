/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the work budget: endpoint drivers in the lab, on its test clock, where each unit of
//! work charges a set cost.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Write;
use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::Release;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::SrcPortBlocklist;
use mvfstr_proto::Tick;
use mvfstr_proto::TransportConfig;
use rustls::pki_types::ServerName;

use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::PollOutcome;
use crate::Steering;
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
use crate::lab::NetEvent;
use crate::lab::Probe;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::nth_socket;
use crate::lab::transport;
use crate::turn::Core;
use crate::turn::KEYS_MOVED;
use crate::turn::Limits;
use crate::turn::Mark;
use crate::turn::Phase;
use crate::turn::TxRecord;

type Handle = EndpointHandle<LabApp, MemBackend>;

/// How the server of a [`Scene`] treats its connections.
struct ServerPlan {
    /// Whether the server socket's caps have kernel release; runs still leave at its flush.
    release: bool,
    /// Uni streams each accepted connection opens, and the bytes it sends on each.
    streams: usize,
    len: Option<usize>,
    /// Whether the `n`-th accepted connection paces.
    paced: fn(usize) -> bool,
    /// The builder's cap on the datagrams of one transmit attempt.
    segments: u16,
    /// The server's work budget, and the client's.
    budget: Option<WorkBudget>,
    client_budget: Option<WorkBudget>,
    /// The server's limit on connection attempts per turn, if not the default.
    handshakes: Option<usize>,
    /// The server's limit on `poll_send` calls per turn, if not the default.
    polls: Option<usize>,
    /// The cost of each accept by its number; later accepts cost the last.
    accept_costs: Vec<Duration>,
    /// The server's steering group and its worker index in it.
    steering: Option<(Arc<Steering>, u16)>,
    /// The server socket's limit on the datagrams of one send, if not the lab's.
    socket_segments: Option<u16>,
    /// How far ahead of their release the server's connections build datagrams on its release
    /// socket.
    build_horizon: Duration,
    /// The initial window, in packets, of the connections the server accepts, if not the lab's.
    window: Option<u32>,
}

impl Default for ServerPlan {
    fn default() -> Self {
        Self {
            release: false,
            streams: 0,
            len: Some(0),
            paced: |_| false,
            segments: u16::MAX,
            budget: None,
            client_budget: None,
            handshakes: None,
            polls: None,
            accept_costs: Vec::new(),
            steering: None,
            socket_segments: None,
            build_horizon: Duration::ZERO,
            window: None,
        }
    }
}

/// A server driver and a client driver on one lab worker.
struct Scene {
    server: Handle,
    server_task: usize,
    client: Handle,
    client_task: usize,
    client_config: Arc<ClientConfig>,
    endpoint: Arc<EndpointConfig>,
    server_config: Arc<ServerConfig>,
    /// The server sessions' probes, in accept order.
    accepted: Rc<RefCell<Vec<Rc<Probe>>>>,
    /// The client sessions' probes, in connect order.
    clients: Vec<Rc<Probe>>,
    lab: Lab,
}

impl Scene {
    fn new(plan: ServerPlan) -> Self {
        let lab = Lab::new();
        let (client_config, server_config, endpoint) = lab_configs();
        let accepted: Rc<RefCell<Vec<Rc<Probe>>>> = Rc::default();
        let net = lab.net.clone();
        let probes = Rc::clone(&accepted);
        let ServerPlan {
            release,
            streams,
            len,
            paced,
            segments,
            budget,
            client_budget,
            handshakes,
            polls,
            accept_costs,
            steering,
            socket_segments,
            build_horizon,
            window,
        } = plan;
        let endpoint = if build_horizon.is_zero() {
            endpoint
        } else {
            endpoint
                .to_builder()
                .build_horizon(build_horizon)
                .build()
                .expect("an endpoint config")
        };
        let mut app = LabApp::new(&lab.net, move |n, options| {
            options.transport = Some(match window {
                Some(window) => windowed(paced(n), window),
                None => transport(paced(n)),
            });
            let (session, probe) = Bulk::new(&net, streams, len);
            probes.borrow_mut().push(probe);
            session
        });
        app.accept_costs = accept_costs;
        let options = MemOptions {
            net: Some(lab.net.clone()),
            release,
            max_segments: socket_segments,
        };
        let socket = MemBackend::bind(SERVER, &options).expect("the lab binds");
        let mut server = EndpointDriver::builder(Arc::clone(&endpoint), app);
        if let Some((group, index)) = steering {
            server = server.worker(index, group.workers()).steering(group);
        }
        if handshakes.is_some() || polls.is_some() {
            let limits = Limits::default();
            server = server.limits(Limits {
                handshakes: handshakes.unwrap_or(limits.handshakes),
                polls: polls.unwrap_or(limits.polls),
                ..limits
            });
        }
        if let Some(budget) = budget {
            server = server.work_budget(budget);
        }
        let server = server
            .serve(socket, Arc::clone(&server_config))
            .max_segments(segments)
            .backend_options(options)
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the server starts");
        let server_task = lab.last_spawned();
        let mut client = EndpointDriver::builder(Arc::clone(&endpoint), LabApp::client(&lab.net));
        if let Some(budget) = client_budget {
            client = client.work_budget(budget);
        }
        let client = client
            .backend_options(MemOptions {
                net: Some(lab.net.clone()),
                ..MemOptions::default()
            })
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
            endpoint,
            server_config,
            accepted,
            clients: Vec::new(),
            lab,
        }
    }

    /// Opens a client connection whose session opens `streams` streams of `len` bytes each.
    fn connect(&mut self, streams: usize, len: Option<usize>) -> Rc<Probe> {
        self.connect_to(SERVER, streams, len)
    }

    /// Opens a client connection as [`connect`](Self::connect) does, to `remote`.
    fn connect_to(&mut self, remote: SocketAddr, streams: usize, len: Option<usize>) -> Rc<Probe> {
        let (session, probe) = Bulk::new(&self.lab.net, streams, len);
        self.client
            .connect(
                remote,
                ServerName::try_from("localhost").expect("a name"),
                Arc::clone(&self.client_config),
                ConnOptions {
                    transport: Some(transport(false)),
                },
                session,
            )
            .expect("the client connects");
        self.clients.push(Rc::clone(&probe));
        probe
    }

    /// Opens `n` client connections to an address whose datagrams the lab drops, so each stays at
    /// its first flight and does not probe again while a test polls, and runs until each has sent
    /// that flight. The connections take the client's slots in order, and each probe holds its
    /// connection's handle.
    fn connect_nowhere(&mut self, n: usize) -> Vec<Rc<Probe>> {
        let probes = (0..n)
            .map(|_| {
                let (session, probe) = Bulk::new(&self.lab.net, 0, Some(0));
                let handle = self
                    .client
                    .connect(
                        NOWHERE,
                        ServerName::try_from("localhost").expect("a name"),
                        Arc::clone(&self.client_config),
                        ConnOptions {
                            transport: Some(unhurried()),
                        },
                        session,
                    )
                    .expect("the client connects");
                *probe.handle.borrow_mut() = Some(handle);
                probe
            })
            .collect();
        self.lab.settle();
        probes
    }

    /// Returns the client driver's core.
    fn client_core(&self) -> Rc<Core<LabApp, MemBackend>> {
        self.client.core().expect("the client runs")
    }

    /// Returns the server driver's core.
    fn server_core(&self) -> Rc<Core<LabApp, MemBackend>> {
        self.server.core().expect("the server runs")
    }

    /// Runs until every connection is established at both ends and the lab is quiet.
    fn settle_connected(&self) {
        let clients = self.clients.clone();
        let accepted = Rc::clone(&self.accepted);
        self.lab.run_until(|| {
            let accepted = accepted.borrow();
            accepted.len() == clients.len()
                && accepted
                    .iter()
                    .chain(&clients)
                    .all(|probe| probe.connected.get())
        });
        self.lab.run_quiet(Duration::from_millis(500));
    }

    /// Opens `n` client connections whose sessions do not open streams, and runs until they are
    /// established.
    fn establish(&mut self, n: usize) {
        for _ in 0..n {
            self.connect(0, Some(0));
        }
        self.settle_connected();
    }

    /// Returns the server sessions' probes, in accept order.
    fn servers(&self) -> Vec<Rc<Probe>> {
        self.accepted.borrow().clone()
    }

    /// Starts another server driver, without a budget, as worker `index` of `group`, on a socket
    /// bound to `addr`.
    fn spawn_worker(&self, group: &Arc<Steering>, index: u16, addr: SocketAddr) -> Handle {
        let options = MemOptions {
            net: Some(self.lab.net.clone()),
            ..MemOptions::default()
        };
        let net = self.lab.net.clone();
        let app = LabApp::new(&self.lab.net, move |_, options| {
            options.transport = Some(transport(false));
            Bulk::new(&net, 0, Some(0)).0
        });
        EndpointDriver::builder(Arc::clone(&self.endpoint), app)
            .serve(
                MemBackend::bind(addr, &options).expect("the lab binds"),
                Arc::clone(&self.server_config),
            )
            .worker(index, group.workers())
            .steering(Arc::clone(group))
            .backend_options(options)
            .host_timers(Lab::timers())
            .spawn(self.lab.ctx())
            .expect("the other worker starts")
    }

    /// Polls the server once and returns what the poll did.
    fn poll_server(&self) -> Vec<Mark> {
        let before = self.server.tx_record().marks.len();
        assert!(self.lab.poll(self.server_task), "the server is woken");
        self.server.tx_record().marks[before..].to_vec()
    }

    /// Polls the client once and returns what the poll did.
    fn poll_client(&self) -> Vec<Mark> {
        let before = self.client.tx_record().marks.len();
        assert!(self.lab.poll(self.client_task), "the client is woken");
        self.client.tx_record().marks[before..].to_vec()
    }

    /// Returns the server sessions' `poll_session` counts, in accept order.
    fn visits(&self) -> Vec<u64> {
        self.servers()
            .iter()
            .map(|probe| probe.visits.get())
            .collect()
    }
}

/// The slice of the tests' budgets.
const SLICE: Duration = Duration::from_micros(1_000);

/// An address without a socket on the lab network, whose datagrams the lab drops.
const NOWHERE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

/// Returns transport settings under which a connection whose peer does not answer sends its first
/// probe about three seconds after its first flight, long after a test's polls on the test clock.
fn unhurried() -> Arc<TransportConfig> {
    TransportConfig::builder()
        .initial_rtt(Duration::from_secs(1))
        .build()
        .expect("a transport config")
}

/// Returns the lab's transport settings with an initial window of `window` packets.
fn windowed(pacing: bool, window: u32) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .initial_window(window)
        .initial_rtt(Duration::from_millis(1))
        .max_data(1 << 30)
        .max_stream_data_uni(1 << 26)
        .max_streams_uni(1 << 20)
        .pacing(pacing)
        .build()
        .expect("a transport config")
}

fn us(micros: u64) -> Duration {
    Duration::from_micros(micros)
}

/// Returns the slots of the connections a poll attempted, in order. The server's slots follow
/// the accept order.
fn attempted(marks: &[Mark]) -> Vec<u32> {
    marks
        .iter()
        .filter_map(|mark| match mark {
            Mark::Attempt(key) => Some(key.index),
            _ => None,
        })
        .collect()
}

/// Returns how many units the budget let run before the attempt of the connection in slot
/// `index`, that attempt's own unit included.
fn units_until_attempt(marks: &[Mark], index: u32) -> Option<usize> {
    let at = marks
        .iter()
        .position(|mark| matches!(mark, Mark::Attempt(key) if key.index == index))?;
    Some(
        marks[..at]
            .iter()
            .filter(|mark| matches!(mark, Mark::Unit(_)))
            .count(),
    )
}

/// Returns the phase a poll stopped in.
fn stop(marks: &[Mark]) -> Option<Phase> {
    marks.iter().find_map(|mark| match mark {
        Mark::Stop(phase) => Some(*phase),
        _ => None,
    })
}

/// Returns the batch ranges a poll routed.
fn routes(marks: &[Mark]) -> Vec<(usize, usize)> {
    marks
        .iter()
        .filter_map(|mark| match mark {
            Mark::Route { start, end, .. } => Some((*start, *end)),
            _ => None,
        })
        .collect()
}

/// Returns the slot and the batch range of each delivery from a connection's own socket in a
/// poll.
fn own_receives(marks: &[Mark]) -> Vec<(u32, usize, usize)> {
    marks
        .iter()
        .filter_map(|mark| match mark {
            Mark::Receive { key, start, end } => Some((key.index, *start, *end)),
            _ => None,
        })
        .collect()
}

/// Returns the addresses of the connection attempts a poll took up, grouped by turn and leaving
/// out turns without any. A turn starts at each intake, and the attempts before the poll's first
/// intake form a turn of their own.
fn accepts_per_turn(marks: &[Mark]) -> Vec<Vec<SocketAddr>> {
    let mut turns = vec![Vec::new()];
    for mark in marks {
        match mark {
            Mark::Phase(Phase::Intake) => turns.push(Vec::new()),
            Mark::Accept(remote) => turns.last_mut().expect("a turn").push(*remote),
            _ => {}
        }
    }
    turns.retain(|turn| !turn.is_empty());
    turns
}

fn longest_past(budget: &WorkBudget, kind: UnitKind) -> u64 {
    budget.stats().longest_past_us(kind)
}

/// Returns the FNV-1a hash of `text`.
fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Writes out a [`TxRecord`]'s phases, clock reads inside them, attempts and wakes, its times as
/// offsets from `start`.
fn summary(record: &TxRecord, start: Instant) -> String {
    let mut text = format!(
        "phases {} reads {}\n",
        record.phases, record.phase_clock_reads
    );
    for attempt in &record.attempts {
        let _ = writeln!(
            text,
            "attempt {}/{} phase {} at {:?}",
            attempt.key.index,
            attempt.key.generation,
            attempt.phase,
            attempt.at - start
        );
    }
    for wake in &record.wakes {
        let _ = writeln!(
            text,
            "wake {} due {:?} taken {:?} phase {:?} queued {} next {:?}",
            wake.index,
            wake.due - start,
            wake.taken - start,
            wake.phase,
            wake.queued,
            wake.next
        );
    }
    text
}

/// Runs the scripted transfer: three clients, the second paced at the server, each receiving
/// four 256 KiB streams from the server in attempts of up to eight datagrams; returns the
/// summary of the server's record.
fn scripted_run() -> String {
    let mut scene = Scene::new(ServerPlan {
        streams: 4,
        len: Some(256 * 1024),
        paced: |n| n == 1,
        segments: 8,
        ..ServerPlan::default()
    });
    let clients: Vec<_> = (0..3).map(|_| scene.connect(0, Some(0))).collect();
    scene
        .lab
        .run_until(|| clients.iter().all(|probe| probe.finished.get() == 4));
    summary(&scene.server.tx_record(), scene.lab.net.start())
}

/// The reference hash of [`scripted_run`]'s summary, which a driver without a budget must produce.
const SCRIPTED_RUN: u64 = 0x60b1_31dc_9d94_deb3;

#[test]
fn without_a_budget_a_scripted_runs_record_matches_the_drivers_before_the_budget() {
    let first = scripted_run();
    assert_eq!(first, scripted_run(), "the lab runs deterministically");
    assert!(first.lines().count() > 200, "the run attempts: {first}");
    assert_eq!(fnv1a(&first), SCRIPTED_RUN, "{first}");
}

#[test]
fn a_poll_entered_with_the_slice_closed_runs_no_turn_reports_deferred_and_wakes_itself() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    budget.refill();
    let now = scene.lab.net.now();
    assert!(budget.admit(now));
    assert!(!budget.admit(now + SLICE * 2), "the slice closes");
    scene.servers()[0].poke(1);
    let turns = scene.server.stats().turns;
    let marks = scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    assert_eq!(budget.stats().deferrals, 1);
    assert_eq!(scene.server.stats().turns, turns, "no turn ran");
    assert_eq!(marks, [Mark::Poll], "the poll began no phase");
    assert!(
        scene.lab.queued(scene.server_task),
        "the driver woke itself"
    );
}

#[test]
fn two_drivers_on_one_budget_the_second_sees_it_closed_once_the_first_closes_it() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        client_budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    budget.refill();
    scene.servers()[0].poke(1);
    scene.clients[0].poke(1);
    scene.lab.net.clear_events();
    let marks = scene.poll_server();
    assert_eq!(attempted(&marks), [0], "{marks:?}");
    assert!(
        budget.is_closed(),
        "the server's attempt ran past the deadline"
    );
    assert!(scene.lab.poll(scene.client_task), "the client is woken");
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    let client_attempts = scene
        .lab
        .net
        .events()
        .into_iter()
        .filter(|event| matches!(event, NetEvent::Attempt(addr, _) if *addr != SERVER))
        .count();
    assert_eq!(client_attempts, 0, "the client ran no work");
}

#[test]
fn a_slice_that_closes_in_a_polls_last_unit_records_that_units_time_past_the_deadline_at_park() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.establish(1);
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    scene.servers()[0].poke(1);
    let marks = scene.poll_server();
    assert_eq!(attempted(&marks), [0], "{marks:?}");
    assert_eq!(
        stop(&marks),
        None,
        "the poll ends without a stop: {marks:?}"
    );
    assert_eq!(budget.outcome(), PollOutcome::Ran);
    assert!(budget.is_closed());
    assert_eq!(
        longest_past(&budget, UnitKind::Attempt),
        500,
        "the attempt began at the slice's start and ran 1.5 slices"
    );
    assert!(
        !scene.lab.queued(scene.server_task),
        "the driver waits for a wake"
    );
}

/// Pokes six connections, each attempt 300 µs, under a 1 ms slice: the fourth attempt closes
/// the slice, 200 µs past its deadline.
fn a_slice_closes_during_attempt_k(release: bool, paced: fn(usize) -> bool) {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        release,
        paced,
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.establish(6);
    scene.lab.net.set_costs(Costs {
        attempt: us(300),
        ..Costs::default()
    });
    for probe in scene.servers() {
        probe.poke(1);
    }
    let first = scene.poll_server();
    assert_eq!(attempted(&first), [0, 1, 2, 3], "{first:?}");
    assert_eq!(stop(&first), Some(Phase::FirstTransmit), "{first:?}");
    let last_attempt = first
        .iter()
        .rposition(|mark| matches!(mark, Mark::Attempt(_)))
        .expect("attempts");
    let flushes: Vec<usize> = first
        .iter()
        .enumerate()
        .filter_map(|(place, mark)| (*mark == Mark::Flush).then_some(place))
        .collect();
    assert_eq!(
        flushes.len(),
        1,
        "the stopped phase flushes once: {first:?}"
    );
    assert!(flushes[0] > last_attempt, "after its last attempt");
    // An attempt on a socket with kernel release or of a paced connection runs at a reading of
    // its own. Any other runs at its phase's reading, though its check took a later one.
    let record = scene.server.tx_record();
    let attempts = &record.attempts[record.attempts.len() - 4..];
    let ran_at: Vec<Duration> = attempts
        .iter()
        .map(|attempt| attempt.at - attempts[0].at)
        .collect();
    let own_reading: Vec<Duration> = (0..4_u32)
        .map(|n| {
            if release || paced(n as usize) {
                us(300) * n
            } else {
                Duration::ZERO
            }
        })
        .collect();
    assert_eq!(ran_at, own_reading, "{first:?}");
    assert_eq!(longest_past(&budget, UnitKind::Attempt), 200);
    assert_eq!(budget.outcome(), PollOutcome::Stopped);
    assert!(
        scene.lab.queued(scene.server_task),
        "a stop wakes the driver"
    );
    let second = scene.poll_server();
    assert_eq!(
        attempted(&second).first(),
        Some(&4),
        "the next transmit phase starts with the connection after the stop: {second:?}"
    );
}

#[test]
fn a_slice_that_closes_during_attempt_k_stops_before_attempt_k_plus_1_on_a_plain_socket() {
    a_slice_closes_during_attempt_k(false, |n| n % 2 == 1);
}

#[test]
fn a_slice_that_closes_during_attempt_k_stops_before_attempt_k_plus_1_on_a_release_socket() {
    a_slice_closes_during_attempt_k(true, |_| false);
}

#[test]
fn three_always_dirty_connections_under_a_one_attempt_slice_are_attempted_in_turn() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(3);
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    for probe in scene.servers() {
        probe.poke(u64::MAX);
    }
    let order: Vec<u32> = (0..4)
        .flat_map(|_| attempted(&scene.poll_server()))
        .collect();
    assert_eq!(order, [0, 1, 2, 0]);
}

#[test]
fn after_a_grant_on_a_closed_slice_a_poll_runs_one_unit_and_reports_stopped() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(2);
    scene.lab.net.set_costs(Costs {
        attempt: us(2_500),
        ..Costs::default()
    });
    budget.refill();
    for probe in scene.servers() {
        probe.poke(u64::MAX);
    }
    let first = scene.poll_server();
    assert_eq!(attempted(&first), [0], "{first:?}");
    assert_eq!(budget.outcome(), PollOutcome::Stopped);
    let deferred = scene.poll_server();
    assert_eq!(attempted(&deferred), [0_u32; 0], "{deferred:?}");
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    budget.grant();
    let units = scene.server.tx_record().units;
    let granted = scene.poll_server();
    assert_eq!(attempted(&granted), [1], "{granted:?}");
    assert_eq!(
        scene.server.tx_record().units - units,
        1,
        "one unit: {granted:?}"
    );
    assert_eq!(budget.outcome(), PollOutcome::Stopped);
    assert_eq!(
        longest_past(&budget, UnitKind::Attempt),
        2_500,
        "the granted attempt ran wholly past the deadline"
    );

    scene.lab.net.set_costs(Costs {
        attempt: us(400),
        ..Costs::default()
    });
    budget.refill();
    budget.grant();
    let open = scene.poll_server();
    assert_eq!(
        attempted(&open),
        [0, 1],
        "on an open slice the poll runs as usual: {open:?}"
    );
    assert_eq!(budget.outcome(), PollOutcome::Ran);
}

#[test]
fn while_the_budget_is_held_a_poll_runs_no_turn_unless_a_grant_is_pending() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    budget.refill();
    budget.set_hold(true);
    scene.servers()[0].poke(1);
    let turns = scene.server.stats().turns;
    let held = scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    assert_eq!(scene.server.stats().turns, turns, "no turn ran");
    assert_eq!(held, [Mark::Poll]);
    budget.grant();
    let visits = scene.visits();
    let granted = scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Stopped);
    assert_eq!(
        stop(&granted),
        Some(Phase::FirstApp),
        "the poll served the wake, and stopped before the visit: {granted:?}"
    );
    assert_eq!(scene.visits(), visits);
    budget.set_hold(false);
    budget.refill();
    let free = scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Ran);
    assert_eq!(attempted(&free), [0], "{free:?}");
}

#[test]
fn a_polls_admit_and_its_first_turn_share_one_clock_reading() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    budget.refill();
    budget.set_hold(true);
    scene.servers()[0].poke(1);
    let reads = |scene: &Scene| scene.server.tx_record().clock_reads;
    let before = reads(&scene);
    scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    assert_eq!(reads(&scene) - before, 1, "the admit's reading");
    budget.grant();
    let before = reads(&scene);
    let granted = scene.poll_server();
    assert_eq!(
        stop(&granted),
        Some(Phase::FirstApp),
        "the poll serves the wake and stops before the visit: {granted:?}"
    );
    assert_eq!(
        reads(&scene) - before,
        2,
        "one reading for the admit and the turn, and one for the check before the visit"
    );
}

#[test]
fn with_no_initials_waiting_a_server_turn_reads_no_clock_in_its_receive_phase() {
    let mut scene = Scene::new(ServerPlan::default());
    scene.establish(1);
    assert_eq!(scene.server.waiting(), (0, false));
    // The mark wakes the server for one turn, whose attempt has nothing to send.
    scene.server_core().mark_dirty_at(0);
    let reads = |scene: &Scene| scene.server.tx_record().clock_reads;
    let before = reads(&scene);
    let marks = scene.poll_server();
    assert_eq!(
        marks.iter().filter(|&&mark| mark == Mark::Turn).count(),
        1,
        "one turn: {marks:?}"
    );
    assert_eq!(
        reads(&scene) - before,
        5,
        "one reading for the intake and the first application phase, one each for the first \
         transmit phase, the second application phase and the second transmit phase, and one as \
         the turn parks: {marks:?}"
    );
}

#[test]
fn a_run_the_server_socket_drops_is_declared_lost_at_the_flush_and_sent_again_in_the_turn() {
    let mut scene = Scene::new(ServerPlan {
        len: Some(4_000),
        ..ServerPlan::default()
    });
    scene.establish(1);
    let lost = |scene: &Scene| scene.server_core().conn_stats()[0].lost_packets;
    assert_eq!(lost(&scene), 0);
    // The stream's 4,000 bytes fill four datagrams, which leave as one run.
    scene.lab.net.drop_next_run(SERVER);
    scene.lab.net.clear_events();
    scene.servers()[0].open_streams(1);
    let marks = scene.poll_server();
    let built: Vec<u16> = scene
        .lab
        .net
        .events()
        .into_iter()
        .filter_map(|event| match event {
            NetEvent::Built(SERVER, _, built) => Some(built),
            _ => None,
        })
        .collect();
    assert_eq!(
        lost(&scene),
        4,
        "the dropped run's packets are lost at the flush: {marks:?}"
    );
    assert_eq!(
        built,
        [4, 4],
        "the second transmit phase sends the lost data again: {marks:?}"
    );
}

/// Connects a client and has it send one stream of 400,000 bytes while the datagrams to the server
/// are held; returns 200 of those datagrams of one length, coalesced into one arrival.
fn gro_batch(scene: &mut Scene) -> Arrival {
    let client = scene.connect(0, Some(400_000));
    scene.settle_connected();
    scene.lab.net.hold(SERVER);
    client.open_streams(1);
    scene.lab.settle_except(Some(scene.server_task));
    coalesce(&scene.lab.net.take_held())
}

/// Returns 200 of the `held` datagrams of their most common length, coalesced into one arrival.
fn coalesce(held: &[Arrival]) -> Arrival {
    let mut lens: HashMap<usize, usize> = HashMap::new();
    for arrival in held {
        *lens.entry(arrival.data.len()).or_default() += 1;
    }
    let (&len, _) = lens
        .iter()
        .max_by_key(|&(_, &count)| count)
        .expect("the sender sent");
    let equal: Vec<&Arrival> = held
        .iter()
        .filter(|arrival| arrival.data.len() == len)
        .take(200)
        .collect();
    assert_eq!(
        equal.len(),
        200,
        "the sender sent 200 datagrams of {len} bytes"
    );
    Arrival {
        src: equal[0].src,
        stride: u16::try_from(len).expect("a datagram"),
        data: equal
            .iter()
            .flat_map(|arrival| arrival.data.clone())
            .collect(),
    }
}

/// Polls the server until it is no longer woken; returns what each poll did.
fn polls_while_woken(scene: &Scene) -> Vec<Vec<Mark>> {
    let mut polls = Vec::new();
    while scene.lab.queued(scene.server_task) {
        polls.push(scene.poll_server());
        assert!(polls.len() < 50, "the server keeps waking: {polls:?}");
    }
    polls
}

#[test]
fn a_200_datagram_gro_batch_arrives_in_chunks_of_64_in_order_with_one_receive() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    let batch = gro_batch(&mut scene);
    let server = Rc::clone(&scene.servers()[0]);
    server.poke(1);
    polls_while_woken(&scene);
    let received = server.stats.get().recv_packets;
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    scene.lab.net.clear_events();
    scene.lab.net.inject(SERVER, batch);
    let mut polls = vec![scene.poll_server()];
    // A datagram that arrives while part of the batch waits stays in the socket until the batch
    // is done.
    scene.lab.net.inject(
        SERVER,
        Arrival {
            src: SocketAddr::from(([127, 0, 0, 1], 9)),
            stride: 1,
            data: vec![0x40],
        },
    );
    polls.extend(polls_while_woken(&scene));
    let routed: Vec<(usize, usize)> = polls.iter().flat_map(|marks| routes(marks)).collect();
    assert_eq!(
        routed,
        [(0, 64), (64, 128), (128, 192), (192, 200), (0, 1)],
        "{polls:?}"
    );
    let server_io: Vec<NetEvent> = scene
        .lab
        .net
        .events()
        .into_iter()
        .filter(|event| {
            matches!(event, NetEvent::Recv(addr, _) | NetEvent::Chunk(addr) if *addr == SERVER)
        })
        .collect();
    assert_eq!(
        server_io,
        [
            NetEvent::Recv(SERVER, 200),
            NetEvent::Chunk(SERVER),
            NetEvent::Chunk(SERVER),
            NetEvent::Chunk(SERVER),
            NetEvent::Chunk(SERVER),
            NetEvent::Recv(SERVER, 1),
            NetEvent::Chunk(SERVER),
        ],
        "no receive while part of the batch waits"
    );
    scene.lab.net.set_costs(Costs::default());
    server.poke(1);
    polls_while_woken(&scene);
    assert_eq!(
        server.stats.get().recv_packets - received,
        200,
        "every datagram of the batch reached the connection"
    );
}

#[test]
fn each_chunk_of_a_resumed_batch_steps_over_only_the_datagrams_it_routes() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    let batch = gro_batch(&mut scene);
    polls_while_woken(&scene);
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    scene.lab.net.inject(SERVER, batch);
    let walks: Vec<(usize, usize, usize)> = polls_while_woken(&scene)
        .concat()
        .into_iter()
        .filter_map(|mark| match mark {
            Mark::Route { start, end, walked } => Some((start, end, walked)),
            _ => None,
        })
        .collect();
    assert_eq!(
        walks,
        [(0, 64, 64), (64, 128, 64), (128, 192, 64), (192, 200, 8)],
        "start, end and datagrams stepped over"
    );
}

#[test]
fn a_stop_with_part_of_a_batch_left_and_the_socket_empty_wakes_the_driver_again() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    let batch = gro_batch(&mut scene);
    polls_while_woken(&scene);
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    scene.lab.net.inject(SERVER, batch);
    let first = scene.poll_server();
    assert_eq!(routes(&first), [(0, 64)], "{first:?}");
    assert_eq!(stop(&first), Some(Phase::Receive));
    assert_eq!(budget.outcome(), PollOutcome::Stopped);
    assert!(
        scene.lab.queued(scene.server_task),
        "the stop wakes the driver while its socket holds nothing new"
    );
    let second = scene.poll_server();
    assert_eq!(routes(&second), [(64, 128)], "{second:?}");
}

/// A driver without a TLS host: a poll granted one unit after a receive stop resumes at the
/// second application phase rather than at the TLS phase, so it runs that phase at its own
/// reading.
#[test]
fn a_poll_resumed_after_a_receive_stop_runs_its_second_application_phase_at_its_own_reading() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    let batch = gro_batch(&mut scene);
    polls_while_woken(&scene);
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    budget.refill();
    scene.lab.net.inject(SERVER, batch);
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    budget.set_hold(true);
    budget.grant();
    let reads = |scene: &Scene| scene.server.tx_record().clock_reads;
    let before = reads(&scene);
    let granted = scene.poll_server();
    assert_eq!(
        granted[..3],
        [
            Mark::Poll,
            Mark::Phase(Phase::SecondApp),
            Mark::Unit(UnitKind::AppVisit)
        ],
        "{granted:?}"
    );
    assert_eq!(stop(&granted), Some(Phase::SecondTransmit), "{granted:?}");
    assert_eq!(
        reads(&scene) - before,
        3,
        "one reading for the admit and the application phase, one for the transmit phase, and one \
         for the check that stops it before its attempt, which leaves nothing to flush: \
         {granted:?}"
    );
}

#[test]
fn a_slice_that_closes_in_an_accept_stops_right_after_it_in_route_batch() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        accept_costs: vec![SLICE * 2],
        ..ServerPlan::default()
    });
    scene.connect(0, Some(0));
    scene.connect(0, Some(0));
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(scene.servers().len(), 1, "one accept: {first:?}");
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    assert_eq!(longest_past(&budget, UnitKind::Accept), 1_000);
    scene.poll_server();
    assert_eq!(scene.servers().len(), 2, "the next poll accepts the other");
}

#[test]
fn a_slice_that_closes_in_an_accept_stops_right_after_it_in_serve_waiting() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        handshakes: Some(2),
        accept_costs: vec![Duration::ZERO, Duration::ZERO, SLICE * 2, Duration::ZERO],
        ..ServerPlan::default()
    });
    for _ in 0..4 {
        scene.connect(0, Some(0));
    }
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    let first = scene.poll_server();
    assert_eq!(
        scene.servers().len(),
        3,
        "two accepts from the batch, and one of the two kept waiting: {first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    assert_eq!(
        scene.server.waiting(),
        (1, false),
        "the stop came before the last waiting Initial was routed again: {first:?}"
    );
    assert_eq!(longest_past(&budget, UnitKind::Accept), 1_000);
    scene.poll_server();
    assert_eq!(
        scene.servers().len(),
        4,
        "the last waiting Initial is accepted next"
    );
}

#[test]
fn a_stop_before_an_accept_in_route_batch_keeps_the_attempt_for_a_later_polls_first_unit() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.connect(0, Some(0));
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    budget.set_hold(true);
    budget.grant();
    let first = scene.poll_server();
    assert_eq!(
        routes(&first),
        [(0, 1)],
        "the poll's one unit routed the Initial: {first:?}"
    );
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    assert!(scene.servers().is_empty());
    budget.grant();
    let second = scene.poll_server();
    assert_eq!(accepts_per_turn(&second), [[nth_socket(0)]], "{second:?}");
    assert!(
        routes(&second).is_empty(),
        "the accept was the poll's one unit: {second:?}"
    );
    assert_eq!(scene.servers().len(), 1);
}

#[test]
fn a_kept_attempt_from_a_port_blocked_since_it_was_routed_is_dropped() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.connect(0, Some(0));
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    budget.set_hold(true);
    budget.grant();
    let first = scene.poll_server();
    assert_eq!(scene.server.waiting(), (0, true), "{first:?}");
    let blocklist = SrcPortBlocklist::new(0, [nth_socket(0).port()]);
    scene
        .server
        .set_src_port_blocklist(Some(Arc::new(blocklist)));
    budget.grant();
    let second = scene.poll_server();
    assert!(accepts_per_turn(&second).is_empty(), "{second:?}");
    assert_eq!(scene.server.waiting(), (0, false), "{second:?}");
    assert!(scene.servers().is_empty());
    assert_eq!(scene.server.stats().invalid_src_port, 1);
}

#[test]
fn a_waiting_initial_stopped_before_its_accept_is_accepted_by_a_later_poll_on_a_grant() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        handshakes: Some(1),
        ..ServerPlan::default()
    });
    scene.connect(0, Some(0));
    scene.connect(0, Some(0));
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    // The first poll accepts one attempt and keeps the other waiting; the new connection's visit
    // then closes the slice, and the check before its attempt stops the poll.
    scene.lab.net.set_costs(Costs {
        visit: SLICE * 2,
        ..Costs::default()
    });
    budget.refill();
    let first = scene.poll_server();
    assert_eq!(scene.servers().len(), 1, "{first:?}");
    assert_eq!(stop(&first), Some(Phase::SecondTransmit), "{first:?}");
    scene.lab.net.set_costs(Costs::default());
    budget.set_hold(true);
    let mut polls = Vec::new();
    while scene.servers().len() < 2 {
        assert!(
            polls.len() < 20,
            "polls on grants never accept the waiting attempt: {polls:?}"
        );
        budget.grant();
        polls.push(scene.poll_server());
        assert_eq!(budget.outcome(), PollOutcome::Stopped);
    }
}

#[test]
fn a_kept_attempt_is_accepted_ahead_of_steered_initials_and_within_the_turns_cap() {
    let other_addr = SocketAddr::from(([127, 0, 0, 1], 444));
    let group = Steering::new(2);
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        handshakes: Some(1),
        steering: Some((Arc::clone(&group), 0)),
        ..ServerPlan::default()
    });
    let other = scene.spawn_worker(&group, 1, other_addr);
    scene.connect(0, Some(0));
    scene.connect_to(other_addr, 0, Some(0));
    scene.connect_to(other_addr, 0, Some(0));
    scene.lab.settle_except(Some(scene.server_task));
    scene.lab.advance(DELAY);
    // The group's first new connection stays with this worker, whose poll on a grant stops
    // before accepting it.
    budget.set_hold(true);
    budget.grant();
    let kept = scene.poll_server();
    assert_eq!(stop(&kept), Some(Phase::Receive), "{kept:?}");
    assert!(accepts_per_turn(&kept).is_empty(), "{kept:?}");
    // The other worker keeps the second and hands the third to this one.
    scene.lab.settle_except(Some(scene.server_task));
    assert_eq!(other.stats().steered_out, 1);
    budget.set_hold(false);
    budget.refill();
    let mut marks = Vec::new();
    while scene.lab.queued(scene.server_task) && scene.servers().len() < 2 {
        assert!(marks.len() < 2_000, "the server keeps waking: {marks:?}");
        marks.extend(scene.poll_server());
    }
    assert_eq!(
        accepts_per_turn(&marks),
        [[nth_socket(0)], [nth_socket(2)]],
        "the kept attempt first, then the steered one in a turn of its own: {marks:?}"
    );
}

#[test]
fn when_one_side_always_overruns_the_slice_each_poll_after_its_stop_runs_the_other() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(3);
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    for probe in scene.servers() {
        probe.poke(u64::MAX);
    }
    let polls: Vec<Vec<Mark>> = (0..12).map(|_| scene.poll_server()).collect();
    let mut transmit_stops = 0;
    for pair in polls.windows(2) {
        if matches!(
            stop(&pair[0]),
            Some(Phase::FirstTransmit | Phase::SecondTransmit)
        ) {
            transmit_stops += 1;
            assert!(
                pair[1].contains(&Mark::Phase(Phase::Receive)),
                "receive runs in the poll after a transmit stop: {polls:?}"
            );
        }
    }
    assert!(transmit_stops >= 6, "{polls:?}");

    for probe in scene.servers() {
        probe.pokes.set(0);
    }
    scene.lab.net.set_costs(Costs {
        chunk: us(1_500),
        ..Costs::default()
    });
    let junk = SocketAddr::from(([127, 0, 0, 1], 9));
    let mut polls = Vec::new();
    for _ in 0..12 {
        for _ in 0..100 {
            scene.lab.net.inject(
                SERVER,
                Arrival {
                    src: junk,
                    stride: 1,
                    data: vec![0x40],
                },
            );
        }
        polls.push(scene.poll_server());
    }
    let mut receive_stops = 0;
    for pair in polls.windows(2) {
        if stop(&pair[0]) == Some(Phase::Receive) {
            receive_stops += 1;
            assert!(
                pair[1].iter().any(|mark| matches!(
                    mark,
                    Mark::Phase(Phase::FirstTransmit | Phase::SecondTransmit)
                )),
                "a transmit phase runs in the poll after a receive stop: {polls:?}"
            );
        }
    }
    assert!(receive_stops >= 6, "{polls:?}");
}

#[test]
fn an_intake_stop_leaves_the_rest_of_the_ready_queue_for_the_next_turn() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(5);
    scene.lab.net.set_costs(Costs {
        read: us(400),
        ..Costs::default()
    });
    for probe in scene.servers() {
        probe.poke(1);
    }
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::Intake), "{first:?}");
    assert_eq!(attempted(&first), [0_u32; 0]);
    let order: Vec<u32> = polls_while_woken(&scene)
        .iter()
        .flat_map(|marks| attempted(marks))
        .collect();
    assert_eq!(order, [0, 1, 2, 3, 4]);
}

#[test]
fn an_application_phase_stop_leaves_the_unvisited_connections_at_the_head_of_its_queue() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(4);
    scene.lab.net.set_costs(Costs {
        visit: us(600),
        ..Costs::default()
    });
    for probe in scene.servers() {
        probe.poke(1);
    }
    let start = scene.visits();
    let since = |scene: &Scene| -> Vec<u64> {
        scene
            .visits()
            .iter()
            .zip(&start)
            .map(|(now, then)| now - then)
            .collect()
    };
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::FirstApp), "{first:?}");
    assert_eq!(since(&scene), [1, 1, 0, 0]);
    scene.poll_server();
    assert_eq!(since(&scene), [1, 1, 1, 1]);
}

#[test]
fn a_turn_split_by_a_stop_counts_once_and_keeps_its_poll_cap_across_the_split() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        len: Some(100),
        polls: Some(3),
        budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(4);
    scene.lab.net.set_costs(Costs {
        visit: us(600),
        ..Costs::default()
    });
    // Each connection opens a stream in its next visit, and its pull step then polls the stream
    // once if the turn's cap on polls is not yet spent.
    for probe in scene.servers() {
        probe.open_streams(1);
    }
    let sends = |scene: &Scene| -> Vec<u64> {
        scene
            .servers()
            .iter()
            .map(|probe| probe.sends.get())
            .collect()
    };
    let turns = scene.server.stats().turns;
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::FirstApp), "{first:?}");
    assert_eq!(scene.server.stats().turns - turns, 1, "{first:?}");
    assert_eq!(sends(&scene), [1, 1, 0, 0], "{first:?}");

    let turns = scene.server.stats().turns;
    let second = scene.poll_server();
    assert!(
        !second.contains(&Mark::Phase(Phase::Intake)),
        "the poll runs only the rest of the turn: {second:?}"
    );
    assert_eq!(
        scene.server.stats().turns,
        turns,
        "the rest of a turn is not another turn: {second:?}"
    );
    assert_eq!(
        sends(&scene),
        [1, 1, 1, 0],
        "the turn's third poll is its last: {second:?}"
    );

    polls_while_woken(&scene);
    assert_eq!(
        sends(&scene),
        [1, 1, 1, 1],
        "the next turn polls the fourth"
    );
}

#[test]
fn the_keys_a_poll_moves_grow_with_the_units_it_runs_not_with_the_connections_left_over() {
    const CONNECTIONS: usize = 50_000;
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(budget),
        ..ServerPlan::default()
    });
    // The lab drops datagrams to that address, so every connection stays at its first flight.
    let nowhere = SocketAddr::from(([127, 0, 0, 1], 1));
    for _ in 0..CONNECTIONS {
        scene.connect_to(nowhere, 0, Some(0));
    }
    scene.lab.net.set_costs(Costs {
        attempt: us(300),
        visit: us(300),
        ..Costs::default()
    });
    // The first transmit phase moves each new connection from the dirty list into the queue once,
    // a cost of the connects rather than of the leftover.
    let mut polls = 0;
    while scene.client.queued_keys().1 < CONNECTIONS - 100 {
        assert!(polls < 4, "the connections reach the transmit queue");
        assert!(scene.lab.poll(scene.client_task), "the client is woken");
        polls += 1;
    }
    for poll in 0..12 {
        let units = scene.client.tx_record().units;
        KEYS_MOVED.with(|moved| moved.set(0));
        assert!(scene.lab.poll(scene.client_task), "the client is woken");
        let moved = KEYS_MOVED.with(|moved| moved.get());
        let ran = scene.client.tx_record().units - units;
        assert!(
            moved <= 4 * ran + 64,
            "poll {poll} moved {moved} keys for {ran} units"
        );
    }
    let (app, transmit) = scene.client.queued_keys();
    assert!(
        app > CONNECTIONS - 100 && transmit > CONNECTIONS - 100,
        "the connections are left over in both queues: {app} and {transmit}"
    );
}

#[test]
fn a_stop_between_two_receives_on_a_connections_own_socket_leaves_it_at_the_head_of_its_queue() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.establish(2);
    let (first, second) = (nth_socket(0), nth_socket(1));
    let junk = || Arrival {
        src: SERVER,
        stride: 1,
        data: vec![0x40],
    };
    // A receive takes up to 64 arrivals, so the first socket holds two receives' worth.
    for _ in 0..100 {
        scene.lab.net.inject(first, junk());
    }
    for _ in 0..10 {
        scene.lab.net.inject(second, junk());
    }
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    let mut polls = Vec::new();
    while scene.lab.queued(scene.client_task) {
        assert!(polls.len() < 50, "the client keeps waking: {polls:?}");
        scene.lab.net.clear_events();
        scene.poll_client();
        let receives: Vec<(SocketAddr, usize)> = scene
            .lab
            .net
            .events()
            .into_iter()
            .filter_map(|event| match event {
                NetEvent::Recv(addr, datagrams) if addr != SERVER => Some((addr, datagrams)),
                _ => None,
            })
            .collect();
        polls.push(receives);
    }
    assert_eq!(
        polls[0],
        [(first, 64)],
        "a stop before the second receive: {polls:?}"
    );
    assert_eq!(
        polls.concat(),
        [(first, 64), (first, 36), (second, 10)],
        "the first socket's second receive comes before the second socket's: {polls:?}"
    );
}

#[test]
fn a_200_datagram_gro_batch_on_a_connections_own_socket_arrives_in_chunks_of_64_in_order() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        len: Some(400_000),
        client_budget: Some(budget),
        ..ServerPlan::default()
    });
    let client = scene.connect(0, Some(0));
    scene.settle_connected();
    let own = nth_socket(0);
    scene.lab.net.hold(own);
    scene.servers()[0].open_streams(1);
    scene.lab.settle_except(Some(scene.client_task));
    let batch = coalesce(&scene.lab.net.take_held());
    client.poke(1);
    scene.lab.settle_except(Some(scene.server_task));
    let received = client.stats.get().recv_packets;
    scene.lab.net.set_costs(Costs {
        chunk: SLICE * 2,
        ..Costs::default()
    });
    scene.lab.net.clear_events();
    scene.lab.net.inject(own, batch);
    let mut polls = vec![scene.poll_client()];
    // A datagram that arrives while part of the batch waits stays in the socket until the batch
    // is done.
    scene.lab.net.inject(
        own,
        Arrival {
            src: SERVER,
            stride: 1,
            data: vec![0x40],
        },
    );
    while scene.lab.queued(scene.client_task) {
        assert!(polls.len() < 50, "the client keeps waking: {polls:?}");
        polls.push(scene.poll_client());
    }
    let delivered: Vec<(u32, usize, usize)> =
        polls.iter().flat_map(|marks| own_receives(marks)).collect();
    assert_eq!(
        delivered,
        [
            (0, 0, 64),
            (0, 64, 128),
            (0, 128, 192),
            (0, 192, 200),
            (0, 0, 1)
        ],
        "{polls:?}"
    );
    assert_eq!(
        own_receives(&polls[0]),
        [(0, 0, 64)],
        "the slice closes in the first chunk: {polls:?}"
    );
    let own_io: Vec<NetEvent> = scene
        .lab
        .net
        .events()
        .into_iter()
        .filter(|event| {
            matches!(event, NetEvent::Recv(addr, _) | NetEvent::Chunk(addr) if *addr == own)
        })
        .collect();
    assert_eq!(
        own_io,
        [
            NetEvent::Recv(own, 200),
            NetEvent::Chunk(own),
            NetEvent::Chunk(own),
            NetEvent::Chunk(own),
            NetEvent::Chunk(own),
            NetEvent::Recv(own, 1),
            NetEvent::Chunk(own),
        ],
        "no receive while part of the batch waits"
    );
    scene.lab.net.set_costs(Costs::default());
    client.poke(1);
    scene.lab.settle_except(Some(scene.server_task));
    assert_eq!(
        client.stats.get().recv_packets - received,
        200,
        "every datagram of the batch reached the connection"
    );
}

#[test]
fn a_poll_that_ends_the_driver_reports_that_it_ran() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    budget.set_hold(true);
    scene.servers()[0].poke(1);
    scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    scene.server.abort();
    assert!(scene.lab.poll(scene.server_task), "the server is woken");
    assert!(!scene.lab.queued(scene.server_task), "the driver has ended");
    assert_eq!(budget.outcome(), PollOutcome::Ran);
}

#[test]
fn a_poll_whose_turn_panics_reports_that_it_ran() {
    let budget = WorkBudget::new(SLICE);
    let mut scene = Scene::new(ServerPlan {
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.lab.refill_each_iteration(&budget);
    scene.establish(1);
    budget.set_hold(true);
    scene.servers()[0].poke(1);
    scene.poll_server();
    assert_eq!(budget.outcome(), PollOutcome::Deferred);
    budget.set_hold(false);
    budget.refill();
    scene.server.fail_next_turn();
    assert!(scene.lab.poll(scene.server_task), "the server is woken");
    assert!(
        !scene.lab.queued(scene.server_task),
        "the panic ended the driver"
    );
    assert_eq!(budget.outcome(), PollOutcome::Ran);
}

#[test]
fn under_a_budget_an_attempt_builds_at_most_64_datagrams_when_its_socket_takes_more() {
    let most_built = |budget: Option<WorkBudget>| {
        let mut scene = Scene::new(ServerPlan {
            streams: 4,
            len: Some(256 * 1024),
            budget,
            socket_segments: Some(128),
            ..ServerPlan::default()
        });
        let client = scene.connect(0, Some(0));
        scene.lab.run_until(|| client.finished.get() == 4);
        scene
            .lab
            .net
            .events()
            .into_iter()
            .filter_map(|event| match event {
                NetEvent::Built(addr, _, datagrams) if addr == SERVER => Some(datagrams),
                _ => None,
            })
            .max()
            .expect("the server sent")
    };
    assert_eq!(
        most_built(None),
        128,
        "without a budget an attempt fills its socket's send"
    );
    assert_eq!(
        most_built(Some(WorkBudget::per_poll(Duration::from_secs(1)))),
        64
    );
}

#[test]
fn a_due_pacing_wake_is_attempted_before_the_next_connection_a_stop_left_in_the_queue() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(budget),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(7);
    let core = scene.client_core();
    scene.lab.net.set_costs(Costs {
        attempt: us(400),
        ..Costs::default()
    });
    for index in 0..7 {
        core.mark_dirty_at(index);
    }
    // Three attempts fill a slice. The first poll stops in its first transmit phase and the
    // second in its second, leaving the last connection queued; the next poll starts a turn.
    let first = scene.poll_client();
    assert_eq!(attempted(&first), [0, 1, 2], "{first:?}");
    let second = scene.poll_client();
    assert_eq!(attempted(&second), [3, 4, 5], "{second:?}");
    assert_eq!(stop(&second), Some(Phase::SecondTransmit), "{second:?}");
    core.arm_pacing_at(0, scene.lab.net.now());
    let third = scene.poll_client();
    assert_eq!(
        attempted(&third),
        [0, 6],
        "the wake's connection goes before the one left over: {third:?}"
    );
}

#[test]
fn with_more_wakes_due_than_a_slice_holds_the_queue_still_gets_every_other_unit() {
    // Three queued connections and an ordinary one behind them, slot 3, and twelve due wakes of
    // other connections, four slices' worth at three attempts a slice.
    const ORDINARY: u32 = 3;
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(16);
    let core = scene.client_core();
    scene.lab.net.set_costs(Costs {
        attempt: us(400),
        ..Costs::default()
    });
    for index in 0..=ORDINARY {
        core.mark_dirty_at(index);
    }
    let now = scene.lab.net.now();
    for index in 4..16 {
        core.arm_pacing_at(index, now);
    }
    let mut marks = Vec::new();
    while !attempted(&marks).contains(&ORDINARY) {
        assert!(
            marks.len() < 1_000,
            "the ordinary connection waits: {marks:?}"
        );
        marks.extend(scene.poll_client());
    }
    assert_eq!(
        units_until_attempt(&marks, ORDINARY),
        Some(2 * (ORDINARY as usize + 1)),
        "{marks:?}"
    );
    let mut order = attempted(&marks);
    order.truncate(1 + order.iter().position(|&index| index == ORDINARY).unwrap());
    assert_eq!(
        order,
        [4, 0, 5, 1, 6, 2, 7, 3],
        "serves and the queue take turns across stops: {marks:?}"
    );
    // The first stop, at 1,200 µs, left slots 1 to 3; slot 3's attempt began at 2,800 µs.
    assert_eq!(budget.stats().longest_leftover_us, 1_600);
}

#[test]
fn a_thousand_due_wakes_among_ten_thousand_queued_connections_move_keys_in_step_with_attempts() {
    const CONNECTIONS: u32 = 10_000;
    const WAKES: u32 = 1_000;
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(Duration::from_secs(1))),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(CONNECTIONS as usize);
    let core = scene.client_core();
    for round in 0..3 {
        for index in 0..CONNECTIONS {
            core.mark_dirty_at(index);
        }
        // The wakes' connections wait mid-queue, where finding a slot by its key costs most.
        let now = scene.lab.net.now();
        for index in (CONNECTIONS - WAKES) / 2..(CONNECTIONS + WAKES) / 2 {
            core.arm_pacing_at(index, now);
        }
        KEYS_MOVED.with(|moved| moved.set(0));
        let marks = scene.poll_client();
        let moved = KEYS_MOVED.with(|moved| moved.get());
        let attempts = attempted(&marks).len() as u64;
        assert!(
            attempts >= u64::from(CONNECTIONS),
            "round {round}: {attempts}"
        );
        assert!(
            moved <= 4 * attempts,
            "round {round} moved {moved} keys for {attempts} attempts"
        );
    }
}

#[test]
fn a_served_connection_dirtied_again_before_its_old_slot_pops_is_attempted_once_from_the_tail() {
    // Slots 0 and 2 are queued around slot 1, whose wake is due; one attempt fills a slice.
    const SERVED: u32 = 1;
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(SLICE)),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(3);
    let core = scene.client_core();
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    for index in 0..3 {
        core.mark_dirty_at(index);
    }
    core.arm_pacing_at(SERVED, scene.lab.net.now());
    let mut marks = scene.poll_client();
    assert_eq!(attempted(&marks), [SERVED], "{marks:?}");
    // The connection's own work, as from a receive or its application, marks it for another
    // attempt.
    core.mark_dirty_at(SERVED);
    assert_eq!(core.live_slots(SERVED), 1);
    while attempted(&marks).len() < 4 {
        assert!(marks.len() < 1_000, "the queue drains: {marks:?}");
        marks.extend(scene.poll_client());
    }
    assert_eq!(attempted(&marks), [SERVED, 0, 2, SERVED], "{marks:?}");
}

/// The live slot behind the retired ones of [`retired_run`].
const LIVE: u32 = 2_000;

/// Queues slots 0 to 999, then slots 1,000 to 1,999 with due wakes, then slot [`LIVE`], and polls
/// the client once under a slice that the last of the poll's 2,000 attempts, 2 µs each, closes.
/// Each serve takes turns with a pop from the front, so once every wake is served the queue holds
/// the served connections' 1,000 retired slots ahead of slot [`LIVE`]'s live one. Returns the
/// scene and the poll's marks.
fn retired_run() -> (Scene, Vec<Mark>) {
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(us(3_999))),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(LIVE as usize + 1);
    let core = scene.client_core();
    scene.lab.net.set_costs(Costs {
        attempt: us(2),
        ..Costs::default()
    });
    for index in 0..=LIVE {
        core.mark_dirty_at(index);
    }
    let now = scene.lab.net.now();
    for index in 1_000..LIVE {
        core.arm_pacing_at(index, now);
    }
    let marks = scene.poll_client();
    (scene, marks)
}

#[test]
fn a_run_of_retired_slots_is_checked_every_64_skips_and_a_closed_slice_stops_it_at_such_a_check() {
    let (scene, first) = retired_run();
    let core = scene.client_core();
    assert_eq!(attempted(&first).len(), 2_000);
    assert_eq!(
        skipped(&first),
        64,
        "the slice closed before the first check"
    );
    assert_eq!(
        core.tx_queue_indices(),
        (1_064..=LIVE).collect::<Vec<_>>(),
        "the rest stay in place"
    );
    // The skips are the next poll's first unit, so its first check comes after 64 of them.
    let second = scene.poll_client();
    let mut runs = Vec::new();
    let mut run = 0;
    for mark in &second {
        match mark {
            Mark::Skip(_) => run += 1,
            Mark::Unit(_) => runs.push(mem::take(&mut run)),
            _ => {}
        }
    }
    let mut checked = vec![0];
    checked.extend([64; 14]);
    checked.push(40);
    assert_eq!(runs, checked, "skips before each unit: {second:?}");
    assert_eq!(attempted(&second), [LIVE]);
}

#[test]
fn a_poll_whose_first_unit_is_a_run_of_retired_slots_stops_at_the_check_after_64_of_them() {
    let (scene, _) = retired_run();
    let core = scene.client_core();
    // Each clock reading takes longer than the slice, so the next poll's first check fails.
    scene.lab.net.set_costs(Costs {
        read: us(4_000),
        ..Costs::default()
    });
    let second = scene.poll_client();
    assert_eq!(skipped(&second), 64, "{second:?}");
    assert_eq!(attempted(&second), [], "{second:?}");
    assert_eq!(stop(&second), Some(Phase::SecondTransmit), "{second:?}");
    assert_eq!(
        core.tx_queue_indices(),
        (1_128..=LIVE).collect::<Vec<_>>(),
        "the rest stay in place"
    );
}

#[test]
fn while_a_later_wake_is_armed_a_run_of_retired_slots_reads_the_clock_once_per_64_skips() {
    let (scene, _) = retired_run();
    let core = scene.client_core();
    // The wakes have the turn, and an armed wake that is not due keeps the pacing check running.
    core.arm_pacing_at(LIVE, scene.lab.net.now() + Duration::from_secs(1));
    let before = scene.client.tx_record().phase_clock_reads;
    let second = scene.poll_client();
    let reads = scene.client.tx_record().phase_clock_reads - before;
    let skips = skipped(&second) as u64;
    assert_eq!(skips, 936, "{second:?}");
    assert_eq!(attempted(&second), [LIVE], "{second:?}");
    // One reading before the run's first pop and one per 64 skips after it, which their checks
    // share, then one for the live slot's check.
    assert!(
        reads <= skips.div_ceil(64) + 1,
        "{reads} readings for {skips} skips"
    );
}

#[test]
fn slots_of_connections_freed_while_they_wait_are_skipped_with_a_check_every_64() {
    const CONNECTIONS: usize = 1_000;
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(Duration::from_secs(1))),
        ..ServerPlan::default()
    });
    let probes = scene.connect_nowhere(CONNECTIONS);
    // Every connection's idle timeout passes at once. Serving its deadline marks it dirty, and
    // the application phase frees it before a transmit phase pops its slot.
    scene.lab.advance(Duration::from_secs(60));
    let mut marks = Vec::new();
    while scene.lab.queued(scene.client_task) {
        assert!(marks.len() < 100_000, "the client settles: {marks:?}");
        marks.extend(scene.poll_client());
    }
    assert!(probes.iter().all(|probe| probe.closed.get()));
    assert_eq!(attempted(&marks), [], "{marks:?}");
    assert_eq!(skipped(&marks), CONNECTIONS, "{marks:?}");
    let runs = runs_between_units(&marks, |mark| matches!(mark, Mark::Skip(_)));
    assert!(runs.len() > 2, "{runs:?}");
    assert!(
        runs.iter().all(|&run| run <= 64),
        "skips per unit: {runs:?}"
    );
}

/// Returns how many stale slots a poll skipped.
fn skipped(marks: &[Mark]) -> usize {
    marks
        .iter()
        .filter(|mark| matches!(mark, Mark::Skip(_)))
        .count()
}

#[test]
fn a_leftover_wait_ends_only_once_the_last_connection_its_stop_left_has_had_its_attempt() {
    // One attempt fills a slice: slot 0 runs, and the stop before slot 1 leaves slots 1 to 3.
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(4);
    let core = scene.client_core();
    scene.lab.net.set_costs(Costs {
        attempt: us(1_500),
        ..Costs::default()
    });
    for index in 0..4 {
        core.mark_dirty_at(index);
    }
    let mut attempts = attempted(&scene.poll_client());
    // A due wake serves slot 1, which is dirtied again and served again by a second wake.
    core.arm_pacing_at(1, scene.lab.net.now());
    attempts.extend(attempted(&scene.poll_client()));
    core.mark_dirty_at(1);
    core.arm_pacing_at(1, scene.lab.net.now());
    for _ in 0..2 {
        attempts.extend(attempted(&scene.poll_client()));
    }
    assert_eq!(attempts, [0, 1, 2, 1]);
    assert_eq!(
        budget.stats().longest_leftover_us,
        0,
        "slot 3 has not had its attempt"
    );
    attempts.extend(attempted(&scene.poll_client()));
    assert_eq!(attempts, [0, 1, 2, 1, 3]);
    // The stop came at 1,500 µs and slot 3's attempt began at 6,000 µs.
    assert_eq!(budget.stats().longest_leftover_us, 4_500);
    assert_eq!(budget.stats().long_leftovers, 1);
}

#[test]
fn a_quiesce_at_ten_thousand_connections_closes_every_one_walking_at_most_1_024_a_turn() {
    const CONNECTIONS: usize = 10_000;
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(Duration::from_secs(1))),
        ..ServerPlan::default()
    });
    let probes = scene.connect_nowhere(CONNECTIONS);
    // With a zero grace period, the sweep that notifies each connection of the quiesce and the
    // sweep that closes it start in one turn.
    scene.client.quiesce(Duration::ZERO);
    let mut marks = Vec::new();
    while !probes.iter().all(|probe| probe.closed.get()) {
        assert!(
            marks.len() < 10 * CONNECTIONS * 10,
            "every connection closes"
        );
        marks.extend(scene.poll_client());
    }
    let walked: Vec<usize> = marks
        .split(|mark| *mark == Mark::Turn)
        .map(|turn| {
            turn.iter()
                .filter(|mark| matches!(mark, Mark::Swept(_)))
                .count()
        })
        .collect();
    assert!(
        walked.iter().all(|&n| n <= 1_024),
        "walked per turn: {walked:?}"
    );
    assert_eq!(walked.iter().sum::<usize>(), 2 * CONNECTIONS, "{walked:?}");
}

/// Returns, for each unit mark in `marks`, how many marks that match `walked` came between it and
/// the unit mark before it, then how many came after the last unit mark.
fn runs_between_units(marks: &[Mark], walked: impl Fn(&Mark) -> bool) -> Vec<usize> {
    let mut runs = Vec::new();
    let mut run = 0;
    for mark in marks {
        if walked(mark) {
            run += 1;
        } else if matches!(mark, Mark::Unit(_)) {
            runs.push(mem::take(&mut run));
        }
    }
    runs.push(run);
    runs
}

/// Returns the marks of `marks` from its `phase` to its next phase.
fn phase_marks(marks: &[Mark], phase: Phase) -> &[Mark] {
    let Some(start) = marks.iter().position(|mark| *mark == Mark::Phase(phase)) else {
        return &[];
    };
    let rest = &marks[start + 1..];
    let end = rest
        .iter()
        .position(|mark| matches!(mark, Mark::Phase(_)))
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn a_quiesce_sweep_that_a_check_stops_goes_on_from_its_cursor_in_the_next_turn() {
    const CONNECTIONS: u32 = 2_000;
    let mut scene = Scene::new(ServerPlan {
        client_budget: Some(WorkBudget::per_poll(SLICE)),
        ..ServerPlan::default()
    });
    scene.connect_nowhere(CONNECTIONS as usize);
    // Each check reads the clock, so a slice holds about ten of them.
    scene.lab.net.set_costs(Costs {
        read: us(100),
        ..Costs::default()
    });
    // A grace period longer than the test leaves only the sweep that notifies each connection.
    scene.client.quiesce(Duration::from_secs(60));
    let swept = |marks: &[Mark]| -> Vec<u32> {
        marks
            .iter()
            .filter_map(|mark| match mark {
                Mark::Swept(key) => Some(key.index),
                _ => None,
            })
            .collect()
    };
    let first = scene.poll_client();
    assert_eq!(stop(&first), Some(Phase::Intake), "{first:?}");
    assert!(
        first
            .iter()
            .filter(|mark| matches!(mark, Mark::Unit(_)))
            .all(|mark| *mark == Mark::Unit(UnitKind::Sweep)),
        "{first:?}"
    );
    let runs = runs_between_units(&first, |mark| matches!(mark, Mark::Swept(_)));
    assert!(runs.len() > 2, "the sweep spans several units: {runs:?}");
    assert_eq!(runs[0], 0, "a unit begins the sweep: {first:?}");
    assert!(
        runs[1..].iter().all(|&run| run == 64),
        "one step of 64 a unit: {runs:?}"
    );
    let cursor = swept(&first).len() as u32;
    assert_eq!(swept(&first), (0..cursor).collect::<Vec<_>>());
    // The next poll goes on with the rest of the stopped turn, past its intake.
    let second = scene.poll_client();
    let phases: Vec<&Mark> = second
        .iter()
        .filter(|mark| matches!(mark, Mark::Phase(_)))
        .collect();
    assert_eq!(phases[0], &Mark::Phase(Phase::FirstApp), "{second:?}");
    let mut marks = second;
    while swept(&marks).len() < (CONNECTIONS - cursor) as usize {
        assert!(marks.len() < 100_000, "the sweep finishes: {marks:?}");
        marks.extend(scene.poll_client());
    }
    assert_eq!(
        swept(&marks),
        (cursor..CONNECTIONS).collect::<Vec<_>>(),
        "the sweep goes on from its cursor"
    );
}

#[test]
fn a_remark_that_a_check_stops_goes_on_at_the_next_intake_while_the_socket_stays_writable() {
    const CONNECTIONS: usize = 1_000;
    let mut scene = Scene::new(ServerPlan {
        budget: Some(WorkBudget::per_poll(SLICE)),
        handshakes: Some(CONNECTIONS),
        ..ServerPlan::default()
    });
    let core = scene.server_core();
    scene.lab.net.block(SERVER);
    for _ in 0..CONNECTIONS {
        scene.connect(0, Some(0));
    }
    scene.lab.run_until(|| core.parked() == CONNECTIONS);
    let parked = core.parked_indices();
    // Each check reads the clock, so a slice holds about ten of them.
    scene.lab.net.set_costs(Costs {
        read: us(100),
        ..Costs::default()
    });
    scene.lab.net.unblock(SERVER);
    let remarks = |marks: &[Mark]| -> Vec<u32> {
        marks
            .iter()
            .filter_map(|mark| match mark {
                Mark::Remarked(key) => Some(key.index),
                _ => None,
            })
            .collect()
    };
    let first = scene.poll_server();
    assert_eq!(stop(&first), Some(Phase::Intake), "{first:?}");
    let mut remarked = remarks(&first);
    // The polls that go on with the stopped turn leave the rest parked, and the next turn's
    // intake goes on with them.
    loop {
        let left = core.parked();
        assert!(left > 0, "the re-mark finished before a turn began");
        let marks = scene.poll_server();
        remarked.extend(remarks(&marks));
        if marks.contains(&Mark::Turn) {
            assert!(
                !remarks(phase_marks(&marks, Phase::Intake)).is_empty(),
                "the intake goes on with the re-mark: {marks:?}"
            );
            break;
        }
    }
    assert_eq!(remarked, parked[..remarked.len()], "in order");
}

#[test]
fn ten_thousand_connections_parked_on_a_blocked_socket_are_remarked_in_steps_of_64_in_order() {
    const CONNECTIONS: usize = 10_000;
    let mut scene = Scene::new(ServerPlan {
        budget: Some(WorkBudget::per_poll(SLICE)),
        handshakes: Some(CONNECTIONS),
        ..ServerPlan::default()
    });
    let core = scene.server_core();
    scene.lab.net.block(SERVER);
    for _ in 0..CONNECTIONS {
        scene.connect(0, Some(0));
    }
    scene.lab.run_until(|| core.parked() == CONNECTIONS);
    let parked = core.parked_indices();
    // Each check reads the clock, so a slice holds about ten of them.
    scene.lab.net.set_costs(Costs {
        read: us(100),
        ..Costs::default()
    });
    scene.lab.net.unblock(SERVER);
    let mut marks = Vec::new();
    let mut polls = 0;
    while core.parked() > 0 {
        assert!(
            polls < CONNECTIONS,
            "the re-mark finishes: {} parked",
            core.parked()
        );
        marks.extend(scene.poll_server());
        polls += 1;
    }
    let mut runs = Vec::new();
    let mut remarked = Vec::new();
    let mut run = 0;
    for mark in &marks {
        match mark {
            Mark::Remarked(key) => {
                remarked.push(key.index);
                run += 1;
            }
            Mark::Unit(_) => runs.push(mem::take(&mut run)),
            _ => {}
        }
    }
    runs.push(run);
    assert!(
        runs.iter().all(|&run| run <= 64),
        "re-marks per unit: {runs:?}"
    );
    assert!(polls > 1, "the re-mark spans polls");
    assert_eq!(remarked, parked, "in order, none lost");
    scene.lab.net.set_costs(Costs::default());
    let mut left: HashSet<u32> = parked.into_iter().collect();
    for index in attempted(&marks) {
        left.remove(&index);
    }
    polls = 0;
    while !left.is_empty() {
        assert!(polls < CONNECTIONS, "{} wait for an attempt", left.len());
        for index in attempted(&scene.poll_server()) {
            left.remove(&index);
        }
        polls += 1;
    }
}

#[test]
fn a_paced_connection_served_from_between_two_queued_ones_continues_behind_them_in_one_slot() {
    // Accept order is slot order: B, then A, which paces on the release socket, then C.
    const B: u32 = 0;
    const A: u32 = 1;
    const C: u32 = 2;
    let mut scene = Scene::new(ServerPlan {
        release: true,
        len: Some(32 * 1024),
        paced: |n| n == A as usize,
        segments: 4,
        build_horizon: Duration::from_millis(2),
        budget: Some(WorkBudget::per_poll(Duration::from_secs(1))),
        ..ServerPlan::default()
    });
    scene.establish(3);
    let core = scene.server_core();
    for round in 0..3 {
        for index in [B, A, C] {
            core.mark_dirty_at(index);
        }
        // A stream gives A more than one attempt's worth to build ahead, and A's wake is due.
        scene.servers()[A as usize].open_streams(1);
        core.arm_pacing_at(A, scene.lab.net.now());
        assert_eq!(core.live_slots(A), 1);
        let marks = scene.poll_server();
        let steps: Vec<(bool, u32)> = marks
            .iter()
            .filter_map(|mark| match mark {
                Mark::Attempt(key) => Some((true, key.index)),
                Mark::Skip(key) => Some((false, key.index)),
                _ => None,
            })
            .collect();
        assert!(steps.len() >= 5, "round {round}: {marks:?}");
        assert_eq!(
            steps[..5],
            [(true, A), (true, B), (false, A), (true, C), (true, A)],
            "round {round}: {marks:?}"
        );
        assert!(
            steps[5..].iter().all(|&step| step == (true, A)),
            "round {round}: {marks:?}"
        );
        assert!(core.live_slots(A) <= 1, "round {round}");
        scene.lab.run_quiet(Duration::from_millis(100));
    }
}

#[test]
fn a_paced_continuation_a_stop_leaves_keeps_its_place_and_its_releases_go_on_without_a_gap() {
    // At this window the pacer releases 44 datagrams at a time, so under the budget's cap of 64
    // each attempt builds one such run, and filling the 2 ms build horizon takes three.
    const HORIZON: Duration = Duration::from_millis(2);
    let mut scene = Scene::new(ServerPlan {
        release: true,
        len: Some(1 << 20),
        paced: |_| true,
        build_horizon: HORIZON,
        window: Some(150),
        budget: Some(WorkBudget::per_poll(us(100))),
        ..ServerPlan::default()
    });
    scene.establish(1);
    let core = scene.server_core();
    // An attempt takes longer than the slice, so each poll runs one.
    scene.lab.net.set_costs(Costs {
        attempt: us(150),
        ..Costs::default()
    });
    scene.lab.net.clear_events();
    scene.servers()[0].open_streams(1);
    let first = scene.poll_server();
    assert_eq!(attempted(&first), [0], "{first:?}");
    assert_eq!(stop(&first), Some(Phase::FirstTransmit), "{first:?}");
    assert_eq!(
        core.tx_queue_indices(),
        [0],
        "the continuation keeps its place"
    );
    let second = scene.poll_server();
    assert_eq!(attempted(&second), [0], "{second:?}");
    let third = scene.poll_server();
    assert_eq!(attempted(&third), [0], "{third:?}");
    let tick = |at: Instant| u64::try_from((at - scene.lab.net.start()).as_nanos()).unwrap();
    let releases: Vec<u64> = scene
        .lab
        .net
        .events()
        .into_iter()
        .filter_map(|event| match event {
            NetEvent::Run(SERVER, key, Release::At(Tick(at)), _) if key.index == 0 => Some(at),
            _ => None,
        })
        .collect();
    assert_eq!(releases.len(), 3, "one run an attempt: {releases:?}");
    let step = releases[1] - releases[0];
    assert_eq!(
        releases[2] - releases[1],
        step,
        "the releases go on without a gap"
    );
    let attempts = scene.server.tx_record().attempts;
    let [.., resumed, last] = attempts.as_slice() else {
        panic!("the server attempted");
    };
    assert!(
        tick(resumed.at) < releases[0] + step,
        "the continuation resumed within the first attempt's coverage"
    );
    let filled = tick(last.at + HORIZON);
    assert!(
        releases[2] <= filled && filled < releases[2] + step,
        "the third attempt filled to the horizon: {releases:?} {filled}"
    );
}

/// Returns a server scene and its per-poll budget of [`SLICE`]: one established connection that
/// opens four long streams and sends them in attempts of ten datagrams, on a socket with kernel
/// release if `release`. Each attempt costs 100 µs and each datagram a flush sends costs `flush`.
fn streaming(release: bool, flush: Duration) -> (Scene, WorkBudget) {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        release,
        len: Some(1 << 20),
        segments: 10,
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.establish(1);
    scene.lab.net.set_costs(Costs {
        attempt: us(100),
        flush,
        ..Costs::default()
    });
    scene.servers()[0].open_streams(4);
    (scene, budget)
}

/// Returns how many end-of-phase flushes `budget` has timed, the datagrams they sent and their µs.
fn flushes(budget: &WorkBudget) -> (u64, u64, u64) {
    let stats = budget.stats();
    (stats.flushes, stats.flushed_datagrams, stats.flush_us)
}

/// Returns `after` less `before`, field by field.
fn since(after: (u64, u64, u64), before: (u64, u64, u64)) -> (u64, u64, u64) {
    (after.0 - before.0, after.1 - before.1, after.2 - before.2)
}

/// Returns the datagrams each attempt on the server's socket built since the events were last
/// cleared.
fn built_on_server(scene: &Scene) -> Vec<u16> {
    scene
        .lab
        .net
        .events()
        .into_iter()
        .filter_map(|event| match event {
            NetEvent::Built(addr, _, datagrams) if addr == SERVER => Some(datagrams),
            _ => None,
        })
        .collect()
}

#[test]
fn an_end_of_phase_flush_after_a_stop_is_timed_under_its_own_kind() {
    let (scene, budget) = streaming(false, us(5));
    scene.lab.net.clear_events();
    let before = flushes(&budget);
    let marks = scene.poll_server();
    assert_eq!(
        attempted(&marks).len(),
        11,
        "nothing staged was flushed at a cost yet, so nothing is reserved: {marks:?}"
    );
    assert_eq!(stop(&marks), Some(Phase::FirstTransmit), "{marks:?}");
    assert_eq!(built_on_server(&scene), [10; 11]);
    let stats = budget.stats();
    assert_eq!(
        stats.longest_past_us(UnitKind::Attempt),
        100,
        "the eleventh attempt began at the deadline"
    );
    assert_eq!(
        stats.longest_past_us(UnitKind::TransmitFlush),
        550,
        "the flush after the stop sent 110 datagrams at 5 µs each, wholly past the deadline"
    );
    assert_eq!(since(flushes(&budget), before), (1, 110, 550));
}

#[test]
fn an_end_of_phase_flush_after_a_phase_without_a_stop_is_timed_apart_from_its_last_attempt() {
    let budget = WorkBudget::per_poll(SLICE);
    let mut scene = Scene::new(ServerPlan {
        len: Some(5_000),
        budget: Some(budget.clone()),
        ..ServerPlan::default()
    });
    scene.establish(1);
    scene.lab.net.set_costs(Costs {
        attempt: us(900),
        flush: us(100),
        ..Costs::default()
    });
    scene.servers()[0].open_streams(1);
    scene.lab.net.clear_events();
    let before = flushes(&budget);
    let marks = scene.poll_server();
    assert_eq!(attempted(&marks), [0], "{marks:?}");
    let sent: u16 = built_on_server(&scene).iter().sum();
    assert!(sent >= 2, "the stream takes a few datagrams: {sent}");
    assert_eq!(
        stop(&marks),
        Some(Phase::SecondApp),
        "the attempt sent the whole stream and the phase ended without a stop; the flush closed \
         the slice: {marks:?}"
    );
    let stats = budget.stats();
    assert_eq!(
        stats.longest_past_us(UnitKind::Attempt),
        0,
        "the attempt ended at 900 µs, inside the slice"
    );
    assert_eq!(
        stats.longest_past_us(UnitKind::TransmitFlush),
        100 * u64::from(sent) - 100,
        "the flush began at 900 µs and took 100 µs a datagram"
    );
    let (timed, datagrams, _) = since(flushes(&budget), before);
    assert_eq!((timed, datagrams), (1, u64::from(sent)));
}

#[test]
fn a_transmit_phase_stops_before_an_attempt_once_less_is_left_than_its_predicted_flush() {
    for (flush, attempts, took, why) in [
        (
            us(5),
            7,
            us(1_050),
            "after seven attempts 300 µs are left, and flushing their 70 datagrams is predicted \
             at 350 µs from the first poll's 5 µs a datagram",
        ),
        (
            us(100),
            6,
            us(6_600),
            "the reserve is at most half the slice: after six attempts 400 µs are left",
        ),
        (
            us(0),
            11,
            us(1_100),
            "flushes that cost nothing reserve nothing",
        ),
    ] {
        let (scene, budget) = streaming(false, flush);
        let before = flushes(&budget);
        let first = scene.poll_server();
        assert_eq!(attempted(&first).len(), 11, "{why}: {first:?}");
        assert_eq!(budget.stats().reserve_stops, 0);
        scene.lab.net.clear_events();
        let start = scene.lab.net.now();
        let second = scene.poll_server();
        assert_eq!(attempted(&second).len(), attempts, "{why}: {second:?}");
        assert_eq!(
            stop(&second),
            Some(Phase::SecondTransmit),
            "{why}: {second:?}"
        );
        assert_eq!(built_on_server(&scene), vec![10; attempts], "{why}");
        assert_eq!(
            scene.lab.net.now() - start,
            took,
            "the poll's attempts and its flush: {why}"
        );
        let stats = budget.stats();
        assert_eq!(stats.reserve_stops, u64::from(attempts < 11), "{why}");
        assert_eq!(budget.outcome(), PollOutcome::Stopped);
        assert!(
            scene.lab.queued(scene.server_task),
            "a stop wakes the driver"
        );
        assert_eq!(
            since(flushes(&budget), before).1,
            110 + 10 * attempts as u64,
            "each poll's end-of-phase flush sent what its phase built"
        );
    }
}

#[test]
fn a_per_attempt_flush_on_a_release_socket_is_part_of_its_attempt_and_leaves_nothing_reserved() {
    let (scene, budget) = streaming(true, us(5));
    for _ in 0..2 {
        scene.lab.net.clear_events();
        let before = flushes(&budget);
        let marks = scene.poll_server();
        assert_eq!(
            attempted(&marks).len(),
            7,
            "each attempt and its flush take 150 µs, and nothing waits for the phase's flush, \
             so nothing is reserved: {marks:?}"
        );
        let events = scene.lab.net.events();
        let sends = events
            .iter()
            .filter(|event| **event == NetEvent::Flush(SERVER))
            .count();
        assert!(
            sends > 7,
            "a flush after each attempt, then the phase's: {events:?}"
        );
        let stats = budget.stats();
        assert_eq!(
            stats.longest_past_us(UnitKind::Attempt),
            50,
            "the seventh attempt began at 900 µs and its flush ended at 1,050 µs: the budget \
             charges a flush inside an attempt to the attempt"
        );
        assert_eq!(stats.reserve_stops, 0);
        let (timed, datagrams, _) = since(flushes(&budget), before);
        assert_eq!(
            (timed, datagrams),
            (1, 0),
            "the phase's own flush finds nothing left"
        );
        assert_eq!(stats.longest_past_us(UnitKind::TransmitFlush), 0);
    }
}
