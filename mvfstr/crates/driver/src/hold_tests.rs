/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the release hold: a server driver in the lab, on its test clock, whose socket has
//! kernel release and whose connections build ahead, holds the runs of its transmit attempts on
//! the socket and hands them to the kernel together.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::Release;
use mvfstr_proto::Tick;
use mvfstr_proto::TransportConfig;
use rustls::pki_types::ServerName;

use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::EndpointStats;
use crate::lab::Bulk;
use crate::lab::Costs;
use crate::lab::FlushRecord;
use crate::lab::Lab;
use crate::lab::LabApp;
use crate::lab::MemBackend;
use crate::lab::MemOptions;
use crate::lab::NetEvent;
use crate::lab::Probe;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::transport;
use crate::turn::AttemptRecord;
use crate::turn::Core;
use crate::turn::HoldRecord;
use crate::turn::Mark;

type Handle = EndpointHandle<LabApp, MemBackend>;

fn us(n: u64) -> Duration {
    Duration::from_micros(n)
}

/// How far ahead of their release the server's connections build, inside the lab socket's 2 ms.
const HORIZON: Duration = Duration::from_millis(1);

/// The bytes of a stream that one datagram carries.
const SMALL: usize = 100;

/// How a [`Scene`] is set up.
#[derive(Clone, Copy)]
struct Plan {
    /// Whether the server socket has kernel release; its runs still leave at its flush.
    release: bool,
    /// How far ahead of their release the connections of both drivers build.
    horizon: Duration,
    /// The server's release hold, if it has one.
    hold: Option<Duration>,
    /// Whether the `n`-th accepted connection paces.
    paced: fn(usize) -> bool,
    /// The bytes each stream of the `n`-th accepted connection sends.
    len: fn(usize) -> usize,
    /// The initial window, in packets, of the `n`-th accepted connection, if not the lab's.
    window: fn(usize) -> Option<u32>,
    /// The builder's cap on the datagrams of one transmit attempt of the server.
    segments: u16,
    /// Whether the client's own sockets have kernel release, and the client's release hold.
    client_release: bool,
    client_hold: Option<Duration>,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            release: true,
            horizon: HORIZON,
            hold: None,
            paced: |_| false,
            len: |_| SMALL,
            window: |_| None,
            segments: u16::MAX,
            client_release: false,
            client_hold: None,
        }
    }
}

/// Returns the lab's transport settings with pacing on or off and an initial window of `window`
/// packets.
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

/// A server driver and a client driver on one lab worker.
struct Scene {
    server: Handle,
    server_task: usize,
    client: Handle,
    client_task: usize,
    client_config: Arc<ClientConfig>,
    /// The server sessions' probes, in accept order, which is slot order.
    accepted: Rc<RefCell<Vec<Rc<Probe>>>>,
    /// The client sessions' probes, in connect order, which is slot order.
    clients: Vec<Rc<Probe>>,
    lab: Lab,
}

impl Scene {
    fn new(plan: Plan) -> Self {
        let lab = Lab::new();
        let (client_config, server_config, endpoint) = lab_configs();
        let endpoint = endpoint
            .to_builder()
            .build_horizon(plan.horizon)
            .build()
            .expect("an endpoint config");
        let accepted: Rc<RefCell<Vec<Rc<Probe>>>> = Rc::default();
        let (net, probes) = (lab.net.clone(), Rc::clone(&accepted));
        let Plan {
            paced, len, window, ..
        } = plan;
        let app = LabApp::new(&lab.net, move |n, options| {
            options.transport = Some(match window(n) {
                Some(window) => windowed(paced(n), window),
                None => transport(paced(n)),
            });
            let (session, probe) = Bulk::new(&net, 0, Some(len(n)));
            probes.borrow_mut().push(probe);
            session
        });
        let options = MemOptions {
            net: Some(lab.net.clone()),
            release: plan.release,
            max_segments: None,
            ..MemOptions::default()
        };
        let socket = MemBackend::bind(SERVER, &options).expect("the lab binds");
        let mut server = EndpointDriver::builder(Arc::clone(&endpoint), app)
            .serve(socket, server_config)
            .max_segments(plan.segments)
            .backend_options(options)
            .host_timers(Lab::timers());
        if let Some(hold) = plan.hold {
            server = server.release_hold(hold);
        }
        let server = server.spawn(lab.ctx()).expect("the server starts");
        let server_task = lab.last_spawned();
        let mut client = EndpointDriver::builder(endpoint, LabApp::client(&lab.net))
            .backend_options(MemOptions {
                net: Some(lab.net.clone()),
                release: plan.client_release,
                max_segments: None,
                ..MemOptions::default()
            })
            .host_timers(Lab::timers());
        if let Some(hold) = plan.client_hold {
            client = client.release_hold(hold);
        }
        let client = client.spawn(lab.ctx()).expect("the client starts");
        let client_task = lab.last_spawned();
        Self {
            server,
            server_task,
            client,
            client_task,
            client_config,
            accepted,
            clients: Vec::new(),
            lab,
        }
    }

    /// Returns a scene with `conns` established connections, quiet. The client's connections do
    /// not pace, and each stream they open sends [`SMALL`] bytes.
    fn established(plan: Plan, conns: usize) -> Self {
        let mut scene = Self::new(plan);
        for _ in 0..conns {
            let (session, probe) = Bulk::new(&scene.lab.net, 0, Some(SMALL));
            scene
                .client
                .connect(
                    SERVER,
                    ServerName::try_from("localhost").expect("a name"),
                    Arc::clone(&scene.client_config),
                    ConnOptions {
                        transport: Some(transport(false)),
                    },
                    session,
                )
                .expect("the client connects");
            scene.clients.push(probe);
        }
        let clients = scene.clients.clone();
        let accepted = Rc::clone(&scene.accepted);
        scene.lab.run_until(|| {
            let accepted = accepted.borrow();
            accepted.len() == clients.len()
                && accepted
                    .iter()
                    .chain(&clients)
                    .all(|probe| probe.connected.get())
        });
        scene.lab.run_quiet(Duration::from_millis(500));
        scene
    }

    fn core(&self) -> Rc<Core<LabApp, MemBackend>> {
        self.server.core().expect("the server runs")
    }

    fn servers(&self) -> Vec<Rc<Probe>> {
        self.accepted.borrow().clone()
    }

    /// Has each server connection in `conns`, by slot, open a stream, in that order, and polls
    /// the server once at `costs`. Returns what the poll did.
    fn round(&self, conns: &[u32], costs: Costs) -> Round {
        let servers = self.servers();
        for &index in conns {
            servers[index as usize].open_streams(1);
        }
        self.poll(costs)
    }

    /// Has each server connection in `conns` open a stream as [`round`](Self::round) does, and
    /// polls the server once at `costs`, but leaves the lab as the poll left it.
    fn round_still(&self, conns: &[u32], costs: Costs) -> Round {
        let servers = self.servers();
        for &index in conns {
            servers[index as usize].open_streams(1);
        }
        self.poll_only(&self.server, self.server_task, costs)
    }

    /// Polls the server once at `costs`, then quiets the lab at no cost. Returns what the poll
    /// did.
    fn poll(&self, costs: Costs) -> Round {
        let round = self.poll_only(&self.server, self.server_task, costs);
        self.lab.run_quiet(Duration::from_millis(500));
        round
    }

    /// Polls `driver`, whose task is `task`, once at `costs` and leaves the lab as the poll left
    /// it. Returns what the poll did.
    fn poll_only(&self, driver: &Handle, task: usize, costs: Costs) -> Round {
        let before = driver.tx_record();
        let counted = driver.stats();
        self.lab.net.clear_events();
        self.lab.net.set_costs(costs);
        let began = self.lab.net.now();
        assert!(self.lab.poll(task), "the driver is woken");
        self.lab.net.set_costs(Costs::default());
        let record = driver.tx_record();
        let stats = driver.stats();
        Round {
            began,
            marks: record.marks[before.marks.len()..].to_vec(),
            attempts: record.attempts[before.attempts.len()..].to_vec(),
            holds: record.holds[before.holds.len()..]
                .iter()
                .map(|hold| HoldRecord {
                    attempt: hold.attempt - before.attempts.len(),
                    ..*hold
                })
                .collect(),
            flushes: self.lab.net.flushes(),
            events: self.lab.net.events(),
            counts: Counts::of(&stats).since(Counts::of(&counted)),
            contained_panics: stats.contained_panics - counted.contained_panics,
            phase_pacing_wakes: stats.phase_pacing_wakes - counted.phase_pacing_wakes,
        }
    }

    /// Has each client connection in `conns`, by slot, open a stream, in that order, and polls
    /// the client once at `costs`, then quiets the lab at no cost. Returns what the poll did.
    fn client_round(&self, conns: &[u32], costs: Costs) -> Round {
        for &index in conns {
            self.clients[index as usize].open_streams(1);
        }
        let round = self.poll_only(&self.client, self.client_task, costs);
        self.lab.run_quiet(Duration::from_millis(500));
        round
    }
}

/// The counters of the release hold and of the attempts on release sockets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    release_attempts: [u64; 4],
    age: u64,
    stamp: u64,
    stops: u64,
    late: u64,
    blocked: u64,
    carried: u64,
    wake_lateness: [u64; 8],
}

impl Counts {
    fn of(stats: &EndpointStats) -> Self {
        Self {
            release_attempts: stats.release_attempts,
            age: stats.hold_flushes_age,
            stamp: stats.hold_flushes_stamp,
            stops: stats.hold_stop_flushes,
            late: stats.hold_late,
            blocked: stats.hold_blocked,
            carried: stats.hold_carried_flushes,
            wake_lateness: stats.pacing_wake_lateness,
        }
    }

    /// Returns these counts less `before`, each.
    fn since(self, before: Self) -> Self {
        let mut release_attempts = [0; 4];
        for (n, count) in release_attempts.iter_mut().enumerate() {
            *count = self.release_attempts[n] - before.release_attempts[n];
        }
        let mut wake_lateness = [0; 8];
        for (n, count) in wake_lateness.iter_mut().enumerate() {
            *count = self.wake_lateness[n] - before.wake_lateness[n];
        }
        Self {
            release_attempts,
            age: self.age - before.age,
            stamp: self.stamp - before.stamp,
            stops: self.stops - before.stops,
            late: self.late - before.late,
            blocked: self.blocked - before.blocked,
            carried: self.carried - before.carried,
            wake_lateness,
        }
    }
}

/// What one poll of a scene's driver did.
#[derive(Debug)]
struct Round {
    /// The test clock as the poll began.
    began: Instant,
    marks: Vec<Mark>,
    /// The poll's transmit attempts, in order.
    attempts: Vec<AttemptRecord>,
    /// The hold after each of `attempts`, by its place there.
    holds: Vec<HoldRecord>,
    /// The flushes of every lab socket in the poll, in order.
    flushes: Vec<FlushRecord>,
    events: Vec<NetEvent>,
    /// The counters the poll moved.
    counts: Counts,
    contained_panics: u64,
    phase_pacing_wakes: u64,
}

impl Round {
    /// Returns the µs from the poll's start to `at`.
    fn since(&self, at: Instant) -> u64 {
        u64::try_from((at - self.began).as_micros()).unwrap()
    }

    /// Returns the slots of the poll's attempts, in order.
    fn slots(&self) -> Vec<u32> {
        self.attempts
            .iter()
            .map(|attempt| attempt.key.index)
            .collect()
    }

    /// Returns the flushes of the server socket that sent datagrams, each as the slots of the
    /// runs it sent.
    fn sent(&self) -> Vec<Vec<u32>> {
        self.flushes
            .iter()
            .filter(|flush| flush.addr == SERVER && flush.datagrams() > 0)
            .map(|flush| flush.runs.iter().map(|&(key, _, _)| key.index).collect())
            .collect()
    }

    /// Returns when each flush of the server socket that sent datagrams began and ended, in µs
    /// from the poll's start.
    fn flush_times(&self) -> Vec<(u64, u64)> {
        self.flushes
            .iter()
            .filter(|flush| flush.addr == SERVER && flush.datagrams() > 0)
            .map(|flush| (self.since(flush.began), self.since(flush.ended)))
            .collect()
    }

    /// Returns each attempt's reading, in µs from the poll's start.
    fn attempt_times(&self) -> Vec<u64> {
        self.attempts
            .iter()
            .map(|attempt| self.since(attempt.at))
            .collect()
    }

    /// Returns, for each hold flush, how many of the poll's attempts came before it.
    fn hold_flushes(&self) -> Vec<usize> {
        let mut attempts = 0;
        let mut before = Vec::new();
        for mark in &self.marks {
            match mark {
                Mark::Attempt(_) => attempts += 1,
                Mark::HoldFlush => before.push(attempts),
                _ => {}
            }
        }
        before
    }

    /// Returns the hold after each attempt, in µs from the poll's start.
    fn hold_times(&self) -> Vec<Option<u64>> {
        self.holds
            .iter()
            .map(|hold| hold.until.map(|until| self.since(until)))
            .collect()
    }

    /// Returns the runs the server socket's attempts built, in order: the slot, the attempt's
    /// place in the poll, the release and the datagrams.
    fn runs(&self) -> Vec<(u32, usize, Release, usize)> {
        let mut attempt = None;
        let mut runs = Vec::new();
        for event in &self.events {
            match *event {
                NetEvent::Attempt(SERVER, _) => attempt = Some(attempt.map_or(0, |n| n + 1)),
                NetEvent::Run(SERVER, key, release, datagrams) => runs.push((
                    key.index,
                    attempt.expect("a run follows its attempt"),
                    release,
                    datagrams,
                )),
                _ => {}
            }
        }
        runs
    }

    /// Returns, for each run in [`runs`](Self::runs), when the flush that sent it ended.
    fn sent_at(&self) -> Vec<Option<Instant>> {
        let mut sent: HashMap<u32, Vec<Instant>> = HashMap::new();
        for flush in self.flushes.iter().filter(|flush| flush.addr == SERVER) {
            for &(key, _, _) in &flush.runs {
                sent.entry(key.index).or_default().push(flush.ended);
            }
        }
        let mut taken: HashMap<u32, usize> = HashMap::new();
        self.runs()
            .iter()
            .map(|&(index, ..)| {
                let n = taken.entry(index).or_default();
                *n += 1;
                sent.get(&index).and_then(|ends| ends.get(*n - 1)).copied()
            })
            .collect()
    }

    /// Returns, for each attempt of slot `index` on the server socket, the datagrams of that
    /// slot the socket held queued as the attempt began.
    fn own_queued_at_attempts(&self, index: u32) -> Vec<usize> {
        let mut flushes = self.flushes.iter().filter(|flush| flush.addr == SERVER);
        let mut queued: HashMap<u32, usize> = HashMap::new();
        let mut at_attempts = Vec::new();
        for event in &self.events {
            match *event {
                NetEvent::Attempt(SERVER, key) if key.index == index => {
                    at_attempts.push(queued.get(&index).copied().unwrap_or(0));
                }
                NetEvent::Run(SERVER, key, _, datagrams) => {
                    *queued.entry(key.index).or_default() += datagrams;
                }
                NetEvent::Flush(SERVER) => {
                    let flush = flushes.next().expect("each flush is recorded");
                    if !flush.runs.is_empty() {
                        queued.clear();
                    }
                }
                _ => {}
            }
        }
        at_attempts
    }
}

/// Returns the slots `0..n`.
fn slots(n: u32) -> Vec<u32> {
    (0..n).collect()
}

/// Returns each slot of `0..n` alone, as the runs of one flush each.
fn one_flush_each(n: u32) -> Vec<Vec<u32>> {
    (0..n).map(|index| vec![index]).collect()
}

/// Sixteen connections that each build one run due at once, at 10 µs an attempt.
const FAN_OUT: u32 = 16;

fn fan_out_costs() -> Costs {
    Costs {
        attempt: us(10),
        ..Costs::default()
    }
}

#[test]
fn without_a_release_hold_every_attempt_on_a_release_socket_is_flushed_after_itself() {
    let scene = Scene::established(Plan::default(), FAN_OUT as usize);
    let round = scene.round(&slots(FAN_OUT), fan_out_costs());
    assert_eq!(round.slots(), slots(FAN_OUT));
    assert_eq!(round.sent(), one_flush_each(FAN_OUT), "{:?}", round.flushes);
    assert_eq!(
        round.hold_flushes(),
        Vec::<usize>::new(),
        "{:?}",
        round.marks
    );
    assert_eq!(round.hold_times(), vec![None; FAN_OUT as usize]);
    assert_eq!(
        scene.core().flush_cost().predict(1),
        Duration::ZERO,
        "the end-of-phase flushes of a driver without a budget are not timed"
    );
}

#[test]
fn a_release_hold_hands_the_runs_of_many_connections_to_the_kernel_in_one_flush_per_bound() {
    // A flush is due once the oldest held run has waited 50 µs, five attempts.
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    let round = scene.round(&slots(FAN_OUT), fan_out_costs());
    assert_eq!(round.slots(), slots(FAN_OUT));
    assert_eq!(
        round.sent(),
        [
            vec![0, 1, 2, 3, 4],
            vec![5, 6, 7, 8, 9],
            vec![10, 11, 12, 13, 14],
            vec![15]
        ],
        "{:?}",
        round.flushes
    );
    assert_eq!(round.hold_flushes(), [5, 10, 15], "{:?}", round.marks);
    assert_eq!(
        round.flush_times(),
        [(50, 50), (100, 100), (150, 150), (160, 160)]
    );
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 16, 0, 0],
            age: 3,
            ..Counts::default()
        }
    );
}

#[test]
fn with_no_bound_on_the_hold_runs_due_at_once_wait_for_the_end_of_the_transmit_phase() {
    let scene = Scene::established(
        Plan {
            hold: Some(Duration::MAX),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    let round = scene.round(&slots(FAN_OUT), fan_out_costs());
    assert_eq!(round.sent(), [slots(FAN_OUT)], "{:?}", round.flushes);
    assert_eq!(round.flush_times(), [(160, 160)]);
    assert_eq!(
        round.hold_flushes(),
        Vec::<usize>::new(),
        "{:?}",
        round.marks
    );
    assert_eq!(
        round.hold_times(),
        vec![None; FAN_OUT as usize],
        "runs due at once set no bound"
    );
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 16, 0, 0],
            ..Counts::default()
        }
    );
}

/// Has connections each build one run due at once under a 50 µs hold, at `attempt` an attempt
/// and 4 µs a datagram flushed: first `training` of them, whose one hold flush trains the
/// driver's flush cost exactly, then `conns`. Returns the second poll.
fn trained_fan_out(attempt: Duration, training: u32, conns: u32) -> (Scene, Round) {
    let costs = Costs {
        attempt,
        flush: us(4),
        ..Costs::default()
    };
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    let first = scene.round(&slots(training), costs);
    assert_eq!(first.hold_flushes().len(), 1, "{:?}", first.marks);
    assert_eq!(
        scene.core().flush_cost().predict(1),
        us(4),
        "the first poll's hold flush trained the flush cost"
    );
    let round = scene.round(&slots(conns), costs);
    (scene, round)
}

/// Asserts that every run of `round` reached the kernel by its attempt's reading plus `bound`.
fn assert_sent_within(round: &Round, bound: Duration) {
    let runs = round.runs();
    for (run, sent) in runs.iter().zip(round.sent_at()) {
        let (index, attempt, ..) = *run;
        let sent = sent.unwrap_or_else(|| panic!("run {run:?} was not sent: {:?}", round.flushes));
        let reading = round.attempts[attempt].at;
        assert!(
            sent <= reading + bound,
            "the run of slot {index} read at {} µs reached the kernel at {} µs: {:?}",
            round.since(reading),
            round.since(sent),
            round.flushes
        );
    }
}

#[test]
fn with_a_trained_flush_cost_a_held_run_due_at_once_reaches_the_kernel_within_the_bound_and_one_attempt_shorter_than_the_bound()
 {
    // Each hold flush of the second poll carries four datagrams, as the training's carried
    // five, so the prediction stays exact at the checks that flush.
    let (_scene, round) = trained_fan_out(us(10), 6, 10);
    assert_sent_within(&round, us(50) + us(10) + us(4));
    // The flush comes once the reading and the predicted flush of the held datagrams reach the
    // bound, four attempts after the oldest, before the bound itself.
    assert_eq!(
        round.sent(),
        [vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9]],
        "{:?}",
        round.flushes
    );
    assert_eq!(round.flush_times(), [(40, 56), (96, 112), (132, 140)]);
    assert_eq!(round.hold_flushes(), [4, 8], "{:?}", round.marks);
    assert_eq!(
        (round.counts.age, round.counts.late),
        (2, 2),
        "{:?}",
        round.counts
    );
}

#[test]
fn with_a_trained_flush_cost_a_held_run_due_at_once_reaches_the_kernel_within_the_bound_and_one_attempt_longer_than_the_bound()
 {
    let (_scene, round) = trained_fan_out(us(80), 2, FAN_OUT);
    assert_sent_within(&round, us(50) + us(80) + us(4));
    // Each attempt outlasts the bound, so the check before the next flushes it.
    let hold_flushes: Vec<usize> = (1..FAN_OUT as usize).collect();
    assert_eq!(round.hold_flushes(), hold_flushes, "{:?}", round.marks);
    assert_eq!(round.sent(), one_flush_each(FAN_OUT), "{:?}", round.flushes);
    assert_eq!(round.counts.age, 15, "{:?}", round.counts);
}

/// Returns a scene with thirteen connections that build up to 2 ms ahead under a hold of `hold`.
/// The first paces, at an initial window of 30 packets, and sends 30,000 bytes a stream: at the
/// lab's 1 ms round trip its pacer releases them as two runs at once and one run 1,066 µs later.
/// The others do not pace and send one datagram a stream.
fn leading(hold: Duration) -> Scene {
    leading_with(Some(hold), Duration::from_millis(2))
}

/// Returns a [`leading`] scene without a hold whose connections build up to `horizon` ahead.
fn leading_within(horizon: Duration) -> Scene {
    leading_with(None, horizon)
}

fn leading_with(hold: Option<Duration>, horizon: Duration) -> Scene {
    Scene::established(
        Plan {
            hold,
            horizon,
            paced: |n| n == 0,
            len: |n| if n == 0 { 30_000 } else { SMALL },
            window: |_| Some(30),
            ..Plan::default()
        },
        13,
    )
}

/// Returns how far, in ns, the run released at `release` lay ahead of `reading`.
fn lead_ns(scene: &Scene, reading: Instant, release: Release) -> u64 {
    let Release::At(Tick(tick)) = release else {
        panic!("an unstamped run on a release socket");
    };
    let read = u64::try_from((reading - scene.lab.net.start()).as_nanos()).unwrap();
    tick.saturating_sub(read)
}

#[test]
fn a_held_run_released_after_its_reading_reaches_the_kernel_by_half_its_lead_and_one_attempt() {
    // Twelve attempts of 100 µs under a 1 ms hold flush once, ten datagrams at 1 µs each, which
    // trains the flush cost. Then the paced connection's attempt holds a run that leads its
    // reading by less than twice the hold.
    let costs = Costs {
        attempt: us(100),
        flush: us(1),
        ..Costs::default()
    };
    let scene = leading(us(1_000));
    let training = scene.round(&(1..13).collect::<Vec<u32>>(), costs);
    assert_eq!(training.hold_flushes(), [10], "{:?}", training.marks);
    assert_eq!(scene.core().flush_cost().predict(1), us(1));
    let round = scene.round(&slots(9), costs);
    let runs = round.runs();
    let ahead: Vec<(u64, Instant)> = runs
        .iter()
        .zip(round.sent_at())
        .filter_map(|(&(_, attempt, release, _), sent)| {
            let reading = round.attempts[attempt].at;
            let lead = lead_ns(&scene, reading, release);
            (lead > 0).then(|| (lead, sent.expect("every run was sent")))
        })
        .collect();
    let [(lead, sent)] = ahead[..] else {
        panic!("not one run was built ahead: {runs:?}");
    };
    let reading = round.attempts[0].at;
    assert_eq!(lead, 1_066_000, "{runs:?}");
    assert!(
        sent <= reading + Duration::from_nanos(lead / 2) + us(100) + us(1),
        "the run {lead} ns ahead of its reading reached the kernel at {} µs: {:?}",
        round.since(sent),
        round.flushes
    );
    assert_eq!(round.hold_times()[0], Some(533), "{:?}", round.holds);
    assert_eq!(round.hold_flushes(), [6], "{:?}", round.marks);
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 8, 0, 1],
            stamp: 1,
            late: 1,
            ..Counts::default()
        }
    );
}

#[test]
fn a_bound_that_both_terms_set_at_once_counts_as_the_stamps() {
    // Half the paced connection's lead is exactly the hold.
    let scene = leading(us(533));
    let round = scene.round(&slots(9), fan_out_costs_of(us(100)));
    assert_eq!(round.hold_times()[0], Some(533), "{:?}", round.holds);
    assert_eq!(round.hold_flushes(), [6], "{:?}", round.marks);
    assert_eq!(
        (round.counts.age, round.counts.stamp),
        (0, 1),
        "{:?}",
        round.counts
    );
}

fn fan_out_costs_of(attempt: Duration) -> Costs {
    Costs {
        attempt,
        ..Costs::default()
    }
}

#[test]
fn an_attempt_after_a_hold_flush_runs_at_a_reading_taken_after_the_flush() {
    // Each held datagram costs 1 µs to flush, and the first hold flush, untrained, is late by its
    // length. The last connection's run is dropped at the end-of-phase flush, so its report is
    // applied at the phase's last reading, which must not precede its attempt.
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    scene.lab.net.drop_next_run_of(SERVER, FAN_OUT - 1);
    let round = scene.round(
        &slots(FAN_OUT),
        Costs {
            attempt: us(10),
            flush: us(1),
            ..Costs::default()
        },
    );
    assert_eq!(round.hold_flushes(), [5, 10, 15], "{:?}", round.marks);
    // The report brings the last connection's second attempt in the poll's second transmit
    // phase.
    assert_eq!(
        round.flush_times(),
        [(50, 55), (105, 110), (160, 165), (185, 186)]
    );
    assert_eq!(
        round.attempt_times(),
        [
            0, 10, 20, 30, 40, 55, 65, 75, 85, 95, 110, 120, 130, 140, 150, 165, 175
        ],
        "each attempt after a hold flush runs at the flush's end"
    );
    assert_eq!(
        round.contained_panics, 0,
        "the attempt and report checks held"
    );
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 17, 0, 0],
            age: 3,
            late: 3,
            ..Counts::default()
        }
    );
    assert_eq!(
        scene.clients[FAN_OUT as usize - 1].received.get(),
        SMALL as u64,
        "the connection whose run was dropped sent it again"
    );
}

#[test]
fn a_holding_attempt_that_fills_its_batch_is_flushed_before_its_connections_next_attempt() {
    // The first connection sends more than four datagrams' worth, at four an attempt, so it is
    // requeued after each attempt; the others' runs wait without a bound on the hold.
    let scene = Scene::established(
        Plan {
            hold: Some(Duration::MAX),
            segments: 4,
            len: |n| if n == 0 { 20_000 } else { SMALL },
            ..Plan::default()
        },
        3,
    );
    let round = scene.round(&slots(3), fan_out_costs());
    let queued = round.own_queued_at_attempts(0);
    assert!(
        queued.len() > 1,
        "the connection was requeued: {:?}",
        round.slots()
    );
    assert!(
        queued.iter().all(|&datagrams| datagrams == 0),
        "the bulk connection attempted with its own datagrams queued: {queued:?} {:?}",
        round.events
    );
    assert_eq!(round.slots(), [0, 1, 2, 0, 0, 0, 0], "{:?}", round.events);
    assert_eq!(
        round.sent(),
        [vec![0], vec![1, 2, 0], vec![0], vec![0], vec![0]],
        "{:?}",
        round.flushes
    );
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 7, 0, 0],
            stops: 4,
            ..Counts::default()
        }
    );
}

#[test]
fn a_holding_attempt_refused_by_the_socket_is_followed_by_a_flush_and_parks_its_connection() {
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        3,
    );
    scene.lab.net.block(SERVER);
    let round = scene.round(&slots(3), fan_out_costs());
    let steps: Vec<String> = round
        .events
        .iter()
        .filter_map(|event| match *event {
            NetEvent::Attempt(SERVER, key) => Some(format!("attempt {}", key.index)),
            NetEvent::Flush(SERVER) => Some("flush".to_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(
        steps,
        ["attempt 0", "flush", "attempt 1", "attempt 2", "flush"],
        "the first refusal flushed, and the EAGAIN it met stopped the flushes after attempts"
    );
    assert_eq!(scene.core().parked_indices(), [0, 1, 2]);
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [3, 0, 0, 0],
            stops: 1,
            ..Counts::default()
        }
    );
    scene.lab.net.unblock(SERVER);
    scene.lab.run_quiet(Duration::from_millis(500));
    for client in &scene.clients {
        assert_eq!(client.received.get(), SMALL as u64, "each connection sent");
    }
}

#[test]
fn after_the_end_of_phase_flush_nothing_is_held_and_the_next_phase_starts_without_a_bound() {
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        4,
    );
    let first = scene.round(&slots(3), fan_out_costs());
    assert_eq!(first.hold_times(), [Some(50), Some(50), Some(50)]);
    assert_eq!(first.sent(), [vec![0, 1, 2]], "{:?}", first.flushes);
    assert_eq!(first.flush_times(), [(30, 30)]);
    // The lab has moved on far past the first phase's bound.
    let second = scene.round(&[3], fan_out_costs());
    assert_eq!(
        second.hold_flushes(),
        Vec::<usize>::new(),
        "{:?}",
        second.marks
    );
    assert_eq!(
        second.hold_times(),
        [Some(50)],
        "the bound is the new attempt's"
    );
    assert_eq!(second.sent(), [vec![3]], "{:?}", second.flushes);
}

#[test]
fn an_eagain_at_the_end_of_phase_flush_keeps_the_held_runs_queued_until_the_socket_drains() {
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        4,
    );
    scene.lab.net.block_next_flush(SERVER);
    let first = scene.round_still(&slots(3), fan_out_costs());
    assert_eq!(first.hold_times(), [Some(50), Some(50), Some(50)]);
    let server_flushes: Vec<&FlushRecord> = first
        .flushes
        .iter()
        .filter(|flush| flush.addr == SERVER)
        .collect();
    let [flush] = server_flushes[..] else {
        panic!("not one flush: {:?}", first.flushes);
    };
    assert!(flush.runs.is_empty(), "the flush met the EAGAIN: {flush:?}");
    assert!(
        scene
            .clients
            .iter()
            .all(|client| client.received.get() == 0),
        "the held runs stayed queued"
    );
    scene.lab.net.unblock(SERVER);
    let drained = scene.poll(Costs::default());
    assert_eq!(drained.sent(), [vec![0, 1, 2]], "{:?}", drained.flushes);
    let next = scene.round(&[3], fan_out_costs());
    assert_eq!(next.hold_flushes(), Vec::<usize>::new(), "{:?}", next.marks);
    assert_eq!(next.hold_times(), [Some(50)]);
}

/// Returns `round`'s flushes of every socket, each as the socket, when it began and ended in µs
/// from the poll's start, and the runs it sent.
type Flushes = Vec<(SocketAddr, u64, u64, Vec<(ConnKey, Release, usize)>)>;

fn flushes_of(round: &Round) -> Flushes {
    round
        .flushes
        .iter()
        .map(|flush| {
            (
                flush.addr,
                round.since(flush.began),
                round.since(flush.ended),
                flush.runs.clone(),
            )
        })
        .collect()
}

/// Returns everything a server on a socket without kernel release recorded, with `hold`, from
/// the first handshake through a poll in which six connections attempt, three paced and two of
/// them sending more than a datagram, and the lab's log and flushes of that poll.
fn timer_server(hold: Option<Duration>) -> (Vec<Mark>, Vec<NetEvent>, Flushes) {
    let scene = Scene::established(
        Plan {
            release: false,
            hold,
            paced: |n| n % 2 == 0,
            len: |n| if n % 3 == 0 { 20_000 } else { SMALL },
            ..Plan::default()
        },
        6,
    );
    let round = scene.round(
        &slots(6),
        Costs {
            attempt: us(10),
            flush: us(1),
            ..Costs::default()
        },
    );
    assert_eq!(round.counts, Counts::default(), "{:?}", round.counts);
    assert!(
        round.holds.iter().all(|hold| hold.until.is_none()),
        "{:?}",
        round.holds
    );
    (
        scene.server.tx_record().marks,
        round.events.clone(),
        flushes_of(&round),
    )
}

#[test]
fn with_a_release_hold_a_server_socket_without_kernel_release_flushes_as_without_one() {
    assert_eq!(timer_server(Some(us(10))), timer_server(None));
}

/// Returns everything a client with `hold`, whose own sockets have kernel release and whose
/// connections build ahead, recorded from its first connect through a poll in which its four
/// connections attempt, and the lab's log and flushes of that poll.
fn release_client(hold: Option<Duration>) -> (Vec<Mark>, Vec<NetEvent>, Flushes) {
    let scene = Scene::established(
        Plan {
            client_release: true,
            client_hold: hold,
            ..Plan::default()
        },
        4,
    );
    let round = scene.client_round(
        &slots(4),
        Costs {
            attempt: us(10),
            flush: us(1),
            ..Costs::default()
        },
    );
    assert!(
        round.holds.iter().all(|hold| hold.until.is_none()),
        "{:?}",
        round.holds
    );
    (
        scene.client.tx_record().marks,
        round.events.clone(),
        flushes_of(&round),
    )
}

#[test]
fn with_a_release_hold_client_connections_on_their_own_sockets_flush_as_without_one() {
    assert_eq!(release_client(Some(us(10))), release_client(None));
}

#[test]
fn on_a_release_socket_attempts_that_do_not_build_ahead_flush_after_themselves_only_if_paced() {
    // Without a build horizon nothing is stamped. The paced connection's flush carries the run
    // the unpaced one before it held; the last one's waits for the end of the phase.
    let scene = Scene::established(
        Plan {
            horizon: Duration::ZERO,
            hold: Some(us(50)),
            paced: |n| n == 1,
            ..Plan::default()
        },
        3,
    );
    let round = scene.round(&slots(3), fan_out_costs());
    assert_eq!(round.slots(), [0, 1, 2]);
    assert_eq!(round.sent(), [vec![0, 1], vec![2]], "{:?}", round.flushes);
    assert_eq!(round.flush_times(), [(20, 20), (30, 30)]);
    assert_eq!(
        round.hold_flushes(),
        Vec::<usize>::new(),
        "{:?}",
        round.marks
    );
    assert_eq!(round.hold_times(), [None, None, None]);
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [0, 3, 0, 0],
            carried: 1,
            ..Counts::default()
        }
    );
}

#[test]
fn after_a_hold_flush_meets_eagain_no_hold_flush_runs_and_refused_connections_wait_for_the_socket()
{
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    scene.lab.net.block_next_flush(SERVER);
    let round = scene.round_still(&slots(FAN_OUT), fan_out_costs());
    assert_eq!(round.slots(), slots(FAN_OUT));
    assert_eq!(round.hold_flushes(), [5], "{:?}", round.marks);
    let server_flushes: Vec<(u64, usize)> = round
        .flushes
        .iter()
        .filter(|flush| flush.addr == SERVER)
        .map(|flush| (round.since(flush.began), flush.runs.len()))
        .collect();
    assert_eq!(
        server_flushes,
        [(50, 0), (160, 0)],
        "the hold flush and the end-of-phase flush met the EAGAIN"
    );
    let refused: Vec<u32> = (5..FAN_OUT).collect();
    assert_eq!(scene.core().parked_indices(), refused);
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [11, 5, 0, 0],
            age: 1,
            blocked: 1,
            ..Counts::default()
        }
    );
    scene.lab.net.unblock(SERVER);
    let drained = scene.poll(Costs::default());
    assert_eq!(drained.sent()[0], slots(5), "{:?}", drained.flushes);
    let remarked: Vec<u32> = drained
        .marks
        .iter()
        .filter_map(|mark| match mark {
            Mark::Remarked(key) => Some(key.index),
            _ => None,
        })
        .collect();
    assert_eq!(remarked, refused, "{:?}", drained.marks);
    for client in &scene.clients {
        assert_eq!(client.received.get(), SMALL as u64, "each connection sent");
    }
}

#[test]
fn a_bound_that_passes_after_the_last_check_while_eagain_stops_the_flushes_is_counted() {
    // With a trained flush cost, the check before the fifth attempt flushes ahead of the bound,
    // and that flush meets the EAGAIN. The bound passes during the fifth attempt, the last.
    let costs = Costs {
        attempt: us(10),
        flush: us(4),
        ..Costs::default()
    };
    let scene = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        6,
    );
    let training = scene.round(&slots(6), costs);
    assert_eq!(training.hold_flushes().len(), 1, "{:?}", training.marks);
    assert_eq!(scene.core().flush_cost().predict(1), us(4));
    scene.lab.net.block_next_flush(SERVER);
    let round = scene.round_still(&slots(5), costs);
    assert_eq!(round.hold_flushes(), [4], "{:?}", round.marks);
    let server_flushes: Vec<(u64, usize)> = round
        .flushes
        .iter()
        .filter(|flush| flush.addr == SERVER)
        .map(|flush| (round.since(flush.began), flush.runs.len()))
        .collect();
    assert_eq!(
        server_flushes,
        [(40, 0), (50, 0)],
        "the hold flush and the end-of-phase flush met the EAGAIN"
    );
    assert_eq!(
        round.counts,
        Counts {
            release_attempts: [1, 4, 0, 0],
            age: 1,
            blocked: 1,
            ..Counts::default()
        }
    );
}

/// Returns a scene of four connections that build up to 2 ms ahead, on a socket with kernel
/// release if `release`, under `hold`. The first paces, at an initial window of 30 packets, and
/// sends 30,000 bytes a stream: its pacer releases them as two runs at once and one 1,066 µs
/// later. The second does not pace and sends one datagram a stream, and the third sends nothing.
/// The fourth paces at a window of 150 packets and sends 60,000 bytes a stream: 44 datagrams at
/// once fill its first attempt, and its pacer releases the rest later.
fn mixed(release: bool, hold: Option<Duration>) -> Scene {
    Scene::established(
        Plan {
            release,
            hold,
            horizon: Duration::from_millis(2),
            paced: |n| n == 0 || n == 3,
            len: |n| match n {
                0 => 30_000,
                3 => 60_000,
                _ => SMALL,
            },
            window: |n| match n {
                0 => Some(30),
                3 => Some(150),
                _ => None,
            },
            ..Plan::default()
        },
        4,
    )
}

/// Has the connections of a [`mixed`] scene but the third open a stream, and the third look for
/// something to send, and polls the server once at 100 µs an attempt.
fn mixed_round(scene: &Scene) -> Round {
    let servers = scene.servers();
    servers[0].open_streams(1);
    servers[1].open_streams(1);
    servers[2].poke(1);
    servers[3].open_streams(1);
    scene.poll(fan_out_costs_of(us(100)))
}

#[test]
fn attempts_on_a_release_socket_are_counted_by_the_runs_they_built_with_or_without_a_hold() {
    // The fourth connection is requeued after its first attempt, and its second builds only
    // ahead.
    for hold in [None, Some(us(1_000))] {
        let scene = mixed(true, hold);
        let round = mixed_round(&scene);
        assert_eq!(
            round.slots(),
            [0, 1, 2, 3, 3],
            "{hold:?}: {:?}",
            round.events
        );
        assert_eq!(
            round.counts.release_attempts,
            [1, 2, 1, 1],
            "{hold:?}: {:?}",
            round.runs()
        );
    }
    let scene = mixed(false, Some(us(1_000)));
    let round = mixed_round(&scene);
    assert_eq!(
        round.counts.release_attempts,
        [0; 4],
        "a socket without kernel release: {:?}",
        round.runs()
    );
}

#[test]
fn pacing_wakes_taken_in_a_transmit_phase_are_counted_by_how_late_the_check_took_them() {
    // Within a 1 ms horizon the paced connection's first attempt builds its two runs due at
    // once, and its wake for the run 1,066 µs later comes due 66 µs into the phase, during the
    // attempt; the check before the next pop takes it 34 µs late.
    let scene = leading_within(HORIZON);
    let round = scene.round(&slots(4), fan_out_costs_of(us(100)));
    assert_eq!(round.slots(), [0, 0, 1, 2, 3], "{:?}", round.events);
    assert_eq!(round.phase_pacing_wakes, 1, "{:?}", round.marks);
    assert_eq!(
        round.counts.wake_lateness,
        [0, 0, 0, 1, 0, 0, 0, 0],
        "{:?}",
        scene.server.tx_record().wakes
    );
    scene.lab.run_quiet(Duration::from_secs(1));
    let stats = scene.server.stats();
    assert_eq!(
        stats.pacing_wake_lateness.iter().sum::<u64>(),
        stats.phase_pacing_wakes,
        "only the wakes taken in transmit phases are counted: {stats:?}"
    );
}

#[test]
fn hold_flushes_train_the_flush_cost_of_a_driver_without_a_budget_and_end_of_phase_flushes_do_not()
{
    let costs = Costs {
        attempt: us(10),
        flush: us(2),
        ..Costs::default()
    };
    let bounded = Scene::established(
        Plan {
            hold: Some(us(50)),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    bounded.round(&slots(FAN_OUT), costs);
    assert_eq!(bounded.core().flush_cost().predict(1), us(2));
    let unbounded = Scene::established(
        Plan {
            hold: Some(Duration::MAX),
            ..Plan::default()
        },
        FAN_OUT as usize,
    );
    let round = unbounded.round(&slots(FAN_OUT), costs);
    assert_eq!(round.sent(), [slots(FAN_OUT)], "{:?}", round.flushes);
    assert_eq!(unbounded.core().flush_cost().predict(1), Duration::ZERO);
}
