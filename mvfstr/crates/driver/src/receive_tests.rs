/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of how a driver reads its server socket: the bound on the receive calls of one receive
//! phase, and the probe, a receive call past the readiness the host last reported once that report
//! has gone stale. The lab's sockets here cache their readiness as a reactor does, so a socket is
//! read through `poll_recv` only after a host poll reported it.

use std::cell::RefCell;
use std::fmt::Write;
use std::mem;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::num::NonZeroU16;
use std::num::NonZeroU64;
use std::os::fd::BorrowedFd;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use mvfstr_io::Backend;
use mvfstr_io::HostBackend;
use mvfstr_io::HostOptions;
use mvfstr_io::Interest;
use mvfstr_io::IoHost;
use mvfstr_io::MmsgOptions;
use mvfstr_io::Readiness;
use mvfstr_io::SocketOptions;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::TransportConfig;
use rustls::pki_types::ServerName;

use crate::EndpointDriver;
use crate::EndpointHandle;
use crate::RxProbe;
use crate::UnitKind;
use crate::WorkBudget;
use crate::lab::Arrival;
use crate::lab::Bulk;
use crate::lab::Costs;
use crate::lab::Lab;
use crate::lab::LabApp;
use crate::lab::LabReadiness;
use crate::lab::MemBackend;
use crate::lab::MemOptions;
use crate::lab::NetEvent;
use crate::lab::Probe;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::nth_socket;
use crate::turn::Core;
use crate::turn::Limits;
use crate::turn::Mark;
use crate::turn::POLL_CHARGE;
use crate::turn::Phase;

type Handle = EndpointHandle<LabApp, MemBackend>;

/// The datagrams of a full receive batch on a lab socket.
const FULL: usize = 64;

/// The slot of the key the server sends stateless replies under, which no connection holds.
const STATELESS: u32 = u32::MAX;

/// The bytes of the stream in the busy scripts: about 2,100 datagrams.
const BULK: usize = 3_000_000;

fn us(micros: u64) -> Duration {
    Duration::from_micros(micros)
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

fn calls(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).expect("not zero")
}

/// Returns a probe on `datagrams` sent, if any, or `after` this long, if any.
fn probe(datagrams: Option<u64>, after: Option<Duration>) -> RxProbe {
    RxProbe {
        datagrams: datagrams.and_then(NonZeroU64::new),
        after,
    }
}

/// Returns the default limits with the server receive bound at `bound` and `probe`.
fn limits(bound: u16, probe: Option<RxProbe>) -> Limits {
    Limits {
        server_rx_calls: calls(bound),
        rx_probe: probe,
        ..Limits::default()
    }
}

/// Returns transport settings with an initial and largest window of `window` packets, at least
/// the default largest, and room for bulk transfers.
fn windowed(window: u32) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .max_window(window.max(2_000))
        .initial_window(window)
        .initial_rtt(Duration::from_millis(1))
        .max_data(1 << 30)
        .max_stream_data_uni(1 << 26)
        .max_streams_uni(1 << 20)
        .build()
        .expect("a transport config")
}

/// Returns a datagram for a connection ID that was never issued, too short for a stateless reset
/// to answer, so the server drops it silently.
fn junk() -> Arrival {
    junk_run(1)
}

/// Returns `n` such datagrams coalesced into one GRO run.
fn junk_run(n: usize) -> Arrival {
    let mut datagram = vec![0x40, 0xee];
    datagram.resize(21, 0xee);
    Arrival {
        src: SocketAddr::from(([127, 0, 0, 1], 9)),
        stride: 21,
        data: datagram.repeat(n),
    }
}

/// How a [`Rig`] is set up.
struct Plan {
    /// The server's limits, among them its receive bound and its probe.
    limits: Limits,
    /// How the server socket learns that it is readable.
    server: LabReadiness,
    /// The client's limits.
    client_limits: Limits,
    /// How the client's own sockets learn that they are readable.
    client: LabReadiness,
    /// The initial window, in packets, of every connection.
    window: u32,
    /// The bytes of each stream a server session opens; `None` sends without end.
    len: Option<usize>,
    /// The server's work budget.
    budget: Option<WorkBudget>,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            server: LabReadiness::Cached,
            client_limits: Limits::default(),
            client: LabReadiness::Fresh,
            window: 1_000,
            len: Some(0),
            budget: None,
        }
    }
}

/// A server driver and a client driver on one lab worker.
struct Rig {
    server: Handle,
    server_task: usize,
    client: Handle,
    client_task: usize,
    client_config: Arc<ClientConfig>,
    window: u32,
    /// The server sessions' probes, in accept order.
    accepted: Rc<RefCell<Vec<Rc<Probe>>>>,
    lab: Lab,
}

impl Rig {
    fn new(plan: Plan) -> Self {
        let lab = Lab::new();
        let (client_config, server_config, endpoint) = lab_configs();
        let accepted: Rc<RefCell<Vec<Rc<Probe>>>> = Rc::default();
        let (net, probes) = (lab.net.clone(), Rc::clone(&accepted));
        let (window, len) = (plan.window, plan.len);
        let app = LabApp::new(&lab.net, move |_, options| {
            options.transport = Some(windowed(window));
            let (session, probe) = Bulk::new(&net, 0, len);
            probes.borrow_mut().push(probe);
            session
        });
        let options = MemOptions {
            net: Some(lab.net.clone()),
            readiness: plan.server,
            ..MemOptions::default()
        };
        let socket = MemBackend::bind(SERVER, &options).expect("the lab binds");
        let mut server = EndpointDriver::builder(Arc::clone(&endpoint), app).limits(plan.limits);
        if let Some(budget) = plan.budget {
            server = server.work_budget(budget);
        }
        let server = server
            .serve(socket, server_config)
            .backend_options(options)
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the server starts");
        let server_task = lab.last_spawned();
        let client = EndpointDriver::builder(endpoint, LabApp::client(&lab.net))
            .limits(plan.client_limits)
            .backend_options(MemOptions {
                net: Some(lab.net.clone()),
                readiness: plan.client,
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
            window,
            accepted,
            lab,
        }
    }

    /// Opens a client connection, on a socket of its own, whose session sends streams of `len`
    /// bytes once a test opens them, and runs until it is established at both ends and the lab is
    /// quiet. The host polls the sockets whenever every task is idle.
    fn connect(&mut self, len: Option<usize>) -> Rc<Probe> {
        let probe = self.start_connect(len);
        let accepted = Rc::clone(&self.accepted);
        let client = Rc::clone(&probe);
        self.lab.run_until(|| {
            client.connected.get()
                && accepted
                    .borrow()
                    .last()
                    .is_some_and(|server| server.connected.get())
        });
        self.lab.run_quiet(ms(500));
        probe
    }

    /// Opens `n` client connections at once, each on a socket of its own, whose sessions open no
    /// stream, and runs until every one is established at both ends and the lab is quiet.
    fn connect_all(&mut self, n: usize) -> Vec<Rc<Probe>> {
        let clients: Vec<Rc<Probe>> = (0..n).map(|_| self.start_connect(Some(0))).collect();
        let accepted = Rc::clone(&self.accepted);
        self.lab.run_until(|| {
            let accepted = accepted.borrow();
            accepted.len() == n
                && accepted
                    .iter()
                    .chain(&clients)
                    .all(|probe| probe.connected.get())
        });
        self.lab.run_quiet(ms(500));
        clients
    }

    /// Starts a client connection, on a socket of its own, whose session sends streams of `len`
    /// bytes once a test opens them.
    fn start_connect(&self, len: Option<usize>) -> Rc<Probe> {
        let (session, probe) = Bulk::new(&self.lab.net, 0, len);
        self.client
            .connect(
                SERVER,
                ServerName::try_from("localhost").expect("a name"),
                Arc::clone(&self.client_config),
                ConnOptions {
                    transport: Some(windowed(self.window)),
                },
                session,
            )
            .expect("the client connects");
        probe
    }

    fn server_core(&self) -> Rc<Core<LabApp, MemBackend>> {
        self.server.core().expect("the server runs")
    }

    /// Returns the probe of the server's first session.
    fn session(&self) -> Rc<Probe> {
        Rc::clone(&self.accepted.borrow()[0])
    }

    /// Returns the datagrams the server's connections have sent.
    fn sent(&self) -> u64 {
        self.server.stats().sent_datagrams
    }

    /// Runs the host's loop until `done` holds; returns how many polls of the server left it
    /// waiting for a wake.
    fn run(&self, mut done: impl FnMut(&Self) -> bool) -> usize {
        let mut parks = 0;
        for _ in 0..200_000 {
            if done(self) {
                return parks;
            }
            let polled = self.lab.step();
            if polled.contains(&self.server_task) && !self.lab.queued(self.server_task) {
                parks += 1;
            }
        }
        panic!("the condition did not hold within the step cap");
    }

    /// Polls the server once and returns what the poll did.
    fn poll_server(&self) -> Vec<Mark> {
        let before = self.server.tx_record().marks.len();
        assert!(self.lab.poll(self.server_task), "the server is woken");
        self.server.tx_record().marks[before..].to_vec()
    }

    /// Polls the server while it is woken, and returns what each poll did.
    fn polls_while_woken(&self) -> Vec<Vec<Mark>> {
        let mut polls = Vec::new();
        while self.lab.queued(self.server_task) {
            polls.push(self.poll_server());
            assert!(polls.len() < 50, "the server keeps waking");
        }
        polls
    }

    /// Returns the clock reads the server has made.
    fn clock_reads(&self) -> u64 {
        self.server.tx_record().clock_reads
    }
}

/// The counters a driver keeps of its server socket's reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RxCounts {
    batches: u64,
    datagrams: u64,
    probes: u64,
    empty: u64,
    bound_hits: u64,
}

impl RxCounts {
    fn of<A: crate::QuicApplication, B: Backend>(handle: &EndpointHandle<A, B>) -> Self {
        let stats = handle.stats();
        Self {
            batches: stats.server_rx_batches,
            datagrams: stats.server_rx_datagrams,
            probes: stats.server_rx_probes,
            empty: stats.server_rx_probes_empty,
            bound_hits: stats.server_rx_bound_hits,
        }
    }

    /// Returns the counts since `before`.
    fn since(self, before: Self) -> Self {
        Self {
            batches: self.batches - before.batches,
            datagrams: self.datagrams - before.datagrams,
            probes: self.probes - before.probes,
            empty: self.empty - before.empty,
            bound_hits: self.bound_hits - before.bound_hits,
        }
    }
}

/// What the lab logged of a socket's reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rx {
    /// A host poll reported the socket readable.
    Ready,
    /// A receive call took this many datagrams.
    Recv(usize),
    /// A `poll_recv` found the cached readiness clear.
    Pending,
    /// The driver took the batch's buffers.
    Chunk,
}

/// Returns what `events` hold of the reads of the socket at `addr`, in order.
fn rx_of(events: &[NetEvent], addr: SocketAddr) -> Vec<Rx> {
    events
        .iter()
        .filter_map(|event| match *event {
            NetEvent::Ready(at) if at == addr => Some(Rx::Ready),
            NetEvent::Recv(at, n) if at == addr => Some(Rx::Recv(n)),
            NetEvent::Pending(at) if at == addr => Some(Rx::Pending),
            NetEvent::Chunk(at) if at == addr => Some(Rx::Chunk),
            _ => None,
        })
        .collect()
}

/// Returns what `events` hold of the server socket's reads, without its chunks.
fn server_rx(events: &[NetEvent]) -> Vec<Rx> {
    rx_of(events, SERVER)
        .into_iter()
        .filter(|rx| *rx != Rx::Chunk)
        .collect()
}

/// Returns the datagrams the server's connections built after the server socket's last receive
/// call in `events`, or in all of them if it made none.
fn built_since_last_recv(events: &[NetEvent]) -> u64 {
    let last = events
        .iter()
        .rposition(|event| matches!(event, NetEvent::Recv(SERVER, _)))
        .map_or(0, |at| at + 1);
    events[last..]
        .iter()
        .map(|event| match *event {
            NetEvent::Built(SERVER, key, n) if key.index != STATELESS => u64::from(n),
            _ => 0,
        })
        .sum()
}

/// Returns the batch ranges each poll routed, all polls together.
fn routes(polls: &[Vec<Mark>]) -> Vec<(usize, usize)> {
    polls
        .iter()
        .flatten()
        .filter_map(|mark| match mark {
            Mark::Route { start, end, .. } => Some((*start, *end)),
            _ => None,
        })
        .collect()
}

/// Returns the batch ranges each turn of a poll routed, leaving out turns that routed none.
fn routes_per_turn(marks: &[Mark]) -> Vec<Vec<(usize, usize)>> {
    let mut turns = vec![Vec::new()];
    for mark in marks {
        match mark {
            Mark::Turn => turns.push(Vec::new()),
            Mark::Route { start, end, .. } => {
                turns.last_mut().expect("a turn").push((*start, *end))
            }
            _ => {}
        }
    }
    turns.retain(|turn| !turn.is_empty());
    turns
}

/// Returns the batches each turn delivered from the connections' own sockets, leaving out turns
/// that delivered none.
fn own_batches_per_turn(marks: &[Mark]) -> Vec<usize> {
    let mut turns = vec![0];
    for mark in marks {
        match mark {
            Mark::Turn => turns.push(0),
            Mark::Receive { start: 0, .. } => *turns.last_mut().expect("a turn") += 1,
            _ => {}
        }
    }
    turns.retain(|&batches| batches > 0);
    turns
}

/// Returns the phase a poll stopped in.
fn stop(marks: &[Mark]) -> Option<Phase> {
    marks.iter().find_map(|mark| match mark {
        Mark::Stop(phase) => Some(*phase),
        _ => None,
    })
}

/// Returns the FNV-1a hash of `text`.
fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The server socket's reads in a stretch of the lab's log, as [`check_probes`] found them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Checked {
    /// Receive calls that found datagrams, and their datagrams.
    batches: u64,
    datagrams: u64,
    /// Receive calls past the cached readiness, and those of them that found the socket empty.
    probes: u64,
    empty: u64,
    /// Receive phases that found the cached readiness clear and made no call past it.
    passed: u64,
}

/// Walks the server socket's reads in `events` and checks, from its first receive call on, that
/// every receive phase that found the socket's cached readiness clear made one receive call past
/// it exactly when `probe` had made the socket stale, or the last such call had filled every
/// buffer. The driver's mark follows its rules: a batch read moves it to the datagrams its
/// connections have built and the clock reading taken for the batch, and a probe that finds the
/// socket empty to the datagrams built and the last reading, without a reading of its own. A park
/// restarts the probe time, so a stretch checked with `probe.after` set must hold none. A
/// receive's datagrams count as the buffers it filled, which holds only without GRO, so a stretch
/// in which the server socket received a GRO run is refused. Returns what the stretch held, from
/// its start.
fn check_probes(events: &[NetEvent], probe: RxProbe) -> Checked {
    let mut checked = Checked::default();
    let mut synced = false;
    let mut built = 0u64;
    let mut mark_built = 0u64;
    let mut mark_at: Option<Duration> = None;
    let mut reading: Option<Duration> = None;
    let mut stamp = false;
    let mut force = false;
    // Set while the last read of the server socket was a `Pending`: whether a probe was due then,
    // if the stretch is synced.
    let mut after_pending: Option<Option<bool>> = None;
    let missed = |at: usize, due: Option<Option<bool>>| {
        assert_ne!(
            due,
            Some(Some(true)),
            "event {at}: the socket was stale and no probe came"
        );
    };
    for (at, event) in events.iter().enumerate() {
        match *event {
            NetEvent::Built(SERVER, key, n) if key.index != STATELESS => built += u64::from(n),
            NetEvent::Clock(now) => {
                reading = Some(now);
                if mem::take(&mut stamp) {
                    mark_at = Some(now);
                }
            }
            NetEvent::Ready(SERVER) => {
                missed(at, after_pending.take());
            }
            NetEvent::GroRuns(SERVER, runs) => panic!(
                "event {at}: a receive on the server socket took {runs} GRO runs, but a batch's \
                 datagrams match its buffers only without GRO, so check_probes checks only \
                 stretches without GRO runs"
            ),
            NetEvent::Pending(SERVER) => {
                let previous = after_pending.take();
                missed(at, previous);
                if previous == Some(Some(false)) {
                    checked.passed += 1;
                }
                let stale_by_count = probe
                    .datagrams
                    .is_some_and(|count| built - mark_built >= count.get());
                let stale_by_time = match (probe.after, reading, mark_at) {
                    (Some(after), Some(now), Some(mark)) => now.saturating_sub(mark) >= after,
                    _ => false,
                };
                after_pending = Some(synced.then_some(force || stale_by_count || stale_by_time));
            }
            NetEvent::Recv(SERVER, n) => {
                let probed = match after_pending.take() {
                    Some(due) => {
                        assert_ne!(
                            due,
                            Some(false),
                            "event {at}: a probe of a socket that was not stale"
                        );
                        true
                    }
                    None => false,
                };
                if probed {
                    checked.probes += 1;
                }
                if n > 0 {
                    checked.batches += 1;
                    checked.datagrams += n as u64;
                    mark_built = built;
                    stamp = true;
                    force = probed && n == FULL;
                } else if probed {
                    checked.empty += 1;
                    mark_built = built;
                    mark_at = reading;
                    force = false;
                }
                synced = true;
            }
            _ => {}
        }
    }
    if let Some(due) = after_pending {
        missed(events.len(), Some(due));
        if due == Some(false) {
            checked.passed += 1;
        }
    }
    checked
}

/// Costs under which the server is busy sending: a turn takes a few hundred microseconds, so the
/// client's acknowledgements reach the server socket while the server keeps turning.
fn busy() -> Costs {
    Costs {
        attempt: us(10),
        chunk: us(5),
        flush: us(10),
        recv: us(2),
        ..Costs::default()
    }
}

/// Returns `limits` with each turn staging three polls' worth of a connection's bytes, a few
/// dozen datagrams.
fn short_turns(limits: Limits) -> Limits {
    Limits {
        turn_staging: 3 * POLL_CHARGE,
        ..limits
    }
}

/// The busy script, after it ran.
struct Busy {
    rig: Rig,
    /// The client session's probe.
    client: Rc<Probe>,
    /// The server's counters as the script began.
    before: RxCounts,
    /// Polls of the server that left it waiting for a wake, and host polls of the sockets.
    parks: usize,
    io_polls: usize,
}

/// Runs the busy script: one connection, whose server session sends a stream of [`BULK`] bytes
/// with a window it never fills, in short turns under [`busy`] costs, with the host polling the
/// sockets only when every task is idle, until the server has sent 2,000 datagrams. Clock reads
/// are logged.
fn busy_script(limits: Limits) -> Busy {
    let mut rig = Rig::new(Plan {
        limits: short_turns(limits),
        window: 100_000,
        len: Some(BULK),
        ..Plan::default()
    });
    let client = rig.connect(Some(0));
    rig.lab.io_every(None);
    rig.lab.net.log_clock();
    rig.lab.net.set_costs(busy());
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let (sent, io_polls) = (rig.sent(), rig.lab.io_polls());
    rig.session().open_streams(1);
    let parks = rig.run(|rig| rig.sent() - sent >= 2_000);
    let io_polls = rig.lab.io_polls() - io_polls;
    Busy {
        rig,
        client,
        before,
        parks,
        io_polls,
    }
}

#[test]
#[should_panic(expected = "check_probes checks only stretches without GRO runs")]
fn the_probe_check_refuses_a_stretch_in_which_the_server_socket_received_a_gro_run() {
    // The lab shuts down before the check panics, because it skips its shutdown while the thread
    // panics.
    let events = {
        let rig = Rig::new(Plan::default());
        rig.lab.settle();
        rig.lab.net.clear_events();
        rig.lab.net.inject(SERVER, junk_run(3));
        rig.lab.settle();
        rig.lab.net.events()
    };
    assert!(
        events.contains(&NetEvent::Recv(SERVER, 3)),
        "one receive took the run's three datagrams in one buffer: {events:?}"
    );
    check_probes(&events, probe(Some(2_048), None));
}

#[test]
fn a_busy_server_reads_its_socket_at_the_first_receive_phase_after_sending_the_probe_datagrams() {
    let probe = probe(Some(128), None);
    let run = busy_script(limits(32, Some(probe)));
    assert_eq!(run.parks, 0, "the server never waits for a wake");
    assert_eq!(run.io_polls, 0, "so the host never polls the sockets");
    let events = run.rig.lab.net.events();
    let checked = check_probes(&events, probe);
    let counted = RxCounts::of(&run.rig.server).since(run.before);
    assert_eq!(
        counted,
        RxCounts {
            batches: checked.batches,
            datagrams: checked.datagrams,
            probes: checked.probes,
            empty: checked.empty,
            bound_hits: 0,
        },
        "the counters match the log: {checked:?}"
    );
    // Twelve probes, seven of which found acknowledgements, and 29 receive phases that came
    // before the next 128 datagrams.
    assert_eq!(
        checked,
        Checked {
            batches: 7,
            datagrams: 8,
            probes: 12,
            empty: 5,
            passed: 29,
        }
    );
    let recvs = server_rx(&events)
        .into_iter()
        .filter(|rx| matches!(rx, Rx::Recv(_)))
        .count();
    assert_eq!(
        recvs, 12,
        "every receive call on the server socket is a probe"
    );
}

#[test]
fn a_busy_server_that_sends_little_reads_its_socket_once_the_probe_time_has_passed() {
    let probe = probe(None, Some(ms(5)));
    // Each turn stages one poll's worth of the stream, about a dozen datagrams, and the stream
    // stays ready to send, so the server turns without waiting for a wake.
    let mut rig = Rig::new(Plan {
        limits: Limits {
            turn_staging: POLL_CHARGE,
            ..limits(32, Some(probe))
        },
        window: 100_000,
        len: None,
        ..Plan::default()
    });
    rig.connect(Some(0));
    rig.lab.io_every(None);
    rig.lab.net.log_clock();
    rig.lab.net.set_costs(Costs {
        attempt: us(100),
        flush: us(10),
        recv: us(2),
        ..Costs::default()
    });
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let (turns, io_polls) = (rig.server.stats().turns, rig.lab.io_polls());
    rig.session().open_streams(1);
    let parks = rig.run(|rig| rig.server.stats().turns - turns >= 400);
    assert_eq!(parks, 0, "the server never waits for a wake");
    assert_eq!(
        rig.lab.io_polls(),
        io_polls,
        "so the host never polls the sockets"
    );
    let events = rig.lab.net.events();
    let checked = check_probes(&events, probe);
    let counted = RxCounts::of(&rig.server).since(before);
    assert_eq!(
        counted,
        RxCounts {
            batches: checked.batches,
            datagrams: checked.datagrams,
            probes: checked.probes,
            empty: checked.empty,
            bound_hits: 0,
        },
        "the counters match the log: {checked:?}"
    );
    assert_eq!(
        checked,
        Checked {
            batches: 48,
            datagrams: 144,
            probes: 49,
            empty: 1,
            passed: 391,
        }
    );
}

/// Runs a script whose every probe finds the server socket empty, and returns what the stretch
/// held, the server's counters over it, and the clock reads the server made in it. The server
/// session sends a stream, and only the server is polled, so the client never answers. With
/// `by_count`, the clock stands still, until the server has sent 300 datagrams; otherwise each
/// transmit attempt takes 500 µs, for 40 turns.
fn empty_probes(probe: Option<RxProbe>, by_count: bool) -> (Checked, RxCounts, u64) {
    let mut rig = Rig::new(Plan {
        limits: short_turns(limits(32, probe)),
        window: 100_000,
        len: Some(BULK),
        ..Plan::default()
    });
    rig.connect(Some(0));
    rig.lab.io_every(None);
    rig.lab.net.log_clock();
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let (reads, sent, turns) = (rig.clock_reads(), rig.sent(), rig.server.stats().turns);
    if !by_count {
        rig.lab.net.set_costs(Costs {
            attempt: us(500),
            ..Costs::default()
        });
    }
    rig.session().open_streams(1);
    if by_count {
        rig.polls_until(|rig| rig.sent() - sent >= 300);
    } else {
        rig.polls_until(|rig| rig.server.stats().turns - turns >= 40);
    }
    let events = rig.lab.net.events();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, NetEvent::Recv(SERVER, n) if *n > 0)),
        "nothing reached the server socket"
    );
    let checked = check_probes(
        &events,
        probe.unwrap_or(RxProbe {
            datagrams: None,
            after: None,
        }),
    );
    (
        checked,
        RxCounts::of(&rig.server).since(before),
        rig.clock_reads() - reads,
    )
}

impl Rig {
    /// Polls only the server, while it is woken, until `done` holds, so no host poll reports its
    /// socket and no other task runs.
    fn polls_until(&self, mut done: impl FnMut(&Self) -> bool) {
        for _ in 0..10_000 {
            if done(self) {
                return;
            }
            self.poll_server();
        }
        panic!("the condition did not hold within the poll cap");
    }
}

#[test]
fn a_probe_that_finds_the_socket_empty_reads_no_clock_and_restarts_both_thresholds() {
    // By the datagrams sent: each probe finds nothing, and the next comes only after 128 more.
    let by_count = probe(Some(128), None);
    let (checked, counted, reads) = empty_probes(Some(by_count), true);
    assert_eq!(
        checked,
        Checked {
            batches: 0,
            datagrams: 0,
            probes: 2,
            empty: 2,
            passed: 4,
        }
    );
    assert_eq!(
        counted,
        RxCounts {
            probes: checked.probes,
            empty: checked.empty,
            ..RxCounts::default()
        }
    );
    let (off, _, reads_off) = empty_probes(None, true);
    assert_eq!(off.probes, 0);
    assert_eq!(
        reads, reads_off,
        "the probes read no clock: the run without them reads as often"
    );

    // By time: each probe finds nothing, and the next comes only 4 ms of readings later.
    let by_time = probe(None, Some(ms(4)));
    let (checked, counted, reads) = empty_probes(Some(by_time), false);
    assert_eq!(
        checked,
        Checked {
            batches: 0,
            datagrams: 0,
            probes: 4,
            empty: 4,
            passed: 28,
        }
    );
    assert_eq!(
        counted,
        RxCounts {
            probes: checked.probes,
            empty: checked.empty,
            ..RxCounts::default()
        }
    );
    let (off, _, reads_off) = empty_probes(None, false);
    assert_eq!(off.probes, 0);
    assert_eq!(
        reads, reads_off,
        "the probes read no clock: the run without them reads as often"
    );
}

#[test]
fn a_full_probe_batch_reads_on_to_the_call_bound_and_the_next_turn_reads_the_rest_without_a_host_poll()
 {
    let mut rig = Rig::new(Plan {
        limits: limits(4, Some(probe(Some(32), None))),
        len: Some(100_000),
        ..Plan::default()
    });
    rig.connect(Some(0));
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");
    // Six full batches and ten datagrams wait in the server socket, which the host has not
    // reported readable.
    for _ in 0..6 * FULL + 10 {
        rig.lab.net.inject(SERVER, junk());
    }
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let io_polls = rig.lab.io_polls();
    // The session's stream wakes the server, whose first transmit phase sends more than the
    // probe's 32 datagrams.
    rig.session().open_streams(1);
    let marks = rig.poll_server();
    assert_eq!(
        routes_per_turn(&marks),
        [vec![(0, 64); 4], vec![(0, 64), (0, 64), (0, 10)]],
        "{marks:?}"
    );
    assert_eq!(
        server_rx(&rig.lab.net.events()),
        [
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(64),
            Rx::Pending,
            Rx::Recv(10),
            Rx::Pending,
            Rx::Pending,
        ],
        "probes all the way, with no empty one"
    );
    assert_eq!(rig.lab.io_polls(), io_polls, "no host poll");
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            batches: 7,
            datagrams: 6 * 64 + 10,
            probes: 7,
            empty: 0,
            bound_hits: 1,
        }
    );
}

#[test]
fn a_receive_error_counts_as_a_call_and_restarts_the_probe_count_as_an_empty_probe_does() {
    let mut rig = Rig::new(Plan {
        limits: limits(32, Some(probe(Some(32), None))),
        len: Some(100_000),
        ..Plan::default()
    });
    rig.connect(Some(0));
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");
    rig.lab.net.fail_next_recv(SERVER);
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    // The session's stream wakes the server, whose first transmit phase sends the whole stream,
    // more than the probe's 32 datagrams, and the client is not polled, so nothing arrives.
    rig.session().open_streams(1);
    rig.poll_server();
    let events = rig.lab.net.events();
    let failed = events
        .iter()
        .position(|event| *event == NetEvent::RecvFailed(SERVER))
        .expect("the probe's call fails");
    assert_eq!(server_rx(&events[..failed]), [Rx::Pending]);
    assert!(
        built_since_last_recv(&events[failed..]) < 32,
        "the server sends less than the probe's count after the failure"
    );
    assert!(
        server_rx(&events[failed..])
            .iter()
            .all(|&rx| rx == Rx::Pending),
        "so it probes no more: {events:?}"
    );
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            batches: 1,
            datagrams: 0,
            probes: 1,
            empty: 0,
            bound_hits: 0,
        },
        "the failed probe is a receive call"
    );
}

/// Opens a rig whose server reads one datagram the host reports, sends from streams of one byte
/// each that its session opens, and parks, all with `probe`. Returns the rig and the datagrams its
/// connections built after that read.
fn parked_after_sending(probe: RxProbe) -> (Rig, u64) {
    let mut rig = Rig::new(Plan {
        limits: limits(32, Some(probe)),
        len: Some(1),
        ..Plan::default()
    });
    rig.connect(Some(0));
    rig.lab.net.inject(SERVER, junk());
    rig.lab.net.clear_events();
    assert!(rig.lab.poll_io(), "the host reports the datagram");
    rig.polls_while_woken();
    rig.session().open_streams(8);
    rig.polls_while_woken();
    let events = rig.lab.net.events();
    assert_eq!(server_rx(&events)[..2], [Rx::Ready, Rx::Recv(1)]);
    (rig, built_since_last_recv(&events))
}

#[test]
fn the_first_turn_after_a_park_restarts_only_the_probe_time() {
    // (a) Long after the server's last read, a wake after a park finds the socket empty: the turn
    // makes no receive call and reads the clock as an idle turn does.
    let mut rig = Rig::new(Plan {
        limits: limits(32, Some(probe(Some(2_048), Some(ms(2))))),
        ..Plan::default()
    });
    rig.connect(Some(0));
    rig.lab.advance(ms(50));
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let reads = rig.clock_reads();
    rig.server_core().mark_dirty_at(0);
    let marks = rig.poll_server();
    assert_eq!(marks.iter().filter(|&&mark| mark == Mark::Turn).count(), 1);
    assert_eq!(
        server_rx(&rig.lab.net.events()),
        [Rx::Pending],
        "no receive call"
    );
    assert_eq!(rig.clock_reads() - reads, 5, "an idle turn's readings");
    assert_eq!(RxCounts::of(&rig.server).since(before), RxCounts::default());

    // (b) The server parks one datagram short of the probe's count, and a connection wake, with
    // no host poll, runs a turn that sends one more: that turn's receive phase probes once.
    let (_, built) = parked_after_sending(probe(Some(u64::MAX), None));
    assert!(built > 0);
    let (rig, again) = parked_after_sending(probe(Some(built + 1), Some(ms(2))));
    assert_eq!(again, built, "the two runs send alike");
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let io_polls = rig.lab.io_polls();
    rig.session().open_streams(1);
    rig.poll_server();
    let events = rig.lab.net.events();
    let first_read = events
        .iter()
        .position(|event| matches!(event, NetEvent::Pending(SERVER)))
        .expect("a receive phase");
    assert_eq!(
        built_since_last_recv(&events[..first_read]),
        1,
        "the turn sent one datagram before its receive phase"
    );
    assert_eq!(rig.lab.io_polls(), io_polls, "no host poll");
    assert_eq!(server_rx(&events), [Rx::Pending, Rx::Recv(0)]);
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            probes: 1,
            empty: 1,
            ..RxCounts::default()
        }
    );
}

/// Returns the checks of the work budget in `marks` that let a receive chunk run.
fn chunk_checks(marks: &[Mark]) -> usize {
    marks
        .iter()
        .filter(|&&mark| mark == Mark::Unit(UnitKind::ReceiveChunk))
        .count()
}

#[test]
fn under_a_work_budget_a_probes_batch_is_a_receive_chunk_checked_after_the_read() {
    let budget = WorkBudget::per_poll(ms(1));
    let mut rig = Rig::new(Plan {
        limits: limits(32, Some(probe(Some(1), None))),
        len: Some(1),
        budget: Some(budget.clone()),
        ..Plan::default()
    });
    rig.connect(Some(0));
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");
    // A full batch of GRO runs of three datagrams each waits unreported, and six runs more.
    for _ in 0..FULL + 6 {
        rig.lab.net.inject(SERVER, junk_run(3));
    }
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    // The probe's call outlasts the slice, so the check after it stops the poll.
    rig.lab.net.set_costs(Costs {
        recv: ms(2),
        ..Costs::default()
    });
    budget.refill();
    rig.session().open_streams(1);
    let first = rig.poll_server();
    assert_eq!(stop(&first), Some(Phase::Receive), "{first:?}");
    assert_eq!(
        chunk_checks(&first),
        0,
        "the one check of the probe's chunk came after its read, and stopped the poll: {first:?}"
    );
    assert_eq!(
        rx_of(&rig.lab.net.events(), SERVER),
        [Rx::Pending, Rx::Recv(192)],
        "one call, and no chunk taken"
    );
    let core = rig.server_core();
    assert_eq!(core.rx_resume(), Some(0), "the batch waits whole");
    assert!(core.rx_forced(), "the full probe batch still reads on");
    drop(core);

    rig.lab.net.set_costs(Costs::default());
    rig.lab.net.clear_events();
    budget.refill();
    let rest = rig.polls_while_woken();
    assert_eq!(
        routes(&rest),
        [(0, 64), (64, 128), (128, 192), (0, 18)],
        "{rest:?}"
    );
    assert_eq!(
        chunk_checks(&rest.concat()),
        4,
        "one check for each chunk, after its read: {rest:?}"
    );
    assert_eq!(
        rx_of(&rig.lab.net.events(), SERVER),
        [
            Rx::Chunk,
            Rx::Chunk,
            Rx::Chunk,
            Rx::Pending,
            Rx::Recv(18),
            Rx::Chunk,
            Rx::Pending,
        ],
        "the kept batch goes before any other receive call"
    );
    assert!(!rig.server_core().rx_forced());
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            batches: 2,
            datagrams: 3 * (64 + 6),
            probes: 2,
            empty: 0,
            bound_hits: 0,
        },
        "every datagram routed once"
    );
}

#[test]
fn a_connections_own_sockets_are_never_probed_and_keep_four_batches_a_turn() {
    // A busy client whose own socket's cached readiness is clear never reads it past the cache,
    // whatever its probe settings.
    let eager = limits(32, Some(probe(Some(1), Some(us(1)))));
    let mut rig = Rig::new(Plan {
        limits: eager,
        client_limits: short_turns(eager),
        client: LabReadiness::Cached,
        window: 100_000,
        ..Plan::default()
    });
    let client = rig.connect(Some(BULK));
    let own = nth_socket(0);
    rig.lab.io_every(None);
    rig.lab.net.set_costs(busy());
    rig.lab.net.clear_events();
    let sent = rig.client.stats().sent_datagrams;
    client.open_streams(1);
    rig.run(|rig| rig.client.stats().sent_datagrams - sent >= 1_000);
    let reads = rx_of(&rig.lab.net.events(), own);
    assert!(
        !reads
            .windows(2)
            .any(|pair| matches!(pair, [Rx::Pending, Rx::Recv(_)])),
        "{reads:?}"
    );
    assert_eq!(RxCounts::of(&rig.client), RxCounts::default());

    // Ten full batches wait in each socket, both reported: the server reads them in one receive
    // phase, the client's own socket four batches a turn.
    let mut rig = Rig::new(Plan {
        limits: eager,
        client_limits: eager,
        client: LabReadiness::Cached,
        ..Plan::default()
    });
    rig.connect(Some(0));
    for _ in 0..10 * FULL {
        rig.lab.net.inject(SERVER, junk());
        rig.lab.net.inject(own, junk());
    }
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    assert!(rig.lab.poll_io());
    let server = rig.poll_server();
    assert_eq!(routes_per_turn(&server), [vec![(0, 64); 10]]);
    let before_client = rig.client.tx_record().marks.len();
    while rig.lab.queued(rig.client_task) {
        rig.lab.poll(rig.client_task);
    }
    let client_marks = rig.client.tx_record().marks[before_client..].to_vec();
    assert_eq!(own_batches_per_turn(&client_marks), [4, 4, 2]);
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            batches: 10,
            datagrams: 640,
            probes: 0,
            empty: 0,
            bound_hits: 0,
        }
    );
    assert_eq!(RxCounts::of(&rig.client), RxCounts::default());
}

#[test]
fn a_connections_own_socket_that_its_receive_finds_not_ready_waits_for_the_host_to_report_it() {
    // The server sends a stream in windows of 100 packets, so the client's own socket, whose
    // readiness is cached, fills while the server waits for acknowledgements. The client reads it
    // only after a host poll reports it, whatever its probe settings.
    let eager = limits(32, Some(probe(Some(1), Some(us(1)))));
    let mut rig = Rig::new(Plan {
        limits: eager,
        client_limits: eager,
        client: LabReadiness::Cached,
        window: 100,
        len: Some(BULK),
        ..Plan::default()
    });
    let client = rig.connect(Some(0));
    let own = nth_socket(0);
    rig.lab.io_every(None);
    rig.lab.net.set_costs(busy());
    rig.lab.net.clear_events();
    rig.session().open_streams(1);
    rig.run(|_| client.received.get() >= 500_000);
    let reads = rx_of(&rig.lab.net.events(), own);
    assert!(
        reads.contains(&Rx::Pending) && reads.contains(&Rx::Ready),
        "the client's receives find its socket not ready, until the host reports it: {reads:?}"
    );
    assert!(
        !reads
            .windows(2)
            .any(|pair| matches!(pair, [Rx::Pending, Rx::Recv(_)])),
        "{reads:?}"
    );
    assert_eq!(RxCounts::of(&rig.client), RxCounts::default());
}

#[test]
fn with_the_probe_off_and_four_calls_the_driver_reads_as_before() {
    let run = busy_script(limits(4, None));
    // The rest of the stream, with the host polling the sockets whenever every task is idle.
    let rig = &run.rig;
    let client = Rc::clone(&run.client);
    rig.run(|_| client.received.get() == BULK as u64);
    let events = rig.lab.net.events();
    let mut text = String::new();
    for event in &events {
        let _ = writeln!(text, "{event:?}");
    }
    assert_eq!(
        (events.len(), fnv1a(&text)),
        (829, 0x239d_623e_3b8d_573e),
        "the log of the busy script"
    );
    assert_eq!(RxCounts::of(&rig.server).since(run.before).probes, 0);
}

/// A host the test runs by hand: it keeps each registration's readiness, for the test to set.
#[derive(Clone, Default)]
struct ScriptedHost(Rc<RefCell<Vec<Readiness>>>);

impl IoHost for ScriptedHost {
    type Registration = ();

    fn register(&self, _fd: BorrowedFd<'_>, readiness: Readiness) -> std::io::Result<()> {
        self.0.borrow_mut().push(readiness);
        Ok(())
    }

    fn watch_writable(&self, _registration: &()) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns a long header of a version no one speaks, which a server answers with Version
/// Negotiation.
fn unknown_version() -> Vec<u8> {
    let mut datagram = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    datagram.extend_from_slice(&[1; 8]);
    datagram.push(8);
    datagram.extend_from_slice(&[2; 8]);
    datagram.resize(1200, 0);
    datagram
}

#[test]
fn the_server_receive_bound_counts_every_call_including_a_batch_of_only_discarded_datagrams() {
    let lab = Lab::new();
    let (_, server_config, endpoint) = lab_configs();
    let host = ScriptedHost::default();
    let mmsg = MmsgOptions {
        rx_batch: 1,
        socket: SocketOptions {
            gro: false,
            ..SocketOptions::default()
        },
        ..MmsgOptions::default()
    };
    let options = HostOptions {
        host: Some(host.clone()),
        mmsg,
    };
    let socket =
        HostBackend::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &options).expect("a socket");
    let addr = socket.local_addr().expect("an address");
    let app = LabApp::new(&lab.net, |_, _| panic!("no connection is accepted"));
    let server = EndpointDriver::builder(endpoint, app)
        .limits(limits(2, None))
        .serve(socket, server_config)
        .backend_options(options)
        .host_timers(Lab::timers())
        .spawn(lab.ctx())
        .expect("the server starts");
    let server_task = lab.last_spawned();
    lab.settle();
    assert!(!lab.queued(server_task), "the server waits for its socket");

    // Two empty datagrams, each a batch whose every datagram is discarded, and then one that
    // needs an answer.
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    peer.send_to(&[], addr).expect("the datagram goes out");
    peer.send_to(&[], addr).expect("the datagram goes out");
    peer.send_to(&unknown_version(), addr)
        .expect("the datagram goes out");
    let before = RxCounts::of(&server);
    let marks_before = server.tx_record().marks.len();
    host.0.borrow()[0].set(Interest::Read);
    assert!(lab.poll(server_task), "the report wakes the server");
    let marks = server.tx_record().marks[marks_before..].to_vec();
    let polls = marks.iter().filter(|&&mark| mark == Mark::Poll).count();
    assert_eq!(polls, 1);
    let mut turns: Vec<Vec<(usize, usize)>> = vec![Vec::new()];
    for mark in &marks {
        match mark {
            Mark::Turn => turns.push(Vec::new()),
            Mark::Route { start, end, .. } => {
                turns.last_mut().expect("a turn").push((*start, *end))
            }
            _ => {}
        }
    }
    turns.retain(|turn| !turn.is_empty());
    assert_eq!(
        turns,
        [vec![(0, 0), (0, 0)], vec![(0, 1)]],
        "two calls in the first receive phase, and the answer's datagram in the next: {marks:?}"
    );
    assert_eq!(
        RxCounts::of(&server).since(before),
        RxCounts {
            batches: 3,
            datagrams: 1,
            probes: 0,
            empty: 0,
            bound_hits: 1,
        }
    );
    let mut reply = [0; 1500];
    let (len, from) = peer
        .recv_from(&mut reply)
        .expect("a Version Negotiation packet comes back");
    assert_eq!(from, addr);
    assert!(len > 5);
    assert_eq!(reply[1..5], [0; 4], "version 0");
}

#[test]
fn on_a_one_connection_bulk_run_the_probe_fires_only_when_the_host_has_not_polled_within_the_probe_time()
 {
    // One connection sends without end, about 110 datagrams and 110 µs a turn on the clock, with
    // a probe at 2,048 datagrams or 2 ms, and the host polls the sockets every `io_every` task
    // polls: the server's and the client's, so every two polls are about four turns of the server.
    // After 100 turns, once the client's acknowledgements flow, the stretch checked is the next
    // 1,000 turns.
    let run = |io_every: usize| {
        let probe = probe(Some(2_048), Some(ms(2)));
        let mut rig = Rig::new(Plan {
            limits: Limits {
                turn_staging: 5 * POLL_CHARGE,
                ..limits(32, Some(probe))
            },
            window: 100_000,
            len: None,
            ..Plan::default()
        });
        rig.connect(Some(0));
        rig.lab.net.log_clock();
        rig.lab.net.set_costs(Costs {
            attempt: us(5),
            chunk: us(2),
            flush: Duration::from_nanos(800),
            recv: us(1),
            ..Costs::default()
        });
        rig.lab.io_every(Some(io_every));
        let turns = rig.server.stats().turns;
        rig.session().open_streams(2);
        assert_eq!(rig.run(|rig| rig.server.stats().turns - turns >= 100), 0);
        rig.lab.net.clear_events();
        let before = RxCounts::of(&rig.server);
        let (turns, sent, io_polls) = (rig.server.stats().turns, rig.sent(), rig.lab.io_polls());
        let start = rig.lab.net.now();
        let parks = rig.run(|rig| rig.server.stats().turns - turns >= 1_000);
        assert_eq!(parks, 0, "the server never waits for a wake");
        let events = rig.lab.net.events();
        let checked = check_probes(&events, probe);
        let counted = RxCounts::of(&rig.server).since(before);
        assert_eq!(
            counted,
            RxCounts {
                batches: checked.batches,
                datagrams: checked.datagrams,
                probes: checked.probes,
                empty: checked.empty,
                bound_hits: 0,
            },
            "the counters match the log: {checked:?}"
        );
        let reported = server_rx(&events)
            .into_iter()
            .filter(|rx| *rx == Rx::Ready)
            .count();
        (
            counted,
            rig.lab.net.now() - start,
            rig.sent() - sent,
            rig.lab.io_polls() - io_polls,
            reported,
        )
    };
    // A host poll every 16 turns, 1.76 ms, comes before either trigger: each of the 62 finds
    // acknowledgements, and no probe fires.
    let (often, elapsed, sent, io_polls, reported) = run(8);
    assert_eq!(
        (elapsed, sent),
        (Duration::from_micros(109_796), 113_000),
        "the turns' shape"
    );
    assert_eq!((io_polls, reported), (62, 62));
    assert_eq!(
        often,
        RxCounts {
            batches: 62,
            datagrams: 496,
            probes: 0,
            empty: 0,
            bound_hits: 0,
        }
    );
    // A host poll every 244 turns: 4 in the stretch, 3 of which find acknowledgements. Between
    // reads, a probe fires about every 19 turns, as 2,048 datagrams or 2 ms pass since the last
    // read, whichever comes first: 50 probes, none of which finds the socket empty.
    let (rarely, _, _, io_polls, reported) = run(122);
    assert_eq!((io_polls, reported), (4, 3));
    assert_eq!(
        rarely,
        RxCounts {
            batches: 53,
            datagrams: 498,
            probes: 50,
            empty: 0,
            bound_hits: 0,
        }
    );
}

/// The connections of the fan-out tick: four turns' intake of 256 connections each.
const FAN_OUT: usize = 1_024;

/// The bytes of each connection's object in the fan-out tick, which fit one datagram.
const OBJECT: usize = 1_000;

/// The datagrams that wait in the server socket as the fan-out tick begins.
const WAITING: usize = 3 * FULL + 10;

/// Returns the datagrams the server's connections built before each read of the server socket in
/// `events`, since the read before it.
fn built_before_each_read(events: &[NetEvent]) -> Vec<u64> {
    let mut built = vec![0];
    for event in events {
        match *event {
            NetEvent::Built(SERVER, key, n) if key.index != STATELESS => {
                *built.last_mut().expect("a stretch") += u64::from(n)
            }
            NetEvent::Pending(SERVER) | NetEvent::Recv(SERVER, _) => built.push(0),
            _ => {}
        }
    }
    built.pop();
    built
}

/// Returns the readings of the host clock in `events`.
fn readings(events: &[NetEvent]) -> Vec<Duration> {
    events
        .iter()
        .filter_map(|event| match *event {
            NetEvent::Clock(at) => Some(at),
            _ => None,
        })
        .collect()
}

#[test]
fn with_the_default_probe_a_fan_out_tick_of_fewer_datagrams_than_its_count_reads_the_server_socket_only_once_the_host_reports_it()
 {
    // A paced fan-out tick: each connection gets an object of one datagram, the server sends them
    // in four turns of 256 connections, longer than 2 ms on the clock, and datagrams wait in its
    // socket, which the host reports only once every task is idle.
    let mut rig = Rig::new(Plan {
        len: Some(OBJECT),
        ..Plan::default()
    });
    let clients = rig.connect_all(FAN_OUT);
    let servers = rig.accepted.borrow().clone();
    rig.lab.io_every(None);
    rig.lab.net.set_costs(Costs {
        attempt: us(4),
        chunk: us(2),
        flush: us(1),
        recv: us(1),
        ..Costs::default()
    });
    // A first tick, whose acknowledgements the server reads once the host reports them.
    for server in &servers {
        server.open_streams(1);
    }
    rig.lab.run_until(|| {
        clients
            .iter()
            .all(|client| client.received.get() == OBJECT as u64)
    });
    rig.lab.run_quiet(ms(100));
    assert!(!rig.lab.queued(rig.server_task), "the server is parked");

    // The next tick, while datagrams the host has not reported wait in the server socket.
    for _ in 0..WAITING {
        rig.lab.net.inject(SERVER, junk());
    }
    rig.lab.net.log_clock();
    rig.lab.net.clear_events();
    let before = RxCounts::of(&rig.server);
    let io_polls = rig.lab.io_polls();
    for server in &servers {
        server.open_streams(1);
    }
    let parks = rig.run(|rig| RxCounts::of(&rig.server).since(before).datagrams >= WAITING as u64);
    let events = rig.lab.net.events();
    // Up to the host's report of the server socket, if any.
    let reported = events
        .iter()
        .position(|event| *event == NetEvent::Ready(SERVER))
        .unwrap_or(events.len());
    let burst = &events[..reported];
    let last_read = burst
        .iter()
        .rposition(|event| *event == NetEvent::Pending(SERVER))
        .expect("a receive phase");
    assert_eq!(
        server_rx(burst),
        [Rx::Pending; 8],
        "each receive phase until the host reports the socket finds its cached readiness clear and \
         reads nothing"
    );
    assert_eq!(
        built_before_each_read(burst),
        [256, 256, 256, 256, 0, 0, 0, 0],
        "one datagram for each connection, in four turns of 256, and four turns more before the \
         server waits"
    );
    let first = readings(burst)[0];
    let last = *readings(&burst[..last_read]).last().expect("a reading");
    assert!(
        last - first > ms(2),
        "the last of those receive phases comes {:?} after the tick's first reading",
        last - first
    );
    // The datagrams that waited through the burst, and those that reached the socket since.
    let mut after = vec![Rx::Ready];
    after.extend([Rx::Recv(64); 13]);
    after.extend([Rx::Recv(2), Rx::Pending]);
    assert_eq!(
        server_rx(&events[reported..]),
        after,
        "the server reads its socket once the host reports it, after the burst"
    );
    assert_eq!(
        RxCounts::of(&rig.server).since(before),
        RxCounts {
            batches: 14,
            datagrams: WAITING as u64 + 632,
            probes: 0,
            empty: 0,
            bound_hits: 0,
        }
    );
    assert_eq!(
        (parks, rig.lab.io_polls() - io_polls),
        (2, 1),
        "the server waits for a wake after the burst and again after its read, and the host polls \
         once, in between"
    );
}
