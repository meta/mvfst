/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the Initials a server keeps for a later turn once a turn's connection attempts run
//! out: a server driver and a client driver in the lab, where the server finds a backlog of first
//! flights on its socket and runs its turns without the clock moving.

use std::cell::Cell;
use std::net::SocketAddr;
use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use mvfstr_io::Backend;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::DatagramSize;
use mvfstr_proto::TransportConfig;
use rustls::pki_types::ServerName;

use crate::EndpointDriver;
use crate::EndpointDriverBuilder;
use crate::EndpointHandle;
use crate::EndpointStats;
use crate::Refusal;
use crate::lab::Arrival;
use crate::lab::Bulk;
use crate::lab::Lab;
use crate::lab::LabApp;
use crate::lab::MemBackend;
use crate::lab::MemOptions;
use crate::lab::SERVER;
use crate::lab::lab_configs;
use crate::lab::nth_socket;
use crate::lab::transport;
use crate::test_support::client_config_offering;
use crate::turn::Limits;
use crate::turn::Mark;

type Handle = EndpointHandle<LabApp, MemBackend>;
type Builder = EndpointDriverBuilder<LabApp, MemBackend>;

/// The length of each datagram of a client's first flight in the lab: the smallest datagram that
/// may carry an Initial.
const FIRST_INITIAL: usize = 1200;

/// A server driver and a client driver on one lab worker.
struct Burst {
    server: Handle,
    server_task: usize,
    client: Handle,
    client_config: Arc<ClientConfig>,
    /// The connection attempts the server's application accepted.
    accepted: Rc<Cell<usize>>,
    lab: Lab,
}

impl Burst {
    /// Starts a client driver and a server driver that `configure` sets up, whose application
    /// accepts every attempt.
    fn new(configure: impl FnOnce(Builder) -> Builder) -> Self {
        Self::build(None, Vec::new(), configure)
    }

    /// Like [`new`](Self::new), with a server application that turns down every attempt with
    /// `refusal`, if given.
    fn answering(refusal: Option<Refusal>, configure: impl FnOnce(Builder) -> Builder) -> Self {
        Self::build(refusal, Vec::new(), configure)
    }

    /// Like [`new`](Self::new), with a server application that moves the test clock on by the
    /// `n`-th of `accept_costs` in its `n`-th accept, and by the last in later ones.
    fn costing(accept_costs: Vec<Duration>, configure: impl FnOnce(Builder) -> Builder) -> Self {
        Self::build(None, accept_costs, configure)
    }

    fn build(
        refusal: Option<Refusal>,
        accept_costs: Vec<Duration>,
        configure: impl FnOnce(Builder) -> Builder,
    ) -> Self {
        let lab = Lab::new();
        let (client_config, server_config, endpoint) = lab_configs();
        let net = lab.net.clone();
        let mut app = LabApp::new(&lab.net, move |_, options| {
            options.transport = Some(transport(false));
            Bulk::new(&net, 0, Some(0)).0
        });
        app.refusal = refusal;
        app.accept_costs = accept_costs;
        let accepted = Rc::clone(&app.accepted);
        let options = MemOptions {
            net: Some(lab.net.clone()),
            ..MemOptions::default()
        };
        let socket = MemBackend::bind(SERVER, &options).expect("the lab binds");
        let server = configure(EndpointDriver::builder(Arc::clone(&endpoint), app))
            .serve(socket, server_config)
            .backend_options(options.clone())
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the server starts");
        let server_task = lab.last_spawned();
        let client = EndpointDriver::builder(endpoint, LabApp::client(&lab.net))
            .backend_options(options)
            .host_timers(Lab::timers())
            .spawn(lab.ctx())
            .expect("the client starts");
        Self {
            server,
            server_task,
            client,
            client_config,
            accepted,
            lab,
        }
    }

    /// Opens a client connection with each of `configs`, in order, and returns the datagrams of
    /// each one's first flight, which the server has not received. Called once per test, so the
    /// `n`-th connection has the lab's `n`-th socket.
    fn first_flights(&self, configs: &[Arc<ClientConfig>]) -> Vec<Vec<Arrival>> {
        let clients: Vec<_> = configs
            .iter()
            .map(|config| (Arc::clone(config), transport(false)))
            .collect();
        self.first_flights_with(&clients)
    }

    /// Like [`first_flights`](Self::first_flights), with each connection's transport settings.
    fn first_flights_with(
        &self,
        clients: &[(Arc<ClientConfig>, Arc<TransportConfig>)],
    ) -> Vec<Vec<Arrival>> {
        for (config, transport) in clients {
            let (session, _) = Bulk::new(&self.lab.net, 0, Some(0));
            self.client
                .connect(
                    SERVER,
                    ServerName::try_from("localhost").expect("a name"),
                    Arc::clone(config),
                    ConnOptions {
                        transport: Some(Arc::clone(transport)),
                    },
                    session,
                )
                .expect("the client connects");
        }
        self.lab.net.hold(SERVER);
        self.lab.settle_except(Some(self.server_task));
        let held = self.lab.net.take_held();
        (0..clients.len())
            .map(|n| {
                let socket = nth_socket(u16::try_from(n).expect("few connections"));
                held.iter()
                    .filter(|arrival| arrival.src == socket)
                    .cloned()
                    .collect()
            })
            .collect()
    }

    /// Opens a client connection for each of `sizes`, whose first flight is one datagram of that
    /// many bytes, and returns those datagrams, which the server has not received. Called once
    /// per test, as [`first_flights`](Self::first_flights) is.
    fn initials(&self, sizes: &[u16]) -> Vec<Arrival> {
        let clients: Vec<_> = sizes
            .iter()
            .map(|&size| (Arc::clone(&self.client_config), sized(size)))
            .collect();
        let flights = self.first_flights_with(&clients);
        let lengths: Vec<Vec<usize>> = flights
            .iter()
            .map(|flight| flight.iter().map(|arrival| arrival.data.len()).collect())
            .collect();
        let expected: Vec<Vec<usize>> = sizes.iter().map(|&size| vec![usize::from(size)]).collect();
        assert_eq!(
            lengths, expected,
            "each first flight is one datagram of its size"
        );
        flights.into_iter().flatten().collect()
    }

    /// Hands the server's socket `arrivals` and polls the server until it is no longer woken,
    /// without moving the clock. Returns each connection attempt the server took up in those
    /// polls, with the number of its turn among the polls' turns, counted from 1.
    fn serve(&self, arrivals: impl IntoIterator<Item = Arrival>) -> Vec<(usize, SocketAddr)> {
        for arrival in arrivals {
            self.lab.net.inject(SERVER, arrival);
        }
        let before = self.server.tx_record().marks.len();
        let mut polls = 0;
        while self.lab.poll(self.server_task) {
            polls += 1;
            assert!(polls < 10_000, "the server keeps waking");
        }
        let mut turn = 0;
        let mut attempts = Vec::new();
        for mark in &self.server.tx_record().marks[before..] {
            match mark {
                Mark::Turn => turn += 1,
                Mark::Accept(remote) => attempts.push((turn, *remote)),
                _ => {}
            }
        }
        attempts
    }
}

/// Returns the number of attempts of each turn, from the first turn to the last that took one up.
fn per_turn(attempts: &[(usize, SocketAddr)]) -> Vec<usize> {
    let mut counts = vec![0; attempts.last().map_or(0, |&(turn, _)| turn)];
    for &(turn, _) in attempts {
        counts[turn - 1] += 1;
    }
    counts
}

/// Returns the attempts of the clients on the lab's sockets in each range, with its turn.
fn in_turns(turns: &[(usize, Range<u16>)]) -> Vec<(usize, SocketAddr)> {
    turns
        .iter()
        .flat_map(|(turn, range)| range.clone().map(|n| (*turn, nth_socket(n))))
        .collect()
}

/// Returns the lab's transport settings with datagrams of `size` bytes, so that a client's first
/// flight is one datagram of that size.
fn sized(size: u16) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .initial_window(1_000)
        .initial_rtt(Duration::from_millis(1))
        .max_data(1 << 30)
        .max_stream_data_uni(1 << 26)
        .max_streams_uni(1 << 20)
        .datagram_size(DatagramSize::Fixed(size))
        .build()
        .expect("a transport config")
}

/// Returns server limits of `handshakes` connection attempts per turn.
fn handshakes(handshakes: usize) -> Limits {
    Limits {
        handshakes,
        ..Limits::default()
    }
}

/// Returns a client config whose ClientHello takes two datagrams with either crypto backend.
fn two_datagram_hello() -> Arc<ClientConfig> {
    client_config_offering(&[&[b'x'; 200][..]; 5])
}

#[test]
fn a_server_keeps_4_mib_of_waiting_initials_by_default() {
    assert_eq!(Limits::default().waiting_initial_bytes, 4 * 1024 * 1024);
}

#[test]
fn a_backlog_of_600_two_datagram_first_flights_is_all_accepted_8_attempts_a_turn() {
    const CLIENTS: u16 = 600;
    let burst = Burst::new(|server| server);
    let flights = burst.first_flights(&vec![two_datagram_hello(); usize::from(CLIENTS)]);
    assert!(
        flights.iter().all(|flight| flight.len() == 2),
        "each ClientHello takes two datagrams"
    );
    // The server reads at most 256 datagrams a turn, so it reads the backlog over its first five
    // turns and keeps what those turns cannot take up.
    let attempts = burst.serve(flights.into_iter().flatten());
    let stats = burst.server.stats();
    assert_eq!(stats.dropped_initials, 0, "{stats:?}");
    assert_eq!(burst.accepted.get(), usize::from(CLIENTS));
    assert_eq!(
        per_turn(&attempts),
        [8; 75],
        "each turn takes up eight attempts, and a second datagram none"
    );
    let order: Vec<SocketAddr> = attempts.iter().map(|&(_, remote)| remote).collect();
    let clients: Vec<SocketAddr> = (0..CLIENTS).map(nth_socket).collect();
    assert_eq!(order, clients, "first in, first out");
}

#[test]
fn initials_past_the_byte_bound_are_dropped_and_counted_and_those_kept_are_served_in_order() {
    // Eight first flights fill 9,600 of the 10,240 bytes, and a ninth would pass the bound.
    let burst = Burst::new(|server| server.waiting_initial_bytes(10 * 1024));
    let flights = burst.first_flights(&vec![Arc::clone(&burst.client_config); 40]);
    assert!(
        flights
            .iter()
            .all(|flight| flight.len() == 1 && flight[0].data.len() == FIRST_INITIAL),
        "each first flight is one datagram of {FIRST_INITIAL} bytes"
    );
    let (early, late) = flights.split_at(20);
    let attempts = burst.serve(early.iter().flatten().cloned());
    assert_eq!(
        attempts,
        in_turns(&[(1, 0..8), (2, 8..16)]),
        "the first turn's eight attempts, then the eight kept, in order"
    );
    assert_eq!(
        burst.server.stats().dropped_initials,
        4,
        "the four past the bound"
    );
    // The Initials served have left the queue, so the next backlog finds the same room.
    let attempts = burst.serve(late.iter().flatten().cloned());
    assert_eq!(attempts, in_turns(&[(1, 20..28), (2, 28..36)]));
    assert_eq!(burst.server.stats().dropped_initials, 8);
}

#[test]
fn each_first_flight_takes_its_own_bytes_and_a_kept_second_datagram_takes_no_attempt() {
    let burst = Burst::new(|server| {
        server
            .limits(Limits {
                handshakes: 1,
                ..Limits::default()
            })
            .waiting_initial_bytes(3 * FIRST_INITIAL)
    });
    let one = Arc::clone(&burst.client_config);
    let flights = burst.first_flights(&[
        Arc::clone(&one),
        two_datagram_hello(),
        Arc::clone(&one),
        one,
    ]);
    assert_eq!(
        flights.iter().map(Vec::len).collect::<Vec<_>>(),
        [1, 2, 1, 1],
        "the second client's ClientHello takes two datagrams, the others' one"
    );
    assert!(
        flights
            .iter()
            .flatten()
            .all(|arrival| arrival.data.len() == FIRST_INITIAL),
        "every datagram is {FIRST_INITIAL} bytes"
    );
    // The first turn takes up the first attempt and keeps the second client's two datagrams and
    // the third client's one, which fill the bound; the fourth client's would pass it. The
    // second client's second datagram then routes to the connection its first created, without
    // taking the attempt of the turn that serves it.
    let attempts = burst.serve(flights.into_iter().flatten());
    assert_eq!(attempts, in_turns(&[(1, 0..1), (2, 1..2), (3, 2..3)]));
    assert_eq!(burst.server.stats().dropped_initials, 1);
    assert_eq!(burst.server.waiting(), (0, false));
}

#[test]
fn a_server_runs_turns_without_a_wake_while_initials_wait() {
    // The application ignores every attempt, so after each turn the Initials kept waiting are
    // all the work the server has left.
    let burst = Burst::answering(Some(Refusal::Ignore), |server| {
        server.limits(Limits {
            handshakes: 1,
            ..Limits::default()
        })
    });
    let flights = burst.first_flights(&vec![Arc::clone(&burst.client_config); 4]);
    let attempts = burst.serve(flights.into_iter().flatten());
    assert_eq!(
        attempts,
        in_turns(&[(1, 0..1), (2, 1..2), (3, 2..3), (4, 3..4)]),
        "one attempt a turn, each turn right after the last"
    );
    assert_eq!(burst.accepted.get(), 0);
    assert_eq!(burst.server.waiting(), (0, false));
}

/// The length of a client's first Initial in these tests when its datagrams are larger than the
/// smallest: mvfst's tperf client size on IPv4.
const LARGE_INITIAL: u16 = 1252;

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// Returns the three waiting peaks of `stats`: datagrams, bytes and the longest wait.
fn peaks(stats: &EndpointStats) -> (u64, u64, Duration) {
    (
        stats.waiting_peak_datagrams,
        stats.waiting_peak_bytes,
        stats.waiting_longest,
    )
}

#[test]
fn the_waiting_peaks_are_the_most_initials_and_bytes_kept_at_once() {
    const LARGE: usize = LARGE_INITIAL as usize;
    // The bound has room for three large Initials and one of the smallest size.
    let bound = 3 * LARGE + FIRST_INITIAL;
    let burst = Burst::new(|server| server.limits(handshakes(1)).waiting_initial_bytes(bound));
    let initials = burst.initials(&[1200, 1252, 1252, 1252, 1252, 1200]);
    // The first turn takes up the first attempt and keeps the next three, which leave 1,200
    // bytes; the fifth would pass the bound and is dropped, and the sixth fills it exactly.
    let attempts = burst.serve(initials);
    assert_eq!(
        attempts,
        in_turns(&[(1, 0..1), (2, 1..2), (3, 2..3), (4, 3..4), (5, 5..6)])
    );
    let stats = burst.server.stats();
    assert_eq!(stats.dropped_initials, 1, "{stats:?}");
    assert_eq!(
        (stats.waiting_peak_datagrams, stats.waiting_peak_bytes),
        (4, u64::try_from(bound).expect("a small bound")),
        "the four kept at once, each charged its length; the dropped one never entered: \
         {stats:?}"
    );
    assert_eq!(burst.server.waiting(), (0, false));
}

#[test]
fn the_waiting_peaks_stay_as_the_queue_drains_and_rise_only_with_a_larger_backlog() {
    let burst = Burst::new(|server| server.limits(handshakes(1)));
    // Three backlogs, from clients opened at once so that each has a socket of its own. The first
    // turn of each backlog takes up its first attempt and keeps the rest.
    let initials = burst.initials(&[
        1200, 1252, 1252, 1252, 1252, // keeps 4 datagrams, 5,008 bytes
        1200, 1200, 1200, 1200, // keeps 3 datagrams, 3,600 bytes
        1200, 1252, 1200, 1252, 1200, 1252, 1200, // keeps 6 datagrams, 7,356 bytes
    ]);
    let (first, rest) = initials.split_at(5);
    let (second, third) = rest.split_at(4);
    burst.serve(first.iter().cloned());
    assert_eq!(burst.server.waiting(), (0, false));
    let stats = burst.server.stats();
    assert_eq!(
        (stats.waiting_peak_datagrams, stats.waiting_peak_bytes),
        (4, 5008),
        "the peaks stay once the queue has drained: {stats:?}"
    );
    burst.serve(second.iter().cloned());
    let stats = burst.server.stats();
    assert_eq!(
        (stats.waiting_peak_datagrams, stats.waiting_peak_bytes),
        (4, 5008),
        "a smaller backlog leaves the peaks: {stats:?}"
    );
    burst.serve(third.iter().cloned());
    let stats = burst.server.stats();
    assert_eq!(
        (stats.waiting_peak_datagrams, stats.waiting_peak_bytes),
        (6, 7356),
        "a larger backlog raises them to its own: {stats:?}"
    );
    assert_eq!(stats.dropped_initials, 0, "{stats:?}");
}

#[test]
fn the_longest_wait_runs_from_when_an_initial_is_kept_to_the_reading_of_the_turn_that_routes_it() {
    // The accepts after the first move the test clock on by 7, 5 and 3 ms.
    let burst = Burst::costing(vec![Duration::ZERO, ms(7), ms(5), ms(3)], |server| {
        server.limits(handshakes(1))
    });
    let initials = burst.initials(&[1200; 4]);
    let start = burst.lab.net.now();
    // The first turn takes up the first attempt at no cost and keeps the other three at its
    // reading. Each later turn routes one of them again at its own reading, before that attempt's
    // accept moves the clock: the second at the start, the third 7 ms and the fourth 12 ms later.
    let attempts = burst.serve(initials);
    assert_eq!(
        attempts,
        in_turns(&[(1, 0..1), (2, 1..2), (3, 2..3), (4, 3..4)])
    );
    assert_eq!(burst.lab.net.now() - start, ms(15), "the accepts' costs");
    let stats = burst.server.stats();
    assert_eq!(stats.waiting_longest, ms(12), "{stats:?}");
}

#[test]
fn resetting_the_waiting_peaks_zeroes_only_them_and_later_peaks_count_only_later_initials() {
    // The second accept moves the clock on by 4 ms and the sixth by 2 ms; the others cost
    // nothing.
    let costs = vec![
        Duration::ZERO,
        ms(4),
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        ms(2),
        Duration::ZERO,
    ];
    let burst = Burst::costing(costs, |server| {
        server
            .limits(handshakes(1))
            .waiting_initial_bytes(3 * FIRST_INITIAL)
    });
    let initials = burst.initials(&[1200; 8]);
    let (early, late) = initials.split_at(5);
    // The first turn takes up the first attempt and keeps three, and the fifth does not fit. The
    // second is routed again at the start and the third and fourth 4 ms later.
    burst.serve(early.iter().cloned());
    let before = burst.server.stats();
    assert_eq!(before.dropped_initials, 1, "{before:?}");
    assert_eq!(peaks(&before), (3, 3600, ms(4)), "{before:?}");

    burst.server.reset_waiting_peaks();
    let after = burst.server.stats();
    assert_eq!(
        after,
        EndpointStats {
            waiting_peak_datagrams: 0,
            waiting_peak_bytes: 0,
            waiting_longest: Duration::ZERO,
            ..before
        },
        "only the waiting peaks change"
    );

    // The first turn takes up the sixth attempt and keeps two; the seventh is routed again at
    // once and the eighth 2 ms later.
    burst.serve(late.iter().cloned());
    let stats = burst.server.stats();
    assert_eq!(
        peaks(&stats),
        (2, 2400, ms(2)),
        "the peaks count only what came after the reset: {stats:?}"
    );
    assert_eq!(stats.dropped_initials, 1, "{stats:?}");
}

#[test]
fn a_reset_once_the_driver_has_ended_zeroes_the_waiting_peaks_of_its_last_counters() {
    let burst = Burst::costing(vec![Duration::ZERO, ms(3)], |server| {
        server.limits(handshakes(1))
    });
    let initials = burst.initials(&[1200; 3]);
    // The first turn keeps two Initials, and the third turn routes the second of them again 3 ms
    // after the first.
    burst.serve(initials);
    burst.server.abort();
    while burst.lab.poll(burst.server_task) {}
    assert!(burst.server.core().is_none(), "the driver has ended");
    let ended = burst.server.stats();
    assert_eq!(peaks(&ended), (2, 2400, ms(3)), "{ended:?}");

    burst.server.reset_waiting_peaks();
    assert_eq!(
        burst.server.stats(),
        EndpointStats {
            waiting_peak_datagrams: 0,
            waiting_peak_bytes: 0,
            waiting_longest: Duration::ZERO,
            ..ended
        },
        "only the waiting peaks change"
    );
}
