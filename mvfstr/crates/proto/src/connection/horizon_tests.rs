/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Build-horizon tests over the pair harness of [`crate::testing`], whose links hold each
//! datagram until its release.

use std::num::NonZeroU64;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::VarInt;

use super::Connection;
use super::stream_tests::App;
use super::stream_tests::ORDER;
use super::stream_tests::RTT;
use super::stream_tests::config;
use super::stream_tests::pattern;
use super::stream_tests::run_apps;
use super::tests::Forge;
use super::tests::client_addr;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::open_own_one_rtt;
use crate::AckPolicy;
use crate::DatagramSize;
use crate::EndpointConfig;
use crate::InlineSealer;
use crate::Release;
use crate::Stop;
use crate::TxLimits;
use crate::TxOutcome;
use crate::cc::Cc;
use crate::cc::SentEvent;
use crate::config::TransportConfigBuilder;
use crate::recovery::Space;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::SentDatagram;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);
const NS: Duration = Duration::from_nanos(1);

/// Returns `setup`'s pair with endpoints whose `build_horizon` is `horizon` and whose backends
/// hold datagrams for as long.
fn paired(setup: &Setup, horizon: Duration) -> PairConfig {
    let mut config = setup.pair();
    config.endpoint = EndpointConfig::builder([7; 32])
        .build_horizon(horizon)
        .build()
        .expect("an endpoint config");
    config.release_horizon = horizon;
    config
}

/// Returns the build horizons of the server's and the client's connections, with endpoints whose
/// `build_horizon` is `build` and whose backends hold datagrams for up to `release`.
fn horizons(build: Duration, release: Duration) -> (Duration, Duration) {
    let mut config = Setup::default().pair();
    config.endpoint = EndpointConfig::builder([7; 32])
        .build_horizon(build)
        .build()
        .expect("an endpoint config");
    config.release_horizon = release;
    let (_, pair) = handshake(config);
    (
        pair.server.conn().build_horizon(),
        pair.client.conn().build_horizon(),
    )
}

#[test]
fn accepted_connections_build_ahead_by_the_smaller_horizon_and_client_ones_not_at_all() {
    let zero = Duration::ZERO;
    // Without release support, connections do not build ahead.
    assert_eq!(horizons(5 * MS, zero), (zero, zero));
    assert_eq!(horizons(5 * MS, 2 * MS), (2 * MS, zero));
    assert_eq!(horizons(5 * MS, 100 * MS), (5 * MS, zero));
    assert_eq!(horizons(zero, 100 * MS), (zero, zero));
}

#[test]
fn the_advertised_max_ack_delay_grows_by_the_horizon_and_a_millisecond_below_2_14_ms() {
    let bound = Duration::from_millis((1 << 14) - 1);
    for (max_ack_delay, horizon, advertised) in
        [(25 * MS, 2 * MS, 28), (bound, Duration::ZERO, 16_383)]
    {
        let server_transport = config(|c| {
            c.ack_policy(AckPolicy {
                max_ack_delay,
                ..AckPolicy::default()
            })
        });
        let setup = Setup {
            server_transport,
            ..Setup::default()
        };
        let (_, pair) = handshake(paired(&setup, 2 * MS));
        assert_eq!(pair.server.conn().build_horizon(), horizon);
        let peer = pair.client.conn().handshake.peer_params.as_ref().unwrap();
        assert_eq!(peer.decoded.max_ack_delay, VarInt::from_u32(advertised));
    }
}

/// Returns a pair whose paced server has `f`'s settings, 1,452-byte datagrams, a 200 µs tick, a
/// window of 300 datagrams and a build horizon of 2 ms, one RTT after the handshake, with `len`
/// bytes queued on as many streams as their staging cap needs.
fn server_backlogged(
    f: impl FnOnce(TransportConfigBuilder) -> TransportConfigBuilder,
    len: usize,
) -> Pair {
    let server_transport = config(|c| {
        f(c.pacing(true)
            .pacing_granularity(200 * US)
            .initial_window(300)
            .datagram_size(DatagramSize::PeerMaximum))
    });
    let client_transport = config(|c| c.max_data(1 << 40).max_stream_data_uni(1 << 30));
    let setup = Setup {
        client_transport,
        server_transport,
        ..Setup::default()
    };
    let (_, mut pair) = handshake(paired(&setup, 2 * MS));
    pair.run(pair.now + RTT);
    let conn = pair.server.conn_mut();
    let mut data = Bytes::from(pattern(len));
    while !data.is_empty() {
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        conn.stream(id).unwrap().send(&mut data).unwrap();
    }
    pair
}

/// Runs one attempt by the server at `now` with room for 44 datagrams, and returns its outcome
/// and the datagrams of each run.
fn server_attempt(pair: &mut Pair, now: Instant) -> (TxOutcome, Vec<Vec<SentDatagram>>) {
    let limits = TxLimits {
        now,
        max_segments: 44,
        ..pair.limits()
    };
    let mut sink = VecSink::new(1500);
    let conn = pair.server.conn_mut();
    let outcome = conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    let mut runs: Vec<Vec<SentDatagram>> = Vec::new();
    for datagram in sink.take() {
        match runs.last_mut() {
            Some(run) if run[0].meta.tx == datagram.meta.tx => run.push(datagram),
            _ => runs.push(vec![datagram]),
        }
    }
    (outcome, runs)
}

/// Returns the release of each run, after `t0`.
fn releases(pair: &Pair, t0: Instant, runs: &[Vec<SentDatagram>]) -> Vec<Duration> {
    runs.iter()
        .map(|run| pair.leaves(t0, run[0].meta.release) - t0)
        .collect()
}

#[test]
fn each_attempt_builds_full_runs_due_within_the_horizon_with_their_own_releases() {
    let mut pair = server_backlogged(|c| c, 400_000);
    let conn = pair.server.conn_mut();
    conn.pacer.set_rate(NonZeroU64::new(125_000_000).unwrap());
    let t = 209 * US;
    assert_eq!((conn.pacer.burst(), conn.pacer.run_time()), (18, t));
    // From idle, the first attempt's two runs share a release; each later one builds two runs
    // T apart and ends with a full batch, until the next release is beyond now plus the horizon.
    let t0 = pair.now;
    let mut built = Vec::new();
    let last = loop {
        let (outcome, runs) = server_attempt(&mut pair, t0);
        assert!(runs.iter().all(|run| run.len() == 18), "{outcome:?}");
        built.push(releases(&pair, t0, &runs));
        if outcome.stop != Stop::BatchFull {
            break outcome;
        }
    };
    let zero = Duration::ZERO;
    let expected: [&[Duration]; 6] = [
        &[zero, zero],
        &[t, 2 * t],
        &[3 * t, 4 * t],
        &[5 * t, 6 * t],
        &[7 * t, 8 * t],
        &[9 * t],
    ];
    assert_eq!(built, expected);
    // The stop and pacing_at are the next release less the horizon, when an attempt can
    // build its run; an attempt a nanosecond earlier does not build it.
    let at = t0 + 10 * t - 2 * MS;
    assert_eq!((last.stop, last.pacing_at), (Stop::Pacing(at), Some(at)));
    let (early, runs) = server_attempt(&mut pair, at - NS);
    assert_eq!((early.stop, early.pacing_at), (Stop::Pacing(at), Some(at)));
    assert!(runs.is_empty());
    let (due, runs) = server_attempt(&mut pair, at);
    assert_eq!(releases(&pair, t0, &runs), [10 * t]);
    assert_eq!(due.stop, Stop::Pacing(t0 + 11 * t - 2 * MS));
}

/// Sets the server to 1 Gbit/s with a recording controller, then runs attempts at its time until
/// one stops for anything but a full batch, and returns the release of each datagram built, by
/// sequence number.
fn built_ahead(pair: &mut Pair) -> Vec<(u64, Instant)> {
    let conn = pair.server.conn_mut();
    conn.cc = conn.cc.recording();
    conn.recovery.enable_rate_samples();
    conn.pacer.set_rate(NonZeroU64::new(125_000_000).unwrap());
    let now = pair.now;
    let mut leaves = Vec::new();
    loop {
        let (outcome, runs) = server_attempt(pair, now);
        for datagram in runs.iter().flatten() {
            leaves.push(pair.leaves(now, datagram.meta.release));
        }
        if outcome.stop != Stop::BatchFull {
            break;
        }
    }
    let conn = pair.server.conn();
    let from = conn.tx_seq - leaves.len() as u64;
    (from..).zip(leaves).collect()
}

fn sent_events(conn: &Connection) -> &[SentEvent] {
    match &conn.cc {
        Cc::Recording(recording) => &recording.sent,
        _ => panic!("the connection has no recording controller"),
    }
}

#[test]
fn packets_are_recorded_and_reported_sent_at_their_runs_release() {
    let mut pair = server_backlogged(|c| c, 400_000);
    let t0 = pair.now;
    let leaves = built_ahead(&mut pair);
    assert!(leaves.iter().any(|&(_, at)| at > t0));
    let conn = pair.server.conn();
    let sent = conn.recovery.space(Space::Data);
    let times: Vec<Duration> = sent
        .outstanding()
        .filter(|packet| packet.tx_seq >= leaves[0].0)
        .map(|packet| packet.time_sent - t0)
        .collect();
    let expected: Vec<Duration> = leaves.iter().map(|&(_, at)| at - t0).collect();
    assert_eq!(times, expected);
    let events = sent_events(conn);
    let reported: Vec<Duration> = events[events.len() - expected.len()..]
        .iter()
        .map(|event| event.time_sent - t0)
        .collect();
    assert_eq!(reported, expected);
}

/// Hands the server hand-built 1-RTT packets from the client, one per frame list, at `now`.
/// The pair must not run afterwards: the client never sent these packet numbers.
fn from_client(pair: &mut Pair, now: Instant, packets: &[&[Frame<'_>]]) {
    let Pair { client, server, .. } = pair;
    let pn = client.conn().recovery.space(Space::Data).next_pn() + 10;
    for (pn, frames) in (pn..).zip(packets) {
        let packet = Forge::of(client.conn(), Space::Data, pn, frames).seal(client.conn());
        deliver(server.conn_mut(), now, client_addr(), packet);
    }
}

#[test]
fn an_ack_only_datagram_leaves_after_the_last_release_and_measures_its_delay_from_then() {
    let mut pair = server_backlogged(|c| c, 400_000);
    let t0 = pair.now;
    let last = built_ahead(&mut pair).last().unwrap().1;
    assert_eq!(last, t0 + 9 * 209 * US);
    // Two ack-eliciting packets make an ACK due at once, while data waits for the pacer.
    from_client(&mut pair, t0, &[&[Frame::Ping], &[Frame::Ping]]);
    let (ack, runs) = server_attempt(&mut pair, t0);
    assert_eq!((ack.datagrams, runs.len()), (1, 1), "{ack:?}");
    let datagram = &runs[0][0];
    assert!(matches!(datagram.meta.release, Release::At(_)));
    assert_eq!(pair.leaves(t0, datagram.meta.release), last);
    let conn = pair.server.conn();
    let delays: Vec<VarInt> = open_own_one_rtt(conn, &datagram.data)
        .iter()
        .flat_map(|plaintext| {
            Frames::new(plaintext)
                .filter_map(|frame| match frame.unwrap() {
                    Frame::Ack(ack) => Some(ack.delay()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .collect();
    // In units of 2^3 µs, the default ack_delay_exponent.
    let micros = u64::try_from((last - t0).as_micros()).unwrap();
    assert_eq!(delays, [VarInt::from_u64(micros >> 3).unwrap()]);
}

#[test]
fn paced_bytes_released_after_now_keep_the_connection_from_being_marked_application_limited() {
    // About 43 datagrams: two full runs, then the rest in a third released T later.
    let mut pair = server_backlogged(|c| c, 60_000);
    let t0 = pair.now;
    let last = built_ahead(&mut pair).last().unwrap().1;
    assert_eq!(last, t0 + 209 * US);
    let conn = pair.server.conn();
    assert!(conn.limited_by_app());
    assert!(!conn.recovery.is_app_limited());
    // At the release, an attempt without data to send marks the connection application-limited.
    server_attempt(&mut pair, last);
    assert!(pair.server.conn().recovery.is_app_limited());
}

#[test]
fn a_transfer_built_ahead_arrives_whole_and_in_order_with_releases_that_never_go_back() {
    let server_transport = config(|c| {
        c.pacing(true)
            .pacing_granularity(200 * US)
            .datagram_size(DatagramSize::PeerMaximum)
    });
    let client_transport = config(|c| c.max_data(1 << 40).max_stream_data_uni(1 << 30));
    let setup = Setup {
        client_transport,
        server_transport,
        ..Setup::default()
    };
    let (_, mut pair) = handshake(paired(&setup, 2 * MS));
    let len = 1 << 20;
    let id = pair.server.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    let (mut client, mut server) = (App::default(), App::default());
    server.write(id, pattern(len), true);
    let until = pair.now + Duration::from_secs(10);
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(client.data.get(&id).map(Vec::len), Some(len));
    assert!(client.data[&id] == pattern(len));
    // Every datagram of the server, those built before pacing started included, carried a
    // release; releases never went back, and the link kept them in order.
    let sent = &pair.server.sent;
    assert!(
        sent.iter()
            .all(|(_, datagram)| matches!(datagram.meta.release, Release::At(_)))
    );
    assert!(sent.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    assert_eq!(pair.to_client.reordered(), 0);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "a connection with a build horizon was given no clock epoch")]
fn an_attempt_without_a_clock_epoch_on_a_connection_with_a_horizon_is_a_caller_bug() {
    let mut pair = server_backlogged(|c| c, 10_000);
    let limits = TxLimits {
        epoch: None,
        ..pair.limits()
    };
    let conn = pair.server.conn_mut();
    conn.poll_transmit(&limits, &mut VecSink::new(1500), &mut InlineSealer);
}

#[test]
fn an_attempt_without_a_clock_epoch_builds_nothing_ahead_of_now() {
    // `poll_transmit` panics on this caller bug in debug builds; `transmit` builds the attempt
    // as with a horizon of 0.
    let mut pair = server_backlogged(|c| c, 400_000);
    let t0 = pair.now;
    let limits = TxLimits {
        max_segments: 44,
        epoch: None,
        ..pair.limits()
    };
    let conn = pair.server.conn_mut();
    conn.pacer.set_rate(NonZeroU64::new(125_000_000).unwrap());
    assert_eq!(conn.build_horizon(), 2 * MS);
    let mut sink = VecSink::new(1500);
    // Two runs of 18 leave from idle, and the next waits for its own release, 209 µs on,
    // not for that less the horizon.
    let next = t0 + 209 * US;
    let first = conn.transmit(&limits, &mut sink, &mut InlineSealer);
    assert_eq!(
        (first.datagrams, first.stop, first.pacing_at),
        (36, Stop::Pacing(next), Some(next))
    );
    let again = conn.transmit(&limits, &mut sink, &mut InlineSealer);
    assert_eq!((again.datagrams, again.stop), (0, Stop::Pacing(next)));
    let sent = sink.take();
    assert!(
        sent.iter()
            .all(|datagram| matches!(datagram.meta.release, Release::Asap))
    );
    let data = conn.recovery.space(Space::Data);
    assert!(data.outstanding().all(|packet| packet.time_sent <= t0));
}
