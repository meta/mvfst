/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Congestion control, pacing and retransmission tests over the pair harness of
//! [`crate::testing`].

use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::VarInt;

use super::Connection;
use super::stream_tests::App;
use super::stream_tests::ORDER;
use super::stream_tests::RTT;
use super::stream_tests::config;
use super::stream_tests::pattern;
use super::stream_tests::run_apps;
use super::tests::Forge;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::limits;
use super::tests::open_own;
use super::tests::server_addr;
use super::tests::start;
use crate::AppCode;
use crate::CongestionControl;
use crate::CreditDue;
use crate::DatagramSize;
use crate::DropReason;
use crate::InlineSealer;
use crate::SendOrder;
use crate::Stop;
use crate::TransportConfig;
use crate::TxOutcome;
use crate::TxReport;
use crate::TxSeqRange;
use crate::cc::bbr3::State;
use crate::cc::bbr3::tests::up_and_idle;
use crate::recovery::Space;
use crate::testing::Loss;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::Peer;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

const CONTROLLERS: [CongestionControl; 2] = [CongestionControl::NewReno, CongestionControl::Cubic];

/// Sets up a pair whose client sends with `client` into flow-control windows too wide to limit it.
pub(super) fn setup(client: Arc<TransportConfig>) -> Setup {
    Setup {
        client_transport: client,
        server_transport: config(|c| c.max_data(1 << 40).max_stream_data_uni(1 << 30)),
        ..Setup::default()
    }
}

/// A client sending `len` bytes on a unidirectional stream, ended with the FIN, to a server
/// that reads everything.
pub(super) struct Bulk {
    id: StreamId,
    client: App,
    server: App,
}

impl Bulk {
    pub(super) fn start(pair: &mut Pair, len: usize) -> Self {
        let id = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
        let mut client = App::default();
        client.write(id, pattern(len), true);
        Self {
            id,
            client,
            server: App::default(),
        }
    }

    /// Runs the pair until `until`.
    pub(super) fn run(&mut self, pair: &mut Pair, until: Instant) {
        self.run_with(pair, until, |_| {});
    }

    /// Runs the pair until `until`, calling `each` once everything due at an instant has run.
    pub(super) fn run_with(
        &mut self,
        pair: &mut Pair,
        until: Instant,
        mut each: impl FnMut(&Pair),
    ) {
        loop {
            // The application tops its stream up for as long as the client sends, so the stream's
            // staging cap does not limit the client.
            loop {
                let (now, sent) = (pair.now, pair.client.sent.len());
                run_apps(pair, now, &mut self.client, &mut self.server);
                if pair.client.sent.len() == sent {
                    break;
                }
            }
            each(pair);
            match pair.next_event() {
                Some(at) if at <= until => pair.now = at,
                _ => {
                    pair.now = pair.now.max(until);
                    return;
                }
            }
        }
    }

    /// Returns how many bytes the server has read.
    pub(super) fn received(&self) -> usize {
        self.server.data.get(&self.id).map_or(0, Vec::len)
    }
}

#[test]
fn acknowledgments_grow_the_window_of_a_sender_the_window_limits() {
    for cc in CONTROLLERS {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        let initial = pair.client.conn().stats().cwnd;
        let mut bulk = Bulk::start(&mut pair, 1 << 20);
        let until = pair.now + 5 * RTT;
        bulk.run(&mut pair, until);
        assert!(bulk.received() > 0, "{cc:?}");
        let cwnd = pair.client.conn().stats().cwnd;
        assert!(cwnd > 2 * initial, "{cc:?}: cwnd {cwnd}, initial {initial}");
    }
}

#[test]
fn the_window_starts_at_the_configured_initial_window_and_stops_at_the_maximum() {
    for cc in CONTROLLERS {
        let client = config(|c| c.congestion_control(cc).initial_window(4).max_window(30));
        let (_, pair) = start(setup(client.clone()).pair());
        assert_eq!(pair.client.conn().stats().cwnd, 4 * 1200, "{cc:?}");
        let (_, mut pair) = handshake(setup(client).pair());
        let mut bulk = Bulk::start(&mut pair, 4 << 20);
        let mut largest = 0;
        for _ in 0..20 {
            let until = pair.now + RTT;
            bulk.run(&mut pair, until);
            largest = largest.max(pair.client.conn().stats().cwnd);
        }
        assert_eq!(largest, 30 * 1200, "{cc:?}");
    }
}

/// Returns the datagrams `peer` sent at the first instant at or after `at`, as indices into its
/// sent list, which are also its link's indices.
fn burst(peer: &Peer, at: Instant) -> Range<usize> {
    let first = peer
        .sent
        .iter()
        .position(|(sent, _)| *sent >= at)
        .expect("a datagram sent at or after `at`");
    let instant = peer.sent[first].0;
    let len = peer.sent[first..]
        .iter()
        .take_while(|(sent, _)| *sent == instant)
        .count();
    first..first + len
}

/// Runs a bulk transfer over `config` with the client's datagrams `dropped` lost, for `rounds`
/// round trips of the test RTT, and returns the pair and how often the slow start threshold
/// changed between instants.
fn reductions(mut config: PairConfig, dropped: Vec<usize>, rounds: u32) -> (Pair, usize) {
    config.to_server.loss = Loss::Drop(dropped);
    let (_, mut pair) = handshake(config);
    let mut bulk = Bulk::start(&mut pair, 8 << 20);
    let mut last = pair.client.conn().cc.ssthresh();
    let mut changes = 0;
    let until = pair.now + rounds * RTT;
    bulk.run_with(&mut pair, until, |pair| {
        let ssthresh = pair.client.conn().cc.ssthresh();
        changes += usize::from(ssthresh != last);
        last = ssthresh;
    });
    (pair, changes)
}

#[test]
fn losses_in_one_recovery_period_reduce_the_window_once() {
    for cc in CONTROLLERS {
        let config = setup(config(|c| c.congestion_control(cc))).pair();
        let (probe, _) = reductions(config.clone(), Vec::new(), 1);
        // The first loss is found by the next ACK, the last only later, because it ends its flight.
        let flight = burst(&probe.client, probe.client.sent[0].0 + RTT / 2);
        assert!(flight.len() >= 5, "{cc:?}: a flight of {flight:?}");
        let dropped = vec![flight.start, flight.end - 1];
        let (pair, changes) = reductions(config, dropped, 3);
        assert_eq!(pair.client.conn().stats().lost_packets, 2, "{cc:?}");
        assert_eq!(changes, 1, "{cc:?}");
    }
}

#[test]
fn a_loss_the_loss_timer_finds_reduces_the_window() {
    for cc in CONTROLLERS {
        // A message of two datagrams whose first is lost: the second is acknowledged before the
        // first is a time threshold old, and the client then stays quiet, so the timer finds it.
        let round = |dropped| {
            let mut config = setup(config(|c| c.congestion_control(cc))).pair();
            config.to_server.loss = Loss::Drop(dropped);
            let (_, mut pair) = handshake(config);
            pair.run(pair.now + RTT);
            let first = pair.client.sent.len();
            let mut bulk = Bulk::start(&mut pair, 2_000);
            let until = pair.now + 2 * RTT;
            bulk.run(&mut pair, until);
            assert_eq!(bulk.received(), 2_000, "{cc:?}");
            (pair, first)
        };
        let (probe, first) = round(Vec::new());
        assert_eq!(probe.client.sent[first].0, probe.client.sent[first + 1].0);
        let (pair, _) = round(vec![first]);
        assert_eq!(pair.client.conn().stats().lost_packets, 1, "{cc:?}");
        assert!(pair.client.conn().cc.ssthresh() < u64::MAX, "{cc:?}");
    }
}

/// Loses every datagram.
const BLACKOUT: Loss = Loss::Seeded {
    seed: 0,
    per_mille: 1000,
};

#[test]
fn persistent_congestion_collapses_the_window_to_the_minimum() {
    for cc in CONTROLLERS {
        let client = config(|c| c.congestion_control(cc).min_window(4));
        let (_, mut pair) = handshake(setup(client).pair());
        let mut bulk = Bulk::start(&mut pair, 8 << 20);
        let until = pair.now + RTT;
        bulk.run(&mut pair, until);
        // Every packet sent for a second is lost, PTO probes included, which spans well over the
        // persistent congestion duration of three PTOs.
        pair.to_server.set_loss(BLACKOUT);
        let until = pair.now + 10 * RTT;
        bulk.run(&mut pair, until);
        pair.to_server.set_loss(Loss::None);
        let mut smallest = u64::MAX;
        let until = pair.now + 20 * RTT;
        bulk.run_with(&mut pair, until, |pair| {
            smallest = smallest.min(pair.client.conn().stats().cwnd);
        });
        // The losses of the ACK that establishes persistent congestion reach the controller
        // before its acknowledgments, as in RFC 9002, so the window restarts from the minimum and
        // grows in slow start by the two PTO probes the ACK acknowledges.
        assert!(
            (4 * 1200..=6 * 1200).contains(&smallest),
            "{cc:?}: smallest window {smallest}"
        );
    }
}

#[test]
fn cubic_does_not_count_idle_time_as_time_to_grow_the_window() {
    // A transfer with one early loss, which leaves CUBIC in congestion avoidance.
    let round = |dropped| {
        let mut config = setup(config(|c| c.congestion_control(CongestionControl::Cubic))).pair();
        config.to_server.loss = Loss::Drop(dropped);
        let (_, mut pair) = handshake(config);
        let mut bulk = Bulk::start(&mut pair, 1 << 20);
        let until = pair.now + 10 * RTT;
        bulk.run(&mut pair, until);
        assert_eq!(bulk.received(), 1 << 20);
        pair
    };
    let probe = round(Vec::new());
    let flight = burst(&probe.client, probe.client.sent[0].0 + RTT / 2);
    let mut pair = round(vec![flight.start]);
    assert!(pair.client.conn().cc.ssthresh() < u64::MAX);
    pair.run(pair.now + 100 * RTT);
    let before = pair.client.conn().stats().cwnd;
    let mut bulk = Bulk::start(&mut pair, 8 << 20);
    let until = pair.now + RTT;
    bulk.run(&mut pair, until);
    // Ten idle seconds counted on the cubic curve would grow the window by half each round
    // trip; near the curve's plateau it grows by a few datagrams in the five that follow.
    let after = pair.client.conn().stats().cwnd;
    assert!(after * 4 < before * 5, "cwnd {before} grew to {after}");
}

#[test]
fn cubic_undoes_a_reduction_whose_losses_prove_spurious() {
    let cubic = config(|c| c.congestion_control(CongestionControl::Cubic));
    let (_, mut pair) = handshake(setup(cubic).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let first = client.recovery.space(Space::Data).next_pn();
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(6_000));
    client.stream(id).unwrap().send(&mut data).unwrap();
    client.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer);
    let last = client.recovery.space(Space::Data).next_pn() - 1;
    assert!(last >= first + 3, "packets {first}..={last}");
    let cwnd = client.stats().cwnd;
    // Hand-built ACKs from the server, whose packet numbers it never used.
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let ack = |range, pn| {
        let mut forge = Forge::of(server, Space::Data, pn, &[]);
        forge.ack = Some(range);
        forge.seal(server)
    };
    let rtt = Duration::from_millis(20);
    deliver(client, now + rtt, server_addr(), ack(first + 1..=last, pn));
    assert!(
        client.stats().cwnd < cwnd,
        "the first packet was declared lost"
    );
    deliver(
        client,
        now + 2 * rtt,
        server_addr(),
        ack(first..=last, pn + 1),
    );
    assert_eq!(client.stats().cwnd, cwnd);
}

/// Queues `len` more bytes on stream `id` of `conn` and makes one attempt at `now`, its
/// datagrams discarded.
fn send_more(conn: &mut Connection, id: StreamId, len: usize, now: Instant) -> TxOutcome {
    let mut data = Bytes::from(pattern(len));
    assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(len));
    conn.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer)
}

#[test]
fn an_ack_reaching_back_into_the_recovery_period_grows_the_window_only_for_later_packets() {
    for cc in CONTROLLERS {
        // The ACK of packet 3 of a flight of four declares packet 0 lost and starts a recovery
        // period, with 1 and 2 still in flight; packets sent after that fill the window. One ACK
        // of 1 and 2 with the later packets grows the window as much as acknowledging 1 and 2
        // alone first, at the same instant, as RFC 9002 ties growth to each packet's send time.
        let window = |together: bool| {
            let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
            pair.run(pair.now + RTT);
            let t0 = pair.now;
            let rtt = Duration::from_millis(20);
            let Pair { client, server, .. } = &mut pair;
            let (client, server) = (client.conn_mut(), server.conn());
            let id = client.open_stream(Dir::Uni, ORDER).unwrap();
            let first = client.recovery.space(Space::Data).next_pn();
            send_more(client, id, 4_000, t0);
            assert_eq!(client.recovery.space(Space::Data).next_pn(), first + 4);
            // Hand-built ACKs from the server, whose packet numbers it never used.
            let pn = server.recovery.space(Space::Data).next_pn() + 10;
            let ack = |range, pn| {
                let mut forge = Forge::of(server, Space::Data, pn, &[]);
                forge.ack = Some(range);
                forge.seal(server)
            };
            let cwnd = client.stats().cwnd;
            let loss = ack(first + 3..=first + 3, pn);
            deliver(client, t0 + rtt, server_addr(), loss);
            assert!(client.stats().cwnd < cwnd, "{cc:?}: packet 0 is lost");
            let after = t0 + rtt + Duration::from_millis(1);
            let refill = send_more(client, id, 20_000, after);
            assert_eq!(refill.stop, Stop::Cwnd, "{cc:?}");
            let last = client.recovery.space(Space::Data).next_pn() - 1;
            let at = t0 + 2 * rtt;
            if together {
                deliver(client, at, server_addr(), ack(first + 1..=last, pn + 1));
            } else {
                // Packet 3 is acknowledged already, so this ACK does not produce an RTT sample.
                let early = ack(first + 1..=first + 3, pn + 1);
                deliver(client, at, server_addr(), early);
                deliver(client, at, server_addr(), ack(first + 4..=last, pn + 2));
            }
            client.stats().cwnd
        };
        assert_eq!(window(true), window(false), "{cc:?}");
    }
}

/// Sends `len` bytes on the client's stream `id` once every test RTT, `rounds` times, and
/// returns the client's window before and after.
fn trickle(pair: &mut Pair, id: StreamId, len: usize, rounds: u32) -> (u64, u64) {
    let before = pair.client.conn().stats().cwnd;
    for _ in 0..rounds {
        let mut data = Bytes::from(pattern(len));
        let sent = pair.client.conn_mut().stream(id).unwrap().send(&mut data);
        assert_eq!(sent, Ok(len));
        pair.run(pair.now + RTT);
    }
    (before, pair.client.conn().stats().cwnd)
}

#[test]
fn an_application_limited_sender_does_not_grow_the_window() {
    for cc in CONTROLLERS {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        pair.run(pair.now + RTT);
        let id = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
        let (before, after) = trickle(&mut pair, id, 2_000, 20);
        assert_eq!(after, before, "{cc:?}");
    }
}

#[test]
fn a_sender_with_a_producer_ready_to_be_polled_is_not_application_limited() {
    for cc in CONTROLLERS {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        pair.run(pair.now + RTT);
        let conn = pair.client.conn_mut();
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let ready = conn.open_stream(Dir::Uni, ORDER).unwrap();
        conn.stream(ready).unwrap().wake_producer();
        let (before, after) = trickle(&mut pair, id, 2_000, 20);
        assert!(after > before, "{cc:?}: cwnd {before} became {after}");
    }
}

#[test]
fn a_sender_the_connection_flow_control_limits_does_not_grow_the_window() {
    for cc in CONTROLLERS {
        let setup = Setup {
            client_transport: config(|c| c.congestion_control(cc)),
            server_transport: config(|c| c.max_data(6_000).max_stream_data_uni(1 << 30)),
            ..Setup::default()
        };
        let (_, mut pair) = handshake(setup.pair());
        pair.run(pair.now + RTT);
        let before = pair.client.conn().stats().cwnd;
        let mut bulk = Bulk::start(&mut pair, 1 << 20);
        let until = pair.now + 10 * RTT;
        bulk.run(&mut pair, until);
        assert!(
            bulk.received() > 100_000,
            "{cc:?}: {} bytes",
            bulk.received()
        );
        assert_eq!(pair.client.conn().stats().cwnd, before, "{cc:?}");
    }
}

#[test]
fn a_sender_that_leaves_less_than_a_datagram_of_the_window_is_not_application_limited() {
    for cc in CONTROLLERS {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        pair.run(pair.now + RTT);
        let before = pair.client.conn().stats().cwnd;
        assert_eq!(before, 10 * 1200, "{cc:?}");
        // Nine full datagrams and a part of a tenth.
        let conn = pair.client.conn_mut();
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let mut data = Bytes::from(pattern(11_000));
        conn.stream(id).unwrap().send(&mut data).unwrap();
        pair.step();
        let stats = pair.client.conn().stats();
        let left = stats.cwnd - stats.bytes_in_flight;
        assert!(
            (1..1200).contains(&left),
            "{cc:?}: {left} bytes of the window left"
        );
        assert_eq!(pair.client.outcomes.last().unwrap().stop, Stop::Idle);
        pair.run(pair.now + RTT);
        let after = pair.client.conn().stats().cwnd;
        assert!(after > before, "{cc:?}: cwnd {before} became {after}");
    }
}

#[test]
fn lossy_transfers_complete_with_either_controller() {
    let len = 1 << 20;
    for cc in CONTROLLERS {
        let mut config = setup(config(|c| c.congestion_control(cc))).pair();
        for (link, seed) in [(&mut config.to_server, 11), (&mut config.to_client, 12)] {
            link.loss = Loss::Seeded {
                seed,
                per_mille: 30,
            };
        }
        let (start, mut pair) = handshake(config);
        let mut bulk = Bulk::start(&mut pair, len);
        while bulk.received() < len {
            assert!(pair.now < start + 600 * RTT, "{cc:?}: no progress");
            let until = pair.now + RTT;
            bulk.run(&mut pair, until);
        }
        assert!(
            bulk.server.data[&bulk.id] == pattern(len),
            "{cc:?}: altered"
        );
        assert!(pair.to_server.lost() > 0 && pair.to_client.lost() > 0);
        assert!(pair.client.conn().cc.ssthresh() < u64::MAX, "{cc:?}");
    }
}

/// A frame of a datagram the client sent, as these tests tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Stream {
        id: StreamId,
        offset: u64,
        len: usize,
    },
    MaxStreamData {
        id: StreamId,
        limit: u64,
    },
    StopSending {
        id: StreamId,
    },
    Ping,
    Other,
}

/// Returns the frames of `peer`'s datagram `index`.
fn seen(peer: &Peer, index: usize) -> Vec<Seen> {
    frames_in(peer.conn(), &peer.sent[index].1.data)
}

/// Returns the frames of a datagram `conn` sent.
fn frames_in(conn: &Connection, datagram: &[u8]) -> Vec<Seen> {
    open_own(conn, datagram)
        .iter()
        .flat_map(|(_, plaintext)| {
            Frames::new(plaintext)
                .map(|frame| match frame.expect("a frame it wrote") {
                    Frame::Stream {
                        id, offset, data, ..
                    } => Seen::Stream {
                        id,
                        offset: offset.into_inner(),
                        len: data.len(),
                    },
                    Frame::MaxStreamData { id, max } => Seen::MaxStreamData {
                        id,
                        limit: max.into_inner(),
                    },
                    Frame::StopSending { id, .. } => Seen::StopSending { id },
                    Frame::Ping => Seen::Ping,
                    _ => Seen::Other,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Runs a quiet connection whose client then sends a 500-byte message, with the client's
/// datagrams `dropped` lost, and returns the pair after ten test RTTs, the stream and the
/// message's first datagram.
fn message_round(dropped: Vec<usize>) -> (Pair, StreamId, usize) {
    message_round_of(500, dropped)
}

/// Runs the same round as [`message_round`] with a message of `len` bytes.
fn message_round_of(len: usize, dropped: Vec<usize>) -> (Pair, StreamId, usize) {
    let mut config = Setup::default().pair();
    config.to_server.loss = Loss::Drop(dropped);
    let (_, mut pair) = handshake(config);
    pair.run(pair.now + RTT);
    let first = pair.client.sent.len();
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(len));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    pair.run(pair.now + 10 * RTT);
    (pair, id, first)
}

#[test]
fn a_probe_carries_the_oldest_unacknowledged_data() {
    let (_, _, first) = message_round(Vec::new());
    let (pair, id, first) = message_round(vec![first]);
    assert_eq!(
        seen(&pair.client, first),
        [Seen::Stream {
            id,
            offset: 0,
            len: 500
        }]
    );
    // Only the PTO's probe follows the lost datagram.
    let probe = first + 1;
    assert!(pair.client.sent[probe].0 > pair.client.sent[first].0);
    assert!(
        seen(&pair.client, probe).contains(&Seen::Stream {
            id,
            offset: 0,
            len: 500
        }),
        "{:?}",
        seen(&pair.client, probe)
    );
}

#[test]
fn a_probe_that_carries_data_carries_no_ping() {
    let (_, _, first) = message_round(Vec::new());
    let (pair, _, first) = message_round(vec![first]);
    let probe = seen(&pair.client, first + 1);
    assert!(
        probe.iter().any(|f| matches!(f, Seen::Stream { .. })),
        "{probe:?}"
    );
    assert!(!probe.contains(&Seen::Ping), "{probe:?}");
}

#[test]
fn the_two_probes_of_a_pto_carry_the_two_oldest_packets_in_flight() {
    let (_, _, first) = message_round_of(2_000, Vec::new());
    let (pair, id, first) = message_round_of(2_000, vec![first, first + 1]);
    let stream = |index| -> Vec<Seen> {
        seen(&pair.client, index)
            .into_iter()
            .filter(|f| matches!(f, Seen::Stream { .. }))
            .collect()
    };
    let lost = [stream(first), stream(first + 1)].concat();
    assert_eq!(lost.len(), 2, "{lost:?}");
    let probes = [stream(first + 2), stream(first + 3)].concat();
    assert_eq!(probes, lost);
    assert!(
        lost.iter()
            .all(|f| matches!(f, Seen::Stream { id: of, .. } if *of == id))
    );
}

#[test]
fn a_probe_carries_the_oldest_data_before_new_data_of_a_more_urgent_stream() {
    let (_, mut pair) = handshake(setup(config(|c| c)).pair());
    pair.run(pair.now + RTT);
    pair.to_server.set_loss(BLACKOUT);
    let later = SendOrder {
        urgency: 5,
        ..ORDER
    };
    let sooner = SendOrder {
        urgency: 1,
        ..ORDER
    };
    let conn = pair.client.conn_mut();
    let old = conn.open_stream(Dir::Uni, later).unwrap();
    let mut data = Bytes::from(pattern(20_000));
    conn.stream(old).unwrap().send(&mut data).unwrap();
    pair.step();
    assert_eq!(pair.client.outcomes.last().unwrap().stop, Stop::Cwnd);
    // A more urgent stream then has new data, which the full window holds back until the PTO.
    let conn = pair.client.conn_mut();
    let urgent = conn.open_stream(Dir::Uni, sooner).unwrap();
    let mut data = Bytes::from(pattern(20_000));
    conn.stream(urgent).unwrap().send(&mut data).unwrap();
    let probe = pair.client.sent.len();
    assert!(pair.run_until(pair.now + 10 * RTT, |pair| pair.client.sent.len() > probe));
    let frames = seen(&pair.client, probe);
    assert!(
        frames
            .iter()
            .any(|f| matches!(f, Seen::Stream { id, offset: 0, .. } if *id == old)),
        "{frames:?}"
    );
}

/// Makes one attempt by the client at `now`, outside the pair's links, and returns the frames of
/// each datagram it sent.
fn sent_at(pair: &mut Pair, now: Instant) -> Vec<Vec<Seen>> {
    let mut sink = VecSink::new(1500);
    let conn = pair.client.conn_mut();
    conn.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    sink.take()
        .iter()
        .map(|d| frames_in(conn, &d.data))
        .collect()
}

/// Fires the client's timers, sending at each, until a PTO makes 1-RTT probes due; returns the
/// time it fired.
fn until_probes(pair: &mut Pair) -> Instant {
    loop {
        let conn = pair.client.conn_mut();
        let at = conn.next_deadline().expect("a timer");
        conn.on_deadline(at);
        if conn.recovery.probes_due(Space::Data) > 0 {
            return at;
        }
        attempt(pair, at);
    }
}

#[test]
fn a_probe_passes_over_the_packets_of_a_reset_stream_to_the_oldest_data_still_owed() {
    let (_, mut pair) = handshake(setup(config(|c| c)).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let conn = pair.client.conn_mut();
    let reset = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(2_000));
    conn.stream(reset).unwrap().send(&mut data).unwrap();
    assert_eq!(sent_at(&mut pair, now).len(), 2);
    // Once the stream is reset, the frames of the two oldest packets in flight do not go again.
    let conn = pair.client.conn_mut();
    conn.stream(reset)
        .unwrap()
        .reset(AppCode::from_u32(1))
        .unwrap();
    assert_eq!(sent_at(&mut pair, now).len(), 1);
    let conn = pair.client.conn_mut();
    let owed = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(500));
    conn.stream(owed).unwrap().send(&mut data).unwrap();
    let message = Seen::Stream {
        id: owed,
        offset: 0,
        len: 500,
    };
    let sent = sent_at(&mut pair, now);
    assert!(sent.len() == 1 && sent[0].contains(&message), "{sent:?}");
    let pto = until_probes(&mut pair);
    let probes = sent_at(&mut pair, pto);
    assert!(
        probes.first().is_some_and(|probe| probe.contains(&message)),
        "{probes:?}"
    );
}

#[test]
fn a_probe_passes_over_window_updates_a_later_one_replaced_to_the_oldest_data_still_owed() {
    let client = config(|c| c.max_stream_data_uni(1_000).max_stream_data_autotune(None));
    let (_, mut pair) = handshake(setup(client).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let incoming = StreamId::new(Side::Server, Dir::Uni, 0).unwrap();
    let data = pattern(600);
    let mut pn = pair.server.conn().recovery.space(Space::Data).next_pn() + 10;
    // The client reads the server's next 600 bytes at once, which makes a larger
    // MAX_STREAM_DATA due: the one in flight no longer needs to be sent again.
    let mut read = |pair: &mut Pair, offset: u32| -> Vec<Seen> {
        let frames = [Frame::Stream {
            id: incoming,
            offset: VarInt::from_u32(offset),
            data: &data,
            fin: false,
        }];
        let packet =
            Forge::of(pair.server.conn(), Space::Data, pn, &frames).seal(pair.server.conn());
        pn += 1;
        let client = pair.client.conn_mut();
        deliver(client, now, server_addr(), packet);
        let due = client.stream(incoming).unwrap().consume(data.len());
        assert_eq!(due, Ok(CreditDue::Due));
        sent_at(pair, now).concat()
    };
    let update = |limit| Seen::MaxStreamData {
        id: incoming,
        limit,
    };
    assert!(read(&mut pair, 0).contains(&update(1_600)));
    assert!(read(&mut pair, 600).contains(&update(2_200)));
    let conn = pair.client.conn_mut();
    let owed = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut message = Bytes::from(pattern(500));
    conn.stream(owed).unwrap().send(&mut message).unwrap();
    let message = Seen::Stream {
        id: owed,
        offset: 0,
        len: 500,
    };
    let sent = sent_at(&mut pair, now);
    assert!(sent.len() == 1 && sent[0].contains(&message), "{sent:?}");
    assert!(read(&mut pair, 1_200).contains(&update(2_800)));
    let pto = until_probes(&mut pair);
    let probes = sent_at(&mut pair, pto);
    assert!(
        probes.first().is_some_and(|probe| probe.contains(&message)),
        "{probes:?}"
    );
}

#[test]
fn a_probe_passes_over_stop_sending_of_ended_receive_halves_to_the_oldest_data_still_owed() {
    let (_, mut pair) = handshake(setup(config(|c| c)).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let data = pattern(100);
    let mut pn = pair.server.conn().recovery.space(Space::Data).next_pn() + 10;
    let mut from_server = |pair: &mut Pair, frames: &[Frame<'_>]| {
        let packet =
            Forge::of(pair.server.conn(), Space::Data, pn, frames).seal(pair.server.conn());
        pn += 1;
        deliver(pair.client.conn_mut(), now, server_addr(), packet);
    };
    let stream = |id, offset, fin| Frame::Stream {
        id,
        offset: VarInt::from_u32(offset),
        data: &data,
        fin,
    };
    // The client stops reading two of the server's streams, each STOP_SENDING in a packet of its
    // own, and then sends a message.
    let [ended, reset] = [0, 1].map(|n| StreamId::new(Side::Server, Dir::Uni, n).unwrap());
    for id in [ended, reset] {
        from_server(&mut pair, &[stream(id, 0, false)]);
        let conn = pair.client.conn_mut();
        conn.stream(id)
            .unwrap()
            .stop_sending(AppCode::from_u32(1))
            .unwrap();
        let sent = sent_at(&mut pair, now);
        assert!(
            sent.len() == 1 && sent[0].contains(&Seen::StopSending { id }),
            "{sent:?}"
        );
    }
    let conn = pair.client.conn_mut();
    let owed = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut message = Bytes::from(pattern(500));
    conn.stream(owed).unwrap().send(&mut message).unwrap();
    let message = Seen::Stream {
        id: owed,
        offset: 0,
        len: 500,
    };
    let sent = sent_at(&mut pair, now);
    assert!(sent.len() == 1 && sent[0].contains(&message), "{sent:?}");
    // The server's FIN on one stream and its RESET_STREAM on the other end both receive halves,
    // so the client may not send either STOP_SENDING again.
    let reset_frame = Frame::ResetStream {
        id: reset,
        error_code: VarInt::from_u32(2),
        final_size: VarInt::from_u32(100),
    };
    from_server(&mut pair, &[stream(ended, 100, true), reset_frame]);
    for id in [ended, reset] {
        let streams = &pair.client.conn().sources.streams.streams;
        let recv = streams.get(id).and_then(|s| s.recv_state());
        assert!(
            recv.is_some_and(|r| !r.may_send_stop_sending()),
            "{id:?}: {recv:?}"
        );
    }
    let pto = until_probes(&mut pair);
    let probes = sent_at(&mut pair, pto);
    assert!(
        probes.first().is_some_and(|probe| probe.contains(&message)),
        "{probes:?}"
    );
}

/// Makes one attempt by the client at `now` and discards its datagrams.
fn attempt(pair: &mut Pair, now: Instant) -> TxOutcome {
    let conn = pair.client.conn_mut();
    conn.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer)
}

#[test]
fn a_paced_sender_stops_until_its_next_release_and_sends_nothing_before_it() {
    let (_, mut pair) = handshake(setup(config(|c| c.pacing(true))).pair());
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    let mut now = pair.now;
    let first = attempt(&mut pair, now);
    let Stop::Pacing(release) = first.stop else {
        panic!("not paced: {first:?}");
    };
    assert!(first.datagrams > 0 && release > now, "{first:?}");
    assert_eq!(first.pacing_at, Some(release));
    let mut sent = u32::from(first.datagrams);
    let mut next = release;
    while sent < 9 {
        for early in [now, next - Duration::from_nanos(1)] {
            let outcome = attempt(&mut pair, early);
            assert_eq!(outcome.datagrams, 0, "at {early:?}: {outcome:?}");
            assert_eq!(outcome.stop, Stop::Pacing(next));
        }
        now = next;
        let outcome = attempt(&mut pair, now);
        assert!(outcome.datagrams > 0, "at its release: {outcome:?}");
        sent += u32::from(outcome.datagrams);
        if let Stop::Pacing(release) = outcome.stop {
            assert!(release > now);
            next = release;
        }
    }
}

#[test]
fn paced_datagrams_are_spaced_at_the_controllers_pacing_rate() {
    let (_, mut pair) = handshake(setup(config(|c| c.pacing(true))).pair());
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    let rate = conn.cc.pacing_rate(conn.recovery.rtt().smoothed()).get();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    let now = pair.now;
    let Stop::Pacing(release) = attempt(&mut pair, now).stop else {
        panic!("not paced");
    };
    let one = attempt(&mut pair, release);
    assert_eq!(one.datagrams, 1, "{one:?}");
    let Stop::Pacing(next) = one.stop else {
        panic!("not paced: {one:?}");
    };
    // The pacer's clock advances by the datagram's size over the rate, rounded up.
    let nanos = (u64::from(one.bytes) * 1_000_000_000).div_ceil(rate);
    assert_eq!(next - release, Duration::from_nanos(nanos));
}

#[test]
fn a_paced_flight_leaves_spread_out_in_virtual_time() {
    let (_, mut pair) = handshake(setup(config(|c| c.pacing(true))).pair());
    pair.run(pair.now + RTT);
    let (start, from) = (pair.now, pair.client.sent.len());
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    pair.run(pair.now + RTT);
    let times: Vec<Instant> = pair.client.sent[from..from + 9]
        .iter()
        .map(|(sent, _)| *sent)
        .collect();
    // Two datagrams of burst credit and the one crossing it leave at once, then one every
    // 1.6 ms, all before the first ACK could arrive 20 ms later.
    assert!(times.iter().take(3).all(|&t| t == start), "{times:?}");
    assert!(times[2..].windows(2).all(|w| w[0] < w[1]), "{times:?}");
    assert!(times[8] < start + Duration::from_millis(20), "{times:?}");
}

/// Hands the client hand-built 1-RTT packets from the server, one per frame list, at `now`.
/// The pair must not run afterwards: the server never sent these packet numbers.
fn from_server(pair: &mut Pair, now: Instant, packets: &[&[Frame<'_>]]) {
    let Pair { client, server, .. } = pair;
    let pn = server.conn().recovery.space(Space::Data).next_pn() + 10;
    for (pn, frames) in (pn..).zip(packets) {
        let packet = Forge::of(server.conn(), Space::Data, pn, frames).seal(server.conn());
        deliver(client.conn_mut(), now, server_addr(), packet);
    }
}

#[test]
fn an_ack_only_datagram_takes_no_pacing_tokens() {
    let (_, mut pair) = handshake(setup(config(|c| c.pacing(true))).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    let Stop::Pacing(release) = attempt(&mut pair, now).stop else {
        panic!("not paced");
    };
    // Two ack-eliciting packets make an ACK due at once.
    from_server(&mut pair, now, &[&[Frame::Ping], &[Frame::Ping]]);
    let ack = attempt(&mut pair, now);
    assert_eq!(ack.datagrams, 1, "{ack:?}");
    assert_eq!(ack.stop, Stop::Pacing(release));
}

#[test]
fn probe_datagrams_take_no_pacing_tokens() {
    let (_, mut pair) = handshake(setup(config(|c| c.pacing(true))).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    assert_eq!(attempt(&mut pair, now).datagrams, 3);
    // The discarded datagrams are not acknowledged, so the PTO comes long after the pacer's clock.
    let conn = pair.client.conn_mut();
    let pto = conn.next_deadline().unwrap();
    conn.on_deadline(pto);
    assert_eq!(conn.recovery.probes_due(Space::Data), 2);
    let outcome = attempt(&mut pair, pto);
    // The two probes, then the burst credit's two datagrams and the one crossing it.
    assert_eq!(outcome.datagrams, 5, "{outcome:?}");
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn a_handshake_flight_is_not_paced_before_the_first_rtt_sample() {
    let paced = config(|c| c.pacing(true));
    // A two-datagram ClientHello lets the server send six datagrams before validating the path,
    // and a large certificate makes it use them.
    let setup = Setup {
        pq: true,
        cert_names: 60,
        ..Setup::default()
    }
    .transport(paced);
    let (_, pair) = handshake(setup.pair());
    let flight = burst(&pair.server, pair.server.sent[0].0);
    assert!(flight.len() >= 4, "a first flight of {flight:?}");
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn initial_and_handshake_packets_are_not_paced_before_the_one_rtt_keys() {
    use super::tests::LIMIT;

    let setup = Setup {
        pq: true,
        ..Setup::default()
    }
    .transport(config(|c| c.pacing(true)));
    let mut config = setup.pair();
    // The first half of the ClientHello is lost; the server acknowledges the second at once,
    // which gives the client an RTT sample long before any 1-RTT key.
    config.to_server.loss = Loss::Drop(vec![0]);
    let (epoch, mut pair) = start(config);
    let sampled = |pair: &Pair| {
        let rtt = pair.client.conn().recovery.rtt();
        rtt.first_sample_time().is_some()
    };
    assert!(pair.run_until(epoch + LIMIT, sampled));
    let now = pair.now;
    let conn = pair.client.conn_mut();
    assert!(!conn.has_keys(Space::Data));
    // A clock this far ahead would hold any paced datagram back for seconds.
    conn.pacer.on_paced(now, 1 << 20);
    assert!(conn.pacer.next_release(now) > now + Duration::from_secs(1));
    let lost = |pair: &Pair| pair.client.conn().stats().lost_packets > 0;
    assert!(pair.run_until(epoch + LIMIT, lost));
    // The lost half goes again as soon as it is declared lost.
    assert_eq!(pair.client.sent.last().unwrap().0, pair.now);
}

#[test]
fn the_pacing_burst_follows_the_datagram_size_the_peer_allows() {
    let client = config(|c| c.pacing(true).datagram_size(DatagramSize::PeerMaximum));
    let (_, mut pair) = handshake(setup(client).pair());
    pair.run(pair.now + RTT);
    let now = pair.now;
    let conn = pair.client.conn_mut();
    assert_eq!(conn.mtu, 1452);
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(10_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    // Two 1,452-byte datagrams of burst credit and the one crossing it.
    let burst = attempt(&mut pair, now);
    assert_eq!((burst.datagrams, burst.bytes), (3, 3 * 1452), "{burst:?}");
}

#[test]
fn datagrams_the_backend_dropped_are_lost_with_no_congestion_response() {
    for cc in CONTROLLERS {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        pair.run(pair.now + RTT);
        let now = pair.now;
        let conn = pair.client.conn_mut();
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let mut data = Bytes::from(pattern(5_000));
        conn.stream(id).unwrap().send(&mut data).unwrap();
        let (cwnd, start) = (conn.stats().cwnd, conn.tx_seq);
        let sent = attempt(&mut pair, now);
        let conn = pair.client.conn_mut();
        let tx = TxSeqRange {
            start,
            end: start + u64::from(sent.datagrams),
        };
        let reason = DropReason::LocalQueue;
        conn.on_tx_report(now, TxReport::Dropped { tx, reason });
        assert_eq!(
            conn.stats().lost_packets,
            u64::from(sent.datagrams),
            "{cc:?}"
        );
        assert_eq!(conn.stats().cwnd, cwnd, "{cc:?}");
        assert_eq!(conn.cc.ssthresh(), u64::MAX, "{cc:?}");
    }
}

#[test]
fn bbr3_sends_its_initial_window_unpaced_and_paces_from_the_next_ack() {
    let bbr3 = config(|c| c.congestion_control(CongestionControl::Bbr3).pacing(true));
    let (_, mut pair) = handshake(setup(bbr3).pair());
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(100_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    // The congestion window, not the pacer, stops the initial window.
    let now = pair.now;
    let first = attempt(&mut pair, now);
    assert_eq!(first.stop, Stop::Cwnd, "{first:?}");
    let from = pair.client.outcomes.len();
    pair.run(now + RTT);
    assert!(pair.client.conn().cc.pacing_ready());
    let paced = pair.client.outcomes[from..]
        .iter()
        .any(|o| matches!(o.stop, Stop::Pacing(_)));
    assert!(paced);
}

#[test]
fn bbr3_restarting_probe_bw_from_idle_paces_the_attempt_at_the_restart_rate() {
    let bbr3 = config(|c| c.congestion_control(CongestionControl::Bbr3).pacing(true));
    let (_, mut pair) = handshake(setup(bbr3).pair());
    let (cc, idle) = up_and_idle();
    pair.run(idle.max(pair.now + RTT));
    let conn = pair.client.conn_mut();
    assert_eq!(conn.recovery.bytes_in_flight(), 0);
    conn.cc = cc;
    conn.refresh_pacing_rate();
    let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(pattern(100_000));
    conn.stream(id).unwrap().send(&mut data).unwrap();
    // The first datagram restarts UP from idle at 1 MB/s, and the pacer takes that rate before
    // it stamps the datagram, without an ACK or timeout in between.
    let mut pacer = conn.pacer.clone();
    pacer.set_rate(NonZeroU64::new(1_000_000).unwrap());
    let now = pair.now;
    let mut sink = VecSink::new(1500);
    let outcome = conn.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    for datagram in sink.take() {
        pacer.on_paced(now, datagram.data.len() as u64);
    }
    assert_eq!(
        outcome.stop,
        Stop::Pacing(pacer.next_release(now)),
        "{outcome:?}"
    );
}

#[test]
fn bbr3_fills_a_fixed_rate_link_within_a_few_round_trips_and_keeps_its_queue_small() {
    // 10 Mbit/s with a 20 ms round trip, a BDP of 25,000 bytes, and a drop-tail buffer of one
    // BDP.
    const RATE: u64 = 1_250_000;
    const BDP: u64 = RATE / 50;
    const ROUND_TRIP: Duration = Duration::from_millis(20);
    let bbr3 = config(|c| c.congestion_control(CongestionControl::Bbr3).pacing(true));
    let mut config = setup(bbr3).pair();
    config.to_server.rate = Some(RATE);
    config.to_server.buffer = Some(BDP as usize);
    let (_, mut pair) = handshake(config);
    pair.run(pair.now + RTT);
    let start = pair.now;
    let mut bulk = Bulk::start(&mut pair, 16 << 20);
    // Startup fills the pipe in two round trips and ends after three more without growth, and
    // Drain empties the queue in one or two, all well within ten.
    bulk.run(&mut pair, start + 10 * ROUND_TRIP);
    let (from, early) = (pair.now, bulk.received());
    let link_bytes = |pair: &Pair| pair.server.conn().stats().recv_bytes;
    let early_link = link_bytes(&pair);
    let (mut weighted, mut probing, mut probed) = (0, Duration::ZERO, false);
    let mut last: Option<(Instant, u64)> = None;
    let mut sample = |pair: &Pair| {
        let state = pair.client.conn().cc.bbr3().state();
        probed |= state == State::ProbeBwUp;
        // The queue only drains between events, so its size after one bounds it until the next.
        if let Some((at, queued)) = last {
            weighted += u128::from(queued) * (pair.now - at).as_nanos();
            probing += pair.now - at;
        }
        let probe_bw = matches!(
            state,
            State::ProbeBwDown | State::ProbeBwCruise | State::ProbeBwRefill | State::ProbeBwUp
        );
        last = probe_bw.then(|| (pair.now, pair.to_server.queued(pair.now)));
    };
    // The link is busy 90% of the next ten round trips or more, which leaves room for at most
    // one idle round trip. This counts the bytes the link delivers, since the stream bytes the
    // server reads here also include those held back behind Startup's losses.
    bulk.run_with(&mut pair, start + 20 * ROUND_TRIP, &mut sample);
    let busy =
        u128::from(link_bytes(&pair) - early_link) * 1_000_000_000 / (pair.now - from).as_nanos();
    assert!(
        busy * 10 >= u128::from(RATE) * 9,
        "the link delivered {busy} bytes per second in round trips 10 to 20"
    );
    // And the stream gets 90% of the link rate or more from then on, over long enough for one
    // bandwidth probe: the probe wait after DOWN is below 3 s.
    bulk.run_with(&mut pair, start + Duration::from_millis(3500), &mut sample);
    let delivered = (bulk.received() - early) as u128;
    let rate = delivered * 1_000_000_000 / (pair.now - from).as_nanos();
    assert!(rate * 10 >= u128::from(RATE) * 9, "{rate} bytes per second");
    // ProbeBW paces at bw in CRUISE and REFILL. UP paces at 1.25 times bw for a few round trips of
    // a 2-3 s cycle, and DOWN drains what UP queued by pacing at 0.9 times bw. So the queue's time
    // average must stay below a quarter of a BDP, far below the buffer's one BDP.
    assert!(probed, "no bandwidth probe");
    let average = weighted / probing.as_nanos();
    assert!(
        average * 4 < u128::from(BDP),
        "an average queue of {average} bytes"
    );
}
