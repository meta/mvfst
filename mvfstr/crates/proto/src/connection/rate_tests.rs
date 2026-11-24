/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the inputs a controller that takes rate samples gets: the send events, the ACK-or-loss
//! events and app-limited marking, over the pair harness of [`crate::testing`].

use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::StreamId;
use mvfstr_wire::VarInt;

use super::Connection;
use super::cc_tests::Bulk;
use super::cc_tests::setup;
use super::stream_tests::ORDER;
use super::stream_tests::RTT;
use super::stream_tests::config;
use super::stream_tests::pattern;
use super::tests::Forge;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::limits;
use super::tests::server_addr;
use super::tests::start;
use crate::CongestionControl;
use crate::InlineSealer;
use crate::TxOutcome;
use crate::cc::Cc;
use crate::cc::SentEvent;
use crate::cc::recording::Recording;
use crate::recovery::Space;
use crate::recovery::sent::LostSample;
use crate::testing::Pair;
use crate::testing::VecSink;

/// Gives `conn` a recording controller that takes rate samples.
fn record(conn: &mut Connection) {
    conn.cc = conn.cc.recording();
    conn.recovery.enable_rate_samples();
}

/// Returns the recording controller's record.
fn recording(conn: &Connection) -> &Recording {
    match &conn.cc {
        Cc::Recording(r) => r,
        _ => panic!("the connection has no recording controller"),
    }
}

#[test]
fn newreno_and_cubic_connections_keep_no_send_snapshots() {
    for cc in [CongestionControl::NewReno, CongestionControl::Cubic] {
        let (_, mut pair) = handshake(setup(config(|c| c.congestion_control(cc))).pair());
        let mut bulk = Bulk::start(&mut pair, 1 << 20);
        let until = pair.now + 5 * RTT;
        bulk.run(&mut pair, until);
        assert!(bulk.received() > 0);
        let recovery = &pair.client.conn().recovery;
        assert!(!recovery.takes_rate_samples(), "{cc:?}");
        for space in Space::ALL {
            assert_eq!(
                recovery.space(space).snapshot_capacity(),
                0,
                "{cc:?} {space:?}"
            );
        }
        assert_eq!(recovery.delivered(), 0, "{cc:?}");
        assert_eq!(recovery.total_sent(), 0, "{cc:?}");
    }
    // A controller that takes samples has them.
    let (_, mut pair) = start(setup(config(|c| c)).pair());
    record(pair.client.conn_mut());
    let until = pair.now + Duration::from_secs(1);
    assert!(pair.handshake(until));
    let mut bulk = Bulk::start(&mut pair, 1 << 20);
    let until = pair.now + 5 * RTT;
    bulk.run(&mut pair, until);
    let recovery = &pair.client.conn().recovery;
    assert!(recovery.space(Space::Data).snapshot_capacity() > 0);
    assert!(recovery.delivered() > 0);
}

#[test]
fn send_events_carry_the_packet_size_send_time_and_bytes_sent() {
    let (epoch, mut pair) = start(setup(config(|c| c)).pair());
    record(pair.client.conn_mut());
    let until = pair.now + Duration::from_secs(1);
    assert!(pair.handshake(until));
    let mut bulk = Bulk::start(&mut pair, 100_000);
    let until = pair.now + 5 * RTT;
    bulk.run(&mut pair, until);
    let conn = pair.client.conn();
    let sent = &recording(conn).sent;
    // The ClientHello's Initial packet fills the first datagram.
    assert_eq!(
        sent[0],
        SentEvent {
            time_sent: epoch,
            bytes_in_flight: 0,
            size: 1200,
            total_sent: 1200,
        }
    );
    for pair in sent.windows(2) {
        assert!(pair[1].total_sent >= pair[0].total_sent + u64::from(pair[1].size));
        assert!(pair[1].time_sent >= pair[0].time_sent);
    }
    // Every packet counts toward the bytes sent, those not in flight too.
    let bytes: usize = pair.client.sent.iter().map(|(_, d)| d.data.len()).sum();
    assert_eq!(conn.recovery.total_sent(), bytes as u64);
    let in_flight: u64 = sent.iter().map(|e| u64::from(e.size)).sum();
    assert!(in_flight <= bytes as u64);
}

/// Returns a pair after the handshake and a quiet round trip, whose client then gets a
/// recording controller.
fn recorded() -> Pair {
    let (_, mut pair) = handshake(setup(config(|c| c)).pair());
    pair.run(pair.now + RTT);
    record(pair.client.conn_mut());
    pair
}

/// Has `conn` send `len` more bytes on stream `id` at `now`, outside the pair's links.
fn send_more(conn: &mut Connection, id: StreamId, len: usize, now: Instant) -> TxOutcome {
    let mut data = Bytes::from(pattern(len));
    assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(len));
    conn.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer)
}

/// Builds a 1-RTT packet from `server`, with a packet number it never used, carrying an ACK
/// frame of `range` with ACK Delay field `delay`.
fn ack_from(server: &Connection, range: RangeInclusive<u64>, delay: VarInt) -> Vec<u8> {
    let pn = server.recovery.space(Space::Data).next_pn() + 10 + range.end();
    let mut forge = Forge::of(server, Space::Data, pn, &[]);
    forge.ack = Some(range);
    forge.ack_delay = delay;
    forge.seal(server)
}

#[test]
fn an_ack_frame_reaches_the_hook_once_with_its_losses_and_a_sample_counting_them() {
    let mut pair = recorded();
    let t0 = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let first = client.recovery.space(Space::Data).next_pn();
    send_more(client, id, 4_000, t0);
    assert_eq!(client.recovery.space(Space::Data).next_pn(), first + 4);
    let sent = recording(client).sent.clone();
    let size = |i: usize| u64::from(sent[i].size);
    // The ACK of packet 3 declares packet 0 lost.
    let rtt = Duration::from_millis(20);
    let ack = ack_from(server, first + 3..=first + 3, VarInt::ZERO);
    deliver(client, t0 + rtt, server_addr(), ack.clone());
    let events = &recording(client).events;
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.now, t0 + rtt);
    let ack_part = event.ack.unwrap();
    assert_eq!(ack_part.acked_bytes, size(3));
    assert_eq!(ack_part.largest_acked_sent, Some(t0));
    assert_eq!(ack_part.rtt_sample, Some(rtt));
    assert_eq!(event.delivered, size(3));
    assert_eq!(event.total_sent, client.recovery.total_sent());
    assert_eq!(event.bytes_in_flight, size(1) + size(2));
    assert_eq!(
        event.lost,
        [LostSample {
            size: sent[0].size,
            pn: first,
            space: Space::Data,
            tx_in_flight: sent[0].bytes_in_flight + size(0),
            is_app_limited: false,
        }]
    );
    assert_eq!(event.largest_lost_sent, Some(t0));
    assert!(!event.persistent_congestion);
    assert_eq!(
        (event.spurious, event.newly_lost, event.declared_lost),
        (0, 1, 1)
    );
    // The sample already counts the frame's loss.
    let rate = ack_part.rate.unwrap();
    assert_eq!(rate.delivered, size(3));
    assert_eq!(rate.lost, size(0));
    // The same frame again does not newly acknowledge any packet or declare one lost.
    deliver(
        client,
        t0 + rtt + Duration::from_millis(1),
        server_addr(),
        ack_from(server, first + 3..=first + 3, VarInt::ZERO),
    );
    assert_eq!(recording(client).events.len(), 1);
}

#[test]
fn a_frame_acknowledging_only_a_lost_packet_reaches_the_hook_with_its_counts_and_no_sample() {
    let mut pair = recorded();
    let t0 = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let first = client.recovery.space(Space::Data).next_pn();
    send_more(client, id, 4_000, t0);
    let ms = Duration::from_millis(1);
    let ack = ack_from(server, first + 3..=first + 3, VarInt::ZERO);
    deliver(client, t0 + 20 * ms, server_addr(), ack);
    let delivered = client.recovery.delivered();
    // Packet 0 arrives after all.
    let ack = ack_from(server, first..=first, VarInt::ZERO);
    deliver(client, t0 + 25 * ms, server_addr(), ack);
    let events = &recording(client).events;
    assert_eq!(events.len(), 2);
    let event = &events[1];
    assert_eq!(event.now, t0 + 25 * ms);
    let part = event.ack.unwrap();
    assert_eq!(part.acked_bytes, 0);
    assert_eq!(part.largest_acked_sent, None);
    assert_eq!(part.rate, None);
    assert_eq!(event.delivered, delivered);
    assert_eq!(event.lost, []);
    assert_eq!(
        (event.spurious, event.newly_lost, event.declared_lost),
        (1, 0, 0)
    );
}

#[test]
fn a_loss_timeout_reaches_the_hook_with_its_time_its_losses_and_the_declared_losses() {
    let mut pair = recorded();
    let t0 = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let first = client.recovery.space(Space::Data).next_pn();
    send_more(client, id, 5_000, t0);
    assert_eq!(client.recovery.space(Space::Data).next_pn(), first + 5);
    // The ACK of packet 4 declares packets 0 and 1 lost; 2 and 3 wait for the loss time.
    let ack = ack_from(server, first + 4..=first + 4, VarInt::ZERO);
    deliver(client, t0 + Duration::from_millis(20), server_addr(), ack);
    assert_eq!(recording(client).events[0].lost.len(), 2);
    let at = client.next_deadline().unwrap();
    client.on_deadline(at);
    let events = &recording(client).events;
    assert_eq!(events.len(), 2);
    let event = &events[1];
    assert_eq!(event.now, at);
    assert_eq!(event.ack, None);
    assert_eq!(
        event.lost.iter().map(|l| l.pn).collect::<Vec<_>>(),
        [first + 2, first + 3]
    );
    assert_eq!(event.largest_lost_sent, Some(t0));
    assert_eq!(
        (event.spurious, event.newly_lost, event.declared_lost),
        (0, 2, 4)
    );
    assert_eq!(event.bytes_in_flight, 0);
}

#[test]
fn an_ack_delay_beyond_a_thousand_seconds_counts_as_zero() {
    let mut pair = recorded();
    let t0 = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let first = client.recovery.space(Space::Data).next_pn();
    let ms = Duration::from_millis(1);
    send_more(client, id, 500, t0);
    deliver(
        client,
        t0 + 20 * ms,
        server_addr(),
        ack_from(server, first..=first, VarInt::ZERO),
    );
    // Packet 1's interval starts at that ACK. The largest field overflows when scaled by the
    // default exponent of 3; it neither panics nor moves the ACK time.
    send_more(client, id, 500, t0 + 20 * ms);
    let ack = ack_from(server, first + 1..=first + 1, VarInt::MAX);
    deliver(client, t0 + 60 * ms, server_addr(), ack);
    let rate = |client: &Connection| {
        let event = recording(client).events.last().unwrap();
        event.ack.unwrap().rate.unwrap()
    };
    assert_eq!(rate(client).interval, 40 * ms);
    // 250,000,000 scaled by 8 is 2,000 s, which does not overflow.
    send_more(client, id, 500, t0 + 60 * ms);
    let ack = ack_from(server, first + 2..=first + 2, VarInt::from_u32(250_000_000));
    deliver(client, t0 + 110 * ms, server_addr(), ack);
    assert_eq!(rate(client).interval, 50 * ms);
}

/// Returns the recording controller, mutably.
fn recording_mut(conn: &mut Connection) -> &mut Recording {
    match &mut conn.cc {
        Cc::Recording(r) => r,
        _ => panic!("the connection has no recording controller"),
    }
}

#[test]
fn a_mark_the_hook_asks_for_is_applied() {
    for ask in [false, true] {
        let mut pair = recorded();
        let t0 = pair.now;
        let Pair { client, server, .. } = &mut pair;
        let (client, server) = (client.conn_mut(), server.conn());
        recording_mut(client).mark_app_limited = ask;
        let id = client.open_stream(Dir::Uni, ORDER).unwrap();
        let first = client.recovery.space(Space::Data).next_pn();
        // More than the window: the attempt ends window-limited and does not mark the connection.
        let outcome = send_more(client, id, 60_000, t0);
        assert_eq!(outcome.stop, crate::Stop::Cwnd);
        assert!(!client.recovery.is_app_limited());
        let ack = ack_from(server, first..=first + 1, VarInt::ZERO);
        deliver(client, t0 + Duration::from_millis(20), server_addr(), ack);
        assert_eq!(client.recovery.is_app_limited(), ask);
    }
}

#[test]
fn the_count_of_streams_with_lost_data_follows_loss_retransmission_acknowledgment_and_reset() {
    // How the lost data of packet 0 leaves: 0 resent, 1 acknowledged late, 2 reset.
    for way in 0..3 {
        let (_, mut pair) = handshake(setup(config(|c| c)).pair());
        pair.run(pair.now + RTT);
        let t0 = pair.now;
        let Pair { client, server, .. } = &mut pair;
        let (client, server) = (client.conn_mut(), server.conn());
        let id = client.open_stream(Dir::Uni, ORDER).unwrap();
        let first = client.recovery.space(Space::Data).next_pn();
        send_more(client, id, 4_000, t0);
        let lost = |client: &Connection| client.sources.streams.backlog().lost;
        assert!(!lost(client));
        let ms = Duration::from_millis(1);
        let ack = ack_from(server, first + 3..=first + 3, VarInt::ZERO);
        deliver(client, t0 + 20 * ms, server_addr(), ack);
        assert!(lost(client), "{way}");
        match way {
            0 => {
                let limits = limits(t0 + 21 * ms);
                client.poll_transmit(&limits, &mut VecSink::new(1500), &mut InlineSealer);
            }
            1 => {
                let ack = ack_from(server, first..=first, VarInt::ZERO);
                deliver(client, t0 + 21 * ms, server_addr(), ack);
            }
            _ => client
                .stream(id)
                .unwrap()
                .reset(crate::AppCode::from_u32(1))
                .unwrap(),
        }
        assert!(!lost(client), "{way}");
        client.sources.streams.streams.assert_indexed();
    }
}

#[test]
fn an_attempt_with_window_to_spare_and_nothing_waiting_marks_the_connection_app_limited() {
    let mut pair = recorded();
    let t0 = pair.now;
    let client = pair.client.conn_mut();
    assert!(!client.recovery.is_app_limited());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let outcome = send_more(client, id, 500, t0);
    assert_eq!(outcome.datagrams, 1);
    assert!(client.recovery.is_app_limited());
}

#[test]
fn a_full_window_is_not_app_limited_but_one_byte_of_room_is() {
    let mut pair = recorded();
    let t0 = pair.now;
    let client = pair.client.conn_mut();
    recording_mut(client).inner.window.cwnd = 1;
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let outcome = send_more(client, id, 500, t0);
    assert_eq!(outcome.datagrams, 1);
    assert_eq!(client.sources.streams.backlog().staged, 0);
    assert!(!client.recovery.is_app_limited());
    let in_flight = client.recovery.bytes_in_flight();
    recording_mut(client).inner.window.cwnd = in_flight;
    assert!(!client.limited_by_app());
    recording_mut(client).inner.window.cwnd = in_flight + 1;
    assert!(client.limited_by_app());
}

/// Returns a pair whose server allows the client `max_data` bytes of stream data, after the
/// handshake and a quiet round trip, whose client then gets a recording controller.
fn recorded_with_max_data(max_data: u64) -> Pair {
    let setup = crate::testing::fixtures::Setup {
        client_transport: config(|c| c),
        server_transport: config(|c| c.max_data(max_data).max_stream_data_uni(1 << 30)),
        ..crate::testing::fixtures::Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    pair.run(pair.now + RTT);
    record(pair.client.conn_mut());
    pair
}

#[test]
fn a_datagram_of_staged_bytes_keeps_the_mark_off_even_behind_flow_control() {
    // Staged bytes beyond the credit: a datagram's worth, then one byte less.
    for short in [0, 1] {
        let mut pair = recorded_with_max_data(10_000);
        let t0 = pair.now;
        let client = pair.client.conn_mut();
        let mtu = u64::from(client.mtu);
        let id = client.open_stream(Dir::Uni, ORDER).unwrap();
        let len = 10_000 + mtu - short;
        let outcome = send_more(client, id, len as usize, t0);
        assert_eq!(outcome.stop, crate::Stop::ConnFlowControl);
        assert_eq!(client.sources.streams.backlog().staged, mtu - short);
        assert_eq!(client.recovery.is_app_limited(), short == 1, "{short}");
    }
}

#[test]
fn a_push_sender_waiting_for_writable_keeps_the_mark_off() {
    let setup = crate::testing::fixtures::Setup {
        client_transport: config(|c| c),
        server_transport: config(|c| c.max_data(1 << 40).max_stream_data_uni(2_000)),
        ..crate::testing::fixtures::Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    pair.run(pair.now + RTT);
    record(pair.client.conn_mut());
    let t0 = pair.now;
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    // The stream takes its credit's worth and refuses the rest.
    let mut data = Bytes::from(pattern(5_000));
    assert_eq!(client.stream(id).unwrap().send(&mut data), Ok(2_000));
    client.poll_transmit(&limits(t0), &mut VecSink::new(1500), &mut InlineSealer);
    let backlog = client.sources.streams.backlog();
    assert_eq!(backlog.staged, 0);
    assert!(backlog.push_blocked);
    assert!(!client.recovery.is_app_limited());
}

#[test]
fn a_pull_ready_producer_keeps_the_mark_off() {
    let mut pair = recorded();
    let t0 = pair.now;
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    client.stream(id).unwrap().wake_producer();
    client.poll_transmit(&limits(t0), &mut VecSink::new(1500), &mut InlineSealer);
    let backlog = client.sources.streams.backlog();
    assert_eq!(backlog.staged, 0);
    assert!(backlog.pull_ready);
    assert!(!client.recovery.is_app_limited());
}

#[test]
fn lost_stream_or_crypto_data_waiting_is_not_app_limited() {
    let mut pair = recorded();
    let t0 = pair.now;
    let Pair { client, server, .. } = &mut pair;
    let (client, server) = (client.conn_mut(), server.conn());
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let first = client.recovery.space(Space::Data).next_pn();
    send_more(client, id, 4_000, t0);
    assert!(client.limited_by_app());
    let ack = ack_from(server, first + 3..=first + 3, VarInt::ZERO);
    deliver(client, t0 + Duration::from_millis(20), server_addr(), ack);
    // Packet 0's stream bytes wait, while the staged count is 0 and the window has room.
    let backlog = client.sources.streams.backlog();
    assert!(backlog.lost);
    assert_eq!(backlog.staged, 0);
    assert!(client.stats().cwnd > client.recovery.bytes_in_flight());
    assert!(!client.limited_by_app());

    // The ClientHello's CRYPTO bytes, made lost as a PTO makes them.
    let (epoch, mut pair) = start(setup(config(|c| c)).pair());
    let client = pair.client.conn_mut();
    record(client);
    client.poll_transmit(&limits(epoch), &mut VecSink::new(1500), &mut InlineSealer);
    assert!(client.limited_by_app());
    client.sources.crypto[Space::Initial.index()].resend_unacked();
    assert!(!client.limited_by_app());
}

#[test]
fn samples_over_a_bottleneck_measure_its_rate_once_the_window_exceeds_the_bdp() {
    // 10 Mbit/s with a 20 ms round trip: a BDP of 25,000 bytes.
    const RATE: u64 = 1_250_000;
    const BDP: u64 = RATE / 50;
    let mut config = setup(config(|c| c)).pair();
    config.to_server.rate = Some(RATE);
    let (_, mut pair) = handshake(config);
    pair.run(pair.now + RTT);
    record(pair.client.conn_mut());
    let mut bulk = Bulk::start(&mut pair, 8 << 20);
    let until = pair.now + Duration::from_secs(2);
    bulk.run(&mut pair, until);
    // The round trip in which slow start first fills the pipe leaves it idle part of the time.
    // It is full when packets are sent with twice the BDP in flight, a round trip later.
    let rates: Vec<u64> = recording(pair.client.conn())
        .events
        .iter()
        .filter_map(|e| e.ack.and_then(|a| a.rate))
        .filter(|r| !r.is_app_limited && r.tx_in_flight > 2 * BDP)
        .map(|r| r.delivery_rate)
        .collect();
    assert!(rates.len() > 500, "{} samples", rates.len());
    for rate in rates {
        assert!(
            rate.abs_diff(RATE) * 20 <= RATE,
            "a sample of {rate} bytes per second"
        );
    }
}
