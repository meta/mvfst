/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the delivery state, rate samples, per-packet losses and app-limited marking that
//! loss recovery keeps for a controller that takes rate samples.

#![expect(
    clippy::single_range_in_vec_init,
    reason = "a one-element array of ranges is an ACK frame with one range"
)]

use super::*;

const MS: Duration = Duration::from_millis(1);
const ELICITING: SentFlags = SentFlags::ACK_ELICITING.union(SentFlags::IN_FLIGHT);

/// Creates loss recovery for a controller that takes rate samples.
fn sampling(t0: Instant) -> LossRecovery {
    let config = RecoveryConfig {
        rate_samples: true,
        ..RecoveryConfig::default()
    };
    LossRecovery::new(config, Side::Client, t0, [0, 0, 0]).unwrap()
}

/// Sends `count` ack-eliciting packets of `size` bytes in `space` at `at`.
fn send(r: &mut LossRecovery, space: Space, count: u64, size: u16, at: Instant) {
    for _ in 0..count {
        let pn = r.space(space).next_pn();
        r.on_packet_sent(space, pn, at, size, ELICITING, pn)
            .unwrap();
    }
}

fn ack(
    r: &mut LossRecovery,
    space: Space,
    ranges: &[RangeInclusive<u64>],
    ack_delay: Duration,
    now: Instant,
) -> AckOutcome {
    r.on_ack_received(space, ranges.iter().cloned(), ack_delay, now, |_| {})
        .unwrap()
}

#[test]
fn acks_in_every_space_feed_the_delivered_bytes() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Initial, 1, 1200, t0);
    send(&mut r, Space::Handshake, 2, 1000, t0);
    send(&mut r, Space::Data, 1, 500, t0);
    ack(
        &mut r,
        Space::Initial,
        &[0..=0],
        Duration::ZERO,
        t0 + 100 * MS,
    );
    assert_eq!(r.delivered(), 1200);
    ack(
        &mut r,
        Space::Handshake,
        &[0..=1],
        Duration::ZERO,
        t0 + 100 * MS,
    );
    assert_eq!(r.delivered(), 3200);
    ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
    assert_eq!(r.delivered(), 3700);
}

#[test]
fn a_steady_flight_gives_its_bytes_per_round_trip() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    // One 1,200-byte packet every 10 ms over a 100 ms round trip: ten in flight, each
    // acknowledged just before the next is sent.
    let mut samples = Vec::new();
    for k in 0..40u64 {
        let now = t0 + MS * (10 * k as u32);
        if k >= 10 {
            let outcome = ack(&mut r, Space::Data, &[k - 10..=k - 10], Duration::ZERO, now);
            samples.push(outcome.rate.expect("a newly acknowledged in-flight packet"));
        }
        if k == 20 {
            // An ACK-only packet in another space counts toward the bytes sent, not in flight.
            r.on_packet_sent(Space::Initial, 0, now, 50, SentFlags::empty(), 0)
                .unwrap();
        }
        send(&mut r, Space::Data, 1, 1200, now);
    }
    // Packets from the second round on were sent a round trip of deliveries after the ACK
    // their interval starts at.
    for sample in &samples[10..] {
        assert_eq!(sample.interval, 100 * MS);
        assert_eq!(sample.delivered, 12_000);
        assert_eq!(sample.delivery_rate, 120_000);
    }
    // Packet 25, acknowledged at 350 ms, was sent after packets 0 to 15 were acknowledged.
    assert_eq!(
        samples[25],
        RateSample {
            prior_delivered: 16 * 1200,
            delivered: 12_000,
            interval: 100 * MS,
            delivery_rate: 120_000,
            is_app_limited: false,
            tx_in_flight: 12_000,
            lost: 0,
            total_sent: 26 * 1200 + 50,
        }
    );
    assert_eq!(r.total_sent(), 40 * 1200 + 50);
}

#[test]
fn ack_elapsed_time_runs_between_ack_times_less_their_ack_delays() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    r.set_handshake_confirmed();
    send(&mut r, Space::Data, 10, 1200, t0);
    // Packet 10 stays in flight, so the next flight does not start from an empty pipe.
    send(&mut r, Space::Data, 1, 1200, t0 + 50 * MS);
    // 30 ms is above the peer's max_ack_delay of 25 ms; it is not clamped.
    ack(&mut r, Space::Data, &[0..=9], 30 * MS, t0 + 100 * MS);
    send(&mut r, Space::Data, 10, 1200, t0 + 100 * MS);
    let outcome = ack(&mut r, Space::Data, &[10..=20], 10 * MS, t0 + 220 * MS);
    let rate = outcome.rate.unwrap();
    // From 100 - 30 = 70 ms to 220 - 10 = 210 ms, longer than the 100 ms send elapsed time.
    assert_eq!(rate.interval, 140 * MS);
    assert_eq!(rate.delivered, 11 * 1200);
    assert_eq!(rate.delivery_rate, 11 * 1200 * 1000 / 140);

    // ACK delays in the Initial space count too, though the RTT estimate ignores them.
    let mut r = sampling(t0);
    send(&mut r, Space::Initial, 1, 1200, t0);
    send(&mut r, Space::Initial, 1, 1200, t0 + 50 * MS);
    ack(&mut r, Space::Initial, &[0..=0], 40 * MS, t0 + 100 * MS);
    send(&mut r, Space::Initial, 1, 1200, t0 + 100 * MS);
    let outcome = ack(
        &mut r,
        Space::Initial,
        &[1..=2],
        Duration::ZERO,
        t0 + 200 * MS,
    );
    assert_eq!(outcome.rate.unwrap().interval, 140 * MS);
}

#[test]
fn a_send_into_an_empty_pipe_restarts_the_interval_at_the_raw_ack_time() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
    // Idle, then packet 1 goes into an empty pipe.
    send(&mut r, Space::Data, 1, 1200, t0 + 500 * MS);
    send(&mut r, Space::Data, 1, 1200, t0 + 510 * MS);
    let outcome = ack(&mut r, Space::Data, &[1..=2], 20 * MS, t0 + 620 * MS);
    let rate = outcome.rate.unwrap();
    // The interval starts at packet 1's send, so the ACK Delay is not taken off: it ends at
    // 620 ms, not 600 ms.
    assert_eq!(rate.interval, 120 * MS);
    assert_eq!(rate.delivered, 2400);
    assert_eq!(rate.delivery_rate, 20_000);
}

/// Sends one PADDING-only packet of 1,200 bytes in the Application Data space at `at`: it
/// counts in flight but is not ack-eliciting, so its ACK alone does not give an RTT sample.
fn send_padding(r: &mut LossRecovery, at: Instant) -> u64 {
    let pn = r.space(Space::Data).next_pn();
    r.on_packet_sent(Space::Data, pn, at, 1200, SentFlags::IN_FLIGHT, pn)
        .unwrap();
    pn
}

#[test]
fn samples_shorter_than_min_rtt_are_kept_and_a_zero_interval_has_no_rate() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    send_padding(&mut r, t0 + 95 * MS);
    ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
    ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 100 * MS);
    send_padding(&mut r, t0 + 100 * MS);
    let outcome = ack(&mut r, Space::Data, &[2..=2], Duration::ZERO, t0 + 105 * MS);
    assert_eq!(r.rtt().min(), 100 * MS);
    let rate = outcome.rate.unwrap();
    assert_eq!(rate.interval, 5 * MS);
    assert_eq!(rate.delivered, 1200);
    assert_eq!(rate.delivery_rate, 240_000);

    // Over a zero-delay link both elapsed times are zero: the sample stays, with a rate of 0.
    let now = t0 + 200 * MS;
    let pn = send_padding(&mut r, now);
    ack(&mut r, Space::Data, &[pn..=pn], Duration::ZERO, now);
    let pn = send_padding(&mut r, now);
    let outcome = ack(&mut r, Space::Data, &[pn..=pn], Duration::ZERO, now);
    let rate = outcome.rate.unwrap();
    assert_eq!(rate.interval, Duration::ZERO);
    assert_eq!(rate.delivered, 1200);
    assert_eq!(rate.delivery_rate, 0);
}

#[test]
fn the_interval_is_the_longer_of_the_send_and_ack_elapsed_times_in_whole_microseconds() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
    // ACK compression: ten packets sent over 90 ms are acknowledged together. The interval is
    // the 190 ms send elapsed time, not the 110 ms ACK elapsed time, which would inflate the
    // rate.
    for k in 0..9 {
        send(&mut r, Space::Data, 1, 1200, t0 + MS * (100 + 10 * k));
    }
    send(
        &mut r,
        Space::Data,
        1,
        1200,
        t0 + 190 * MS + Duration::from_nanos(999),
    );
    let rate = ack(
        &mut r,
        Space::Data,
        &[1..=10],
        Duration::ZERO,
        t0 + 210 * MS,
    )
    .rate
    .unwrap();
    assert_eq!(rate.interval, 190 * MS);
    assert_eq!(rate.delivery_rate, 12_000 * 1000 / 190);
    // A stretched ACK: ten packets sent in one burst 20 ms after packet 10, acknowledged 190 ms
    // after the last ACK. The interval is the ACK elapsed time.
    send(&mut r, Space::Data, 10, 1200, t0 + 210 * MS);
    let rate = ack(
        &mut r,
        Space::Data,
        &[11..=20],
        Duration::ZERO,
        t0 + 400 * MS,
    )
    .rate
    .unwrap();
    assert_eq!(rate.interval, 190 * MS);
    assert_eq!(rate.delivery_rate, 12_000 * 1000 / 190);
}

#[test]
fn the_app_limited_mark_stamps_later_packets_and_clears_on_the_ack_of_one() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    send(&mut r, Space::Data, 1, 1200, t0 + 10 * MS);
    r.mark_app_limited();
    assert!(r.is_app_limited());
    // Packet 0's interval starts at its own send, before the mark.
    let rate = ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS).rate;
    assert!(rate.unwrap().is_app_limited);
    // Packet 1 was sent before the mark, which is 1 us after its send: the flag stays.
    ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 110 * MS);
    assert!(r.is_app_limited());
    // Packet 2 is stamped application-limited. It goes into the empty pipe, so its interval
    // starts at its own send, after the mark: only the stamp makes its sample app-limited.
    send(&mut r, Space::Data, 1, 1200, t0 + 120 * MS);
    let rate = ack(&mut r, Space::Data, &[2..=2], Duration::ZERO, t0 + 220 * MS).rate;
    // Packet 2 was sent after the mark: the flag clears, but its own sample keeps its stamp.
    assert!(!r.is_app_limited());
    assert!(rate.unwrap().is_app_limited);
    send(&mut r, Space::Data, 1, 1200, t0 + 220 * MS);
    let rate = ack(&mut r, Space::Data, &[3..=3], Duration::ZERO, t0 + 320 * MS).rate;
    assert!(!rate.unwrap().is_app_limited);
    // The ACK of a packet sent exactly at the mark clears the flag too.
    send(&mut r, Space::Data, 1, 1200, t0 + 320 * MS);
    r.mark_app_limited();
    let at_mark = t0 + 320 * MS + Duration::from_micros(1);
    send(&mut r, Space::Data, 1, 1200, at_mark);
    ack(&mut r, Space::Data, &[4..=5], Duration::ZERO, t0 + 420 * MS);
    assert!(!r.is_app_limited());
}

#[test]
fn an_ack_only_largest_packet_leaves_the_frame_to_its_largest_in_flight_packet() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    r.mark_app_limited();
    r.on_packet_sent(Space::Data, 1, t0 + 10 * MS, 50, SentFlags::empty(), 1)
        .unwrap();
    let outcome = ack(&mut r, Space::Data, &[0..=1], Duration::ZERO, t0 + 100 * MS);
    assert_eq!(outcome.ack.largest_newly_acked, Some((1, t0 + 10 * MS)));
    assert_eq!(outcome.largest_in_flight_sent, Some(t0));
    // Packet 0 was sent before the mark; the ACK-only packet 1, sent after it, does not count.
    assert!(r.is_app_limited());
    assert_eq!(outcome.rate.unwrap().delivered, 1200);
    // Packet 2's interval starts at packet 0's send: 100 ms of sending against 50 ms of ACKs.
    send(&mut r, Space::Data, 1, 1200, t0 + 100 * MS);
    let rate = ack(&mut r, Space::Data, &[2..=2], Duration::ZERO, t0 + 150 * MS)
        .rate
        .unwrap();
    assert_eq!(rate.interval, 100 * MS);
}

#[test]
fn a_packet_acknowledged_after_being_declared_lost_delivers_nothing() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 4, 1200, t0);
    send(&mut r, Space::Data, 1, 1200, t0 + 10 * MS);
    // Packets 0 and 1 are three below the largest acknowledged.
    let outcome = ack(&mut r, Space::Data, &[4..=4], Duration::ZERO, t0 + 100 * MS);
    assert_eq!(outcome.loss.lost_packets, 2);
    assert_eq!(r.delivered(), 1200);
    let outcome = ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 120 * MS);
    assert_eq!(outcome.ack.spurious, 1);
    assert_eq!(r.delivered(), 1200);
    assert_eq!(outcome.rate, None);
    assert_eq!(outcome.largest_in_flight_sent, None);
    // Nor does it move the start of later intervals: packet 5's starts at packet 4's send.
    send(&mut r, Space::Data, 1, 1200, t0 + 120 * MS);
    let rate = ack(&mut r, Space::Data, &[1..=5], Duration::ZERO, t0 + 130 * MS)
        .rate
        .unwrap();
    assert_eq!(rate.interval, 110 * MS);
    assert_eq!(rate.delivered, 1200 + 1200 + 1200);
}

#[test]
fn losses_arrive_in_send_order_with_their_send_state_and_count_in_the_sample() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 1, 1200, t0);
    r.mark_app_limited();
    send(&mut r, Space::Data, 5, 1200, t0);
    let outcome = ack(&mut r, Space::Data, &[5..=5], Duration::ZERO, t0 + 100 * MS);
    let lost = |pn: u64, is_app_limited| LostSample {
        size: 1200,
        pn,
        space: Space::Data,
        tx_in_flight: 1200 * (pn + 1),
        is_app_limited,
    };
    assert_eq!(
        r.lost_samples(),
        [lost(0, false), lost(1, true), lost(2, true)]
    );
    assert_eq!(outcome.loss.on_path_lost_bytes, 3600);
    assert_eq!(outcome.loss.newly_lost, 3);
    assert_eq!(r.lost(), 3600);
    // The frame's sample counts its own losses.
    assert_eq!(outcome.rate.unwrap().lost, 3600);
    // A packet sent after them does not.
    send(&mut r, Space::Data, 1, 1200, t0 + 100 * MS);
    let outcome = ack(
        &mut r,
        Space::Data,
        &[6..=6, 3..=4],
        Duration::ZERO,
        t0 + 200 * MS,
    );
    assert_eq!(outcome.rate.unwrap().lost, 0);
    assert_eq!(r.lost_samples(), []);
    assert_eq!(r.lost(), 3600);
}

#[test]
fn dropped_and_off_path_packets_give_no_loss_input_and_no_sample() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    let off_path = ELICITING | SentFlags::OFF_PATH;
    send(&mut r, Space::Data, 1, 1200, t0);
    r.on_packet_sent(Space::Data, 1, t0, 1200, off_path, 1)
        .unwrap();
    send(&mut r, Space::Data, 3, 1200, t0);
    r.on_packet_sent(Space::Data, 5, t0 + 10 * MS, 1200, off_path, 5)
        .unwrap();
    assert_eq!(r.total_sent(), 4 * 1200);
    // An ACK of only an off-path packet does not give a sample. Packets 0 to 2 are lost, but
    // packet 1 went off the path.
    let outcome = ack(&mut r, Space::Data, &[5..=5], Duration::ZERO, t0 + 100 * MS);
    assert_eq!(outcome.rate, None);
    assert_eq!(outcome.largest_in_flight_sent, None);
    assert_eq!(r.delivered(), 0);
    assert_eq!(
        r.lost_samples().iter().map(|l| l.pn).collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(outcome.loss.newly_lost, 3);
    assert_eq!(outcome.loss.on_path_lost_bytes, 2400);
    assert_eq!(r.lost(), 2400);
    // A dropped datagram is not a congestion loss.
    let dropped = r.on_tx_dropped(TxSeqRange { start: 3, end: 4 }, |_| {});
    assert_eq!(dropped.lost_packets, 1);
    assert_eq!(dropped.newly_lost, 0);
    assert_eq!(dropped.on_path_lost_bytes, 0);
    assert_eq!(r.lost(), 2400);
    // Its late ACK does not count either; packet 4's sample counts the 2,400 lost bytes.
    let outcome = ack(&mut r, Space::Data, &[3..=4], Duration::ZERO, t0 + 110 * MS);
    assert_eq!(r.delivered(), 1200);
    let rate = outcome.rate.unwrap();
    assert_eq!(rate.delivered, 1200);
    assert_eq!(rate.lost, 2400);
    // Packet 4 was sent with packets 0 to 4 in flight, packet 1 not counted.
    assert_eq!(rate.tx_in_flight, 4 * 1200);
    assert_eq!(rate.total_sent, 4 * 1200);
}

#[test]
fn a_new_path_keeps_the_delivered_and_sent_bytes_and_resets_the_rest() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 5, 1200, t0);
    ack(&mut r, Space::Data, &[4..=4], Duration::ZERO, t0 + 100 * MS);
    assert_eq!(r.lost(), 2400);
    send(&mut r, Space::Data, 1, 1200, t0 + 100 * MS);
    r.mark_app_limited();
    r.reset_for_new_path();
    assert_eq!(r.delivered(), 1200);
    assert_eq!(r.total_sent(), 6 * 1200);
    assert_eq!(r.lost(), 0);
    assert!(!r.is_app_limited());
    // Packet 6 restarts the interval on the new path, at the instant of the old mark and of the
    // old path's last ACK.
    send(&mut r, Space::Data, 1, 1200, t0 + 100 * MS);
    // Packets 2 and 3, sent on the old path, are lost but do not give loss input.
    let outcome = ack(&mut r, Space::Data, &[6..=6], Duration::ZERO, t0 + 150 * MS);
    assert_eq!(outcome.loss.newly_lost, 2);
    assert_eq!(r.lost_samples(), []);
    assert_eq!(r.lost(), 0);
    // An interval from the old path's last ACK would take in packet 4's 100 ms of sending.
    assert_eq!(
        outcome.rate,
        Some(RateSample {
            prior_delivered: 1200,
            delivered: 1200,
            interval: 50 * MS,
            delivery_rate: 24_000,
            is_app_limited: false,
            tx_in_flight: 1200,
            lost: 0,
            total_sent: 7 * 1200,
        })
    );
    // An old-path packet's acknowledgment does not give a sample.
    let outcome = ack(&mut r, Space::Data, &[5..=6], Duration::ZERO, t0 + 210 * MS);
    assert_eq!(outcome.rate, None);
    assert_eq!(outcome.largest_in_flight_sent, None);
    assert_eq!(r.delivered(), 2400);
}

#[test]
fn acks_and_loss_timeouts_never_grow_the_lost_sample_buffer() {
    let t0 = crate::recovery::test_epoch();
    let mut r = sampling(t0);
    send(&mut r, Space::Data, 18, 1200, t0);
    send(&mut r, Space::Data, 3, 1200, t0 + 60 * MS);
    let capacity = r.lost_samples.capacity();
    // The ACK of packet 20 declares packets 0 to 17 lost; 18 and 19, sent with it, wait for the
    // loss time.
    ack(
        &mut r,
        Space::Data,
        &[20..=20],
        Duration::ZERO,
        t0 + 100 * MS,
    );
    assert_eq!(r.lost_samples().len(), 18);
    assert_eq!(r.lost_samples.capacity(), capacity);
    let (at, _) = r.loss_detection_timer(false).unwrap();
    assert!(matches!(
        r.on_timeout(at, false, |_| {}),
        TimeoutOutcome::Lost(Space::Data, _)
    ));
    assert_eq!(r.lost_samples().len(), 2);
    assert_eq!(r.lost_samples.capacity(), capacity);
}
