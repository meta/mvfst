/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! ProbeRTT's entry, wait and exit.

use super::*;

/// Moves `sim` to ProbeBW and returns the time of the first ACK, 20 ms after the start. That ACK
/// set min_rtt to 20 ms, and later samples have not been lower. One packet stays in flight, so
/// later sends are not restarts from idle.
fn probe_bw_with_min_rtt_from(sim: &mut Sim) -> Instant {
    let start = sim.now;
    sim.to_probe_bw();
    sim.ack(sim.flight.len() - 1);
    start + 20 * MS
}

#[test]
fn probe_rtt_starts_after_10_s_without_a_lower_rtt_and_holds_cwnd_at_half_the_bdp() {
    let mut sim = Sim::new();
    let stamp = probe_bw_with_min_rtt_from(&mut sim);
    // An ACK exactly 10 s after the min_rtt sample is not past the filter's length.
    sim.now = stamp + Duration::from_secs(10) - 20 * MS;
    sim.send(20);
    sim.now += 20 * MS;
    assert!(!sim.ack(2));
    assert_ne!(sim.bbr().state, State::ProbeRtt);
    // A later one is. ProbeRTT's cwnd is half the BDP at the expired min_rtt, 10,000 bytes, and
    // every ACK in it marks the connection app-limited.
    sim.now += MS;
    assert!(sim.ack(1));
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert_eq!(sim.cc.cwnd(), 10_000);
    assert!(sim.ack(1));
    assert_eq!(sim.cc.cwnd(), 10_000);
    // Half the BDP at a lower bw, 600 kB/s over the 21 ms sample that replaced the expired min_rtt,
    // is below the cwnd saved at expiry.
    sim.bbr_mut().bw_shortterm = Some(600_000);
    assert!(sim.ack(1));
    assert_eq!(sim.cc.cwnd(), 6300);
    // A loss timeout and a frame that does not newly acknowledge a packet do not run ProbeRTT's
    // step, so they do not mark the connection app-limited.
    assert!(!sim.lose(1));
    assert!(!sim.event(0, 0, 1, false));
}

#[test]
fn probe_rtt_does_not_start_again_while_min_rtt_stays_expired() {
    // CheckProbeRTT() enters only from another state. ProbeRTT begins, and its wait starts, at ACKs
    // without an RTT sample, so min_rtt is still expired at the ACK that ends it.
    let mut sim = Sim::new();
    let stamp = probe_bw_with_min_rtt_from(&mut sim);
    sim.now = stamp + Duration::from_secs(10) - 20 * MS;
    sim.send(20);
    sim.now += 21 * MS;
    sim.no_rtt_sample = true;
    sim.ack(3);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.no_rtt_sample = true;
    sim.ack(10);
    let t0 = sim.now;
    assert_eq!(sim.bbr().probe_rtt_done_stamp, Some(t0 + 200 * MS));
    sim.send(1);
    sim.now = t0 + 201 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

/// Moves `sim` into ProbeRTT as in the test above, 18 packets in flight. Returns cwnd before it.
fn in_probe_rtt(sim: &mut Sim) -> u64 {
    let stamp = probe_bw_with_min_rtt_from(sim);
    sim.now = stamp + Duration::from_secs(10) - 20 * MS;
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(2);
    let cwnd = sim.cc.cwnd();
    sim.now += MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    cwnd
}

#[test]
fn probe_rtt_ends_200_ms_and_a_round_after_inflight_falls_to_its_cwnd() {
    let mut sim = Sim::new();
    let cwnd = in_probe_rtt(&mut sim);
    // Nine packets in flight are above ProbeRTT's cwnd; eight are not, and the wait starts.
    sim.ack(9);
    sim.ack(1);
    let t0 = sim.now;
    sim.send(1);
    // 200 ms pass, then more, without a round.
    sim.now = t0 + 200 * MS;
    sim.ack(1);
    sim.now += MS;
    sim.ack(6);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    // The round ends with the packet sent after the wait started. The pipe was full, so ProbeBW
    // resumes in CRUISE, with cwnd restored and the next ProbeRTT 10 s away. The ACK that ends
    // ProbeRTT still marks the connection app-limited.
    assert!(sim.ack(2));
    assert!(sim.bbr().round_start);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    assert_eq!(
        sim.cc.cwnd(),
        (cwnd + 2 * MSS).min(sim.bbr().max_inflight())
    );
    assert_eq!(sim.bbr().min_rtt_stamp, Some(sim.now));

    // A round that ends before the 200 ms leaves ProbeRTT at the first ACK after them.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.ack(10);
    let t0 = sim.now;
    sim.send(3);
    sim.now = t0 + 100 * MS;
    sim.ack(sim.flight.len() - 2);
    assert!(sim.bbr().round_start);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    // Not at exactly 200 ms.
    sim.now = t0 + 200 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.now = t0 + 201 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn the_round_probe_rtt_waits_for_starts_with_its_wait_not_at_its_entry() {
    // HandleProbeRTT(): a probe sent above ProbeRTT's cwnd before the wait starts does not end the
    // round; the next packet, sent after the wait started, does.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.send(1);
    sim.ack(11);
    let t0 = sim.now;
    assert_eq!(sim.bbr().probe_rtt_done_stamp, Some(t0 + 200 * MS));
    sim.send(1);
    sim.now = t0 + 201 * MS;
    sim.ack(sim.flight.len() - 1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn probe_rtt_waits_once_inflight_is_at_most_its_cwnd_of_at_least_4_datagrams() {
    // ProbeRTTCwnd(): half the BDP at 100 kB/s is below MinPipeCwnd, 4,800 bytes.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.bbr_mut().bw_shortterm = Some(100_000);
    sim.ack(1);
    sim.ack(12);
    assert_eq!(sim.bbr().probe_rtt_done_stamp, None);
    sim.ack(1);
    assert_eq!(sim.inflight(), 4 * MSS);
    assert_eq!(sim.bbr().probe_rtt_done_stamp, Some(sim.now + 200 * MS));
}

#[test]
fn the_next_probe_rtt_also_waits_for_a_round_after_its_200_ms() {
    // The first ProbeRTT ends on its round, with a packet left in flight so that later sends
    // are not restarts from idle.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.ack(10);
    let t0 = sim.now;
    sim.send(2);
    sim.now = t0 + 201 * MS;
    sim.ack(sim.flight.len() - 1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    assert!(sim.bbr().probe_rtt_round_done);
    // The next one is due 10 s later; its wait starts once eight packets are in flight.
    sim.now += Duration::from_secs(10);
    sim.send(20);
    sim.now += 30 * MS;
    sim.ack(2);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.ack(11);
    let t1 = sim.now;
    // 200 ms pass without a round.
    sim.now = t1 + 201 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
}

/// Ends ProbeRTT as [`in_probe_rtt`] leaves it, at an ACK 201 ms and a round after inflight fell to
/// ProbeRTT's cwnd.
fn end_probe_rtt(sim: &mut Sim) {
    sim.ack(10);
    let t0 = sim.now;
    sim.send(1);
    sim.now = t0 + 201 * MS;
    sim.ack(sim.flight.len());
}

#[test]
fn leaving_probe_rtt_restarts_the_wait_before_the_next_probe() {
    // ExitProbeRTT(): ProbeBW resumes through DOWN, which restarts the probing clock at the exit,
    // although the wait that ran before ProbeRTT has long passed.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.ack(10);
    let t0 = sim.now;
    sim.send(2);
    sim.now = t0 + 201 * MS;
    sim.ack(sim.flight.len() - 1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    let refill = sim.now + sim.bbr().bw_probe_wait;
    sim.send(1);
    sim.now = refill;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    // DOWN's round also starts at the exit, so the packet sent before it did not end a round.
    assert!(!sim.bbr().round_start);
    sim.now += MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
}

#[test]
fn leaving_probe_rtt_resets_the_short_term_model() {
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.bbr_mut().bw_shortterm = Some(500_000);
    sim.bbr_mut().inflight_shortterm = Some(10 * MSS);
    end_probe_rtt(&mut sim);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    assert_eq!(sim.bbr().bw_shortterm, None);
    assert_eq!(sim.bbr().inflight_shortterm, None);
}

#[test]
fn probe_rtt_returns_to_startup_if_the_pipe_was_not_full() {
    // The pipe never fills while Startup is app-limited.
    let mut sim = Sim::new();
    let stamp = sim.now + 20 * MS;
    sim.app_limited = true;
    sim.round(10, 20 * MS);
    sim.send(1);
    sim.now = stamp + Duration::from_secs(10) - 20 * MS;
    sim.send(5);
    sim.now += 20 * MS;
    sim.ack(2);
    sim.now += MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert!(!sim.bbr().full_bw_reached);
    sim.send(1);
    sim.now += 201 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().state, State::Startup);
    assert_eq!(sim.bbr().pacing_gain, 277);
}

#[test]
fn probe_rtt_caps_cwnd_at_inflight_longterms_headroom() {
    // BoundCwndForModel(): 9,600 bytes less 15% is below ProbeRTT's 10,000.
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.bbr_mut().inflight_longterm = Some(8 * MSS);
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), 8160);
}

#[test]
fn a_send_into_an_empty_pipe_takes_the_next_rtt_sample_as_min_rtt_instead_of_probe_rtt() {
    let mut sim = Sim::new();
    let stamp = probe_bw_with_min_rtt_from(&mut sim);
    sim.ack(1);
    sim.now = stamp + Duration::from_secs(11);
    sim.send(1);
    sim.now += 30 * MS;
    assert!(!sim.ack(1));
    assert_ne!(sim.bbr().state, State::ProbeRtt);
    assert_eq!(sim.bbr().min_rtt, Some(30 * MS));
    assert_eq!(sim.bbr().min_rtt_stamp, Some(sim.now));
}

#[test]
fn an_ack_without_a_rate_sample_leaves_the_restart_from_idle_pending() {
    // CheckProbeRTT() clears BBR.idle_restart only once a sample delivered data. After a send into
    // an empty pipe, a frame that acknowledges a lost packet as spurious and declares another lost
    // lacks a rate sample.
    let mut sim = Sim::new();
    let stamp = probe_bw_with_min_rtt_from(&mut sim);
    sim.ack(1);
    sim.now = stamp + Duration::from_secs(11);
    sim.send(3);
    sim.lose(1);
    sim.now += 30 * MS;
    sim.event(1, 0, 1, false);
    assert!(!sim.ack(1));
    assert_ne!(sim.bbr().state, State::ProbeRtt);
    assert_eq!(sim.bbr().min_rtt, Some(30 * MS));
}

#[test]
fn a_send_into_an_empty_pipe_after_probe_rtts_200_ms_ends_it_without_waiting_for_a_round() {
    let mut sim = Sim::new();
    in_probe_rtt(&mut sim);
    sim.ack(10);
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().probe_rtt_round_done);
    sim.now += 201 * MS;
    sim.send(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn probe_rtt_that_interrupts_up_ends_its_loss_response_at_its_first_round_start() {
    // CheckProbeRTT() stops the probe: its samples end at ProbeRTT's next round start, and later
    // losses no longer set inflight_longterm.
    let mut sim = Sim::new();
    let stamp = sim.now + 20 * MS;
    sim.to_probe_bw_up();
    // An ACK just past min_rtt's 10 s enters ProbeRTT with UP's loss response still on.
    sim.now = stamp + Duration::from_secs(10) - 19 * MS;
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(2);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert!(sim.bbr().check_probe_loss);
    // EnterProbeRTT(): paced at bw rather than UP's 1.25 times it. The cwnd gain of 0.5 does not
    // matter beside ProbeRTT's own cwnd cap.
    assert_eq!(sim.rate(), 1_000_000);
    assert_eq!(sim.bbr().cwnd_gain, 50);
    // The round ends at the ACK of a packet sent after ProbeRTT began.
    sim.send(4);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len() - 3);
    assert!(sim.bbr().round_start);
    // Two loss events, far above 2% of the bytes in flight.
    sim.event(1, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert_eq!(sim.bbr().inflight_longterm, None);
}

#[test]
fn a_probe_loss_in_probe_rtt_before_its_first_round_start_does_not_leave_probe_rtt() {
    // HandleInflightTooHigh() enters DOWN only from UP. ProbeRTT is entered from UP as above, and
    // two loss events follow before its first round ends. The second packet lost had 4,800 bytes in
    // flight before it; 0.7 times ProbeRTT's cwnd is higher.
    let mut sim = Sim::new();
    let stamp = sim.now + 20 * MS;
    sim.to_probe_bw_up();
    sim.now = stamp + Duration::from_secs(10) - 19 * MS;
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(2);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.event(1, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert_eq!(sim.bbr().inflight_longterm, Some(7000));
}

#[test]
fn entering_probe_rtt_starts_a_round_which_forgets_the_probes_loss_events() {
    // The round that entering ProbeRTT starts clears the round's loss events. UP loses a packet,
    // then ProbeRTT begins at an ACK that is not a round start. One more loss event in ProbeRTT is
    // then the round's only one, so the loss is not too high.
    let mut sim = Sim::new();
    let stamp = sim.now + 20 * MS;
    sim.to_probe_bw_up();
    sim.now = stamp + Duration::from_secs(10) - 40 * MS;
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(2);
    assert!(sim.bbr().round_start);
    sim.event(1, 1, 0, false);
    sim.now += 21 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    assert!(!sim.bbr().round_start && sim.bbr().check_probe_loss);
    sim.lose(1);
    assert_eq!(sim.bbr().inflight_longterm, None);
}
