/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The loss response, the short-term bounds and the cwnd caps.

use super::*;

/// Returns a sender in UP at 1 MB/s and 20 ms that sent `n` packets at once into an empty pipe
/// 20 ms earlier: packet `i` was sent with `(i + 1) * MSS` bytes in flight.
fn up_with_flight(n: usize) -> Sim {
    up_with_flight_from(Sim::new(), n)
}

/// Returns `sim` after the steps of [`up_with_flight`].
fn up_with_flight_from(mut sim: Sim, n: usize) -> Sim {
    sim.to_probe_bw_up();
    sim.now += 20 * MS;
    sim.ack(1);
    sim.send(n);
    sim.now += 20 * MS;
    sim
}

#[test]
fn up_ends_on_more_than_2_percent_lost_in_the_round_with_two_loss_events() {
    // One run of two lost packets, 2,400 bytes, is above 2% of the 62,400 bytes in flight when the
    // second was sent, but it is one loss event, and loss is too high only with two.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(2, 1, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    assert_eq!(sim.bbr().inflight_longterm, None);
    // A second event ends UP. InflightAtLoss: 63,600 bytes in flight before packet 53 and
    // 2,400 lost before it, already above 2%, so the prefix is clamped at 0.
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(63_600));
    // DOWN does not respond to each lost packet.
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().inflight_longterm, Some(63_600));

    // A loss below 2% of the bytes in flight before it leaves a prefix: with 62,400 bytes in
    // flight before packet 52 and 1,200 lost, (0.02 * 62,400 - 1,200) / 0.98 = 48.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(1, 1, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(62_448));
}

#[test]
fn a_probe_loss_sets_inflight_longterm_no_lower_than_0_7_times_target_inflight() {
    // HandleInflightTooHigh(): packets 1 and 3 are lost, two loss events. 3,600 bytes were in
    // flight before packet 3, and the 1,200 lost before it are above 2% of them, so InflightAtLoss
    // is 3,600. TargetInflight is the BDP, 20,000 bytes, below cwnd.
    let mut sim = up_with_flight(60);
    sim.ack(1);
    sim.event(1, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(14_000));
    // With a maximum window of ten datagrams, TargetInflight is cwnd, 12,000 bytes.
    let config = CcConfig {
        max_window_packets: 10,
        ..CcConfig::default()
    };
    let mut sim = up_with_flight_from(Sim::start(config, CcStart::default()), 60);
    assert_eq!(sim.cc.cwnd(), 10 * MSS);
    sim.ack(1);
    sim.event(1, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(8400));
}

#[test]
fn an_app_limited_lost_packet_ends_up_without_setting_inflight_longterm() {
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    sim.now += 20 * MS;
    sim.ack(1);
    sim.app_limited = true;
    sim.send(60);
    sim.now += 20 * MS;
    sim.ack(50);
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, None);
    // Nor does it move the uncapped mark, so with inflight_longterm set, as an earlier probe could
    // have left it, the rest of this flight raises it.
    sim.bbr_mut().inflight_longterm = Some(10_000);
    sim.ack(1);
    assert_eq!(sim.bbr().inflight_longterm, Some(54 * MSS));
}

#[test]
fn a_sample_without_too_much_loss_raises_inflight_longterm_to_its_bytes_in_flight() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.ack(29);
    sim.bbr_mut().inflight_longterm = Some(10_000);
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(10);
    assert_eq!(sim.bbr().inflight_longterm, Some(10 * MSS));
    sim.ack(10);
    assert_eq!(sim.bbr().inflight_longterm, Some(20 * MSS));
}

#[test]
fn inflight_longterm_does_not_grow_from_packets_sent_before_it_capped_them() {
    // Startup's loss exit sets it from the BDP and the loss round's delivered bytes. The rest of
    // that flight, sent in Startup, leaves it there; a flight sent in CRUISE raises it.
    let mut sim = super::loss_round(40, &[1; 6]);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    assert_eq!(sim.bbr().inflight_longterm, Some(34 * MSS));
    sim.send(50);
    sim.now += 20 * MS;
    sim.ack(50);
    assert_eq!(sim.bbr().inflight_longterm, Some(50 * MSS));
    // UP's loss exit sets it at 62,448 bytes. The packets sent before, with up to 72,000 bytes
    // in flight, leave it there; a flight sent after raises it.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().inflight_longterm, Some(62_448));
    sim.send(60);
    sim.now += 20 * MS;
    sim.ack(60);
    assert_eq!(sim.bbr().inflight_longterm, Some(60 * MSS));
}

#[test]
fn inflight_longterm_does_not_grow_in_drain() {
    // Not even from a packet past the uncapped mark.
    let mut sim = Sim::new();
    sim.to_drain();
    sim.bbr_mut().inflight_longterm = Some(10_000);
    sim.bbr_mut().uncapped_sent = None;
    sim.ack(5);
    assert_eq!(sim.bbr().state, State::Drain);
    assert_eq!(sim.bbr().inflight_longterm, Some(10_000));
}

/// Returns a sender in CRUISE at 1 MB/s with inflight_longterm at 10,000 bytes, after 30 packets
/// sent at once and the first of them acknowledged at a round start: packet `i` was sent with
/// `(i + 1) * MSS` in flight.
fn cruise_with_flight() -> Sim {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.ack(29);
    sim.send(30);
    sim.now += 20 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    sim.bbr_mut().inflight_longterm = Some(10_000);
    sim
}

#[test]
fn a_sample_with_too_much_loss_does_not_raise_inflight_longterm() {
    // Two loss events, packets 1 and 3, are 2,400 bytes lost since packet 4 was sent with
    // 6,000 bytes in flight.
    let mut sim = cruise_with_flight();
    sim.bbr_mut().inflight_longterm = Some(4000);
    sim.event(1, 1, 0, false);
    sim.event(1, 1, 0, false);
    assert_eq!(sim.bbr().inflight_longterm, Some(4000));
}

#[test]
fn one_loss_event_in_the_round_does_not_stop_inflight_longterm_from_growing() {
    // 1,200 bytes lost since packet 19 was sent with 24,000 bytes in flight is more than 2%, but it
    // is the round's only loss event, and loss is too high only with two.
    let mut sim = cruise_with_flight();
    sim.event(1, 18, 0, false);
    assert_eq!(sim.bbr().inflight_longterm, Some(20 * MSS));
}

#[test]
fn cwnd_is_capped_by_inflight_longterm_its_headroom_in_cruise_and_inflight_shortterm() {
    // The draft's BoundCwndForModel().
    let mut sim = Sim::new();
    sim.to_probe_bw();
    assert!(sim.cc.cwnd() > 20 * MSS, "{}", sim.cc.cwnd());
    sim.bbr_mut().inflight_longterm = Some(20 * MSS);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.cc.cwnd(), 20 * MSS);
    // CRUISE leaves headroom: 24,000 - 15% of it.
    sim.ack(12);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    assert_eq!(sim.cc.cwnd(), 20_400);
    sim.bbr_mut().inflight_shortterm = Some(15_000);
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), 15_000);
    // Never below MinPipeCwnd.
    sim.bbr_mut().inflight_shortterm = Some(1000);
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
}

#[test]
fn cwnd_is_capped_by_inflight_longterm_in_refill_and_up() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    let refill = sim.now + sim.bbr().bw_probe_wait + MS;
    sim.ack(13);
    sim.now = refill;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    assert!(sim.cc.cwnd() > 20 * MSS, "{}", sim.cc.cwnd());
    sim.bbr_mut().inflight_longterm = Some(20 * MSS);
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), 20 * MSS);
    // UP's ACKs would grow cwnd past it.
    sim.send(2);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len() - 1);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    assert_eq!(sim.cc.cwnd(), 20 * MSS);
}

#[test]
fn drain_is_not_capped_by_inflight_longterm() {
    // As in the draft's pseudocode, though the draft's table of states caps Drain.
    let mut sim = Sim::new();
    sim.to_drain();
    sim.bbr_mut().inflight_longterm = Some(10 * MSS);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::Drain);
    assert!(sim.cc.cwnd() > 10 * MSS, "{}", sim.cc.cwnd());
}

/// Runs a loss round at `bw` from CRUISE at 1 MB/s with an empty pipe: it starts with a loss and
/// ends at the ACK of a packet sent after it. Returns cwnd before that ACK.
fn cruise_loss_round(sim: &mut Sim, bw: u64) -> u64 {
    sim.send(30);
    sim.now += 20 * MS;
    sim.bw = bw;
    sim.ack(1);
    sim.event(1, 1, 0, false);
    sim.send(1);
    let cwnd = sim.cc.cwnd();
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert!(sim.bbr().loss_round_start);
    cwnd
}

#[test]
fn outside_a_probe_each_loss_round_with_a_loss_lowers_the_short_term_model() {
    // AdaptLowerBoundsFromCongestion(): from max_bw and cwnd, to the larger of the round's latest
    // delivery and 0.7 times the bound. bw follows bw_shortterm.
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.ack(29);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    let cwnd = cruise_loss_round(&mut sim, 500_000);
    assert_eq!(sim.bbr().bw_shortterm, Some(700_000));
    assert_eq!(sim.bbr().bw, 700_000);
    assert_eq!(sim.bbr().inflight_shortterm, Some(cwnd * 7 / 10));
    assert!(sim.cc.cwnd() <= cwnd * 7 / 10);
    // The next one, at 500 kB/s, lowers bw_shortterm to the latest delivery rate.
    cruise_loss_round(&mut sim, 500_000);
    assert_eq!(sim.bbr().bw_shortterm, Some(500_000));
}

#[test]
fn entering_down_forgets_the_probes_losses_for_the_short_term_model() {
    // ResetCongestionSignals() on entering DOWN: UP's losses ended UP and do not lower the
    // short-term model at the end of their loss round, which comes in DOWN.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    sim.ack(sim.flight.len());
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(1);
    assert!(sim.bbr().loss_round_start);
    assert_eq!(sim.bbr().bw_shortterm, None);
    assert_eq!(sim.bbr().inflight_shortterm, None);
}

#[test]
fn a_loss_in_down_lowers_the_short_term_model_from_downs_delivery_signals_not_ups() {
    // ResetCongestionSignals() on entering DOWN: UP's samples ran at 1 MB/s and delivered up to
    // 61,200 bytes. The rest of UP's flight is lost in DOWN, which starts a loss round, and the
    // packet sent next ends it with a sample of 500 kB/s and 1,200 bytes.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    sim.lose(sim.flight.len());
    sim.bw = 500_000;
    sim.send(1);
    let cwnd = sim.cc.cwnd();
    sim.now += 20 * MS;
    sim.ack(1);
    assert!(sim.bbr().loss_round_start);
    // 0.7 times max_bw and cwnd are above DOWN's signals.
    assert_eq!(sim.bbr().bw_shortterm, Some(700_000));
    assert_eq!(sim.bbr().inflight_shortterm, Some(cwnd * 7 / 10));
}

/// Returns a cwnd-limited sender in UP at the round start after UP's start, with 20 packets in
/// flight, inflight_longterm = cwnd, and the long-term model growing one datagram per `per_inc`
/// bytes acknowledged.
fn up_at_inflight_longterm(config: CcConfig, per_inc: u64) -> Sim {
    let mut sim = Sim::start(config, CcStart::default());
    sim.to_probe_bw_up();
    sim.send(21);
    sim.now += 20 * MS;
    sim.ack(2);
    assert!(sim.bbr().round_start);
    let cwnd = sim.cc.cwnd();
    let bbr = sim.bbr_mut();
    bbr.inflight_longterm = Some(cwnd);
    bbr.cwnd_limited_in_round = true;
    bbr.probe_up_acked_per_inc = per_inc;
    bbr.bw_probe_up_acked = 0;
    sim
}

#[test]
fn up_raises_inflight_longterm_by_a_datagram_per_increment_acked_while_cwnd_limited_at_it() {
    // ProbeInflightLongtermUpward(): 12,000 bytes acknowledged are five increments of 2,400.
    let mut sim = up_at_inflight_longterm(CcConfig::default(), 2 * MSS);
    let longterm = sim.cc.cwnd();
    sim.ack(10);
    assert_eq!(sim.bbr().inflight_longterm, Some(longterm + 5 * MSS));
    // Not when the sender has not filled the cwnd this round, even at inflight_longterm = cwnd.
    let bbr = sim.bbr_mut();
    bbr.cwnd_limited_in_round = false;
    let longterm = bbr.window.cwnd;
    bbr.inflight_longterm = Some(longterm);
    sim.ack(4);
    assert_eq!(sim.bbr().inflight_longterm, Some(longterm));
    // Nor when it has, but cwnd is below inflight_longterm, which then does not limit it.
    let bbr = sim.bbr_mut();
    bbr.cwnd_limited_in_round = true;
    let longterm = bbr.window.cwnd + MSS;
    bbr.inflight_longterm = Some(longterm);
    sim.ack(2);
    assert_eq!(sim.bbr().inflight_longterm, Some(longterm));
    // Bytes past an increment count toward the next: at inflight_longterm = cwnd again, three
    // datagrams are one increment and half of the next, which one more datagram completes.
    let cwnd = sim.cc.cwnd();
    sim.bbr_mut().inflight_longterm = Some(cwnd);
    sim.ack(3);
    assert_eq!(sim.bbr().inflight_longterm, Some(cwnd + MSS));
    sim.bbr_mut().inflight_longterm = Some(cwnd);
    sim.ack(1);
    assert_eq!(sim.bbr().inflight_longterm, Some(cwnd + MSS));
}

#[test]
fn inflight_longterm_grows_by_increments_only_in_up() {
    // AdaptLongTermModel(): in DOWN after UP's loss exit, at inflight_longterm = cwnd with a
    // cwnd-limited sender and a growth step of one datagram, a packet sent in DOWN is acknowledged.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(2, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.cc.cwnd(), 63_600);
    sim.send(40);
    sim.now += 20 * MS;
    let bbr = sim.bbr_mut();
    bbr.cwnd_limited_in_round = true;
    bbr.probe_up_acked_per_inc = MSS;
    sim.ack(8);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(63_600));
}

#[test]
fn up_raises_inflight_longterm_at_most_to_the_maximum_window() {
    // Fifteen datagrams more would pass a maximum of 120 datagrams.
    let config = CcConfig {
        max_window_packets: 120,
        ..CcConfig::default()
    };
    let mut sim = up_at_inflight_longterm(config, MSS);
    assert_eq!(sim.cc.cwnd(), 132_200);
    sim.ack(15);
    assert_eq!(sim.bbr().inflight_longterm, Some(120 * MSS));
}

#[test]
fn each_round_start_in_up_at_inflight_longterm_doubles_the_next_rounds_growth() {
    // RaiseInflightLongtermSlope() from ProbeInflightLongtermUpward(): UP's start made the first
    // round's growth one datagram per cwnd; the next round start makes it two.
    let mut sim = up_at_inflight_longterm(CcConfig::default(), u64::MAX);
    let cwnd = sim.cc.cwnd();
    sim.ack(20);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(1);
    assert!(sim.bbr().round_start);
    assert_eq!(sim.bbr().probe_up_acked_per_inc, cwnd / 2);
    assert_eq!(sim.bbr().bw_probe_up_rounds, 2);
}

#[test]
fn refills_losses_do_not_count_toward_ups_loss_exit() {
    // Entering UP starts a round, which clears the round's losses.
    let mut sim = Sim::new();
    sim.to_probe_bw();
    let refill = sim.now + sim.bbr().bw_probe_wait + MS;
    sim.ack(13);
    sim.now = refill;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    // Two loss events in REFILL, far above 2%.
    sim.event(1, 1, 0, false);
    sim.event(1, 0, 0, false);
    sim.send(2);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len() - 1);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    // One loss event in UP is not enough.
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
}

#[test]
fn a_loss_timeout_reruns_the_control_outputs() {
    // After UP's loss exit in a loss timeout, without an ACK, BBR3 paces at DOWN's rate and caps
    // cwnd at the new inflight_longterm at once.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(2, 1, 0, false);
    assert_eq!(sim.rate(), 1_250_000);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.rate(), 900_000);
    assert_eq!(sim.cc.cwnd(), 63_600);
}

#[test]
fn the_probe_after_a_loss_exit_is_not_cut_short_at_inflight_longterm() {
    // BBR3 does not decelerate as a precaution, so it does not accelerate as one either. UP ended
    // on loss with inflight_longterm at 63,600 bytes.
    let mut sim = up_with_flight(60);
    sim.ack(50);
    sim.event(2, 1, 0, false);
    sim.lose(1);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    let refill = sim.now + sim.bbr().bw_probe_wait + MS;
    // The probe's samples end at the next round start, which stays in ProbeBW's cycle rather
    // than refilling at once. DOWN's round started at the loss, so the rest of UP's flight does
    // not end it.
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().round_start);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(1);
    assert!(sim.bbr().round_start);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    sim.send(1);
    sim.now = refill;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    sim.send(60);
    sim.now += 20 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    // The next probe has 70,800 bytes in flight before this ACK and 69,600 after it, both
    // above inflight_longterm, and goes on.
    sim.ack(1);
    assert_eq!(sim.inflight(), 58 * MSS);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
}
