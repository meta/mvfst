/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The spurious undo, which works per loss episode.

use super::*;

/// Moves `sim` to CRUISE at 1 MB/s with an empty pipe, sends 30 packets at once and acknowledges
/// the first of them 20 ms later, at a loss round start, with a sample of `bw`. Returns cwnd.
fn cruise_with_flight(sim: &mut Sim, bw: u64) -> u64 {
    sim.to_probe_bw();
    sim.ack(29);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    sim.send(30);
    sim.now += 20 * MS;
    sim.bw = bw;
    sim.ack(1);
    assert!(sim.bbr().loss_round_start);
    sim.cc.cwnd()
}

#[test]
fn an_episode_is_undone_once_every_loss_in_it_is_acknowledged_as_spurious() {
    let mut sim = Sim::new();
    let cwnd = cruise_with_flight(&mut sim, 500_000);
    // One loss event of two packets opens the episode. The loss round it starts, at
    // 500 kB/s, lowers the short-term model at its end.
    sim.event(2, 1, 0, false);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().bw_shortterm, Some(700_000));
    let lowered = sim.cc.cwnd();
    assert!(lowered < cwnd, "{lowered}");
    // One of the two acknowledged as spurious is not enough.
    sim.event(0, 0, 1, false);
    assert_eq!(sim.cc.cwnd(), lowered);
    assert_eq!(sim.bbr().bw_shortterm, Some(700_000));
    // The second undoes the episode, in a frame that does not acknowledge anything else: cwnd, the
    // bounds and the pacing rate return.
    sim.event(0, 0, 1, false);
    assert_eq!(sim.cc.cwnd(), cwnd);
    assert_eq!(sim.bbr().bw_shortterm, None);
    assert_eq!(sim.bbr().inflight_shortterm, None);
    assert_eq!(sim.rate(), 1_000_000);
}

#[test]
fn the_undo_ends_recovery_forgets_the_rounds_losses_and_restarts_the_full_bw_check() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 500_000);
    sim.event(1, 1, 0, false);
    assert!(sim.bbr().in_recovery);
    sim.event(0, 0, 1, false);
    assert!(!sim.bbr().in_recovery);
    assert_eq!(sim.bbr().bytes_lost_in_round, 0);
    assert_eq!(sim.bbr().losses_in_round.count, 0);
    assert_eq!(sim.bbr().losses_in_loss_round.count, 0);
    assert_eq!((sim.bbr().full_bw, sim.bbr().full_bw_count), (0, 0));
    // The loss round ends at 500 kB/s without lowering the short-term model.
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert!(sim.bbr().loss_round_start);
    assert_eq!(sim.bbr().bw_shortterm, None);
}

#[test]
fn persistent_congestion_ends_the_episode() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.event(1, 0, 0, true);
    let cwnd = sim.cc.cwnd();
    assert_eq!(cwnd, 4 * MSS);
    sim.event(0, 0, 1, false);
    assert_eq!(sim.cc.cwnd(), cwnd);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn a_loss_outside_the_episode_ends_it() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.lose(1);
    // A packet sent to the alternate path's address is declared lost: it counts as declared but
    // lacks a LostSample, so it does not join the episode.
    sim.declared += 1;
    sim.cc.on_ack_or_loss(&AckOrLoss {
        now: sim.now,
        ack: None,
        delivered: sim.delivered,
        total_sent: sim.total_sent,
        bytes_in_flight: sim.inflight(),
        lost: &[],
        largest_lost_sent: None,
        persistent_congestion: false,
        spurious: 0,
        newly_lost: 1,
        declared_lost: sim.declared,
    });
    // The episode's own loss acknowledged as spurious no longer undoes it.
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn a_later_loss_of_a_packet_sent_before_the_episode_began_joins_it() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.lose(1);
    sim.event(1, 1, 0, false);
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().in_recovery);
    sim.event(0, 0, 1, false);
    assert!(!sim.bbr().in_recovery);
}

#[test]
fn the_episode_begins_at_the_newest_send_not_at_the_lost_packets_send() {
    // From CRUISE with an empty pipe, one packet goes out, then another 10 ms later. The first
    // is lost, which opens the episode at the second's send time, so the second's loss joins it.
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.ack(29);
    sim.send(1);
    sim.now += 10 * MS;
    sim.send(1);
    sim.now += 20 * MS;
    sim.lose(1);
    sim.lose(1);
    sim.event(0, 0, 2, false);
    assert!(!sim.bbr().in_recovery);
}

#[test]
fn a_loss_of_a_packet_sent_after_the_episode_began_ends_it() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.lose(1);
    sim.send(1);
    sim.ack(sim.flight.len() - 1);
    sim.lose(1);
    sim.event(0, 0, 2, false);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn no_episode_opens_while_another_declared_loss_is_pending() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    // A loss whose recovery and loss round end, while it stays declared.
    sim.event(1, 1, 0, false);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().in_recovery && !sim.bbr().loss_in_round);
    sim.send(2);
    sim.now += 20 * MS;
    sim.lose(1);
    // The older lost packet leaves the declared-lost count, then the newer one is acknowledged
    // as spurious.
    sim.declared -= 1;
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn no_episode_opens_in_recovery() {
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    // A loss whose loss round ends at a packet sent at the same instant as the newest send
    // before it, which does not end recovery. Its lost packet leaves the declared-lost count,
    // which ends its episode.
    sim.send(1);
    sim.lose(1);
    sim.send(1);
    sim.declared -= 1;
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert!(sim.bbr().in_recovery && !sim.bbr().loss_in_round);
    sim.send(2);
    sim.now += 20 * MS;
    sim.lose(1);
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn no_episode_opens_after_a_loss_in_the_loss_round() {
    // Set by hand: the events in these tests set loss_in_round only together with recovery.
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.bbr_mut().loss_in_round = true;
    sim.lose(1);
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().in_recovery);
}

#[test]
fn undoing_the_episode_that_ended_startup_returns_to_startup() {
    // Startup ends on loss, in an episode of six lost packets, and the empty pipe takes Drain
    // on to ProbeBW at once.
    let mut sim = loss_round(40, &[1; 6]);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    // As if REFILL had begun a probe by then.
    sim.bbr_mut().check_probe_loss = true;
    sim.event(0, 0, 6, false);
    assert_eq!(sim.bbr().state, State::Startup);
    assert!(!sim.bbr().full_bw_reached);
    assert!(!sim.bbr().check_probe_loss);
    assert_eq!(sim.bbr().inflight_longterm, None);
    assert_eq!(sim.rate(), 2_770_000);
    // The send quantum follows the rate: 1 ms of it.
    assert_eq!(sim.bbr().send_quantum, 2770);
}

#[test]
fn undoing_the_episode_that_ended_startup_in_probe_rtt_stays_in_probe_rtt() {
    // As above, with a packet left in flight whose ACK 10 s later, past min_rtt's 10 s, enters
    // ProbeRTT.
    let mut sim = loss_round(40, &[1; 6]);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len() - 1);
    assert!(sim.bbr().full_bw_reached);
    sim.now += Duration::from_secs(10);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    let cwnd = sim.cc.cwnd();
    sim.event(0, 0, 6, false);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    // ProbeRTT then returns to Startup.
    assert!(!sim.bbr().full_bw_reached);
    // ProbeRTT's cap still holds over the episode's cwnd.
    assert_eq!(sim.cc.cwnd(), cwnd);
}

/// Returns a sender whose UP at 1 MB/s and 20 ms ended on loss in an episode of three lost packets,
/// as in the first loss exit test, with six packets still in flight.
fn up_ended_on_loss() -> Sim {
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    sim.now += 20 * MS;
    sim.ack(1);
    sim.send(60);
    sim.now += 20 * MS;
    sim.ack(50);
    sim.event(2, 1, 0, false);
    sim.event(1, 0, 0, false);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert_eq!(sim.bbr().inflight_longterm, Some(63_600));
    sim
}

#[test]
fn undoing_the_episode_that_ended_up_refills_for_a_new_probe() {
    let mut sim = up_ended_on_loss();
    sim.event(0, 0, 3, false);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    assert_eq!(sim.bbr().inflight_longterm, None);
    // REFILL's round starts at the undo, so a packet sent before it does not end the round.
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
}

#[test]
fn undoing_the_episode_that_ended_up_in_probe_rtt_stays_in_probe_rtt() {
    let mut sim = up_ended_on_loss();
    sim.now += Duration::from_secs(10);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
    sim.event(0, 0, 3, false);
    assert_eq!(sim.bbr().state, State::ProbeRtt);
}

#[test]
fn undoing_the_episode_that_ended_up_in_the_next_up_goes_on_probing() {
    let mut sim = up_ended_on_loss();
    let refill = sim.now + sim.bbr().bw_probe_wait + MS;
    sim.ack(sim.flight.len());
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    sim.send(1);
    sim.now = refill;
    sim.ack(1);
    sim.send(2);
    sim.now += 20 * MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    sim.event(0, 0, 3, false);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
}

#[test]
fn the_undo_clears_the_uncapped_mark_only_if_it_changes_inflight_longterm() {
    // Packets sent under the cap the undo lifts may raise inflight_longterm again.
    let mut sim = up_ended_on_loss();
    assert!(sim.bbr().uncapped_sent.is_some());
    sim.event(0, 0, 3, false);
    assert_eq!(sim.bbr().uncapped_sent, None);
    // An undo that leaves inflight_longterm unset keeps the mark from Drain.
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    let mark = sim.bbr().uncapped_sent;
    assert!(mark.is_some());
    sim.lose(1);
    sim.event(0, 0, 1, false);
    assert!(!sim.bbr().in_recovery);
    assert_eq!(sim.bbr().uncapped_sent, mark);
}

#[test]
fn the_undo_raises_the_bounds_to_their_values_at_the_loss_but_never_lowers_them() {
    // inflight_longterm is 10,000 bytes at the loss, then a sample raises it to 24,000.
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.bbr_mut().inflight_longterm = Some(10_000);
    sim.event(1, 18, 0, false);
    assert_eq!(sim.bbr().inflight_longterm, Some(20 * MSS));
    sim.event(0, 0, 1, false);
    assert!(!sim.bbr().in_recovery);
    assert_eq!(sim.bbr().inflight_longterm, Some(20 * MSS));
    // CRUISE's cap still holds over the episode's cwnd: 24,000 less 15% of it.
    assert_eq!(sim.cc.cwnd(), 20_400);
}

#[test]
fn the_undo_never_lowers_the_short_term_bounds() {
    // The bounds are 500 kB/s and 12,000 bytes at the loss. Its loss round ends at 1 MB/s with
    // 34,800 bytes delivered, which raises both.
    let mut sim = Sim::new();
    cruise_with_flight(&mut sim, 1_000_000);
    sim.bbr_mut().bw_shortterm = Some(500_000);
    sim.bbr_mut().inflight_shortterm = Some(10 * MSS);
    sim.lose(1);
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().bw_shortterm, Some(1_000_000));
    assert_eq!(sim.bbr().inflight_shortterm, Some(29 * MSS));
    assert!(sim.bbr().loss_episode.is_some());
    sim.event(0, 0, 1, false);
    assert!(sim.bbr().loss_episode.is_none());
    assert_eq!(sim.bbr().bw_shortterm, Some(1_000_000));
    assert_eq!(sim.bbr().inflight_shortterm, Some(29 * MSS));
}
