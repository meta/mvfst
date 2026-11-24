/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::VecDeque;
use std::mem;
use std::time::Duration;
use std::time::Instant;

use super::*;
use crate::cc::AckPart;
use crate::cc::Cc;
use crate::cc::CcConfig;
use crate::cc::CongestionSignal;
use crate::config::CongestionControl;
use crate::recovery::Space;
use crate::recovery::loss::RateSample;
use crate::recovery::sent::LostSample;

mod loss;
mod probe_rtt;
mod undo;

const MSS: u64 = 1200;
const MS: Duration = Duration::from_millis(1);
/// The initial window: ten datagrams.
const IW: u64 = 10 * MSS;

/// An unacknowledged packet as the sender recorded it.
#[derive(Clone, Copy)]
struct Packet {
    pn: u64,
    sent: Instant,
    delivered: u64,
    lost: u64,
    total_sent: u64,
    tx_in_flight: u64,
    app_limited: bool,
}

/// A sender of full-size packets driving a BBR3 controller, whose rate samples carry `bw`.
struct Sim {
    cc: Cc,
    now: Instant,
    pn: u64,
    delivered: u64,
    lost: u64,
    total_sent: u64,
    declared: u32,
    flight: VecDeque<Packet>,
    bw: u64,
    app_limited: bool,
    /// RS.lost for the next rate sample, in place of the computed one.
    sample_lost: Option<u64>,
    /// Whether to leave the next ACK frame without an RTT sample, as when its largest acknowledged
    /// packet was acknowledged before.
    no_rtt_sample: bool,
}

impl Sim {
    fn new() -> Self {
        Self::start(CcConfig::default(), CcStart::default())
    }

    fn start(config: CcConfig, start: CcStart) -> Self {
        Self {
            cc: Cc::start(CongestionControl::Bbr3, &config, MSS as u16, &start).unwrap(),
            now: crate::recovery::test_epoch(),
            pn: 0,
            delivered: 0,
            lost: 0,
            total_sent: start.total_sent,
            declared: 0,
            flight: VecDeque::new(),
            bw: 1_000_000,
            app_limited: false,
            sample_lost: None,
            no_rtt_sample: false,
        }
    }

    fn bbr(&self) -> &Bbr3 {
        self.cc.bbr3()
    }

    fn bbr_mut(&mut self) -> &mut Bbr3 {
        match &mut self.cc {
            Cc::Bbr3(b) => b,
            _ => unreachable!(),
        }
    }

    /// Sends one packet, app-limited if `app_limited`, and acknowledges everything with a
    /// sample of `bw` from it.
    fn sample(&mut self, bw: u64, app_limited: bool) {
        (self.bw, self.app_limited) = (bw, app_limited);
        self.send(1);
        self.ack(self.flight.len());
        self.app_limited = false;
    }

    fn rate(&self) -> u64 {
        self.cc.pacing_rate(Duration::ZERO).get()
    }

    fn inflight(&self) -> u64 {
        self.flight.len() as u64 * MSS
    }

    /// Sends `n` packets now.
    fn send(&mut self, n: usize) {
        for _ in 0..n {
            let before = self.inflight();
            self.total_sent += MSS;
            self.cc.on_sent(&SentEvent {
                time_sent: self.now,
                bytes_in_flight: before,
                size: MSS as u16,
                total_sent: self.total_sent,
                on_path: true,
            });
            self.flight.push_back(Packet {
                pn: self.pn,
                sent: self.now,
                delivered: self.delivered,
                lost: self.lost,
                total_sent: self.total_sent,
                tx_in_flight: before + MSS,
                app_limited: self.app_limited,
            });
            self.pn += 1;
        }
    }

    /// Acknowledges the `n` oldest packets in one ACK frame.
    fn ack(&mut self, n: usize) -> bool {
        self.event(0, n, 0, false)
    }

    /// Declares the `n` oldest packets lost in a loss timeout.
    fn lose(&mut self, n: usize) -> bool {
        self.event(n, 0, 0, false)
    }

    /// Declares the `lost` oldest packets lost and acknowledges the `acked` next ones, with
    /// `spurious` earlier losses, in one ACK frame, or in a loss timeout if `acked` and `spurious`
    /// are 0. Returns whether to mark the connection app-limited.
    fn event(&mut self, lost: usize, acked: usize, spurious: u32, persistent: bool) -> bool {
        let lost: Vec<Packet> = self.flight.drain(..lost).collect();
        let samples: Vec<LostSample> = lost
            .iter()
            .map(|p| LostSample {
                size: MSS as u16,
                pn: p.pn,
                space: Space::Data,
                tx_in_flight: p.tx_in_flight,
                is_app_limited: p.app_limited,
            })
            .collect();
        self.lost += MSS * lost.len() as u64;
        self.declared = self.declared + lost.len() as u32 - spurious;
        let newest = self.flight.drain(..acked).next_back();
        self.delivered += MSS * acked as u64;
        let rate = newest.map(|p| {
            let delivered = self.delivered - p.delivered;
            RateSample {
                prior_delivered: p.delivered,
                delivered,
                interval: Duration::from_nanos(delivered * 1_000_000_000 / self.bw),
                delivery_rate: self.bw,
                is_app_limited: p.app_limited,
                tx_in_flight: p.tx_in_flight,
                lost: self.sample_lost.take().unwrap_or(self.lost - p.lost),
                total_sent: p.total_sent,
            }
        });
        let no_rtt_sample = mem::take(&mut self.no_rtt_sample);
        let ack = (acked > 0 || spurious > 0).then(|| AckPart {
            acked_bytes: MSS * acked as u64,
            largest_acked_sent: newest.map(|p| p.sent),
            rtt_sample: newest.filter(|_| !no_rtt_sample).map(|p| self.now - p.sent),
            rate,
        });
        self.cc.on_ack_or_loss(&AckOrLoss {
            now: self.now,
            ack,
            delivered: self.delivered,
            total_sent: self.total_sent,
            bytes_in_flight: self.inflight(),
            lost: &samples,
            largest_lost_sent: lost.last().map(|p| p.sent),
            persistent_congestion: persistent,
            spurious,
            newly_lost: lost.len() as u32,
            declared_lost: self.declared,
        })
    }

    /// Sends `n` packets and acknowledges them all in one ACK frame `rtt` later.
    fn round(&mut self, n: usize, rtt: Duration) {
        self.send(n);
        self.now += rtt;
        self.ack(n);
    }

    /// Fills the pipe at 1 MB/s with a 20 ms RTT, a BDP of 20,000 bytes, and enters Drain at a
    /// round start with 30 packets in flight.
    fn to_drain(&mut self) {
        self.bw = 1_000_000;
        for _ in 0..3 {
            self.round(10, 20 * MS);
        }
        self.send(40);
        self.now += 20 * MS;
        self.ack(10);
        assert_eq!(self.bbr().state, State::Drain);
    }

    /// Continues [`Sim::to_drain`] with three rounds that keep 29 packets in flight and end Drain.
    fn to_probe_bw(&mut self) {
        self.to_drain();
        for _ in 0..3 {
            self.send(30);
            self.now += 20 * MS;
            self.ack(self.flight.len() - 29);
        }
        assert_eq!(self.bbr().state, State::ProbeBwDown);
    }

    /// Continues [`Sim::to_probe_bw`] through CRUISE, REFILL once the probe wait has passed, and
    /// UP at the next round start, 20 ms later, with one packet left in flight.
    fn to_probe_bw_up(&mut self) {
        self.to_probe_bw();
        let refill = self.now + self.bbr().bw_probe_wait + MS;
        self.ack(13);
        assert_eq!(self.bbr().state, State::ProbeBwCruise);
        self.now = refill;
        self.ack(1);
        assert_eq!(self.bbr().state, State::ProbeBwRefill);
        self.send(2);
        self.now += 20 * MS;
        self.ack(self.flight.len() - 1);
        assert_eq!(self.bbr().state, State::ProbeBwUp);
    }
}

/// Returns a controller in UP at 1.25 * 1 MB/s whose pipe has just emptied, and when it emptied.
pub(crate) fn up_and_idle() -> (Cc, Instant) {
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    sim.now += 20 * MS;
    sim.ack(1);
    (sim.cc, sim.now)
}

/// Runs [`up_and_idle`], then sets a bandwidth estimate of `bw` bytes per second and a window of
/// `cwnd` bytes: UP paces at 1.25 * `bw`, and a restart from idle at `bw`.
pub(crate) fn up_and_idle_at(bw: u64, cwnd: u64) -> (Cc, Instant) {
    let (mut cc, idle) = up_and_idle();
    let Cc::Bbr3(bbr) = &mut cc else {
        unreachable!("up_and_idle gives a BBR3 controller")
    };
    bbr.bw = bw;
    bbr.pacing_rate = gain(bw, PROBE_BW_UP_PACING_GAIN);
    bbr.window.cwnd = cwnd;
    (cc, idle)
}

#[test]
fn starts_in_startup_with_the_initial_window_paced_at_2_77_times_it_per_srtt_or_1ms() {
    let sim = Sim::new();
    assert_eq!(sim.bbr().state, State::Startup);
    assert_eq!(sim.cc.cwnd(), IW);
    assert_eq!(sim.rate(), IW * 277 * 1000 / 100);
    // The path's smoothed RTT counts once it has an RTT sample.
    let start = CcStart {
        srtt: Some(40 * MS),
        ..CcStart::default()
    };
    let sim = Sim::start(CcConfig::default(), start);
    assert_eq!(sim.rate(), IW * 277 * 25 / 100);
    assert_eq!(sim.cc.ssthresh(), u64::MAX);
}

#[test]
fn the_initial_pacing_rate_is_set_again_from_the_first_min_rtt() {
    // Without an RTT sample the initial rate uses 1 ms; the first sample sets it again from
    // 100 ms, even though that lowers it. The bandwidth is too low to matter.
    let mut sim = Sim::new();
    sim.bw = 1000;
    sim.round(1, 100 * MS);
    assert_eq!(sim.rate(), IW * 277 * 10 / 100);
    // Only once.
    sim.round(1, 50 * MS);
    assert_eq!(sim.rate(), IW * 277 * 10 / 100);
}

#[test]
fn startup_raises_the_pacing_rate_to_2_77_bw_and_never_lowers_it() {
    // The rate is not discounted by a pacing margin, and before full_bw_reached it only rises.
    let start = CcStart {
        srtt: Some(10 * MS),
        ..CcStart::default()
    };
    let mut sim = Sim::start(CcConfig::default(), start);
    let initial = sim.rate();
    sim.bw = 1_000_000;
    sim.round(1, 10 * MS);
    assert_eq!(sim.rate(), initial, "2.77 * bw is lower");
    sim.bw = 2_000_000;
    sim.round(1, 10 * MS);
    assert_eq!(sim.rate(), 5_540_000);
}

#[test]
fn startup_grows_cwnd_by_the_newly_acked_bytes_below_max_inflight_or_the_initial_window() {
    // A BDP of 2,400 bytes at 120 kB/s and 20 ms: max_inflight is the budget of three 2-MSS
    // send quanta, below cwnd, but C.delivered is still below InitialCwnd.
    let mut sim = Sim::new();
    sim.bw = 120_000;
    sim.send(10);
    sim.now += 20 * MS;
    sim.ack(2);
    assert_eq!(sim.cc.cwnd(), IW + 2 * MSS);
    sim.ack(8);
    assert_eq!(sim.cc.cwnd(), IW + 2 * MSS);
    // A BDP of 24,000 bytes: max_inflight is twice that.
    sim.bw = 1_200_000;
    sim.round(12, 20 * MS);
    assert_eq!(sim.cc.cwnd(), 24 * MSS);
    sim.round(24, 20 * MS);
    assert_eq!(sim.cc.cwnd(), 48 * MSS);
    sim.round(48, 20 * MS);
    assert_eq!(sim.cc.cwnd(), 48 * MSS, "at or above max_inflight");
}

#[test]
fn startup_ends_after_three_rounds_without_25_percent_growth_of_max_bw() {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    sim.round(10, 20 * MS);
    // A mid-round sample 25% higher raises max_bw, which the next round start compares,
    // although that round's own sample is lower.
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(10);
    sim.bw = 1_250_000;
    sim.ack(10);
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    assert_eq!(sim.bbr().state, State::Startup);
    // App-limited rounds do not count.
    sim.app_limited = true;
    sim.round(10, 20 * MS);
    sim.app_limited = false;
    sim.round(10, 20 * MS);
    sim.round(10, 20 * MS);
    assert_eq!(sim.bbr().state, State::Startup);
    sim.round(10, 20 * MS);
    // Drain, which ends at once with an empty pipe, and DOWN too.
    assert!(sim.bbr().full_bw_reached);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn drain_ends_after_three_full_rounds_or_at_inflight_1() {
    // Drain entered at a round start ends when round_count reaches its start + 3.
    let mut sim = Sim::new();
    sim.to_drain();
    let start = sim.bbr().round_count;
    // Each round acknowledges the previous flight and one packet of a new one, keeping 29
    // packets in flight, above Inflight(1.0) = 20,000 bytes, as `Sim::to_probe_bw` does.
    for round in 1..=3 {
        sim.send(30);
        sim.now += 20 * MS;
        let n = sim.flight.len() - 29;
        sim.ack(n);
        assert_eq!(sim.bbr().round_count, start + round);
        let expected = if round < 3 {
            State::Drain
        } else {
            State::ProbeBwDown
        };
        assert_eq!(sim.bbr().state, expected, "round {round}");
    }
    // Or once inflight is at most Inflight(1.0).
    let mut sim = Sim::new();
    sim.to_drain();
    sim.ack(13);
    assert_eq!(sim.bbr().state, State::Drain);
    sim.ack(1);
    assert_eq!(sim.inflight(), 16 * MSS);
    // DOWN, which ends at once at that inflight.
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn probe_bw_cycles_down_cruise_refill_up_with_a_probe_wait_of_2_to_3_seconds() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    let down = sim.now;
    let wait = sim.bbr().bw_probe_wait;
    // 2 s plus a whole number of milliseconds below 1,000, without a Reno bound.
    let in_range = |wait: Duration| {
        wait >= 2000 * MS && wait < 3000 * MS && wait.subsec_nanos().is_multiple_of(1_000_000)
    };
    assert!(in_range(wait), "{wait:?}");
    // CRUISE once inflight is at most Inflight(max_bw, 1.0), 20,000 bytes.
    sim.ack(12);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    // REFILL once the wait has passed.
    sim.now = down + wait;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
    sim.now += MS;
    sim.ack(1);
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    // UP at the next round start. The plateau check starts from max_bw, not from this ACK's
    // lower sample.
    sim.send(1);
    sim.bw = 800_000;
    sim.ack(sim.flight.len());
    sim.bw = 1_000_000;
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    assert!(sim.bbr().check_probe_loss);
    assert_eq!(sim.bbr().full_bw, 1_000_000);
    // DOWN again after three rounds without growth of max_bw, with a new wait.
    sim.round(10, 20 * MS);
    sim.round(10, 20 * MS);
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    let cycle = sim.bbr().cycle_count;
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(10);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    assert!(in_range(sim.bbr().bw_probe_wait));
    // The probe's samples end at the next round start, which ends the cycle.
    assert_eq!(sim.bbr().cycle_count, cycle);
    sim.send(1);
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().cycle_count, cycle + 1);
    // The wait is reproducible from the seed.
    let waits: Vec<Duration> = (0..4)
        .map(|seed| {
            let mut sim = Sim::start(
                CcConfig::default(),
                CcStart {
                    seed,
                    ..CcStart::default()
                },
            );
            sim.to_probe_bw();
            sim.bbr().bw_probe_wait
        })
        .collect();
    assert_eq!(waits[0], wait);
    assert!(waits.iter().any(|w| *w != wait), "{waits:?}");
}

#[test]
fn down_cruises_once_inflight_is_at_most_the_bdp_with_its_quantization_budget() {
    // At 100 kB/s and 20 ms the BDP is 2,000 bytes, so Inflight(max_bw, 1.0) is the quantization
    // budget, three 2-MSS send quanta or 7,200 bytes.
    let mut sim = Sim::new();
    sim.bw = 100_000;
    for _ in 0..3 {
        sim.round(10, 20 * MS);
    }
    // Startup ends at the next round start, and Drain three rounds later, ten packets staying
    // in flight.
    sim.send(20);
    sim.now += 20 * MS;
    sim.ack(10);
    assert_eq!(sim.bbr().state, State::Drain);
    for _ in 0..3 {
        sim.send(11);
        sim.now += 20 * MS;
        sim.ack(sim.flight.len() - 10);
    }
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    sim.ack(3);
    assert_eq!(sim.inflight(), 7 * MSS);
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
    sim.ack(2);
    assert_eq!(sim.bbr().state, State::ProbeBwCruise);
}

#[test]
fn the_send_quantum_follows_the_granularity_and_the_offload_budget_adds_rate_times_horizon() {
    // At 100 kB/s the BDP is too small to matter, and the rate stays the initial one,
    // 2.77 * InitialCwnd per min_rtt.
    for (rtt, granularity, horizon, rate, quantum) in [
        (10u32, MS, 0u32, 3_324_000u64, 3_324u64),
        (10, 2 * MS, 0, 3_324_000, 6_648),
        (10, 30 * MS, 0, 3_324_000, 65_536),
        (20, MS, 0, 1_662_000, 2 * MSS),
        (10, 2 * MS, 5, 3_324_000, 6_648),
    ] {
        let start = CcStart {
            pacing_granularity: granularity,
            horizon: horizon * MS,
            ..CcStart::default()
        };
        let mut sim = Sim::start(CcConfig::default(), start);
        sim.bw = 100_000;
        sim.round(1, rtt * MS);
        assert_eq!(sim.rate(), rate);
        // The send quantum is clamp(pacing_rate * granularity, 2 MSS, 64 KiB).
        assert_eq!(sim.bbr().send_quantum, quantum, "{granularity:?}");
        // The offload budget is three quanta plus pacing_rate * horizon.
        let budget = 3 * quantum + rate * u64::from(horizon) / 1000;
        assert_eq!(sim.bbr().max_inflight(), budget, "{horizon} ms");
    }
}

#[test]
fn the_offload_budget_saturates_at_any_rate_and_horizon() {
    // In UP, where the budget also gains two datagrams.
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    let bbr = sim.bbr_mut();
    bbr.pacing_rate = u64::MAX;
    bbr.horizon = Duration::from_secs(16);
    assert_eq!(sim.bbr().offload_budget(), u64::MAX);
    assert_eq!(sim.bbr().max_inflight(), u64::MAX);
}

#[test]
fn pacing_waits_for_a_control_update_after_the_initial_window_is_sent() {
    // The initial window goes out unpaced.
    let mut sim = Sim::new();
    sim.send(5);
    sim.ack(1);
    assert!(
        !sim.cc.pacing_ready(),
        "a control update before InitialCwnd is sent"
    );
    sim.send(6);
    assert_eq!(sim.total_sent, IW + MSS);
    assert!(!sim.cc.pacing_ready(), "no control update yet");
    sim.ack(1);
    assert!(sim.cc.pacing_ready());
}

#[test]
fn an_app_limited_sample_enters_max_bw_only_above_it() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    assert_eq!(sim.bbr().cycle_count, 1);
    // An app-limited sample equal to max_bw does not enter the filter, so it does not keep
    // max_bw for another cycle.
    sim.sample(1_000_000, true);
    sim.sample(800_000, false);
    assert_eq!(sim.bbr().bw, 1_000_000);
    sim.bbr_mut().cycle_count = 2;
    sim.sample(800_000, false);
    assert_eq!(sim.bbr().bw, 800_000);
    sim.sample(900_000, true);
    assert_eq!(sim.bbr().bw, 900_000);
}

#[test]
fn extra_acked_joins_max_inflight_once_the_pipe_is_full() {
    // A first ACK of 10 packets has all its bytes in excess of bw * interval.
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    assert_eq!(sim.bbr().extra_acked, 10 * MSS);
    // It stays out of max_inflight in Startup, where max_inflight is twice the 20,000-byte BDP.
    assert_eq!(sim.bbr().max_inflight(), 40_000);
    // Startup's filter keeps only the current round.
    sim.round(1, 20 * MS);
    assert_eq!(sim.bbr().extra_acked, MSS);
    // Once the pipe is full, it joins max_inflight and lasts ten rounds.
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.ack(20);
    let extra = sim.bbr().extra_acked;
    assert!(extra >= 20 * MSS, "{extra}");
    assert_eq!(sim.bbr().max_inflight(), 40_000 + extra);
    sim.round(9, 20 * MS);
    assert_eq!(sim.bbr().extra_acked, extra);
}

#[test]
fn once_the_pipe_is_full_cwnd_follows_max_inflight_and_the_rate_is_gain_times_bw() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    // Exactly gain * bw, here DOWN's 0.9, though lower than before.
    assert_eq!(sim.rate(), 900_000);
    sim.bbr_mut().window.cwnd = 100 * MSS;
    sim.ack(1);
    let max_inflight = sim.bbr().max_inflight();
    assert_eq!(sim.cc.cwnd(), max_inflight);
    sim.bbr_mut().window.cwnd = max_inflight - 2 * MSS;
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), max_inflight - MSS);
}

#[test]
fn persistent_congestion_drops_cwnd_to_4_mss_and_ending_recovery_restores_it() {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    let cwnd = sim.cc.cwnd();
    sim.send(10);
    let sent = sim.now;
    sim.now += 100 * MS;
    sim.event(5, 0, 0, true);
    // MinPipeCwnd, not inflight plus a packet.
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
    // Recovery starts at the newest send and each loss moves it there.
    assert!(sim.cc.in_recovery(sent));
    sim.send(1);
    assert!(!sim.cc.in_recovery(sim.now));
    sim.lose(1);
    assert!(sim.cc.in_recovery(sim.now));
    // An ACK of a packet sent no later than that does not end it, though cwnd grows; a later
    // one ends it and restores cwnd, which then grows by the ACK.
    sim.ack(4);
    assert!(sim.cc.in_recovery(sent));
    assert_eq!(sim.cc.cwnd(), 8 * MSS);
    sim.now += MS;
    sim.send(1);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert!(!sim.cc.in_recovery(sent));
    assert_eq!(sim.cc.cwnd(), cwnd + 2 * MSS);
}

/// Returns a sender in Startup at 1 MB/s that sent `flight` packets at once, with a loss round
/// among them whose losses are runs of consecutive packets, of the lengths in `runs`: the first
/// run, a packet sent after it, then the other runs, each in an ACK of the packet after it.
fn loss_round(flight: usize, runs: &[usize]) -> Sim {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    sim.send(flight);
    sim.now += 20 * MS;
    sim.event(runs[0], 1, 0, false);
    sim.send(1);
    for &run in &runs[1..] {
        sim.event(run, 1, 0, false);
    }
    sim
}

#[test]
fn startup_ends_on_more_than_2_percent_loss_with_6_loss_events_in_recovery() {
    // The loss round ends at the ACK of the packet sent after its first loss; the five losses
    // since are 10% of its tx_in_flight.
    let mut sim = loss_round(40, &[1; 5]);
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().full_bw_reached, "five loss events");
    let mut sim = loss_round(40, &[1; 6]);
    assert!(sim.cc.in_recovery(sim.now));
    sim.ack(sim.flight.len());
    assert!(sim.bbr().full_bw_reached);
    assert_ne!(sim.bbr().state, State::Startup);
    let longterm = sim
        .bbr()
        .bdp_multiple(1_000_000, 100)
        .max(sim.bbr().inflight_latest);
    assert_eq!(sim.bbr().inflight_longterm, Some(longterm));
    // The check comes before the ACK ends recovery. A packet sent after the losses ends it;
    // its sample is given the losses' bytes, as if they counted.
    let mut sim = loss_round(40, &[1; 6]);
    sim.now += MS;
    sim.send(1);
    sim.sample_lost = Some(6 * MSS);
    sim.ack(sim.flight.len());
    assert!(!sim.cc.in_recovery(sim.now - MS));
    assert!(sim.bbr().full_bw_reached);
}

#[test]
fn a_run_of_consecutive_lost_packets_in_one_space_is_one_loss_event() {
    // Seven lost packets in five runs are five loss events, too few to end Startup, though
    // their bytes are far above 2%; in six runs they end it.
    let mut sim = loss_round(40, &[1, 2, 1, 2, 1]);
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().full_bw_reached, "five runs");
    let mut sim = loss_round(40, &[1, 2, 1, 2, 1, 1]);
    sim.ack(sim.flight.len());
    assert!(sim.bbr().full_bw_reached, "six runs");
    // Packet numbers in another space do not join a run, and one not lost, such as that of an
    // ACK-only packet, ends it: Data 5 and 6 are one event, Handshake 6 another, Data 8 a third.
    let mut events = LossEvents::default();
    for (space, pn) in [
        (Space::Data, 5),
        (Space::Handshake, 6),
        (Space::Data, 6),
        (Space::Data, 8),
    ] {
        events.add(&LostSample {
            size: MSS as u16,
            pn,
            space,
            tx_in_flight: 0,
            is_app_limited: false,
        });
    }
    assert_eq!(events.count, 3);
}

#[test]
fn startup_needs_more_than_2_percent_of_the_bytes_in_flight_lost_to_end_on_loss() {
    // The packet that ends the loss round was sent with `flight - 1` packets in flight, and the
    // five losses after it are 6,000 bytes: more than 2% of 249 packets, exactly 2% of 250.
    let mut sim = loss_round(250, &[1; 6]);
    sim.ack(sim.flight.len());
    assert!(sim.bbr().full_bw_reached, "6,000 of 298,800 bytes");
    let mut sim = loss_round(251, &[1; 6]);
    sim.ack(sim.flight.len());
    assert!(!sim.bbr().full_bw_reached, "6,000 of 300,000 bytes");
}

#[test]
fn each_loss_round_starts_at_its_first_loss_and_counts_only_its_own_loss_events() {
    // Two loss rounds of three loss events each, both ending in recovery with more than 2%
    // lost, leave Startup alone; carried over, the count would reach six. A third loss round
    // with six ends Startup, since it starts at its first loss. Doubling bw at each round start
    // keeps the plateau check from ending Startup.
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    for (loss_round, events) in [(1, 3), (2, 3), (3, 6)] {
        sim.send(40);
        sim.now += 20 * MS;
        sim.bw *= 2;
        // The first loss starts the loss round, and the ACK of the packet sent after it ends it.
        sim.event(1, 1, 0, false);
        sim.send(1);
        for _ in 2..events {
            sim.event(1, 1, 0, false);
        }
        // A loss after a later send keeps recovery on past that ACK.
        sim.now += MS;
        sim.send(1);
        sim.event(1, 1, 0, false);
        sim.bw *= 2;
        sim.ack(sim.flight.len() - 1);
        assert!(sim.bbr().loss_round_start, "loss round {loss_round}");
        assert!(sim.cc.in_recovery(sim.now), "loss round {loss_round}");
        assert_eq!(
            sim.bbr().full_bw_reached,
            events == 6,
            "loss round {loss_round}"
        );
    }
}

#[test]
fn drain_entered_mid_round_counts_its_three_rounds_from_the_next_round_start() {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.send(10);
    sim.now += 20 * MS;
    // A round starts with the first ACK, and a loss round with the first loss, after it.
    sim.ack(1);
    sim.send(30);
    sim.ack(1);
    sim.lose(1);
    sim.send(20);
    sim.ack(7);
    sim.now += 20 * MS;
    // The next round starts with the first of five more losses, each its own run.
    for _ in 0..5 {
        sim.event(1, 1, 0, false);
    }
    let round = sim.bbr().round_count;
    // The first packet sent after the first loss ends the loss round, but this ACK does not
    // start a round: Startup's loss exit enters Drain mid-round, with 19 packets left in flight,
    // above Inflight(1.0) = 20,000 bytes.
    sim.ack(21);
    assert_eq!(sim.bbr().state, State::Drain);
    assert_eq!(sim.bbr().round_count, round);
    // The round under way does not count, so Drain lasts until the fourth round start.
    for n in 1..=4 {
        sim.send(30);
        sim.now += 20 * MS;
        let acked = sim.flight.len() - 29;
        sim.ack(acked);
        assert_eq!(sim.bbr().round_count, round + n);
        let expected = if n < 4 {
            State::Drain
        } else {
            State::ProbeBwDown
        };
        assert_eq!(sim.bbr().state, expected, "round {n}");
    }
}

#[test]
fn persistent_congestion_restarts_startups_plateau_count() {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    for _ in 0..3 {
        sim.round(10, 20 * MS);
    }
    assert_eq!(sim.bbr().full_bw_count, 2);
    sim.send(10);
    sim.now += 100 * MS;
    sim.event(5, 0, 0, true);
    // The full-bw check starts over, so one round sets full_bw again and three more without
    // growth fill the pipe.
    for round in 1..=3 {
        sim.round(10, 20 * MS);
        assert!(!sim.bbr().full_bw_reached, "round {round}");
    }
    sim.round(10, 20 * MS);
    assert!(sim.bbr().full_bw_reached);
}

#[test]
fn persistent_congestion_outside_a_probe_sets_an_unset_inflight_shortterm_to_the_larger_cwnd() {
    // In DOWN, inflight_shortterm becomes max(cwnd, prior_cwnd).
    let mut sim = Sim::new();
    sim.to_probe_bw();
    let cwnd = sim.cc.cwnd();
    sim.event(5, 0, 0, true);
    assert_eq!(sim.bbr().inflight_shortterm, Some(cwnd));
    // A bound already set stays.
    sim.bbr_mut().inflight_shortterm = Some(10 * MSS);
    sim.event(5, 0, 0, true);
    assert_eq!(sim.bbr().inflight_shortterm, Some(10 * MSS));
    // Still in recovery, prior_cwnd keeps the window before the first drop to MinPipeCwnd.
    sim.bbr_mut().inflight_shortterm = None;
    sim.event(5, 0, 0, true);
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
    assert_eq!(sim.bbr().inflight_shortterm, Some(cwnd));
    // Startup and UP probe, and leave it unset.
    let mut sim = Sim::new();
    sim.round(10, 20 * MS);
    sim.send(10);
    sim.event(5, 0, 0, true);
    assert_eq!(sim.bbr().inflight_shortterm, None);
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    sim.send(10);
    sim.event(5, 0, 0, true);
    assert_eq!(sim.bbr().inflight_shortterm, None);
}

#[test]
fn a_send_into_an_empty_pipe_restarts_probe_bw_at_bw_even_with_a_full_window() {
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    assert_eq!(sim.rate(), 1_250_000);
    // Only a send into an empty pipe restarts.
    sim.send(1);
    assert_eq!(sim.rate(), 1_250_000);
    sim.now += 20 * MS;
    sim.ack(sim.flight.len());
    assert_eq!(sim.bbr().state, State::ProbeBwUp);
    assert_eq!(sim.rate(), 1_250_000);
    // The sender has not marked itself app-limited, which the draft's restart requires.
    sim.send(1);
    assert_eq!(sim.rate(), 1_000_000);
}

#[test]
fn a_send_into_an_empty_pipe_restarts_the_ack_aggregation_interval_and_count() {
    let mut sim = Sim::new();
    sim.bw = 1_000_000;
    sim.round(10, 20 * MS);
    assert_eq!(sim.bbr().extra_acked_delivered, 10 * MSS);
    sim.now += 100 * MS;
    // The count of bytes delivered before the idle period is zeroed too, as in mvfst.
    sim.send(1);
    assert_eq!(sim.bbr().extra_acked_interval_start, Some(sim.now));
    assert_eq!(sim.bbr().extra_acked_delivered, 0);
}

#[test]
fn up_keeps_probing_while_inflight_longterm_limits_a_sender_that_fills_the_cwnd() {
    // inflight_longterm at the maximum window cannot grow, so it stays the limit.
    let config = CcConfig {
        max_window_packets: 100,
        ..CcConfig::default()
    };
    let mut sim = Sim::start(config, CcStart::default());
    sim.to_probe_bw_up();
    sim.now += 20 * MS;
    sim.ack(1);
    assert_eq!(sim.cc.cwnd(), 100 * MSS);
    sim.bbr_mut().inflight_longterm = Some(sim.cc.cwnd());
    // Each round the sender fills the cwnd, which is at inflight_longterm, restarts the
    // plateau check from max_bw, not from the samples' lower rate, so rounds without growth of
    // max_bw do not end UP.
    sim.bw = 900_000;
    for round in 1..=4 {
        let fill = sim.cc.cwnd().div_ceil(MSS) as usize;
        sim.round(fill, 20 * MS);
        assert_eq!(sim.bbr().state, State::ProbeBwUp, "round {round}");
        assert_eq!(sim.bbr().full_bw, 1_000_000);
    }
    // Three rounds that leave the cwnd unfilled do.
    for _ in 0..3 {
        sim.round(1, 20 * MS);
    }
    assert_eq!(sim.bbr().state, State::ProbeBwDown);
}

#[test]
fn up_adds_two_datagrams_to_the_quantization_budget() {
    let mut sim = Sim::new();
    sim.to_probe_bw_up();
    // 2.25 times the 20,000-byte BDP, plus extra_acked, plus two datagrams in UP only.
    let extra = sim.bbr().extra_acked;
    assert_eq!(sim.bbr().max_inflight(), 45_000 + extra + 2 * MSS);
    assert_eq!(sim.bbr().inflight(1_000_000, 100), 20_000 + 2 * MSS);
}

#[test]
fn a_new_datagram_size_moves_the_initial_window_the_minimum_and_the_maximum() {
    let config = CcConfig {
        max_window_packets: 20,
        ..CcConfig::default()
    };
    let mut sim = Sim::start(config, CcStart::default());
    sim.bw = 1_000_000;
    // InitialCwnd: a window still at it is recomputed, and pacing waits for its bytes.
    sim.cc.set_max_datagram_size(1452).unwrap();
    assert_eq!(sim.cc.cwnd(), 14_520);
    sim.round(12, 20 * MS);
    assert!(!sim.cc.pacing_ready(), "14,400 bytes sent");
    sim.round(1, 20 * MS);
    assert!(sim.cc.pacing_ready());
    // MinPipeCwnd: four datagrams of the size in use, which holds right after a change.
    sim.cc.set_max_datagram_size(1200).unwrap();
    sim.send(10);
    sim.event(5, 0, 0, true);
    assert_eq!(sim.cc.cwnd(), 4 * 1200);
    sim.cc.set_max_datagram_size(1452).unwrap();
    assert_eq!(sim.cc.cwnd(), 4 * 1452);
    // The clamp: twenty datagrams of the size in use.
    for _ in 0..3 {
        sim.round(40, 20 * MS);
    }
    assert_eq!(sim.cc.cwnd(), 20 * 1452);
}

#[test]
fn with_a_maximum_of_two_datagrams_cwnd_stays_at_four() {
    // The config accepts a maximum below MinPipeCwnd, and the floor wins without a panic.
    let config = CcConfig {
        max_window_packets: 2,
        ..CcConfig::default()
    };
    let mut sim = Sim::start(config, CcStart::default());
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
    sim.bw = 1_000_000;
    sim.round(4, 20 * MS);
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
    for size in [1452, 1200] {
        sim.cc.set_max_datagram_size(size).unwrap();
        assert_eq!(sim.cc.cwnd(), 4 * u64::from(size));
        sim.round(4, 20 * MS);
        assert_eq!(sim.cc.cwnd(), 4 * u64::from(size));
    }
    sim.send(4);
    sim.event(2, 0, 0, true);
    assert_eq!(sim.cc.cwnd(), 4 * MSS);
}

#[test]
fn a_ce_mark_changes_nothing() {
    // As in mvfst, BBR3 does not respond to ECN.
    let mut sim = Sim::new();
    sim.to_probe_bw();
    let before = format!("{:?}", sim.cc);
    let now = sim.now;
    sim.cc
        .on_congestion_event(now, now - 20 * MS, CongestionSignal::Ecn);
    assert_eq!(format!("{:?}", sim.cc), before);
}

#[test]
fn an_event_with_neither_a_newly_acknowledged_packet_nor_a_loss_only_resolves_the_episode() {
    let mut sim = Sim::new();
    sim.to_probe_bw();
    sim.lose(2);
    let before = format!("{:?}", sim.cc);
    // A frame that acknowledges only one of the two lost packets, late enough that an ACK would end
    // DOWN's probe wait. Only the episode's count of pending losses changes.
    sim.now += 3000 * MS;
    sim.event(0, 0, 1, false);
    assert_eq!(
        format!("{:?}", sim.cc),
        before.replace("pending: 2", "pending: 1")
    );
}
