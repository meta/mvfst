/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! CUBIC (RFC 9438) with fast convergence, the Reno-friendly region, application-limited
//! handling and undo of spurious reductions. Slow start is Reno's; HyStart++ is not implemented.

use std::time::Duration;
use std::time::Instant;

use super::AckEvent;
use super::CongestionSignal;
use super::CubicConfig;
use super::Window;

/// CUBIC.
#[derive(Clone, Debug)]
pub struct Cubic {
    pub(crate) window: Window,
    config: CubicConfig,
    /// W_max in bytes.
    w_max: f64,
    /// cwnd_prior in bytes.
    cwnd_prior: u64,
    /// K in seconds.
    k: f64,
    /// t_epoch, when the current congestion avoidance stage started; `None` until its first ACK.
    epoch: Option<Instant>,
    /// Growth below one byte, carried to the next ACK.
    carry: f64,
    /// W_est in bytes, the window Reno would have.
    w_est: f64,
    /// When the current application-limited period started.
    app_limited_since: Option<Instant>,
    last_sent: Option<Instant>,
    last_ack: Option<Instant>,
    /// Whether the next stage starts with K = 0 and W_max = cwnd, as after a timeout.
    flat_start: bool,
    /// The state before the reduction that began the current recovery period, restored if that
    /// period's losses prove spurious. Each new recovery period replaces or drops it.
    undo: Option<Undo>,
}

/// The variables saved before a reduction so that it can be undone (RFC 9438).
#[derive(Clone, Copy, Debug)]
struct Undo {
    cwnd: u64,
    ssthresh: u64,
    cwnd_prior: u64,
    w_max: f64,
    k: f64,
    epoch: Option<Instant>,
    w_est: f64,
}

impl Cubic {
    pub(crate) fn new(window: Window, config: CubicConfig) -> Self {
        Self {
            window,
            config,
            w_max: 0.0,
            cwnd_prior: 0,
            k: 0.0,
            epoch: None,
            carry: 0.0,
            w_est: 0.0,
            app_limited_since: None,
            last_sent: None,
            last_ack: None,
            flat_start: false,
            undo: None,
        }
    }

    pub(crate) fn on_sent(&mut self, now: Instant, bytes_in_flight: u64) {
        // Restarting after idle: the idle time is application-limited too (RFC 9438),
        // unless an application-limited ACK already paused the curve. Idle starts at the later
        // of the last send and the last ACK: while a flight was out the sender was not idle.
        if bytes_in_flight == 0
            && self.app_limited_since.is_none()
            && let Some(last) = self.last_sent.max(self.last_ack)
        {
            self.shift_epoch(now.saturating_duration_since(last), now);
        }
        self.last_sent = Some(now);
    }

    pub(crate) fn on_ack(&mut self, ack: &AckEvent) {
        self.last_ack = Some(ack.now);
        if self.window.in_recovery(ack.largest_acked_sent) {
            return;
        }
        // RFC 9438: the window does not grow while application-limited, and t excludes that time.
        if ack.app_limited {
            self.app_limited_since.get_or_insert(ack.now);
            return;
        }
        if let Some(since) = self.app_limited_since.take() {
            self.shift_epoch(ack.now.saturating_duration_since(since), ack.now);
        }
        let acked = self.window.slow_start(self.window.growth(ack));
        if acked > 0 {
            self.congestion_avoidance(ack.now, acked, ack.rtt);
        }
    }

    /// Grows the window, in bytes, for one ACK in congestion avoidance. In the Reno-friendly
    /// region, where W_cubic(t) < W_est, the window is W_est. Elsewhere it moves toward
    /// target = W_cubic(t + RTT), bounded to [cwnd, 1.5 * cwnd], by (target - cwnd) / cwnd per
    /// acknowledged byte, which is RFC 9438's per-segment increment scaled to bytes, so the
    /// window reaches the target after one RTT of acknowledgments however often the peer
    /// acknowledges.
    fn congestion_avoidance(&mut self, now: Instant, acked: u64, rtt: Duration) {
        let epoch = match self.epoch {
            Some(epoch) => epoch,
            None => self.start_epoch(now),
        };
        let cwnd = self.window.cwnd as f64;
        let t = now.saturating_duration_since(epoch).as_secs_f64();
        let mut reno_friendly = false;
        if self.config.reno_friendly {
            let beta = self.config.beta;
            let alpha = if self.w_est >= self.cwnd_prior as f64 {
                1.0
            } else {
                3.0 * (1.0 - beta) / (1.0 + beta)
            };
            self.w_est += alpha * acked as f64 * self.window.mss as f64 / cwnd;
            reno_friendly = self.w_cubic(t) < self.w_est;
        }
        let next = if reno_friendly {
            // The window never shrinks without a congestion event.
            (cwnd + self.carry).max(self.w_est)
        } else {
            let target = self.w_cubic(t + rtt.as_secs_f64()).clamp(cwnd, 1.5 * cwnd);
            cwnd + self.carry + (target - cwnd) * acked as f64 / cwnd
        };
        let grown = next.floor();
        self.carry = next - grown;
        self.window.cwnd = (grown as u64).min(self.window.max);
    }

    /// Moves t_epoch later by `pause`, never past `now`.
    fn shift_epoch(&mut self, pause: Duration, now: Instant) {
        if let Some(epoch) = &mut self.epoch {
            *epoch = (*epoch + pause).min(now);
        }
    }

    /// Starts a congestion avoidance stage at `now`: K = cbrt((W_max - cwnd) / (C * MSS)) seconds.
    fn start_epoch(&mut self, now: Instant) -> Instant {
        let cwnd = self.window.cwnd as f64;
        if self.flat_start {
            // RFC 9438: the first stage after a timeout has K = 0 and W_max = cwnd.
            self.flat_start = false;
            self.w_max = cwnd;
        }
        self.k = ((self.w_max - cwnd) / self.window.mss as f64 / self.config.c).cbrt();
        self.carry = 0.0;
        self.w_est = cwnd;
        self.epoch = Some(now);
        now
    }

    /// Returns W_cubic(t) = C * (t - K)^3 * MSS + W_max, in bytes.
    fn w_cubic(&self, t: f64) -> f64 {
        let d = t - self.k;
        self.config.c * (d * d * d) * self.window.mss as f64 + self.w_max
    }

    pub(crate) fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        signal: CongestionSignal,
    ) {
        // RFC 9438 allows undoing only a reduction caused by a loss later proved spurious. CE
        // marks are certain congestion, also inside a loss's recovery period.
        if signal == CongestionSignal::Ecn {
            self.undo = None;
        }
        let w = &mut self.window;
        if !w.enter_recovery(now, sent) {
            return;
        }
        if self.config.spurious_undo && signal == CongestionSignal::Loss {
            self.undo = Some(Undo {
                cwnd: w.cwnd,
                ssthresh: w.ssthresh,
                cwnd_prior: self.cwnd_prior,
                w_max: self.w_max,
                k: self.k,
                epoch: self.epoch,
                w_est: self.w_est,
            });
        }
        let cwnd = w.cwnd as f64;
        let beta = self.config.beta;
        // RFC 9438: a loss below the last W_max means the available bandwidth shrank.
        self.w_max = if self.config.fast_convergence && cwnd < self.w_max {
            cwnd * (1.0 + beta) / 2.0
        } else {
            cwnd
        };
        self.cwnd_prior = w.cwnd;
        // The reduction starts from cwnd rather than flight size, which RFC 9438 allows because
        // the window does not grow while the sender is application-limited. Rounded to the
        // nearest byte, since 84,000 * 0.7 is 58,799.99... in binary floating point.
        w.ssthresh = ((cwnd * beta).round() as u64).max(w.min);
        w.cwnd = w.ssthresh;
        self.epoch = None;
    }

    pub(crate) fn on_persistent_congestion(&mut self) {
        self.window.collapse();
        self.epoch = None;
        self.flat_start = true;
        self.undo = None;
    }

    /// Drops the state saved for undoing the last reduction.
    pub(crate) fn forget_undo(&mut self) {
        self.undo = None;
    }

    pub(crate) fn on_spurious_loss(&mut self, recovery_start: Instant) {
        // RFC 9438: restore only the reduction those losses caused, the one that began
        // the current recovery period, and only while the window is still below cwnd_prior.
        if self.window.recovery_start() == Some(recovery_start)
            && let Some(undo) = self.undo.take()
            && self.window.cwnd < self.cwnd_prior
        {
            self.window.cwnd = undo.cwnd;
            self.window.ssthresh = undo.ssthresh;
            self.cwnd_prior = undo.cwnd_prior;
            self.w_max = undo.w_max;
            self.k = undo.k;
            self.epoch = undo.epoch;
            self.w_est = undo.w_est;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::CcConfig;
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn cubic(config: &CcConfig) -> Cubic {
        Cubic::new(Window::new(config, 1200), config.cubic)
    }

    fn ack_at(c: &mut Cubic, now: Instant, acked_bytes: u64, rtt: Duration, sent: Instant) {
        c.on_ack(&AckEvent {
            now,
            acked_bytes,
            acked_in_recovery: 0,
            largest_acked_sent: sent,
            rtt,
            rtt_sample: Some(rtt),
            app_limited: false,
        });
    }

    /// Returns the defaults without the Reno-friendly region, so the window follows the curve.
    fn curve_only() -> CcConfig {
        let mut config = CcConfig::default();
        config.cubic.reno_friendly = false;
        config
    }

    /// Builds CUBIC grown to 100 datagrams in slow start, then reduced by a loss at 200 ms.
    fn reduced(config: &CcConfig, t0: Instant) -> Cubic {
        let mut c = cubic(config);
        ack_at(&mut c, t0 + 100 * MS, 108_000, 100 * MS, t0);
        assert_eq!(c.window.cwnd, 120_000);
        c.on_congestion_event(t0 + 200 * MS, t0 + 150 * MS, CongestionSignal::Loss);
        c
    }

    #[test]
    fn a_congestion_event_reduces_by_beta_and_remembers_w_max() {
        let t0 = crate::recovery::test_epoch();
        let c = reduced(&CcConfig::default(), t0);
        assert_eq!((c.window.cwnd, c.window.ssthresh), (84_000, 84_000));
        assert_eq!(c.w_max, 120_000.0);
        assert_eq!(c.cwnd_prior, 120_000);
    }

    #[test]
    fn fast_convergence_lowers_w_max_below_the_previous_one() {
        let t0 = crate::recovery::test_epoch();
        let mut c = reduced(&CcConfig::default(), t0);
        // A new loss at 84,000 bytes, below W_max: W_max = 84,000 * (1 + 0.7) / 2.
        c.on_congestion_event(t0 + 400 * MS, t0 + 300 * MS, CongestionSignal::Loss);
        assert_eq!(c.w_max, 71_400.0);
        assert_eq!((c.window.cwnd, c.window.ssthresh), (58_800, 58_800));
        assert_eq!(c.cwnd_prior, 84_000);

        let mut config = CcConfig::default();
        config.cubic.fast_convergence = false;
        let mut c = reduced(&config, t0);
        c.on_congestion_event(t0 + 400 * MS, t0 + 300 * MS, CongestionSignal::Loss);
        assert_eq!(c.w_max, 84_000.0);
    }

    #[test]
    fn congestion_avoidance_follows_the_cubic_curve_toward_w_max() {
        let t0 = crate::recovery::test_epoch();
        let mut c = reduced(&curve_only(), t0);
        let rtt = 100 * MS;
        let sent = t0 + 250 * MS;
        // The stage starts at 300 ms: K = cbrt((120,000 - 84,000) / 1,200 / 0.4) = cbrt(75)
        // = 4.2171633 s. target = W_cubic(0.1) = 0.4 * (0.1 - K)^3 * 1,200 + 120,000
        // = 86,500.716, so cwnd += (86,500.716 - 84,000) * 12,000 / 84,000 = 357.245.
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 84_357);
        // One second later: W_cubic(1.1) = 105,461.490, so cwnd += (105,461.490 - 84,357)
        // * 12,000 / 84,357 = 3,002.155, plus the 0.245 carried.
        ack_at(&mut c, t0 + 1300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 87_359);
        // Far along, W_cubic(10.1) = 212,824.8 exceeds 1.5 * cwnd: the target is capped at
        // 131,038.5 and cwnd grows by half the acknowledged bytes.
        ack_at(&mut c, t0 + 10_300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 93_359);
    }

    #[test]
    fn the_reno_friendly_region_keeps_up_with_reno() {
        let t0 = crate::recovery::test_epoch();
        let rtt = MS;
        let sent = t0 + 250 * MS;
        // With a 1 ms RTT the curve barely moves: W_cubic(0.001) = 84,025.604, a growth of
        // 3.66 bytes. W_est = 84,000 + 3 * 0.3 / 1.7 * 12,000 * 1,200 / 84,000 = 84,090.756
        // exceeds W_cubic(0) = 84,000, so cwnd follows W_est.
        let mut c = reduced(&CcConfig::default(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 84_090);
        let mut config = CcConfig::default();
        config.cubic.reno_friendly = false;
        let mut c = reduced(&config, t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 84_003);
    }

    #[test]
    fn in_the_reno_friendly_region_the_window_is_w_est_even_if_the_curve_step_is_larger() {
        let t0 = crate::recovery::test_epoch();
        // With a 100 ms RTT the curve step alone would reach 84,357 (see the cubic curve test),
        // but W_cubic(0) = 84,000 is below W_est = 84,090.756, so cwnd is W_est, as RFC 9438
        // recommends, and not the larger step.
        let mut c = reduced(&CcConfig::default(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, 100 * MS, t0 + 250 * MS);
        assert_eq!(c.window.cwnd, 84_090);
    }

    #[test]
    fn w_est_grows_like_reno_once_it_reaches_cwnd_prior() {
        let t0 = crate::recovery::test_epoch();
        let rtt = MS;
        let sent = t0 + 250 * MS;
        let mut c = reduced(&CcConfig::default(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 84_090);
        // Just below cwnd_prior (120,000), alpha is 3 * 0.3 / 1.7: W_est += 0.529 * 12,000 *
        // 1,200 / 84,090 = 90.66.
        let mut below = c.clone();
        below.w_est = 119_999.0;
        ack_at(&mut below, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(below.window.cwnd, 120_089);
        // At cwnd_prior alpha is 1: W_est += 12,000 * 1,200 / 84,090 = 171.25.
        c.w_est = 120_000.0;
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 120_171);
    }

    #[test]
    fn one_recovery_period_reduces_the_window_once() {
        let t0 = crate::recovery::test_epoch();
        // Recovery started at 200 ms.
        let mut c = reduced(&CcConfig::default(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, 100 * MS, t0 + 150 * MS);
        assert_eq!(c.window.cwnd, 84_000);
        assert_eq!(c.epoch, None);
        c.on_congestion_event(t0 + 310 * MS, t0 + 190 * MS, CongestionSignal::Loss);
        assert_eq!((c.window.cwnd, c.w_max), (84_000, 120_000.0));
        // A packet sent after the start ends the period, and the stage starts at W_est.
        ack_at(&mut c, t0 + 320 * MS, 12_000, 100 * MS, t0 + 250 * MS);
        assert_eq!(c.window.cwnd, 84_090);
    }

    #[test]
    fn application_limited_time_does_not_advance_the_curve() {
        let t0 = crate::recovery::test_epoch();
        let rtt = 100 * MS;
        let sent = t0 + 250 * MS;
        let mut c = reduced(&curve_only(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 84_357);
        // Application-limited from 1.3 s to 2.3 s: the window does not grow, and the second does
        // not count, so 2.3 s is t = 1 s on the curve, as in the cubic curve test.
        c.on_ack(&AckEvent {
            now: t0 + 1300 * MS,
            acked_bytes: 12_000,
            acked_in_recovery: 0,
            largest_acked_sent: sent,
            rtt,
            rtt_sample: None,
            app_limited: true,
        });
        assert_eq!(c.window.cwnd, 84_357);
        ack_at(&mut c, t0 + 2300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 87_359);
    }

    #[test]
    fn idle_time_does_not_advance_the_curve() {
        let t0 = crate::recovery::test_epoch();
        let rtt = 100 * MS;
        let sent = t0 + 250 * MS;
        let mut c = reduced(&curve_only(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        c.on_sent(t0 + 400 * MS, 12_000);
        // Idle from the last send at 0.4 s until 1.4 s, with zero bytes in flight.
        c.on_sent(t0 + 1400 * MS, 0);
        ack_at(&mut c, t0 + 2300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 87_359);
    }

    #[test]
    fn a_flight_acknowledged_and_refilled_at_once_was_not_idle() {
        let t0 = crate::recovery::test_epoch();
        let rtt = 100 * MS;
        let sent = t0 + 250 * MS;
        let mut c = reduced(&curve_only(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        c.on_sent(t0 + 400 * MS, 12_000);
        // One ACK at 1.3 s covers the whole flight, as in the cubic curve test, and the
        // window-limited sender fills the window again at once.
        ack_at(&mut c, t0 + 1300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 87_359);
        c.on_sent(t0 + 1300 * MS, 0);
        // 2.3 s is t = 2 s on the curve: W_cubic(2.1) = 115,444.833, so cwnd += (115,444.833 -
        // 87,359) * 12,000 / 87,359 = 3,857.988, plus the 0.413 carried.
        ack_at(&mut c, t0 + 2300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 91_217);
    }

    #[test]
    fn idle_time_runs_from_the_ack_of_the_last_flight() {
        let t0 = crate::recovery::test_epoch();
        let rtt = 100 * MS;
        let sent = t0 + 250 * MS;
        let mut c = reduced(&curve_only(), t0);
        ack_at(&mut c, t0 + 300 * MS, 12_000, rtt, sent);
        c.on_sent(t0 + 400 * MS, 12_000);
        ack_at(&mut c, t0 + 1300 * MS, 12_000, rtt, sent);
        // Idle from that ACK at 1.3 s until 2.3 s, so 3.3 s is t = 2 s on the curve, as in the
        // test above.
        c.on_sent(t0 + 2300 * MS, 0);
        ack_at(&mut c, t0 + 3300 * MS, 12_000, rtt, sent);
        assert_eq!(c.window.cwnd, 91_217);
    }

    #[test]
    fn after_persistent_congestion_the_curve_starts_flat_at_the_window() {
        let t0 = crate::recovery::test_epoch();
        let mut c = reduced(&curve_only(), t0);
        c.on_persistent_congestion();
        assert_eq!((c.window.cwnd, c.window.ssthresh), (2400, 84_000));
        // The recovery period is over: slow start back to ssthresh.
        ack_at(&mut c, t0 + 400 * MS, 81_600, 100 * MS, t0 + 100 * MS);
        assert_eq!(c.window.cwnd, 84_000);
        // RFC 9438: K = 0 and W_max = 84,000, so the target W_cubic(0.1) = 84,000.48 adds
        // 0.07 bytes; with the old W_max of 120,000 the curve would give 84,357.
        ack_at(&mut c, t0 + 500 * MS, 12_000, 100 * MS, t0 + 450 * MS);
        assert_eq!(c.window.cwnd, 84_000);
    }

    #[test]
    fn a_spurious_loss_undoes_the_reduction() {
        let t0 = crate::recovery::test_epoch();
        let mut c = reduced(&CcConfig::default(), t0);
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!((c.window.cwnd, c.window.ssthresh), (120_000, u64::MAX));
        assert_eq!((c.w_max, c.cwnd_prior), (0.0, 0));
        // Once only.
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 120_000);

        // Not once the window has grown back to cwnd_prior (RFC 9438).
        let mut c = reduced(&CcConfig::default(), t0);
        c.window.cwnd = 120_000;
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!((c.window.cwnd, c.window.ssthresh), (120_000, 84_000));

        let mut config = CcConfig::default();
        config.cubic.spurious_undo = false;
        let mut c = reduced(&config, t0);
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 84_000);
    }

    #[test]
    fn a_spurious_loss_undoes_only_the_reduction_of_its_recovery_period() {
        let t0 = crate::recovery::test_epoch();
        // The reduction's recovery period began at 200 ms. Losses of an episode that began at
        // another time did not cause it.
        let mut c = reduced(&CcConfig::default(), t0);
        c.on_spurious_loss(t0 + 300 * MS);
        assert_eq!(c.window.cwnd, 84_000);
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 120_000);
        // After a second reduction at 400 ms, the first period's losses cannot undo it.
        let mut c = reduced(&CcConfig::default(), t0);
        c.on_congestion_event(t0 + 400 * MS, t0 + 300 * MS, CongestionSignal::Loss);
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 58_800);
        c.on_spurious_loss(t0 + 400 * MS);
        assert_eq!(c.window.cwnd, 84_000);
    }

    #[test]
    fn an_ecn_reduction_is_never_undone() {
        let t0 = crate::recovery::test_epoch();
        let mut c = cubic(&CcConfig::default());
        ack_at(&mut c, t0 + 100 * MS, 108_000, 100 * MS, t0);
        c.on_congestion_event(t0 + 200 * MS, t0 + 150 * MS, CongestionSignal::Ecn);
        assert_eq!(c.window.cwnd, 84_000);
        // A late acknowledgment of an older lost packet does not undo the response to CE.
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 84_000);
        // CE marks inside a loss's recovery period confirm the congestion, so the reduction stays.
        let mut c = reduced(&CcConfig::default(), t0);
        c.on_congestion_event(t0 + 210 * MS, t0 + 160 * MS, CongestionSignal::Ecn);
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 84_000);
    }

    #[test]
    fn persistent_congestion_is_not_undone() {
        let t0 = crate::recovery::test_epoch();
        let mut c = reduced(&CcConfig::default(), t0);
        c.on_persistent_congestion();
        c.on_spurious_loss(t0 + 200 * MS);
        assert_eq!(c.window.cwnd, 2400);
    }

    #[test]
    fn congestion_avoidance_stops_at_the_maximum_window() {
        let t0 = crate::recovery::test_epoch();
        let config = CcConfig {
            max_window_packets: 100,
            ..CcConfig::default()
        };
        let mut c = reduced(&config, t0);
        for i in 0..20 {
            ack_at(
                &mut c,
                t0 + (300 + 1000 * i) * MS,
                12_000,
                100 * MS,
                t0 + 250 * MS,
            );
        }
        assert_eq!(c.window.cwnd, 120_000);
    }
}
