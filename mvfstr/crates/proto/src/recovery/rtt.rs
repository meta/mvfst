/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The RTT estimator of RFC 9002.

use std::time::Duration;
use std::time::Instant;

/// Minimum, smoothed, variation and latest RTT of one path (RFC 9002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RttEstimator {
    latest: Duration,
    smoothed: Duration,
    var: Duration,
    min: Duration,
    first_sample: Option<Instant>,
}

impl RttEstimator {
    /// Creates an estimator without samples, seeded with `initial_rtt` (RFC 9002).
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            latest: Duration::ZERO,
            smoothed: initial_rtt,
            var: initial_rtt / 2,
            min: Duration::ZERO,
            first_sample: None,
        }
    }

    /// Returns the most recent sample, or zero before the first.
    pub fn latest(&self) -> Duration {
        self.latest
    }

    /// Returns the smoothed RTT.
    pub fn smoothed(&self) -> Duration {
        self.smoothed
    }

    /// Returns the RTT variation (rttvar).
    pub fn var(&self) -> Duration {
        self.var
    }

    /// Returns the minimum sample, ignoring ACK delay, or zero before the first sample.
    pub fn min(&self) -> Duration {
        self.min
    }

    /// Returns when the first sample was taken.
    pub fn first_sample_time(&self) -> Option<Instant> {
        self.first_sample
    }

    /// Takes the RTT sample `latest` with the peer's reported `ack_delay` (RFC 9002).
    /// `max_ack_delay` is the peer's limit once the handshake is confirmed, and `None` before,
    /// when reported delays are used unclamped.
    pub fn update(
        &mut self,
        now: Instant,
        latest: Duration,
        ack_delay: Duration,
        max_ack_delay: Option<Duration>,
    ) {
        self.latest = latest;
        if self.first_sample.is_none() {
            self.first_sample = Some(now);
            self.min = latest;
            self.smoothed = latest;
            self.var = latest / 2;
            return;
        }
        self.min = self.min.min(latest);
        let ack_delay = max_ack_delay.map_or(ack_delay, |max| ack_delay.min(max));
        // Peer input: a delay too large to subtract is implausible and ignored, never a panic.
        let adjusted = latest
            .checked_sub(ack_delay)
            .filter(|adjusted| *adjusted >= self.min)
            .unwrap_or(latest);
        // rttvar uses the smoothed RTT before this sample, as RFC 9002 and RFC 6298 do.
        self.var = (3 * self.var + self.smoothed.abs_diff(adjusted)) / 4;
        self.smoothed = (7 * self.smoothed + adjusted) / 8;
    }

    /// Restarts min_rtt from the latest sample once persistent congestion is declared, as RFC 9002
    /// recommends, so that persistent congestion is not declared repeatedly when the RTT rises.
    pub fn on_persistent_congestion(&mut self) {
        self.min = self.latest;
    }

    /// Returns `smoothed_rtt + max(4 * rttvar, granularity)`: the PTO period without
    /// max_ack_delay or backoff (RFC 9002).
    pub fn pto_base(&self, granularity: Duration) -> Duration {
        self.smoothed + (4 * self.var).max(granularity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn a_new_estimator_starts_from_the_initial_rtt() {
        let rtt = RttEstimator::new(333 * MS);
        assert_eq!(rtt.smoothed(), 333 * MS);
        assert_eq!(rtt.var(), Duration::from_micros(166_500));
        assert_eq!(rtt.latest(), Duration::ZERO);
        assert_eq!(rtt.min(), Duration::ZERO);
        assert_eq!(rtt.first_sample_time(), None);
    }

    #[test]
    fn the_first_sample_resets_the_estimator_and_ignores_ack_delay() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = RttEstimator::new(333 * MS);
        rtt.update(t0, 100 * MS, 20 * MS, None);
        assert_eq!(rtt.latest(), 100 * MS);
        assert_eq!(rtt.min(), 100 * MS);
        assert_eq!(rtt.smoothed(), 100 * MS);
        assert_eq!(rtt.var(), 50 * MS);
        assert_eq!(rtt.first_sample_time(), Some(t0));
    }

    /// Returns an estimator after a 100 ms first sample: smoothed 100 ms, rttvar 50 ms, min 100 ms.
    fn after_first_sample(t0: Instant) -> RttEstimator {
        let mut rtt = RttEstimator::new(333 * MS);
        rtt.update(t0, 100 * MS, Duration::ZERO, None);
        rtt
    }

    #[test]
    fn later_samples_subtract_a_plausible_ack_delay_and_update_the_averages() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = after_first_sample(t0);
        // adjusted = 120 - 10 = 110; rttvar = 3/4 * 50 + 1/4 * |100 - 110| = 40;
        // smoothed = 7/8 * 100 + 1/8 * 110 = 101.25.
        rtt.update(t0 + MS, 120 * MS, 10 * MS, None);
        assert_eq!(rtt.latest(), 120 * MS);
        assert_eq!(rtt.min(), 100 * MS);
        assert_eq!(rtt.var(), 40 * MS);
        assert_eq!(rtt.smoothed(), Duration::from_micros(101_250));
        assert_eq!(rtt.first_sample_time(), Some(t0));
    }

    #[test]
    fn an_ack_delay_that_would_go_below_min_rtt_is_not_subtracted() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = after_first_sample(t0);
        // 105 < min 100 + delay 10, so adjusted = 105; rttvar = 37.5 + 1.25; smoothed = 87.5 +
        // 13.125.
        rtt.update(t0 + MS, 105 * MS, 10 * MS, None);
        assert_eq!(rtt.var(), Duration::from_micros(38_750));
        assert_eq!(rtt.smoothed(), Duration::from_micros(100_625));
    }

    #[test]
    fn ack_delay_is_clamped_to_max_ack_delay_only_after_confirmation() {
        let t0 = crate::recovery::test_epoch();
        // Confirmed: the 40 ms delay counts as 25 ms, adjusted = 125; rttvar = 37.5 + 6.25;
        // smoothed = 87.5 + 15.625.
        let mut confirmed = after_first_sample(t0);
        confirmed.update(t0 + MS, 150 * MS, 40 * MS, Some(25 * MS));
        assert_eq!(confirmed.var(), Duration::from_micros(43_750));
        assert_eq!(confirmed.smoothed(), Duration::from_micros(103_125));
        // Not confirmed: the whole 40 ms is subtracted, adjusted = 110.
        let mut handshaking = after_first_sample(t0);
        handshaking.update(t0 + MS, 150 * MS, 40 * MS, None);
        assert_eq!(handshaking.var(), 40 * MS);
        assert_eq!(handshaking.smoothed(), Duration::from_micros(101_250));
    }

    #[test]
    fn an_unclamped_ack_delay_too_large_to_add_is_not_subtracted() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = after_first_sample(t0);
        // Before confirmation the peer's delay is unclamped and may be any decoded value.
        rtt.update(t0 + MS, 120 * MS, Duration::MAX, None);
        assert_eq!(rtt.smoothed(), Duration::from_micros(102_500));
    }

    #[test]
    fn min_rtt_follows_the_smallest_sample_without_ack_delay() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = after_first_sample(t0);
        rtt.update(t0 + MS, 80 * MS, 30 * MS, None);
        assert_eq!(rtt.min(), 80 * MS);
        rtt.update(t0 + 2 * MS, 90 * MS, Duration::ZERO, None);
        assert_eq!(rtt.min(), 80 * MS);
    }

    #[test]
    fn persistent_congestion_restarts_min_rtt_from_the_latest_sample() {
        let t0 = crate::recovery::test_epoch();
        let mut rtt = after_first_sample(t0);
        rtt.update(t0 + MS, 80 * MS, Duration::ZERO, None);
        rtt.update(t0 + 2 * MS, 150 * MS, Duration::ZERO, None);
        rtt.on_persistent_congestion();
        assert_eq!(rtt.min(), 150 * MS);
    }

    #[test]
    fn the_pto_base_is_smoothed_plus_four_variations_or_the_granularity() {
        let t0 = crate::recovery::test_epoch();
        assert_eq!(after_first_sample(t0).pto_base(MS), 300 * MS);
        let mut small = RttEstimator::new(333 * MS);
        small.update(t0, MS, Duration::ZERO, None);
        assert_eq!(small.pto_base(10 * MS), 11 * MS);
    }
}
