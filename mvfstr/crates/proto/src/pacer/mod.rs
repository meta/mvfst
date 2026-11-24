/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pacer: a per-path virtual departure clock.
//!
//! The clock has a `burst_credit`, never releases a packet before `now`, restarts after idle and
//! takes its rate from the congestion controller. Its next release time is behind
//! `Stop::Pacing(t)` and `TxOutcome::pacing_at`. The connection holds packets back for the
//! pacer by not building them.
//!
//! Per path, with `v` the virtual departure clock:
//!
//! ```text
//! release      = max(now, v - burst_credit / rate, last_release)
//! v            = max(v, release) + size / rate
//! burst_credit = max(2 * MSS, rate * enforcer_granularity)
//! ```
//!
//! A packet may leave while the clock is at most `burst_credit` ahead of real time, so after
//! idle, when `v` has fallen behind `now`, at most `burst_credit` plus the datagram (or GSO run)
//! that crosses it leaves at once. A GSO run is stamped once with all its bytes.

use std::num::NonZeroU64;
use std::time::Duration;
use std::time::Instant;

/// The pacer of one path.
#[derive(Clone, Debug)]
pub struct Pacer {
    mss: u64,
    granularity: Duration,
    rate: NonZeroU64,
    burst_credit: u64,
    /// The virtual departure clock; `None` before the first paced packet.
    clock: Option<Instant>,
    /// The latest release stamped, paced or not; the next release is never earlier.
    last_release: Option<Instant>,
}

impl Pacer {
    /// Creates a pacer for datagrams of up to `max_datagram_size` bytes, sending at `rate` bytes
    /// per second, whose releases are enforced with `granularity`, the `enforcer_granularity` of
    /// the module docs.
    pub fn new(max_datagram_size: u16, granularity: Duration, rate: NonZeroU64) -> Self {
        let mut pacer = Self {
            mss: u64::from(max_datagram_size),
            granularity,
            rate,
            burst_credit: 0,
            clock: None,
            last_release: None,
        };
        pacer.set_rate(rate);
        pacer
    }

    /// Sets the rate in bytes per second, usually the congestion controller's pacing rate.
    pub fn set_rate(&mut self, rate: NonZeroU64) {
        self.rate = rate;
        let per_granularity = u128::from(rate.get()) * self.granularity.as_nanos() / NANOS;
        self.burst_credit = u64::try_from(per_granularity)
            .unwrap_or(u64::MAX)
            .max(2 * self.mss);
    }

    /// Sets the path's maximum datagram size; the burst credit is at least two such datagrams.
    pub fn set_max_datagram_size(&mut self, max_datagram_size: u16) {
        self.mss = u64::from(max_datagram_size);
        self.set_rate(self.rate);
    }

    /// Returns the release a paced packet sent at `now` would get; the sender is pacing-blocked
    /// until then if it is later than `now` (`Stop::Pacing`).
    pub fn next_release(&self, now: Instant) -> Instant {
        let mut release = now;
        if let Some(clock) = self.clock
            && let Some(start) = clock.checked_sub(self.duration_of(self.burst_credit))
        {
            release = release.max(start);
        }
        release.max(self.last_release.unwrap_or(now))
    }

    /// Stamps a paced datagram or GSO run of `bytes` built at `now` and returns its release.
    pub fn on_paced(&mut self, now: Instant, bytes: u64) -> Instant {
        let release = self.next_release(now);
        let clock = self.clock.map_or(release, |clock| clock.max(release));
        self.clock = Some(clock + self.duration_of(bytes));
        self.last_release = Some(release);
        release
    }

    /// Stamps an ACK-only or probe packet built at `now`: it waits only for the previous release
    /// on the path and does not move the clock. Returns its release.
    pub fn on_unpaced(&mut self, now: Instant) -> Instant {
        let release = self.last_release.map_or(now, |last| last.max(now));
        self.last_release = Some(release);
        release
    }

    /// Returns how long `bytes` take at the current rate, rounded up to whole nanoseconds.
    fn duration_of(&self, bytes: u64) -> Duration {
        let nanos = (u128::from(bytes) * NANOS).div_ceil(u128::from(self.rate.get()));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

const NANOS: u128 = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// Builds a pacer sending 1,200 bytes per millisecond with 1,200-byte datagrams and a 1 ms
    /// granularity: the burst credit is two datagrams.
    fn pacer() -> Pacer {
        Pacer::new(1200, MS, NonZeroU64::new(1_200_000).unwrap())
    }

    fn releases(p: &mut Pacer, now: Instant, n: usize) -> Vec<Duration> {
        let base = now;
        (0..n).map(|_| p.on_paced(now, 1200) - base).collect()
    }

    #[test]
    fn packets_are_spaced_by_size_over_rate_after_the_burst() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        // Two datagrams of credit plus the one crossing it leave at once, then one per ms.
        assert_eq!(
            releases(&mut p, t0, 6),
            [
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                MS,
                2 * MS,
                3 * MS
            ]
        );
    }

    #[test]
    fn after_idle_the_clock_restarts_at_now_with_one_burst() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 6);
        let later = t0 + Duration::from_secs(1);
        assert_eq!(p.next_release(later), later);
        assert_eq!(
            releases(&mut p, later, 5),
            [Duration::ZERO, Duration::ZERO, Duration::ZERO, MS, 2 * MS]
        );
    }

    #[test]
    fn a_release_is_never_before_now() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 6);
        // The clock is at 6 ms: the next release is 4 ms, or now if later.
        assert_eq!(p.next_release(t0), t0 + 4 * MS);
        assert_eq!(p.next_release(t0 + 5 * MS), t0 + 5 * MS);
        assert_eq!(p.on_paced(t0 + 5 * MS, 1200), t0 + 5 * MS);
    }

    #[test]
    fn the_burst_credit_covers_one_enforcer_granularity_at_the_rate() {
        let t0 = crate::recovery::test_epoch();
        // 12,000 bytes per millisecond: ten datagrams of credit, plus the one crossing it.
        let mut p = Pacer::new(1200, MS, NonZeroU64::new(12_000_000).unwrap());
        let at_once = releases(&mut p, t0, 12)
            .into_iter()
            .filter(|d| d.is_zero())
            .count();
        assert_eq!(at_once, 11);
    }

    #[test]
    fn the_minimum_burst_follows_the_datagram_size() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        p.set_max_datagram_size(1500);
        // Two 1,500-byte datagrams of credit (2.5 ms at the rate) plus the one crossing it.
        let at_once = (0..6)
            .map(|_| p.on_paced(t0, 1500))
            .filter(|release| *release == t0)
            .count();
        assert_eq!(at_once, 3);
    }

    #[test]
    fn releases_never_go_backwards_when_the_rate_drops() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 6);
        // At 1,200 bytes per second the credit spans 2 s, which would reach back before the
        // last release at 3 ms.
        p.set_rate(NonZeroU64::new(1200).unwrap());
        assert_eq!(p.on_paced(t0, 1200), t0 + 3 * MS);
    }

    #[test]
    fn unpaced_packets_wait_only_for_the_previous_release() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        // Paced releases at 0, 0, 0 and 1 ms; the next paced one is due at 2 ms.
        releases(&mut p, t0, 4);
        assert_eq!(p.on_unpaced(t0), t0 + MS);
        assert_eq!(p.next_release(t0), t0 + 2 * MS);
        assert_eq!(p.on_unpaced(t0 + 10 * MS), t0 + 10 * MS);
    }
}
