/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pacer: a per-path virtual departure clock.
//!
//! The clock has a burst credit, never releases a run before `now` or the previous release,
//! restarts after idle and takes its rate, which sizes its runs, from the congestion controller.
//! Its next release time is behind `Stop::Pacing(t)` and `TxOutcome::pacing_at`.
//!
//! Runs follow mvfst BBR3's pacing arithmetic: N datagrams every T, from the rate r, the datagram
//! size D, the pacing granularity and the minimum and maximum bursts. Per path, with `v` the
//! virtual departure clock, `c` the burst credit's time and `rate'` the pacer's rate, N * D / T,
//! or r itself when the maximum burst lowered N:
//!
//! ```text
//! release      = max(now, v - c, last_release)
//! v            = max(v, release) + paced_bytes / rate'
//! burst_credit = min(N, max_burst - N) * D
//! ```
//!
//! A run takes one release and moves the clock once with all its paced bytes, so a full run
//! moves it by T, or by N * D / r when the maximum burst lowered N. A run starts while the clock
//! is at most `c` ahead of real time: a wake late by at most `c` keeps the schedule, more
//! lateness is forfeited, and after idle at most the credit and one run leave at once. mvfst
//! instead scales a late wake's batch by its lateness.

use std::num::NonZeroU64;
use std::time::Duration;
use std::time::Instant;

/// How the pacer sizes runs: [`TransportConfig`](crate::TransportConfig)'s pacing granularity,
/// minimum burst and maximum burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bursts {
    /// The tick a run is sized for, a non-zero whole number of microseconds.
    pub granularity: Duration,
    /// The fewest datagrams a run is sized for, at least 1.
    pub min: u16,
    /// The most datagrams in a run, at least `min`.
    pub max: u16,
}

/// The pacer of one path.
#[derive(Clone, Debug)]
pub struct Pacer {
    mss: u64,
    bursts: Bursts,
    rate: NonZeroU64,
    /// N, the datagrams of a full run.
    burst: u16,
    /// T, the time between full runs.
    run_time: Duration,
    /// Whether the maximum burst lowered N, so that runs leave at the rate itself.
    capped: bool,
    /// c, the burst credit at the pacer's rate: how far the clock may run ahead of a release.
    credit: Duration,
    /// The virtual departure clock; `None` before the first paced packet.
    clock: Option<Instant>,
    /// The latest release stamped, paced or not; the next release is never earlier.
    last_release: Option<Instant>,
    /// The latest release of a run with paced bytes.
    last_paced: Option<Instant>,
}

impl Pacer {
    /// Creates a pacer for datagrams of up to `max_datagram_size` bytes, sending at `rate` bytes
    /// per second in runs sized by `bursts`.
    pub fn new(max_datagram_size: u16, bursts: Bursts, rate: NonZeroU64) -> Self {
        let mut pacer = Self {
            mss: u64::from(max_datagram_size),
            bursts,
            rate,
            burst: bursts.min,
            run_time: Duration::ZERO,
            capped: false,
            credit: Duration::ZERO,
            clock: None,
            last_release: None,
            last_paced: None,
        };
        pacer.set_rate(rate);
        pacer
    }

    /// Sets the rate in bytes per second, usually the congestion controller's pacing rate.
    pub fn set_rate(&mut self, rate: NonZeroU64) {
        self.rate = rate;
        (self.burst, self.run_time, self.capped) = schedule(rate.get(), self.mss, self.bursts);
        // A run may start while the clock is at most one run ahead, or what the maximum burst
        // leaves of one, so that one release takes at most two runs or the maximum burst.
        let credit = self.burst.min(self.bursts.max - self.burst);
        self.credit = self.duration_of(u64::from(credit) * self.mss);
    }

    /// Sets the path's maximum datagram size; runs and the burst credit follow it.
    pub fn set_max_datagram_size(&mut self, max_datagram_size: u16) {
        self.mss = u64::from(max_datagram_size);
        self.set_rate(self.rate);
    }

    /// Returns N, the datagrams of a full run.
    pub fn burst(&self) -> u16 {
        self.burst
    }

    /// Returns T, the time between full runs at the current rate.
    pub fn run_time(&self) -> Duration {
        self.run_time
    }

    /// Returns the release a paced packet sent at `now` would get; the sender is pacing-blocked
    /// until then if it is later than `now` (`Stop::Pacing`).
    pub fn next_release(&self, now: Instant) -> Instant {
        let mut release = now;
        if let Some(clock) = self.clock
            && let Some(start) = clock.checked_sub(self.credit)
        {
            release = release.max(start);
        }
        release.max(self.last_release.unwrap_or(now))
    }

    /// Returns the release of a run built at `now` without paced bytes, such as an ACK-only or
    /// probe run: it waits only for the previous release on the path.
    pub fn unpaced_release(&self, now: Instant) -> Instant {
        self.last_release.map_or(now, |last| last.max(now))
    }

    /// Records a run released at `release`: its `paced_bytes` move the clock once, and a run
    /// without paced bytes does not move it.
    pub fn on_run(&mut self, release: Instant, paced_bytes: u64) {
        if paced_bytes > 0 {
            let clock = self.clock.map_or(release, |clock| clock.max(release));
            self.clock = Some(clock + self.duration_of(paced_bytes));
            self.last_paced = Some(release);
        }
        self.last_release = Some(self.last_release.map_or(release, |last| last.max(release)));
    }

    /// Returns whether paced bytes released later than `now` wait below the transport, which
    /// draft-ietf-ccwg-bbr-07 counts in C.pending_transmissions.
    pub fn has_pending(&self, now: Instant) -> bool {
        self.last_paced.is_some_and(|release| release > now)
    }

    /// Stamps a paced run of `bytes` built at `now` and returns its release.
    pub fn on_paced(&mut self, now: Instant, bytes: u64) -> Instant {
        let release = self.next_release(now);
        self.on_run(release, bytes);
        release
    }

    /// Stamps an unpaced run built at `now` and returns its release.
    pub fn on_unpaced(&mut self, now: Instant) -> Instant {
        let release = self.unpaced_release(now);
        self.on_run(release, 0);
        release
    }

    /// Returns how long `bytes` take at the pacer's rate, rounded up to whole nanoseconds: N
    /// datagrams per T, so that a full run takes exactly T, or the rate itself when the maximum
    /// burst lowered N.
    fn duration_of(&self, bytes: u64) -> Duration {
        let bytes = u128::from(bytes);
        let nanos = if self.capped {
            (bytes * NANOS).div_ceil(u128::from(self.rate.get()))
        } else {
            let run_bytes = u128::from(self.burst) * u128::from(self.mss);
            (bytes * self.run_time.as_nanos()).div_ceil(run_bytes.max(1))
        };
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

const NANOS: u128 = 1_000_000_000;
const MICROS: u128 = 1_000_000;

/// The shortest interval that runs are sized from, in full-size datagrams' time at the rate.
const PACER_WINDOW: u128 = 64;

/// Returns N, T and whether the maximum burst lowered N, at `rate` bytes per second for datagrams
/// of `mss` bytes, in integer steps: the interval
/// I = max(ceil(64 × 10^6 × D / r), G) in whole microseconds, the P = floor(r × I / (10^6 × D))
/// whole datagrams in it, N = ceil(P × G / I) within the minimum and maximum bursts, and
/// T = floor(I × N / P) microseconds. The products saturate: a tick long enough to overflow them
/// holds more datagrams than any maximum burst, so N is the maximum either way.
fn schedule(rate: u64, mss: u64, bursts: Bursts) -> (u16, Duration, bool) {
    let (rate, mss) = (u128::from(rate), u128::from(mss.max(1)));
    let tick = bursts.granularity.as_micros().max(1);
    let interval = (PACER_WINDOW * mss * MICROS).div_ceil(rate).max(tick);
    let packets = (rate.saturating_mul(interval) / (MICROS * mss)).max(1);
    let wanted = packets.saturating_mul(tick).div_ceil(interval);
    let burst = wanted.clamp(u128::from(bursts.min), u128::from(bursts.max));
    let capped = wanted > burst;
    let nanos = if capped {
        // mvfst does not cap its bursts, so its spacing does not apply here: N × D / T would
        // drift from the rate, or T reach 0. Such runs leave at the rate itself.
        (burst * mss * NANOS).div_ceil(rate).max(1)
    } else {
        interval * burst / packets * 1000
    };
    let burst = u16::try_from(burst).unwrap_or(u16::MAX);
    let run_time = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
    (burst, run_time, capped)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// Builds a pacer sending 1,200 bytes per millisecond with 1,200-byte datagrams and a 1 ms
    /// tick: runs of N = 5 datagrams every T = 5 ms, and a credit of one run.
    fn pacer() -> Pacer {
        Pacer::new(1200, ms(), NonZeroU64::new(1_200_000).unwrap())
    }

    /// Returns a 1 ms tick and a minimum burst of 5, mvfst's defaults, and a maximum burst of 44.
    fn ms() -> Bursts {
        Bursts {
            granularity: MS,
            min: 5,
            max: 44,
        }
    }

    fn releases(p: &mut Pacer, now: Instant, n: usize) -> Vec<Duration> {
        let base = now;
        (0..n).map(|_| p.on_paced(now, 1200) - base).collect()
    }

    const US: Duration = Duration::from_micros(1);
    const NS: Duration = Duration::from_nanos(1);

    /// Returns mvfst tperf's `--pacing` tick and minimum burst, 200 µs and 5, and a maximum of 44.
    fn tperf() -> Bursts {
        Bursts {
            granularity: 200 * US,
            min: 5,
            max: 44,
        }
    }

    /// Converts `mbit` megabits per second to bytes per second.
    fn mbit(mbit: u64) -> NonZeroU64 {
        NonZeroU64::new(mbit * 125_000).unwrap()
    }

    #[test]
    fn bursts_and_their_spacing_follow_mvfsts_bbr3_arithmetic() {
        // 1,452-byte datagrams at 20, 100 and 200 Mbit/s and 1 Gbit/s.
        for (rate, burst, spacing) in [(20, 5, 2904), (100, 5, 580), (200, 5, 290), (1000, 18, 209)]
        {
            let p = Pacer::new(1452, tperf(), mbit(rate));
            assert_eq!(
                (p.burst(), p.run_time()),
                (burst, spacing * US),
                "{rate} Mbit/s"
            );
        }
        // Above 64 datagrams per tick the interval is the tick: with the maximum out of reach,
        // 1 GB/s gives runs of the 137 whole datagrams in 200 µs, every 200 µs.
        let uncapped = Bursts {
            max: u16::MAX,
            ..tperf()
        };
        let p = Pacer::new(1452, uncapped, NonZeroU64::new(1_000_000_000).unwrap());
        assert_eq!((p.burst(), p.run_time()), (137, 200 * US));
    }

    #[test]
    fn no_run_holds_more_than_the_maximum_burst() {
        // mvfst's arithmetic gives 275 datagrams per tick at 2 GB/s and 18 at 1 Gbit/s.
        let p = Pacer::new(1452, tperf(), NonZeroU64::new(2_000_000_000).unwrap());
        assert_eq!(p.burst(), 44);
        let ten = Bursts { max: 10, ..tperf() };
        assert_eq!(Pacer::new(1452, ten, mbit(1000)).burst(), 10);
        assert_eq!(Pacer::new(1452, ten, mbit(100)).burst(), 5);
    }

    #[test]
    fn a_burst_the_maximum_lowered_runs_at_the_rate_itself() {
        let gbyte = NonZeroU64::new(2_000_000_000).unwrap();
        // mvfst's spacing would be 32 µs, 1,996,500,000 B/s for 44 datagrams.
        let p = Pacer::new(1452, tperf(), gbyte);
        assert_eq!(
            (p.burst(), p.run_time()),
            (44, Duration::from_nanos(31_944))
        );
        // It would be 0 for single datagrams.
        let single = Bursts {
            min: 1,
            max: 1,
            ..tperf()
        };
        let p = Pacer::new(1452, single, gbyte);
        assert_eq!((p.burst(), p.run_time()), (1, Duration::from_nanos(726)));
        let defaults = Bursts {
            granularity: MS,
            min: 5,
            max: 44,
        };
        let p = Pacer::new(1452, defaults, NonZeroU64::MAX);
        assert_eq!((p.burst(), p.run_time()), (44, Duration::from_nanos(1)));
    }

    #[test]
    fn a_tick_of_any_length_gives_runs_at_the_rate_without_overflow() {
        // Ticks this long hold more datagrams than any maximum, at any rate.
        for granularity in [Duration::from_secs(u64::MAX), Duration::MAX] {
            let longest = Bursts {
                granularity,
                ..tperf()
            };
            let p = Pacer::new(1200, longest, NonZeroU64::new(750_000).unwrap());
            assert_eq!((p.burst(), p.run_time()), (44, 70_400 * US));
            let p = Pacer::new(1200, longest, NonZeroU64::MAX);
            assert_eq!((p.burst(), p.run_time()), (44, NS));
        }
    }

    #[test]
    fn a_run_moves_the_clock_by_its_bytes_at_the_pacers_rate() {
        let t0 = crate::recovery::test_epoch();
        // N = 18 and T = 209 µs, so the pacer runs at 18 × 1,452 B per 209 µs, a little faster
        // than 1 Gbit/s.
        let mut p = Pacer::new(1452, tperf(), mbit(1000));
        assert_eq!(p.on_paced(t0, 18 * 1452), t0);
        assert_eq!(p.clock, Some(t0 + 209 * US));
        // Half a run takes half the time, rounded up to whole nanoseconds.
        p.on_paced(t0, 9 * 1452);
        assert_eq!(p.clock, Some(t0 + 209 * US + Duration::from_nanos(104_500)));
        p.on_paced(t0, 1);
        assert_eq!(p.clock, Some(t0 + 313_500 * NS + 8 * NS));
        // A burst the maximum lowered runs at the rate itself: 726 ns per datagram at 2 GB/s.
        let mut p = Pacer::new(1452, tperf(), NonZeroU64::new(2_000_000_000).unwrap());
        p.on_paced(t0, 44 * 1452);
        assert_eq!(p.clock, Some(t0 + 31_944 * NS));
        p.on_paced(t0, 1452);
        assert_eq!(p.clock, Some(t0 + 32_670 * NS));
    }

    #[test]
    fn a_run_is_debited_once_from_its_release_and_its_bytes_are_pending_until_then() {
        let t0 = crate::recovery::test_epoch();
        let (full, t) = (18 * 1452, 209 * US);
        let mut p = Pacer::new(1452, tperf(), mbit(1000));
        // A run released 100 µs ahead of the attempt that built it.
        let release = t0 + 100 * US;
        assert_eq!(p.next_release(t0), t0);
        p.on_run(release, full);
        assert_eq!(p.clock, Some(release + t));
        assert!(p.has_pending(t0) && p.has_pending(release - NS));
        assert!(!p.has_pending(release));
        // An unpaced run waits for it but does not take tokens or leave bytes pending.
        assert_eq!(p.unpaced_release(t0), release);
        p.on_run(release, 0);
        assert_eq!(p.clock, Some(release + t));
        let later = t0 + 10 * t;
        assert_eq!(p.unpaced_release(later), later);
        p.on_run(later, 0);
        assert!(!p.has_pending(t0 + t));
        assert_eq!(p.next_release(later), later);
    }

    #[test]
    fn a_wake_late_by_at_most_a_run_time_keeps_the_schedule_and_more_is_forfeited() {
        let t0 = crate::recovery::test_epoch();
        // N = 18 is at most half the maximum, so the credit is a full run: c = T = 209 µs.
        let (full, t) = (18 * 1452, 209 * US);
        let mut p = Pacer::new(1452, tperf(), mbit(1000));
        assert_eq!(p.on_paced(t0, full), t0);
        assert_eq!(p.on_paced(t0, full), t0);
        assert_eq!(p.next_release(t0), t0 + t);
        assert_eq!(p.on_paced(t0 + t, full), t0 + t);
        // Due at 2T and 150 µs late: it leaves at once, and the next run keeps its time.
        let late = t0 + 2 * t + 150 * US;
        assert_eq!(p.on_paced(late, full), late);
        assert_eq!(p.next_release(late), t0 + 3 * t);
        assert_eq!(p.on_paced(t0 + 3 * t, full), t0 + 3 * t);
        // Due at 4T and T + 50 µs late: a second run follows at once, and the 50 µs beyond the
        // credit are lost.
        let later = t0 + 5 * t + 50 * US;
        assert_eq!(p.on_paced(later, full), later);
        assert_eq!(p.on_paced(later, full), later);
        assert_eq!(p.next_release(later), later + t);
    }

    #[test]
    fn above_half_the_maximum_burst_the_credit_is_what_the_maximum_leaves() {
        let t0 = crate::recovery::test_epoch();
        // N = 18 with a maximum of 30: a credit of 12 datagrams, c = 139,334 ns of T = 209 µs.
        let (full, t, c) = (18 * 1452, 209 * US, 139_334 * NS);
        let bursts = Bursts { max: 30, ..tperf() };
        let mut p = Pacer::new(1452, bursts, mbit(1000));
        // One run leaves after idle, not two.
        assert_eq!(p.on_paced(t0, full), t0);
        assert_eq!(p.next_release(t0), t0 + t - c);
        assert_eq!(p.on_paced(t0 + t - c, full), t0 + t - c);
        // Late by c, the run still keeps the schedule; late by 10 µs more, the 10 µs are lost.
        let late = t0 + 2 * t;
        assert_eq!(p.on_paced(late, full), late);
        assert_eq!(p.next_release(late), t0 + 3 * t - c);
        let later = t0 + 3 * t + 10 * US;
        assert_eq!(p.on_paced(later, full), later);
        assert_eq!(p.next_release(later), later + t - c);
        // At the maximum the credit is zero: each run waits for the previous one's time.
        let all = Bursts { max: 18, ..tperf() };
        let mut p = Pacer::new(1452, all, mbit(1000));
        assert_eq!(p.on_paced(t0, full), t0);
        assert_eq!(p.next_release(t0), t0 + p.run_time());
    }

    #[test]
    fn single_datagrams_after_the_burst_credit_are_spaced_by_size_over_rate() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        // N = 5 and T = 5 ms: the credit of five datagrams and the one crossing it leave at
        // once, then one per ms.
        assert_eq!(
            releases(&mut p, t0, 9),
            [
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
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
    fn after_idle_the_clock_restarts_at_now_with_one_burst_of_credit() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 9);
        let later = t0 + Duration::from_secs(1);
        assert_eq!(p.next_release(later), later);
        assert_eq!(
            releases(&mut p, later, 8),
            [
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                MS,
                2 * MS
            ]
        );
    }

    #[test]
    fn a_release_is_never_before_now() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 9);
        // The clock is at 9 ms: the next release is 4 ms, or now if later.
        assert_eq!(p.next_release(t0), t0 + 4 * MS);
        assert_eq!(p.next_release(t0 + 5 * MS), t0 + 5 * MS);
        assert_eq!(p.on_paced(t0 + 5 * MS, 1200), t0 + 5 * MS);
    }

    /// Counts the runs of `datagrams` 1,452-byte datagrams that leave at once after idle.
    fn at_once(bursts: Bursts, rate: NonZeroU64, datagrams: u64) -> usize {
        let t0 = crate::recovery::test_epoch() + Duration::from_secs(10);
        let mut p = Pacer::new(1452, bursts, rate);
        p.on_paced(t0 - Duration::from_secs(1), 1452);
        (0..100)
            .map(|_| p.on_paced(t0, datagrams * 1452))
            .take_while(|release| *release == t0)
            .count()
    }

    #[test]
    fn after_idle_at_most_the_credit_and_one_run_share_a_release() {
        // Full runs: two of N = 18 at 1 Gbit/s; one of N = 18 when the maximum is 30, whose
        // credit is 12 datagrams.
        assert_eq!(at_once(tperf(), mbit(1000), 18), 2);
        let thirty = Bursts { max: 30, ..tperf() };
        assert_eq!(at_once(thirty, mbit(1000), 18), 1);
        // One-datagram runs: N = 5 at 100 Mbit/s, five of credit and one more; at most 12 + 1
        // for N = 18 with a maximum of 30, and 18 + 1 at 1 Gbit/s.
        assert_eq!(at_once(tperf(), mbit(100), 1), 6);
        assert!(at_once(thirty, mbit(1000), 1) <= 13);
        assert!(at_once(tperf(), mbit(1000), 1) <= 19);
    }

    #[test]
    fn the_burst_credit_follows_the_datagram_size() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        p.set_max_datagram_size(1500);
        // N = 5 and T = 6.25 ms: five 1,500-byte datagrams of credit and the one crossing it.
        let together = (0..9)
            .map(|_| p.on_paced(t0, 1500))
            .filter(|release| *release == t0)
            .count();
        assert_eq!(together, 6);
    }

    #[test]
    fn releases_never_go_backwards_when_the_rate_drops() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        releases(&mut p, t0, 9);
        // At 1,200 bytes per second the credit spans 5 s, which would reach back before the
        // last release at 3 ms.
        p.set_rate(NonZeroU64::new(1200).unwrap());
        assert_eq!(p.on_paced(t0, 1200), t0 + 3 * MS);
    }

    #[test]
    fn unpaced_packets_wait_only_for_the_previous_release() {
        let t0 = crate::recovery::test_epoch();
        let mut p = pacer();
        // Paced releases at 0 (six times), 1 and 2 ms; the next paced one is due at 3 ms.
        releases(&mut p, t0, 8);
        assert_eq!(p.on_unpaced(t0), t0 + 2 * MS);
        assert_eq!(p.next_release(t0), t0 + 3 * MS);
        assert_eq!(p.on_unpaced(t0 + 10 * MS), t0 + 10 * MS);
    }
}
