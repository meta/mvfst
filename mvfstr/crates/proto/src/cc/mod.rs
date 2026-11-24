/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Congestion control with explicit inputs and outputs: NewReno (RFC 9002) and CUBIC (RFC 9438).
//!
//! A controller is driven by explicit events (packet sent, bytes acknowledged with an RTT sample
//! and an app-limited flag, congestion event, persistent congestion) and produces the congestion
//! window, slow-start threshold and pacing rate. It does not touch connection or pacer state.
//!
//! Bytes in flight belong to the caller (loss recovery). Acknowledgments arrive aggregated per
//! ACK frame, as in mvfst: the newly acknowledged in-flight bytes, the part of them sent within the
//! recovery period, and the send time of the largest newly acknowledged packet, which determines
//! whether the ACK ends that period.

pub mod cubic;
pub mod new_reno;

use std::num::NonZeroU64;
use std::time::Duration;
use std::time::Instant;

pub use cubic::Cubic;
pub use new_reno::NewReno;

use crate::config::ConfigError;
use crate::config::CongestionControl;

/// Congestion controller settings shared by the algorithms.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CcConfig {
    /// The initial window in datagrams, limited to max(this * 1,472, 2 datagrams) bytes, as
    /// RFC 9002 recommends. Default 10, as in mvfst.
    pub initial_window_packets: u32,
    /// The minimum window in datagrams, at least 2. Default 2, as in RFC 9002 and mvfst.
    pub min_window_packets: u32,
    /// The maximum window in datagrams. Default 2,000, mvfst's library default; mvfst's tperf
    /// uses 860,000, effectively unbounded.
    pub max_window_packets: u32,
    /// The pacing gain N of RFC 9002's pacing rate, as (numerator, denominator). Default 5/4.
    pub pacing_gain: (u32, u32),
    /// CUBIC parameters.
    pub cubic: CubicConfig,
}

impl CcConfig {
    /// Refuses settings that the controllers cannot work with, for datagrams of up to
    /// `max_datagram_size` bytes.
    pub fn validate(&self, max_datagram_size: u16) -> Result<(), ConfigError> {
        let check = |ok: bool, field| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::OutOfRange { field })
            }
        };
        check_datagram_size(max_datagram_size)?;
        check(self.min_window_packets >= 2, "min_window_packets")?;
        check(
            self.max_window_packets >= self.min_window_packets,
            "max_window_packets",
        )?;
        check(
            self.pacing_gain.0 > 0 && self.pacing_gain.1 > 0,
            "pacing_gain",
        )?;
        let cubic = &self.cubic;
        check(cubic.beta > 0.0 && cubic.beta < 1.0, "cubic.beta")?;
        check(cubic.c > 0.0 && cubic.c.is_finite(), "cubic.c")
    }
}

/// Refuses a maximum datagram size below 1,200 bytes, which RFC 9000 does not allow for QUIC.
fn check_datagram_size(max_datagram_size: u16) -> Result<(), ConfigError> {
    if max_datagram_size >= 1200 {
        Ok(())
    } else {
        Err(ConfigError::OutOfRange {
            field: "max_datagram_size",
        })
    }
}

impl Default for CcConfig {
    fn default() -> Self {
        Self {
            initial_window_packets: 10,
            min_window_packets: 2,
            max_window_packets: 2000,
            pacing_gain: (5, 4),
            cubic: CubicConfig::default(),
        }
    }
}

/// CUBIC parameters (RFC 9438); the defaults are the RFC's and mvfst's.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CubicConfig {
    /// β_cubic, the multiplicative decrease factor. Default 0.7.
    pub beta: f64,
    /// C, in segments per second cubed. Default 0.4.
    pub c: f64,
    /// Fast convergence: a loss below the last W_max lowers W_max further. Default on.
    pub fast_convergence: bool,
    /// The Reno-friendly region, where the window follows an estimate of Reno's window when that is
    /// above the cubic curve. Default on.
    pub reno_friendly: bool,
    /// Undo of a reduction caused by a spurious loss. Default on.
    pub spurious_undo: bool,
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            beta: 0.7,
            c: 0.4,
            fast_convergence: true,
            reno_friendly: true,
            spurious_undo: true,
        }
    }
}

/// What signalled a congestion event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionSignal {
    /// Loss detection declared in-flight packets lost.
    Loss,
    /// The peer reported more ECN-CE marks.
    Ecn,
}

/// One ACK frame, as reported to the congestion controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckEvent {
    /// When the ACK was processed.
    pub now: Instant,
    /// In-flight bytes it newly acknowledged.
    pub acked_bytes: u64,
    /// Of `acked_bytes`, those of packets sent within the recovery period the controller was in
    /// when the ACK arrived ([`Cc::in_recovery`] before the ACK's own losses), which do not grow
    /// the window (RFC 9002). Zero outside a recovery period.
    pub acked_in_recovery: u64,
    /// The send time of the largest newly acknowledged packet.
    pub largest_acked_sent: Instant,
    /// The smoothed RTT after the ACK's sample.
    pub rtt: Duration,
    /// The ACK's RTT sample, RFC 9002's latest_rtt, if it produced one
    /// ([`crate::recovery::sent::AckSummary::rtt_sample`]). NewReno and CUBIC do not use it.
    pub rtt_sample: Option<Duration>,
    /// Whether the sender was application- or flow-control-limited, leaving the window
    /// underused; the window then does not grow, as RFC 9002 recommends.
    pub app_limited: bool,
}

/// A congestion controller.
#[derive(Clone, Debug)]
pub enum Cc {
    /// NewReno (RFC 9002).
    NewReno(NewReno),
    /// CUBIC (RFC 9438).
    Cubic(Cubic),
}

impl Cc {
    /// Creates a controller of `kind` for datagrams of up to `max_datagram_size` bytes, or fails
    /// as [`CcConfig::validate`] does.
    pub fn new(
        kind: CongestionControl,
        config: &CcConfig,
        max_datagram_size: u16,
    ) -> Result<Self, ConfigError> {
        config.validate(max_datagram_size)?;
        let window = Window::new(config, max_datagram_size);
        Ok(match kind {
            CongestionControl::NewReno => Self::NewReno(NewReno::new(window)),
            CongestionControl::Cubic => Self::Cubic(Cubic::new(window, config.cubic)),
        })
    }

    /// Records a packet counted in flight, sent at `now`; `bytes_in_flight` is the count before it.
    pub fn on_sent(&mut self, now: Instant, bytes_in_flight: u64) {
        match self {
            Self::NewReno(_) => {}
            Self::Cubic(c) => c.on_sent(now, bytes_in_flight),
        }
    }

    /// Records an ACK frame that newly acknowledged in-flight packets.
    pub fn on_ack(&mut self, ack: &AckEvent) {
        match self {
            Self::NewReno(c) => c.on_ack(ack),
            Self::Cubic(c) => c.on_ack(ack),
        }
    }

    /// Records a congestion event of kind `signal` at `now`. `sent` is the send time of the last
    /// lost packet, or for ECN of the largest acknowledged one, as in RFC 9002's pseudocode. An
    /// event inside the current recovery period is ignored, except that CE marks there rule out
    /// undoing its reduction. For losses, `now` is the time given to the
    /// [`crate::recovery::loss::LossRecovery`] call that declared them, so a new recovery period
    /// starts with the loss episode that may later prove it spurious.
    pub fn on_congestion_event(&mut self, now: Instant, sent: Instant, signal: CongestionSignal) {
        match self {
            Self::NewReno(c) => c.on_congestion_event(now, sent),
            Self::Cubic(c) => c.on_congestion_event(now, sent, signal),
        }
    }

    /// Records that persistent congestion was established; the caller reports it after the
    /// congestion event for the same losses.
    pub fn on_persistent_congestion(&mut self) {
        match self {
            Self::NewReno(c) => c.on_persistent_congestion(),
            Self::Cubic(c) => c.on_persistent_congestion(),
        }
    }

    /// Records that every loss of the loss episode that began at `recovery_start` proved spurious
    /// ([`crate::recovery::loss::AckOutcome`]'s `spurious_congestion`). CUBIC undoes its last
    /// reduction, as RFC 9438 allows, if that reduction's recovery period began at
    /// `recovery_start` and the window is still below its value then; NewReno ignores it.
    pub fn on_spurious_loss(&mut self, recovery_start: Instant) {
        match self {
            Self::NewReno(_) => {}
            Self::Cubic(c) => c.on_spurious_loss(recovery_start),
        }
    }

    /// Sets the path's maximum datagram size, for example once the peer's transport parameters
    /// allow larger datagrams. Fails below 1,200 bytes and leaves the controller unchanged.
    ///
    /// The initial window and the bounds follow, as RFC 9002 recommends: a window still at its
    /// initial value is recomputed, a smaller size (as when the handshake needs one) caps the
    /// window at the new initial window, and any other window is kept within the new bounds.
    /// CUBIC no longer undoes its last reduction, whose saved window is in bytes of the old size.
    pub fn set_max_datagram_size(&mut self, max_datagram_size: u16) -> Result<(), ConfigError> {
        check_datagram_size(max_datagram_size)?;
        let w = match self {
            Self::NewReno(c) => &mut c.window,
            Self::Cubic(c) => {
                c.forget_undo();
                &mut c.window
            }
        };
        let untouched = w.cwnd == w.initial;
        let smaller = u64::from(max_datagram_size) < w.mss;
        w.set_mss(max_datagram_size);
        if untouched {
            w.cwnd = w.initial;
        } else if smaller {
            w.cwnd = w.cwnd.min(w.initial);
        }
        w.cwnd = w.cwnd.clamp(w.min, w.max);
        Ok(())
    }

    /// Returns whether a packet sent at `sent` belongs to the current recovery period, whose
    /// packets do not grow the window when acknowledged (RFC 9002).
    pub fn in_recovery(&self, sent: Instant) -> bool {
        self.window().in_recovery(sent)
    }

    /// Returns the congestion window in bytes.
    pub fn cwnd(&self) -> u64 {
        self.window().cwnd
    }

    /// Returns the slow start threshold in bytes; `u64::MAX` until the first congestion event.
    pub fn ssthresh(&self) -> u64 {
        self.window().ssthresh
    }

    /// Returns the pacing rate in bytes per second, RFC 9002's N * cwnd / smoothed_rtt, with the
    /// RTT taken as at least one microsecond.
    pub fn pacing_rate(&self, smoothed_rtt: Duration) -> NonZeroU64 {
        let w = self.window();
        let (num, den) = w.pacing_gain;
        let rtt_us = smoothed_rtt.as_micros().max(1);
        let rate = u128::from(w.cwnd) * u128::from(num) * 1_000_000 / (u128::from(den) * rtt_us);
        NonZeroU64::new(u64::try_from(rate).unwrap_or(u64::MAX)).unwrap_or(NonZeroU64::MIN)
    }

    fn window(&self) -> &Window {
        match self {
            Self::NewReno(c) => &c.window,
            Self::Cubic(c) => &c.window,
        }
    }
}

/// The state both algorithms share: the window, its bounds and the recovery period.
#[derive(Clone, Debug)]
pub(crate) struct Window {
    pub(crate) mss: u64,
    pub(crate) cwnd: u64,
    pub(crate) ssthresh: u64,
    pub(crate) min: u64,
    pub(crate) max: u64,
    /// The initial window for the current datagram size.
    initial: u64,
    /// The initial, minimum and maximum windows in datagrams.
    packets: [u32; 3],
    pacing_gain: (u32, u32),
    /// When the current recovery period started.
    recovery_start: Option<Instant>,
}

impl Window {
    fn new(config: &CcConfig, max_datagram_size: u16) -> Self {
        let mut window = Self {
            mss: 0,
            cwnd: 0,
            ssthresh: u64::MAX,
            min: 0,
            max: 0,
            initial: 0,
            packets: [
                config.initial_window_packets,
                config.min_window_packets,
                config.max_window_packets,
            ],
            pacing_gain: config.pacing_gain,
            recovery_start: None,
        };
        window.set_mss(max_datagram_size);
        window.cwnd = window.initial;
        window
    }

    /// Recomputes the bounds and the initial window for datagrams of `max_datagram_size` bytes.
    fn set_mss(&mut self, max_datagram_size: u16) {
        let mss = u64::from(max_datagram_size);
        let [initial, min, max] = self.packets.map(u64::from);
        self.mss = mss;
        self.min = min * mss;
        self.max = max * mss;
        // RFC 9002: 10 * max_datagram_size, limited to max(14,720, 2 * max_datagram_size).
        self.initial = (initial * mss)
            .min((initial * 1472).max(2 * mss))
            .clamp(self.min, self.max);
    }

    /// Returns when the current recovery period started, if the window is in one.
    pub(crate) fn recovery_start(&self) -> Option<Instant> {
        self.recovery_start
    }

    /// Returns whether a packet sent at `sent` belongs to the current recovery period.
    pub(crate) fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|start| sent <= start)
    }

    /// Returns the bytes of `ack` that grow the window (RFC 9002): those sent after the recovery
    /// period began, or all once persistent congestion ended it. The window does not grow if the
    /// ACK's largest packet belongs to the period, as all its packets do when its losses began one.
    pub(crate) fn growth(&self, ack: &AckEvent) -> u64 {
        if self.in_recovery(ack.largest_acked_sent) {
            0
        } else if self.recovery_start.is_some() {
            ack.acked_bytes.saturating_sub(ack.acked_in_recovery)
        } else {
            ack.acked_bytes
        }
    }

    /// Drops the window to the minimum after persistent congestion and ends any recovery period.
    pub(crate) fn collapse(&mut self) {
        self.cwnd = self.min;
        self.recovery_start = None;
    }

    /// Grows the window in slow start by `acked` bytes up to ssthresh and returns the bytes left
    /// for congestion avoidance.
    pub(crate) fn slow_start(&mut self, acked: u64) -> u64 {
        if self.cwnd >= self.ssthresh {
            return acked;
        }
        let grow = acked.min(self.ssthresh - self.cwnd);
        self.cwnd = (self.cwnd + grow).min(self.max);
        acked - grow
    }

    /// Starts a recovery period at `now` for a loss of a packet sent at `sent`, unless that
    /// packet belongs to the current one; returns whether it started.
    pub(crate) fn enter_recovery(&mut self, now: Instant, sent: Instant) -> bool {
        if self.in_recovery(sent) {
            return false;
        }
        self.recovery_start = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_initial_window_is_ten_datagrams_up_to_14720_bytes() {
        let config = CcConfig::default();
        for kind in [CongestionControl::NewReno, CongestionControl::Cubic] {
            let cc = Cc::new(kind, &config, 1200).unwrap();
            assert_eq!(cc.cwnd(), 12_000);
            assert_eq!(cc.ssthresh(), u64::MAX);
            assert_eq!(Cc::new(kind, &config, 1500).unwrap().cwnd(), 14_720);
            // Never below two datagrams.
            let one = CcConfig {
                initial_window_packets: 1,
                ..config
            };
            assert_eq!(Cc::new(kind, &one, 1200).unwrap().cwnd(), 2400);
        }
    }

    #[test]
    fn settings_that_cannot_work_are_refused() {
        let ok = CcConfig::default();
        let refused = |kind, config: CcConfig, max_datagram_size| {
            Cc::new(kind, &config, max_datagram_size).unwrap_err()
        };
        let out_of_range = |field| ConfigError::OutOfRange { field };
        for kind in [CongestionControl::NewReno, CongestionControl::Cubic] {
            // RFC 9000: QUIC needs paths that carry 1,200-byte datagrams.
            assert_eq!(refused(kind, ok, 1199), out_of_range("max_datagram_size"));
            let zero_min = CcConfig {
                min_window_packets: 0,
                ..ok
            };
            assert_eq!(
                refused(kind, zero_min, 1200),
                out_of_range("min_window_packets")
            );
            let max_below_min = CcConfig {
                max_window_packets: 1,
                ..ok
            };
            assert_eq!(
                refused(kind, max_below_min, 1200),
                out_of_range("max_window_packets")
            );
            for pacing_gain in [(5, 0), (0, 4)] {
                let gain = CcConfig { pacing_gain, ..ok };
                assert_eq!(refused(kind, gain, 1200), out_of_range("pacing_gain"));
            }
            for beta in [0.0, 1.0, f64::NAN] {
                let mut config = ok;
                config.cubic.beta = beta;
                assert_eq!(refused(kind, config, 1200), out_of_range("cubic.beta"));
            }
            for c in [0.0, -0.4, f64::INFINITY, f64::NAN] {
                let mut config = ok;
                config.cubic.c = c;
                assert_eq!(refused(kind, config, 1200), out_of_range("cubic.c"));
            }
        }
    }

    #[test]
    fn a_minimum_window_below_two_datagrams_is_refused() {
        // RFC 9002: with a one-datagram window, the sender must wait for a PTO to recover a loss.
        let one = CcConfig {
            min_window_packets: 1,
            ..CcConfig::default()
        };
        for kind in [CongestionControl::NewReno, CongestionControl::Cubic] {
            assert_eq!(
                Cc::new(kind, &one, 1200).unwrap_err(),
                ConfigError::OutOfRange {
                    field: "min_window_packets"
                }
            );
        }
    }

    #[test]
    fn a_new_datagram_size_recomputes_the_window_bounds_and_an_untouched_initial_window() {
        let t0 = crate::recovery::test_epoch();
        let config = CcConfig {
            max_window_packets: 20,
            ..CcConfig::default()
        };
        let ack = |cc: &mut Cc, acked_bytes| {
            cc.on_ack(&AckEvent {
                now: t0 + Duration::from_millis(100),
                acked_bytes,
                acked_in_recovery: 0,
                largest_acked_sent: t0,
                rtt: Duration::from_millis(100),
                rtt_sample: None,
                app_limited: false,
            });
        };
        for kind in [CongestionControl::NewReno, CongestionControl::Cubic] {
            let mut cc = Cc::new(kind, &config, 1200).unwrap();
            // RFC 9002: the initial window is recomputed for the new size.
            cc.set_max_datagram_size(1452).unwrap();
            assert_eq!(cc.cwnd(), 14_520);
            // So is the maximum, twenty datagrams.
            ack(&mut cc, 100_000);
            assert_eq!(cc.cwnd(), 29_040);
            // A smaller size, as when the handshake needs one, goes back to the initial window.
            cc.set_max_datagram_size(1200).unwrap();
            assert_eq!(cc.cwnd(), 12_000);
            // The minimum is two datagrams of the current size.
            cc.on_persistent_congestion();
            assert_eq!(cc.cwnd(), 2400);
            // A window that has moved stays where it is.
            ack(&mut cc, 1200);
            cc.set_max_datagram_size(1500).unwrap();
            assert_eq!(cc.cwnd(), 3600);
            // A size QUIC cannot use is refused and leaves the bounds unchanged.
            assert_eq!(
                cc.set_max_datagram_size(1000),
                Err(ConfigError::OutOfRange {
                    field: "max_datagram_size"
                })
            );
            cc.on_persistent_congestion();
            assert_eq!(cc.cwnd(), 3000);
        }
    }

    #[test]
    fn a_new_datagram_size_forgets_the_window_saved_for_undo() {
        let t0 = crate::recovery::test_epoch();
        let ms = Duration::from_millis(1);
        let config = CcConfig {
            max_window_packets: 20,
            ..CcConfig::default()
        };
        let mut cc = Cc::new(CongestionControl::Cubic, &config, 1452).unwrap();
        cc.on_ack(&AckEvent {
            now: t0 + 100 * ms,
            acked_bytes: 100_000,
            acked_in_recovery: 0,
            largest_acked_sent: t0,
            rtt: 100 * ms,
            rtt_sample: None,
            app_limited: false,
        });
        assert_eq!(cc.cwnd(), 29_040);
        let start = t0 + 200 * ms;
        cc.on_congestion_event(start, t0 + 150 * ms, CongestionSignal::Loss);
        assert_eq!(cc.cwnd(), 20_328);
        cc.set_max_datagram_size(1200).unwrap();
        assert_eq!(cc.cwnd(), 12_000);
        // The saved 29,040 bytes belong to the old size and exceed the new maximum, 24,000.
        cc.on_spurious_loss(start);
        assert_eq!(cc.cwnd(), 12_000);
    }

    #[test]
    fn bytes_sent_within_a_recovery_period_grow_the_window_once_persistent_congestion_ends_it() {
        let t0 = crate::recovery::test_epoch();
        let ms = Duration::from_millis(1);
        for kind in [CongestionControl::NewReno, CongestionControl::Cubic] {
            let mut cc = Cc::new(kind, &CcConfig::default(), 1200).unwrap();
            cc.on_congestion_event(t0 + 100 * ms, t0 + 50 * ms, CongestionSignal::Loss);
            // A later ACK acknowledges 2,400 bytes sent within that recovery period and 1,200 sent
            // after it, and its losses, all sent within the period, establish persistent congestion
            // and so end the period: all 3,600 bytes grow the minimum window in slow start.
            cc.on_persistent_congestion();
            cc.on_ack(&AckEvent {
                now: t0 + 300 * ms,
                acked_bytes: 3600,
                acked_in_recovery: 2400,
                largest_acked_sent: t0 + 150 * ms,
                rtt: 100 * ms,
                rtt_sample: None,
                app_limited: false,
            });
            assert_eq!(cc.cwnd(), 2400 + 3600, "{kind:?}");
        }
    }

    #[test]
    fn the_pacing_rate_is_the_gain_times_cwnd_over_srtt() {
        let cc = Cc::new(CongestionControl::Cubic, &CcConfig::default(), 1200).unwrap();
        // 1.25 * 12,000 bytes / 100 ms.
        assert_eq!(cc.pacing_rate(Duration::from_millis(100)).get(), 150_000);
        // A zero RTT is treated as one microsecond rather than dividing by zero.
        assert_eq!(cc.pacing_rate(Duration::ZERO).get(), 15_000_000_000);
    }
}
