/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! NewReno congestion control (RFC 9002).

use std::time::Instant;

use super::AckEvent;
use super::Window;

/// NewReno: slow start, then one datagram of growth per window acknowledged; the window halves
/// once per recovery period.
#[derive(Clone, Debug)]
pub struct NewReno {
    pub(crate) window: Window,
    /// Bytes acknowledged in congestion avoidance toward the next datagram of growth.
    acked_in_window: u64,
}

impl NewReno {
    pub(crate) fn new(window: Window) -> Self {
        Self {
            window,
            acked_in_window: 0,
        }
    }

    pub(crate) fn on_ack(&mut self, ack: &AckEvent) {
        if ack.app_limited {
            return;
        }
        let w = &mut self.window;
        let acked = w.slow_start(w.growth(ack));
        if acked == 0 {
            return;
        }
        // Appropriate byte counting (RFC 3465): one datagram per window acknowledged.
        self.acked_in_window += acked;
        while self.acked_in_window >= w.cwnd {
            self.acked_in_window -= w.cwnd;
            w.cwnd = (w.cwnd + w.mss).min(w.max);
        }
    }

    pub(crate) fn on_congestion_event(&mut self, now: Instant, sent: Instant) {
        let w = &mut self.window;
        if !w.enter_recovery(now, sent) {
            return;
        }
        // RFC 9002's kLossReductionFactor, 0.5.
        w.ssthresh = w.cwnd / 2;
        w.cwnd = w.ssthresh.max(w.min);
        self.acked_in_window = 0;
    }

    pub(crate) fn on_persistent_congestion(&mut self) {
        self.window.collapse();
        self.acked_in_window = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::Cc;
    use super::super::CcConfig;
    use super::super::CongestionSignal;
    use super::*;
    use crate::config::CongestionControl;

    const MS: Duration = Duration::from_millis(1);

    fn new_reno(config: &CcConfig) -> Cc {
        Cc::new(CongestionControl::NewReno, config, 1200).unwrap()
    }

    fn ack(cc: &mut Cc, now: Instant, acked_bytes: u64, largest_acked_sent: Instant) {
        cc.on_ack(&AckEvent {
            now,
            acked_bytes,
            acked_in_recovery: 0,
            largest_acked_sent,
            rtt: 100 * MS,
            rtt_sample: None,
            app_limited: false,
        });
    }

    #[test]
    fn slow_start_grows_by_the_acknowledged_bytes_up_to_the_maximum() {
        let t0 = crate::recovery::test_epoch();
        let config = CcConfig {
            max_window_packets: 20,
            ..CcConfig::default()
        };
        let mut cc = new_reno(&config);
        ack(&mut cc, t0 + 100 * MS, 6000, t0);
        assert_eq!(cc.cwnd(), 18_000);
        ack(&mut cc, t0 + 110 * MS, 12_000, t0);
        assert_eq!(cc.cwnd(), 24_000);
    }

    #[test]
    fn a_congestion_event_halves_the_window_down_to_the_minimum() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        cc.on_congestion_event(t0 + 100 * MS, t0, CongestionSignal::Loss);
        assert_eq!((cc.cwnd(), cc.ssthresh()), (6000, 6000));
        cc.on_congestion_event(t0 + 200 * MS, t0 + 150 * MS, CongestionSignal::Loss);
        assert_eq!((cc.cwnd(), cc.ssthresh()), (3000, 3000));
        cc.on_congestion_event(t0 + 300 * MS, t0 + 250 * MS, CongestionSignal::Loss);
        // ssthresh 1,500, but the window stays at two datagrams.
        assert_eq!((cc.cwnd(), cc.ssthresh()), (2400, 1500));
    }

    #[test]
    fn congestion_avoidance_adds_one_datagram_per_window_acknowledged() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        cc.on_congestion_event(t0 + 10 * MS, t0, CongestionSignal::Loss);
        assert_eq!(cc.cwnd(), 6000);
        // Packets sent after the recovery period started.
        let sent = t0 + 20 * MS;
        ack(&mut cc, t0 + 100 * MS, 4800, sent);
        assert_eq!(cc.cwnd(), 6000);
        ack(&mut cc, t0 + 101 * MS, 1200, sent);
        assert_eq!(cc.cwnd(), 7200);
        // The next datagram of growth needs a whole 7,200-byte window.
        ack(&mut cc, t0 + 102 * MS, 7000, sent);
        assert_eq!(cc.cwnd(), 7200);
        ack(&mut cc, t0 + 103 * MS, 200, sent);
        assert_eq!(cc.cwnd(), 8400);
    }

    #[test]
    fn a_reduction_forgets_the_bytes_counted_toward_growth() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        cc.on_congestion_event(t0 + 10 * MS, t0, CongestionSignal::Loss);
        ack(&mut cc, t0 + 100 * MS, 4800, t0 + 20 * MS);
        assert_eq!(cc.cwnd(), 6000);
        // The reduction drops the 4,800 bytes counted toward the 6,000-byte window.
        cc.on_congestion_event(t0 + 110 * MS, t0 + 30 * MS, CongestionSignal::Loss);
        assert_eq!(cc.cwnd(), 3000);
        ack(&mut cc, t0 + 200 * MS, 1200, t0 + 120 * MS);
        assert_eq!(cc.cwnd(), 3000);

        // Persistent congestion drops them too, as shown once slow start is back at ssthresh.
        let mut cc = new_reno(&CcConfig::default());
        cc.on_congestion_event(t0 + 10 * MS, t0, CongestionSignal::Loss);
        ack(&mut cc, t0 + 100 * MS, 4800, t0 + 20 * MS);
        cc.on_persistent_congestion();
        ack(&mut cc, t0 + 200 * MS, 3600, t0 + 120 * MS);
        assert_eq!(cc.cwnd(), 6000);
        ack(&mut cc, t0 + 210 * MS, 1200, t0 + 120 * MS);
        assert_eq!(cc.cwnd(), 6000);
    }

    #[test]
    fn one_recovery_period_reduces_the_window_once() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        // Recovery starts at 100 ms.
        cc.on_congestion_event(t0 + 100 * MS, t0 + 50 * MS, CongestionSignal::Loss);
        assert_eq!(cc.cwnd(), 6000);
        // Acknowledgments of packets sent before it do not grow the window...
        ack(&mut cc, t0 + 150 * MS, 6000, t0 + 90 * MS);
        assert_eq!(cc.cwnd(), 6000);
        // ...and losses of such packets do not reduce it again.
        cc.on_congestion_event(t0 + 160 * MS, t0 + 100 * MS, CongestionSignal::Loss);
        assert_eq!(cc.cwnd(), 6000);
        // A packet sent after it ends the period.
        ack(&mut cc, t0 + 250 * MS, 6000, t0 + 120 * MS);
        assert_eq!(cc.cwnd(), 7200);
        // The loss of a packet sent after the start is a new congestion event.
        cc.on_congestion_event(t0 + 260 * MS, t0 + 110 * MS, CongestionSignal::Loss);
        assert_eq!((cc.cwnd(), cc.ssthresh()), (3600, 3600));
    }

    #[test]
    fn persistent_congestion_restarts_slow_start_from_the_minimum() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        cc.on_congestion_event(t0 + 100 * MS, t0 + 50 * MS, CongestionSignal::Loss);
        cc.on_persistent_congestion();
        assert_eq!((cc.cwnd(), cc.ssthresh()), (2400, 6000));
        // The recovery period is over: even a packet sent before it grows the window.
        ack(&mut cc, t0 + 150 * MS, 1200, t0 + 90 * MS);
        assert_eq!(cc.cwnd(), 3600);
        // Slow start stops at ssthresh; the rest counts toward congestion avoidance.
        ack(&mut cc, t0 + 300 * MS, 4800, t0 + 200 * MS);
        assert_eq!(cc.cwnd(), 6000);
        ack(&mut cc, t0 + 301 * MS, 3600, t0 + 200 * MS);
        assert_eq!(cc.cwnd(), 7200);
    }

    #[test]
    fn an_application_limited_sender_does_not_grow_the_window() {
        let t0 = crate::recovery::test_epoch();
        let mut cc = new_reno(&CcConfig::default());
        cc.on_ack(&AckEvent {
            now: t0 + 100 * MS,
            acked_bytes: 6000,
            acked_in_recovery: 0,
            largest_acked_sent: t0,
            rtt: 100 * MS,
            rtt_sample: None,
            app_limited: true,
        });
        assert_eq!(cc.cwnd(), 12_000);
    }
}
