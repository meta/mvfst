/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Delivery of control frames: s2n-quic's machines, each `Idle → Pending → InFlight → Delivered`,
//! where a loss returns a frame to `Pending` only if its value is still current.
//!
//! [`IncrementalValue`] carries a monotonic value: MAX_STREAMS, DATA_BLOCKED and STREAMS_BLOCKED
//! here. The receive windows of `flow_control` are the same machine for MAX_DATA and
//! MAX_STREAM_DATA (a pending flag and the limit last advertised, with the same loss rule). The
//! valueless machine of a per-stream RESET_STREAM or STOP_SENDING is the stream guard's `Owed`
//! bit for `Pending` and the stream's half state for the rest: the frame is current while the
//! half state still permits it.

/// Where a control frame's latest value is on its way to the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Delivery {
    /// Not to be sent.
    Idle,
    /// To be sent.
    Pending,
    /// Written into a packet, not yet acknowledged or lost.
    InFlight,
    /// Acknowledged.
    Delivered,
}

/// The delivery of a frame whose value only rises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct IncrementalValue {
    value: u64,
    state: Delivery,
}

impl IncrementalValue {
    /// Returns a machine that does not have a value to send.
    pub(crate) const fn idle() -> Self {
        Self {
            value: 0,
            state: Delivery::Idle,
        }
    }

    /// Returns a machine whose `value` the peer already has, as from a transport parameter.
    pub(crate) const fn delivered(value: u64) -> Self {
        Self {
            value,
            state: Delivery::Delivered,
        }
    }

    /// Returns the latest value and its delivery state.
    #[cfg(test)]
    pub(crate) fn state(&self) -> (u64, Delivery) {
        (self.value, self.state)
    }

    /// Makes `value` the one to send if it is larger than the latest, or if the machine is idle;
    /// returns whether it became pending.
    pub(crate) fn raise(&mut self, value: u64) -> bool {
        if value <= self.value && self.state != Delivery::Idle {
            return false;
        }
        self.value = value;
        self.state = Delivery::Pending;
        true
    }

    /// Returns the value to send, if one is pending.
    pub(crate) fn pending(&self) -> Option<u64> {
        (self.state == Delivery::Pending).then_some(self.value)
    }

    /// Records that a frame carrying `value` was written into a packet.
    pub(crate) fn on_written(&mut self, value: u64) {
        if value == self.value && self.state == Delivery::Pending {
            self.state = Delivery::InFlight;
        }
    }

    /// Records that a packet carrying `value` was acknowledged. If `value` is still the latest,
    /// the peer has it, even if it was declared lost and made pending again.
    pub(crate) fn on_acked(&mut self, value: u64) {
        if value == self.value && matches!(self.state, Delivery::InFlight | Delivery::Pending) {
            self.state = Delivery::Delivered;
        }
    }

    /// Records that a packet carrying `value` was lost; the frame is pending again if `value` is
    /// still the latest and another copy has not delivered it. Returns whether it became pending.
    pub(crate) fn on_lost(&mut self, value: u64) -> bool {
        if value != self.value || self.state != Delivery::InFlight {
            return false;
        }
        self.state = Delivery::Pending;
        true
    }

    /// Stops delivering the latest value, which is no longer worth sending, as for a blocked frame
    /// once the limit rose.
    pub(crate) fn cancel(&mut self) {
        self.state = Delivery::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raised_value_is_pending_until_written_and_delivered_once_acknowledged() {
        let mut v = IncrementalValue::delivered(10);
        assert_eq!(v.pending(), None);
        assert!(!v.raise(10), "the peer has 10 already");
        assert!(v.raise(15));
        assert_eq!(v.pending(), Some(15));
        assert_eq!(v.state(), (15, Delivery::Pending));
        // A larger value before the write replaces it.
        assert!(v.raise(20));
        assert_eq!(v.pending(), Some(20));
        v.on_written(20);
        assert_eq!(v.pending(), None);
        assert_eq!(v.state(), (20, Delivery::InFlight));
        v.on_acked(20);
        assert_eq!(v.state(), (20, Delivery::Delivered));
        let mut blocked = IncrementalValue::idle();
        assert!(blocked.raise(0), "an idle machine sends even a zero value");
        assert_eq!(blocked.pending(), Some(0));
    }

    #[test]
    fn a_loss_returns_the_frame_to_pending_only_while_its_value_is_current() {
        let mut v = IncrementalValue::delivered(10);
        v.raise(15);
        v.on_written(15);
        assert!(v.on_lost(15), "the latest value in flight goes again");
        assert_eq!(v.pending(), Some(15));
        v.on_written(15);
        // A newer value was raised and sent: the older one's loss does not matter.
        v.raise(20);
        assert!(!v.on_lost(15));
        assert_eq!(v.pending(), Some(20));
        v.on_written(20);
        v.on_acked(20);
        assert!(
            !v.on_lost(20),
            "a value the peer acknowledged is not sent again"
        );
        assert_eq!(v.state(), (20, Delivery::Delivered));
        // A cancelled value is no longer current.
        let mut blocked = IncrementalValue::idle();
        blocked.raise(1000);
        blocked.on_written(1000);
        blocked.cancel();
        assert!(!blocked.on_lost(1000));
        assert_eq!(blocked.pending(), None);
        assert!(
            blocked.raise(1000),
            "blocked again at a limit, it is sent again"
        );
    }

    #[test]
    fn a_late_ack_of_a_lost_value_delivers_it_before_it_goes_again() {
        let mut v = IncrementalValue::delivered(10);
        v.raise(15);
        v.on_written(15);
        assert!(v.on_lost(15));
        assert_eq!(v.pending(), Some(15));
        // The packet declared lost is acknowledged after all, before the value went again.
        v.on_acked(15);
        assert_eq!(v.pending(), None, "the peer has 15");
        assert_eq!(v.state(), (15, Delivery::Delivered));
    }
}
