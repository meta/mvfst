/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Received-packet tracking for one packet number space: the ranges an ACK frame reports,
//! duplicate detection, ECN counts and the once-per-batch "ACK due" decision (RFC 9000).

#[cfg(test)]
use std::cell::Cell;
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use super::Space;
use crate::AckPolicy;
use crate::receive::Ecn;

/// The ECN counts of one space, reported in ACK_ECN frames (RFC 9000).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EcnCounts {
    /// Packets received with ECT(0).
    pub ect0: u64,
    /// Packets received with ECT(1).
    pub ect1: u64,
    /// Packets received with CE.
    pub ce: u64,
}

/// Whether an ACK frame is due in a space, evaluated once per receive batch (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckDue {
    /// The space has not received a packet since the last ACK frame.
    None,
    /// Only packets that are not ack-eliciting arrived: an ACK may join a packet sent for another
    /// reason but must not start one (RFC 9000).
    Piggyback,
    /// Ack-eliciting packets wait; an ACK must start a packet by this time and may join one
    /// before.
    At(Instant),
    /// An ACK must be sent now.
    Now,
}

/// The packets received in one space, and what that means for the next ACK frame.
#[derive(Clone, Debug)]
pub struct ReceivedPackets {
    space: Space,
    /// Disjoint, non-adjacent inclusive ranges in ascending order.
    ranges: VecDeque<(u64, u64)>,
    max_ranges: usize,
    /// The packet number below which packets were in dropped ranges and count as duplicates.
    floor: u64,
    /// The packet number below which packets were in an ACK frame the peer acknowledged and are not
    /// reported.
    report_floor: u64,
    ecn: EcnCounts,
    /// Whether any packet arrived since the last ACK frame was sent.
    unacked: bool,
    /// Ack-eliciting packets that arrived since the last ACK frame was sent.
    unacked_eliciting: u32,
    /// When the first of those arrived.
    first_unacked_eliciting: Option<Instant>,
    /// Whether a packet that arrived since the last ACK frame is to be acknowledged at once.
    immediate: bool,
    /// The largest ack-eliciting packet number received.
    largest_eliciting: Option<u64>,
    /// The largest packet number received and when it arrived.
    largest: Option<(u64, Instant)>,
    /// Searches of the ranges, for tests of their cost.
    #[cfg(test)]
    searches: Cell<u64>,
}

impl ReceivedPackets {
    /// Creates the tracking for `space`, which keeps at most `max_ranges` ranges (at least 1) and
    /// drops the oldest first. The ranges take no memory until a packet arrives.
    pub fn new(space: Space, max_ranges: usize) -> Self {
        let max_ranges = max_ranges.max(1);
        Self {
            space,
            ranges: VecDeque::new(),
            max_ranges,
            floor: 0,
            report_floor: 0,
            ecn: EcnCounts::default(),
            unacked: false,
            unacked_eliciting: 0,
            first_unacked_eliciting: None,
            immediate: false,
            largest_eliciting: None,
            largest: None,
            #[cfg(test)]
            searches: Cell::new(0),
        }
    }

    /// Records a decrypted packet, or returns `false` without recording it if it is a duplicate.
    pub fn on_packet(&mut self, pn: u64, ack_eliciting: bool, ecn: Ecn, rx_time: Instant) -> bool {
        if !self.insert(pn) {
            return false;
        }
        match ecn {
            Ecn::NotEct => {}
            Ecn::Ect0 => self.ecn.ect0 += 1,
            Ecn::Ect1 => self.ecn.ect1 += 1,
            Ecn::Ce => self.ecn.ce += 1,
        }
        self.unacked = true;
        if self.largest.is_none_or(|(largest, _)| pn > largest) {
            self.largest = Some((pn, rx_time));
        }
        if ack_eliciting {
            self.unacked_eliciting += 1;
            self.first_unacked_eliciting.get_or_insert(rx_time);
            // Initial and Handshake packets are never acknowledged late, as RFC 9000 requires; it
            // recommends the same on reordering, a gap or a CE mark to speed the peer's response.
            if self.space != Space::Data || ecn == Ecn::Ce || self.reorders_or_gaps(pn) {
                self.immediate = true;
            }
            self.largest_eliciting = self.largest_eliciting.max(Some(pn));
        }
        while self.ranges.len() > self.max_ranges
            && let Some((_, end)) = self.ranges.pop_front()
        {
            self.floor = end + 1;
        }
        true
    }

    /// Returns whether `pn` was already received; if so, the packet must not be processed again.
    pub fn is_duplicate(&self, pn: u64) -> bool {
        if pn < self.floor {
            return true;
        }
        // The common case: a packet above every one received.
        if self.ranges.back().is_none_or(|&(_, end)| pn > end) {
            return false;
        }
        let i = self.search(pn);
        i < self.ranges.len() && self.ranges[i].0 <= pn
    }

    /// Returns whether the newly recorded ack-eliciting `pn` is below the largest ack-eliciting
    /// packet received, or above it with a packet missing in between.
    fn reorders_or_gaps(&self, pn: u64) -> bool {
        let Some(largest) = self.largest_eliciting else {
            return false;
        };
        if pn < largest {
            return true;
        }
        // `pn` was just recorded, so a range holds it (the newest one when packets arrive in
        // order); every packet down to `largest` has arrived exactly when that range reaches it.
        let start = match self.ranges.back() {
            Some(&(start, end)) if (start..=end).contains(&pn) => Some(start),
            _ => self.ranges.get(self.search(pn)).map(|&(start, _)| start),
        };
        start.is_none_or(|start| start > largest)
    }

    /// Returns the index of the first range that ends at or above `pn`.
    fn search(&self, pn: u64) -> usize {
        #[cfg(test)]
        {
            self.searches.set(self.searches.get() + 1);
        }
        self.ranges.partition_point(|&(_, end)| end < pn)
    }

    /// Adds `pn` to the ranges, or returns `false` if it is already there.
    fn insert(&mut self, pn: u64) -> bool {
        if pn < self.floor {
            return false;
        }
        // The common case: the next packet in order extends the newest range.
        match self.ranges.back_mut() {
            Some(last) if pn == last.1 + 1 => {
                last.1 = pn;
                return true;
            }
            Some(last) if pn > last.1 + 1 => {
                self.reserve_range();
                self.ranges.push_back((pn, pn));
                return true;
            }
            None => {
                self.reserve_range();
                self.ranges.push_back((pn, pn));
                return true;
            }
            Some(_) => {}
        }
        if self.is_duplicate(pn) {
            return false;
        }
        let i = self.search(pn);
        let joins_prev = i > 0 && self.ranges[i - 1].1 + 1 == pn;
        let joins_next = i < self.ranges.len() && self.ranges[i].0 == pn + 1;
        match (joins_prev, joins_next) {
            (true, true) => {
                self.ranges[i - 1].1 = self.ranges[i].1;
                self.ranges.remove(i);
            }
            (true, false) => self.ranges[i - 1].1 = pn,
            (false, true) => self.ranges[i].0 = pn,
            (false, false) => {
                self.reserve_range();
                self.ranges.insert(i, (pn, pn));
            }
        }
        true
    }

    /// Makes room for one more range: the room doubles from 4 up to `max_ranges + 1`, the most
    /// ranges held at once, because `on_packet` adds a range before it drops the oldest.
    fn reserve_range(&mut self) {
        let len = self.ranges.len();
        if len == self.ranges.capacity() {
            // `on_packet` leaves at most `max_ranges` ranges, so `room > len`.
            let room = (len * 2).max(4).min(self.max_ranges + 1);
            self.ranges.reserve_exact(room - len);
        }
    }

    /// Returns whether an ACK frame is due at `now`, acknowledging once as many ack-eliciting
    /// packets wait as `policy` sets for the largest packet number received, and at most `delay`
    /// after the first of them arrived. The caller evaluates it once per receive batch, after
    /// recording every packet in it.
    pub fn ack_due(&self, now: Instant, policy: &AckPolicy, delay: Duration) -> AckDue {
        if let Some(first) = self.first_unacked_eliciting {
            let past_init = self
                .largest
                .is_some_and(|(largest, _)| largest > policy.init_threshold);
            let threshold = if past_init {
                policy.after_init
            } else {
                policy.before_init
            };
            let deadline = first + delay;
            if self.immediate || self.unacked_eliciting >= u32::from(threshold) || now >= deadline {
                return AckDue::Now;
            }
            return AckDue::At(deadline);
        }
        if self.unacked {
            AckDue::Piggyback
        } else {
            AckDue::None
        }
    }

    /// Resets the ACK-due decision when an ACK frame that covers the packets so far is sealed.
    pub fn on_ack_sent(&mut self) {
        self.unacked = false;
        self.unacked_eliciting = 0;
        self.first_unacked_eliciting = None;
        self.immediate = false;
    }

    /// Returns the largest packet number received and when it arrived.
    pub fn largest(&self) -> Option<(u64, Instant)> {
        self.largest
    }

    /// Returns the ACK Delay to report at `now`: the time since the largest packet arrived
    /// (RFC 9000).
    pub fn ack_delay(&self, now: Instant) -> Duration {
        self.largest
            .map_or(Duration::ZERO, |(_, at)| now.saturating_duration_since(at))
    }

    /// Returns the ECN counts of the packets processed so far.
    pub fn ecn_counts(&self) -> EcnCounts {
        self.ecn
    }

    /// Lets later ACK frames leave out packets up to `largest`, as RFC 9000 allows once a packet
    /// carrying our ACK frame with that Largest Acknowledged is acknowledged. Those packets still
    /// count as duplicates.
    pub fn on_ack_frame_acked(&mut self, largest: u64) {
        self.report_floor = self.report_floor.max(largest + 1);
    }

    /// Returns how many times the ranges were searched.
    #[cfg(test)]
    pub(crate) fn searches(&self) -> u64 {
        self.searches.get()
    }

    /// Returns how many ranges fit in the memory the ranges hold.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.ranges.capacity()
    }

    /// Returns the ranges to acknowledge, largest first, as the ACK encoder takes them. The
    /// iterator is `Clone` because the encoder walks the ranges twice.
    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + Clone + '_ {
        let largest = self.ranges.back().map_or(0, |&(_, end)| end);
        let floor = self.report_floor.min(largest);
        self.ranges
            .iter()
            .rev()
            .take_while(move |&&(_, end)| end >= floor)
            .map(move |&(start, end)| start.max(floor)..=end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(r: &ReceivedPackets) -> Vec<RangeInclusive<u64>> {
        r.ranges().collect()
    }

    fn receive(r: &mut ReceivedPackets, t: Instant, pns: &[u64]) {
        for &pn in pns {
            assert!(
                r.on_packet(pn, true, Ecn::NotEct, t),
                "{pn} reported duplicate"
            );
        }
    }

    #[test]
    fn packets_are_merged_into_ranges_reported_largest_first() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        receive(&mut r, t0, &[10, 11, 12, 15, 14, 20, 18, 13]);
        assert_eq!(ranges(&r), vec![20..=20, 18..=18, 10..=15]);
        receive(&mut r, t0, &[19, 5]);
        assert_eq!(ranges(&r), vec![18..=20, 10..=15, 5..=5]);
    }

    #[test]
    fn duplicates_are_detected_and_not_recorded() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        receive(&mut r, t0, &[1, 2, 3, 7, 8]);
        for pn in [1, 2, 3, 7, 8] {
            assert!(r.is_duplicate(pn));
            assert!(!r.on_packet(pn, true, Ecn::NotEct, t0));
        }
        assert!(!r.is_duplicate(5));
        assert_eq!(ranges(&r), vec![7..=8, 1..=3]);
    }

    #[test]
    fn the_oldest_ranges_are_dropped_and_their_packets_count_as_duplicates() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 3);
        receive(&mut r, t0, &[1, 3, 5, 7]);
        assert_eq!(ranges(&r), vec![7..=7, 5..=5, 3..=3]);
        // Packets in or below the dropped range are never accepted again, as RFC 9000 requires.
        assert!(r.is_duplicate(0));
        assert!(r.is_duplicate(1));
        assert!(!r.on_packet(1, true, Ecn::NotEct, t0));
        assert!(!r.is_duplicate(2));
        receive(&mut r, t0, &[11]);
        assert_eq!(ranges(&r), vec![11..=11, 7..=7, 5..=5]);
        // An out-of-order packet that adds a range in the middle also drops the oldest.
        receive(&mut r, t0, &[9]);
        assert_eq!(ranges(&r), vec![11..=11, 9..=9, 7..=7]);
        assert!(r.is_duplicate(5));
        assert!(!r.is_duplicate(6));
        assert!(!r.is_duplicate(8));
    }

    /// Takes the ranges with the bounds of the ACK encoder (`mvfstr_wire::PacketWriter::ack`) and
    /// walks the older ones twice, as it does: once to count them, once to collect them.
    fn encode<I>(largest: RangeInclusive<u64>, older: I) -> (usize, Vec<RangeInclusive<u64>>)
    where
        I: IntoIterator<Item = RangeInclusive<u64>>,
        I::IntoIter: Clone,
    {
        let older = older.into_iter();
        let count = older.clone().count();
        (count, std::iter::once(largest).chain(older).collect())
    }

    #[test]
    fn the_ranges_feed_the_ack_encoder_without_a_copy() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        receive(&mut r, t0, &[1, 2, 5, 6, 9]);
        let mut it = r.ranges();
        let largest = it.next().unwrap();
        assert_eq!(encode(largest, it), (2, vec![9..=9, 5..=6, 1..=2]));
    }

    #[test]
    fn ranges_covered_by_an_acknowledged_ack_frame_are_no_longer_reported() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        receive(&mut r, t0, &[1, 2, 3, 4, 5, 8, 9, 10]);
        r.on_ack_frame_acked(4);
        assert_eq!(ranges(&r), vec![8..=10, 5..=5]);
        assert!(r.is_duplicate(2));
        // The largest received packet is always reported (RFC 9000).
        r.on_ack_frame_acked(10);
        assert_eq!(ranges(&r), vec![10..=10]);
        receive(&mut r, t0, &[11]);
        assert_eq!(ranges(&r), vec![11..=11]);
        // An older ACK frame acknowledged late leaves the ranges unchanged.
        r.on_ack_frame_acked(4);
        assert_eq!(ranges(&r), vec![11..=11]);
    }

    #[test]
    fn ecn_counts_grow_once_per_processed_packet() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        for (pn, ecn) in [(1, Ecn::Ect0), (2, Ecn::Ect0), (3, Ecn::Ect1), (4, Ecn::Ce)] {
            assert!(r.on_packet(pn, false, ecn, t0));
        }
        assert!(r.on_packet(5, false, Ecn::NotEct, t0));
        // Duplicates are not processed and do not count (RFC 9000).
        assert!(!r.on_packet(4, false, Ecn::Ce, t0));
        assert_eq!(
            r.ecn_counts(),
            EcnCounts {
                ect0: 2,
                ect1: 1,
                ce: 1
            }
        );
    }

    const MS: Duration = Duration::from_millis(1);

    /// Returns a policy that acknowledges once `threshold` ack-eliciting packets wait, whatever
    /// the largest packet number received.
    fn threshold(threshold: u16) -> AckPolicy {
        AckPolicy {
            before_init: threshold,
            after_init: threshold,
            ..AckPolicy::default()
        }
    }

    #[test]
    fn the_threshold_switches_once_the_largest_packet_number_passes_the_init_threshold() {
        let t0 = crate::recovery::test_epoch();
        let policy = AckPolicy {
            init_threshold: 20,
            before_init: 3,
            after_init: 6,
            ..AckPolicy::default()
        };
        // Records the in-order ack-eliciting packets `pns` as one batch and decides once.
        let batch = |r: &mut ReceivedPackets, pns: RangeInclusive<u64>| {
            for pn in pns {
                assert!(
                    r.on_packet(pn, true, Ecn::NotEct, t0),
                    "{pn} reported duplicate"
                );
            }
            r.ack_due(t0, &policy, 25 * MS)
        };
        let waits = AckDue::At(t0 + 25 * MS);

        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert_eq!(batch(&mut r, 0..=17), AckDue::Now);
        r.on_ack_sent();
        assert_eq!(batch(&mut r, 18..=19), waits);
        // Three wait and the largest packet number is the init threshold, not above it.
        assert_eq!(batch(&mut r, 20..=20), AckDue::Now);
        r.on_ack_sent();
        // Above the init threshold, three to five waiting packets are not enough; six are.
        assert_eq!(batch(&mut r, 21..=23), waits);
        assert_eq!(batch(&mut r, 24..=25), waits);
        assert_eq!(batch(&mut r, 26..=26), AckDue::Now);

        // The threshold follows the largest packet number when the batch is decided, so packets
        // that arrived at or below the init threshold count toward the larger one.
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert_eq!(batch(&mut r, 0..=18), AckDue::Now);
        r.on_ack_sent();
        assert_eq!(batch(&mut r, 19..=20), waits);
        assert_eq!(batch(&mut r, 21..=21), waits);
        assert_eq!(batch(&mut r, 22..=24), AckDue::Now);
    }

    #[test]
    fn no_ack_is_due_without_packets_and_none_starts_for_non_eliciting_ones() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert_eq!(r.ack_due(t0, &threshold(2), 25 * MS), AckDue::None);
        for pn in 1..=5 {
            assert!(r.on_packet(pn, false, Ecn::NotEct, t0));
        }
        assert_eq!(
            r.ack_due(t0 + 100 * MS, &threshold(2), 25 * MS),
            AckDue::Piggyback
        );
    }

    #[test]
    fn ack_eliciting_packets_make_an_ack_due_at_the_threshold_or_after_the_delay() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert!(r.on_packet(1, false, Ecn::NotEct, t0));
        assert!(r.on_packet(2, true, Ecn::NotEct, t0 + MS));
        assert!(r.on_packet(3, false, Ecn::NotEct, t0 + 2 * MS));
        // One ack-eliciting packet: due max_ack_delay after it arrived.
        assert_eq!(
            r.ack_due(t0 + 2 * MS, &threshold(2), 25 * MS),
            AckDue::At(t0 + 26 * MS)
        );
        assert_eq!(r.ack_due(t0 + 26 * MS, &threshold(2), 25 * MS), AckDue::Now);
        // A second one reaches the threshold.
        assert!(r.on_packet(4, true, Ecn::NotEct, t0 + 3 * MS));
        assert_eq!(r.ack_due(t0 + 3 * MS, &threshold(2), 25 * MS), AckDue::Now);
        assert_eq!(
            r.ack_due(t0 + 3 * MS, &threshold(3), 25 * MS),
            AckDue::At(t0 + 26 * MS)
        );
    }

    #[test]
    fn ack_eliciting_initial_and_handshake_packets_are_acknowledged_at_once() {
        let t0 = crate::recovery::test_epoch();
        for space in [Space::Initial, Space::Handshake] {
            let mut r = ReceivedPackets::new(space, 32);
            assert!(r.on_packet(0, false, Ecn::NotEct, t0));
            assert_eq!(
                r.ack_due(t0, &threshold(2), 25 * MS),
                AckDue::Piggyback,
                "{space:?}"
            );
            assert!(r.on_packet(1, true, Ecn::NotEct, t0));
            assert_eq!(
                r.ack_due(t0, &threshold(2), 25 * MS),
                AckDue::Now,
                "{space:?}"
            );
        }
    }

    /// Feeds `(pn, ack_eliciting)` packets to a fresh 1-RTT tracker with a threshold of 10 and
    /// returns whether an ACK is due at once.
    fn due_now_after(packets: &[(u64, bool)]) -> bool {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        for &(pn, eliciting) in packets {
            assert!(r.on_packet(pn, eliciting, Ecn::NotEct, t0));
        }
        r.ack_due(t0, &threshold(10), 25 * MS) == AckDue::Now
    }

    #[test]
    fn reordered_or_gapped_ack_eliciting_packets_are_acknowledged_at_once() {
        // In order, including through a received non-eliciting packet: an ACK is not due at once.
        assert!(!due_now_after(&[(1, true), (2, true)]));
        assert!(!due_now_after(&[(1, true), (2, false), (3, true)]));
        assert!(!due_now_after(&[(1, false), (2, false), (3, true)]));
        // Smaller than an ack-eliciting packet already received.
        assert!(due_now_after(&[(2, true), (1, true)]));
        // Larger than the largest ack-eliciting packet with packets missing in between.
        assert!(due_now_after(&[(1, true), (2, true), (4, true)]));
        assert!(due_now_after(&[(1, true), (3, false), (5, true)]));
        // A non-eliciting packet never makes an ACK due.
        assert!(!due_now_after(&[(1, true), (3, false)]));
    }

    #[test]
    fn in_order_packets_are_recorded_without_searching() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert!(r.on_packet(0, true, Ecn::NotEct, t0));
        let before = r.searches();
        // Each packet is checked for a duplicate before it is recorded, as a connection does.
        for pn in 1..=100 {
            assert!(!r.is_duplicate(pn), "{pn} reported duplicate");
            assert!(r.on_packet(pn, true, Ecn::NotEct, t0));
        }
        assert_eq!(ranges(&r), vec![0..=100]);
        assert_eq!(
            r.ack_due(t0, &threshold(u16::MAX), 25 * MS),
            AckDue::At(t0 + 25 * MS),
            "an in-order packet made an ACK due at once"
        );
        assert_eq!(r.searches() - before, 0);
    }

    /// Feeds `(pn, ack_eliciting)` packets to a fresh 1-RTT tracker with a threshold of 10, the
    /// last one checked for a duplicate first, as a connection does. Returns whether an ACK is due
    /// at once and how many searches were made for the last packet.
    fn due_now_and_searches(packets: &[(u64, bool)]) -> (bool, u64) {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        let (&(last, eliciting), earlier) = packets.split_last().expect("a packet");
        for &(pn, eliciting) in earlier {
            assert!(r.on_packet(pn, eliciting, Ecn::NotEct, t0));
        }
        let before = r.searches();
        assert!(!r.is_duplicate(last), "{last} reported duplicate");
        assert!(r.on_packet(last, eliciting, Ecn::NotEct, t0));
        (
            r.ack_due(t0, &threshold(10), 25 * MS) == AckDue::Now,
            r.searches() - before,
        )
    }

    #[test]
    fn a_back_range_that_starts_above_the_largest_eliciting_packet_is_a_gap() {
        // Each case gives whether an ACK is due at once and the searches made for the last packet.
        let cases = [
            // The newest range holds the new packet but starts at a non-eliciting packet above
            // the largest ack-eliciting one, so a packet between them is missing.
            due_now_and_searches(&[(1, true), (3, false), (4, true)]),
            due_now_and_searches(&[(1, false), (2, true), (4, false), (5, true)]),
            // The range runs from the largest ack-eliciting packet through non-eliciting ones.
            due_now_and_searches(&[(1, true), (2, false), (3, false), (4, true)]),
            // The new packet opens the newest range above a gap.
            due_now_and_searches(&[(1, true), (2, true), (4, true)]),
        ];
        assert_eq!(cases, [(true, 0), (true, 0), (false, 0), (true, 0)]);
        // Below a newer non-eliciting packet, the range that holds the new packet decides.
        assert!(!due_now_and_searches(&[(1, true), (5, false), (2, true)]).0);
        assert!(due_now_and_searches(&[(1, true), (5, false), (3, true)]).0);
    }

    #[test]
    fn a_ce_marked_ack_eliciting_packet_is_acknowledged_at_once() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        // Not for a non-eliciting packet: that would answer it with an ACK-only packet.
        assert!(r.on_packet(1, false, Ecn::Ce, t0));
        assert_eq!(r.ack_due(t0, &threshold(10), 25 * MS), AckDue::Piggyback);
        assert!(r.on_packet(2, true, Ecn::Ce, t0));
        assert_eq!(r.ack_due(t0, &threshold(10), 25 * MS), AckDue::Now);
    }

    #[test]
    fn sending_an_ack_resets_the_decision_but_keeps_the_ranges() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert!(r.on_packet(1, true, Ecn::NotEct, t0));
        assert!(r.on_packet(3, true, Ecn::NotEct, t0));
        assert_eq!(r.ack_due(t0, &threshold(10), 25 * MS), AckDue::Now);
        r.on_ack_sent();
        assert_eq!(
            r.ack_due(t0 + 30 * MS, &threshold(10), 25 * MS),
            AckDue::None
        );
        assert_eq!(ranges(&r), vec![3..=3, 1..=1]);
        assert!(r.on_packet(4, false, Ecn::NotEct, t0 + 40 * MS));
        assert_eq!(
            r.ack_due(t0 + 40 * MS, &threshold(10), 25 * MS),
            AckDue::Piggyback
        );
        // The delay runs from the first ack-eliciting packet after the ACK.
        assert!(r.on_packet(5, true, Ecn::NotEct, t0 + 50 * MS));
        assert_eq!(
            r.ack_due(t0 + 50 * MS, &threshold(10), 25 * MS),
            AckDue::At(t0 + 75 * MS)
        );
    }

    #[test]
    fn the_ranges_start_empty_and_grow_by_doubling_to_one_past_the_maximum() {
        let t0 = crate::recovery::test_epoch();
        // 1,000 packets with a gap after each one: the even numbers below 2,000, in blocks whose
        // largest packet arrives first. Blocks of two make every growth happen at the back. Blocks
        // of three add the other two ranges of a block in the middle, and from the second growth
        // on, the ranges grow there.
        let evens: Vec<u64> = (0..1000).map(|i| 2 * i).collect();
        for (max_ranges, growth) in [(32, &[0, 4, 8, 16, 32, 33][..]), (3, &[0, 4]), (1, &[0, 2])] {
            for block in [2, 3] {
                let case = format!("{max_ranges} ranges, blocks of {block}");
                let mut r = ReceivedPackets::new(Space::Data, max_ranges);
                let mut capacities = vec![r.capacity()];
                for chunk in evens.chunks(block) {
                    let (largest, earlier) = chunk.split_last().expect("a block holds a packet");
                    for pn in std::iter::once(largest).chain(earlier) {
                        assert!(
                            r.on_packet(*pn, true, Ecn::NotEct, t0),
                            "{case}: {pn} reported duplicate"
                        );
                        let capacity = r.capacity();
                        assert!(
                            capacity <= max_ranges + 1,
                            "{case}: room for {capacity} ranges after {pn}"
                        );
                        if capacities.last() != Some(&capacity) {
                            capacities.push(capacity);
                        }
                    }
                }
                assert_eq!(capacities, growth, "{case}: the capacities in turn");
                // The newest ranges are reported, and the packets of dropped ranges count as
                // duplicates.
                let oldest = 2000 - 2 * max_ranges as u64;
                let kept: Vec<_> = (0..max_ranges as u64)
                    .map(|i| 1998 - 2 * i)
                    .map(|pn| pn..=pn)
                    .collect();
                assert_eq!(ranges(&r), kept, "{case}");
                assert!(r.is_duplicate(oldest - 2), "{case}");
                assert!(!r.on_packet(oldest - 2, true, Ecn::NotEct, t0), "{case}");
                assert!(!r.is_duplicate(oldest - 1), "{case}");
                assert!(!r.is_duplicate(1999), "{case}");
            }
        }
    }

    #[test]
    fn the_ack_delay_runs_from_the_arrival_of_the_largest_packet() {
        let t0 = crate::recovery::test_epoch();
        let mut r = ReceivedPackets::new(Space::Data, 32);
        assert_eq!(r.largest(), None);
        assert!(r.on_packet(5, true, Ecn::NotEct, t0 + MS));
        assert!(r.on_packet(3, true, Ecn::NotEct, t0 + 2 * MS));
        assert_eq!(r.largest(), Some((5, t0 + MS)));
        assert_eq!(r.ack_delay(t0 + 10 * MS), 9 * MS);
        assert!(r.on_packet(6, false, Ecn::NotEct, t0 + 3 * MS));
        assert_eq!(r.largest(), Some((6, t0 + 3 * MS)));
        assert_eq!(r.ack_delay(t0 + 10 * MS), 7 * MS);
    }
}
