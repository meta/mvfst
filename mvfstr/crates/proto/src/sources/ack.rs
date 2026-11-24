/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Ack source: the ACK frames of one packet number space (RFC 9000).
//!
//! The ACK decision is made once per receive batch ([`AckSource::decide`]): a due ACK is an
//! AckOnly candidate that may start a packet, one that is not due is a Piggyback candidate that
//! only joins. The tracker's state clears only when a packet carrying the ACK is sealed.

use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::EcnCounts;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::VarInt;

use super::FrameSource;
use super::SendCx;
use crate::receive::Ecn;
use crate::recovery::AckDue;
use crate::recovery::ReceivedPackets;
use crate::recovery::Space;
use crate::recovery::sent::SentFrame;
use crate::transmit::admission::Class;

/// The Ack source of one space.
#[derive(Debug)]
pub(crate) struct AckSource {
    received: ReceivedPackets,
    /// The decision of the last receive batch, or of an ACK deadline since.
    due: AckDue,
    /// Whether an ACK is due again because a packet that carried one was dropped before it left.
    rearmed: bool,
    #[cfg(test)]
    pub(crate) log: AckLog,
}

/// What a test checks ACK frames against: every packet number recorded, and each ACK frame
/// written with the packet numbers recorded when it was.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AckLog {
    pub(crate) received: Vec<u64>,
    pub(crate) frames: Vec<(Vec<std::ops::RangeInclusive<u64>>, Vec<u64>)>,
}

impl AckSource {
    /// Creates the source for `space`, tracking at most `max_ranges` ranges.
    pub(crate) fn new(space: Space, max_ranges: usize) -> Self {
        Self {
            received: ReceivedPackets::new(space, max_ranges),
            due: AckDue::None,
            rearmed: false,
            #[cfg(test)]
            log: AckLog::default(),
        }
    }

    /// Returns the packets received in the space.
    pub(crate) fn received(&self) -> &ReceivedPackets {
        &self.received
    }

    /// Records a decrypted packet; `false` if it is a duplicate.
    pub(crate) fn on_packet(
        &mut self,
        pn: u64,
        ack_eliciting: bool,
        ecn: Ecn,
        rx_time: Instant,
    ) -> bool {
        let fresh = self.received.on_packet(pn, ack_eliciting, ecn, rx_time);
        #[cfg(test)]
        if fresh {
            self.log.received.push(pn);
        }
        fresh
    }

    /// Makes the ACK decision at the end of a receive batch.
    pub(crate) fn decide(&mut self, now: Instant, threshold: u8, delay: Duration) {
        self.due = self.received.ack_due(now, threshold, delay);
    }

    /// Returns when a delayed ACK becomes due, if one is waiting.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match self.due {
            AckDue::At(at) => Some(at),
            AckDue::None | AckDue::Piggyback | AckDue::Now => None,
        }
    }

    /// Makes a delayed ACK due once its deadline passes.
    pub(crate) fn on_deadline(&mut self, now: Instant) {
        if let AckDue::At(at) = self.due
            && at <= now
        {
            self.due = AckDue::Now;
        }
    }

    /// Records that a packet carrying this source's ACK frame was sealed.
    pub(crate) fn on_sealed(&mut self) {
        self.received.on_ack_sent();
        self.due = AckDue::None;
        self.rearmed = false;
    }

    /// Records that an ACK frame of this source with Largest Acknowledged `largest` was
    /// acknowledged, so later ACK frames may leave out packets up to `largest`, as RFC 9000 allows.
    pub(crate) fn on_frame_acked(&mut self, largest: u64) {
        self.received.on_ack_frame_acked(largest);
    }

    /// Sends the ACK again, as a due one, if anything was received.
    pub(crate) fn rearm(&mut self) {
        self.rearmed = self.received.largest().is_some();
    }

    /// Returns the decision, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn state(&self) -> (AckDue, bool) {
        (self.due, self.rearmed)
    }

    /// Returns the fields of the ACK frame released at `cx.release` besides the older ranges: the
    /// largest range, the ACK Delay and the ECN counts; `None` before the space receives a packet.
    fn fields(&self, cx: &SendCx<'_>) -> Option<AckFields> {
        let largest = self.received.ranges().next()?;
        // The time since the largest packet arrived, in units of 2^ack_delay_exponent microseconds.
        let micros =
            u64::try_from(self.received.ack_delay(cx.release).as_micros()).unwrap_or(u64::MAX);
        let delay = VarInt::from_u64(micros >> cx.ack_delay_exponent).unwrap_or(VarInt::MAX);
        let counts = self.received.ecn_counts();
        let ecn = (counts.ect0 + counts.ect1 + counts.ce > 0).then(|| EcnCounts {
            ect0: VarInt::from_u64(counts.ect0).unwrap_or(VarInt::MAX),
            ect1: VarInt::from_u64(counts.ect1).unwrap_or(VarInt::MAX),
            ce: VarInt::from_u64(counts.ce).unwrap_or(VarInt::MAX),
        });
        Some(AckFields {
            largest,
            delay,
            ecn,
        })
    }
}

/// The fields of an ACK frame other than its older ranges.
struct AckFields {
    largest: RangeInclusive<u64>,
    delay: VarInt,
    ecn: Option<EcnCounts>,
}

impl AckFields {
    /// Returns the length of the frame holding only the largest range.
    fn smallest_frame_len(&self) -> usize {
        let varint =
            |value: u64| VarInt::from_u64(value).map_or(VarInt::MAX_SIZE, VarInt::encoded_size);
        let ecn = self.ecn.map_or(0, |e| {
            e.ect0.encoded_size() + e.ect1.encoded_size() + e.ce.encoded_size()
        });
        // The type, Largest Acknowledged, ACK Delay, an ACK Range Count of zero and the First
        // ACK Range.
        1 + varint(*self.largest.end())
            + self.delay.encoded_size()
            + 1
            + varint(self.largest.end() - self.largest.start())
            + ecn
    }
}

impl FrameSource for AckSource {
    type Cand = ();

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ())> {
        if cx.packet.ack.is_some() {
            return None;
        }
        let class = match self.due {
            AckDue::Now => Class::AckOnly,
            _ if self.rearmed => Class::AckOnly,
            AckDue::At(_) | AckDue::Piggyback => Class::Piggyback,
            AckDue::None => return None,
        };
        Some((class, ()))
    }

    fn min_len(&self, _cand: (), cx: &SendCx<'_>) -> usize {
        // Older ranges are left out when they do not fit.
        self.fields(cx)
            .map_or(0, |fields| fields.smallest_frame_len())
    }

    fn write(
        &mut self,
        _cand: (),
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let AckFields {
            largest,
            delay,
            ecn,
        } = self.fields(cx).ok_or(Full)?;
        let top = *largest.end();
        let _written = w.ack(largest, self.received.ranges().skip(1), delay, ecn)?;
        #[cfg(test)]
        self.log.frames.push((
            self.received.ranges().take(_written).collect(),
            self.log.received.clone(),
        ));
        cx.sent.push(SentFrame::Ack { largest: top });
        cx.packet.ack = Some(top);
        Ok(())
    }
}
