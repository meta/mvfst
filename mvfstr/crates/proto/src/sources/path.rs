/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Path source: PATH_CHALLENGE and PATH_RESPONSE, with one state machine per path.
//!
//! Slot 0 is the current path and slot 1 the alternate one, the previous path while a migration
//! is validated or an address the peer probes from. Only the latest challenge received on a slot's
//! path is answered, and only once. A slot's validation holds the unpredictable data of up to
//! [`CHALLENGES`] PATH_CHALLENGE frames, drawn when validation starts so that `next` is `Some`
//! only when the bytes exist. The next challenge goes when the latest one is lost or has not been
//! answered within a PTO, doubled for each challenge already sent, and a response matching any
//! data sent validates the path.

use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;

use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::SentFrame;
use crate::transmit::admission::Class;

/// The PATH_CHALLENGE frames one validation may send.
pub(crate) const CHALLENGES: usize = 3;
/// The current path's slot.
pub(crate) const CURRENT: usize = 0;
/// The alternate path's slot.
pub(crate) const ALTERNATE: usize = 1;

/// One path's validation (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Validation {
    data: [[u8; 8]; CHALLENGES],
    /// How many challenges were written.
    sent: usize,
    /// Whether each challenge sent went out in a datagram of at least 1,200 bytes.
    full_size: [bool; CHALLENGES],
    /// Whether a challenge is due.
    pending: bool,
    /// When the next challenge is due if a response has not come by then.
    retry_at: Option<Instant>,
    /// When the validation fails.
    pub(crate) deadline: Instant,
}

/// The PATH_RESPONSE and PATH_CHALLENGE state of one path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct PathSlot {
    /// The data of the latest PATH_CHALLENGE received, still to be answered with a PATH_RESPONSE.
    response: Option<[u8; 8]>,
    pub(crate) validation: Option<Validation>,
}

/// What a Path candidate writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathCand {
    Response([u8; 8]),
    Challenge([u8; 8]),
}

/// The Path source of a connection.
#[derive(Clone, Debug, Default, Hash)]
pub(crate) struct PathSource {
    pub(crate) slots: [PathSlot; 2],
}

impl PathSource {
    /// Starts validating the path of `slot` with challenges carrying `data`, failing at
    /// `deadline`.
    pub(crate) fn validate(&mut self, slot: usize, data: [[u8; 8]; CHALLENGES], deadline: Instant) {
        self.slots[slot].validation = Some(Validation {
            data,
            sent: 0,
            full_size: [false; CHALLENGES],
            pending: true,
            retry_at: None,
            deadline,
        });
    }

    /// Records a PATH_CHALLENGE with `data` that arrived on the path of `slot`; it replaces any
    /// older one not yet answered.
    pub(crate) fn challenged(&mut self, slot: usize, data: [u8; 8]) {
        self.slots[slot].response = Some(data);
    }

    /// Returns the slot whose validation a PATH_RESPONSE with `data` answers, if any, and whether
    /// the challenge it answers went out in a datagram of at least 1,200 bytes.
    pub(crate) fn answered(&self, data: [u8; 8]) -> Option<(usize, bool)> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let validation = slot.validation?;
            let challenge = validation.data[..validation.sent]
                .iter()
                .position(|sent| *sent == data)?;
            Some((index, validation.full_size[challenge]))
        })
    }

    /// Records that a datagram carrying the latest challenge of `slot` was sealed at `now`;
    /// `full_size` is whether it held 1,200 bytes, and `pto` the current PTO.
    pub(crate) fn on_challenge_sealed(
        &mut self,
        slot: usize,
        full_size: bool,
        now: Instant,
        pto: Duration,
    ) {
        if let Some(validation) = &mut self.slots[slot].validation
            && let Some(latest) = validation.sent.checked_sub(1)
        {
            validation.full_size[latest] = full_size;
            validation.retry_at = (validation.sent < CHALLENGES).then(|| now + pto * (1 << latest));
        }
    }

    /// Returns the earliest time an unanswered challenge goes again.
    pub(crate) fn retry_at(&self) -> Option<Instant> {
        self.slots
            .iter()
            .filter_map(|slot| slot.validation?.retry_at)
            .min()
    }

    /// Makes the next challenge due on every path whose latest one has not been answered by `now`.
    pub(crate) fn on_retry_due(&mut self, now: Instant) {
        for validation in self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.validation.as_mut())
        {
            if validation.retry_at.is_some_and(|at| now >= at) {
                validation.retry_at = None;
                validation.pending = true;
            }
        }
    }

    /// Swaps the current and alternate paths' machines.
    pub(crate) fn swap(&mut self) {
        self.slots.swap(CURRENT, ALTERNATE);
    }

    /// Handles the loss of a packet carrying a Path frame of `slot` with `data`: a lost challenge
    /// goes again with the next data while any is left, and a PATH_RESPONSE is not sent again
    /// (RFC 9000).
    pub(crate) fn on_lost(&mut self, kind: ControlKind, slot: usize, data: [u8; 8]) {
        let Some(validation) = self.slots.get_mut(slot).and_then(|s| s.validation.as_mut()) else {
            return;
        };
        if kind == ControlKind::PathChallenge
            && validation.sent > 0
            && validation.data[validation.sent - 1] == data
            && validation.sent < CHALLENGES
        {
            validation.pending = true;
            validation.retry_at = None;
        }
    }

    /// Handles a packet carrying a Path frame of `slot` with `data` that was built but never
    /// sealed: the frame is due again as it was.
    pub(crate) fn on_unsealed(&mut self, kind: ControlKind, slot: usize, data: [u8; 8]) {
        let Some(slot) = self.slots.get_mut(slot) else {
            return;
        };
        match kind {
            ControlKind::PathResponse => {
                slot.response.get_or_insert(data);
            }
            ControlKind::PathChallenge => {
                if let Some(validation) = &mut slot.validation
                    && validation.sent > 0
                    && validation.data[validation.sent - 1] == data
                {
                    validation.sent -= 1;
                    validation.pending = true;
                    validation.retry_at = None;
                }
            }
            _ => {}
        }
    }

    fn slot_of(cx: &SendCx<'_>) -> usize {
        usize::from(cx.path.0).min(ALTERNATE)
    }
}

impl FrameSource for PathSource {
    type Cand = PathCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, PathCand)> {
        if cx.space != Space::Data {
            return None;
        }
        let slot = &self.slots[Self::slot_of(cx)];
        if let Some(data) = slot.response {
            return Some((Class::Response, PathCand::Response(data)));
        }
        let validation = slot.validation.filter(|v| v.pending)?;
        Some((
            Class::Response,
            PathCand::Challenge(validation.data[validation.sent]),
        ))
    }

    fn min_len(&self, _cand: PathCand, _cx: &SendCx<'_>) -> usize {
        Frame::PathChallenge([0; 8]).encoded_len()
    }

    fn write(
        &mut self,
        cand: PathCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let index = Self::slot_of(cx);
        let (frame, kind, data) = match cand {
            PathCand::Response(data) => {
                (Frame::PathResponse(data), ControlKind::PathResponse, data)
            }
            PathCand::Challenge(data) => {
                (Frame::PathChallenge(data), ControlKind::PathChallenge, data)
            }
        };
        w.frame(&frame).map_err(|_| Full)?;
        let slot = &mut self.slots[index];
        match cand {
            PathCand::Response(_) => slot.response = None,
            PathCand::Challenge(_) => {
                if let Some(validation) = &mut slot.validation {
                    validation.sent += 1;
                    validation.pending = false;
                }
                cx.packet.challenge = true;
            }
        }
        cx.packet.path = true;
        cx.sent.push(SentFrame::Control {
            kind,
            key: index as u64,
            value: u64::from_be_bytes(data),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_crypto::TAG_LEN;
    use mvfstr_wire::ConnectionId;
    use mvfstr_wire::HeaderSpec;

    use super::*;
    use crate::PathId;
    use crate::recovery::test_epoch;
    use crate::sources::PacketCx;

    const DATA: [[u8; 8]; CHALLENGES] = [[1; 8], [2; 8], [3; 8]];
    const PTO: Duration = Duration::from_millis(100);

    fn validating(slot: usize) -> PathSource {
        let mut source = PathSource::default();
        source.validate(slot, DATA, test_epoch() + PTO * 10);
        source
    }

    /// Writes the source's next frame on the path of `slot` and returns the frame's record and
    /// whether it was a challenge.
    fn write(source: &mut PathSource, slot: usize) -> Option<((ControlKind, u64, [u8; 8]), bool)> {
        let mut sent = Vec::new();
        let mut cx = SendCx {
            now: test_epoch(),
            space: Space::Data,
            path: PathId(slot as u16),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        let (_, cand) = source.next(&cx)?;
        let header = HeaderSpec::OneRtt {
            dcid: ConnectionId::new(&[1; 8]).unwrap(),
            spin: false,
            key_phase: false,
        };
        let mut buf = vec![0; 256];
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        source.write(cand, &mut w, &mut cx).expect("the frame fits");
        let challenge = cx.packet.challenge;
        assert!(cx.packet.path);
        match sent.pop() {
            Some(SentFrame::Control { kind, key, value }) => {
                Some(((kind, key, value.to_be_bytes()), challenge))
            }
            other => panic!("not a control record: {other:?}"),
        }
    }

    fn challenge(source: &mut PathSource, slot: usize) -> [u8; 8] {
        match write(source, slot) {
            Some(((ControlKind::PathChallenge, key, data), true)) => {
                assert_eq!(key, slot as u64);
                data
            }
            other => panic!("no challenge: {other:?}"),
        }
    }

    #[test]
    fn a_lost_challenge_goes_again_with_the_next_data_three_at_most() {
        let mut source = validating(ALTERNATE);
        for (index, data) in DATA.into_iter().enumerate() {
            assert_eq!(challenge(&mut source, ALTERNATE), data);
            if let Some(earlier) = index.checked_sub(1) {
                source.on_lost(ControlKind::PathChallenge, ALTERNATE, DATA[earlier]);
            }
            assert_eq!(
                write(&mut source, ALTERNATE),
                None,
                "only the latest one's loss"
            );
            source.on_lost(ControlKind::PathChallenge, ALTERNATE, data);
        }
        assert_eq!(write(&mut source, ALTERNATE), None);
        assert_eq!(write(&mut source, CURRENT), None);
    }

    #[test]
    fn a_response_to_any_challenge_sent_validates_and_tells_whether_it_was_full_size() {
        let mut source = validating(CURRENT);
        let now = test_epoch();
        for full_size in [true, false] {
            challenge(&mut source, CURRENT);
            source.on_challenge_sealed(CURRENT, full_size, now, PTO);
            source.on_lost(
                ControlKind::PathChallenge,
                CURRENT,
                DATA[usize::from(!full_size)],
            );
        }
        assert_eq!(source.answered(DATA[0]), Some((CURRENT, true)));
        assert_eq!(source.answered(DATA[1]), Some((CURRENT, false)));
        assert_eq!(source.answered(DATA[2]), None, "never sent");
        assert_eq!(source.answered([9; 8]), None);
    }

    #[test]
    fn an_unsealed_response_or_challenge_is_owed_again_as_it_was() {
        let mut source = validating(ALTERNATE);
        source.challenged(ALTERNATE, [7; 8]);
        let response = write(&mut source, ALTERNATE);
        assert_eq!(
            response,
            Some(((ControlKind::PathResponse, 1, [7; 8]), false))
        );
        source.on_unsealed(ControlKind::PathResponse, ALTERNATE, [7; 8]);
        assert_eq!(write(&mut source, ALTERNATE), response);
        assert_eq!(challenge(&mut source, ALTERNATE), DATA[0]);
        source.on_unsealed(ControlKind::PathChallenge, ALTERNATE, DATA[0]);
        assert_eq!(source.answered(DATA[0]), None, "not sent");
        assert_eq!(challenge(&mut source, ALTERNATE), DATA[0]);
        assert_eq!(write(&mut source, ALTERNATE), None);
    }

    #[test]
    fn a_challenge_in_flight_when_the_slots_swap_is_not_owed_again() {
        let mut source = validating(ALTERNATE);
        assert_eq!(challenge(&mut source, ALTERNATE), DATA[0]);
        source.swap();
        source.validate(ALTERNATE, [[4; 8], [5; 8], [6; 8]], test_epoch() + PTO);
        assert_eq!(challenge(&mut source, ALTERNATE), [4; 8]);
        source.on_lost(ControlKind::PathChallenge, ALTERNATE, DATA[0]);
        source.on_unsealed(ControlKind::PathChallenge, ALTERNATE, DATA[0]);
        assert_eq!(write(&mut source, ALTERNATE), None);
        assert_eq!(write(&mut source, CURRENT), None);
        assert_eq!(source.answered(DATA[0]), Some((CURRENT, false)));
    }

    #[test]
    fn an_unanswered_challenge_goes_again_after_a_pto_doubled_per_challenge_sent() {
        let mut source = validating(CURRENT);
        let mut now = test_epoch();
        assert_eq!(source.retry_at(), None);
        for (index, data) in DATA.into_iter().enumerate() {
            assert_eq!(challenge(&mut source, CURRENT), data);
            source.on_challenge_sealed(CURRENT, true, now, PTO);
            if index + 1 == CHALLENGES {
                assert_eq!(source.retry_at(), None, "the last challenge only fails");
                break;
            }
            let at = now + PTO * (1 << index);
            assert_eq!(source.retry_at(), Some(at));
            source.on_retry_due(at - Duration::from_millis(1));
            assert_eq!(write(&mut source, CURRENT), None);
            source.on_retry_due(at);
            assert_eq!(source.retry_at(), None);
            now = at;
        }
        assert_eq!(write(&mut source, CURRENT), None);
    }

    #[test]
    fn a_loss_or_an_unsealed_challenge_cancels_the_retry() {
        for lost in [true, false] {
            let mut source = validating(CURRENT);
            challenge(&mut source, CURRENT);
            source.on_challenge_sealed(CURRENT, true, test_epoch(), PTO);
            if lost {
                source.on_lost(ControlKind::PathChallenge, CURRENT, DATA[0]);
            } else {
                source.on_unsealed(ControlKind::PathChallenge, CURRENT, DATA[0]);
            }
            assert_eq!(source.retry_at(), None);
            assert_eq!(challenge(&mut source, CURRENT), DATA[usize::from(lost)]);
        }
    }
}
