/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Crypto source: the CRYPTO frames of one encryption level (RFC 9001).
//!
//! CRYPTO bytes TLS writes at a level go into that level's send buffer, which emits lost
//! bytes before new ones; lost bytes are a Lost candidate and new bytes a Control one. The
//! Application Data level also carries the HANDSHAKE_DONE the server sends once the handshake
//! completes, a frame without fields that has its own delivery state.

use bytes::Bytes;
use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::VarInt;

use super::Adapter;
use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::SentFrame;
use crate::streams::send_buf::FrameKind;
use crate::streams::send_buf::Pending;
use crate::streams::send_buf::PushError;
use crate::streams::send_buf::SendBuffer;
use crate::transmit::admission::Class;

/// The delivery state of HANDSHAKE_DONE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum HandshakeDone {
    /// Not to be sent (yet).
    #[default]
    Idle,
    /// To be sent.
    Pending,
    /// In a sealed packet not yet acknowledged or lost.
    InFlight,
    /// Acknowledged.
    Delivered,
}

/// What a Crypto candidate writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptoCand {
    /// CRYPTO bytes.
    Data,
    /// HANDSHAKE_DONE.
    HandshakeDone,
}

/// The Crypto source of one level.
#[derive(Debug)]
pub(crate) struct CryptoSource {
    level: Space,
    send: SendBuffer,
    handshake_done: HandshakeDone,
}

impl CryptoSource {
    /// Creates an empty source for `level`.
    pub(crate) fn new(level: Space) -> Self {
        Self {
            level,
            send: SendBuffer::new(),
            handshake_done: HandshakeDone::Idle,
        }
    }

    /// Queues CRYPTO bytes TLS wrote at this level.
    pub(crate) fn push(&mut self, data: Bytes) -> Result<(), PushError> {
        self.send.push(data)
    }

    /// Queues HANDSHAKE_DONE.
    pub(crate) fn send_handshake_done(&mut self) {
        self.handshake_done = HandshakeDone::Pending;
    }

    /// Records that CRYPTO bytes `offset..offset + len` were acknowledged.
    pub(crate) fn on_acked(&mut self, offset: u64, len: u16) {
        self.send.on_ack(offset, usize::from(len), false);
    }

    /// Records that CRYPTO bytes `offset..offset + len` were lost; unacknowledged ones go again.
    /// Returns whether any of them became lost.
    pub(crate) fn on_lost(&mut self, offset: u64, len: u16) -> bool {
        self.send.on_lost(offset, usize::from(len), false)
    }

    /// Returns whether lost CRYPTO bytes wait for retransmission.
    pub(crate) fn has_lost(&self) -> bool {
        self.send.has_lost()
    }

    /// Sends every byte sent and not yet acknowledged again, as a PTO probe in a handshake space
    /// carries data rather than only a PING (RFC 9002).
    pub(crate) fn resend_unacked(&mut self) {
        let (acked, sent) = (self.send.acked_end(), self.send.sent_end());
        if sent > acked {
            let len = usize::try_from(sent - acked).unwrap_or(usize::MAX);
            self.send.on_lost(acked, len, false);
        }
    }

    pub(crate) fn on_handshake_done_sealed(&mut self) {
        if self.handshake_done == HandshakeDone::Pending {
            self.handshake_done = HandshakeDone::InFlight;
        }
    }

    pub(crate) fn on_handshake_done_acked(&mut self) {
        self.handshake_done = HandshakeDone::Delivered;
    }

    /// Records that a packet carrying HANDSHAKE_DONE was lost and returns whether the frame became
    /// pending again.
    pub(crate) fn on_handshake_done_lost(&mut self) -> bool {
        let in_flight = self.handshake_done == HandshakeDone::InFlight;
        if in_flight {
            self.handshake_done = HandshakeDone::Pending;
        }
        in_flight
    }

    /// Returns the HANDSHAKE_DONE state.
    #[cfg_attr(
        not(any(test, debug_assertions)),
        expect(dead_code, reason = "tests and the digest read it")
    )]
    pub(crate) fn handshake_done(&self) -> HandshakeDone {
        self.handshake_done
    }

    /// Returns the send buffer's offsets, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn offsets(&self) -> (u64, u64, u64, Option<Pending>) {
        (
            self.send.acked_end(),
            self.send.sent_end(),
            self.send.staged_end(),
            self.send.pending(u64::MAX),
        )
    }
}

impl FrameSource for CryptoSource {
    type Cand = CryptoCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, CryptoCand)> {
        match self.send.pending(u64::MAX) {
            Some(Pending::Retransmit) => return Some((Class::Lost, CryptoCand::Data)),
            Some(Pending::New { .. }) => return Some((Class::Control, CryptoCand::Data)),
            // CRYPTO streams never end.
            Some(Pending::Fin) | None => {}
        }
        (self.handshake_done == HandshakeDone::Pending && !cx.packet.handshake_done)
            .then_some((Class::Control, CryptoCand::HandshakeDone))
    }

    fn min_len(&self, cand: CryptoCand, _cx: &SendCx<'_>) -> usize {
        match cand {
            // One byte at the first unsent offset; lost bytes start below it, so their offset
            // does not take more room.
            CryptoCand::Data => Frame::Crypto {
                offset: VarInt::from_u64(self.send.sent_end()).unwrap_or(VarInt::MAX),
                data: &[0],
            }
            .encoded_len(),
            CryptoCand::HandshakeDone => Frame::HandshakeDone.encoded_len(),
        }
    }

    fn write(
        &mut self,
        cand: CryptoCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        match cand {
            CryptoCand::Data => {
                let emitted = self
                    .send
                    .emit(FrameKind::Crypto, &mut Adapter(w), usize::MAX, u64::MAX)
                    .ok_or(Full)?;
                cx.sent.push(SentFrame::Crypto {
                    level: self.level,
                    offset: emitted.offset,
                    // A frame fits in a datagram.
                    len: u16::try_from(emitted.len).unwrap_or(u16::MAX),
                });
                cx.packet.crypto = true;
            }
            CryptoCand::HandshakeDone => {
                w.frame(&Frame::HandshakeDone).map_err(|_| Full)?;
                cx.sent.push(SentFrame::Control {
                    kind: ControlKind::HandshakeDone,
                    key: 0,
                    value: 0,
                });
                cx.packet.handshake_done = true;
            }
        }
        Ok(())
    }
}
