/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Close source: the CONNECTION_CLOSE frames of a closing connection (RFC 9000).
//!
//! It has a candidate only while the packet's space still has to carry the frame. Before the
//! handshake is confirmed the connection sends it in every space the peer may have keys for,
//! and an application close goes out in Initial and Handshake packets as a transport
//! APPLICATION_ERROR without its reason, since those packets are not authenticated.

use bytes::Bytes;
use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::transmit::admission::Class;

/// The longest reason phrase sent; longer ones are cut, so a CLOSE fits any packet.
const MAX_REASON: usize = 256;

/// The CONNECTION_CLOSE a closing connection sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CloseFrame {
    /// A transport error (frame type 0x1c).
    Transport {
        code: TransportErrorCode,
        frame_type: VarInt,
        reason: Bytes,
    },
    /// An application close (frame type 0x1d).
    Application { code: VarInt, reason: Bytes },
}

impl CloseFrame {
    /// Cuts the reason to `MAX_REASON` bytes.
    pub(crate) fn bounded(mut self) -> Self {
        let (CloseFrame::Transport { reason, .. } | CloseFrame::Application { reason, .. }) =
            &mut self;
        reason.truncate(MAX_REASON);
        self
    }
}

/// The Close source.
#[derive(Debug, Default)]
pub(crate) struct CloseSource {
    frame: Option<CloseFrame>,
    owed: [bool; 3],
}

impl CloseSource {
    /// Queues `frame` in each of `spaces`.
    pub(crate) fn start(&mut self, frame: CloseFrame, spaces: [bool; 3]) {
        self.frame = Some(frame.bounded());
        self.owed = spaces;
    }

    /// Queues the frame again in each of `spaces`: a closing connection answers a received
    /// packet with it (RFC 9000).
    pub(crate) fn owe_again(&mut self, spaces: [bool; 3]) {
        if self.frame.is_some() {
            self.owed = spaces;
        }
    }

    /// Returns the spaces that still have to carry the frame, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn owed(&self) -> [bool; 3] {
        self.owed
    }

    /// Records that a packet carrying the frame in `space` was sealed.
    pub(crate) fn on_sealed(&mut self, space: Space) {
        self.owed[space.index()] = false;
    }

    /// Stops queueing the frame in `space`, whose keys are gone.
    pub(crate) fn discard(&mut self, space: Space) {
        self.owed[space.index()] = false;
    }

    /// Returns the frame a packet in `space` carries.
    fn frame_in(&self, space: Space) -> Option<Frame<'_>> {
        let frame = match (self.frame.as_ref()?, space) {
            (
                CloseFrame::Transport {
                    code,
                    frame_type,
                    reason,
                },
                _,
            ) => Frame::ConnectionClose {
                error_code: *code,
                frame_type: *frame_type,
                reason,
            },
            (CloseFrame::Application { .. }, Space::Initial | Space::Handshake) => {
                Frame::ConnectionClose {
                    error_code: TransportErrorCode::APPLICATION_ERROR,
                    frame_type: VarInt::ZERO,
                    reason: &[],
                }
            }
            (CloseFrame::Application { code, reason }, Space::Data) => Frame::ApplicationClose {
                error_code: *code,
                reason,
            },
        };
        Some(frame)
    }
}

impl FrameSource for CloseSource {
    type Cand = ();

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ())> {
        (self.frame.is_some() && self.owed[cx.space.index()] && !cx.packet.close)
            .then_some((Class::Response, ()))
    }

    fn min_len(&self, _cand: (), cx: &SendCx<'_>) -> usize {
        // The frame is never split.
        self.frame_in(cx.space)
            .map_or(0, |frame| frame.encoded_len())
    }

    fn write(
        &mut self,
        _cand: (),
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let frame = self.frame_in(cx.space).ok_or(Full)?;
        w.frame(&frame).map_err(|_| Full)?;
        cx.packet.close = true;
        Ok(())
    }
}
