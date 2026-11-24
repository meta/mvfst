/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Ping source: an application PING in a 1-RTT packet. PING is never retransmitted; a lost
//! one has done its work once another packet is acknowledged.

use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;

use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::recovery::sent::SentFrame;
use crate::transmit::admission::Class;

/// The Ping source.
#[derive(Debug, Default)]
pub(crate) struct PingSource {
    pending: bool,
}

impl PingSource {
    /// Queues a PING.
    pub(crate) fn queue(&mut self) {
        self.pending = true;
    }

    /// Returns whether a PING is queued.
    #[cfg(debug_assertions)]
    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }

    /// Records that a packet carrying the PING was sealed.
    pub(crate) fn on_sealed(&mut self) {
        self.pending = false;
    }
}

impl FrameSource for PingSource {
    type Cand = ();

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ())> {
        (self.pending && cx.space == Space::Data && !cx.packet.ping).then_some((Class::Control, ()))
    }

    fn min_len(&self, _cand: (), _cx: &SendCx<'_>) -> usize {
        Frame::Ping.encoded_len()
    }

    fn write(
        &mut self,
        _cand: (),
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        w.frame(&Frame::Ping).map_err(|_| Full)?;
        cx.sent.push(SentFrame::Ping);
        cx.packet.ping = true;
        Ok(())
    }
}
