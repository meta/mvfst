/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Probe source: a PING that makes a PTO probe ack-eliciting, as RFC 9002 requires.
//!
//! `probes_due[space]` is loss recovery's state, set when the PTO expires and reduced by one for
//! each sealed ack-eliciting packet in the space. A probe packet carries data when a source has
//! some, which the admission table lets join past the congestion window; this source adds a
//! PING only to a packet that is not already ack-eliciting.

use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;

use super::FrameSource;
use super::SendCx;
use crate::recovery::sent::SentFrame;
use crate::transmit::admission::Class;

/// The Probe source; its state is loss recovery's `probes_due`.
#[derive(Debug, Default)]
pub(crate) struct ProbeSource;

impl FrameSource for ProbeSource {
    type Cand = ();

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ())> {
        (cx.probes_due > 0 && !cx.packet.ack_eliciting).then_some((Class::Probe, ()))
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
        cx.packet.ack_eliciting = true;
        Ok(())
    }
}
