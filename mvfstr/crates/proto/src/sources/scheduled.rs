/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Scheduled source: STREAM frames in the wire scheduler's order, each stream's lost bytes
//! before its new ones. A PTO probe takes every stream's lost bytes before any new ones, because
//! the PTO queues the oldest data in flight as lost bytes for it.
//!
//! Connection credit gates new bytes at emit and never takes a stream out of the scheduler: the
//! walk offers the first stream with something it may send now, so lost bytes and FINs go out
//! while the credit is spent, and only when every scheduled stream waits for credit does it
//! offer a `NewStream` candidate, which the admission table refuses with `ConnFlowControl`. The
//! bytes are taken from the send buffer at write; a packet that is never sealed returns them as
//! lost, and a sealed one rotates the scheduler by its bytes.

use std::iter;

use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::VarInt;

use super::Adapter;
use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::recovery::sent::SentFrame;
use crate::streams::conn::StreamState;
use crate::streams::guard::Owed;
use crate::streams::scheduler::Cursor;
use crate::streams::send_buf::FrameKind;
use crate::streams::send_buf::Pending;
use crate::transmit::admission::Class;

/// The Scheduled source's candidate: a stream's slab slot.
pub(crate) type ScheduledCand = u32;

/// Returns the stream to send from next and its class: lost bytes and a lone FIN do not take
/// connection credit, new bytes do. A probe takes lost bytes first, whichever stream holds them.
pub(crate) fn next(state: &StreamState, cx: &SendCx<'_>) -> Option<(Class, ScheduledCand)> {
    if cx.space != Space::Data {
        return None;
    }
    if cx.probes_due > 0
        && let Some(slot) = retransmission(state)
    {
        return Some((Class::Lost, slot));
    }
    let conn_credit = state.conn_send.available();
    let scheduler = state.streams.scheduler();
    let mut cursor = Cursor::default();
    let mut blocked = None;
    while let Some(slot) = scheduler.next(&mut cursor) {
        let Some(send) = state
            .streams
            .get_slot(slot)
            .and_then(|stream| stream.data().send.as_ref())
        else {
            continue;
        };
        match send.buf.pending(send.credit.limit()) {
            Some(Pending::Retransmit) => return Some((Class::Lost, slot)),
            // A FIN alone does not take credit, so it is admitted as a control frame is.
            Some(Pending::Fin) => return Some((Class::Control, slot)),
            Some(Pending::New { .. }) if conn_credit > 0 => return Some((Class::NewStream, slot)),
            Some(Pending::New { .. }) => {
                blocked.get_or_insert(slot);
            }
            None => {}
        }
    }
    blocked.map(|slot| (Class::NewStream, slot))
}

/// Returns the first stream in the wire order with lost bytes to send.
fn retransmission(state: &StreamState) -> Option<ScheduledCand> {
    let scheduler = state.streams.scheduler();
    let mut cursor = Cursor::default();
    iter::from_fn(|| scheduler.next(&mut cursor)).find(|&slot| {
        state
            .streams
            .get_slot(slot)
            .and_then(|stream| stream.data().send.as_ref())
            .is_some_and(|send| send.buf.pending(send.credit.limit()) == Some(Pending::Retransmit))
    })
}

/// Returns the room the smallest STREAM frame of the stream in `slot` takes: one byte at its
/// first unsent offset (lost bytes start below it, so their offset does not take more room).
pub(crate) fn min_len(state: &StreamState, slot: ScheduledCand) -> usize {
    let Some(stream) = state.streams.get_slot(slot) else {
        return 0;
    };
    let offset = stream
        .data()
        .send
        .as_ref()
        .map_or(0, |send| send.buf.sent_end());
    Frame::Stream {
        id: stream.id(),
        offset: VarInt::from_u64(offset).unwrap_or(VarInt::MAX),
        data: &[0],
        fin: false,
    }
    .encoded_len()
}

/// The Scheduled source over a connection's streams.
pub(crate) struct ScheduledSource<'a>(pub(crate) &'a mut StreamState);

impl FrameSource for ScheduledSource<'_> {
    type Cand = ScheduledCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ScheduledCand)> {
        next(self.0, cx)
    }

    fn min_len(&self, cand: ScheduledCand, _cx: &SendCx<'_>) -> usize {
        min_len(self.0, cand)
    }

    fn write(
        &mut self,
        cand: ScheduledCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let state = &mut *self.0;
        let Some(mut stream) = state.streams.by_slot(cand) else {
            return Err(Full);
        };
        let id = stream.id();
        let Some(send) = stream.data_mut().send.as_mut() else {
            return Err(Full);
        };
        let credit_end = send.credit.credit_end(&state.conn_send);
        let before = send.buf.sent_end();
        let emitted = send
            .buf
            .emit(
                FrameKind::Stream(id),
                &mut Adapter(w),
                usize::MAX,
                credit_end,
            )
            .ok_or(Full)?;
        let new = send.buf.sent_end() - before;
        send.credit.consume(new);
        state.conn_send.consume(new);
        state.staged -= new;
        // The stream credit is spent while the stream may still take bytes, so STREAM_DATA_BLOCKED
        // is due, as RFC 9000 advises.
        let blocked = send.buf.final_size().is_none() && send.credit.note_blocked().is_some();
        if blocked {
            stream.owe(Owed::STREAM_DATA_BLOCKED);
        }
        let sent = stream.on_sent(emitted.fin);
        debug_assert!(sent.is_ok(), "a scheduled stream may send STREAM frames");
        drop(stream);
        state.note_conn_blocked();
        cx.sent.push(SentFrame::Stream {
            id,
            offset: emitted.offset,
            // A frame fits in a datagram.
            len: u16::try_from(emitted.len).unwrap_or(u16::MAX),
            fin: emitted.fin,
        });
        Ok(())
    }
}
