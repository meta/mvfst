/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Control source: flow control and stream state frames.
//!
//! Each frame has a delivery machine (see [`delivery`](super::delivery)): written frames are in
//! flight until acknowledged or lost, and a lost frame is pending again only while its value is
//! current. Writing moves a frame to in flight; a packet that is never sealed returns its frames
//! as lost, which makes the current ones pending again.

use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::VarInt;

use super::FrameSource;
use super::SendCx;
use crate::recovery::Space;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::SentFrame;
use crate::streams::conn::StreamState;
use crate::streams::conn::dir_index;
use crate::streams::guard::List;
use crate::streams::guard::Owed;
use crate::streams::state::SendState;
use crate::transmit::admission::Class;

/// A frame due on one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamControl {
    /// RESET_STREAM with the send half's code and final size.
    ResetStream,
    /// STOP_SENDING with the application's code.
    StopSending,
    /// MAX_STREAM_DATA with the stream's next receive limit.
    MaxStreamData,
    /// STREAM_DATA_BLOCKED at the stream's send limit.
    StreamDataBlocked,
}

impl StreamControl {
    /// The frames in the order a stream sends them.
    const ORDER: [StreamControl; 4] = [
        StreamControl::ResetStream,
        StreamControl::StopSending,
        StreamControl::MaxStreamData,
        StreamControl::StreamDataBlocked,
    ];

    /// Returns the guard's bit for the frame.
    fn owed(self) -> Owed {
        match self {
            StreamControl::ResetStream => Owed::RESET_STREAM,
            StreamControl::StopSending => Owed::STOP_SENDING,
            StreamControl::MaxStreamData => Owed::MAX_STREAM_DATA,
            StreamControl::StreamDataBlocked => Owed::STREAM_DATA_BLOCKED,
        }
    }
}

/// What a Control candidate writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlCand {
    /// MAX_DATA with the connection's next receive limit.
    MaxData,
    /// MAX_STREAMS for peer streams in direction `Dir`.
    MaxStreams(Dir),
    /// DATA_BLOCKED at the peer's connection limit.
    DataBlocked,
    /// STREAMS_BLOCKED at the peer's stream limit for direction `Dir`.
    StreamsBlocked(Dir),
    /// A frame due on the stream in slab slot `slot`.
    Stream { slot: u32, frame: StreamControl },
}

/// Returns the next control frame to send: connection frames first, then the first stream on
/// the control list.
pub(crate) fn next(state: &StreamState, cx: &SendCx<'_>) -> Option<(Class, ControlCand)> {
    if cx.space != Space::Data {
        return None;
    }
    if state.conn_recv.is_update_pending() {
        return Some((Class::Control, ControlCand::MaxData));
    }
    for dir in [Dir::Bi, Dir::Uni] {
        if state.max_streams[dir_index(dir)].pending().is_some() {
            return Some((Class::Control, ControlCand::MaxStreams(dir)));
        }
    }
    if state.data_blocked.pending().is_some() {
        return Some((Class::Control, ControlCand::DataBlocked));
    }
    for dir in [Dir::Bi, Dir::Uni] {
        if state.streams_blocked[dir_index(dir)].pending().is_some() {
            return Some((Class::Control, ControlCand::StreamsBlocked(dir)));
        }
    }
    let slot = state.streams.first(List::Control)?;
    let due = state.streams.get_slot(slot)?.due();
    let frame = StreamControl::ORDER
        .into_iter()
        .find(|frame| due.contains(frame.owed()))?;
    Some((Class::Control, ControlCand::Stream { slot, frame }))
}

/// Returns the room the candidate's frame takes.
pub(crate) fn min_len(state: &StreamState, cand: ControlCand) -> usize {
    frame(state, cand).map_or(0, |(frame, _)| frame.encoded_len())
}

/// Builds the candidate's frame and its sent-frame record.
fn frame(state: &StreamState, cand: ControlCand) -> Option<(Frame<'static>, SentFrame)> {
    let varint = |value: u64| VarInt::from_u64(value).unwrap_or(VarInt::MAX);
    let record = |kind, key, value| SentFrame::Control { kind, key, value };
    match cand {
        ControlCand::MaxData => {
            let limit = state.conn_recv.next_limit();
            Some((
                Frame::MaxData(varint(limit)),
                record(ControlKind::MaxData, 0, limit),
            ))
        }
        ControlCand::MaxStreams(dir) => {
            let max = state.max_streams[dir_index(dir)].pending()?;
            let kind = match dir {
                Dir::Bi => ControlKind::MaxStreamsBidi,
                Dir::Uni => ControlKind::MaxStreamsUni,
            };
            Some((
                Frame::MaxStreams {
                    dir,
                    max: varint(max),
                },
                record(kind, 0, max),
            ))
        }
        ControlCand::StreamsBlocked(dir) => {
            let limit = state.streams_blocked[dir_index(dir)].pending()?;
            let kind = match dir {
                Dir::Bi => ControlKind::StreamsBlockedBidi,
                Dir::Uni => ControlKind::StreamsBlockedUni,
            };
            Some((
                Frame::StreamsBlocked {
                    dir,
                    limit: varint(limit),
                },
                record(kind, 0, limit),
            ))
        }
        ControlCand::DataBlocked => {
            let limit = state.data_blocked.pending()?;
            Some((
                Frame::DataBlocked(varint(limit)),
                record(ControlKind::DataBlocked, 0, limit),
            ))
        }
        ControlCand::Stream { slot, frame } => {
            let stream = state.streams.get_slot(slot)?;
            let id = stream.id();
            let key = id.into_inner();
            Some(match frame {
                StreamControl::ResetStream => {
                    let Some(SendState::ResetSent { code, final_size }) = stream.send_state()
                    else {
                        return None;
                    };
                    (
                        Frame::ResetStream {
                            id,
                            error_code: code.0,
                            final_size: varint(final_size),
                        },
                        record(ControlKind::ResetStream, key, final_size),
                    )
                }
                StreamControl::StopSending => {
                    let code = stream.stop_code()?;
                    (
                        Frame::StopSending {
                            id,
                            error_code: code.0,
                        },
                        record(ControlKind::StopSending, key, 0),
                    )
                }
                StreamControl::MaxStreamData => {
                    let limit = stream.data().recv.as_ref()?.flow.window().next_limit();
                    (
                        Frame::MaxStreamData {
                            id,
                            max: varint(limit),
                        },
                        record(ControlKind::MaxStreamData, key, limit),
                    )
                }
                StreamControl::StreamDataBlocked => {
                    let limit = stream.data().send.as_ref()?.credit.limit();
                    (
                        Frame::StreamDataBlocked {
                            id,
                            limit: varint(limit),
                        },
                        record(ControlKind::StreamDataBlocked, key, limit),
                    )
                }
            })
        }
    }
}

/// The Control source over a connection's streams.
pub(crate) struct ControlSource<'a>(pub(crate) &'a mut StreamState);

impl FrameSource for ControlSource<'_> {
    type Cand = ControlCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ControlCand)> {
        next(self.0, cx)
    }

    fn min_len(&self, cand: ControlCand, _cx: &SendCx<'_>) -> usize {
        min_len(self.0, cand)
    }

    fn write(
        &mut self,
        cand: ControlCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let (frame, sent) = frame(self.0, cand).ok_or(Full)?;
        w.frame(&frame).map_err(|_| Full)?;
        let SentFrame::Control { value, .. } = sent else {
            unreachable!("control frames have control records");
        };
        let state = &mut *self.0;
        match cand {
            ControlCand::MaxData => state.conn_recv.on_update_sent(value, cx.now),
            ControlCand::MaxStreams(dir) => {
                state.max_streams[dir_index(dir)].on_written(value);
                state.streams.on_max_streams_sent(dir, value);
            }
            ControlCand::DataBlocked => state.data_blocked.on_written(value),
            ControlCand::StreamsBlocked(dir) => {
                state.streams_blocked[dir_index(dir)].on_written(value);
            }
            ControlCand::Stream { slot, frame } => {
                if let Some(mut stream) = state.streams.by_slot(slot) {
                    match frame {
                        StreamControl::ResetStream | StreamControl::StopSending => {}
                        StreamControl::MaxStreamData => {
                            if let Some(recv) = stream.data_mut().recv.as_mut() {
                                recv.flow.on_update_sent(value, cx.now);
                            }
                        }
                        StreamControl::StreamDataBlocked => {
                            let sent = stream.on_sent(false);
                            debug_assert!(
                                sent.is_ok(),
                                "STREAM_DATA_BLOCKED is due only before the FIN"
                            );
                        }
                    }
                    stream.on_control_sent(frame.owed());
                }
            }
        }
        cx.sent.push(sent);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use bytes::Bytes;
    use mvfstr_crypto::TAG_LEN;
    use mvfstr_wire::ConnectionId;
    use mvfstr_wire::HeaderSpec;
    use mvfstr_wire::Side;
    use mvfstr_wire::StreamId;

    use super::*;
    use crate::AppCode;
    use crate::CreditDue;
    use crate::OpenError;
    use crate::SendOrder;
    use crate::TransportConfig;
    use crate::recovery::test_epoch;
    use crate::sources::PacketCx;
    use crate::streams::recv_buf::PagePool;

    const SRTT: Duration = Duration::from_millis(20);

    /// Returns a server's streams with 1,000-byte receive windows that do not autotune.
    fn state() -> StreamState {
        let config = TransportConfig::builder()
            .max_data(1_000)
            .max_data_autotune(None)
            .max_stream_data_bidi_remote(1_000)
            .max_stream_data_uni(1_000)
            .max_stream_data_autotune(None)
            .build()
            .expect("a valid transport config");
        StreamState::new(Side::Server, &config, PagePool::new())
    }

    fn cx(now: Instant, sent: &mut Vec<SentFrame>) -> SendCx<'_> {
        SendCx {
            now,
            release: now,
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent,
        }
    }

    /// Returns the next control frame due, if any.
    fn due(state: &StreamState) -> Option<ControlCand> {
        next(state, &cx(test_epoch(), &mut Vec::new())).map(|(_, cand)| cand)
    }

    /// Writes the next control frame due into a packet and returns its record.
    fn write(state: &mut StreamState) -> (ControlKind, u64, u64) {
        let mut sent = Vec::new();
        let mut cx = cx(test_epoch(), &mut sent);
        let (_, cand) = next(state, &cx).expect("a control frame is due");
        let header = HeaderSpec::OneRtt {
            dcid: ConnectionId::new(&[1; 8]).unwrap(),
            spin: false,
            key_phase: false,
        };
        let mut buf = vec![0; 256];
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        ControlSource(state)
            .write(cand, &mut w, &mut cx)
            .expect("the frame fits");
        match sent.pop() {
            Some(SentFrame::Control { kind, key, value }) => (kind, key, value),
            other => panic!("not a control record: {other:?}"),
        }
    }

    /// Declares the packets carrying `frames` lost.
    fn lose(state: &mut StreamState, frames: &[(ControlKind, u64, u64)]) {
        for &(kind, key, value) in frames {
            state.on_control_lost(kind, key, value);
        }
    }

    /// Acknowledges the packets carrying `frames`.
    fn ack(state: &mut StreamState, frames: &[(ControlKind, u64, u64)]) {
        for &(kind, key, value) in frames {
            state.on_control_acked(kind, key, value);
        }
    }

    /// Writes `frames` again, as the loss made them due.
    fn resend(state: &mut StreamState, frames: &[(ControlKind, u64, u64)]) {
        for &frame in frames {
            assert_eq!(write(state), frame);
        }
    }

    #[test]
    fn a_late_ack_delivers_a_lost_credit_update_whichever_copy_it_acknowledges() {
        let now = test_epoch();
        let a = StreamId::new(Side::Client, Dir::Bi, 0).unwrap();
        for resent in [false, true] {
            let mut s = state();
            s.on_stream_frame(a, 0, &[0; 600], false, now, SRTT)
                .unwrap();
            assert_eq!(s.consume(a, 600, now, SRTT), Ok(CreditDue::Due));
            let updates = [write(&mut s), write(&mut s)];
            assert_eq!(
                updates,
                [
                    (ControlKind::MaxData, 0, 1_600),
                    (ControlKind::MaxStreamData, a.into_inner(), 1_600)
                ]
            );
            lose(&mut s, &updates);
            if resent {
                resend(&mut s, &updates);
            }
            // The packet declared lost is acknowledged after all; a resent copy is then lost.
            ack(&mut s, &updates);
            if resent {
                lose(&mut s, &updates);
            }
            assert_eq!(due(&s), None, "resent {resent}: the peer has both limits");
        }
    }

    #[test]
    fn a_late_ack_delivers_a_lost_blocked_frame_or_stop_sending_whichever_copy_it_acknowledges() {
        let now = test_epoch();
        let order = SendOrder {
            class: 1,
            urgency: 3,
            incremental: false,
            order: 0,
        };
        let theirs = StreamId::new(Side::Client, Dir::Uni, 0).unwrap();
        for resent in [false, true] {
            let mut s = state();
            // A stream of ours at the peer's zero stream window, and one of the peer's we stop.
            s.streams.on_peer_max_streams(Dir::Bi, 1).unwrap();
            let ours = s.open(Dir::Bi, order).unwrap();
            assert_eq!(s.send(ours, &mut Bytes::from_static(b"x"), 1 << 20), Ok(0));
            s.on_stream_frame(theirs, 0, &[0; 10], false, now, SRTT)
                .unwrap();
            s.stop_sending(theirs, AppCode::from_u32(1), now, SRTT)
                .unwrap();
            let frames = [write(&mut s), write(&mut s)];
            assert_eq!(
                frames,
                [
                    (ControlKind::StreamDataBlocked, ours.into_inner(), 0),
                    (ControlKind::StopSending, theirs.into_inner(), 0)
                ]
            );
            lose(&mut s, &frames);
            if resent {
                resend(&mut s, &frames);
            }
            ack(&mut s, &frames);
            if resent {
                lose(&mut s, &frames);
            }
            assert_eq!(due(&s), None, "resent {resent}: the peer has both frames");
        }
    }

    #[test]
    fn a_late_ack_delivers_a_lost_uni_stream_limit_or_streams_blocked_whichever_copy_it_acknowledges()
     {
        let now = test_epoch();
        let order = SendOrder {
            class: 1,
            urgency: 3,
            incremental: false,
            order: 0,
        };
        let theirs = StreamId::new(Side::Client, Dir::Uni, 0).unwrap();
        for resent in [false, true] {
            let config = TransportConfig::builder()
                .max_streams_uni(1)
                .build()
                .expect("a valid transport config");
            let mut s = StreamState::new(Side::Server, &config, PagePool::new());
            // The peer allows one uni stream of ours, and the one uni stream we allow is reaped.
            s.streams.on_peer_max_streams(Dir::Uni, 1).unwrap();
            s.open(Dir::Uni, order).unwrap();
            assert_eq!(s.open(Dir::Uni, order), Err(OpenError::StreamLimit));
            s.on_stream_frame(theirs, 0, &[0; 10], true, now, SRTT)
                .unwrap();
            assert_eq!(s.consume(theirs, 10, now, SRTT), Ok(CreditDue::NotDue));
            while s.next_edge().is_some() {}
            let frames = [write(&mut s), write(&mut s)];
            assert_eq!(
                frames,
                [
                    (ControlKind::MaxStreamsUni, 0, 2),
                    (ControlKind::StreamsBlockedUni, 0, 1)
                ]
            );
            lose(&mut s, &frames);
            if resent {
                resend(&mut s, &frames);
            }
            ack(&mut s, &frames);
            if resent {
                lose(&mut s, &frames);
            }
            assert_eq!(due(&s), None, "resent {resent}: the peer has both frames");
        }
    }
}
