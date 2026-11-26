/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Scheduled source: STREAM frames in the prioritizer's wire order, each stream's lost bytes
//! before its new ones, and DATAGRAM frames (RFC 9221). A PTO probe takes every stream's lost
//! bytes before any new ones, because the PTO queues the oldest data in flight as lost bytes for
//! it.
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
use crate::datagram::wire_key;
use crate::recovery::Space;
use crate::recovery::sent::SentFrame;
use crate::streams::conn::StreamState;
use crate::streams::guard::Owed;
use crate::streams::prioritizer::Prioritizer;
use crate::streams::send_buf::FrameKind;
use crate::streams::send_buf::Pending;
use crate::transmit::admission::Class;

/// The Scheduled source's candidate: a stream's slab slot, or [`DATAGRAM`].
pub(crate) type ScheduledCand = u32;

/// The candidate that stands for the first datagram in wire order. The scheduler marks a missing
/// slot with this value, so no stream's slot takes it.
pub(crate) const DATAGRAM: ScheduledCand = u32::MAX;

/// Returns the candidate to send next and its class: the first datagram in wire order when it
/// comes before the first stream with something to send, or ties with it, and that stream
/// otherwise. Lost bytes and a lone FIN do not take connection credit, new bytes do. A probe takes
/// lost bytes first, whichever stream holds them.
pub(crate) fn next<P: Prioritizer>(
    state: &StreamState<P>,
    cx: &SendCx<'_>,
) -> Option<(Class, ScheduledCand)> {
    if cx.space != Space::Data {
        return None;
    }
    // The walk finds a stream exactly when `lost` counts one, so it runs only then.
    if cx.probes_due > 0
        && state.streams.lost() > 0
        && let Some(slot) = retransmission(state)
    {
        return Some((Class::Lost, slot));
    }
    let stream = next_stream(state);
    if state.datagrams.is_empty() {
        return stream;
    }
    datagram_or(state, cx, stream)
}

/// Returns the first datagram in wire order when it comes before `stream`, the first stream with
/// something to send, or ties with it, and that stream otherwise.
// Out of line, so the code that sends streams alone stays as small as without datagrams.
#[inline(never)]
fn datagram_or<P: Prioritizer>(
    state: &StreamState<P>,
    cx: &SendCx<'_>,
    stream: Option<(Class, ScheduledCand)>,
) -> Option<(Class, ScheduledCand)> {
    let Some(datagram) = state.datagrams.head_key(cx.now) else {
        return stream;
    };
    let goes_first = match stream {
        None => true,
        // Connection flow control does not hold back datagrams (RFC 9221).
        Some((Class::NewStream, _)) if state.conn_send.available() == 0 => true,
        Some((_, slot)) => state
            .streams
            .prioritizer()
            .order(slot)
            .is_none_or(|order| datagram <= wire_key(order)),
    };
    match stream {
        Some(stream) if !goes_first => Some(stream),
        _ => Some((Class::Datagram, DATAGRAM)),
    }
}

/// Returns the class and slot of the stream to send from next.
fn next_stream<P: Prioritizer>(state: &StreamState<P>) -> Option<(Class, ScheduledCand)> {
    let conn_credit = state.conn_send.available();
    let prioritizer = state.streams.prioritizer();
    let mut cursor = P::Cursor::default();
    // When the credit is spent and the streams do not hold lost data or a lone FIN, every
    // scheduled stream waits for credit, and the walk below would offer the first.
    if conn_credit == 0 && state.streams.lost() == 0 && state.streams.fin_only() == 0 {
        return prioritizer
            .next(&mut cursor)
            .map(|slot| (Class::NewStream, slot));
    }
    let mut blocked = None;
    while let Some(slot) = prioritizer.next(&mut cursor) {
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
fn retransmission<P: Prioritizer>(state: &StreamState<P>) -> Option<ScheduledCand> {
    let prioritizer = state.streams.prioritizer();
    let mut cursor = P::Cursor::default();
    iter::from_fn(|| prioritizer.next(&mut cursor)).find(|&slot| {
        state
            .streams
            .get_slot(slot)
            .and_then(|stream| stream.data().send.as_ref())
            .is_some_and(|send| send.buf.pending(send.credit.limit()) == Some(Pending::Retransmit))
    })
}

/// Returns the room the candidate takes: the oldest datagram's whole frame, or the smallest STREAM
/// frame of the stream, one byte at its first unsent offset (lost bytes start below it, so their
/// offset does not take more room).
pub(crate) fn min_len<P: Prioritizer>(
    state: &StreamState<P>,
    cand: ScheduledCand,
    cx: &SendCx<'_>,
) -> usize {
    if cand == DATAGRAM {
        return state.datagrams.head_frame_len(cx.now).unwrap_or(0);
    }
    let Some(stream) = state.streams.get_slot(cand) else {
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
pub(crate) struct ScheduledSource<'a, P: Prioritizer>(pub(crate) &'a mut StreamState<P>);

impl<P: Prioritizer> FrameSource for ScheduledSource<'_, P> {
    type Cand = ScheduledCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, ScheduledCand)> {
        next(self.0, cx)
    }

    fn min_len(&self, cand: ScheduledCand, cx: &SendCx<'_>) -> usize {
        min_len(self.0, cand, cx)
    }

    fn write(
        &mut self,
        cand: ScheduledCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let state = &mut *self.0;
        if cand == DATAGRAM {
            // A DATAGRAM frame is not retransmitted, so it leaves no sent-frame record.
            return state.datagrams.write_head(w, cx.now);
        }
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mvfstr_crypto::TAG_LEN;
    use mvfstr_wire::ConnectionId;
    use mvfstr_wire::Dir;
    use mvfstr_wire::HeaderSpec;
    use mvfstr_wire::Side;
    use mvfstr_wire::StreamId;
    use mvfstr_wire::TransportParameters;

    use super::*;
    use crate::AppCode;
    use crate::SendOrder;
    use crate::TransportConfig;
    use crate::recovery::test_epoch;
    use crate::sources::PacketCx;
    use crate::streams::guard::census;
    use crate::streams::prioritizer::FairShare;
    use crate::streams::prioritizer::MirroredUrgency;
    use crate::streams::recv_buf::PagePool;

    /// Returns a server's streams with `count` sequential streams in one bucket, in the wire order
    /// they were opened in, each with 100 new bytes staged within its stream and connection credit.
    fn staged(count: u32) -> (StreamState, Vec<StreamId>) {
        staged_with(count, 1 << 20, false)
    }

    /// Returns a server's streams with `count` streams in one bucket, sequential or `incremental`,
    /// in the wire order they were opened in, each with 100 new bytes staged within its stream
    /// credit, and `max_data` bytes of connection credit.
    fn staged_with(count: u32, max_data: u32, incremental: bool) -> (StreamState, Vec<StreamId>) {
        let config = TransportConfig::builder()
            .build()
            .expect("a valid transport config");
        let mut s = StreamState::new(Side::Server, &config, PagePool::new());
        s.on_peer_params(&TransportParameters {
            initial_max_data: VarInt::from_u32(max_data),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(count),
            ..TransportParameters::default()
        })
        .expect("valid parameters");
        let ids = (0..count)
            .map(|order| {
                let order = SendOrder {
                    class: 1,
                    urgency: 3,
                    incremental,
                    order: if incremental { 0 } else { u128::from(order) },
                };
                let id = s.open(Dir::Uni, order).unwrap();
                let staged = s.send(id, &mut Bytes::from_static(&[7; 100]), u64::MAX);
                assert_eq!(staged, Ok(100));
                id
            })
            .collect();
        (s, ids)
    }

    fn slot(s: &StreamState, id: StreamId) -> ScheduledCand {
        s.streams.get(id).unwrap().slot()
    }

    fn cx(probes_due: u8, sent: &mut Vec<SentFrame>) -> SendCx<'_> {
        SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent,
        }
    }

    /// Returns the candidate `next` offers with `probes_due` probes due, and how many streams its
    /// scheduler walks visited.
    fn next_with_visits(s: &StreamState, probes_due: u8) -> (Option<(Class, ScheduledCand)>, u64) {
        let mut sent = Vec::new();
        let cx = cx(probes_due, &mut sent);
        census::reset();
        let offered = next(s, &cx);
        (offered, census::read().scheduler_visits)
    }

    /// Writes stream `id`'s next STREAM frame into a packet with room for all of its bytes.
    fn write(s: &mut StreamState, id: StreamId) {
        let cand = slot(s, id);
        let mut sent = Vec::new();
        let mut cx = cx(0, &mut sent);
        let mut buf = vec![0; 1_200];
        let header = HeaderSpec::OneRtt {
            dcid: ConnectionId::new(&[1; 8]).unwrap(),
            spin: false,
            key_phase: false,
        };
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        ScheduledSource(s).write(cand, &mut w, &mut cx).unwrap();
    }

    #[test]
    fn probe_without_lost_data_does_not_walk() {
        let (s, ids) = staged(100);
        assert_eq!(s.streams.lost(), 0);
        let first = Some((Class::NewStream, slot(&s, ids[0])));
        let (plain, plain_visits) = next_with_visits(&s, 0);
        assert_eq!(plain, first);
        assert_eq!(plain_visits, 1, "the walk stops at the first stream");
        let (probe, probe_visits) = next_with_visits(&s, 1);
        assert_eq!(
            probe, first,
            "without lost data, a probe carries new bytes in the wire order"
        );
        assert_eq!(
            probe_visits, plain_visits,
            "a probe without lost data visited {probe_visits} streams, not {plain_visits}"
        );
    }

    #[test]
    fn a_probe_takes_lost_data_first_whichever_stream_holds_it() {
        let (mut s, ids) = staged(10);
        let candidate = |s: &StreamState, probes_due| next_with_visits(s, probes_due).0;
        let first = Some((Class::NewStream, slot(&s, ids[0])));
        // Stream 5's bytes and stream 8's FIN are sent and lost, behind streams with new bytes.
        write(&mut s, ids[5]);
        assert!(s.on_stream_lost(ids[5], 0, 100, false));
        s.finish(ids[8]).unwrap();
        write(&mut s, ids[8]);
        assert!(s.on_stream_lost(ids[8], 100, 0, true));
        assert_eq!(s.streams.lost(), 2);
        assert_eq!(candidate(&s, 0), first, "without probes, the wire order");
        assert_eq!(
            candidate(&s, 1),
            Some((Class::Lost, slot(&s, ids[5]))),
            "lost bytes go first under probes"
        );
        write(&mut s, ids[5]);
        assert_eq!(s.streams.lost(), 1);
        assert_eq!(
            candidate(&s, 1),
            Some((Class::Lost, slot(&s, ids[8]))),
            "a lost FIN goes first under probes"
        );
        assert_eq!(candidate(&s, 0), first);
    }

    /// Returns the streams counted with lost data and with a lone FIN, after checking that every
    /// list and the scheduler hold exactly the streams whose state calls for them.
    fn counts(s: &StreamState) -> (u32, u32) {
        s.streams.assert_indexed();
        (s.streams.lost(), s.streams.fin_only())
    }

    #[test]
    fn conn_blocked_next_visits_one_stream() {
        for incremental in [false, true] {
            // The first stream's write spends the connection credit; every stream holds only new
            // bytes.
            let (mut s, ids) = staged_with(1_000, 50, incremental);
            write(&mut s, ids[0]);
            assert_eq!(s.conn_send.available(), 0, "the connection window is spent");
            assert_eq!(counts(&s), (0, 0));
            let (offered, visits) = next_with_visits(&s, 0);
            assert_eq!(
                offered,
                Some((Class::NewStream, slot(&s, ids[0]))),
                "the first stream in the wire order, for the admission table to refuse"
            );
            assert_eq!(
                visits, 1,
                "incremental {incremental}: a connection-blocked `next` visited {visits} streams"
            );
            // The first stream leaves the scheduler, so the next one is offered.
            s.reset(ids[0], AppCode::from_u32(1)).unwrap();
            assert_eq!(counts(&s), (0, 0));
            let (offered, visits) = next_with_visits(&s, 0);
            assert_eq!(offered, Some((Class::NewStream, slot(&s, ids[1]))));
            assert_eq!(
                visits, 1,
                "incremental {incremental}: after a reset, `next` visited {visits} streams"
            );
        }
    }

    #[test]
    fn conn_blocked_next_offers_a_lone_fin_or_lost_bytes_wherever_their_streams_stand() {
        for incremental in [false, true] {
            let (mut s, ids) = staged_with(10, 350, incremental);
            // Streams 5, 7 and 8 send their bytes; stream 5's FIN waits alone and stream 7's
            // bytes are lost. Stream 0 spends the rest of the connection credit.
            for i in [5, 7, 8] {
                write(&mut s, ids[i]);
            }
            s.finish(ids[5]).unwrap();
            assert!(s.on_stream_lost(ids[7], 0, 100, false));
            write(&mut s, ids[0]);
            assert_eq!(s.conn_send.available(), 0, "the connection window is spent");
            let offered = |s: &StreamState| next_with_visits(s, 0);
            let first = Some((Class::NewStream, slot(&s, ids[0])));

            assert_eq!(
                offered(&s).0,
                Some((Class::Control, slot(&s, ids[5]))),
                "incremental {incremental}: a lone FIN does not take connection credit"
            );
            assert_eq!(counts(&s), (1, 1), "stream 7's lost bytes, stream 5's FIN");

            write(&mut s, ids[5]);
            assert_eq!(counts(&s), (1, 0), "stream 5's FIN is sent");
            assert_eq!(
                offered(&s).0,
                Some((Class::Lost, slot(&s, ids[7]))),
                "incremental {incremental}: lost bytes do not take connection credit"
            );

            write(&mut s, ids[7]);
            assert_eq!(counts(&s), (0, 0), "stream 7's bytes are resent");
            assert_eq!(offered(&s), (first, 1), "incremental {incremental}");

            // A FIN late in the order is found as well.
            s.finish(ids[8]).unwrap();
            assert_eq!(counts(&s), (0, 1), "stream 8's FIN");
            assert_eq!(
                offered(&s).0,
                Some((Class::Control, slot(&s, ids[8]))),
                "incremental {incremental}: a late stream's lone FIN"
            );
            write(&mut s, ids[8]);
            assert_eq!(counts(&s), (0, 0));
            assert_eq!(offered(&s), (first, 1), "incremental {incremental}");
        }
    }

    #[test]
    fn fin_only_counts_the_streams_with_only_an_unsent_fin_to_send() {
        let (mut s, ids) = staged_with(3, 1 << 20, false);
        s.finish(ids[0]).unwrap();
        assert_eq!(
            counts(&s),
            (0, 0),
            "a FIN behind unsent bytes goes with them"
        );
        write(&mut s, ids[0]);
        assert_eq!(counts(&s), (0, 0), "the FIN went with the last bytes");

        write(&mut s, ids[1]);
        s.finish(ids[1]).unwrap();
        assert_eq!(
            counts(&s),
            (0, 1),
            "a FIN staged after every byte was sent goes alone"
        );
        s.on_max_streams(Dir::Uni, 4).unwrap();
        let order = SendOrder {
            class: 1,
            urgency: 3,
            incremental: false,
            order: 3,
        };
        let empty = s.open(Dir::Uni, order).unwrap();
        s.finish(empty).unwrap();
        assert_eq!(
            counts(&s),
            (0, 2),
            "a stream that ends without bytes has a lone FIN"
        );

        write(&mut s, ids[1]);
        assert_eq!(counts(&s), (0, 1), "a sent FIN leaves the count");
        assert!(s.on_stream_lost(ids[1], 100, 0, true));
        assert_eq!(
            counts(&s),
            (1, 1),
            "a lost FIN counts as lost data, not as a lone FIN"
        );
        write(&mut s, ids[1]);
        assert_eq!(counts(&s), (0, 1), "the lost FIN is resent");

        write(&mut s, ids[2]);
        s.finish(ids[2]).unwrap();
        assert_eq!(counts(&s), (0, 2));
        assert!(s.on_stream_lost(ids[2], 0, 100, false));
        assert_eq!(
            counts(&s),
            (1, 1),
            "lost bytes ahead of the FIN count as lost data"
        );
        write(&mut s, ids[2]);
        assert_eq!(
            counts(&s),
            (0, 2),
            "once the lost bytes are resent, the FIN goes alone"
        );

        s.reset(ids[2], AppCode::from_u32(1)).unwrap();
        assert_eq!(counts(&s), (0, 1), "a reset drops the FIN");
        s.on_stop_sending(empty, AppCode::from_u32(2)).unwrap();
        assert_eq!(counts(&s), (0, 0), "the peer's STOP_SENDING drops the FIN");
    }

    /// Opens sequential streams of class 1 at urgencies 0, 3 and 7 on a server whose streams `P`
    /// orders, with 100 bytes staged on each, and returns them in the order they were opened and
    /// in the order the source offers them. Each stream is reset once offered, which unschedules
    /// it, so the next walk goes on to the stream after it. The streams' indexes are checked
    /// after each step.
    fn offered_in_wire_order<P: Prioritizer>() -> (Vec<StreamId>, Vec<StreamId>) {
        let config = TransportConfig::builder()
            .build()
            .expect("a valid transport config");
        let mut s = StreamState::<P>::new(Side::Server, &config, PagePool::new());
        s.on_peer_params(&TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(3),
            ..TransportParameters::default()
        })
        .expect("valid parameters");
        let opened: Vec<_> = [0, 3, 7]
            .into_iter()
            .map(|urgency| {
                let order = SendOrder {
                    class: 1,
                    urgency,
                    incremental: false,
                    order: 0,
                };
                let id = s.open(Dir::Uni, order).unwrap();
                let staged = s.send(id, &mut Bytes::from_static(&[7; 100]), u64::MAX);
                assert_eq!(staged, Ok(100));
                id
            })
            .collect();
        s.streams.assert_indexed();
        let mut offered = Vec::new();
        let mut sent = Vec::new();
        loop {
            let candidate = next(&s, &cx(0, &mut sent));
            let Some((class, slot)) = candidate else {
                break;
            };
            assert_eq!(class, Class::NewStream, "new bytes within credit");
            let id = s.streams.get_slot(slot).expect("a live stream").id();
            offered.push(id);
            s.reset(id, AppCode::from_u32(1)).unwrap();
            s.streams.assert_indexed();
        }
        (opened, offered)
    }

    #[test]
    fn the_source_offers_streams_in_the_wire_order_of_their_plug() {
        let (opened, offered) = offered_in_wire_order::<FairShare>();
        assert_eq!(
            offered, opened,
            "the default plug offers the most urgent stream first"
        );
        let (opened, offered) = offered_in_wire_order::<MirroredUrgency<FairShare>>();
        let reversed: Vec<_> = opened.into_iter().rev().collect();
        assert_eq!(
            offered, reversed,
            "a plug that mirrors urgencies offers the least urgent stream first"
        );
    }
}
