/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The fixed frame sources of the write decision.
//!
//! The write decision picks every frame a connection sends from one of eight sources, tried in a
//! fixed order (Close, Ack, Crypto, Path, Control, Probe, Scheduled, Ping) and statically
//! dispatched. Each implements [`FrameSource`]: [`FrameSource::next`] gives its candidate and the
//! candidate's [`Class`] for the admission table, [`FrameSource::min_len`] the room the candidate
//! needs in a packet, and [`FrameSource::write`] writes it from the same state. A write changes
//! only what the packet being built needs: the frames it writes are logged in the [`SendCx`] and
//! reach loss recovery when the packet is sealed, and state that only a sealed packet may change
//! (an ACK sent, a CLOSE emitted, HANDSHAKE_DONE in flight) is applied by
//! [`Sources::on_sealed`]. CRYPTO data is the exception: its send buffer takes the bytes at write,
//! and a packet that is never sealed returns them as lost.
//!
//! The Control and Scheduled sources send from the connection's [`StreamState`], which also takes
//! their frames' acknowledgments and losses, and Control also sends the connection ID frames of
//! [`Cids`]. The Path source sends PATH_CHALLENGE and PATH_RESPONSE for each path. Control, Path
//! and STREAM frames change their state at write, as CRYPTO bytes do, and a packet that is never
//! sealed returns them as lost.

mod ack;
mod close;
mod control;
mod crypto;
pub(crate) mod delivery;
pub(crate) mod path;
mod ping;
mod probe;
mod scheduled;

use std::ops::Range;
use std::time::Instant;

pub(crate) use ack::AckSource;
use bytes::Bytes;
pub(crate) use close::CloseFrame;
pub(crate) use close::CloseSource;
use control::ControlSource;
pub(crate) use crypto::CryptoSource;
use mvfstr_wire::FrameKind;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::StreamId;
use path::PathSource;
pub(crate) use ping::PingSource;
pub(crate) use probe::ProbeSource;
use scheduled::ScheduledSource;

use crate::PathId;
use crate::cid::Cids;
use crate::recovery::Space;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::PacketEvent;
use crate::recovery::sent::SentFrame;
use crate::recovery::sent::SentPacket;
use crate::streams::conn::StreamState;
use crate::streams::prioritizer::MvfstOrder;
use crate::streams::prioritizer::Prioritizer;
use crate::streams::send_buf::FrameWriter;
use crate::transmit::admission::Class;

/// A frame source, in the order the attempt tries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceId {
    /// CONNECTION_CLOSE, while the space still has to carry it; per space.
    Close,
    /// ACK and ACK_ECN; per space.
    Ack,
    /// CRYPTO, lost bytes before new ones, and HANDSHAKE_DONE; per level.
    Crypto,
    /// PATH_CHALLENGE and PATH_RESPONSE; per path.
    Path,
    /// Flow control, stream state and connection ID frames.
    Control,
    /// PTO probes: a PING when the packet is not otherwise ack-eliciting; per space.
    Probe,
    /// STREAM and DATAGRAM frames through the scheduler's cursor.
    Scheduled,
    /// Keepalive and application PING.
    Ping,
}

impl SourceId {
    /// The fixed order of the sources.
    pub(crate) const ORDER: [SourceId; 8] = [
        SourceId::Close,
        SourceId::Ack,
        SourceId::Crypto,
        SourceId::Path,
        SourceId::Control,
        SourceId::Probe,
        SourceId::Scheduled,
        SourceId::Ping,
    ];

    /// The order the sources fill a packet: [`ORDER`](Self::ORDER) with the probe last, so a
    /// probe carries data whenever any may join it and a PING only otherwise.
    pub(crate) const FILL_ORDER: [SourceId; 8] = [
        SourceId::Close,
        SourceId::Ack,
        SourceId::Crypto,
        SourceId::Path,
        SourceId::Control,
        SourceId::Scheduled,
        SourceId::Ping,
        SourceId::Probe,
    ];

    /// Returns the position in [`ORDER`](Self::ORDER).
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

/// The writer of a frame type, given by an exhaustive `match` without a wildcard, so a frame type
/// without an owner does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// The frame source.
    Source(SourceId),
    /// The packet commit, which pads.
    Commit,
}

/// Returns the owner of frame type `kind`. PING belongs to the Ping source; the Probe source
/// writes one too when a probe packet is not otherwise ack-eliciting.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the exhaustive map is a compile-time check; tests walk it"
    )
)]
pub(crate) const fn frame_owner(kind: FrameKind) -> Owner {
    match kind {
        FrameKind::Padding => Owner::Commit,
        FrameKind::Ping => Owner::Source(SourceId::Ping),
        FrameKind::Ack => Owner::Source(SourceId::Ack),
        FrameKind::Crypto | FrameKind::HandshakeDone => Owner::Source(SourceId::Crypto),
        FrameKind::PathChallenge | FrameKind::PathResponse => Owner::Source(SourceId::Path),
        FrameKind::ResetStream
        | FrameKind::StopSending
        | FrameKind::NewToken
        | FrameKind::MaxData
        | FrameKind::MaxStreamData
        | FrameKind::MaxStreams
        | FrameKind::DataBlocked
        | FrameKind::StreamDataBlocked
        | FrameKind::StreamsBlocked
        | FrameKind::NewConnectionId
        | FrameKind::RetireConnectionId => Owner::Source(SourceId::Control),
        FrameKind::Stream | FrameKind::Datagram => Owner::Source(SourceId::Scheduled),
        FrameKind::ConnectionClose | FrameKind::ApplicationClose => Owner::Source(SourceId::Close),
    }
}

/// Returns the source that a sent-frame record goes back to on acknowledgment or loss.
pub(crate) const fn sent_owner(frame: &SentFrame) -> SourceId {
    match frame {
        SentFrame::Stream { .. } => SourceId::Scheduled,
        SentFrame::Crypto { .. } => SourceId::Crypto,
        SentFrame::Ack { .. } => SourceId::Ack,
        SentFrame::Ping => SourceId::Ping,
        SentFrame::Control { kind, .. } => match kind {
            ControlKind::HandshakeDone => SourceId::Crypto,
            ControlKind::PathChallenge | ControlKind::PathResponse => SourceId::Path,
            ControlKind::MaxData
            | ControlKind::MaxStreamData
            | ControlKind::MaxStreamsBidi
            | ControlKind::MaxStreamsUni
            | ControlKind::DataBlocked
            | ControlKind::StreamDataBlocked
            | ControlKind::StreamsBlockedBidi
            | ControlKind::StreamsBlockedUni
            | ControlKind::NewConnectionId
            | ControlKind::RetireConnectionId
            | ControlKind::NewToken
            | ControlKind::ResetStream
            | ControlKind::StopSending => SourceId::Control,
        },
    }
}

/// A frame source.
pub(crate) trait FrameSource {
    /// What `next` hands to `write`.
    type Cand: Copy;

    /// Returns the source's candidate for the packet `cx` describes, and its class, without
    /// changing state.
    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, Self::Cand)>;

    /// Returns the room for frames a packet needs to carry `cand`, from the same state as `next`:
    /// the length of the smallest frame `write` accepts, or a bound above it.
    fn min_len(&self, cand: Self::Cand, cx: &SendCx<'_>) -> usize;

    /// Writes the candidate, or returns [`Full`] and leaves the packet as it was.
    fn write(
        &mut self,
        cand: Self::Cand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full>;
}

/// The packet being built, as the sources read it, or an empty packet while the attempt chooses
/// a candidate to start one.
#[derive(Debug)]
pub(crate) struct SendCx<'a> {
    /// The time of the attempt.
    pub(crate) now: Instant,
    /// When the packet leaves: its run's release, `now` or later.
    pub(crate) release: Instant,
    /// The packet's space.
    pub(crate) space: Space,
    /// The packet's path: the current one, or the alternate one, which takes only Path frames.
    pub(crate) path: PathId,
    /// Probes due in the space.
    pub(crate) probes_due: u8,
    /// The ack_delay_exponent this endpoint advertised, which scales its ACK Delay fields.
    pub(crate) ack_delay_exponent: u8,
    /// What has been written into the packet so far.
    pub(crate) packet: PacketCx,
    /// The sent-frame records of the frames written, for loss recovery once sealed.
    pub(crate) sent: &'a mut Vec<SentFrame>,
}

/// A source's candidate, as the admission table and the datagram plan use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) class: Class,
    /// The room for frames a packet needs to carry it ([`FrameSource::min_len`]).
    pub(crate) min_len: usize,
}

/// What the sources have written into one packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PacketCx {
    /// The Largest Acknowledged of the ACK frame written.
    pub(crate) ack: Option<u64>,
    /// Whether a CONNECTION_CLOSE was written.
    pub(crate) close: bool,
    /// Whether HANDSHAKE_DONE was written.
    pub(crate) handshake_done: bool,
    /// Whether the Ping source's PING was written.
    pub(crate) ping: bool,
    /// Whether a CRYPTO frame was written.
    pub(crate) crypto: bool,
    /// Whether an ack-eliciting frame was written.
    pub(crate) ack_eliciting: bool,
    /// Whether a frame of a class that takes pacing tokens was written.
    pub(crate) paced: bool,
    /// Whether a PATH_CHALLENGE or PATH_RESPONSE was written: the datagram is then padded to 1,200
    /// bytes when the path's credit allows.
    pub(crate) path: bool,
    /// Whether a PATH_CHALLENGE was written.
    pub(crate) challenge: bool,
}

/// The state of every frame source of a connection.
pub(crate) struct Sources<P: Prioritizer = MvfstOrder> {
    pub(crate) close: CloseSource,
    pub(crate) ack: [AckSource; 3],
    pub(crate) crypto: [CryptoSource; 3],
    pub(crate) path: PathSource,
    pub(crate) probe: ProbeSource,
    pub(crate) ping: PingSource,
    /// The streams and flow control the Control and Scheduled sources send from.
    pub(crate) streams: StreamState<P>,
    /// The connection IDs whose frames the Control source sends after the streams'.
    pub(crate) cids: Cids,
    /// The calls of [`Sources::fill`] into a packet without room left.
    #[cfg(test)]
    pub(crate) fills_without_room: u64,
    /// Whether [`Sources::on_packet_event`] ignores the run it is given and applies each STREAM
    /// frame on its own: the reference that coalesced runs are checked against.
    #[cfg(test)]
    pub(crate) per_frame_acks: bool,
}

/// STREAM bytes that one ACK frame acknowledged and that have not reached their stream yet: a
/// run of contiguous ranges of one stream, applied to it at once when the run ends. The holder
/// flushes it once the ACK frame is processed.
#[derive(Debug, Default)]
pub(crate) struct AckedRun {
    /// The stream, or `None` while the run is empty.
    id: Option<StreamId>,
    /// The first byte of the run.
    start: u64,
    /// The offset after the last byte of the run.
    end: u64,
    /// Whether the run ends with the FIN.
    fin: bool,
}

impl AckedRun {
    /// Adds the acknowledged frame `(offset, len, fin)` of stream `id`. Unless the frame continues
    /// the run, the run goes to its stream first and a new one starts.
    fn add<P: Prioritizer>(
        &mut self,
        streams: &mut StreamState<P>,
        id: StreamId,
        offset: u64,
        len: u16,
        fin: bool,
    ) {
        if self.id != Some(id) || offset != self.end {
            self.flush(streams);
            self.id = Some(id);
            self.start = offset;
            self.end = offset;
        }
        self.end += u64::from(len);
        self.fin |= fin;
    }

    /// Applies the run to its stream, if it holds one, and empties it.
    pub(crate) fn flush<P: Prioritizer>(&mut self, streams: &mut StreamState<P>) {
        let run = std::mem::take(self);
        if let Some(id) = run.id {
            streams.on_stream_acked(id, run.start, run.end - run.start, run.fin);
        }
    }
}

impl<P: Prioritizer> Sources<P> {
    /// Creates a connection's sources over `streams`; ACK tracking keeps at most
    /// `max_ack_ranges` ranges.
    pub(crate) fn new(max_ack_ranges: usize, streams: StreamState<P>, cids: Cids) -> Self {
        Self {
            close: CloseSource::default(),
            ack: Space::ALL.map(|space| AckSource::new(space, max_ack_ranges)),
            crypto: Space::ALL.map(CryptoSource::new),
            path: PathSource::default(),
            probe: ProbeSource,
            ping: PingSource::default(),
            streams,
            cids,
            #[cfg(test)]
            fills_without_room: 0,
            #[cfg(test)]
            per_frame_acks: false,
        }
    }

    /// Returns source `id`'s candidate for the packet `cx` describes.
    pub(crate) fn candidate(&self, id: SourceId, cx: &SendCx<'_>) -> Option<Candidate> {
        let space = cx.space.index();
        match id {
            SourceId::Close => candidate_of(&self.close, cx),
            SourceId::Ack => candidate_of(&self.ack[space], cx),
            SourceId::Crypto => candidate_of(&self.crypto[space], cx),
            SourceId::Path => candidate_of(&self.path, cx),
            SourceId::Control => control::next(&self.streams, cx)
                .map(|(class, cand)| Candidate {
                    class,
                    min_len: control::min_len(&self.streams, cand),
                })
                .or_else(|| candidate_of(&self.cids, cx)),
            SourceId::Probe => candidate_of(&self.probe, cx),
            SourceId::Scheduled => {
                scheduled::next(&self.streams, cx).map(|(class, slot)| Candidate {
                    class,
                    min_len: scheduled::min_len(&self.streams, slot, cx),
                })
            }
            SourceId::Ping => candidate_of(&self.ping, cx),
        }
    }

    /// Writes source `id`'s candidates into the packet while `admit` accepts their class and
    /// they fit.
    // The attempt calls this for the active sources of every packet it builds. `#[inline]` here
    // and on `fill_from` puts a copy of both into the attempt's codegen unit, so LLVM can inline
    // them however rustc partitions the crate that instantiates the attempt.
    #[inline]
    pub(crate) fn fill(
        &mut self,
        id: SourceId,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
        admit: impl Fn(Class) -> bool,
    ) {
        #[cfg(test)]
        if w.remaining() == 0 {
            self.fills_without_room += 1;
        }
        let space = cx.space.index();
        match id {
            SourceId::Close => fill_from(&mut self.close, w, cx, admit),
            SourceId::Ack => fill_from(&mut self.ack[space], w, cx, admit),
            SourceId::Crypto => fill_from(&mut self.crypto[space], w, cx, admit),
            SourceId::Path => fill_from(&mut self.path, w, cx, admit),
            SourceId::Control => {
                fill_from(&mut ControlSource(&mut self.streams), w, cx, &admit);
                fill_from(&mut self.cids, w, cx, admit);
            }
            SourceId::Probe => fill_from(&mut self.probe, w, cx, admit),
            SourceId::Scheduled => fill_from(&mut ScheduledSource(&mut self.streams), w, cx, admit),
            SourceId::Ping => fill_from(&mut self.ping, w, cx, admit),
        }
    }

    /// Applies what a sealed packet in `space` carried, as `packet` records.
    pub(crate) fn on_sealed(&mut self, space: Space, packet: &PacketCx) {
        if packet.ack.is_some() {
            self.ack[space.index()].on_sealed();
        }
        if packet.close {
            self.close.on_sealed(space);
        }
        if packet.handshake_done {
            self.crypto[space.index()].on_handshake_done_sealed();
        }
        if packet.ping {
            self.ping.on_sealed();
        }
    }

    /// Applies what the frames of a sealed packet change only once sealed: the stream bytes are
    /// committed to the prioritizer, which may move the streams in the wire order.
    pub(crate) fn on_frames_sealed(&mut self, frames: &[SentFrame]) {
        self.streams.on_sealed(frames);
        for frame in frames {
            if let SentFrame::Control { kind, key, .. } = *frame
                && is_cid_kind(kind)
            {
                self.cids.on_sealed(kind, key);
            }
        }
    }

    /// Returns the frames of a packet that was built but not sealed to their sources, as lost:
    /// CRYPTO and STREAM bytes and control frames changed their source's state at write.
    pub(crate) fn on_unsealed(&mut self, frames: &[SentFrame]) {
        for frame in frames {
            match *frame {
                SentFrame::Crypto { level, offset, len } => {
                    self.crypto[level.index()].on_lost(offset, len);
                }
                SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                } => {
                    self.streams.on_stream_lost(id, offset, len, fin);
                }
                SentFrame::Control { kind, key, .. } if is_cid_kind(kind) => {
                    self.cids.on_lost(kind, key);
                }
                SentFrame::Control { kind, key, value } if sent_owner(frame) == SourceId::Path => {
                    let slot = usize::try_from(key).unwrap_or(usize::MAX);
                    self.path.on_unsealed(kind, slot, value.to_be_bytes());
                }
                SentFrame::Control { kind, key, value }
                    if sent_owner(frame) == SourceId::Control =>
                {
                    self.streams.on_control_lost(kind, key, value);
                }
                _ => {}
            }
        }
    }

    /// Hands a packet's acknowledgment or loss to the sources that wrote its frames. `space` is
    /// the packet's space, if the caller has it. `dropped` is whether the backend reported that
    /// its datagram never left, which re-arms the ACK it carried. `run` is given while one ACK
    /// frame is processed and collects the STREAM bytes it acknowledges; without it, each STREAM
    /// frame reaches its stream at once. Returns whether a loss made any of its frames pending
    /// again.
    pub(crate) fn on_packet_event(
        &mut self,
        space: Option<Space>,
        event: PacketEvent<'_>,
        dropped: bool,
        run: Option<&mut AckedRun>,
    ) -> bool {
        let mut run = run;
        #[cfg(test)]
        if self.per_frame_acks {
            run = None;
        }
        let (packet, delivered) = match event {
            PacketEvent::Acked(packet) | PacketEvent::AckedAfterLoss(packet) => (packet, true),
            PacketEvent::Lost(packet) => (packet, false),
        };
        // Loss handling depends on the acknowledged bytes, so the run reaches its stream first.
        if !delivered && let Some(run) = run.as_deref_mut() {
            run.flush(&mut self.streams);
        }
        let mut pending = false;
        for frame in packet.frames() {
            match (sent_owner(frame), *frame) {
                (SourceId::Crypto, SentFrame::Crypto { level, offset, len }) => {
                    let crypto = &mut self.crypto[level.index()];
                    if delivered {
                        crypto.on_acked(offset, len);
                    } else {
                        pending |= crypto.on_lost(offset, len);
                    }
                }
                (SourceId::Crypto, SentFrame::Control { .. }) => {
                    let crypto = &mut self.crypto[Space::Data.index()];
                    if delivered {
                        crypto.on_handshake_done_acked();
                    } else {
                        pending |= crypto.on_handshake_done_lost();
                    }
                }
                (SourceId::Ack, SentFrame::Ack { largest }) => match (space, delivered) {
                    (Some(space), true) => self.ack[space.index()].on_frame_acked(largest),
                    // A dropped packet's space is unknown, so the ACK goes again in every space
                    // that has packets to acknowledge.
                    (_, false) if dropped => self.ack.iter_mut().for_each(AckSource::rearm),
                    _ => {}
                },
                (
                    SourceId::Scheduled,
                    SentFrame::Stream {
                        id,
                        offset,
                        len,
                        fin,
                    },
                ) => {
                    if !delivered {
                        pending |= self.streams.on_stream_lost(id, offset, len, fin);
                    } else if let Some(run) = run.as_deref_mut() {
                        run.add(&mut self.streams, id, offset, len, fin);
                    } else {
                        self.streams
                            .on_stream_acked(id, offset, u64::from(len), fin);
                    }
                }
                (SourceId::Control, SentFrame::Control { kind, key, .. }) if is_cid_kind(kind) => {
                    if delivered {
                        self.cids.on_acked(kind, key);
                    } else {
                        pending |= self.cids.on_lost(kind, key);
                    }
                }
                (SourceId::Control, SentFrame::Control { kind, key, value }) => {
                    // The run reaches its stream first, so that edges keep the order of frames.
                    if let Some(run) = run.as_deref_mut() {
                        run.flush(&mut self.streams);
                    }
                    if delivered {
                        self.streams.on_control_acked(kind, key, value);
                    } else {
                        pending |= self.streams.on_control_lost(kind, key, value);
                    }
                }
                (SourceId::Path, SentFrame::Control { kind, key, value }) if !delivered => {
                    let slot = usize::try_from(key).unwrap_or(usize::MAX);
                    self.path.on_lost(kind, slot, value.to_be_bytes());
                }
                // PING is never retransmitted.
                _ => {}
            }
        }
        pending
    }

    /// Queues the frames of `packet`, still in flight in the 1-RTT space, to go again in a PTO
    /// probe without declaring the packet lost, as mvfst's non-cloning PTO does. Returns whether
    /// any of them became pending again.
    pub(crate) fn requeue(&mut self, packet: SentPacket<'_>) -> bool {
        self.on_packet_event(Some(Space::Data), PacketEvent::Lost(packet), false, None)
    }

    /// Clears the state of `space` when its keys are discarded.
    pub(crate) fn discard(&mut self, space: Space, max_ack_ranges: usize) {
        self.ack[space.index()] = AckSource::new(space, max_ack_ranges);
        self.crypto[space.index()] = CryptoSource::new(space);
        self.close.discard(space);
    }
}

/// The send buffer's view of a packet writer.
pub(super) struct Adapter<'w, 'a>(pub(super) &'w mut PacketWriter<'a>);

impl FrameWriter for Adapter<'_, '_> {
    fn remaining(&self) -> usize {
        self.0.remaining()
    }

    fn put_slice(&mut self, bytes: &[u8]) {
        self.0
            .put_ack_eliciting_bytes(bytes)
            .expect("should fit: the send buffer stays within the room it was given");
    }

    fn put_payload(&mut self, data: &Bytes, range: Range<usize>) {
        self.put_slice(&data[range]);
    }
}

/// Returns whether a Control record is a connection ID frame, whose acknowledgment and loss go to
/// [`Cids`] rather than to the streams.
fn is_cid_kind(kind: ControlKind) -> bool {
    matches!(
        kind,
        ControlKind::NewConnectionId | ControlKind::RetireConnectionId
    )
}

/// Returns a source's candidate, with its class and the room it needs.
fn candidate_of<S: FrameSource>(source: &S, cx: &SendCx<'_>) -> Option<Candidate> {
    source.next(cx).map(|(class, cand)| Candidate {
        class,
        min_len: source.min_len(cand, cx),
    })
}

/// Joins `source`'s candidates to the packet while room is left, `admit` accepts their class and
/// they fit.
// Inlined with `Sources::fill`; see there.
#[inline]
fn fill_from<S: FrameSource>(
    source: &mut S,
    w: &mut PacketWriter<'_>,
    cx: &mut SendCx<'_>,
    admit: impl Fn(Class) -> bool,
) {
    // Every frame takes at least one byte.
    while w.remaining() > 0
        && let Some((class, cand)) = source.next(cx)
        && admit(class)
    {
        if source.write(cand, w, cx).is_err() {
            break;
        }
        cx.packet.ack_eliciting = w.is_ack_eliciting();
        cx.packet.paced |= class.is_paced();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use bytes::Bytes;
    use mvfstr_crypto::TAG_LEN;
    use mvfstr_wire::ConnectionId;
    use mvfstr_wire::Dir;
    use mvfstr_wire::Frame;
    use mvfstr_wire::Frames;
    use mvfstr_wire::HeaderSpec;
    use mvfstr_wire::Side;
    use mvfstr_wire::StreamId;
    use mvfstr_wire::TransportErrorCode;
    use mvfstr_wire::TransportParameters;
    use mvfstr_wire::VarInt;

    use super::control::ControlCand;
    use super::*;
    use crate::AckPolicy;
    use crate::AppCode;
    use crate::CreditDue;
    use crate::OpenError;
    use crate::SendOrder;
    use crate::TransportConfig;
    use crate::receive::Ecn;
    use crate::recovery::sent::SentFlags;
    use crate::recovery::sent::SentPackets;
    use crate::recovery::test_epoch;
    use crate::streams::recv_buf::PagePool;

    /// Checks that `source`'s candidate in `space` fits a packet with exactly the room for frames
    /// that `min_len` returns and, when `exact`, does not fit one with a byte less.
    fn fits_the_room_it_asks_for<S: FrameSource>(source: &mut S, space: Space, exact: bool) {
        let mut sent = Vec::new();
        let mut cx = SendCx {
            now: test_epoch() + Duration::from_millis(5),
            release: test_epoch() + Duration::from_millis(5),
            space,
            path: crate::PathId(0),
            probes_due: 1,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        let (_, cand) = source.next(&cx).expect("a candidate");
        let min_len = source.min_len(cand, &cx);
        let dcid = ConnectionId::new(&[1; 8]).unwrap();
        let header = HeaderSpec::OneRtt {
            dcid,
            spin: false,
            key_phase: false,
        };
        // A short header with a 4-byte packet number, `payload` bytes of frames and the tag.
        let packet = |payload: usize| vec![0; 1 + dcid.len() + 4 + payload + TAG_LEN];
        if exact && min_len > 1 {
            let mut buf = packet(min_len - 1);
            let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
            assert_eq!(w.remaining(), min_len - 1);
            assert!(
                source.write(cand, &mut w, &mut cx).is_err(),
                "{space:?}: {min_len} bytes is more than the frame needs"
            );
        }
        let mut buf = packet(min_len);
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        assert_eq!(w.remaining(), min_len);
        assert_eq!(
            source.write(cand, &mut w, &mut cx),
            Ok(()),
            "{space:?}: the frame does not fit the {min_len} bytes it asks for"
        );
    }

    #[test]
    fn every_candidate_fits_the_room_it_asks_for() {
        let mut close = CloseSource::default();
        close.start(
            CloseFrame::Transport {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: VarInt::from_u32(0x1e),
                reason: Bytes::from_static(b"a transport reason, sent in every space"),
            },
            [true; 3],
        );
        fits_the_room_it_asks_for(&mut close, Space::Initial, true);
        let mut close = CloseSource::default();
        close.start(
            CloseFrame::Application {
                code: VarInt::from_u32(7),
                reason: Bytes::from(vec![b'x'; 100]),
            },
            [true; 3],
        );
        // Without its reason in Initial and Handshake packets, with it in 1-RTT ones.
        fits_the_room_it_asks_for(&mut close, Space::Handshake, true);
        fits_the_room_it_asks_for(&mut close, Space::Data, true);

        // An ACK_ECN frame with a gap: the smallest frame holds the largest range alone.
        let mut ack = AckSource::new(Space::Data, 32);
        for pn in (0..=3).chain(70..=90) {
            ack.on_packet(pn, true, Ecn::Ect0, test_epoch());
        }
        ack.decide(
            test_epoch(),
            &AckPolicy::default(),
            Duration::from_millis(24),
        );
        fits_the_room_it_asks_for(&mut ack, Space::Data, true);

        // New CRYPTO bytes at an offset past 63, whose varint takes two bytes.
        let mut crypto = CryptoSource::new(Space::Handshake);
        crypto.push(Bytes::from(vec![7; 300])).unwrap();
        fits_the_room_it_asks_for(&mut crypto, Space::Handshake, true);
        let mut crypto_cx_sent = Vec::new();
        let mut buf = vec![0; 100 + TAG_LEN];
        let dcid = ConnectionId::new(&[1; 8]).unwrap();
        let header = HeaderSpec::OneRtt {
            dcid,
            spin: false,
            key_phase: false,
        };
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        let mut cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Handshake,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut crypto_cx_sent,
        };
        crypto
            .write(crypto::CryptoCand::Data, &mut w, &mut cx)
            .unwrap();
        fits_the_room_it_asks_for(&mut crypto, Space::Handshake, true);
        // Lost bytes start at a lower offset, whose varint may be shorter.
        crypto.on_lost(0, 10);
        fits_the_room_it_asks_for(&mut crypto, Space::Handshake, false);
        let mut done = CryptoSource::new(Space::Data);
        done.send_handshake_done();
        fits_the_room_it_asks_for(&mut done, Space::Data, true);

        let mut ping = PingSource::default();
        ping.queue();
        fits_the_room_it_asks_for(&mut ping, Space::Data, true);
        fits_the_room_it_asks_for(&mut ProbeSource, Space::Handshake, true);

        control_candidates_fit_the_room_they_ask_for();
        scheduled_candidates_fit_the_room_they_ask_for();
    }

    const ORDER: SendOrder = SendOrder {
        class: 1,
        urgency: 3,
        incremental: false,
        order: 0,
    };

    /// Returns a server's streams after the client's transport parameters `peer`, with 1,000-byte
    /// receive windows that do not autotune and one unidirectional stream for the client.
    fn server_streams(peer: TransportParameters) -> StreamState {
        let config = TransportConfig::builder()
            .max_data(1_000)
            .max_data_autotune(None)
            .max_stream_data_bidi_remote(1_000)
            .max_stream_data_autotune(None)
            .max_streams_uni(1)
            .build()
            .expect("a valid transport config");
        let mut streams = StreamState::new(Side::Server, &config, PagePool::new());
        streams.on_peer_params(&peer).expect("valid parameters");
        streams
    }

    /// Returns the Control source's candidate, if any.
    fn control_candidate(streams: &mut StreamState) -> Option<ControlCand> {
        let mut sent = Vec::new();
        let cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        ControlSource(streams).next(&cx).map(|(_, cand)| cand)
    }

    /// Checks each kind of Control frame, the connection's and a stream's.
    fn control_candidates_fit_the_room_they_ask_for() {
        let now = test_epoch();
        let srtt = Duration::from_millis(20);
        let client = |dir, index| StreamId::new(Side::Client, dir, index).unwrap();
        let mut s = server_streams(TransportParameters {
            initial_max_stream_data_bidi_remote: VarInt::from_u32(100),
            initial_max_streams_bidi: VarInt::from_u32(2),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        // Read bytes make MAX_DATA and MAX_STREAM_DATA due, and a reaped client stream MAX_STREAMS.
        let read = client(Dir::Bi, 0);
        s.on_stream_frame(read, 0, &[0; 600], false, now, srtt)
            .unwrap();
        assert_eq!(s.consume(read, 600, now, srtt), Ok(CreditDue::Due));
        let reaped = client(Dir::Uni, 0);
        s.on_stream_frame(reaped, 0, &[0; 10], true, now, srtt)
            .unwrap();
        assert_eq!(s.consume(reaped, 10, now, srtt), Ok(CreditDue::NotDue));
        while s.next_edge().is_some() {}
        // A reset stream makes RESET_STREAM due, bytes staged without connection credit
        // DATA_BLOCKED, and an open past the limit STREAMS_BLOCKED.
        let ours = s.open(Dir::Bi, ORDER).unwrap();
        s.reset(ours, AppCode::from_u32(1)).unwrap();
        let staged = s.open(Dir::Bi, ORDER).unwrap();
        assert_eq!(
            s.send(staged, &mut Bytes::from(vec![0; 10]), 1 << 20),
            Ok(10)
        );
        assert_eq!(s.open(Dir::Bi, ORDER), Err(OpenError::StreamLimit));
        // A stream at zero stream credit makes STREAM_DATA_BLOCKED due, and a stopped client
        // stream STOP_SENDING.
        let uni = s.open(Dir::Uni, ORDER).unwrap();
        assert_eq!(s.send(uni, &mut Bytes::from_static(b"x"), 1 << 20), Ok(0));
        let stopped = client(Dir::Bi, 1);
        s.on_stream_frame(stopped, 0, &[0; 10], false, now, srtt)
            .unwrap();
        s.stop_sending(stopped, AppCode::from_u32(2), now, srtt)
            .unwrap();
        let mut kinds = Vec::new();
        while let Some(cand) = control_candidate(&mut s) {
            kinds.push(match cand {
                ControlCand::Stream { frame, .. } => format!("{frame:?}"),
                other => format!("{other:?}"),
            });
            fits_the_room_it_asks_for(&mut ControlSource(&mut s), Space::Data, true);
        }
        assert_eq!(
            kinds,
            [
                "MaxData",
                "MaxStreams(Uni)",
                "DataBlocked",
                "StreamsBlocked(Bi)",
                "MaxStreamData",
                "ResetStream",
                "StreamDataBlocked",
                "StopSending"
            ]
        );
    }

    /// Checks new bytes at offsets whose varints take one and two bytes, then lost bytes at a
    /// lower offset. A frame that ends the packet leaves out its length, so a room one byte
    /// smaller than `min_len` still holds one: `min_len` is a bound, not exact.
    fn scheduled_candidates_fit_the_room_they_ask_for() {
        let mut s = server_streams(TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        let id = s.open(Dir::Uni, ORDER).unwrap();
        assert_eq!(
            s.send(id, &mut Bytes::from(vec![7; 1_000]), 1 << 20),
            Ok(1_000)
        );
        fits_the_room_it_asks_for(&mut ScheduledSource(&mut s), Space::Data, false);
        let mut sent = Vec::new();
        let mut buf = vec![0; 100 + TAG_LEN];
        let header = HeaderSpec::OneRtt {
            dcid: ConnectionId::new(&[1; 8]).unwrap(),
            spin: false,
            key_phase: false,
        };
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        let mut cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        let (_, cand) = ScheduledSource(&mut s).next(&cx).expect("new bytes");
        ScheduledSource(&mut s)
            .write(cand, &mut w, &mut cx)
            .unwrap();
        let sent_end = |s: &StreamState| {
            s.streams
                .get(id)
                .unwrap()
                .data()
                .send
                .as_ref()
                .unwrap()
                .buf
                .sent_end()
        };
        assert!(sent_end(&s) > 63, "the next offset takes two bytes");
        fits_the_room_it_asks_for(&mut ScheduledSource(&mut s), Space::Data, false);
        s.on_stream_lost(id, 0, 10, false);
        fits_the_room_it_asks_for(&mut ScheduledSource(&mut s), Space::Data, false);
    }

    #[test]
    fn nothing_can_follow_a_stream_frame_without_its_length() {
        let mut s = server_streams(TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        let id = s.open(Dir::Uni, ORDER).unwrap();
        let data: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            s.send(id, &mut Bytes::from(data.clone()), 1 << 20),
            Ok(5_000)
        );
        let mut ping = PingSource::default();
        ping.queue();
        let dcid = ConnectionId::new(&[1; 8]).unwrap();
        let header = HeaderSpec::OneRtt {
            dcid,
            spin: false,
            key_phase: false,
        };
        let overhead = 1 + dcid.len() + 4 + TAG_LEN;
        let mut sent = Vec::new();
        let mut cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        let (_, cand) = ScheduledSource(&mut s).next(&cx).expect("new bytes");
        // A payload one byte smaller than the candidate's `min_len`, then a full-size packet.
        for payload in [scheduled::min_len(&s, cand, &cx) - 1, 1_200 - overhead] {
            let mut buf = vec![0; overhead + payload];
            let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
            cx.sent.clear();
            let (_, cand) = ScheduledSource(&mut s).next(&cx).expect("new bytes");
            ScheduledSource(&mut s)
                .write(cand, &mut w, &mut cx)
                .unwrap();
            assert_eq!(w.remaining(), 0, "the STREAM frame fills the packet");
            // Every later source and every way into the packet, padding included, is refused.
            assert_eq!(
                ScheduledSource(&mut s).write(cand, &mut w, &mut cx),
                Err(Full)
            );
            assert_eq!(ping.write((), &mut w, &mut cx), Err(Full));
            assert_eq!(ProbeSource.write((), &mut w, &mut cx), Err(Full));
            assert!(w.frame(&Frame::Ping).is_err());
            assert!(w.frame(&Frame::Padding { len: 1 }).is_err());
            assert_eq!(w.put_ack_eliciting_bytes(&[0]), Err(Full));
            assert_eq!(
                w.ack(0..=0, std::iter::empty(), VarInt::ZERO, None),
                Err(Full)
            );
            // A full-size packet is already 1,200 bytes long; a shorter one cannot be padded.
            assert_eq!(w.pad_to(1_200).is_ok(), overhead + payload == 1_200);
            assert_eq!(w.remaining(), 0);
            let layout = w.finish();
            assert_eq!(
                (layout.len, layout.payload_len),
                (overhead + payload, payload)
            );

            let [SentFrame::Stream { offset, len, .. }] = cx.sent[..] else {
                panic!("{:?}", cx.sent);
            };
            let plaintext = &buf[layout.hdr_len..layout.hdr_len + layout.payload_len];
            assert_eq!(plaintext[0] & 0x02, 0, "the STREAM frame has no length");
            let frames: Vec<_> = Frames::new(plaintext).map(Result::unwrap).collect();
            let at = offset as usize;
            assert!(
                matches!(
                    frames[..],
                    [Frame::Stream { offset: o, data: d, fin: false, .. }]
                        if o.into_inner() == offset && d == &data[at..at + usize::from(len)]
                ),
                "{frames:?}"
            );
        }
    }

    /// A source with a candidate for each of its `left` frames, each taking `len` bytes or the
    /// rest of the packet if less is left. It counts the calls of `next` and `write`, and the
    /// writes that fail with [`Full`].
    struct Counting {
        left: usize,
        len: usize,
        nexts: Cell<usize>,
        writes: usize,
        full: usize,
    }

    impl Counting {
        fn new(left: usize, len: usize) -> Self {
            Self {
                left,
                len,
                nexts: Cell::new(0),
                writes: 0,
                full: 0,
            }
        }

        /// Returns the calls of `next` and `write` so far, and how many of the writes failed.
        fn calls(&self) -> (usize, usize, usize) {
            (self.nexts.get(), self.writes, self.full)
        }
    }

    impl FrameSource for Counting {
        type Cand = ();

        fn next(&self, _cx: &SendCx<'_>) -> Option<(Class, ())> {
            self.nexts.set(self.nexts.get() + 1);
            (self.left > 0).then_some((Class::NewStream, ()))
        }

        fn min_len(&self, _cand: (), _cx: &SendCx<'_>) -> usize {
            1
        }

        fn write(
            &mut self,
            _cand: (),
            w: &mut PacketWriter<'_>,
            _cx: &mut SendCx<'_>,
        ) -> Result<(), Full> {
            self.writes += 1;
            // Every frame takes at least one byte.
            let written = w.put_ack_eliciting_bytes(&vec![0; self.len.min(w.remaining()).max(1)]);
            match written {
                Ok(()) => self.left -= 1,
                Err(Full) => self.full += 1,
            }
            written
        }
    }

    #[test]
    fn filling_stops_once_a_frame_fills_the_packet() {
        let dcid = ConnectionId::new(&[1; 8]).unwrap();
        let header = HeaderSpec::OneRtt {
            dcid,
            spin: false,
            key_phase: false,
        };
        let mut sent = Vec::new();
        let mut cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        // A frame that takes the rest of the packet, as a STREAM frame without its Length does.
        let mut buf = vec![0; 1_200];
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        let mut fills = Counting::new(usize::MAX, usize::MAX);
        fill_from(&mut fills, &mut w, &mut cx, |_| true);
        assert_eq!(w.remaining(), 0);
        assert_eq!(
            fills.calls(),
            (1, 1, 0),
            "one candidate, whose frame fills the packet, and one write"
        );

        // Frames that leave room let their source and the next one write, until a frame fills
        // the packet; then a later source is not called at all.
        let payload = 10;
        let mut buf = vec![0; 1 + dcid.len() + 4 + payload + TAG_LEN];
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        assert_eq!(w.remaining(), payload);
        let mut short = Counting::new(2, 3);
        let mut fills = Counting::new(usize::MAX, usize::MAX);
        let mut later = Counting::new(usize::MAX, usize::MAX);
        for source in [&mut short, &mut fills, &mut later] {
            fill_from(source, &mut w, &mut cx, |_| true);
        }
        assert_eq!(
            short.calls(),
            (3, 2, 0),
            "two 3-byte frames, then the source has no more candidates"
        );
        assert_eq!(fills.calls(), (1, 1, 0), "one frame in the last 4 bytes");
        assert_eq!(later.calls(), (0, 0, 0), "the packet is full");
        assert_eq!(w.finish().payload_len, payload);
    }

    /// Writes every candidate of `source` into one 1-RTT packet; returns their records.
    fn write_all<S: FrameSource>(source: &mut S) -> Vec<SentFrame> {
        let mut sent = Vec::new();
        let mut buf = vec![0; 1_200];
        let header = HeaderSpec::OneRtt {
            dcid: ConnectionId::new(&[1; 8]).unwrap(),
            spin: false,
            key_phase: false,
        };
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
        let mut cx = SendCx {
            now: test_epoch(),
            release: test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: PacketCx::default(),
            sent: &mut sent,
        };
        while let Some((_, cand)) = source.next(&cx) {
            source.write(cand, &mut w, &mut cx).expect("room for it");
        }
        sent
    }

    /// Returns the sources of a connection with `streams` and only its handshake connection IDs.
    fn sources(streams: StreamState) -> Sources {
        let cid = ConnectionId::new(&[1; 8]).unwrap();
        let cids = Cids {
            local: crate::cid::LocalCids::new(cid, mvfstr_wire::ResetToken([0; 16])),
            peer: crate::cid::PeerCids::new(cid, 2),
        };
        Sources::new(32, streams, cids)
    }

    /// Returns [`Sources::requeue`]'s result for a 1-RTT packet in flight that carried `frames`.
    fn requeue(sources: &mut Sources, frames: &[SentFrame]) -> bool {
        let mut sent = SentPackets::new(test_epoch(), 0);
        for frame in frames {
            sent.push_frame(*frame);
        }
        let flags = SentFlags::ACK_ELICITING | SentFlags::IN_FLIGHT;
        sent.on_sent(0, test_epoch(), 1_200, flags, 0)
            .expect("the first packet number");
        sources.requeue(sent.get(0).expect("the packet just recorded"))
    }

    #[test]
    fn a_requeued_stream_frame_counts_only_if_some_of_it_became_lost() {
        let mut s = server_streams(TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        let id = s.open(Dir::Uni, ORDER).unwrap();
        assert_eq!(
            s.send(id, &mut Bytes::from(vec![7; 1_000]), 1 << 20),
            Ok(1_000)
        );
        s.finish(id).unwrap();
        let stream = |offset, len, fin| SentFrame::Stream {
            id,
            offset,
            len,
            fin,
        };
        assert_eq!(
            write_all(&mut ScheduledSource(&mut s)),
            [stream(0, 1_000, true)]
        );
        let mut sources = sources(s);
        sources.streams.on_stream_acked(id, 0, 300, false);
        sources.streams.on_stream_acked(id, 600, 100, false);
        assert!(
            !requeue(&mut sources, &[stream(0, 300, false)]),
            "acknowledged"
        );
        assert!(
            !requeue(&mut sources, &[stream(600, 100, false)]),
            "acknowledged out of order"
        );
        assert!(
            requeue(&mut sources, &[stream(200, 200, false)]),
            "300..400"
        );
        assert!(
            !requeue(&mut sources, &[stream(300, 100, false)]),
            "lost already"
        );
        assert!(
            requeue(&mut sources, &[stream(300, 400, false)]),
            "400..600"
        );
        assert!(requeue(&mut sources, &[stream(1_000, 0, true)]), "the FIN");
        assert!(
            !requeue(&mut sources, &[stream(1_000, 0, true)]),
            "the FIN is lost already"
        );
    }

    /// Returns the sources of a server whose one unidirectional stream sent its 1,000 bytes and
    /// its FIN in one frame, and that stream.
    fn sent_stream() -> (Sources, StreamId) {
        let mut s = server_streams(TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        let id = s.open(Dir::Uni, ORDER).unwrap();
        assert_eq!(
            s.send(id, &mut Bytes::from(vec![7; 1_000]), 1 << 20),
            Ok(1_000)
        );
        s.finish(id).unwrap();
        assert_eq!(write_all(&mut ScheduledSource(&mut s)).len(), 1);
        (sources(s), id)
    }

    /// Returns a record of 1-RTT packets in flight, numbered from 0, each carrying the frames of
    /// its entry in `packets`.
    fn sent_packets(packets: &[&[SentFrame]]) -> SentPackets {
        let mut sent = SentPackets::new(test_epoch(), 0);
        for (pn, frames) in (0..).zip(packets) {
            for frame in *frames {
                sent.push_frame(*frame);
            }
            let flags = SentFlags::ACK_ELICITING | SentFlags::IN_FLIGHT;
            sent.on_sent(pn, test_epoch(), 1_200, flags, pn)
                .expect("the next packet number");
        }
        sent
    }

    /// Returns what the send buffer of stream `id` shows, and how many streams hold lost data.
    fn send_view(sources: &Sources, id: StreamId) -> (u64, usize, bool, bool, u32) {
        let buf = sources.streams.send_buf(id).expect("a send half");
        (
            buf.acked_end(),
            buf.buffered(),
            buf.has_lost(),
            buf.is_acked(),
            sources.streams.streams.lost(),
        )
    }

    #[test]
    fn a_loss_after_a_run_in_the_same_ack_frame_is_pending_as_without_the_run() {
        let (_, id) = sent_stream();
        let stream = |offset, len, fin| SentFrame::Stream {
            id,
            offset,
            len,
            fin,
        };
        // Each case acknowledges one packet and then declares lost another that carried the same
        // bytes again: a retransmission the run covers, one that reaches past it, and the FIN.
        for (acked, lost) in [
            (stream(0, 300, false), stream(0, 300, false)),
            (stream(0, 300, false), stream(200, 200, false)),
            (stream(700, 300, true), stream(1_000, 0, true)),
        ] {
            let sent = sent_packets(&[&[acked], &[lost]]);
            let packet = |pn| sent.get(pn).expect("a packet in the record");
            let space = Some(Space::Data);

            let (mut reference, _) = sent_stream();
            reference.on_packet_event(space, PacketEvent::Acked(packet(0)), false, None);
            let want = reference.on_packet_event(space, PacketEvent::Lost(packet(1)), false, None);

            let (mut sources, _) = sent_stream();
            let mut run = AckedRun::default();
            let before = sources.streams.streams.reindexes();
            sources.on_packet_event(space, PacketEvent::Acked(packet(0)), false, Some(&mut run));
            assert_eq!(
                sources.streams.streams.reindexes(),
                before,
                "{acked:?}: the acknowledgment stays in the run"
            );
            let pending =
                sources.on_packet_event(space, PacketEvent::Lost(packet(1)), false, Some(&mut run));
            assert_eq!(pending, want, "{lost:?} after {acked:?}");
            run.flush(&mut sources.streams);
            assert_eq!(
                send_view(&sources, id),
                send_view(&reference, id),
                "{lost:?} after {acked:?}"
            );
            sources.streams.streams.assert_indexed();
        }
    }

    #[test]
    fn a_requeued_control_frame_counts_only_if_it_became_pending_again() {
        let now = test_epoch();
        let srtt = Duration::from_millis(20);
        let mut s = server_streams(TransportParameters {
            initial_max_streams_bidi: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        // A MAX_DATA and a MAX_STREAMS, each replaced by a larger one.
        s.conn_recv.on_update_sent(2_000, now);
        s.conn_recv.on_update_sent(3_000, now);
        let limit = s.max_streams[0].state().0;
        for value in [limit + 1, limit + 2] {
            s.max_streams[0].raise(value);
            s.max_streams[0].on_written(value);
        }
        // DATA_BLOCKED for a byte staged at the zero connection credit, RESET_STREAM for a reset
        // stream and STOP_SENDING for a stopped client stream, all sent; the client
        // acknowledged the STOP_SENDING.
        s.staged = 1;
        s.note_conn_blocked();
        let ours = s.open(Dir::Bi, ORDER).unwrap();
        s.reset(ours, AppCode::from_u32(1)).unwrap();
        let stopped = StreamId::new(Side::Client, Dir::Bi, 0).unwrap();
        s.on_stream_frame(stopped, 0, &[0; 10], false, now, srtt)
            .unwrap();
        s.stop_sending(stopped, AppCode::from_u32(2), now, srtt)
            .unwrap();
        let sent = write_all(&mut ControlSource(&mut s));
        let [blocked, reset, stop] = sent[..] else {
            panic!("{sent:?}");
        };
        let SentFrame::Control { kind, key, value } = stop else {
            panic!("{stop:?}");
        };
        assert_eq!(kind, ControlKind::StopSending);
        s.on_control_acked(kind, key, value);
        let mut sources = sources(s);
        let lost = |sources: &mut Sources, kind, value| {
            requeue(
                sources,
                &[SentFrame::Control {
                    kind,
                    key: 0,
                    value,
                }],
            )
        };
        assert!(!lost(&mut sources, ControlKind::MaxData, 2_000), "replaced");
        assert!(lost(&mut sources, ControlKind::MaxData, 3_000));
        assert!(
            !lost(&mut sources, ControlKind::MaxData, 3_000),
            "MAX_DATA pending already"
        );
        let bidi = ControlKind::MaxStreamsBidi;
        assert!(!lost(&mut sources, bidi, limit + 1), "replaced");
        assert!(lost(&mut sources, bidi, limit + 2));
        assert!(
            !lost(&mut sources, bidi, limit + 2),
            "MAX_STREAMS pending already"
        );
        assert!(
            !lost(&mut sources, ControlKind::StreamsBlockedBidi, 5),
            "a stream limit the peer never set"
        );
        assert!(requeue(&mut sources, &[blocked]));
        assert!(
            !requeue(&mut sources, &[blocked]),
            "DATA_BLOCKED pending already"
        );
        // Sent again, then the staged byte goes away.
        assert!(write_all(&mut ControlSource(&mut sources.streams)).contains(&blocked));
        sources.streams.staged = 0;
        assert!(
            !requeue(&mut sources, &[blocked]),
            "DATA_BLOCKED with nothing staged"
        );
        assert!(requeue(&mut sources, &[reset]));
        assert!(
            !requeue(&mut sources, &[reset]),
            "RESET_STREAM owed already"
        );
        assert!(!requeue(&mut sources, &[stop]), "STOP_SENDING acknowledged");
        assert!(
            !lost(&mut sources, ControlKind::NewToken, 0),
            "nothing sends NEW_TOKEN again"
        );
    }

    #[test]
    fn a_requeued_stream_control_frame_counts_only_while_the_half_states_permit_it() {
        let now = test_epoch();
        let srtt = Duration::from_millis(20);
        let mut s = server_streams(TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 20),
            initial_max_stream_data_uni: VarInt::from_u32(100),
            initial_max_streams_uni: VarInt::from_u32(1),
            ..TransportParameters::default()
        });
        // STREAM_DATA_BLOCKED for a stream that spent its 100 bytes of credit with more staged,
        // and STOP_SENDING for two client streams.
        let blocked = s.open(Dir::Uni, ORDER).unwrap();
        s.send(blocked, &mut Bytes::from(vec![7; 200]), 1 << 20)
            .unwrap();
        write_all(&mut ScheduledSource(&mut s));
        let [finished, reset] = [0, 1].map(|n| StreamId::new(Side::Client, Dir::Bi, n).unwrap());
        for id in [finished, reset] {
            s.on_stream_frame(id, 0, &[0; 10], false, now, srtt)
                .unwrap();
            s.stop_sending(id, AppCode::from_u32(2), now, srtt).unwrap();
        }
        let sent = write_all(&mut ControlSource(&mut s));
        let [data_blocked, stop_finished, stop_reset] = sent[..] else {
            panic!("{sent:?}");
        };
        let mut sources = sources(s);
        for frame in sent.iter().copied() {
            assert!(requeue(&mut sources, &[frame]), "{frame:?} while permitted");
        }
        assert_eq!(write_all(&mut ControlSource(&mut sources.streams)), sent);
        // The stream is reset; every byte of one client stream arrives, and the client resets
        // the other.
        let s = &mut sources.streams;
        s.reset(blocked, AppCode::from_u32(1)).unwrap();
        s.on_stream_frame(finished, 10, &[0; 10], true, now, srtt)
            .unwrap();
        s.on_reset_stream(reset, AppCode::from_u32(3), 10, now, srtt)
            .unwrap();
        let counted = [data_blocked, stop_finished, stop_reset].map(|frame| {
            let SentFrame::Control { kind, .. } = frame else {
                panic!("{frame:?}");
            };
            (kind, requeue(&mut sources, &[frame]))
        });
        assert_eq!(
            counted,
            [
                (ControlKind::StreamDataBlocked, false),
                (ControlKind::StopSending, false),
                (ControlKind::StopSending, false),
            ]
        );
    }

    #[test]
    fn a_requeued_crypto_frame_counts_only_if_some_of_it_became_lost() {
        let mut sources = sources(server_streams(TransportParameters::default()));
        let crypto = &mut sources.crypto[Space::Data.index()];
        crypto.push(Bytes::from(vec![7; 300])).unwrap();
        let frame = |offset, len| SentFrame::Crypto {
            level: Space::Data,
            offset,
            len,
        };
        assert_eq!(write_all(crypto), [frame(0, 300)]);
        crypto.on_acked(0, 100);
        assert!(!requeue(&mut sources, &[frame(0, 100)]), "acknowledged");
        assert!(requeue(&mut sources, &[frame(0, 300)]), "100..300");
        assert!(!requeue(&mut sources, &[frame(100, 200)]), "lost already");
    }

    #[test]
    fn a_requeued_handshake_done_counts_only_if_it_became_pending_again() {
        let mut sources = sources(server_streams(TransportParameters::default()));
        let crypto = &mut sources.crypto[Space::Data.index()];
        crypto.send_handshake_done();
        let sent = write_all(crypto);
        crypto.on_handshake_done_sealed();
        assert!(requeue(&mut sources, &sent));
        assert!(!requeue(&mut sources, &sent), "pending already");
        // Sent again, and the peer acknowledged that copy.
        let crypto = &mut sources.crypto[Space::Data.index()];
        assert_eq!(write_all(crypto), sent);
        crypto.on_handshake_done_sealed();
        crypto.on_handshake_done_acked();
        assert!(!requeue(&mut sources, &sent), "delivered");
    }

    #[test]
    fn a_requeued_connection_id_frame_counts_only_if_it_became_pending_again() {
        let mut sources = sources(server_streams(TransportParameters::default()));
        // A NEW_CONNECTION_ID for a new local ID, and a RETIRE_CONNECTION_ID for the peer's
        // handshake ID, which a Retire Prior To of 1 retires.
        let cids = &mut sources.cids;
        cids.local.issue(
            ConnectionId::new(&[2; 8]).unwrap(),
            mvfstr_wire::ResetToken([2; 16]),
        );
        let fresh = ConnectionId::new(&[3; 8]).unwrap();
        cids.peer
            .on_new(1, 1, fresh, mvfstr_wire::ResetToken([3; 16]))
            .unwrap();
        let sent = write_all(cids);
        let [new, retire] = sent[..] else {
            panic!("{sent:?}");
        };
        for frame in [new, retire] {
            assert!(requeue(&mut sources, &[frame]), "{frame:?} in flight");
            assert!(
                !requeue(&mut sources, &[frame]),
                "{frame:?} pending already"
            );
        }
        // Sent again, and the peer acknowledged both copies.
        assert_eq!(write_all(&mut sources.cids), sent);
        for frame in &sent {
            let SentFrame::Control { kind, key, .. } = *frame else {
                panic!("{frame:?}");
            };
            sources.cids.on_acked(kind, key);
        }
        for frame in [new, retire] {
            assert!(!requeue(&mut sources, &[frame]), "{frame:?} delivered");
        }
    }

    #[test]
    fn every_frame_type_has_an_owner() {
        for kind in FrameKind::ALL {
            let owner = frame_owner(kind);
            assert_eq!(
                owner == Owner::Commit,
                kind == FrameKind::Padding,
                "{kind:?}: only PADDING is written outside the sources"
            );
        }
        assert_eq!(
            frame_owner(FrameKind::HandshakeDone),
            Owner::Source(SourceId::Crypto)
        );
        assert_eq!(
            sent_owner(&SentFrame::Control {
                kind: ControlKind::HandshakeDone,
                key: 0,
                value: 0,
            }),
            SourceId::Crypto,
            "HANDSHAKE_DONE returns to the source that wrote it"
        );
    }

    #[test]
    fn sources_are_asked_in_the_fixed_order() {
        let names: Vec<_> = SourceId::ORDER.iter().map(|id| format!("{id:?}")).collect();
        assert_eq!(
            names,
            [
                "Close",
                "Ack",
                "Crypto",
                "Path",
                "Control",
                "Probe",
                "Scheduled",
                "Ping"
            ]
        );
        for (i, id) in SourceId::ORDER.iter().enumerate() {
            assert_eq!(id.index(), i);
        }
    }
}
