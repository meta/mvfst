/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The per-stream send buffer.
//!
//! A [`SendBuffer`] holds one stream's outgoing bytes, or one encryption level's CRYPTO bytes, as
//! the `Bytes` entries the application gave: a payload shared by many streams stays one
//! allocation, and [`push_parts`](SendBuffer::push_parts) (behind `StreamMut::send_parts`) keeps a
//! header and a shared payload as two entries. Offsets fall into three regions: acknowledged
//! (an entry is freed once all of it is acknowledged), sent (with the lost ranges as an interval
//! set) and staged. [`SendBuffer::emit`] writes the next STREAM or CRYPTO frame into a
//! [`FrameWriter`] under a byte limit, lost bytes before new ones, reading retransmitted bytes by
//! offset so that the records of sent packets do not hold frame data. A STREAM frame whose data
//! fills the writer leaves out its Length field. The loss callback takes a sent-frame record's
//! `(offset, len, fin)`, and the ACK callback a run of acknowledged frames in the same form.

use std::collections::VecDeque;
use std::ops::Range;

use bytes::Bytes;
use mvfstr_wire::StreamId;
use mvfstr_wire::VarInt;

/// The packet-writer operations that [`SendBuffer::emit`] uses: the room left, raw frame-header
/// bytes, and payload by range.
pub trait FrameWriter {
    /// Returns how many bytes the writer can still take, up to the end of the packet. A STREAM
    /// frame that fills them leaves out its Length field and must end the packet.
    fn remaining(&self) -> usize;
    /// Writes `bytes`, which fit in [`remaining`](Self::remaining).
    fn put_slice(&mut self, bytes: &[u8]);
    /// Writes `data[range]`, which fits in [`remaining`](Self::remaining). Taking the `Bytes`
    /// lets an implementation keep a reference instead of copying.
    fn put_payload(&mut self, data: &Bytes, range: Range<usize>);
}

/// The frame type [`SendBuffer::emit`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// A STREAM frame for this stream; it leaves out the Length field when its data fills the
    /// writer.
    Stream(StreamId),
    /// A CRYPTO frame, which always has its Length field; the buffer then holds one encryption
    /// level's handshake bytes.
    Crypto,
}

/// What the next [`SendBuffer::emit`] would carry, for the caller's admission class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Lost bytes or a lost FIN; a retransmission does not take credit.
    Retransmit,
    /// New bytes, as many as the credit allows; a FIN may ride on the last one.
    New {
        /// The new bytes the credit allows now.
        bytes: u64,
    },
    /// The FIN alone, after every byte was sent; it does not take credit.
    Fin,
}

/// What [`SendBuffer::emit`] wrote: the fields of the sent-frame record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Emitted {
    /// The stream offset of the first byte.
    pub offset: u64,
    /// The number of stream bytes carried.
    pub len: usize,
    /// Whether the frame carries the FIN.
    pub fin: bool,
    /// Whether the bytes (or the FIN) were sent before and declared lost; a retransmission does
    /// not take flow-control credit.
    pub retransmit: bool,
    /// The bytes written to the writer, header included.
    pub frame_len: usize,
}

#[derive(Debug)]
struct Entry {
    offset: u64,
    data: Bytes,
}

/// One stream's outgoing bytes from the first unacknowledged entry to the last staged byte.
#[derive(Debug, Default)]
pub struct SendBuffer {
    /// Entries as the application gave them, in offset order.
    entries: VecDeque<Entry>,
    /// The stream offset of the first retained entry.
    base: u64,
    /// The offset after the last staged byte.
    end: u64,
    /// The offset after the highest byte ever sent; `sent..end` is staged.
    sent: u64,
    /// Sent bytes declared lost and not yet retransmitted.
    lost: RangeSet,
    /// Every byte below this offset is acknowledged.
    acked: u64,
    /// Acknowledged ranges above `acked`.
    acked_above: RangeSet,
    fin: FinState,
    /// The offset set by [`track`](Self::track), or 0, which every stream has reached, when the
    /// buffer does not track one.
    tracked: u64,
    /// The acks that moved `acked` without touching `acked_above`.
    #[cfg(test)]
    direct_acks: usize,
}

/// Where the FIN is; the final size is `end` once the FIN is staged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FinState {
    /// `finish` has not been called.
    #[default]
    Open,
    /// The FIN is staged, not yet sent.
    Staged,
    /// The FIN is in flight.
    Sent,
    /// The FIN was declared lost and awaits retransmission.
    Lost,
    /// The FIN is acknowledged.
    Acked,
    /// The stream was reset, and the buffer does not send anything more.
    Reset,
}

impl SendBuffer {
    /// Returns the buffer's offsets and ranges, without its bytes, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn digest(&self) -> impl std::fmt::Debug + '_ {
        (
            self.base,
            self.end,
            self.sent,
            &self.lost,
            self.acked,
            &self.acked_above,
            self.fin,
        )
    }

    /// Creates an empty buffer at offset 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `data` as one entry, without copying.
    pub fn push(&mut self, data: Bytes) -> Result<(), PushError> {
        self.check_push(data.len())?;
        if data.is_empty() {
            return Ok(());
        }
        let offset = self.end;
        self.end += data.len() as u64;
        self.entries.push_back(Entry { offset, data });
        Ok(())
    }

    /// Appends a per-stream `header` and a `shared` payload as two entries, without copying either.
    pub fn push_parts(&mut self, header: Bytes, shared: Bytes) -> Result<(), PushError> {
        self.check_push(header.len().saturating_add(shared.len()))?;
        self.push(header)?;
        self.push(shared)
    }

    fn check_push(&self, len: usize) -> Result<(), PushError> {
        if self.fin != FinState::Open {
            return Err(PushError::Ended);
        }
        if len as u64 > VarInt::MAX.into_inner() - self.end {
            return Err(PushError::OffsetLimit);
        }
        Ok(())
    }

    /// Ends the stream after the bytes pushed so far (STREAM buffers only).
    pub fn finish(&mut self) -> Result<(), PushError> {
        if self.fin != FinState::Open {
            return Err(PushError::Ended);
        }
        self.fin = FinState::Staged;
        Ok(())
    }

    /// Records that the frame `(offset, len, fin)` was declared lost. Returns whether any of its
    /// bytes, or its FIN, became lost: those acknowledged or lost already do not.
    pub fn on_lost(&mut self, offset: u64, len: usize, fin: bool) -> bool {
        let fin_lost = fin && self.fin == FinState::Sent;
        if fin_lost {
            self.fin = FinState::Lost;
        }
        let range = offset.max(self.acked)..offset + len as u64;
        if range.is_empty() {
            return fin_lost;
        }
        // Lost and acknowledged ranges are disjoint, so the sum counts each byte at most once.
        let known = self.lost.covered(range.clone()) + self.acked_above.covered(range.clone());
        self.lost.insert(range.clone());
        for acked in self.acked_above.overlapping(range.clone()) {
            self.lost.remove(acked);
        }
        fin_lost || known < range.end - range.start
    }

    /// Records the acknowledged run `(offset, len, fin)` of sent frames; returns the bytes freed.
    pub fn on_ack(&mut self, offset: u64, len: usize, fin: bool) -> usize {
        if self.fin == FinState::Reset {
            return 0;
        }
        if fin {
            self.fin = FinState::Acked;
        }
        let end = offset + len as u64;
        self.lost.remove(offset..end);
        if offset <= self.acked && self.acked_above.is_empty() {
            self.acked = self.acked.max(end);
            #[cfg(test)]
            {
                self.direct_acks += 1;
            }
        } else if end > self.acked {
            self.acked_above.insert(offset.max(self.acked)..end);
        }
        while let Some(r) = self.acked_above.first() {
            if r.start > self.acked {
                break;
            }
            self.acked = self.acked.max(r.end);
            self.acked_above.pop_first();
        }
        let before = self.base;
        while let Some(e) = self.entries.front() {
            let entry_end = e.offset + e.data.len() as u64;
            if entry_end > self.acked {
                break;
            }
            self.base = entry_end;
            self.entries.pop_front();
        }
        (self.base - before) as usize
    }

    /// Abandons the stream for a RESET_STREAM: drops every entry and lost range and the tracked
    /// offset, and returns the final size, the offset after the highest byte sent, as RFC 9000
    /// defines it.
    pub fn reset(&mut self) -> u64 {
        self.entries.clear();
        self.lost.clear();
        self.acked_above.clear();
        self.tracked = 0;
        self.base = self.sent;
        self.end = self.sent;
        self.acked = self.sent;
        self.fin = FinState::Reset;
        self.sent
    }

    /// Returns whether every byte and the FIN are acknowledged: RFC 9000's Data Recvd state.
    pub fn is_acked(&self) -> bool {
        self.fin == FinState::Acked && self.acked == self.end
    }

    /// Returns the retained entries, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &Bytes> {
        self.entries.iter().map(|e| &e.data)
    }

    /// Returns the number of bytes the retained entries hold: what the buffer pins in memory.
    pub fn buffered(&self) -> usize {
        (self.end - self.base) as usize
    }

    /// Returns the number of bytes pushed but never sent.
    pub fn staged(&self) -> u64 {
        self.end - self.sent
    }

    /// Returns the offset below which every byte is acknowledged.
    pub fn acked_end(&self) -> u64 {
        self.acked
    }

    /// Returns the offset after the highest byte ever sent: the stream's flow-control usage.
    pub fn sent_end(&self) -> u64 {
        self.sent
    }

    /// Returns the offset after the last byte pushed.
    pub fn staged_end(&self) -> u64 {
        self.end
    }

    /// Tracks `offset`, in place of any offset tracked before, until every byte below it is
    /// acknowledged, which [`take_progress`](Self::take_progress) reports. The FIN counts as the
    /// byte at the final size, as mvfst counts it for delivery callbacks, so an offset past the
    /// final size is reached once every byte and the FIN are acknowledged. A reset drops the
    /// offset. Returns whether the offset is reached already, which stops tracking it.
    pub fn track(&mut self, offset: u64) -> bool {
        self.tracked = offset;
        offset == 0 || self.take_progress()
    }

    /// Returns whether the tracked offset is reached, and stops tracking it if so.
    pub fn take_progress(&mut self) -> bool {
        if self.tracked == 0 || (self.tracked > self.acked && !self.is_acked()) {
            return false;
        }
        self.tracked = 0;
        true
    }

    /// Returns the final size, once the stream ended with `finish` or `reset`.
    pub fn final_size(&self) -> Option<u64> {
        (self.fin != FinState::Open).then_some(self.end)
    }

    /// Returns whether lost bytes or a lost FIN wait for retransmission.
    pub fn has_lost(&self) -> bool {
        !self.lost.is_empty() || self.fin == FinState::Lost
    }

    /// Returns what the next [`emit`](Self::emit) would send with new bytes allowed up to
    /// `credit_end`, or `None` if it would not send anything. It does not change the buffer.
    pub fn pending(&self, credit_end: u64) -> Option<Pending> {
        if self.has_lost() {
            return Some(Pending::Retransmit);
        }
        let bytes = self.end.min(credit_end).saturating_sub(self.sent);
        if bytes > 0 {
            Some(Pending::New { bytes })
        } else if self.sent == self.end && self.fin == FinState::Staged {
            Some(Pending::Fin)
        } else {
            None
        }
    }

    /// Writes the next frame into `w`, using at most `limit` bytes, or `w.remaining()` if that is
    /// less. New bytes go only up to the absolute stream offset `credit_end`, the smaller of the
    /// stream and connection credit. A STREAM frame whose data fills all of `w.remaining()` leaves
    /// out its Length field; one cut short by `limit` keeps it. Returns `None` without writing
    /// when the buffer does not have anything to send or the frame does not fit.
    pub fn emit<W: FrameWriter + ?Sized>(
        &mut self,
        kind: FrameKind,
        w: &mut W,
        limit: usize,
        credit_end: u64,
    ) -> Option<Emitted> {
        let room = w.remaining();
        // A frame cut short by `limit` leaves room after it, so it keeps its length.
        let to_end = limit >= room;
        let limit = limit.min(room);
        if let Some(lost) = self.lost.first() {
            let offset = lost.start;
            let (header, len) = FrameHeader::fit(kind, offset, lost.end - offset, limit, to_end)?;
            let fin = self.fin == FinState::Lost && offset + len as u64 == self.end;
            let frame_len = self.write_frame(w, header, len, fin);
            self.lost.remove(offset..offset + len as u64);
            return Some(Emitted {
                offset,
                len,
                fin,
                retransmit: true,
                frame_len,
            });
        }
        if self.fin == FinState::Lost {
            let (header, _) = FrameHeader::fit(kind, self.end, 0, limit, to_end)?;
            let frame_len = self.write_frame(w, header, 0, true);
            return Some(Emitted {
                offset: self.end,
                len: 0,
                fin: true,
                retransmit: true,
                frame_len,
            });
        }
        let offset = self.sent;
        let avail = self.end.min(credit_end).saturating_sub(offset);
        let fin_alone = offset == self.end && self.fin == FinState::Staged;
        if avail == 0 && !fin_alone {
            return None;
        }
        let (header, len) = FrameHeader::fit(kind, offset, avail, limit, to_end)?;
        let fin = self.fin == FinState::Staged && offset + len as u64 == self.end;
        let frame_len = self.write_frame(w, header, len, fin);
        self.sent += len as u64;
        Some(Emitted {
            offset,
            len,
            fin,
            retransmit: false,
            frame_len,
        })
    }

    /// Writes one frame and moves an emitted FIN to `Sent`; returns the frame's length.
    fn write_frame<W: FrameWriter + ?Sized>(
        &mut self,
        w: &mut W,
        header: FrameHeader,
        len: usize,
        fin: bool,
    ) -> usize {
        let encoded = header.encode(len, fin);
        w.put_slice(encoded.as_slice());
        self.put_range(w, header.offset, len);
        debug_assert!(
            header.length || w.remaining() == 0,
            "a frame without its length ends the packet"
        );
        if fin {
            self.fin = FinState::Sent;
        }
        encoded.len + len
    }

    /// Writes the stream bytes `offset..offset + len`, entry by entry.
    fn put_range<W: FrameWriter + ?Sized>(&self, w: &mut W, offset: u64, len: usize) {
        let stop = offset + len as u64;
        let mut at = offset;
        let mut i = self
            .entries
            .partition_point(|e| e.offset + e.data.len() as u64 <= offset);
        while at < stop {
            let e = &self.entries[i];
            let from = (at - e.offset) as usize;
            let to = ((stop - e.offset) as usize).min(e.data.len());
            w.put_payload(&e.data, from..to);
            at = e.offset + to as u64;
            i += 1;
        }
    }
}

/// The fields of a STREAM or CRYPTO frame header before its length is chosen.
#[derive(Clone, Copy, Debug)]
struct FrameHeader {
    kind: FrameKind,
    offset: u64,
    /// Whether the header carries the Length field.
    length: bool,
}

/// An encoded frame header: at most a type byte and three 8-byte varints.
struct EncodedHeader {
    bytes: [u8; 1 + 3 * VarInt::MAX_SIZE],
    len: usize,
}

impl EncodedHeader {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn put_varint(&mut self, value: u64) {
        let v = VarInt::from_u64(value).expect("stream offsets and lengths stay below 2^62");
        self.len += v
            .encode(&mut self.bytes[self.len..])
            .expect("the header array holds three varints");
    }
}

/// Returns the largest value of a varint encoded in `size` bytes.
const fn varint_max(size: usize) -> u64 {
    (1 << (8 * size - 2)) - 1
}

fn varint_size(value: u64) -> usize {
    VarInt::from_u64(value).map_or(VarInt::MAX_SIZE, VarInt::encoded_size)
}

impl FrameHeader {
    /// Returns the header size without the length field.
    fn base_len(self) -> usize {
        match self.kind {
            FrameKind::Stream(id) => {
                let offset = if self.offset == 0 {
                    0
                } else {
                    varint_size(self.offset)
                };
                1 + varint_size(id.into_inner()) + offset
            }
            FrameKind::Crypto => 1 + varint_size(self.offset),
        }
    }

    /// Returns the header and the longest payload of at most `avail` bytes that fit in `limit`
    /// bytes. A payload of zero bytes (a FIN alone) is allowed only when `avail` is zero.
    ///
    /// When `limit` is the writer's whole room (`to_end`) and a STREAM frame has the bytes to
    /// fill it, the frame leaves out its Length field and its data runs to the end of the packet,
    /// as RFC 9000 allows for a packet's last frame. Any other frame, a FIN alone included, keeps
    /// its length.
    fn fit(
        kind: FrameKind,
        offset: u64,
        avail: u64,
        limit: usize,
        to_end: bool,
    ) -> Option<(Self, usize)> {
        let header = Self {
            kind,
            offset,
            length: true,
        };
        let room = limit.checked_sub(header.base_len())?;
        if to_end && matches!(kind, FrameKind::Stream(_)) && room > 0 && avail >= room as u64 {
            let header = Self {
                length: false,
                ..header
            };
            return Some((header, room));
        }
        let mut best = None;
        for size in [1, 2, 4, 8] {
            let Some(space) = room.checked_sub(size) else {
                break;
            };
            let len = avail.min(space as u64).min(varint_max(size)) as usize;
            if best.is_none_or(|b| len > b) {
                best = Some(len);
            }
        }
        let len = best?;
        (len > 0 || avail == 0).then_some((header, len))
    }

    fn encode(self, len: usize, fin: bool) -> EncodedHeader {
        debug_assert!(
            !fin || matches!(self.kind, FrameKind::Stream(_)),
            "a CRYPTO buffer is never finished"
        );
        let mut out = EncodedHeader {
            bytes: [0; 1 + 3 * VarInt::MAX_SIZE],
            len: 1,
        };
        match self.kind {
            FrameKind::Stream(id) => {
                let mut ty = 0x08;
                if self.length {
                    ty |= 0x02;
                }
                if self.offset != 0 {
                    ty |= 0x04;
                }
                if fin {
                    ty |= 0x01;
                }
                out.bytes[0] = ty;
                out.put_varint(id.into_inner());
                if self.offset != 0 {
                    out.put_varint(self.offset);
                }
            }
            FrameKind::Crypto => {
                out.bytes[0] = 0x06;
                out.put_varint(self.offset);
            }
        }
        if self.length {
            out.put_varint(len as u64);
        }
        out
    }
}

/// A set of disjoint, non-adjacent `u64` ranges in ascending order.
#[derive(Clone, Debug, Default)]
pub(crate) struct RangeSet {
    ranges: VecDeque<Range<u64>>,
}

impl RangeSet {
    /// Adds `range`, merging it with every range it overlaps or touches.
    pub(crate) fn insert(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let first = self.ranges.partition_point(|r| r.end < range.start);
        let last = self.ranges.partition_point(|r| r.start <= range.end);
        if first == last {
            self.ranges.insert(first, range);
            return;
        }
        let start = range.start.min(self.ranges[first].start);
        let end = range.end.max(self.ranges[last - 1].end);
        self.ranges[first] = start..end;
        self.ranges.drain(first + 1..last);
    }

    /// Removes `range`, trimming or splitting the ranges it overlaps.
    pub(crate) fn remove(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let first = self.ranges.partition_point(|r| r.end <= range.start);
        let last = self.ranges.partition_point(|r| r.start < range.end);
        if first == last {
            return;
        }
        let left = self.ranges[first].start..range.start;
        let right = range.end..self.ranges[last - 1].end;
        self.ranges.drain(first..last);
        if !right.is_empty() {
            self.ranges.insert(first, right);
        }
        if !left.is_empty() {
            self.ranges.insert(first, left);
        }
    }

    /// Returns the lowest range.
    pub(crate) fn first(&self) -> Option<Range<u64>> {
        self.ranges.front().cloned()
    }

    /// Returns the ranges that overlap `range`, in ascending order.
    pub(crate) fn overlapping(&self, range: Range<u64>) -> impl Iterator<Item = Range<u64>> + '_ {
        let first = self.ranges.partition_point(|r| r.end <= range.start);
        let last = self.ranges.partition_point(|r| r.start < range.end);
        self.ranges.range(first..last.max(first)).cloned()
    }

    /// Returns how many of the values in `range` the set holds.
    pub(crate) fn covered(&self, range: Range<u64>) -> u64 {
        self.overlapping(range.clone())
            .map(|r| r.end.min(range.end) - r.start.max(range.start))
            .sum()
    }

    /// Removes the lowest range.
    pub(crate) fn pop_first(&mut self) -> Option<Range<u64>> {
        self.ranges.pop_front()
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the number of ranges.
    pub(crate) fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Returns the number of ranges the set has room for without allocating.
    pub(crate) fn capacity(&self) -> usize {
        self.ranges.capacity()
    }

    /// Returns the ranges in ascending order.
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.ranges.iter().cloned()
    }
}

/// Why [`SendBuffer::push`] refused data; the buffer did not store any of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError {
    /// The send half already ended with a FIN or a reset.
    Ended,
    /// The stream would pass offset 2^62 - 1, the largest a STREAM frame can carry.
    OffsetLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet writer stand-in with a fixed capacity that records payload calls.
    struct TestWriter {
        out: Vec<u8>,
        cap: usize,
        payload_calls: Vec<(*const u8, Range<usize>)>,
    }

    impl TestWriter {
        fn new(cap: usize) -> Self {
            Self {
                out: Vec::new(),
                cap,
                payload_calls: Vec::new(),
            }
        }
    }

    impl FrameWriter for TestWriter {
        fn remaining(&self) -> usize {
            self.cap - self.out.len()
        }

        fn put_slice(&mut self, bytes: &[u8]) {
            assert!(bytes.len() <= self.remaining());
            self.out.extend_from_slice(bytes);
        }

        fn put_payload(&mut self, data: &Bytes, range: Range<usize>) {
            assert!(range.len() <= self.remaining());
            self.payload_calls.push((data.as_ptr(), range.clone()));
            self.out.extend_from_slice(&data[range]);
        }
    }

    /// A decoded STREAM or CRYPTO frame.
    #[derive(Debug, PartialEq, Eq)]
    struct Parsed {
        ty: u8,
        id: Option<u64>,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    }

    /// Decodes one frame that must fill `bytes` exactly.
    fn parse(bytes: &[u8]) -> Parsed {
        let ty = bytes[0];
        let mut at = 1;
        let next = |at: &mut usize| {
            let (v, n) = VarInt::decode(&bytes[*at..]).unwrap();
            *at += n;
            v.into_inner()
        };
        let (id, offset, len, fin) = if ty == 0x06 {
            let offset = next(&mut at);
            let len = next(&mut at);
            (None, offset, len, false)
        } else {
            assert_eq!(ty & !0x07, 0x08, "not a STREAM frame: {ty:#x}");
            let id = next(&mut at);
            let offset = if ty & 0x04 != 0 { next(&mut at) } else { 0 };
            // Without its Length field the frame's data runs to the end of the output.
            let len = if ty & 0x02 != 0 {
                next(&mut at)
            } else {
                assert!(
                    at < bytes.len(),
                    "only a frame with data leaves out its length"
                );
                (bytes.len() - at) as u64
            };
            (Some(id), offset, len, ty & 0x01 != 0)
        };
        let data = bytes[at..].to_vec();
        assert_eq!(data.len() as u64, len, "the frame must fill the output");
        Parsed {
            ty,
            id,
            offset,
            fin,
            data,
        }
    }

    fn stream(id: u64) -> FrameKind {
        FrameKind::Stream(StreamId::try_from(id).unwrap())
    }

    #[test]
    fn push_keeps_entries_as_given() {
        let a = Bytes::from_static(b"hello ");
        let b = Bytes::from(vec![7u8; 100]);
        let mut buf = SendBuffer::new();
        buf.push(a.clone()).unwrap();
        buf.push(b.clone()).unwrap();
        let entries: Vec<&Bytes> = buf.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].as_ptr(), a.as_ptr());
        assert_eq!(entries[1].as_ptr(), b.as_ptr());
        assert_eq!(buf.buffered(), 106);
        assert_eq!(buf.staged(), 106);
    }

    #[test]
    fn push_parts_keeps_header_and_shared_payload_as_two_entries() {
        let header = Bytes::from_static(b"\x01\x02");
        let shared = Bytes::from(vec![9u8; 1000]);
        let other_subscriber = shared.clone();
        let mut buf = SendBuffer::new();
        buf.push_parts(header.clone(), shared.clone()).unwrap();
        let entries: Vec<&Bytes> = buf.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].as_ptr(), header.as_ptr());
        assert_eq!(entries[1].as_ptr(), other_subscriber.as_ptr());
        assert_eq!(buf.buffered(), 1002);
    }

    #[test]
    fn emit_writes_new_bytes_as_a_stream_frame() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from_static(b"hello world")).unwrap();
        let mut w = TestWriter::new(100);
        let sent = buf.emit(stream(4), &mut w, 100, u64::MAX).unwrap();
        assert_eq!(
            sent,
            Emitted {
                offset: 0,
                len: 11,
                fin: false,
                retransmit: false,
                frame_len: w.out.len(),
            }
        );
        assert_eq!(
            parse(&w.out),
            Parsed {
                ty: 0x0a,
                id: Some(4),
                offset: 0,
                fin: false,
                data: b"hello world".to_vec(),
            }
        );
        assert_eq!(buf.staged(), 0);
        assert_eq!(buf.emit(stream(4), &mut w, 100, u64::MAX), None);
    }

    #[test]
    fn emit_splits_at_the_byte_limit_and_continues_at_the_next_offset() {
        let data: Vec<u8> = (0..200u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        // Type, a 1-byte ID and a 1-byte length leave 17 payload bytes in 20.
        let mut w = TestWriter::new(1000);
        let first = buf.emit(stream(0), &mut w, 20, u64::MAX).unwrap();
        assert_eq!((first.offset, first.len, first.frame_len), (0, 17, 20));
        assert_eq!(parse(&w.out).data, data[..17]);
        // Now the offset field (1 byte for 17) costs one more byte.
        let mut w = TestWriter::new(1000);
        let second = buf.emit(stream(0), &mut w, 20, u64::MAX).unwrap();
        assert_eq!((second.offset, second.len, second.frame_len), (17, 16, 20));
        let p = parse(&w.out);
        assert_eq!((p.ty, p.offset), (0x0e, 17));
        assert_eq!(p.data, data[17..33]);
        assert_eq!(buf.staged(), 200 - 33);
    }

    #[test]
    fn emit_reads_a_frame_across_entries_without_copying() {
        let header = Bytes::from_static(b"HDR");
        let shared = Bytes::from(vec![5u8; 50]);
        let mut buf = SendBuffer::new();
        buf.push_parts(header.clone(), shared.clone()).unwrap();
        let mut w = TestWriter::new(1000);
        let sent = buf.emit(stream(8), &mut w, 1000, u64::MAX).unwrap();
        assert_eq!(sent.len, 53);
        assert_eq!(
            w.payload_calls,
            vec![(header.as_ptr(), 0..3), (shared.as_ptr(), 0..50)]
        );
        let mut expected = b"HDR".to_vec();
        expected.extend_from_slice(&shared);
        assert_eq!(parse(&w.out).data, expected);
    }

    #[test]
    fn new_bytes_stop_at_the_credit_end() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        let mut w = TestWriter::new(1000);
        let sent = buf.emit(stream(0), &mut w, 1000, 40).unwrap();
        assert_eq!((sent.offset, sent.len), (0, 40));
        assert_eq!(buf.emit(stream(0), &mut w, 1000, 40), None);
        let sent = buf.emit(stream(0), &mut w, 1000, 1 << 20).unwrap();
        assert_eq!((sent.offset, sent.len), (40, 60));
    }

    #[test]
    fn fin_rides_on_the_frame_with_the_last_bytes() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from_static(b"0123456789")).unwrap();
        buf.finish().unwrap();
        let mut w = TestWriter::new(1000);
        let first = buf.emit(stream(4), &mut w, 9, u64::MAX).unwrap();
        assert!(!first.fin, "the FIN waits for the last byte");
        let mut w = TestWriter::new(1000);
        let last = buf.emit(stream(4), &mut w, 1000, u64::MAX).unwrap();
        assert!(last.fin);
        let p = parse(&w.out);
        assert!(p.fin);
        assert_eq!(
            (p.ty, p.offset, p.data.len()),
            (0x0f, last.offset, last.len)
        );
        assert_eq!(last.offset + last.len as u64, 10);
        assert_eq!(buf.emit(stream(4), &mut w, 1000, u64::MAX), None);
    }

    #[test]
    fn fin_alone_follows_bytes_already_sent_and_needs_no_credit() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from_static(b"abcde")).unwrap();
        let mut w = TestWriter::new(1000);
        buf.emit(stream(4), &mut w, 1000, 5).unwrap();
        buf.finish().unwrap();
        let mut w = TestWriter::new(1000);
        let fin = buf.emit(stream(4), &mut w, 1000, 5).unwrap();
        assert_eq!(
            fin,
            Emitted {
                offset: 5,
                len: 0,
                fin: true,
                retransmit: false,
                frame_len: 4,
            }
        );
        let p = parse(&w.out);
        assert!(p.fin);
        assert_eq!((p.offset, p.data.len()), (5, 0));
        assert_eq!(buf.emit(stream(4), &mut w, 1000, 5), None);
    }

    fn ranges(set: &RangeSet) -> Vec<Range<u64>> {
        set.iter().collect()
    }

    #[test]
    fn range_set_insert_merges_overlapping_and_adjacent_ranges() {
        let mut set = RangeSet::default();
        set.insert(10..20);
        set.insert(30..40);
        set.insert(50..60);
        assert_eq!(ranges(&set), vec![10..20, 30..40, 50..60]);
        set.insert(0..5);
        set.insert(20..25);
        assert_eq!(ranges(&set), vec![0..5, 10..25, 30..40, 50..60]);
        set.insert(24..55);
        assert_eq!(ranges(&set), vec![0..5, 10..60]);
        set.insert(12..13);
        set.insert(5..5);
        assert_eq!(ranges(&set), vec![0..5, 10..60]);
        set.insert(5..10);
        assert_eq!(ranges(&set), vec![0..60]);
    }

    #[test]
    fn range_set_remove_trims_and_splits_ranges() {
        let mut set = RangeSet::default();
        set.insert(0..10);
        set.insert(20..30);
        set.insert(40..50);
        set.remove(25..45);
        assert_eq!(ranges(&set), vec![0..10, 20..25, 45..50]);
        set.remove(3..6);
        assert_eq!(ranges(&set), vec![0..3, 6..10, 20..25, 45..50]);
        set.remove(10..20);
        set.remove(7..7);
        assert_eq!(ranges(&set), vec![0..3, 6..10, 20..25, 45..50]);
        set.remove(0..100);
        assert!(set.is_empty());
    }

    /// Emits one frame of at most `limit` bytes, with unlimited credit, into a room one byte
    /// larger, so the frame keeps its Length field whatever its size.
    fn emit_one(buf: &mut SendBuffer, limit: usize) -> Option<Emitted> {
        let mut w = TestWriter::new(limit + 1);
        buf.emit(stream(0), &mut w, limit, u64::MAX)
    }

    #[test]
    fn lost_bytes_are_retransmitted_before_new_bytes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        let a = emit_one(&mut buf, 104).unwrap();
        let b = emit_one(&mut buf, 106).unwrap();
        assert_eq!((a.offset, a.len, b.offset, b.len), (0, 100, 100, 100));
        buf.on_lost(a.offset, a.len, a.fin);
        let mut w = TestWriter::new(1000);
        let again = buf.emit(stream(0), &mut w, 1000, u64::MAX).unwrap();
        assert_eq!((again.offset, again.len, again.retransmit), (0, 100, true));
        assert_eq!(parse(&w.out).data, data[..100]);
        let new = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((new.offset, new.len, new.retransmit), (200, 100, false));
    }

    #[test]
    fn retransmissions_take_no_credit() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![3u8; 100])).unwrap();
        let mut w = TestWriter::new(1000);
        let a = buf.emit(stream(0), &mut w, 1000, 100).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        // All credit (up to offset 100) is used; the retransmission still goes.
        let mut w = TestWriter::new(1000);
        let again = buf.emit(stream(0), &mut w, 1000, 100).unwrap();
        assert_eq!((again.offset, again.len, again.retransmit), (0, 100, true));
    }

    #[test]
    fn a_lost_range_is_retransmitted_in_pieces_under_the_limit() {
        let data: Vec<u8> = (0..100u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        let a = emit_one(&mut buf, 1000).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        let mut w = TestWriter::new(1000);
        let first = buf.emit(stream(0), &mut w, 43, u64::MAX).unwrap();
        assert_eq!((first.offset, first.len, first.retransmit), (0, 40, true));
        let mut w = TestWriter::new(1000);
        let second = buf.emit(stream(0), &mut w, 1000, u64::MAX).unwrap();
        assert_eq!(
            (second.offset, second.len, second.retransmit),
            (40, 60, true)
        );
        assert_eq!(parse(&w.out).data, data[40..]);
        assert_eq!(emit_one(&mut buf, 1000), None);
    }

    #[test]
    fn acks_free_entries_once_the_acked_prefix_covers_them() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 10])).unwrap();
        buf.push(Bytes::from(vec![2u8; 20])).unwrap();
        buf.push(Bytes::from(vec![3u8; 30])).unwrap();
        while emit_one(&mut buf, 1000).is_some() {}
        assert_eq!(buf.on_ack(30, 30, false), 0, "out of order: nothing freed");
        assert_eq!(buf.buffered(), 60);
        assert_eq!(buf.on_ack(0, 5, false), 0, "an entry is freed only whole");
        assert_eq!(buf.on_ack(5, 10, false), 10);
        assert_eq!(buf.buffered(), 50);
        assert_eq!(buf.entries().count(), 2);
        assert_eq!(buf.on_ack(15, 15, false), 50);
        assert_eq!(buf.buffered(), 0);
        assert_eq!(buf.entries().count(), 0);
    }

    #[test]
    fn a_late_ack_cancels_the_retransmission_of_a_lost_range() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        let a = emit_one(&mut buf, 54).unwrap();
        let b = emit_one(&mut buf, 1000).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        buf.on_lost(b.offset, b.len, b.fin);
        // The packet carrying `b` was only late: its ACK arrives after the loss.
        buf.on_ack(b.offset, b.len, b.fin);
        let again = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((again.offset, again.len), (a.offset, a.len));
        assert_eq!(emit_one(&mut buf, 1000), None);
    }

    #[test]
    fn a_loss_never_resends_acknowledged_bytes() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 200])).unwrap();
        let a = emit_one(&mut buf, 1000).unwrap();
        assert_eq!(a.len, 200);
        buf.on_lost(a.offset, a.len, a.fin);
        let b = emit_one(&mut buf, 1000).unwrap();
        assert!(b.retransmit);
        // The first copy was only late; then the second copy is declared lost.
        buf.on_ack(a.offset, a.len, a.fin);
        buf.on_lost(b.offset, b.len, b.fin);
        assert_eq!(emit_one(&mut buf, 1000), None);

        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 200])).unwrap();
        let a = emit_one(&mut buf, 1000).unwrap();
        buf.on_ack(0, 30, false);
        buf.on_ack(150, 20, false);
        buf.on_lost(a.offset, a.len, a.fin);
        let r1 = emit_one(&mut buf, 1000).unwrap();
        let r2 = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((r1.offset, r1.len, r2.offset, r2.len), (30, 120, 170, 30));
        assert_eq!(emit_one(&mut buf, 1000), None);
    }

    #[test]
    fn a_lost_fin_is_retransmitted_with_the_tail_or_alone() {
        // The FIN rode with the last bytes: both come back together.
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 10])).unwrap();
        buf.finish().unwrap();
        let a = emit_one(&mut buf, 1000).unwrap();
        assert!(a.fin);
        buf.on_lost(a.offset, a.len, a.fin);
        let again = emit_one(&mut buf, 1000).unwrap();
        assert_eq!(
            (again.offset, again.len, again.fin, again.retransmit),
            (0, 10, true, true)
        );
        assert_eq!(emit_one(&mut buf, 1000), None);

        // The FIN went alone and only it was lost.
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 10])).unwrap();
        emit_one(&mut buf, 1000).unwrap();
        buf.finish().unwrap();
        let fin = emit_one(&mut buf, 1000).unwrap();
        buf.on_lost(fin.offset, fin.len, fin.fin);
        let mut w = TestWriter::new(1000);
        let again = buf.emit(stream(0), &mut w, 1000, 0).unwrap();
        assert_eq!(
            (again.offset, again.len, again.fin, again.retransmit),
            (10, 0, true, true)
        );
        assert!(parse(&w.out).fin);
        assert_eq!(emit_one(&mut buf, 1000), None);

        // A lost tail retransmitted in pieces carries the FIN only on the last piece.
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        buf.finish().unwrap();
        let a = emit_one(&mut buf, 1000).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        let first = emit_one(&mut buf, 43).unwrap();
        let last = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((first.len, first.fin), (40, false));
        assert_eq!((last.offset, last.len, last.fin), (40, 60, true));
    }

    #[test]
    fn the_buffer_is_done_once_every_byte_and_the_fin_are_acknowledged() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 10])).unwrap();
        let data = emit_one(&mut buf, 1000).unwrap();
        buf.finish().unwrap();
        let fin = emit_one(&mut buf, 1000).unwrap();
        assert!(!buf.is_acked());
        buf.on_ack(data.offset, data.len, data.fin);
        assert!(!buf.is_acked(), "the FIN is not acknowledged yet");
        buf.on_lost(fin.offset, fin.len, fin.fin);
        let again = emit_one(&mut buf, 1000).unwrap();
        buf.on_ack(again.offset, again.len, again.fin);
        assert!(buf.is_acked());
        // A late loss of the first FIN copy does not change anything.
        buf.on_lost(fin.offset, fin.len, fin.fin);
        assert_eq!(emit_one(&mut buf, 1000), None);
        assert!(buf.is_acked());

        let mut buf = SendBuffer::new();
        buf.finish().unwrap();
        let fin = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((fin.offset, fin.len, fin.fin), (0, 0, true));
        buf.on_ack(fin.offset, fin.len, fin.fin);
        assert!(buf.is_acked());
    }

    #[test]
    fn in_order_acks_move_the_acknowledged_prefix_directly() {
        let mut buf = SendBuffer::new();
        for fill in 1..=3u8 {
            buf.push(Bytes::from(vec![fill; 100])).unwrap();
        }
        buf.finish().unwrap();
        let a = emit_one(&mut buf, 104).unwrap();
        let b = emit_one(&mut buf, 106).unwrap();
        let c = emit_one(&mut buf, 106).unwrap();
        assert_eq!((c.offset, c.len, c.fin), (200, 100, true));
        let freed = [a, b, c].map(|f| buf.on_ack(f.offset, f.len, f.fin));
        assert_eq!(freed, [100, 100, 100]);
        assert_eq!(buf.acked_end(), 300);
        assert!(buf.is_acked());
        assert_eq!(buf.entries().count(), 0);
        assert_eq!(
            (buf.direct_acks, buf.acked_above.capacity()),
            (3, 0),
            "each ack moves the prefix, and the ranges above it stay unallocated"
        );
    }

    /// Emits the next frame, with new bytes only up to `credit_end`.
    fn emit_to(buf: &mut SendBuffer, credit_end: u64) -> Emitted {
        let mut w = TestWriter::new(1000);
        buf.emit(stream(0), &mut w, 1000, credit_end).unwrap()
    }

    #[test]
    fn an_in_order_ack_goes_directly_once_an_out_of_order_ack_is_joined() {
        let mut buf = SendBuffer::new();
        for _ in 0..4 {
            buf.push(Bytes::from(vec![1u8; 50])).unwrap();
        }
        let [a, b, c, d] = [50, 100, 150, 200].map(|end| emit_to(&mut buf, end));
        assert_eq!(buf.on_ack(c.offset, c.len, c.fin), 0, "out of order");
        assert_eq!(buf.acked_end(), 0);
        assert_eq!(buf.on_ack(a.offset, a.len, a.fin), 50);
        assert_eq!(buf.acked_end(), 50);
        assert_eq!(buf.on_ack(b.offset, b.len, b.fin), 100, "b joins c");
        assert_eq!(buf.acked_end(), 150);
        let joined = buf.direct_acks;
        assert_eq!(buf.on_ack(d.offset, d.len, d.fin), 50);
        assert_eq!(buf.acked_end(), 200);
        assert_eq!(
            (joined, buf.direct_acks),
            (0, 1),
            "only the ack after the join goes directly"
        );
    }

    #[test]
    fn an_in_order_ack_of_lost_bytes_cancels_their_retransmission() {
        let mut buf = SendBuffer::new();
        for _ in 0..3 {
            buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        }
        let a = emit_one(&mut buf, 104).unwrap();
        let b = emit_one(&mut buf, 106).unwrap();
        let c = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((c.offset, c.len), (200, 100));
        assert_eq!(buf.on_ack(a.offset, a.len, a.fin), 100);
        buf.on_lost(b.offset, b.len, b.fin);
        buf.on_lost(c.offset, c.len, c.fin);
        // The packet carrying `b` was only late: its ACK arrives after the loss.
        assert_eq!(buf.on_ack(b.offset, b.len, b.fin), 100);
        let again = emit_one(&mut buf, 1000).unwrap();
        assert_eq!(
            (again.offset, again.len, again.retransmit),
            (200, 100, true)
        );
        assert_eq!(emit_one(&mut buf, 1000), None);
        assert_eq!(buf.on_ack(again.offset, again.len, again.fin), 100);
        assert!(!buf.has_lost());
        assert_eq!(buf.acked_end(), 300);
        assert_eq!(buf.direct_acks, 3);
    }

    #[test]
    fn duplicate_and_overlapping_acks_free_each_entry_once() {
        let mut buf = SendBuffer::new();
        for _ in 0..3 {
            buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        }
        let a = emit_one(&mut buf, 104).unwrap();
        let b = emit_one(&mut buf, 106).unwrap();
        let c = emit_one(&mut buf, 106).unwrap();
        assert_eq!(buf.on_ack(a.offset, a.len, a.fin), 100);
        assert_eq!(buf.on_ack(a.offset, a.len, a.fin), 0, "a duplicate");
        // A run that starts inside the acknowledged prefix extends it.
        assert_eq!(buf.on_ack(50, 100, false), 0);
        assert_eq!(buf.acked_end(), 150);
        assert_eq!(buf.on_ack(b.offset, b.len, b.fin), 100);
        assert_eq!(buf.on_ack(b.offset, b.len, b.fin), 0, "a duplicate");
        assert_eq!(buf.on_ack(c.offset, c.len, c.fin), 100);
        assert_eq!(buf.acked_end(), 300);
        assert_eq!(buf.buffered(), 0);
        assert_eq!((buf.direct_acks, buf.acked_above.capacity()), (6, 0));
    }

    #[test]
    fn pushes_after_the_fin_are_refused_and_store_nothing() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from_static(b"abc")).unwrap();
        buf.finish().unwrap();
        assert_eq!(buf.push(Bytes::from_static(b"d")), Err(PushError::Ended));
        assert_eq!(
            buf.push_parts(Bytes::from_static(b"h"), Bytes::from_static(b"p")),
            Err(PushError::Ended)
        );
        assert_eq!(buf.finish(), Err(PushError::Ended));
        assert_eq!(buf.buffered(), 3);
        assert_eq!(buf.entries().count(), 1);
    }

    /// Builds a buffer whose stream already carried `offset` bytes, all acknowledged.
    fn buffer_at(offset: u64) -> SendBuffer {
        SendBuffer {
            base: offset,
            end: offset,
            sent: offset,
            acked: offset,
            ..SendBuffer::default()
        }
    }

    #[test]
    fn pushes_past_the_largest_stream_offset_are_refused_whole() {
        let max = VarInt::MAX.into_inner();
        let mut buf = buffer_at(max - 4);
        assert_eq!(
            buf.push(Bytes::from_static(b"12345")),
            Err(PushError::OffsetLimit)
        );
        assert_eq!(
            buf.push_parts(Bytes::from_static(b"12"), Bytes::from_static(b"345")),
            Err(PushError::OffsetLimit)
        );
        assert_eq!(buf.buffered(), 0);
        buf.push(Bytes::from_static(b"1234")).unwrap();
        assert_eq!(buf.staged(), 4);
    }

    #[test]
    fn reset_discards_everything_and_reports_the_final_size() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        let a = emit_one(&mut buf, 54).unwrap();
        let b = emit_one(&mut buf, 25).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        // The final size is what flow control consumed: the offset after the highest byte sent.
        assert_eq!(buf.reset(), b.offset + b.len as u64);
        assert_eq!(buf.final_size(), Some(b.offset + b.len as u64));
        assert_eq!(buf.buffered(), 0);
        assert_eq!(buf.staged(), 0);
        assert_eq!(emit_one(&mut buf, 1000), None);
        assert_eq!(buf.push(Bytes::from_static(b"x")), Err(PushError::Ended));
        assert_eq!(buf.finish(), Err(PushError::Ended));
        buf.on_ack(b.offset, b.len, b.fin);
        buf.on_lost(a.offset, a.len, a.fin);
        assert_eq!(emit_one(&mut buf, 1000), None);
    }

    #[test]
    fn crypto_frames_always_carry_the_offset() {
        let hello: Vec<u8> = (0..100u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(hello.clone())).unwrap();
        let mut w = TestWriter::new(1000);
        // Type, offset 0 and a 1-byte length leave 37 bytes in 40.
        let first = buf.emit(FrameKind::Crypto, &mut w, 40, u64::MAX).unwrap();
        assert_eq!((first.offset, first.len, first.fin), (0, 37, false));
        let p = parse(&w.out);
        assert_eq!((p.ty, p.id, p.offset), (0x06, None, 0));
        assert_eq!(p.data, hello[..37]);
        let mut w = TestWriter::new(1000);
        let second = buf.emit(FrameKind::Crypto, &mut w, 1000, u64::MAX).unwrap();
        let p = parse(&w.out);
        assert_eq!((p.offset, p.data.len()), (37, 63));
        assert_eq!(second.frame_len, w.out.len());
    }

    #[test]
    fn a_frame_that_does_not_fit_writes_nothing_and_changes_nothing() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        // Type, ID and length take all 3 bytes, so a single payload byte does not fit.
        let mut w = TestWriter::new(1000);
        assert_eq!(buf.emit(stream(0), &mut w, 3, u64::MAX), None);
        // The writer's own room bounds the frame too: type and ID fill a 2-byte room, so a payload
        // byte does not fit even in a frame without its length.
        let mut w = TestWriter::new(2);
        assert_eq!(buf.emit(stream(0), &mut w, 1000, u64::MAX), None);
        assert!(w.out.is_empty());
        assert_eq!(buf.staged(), 100);

        let a = emit_one(&mut buf, 1000).unwrap();
        buf.on_lost(a.offset, a.len, a.fin);
        let mut w = TestWriter::new(1000);
        assert_eq!(buf.emit(stream(0), &mut w, 3, u64::MAX), None);
        assert!(w.out.is_empty());
        let again = emit_one(&mut buf, 1000).unwrap();
        assert_eq!((again.offset, again.len, again.retransmit), (0, 100, true));
    }

    #[test]
    fn pending_names_what_the_next_frame_would_carry_without_changing_state() {
        let mut buf = SendBuffer::new();
        assert_eq!(buf.pending(u64::MAX), None);
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        assert_eq!(buf.pending(u64::MAX), Some(Pending::New { bytes: 100 }));
        assert_eq!(buf.pending(30), Some(Pending::New { bytes: 30 }));
        assert_eq!(buf.pending(0), None, "staged bytes without credit");
        let a = emit_one(&mut buf, 53).unwrap();
        assert_eq!(buf.pending(u64::MAX), Some(Pending::New { bytes: 50 }));
        buf.on_lost(a.offset, a.len, a.fin);
        assert_eq!(buf.pending(0), Some(Pending::Retransmit));
        emit_one(&mut buf, 1000).unwrap();
        emit_one(&mut buf, 1000).unwrap();
        assert_eq!(buf.pending(u64::MAX), None);
        buf.finish().unwrap();
        assert_eq!(buf.pending(0), Some(Pending::Fin));
        let fin = emit_one(&mut buf, 1000).unwrap();
        assert_eq!(buf.pending(u64::MAX), None);
        buf.on_lost(fin.offset, fin.len, fin.fin);
        assert_eq!(buf.pending(0), Some(Pending::Retransmit));
    }

    #[test]
    fn offsets_report_the_staged_sent_and_acknowledged_regions() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 100])).unwrap();
        let a = emit_one(&mut buf, 43).unwrap();
        assert_eq!(
            (buf.acked_end(), buf.sent_end(), buf.staged_end()),
            (0, 40, 100)
        );
        buf.on_ack(a.offset, a.len, a.fin);
        assert_eq!(
            (buf.acked_end(), buf.sent_end(), buf.staged_end()),
            (40, 40, 100)
        );
        assert_eq!(buf.final_size(), None);
        buf.finish().unwrap();
        assert_eq!(buf.final_size(), Some(100));
    }

    #[test]
    fn the_length_field_size_is_chosen_to_carry_the_most_bytes() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 20_000])).unwrap();
        // 16,385 bytes after type and ID: a 2-byte length carries 16,383 (the 2-byte maximum),
        // more than the 16,381 a 4-byte length would leave room for.
        let mut w = TestWriter::new(1 << 20);
        let sent = buf.emit(stream(0), &mut w, 2 + 16_385, u64::MAX).unwrap();
        assert_eq!((sent.len, sent.frame_len), (16_383, 2 + 16_385));
        assert_eq!(parse(&w.out).data.len(), 16_383);
    }

    #[test]
    fn the_last_bytes_and_the_fin_reaching_the_end_of_the_room_go_without_a_length() {
        let data: Vec<u8> = (0..98u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        buf.finish().unwrap();
        // Type and a 1-byte ID leave exactly the stream's 98 bytes of the 100-byte room; a
        // 2-byte Length field would leave room for only 96 of them.
        let mut w = TestWriter::new(100);
        let sent = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            sent,
            Emitted {
                offset: 0,
                len: 98,
                fin: true,
                retransmit: false,
                frame_len: 100,
            }
        );
        assert_eq!(w.remaining(), 0, "the frame ends the room");
        assert_eq!(
            parse(&w.out),
            Parsed {
                ty: 0x09,
                id: Some(4),
                offset: 0,
                fin: true,
                data,
            }
        );
        assert_eq!(
            buf.pending(u64::MAX),
            None,
            "every byte and the FIN are sent"
        );
        assert_eq!((buf.sent_end(), buf.staged()), (98, 0));
    }

    #[test]
    fn a_frame_cut_by_the_limit_keeps_its_length() {
        let data: Vec<u8> = (0..98u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        // The limit would hold the 98 bytes without a Length field, but the writer has room past
        // it: the frame keeps a 2-byte length and carries 96.
        let mut w = TestWriter::new(1_200);
        let sent = buf.emit(stream(4), &mut w, 100, u64::MAX).unwrap();
        assert_eq!((sent.offset, sent.len, sent.frame_len), (0, 96, 100));
        assert_eq!(w.remaining(), 1_100);
        let p = parse(&w.out);
        assert_eq!((p.ty, p.data), (0x0a, data[..96].to_vec()));

        // With more bytes than the limit holds, too: type, ID, a 2-byte offset and a 2-byte
        // length leave 594 of 600.
        buf.push(Bytes::from(vec![7u8; 2_000])).unwrap();
        let mut w = TestWriter::new(1_200);
        let sent = buf.emit(stream(4), &mut w, 600, u64::MAX).unwrap();
        assert_eq!((sent.offset, sent.len, sent.frame_len), (96, 594, 600));
        assert_eq!(parse(&w.out).ty, 0x0e);
    }

    #[test]
    fn a_fin_alone_keeps_its_length() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from_static(b"abcde")).unwrap();
        emit_one(&mut buf, 1000).unwrap();
        buf.finish().unwrap();
        // Type, ID and offset fill a 3-byte room; the FIN alone needs a length byte more.
        let mut w = TestWriter::new(3);
        assert_eq!(buf.emit(stream(0), &mut w, usize::MAX, u64::MAX), None);
        assert!(w.out.is_empty());
        let mut w = TestWriter::new(4);
        let fin = buf.emit(stream(0), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            (fin.offset, fin.len, fin.fin, fin.frame_len),
            (5, 0, true, 4)
        );
        assert_eq!(parse(&w.out).ty, 0x0f);

        // A lost FIN alone goes again the same way.
        buf.on_lost(fin.offset, fin.len, fin.fin);
        let mut w = TestWriter::new(3);
        assert_eq!(buf.emit(stream(0), &mut w, usize::MAX, u64::MAX), None);
        assert!(w.out.is_empty());
        let mut w = TestWriter::new(4);
        let again = buf.emit(stream(0), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            (again.offset, again.len, again.fin, again.retransmit),
            (5, 0, true, true)
        );
        assert_eq!(parse(&w.out).ty, 0x0f);
    }

    #[test]
    fn a_frame_reaching_the_end_of_the_room_leaves_out_its_length_for_two_more_bytes() {
        let data: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        // The frame with its Length field, cut at 1,200 bytes inside a larger room: type, ID
        // and a 2-byte length leave 1,196 bytes.
        let mut with_length = SendBuffer::new();
        with_length.push(Bytes::from(data.clone())).unwrap();
        let mut w = TestWriter::new(1 << 16);
        let kept = with_length
            .emit(stream(4), &mut w, 1_200, u64::MAX)
            .unwrap();
        assert_eq!((kept.len, kept.frame_len), (1_196, 1_200));

        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        let mut w = TestWriter::new(1_200);
        let sent = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            sent,
            Emitted {
                offset: 0,
                len: kept.len + 2,
                fin: false,
                retransmit: false,
                frame_len: 1_200,
            }
        );
        assert_eq!(w.remaining(), 0, "the frame ends the room");
        let p = parse(&w.out);
        assert_eq!((p.ty, p.id, p.offset), (0x08, Some(4), 0));
        assert_eq!(p.data, data[..1_198]);
        assert_eq!((buf.sent_end(), buf.staged()), (1_198, 5_000 - 1_198));

        // The next frame starts after it and also runs to the end of its room: type, ID and a
        // 2-byte offset leave 1,196 bytes.
        let mut w = TestWriter::new(1_200);
        let next = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            (next.offset, next.len, next.frame_len),
            (1_198, 1_196, 1_200)
        );
        let p = parse(&w.out);
        assert_eq!((p.ty, p.offset), (0x0c, 1_198));
        assert_eq!(p.data, data[1_198..2_394]);
    }

    #[test]
    fn crypto_frames_keep_their_length_at_the_end_of_the_room() {
        let hello: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(hello.clone())).unwrap();
        // CRYPTO always carries its length: type, offset 0 and a 2-byte length leave 96 of the
        // 100-byte room.
        let mut w = TestWriter::new(100);
        let sent = buf
            .emit(FrameKind::Crypto, &mut w, usize::MAX, u64::MAX)
            .unwrap();
        assert_eq!((sent.offset, sent.len, sent.frame_len), (0, 96, 100));
        assert_eq!(w.remaining(), 0);
        let p = parse(&w.out);
        assert_eq!((p.ty, p.offset), (0x06, 0));
        assert_eq!(p.data, hello[..96]);
    }

    #[test]
    fn a_lost_range_reaching_the_end_of_the_room_goes_again_without_its_length() {
        let data: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        buf.finish().unwrap();
        // A first frame without a length fills its room, a second takes the rest and the FIN;
        // both are lost.
        let mut w = TestWriter::new(1_200);
        let first = buf.emit(stream(0), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            (first.offset, first.len, first.frame_len),
            (0, 1_198, 1_200)
        );
        let second = emit_one(&mut buf, 2_000).unwrap();
        assert_eq!(
            (second.offset, second.len, second.fin),
            (1_198, 1_802, true)
        );
        buf.on_lost(first.offset, first.len, first.fin);
        buf.on_lost(second.offset, second.len, second.fin);

        // Each retransmission fills its room without a length; the last carries the FIN.
        let mut acked = Vec::new();
        for (room, offset, len, fin, ty) in [
            (500, 0, 498, false, 0x08),
            (1_200, 498, 1_196, false, 0x0c),
            (1_310, 1_694, 1_306, true, 0x0d),
        ] {
            let mut w = TestWriter::new(room);
            let again = buf.emit(stream(0), &mut w, usize::MAX, 0).unwrap();
            assert_eq!(
                again,
                Emitted {
                    offset,
                    len,
                    fin,
                    retransmit: true,
                    frame_len: room,
                }
            );
            assert_eq!(w.remaining(), 0, "the frame at {offset} ends the room");
            let p = parse(&w.out);
            assert_eq!((p.ty, p.offset, p.fin), (ty, offset, fin));
            assert_eq!(p.data, data[offset as usize..offset as usize + len]);
            acked.push(again);
        }
        assert_eq!(buf.pending(u64::MAX), None, "nothing is left to send");
        for a in acked {
            buf.on_ack(a.offset, a.len, a.fin);
        }
        assert!(buf.is_acked());
        assert_eq!(buf.buffered(), 0);
    }

    #[test]
    fn a_frame_whose_data_ends_before_the_end_of_the_room_keeps_its_length() {
        // Well before the end: type, ID, a 2-byte length and 500 bytes leave 696.
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 500])).unwrap();
        let mut w = TestWriter::new(1_200);
        let sent = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!((sent.len, sent.frame_len, w.remaining()), (500, 504, 696));
        assert_eq!(parse(&w.out).ty, 0x0a);

        // One byte short of what the room holds without a length: a 1-byte length makes the
        // frame fill the room, and it keeps the length.
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![2u8; 47])).unwrap();
        let mut w = TestWriter::new(50);
        let sent = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!((sent.len, sent.frame_len, w.remaining()), (47, 50, 0));
        assert_eq!(parse(&w.out).ty, 0x0a);

        // One byte short where the length takes two bytes: the frame keeps its length and
        // carries 98 of the 99 bytes, and the last goes in the next frame.
        let data: Vec<u8> = (0..99u8).collect();
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(data.clone())).unwrap();
        let mut w = TestWriter::new(102);
        let sent = buf.emit(stream(4), &mut w, usize::MAX, u64::MAX).unwrap();
        assert_eq!((sent.len, sent.frame_len, w.remaining()), (98, 102, 0));
        let p = parse(&w.out);
        assert_eq!((p.ty, p.data), (0x0a, data[..98].to_vec()));
        assert_eq!(buf.staged(), 1);
    }

    #[test]
    fn seeded_lossy_transfer_delivers_every_byte_and_the_fin() {
        use crate::streams::recv_buf::PagePool;
        use crate::streams::recv_buf::RecvBuffer;

        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 253) as u8).collect();
        let mut buf = SendBuffer::new();
        let mut at = 0;
        while at < data.len() {
            let n = (1 + next(700)).min(data.len() - at);
            buf.push(Bytes::copy_from_slice(&data[at..at + n])).unwrap();
            at += n;
        }
        buf.finish().unwrap();
        let mut pool = PagePool::new();
        let mut recv = RecvBuffer::new();
        let mut in_flight: Vec<(Emitted, Vec<u8>)> = Vec::new();
        for _ in 0..10_000 {
            if buf.is_acked() {
                break;
            }
            for _ in 0..next(8) {
                let mut w = TestWriter::new(1 << 16);
                let limit = 30 + next(1300);
                if let Some(sent) = buf.emit(stream(0), &mut w, limit, u64::MAX) {
                    in_flight.push((sent, w.out));
                }
            }
            // Packets leave the network in random order; one in ten is lost.
            for _ in 0..next(in_flight.len() + 1) {
                let (sent, frame) = in_flight.swap_remove(next(in_flight.len()));
                if next(10) == 0 {
                    buf.on_lost(sent.offset, sent.len, sent.fin);
                } else {
                    let p = parse(&frame);
                    recv.insert(p.offset, &p.data, p.fin, &mut pool).unwrap();
                    buf.on_ack(sent.offset, sent.len, sent.fin);
                }
            }
        }
        assert!(buf.is_acked());
        assert_eq!(buf.buffered(), 0);
        assert!(recv.is_complete());
        let got: Vec<u8> = recv
            .readable()
            .segments()
            .flat_map(|s| s.to_vec())
            .collect();
        assert_eq!(got, data);
    }

    #[test]
    fn a_tracked_offset_is_reached_only_when_the_acknowledged_prefix_covers_it() {
        let mut buf = SendBuffer::new();
        buf.push(Bytes::from(vec![1u8; 10])).unwrap();
        while emit_one(&mut buf, 1000).is_some() {}
        assert!(!buf.track(10), "nothing is acknowledged");
        buf.on_ack(5, 5, false);
        assert!(!buf.take_progress(), "bytes 0..5 are not acknowledged");
        buf.on_ack(0, 5, false);
        assert!(buf.take_progress());
        assert!(!buf.take_progress(), "reported once");
    }
}
