/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-place packet writer.

use std::fmt;
use std::ops::Range;
use std::ops::RangeInclusive;

use bytes::Bytes;

use crate::ConnectionId;
use crate::EcnCounts;
use crate::Frame;
use crate::FrameEncodeError;
use crate::InvalidFrame;
use crate::SAMPLE_LEN;
use crate::StreamId;
use crate::VarInt;
use crate::Version;
use crate::codec::Writer;
use crate::codec::varint_from_len;
use crate::codec::varint_len_of;
use crate::frame::ACK;
use crate::frame::ACK_ECN;
use crate::frame::CRYPTO;
use crate::frame::DATAGRAM_LEN;
use crate::frame::STREAM;
use crate::frame::STREAM_FIN;
use crate::frame::STREAM_LEN;
use crate::frame::STREAM_OFF;
use crate::frame::datagram_frame_len;
use crate::frame::type_varint;
use crate::header::FIXED_BIT;
use crate::header::HANDSHAKE_TYPE;
use crate::header::INITIAL_TYPE;
use crate::header::KEY_PHASE_BIT;
use crate::header::LONG_FORM;
use crate::header::SPIN_BIT;
use crate::header::ZERO_RTT_TYPE;

/// The header of a packet to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderSpec<'t> {
    /// An Initial packet (RFC 9000).
    Initial {
        /// The version.
        version: Version,
        /// The Destination Connection ID.
        dcid: ConnectionId,
        /// The Source Connection ID.
        scid: ConnectionId,
        /// The Token: empty, or one from a Retry packet or a NEW_TOKEN frame. A server sends it
        /// empty.
        token: &'t [u8],
    },
    /// A 0-RTT packet (RFC 9000).
    ZeroRtt {
        /// The version.
        version: Version,
        /// The Destination Connection ID.
        dcid: ConnectionId,
        /// The Source Connection ID.
        scid: ConnectionId,
    },
    /// A Handshake packet (RFC 9000).
    Handshake {
        /// The version.
        version: Version,
        /// The Destination Connection ID.
        dcid: ConnectionId,
        /// The Source Connection ID.
        scid: ConnectionId,
    },
    /// A 1-RTT packet with a short header (RFC 9000).
    OneRtt {
        /// The Destination Connection ID.
        dcid: ConnectionId,
        /// The latency spin bit (RFC 9000).
        spin: bool,
        /// The key phase bit (RFC 9001).
        key_phase: bool,
    },
}

/// An in-place writer for one packet: the header, then frames, leaving room for the AEAD tag.
///
/// Frame encoders write a frame whole or refuse it and leave the packet as it was; the STREAM
/// and CRYPTO encoders take as much data as fits, and the ACK encoder as many ranges.
/// [`finish`](Self::finish) pads for header protection, fills in a long header's Length field
/// and returns the [`PacketLayout`] the sealer needs. Coalesced packets are written by one writer
/// each over consecutive parts of a slot. The writer never allocates.
#[derive(Debug)]
pub struct PacketWriter<'a> {
    buf: &'a mut [u8],
    hdr_len: usize,
    pn_offset: usize,
    /// The offset and encoded size of a long header's Length field.
    length_field: Option<(usize, usize)>,
    pos: usize,
    tag_len: usize,
    has_frames: bool,
    ack_eliciting: bool,
}

impl<'a> PacketWriter<'a> {
    /// Writes `header` with packet number `pn`, truncated to `pn_len` bytes (see
    /// [`packet_number_len`](crate::packet_number_len)), at the start of `buf`, and reserves the
    /// last `tag_len` bytes of the packet for the AEAD tag.
    ///
    /// `buf` bounds the packet, so it is the slot's room for this packet. It must hold the
    /// header, the tag, and a payload of at least one byte and at least the size header
    /// protection needs to sample. On error `buf` is unchanged.
    pub fn new(
        buf: &'a mut [u8],
        header: HeaderSpec<'_>,
        pn: u64,
        pn_len: usize,
        tag_len: usize,
    ) -> Result<Self, WriterError> {
        if !(1..=4).contains(&pn_len) {
            return Err(WriterError::InvalidPnLen);
        }
        let pn_bits = pn_len as u8 - 1;
        // The first byte, the Destination Connection ID, and the long-header fields after it.
        let (first, dcid, long) = match header {
            HeaderSpec::Initial {
                version,
                dcid,
                scid,
                token,
            } => (
                long_first(INITIAL_TYPE, pn_bits),
                dcid,
                Some((version, scid, Some(token))),
            ),
            HeaderSpec::ZeroRtt {
                version,
                dcid,
                scid,
            } => (
                long_first(ZERO_RTT_TYPE, pn_bits),
                dcid,
                Some((version, scid, None)),
            ),
            HeaderSpec::Handshake {
                version,
                dcid,
                scid,
            } => (
                long_first(HANDSHAKE_TYPE, pn_bits),
                dcid,
                Some((version, scid, None)),
            ),
            HeaderSpec::OneRtt {
                dcid,
                spin,
                key_phase,
            } => {
                let mut first = FIXED_BIT | pn_bits;
                if spin {
                    first |= SPIN_BIT;
                }
                if key_phase {
                    first |= KEY_PHASE_BIT;
                }
                (first, dcid, None)
            }
        };
        // Lay the header out before writing anything, so a short buffer is left unchanged.
        let length_field = long.map(|(_, scid, token)| {
            let token_len = token.map_or(0, |t: &[u8]| varint_len_of(t.len()) + t.len());
            let offset = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + token_len;
            // Sized for the largest packet the buffer can hold, so it is known before the
            // payload is.
            (offset, varint_len_of(buf.len()))
        });
        let pn_offset = length_field.map_or(1 + dcid.len(), |(offset, size)| offset + size);
        let hdr_len = pn_offset + pn_len;
        let min_len = (hdr_len + 1)
            .checked_add(tag_len)
            .map(|len| len.max(pn_offset + 4 + SAMPLE_LEN));
        if min_len.is_none_or(|min_len| buf.len() < min_len) {
            return Err(WriterError::BufferTooShort);
        }
        let mut w = Writer::new(buf);
        w.put_u8(first);
        if let Some((version, _, _)) = long {
            w.put_u32(version.0);
            // Connection IDs hold at most 20 bytes.
            w.put_u8(dcid.len() as u8);
        }
        w.put_slice(&dcid);
        if let Some((_, scid, token)) = long {
            w.put_u8(scid.len() as u8);
            w.put_slice(&scid);
            if let Some(token) = token {
                w.put_varint(varint_from_len(token.len()));
                w.put_slice(token);
            }
        }
        if let Some((_, size)) = length_field {
            w.put_zeros(size);
        }
        debug_assert_eq!(w.pos(), pn_offset);
        // The low `pn_len` bytes of the packet number.
        w.put_slice(&pn.to_be_bytes()[8 - pn_len..]);
        Ok(Self {
            buf,
            hdr_len,
            pn_offset,
            length_field,
            pos: hdr_len,
            tag_len,
            has_frames: false,
            ack_eliciting: false,
        })
    }

    /// Returns the header length, packet number included.
    pub fn header_len(&self) -> usize {
        self.hdr_len
    }

    /// Returns the offset of the Packet Number field.
    pub fn pn_offset(&self) -> usize {
        self.pn_offset
    }

    /// Returns how many bytes are left for frames.
    pub fn remaining(&self) -> usize {
        self.limit() - self.pos
    }

    /// Returns true until a frame has been written.
    pub fn is_empty(&self) -> bool {
        !self.has_frames
    }

    /// Returns whether an ack-eliciting frame has been written.
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    /// Writes `frame` whole. Returns [`FrameWriteError::Full`] if it does not fit, and
    /// [`FrameWriteError::Invalid`] if its contents break a rule that [`Frame::encode`] checks.
    /// Zero-length PADDING leaves the packet as it was.
    pub fn frame(&mut self, frame: &Frame<'_>) -> Result<(), FrameWriteError> {
        let limit = self.limit();
        let len = frame
            .encode(&mut self.buf[self.pos..limit])
            .map_err(|e| match e {
                FrameEncodeError::BufferTooShort => FrameWriteError::Full,
                FrameEncodeError::Invalid(why) => FrameWriteError::Invalid(why),
            })?;
        self.pos += len;
        // Only zero-length PADDING has an empty encoding.
        self.has_frames |= len > 0;
        self.ack_eliciting |= frame.kind().is_ack_eliciting();
        Ok(())
    }

    /// Writes a STREAM frame with as much of `data` as fits, from stream offset `offset`, and
    /// returns how much it took. `fin` is set only if all of `data` fits. A frame whose data
    /// reaches the end of the packet omits its Length field, and PADDING may precede it to make it
    /// do so. Returns [`Full`] if `data` is not empty and its first byte does not fit, or if a
    /// FIN-only frame does not fit. Data that would end beyond stream offset 2^62 - 1, which flow
    /// control never allows, is refused whole with [`Full`].
    pub fn stream(
        &mut self,
        id: StreamId,
        offset: VarInt,
        data: &[u8],
        fin: bool,
    ) -> Result<StreamFit, Full> {
        let mut payload = self.begin_stream(id, offset, data.len(), fin)?;
        let len = payload.fit.len;
        payload.put(&data[..len]).map_err(|_| Full)?;
        payload.finish().map_err(|_| Full)
    }

    /// Starts a STREAM frame for up to `len` bytes from stream offset `offset`, writing its
    /// header, and returns the [`FramePayload`] through which the caller supplies the data. As
    /// with [`stream`](Self::stream), the frame takes as many bytes as fit.
    pub fn begin_stream(
        &mut self,
        id: StreamId,
        offset: VarInt,
        len: usize,
        fin: bool,
    ) -> Result<FramePayload<'_, 'a>, Full> {
        if len > room_after(offset) {
            return Err(Full);
        }
        let id = VarInt::from(id);
        let has_offset = offset != VarInt::ZERO;
        let header_len = 1 + id.encoded_size() + if has_offset { offset.encoded_size() } else { 0 };
        let avail = self.remaining().checked_sub(header_len).ok_or(Full)?;
        // Data that reaches the end of the packet does not need a Length field, as RFC 9000
        // allows for a packet's last frame; the frame then fills the packet exactly, so other
        // frames, padding included, cannot follow it. Data that fits only without the Length
        // field is preceded by PADDING so that it still ends the packet.
        let (data_len, with_length, pad) = if len >= avail {
            (avail, false, 0)
        } else if fit_with_length(avail, len).ok_or(Full)? < len {
            (len, false, avail - len)
        } else {
            (len, true, 0)
        };
        if data_len == 0 && len > 0 {
            return Err(Full);
        }
        let fin = fin && data_len == len;
        let mut ty = STREAM;
        if with_length {
            ty |= STREAM_LEN;
        }
        if has_offset {
            ty |= STREAM_OFF;
        }
        if fin {
            ty |= STREAM_FIN;
        }
        let frame_start = self.pos;
        let limit = self.limit();
        let mut w = Writer::new(&mut self.buf[frame_start..limit]);
        w.put_zeros(pad);
        w.put_varint(type_varint(ty));
        w.put_varint(id);
        if has_offset {
            w.put_varint(offset);
        }
        if with_length {
            w.put_varint(varint_from_len(data_len));
        }
        self.pos += w.pos();
        Ok(self.payload(frame_start, StreamFit { len: data_len, fin }))
    }

    /// Writes a CRYPTO frame with as much of `data` as fits, from crypto stream offset `offset`,
    /// and returns how many bytes it took, or [`Full`] if the first byte does not fit. As with
    /// [`stream`](Self::stream), data that would end beyond offset 2^62 - 1 is refused whole.
    pub fn crypto(&mut self, offset: VarInt, data: &[u8]) -> Result<usize, Full> {
        let mut payload = self.begin_crypto(offset, data.len())?;
        let len = payload.fit.len;
        payload.put(&data[..len]).map_err(|_| Full)?;
        Ok(payload.finish().map_err(|_| Full)?.len)
    }

    /// Starts a CRYPTO frame for up to `len` bytes, as [`begin_stream`](Self::begin_stream) does
    /// for STREAM frames.
    pub fn begin_crypto(
        &mut self,
        offset: VarInt,
        len: usize,
    ) -> Result<FramePayload<'_, 'a>, Full> {
        if len > room_after(offset) {
            return Err(Full);
        }
        let avail = self
            .remaining()
            .checked_sub(1 + offset.encoded_size())
            .ok_or(Full)?;
        let data_len = fit_with_length(avail, len).ok_or(Full)?;
        if data_len == 0 && len > 0 {
            return Err(Full);
        }
        let frame_start = self.pos;
        let limit = self.limit();
        let mut w = Writer::new(&mut self.buf[frame_start..limit]);
        w.put_varint(type_varint(CRYPTO));
        w.put_varint(offset);
        w.put_varint(varint_from_len(data_len));
        self.pos += w.pos();
        Ok(self.payload(
            frame_start,
            StreamFit {
                len: data_len,
                fin: false,
            },
        ))
    }

    /// Hands out the payload of a frame whose header ends at `self.pos`.
    fn payload(&mut self, frame_start: usize, fit: StreamFit) -> FramePayload<'_, 'a> {
        let was_empty = !self.has_frames;
        let was_ack_eliciting = self.ack_eliciting;
        self.has_frames = true;
        self.ack_eliciting = true;
        FramePayload {
            writer: self,
            frame_start,
            was_empty,
            was_ack_eliciting,
            fit,
            due: fit.len,
            done: false,
        }
    }

    /// Writes an ACK frame, or ACK_ECN when `ecn` is given, and returns how many ranges it
    /// holds.
    ///
    /// `largest` is the range holding the largest acknowledged packet number; `older` yields the
    /// other ranges in descending order, each separated from the one before by at least one
    /// missing packet number. The frame holds `largest` and as many of `older` as fit, from the
    /// newest. `delay` is the ACK Delay field, already scaled by the ack_delay_exponent. Returns
    /// [`Full`] if not even `largest` fits. A range out of order, or a packet number of 2^62 or
    /// more, ends the frame there (and is [`Full`] for `largest`).
    pub fn ack<I>(
        &mut self,
        largest: RangeInclusive<u64>,
        older: I,
        delay: VarInt,
        ecn: Option<EcnCounts>,
    ) -> Result<usize, Full>
    where
        I: IntoIterator<Item = RangeInclusive<u64>>,
        I::IntoIter: Clone,
    {
        let largest_acked = VarInt::from_u64(*largest.end()).map_err(|_| Full)?;
        let first_range =
            VarInt::from_u64(largest.end().checked_sub(*largest.start()).ok_or(Full)?)
                .map_err(|_| Full)?;
        let ecn_len = ecn.map_or(0, |e| {
            e.ect0.encoded_size() + e.ect1.encoded_size() + e.ce.encoded_size()
        });
        let fixed_len = 1
            + largest_acked.encoded_size()
            + delay.encoded_size()
            + first_range.encoded_size()
            + ecn_len;
        let room = self.remaining();
        // The ACK Range Count precedes the ranges and its size depends on how many fit, so
        // count them first, then write.
        let older = older.into_iter();
        let mut count = 0;
        let mut ranges_len = 0;
        for (gap, len) in AckGaps::new(*largest.start(), older.clone()) {
            let next_len = ranges_len + gap.encoded_size() + len.encoded_size();
            if fixed_len + varint_len_of(count + 1) + next_len > room {
                break;
            }
            count += 1;
            ranges_len = next_len;
        }
        if fixed_len + varint_len_of(count) + ranges_len > room {
            return Err(Full);
        }
        let limit = self.limit();
        let mut w = Writer::new(&mut self.buf[self.pos..limit]);
        w.put_varint(type_varint(if ecn.is_some() { ACK_ECN } else { ACK }));
        w.put_varint(largest_acked);
        w.put_varint(delay);
        w.put_varint(varint_from_len(count));
        w.put_varint(first_range);
        for (gap, len) in AckGaps::new(*largest.start(), older).take(count) {
            w.put_varint(gap);
            w.put_varint(len);
        }
        if let Some(ecn) = ecn {
            w.put_varint(ecn.ect0);
            w.put_varint(ecn.ect1);
            w.put_varint(ecn.ce);
        }
        self.pos += w.pos();
        self.has_frames = true;
        Ok(count + 1)
    }

    /// Appends `bytes`, ack-eliciting frames the caller encoded, possibly one frame in several
    /// pieces written in order: the stream and CRYPTO send buffers write their frames this way.
    /// Fails with [`Full`], leaving the packet unchanged, if the bytes do not fit.
    pub fn put_ack_eliciting_bytes(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .filter(|&end| end <= self.limit())
            .ok_or(Full)?;
        if bytes.is_empty() {
            return Ok(());
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        self.has_frames = true;
        self.ack_eliciting = true;
        Ok(())
    }

    /// Writes a DATAGRAM frame (RFC 9221) with a Length field whose data is `parts` in order, each
    /// copied once into the packet. Fails with [`Full`], leaving the packet unchanged, if the whole
    /// frame does not fit.
    pub fn datagram<B: AsRef<[u8]>>(&mut self, parts: &[B]) -> Result<(), Full> {
        let len: usize = parts.iter().map(|part| part.as_ref().len()).sum();
        let frame_len = datagram_frame_len(len);
        if frame_len > self.remaining() {
            return Err(Full);
        }
        let limit = self.limit();
        let mut w = Writer::new(&mut self.buf[self.pos..limit]);
        w.put_varint(type_varint(DATAGRAM_LEN));
        w.put_varint(varint_from_len(len));
        for part in parts {
            w.put_slice(part.as_ref());
        }
        self.pos += frame_len;
        self.has_frames = true;
        self.ack_eliciting = true;
        Ok(())
    }

    /// Pads the packet with PADDING frames until it is `len` bytes long, AEAD tag included.
    /// Returns at once if it is already at least that long, and returns [`Full`] if `len` exceeds
    /// the buffer.
    pub fn pad_to(&mut self, len: usize) -> Result<(), Full> {
        let end = len.saturating_sub(self.tag_len);
        if end <= self.pos {
            return Ok(());
        }
        if end > self.limit() {
            return Err(Full);
        }
        self.buf[self.pos..end].fill(0);
        self.pos = end;
        self.has_frames = true;
        Ok(())
    }

    /// Completes the packet: pads it so header protection can sample it and so it holds at least
    /// one frame, writes a long header's Length field, and returns where everything is for sealing.
    pub fn finish(mut self) -> PacketLayout {
        // The sample starts 4 bytes into the packet number field; the constructor checked that
        // the buffer reaches its end and has room for one payload byte.
        let sample_end = self.pn_offset + 4 + SAMPLE_LEN;
        let min_pos = sample_end
            .saturating_sub(self.tag_len)
            .max(self.hdr_len + usize::from(!self.has_frames));
        if self.pos < min_pos {
            self.buf[self.pos..min_pos].fill(0);
            self.pos = min_pos;
            self.has_frames = true;
        }
        let len = self.pos + self.tag_len;
        if let Some((offset, size)) = self.length_field {
            // The field was sized for the whole buffer, so the length fits.
            varint_from_len(len - self.pn_offset)
                .encode_with_size(size, &mut self.buf[offset..])
                .expect("the Length field was sized for the buffer");
        }
        PacketLayout {
            hdr_len: self.hdr_len,
            pn_offset: self.pn_offset,
            payload_len: self.pos - self.hdr_len,
            len: self.pos + self.tag_len,
        }
    }

    /// Returns the end of the space for frames, where the AEAD tag starts.
    fn limit(&self) -> usize {
        self.buf.len() - self.tag_len
    }
}

/// Returns the largest data length `d <= len` such that a variable-length integer holding `d` and
/// then `d` bytes fit in `avail` bytes, or `None` if not even an empty length field fits.
fn fit_with_length(avail: usize, len: usize) -> Option<usize> {
    let mut data_len = len.min(avail.checked_sub(1)?);
    // Shrinking the data can only shrink its length field, so this settles within a few steps.
    while varint_len_of(data_len) + data_len > avail {
        data_len -= 1;
    }
    Some(data_len)
}

/// Returns how many bytes can follow `offset` before data would end beyond 2^62 - 1.
fn room_after(offset: VarInt) -> usize {
    usize::try_from(VarInt::MAX.into_inner() - offset.into_inner()).unwrap_or(usize::MAX)
}

/// The Gap and ACK Range Length fields of ACK ranges in descending order, ending at the first
/// range that does not lie below the one before it.
#[derive(Clone)]
struct AckGaps<I> {
    smallest: u64,
    ranges: I,
}

impl<I> AckGaps<I> {
    /// Returns an iterator over the fields of `ranges`, which follow a range whose smallest packet
    /// number is `smallest`.
    fn new(smallest: u64, ranges: I) -> Self {
        Self { smallest, ranges }
    }
}

impl<I: Iterator<Item = RangeInclusive<u64>>> Iterator for AckGaps<I> {
    type Item = (VarInt, VarInt);

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.ranges.next()?;
        let (start, end) = (*range.start(), *range.end());
        // At least one missing packet number between ranges: largest <= smallest - 2.
        let gap = self.smallest.checked_sub(end)?.checked_sub(2)?;
        let len = end.checked_sub(start)?;
        self.smallest = start;
        // Both are below the first range's largest, which is below 2^62.
        Some((VarInt::from_u64(gap).ok()?, VarInt::from_u64(len).ok()?))
    }
}

/// Returns the first byte of a long header of type `ty` with Packet Number Length bits `pn_bits`.
fn long_first(ty: u8, pn_bits: u8) -> u8 {
    LONG_FORM | FIXED_BIT | ty << 4 | pn_bits
}

/// Where the parts of a finished packet lie in its buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLayout {
    /// The header length, packet number included.
    pub hdr_len: usize,
    /// The offset of the Packet Number field.
    pub pn_offset: usize,
    /// The length of the plaintext payload, between the header and the AEAD tag.
    pub payload_len: usize,
    /// The packet length, AEAD tag included.
    pub len: usize,
}

/// How much of the offered data a STREAM or CRYPTO frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamFit {
    /// The data bytes in the frame.
    pub len: usize,
    /// Whether the frame carries FIN; always false for CRYPTO.
    pub fin: bool,
}

/// The data of a STREAM or CRYPTO frame whose header is written, supplied by
/// [`put_payload`](Self::put_payload).
///
/// The frame becomes part of the packet only through [`finish`](Self::finish) once all its
/// bytes are supplied; dropping the payload unfinished removes the frame again, so a packet never
/// holds a frame whose Length disagrees with its data.
#[derive(Debug)]
#[must_use = "an unfinished frame payload is removed from the packet"]
pub struct FramePayload<'w, 'a> {
    writer: &'w mut PacketWriter<'a>,
    frame_start: usize,
    was_empty: bool,
    was_ack_eliciting: bool,
    fit: StreamFit,
    due: usize,
    done: bool,
}

impl FramePayload<'_, '_> {
    /// Returns how much data the frame carries, and whether it has FIN.
    pub fn fit(&self) -> StreamFit {
        self.fit
    }

    /// Returns how many bytes are still to supply.
    pub fn due(&self) -> usize {
        self.due
    }

    /// Copies `data[range]` into the frame. On error the frame is unchanged.
    pub fn put_payload(&mut self, data: &Bytes, range: Range<usize>) -> Result<(), PayloadError> {
        self.put(data.get(range).ok_or(PayloadError::OutOfBounds)?)
    }

    /// Completes the frame, or returns [`PayloadError::Incomplete`] and removes it if bytes are
    /// still due.
    pub fn finish(mut self) -> Result<StreamFit, PayloadError> {
        if self.due > 0 {
            return Err(PayloadError::Incomplete);
        }
        self.done = true;
        Ok(self.fit)
    }

    fn put(&mut self, data: &[u8]) -> Result<(), PayloadError> {
        if data.len() > self.due {
            return Err(PayloadError::TooLong);
        }
        let pos = self.writer.pos;
        self.writer.buf[pos..pos + data.len()].copy_from_slice(data);
        self.writer.pos += data.len();
        self.due -= data.len();
        Ok(())
    }
}

impl Drop for FramePayload<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.writer.pos = self.frame_start;
            self.writer.has_frames = !self.was_empty;
            self.writer.ack_eliciting = self.was_ack_eliciting;
        }
    }
}

/// The error for a frame that does not fit in the packet, which is left unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("frame does not fit in the packet")
    }
}

impl std::error::Error for Full {}

/// Why [`PacketWriter::frame`] did not write a frame. The packet is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameWriteError {
    /// The frame does not fit in the space left in the packet.
    Full,
    /// The frame's contents break a rule of RFC 9000, so it may not be sent.
    Invalid(InvalidFrame),
}

impl fmt::Display for FrameWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => Full.fmt(f),
            Self::Invalid(why) => write!(f, "invalid frame: {why}"),
        }
    }
}

impl std::error::Error for FrameWriteError {}

/// Why a [`PacketWriter`] could not start a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterError {
    /// The buffer cannot hold the header, the AEAD tag and the smallest payload.
    BufferTooShort,
    /// The packet number length is not 1 to 4.
    InvalidPnLen,
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooShort => "buffer too short for a packet",
            Self::InvalidPnLen => "packet number length must be 1 to 4",
        })
    }
}

impl std::error::Error for WriterError {}

/// Why [`FramePayload`] refused data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// The range is not within the data.
    OutOfBounds,
    /// The range is longer than the bytes still due.
    TooLong,
    /// The frame was finished with bytes still due, and was removed.
    Incomplete,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutOfBounds => "payload range outside the data",
            Self::TooLong => "payload longer than the frame's declared length",
            Self::Incomplete => "frame finished before all of its payload was supplied",
        })
    }
}

impl std::error::Error for PayloadError {}
