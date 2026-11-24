/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC frames (RFC 9000).
//!
//! [`Frames`] decodes a decrypted packet payload into [`Frame`]s that borrow from it, so stream
//! and crypto data are never copied here. [`FrameKind`] names each frame type without its
//! contents, holds RFC 9000's rules for it (which packet types may carry it, whether it is
//! ack-eliciting, whether it is a probing frame), and gives the connection's frame sources an
//! exhaustive `match` over every frame type. [`Frame::encode`] writes whole frames and refuses
//! contents that [`Frames`] would reject; [`PacketWriter`](crate::PacketWriter) adds the encoders
//! that split or fit frames to a packet.
//!
//! DATAGRAM frames (RFC 9221, types 0x30 and 0x31) are not implemented. mvfstr never advertises
//! `max_datagram_frame_size`, so receiving one is a PROTOCOL_VIOLATION.

use std::fmt;
use std::ops::RangeInclusive;

use crate::ConnectionId;
use crate::Dir;
use crate::PacketType;
use crate::ResetToken;
use crate::StreamId;
use crate::TransportErrorCode;
use crate::VarInt;
use crate::codec::Reader;
use crate::codec::Writer;
use crate::codec::varint_from_len;
use crate::codec::varint_len_of;

/// A frame type, without the frame's contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// PADDING (0x00).
    Padding,
    /// PING (0x01).
    Ping,
    /// ACK (0x02) and ACK with ECN counts (0x03).
    Ack,
    /// RESET_STREAM (0x04).
    ResetStream,
    /// STOP_SENDING (0x05).
    StopSending,
    /// CRYPTO (0x06).
    Crypto,
    /// NEW_TOKEN (0x07).
    NewToken,
    /// STREAM (0x08-0x0f).
    Stream,
    /// MAX_DATA (0x10).
    MaxData,
    /// MAX_STREAM_DATA (0x11).
    MaxStreamData,
    /// MAX_STREAMS (0x12 bidirectional, 0x13 unidirectional).
    MaxStreams,
    /// DATA_BLOCKED (0x14).
    DataBlocked,
    /// STREAM_DATA_BLOCKED (0x15).
    StreamDataBlocked,
    /// STREAMS_BLOCKED (0x16 bidirectional, 0x17 unidirectional).
    StreamsBlocked,
    /// NEW_CONNECTION_ID (0x18).
    NewConnectionId,
    /// RETIRE_CONNECTION_ID (0x19).
    RetireConnectionId,
    /// PATH_CHALLENGE (0x1a).
    PathChallenge,
    /// PATH_RESPONSE (0x1b).
    PathResponse,
    /// CONNECTION_CLOSE carrying a transport error code, NO_ERROR included (0x1c).
    ConnectionClose,
    /// CONNECTION_CLOSE signalling an application error (0x1d).
    ApplicationClose,
    /// HANDSHAKE_DONE (0x1e).
    HandshakeDone,
}

impl FrameKind {
    /// Every frame kind, in frame type order.
    pub const ALL: [FrameKind; 21] = [
        FrameKind::Padding,
        FrameKind::Ping,
        FrameKind::Ack,
        FrameKind::ResetStream,
        FrameKind::StopSending,
        FrameKind::Crypto,
        FrameKind::NewToken,
        FrameKind::Stream,
        FrameKind::MaxData,
        FrameKind::MaxStreamData,
        FrameKind::MaxStreams,
        FrameKind::DataBlocked,
        FrameKind::StreamDataBlocked,
        FrameKind::StreamsBlocked,
        FrameKind::NewConnectionId,
        FrameKind::RetireConnectionId,
        FrameKind::PathChallenge,
        FrameKind::PathResponse,
        FrameKind::ConnectionClose,
        FrameKind::ApplicationClose,
        FrameKind::HandshakeDone,
    ];

    /// Returns whether a frame of this kind may appear in a packet of type `ty`. As RFC 9000
    /// lists them, Initial and Handshake packets carry only PADDING, PING, ACK, CRYPTO and
    /// CONNECTION_CLOSE of type 0x1c, 0-RTT packets do not carry ACK, CRYPTO, NEW_TOKEN,
    /// PATH_RESPONSE or HANDSHAKE_DONE, and 1-RTT packets carry any frame. Receiving a frame in a
    /// packet type that does not permit it is a PROTOCOL_VIOLATION.
    ///
    /// RETIRE_CONNECTION_ID is allowed in 0-RTT as listed, although a client cannot send it there
    /// and RFC 9000 lets a server treat receiving it as a PROTOCOL_VIOLATION; that choice is the
    /// connection's.
    pub const fn allowed_in(self, ty: PacketType) -> bool {
        use FrameKind::*;
        match ty {
            PacketType::OneRtt => true,
            PacketType::Initial | PacketType::Handshake => {
                matches!(self, Padding | Ping | Ack | Crypto | ConnectionClose)
            }
            PacketType::ZeroRtt => {
                !matches!(self, Ack | Crypto | NewToken | PathResponse | HandshakeDone)
            }
        }
    }

    /// Returns whether a frame of this kind makes its packet ack-eliciting: every kind but
    /// PADDING, ACK and CONNECTION_CLOSE does.
    pub const fn is_ack_eliciting(self) -> bool {
        !matches!(
            self,
            FrameKind::Padding
                | FrameKind::Ack
                | FrameKind::ConnectionClose
                | FrameKind::ApplicationClose
        )
    }

    /// Returns whether a frame of this kind is a probing frame: PADDING, NEW_CONNECTION_ID,
    /// PATH_CHALLENGE or PATH_RESPONSE. Packets holding only probing frames may probe a new path.
    pub const fn is_probing(self) -> bool {
        matches!(
            self,
            FrameKind::Padding
                | FrameKind::NewConnectionId
                | FrameKind::PathChallenge
                | FrameKind::PathResponse
        )
    }
}

/// A decoded frame, borrowing variable-length fields from the packet payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A run of `len` consecutive PADDING frames, decoded as one.
    Padding {
        /// The number of PADDING frames (bytes) in the run.
        len: usize,
    },
    /// PING.
    Ping,
    /// ACK or ACK_ECN.
    Ack(AckFrame<'a>),
    /// RESET_STREAM.
    ResetStream {
        /// The stream.
        id: StreamId,
        /// The application protocol error code.
        error_code: VarInt,
        /// The final size of the stream.
        final_size: VarInt,
    },
    /// STOP_SENDING.
    StopSending {
        /// The stream.
        id: StreamId,
        /// The application protocol error code.
        error_code: VarInt,
    },
    /// CRYPTO.
    Crypto {
        /// The offset of `data` in the encryption level's crypto stream.
        offset: VarInt,
        /// The crypto data.
        data: &'a [u8],
    },
    /// NEW_TOKEN.
    NewToken {
        /// The token, never empty.
        token: &'a [u8],
    },
    /// STREAM.
    Stream {
        /// The stream.
        id: StreamId,
        /// The offset of `data` in the stream.
        offset: VarInt,
        /// The stream data.
        data: &'a [u8],
        /// Whether the frame ends the stream.
        fin: bool,
    },
    /// MAX_DATA.
    MaxData(VarInt),
    /// MAX_STREAM_DATA.
    MaxStreamData {
        /// The stream.
        id: StreamId,
        /// The maximum stream data.
        max: VarInt,
    },
    /// MAX_STREAMS.
    MaxStreams {
        /// The stream type the limit applies to.
        dir: Dir,
        /// The cumulative number of streams of that type the peer may open, at most 2^60.
        max: VarInt,
    },
    /// DATA_BLOCKED.
    DataBlocked(VarInt),
    /// STREAM_DATA_BLOCKED.
    StreamDataBlocked {
        /// The stream.
        id: StreamId,
        /// The stream data limit at which the sender is blocked.
        limit: VarInt,
    },
    /// STREAMS_BLOCKED.
    StreamsBlocked {
        /// The stream type.
        dir: Dir,
        /// The stream limit at which the sender is blocked, at most 2^60.
        limit: VarInt,
    },
    /// NEW_CONNECTION_ID.
    NewConnectionId {
        /// The sequence number of the connection ID.
        seq: VarInt,
        /// Connection IDs with lower sequence numbers are to be retired.
        retire_prior_to: VarInt,
        /// The connection ID, 1 to 20 bytes.
        cid: ConnectionId,
        /// The stateless reset token for the connection ID.
        reset_token: ResetToken,
    },
    /// RETIRE_CONNECTION_ID.
    RetireConnectionId {
        /// The sequence number of the retired connection ID.
        seq: VarInt,
    },
    /// PATH_CHALLENGE.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE of type 0x1c: a transport error code, NO_ERROR included.
    ConnectionClose {
        /// The transport error code.
        error_code: TransportErrorCode,
        /// The type of the frame that caused the error, 0 if unknown.
        frame_type: VarInt,
        /// The reason phrase, which should be UTF-8.
        reason: &'a [u8],
    },
    /// CONNECTION_CLOSE of type 0x1d: an application error.
    ApplicationClose {
        /// The application protocol error code.
        error_code: VarInt,
        /// The reason phrase, which should be UTF-8.
        reason: &'a [u8],
    },
    /// HANDSHAKE_DONE.
    HandshakeDone,
}

impl Frame<'_> {
    /// Returns the length of the frame's encoding by [`encode`](Self::encode).
    pub fn encoded_len(&self) -> usize {
        fn vlen(value: VarInt) -> usize {
            value.encoded_size()
        }
        fn bytes_len(bytes: &[u8]) -> usize {
            varint_len_of(bytes.len()) + bytes.len()
        }
        let id_len = |id: &StreamId| vlen(VarInt::from(*id));
        // Every frame type defined by RFC 9000 encodes on one byte.
        1 + match self {
            Frame::Padding { len } => return *len,
            Frame::Ping | Frame::HandshakeDone => 0,
            Frame::Ack(ack) => {
                vlen(ack.largest)
                    + vlen(ack.delay)
                    + vlen(ack.range_count)
                    + vlen(ack.first_range)
                    + ack.ranges.len()
                    + ack
                        .ecn
                        .map_or(0, |e| vlen(e.ect0) + vlen(e.ect1) + vlen(e.ce))
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => id_len(id) + vlen(*error_code) + vlen(*final_size),
            Frame::StopSending { id, error_code } => id_len(id) + vlen(*error_code),
            Frame::Crypto { offset, data } => vlen(*offset) + bytes_len(data),
            Frame::NewToken { token } => bytes_len(token),
            Frame::Stream {
                id, offset, data, ..
            } => {
                let offset_len = if *offset == VarInt::ZERO {
                    0
                } else {
                    vlen(*offset)
                };
                id_len(id) + offset_len + bytes_len(data)
            }
            Frame::MaxData(max) | Frame::DataBlocked(max) => vlen(*max),
            Frame::MaxStreamData { id, max } => id_len(id) + vlen(*max),
            Frame::StreamDataBlocked { id, limit } => id_len(id) + vlen(*limit),
            Frame::MaxStreams { max, .. } => vlen(*max),
            Frame::StreamsBlocked { limit, .. } => vlen(*limit),
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                ..
            } => vlen(*seq) + vlen(*retire_prior_to) + 1 + cid.len() + ResetToken::LEN,
            Frame::RetireConnectionId { seq } => vlen(*seq),
            Frame::PathChallenge(_) | Frame::PathResponse(_) => 8,
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => vlen(error_code.to_varint()) + vlen(*frame_type) + bytes_len(reason),
            Frame::ApplicationClose { error_code, reason } => vlen(*error_code) + bytes_len(reason),
        }
    }

    /// Writes the whole frame at the start of `out` and returns its length. STREAM frames always
    /// carry a Length field and carry an Offset field only when the offset is not zero. A frame
    /// that [`Frames`] would reject is refused whatever room `out` has (see [`InvalidFrame`]). On
    /// error `out` is unchanged.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, FrameEncodeError> {
        self.check().map_err(FrameEncodeError::Invalid)?;
        let len = self.encoded_len();
        let mut w = Writer::new(out.get_mut(..len).ok_or(FrameEncodeError::BufferTooShort)?);
        match self {
            Frame::Padding { len } => w.put_zeros(*len),
            Frame::Ping => w.put_varint(type_varint(PING)),
            Frame::Ack(ack) => {
                w.put_varint(type_varint(if ack.ecn.is_some() { ACK_ECN } else { ACK }));
                w.put_varint(ack.largest);
                w.put_varint(ack.delay);
                w.put_varint(ack.range_count);
                w.put_varint(ack.first_range);
                w.put_slice(ack.ranges);
                if let Some(ecn) = ack.ecn {
                    w.put_varint(ecn.ect0);
                    w.put_varint(ecn.ect1);
                    w.put_varint(ecn.ce);
                }
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                w.put_varint(type_varint(RESET_STREAM));
                w.put_varint(VarInt::from(*id));
                w.put_varint(*error_code);
                w.put_varint(*final_size);
            }
            Frame::StopSending { id, error_code } => {
                w.put_varint(type_varint(STOP_SENDING));
                w.put_varint(VarInt::from(*id));
                w.put_varint(*error_code);
            }
            Frame::Crypto { offset, data } => {
                w.put_varint(type_varint(CRYPTO));
                w.put_varint(*offset);
                put_bytes(&mut w, data);
            }
            Frame::NewToken { token } => {
                w.put_varint(type_varint(NEW_TOKEN));
                put_bytes(&mut w, token);
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                let has_offset = *offset != VarInt::ZERO;
                let mut bits = STREAM | STREAM_LEN;
                if has_offset {
                    bits |= STREAM_OFF;
                }
                if *fin {
                    bits |= STREAM_FIN;
                }
                w.put_varint(type_varint(bits));
                w.put_varint(VarInt::from(*id));
                if has_offset {
                    w.put_varint(*offset);
                }
                put_bytes(&mut w, data);
            }
            Frame::MaxData(max) => {
                w.put_varint(type_varint(MAX_DATA));
                w.put_varint(*max);
            }
            Frame::MaxStreamData { id, max } => {
                w.put_varint(type_varint(MAX_STREAM_DATA));
                w.put_varint(VarInt::from(*id));
                w.put_varint(*max);
            }
            Frame::MaxStreams { dir, max } => {
                w.put_varint(type_varint(match dir {
                    Dir::Bi => MAX_STREAMS_BIDI,
                    Dir::Uni => MAX_STREAMS_UNI,
                }));
                w.put_varint(*max);
            }
            Frame::DataBlocked(limit) => {
                w.put_varint(type_varint(DATA_BLOCKED));
                w.put_varint(*limit);
            }
            Frame::StreamDataBlocked { id, limit } => {
                w.put_varint(type_varint(STREAM_DATA_BLOCKED));
                w.put_varint(VarInt::from(*id));
                w.put_varint(*limit);
            }
            Frame::StreamsBlocked { dir, limit } => {
                w.put_varint(type_varint(match dir {
                    Dir::Bi => STREAMS_BLOCKED_BIDI,
                    Dir::Uni => STREAMS_BLOCKED_UNI,
                }));
                w.put_varint(*limit);
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                w.put_varint(type_varint(NEW_CONNECTION_ID));
                w.put_varint(*seq);
                w.put_varint(*retire_prior_to);
                // Connection IDs hold at most 20 bytes.
                w.put_u8(cid.len() as u8);
                w.put_slice(cid);
                w.put_slice(&reset_token.0);
            }
            Frame::RetireConnectionId { seq } => {
                w.put_varint(type_varint(RETIRE_CONNECTION_ID));
                w.put_varint(*seq);
            }
            Frame::PathChallenge(data) => {
                w.put_varint(type_varint(PATH_CHALLENGE));
                w.put_slice(data);
            }
            Frame::PathResponse(data) => {
                w.put_varint(type_varint(PATH_RESPONSE));
                w.put_slice(data);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                w.put_varint(type_varint(CONNECTION_CLOSE));
                w.put_varint(error_code.to_varint());
                w.put_varint(*frame_type);
                put_bytes(&mut w, reason);
            }
            Frame::ApplicationClose { error_code, reason } => {
                w.put_varint(type_varint(APPLICATION_CLOSE));
                w.put_varint(*error_code);
                put_bytes(&mut w, reason);
            }
            Frame::HandshakeDone => w.put_varint(type_varint(HANDSHAKE_DONE)),
        }
        debug_assert_eq!(w.pos(), len);
        Ok(len)
    }

    /// Checks the RFC 9000 field rules that [`Frames`] enforces on decode.
    fn check(&self) -> Result<(), InvalidFrame> {
        match self {
            Frame::NewToken { token: [] } => Err(InvalidFrame::EmptyToken),
            Frame::Stream { offset, data, .. } | Frame::Crypto { offset, data }
                if !ends_by_max_offset(*offset, data) =>
            {
                Err(InvalidFrame::DataBeyondMaxOffset)
            }
            Frame::MaxStreams { max: count, .. } | Frame::StreamsBlocked { limit: count, .. }
                if count.into_inner() > StreamId::INDEX_LIMIT =>
            {
                Err(InvalidFrame::StreamCountAboveLimit)
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                ..
            } if retire_prior_to > seq => Err(InvalidFrame::RetirePriorToAboveSequence),
            Frame::NewConnectionId { cid, .. } if cid.is_empty() => {
                Err(InvalidFrame::EmptyConnectionId)
            }
            _ => Ok(()),
        }
    }

    /// Returns the frame's kind.
    pub const fn kind(&self) -> FrameKind {
        match self {
            Frame::Padding { .. } => FrameKind::Padding,
            Frame::Ping => FrameKind::Ping,
            Frame::Ack(_) => FrameKind::Ack,
            Frame::ResetStream { .. } => FrameKind::ResetStream,
            Frame::StopSending { .. } => FrameKind::StopSending,
            Frame::Crypto { .. } => FrameKind::Crypto,
            Frame::NewToken { .. } => FrameKind::NewToken,
            Frame::Stream { .. } => FrameKind::Stream,
            Frame::MaxData(_) => FrameKind::MaxData,
            Frame::MaxStreamData { .. } => FrameKind::MaxStreamData,
            Frame::MaxStreams { .. } => FrameKind::MaxStreams,
            Frame::DataBlocked(_) => FrameKind::DataBlocked,
            Frame::StreamDataBlocked { .. } => FrameKind::StreamDataBlocked,
            Frame::StreamsBlocked { .. } => FrameKind::StreamsBlocked,
            Frame::NewConnectionId { .. } => FrameKind::NewConnectionId,
            Frame::RetireConnectionId { .. } => FrameKind::RetireConnectionId,
            Frame::PathChallenge(_) => FrameKind::PathChallenge,
            Frame::PathResponse(_) => FrameKind::PathResponse,
            Frame::ConnectionClose { .. } => FrameKind::ConnectionClose,
            Frame::ApplicationClose { .. } => FrameKind::ApplicationClose,
            Frame::HandshakeDone => FrameKind::HandshakeDone,
        }
    }
}

/// The ECN counts of an ACK_ECN frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcnCounts {
    /// Packets received with ECT(0).
    pub ect0: VarInt,
    /// Packets received with ECT(1).
    pub ect1: VarInt,
    /// Packets received with ECN-CE.
    pub ce: VarInt,
}

/// A decoded ACK or ACK_ECN frame. Decoding checked every range, so [`ranges`](Self::ranges)
/// yields them without further errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFrame<'a> {
    largest: VarInt,
    delay: VarInt,
    range_count: VarInt,
    first_range: VarInt,
    ranges: &'a [u8],
    ecn: Option<EcnCounts>,
}

impl<'a> AckFrame<'a> {
    /// Returns the Largest Acknowledged packet number.
    pub fn largest(&self) -> VarInt {
        self.largest
    }

    /// Returns the ACK Delay field, still scaled by the peer's ack_delay_exponent.
    pub fn delay(&self) -> VarInt {
        self.delay
    }

    /// Returns the ECN counts of an ACK_ECN frame, or `None` for a plain ACK.
    pub fn ecn(&self) -> Option<EcnCounts> {
        self.ecn
    }

    /// Returns the acknowledged ranges, largest first, each as `smallest..=largest`.
    pub fn ranges(&self) -> AckRanges<'a> {
        let largest = self.largest.into_inner();
        AckRanges {
            r: Reader::new(self.ranges),
            next: Some(largest.saturating_sub(self.first_range.into_inner())..=largest),
        }
    }
}

/// The ranges of an [`AckFrame`], in descending order.
#[derive(Clone, Debug)]
pub struct AckRanges<'a> {
    r: Reader<'a>,
    next: Option<RangeInclusive<u64>>,
}

impl Iterator for AckRanges<'_> {
    type Item = RangeInclusive<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.take()?;
        if !self.r.is_empty() {
            // Decoding validated every range, so these reads and subtractions succeed; a
            // failure just ends the iteration.
            if let (Ok(gap), Ok(len)) = (self.r.varint(), self.r.varint()) {
                self.next = next_ack_range(*current.start(), gap, len);
            }
        }
        Some(current)
    }
}

/// Returns the range after one whose smallest packet number is `smallest`, given the next Gap
/// and ACK Range Length fields, or `None` if it would go below packet number 0.
fn next_ack_range(smallest: u64, gap: VarInt, len: VarInt) -> Option<RangeInclusive<u64>> {
    let largest = smallest.checked_sub(gap.into_inner() + 2)?;
    Some(largest.checked_sub(len.into_inner())?..=largest)
}

/// A frame that failed to decode, with the error to close the connection with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameError {
    code: TransportErrorCode,
    frame_type: VarInt,
    reason: &'static str,
}

impl FrameError {
    fn new(code: TransportErrorCode, frame_type: VarInt, reason: &'static str) -> Self {
        Self {
            code,
            frame_type,
            reason,
        }
    }

    fn encoding(frame_type: VarInt, reason: &'static str) -> Self {
        Self::new(TransportErrorCode::FRAME_ENCODING_ERROR, frame_type, reason)
    }

    /// Returns the transport error code for the CONNECTION_CLOSE frame.
    pub fn code(&self) -> TransportErrorCode {
        self.code
    }

    /// Returns the type of the offending frame, for the CONNECTION_CLOSE Frame Type field, or 0
    /// when the type itself could not be read.
    pub fn frame_type(&self) -> VarInt {
        self.frame_type
    }

    /// Returns a short description, suitable for a reason phrase.
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (frame type {:#x}): {}",
            self.code,
            self.frame_type.into_inner(),
            self.reason
        )
    }
}

impl std::error::Error for FrameError {}

/// Why [`Frame::encode`] did not write a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameEncodeError {
    /// The output buffer is too short for the frame.
    BufferTooShort,
    /// The frame's contents break a field rule of RFC 9000.
    Invalid(InvalidFrame),
}

impl fmt::Display for FrameEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("output buffer too short for the frame"),
            Self::Invalid(why) => write!(f, "invalid frame: {why}"),
        }
    }
}

impl std::error::Error for FrameEncodeError {}

/// Frame contents that RFC 9000 forbids. [`Frames`] rejects each of these with
/// FRAME_ENCODING_ERROR, so a packet must not carry them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidFrame {
    /// STREAM or CRYPTO data that ends beyond offset 2^62 - 1.
    DataBeyondMaxOffset,
    /// A NEW_TOKEN frame with an empty token.
    EmptyToken,
    /// A MAX_STREAMS or STREAMS_BLOCKED count above 2^60.
    StreamCountAboveLimit,
    /// A NEW_CONNECTION_ID frame whose Retire Prior To exceeds its Sequence Number.
    RetirePriorToAboveSequence,
    /// A NEW_CONNECTION_ID frame with an empty connection ID.
    EmptyConnectionId,
}

impl fmt::Display for InvalidFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DataBeyondMaxOffset => "data ends beyond 2^62 - 1",
            Self::EmptyToken => "empty token",
            Self::StreamCountAboveLimit => "stream count above 2^60",
            Self::RetirePriorToAboveSequence => "retire prior to exceeds sequence number",
            Self::EmptyConnectionId => "empty connection ID",
        })
    }
}

impl std::error::Error for InvalidFrame {}

/// The frames of a decrypted packet payload, in order.
///
/// Consecutive PADDING frames are decoded as one [`Frame::Padding`]. The first malformed frame
/// yields its error and ends the iteration. An empty payload does not yield a frame; RFC 9000
/// makes a packet without frames a PROTOCOL_VIOLATION, which the caller checks. DATAGRAM frames
/// (RFC 9221) are not supported and yield a PROTOCOL_VIOLATION error.
#[derive(Clone, Debug)]
pub struct Frames<'a> {
    r: Reader<'a>,
    failed: bool,
}

impl<'a> Frames<'a> {
    /// Iterates over the frames of `payload`.
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            r: Reader::new(payload),
            failed: false,
        }
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.r.is_empty() {
            return None;
        }
        let frame = decode(&mut self.r);
        self.failed = frame.is_err();
        Some(frame)
    }
}

fn decode<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, FrameError> {
    let (ty, size) = r
        .varint_sized()
        .map_err(|_| FrameError::encoding(VarInt::ZERO, "truncated frame type"))?;
    // RFC 9000 lets a receiver treat a longer encoding as a PROTOCOL_VIOLATION.
    if size != ty.encoded_size() {
        return Err(FrameError::new(
            TransportErrorCode::PROTOCOL_VIOLATION,
            ty,
            "frame type not minimally encoded",
        ));
    }
    let mut f = FieldReader { r, ty };
    Ok(match ty.into_inner() {
        PADDING => {
            let run = f.r.peek_rest().iter().take_while(|&&b| b == 0).count();
            f.bytes(run)?;
            Frame::Padding { len: 1 + run }
        }
        bits @ STREAM..=STREAM_LAST => {
            let id = f.stream_id()?;
            let offset = match bits & STREAM_OFF {
                0 => VarInt::ZERO,
                _ => f.varint()?,
            };
            let data = match bits & STREAM_LEN {
                0 => f.r.rest(),
                _ => {
                    let len = f.varint()?;
                    f.bytes_varint_len(len)?
                }
            };
            f.check_end(offset, data)?;
            Frame::Stream {
                id,
                offset,
                data,
                fin: bits & STREAM_FIN != 0,
            }
        }
        RESET_STREAM => Frame::ResetStream {
            id: f.stream_id()?,
            error_code: f.varint()?,
            final_size: f.varint()?,
        },
        STOP_SENDING => Frame::StopSending {
            id: f.stream_id()?,
            error_code: f.varint()?,
        },
        MAX_DATA => Frame::MaxData(f.varint()?),
        MAX_STREAM_DATA => Frame::MaxStreamData {
            id: f.stream_id()?,
            max: f.varint()?,
        },
        MAX_STREAMS_BIDI | MAX_STREAMS_UNI => Frame::MaxStreams {
            dir: dir_of(ty, MAX_STREAMS_UNI),
            max: f.stream_count()?,
        },
        DATA_BLOCKED => Frame::DataBlocked(f.varint()?),
        STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
            id: f.stream_id()?,
            limit: f.varint()?,
        },
        STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
            dir: dir_of(ty, STREAMS_BLOCKED_UNI),
            limit: f.stream_count()?,
        },
        NEW_CONNECTION_ID => {
            let seq = f.varint()?;
            let retire_prior_to = f.varint()?;
            if retire_prior_to > seq {
                return Err(FrameError::encoding(
                    ty,
                    "retire prior to exceeds sequence number",
                ));
            }
            let len = usize::from(f.u8()?);
            if !(1..=ConnectionId::MAX_LEN).contains(&len) {
                return Err(FrameError::encoding(ty, "connection ID length not 1 to 20"));
            }
            let cid = ConnectionId::new(f.bytes(len)?)
                .map_err(|_| FrameError::encoding(ty, "connection ID length not 1 to 20"))?;
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token: ResetToken(f.array()?),
            }
        }
        RETIRE_CONNECTION_ID => Frame::RetireConnectionId { seq: f.varint()? },
        PATH_CHALLENGE => Frame::PathChallenge(f.array()?),
        PATH_RESPONSE => Frame::PathResponse(f.array()?),
        CONNECTION_CLOSE => {
            let error_code = TransportErrorCode::new(f.varint()?);
            let frame_type = f.varint()?;
            let len = f.varint()?;
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason: f.bytes_varint_len(len)?,
            }
        }
        APPLICATION_CLOSE => {
            let error_code = f.varint()?;
            let len = f.varint()?;
            Frame::ApplicationClose {
                error_code,
                reason: f.bytes_varint_len(len)?,
            }
        }
        NEW_TOKEN => {
            let len = f.varint()?;
            let token = f.bytes_varint_len(len)?;
            if token.is_empty() {
                return Err(FrameError::encoding(ty, "empty token"));
            }
            Frame::NewToken { token }
        }
        PING => Frame::Ping,
        HANDSHAKE_DONE => Frame::HandshakeDone,
        CRYPTO => {
            let offset = f.varint()?;
            let len = f.varint()?;
            let data = f.bytes_varint_len(len)?;
            f.check_end(offset, data)?;
            Frame::Crypto { offset, data }
        }
        ACK | ACK_ECN => {
            let negative = || FrameError::encoding(ty, "ACK range below packet number 0");
            let largest = f.varint()?;
            let delay = f.varint()?;
            let range_count = f.varint()?;
            let first_range = f.varint()?;
            let mut smallest = largest
                .into_inner()
                .checked_sub(first_range.into_inner())
                .ok_or_else(negative)?;
            let ranges_start = f.r.peek_rest();
            let before = f.r.remaining();
            // Each range takes at least two bytes, so a huge count soon runs out of input.
            for _ in 0..range_count.into_inner() {
                let gap = f.varint()?;
                let len = f.varint()?;
                smallest = *next_ack_range(smallest, gap, len)
                    .ok_or_else(negative)?
                    .start();
            }
            let ranges = &ranges_start[..before - f.r.remaining()];
            let ecn = match ty.into_inner() {
                ACK_ECN => Some(EcnCounts {
                    ect0: f.varint()?,
                    ect1: f.varint()?,
                    ce: f.varint()?,
                }),
                _ => None,
            };
            Frame::Ack(AckFrame {
                largest,
                delay,
                range_count,
                first_range,
                ranges,
                ecn,
            })
        }
        DATAGRAM | DATAGRAM_LEN => {
            return Err(FrameError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                ty,
                "DATAGRAM frames are not supported",
            ));
        }
        _ => return Err(FrameError::encoding(ty, "unknown frame type")),
    })
}

/// Writes a length-prefixed byte string.
fn put_bytes(w: &mut Writer<'_>, bytes: &[u8]) {
    w.put_varint(varint_from_len(bytes.len()));
    w.put_slice(bytes);
}

/// Returns the stream direction of a MAX_STREAMS or STREAMS_BLOCKED frame type.
fn dir_of(ty: VarInt, uni: u64) -> Dir {
    if ty.into_inner() == uni {
        Dir::Uni
    } else {
        Dir::Bi
    }
}

/// Converts a frame type value to the variable-length integer that encodes it.
pub(crate) const fn type_varint(value: u64) -> VarInt {
    // Every frame type defined here is below 0x40.
    VarInt::from_u32(value as u32)
}

/// Frame type values (RFC 9000).
const PADDING: u64 = 0x00;
const PING: u64 = 0x01;
pub(crate) const ACK: u64 = 0x02;
pub(crate) const ACK_ECN: u64 = 0x03;
const RESET_STREAM: u64 = 0x04;
const STOP_SENDING: u64 = 0x05;
pub(crate) const CRYPTO: u64 = 0x06;
const NEW_TOKEN: u64 = 0x07;
pub(crate) const STREAM: u64 = 0x08;
const STREAM_LAST: u64 = 0x0f;
const MAX_DATA: u64 = 0x10;
const MAX_STREAM_DATA: u64 = 0x11;
const MAX_STREAMS_BIDI: u64 = 0x12;
const MAX_STREAMS_UNI: u64 = 0x13;
const DATA_BLOCKED: u64 = 0x14;
const STREAM_DATA_BLOCKED: u64 = 0x15;
const STREAMS_BLOCKED_BIDI: u64 = 0x16;
const STREAMS_BLOCKED_UNI: u64 = 0x17;
const NEW_CONNECTION_ID: u64 = 0x18;
const RETIRE_CONNECTION_ID: u64 = 0x19;
const PATH_CHALLENGE: u64 = 0x1a;
const PATH_RESPONSE: u64 = 0x1b;
const CONNECTION_CLOSE: u64 = 0x1c;
const APPLICATION_CLOSE: u64 = 0x1d;
const HANDSHAKE_DONE: u64 = 0x1e;
/// DATAGRAM (RFC 9221), reserved here and not implemented.
const DATAGRAM: u64 = 0x30;
const DATAGRAM_LEN: u64 = 0x31;
/// The flag bits of a STREAM frame type.
pub(crate) const STREAM_OFF: u64 = 0x04;
pub(crate) const STREAM_LEN: u64 = 0x02;
pub(crate) const STREAM_FIN: u64 = 0x01;

/// A reader of one frame's fields, which turns a truncated field into a FRAME_ENCODING_ERROR
/// that names the frame type.
struct FieldReader<'r, 'a> {
    r: &'r mut Reader<'a>,
    ty: VarInt,
}

impl<'a> FieldReader<'_, 'a> {
    fn truncated(&self) -> FrameError {
        FrameError::encoding(self.ty, "frame truncated")
    }

    fn varint(&mut self) -> Result<VarInt, FrameError> {
        self.r.varint().map_err(|_| self.truncated())
    }

    fn stream_id(&mut self) -> Result<StreamId, FrameError> {
        Ok(StreamId::from_varint(self.varint()?))
    }

    /// Reads a stream count, which cannot exceed 2^60 since stream IDs stop at 2^62 - 1.
    fn stream_count(&mut self) -> Result<VarInt, FrameError> {
        let count = self.varint()?;
        if count.into_inner() > StreamId::INDEX_LIMIT {
            return Err(FrameError::encoding(self.ty, "stream count above 2^60"));
        }
        Ok(count)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        self.r.u8().map_err(|_| self.truncated())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        self.r.array().map_err(|_| self.truncated())
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], FrameError> {
        self.r.bytes(len).map_err(|_| self.truncated())
    }

    fn bytes_varint_len(&mut self, len: VarInt) -> Result<&'a [u8], FrameError> {
        self.r.bytes_varint_len(len).map_err(|_| self.truncated())
    }

    fn check_end(&self, offset: VarInt, data: &[u8]) -> Result<(), FrameError> {
        if !ends_by_max_offset(offset, data) {
            return Err(FrameError::encoding(self.ty, "data ends beyond 2^62 - 1"));
        }
        Ok(())
    }
}

/// Returns whether stream or crypto data at `offset` ends at or below 2^62 - 1.
fn ends_by_max_offset(offset: VarInt, data: &[u8]) -> bool {
    VarInt::MAX.into_inner() - offset.into_inner() >= data.len() as u64
}
