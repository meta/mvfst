/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC wire encodings shared by every mvfstr crate.
//!
//! The crate holds the basic protocol values of RFC 9000: variable-length integers ([`VarInt`]),
//! connection IDs ([`ConnectionId`]), stream IDs ([`StreamId`]), endpoint roles ([`Side`]) and
//! stream directions ([`Dir`]), QUIC versions ([`Version`]) and transport error codes
//! ([`TransportErrorCode`]). On top of them it holds the codecs for packet headers and coalesced
//! datagrams ([`Header`], [`Packets`]), packet numbers ([`packet_number_len`],
//! [`decode_packet_number`]), frames ([`Frame`], [`Frames`]) and transport parameters
//! ([`TransportParameters`]), and the in-place [`PacketWriter`].
//!
//! The crate does not do I/O or read a clock. Parsing borrows from its input and never panics on
//! peer bytes, and writing a packet never allocates.

#![forbid(unsafe_code)]

mod cid;
mod codec;
mod error_code;
mod frame;
mod header;
mod packet_number;
mod side;
mod stream_id;
mod transport_params;
mod varint;
mod version;
mod writer;

pub use cid::CidTooLong;
pub use cid::ConnectionId;
pub use cid::ResetToken;
pub use error_code::TransportErrorCode;
pub use frame::AckFrame;
pub use frame::AckRanges;
pub use frame::EcnCounts;
pub use frame::Frame;
pub use frame::FrameEncodeError;
pub use frame::FrameError;
pub use frame::FrameKind;
pub use frame::Frames;
pub use frame::InvalidFrame;
pub use header::EncodeError;
pub use header::Header;
pub use header::HeaderError;
pub use header::PacketType;
pub use header::Packets;
pub use header::ProtectedHeader;
pub use header::RETRY_INTEGRITY_TAG_LEN;
pub use header::RetryHeader;
pub use header::SAMPLE_LEN;
pub use header::UnsupportedVersion;
pub use header::VersionNegotiation;
pub use header::encode_retry;
pub use header::encode_version_negotiation;
pub use packet_number::decode_packet_number;
pub use packet_number::packet_number_len;
pub use side::Dir;
pub use side::Side;
pub use stream_id::StreamId;
pub use transport_params::PreferredAddress;
pub use transport_params::TransportParameterError;
pub use transport_params::TransportParameters;
pub use varint::BufferTooShort;
pub use varint::UnexpectedEnd;
pub use varint::VarInt;
pub use varint::VarIntBoundsExceeded;
pub use varint::VarIntEncodeError;
pub use version::Version;
pub use writer::FramePayload;
pub use writer::FrameWriteError;
pub use writer::Full;
pub use writer::HeaderSpec;
pub use writer::PacketLayout;
pub use writer::PacketWriter;
pub use writer::PayloadError;
pub use writer::StreamFit;
pub use writer::WriterError;
