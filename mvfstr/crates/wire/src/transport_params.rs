/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC transport parameters (RFC 9000).
//!
//! [`TransportParameters`] decodes and encodes the transport parameters TLS extension: every
//! parameter RFC 9000 defines, with the value ranges it sets. Unknown and reserved ids are
//! ignored, including mvfst's ack_receive_timestamps_enabled (0xff0a001), which a tperf client
//! always sends; decoding keeps the raw values of any ids the caller names. The caller checks
//! which parameters the sender's role and version allow, and that the connection IDs match the
//! handshake.

use std::fmt;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use bytes::Bytes;

use crate::ConnectionId;
use crate::ResetToken;
use crate::TransportErrorCode;
use crate::UnexpectedEnd;
use crate::VarInt;
use crate::codec::Reader;
use crate::codec::varint_from_len;

/// The transport parameters one endpoint sends. The [`Default`] holds the value RFC 9000 gives
/// each absent parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParameters {
    /// original_destination_connection_id (0x00).
    pub original_destination_connection_id: Option<ConnectionId>,
    /// max_idle_timeout (0x01), in milliseconds; zero disables the timeout.
    pub max_idle_timeout: VarInt,
    /// stateless_reset_token (0x02).
    pub stateless_reset_token: Option<ResetToken>,
    /// max_udp_payload_size (0x03).
    pub max_udp_payload_size: VarInt,
    /// initial_max_data (0x04).
    pub initial_max_data: VarInt,
    /// initial_max_stream_data_bidi_local (0x05).
    pub initial_max_stream_data_bidi_local: VarInt,
    /// initial_max_stream_data_bidi_remote (0x06).
    pub initial_max_stream_data_bidi_remote: VarInt,
    /// initial_max_stream_data_uni (0x07).
    pub initial_max_stream_data_uni: VarInt,
    /// initial_max_streams_bidi (0x08).
    pub initial_max_streams_bidi: VarInt,
    /// initial_max_streams_uni (0x09).
    pub initial_max_streams_uni: VarInt,
    /// ack_delay_exponent (0x0a).
    pub ack_delay_exponent: VarInt,
    /// max_ack_delay (0x0b), in milliseconds.
    pub max_ack_delay: VarInt,
    /// disable_active_migration (0x0c).
    pub disable_active_migration: bool,
    /// preferred_address (0x0d).
    pub preferred_address: Option<PreferredAddress>,
    /// active_connection_id_limit (0x0e).
    pub active_connection_id_limit: VarInt,
    /// initial_source_connection_id (0x0f).
    pub initial_source_connection_id: Option<ConnectionId>,
    /// retry_source_connection_id (0x10).
    pub retry_source_connection_id: Option<ConnectionId>,
    /// Raw values of parameters RFC 9000 does not define. Decoding keeps those whose ids the
    /// caller names, in the order received; encoding writes them after the others.
    pub extra: Vec<(VarInt, Bytes)>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: VarInt::ZERO,
            stateless_reset_token: None,
            // The largest UDP payload over IPv6 or IPv4: 65,535 less the 8-byte UDP header.
            max_udp_payload_size: VarInt::from_u32(65_527),
            initial_max_data: VarInt::ZERO,
            initial_max_stream_data_bidi_local: VarInt::ZERO,
            initial_max_stream_data_bidi_remote: VarInt::ZERO,
            initial_max_stream_data_uni: VarInt::ZERO,
            initial_max_streams_bidi: VarInt::ZERO,
            initial_max_streams_uni: VarInt::ZERO,
            ack_delay_exponent: VarInt::from_u32(3),
            max_ack_delay: VarInt::from_u32(25),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: VarInt::from_u32(2),
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            extra: Vec::new(),
        }
    }
}

impl TransportParameters {
    /// Decodes a transport parameters extension, keeping in [`extra`](Self::extra) the raw
    /// values of the ids in `keep` that RFC 9000 does not define. It does not check which
    /// parameters the sender's role and version allow, or that the connection IDs match the
    /// handshake; the caller checks both.
    pub fn decode(input: &[u8], keep: &[VarInt]) -> Result<Self, TransportParameterError> {
        let mut params = Self::default();
        let mut ids = Vec::new();
        let mut r = Reader::new(input);
        while !r.is_empty() {
            let id = r.varint().map_err(|_| TransportParameterError::Truncated)?;
            let len = r.varint().map_err(|_| TransportParameterError::Truncated)?;
            let value = r
                .bytes_varint_len(len)
                .map_err(|_| TransportParameterError::Truncated)?;
            ids.push(id);
            let field = Field { id, value };
            match id {
                ORIGINAL_DESTINATION_CONNECTION_ID => {
                    params.original_destination_connection_id = Some(field.cid()?);
                }
                MAX_IDLE_TIMEOUT => params.max_idle_timeout = field.int()?,
                STATELESS_RESET_TOKEN => {
                    params.stateless_reset_token = Some(ResetToken(field.array()?));
                }
                MAX_UDP_PAYLOAD_SIZE => params.max_udp_payload_size = field.int()?,
                INITIAL_MAX_DATA => params.initial_max_data = field.int()?,
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.initial_max_stream_data_bidi_local = field.int()?;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.initial_max_stream_data_bidi_remote = field.int()?;
                }
                INITIAL_MAX_STREAM_DATA_UNI => params.initial_max_stream_data_uni = field.int()?,
                INITIAL_MAX_STREAMS_BIDI => params.initial_max_streams_bidi = field.int()?,
                INITIAL_MAX_STREAMS_UNI => params.initial_max_streams_uni = field.int()?,
                ACK_DELAY_EXPONENT => params.ack_delay_exponent = field.int()?,
                MAX_ACK_DELAY => params.max_ack_delay = field.int()?,
                DISABLE_ACTIVE_MIGRATION => {
                    field.empty()?;
                    params.disable_active_migration = true;
                }
                PREFERRED_ADDRESS => params.preferred_address = Some(field.preferred_address()?),
                ACTIVE_CONNECTION_ID_LIMIT => params.active_connection_id_limit = field.int()?,
                INITIAL_SOURCE_CONNECTION_ID => {
                    params.initial_source_connection_id = Some(field.cid()?);
                }
                RETRY_SOURCE_CONNECTION_ID => {
                    params.retry_source_connection_id = Some(field.cid()?);
                }
                _ if keep.contains(&id) => {
                    params.extra.push((id, Bytes::copy_from_slice(value)));
                }
                // Unknown and reserved parameters are ignored, as RFC 9000 requires.
                _ => {}
            }
        }
        // Sorting finds repeats in O(n log n) however many parameters a peer packs in.
        ids.sort_unstable();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(TransportParameterError::Duplicate(pair[0]));
        }
        params.check_ranges()?;
        Ok(params)
    }

    /// Checks the value ranges RFC 9000 sets.
    fn check_ranges(&self) -> Result<(), TransportParameterError> {
        let invalid = [
            (
                MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size.into_inner() < 1200,
            ),
            (
                INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi.into_inner() > MAX_STREAMS,
            ),
            (
                INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni.into_inner() > MAX_STREAMS,
            ),
            (
                ACK_DELAY_EXPONENT,
                self.ack_delay_exponent.into_inner() > 20,
            ),
            (MAX_ACK_DELAY, self.max_ack_delay.into_inner() >= 1 << 14),
            (
                ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit.into_inner() < 2,
            ),
            // A server using zero-length connection IDs cannot offer a preferred address.
            (
                PREFERRED_ADDRESS,
                self.preferred_address
                    .is_some_and(|address| address.connection_id.is_empty()),
            ),
        ];
        match invalid.into_iter().find(|&(_, invalid)| invalid) {
            Some((id, _)) => Err(TransportParameterError::InvalidValue(id)),
            None => Ok(()),
        }
    }

    /// Appends the encoding of these parameters to `out`, in id order and leaving out those at
    /// their defaults, then the extra ones. Fails, leaving `out` unchanged, on anything
    /// [`decode`](Self::decode) would reject: a value out of range, or an extra parameter whose
    /// id repeats or is one RFC 9000 defines.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), TransportParameterError> {
        self.check_encodable()?;
        // An absent parameter takes its default, so a parameter at its default is left out.
        let default = Self::default();
        if let Some(cid) = &self.original_destination_connection_id {
            put_param(out, ORIGINAL_DESTINATION_CONNECTION_ID, cid);
        }
        put_int(
            out,
            MAX_IDLE_TIMEOUT,
            self.max_idle_timeout,
            default.max_idle_timeout,
        );
        if let Some(token) = &self.stateless_reset_token {
            put_param(out, STATELESS_RESET_TOKEN, &token.0);
        }
        put_int(
            out,
            MAX_UDP_PAYLOAD_SIZE,
            self.max_udp_payload_size,
            default.max_udp_payload_size,
        );
        put_int(
            out,
            INITIAL_MAX_DATA,
            self.initial_max_data,
            default.initial_max_data,
        );
        put_int(
            out,
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
            default.initial_max_stream_data_bidi_local,
        );
        put_int(
            out,
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
            default.initial_max_stream_data_bidi_remote,
        );
        put_int(
            out,
            INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
            default.initial_max_stream_data_uni,
        );
        put_int(
            out,
            INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
            default.initial_max_streams_bidi,
        );
        put_int(
            out,
            INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
            default.initial_max_streams_uni,
        );
        put_int(
            out,
            ACK_DELAY_EXPONENT,
            self.ack_delay_exponent,
            default.ack_delay_exponent,
        );
        put_int(
            out,
            MAX_ACK_DELAY,
            self.max_ack_delay,
            default.max_ack_delay,
        );
        if self.disable_active_migration {
            put_param(out, DISABLE_ACTIVE_MIGRATION, &[]);
        }
        if let Some(address) = &self.preferred_address {
            put_preferred_address(out, address);
        }
        put_int(
            out,
            ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
            default.active_connection_id_limit,
        );
        if let Some(cid) = &self.initial_source_connection_id {
            put_param(out, INITIAL_SOURCE_CONNECTION_ID, cid);
        }
        if let Some(cid) = &self.retry_source_connection_id {
            put_param(out, RETRY_SOURCE_CONNECTION_ID, cid);
        }
        for (id, value) in &self.extra {
            put_param(out, *id, value);
        }
        Ok(())
    }

    /// Appends the encoding of these parameters in the order of an mvfst server, for a server
    /// that must send the same bytes: original_destination_connection_id; the stream and
    /// connection windows, the stream limits, max_idle_timeout, ack_delay_exponent,
    /// max_udp_payload_size and active_connection_id_limit, each written even at its default, with
    /// max_ack_delay after ack_delay_exponent when it is not the default; stateless_reset_token,
    /// disable_active_migration, then preferred_address, which mvfst never sends;
    /// initial_source_connection_id and retry_source_connection_id; then the extra ones. Fails
    /// as [`encode`](Self::encode) does.
    pub fn encode_in_mvfst_server_order(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportParameterError> {
        self.check_encodable()?;
        if let Some(cid) = &self.original_destination_connection_id {
            put_param(out, ORIGINAL_DESTINATION_CONNECTION_ID, cid);
        }
        for (id, value) in [
            (
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            ),
            (
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            ),
            (
                INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
            ),
            (INITIAL_MAX_DATA, self.initial_max_data),
            (INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
            (MAX_IDLE_TIMEOUT, self.max_idle_timeout),
            (ACK_DELAY_EXPONENT, self.ack_delay_exponent),
        ] {
            put_int_always(out, id, value);
        }
        // mvfst never sends max_ack_delay, so its peers assume the default; a server with another
        // value must still send it.
        put_int(
            out,
            MAX_ACK_DELAY,
            self.max_ack_delay,
            Self::default().max_ack_delay,
        );
        put_int_always(out, MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size);
        put_int_always(
            out,
            ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        );
        if let Some(token) = &self.stateless_reset_token {
            put_param(out, STATELESS_RESET_TOKEN, &token.0);
        }
        if self.disable_active_migration {
            put_param(out, DISABLE_ACTIVE_MIGRATION, &[]);
        }
        if let Some(address) = &self.preferred_address {
            put_preferred_address(out, address);
        }
        if let Some(cid) = &self.initial_source_connection_id {
            put_param(out, INITIAL_SOURCE_CONNECTION_ID, cid);
        }
        if let Some(cid) = &self.retry_source_connection_id {
            put_param(out, RETRY_SOURCE_CONNECTION_ID, cid);
        }
        for (id, value) in &self.extra {
            put_param(out, *id, value);
        }
        Ok(())
    }

    /// Fails on anything [`decode`](Self::decode) would reject: a value out of range, or an extra
    /// parameter whose id repeats or is one RFC 9000 defines.
    fn check_encodable(&self) -> Result<(), TransportParameterError> {
        self.check_ranges()?;
        for (i, (id, _)) in self.extra.iter().enumerate() {
            let repeated = self.extra[..i].iter().any(|(earlier, _)| earlier == id);
            if *id <= LAST_RFC9000_ID || repeated {
                return Err(TransportParameterError::Duplicate(*id));
            }
        }
        Ok(())
    }
}

fn put_varint(out: &mut Vec<u8>, value: VarInt) {
    let mut buf = [0; VarInt::MAX_SIZE];
    let len = value
        .encode(&mut buf)
        .expect("any variable-length integer fits in its maximum size");
    out.extend_from_slice(&buf[..len]);
}

fn put_param(out: &mut Vec<u8>, id: VarInt, value: &[u8]) {
    put_varint(out, id);
    put_varint(out, varint_from_len(value.len()));
    out.extend_from_slice(value);
}

fn put_int(out: &mut Vec<u8>, id: VarInt, value: VarInt, default: VarInt) {
    if value == default {
        return;
    }
    put_int_always(out, id, value);
}

fn put_preferred_address(out: &mut Vec<u8>, address: &PreferredAddress) {
    put_varint(out, PREFERRED_ADDRESS);
    let cid = &address.connection_id;
    // Two addresses with ports, the CID length byte, the CID and the token.
    put_varint(
        out,
        varint_from_len(4 + 2 + 16 + 2 + 1 + cid.len() + ResetToken::LEN),
    );
    out.extend_from_slice(&address.ipv4.ip().octets());
    out.extend_from_slice(&address.ipv4.port().to_be_bytes());
    out.extend_from_slice(&address.ipv6.ip().octets());
    out.extend_from_slice(&address.ipv6.port().to_be_bytes());
    // Connection IDs hold at most 20 bytes.
    out.push(cid.len() as u8);
    out.extend_from_slice(cid);
    out.extend_from_slice(&address.stateless_reset_token.0);
}

fn put_int_always(out: &mut Vec<u8>, id: VarInt, value: VarInt) {
    put_varint(out, id);
    put_varint(out, varint_from_len(value.encoded_size()));
    put_varint(out, value);
}

/// One parameter's id and value.
struct Field<'a> {
    id: VarInt,
    value: &'a [u8],
}

impl Field<'_> {
    fn malformed(&self) -> TransportParameterError {
        TransportParameterError::Malformed(self.id)
    }

    /// Reads the value as exactly one variable-length integer.
    fn int(&self) -> Result<VarInt, TransportParameterError> {
        match VarInt::decode(self.value) {
            Ok((value, len)) if len == self.value.len() => Ok(value),
            _ => Err(self.malformed()),
        }
    }

    /// Reads the value as a connection ID.
    fn cid(&self) -> Result<ConnectionId, TransportParameterError> {
        ConnectionId::new(self.value).map_err(|_| self.malformed())
    }

    /// Reads the value as a fixed-length array.
    fn array<const N: usize>(&self) -> Result<[u8; N], TransportParameterError> {
        self.value.try_into().map_err(|_| self.malformed())
    }

    /// Checks that the value has zero length.
    fn empty(&self) -> Result<(), TransportParameterError> {
        if self.value.is_empty() {
            Ok(())
        } else {
            Err(self.malformed())
        }
    }

    fn preferred_address(&self) -> Result<PreferredAddress, TransportParameterError> {
        let mut r = Reader::new(self.value);
        let mut read = || -> Result<_, UnexpectedEnd> {
            let ipv4 = SocketAddrV4::new(r.array::<4>()?.into(), r.u16()?);
            let ipv6 = SocketAddrV6::new(r.array::<16>()?.into(), r.u16()?, 0, 0);
            let cid_len = r.u8()?;
            let cid = r.bytes(usize::from(cid_len))?;
            Ok((ipv4, ipv6, cid, r.array()?))
        };
        let (ipv4, ipv6, cid, token) = read().map_err(|_| self.malformed())?;
        if !r.is_empty() {
            return Err(self.malformed());
        }
        Ok(PreferredAddress {
            ipv4,
            ipv6,
            connection_id: ConnectionId::new(cid).map_err(|_| self.malformed())?,
            stateless_reset_token: ResetToken(token),
        })
    }
}

/// The largest stream count a stream limit can hold (RFC 9000).
const MAX_STREAMS: u64 = 1 << 60;

const ORIGINAL_DESTINATION_CONNECTION_ID: VarInt = VarInt::from_u32(0x00);
const MAX_IDLE_TIMEOUT: VarInt = VarInt::from_u32(0x01);
const STATELESS_RESET_TOKEN: VarInt = VarInt::from_u32(0x02);
const MAX_UDP_PAYLOAD_SIZE: VarInt = VarInt::from_u32(0x03);
const INITIAL_MAX_DATA: VarInt = VarInt::from_u32(0x04);
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: VarInt = VarInt::from_u32(0x05);
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: VarInt = VarInt::from_u32(0x06);
const INITIAL_MAX_STREAM_DATA_UNI: VarInt = VarInt::from_u32(0x07);
const INITIAL_MAX_STREAMS_BIDI: VarInt = VarInt::from_u32(0x08);
const INITIAL_MAX_STREAMS_UNI: VarInt = VarInt::from_u32(0x09);
const ACK_DELAY_EXPONENT: VarInt = VarInt::from_u32(0x0a);
const MAX_ACK_DELAY: VarInt = VarInt::from_u32(0x0b);
const DISABLE_ACTIVE_MIGRATION: VarInt = VarInt::from_u32(0x0c);
const PREFERRED_ADDRESS: VarInt = VarInt::from_u32(0x0d);
const ACTIVE_CONNECTION_ID_LIMIT: VarInt = VarInt::from_u32(0x0e);
const INITIAL_SOURCE_CONNECTION_ID: VarInt = VarInt::from_u32(0x0f);
const RETRY_SOURCE_CONNECTION_ID: VarInt = VarInt::from_u32(0x10);
/// RFC 9000 defines ids 0x00 to 0x10.
const LAST_RFC9000_ID: VarInt = RETRY_SOURCE_CONNECTION_ID;

/// The preferred_address transport parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferredAddress {
    /// The IPv4 address and port.
    pub ipv4: SocketAddrV4,
    /// The IPv6 address and port.
    pub ipv6: SocketAddrV6,
    /// The connection ID to use at the preferred address.
    pub connection_id: ConnectionId,
    /// The stateless reset token for that connection ID.
    pub stateless_reset_token: ResetToken,
}

/// Transport parameters that cannot be decoded or encoded: a TRANSPORT_PARAMETER_ERROR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportParameterError {
    /// The input ends inside a parameter.
    Truncated,
    /// The parameter with this id appears more than once. When encoding, also an extra
    /// parameter with an id RFC 9000 defines.
    Duplicate(VarInt),
    /// The value of the parameter with this id is not encoded as RFC 9000 requires.
    Malformed(VarInt),
    /// The value of the parameter with this id is outside the range RFC 9000 allows.
    InvalidValue(VarInt),
}

impl TransportParameterError {
    /// Returns the transport error code to close the connection with.
    pub fn code(&self) -> TransportErrorCode {
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR
    }
}

impl fmt::Display for TransportParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("transport parameters end inside a parameter"),
            Self::Duplicate(id) => {
                write!(
                    f,
                    "transport parameter {:#x} appears twice",
                    id.into_inner()
                )
            }
            Self::Malformed(id) => {
                write!(f, "transport parameter {:#x} is malformed", id.into_inner())
            }
            Self::InvalidValue(id) => {
                write!(
                    f,
                    "transport parameter {:#x} has an invalid value",
                    id.into_inner()
                )
            }
        }
    }
}

impl std::error::Error for TransportParameterError {}
