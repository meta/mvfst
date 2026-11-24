/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! App tokens in mvfst's format, and mvfst's 0-RTT checks on them.
//!
//! A server stores an app token in every session ticket it issues: the transport parameters it
//! advertised, the client addresses the ticket was used from, the QUIC version and opaque
//! application parameters such as HTTP/3 SETTINGS. When a client resumes with 0-RTT, the server
//! refuses early data if it no longer honours the limits remembered in the ticket, as RFC 9000
//! requires. The bytes and the checks follow mvfst exactly, so mvfst and a server that uses this
//! module read each other's app tokens, and [`Validator`] makes the 0-RTT checks of mvfst's default
//! validator. The module does not issue or encrypt tickets. The layout, in network byte order:
//!
//! ```text
//! u16 0xffa5, u16 length, then (varint id, varint length, varint value) per parameter
//! u8 length, then (u8 length, 4 or 16 address bytes) per source address
//! u32 QUIC version
//! u16 length, then the application parameters
//! ```

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use mvfstr_wire::VarInt;
use mvfstr_wire::Version;

/// The most client addresses a token holds.
pub const MAX_SOURCE_ADDRESSES: usize = 3;

const IDLE_TIMEOUT: u64 = 0x01;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
/// mvfst's parameter for its extended ACK feature mask.
const EXTENDED_ACK_FEATURES: u64 = 0xff0_a004;
/// mvfst's parameter for the congestion window hint, in bytes.
pub const CWND_HINT_BYTES: u64 = 0x7492;
/// mvfst's parameter for the RTT hint, in milliseconds.
pub const RTT_HINT_MS: u64 = 0x7493;

/// mvfst refuses 0-RTT on a token with fewer distinct parameters than this. It is a minimum, so
/// that a later version can add optional parameters.
const MIN_PARAMS: usize = 8;

/// The TLS extension type mvfst keeps ticket parameters under, whatever the connection's version.
const TICKET_PARAMS_EXTENSION: u16 = 0xffa5;

/// The transport parameters a server remembers in a ticket, and the hints mvfst adds to them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TicketParams {
    /// max_idle_timeout, in milliseconds.
    pub idle_timeout_ms: u64,
    /// max_udp_payload_size.
    pub max_udp_payload_size: u64,
    /// initial_max_data.
    pub initial_max_data: u64,
    /// initial_max_stream_data_bidi_local.
    pub initial_max_stream_data_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote.
    pub initial_max_stream_data_bidi_remote: u64,
    /// initial_max_stream_data_uni.
    pub initial_max_stream_data_uni: u64,
    /// initial_max_streams_bidi.
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni.
    pub initial_max_streams_uni: u64,
    /// mvfst's extended ACK feature mask.
    pub extended_ack_features: u8,
    /// The congestion window hint in bytes, from [`cwnd_hint_bytes`]. By default mvfst writes it on
    /// the versions for which [`writes_cwnd_hint`] is true.
    pub cwnd_hint_bytes: Option<u64>,
    /// The RTT hint in milliseconds, from [`rtt_hint_ms`].
    pub rtt_hint_ms: Option<u64>,
}

impl TicketParams {
    /// Returns the integer parameters in the order mvfst writes them.
    fn integers(&self) -> impl Iterator<Item = (u64, u64)> {
        [
            (IDLE_TIMEOUT, Some(self.idle_timeout_ms)),
            (MAX_UDP_PAYLOAD_SIZE, Some(self.max_udp_payload_size)),
            (INITIAL_MAX_DATA, Some(self.initial_max_data)),
            (
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                Some(self.initial_max_stream_data_bidi_local),
            ),
            (
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                Some(self.initial_max_stream_data_bidi_remote),
            ),
            (
                INITIAL_MAX_STREAM_DATA_UNI,
                Some(self.initial_max_stream_data_uni),
            ),
            (
                INITIAL_MAX_STREAMS_BIDI,
                Some(self.initial_max_streams_bidi),
            ),
            (INITIAL_MAX_STREAMS_UNI, Some(self.initial_max_streams_uni)),
            (
                EXTENDED_ACK_FEATURES,
                Some(u64::from(self.extended_ack_features)),
            ),
            (CWND_HINT_BYTES, self.cwnd_hint_bytes),
            (RTT_HINT_MS, self.rtt_hint_ms),
        ]
        .into_iter()
        .filter_map(|(id, value)| Some((id, value?)))
    }
}

/// An app token to write into a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppToken {
    /// The parameters the server advertises.
    pub params: TicketParams,
    /// Client addresses, oldest first and at most [`MAX_SOURCE_ADDRESSES`], see
    /// [`note_peer_address`].
    pub source_addresses: Vec<IpAddr>,
    /// The connection's QUIC version.
    pub version: Version,
    /// The application parameters.
    pub app_params: Vec<u8>,
}

impl AppToken {
    /// Appends the token's bytes to `out`. Fails with [`EncodeError`] when the token cannot be
    /// encoded, and then leaves `out` unchanged.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.source_addresses.len() > MAX_SOURCE_ADDRESSES {
            return Err(EncodeError::TooManySourceAddresses);
        }
        let start = out.len();
        let encoded = encode_token(self.params.integers(), self, out);
        if encoded.is_err() {
            out.truncate(start);
        }
        encoded
    }
}

/// Appends a token with these integer parameters, in this order, and the rest of `token`. Unlike
/// [`AppToken::encode`] it writes as many source addresses as the length prefix holds, so tests
/// can build tokens that mvfst decodes but never writes.
fn encode_token(
    params: impl IntoIterator<Item = (u64, u64)>,
    token: &AppToken,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    out.extend_from_slice(&TICKET_PARAMS_EXTENSION.to_be_bytes());
    let params_at = out.len();
    out.extend_from_slice(&[0; 2]);
    for (id, value) in params {
        let too_large = |_| EncodeError::ParameterTooLarge(id);
        let value = VarInt::from_u64(value).map_err(too_large)?;
        put_varint(out, VarInt::from_u64(id).map_err(too_large)?);
        put_varint(out, VarInt::from(value.encoded_size() as u8));
        put_varint(out, value);
    }
    let params_len =
        u16::try_from(out.len() - params_at - 2).map_err(|_| EncodeError::FieldTooLong)?;
    out[params_at..params_at + 2].copy_from_slice(&params_len.to_be_bytes());

    let addresses_at = out.len();
    out.push(0);
    for address in &token.source_addresses {
        match address {
            IpAddr::V4(address) => {
                out.push(4);
                out.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                out.push(16);
                out.extend_from_slice(&address.octets());
            }
        }
    }
    out[addresses_at] =
        u8::try_from(out.len() - addresses_at - 1).map_err(|_| EncodeError::FieldTooLong)?;

    out.extend_from_slice(&token.version.0.to_be_bytes());
    let app_params_len =
        u16::try_from(token.app_params.len()).map_err(|_| EncodeError::FieldTooLong)?;
    out.extend_from_slice(&app_params_len.to_be_bytes());
    out.extend_from_slice(&token.app_params);
    Ok(())
}

fn put_varint(out: &mut Vec<u8>, value: VarInt) {
    let mut buf = [0; VarInt::MAX_SIZE];
    let len = value
        .encode(&mut buf)
        .expect("any variable-length integer fits in its maximum size");
    out.extend_from_slice(&buf[..len]);
}

/// The reason an app token cannot be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The value of the parameter with this ID is above the largest variable-length integer.
    ParameterTooLarge(u64),
    /// The token holds more than [`MAX_SOURCE_ADDRESSES`] source addresses.
    TooManySourceAddresses,
    /// A field is too long for its length prefix: the application parameters take more than
    /// 65,535 bytes.
    FieldTooLong,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParameterTooLarge(id) => write!(f, "ticket parameter {id:#x} is too large"),
            Self::TooManySourceAddresses => write!(
                f,
                "app token holds more than {MAX_SOURCE_ADDRESSES} source addresses"
            ),
            Self::FieldTooLong => f.write_str("app token field is too long for its length prefix"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// An app token read from a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedAppToken<'a> {
    params: Vec<(u64, &'a [u8])>,
    /// Client addresses, oldest first.
    pub source_addresses: Vec<IpAddr>,
    /// The QUIC version, absent from a token that ends after its source addresses.
    pub version: Option<Version>,
    /// The application parameters, absent from a token that ends after its source addresses.
    pub app_params: Option<&'a [u8]>,
}

impl<'a> DecodedAppToken<'a> {
    /// Decodes a token, or returns `None` for bytes mvfst refuses. Bytes after the application
    /// parameters are ignored, as mvfst ignores them.
    pub fn decode(token: &'a [u8]) -> Option<Self> {
        let mut reader = Reader(token);
        if reader.u16()? != TICKET_PARAMS_EXTENSION {
            return None;
        }
        let params_len = reader.u16()?;
        let mut params_reader = Reader(reader.bytes(usize::from(params_len))?);
        let mut params = Vec::new();
        while !params_reader.is_empty() {
            let id = params_reader.varint()?;
            let len = usize::try_from(params_reader.varint()?).ok()?;
            let value = params_reader.bytes(len)?;
            // mvfst keeps one parameter per ID, and for lists as short as a ticket's, the first.
            if params.iter().all(|&(seen, _)| seen != id) {
                params.push((id, value));
            }
        }

        let addresses_len = reader.u8()?;
        let mut addresses = Reader(reader.bytes(usize::from(addresses_len))?);
        let mut source_addresses = Vec::new();
        while !addresses.is_empty() {
            let len = addresses.u8()?;
            let bytes = addresses.bytes(usize::from(len))?;
            let address = match <[u8; 4]>::try_from(bytes) {
                Ok(v4) => IpAddr::from(v4),
                Err(_) => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
            };
            source_addresses.push(address);
        }

        let mut token = Self {
            params,
            source_addresses,
            version: None,
            app_params: None,
        };
        if reader.is_empty() {
            return Some(token);
        }
        token.version = Some(Version(reader.u32()?));
        let app_params_len = reader.u16()?;
        token.app_params = Some(reader.bytes(usize::from(app_params_len))?);
        Some(token)
    }

    /// Returns the number of distinct parameters in the token.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Returns the integer value of the parameter with this ID, or `None` if the token lacks it.
    /// Like mvfst, it reads the varint at the start of the value and ignores any bytes after it.
    /// Fails with [`MalformedParameter`] when the value does not start with a varint.
    pub fn integer(&self, id: u64) -> Result<Option<u64>, MalformedParameter> {
        let Some(&(_, value)) = self.params.iter().find(|&&(seen, _)| seen == id) else {
            return Ok(None);
        };
        let (value, _) = VarInt::decode(value).map_err(|_| MalformedParameter { id })?;
        Ok(Some(value.into_inner()))
    }
}

/// Reads big-endian fields off the front of a slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        self.bytes(2)?.try_into().ok().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.bytes(4)?.try_into().ok().map(u32::from_be_bytes)
    }

    fn varint(&mut self) -> Option<u64> {
        let (value, len) = VarInt::decode(self.0).ok()?;
        self.bytes(len)?;
        Some(value.into_inner())
    }
}

/// A ticket parameter whose value does not start with a variable-length integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MalformedParameter {
    /// The parameter's ID.
    pub id: u64,
}

impl fmt::Display for MalformedParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ticket parameter {:#x} is not an integer", self.id)
    }
}

impl std::error::Error for MalformedParameter {}

/// How a server treats a ticket whose source addresses lack the client's address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceTokenPolicy {
    /// Refuse 0-RTT. mvfst's default.
    #[default]
    RejectIfNoExactMatch,
    /// Accept 0-RTT, and limit what the server sends until the client's address is validated.
    LimitIfNoExactMatch,
    /// Refuse 0-RTT, also when the address matches.
    AlwaysReject,
}

/// The reason a server refuses 0-RTT on a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The ticket does not carry an app token.
    NoToken,
    /// The app token does not decode.
    Undecodable,
    /// The app token holds fewer than eight distinct parameters.
    TooFewParameters,
    /// The idle timeout differs from the current one, or the token lacks it.
    IdleTimeoutChanged,
    /// The current max_udp_payload_size is lower than the token's, or the token lacks it.
    MaxUdpPayloadSizeLowered,
    /// The current initial_max_data is lower than the token's, or the token lacks it.
    MaxDataLowered,
    /// A current stream data window is lower than the token's, or the token lacks one.
    MaxStreamDataLowered,
    /// A current stream limit is lower than the token's, or the token lacks one.
    MaxStreamsLowered,
    /// The extended ACK feature mask differs from the current one.
    ExtendedAckFeaturesChanged,
    /// The client's address fails the source-token policy.
    SourceToken,
    /// The application refused its parameters.
    AppParams,
}

/// The outcome of [`Validator::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The reason 0-RTT is refused, or `None` when it is accepted.
    pub rejection: Option<Rejection>,
    /// Whether the token's transport parameters allow 0-RTT under the current ones.
    pub transport_params_matching: bool,
    /// Whether the client's address is among the token's source addresses.
    pub source_token_matching: bool,
    /// Whether the token validates the client's address, which a match does under every policy.
    pub client_address_verified: bool,
    /// Whether the server limits what it sends until the client's address is validated: set
    /// whenever the address did not match a source address under
    /// [`SourceTokenPolicy::LimitIfNoExactMatch`], even when the application then refuses 0-RTT on
    /// its parameters, because mvfst sets the limit before it checks them. mvfst allows
    /// limitedCwndInMss full-sized packets, and as many more per packet received.
    pub limit_writable_bytes: bool,
    /// The source addresses the next ticket starts from, oldest first: the token's, with the
    /// client's address moved or added to the end and at most [`MAX_SOURCE_ADDRESSES`] kept.
    /// Empty when the transport parameters did not match.
    pub source_addresses: Vec<IpAddr>,
}

impl Verdict {
    fn refused(rejection: Rejection) -> Self {
        Self {
            rejection: Some(rejection),
            transport_params_matching: false,
            source_token_matching: false,
            client_address_verified: false,
            limit_writable_bytes: false,
            source_addresses: Vec::new(),
        }
    }

    /// Returns whether 0-RTT is accepted.
    pub fn accepts_early_data(&self) -> bool {
        self.rejection.is_none()
    }
}

/// A server's 0-RTT checks on app tokens, as mvfst's default validator makes them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Validator {
    /// The parameters the server advertises now. Their hints are not used.
    pub current: TicketParams,
    /// How the server treats a ticket whose source addresses lack the client's address.
    pub policy: SourceTokenPolicy,
}

impl Validator {
    /// Decides whether to accept 0-RTT on a resumed ticket that carries `token`.
    ///
    /// The token must hold at least eight distinct parameters. The idle timeout and the extended
    /// ACK feature mask must equal the token's, and max_udp_payload_size, initial_max_data, the
    /// stream data windows and the stream limits must not be lower. Then `peer`, the client's
    /// address, must pass the source-token policy. Last, `app_params_valid` gets the token's
    /// application parameters; it runs only when every check before it passed.
    ///
    /// Fails with [`MalformedParameter`] when a parameter that a check reads is not an integer,
    /// rather than refusing 0-RTT, because mvfst fails the handshake on it.
    pub fn validate(
        &self,
        token: Option<&[u8]>,
        peer: IpAddr,
        app_params_valid: impl FnOnce(Option<&[u8]>) -> bool,
    ) -> Result<Verdict, MalformedParameter> {
        let Some(token) = token else {
            return Ok(Verdict::refused(Rejection::NoToken));
        };
        let Some(token) = DecodedAppToken::decode(token) else {
            return Ok(Verdict::refused(Rejection::Undecodable));
        };
        if let Some(rejection) = self.check_params(&token)? {
            return Ok(Verdict::refused(rejection));
        }

        let DecodedAppToken {
            source_addresses: mut addresses,
            app_params,
            ..
        } = token;
        let matched = move_matches_to_end(&mut addresses, peer);
        if !matched {
            addresses.push(peer);
        }
        keep_newest(&mut addresses);
        let (accepted, limited) = match (matched, self.policy) {
            (_, SourceTokenPolicy::AlwaysReject) => (false, false),
            (true, _) => (true, false),
            (false, SourceTokenPolicy::LimitIfNoExactMatch) => (true, true),
            (false, SourceTokenPolicy::RejectIfNoExactMatch) => (false, false),
        };
        let mut verdict = Verdict {
            rejection: Some(Rejection::SourceToken),
            transport_params_matching: true,
            source_token_matching: matched,
            client_address_verified: matched,
            limit_writable_bytes: limited,
            source_addresses: addresses,
        };
        if !accepted {
            return Ok(verdict);
        }

        verdict.rejection = (!app_params_valid(app_params)).then_some(Rejection::AppParams);
        Ok(verdict)
    }

    /// Returns the reason the token's transport parameters do not allow 0-RTT, or `None` when they
    /// do, checking them in mvfst's order.
    fn check_params(
        &self,
        token: &DecodedAppToken<'_>,
    ) -> Result<Option<Rejection>, MalformedParameter> {
        let current = &self.current;
        // A parameter the token lacks fails its check.
        let at_most =
            |(ticket, now): (Option<u64>, u64)| ticket.is_some_and(|ticket| ticket <= now);

        if token.param_count() < MIN_PARAMS {
            return Ok(Some(Rejection::TooFewParameters));
        }
        if token.integer(IDLE_TIMEOUT)? != Some(current.idle_timeout_ms) {
            return Ok(Some(Rejection::IdleTimeoutChanged));
        }
        if !at_most((
            token.integer(MAX_UDP_PAYLOAD_SIZE)?,
            current.max_udp_payload_size,
        )) {
            return Ok(Some(Rejection::MaxUdpPayloadSizeLowered));
        }
        if !at_most((token.integer(INITIAL_MAX_DATA)?, current.initial_max_data)) {
            return Ok(Some(Rejection::MaxDataLowered));
        }
        let windows = [
            (
                token.integer(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)?,
                current.initial_max_stream_data_bidi_local,
            ),
            (
                token.integer(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)?,
                current.initial_max_stream_data_bidi_remote,
            ),
            (
                token.integer(INITIAL_MAX_STREAM_DATA_UNI)?,
                current.initial_max_stream_data_uni,
            ),
        ];
        if !windows.into_iter().all(at_most) {
            return Ok(Some(Rejection::MaxStreamDataLowered));
        }
        let streams = [
            (
                token.integer(INITIAL_MAX_STREAMS_BIDI)?,
                current.initial_max_streams_bidi,
            ),
            (
                token.integer(INITIAL_MAX_STREAMS_UNI)?,
                current.initial_max_streams_uni,
            ),
        ];
        if !streams.into_iter().all(at_most) {
            return Ok(Some(Rejection::MaxStreamsLowered));
        }
        // mvfst reads an absent mask as 0.
        let mask = token.integer(EXTENDED_ACK_FEATURES)?.unwrap_or(0);
        if mask != u64::from(current.extended_ack_features) {
            return Ok(Some(Rejection::ExtendedAckFeaturesChanged));
        }
        Ok(None)
    }
}

/// Moves every source address equal to `peer` to the end, replaced by `peer`, as mvfst does, and
/// returns whether any matched.
fn move_matches_to_end(addresses: &mut Vec<IpAddr>, peer: IpAddr) -> bool {
    let mut matched = false;
    for at in (0..addresses.len()).rev() {
        if same_address(addresses[at], peer) {
            matched = true;
            addresses.remove(at);
            addresses.push(peer);
        }
    }
    matched
}

/// Drops the oldest addresses beyond [`MAX_SOURCE_ADDRESSES`]. mvfst drops a single address when it
/// adds one to a full list, which gives the same result for the tokens it writes, since they never
/// hold more.
fn keep_newest(addresses: &mut Vec<IpAddr>) {
    let excess = addresses.len().saturating_sub(MAX_SOURCE_ADDRESSES);
    addresses.drain(..excess);
}

/// Compares addresses as mvfst does, through folly, where an IPv4 address equals its IPv4-mapped
/// IPv6 form.
fn same_address(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(v4), IpAddr::V6(v6)) | (IpAddr::V6(v6), IpAddr::V4(v4)) => {
            v6.to_ipv4_mapped() == Some(v4)
        }
        _ => a == b,
    }
}

/// Returns whether mvfst puts a congestion window hint in the tickets of connections on `version`
/// by default. It does for its versions QUIC_V1_ALIAS, QUIC_V1_ALIAS2 and MVFST_EXPERIMENTAL. A
/// server's transport settings can turn the hint on or off for any version, and mvfst writes it
/// only for connections with a congestion controller.
pub fn writes_cwnd_hint(version: Version) -> bool {
    const QUIC_V1_ALIAS: Version = Version(0xface_b003);
    const QUIC_V1_ALIAS2: Version = Version(0xface_b004);
    const MVFST_EXPERIMENTAL: Version = Version(0xface_b00e);
    matches!(version, QUIC_V1_ALIAS | QUIC_V1_ALIAS2 | MVFST_EXPERIMENTAL)
}

/// Returns the congestion window hint mvfst writes: the bandwidth-delay product `bdp` in bytes,
/// but not less than the initial congestion window of `init_cwnd_packets` packets of
/// `udp_send_packet_len` bytes. It is at most the largest variable-length integer, so it always
/// encodes.
pub fn cwnd_hint_bytes(bdp: u64, udp_send_packet_len: u64, init_cwnd_packets: u64) -> u64 {
    bdp.max(udp_send_packet_len.saturating_mul(init_cwnd_packets))
        .min(VarInt::MAX.into_inner())
}

/// Returns the RTT hint mvfst writes: the smoothed RTT in whole milliseconds, once there is one.
/// It is at most the largest variable-length integer, so it always encodes.
pub fn rtt_hint_ms(srtt: Duration) -> Option<u64> {
    let max = VarInt::MAX.into_inner();
    (!srtt.is_zero()).then(|| u64::try_from(srtt.as_millis()).map_or(max, |ms| ms.min(max)))
}

/// Puts the client's current address last in the source addresses of the next ticket, as mvfst
/// does before it writes each ticket. A present address moves to the end; a new one is added at
/// the end, and the oldest address is dropped to keep at most [`MAX_SOURCE_ADDRESSES`].
pub fn note_peer_address(addresses: &mut Vec<IpAddr>, peer: IpAddr) {
    match addresses
        .iter()
        .position(|&address| same_address(address, peer))
    {
        Some(at) if at + 1 == addresses.len() => {}
        Some(at) => {
            addresses.remove(at);
            addresses.push(peer);
        }
        None => addresses.push(peer),
    }
    keep_newest(addresses);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test addresses parse")
    }

    fn plain_token() -> AppToken {
        AppToken {
            params: TicketParams {
                idle_timeout_ms: 60_000,
                max_udp_payload_size: 1452,
                initial_max_data: 1_500_000,
                initial_max_stream_data_bidi_local: 262_144,
                initial_max_stream_data_bidi_remote: 65_536,
                initial_max_stream_data_uni: 1_048_576,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 10,
                extended_ack_features: 0,
                cwnd_hint_bytes: None,
                rtt_hint_ms: None,
            },
            source_addresses: Vec::new(),
            version: Version::MVFST,
            app_params: Vec::new(),
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("test hex is valid"))
            .collect()
    }

    /// Tokens and the bytes that mvfst's encodeAppToken produces for the same inputs.
    fn golden() -> Vec<(AppToken, Vec<u8>)> {
        vec![
            (
                plain_token(),
                hex(concat!(
                    "ffa5002f01048000ea60030245ac04048016e360050480040000060480010000",
                    "0704801000000802406409010a8ff0a004010000faceb0020000",
                )),
            ),
            (
                AppToken {
                    params: TicketParams {
                        idle_timeout_ms: 30_000,
                        max_udp_payload_size: 1500,
                        initial_max_data: 10_485_760,
                        initial_max_stream_data_bidi_local: 1_048_576,
                        initial_max_stream_data_bidi_remote: 1_048_576,
                        initial_max_stream_data_uni: 65_536,
                        initial_max_streams_bidi: 4_294_967_295,
                        initial_max_streams_uni: 100,
                        extended_ack_features: 2,
                        cwnd_hint_bytes: Some(1 << 40),
                        rtt_hint_ms: Some(25),
                    },
                    source_addresses: vec![
                        ip("1.2.3.4"),
                        ip("2401:db00::1"),
                        ip("::ffff:10.0.0.1"),
                    ],
                    version: Version(0xface_b003),
                    app_params: vec![0x02, 0x01, 0x40, 0x64, 0x06, 0x44, 0x00],
                },
                hex(concat!(
                    "ffa50049010480007530030245dc040480a00000050480100000060480100000",
                    "0704800100000808c0000000ffffffff090240648ff0a00401028000749208c0",
                    "00010000000000800074930119270401020304102401db000000000000000000",
                    "000000011000000000000000000000ffff0a000001faceb00300070201406406",
                    "4400",
                )),
            ),
            (
                AppToken {
                    params: TicketParams {
                        idle_timeout_ms: 0,
                        max_udp_payload_size: 1252,
                        initial_max_data: 63,
                        initial_max_stream_data_bidi_local: 64,
                        initial_max_stream_data_bidi_remote: 16_383,
                        initial_max_stream_data_uni: 16_384,
                        initial_max_streams_bidi: 1_073_741_823,
                        initial_max_streams_uni: 1_073_741_824,
                        extended_ack_features: 3,
                        cwnd_hint_bytes: None,
                        rtt_hint_ms: Some(0),
                    },
                    source_addresses: vec![ip("2401:db00:2111:7283:face::46:0")],
                    version: Version::V1,
                    app_params: Vec::new(),
                },
                hex(concat!(
                    "ffa50034010100030244e404013f0502404006027fff0704800040000804bfff",
                    "ffff0908c0000000400000008ff0a004010380007493010011102401db002111",
                    "7283face000000460000000000010000",
                )),
            ),
            (
                AppToken {
                    params: TicketParams {
                        idle_timeout_ms: 120_000,
                        max_udp_payload_size: 1452,
                        initial_max_data: (1 << 62) - 1,
                        initial_max_stream_data_bidi_local: 0,
                        initial_max_stream_data_bidi_remote: 0,
                        initial_max_stream_data_uni: 0,
                        initial_max_streams_bidi: 0,
                        initial_max_streams_uni: 0,
                        extended_ack_features: 1,
                        cwnd_hint_bytes: Some(14_520),
                        rtt_hint_ms: None,
                    },
                    source_addresses: vec![ip("127.0.0.1")],
                    version: Version(0xface_b00e),
                    app_params: b"h3".to_vec(),
                },
                hex(concat!(
                    "ffa5003001048001d4c0030245ac0408ffffffffffffffff0501000601000701",
                    "000801000901008ff0a0040101800074920278b805047f000001faceb00e0002",
                    "6833",
                )),
            ),
        ]
    }

    #[test]
    fn encode_matches_mvfst_golden_vectors_with_and_without_hints() {
        for (token, expected) in golden() {
            let mut out = vec![0xaa];
            token.encode(&mut out).expect("golden tokens encode");
            assert_eq!(&out[..1], [0xaa], "encode appends");
            assert_eq!(out[1..], expected, "bytes of {token:?}");
        }
    }

    #[test]
    fn decode_reads_golden_vectors_back_and_refuses_their_truncations() {
        for (token, bytes) in golden() {
            let decoded = DecodedAppToken::decode(&bytes).expect("golden tokens decode");
            let integers: Vec<_> = token.params.integers().collect();
            assert_eq!(decoded.param_count(), integers.len());
            for (id, value) in integers {
                assert_eq!(decoded.integer(id), Ok(Some(value)), "parameter {id:#x}");
            }
            assert_eq!(
                decoded.integer(0x0e),
                Ok(None),
                "the token lacks this parameter"
            );
            assert_eq!(decoded.source_addresses, token.source_addresses);
            assert_eq!(decoded.version, Some(token.version));
            assert_eq!(decoded.app_params, Some(&token.app_params[..]));

            // A token that ends right after its source addresses decodes; every other cut fails.
            let addresses_end = bytes.len() - 4 - 2 - token.app_params.len();
            for cut in (0..bytes.len()).filter(|&cut| cut != addresses_end) {
                assert_eq!(DecodedAppToken::decode(&bytes[..cut]), None, "cut at {cut}");
            }
        }

        let (_, bytes) = golden().swap_remove(1);
        let addresses_at = 4 + usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let corrupt = |at: usize, value: u8| {
            let mut bytes = bytes.clone();
            bytes[at] = value;
            bytes
        };
        for (what, bytes) in [
            ("parameters one byte short", corrupt(3, bytes[3] - 1)),
            (
                "address list one byte short",
                corrupt(addresses_at, bytes[addresses_at] - 1),
            ),
            ("a 5-byte address", corrupt(addresses_at + 1, 5)),
            ("an empty address", corrupt(addresses_at + 1, 0)),
        ] {
            assert_eq!(DecodedAppToken::decode(&bytes), None, "{what}");
        }
    }

    #[test]
    fn decode_takes_a_token_without_version_and_ignores_bytes_after_the_app_params() {
        let (token, bytes) = golden().swap_remove(1);
        let addresses_end = bytes.len() - 4 - 2 - token.app_params.len();

        let short = DecodedAppToken::decode(&bytes[..addresses_end]).expect("mvfst decodes it");
        assert_eq!(short.source_addresses, token.source_addresses);
        assert_eq!(short.version, None);
        assert_eq!(short.app_params, None);
        assert_eq!(short.integer(RTT_HINT_MS), Ok(Some(25)));

        let mut long = bytes.clone();
        long.extend_from_slice(b"trailing");
        let long = DecodedAppToken::decode(&long).expect("mvfst ignores trailing bytes");
        assert_eq!(
            long,
            DecodedAppToken::decode(&bytes).expect("golden tokens decode")
        );
    }

    #[test]
    fn decode_refuses_parameters_under_another_extension_type() {
        let (_, mut bytes) = golden().swap_remove(0);
        // The RFC 9001 codepoint, which mvfst never writes into a ticket.
        bytes[..2].copy_from_slice(&0x39_u16.to_be_bytes());
        assert_eq!(DecodedAppToken::decode(&bytes), None);
    }

    /// Encodes `token` with these integer parameters instead of its own.
    fn with_params(token: &AppToken, params: impl IntoIterator<Item = (u64, u64)>) -> Vec<u8> {
        let mut out = Vec::new();
        encode_token(params, token, &mut out).expect("test tokens encode");
        out
    }

    #[test]
    fn decode_keeps_the_first_of_duplicate_parameters() {
        let token = plain_token();
        let standard: Vec<_> = token.params.integers().collect();

        let later = with_params(
            &token,
            standard.iter().copied().chain([(IDLE_TIMEOUT, 100)]),
        );
        let decoded = DecodedAppToken::decode(&later).expect("duplicates decode");
        assert_eq!(decoded.param_count(), standard.len(), "distinct parameters");
        assert_eq!(decoded.integer(IDLE_TIMEOUT), Ok(Some(60_000)));

        let earlier = with_params(
            &token,
            [(IDLE_TIMEOUT, 100)].into_iter().chain(standard.clone()),
        );
        let decoded = DecodedAppToken::decode(&earlier).expect("duplicates decode");
        assert_eq!(decoded.param_count(), standard.len(), "distinct parameters");
        assert_eq!(decoded.integer(IDLE_TIMEOUT), Ok(Some(100)));
    }

    /// Builds a token whose parameters carry these raw values, without addresses or app params.
    fn raw_token(params: &[(u64, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for &(id, value) in params {
            put_varint(&mut body, VarInt::from_u64(id).expect("test IDs fit"));
            put_varint(&mut body, VarInt::from_u32(value.len() as u32));
            body.extend_from_slice(value);
        }
        let mut token = [0xff, 0xa5].to_vec();
        token.extend_from_slice(&(body.len() as u16).to_be_bytes());
        token.extend_from_slice(&body);
        token.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0]);
        token
    }

    #[test]
    fn integer_reads_the_leading_varint_and_reports_a_malformed_value() {
        let bytes = raw_token(&[
            (0x01, &[0x45, 0xac, 0xff]),
            (0x03, &[]),
            (0x04, &[0x80, 0x01]),
        ]);
        let token = DecodedAppToken::decode(&bytes).expect("raw values decode");
        assert_eq!(
            token.integer(0x01),
            Ok(Some(1452)),
            "bytes after the varint are ignored"
        );
        assert_eq!(
            token.integer(0x03),
            Err(MalformedParameter { id: 0x03 }),
            "empty value"
        );
        assert_eq!(
            token.integer(0x04),
            Err(MalformedParameter { id: 0x04 }),
            "cut varint"
        );
        assert_eq!(token.integer(0x05), Ok(None));
    }

    const PEER: &str = "1.2.3.4";

    /// Returns the ticket parameters of `plain_token` with `change` applied, as (ID, value) pairs.
    fn params_with(change: impl FnOnce(&mut TicketParams)) -> Vec<(u64, u64)> {
        let mut params = plain_token().params;
        change(&mut params);
        params.integers().collect()
    }

    /// Encodes these parameters with the given source addresses.
    fn ticket(params: impl IntoIterator<Item = (u64, u64)>, addresses: &[&str]) -> Vec<u8> {
        let mut token = plain_token();
        token.app_params = b"settings".to_vec();
        token.source_addresses = addresses.iter().map(|address| ip(address)).collect();
        with_params(&token, params)
    }

    #[test]
    fn validator_truth_table_mirrors_mvfsts_default_validator_tests() {
        let current = plain_token().params;
        let limit = Validator {
            current,
            policy: SourceTokenPolicy::LimitIfNoExactMatch,
        };
        let default = Validator {
            current,
            policy: SourceTokenPolicy::default(),
        };
        let with_mask = Validator {
            current: TicketParams {
                extended_ack_features: 2,
                ..current
            },
            ..default
        };
        let unchanged = params_with(|_| {});
        let without = |id| -> Vec<(u64, u64)> {
            unchanged
                .iter()
                .copied()
                .filter(|&(seen, _)| seen != id)
                .collect()
        };
        let missing_params = [
            (INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 262_144),
            (INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 65_536),
            (INITIAL_MAX_STREAM_DATA_UNI, 1_048_576),
            (0x0a, 3),
            (MAX_UDP_PAYLOAD_SIZE, 1452),
        ];
        let with_extra = |extra: (u64, u64)| unchanged.iter().copied().chain([extra]);

        use Rejection::*;
        #[rustfmt::skip]
        let rows: Vec<(&str, Validator, Option<Vec<u8>>, bool, Option<Rejection>)> = vec![
            ("valid params", limit, Some(ticket(unchanged.clone(), &[])), true, None),
            ("valid optional parameter", limit, Some(ticket(with_extra((0x0c, 1)), &[])), true, None),
            ("valid unequal params", limit, Some(ticket(params_with(|p| p.initial_max_data -= 1), &[])), true, None),
            ("null app token", default, None, true, Some(NoToken)),
            ("undecodable app token", default, Some(vec![0xff]), true, Some(Undecodable)),
            ("empty transport params", default, Some(ticket([], &[])), true, Some(TooFewParameters)),
            ("missing params", default, Some(ticket(missing_params, &[PEER])), true, Some(TooFewParameters)),
            ("changed idle timeout", default, Some(ticket(params_with(|p| p.idle_timeout_ms += 100), &[PEER])), true, Some(IdleTimeoutChanged)),
            ("lower idle timeout", default, Some(ticket(params_with(|p| p.idle_timeout_ms -= 100), &[PEER])), true, Some(IdleTimeoutChanged)),
            ("no idle timeout", default, Some(ticket(with_extra((0x0c, 1)).filter(|&(id, _)| id != IDLE_TIMEOUT), &[PEER])), true, Some(IdleTimeoutChanged)),
            ("decreased max packet size", default, Some(ticket(params_with(|p| p.max_udp_payload_size += 1), &[PEER])), true, Some(MaxUdpPayloadSizeLowered)),
            ("decreased max data", default, Some(ticket(params_with(|p| p.initial_max_data += 1), &[PEER])), true, Some(MaxDataLowered)),
            ("no max data", default, Some(ticket(with_extra((0x0c, 1)).filter(|&(id, _)| id != INITIAL_MAX_DATA), &[PEER])), true, Some(MaxDataLowered)),
            ("decreased initial max stream data", default, Some(ticket(params_with(|p| {
                p.initial_max_stream_data_bidi_local += 1;
                p.initial_max_stream_data_bidi_remote += 1;
                p.initial_max_stream_data_uni += 1;
            }), &[PEER])), true, Some(MaxStreamDataLowered)),
            ("decreased uni stream data", default, Some(ticket(params_with(|p| p.initial_max_stream_data_uni += 1), &[PEER])), true, Some(MaxStreamDataLowered)),
            ("decreased initial max streams", default, Some(ticket(params_with(|p| {
                p.initial_max_streams_bidi += 1;
                p.initial_max_streams_uni += 1;
            }), &[PEER])), true, Some(MaxStreamsLowered)),
            ("decreased uni streams", default, Some(ticket(params_with(|p| p.initial_max_streams_uni += 1), &[PEER])), true, Some(MaxStreamsLowered)),
            ("extended ack support changed", default, Some(ticket(params_with(|p| p.extended_ack_features += 1), &[PEER])), true, Some(ExtendedAckFeaturesChanged)),
            ("absent extended ack mask reads as 0", default, Some(ticket(without(EXTENDED_ACK_FEATURES), &[PEER])), true, None),
            ("absent extended ack mask against a set one", with_mask, Some(ticket(without(EXTENDED_ACK_FEATURES), &[PEER])), true, Some(ExtendedAckFeaturesChanged)),
            ("invalid app params", default, Some(ticket(with_extra((IDLE_TIMEOUT, 100)), &[PEER])), false, Some(AppParams)),
        ];

        for (name, validator, token, app_answer, expected) in rows {
            let mut app_params_seen = None;
            let verdict = validator
                .validate(token.as_deref(), ip(PEER), |app_params| {
                    app_params_seen = Some(app_params.map(<[u8]>::to_vec));
                    app_answer
                })
                .expect("well-formed tickets validate");
            assert_eq!(verdict.rejection, expected, "{name}");
            assert_eq!(verdict.accepts_early_data(), expected.is_none(), "{name}");

            let params_match = matches!(expected, None | Some(SourceToken | AppParams));
            assert_eq!(verdict.transport_params_matching, params_match, "{name}");
            let expected_app_call = params_match.then(|| Some(b"settings".to_vec()));
            assert_eq!(
                app_params_seen, expected_app_call,
                "{name}: app params checked last"
            );
        }
    }

    #[test]
    fn the_default_source_token_policy_is_mvfsts_default() {
        assert_eq!(
            SourceTokenPolicy::default(),
            SourceTokenPolicy::RejectIfNoExactMatch,
            "mvfst's zeroRttSourceTokenMatchingPolicy defaults to REJECT_IF_NO_EXACT_MATCH"
        );
    }

    #[test]
    fn source_token_policies_mirror_mvfsts_tests() {
        use SourceTokenPolicy::*;
        let empty: &[&str] = &[];
        let one_no_match = &["1.2.3.5"];
        let one_match = &[PEER];
        let max_no_match = &["1.2.3.5", "1.2.3.6", "1.2.3.7"];
        let max_match = &["1.2.3.5", PEER, "1.2.3.7"];
        let after_one_no_match = &["1.2.3.5", PEER];
        let after_max = &["1.2.3.6", "1.2.3.7", PEER];
        let after_max_match = &["1.2.3.5", "1.2.3.7", PEER];

        // (policy, token addresses, accepted, limited, addresses for the next ticket, matched)
        #[rustfmt::skip]
        let rows: [(SourceTokenPolicy, &[&str], bool, bool, &[&str], bool); 15] = [
            (LimitIfNoExactMatch, empty, true, true, one_match, false),
            (LimitIfNoExactMatch, one_no_match, true, true, after_one_no_match, false),
            (LimitIfNoExactMatch, one_match, true, false, one_match, true),
            (LimitIfNoExactMatch, max_no_match, true, true, after_max, false),
            (LimitIfNoExactMatch, max_match, true, false, after_max_match, true),
            (RejectIfNoExactMatch, empty, false, false, one_match, false),
            (RejectIfNoExactMatch, one_no_match, false, false, after_one_no_match, false),
            (RejectIfNoExactMatch, one_match, true, false, one_match, true),
            (RejectIfNoExactMatch, max_no_match, false, false, after_max, false),
            (RejectIfNoExactMatch, max_match, true, false, after_max_match, true),
            (AlwaysReject, empty, false, false, one_match, false),
            (AlwaysReject, one_no_match, false, false, after_one_no_match, false),
            (AlwaysReject, one_match, false, false, one_match, true),
            (AlwaysReject, max_no_match, false, false, after_max, false),
            (AlwaysReject, max_match, false, false, after_max_match, true),
        ];

        for (policy, addresses, accepted, limited, next, matched) in rows {
            let validator = Validator {
                current: plain_token().params,
                policy,
            };
            let mut app_params_checked = false;
            let verdict = validator
                .validate(
                    Some(&ticket(params_with(|_| {}), addresses)),
                    ip(PEER),
                    |_| {
                        app_params_checked = true;
                        true
                    },
                )
                .expect("well-formed tickets validate");
            let row = format!("{policy:?} with {addresses:?}");
            let expected = (!accepted).then_some(Rejection::SourceToken);
            assert_eq!(verdict.rejection, expected, "{row}");
            assert_eq!(
                app_params_checked, accepted,
                "{row}: app params only after a pass"
            );
            assert!(verdict.transport_params_matching, "{row}");
            assert_eq!(verdict.limit_writable_bytes, limited, "{row}");
            let next: Vec<_> = next.iter().map(|address| ip(address)).collect();
            assert_eq!(verdict.source_addresses, next, "{row}");
            assert_eq!(verdict.source_token_matching, matched, "{row}");
            assert_eq!(verdict.client_address_verified, matched, "{row}");
        }
    }

    #[test]
    fn the_limit_policy_limits_writes_even_when_the_app_params_refuse() {
        let validator = Validator {
            current: plain_token().params,
            policy: SourceTokenPolicy::LimitIfNoExactMatch,
        };
        let verdict = validator
            .validate(
                Some(&ticket(params_with(|_| {}), &["1.2.3.5"])),
                ip(PEER),
                |_| false,
            )
            .expect("well-formed tickets validate");
        assert_eq!(verdict.rejection, Some(Rejection::AppParams));
        assert!(
            verdict.limit_writable_bytes,
            "mvfst sets the write limit before it asks the application"
        );
        assert!(!verdict.client_address_verified);
        assert_eq!(verdict.source_addresses, [ip("1.2.3.5"), ip(PEER)]);
    }

    #[test]
    fn an_ipv4_address_matches_its_ipv4_mapped_form_as_in_folly() {
        let validator = Validator {
            current: plain_token().params,
            policy: SourceTokenPolicy::RejectIfNoExactMatch,
        };
        for (token_address, peer, matched) in [
            ("::ffff:1.2.3.4", "1.2.3.4", true),
            ("1.2.3.4", "::ffff:1.2.3.4", true),
            ("::1.2.3.4", "1.2.3.4", false),
            ("::ffff:1.2.3.5", "1.2.3.4", false),
        ] {
            let verdict = validator
                .validate(
                    Some(&ticket(params_with(|_| {}), &[token_address])),
                    ip(peer),
                    |_| true,
                )
                .expect("well-formed tickets validate");
            assert_eq!(
                verdict.source_token_matching, matched,
                "{token_address} against {peer}"
            );
            assert_eq!(
                verdict.accepts_early_data(),
                matched,
                "{token_address} against {peer}"
            );
            assert_eq!(
                verdict.source_addresses.last(),
                Some(&ip(peer)),
                "the peer's form is kept"
            );
        }
    }

    #[test]
    fn the_next_ticket_keeps_at_most_three_source_addresses() {
        let validator = Validator {
            current: plain_token().params,
            policy: SourceTokenPolicy::LimitIfNoExactMatch,
        };
        let five = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"];
        let five_with_peer = ["10.0.0.1", PEER, "10.0.0.3", "10.0.0.4", "10.0.0.5"];
        for (addresses, next) in [
            (&five, ["10.0.0.4", "10.0.0.5", PEER]),
            (&five_with_peer, ["10.0.0.4", "10.0.0.5", PEER]),
        ] {
            let verdict = validator
                .validate(
                    Some(&ticket(params_with(|_| {}), addresses)),
                    ip(PEER),
                    |_| true,
                )
                .expect("well-formed tickets validate");
            let next: Vec<_> = next.iter().map(|address| ip(address)).collect();
            assert_eq!(verdict.source_addresses, next, "from {addresses:?}");
        }
    }

    #[test]
    fn a_malformed_parameter_fails_validation_once_the_validator_reads_it() {
        let validator = Validator {
            current: plain_token().params,
            policy: SourceTokenPolicy::LimitIfNoExactMatch,
        };
        let varint = |value: u64| {
            let mut out = Vec::new();
            put_varint(&mut out, VarInt::from_u64(value).expect("test values fit"));
            out
        };
        let raw = |change: &dyn Fn(&mut TicketParams), malformed: &[u64]| {
            let values: Vec<(u64, Vec<u8>)> = params_with(change)
                .into_iter()
                .map(|(id, value)| {
                    (
                        id,
                        if malformed.contains(&id) {
                            Vec::new()
                        } else {
                            varint(value)
                        },
                    )
                })
                .chain([(0x0c, Vec::new())])
                .collect();
            let params: Vec<(u64, &[u8])> =
                values.iter().map(|(id, value)| (*id, &value[..])).collect();
            raw_token(&params)
        };
        let unchanged = |_: &mut TicketParams| {};
        let malformed = |id| Err(MalformedParameter { id });

        #[rustfmt::skip]
        let rows: [(&str, Vec<u8>, Result<Option<Rejection>, MalformedParameter>); 6] = [
            ("an unread parameter", raw(&unchanged, &[]), Ok(None)),
            ("idle timeout", raw(&unchanged, &[IDLE_TIMEOUT]), malformed(IDLE_TIMEOUT)),
            ("after a changed idle timeout", raw(&|p| p.idle_timeout_ms += 1, &[MAX_UDP_PAYLOAD_SIZE]), Ok(Some(Rejection::IdleTimeoutChanged))),
            ("max data", raw(&unchanged, &[INITIAL_MAX_DATA]), malformed(INITIAL_MAX_DATA)),
            ("uni window beside a lowered bidi window", raw(&|p| p.initial_max_stream_data_bidi_local += 1, &[INITIAL_MAX_STREAM_DATA_UNI]), malformed(INITIAL_MAX_STREAM_DATA_UNI)),
            ("extended ack mask", raw(&unchanged, &[EXTENDED_ACK_FEATURES]), malformed(EXTENDED_ACK_FEATURES)),
        ];
        for (name, token, expected) in rows {
            let verdict = validator.validate(Some(&token), ip(PEER), |_| true);
            assert_eq!(verdict.map(|verdict| verdict.rejection), expected, "{name}");
        }
    }

    #[test]
    fn cwnd_hints_are_written_for_mvfsts_alias_versions_only() {
        for (version, writes) in [
            (Version(0xface_b003), true),
            (Version(0xface_b004), true),
            (Version(0xface_b00e), true),
            (Version::V1, false),
            (Version::MVFST, false),
            (Version(0xface_b010), false),
            (Version(0xface_b011), false),
        ] {
            assert_eq!(writes_cwnd_hint(version), writes, "{version:?}");
        }
    }

    #[test]
    fn the_rtt_hint_is_the_smoothed_rtt_in_whole_milliseconds_once_there_is_one() {
        for (srtt, hint) in [
            (Duration::ZERO, None),
            (Duration::from_micros(999), Some(0)),
            (Duration::from_micros(25_900), Some(25)),
            (Duration::from_secs(3), Some(3000)),
            (Duration::MAX, Some(VarInt::MAX.into_inner())),
        ] {
            assert_eq!(rtt_hint_ms(srtt), hint, "{srtt:?}");
        }
    }

    #[test]
    fn the_cwnd_hint_is_the_bdp_but_not_less_than_the_initial_window() {
        assert_eq!(cwnd_hint_bytes(200_000, 1252, 10), 200_000);
        assert_eq!(cwnd_hint_bytes(5_000, 1252, 10), 12_520);
        assert_eq!(
            cwnd_hint_bytes(0, u64::MAX, 2),
            VarInt::MAX.into_inner(),
            "an overflowing initial window is clamped to what a varint holds"
        );
        assert_eq!(
            cwnd_hint_bytes(u64::MAX, 1252, 10),
            VarInt::MAX.into_inner(),
            "a huge BDP is clamped to what a varint holds"
        );
    }

    #[test]
    fn the_largest_hints_still_encode() {
        let mut token = plain_token();
        token.params.cwnd_hint_bytes = Some(cwnd_hint_bytes(u64::MAX, u64::MAX, u64::MAX));
        token.params.rtt_hint_ms = rtt_hint_ms(Duration::MAX);
        assert_eq!(token.encode(&mut Vec::new()), Ok(()));
    }

    #[test]
    fn each_ticket_lists_the_current_peer_address_last() {
        let mapped = "::ffff:1.2.3.4";
        #[rustfmt::skip]
        let rows: [(&[&str], &[&str]); 8] = [
            (&[], &[PEER]),
            (&["10.0.0.1"], &["10.0.0.1", PEER]),
            (&["10.0.0.1", "10.0.0.2", "10.0.0.3"], &["10.0.0.2", "10.0.0.3", PEER]),
            (&[PEER, "10.0.0.1"], &["10.0.0.1", PEER]),
            (&["10.0.0.1", PEER], &["10.0.0.1", PEER]),
            (&["10.0.0.1", mapped], &["10.0.0.1", mapped]),
            (&[mapped, "10.0.0.1"], &["10.0.0.1", PEER]),
            (&["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"], &["10.0.0.4", "10.0.0.5", PEER]),
        ];
        for (before, after) in rows {
            let mut addresses: Vec<_> = before.iter().map(|address| ip(address)).collect();
            note_peer_address(&mut addresses, ip(PEER));
            let after: Vec<_> = after.iter().map(|address| ip(address)).collect();
            assert_eq!(addresses, after, "from {before:?}");
        }
    }

    #[test]
    fn encode_refuses_what_the_format_cannot_hold_and_leaves_out_unchanged() {
        let mut too_large = plain_token();
        too_large.params.initial_max_data = 1 << 62;
        let mut long_app_params = plain_token();
        long_app_params.app_params = vec![0; 65_536];
        let mut many_addresses = plain_token();
        many_addresses.source_addresses = vec![ip("10.0.0.1"); MAX_SOURCE_ADDRESSES + 1];

        for (token, error) in [
            (too_large, EncodeError::ParameterTooLarge(0x04)),
            (long_app_params, EncodeError::FieldTooLong),
            (many_addresses, EncodeError::TooManySourceAddresses),
        ] {
            let mut out = vec![0xaa];
            assert_eq!(token.encode(&mut out), Err(error));
            assert_eq!(out, [0xaa], "a failed encode leaves the buffer as it was");
        }

        let mut at_limits = plain_token();
        at_limits.params.initial_max_data = (1 << 62) - 1;
        at_limits.app_params = vec![0; 65_535];
        at_limits.source_addresses = vec![ip("2401:db00::1"); MAX_SOURCE_ADDRESSES];
        assert_eq!(at_limits.encode(&mut Vec::new()), Ok(()));
    }
}
