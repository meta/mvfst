/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC packet headers (RFC 9000, RFC 8999).
//!
//! [`Header::parse`] reads the packet at the front of a datagram without copying, and
//! [`Packets`] walks the coalesced packets of a datagram. Parsing reads only what header
//! protection leaves in the clear: the packet number length, the reserved bits and the key phase
//! are protected, so a [`ProtectedHeader`] exposes where the packet number starts and where the
//! header-protection sample lies, and the caller removes the protection in place. Packets that
//! carry frames are written in place by [`PacketWriter`](crate::PacketWriter);
//! [`encode_version_negotiation`] and [`encode_retry`] write the two packet types that do not,
//! which an endpoint sends as stateless replies.

use std::fmt;
use std::ops::Range;

use crate::ConnectionId;
use crate::UnexpectedEnd;
use crate::Version;
use crate::codec::Reader;
use crate::codec::Writer;

/// The length of the ciphertext sample that header protection takes, for every QUIC v1 AEAD.
pub const SAMPLE_LEN: usize = 16;

/// The length of a Retry packet's integrity tag (RFC 9001).
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// The packet types that carry frames: those with a packet number and packet protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// A long-header Initial packet.
    Initial,
    /// A long-header 0-RTT packet.
    ZeroRtt,
    /// A long-header Handshake packet.
    Handshake,
    /// A short-header 1-RTT packet.
    OneRtt,
}

/// The header of the packet at the front of a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    /// An Initial, 0-RTT, Handshake or 1-RTT packet.
    Protected(ProtectedHeader<'a>),
    /// A Retry packet.
    Retry(RetryHeader<'a>),
    /// A Version Negotiation packet.
    VersionNegotiation(VersionNegotiation<'a>),
    /// A long-header packet of an unsupported version. Only the version-independent fields of
    /// RFC 8999 are read, which is enough to answer with Version Negotiation.
    UnsupportedVersion(UnsupportedVersion<'a>),
}

impl<'a> Header<'a> {
    /// Parses the packet at the front of `datagram`. `local_cid_len` is the length of the
    /// connection IDs this endpoint issues, which short headers do not encode.
    pub fn parse(datagram: &'a [u8], local_cid_len: usize) -> Result<Self, HeaderError> {
        match datagram.first() {
            Some(first) if first & LONG_FORM != 0 => parse_long(datagram),
            _ => parse_short(datagram, local_cid_len),
        }
    }

    /// Returns how many bytes of the datagram the packet occupies.
    pub fn packet_len(&self) -> usize {
        match self {
            Header::Protected(h) => h.packet_len,
            Header::Retry(h) => h.packet_len,
            Header::VersionNegotiation(h) => h.packet_len,
            Header::UnsupportedVersion(h) => h.packet_len,
        }
    }

    /// Returns the Destination Connection ID.
    pub fn dcid(&self) -> &'a [u8] {
        match self {
            Header::Protected(h) => h.dcid,
            Header::Retry(h) => h.dcid,
            Header::VersionNegotiation(h) => h.dcid,
            Header::UnsupportedVersion(h) => h.dcid,
        }
    }

    /// Returns the version of a long header, or `None` for a short header.
    pub fn version(&self) -> Option<Version> {
        match self {
            Header::Protected(h) => h.version,
            Header::Retry(h) => Some(h.version),
            Header::VersionNegotiation(_) => Some(Version::NEGOTIATION),
            Header::UnsupportedVersion(h) => Some(h.version),
        }
    }
}

/// The Header Form bit of the first byte: set for long headers.
pub(crate) const LONG_FORM: u8 = 0x80;
/// The Fixed Bit of the first byte.
pub(crate) const FIXED_BIT: u8 = 0x40;
/// The Spin Bit of a short header's first byte.
pub(crate) const SPIN_BIT: u8 = 0x20;
/// The Key Phase bit of a short header's first byte.
pub(crate) const KEY_PHASE_BIT: u8 = 0x04;
/// The Long Packet Type values (RFC 9000).
pub(crate) const INITIAL_TYPE: u8 = 0x00;
pub(crate) const ZERO_RTT_TYPE: u8 = 0x01;
pub(crate) const HANDSHAKE_TYPE: u8 = 0x02;
const RETRY_TYPE: u8 = 0x03;
/// The longest connection ID a QUIC v1 long header may carry.
const MAX_CID_LEN: usize = 20;

fn parse_short(datagram: &[u8], local_cid_len: usize) -> Result<Header<'_>, HeaderError> {
    let mut r = Reader::new(datagram);
    if r.u8()? & FIXED_BIT == 0 {
        return Err(HeaderError::FixedBitZero);
    }
    let dcid = r.bytes(local_cid_len)?;
    let pn_offset = r.pos();
    if r.remaining() < 4 + SAMPLE_LEN {
        return Err(HeaderError::TooShortForSample);
    }
    Ok(Header::Protected(ProtectedHeader {
        ty: PacketType::OneRtt,
        version: None,
        dcid,
        scid: &[],
        token: &[],
        pn_offset,
        packet_len: datagram.len(),
    }))
}

/// Returns whether packets of `version` use the QUIC v1 layout. mvfst's own version lays out its
/// packets as v1 does; its differences (the Initial salt, the Retry integrity key and nonce, the
/// transport-parameter extension and the parameters it requires) do not touch the packet layout.
fn has_v1_layout(version: Version) -> bool {
    matches!(version, Version::V1 | Version::MVFST)
}

fn parse_long(datagram: &[u8]) -> Result<Header<'_>, HeaderError> {
    let mut r = Reader::new(datagram);
    let first = r.u8()?;
    let version = Version(r.u32()?);
    let dcid_len = r.u8()?;
    let dcid = r.bytes(usize::from(dcid_len))?;
    let scid_len = r.u8()?;
    let scid = r.bytes(usize::from(scid_len))?;
    if version == Version::NEGOTIATION {
        let versions = r.rest();
        if versions.is_empty() || !versions.len().is_multiple_of(4) {
            return Err(HeaderError::BadVersionList);
        }
        return Ok(Header::VersionNegotiation(VersionNegotiation {
            dcid,
            scid,
            versions,
            packet_len: datagram.len(),
        }));
    }
    if !has_v1_layout(version) {
        return Ok(Header::UnsupportedVersion(UnsupportedVersion {
            version,
            dcid,
            scid,
            packet_len: datagram.len(),
        }));
    }
    if first & FIXED_BIT == 0 {
        return Err(HeaderError::FixedBitZero);
    }
    if dcid.len() > MAX_CID_LEN || scid.len() > MAX_CID_LEN {
        return Err(HeaderError::CidTooLong);
    }
    let ty = match (first >> 4) & 0x03 {
        INITIAL_TYPE => PacketType::Initial,
        ZERO_RTT_TYPE => PacketType::ZeroRtt,
        HANDSHAKE_TYPE => PacketType::Handshake,
        _ => {
            let (token, integrity_tag) = r
                .rest()
                .split_last_chunk::<RETRY_INTEGRITY_TAG_LEN>()
                .ok_or(HeaderError::RetryTooShort)?;
            return Ok(Header::Retry(RetryHeader {
                version,
                dcid,
                scid,
                token,
                integrity_tag,
                packet_len: datagram.len(),
            }));
        }
    };
    let token = match ty {
        PacketType::Initial => {
            let token_len = r.varint()?;
            r.bytes_varint_len(token_len)?
        }
        _ => &[],
    };
    let length = r.varint()?;
    let pn_offset = r.pos();
    let length = usize::try_from(length.into_inner())
        .ok()
        .filter(|&length| length <= r.remaining())
        .ok_or(HeaderError::LengthBeyondDatagram)?;
    if length < 4 + SAMPLE_LEN {
        return Err(HeaderError::TooShortForSample);
    }
    Ok(Header::Protected(ProtectedHeader {
        ty,
        version: Some(version),
        dcid,
        scid,
        token,
        pn_offset,
        packet_len: pn_offset + length,
    }))
}

impl From<UnexpectedEnd> for HeaderError {
    fn from(_: UnexpectedEnd) -> Self {
        HeaderError::UnexpectedEnd
    }
}

/// The coalesced packets of a datagram, each with its offset in the datagram.
///
/// A malformed packet yields one error and ends the iteration, since the packets after it cannot
/// be located. Long-header packets with a Length field may be followed by more packets; every
/// other packet takes the rest of the datagram. Dropping later packets whose Destination
/// Connection ID differs from the first one's, as RFC 9000 recommends, is left to the caller.
#[derive(Clone, Debug)]
pub struct Packets<'a> {
    datagram: &'a [u8],
    local_cid_len: usize,
    offset: usize,
    failed: bool,
}

impl<'a> Packets<'a> {
    /// Iterates over the packets of `datagram`. `local_cid_len` is as for [`Header::parse`].
    pub fn new(datagram: &'a [u8], local_cid_len: usize) -> Self {
        Self {
            datagram,
            local_cid_len,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<(usize, Header<'a>), HeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.datagram.get(self.offset..)?;
        if rest.is_empty() || self.failed {
            return None;
        }
        match Header::parse(rest, self.local_cid_len) {
            Ok(header) => {
                let offset = self.offset;
                self.offset += header.packet_len();
                Some(Ok((offset, header)))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

/// The header of an Initial, 0-RTT, Handshake or 1-RTT packet, as received: the packet number
/// and the low bits of the first byte are still under header protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectedHeader<'a> {
    ty: PacketType,
    version: Option<Version>,
    dcid: &'a [u8],
    scid: &'a [u8],
    token: &'a [u8],
    pn_offset: usize,
    packet_len: usize,
}

impl<'a> ProtectedHeader<'a> {
    /// Returns the packet type.
    pub fn ty(&self) -> PacketType {
        self.ty
    }

    /// Returns the version of a long header, or `None` for a short header.
    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// Returns the Destination Connection ID.
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// Returns the Source Connection ID of a long header; it is empty for a short header.
    pub fn scid(&self) -> &'a [u8] {
        self.scid
    }

    /// Returns the Token of an Initial packet; it is empty for other types.
    pub fn token(&self) -> &'a [u8] {
        self.token
    }

    /// Returns the offset of the Packet Number field from the start of the packet.
    pub fn pn_offset(&self) -> usize {
        self.pn_offset
    }

    /// Returns how many bytes of the datagram this packet occupies: for a long header, the bytes
    /// before the Packet Number field plus the Length field's value; for a short header, the rest
    /// of the datagram.
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }

    /// Returns where the header-protection sample lies in the packet: 16 bytes starting 4 bytes
    /// after the start of the Packet Number field (RFC 9001). Parsing checked that the packet is
    /// long enough to hold it.
    pub fn sample_range(&self) -> Range<usize> {
        let start = self.pn_offset + 4;
        start..start + SAMPLE_LEN
    }
}

/// A Retry packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryHeader<'a> {
    version: Version,
    dcid: &'a [u8],
    scid: &'a [u8],
    token: &'a [u8],
    integrity_tag: &'a [u8; RETRY_INTEGRITY_TAG_LEN],
    packet_len: usize,
}

impl<'a> RetryHeader<'a> {
    /// Returns the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the Destination Connection ID.
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// Returns the Source Connection ID: the server's choice for the client's next Initial.
    pub fn scid(&self) -> &'a [u8] {
        self.scid
    }

    /// Returns the Retry Token. A client discards a Retry whose token is empty (RFC 9000).
    pub fn token(&self) -> &'a [u8] {
        self.token
    }

    /// Returns the Retry Integrity Tag (RFC 9001).
    pub fn integrity_tag(&self) -> &'a [u8; RETRY_INTEGRITY_TAG_LEN] {
        self.integrity_tag
    }

    /// Returns how many bytes of the datagram the packet occupies: all of them from its start.
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
}

/// A Version Negotiation packet (RFC 8999).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionNegotiation<'a> {
    dcid: &'a [u8],
    scid: &'a [u8],
    versions: &'a [u8],
    packet_len: usize,
}

impl<'a> VersionNegotiation<'a> {
    /// Returns the Destination Connection ID, up to 255 bytes.
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// Returns the Source Connection ID, up to 255 bytes.
    pub fn scid(&self) -> &'a [u8] {
        self.scid
    }

    /// Returns the Supported Version list, in packet order. Parsing checked that it is non-empty
    /// and holds whole versions.
    pub fn versions(&self) -> impl Iterator<Item = Version> + 'a {
        let (versions, _) = self.versions.as_chunks::<4>();
        versions.iter().map(|&v| Version(u32::from_be_bytes(v)))
    }

    /// Returns how many bytes of the datagram the packet occupies: all of them from its start.
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
}

/// The version-independent fields of a long header of an unsupported version (RFC 8999).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedVersion<'a> {
    version: Version,
    dcid: &'a [u8],
    scid: &'a [u8],
    packet_len: usize,
}

impl<'a> UnsupportedVersion<'a> {
    /// Returns the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the Destination Connection ID, up to 255 bytes.
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// Returns the Source Connection ID, up to 255 bytes.
    pub fn scid(&self) -> &'a [u8] {
        self.scid
    }

    /// Returns how many bytes of the datagram the packet occupies: all of them from its start,
    /// since its length is version specific.
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
}

/// Writes a Version Negotiation packet at the start of `out` and returns its length.
///
/// `dcid` and `scid` echo the Source and Destination Connection IDs of the packet that prompted
/// it, which may be up to 255 bytes long. `unused` supplies the six arbitrary low bits of the
/// first byte; the Fixed Bit is always set, as RFC 9000 recommends. On error `out` is unchanged.
pub fn encode_version_negotiation(
    out: &mut [u8],
    unused: u8,
    dcid: &[u8],
    scid: &[u8],
    versions: &[Version],
) -> Result<usize, EncodeError> {
    if versions.is_empty() {
        return Err(EncodeError::NoVersions);
    }
    if dcid.len() > usize::from(u8::MAX) || scid.len() > usize::from(u8::MAX) {
        return Err(EncodeError::CidTooLong);
    }
    let len = 7 + dcid.len() + scid.len() + 4 * versions.len();
    let out = out.get_mut(..len).ok_or(EncodeError::BufferTooShort)?;
    let mut w = Writer::new(out);
    w.put_u8(LONG_FORM | FIXED_BIT | (unused & 0x3f));
    w.put_u32(Version::NEGOTIATION.0);
    put_cid(&mut w, dcid);
    put_cid(&mut w, scid);
    for version in versions {
        w.put_u32(version.0);
    }
    Ok(len)
}

/// Writes a Retry packet without its integrity tag at the start of `out` and returns its length.
/// The caller computes the Retry Integrity Tag over this packet (RFC 9001) and writes it in the
/// [`RETRY_INTEGRITY_TAG_LEN`] bytes that follow, which `out` must have room for. `unused`
/// supplies the four arbitrary low bits of the first byte. On error `out` is unchanged.
pub fn encode_retry(
    out: &mut [u8],
    unused: u8,
    version: Version,
    dcid: &ConnectionId,
    scid: &ConnectionId,
    token: &[u8],
) -> Result<usize, EncodeError> {
    let len = 7 + dcid.len() + scid.len() + token.len();
    let out = out
        .get_mut(..len + RETRY_INTEGRITY_TAG_LEN)
        .ok_or(EncodeError::BufferTooShort)?;
    let mut w = Writer::new(out);
    w.put_u8(LONG_FORM | FIXED_BIT | RETRY_TYPE << 4 | (unused & 0x0f));
    w.put_u32(version.0);
    put_cid(&mut w, dcid);
    put_cid(&mut w, scid);
    w.put_slice(token);
    Ok(len)
}

/// Writes a connection ID of at most 255 bytes with its 8-bit length prefix.
fn put_cid(w: &mut Writer<'_>, cid: &[u8]) {
    debug_assert!(cid.len() <= usize::from(u8::MAX));
    w.put_u8(cid.len() as u8);
    w.put_slice(cid);
}

/// Why a Version Negotiation or Retry packet could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer is too short.
    BufferTooShort,
    /// A connection ID is longer than its length field allows.
    CidTooLong,
    /// A Version Negotiation packet needs at least one version (RFC 8999).
    NoVersions,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooShort => "output buffer too short for the packet",
            Self::CidTooLong => "connection ID longer than its length field allows",
            Self::NoVersions => "version negotiation packet with no versions",
        })
    }
}

impl std::error::Error for EncodeError {}

/// Why a packet header is malformed. The packet, and any packets after it in the datagram, are
/// discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The datagram ends inside the header.
    UnexpectedEnd,
    /// The Fixed Bit is zero.
    FixedBitZero,
    /// A QUIC v1 long header has a connection ID longer than 20 bytes.
    CidTooLong,
    /// The Length field runs past the end of the datagram.
    LengthBeyondDatagram,
    /// The packet is too short to hold a header-protection sample.
    TooShortForSample,
    /// A Version Negotiation packet has an empty version list or ends inside a version.
    BadVersionList,
    /// A Retry packet is too short to hold its integrity tag.
    RetryTooShort,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedEnd => "datagram ends inside a packet header",
            Self::FixedBitZero => "fixed bit is zero",
            Self::CidTooLong => "connection ID longer than 20 bytes in a QUIC v1 long header",
            Self::LengthBeyondDatagram => "packet length runs past the end of the datagram",
            Self::TooShortForSample => "packet too short for a header protection sample",
            Self::BadVersionList => {
                "version negotiation packet with an empty or truncated version list"
            }
            Self::RetryTooShort => "retry packet too short for its integrity tag",
        })
    }
}

impl std::error::Error for HeaderError {}
