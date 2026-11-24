/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Packet header parsing and the Version Negotiation and Retry encoders (RFC 9000, RFC 8999).

use mvfstr_wire::ConnectionId;
use mvfstr_wire::EncodeError;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderError;
use mvfstr_wire::PacketType;
use mvfstr_wire::Packets;
use mvfstr_wire::ProtectedHeader;
use mvfstr_wire::RETRY_INTEGRITY_TAG_LEN;
use mvfstr_wire::Version;
use mvfstr_wire::encode_retry;
use mvfstr_wire::encode_version_negotiation;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn protected(datagram: &[u8], local_cid_len: usize) -> ProtectedHeader<'_> {
    match Header::parse(datagram, local_cid_len) {
        Ok(Header::Protected(header)) => header,
        other => panic!("expected a protected header, got {other:?}"),
    }
}

/// Returns RFC 9001 App. A.2's protected client Initial header, padded to the packet's 1,200
/// bytes. The header ends with a 4-byte packet number at offset 18 and a Length of 1,182.
fn rfc9001_client_initial() -> Vec<u8> {
    let mut packet = hex("c000000001088394c8f03e5157080000449e7b9aec34");
    packet.resize(1200, 0xd1);
    packet
}

#[test]
fn parses_the_rfc9001_client_initial() {
    let packet = rfc9001_client_initial();
    let header = protected(&packet, 0);
    assert_eq!(header.ty(), PacketType::Initial);
    assert_eq!(header.version(), Some(Version::V1));
    assert_eq!(header.dcid(), hex("8394c8f03e515708"));
    assert_eq!(header.scid(), b"");
    assert_eq!(header.token(), b"");
    assert_eq!(header.pn_offset(), 18);
    assert_eq!(header.packet_len(), 1200);
    assert_eq!(header.sample_range(), 22..38);
}

#[test]
fn parses_mvfsts_alias_versions_as_version_1_but_not_its_experimental_versions() {
    for version in [
        Version::QUIC_V1_ALIAS,
        Version::QUIC_V1_ALIAS2,
        Version::MVFST_ALIAS,
    ] {
        let mut packet = rfc9001_client_initial();
        packet[1..5].copy_from_slice(&version.0.to_be_bytes());
        let header = protected(&packet, 0);
        assert_eq!(header.ty(), PacketType::Initial);
        assert_eq!(header.version(), Some(version));
        assert_eq!(header.dcid(), hex("8394c8f03e515708"));
        assert_eq!(header.pn_offset(), 18);
    }
    // mvfst's MVFST_EXPERIMENTAL to MVFST_EXPERIMENTAL5 stay unsupported.
    for version in [
        0xface_b00e_u32,
        0xface_b011,
        0xface_b013,
        0xface_b014,
        0xface_b015,
    ] {
        let mut packet = rfc9001_client_initial();
        packet[1..5].copy_from_slice(&version.to_be_bytes());
        let Ok(Header::UnsupportedVersion(header)) = Header::parse(&packet, 0) else {
            panic!("expected {version:#x} to be unsupported");
        };
        assert_eq!(header.version(), Version(version));
    }
}

#[test]
fn parses_zero_rtt_and_handshake_headers_without_a_token_field() {
    // Type bits 01 (0-RTT) and 10 (Handshake); Length 0x0018 = 24 covers PN and payload.
    for (first, ty) in [(0xd0, PacketType::ZeroRtt), (0xe3, PacketType::Handshake)] {
        let mut packet = vec![first, 0, 0, 0, 1, 2, 0xaa, 0xbb, 3, 1, 2, 3, 0x40, 24];
        packet.resize(14 + 24, 0x5a);
        let header = protected(&packet, 0);
        assert_eq!(header.ty(), ty);
        assert_eq!(header.dcid(), [0xaa, 0xbb]);
        assert_eq!(header.scid(), [1, 2, 3]);
        assert_eq!(header.token(), b"");
        assert_eq!(header.pn_offset(), 14);
        assert_eq!(header.packet_len(), 38);
        assert_eq!(header.sample_range(), 18..34);
    }
}

/// RFC 9001 App. A.4.
const RFC9001_RETRY: &str =
    "ff000000010008f067a5502a4262b5 746f6b656e 04a265ba2eff4d829058fb3f0f2496ba";

#[test]
fn parses_the_rfc9001_retry() {
    let packet = hex(RFC9001_RETRY);
    let Ok(Header::Retry(retry)) = Header::parse(&packet, 0) else {
        panic!("expected a Retry header");
    };
    assert_eq!(retry.version(), Version::V1);
    assert_eq!(retry.dcid(), b"");
    assert_eq!(retry.scid(), hex("f067a5502a4262b5"));
    assert_eq!(retry.token(), b"token");
    assert_eq!(
        retry.integrity_tag()[..],
        hex("04a265ba2eff4d829058fb3f0f2496ba")
    );
    assert_eq!(retry.packet_len(), packet.len());
}

#[test]
fn parses_version_negotiation_whatever_the_first_byte() {
    // Version 0; the 7 unused bits are arbitrary, the Fixed Bit included, as RFC 8999 allows.
    for first in [0x80, 0xbf, 0xff] {
        let mut packet = vec![first, 0, 0, 0, 0, 1, 0x11, 2, 0x22, 0x33];
        packet.extend_from_slice(&[0, 0, 0, 1, 0xfa, 0xce, 0xb0, 0x02, 0x1a, 0x2a, 0x3a, 0x4a]);
        let Ok(Header::VersionNegotiation(vn)) = Header::parse(&packet, 0) else {
            panic!("expected Version Negotiation");
        };
        assert_eq!(vn.dcid(), [0x11]);
        assert_eq!(vn.scid(), [0x22, 0x33]);
        let versions: Vec<Version> = vn.versions().collect();
        assert_eq!(
            versions,
            [Version::V1, Version::MVFST, Version(0x1a2a_3a4a)]
        );
        assert_eq!(vn.packet_len(), packet.len());
    }
}

#[test]
fn reads_only_invariant_fields_of_unsupported_versions() {
    // QUIC v2's version with 21- and 255-byte connection IDs and a clear Fixed Bit: the v1 rules
    // do not apply, so a server can still answer with Version Negotiation.
    let mut packet = vec![0x80, 0x6b, 0x33, 0x43, 0xcf, 21];
    packet.extend_from_slice(&[7; 21]);
    packet.push(255);
    packet.extend_from_slice(&[9; 255]);
    packet.extend_from_slice(&[0xee; 900]);
    let Ok(Header::UnsupportedVersion(header)) = Header::parse(&packet, 0) else {
        panic!("expected an unsupported version");
    };
    assert_eq!(header.version(), Version(0x6b33_43cf));
    assert_eq!(header.dcid(), [7; 21]);
    assert_eq!(header.scid(), [9; 255]);
    assert_eq!(header.packet_len(), packet.len());
}

#[test]
fn parses_short_headers_with_the_local_cid_length() {
    // RFC 9001 App. A.5: the smallest possible packet, 21 bytes with an empty DCID.
    let packet = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    let header = protected(&packet, 0);
    assert_eq!(header.ty(), PacketType::OneRtt);
    assert_eq!(header.version(), None);
    assert_eq!(header.dcid(), b"");
    assert_eq!(header.pn_offset(), 1);
    assert_eq!(header.packet_len(), 21);
    assert_eq!(header.sample_range(), 5..21);

    let mut packet = vec![0x40];
    packet.extend_from_slice(&[0xc1; 8]);
    packet.extend_from_slice(&[0; 30]);
    let header = protected(&packet, 8);
    assert_eq!(header.dcid(), [0xc1; 8]);
    assert_eq!(header.scid(), b"");
    assert_eq!(header.token(), b"");
    assert_eq!(header.pn_offset(), 9);
    assert_eq!(header.packet_len(), 39);
}

#[test]
fn rejects_a_clear_fixed_bit() {
    let mut initial = rfc9001_client_initial();
    initial[0] &= !0x40;
    assert_eq!(Header::parse(&initial, 0), Err(HeaderError::FixedBitZero));
    let short = [0x01; 40];
    assert_eq!(Header::parse(&short, 8), Err(HeaderError::FixedBitZero));
}

#[test]
fn rejects_packets_too_short_for_the_sample() {
    // A short header needs 4 + 16 bytes after the packet number offset.
    let short = [0x40; 1 + 8 + 19];
    assert_eq!(
        Header::parse(&short, 8),
        Err(HeaderError::TooShortForSample)
    );
    assert!(Header::parse(&[0x40; 1 + 8 + 20], 8).is_ok());
    // A long header's Length must cover the same 20 bytes.
    let mut handshake = vec![0xe0, 0, 0, 0, 1, 0, 0, 19];
    handshake.resize(8 + 19, 0);
    assert_eq!(
        Header::parse(&handshake, 0),
        Err(HeaderError::TooShortForSample)
    );
}

#[test]
fn rejects_v1_connection_ids_longer_than_twenty_bytes() {
    for (dcid_len, scid_len) in [(21, 0), (0, 21), (255, 20)] {
        let mut packet = vec![0xc0, 0, 0, 0, 1, dcid_len];
        packet.extend(std::iter::repeat_n(1, usize::from(dcid_len)));
        packet.push(scid_len);
        packet.extend(std::iter::repeat_n(2, usize::from(scid_len)));
        packet.extend_from_slice(&[0, 0x40, 30]);
        packet.resize(packet.len() + 30, 0);
        assert_eq!(Header::parse(&packet, 0), Err(HeaderError::CidTooLong));
    }
}

#[test]
fn rejects_a_length_beyond_the_datagram() {
    let mut initial = rfc9001_client_initial();
    initial.truncate(1199);
    assert_eq!(
        Header::parse(&initial, 0),
        Err(HeaderError::LengthBeyondDatagram)
    );
    // A Length near 2^62 must not overflow the bound check.
    let mut handshake = vec![0xe0, 0, 0, 0, 1, 0, 0];
    handshake.extend_from_slice(&[0xff; 8]);
    handshake.resize(64, 0);
    assert_eq!(
        Header::parse(&handshake, 0),
        Err(HeaderError::LengthBeyondDatagram)
    );
}

#[test]
fn rejects_version_negotiation_without_whole_versions() {
    let empty = [0x80, 0, 0, 0, 0, 0, 0];
    assert_eq!(Header::parse(&empty, 0), Err(HeaderError::BadVersionList));
    let truncated = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xfa, 0xce];
    assert_eq!(
        Header::parse(&truncated, 0),
        Err(HeaderError::BadVersionList)
    );
}

#[test]
fn rejects_retry_shorter_than_its_integrity_tag() {
    let mut retry = hex(RFC9001_RETRY);
    retry.truncate(retry.len() - 5 - 12);
    assert_eq!(Header::parse(&retry, 0), Err(HeaderError::RetryTooShort));
}

#[test]
fn truncated_headers_are_errors_not_panics() {
    let initial = rfc9001_client_initial();
    for len in 0..initial.len() {
        assert!(Header::parse(&initial[..len], 0).is_err(), "prefix {len}");
    }
    for len in 0..7 + 8 {
        assert_eq!(
            Header::parse(&hex(RFC9001_RETRY)[..len], 0),
            Err(HeaderError::UnexpectedEnd),
            "prefix {len}"
        );
    }
    assert_eq!(Header::parse(&[], 0), Err(HeaderError::UnexpectedEnd));
    assert_eq!(
        Header::parse(&[0x40; 8], 8),
        Err(HeaderError::UnexpectedEnd)
    );
}

#[test]
fn walks_coalesced_packets_with_their_offsets() {
    let mut datagram = rfc9001_client_initial();
    let mut handshake = vec![0xe0, 0, 0, 0, 1, 0, 0, 24];
    handshake.resize(8 + 24, 0x77);
    datagram.extend_from_slice(&handshake);
    datagram.extend_from_slice(&[0x40; 30]);
    let packets: Vec<_> = Packets::new(&datagram, 0)
        .map(|p| p.map(|(offset, header)| (offset, header.packet_len())))
        .collect();
    assert_eq!(packets, [Ok((0, 1200)), Ok((1200, 32)), Ok((1232, 30))]);
    let Some(Ok((_, Header::Protected(third)))) = Packets::new(&datagram, 0).nth(2) else {
        panic!("expected a short header third");
    };
    assert_eq!(third.ty(), PacketType::OneRtt);
}

#[test]
fn stops_at_the_first_malformed_packet() {
    let mut datagram = rfc9001_client_initial();
    datagram.extend_from_slice(&[0xe0, 0, 0, 0, 1, 0, 0, 0x40, 200, 0, 0]);
    let packets: Vec<_> = Packets::new(&datagram, 0)
        .map(|p| p.map(|(offset, _)| offset))
        .collect();
    assert_eq!(packets, [Ok(0), Err(HeaderError::LengthBeyondDatagram)]);
    // Zero bytes after the last packet are not a packet either.
    let mut padded = rfc9001_client_initial();
    padded.extend_from_slice(&[0; 3]);
    let packets: Vec<_> = Packets::new(&padded, 0).map(|p| p.is_ok()).collect();
    assert_eq!(packets, [true, false]);
    assert_eq!(Packets::new(&[], 0).count(), 0);
}

/// A small deterministic generator, so malformed-input tests are reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for i in 0..20_000 {
        let len = (rng.next() % 80) as usize;
        let mut datagram = rng.bytes(len);
        // Bias half the inputs toward plausible v1 long headers to reach the deeper fields.
        if i % 2 == 0 && len >= 7 {
            datagram[0] |= 0xc0;
            datagram[1..5].copy_from_slice(&[0, 0, 0, 1]);
            datagram[5] %= 24;
        }
        let cid_len = (rng.next() % 21) as usize;
        let mut covered = 0;
        for packet in Packets::new(&datagram, cid_len) {
            let Ok((offset, header)) = packet else { break };
            assert_eq!(offset, covered);
            covered += header.packet_len();
            assert!(covered <= datagram.len());
            if let Header::Protected(h) = header {
                assert!(h.sample_range().end <= h.packet_len());
            }
        }
    }
}

#[test]
fn encodes_the_rfc9001_retry() {
    let expected = hex(RFC9001_RETRY);
    let mut out = [0u8; 64];
    let scid = ConnectionId::new(&hex("f067a5502a4262b5")).unwrap();
    let len = encode_retry(
        &mut out,
        0x0f,
        Version::V1,
        &ConnectionId::EMPTY,
        &scid,
        b"token",
    );
    assert_eq!(len, Ok(expected.len() - RETRY_INTEGRITY_TAG_LEN));
    assert_eq!(out[..expected.len() - 16], expected[..expected.len() - 16]);
}

#[test]
fn version_negotiation_round_trips() {
    let dcid = [0xd1; 255];
    let versions = [Version::V1, Version::MVFST, Version(0x0a0a_0a0a)];
    let mut out = [0u8; 600];
    let len = encode_version_negotiation(&mut out, 0x2a, &dcid, &[5, 6], &versions).unwrap();
    assert_eq!(len, 7 + 255 + 2 + 12);
    assert_eq!(out[0], 0x80 | 0x40 | 0x2a);
    assert_eq!(out[1..5], [0; 4]);
    let Ok(Header::VersionNegotiation(vn)) = Header::parse(&out[..len], 0) else {
        panic!("expected Version Negotiation");
    };
    assert_eq!(vn.dcid(), dcid);
    assert_eq!(vn.scid(), [5, 6]);
    assert!(vn.versions().eq(versions));
}

#[test]
fn encoders_reject_bad_requests_without_writing() {
    let mut out = [0xaa_u8; 600];
    assert_eq!(
        encode_version_negotiation(&mut out, 0, &[1], &[2], &[]),
        Err(EncodeError::NoVersions)
    );
    assert_eq!(
        encode_version_negotiation(&mut out, 0, &[1; 256], &[2], &[Version::V1]),
        Err(EncodeError::CidTooLong)
    );
    assert_eq!(
        encode_version_negotiation(&mut out[..14], 0, &[1], &[2], &[Version::V1, Version::V1]),
        Err(EncodeError::BufferTooShort)
    );
    let scid = ConnectionId::new(&[3; 8]).unwrap();
    // 7 + 0 + 8 + 5 bytes of header and token, and 16 for the tag.
    assert_eq!(
        encode_retry(
            &mut out[..35],
            0,
            Version::V1,
            &ConnectionId::EMPTY,
            &scid,
            b"token"
        ),
        Err(EncodeError::BufferTooShort)
    );
    assert_eq!(out, [0xaa; 600]);
    assert_eq!(
        encode_retry(
            &mut out[..36],
            0,
            Version::V1,
            &ConnectionId::EMPTY,
            &scid,
            b"token"
        ),
        Ok(20)
    );
}
