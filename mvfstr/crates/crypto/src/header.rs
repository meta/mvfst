/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC header protection (RFC 9001).

use std::fmt;

use rustls::quic::HeaderProtectionKey;

use crate::algorithm::KeyLengthError;
use crate::algorithm::QuicAlgorithm;
use crate::backend::aead;

/// The ciphertext sample length of every QUIC header-protection cipher.
pub const SAMPLE_LEN: usize = 16;

/// The header-protection mask length: one byte for the first header byte, four for the packet
/// number.
pub const MASK_LEN: usize = 5;

/// The longest packet number field, in bytes (RFC 9000).
const MAX_PN_LEN: usize = 4;

/// A header-protection key: AES-ECB for the AES suites, raw ChaCha20 for ChaCha20-Poly1305
/// (RFC 9001).
pub struct AeadHeaderKey {
    key: aead::quic::HeaderProtectionKey,
}

impl AeadHeaderKey {
    /// Builds the header-protection key of `alg` from its key bytes. Fails with [`KeyLengthError`]
    /// when the length of `key` does not match `alg`.
    pub fn new(alg: &QuicAlgorithm, key: &[u8]) -> Result<AeadHeaderKey, KeyLengthError> {
        let key =
            aead::quic::HeaderProtectionKey::new(alg.header, key).map_err(|_| KeyLengthError)?;
        Ok(AeadHeaderKey { key })
    }

    /// Computes the mask for a ciphertext sample, which must be [`SAMPLE_LEN`] bytes.
    pub fn mask(&self, sample: &[u8]) -> Option<[u8; MASK_LEN]> {
        self.key.new_mask(sample).ok()
    }
}

/// Whether header protection is being applied or removed, which decides where the packet number
/// length is read from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Protect,
    Unprotect,
}

impl AeadHeaderKey {
    /// XORs the mask into the low bits of the first byte (4 for a long header, 5 for a short one)
    /// and into the packet number bytes, as RFC 9001 specifies. `packet_number` may extend past
    /// the packet number field, up to four bytes; only the field is masked.
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        direction: Direction,
    ) -> Result<(), rustls::Error> {
        if packet_number.len() > MAX_PN_LEN {
            return Err(rustls::Error::General(
                "packet number field too long".into(),
            ));
        }
        let mask = self
            .mask(sample)
            .ok_or_else(|| rustls::Error::General("header protection sample length".into()))?;
        let first_bits = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
        let plain_first = match direction {
            Direction::Protect => *first,
            Direction::Unprotect => *first ^ (mask[0] & first_bits),
        };
        let pn_len = usize::from(plain_first & 0x03) + 1;
        if packet_number.len() < pn_len {
            return Err(rustls::Error::General(
                "packet number field truncated".into(),
            ));
        }
        *first ^= mask[0] & first_bits;
        for (byte, m) in packet_number[..pn_len].iter_mut().zip(&mask[1..]) {
            *byte ^= m;
        }
        Ok(())
    }
}

impl HeaderProtectionKey for AeadHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.xor_in_place(sample, first, packet_number, Direction::Protect)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.xor_in_place(sample, first, packet_number, Direction::Unprotect)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

/// Why header protection could not be applied or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderProtectionError {
    /// The packet number would start at the first byte, or the packet is too short to hold a
    /// full sample, which starts four bytes after the packet number offset.
    TooShort,
    /// The key rejected the sample or the packet number.
    Key,
}

impl fmt::Display for HeaderProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "packet too short for header protection",
            Self::Key => "header protection key rejected the packet",
        })
    }
}

impl std::error::Error for HeaderProtectionError {}

/// Applies header protection to the packet in `packet`, whose packet number starts at
/// `pn_offset` and whose payload is already sealed.
///
/// The packet number length comes from the unprotected first byte. Fails with
/// [`HeaderProtectionError`], leaving the packet unchanged, when `pn_offset` is 0, when the packet
/// is too short for the sample, or when the key returns an error.
pub fn protect_header(
    key: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
) -> Result<(), HeaderProtectionError> {
    let (first, packet_number, sample) = split_for_header_protection(key, packet, pn_offset)?;
    key.encrypt_in_place(sample, first, packet_number)
        .map_err(|_| HeaderProtectionError::Key)
}

/// Removes header protection from the packet in `packet`, whose packet number starts at
/// `pn_offset`, and returns the packet number length.
///
/// The packet number length is read from the first byte once it is unmasked, so the caller
/// does not pass it. Fails with [`HeaderProtectionError`], leaving the packet unchanged, when
/// `pn_offset` is 0, when the packet is too short for the sample, or when the key returns an error.
pub fn unprotect_header(
    key: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
) -> Result<usize, HeaderProtectionError> {
    let (first, packet_number, sample) = split_for_header_protection(key, packet, pn_offset)?;
    key.decrypt_in_place(sample, first, packet_number)
        .map_err(|_| HeaderProtectionError::Key)?;
    Ok(usize::from(*first & 0x03) + 1)
}

/// Splits a packet into its first byte, the four bytes from the packet number offset, and the
/// sample that starts after them.
fn split_for_header_protection<'a>(
    key: &dyn HeaderProtectionKey,
    packet: &'a mut [u8],
    pn_offset: usize,
) -> Result<(&'a mut u8, &'a mut [u8], &'a [u8]), HeaderProtectionError> {
    let sample_end = pn_offset
        .checked_add(MAX_PN_LEN + key.sample_len())
        .ok_or(HeaderProtectionError::TooShort)?;
    if pn_offset == 0 || packet.len() < sample_end {
        return Err(HeaderProtectionError::TooShort);
    }
    let (first, rest) = packet.split_at_mut(1);
    let (packet_number, rest) = rest[pn_offset - 1..].split_at_mut(MAX_PN_LEN);
    Ok((&mut first[0], packet_number, &rest[..key.sample_len()]))
}

impl fmt::Debug for AeadHeaderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadHeaderKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AES_128_GCM;
    use crate::algorithm::CHACHA20_POLY1305;
    use crate::testdata::A2_HEADER;
    use crate::testdata::A2_PACKET;
    use crate::testdata::A3_HEADER;
    use crate::testdata::A3_PACKET;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn masks_match_rfc9001_a2_a3_and_a5() {
        let cases = [
            (
                &AES_128_GCM,
                "9f50449e04a0e810283a1e9933adedd2",
                "d1b1c98dd7689fb8ec11d242b123dc9b",
                "437b9aec36",
            ),
            (
                &AES_128_GCM,
                "c206b8d9b9f0f37644430b490eeaa314",
                "2cd0991cd25b0aac406a5816b6394100",
                "2ec0d8356a",
            ),
            (
                &CHACHA20_POLY1305,
                "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                "5e5cd55c41f69080575d7999c25a5bfb",
                "aefefe7d03",
            ),
        ];
        for (alg, hp, sample, mask) in cases {
            let key = AeadHeaderKey::new(alg, &unhex(hp)).unwrap();
            assert_eq!(
                key.mask(&unhex(sample)).unwrap().to_vec(),
                unhex(mask),
                "{alg:?}"
            );
        }
    }

    /// Replaces the protected header at the front of an RFC packet with its unprotected form,
    /// leaving the sealed payload.
    fn with_unprotected_header(packet: &str, header: &str) -> Vec<u8> {
        let mut out = unhex(packet);
        let header = unhex(header);
        out[..header.len()].copy_from_slice(&header);
        out
    }

    #[test]
    fn protect_masks_long_and_short_headers_as_rfc9001_a2_a3_and_a5() {
        let cases = [
            // Long header, 4-byte packet number: 4 bits of the first byte are masked.
            (
                &AES_128_GCM,
                "9f50449e04a0e810283a1e9933adedd2",
                A2_PACKET,
                A2_HEADER,
            ),
            // Long header, 2-byte packet number.
            (
                &AES_128_GCM,
                "c206b8d9b9f0f37644430b490eeaa314",
                A3_PACKET,
                A3_HEADER,
            ),
            // Short header, 3-byte packet number: 5 bits of the first byte are masked.
            (
                &CHACHA20_POLY1305,
                "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
                "4200bff4",
            ),
        ];
        for (alg, hp, protected, header) in cases {
            let key = AeadHeaderKey::new(alg, &unhex(hp)).unwrap();
            let mut packet = with_unprotected_header(protected, header);
            let pn_len = usize::from(packet[0] & 0x03) + 1;
            let pn_offset = unhex(header).len() - pn_len;
            protect_header(&key, &mut packet, pn_offset).unwrap();
            let expected = unhex(protected);
            let header_len = pn_offset + pn_len;
            assert_eq!(
                hex(&packet[..header_len]),
                hex(&expected[..header_len]),
                "{alg:?}"
            );
            assert_eq!(packet, expected, "{alg:?} {header}");
        }
    }

    #[test]
    fn unprotect_reads_the_packet_number_length_from_the_unmasked_first_byte() {
        let cases = [
            (
                &AES_128_GCM,
                "9f50449e04a0e810283a1e9933adedd2",
                A2_PACKET,
                A2_HEADER,
            ),
            (
                &AES_128_GCM,
                "c206b8d9b9f0f37644430b490eeaa314",
                A3_PACKET,
                A3_HEADER,
            ),
            (
                &CHACHA20_POLY1305,
                "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
                "4200bff4",
            ),
        ];
        for (alg, hp, protected, header) in cases {
            let key = AeadHeaderKey::new(alg, &unhex(hp)).unwrap();
            let header = unhex(header);
            let expected_pn_len = usize::from(header[0] & 0x03) + 1;
            let pn_offset = header.len() - expected_pn_len;
            let mut packet = unhex(protected);
            let pn_len = unprotect_header(&key, &mut packet, pn_offset).unwrap();
            assert_eq!(pn_len, expected_pn_len, "{alg:?}");
            assert_eq!(hex(&packet[..header.len()]), hex(&header), "{alg:?}");
            assert_eq!(packet[header.len()..], unhex(protected)[header.len()..]);
        }
    }

    #[test]
    fn packets_without_a_full_sample_are_refused_unchanged() {
        let key = AeadHeaderKey::new(&AES_128_GCM, &[1; 16]).unwrap();
        // A short header with an 8-byte connection ID: the packet number starts at byte 9 and
        // the sample covers bytes 13..29.
        let pn_offset = 9;
        let original: Vec<u8> = (0..28u8).map(|b| b | 0x40).collect();
        for len in [0, 1, pn_offset, pn_offset + 4, 28] {
            let mut packet = original[..len].to_vec();
            assert_eq!(
                protect_header(&key, &mut packet, pn_offset),
                Err(HeaderProtectionError::TooShort),
                "protect, {len} bytes"
            );
            assert_eq!(
                unprotect_header(&key, &mut packet, pn_offset),
                Err(HeaderProtectionError::TooShort),
                "unprotect, {len} bytes"
            );
            assert_eq!(packet, original[..len], "{len} bytes");
        }
        let mut packet = original.clone();
        packet.push(0);
        assert_eq!(
            protect_header(&key, &mut packet, 0),
            Err(HeaderProtectionError::TooShort),
            "the packet number cannot start at the first byte"
        );
        assert_eq!(
            protect_header(&key, &mut packet, usize::MAX),
            Err(HeaderProtectionError::TooShort)
        );
        assert_eq!(packet[..28], original[..]);
    }

    #[test]
    fn packet_number_slices_longer_than_four_bytes_are_refused_unchanged() {
        let key = AeadHeaderKey::new(&AES_128_GCM, &[1; 16]).unwrap();
        let sample = [2; SAMPLE_LEN];
        let pn = [0x10, 0x20, 0x30, 0x40, 0x50];
        for (name, apply) in [
            (
                "protect",
                AeadHeaderKey::encrypt_in_place as fn(&_, &_, &mut _, &mut _) -> _,
            ),
            ("unprotect", AeadHeaderKey::decrypt_in_place),
        ] {
            let (mut first, mut packet_number) = (0xc3, pn);
            assert!(
                apply(&key, &sample, &mut first, &mut packet_number).is_err(),
                "{name}"
            );
            assert_eq!((first, packet_number), (0xc3, pn), "{name}");
            assert!(
                apply(&key, &sample, &mut first, &mut packet_number[..4]).is_ok(),
                "{name}"
            );
        }
    }
}
