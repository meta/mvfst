/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC packet protection with an AEAD (RFC 9001).

use std::fmt;

use aws_lc_rs::aead;
use rustls::quic::PacketKey;
use rustls::quic::Tag;

use crate::algorithm::KeyLengthError;
use crate::algorithm::QuicAlgorithm;

/// The AEAD nonce and IV length of every QUIC AEAD.
pub const NONCE_LEN: usize = 12;

/// The AEAD tag length of every QUIC AEAD.
pub const TAG_LEN: usize = 16;

/// A packet-protection key over aws-lc-rs: the AEAD key and IV of one key generation in one
/// direction, with the algorithm's usage limits.
pub struct AeadPacketKey {
    key: aead::LessSafeKey,
    iv: [u8; NONCE_LEN],
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl AeadPacketKey {
    /// Builds a key of `alg` from its AEAD key and IV. Fails with [`KeyLengthError`] when the
    /// length of `key` does not match `alg`.
    pub fn new(
        alg: &QuicAlgorithm,
        key: &[u8],
        iv: [u8; NONCE_LEN],
    ) -> Result<AeadPacketKey, KeyLengthError> {
        let key = aead::UnboundKey::new(alg.aead, key).map_err(|_| KeyLengthError)?;
        Ok(AeadPacketKey {
            key: aead::LessSafeKey::new(key),
            iv,
            confidentiality_limit: alg.confidentiality_limit(),
            integrity_limit: alg.integrity_limit(),
        })
    }

    /// Computes the nonce for a packet number: the IV XORed with the packet number, big-endian and
    /// left-padded to the IV length (RFC 9001).
    fn nonce(&self, packet_number: u64) -> aead::Nonce {
        let mut nonce = self.iv;
        for (byte, pn) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(packet_number.to_be_bytes())
        {
            *byte ^= pn;
        }
        aead::Nonce::assume_unique_for_key(nonce)
    }
}

impl PacketKey for AeadPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, rustls::Error> {
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(packet_number), aead::Aad::from(header), payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        // Every QUIC AEAD has a 16-byte tag, the length `Tag::from` requires.
        Ok(Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        let plain = self
            .key
            .open_in_place(self.nonce(packet_number), aead::Aad::from(header), payload)
            .map_err(|_| rustls::Error::DecryptError)?;
        Ok(plain)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

impl fmt::Debug for AeadPacketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadPacketKey")
            .field("algorithm", &self.key.algorithm())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::CHACHA20_POLY1305;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn chacha20_seal_and_open_match_rfc9001_a5() {
        let key = unhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
        let iv = unhex("e0459b3474bdd0e44a41c144").try_into().unwrap();
        let key = AeadPacketKey::new(&CHACHA20_POLY1305, &key, iv).unwrap();
        let header = unhex("4200bff4");
        let mut payload = vec![0x01];
        let tag = key
            .encrypt_in_place(654_360_564, &header, &mut payload)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        assert_eq!(hex(&payload), "655e5cd55c41f69080575d7999c25a5bfb");
        let sealed = payload.clone();
        let plain = key
            .decrypt_in_place(654_360_564, &header, &mut payload)
            .unwrap();
        assert_eq!(plain, [0x01]);

        // A changed ciphertext, header or packet number fails authentication.
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        let mut other_header = header.clone();
        other_header[1] ^= 1;
        let attempts = [
            (654_360_564, header.as_slice(), tampered),
            (654_360_564, other_header.as_slice(), sealed.clone()),
            (654_360_565, header.as_slice(), sealed.clone()),
        ];
        for (pn, header, mut packet) in attempts {
            assert!(matches!(
                key.decrypt_in_place(pn, header, &mut packet),
                Err(rustls::Error::DecryptError)
            ));
        }
    }
}
