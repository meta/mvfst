/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Key material and the per-level key sets a connection holds (RFC 9001).

use std::fmt;
use std::sync::Arc;

use rustls::quic::HeaderProtectionKey;
use rustls::quic::PacketKey;

use crate::algorithm::MAX_KEY_LEN;
use crate::algorithm::QuicAlgorithm;
use crate::header::AeadHeaderKey;
use crate::hkdf::SHA256_LEN;
use crate::hkdf::hkdf_expand_label;
use crate::packet::AeadPacketKey;
use crate::packet::NONCE_LEN;

/// The AEAD key, IV and header-protection key derived from one traffic secret with the labels
/// "quic key", "quic iv" and "quic hp" (RFC 9001).
pub struct KeyMaterial {
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    iv: [u8; NONCE_LEN],
    hp: [u8; MAX_KEY_LEN],
}

impl KeyMaterial {
    /// Derives the material for `alg` from a traffic secret with HKDF-SHA256, the hash of the
    /// Initial secrets and of the SHA-256 cipher suites. The secret is therefore a SHA-256
    /// output; rustls derives the keys of SHA-384 suites itself.
    pub fn derive(alg: &QuicAlgorithm, secret: &[u8; SHA256_LEN]) -> KeyMaterial {
        let key_len = alg.key_len();
        let mut material = KeyMaterial {
            key: [0; MAX_KEY_LEN],
            key_len,
            iv: [0; NONCE_LEN],
            hp: [0; MAX_KEY_LEN],
        };
        // A 32-byte secret, fixed short labels and outputs of at most 32 bytes always fit
        // HKDF-Expand-Label.
        let expand = |label: &[u8], out: &mut [u8]| {
            hkdf_expand_label(secret, label, &[], out).expect("fixed QUIC labels fit")
        };
        expand(b"quic key", &mut material.key[..key_len]);
        expand(b"quic iv", &mut material.iv);
        expand(b"quic hp", &mut material.hp[..key_len]);
        material
    }

    /// Returns the AEAD key.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Returns the AEAD IV, which the packet number is XORed into to form the nonce.
    pub fn iv(&self) -> &[u8; NONCE_LEN] {
        &self.iv
    }

    /// Returns the header-protection key.
    pub fn hp(&self) -> &[u8] {
        &self.hp[..self.key_len]
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("key_len", &self.key_len)
            .finish_non_exhaustive()
    }
}

/// The keys that protect packets in one direction at one encryption level: the AEAD packet key
/// and the header-protection key.
///
/// The header-protection key is shared, because a key update replaces only the packet key.
pub struct PacketKeys {
    packet: Box<dyn PacketKey>,
    header: Arc<dyn HeaderProtectionKey>,
}

impl PacketKeys {
    /// Pairs a packet key with the header-protection key of the same level and direction.
    pub fn new(packet: Box<dyn PacketKey>, header: Box<dyn HeaderProtectionKey>) -> PacketKeys {
        PacketKeys::with_shared_header(packet, Arc::from(header))
    }

    /// Pairs a packet key with a header-protection key shared with other key phases of the
    /// same level and direction.
    pub fn with_shared_header(
        packet: Box<dyn PacketKey>,
        header: Arc<dyn HeaderProtectionKey>,
    ) -> PacketKeys {
        PacketKeys { packet, header }
    }

    /// Derives the keys of `alg` from a SHA-256 traffic secret with HKDF-SHA256 (RFC 9001).
    pub fn from_secret(alg: &QuicAlgorithm, secret: &[u8; SHA256_LEN]) -> PacketKeys {
        let material = KeyMaterial::derive(alg, secret);
        // `KeyMaterial::derive` produces keys of exactly `alg`'s length.
        let packet = AeadPacketKey::new(alg, material.key(), *material.iv())
            .expect("derived key has the algorithm's length");
        let header =
            AeadHeaderKey::new(alg, material.hp()).expect("derived key has the algorithm's length");
        PacketKeys::new(Box::new(packet), Box::new(header))
    }

    /// Takes over the keys rustls built for one direction of one encryption level.
    pub fn from_rustls(keys: rustls::quic::DirectionalKeys) -> PacketKeys {
        PacketKeys::new(keys.packet, keys.header)
    }

    /// Returns the AEAD packet key.
    pub fn packet(&self) -> &dyn PacketKey {
        &*self.packet
    }

    /// Returns the header-protection key.
    pub fn header(&self) -> &dyn HeaderProtectionKey {
        &*self.header
    }

    /// Returns the AEAD tag length.
    pub fn tag_len(&self) -> usize {
        self.packet.tag_len()
    }

    /// Returns the number of packets the packet key may seal (RFC 9001).
    pub fn confidentiality_limit(&self) -> u64 {
        self.packet.confidentiality_limit()
    }

    /// Returns the number of packets that may fail to open in the connection (RFC 9001).
    pub fn integrity_limit(&self) -> u64 {
        self.packet.integrity_limit()
    }
}

impl fmt::Debug for PacketKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketKeys")
            .field("tag_len", &self.packet.tag_len())
            .finish_non_exhaustive()
    }
}

/// The keys of one encryption level in both directions.
///
/// The local keys are behind an `Arc` because a [`SealJob`](crate::SealJob) borrows them and a
/// deferring sealer may hold them until it seals.
#[derive(Debug)]
pub struct KeySet {
    /// The keys protecting packets this endpoint sends.
    pub local: Arc<PacketKeys>,
    /// The keys protecting packets the peer sends.
    pub remote: PacketKeys,
}

impl KeySet {
    /// Takes over the keys rustls built for one encryption level.
    pub fn from_rustls(keys: rustls::quic::Keys) -> KeySet {
        KeySet {
            local: Arc::new(PacketKeys::from_rustls(keys.local)),
            remote: PacketKeys::from_rustls(keys.remote),
        }
    }
}

/// A 1-RTT key updater: it derives the keys of later key phases (RFC 9001).
///
/// Built from the `Secrets` rustls returns with the 1-RTT keys. Each call to
/// [`next_keys`](Self::next_keys) advances both directions one generation through rustls's "quic
/// ku" derivation, with the keys built by the mvfstr algorithm; the header-protection keys
/// stay those of the first 1-RTT keys.
pub struct KeyUpdater {
    // Boxed because the secrets are about 200 bytes and every key change from TLS would otherwise
    // be as large as the 1-RTT one, which carries the updater.
    secrets: Box<rustls::quic::Secrets>,
    local_header: Arc<dyn HeaderProtectionKey>,
    remote_header: Arc<dyn HeaderProtectionKey>,
}

impl KeyUpdater {
    /// Wraps the secrets of rustls's 1-RTT key change; `current` is the key set that came with
    /// them.
    pub fn new(secrets: rustls::quic::Secrets, current: &KeySet) -> KeyUpdater {
        KeyUpdater {
            secrets: Box::new(secrets),
            local_header: current.local.header.clone(),
            remote_header: current.remote.header.clone(),
        }
    }

    /// Derives the keys of the next key phase, in both directions, and moves the updater to it.
    pub fn next_keys(&mut self) -> KeySet {
        let next = self.secrets.next_packet_keys();
        KeySet {
            local: Arc::new(PacketKeys::with_shared_header(
                next.local,
                self.local_header.clone(),
            )),
            remote: PacketKeys::with_shared_header(next.remote, self.remote_header.clone()),
        }
    }
}

impl fmt::Debug for KeyUpdater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyUpdater").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AES_128_GCM;
    use crate::algorithm::CHACHA20_POLY1305;
    use crate::backend::cipher_suite as rustls_suite;
    use crate::header::unprotect_header;
    use crate::packet::TAG_LEN;
    use crate::seal::InlineSealer;
    use crate::seal::SealJob;
    use crate::seal::Sealer;
    use crate::seal::SlotId;
    use crate::testdata::A2_PACKET;
    use crate::testdata::A3_HEADER;
    use crate::testdata::A3_PACKET;
    use crate::testdata::A3_PAYLOAD;
    use crate::testdata::RFC9001_DCID;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn rustls_keys_become_a_key_set_with_the_same_directions() {
        let keys = rustls::quic::Keys::initial(
            rustls::quic::Version::V1,
            rustls_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
            &AES_128_GCM,
            &RFC9001_DCID,
            rustls::Side::Server,
        );
        let set = KeySet::from_rustls(keys);
        let header = unhex(A3_HEADER);
        let mut slot = [header.clone(), unhex(A3_PAYLOAD), vec![0; TAG_LEN]].concat();
        let job = SealJob {
            slot: SlotId(0),
            keys: &set.local,
            pn: 1,
            hdr_len: header.len() as u16,
            len: slot.len() as u16,
        };
        InlineSealer.seal(job, &mut slot).unwrap();
        assert_eq!(hex(&slot), hex(&unhex(A3_PACKET)));

        let mut a2 = unhex(A2_PACKET);
        let pn_len = unprotect_header(set.remote.header(), &mut a2, 18).unwrap();
        let (header, payload) = a2.split_at_mut(18 + pn_len);
        assert!(
            set.remote
                .packet()
                .decrypt_in_place(2, header, payload)
                .is_ok()
        );
    }

    #[test]
    fn material_matches_rfc9001_a1_and_a5() {
        let cases = [
            // A.1 client and server Initial secrets (AES-128-GCM).
            (
                &AES_128_GCM,
                "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
                "1f369613dd76d5467730efcbe3b1a22d",
                "fa044b2f42a3fd3b46fb255c",
                "9f50449e04a0e810283a1e9933adedd2",
            ),
            (
                &AES_128_GCM,
                "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
                "cf3a5331653c364c88f0f379b6067e37",
                "0ac1493ca1905853b0bba03e",
                "c206b8d9b9f0f37644430b490eeaa314",
            ),
            // A.5 ChaCha20-Poly1305 1-RTT secret.
            (
                &CHACHA20_POLY1305,
                "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
                "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
                "e0459b3474bdd0e44a41c144",
                "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
            ),
        ];
        for (alg, secret, key, iv, hp) in cases {
            let secret = unhex(secret).try_into().unwrap();
            let material = KeyMaterial::derive(alg, &secret);
            assert_eq!(material.key(), unhex(key), "{alg:?} key");
            assert_eq!(material.iv().to_vec(), unhex(iv), "{alg:?} iv");
            assert_eq!(material.hp(), unhex(hp), "{alg:?} hp");
        }
    }
}
