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
use crate::header::SAMPLE_LEN;
use crate::hkdf::SHA256_LEN;
use crate::hkdf::expand_label;
use crate::packet::AeadPacketKey;
use crate::packet::NONCE_LEN;
use crate::packet::TAG_LEN;
use crate::secrets::SecretHash;
use crate::secrets::TrafficSecret;

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
    /// output; [`PacketKeys::from_traffic_secret`] also takes SHA-384 secrets.
    pub fn derive(alg: &QuicAlgorithm, secret: &[u8; SHA256_LEN]) -> KeyMaterial {
        KeyMaterial::expand(alg, SecretHash::Sha256, secret)
    }

    /// Derives the material for `alg` from a raw traffic secret, with HKDF over its hash.
    fn from_traffic_secret(alg: &QuicAlgorithm, secret: &TrafficSecret) -> KeyMaterial {
        KeyMaterial::expand(alg, secret.hash(), secret.as_bytes())
    }

    fn expand(alg: &QuicAlgorithm, hash: SecretHash, secret: &[u8]) -> KeyMaterial {
        let key_len = alg.key_len();
        let mut material = KeyMaterial {
            key: [0; MAX_KEY_LEN],
            key_len,
            iv: [0; NONCE_LEN],
            hp: [0; MAX_KEY_LEN],
        };
        // A secret of at most 48 bytes, fixed short labels and outputs of at most 32 bytes always
        // fit HKDF-Expand-Label.
        let expand = |label: &[u8], out: &mut [u8]| {
            expand_label(hash, secret, label, &[], out).expect("fixed QUIC labels fit")
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

/// Keys from rustls whose AEAD tag or header-protection sample is not 16 bytes. Every QUIC v1
/// cipher suite uses 16 bytes for both, and mvfstr seals and protects headers with those lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedKeyError;

impl fmt::Display for UnsupportedKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("keys without a 16-byte AEAD tag and header-protection sample")
    }
}

impl std::error::Error for UnsupportedKeyError {}

/// The keys that protect packets in one direction at one encryption level: the AEAD packet key
/// and the header-protection key.
///
/// The header-protection key is shared, because a key update replaces only the packet key.
/// Sealing and header protection use the 16-byte tag and sample of every QUIC v1 cipher suite, not
/// the lengths the keys report; [`from_rustls`](Self::from_rustls) refuses keys that report others.
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
        PacketKeys::from_material(alg, &KeyMaterial::derive(alg, secret))
    }

    /// Derives the keys of `alg` from a raw traffic secret, with HKDF over its hash (RFC 9001).
    /// This is the form for keys that protect one direction only, such as 0-RTT keys.
    pub fn from_traffic_secret(alg: &QuicAlgorithm, secret: &TrafficSecret) -> PacketKeys {
        PacketKeys::from_material(alg, &KeyMaterial::from_traffic_secret(alg, secret))
    }

    fn from_material(alg: &QuicAlgorithm, material: &KeyMaterial) -> PacketKeys {
        // `KeyMaterial` holds keys of exactly `alg`'s length.
        let header =
            AeadHeaderKey::new(alg, material.hp()).expect("derived key has the algorithm's length");
        let keys = PacketKeys::new(Box::new(aead_packet_key(alg, material)), Box::new(header));
        debug_assert!(
            keys.has_quic_lengths(),
            "derived keys use 16-byte tags and samples"
        );
        keys
    }

    /// Takes over the keys rustls built for one direction of one encryption level. Fails with
    /// [`UnsupportedKeyError`] when the AEAD tag or the header-protection sample of the keys is
    /// not 16 bytes.
    pub fn from_rustls(
        keys: rustls::quic::DirectionalKeys,
    ) -> Result<PacketKeys, UnsupportedKeyError> {
        let keys = PacketKeys::new(keys.packet, keys.header);
        if !keys.has_quic_lengths() {
            return Err(UnsupportedKeyError);
        }
        Ok(keys)
    }

    /// Returns whether the keys report the 16-byte tag and sample that sealing and header
    /// protection use.
    fn has_quic_lengths(&self) -> bool {
        self.packet.tag_len() == TAG_LEN && self.header.sample_len() == SAMPLE_LEN
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

/// Builds the packet key of `alg` from material derived for it.
fn aead_packet_key(alg: &QuicAlgorithm, material: &KeyMaterial) -> AeadPacketKey {
    // `KeyMaterial` holds keys of exactly `alg`'s length.
    AeadPacketKey::new(alg, material.key(), *material.iv())
        .expect("derived key has the algorithm's length")
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
    /// Takes over the keys rustls built for one encryption level. Fails as
    /// [`PacketKeys::from_rustls`] does for either direction.
    pub fn from_rustls(keys: rustls::quic::Keys) -> Result<KeySet, UnsupportedKeyError> {
        Ok(KeySet {
            local: Arc::new(PacketKeys::from_rustls(keys.local)?),
            remote: PacketKeys::from_rustls(keys.remote)?,
        })
    }

    /// Derives the keys of one encryption level from its raw traffic secrets: `local` protects the
    /// packets this endpoint sends and `remote` those the peer sends. Each secret is expanded with
    /// the hash of its cipher suite (RFC 9001).
    pub fn from_secrets(
        alg: &QuicAlgorithm,
        local: &TrafficSecret,
        remote: &TrafficSecret,
    ) -> KeySet {
        KeySet {
            local: Arc::new(PacketKeys::from_traffic_secret(alg, local)),
            remote: PacketKeys::from_traffic_secret(alg, remote),
        }
    }
}

/// A 1-RTT key updater: it derives the keys of later key phases (RFC 9001).
///
/// Each call to [`next_keys`](Self::next_keys) advances the secrets of both directions one
/// generation with the "quic ku" derivation and builds their packet keys with the mvfstr
/// algorithm; the header-protection keys stay those of the first 1-RTT keys. The secrets are
/// either the `Secrets` rustls returns with the 1-RTT keys or raw traffic secrets.
pub struct KeyUpdater {
    // Boxed because the secrets are about 200 bytes and every key change from TLS would otherwise
    // be as large as the 1-RTT one, which carries the updater.
    secrets: Box<UpdateSecrets>,
    local_header: Arc<dyn HeaderProtectionKey>,
    remote_header: Arc<dyn HeaderProtectionKey>,
}

/// The secrets a [`KeyUpdater`] advances.
enum UpdateSecrets {
    /// rustls's secrets, which are already those of the next key phase.
    Rustls(rustls::quic::Secrets),
    /// The raw secrets of the current key phase and the algorithm of their keys.
    Raw {
        alg: &'static QuicAlgorithm,
        local: TrafficSecret,
        remote: TrafficSecret,
    },
}

impl KeyUpdater {
    /// Wraps the secrets of rustls's 1-RTT key change; `current` is the key set that came with
    /// them.
    pub fn new(secrets: rustls::quic::Secrets, current: &KeySet) -> KeyUpdater {
        KeyUpdater::with_secrets(UpdateSecrets::Rustls(secrets), current)
    }

    /// Takes over the raw 1-RTT traffic secrets that `current` was derived from with
    /// [`KeySet::from_secrets`]: `local` protects the packets this endpoint sends and `remote`
    /// those the peer sends.
    pub fn from_secrets(
        alg: &'static QuicAlgorithm,
        local: TrafficSecret,
        remote: TrafficSecret,
        current: &KeySet,
    ) -> KeyUpdater {
        KeyUpdater::with_secrets(UpdateSecrets::Raw { alg, local, remote }, current)
    }

    fn with_secrets(secrets: UpdateSecrets, current: &KeySet) -> KeyUpdater {
        KeyUpdater {
            secrets: Box::new(secrets),
            local_header: current.local.header.clone(),
            remote_header: current.remote.header.clone(),
        }
    }

    /// Derives the keys of the next key phase, in both directions, and moves the updater to it.
    pub fn next_keys(&mut self) -> KeySet {
        let (local, remote) = match &mut *self.secrets {
            UpdateSecrets::Rustls(secrets) => {
                let next = secrets.next_packet_keys();
                (next.local, next.remote)
            }
            UpdateSecrets::Raw { alg, local, remote } => {
                *local = local.next();
                *remote = remote.next();
                let key = |secret| -> Box<dyn PacketKey> {
                    let material = KeyMaterial::from_traffic_secret(alg, secret);
                    Box::new(aead_packet_key(alg, &material))
                };
                (key(local), key(remote))
            }
        };
        let next = KeySet {
            local: Arc::new(PacketKeys::with_shared_header(
                local,
                self.local_header.clone(),
            )),
            remote: PacketKeys::with_shared_header(remote, self.remote_header.clone()),
        };
        debug_assert!(
            next.local.has_quic_lengths() && next.remote.has_quic_lengths(),
            "a key update keeps the 16-byte tag and sample of the first 1-RTT keys"
        );
        next
    }
}

impl fmt::Debug for KeyUpdater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyUpdater").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use rustls::CipherSuite;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::ServerName;
    use rustls::pki_types::UnixTime;
    use rustls::quic;
    use rustls::time_provider::TimeProvider;

    use super::*;
    use crate::algorithm::AES_128_GCM;
    use crate::algorithm::AES_256_GCM;
    use crate::algorithm::CHACHA20_POLY1305;
    use crate::backend::cipher_suite as rustls_suite;
    use crate::backend::default_provider;
    use crate::header::SAMPLE_LEN;
    use crate::header::protect_header;
    use crate::header::unprotect_header;
    use crate::packet::TAG_LEN;
    use crate::seal::InlineSealer;
    use crate::seal::SealJob;
    use crate::seal::Sealer;
    use crate::seal::SlotId;
    use crate::suite::with_quic_suites;
    use crate::testdata::A2_CRYPTO;
    use crate::testdata::A2_HEADER;
    use crate::testdata::A2_PACKET;
    use crate::testdata::A3_HEADER;
    use crate::testdata::A3_PACKET;
    use crate::testdata::A3_PAYLOAD;
    use crate::testdata::A4_RETRY;
    use crate::testdata::RFC9001_DCID;
    use crate::testdata::TEST_CERT;
    use crate::testdata::TEST_KEY;
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
        let set = KeySet::from_rustls(keys).unwrap();
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

    /// A packet key that reports `tag_len` as its tag length and otherwise seals and opens as
    /// `inner` does.
    struct TagLenDouble {
        inner: Box<dyn PacketKey>,
        tag_len: usize,
    }

    impl PacketKey for TagLenDouble {
        fn encrypt_in_place(
            &self,
            packet_number: u64,
            header: &[u8],
            payload: &mut [u8],
        ) -> Result<quic::Tag, rustls::Error> {
            self.inner.encrypt_in_place(packet_number, header, payload)
        }

        fn decrypt_in_place<'a>(
            &self,
            packet_number: u64,
            header: &[u8],
            payload: &'a mut [u8],
        ) -> Result<&'a [u8], rustls::Error> {
            self.inner.decrypt_in_place(packet_number, header, payload)
        }

        fn tag_len(&self) -> usize {
            self.tag_len
        }

        fn confidentiality_limit(&self) -> u64 {
            self.inner.confidentiality_limit()
        }

        fn integrity_limit(&self) -> u64 {
            self.inner.integrity_limit()
        }
    }

    /// A header-protection key that reports `sample_len` as its sample length and otherwise masks
    /// as `inner` does.
    struct SampleLenDouble {
        inner: Box<dyn HeaderProtectionKey>,
        sample_len: usize,
    }

    impl HeaderProtectionKey for SampleLenDouble {
        fn encrypt_in_place(
            &self,
            sample: &[u8],
            first: &mut u8,
            packet_number: &mut [u8],
        ) -> Result<(), rustls::Error> {
            self.inner.encrypt_in_place(sample, first, packet_number)
        }

        fn decrypt_in_place(
            &self,
            sample: &[u8],
            first: &mut u8,
            packet_number: &mut [u8],
        ) -> Result<(), rustls::Error> {
            self.inner.decrypt_in_place(sample, first, packet_number)
        }

        fn sample_len(&self) -> usize {
            self.sample_len
        }
    }

    /// Returns whether rustls's server Initial keys of RFC 9001 Appendix A install after `alter`
    /// changed one direction: as packet keys, and as a key set with the change in its local or in
    /// its remote direction.
    fn installs(alter: impl Fn(quic::DirectionalKeys) -> quic::DirectionalKeys) -> [bool; 3] {
        let initial = || {
            quic::Keys::initial(
                quic::Version::V1,
                rustls_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
                &AES_128_GCM,
                &RFC9001_DCID,
                rustls::Side::Server,
            )
        };
        let alone = PacketKeys::from_rustls(alter(initial().local));
        let (keys, other) = (initial(), initial());
        let local = KeySet::from_rustls(quic::Keys {
            local: alter(keys.local),
            remote: keys.remote,
        });
        let remote = KeySet::from_rustls(quic::Keys {
            local: other.local,
            remote: alter(other.remote),
        });
        [alone.is_ok(), local.is_ok(), remote.is_ok()]
    }

    #[test]
    fn rustls_keys_with_a_12_byte_tag_are_refused_at_install() {
        let tag_len = |tag_len| {
            move |keys: quic::DirectionalKeys| quic::DirectionalKeys {
                packet: Box::new(TagLenDouble {
                    inner: keys.packet,
                    tag_len,
                }),
                header: keys.header,
            }
        };
        assert_eq!(installs(tag_len(TAG_LEN)), [true; 3], "16-byte tags");
        assert_eq!(installs(tag_len(12)), [false; 3], "12-byte tags");
    }

    #[test]
    fn rustls_keys_with_a_sample_other_than_16_bytes_are_refused_at_install() {
        let sample_len = |sample_len| {
            move |keys: quic::DirectionalKeys| quic::DirectionalKeys {
                packet: keys.packet,
                header: Box::new(SampleLenDouble {
                    inner: keys.header,
                    sample_len,
                }),
            }
        };
        assert_eq!(
            installs(sample_len(SAMPLE_LEN)),
            [true; 3],
            "16-byte samples"
        );
        for len in [12, 20] {
            assert_eq!(installs(sample_len(len)), [false; 3], "{len}-byte samples");
        }
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

    fn secret(hex: &str) -> TrafficSecret {
        TrafficSecret::new(&unhex(hex)).unwrap()
    }

    /// Seals a packet with `keys`, header protection included. The packet number length is in the
    /// low two bits of the header's first byte.
    fn seal(keys: &PacketKeys, pn: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut packet = [header, payload].concat();
        let tag = keys
            .packet()
            .encrypt_in_place(pn, header, &mut packet[header.len()..]);
        packet.extend_from_slice(tag.unwrap().as_ref());
        let pn_len = usize::from(header[0] & 0x03) + 1;
        protect_header(keys.header(), &mut packet, header.len() - pn_len).unwrap();
        packet
    }

    /// RFC 9001 Appendix A, with key sets built from raw secrets: the Initial secrets of A.1 seal
    /// the server Initial of A.3 and open the client Initial of A.2, RFC 9001's Retry secret gives
    /// the tag of A.4, and the secret of A.5 seals its ChaCha20-Poly1305 short-header packet.
    #[test]
    fn key_sets_from_secrets_reproduce_rfc9001_appendix_a() {
        let client_in = secret("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let server_in = secret("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
        let server = KeySet::from_secrets(&AES_128_GCM, &server_in, &client_in);
        let a3 = seal(&server.local, 1, &unhex(A3_HEADER), &unhex(A3_PAYLOAD));
        assert_eq!(hex(&a3), hex(&unhex(A3_PACKET)));

        let mut a2 = unhex(A2_PACKET);
        let pn_len = unprotect_header(server.remote.header(), &mut a2, 18).unwrap();
        let (header, payload) = a2.split_at_mut(18 + pn_len);
        assert_eq!(hex(header), A2_HEADER);
        let plain = server.remote.packet().decrypt_in_place(2, header, payload);
        let mut crypto = unhex(A2_CRYPTO);
        crypto.resize(1162, 0);
        assert_eq!(plain.unwrap(), crypto);

        // The Retry tag is the AEAD tag of an empty plaintext under packet number 0, with the
        // original Destination Connection ID, length-prefixed, and the Retry packet as the
        // associated data.
        let retry_secret =
            secret("d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e");
        let retry = KeySet::from_secrets(&AES_128_GCM, &retry_secret, &retry_secret);
        let a4 = unhex(A4_RETRY);
        let (packet, tag) = a4.split_at(a4.len() - TAG_LEN);
        let pseudo = [&[RFC9001_DCID.len() as u8][..], &RFC9001_DCID, packet].concat();
        let sealed = retry.local.packet().encrypt_in_place(0, &pseudo, &mut []);
        assert_eq!(hex(sealed.unwrap().as_ref()), hex(tag));

        let one_rtt = secret("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let a5 = KeySet::from_secrets(&CHACHA20_POLY1305, &one_rtt, &one_rtt);
        let mut packet = seal(&a5.local, 654_360_564, &unhex("4200bff4"), &[0x01]);
        assert_eq!(hex(&packet), "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        assert_eq!(unprotect_header(a5.remote.header(), &mut packet, 1), Ok(3));
        let (header, payload) = packet.split_at_mut(4);
        let plain = a5
            .remote
            .packet()
            .decrypt_in_place(654_360_564, header, payload);
        assert_eq!(plain.unwrap(), [0x01]);
    }

    /// RFC 9001 does not include a SHA-384 example, so these values were computed apart from both
    /// backends, with OpenSSL's HKDF over SHA-384.
    #[test]
    fn sha384_secrets_expand_with_hkdf_sha384() {
        let secret = secret(concat!(
            "1472261c7cd018dd097853dd7555e9ce1f1fc8b1a72c8188",
            "c300e1746568c6801ec40349b6c2c84323cc7957bdf5d119",
        ));
        let (key, iv, hp) = (
            "8a295b286b4bbbc9e04902b900dee1038c1cf51a378654173aefece3896d9061",
            "6498fbe4e166cc6d60aea773",
            "f95c4182d74ea34bfdb0e799b3f5e1d725c6b3b6e8a51ff3ce98180b6fe48c4a",
        );
        let material = KeyMaterial::from_traffic_secret(&AES_256_GCM, &secret);
        assert_eq!(hex(material.key()), key);
        assert_eq!(hex(material.iv()), iv);
        assert_eq!(hex(material.hp()), hp);

        let keys = KeySet::from_secrets(&AES_256_GCM, &secret, &secret);
        let packet = AeadPacketKey::new(&AES_256_GCM, &unhex(key), unhex(iv).try_into().unwrap());
        let header = AeadHeaderKey::new(&AES_256_GCM, &unhex(hp));
        let pinned = PacketKeys::new(Box::new(packet.unwrap()), Box::new(header.unwrap()));
        let (header, payload) = (unhex("41d1d1d1d10007"), [0x42; 24]);
        assert_eq!(
            hex(&seal(&keys.local, 7, &header, &payload)),
            hex(&seal(&pinned, 7, &header, &payload))
        );
    }

    /// A fixed clock for the rustls handshake, 2026-09-21.
    #[derive(Debug)]
    struct FixedTime;

    impl TimeProvider for FixedTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(
                1_790_000_000,
            )))
        }
    }

    /// The secrets rustls logs, by label.
    #[derive(Debug, Default)]
    struct SecretLog(Mutex<Vec<(String, Vec<u8>)>>);

    impl rustls::KeyLog for SecretLog {
        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            let entry = (label.to_string(), secret.to_vec());
            self.0.lock().unwrap().push(entry);
        }
    }

    impl SecretLog {
        fn secret(&self, label: &str) -> TrafficSecret {
            let entries = self.0.lock().unwrap();
            let (_, secret) = entries.iter().find(|(logged, _)| logged == label).unwrap();
            TrafficSecret::new(secret).unwrap()
        }
    }

    /// The client's end of a finished rustls handshake: the 1-RTT keys and `Secrets` rustls
    /// returned, and the 1-RTT traffic secrets it logged.
    struct ClientOneRtt {
        keys: quic::Keys,
        next: quic::Secrets,
        local: TrafficSecret,
        remote: TrafficSecret,
    }

    /// Passes the handshake bytes `from` writes to `to`, one encryption level per read as rustls
    /// requires, and returns the 1-RTT key change of `from` if it made one.
    fn deliver(
        from: &mut quic::Connection,
        to: &mut quic::Connection,
    ) -> Option<(quic::Keys, quic::Secrets)> {
        let mut one_rtt = None;
        loop {
            let mut level = Vec::new();
            let change = from.write_hs(&mut level);
            to.read_hs(&level).unwrap();
            match change {
                None => return one_rtt,
                Some(quic::KeyChange::OneRtt { keys, next }) => one_rtt = Some((keys, next)),
                Some(quic::KeyChange::Handshake { .. }) => {}
            }
        }
    }

    /// Runs an in-memory rustls QUIC handshake with one TLS 1.3 cipher suite and mvfstr's packet
    /// protection.
    fn rustls_handshake(suite: CipherSuite) -> ClientOneRtt {
        let mut provider = with_quic_suites(default_provider());
        provider.cipher_suites.retain(|s| s.suite() == suite);
        let provider = Arc::new(provider);
        let time: Arc<dyn TimeProvider> = Arc::new(FixedTime);
        let tls13 = &[&rustls::version::TLS13];
        let cert = CertificateDer::from(unhex(TEST_CERT));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_details(provider.clone(), time.clone())
            .with_protocol_versions(tls13)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let log = Arc::new(SecretLog::default());
        client.key_log = log.clone();
        let key = PrivatePkcs8KeyDer::from(unhex(TEST_KEY));
        let server = rustls::ServerConfig::builder_with_details(server_provider(provider), time)
            .with_protocol_versions(tls13)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .unwrap();

        let name = ServerName::try_from("localhost").unwrap();
        let version = quic::Version::V1;
        let client = quic::ClientConnection::new(Arc::new(client), version, name, Vec::new());
        let server = quic::ServerConnection::new(Arc::new(server), version, Vec::new());
        let mut client = quic::Connection::Client(client.unwrap());
        let mut server = quic::Connection::Server(server.unwrap());
        let mut one_rtt = None;
        for _ in 0..3 {
            one_rtt = one_rtt.or(deliver(&mut client, &mut server));
            deliver(&mut server, &mut client);
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let (keys, next) = one_rtt.unwrap();
        ClientOneRtt {
            keys,
            next,
            local: log.secret("CLIENT_TRAFFIC_SECRET_0"),
            remote: log.secret("SERVER_TRAFFIC_SECRET_0"),
        }
    }

    /// Returns the server's provider for [`rustls_handshake`]: `provider` itself on aws-lc-rs
    /// and ring.
    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    fn server_provider(provider: Arc<CryptoProvider>) -> Arc<CryptoProvider> {
        provider
    }

    /// Returns the server's provider for [`rustls_handshake`]: `provider` with ring's key loading,
    /// because the provider over an app's library does not load private keys.
    #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
    fn server_provider(provider: Arc<CryptoProvider>) -> Arc<CryptoProvider> {
        Arc::new(CryptoProvider {
            key_provider: rustls::crypto::ring::default_provider().key_provider,
            ..CryptoProvider::clone(&provider)
        })
    }

    /// Seals a fixed short-header packet with `keys`, as hex.
    fn sealed(keys: &PacketKeys) -> String {
        let header = [0x41, 0xd1, 0xd1, 0xd1, 0xd1, 0x00, 0x05];
        hex(&seal(keys, 5, &header, &[0x42; 32]))
    }

    #[test]
    fn raw_secrets_seal_as_rustls_keys_do_over_three_key_updates() {
        let suites = [
            (CipherSuite::TLS13_AES_128_GCM_SHA256, &AES_128_GCM),
            (
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                &CHACHA20_POLY1305,
            ),
            (CipherSuite::TLS13_AES_256_GCM_SHA384, &AES_256_GCM),
        ];
        for (suite, alg) in suites {
            let handshake = rustls_handshake(suite);
            let theirs = KeySet::from_rustls(handshake.keys).unwrap();
            let ours = KeySet::from_secrets(alg, &handshake.local, &handshake.remote);
            assert_eq!(sealed(&ours.local), sealed(&theirs.local), "{alg:?}");
            assert_eq!(sealed(&ours.remote), sealed(&theirs.remote), "{alg:?}");

            let mut their_updater = KeyUpdater::new(handshake.next, &theirs);
            let mut our_updater =
                KeyUpdater::from_secrets(alg, handshake.local, handshake.remote, &ours);
            for generation in 1..=3 {
                let (theirs, ours) = (their_updater.next_keys(), our_updater.next_keys());
                let context = format!("{alg:?} generation {generation}");
                assert_eq!(sealed(&ours.local), sealed(&theirs.local), "{context}");
                assert_eq!(sealed(&ours.remote), sealed(&theirs.remote), "{context}");
            }
        }
    }
}
