/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Packet protection and header protection with the shape of `ring::aead` and
//! `ring::aead::quic`, over `sys`.

use std::fmt;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use super::AeadAlg;
use super::Unspecified;
use super::sys;

/// The tag length of every AEAD here.
const TAG_LEN: usize = 16;

/// The nonce length of every AEAD here.
const NONCE_LEN: usize = 12;

/// An AEAD algorithm.
pub(crate) struct Algorithm {
    id: AeadAlg,
    name: &'static str,
}

impl Algorithm {
    /// Returns the key length in bytes.
    pub(crate) fn key_len(&self) -> usize {
        self.id.key_len()
    }

    /// Returns which AEAD this is.
    pub(super) fn id(&self) -> AeadAlg {
        self.id
    }
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// AES-128-GCM.
pub(crate) static AES_128_GCM: Algorithm = Algorithm {
    id: AeadAlg::Aes128Gcm,
    name: "AES_128_GCM",
};

/// AES-256-GCM.
pub(crate) static AES_256_GCM: Algorithm = Algorithm {
    id: AeadAlg::Aes256Gcm,
    name: "AES_256_GCM",
};

/// ChaCha20-Poly1305.
pub(crate) static CHACHA20_POLY1305: Algorithm = Algorithm {
    id: AeadAlg::ChaCha20Poly1305,
    name: "CHACHA20_POLY1305",
};

/// An AEAD key not yet wrapped for use.
pub(crate) struct UnboundKey {
    alg: &'static Algorithm,
    key: sys::AeadKey,
}

impl UnboundKey {
    /// Makes a key of `alg` from its bytes. Fails if their length is not the algorithm's key
    /// length.
    pub(crate) fn new(alg: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let key = sys::AeadKey::new(alg.id, key_bytes).ok_or(Unspecified)?;
        Ok(UnboundKey { alg, key })
    }
}

/// An AEAD key whose user makes sure each nonce seals once, as with ring's `LessSafeKey`.
///
/// The library context sits behind a mutex because sealing and opening change it while rustls
/// holds keys by shared reference. One thread drives a connection, so the lock is uncontended.
pub(crate) struct LessSafeKey {
    alg: &'static Algorithm,
    key: Mutex<sys::AeadKey>,
}

impl LessSafeKey {
    /// Wraps a key for sealing and opening.
    pub(crate) fn new(key: UnboundKey) -> Self {
        LessSafeKey {
            alg: key.alg,
            key: Mutex::new(key.key),
        }
    }

    /// Encrypts `in_out` in place and returns the tag.
    pub(crate) fn seal_in_place_separate_tag<A: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified> {
        let mut tag = [0; TAG_LEN];
        if !self.lock().seal(&nonce.0, aad.0.as_ref(), in_out, &mut tag) {
            return Err(Unspecified);
        }
        Ok(Tag(tag))
    }

    /// Authenticates and decrypts `in_out`, the ciphertext followed by its tag, and returns the
    /// plaintext. On failure the plaintext is zeroed, as ring does, so that it cannot be used.
    pub(crate) fn open_in_place<'a, A: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Unspecified> {
        let plain_len = in_out.len().checked_sub(TAG_LEN).ok_or(Unspecified)?;
        let (plain, tag) = in_out.split_at_mut(plain_len);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().map_err(|_| Unspecified)?;
        if !self.lock().open(&nonce.0, aad.0.as_ref(), plain, tag) {
            plain.fill(0);
            return Err(Unspecified);
        }
        Ok(plain)
    }

    /// Returns the key's algorithm.
    pub(crate) fn algorithm(&self) -> &'static Algorithm {
        self.alg
    }

    fn lock(&self) -> MutexGuard<'_, sys::AeadKey> {
        self.key.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A nonce that must be used only once with its key.
pub(crate) struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wraps `value`, which must be unique for the key.
    pub(crate) fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Nonce(value)
    }
}

/// Associated data.
pub(crate) struct Aad<A>(A);

impl<A> From<A> for Aad<A> {
    fn from(aad: A) -> Self {
        Aad(aad)
    }
}

/// An AEAD tag.
pub(crate) struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// QUIC header protection (RFC 9001), with the shape of `ring::aead::quic`.
pub(crate) mod quic {
    use std::sync::Mutex;
    use std::sync::PoisonError;

    use super::super::HeaderAlg;
    use super::super::Unspecified;
    use super::super::sys;

    /// The sample length of every header-protection cipher.
    const SAMPLE_LEN: usize = 16;

    /// The mask length: one byte for the first header byte, four for the packet number.
    const MASK_LEN: usize = 5;

    /// A header-protection cipher.
    pub(crate) struct Algorithm(HeaderAlg);

    /// AES-128 in ECB mode over one block.
    pub(crate) static AES_128: Algorithm = Algorithm(HeaderAlg::Aes128);

    /// AES-256 in ECB mode over one block.
    pub(crate) static AES_256: Algorithm = Algorithm(HeaderAlg::Aes256);

    /// ChaCha20 with the sample as its block counter and nonce.
    pub(crate) static CHACHA20: Algorithm = Algorithm(HeaderAlg::ChaCha20);

    /// A header-protection key. Like `LessSafeKey`, it locks its library context.
    pub(crate) struct HeaderProtectionKey {
        key: Mutex<sys::HeaderKey>,
    }

    impl HeaderProtectionKey {
        /// Makes a key of `algorithm`. Fails if `key_bytes` is not the algorithm's key length.
        pub(crate) fn new(
            algorithm: &'static Algorithm,
            key_bytes: &[u8],
        ) -> Result<Self, Unspecified> {
            let key = sys::HeaderKey::new(algorithm.0, key_bytes).ok_or(Unspecified)?;
            Ok(HeaderProtectionKey {
                key: Mutex::new(key),
            })
        }

        /// Returns the mask for a 16-byte ciphertext sample. Fails if `sample` has another
        /// length.
        pub(crate) fn new_mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Unspecified> {
            let sample: &[u8; SAMPLE_LEN] = sample.try_into().map_err(|_| Unspecified)?;
            self.key
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .mask(sample)
                .ok_or(Unspecified)
        }
    }

    #[cfg(test)]
    mod tests {
        use rustls::crypto::cipher::AeadKey;
        use rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384;
        use rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;

        use super::*;
        use crate::testdata::unhex;

        #[test]
        fn aes_256_masks_match_fips_197_c3() {
            // FIPS-197 C.3 encrypts 00112233..ff under the key 000102..1f to
            // 8ea2b7ca516745bfeafc49904b496089; the mask is its first five bytes.
            let key: Vec<u8> = (0..32).collect();
            let key = HeaderProtectionKey::new(&AES_256, &key).unwrap();
            let expected: [u8; MASK_LEN] = unhex("8ea2b7ca51").try_into().unwrap();
            assert_eq!(
                key.new_mask(&unhex("00112233445566778899aabbccddeeff")),
                Ok(expected)
            );
        }

        #[test]
        fn masks_of_the_32_byte_keys_match_rings() {
            let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0xa5);
            for (ours, suite) in [
                (&AES_256, TLS13_AES_256_GCM_SHA384),
                (&CHACHA20, TLS13_CHACHA20_POLY1305_SHA256),
            ] {
                let ours = HeaderProtectionKey::new(ours, &key).unwrap();
                let ring = suite
                    .tls13()
                    .and_then(|suite| suite.quic)
                    .unwrap()
                    .header_protection_key(AeadKey::from(key));
                for n in 0..8u8 {
                    let sample: [u8; SAMPLE_LEN] =
                        std::array::from_fn(|i| (i as u8).wrapping_add(n.wrapping_mul(71)));
                    let mask = ours.new_mask(&sample).unwrap();
                    // A short header with a four-byte packet number shows the low five bits of
                    // the first mask byte and all four packet number bytes.
                    let (mut first, mut packet_number) = (0x03, [0; 4]);
                    ring.encrypt_in_place(&sample, &mut first, &mut packet_number)
                        .unwrap();
                    assert_eq!(
                        (first ^ 0x03, packet_number),
                        (mask[0] & 0x1f, [mask[1], mask[2], mask[3], mask[4]]),
                        "{suite:?}, sample {n}"
                    );
                }
            }
        }
    }
}
