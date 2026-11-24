/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Raw TLS 1.3 traffic secrets, as a TLS stack other than rustls hands them over.

use std::fmt;
use std::ptr;
use std::sync::atomic;
use std::sync::atomic::Ordering;

use crate::hkdf::SHA256_LEN;
use crate::hkdf::SHA384_LEN;
use crate::hkdf::expand_label;

/// The hash of the TLS 1.3 cipher suite that a traffic secret comes from. QUIC expands the secret
/// with HKDF over this hash, and the secret is one hash output long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretHash {
    /// SHA-256, the hash of TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256.
    Sha256,
    /// SHA-384, the hash of TLS_AES_256_GCM_SHA384.
    Sha384,
}

impl SecretHash {
    /// Returns the hash's output length, which is the length of its traffic secrets.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_LEN,
            Self::Sha384 => SHA384_LEN,
        }
    }
}

/// A traffic secret that is neither 32 nor 48 bytes long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretLengthError;

impl fmt::Display for SecretLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("traffic secret is neither 32 nor 48 bytes long")
    }
}

impl std::error::Error for SecretLengthError {}

/// A TLS 1.3 traffic secret: 32 bytes from a SHA-256 cipher suite or 48 bytes from a SHA-384 one.
/// Dropping it overwrites its bytes with zeros.
pub struct TrafficSecret {
    bytes: [u8; SHA384_LEN],
    hash: SecretHash,
}

impl TrafficSecret {
    /// Takes a copy of a traffic secret, whose length gives the hash of its cipher suite. Fails
    /// with [`SecretLengthError`] when it is neither 32 nor 48 bytes long.
    pub fn new(secret: &[u8]) -> Result<TrafficSecret, SecretLengthError> {
        let hash = match secret.len() {
            SHA256_LEN => SecretHash::Sha256,
            SHA384_LEN => SecretHash::Sha384,
            _ => return Err(SecretLengthError),
        };
        let mut bytes = [0; SHA384_LEN];
        bytes[..secret.len()].copy_from_slice(secret);
        Ok(TrafficSecret { bytes, hash })
    }

    /// Returns the hash of the secret's cipher suite.
    pub fn hash(&self) -> SecretHash {
        self.hash
    }

    /// Returns the secret.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.hash.output_len()]
    }

    /// Returns the secret of the next 1-RTT key phase: HKDF-Expand-Label of this one with the
    /// label "quic ku", one hash output long (RFC 9001).
    pub(crate) fn next(&self) -> TrafficSecret {
        let mut next = TrafficSecret {
            bytes: [0; SHA384_LEN],
            hash: self.hash,
        };
        let len = self.hash.output_len();
        // A secret and an output of at most 48 bytes and a fixed label always fit.
        expand_label(
            self.hash,
            self.as_bytes(),
            b"quic ku",
            &[],
            &mut next.bytes[..len],
        )
        .expect("the quic ku label fits");
        next
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: `byte` is a mutable reference into `self.bytes`, so it is valid, aligned and
            // unaliased for the write. A volatile write is not removed as a dead store.
            unsafe { ptr::write_volatile(byte, 0) };
        }
        // Keeps the compiler from moving later memory accesses before the zeroing.
        atomic::compiler_fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficSecret")
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn a_traffic_secret_is_32_or_48_bytes() {
        let sha256 = TrafficSecret::new(&[1; 32]).unwrap();
        assert_eq!(sha256.hash(), SecretHash::Sha256);
        assert_eq!(sha256.as_bytes(), [1; 32]);
        let sha384 = TrafficSecret::new(&[2; 48]).unwrap();
        assert_eq!(sha384.hash(), SecretHash::Sha384);
        assert_eq!(sha384.as_bytes(), [2; 48]);
        for len in [0, 16, 31, 33, 47, 49, 64] {
            let refused = TrafficSecret::new(&vec![3; len]);
            assert_eq!(refused.err(), Some(SecretLengthError), "{len} bytes");
        }
    }

    #[test]
    fn debug_output_leaves_the_secret_out() {
        let secret = TrafficSecret::new(&[0xa5; 32]).unwrap();
        let debug = format!("{secret:?}");
        assert!(debug.contains("Sha256"), "{debug}");
        assert!(!debug.contains("165"), "{debug}");
    }

    #[test]
    fn a_dropped_secret_leaves_zeros_behind() {
        for len in [SHA256_LEN, SHA384_LEN] {
            let mut secret = ManuallyDrop::new(TrafficSecret::new(&vec![0xa5; len]).unwrap());
            // SAFETY: `secret` is dropped once and not used as a `TrafficSecret` afterwards.
            // Dropping leaves the memory as the destructor wrote it, so `bytes` still holds
            // initialized bytes for the read below.
            unsafe { ManuallyDrop::drop(&mut secret) };
            assert_eq!(secret.bytes, [0; SHA384_LEN], "{len} bytes");
        }
    }

    /// The SHA-256 case is RFC 9001 Appendix A.5. RFC 9001 does not include a SHA-384 example, so
    /// those values were computed apart from both backends, with OpenSSL's HKDF over SHA-384.
    #[test]
    fn the_next_secret_is_quic_ku_one_hash_output_long() {
        let sha384_0 = concat!(
            "1472261c7cd018dd097853dd7555e9ce1f1fc8b1a72c8188",
            "c300e1746568c6801ec40349b6c2c84323cc7957bdf5d119",
        );
        let sha384_1 = concat!(
            "2d1ad7593c7d84694ceb8188d734a76a612801186fb1b54b",
            "7f10dd4a2b17afe78916c78f00b43035a16d93134766000f",
        );
        let sha384_2 = concat!(
            "afcf490e2856813df124446129be63caeaa58c71731b92cb",
            "4c674cf34e0bcc1d96993adea06d34b38ef47d359f9905ea",
        );
        let cases = [
            (
                "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
                "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
            ),
            (sha384_0, sha384_1),
            (sha384_1, sha384_2),
        ];
        for (secret, expected) in cases {
            let secret = TrafficSecret::new(&unhex(secret)).unwrap();
            let next = secret.next();
            assert_eq!(next.hash(), secret.hash());
            assert_eq!(hex(next.as_bytes()), expected);
        }
    }
}
