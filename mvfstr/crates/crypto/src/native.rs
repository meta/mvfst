/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! mvfstr's own binding to a cryptography library that the app already links, so that a build
//! does not add a second one. The `openssl` feature binds the OpenSSL libcrypto that Fizz links.
//!
//! `aead`, `digest`, `hkdf` and `hmac` have ring's shape for exactly the part of ring's API the
//! rest of the crate uses, so `crate::backend` re-exports them in place of ring's modules.
//! `provider` is a rustls `CryptoProvider` on the same binding. All of them are safe Rust over
//! `sys`, the only module that calls the library: `sys_openssl` under `openssl`, over the raw
//! functions of openssl-sys.
//!
//! The enums here name the algorithms that callers request from `sys`; every library binding
//! takes the same enums.

pub(crate) mod aead;
pub(crate) mod digest;
pub(crate) mod hkdf;
pub(crate) mod hmac;
pub(crate) mod provider;
pub(crate) mod sys_openssl;

pub(crate) use sys_openssl as sys;

/// An AEAD of QUIC packet protection and TLS 1.3 records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    /// Returns the key length in bytes.
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

/// A QUIC header-protection cipher (RFC 9001).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderAlg {
    Aes128,
    Aes256,
    ChaCha20,
}

impl HeaderAlg {
    /// Returns the key length in bytes.
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
        }
    }
}

/// A hash of the TLS 1.3 key schedule, for digests and HMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    /// Returns the output length in bytes.
    pub(crate) const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// A key exchange group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KxGroupId {
    X25519,
    Secp256r1,
}

/// The kind of public key a signature is checked with, which fixes the curve or the padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigKind {
    EcP256,
    EcP384,
    RsaPkcs1,
    RsaPss,
    Ed25519,
}

/// The hash a signature is made over; `None` for Ed25519, which takes the message itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigHash {
    Sha256,
    Sha384,
    Sha512,
    None,
}

/// The error of every fallible shell operation. Like ring's `Unspecified`, it does not carry
/// details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unspecified;

#[cfg(test)]
mod tests {
    use super::sys;
    use crate::testdata::unhex;

    #[test]
    fn x25519_matches_rfc7748_section_6_1() {
        let alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let (alice, alice_public) =
            sys::KxKey::x25519_from_private(&alice.try_into().unwrap()).unwrap();
        let (bob, bob_public) = sys::KxKey::x25519_from_private(&bob.try_into().unwrap()).unwrap();
        assert_eq!(
            alice_public.to_vec(),
            unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public.to_vec(),
            unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(alice.agree(&bob_public).unwrap(), shared);
        assert_eq!(bob.agree(&alice_public).unwrap(), shared);
    }
}
