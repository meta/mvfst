/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A rustls `CryptoProvider` over `sys`, with the shape of `rustls::crypto::ring` for the part
//! the crate uses: [`default_provider`] and [`cipher_suite`].
//!
//! It has ring's three TLS 1.3 suites in ring's order, X25519 then secp256r1, the signature
//! verification algorithms of rustls's ring provider within ring's limits, the library's random
//! number generator, and a key provider that refuses every key, for clients that do not offer a
//! certificate.

mod aead;
mod hash;
mod hmac;
mod kx;
mod sig;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use rustls::Error;
use rustls::crypto::CryptoProvider;
use rustls::crypto::GetRandomFailed;
use rustls::crypto::KeyProvider;
use rustls::crypto::SecureRandom;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;

use super::sys;

/// Returns the provider: the suites of [`cipher_suite`], the groups of [`kx_group`], the
/// signature verification algorithms, random bytes and a key provider that refuses every key.
pub(crate) fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![kx_group::X25519, kx_group::SECP256R1],
        signature_verification_algorithms: sig::SUPPORTED_SIG_ALGS,
        secure_random: &Library,
        key_provider: &Library,
    }
}

/// The TLS 1.3 cipher suites.
///
/// Each one already carries mvfstr's QUIC algorithm, so `crate::with_quic_suites` keeps it as it
/// is rather than deriving a copy.
pub(crate) mod cipher_suite {
    use rustls::CipherSuite;
    use rustls::CipherSuiteCommon;
    use rustls::SupportedCipherSuite;
    use rustls::Tls13CipherSuite;
    use rustls::crypto::tls13::HkdfUsingHmac;

    use super::aead;
    use super::hash;
    use super::hmac;
    use crate::algorithm;

    // Named statics rather than promoted constants, so that every suite derived from these at
    // compile time points at the same objects.
    static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&hmac::HMAC_SHA256);
    static HKDF_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(&hmac::HMAC_SHA384);

    /// TLS_AES_128_GCM_SHA256.
    pub(crate) static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: 1 << 24,
            },
            hkdf_provider: &HKDF_SHA256,
            aead_alg: &aead::AES_128_GCM,
            quic: Some(&algorithm::AES_128_GCM),
        });

    /// TLS_AES_256_GCM_SHA384.
    pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &hash::SHA384,
                confidentiality_limit: 1 << 24,
            },
            hkdf_provider: &HKDF_SHA384,
            aead_alg: &aead::AES_256_GCM,
            quic: Some(&algorithm::AES_256_GCM),
        });

    /// TLS_CHACHA20_POLY1305_SHA256.
    pub(crate) static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &HKDF_SHA256,
            aead_alg: &aead::CHACHA20_POLY1305,
            quic: Some(&algorithm::CHACHA20_POLY1305),
        });
}

/// The key exchange groups.
pub(crate) mod kx_group {
    pub(crate) use super::kx::SECP256R1;
    pub(crate) use super::kx::X25519;
}

/// The library's random number generator, and a key provider that refuses every key.
#[derive(Debug)]
struct Library;

impl SecureRandom for Library {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        sys::fill_random(buf).then_some(()).ok_or(GetRandomFailed)
    }
}

impl KeyProvider for Library {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "mvfstr's provider loads no private keys".into(),
        ))
    }
}
