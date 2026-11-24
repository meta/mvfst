/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The crypto library behind packet protection, header protection, HKDF and the rustls
//! provider: aws-lc-rs when the `aws-lc-rs` feature is on, else ring when `ring` is on, else
//! mvfstr's own binding to the OpenSSL libcrypto an app already links (`crate::native`) when
//! `openssl` is on.
//!
//! The other modules reach the library only through the names re-exported here, whose APIs the
//! libraries share, so the choice is made at compile time.

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring", feature = "openssl")))]
compile_error!("mvfstr_crypto needs the `aws-lc-rs`, `ring` or `openssl` feature");

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as library;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as library;
#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs as provider;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use rustls::crypto::ring as provider;

pub(crate) use self::library::aead;
pub(crate) use self::library::digest;
pub(crate) use self::library::hkdf;
pub(crate) use self::library::hmac;
pub(crate) use self::provider::cipher_suite;
#[cfg(all(feature = "openssl", not(any(feature = "aws-lc-rs", feature = "ring"))))]
use crate::native as library;
#[cfg(all(feature = "openssl", not(any(feature = "aws-lc-rs", feature = "ring"))))]
use crate::native::provider;

/// Returns the default rustls `CryptoProvider` of the library that protects packets: aws-lc-rs
/// when the `aws-lc-rs` feature is on, as it is by default, even if another is on too, ring when
/// `ring` is on without it, and mvfstr's provider over OpenSSL when only `openssl` is on.
///
/// The aws-lc-rs provider offers the post-quantum X25519MLKEM768 key exchange first, and the
/// others do not have it. The cipher suites of the aws-lc-rs and ring providers are rustls's own,
/// which [`with_quic_suites`](crate::with_quic_suites) replaces with suites carrying mvfstr's
/// packet protection; the OpenSSL provider's suites already carry it.
pub fn default_provider() -> rustls::crypto::CryptoProvider {
    provider::default_provider()
}

#[cfg(test)]
mod tests {
    use rustls::CipherSuite;
    use rustls::NamedGroup;
    use rustls::crypto::CryptoProvider;

    use super::*;

    /// Returns a provider's cipher suites and key exchange groups, in its order of preference.
    fn suites_and_groups(provider: &CryptoProvider) -> (Vec<CipherSuite>, Vec<NamedGroup>) {
        (
            provider.cipher_suites.iter().map(|s| s.suite()).collect(),
            provider.kx_groups.iter().map(|g| g.name()).collect(),
        )
    }

    #[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
    #[test]
    fn aws_lc_rs_is_used_when_both_backends_are_built() {
        use std::any::TypeId;

        assert_eq!(
            TypeId::of::<aead::Algorithm>(),
            TypeId::of::<aws_lc_rs::aead::Algorithm>(),
            "packet protection runs on aws-lc-rs",
        );
        assert_ne!(
            TypeId::of::<aead::Algorithm>(),
            TypeId::of::<ring::aead::Algorithm>()
        );
        let provider = suites_and_groups(&default_provider());
        assert_eq!(
            provider,
            suites_and_groups(&rustls::crypto::aws_lc_rs::default_provider()),
            "the default provider is aws-lc-rs's",
        );
        assert_ne!(
            provider,
            suites_and_groups(&rustls::crypto::ring::default_provider())
        );
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn the_aws_lc_rs_provider_offers_post_quantum_key_exchange_first() {
        assert_eq!(
            suites_and_groups(&default_provider()).1.first(),
            Some(&NamedGroup::X25519MLKEM768)
        );
    }

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    #[test]
    fn ring_is_used_without_aws_lc_rs() {
        use std::any::TypeId;

        assert_eq!(
            TypeId::of::<aead::Algorithm>(),
            TypeId::of::<ring::aead::Algorithm>(),
            "packet protection runs on ring",
        );
        assert_eq!(
            suites_and_groups(&default_provider()),
            suites_and_groups(&rustls::crypto::ring::default_provider()),
            "the default provider is ring's",
        );
    }

    #[cfg(all(feature = "openssl", not(any(feature = "aws-lc-rs", feature = "ring"))))]
    #[test]
    fn openssl_is_used_without_aws_lc_rs_or_ring() {
        use std::any::TypeId;

        assert_eq!(
            TypeId::of::<aead::Algorithm>(),
            TypeId::of::<crate::native::aead::Algorithm>(),
            "packet protection runs on mvfstr's OpenSSL binding",
        );
        assert_eq!(
            suites_and_groups(&default_provider()).0,
            [
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ],
            "the default provider is mvfstr's OpenSSL provider",
        );
    }
}
