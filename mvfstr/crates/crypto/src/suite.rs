/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The bridge to rustls: `rustls::quic::Algorithm` for the mvfstr algorithms, TLS 1.3 cipher
//! suites that carry them, and the rewrite of a caller's `CryptoProvider` to use those suites.
//!
//! rustls runs the TLS 1.3 key schedule with the negotiated suite's hash, then hands each
//! traffic secret's key and IV to the suite's `quic` algorithm. With the suites here, every
//! Handshake and 1-RTT key (key updates included) is an mvfstr key.

use std::sync::Mutex;
use std::sync::PoisonError;

use rustls::CipherSuite;
use rustls::CipherSuiteCommon;
use rustls::SupportedCipherSuite;
use rustls::Tls13CipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::crypto::cipher::AeadKey;
use rustls::crypto::cipher::Iv;
use rustls::quic;

use crate::algorithm::AES_128_GCM;
use crate::algorithm::AES_256_GCM;
use crate::algorithm::CHACHA20_POLY1305;
use crate::algorithm::QuicAlgorithm;
use crate::header::AeadHeaderKey;
use crate::packet::AeadPacketKey;
use crate::packet::NONCE_LEN;

impl quic::Algorithm for QuicAlgorithm {
    // rustls derives keys of `aead_key_len()` bytes and IVs of `NONCE_LEN` bytes, so both
    // constructors succeed, and the trait cannot report a failure.
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        let iv: [u8; NONCE_LEN] = iv.as_ref().try_into().expect("rustls IVs are 12 bytes");
        Box::new(
            AeadPacketKey::new(self, key.as_ref(), iv).expect("rustls sizes keys by aead_key_len"),
        )
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AeadHeaderKey::new(self, key.as_ref()).expect("rustls sizes keys by aead_key_len"))
    }

    fn aead_key_len(&self) -> usize {
        self.key_len()
    }
}

/// Returns a copy of the TLS 1.3 suite `base` whose QUIC algorithm is `alg`. Everything TLS uses
/// (hash, HKDF, record AEAD) stays the base suite's.
///
/// This is a `const fn`, so the result can be a `static` built from a provider's suite statics.
/// It panics, at compile time in a `static`, if `base` is not a TLS 1.3 suite.
pub const fn derive_suite(
    base: SupportedCipherSuite,
    alg: &'static QuicAlgorithm,
) -> Tls13CipherSuite {
    let Some(base) = base.tls13() else {
        panic!("QUIC needs a TLS 1.3 cipher suite");
    };
    derive_tls13(base, alg)
}

const fn derive_tls13(base: &Tls13CipherSuite, alg: &'static QuicAlgorithm) -> Tls13CipherSuite {
    Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: base.hkdf_provider,
        aead_alg: base.aead_alg,
        quic: Some(alg),
    }
}

/// The TLS 1.3 suites of rustls's aws-lc-rs provider with mvfstr's QUIC algorithms.
pub mod cipher_suite {
    use rustls::Tls13CipherSuite;
    use rustls::crypto::aws_lc_rs::cipher_suite as aws_lc;

    use super::derive_suite;
    use crate::algorithm::AES_128_GCM;
    use crate::algorithm::AES_256_GCM;
    use crate::algorithm::CHACHA20_POLY1305;

    /// TLS_AES_128_GCM_SHA256 with mvfstr AES-128-GCM packet protection.
    pub static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite =
        derive_suite(aws_lc::TLS13_AES_128_GCM_SHA256, &AES_128_GCM);

    /// TLS_AES_256_GCM_SHA384 with mvfstr AES-256-GCM packet protection.
    pub static TLS13_AES_256_GCM_SHA384: Tls13CipherSuite =
        derive_suite(aws_lc::TLS13_AES_256_GCM_SHA384, &AES_256_GCM);

    /// TLS_CHACHA20_POLY1305_SHA256 with mvfstr ChaCha20-Poly1305 packet protection.
    pub static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite =
        derive_suite(aws_lc::TLS13_CHACHA20_POLY1305_SHA256, &CHACHA20_POLY1305);
}

/// Rewrites a provider so that every QUIC connection built from it protects packets with
/// mvfstr's keys.
///
/// Each TLS 1.3 suite whose AEAD mvfstr implements is replaced, in place, by a copy carrying
/// the mvfstr algorithm and the base suite's hash, HKDF and record AEAD (see
/// [`derive_suite`]); other suites, TLS 1.2 ones included, are dropped. Suites that already
/// carry an mvfstr algorithm, such as those of [`cipher_suite`], are kept. Key exchange,
/// signature verification, randomness and key loading stay the caller's.
pub fn with_quic_suites(provider: CryptoProvider) -> CryptoProvider {
    let cipher_suites = provider
        .cipher_suites
        .iter()
        .filter_map(|suite| suite.tls13())
        .filter_map(quic_suite)
        .map(SupportedCipherSuite::Tls13)
        .collect();
    CryptoProvider {
        cipher_suites,
        ..provider
    }
}

/// Returns the mvfstr algorithm a suite carries, or `None` if its QUIC algorithm is not mvfstr's.
pub fn quic_algorithm(suite: &Tls13CipherSuite) -> Option<&'static QuicAlgorithm> {
    let quic = suite.quic? as *const dyn quic::Algorithm;
    [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305]
        .into_iter()
        .find(|ours| std::ptr::addr_eq(quic, *ours as *const QuicAlgorithm))
}

/// Returns the mvfstr algorithm for a TLS 1.3 suite's AEAD.
fn algorithm_for(suite: CipherSuite) -> Option<&'static QuicAlgorithm> {
    match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(&AES_128_GCM),
        CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(&AES_256_GCM),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some(&CHACHA20_POLY1305),
        _ => None,
    }
}

/// Returns the suite to use in place of `base`, or `None` if mvfstr does not implement its AEAD.
fn quic_suite(base: &'static Tls13CipherSuite) -> Option<&'static Tls13CipherSuite> {
    let alg = algorithm_for(base.common.suite)?;
    if quic_algorithm(base).is_some_and(|quic| std::ptr::eq(quic, alg)) {
        return Some(base);
    }
    Some(derived_suite(base, alg))
}

/// Derives a suite from a provider's suite. rustls requires `&'static` suites, so each derived
/// suite is leaked, once per distinct base suite for the life of the process.
///
/// The base cannot be matched to the statics in [`cipher_suite`] by address: rustc gives the
/// suites inside rustls's default provider different addresses from rustls's public suite
/// statics, down to their HKDF and AEAD objects.
fn derived_suite(
    base: &'static Tls13CipherSuite,
    alg: &'static QuicAlgorithm,
) -> &'static Tls13CipherSuite {
    type Derived = Vec<(&'static Tls13CipherSuite, &'static Tls13CipherSuite)>;
    static DERIVED: Mutex<Derived> = Mutex::new(Vec::new());
    let mut derived = DERIVED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, ours)) = derived.iter().find(|(seen, _)| std::ptr::eq(*seen, base)) {
        return ours;
    }
    let ours: &'static Tls13CipherSuite = Box::leak(Box::new(derive_tls13(base, alg)));
    derived.push((base, ours));
    ours
}

#[cfg(test)]
mod tests {
    use mvfstr_wire::Side;
    use mvfstr_wire::Version;

    use super::*;
    use crate::initial::initial_keys;
    use crate::testdata::RFC9001_DCID;

    /// Seals a short packet with `tx` and opens it with `rx`.
    fn seal_open(tx: &dyn quic::PacketKey, rx: &dyn quic::PacketKey) -> Vec<u8> {
        let header = [0x41, 0xaa, 0xbb];
        let mut packet = b"mvfstr payload".to_vec();
        let tag = tx.encrypt_in_place(7, &header, &mut packet).unwrap();
        packet.extend_from_slice(tag.as_ref());
        let sealed = packet.clone();
        let plain = rx.decrypt_in_place(7, &header, &mut packet).unwrap();
        assert_eq!(plain, b"mvfstr payload");
        sealed
    }

    #[test]
    fn rustls_builds_mvfstr_keys_that_match_mvfstr_initial_keys() {
        let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        let rustls_keys = quic::Keys::initial(
            quic::Version::V1,
            suite,
            &AES_128_GCM,
            &RFC9001_DCID,
            rustls::Side::Client,
        );
        let ours = initial_keys(Version::V1, &RFC9001_DCID, Side::Server).unwrap();
        let sealed = seal_open(&*rustls_keys.local.packet, ours.remote.packet());
        let resealed = seal_open(ours.remote.packet(), &*rustls_keys.local.packet);
        assert_eq!(
            sealed, resealed,
            "both derivations give the same key and IV"
        );
        assert_eq!(rustls_keys.local.header.sample_len(), 16);
        let mut first = 0xc3;
        let mut pn = [0, 0, 0, 2];
        rustls_keys
            .local
            .header
            .encrypt_in_place(&[5; 16], &mut first, &mut pn)
            .unwrap();
        ours.remote
            .header()
            .decrypt_in_place(&[5; 16], &mut first, &mut pn)
            .unwrap();
        assert_eq!((first, pn), (0xc3, [0, 0, 0, 2]));
    }

    #[test]
    fn every_algorithm_reports_the_rfc9001_limits_on_its_keys() {
        use rustls::crypto::aws_lc_rs::cipher_suite as lc;
        let cases = [
            (lc::TLS13_AES_128_GCM_SHA256, &AES_128_GCM, 1 << 23, 1 << 52),
            (lc::TLS13_AES_256_GCM_SHA384, &AES_256_GCM, 1 << 23, 1 << 52),
            (
                lc::TLS13_CHACHA20_POLY1305_SHA256,
                &CHACHA20_POLY1305,
                u64::MAX,
                1 << 36,
            ),
        ];
        for (suite, alg, confidentiality, integrity) in cases {
            let suite = suite.tls13().unwrap();
            let keys = |side| quic::Keys::initial(quic::Version::V1, suite, alg, &[1; 8], side);
            let (client, server) = (keys(rustls::Side::Client), keys(rustls::Side::Server));
            seal_open(&*client.local.packet, &*server.remote.packet);
            seal_open(&*server.local.packet, &*client.remote.packet);
            for key in [&client.local.packet, &client.remote.packet] {
                assert_eq!(key.confidentiality_limit(), confidentiality, "{alg:?}");
                assert_eq!(key.integrity_limit(), integrity, "{alg:?}");
                assert_eq!(key.tag_len(), 16, "{alg:?}");
            }
            assert_eq!(client.local.header.sample_len(), 16, "{alg:?}");
        }
    }

    fn mvfstr_algorithm(suite: &Tls13CipherSuite) -> Option<&'static str> {
        quic_algorithm(suite).map(QuicAlgorithm::name)
    }

    #[test]
    fn the_aws_lc_provider_is_rewritten_to_mvfstr_suites_in_its_order() {
        let base = rustls::crypto::aws_lc_rs::default_provider();
        let base_suites: Vec<&'static Tls13CipherSuite> = base
            .cipher_suites
            .iter()
            .filter_map(|s| s.tls13())
            .collect();
        let (kx_groups, sig_schemes) = (
            base.kx_groups.len(),
            base.signature_verification_algorithms.supported_schemes(),
        );
        let rewritten = with_quic_suites(base);
        let suites: Vec<&'static Tls13CipherSuite> = rewritten
            .cipher_suites
            .iter()
            .map(|s| s.tls13().expect("only TLS 1.3 suites remain"))
            .collect();
        let names: Vec<_> = suites.iter().map(|s| mvfstr_algorithm(s)).collect();
        assert_eq!(
            names,
            [
                Some("AES-256-GCM"),
                Some("AES-128-GCM"),
                Some("ChaCha20-Poly1305")
            ]
        );
        assert_eq!(suites.len(), base_suites.len());
        for (suite, base) in suites.iter().zip(&base_suites) {
            assert_eq!(suite.common.suite, base.common.suite);
            assert!(std::ptr::addr_eq(suite.hkdf_provider, base.hkdf_provider));
            assert!(std::ptr::addr_eq(suite.aead_alg, base.aead_alg));
        }
        assert_eq!(rewritten.kx_groups.len(), kx_groups);
        assert_eq!(
            rewritten
                .signature_verification_algorithms
                .supported_schemes(),
            sig_schemes
        );

        // The static suites already carry mvfstr algorithms and pass through unchanged.
        let statics = [
            &cipher_suite::TLS13_AES_128_GCM_SHA256,
            &cipher_suite::TLS13_AES_256_GCM_SHA384,
            &cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        let provider = CryptoProvider {
            cipher_suites: statics
                .into_iter()
                .map(SupportedCipherSuite::Tls13)
                .collect(),
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let kept = with_quic_suites(provider);
        for (suite, expected) in kept.cipher_suites.iter().zip(statics) {
            assert!(std::ptr::eq(suite.tls13().unwrap(), expected));
        }
    }

    #[test]
    fn other_providers_suites_keep_their_tls_parts_and_are_derived_once() {
        let aws_lc_suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        // A suite of some other provider: its own static, without a QUIC algorithm.
        let foreign: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
            common: CipherSuiteCommon {
                confidentiality_limit: 12_345,
                ..aws_lc_suite.common
            },
            quic: None,
            ..*aws_lc_suite
        }));
        let provider = || CryptoProvider {
            cipher_suites: vec![SupportedCipherSuite::Tls13(foreign)],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let first = with_quic_suites(provider());
        let derived = first.cipher_suites[0].tls13().unwrap();
        assert_eq!(derived.common.suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(derived.common.confidentiality_limit, 12_345);
        assert_eq!(mvfstr_algorithm(derived), Some("AES-128-GCM"));

        let again = with_quic_suites(provider());
        assert!(std::ptr::eq(
            again.cipher_suites[0].tls13().unwrap(),
            derived
        ));
        let rewritten_twice = with_quic_suites(first);
        assert!(std::ptr::eq(
            rewritten_twice.cipher_suites[0].tls13().unwrap(),
            derived
        ));
    }
}
