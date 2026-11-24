/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! TLS 1.3 CertificateVerify signatures, checked with the end-entity certificate's key.

use rustls::DigitallySignedStruct;
use rustls::Error;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::CertificateDer;

/// Checks a TLS 1.3 CertificateVerify signature with the key of the end-entity certificate `cert`.
///
/// `algorithms` maps `dss.scheme` to the algorithm that checks it, as in a rustls
/// `CryptoProvider`; any provider's algorithms work.
///
/// Under the `aws-lc-rs` and `ring` features this calls `rustls::crypto::verify_tls13_signature`,
/// so the results are its results. Under `openssl` it parses the certificate with OpenSSL instead
/// of rustls-webpki, with this contract:
/// - on every case of this module's tests, the result equals that of
///   `rustls::crypto::verify_tls13_signature` with the algorithms of rustls's ring provider: the
///   same `Ok`, or the same error;
/// - on any input, it returns `Ok` only for a signature that verifies under the certificate's own
///   key, with the scheme's algorithm and, for this crate's algorithms, ring's limits;
/// - it takes only the SubjectPublicKeyInfo from the certificate, so elsewhere it can differ from
///   rustls in two ways. It can give a different error for a certificate both reject. And it can
///   accept a certificate that rustls-webpki rejects for a reason unrelated to the key, such as a
///   v1 or v2 certificate, or one with an unknown critical extension, which OpenSSL parses. That
///   is harmless where rustls has already run the certificate verifier on the chain.
pub fn verify_tls13_certificate_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algorithms: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    {
        rustls::crypto::verify_tls13_signature(message, cert, dss, algorithms)
    }
    #[cfg(all(feature = "openssl", not(any(feature = "aws-lc-rs", feature = "ring"))))]
    {
        native::verify(message, cert, dss, algorithms)
    }
}

/// The steps of `rustls::crypto::verify_tls13_signature` and rustls-webpki's `verify_signature`,
/// in their order, over the library's certificate parser.
#[cfg(all(feature = "openssl", not(any(feature = "aws-lc-rs", feature = "ring"))))]
mod native {
    use rustls::CertificateError;
    use rustls::DigitallySignedStruct;
    use rustls::Error;
    use rustls::PeerMisbehaved;
    use rustls::SignatureScheme;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::SignatureVerificationAlgorithm;

    use crate::native::sys;
    use crate::spki;

    pub(super) fn verify(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        algorithms: &WebPkiSupportedAlgorithms,
    ) -> Result<HandshakeSignatureValid, Error> {
        let alg = algorithm(dss.scheme, algorithms)
            .ok_or(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;
        let bad_encoding = || Error::InvalidCertificate(CertificateError::BadEncoding);
        let spki = sys::cert_spki(cert.as_ref()).ok_or_else(bad_encoding)?;
        let (alg_id, key) = spki::split(&spki).ok_or_else(bad_encoding)?;
        if alg_id != alg.public_key_alg_id().as_ref() {
            return Err(
                CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                    signature_algorithm_id: alg.signature_alg_id().as_ref().to_vec(),
                    public_key_algorithm_id: alg_id.to_vec(),
                }
                .into(),
            );
        }
        alg.verify_signature(key, message, dss.signature())
            .map_err(|_| CertificateError::BadSignature)?;
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Returns the first algorithm of the first mapping entry for `scheme`, if TLS 1.3 allows the
    /// scheme.
    fn algorithm(
        scheme: SignatureScheme,
        algorithms: &WebPkiSupportedAlgorithms,
    ) -> Option<&'static dyn SignatureVerificationAlgorithm> {
        if !allowed_in_tls13(scheme) {
            return None;
        }
        let (_, algs) = algorithms.mapping.iter().find(|(s, _)| *s == scheme)?;
        algs.first().copied()
    }

    /// Returns whether TLS 1.3 allows `scheme`, by the rule of rustls's private
    /// `SignatureScheme::supported_in_tls13`: a denylist of the hashes NONE, MD5, SHA-1 and
    /// SHA-224 and the signatures anonymous, RSA (PKCS#1 v1.5) and DSA (RFC 8446). Unknown values
    /// are allowed.
    fn allowed_in_tls13(scheme: SignatureScheme) -> bool {
        let [hash, signature] = scheme.to_array();
        hash > 0x03 && signature > 0x02
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rustls::CertificateError;
    use rustls::PeerMisbehaved;
    use rustls::SignatureScheme;
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::pki_types::SignatureVerificationAlgorithm;

    use super::*;
    use crate::default_provider;
    use crate::testcerts::KeyType;
    use crate::testcerts::LEADING_ZERO_MESSAGE;
    use crate::testcerts::RSA_2048_PSS_SHA256_LEADING_ZERO;
    use crate::testcerts::TestCert;
    use crate::testcerts::dss;
    use crate::testcerts::self_signed;
    use crate::testcerts::self_signed_with_key_bits;
    use crate::testcerts::sign;
    use crate::testdata::unhex;

    const MESSAGE: &[u8] = b"mvfstr CertificateVerify test message";

    fn ours() -> WebPkiSupportedAlgorithms {
        default_provider().signature_verification_algorithms
    }

    fn ring() -> WebPkiSupportedAlgorithms {
        rustls::crypto::ring::default_provider().signature_verification_algorithms
    }

    /// Runs the differential check: this crate's function with the backend provider's algorithms,
    /// and with ring's, against rustls with ring's. Returns the common result.
    fn verify_both(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<(), Error> {
        let reference =
            rustls::crypto::verify_tls13_signature(message, cert, dss, &ring()).map(drop);
        let with_ours = verify_tls13_certificate_signature(message, cert, dss, &ours()).map(drop);
        assert_eq!(
            with_ours, reference,
            "{:?} with the backend's algorithms",
            dss.scheme
        );
        let with_ring = verify_tls13_certificate_signature(message, cert, dss, &ring()).map(drop);
        assert_eq!(
            with_ring, reference,
            "{:?} with ring's algorithms",
            dss.scheme
        );
        reference
    }

    fn signed(kind: KeyType, scheme: SignatureScheme) -> (TestCert, DigitallySignedStruct) {
        let cert = self_signed(kind);
        let signature = sign(&cert.key, scheme, MESSAGE);
        (cert, dss(scheme, &signature))
    }

    fn flipped(dss: &DigitallySignedStruct) -> DigitallySignedStruct {
        let mut signature = dss.signature().to_vec();
        signature[0] ^= 0x10;
        crate::testcerts::dss(dss.scheme, &signature)
    }

    const BAD_SIGNATURE: Error = Error::InvalidCertificate(CertificateError::BadSignature);
    const BAD_ENCODING: Error = Error::InvalidCertificate(CertificateError::BadEncoding);
    const UNADVERTISED: Error =
        Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme);

    #[test]
    fn a_good_signature_verifies_for_each_certificate_type() {
        let cases = KeyType::ALL
            .into_iter()
            .map(|kind| (kind, kind.scheme()))
            .chain([
                (KeyType::Rsa2048, SignatureScheme::RSA_PSS_SHA384),
                (KeyType::Rsa2048, SignatureScheme::RSA_PSS_SHA512),
            ]);
        for (kind, scheme) in cases {
            let (cert, dss) = signed(kind, scheme);
            assert_eq!(verify_both(MESSAGE, &cert.cert, &dss), Ok(()), "{scheme:?}");
        }
    }

    #[test]
    fn a_flipped_bit_is_a_bad_signature() {
        for kind in KeyType::ALL {
            let (cert, dss) = signed(kind, kind.scheme());
            assert_eq!(
                verify_both(MESSAGE, &cert.cert, &flipped(&dss)),
                Err(BAD_SIGNATURE)
            );
            assert_eq!(
                verify_both(b"another message", &cert.cert, &dss),
                Err(BAD_SIGNATURE)
            );
        }
    }

    #[test]
    fn schemes_no_mapping_has_and_tls12_only_schemes_are_unadvertised() {
        let (cert, _) = signed(KeyType::Rsa2048, SignatureScheme::RSA_PSS_SHA256);
        let pkcs1 = sign(&cert.key, SignatureScheme::RSA_PKCS1_SHA256, MESSAGE);
        let cases = [
            (SignatureScheme::ED448, &[0; 114][..]),
            (SignatureScheme::from(0xfefe), &[0; 64][..]),
            // In every mapping and validly signed, so only the denylist rejects it.
            (SignatureScheme::RSA_PKCS1_SHA256, &pkcs1[..]),
        ];
        for (scheme, signature) in cases {
            assert_eq!(
                verify_both(MESSAGE, &cert.cert, &dss(scheme, signature)),
                Err(UNADVERTISED),
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn a_scheme_for_another_key_type_is_unsupported_for_the_key() {
        let (p256, ecdsa) = signed(KeyType::P256, SignatureScheme::ECDSA_NISTP256_SHA256);
        let cases = [
            (SignatureScheme::RSA_PSS_SHA256, KeyType::P256),
            (SignatureScheme::ECDSA_NISTP384_SHA384, KeyType::P256),
            (SignatureScheme::ED25519, KeyType::P384),
            (SignatureScheme::ECDSA_NISTP256_SHA256, KeyType::Rsa2048),
        ];
        for (scheme, kind) in cases {
            let cert = if kind == KeyType::P256 {
                &p256.cert
            } else {
                &self_signed(kind).cert
            };
            let result = verify_both(MESSAGE, cert, &dss(scheme, ecdsa.signature()));
            assert!(
                matches!(
                    result,
                    Err(Error::InvalidCertificate(
                        CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
                    ))
                ),
                "{scheme:?} with {kind:?}: {result:?}"
            );
        }
    }

    #[test]
    fn garbage_and_trailing_bytes_are_bad_encodings() {
        let (cert, dss) = signed(KeyType::P256, SignatureScheme::ECDSA_NISTP256_SHA256);
        let mut trailing = cert.cert.to_vec();
        trailing.push(0);
        let mut truncated = cert.cert.to_vec();
        truncated.pop();
        for der in [
            b"not a certificate".to_vec(),
            Vec::new(),
            trailing,
            truncated,
            [cert.cert.as_ref(), cert.cert.as_ref()].concat(),
        ] {
            assert_eq!(
                verify_both(MESSAGE, &CertificateDer::from(der), &dss),
                Err(BAD_ENCODING)
            );
        }
    }

    /// RFC 8017 allows only a signature as long as the modulus; OpenSSL's PSS check also takes one
    /// without its leading zero bytes.
    #[test]
    fn an_rsa_signature_shorter_than_the_modulus_is_a_bad_signature() {
        let cert = self_signed(KeyType::Rsa2048).cert;
        let signature = unhex(RSA_2048_PSS_SHA256_LEADING_ZERO);
        assert_eq!((signature.len(), signature[0]), (256, 0));
        let scheme = SignatureScheme::RSA_PSS_SHA256;
        let verify =
            |signature: &[u8]| verify_both(LEADING_ZERO_MESSAGE, &cert, &dss(scheme, signature));
        assert_eq!(verify(&signature), Ok(()));
        assert_eq!(verify(&signature[1..]), Err(BAD_SIGNATURE));
    }

    /// OpenSSL's RSA key parser takes an RSAPublicKey with trailing data; ring does not.
    #[test]
    fn an_rsa_key_with_trailing_bytes_is_a_bad_signature() {
        let cert = self_signed_with_key_bits(KeyType::Rsa2048, |key| [key, &[0, 1, 2]].concat());
        let scheme = SignatureScheme::RSA_PSS_SHA256;
        let signature = sign(&cert.key, scheme, MESSAGE);
        assert_eq!(
            verify_both(MESSAGE, &cert.cert, &dss(scheme, &signature)),
            Err(BAD_SIGNATURE)
        );
    }

    /// aws-lc-rs takes compressed points, so under it the delegate and the ring reference differ
    /// for a reason outside this crate.
    #[cfg(not(feature = "aws-lc-rs"))]
    #[test]
    fn a_compressed_p256_key_is_a_bad_signature() {
        let cert = crate::testcerts::compressed_p256();
        let signature = sign(&cert.key, SignatureScheme::ECDSA_NISTP256_SHA256, MESSAGE);
        let dss = dss(SignatureScheme::ECDSA_NISTP256_SHA256, &signature);
        assert_eq!(verify_both(MESSAGE, &cert.cert, &dss), Err(BAD_SIGNATURE));
    }

    type MappingEntry = (
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    );

    /// Returns one mapping entry per code point, each to the Ed25519 algorithm of `algorithms`,
    /// indexed by code point. It lives in `cell` so that it is `'static` without leaking.
    fn every_scheme(
        cell: &'static OnceLock<Vec<MappingEntry>>,
        algorithms: WebPkiSupportedAlgorithms,
    ) -> &'static [MappingEntry] {
        cell.get_or_init(|| {
            let (_, ed25519) = algorithms
                .mapping
                .iter()
                .find(|(scheme, _)| *scheme == SignatureScheme::ED25519)
                .unwrap();
            (0..=u16::MAX)
                .map(|value| (SignatureScheme::from(value), *ed25519))
                .collect()
        })
    }

    #[test]
    fn the_tls13_denylist_matches_rustls_on_every_scheme() {
        static OURS: OnceLock<Vec<MappingEntry>> = OnceLock::new();
        static RING: OnceLock<Vec<MappingEntry>> = OnceLock::new();
        let ours = every_scheme(&OURS, ours());
        let ring = every_scheme(&RING, ring());
        let only = |entries: &'static [MappingEntry], value: u16| {
            let index = usize::from(value);
            WebPkiSupportedAlgorithms {
                all: &[],
                mapping: &entries[index..=index],
            }
        };
        let cert = self_signed(KeyType::Ed25519).cert;
        let mut allowed = 0;
        for value in 0..=u16::MAX {
            // An empty signature fails at once, so each result shows only whether the scheme
            // passed the denylist.
            let dss = dss(SignatureScheme::from(value), &[]);
            let reference =
                rustls::crypto::verify_tls13_signature(MESSAGE, &cert, &dss, &only(ring, value))
                    .map(drop);
            let result =
                verify_tls13_certificate_signature(MESSAGE, &cert, &dss, &only(ours, value))
                    .map(drop);
            assert_eq!(result, reference, "{value:#06x}");
            if reference == Err(BAD_SIGNATURE) {
                allowed += 1;
            } else {
                assert_eq!(reference, Err(UNADVERTISED), "{value:#06x}");
            }
        }
        // 252 hash values above SHA-224 times 253 signature values above DSA.
        assert_eq!(allowed, 252 * 253);
    }
}
