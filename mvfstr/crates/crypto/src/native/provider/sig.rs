/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Signature verification algorithms: those of rustls's ring provider, with ring's limits.

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::AlgorithmIdentifier;
use rustls::pki_types::InvalidSignature;
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::pki_types::alg_id;

use crate::native::SigHash;
use crate::native::SigKind;
use crate::native::sys;
use crate::spki;

/// A signature algorithm: the key kind and hash `sys::verify` checks with, and the identifiers
/// rustls matches it by.
#[derive(Debug)]
struct Algorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    kind: SigKind,
    hash: SigHash,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let ring_accepts_encoding = match self.kind {
            // ring takes uncompressed points only; the libraries also take compressed ones.
            SigKind::EcP256 => is_uncompressed_point(public_key, 65),
            SigKind::EcP384 => is_uncompressed_point(public_key, 97),
            // ring reads the key as strict DER without trailing data, and takes a signature only
            // as long as the modulus, as RFC 8017 requires; OpenSSL is looser on both.
            SigKind::RsaPkcs1 | SigKind::RsaPss => {
                spki::rsa_modulus(public_key).is_some_and(|n| n.len() == signature.len())
            }
            SigKind::Ed25519 => true,
        };
        if !ring_accepts_encoding {
            return Err(InvalidSignature);
        }
        let spki = spki::build(self.public_key_alg_id.as_ref(), public_key);
        sys::verify(self.kind, self.hash, &spki, message, signature)
            .then_some(())
            .ok_or(InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

/// Returns whether `key` is an uncompressed elliptic-curve point of `len` bytes.
fn is_uncompressed_point(key: &[u8], len: usize) -> bool {
    key.len() == len && key[0] == 0x04
}

/// sha256WithRSAEncryption without the NULL parameter, for which pki-types does not have a
/// constant.
const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);

/// sha384WithRSAEncryption without the NULL parameter.
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);

/// sha512WithRSAEncryption without the NULL parameter.
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

const fn ecdsa(
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    kind: SigKind,
    hash: SigHash,
) -> Algorithm {
    Algorithm {
        public_key_alg_id,
        signature_alg_id,
        kind,
        hash,
    }
}

const fn rsa(signature_alg_id: AlgorithmIdentifier, kind: SigKind, hash: SigHash) -> Algorithm {
    Algorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id,
        kind,
        hash,
    }
}

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa(
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256,
    SigKind::EcP256,
    SigHash::Sha256,
);
static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa(
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384,
    SigKind::EcP256,
    SigHash::Sha384,
);
static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa(
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256,
    SigKind::EcP384,
    SigHash::Sha256,
);
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa(
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384,
    SigKind::EcP384,
    SigHash::Sha384,
);
static ED25519: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    kind: SigKind::Ed25519,
    hash: SigHash::None,
};
static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PSS_SHA256, SigKind::RsaPss, SigHash::Sha256);
static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PSS_SHA384, SigKind::RsaPss, SigHash::Sha384);
static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PSS_SHA512, SigKind::RsaPss, SigHash::Sha512);
static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PKCS1_SHA256, SigKind::RsaPkcs1, SigHash::Sha256);
static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PKCS1_SHA384, SigKind::RsaPkcs1, SigHash::Sha384);
static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm =
    &rsa(alg_id::RSA_PKCS1_SHA512, SigKind::RsaPkcs1, SigHash::Sha512);
static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &rsa(
    RSA_PKCS1_SHA256_ABSENT_PARAMS,
    SigKind::RsaPkcs1,
    SigHash::Sha256,
);
static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &rsa(
    RSA_PKCS1_SHA384_ABSENT_PARAMS,
    SigKind::RsaPkcs1,
    SigHash::Sha384,
);
static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &rsa(
    RSA_PKCS1_SHA512_ABSENT_PARAMS,
    SigKind::RsaPkcs1,
    SigHash::Sha512,
);

/// The algorithms and scheme mapping of rustls's ring provider, in the same order. In TLS 1.3 the
/// scheme fixes the curve, and rustls uses the first algorithm of each entry.
pub(super) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::*;
    use crate::testcerts::KeyType;
    use crate::testcerts::LEADING_ZERO_MESSAGE;
    use crate::testcerts::RSA_2048_PSS_SHA256_LEADING_ZERO;
    use crate::testcerts::TestCert;
    use crate::testcerts::self_signed;
    use crate::testcerts::sign;
    use crate::testdata::unhex;

    /// The message the fixed RSA-1024 signatures sign.
    const RSA_1024_MESSAGE: &[u8] = b"mvfstr RSA-1024 test message";

    /// The message the fixed cross-hash ECDSA signatures sign.
    const CROSS_HASH_MESSAGE: &[u8] = b"mvfstr cross-hash ECDSA test message";

    /// An RSA-1024 SubjectPublicKeyInfo, below ring's 2048-bit minimum.
    const RSA_1024_SPKI: &str = concat!(
        "30819f300d06092a864886f70d010101050003818d0030818902818100dc70ef",
        "80386428f20ecb743ca849186436d245286cab9f5d47a90263addd27baa83b62",
        "841fd126bdd1a6acc6147a31b1a49c8398d0d237a9c4950e68657165a7a7174e",
        "849f5da29386a0f38be7ca64434b41b8ce95cfdf00557e8984305bd3098014f2",
        "4f2ea1a86d13e8b5283fa0cea6d2dd0f143dfeeba5fc1be46fcb1b2c39020301",
        "0001",
    );

    /// [`RSA_1024_MESSAGE`] signed with the RSA-1024 key, PKCS#1 v1.5 with SHA-256.
    const RSA_1024_PKCS1_SHA256: &str = concat!(
        "bf35cfb481bb4b222b58252d4493daddad385a139b9bca4578f42220babfac48",
        "60b0958f188dc05f883cb5c4c98e023ceff797e0bb7e93d455fedd79d77f27e7",
        "c169a20f1082fa2db55e2cd927d505e830b38bd4a7502b781ed3476572b308bd",
        "f4bac615f9b0dc0fd25b96b7b5c86cd01ee11c7b4609fdd18fdfb048ca0d288a",
    );

    /// [`RSA_1024_MESSAGE`] signed with the RSA-1024 key, PSS with SHA-256 and a 32-byte salt.
    const RSA_1024_PSS_SHA256: &str = concat!(
        "7afafe430784a44bbb52b7a5443eedef38837c2903082ecc822180e47e5bf3e2",
        "ad9600a7266a7972c51a5fec302cc412a59db8715de1de268f7b3c0530f8949b",
        "3415cc50e73aec6912fb29d89e51fee9d6adf49efe4f1c6a13cbe721206f719a",
        "ecc9344f7939f164d21830764e3e787268da14099aed27e0898b7dfc1d35197d",
    );

    /// A fixed P-256 public key.
    const P256_POINT: &str = concat!(
        "0441eb70b31a4003f28643fc63bb4dcc94ece01b36010b6662776476e708587a",
        "82e88ca4b7cf222c50f00df8430c93e4d05e69f1d3cee81180f0d0182bf685fc",
        "ef",
    );

    /// [`CROSS_HASH_MESSAGE`] signed with the P-256 key over SHA-384.
    const P256_SHA384_SIG: &str = concat!(
        "3046022100b5e71c507664e63b4af2e7e7d4dc486485b18d9b99a1a4f36813e3",
        "da4b7a1448022100ec453b2e7ff25bed002b269c481b911850e44c13775c63f3",
        "22b70a953e0783cf",
    );

    /// A fixed P-384 public key.
    const P384_POINT: &str = concat!(
        "0492a933857a96669216c33e401075dedc32019f374372ba2ecee8741f44d138",
        "55137809f5c22d6314d585bccf9e2aa0466d5e4b887fd7ecf49ec8c7fbc89c04",
        "0e3b6c557a7aa67b7438b31b2607bf90aff711b4b5d8c25c3d5f222f36663e37",
        "70",
    );

    /// [`CROSS_HASH_MESSAGE`] signed with the P-384 key over SHA-256.
    const P384_SHA256_SIG: &str = concat!(
        "306502304abf46beab1a388f37aaa2540a8f15065d6342db628d67663cb4831d",
        "52cefdbc335cf7cbc8164b2ce4e66e9efdebaf9b023100eb7aa4db48e9a7912e",
        "d6eb57bc266defa85120f70137818e4da43e45e6e1f7afbd6d0a37b7290dfa4f",
        "45d0142a2ccb60",
    );

    const MESSAGE: &[u8] = b"mvfstr signature verification test message";

    /// [`LEADING_ZERO_MESSAGE`] signed by the RSA-2048 test key with PKCS#1 v1.5 and SHA-256,
    /// made by the openssl command line. Its first byte is zero.
    const RSA_2048_PKCS1_SHA256_LEADING_ZERO: &str = concat!(
        "00a569a350051db0e29411aca004015ea25f7451a6871ddc2bdc182ae7311dac",
        "dfd0f9d0e639ba1e6a7492cf707f388d0c383f44330b4342493e782bfefe98c2",
        "2d8e71447d79ff2679e8d65d0ef07ba2b6c39caaf9d3f2b6dfd2ad062f50a7c9",
        "24b29ca06c7f1a89c5705b3ee8d1c163741eec8e983a9cd9e37233be9e5f801a",
        "61189ad848c5e1fd51483094b762bfaab1e79178ef0ea37c02b292ccd74f2c24",
        "9730652247e96ff9feebc673c3e2569595ef0e6b2f7164f6d12099a112ffa208",
        "7d99dd4bda967bc173f08420c70da26edab7cea5f0cdfe222520c33ebab4b2de",
        "95620850ff3f7c3e6e57e1bf87dac0fb177f865486208f54b5ce0524cbd0d341",
    );

    /// [`MESSAGE`] signed by the RSA-2048 test key with PSS, SHA-256 and a 20-byte salt, made by
    /// the openssl command line, which verifies it with a salt length of 20 or `auto`.
    const RSA_PSS_SHA256_SALT_20: &str = concat!(
        "a2434d73e2208081ad2c2eeeb34553c4903660fe1d1d36a2a979e489abec407e",
        "db55ce5079e0a3673707e06ab94fb48b503710e5bcb6c621d523f7d19628563c",
        "420640f347ef1855a93949ca85100e45b74b9ac8dc535c4e015f1dfef00d4995",
        "fe70d030d6239f227b1462af933b7e2a7f5c1d797d902438ec5b30ffb46613e7",
        "6697ad091cb9727d55cedecdc87b3eb69ac24df8e01748232f0239fe155a3469",
        "a796003f7599d13053054afd61b6033055758dad299af6bae67e2e6e7bb1daaa",
        "9d25dac821c168eba3fdc7844d68f48d9a24bdfbd88317b482545c2c8016e656",
        "bb0f803c43c754a492106c07d96b3f1935819afcc63eaa2aa86d45e51b4928ea",
    );

    /// [`MESSAGE`] signed by the RSA-2048 test key with PSS, SHA-256, a 32-byte salt and MGF1
    /// over SHA-1, made by the openssl command line, which verifies it with those parameters.
    const RSA_PSS_SHA256_MGF1_SHA1: &str = concat!(
        "5429fa5e64da9e70fd93d5fe2a1e6ed778c6f97b31428818e8c08a29124012cb",
        "bca5e6037be72e0bb53ad85014fd5173e0a63a574277d9aff881520bdcb96e1b",
        "ee92f13497ec7e3d8fcd79f87a92877f93e7c7d5a5c1f80f14976b09926a2294",
        "0dc2ebb4f18c8b26af9ce41316099d362ba20f0b6ba092238380b875685bab22",
        "1f44f514d15c6ccd8df563479174691dd9f2effee0641fb6417a1c59cb477d3a",
        "e1358ca3ce7f35fcf4934ad769c498a2cd459d2d7e301383e68649e708109ee2",
        "d6b0e516f013efe3b590130216fe667cc6e014f8ee437824642e1339a638b332",
        "9b135937a48177ad8627a81301661c5a342b08066e2bb6037c05755180bcf3e0",
    );

    /// The key and scheme ring signs with for each signature algorithm identifier, apart from
    /// the two cross-hash ECDSA algorithms, which ring cannot sign with.
    const BY_SIGNATURE_ALG_ID: [(AlgorithmIdentifier, KeyType, SignatureScheme); 12] = [
        (
            alg_id::ECDSA_SHA256,
            KeyType::P256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ),
        (
            alg_id::ECDSA_SHA384,
            KeyType::P384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ),
        (alg_id::ED25519, KeyType::Ed25519, SignatureScheme::ED25519),
        (
            alg_id::RSA_PSS_SHA256,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PSS_SHA256,
        ),
        (
            alg_id::RSA_PSS_SHA384,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PSS_SHA384,
        ),
        (
            alg_id::RSA_PSS_SHA512,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PSS_SHA512,
        ),
        (
            alg_id::RSA_PKCS1_SHA256,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA256,
        ),
        (
            alg_id::RSA_PKCS1_SHA384,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA384,
        ),
        (
            alg_id::RSA_PKCS1_SHA512,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA512,
        ),
        (
            RSA_PKCS1_SHA256_ABSENT_PARAMS,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA256,
        ),
        (
            RSA_PKCS1_SHA384_ABSENT_PARAMS,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA384,
        ),
        (
            RSA_PKCS1_SHA512_ABSENT_PARAMS,
            KeyType::Rsa2048,
            SignatureScheme::RSA_PKCS1_SHA512,
        ),
    ];

    fn ring_algorithms() -> WebPkiSupportedAlgorithms {
        rustls::crypto::ring::default_provider().signature_verification_algorithms
    }

    /// Returns the subjectPublicKey bits of a certificate, as rustls passes them to
    /// `verify_signature`.
    fn key_bits(cert: &CertificateDer<'_>) -> Vec<u8> {
        let spki = sys::cert_spki(cert.as_ref()).unwrap();
        spki::split(&spki).unwrap().1.to_vec()
    }

    /// Returns a key of `kind` and ring's signature of `message` by it with `scheme`.
    fn signed(kind: KeyType, scheme: SignatureScheme, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let TestCert { cert, key } = self_signed(kind);
        (key_bits(&cert), sign(&key, scheme, message))
    }

    fn flipped(signature: &[u8]) -> Vec<u8> {
        let mut flipped = signature.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        flipped
    }

    /// Checks ours and ring's algorithm on the same inputs, and returns the common result.
    fn verify_both(
        ours: &dyn SignatureVerificationAlgorithm,
        ring: &dyn SignatureVerificationAlgorithm,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let ours = ours.verify_signature(key, message, signature).is_ok();
        let theirs = ring.verify_signature(key, message, signature).is_ok();
        assert_eq!(ours, theirs, "{ring:?}");
        ours
    }

    #[test]
    fn each_mapping_scheme_verifies_signatures_made_by_ring() {
        let ring = ring_algorithms();
        assert_eq!(SUPPORTED_SIG_ALGS.mapping.len(), ring.mapping.len());
        for ((scheme, ours), (ring_scheme, theirs)) in
            SUPPORTED_SIG_ALGS.mapping.iter().zip(ring.mapping)
        {
            assert_eq!(scheme, ring_scheme);
            let kind = match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => KeyType::P256,
                SignatureScheme::ECDSA_NISTP384_SHA384 => KeyType::P384,
                SignatureScheme::ED25519 => KeyType::Ed25519,
                _ => KeyType::Rsa2048,
            };
            let (key, signature) = signed(kind, *scheme, MESSAGE);
            assert!(
                verify_both(ours[0], theirs[0], &key, MESSAGE, &signature),
                "{scheme:?}"
            );
            assert!(!verify_both(
                ours[0],
                theirs[0],
                &key,
                MESSAGE,
                &flipped(&signature)
            ));
            assert!(!verify_both(
                ours[0],
                theirs[0],
                &key,
                b"another message",
                &signature
            ));
        }
    }

    #[test]
    fn every_algorithm_verifies_what_ring_verifies() {
        let ring = ring_algorithms();
        assert_eq!(SUPPORTED_SIG_ALGS.all.len(), 14);
        assert_eq!(SUPPORTED_SIG_ALGS.all.len(), ring.all.len());
        for (ours, theirs) in SUPPORTED_SIG_ALGS.all.iter().zip(ring.all) {
            assert_eq!(ours.public_key_alg_id(), theirs.public_key_alg_id());
            assert_eq!(ours.signature_alg_id(), theirs.signature_alg_id());
            assert!(!ours.fips());
            let id = (ours.public_key_alg_id(), ours.signature_alg_id());
            let (key, message, signature) = if id == (alg_id::ECDSA_P256, alg_id::ECDSA_SHA384) {
                (
                    unhex(P256_POINT),
                    CROSS_HASH_MESSAGE,
                    unhex(P256_SHA384_SIG),
                )
            } else if id == (alg_id::ECDSA_P384, alg_id::ECDSA_SHA256) {
                (
                    unhex(P384_POINT),
                    CROSS_HASH_MESSAGE,
                    unhex(P384_SHA256_SIG),
                )
            } else {
                let (_, kind, scheme) = BY_SIGNATURE_ALG_ID
                    .iter()
                    .find(|(sig_id, ..)| *sig_id == id.1)
                    .unwrap();
                let (key, signature) = signed(*kind, *scheme, MESSAGE);
                (key, MESSAGE, signature)
            };
            assert!(
                verify_both(*ours, *theirs, &key, message, &signature),
                "{theirs:?}"
            );
            assert!(!verify_both(
                *ours,
                *theirs,
                &key,
                message,
                &flipped(&signature)
            ));
        }
    }

    #[test]
    fn a_key_of_the_wrong_type_fails() {
        let ring = ring_algorithms();
        let p256 = key_bits(&self_signed(KeyType::P256).cert);
        let p384 = key_bits(&self_signed(KeyType::P384).cert);
        let ed25519 = key_bits(&self_signed(KeyType::Ed25519).cert);
        let rsa = key_bits(&self_signed(KeyType::Rsa2048).cert);
        let cases = [
            (
                0,
                &p384,
                KeyType::P256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                0,
                &ed25519,
                KeyType::P256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                3,
                &p256,
                KeyType::P384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
            (4, &p256, KeyType::Ed25519, SignatureScheme::ED25519),
            (4, &rsa, KeyType::Ed25519, SignatureScheme::ED25519),
            (5, &p256, KeyType::Rsa2048, SignatureScheme::RSA_PSS_SHA256),
            (
                8,
                &ed25519,
                KeyType::Rsa2048,
                SignatureScheme::RSA_PKCS1_SHA256,
            ),
        ];
        for (index, key, kind, scheme) in cases {
            let signature = signed(kind, scheme, MESSAGE).1;
            let (ours, theirs) = (SUPPORTED_SIG_ALGS.all[index], ring.all[index]);
            assert!(
                !verify_both(ours, theirs, key, MESSAGE, &signature),
                "{theirs:?}"
            );
        }
    }

    // Indexes in `all`.
    const PSS_SHA256: usize = 5;
    const PKCS1_SHA256: usize = 8;
    const PKCS1_SHA256_ABSENT_PARAMS: usize = 11;

    #[test]
    fn an_rsa_signature_must_be_as_long_as_the_modulus() {
        let ring = ring_algorithms();
        let key = key_bits(&self_signed(KeyType::Rsa2048).cert);
        for (index, signature) in [
            (PKCS1_SHA256, RSA_2048_PKCS1_SHA256_LEADING_ZERO),
            (
                PKCS1_SHA256_ABSENT_PARAMS,
                RSA_2048_PKCS1_SHA256_LEADING_ZERO,
            ),
            (PSS_SHA256, RSA_2048_PSS_SHA256_LEADING_ZERO),
        ] {
            let signature = unhex(signature);
            assert_eq!((signature.len(), signature[0]), (256, 0));
            let (ours, theirs) = (SUPPORTED_SIG_ALGS.all[index], ring.all[index]);
            let verify =
                |signature: &[u8]| verify_both(ours, theirs, &key, LEADING_ZERO_MESSAGE, signature);
            assert!(verify(&signature), "{theirs:?}");
            assert!(!verify(&signature[1..]), "{theirs:?} without the zero byte");
            assert!(
                !verify(&[&[0], &signature[..]].concat()),
                "{theirs:?} with another zero byte"
            );
        }
    }

    #[test]
    fn rsa_keys_are_read_as_ring_reads_them() {
        let ring = ring_algorithms();
        let TestCert { cert, key } = self_signed(KeyType::Rsa2048);
        let good = key_bits(&cert);
        let n = spki::rsa_modulus(&good).unwrap();
        let integer = |contents: &[u8]| spki::der(spki::INTEGER, &[contents]);
        let rsa_key = |n: &[u8], e: &[u8]| spki::der(spki::SEQUENCE, &[&integer(n), &integer(e)]);
        let signed_n = [&[0], n].concat();
        let e = [1, 0, 1];
        assert_eq!(rsa_key(&signed_n, &e), good);
        let cases = [
            ("trailing data", [&good[..], &[0, 1, 2]].concat()),
            (
                "a long-form length",
                [&[0x30, 0x83, 0x00][..], &good[2..]].concat(),
            ),
            ("a negative modulus", rsa_key(n, &e)),
            (
                "an unneeded zero byte in the modulus",
                rsa_key(&[&[0, 0], n].concat(), &e),
            ),
            (
                "an unneeded zero byte in the exponent",
                rsa_key(&signed_n, &[0, 1, 0, 1]),
            ),
        ];
        for (index, scheme) in [
            (PSS_SHA256, SignatureScheme::RSA_PSS_SHA256),
            (PKCS1_SHA256, SignatureScheme::RSA_PKCS1_SHA256),
        ] {
            let signature = sign(&key, scheme, MESSAGE);
            let (ours, theirs) = (SUPPORTED_SIG_ALGS.all[index], ring.all[index]);
            assert!(verify_both(ours, theirs, &good, MESSAGE, &signature));
            // Each result is (case, ours, ring's); all must reject.
            let results: Vec<_> = cases
                .iter()
                .map(|(what, malformed)| {
                    let ok = |alg: &dyn SignatureVerificationAlgorithm| {
                        alg.verify_signature(malformed, MESSAGE, &signature).is_ok()
                    };
                    (*what, ok(ours), ok(theirs))
                })
                .collect();
            assert!(
                results.iter().all(|&(_, ours, theirs)| !ours && !theirs),
                "{scheme:?}: {results:?}"
            );
        }
    }

    #[test]
    fn pss_takes_only_a_salt_as_long_as_the_hash_and_mgf1_over_it() {
        let ring = ring_algorithms();
        let key = key_bits(&self_signed(KeyType::Rsa2048).cert);
        let (ours, theirs) = (SUPPORTED_SIG_ALGS.all[PSS_SHA256], ring.all[PSS_SHA256]);
        for (what, signature) in [
            ("a 20-byte salt", RSA_PSS_SHA256_SALT_20),
            ("MGF1 over SHA-1", RSA_PSS_SHA256_MGF1_SHA1),
        ] {
            let signature = unhex(signature);
            assert!(
                !verify_both(ours, theirs, &key, MESSAGE, &signature),
                "{what}"
            );
        }
    }

    #[test]
    fn an_rsa_1024_key_is_rejected() {
        let ring = ring_algorithms();
        let spki = unhex(RSA_1024_SPKI);
        let (alg, key) = spki::split(&spki).unwrap();
        assert_eq!(alg, alg_id::RSA_ENCRYPTION.as_ref());
        // Both signatures are valid (the openssl command line verifies them); the 2048-bit
        // minimum is what rejects them.
        for (index, signature, kind, hash) in [
            (8, RSA_1024_PKCS1_SHA256, SigKind::RsaPkcs1, SigHash::Sha256),
            (
                11,
                RSA_1024_PKCS1_SHA256,
                SigKind::RsaPkcs1,
                SigHash::Sha256,
            ),
            (5, RSA_1024_PSS_SHA256, SigKind::RsaPss, SigHash::Sha256),
        ] {
            let signature = unhex(signature);
            let (ours, theirs) = (SUPPORTED_SIG_ALGS.all[index], ring.all[index]);
            assert!(!verify_both(
                ours,
                theirs,
                key,
                RSA_1024_MESSAGE,
                &signature
            ));
            assert!(!sys::verify(
                kind,
                hash,
                &spki,
                RSA_1024_MESSAGE,
                &signature
            ));
        }
    }
}
