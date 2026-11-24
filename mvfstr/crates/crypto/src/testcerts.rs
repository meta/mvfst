/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Certificates, keys and signatures for the signature tests of every backend. Signatures are
//! made by ring, through rustls's ring provider.

use rcgen::CertificateParams;
use rcgen::KeyPair;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::internal::msgs::codec::Codec;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;

use crate::testdata::unhex;

/// A fixed RSA-2048 key in PKCS#8, with public exponent 65537.
pub(crate) const RSA_2048_PKCS8: &str = concat!(
    "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201",
    "000282010100a423da2bf1f54b120172525028e8c2bd4ce5df3e017b360bc385",
    "8496a448322552a6ffb63c7a38044c10200fd265b03d4952c480c17b3d96fa65",
    "619de39c2ab9b6c6298745ffbd56617ae642cb07aa47dd1f1ec7e4a158abaf03",
    "9d090616f4b66d1e75e42b20945bcf3f4f2b6688c4bc902fc01d270e70de0b8f",
    "fb029073c98f9b8a700fde06e081bf192c9c0d52df5e932a4d1353d760e4559e",
    "902dd441b9ffcf13348405f0e063c549ce454b706ec4aaeee1425e0d344fcc04",
    "dd295f92fa58dcbc6062e5eb304178792ea1f8af785e2f16426cdeff25f91d29",
    "d1ffcd17a15dc6b3007f293abc00cd3ba1eca698b659ae421464d6684cf2bdb7",
    "0aee75388e470203010001028201004a46a10d1ece31dce183b2a4ec863bcd7e",
    "d54cdad9bfc03abd8d176d35c527d004e16638b89053f5f9d79832a0b27c7897",
    "4c1978ec55110f579af5fc054a1f796fb0a78d3bcb590a144d91922b1efa5acf",
    "c0abe4a7dcad6bef6432b52928cd2f1a1cdd1b55bac5f7efc645d4ad6ef99c1c",
    "a1470dca253a44f8b57c50723ebb3804074c150172890685f2cc25d7fff572e4",
    "f1d369f82fd9a0f1d9aab26510ce351a7f3d2a645ba78dd2d5b782ebc62b1a57",
    "4e387752aef81ee554a84998f6f7a835c1c71bb7d9c2b1e114c2b5f8fee99809",
    "eb7a437facceecda51796b7d70350ceeba5cb6da94fd2dab47697d73898b51cc",
    "67ba0d177343f6e3912bac208d854d02818100d1db4db9cd036fa8744fbf427e",
    "0314a3d6a2373ab73024df37350993db254894a2e1ae11691bd52d4225e8750d",
    "27a92eacd31f507d80bfa66a8e43b9617b17da84f65ae58051c53a4f83071237",
    "3a369dcb1d924f14d95da1d6465ef5d0596508baaddc3a486324fd3f724bf144",
    "4790fec4c4a196d142f3602d722caf6532eb6302818100c83b30ae25026f767b",
    "f50c8b0adeb718ca08e31ef697e9f7f9fbc589c03fcf9e35658efabeff78c046",
    "286c1b7629f288966f7ddbb326485f02baa31a720fc84b1945bb34a99cc33d2a",
    "30bf486c05a8cb4f62316e4a1bb65884911bfe149678bf6144d490fc4fa2a089",
    "f51826a188e3afeec5cff4c2e2f70486742732d54ab0cd0281801c88b41dd259",
    "68424066637c180435373dc4dabb9a12eac08b1224163d92e936849b28fee70a",
    "c8c6999aebeb96795110aea11a3de882ac0c65aaa85cb97b7237dd225e239c7a",
    "01d636df7b03a80cbb46634ac70d07a9b28881c919ba54b502fed7db31f99ec4",
    "145076e3049e6e894896cb8c6ce843d5d59fbb2e2e133f30583f028180373b8c",
    "9c1cfd64fdcc07b6a40c258f60392ae66bbe1dfd9e37c8e99eabf76e2ff80ec1",
    "b80d43af6d6a6cf0154b2d1b07ee6766d259c2afa7f5bac20f2373930e943416",
    "05dadbb1478801d66205da31cb936444ba659aeb5bd385abb114c0c5221594c5",
    "0611736e2ad6a3533c24c6fbf7a5e7cf0b774ee050d13ded2a2a87e5e9028180",
    "7ff89577889a2f1d897f2eb15a4d05361dafdbb0dbf34123ab9a1cc79b8dd6d5",
    "b1e55c8992de11e7fe06a50af6f0ad003a2ac319c38bad5d5016d4c4d2f5422e",
    "1c21face45de97127217d30656f8c8347cd067d454db49a69cbd40c2bc8aa84a",
    "d52b947b41f68c5141f11647939bbc3e042cc74b9107962c91ca25f761af7f2a",
);

/// The message of the RSA-2048 signatures that begin with a zero byte.
pub(crate) const LEADING_ZERO_MESSAGE: &[u8] = b"mvfstr leading-zero signature test message 147";

/// [`LEADING_ZERO_MESSAGE`] signed by [`RSA_2048_PKCS8`] with PSS, SHA-256 and a 32-byte salt,
/// made by the openssl command line. Its first byte is zero.
pub(crate) const RSA_2048_PSS_SHA256_LEADING_ZERO: &str = concat!(
    "0016adc81f60afb45a481737667a51f5738009e6437f3686bb2c67b94dddcb64",
    "3d110588f744f05cf9bfdc38be2d2f4ba41d878463d18cc744bf23ee1f2fa0bc",
    "4a112b0e97d22c2c145ffa7b4ef5b19c23a348bc3a46f0175bf3ef72d228e6e4",
    "f203d2a8bd4ea44368215d99ef9810e6229e337abda48b9db63086e8cb5af94a",
    "eb75ca698d384231823d04f3c2160143facd438ae32d39e1c6ee071b4d3b347a",
    "5dce25472bb797e21a05668853fce628a7cb009b6f9c9eccfcca5c25a547e70c",
    "85eba17d0b5fde5acb4c41f047a01fb2df304a27aebb26230bb7c92f740b5381",
    "431d541e716c0185862e786b84ea9533748260d00937f5a9fbe3a55de26c41e7",
);

/// An RSA-4096 SubjectPublicKeyInfo, whose DER lengths take two bytes.
pub(crate) const RSA_4096_SPKI: &str = concat!(
    "30820222300d06092a864886f70d01010105000382020f003082020a02820201",
    "00a515a46350ce6452ffdf765185cffd2c977062efa5468a61c4163ffb3aa633",
    "cbae4f57c5748cc18b48f4502a49611813cc853032e25f6958b99b0b2b7e852c",
    "e92c1a1b7f38933b67f149896f55287bc00a90c0d00b587c2f9da649b7b22ff4",
    "fcca9816d59cfbda07806516c7580e0c7e5c4e1bcafea3e31272d46c7aa3e14f",
    "2d0742517ddd013411cf663fd79dedb041125dfed79b2348c94518fea4ad918f",
    "48a3cc4cb4f30cfa8b51390b9b8a1eb9e3e447a49e71dd5fa8d12ff94adf6efb",
    "b5018ee892b8428ff6e2471fd733765a9f53dcce0050496bbafa80a54255a0c6",
    "85af6bddc14b9e6dc1d5559ab611d0aa7cd929571440503c4d29a632800f905f",
    "8083b40f7fb7e5fb67e2ed0ff5b48b381c66119d92698fd50c19fd5fc58937d1",
    "535a17360f242820fbcce5d339272ffdbb41a1b54c60145391bfefeeae5f1eb9",
    "a9ba7a2bb9beed11514d1b8b4963b7ee4a73b07ff2707e9c5118b525becd9234",
    "d3a945175fce0ba94f48ece8fb50068e755003ec80b6c39b194ee0b3b539223d",
    "27919eaf30c50c8109c2bc0f40f52be449719c63fc6bdfd45856400e35f74ae1",
    "dd739ae143fd263f90c4236131d774da1e91bdcbf6010af639304751262e3958",
    "579165c64db78b435106556c9504f8001977ca253f6a6ce37e6c98f90b83bbc4",
    "6d2e896b34ea8e8d2bc6d8e9c0cea145146827e6ce164b96f8ef71a82bf1322a",
    "6f0203010001",
);

/// An RSA-8192 SubjectPublicKeyInfo, whose DER lengths take two bytes.
pub(crate) const RSA_8192_SPKI: &str = concat!(
    "30820422300d06092a864886f70d01010105000382040f003082040a02820401",
    "00c755eff315dc91a6c50da2977e9ddb14dbb424a8d54d7cd7e050d9b5dd9728",
    "21c4ce088f5344b0fb50ecb8e0279c7f7aafca2c2f806c3402b5af1889474774",
    "8f00ab00984c2a921fc4a6f040cda7864ead7e7d7936993d1f4a5be6115e04bc",
    "60c51090aa0d01a6dc8965a71627606acf3ac3c3990c6c9458be27878163b1f1",
    "383f4ef7bf2cdce9787e30a143d099828b0281aa10a1ce6a4f4c952c28c09bf8",
    "5bfa5c660ec7a6d35f87e35cd63d309f2b569317b6ed111094c73350a3cda501",
    "46ef07432ad502682c0ad2a87d2fabd4693426644c35873a8383f7aef2a44334",
    "52b4b32a4d1b5798bcb0189a30f1e58f099be5a1262e0c8575ba95eb1788395d",
    "11c53b4fe1d9e1f532fc1e99651496dbf56f04de16eaf8d066620ab27fc6a26d",
    "b6a04bf3b1fff1f0beb6996bc63811a11e50de96951831c2ac8bf904aaa6b397",
    "537268d398f65b0f60b19e20eca95a7505ebc72b161628afa577bac7156427fe",
    "d26d49471fcc5261672001cf5577a6dafb42a82ff66867df5561181596939090",
    "1340693885b9fe31c0fa0fd99ffa5ce97c063f0772b08856b6397ba56300aaf1",
    "e8299110e8fc9fa347a535d0dd67122a79dcc3bcf4dfd1c9d85497bd93d03fff",
    "8dedb034bbc0c011bf1508a398926812c49f2bcd139d27d1028f72bc02e39ee9",
    "2cc499577cd46fb73d66cf74aa9be403e7902f916b09387475b2cbf4eabef761",
    "01662649c9cbbe8d3dd883b08592710bfa310b7241ca290a827cc54e22426bf7",
    "5a7eacb9a075d17378d06bae9f97ba32a2e535cd6c09d2b38cc060c735b24a75",
    "366b7f5e5eeb808451b403945732a67c67f6d266fdf1b5deacaa998c325f3e8d",
    "049421dcbe26e673b09227f79d48be77801c364a7ca06feccf3916722a8b1755",
    "a3994b0c55e1a1e31b9d55ba48dd5e033728d7eff29968af5d1edb57c8d130ea",
    "b01956bf45f926e354b220c2fede27cc73f78f1fad160ea82e1a840af9197489",
    "c4b875b1588d79365a0a8806b27bf1a9e7ff72e2acf095b3210e0cdd16aa29cb",
    "2ec48990a07c9793641ac7da7a737220df4da9a023dd6e01cb4be3e73a309556",
    "a70333d60eb144f3a43b3f72a624fac5240641d74900392c68a837c1f1df8e88",
    "a18f4ab1fde41ed7f8cf3e187a84262b100d78bbe45b3e3a88fb734c08415958",
    "2551e9913d907d8bfe811b5223ba1896021d17a1e8ebb93687e7eb0608a4a10e",
    "7c2aaddeac238677d0ee586f5bd8aa72ee907d0ca2e9cbac8fe8a20650b70171",
    "5d00d2967c9aa4e1b85f0a5840dc17714ace8a3c30393fc2ac5a6e764615fb4b",
    "f1cdd96b293880275d9abffd4b6278269f20bf937d591f1b430609ab99ba0ffb",
    "317b8a3e0a619b49d8632cb20b624a549e204bcef6ce3bdaee2257e1021bf45a",
    "0f56ddc28f0a787504272698a9988400ce2d22969cb92c6fa2d4c1dcf6a0dc7c",
    "b30203010001",
);

/// The certificate key types the tests cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
    P256,
    P384,
    Ed25519,
    Rsa2048,
}

impl KeyType {
    /// Every key type.
    pub(crate) const ALL: [KeyType; 4] = [
        KeyType::P256,
        KeyType::P384,
        KeyType::Ed25519,
        KeyType::Rsa2048,
    ];

    /// Returns the TLS 1.3 scheme that a CertificateVerify with this key uses here: PSS for RSA.
    pub(crate) fn scheme(self) -> SignatureScheme {
        match self {
            KeyType::P256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            KeyType::P384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            KeyType::Ed25519 => SignatureScheme::ED25519,
            KeyType::Rsa2048 => SignatureScheme::RSA_PSS_SHA256,
        }
    }
}

/// A self-signed certificate and its private key.
pub(crate) struct TestCert {
    pub(crate) cert: CertificateDer<'static>,
    pub(crate) key: PrivateKeyDer<'static>,
}

/// Returns a key pair of `kind`: fresh for the elliptic curves, the fixed RSA-2048 key for RSA.
fn key_pair(kind: KeyType) -> KeyPair {
    match kind {
        KeyType::P256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
        KeyType::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        KeyType::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
        KeyType::Rsa2048 => KeyPair::try_from(&unhex(RSA_2048_PKCS8)[..]),
    }
    .unwrap()
}

fn params() -> CertificateParams {
    CertificateParams::new(vec!["localhost".to_owned()]).unwrap()
}

fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(key.serialize_der()).into()
}

/// Makes a self-signed certificate for `localhost` with a key of `kind`.
pub(crate) fn self_signed(kind: KeyType) -> TestCert {
    let key = key_pair(kind);
    let cert = params().self_signed(&key).unwrap();
    TestCert {
        cert: cert.der().clone(),
        key: private_key(&key),
    }
}

/// Returns ring's signature of `message` by `key` with `scheme`.
pub(crate) fn sign(key: &PrivateKeyDer<'_>, scheme: SignatureScheme, message: &[u8]) -> Vec<u8> {
    rustls::crypto::ring::sign::any_supported_type(key)
        .unwrap()
        .choose_scheme(&[scheme])
        .expect("the key signs with the scheme")
        .sign(message)
        .unwrap()
}

/// Returns a CertificateVerify signature. rustls constructs these only by decoding, so this
/// decodes one.
pub(crate) fn dss(scheme: SignatureScheme, signature: &[u8]) -> DigitallySignedStruct {
    let mut encoded = scheme.to_array().to_vec();
    encoded.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
    encoded.extend_from_slice(signature);
    DigitallySignedStruct::read_bytes(&encoded).unwrap()
}

/// A key pair whose certificate carries other public key bits than its own.
struct OtherKeyBits {
    key: KeyPair,
    key_bits: Vec<u8>,
}

impl rcgen::PublicKeyData for OtherKeyBits {
    fn der_bytes(&self) -> &[u8] {
        &self.key_bits
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::PublicKeyData::algorithm(&self.key)
    }
}

impl rcgen::SigningKey for OtherKeyBits {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        rcgen::SigningKey::sign(&self.key, message)
    }
}

/// Makes a self-signed certificate for `localhost` with a key of `kind`, whose
/// SubjectPublicKeyInfo holds `key_bits(<the key's own bits>)` in their place.
pub(crate) fn self_signed_with_key_bits(
    kind: KeyType,
    key_bits: impl FnOnce(&[u8]) -> Vec<u8>,
) -> TestCert {
    let key = key_pair(kind);
    let key_bits = key_bits(key.public_key_raw());
    let signer = OtherKeyBits { key, key_bits };
    let cert = params().self_signed(&signer).unwrap();
    TestCert {
        cert: cert.der().clone(),
        key: private_key(&signer.key),
    }
}

/// Makes a self-signed P-256 certificate whose SubjectPublicKeyInfo holds the 33-byte compressed
/// form of its key, with that key. aws-lc-rs takes compressed points, so the test that uses it
/// does not run under that feature.
#[cfg(not(feature = "aws-lc-rs"))]
pub(crate) fn compressed_p256() -> TestCert {
    self_signed_with_key_bits(KeyType::P256, |point| {
        [&[0x02 | (point[64] & 1)][..], &point[1..33]].concat()
    })
}
