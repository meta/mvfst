/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HKDF-Extract, HKDF-Expand and HKDF-Expand-Label (RFC 5869, RFC 8446).
//!
//! QUIC derives its Initial secrets, and the key, IV and header-protection key of any traffic
//! secret, with these functions (RFC 9001). The Initial secrets use SHA-256, and a traffic secret
//! uses the hash of its cipher suite, SHA-256 or SHA-384.

use std::fmt;

use crate::backend::digest;
use crate::backend::hkdf;
use crate::backend::hmac;
use crate::secrets::SecretHash;

/// The SHA-256 output length, which is the length of an Initial secret.
pub const SHA256_LEN: usize = 32;

/// The SHA-384 output length, which is the length of a traffic secret of a SHA-384 cipher suite.
pub(crate) const SHA384_LEN: usize = 48;

/// The longest secret taken as an HKDF pseudorandom key, the longest digest output. aws-lc-rs's
/// `Prk::new_less_safe` panics on a longer one and ring's takes any length; refusing a longer
/// secret on both keeps the backends alike.
const MAX_SECRET_LEN: usize = digest::MAX_OUTPUT_LEN;

/// Returns the HKDF-Extract pseudorandom key for `ikm` under `salt`, with SHA-256.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_LEN] {
    // HKDF-Extract is HMAC(salt, ikm). Computing it as an HMAC gives plain PRK bytes, which
    // `Salt::extract` does not return.
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), ikm);
    let mut prk = [0; SHA256_LEN];
    prk.copy_from_slice(tag.as_ref());
    prk
}

/// Why HKDF-Expand or HKDF-Expand-Label refused its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandLabelError {
    /// The label (with its "tls13 " prefix) or the context is longer than 255 bytes, or the
    /// output is longer than 255 hash lengths.
    TooLong,
    /// The secret or pseudorandom key is longer than 64 bytes, the longest digest output.
    SecretTooLong,
}

impl fmt::Display for ExpandLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("HKDF-Expand input or output too long"),
            Self::SecretTooLong => f.write_str("HKDF-Expand secret longer than 64 bytes"),
        }
    }
}

impl std::error::Error for ExpandLabelError {}

/// Fills `out` with HKDF-Expand-Label over SHA-256 (RFC 8446), from `secret`, `label` (without
/// the "tls13 " prefix) and `context`. Fails with [`ExpandLabelError`] when `secret`, `label`,
/// `context` or `out` is too long.
pub fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), ExpandLabelError> {
    expand_label(SecretHash::Sha256, secret, label, context, out)
}

/// Fills `out` with HKDF-Expand-Label over `hash`, as [`hkdf_expand_label`] does over SHA-256.
pub(crate) fn expand_label(
    hash: SecretHash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), ExpandLabelError> {
    const PREFIX: &[u8] = b"tls13 ";
    let full_label_len =
        u8::try_from(PREFIX.len() + label.len()).map_err(|_| ExpandLabelError::TooLong)?;
    let context_len = u8::try_from(context.len()).map_err(|_| ExpandLabelError::TooLong)?;
    let out_len = u16::try_from(out.len()).map_err(|_| ExpandLabelError::TooLong)?;
    // The HkdfLabel structure, in pieces that HKDF-Expand concatenates.
    let out_len_bytes = out_len.to_be_bytes();
    let info: [&[u8]; 6] = [
        &out_len_bytes,
        &[full_label_len],
        PREFIX,
        label,
        &[context_len],
        context,
    ];
    let hash = match hash {
        SecretHash::Sha256 => hkdf::HKDF_SHA256,
        SecretHash::Sha384 => hkdf::HKDF_SHA384,
    };
    expand(hash, secret, &info, out)
}

/// Fills `out` with HKDF-Expand over SHA-256 (RFC 5869) of the pseudorandom key `prk`, with the
/// concatenation of the `info` parts as the info string. Fails with [`ExpandLabelError`] when
/// `prk` is longer than 64 bytes or `out` longer than 255 hash lengths.
pub fn hkdf_expand_sha256(
    prk: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), ExpandLabelError> {
    expand(hkdf::HKDF_SHA256, prk, info, out)
}

/// Fills `out` with HKDF-Expand of `prk` over `hash`, with the concatenation of the `info` parts.
fn expand(
    hash: hkdf::Algorithm,
    prk: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), ExpandLabelError> {
    if prk.len() > MAX_SECRET_LEN {
        return Err(ExpandLabelError::SecretTooLong);
    }
    hkdf::Prk::new_less_safe(hash, prk)
        .expand(info, OutLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| ExpandLabelError::TooLong)
}

/// An HKDF output length chosen at run time.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata::RFC9001_DCID;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn extract_matches_the_rfc9001_a1_initial_secret() {
        let salt = unhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        assert_eq!(
            hkdf_extract_sha256(&salt, &RFC9001_DCID).to_vec(),
            unhex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
    }

    #[test]
    fn expand_label_matches_rfc9001_a1() {
        let initial = unhex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
        let client = unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let cases: [(&[u8], &[u8], &str); 5] = [
            (
                &initial,
                b"client in",
                "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            ),
            (
                &initial,
                b"server in",
                "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
            ),
            (&client, b"quic key", "1f369613dd76d5467730efcbe3b1a22d"),
            (&client, b"quic iv", "fa044b2f42a3fd3b46fb255c"),
            (&client, b"quic hp", "9f50449e04a0e810283a1e9933adedd2"),
        ];
        for (secret, label, expected) in cases {
            let expected = unhex(expected);
            let mut out = vec![0; expected.len()];
            hkdf_expand_label(secret, label, &[], &mut out).unwrap();
            assert_eq!(out, expected, "{}", String::from_utf8_lossy(label));
        }
    }

    #[test]
    fn expand_label_derives_the_rfc9001_a5_key_update_secret() {
        let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let mut next = [0; SHA256_LEN];
        hkdf_expand_label(&secret, b"quic ku", &[], &mut next).unwrap();
        assert_eq!(
            next.to_vec(),
            unhex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );
    }

    #[test]
    fn expand_label_rejects_inputs_its_encoding_cannot_carry() {
        let secret = [7; SHA256_LEN];
        let mut out = [0; 16];
        let long_label = [b'a'; 250];
        let long_context = [0; 256];
        assert_eq!(
            hkdf_expand_label(&secret, &long_label, &[], &mut out),
            Err(ExpandLabelError::TooLong)
        );
        assert_eq!(
            hkdf_expand_label(&secret, b"quic key", &long_context, &mut out),
            Err(ExpandLabelError::TooLong)
        );
        let mut huge = vec![0; 255 * SHA256_LEN + 1];
        assert_eq!(
            hkdf_expand_label(&secret, b"quic key", &[], &mut huge),
            Err(ExpandLabelError::TooLong)
        );
        assert_eq!(out, [0; 16], "a refused expansion writes nothing");
    }

    /// RFC 5869 Appendix A test cases 1-3, the SHA-256 ones, from their pseudorandom keys. Each
    /// info string is also split into parts, which expand as their concatenation.
    #[test]
    fn expand_matches_rfc5869_sha256_cases_with_info_in_parts() {
        let info_2: Vec<u8> = (0xb0..=0xff).collect();
        let cases = [
            (
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                unhex("f0f1f2f3f4f5f6f7f8f9"),
                concat!(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                    "34007208d5b887185865",
                ),
            ),
            (
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                info_2,
                concat!(
                    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
                    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
                    "cc30c58179ec3e87c14c01d5c1f3434f1d87",
                ),
            ),
            (
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                Vec::new(),
                concat!(
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                    "9d201395faa4b61a96c8",
                ),
            ),
        ];
        for (prk, info, okm) in cases {
            let (prk, okm) = (unhex(prk), unhex(okm));
            let (head, tail) = info.split_at(info.len() / 3);
            for parts in [&[&info[..]][..], &[head, &[], tail]] {
                let mut out = vec![0; okm.len()];
                hkdf_expand_sha256(&prk, parts, &mut out).unwrap();
                assert_eq!(hex(&out), hex(&okm), "{} info parts", parts.len());
            }
        }
    }

    #[test]
    fn expand_refuses_a_long_output_or_key_and_writes_nothing() {
        let mut huge = vec![0; 255 * SHA256_LEN + 1];
        assert_eq!(
            hkdf_expand_sha256(&[7; SHA256_LEN], &[b"info"], &mut huge),
            Err(ExpandLabelError::TooLong)
        );
        assert!(
            huge.iter().all(|b| *b == 0),
            "a refused expansion writes nothing"
        );

        let mut out = [0; 16];
        assert_eq!(hkdf_expand_sha256(&[7; 64], &[b"info"], &mut out), Ok(()));
        let mut refused = [0; 16];
        assert_eq!(
            hkdf_expand_sha256(&[7; 65], &[b"info"], &mut refused),
            Err(ExpandLabelError::SecretTooLong)
        );
        assert_eq!(refused, [0; 16], "a refused expansion writes nothing");
    }

    #[test]
    fn expand_label_refuses_a_secret_longer_than_64_bytes() {
        let mut out = [0; 16];
        assert_eq!(
            hkdf_expand_label(&[7; 64], b"quic key", &[], &mut out),
            Ok(())
        );
        let mut refused = [0; 16];
        assert_eq!(
            hkdf_expand_label(&[7; 65], b"quic key", &[], &mut refused),
            Err(ExpandLabelError::SecretTooLong)
        );
        assert_eq!(refused, [0; 16], "a refused expansion writes nothing");
    }
}
