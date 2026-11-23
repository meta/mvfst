/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HKDF-Extract and HKDF-Expand-Label over SHA-256 (RFC 5869, RFC 8446).
//!
//! QUIC derives its Initial secrets, and the key, IV and header-protection key of any traffic
//! secret, with these functions (RFC 9001). Every secret mvfstr derives itself uses SHA-256;
//! rustls derives the Handshake and 1-RTT secrets with the negotiated suite's hash.

use std::fmt;

use crate::backend::digest;
use crate::backend::hkdf;
use crate::backend::hmac;

/// The SHA-256 output length, which is the length of an Initial secret.
pub const SHA256_LEN: usize = 32;

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

/// Why HKDF-Expand-Label refused its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandLabelError {
    /// The label (with its "tls13 " prefix) or the context is longer than 255 bytes, or the
    /// output is longer than 255 hash lengths.
    TooLong,
    /// The secret is longer than 64 bytes, the longest digest output.
    SecretTooLong,
}

impl fmt::Display for ExpandLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("HKDF-Expand-Label input or output too long"),
            Self::SecretTooLong => f.write_str("HKDF-Expand-Label secret longer than 64 bytes"),
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
    const PREFIX: &[u8] = b"tls13 ";
    if secret.len() > MAX_SECRET_LEN {
        return Err(ExpandLabelError::SecretTooLong);
    }
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
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    prk.expand(&info, OutLen(out.len()))
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
