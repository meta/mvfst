/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HMAC-SHA256 and HMAC-SHA384, under the suites' HKDF.

use rustls::crypto::hmac;

use crate::native::HashAlg;
use crate::native::hmac as shell;

/// An HMAC algorithm.
pub(super) struct Hmac(HashAlg);

/// HMAC-SHA256.
pub(super) static HMAC_SHA256: Hmac = Hmac(HashAlg::Sha256);

/// HMAC-SHA384.
pub(super) static HMAC_SHA384: Hmac = Hmac(HashAlg::Sha384);

impl hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(Key(shell::Key::new(shell::Algorithm(self.0), key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }
}

struct Key(shell::Key);

impl hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let parts: Vec<&[u8]> = std::iter::once(first)
            .chain(middle.iter().copied())
            .chain(std::iter::once(last))
            .collect();
        hmac::Tag::new(self.0.sign_parts(&parts).as_ref())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hmac::Hmac as _;
    use rustls::crypto::tls13::Hkdf;
    use rustls::crypto::tls13::HkdfUsingHmac;

    use super::*;
    use crate::testdata::unhex;

    /// RFC 4231 test cases 1-4: key, data, HMAC-SHA256, HMAC-SHA384.
    const RFC4231: [(&str, &str, &str, &str); 4] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
             dddddddddddddddddddddddddddddddddddd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
             2a5ab39dc13814b94e3ab6e101a34f27",
        ),
        (
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
             cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
             6801dd23c4a7d679ccf8a386c674cffb",
        ),
    ];

    #[test]
    fn hmac_sha256_and_sha384_match_rfc4231_cases_1_to_4() {
        for (key, data, sha256, sha384) in RFC4231 {
            let (key, data) = (unhex(key), unhex(data));
            for (hmac, expected) in [(&HMAC_SHA256, sha256), (&HMAC_SHA384, sha384)] {
                let key = hmac.with_key(&key);
                let expected = unhex(expected);
                assert_eq!(key.sign(&[&data]).as_ref(), expected);
                assert_eq!(key.tag_len(), expected.len());
                assert_eq!(hmac.hash_output_len(), expected.len());
                let (first, rest) = data.split_at(1);
                let (middle, last) = rest.split_at(rest.len() / 2);
                let (middle_a, middle_b) = middle.split_at(middle.len() / 2);
                assert_eq!(
                    key.sign_concat(first, &[middle_a, &[], middle_b], last)
                        .as_ref(),
                    expected
                );
                assert_eq!(key.sign_concat(&[], &[], &data).as_ref(), expected);
            }
        }
    }

    #[test]
    fn hkdf_sha256_over_this_hmac_matches_rfc5869_a_1() {
        let hkdf = HkdfUsingHmac(&HMAC_SHA256);
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0; 42];
        let (info_a, info_b) = info.split_at(3);
        expander.expand_slice(&[info_a, info_b], &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
        );
    }
}
