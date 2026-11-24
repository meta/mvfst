/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HKDF-Expand with the shape of `ring::hkdf`, computed over the HMAC of `sys` (RFC 5869).
//! The crate extracts with `hmac::sign`, so only the expand side is here.

use std::iter;

use super::HashAlg;
use super::Unspecified;
use super::digest::MAX_OUTPUT_LEN;
use super::hmac;

/// An HKDF algorithm, named by its HMAC.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Algorithm(hmac::Algorithm);

/// HKDF with HMAC-SHA256.
pub(crate) static HKDF_SHA256: Algorithm = Algorithm(hmac::Algorithm(HashAlg::Sha256));

/// HKDF with HMAC-SHA384, for the traffic secrets of SHA-384 cipher suites.
pub(crate) static HKDF_SHA384: Algorithm = Algorithm(hmac::Algorithm(HashAlg::Sha384));

/// The length of an HKDF output, as `ring::hkdf::KeyType`.
pub(crate) trait KeyType {
    /// Returns the output length in bytes.
    fn len(&self) -> usize;
}

/// A pseudorandom key.
pub(crate) struct Prk(hmac::Key);

impl Prk {
    /// Makes a pseudorandom key from bytes that the caller has already extracted.
    pub(crate) fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        Prk(hmac::Key::new(algorithm.0, value))
    }

    /// Returns the HKDF-Expand output of `len` bytes with `info`, the concatenation of its parts.
    /// Fails, as ring does, if `len` is more than 255 hash lengths.
    pub(crate) fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, Unspecified> {
        if len.len() > 255 * self.0.tag_len() {
            return Err(Unspecified);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
        })
    }
}

/// HKDF-Expand output, computed when it is filled.
pub(crate) struct Okm<'a, L> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
}

impl<L: KeyType> Okm<'_, L> {
    /// Writes the output into `out`, which must have the length passed to `expand`:
    /// T(i) = HMAC(PRK, T(i-1) | info | i), concatenated and truncated.
    pub(crate) fn fill(self, out: &mut [u8]) -> Result<(), Unspecified> {
        if out.len() != self.len.len() {
            return Err(Unspecified);
        }
        let mut previous = [0; MAX_OUTPUT_LEN];
        let mut previous_len = 0;
        for (i, chunk) in out.chunks_mut(self.prk.0.tag_len()).enumerate() {
            // `expand` caps the output at 255 blocks.
            let counter = [u8::try_from(i + 1).map_err(|_| Unspecified)?];
            let parts: Vec<&[u8]> = iter::once(&previous[..previous_len])
                .chain(self.info.iter().copied())
                .chain(iter::once(&counter[..]))
                .collect();
            let block = self.prk.0.sign_parts(&parts);
            let block = block.as_ref();
            chunk.copy_from_slice(&block[..chunk.len()]);
            previous[..block.len()].copy_from_slice(block);
            previous_len = block.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::crypto::tls13::OkmBlock;

    use super::*;
    use crate::testdata::unhex;

    struct Len(usize);

    impl KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    fn expand(prk: &[u8], info: &[&[u8]], len: usize) -> Result<Vec<u8>, Unspecified> {
        let prk = Prk::new_less_safe(HKDF_SHA256, prk);
        let mut out = vec![0; len];
        prk.expand(info, Len(len))?.fill(&mut out)?;
        Ok(out)
    }

    #[test]
    fn expand_matches_rfc5869_a1_to_a3() {
        // (PRK, info, OKM). A.1 and A.3 take two blocks, A.2 three.
        let cases = [
            (
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                (0xf0..=0xf9).collect::<Vec<u8>>(),
                concat!(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                    "34007208d5b887185865",
                ),
            ),
            (
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                (0xb0..=0xff).collect(),
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
            assert_eq!(expand(&prk, &[&info[..]], okm.len()), Ok(okm.clone()));
            let (head, tail) = info.split_at(info.len() / 2);
            let parts: [&[u8]; 3] = [head, &[], tail];
            assert_eq!(expand(&prk, &parts, okm.len()), Ok(okm), "info in parts");
        }
    }

    #[test]
    fn expand_matches_rings_up_to_255_blocks() {
        let prk: Vec<u8> = (0..32u8).map(|b| b.wrapping_mul(97) ^ 0x5c).collect();
        let info: [&[u8]; 2] = [b"mvfstr", &[0, 1, 2]];
        let ring = TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .hkdf_provider
            .expander_for_okm(&OkmBlock::new(&prk));
        for len in [0, 1, 31, 32, 33, 64, 65, 255, 255 * 32] {
            let mut theirs = vec![0; len];
            ring.expand_slice(&info, &mut theirs).unwrap();
            assert_eq!(expand(&prk, &info, len), Ok(theirs), "{len} bytes");
        }
        assert_eq!(expand(&prk, &info, 255 * 32 + 1), Err(Unspecified));
        assert!(ring.expand_slice(&info, &mut [0; 255 * 32 + 1]).is_err());
    }
}
