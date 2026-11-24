/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HMAC with the shape of `ring::hmac`, over `sys`.

use super::HashAlg;
use super::digest::MAX_OUTPUT_LEN;
use super::sys;

/// An HMAC algorithm.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Algorithm(pub(super) HashAlg);

/// HMAC-SHA256.
pub(crate) static HMAC_SHA256: Algorithm = Algorithm(HashAlg::Sha256);

/// An HMAC key.
pub(crate) struct Key {
    alg: Algorithm,
    key: Vec<u8>,
}

impl Key {
    /// Makes a key of `algorithm` with the value `key_value`, of any length.
    pub(crate) fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {
        Key {
            alg: algorithm,
            key: key_value.to_vec(),
        }
    }

    /// Returns the tag length, which is the hash's output length.
    pub(super) fn tag_len(&self) -> usize {
        self.alg.0.output_len()
    }

    /// Returns the HMAC of the concatenation of `parts`.
    ///
    /// Like ring's, this does not return an error. It panics if the key is longer than `c_int::MAX`
    /// bytes, or if OpenSSL cannot allocate memory, where a Rust program aborts too.
    pub(super) fn sign_parts(&self, parts: &[&[u8]]) -> Tag {
        let len = self.tag_len();
        let mut buf = [0; MAX_OUTPUT_LEN];
        assert!(
            sys::hmac(self.alg.0, &self.key, parts, &mut buf[..len]),
            "the library failed an HMAC, which it does only when out of memory"
        );
        Tag { buf, len }
    }
}

/// An HMAC tag.
pub(crate) struct Tag {
    buf: [u8; MAX_OUTPUT_LEN],
    len: usize,
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Returns the HMAC of `data` under `key`.
pub(crate) fn sign(key: &Key, data: &[u8]) -> Tag {
    key.sign_parts(&[data])
}
