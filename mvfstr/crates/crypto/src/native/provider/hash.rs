/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SHA-256 and SHA-384 for the TLS 1.3 transcript.

use std::sync::Mutex;
use std::sync::PoisonError;

use rustls::crypto::hash;
use rustls::crypto::hash::HashAlgorithm;

use crate::native::HashAlg;
use crate::native::sys;

/// A hash function.
pub(super) struct Hash(HashAlg);

/// SHA-256.
pub(super) static SHA256: Hash = Hash(HashAlg::Sha256);

/// SHA-384.
pub(super) static SHA384: Hash = Hash(HashAlg::Sha384);

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Context(Mutex::new(sys::Hash::new(self.0))))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hash = sys::Hash::new(self.0);
        hash.update(data);
        finish(hash)
    }

    fn output_len(&self) -> usize {
        self.0.output_len()
    }

    fn algorithm(&self) -> HashAlgorithm {
        match self.0 {
            HashAlg::Sha256 => HashAlgorithm::SHA256,
            HashAlg::Sha384 => HashAlgorithm::SHA384,
        }
    }
}

/// A hash in progress. rustls requires it to be `Sync`, so the library context sits behind a
/// mutex.
struct Context(Mutex<sys::Hash>);

impl Context {
    fn hash(&self) -> std::sync::MutexGuard<'_, sys::Hash> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl hash::Context for Context {
    fn fork_finish(&self) -> hash::Output {
        finish(self.hash().fork())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Context(Mutex::new(self.hash().fork())))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        finish(self.0.into_inner().unwrap_or_else(PoisonError::into_inner))
    }

    fn update(&mut self, data: &[u8]) {
        self.0
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .update(data);
    }
}

fn finish(hash: sys::Hash) -> hash::Output {
    let mut out = [0; crate::native::digest::MAX_OUTPUT_LEN];
    let out = &mut out[..hash.output_len()];
    hash.finish(out);
    hash::Output::new(out)
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hash::Hash as _;

    use super::*;
    use crate::testdata::unhex;

    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                              8086072ba1e7cc2358baeca134c825a7";
    const SHA384_EMPTY: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                                274edebfe76f65fbd51ad2f14898b95b";

    #[test]
    fn sha256_and_sha384_match_fips_180_4() {
        for (hash, abc, empty) in [
            (&SHA256, SHA256_ABC, SHA256_EMPTY),
            (&SHA384, SHA384_ABC, SHA384_EMPTY),
        ] {
            assert_eq!(hash.hash(b"abc").as_ref(), unhex(abc));
            assert_eq!(hash.hash(b"").as_ref(), unhex(empty));
            assert_eq!(hash.start().finish().as_ref(), unhex(empty));
            assert_eq!(hash.output_len(), unhex(abc).len());

            let mut context = hash.start();
            context.update(b"a");
            context.update(b"");
            context.update(b"bc");
            assert_eq!(context.fork_finish().as_ref(), unhex(abc));
            assert_eq!(context.finish().as_ref(), unhex(abc));
        }
        assert_eq!(SHA256.algorithm(), HashAlgorithm::SHA256);
        assert_eq!(SHA384.algorithm(), HashAlgorithm::SHA384);
    }

    #[test]
    fn a_fork_goes_on_independently() {
        for (hash, abc, empty) in [
            (&SHA256, SHA256_ABC, SHA256_EMPTY),
            (&SHA384, SHA384_ABC, SHA384_EMPTY),
        ] {
            let mut original = hash.start();
            let mut fork = original.fork();
            fork.update(b"abc");
            assert_eq!(original.fork_finish().as_ref(), unhex(empty));
            original.update(b"ab");
            let mut second = original.fork();
            original.update(b"x");
            second.update(b"c");
            assert_eq!(fork.finish().as_ref(), unhex(abc));
            assert_eq!(second.finish().as_ref(), unhex(abc));
            assert_eq!(original.finish().as_ref(), hash.hash(b"abx").as_ref());
        }
    }
}
