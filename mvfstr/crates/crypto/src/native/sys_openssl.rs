/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The only code in mvfstr that calls OpenSSL: `sys` over the raw functions of openssl-sys, for
//! the libcrypto that Fizz links, OpenSSL 1.1.1 or 3.x.
//!
//! Every function here keeps three rules:
//! - it uses only functions that have the same name in OpenSSL 1.1.1 and 3.x, so it does not use
//!   the getters that 3.0 renamed to `*_get_*`;
//! - it does not call `openssl_sys::init()`, which would pull in libssl's `OPENSSL_init_ssl`;
//!   OpenSSL 1.1.1 initialises libcrypto on first use;
//! - after a call fails, it empties the thread's error queue before returning, because Fizz and
//!   folly read the same queue.

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ptr;

use openssl_sys as ffi;

use super::AeadAlg;
use super::HashAlg;
use super::HeaderAlg;
use super::KxGroupId;
use super::SigHash;
use super::SigKind;

/// OpenSSL's `X509_PUBKEY`, which openssl-sys does not declare.
#[repr(C)]
struct X509Pubkey {
    _opaque: [u8; 0],
}

// openssl-sys 0.9.116 does not declare either function, and libcrypto exports both in OpenSSL
// 1.1.1 and 3.x. Together they give a certificate's own SubjectPublicKeyInfo encoding;
// `X509_get_pubkey` plus `i2d_PUBKEY` would decode the key and re-encode it, which fails on keys
// OpenSSL cannot decode and can rewrite the AlgorithmIdentifier.
unsafe extern "C" {
    fn X509_get_X509_PUBKEY(x: *const ffi::X509) -> *mut X509Pubkey;
    fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut u8) -> c_int;
}

/// `RSA_PSS_SALTLEN_DIGEST`, the same in OpenSSL 1.1.1 and 3.x; openssl-sys does not define it.
const RSA_PSS_SALTLEN_DIGEST: c_int = -1;

/// The tag length of the AEADs.
const TAG_LEN: usize = 16;

/// The length of a QUIC header-protection mask.
const MASK_LEN: usize = 5;

/// An owned OpenSSL object, freed when dropped.
struct Owned<T> {
    ptr: *mut T,
    free: unsafe extern "C" fn(*mut T),
}

impl<T> Owned<T> {
    /// Takes ownership of an OpenSSL constructor's result, or returns `None` if it is NULL.
    fn new(ptr: *mut T, free: unsafe extern "C" fn(*mut T)) -> Option<Self> {
        (!ptr.is_null()).then_some(Owned { ptr, free })
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live object that only this value owns, and `free` is its destructor.
        unsafe { (self.free)(self.ptr) }
    }
}

/// Empties the calling thread's OpenSSL error queue.
fn clear_errors() {
    // SAFETY: `ERR_clear_error` does not take arguments and touches only this thread's error
    // queue.
    unsafe { ffi::ERR_clear_error() }
}

/// Returns `result`, after emptying the error queue if it is a failure.
fn checked<T>(result: Option<T>) -> Option<T> {
    if result.is_none() {
        clear_errors();
    }
    result
}

/// Returns the value of an OpenSSL call that fails only when OpenSSL cannot allocate memory.
/// Panics if the call failed: a Rust program aborts when it runs out of memory too.
fn allocated<T>(result: Option<T>, what: &str) -> T {
    match result {
        Some(value) => value,
        None => {
            clear_errors();
            panic!("OpenSSL could not {what}, which happens only when it is out of memory");
        }
    }
}

/// Returns a cipher context with its cipher and key set.
fn cipher_context(
    cipher: *const ffi::EVP_CIPHER,
    key: &[u8],
) -> Option<Owned<ffi::EVP_CIPHER_CTX>> {
    // SAFETY: allocates a context, or returns NULL.
    let ctx = Owned::new(
        unsafe { ffi::EVP_CIPHER_CTX_new() },
        ffi::EVP_CIPHER_CTX_free,
    )?;
    // SAFETY: `ctx` is a fresh context and `cipher` a static descriptor. The callers check that
    // `key` has the cipher's key length; OpenSSL copies it.
    let ok = unsafe {
        ffi::EVP_EncryptInit_ex(ctx.ptr, cipher, ptr::null_mut(), key.as_ptr(), ptr::null())
    } == 1;
    ok.then_some(ctx)
}

/// An AEAD key: one cipher context with the key set once, given a nonce per packet.
pub(crate) struct AeadKey(Owned<ffi::EVP_CIPHER_CTX>);

// SAFETY: an OpenSSL cipher context is not tied to the thread that made it, and only the owner of
// this value can reach it, so moving the value moves every access to the context.
unsafe impl Send for AeadKey {}

impl AeadKey {
    /// Makes a key of `alg`, or returns `None` if `key` is not the algorithm's key length.
    pub(crate) fn new(alg: AeadAlg, key: &[u8]) -> Option<Self> {
        if key.len() != alg.key_len() {
            return None;
        }
        // SAFETY: the cipher getters do not take arguments and return static descriptors.
        let cipher = unsafe {
            match alg {
                AeadAlg::Aes128Gcm => ffi::EVP_aes_128_gcm(),
                AeadAlg::Aes256Gcm => ffi::EVP_aes_256_gcm(),
                AeadAlg::ChaCha20Poly1305 => ffi::EVP_chacha20_poly1305(),
            }
        };
        checked(cipher_context(cipher, key)).map(AeadKey)
    }

    /// Encrypts `in_out` in place under `nonce` and `aad`, and writes the tag.
    pub(crate) fn seal(
        &mut self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> bool {
        checked(self.seal_inner(nonce, aad, in_out, tag)).is_some()
    }

    fn seal_inner(
        &mut self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Option<()> {
        let ctx = self.0.ptr;
        // SAFETY: `ctx` has its cipher and key set; with a NULL cipher and key, this only sets the
        // 12-byte nonce, the AEADs' default length, and the direction.
        let ok = unsafe {
            ffi::EVP_EncryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                nonce.as_ptr(),
            )
        } == 1;
        if !ok {
            return None;
        }
        self.update(aad, in_out)?;
        let mut last = [0u8; TAG_LEN];
        let mut last_len: c_int = 0;
        // SAFETY: `ctx` is mid-encryption; an AEAD's final step does not write output, and `last`
        // would hold a block if it did. The tag control writes 16 bytes into `tag`.
        let ok = unsafe {
            ffi::EVP_EncryptFinal_ex(ctx, last.as_mut_ptr(), &mut last_len) == 1
                && ffi::EVP_CIPHER_CTX_ctrl(
                    ctx,
                    ffi::EVP_CTRL_GCM_GET_TAG,
                    TAG_LEN as c_int,
                    tag.as_mut_ptr().cast::<c_void>(),
                ) == 1
        };
        (ok && last_len == 0).then_some(())
    }

    /// Decrypts `in_out` in place under `nonce` and `aad`; false if `tag` does not authenticate
    /// it, in which case `in_out` holds unauthenticated plaintext the caller must discard.
    pub(crate) fn open(
        &mut self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> bool {
        checked(self.open_inner(nonce, aad, in_out, tag)).is_some()
    }

    fn open_inner(
        &mut self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Option<()> {
        let ctx = self.0.ptr;
        // SAFETY: as in `seal_inner`, this sets the nonce and the direction only.
        let ok = unsafe {
            ffi::EVP_DecryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                nonce.as_ptr(),
            )
        } == 1;
        if !ok {
            return None;
        }
        self.update(aad, in_out)?;
        let mut last = [0u8; TAG_LEN];
        let mut last_len: c_int = 0;
        // SAFETY: `ctx` is mid-decryption. The tag control copies 16 bytes from `tag` and does not
        // write through the pointer. The final step checks the tag and does not write output.
        let ok = unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                ctx,
                ffi::EVP_CTRL_GCM_SET_TAG,
                TAG_LEN as c_int,
                tag.as_ptr().cast_mut().cast::<c_void>(),
            ) == 1
                && ffi::EVP_DecryptFinal_ex(ctx, last.as_mut_ptr(), &mut last_len) == 1
        };
        (ok && last_len == 0).then_some(())
    }

    /// Feeds the associated data, then transforms `in_out` in place, in the direction the last
    /// init set.
    fn update(&mut self, aad: &[u8], in_out: &mut [u8]) -> Option<()> {
        let ctx = self.0.ptr;
        let aad_len = c_int::try_from(aad.len()).ok()?;
        let len = c_int::try_from(in_out.len()).ok()?;
        let mut out_len: c_int = 0;
        // `EVP_CipherUpdate` follows the direction of the last init; a NULL output pointer makes
        // the input associated data.
        if !aad.is_empty() {
            // SAFETY: `ctx` has a nonce set, and `aad` is valid for `aad_len` bytes.
            let ok = unsafe {
                ffi::EVP_CipherUpdate(ctx, ptr::null_mut(), &mut out_len, aad.as_ptr(), aad_len)
            } == 1;
            if !ok {
                return None;
            }
        }
        if !in_out.is_empty() {
            let data = in_out.as_mut_ptr();
            // SAFETY: `data` is valid for `len` bytes of reading and writing. The AEADs process
            // exact in-place updates and write exactly `len` bytes.
            let ok = unsafe { ffi::EVP_CipherUpdate(ctx, data, &mut out_len, data, len) } == 1;
            if !ok || out_len != len {
                return None;
            }
        }
        Some(())
    }
}

/// A QUIC header-protection key.
pub(crate) struct HeaderKey {
    ctx: Owned<ffi::EVP_CIPHER_CTX>,
    alg: HeaderAlg,
}

// SAFETY: as for `AeadKey`, the context is reachable only through this value's owner.
unsafe impl Send for HeaderKey {}

impl HeaderKey {
    /// Makes a key of `alg`, or returns `None` if `key` is not the cipher's key length.
    pub(crate) fn new(alg: HeaderAlg, key: &[u8]) -> Option<Self> {
        if key.len() != alg.key_len() {
            return None;
        }
        checked(Self::new_inner(alg, key))
    }

    fn new_inner(alg: HeaderAlg, key: &[u8]) -> Option<Self> {
        // SAFETY: the cipher getters do not take arguments and return static descriptors.
        let cipher = unsafe {
            match alg {
                HeaderAlg::Aes128 => ffi::EVP_aes_128_ecb(),
                HeaderAlg::Aes256 => ffi::EVP_aes_256_ecb(),
                HeaderAlg::ChaCha20 => ffi::EVP_chacha20(),
            }
        };
        let ctx = cipher_context(cipher, key)?;
        if alg != HeaderAlg::ChaCha20 {
            // SAFETY: `ctx` is a live ECB context; with padding off, each update of one block
            // writes exactly that block.
            let ok = unsafe { ffi::EVP_CIPHER_CTX_set_padding(ctx.ptr, 0) } == 1;
            if !ok {
                return None;
            }
        }
        Some(HeaderKey { ctx, alg })
    }

    /// Returns the mask for a 16-byte ciphertext sample (RFC 9001).
    pub(crate) fn mask(&mut self, sample: &[u8; 16]) -> Option<[u8; MASK_LEN]> {
        checked(self.mask_inner(sample))
    }

    fn mask_inner(&mut self, sample: &[u8; 16]) -> Option<[u8; MASK_LEN]> {
        let ctx = self.ctx.ptr;
        // OpenSSL requires room for the input plus one block.
        let mut out = [0u8; 32];
        let mut out_len: c_int = 0;
        let expected = match self.alg {
            HeaderAlg::Aes128 | HeaderAlg::Aes256 => {
                // SAFETY: `ctx` is an ECB context with its key set and padding off; `sample` is one
                // block and `out` has room for two.
                let ok = unsafe {
                    ffi::EVP_EncryptUpdate(ctx, out.as_mut_ptr(), &mut out_len, sample.as_ptr(), 16)
                } == 1;
                ok.then_some(16)?
            }
            HeaderAlg::ChaCha20 => {
                // OpenSSL's 16-byte ChaCha20 IV is a little-endian block counter followed by the
                // nonce, the layout RFC 9001 gives the sample. The mask is the keystream, that is
                // the encryption of five zero bytes.
                let zeros = [0u8; MASK_LEN];
                // SAFETY: `ctx` has its key set; with a NULL cipher and key, the init sets the IV
                // from the 16 bytes of `sample`. The update reads 5 bytes and writes 5 into `out`.
                let ok = unsafe {
                    ffi::EVP_EncryptInit_ex(
                        ctx,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                        sample.as_ptr(),
                    ) == 1
                        && ffi::EVP_EncryptUpdate(
                            ctx,
                            out.as_mut_ptr(),
                            &mut out_len,
                            zeros.as_ptr(),
                            MASK_LEN as c_int,
                        ) == 1
                };
                ok.then_some(MASK_LEN as c_int)?
            }
        };
        if out_len != expected {
            return None;
        }
        let mut mask = [0; MASK_LEN];
        mask.copy_from_slice(&out[..MASK_LEN]);
        Some(mask)
    }
}

/// Returns the message digest of `alg`.
fn message_digest(alg: HashAlg) -> *const ffi::EVP_MD {
    // SAFETY: the digest getters do not take arguments and return static descriptors.
    unsafe {
        match alg {
            HashAlg::Sha256 => ffi::EVP_sha256(),
            HashAlg::Sha384 => ffi::EVP_sha384(),
        }
    }
}

/// An incremental SHA-256 or SHA-384.
pub(crate) struct Hash {
    ctx: Owned<ffi::EVP_MD_CTX>,
    alg: HashAlg,
}

// SAFETY: as for `AeadKey`, the context is reachable only through this value's owner.
unsafe impl Send for Hash {}

impl Hash {
    /// Starts a hash of `alg`.
    pub(crate) fn new(alg: HashAlg) -> Self {
        let ctx = Self::context();
        // SAFETY: `ctx` is a fresh context and the digest a static descriptor.
        let ok =
            unsafe { ffi::EVP_DigestInit_ex(ctx.ptr, message_digest(alg), ptr::null_mut()) } == 1;
        allocated(ok.then_some(()), "start a hash");
        Hash { ctx, alg }
    }

    fn context() -> Owned<ffi::EVP_MD_CTX> {
        // SAFETY: allocates a context, or returns NULL.
        let ctx = Owned::new(unsafe { ffi::EVP_MD_CTX_new() }, ffi::EVP_MD_CTX_free);
        allocated(ctx, "allocate a digest context")
    }

    /// Adds `data` to the hash.
    pub(crate) fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // SAFETY: the context is initialised and `data` is valid for its length.
        let ok = unsafe {
            ffi::EVP_DigestUpdate(self.ctx.ptr, data.as_ptr().cast::<c_void>(), data.len())
        } == 1;
        allocated(ok.then_some(()), "update a hash");
    }

    /// Returns a copy of the hash in its current state, which then goes on independently.
    pub(crate) fn fork(&self) -> Self {
        let ctx = Self::context();
        // SAFETY: both contexts are live; the copy duplicates the source's state into `ctx`.
        let ok = unsafe { ffi::EVP_MD_CTX_copy_ex(ctx.ptr, self.ctx.ptr) } == 1;
        allocated(ok.then_some(()), "copy a hash");
        Hash { ctx, alg: self.alg }
    }

    /// Returns the digest length in bytes.
    pub(crate) fn output_len(&self) -> usize {
        self.alg.output_len()
    }

    /// Writes the digest into `out`. Panics if `out` is not the hash's output length.
    pub(crate) fn finish(self, out: &mut [u8]) {
        assert_eq!(out.len(), self.alg.output_len(), "digest buffer length");
        let mut len: c_uint = 0;
        // SAFETY: the context is initialised, and `out` holds the digest's output length, checked
        // above, which is what the call writes.
        let ok = unsafe { ffi::EVP_DigestFinal_ex(self.ctx.ptr, out.as_mut_ptr(), &mut len) } == 1;
        allocated(
            (ok && len as usize == out.len()).then_some(()),
            "finish a hash",
        );
    }
}

/// Writes the HMAC with `alg` under `key` of the concatenation of `parts` into `out`. Returns
/// false if `out` is not the hash's output length or OpenSSL fails.
pub(crate) fn hmac(alg: HashAlg, key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> bool {
    if out.len() != alg.output_len() {
        return false;
    }
    checked(hmac_inner(alg, key, parts, out)).is_some()
}

fn hmac_inner(alg: HashAlg, key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Option<()> {
    let key_len = c_int::try_from(key.len()).ok()?;
    // SAFETY: allocates a context, or returns NULL.
    let ctx = Owned::new(unsafe { ffi::HMAC_CTX_new() }, ffi::HMAC_CTX_free)?;
    // SAFETY: `ctx` is fresh and the digest a static descriptor. `key` is valid for `key_len`
    // bytes and never NULL, even when empty, so OpenSSL takes it as the key rather than reusing
    // an earlier one.
    let ok = unsafe {
        ffi::HMAC_Init_ex(
            ctx.ptr,
            key.as_ptr().cast::<c_void>(),
            key_len,
            message_digest(alg),
            ptr::null_mut(),
        )
    } == 1;
    if !ok {
        return None;
    }
    for part in parts.iter().filter(|part| !part.is_empty()) {
        // SAFETY: `ctx` is initialised and `part` is valid for its length.
        let ok = unsafe { ffi::HMAC_Update(ctx.ptr, part.as_ptr(), part.len()) } == 1;
        if !ok {
            return None;
        }
    }
    let mut len: c_uint = 0;
    // SAFETY: `out` holds the hash's output length, checked by `hmac`, which is what this writes.
    let ok = unsafe { ffi::HMAC_Final(ctx.ptr, out.as_mut_ptr(), &mut len) } == 1;
    (ok && len as usize == out.len()).then_some(())
}

/// The length of an X25519 key or shared secret, and of a P-256 shared secret.
const KX_SECRET_LEN: usize = 32;

/// The length of an uncompressed P-256 point.
const P256_POINT_LEN: usize = 65;

/// An ephemeral key exchange key.
pub(crate) struct KxKey {
    pkey: Owned<ffi::EVP_PKEY>,
    group: KxGroupId,
}

// SAFETY: as for `AeadKey`, the key is reachable only through this value's owner.
unsafe impl Send for KxKey {}

impl KxKey {
    /// Generates a fresh key pair in `group`, with its public value: 32 bytes for X25519, an
    /// uncompressed point for P-256.
    pub(crate) fn generate(group: KxGroupId) -> Option<(Self, Vec<u8>)> {
        checked(match group {
            KxGroupId::X25519 => generate_x25519(),
            KxGroupId::Secp256r1 => generate_p256(),
        })
    }

    /// Returns the shared secret with the peer's public value, or `None` if the value is malformed,
    /// is not on the curve, or does not give a secret (OpenSSL refuses an all-zero X25519 result).
    pub(crate) fn agree(self, peer: &[u8]) -> Option<Vec<u8>> {
        checked(self.agree_inner(peer))
    }

    fn agree_inner(&self, peer: &[u8]) -> Option<Vec<u8>> {
        let peer = match self.group {
            KxGroupId::X25519 => x25519_peer(peer)?,
            KxGroupId::Secp256r1 => p256_peer(peer)?,
        };
        derive(&self.pkey, &peer)
    }

    /// Returns the X25519 key with the private scalar `scalar`, as RFC 7748 writes it (OpenSSL
    /// clamps it), and its public value.
    #[cfg(test)]
    pub(crate) fn x25519_from_private(scalar: &[u8; 32]) -> Option<(Self, [u8; 32])> {
        let make = || {
            // SAFETY: `scalar` is valid for 32 bytes, which OpenSSL copies.
            let pkey = unsafe {
                ffi::EVP_PKEY_new_raw_private_key(
                    ffi::EVP_PKEY_X25519,
                    ptr::null_mut(),
                    scalar.as_ptr(),
                    scalar.len(),
                )
            };
            let pkey = Owned::new(pkey, ffi::EVP_PKEY_free)?;
            let public = x25519_public(&pkey)?;
            let key = KxKey {
                pkey,
                group: KxGroupId::X25519,
            };
            Some((key, public))
        };
        checked(make())
    }
}

fn generate_x25519() -> Option<(KxKey, Vec<u8>)> {
    // SAFETY: allocates a key generation context for X25519, or returns NULL.
    let ctx = unsafe { ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_X25519, ptr::null_mut()) };
    let ctx = Owned::new(ctx, ffi::EVP_PKEY_CTX_free)?;
    let mut pkey = ptr::null_mut();
    // SAFETY: `ctx` is live; keygen stores a new key, which this function then owns, in `pkey`.
    let ok = unsafe {
        ffi::EVP_PKEY_keygen_init(ctx.ptr) == 1 && ffi::EVP_PKEY_keygen(ctx.ptr, &mut pkey) == 1
    };
    let pkey = Owned::new(pkey, ffi::EVP_PKEY_free)?;
    if !ok {
        return None;
    }
    let public = x25519_public(&pkey)?;
    let key = KxKey {
        pkey,
        group: KxGroupId::X25519,
    };
    Some((key, public.to_vec()))
}

fn x25519_public(pkey: &Owned<ffi::EVP_PKEY>) -> Option<[u8; KX_SECRET_LEN]> {
    let mut public = [0u8; KX_SECRET_LEN];
    let mut len = public.len();
    // SAFETY: `pkey` is a live X25519 key; OpenSSL writes at most `len` bytes into `public`.
    let ok =
        unsafe { ffi::EVP_PKEY_get_raw_public_key(pkey.ptr, public.as_mut_ptr(), &mut len) } == 1;
    (ok && len == KX_SECRET_LEN).then_some(public)
}

fn x25519_peer(peer: &[u8]) -> Option<Owned<ffi::EVP_PKEY>> {
    if peer.len() != KX_SECRET_LEN {
        return None;
    }
    // SAFETY: `peer` is valid for its 32 bytes, which OpenSSL copies.
    let pkey = unsafe {
        ffi::EVP_PKEY_new_raw_public_key(
            ffi::EVP_PKEY_X25519,
            ptr::null_mut(),
            peer.as_ptr(),
            peer.len(),
        )
    };
    Owned::new(pkey, ffi::EVP_PKEY_free)
}

/// Returns a new key on P-256.
fn p256_key() -> Option<Owned<ffi::EC_KEY>> {
    // SAFETY: allocates a key on the named curve, or returns NULL.
    let ec = unsafe { ffi::EC_KEY_new_by_curve_name(ffi::NID_X9_62_prime256v1) };
    Owned::new(ec, ffi::EC_KEY_free)
}

/// Returns an `EVP_PKEY` that holds its own reference to `ec`.
fn wrap_ec_key(ec: &Owned<ffi::EC_KEY>) -> Option<Owned<ffi::EVP_PKEY>> {
    // SAFETY: allocates an empty key, or returns NULL.
    let pkey = Owned::new(unsafe { ffi::EVP_PKEY_new() }, ffi::EVP_PKEY_free)?;
    // SAFETY: both are live; `set1` takes a new reference to `ec`, so `ec` keeps its own.
    let ok = unsafe { ffi::EVP_PKEY_set1_EC_KEY(pkey.ptr, ec.ptr) } == 1;
    ok.then_some(pkey)
}

fn generate_p256() -> Option<(KxKey, Vec<u8>)> {
    let ec = p256_key()?;
    // SAFETY: `ec` is a live key on P-256.
    if unsafe { ffi::EC_KEY_generate_key(ec.ptr) } != 1 {
        return None;
    }
    let mut public = vec![0u8; P256_POINT_LEN];
    // SAFETY: `ec` has a group and, now, a public key, both borrowed from it for this call;
    // OpenSSL writes at most `public.len()` bytes.
    let written = unsafe {
        ffi::EC_POINT_point2oct(
            ffi::EC_KEY_get0_group(ec.ptr),
            ffi::EC_KEY_get0_public_key(ec.ptr),
            ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
            public.as_mut_ptr(),
            public.len(),
            ptr::null_mut(),
        )
    };
    if written != P256_POINT_LEN {
        return None;
    }
    let pkey = wrap_ec_key(&ec)?;
    let key = KxKey {
        pkey,
        group: KxGroupId::Secp256r1,
    };
    Some((key, public))
}

fn p256_peer(peer: &[u8]) -> Option<Owned<ffi::EVP_PKEY>> {
    // RFC 8446 allows only uncompressed points in TLS 1.3 key shares.
    if peer.len() != P256_POINT_LEN || peer[0] != 0x04 {
        return None;
    }
    let ec = p256_key()?;
    // SAFETY: `ec` is live; the group is borrowed from it.
    let group = unsafe { ffi::EC_KEY_get0_group(ec.ptr) };
    // SAFETY: `group` is P-256's; this allocates a point on it, or returns NULL.
    let point = Owned::new(unsafe { ffi::EC_POINT_new(group) }, ffi::EC_POINT_free)?;
    // SAFETY: `peer` is valid for its length. `EC_POINT_oct2point` rejects a point that is not on
    // the curve, and `EC_KEY_set_public_key` copies the point.
    let ok = unsafe {
        ffi::EC_POINT_oct2point(group, point.ptr, peer.as_ptr(), peer.len(), ptr::null_mut()) == 1
            && ffi::EC_KEY_set_public_key(ec.ptr, point.ptr) == 1
    };
    if !ok {
        return None;
    }
    wrap_ec_key(&ec)
}

/// Returns the 32-byte shared secret of `ours` with `peer`.
fn derive(ours: &Owned<ffi::EVP_PKEY>, peer: &Owned<ffi::EVP_PKEY>) -> Option<Vec<u8>> {
    // SAFETY: `ours` is live; the context takes its own reference to it.
    let ctx = Owned::new(
        unsafe { ffi::EVP_PKEY_CTX_new(ours.ptr, ptr::null_mut()) },
        ffi::EVP_PKEY_CTX_free,
    )?;
    let mut len = 0;
    // SAFETY: `ctx` and `peer` are live, and the context takes its own reference to `peer`. With
    // a NULL output, `EVP_PKEY_derive` only reports the secret's length.
    let ok = unsafe {
        ffi::EVP_PKEY_derive_init(ctx.ptr) == 1
            && ffi::EVP_PKEY_derive_set_peer(ctx.ptr, peer.ptr) == 1
            && ffi::EVP_PKEY_derive(ctx.ptr, ptr::null_mut(), &mut len) == 1
    };
    if !ok || len != KX_SECRET_LEN {
        return None;
    }
    let mut secret = vec![0u8; len];
    // SAFETY: `secret` holds the `len` bytes the derivation writes.
    let ok = unsafe { ffi::EVP_PKEY_derive(ctx.ptr, secret.as_mut_ptr(), &mut len) } == 1;
    (ok && len == KX_SECRET_LEN).then_some(secret)
}

/// Returns whether `sig` is a valid signature of `msg` under the DER SubjectPublicKeyInfo
/// `spki_der`, for a key of `kind` with `hash`, within ring's limits: an RSA modulus of 2048 to
/// 8192 bits (counted in whole bytes at the low end, as ring does), an odd public exponent from 3
/// to 2^33 - 1, PSS with a salt as long as the hash and MGF1 over it, and the curve that `kind`
/// names.
pub(crate) fn verify(
    kind: SigKind,
    hash: SigHash,
    spki_der: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> bool {
    checked(verify_inner(kind, hash, spki_der, msg, sig)).is_some()
}

fn verify_inner(
    kind: SigKind,
    hash: SigHash,
    spki_der: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Option<()> {
    // Ed25519 signs the message itself; every other kind signs a digest of it.
    if (kind == SigKind::Ed25519) != (hash == SigHash::None) {
        return None;
    }
    let pkey = public_key(spki_der)?;
    match kind {
        SigKind::RsaPkcs1 | SigKind::RsaPss => rsa_within_limits(&pkey)?,
        SigKind::EcP256 => curve_is(&pkey, ffi::NID_X9_62_prime256v1)?,
        SigKind::EcP384 => curve_is(&pkey, ffi::NID_secp384r1)?,
        SigKind::Ed25519 => {}
    }
    // SAFETY: the digest getters do not take arguments and return static descriptors.
    let md = unsafe {
        match hash {
            SigHash::Sha256 => ffi::EVP_sha256(),
            SigHash::Sha384 => ffi::EVP_sha384(),
            SigHash::Sha512 => ffi::EVP_sha512(),
            SigHash::None => ptr::null(),
        }
    };
    // SAFETY: allocates a context, or returns NULL.
    let mctx = Owned::new(unsafe { ffi::EVP_MD_CTX_new() }, ffi::EVP_MD_CTX_free)?;
    let mut pctx = ptr::null_mut();
    // SAFETY: `mctx` is fresh and `pkey` live; `pctx` receives a key context that `mctx` owns.
    // A NULL digest is what Ed25519 takes.
    let ok =
        unsafe { ffi::EVP_DigestVerifyInit(mctx.ptr, &mut pctx, md, ptr::null_mut(), pkey.ptr) }
            == 1;
    if !ok {
        return None;
    }
    match kind {
        SigKind::RsaPss => {
            rsa_control(
                pctx,
                ffi::EVP_PKEY_CTRL_RSA_PADDING,
                ffi::RSA_PKCS1_PSS_PADDING,
                ptr::null_mut(),
            )?;
            rsa_control(
                pctx,
                ffi::EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                RSA_PSS_SALTLEN_DIGEST,
                ptr::null_mut(),
            )?;
            rsa_control(
                pctx,
                ffi::EVP_PKEY_CTRL_RSA_MGF1_MD,
                0,
                md.cast_mut().cast::<c_void>(),
            )?;
        }
        SigKind::RsaPkcs1 => {
            rsa_control(
                pctx,
                ffi::EVP_PKEY_CTRL_RSA_PADDING,
                ffi::RSA_PKCS1_PADDING,
                ptr::null_mut(),
            )?;
        }
        SigKind::EcP256 | SigKind::EcP384 | SigKind::Ed25519 => {}
    }
    // SAFETY: `mctx` is initialised for verification; `sig` and `msg` are valid for their lengths.
    let ok = unsafe {
        ffi::EVP_DigestVerify(mctx.ptr, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len())
    } == 1;
    ok.then_some(())
}

/// Parses the public key in a DER SubjectPublicKeyInfo, which must be the whole input.
fn public_key(spki_der: &[u8]) -> Option<Owned<ffi::EVP_PKEY>> {
    let len = c_long::try_from(spki_der.len()).ok()?;
    let mut next = spki_der.as_ptr();
    // SAFETY: `next` points at `len` readable bytes; OpenSSL advances it past what it parses.
    let pkey = unsafe { ffi::d2i_PUBKEY(ptr::null_mut(), &mut next, len) };
    let pkey = Owned::new(pkey, ffi::EVP_PKEY_free)?;
    (next == spki_der.as_ptr().wrapping_add(spki_der.len())).then_some(pkey)
}

/// Sets an RSA parameter on a verification context.
///
/// The openssl-sys wrappers name the operations with OpenSSL 1.1.1's bit values, which 3.x
/// renumbered; an operation of -1 matches any operation in both.
fn rsa_control(pctx: *mut ffi::EVP_PKEY_CTX, cmd: c_int, p1: c_int, p2: *mut c_void) -> Option<()> {
    // SAFETY: `pctx` is the live key context of an RSA verification; the RSA controls used here
    // read `p2` only as a digest descriptor or ignore it.
    let ok = unsafe { ffi::EVP_PKEY_CTX_ctrl(pctx, ffi::EVP_PKEY_RSA, -1, cmd, p1, p2) } > 0;
    ok.then_some(())
}

/// Checks that an RSA key is within ring's limits for these algorithms.
fn rsa_within_limits(pkey: &Owned<ffi::EVP_PKEY>) -> Option<()> {
    // SAFETY: `pkey` is live; this returns a new reference to its RSA key, or NULL if it does not
    // have one.
    let rsa = Owned::new(unsafe { ffi::EVP_PKEY_get1_RSA(pkey.ptr) }, ffi::RSA_free)?;
    let (mut n, mut e) = (ptr::null(), ptr::null());
    // SAFETY: `rsa` is live; this stores borrowed pointers to its modulus and exponent, valid
    // while `rsa` is, and skips the NULL out-pointer for the private exponent.
    unsafe { ffi::RSA_get0_key(rsa.ptr, &mut n, &mut e, ptr::null_mut()) };
    if n.is_null() || e.is_null() {
        return None;
    }
    // SAFETY: `n` and `e` are live numbers owned by `rsa`.
    let (n_bits, n_odd, e_bits, e_odd, negative) = unsafe {
        (
            ffi::BN_num_bits(n),
            ffi::BN_is_odd(n) == 1,
            ffi::BN_num_bits(e),
            ffi::BN_is_odd(e) == 1,
            ffi::BN_is_negative(n) != 0 || ffi::BN_is_negative(e) != 0,
        )
    };
    // ring compares the modulus length rounded up to whole bytes with the minimum, and its exact
    // bit length with the maximum.
    let n_ok = n_odd && (n_bits + 7) / 8 * 8 >= 2048 && n_bits <= 8192;
    // Odd with at least 2 bits is at least 3; at most 33 bits is below 2^33.
    let e_ok = e_odd && (2..=33).contains(&e_bits);
    (!negative && n_ok && e_ok).then_some(())
}

/// Checks that an EC key is on the curve `nid`.
fn curve_is(pkey: &Owned<ffi::EVP_PKEY>, nid: c_int) -> Option<()> {
    // SAFETY: `pkey` is live; this returns a new reference to its EC key, or NULL if it does not
    // have one.
    let ec = Owned::new(
        unsafe { ffi::EVP_PKEY_get1_EC_KEY(pkey.ptr) },
        ffi::EC_KEY_free,
    )?;
    // SAFETY: `ec` is live; the group is borrowed from it.
    let group = unsafe { ffi::EC_KEY_get0_group(ec.ptr) };
    if group.is_null() {
        return None;
    }
    // SAFETY: `group` is live while `ec` is.
    let curve = unsafe { ffi::EC_GROUP_get_curve_name(group) };
    (curve == nid).then_some(())
}

/// Returns the DER SubjectPublicKeyInfo of the DER certificate `cert_der`, as the certificate
/// encodes it, or `None` unless OpenSSL parses the whole input as one certificate.
pub(crate) fn cert_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    checked(cert_spki_inner(cert_der))
}

fn cert_spki_inner(cert_der: &[u8]) -> Option<Vec<u8>> {
    let len = c_long::try_from(cert_der.len()).ok()?;
    let mut next = cert_der.as_ptr();
    // SAFETY: `next` points at `len` readable bytes; OpenSSL advances it past what it parses.
    let cert = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut next, len) };
    let cert = Owned::new(cert, ffi::X509_free)?;
    if next != cert_der.as_ptr().wrapping_add(cert_der.len()) {
        return None;
    }
    // SAFETY: `cert` is live; the key is borrowed from it.
    let key = unsafe { X509_get_X509_PUBKEY(cert.ptr) };
    if key.is_null() {
        return None;
    }
    // SAFETY: `key` is live while `cert` is; with a NULL output, this only returns the length.
    let spki_len = unsafe { i2d_X509_PUBKEY(key, ptr::null_mut()) };
    let spki_len = usize::try_from(spki_len).ok().filter(|&len| len > 0)?;
    let mut spki = vec![0u8; spki_len];
    let mut out = spki.as_mut_ptr();
    // SAFETY: `out` points at `spki_len` bytes, the length of the encoding.
    let written = unsafe { i2d_X509_PUBKEY(key, &mut out) };
    (usize::try_from(written).ok() == Some(spki_len)).then_some(spki)
}

/// Fills `dest` from OpenSSL's random number generator.
pub(crate) fn fill_random(dest: &mut [u8]) -> bool {
    let filled = dest.chunks_mut(c_int::MAX as usize).all(|chunk| {
        // SAFETY: `chunk` is valid for writing its length, which fits a `c_int`.
        unsafe { ffi::RAND_bytes(chunk.as_mut_ptr(), chunk.len() as c_int) == 1 }
    });
    checked(filled.then_some(())).is_some()
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::alg_id;

    use super::*;
    use crate::spki;

    #[test]
    fn rsa_keys_are_held_to_ring_limits() {
        // ring compares the modulus rounded up to whole bytes with 2048 bits and its exact length
        // with 8192 bits, and takes an odd exponent from 3 to 2^33 - 1 (ring 0.17.14).
        let modulus = |first: u8, len: usize| [&[first][..], &vec![0xff; len - 1]].concat();
        let n_2048 = modulus(0xff, 256);
        let f4: &[u8] = &[1, 0, 1];
        let cases: [(&str, Vec<u8>, &[u8], bool); 13] = [
            ("2033 bits in 255 bytes", modulus(0x01, 255), f4, false),
            ("2041 bits in 256 bytes", modulus(0x01, 256), f4, true),
            ("2048 bits", n_2048.clone(), f4, true),
            ("8192 bits", modulus(0xff, 1024), f4, true),
            ("8193 bits", modulus(0x01, 1025), f4, false),
            (
                "an even modulus",
                [&n_2048[..255], &[0xfe]].concat(),
                f4,
                false,
            ),
            ("exponent 1", n_2048.clone(), &[1], false),
            ("exponent 2", n_2048.clone(), &[2], false),
            ("exponent 3", n_2048.clone(), &[3], true),
            ("exponent 65536", n_2048.clone(), &[1, 0, 0], false),
            ("exponent 65537", n_2048.clone(), f4, true),
            (
                "exponent 2^33 - 1",
                n_2048.clone(),
                &[0x01, 0xff, 0xff, 0xff, 0xff],
                true,
            ),
            ("exponent 2^33 + 1", n_2048, &[0x02, 0, 0, 0, 0x01], false),
        ];
        for (what, n, e, within) in cases {
            let key = spki::rsa_public_key(&n, e);
            let spki = spki::build(alg_id::RSA_ENCRYPTION.as_ref(), &key);
            let pkey = public_key(&spki).unwrap();
            assert_eq!(rsa_within_limits(&pkey).is_some(), within, "{what}");
        }
    }

    #[test]
    fn links_openssl_1_1_1_or_later() {
        // SAFETY: `OpenSSL_version_num` does not take arguments and returns a constant.
        let version = unsafe { ffi::OpenSSL_version_num() };
        println!("linked OpenSSL version number: {version:#010x}");
        assert!(
            version >= 0x1010_1000,
            "the raw-key and one-shot verify functions need OpenSSL 1.1.1"
        );
    }
}
