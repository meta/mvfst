/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The QUIC packet-protection algorithms and their AEAD usage limits (RFC 9001).

use std::fmt;

use crate::backend::aead;

/// The largest AEAD or header-protection key mvfstr uses, in bytes.
pub const MAX_KEY_LEN: usize = 32;

/// A key whose length does not match its algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyLengthError;

impl fmt::Display for KeyLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key length does not match the algorithm")
    }
}

impl std::error::Error for KeyLengthError {}

/// A QUIC packet-protection algorithm: an AEAD, its header-protection cipher and the AEAD's
/// usage limits.
///
/// The three statics are the algorithms of the TLS 1.3 cipher suites QUIC can use. Each also
/// implements `rustls::quic::Algorithm`, through which rustls builds every Handshake and 1-RTT
/// key with mvfstr's key types.
pub struct QuicAlgorithm {
    name: &'static str,
    pub(crate) aead: &'static aead::Algorithm,
    pub(crate) header: &'static aead::quic::Algorithm,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

/// AEAD_AES_128_GCM with AES-128 header protection. The limits are RFC 9001's: 2^23 packets
/// sealed per key, 2^52 failed opens per connection.
pub static AES_128_GCM: QuicAlgorithm = QuicAlgorithm {
    name: "AES-128-GCM",
    aead: &aead::AES_128_GCM,
    header: &aead::quic::AES_128,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// AEAD_AES_256_GCM with AES-256 header protection, with the same limits as AES-128-GCM.
pub static AES_256_GCM: QuicAlgorithm = QuicAlgorithm {
    name: "AES-256-GCM",
    aead: &aead::AES_256_GCM,
    header: &aead::quic::AES_256,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// AEAD_CHACHA20_POLY1305 with ChaCha20 header protection. Its confidentiality limit exceeds
/// the number of possible packets, so it is `u64::MAX`; the integrity limit is 2^36.
pub static CHACHA20_POLY1305: QuicAlgorithm = QuicAlgorithm {
    name: "ChaCha20-Poly1305",
    aead: &aead::CHACHA20_POLY1305,
    header: &aead::quic::CHACHA20,
    confidentiality_limit: u64::MAX,
    integrity_limit: 1 << 36,
};

impl QuicAlgorithm {
    /// Returns the AEAD's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the length of the AEAD key and of the header-protection key, in bytes.
    pub fn key_len(&self) -> usize {
        self.aead.key_len()
    }

    /// Returns the number of packets one key may seal (RFC 9001).
    pub fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    /// Returns the number of packets that may fail to open in one connection (RFC 9001).
    pub fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

impl fmt::Debug for QuicAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}
