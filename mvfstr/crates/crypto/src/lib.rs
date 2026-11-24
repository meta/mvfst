/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC packet protection for mvfstr.
//!
//! The crate derives the Initial keys of v1, of MVFST 0xfaceb002 and of mvfst's aliases of the
//! two ([`initial_keys`]), computes v1 Retry integrity tags, and implements AES-128-GCM,
//! AES-256-GCM and ChaCha20-Poly1305 packet and header protection as rustls `PacketKey`s and
//! `HeaderProtectionKey`s, with the usage limits of RFC 9001 on every packet key.
//! [`QuicAlgorithm`] is the `rustls::quic::Algorithm` through which rustls's TLS 1.3 key schedule
//! builds every Handshake, 1-RTT and key-update key as an mvfstr key; [`with_quic_suites`]
//! rewrites a caller's `CryptoProvider` to suites that carry it. [`KeySet`] holds the keys of one
//! level and [`KeyUpdater`] derives later 1-RTT key phases; both are built either from rustls or
//! from the raw [`TrafficSecret`]s of another TLS stack. The [`seal`] module holds the
//! [`Sealer`] seam, through which the connection seals a packet it built in a backend slot;
//! [`InlineSealer`] seals it at once.
//!
//! The crate does not perform I/O or read a clock.
//!
//! # Crypto backend
//!
//! Packet protection, header protection, HKDF and [`default_provider`] run on aws-lc-rs or ring,
//! chosen by Cargo feature. The `aws-lc-rs` feature is on by default, and aws-lc-rs is used
//! whenever it is on, even with `ring` on too. With only `ring` on, ring is used. At least one of
//! the two must be on. The default provider offers post-quantum key exchange only with aws-lc-rs.
//! Builds for Android or iOS that do not have aws-lc-rs can turn on only `ring`.

mod algorithm;
mod backend;
mod header;
mod hkdf;
mod initial;
mod keys;
mod packet;
mod retry;
pub mod seal;
mod secrets;
pub mod suite;
#[cfg(test)]
mod testdata;

pub use algorithm::AES_128_GCM;
pub use algorithm::AES_256_GCM;
pub use algorithm::CHACHA20_POLY1305;
pub use algorithm::KeyLengthError;
pub use algorithm::MAX_KEY_LEN;
pub use algorithm::QuicAlgorithm;
pub use backend::default_provider;
pub use header::AeadHeaderKey;
pub use header::HeaderProtectionError;
pub use header::MASK_LEN;
pub use header::SAMPLE_LEN;
pub use header::protect_header;
pub use header::unprotect_header;
pub use hkdf::ExpandLabelError;
pub use hkdf::SHA256_LEN;
pub use hkdf::hkdf_expand_label;
pub use hkdf::hkdf_expand_sha256;
pub use hkdf::hkdf_extract_sha256;
pub use initial::INITIAL_SALT_MVFST;
pub use initial::INITIAL_SALT_V1;
pub use initial::InitialSecrets;
pub use initial::UnsupportedVersion;
pub use initial::initial_keys;
pub use initial::initial_salt;
pub use initial::initial_secrets;
pub use keys::KeyMaterial;
pub use keys::KeySet;
pub use keys::KeyUpdater;
pub use keys::PacketKeys;
pub use packet::AeadPacketKey;
pub use packet::NONCE_LEN;
pub use packet::TAG_LEN;
pub use retry::RETRY_TAG_LEN;
pub use retry::retry_integrity_tag;
pub use retry::verify_retry_integrity;
pub use seal::InlineSealer;
pub use seal::SealError;
pub use seal::SealJob;
pub use seal::SealOutcome;
pub use seal::Sealer;
pub use seal::SlotAccess;
pub use seal::SlotId;
pub use secrets::SecretHash;
pub use secrets::SecretLengthError;
pub use secrets::TrafficSecret;
pub use suite::cipher_suite;
pub use suite::derive_suite;
pub use suite::quic_algorithm;
pub use suite::with_quic_suites;
