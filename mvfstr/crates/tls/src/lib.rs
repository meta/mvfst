/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC-TLS for mvfstr, over rustls 0.23 or a TLS stack outside the crate.
//!
//! [`TlsSession`] runs one handshake in either role: it takes and yields CRYPTO bytes per
//! encryption [`Level`], reports key changes as mvfstr [`KeyChange`]s, exposes the peer's
//! transport parameters and the negotiated ALPN, and maps TLS alerts to CRYPTO_ERROR codes. A
//! session on rustls runs only the TLS 1.3 state machine, through `rustls::quic`, as RFC 9001
//! describes. An External session hands out [`TlsInput`]s for a [`TlsHost`] and applies the
//! [`TlsStep`]s the host returns, which carry raw traffic secrets; [`testing::RustlsHost`] is a
//! host on rustls for tests.
//! The config helpers [`server_config`] and [`client_config`] build TLS 1.3-only rustls configs
//! whose suites carry mvfstr's packet protection, and [`ManualTimeProvider`] keeps rustls off the
//! system clock. [`app_token`] holds session-ticket app tokens in mvfst's format and mvfst's
//! 0-RTT checks on them.
//!
//! The crate does not do I/O or read a clock.

#![forbid(unsafe_code)]

pub mod app_token;
mod config;
mod external;
mod session;
pub mod testing;
mod time;

pub use config::AcceptAnyServerCert;
pub use config::ServerVerification;
pub use config::client_config;
pub use config::server_config;
pub use external::AppTokenVerdict;
pub use external::EarlyDataOutcome;
pub use external::EchOutcome;
pub use external::ExternalSession;
pub use external::HandshakeSummary;
pub use external::PskMode;
pub use external::PskOutcome;
pub use external::ReplayCheck;
pub use external::SecretPair;
pub use external::TlsConnId;
pub use external::TlsHost;
pub use external::TlsInput;
pub use external::TlsPoll;
pub use external::TlsStep;
pub use external::TlsSuite;
pub use session::CryptoOutput;
pub use session::KeyChange;
pub use session::Level;
pub use session::RustlsSession;
pub use session::TlsError;
pub use session::TlsSession;
pub use time::ManualTimeProvider;
