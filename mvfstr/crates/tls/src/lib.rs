/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC-TLS for mvfstr over rustls 0.23.
//!
//! rustls runs only the TLS 1.3 state machine, through `rustls::quic`, as RFC 9001 describes.
//! [`TlsSession`] wraps a `rustls::quic::Connection` for either role: it takes and yields CRYPTO
//! bytes per encryption [`Level`], reports key changes as mvfstr [`KeyChange`]s, exposes the
//! peer's transport parameters and the negotiated ALPN, and maps TLS alerts to CRYPTO_ERROR codes.
//! The config helpers [`server_config`] and [`client_config`] build TLS 1.3-only rustls configs
//! whose suites carry mvfstr's packet protection, and [`ManualTimeProvider`] keeps rustls off the
//! system clock.
//!
//! The crate does not do I/O or read a clock.

#![forbid(unsafe_code)]

mod config;
mod session;
mod time;

pub use config::AcceptAnyServerCert;
pub use config::ServerVerification;
pub use config::client_config;
pub use config::server_config;
pub use session::CryptoOutput;
pub use session::KeyChange;
pub use session::Level;
pub use session::TlsError;
pub use session::TlsSession;
pub use time::ManualTimeProvider;
