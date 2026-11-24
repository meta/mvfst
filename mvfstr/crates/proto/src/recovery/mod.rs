/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Loss recovery state (RFC 9002).
//!
//! The module holds the RTT estimator, received-packet tracking per packet number space with the
//! once-per-batch decision whether an ACK is due, the allocation-free rings of sent packets and
//! sent frames with one-pass ACK processing, packet- and time-threshold loss detection, PTO with
//! backoff, persistent congestion and per-space discard.

pub mod loss;
pub mod received;
pub mod rtt;
pub mod sent;

pub use loss::LossRecovery;
pub use loss::RecoveryConfig;
pub use received::AckDue;
pub use received::EcnCounts;
pub use received::ReceivedPackets;
pub use rtt::RttEstimator;
pub use sent::SentFlags;
pub use sent::SentFrame;
pub use sent::SentPackets;

/// A packet number space (RFC 9000). 0-RTT and 1-RTT packets share [`Space::Data`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Space {
    /// Initial packets.
    Initial = 0,
    /// Handshake packets.
    Handshake = 1,
    /// 0-RTT and 1-RTT packets.
    Data = 2,
}

impl Space {
    /// Every space, in the order RFC 9002's pseudocode walks them.
    pub const ALL: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];

    /// Returns the space as an array index.
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Returns a real `Instant` for a test to use as the epoch of its virtual clock; every other time
/// in the test is an offset from it, so the test stays deterministic.
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "tests need one real Instant as the epoch of their virtual clock"
)]
pub(crate) fn test_epoch() -> std::time::Instant {
    std::time::Instant::now()
}
