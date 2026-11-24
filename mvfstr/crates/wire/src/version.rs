/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC versions (RFC 9000).

use std::fmt;

/// A 32-bit QUIC version number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u32);

impl Version {
    /// The version field of a Version Negotiation packet.
    pub const NEGOTIATION: Version = Version(0);
    /// QUIC version 1 (RFC 9000).
    pub const V1: Version = Version(0x0000_0001);
    /// mvfst's own version, which mvfst tperf clients offer. It uses the draft-23 Initial salt and
    /// carries transport parameters in TLS extension 0xffa5.
    pub const MVFST: Version = Version(0xface_b002);
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::V1 => f.write_str("Version::V1"),
            Version::MVFST => f.write_str("Version::MVFST"),
            Version(other) => write!(f, "Version({other:#010x})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_wire_values() {
        assert_eq!(Version::V1.0.to_be_bytes(), [0, 0, 0, 1]);
        assert_eq!(Version::MVFST.0.to_be_bytes(), [0xfa, 0xce, 0xb0, 0x02]);
        assert_eq!(Version::NEGOTIATION.0, 0);
    }

    #[test]
    fn debug_names_known_versions() {
        assert_eq!(format!("{:?}", Version::V1), "Version::V1");
        assert_eq!(format!("{:?}", Version::MVFST), "Version::MVFST");
        assert_eq!(format!("{:?}", Version(0x1a2a_3a4a)), "Version(0x1a2a3a4a)");
    }
}
