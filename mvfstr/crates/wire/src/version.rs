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
    /// mvfst's first alias of version 1. mvfst clients offer an alias so that the server can treat
    /// them differently, for example by putting congestion hints in session tickets. Apart from
    /// its number, it is version 1 on the wire.
    pub const QUIC_V1_ALIAS: Version = Version(0xface_b003);
    /// mvfst's second alias of version 1.
    pub const QUIC_V1_ALIAS2: Version = Version(0xface_b004);
    /// mvfst's alias of [`Version::MVFST`].
    pub const MVFST_ALIAS: Version = Version(0xface_b010);

    /// Returns the version that `self` is an alias of: [`Version::V1`] for
    /// [`Version::QUIC_V1_ALIAS`] and [`Version::QUIC_V1_ALIAS2`], [`Version::MVFST`] for
    /// [`Version::MVFST_ALIAS`], and `self` for any other version.
    pub const fn unaliased(self) -> Version {
        match self {
            Version::QUIC_V1_ALIAS | Version::QUIC_V1_ALIAS2 => Version::V1,
            Version::MVFST_ALIAS => Version::MVFST,
            other => other,
        }
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::V1 => f.write_str("Version::V1"),
            Version::MVFST => f.write_str("Version::MVFST"),
            Version::QUIC_V1_ALIAS => f.write_str("Version::QUIC_V1_ALIAS"),
            Version::QUIC_V1_ALIAS2 => f.write_str("Version::QUIC_V1_ALIAS2"),
            Version::MVFST_ALIAS => f.write_str("Version::MVFST_ALIAS"),
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
        assert_eq!(Version::QUIC_V1_ALIAS.0, 0xface_b003);
        assert_eq!(Version::QUIC_V1_ALIAS2.0, 0xface_b004);
        assert_eq!(Version::MVFST_ALIAS.0, 0xface_b010);
    }

    #[test]
    fn mvfsts_aliases_stand_for_version_1_and_mvfst() {
        for (alias, version) in [
            (Version::QUIC_V1_ALIAS, Version::V1),
            (Version::QUIC_V1_ALIAS2, Version::V1),
            (Version::MVFST_ALIAS, Version::MVFST),
        ] {
            assert_eq!(alias.unaliased(), version, "{alias:?}");
        }
        // mvfstr does not treat mvfst's MVFST_EXPERIMENTAL to MVFST_EXPERIMENTAL5 as aliases.
        for version in [
            Version::NEGOTIATION,
            Version::V1,
            Version::MVFST,
            Version(0xface_b00e),
            Version(0xface_b011),
            Version(0xface_b013),
            Version(0xface_b014),
            Version(0xface_b015),
        ] {
            assert_eq!(version.unaliased(), version, "{version:?}");
        }
    }

    #[test]
    fn debug_names_known_versions() {
        assert_eq!(format!("{:?}", Version::V1), "Version::V1");
        assert_eq!(format!("{:?}", Version::MVFST), "Version::MVFST");
        assert_eq!(
            format!("{:?}", Version::QUIC_V1_ALIAS),
            "Version::QUIC_V1_ALIAS"
        );
        assert_eq!(
            format!("{:?}", Version::QUIC_V1_ALIAS2),
            "Version::QUIC_V1_ALIAS2"
        );
        assert_eq!(
            format!("{:?}", Version::MVFST_ALIAS),
            "Version::MVFST_ALIAS"
        );
        assert_eq!(format!("{:?}", Version(0x1a2a_3a4a)), "Version(0x1a2a3a4a)");
    }
}
