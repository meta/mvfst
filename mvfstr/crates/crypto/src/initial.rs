/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC Initial secrets and keys (RFC 9001).
//!
//! Initial packets are protected with AES-128-GCM under keys derived from the Destination
//! Connection ID of the client's first Initial packet and a salt that depends on the QUIC
//! version.

use std::fmt;

use mvfstr_wire::Side;
use mvfstr_wire::Version;

use crate::algorithm::AES_128_GCM;
use crate::hkdf::SHA256_LEN;
use crate::hkdf::hkdf_expand_label;
use crate::hkdf::hkdf_extract_sha256;
use crate::keys::KeySet;
use crate::keys::PacketKeys;

/// The QUIC v1 Initial salt (RFC 9001).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The Initial salt of mvfst's version 0xfaceb002, which is draft-ietf-quic-tls-23's salt.
pub const INITIAL_SALT_MVFST: [u8; 20] = [
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02,
];

/// Returns the Initial salt of a version, or `None` for a version mvfstr does not implement. Each
/// of mvfst's aliases uses the salt of the version it aliases.
pub fn initial_salt(version: Version) -> Option<&'static [u8; 20]> {
    match version.unaliased() {
        Version::V1 => Some(&INITIAL_SALT_V1),
        Version::MVFST => Some(&INITIAL_SALT_MVFST),
        _ => None,
    }
}

/// A QUIC version without Initial keys in mvfstr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedVersion(pub Version);

impl fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no Initial keys for QUIC version {:?}", self.0)
    }
}

impl std::error::Error for UnsupportedVersion {}

/// The client and server Initial secrets of a connection.
#[derive(Clone)]
pub struct InitialSecrets {
    /// The secret protecting packets the client sends ("client in").
    pub client: [u8; SHA256_LEN],
    /// The secret protecting packets the server sends ("server in").
    pub server: [u8; SHA256_LEN],
}

impl fmt::Debug for InitialSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialSecrets").finish_non_exhaustive()
    }
}

/// Derives the Initial secrets of `version` from the Destination Connection ID of the client's
/// first Initial packet (or of its Initial after a Retry). Fails with [`UnsupportedVersion`] for
/// a version without an Initial salt.
pub fn initial_secrets(
    version: Version,
    client_dcid: &[u8],
) -> Result<InitialSecrets, UnsupportedVersion> {
    let salt = initial_salt(version).ok_or(UnsupportedVersion(version))?;
    let initial = hkdf_extract_sha256(salt, client_dcid);
    let mut secrets = InitialSecrets {
        client: [0; SHA256_LEN],
        server: [0; SHA256_LEN],
    };
    // A 32-byte secret, fixed labels and a 32-byte output always fit HKDF-Expand-Label.
    hkdf_expand_label(&initial, b"client in", &[], &mut secrets.client)
        .expect("fixed QUIC labels fit");
    hkdf_expand_label(&initial, b"server in", &[], &mut secrets.server)
        .expect("fixed QUIC labels fit");
    Ok(secrets)
}

/// Derives the Initial keys of `version` for the endpoint on `side`: AES-128-GCM keys from the
/// Destination Connection ID of the client's first Initial packet (RFC 9001). Fails with
/// [`UnsupportedVersion`] for a version without an Initial salt.
pub fn initial_keys(
    version: Version,
    client_dcid: &[u8],
    side: Side,
) -> Result<KeySet, UnsupportedVersion> {
    let secrets = initial_secrets(version, client_dcid)?;
    let (local, remote) = match side {
        Side::Client => (&secrets.client, &secrets.server),
        Side::Server => (&secrets.server, &secrets.client),
    };
    Ok(KeySet {
        local: PacketKeys::from_secret(&AES_128_GCM, local),
        remote: PacketKeys::from_secret(&AES_128_GCM, remote),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::unprotect_header;
    use crate::seal::InlineSealer;
    use crate::seal::SealJob;
    use crate::seal::Sealer;
    use crate::seal::SlotId;
    use crate::testdata::A2_CRYPTO;
    use crate::testdata::A2_PACKET;
    use crate::testdata::A3_HEADER;
    use crate::testdata::A3_PACKET;
    use crate::testdata::A3_PAYLOAD;
    use crate::testdata::RFC9001_DCID;
    use crate::testdata::unhex;

    #[test]
    fn v1_initial_secrets_match_rfc9001_a1() {
        let secrets = initial_secrets(Version::V1, &RFC9001_DCID).unwrap();
        assert_eq!(
            secrets.client.to_vec(),
            unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            secrets.server.to_vec(),
            unhex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
    }

    /// draft-ietf-quic-tls-23 Appendix A gives these secrets for the same Destination
    /// Connection ID under its salt, which MVFST 0xfaceb002 uses.
    #[test]
    fn mvfst_initial_secrets_use_the_draft_23_salt() {
        assert_eq!(
            hkdf_extract_sha256(&INITIAL_SALT_MVFST, &RFC9001_DCID).to_vec(),
            unhex("524e374c6da8cf8b496f4bcb696783507aafee6198b202b4bc823ebf7514a423")
        );
        let secrets = initial_secrets(Version::MVFST, &RFC9001_DCID).unwrap();
        assert_eq!(
            secrets.client.to_vec(),
            unhex("fda3953aecc040e48b34e27ef87de3a6098ecf0e38b7e032c5c57bcbd5975b84")
        );
        assert_eq!(
            secrets.server.to_vec(),
            unhex("554366b81912ff90be41f17e8022213090ab17d8149179bcadf222f29ff2ddd5")
        );
    }

    /// Checks the secrets against those mvfst derives for the RFC 9001 Destination Connection ID:
    /// its aliases of version 1 use the version 1 salt, and its alias of MVFST the draft-23 salt.
    #[test]
    fn mvfsts_alias_versions_have_the_initial_secrets_mvfst_derives() {
        let v1 = (
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        );
        let mvfst = (
            "fda3953aecc040e48b34e27ef87de3a6098ecf0e38b7e032c5c57bcbd5975b84",
            "554366b81912ff90be41f17e8022213090ab17d8149179bcadf222f29ff2ddd5",
        );
        for (version, (client, server)) in [
            (Version::QUIC_V1_ALIAS, v1),
            (Version::QUIC_V1_ALIAS2, v1),
            (Version::MVFST_ALIAS, mvfst),
        ] {
            let secrets = initial_secrets(version, &RFC9001_DCID).unwrap();
            assert_eq!(secrets.client.to_vec(), unhex(client), "{version:?}");
            assert_eq!(secrets.server.to_vec(), unhex(server), "{version:?}");
        }
    }

    /// Removes header protection and opens `packet`, whose packet number starts at
    /// `pn_offset`; returns the packet number and the plaintext payload.
    fn open(keys: &PacketKeys, packet: &[u8], pn_offset: usize) -> (u64, Vec<u8>) {
        let mut packet = packet.to_vec();
        let pn_len = unprotect_header(keys.header(), &mut packet, pn_offset).unwrap();
        let hdr_len = pn_offset + pn_len;
        let pn = packet[pn_offset..hdr_len]
            .iter()
            .fold(0u64, |pn, b| (pn << 8) | u64::from(*b));
        let (header, payload) = packet.split_at_mut(hdr_len);
        let plain = keys.packet().decrypt_in_place(pn, header, payload).unwrap();
        (pn, plain.to_vec())
    }

    #[test]
    fn initial_keys_protect_each_direction_as_rfc9001_a2_and_a3() {
        let client = initial_keys(Version::V1, &RFC9001_DCID, Side::Client).unwrap();
        let server = initial_keys(Version::V1, &RFC9001_DCID, Side::Server).unwrap();

        // The client's packet of A.2 opens with the server's remote keys, and the server's of
        // A.3 with the client's.
        let mut a2_payload = unhex(A2_CRYPTO);
        a2_payload.resize(1162, 0);
        assert_eq!(open(&server.remote, &unhex(A2_PACKET), 18), (2, a2_payload));
        assert_eq!(
            open(&client.remote, &unhex(A3_PACKET), 18),
            (1, unhex(A3_PAYLOAD))
        );

        // Each side's local keys produce those packets.
        let header = unhex(A3_HEADER);
        let mut slot = [header.clone(), unhex(A3_PAYLOAD), vec![0; 16]].concat();
        let job = SealJob {
            slot: SlotId(0),
            keys: &server.local,
            pn: 1,
            hdr_len: header.len() as u16,
            len: slot.len() as u16,
        };
        InlineSealer.seal(job, &mut slot).unwrap();
        assert_eq!(slot, unhex(A3_PACKET));
        assert_eq!(open(&client.remote, &slot, 18).0, 1);
        assert_eq!(client.local.confidentiality_limit(), 1 << 23);
    }

    #[test]
    fn other_versions_have_no_initial_secrets() {
        // The last five are mvfst's experimental versions, which mvfstr does not implement.
        for version in [
            Version::NEGOTIATION,
            Version(0xff00_001d),
            Version(0x6b33_43cf),
            Version(0xface_b00e),
            Version(0xface_b011),
            Version(0xface_b013),
            Version(0xface_b014),
            Version(0xface_b015),
        ] {
            assert_eq!(initial_salt(version), None);
            assert_eq!(
                initial_secrets(version, &RFC9001_DCID).unwrap_err(),
                UnsupportedVersion(version)
            );
        }
    }
}
