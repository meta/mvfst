/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Ephemeral X25519 and secp256r1 key exchange.

use std::fmt;
use std::sync::Mutex;
use std::sync::PoisonError;

use rustls::Error;
use rustls::NamedGroup;
use rustls::PeerMisbehaved;
use rustls::crypto::ActiveKeyExchange;
use rustls::crypto::GetRandomFailed;
use rustls::crypto::SharedSecret;
use rustls::crypto::SupportedKxGroup;

use crate::native::KxGroupId;
use crate::native::sys;

/// A key exchange group.
struct KxGroup {
    name: NamedGroup,
    id: KxGroupId,
}

/// X25519 (RFC 7748).
pub(crate) static X25519: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::X25519,
    id: KxGroupId::X25519,
};

/// secp256r1, also called P-256.
pub(crate) static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp256r1,
    id: KxGroupId::Secp256r1,
};

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (key, pub_key) = sys::KxKey::generate(self.id).ok_or(GetRandomFailed)?;
        Ok(Box::new(KeyExchange {
            name: self.name,
            id: self.id,
            key: Mutex::new(key),
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

impl fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// A key exchange in progress, with the local key pair. rustls requires it to be `Sync`, so the
/// library key sits behind a mutex, which is never locked: `complete` takes the key out.
struct KeyExchange {
    name: NamedGroup,
    id: KxGroupId,
    key: Mutex<sys::KxKey>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let invalid = || Error::from(PeerMisbehaved::InvalidKeyShare);
        // TLS 1.3 shares have one length per group, and RFC 8446 allows only uncompressed P-256
        // points.
        let well_formed = match self.id {
            KxGroupId::X25519 => peer.len() == 32,
            KxGroupId::Secp256r1 => peer.len() == 65 && peer[0] == 0x04,
        };
        if !well_formed {
            return Err(invalid());
        }
        let key = self
            .key
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let secret = key.agree(peer).ok_or_else(invalid)?;
        // An all-zero X25519 secret means a low-order peer key, and RFC 8446 requires aborting.
        if self.id == KxGroupId::X25519 && secret.iter().all(|&b| b == 0) {
            return Err(invalid());
        }
        Ok(SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::ring::kx_group as ring;

    use super::*;
    use crate::testdata::unhex;

    fn complete_err(ours: &dyn SupportedKxGroup, peer: &[u8]) -> Error {
        ours.start().unwrap().complete(peer).err().unwrap()
    }

    #[test]
    fn each_group_agrees_with_ring_in_both_directions() {
        for (ours, theirs) in [(X25519, ring::X25519), (SECP256R1, ring::SECP256R1)] {
            assert_eq!(ours.name(), theirs.name());
            assert!(ours.ffdhe_group().is_none());

            let a = ours.start().unwrap();
            assert_eq!(a.group(), theirs.name());
            assert!(a.ffdhe_group().is_none());
            let b = theirs.start().unwrap();
            assert_eq!(a.pub_key().len(), b.pub_key().len());
            let a_pub = a.pub_key().to_vec();
            let b_pub = b.pub_key().to_vec();
            let ours_secret = a.complete(&b_pub).unwrap();
            let theirs_secret = b.complete(&a_pub).unwrap();
            assert_eq!(ours_secret.secret_bytes(), theirs_secret.secret_bytes());
            assert_eq!(ours_secret.secret_bytes().len(), 32);

            let b = theirs.start().unwrap();
            let b_pub = b.pub_key().to_vec();
            let completed = ours.start_and_complete(&b_pub).unwrap();
            let theirs_secret = b.complete(&completed.pub_key).unwrap();
            assert_eq!(
                completed.secret.secret_bytes(),
                theirs_secret.secret_bytes()
            );
        }
    }

    #[test]
    fn fresh_keys_differ() {
        for group in [X25519, SECP256R1] {
            let (a, b) = (group.start().unwrap(), group.start().unwrap());
            assert_ne!(a.pub_key(), b.pub_key());
        }
        assert_eq!(format!("{X25519:?}"), "X25519");
        assert_eq!(format!("{SECP256R1:?}"), "secp256r1");
    }

    #[test]
    fn a_low_order_x25519_peer_is_an_invalid_key_share() {
        // The point of order 8 in the published lists of Curve25519 small-order points, such as
        // libsodium's; every scalar gives the all-zero secret with it, which RFC 7748 lets an
        // implementation check for.
        let low_order = unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(
            complete_err(X25519, &low_order),
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        );
        assert_eq!(
            complete_err(X25519, &[0; 32]),
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        );
        assert_eq!(
            complete_err(X25519, &[9; 31]),
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        );
    }

    #[test]
    fn malformed_p256_peers_are_invalid_key_shares() {
        let good = SECP256R1.start().unwrap().pub_key().to_vec();
        let mut off_curve = good.clone();
        off_curve[64] ^= 1;
        let mut compressed = vec![0x02 | (good[64] & 1)];
        compressed.extend_from_slice(&good[1..33]);
        let mut long = good.clone();
        long.push(0);
        let mut hybrid = good.clone();
        hybrid[0] = 0x06 | (good[64] & 1);
        let mut infinity = vec![0x04];
        infinity.extend_from_slice(&[0; 64]);
        for peer in [
            &good[..64],
            &long[..],
            &compressed[..],
            &off_curve[..],
            &hybrid[..],
            &infinity[..],
            &[0x00][..],
            &[][..],
        ] {
            assert_eq!(
                complete_err(SECP256R1, peer),
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                "{peer:02x?}"
            );
        }
        // The well-formed share still completes.
        SECP256R1.start().unwrap().complete(&good).unwrap();
    }
}
