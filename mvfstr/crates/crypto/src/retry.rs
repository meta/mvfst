/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The QUIC v1 Retry Integrity Tag (RFC 9001).

use aws_lc_rs::aead;
use aws_lc_rs::constant_time;
use mvfstr_wire::ConnectionId;

/// The length of a Retry Integrity Tag.
pub const RETRY_TAG_LEN: usize = 16;

/// The fixed QUIC v1 Retry key, from HKDF-Expand-Label of RFC 9001's Retry secret with
/// "quic key".
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The fixed QUIC v1 Retry nonce, from the same secret with "quic iv".
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Computes the Retry Integrity Tag of a QUIC v1 Retry packet. `retry` is the packet without its
/// tag and `original_dcid` the Destination Connection ID of the client Initial it answers.
pub fn retry_integrity_tag(original_dcid: &ConnectionId, retry: &[u8]) -> [u8; RETRY_TAG_LEN] {
    // The associated data is the Retry pseudo-packet: the original DCID, length-prefixed,
    // followed by the Retry packet without its tag.
    let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + retry.len());
    // A `ConnectionId` holds at most 20 bytes.
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid);
    pseudo.extend_from_slice(retry);
    // The key length matches AES-128-GCM and sealing an empty plaintext cannot fail.
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_KEY_V1).expect("a 16-byte AES key"),
    );
    let tag = key
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(RETRY_NONCE_V1),
            aead::Aad::from(&pseudo),
            &mut [],
        )
        .expect("sealing an empty plaintext succeeds");
    let mut out = [0; RETRY_TAG_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Returns whether a whole QUIC v1 Retry packet, tag included, carries a valid tag for the client
/// Initial whose Destination Connection ID was `original_dcid`.
pub fn verify_retry_integrity(original_dcid: &ConnectionId, packet: &[u8]) -> bool {
    let Some(retry_len) = packet.len().checked_sub(RETRY_TAG_LEN) else {
        return false;
    };
    let (retry, tag) = packet.split_at(retry_len);
    let expected = retry_integrity_tag(original_dcid, retry);
    constant_time::verify_slices_are_equal(&expected, tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf::hkdf_expand_label;
    use crate::testdata::A4_RETRY;
    use crate::testdata::RFC9001_DCID;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    #[test]
    fn retry_tag_matches_rfc9001_a4() {
        let odcid = ConnectionId::new(&RFC9001_DCID).unwrap();
        let packet = unhex(A4_RETRY);
        let (retry, tag) = packet.split_at(packet.len() - RETRY_TAG_LEN);
        assert_eq!(hex(&retry_integrity_tag(&odcid, retry)), hex(tag));

        // The fixed key and nonce come from RFC 9001's Retry secret.
        let secret = unhex("d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e");
        let (mut key, mut nonce) = ([0; 16], [0; 12]);
        hkdf_expand_label(&secret, b"quic key", &[], &mut key).unwrap();
        hkdf_expand_label(&secret, b"quic iv", &[], &mut nonce).unwrap();
        assert_eq!((key, nonce), (RETRY_KEY_V1, RETRY_NONCE_V1));
    }

    #[test]
    fn verification_accepts_only_the_tag_for_the_original_dcid() {
        let odcid = ConnectionId::new(&RFC9001_DCID).unwrap();
        let packet = unhex(A4_RETRY);
        assert!(verify_retry_integrity(&odcid, &packet));

        let other_odcid = ConnectionId::new(&RFC9001_DCID[..7]).unwrap();
        assert!(!verify_retry_integrity(&other_odcid, &packet));
        for i in [0, 9, packet.len() - 17, packet.len() - 1] {
            let mut tampered = packet.clone();
            tampered[i] ^= 0x10;
            assert!(!verify_retry_integrity(&odcid, &tampered), "byte {i}");
        }
        assert!(!verify_retry_integrity(
            &odcid,
            &packet[..RETRY_TAG_LEN - 1]
        ));
        assert!(!verify_retry_integrity(&odcid, &packet[1..]));
    }
}
