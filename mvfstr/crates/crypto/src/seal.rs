/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The [`Sealer`] seam between building a packet and sealing it.
//!
//! A packet is planned and written into a backend slot by the connection, then sealed: the
//! payload is encrypted in place and header protection applied. The connection hands each built
//! packet to a [`Sealer`]. [`InlineSealer`] seals at once; another sealer may record the job and
//! seal a batch across connections in [`Sealer::finish`], before the backend flushes. Slot IDs
//! stay valid in the backend until the run is flushed or abandoned, which is what lets a sealer
//! defer.

use std::fmt;
use std::sync::Arc;

use crate::header::protect_header;
// Also exported from this module, beside the `SealJob` that holds it.
pub use crate::keys::PacketKeys;
use crate::packet::TAG_LEN;

/// A datagram slot in a transmit backend's buffer pool, stable until the backend sends or
/// abandons it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotId(pub u32);

/// One built packet to seal.
///
/// The packet occupies `pkt[..len]` of its slot: the header in `pkt[..hdr_len]`, ending with the
/// packet number, whose length is in the low two bits of the unprotected first byte; then the
/// plaintext payload; then room for the AEAD tag in the last `keys.packet().tag_len()` bytes.
#[derive(Clone, Copy, Debug)]
pub struct SealJob<'a> {
    /// The backend slot holding the packet.
    pub slot: SlotId,
    /// The keys of the packet's encryption level.
    pub keys: &'a Arc<PacketKeys>,
    /// The full packet number, which forms the AEAD nonce.
    pub pn: u64,
    /// The header length, packet number included.
    pub hdr_len: u16,
    /// The packet length, AEAD tag included.
    pub len: u16,
}

/// Why sealing failed. The connection treats the packet as never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The job's lengths do not fit the slot, or do not leave room for the tag or the
    /// header-protection sample.
    BadLayout,
    /// The AEAD key refused to encrypt.
    Encrypt,
    /// The header-protection key refused to mask the header.
    HeaderProtection,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadLayout => "packet layout does not fit its slot",
            Self::Encrypt => "packet encryption failed",
            Self::HeaderProtection => "header protection failed",
        })
    }
}

impl std::error::Error for SealError {}

/// Access to backend slots by ID, for a sealer that seals recorded jobs in
/// [`Sealer::finish`].
pub trait SlotAccess {
    /// Returns the bytes of a slot that has not been flushed or abandoned.
    fn slot_mut(&mut self, slot: SlotId) -> Option<&mut [u8]>;
}

/// The result of [`Sealer::finish`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealOutcome {
    /// Every recorded job is sealed. It is the only variant, so a deferred job that fails to seal
    /// is not reported.
    Done,
}

/// A sealer of built packets, which seals each one at once or before the next flush.
pub trait Sealer {
    /// Seals the packet in `pkt` (its slot's bytes, at least `job.len` long) or records the job
    /// to seal it in [`finish`](Self::finish).
    fn seal(&mut self, job: SealJob<'_>, pkt: &mut [u8]) -> Result<(), SealError>;

    /// Seals every recorded job. Called before the backend flushes.
    fn finish(&mut self, slots: &mut dyn SlotAccess) -> SealOutcome {
        let _ = slots;
        SealOutcome::Done
    }
}

/// A sealer that seals each packet inside [`Sealer::seal`], encrypting the payload in place and
/// then applying header protection (RFC 9001). Its [`Sealer::finish`] returns at once.
#[derive(Clone, Copy, Debug, Default)]
pub struct InlineSealer;

impl Sealer for InlineSealer {
    fn seal(&mut self, job: SealJob<'_>, pkt: &mut [u8]) -> Result<(), SealError> {
        let keys = &**job.keys;
        let (len, hdr_len, tag_len) = (
            usize::from(job.len),
            usize::from(job.hdr_len),
            keys.tag_len(),
        );
        if tag_len != TAG_LEN {
            // rustls tags are 16 bytes; a key that reports another tag length cannot seal a packet.
            return Err(SealError::Encrypt);
        }
        if len == 0 || len > pkt.len() {
            return Err(SealError::BadLayout);
        }
        let pn_len = usize::from(pkt[0] & 0x03) + 1;
        let pn_offset = hdr_len.checked_sub(pn_len).ok_or(SealError::BadLayout)?;
        let sample_end = pn_offset + 4 + keys.header().sample_len();
        if pn_offset == 0 || hdr_len + tag_len > len || sample_end > len {
            return Err(SealError::BadLayout);
        }
        let packet = &mut pkt[..len];
        let (header, rest) = packet.split_at_mut(hdr_len);
        let (payload, tag_room) = rest.split_at_mut(len - hdr_len - tag_len);
        let tag = keys
            .packet()
            .encrypt_in_place(job.pn, header, payload)
            .map_err(|_| SealError::Encrypt)?;
        tag_room.copy_from_slice(tag.as_ref());
        protect_header(keys.header(), packet, pn_offset).map_err(|_| SealError::HeaderProtection)
    }
}

#[cfg(test)]
mod tests {
    use rustls::quic::PacketKey;

    use super::*;
    use crate::algorithm::AES_128_GCM;
    use crate::header::AeadHeaderKey;
    use crate::testdata::A2_CRYPTO;
    use crate::testdata::A2_HEADER;
    use crate::testdata::A2_PACKET;
    use crate::testdata::A3_HEADER;
    use crate::testdata::A3_PACKET;
    use crate::testdata::A3_PAYLOAD;
    use crate::testdata::hex;
    use crate::testdata::unhex;

    struct Recorder(Vec<(SlotId, u64)>);

    impl Sealer for Recorder {
        fn seal(&mut self, job: SealJob<'_>, _pkt: &mut [u8]) -> Result<(), SealError> {
            self.0.push((job.slot, job.pn));
            Ok(())
        }
    }

    struct NoSlots;

    impl SlotAccess for NoSlots {
        fn slot_mut(&mut self, _slot: SlotId) -> Option<&mut [u8]> {
            None
        }
    }

    #[test]
    fn a_sealer_that_seals_inline_needs_no_finish() {
        let mut sealer = Recorder(Vec::new());
        assert_eq!(sealer.finish(&mut NoSlots), SealOutcome::Done);
        assert!(sealer.0.is_empty());
    }

    #[test]
    fn inline_sealer_reproduces_rfc9001_a2_and_a3() {
        let secrets = [
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        ];
        let mut a2_payload = unhex(A2_CRYPTO);
        a2_payload.resize(1162, 0);
        let cases = [
            (secrets[0], 2, A2_HEADER, a2_payload, A2_PACKET),
            (secrets[1], 1, A3_HEADER, unhex(A3_PAYLOAD), A3_PACKET),
        ];
        for (secret, pn, header, payload, protected) in cases {
            let secret = unhex(secret).try_into().unwrap();
            let keys = Arc::new(PacketKeys::from_secret(&AES_128_GCM, &secret));
            let header = unhex(header);
            let mut slot = header.clone();
            slot.extend_from_slice(&payload);
            slot.extend_from_slice(&[0; TAG_LEN]);
            let job = SealJob {
                slot: SlotId(3),
                keys: &keys,
                pn,
                hdr_len: header.len() as u16,
                len: slot.len() as u16,
            };
            InlineSealer.seal(job, &mut slot).unwrap();
            let expected = unhex(protected);
            assert_eq!(hex(&slot[..header.len()]), hex(&expected[..header.len()]));
            assert_eq!(slot, expected, "packet number {pn}");
        }
    }

    /// Builds a short-header packet with an 8-byte connection ID and a 1-byte packet number: the
    /// header is 10 bytes and the packet must reach byte 29 to hold a full sample.
    fn short_packet(payload_len: usize) -> Vec<u8> {
        let mut pkt = vec![0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0x2a];
        pkt.extend((0..payload_len).map(|i| i as u8));
        pkt.extend_from_slice(&[0; TAG_LEN]);
        pkt
    }

    #[test]
    fn jobs_that_do_not_fit_their_slot_are_refused_unchanged() {
        let keys = Arc::new(PacketKeys::from_secret(&AES_128_GCM, &[9; 32]));
        let fits = short_packet(3);
        let job = |hdr_len: u16, len: u16| SealJob {
            slot: SlotId(0),
            keys: &keys,
            pn: 0x2a,
            hdr_len,
            len,
        };
        let full = fits.len() as u16;
        let cases = [
            ("longer than the slot", fits.clone(), job(10, full + 1)),
            ("empty", Vec::new(), job(0, 0)),
            ("no header", fits.clone(), job(0, full)),
            ("packet number past the header", fits.clone(), job(1, full)),
            ("header past the end", fits.clone(), job(full, full)),
            ("no room for the tag", fits.clone(), job(10, 20)),
            ("no full sample", short_packet(2), job(10, full - 1)),
        ];
        for (what, mut slot, job) in cases {
            let before = slot.clone();
            assert_eq!(
                InlineSealer.seal(job, &mut slot),
                Err(SealError::BadLayout),
                "{what}"
            );
            assert_eq!(slot, before, "{what}");
        }
        let mut slot = fits.clone();
        InlineSealer.seal(job(10, full), &mut slot).unwrap();
        assert_ne!(slot, fits);
    }

    /// A packet key that reports an 8-byte tag, which rustls's 16-byte `Tag` cannot carry.
    struct ShortTagKey(PacketKeys);

    impl PacketKey for ShortTagKey {
        fn encrypt_in_place(
            &self,
            packet_number: u64,
            header: &[u8],
            payload: &mut [u8],
        ) -> Result<rustls::quic::Tag, rustls::Error> {
            self.0
                .packet()
                .encrypt_in_place(packet_number, header, payload)
        }

        fn decrypt_in_place<'a>(
            &self,
            packet_number: u64,
            header: &[u8],
            payload: &'a mut [u8],
        ) -> Result<&'a [u8], rustls::Error> {
            self.0
                .packet()
                .decrypt_in_place(packet_number, header, payload)
        }

        fn tag_len(&self) -> usize {
            8
        }

        fn confidentiality_limit(&self) -> u64 {
            self.0.confidentiality_limit()
        }

        fn integrity_limit(&self) -> u64 {
            self.0.integrity_limit()
        }
    }

    #[test]
    fn keys_whose_tag_length_differs_from_rustls_tags_are_refused() {
        let inner = PacketKeys::from_secret(&AES_128_GCM, &[9; 32]);
        let header = Box::new(AeadHeaderKey::new(&AES_128_GCM, &[1; 16]).unwrap());
        let keys = Arc::new(PacketKeys::new(Box::new(ShortTagKey(inner)), header));
        let mut slot = short_packet(12);
        let before = slot.clone();
        let job = SealJob {
            slot: SlotId(0),
            keys: &keys,
            pn: 0x2a,
            hdr_len: 10,
            len: (slot.len() - 8) as u16,
        };
        assert_eq!(InlineSealer.seal(job, &mut slot), Err(SealError::Encrypt));
        assert_eq!(slot, before);
    }

    #[test]
    fn keys_can_be_shared_across_threads() {
        // A `Connection` is `Send` and holds `Arc<PacketKeys>`; a batch sealer may share them.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PacketKeys>();
        assert_send_sync::<Arc<PacketKeys>>();
    }
}
