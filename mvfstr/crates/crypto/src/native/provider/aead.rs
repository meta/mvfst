/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! TLS 1.3 record protection (RFC 8446). QUIC never uses it, but rustls builds it in the key
//! schedule of every suite.

use rustls::ConnectionTrafficSecrets;
use rustls::ContentType;
use rustls::Error;
use rustls::ProtocolVersion;
use rustls::crypto::cipher::AeadKey;
use rustls::crypto::cipher::InboundOpaqueMessage;
use rustls::crypto::cipher::InboundPlainMessage;
use rustls::crypto::cipher::Iv;
use rustls::crypto::cipher::MessageDecrypter;
use rustls::crypto::cipher::MessageEncrypter;
use rustls::crypto::cipher::Nonce;
use rustls::crypto::cipher::OutboundOpaqueMessage;
use rustls::crypto::cipher::OutboundPlainMessage;
use rustls::crypto::cipher::PrefixedPayload;
use rustls::crypto::cipher::Tls13AeadAlgorithm;
use rustls::crypto::cipher::UnsupportedOperationError;
use rustls::crypto::cipher::make_tls13_aad;

use crate::native::AeadAlg;
use crate::native::aead;

/// The tag length of every record AEAD here.
const TAG_LEN: usize = 16;

/// A record AEAD over one of the shell's AEADs.
pub(super) struct RecordAead(&'static aead::Algorithm);

/// AES-128-GCM records.
pub(super) static AES_128_GCM: RecordAead = RecordAead(&aead::AES_128_GCM);

/// AES-256-GCM records.
pub(super) static AES_256_GCM: RecordAead = RecordAead(&aead::AES_256_GCM);

/// ChaCha20-Poly1305 records.
pub(super) static CHACHA20_POLY1305: RecordAead = RecordAead(&aead::CHACHA20_POLY1305);

impl RecordAead {
    fn key(&self, key: &AeadKey) -> aead::LessSafeKey {
        // rustls sizes record keys by `key_len()`, so the length always matches.
        let key = aead::UnboundKey::new(self.0, key.as_ref())
            .expect("rustls sizes record keys by key_len");
        aead::LessSafeKey::new(key)
    }
}

impl Tls13AeadAlgorithm for RecordAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Encrypter {
            key: self.key(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Decrypter {
            key: self.key(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0.id() {
            AeadAlg::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            AeadAlg::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            AeadAlg::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        })
    }
}

struct Encrypter {
    key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(tag.as_ref());
        // TLS 1.3 records carry the legacy version TLS 1.2, as RFC 8446 requires.
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

struct Decrypter {
    key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageDecrypter for Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}
