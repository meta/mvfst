/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The provider against rustls's ring provider: its lists, and TLS and QUIC handshakes in memory.

use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use rustls::CipherSuite;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::HandshakeKind;
use rustls::NamedGroup;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use rustls::SupportedCipherSuite;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::quic;
use rustls::quic::PacketKey;

use super::*;
use crate::KeySet;
use crate::KeyUpdater;
use crate::testcerts::KeyType;
use crate::testcerts::self_signed;

fn ring_provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

fn suite_ids(provider: &CryptoProvider) -> Vec<CipherSuite> {
    provider
        .cipher_suites
        .iter()
        .filter(|suite| suite.tls13().is_some())
        .map(|suite| suite.suite())
        .collect()
}

#[test]
fn the_lists_match_rustls_ring_provider() {
    let (ours, ring) = (default_provider(), ring_provider());
    assert_eq!(suite_ids(&ours), suite_ids(&ring));
    assert_eq!(ours.cipher_suites.len(), 3, "TLS 1.3 suites only");
    for (suite, theirs) in ours.cipher_suites.iter().zip(&ring.cipher_suites) {
        let (suite, theirs) = (suite.tls13().unwrap(), theirs.tls13().unwrap());
        assert_eq!(
            suite.common.hash_provider.algorithm(),
            theirs.common.hash_provider.algorithm()
        );
        assert_eq!(
            suite.common.confidentiality_limit,
            theirs.common.confidentiality_limit
        );
        assert_eq!(suite.aead_alg.key_len(), theirs.aead_alg.key_len());
        assert!(!suite.fips());
    }
    let groups: Vec<NamedGroup> = ours.kx_groups.iter().map(|group| group.name()).collect();
    assert_eq!(groups, [NamedGroup::X25519, NamedGroup::secp256r1]);
    assert_eq!(
        ours.signature_verification_algorithms.supported_schemes(),
        ring.signature_verification_algorithms.supported_schemes()
    );
    let mapping = |algorithms: &WebPkiSupportedAlgorithms| {
        algorithms
            .mapping
            .iter()
            .map(|(scheme, algs)| {
                let ids: Vec<_> = algs
                    .iter()
                    .map(|alg| (alg.public_key_alg_id(), alg.signature_alg_id()))
                    .collect();
                (*scheme, ids)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        mapping(&ours.signature_verification_algorithms),
        mapping(&ring.signature_verification_algorithms)
    );
    assert!(!ours.fips());
}

#[test]
fn the_rewritten_provider_is_the_cipher_suite_statics() {
    let rewritten = crate::with_quic_suites(default_provider());
    let statics = [
        &crate::cipher_suite::TLS13_AES_256_GCM_SHA384,
        &crate::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &crate::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    assert_eq!(rewritten.cipher_suites.len(), statics.len());
    for ((suite, expected), base) in rewritten
        .cipher_suites
        .iter()
        .zip(statics)
        .zip(default_provider().cipher_suites)
    {
        let suite = suite.tls13().unwrap();
        assert!(
            std::ptr::eq(suite, base.tls13().unwrap()),
            "kept, not derived"
        );
        assert_eq!(suite.common.suite, expected.common.suite);
        assert!(std::ptr::addr_eq(
            suite.common.hash_provider,
            expected.common.hash_provider
        ));
        assert_eq!(
            suite.common.confidentiality_limit,
            expected.common.confidentiality_limit
        );
        assert!(std::ptr::addr_eq(
            suite.hkdf_provider,
            expected.hkdf_provider
        ));
        assert!(std::ptr::addr_eq(suite.aead_alg, expected.aead_alg));
        let (quic, expected_quic) = (
            crate::quic_algorithm(suite).unwrap(),
            crate::quic_algorithm(expected).unwrap(),
        );
        assert!(std::ptr::eq(quic, expected_quic));
    }
}

#[test]
fn random_fills_and_differs() {
    let random = default_provider().secure_random;
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    random.fill(&mut a).unwrap();
    random.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0; 64]);
    random.fill(&mut []).unwrap();
}

#[test]
fn the_key_provider_loads_no_keys() {
    let key = self_signed(KeyType::P256).key;
    let result = default_provider().key_provider.load_private_key(key);
    assert!(matches!(result, Err(rustls::Error::General(_))));
    let garbage = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(vec![1, 2, 3]));
    assert!(
        default_provider()
            .key_provider
            .load_private_key(garbage)
            .is_err()
    );
}

/// A client verifier that accepts any chain and checks CertificateVerify with
/// `verify_tls13_certificate_signature`, counting the calls.
#[derive(Debug)]
struct Verifier {
    algorithms: WebPkiSupportedAlgorithms,
    calls: AtomicUsize,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        crate::verify_tls13_certificate_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Returns a client config on `provider` with a [`Verifier`] over the provider's own algorithms.
fn client_config(provider: CryptoProvider) -> (Arc<ClientConfig>, Arc<Verifier>) {
    let verifier = Arc::new(Verifier {
        algorithms: provider.signature_verification_algorithms,
        calls: AtomicUsize::new(0),
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    (Arc::new(config), verifier)
}

/// Returns a server config on `provider` with a certificate of `kind`.
fn server_config(provider: CryptoProvider, kind: KeyType) -> Arc<ServerConfig> {
    let cert = self_signed(kind);
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert], cert.key)
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

/// Returns rustls's ring provider with only `suite` and only `groups`.
fn ring_with(suite: SupportedCipherSuite, groups: &[NamedGroup]) -> CryptoProvider {
    let ring = ring_provider();
    CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: ring
            .kx_groups
            .iter()
            .copied()
            .filter(|group| groups.contains(&group.name()))
            .collect(),
        ..ring
    }
}

const RING_SUITES: [SupportedCipherSuite; 3] = [
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

/// Moves every TLS record `from` has to `to`; true if there were any.
fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) -> bool {
    let mut records = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut records).unwrap();
    }
    let mut unread = &records[..];
    while !unread.is_empty() {
        to.read_tls(&mut unread).unwrap();
        to.process_new_packets().unwrap();
    }
    !records.is_empty()
}

#[test]
fn tls_over_tcp_with_a_ring_server_exchanges_data_with_each_suite() {
    let groups = [NamedGroup::X25519, NamedGroup::secp256r1];
    for suite in RING_SUITES {
        let (config, verifier) = client_config(default_provider());
        let mut client: rustls::Connection =
            rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
                .unwrap()
                .into();
        let server_config = server_config(ring_with(suite, &groups), KeyType::P256);
        let mut server: rustls::Connection =
            rustls::ServerConnection::new(server_config).unwrap().into();
        while pump(&mut client, &mut server) | pump(&mut server, &mut client) {}
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(
            client.negotiated_cipher_suite().unwrap().suite(),
            suite.suite()
        );
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);

        client.writer().write_all(b"from the client").unwrap();
        pump(&mut client, &mut server);
        let mut received = [0; 15];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"from the client");

        server.writer().write_all(b"from the server").unwrap();
        pump(&mut server, &mut client);
        client.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"from the server");
    }
}

/// One side of an in-memory QUIC handshake, with the 1-RTT keys it installed.
struct QuicPeer {
    conn: quic::Connection,
    one_rtt: Option<(KeySet, KeyUpdater)>,
}

impl QuicPeer {
    /// Hands everything `self` has written to `to`; true if there was anything.
    fn send(&mut self, to: &mut QuicPeer) -> bool {
        let mut progressed = false;
        loop {
            let mut crypto = Vec::new();
            let change = self.conn.write_hs(&mut crypto);
            if !crypto.is_empty() {
                to.conn.read_hs(&crypto).unwrap();
                progressed = true;
            }
            match change {
                Some(quic::KeyChange::OneRtt { keys, next }) => {
                    let keys = KeySet::from_rustls(keys);
                    let updater = KeyUpdater::new(next, &keys);
                    self.one_rtt = Some((keys, updater));
                }
                Some(quic::KeyChange::Handshake { .. }) => {}
                None if crypto.is_empty() => return progressed,
                None => {}
            }
            progressed = true;
        }
    }
}

/// Seals a packet with `tx` and opens it with `rx`.
fn seal_open(tx: &dyn PacketKey, rx: &dyn PacketKey, packet_number: u64) {
    let header = [0x41, 0x01, 0x02, 0x03];
    let mut packet = b"a 1-RTT packet".to_vec();
    let tag = tx
        .encrypt_in_place(packet_number, &header, &mut packet)
        .unwrap();
    packet.extend_from_slice(tag.as_ref());
    let plain = rx
        .decrypt_in_place(packet_number, &header, &mut packet)
        .unwrap();
    assert_eq!(plain, b"a 1-RTT packet");
}

/// Runs a QUIC handshake of a client on `default_provider()` against a ring server, and checks
/// that their 1-RTT keys and next key phase work in both directions. Returns the client.
fn quic_handshake(server: Arc<ServerConfig>) -> (quic::Connection, Arc<Verifier>) {
    let (config, verifier) = client_config(crate::default_provider());
    let client = quic::ClientConnection::new(
        config,
        quic::Version::V1,
        ServerName::try_from("localhost").unwrap(),
        b"client transport parameters".to_vec(),
    )
    .unwrap();
    let server = quic::ServerConnection::new(
        server,
        quic::Version::V1,
        b"server transport parameters".to_vec(),
    )
    .unwrap();
    let mut client = QuicPeer {
        conn: client.into(),
        one_rtt: None,
    };
    let mut server = QuicPeer {
        conn: server.into(),
        one_rtt: None,
    };
    while client.send(&mut server) | server.send(&mut client) {}
    assert!(!client.conn.is_handshaking() && !server.conn.is_handshaking());
    assert_eq!(
        client.conn.quic_transport_parameters(),
        Some(&b"server transport parameters"[..])
    );
    let (mut client_keys, mut client_updater) = client.one_rtt.take().unwrap();
    let (mut server_keys, mut server_updater) = server.one_rtt.take().unwrap();
    for phase in 0..2 {
        seal_open(
            client_keys.local.packet(),
            server_keys.remote.packet(),
            phase,
        );
        seal_open(
            server_keys.local.packet(),
            client_keys.remote.packet(),
            phase,
        );
        client_keys = client_updater.next_keys();
        server_keys = server_updater.next_keys();
    }
    (client.conn, verifier)
}

#[test]
fn quic_handshakes_with_a_ring_server_cover_every_certificate_and_suite() {
    let groups = [NamedGroup::X25519, NamedGroup::secp256r1];
    for kind in KeyType::ALL {
        for suite in RING_SUITES {
            let server = crate::with_quic_suites(ring_with(suite, &groups));
            let (client, verifier) = quic_handshake(server_config(server, kind));
            assert_eq!(
                client.negotiated_cipher_suite().unwrap().suite(),
                suite.suite()
            );
            assert_eq!(
                client.negotiated_key_exchange_group().unwrap().name(),
                NamedGroup::X25519
            );
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
            assert_eq!(verifier.calls.load(Ordering::Relaxed), 1, "{kind:?}");
        }
    }
}

#[test]
fn a_quic_handshake_completes_on_p256_after_hello_retry_request() {
    let server = crate::with_quic_suites(ring_with(RING_SUITES[1], &[NamedGroup::secp256r1]));
    let (client, verifier) = quic_handshake(server_config(server, KeyType::P256));
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
}
