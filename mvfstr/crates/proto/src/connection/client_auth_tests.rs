/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of client certificates over the pair harness: a server that asks for one and accepts a
//! client without one, and a client that presents one.

use std::sync::Arc;
use std::time::Duration;

use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use mvfstr_tls::testing::RustlsHost;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;

use super::tests::LIMIT;
use super::tests::handshake;
use super::tests::start;
use crate::CloseReason;
use crate::ConnEvent;
use crate::Initiator;
use crate::ServerTls;
use crate::testing::PairConfig;
use crate::testing::Peer;
use crate::testing::fixtures::Setup;
use crate::testing::fixtures::unix_now;

/// The TLS alert for a certificate whose issuer is not among the roots (RFC 8446).
const UNKNOWN_CA: u8 = 48;

/// A certificate chain and its key.
type Identity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Returns the Ed25519 key with this seed, as PKCS #8 (RFC 8410). Fixed keys make every
/// certificate, and so every handshake, the same in each run.
fn ed25519(seed: u8) -> PrivatePkcs8KeyDer<'static> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    PrivatePkcs8KeyDer::from([&PREFIX[..], &[seed; 32]].concat())
}

fn key_pair(key: &PrivatePkcs8KeyDer<'_>) -> rcgen::KeyPair {
    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(key, &rcgen::PKCS_ED25519)
        .expect("rcgen takes the Ed25519 key")
}

/// A certificate authority that issues client certificates.
struct Ca {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Ca {
    fn new(name: &str, seed: u8) -> Ca {
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("CA params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(params, key_pair(&ed25519(seed)))
            .expect("rcgen makes the CA certificate");
        Ca { issuer }
    }

    /// Returns roots that hold only this CA.
    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(self.issuer.der().clone())
            .expect("the CA certificate is a valid root");
        Arc::new(roots)
    }

    /// Issues a client certificate, and returns the chain the client presents: the certificate,
    /// then the CA's.
    fn client(&self, seed: u8) -> Identity {
        let key = ed25519(seed);
        let mut params =
            rcgen::CertificateParams::new(vec!["client.test".to_owned()]).expect("client params");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params
            .signed_by(&key_pair(&key), &self.issuer)
            .expect("the CA signs the client certificate");
        (
            vec![cert.der().clone(), self.issuer.der().clone()],
            key.into(),
        )
    }
}

/// Returns the server's self-signed certificate for localhost.
fn server_identity() -> Identity {
    let key = ed25519(1);
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .and_then(|params| params.self_signed(&key_pair(&key)))
        .expect("rcgen makes the server certificate");
    (vec![cert.der().clone()], key.into())
}

/// Returns mvfstr_crypto's provider with X25519 alone, so that a ClientHello fits one packet.
fn provider() -> CryptoProvider {
    let mut provider = mvfstr_crypto::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519);
    provider
}

fn time() -> Arc<ManualTimeProvider> {
    Arc::new(ManualTimeProvider::new(unix_now()))
}

/// Builds the rustls configs of a server that asks for client certificates issued under
/// `client_roots`, or with `None` asks for none, and of a client that presents `client` when
/// asked.
fn tls(
    client_roots: Option<Arc<RootCertStore>>,
    client: Option<Identity>,
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let (chain, key) = server_identity();
    let alpn: &[&[u8]] = &[b"h3"];
    let server = match client_roots {
        Some(roots) => {
            mvfstr_tls::server_config_with_client_auth(provider(), time(), chain, key, alpn, roots)
        }
        None => mvfstr_tls::server_config(provider(), time(), chain, key, alpn),
    }
    .expect("a server TLS config");
    let verification = ServerVerification::AcceptAnyCertificate;
    let client = match client {
        Some((chain, key)) => {
            mvfstr_tls::client_config_with_cert(provider(), time(), verification, alpn, chain, key)
        }
        None => mvfstr_tls::client_config(provider(), time(), verification, alpn),
    }
    .expect("a client TLS config");
    (Arc::new(server), Arc::new(client))
}

/// Builds a pair whose handshakes run on rustls with the configs of [`tls`].
fn pair(client_roots: Option<Arc<RootCertStore>>, client: Option<Identity>) -> PairConfig {
    let (server, client) = tls(client_roots, client);
    Setup::default().pair_with(server.into(), client.into())
}

/// Returns the code of the transport CONNECTION_CLOSE `peer` reported, and who closed.
fn close_of(peer: &Peer) -> Option<(TransportErrorCode, Initiator)> {
    peer.events.iter().find_map(|event| match event {
        ConnEvent::Closed {
            reason: CloseReason::Transport { code, .. },
            initiator,
        } => Some((*code, *initiator)),
        _ => None,
    })
}

#[test]
fn a_client_certificate_from_another_ca_fails_the_handshake_with_the_tls_alert() {
    let configured = Ca::new("mvfstr test client CA", 2);
    let other = Ca::new("another client CA", 3);
    let (epoch, mut pair) = start(pair(Some(configured.roots()), Some(other.client(4))));
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    });

    let code = TransportErrorCode::crypto(UNKNOWN_CA);
    assert_eq!(close_of(&pair.server), Some((code, Initiator::Local)));
    assert_eq!(close_of(&pair.client), Some((code, Initiator::Peer)));
    assert!(!pair.server.has_event(&ConnEvent::Connected));
    for peer in [&pair.client, &pair.server] {
        assert!(!peer.has_event(&ConnEvent::Confirmed));
        assert_eq!(peer.events.last(), Some(&ConnEvent::Drained));
    }
}

#[test]
fn the_client_sees_the_servers_certificate_chain() {
    let (_, pair) = handshake(pair(None, None));
    let (chain, _) = server_identity();
    assert_eq!(pair.client.conn().peer_certificates(), Some(&chain[..]));
}

#[test]
fn a_client_certificate_from_the_configured_ca_appears_in_peer_certificates() {
    let ca = Ca::new("mvfstr test client CA", 2);
    let (chain, key) = ca.client(4);
    let (_, pair) = handshake(pair(Some(ca.roots()), Some((chain.clone(), key))));
    // The server has confirmed the handshake and dropped its TLS state; the chain stays.
    assert!(pair.server.has_event(&ConnEvent::Confirmed));
    assert_eq!(pair.server.conn().peer_certificates(), Some(&chain[..]));
}

#[test]
fn no_client_certificate_gives_none_and_the_handshake_succeeds() {
    let ca = Ca::new("mvfstr test client CA", 2);
    let (epoch, mut pair) = start(pair(Some(ca.roots()), None));
    assert!(
        pair.handshake(epoch + LIMIT),
        "no handshake: client {:?}, server {:?}",
        pair.client.events,
        pair.server.events
    );
    assert_eq!(pair.server.conn().peer_certificates(), None);
    let (chain, _) = server_identity();
    assert_eq!(pair.client.conn().peer_certificates(), Some(&chain[..]));
}

#[test]
fn a_server_that_does_not_ask_gets_no_client_certificate() {
    let ca = Ca::new("mvfstr test client CA", 2);
    let (_, pair) = handshake(pair(None, Some(ca.client(4))));
    assert_eq!(pair.server.conn().peer_certificates(), None);
}

#[test]
fn a_server_whose_tls_host_runs_the_handshake_reports_no_client_certificate() {
    let ca = Ca::new("mvfstr test client CA", 2);
    let (server_tls, client_tls) = tls(Some(ca.roots()), Some(ca.client(4)));
    let config = Setup::default().pair_with(ServerTls::External, client_tls.into());
    let (epoch, mut pair) = start(config);
    pair.set_tls_host(
        Side::Server,
        Box::new(RustlsHost::server(server_tls)),
        Duration::ZERO,
    );
    assert!(pair.handshake(epoch + LIMIT));
    // The host verified the client's certificate, but a TLS host does not report it.
    assert_eq!(pair.server.conn().peer_certificates(), None);
}
