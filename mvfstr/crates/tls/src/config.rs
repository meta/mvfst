/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! rustls configs for QUIC (RFC 9001).
//!
//! Both helpers allow TLS 1.3 only, rewrite the caller's crypto provider so that every packet
//! key is an mvfstr key ([`mvfstr_crypto::with_quic_suites`]), and take the time from the
//! caller's [`TimeProvider`] instead of the system clock.

use std::fmt;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

/// Builds a server config for QUIC with one certificate chain and its key.
///
/// `alpn` lists the application protocols the server accepts, in preference order. With an empty
/// list the server does not negotiate an application protocol and accepts only clients that do
/// not offer one, the mode that mvfst tperf clients use. With a non-empty list, a client that does
/// not offer any of them fails with CRYPTO_ERROR 0x0178.
///
/// Fails with a [`rustls::Error`] when the rewritten provider does not have a TLS 1.3 suite or a
/// key exchange group, when the provider cannot load `key`, or when `key` does not match the first
/// certificate of `cert_chain`.
pub fn server_config(
    provider: CryptoProvider,
    time: Arc<dyn TimeProvider>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<ServerConfig, rustls::Error> {
    let provider = Arc::new(mvfstr_crypto::with_quic_suites(provider));
    let mut config = ServerConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// How a client checks the server's certificate.
#[derive(Clone, Debug)]
pub enum ServerVerification {
    /// Verify the chain and the server name against these roots with webpki.
    Roots(Arc<RootCertStore>),
    /// Accept any chain for any name, but still check the CertificateVerify signature, which
    /// proves the server holds the certificate's key. For benchmarks and tests only; mvfst tperf
    /// clients do the same.
    AcceptAnyCertificate,
}

/// Builds a client config for QUIC.
///
/// `alpn` lists the application protocols to offer, in preference order; with an empty list the
/// client does not offer any.
///
/// Fails with a [`rustls::Error`] when the rewritten provider does not have a TLS 1.3 suite or a
/// key exchange group.
pub fn client_config(
    provider: CryptoProvider,
    time: Arc<dyn TimeProvider>,
    verification: ServerVerification,
    alpn: &[&[u8]],
) -> Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(mvfstr_crypto::with_quic_suites(provider));
    let builder = ClientConfig::builder_with_details(provider.clone(), time)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = match verification {
        ServerVerification::Roots(roots) => builder.with_root_certificates(roots),
        ServerVerification::AcceptAnyCertificate => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new(&provider))),
    }
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// A certificate verifier that accepts any chain and name but checks the CertificateVerify
/// signature with the provider's algorithms.
pub struct AcceptAnyServerCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AcceptAnyServerCert {
    /// Builds a verifier that checks signatures with `provider`'s verification algorithms.
    pub fn new(provider: &CryptoProvider) -> AcceptAnyServerCert {
        AcceptAnyServerCert {
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for AcceptAnyServerCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptAnyServerCert")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
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
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;
    use crate::time::ManualTimeProvider;

    fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        (vec![certified.cert.der().clone()], key.into())
    }

    fn only_mvfstr_tls13_suites(provider: &CryptoProvider) -> bool {
        !provider.cipher_suites.is_empty()
            && provider.cipher_suites.iter().all(|suite| {
                suite
                    .tls13()
                    .is_some_and(|suite| mvfstr_crypto::quic_algorithm(suite).is_some())
            })
    }

    #[test]
    fn configs_use_mvfstr_suites_the_alpn_list_and_the_callers_time() {
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let time = Arc::new(ManualTimeProvider::new(now));
        let (chain, key) = self_signed();
        let server = server_config(
            rustls::crypto::aws_lc_rs::default_provider(),
            time.clone(),
            chain,
            key,
            &[b"h3", b"hq-interop"],
        )
        .unwrap();
        assert_eq!(
            server.alpn_protocols,
            [b"h3".to_vec(), b"hq-interop".to_vec()]
        );
        assert!(only_mvfstr_tls13_suites(server.crypto_provider()));
        assert_eq!(server.time_provider.current_time(), Some(now));
        assert_eq!(server.max_early_data_size, 0);

        let client = client_config(
            rustls::crypto::aws_lc_rs::default_provider(),
            time.clone(),
            ServerVerification::AcceptAnyCertificate,
            &[],
        )
        .unwrap();
        assert!(client.alpn_protocols.is_empty());
        assert!(only_mvfstr_tls13_suites(client.crypto_provider()));
        let later = UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_100));
        time.set(later);
        assert_eq!(client.time_provider.current_time(), Some(later));
        assert!(!client.enable_early_data);
    }
}
