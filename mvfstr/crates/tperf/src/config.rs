/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The transport and TLS settings each side runs with, which match those of mvfst's tperf.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use mvfstr_proto::AlpnPolicy;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConfigError;
use mvfstr_proto::DatagramSize;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::Version;
use mvfstr_tls::ServerVerification;
use rustls::CipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::time_provider::DefaultTimeProvider;

use crate::flags::Flags;
use crate::flags::MIN_BURST;
use crate::flags::PACING_TICK_US;
use crate::flags::QuicVersion;

/// The application protocol the mvfst tperf server selects.
const ALPN: &[u8] = b"quic_test";

/// The name the client sends as SNI and the certificate holds, as mvfst tperf's client sends.
pub(crate) const SERVER_NAME: &str = "tperf";

/// mvfst's ceiling for an autotuned connection receive window.
const AUTOTUNE_CEILING: u64 = 32 << 20;

/// What both mvfst tperf peers advertise for stream counts and the idle timeout.
const MAX_STREAMS: u64 = 2048;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The active_connection_id_limit an mvfst server advertises.
const SERVER_CONNECTION_ID_LIMIT: u64 = 5;

/// Returns the client's transport settings, those of mvfst's tperf client: a `--window`
/// connection window that autotunes up to 32 MiB with `--autotune_window`, a 4 GiB
/// unidirectional stream window, and `--max_receive_packet_size` as max_udp_payload_size.
pub(crate) fn client_transport(flags: &Flags) -> Result<Arc<TransportConfig>, ConfigError> {
    TransportConfig::builder()
        .max_data(flags.window)
        .max_data_autotune(
            flags
                .autotune_window
                .then(|| AUTOTUNE_CEILING.max(flags.window)),
        )
        .max_stream_data_uni(u64::from(u32::MAX))
        .max_streams_bidi(MAX_STREAMS)
        .max_streams_uni(MAX_STREAMS)
        .idle_timeout(Some(IDLE_TIMEOUT))
        .max_udp_payload_size(flags.max_receive_packet_size)
        .congestion_control(flags.congestion)
        .build()
}

/// Returns the server's transport settings: `--congestion`, `--pacing` and `--max_cwnd_mss`, and
/// with `--override_packet_size` datagrams at the peer's max_udp_payload_size, capped by
/// `--max_receive_packet_size` as mvfst caps it at its own. `--pacing` also sets mvfst tperf's
/// 200 µs tick and minimum burst of 5, or the pacing flags' values, and `--writes_per_loop` as
/// the maximum burst. Flow-control windows are mvfst's defaults.
pub(crate) fn server_transport(flags: &Flags) -> Result<Arc<TransportConfig>, ConfigError> {
    let datagram_size = if flags.override_packet_size {
        DatagramSize::PeerMaximum
    } else {
        DatagramSize::Minimum
    };
    let mut builder = TransportConfig::builder();
    if flags.pacing {
        let tick = flags.pacing_granularity_us.unwrap_or(PACING_TICK_US);
        builder = builder
            .pacing_granularity(Duration::from_micros(u64::from(tick)))
            .pacing_min_burst(flags.pacing_min_burst.unwrap_or(MIN_BURST))
            .pacing_max_burst(flags.writes_per_loop);
    }
    builder
        .max_streams_bidi(MAX_STREAMS)
        .max_streams_uni(MAX_STREAMS)
        .idle_timeout(Some(IDLE_TIMEOUT))
        .max_udp_payload_size(flags.max_receive_packet_size)
        .congestion_control(flags.congestion)
        .pacing(flags.pacing)
        .max_window(flags.max_cwnd_mss)
        .active_connection_id_limit(SERVER_CONNECTION_ID_LIMIT)
        .datagram_size(datagram_size)
        .build()
}

/// Generates the server's certificate and key; mvfst's tperf client accepts any certificate.
pub(crate) fn self_signed()
-> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), rcgen::Error> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = rcgen::CertificateParams::new(vec![SERVER_NAME.to_owned()])?.self_signed(&key)?;
    Ok((
        cert.der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    ))
}

/// Returns the server's settings: a fresh certificate, ALPN `quic_test`, and versions 1 and MVFST
/// and mvfst's aliases of them, which mvfst's tperf server accepts too. With `--compat_mvfst`, a
/// ClientHello of MVFST or its alias may also leave out ALPN, as mvfst's tperf client does.
pub(crate) fn server_config(flags: &Flags) -> Result<Arc<ServerConfig>, SetupError> {
    let (cert, key) = self_signed()?;
    let tls = |alpn: &[&[u8]]| {
        mvfstr_tls::server_config(
            provider(),
            Arc::new(DefaultTimeProvider),
            vec![cert.clone()],
            key.clone_key(),
            alpn,
        )
        .map(Arc::new)
    };
    let mut builder = ServerConfig::builder(tls(&[ALPN])?)
        .transport(server_transport(flags)?)
        .versions(vec![
            Version::V1,
            Version::MVFST,
            Version::QUIC_V1_ALIAS,
            Version::QUIC_V1_ALIAS2,
            Version::MVFST_ALIAS,
        ]);
    if flags.compat_mvfst {
        builder = builder.mvfst_tls(tls(&[])?);
    }
    Ok(builder.build()?)
}

/// Returns how far ahead of its release a server connection may build: `--build_horizon_us`,
/// which needs `--txtime`. The server socket's release horizon caps it.
pub(crate) fn build_horizon(flags: &Flags) -> Duration {
    Duration::from_micros(flags.build_horizon_us.map_or(0, u64::from))
}

/// Returns an endpoint config with a random stateless reset key and the [`build_horizon`].
pub(crate) fn endpoint_config(flags: &Flags) -> Result<Arc<EndpointConfig>, SetupError> {
    let mut reset_key = [0; 32];
    provider()
        .secure_random
        .fill(&mut reset_key)
        .map_err(rustls::Error::from)?;
    Ok(EndpointConfig::builder(reset_key)
        .build_horizon(build_horizon(flags))
        .build()?)
}

/// Returns mvfstr_crypto's default provider, preferring AES-128-GCM as mvfst's tperf peers do.
fn provider() -> CryptoProvider {
    let mut provider = mvfstr_crypto::default_provider();
    provider
        .cipher_suites
        .sort_by_key(|suite| suite.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256);
    provider
}

/// Returns the client's settings: version 1 with ALPN `quic_test`, or with `--quic_version=mvfst`
/// MVFST without ALPN, as mvfst's tperf client offers. The client accepts any server certificate,
/// as that client does.
pub(crate) fn client_config(flags: &Flags) -> Result<Arc<ClientConfig>, SetupError> {
    let (version, alpn, policy): (Version, &[&[u8]], AlpnPolicy) = match flags.quic_version {
        QuicVersion::V1 => (Version::V1, &[ALPN], AlpnPolicy::Required),
        QuicVersion::Mvfst => (Version::MVFST, &[], AlpnPolicy::AllowMissing),
    };
    let tls = mvfstr_tls::client_config(
        provider(),
        Arc::new(DefaultTimeProvider),
        ServerVerification::AcceptAnyCertificate,
        alpn,
    )?;
    Ok(ClientConfig::builder(Arc::new(tls))
        .transport(client_transport(flags)?)
        .versions(vec![version])
        .alpn(policy)
        .build()?)
}

/// Why the settings could not be built.
#[derive(Debug)]
pub enum SetupError {
    /// Generating the certificate failed.
    Certificate(rcgen::Error),
    /// rustls refused the TLS settings.
    Tls(rustls::Error),
    /// A transport, server or client config refused its settings.
    Config(ConfigError),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(error) => write!(f, "generating the certificate failed: {error}"),
            Self::Tls(error) => write!(f, "rustls refused the TLS settings: {error}"),
            Self::Config(error) => write!(f, "invalid settings: {error}"),
        }
    }
}

impl std::error::Error for SetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Config(error) => Some(error),
        }
    }
}

impl From<rcgen::Error> for SetupError {
    fn from(error: rcgen::Error) -> Self {
        Self::Certificate(error)
    }
}

impl From<rustls::Error> for SetupError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

impl From<ConfigError> for SetupError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::CongestionControl;
    use rustls::SignatureAlgorithm;
    use rustls::SignatureScheme;
    use rustls::sign::CertifiedKey;

    use super::*;

    #[test]
    fn the_client_advertises_what_the_mvfst_tperf_client_does() {
        let config = client_transport(&Flags::default()).unwrap();
        assert_eq!(config.max_data(), 1 << 20);
        assert_eq!(config.max_data_autotune(), Some(32 << 20));
        assert_eq!(config.max_stream_data_uni(), u64::from(u32::MAX));
        assert_eq!(config.max_stream_data_bidi_local(), 65 * 1024);
        assert_eq!(config.max_stream_data_bidi_remote(), 65 * 1024);
        assert_eq!(config.max_stream_data_autotune(), None);
        assert_eq!(
            (config.max_streams_bidi(), config.max_streams_uni()),
            (2048, 2048)
        );
        assert_eq!(config.idle_timeout(), Some(Duration::from_secs(60)));
        assert_eq!(config.max_udp_payload_size(), 1452);
        assert_eq!(config.active_connection_id_limit(), 2);
        assert_eq!(config.congestion_control(), CongestionControl::Cubic);
        assert_eq!(config.datagram_size(), DatagramSize::Minimum);

        let flags = Flags {
            window: 3 << 20,
            max_receive_packet_size: 1350,
            congestion: CongestionControl::NewReno,
            ..Flags::default()
        };
        let config = client_transport(&flags).unwrap();
        assert_eq!(config.max_data(), 3 << 20);
        assert_eq!(config.max_udp_payload_size(), 1350);
        assert_eq!(config.congestion_control(), CongestionControl::NewReno);
        let fixed = Flags {
            autotune_window: false,
            ..Flags::default()
        };
        assert_eq!(client_transport(&fixed).unwrap().max_data_autotune(), None);
        let large = Flags {
            window: 64 << 20,
            ..Flags::default()
        };
        assert_eq!(
            client_transport(&large).unwrap().max_data_autotune(),
            Some(64 << 20),
            "a window above 32 MiB is its own ceiling"
        );
    }

    #[test]
    fn the_server_sends_as_the_mvfst_tperf_server_does() {
        let config = server_transport(&Flags::default()).unwrap();
        assert_eq!(config.datagram_size(), DatagramSize::PeerMaximum);
        assert_eq!(config.max_window(), 860_000);
        assert_eq!(config.congestion_control(), CongestionControl::Cubic);
        assert!(!config.pacing());
        assert_eq!(config.max_udp_payload_size(), 1452);
        // mvfst's own defaults: the server ignores --window.
        assert_eq!(config.max_data(), 1 << 20);
        assert_eq!(config.max_data_autotune(), None);
        assert_eq!(config.max_stream_data_uni(), 65 * 1024);
        assert_eq!(
            (config.max_streams_bidi(), config.max_streams_uni()),
            (2048, 2048)
        );
        assert_eq!(config.idle_timeout(), Some(Duration::from_secs(60)));
        assert_eq!(config.active_connection_id_limit(), 5);

        let flags = Flags {
            override_packet_size: false,
            max_cwnd_mss: 1000,
            congestion: CongestionControl::NewReno,
            pacing: true,
            max_receive_packet_size: 1300,
            window: 8 << 20,
            ..Flags::default()
        };
        let config = server_transport(&flags).unwrap();
        assert_eq!(config.datagram_size(), DatagramSize::Minimum);
        assert_eq!(config.max_window(), 1000);
        assert_eq!(config.congestion_control(), CongestionControl::NewReno);
        assert!(config.pacing());
        assert_eq!(config.max_udp_payload_size(), 1300);
        assert_eq!(config.max_data(), 1 << 20);
    }

    #[test]
    fn pacing_sets_mvfst_tperfs_tick_and_minimum_burst_and_the_batch_as_maximum_burst() {
        let bursts = |flags: &Flags| {
            let config = server_transport(flags).unwrap();
            (
                config.pacing_granularity(),
                config.pacing_min_burst(),
                config.pacing_max_burst(),
            )
        };
        let us = Duration::from_micros;
        let paced = Flags {
            pacing: true,
            ..Flags::default()
        };
        assert_eq!(bursts(&paced), (us(200), 5, 44));
        let tuned = Flags {
            pacing_granularity_us: Some(100),
            pacing_min_burst: Some(8),
            writes_per_loop: 16,
            ..paced
        };
        assert_eq!(bursts(&tuned), (us(100), 8, 16));
        // Unpaced, the library's defaults stay.
        let unpaced = Flags {
            writes_per_loop: 4,
            ..Flags::default()
        };
        assert_eq!(bursts(&unpaced), (us(1000), 5, 44));
    }

    #[test]
    fn the_server_certificate_is_a_fresh_self_signed_p256_one() {
        let (cert, key) = self_signed().unwrap();
        // The mvfst tperf client offers only ECDSA and RSA-PSS signature schemes.
        let provider = mvfstr_crypto::default_provider();
        let signer = provider
            .key_provider
            .load_private_key(key.clone_key())
            .expect("a key the provider loads");
        assert_eq!(signer.algorithm(), SignatureAlgorithm::ECDSA);
        assert!(
            signer
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some()
        );
        assert!(
            signer
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none(),
            "a P-256 key"
        );
        CertifiedKey::from_der(vec![cert.clone()], key, &provider)
            .expect("the certificate holds the key's public half");
        let (other, _) = self_signed().unwrap();
        assert_ne!(cert, other, "every run makes its own");
    }

    /// Returns the first cipher suite of `provider`, its most preferred one.
    fn first_suite(provider: &rustls::crypto::CryptoProvider) -> CipherSuite {
        provider.cipher_suites[0].suite()
    }

    /// The versions mvfst's tperf server accepts that mvfstr implements.
    const SERVER_VERSIONS: [Version; 5] = [
        Version::V1,
        Version::MVFST,
        Version::QUIC_V1_ALIAS,
        Version::QUIC_V1_ALIAS2,
        Version::MVFST_ALIAS,
    ];

    #[test]
    fn the_server_takes_quic_test_and_in_compat_mode_mvfst_without_alpn() {
        let config = server_config(&Flags::default()).unwrap();
        assert_eq!(config.versions(), SERVER_VERSIONS);
        assert_eq!(config.transport().max_window(), 860_000);
        assert_eq!(config.tls().alpn_protocols, [b"quic_test".to_vec()]);
        assert_eq!(
            first_suite(config.tls().crypto_provider()),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            "AES-128-GCM, which mvfst peers negotiate"
        );
        let (v1, policy) = config.tls_without_alpn(Version::V1);
        assert!(v1.is_none());
        assert_eq!(policy, AlpnPolicy::Required);
        let (mvfst, policy) = config.tls_without_alpn(Version::MVFST);
        assert!(
            mvfst
                .expect("a config without ALPN")
                .alpn_protocols
                .is_empty()
        );
        assert_eq!(policy, AlpnPolicy::AllowMissing);

        let strict = Flags {
            compat_mvfst: false,
            ..Flags::default()
        };
        let config = server_config(&strict).unwrap();
        assert_eq!(config.versions(), SERVER_VERSIONS);
        let (mvfst, policy) = config.tls_without_alpn(Version::MVFST);
        assert!(mvfst.is_none());
        assert_eq!(policy, AlpnPolicy::Required);
    }

    #[test]
    fn the_client_offers_version_1_with_quic_test_or_mvfst_without_alpn() {
        let config = client_config(&Flags::default()).unwrap();
        assert_eq!(config.versions(), [Version::V1]);
        assert_eq!(config.tls().alpn_protocols, [b"quic_test".to_vec()]);
        assert_eq!(config.alpn(), AlpnPolicy::Required);
        assert_eq!(config.transport().max_data_autotune(), Some(32 << 20));
        assert_eq!(
            first_suite(config.tls().crypto_provider()),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );

        let mvfst = Flags {
            mode: crate::flags::Mode::Client,
            quic_version: QuicVersion::Mvfst,
            ..Flags::default()
        };
        let config = client_config(&mvfst).unwrap();
        assert_eq!(config.versions(), [Version::MVFST]);
        assert!(config.tls().alpn_protocols.is_empty());
        assert_eq!(config.alpn(), AlpnPolicy::AllowMissing);
    }

    #[test]
    fn build_horizon_us_sets_how_far_ahead_the_server_may_build() {
        assert_eq!(
            endpoint_config(&Flags::default()).unwrap().build_horizon(),
            Duration::ZERO
        );
        let flags = Flags {
            pacing: true,
            txtime: true,
            build_horizon_us: Some(5000),
            ..Flags::default()
        };
        assert_eq!(
            endpoint_config(&flags).unwrap().build_horizon(),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn every_endpoint_gets_its_own_reset_key() {
        let first = endpoint_config(&Flags::default()).unwrap();
        let second = endpoint_config(&Flags::default()).unwrap();
        assert_ne!(first.reset_key(), second.reset_key());
        assert_eq!(first.worker(), (0, 1), "one worker, as mvfst tperf");
    }
}
