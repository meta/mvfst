/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Configs and connections for the driver's tests.

use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::MmsgOptions;
use mvfstr_io::SocketOptions;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::config::TransportConfigBuilder;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::UnixTime;

/// A plain place in the wire order for test streams.
pub(crate) const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

/// Returns a client config and a server config for a self-signed `localhost` certificate, both
/// with ALPN `h3`, and an endpoint config.
pub(crate) fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    configs_carrying(None)
}

/// Like [`configs`], with `transport`, if any, for both sides.
fn configs_carrying(
    transport: Option<Arc<TransportConfig>>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    let key = rcgen::KeyPair::generate().expect("rcgen makes a key");
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen takes the name");
    configs_of(params, &key, transport)
}

/// Returns the configs of [`configs`] for the certificate that `params` describes, signed by
/// `key`.
pub(crate) fn configs_with(
    params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
) -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    configs_of(params, key, None)
}

/// Like [`configs_with`], with `transport`, if any, for both sides.
fn configs_of(
    params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
    transport: Option<Arc<TransportConfig>>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    let cert = params.self_signed(key).expect("rcgen makes a certificate");
    let time = Arc::new(ManualTimeProvider::new(UnixTime::now()));
    let alpn: &[&[u8]] = &[b"h3"];
    let server_tls = mvfstr_tls::server_config(
        provider(),
        time.clone(),
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        alpn,
    )
    .expect("a server TLS config");
    let client_tls = mvfstr_tls::client_config(
        provider(),
        time,
        ServerVerification::AcceptAnyCertificate,
        alpn,
    )
    .expect("a client TLS config");
    let mut server = ServerConfig::builder(Arc::new(server_tls));
    let mut client = ClientConfig::builder(Arc::new(client_tls));
    if let Some(transport) = transport {
        server = server.transport(transport.clone());
        client = client.transport(transport);
    }
    let server = server.build().expect("a server config");
    let client = client.build().expect("a client config");
    let endpoint = EndpointConfig::builder(reset_key())
        .build()
        .expect("an endpoint config");
    (client, server, endpoint)
}

/// Returns a stateless reset key read from the OS's random source, so that a reset from another
/// test's endpoint does not carry a token that this test's endpoints accept.
pub(crate) fn reset_key() -> [u8; 32] {
    let mut key = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut key))
        .expect("the OS's random source reads");
    key
}

/// Returns the backend's default settings without SO_REUSEPORT. If two sockets of one user both
/// set it, Linux may bind the second to the first one's port when asked for port 0 and then spread
/// datagrams over both, so one test's server could receive another test's connections.
pub(crate) fn mmsg_options() -> MmsgOptions {
    MmsgOptions {
        socket: SocketOptions {
            reuse_port: false,
            ..SocketOptions::default()
        },
        ..MmsgOptions::default()
    }
}

/// Returns a client config like the one [`configs`] returns that also offers the protocols `more`
/// after `h3`, so its ClientHello can be made to span several packets.
pub(crate) fn client_config_offering(more: &[&[u8]]) -> Arc<ClientConfig> {
    let alpn: Vec<&[u8]> = [b"h3".as_slice()]
        .into_iter()
        .chain(more.iter().copied())
        .collect();
    let tls = mvfstr_tls::client_config(
        provider(),
        Arc::new(ManualTimeProvider::new(UnixTime::now())),
        ServerVerification::AcceptAnyCertificate,
        &alpn,
    )
    .expect("a client TLS config");
    ClientConfig::builder(Arc::new(tls))
        .build()
        .expect("a client config")
}

/// Returns the crypto provider of the test configs, with X25519 alone for key exchange.
fn provider() -> CryptoProvider {
    let mut provider = mvfstr_crypto::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    provider
}

/// Returns a pair harness whose handshake has completed.
pub(crate) fn handshaken_pair() -> Pair {
    handshake(configs())
}

/// Returns a pair harness whose two sides take DATAGRAM frames, with its handshake completed.
pub(crate) fn handshaken_datagram_pair() -> Pair {
    handshaken_datagram_pair_with(|transport| transport)
}

/// Like [`handshaken_datagram_pair`], with the transport settings `f` makes of those.
pub(crate) fn handshaken_datagram_pair_with(
    f: impl FnOnce(TransportConfigBuilder) -> TransportConfigBuilder,
) -> Pair {
    let transport = f(TransportConfig::builder().max_datagram_frame_size(65535))
        .build()
        .expect("a transport config");
    handshake(configs_carrying(Some(transport)))
}

/// Returns a pair harness of `configs` whose handshake has completed.
fn handshake(
    (client, server, endpoint): (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>),
) -> Pair {
    let epoch = Instant::now();
    let mut pair = Pair::new(
        epoch,
        UnixTime::now(),
        PairConfig::new(client, server, endpoint),
    );
    assert!(
        pair.handshake(epoch + Duration::from_secs(5)),
        "the handshake completes"
    );
    pair
}
