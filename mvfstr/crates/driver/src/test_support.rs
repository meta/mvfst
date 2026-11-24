/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Configs and connections for the driver's tests.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ClientConfig;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use rustls::NamedGroup;
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
    let key = rcgen::KeyPair::generate().expect("rcgen makes a key");
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen takes the name");
    configs_with(params, &key)
}

/// Returns the configs of [`configs`] for the certificate that `params` describes, signed by
/// `key`.
pub(crate) fn configs_with(
    params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
) -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    let cert = params.self_signed(key).expect("rcgen makes a certificate");
    let provider = || {
        let mut provider = mvfstr_crypto::default_provider();
        provider
            .kx_groups
            .retain(|group| group.name() == NamedGroup::X25519);
        provider
    };
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
    let server = ServerConfig::builder(Arc::new(server_tls))
        .build()
        .expect("a server config");
    let client = ClientConfig::builder(Arc::new(client_tls))
        .build()
        .expect("a client config");
    let endpoint = EndpointConfig::builder([7; 32])
        .build()
        .expect("an endpoint config");
    (client, server, endpoint)
}

/// Returns a pair harness whose handshake has completed.
pub(crate) fn handshaken_pair() -> Pair {
    let (client, server, endpoint) = configs();
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
