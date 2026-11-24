/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the read-only accessors over the pair harness: the latest RTT, the openable streams
//! and the peer's transport parameters.

use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::VarInt;
use rustls::pki_types::ServerName;

use super::ConnSetup;
use super::Connection;
use super::DatagramPool;
use super::stream_tests::ORDER;
use super::tests::LIMIT;
use super::tests::handshake;
use super::tests::start;
use crate::AckPolicy;
use crate::AppCode;
use crate::OpenError;
use crate::TransportConfig;
use crate::testing::Link;
use crate::testing::LinkConfig;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::fixtures::Setup;

const MS: Duration = Duration::from_millis(1);

/// Returns `value` as a variable-length integer.
fn varint(value: u64) -> Vec<u8> {
    let mut out = [0; 8];
    let len = VarInt::from_u64(value).unwrap().encode(&mut out).unwrap();
    out[..len].to_vec()
}

/// Encodes transport parameters in the order given.
fn encode_params(params: &[(u64, Vec<u8>)]) -> Vec<u8> {
    params
        .iter()
        .flat_map(|(id, value)| [varint(*id), varint(value.len() as u64), value.clone()].concat())
        .collect()
}

/// Returns transport parameters a client with Initial Source Connection ID `scid` may send, out
/// of id order and with ids that RFC 9000 does not define among those it does.
fn client_params(scid: ConnectionId) -> Vec<(u64, Vec<u8>)> {
    vec![
        // A reserved id, 31 * N + 27 (RFC 9000).
        (0x1b, b"grease".to_vec()),
        // mvfst's ack_receive_timestamps_enabled.
        (0xff0a001, varint(1)),
        // max_datagram_frame_size (RFC 9221).
        (0x20, varint(65_535)),
        // initial_source_connection_id.
        (0x0f, scid.to_vec()),
        // initial_max_streams_uni and _bidi.
        (0x09, varint(10)),
        (0x08, varint(10)),
        // initial_max_stream_data_uni, _bidi_remote and _bidi_local.
        (0x07, varint(1 << 16)),
        (0x06, varint(1 << 16)),
        (0x05, varint(1 << 16)),
        // initial_max_data.
        (0x04, varint(1 << 20)),
        // max_idle_timeout.
        (0x01, varint(30_000)),
    ]
}

/// Starts a pair whose client sends, in place of its own transport parameters, the encoding that
/// `params` returns for the client's Initial Source Connection ID.
fn start_sending(
    config: PairConfig,
    params: impl FnOnce(ConnectionId) -> Vec<u8>,
) -> (Instant, Pair) {
    let tls = config.client.tls().clone();
    let (epoch, mut pair) = start(config);
    let own = pair.client.conn();
    let setup = ConnSetup {
        now: epoch,
        version: own.version,
        transport: own.config.clone(),
        alpn: own.alpn_policy,
        remote: own.remote,
        local_ip: None,
        local_cid: own.local_cid,
        remote_cid: own.original_dcid,
        original_dcid: own.original_dcid,
        cids: own.cid_gen.clone(),
        rng_seed: [3; 32],
        horizon: Duration::ZERO,
        src_ports: None,
        pool: DatagramPool::default(),
    };
    let raw = params(own.local_cid);
    let name = ServerName::try_from("localhost").unwrap();
    let conn = Connection::client_with_params(setup, &tls, name, raw).unwrap();
    pair.client.conn = Some(conn);
    (epoch, pair)
}

/// Returns how many bidirectional and unidirectional streams `conn` may open.
fn openable(conn: &Connection) -> [u64; 2] {
    [Dir::Bi, Dir::Uni].map(|dir| conn.openable_streams(dir))
}

#[test]
fn the_latest_rtt_is_the_newest_sample_rather_than_the_smoothed_rtt() {
    // The server acknowledges each ack-eliciting packet at once, so a sample is the round trip.
    let immediate = AckPolicy {
        eliciting_threshold: 1,
        ..AckPolicy::default()
    };
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .ack_policy(immediate)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    assert_eq!(
        pair.client.conn().latest_rtt(),
        Duration::ZERO,
        "no sample yet"
    );
    assert!(pair.handshake(epoch + LIMIT));
    let settled = pair.now + Duration::from_secs(1);
    pair.run(settled);
    // The links take 10 ms each way.
    assert_eq!(pair.client.conn().latest_rtt(), 20 * MS);

    // The way to the server slows to 70 ms, and a PING takes one 80 ms sample.
    pair.to_server = Link::new(
        LinkConfig {
            delay: 70 * MS,
            ..LinkConfig::default()
        },
        9,
    );
    pair.client.conn_mut().ping();
    let settled = pair.now + Duration::from_secs(1);
    pair.run(settled);
    let conn = pair.client.conn();
    assert_eq!(conn.latest_rtt(), 80 * MS);
    let smoothed = conn.stats().smoothed_rtt;
    assert!(
        smoothed < 80 * MS,
        "one sample moves the smoothed RTT only part of the way: {smoothed:?}"
    );
}

#[test]
fn openable_streams_are_the_peers_limit_less_the_streams_opened() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .max_streams_bidi(3)
            .max_streams_uni(2)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    assert_eq!(
        openable(pair.client.conn()),
        [0, 0],
        "the server's limits have not arrived"
    );
    assert!(pair.handshake(epoch + LIMIT));
    assert_eq!(openable(pair.client.conn()), [3, 2]);

    let client = pair.client.conn_mut();
    client.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(openable(client), [2, 2]);
    client.open_stream(Dir::Uni, ORDER).unwrap();
    client.open_stream(Dir::Uni, ORDER).unwrap();
    assert_eq!(openable(client), [2, 0]);
    assert_eq!(
        client.open_stream(Dir::Uni, ORDER),
        Err(OpenError::StreamLimit)
    );
    assert_eq!(openable(client), [2, 0], "a refused open opens nothing");

    // The server opens under the client's limits, the defaults.
    let defaults = TransportConfig::default();
    assert_eq!(
        openable(pair.server.conn()),
        [defaults.max_streams_bidi(), defaults.max_streams_uni()]
    );
}

#[test]
fn no_streams_are_openable_after_shutdown() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    assert_eq!(openable(client), [100, 100], "the default limits");
    client.shutdown(now);
    assert_eq!(client.open_stream(Dir::Bi, ORDER), Err(OpenError::Closed));
    assert_eq!(openable(client), [0, 0]);
}

#[test]
fn no_streams_are_openable_once_the_connection_closes() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let server = pair.server.conn_mut();
    server.close(now, AppCode::from_u32(1), Bytes::new());
    assert_eq!(server.open_stream(Dir::Uni, ORDER), Err(OpenError::Closed));
    assert_eq!(openable(server), [0, 0]);

    // The client drains once the close reaches it.
    assert_eq!(openable(pair.client.conn()), [100, 100]);
    pair.run(now + 20 * MS);
    let client = pair.client.conn_mut();
    assert_eq!(client.open_stream(Dir::Bi, ORDER), Err(OpenError::Closed));
    assert_eq!(openable(client), [0, 0]);
}

#[test]
fn each_side_keeps_the_peers_transport_parameters_as_sent() {
    let mut sent = Vec::new();
    let (epoch, mut pair) = start_sending(Setup::default().pair(), |scid| {
        sent = encode_params(&client_params(scid));
        sent.clone()
    });
    assert_eq!(
        pair.client.conn().peer_transport_params(),
        None,
        "nothing from the server yet"
    );
    assert!(pair.handshake(epoch + LIMIT));
    let server = pair.server.conn();
    assert_eq!(
        server
            .peer_transport_params()
            .map(|params| params.as_bytes()),
        Some(&sent[..])
    );

    // The client keeps the server's as its TLS session delivered them.
    let client = pair.client.conn();
    let delivered = client.tls.peer_transport_params();
    assert!(delivered.is_some());
    assert_eq!(
        client
            .peer_transport_params()
            .map(|params| params.as_bytes()),
        delivered
    );
}

#[test]
fn the_peers_transport_parameters_iterate_in_wire_order() {
    let mut sent = Vec::new();
    let (epoch, mut pair) = start_sending(Setup::default().pair(), |scid| {
        sent = client_params(scid);
        encode_params(&sent)
    });
    assert!(pair.handshake(epoch + LIMIT));
    let params = pair.server.conn().peer_transport_params().unwrap();
    let received = params
        .iter()
        .map(|(id, value)| (id.into_inner(), value.to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(received, sent, "every parameter, in the order sent");
    assert_eq!(params.into_iter().count(), sent.len());
}

#[test]
fn the_peers_max_datagram_frame_size_is_the_value_it_sent() {
    let (epoch, mut pair) = start_sending(Setup::default().pair(), |scid| {
        encode_params(&client_params(scid))
    });
    assert!(pair.handshake(epoch + LIMIT));
    assert_eq!(pair.server.conn().peer_max_datagram_frame_size(), 65_535);
    // The server does not send it, which means 0 (RFC 9221).
    assert_eq!(pair.client.conn().peer_max_datagram_frame_size(), 0);
}
