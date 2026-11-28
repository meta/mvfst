/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Absolute stream send credit and the credit edge, over the public in-memory pair.
//! [`StreamMut::credit_limit`](mvfstr_proto::StreamMut::credit_limit) is the peer's absolute
//! limit for a send half, and
//! [`StreamMut::notify_credit_above`](mvfstr_proto::StreamMut::notify_credit_above) arms one
//! [`StreamReady::CreditRaised`] edge for a MAX_STREAM_DATA that raises the limit above the armed
//! value.
//!
//! The server sends, as a relay does on the streams it opens, and the client grants credit by
//! consuming what it received. The client consumes a whole window at once and its windows do not
//! autotune, so each MAX_STREAM_DATA it sends carries the bytes consumed plus its window: after
//! round `r` of "the server spends the window, the client consumes it", the limit is `(r + 1)`
//! windows. Every raise in these tests is 1,000 to 3,000 bytes, below the 16 KiB low-water mark
//! of `Writable`.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::AppCode;
use mvfstr_proto::Bytes;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::Connection;
use mvfstr_proto::CreditDue;
use mvfstr_proto::Dir;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::UnixTime;

/// The client's initial_max_stream_data_uni: the server's credit on the unidirectional streams it
/// opens.
const CLIENT_UNI: u64 = 1_000;
/// The client's initial_max_stream_data_bidi_remote: the server's credit on the bidirectional
/// streams it opens.
const CLIENT_BIDI_REMOTE: u64 = 2_000;
/// The client's initial_max_stream_data_bidi_local: the server's credit on the bidirectional
/// streams the client opens.
const CLIENT_BIDI_LOCAL: u64 = 3_000;
/// The server's initial_max_stream_data_bidi_local: the client's credit on the bidirectional
/// streams the server opens.
const SERVER_BIDI_LOCAL: u64 = 4_000;
/// The server's initial_max_stream_data_bidi_remote: the client's credit on the bidirectional
/// streams it opens.
const SERVER_BIDI_REMOTE: u64 = 5_000;
/// The server's initial_max_stream_data_uni: the client's credit on the unidirectional streams it
/// opens.
const SERVER_UNI: u64 = 6_000;

/// The allowance that a push sender's stream must regain before the sender gets `Writable`,
/// 16 KiB.
const LOW_WATER: u64 = 16 * 1024;

/// How long a handshake or a wait for a frame may take.
const LIMIT: Duration = Duration::from_secs(10);
/// Long enough for every exchange in flight to end, ten round trips of the pair's 20 ms.
const QUIET: Duration = Duration::from_millis(200);

const ORDER: SendOrder = SendOrder {
    class: 0,
    urgency: 3,
    incremental: false,
    order: 0,
};

fn transport(bidi_local: u64, bidi_remote: u64, uni: u64) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .max_stream_data_bidi_local(bidi_local)
        .max_stream_data_bidi_remote(bidi_remote)
        .max_stream_data_uni(uni)
        .build()
        .expect("a transport config")
}

/// Returns a lossless pair config with the windows of [`CLIENT_UNI`] and the constants after it.
fn pair_config() -> PairConfig {
    // RFC 8410: a PKCS #8 v1 document with the id-Ed25519 algorithm around the seed.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let key = PrivatePkcs8KeyDer::from([&PREFIX[..], b"mvfstr stream credit test key 01"].concat());
    let signing_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
        .expect("rcgen takes the Ed25519 key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .and_then(|params| params.self_signed(&signing_key))
        .expect("rcgen makes a certificate");
    let time = Arc::new(ManualTimeProvider::new(unix_now()));
    // One key share keeps the ClientHello in one datagram.
    let mut provider: CryptoProvider = mvfstr_crypto::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    let server_tls = mvfstr_tls::server_config(
        provider.clone(),
        time.clone(),
        vec![cert.der().clone()],
        key.into(),
        &[b"h3"],
    )
    .expect("a server TLS config");
    let client_tls = mvfstr_tls::client_config(
        provider,
        time,
        ServerVerification::AcceptAnyCertificate,
        &[b"h3"],
    )
    .expect("a client TLS config");
    let server = ServerConfig::builder(Arc::new(server_tls))
        .transport(transport(SERVER_BIDI_LOCAL, SERVER_BIDI_REMOTE, SERVER_UNI))
        .build()
        .expect("a server config");
    let client = ClientConfig::builder(Arc::new(client_tls))
        .transport(transport(CLIENT_BIDI_LOCAL, CLIENT_BIDI_REMOTE, CLIENT_UNI))
        .build()
        .expect("a client config");
    let endpoint = EndpointConfig::builder([7; 32])
        .build()
        .expect("an endpoint config");
    PairConfig::new(client, server, endpoint)
}

fn unix_now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test needs one real Instant as the epoch of the pair's virtual clock"
)]
fn epoch() -> Instant {
    Instant::now()
}

/// Returns a pair whose handshake is complete and whose connections have gone quiet.
fn connected() -> Pair {
    let mut pair = Pair::new(epoch(), unix_now(), pair_config());
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit), "the handshake completes");
    pair.run(pair.now + QUIET);
    pair
}

/// Steps the pair from event to event until `done` holds; panics if it does not within
/// [`LIMIT`].
fn run_until(pair: &mut Pair, what: &str, mut done: impl FnMut(&mut Pair) -> bool) {
    let limit = pair.now + LIMIT;
    loop {
        pair.step();
        if done(pair) {
            return;
        }
        match pair.next_event() {
            Some(at) if at <= limit => pair.now = at,
            _ => panic!("{what}: not within {LIMIT:?}"),
        }
    }
}

/// Opens a unidirectional stream at the server.
fn open_server_uni(pair: &mut Pair) -> StreamId {
    pair.server
        .conn_mut()
        .open_stream(Dir::Uni, ORDER)
        .expect("the server opens a stream")
}

/// Stages `len` bytes on stream `id` of `conn`; the allowance takes them all.
fn stage(conn: &mut Connection, id: StreamId, len: u64) {
    let len = usize::try_from(len).expect("a small length");
    let mut data = Bytes::from(vec![0x5a; len]);
    let mut stream = conn.stream(id).expect("an open stream");
    assert_eq!(
        stream.send(&mut data),
        Ok(len),
        "{id}: the allowance takes every byte"
    );
}

/// Returns the server's allowance on stream `id`.
fn capacity(pair: &mut Pair, id: StreamId) -> u64 {
    let stream = pair.server.conn_mut().stream(id).expect("an open stream");
    stream.send_capacity() as u64
}

/// Returns the server's [`credit_limit`](mvfstr_proto::StreamMut::credit_limit) on stream `id`.
fn server_limit(pair: &mut Pair, id: StreamId) -> u64 {
    pair.server
        .conn_mut()
        .stream(id)
        .expect("an open stream")
        .credit_limit()
}

/// Returns the client's [`credit_limit`](mvfstr_proto::StreamMut::credit_limit) on stream `id`.
fn client_limit(pair: &mut Pair, id: StreamId) -> u64 {
    pair.client
        .conn_mut()
        .stream(id)
        .expect("an open stream")
        .credit_limit()
}

/// Stages, on each of the server's streams in `spends`, the length given with it, which is all its
/// credit left: the stream's allowance is zero afterwards.
fn exhaust(pair: &mut Pair, spends: &[(StreamId, u64)]) {
    for &(id, len) in spends {
        stage(pair.server.conn_mut(), id, len);
        assert_eq!(
            capacity(pair, id),
            0,
            "{id}: every byte of credit is staged"
        );
    }
}

/// Runs until the client can read, on each stream in `spends`, the length given with it, then
/// consumes all of it at once, which makes the stream's MAX_STREAM_DATA due. Returns before the
/// client sends it.
fn consume(pair: &mut Pair, spends: &[(StreamId, u64)]) {
    let readable = |pair: &mut Pair, id: StreamId| {
        pair.client
            .conn_mut()
            .stream(id)
            .map_or(0, |stream| stream.readable().chain_length() as u64)
    };
    run_until(pair, "the client receives the bytes", |pair| {
        spends.iter().all(|&(id, len)| readable(pair, id) == len)
    });
    for &(id, len) in spends {
        let mut stream = pair.client.conn_mut().stream(id).expect("an open stream");
        let len = usize::try_from(len).expect("a small length");
        assert_eq!(
            stream.consume(len),
            Ok(CreditDue::Due),
            "{id}: a whole window consumed makes MAX_STREAM_DATA due"
        );
    }
}

/// Runs until each of the server's streams `ids` has credit again: the client's MAX_STREAM_DATA
/// for it arrived.
fn until_credit(pair: &mut Pair, ids: &[StreamId]) {
    run_until(pair, "MAX_STREAM_DATA reaches the server", |pair| {
        ids.iter().all(|&id| capacity(pair, id) > 0)
    });
}

/// Arms the server's stream `id` for a raise above `limit`.
fn arm(pair: &mut Pair, id: StreamId, limit: u64) {
    let mut stream = pair.server.conn_mut().stream(id).expect("an open stream");
    assert_eq!(stream.notify_credit_above(limit), Ok(()), "{id}: armed");
}

/// Drains the server's readiness.
fn server_edges(pair: &mut Pair) -> Vec<(StreamId, StreamReady)> {
    pair.server.conn_mut().readiness().collect()
}

/// Returns the edges of stream `id` among `edges`.
fn of(edges: &[(StreamId, StreamReady)], id: StreamId) -> Vec<StreamReady> {
    edges
        .iter()
        .filter(|(stream, _)| *stream == id)
        .map(|(_, edge)| *edge)
        .collect()
}

/// Returns the number of credit edges of stream `id` among `edges`.
fn credit_edges(edges: &[(StreamId, StreamReady)], id: StreamId) -> usize {
    of(edges, id)
        .into_iter()
        .filter(|edge| *edge == StreamReady::CreditRaised)
        .count()
}

/// Opens two unidirectional streams at the server, stages all their credit, arms both at the
/// limit they are exhausted at, and runs until the bytes are delivered and acknowledged and the
/// links are empty: the first for the stream a test resets or stops, the second for one that
/// keeps its edge.
fn two_armed(pair: &mut Pair) -> (StreamId, StreamId) {
    let (cancelled, control) = (open_server_uni(pair), open_server_uni(pair));
    exhaust(pair, &[(cancelled, CLIENT_UNI), (control, CLIENT_UNI)]);
    arm(pair, cancelled, CLIENT_UNI);
    arm(pair, control, CLIENT_UNI);
    pair.run(pair.now + QUIET);
    (cancelled, control)
}

#[test]
fn credit_limit_is_the_peers_initial_limit_for_each_kind_of_stream() {
    let mut pair = connected();
    let server_uni = open_server_uni(&mut pair);
    let server_bidi = pair.server.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let client_bidi = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let client_uni = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    // Bytes on each stream open it at the peer and spend credit, which leaves the absolute limit
    // as it is.
    for id in [server_uni, server_bidi] {
        stage(pair.server.conn_mut(), id, 100);
    }
    for id in [client_bidi, client_uni] {
        stage(pair.client.conn_mut(), id, 100);
    }
    pair.run(pair.now + QUIET);
    for id in [server_uni, server_bidi] {
        let stream = pair.server.conn_mut().stream(id).unwrap();
        assert_eq!(stream.sent_end(), 100, "{id}: the server spent credit");
    }
    for id in [client_bidi, client_uni] {
        let stream = pair.client.conn_mut().stream(id).unwrap();
        assert_eq!(stream.sent_end(), 100, "{id}: the client spent credit");
    }

    assert_eq!(
        server_limit(&mut pair, server_uni),
        CLIENT_UNI,
        "the server's uni stream: the client's initial_max_stream_data_uni"
    );
    assert_eq!(
        server_limit(&mut pair, server_bidi),
        CLIENT_BIDI_REMOTE,
        "the server's bidi stream: the client's initial_max_stream_data_bidi_remote"
    );
    assert_eq!(
        server_limit(&mut pair, client_bidi),
        CLIENT_BIDI_LOCAL,
        "the client's bidi stream at the server: the client's initial_max_stream_data_bidi_local"
    );
    assert_eq!(
        client_limit(&mut pair, client_uni),
        SERVER_UNI,
        "the client's uni stream: the server's initial_max_stream_data_uni"
    );
    assert_eq!(
        client_limit(&mut pair, client_bidi),
        SERVER_BIDI_REMOTE,
        "the client's bidi stream: the server's initial_max_stream_data_bidi_remote"
    );
    assert_eq!(
        client_limit(&mut pair, server_bidi),
        SERVER_BIDI_LOCAL,
        "the server's bidi stream at the client: the server's initial_max_stream_data_bidi_local"
    );
}

#[test]
fn credit_limit_is_the_new_limit_after_max_stream_data() {
    let mut pair = connected();
    let server_uni = open_server_uni(&mut pair);
    let server_bidi = pair.server.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let client_bidi = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    // A byte opens the client's stream at the server.
    stage(pair.client.conn_mut(), client_bidi, 1);
    pair.run(pair.now + QUIET);
    let windows = [
        (server_uni, CLIENT_UNI),
        (server_bidi, CLIENT_BIDI_REMOTE),
        (client_bidi, CLIENT_BIDI_LOCAL),
    ];
    let ids = windows.map(|(id, _)| id);
    for round in 1..=2 {
        exhaust(&mut pair, &windows);
        consume(&mut pair, &windows);
        until_credit(&mut pair, &ids);
        for (id, window) in windows {
            assert_eq!(
                server_limit(&mut pair, id),
                (round + 1) * window,
                "{id}, round {round}: the limit of the client's MAX_STREAM_DATA"
            );
        }
    }
}

#[test]
fn an_armed_edge_fires_once_for_a_raise_above_the_armed_value_and_not_at_or_below_it() {
    let mut pair = connected();
    let (at, below) = (open_server_uni(&mut pair), open_server_uni(&mut pair));
    let windows = [(at, CLIENT_UNI), (below, CLIENT_UNI)];
    exhaust(&mut pair, &windows);
    // The first raise takes the limit to 2,000: exactly `at`'s armed value, below `below`'s.
    arm(&mut pair, at, 2 * CLIENT_UNI);
    arm(&mut pair, below, 2 * CLIENT_UNI + CLIENT_UNI / 2);
    consume(&mut pair, &windows);
    until_credit(&mut pair, &[at, below]);
    let edges = server_edges(&mut pair);
    assert_eq!(
        credit_edges(&edges, at),
        0,
        "a raise to the armed value is not above it"
    );
    assert_eq!(
        credit_edges(&edges, below),
        0,
        "a raise below the armed value"
    );

    // The second raise, to 3,000, is above both.
    exhaust(&mut pair, &windows);
    consume(&mut pair, &windows);
    until_credit(&mut pair, &[at, below]);
    let edges = server_edges(&mut pair);
    assert_eq!(of(&edges, at), [StreamReady::CreditRaised]);
    assert_eq!(of(&edges, below), [StreamReady::CreditRaised]);

    // The third, to 4,000, comes while both streams are disarmed.
    exhaust(&mut pair, &windows);
    consume(&mut pair, &windows);
    until_credit(&mut pair, &[at, below]);
    let edges = server_edges(&mut pair);
    assert_eq!(credit_edges(&edges, at), 0, "one edge per arm");
    assert_eq!(credit_edges(&edges, below), 0, "one edge per arm");
}

#[test]
fn a_raise_before_the_arm_gives_the_edge_at_once_and_one_after_it_gives_it_on_that_frame() {
    let mut pair = connected();
    let id = open_server_uni(&mut pair);
    let window = [(id, CLIENT_UNI)];
    exhaust(&mut pair, &window);
    consume(&mut pair, &window);
    until_credit(&mut pair, &[id]);
    assert_eq!(server_edges(&mut pair), [], "the stream is not armed");

    // The application arms at the limit it read last, 1,000, which the MAX_STREAM_DATA above
    // already raised to 2,000. The edge comes without a later frame.
    arm(&mut pair, id, CLIENT_UNI);
    assert_eq!(
        server_edges(&mut pair),
        [(id, StreamReady::CreditRaised)],
        "at once, without another frame"
    );
    arm(&mut pair, id, 2 * CLIENT_UNI);
    assert_eq!(
        server_edges(&mut pair),
        [],
        "the limit is not above the armed value"
    );

    // The step that applies the next MAX_STREAM_DATA, to 3,000, gives the edge.
    exhaust(&mut pair, &window);
    consume(&mut pair, &window);
    let mut edges = Vec::new();
    run_until(&mut pair, "MAX_STREAM_DATA reaches the server", |pair| {
        edges.extend(server_edges(pair));
        capacity(pair, id) > 0
    });
    assert_eq!(
        edges,
        [(id, StreamReady::CreditRaised)],
        "with the frame that raised the limit"
    );
}

#[test]
fn a_raise_below_the_low_water_mark_after_complete_exhaustion_still_fires() {
    let mut pair = connected();
    let id = open_server_uni(&mut pair);
    let window = [(id, CLIENT_UNI)];
    exhaust(&mut pair, &window);
    pair.run(pair.now + QUIET);
    let mut stream = pair.server.conn_mut().stream(id).unwrap();
    assert_eq!(
        stream.sent_end(),
        CLIENT_UNI,
        "every byte of credit is sent"
    );
    assert_eq!(stream.acked_end(), CLIENT_UNI, "and acknowledged");
    assert_eq!(stream.send_capacity(), 0, "the allowance is spent");
    assert_eq!(stream.notify_credit_above(CLIENT_UNI), Ok(()));

    consume(&mut pair, &window);
    until_credit(&mut pair, &[id]);
    let raise = capacity(&mut pair, id);
    assert!(
        raise < LOW_WATER,
        "the raise, {raise} bytes, is below the low-water mark of {LOW_WATER} bytes"
    );
    assert_eq!(
        server_edges(&mut pair),
        [(id, StreamReady::CreditRaised)],
        "a credit edge, where a push sender that was never refused bytes does not get Writable"
    );
}

#[test]
fn a_local_reset_before_the_raise_arrives_leaves_no_edge() {
    let mut pair = connected();
    let (reset, control) = two_armed(&mut pair);
    consume(&mut pair, &[(reset, CLIENT_UNI), (control, CLIENT_UNI)]);
    pair.step();
    assert_eq!(
        capacity(&mut pair, control),
        0,
        "the client's MAX_STREAM_DATA frames are on their way"
    );
    let mut stream = pair.server.conn_mut().stream(reset).unwrap();
    assert_eq!(stream.reset(AppCode::from_u32(7)), Ok(()));

    until_credit(&mut pair, &[control]);
    let edges = server_edges(&mut pair);
    assert_eq!(
        of(&edges, control),
        [StreamReady::CreditRaised],
        "the stream that was not reset gets an edge for its raise"
    );
    assert_eq!(credit_edges(&edges, reset), 0, "the reset stream does not");
}

#[test]
fn a_local_reset_drops_an_undelivered_credit_edge() {
    let mut pair = connected();
    let (reset, control) = two_armed(&mut pair);
    consume(&mut pair, &[(reset, CLIENT_UNI), (control, CLIENT_UNI)]);
    until_credit(&mut pair, &[reset, control]);
    let mut stream = pair.server.conn_mut().stream(reset).unwrap();
    assert_eq!(stream.reset(AppCode::from_u32(7)), Ok(()));

    let edges = server_edges(&mut pair);
    assert_eq!(
        of(&edges, control),
        [StreamReady::CreditRaised],
        "the stream that was not reset gets an edge for its raise"
    );
    assert_eq!(
        credit_edges(&edges, reset),
        0,
        "the reset drops the edge its raise marked"
    );
}

#[test]
fn a_peer_stop_sending_before_the_raise_arrives_leaves_no_edge() {
    let mut pair = connected();
    let (stopped, control) = two_armed(&mut pair);
    consume(&mut pair, &[(stopped, CLIENT_UNI), (control, CLIENT_UNI)]);
    pair.step();
    // Holds the client's MAX_STREAM_DATA frames back, so that its STOP_SENDING arrives first.
    let held = pair.to_server.deliver(pair.now + LIMIT);
    assert!(
        !held.is_empty(),
        "the client sent its MAX_STREAM_DATA frames"
    );
    let code = AppCode::from_u32(9);
    let mut stream = pair.client.conn_mut().stream(stopped).unwrap();
    assert_eq!(stream.stop_sending(code), Ok(()));
    let mut edges = Vec::new();
    run_until(&mut pair, "the STOP_SENDING reaches the server", |pair| {
        edges.extend(server_edges(pair));
        edges.contains(&(stopped, StreamReady::Stopped { code }))
    });

    for datagram in held {
        pair.to_server.send(pair.now, datagram);
    }
    until_credit(&mut pair, &[control]);
    assert!(
        pair.server.conn_mut().stream(stopped).is_ok(),
        "the stopped stream is still there when its raise arrives"
    );
    edges.extend(server_edges(&mut pair));
    assert_eq!(
        of(&edges, control),
        [StreamReady::CreditRaised],
        "the stream that was not stopped gets an edge for its raise"
    );
    assert_eq!(
        credit_edges(&edges, stopped),
        0,
        "the stopped stream does not"
    );
}

#[test]
fn a_peer_stop_sending_drops_an_undelivered_credit_edge() {
    let mut pair = connected();
    let (stopped, control) = two_armed(&mut pair);
    consume(&mut pair, &[(stopped, CLIENT_UNI), (control, CLIENT_UNI)]);
    until_credit(&mut pair, &[stopped, control]);
    let code = AppCode::from_u32(9);
    let mut stream = pair.client.conn_mut().stream(stopped).unwrap();
    assert_eq!(stream.stop_sending(code), Ok(()));
    // The STOP_SENDING resets the send half, whose allowance drops back to zero.
    run_until(&mut pair, "the STOP_SENDING reaches the server", |pair| {
        capacity(pair, stopped) == 0
    });

    let edges = server_edges(&mut pair);
    assert_eq!(
        of(&edges, control),
        [StreamReady::CreditRaised],
        "the stream that was not stopped gets an edge for its raise"
    );
    assert!(
        of(&edges, stopped).contains(&StreamReady::Stopped { code }),
        "the STOP_SENDING arrived"
    );
    assert_eq!(
        credit_edges(&edges, stopped),
        0,
        "the STOP_SENDING drops the edge the raise marked"
    );
}
