/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of a client connection's per-stream ack progress, RTT values, TLS failure detail and
//! negotiated parameters, stream limits, keepalive, PTO limit, Retry and 0-RTT.

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_crypto::AES_128_GCM;
use mvfstr_crypto::PacketKeys;
use mvfstr_crypto::TAG_LEN;
use mvfstr_crypto::retry_integrity_tag;
use mvfstr_crypto::unprotect_header;
use mvfstr_tls::AcceptAnyServerCert;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::PacketType;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::Version;
use mvfstr_wire::decode_packet_number;
use mvfstr_wire::encode_retry;
use mvfstr_wire::encode_version_negotiation;
use rustls::CipherSuiteCommon;
use rustls::SupportedCipherSuite;
use rustls::Tls13CipherSuite;
use rustls::crypto::cipher::AeadKey;
use rustls::crypto::cipher::Iv;
use rustls::quic;

use super::Connection;
use super::State;
use super::stream_tests::App;
use super::stream_tests::ORDER;
use super::stream_tests::RTT;
use super::stream_tests::run_apps;
use super::tests::Forge;
use super::tests::LIMIT;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::limits;
use super::tests::open_own_one_rtt;
use super::tests::server_addr;
use super::tests::start;
use crate::ClientTls;
use crate::CloseReason;
use crate::ConnEvent;
use crate::DatagramSize;
use crate::Initiator;
use crate::InlineSealer;
use crate::KeepAlive;
use crate::OpenError;
use crate::PathId;
use crate::ServerConfig;
use crate::ServerTls;
use crate::StreamReady;
use crate::TransportConfig;
use crate::config::TransportConfigBuilder;
use crate::recovery::Space;
use crate::testing::Loss;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;
use crate::testing::fixtures::unix_now;

fn transport(
    build: impl FnOnce(TransportConfigBuilder) -> TransportConfigBuilder,
) -> Arc<TransportConfig> {
    build(TransportConfig::builder()).build().unwrap()
}

/// Queues `len` bytes and the FIN on stream `id`.
fn send_all(conn: &mut Connection, id: StreamId, len: usize) {
    let mut stream = conn.stream(id).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(vec![0x5a; len])), Ok(len));
    stream.finish().unwrap();
}

/// Consumes stream `id`'s readable bytes and returns how many there were and whether the FIN
/// came with them.
fn read_all(conn: &mut Connection, id: StreamId) -> (usize, bool) {
    let mut stream = conn.stream(id).unwrap();
    let n = stream.readable().chain_length();
    stream.consume(n).unwrap();
    (n, stream.peer_finished())
}

fn drain_acked(conn: &mut Connection) -> Vec<(StreamId, u64)> {
    std::iter::from_fn(|| conn.poll_stream_acked()).collect()
}

/// A transport config that queues the growths of the send halves' acknowledged prefixes.
fn ack_progress() -> Arc<TransportConfig> {
    transport(|c| c.stream_ack_progress(true))
}

/// Returns `setup` with a client that queues ack progress.
fn with_ack_progress(setup: Setup) -> Setup {
    Setup {
        client_transport: ack_progress(),
        ..setup
    }
}

/// Returns the frames of the 1-RTT packets of a datagram `conn` sent.
fn one_rtt_frames(conn: &Connection, datagram: &[u8]) -> Vec<String> {
    open_own_one_rtt(conn, datagram)
        .iter()
        .flat_map(|plaintext| {
            Frames::new(plaintext)
                .map(|frame| format!("{:?}", frame.unwrap()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn is_ping(frame: &str) -> bool {
    frame == "Ping"
}

fn is_ack_eliciting(frame: &str) -> bool {
    !frame.starts_with("Padding") && !frame.starts_with("Ack(")
}

/// Returns the types of the packets coalesced in a datagram.
fn packet_types(mut datagram: &[u8]) -> Vec<PacketType> {
    let mut types = Vec::new();
    while let Ok(Header::Protected(header)) = Header::parse(datagram, 8) {
        types.push(header.ty());
        datagram = &datagram[header.packet_len()..];
    }
    types
}

/// A long-header packet of a datagram, with its type, token, Destination and Source Connection
/// IDs and bytes.
struct LongPacket {
    ty: PacketType,
    token: Vec<u8>,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    pn_offset: usize,
    bytes: Vec<u8>,
}

fn long_packets(mut datagram: &[u8]) -> Vec<LongPacket> {
    let mut out = Vec::new();
    while let Ok(Header::Protected(header)) = Header::parse(datagram, 8) {
        if header.version().is_none() {
            break;
        }
        let (packet, rest) = datagram.split_at(header.packet_len());
        out.push(LongPacket {
            ty: header.ty(),
            token: header.token().to_vec(),
            dcid: header.dcid().to_vec(),
            scid: header.scid().to_vec(),
            pn_offset: header.pn_offset(),
            bytes: packet.to_vec(),
        });
        datagram = rest;
    }
    out
}

/// Opens a long-header packet with `keys`: its packet number and plaintext.
fn open_long(keys: &PacketKeys, packet: &LongPacket) -> (u64, Vec<u8>) {
    let mut bytes = packet.bytes.clone();
    let pn_len = unprotect_header(keys.header(), &mut bytes, packet.pn_offset).unwrap();
    let truncated = bytes[packet.pn_offset..packet.pn_offset + pn_len]
        .iter()
        .fold(0u32, |acc, &byte| acc << 8 | u32::from(byte));
    let pn = decode_packet_number(None, truncated, pn_len);
    let (header, payload) = bytes.split_at_mut(packet.pn_offset + pn_len);
    let plaintext = keys
        .packet()
        .decrypt_in_place(pn, header, payload)
        .unwrap()
        .to_vec();
    (pn, plaintext)
}

/// Returns the CRYPTO data of a plaintext, as (offset, bytes).
fn crypto_frames(plaintext: &[u8]) -> Vec<(u64, Vec<u8>)> {
    Frames::new(plaintext)
        .filter_map(|frame| match frame.unwrap() {
            Frame::Crypto { offset, data } => Some((offset.into_inner(), data.to_vec())),
            _ => None,
        })
        .collect()
}

/// Returns every datagram the client has sent so far.
fn client_datagrams(pair: &Pair) -> Vec<Vec<u8>> {
    pair.client
        .sent
        .iter()
        .map(|(_, datagram)| datagram.data.clone())
        .collect()
}

/// Makes the client transmit and returns the datagrams.
fn transmit(conn: &mut Connection, now: Instant) -> Vec<Vec<u8>> {
    let mut sink = VecSink::new(1500);
    conn.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    sink.take().into_iter().map(|sent| sent.data).collect()
}

fn cid(byte: u8) -> ConnectionId {
    ConnectionId::new(&[byte; 8]).unwrap()
}

/// Builds a Retry from the server to `conn` naming `scid` and carrying `token`, its tag computed
/// over `odcid`.
fn retry_packet(
    conn: &Connection,
    scid: ConnectionId,
    token: &[u8],
    odcid: ConnectionId,
) -> Vec<u8> {
    let mut out = vec![0; 256];
    let len = encode_retry(&mut out, 0, conn.version, &conn.local_cid, &scid, token).unwrap();
    let tag = retry_integrity_tag(&odcid, &out[..len]);
    out[len..len + tag.len()].copy_from_slice(&tag);
    out.truncate(len + tag.len());
    out
}

fn closed(pair_peer_events: &[ConnEvent]) -> Option<(CloseReason, Initiator)> {
    pair_peer_events.iter().find_map(|event| match event {
        ConnEvent::Closed { reason, initiator } => Some((reason.clone(), *initiator)),
        _ => None,
    })
}

#[test]
fn ack_progress_reports_each_streams_acknowledged_prefix_in_order() {
    let (_, mut pair) = handshake(with_ack_progress(Setup::default()).pair());
    let client = pair.client.conn_mut();
    let a = client.open_stream(Dir::Bi, ORDER).unwrap();
    let b = client.open_stream(Dir::Bi, ORDER).unwrap();
    // b grows first, then a, then b again, all before anything is polled.
    let mut head = Bytes::from(vec![0x5a; 3_000]);
    assert_eq!(client.stream(b).unwrap().send(&mut head), Ok(3_000));
    let quiet = pair.now + Duration::from_secs(1);
    pair.run(quiet);
    send_all(pair.client.conn_mut(), a, 20_000);
    let quiet = pair.now + Duration::from_secs(1);
    pair.run(quiet);
    send_all(pair.client.conn_mut(), b, 2_000);
    let quiet = pair.now + Duration::from_secs(1);
    pair.run(quiet);
    // Unpolled growths coalesce into one entry per stream, in the order the streams first
    // grew, carrying the whole acknowledged prefix with the FIN not counted.
    let client = pair.client.conn_mut();
    assert_eq!(drain_acked(client), [(b, 5_000), (a, 20_000)]);
    assert_eq!(client.poll_stream_acked(), None);
}

#[test]
fn ack_progress_grows_step_by_step_and_outlives_the_stream() {
    let (_, mut pair) = handshake(with_ack_progress(Setup::default()).pair());
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 40_000);
    let mut values = Vec::new();
    let mut answered = false;
    let mut closed_edge = false;
    let limit = pair.now + Duration::from_secs(5);
    while pair.now < limit && !closed_edge {
        pair.step();
        // The server ends its half with a bare FIN as soon as it sees the stream, so the
        // stream closes when the client's last bytes are acknowledged.
        if !answered && let Ok(mut stream) = pair.server.conn_mut().stream(id) {
            stream.finish().unwrap();
            answered = true;
        }
        let client = pair.client.conn_mut();
        // The Closed edge reaps the stream; its last value is queued by then.
        closed_edge = client
            .readiness()
            .any(|edge| edge == (id, StreamReady::Closed));
        values.extend(drain_acked(client).into_iter().map(|(acked_id, acked)| {
            assert_eq!(acked_id, id);
            acked
        }));
        let Some(next) = pair.next_event() else { break };
        if !closed_edge {
            pair.now = next;
        }
    }
    assert!(closed_edge, "the stream never closed");
    assert!(
        pair.client.conn_mut().stream(id).is_err(),
        "the stream was reaped"
    );
    assert!(values.len() > 1, "{values:?}");
    assert!(values.windows(2).all(|w| w[0] < w[1]), "{values:?}");
    assert_eq!(values.last(), Some(&40_000));
}

#[test]
fn ack_progress_skips_holes_until_lost_bytes_are_acknowledged() {
    let (_, mut pair) = handshake(with_ack_progress(Setup::default()).pair());
    pair.to_server.set_loss(Loss::Seeded {
        seed: 11,
        per_mille: 150,
    });
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 60_000);
    let limit = pair.now + Duration::from_secs(10);
    let mut values = Vec::new();
    loop {
        pair.step();
        values.extend(
            drain_acked(pair.client.conn_mut())
                .into_iter()
                .map(|(acked_id, acked)| {
                    assert_eq!(acked_id, id);
                    acked
                }),
        );
        match pair.next_event() {
            Some(next) if next <= limit => pair.now = next,
            _ => break,
        }
    }
    assert!(pair.client.conn().stats().lost_packets > 0);
    assert!(values.len() > 1, "{values:?}");
    assert!(values.windows(2).all(|w| w[0] < w[1]), "{values:?}");
    assert_eq!(values.last(), Some(&60_000));
}

#[test]
fn a_server_queues_no_ack_progress() {
    // Even with the setting on.
    let (_, mut pair) = handshake(Setup::default().transport(ack_progress()).pair());
    let server = pair.server.conn_mut();
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    send_all(server, id, 5_000);
    let quiet = pair.now + Duration::from_secs(1);
    pair.run(quiet);
    assert_eq!(pair.server.conn_mut().poll_stream_acked(), None);
}

/// Runs 200 request streams over `setup`'s pair, 100 at a time, each a request and its FIN
/// answered by a response and its FIN, until every stream is closed and reaped on both sides;
/// the test does not poll ack progress. Returns the pair and the streams.
fn requests_without_polling(setup: Setup) -> (Pair, Vec<StreamId>) {
    let (_, mut pair) = handshake(setup.pair());
    let (mut client, mut server) = (App::default(), App::default());
    let mut ids = Vec::new();
    for _ in 0..2 {
        let conn = pair.client.conn_mut();
        let batch: Vec<StreamId> = (0..100)
            .map(|_| conn.open_stream(Dir::Bi, ORDER).unwrap())
            .collect();
        for &id in &batch {
            client.write(id, &b"request"[..], true);
        }
        let until = pair.now + RTT;
        run_apps(&mut pair, until, &mut client, &mut server);
        for &id in &batch {
            server.write(id, &b"response"[..], true);
        }
        // Long enough for the server to reap the streams and raise the stream limit.
        let until = pair.now + 3 * RTT;
        run_apps(&mut pair, until, &mut client, &mut server);
        ids.extend(batch);
    }
    for &id in &ids {
        assert_eq!(client.data[&id], b"response", "{id:?}");
        assert_eq!(client.edges_of(id).last(), Some(&StreamReady::Closed));
        assert_eq!(server.edges_of(id).last(), Some(&StreamReady::Closed));
        assert!(pair.client.conn_mut().stream(id).is_err(), "{id:?}");
    }
    (pair, ids)
}

#[test]
fn default_client_keeps_no_ack_progress() {
    let (mut pair, _) = requests_without_polling(Setup::default());
    let client = pair.client.conn_mut();
    assert_eq!(client.sources.streams.acked_len(), 0);
    assert_eq!(client.poll_stream_acked(), None);

    // With the setting on, the same run keeps one entry per stream after the streams are reaped.
    let (mut pair, ids) = requests_without_polling(with_ack_progress(Setup::default()));
    let client = pair.client.conn_mut();
    assert_eq!(client.sources.streams.acked_len(), 200);
    let mut acked = drain_acked(client);
    acked.sort();
    // The 7 bytes of each request; the FIN is not counted.
    let expected: Vec<(StreamId, u64)> = ids.iter().map(|&id| (id, 7)).collect();
    assert_eq!(acked, expected);
    assert_eq!(client.sources.streams.acked_len(), 0);
}

#[test]
fn stats_carry_the_latest_rtt_and_its_variation() {
    let (_, pair) = handshake(Setup::default().pair());
    let stats = pair.client.conn().stats();
    let rtt = pair.client.conn().recovery.rtt();
    assert_eq!(stats.latest_rtt, rtt.latest());
    assert_eq!(stats.rtt_var, rtt.var());
    // 10 ms each way.
    assert!(stats.latest_rtt >= Duration::from_millis(20), "{stats:?}");
    assert!(!stats.rtt_var.is_zero(), "{stats:?}");
}

#[test]
fn a_tls_failure_keeps_the_rustls_error_and_closes_with_its_alert() {
    let setup = Setup {
        empty_roots: true,
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    });
    let client = pair.client.conn();
    assert!(
        matches!(
            client.local_tls_error(),
            Some(rustls::Error::InvalidCertificate(_))
        ),
        "{:?}",
        client.local_tls_error()
    );
    // The alert as a CRYPTO_ERROR code (RFC 9001): 0x100 + unknown_ca (48).
    let code = TransportErrorCode::crypto(48);
    let Some((CloseReason::Transport { code: sent, .. }, Initiator::Local)) =
        closed(&pair.client.events)
    else {
        panic!("no local close: {:?}", pair.client.events);
    };
    assert_eq!(sent, code);
    let Some((CloseReason::Transport { code: heard, .. }, Initiator::Peer)) =
        closed(&pair.server.events)
    else {
        panic!("no peer close: {:?}", pair.server.events);
    };
    assert_eq!(heard, code);
    assert!(pair.server.conn().local_tls_error().is_none());
    assert_eq!(client.tls_info(), None);
}

/// A packet key that reports a 12-byte AEAD tag and otherwise seals and opens as the key it wraps.
struct TwelveByteTag(Box<dyn quic::PacketKey>);

impl quic::PacketKey for TwelveByteTag {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        self.0.encrypt_in_place(packet_number, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        self.0.decrypt_in_place(packet_number, header, payload)
    }

    fn tag_len(&self) -> usize {
        12
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

/// mvfstr's AES-128-GCM, except that its packet keys report a 12-byte tag.
struct TwelveByteTags;

impl quic::Algorithm for TwelveByteTags {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(TwelveByteTag(AES_128_GCM.packet_key(key, iv)))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        AES_128_GCM.header_protection_key(key)
    }

    fn aead_key_len(&self) -> usize {
        AES_128_GCM.aead_key_len()
    }
}

/// Returns a client rustls config, built without mvfstr_tls's suite rewrite, that offers only
/// TLS_AES_128_GCM_SHA256 with [`TwelveByteTags`] as its QUIC algorithm.
fn twelve_byte_tag_client() -> Arc<rustls::ClientConfig> {
    static SUITE: LazyLock<Tls13CipherSuite> = LazyLock::new(|| {
        let base = &mvfstr_crypto::cipher_suite::TLS13_AES_128_GCM_SHA256;
        Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: base.common.suite,
                hash_provider: base.common.hash_provider,
                confidentiality_limit: base.common.confidentiality_limit,
            },
            hkdf_provider: base.hkdf_provider,
            aead_alg: base.aead_alg,
            quic: Some(&TwelveByteTags),
        }
    });
    let mut provider = mvfstr_crypto::default_provider();
    provider.cipher_suites = vec![SupportedCipherSuite::Tls13(&SUITE)];
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519);
    let verifier = Arc::new(AcceptAnyServerCert::new(&provider));
    let time = Arc::new(ManualTimeProvider::new(unix_now()));
    let mut config = rustls::ClientConfig::builder_with_details(Arc::new(provider), time)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the provider has a TLS 1.3 suite and a group")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

#[test]
fn a_client_refuses_tls_keys_with_a_12_byte_tag_when_tls_installs_them() {
    let setup = Setup::default();
    let (server, _) = setup.rustls();
    let config = setup.pair_with(
        ServerTls::Rustls(server),
        ClientTls::Rustls(twelve_byte_tag_client()),
    );
    let (epoch, mut pair) = start(config);
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    });
    // mvfstr seals with 16-byte tags only. The client refuses the Handshake keys as TLS
    // installs them and closes with INTERNAL_ERROR, which the server receives, before the
    // handshake completes.
    let code = TransportErrorCode::INTERNAL_ERROR;
    let Some((CloseReason::Transport { code: sent, .. }, Initiator::Internal)) =
        closed(&pair.client.events)
    else {
        panic!("no internal close: {:?}", pair.client.events);
    };
    assert_eq!(sent, code);
    let Some((CloseReason::Transport { code: heard, .. }, Initiator::Peer)) =
        closed(&pair.server.events)
    else {
        panic!("no peer close: {:?}", pair.server.events);
    };
    assert_eq!(heard, code);
    assert!(!pair.client.has_event(&ConnEvent::Connected));
}

#[test]
fn tls_info_reports_the_negotiation_and_a_resumption() {
    let config = Setup::default().pair();
    let (epoch, mut first) = start(config.clone());
    assert_eq!(first.client.conn().tls_info(), None);
    assert!(first.handshake(epoch + LIMIT));
    let quiet = first.now + Duration::from_millis(200);
    first.run(quiet);
    let info = first.client.conn().tls_info().unwrap();
    assert!(!info.resumed);
    assert_eq!(info.group, Some(rustls::NamedGroup::X25519));
    assert_eq!(
        info.suite,
        first
            .client
            .conn()
            .tls
            .rustls()
            .unwrap()
            .negotiated_cipher_suite()
            .map(|suite| suite.suite())
    );
    assert!(info.suite.is_some());
    assert_eq!(
        first.server.conn().tls_info().map(|info| info.resumed),
        Some(false)
    );
    // A second connection from the same client config resumes the session.
    let (_, second) = handshake(config);
    assert_eq!(
        second.client.conn().tls_info().map(|info| info.resumed),
        Some(true)
    );
    assert_eq!(
        second.server.conn().tls_info().map(|info| info.resumed),
        Some(true)
    );
}

#[test]
fn stream_limits_come_from_the_peers_parameters() {
    let setup = Setup {
        server_transport: transport(|c| c.max_streams_bidi(3).max_streams_uni(7)),
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    let client = pair.client.conn();
    for dir in [Dir::Bi, Dir::Uni] {
        assert_eq!(client.peer_max_streams(dir), 0);
        assert_eq!(client.openable_streams(dir), 0);
    }
    assert!(pair.handshake(epoch + LIMIT));
    let client = pair.client.conn_mut();
    assert_eq!(client.peer_max_streams(Dir::Bi), 3);
    assert_eq!(client.peer_max_streams(Dir::Uni), 7);
    assert_eq!(client.openable_streams(Dir::Bi), 3);
    client.open_stream(Dir::Bi, ORDER).unwrap();
    client.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(client.openable_streams(Dir::Bi), 1);
    client.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(client.openable_streams(Dir::Bi), 0);
    assert_eq!(
        client.open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
    assert_eq!(client.peer_max_streams(Dir::Bi), 3);
    assert_eq!(client.openable_streams(Dir::Uni), 7);
}

/// A pair whose client keeps alive with `keep_alive`, with idle timeouts of `client_idle` and
/// `server_idle`, past its handshake; and the times the client sent each datagram, and whether
/// it held a PING or was ack-eliciting at all, over the next ten seconds.
struct KeepAliveRun {
    pair: Pair,
    /// When the client last sent an ack-eliciting packet before the run.
    last_eliciting: Instant,
    /// (time, holds a PING, ack-eliciting) of each client datagram after the handshake.
    sent: Vec<(Instant, bool, bool)>,
}

fn keep_alive_run(
    keep_alive: Option<KeepAlive>,
    client_idle: u64,
    server_idle: u64,
) -> KeepAliveRun {
    let setup = Setup {
        client_transport: transport(|c| {
            c.keep_alive(keep_alive)
                .idle_timeout(Some(Duration::from_secs(client_idle)))
        }),
        server_transport: transport(|c| c.idle_timeout(Some(Duration::from_secs(server_idle)))),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let confirmed = pair.now;
    let from = pair.client.sent.len();
    // The handshake's last ack-eliciting packet may be a Handshake one, whose keys are gone.
    let last_eliciting = pair.client.conn().keepalive_base;
    assert!(
        pair.client.sent[..from]
            .iter()
            .any(|(at, _)| *at == last_eliciting)
    );
    pair.run_until(confirmed + Duration::from_secs(10), |pair| {
        pair.client.has_event(&ConnEvent::Drained)
    });
    let client = pair.client.conn();
    let sent = pair.client.sent[from..]
        .iter()
        .map(|(at, datagram)| {
            let frames = one_rtt_frames(client, &datagram.data);
            (
                *at,
                frames.iter().any(|frame| is_ping(frame)),
                frames.iter().any(|frame| is_ack_eliciting(frame)),
            )
        })
        .collect();
    KeepAliveRun {
        pair,
        last_eliciting,
        sent,
    }
}

impl KeepAliveRun {
    fn pings(&self) -> Vec<Instant> {
        self.sent
            .iter()
            .filter(|(_, ping, _)| *ping)
            .map(|(at, _, _)| *at)
            .collect()
    }

    /// Returns the time from the last ack-eliciting datagram before the first PING to that PING.
    fn first_ping_gap(&self) -> Duration {
        let first = self.pings()[0];
        let last = self
            .sent
            .iter()
            .filter(|(at, ping, eliciting)| *at < first && *eliciting && !*ping)
            .map(|(at, _, _)| *at)
            .max()
            .unwrap_or(self.last_eliciting);
        first - last
    }

    fn assert_open(&self) {
        for peer in [&self.pair.client, &self.pair.server] {
            assert_eq!(closed(&peer.events), None, "{:?}", peer.events);
        }
    }
}

#[test]
fn a_keepalive_interval_keeps_an_idle_connection_open() {
    let run = keep_alive_run(Some(KeepAlive::Interval(Duration::from_secs(1))), 3, 3);
    run.assert_open();
    let pings = run.pings();
    assert!(pings.len() >= 8, "{pings:?}");
    assert!(
        pings
            .windows(2)
            .all(|w| w[1] - w[0] == Duration::from_secs(1)),
        "{pings:?}"
    );
}

#[test]
fn the_negotiated_keepalive_pings_at_85_percent_of_the_smaller_idle_timeout() {
    for (client_idle, server_idle) in [(3, 2), (2, 3)] {
        let run = keep_alive_run(Some(KeepAlive::NegotiatedIdle), client_idle, server_idle);
        run.assert_open();
        let pings = run.pings();
        assert!(pings.len() >= 4, "{client_idle} {server_idle}: {pings:?}");
        assert_eq!(
            run.first_ping_gap(),
            Duration::from_millis(1_700),
            "{client_idle} {server_idle}"
        );
        assert!(
            pings
                .windows(2)
                .all(|w| w[1] - w[0] == Duration::from_millis(1_700)),
            "{client_idle} {server_idle}: {pings:?}"
        );
    }
}

#[test]
fn keepalive_intervals_at_the_varint_limit_do_not_overflow() {
    const LARGEST: u64 = (1 << 62) - 1;
    // LARGEST - LARGEST * 15 / 100, with the product taken without overflow.
    const NEGOTIATED: u64 = 3_919_933_115_663_279_718;
    let largest = Some(Duration::from_millis(LARGEST));
    let cases = [
        // The peer's idle timeout alone, then the local one alone.
        (KeepAlive::NegotiatedIdle, None, largest, NEGOTIATED),
        (KeepAlive::NegotiatedIdle, largest, None, NEGOTIATED),
        (
            KeepAlive::Interval(Duration::from_millis(LARGEST)),
            largest,
            largest,
            LARGEST,
        ),
    ];
    for (keep_alive, client_idle, server_idle, interval) in cases {
        let setup = Setup {
            client_transport: transport(|c| {
                c.keep_alive(Some(keep_alive)).idle_timeout(client_idle)
            }),
            server_transport: transport(|c| c.idle_timeout(server_idle)),
            ..Setup::default()
        };
        let (_, mut pair) = handshake(setup.pair());
        let client = pair.client.conn();
        assert_eq!(
            client.keepalive_interval(),
            Some(Duration::from_millis(interval)),
            "{keep_alive:?}"
        );
        assert!(client.keepalive_deadline().is_some(), "{keep_alive:?}");
        let quiet = pair.now + Duration::from_secs(5);
        pair.run(quiet);
        assert_eq!(closed(&pair.client.events), None, "{keep_alive:?}");
    }
}

#[test]
fn without_a_keepalive_an_idle_connection_closes() {
    let run = keep_alive_run(None, 3, 3);
    assert!(run.pings().is_empty());
    assert_eq!(
        closed(&run.pair.client.events),
        Some((CloseReason::Silent, Initiator::IdleTimeout))
    );
}

/// Returns a pair past its handshake whose links then lose everything, with the client sending
/// once into the black hole, run until the client drains.
fn black_holed(max_ptos: Option<u32>) -> (Pair, usize) {
    let setup = Setup {
        client_transport: transport(|c| c.max_ptos(max_ptos)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    let all = Loss::Seeded {
        seed: 3,
        per_mille: 1000,
    };
    pair.to_server.set_loss(all.clone());
    pair.to_client.set_loss(all);
    let from = pair.client.sent.len();
    pair.client.conn_mut().ping();
    let limit = pair.now + Duration::from_secs(40);
    assert!(pair.run_until(limit, |pair| pair.client.has_event(&ConnEvent::Drained)));
    (pair, from)
}

#[test]
fn the_pto_limit_closes_silently_at_the_fifth_pto() {
    let (pair, from) = black_holed(Some(5));
    let client = pair.client.conn();
    assert_eq!(
        closed(&pair.client.events),
        Some((CloseReason::Silent, Initiator::PtoLimit))
    );
    assert_eq!(pair.client.events.last(), Some(&ConnEvent::Drained));
    assert_eq!(client.recovery.pto_count(), 5);
    for (_, datagram) in &pair.client.sent[from..] {
        let frames = one_rtt_frames(client, &datagram.data);
        assert!(
            !frames
                .iter()
                .any(|frame| frame.starts_with("ConnectionClose")),
            "{frames:?}"
        );
    }
}

#[test]
fn without_a_pto_limit_a_black_hole_ends_on_the_idle_timeout() {
    let (pair, _) = black_holed(None);
    assert_eq!(
        closed(&pair.client.events),
        Some((CloseReason::Silent, Initiator::IdleTimeout))
    );
    assert!(pair.client.conn().recovery.pto_count() > 5);
}

/// Returns a client that has sent its first Initial, and the datagrams it sent.
fn first_flight() -> (Instant, Pair, Vec<Vec<u8>>) {
    let (epoch, mut pair) = start(Setup::default().pair());
    let sent = transmit(pair.client.conn_mut(), epoch);
    assert_eq!(sent.len(), 1);
    (epoch, pair, sent)
}

#[test]
fn a_client_follows_a_retry() {
    let (epoch, mut pair, first) = first_flight();
    let client = pair.client.conn_mut();
    let odcid = client.original_dcid;
    let own = client.local_cid;
    let cwnd = client.stats().cwnd;
    let (_, hello) = open_long(
        &mvfstr_crypto::initial_keys(Version::V1, &odcid, Side::Server)
            .unwrap()
            .remote,
        &long_packets(&first[0])[0],
    );
    let hello = crypto_frames(&hello);
    let token = b"retry token".to_vec();
    let retry_scid = cid(0xab);
    let now = epoch + Duration::from_millis(20);
    let retry = retry_packet(client, retry_scid, &token, odcid);
    let summary = deliver(client, now, server_addr(), retry);
    assert_eq!(summary.dropped, 0);
    let sent = transmit(client, now);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), 1200);
    let packets = long_packets(&sent[0]);
    assert_eq!(packets[0].ty, PacketType::Initial);
    assert_eq!(packets[0].token, token);
    assert_eq!(packets[0].dcid, &retry_scid[..]);
    assert_eq!(packets[0].scid, &own[..]);
    // Keys derived from the Retry's Source Connection ID open it; packet numbers go on.
    let keys = mvfstr_crypto::initial_keys(Version::V1, &retry_scid, Side::Server).unwrap();
    let (pn, plaintext) = open_long(&keys.remote, &packets[0]);
    assert_eq!(pn, 1);
    assert_eq!(crypto_frames(&plaintext), hello);
    // The first Initial left recovery uncounted; the window starts over.
    let stats = client.stats();
    assert_eq!(stats.lost_packets, 0);
    assert_eq!(stats.bytes_in_flight, 1200);
    assert_eq!(stats.cwnd, cwnd);
    assert_eq!(client.recovery.pto_count(), 0);
    // Every later Initial carries the token, through PTOs.
    for _ in 0..2 {
        let now = client.next_deadline().unwrap();
        client.on_deadline(now);
        let sent = transmit(client, now);
        assert!(!sent.is_empty());
        for datagram in &sent {
            for packet in long_packets(datagram) {
                assert_eq!(packet.token, token);
                assert_eq!(packet.dcid, &retry_scid[..]);
            }
        }
    }
    assert_eq!(client.stats().lost_packets, 0);
}

#[test]
fn a_client_ignores_a_retry_it_must_not_follow() {
    let token = b"retry token".to_vec();
    let check = |name: &str, make: &dyn Fn(&Connection) -> Vec<u8>| {
        let (epoch, mut pair, _) = first_flight();
        let client = pair.client.conn_mut();
        let retry = make(client);
        let summary = deliver(
            client,
            epoch + Duration::from_millis(20),
            server_addr(),
            retry,
        );
        assert_eq!(summary.dropped, 1, "{name}");
        assert!(client.retry.is_none(), "{name}");
        assert_eq!(client.remote_cid(), client.original_dcid, "{name}");
    };
    check("bad tag", &|client| {
        let mut retry = retry_packet(client, cid(0xab), &token, client.original_dcid);
        *retry.last_mut().unwrap() ^= 1;
        retry
    });
    check("tag over another ID", &|client| {
        retry_packet(client, cid(0xab), &token, cid(0x01))
    });
    check("empty token", &|client| {
        retry_packet(client, cid(0xab), &[], client.original_dcid)
    });
    check("same ID", &|client| {
        retry_packet(client, client.original_dcid, &token, client.original_dcid)
    });
}

#[test]
fn a_client_follows_only_the_first_retry_and_none_after_a_server_packet() {
    let token = b"retry token".to_vec();
    let (epoch, mut pair, _) = first_flight();
    let client = pair.client.conn_mut();
    let odcid = client.original_dcid;
    let now = epoch + Duration::from_millis(20);
    let retry = retry_packet(client, cid(0xab), &token, odcid);
    deliver(client, now, server_addr(), retry);
    let second = retry_packet(client, cid(0xcd), b"another", odcid);
    assert_eq!(deliver(client, now, server_addr(), second).dropped, 1);
    assert_eq!(
        client.retry.as_ref().map(|retry| retry.scid),
        Some(cid(0xab))
    );
    assert_eq!(client.remote_cid(), cid(0xab));

    // After the server's first Initial, a Retry is late.
    let (epoch, mut pair) = start(Setup::default().pair());
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.conn().stats().recv_packets > 0
    });
    let client = pair.client.conn_mut();
    let peer = client.remote_cid();
    let late = retry_packet(client, cid(0xab), &token, client.original_dcid);
    assert_eq!(deliver(client, pair.now, server_addr(), late).dropped, 1);
    assert!(client.retry.is_none());
    assert_eq!(client.remote_cid(), peer);
}

/// Returns a pair after the handshake and a quiet half second.
fn established() -> Pair {
    let (_, mut pair) = handshake(Setup::default().pair());
    let quiet = pair.now + Duration::from_millis(500);
    pair.run(quiet);
    pair
}

/// Returns a pair stopped at the step in which its client processed its first packet from the
/// server.
fn past_the_first_server_packet() -> Pair {
    let (epoch, mut pair) = start(Setup::default().pair());
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.conn().stats().recv_packets > 0
    }));
    pair
}

#[test]
fn an_established_client_parses_no_short_header_datagram_for_a_retry() {
    let mut pair = established();
    let now = pair.now;
    let server = pair.server.conn();
    let datagrams: Vec<_> = (0..10)
        .map(|i| Forge::of(server, Space::Data, 1_000 + i, &[Frame::Ping]).seal(server))
        .collect();
    let client = pair.client.conn_mut();
    let probes = client.retry_probes;
    for datagram in datagrams {
        assert_eq!(deliver(client, now, server_addr(), datagram).packets, 1);
    }
    assert_eq!(
        client.retry_probes - probes,
        0,
        "a Retry cannot be followed once a packet from the server was processed"
    );
}

#[test]
fn a_client_parses_datagrams_for_a_retry_only_until_it_follows_one() {
    let (epoch, mut pair, _) = first_flight();
    let client = pair.client.conn_mut();
    let odcid = client.original_dcid;
    let now = epoch + Duration::from_millis(20);
    let first = retry_packet(client, cid(0xab), b"retry token", odcid);
    assert_eq!(deliver(client, now, server_addr(), first).dropped, 0);
    assert_eq!(
        client.retry_probes, 1,
        "the first Retry is parsed and followed"
    );
    while client.poll_event().is_some() {}

    let second = retry_packet(client, cid(0xcd), b"another", odcid);
    let summary = deliver(client, now, server_addr(), second);
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    assert_eq!(
        client.retry.as_ref().map(|retry| retry.scid),
        Some(cid(0xab))
    );
    assert_eq!(client.remote_cid(), cid(0xab));
    assert_eq!(client.poll_event(), None);
    assert_eq!(client.state, State::Open);
    assert_eq!(client.retry_probes, 1, "a second Retry cannot be followed");
}

#[test]
fn a_retry_after_the_first_server_packet_is_dropped_without_a_retry_parse() {
    let mut pair = past_the_first_server_packet();
    let now = pair.now;
    let client = pair.client.conn_mut();
    let peer = client.remote_cid();
    let received = client.stats().recv_packets;
    let probes = client.retry_probes;
    let late = retry_packet(client, cid(0xab), b"retry token", client.original_dcid);
    let summary = deliver(client, now, server_addr(), late);
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    assert!(client.retry.is_none());
    assert_eq!(client.remote_cid(), peer);
    assert_eq!(client.stats().recv_packets, received);
    assert_eq!(client.poll_event(), None);
    assert_eq!(client.state, State::Open);
    // A long header with the Retry type is not parsed for a Retry either: the gate is the
    // connection's state, not the first byte.
    assert_eq!(
        client.retry_probes - probes,
        0,
        "a Retry cannot be followed once a packet from the server was processed"
    );
}

#[test]
fn a_version_negotiation_after_the_first_server_packet_is_ignored_without_a_retry_parse() {
    let mut pair = past_the_first_server_packet();
    let now = pair.now;
    let client = pair.client.conn_mut();
    let probes = client.retry_probes;
    let mut vn = vec![0; 100];
    let versions = [Version(0x1a2a_3a4a)];
    let len = encode_version_negotiation(
        &mut vn,
        0x2a,
        &client.local_cid,
        &client.original_dcid,
        &versions,
    )
    .unwrap();
    vn.truncate(len);
    let summary = deliver(client, now, server_addr(), vn);
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    assert_eq!(client.poll_event(), None);
    assert_eq!(client.state, State::Open);
    assert_eq!(
        client.retry_probes - probes,
        0,
        "a Retry cannot be followed once a packet from the server was processed"
    );
}

#[test]
fn a_retry_shaped_datagram_ending_in_the_peer_token_resets_an_established_client() {
    let mut pair = established();
    let now = pair.now;
    let client = pair.client.conn_mut();
    let token = client.sources.cids.peer.current().unwrap().1.unwrap();
    let mut datagram = retry_packet(client, cid(0xab), b"retry token", client.original_dcid);
    datagram.extend_from_slice(&token.0);
    let summary = deliver(client, now, server_addr(), datagram);
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    let events: Vec<_> = std::iter::from_fn(|| client.poll_event()).collect();
    assert_eq!(
        closed(&events),
        Some((CloseReason::Silent, Initiator::StatelessReset)),
        "a datagram that cannot be processed and ends in the token is a stateless reset: \
         {events:?}"
    );
}

/// Returns a pair config whose client holds a session ticket from a finished connection.
fn resumable(setup: &Setup) -> PairConfig {
    let config = setup.pair();
    let (_, mut pair) = handshake(config.clone());
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    config
}

/// Returns `config` with a server that shares its session cache but has `transport` and, if
/// `accept_early_data`, accepts 0-RTT.
fn with_server(
    config: &PairConfig,
    transport: Arc<TransportConfig>,
    accept_early_data: bool,
) -> PairConfig {
    let mut tls = rustls::ServerConfig::clone(config.server.tls().rustls().unwrap());
    tls.max_early_data_size = 0;
    let server = ServerConfig::builder(Arc::new(tls))
        .transport(transport)
        .accept_early_data(accept_early_data)
        .build()
        .unwrap();
    PairConfig {
        server,
        ..config.clone()
    }
}

fn early_setup() -> Setup {
    Setup {
        early_data: true,
        ..Setup::default()
    }
}

/// Returns whether the client's events hold `EarlyData { accepted }` before `Connected`, after
/// a single `EarlyDataWritable` first.
fn early_events_in_order(events: &[ConnEvent], accepted: bool) -> bool {
    let at = |wanted: &ConnEvent| events.iter().position(|event| event == wanted);
    let writable = events
        .iter()
        .filter(|event| **event == ConnEvent::EarlyDataWritable)
        .count();
    writable == 1
        && events.first() == Some(&ConnEvent::EarlyDataWritable)
        && at(&ConnEvent::EarlyData { accepted })
            .zip(at(&ConnEvent::Connected))
            .is_some_and(|(early, connected)| early < connected)
}

#[test]
fn accepted_0rtt_carries_a_request_before_the_handshake_completes() {
    let config = resumable(&with_ack_progress(early_setup()));
    let (epoch, mut pair) = start(config);
    let client = pair.client.conn_mut();
    assert_eq!(client.poll_event(), Some(ConnEvent::EarlyDataWritable));
    pair.client.events.push(ConnEvent::EarlyDataWritable);
    let client = pair.client.conn_mut();
    // The remembered limits are in force.
    assert_eq!(client.peer_max_streams(Dir::Bi), 100);
    assert_eq!(client.openable_streams(Dir::Bi), 100);
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(id, StreamId::new(Side::Client, Dir::Bi, 0).unwrap());
    send_all(client, id, 1_000);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Confirmed)
    }));
    let datagrams = client_datagrams(&pair);
    assert_eq!(
        packet_types(&datagrams[0]),
        [PacketType::Initial, PacketType::ZeroRtt]
    );
    assert!(
        early_events_in_order(&pair.client.events, true),
        "{:?}",
        pair.client.events
    );
    assert_eq!(read_all(pair.server.conn_mut(), id), (1_000, true));
    send_all(pair.server.conn_mut(), id, 500);
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    assert_eq!(read_all(pair.client.conn_mut(), id), (500, true));
    let client = pair.client.conn_mut();
    assert_eq!(drain_acked(client), [(id, 1_000)]);
    assert_eq!(client.stats().lost_packets, 0);
    assert_eq!(client.tls_info().map(|info| info.resumed), Some(true));
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn a_client_hello_in_two_datagrams_takes_0rtt_data_in_the_first() {
    // A post-quantum key share makes the ClientHello longer than one datagram.
    let config = resumable(&Setup {
        pq: true,
        ..early_setup()
    });
    let (epoch, mut pair) = start(config);
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 1_000);
    let sent = transmit(client, epoch);
    // The 0-RTT data joins the first datagram, ahead of the end of the ClientHello: a server can
    // keep packets that arrive before their keys (RFC 9001).
    assert_eq!(
        packet_types(&sent[0]),
        [PacketType::Initial, PacketType::ZeroRtt]
    );
    assert_eq!(
        packet_types(&sent[1]).first(),
        Some(&PacketType::Initial),
        "the ClientHello goes on in the second datagram"
    );
}

#[test]
fn a_resumed_peer_maximum_client_sizes_0rtt_datagrams_from_the_remembered_limit_and_the_cap() {
    // The server advertised 1,500 bytes, above the cap and above what the client advertises.
    let setup = Setup {
        early_data: true,
        client_transport: transport(|c| {
            c.max_udp_payload_size(1300)
                .datagram_size(DatagramSize::PeerMaximum {
                    initial: 1232,
                    cap: 1452,
                })
        }),
        server_transport: transport(|c| c.max_udp_payload_size(1500)),
        ..Setup::default()
    };
    let (epoch, mut pair) = start(resumable(&setup));
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 6_000);
    let sent = transmit(client, epoch);
    assert_eq!(
        packet_types(&sent[0]),
        [PacketType::Initial, PacketType::ZeroRtt]
    );
    let sizes: Vec<usize> = sent.iter().map(Vec::len).collect();
    assert_eq!(sizes[0], 1452, "the first datagram: {sizes:?}");
    assert!(sizes.iter().all(|&len| len <= 1452), "{sizes:?}");
    let full = sizes.iter().filter(|&&len| len == 1452).count();
    assert!(full >= 3, "{sizes:?}");
}

#[test]
fn rejected_0rtt_discards_the_early_streams_and_numbering_starts_over() {
    let config = resumable(&with_ack_progress(early_setup()));
    let rejecting = with_server(&config, Arc::new(TransportConfig::default()), false);
    let (epoch, mut pair) = start(rejecting);
    let client = pair.client.conn_mut();
    let bidi = client.open_stream(Dir::Bi, ORDER).unwrap();
    let uni = client.open_stream(Dir::Uni, ORDER).unwrap();
    send_all(client, bidi, 1_000);
    send_all(client, uni, 700);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Confirmed)
    }));
    assert!(
        early_events_in_order(&pair.client.events, false),
        "{:?}",
        pair.client.events
    );
    assert!(
        client_datagrams(&pair)
            .iter()
            .any(|datagram| packet_types(datagram).contains(&PacketType::ZeroRtt))
    );
    let client = pair.client.conn_mut();
    assert_eq!(client.readiness().count(), 0);
    assert_eq!(client.poll_stream_acked(), None);
    assert_eq!(client.stats().lost_packets, 0);
    assert!(client.stream(uni).is_err());
    // The server did not receive any of the early data; the first bidirectional stream is 0 again.
    let again = client.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(again, bidi);
    send_all(client, again, 300);
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    assert_eq!(read_all(pair.server.conn_mut(), again), (300, true));
    assert!(pair.server.conn_mut().stream(uni).is_err());
    send_all(pair.server.conn_mut(), again, 400);
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    assert_eq!(read_all(pair.client.conn_mut(), again), (400, true));
    assert_eq!(drain_acked(pair.client.conn_mut()), [(again, 300)]);
}

#[test]
fn without_a_ticket_there_is_no_0rtt() {
    let (epoch, mut pair) = start(early_setup().pair());
    let client = pair.client.conn_mut();
    assert_eq!(client.poll_event(), None);
    assert_eq!(
        client.open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
    assert!(pair.handshake(epoch + LIMIT));
    assert!(!pair.client.has_event(&ConnEvent::EarlyDataWritable));
    assert!(
        !pair
            .client
            .events
            .iter()
            .any(|event| matches!(event, ConnEvent::EarlyData { .. }))
    );
    assert!(
        client_datagrams(&pair)
            .iter()
            .all(|datagram| !packet_types(datagram).contains(&PacketType::ZeroRtt))
    );
}

#[test]
fn a_retry_after_0rtt_sends_the_early_data_again() {
    let config = resumable(&early_setup());
    let (epoch, mut pair) = start(config);
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 1_000);
    let first = transmit(client, epoch);
    assert_eq!(
        packet_types(&first[0]),
        [PacketType::Initial, PacketType::ZeroRtt]
    );
    let token = b"retry token".to_vec();
    let odcid = client.original_dcid;
    let now = epoch + Duration::from_millis(20);
    let retry = retry_packet(client, cid(0xab), &token, odcid);
    deliver(client, now, server_addr(), retry);
    let sent = transmit(client, now);
    let packets: Vec<LongPacket> = sent
        .iter()
        .flat_map(|datagram| long_packets(datagram))
        .collect();
    assert_eq!(packets[0].ty, PacketType::Initial);
    assert_eq!(packets[0].token, token);
    let keys = client.early.as_ref().unwrap().keys.as_ref().unwrap();
    let mut streams = Vec::new();
    for packet in packets
        .iter()
        .filter(|packet| packet.ty == PacketType::ZeroRtt)
    {
        assert_eq!(packet.dcid, &cid(0xab)[..]);
        let (_, plaintext) = open_long(keys, packet);
        for frame in Frames::new(&plaintext) {
            if let Frame::Stream {
                id: frame_id,
                offset,
                data,
                fin,
            } = frame.unwrap()
            {
                streams.push((frame_id, offset.into_inner(), data.len(), fin));
            }
        }
    }
    // The early data goes again unchanged: the same bytes and FIN, without new credit.
    let mut next = 0;
    for &(frame_id, offset, len, fin) in &streams {
        assert_eq!((frame_id, offset), (id, next), "{streams:?}");
        next += len as u64;
        assert_eq!(fin, next == 1_000, "{streams:?}");
    }
    assert_eq!(next, 1_000, "{streams:?}");
    assert!(client.stream(id).is_ok());
    assert_eq!(client.stats().lost_packets, 0);
    // The first EarlyDataWritable is the only event: the Retry does not queue another.
    assert_eq!(client.poll_event(), Some(ConnEvent::EarlyDataWritable));
    assert_eq!(client.poll_event(), None);
    assert_eq!(client.readiness().count(), 0);
}

/// Checks that `packet_room` in `space` is the header a writer lays out for a `ty` packet on the
/// first path, at a 4-byte packet number and Length field, plus the payload and the AEAD tag.
fn assert_room_is_the_written_header(conn: &Connection, space: Space, ty: PacketType) {
    let (version, dcid, scid) = (conn.version, conn.remote_cid(), conn.local_cid);
    let token = conn
        .retry
        .as_ref()
        .map_or(&[][..], |retry| &retry.token[..]);
    let header = match ty {
        PacketType::Initial => HeaderSpec::Initial {
            version,
            dcid,
            scid,
            token,
        },
        PacketType::ZeroRtt => HeaderSpec::ZeroRtt {
            version,
            dcid,
            scid,
        },
        PacketType::Handshake => HeaderSpec::Handshake {
            version,
            dcid,
            scid,
        },
        PacketType::OneRtt => HeaderSpec::OneRtt {
            dcid,
            spin: false,
            key_phase: false,
        },
    };
    // The writer sizes the Length field for its buffer: 4 bytes from 2^14 bytes on.
    let mut buf = vec![0; 1 << 14];
    let writer = PacketWriter::new(&mut buf, header, 0, 4, TAG_LEN).unwrap();
    for payload in [1, 1_000] {
        assert_eq!(
            conn.packet_room(space, PathId(0), payload),
            writer.header_len() + payload + TAG_LEN,
            "{ty:?} packet with {payload} payload bytes, {}-byte source ID",
            scid.len()
        );
    }
}

#[test]
fn packet_room_holds_the_header_of_every_packet_type() {
    let config = resumable(&early_setup());
    let (epoch, mut pair) = start(config.clone());
    let client = pair.client.conn_mut();
    assert!(!client.local_cid.is_empty());
    assert!(client.zero_rtt_write_keys().is_some());
    assert_room_is_the_written_header(client, Space::Initial, PacketType::Initial);
    assert_room_is_the_written_header(client, Space::Handshake, PacketType::Handshake);
    assert_room_is_the_written_header(client, Space::Data, PacketType::ZeroRtt);

    let odcid = client.original_dcid;
    let retry = retry_packet(client, cid(0xab), b"retry token", odcid);
    deliver(client, epoch, server_addr(), retry);
    assert!(client.retry.is_some());
    assert_room_is_the_written_header(client, Space::Initial, PacketType::Initial);
    assert_room_is_the_written_header(client, Space::Data, PacketType::ZeroRtt);

    let (_, pair) = handshake(config);
    let server = pair.server.conn();
    assert!(!server.local_cid.is_empty());
    assert_room_is_the_written_header(server, Space::Initial, PacketType::Initial);
    assert_room_is_the_written_header(server, Space::Handshake, PacketType::Handshake);
    for conn in [pair.client.conn(), server] {
        assert_room_is_the_written_header(conn, Space::Data, PacketType::OneRtt);
    }
}

#[test]
fn a_server_lowering_a_limit_0rtt_used_is_a_protocol_violation() {
    let config = resumable(&early_setup());
    let lower = with_server(&config, transport(|c| c.max_data(1 << 19)), true);
    let (epoch, mut pair) = start(lower);
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 1_000);
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained)
    });
    let Some((CloseReason::Transport { code, .. }, Initiator::Local)) = closed(&pair.client.events)
    else {
        panic!("{:?}", pair.client.events);
    };
    assert_eq!(code, TransportErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn a_server_lowering_its_idle_timeout_under_0rtt_is_fine() {
    let config = resumable(&early_setup());
    let shorter = with_server(
        &config,
        transport(|c| c.idle_timeout(Some(Duration::from_secs(10)))),
        true,
    );
    let (epoch, mut pair) = start(shorter);
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Bi, ORDER).unwrap();
    send_all(client, id, 1_000);
    assert!(pair.handshake(epoch + LIMIT));
    assert!(
        pair.client
            .has_event(&ConnEvent::EarlyData { accepted: true })
    );
    assert_eq!(closed(&pair.client.events), None);
    assert_eq!(read_all(pair.server.conn_mut(), id), (1_000, true));
}

/// Returns a transport config that advertises a max_datagram_frame_size of 65535.
fn datagrams() -> Arc<TransportConfig> {
    transport(|c| c.max_datagram_frame_size(65535))
}

#[test]
fn a_ticket_from_a_connection_that_advertises_datagrams_does_not_allow_0rtt() {
    // RFC 9221: a server that accepts 0-RTT must advertise at least the max_datagram_frame_size of
    // the connection that issued the ticket, and this server does not advertise one.
    let config = resumable(&early_setup().transport(datagrams()));
    let without_datagrams = with_server(&config, Arc::new(TransportConfig::default()), true);
    let (epoch, mut pair) = start(without_datagrams);
    assert!(pair.handshake(epoch + LIMIT));
    assert!(!pair.client.has_event(&ConnEvent::EarlyDataWritable));
    assert!(
        !pair
            .client
            .events
            .iter()
            .any(|event| matches!(event, ConnEvent::EarlyData { .. }))
    );
    let client = pair.client.conn_mut();
    assert_eq!(client.tls_info().map(|info| info.resumed), Some(true));
    assert_eq!(client.peer_max_datagram_frame_size(), 0);
}

#[test]
fn a_connection_that_advertises_datagrams_does_not_accept_0rtt() {
    let config = resumable(&early_setup());
    let (epoch, mut pair) = start(with_server(&config, datagrams(), true));
    assert!(pair.handshake(epoch + LIMIT));
    assert!(
        early_events_in_order(&pair.client.events, false),
        "{:?}",
        pair.client.events
    );
    assert_eq!(pair.client.conn_mut().peer_max_datagram_frame_size(), 65535);
}
