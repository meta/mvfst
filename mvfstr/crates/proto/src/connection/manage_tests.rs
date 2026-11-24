/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection management tests over the pair harness: connection IDs, stateless resets, Version
//! Negotiation, the address policy before confirmation, path validation and key updates.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::ops::Range;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_crypto::TAG_LEN;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::ResetToken;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use mvfstr_wire::encode_version_negotiation;

use super::Connection;
use super::MIN_DATAGRAM;
use super::State;
use super::tests::Forge;
use super::tests::LIMIT;
use super::tests::client_addr;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::open_own_one_rtt;
use super::tests::server_addr;
use super::tests::start;
use crate::AppCode;
use crate::ClockEpoch;
use crate::CloseReason;
use crate::CongestionControl;
use crate::ConnEvent;
use crate::Ecn;
use crate::Endpoint;
use crate::EndpointConfig;
use crate::EndpointEvent;
use crate::Initiator;
use crate::InlineSealer;
use crate::KeyUpdatePolicy;
use crate::PathEvent;
use crate::PathId;
use crate::Route;
use crate::RxMeta;
use crate::SealJob;
use crate::Sealer;
use crate::SendOrder;
use crate::SlotId;
use crate::SrcPortBlocklist;
use crate::StreamReady;
use crate::Tick;
use crate::TransportConfig;
use crate::TxLimits;
use crate::cc::Cc;
use crate::cc::CcConfig;
use crate::cc::CongestionSignal;
use crate::cid::CidGenerator;
use crate::cid::PeerCids;
use crate::recovery::Space;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::SentDatagram;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

fn transport(active_connection_id_limit: u64) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .active_connection_id_limit(active_connection_id_limit)
        .build()
        .unwrap()
}

/// Returns a pair past the handshake that has had time to exchange its connection IDs.
fn settled(setup: &Setup) -> Pair {
    settled_pair(setup.pair())
}

/// Returns a pair of `config` past the handshake that has had time to exchange its connection IDs.
fn settled_pair(config: PairConfig) -> Pair {
    let (_, mut pair) = handshake(config);
    let quiet = pair.now + Duration::from_millis(500);
    pair.run(quiet);
    pair
}

/// Returns the generator of the pair harness's endpoints.
fn generator() -> CidGenerator {
    CidGenerator::new(&Setup::default().pair().endpoint)
}

fn meta(src: std::net::SocketAddr, now: std::time::Instant) -> RxMeta {
    RxMeta {
        src,
        dst_ip: None,
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: now,
    }
}

/// Returns a short-header datagram for `cid`, padded with zeros: enough to route, not to open.
fn short_header(cid: &ConnectionId) -> Vec<u8> {
    let mut out = vec![0x40];
    out.extend_from_slice(cid);
    out.resize(60, 0);
    out
}

fn endpoint_events(conn: &mut Connection) -> Vec<EndpointEvent> {
    std::iter::from_fn(|| conn.poll_endpoint_event()).collect()
}

fn events(conn: &mut Connection) -> Vec<ConnEvent> {
    std::iter::from_fn(|| conn.poll_event()).collect()
}

/// Returns whether `conn` reported a stateless reset since its events were last read.
fn was_reset(conn: &mut Connection) -> bool {
    events(conn).iter().any(|event| {
        matches!(
            event,
            ConnEvent::Closed {
                initiator: Initiator::StatelessReset,
                ..
            }
        )
    })
}

fn transport_close(code: TransportErrorCode) -> impl Fn(&ConnEvent) -> bool {
    move |event| {
        matches!(
            event,
            ConnEvent::Closed {
                reason: CloseReason::Transport { code: c, .. },
                initiator: Initiator::Local,
            } if *c == code
        )
    }
}

/// Returns the frames of the 1-RTT packets `conn` sends now.
fn sent_frames(conn: &mut Connection) -> Vec<(ConnectionId, Vec<String>)> {
    let now = conn.now;
    let mut sink = VecSink::new(1500);
    let limits = TxLimits {
        now,
        max_segments: 16,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: None,
    };
    conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    frames_of(conn, &sink.take())
}

/// Returns the frames of the 1-RTT packets of `sent`, datagrams `conn` sent.
fn frames_of(conn: &Connection, sent: &[SentDatagram]) -> Vec<(ConnectionId, Vec<String>)> {
    let mut out = Vec::new();
    for datagram in sent {
        let Ok(header) = Header::parse(&datagram.data, 8) else {
            continue;
        };
        let dcid = ConnectionId::new(header.dcid()).unwrap();
        for plaintext in open_own_one_rtt(conn, &datagram.data) {
            let frames = Frames::new(&plaintext)
                .map(|frame| format!("{:?}", frame.unwrap()))
                .collect();
            out.push((dcid, frames));
        }
    }
    out
}

#[test]
fn both_sides_issue_connection_ids_up_to_the_peer_limit() {
    let mut pair = settled(&Setup::default().transport(transport(4)));
    let now = pair.now;
    let generator = generator();
    for issued_by_server in [true, false] {
        let (holder, issuer) = if issued_by_server {
            (&pair.client, &mut pair.server)
        } else {
            (&pair.server, &mut pair.client)
        };
        let ids = holder.conn().sources.cids.peer.ids();
        assert_eq!(ids.len(), 4, "{:?}", holder.conn().side());
        assert_eq!(issuer.conn().sources.cids.local.active(), 4);
        for (seq, cid, token) in ids {
            let route = issuer
                .endpoint
                .route(now, &meta(holder.addr, now), &short_header(&cid));
            assert!(
                matches!(route, Route::Existing(key) if key == issuer.key),
                "{seq}: {route:?}"
            );
            // A client does not send the stateless_reset_token parameter, so its handshake ID lacks
            // a token; every other ID has its token.
            if seq > 0 || issued_by_server {
                assert_eq!(token, Some(generator.reset_token(&cid)), "{seq}");
            }
        }
    }
}

#[test]
fn a_retired_connection_id_is_replaced_and_no_longer_routed() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let ids = pair.client.conn().sources.cids.peer.ids();
    assert_eq!(ids.len(), 2);
    let (_, retired, _) = ids[1];
    let frames = [Frame::RetireConnectionId {
        seq: VarInt::from_u32(1),
    }];
    let datagram =
        Forge::of(pair.client.conn(), Space::Data, 1000, &frames).seal(pair.client.conn());
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), datagram);
    let events = endpoint_events(server);
    assert!(
        events.contains(&EndpointEvent::RetiredLocalCid { cid: retired }),
        "{events:?}"
    );
    let replacement = events.iter().find_map(|event| match event {
        EndpointEvent::NewLocalCid { cid, .. } => Some(*cid),
        _ => None,
    });
    assert!(replacement.is_some(), "{events:?}");
    assert_eq!(server.sources.cids.local.active(), 2);
    for event in events {
        pair.server.endpoint.handle_event(pair.server.key, event);
    }
    let mut route = |cid| {
        pair.server
            .endpoint
            .route(now, &meta(client_addr(), now), &short_header(&cid))
    };
    assert!(!matches!(route(retired), Route::Existing(_)));
    assert!(matches!(route(replacement.unwrap()), Route::Existing(_)));
}

#[test]
fn retiring_the_id_a_packet_was_sent_to_closes_the_connection() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let frames = [Frame::RetireConnectionId { seq: VarInt::ZERO }];
    let datagram =
        Forge::of(pair.client.conn(), Space::Data, 1000, &frames).seal(pair.client.conn());
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), datagram);
    let events = events(server);
    assert!(
        events
            .iter()
            .any(transport_close(TransportErrorCode::PROTOCOL_VIOLATION)),
        "{events:?}"
    );
}

#[test]
fn retire_prior_to_moves_the_client_to_a_new_server_id() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new = ConnectionId::new(&[42; 8]).unwrap();
    let token = ResetToken([42; 16]);
    let frames = [Frame::NewConnectionId {
        seq: VarInt::from_u32(2),
        retire_prior_to: VarInt::from_u32(2),
        cid: new,
        reset_token: token,
    }];
    let datagram =
        Forge::of(pair.server.conn(), Space::Data, 1000, &frames).seal(pair.server.conn());
    let client = pair.client.conn_mut();
    deliver(client, now, server_addr(), datagram);
    assert_eq!(client.remote_cid(), new);
    let sent = sent_frames(client);
    let events = endpoint_events(client);
    assert!(
        events.contains(&EndpointEvent::PeerResetTokens {
            current: Some((server_addr(), token)),
            alternate: None,
        }),
        "{events:?}"
    );
    let retired: Vec<_> = sent
        .iter()
        .flat_map(|(dcid, frames)| {
            assert_eq!(*dcid, new);
            frames
                .iter()
                .filter(|frame| frame.starts_with("RetireConnectionId"))
        })
        .collect();
    assert_eq!(retired.len(), 2, "{sent:?}");
}

#[test]
fn a_reset_token_counts_only_once_a_packet_went_out_with_its_id() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let token = ResetToken([42; 16]);
    let frames = [Frame::NewConnectionId {
        seq: VarInt::from_u32(2),
        retire_prior_to: VarInt::from_u32(2),
        cid: ConnectionId::new(&[42; 8]).unwrap(),
        reset_token: token,
    }];
    let datagram =
        Forge::of(pair.server.conn(), Space::Data, 1000, &frames).seal(pair.server.conn());
    let client = pair.client.conn_mut();
    deliver(client, now, server_addr(), datagram);
    let mut reset = vec![0x5f; 30];
    reset.extend_from_slice(&token.0);
    let learned = |events: &[EndpointEvent]| {
        events.contains(&EndpointEvent::PeerResetTokens {
            current: Some((server_addr(), token)),
            alternate: None,
        })
    };
    let events = endpoint_events(client);
    assert!(!learned(&events), "{events:?}");
    deliver(client, now, server_addr(), reset.clone());
    assert!(
        !was_reset(client),
        "not before a packet went out with its ID, as RFC 9000 requires"
    );
    client.ping();
    assert!(!transmit(client, now).is_empty());
    let events = endpoint_events(client);
    assert!(learned(&events), "{events:?}");
    deliver(client, now, server_addr(), reset);
    assert!(was_reset(client));
}

#[test]
fn a_new_connection_id_that_fails_after_moving_the_id_in_use_closes_on_the_new_id() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    // Each frame retires every earlier ID and the client's retirements stay unacknowledged, so the
    // fourth goes past twice the active_connection_id_limit of 2.
    let frames: Vec<_> = (2..=5u8)
        .map(|seq| Frame::NewConnectionId {
            seq: VarInt::from_u32(seq.into()),
            retire_prior_to: VarInt::from_u32(seq.into()),
            cid: ConnectionId::new(&[seq; 8]).unwrap(),
            reset_token: ResetToken([seq; 16]),
        })
        .collect();
    let datagram =
        Forge::of(pair.server.conn(), Space::Data, 1000, &frames).seal(pair.server.conn());
    let client = pair.client.conn_mut();
    deliver(client, now, server_addr(), datagram);
    let events = events(client);
    assert!(
        events
            .iter()
            .any(transport_close(TransportErrorCode::PROTOCOL_VIOLATION)),
        "{events:?}"
    );
    let sent = sent_frames(client);
    assert!(!sent.is_empty(), "the CLOSE");
    for (dcid, frames) in sent {
        assert_eq!(dcid, ConnectionId::new(&[5; 8]).unwrap(), "{frames:?}");
    }
}

#[test]
fn a_server_that_lost_its_state_resets_the_client() {
    let mut pair = settled(&Setup::default());
    // The server restarts with the same reset key but without its connections.
    let config = Setup::default().pair();
    pair.server.endpoint = Endpoint::new(config.endpoint, Some(config.server));
    pair.server.conn = None;
    pair.client.conn_mut().ping();
    let reset = ConnEvent::Closed {
        reason: CloseReason::Silent,
        initiator: Initiator::StatelessReset,
    };
    let limit = pair.now + LIMIT;
    assert!(
        pair.run_until(limit, |pair| pair.client.has_event(&reset)),
        "{:?}",
        pair.client.events
    );
    let sent = pair.client.sent.len();
    let limit = pair.now + LIMIT;
    pair.run(limit);
    assert_eq!(
        pair.client.sent.len(),
        sent,
        "a reset connection sends nothing"
    );
    assert!(pair.client.has_event(&ConnEvent::Drained));
}

#[test]
fn a_reset_counts_only_from_the_peers_address() {
    let pair = settled(&Setup::default());
    let token = pair
        .client
        .conn()
        .sources
        .cids
        .peer
        .current()
        .unwrap()
        .1
        .unwrap();
    let mut reset = vec![0x5f; 30];
    reset.extend_from_slice(&token.0);
    let reset_event = |conn: &mut Connection| {
        events(conn).iter().any(|event| {
            matches!(
                event,
                ConnEvent::Closed {
                    initiator: Initiator::StatelessReset,
                    ..
                }
            )
        })
    };
    let mut client = pair.client.conn.unwrap();
    let now = client.now;
    let stranger = std::net::SocketAddr::new(server_addr().ip(), 4434);
    deliver(&mut client, now, stranger, reset.clone());
    assert!(!reset_event(&mut client), "not from the server's address");
    deliver(&mut client, now, server_addr(), reset);
    assert!(reset_event(&mut client));
    let mut sink = VecSink::new(1500);
    client.ping();
    let limits = TxLimits {
        now,
        max_segments: 16,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: None,
    };
    client.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    assert!(sink.take().is_empty(), "a reset connection drains silently");
}

#[test]
fn a_server_holding_a_client_token_counts_a_reset_only_from_the_clients_address() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let token = ResetToken([8; 16]);
    let frames = [Frame::NewConnectionId {
        seq: VarInt::from_u32(2),
        retire_prior_to: VarInt::from_u32(2),
        cid: ConnectionId::new(&[8; 8]).unwrap(),
        reset_token: token,
    }];
    let datagram = client_packet(&pair, 10, None, None, &frames);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), datagram);
    assert_eq!(server.sources.cids.peer.current().unwrap().1, Some(token));
    server.ping();
    assert!(
        !transmit(server, now).is_empty(),
        "a packet under the new ID"
    );
    let mut reset = vec![0x5f; 30];
    reset.extend_from_slice(&token.0);
    let reset_event = |conn: &mut Connection| {
        events(conn).iter().any(|event| {
            matches!(
                event,
                ConnEvent::Closed {
                    initiator: Initiator::StatelessReset,
                    ..
                }
            )
        })
    };
    deliver(server, now, stranger(), reset.clone());
    assert!(!reset_event(server), "not from the client's address");
    deliver(server, now, client_addr(), reset);
    assert!(reset_event(server));
}

/// Returns a Version Negotiation packet in answer to `client`'s Initial, listing `versions`.
fn version_negotiation(client: &Connection, versions: &[Version]) -> Vec<u8> {
    version_negotiation_for(&client.local_cid, &client.original_dcid, versions)
}

fn version_negotiation_for(dcid: &[u8], scid: &[u8], versions: &[Version]) -> Vec<u8> {
    let mut out = vec![0; 100];
    let len = encode_version_negotiation(&mut out, 0x2a, dcid, scid, versions).unwrap();
    out.truncate(len);
    out
}

#[test]
fn a_client_abandons_the_attempt_when_the_server_shares_no_version() {
    let (now, mut pair) = start(Setup::default().pair());
    let client = pair.client.conn_mut();
    let vn = version_negotiation(client, &[Version(0x1a2a_3a4a), Version::MVFST]);
    deliver(client, now, server_addr(), vn);
    assert_eq!(
        events(client),
        [
            ConnEvent::Closed {
                reason: CloseReason::NoCommonVersion,
                initiator: Initiator::Peer,
            },
            ConnEvent::Drained,
        ]
    );
    assert_eq!(endpoint_events(client), [EndpointEvent::Drained]);
}

#[test]
fn version_negotiation_is_ignored_unless_it_answers_the_first_initial() {
    let (now, mut pair) = start(Setup::default().pair());
    let other = [Version(0x1a2a_3a4a)];
    let client = pair.client.conn_mut();
    let (dcid, scid) = (client.local_cid, client.original_dcid);
    for (why, vn) in [
        (
            "it lists the version in use",
            version_negotiation(client, &[Version(0x1a2a_3a4a), Version::V1]),
        ),
        (
            "it does not echo the client's IDs",
            version_negotiation_for(&scid, &dcid, &other),
        ),
    ] {
        deliver(client, now, server_addr(), vn);
        assert_eq!(events(client), [], "{why}");
    }
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let vn = version_negotiation(client, &other);
    deliver(client, now, server_addr(), vn);
    assert_eq!(events(client), [], "packets were processed before");
    let server = pair.server.conn_mut();
    let vn = version_negotiation_for(&server.local_cid, &server.remote_cid(), &other);
    deliver(server, now, client_addr(), vn);
    assert_eq!(events(server), [], "a server ignores Version Negotiation");
}

#[test]
fn a_version_negotiation_ending_in_the_peer_token_resets_an_established_client() {
    let pair = settled(&Setup::default());
    let mut client = pair.client.conn.unwrap();
    let now = client.now;
    let token = client.sources.cids.peer.current().unwrap().1.unwrap();
    let mut datagram = version_negotiation(&client, &[Version(0x1a2a_3a4a)]);
    datagram.extend_from_slice(&token.0);
    deliver(&mut client, now, server_addr(), datagram);
    let reset = ConnEvent::Closed {
        reason: CloseReason::Silent,
        initiator: Initiator::StatelessReset,
    };
    assert!(events(&mut client).contains(&reset));
}

fn stranger() -> std::net::SocketAddr {
    std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
        50_000,
    )
}

/// Returns the client's address after a NAT rebinding that kept its IP.
fn rebound_port() -> SocketAddr {
    SocketAddr::new(client_addr().ip(), 50_001)
}

/// Returns the datagrams `conn` sends now, to a backend with release support, which a connection
/// with a build horizon needs.
fn transmit(conn: &mut Connection, now: Instant) -> Vec<SentDatagram> {
    let mut sink = VecSink::new(1500);
    let limits = TxLimits {
        now,
        max_segments: 16,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: Some(ClockEpoch {
            instant: crate::recovery::test_epoch(),
            tick: Tick(0),
        }),
    };
    conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    sink.take()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathFrame {
    Challenge([u8; 8]),
    Response([u8; 8]),
}

/// Returns the PATH_CHALLENGE and PATH_RESPONSE frames of a datagram `conn` sent.
fn path_frames(conn: &Connection, datagram: &[u8]) -> Vec<PathFrame> {
    let mut out = Vec::new();
    for plaintext in open_own_one_rtt(conn, datagram) {
        for frame in Frames::new(&plaintext) {
            match frame.unwrap() {
                Frame::PathChallenge(data) => out.push(PathFrame::Challenge(data)),
                Frame::PathResponse(data) => out.push(PathFrame::Response(data)),
                _ => {}
            }
        }
    }
    out
}

/// Returns the data of the first PATH_CHALLENGE among `sent` that went to `to`.
fn challenge_to(conn: &Connection, sent: &[SentDatagram], to: SocketAddr) -> Option<[u8; 8]> {
    sent.iter()
        .filter(|datagram| datagram.meta.dst == to)
        .flat_map(|datagram| path_frames(conn, &datagram.data))
        .find_map(|frame| match frame {
            PathFrame::Challenge(data) => Some(data),
            PathFrame::Response(_) => None,
        })
}

/// Returns a 1-RTT datagram the client could send with `frames`, `ahead` packet numbers past the
/// next one it would use.
fn from_client(pair: &Pair, ahead: u64, frames: &[Frame<'_>]) -> Vec<u8> {
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Data).next_pn() + ahead;
    Forge::of(client, Space::Data, pn, frames).seal(client)
}

/// Returns a 1-RTT datagram the client could send `ahead` packet numbers past the next one it would
/// use, to `dcid` (its current one if `None`), with an ACK of the server's `acked` packets first if
/// any, then `frames`.
fn client_packet(
    pair: &Pair,
    ahead: u64,
    dcid: Option<ConnectionId>,
    acked: Option<RangeInclusive<u64>>,
    frames: &[Frame<'_>],
) -> Vec<u8> {
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Data).next_pn() + ahead;
    let mut buf = vec![0; 1500];
    let header = HeaderSpec::OneRtt {
        dcid: dcid.unwrap_or(client.remote_cid()),
        spin: false,
        key_phase: false,
    };
    let mut w = PacketWriter::new(&mut buf, header, pn, 4, TAG_LEN).unwrap();
    if let Some(range) = acked {
        w.ack(range, std::iter::empty(), VarInt::ZERO, None)
            .unwrap();
    }
    for frame in frames {
        w.frame(frame).unwrap();
    }
    let layout = w.finish();
    let keys = &client.spaces[Space::Data.index()]
        .keys
        .as_ref()
        .unwrap()
        .local;
    let job = SealJob {
        slot: SlotId(0),
        keys,
        pn,
        hdr_len: u16::try_from(layout.hdr_len).unwrap(),
        len: u16::try_from(layout.len).unwrap(),
    };
    InlineSealer.seal(job, &mut buf).unwrap();
    buf.truncate(layout.len);
    buf
}

#[test]
fn a_path_challenge_is_answered_on_its_path_in_a_full_size_datagram() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let challenge = from_client(&pair, 10, &[Frame::PathChallenge([7; 8])]);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), challenge);
    let sent = transmit(server, now);
    let answers: Vec<_> = sent
        .iter()
        .filter(|datagram| {
            path_frames(server, &datagram.data).contains(&PathFrame::Response([7; 8]))
        })
        .collect();
    assert_eq!(answers.len(), 1, "{} datagrams", sent.len());
    assert_eq!(answers[0].meta.dst, client_addr());
    assert_eq!(answers[0].meta.path, PathId(0));
    assert!(answers[0].data.len() >= 1200, "{}", answers[0].data.len());
}

#[test]
fn only_the_latest_challenge_on_a_path_is_answered() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let first = from_client(&pair, 10, &[Frame::PathChallenge([1; 8])]);
    let second = from_client(&pair, 11, &[Frame::PathChallenge([2; 8])]);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), first);
    deliver(server, now, client_addr(), second);
    let sent = transmit(server, now);
    let frames: Vec<_> = sent
        .iter()
        .flat_map(|datagram| path_frames(server, &datagram.data))
        .collect();
    assert_eq!(frames, [PathFrame::Response([2; 8])]);
}

#[test]
fn a_probe_from_a_new_address_is_answered_there_without_migrating() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let probe = from_client(
        &pair,
        10,
        &[Frame::PathChallenge([3; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), probe);
    let sent = transmit(server, now);
    let there: Vec<_> = sent
        .iter()
        .filter(|datagram| datagram.meta.dst == stranger())
        .collect();
    assert_eq!(there.len(), 1, "{} datagrams", sent.len());
    assert_eq!(there[0].meta.path, PathId(1));
    assert_eq!(
        path_frames(server, &there[0].data),
        [PathFrame::Response([3; 8])]
    );
    assert!(there[0].data.len() >= 1200, "{}", there[0].data.len());
    assert_eq!(server.remote_address(), client_addr());
}

#[test]
fn a_probe_under_a_new_connection_id_is_answered_with_an_unused_peer_id_or_not_at_all() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let in_use = pair.server.conn().remote_cid();
    let probe = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::PathChallenge([3; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), probe.clone());
    let sent = transmit(server, now);
    let answer = dcids_to(&sent, stranger());
    assert_eq!(answer.len(), 1, "{answer:?}");
    assert!(
        !answer.contains(&in_use),
        "one ID per destination address, as RFC 9000 requires"
    );
    assert_eq!(server.remote_address(), client_addr());
    let mut pair = settled(&Setup::default());
    let server = pair.server.conn_mut();
    server.sources.cids.peer = PeerCids::new(in_use, 2);
    deliver(server, now, stranger(), probe);
    let sent = transmit(server, now);
    assert!(
        dcids_to(&sent, stranger()).is_empty(),
        "no unused ID to answer with"
    );
}

#[test]
fn a_reset_from_the_alternate_paths_address_ending_in_its_token_is_detected_and_routed() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let probe = client_packet(
        &pair,
        10,
        Some(spare_server_id(&pair)),
        None,
        &[Frame::PathChallenge([3; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), probe);
    let alt_id = *dcids_to(&transmit(server, now), stranger())
        .first()
        .expect("an answer on the alternate path");
    let token = server
        .sources
        .cids
        .peer
        .ids()
        .into_iter()
        .find_map(|(_, cid, token)| token.filter(|_| cid == alt_id))
        .expect("the token of the alternate path's ID");
    let mut reset = vec![0x5f; 30];
    reset.extend_from_slice(&token.0);
    let events = endpoint_events(server);
    deliver(server, now, client_addr(), reset.clone());
    assert!(!was_reset(server), "not from the current path's address");
    deliver(server, now, stranger(), reset);
    assert!(
        was_reset(server),
        "every token in use counts from its own address, as RFC 9000 requires"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::PeerResetTokens {
                alternate: Some(entry),
                ..
            } if *entry == (stranger(), token)
        )),
        "{events:?}"
    );
}

#[test]
fn after_a_rebinding_a_reset_from_the_previous_address_ending_in_the_shared_token_is_detected() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let token = ResetToken([8; 16]);
    let frames = [Frame::NewConnectionId {
        seq: VarInt::from_u32(2),
        retire_prior_to: VarInt::from_u32(2),
        cid: ConnectionId::new(&[8; 8]).unwrap(),
        reset_token: token,
    }];
    let tokened = client_packet(&pair, 10, None, None, &frames);
    let rebound = from_client(&pair, 11, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), tokened);
    deliver(server, now, rebound_port(), rebound);
    assert_eq!(server.remote_address(), rebound_port());
    assert!(
        !dcids_to(&transmit(server, now), client_addr()).is_empty(),
        "a challenge to the previous address under the shared ID"
    );
    let mut reset = vec![0x5f; 30];
    reset.extend_from_slice(&token.0);
    deliver(server, now, client_addr(), reset);
    assert!(
        was_reset(server),
        "the previous path shares the ID in use and so its token"
    );
}

#[test]
fn a_server_does_not_move_to_a_blocklisted_source_port() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let blocked = rebound_port();
    let blocklist = SrcPortBlocklist::new(1024, [blocked.port()]);
    pair.server
        .endpoint
        .set_src_port_blocklist(Some(Arc::new(blocklist)));
    assert!(pair.handshake(epoch + LIMIT), "no handshake");
    let quiet = pair.now + Duration::from_millis(500);
    pair.run(quiet);
    let now = pair.now;
    let padding = Frame::Padding { len: 1200 };
    let rebound = from_client(&pair, 10, &[Frame::Ping, padding]);
    let probe = from_client(&pair, 11, &[Frame::PathChallenge([7; 8]), padding]);
    let moved = from_client(&pair, 12, &[Frame::Ping, padding]);
    let server = pair.server.conn_mut();
    for datagram in [rebound, probe] {
        let summary = deliver(server, now, blocked, datagram);
        assert_eq!((summary.packets, summary.dropped), (0, 1));
    }
    assert_eq!(server.remote_address(), client_addr());
    assert!(
        dcids_to(&transmit(server, now), blocked).is_empty(),
        "nothing goes to the blocked port"
    );
    let elsewhere = SocketAddr::new(client_addr().ip(), 50_002);
    deliver(server, now, elsewhere, moved);
    assert_eq!(
        server.remote_address(),
        elsewhere,
        "a port the list does not block"
    );
}

#[test]
fn a_server_checks_a_move_against_the_blocklist_posted_last() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let first = SrcPortBlocklist::new(1024, [rebound_port().port()]);
    pair.server
        .endpoint
        .set_src_port_blocklist(Some(Arc::new(first)));
    assert!(pair.handshake(epoch + LIMIT), "no handshake");
    let quiet = pair.now + Duration::from_millis(500);
    pair.run(quiet);
    let later = SocketAddr::new(client_addr().ip(), 50_002);
    let second = SrcPortBlocklist::new(1024, [later.port()]);
    pair.server
        .endpoint
        .set_src_port_blocklist(Some(Arc::new(second)));
    let now = pair.now;
    let padding = Frame::Padding { len: 1200 };
    let to_later = from_client(&pair, 10, &[Frame::Ping, padding]);
    let to_rebound = from_client(&pair, 11, &[Frame::Ping, padding]);
    let server = pair.server.conn_mut();
    let summary = deliver(server, now, later, to_later);
    assert_eq!(
        (summary.packets, summary.dropped),
        (0, 1),
        "the list posted after the accept blocks the port"
    );
    assert_eq!(server.remote_address(), client_addr());
    deliver(server, now, rebound_port(), to_rebound);
    assert_eq!(
        server.remote_address(),
        rebound_port(),
        "the list in force at the accept no longer applies"
    );
}

#[test]
fn datagrams_refused_a_move_for_their_source_port_are_counted() {
    let mut pair = settled(&Setup::default());
    let ports = [rebound_port().port(), client_addr().port()];
    pair.server
        .endpoint
        .set_src_port_blocklist(Some(Arc::new(SrcPortBlocklist::new(1024, ports))));
    let now = pair.now;
    let padding = Frame::Padding { len: 1200 };
    let rebound = from_client(&pair, 10, &[Frame::Ping, padding]);
    let probe = from_client(&pair, 11, &[Frame::PathChallenge([7; 8]), padding]);
    let current = from_client(&pair, 12, &[Frame::Ping, padding]);
    let server = pair.server.conn_mut();
    for datagram in [rebound, probe] {
        deliver(server, now, rebound_port(), datagram);
    }
    let summary = deliver(server, now, client_addr(), current);
    assert_eq!(summary.packets, 1, "the current address is not checked");
    assert_eq!(
        pair.server.endpoint.src_port_drops().get(),
        2,
        "the two from the new address"
    );
}

#[test]
fn after_a_migration_the_previous_address_is_challenged_on_its_own_path() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let sent = transmit(server, now);
    let old: Vec<_> = sent
        .iter()
        .filter(|datagram| datagram.meta.dst == client_addr())
        .collect();
    assert_eq!(old.len(), 1, "{} datagrams", sent.len());
    assert_eq!(old[0].meta.path, PathId(1));
    assert!(matches!(
        path_frames(server, &old[0].data)[..],
        [PathFrame::Challenge(_)]
    ));
    assert!(old[0].data.len() >= 1200, "{}", old[0].data.len());
}

/// Collapses the server's window, then moves the client to `to` and has it answer the server's
/// challenge there; returns the server's window and smoothed RTT before the move, and the pair
/// after it.
fn migrate_after_congestion(to: SocketAddr) -> (u64, Duration, Pair) {
    migrate_after_congestion_in(&Setup::default(), to, |_| {})
}

/// Runs the steps of [`migrate_after_congestion`] for a pair of `setup`, with `before` run on the
/// server just after the collapse.
fn migrate_after_congestion_in(
    setup: &Setup,
    to: SocketAddr,
    before: impl FnOnce(&mut Connection),
) -> (u64, Duration, Pair) {
    migrate_after_congestion_with(setup.pair(), to, before)
}

/// Does what [`migrate_after_congestion_in`] does, on a pair of `config`.
fn migrate_after_congestion_with(
    config: PairConfig,
    to: SocketAddr,
    before: impl FnOnce(&mut Connection),
) -> (u64, Duration, Pair) {
    let mut pair = settled_pair(config);
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    server.cc.on_persistent_congestion();
    before(server);
    let (cwnd, srtt) = (server.cc.cwnd(), server.recovery.rtt().smoothed());
    deliver(server, now, to, moved);
    assert_eq!(
        server.remote_address(),
        to,
        "the server follows the newest packet"
    );
    let sent = transmit(server, now);
    let data = challenge_to(server, &sent, to).expect("a challenge to the new address");
    assert!(
        events(server).is_empty(),
        "nothing is reported before validation"
    );
    let response = from_client(
        &pair,
        11,
        &[Frame::PathResponse(data), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, to, response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: to })]
    );
    (cwnd, srtt, pair)
}

/// Returns the Destination Connection IDs of the datagrams among `sent` that went to `to`.
fn dcids_to(sent: &[SentDatagram], to: SocketAddr) -> BTreeSet<ConnectionId> {
    sent.iter()
        .filter(|datagram| datagram.meta.dst == to)
        .map(|datagram| {
            let header = Header::parse(&datagram.data, 8).unwrap();
            ConnectionId::new(header.dcid()).unwrap()
        })
        .collect()
}

/// Returns a server connection ID the client holds but does not use.
fn spare_server_id(pair: &Pair) -> ConnectionId {
    let client = pair.client.conn();
    let ids = client.sources.cids.peer.ids();
    ids.into_iter()
        .map(|(_, cid, _)| cid)
        .find(|cid| *cid != client.remote_cid())
        .expect("a spare server ID")
}

#[test]
fn a_move_under_a_new_connection_id_gets_an_unused_peer_id_and_the_old_one_is_retired() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let old_id = pair.server.conn().remote_cid();
    let moved = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let sent = transmit(server, now);
    let to_new = dcids_to(&sent, stranger());
    assert_eq!(to_new.len(), 1, "{to_new:?}");
    let new_id = *to_new.first().unwrap();
    assert_ne!(
        new_id, old_id,
        "one ID per destination address, as RFC 9000 requires"
    );
    assert_eq!(
        dcids_to(&sent, client_addr()),
        BTreeSet::from([old_id]),
        "the old path's challenge"
    );
    let data = challenge_to(server, &sent, stranger()).expect("a challenge");
    let response = client_packet(
        &pair,
        11,
        new_dcid,
        None,
        &[Frame::PathResponse(data), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );
    let sent = sent_frames(server);
    assert!(sent.iter().all(|(dcid, _)| *dcid == new_id), "{sent:?}");
    assert!(
        sent.iter()
            .flat_map(|(_, frames)| frames)
            .any(|frame| frame == "RetireConnectionId { seq: VarInt(0) }"),
        "{sent:?}"
    );
}

#[test]
fn after_a_rebinding_a_move_under_a_new_connection_id_leaves_the_old_path_its_own_id() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let old_id = pair.server.conn().remote_cid();
    let rebound = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let moved = client_packet(
        &pair,
        11,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, rebound_port(), rebound);
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let sent = transmit(server, now);
    let to_new = dcids_to(&sent, stranger());
    assert_eq!(to_new.len(), 1, "{to_new:?}");
    assert_eq!(
        dcids_to(&sent, client_addr()),
        BTreeSet::from([old_id]),
        "the validated old path keeps its ID, and RFC 9000 forbids reusing it for the new one"
    );
    assert!(!to_new.contains(&old_id));
}

#[test]
fn a_failed_move_under_a_new_connection_id_returns_to_the_old_id_and_retires_the_new_one() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let old_id = pair.server.conn().remote_cid();
    let moved = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let new_id = *dcids_to(&transmit(server, now), stranger())
        .first()
        .expect("a datagram to the new address");
    let limit = now + LIMIT;
    let mut at = now;
    while server.remote_address() == stranger() {
        at = server.next_deadline().expect("a deadline");
        assert!(at <= limit, "validation never failed");
        server.on_deadline(at);
        if server.remote_address() == stranger() {
            transmit(server, at);
        }
    }
    assert_eq!(server.remote_cid(), old_id);
    assert_ne!(new_id, old_id);
    let datagrams = transmit(server, at);
    let sent = frames_of(server, &datagrams);
    assert!(sent.iter().all(|(dcid, _)| *dcid == old_id), "{sent:?}");
    assert!(
        sent.iter()
            .flat_map(|(_, frames)| frames)
            .any(|frame| frame == "RetireConnectionId { seq: VarInt(1) }"),
        "{sent:?}"
    );
}

#[test]
fn an_alternate_path_whose_own_id_the_peer_retires_takes_the_next_fresh_one() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let old_id = pair.server.conn().remote_cid();
    let moved = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    // Retire Prior To 1 retires the ID the server used before the move, now the old path's.
    let retire = client_packet(
        &pair,
        11,
        new_dcid,
        None,
        &[Frame::NewConnectionId {
            seq: VarInt::from_u32(2),
            retire_prior_to: VarInt::from_u32(1),
            cid: ConnectionId::new(&[2; 8]).unwrap(),
            reset_token: ResetToken([2; 16]),
        }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let in_use = server.remote_cid();
    deliver(server, now, stranger(), retire);
    assert_eq!(server.remote_address(), stranger());
    assert_eq!(server.remote_cid(), in_use);
    assert_ne!(in_use, old_id);
    let sent = transmit(server, now);
    assert_eq!(
        dcids_to(&sent, client_addr()),
        BTreeSet::from([ConnectionId::new(&[2; 8]).unwrap()]),
        "the old path is still challenged, under neither the retired ID nor the one in use"
    );
}

#[test]
fn a_move_under_a_new_connection_id_waits_until_the_peer_provides_an_unused_one() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let server = pair.server.conn_mut();
    let in_use = server.remote_cid();
    // The server holds only the client ID it uses.
    server.sources.cids.peer = PeerCids::new(in_use, 2);
    let moved = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), client_addr());
    let sent = transmit(server, now);
    assert!(dcids_to(&sent, stranger()).is_empty());
    let spare = ConnectionId::new(&[7; 8]).unwrap();
    let provided = client_packet(
        &pair,
        11,
        None,
        None,
        &[Frame::NewConnectionId {
            seq: VarInt::from_u32(1),
            retire_prior_to: VarInt::ZERO,
            cid: spare,
            reset_token: ResetToken([7; 16]),
        }],
    );
    let moved = client_packet(
        &pair,
        12,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), provided);
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let sent = transmit(server, now);
    assert_eq!(dcids_to(&sent, stranger()), BTreeSet::from([spare]));
    assert_eq!(dcids_to(&sent, client_addr()), BTreeSet::from([in_use]));
}

/// Returns a pair whose client uses zero-length connection IDs, past the handshake and the exchange
/// of the server's IDs.
fn settled_with_zero_length_client_ids() -> Pair {
    let mut config = Setup::default().pair();
    config.client_endpoint = Some(
        EndpointConfig::builder([7; 32])
            .local_cid_len(0)
            .build()
            .unwrap(),
    );
    let (_, mut pair) = handshake(config);
    let quiet = pair.now + Duration::from_millis(500);
    pair.run(quiet);
    pair
}

#[test]
fn a_probe_under_a_new_server_id_from_a_client_with_zero_length_ids_is_answered() {
    let mut pair = settled_with_zero_length_client_ids();
    let now = pair.now;
    let probe = client_packet(
        &pair,
        10,
        Some(spare_server_id(&pair)),
        None,
        &[Frame::PathChallenge([3; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), probe);
    let sent = transmit(server, now);
    // The answer opens only with the zero-length ID in its header.
    let answers: Vec<_> = sent
        .iter()
        .filter(|datagram| datagram.meta.dst == stranger())
        .flat_map(|datagram| path_frames(server, &datagram.data))
        .collect();
    assert_eq!(
        answers,
        [PathFrame::Response([3; 8])],
        "the probe is answered there, as RFC 9000 requires, under the shared zero-length ID"
    );
    assert_eq!(server.remote_address(), client_addr());
}

#[test]
fn a_client_with_zero_length_ids_that_moves_under_a_new_server_id_is_followed_and_validated() {
    let mut pair = settled_with_zero_length_client_ids();
    let now = pair.now;
    let new_dcid = Some(spare_server_id(&pair));
    let moved = client_packet(
        &pair,
        10,
        new_dcid,
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(
        server.remote_address(),
        stranger(),
        "the server follows the newest packet"
    );
    let sent = transmit(server, now);
    let data = challenge_to(server, &sent, stranger()).expect("a challenge to the new address");
    assert!(
        challenge_to(server, &sent, client_addr()).is_some(),
        "and one to the validated old address, as RFC 9000 requires"
    );
    let response = client_packet(
        &pair,
        11,
        new_dcid,
        None,
        &[Frame::PathResponse(data), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );
}

/// Returns the client's address after a second NAT rebinding.
fn third_address() -> SocketAddr {
    SocketAddr::new(stranger().ip(), 50_002)
}

/// Leaves the server of `pair` without a client ID to send with on either path: the client probes
/// under a spare server ID, which gives the alternate path the client's ID 1, then probes from a
/// third address under the ID in use, which replaces that path and retires ID 1, then repeats
/// ID 1's NEW_CONNECTION_ID with Retire Prior To 1, which retires ID 0 in use.
fn leave_the_server_waiting(pair: &mut Pair) {
    let now = pair.now;
    let probe = client_packet(
        pair,
        10,
        Some(spare_server_id(pair)),
        None,
        &[Frame::PathChallenge([1; 8]), Frame::Padding { len: 1200 }],
    );
    let other_probe = from_client(
        pair,
        11,
        &[Frame::PathChallenge([2; 8]), Frame::Padding { len: 1200 }],
    );
    let (seq, id, token) = pair.server.conn().sources.cids.peer.ids()[1];
    assert_eq!(seq, 1);
    let repeat = client_packet(
        pair,
        12,
        None,
        None,
        &[Frame::NewConnectionId {
            seq: VarInt::from_u32(1),
            retire_prior_to: VarInt::from_u32(1),
            cid: id,
            reset_token: token.unwrap(),
        }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), probe);
    deliver(server, now, third_address(), other_probe);
    deliver(server, now, client_addr(), repeat);
}

#[test]
fn a_repeat_that_retires_every_usable_id_makes_the_server_wait_for_the_next_one() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    leave_the_server_waiting(&mut pair);
    let server = pair.server.conn_mut();
    let inconsistent = server.stats().tx_inconsistent;
    assert!(
        transmit(server, now).is_empty(),
        "no ID to send with on either path"
    );
    assert_eq!(
        server.stats().tx_inconsistent,
        inconsistent,
        "and no packet tried"
    );
    let closed = events(server)
        .iter()
        .any(|event| matches!(event, ConnEvent::Closed { .. }));
    assert!(!closed, "not a connection error");
    // The next NEW_CONNECTION_ID gives the current path an ID, and the pending retirements go out.
    let fresh = ConnectionId::new(&[9; 8]).unwrap();
    let next = client_packet(
        &pair,
        13,
        None,
        None,
        &[Frame::NewConnectionId {
            seq: VarInt::from_u32(2),
            retire_prior_to: VarInt::from_u32(1),
            cid: fresh,
            reset_token: ResetToken([9; 16]),
        }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), next);
    let sent = transmit(server, now);
    assert_eq!(dcids_to(&sent, client_addr()), BTreeSet::from([fresh]));
    assert!(
        dcids_to(&sent, third_address()).is_empty(),
        "the third address waits for an ID of its own, as RFC 9000 requires"
    );
    let frames = frames_of(server, &sent);
    for seq in [0, 1] {
        let retire = format!("RetireConnectionId {{ seq: VarInt({seq}) }}");
        assert!(
            frames.iter().flat_map(|(_, f)| f).any(|f| *f == retire),
            "{retire}: {frames:?}"
        );
    }
}

#[test]
fn a_return_to_an_address_waiting_for_an_id_does_not_take_the_other_addresss_id() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let rebound = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let (_, spare, token) = pair.server.conn().sources.cids.peer.ids()[1];
    // Retire Prior To 1 retires ID 0, which both addresses shared: the new address takes ID 1
    // and the previous one waits.
    let retire = from_client(
        &pair,
        11,
        &[Frame::NewConnectionId {
            seq: VarInt::from_u32(1),
            retire_prior_to: VarInt::from_u32(1),
            cid: spare,
            reset_token: token.unwrap(),
        }],
    );
    let back = from_client(&pair, 12, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, rebound_port(), rebound);
    deliver(server, now, rebound_port(), retire);
    let sent = transmit(server, now);
    assert_eq!(dcids_to(&sent, rebound_port()), BTreeSet::from([spare]));
    assert!(dcids_to(&sent, client_addr()).is_empty());
    deliver(server, now, client_addr(), back);
    assert_eq!(server.remote_address(), client_addr());
    server.ping();
    assert!(
        dcids_to(&transmit(server, now), client_addr()).is_empty(),
        "ID 1 went to the other address, and RFC 9000 forbids reusing it for this one"
    );
}

/// Returns NEW_CONNECTION_ID frames of which the first three each retire every ID before them,
/// leaving the server IDs 4 and 5 and four retirements the client has not acknowledged: as many as
/// twice the active_connection_id_limit of 2.
fn four_retirements() -> Vec<Frame<'static>> {
    [(2u8, 2u8), (3, 3), (4, 4), (5, 4)]
        .into_iter()
        .map(|(seq, retire_prior_to)| Frame::NewConnectionId {
            seq: VarInt::from_u32(seq.into()),
            retire_prior_to: VarInt::from_u32(retire_prior_to.into()),
            cid: ConnectionId::new(&[seq; 8]).unwrap(),
            reset_token: ResetToken([seq; 16]),
        })
        .collect()
}

#[test]
fn a_path_change_that_retires_past_the_bound_closes_the_connection() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let issued = client_packet(&pair, 10, None, None, &four_retirements());
    // A probe under a spare server ID gives the alternate path ID 5, and a probe from a third
    // address under the ID in use replaces that path, which retires ID 5: a fifth retirement.
    let probe = client_packet(
        &pair,
        11,
        Some(spare_server_id(&pair)),
        None,
        &[Frame::PathChallenge([1; 8]), Frame::Padding { len: 1200 }],
    );
    let other_probe = from_client(
        &pair,
        12,
        &[Frame::PathChallenge([2; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), issued);
    deliver(server, now, stranger(), probe);
    let before = events(server);
    assert!(
        !before
            .iter()
            .any(|event| matches!(event, ConnEvent::Closed { .. })),
        "{before:?}"
    );
    deliver(server, now, third_address(), other_probe);
    let after = events(server);
    assert!(
        after
            .iter()
            .any(transport_close(TransportErrorCode::PROTOCOL_VIOLATION)),
        "every retirement counts: {after:?}"
    );
}

#[test]
fn a_failed_validation_that_retires_past_the_bound_closes_the_connection() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let issued = client_packet(&pair, 10, None, None, &four_retirements());
    // A move under a spare server ID gives the new address ID 5 and leaves ID 4 to the old path.
    let moved = client_packet(
        &pair,
        11,
        Some(spare_server_id(&pair)),
        None,
        &[Frame::Ping, Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), issued);
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    // The challenges go unanswered, so the connection goes back and retires ID 5: a fifth.
    let limit = now + LIMIT;
    while server.remote_address() == stranger() {
        let at = server.next_deadline().expect("a deadline");
        assert!(at <= limit, "validation never failed");
        server.on_deadline(at);
        transmit(server, at);
    }
    let events = events(server);
    assert!(
        events
            .iter()
            .any(transport_close(TransportErrorCode::PROTOCOL_VIOLATION)),
        "every retirement counts: {events:?}"
    );
}

#[test]
fn a_connection_that_closes_while_waiting_for_a_peer_id_drains_without_a_close() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    leave_the_server_waiting(&mut pair);
    let server = pair.server.conn_mut();
    server.close(now, AppCode(VarInt::from_u32(7)), Bytes::new());
    assert!(
        matches!(server.state, State::Draining { .. }),
        "no ID to put in a CONNECTION_CLOSE: {:?}",
        server.state
    );
    assert_eq!(
        server.next_deadline(),
        Some(now + 3 * server.pto_interval())
    );
    assert!(transmit(server, now).is_empty());
    assert!(events(server).contains(&ConnEvent::Closed {
        reason: CloseReason::Application {
            code: AppCode(VarInt::from_u32(7)),
            reason: Bytes::new(),
        },
        initiator: Initiator::Local,
    }));
}

#[test]
fn a_validated_move_that_changed_only_the_port_keeps_the_window_and_the_rtt() {
    let (cwnd, srtt, pair) = migrate_after_congestion(rebound_port());
    let server = pair.server.conn();
    assert_eq!(server.cc.cwnd(), cwnd);
    assert_eq!(server.recovery.rtt().smoothed(), srtt);
}

#[test]
fn a_validated_move_to_a_new_ip_resets_the_window_and_the_rtt() {
    let (cwnd, srtt, pair) = migrate_after_congestion(stranger());
    let server = pair.server.conn();
    let initial = Cc::new(
        server.config.congestion_control(),
        &CcConfig::default(),
        server.mtu,
    )
    .unwrap()
    .cwnd();
    let initial_rtt = TransportConfig::default().initial_rtt();
    assert!(cwnd < initial, "{cwnd} after the collapse");
    assert_ne!(srtt, initial_rtt);
    assert_eq!(server.cc.cwnd(), initial);
    assert_eq!(server.recovery.rtt().smoothed(), initial_rtt);
}

#[test]
fn a_bbr3_controller_rebuilt_on_a_move_to_a_new_ip_is_seeded_and_ready_to_pace_at_once() {
    // A two-datagram initial window, which the handshake's bytes exceed.
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .congestion_control(CongestionControl::Bbr3)
            .pacing(true)
            .initial_window(2)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let rebuilt = || {
        let mut before = 0;
        let (_, _, pair) = migrate_after_congestion_in(&setup, stranger(), |server| {
            before = server.cc.bbr3().rng();
        });
        let cc = &pair.server.conn().cc;
        // C.total_sent survives the move, so the new controller is ready to pace at once; the
        // connection paces from the new path's first RTT sample, as mvfst does from the rebuilt
        // controller's first control update.
        assert!(cc.pacing_ready());
        (before, cc.bbr3().rng())
    };
    let (before, after) = rebuilt();
    assert_ne!(
        after, before,
        "a fresh draw from the connection's generator"
    );
    assert_eq!(
        rebuilt(),
        (before, after),
        "reproducible from the connection's seed"
    );
}

#[test]
fn bbr3_takes_the_pacing_granularity_and_the_build_horizon_at_creation_and_after_a_move() {
    let tick = Duration::from_micros(200);
    let horizon = Duration::from_millis(2);
    let setup = Setup::default().transport(
        TransportConfig::builder()
            .congestion_control(CongestionControl::Bbr3)
            .pacing(true)
            .pacing_granularity(tick)
            .build()
            .unwrap(),
    );
    let mut config = setup.pair();
    config.endpoint = EndpointConfig::builder([7; 32])
        .build_horizon(horizon)
        .build()
        .unwrap();
    config.release_horizon = horizon;
    let mut created = None;
    let (_, _, pair) = migrate_after_congestion_with(config, stranger(), |server| {
        let bbr = server.cc.bbr3();
        // The offload budget: three send quanta plus the pacing rate times the 2 ms horizon.
        let rate = server.cc.pacing_rate(Duration::ZERO).get();
        assert_eq!(
            bbr.offload_budget(),
            3 * bbr.send_quantum() + rate * 2 / 1000
        );
        created = Some(bbr.pacing_inputs());
    });
    assert_eq!(created, Some((tick, horizon)));
    assert_eq!(
        pair.server.conn().cc.bbr3().pacing_inputs(),
        (tick, horizon),
        "the rebuilt controller"
    );
}

#[test]
fn a_validated_move_to_a_new_ip_restarts_the_configured_window_and_the_pacer() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .initial_window(4)
            .min_window(3)
            .pacing(true)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let (cwnd, _, pair) = migrate_after_congestion_in(&setup, stranger(), |server| {
        // The old path's pacer runs a megabyte ahead of now.
        server.pacer.on_paced(server.now, 1 << 20);
    });
    let server = pair.server.conn();
    let mss = u64::from(server.mtu);
    assert_eq!(
        cwnd,
        3 * mss,
        "the configured minimum window after the collapse"
    );
    assert_eq!(server.cc.cwnd(), 4 * mss, "the configured initial window");
    assert_eq!(server.pacer.next_release(pair.now), pair.now);
    // The idle server's last attempt before the move left the old window underused, which does
    // not carry over to the new one.
    assert!(!server.app_limited);
}

#[test]
fn after_the_reset_the_old_paths_acknowledgments_and_losses_leave_the_new_window_alone() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let server = pair.server.conn_mut();
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    let (mut data, mut finished) = (Bytes::from(pattern(1 << 16)), false);
    push(server, id, &mut data, &mut finished);
    let first_old = server.recovery.space(Space::Data).next_pn();
    let old = transmit(server, now);
    assert!(old.len() > 4, "{} datagrams on the old path", old.len());

    let moved = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let sent = transmit(server, now);
    let challenge =
        challenge_to(server, &sent, stranger()).expect("a challenge to the new address");
    let response = from_client(
        &pair,
        11,
        &[Frame::PathResponse(challenge), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );
    let first_new = server.recovery.space(Space::Data).next_pn();
    let new = transmit(server, now);
    let last_new = server.recovery.space(Space::Data).next_pn() - 1;
    let fresh = server.cc.cwnd();
    let new_bytes: u64 = new.iter().map(|datagram| datagram.data.len() as u64).sum();

    // As RFC 9000 requires, an acknowledgment of the old path's first packets alone does not grow
    // the new window.
    let ack = client_packet(&pair, 12, None, Some(first_old..=first_old + 2), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(10), stranger(), ack);
    assert_eq!(server.cc.cwnd(), fresh);

    // Once the client acknowledges the new packets, the rest of the old flight is declared lost,
    // which is not a congestion event on the new path: its window grows in slow start by the new
    // packets alone.
    let lost = server.stats().lost_packets;
    let ack = client_packet(&pair, 13, None, Some(first_new..=last_new), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(20), stranger(), ack);
    assert!(server.stats().lost_packets > lost, "the old flight is lost");
    assert_eq!(server.cc.ssthresh(), u64::MAX);
    assert_eq!(server.cc.cwnd(), fresh + new_bytes);
}

#[test]
fn after_the_reset_an_acknowledgment_of_a_packet_sent_on_the_old_path_gives_no_rtt_sample() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let server = pair.server.conn_mut();
    server.ping();
    let old = transmit(server, now);
    assert!(
        old.iter()
            .all(|datagram| datagram.meta.dst == client_addr())
    );
    let old_pn = server.recovery.space(Space::Data).next_pn() - 1;
    let moved = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let sent = transmit(server, now);
    let data = challenge_to(server, &sent, stranger()).expect("a challenge to the new address");
    let response = from_client(
        &pair,
        11,
        &[Frame::PathResponse(data), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    let initial_rtt = TransportConfig::default().initial_rtt();
    assert_eq!(server.recovery.rtt().smoothed(), initial_rtt, "reset");
    let ack = client_packet(&pair, 12, None, Some(old_pn..=old_pn), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(50), stranger(), ack);
    assert_eq!(server.recovery.rtt().smoothed(), initial_rtt);
}

/// Returns the stream byte ranges of the STREAM frames among `sent` that went to `to`, in order.
fn stream_data_to(conn: &Connection, sent: &[SentDatagram], to: SocketAddr) -> Vec<Range<u64>> {
    sent.iter()
        .filter(|datagram| datagram.meta.dst == to)
        .flat_map(|datagram| open_own_one_rtt(conn, &datagram.data))
        .flat_map(|plaintext| {
            Frames::new(&plaintext)
                .filter_map(|frame| match frame.unwrap() {
                    Frame::Stream { offset, data, .. } => {
                        let start = offset.into_inner();
                        Some(start..start + data.len() as u64)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn after_the_reset_packets_still_in_flight_on_the_old_path_do_not_hold_back_the_new_window() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let server = pair.server.conn_mut();
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    let (mut data, mut finished) = (Bytes::from(pattern(1 << 16)), false);
    push(server, id, &mut data, &mut finished);
    assert!(finished, "the stream stages every byte");
    let old = transmit(server, now);
    let old_data = stream_data_to(server, &old, client_addr());
    let old_end = old_data.last().expect("stream data on the old path").end;
    let window = server.cc.cwnd();
    assert!(
        server.recovery.bytes_in_flight() >= window,
        "the old path's window is full"
    );

    let moved = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let sent = transmit(server, now);
    assert!(
        stream_data_to(server, &sent, stranger()).is_empty(),
        "no data goes before validation while the window is full"
    );
    let challenge =
        challenge_to(server, &sent, stranger()).expect("a challenge to the new address");
    let response = from_client(
        &pair,
        11,
        &[Frame::PathResponse(challenge), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );

    // As RFC 9000 requires, the old path's unacknowledged flight does not count against the new
    // path's window.
    let first_new = server.recovery.space(Space::Data).next_pn();
    let new = transmit(server, now);
    let fresh = server.cc.cwnd();
    let to_new: u64 = new
        .iter()
        .filter(|datagram| datagram.meta.dst == stranger())
        .map(|datagram| datagram.data.len() as u64)
        .sum();
    assert!(
        to_new + u64::from(MIN_DATAGRAM) > fresh && to_new < fresh + u64::from(MIN_DATAGRAM),
        "{to_new} bytes went to the new address under a fresh window of {fresh}"
    );
    let new_data = stream_data_to(server, &new, stranger());
    assert_eq!(new_data.first().map(|range| range.start), Some(old_end));

    // The old flight is still tracked: once the client acknowledges only the new packets, it is
    // declared lost and its data goes again, on the new path.
    let last_new = server.recovery.space(Space::Data).next_pn() - 1;
    let ack = client_packet(&pair, 12, None, Some(first_new..=last_new), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), ack);
    let again = transmit(server, now);
    assert_eq!(
        stream_data_to(server, &again, stranger())
            .first()
            .map(|range| range.start),
        Some(0)
    );
    assert!(again.iter().all(|datagram| datagram.meta.dst == stranger()));
}

#[test]
fn after_the_reset_responses_sent_to_the_old_address_count_neither_in_flight_nor_for_the_rtt() {
    let (_, _, mut pair) = migrate_after_congestion(stranger());
    let now = pair.now;
    let server = pair.server.conn_mut();
    transmit(server, now);
    let in_flight = server.recovery.bytes_in_flight();
    let tracked = server.recovery.space(Space::Data).bytes_in_flight();
    let initial_rtt = TransportConfig::default().initial_rtt();
    assert_eq!(server.recovery.rtt().smoothed(), initial_rtt, "reset");

    // The client probes from its old address, and the server answers there first.
    let probe = from_client(
        &pair,
        12,
        &[Frame::PathChallenge([9; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), probe);
    let response_pn = server.recovery.space(Space::Data).next_pn();
    let sent = transmit(server, now);
    assert_eq!(sent[0].meta.dst, client_addr());
    assert_eq!(
        path_frames(server, &sent[0].data),
        [PathFrame::Response([9; 8])]
    );
    let size = sent[0].data.len() as u64;
    assert!(size >= u64::from(MIN_DATAGRAM), "{size}");
    // It goes on the old path, so the new path's window and RTT estimate do not count it, as
    // RFC 9000 requires, though loss detection tracks it.
    assert_eq!(server.recovery.bytes_in_flight(), in_flight);
    assert_eq!(
        server.recovery.space(Space::Data).bytes_in_flight(),
        tracked + size
    );
    let ack = client_packet(&pair, 13, None, Some(response_pn..=response_pn), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(5), stranger(), ack);
    assert_eq!(server.recovery.rtt().smoothed(), initial_rtt);

    // A second response, never acknowledged, is declared lost once three later packets to the
    // new address are acknowledged, after which both counts of bytes in flight are zero.
    let probe = from_client(
        &pair,
        14,
        &[Frame::PathChallenge([10; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), probe);
    let sent = transmit(server, now);
    assert_eq!(
        path_frames(server, &sent[0].data),
        [PathFrame::Response([10; 8])]
    );
    let first_ping = server.recovery.space(Space::Data).next_pn();
    for _ in 0..3 {
        server.ping();
        transmit(server, now);
    }
    let last_ping = server.recovery.space(Space::Data).next_pn() - 1;
    assert_eq!(last_ping - first_ping, 2, "one packet per ping");
    let ack = client_packet(&pair, 15, None, Some(first_ping..=last_ping), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(10), stranger(), ack);
    assert_eq!(server.recovery.space(Space::Data).bytes_in_flight(), 0);
    assert_eq!(server.recovery.bytes_in_flight(), 0);
}

#[test]
fn after_the_reset_an_acknowledged_response_to_the_old_address_takes_nothing_from_window_growth() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .congestion_control(CongestionControl::NewReno)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let (_, _, mut pair) = migrate_after_congestion_in(&setup, stranger(), |_| {});
    let now = pair.now;
    let server = pair.server.conn_mut();
    transmit(server, now);
    assert_eq!(
        server.recovery.bytes_in_flight(),
        0,
        "nothing on the new path yet"
    );

    // The client probes from its old address, and the server answers there.
    let probe = from_client(
        &pair,
        12,
        &[Frame::PathChallenge([9; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), probe);
    let response_pn = server.recovery.space(Space::Data).next_pn();
    let sent = transmit(server, now);
    assert_eq!(sent[0].meta.dst, client_addr());
    assert_eq!(
        path_frames(server, &sent[0].data),
        [PathFrame::Response([9; 8])]
    );
    assert_eq!(server.recovery.bytes_in_flight(), 0, "an ACK at most");

    // A recovery period on the new path begins after the response went, and a window of new
    // data follows it there.
    let start = now + Duration::from_millis(1);
    server
        .cc
        .on_congestion_event(start, now, CongestionSignal::Loss);
    let window = server.cc.cwnd();
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    let (mut data, mut finished) = (Bytes::from(pattern(1 << 16)), false);
    push(server, id, &mut data, &mut finished);
    let new = transmit(server, now + Duration::from_millis(2));
    let last_new = server.recovery.space(Space::Data).next_pn() - 1;
    let new_bytes: u64 = new.iter().map(|datagram| datagram.data.len() as u64).sum();
    assert_eq!(new_bytes, window, "the new data fills the window exactly");

    // One ACK covers the response, sent within the recovery period, and the new data, sent
    // after it. Only packets on the new path count, so the new data alone grows the window by
    // one datagram.
    let ack = client_packet(&pair, 13, None, Some(response_pn..=last_new), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now + Duration::from_millis(10), stranger(), ack);
    assert_eq!(server.cc.cwnd(), window + u64::from(server.mtu));
}

#[test]
fn after_the_reset_a_response_sent_to_the_old_address_leaves_the_bbr3_controller_alone() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .congestion_control(CongestionControl::Bbr3)
            .pacing(true)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let (_, _, mut pair) = migrate_after_congestion_in(&setup, stranger(), |_| {});
    let now = pair.now;
    let server = pair.server.conn_mut();
    transmit(server, now);
    assert_eq!(
        server.recovery.bytes_in_flight(),
        0,
        "nothing on the new path yet"
    );

    // The client probes from its old address a little later, and the server answers there in a
    // full-size datagram, which is in flight on the old path.
    let later = now + Duration::from_millis(5);
    let probe = from_client(
        &pair,
        12,
        &[Frame::PathChallenge([9; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, later, client_addr(), probe);
    let before = format!("{:?}", server.cc);
    let sent = transmit(server, later);
    let old: Vec<_> = sent
        .iter()
        .filter(|datagram| datagram.meta.dst == client_addr())
        .collect();
    assert_eq!(old.len(), 1, "{} datagrams", sent.len());
    assert_eq!(
        path_frames(server, &old[0].data),
        [PathFrame::Response([9; 8])]
    );
    assert!(old[0].data.len() >= 1200, "{}", old[0].data.len());
    assert_eq!(
        server.recovery.bytes_in_flight(),
        0,
        "nothing went in flight on the new path"
    );
    // RFC 9000 keeps packets sent on the old path out of the new path's congestion control, so
    // the response does not reach the controller, as a send or as a restart from idle.
    assert_eq!(format!("{:?}", server.cc), before);
}

#[test]
fn a_challenge_the_credit_kept_short_is_followed_by_a_full_size_one_once_validated() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let credit = 3 * moved.len();
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let sent = transmit(server, now);
    let to_new: Vec<_> = sent
        .iter()
        .filter(|datagram| datagram.meta.dst == stranger())
        .collect();
    let bytes: usize = to_new.iter().map(|datagram| datagram.data.len()).sum();
    assert!(bytes <= credit, "{bytes} sent for {credit} of credit");
    let data = challenge_to(server, &sent, stranger()).expect("a challenge within the credit");
    let response = from_client(&pair, 11, &[Frame::PathResponse(data)]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );
    let sent = transmit(server, now);
    let full = sent.iter().find(|datagram| {
        datagram.meta.dst == stranger()
            && path_frames(server, &datagram.data)
                .iter()
                .any(|frame| matches!(frame, PathFrame::Challenge(_)))
    });
    let full = full.expect("a second challenge");
    assert!(full.data.len() >= 1200, "{}", full.data.len());
}

#[test]
fn a_full_size_datagram_with_only_a_response_does_not_make_a_short_challenge_full_size() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let sent = transmit(server, now);
    let data = challenge_to(server, &sent, stranger()).expect("a challenge within the credit");
    assert!(
        sent.iter()
            .filter(|datagram| datagram.meta.dst == stranger())
            .all(|datagram| datagram.data.len() < 1200)
    );
    let challenge = from_client(
        &pair,
        11,
        &[Frame::PathChallenge([9; 8]), Frame::Padding { len: 1200 }],
    );
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), challenge);
    let sent = transmit(server, now);
    let answers: Vec<_> = sent
        .iter()
        .map(|datagram| (datagram.data.len(), path_frames(server, &datagram.data)))
        .filter(|(_, frames)| frames.contains(&PathFrame::Response([9; 8])))
        .collect();
    assert!(
        matches!(answers[..], [(len, ref frames)] if len >= 1200 && frames.len() == 1),
        "{answers:?}"
    );
    let response = from_client(&pair, 12, &[Frame::PathResponse(data)]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), response);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::Migrated { remote: stranger() })]
    );
    let sent = transmit(server, now);
    let full = sent.iter().find(|datagram| {
        datagram.meta.dst == stranger()
            && path_frames(server, &datagram.data)
                .iter()
                .any(|frame| matches!(frame, PathFrame::Challenge(_)))
    });
    let full = full.expect("a second challenge");
    assert!(full.data.len() >= 1200, "{}", full.data.len());
}

#[test]
fn an_unanswered_challenge_goes_again_after_a_pto_even_once_acknowledged_three_at_most() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    let first_pn = server.recovery.space(Space::Data).next_pn();
    let pto = server.pto_interval();
    let sent = transmit(server, now);
    let first = challenge_to(server, &sent, stranger()).expect("a challenge");
    let largest = server.recovery.space(Space::Data).next_pn() - 1;
    // The client acknowledges the challenge's packet, and its PATH_RESPONSE is lost.
    let ack = client_packet(&pair, 11, None, Some(first_pn..=largest), &[]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), ack);
    let mut challenges = vec![(now, first)];
    let limit = now + LIMIT;
    while server.remote_address() == stranger() {
        let at = server.next_deadline().expect("a deadline");
        assert!(at <= limit, "validation never failed");
        server.on_deadline(at);
        let sent = transmit(server, at);
        challenges.extend(
            sent.iter()
                .filter(|datagram| datagram.meta.dst == stranger())
                .flat_map(|datagram| path_frames(server, &datagram.data))
                .filter_map(|frame| match frame {
                    PathFrame::Challenge(data) => Some((at, data)),
                    PathFrame::Response(_) => None,
                }),
        );
    }
    assert_eq!(challenges.len(), 3, "{challenges:?}");
    assert!(
        challenges[1].0 <= now + pto,
        "{challenges:?} with a PTO of {pto:?}"
    );
    let data: BTreeSet<_> = challenges.iter().map(|(_, data)| *data).collect();
    assert_eq!(data.len(), 3, "each challenge has its own data");
}

#[test]
fn a_new_address_that_fails_validation_sends_the_connection_back_to_the_validated_one() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let limit = now + LIMIT;
    let mut at = now;
    while server.remote_address() == stranger() {
        transmit(server, at);
        at = server.next_deadline().expect("a deadline");
        assert!(at <= limit, "validation never failed");
        server.on_deadline(at);
    }
    assert_eq!(server.remote_address(), client_addr());
    assert!(server.path.validated);
    assert_eq!(
        events(server),
        [ConnEvent::Path(PathEvent::ValidationFailed {
            remote: stranger()
        })]
    );
}

#[test]
fn a_second_move_before_validation_keeps_the_last_validated_address_to_return_to() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let rebound = from_client(&pair, 10, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let moved = from_client(&pair, 11, &[Frame::Ping, Frame::Padding { len: 1200 }]);
    let server = pair.server.conn_mut();
    deliver(server, now, rebound_port(), rebound);
    transmit(server, now);
    // The client moves on a PTO later, so the old path's challenge times out first, and every
    // challenge goes unanswered.
    let later = now + server.pto_interval();
    deliver(server, later, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    let limit = later + LIMIT;
    let mut at = later;
    while server.remote_address() == stranger() {
        transmit(server, at);
        let Some(next) = server.next_deadline() else {
            break;
        };
        at = next;
        assert!(at <= limit, "validation never failed");
        server.on_deadline(at);
    }
    assert_eq!(
        server.remote_address(),
        client_addr(),
        "back to the last validated address, as RFC 9000 requires"
    );
    assert!(
        events(server).contains(&ConnEvent::Path(PathEvent::ValidationFailed {
            remote: stranger()
        }))
    );
}

#[test]
fn a_reordered_packet_from_the_previous_address_does_not_move_the_connection_back() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let late = from_client(&pair, 5, &[Frame::Ping]);
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    assert_eq!(deliver(server, now, client_addr(), late).packets, 1);
    assert_eq!(server.remote_address(), stranger());
}

#[test]
fn the_connection_follows_the_highest_non_probing_packet_whatever_probes_came_between() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let ping = from_client(&pair, 10, &[Frame::Ping]);
    let probe = from_client(
        &pair,
        30,
        &[Frame::PathChallenge([3; 8]), Frame::Padding { len: 1200 }],
    );
    let moved = from_client(&pair, 20, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), ping);
    deliver(server, now, stranger(), probe);
    assert_eq!(
        server.remote_address(),
        client_addr(),
        "a probe moves nothing"
    );
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
}

#[test]
fn the_newest_packet_from_the_previous_validated_address_moves_the_connection_back_at_once() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let moved = from_client(&pair, 10, &[Frame::Ping]);
    let back = from_client(&pair, 11, &[Frame::Ping]);
    let server = pair.server.conn_mut();
    deliver(server, now, stranger(), moved);
    assert_eq!(server.remote_address(), stranger());
    deliver(server, now, client_addr(), back);
    assert_eq!(server.remote_address(), client_addr());
    assert!(server.path.validated);
    let sent = transmit(server, now);
    assert_eq!(challenge_to(server, &sent, client_addr()), None);
    assert!(
        sent.iter()
            .all(|datagram| datagram.meta.dst == client_addr())
    );
    assert!(events(server).is_empty());
}

#[test]
fn a_transfer_survives_a_nat_rebinding_of_the_client() {
    let mut pair = settled(&Setup::default());
    bulk_both_ways(&mut pair, 1 << 16);
    pair.client.addr = rebound_port();
    bulk_both_ways(&mut pair, 1 << 18);
    assert_eq!(pair.server.conn().remote_address(), rebound_port());
    assert!(
        pair.server.has_event(&ConnEvent::Path(PathEvent::Migrated {
            remote: rebound_port()
        })),
        "{:?}",
        pair.server.events
    );
}

/// Parses a packet's `plaintext` into frames, each with its first byte, which holds a STREAM
/// frame's type bits.
fn typed_frames(plaintext: &[u8]) -> Vec<(u8, Frame<'_>)> {
    let mut out = Vec::new();
    let mut rest = plaintext;
    while let Some(&ty) = rest.first() {
        let frame = Frames::new(rest)
            .next()
            .expect("a frame")
            .expect("a frame it wrote");
        let len = match frame {
            // A STREAM frame ends with its data, whether or not it has a Length field.
            Frame::Stream { data, .. } => data.as_ptr().addr() + data.len() - rest.as_ptr().addr(),
            ref other => other.encoded_len(),
        };
        out.push((ty, frame));
        rest = &rest[len..];
    }
    out
}

#[test]
fn full_packets_end_in_a_stream_frame_without_its_length_and_nothing_follows_one() {
    let mut pair = settled(&Setup::default());
    bulk_both_ways(&mut pair, 1 << 16);
    // After a NAT rebinding the server validates the new path with PATH_CHALLENGE frames among
    // its STREAM frames, in datagrams it pads to 1,200 bytes.
    pair.client.addr = rebound_port();
    bulk_both_ways(&mut pair, 1 << 16);
    let sent_bytes = pattern(1 << 16);
    let mut padded = 0;
    for (side, peer) in [("client", &pair.client), ("server", &pair.server)] {
        let conn = peer.conn();
        let mut full = 0;
        for (_, datagram) in &peer.sent {
            let size = datagram.data.len();
            let path = !path_frames(conn, &datagram.data).is_empty();
            for plaintext in open_own_one_rtt(conn, &datagram.data) {
                let frames = typed_frames(&plaintext);
                for (ty, frame) in &frames {
                    let Frame::Stream { offset, data, .. } = frame else {
                        continue;
                    };
                    // A frame without its length takes the rest of the packet as data, so
                    // anything written after it, PADDING included, would fail this comparison.
                    let at = usize::try_from(offset.into_inner()).unwrap();
                    assert!(
                        *data == &sent_bytes[at..at + data.len()],
                        "{side}: the STREAM frame at {at} carries other bytes than the stream's"
                    );
                    if ty & 0x02 == 0 {
                        assert!(!data.is_empty(), "{side}: no length and no data at {at}");
                        padded += usize::from(path && size == usize::from(MIN_DATAGRAM));
                    }
                }
                // The stream's last bytes may end before the end of the packet.
                let last_stream = frames
                    .iter()
                    .rev()
                    .find(|(_, frame)| matches!(frame, Frame::Stream { .. }));
                if size == usize::from(MIN_DATAGRAM)
                    && let Some((ty, Frame::Stream { fin: false, .. })) = last_stream
                {
                    assert_eq!(
                        ty & 0x02,
                        0,
                        "{side}: a full packet's last STREAM frame has its length"
                    );
                    full += 1;
                }
            }
        }
        assert!(full > 50, "{side}: only {full} full packets");
    }
    assert!(
        padded > 0,
        "no padded datagram holds a STREAM frame without its length"
    );
}

#[test]
fn before_confirmation_packets_from_a_stranger_address_are_dropped() {
    let (epoch, mut pair) = start(Setup::default().pair());
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.conn().has_keys(Space::Handshake)
    }));
    assert!(!pair.server.conn().handshake.confirmed);
    let now = pair.now;
    let frames = [Frame::Ping];
    let from_client =
        Forge::of(pair.client.conn(), Space::Handshake, 50, &frames).seal(pair.client.conn());
    let from_server =
        Forge::of(pair.server.conn(), Space::Handshake, 50, &frames).seal(pair.server.conn());
    let server = pair.server.conn_mut();
    let summary = deliver(server, now, stranger(), from_client.clone());
    assert_eq!((summary.packets, summary.dropped), (0, 1), "server");
    assert_eq!(deliver(server, now, client_addr(), from_client).packets, 1);
    let client = pair.client.conn_mut();
    let summary = deliver(client, now, stranger(), from_server.clone());
    assert_eq!((summary.packets, summary.dropped), (0, 1), "client");
    assert_eq!(deliver(client, now, server_addr(), from_server).packets, 1);
}

#[test]
fn a_client_never_takes_packets_from_another_address_than_the_servers() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let frames = [Frame::Ping];
    let packet = Forge::of(pair.server.conn(), Space::Data, 1000, &frames).seal(pair.server.conn());
    let client = pair.client.conn_mut();
    assert!(client.handshake.confirmed);
    assert_eq!(deliver(client, now, stranger(), packet.clone()).packets, 0);
    assert_eq!(deliver(client, now, server_addr(), packet).packets, 1);
}

fn key_update(policy: KeyUpdatePolicy) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .key_update(policy)
        .build()
        .unwrap()
}

fn generation(conn: &Connection) -> u64 {
    conn.key_phases
        .as_ref()
        .map_or(0, |phases| phases.generation)
}

/// Returns a 1-RTT packet numbered `pn` that `sender` could send with its current write keys, under
/// Key Phase bit `phase`.
fn one_rtt(sender: &Connection, pn: u64, phase: bool) -> Vec<u8> {
    let mut buf = vec![0; 1500];
    let header = HeaderSpec::OneRtt {
        dcid: sender.remote_cid(),
        spin: false,
        key_phase: phase,
    };
    let mut w = PacketWriter::new(&mut buf, header, pn, 4, TAG_LEN).unwrap();
    w.frame(&Frame::Ping).unwrap();
    w.frame(&Frame::Padding { len: 30 }).unwrap();
    let layout = w.finish();
    let keys = &sender.spaces[Space::Data.index()]
        .keys
        .as_ref()
        .unwrap()
        .local;
    let job = SealJob {
        slot: SlotId(0),
        keys,
        pn,
        hdr_len: u16::try_from(layout.hdr_len).unwrap(),
        len: u16::try_from(layout.len).unwrap(),
    };
    InlineSealer.seal(job, &mut buf).unwrap();
    buf.truncate(layout.len);
    buf
}

/// Has `conn` send a PING at `now`; returns its datagrams.
fn ping(conn: &mut Connection, now: Instant) -> Vec<Vec<u8>> {
    conn.ping();
    let mut sink = VecSink::new(1500);
    let limits = TxLimits {
        now,
        max_segments: 16,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: None,
    };
    conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    sink.take()
        .into_iter()
        .map(|datagram| datagram.data)
        .collect()
}

fn closed_by(conn: &mut Connection, code: TransportErrorCode) -> bool {
    events(conn).iter().any(transport_close(code))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

/// Pushes what the stream takes of `data`, then the FIN.
fn push(conn: &mut Connection, id: StreamId, data: &mut Bytes, finished: &mut bool) {
    if *finished {
        return;
    }
    let Ok(mut stream) = conn.stream(id) else {
        return;
    };
    if stream.send(data).is_ok() && data.is_empty() {
        stream.finish().unwrap();
        *finished = true;
    }
}

/// Reads every readable byte into `got`; returns whether a stream finished.
fn pull(conn: &mut Connection, got: &mut Vec<u8>) -> bool {
    let mut finished = false;
    while let Some((id, edge)) = conn.readiness().next() {
        if matches!(
            edge,
            StreamReady::Opened | StreamReady::Readable | StreamReady::Finished
        ) && let Ok(mut stream) = conn.stream(id)
        {
            let bytes: Vec<u8> = stream
                .readable()
                .segments()
                .flat_map(|segment| segment.to_vec())
                .collect();
            stream.consume(bytes.len()).unwrap();
            got.extend(bytes);
        }
        finished |= edge == StreamReady::Finished;
    }
    finished
}

/// Sends `len` bytes each way and runs the pair until both arrive whole.
fn bulk_both_ways(pair: &mut Pair, len: usize) {
    let up = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    let down = pair.server.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    let (mut to_server, mut to_client) = (Bytes::from(pattern(len)), Bytes::from(pattern(len)));
    let (mut up_sent, mut down_sent) = (false, false);
    let (mut at_server, mut at_client) = (Vec::new(), Vec::new());
    let (mut up_done, mut down_done) = (false, false);
    let limit = pair.now + 60 * LIMIT;
    while !(up_done && down_done) {
        push(pair.client.conn_mut(), up, &mut to_server, &mut up_sent);
        push(pair.server.conn_mut(), down, &mut to_client, &mut down_sent);
        pair.step();
        up_done |= pull(pair.server.conn_mut(), &mut at_server);
        down_done |= pull(pair.client.conn_mut(), &mut at_client);
        match pair.next_event() {
            Some(at) if at <= limit => pair.now = pair.now.max(at),
            _ => panic!("the transfer stalled"),
        }
    }
    assert!(at_server == pattern(len), "the upload arrived altered");
    assert!(at_client == pattern(len), "the download arrived altered");
}

/// Runs a bulk transfer each way with the sides' key update policies; returns the pair after
/// it went quiet.
fn bulk_with_updates(client: KeyUpdatePolicy, server: KeyUpdatePolicy) -> Pair {
    let setup = Setup {
        client_transport: key_update(client),
        server_transport: key_update(server),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    bulk_both_ways(&mut pair, 1 << 20);
    let quiet = pair.now + Duration::from_secs(1);
    pair.run(quiet);
    for peer in [&pair.client, &pair.server] {
        assert!(
            !peer
                .events
                .iter()
                .any(|event| matches!(event, ConnEvent::Closed { .. })),
            "{:?}",
            peer.events
        );
    }
    pair
}

#[test]
fn the_client_updates_keys_in_the_middle_of_bulk_data_and_the_server_follows() {
    let pair = bulk_with_updates(KeyUpdatePolicy::Every(200), KeyUpdatePolicy::AtLimit);
    let (client, server) = (
        generation(pair.client.conn()),
        generation(pair.server.conn()),
    );
    assert!(client >= 2, "{client} updates");
    assert_eq!(server, client);
}

#[test]
fn the_server_updates_keys_in_the_middle_of_bulk_data_and_the_client_follows() {
    let pair = bulk_with_updates(KeyUpdatePolicy::AtLimit, KeyUpdatePolicy::Every(200));
    let (client, server) = (
        generation(pair.client.conn()),
        generation(pair.server.conn()),
    );
    assert!(server >= 2, "{server} updates");
    assert_eq!(client, server);
}

#[test]
fn a_key_update_waits_for_an_acknowledgment_in_the_current_phase_then_three_ptos() {
    let setup = Setup {
        client_transport: key_update(KeyUpdatePolicy::Every(1000)),
        ..Setup::default()
    };
    let mut pair = settled(&setup);
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    let set_sealed = |conn: &mut Connection, sealed| {
        conn.key_phases.as_mut().unwrap().sealed = sealed;
    };
    set_sealed(client, 998);
    let mut to_server = ping(client, now);
    assert_eq!(generation(client), 0, "999 sealed");
    to_server.extend(ping(client, now));
    assert_eq!(generation(client), 1, "1,000 sealed");
    set_sealed(client, 998);
    for _ in 0..3 {
        to_server.extend(ping(client, now));
    }
    assert_eq!(
        generation(client),
        1,
        "nothing sent with the new keys is acknowledged"
    );
    for datagram in to_server {
        deliver(server, now, client_addr(), datagram);
    }
    assert_eq!(generation(server), 1, "the server follows");
    for datagram in ping(server, now) {
        deliver(client, now, server_addr(), datagram);
    }
    set_sealed(client, 998);
    for _ in 0..3 {
        ping(client, now);
    }
    assert_eq!(generation(client), 1, "three PTOs after the acknowledgment");
    let later = now + 3 * client.pto_interval();
    ping(client, later);
    assert_eq!(generation(client), 2);
}

#[test]
fn a_version_1_connection_updates_at_0_8_of_the_confidentiality_limit() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let phases = client.key_phases.as_mut().unwrap();
    phases.confidentiality_limit = 100;
    phases.sealed = 78;
    ping(client, now);
    assert_eq!(generation(client), 0);
    ping(client, now);
    assert_eq!(generation(client), 1, "80 packets sealed");
    // Not allowed to update again before an acknowledgment, it closes short of the limit.
    let phases = client.key_phases.as_mut().unwrap();
    phases.confidentiality_limit = 100;
    phases.sealed = 89;
    ping(client, now);
    assert!(closed_by(client, TransportErrorCode::AEAD_LIMIT_REACHED));
}

fn mvfst() -> Setup {
    Setup {
        client_versions: vec![mvfstr_wire::Version::MVFST],
        server_versions: vec![mvfstr_wire::Version::V1, mvfstr_wire::Version::MVFST],
        client_transport: key_update(KeyUpdatePolicy::Every(5)),
        ..Setup::default()
    }
}

#[test]
fn an_mvfst_connection_never_updates_first_and_closes_at_the_limit_instead() {
    let mut pair = settled(&mvfst());
    let now = pair.now;
    let client = pair.client.conn_mut();
    assert_eq!(client.version, mvfstr_wire::Version::MVFST);
    for _ in 0..20 {
        ping(client, now);
    }
    assert_eq!(generation(client), 0);
    let phases = client.key_phases.as_mut().unwrap();
    phases.confidentiality_limit = 100;
    phases.sealed = 79;
    ping(client, now);
    assert!(closed_by(client, TransportErrorCode::AEAD_LIMIT_REACHED));
}

#[test]
fn an_mvfst_connection_follows_the_peers_update() {
    let mut pair = settled(&mvfst());
    let now = pair.now;
    let client = pair.client.conn.as_mut().unwrap();
    client.initiate_key_update();
    let datagrams = ping(client, now);
    let server = pair.server.conn_mut();
    for datagram in datagrams {
        deliver(server, now, client_addr(), datagram);
    }
    assert_eq!(generation(server), 1);
}

#[test]
fn the_previous_read_keys_stay_for_three_ptos_after_the_first_packet_under_the_new_ones() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    let next = server.recovery.space(Space::Data).next_pn();
    let (old_a, old_b) = (
        one_rtt(server, next + 10, false),
        one_rtt(server, next + 11, false),
    );
    client.initiate_key_update();
    let pn = client.recovery.space(Space::Data).next_pn() + 10;
    deliver(server, now, client_addr(), one_rtt(client, pn, true));
    assert_eq!(generation(server), 1);
    deliver(client, now, server_addr(), one_rtt(server, next + 20, true));
    assert_eq!(
        deliver(client, now, server_addr(), old_a).packets,
        1,
        "a delayed packet under the old keys"
    );
    let later = now + 3 * client.pto_interval();
    assert_eq!(client.next_deadline().map(|at| at <= later), Some(true));
    client.on_deadline(later);
    assert!(!client.key_phases.as_ref().unwrap().has_previous());
    assert_eq!(deliver(client, later, server_addr(), old_b).packets, 0);
}

#[test]
fn a_newer_key_phase_below_the_largest_packet_number_is_a_key_update_error() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    let next = client.recovery.space(Space::Data).next_pn();
    assert_eq!(
        deliver(
            server,
            now,
            client_addr(),
            one_rtt(client, next + 100, false)
        )
        .packets,
        1
    );
    client.initiate_key_update();
    deliver(server, now, client_addr(), one_rtt(client, next + 50, true));
    assert!(closed_by(server, TransportErrorCode::KEY_UPDATE_ERROR));
}

#[test]
fn the_previous_keys_open_only_packets_below_every_one_under_the_current_keys() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    let next = client.recovery.space(Space::Data).next_pn();
    let old = one_rtt(client, next + 90, false);
    client.initiate_key_update();
    for pn in [next + 100, next + 80] {
        let summary = deliver(server, now, client_addr(), one_rtt(client, pn, true));
        assert_eq!(summary.packets, 1, "{pn} under the new keys");
    }
    assert_eq!(generation(server), 1);
    // 90 is above a packet number of the current phase, so under RFC 9001 it needs the next keys.
    assert_eq!(deliver(server, now, client_addr(), old).packets, 0);
}

#[test]
fn packets_failing_authentication_past_the_integrity_limit_close_the_connection() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    server.integrity_limit = 2;
    let next = client.recovery.space(Space::Data).next_pn();
    let mut forged = one_rtt(client, next, false);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    for _ in 0..2 {
        deliver(server, now, client_addr(), forged.clone());
    }
    assert!(!closed_by(server, TransportErrorCode::AEAD_LIMIT_REACHED));
    deliver(server, now, client_addr(), forged);
    assert!(closed_by(server, TransportErrorCode::AEAD_LIMIT_REACHED));
}

#[test]
fn past_the_integrity_limit_no_packet_is_opened_or_answered() {
    let mut pair = settled(&Setup::default());
    let now = pair.now;
    let (client, server) = (
        pair.client.conn.as_mut().unwrap(),
        pair.server.conn.as_mut().unwrap(),
    );
    server.integrity_limit = 0;
    let next = client.recovery.space(Space::Data).next_pn();
    let mut forged = one_rtt(client, next, false);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    deliver(server, now, client_addr(), forged);
    assert!(closed_by(server, TransportErrorCode::AEAD_LIMIT_REACHED));
    assert_eq!(transmit(server, now).len(), 1, "the CLOSE");
    client.initiate_key_update();
    let update = one_rtt(client, next + 1, true);
    assert_eq!(deliver(server, now, client_addr(), update).packets, 0);
    assert_eq!(generation(server), 0);
    assert!(
        transmit(server, now).is_empty(),
        "only stateless resets answer packets past the integrity limit, as RFC 9001 requires"
    );
}
