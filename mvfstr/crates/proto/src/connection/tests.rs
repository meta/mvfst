/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection tests over the pair harness of [`crate::testing`].

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_crypto::PacketKeys;
use mvfstr_crypto::TAG_LEN;
use mvfstr_crypto::unprotect_header;
use mvfstr_tls::Level;
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
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use rustls::pki_types::ServerName;

use super::ConnError;
use super::Connection;
use super::Handshake;
use super::PacketSpace;
use super::PeerParams;
use super::stream_tests::App;
use super::stream_tests::ORDER;
use super::stream_tests::pattern;
use super::stream_tests::run_apps;
use crate::AckPolicy;
use crate::AlpnPolicy;
use crate::AppCode;
use crate::CloseReason;
use crate::CongestionControl;
use crate::ConnEvent;
use crate::ConnKey;
use crate::ConnOptions;
use crate::DatagramSize;
use crate::DropReason;
use crate::Ecn;
use crate::Endpoint;
use crate::EndpointEvent;
use crate::Initiator;
use crate::InlineSealer;
use crate::Inputs;
use crate::PathEvent;
use crate::Prioritizer;
use crate::RecvSummary;
use crate::Route;
use crate::RxDatagram;
use crate::RxMeta;
use crate::SealError;
use crate::SealJob;
use crate::Sealer;
use crate::SendOrder;
use crate::ServerConfig;
use crate::SlotId;
use crate::Stop;
use crate::StreamReady;
use crate::TransportConfig;
use crate::TxLimits;
use crate::TxReport;
use crate::TxSeqRange;
use crate::recovery::RecoveryConfig;
use crate::recovery::Space;
use crate::recovery::sent::SentFlags;
use crate::recovery::sent::SentPackets;
use crate::recovery::test_epoch;
use crate::sources::AckSource;
use crate::sources::CryptoSource;
use crate::streams::guard::List;
use crate::streams::recv_buf::PAGE_SIZE;
use crate::testing::LinkConfig;
use crate::testing::Loss;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::Peer;
use crate::testing::TestRng;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;
use crate::testing::fixtures::unix_now;

/// Every handshake here completes well within this, losses included.
pub(super) const LIMIT: Duration = Duration::from_secs(10);

/// Returns an ACK policy that acknowledges two ack-eliciting packets at once, and a lone one
/// max_ack_delay less 1 ms after it arrived, whatever the RTT.
pub(super) fn every_other_packet() -> AckPolicy {
    AckPolicy {
        before_init: 2,
        after_init: 2,
        rtt_timer: false,
        ..AckPolicy::default()
    }
}

pub(super) fn start(config: PairConfig) -> (Instant, Pair) {
    let epoch = test_epoch();
    (epoch, Pair::new(epoch, unix_now(), config))
}

pub(super) fn handshake(config: PairConfig) -> (Instant, Pair) {
    let (epoch, mut pair) = start(config);
    assert!(
        pair.handshake(epoch + LIMIT),
        "no handshake: client {:?}, server {:?}",
        pair.client.events,
        pair.server.events
    );
    (epoch, pair)
}

/// Returns the types of the packets coalesced in a datagram.
pub(super) fn packet_types(mut datagram: &[u8]) -> Vec<PacketType> {
    let mut types = Vec::new();
    while !datagram.is_empty() {
        let Ok(Header::Protected(header)) = Header::parse(datagram, 8) else {
            panic!("an unparsable packet");
        };
        types.push(header.ty());
        datagram = &datagram[header.packet_len()..];
    }
    types
}

/// Splits a datagram into its coalesced packets.
fn packets(datagram: &[u8]) -> Vec<(PacketType, Vec<u8>)> {
    packets_to(datagram, 8)
}

/// Splits a datagram into its coalesced packets, whose short headers carry a Destination
/// Connection ID of `dcid_len` bytes.
fn packets_to(mut datagram: &[u8], dcid_len: usize) -> Vec<(PacketType, Vec<u8>)> {
    let mut out = Vec::new();
    while let Ok(Header::Protected(header)) = Header::parse(datagram, dcid_len) {
        let (packet, rest) = datagram.split_at(header.packet_len());
        out.push((header.ty(), packet.to_vec()));
        datagram = rest;
    }
    out
}

fn closed(reason: CloseReason, initiator: Initiator) -> ConnEvent {
    ConnEvent::Closed { reason, initiator }
}

pub(super) fn limits(now: Instant) -> TxLimits {
    TxLimits {
        now,
        max_segments: 16,
        max_datagram: 1500,
        max_bytes: u32::MAX,
        epoch: None,
    }
}

pub(super) fn client_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000)
}

pub(super) fn server_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4433)
}

/// Hands `conn` one datagram from `src`.
pub(super) fn deliver(
    conn: &mut Connection,
    now: Instant,
    src: SocketAddr,
    mut data: Vec<u8>,
) -> RecvSummary {
    let meta = RxMeta {
        src,
        dst_ip: None,
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: now,
    };
    conn.recv_batch(
        now,
        &mut [RxDatagram {
            meta: &meta,
            data: &mut data,
        }],
    )
}

/// A client that has sent its first datagram, and a server connection that has processed it
/// and not sent anything yet.
struct Accepted {
    now: Instant,
    client: Connection,
    server: Connection,
}

fn accepted(setup: &Setup) -> Accepted {
    let now = test_epoch();
    let config = setup.pair();
    let mut rng = TestRng::new(1);
    let mut cx = Inputs {
        now,
        unix_now: unix_now(),
        rng: &mut rng,
    };
    let key = ConnKey {
        index: 1,
        generation: 1,
    };
    let mut client = Endpoint::new(config.endpoint.clone(), None)
        .connect(
            &mut cx,
            key,
            server_addr(),
            ServerName::try_from("localhost").unwrap(),
            &config.client,
            ConnOptions::default(),
        )
        .unwrap();
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    let mut sent = sink.take();
    assert_eq!(sent.len(), 1, "a ClientHello in one datagram");
    let datagram = sent.remove(0).data;
    let meta = RxMeta {
        src: client_addr(),
        dst_ip: None,
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: now,
    };
    let mut endpoint = Endpoint::new(config.endpoint, Some(config.server.clone()));
    let Route::Accept(incoming) = endpoint.route(now, &meta, &datagram) else {
        panic!("the server does not accept the ClientHello");
    };
    let server = endpoint
        .accept(
            &mut cx,
            key,
            incoming,
            &config.server,
            ConnOptions::default(),
        )
        .unwrap();
    Accepted {
        now,
        client,
        server,
    }
}

/// A packet built by hand and sealed with a connection's write keys.
pub(super) struct Forge<'a> {
    space: Space,
    header: HeaderSpec<'a>,
    pn: u64,
    /// An ACK frame of this range and `older`, written first.
    pub(super) ack: Option<RangeInclusive<u64>>,
    /// The other ranges of that frame, in descending order.
    pub(super) older: &'a [RangeInclusive<u64>],
    /// The ACK Delay field of that frame.
    pub(super) ack_delay: VarInt,
    frames: &'a [Frame<'a>],
    /// Bytes written as they are after the frames, for frames encoded as `frames` would not be.
    pub(super) raw: &'a [u8],
    /// PADDING up to this packet length.
    len: usize,
    /// Bits set in the first byte under header protection.
    first_bits: u8,
    /// Whether the payload is empty, so the AEAD tag follows the header. Short headers only.
    empty: bool,
}

impl<'a> Forge<'a> {
    /// Returns a packet `conn` could send in `space`, with packet number `pn` and `frames`.
    pub(super) fn of(conn: &Connection, space: Space, pn: u64, frames: &'a [Frame<'a>]) -> Self {
        let header = match space {
            Space::Initial => HeaderSpec::Initial {
                version: conn.version,
                dcid: conn.remote_cid(),
                scid: conn.local_cid,
                token: &[],
            },
            Space::Handshake => HeaderSpec::Handshake {
                version: conn.version,
                dcid: conn.remote_cid(),
                scid: conn.local_cid,
            },
            Space::Data => HeaderSpec::OneRtt {
                dcid: conn.remote_cid(),
                spin: false,
                key_phase: false,
            },
        };
        Self {
            space,
            header,
            pn,
            ack: None,
            older: &[],
            ack_delay: VarInt::ZERO,
            frames,
            raw: &[],
            len: 0,
            first_bits: 0,
            empty: false,
        }
    }

    /// Seals the packet with `conn`'s keys.
    pub(super) fn seal(&self, conn: &Connection) -> Vec<u8> {
        let mut buf = vec![0; 1500];
        let mut w = PacketWriter::new(&mut buf, self.header, self.pn, 4, TAG_LEN).unwrap();
        if let Some(range) = self.ack.clone() {
            w.ack(range, self.older.iter().cloned(), self.ack_delay, None)
                .unwrap();
        }
        for frame in self.frames {
            w.frame(frame).unwrap();
        }
        w.put_ack_eliciting_bytes(self.raw).unwrap();
        w.pad_to(self.len).unwrap();
        let layout = w.finish();
        let len = if self.empty {
            layout.hdr_len + TAG_LEN
        } else {
            layout.len
        };
        buf[0] |= self.first_bits;
        let keys = &conn.spaces[self.space.index()].keys.as_ref().unwrap().local;
        let job = SealJob {
            slot: SlotId(0),
            keys,
            pn: self.pn,
            hdr_len: u16::try_from(layout.hdr_len).unwrap(),
            len: u16::try_from(len).unwrap(),
        };
        InlineSealer.seal(job, &mut buf).unwrap();
        buf.truncate(len);
        buf
    }
}

/// Opens the packets of a datagram `conn` sent with its own write keys: each packet's type and
/// plaintext.
pub(super) fn open_own(conn: &Connection, datagram: &[u8]) -> Vec<(PacketType, Vec<u8>)> {
    packets_to(datagram, dcid_len(conn))
        .into_iter()
        .map(|(ty, packet)| (ty, open_packet(conn, ty, packet)))
        .collect()
}

/// Returns the plaintexts of the 1-RTT packets of a datagram `conn` sent, skipping the packets of
/// other spaces, whose keys may be discarded by now.
pub(super) fn open_own_one_rtt(conn: &Connection, datagram: &[u8]) -> Vec<Vec<u8>> {
    packets_to(datagram, dcid_len(conn))
        .into_iter()
        .filter(|(ty, _)| *ty == PacketType::OneRtt)
        .map(|(ty, packet)| open_packet(conn, ty, packet))
        .collect()
}

/// Returns the length of the Destination Connection ID in the short headers `conn` sends: that of
/// its peer's IDs, which have one length in these tests.
fn dcid_len(conn: &Connection) -> usize {
    conn.sources
        .cids
        .peer
        .ids()
        .first()
        .map_or(8, |(_, cid, _)| cid.len())
}

fn open_packet(conn: &Connection, ty: PacketType, packet: Vec<u8>) -> Vec<u8> {
    let space = match ty {
        PacketType::Initial => Space::Initial,
        PacketType::Handshake => Space::Handshake,
        PacketType::OneRtt => Space::Data,
        PacketType::ZeroRtt => panic!("no 0-RTT packets are built"),
    };
    let keys = &conn.spaces[space.index()].keys.as_ref().unwrap().local;
    open_with(keys, dcid_len(conn), packet)
}

/// Opens a packet with `keys`, its short header carrying a Destination Connection ID of `dcid_len`
/// bytes.
fn open_with(keys: &PacketKeys, dcid_len: usize, mut packet: Vec<u8>) -> Vec<u8> {
    let Ok(Header::Protected(header)) = Header::parse(&packet, dcid_len) else {
        panic!("an unparsable packet");
    };
    let pn_offset = header.pn_offset();
    let pn_len = unprotect_header(keys.header(), &mut packet, pn_offset).unwrap();
    let pn = packet[pn_offset..pn_offset + pn_len]
        .iter()
        .fold(0, |acc, &byte| acc << 8 | u64::from(byte));
    let (header, payload) = packet.split_at_mut(pn_offset + pn_len);
    keys.packet()
        .decrypt_in_place(pn, header, payload)
        .unwrap()
        .to_vec()
}

/// Returns the code and frame type of the CONNECTION_CLOSE `conn` reports it sent on an error.
pub(super) fn local_close(conn: &mut Connection) -> Option<(TransportErrorCode, Option<VarInt>)> {
    std::iter::from_fn(|| conn.poll_event()).find_map(|event| match event {
        ConnEvent::Closed {
            reason: CloseReason::Transport {
                code, frame_type, ..
            },
            initiator: Initiator::Local,
        } => Some((code, frame_type)),
        _ => None,
    })
}

#[test]
fn the_handshake_completes_for_client_and_server() {
    let (_, pair) = handshake(Setup::default().pair());
    for (peer, side) in [(&pair.client, Side::Client), (&pair.server, Side::Server)] {
        let conn = peer.conn();
        assert_eq!(conn.side(), side);
        assert_eq!(conn.version(), Version::V1);
        assert_eq!(conn.alpn(), Some(&b"h3"[..]));
        assert_eq!(
            peer.events[..3],
            [
                ConnEvent::WriteKeysReady,
                ConnEvent::Connected,
                ConnEvent::Confirmed
            ]
        );
        // Both handshake spaces are discarded once the handshake is confirmed (RFC 9001).
        assert!(conn.spaces[Space::Initial.index()].discarded);
        assert!(conn.spaces[Space::Handshake.index()].discarded);
        assert_eq!(conn.stats().tx_inconsistent, 0);
    }
    // The server's flight coalesces its Initial and Handshake packets, as RFC 9000 allows.
    let (_, first) = &pair.server.sent[0];
    assert_eq!(
        packet_types(&first.data)[..2],
        [PacketType::Initial, PacketType::Handshake]
    );
    // Client datagrams with an Initial, and server datagrams with an ack-eliciting one, are
    // padded to 1,200 bytes, as RFC 9000 requires.
    for (_, datagram) in &pair.client.sent {
        if packet_types(&datagram.data).contains(&PacketType::Initial) {
            assert_eq!(datagram.data.len(), 1200);
        }
    }
    assert_eq!(first.data.len(), 1200);
}

#[test]
fn a_handshake_failure_closes_both_sides_with_the_tls_alert() {
    let setup = Setup {
        client_alpn: &[b"hq-interop"],
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    });
    // Without a common application protocol, RFC 9001 requires the TLS alert 120.
    let code = TransportErrorCode::crypto(120);
    let server_close = pair.server.events.iter().find_map(|event| match event {
        ConnEvent::Closed {
            reason: CloseReason::Transport { code, .. },
            initiator,
        } => Some((*code, *initiator)),
        _ => None,
    });
    assert_eq!(server_close, Some((code, Initiator::Local)));
    let client_close = pair.client.events.iter().find_map(|event| match event {
        ConnEvent::Closed {
            reason: CloseReason::Transport { code, .. },
            initiator,
        } => Some((*code, *initiator)),
        _ => None,
    });
    assert_eq!(client_close, Some((code, Initiator::Peer)));
    for peer in [&pair.client, &pair.server] {
        assert!(!peer.has_event(&ConnEvent::Connected));
        assert_eq!(peer.events.last(), Some(&ConnEvent::Drained));
    }
}

#[test]
fn the_handshake_survives_losing_each_of_its_datagrams_once() {
    let (_, baseline) = handshake(Setup::default().pair());
    let counts = [baseline.client.sent.len(), baseline.server.sent.len()];
    assert!(counts[0] >= 2 && counts[1] >= 2, "{counts:?}");
    for (to_server, count) in [(true, counts[0]), (false, counts[1])] {
        for index in 0..count {
            let mut config = Setup::default().pair();
            let link = if to_server {
                &mut config.to_server
            } else {
                &mut config.to_client
            };
            link.loss = Loss::Drop(vec![index]);
            let (_, pair) = handshake(config);
            let lost = if to_server {
                pair.to_server.lost()
            } else {
                pair.to_client.lost()
            };
            assert_eq!(lost, 1, "datagram {index} towards the server: {to_server}");
        }
    }
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn the_handshake_completes_over_a_1200_byte_mtu() {
    // A post-quantum ClientHello and a large certificate take several datagrams each way.
    let mut config = Setup {
        pq: true,
        cert_names: 40,
        ..Setup::default()
    }
    .pair();
    config.to_server.mtu = 1200;
    config.to_client.mtu = 1200;
    let (_, pair) = handshake(config);
    assert_eq!(pair.to_server.lost() + pair.to_client.lost(), 0);
    for peer in [&pair.client, &pair.server] {
        let full = peer
            .sent
            .iter()
            .filter(|(_, d)| d.data.len() == 1200)
            .count();
        assert!(full >= 2, "{full} full datagrams");
    }
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn peer_maximum_datagrams_fill_a_1452_byte_mtu() {
    let transport = TransportConfig::builder()
        .datagram_size(DatagramSize::PeerMaximum {
            initial: 1200,
            cap: 1452,
        })
        .build()
        .unwrap();
    // A post-quantum key share makes the server's flight larger than one datagram.
    let setup = Setup {
        pq: true,
        ..Setup::default()
    }
    .transport(transport);
    let mut config = setup.pair();
    config.to_server.mtu = 1452;
    config.to_client.mtu = 1452;
    let (_, pair) = handshake(config);
    assert_eq!(pair.to_server.lost() + pair.to_client.lost(), 0);
    // The client's Initials go out before the server's limit arrives; the server has the
    // client's from the ClientHello.
    assert_eq!(pair.client.sent[0].1.data.len(), 1200);
    assert_eq!(pair.server.sent[0].1.data.len(), 1452);
    let largest = [&pair.client, &pair.server]
        .into_iter()
        .flat_map(|peer| &peer.sent)
        .map(|(_, datagram)| datagram.data.len())
        .max();
    assert_eq!(largest, Some(1452));
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn the_minimum_policy_keeps_datagrams_at_1200_bytes_whatever_the_peer_allows() {
    let mut config = Setup {
        pq: true,
        ..Setup::default()
    }
    .pair();
    config.to_server.mtu = 1452;
    config.to_client.mtu = 1452;
    let (_, pair) = handshake(config);
    let largest = [&pair.client, &pair.server]
        .into_iter()
        .flat_map(|peer| &peer.sent)
        .map(|(_, datagram)| datagram.data.len())
        .max();
    assert_eq!(largest, Some(1200));
}

/// Returns a transport config that sends datagrams of `size`, advertises `max_udp_payload_size`
/// and takes a bulk transfer on a unidirectional stream without its windows holding it back.
fn sending(size: DatagramSize, max_udp_payload_size: u16) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .datagram_size(size)
        .max_udp_payload_size(max_udp_payload_size)
        .max_data(1 << 30)
        .max_stream_data_uni(1 << 30)
        .build()
        .unwrap()
}

/// A client that sends 1,252-byte datagrams and a server that sends 1,232-byte ones, the sizes
/// of an mvfst client towards an IPv4 server and of an mvfst server.
fn fixed_sizes() -> Setup {
    Setup {
        client_transport: sending(DatagramSize::Fixed(1252), 1452),
        server_transport: sending(DatagramSize::Fixed(1232), 1452),
        ..Setup::default()
    }
}

/// Runs the handshake of `setup`, then has the server, or the client if not `from_server`, send
/// `len` bytes on a unidirectional stream that the other side reads. Returns the pair and how many
/// datagrams the sender had sent when the handshake was confirmed.
fn transfer(setup: &Setup, from_server: bool, len: usize) -> (Pair, usize) {
    let (_, mut pair) = handshake(setup.pair());
    let sender = if from_server {
        &mut pair.server
    } else {
        &mut pair.client
    };
    let before = sender.sent.len();
    let id = sender.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    let (mut client, mut server) = (App::default(), App::default());
    let writer = if from_server {
        &mut server
    } else {
        &mut client
    };
    writer.write(id, pattern(len), true);
    let until = pair.now + Duration::from_secs(2);
    run_apps(&mut pair, until, &mut client, &mut server);
    let reader = if from_server { &client } else { &server };
    assert_eq!(
        reader.data.get(&id).map_or(0, Vec::len),
        len,
        "the transfer did not complete"
    );
    (pair, before)
}

/// Returns the sizes of the datagrams `peer` sent from its datagram `from` on.
fn sizes_from(peer: &Peer, from: usize) -> Vec<usize> {
    peer.sent[from..]
        .iter()
        .map(|(_, datagram)| datagram.data.len())
        .collect()
}

/// Returns how many of `sizes` are exactly `size`.
fn count_of(sizes: &[usize], size: usize) -> usize {
    sizes.iter().filter(|&&len| len == size).count()
}

/// Returns the sizes of the datagrams `peer` sent that carry an ack-eliciting Initial packet. The
/// Initial keys are derived again from the client's first Destination Connection ID, so that the
/// packets open after the connection discarded its own keys.
fn eliciting_initial_sizes(peer: &Peer) -> Vec<usize> {
    let conn = peer.conn();
    let keys = mvfstr_crypto::initial_keys(conn.version, &conn.original_dcid, conn.side)
        .unwrap()
        .local;
    peer.sent
        .iter()
        .map(|(_, datagram)| &datagram.data)
        .filter(|data| {
            packets(data)
                .into_iter()
                .filter(|(ty, _)| *ty == PacketType::Initial)
                .any(|(_, packet)| {
                    let plaintext = open_with(&keys, 8, packet);
                    Frames::new(&plaintext).any(|frame| frame.unwrap().kind().is_ack_eliciting())
                })
        })
        .map(Vec::len)
        .collect()
}

/// Asserts that the congestion controller and the pacer of `conn`, which has not received an
/// acknowledgment yet, are sized for datagrams of `size` bytes: RFC 9002's initial window of 10
/// datagrams, and runs of `size`-byte datagrams at the pacer's rate.
fn assert_started_at(conn: &Connection, size: u16) {
    assert_eq!(conn.cc.cwnd(), 10 * u64::from(size), "the initial window");
    let mut sized = conn.pacer.clone();
    sized.set_max_datagram_size(size);
    assert_eq!(
        (conn.pacer.burst(), conn.pacer.run_time()),
        (sized.burst(), sized.run_time()),
        "the pacer's runs"
    );
}

#[test]
fn a_fixed_size_client_pads_its_first_initial_to_that_size_and_starts_at_it() {
    let (_, mut pair) = start(fixed_sizes().pair());
    pair.step();
    let first = &pair.client.sent[0].1.data;
    assert_eq!(packet_types(first), [PacketType::Initial]);
    assert_eq!(first.len(), 1252, "the ClientHello's datagram");
    assert_started_at(pair.client.conn(), 1252);
}

#[test]
fn a_fixed_size_server_starts_its_controller_and_pacer_at_that_size() {
    let (epoch, mut pair) = start(fixed_sizes().pair());
    assert!(pair.run_until(epoch + LIMIT, |pair| pair.server.conn.is_some()));
    assert_started_at(pair.server.conn(), 1232);
}

#[test]
fn a_fixed_size_server_pads_every_datagram_with_an_ack_eliciting_initial_to_that_size() {
    let (_, pair) = handshake(fixed_sizes().pair());
    let initials = eliciting_initial_sizes(&pair.server);
    assert!(!initials.is_empty(), "no Initial from the server");
    assert!(initials.iter().all(|&len| len == 1232), "{initials:?}");
}

#[test]
fn a_fixed_size_server_fills_backlogged_datagrams_to_that_size_and_never_more() {
    let (pair, from) = transfer(&fixed_sizes(), true, 200_000);
    let sizes = sizes_from(&pair.server, from);
    assert_eq!(sizes.iter().max(), Some(&1232));
    let full = count_of(&sizes, 1232);
    assert!(full >= 100, "{full} full datagrams of {}", sizes.len());
}

#[test]
fn a_fixed_size_server_ignores_a_larger_limit_from_the_client() {
    let setup = Setup {
        client_transport: sending(DatagramSize::default(), 1500),
        server_transport: sending(DatagramSize::Fixed(1232), 1500),
        ..Setup::default()
    };
    let (pair, from) = transfer(&setup, true, 200_000);
    let every = sizes_from(&pair.server, 0);
    assert_eq!(every.iter().max(), Some(&1232), "{every:?}");
    let full = count_of(&sizes_from(&pair.server, from), 1232);
    assert!(full >= 100, "{full} full datagrams");
}

/// Has a server with `cap` and `ours` as its own max_udp_payload_size send to a client that
/// advertises `peer`, and asserts that its full 1-RTT datagrams and its datagrams carrying an
/// ack-eliciting Initial are all `expected` bytes and none is larger.
fn assert_peer_maximum(ours: u16, cap: u16, peer: u16, expected: usize) {
    let case = format!("ours {ours}, cap {cap}, the client's {peer}");
    let setup = Setup {
        client_transport: sending(DatagramSize::default(), peer),
        server_transport: sending(DatagramSize::PeerMaximum { initial: 1232, cap }, ours),
        ..Setup::default()
    };
    let (pair, from) = transfer(&setup, true, 200_000);
    let sizes = sizes_from(&pair.server, from);
    assert_eq!(sizes.iter().max(), Some(&expected), "{case}");
    let full = count_of(&sizes, expected);
    assert!(
        full >= 100,
        "{case}: {full} full datagrams of {}",
        sizes.len()
    );
    // The server has the client's parameters from the ClientHello before it sends anything.
    let initials = eliciting_initial_sizes(&pair.server);
    assert!(
        !initials.is_empty() && initials.iter().all(|&len| len == expected),
        "{case}: Initials of {initials:?}"
    );
}

#[test]
fn a_peer_maximum_server_sends_the_smaller_of_the_clients_limit_and_the_cap() {
    assert_peer_maximum(1500, 1452, 1500, 1452);
    assert_peer_maximum(1500, 1452, 1300, 1300);
    assert_peer_maximum(1280, 1452, 1300, 1300);
}

#[test]
fn the_peer_maximum_cap_does_not_follow_the_max_udp_payload_size_we_advertise() {
    assert_peer_maximum(1300, 1452, 1500, 1452);
}

#[test]
fn a_peer_maximum_client_sends_its_initial_size_until_the_servers_parameters_arrive() {
    let setup = Setup {
        client_transport: sending(
            DatagramSize::PeerMaximum {
                initial: 1232,
                cap: 1452,
            },
            1500,
        ),
        server_transport: sending(DatagramSize::default(), 1500),
        ..Setup::default()
    };
    let (pair, from) = transfer(&setup, false, 200_000);
    let first = &pair.client.sent[0].1.data;
    assert_eq!(packet_types(first), [PacketType::Initial]);
    assert_eq!(first.len(), 1232, "the ClientHello's datagram");
    let sizes = sizes_from(&pair.client, from);
    assert_eq!(sizes.iter().max(), Some(&1452));
    let full = count_of(&sizes, 1452);
    assert!(full >= 100, "{full} full datagrams of {}", sizes.len());
}

#[test]
fn a_fixed_size_client_pads_every_datagram_with_an_initial_to_that_size() {
    let (_, pair) = handshake(fixed_sizes().pair());
    let initials: Vec<usize> = pair
        .client
        .sent
        .iter()
        .map(|(_, datagram)| &datagram.data)
        .filter(|data| packet_types(data).contains(&PacketType::Initial))
        .map(Vec::len)
        .collect();
    // The ClientHello, and the acknowledgment of the server's Initial.
    assert!(initials.len() >= 2, "{initials:?}");
    assert!(initials.iter().all(|&len| len == 1252), "{initials:?}");
}

#[test]
fn a_server_initial_larger_than_the_anti_amplification_credit_fills_the_credit() {
    // A 1,200-byte ClientHello allows the server 3,600 bytes, less than its datagram size.
    let setup = Setup {
        server_transport: sending(DatagramSize::Fixed(4000), 9000),
        ..Setup::default()
    };
    let mut config = setup.pair();
    config.max_datagram = 9000;
    config.to_server.mtu = 9000;
    config.to_client.mtu = 9000;
    let (_, pair) = handshake(config);
    let first = &pair.server.sent[0].1.data;
    assert_eq!(packet_types(first)[0], PacketType::Initial);
    assert_eq!(first.len(), 3600, "the server's first datagram");
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn a_client_hello_in_two_datagrams_completes() {
    let setup = Setup {
        pq: true,
        ..Setup::default()
    };
    let (epoch, pair) = handshake(setup.pair());
    let first_flight: Vec<_> = pair
        .client
        .sent
        .iter()
        .filter(|(at, _)| *at == epoch)
        .map(|(_, datagram)| datagram)
        .collect();
    assert_eq!(first_flight.len(), 2);
    for datagram in first_flight {
        assert_eq!(datagram.data.len(), 1200);
        assert_eq!(packet_types(&datagram.data), [PacketType::Initial]);
    }
}

#[test]
fn the_handshake_completes_on_mvfst_connections() {
    let setup = Setup {
        client_versions: vec![Version::MVFST],
        server_versions: vec![Version::V1, Version::MVFST],
        ..Setup::default()
    };
    let (_, pair) = handshake(setup.pair());
    assert_eq!(pair.client.conn().version(), Version::MVFST);
    assert_eq!(pair.server.conn().version(), Version::MVFST);
}

#[test]
fn the_handshake_completes_on_mvfsts_alias_versions() {
    for version in [
        Version::QUIC_V1_ALIAS,
        Version::QUIC_V1_ALIAS2,
        Version::MVFST_ALIAS,
    ] {
        let setup = Setup {
            client_versions: vec![version],
            server_versions: vec![Version::V1, Version::MVFST, version],
            ..Setup::default()
        };
        let (_, pair) = handshake(setup.pair());
        assert_eq!(pair.client.conn().version(), version);
        assert_eq!(pair.server.conn().version(), version);
    }
}

#[test]
fn one_server_takes_mvfst_clients_with_or_without_alpn_and_version_1_clients_with_it() {
    // rustls refuses a ClientHello without ALPN under the server's main config, which lists h3,
    // and one with ALPN under its MVFST config, whose protocol list is empty.
    let no_alpn = Setup {
        server_alpn: &[],
        alpn: AlpnPolicy::AllowMissing,
        ..Setup::default()
    }
    .pair()
    .server
    .tls()
    .rustls()
    .expect("a rustls server")
    .clone();
    let with_server = |client: Setup| {
        let mut config = client.pair();
        config.server = ServerConfig::builder(Setup::default().pair().server.tls().clone())
            .versions(vec![Version::V1, Version::MVFST])
            .mvfst_tls(no_alpn.clone())
            .build()
            .expect("a server config");
        config
    };

    let mvfst_client = Setup {
        client_versions: vec![Version::MVFST],
        client_alpn: &[],
        alpn: AlpnPolicy::AllowMissing,
        ..Setup::default()
    };
    let (_, pair) = handshake(with_server(mvfst_client));
    assert_eq!(pair.server.conn().version(), Version::MVFST);
    assert_eq!(pair.server.conn().alpn(), None);

    let mvfst_client_with_alpn = Setup {
        client_versions: vec![Version::MVFST],
        ..Setup::default()
    };
    let (_, pair) = handshake(with_server(mvfst_client_with_alpn));
    assert_eq!(pair.server.conn().version(), Version::MVFST);
    assert_eq!(pair.server.conn().alpn(), Some(&b"h3"[..]));

    let (_, pair) = handshake(with_server(Setup::default()));
    assert_eq!(pair.server.conn().version(), Version::V1);
    assert_eq!(pair.server.conn().alpn(), Some(&b"h3"[..]));
}

#[test]
fn the_idle_timeout_closes_both_sides_silently() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let confirmed = pair.now;
    let idle = closed(CloseReason::Silent, Initiator::IdleTimeout);
    // The idle timeout does not fire before the 30-second default.
    assert!(
        !pair.run_until(confirmed + Duration::from_secs(29), |pair| {
            pair.client.has_event(&idle) || pair.server.has_event(&idle)
        })
    );
    assert!(pair.run_until(confirmed + Duration::from_secs(31), |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    }));
    for peer in [&pair.client, &pair.server] {
        let tail = &peer.events[peer.events.len() - 2..];
        assert_eq!(tail, [idle.clone(), ConnEvent::Drained]);
        assert_eq!(peer.conn().next_deadline(), None);
        // The drained connection's routes are gone.
        assert_eq!(peer.endpoint.route_count(), 0);
    }
}

#[test]
fn the_smaller_idle_timeout_of_the_two_sides_applies() {
    let short = TransportConfig::builder()
        .idle_timeout(Some(Duration::from_secs(5)))
        .build()
        .unwrap();
    let setup = Setup {
        server_transport: short,
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let confirmed = pair.now;
    assert!(pair.run_until(confirmed + Duration::from_secs(6), |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    }));
    assert!(pair.now >= confirmed + Duration::from_secs(4));
}

#[test]
fn close_sends_connection_close_and_both_sides_drain() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let srtt = pair.client.conn().stats().smoothed_rtt;
    let closed_at = pair.now;
    let reason = CloseReason::Application {
        code: AppCode(VarInt::from_u32(7)),
        reason: Bytes::from_static(b"bye"),
    };
    pair.client.conn_mut().close(
        closed_at,
        AppCode(VarInt::from_u32(7)),
        Bytes::from_static(b"bye"),
    );
    assert!(pair.run_until(closed_at + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained)
    }));
    // The closing period lasts three PTOs, as RFC 9000 recommends.
    assert!(pair.now >= closed_at + 3 * (srtt + Duration::from_millis(25)));
    pair.run(closed_at + LIMIT);
    let client_tail = &pair.client.events[pair.client.events.len() - 2..];
    assert_eq!(
        client_tail,
        [closed(reason.clone(), Initiator::Local), ConnEvent::Drained]
    );
    let server_tail = &pair.server.events[pair.server.events.len() - 2..];
    assert_eq!(
        server_tail,
        [closed(reason, Initiator::Peer), ConnEvent::Drained]
    );
    // One CONNECTION_CLOSE from the client; RFC 9000 bars a draining server from sending.
    assert_eq!(
        pair.client
            .sent
            .iter()
            .filter(|(at, _)| *at >= closed_at)
            .count(),
        1
    );
    assert_eq!(
        pair.server
            .sent
            .iter()
            .filter(|(at, _)| *at >= closed_at)
            .count(),
        0
    );
    assert_eq!(pair.server.endpoint.route_count(), 0);
    assert_eq!(pair.client.endpoint.route_count(), 0);
}

#[test]
fn a_transport_close_carries_its_code_to_the_peer() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let closed_at = pair.now;
    pair.server.conn_mut().close_transport(
        closed_at,
        TransportErrorCode::NO_ERROR,
        Bytes::from_static(b"quiesced"),
    );
    pair.run(closed_at + LIMIT);
    let reason = |frame_type| CloseReason::Transport {
        code: TransportErrorCode::NO_ERROR,
        frame_type,
        reason: Bytes::from_static(b"quiesced"),
    };
    let server_tail = &pair.server.events[pair.server.events.len().saturating_sub(2)..];
    assert_eq!(
        server_tail,
        [closed(reason(None), Initiator::Local), ConnEvent::Drained]
    );
    // The frame carries frame type 0 for "unknown", which the receiver reports as given.
    let client_tail = &pair.client.events[pair.client.events.len().saturating_sub(2)..];
    assert_eq!(
        client_tail,
        [
            closed(reason(Some(VarInt::ZERO)), Initiator::Peer),
            ConnEvent::Drained
        ]
    );
}

#[test]
fn a_closing_endpoint_answers_packets_with_its_close() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let closed_at = pair.now;
    pair.client
        .conn_mut()
        .close(closed_at, AppCode(VarInt::from_u32(1)), Bytes::new());
    // The server's PING crosses the client's CONNECTION_CLOSE.
    pair.server.conn_mut().ping();
    pair.run(closed_at + LIMIT);
    assert_eq!(
        pair.server
            .sent
            .iter()
            .filter(|(at, _)| *at >= closed_at)
            .count(),
        1
    );
    assert_eq!(
        pair.client
            .sent
            .iter()
            .filter(|(at, _)| *at >= closed_at)
            .count(),
        2
    );
    assert!(pair.server.has_event(&ConnEvent::Drained));
}

#[test]
fn abort_ends_the_connection_without_sending() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let aborted_at = pair.now;
    pair.client.conn_mut().abort();
    pair.step();
    let tail = &pair.client.events[pair.client.events.len() - 2..];
    assert_eq!(
        tail,
        [
            closed(CloseReason::Silent, Initiator::Local),
            ConnEvent::Drained
        ]
    );
    assert_eq!(
        pair.client
            .sent
            .iter()
            .filter(|(at, _)| *at >= aborted_at)
            .count(),
        0
    );
    let outcome = pair.client.conn_mut().poll_transmit(
        &limits(aborted_at),
        &mut VecSink::new(1500),
        &mut InlineSealer,
    );
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Closed));
}

#[test]
fn a_server_sends_at_most_three_times_what_it_received_before_validation() {
    // A certificate of several kilobytes makes the server's flight larger than its credit.
    let setup = Setup {
        cert_names: 120,
        ..Setup::default()
    };
    let mut config = setup.pair();
    // Only the client's first datagram arrives, so the address is never validated.
    config.to_server.loss = Loss::Drop((1..1000).collect());
    let (epoch, mut pair) = start(config);
    pair.run(epoch + LIMIT);
    let received = pair.server.conn().stats().recv_bytes;
    let sent: usize = pair.server.sent.iter().map(|(_, d)| d.data.len()).sum();
    assert_eq!(received, 1200);
    assert!(sent as u64 <= 3 * received, "sent {sent}");
    assert!(
        pair.server
            .outcomes
            .iter()
            .any(|outcome| outcome.stop == Stop::Amplification)
    );
    assert!(!pair.server.has_event(&ConnEvent::Connected));
}

#[test]
fn a_large_server_flight_resumes_once_the_client_validates_the_address() {
    let setup = Setup {
        cert_names: 120,
        ..Setup::default()
    };
    let (_, pair) = handshake(setup.pair());
    // Bytes sent never pass three times those received until the first Handshake packet from
    // the client arrives; the link delays datagrams by 10 ms and does not drop any.
    let delay = Duration::from_millis(10);
    let validated_at = pair
        .client
        .sent
        .iter()
        .find(|(_, d)| packet_types(&d.data).contains(&PacketType::Handshake))
        .map(|(at, _)| *at + delay)
        .unwrap();
    let mut sent = 0;
    for (at, datagram) in pair.server.sent.iter().filter(|(at, _)| *at < validated_at) {
        sent += datagram.data.len();
        let received: usize = pair
            .client
            .sent
            .iter()
            .filter(|(sent_at, _)| *sent_at + delay <= *at)
            .map(|(_, d)| d.data.len())
            .sum();
        assert!(sent <= 3 * received, "sent {sent}, received {received}");
    }
    assert!(
        pair.server
            .outcomes
            .iter()
            .any(|outcome| outcome.stop == Stop::Amplification)
    );
}

#[test]
fn ack_frames_acknowledge_exactly_the_packets_received() {
    let mut config = Setup::default().pair();
    // Gaps in both directions once the handshake is over.
    config.to_server.loss = Loss::Drop(vec![8, 11, 12, 15]);
    config.to_client.loss = Loss::Drop(vec![9, 13]);
    let (_, mut pair) = handshake(config);
    for _ in 0..20 {
        pair.client.conn_mut().ping();
        pair.server.conn_mut().ping();
        let until = pair.now + Duration::from_millis(30);
        pair.run(until);
    }
    let mut gaps = false;
    for peer in [&pair.client, &pair.server] {
        let log = &peer.conn().sources.ack[Space::Data.index()].log;
        assert!(log.frames.len() > 5);
        for (ranges, received) in &log.frames {
            let acked: BTreeSet<u64> = ranges.iter().flat_map(|r| r.clone()).collect();
            let lowest = *acked.first().unwrap();
            let expected: BTreeSet<u64> = received
                .iter()
                .copied()
                .filter(|&pn| pn >= lowest)
                .collect();
            assert_eq!(acked, expected);
            assert_eq!(acked.last(), received.iter().max());
            gaps |= ranges.len() > 1;
        }
    }
    assert!(gaps, "no ACK frame had a gap");
    assert!(pair.to_server.lost() + pair.to_client.lost() == 6);
}

#[test]
fn a_refused_slot_leaves_the_connection_unchanged() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let before = (
        format!("{:?}", conn.explain_transmit(&limits(epoch))),
        conn.stats(),
        conn.next_deadline(),
    );
    let mut sink = VecSink::new(1500);
    sink.set_refuse(true);
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Socket));
    let after = (
        format!("{:?}", conn.explain_transmit(&limits(epoch))),
        conn.stats(),
        conn.next_deadline(),
    );
    assert_eq!(before, after);
    assert_eq!(conn.recovery.space(Space::Initial).next_pn(), 0);
    // A full batch also ends before a slot is taken.
    let mut sink = VecSink::new(1500);
    let outcome = conn.poll_transmit(
        &TxLimits {
            max_segments: 0,
            ..limits(epoch)
        },
        &mut sink,
        &mut InlineSealer,
    );
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::BatchFull));
    assert_eq!(sink.slots_lent(), 0);
    // So does a used-up egress grant.
    let outcome = conn.poll_transmit(
        &TxLimits {
            max_bytes: 100,
            ..limits(epoch)
        },
        &mut sink,
        &mut InlineSealer,
    );
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Endpoint));
    assert_eq!(sink.slots_lent(), 0);
    // The next attempt sends the ClientHello with packet number 0.
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    assert_eq!(conn.recovery.space(Space::Initial).next_pn(), 1);
}

#[test]
fn a_candidate_that_fits_no_packet_is_skipped_and_counted() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let tiny = TxLimits {
        max_datagram: 20,
        ..limits(epoch)
    };
    let mut sink = VecSink::new(20);
    let outcome = conn.poll_transmit(&tiny, &mut sink, &mut InlineSealer);
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Inconsistent));
    assert_eq!(conn.stats().tx_inconsistent, 1);
    assert_eq!(conn.stats().sent_packets, 0);
    assert_eq!(conn.recovery.space(Space::Initial).next_pn(), 0);
    // The skipped ClientHello stays queued, so the handshake still completes.
    assert!(pair.handshake(epoch + LIMIT));
}

#[test]
fn an_idle_connection_reports_idle_and_keys_pending_waits_for_keys() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let mut sink = VecSink::new(1500);
    let conn = pair.client.conn_mut();
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!((outcome.datagrams, outcome.stop), (1, Stop::Idle));
    // A PING waits for 1-RTT keys.
    conn.ping();
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::KeysPending));
    drop(sink.take());
    assert!(pair.handshake(epoch + LIMIT));
    let now = pair.now + Duration::from_secs(1);
    let outcome = pair.client.conn_mut().poll_transmit(
        &limits(now),
        &mut VecSink::new(1500),
        &mut InlineSealer,
    );
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Idle));
}

#[test]
fn a_server_buffers_1rtt_packets_until_the_handshake_completes() {
    buffers_1rtt_packets_up_to(Setup::default(), 20);
}

#[test]
fn a_server_buffers_as_many_packets_as_configured() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .buffered_packets(3)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    buffers_1rtt_packets_up_to(setup, 3);
}

#[test]
fn discarding_a_space_drops_the_packets_that_wait_for_its_keys() {
    let (_, mut pair) = start(Setup::default().pair());
    let client = pair.client.conn_mut();
    let now = client.now;
    let meta = RxMeta {
        src: server_addr(),
        dst_ip: None,
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: now,
    };
    // A Handshake packet that came before the server's Initial, and a 1-RTT packet.
    for space in [Space::Handshake, Space::Data] {
        assert!(client.buffered.push(space, &meta, 100, &[0; 100], 20));
    }
    client.discard_space(Space::Handshake, now);
    let waiting = client.buffered.take();
    let spaces: Vec<_> = waiting.iter().map(|packet| packet.space).collect();
    assert_eq!(spaces, [Space::Data]);
}

/// Checks that the server of a pair from `setup` buffers `limit` copies of the client's first
/// 1-RTT packet, drops the next, and opens the buffered ones once its handshake completes.
fn buffers_1rtt_packets_up_to(setup: Setup, limit: usize) {
    let mut config = setup.pair();
    // The client's second datagram carries its Finished and, coalesced after it, a 1-RTT PING;
    // it is held back and delivered in pieces below.
    config.to_server.loss = Loss::Drop(vec![1]);
    let (epoch, mut pair) = start(config);
    pair.client.conn_mut().ping();
    assert!(pair.run_until(epoch + LIMIT, |pair| pair.to_server.lost() == 1));
    let datagram = pair.client.sent[1].1.data.clone();
    let parts = packets(&datagram);
    let types: Vec<_> = parts.iter().map(|(ty, _)| *ty).collect();
    assert!(
        types.ends_with(&[PacketType::Handshake, PacketType::OneRtt]),
        "{types:?}"
    );
    let (one_rtt, rest): (Vec<_>, Vec<_>) = parts
        .into_iter()
        .partition(|(ty, _)| *ty == PacketType::OneRtt);
    let one_rtt = one_rtt.into_iter().next().unwrap().1;
    let rest: Vec<u8> = rest.into_iter().flat_map(|(_, bytes)| bytes).collect();
    let meta = RxMeta {
        src: pair.client.addr,
        dst_ip: Some(pair.server.addr.ip()),
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: pair.now,
    };
    let now = pair.now;
    let server = pair.server.conn_mut();
    // The server holds 1-RTT keys but, as RFC 9001 requires, does not open 1-RTT packets before
    // the handshake completes; it buffers a bounded number.
    for copy in 0..=limit {
        let mut data = one_rtt.clone();
        let summary = server.recv_batch(
            now,
            &mut [RxDatagram {
                meta: &meta,
                data: &mut data,
            }],
        );
        let expect = if copy < limit { (1, 0) } else { (0, 1) };
        assert_eq!((summary.buffered, summary.dropped), expect);
        assert_eq!(summary.packets, 0);
    }
    let mut data = rest;
    let summary = server.recv_batch(
        now,
        &mut [RxDatagram {
            meta: &meta,
            data: &mut data,
        }],
    );
    assert!(server.handshake.complete);
    // The Handshake packet, then one copy of the PING; the other copies are duplicates, and the
    // Initial is in a datagram below 1,200 bytes.
    assert_eq!(summary.packets, 2);
    assert_eq!(summary.dropped, limit as u32);
    assert_eq!(server.sources.ack[Space::Data.index()].log.received, [0]);
}

#[test]
fn a_client_drops_a_server_initial_that_carries_a_token() {
    let Accepted {
        now,
        mut client,
        server,
    } = accepted(&Setup::default());
    let close = [Frame::ConnectionClose {
        error_code: TransportErrorCode::CONNECTION_REFUSED,
        frame_type: VarInt::ZERO,
        reason: b"",
    }];
    let with_token = Forge {
        header: HeaderSpec::Initial {
            version: Version::V1,
            dcid: server.remote_cid(),
            scid: server.local_cid,
            token: b"token",
        },
        ..Forge::of(&server, Space::Initial, 0, &close)
    };
    // RFC 9000 requires an empty token in a server's Initial, so the client discards the packet.
    let summary = deliver(&mut client, now, server_addr(), with_token.seal(&server));
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    assert_eq!(client.poll_event(), None);
    // Without the token the same CONNECTION_CLOSE is taken.
    let packet = Forge::of(&server, Space::Initial, 1, &close).seal(&server);
    let summary = deliver(&mut client, now, server_addr(), packet);
    assert_eq!(summary.packets, 1);
    assert!(matches!(
        client.poll_event(),
        Some(ConnEvent::Closed {
            initiator: Initiator::Peer,
            ..
        })
    ));
}

#[test]
fn datagrams_from_another_address_earn_no_amplification_credit() {
    let setup = Setup {
        cert_names: 120,
        ..Setup::default()
    };
    let Accepted {
        now, mut server, ..
    } = accepted(&setup);
    let mut sink = VecSink::new(1500);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.stop, Stop::Amplification);
    // Datagrams routed here by connection ID, but from another address.
    let stranger = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 9);
    for _ in 0..3 {
        deliver(&mut server, now, stranger, vec![0; 1200]);
    }
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Amplification));
    // Credit comes only from the address being validated, as RFC 9000 requires.
    deliver(&mut server, now, client_addr(), vec![0; 1200]);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert!(outcome.datagrams > 0);
    let sent: usize = sink.take().iter().map(|d| d.data.len()).sum();
    assert!(sent <= 3 * 2400, "sent {sent}");
}

#[test]
fn a_datagram_started_by_an_ack_takes_no_data_past_the_egress_grant() {
    let Accepted {
        now, mut server, ..
    } = accepted(&Setup::default());
    let mut sink = VecSink::new(1500);
    let spent = TxLimits {
        max_bytes: 0,
        ..limits(now)
    };
    let outcome = server.poll_transmit(&spent, &mut sink, &mut InlineSealer);
    // The grant never refuses the due Initial ACK, but CRYPTO data needs the grant to join it.
    assert_eq!((outcome.datagrams, outcome.stop), (1, Stop::Endpoint));
    let datagram = sink.take().remove(0).data;
    assert_eq!(packet_types(&datagram), [PacketType::Initial]);
    assert!(datagram.len() < 1200, "an ACK-only Initial is not padded");
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert!(outcome.datagrams > 0);
    drop(sink.take());
}

#[test]
fn a_due_probe_goes_out_with_the_egress_grant_spent() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let mut sink = VecSink::new(1500);
    conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!(sink.take().len(), 1);
    // The ClientHello is lost: the PTO makes probes due and queues its bytes again as lost data.
    let pto = conn.next_deadline().unwrap();
    conn.on_deadline(pto);
    assert!(conn.recovery.probes_due(Space::Initial) > 0);
    let spent = TxLimits {
        max_bytes: 0,
        ..limits(pto)
    };
    let outcome = conn.poll_transmit(&spent, &mut sink, &mut InlineSealer);
    // The grant refuses the lost data's own start but never a probe, which the lost data joins.
    assert!(outcome.datagrams > 0, "{outcome:?}");
    let probe = sink.take().remove(0).data;
    assert_eq!(probe.len(), 1200);
    let opened = open_own(conn, &probe);
    assert_eq!(opened.len(), 1);
    assert!(
        Frames::new(&opened[0].1)
            .map(Result::unwrap)
            .any(|frame| matches!(frame, Frame::Crypto { offset, .. } if offset == VarInt::ZERO)),
        "the probe carries the ClientHello again"
    );
}

#[test]
fn a_short_credit_goes_to_the_start_packet_before_any_joiner() {
    let setup = Setup {
        cert_names: 120,
        ..Setup::default()
    };
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&setup);
    let mut sink = VecSink::new(1500);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.stop, Stop::Amplification);
    drop(sink.take());
    // A client PING makes the Initial ACK due while Handshake CRYPTO data is still queued.
    let ping = Forge {
        len: 1200,
        ..Forge::of(&client, Space::Initial, 1, &[Frame::Ping])
    };
    deliver(&mut server, now, client_addr(), ping.seal(&client));
    // Credit for the smallest Initial packet and a few bytes more, not for a Handshake one too.
    let credit = server.min_packet_len(Space::Initial) as u64 + 11;
    assert!(
        credit
            < (server.min_packet_len(Space::Initial) + server.min_packet_len(Space::Handshake))
                as u64
    );
    server.path.sent = 3 * server.path.received - credit;
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    // The datagram holds the packet its start was admitted for.
    let datagram = sink.take().remove(0).data;
    assert_eq!(packet_types(&datagram), [PacketType::Initial]);
}

/// Returns whether a packet's plaintext holds a CONNECTION_CLOSE of either type.
fn holds_close(plaintext: &[u8]) -> bool {
    Frames::new(plaintext).map(Result::unwrap).any(|frame| {
        matches!(
            frame,
            Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. }
        )
    })
}

#[test]
fn a_close_waits_for_credit_that_holds_its_frame() {
    let Accepted {
        now, mut server, ..
    } = accepted(&Setup::default());
    // A reason far longer than the few bytes the smallest 1-RTT packet has room for.
    server.close(
        now,
        AppCode(VarInt::from_u32(7)),
        Bytes::from(vec![b'x'; 100]),
    );
    // Credit for the Initial and Handshake CLOSEs and for the smallest 1-RTT packet, not for
    // the 1-RTT CLOSE with its reason.
    server.path.sent = 3 * server.path.received - 200;
    let mut sink = VecSink::new(1500);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    let sent = sink.take();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        packet_types(&sent[0].data),
        [PacketType::Initial, PacketType::Handshake]
    );
    assert!(server.path.credit() >= server.min_packet_len(Space::Data) as u64);
    // The credit stops the attempt with the CLOSE still pending, and tx_inconsistent stays at zero.
    assert_eq!(outcome.stop, Stop::Amplification);
    assert_eq!(server.stats().tx_inconsistent, 0);
    // The client's next datagram brings the credit the CLOSE needs.
    deliver(&mut server, now, client_addr(), vec![0; 1200]);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    let opened = open_own(&server, &sink.take().remove(0).data);
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].0, PacketType::OneRtt);
    assert!(Frames::new(&opened[0].1).map(Result::unwrap).any(
        |frame| matches!(frame, Frame::ApplicationClose { reason, .. } if reason.len() == 100)
    ));
}

#[test]
fn a_closing_connection_sends_no_packet_without_its_close() {
    let Accepted {
        now, mut server, ..
    } = accepted(&Setup::default());
    // The ClientHello's ACK is due, and a transport CLOSE keeps its reason in every space.
    server.close_on_error(
        now,
        ConnError::new(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "a reason longer than the room an ACK leaves in the smallest Initial packet",
        ),
    );
    // Credit for an Initial packet that holds the ACK but not the CLOSE.
    let credit = server.min_packet_len(Space::Initial) as u64 + 11;
    server.path.sent = 3 * server.path.received - credit;
    let mut sink = VecSink::new(1500);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    // While closing, an ACK goes out only in a packet with the CLOSE (RFC 9000).
    for datagram in sink.take() {
        for (ty, plaintext) in open_own(&server, &datagram.data) {
            assert!(holds_close(&plaintext), "a {ty:?} packet without the CLOSE");
        }
    }
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Amplification));
    assert_eq!(server.stats().tx_inconsistent, 0);
    deliver(&mut server, now, client_addr(), vec![0; 1200]);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    let opened = open_own(&server, &sink.take().remove(0).data);
    assert_eq!(opened.len(), 3);
    for (ty, plaintext) in &opened {
        assert!(holds_close(plaintext), "a {ty:?} packet without the CLOSE");
    }
}

/// Returns a server that has processed a ClientHello and, at its write keys, written 40 bytes on a
/// unidirectional stream, as an HTTP/3 server writes its control streams. Its certificate has
/// `cert_names` names, which set the length of its flight.
fn stream_data_at_write_keys(cert_names: usize) -> (Instant, Connection) {
    let setup = Setup {
        cert_names,
        ..Setup::default()
    };
    let Accepted {
        now, mut server, ..
    } = accepted(&setup);
    assert_eq!(server.poll_event(), Some(ConnEvent::WriteKeysReady));
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    server
        .stream(id)
        .unwrap()
        .send(&mut Bytes::from(vec![7; 40]))
        .unwrap();
    (now, server)
}

/// Makes `conn` transmit at `now`; returns why the attempt stopped and the datagrams.
fn attempt(conn: &mut Connection, now: Instant) -> (Stop, Vec<Vec<u8>>) {
    let mut sink = VecSink::new(1500);
    let outcome = conn.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    (
        outcome.stop,
        sink.take().into_iter().map(|d| d.data).collect(),
    )
}

/// Where a packet sits in a run of datagrams: the datagram's index, then the packet's.
type At = (usize, usize);

/// Checks that the first `joiner` packet in the `datagrams` that `server` sent follows the last
/// `crypto` packet with CRYPTO data, in that packet's datagram, and returns its plaintext. A client
/// opens a packet of a later space only once it has processed that CRYPTO data, and may drop one
/// that arrives earlier (RFC 9001).
fn expect_joiner_after_crypto_data(
    server: &Connection,
    datagrams: &[Vec<u8>],
    crypto: PacketType,
    joiner: PacketType,
) -> Vec<u8> {
    assert!(
        datagrams.len() > 1,
        "the CRYPTO data takes more than one datagram"
    );
    assert_eq!(datagrams[0].len(), 1200, "the Initial's datagram is padded");
    let (end, first, plaintext) = crypto_end_and_joiner(server, datagrams, crypto, joiner);
    assert!(
        first > end,
        "a {joiner:?} packet at {first:?}, ahead of the end of the {crypto:?} CRYPTO data at \
         {end:?}"
    );
    assert_eq!(
        first.0, end.0,
        "the {joiner:?} packet rides in the datagram that ends the {crypto:?} CRYPTO data"
    );
    plaintext
}

/// Returns where the last `crypto` packet with CRYPTO data and the first `joiner` packet sit in
/// the `datagrams` that `server` sent, and the joiner's plaintext.
fn crypto_end_and_joiner(
    server: &Connection,
    datagrams: &[Vec<u8>],
    crypto: PacketType,
    joiner: PacketType,
) -> (At, At, Vec<u8>) {
    let mut end: Option<At> = None;
    let mut first: Option<(At, Vec<u8>)> = None;
    for (d, datagram) in datagrams.iter().enumerate() {
        for (p, (ty, plaintext)) in open_own(server, datagram).into_iter().enumerate() {
            let mut frames = Frames::new(&plaintext).map(Result::unwrap);
            if ty == crypto && frames.any(|frame| matches!(frame, Frame::Crypto { .. })) {
                end = Some((d, p));
            }
            if ty == joiner && first.is_none() {
                first = Some(((d, p), plaintext));
            }
        }
    }
    let end = end.unwrap_or_else(|| panic!("no {crypto:?} packet with CRYPTO data"));
    let (first, plaintext) = first.unwrap_or_else(|| panic!("no {joiner:?} packet"));
    (end, first, plaintext)
}

/// Checks that the first 1-RTT packet in the `datagrams` that `server` sent carries the stream data
/// and follows the end of the server's handshake flight, in the flight's last datagram: a client
/// opens a 1-RTT packet only once it has the server's Finished.
fn expect_stream_data_after_the_flight(server: &Connection, datagrams: &[Vec<u8>]) {
    let plaintext = expect_joiner_after_crypto_data(
        server,
        datagrams,
        PacketType::Handshake,
        PacketType::OneRtt,
    );
    assert!(
        Frames::new(&plaintext)
            .map(Result::unwrap)
            .any(|frame| matches!(frame, Frame::Stream { .. })),
        "the first 1-RTT packet carries the stream data"
    );
}

#[test]
fn a_server_sends_no_1rtt_packet_ahead_of_its_handshake_flight() {
    // The flight fills two datagrams.
    let (now, mut server) = stream_data_at_write_keys(30);
    let (_, datagrams) = attempt(&mut server, now);
    expect_stream_data_after_the_flight(&server, &datagrams);
}

#[test]
fn a_server_sends_its_stream_data_after_a_flight_that_outruns_its_credit() {
    // The flight is longer than three times the ClientHello's datagram.
    let (now, mut server) = stream_data_at_write_keys(120);
    let (stop, mut datagrams) = attempt(&mut server, now);
    assert_eq!(stop, Stop::Amplification);
    // The client's next datagram brings the credit for the rest of the flight.
    deliver(&mut server, now, client_addr(), vec![0; 1200]);
    let (stop, rest) = attempt(&mut server, now);
    assert_ne!(stop, Stop::Amplification);
    datagrams.extend(rest);
    expect_stream_data_after_the_flight(&server, &datagrams);
}

#[test]
fn a_server_sends_its_stream_data_after_the_flight_it_sends_again() {
    let setup = Setup {
        cert_names: 30,
        ..Setup::default()
    };
    let Accepted {
        now, mut server, ..
    } = accepted(&setup);
    assert_eq!(server.poll_event(), Some(ConnEvent::WriteKeysReady));
    let (_, flight) = attempt(&mut server, now);
    assert_eq!(flight.len(), 2, "the flight fills two datagrams");
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    server
        .stream(id)
        .unwrap()
        .send(&mut Bytes::from(vec![7; 40]))
        .unwrap();
    // The flight is lost: the PTO queues its CRYPTO data again as lost data.
    let pto = server.next_deadline().unwrap();
    server.on_deadline(pto);
    assert!(server.sources.crypto[Space::Handshake.index()].has_lost());
    deliver(&mut server, pto, client_addr(), vec![0; 1200]);
    let (_, datagrams) = attempt(&mut server, pto);
    expect_stream_data_after_the_flight(&server, &datagrams);
}

#[test]
fn a_server_flight_in_one_datagram_takes_its_stream_data_along() {
    // The flight and the stream data fit one datagram.
    let (now, mut server) = stream_data_at_write_keys(1);
    let (_, datagrams) = attempt(&mut server, now);
    assert_eq!(datagrams.len(), 1);
    assert_eq!(datagrams[0].len(), 1200);
    let types: Vec<_> = open_own(&server, &datagrams[0])
        .into_iter()
        .map(|(ty, _)| ty)
        .collect();
    assert_eq!(
        types,
        [
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRtt
        ]
    );
}

#[test]
fn a_server_pads_a_flight_that_leaves_too_little_room_for_its_stream_data() {
    // A certificate name lengthens the flight by about as much as the smallest 1-RTT packet, so
    // one of these flights ends in its first datagram with too little room left for the stream
    // data. The stream data then goes in the next datagram, and the first one is still padded to
    // 1,200 bytes.
    let mut ends_without_stream_data = false;
    for cert_names in 1..=20 {
        let (now, mut server) = stream_data_at_write_keys(cert_names);
        let (_, datagrams) = attempt(&mut server, now);
        for datagram in &datagrams {
            if packet_types(datagram).contains(&PacketType::Initial) {
                assert_eq!(
                    datagram.len(),
                    1200,
                    "{cert_names} names: a datagram with an Initial packet is padded"
                );
            }
        }
        let (end, first, _) = crypto_end_and_joiner(
            &server,
            &datagrams,
            PacketType::Handshake,
            PacketType::OneRtt,
        );
        assert!(
            first > end,
            "{cert_names} names: a OneRtt packet at {first:?}, ahead of the end of the flight at \
             {end:?}"
        );
        ends_without_stream_data |= end.0 == 0 && first.0 > 0;
    }
    assert!(
        ends_without_stream_data,
        "a flight ends in its first datagram, without the stream data"
    );
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn a_server_sends_no_handshake_packet_ahead_of_the_end_of_its_server_hello() {
    // A post-quantum key share makes the ServerHello longer than one Initial packet.
    let setup = Setup {
        pq: true,
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    assert!(pair.run_until(epoch + LIMIT, |pair| !pair.server.sent.is_empty()));
    let datagrams: Vec<_> = pair
        .server
        .sent
        .iter()
        .map(|(_, datagram)| datagram.data.clone())
        .collect();
    expect_joiner_after_crypto_data(
        pair.server.conn(),
        &datagrams,
        PacketType::Initial,
        PacketType::Handshake,
    );
}

#[test]
fn a_connection_takes_the_longest_initial_rtt_the_builder_accepts() {
    let longest = TransportConfig::builder()
        .initial_rtt(RecoveryConfig::MAX_TIMER_SETTING)
        .build()
        .unwrap();
    handshake(Setup::default().transport(longest).pair());
}

#[test]
fn handshakes_from_one_setup_send_datagrams_of_the_same_sizes() {
    // The server's flight fills several datagrams, so its length shows in the last one
    // instead of in padding.
    let setup = Setup {
        cert_names: 120,
        ..Setup::default()
    };
    let sizes = |pair: &Pair| {
        [&pair.client, &pair.server].map(|peer| {
            peer.sent
                .iter()
                .map(|(_, datagram)| datagram.data.len())
                .collect::<Vec<_>>()
        })
    };
    let (_, first) = handshake(setup.pair());
    for _ in 0..3 {
        let (_, pair) = handshake(setup.pair());
        assert_eq!(sizes(&pair), sizes(&first));
    }
}

#[test]
fn rtt_samples_run_to_when_the_ack_arrived() {
    let Accepted {
        now,
        mut client,
        server,
    } = accepted(&Setup::default());
    let ack = Forge {
        ack: Some(0..=0),
        ..Forge::of(&server, Space::Initial, 0, &[])
    };
    let mut data = ack.seal(&server);
    // The ACK of the ClientHello arrives after 20 ms and waits 80 ms more to be processed.
    let meta = RxMeta {
        src: server_addr(),
        dst_ip: None,
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: now + Duration::from_millis(20),
    };
    let summary = client.recv_batch(
        now + Duration::from_millis(100),
        &mut [RxDatagram {
            meta: &meta,
            data: &mut data,
        }],
    );
    assert_eq!(summary.packets, 1);
    // The sample ends when the ACK was received, as RFC 9002 defines it.
    assert_eq!(client.recovery.rtt().latest(), Duration::from_millis(20));
}

#[test]
fn a_server_arms_its_pto_when_its_credit_covers_a_handshake_probe() {
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&Setup::default());
    let mut sink = VecSink::new(1500);
    server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    drop(sink.take());
    // The client acknowledges the server's Initial but does not send a Handshake packet, so the
    // address stays unvalidated with only Handshake data in flight.
    let ack = Forge {
        ack: Some(0..=0),
        len: 1200,
        ..Forge::of(&client, Space::Initial, 1, &[])
    };
    let summary = deliver(&mut server, now, client_addr(), ack.seal(&client));
    assert_eq!(summary.packets, 1);
    assert_eq!(
        server
            .recovery
            .space(Space::Initial)
            .ack_eliciting_in_flight(),
        0
    );
    assert!(
        server
            .recovery
            .space(Space::Handshake)
            .ack_eliciting_in_flight()
            > 0
    );
    assert!(!server.path.validated);
    let idle = now + Duration::from_secs(30);
    // Too little credit for an Initial, enough for a Handshake probe.
    server.path.sent = 3 * server.path.received - 900;
    assert!(server.next_deadline().unwrap() < idle, "no PTO armed");
    // The PTO stays unarmed when not even a Handshake packet fits, as RFC 9002 requires.
    server.path.sent = 3 * server.path.received - 30;
    assert_eq!(server.next_deadline(), Some(idle));
}

/// Seals a 1-RTT packet with `frames`, as the client of a confirmed pair would but with
/// `first_bits` and `empty` as in [`Forge`], delivers it to the server, and returns the
/// server's CONNECTION_CLOSE.
fn server_close_on_one_rtt(
    first_bits: u8,
    empty: bool,
    frames: &[Frame<'_>],
) -> Option<(TransportErrorCode, Option<VarInt>)> {
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Data).next_pn() + 10;
    let packet = Forge {
        first_bits,
        empty,
        ..Forge::of(client, Space::Data, pn, frames)
    }
    .seal(client);
    let server = pair.server.conn_mut();
    let summary = deliver(server, now, client_addr(), packet);
    assert_eq!(summary.packets, 1);
    local_close(server)
}

#[test]
fn reserved_bits_set_are_a_protocol_violation() {
    // The short header's reserved bits are 0x18, and RFC 9000 requires them to be zero.
    assert_eq!(
        server_close_on_one_rtt(0x10, false, &[Frame::Ping]),
        Some((TransportErrorCode::PROTOCOL_VIOLATION, None))
    );
}

#[test]
fn a_packet_without_frames_is_a_protocol_violation() {
    assert_eq!(
        server_close_on_one_rtt(0, true, &[]),
        Some((TransportErrorCode::PROTOCOL_VIOLATION, None))
    );
}

#[test]
fn handshake_done_from_a_client_is_a_protocol_violation() {
    assert_eq!(
        server_close_on_one_rtt(0, false, &[Frame::HandshakeDone]),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(0x1e))
        ))
    );
}

#[test]
fn new_token_from_a_client_is_a_protocol_violation() {
    let new_token = [Frame::NewToken { token: b"token" }];
    // RFC 9000 lets only a server send NEW_TOKEN.
    assert_eq!(
        server_close_on_one_rtt(0, false, &new_token),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(0x07))
        ))
    );
    // A client accepts it but does not keep the token: Retry and resumption are not supported.
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let packet = Forge::of(server, Space::Data, pn, &new_token).seal(server);
    let client = pair.client.conn_mut();
    let summary = deliver(client, now, server_addr(), packet);
    assert_eq!(summary.packets, 1);
    assert_eq!(local_close(client), None);
}

#[test]
fn every_ack_frame_received_is_counted() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let largest = pair
        .client
        .conn()
        .recovery
        .space(Space::Data)
        .next_pn()
        .checked_sub(1)
        .expect("the client sent a 1-RTT packet");
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let acking = Forge {
        ack: Some(largest..=largest),
        ..Forge::of(server, Space::Data, pn, &[Frame::Ping])
    }
    .seal(server);
    let pinging = Forge::of(server, Space::Data, pn + 1, &[Frame::Ping]).seal(server);
    let client = pair.client.conn_mut();
    let before = client.stats().acks_received;

    assert_eq!(deliver(client, now, server_addr(), acking).packets, 1);
    assert_eq!(
        client.stats().acks_received - before,
        1,
        "a packet with an ACK frame"
    );
    assert_eq!(deliver(client, now, server_addr(), pinging).packets, 1);
    assert_eq!(
        client.stats().acks_received - before,
        1,
        "a packet without one"
    );
    assert_eq!(local_close(client), None);
}

/// Writes twelve bytes on stream `id` and transmits at `at`.
fn write_and_transmit(conn: &mut Connection, id: StreamId, at: Instant) {
    let mut data = Bytes::from_static(b"twelve bytes");
    conn.stream(id).unwrap().send(&mut data).unwrap();
    conn.poll_transmit(&limits(at), &mut VecSink::new(1500), &mut InlineSealer);
}

#[test]
fn the_loss_timer_moves_with_every_transmit_of_ack_eliciting_data() {
    let (_, mut pair) = handshake(Setup::default().pair());
    pair.run(pair.now + Duration::from_millis(500));
    let now = pair.now;
    let client = pair.client.conn_mut();
    let loss_timer = |conn: &Connection| {
        conn.recovery
            .loss_detection_timer(conn.amplification_blocked())
            .map(|(at, _)| at)
    };
    assert_eq!(loss_timer(client), None, "nothing in flight once settled");
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let pto = client.recovery.pto_period(Space::Data);

    write_and_transmit(client, id, now);
    assert_eq!(loss_timer(client), Some(now + pto), "a PTO after the write");
    let later = now + pto / 2;
    write_and_transmit(client, id, later);
    assert_eq!(
        loss_timer(client),
        Some(later + pto),
        "a later write moves it"
    );
    let fired = later + pto;
    client.on_deadline(fired);
    assert_eq!(client.recovery.pto_period(Space::Data), 2 * pto);
    client.poll_transmit(&limits(fired), &mut VecSink::new(1500), &mut InlineSealer);
    assert_eq!(
        loss_timer(client),
        Some(fired + 2 * pto),
        "the probe moves it a doubled PTO on"
    );
}

#[test]
fn a_frame_its_packet_type_may_not_carry_is_a_protocol_violation() {
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&Setup::default());
    let frames = [Frame::MaxData(VarInt::from_u32(1000))];
    let packet = Forge {
        len: 1200,
        ..Forge::of(&client, Space::Initial, 1, &frames)
    };
    deliver(&mut server, now, client_addr(), packet.seal(&client));
    assert_eq!(
        local_close(&mut server),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(0x10))
        ))
    );
}

#[test]
fn new_crypto_data_at_a_finished_level_is_a_protocol_violation() {
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&Setup::default());
    // The server has read the ClientHello and now reads Handshake CRYPTO.
    assert_eq!(server.tls.read_level(), Level::Handshake);
    let frames = [Frame::Crypto {
        offset: VarInt::from_u32(5000),
        data: &[1; 10],
    }];
    let packet = Forge {
        len: 1200,
        ..Forge::of(&client, Space::Initial, 1, &frames)
    };
    deliver(&mut server, now, client_addr(), packet.seal(&client));
    assert_eq!(
        local_close(&mut server),
        Some((TransportErrorCode::PROTOCOL_VIOLATION, None))
    );
}

/// Returns a pair whose client sent its Finished in a datagram the server never got, with the
/// offset and bytes of the CRYPTO frame that carried it.
fn held_finished() -> (Pair, u64, Vec<u8>) {
    let mut config = Setup::default().pair();
    config.to_server.loss = Loss::Drop(vec![1]);
    let (epoch, mut pair) = start(config);
    assert!(pair.run_until(epoch + LIMIT, |pair| pair.to_server.lost() == 1));
    assert!(!pair.server.conn().handshake.complete);
    let datagram = &pair.client.sent[1].1.data;
    let (_, packet) = packets(datagram)
        .into_iter()
        .find(|(ty, _)| *ty == PacketType::Handshake)
        .expect("the client's second datagram carries its Finished");
    let (_, plaintext) = open_own(pair.client.conn(), &packet).remove(0);
    let (offset, data) = Frames::new(&plaintext)
        .map(Result::unwrap)
        .find_map(|frame| match frame {
            Frame::Crypto { offset, data } => Some((offset.into_inner(), data.to_vec())),
            _ => None,
        })
        .expect("a CRYPTO frame");
    (pair, offset, data)
}

/// Seals a Handshake packet with `frames` as the client of `pair` would, with a packet number
/// `ahead` past its next one, and delivers it to the server.
fn client_handshake_packet(pair: &mut Pair, ahead: u64, frames: &[Frame<'_>]) -> RecvSummary {
    let now = pair.now;
    let addr = pair.client.addr;
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Handshake).next_pn() + ahead;
    let packet = Forge::of(client, Space::Handshake, pn, frames).seal(client);
    deliver(pair.server.conn_mut(), now, addr, packet)
}

#[test]
fn the_finished_repeated_in_its_own_packet_completes_the_handshake() {
    let (mut pair, offset, finished) = held_finished();
    let crypto = Frame::Crypto {
        offset: VarInt::from_u64(offset).unwrap(),
        data: &finished,
    };
    // RFC 9000 lets CRYPTO data arrive again, here in the packet that completes the handshake,
    // after the server confirmed it.
    let summary = client_handshake_packet(&mut pair, 0, &[crypto, crypto]);
    assert_eq!(summary.packets, 1);
    let server = pair.server.conn_mut();
    assert_eq!(local_close(server), None);
    assert!(server.handshake.confirmed);
    assert!(server.spaces[Space::Handshake.index()].discarded);
}

#[test]
fn handshake_crypto_data_left_past_the_finished_is_a_protocol_violation() {
    let (mut pair, offset, finished) = held_finished();
    let end = offset + finished.len() as u64;
    let beyond = [Frame::Crypto {
        offset: VarInt::from_u64(end + 10).unwrap(),
        data: &[1; 5],
    }];
    let summary = client_handshake_packet(&mut pair, 0, &beyond);
    assert_eq!(summary.packets, 1);
    assert_eq!(local_close(pair.server.conn_mut()), None);
    let crypto = [Frame::Crypto {
        offset: VarInt::from_u64(offset).unwrap(),
        data: &finished,
    }];
    client_handshake_packet(&mut pair, 1, &crypto);
    // TLS moved past the level with bytes still unread at it, a protocol violation under RFC 9001.
    assert_eq!(
        local_close(pair.server.conn_mut()),
        Some((TransportErrorCode::PROTOCOL_VIOLATION, None))
    );
}

#[test]
fn crypto_data_far_past_what_tls_read_is_crypto_buffer_exceeded() {
    let Accepted {
        now,
        mut client,
        server,
    } = accepted(&Setup::default());
    let frames = [Frame::Crypto {
        offset: VarInt::from_u32(100_000),
        data: &[1],
    }];
    let packet = Forge::of(&server, Space::Initial, 0, &frames).seal(&server);
    deliver(&mut client, now, server_addr(), packet);
    assert_eq!(
        local_close(&mut client),
        Some((TransportErrorCode::CRYPTO_BUFFER_EXCEEDED, None))
    );
}

#[test]
fn later_packets_of_a_datagram_for_another_connection_id_are_ignored() {
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&Setup::default());
    let first = Forge::of(&client, Space::Initial, 1, &[Frame::Ping]).seal(&client);
    let other = ConnectionId::new(&[9; 8]).unwrap();
    let second = Forge {
        header: HeaderSpec::Initial {
            version: Version::V1,
            dcid: other,
            scid: client.local_cid,
            token: &[],
        },
        len: 1200 - first.len(),
        ..Forge::of(&client, Space::Initial, 2, &[Frame::Ping])
    }
    .seal(&client);
    let datagram = [first, second].concat();
    assert_eq!(datagram.len(), 1200);
    // RFC 9000 has a receiver ignore a later packet with a different Destination Connection ID.
    let summary = deliver(&mut server, now, client_addr(), datagram);
    assert_eq!((summary.packets, summary.dropped), (1, 1));
}

#[test]
fn long_header_packets_from_another_source_connection_id_are_ignored() {
    let Accepted {
        now,
        client,
        mut server,
    } = accepted(&Setup::default());
    let stranger = Forge {
        header: HeaderSpec::Initial {
            version: Version::V1,
            dcid: client.remote_cid(),
            scid: ConnectionId::new(&[9; 8]).unwrap(),
            token: &[],
        },
        len: 1200,
        ..Forge::of(&client, Space::Initial, 1, &[Frame::Ping])
    };
    // The client's first Initial fixed its connection ID (RFC 9000).
    let summary = deliver(&mut server, now, client_addr(), stranger.seal(&client));
    assert_eq!((summary.packets, summary.dropped), (0, 1));
    let own = Forge {
        len: 1200,
        ..Forge::of(&client, Space::Initial, 2, &[Frame::Ping])
    };
    let summary = deliver(&mut server, now, client_addr(), own.seal(&client));
    assert_eq!((summary.packets, summary.dropped), (1, 0));
}

#[test]
fn an_application_close_before_confirmation_goes_out_in_every_keyed_space() {
    let Accepted {
        now, mut server, ..
    } = accepted(&Setup::default());
    server.close(
        now,
        AppCode(VarInt::from_u32(7)),
        Bytes::from_static(b"bye"),
    );
    let mut sink = VecSink::new(1500);
    let outcome = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    let datagram = sink.take().remove(0).data;
    let opened = open_own(&server, &datagram);
    let types: Vec<_> = opened.iter().map(|(ty, _)| *ty).collect();
    assert_eq!(
        types,
        [
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRtt
        ]
    );
    for (ty, plaintext) in &opened {
        let close = Frames::new(plaintext).map(Result::unwrap).find(|frame| {
            matches!(
                frame,
                Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. }
            )
        });
        // RFC 9000 has an application close in an Initial or Handshake packet sent as a
        // transport APPLICATION_ERROR, with its reason cleared.
        let expected = match ty {
            PacketType::OneRtt => Frame::ApplicationClose {
                error_code: VarInt::from_u32(7),
                reason: b"bye",
            },
            _ => Frame::ConnectionClose {
                error_code: TransportErrorCode::APPLICATION_ERROR,
                frame_type: VarInt::ZERO,
                reason: b"",
            },
        };
        assert_eq!(close, Some(expected), "{ty:?}");
    }
}

#[test]
fn a_dropped_datagram_is_lost_at_once_and_its_ack_sent_again() {
    let Accepted {
        now, mut server, ..
    } = accepted(&Setup::default());
    let mut sink = VecSink::new(1500);
    let first = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    let sent_packets: usize = sink
        .take()
        .iter()
        .map(|d| packet_types(&d.data).len())
        .sum();
    let acks = |server: &Connection| server.sources.ack[Space::Initial.index()].log.frames.len();
    assert_eq!(acks(&server), 1);
    let idle = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!((idle.datagrams, idle.stop), (0, Stop::Idle));
    server.on_tx_report(
        now,
        TxReport::Dropped {
            tx: TxSeqRange {
                start: 0,
                end: u64::from(first.datagrams),
            },
            reason: DropReason::LocalQueue,
        },
    );
    assert_eq!(server.stats().lost_packets, sent_packets as u64);
    // The CRYPTO data goes out again at once, with the Initial ACK.
    let again = server.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(again.datagrams, first.datagrams);
    assert_eq!(acks(&server), 2);
    drop(sink.take());
}

/// A sealer that refuses every packet.
struct Refusing;

impl Sealer for Refusing {
    fn seal(&mut self, _job: SealJob<'_>, _pkt: &mut [u8]) -> Result<(), SealError> {
        Err(SealError::Encrypt)
    }
}

#[test]
fn a_seal_failure_sends_nothing_and_keeps_the_crypto_data() {
    let (epoch, mut pair) = start(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let mut sink = VecSink::new(1500);
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut Refusing);
    assert_eq!((outcome.datagrams, outcome.stop), (0, Stop::Inconsistent));
    assert!(sink.take().is_empty());
    assert_eq!(conn.recovery.space(Space::Initial).next_pn(), 0);
    assert_eq!(conn.stats().sent_packets, 0);
    // The ClientHello went back to its buffer: the next attempt sends it.
    let outcome = conn.poll_transmit(&limits(epoch), &mut sink, &mut InlineSealer);
    assert_eq!(outcome.datagrams, 1);
    assert_eq!(conn.recovery.space(Space::Initial).next_pn(), 1);
    drop(sink.take());
}

#[test]
fn a_connection_that_requires_alpn_closes_when_tls_agrees_on_none() {
    // Both protocol lists are empty, so TLS completes without one; the config builders refuse
    // AlpnPolicy::Required without protocols, so the server's policy is set by hand.
    let setup = Setup {
        client_alpn: &[],
        server_alpn: &[],
        alpn: AlpnPolicy::AllowMissing,
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    assert!(pair.run_until(epoch + LIMIT, |pair| pair.server.conn.is_some()));
    pair.server.conn_mut().alpn_policy = AlpnPolicy::Required;
    pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Drained) && pair.server.has_event(&ConnEvent::Drained)
    });
    // Without a negotiated application protocol, RFC 9001 requires the TLS alert 120.
    let code = TransportErrorCode::crypto(120);
    assert!(!pair.server.has_event(&ConnEvent::Connected));
    assert!(pair.server.events.iter().any(|event| matches!(
        event,
        ConnEvent::Closed {
            reason: CloseReason::Transport { code: c, .. },
            initiator: Initiator::Local,
        } if *c == code
    )));
    assert!(pair.client.events.iter().any(|event| matches!(
        event,
        ConnEvent::Closed {
            reason: CloseReason::Transport { code: c, .. },
            initiator: Initiator::Peer,
        } if *c == code
    )));
}

#[test]
fn a_connection_moves_between_threads_but_is_never_shared() {
    fn assert_send<T: Send>() {}
    assert_send::<Connection>();
    // With a `Sync` connection both impls apply and the call below is ambiguous.
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    <Connection as AmbiguousIfSync<_>>::check();
}

#[test]
fn the_handshake_and_its_acks_hold_up_over_a_reordering_link() {
    let mut config = Setup::default().pair();
    let jittery = LinkConfig {
        jitter: Duration::from_millis(15),
        ..LinkConfig::default()
    };
    config.to_server = jittery.clone();
    config.to_client = jittery;
    let (_, mut pair) = handshake(config);
    for _ in 0..20 {
        pair.client.conn_mut().ping();
        pair.server.conn_mut().ping();
        let until = pair.now + Duration::from_millis(5);
        pair.run(until);
    }
    let until = pair.now + Duration::from_millis(100);
    pair.run(until);
    assert!(pair.to_server.reordered() + pair.to_client.reordered() > 0);
    for peer in [&pair.client, &pair.server] {
        let log = &peer.conn().sources.ack[Space::Data.index()].log;
        assert!(!log.frames.is_empty());
        for (ranges, received) in &log.frames {
            let acked: BTreeSet<u64> = ranges.iter().flat_map(|r| r.clone()).collect();
            let lowest = *acked.first().unwrap();
            let expected: BTreeSet<u64> = received
                .iter()
                .copied()
                .filter(|&pn| pn >= lowest)
                .collect();
            assert_eq!(acked, expected);
        }
    }
}

/// Returns how many times `conn` reindexed one of its streams.
fn reindexes(conn: &Connection) -> u64 {
    conn.sources.streams.streams.reindexes()
}

/// Returns the packet number `conn` sends next in the 1-RTT space.
fn next_pn(conn: &Connection) -> u64 {
    conn.recovery.space(Space::Data).next_pn()
}

/// Builds a 1-RTT packet from `peer` with packet number `pn`, carrying one ACK frame of the range
/// `largest` and the `older` ones, in descending order.
fn ack_frame(
    peer: &Connection,
    pn: u64,
    largest: RangeInclusive<u64>,
    older: &[RangeInclusive<u64>],
) -> Vec<u8> {
    Forge {
        ack: Some(largest),
        older,
        ..Forge::of(peer, Space::Data, pn, &[])
    }
    .seal(peer)
}

/// Returns the connection of `side` in `pair`, which sends the stream data, and its peer.
fn sender_and_peer(pair: &mut Pair, side: Side) -> (&mut Connection, &Connection) {
    let Pair { client, server, .. } = pair;
    match side {
        Side::Client => (client.conn_mut(), server.conn()),
        Side::Server => (server.conn_mut(), client.conn()),
    }
}

/// Returns the address of the peer of the connection of `side`.
fn peer_addr(side: Side) -> SocketAddr {
    match side {
        Side::Client => server_addr(),
        Side::Server => client_addr(),
    }
}

/// Stages `len` bytes on stream `id` and transmits at `now`; returns how many packets went out.
fn send_on(conn: &mut Connection, id: StreamId, len: usize, now: Instant) -> u64 {
    let first = next_pn(conn);
    let mut data = Bytes::from(vec![0x5a; len]);
    assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(len));
    conn.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer);
    next_pn(conn) - first
}

/// Returns a pair after the handshake and a quiet half second, from `config`.
fn settled(config: PairConfig) -> Pair {
    let (_, mut pair) = handshake(config);
    let until = pair.now + Duration::from_millis(500);
    pair.run(until);
    pair
}

#[test]
fn an_ack_frame_covering_a_run_of_one_streams_packets_reindexes_it_once() {
    let mut pair = settled(Setup::default().pair());
    let now = pair.now;
    let (server, client) = sender_and_peer(&mut pair, Side::Server);
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    let first = next_pn(server);
    // More than the initial window takes, so that ten full packets fill it.
    let mut data = Bytes::from(vec![0x5a; 16_000]);
    server.stream(id).unwrap().send(&mut data).unwrap();
    server.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer);
    assert_eq!(next_pn(server), first + 10, "ten packets fill the window");
    let sent = server.stream_send_buf(id).unwrap().sent_end();
    let ack = ack_frame(client, next_pn(client) + 10, first..=first + 9, &[]);
    let before = reindexes(server);

    deliver(server, now + Duration::from_millis(20), client_addr(), ack);
    assert_eq!(
        reindexes(server) - before,
        1,
        "one reindex for the stream's run of ten packets"
    );
    assert_eq!(server.stream_send_buf(id).unwrap().acked_end(), sent);
    server.sources.streams.streams.assert_indexed();
}

#[test]
fn an_ack_frame_covering_more_than_65535_bytes_of_one_stream_acknowledges_them_in_one_run() {
    let setup = Setup {
        server_transport: TransportConfig::builder()
            .initial_window(64)
            .build()
            .unwrap(),
        client_transport: TransportConfig::builder()
            .max_stream_data_uni(1 << 20)
            .build()
            .unwrap(),
        ..Setup::default()
    };
    let mut pair = settled(setup.pair());
    let now = pair.now;
    let (server, client) = sender_and_peer(&mut pair, Side::Server);
    let id = server.open_stream(Dir::Uni, ORDER).unwrap();
    let first = next_pn(server);
    // A stream stages at most 64 KiB at a time, so it stages more as bytes leave, until the
    // window of 64 datagrams is full.
    let mut data = Bytes::from(vec![0x5a; 200_000]);
    loop {
        server.stream(id).unwrap().send(&mut data).unwrap();
        let attempt =
            server.poll_transmit(&limits(now), &mut VecSink::new(1500), &mut InlineSealer);
        if attempt.datagrams == 0 {
            break;
        }
    }
    let last = next_pn(server) - 1;
    let sent = server.stream_send_buf(id).unwrap().sent_end();
    assert!(sent > 70_000, "{sent} bytes sent");
    let ack = ack_frame(client, next_pn(client) + 10, first..=last, &[]);
    let before = reindexes(server);

    deliver(server, now + Duration::from_millis(20), client_addr(), ack);
    assert_eq!(
        reindexes(server) - before,
        1,
        "one reindex for the stream's run of {} packets",
        last + 1 - first
    );
    assert_eq!(server.stream_send_buf(id).unwrap().acked_end(), sent);
    server.sources.streams.streams.assert_indexed();
}

/// Returns two settled pairs from one config whose connections of `side` send the stream data.
/// The second applies each STREAM frame that an ACK frame acknowledges on its own: the
/// reference.
fn ack_twins(setup: &Setup, side: Side) -> [Pair; 2] {
    let config = setup.pair();
    let mut twins = [(); 2].map(|()| settled(config.clone()));
    sender_and_peer(&mut twins[1], side)
        .0
        .sources
        .per_frame_acks = true;
    twins
}

/// Runs `op` on each twin's connection of `side` with its peer, checks that both gave the same
/// result, and returns it.
fn on_twins<R: PartialEq + std::fmt::Debug>(
    twins: &mut [Pair; 2],
    side: Side,
    at: &str,
    mut op: impl FnMut(&mut Connection, &Connection) -> R,
) -> R {
    let [a, b] = twins;
    let (conn, peer) = sender_and_peer(a, side);
    let first = op(conn, peer);
    let (conn, peer) = sender_and_peer(b, side);
    let second = op(conn, peer);
    assert_eq!(first, second, "{at}: the twins diverged");
    first
}

/// Delivers to each twin's connection of `side`, at `now`, an ACK frame of the range `largest`
/// and the `older` ones from its peer, with packet number `ahead` past the peer's next; returns
/// how many reindexes each ran.
fn ack_twins_at(
    twins: &mut [Pair; 2],
    side: Side,
    now: Instant,
    ahead: u64,
    largest: &RangeInclusive<u64>,
    older: &[RangeInclusive<u64>],
) -> [u64; 2] {
    twins.each_mut().map(|pair| {
        let (conn, peer) = sender_and_peer(pair, side);
        let packet = ack_frame(peer, next_pn(peer) + ahead, largest.clone(), older);
        let before = reindexes(conn);
        assert_eq!(deliver(conn, now, peer_addr(side), packet).packets, 1);
        reindexes(conn) - before
    })
}

/// Returns, line by line, what the streams of `conn` show that an acknowledgment may change:
/// whether each of `ids` is still open and its half states, send buffer, lists and scheduling,
/// then each list and the scheduler in order, and the number of streams with lost data.
fn ack_view(conn: &Connection, ids: &[StreamId]) -> Vec<String> {
    let streams = &conn.sources.streams.streams;
    let id_of = |slot| streams.get_slot(slot).map(|stream| stream.id());
    let mut view: Vec<String> = ids
        .iter()
        .map(|&id| {
            let Some(stream) = streams.get(id) else {
                return format!("{id} reaped");
            };
            let send = stream.data().send.as_ref().map(|send| {
                let buf = &send.buf;
                (
                    buf.acked_end(),
                    buf.buffered(),
                    buf.has_lost(),
                    buf.is_acked(),
                    buf.final_size(),
                )
            });
            let lists = List::ALL.map(|list| streams.is_on(list, stream.slot()));
            format!(
                "{} {:?} {:?} {send:?} {lists:?} {:?}",
                stream.id(),
                stream.send_state(),
                stream.recv_state(),
                streams.prioritizer().order(stream.slot()),
            )
        })
        .collect();
    for list in List::ALL {
        let order: Vec<_> =
            std::iter::successors(streams.first(list), |&slot| streams.next_on(list, slot))
                .map(id_of)
                .collect();
        view.push(format!("{list:?} {order:?}"));
    }
    let scheduled: Vec<_> = streams.prioritizer().iter().map(id_of).collect();
    view.push(format!("scheduled {scheduled:?}, lost {}", streams.lost()));
    view
}

/// Checks that the twins' connections of `side` show the same streams `ids`, with consistent
/// indexes.
fn assert_twins_agree(twins: &mut [Pair; 2], side: Side, ids: &[StreamId], at: &str) {
    let [coalesced, reference] = twins.each_mut().map(|pair| {
        let conn = sender_and_peer(pair, side).0;
        conn.sources.streams.streams.assert_indexed();
        ack_view(conn, ids)
    });
    assert_eq!(
        coalesced, reference,
        "{at}: the streams after the ACK frame"
    );
}

#[test]
fn an_ack_frame_over_interleaved_runs_of_two_streams_reindexes_once_per_run() {
    let side = Side::Server;
    let mut twins = ack_twins(&Setup::default(), side);
    let now = twins[0].now;
    let (first, ids) = on_twins(&mut twins, side, "sending", |server, _| {
        let a = server.open_stream(Dir::Uni, ORDER).unwrap();
        let b = server.open_stream(Dir::Uni, ORDER).unwrap();
        let first = next_pn(server);
        // Two packets of A, two of B, two more of A and two more of B.
        for id in [a, b, a, b] {
            assert_eq!(send_on(server, id, 2_000, now), 2);
        }
        (first, [a, b])
    });

    let reindexed = ack_twins_at(
        &mut twins,
        side,
        now + Duration::from_millis(20),
        10,
        &(first..=first + 7),
        &[],
    );
    assert_eq!(
        reindexed,
        [4, 8],
        "one reindex per run, and one per packet for the reference"
    );
    assert_twins_agree(&mut twins, side, &ids, "interleaved runs");
    for id in ids {
        let acked = on_twins(&mut twins, side, "acknowledged", |server, _| {
            server.stream_send_buf(id).unwrap().acked_end()
        });
        assert_eq!(acked, 4_000, "{id}");
    }
}

#[test]
fn an_ack_frame_that_fails_after_a_run_still_applies_the_run() {
    let side = Side::Server;
    let mut twins = ack_twins(&Setup::default(), side);
    let now = twins[0].now;
    let (id, acked) = on_twins(&mut twins, side, "sending", |server, _| {
        let id = server.open_stream(Dir::Uni, ORDER).unwrap();
        let first = next_pn(server);
        assert_eq!(send_on(server, id, 4_000, now), 4);
        // Skips a packet number above the stream's packets: an ACK frame that covers it fails
        // after acknowledging the packets below it.
        let pn = next_pn(server) + 1;
        let last = server.recovery.space(Space::Data).outstanding().last();
        let tx_seq = last.unwrap().tx_seq;
        let recovery = &mut server.recovery;
        let recorded =
            recovery.on_packet_sent(Space::Data, pn, now, 50, SentFlags::empty(), tx_seq);
        assert_eq!(recorded, Ok(()));
        (id, first..=pn)
    });

    let at = now + Duration::from_millis(20);
    let reindexed = twins.each_mut().map(|pair| {
        let (conn, peer) = sender_and_peer(pair, side);
        let packet = ack_frame(peer, next_pn(peer) + 10, acked.clone(), &[]);
        let before = reindexes(conn);
        deliver(conn, at, peer_addr(side), packet);
        assert_eq!(
            local_close(conn),
            Some((
                TransportErrorCode::PROTOCOL_VIOLATION,
                Some(VarInt::from_u32(0x02))
            ))
        );
        reindexes(conn) - before
    });
    assert_eq!(
        reindexed,
        [1, 4],
        "one reindex for the run, and one per packet for the reference"
    );
    assert_twins_agree(&mut twins, side, &[id], "a failed ACK frame");
    let acked_end = on_twins(&mut twins, side, "acknowledged", |server, _| {
        server.stream_send_buf(id).unwrap().acked_end()
    });
    assert_eq!(acked_end, 4_000);
}

/// What the equivalence runs reached, so that runs that miss a case fail.
#[derive(Debug, Default)]
struct AckRunsSeen {
    /// ACK frames with more than one range.
    multi_range: usize,
    /// Packets declared lost.
    lost: usize,
    /// Acknowledgments of packets declared lost before.
    late: usize,
    /// Transmits that went out while a stream had lost data to send again.
    retransmits: usize,
    /// Streams whose bytes and FIN were all acknowledged.
    fins: usize,
    /// Streams reset with bytes in flight.
    resets: usize,
    /// The most streams taking bytes at once.
    most_streams: usize,
    /// `Progress` edges.
    progress: usize,
    /// Growths of acknowledged prefixes polled.
    acked: usize,
}

/// Returns a value below `n` from `rng`.
fn below(rng: &mut TestRng, n: u64) -> u64 {
    rng.next_u64() % n
}

/// Returns the packet numbers of the 1-RTT packets `conn` has in flight.
fn outstanding(conn: &Connection) -> BTreeSet<u64> {
    conn.recovery
        .space(Space::Data)
        .outstanding()
        .map(|packet| packet.pn)
        .collect()
}

/// Returns the ranges of a random ACK frame for packets `first..next`, from the largest down,
/// with gaps, and sometimes a range for a packet of `lost` below the others. Returns an empty list
/// for a step without an ACK frame.
fn random_ack_ranges(
    rng: &mut TestRng,
    first: u64,
    next: u64,
    lost: &BTreeSet<u64>,
) -> Vec<RangeInclusive<u64>> {
    let mut ranges = Vec::new();
    if next == first || below(rng, 6) == 0 {
        return ranges;
    }
    // The newest packets stay unacknowledged now and then.
    let mut hi = next - 1 - below(rng, 3).min(next - 1 - first);
    let floor = hi.saturating_sub(48).max(first);
    loop {
        let lo = hi.saturating_sub(below(rng, 12)).max(floor);
        ranges.push(lo..=hi);
        let gap = 1 + below(rng, 3);
        if ranges.len() == 4 || lo < floor + gap + 1 {
            break;
        }
        hi = lo - gap - 1;
    }
    let lowest = *ranges.last().expect("a range").start();
    let late: Vec<u64> = lost.range(..lowest.saturating_sub(1)).copied().collect();
    if !late.is_empty() && below(rng, 2) == 0 {
        let pn = late[below(rng, late.len() as u64) as usize];
        ranges.push(pn..=pn);
    }
    ranges
}

/// Runs `steps` random steps from `seed` on twins whose connections of `side` send on up to four
/// streams at a time: each step stages, finishes, resets and tracks, transmits, and delivers one
/// ACK frame, after which the twins must agree. Returns the reindexes each twin ran for its ACK
/// frames.
fn run_ack_twins(seed: u64, side: Side, steps: u64, seen: &mut AckRunsSeen) -> [u64; 2] {
    let window = 1 << 20;
    let transport = TransportConfig::builder()
        .max_data(16 * window)
        .max_stream_data_bidi_remote(window)
        .max_stream_data_uni(window)
        .stream_ack_progress(true)
        .build()
        .unwrap();
    let mut twins = ack_twins(&Setup::default().transport(transport), side);
    let mut rng = TestRng::new(seed);
    let streams = 1 + below(&mut rng, 4) as usize;
    // Streams that take bytes, streams that are not reaped yet, and every stream opened.
    let mut open: Vec<StreamId> = Vec::new();
    let mut live: Vec<StreamId> = Vec::new();
    let mut opened: Vec<StreamId> = Vec::new();
    let mut fins = BTreeSet::new();
    // Packets declared lost and not acknowledged since.
    let mut lost = BTreeSet::new();
    let first = on_twins(&mut twins, side, "start", |conn, _| next_pn(conn));
    let mut reindexed = [0; 2];
    for step in 0..steps {
        let at = format!("seed {seed}, step {step}");
        let now = twins[0].now;
        while open.len() < streams {
            let dir = if below(&mut rng, 2) == 0 {
                Dir::Uni
            } else {
                Dir::Bi
            };
            let order = SendOrder {
                class: 1,
                urgency: 2 + below(&mut rng, 2) as u8,
                incremental: below(&mut rng, 2) == 0,
                order: 0,
            };
            let id = on_twins(&mut twins, side, &at, |conn, _| {
                conn.open_stream(dir, order)
            })
            .expect("a stream within the limit");
            open.push(id);
            live.push(id);
            opened.push(id);
        }
        seen.most_streams = seen.most_streams.max(open.len());
        for id in open.clone() {
            let (acked, end, in_flight) = on_twins(&mut twins, side, &at, |conn, _| {
                let buf = conn.stream_send_buf(id).unwrap();
                (
                    buf.acked_end(),
                    buf.staged_end(),
                    buf.sent_end() > buf.acked_end(),
                )
            });
            match below(&mut rng, 24) {
                0 => {
                    on_twins(&mut twins, side, &at, |conn, _| {
                        conn.stream(id).unwrap().reset(AppCode::from_u32(7))
                    })
                    .unwrap();
                    seen.resets += usize::from(in_flight);
                    open.retain(|&other| other != id);
                }
                1 | 2 => {
                    on_twins(&mut twins, side, &at, |conn, _| {
                        conn.stream(id).unwrap().finish()
                    })
                    .unwrap();
                    open.retain(|&other| other != id);
                }
                3..=5 => {
                    // Sometimes past the end, which the FIN reaches.
                    let offset = acked + 1 + below(&mut rng, end - acked + 2);
                    on_twins(&mut twins, side, &at, |conn, _| {
                        conn.stream(id).unwrap().track(offset)
                    })
                    .unwrap();
                }
                _ => {
                    let len = below(&mut rng, 6_000) as usize;
                    on_twins(&mut twins, side, &at, |conn, _| {
                        let mut data = Bytes::from(vec![0x5a; len]);
                        conn.stream(id).unwrap().send(&mut data)
                    })
                    .unwrap();
                }
            }
        }
        for _ in 0..1 + below(&mut rng, 2) {
            let limits = TxLimits {
                max_segments: 1 + below(&mut rng, 16) as u16,
                ..limits(now)
            };
            let (had_lost, datagrams) = on_twins(&mut twins, side, &at, |conn, _| {
                let had_lost = conn.sources.streams.streams.lost() > 0;
                let sent = conn.poll_transmit(&limits, &mut VecSink::new(1500), &mut InlineSealer);
                (had_lost, sent.datagrams)
            });
            seen.retransmits += usize::from(had_lost && datagrams > 0);
        }

        let next = on_twins(&mut twins, side, &at, |conn, _| next_pn(conn));
        let ranges = random_ack_ranges(&mut rng, first, next, &lost);
        let before = on_twins(&mut twins, side, &at, |conn, _| outstanding(conn));
        let acked: BTreeSet<u64> = ranges.iter().flat_map(|range| range.clone()).collect();
        seen.late += on_twins(&mut twins, side, &at, |conn, _| {
            let sent = conn.recovery.space(Space::Data);
            acked
                .iter()
                .filter(|&&pn| lost.contains(&pn) && sent.get(pn).is_some())
                .count()
        });
        let dt = Duration::from_millis(1 + below(&mut rng, 25));
        for pair in &mut twins {
            pair.now += dt;
        }
        let now = twins[0].now;
        if let Some((largest, older)) = ranges.split_first() {
            seen.multi_range += usize::from(!older.is_empty());
            let [coalesced, reference] =
                ack_twins_at(&mut twins, side, now, 10 + step, largest, older);
            assert!(
                coalesced <= reference,
                "{at}: {coalesced} reindexes, {reference} for the reference"
            );
            reindexed[0] += coalesced;
            reindexed[1] += reference;
        }
        assert_twins_agree(&mut twins, side, &opened, &at);
        on_twins(&mut twins, side, &at, |conn, _| {
            if conn.next_deadline().is_some_and(|deadline| deadline <= now) {
                conn.on_deadline(now);
            }
        });
        let after = on_twins(&mut twins, side, &at, |conn, _| outstanding(conn));
        for &pn in before.difference(&after) {
            if !acked.contains(&pn) && lost.insert(pn) {
                seen.lost += 1;
            }
        }
        for pn in &acked {
            lost.remove(pn);
        }

        assert_twins_agree(&mut twins, side, &opened, &at);
        on_twins(&mut twins, side, &at, |conn, _| {
            let s = conn.stats();
            (
                s.sent_packets,
                s.lost_packets,
                s.cwnd,
                s.bytes_in_flight,
                s.acks_received,
            )
        });
        for &id in &live {
            let done = on_twins(&mut twins, side, &at, |conn, _| {
                conn.stream_send_buf(id).is_some_and(|buf| buf.is_acked())
            });
            if done {
                fins.insert(id);
            }
        }
        let edges = on_twins(&mut twins, side, &at, |conn, _| {
            conn.readiness().collect::<Vec<_>>()
        });
        seen.progress += edges
            .iter()
            .filter(|(_, edge)| *edge == StreamReady::Progress)
            .count();
        let growths = on_twins(&mut twins, side, &at, |conn, _| {
            std::iter::from_fn(|| conn.poll_stream_acked()).collect::<Vec<_>>()
        });
        seen.acked += growths.len();
        let reaped: Vec<StreamId> = live
            .iter()
            .copied()
            .filter(|&id| {
                on_twins(&mut twins, side, &at, |conn, _| {
                    conn.sources.streams.streams.get(id).is_none()
                })
            })
            .collect();
        live.retain(|id| !reaped.contains(id));
        open.retain(|id| !reaped.contains(id));
    }
    seen.fins += fins.len();
    reindexed
}

#[test]
fn ack_frames_leave_the_streams_as_acknowledging_each_frame_alone_does() {
    let mut seen = AckRunsSeen::default();
    let mut reindexed = [0; 2];
    for seed in 0..16 {
        let side = if seed % 2 == 0 {
            Side::Client
        } else {
            Side::Server
        };
        let [coalesced, reference] = run_ack_twins(seed, side, 48, &mut seen);
        reindexed[0] += coalesced;
        reindexed[1] += reference;
    }
    let AckRunsSeen {
        multi_range,
        lost,
        late,
        retransmits,
        fins,
        resets,
        most_streams,
        progress,
        acked,
    } = seen;
    assert!(
        [
            multi_range,
            lost,
            late,
            retransmits,
            fins,
            resets,
            progress,
            acked
        ]
        .iter()
        .all(|&n| n > 0),
        "{seen:?}"
    );
    assert_eq!(most_streams, 4, "{seen:?}");
    assert!(
        reindexed[0] < reindexed[1],
        "the ACK frames did not coalesce any run: {} reindexes, as many as the reference",
        reindexed[0]
    );
}

/// Returns the size of the connection and of the parts that it holds per packet number space, for
/// the handshake and per queued event. These are the sizes of a test build, whose types carry
/// test-only fields that a production build does not have.
fn layout() -> [(&'static str, usize); 9] {
    [
        ("Connection", size_of::<Connection>()),
        ("PacketSpace", size_of::<PacketSpace>()),
        ("AckSource", size_of::<AckSource>()),
        ("CryptoSource", size_of::<CryptoSource>()),
        ("SentPackets", size_of::<SentPackets>()),
        ("PeerParams", size_of::<PeerParams>()),
        ("Handshake", size_of::<Handshake>()),
        ("ConnEvent", size_of::<ConnEvent>()),
        ("EndpointEvent", size_of::<EndpointEvent>()),
    ]
}

#[test]
fn the_size_print_gives_the_connection_and_the_parts_it_holds() {
    let sizes = layout();
    println!("sizes in a test build, test-only fields included:");
    for (name, size) in sizes {
        println!("{name:>13}: {size:>5} bytes");
    }
    assert_eq!(
        sizes.map(|(name, _)| name),
        [
            "Connection",
            "PacketSpace",
            "AckSource",
            "CryptoSource",
            "SentPackets",
            "PeerParams",
            "Handshake",
            "ConnEvent",
            "EndpointEvent"
        ]
    );
    // The connection holds the other parts inline, and its queues hold the events on the heap.
    let [
        (_, connection),
        inline @ ..,
        (_, conn_event),
        (_, endpoint_event),
    ] = sizes;
    for (name, size) in inline {
        assert!(
            size > 0 && size < connection,
            "a {name} of {size} bytes inside a connection of {connection} bytes"
        );
    }
    assert!(
        conn_event > 0 && endpoint_event > 0,
        "events of {conn_event} and {endpoint_event} bytes"
    );
}

/// Returns a pair from the default setup, whose server sends session tickets, once both sides
/// are confirmed and have gone quiet.
fn confirmed_and_quiet() -> Pair {
    let (_, mut pair) = handshake(Setup::default().pair());
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    pair
}

#[test]
fn a_confirmed_connection_gives_its_crypto_page_to_the_endpoints_pool() {
    let pair = confirmed_and_quiet();
    for (side, peer) in [(Side::Server, &pair.server), (Side::Client, &pair.client)] {
        let conn = peer.conn();
        for space in [Space::Initial, Space::Handshake, Space::Data] {
            assert_eq!(
                conn.spaces[space.index()].crypto_recv.held_pages(),
                0,
                "the {side:?} holds no {space:?} CRYPTO page once confirmed"
            );
        }
        let pool = peer.endpoint.pages();
        assert_eq!(
            (pool.pages_allocated(), pool.memory()),
            (1, PAGE_SIZE),
            "the {side:?}'s handshake allocated one CRYPTO page, which its endpoint's pool holds"
        );
    }
}

#[test]
fn a_client_releases_the_crypto_page_of_its_tickets() {
    let pair = confirmed_and_quiet();
    let tickets = &pair.client.conn().spaces[Space::Data.index()].crypto_recv;
    assert!(
        tickets.read_offset() > 0,
        "the client read the server's session tickets"
    );
    assert_eq!(
        tickets.held_pages(),
        0,
        "the client releases the page of the tickets that it read"
    );
}

#[test]
fn discarded_spaces_free_their_ack_ranges_and_sent_packet_rings() {
    let cubic = Arc::new(TransportConfig::default());
    // A controller that takes rate samples also keeps send snapshots in the handshake spaces.
    let bbr3 = TransportConfig::builder()
        .congestion_control(CongestionControl::Bbr3)
        .pacing(true)
        .build()
        .expect("a valid transport config");
    let mut held = Vec::new();
    for transport in [cubic, bbr3] {
        let cc = transport.congestion_control();
        let (_, mut pair) = handshake(Setup::default().transport(transport).pair());
        pair.run(pair.now + Duration::from_millis(200));
        for (side, peer) in [(Side::Server, &pair.server), (Side::Client, &pair.client)] {
            let conn = peer.conn();
            for space in [Space::Initial, Space::Handshake] {
                assert!(
                    conn.spaces[space.index()].discarded,
                    "{cc:?} {side:?} {space:?}"
                );
                held.push((
                    (cc, side, space),
                    conn.sources.ack[space.index()].received().capacity(),
                    conn.recovery.space(space).capacities(),
                ));
            }
        }
    }
    // The capacity of the ACK ranges, then those of the record, frame, hole and snapshot rings.
    let none: Vec<_> = held.iter().map(|&(case, ..)| (case, 0, [0; 4])).collect();
    assert_eq!(held, none, "the memory of the discarded spaces");
}

#[test]
fn the_tls_output_buffer_is_freed_once_the_handshake_completes() {
    fn conn(pair: &Pair, side: Side) -> &Connection {
        match side {
            Side::Client => pair.client.conn(),
            Side::Server => pair.server.conn(),
        }
    }
    let (epoch, mut pair) = start(Setup::default().pair());
    let mut held = Vec::new();
    // The client completes its handshake a round trip before HANDSHAKE_DONE confirms it; the
    // server completes and confirms it at once.
    for side in [Side::Client, Side::Server] {
        assert!(pair.run_until(epoch + LIMIT, |pair| conn(pair, side).handshake.complete));
        let completed = conn(&pair, side);
        if side == Side::Client {
            assert!(
                !completed.handshake.confirmed,
                "the client is not yet confirmed"
            );
        }
        held.push((side, "complete", completed.tls_out.capacity()));
    }
    // A client reads session tickets after its handshake, and TLS writes nothing in answer.
    let quiet = pair.now + Duration::from_millis(200);
    pair.run(quiet);
    assert!(
        conn(&pair, Side::Client).spaces[Space::Data.index()]
            .crypto_recv
            .read_offset()
            > 0,
        "the client read the server's session tickets"
    );
    for side in [Side::Client, Side::Server] {
        held.push((side, "quiet", conn(&pair, side).tls_out.capacity()));
    }
    let none: Vec<_> = held
        .iter()
        .map(|&(side, moment, _)| (side, moment, 0))
        .collect();
    assert_eq!(held, none, "the capacity of the TLS output buffer");
}

#[test]
fn a_drained_endpoint_event_queue_holds_no_heap_after_the_handshake() {
    let mut held = Vec::new();
    // At the largest limit each side issues the most connection IDs, one NewLocalCid event each.
    for limit in [2, TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT] {
        let transport = TransportConfig::builder()
            .active_connection_id_limit(limit)
            .build()
            .expect("a valid transport config");
        let (_, mut pair) = handshake(Setup::default().transport(transport).pair());
        pair.run(pair.now + Duration::from_millis(200));
        // The pair drains each side's endpoint events as a driver does, until the queue is empty.
        for (side, peer) in [(Side::Server, &pair.server), (Side::Client, &pair.client)] {
            let conn = peer.conn();
            assert_eq!(
                conn.sources.cids.local.active(),
                limit,
                "the {side:?} issued its connection IDs"
            );
            assert!(conn.endpoint_events.is_empty(), "{side:?}");
            held.push(((limit, side), conn.endpoint_events.capacity()));
        }
    }
    let none: Vec<_> = held.iter().map(|&(case, _)| (case, 0)).collect();
    assert_eq!(
        held, none,
        "the capacity of the endpoint event queues, by active_connection_id_limit"
    );
}

#[test]
fn the_event_queue_grows_only_as_far_as_the_events_queued_at_once_and_keeps_that_room() {
    let (epoch, mut pair) = start(Setup::default().pair());
    // The pair drains each side's events at the end of every round of a step, so the events that
    // a side reports in one step bound those that its queue held at once.
    let (mut reported, mut most) = ([0; 2], [0; 2]);
    let mut track = |pair: &Pair| {
        for (at, peer) in [&pair.client, &pair.server].into_iter().enumerate() {
            most[at] = most[at].max(peer.events.len() - reported[at]);
            reported[at] = peer.events.len();
        }
    };
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        track(pair);
        pair.client.has_event(&ConnEvent::Confirmed) && pair.server.has_event(&ConnEvent::Confirmed)
    }));
    pair.run_until(pair.now + Duration::from_millis(200), |pair| {
        track(pair);
        false
    });
    let held: Vec<_> = [(Side::Client, &pair.client), (Side::Server, &pair.server)]
        .into_iter()
        .zip(most)
        .map(|((side, peer), most)| (side, most, peer.conn().events.capacity()))
        .collect();
    assert!(
        held.iter().all(|&(_, most, _)| (1..=4).contains(&most)),
        "each side queues between 1 and 4 events at once: {held:?}"
    );
    assert!(
        held.iter().all(|&(.., capacity)| capacity <= 4),
        "the capacity of the event queues, after at most 4 events at once: {held:?}"
    );
    // A burst of more events grows the queue, which keeps that room once drained, so events that
    // arrive with every receive batch, such as DatagramsReadable, do not allocate each time. An
    // event equal to a queued one is dropped, and the others come out in order.
    let migrated = PathEvent::Migrated {
        remote: client_addr(),
    };
    let failed = PathEvent::ValidationFailed {
        remote: server_addr(),
    };
    let burst = [
        ConnEvent::StreamsAvailable { dir: Dir::Bi },
        ConnEvent::DatagramsReadable,
        ConnEvent::StreamsAvailable { dir: Dir::Uni },
        ConnEvent::DatagramsReadable,
        ConnEvent::Path(migrated),
        ConnEvent::Quiet,
        ConnEvent::StreamsAvailable { dir: Dir::Bi },
        ConnEvent::Path(failed),
    ];
    let server = pair.server.conn_mut();
    for event in burst {
        server.push_event(event);
    }
    let room = server.events.capacity();
    let polled: Vec<_> = std::iter::from_fn(|| server.poll_event()).collect();
    assert_eq!(
        polled,
        [
            ConnEvent::StreamsAvailable { dir: Dir::Bi },
            ConnEvent::DatagramsReadable,
            ConnEvent::StreamsAvailable { dir: Dir::Uni },
            ConnEvent::Path(migrated),
            ConnEvent::Quiet,
            ConnEvent::Path(failed),
        ],
        "the burst, once each and in order"
    );
    assert!(room >= polled.len(), "a queue of {room} events");
    server.push_event(ConnEvent::DatagramsReadable);
    assert_eq!(server.poll_event(), Some(ConnEvent::DatagramsReadable));
    assert_eq!(
        server.events.capacity(),
        room,
        "the drained queue keeps the room of the burst"
    );
}
