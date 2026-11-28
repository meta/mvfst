/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Stream and flow control tests over the pair harness of [`crate::testing`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::PacketType;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use super::Connection;
use super::tests::Forge;
use super::tests::LIMIT;
use super::tests::client_addr;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::local_close;
use super::tests::open_own;
use super::tests::open_own_one_rtt;
use super::tests::server_addr;
use super::tests::start;
use crate::AppCode;
use crate::CongestionControl;
use crate::ConnEvent;
use crate::CreditDue;
use crate::InlineSealer;
use crate::OpenError;
use crate::Prioritizer;
use crate::SendError;
use crate::SendOrder;
use crate::Stop;
use crate::StreamError;
use crate::StreamMut;
use crate::StreamReady;
use crate::TransportConfig;
use crate::TxLimits;
use crate::cc::Cc;
use crate::cc::CcConfig;
use crate::config::TransportConfigBuilder;
use crate::recovery::Space;
use crate::streams::guard::List;
use crate::streams::guard::Owed;
use crate::streams::guard::census;
use crate::streams::state::RecvState;
use crate::streams::state::SendState;
use crate::testing::Loss;
use crate::testing::Pair;
use crate::testing::PairConfig;
use crate::testing::Peer;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

/// Comfortably more than the pair's round trip of 20 ms.
pub(super) const RTT: Duration = Duration::from_millis(100);

/// A sequential order in the default bucket.
pub(super) const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

fn id(side: Side, dir: Dir, index: u64) -> StreamId {
    StreamId::new(side, dir, index).expect("a valid stream index")
}

pub(super) fn config(
    f: impl FnOnce(TransportConfigBuilder) -> TransportConfigBuilder,
) -> Arc<TransportConfig> {
    f(TransportConfig::builder())
        .build()
        .expect("a valid transport config")
}

#[test]
fn open_stream_is_held_to_the_peers_stream_limits() {
    let setup = Setup {
        server_transport: config(|c| c.max_streams_bidi(2).max_streams_uni(1)),
        ..Setup::default()
    };
    let (epoch, mut pair) = start(setup.pair());
    assert_eq!(
        pair.client.conn_mut().open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit),
        "no limit is known before the server's transport parameters"
    );
    assert!(pair.handshake(epoch + LIMIT));
    let client = pair.client.conn_mut();
    assert_eq!(
        client.open_stream(Dir::Bi, ORDER),
        Ok(id(Side::Client, Dir::Bi, 0))
    );
    assert_eq!(
        client.open_stream(Dir::Bi, ORDER),
        Ok(id(Side::Client, Dir::Bi, 1))
    );
    assert_eq!(
        client.open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
    assert_eq!(
        client.open_stream(Dir::Uni, ORDER),
        Ok(id(Side::Client, Dir::Uni, 0))
    );
    assert_eq!(
        client.open_stream(Dir::Uni, ORDER),
        Err(OpenError::StreamLimit)
    );
    let server = pair.server.conn_mut();
    assert_eq!(
        server.open_stream(Dir::Uni, ORDER),
        Ok(id(Side::Server, Dir::Uni, 0))
    );
}

#[test]
fn an_open_refused_before_the_peers_limits_arrive_hears_of_them_and_sends_no_blocked_frame() {
    let (epoch, mut pair) = start(Setup::default().pair());
    assert_eq!(
        pair.client.conn_mut().open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
    assert!(pair.handshake(epoch + LIMIT));
    pair.run(pair.now + RTT);
    assert!(
        pair.client
            .has_event(&ConnEvent::StreamsAvailable { dir: Dir::Bi }),
        "the transport parameters raised the limit the open failed at"
    );
    assert!(
        !pair
            .client
            .has_event(&ConnEvent::StreamsAvailable { dir: Dir::Uni }),
        "no unidirectional open failed"
    );
    assert!(
        !all_sent_frames(&pair.client)
            .iter()
            .any(|f| matches!(f, Sent::StreamsBlocked(..))),
        "the client is not blocked once it has the server's limits"
    );
    assert!(pair.client.conn_mut().open_stream(Dir::Bi, ORDER).is_ok());
}

#[test]
fn stream_hands_out_open_streams_only() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let client = pair.client.conn_mut();
    let first = id(Side::Client, Dir::Bi, 0);
    assert_eq!(
        client.stream(first).err(),
        Some(StreamError::Closed),
        "not opened yet"
    );
    assert_eq!(client.open_stream(Dir::Bi, ORDER), Ok(first));
    assert_eq!(client.stream(first).map(|s| s.id()).ok(), Some(first));
    assert_eq!(
        client.stream(id(Side::Server, Dir::Bi, 0)).err(),
        Some(StreamError::Closed),
        "the server opened nothing"
    );
}

#[test]
fn a_peer_stream_opened_implicitly_by_a_higher_one_is_there_to_use() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let (mut client, mut server) = (App::default(), App::default());
    let conn = pair.client.conn_mut();
    let [lower, higher] = [(); 2].map(|()| conn.open_stream(Dir::Bi, ORDER).unwrap());
    client.write(higher, &b"request"[..], true);
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(server.data[&higher], b"request");
    assert_eq!(server.edges_of(lower), [], "no frame named it");
    let mut stream = pair
        .server
        .conn_mut()
        .stream(lower)
        .expect("opened with the higher stream, as RFC 9000 requires");
    assert_eq!(stream.send(&mut Bytes::from_static(b"early")), Ok(5));
    assert_eq!(stream.finish(), Ok(()));
    let until = pair.now + 2 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(client.data[&lower], b"early");
    assert_eq!(
        pair.server
            .conn_mut()
            .stream(id(Side::Client, Dir::Bi, 2))
            .err(),
        Some(StreamError::Closed),
        "not opened"
    );
}

#[test]
fn send_takes_what_the_stream_credit_and_the_staging_cap_allow() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(10_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let client = pair.client.conn_mut();
    let bidi = client.open_stream(Dir::Bi, ORDER).unwrap();
    let uni = client.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = client.stream(bidi).unwrap();
    assert_eq!(stream.send_capacity(), 10_000, "the server's window");
    let mut data = Bytes::from(vec![7; 4_000]);
    assert_eq!(stream.send(&mut data), Ok(4_000));
    assert!(data.is_empty());
    assert_eq!(stream.send_capacity(), 6_000);
    let mut data = Bytes::from(vec![7; 8_000]);
    assert_eq!(
        stream.send(&mut data),
        Ok(6_000),
        "the longest prefix within the credit"
    );
    assert_eq!(data.len(), 2_000);
    assert_eq!(stream.send_capacity(), 0);
    let stream = client.stream(uni).unwrap();
    assert_eq!(
        stream.send_capacity(),
        64 * 1024,
        "the per-stream staging cap"
    );
}

/// Returns the readable bytes of a stream, flattened.
fn readable(stream: &StreamMut<'_>) -> Vec<u8> {
    stream
        .readable()
        .segments()
        .flat_map(|s| s.to_vec())
        .collect()
}

/// Returns every readiness edge the connection reports now.
fn edges(conn: &mut Connection) -> Vec<(StreamId, StreamReady)> {
    conn.readiness().collect()
}

/// An application that drains its connection's readiness, reading every readable byte.
#[derive(Debug, Default)]
pub(super) struct App {
    /// Every edge, in order.
    edges: Vec<(StreamId, StreamReady)>,
    /// The bytes read, by stream.
    pub(super) data: BTreeMap<StreamId, Vec<u8>>,
    /// Bytes to push on each stream as its allowance takes them, then the FIN if set.
    out: BTreeMap<StreamId, (Bytes, bool)>,
}

impl App {
    /// Queues `data` for stream `id`, ended with the FIN if `fin`.
    pub(super) fn write(&mut self, id: StreamId, data: impl Into<Bytes>, fin: bool) {
        self.out.insert(id, (data.into(), fin));
    }

    fn poll(&mut self, conn: &mut Connection) {
        self.out.retain(|&id, (data, fin)| {
            let Ok(mut stream) = conn.stream(id) else {
                return false;
            };
            if stream.send(data).is_err() {
                return false;
            }
            if !data.is_empty() {
                return true;
            }
            if *fin {
                stream.finish().expect("an open send half");
            }
            false
        });
        loop {
            let next = conn.readiness().next();
            let Some((id, edge)) = next else {
                return;
            };
            self.edges.push((id, edge));
            if matches!(
                edge,
                StreamReady::Opened | StreamReady::Readable | StreamReady::Finished
            ) && let Ok(mut stream) = conn.stream(id)
            {
                let bytes = readable(&stream);
                stream.consume(bytes.len()).expect("the readable bytes");
                self.data.entry(id).or_default().extend(bytes);
            }
        }
    }

    /// Returns the edges of stream `id`.
    pub(super) fn edges_of(&self, id: StreamId) -> Vec<StreamReady> {
        self.edges
            .iter()
            .filter(|(of, _)| *of == id)
            .map(|(_, edge)| *edge)
            .collect()
    }
}

/// Runs the pair until `until`, letting both applications poll after every step.
pub(super) fn run_apps(pair: &mut Pair, until: Instant, client: &mut App, server: &mut App) {
    loop {
        pair.step();
        client.poll(pair.client.conn_mut());
        server.poll(pair.server.conn_mut());
        pair.step();
        match pair.next_event() {
            Some(at) if at <= until => pair.now = pair.now.max(at),
            _ => {
                pair.now = pair.now.max(until);
                return;
            }
        }
    }
}

#[test]
fn stream_bytes_and_the_fin_reach_the_peer_with_opened_readable_and_finished_edges() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let client = pair.client.conn_mut();
    let a = client.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = client.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.finish(), Ok(()));
    pair.run(pair.now + RTT);
    let server = pair.server.conn_mut();
    assert_eq!(
        edges(server),
        [
            (a, StreamReady::Opened),
            (a, StreamReady::Readable),
            (a, StreamReady::Finished)
        ]
    );
    let mut stream = server.stream(a).unwrap();
    assert_eq!(readable(&stream), b"hello");
    assert_eq!(stream.consume(5), Ok(CreditDue::NotDue));
    assert!(stream.readable().is_empty());
    assert_eq!(edges(server), [], "consuming reports nothing");
}

#[test]
fn a_stream_whose_halves_both_end_is_reported_closed_and_reaped() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let (mut client, mut server) = (App::default(), App::default());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    stream.send(&mut Bytes::from_static(b"ping")).unwrap();
    stream.finish().unwrap();
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(server.data[&a], b"ping");
    let mut stream = pair.server.conn_mut().stream(a).unwrap();
    stream.send(&mut Bytes::from_static(b"pong")).unwrap();
    stream.finish().unwrap();
    let until = pair.now + 3 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(client.data[&a], b"pong");
    use StreamReady::*;
    assert_eq!(client.edges_of(a), [Readable, Finished, Closed]);
    assert_eq!(server.edges_of(a), [Opened, Readable, Finished, Closed]);
    assert_eq!(
        pair.client.conn_mut().stream(a).err(),
        Some(StreamError::Closed)
    );
    assert_eq!(
        pair.server.conn_mut().stream(a).err(),
        Some(StreamError::Closed)
    );
}

/// A frame a peer sent, without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Stream {
        id: StreamId,
        offset: u64,
        len: usize,
        fin: bool,
    },
    MaxData(u64),
    MaxStreamData(StreamId, u64),
    MaxStreams(Dir, u64),
    DataBlocked(u64),
    StreamDataBlocked(StreamId, u64),
    StreamsBlocked(Dir, u64),
    ResetStream {
        id: StreamId,
        code: u64,
        final_size: u64,
    },
    StopSending(StreamId, u64),
    Other,
}

/// Returns the frames of the 1-RTT packets `peer` sent from its datagram `from` on; earlier
/// datagrams may hold packets of discarded spaces.
fn sent_frames(peer: &Peer, from: usize) -> Vec<Sent> {
    frames_in(peer, from..peer.sent.len())
}

/// Returns the frames of the 1-RTT packets in `peer`'s datagrams `range`.
fn frames_in(peer: &Peer, range: std::ops::Range<usize>) -> Vec<Sent> {
    let mut out = Vec::new();
    for (_, datagram) in &peer.sent[range] {
        for (ty, plaintext) in open_own(peer.conn(), &datagram.data) {
            assert_eq!(ty, PacketType::OneRtt);
            push_frames(&mut out, &plaintext);
        }
    }
    out
}

/// Returns the frames of every 1-RTT packet `peer` sent, the handshake's included.
fn all_sent_frames(peer: &Peer) -> Vec<Sent> {
    let mut out = Vec::new();
    for (_, datagram) in &peer.sent {
        for plaintext in open_own_one_rtt(peer.conn(), &datagram.data) {
            push_frames(&mut out, &plaintext);
        }
    }
    out
}

/// Appends the frames of a 1-RTT packet's `plaintext` to `out`.
fn push_frames(out: &mut Vec<Sent>, plaintext: &[u8]) {
    for frame in Frames::new(plaintext) {
        out.push(match frame.expect("a frame it wrote") {
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => Sent::Stream {
                id,
                offset: offset.into_inner(),
                len: data.len(),
                fin,
            },
            Frame::MaxData(max) => Sent::MaxData(max.into_inner()),
            Frame::MaxStreamData { id, max } => Sent::MaxStreamData(id, max.into_inner()),
            Frame::MaxStreams { dir, max } => Sent::MaxStreams(dir, max.into_inner()),
            Frame::DataBlocked(limit) => Sent::DataBlocked(limit.into_inner()),
            Frame::StreamDataBlocked { id, limit } => {
                Sent::StreamDataBlocked(id, limit.into_inner())
            }
            Frame::StreamsBlocked { dir, limit } => Sent::StreamsBlocked(dir, limit.into_inner()),
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => Sent::ResetStream {
                id,
                code: error_code.into_inner(),
                final_size: final_size.into_inner(),
            },
            Frame::StopSending { id, error_code } => Sent::StopSending(id, error_code.into_inner()),
            _ => Sent::Other,
        });
    }
}

/// Returns `len` bytes that differ from offset to offset.
pub(super) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_sender_held_to_the_stream_window_resumes_as_the_reader_consumes() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (mut client, mut server) = (App::default(), App::default());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    client.write(a, pattern(40_000), true);
    let until = pair.now + 20 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(server.data[&a].len(), 40_000);
    assert!(server.data[&a] == pattern(40_000));
    assert_eq!(server.edges_of(a).last(), Some(&StreamReady::Finished));
}

#[test]
fn a_sender_at_the_stream_limit_says_so_and_the_receiver_answers_with_credit() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(pattern(8_000))), Ok(8_000));
    // The server does not read, so only the blocked frame makes it send MAX_STREAM_DATA.
    pair.run(pair.now + 3 * RTT);
    let client_sent = sent_frames(&pair.client, client_from);
    assert_eq!(
        client_sent
            .iter()
            .filter(|f| matches!(f, Sent::StreamDataBlocked(..)))
            .collect::<Vec<_>>(),
        [&Sent::StreamDataBlocked(a, 8_000)],
        "once, at the limit"
    );
    assert!(
        sent_frames(&pair.server, server_from).contains(&Sent::MaxStreamData(a, 8_000)),
        "the server repeats its limit when told the client is blocked"
    );
}

#[test]
fn a_sender_refused_bytes_at_zero_stream_credit_says_so_and_resumes_when_credit_arrives() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(0)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let client_from = pair.client.sent.len();
    let conn = pair.client.conn_mut();
    let [a, b] = [(); 2].map(|()| conn.open_stream(Dir::Bi, ORDER).unwrap());
    let mut rest = Bytes::from(pattern(1_000));
    assert_eq!(conn.stream(a).unwrap().send(&mut rest), Ok(0));
    assert_eq!(
        conn.stream(b)
            .unwrap()
            .send_parts(Bytes::from_static(b"head"), Bytes::from(pattern(100))),
        Err(SendError::OverAllowance)
    );
    pair.run(pair.now + RTT);
    let sent = sent_frames(&pair.client, client_from);
    for id in [a, b] {
        assert_eq!(
            count(&sent, Sent::StreamDataBlocked(id, 0)),
            1,
            "{id}: once, at the zero limit"
        );
    }
    assert_eq!(
        edges(pair.server.conn_mut()),
        [(a, StreamReady::Opened), (b, StreamReady::Opened)],
        "the blocked frames open the streams at the server"
    );
    // A server that grants credit on request answers with MAX_STREAM_DATA.
    let now = pair.now;
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let frames = [a, b].map(|id| Frame::MaxStreamData {
        id,
        max: varint(1_000),
    });
    let packet = Forge::of(server, Space::Data, pn, &frames).seal(server);
    let client = pair.client.conn_mut();
    deliver(client, now, server_addr(), packet);
    assert_eq!(
        edges(client),
        [(a, StreamReady::Writable), (b, StreamReady::Writable)]
    );
    assert_eq!(client.stream(a).unwrap().send(&mut rest), Ok(1_000));
}

#[test]
fn senders_held_to_the_connection_window_resume_as_the_reader_consumes() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(16_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (mut client, mut server) = (App::default(), App::default());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let b = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    client.write(a, pattern(30_000), true);
    client.write(b, pattern(30_000), true);
    let until = pair.now + 30 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    for id in [a, b] {
        assert_eq!(server.data.get(&id).map(Vec::len), Some(30_000));
        assert!(server.data[&id] == pattern(30_000));
    }
}

#[test]
fn a_sender_out_of_connection_credit_says_so_and_stops_on_connection_flow_control() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(5_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(pattern(8_000))), Ok(8_000));
    pair.run(pair.now + 3 * RTT);
    let client_sent = sent_frames(&pair.client, client_from);
    let new_bytes: usize = client_sent
        .iter()
        .map(|f| match f {
            Sent::Stream { len, .. } => *len,
            _ => 0,
        })
        .sum();
    assert_eq!(new_bytes, 5_000);
    assert_eq!(
        client_sent
            .iter()
            .filter(|f| matches!(f, Sent::DataBlocked(_)))
            .collect::<Vec<_>>(),
        [&Sent::DataBlocked(5_000)],
        "once, at the limit"
    );
    assert!(sent_frames(&pair.server, server_from).contains(&Sent::MaxData(5_000)));
    let limits = pair.limits();
    assert_eq!(
        pair.client.conn().explain_transmit(&limits).stop,
        Stop::ConnFlowControl
    );
}

/// How a test ends a send half, dropping its staged bytes unsent.
#[derive(Clone, Copy, Debug)]
enum DropBy {
    /// The application resets the stream.
    Reset,
    /// The peer's STOP_SENDING resets it.
    Stopped,
}

/// Ends stream `id`'s send half at the client as `how` selects, dropping its staged bytes. The
/// tests step the pair at this instant to check what the client sends, but must not run it on in
/// time, as after [`to_client`].
fn drop_staged(pair: &mut Pair, id: StreamId, how: DropBy) {
    match how {
        DropBy::Reset => {
            let mut stream = pair.client.conn_mut().stream(id).unwrap();
            assert_eq!(stream.reset(AppCode::from_u32(1)), Ok(()));
        }
        DropBy::Stopped => to_client(
            pair,
            &[Frame::StopSending {
                id,
                error_code: varint(1),
            }],
        ),
    }
}

#[test]
fn a_data_blocked_frame_owed_only_for_bytes_a_reset_or_stop_sending_drops_is_not_sent() {
    for how in [DropBy::Reset, DropBy::Stopped] {
        let setup = Setup {
            server_transport: config(|c| c.max_data(5_000)),
            ..Setup::default()
        };
        let (_, mut pair) = handshake(setup.pair());
        let conn = pair.client.conn_mut();
        let [a, b, c] = [(); 3].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
        let mut stream = conn.stream(a).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(5_000))), Ok(5_000));
        // The connection credit goes out before more is staged, so the client is not blocked yet.
        pair.step();
        let from = pair.client.sent.len();
        let mut stream = pair.client.conn_mut().stream(b).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(1_000))), Ok(1_000));
        drop_staged(&mut pair, b, how);
        pair.step();
        let sent = sent_frames(&pair.client, from);
        assert_eq!(
            count(&sent, Sent::DataBlocked(5_000)),
            0,
            "{how:?}: {sent:?}"
        );
        // Bytes that later wait at the same limit make the frame due again.
        let from = pair.client.sent.len();
        let mut stream = pair.client.conn_mut().stream(c).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(1_000))), Ok(1_000));
        pair.step();
        let sent = sent_frames(&pair.client, from);
        assert_eq!(
            count(&sent, Sent::DataBlocked(5_000)),
            1,
            "{how:?}: {sent:?}"
        );
    }
}

#[test]
fn a_stream_data_blocked_frame_owed_before_a_reset_or_stop_sending_is_not_sent() {
    for how in [DropBy::Reset, DropBy::Stopped] {
        let setup = Setup {
            server_transport: config(|c| c.max_stream_data_uni(0)),
            ..Setup::default()
        };
        let (_, mut pair) = handshake(setup.pair());
        let from = pair.client.sent.len();
        let a = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
        let mut stream = pair.client.conn_mut().stream(a).unwrap();
        assert_eq!(
            stream.send(&mut Bytes::from(pattern(1_000))),
            Ok(0),
            "refused at zero stream credit, which owes STREAM_DATA_BLOCKED"
        );
        drop_staged(&mut pair, a, how);
        pair.step();
        let sent = sent_frames(&pair.client, from);
        assert_eq!(
            count(&sent, Sent::StreamDataBlocked(a, 0)),
            0,
            "{how:?}: {sent:?}"
        );
    }
}

#[test]
fn a_lost_data_blocked_frame_for_bytes_a_reset_dropped_does_not_go_again() {
    // The client spends its 5,000 bytes of connection credit, stages more on another stream,
    // sends DATA_BLOCKED for them and then resets that stream, with its datagrams `dropped`
    // lost. The server does not read, so the limit stays where it is.
    let round = |dropped: Vec<usize>| {
        let mut config = Setup {
            server_transport: config(|c| c.max_data(5_000)),
            ..Setup::default()
        }
        .pair();
        config.to_server.loss = Loss::Drop(dropped);
        let (_, mut pair) = handshake(config);
        let conn = pair.client.conn_mut();
        let [a, b] = [(); 2].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
        let mut stream = conn.stream(a).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(5_000))), Ok(5_000));
        pair.step();
        let from = pair.client.sent.len();
        let mut stream = pair.client.conn_mut().stream(b).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(1_000))), Ok(1_000));
        pair.step();
        drop_staged(&mut pair, b, DropBy::Reset);
        pair.run(pair.now + 10 * RTT);
        (pair, from)
    };
    let blocked = Sent::DataBlocked(5_000);
    let (probe, from) = round(Vec::new());
    let lost = datagram_with(&probe.client, from, blocked);
    let (pair, from) = round(vec![lost]);
    assert!(
        pair.client.conn().stats().lost_packets > 0,
        "the loss was detected"
    );
    assert_eq!(count(&sent_frames(&pair.client, from), blocked), 1);
}

#[test]
fn bytes_staged_at_the_limit_after_a_lost_data_blocked_frame_for_dropped_bytes_owe_it_again() {
    // The client spends its 5,000 bytes of connection credit on `c`, whose frame opens `b` at
    // the server, and `a`. It stages more on `b` and writes DATA_BLOCKED for them in the
    // datagrams `dropped`; a reset or the server's STOP_SENDING drops those bytes before the
    // loss is declared. The server does not read, so the limit stays where it is.
    let round = |how: DropBy, dropped: Vec<usize>| {
        let mut config = Setup {
            server_transport: config(|c| c.max_data(5_000)),
            ..Setup::default()
        }
        .pair();
        config.to_server.loss = Loss::Drop(dropped);
        let (_, mut pair) = handshake(config);
        let conn = pair.client.conn_mut();
        let [a, b, c] = [(); 3].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
        for (id, len) in [(c, 1_000), (a, 4_000)] {
            let mut stream = conn.stream(id).unwrap();
            assert_eq!(stream.send(&mut Bytes::from(pattern(len))), Ok(len));
        }
        pair.step();
        let from = pair.client.sent.len();
        let mut stream = pair.client.conn_mut().stream(b).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(1_000))), Ok(1_000));
        pair.step();
        match how {
            DropBy::Reset => drop_staged(&mut pair, b, how),
            DropBy::Stopped => {
                let until = pair.now + RTT;
                let opened = |p: &Pair| p.server.conn().sources.streams.streams.get(c).is_some();
                assert!(pair.run_until(until, opened));
                let mut stream = pair.server.conn_mut().stream(b).unwrap();
                assert_eq!(stream.stop_sending(AppCode::from_u32(1)), Ok(()));
                let reset = |p: &Pair| {
                    matches!(send_state(&p.client, b), Some(SendState::ResetSent { .. }))
                };
                assert!(pair.run_until(until, reset));
            }
        }
        assert_eq!(
            pair.client.conn().stats().lost_packets,
            0,
            "{how:?}: the bytes are dropped while the frame is in flight"
        );
        pair.run(pair.now + 10 * RTT);
        (pair, a, from)
    };
    let blocked = Sent::DataBlocked(5_000);
    for how in [DropBy::Reset, DropBy::Stopped] {
        let (probe, _, from) = round(how, Vec::new());
        let lost = datagram_with(&probe.client, from, blocked);
        let (mut pair, a, from) = round(how, vec![lost]);
        assert!(
            pair.client.conn().stats().lost_packets > 0,
            "{how:?}: the loss was detected"
        );
        assert_eq!(
            count(&sent_frames(&pair.client, from), blocked),
            1,
            "{how:?}: not sent again while nothing waits"
        );
        let mut stream = pair.client.conn_mut().stream(a).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(1_000))), Ok(1_000));
        pair.run(pair.now + RTT);
        let sent = sent_frames(&pair.client, from);
        assert_eq!(count(&sent, blocked), 2, "{how:?}: {sent:?}");
    }
}

/// Counts the stream bytes of `id` that `sent` carries at or past `from`.
fn bytes_from(sent: &[Sent], id: StreamId, from: u64) -> usize {
    sent.iter()
        .map(|f| match *f {
            Sent::Stream {
                id: of,
                offset,
                len,
                ..
            } if of == id && offset >= from => len,
            _ => 0,
        })
        .sum()
}

/// Consumes every readable byte of stream `id`.
fn read_all(conn: &mut Connection, id: StreamId) -> CreditDue {
    let mut stream = conn.stream(id).unwrap();
    let n = stream.readable().chain_length();
    stream.consume(n).unwrap()
}

#[test]
fn stream_credit_that_arrives_while_the_connection_credit_is_spent_is_used_once_it_returns() {
    // `a`, `b` and `c` spend the whole connection window, and `a` its whole stream window.
    let setup = Setup {
        server_transport: config(|c| c.max_data(10_000).max_stream_data_bidi_remote(4_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let client_from = pair.client.sent.len();
    let client = pair.client.conn_mut();
    let [a, b, c] = [(); 3].map(|()| client.open_stream(Dir::Bi, ORDER).unwrap());
    for (id, len) in [(a, 4_000), (b, 4_000), (c, 2_000)] {
        let mut stream = client.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(len))), Ok(len));
    }
    pair.run(pair.now + 2 * RTT);
    // Reading `a` earns it stream credit; the connection window is not yet half consumed, so
    // MAX_STREAM_DATA arrives while the client's connection credit is spent.
    assert_eq!(read_all(pair.server.conn_mut(), a), CreditDue::Due);
    pair.run(pair.now + 2 * RTT);
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send_capacity(), 4_000);
    assert_eq!(stream.send(&mut Bytes::from(pattern(4_000))), Ok(4_000));
    let limits = pair.limits();
    assert_eq!(
        pair.client.conn().explain_transmit(&limits).stop,
        Stop::ConnFlowControl
    );
    // DATA_BLOCKED brings MAX_DATA with the consumed bytes, and `a` sends what its stream
    // credit allows.
    pair.run(pair.now + 2 * RTT);
    let sent = sent_frames(&pair.client, client_from);
    assert!(sent.contains(&Sent::DataBlocked(10_000)));
    assert_eq!(bytes_from(&sent, a, 4_000), 4_000);
}

#[test]
fn stream_credit_that_arrives_while_bytes_stay_staged_is_offered_though_the_room_is_small() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(5_000).max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut rest = Bytes::from(pattern(10_000));
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut rest), Ok(8_000));
    pair.run(pair.now + 3 * RTT);
    assert_eq!(
        pair.client.conn().sources.streams.staged,
        3_000,
        "what the connection credit did not let out"
    );
    to_client(
        &mut pair,
        &[Frame::MaxStreamData {
            id: a,
            max: varint(16_000),
        }],
    );
    // 8,000 bytes of room, below 16 KiB, with 3,000 bytes still staged: the stream credit caps
    // the low-water mark, so the room reaches it.
    let conn = pair.client.conn_mut();
    assert_eq!(edges(conn), [(a, StreamReady::Writable)]);
    conn.stream(a).unwrap().wake_producer();
    assert_eq!(conn.pull_ready().collect::<Vec<_>>(), [(a, 8_000)]);
    assert_eq!(conn.stream(a).unwrap().send(&mut rest), Ok(2_000));
}

/// Returns the code and frame type of the CONNECTION_CLOSE the server reports after one client
/// 1-RTT packet carrying `frames`.
fn server_close_on(
    setup: &Setup,
    frames: &[Frame<'_>],
) -> Option<(TransportErrorCode, Option<VarInt>)> {
    let (_, mut pair) = handshake(setup.pair());
    let now = pair.now;
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Data).next_pn() + 10;
    let packet = Forge::of(client, Space::Data, pn, frames).seal(client);
    let server = pair.server.conn_mut();
    deliver(server, now, client_addr(), packet);
    local_close(server)
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

/// STREAM, with the length field: frame type 0x0a, plus 0x04 with an offset and 0x01 with the
/// FIN. The error reports the type the frame kind maps to.
const STREAM_TYPE: u32 = 0x08;

#[test]
fn stream_data_past_a_receive_limit_is_a_flow_control_error() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(20_000).max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    };
    let a = id(Side::Client, Dir::Bi, 0);
    let b = id(Side::Client, Dir::Bi, 1);
    let flow_control = Some((
        TransportErrorCode::FLOW_CONTROL_ERROR,
        Some(VarInt::from_u32(STREAM_TYPE)),
    ));
    let past_stream = [Frame::Stream {
        id: a,
        offset: varint(7_999),
        data: &[0, 0],
        fin: false,
    }];
    assert_eq!(server_close_on(&setup, &past_stream), flow_control);
    // Each stream within its window; their highest offsets sum past the connection's.
    let past_connection = [
        Frame::Stream {
            id: a,
            offset: varint(7_999),
            data: &[0],
            fin: false,
        },
        Frame::Stream {
            id: b,
            offset: varint(7_999),
            data: &[0],
            fin: false,
        },
        Frame::Stream {
            id: id(Side::Client, Dir::Bi, 2),
            offset: varint(4_000),
            data: &[0],
            fin: false,
        },
    ];
    assert_eq!(server_close_on(&setup, &past_connection), flow_control);
    let within = [Frame::Stream {
        id: a,
        offset: varint(7_999),
        data: &[0],
        fin: false,
    }];
    assert_eq!(server_close_on(&setup, &within), None);
}

/// RESET_STREAM's frame type.
const RESET_STREAM_TYPE: u32 = 0x04;

#[test]
fn out_of_order_ranges_past_the_connections_cap_are_a_protocol_violation() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let mut forge = ToServer::new(&pair);
    let gaps = |stream: u64| {
        let id = id(Side::Client, Dir::Uni, stream);
        (1..=1024).map(move |k| stream_frame(id, 2 * k, 1, false))
    };
    // Eight streams of 1,024 one-byte ranges each: each stream is at its cap of out-of-order
    // ranges, and together they are at the connection's cap of 8,192.
    let frames: Vec<_> = (0..8).flat_map(gaps).collect();
    for packet in frames.chunks(100) {
        forge.send(&mut pair, packet);
    }
    assert_eq!(local_close(pair.server.conn_mut()), None);
    let one_more: Vec<_> = gaps(8).take(1).collect();
    forge.send(&mut pair, &one_more);
    assert_eq!(
        local_close(pair.server.conn_mut()),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(STREAM_TYPE))
        ))
    );
}

#[test]
fn frames_that_contradict_a_final_size_are_a_final_size_error() {
    let setup = Setup::default();
    let a = id(Side::Client, Dir::Bi, 0);
    let stream = |offset: u64, len: usize, fin: bool| Frame::Stream {
        id: a,
        offset: varint(offset),
        data: &[0; 20][..len],
        fin,
    };
    let reset = |final_size: u64| Frame::ResetStream {
        id: a,
        error_code: varint(7),
        final_size: varint(final_size),
    };
    let error = |ty: u32| {
        Some((
            TransportErrorCode::FINAL_SIZE_ERROR,
            Some(VarInt::from_u32(ty)),
        ))
    };
    let cases: [(&[Frame<'_>], _); 7] = [
        (
            &[stream(0, 10, true), stream(10, 1, false)],
            error(STREAM_TYPE),
        ),
        (
            &[stream(0, 10, true), stream(10, 2, true)],
            error(STREAM_TYPE),
        ),
        (
            &[stream(0, 20, false), stream(0, 10, true)],
            error(STREAM_TYPE),
        ),
        (&[stream(0, 20, false), reset(10)], error(RESET_STREAM_TYPE)),
        (&[stream(0, 10, true), reset(12)], error(RESET_STREAM_TYPE)),
        (&[reset(10), stream(10, 1, false)], error(STREAM_TYPE)),
        (&[stream(0, 10, true), reset(10), stream(0, 10, true)], None),
    ];
    for (frames, close) in cases {
        assert_eq!(server_close_on(&setup, frames), close, "{frames:?}");
    }
    let past_window = [reset(65 * 1024 + 1)];
    assert_eq!(
        server_close_on(&setup, &past_window),
        Some((
            TransportErrorCode::FLOW_CONTROL_ERROR,
            Some(VarInt::from_u32(RESET_STREAM_TYPE))
        ))
    );
}

#[test]
fn frames_for_a_stream_or_half_that_does_not_exist_are_stream_errors() {
    let setup = Setup::default();
    let server_uni = id(Side::Server, Dir::Uni, 0);
    let server_bidi = id(Side::Server, Dir::Bi, 0);
    let client_uni = id(Side::Client, Dir::Uni, 0);
    let one = |id| Frame::Stream {
        id,
        offset: varint(0),
        data: &[0],
        fin: false,
    };
    let state = |ty: u32| {
        Some((
            TransportErrorCode::STREAM_STATE_ERROR,
            Some(VarInt::from_u32(ty)),
        ))
    };
    let stop = |id| Frame::StopSending {
        id,
        error_code: varint(1),
    };
    let cases = [
        // RFC 9000's error codes: STREAM for a send-only stream, or a local one not yet opened.
        (one(server_uni), state(STREAM_TYPE)),
        (one(server_bidi), state(STREAM_TYPE)),
        // STREAM for a stream ID past the limit sent.
        (
            one(id(Side::Client, Dir::Bi, 100)),
            Some((
                TransportErrorCode::STREAM_LIMIT_ERROR,
                Some(VarInt::from_u32(STREAM_TYPE)),
            )),
        ),
        // MAX_STREAM_DATA for a receive-only stream.
        (
            Frame::MaxStreamData {
                id: client_uni,
                max: varint(1),
            },
            state(0x11),
        ),
        // RESET_STREAM for a send-only stream.
        (
            Frame::ResetStream {
                id: server_uni,
                error_code: varint(1),
                final_size: varint(0),
            },
            state(RESET_STREAM_TYPE),
        ),
        // STOP_SENDING for a receive-only stream, or a local one not yet opened.
        (stop(client_uni), state(0x05)),
        (stop(server_bidi), state(0x05)),
        // STREAM_DATA_BLOCKED for a send-only stream.
        (
            Frame::StreamDataBlocked {
                id: server_uni,
                limit: varint(0),
            },
            state(0x15),
        ),
    ];
    for (frame, close) in cases {
        assert_eq!(server_close_on(&setup, &[frame]), close, "{frame:?}");
    }
}

#[test]
fn a_reset_tells_the_reader_and_returns_its_unread_bytes_to_the_connection_window() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(16_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(pattern(10_000))), Ok(10_000));
    pair.run(pair.now + 2 * RTT);
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.reset(AppCode::from_u32(9)), Ok(()));
    assert_eq!(stream.send_capacity(), 0);
    pair.run(pair.now + 2 * RTT);
    assert!(
        sent_frames(&pair.client, client_from).contains(&Sent::ResetStream {
            id: a,
            code: 9,
            final_size: 10_000
        })
    );
    let server = pair.server.conn_mut();
    // The undelivered readable edge goes with the data.
    assert_eq!(
        edges(server),
        [
            (a, StreamReady::Opened),
            (
                a,
                StreamReady::Reset {
                    code: AppCode::from_u32(9),
                    final_size: 10_000
                }
            )
        ]
    );
    assert!(server.stream(a).unwrap().readable().is_empty());
    pair.run(pair.now + 2 * RTT);
    assert!(
        sent_frames(&pair.server, server_from).contains(&Sent::MaxData(26_000)),
        "the 10,000 unread bytes return to the connection window"
    );
}

#[test]
fn reset_abandons_a_send_half_that_has_not_ended_and_the_stream_then_closes() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let (mut client, mut server) = (App::default(), App::default());
    let client_from = pair.client.sent.len();
    let code = AppCode::from_u32(3);
    let conn = pair.client.conn_mut();
    let [ready, send, data_sent, data_recvd] =
        [(); 4].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    conn.stream(send)
        .unwrap()
        .send(&mut Bytes::from(pattern(1_000)))
        .unwrap();
    for id in [data_sent, data_recvd] {
        let mut stream = conn.stream(id).unwrap();
        stream.send(&mut Bytes::from(pattern(2_000))).unwrap();
        stream.finish().unwrap();
    }
    pair.step();
    // Everything went out and is unacknowledged until the next round trip.
    let until = pair.now + RTT;
    let conn = pair.client.conn_mut();
    for id in [ready, send, data_sent] {
        assert_eq!(conn.stream(id).unwrap().reset(code), Ok(()), "{id}");
    }
    assert_eq!(
        conn.stream(ready).unwrap().reset(code),
        Err(SendError::Ended),
        "reset once"
    );
    // The client does not poll yet, so its closed streams wait for their last edge.
    pair.run(until);
    assert_eq!(
        pair.client
            .conn_mut()
            .stream(data_recvd)
            .unwrap()
            .reset(code),
        Err(SendError::Ended),
        "every byte and the FIN are acknowledged"
    );
    let until = pair.now + 2 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    let sent = sent_frames(&pair.client, client_from);
    for (id, final_size) in [(ready, 0), (send, 1_000), (data_sent, 2_000)] {
        assert!(
            sent.contains(&Sent::ResetStream {
                id,
                code: 3,
                final_size
            }),
            "{id}"
        );
    }
    for id in [ready, send, data_sent, data_recvd] {
        assert_eq!(client.edges_of(id), [StreamReady::Closed], "{id}");
        assert_eq!(
            pair.client.conn_mut().stream(id).err(),
            Some(StreamError::Closed)
        );
        assert_eq!(
            server.edges_of(id).last(),
            Some(&StreamReady::Closed),
            "{id}"
        );
    }
    assert_eq!(
        server.edges_of(ready),
        [
            StreamReady::Opened,
            StreamReady::Reset {
                code,
                final_size: 0
            },
            StreamReady::Closed
        ]
    );
}

#[test]
fn stop_sending_drops_a_pending_readable_edge_with_the_bytes() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let a = pair.client.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(pattern(100))), Ok(100));
    pair.run(pair.now + RTT);
    let server = pair.server.conn_mut();
    let mut stream = server.stream(a).unwrap();
    assert_eq!(stream.readable().chain_length(), 100);
    assert_eq!(stream.stop_sending(AppCode::from_u32(5)), Ok(()));
    assert_eq!(stream.readable().chain_length(), 0);
    assert_eq!(
        edges(server),
        [(a, StreamReady::Opened)],
        "nothing is readable any more"
    );
}

#[test]
fn stop_sending_makes_the_peer_reset_whatever_its_application_does() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let (mut client, mut server) = (App::default(), App::default());
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    client.write(a, pattern(3_000), false);
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(server.data[&a].len(), 3_000);
    let code = AppCode::from_u32(5);
    let mut stream = pair.server.conn_mut().stream(a).unwrap();
    assert_eq!(stream.stop_sending(code), Ok(()));
    assert_eq!(
        stream.stop_sending(code),
        Err(StreamError::ReceiveEnded),
        "once"
    );
    let until = pair.now + 2 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert!(sent_frames(&pair.server, server_from).contains(&Sent::StopSending(a, 5)));
    assert_eq!(client.edges_of(a), [StreamReady::Stopped { code }]);
    assert!(
        sent_frames(&pair.client, client_from).contains(&Sent::ResetStream {
            id: a,
            code: 5,
            final_size: 3_000
        }),
        "RESET_STREAM goes out without the application"
    );
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(
        stream.send(&mut Bytes::from_static(b"more")),
        Err(SendError::Stopped { code })
    );
    assert_eq!(stream.send_capacity(), 0);
    assert_eq!(
        server.edges_of(a).last(),
        Some(&StreamReady::Reset {
            code,
            final_size: 3_000
        })
    );
}

/// Hands the client one server 1-RTT packet built by hand carrying `frames`. The pair must not
/// run afterwards: the server never sent this packet number.
fn to_client(pair: &mut Pair, frames: &[Frame<'_>]) {
    to_client_numbered(pair, 10, frames);
}

/// Returns the send state of stream `id` at `peer`, if the stream is open there.
fn send_state(peer: &Peer, id: StreamId) -> Option<SendState> {
    peer.conn()
        .sources
        .streams
        .streams
        .get(id)
        .and_then(|stream| stream.send_state())
}

#[test]
fn a_stop_sending_resets_a_send_half_in_each_state_that_may_still_send() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let app_code = AppCode::from_u32(3);
    let conn = pair.client.conn_mut();
    let data_recvd = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = conn.stream(data_recvd).unwrap();
    stream.send(&mut Bytes::from(pattern(2_000))).unwrap();
    stream.finish().unwrap();
    pair.run(pair.now + RTT);
    assert_eq!(
        send_state(&pair.client, data_recvd),
        Some(SendState::DataRecvd)
    );
    let conn = pair.client.conn_mut();
    let [ready, send, data_sent, reset_sent] =
        [(); 4].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    conn.stream(send)
        .unwrap()
        .send(&mut Bytes::from(pattern(1_000)))
        .unwrap();
    for id in [data_sent, reset_sent] {
        let mut stream = conn.stream(id).unwrap();
        stream.send(&mut Bytes::from(pattern(2_000))).unwrap();
        stream.finish().unwrap();
    }
    // Everything goes out and is unacknowledged when the STOP_SENDING frames arrive.
    pair.step();
    assert_eq!(
        send_state(&pair.client, data_sent),
        Some(SendState::DataSent)
    );
    let conn = pair.client.conn_mut();
    conn.stream(reset_sent).unwrap().reset(app_code).unwrap();
    let stops = [ready, send, data_sent, data_recvd, reset_sent].map(|id| Frame::StopSending {
        id,
        error_code: varint(7),
    });
    to_client(&mut pair, &stops);
    let code = AppCode::from_u32(7);
    let reset = |code, final_size| Some(SendState::ResetSent { code, final_size });
    for (id, state) in [
        (ready, reset(code, 0)),
        (send, reset(code, 1_000)),
        (data_sent, reset(code, 2_000)),
        (data_recvd, Some(SendState::DataRecvd)),
        (reset_sent, reset(app_code, 2_000)),
    ] {
        assert_eq!(send_state(&pair.client, id), state, "{id}");
    }
    let edges = edges(pair.client.conn_mut());
    let of = |id| -> Vec<_> {
        edges
            .iter()
            .filter(|(of, _)| *of == id)
            .map(|(_, edge)| *edge)
            .collect()
    };
    for id in [ready, send, data_sent, reset_sent] {
        assert_eq!(of(id), [StreamReady::Stopped { code }], "{id}");
    }
    assert_eq!(
        of(data_recvd),
        [StreamReady::Stopped { code }, StreamReady::Closed]
    );
}

/// A sender that hands the server client 1-RTT packets built by hand, numbered from `pn`. The
/// pair must not run afterwards: the client never sent these packet numbers.
struct ToServer {
    pn: u64,
}

impl ToServer {
    fn new(pair: &Pair) -> Self {
        Self {
            pn: pair.client.conn().recovery.space(Space::Data).next_pn() + 10,
        }
    }

    fn send(&mut self, pair: &mut Pair, frames: &[Frame<'_>]) {
        let client = pair.client.conn();
        let packet = Forge::of(client, Space::Data, self.pn, frames).seal(client);
        self.pn += 1;
        let now = pair.now;
        let summary = deliver(pair.server.conn_mut(), now, client_addr(), packet);
        assert_eq!(summary.packets, 1);
    }
}

fn stream_frame(id: StreamId, offset: u64, len: usize, fin: bool) -> Frame<'static> {
    Frame::Stream {
        id,
        offset: varint(offset),
        data: &[0; 20][..len],
        fin,
    }
}

#[test]
fn stop_sending_drops_ingress_until_every_byte_up_to_the_final_size_arrives() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let mut forge = ToServer::new(&pair);
    let uni = |index| id(Side::Client, Dir::Uni, index);
    forge.send(
        &mut pair,
        &[
            // Recv: bytes without the FIN.
            stream_frame(uni(0), 0, 5, false),
            // Size Known: the FIN, with bytes missing before it.
            stream_frame(uni(1), 10, 10, true),
            // Data Recvd: every byte, unread.
            stream_frame(uni(2), 0, 10, true),
            Frame::ResetStream {
                id: uni(3),
                error_code: varint(1),
                final_size: varint(0),
            },
            // Recv, to get its FIN with bytes missing before it.
            stream_frame(uni(4), 0, 5, false),
        ],
    );
    let server = pair.server.conn_mut();
    edges(server);
    let code = AppCode::from_u32(2);
    let mut stop = |id| server.stream(id).unwrap().stop_sending(code);
    assert_eq!(stop(uni(0)), Ok(()));
    assert_eq!(stop(uni(1)), Ok(()));
    assert_eq!(stop(uni(2)), Err(StreamError::ReceiveEnded));
    assert_eq!(stop(uni(4)), Ok(()));
    let own = server.open_stream(Dir::Uni, ORDER).unwrap();
    assert_eq!(
        server.stream(own).unwrap().stop_sending(code),
        Err(StreamError::NoReceiveHalf)
    );
    assert!(server.stream(uni(0)).unwrap().readable().is_empty());
    // Each stopped half ends once every byte up to its final size has arrived, and its bytes are
    // not delivered.
    forge.send(
        &mut pair,
        &[
            stream_frame(uni(1), 0, 10, false),
            stream_frame(uni(0), 5, 5, true),
            stream_frame(uni(4), 15, 5, true),
        ],
    );
    assert_eq!(
        edges(pair.server.conn_mut()),
        [(uni(1), StreamReady::Closed), (uni(0), StreamReady::Closed)]
    );
    assert_eq!(recv_state(&pair.server, uni(4)), Some(RecvState::SizeKnown));
    let stream = pair.server.conn().sources.streams.streams.get(uni(4));
    assert!(
        stream.is_some_and(|s| s.due().contains(Owed::STOP_SENDING)),
        "STOP_SENDING is still owed with bytes missing before the FIN"
    );
    forge.send(&mut pair, &[stream_frame(uni(4), 5, 10, false)]);
    assert_eq!(
        edges(pair.server.conn_mut()),
        [(uni(4), StreamReady::Closed)]
    );
}

/// `peer_finished` holds once the peer's FIN and every byte before it are readable, before the
/// `Finished` edge, and still after the bytes are consumed. It does not hold while bytes before
/// the FIN are missing, after a reset or after the reader's own STOP_SENDING.
#[test]
fn peer_finished_holds_once_the_fin_and_every_byte_before_it_arrived() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let mut forge = ToServer::new(&pair);
    let uni = |index| id(Side::Client, Dir::Uni, index);
    forge.send(
        &mut pair,
        &[
            // Recv: bytes without the FIN.
            stream_frame(uni(0), 0, 5, false),
            // Size Known: the FIN, with bytes missing before it.
            stream_frame(uni(1), 10, 10, true),
            // Data Recvd: every byte and the FIN in one frame.
            stream_frame(uni(2), 0, 10, true),
            Frame::ResetStream {
                id: uni(3),
                error_code: varint(1),
                final_size: varint(0),
            },
            // Recv, to be stopped before its FIN arrives.
            stream_frame(uni(4), 0, 5, false),
        ],
    );
    let server = pair.server.conn_mut();
    let finished = |server: &mut Connection, id| server.stream(id).unwrap().peer_finished();
    assert!(!finished(server, uni(0)), "no FIN yet");
    assert!(
        !finished(server, uni(1)),
        "bytes before the FIN are missing"
    );
    assert!(finished(server, uni(2)), "known before the Finished edge");
    assert!(!finished(server, uni(3)), "reset");
    server.stream(uni(2)).unwrap().consume(10).unwrap();
    assert!(finished(server, uni(2)), "every byte consumed");
    assert!(
        edges(server).contains(&(uni(2), StreamReady::Finished)),
        "the edge still follows"
    );
    server
        .stream(uni(4))
        .unwrap()
        .stop_sending(AppCode::from_u32(2))
        .unwrap();

    forge.send(
        &mut pair,
        &[
            stream_frame(uni(0), 5, 5, true),
            stream_frame(uni(1), 0, 10, false),
            stream_frame(uni(4), 5, 5, true),
        ],
    );
    let server = pair.server.conn_mut();
    assert!(finished(server, uni(0)), "the FIN after the earlier bytes");
    assert!(finished(server, uni(1)), "the missing bytes arrived");
    assert!(!finished(server, uni(4)), "a stopped half delivers nothing");
}

/// Returns the code and frame type of the CONNECTION_CLOSE the server reports after client
/// 1-RTT packets carrying `first`, which end and reap the client's first unidirectional stream
/// once its edges are delivered, and then `then`.
fn server_close_after_reap(
    first: &[Frame<'_>],
    then: &[Frame<'_>],
) -> Option<(TransportErrorCode, Option<VarInt>)> {
    let (_, mut pair) = handshake(Setup::default().pair());
    let a = id(Side::Client, Dir::Uni, 0);
    let mut forge = ToServer::new(&pair);
    forge.send(&mut pair, first);
    let server = pair.server.conn_mut();
    assert_eq!(edges(server).last(), Some(&(a, StreamReady::Closed)));
    assert_eq!(server.stream(a).err(), Some(StreamError::Closed), "reaped");
    forge.send(&mut pair, then);
    local_close(pair.server.conn_mut())
}

#[test]
fn frames_for_a_reaped_stream_are_still_held_to_its_final_size() {
    let a = id(Side::Client, Dir::Uni, 0);
    let reset = |final_size: u64| Frame::ResetStream {
        id: a,
        error_code: varint(1),
        final_size: varint(final_size),
    };
    let error = |ty: u32| {
        Some((
            TransportErrorCode::FINAL_SIZE_ERROR,
            Some(VarInt::from_u32(ty)),
        ))
    };
    let empty = stream_frame(a, 0, 0, true);
    let cases: [(&[Frame<'_>], &[Frame<'_>], _); 5] = [
        (&[empty], &[reset(1)], error(RESET_STREAM_TYPE)),
        (
            &[reset(5)],
            &[stream_frame(a, 3, 5, false)],
            error(STREAM_TYPE),
        ),
        (
            &[reset(5)],
            &[stream_frame(a, 0, 4, true)],
            error(STREAM_TYPE),
        ),
        (&[empty], &[empty, reset(0)], None),
        (&[reset(5)], &[stream_frame(a, 0, 5, true), reset(5)], None),
    ];
    for (first, then, close) in cases {
        assert_eq!(
            server_close_after_reap(first, then),
            close,
            "{first:?} then {then:?}"
        );
    }
}

#[test]
fn a_reset_ends_a_receive_half_once_in_each_state_and_releases_its_bytes() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let mut forge = ToServer::new(&pair);
    let uni = |index| id(Side::Client, Dir::Uni, index);
    let reset = |index, final_size: u64| Frame::ResetStream {
        id: uni(index),
        error_code: varint(9),
        final_size: varint(final_size),
    };
    let code = AppCode::from_u32(9);
    let released = |pair: &Pair| pair.server.conn().sources.streams.conn_recv.consumed();
    forge.send(
        &mut pair,
        &[
            // Size Known: 5 readable bytes, a gap, then 10 bytes and the FIN.
            stream_frame(uni(0), 0, 5, false),
            stream_frame(uni(0), 10, 10, true),
            // Recv, to be stopped by the application.
            stream_frame(uni(1), 0, 5, false),
        ],
    );
    assert_eq!(recv_state(&pair.server, uni(0)), Some(RecvState::SizeKnown));
    let server = pair.server.conn_mut();
    edges(server);
    let stop = AppCode::from_u32(2);
    assert_eq!(server.stream(uni(1)).unwrap().stop_sending(stop), Ok(()));
    assert_eq!(released(&pair), 5, "the stopped stream's unread bytes");
    // Each reset arrives twice; uni(2) is reset before any data.
    let resets = [reset(0, 20), reset(1, 8), reset(2, 4)];
    forge.send(&mut pair, &resets);
    forge.send(&mut pair, &resets);
    assert_eq!(local_close(pair.server.conn_mut()), None);
    assert_eq!(
        released(&pair),
        20 + 8 + 4,
        "every byte up to each final size, read or not, returns to the connection window"
    );
    let server = pair.server.conn_mut();
    assert_eq!(
        server.stream(uni(0)).unwrap().stop_sending(stop),
        Err(StreamError::ReceiveEnded),
        "a reset receive half takes no STOP_SENDING"
    );
    let reset_edge = |final_size| StreamReady::Reset { code, final_size };
    assert_eq!(
        edges(server),
        [
            (uni(0), reset_edge(20)),
            (uni(0), StreamReady::Closed),
            (uni(1), reset_edge(8)),
            (uni(1), StreamReady::Closed),
            (uni(2), StreamReady::Opened),
            (uni(2), reset_edge(4)),
            (uni(2), StreamReady::Closed),
        ],
        "one reset edge each, and no data edge after it"
    );
}

/// Returns the receive state of stream `id` at `peer`, if the stream is open there.
fn recv_state(peer: &Peer, id: StreamId) -> Option<RecvState> {
    peer.conn()
        .sources
        .streams
        .streams
        .get(id)
        .and_then(|stream| stream.recv_state())
}

#[test]
fn stop_sending_with_bytes_missing_before_the_fin_still_asks_the_peer_to_reset() {
    // The client sends 3,000 bytes and the FIN on a unidirectional stream; its datagrams
    // `dropped` are lost.
    let round = |dropped: Vec<usize>| {
        let mut config = Setup::default().pair();
        config.to_server.loss = Loss::Drop(dropped);
        let (_, mut pair) = handshake(config);
        let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
        let conn = pair.client.conn_mut();
        let a = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let mut stream = conn.stream(a).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(3_000))), Ok(3_000));
        assert_eq!(stream.finish(), Ok(()));
        (pair, a, client_from, server_from)
    };
    let (mut probe, a, client_from, _) = round(Vec::new());
    probe.run(probe.now + RTT);
    let first = (client_from..probe.client.sent.len())
        .find(|&i| {
            frames_in(&probe.client, i..i + 1)
                .iter()
                .any(|f| matches!(f, Sent::Stream { id, offset: 0, .. } if *id == a))
        })
        .expect("the stream's first bytes were sent");
    // Without its first datagram, the server has the FIN and a gap before it: Size Known.
    let (mut pair, a, client_from, server_from) = round(vec![first]);
    let limit = pair.now + RTT;
    assert!(pair.run_until(limit, |pair| {
        recv_state(&pair.server, a) == Some(RecvState::SizeKnown)
    }));
    let code = AppCode::from_u32(4);
    let server = pair.server.conn_mut();
    assert_eq!(server.stream(a).unwrap().stop_sending(code), Ok(()));
    pair.run(pair.now + 3 * RTT);
    assert!(
        sent_frames(&pair.server, server_from).contains(&Sent::StopSending(a, 4)),
        "STOP_SENDING is useful in Size Known, as RFC 9000 notes"
    );
    assert!(
        sent_frames(&pair.client, client_from).contains(&Sent::ResetStream {
            id: a,
            code: 4,
            final_size: 3_000
        })
    );
    assert_eq!(
        edges(pair.server.conn_mut()),
        [
            (a, StreamReady::Opened),
            (
                a,
                StreamReady::Reset {
                    code,
                    final_size: 3_000
                }
            ),
            (a, StreamReady::Closed)
        ],
        "nothing is read; the reset ends the receive half"
    );
}

#[test]
fn reaped_peer_streams_raise_the_stream_limit_and_the_opener_hears_of_it() {
    let setup = Setup {
        server_transport: config(|c| c.max_streams_bidi(2)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (mut client, mut server) = (App::default(), App::default());
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let conn = pair.client.conn_mut();
    let [a, b] = [(); 2].map(|()| conn.open_stream(Dir::Bi, ORDER).unwrap());
    assert_eq!(
        conn.open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
    for id in [a, b] {
        client.write(id, &b"request"[..], true);
    }
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert!(
        sent_frames(&pair.client, client_from).contains(&Sent::StreamsBlocked(Dir::Bi, 2)),
        "the client says it is held at the limit"
    );
    assert!(
        !pair
            .client
            .has_event(&ConnEvent::StreamsAvailable { dir: Dir::Bi })
    );
    for id in [a, b] {
        server.write(id, &b"response"[..], true);
    }
    let until = pair.now + 3 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    for id in [a, b] {
        assert_eq!(server.edges_of(id).last(), Some(&StreamReady::Closed));
    }
    assert!(sent_frames(&pair.server, server_from).contains(&Sent::MaxStreams(Dir::Bi, 4)));
    assert!(
        pair.client
            .has_event(&ConnEvent::StreamsAvailable { dir: Dir::Bi })
    );
    let conn = pair.client.conn_mut();
    assert_eq!(
        conn.open_stream(Dir::Bi, ORDER),
        Ok(id(Side::Client, Dir::Bi, 2))
    );
    assert_eq!(
        conn.open_stream(Dir::Bi, ORDER),
        Ok(id(Side::Client, Dir::Bi, 3))
    );
    assert_eq!(
        conn.open_stream(Dir::Bi, ORDER),
        Err(OpenError::StreamLimit)
    );
}

/// Returns the streams of the STREAM frames in `sent`, in order.
fn stream_order(sent: &[Sent]) -> Vec<StreamId> {
    sent.iter()
        .filter_map(|f| match *f {
            Sent::Stream { id, len, .. } if len > 0 => Some(id),
            _ => None,
        })
        .collect()
}

#[test]
fn streams_go_out_by_urgency_then_order_and_incremental_ones_take_turns() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let client_from = pair.client.sent.len();
    let order = |urgency, incremental, order| SendOrder {
        class: 1,
        urgency,
        incremental,
        order,
    };
    let conn = pair.client.conn_mut();
    // Each stream stages all it has and ends; an unfinished stream with room would keep its
    // room of the staging budget for itself, ahead of the streams after it.
    let mut open = |order: SendOrder, len: usize| {
        let id = conn.open_stream(Dir::Uni, order).unwrap();
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(len))), Ok(len));
        assert_eq!(stream.finish(), Ok(()));
        id
    };
    let urgent = open(order(0, false, 0), 6_000);
    let second = open(order(3, false, 1), 3_000);
    let first = open(order(3, false, 0), 3_000);
    let inc = [
        open(order(5, true, 0), 12_000),
        open(order(5, true, 0), 12_000),
    ];
    let late = open(order(7, false, 0), 3_000);
    conn.stream(late).unwrap().set_order(order(0, false, 1));
    pair.run(pair.now + 10 * RTT);
    let sent = stream_order(&sent_frames(&pair.client, client_from));
    let first_of = |id| sent.iter().position(|&of| of == id).unwrap();
    let last_of = |id| sent.iter().rposition(|&of| of == id).unwrap();
    assert!(last_of(urgent) < first_of(late), "{sent:?}");
    assert!(last_of(late) < first_of(first), "{sent:?}");
    assert!(last_of(first) < first_of(second), "{sent:?}");
    assert!(
        last_of(second) < first_of(inc[0]).min(first_of(inc[1])),
        "{sent:?}"
    );
    // Each incremental stream is served before the other finishes.
    assert!(first_of(inc[1]) < last_of(inc[0]), "{sent:?}");
    assert!(first_of(inc[0]) < last_of(inc[1]), "{sent:?}");
}

#[test]
fn forty_concurrent_streams_arrive_whole_in_urgency_order_with_incremental_ones_interleaved() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let client_from = pair.client.sent.len();
    let conn = pair.client.conn_mut();
    let urgencies = [0, 2, 4, 6];
    // Opened lowest priority first, so stream IDs run against the wire order.
    let mut lens = BTreeMap::new();
    let mut open = |urgency, incremental, order, len| {
        let order = SendOrder {
            class: 1,
            urgency,
            incremental,
            order,
        };
        let id = conn.open_stream(Dir::Uni, order).unwrap();
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(pattern(len))), Ok(len));
        assert_eq!(stream.finish(), Ok(()));
        lens.insert(id, len);
        id
    };
    let buckets = urgencies.map(|urgency| {
        let incremental = [(); 5].map(|()| open(urgency, true, 0, 4_000));
        let mut sequential = [4, 3, 2, 1, 0].map(|order| open(urgency, false, order, 2_000));
        sequential.reverse();
        (sequential, incremental)
    });
    let (mut client, mut server) = (App::default(), App::default());
    let until = pair.now + 20 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    for (&id, &len) in &lens {
        assert_eq!(server.data.get(&id), Some(&pattern(len)), "{id:?}");
        assert!(
            server.edges_of(id).contains(&StreamReady::Finished),
            "{id:?}"
        );
    }
    let sent = stream_order(&sent_frames(&pair.client, client_from));
    let first_of = |id| sent.iter().position(|&of| of == id).unwrap();
    let last_of = |id| sent.iter().rposition(|&of| of == id).unwrap();
    let all = |(sequential, incremental): &([StreamId; 5], [StreamId; 5])| {
        sequential
            .iter()
            .chain(incremental)
            .copied()
            .collect::<Vec<_>>()
    };
    for pair in buckets.windows(2) {
        let last = all(&pair[0]).into_iter().map(last_of).max().unwrap();
        let first = all(&pair[1]).into_iter().map(first_of).min().unwrap();
        assert!(
            last < first,
            "each urgency drains before the next: {sent:?}"
        );
    }
    for (sequential, incremental) in &buckets {
        for ids in sequential.windows(2) {
            assert!(last_of(ids[0]) < first_of(ids[1]), "by order: {sent:?}");
        }
        let first = incremental.iter().copied().map(first_of).min().unwrap();
        assert!(
            last_of(sequential[4]) < first,
            "sequential before incremental: {sent:?}"
        );
        for &a in incremental {
            for &b in incremental.iter().filter(|&&b| b != a) {
                assert!(first_of(b) < last_of(a), "turns: {sent:?}");
            }
        }
    }
}

#[test]
fn readiness_reports_each_edge_once_and_nothing_without_new_ingress() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let send = |pair: &mut Pair, data: &'static [u8]| {
        let mut stream = pair.client.conn_mut().stream(a).unwrap();
        assert_eq!(stream.send(&mut Bytes::from_static(data)), Ok(data.len()));
        pair.run(pair.now + RTT);
    };
    send(&mut pair, b"abc");
    let server = pair.server.conn_mut();
    assert_eq!(
        edges(server),
        [(a, StreamReady::Opened), (a, StreamReady::Readable)]
    );
    assert_eq!(server.stream(a).unwrap().consume(1), Ok(CreditDue::NotDue));
    assert_eq!(
        edges(server),
        [],
        "consuming part of the bytes reports nothing"
    );
    pair.run(pair.now + 5 * RTT);
    assert_eq!(
        edges(pair.server.conn_mut()),
        [],
        "time alone reports nothing"
    );
    send(&mut pair, b"def");
    let server = pair.server.conn_mut();
    assert_eq!(edges(server), [(a, StreamReady::Readable)]);
    assert_eq!(readable(&server.stream(a).unwrap()), b"bcdef");
}

#[test]
fn a_push_sender_refused_bytes_hears_writable_once_its_allowance_returns() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let [a, b] = [(); 2].map(|()| conn.open_stream(Dir::Bi, ORDER).unwrap());
    let mut rest = Bytes::from(pattern(10_000));
    assert_eq!(conn.stream(a).unwrap().send(&mut rest), Ok(8_000));
    assert_eq!(
        conn.stream(b).unwrap().send(&mut Bytes::from(pattern(100))),
        Ok(100)
    );
    pair.run(pair.now + 2 * RTT);
    assert_eq!(edges(pair.client.conn_mut()), [], "no credit came back yet");
    assert_eq!(read_all(pair.server.conn_mut(), a), CreditDue::Due);
    pair.run(pair.now + 2 * RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(edges(conn), [(a, StreamReady::Writable)]);
    assert_eq!(conn.stream(a).unwrap().send(&mut rest), Ok(2_000));
    assert_eq!(edges(conn), []);
}

/// The per-stream staging cap: the most bytes one stream stages.
const CAP: usize = 64 * 1024;

/// Opens streams at `idle` that stay open and never send, then a stream at `order` after the
/// first `ahead` of them in the wire order, and checks that its push sender takes bytes at once,
/// receives one `Writable` edge after a refusal, and gets every byte across.
fn idle_streams_leave_the_staging_budget(idle: &[SendOrder], ahead: usize, order: SendOrder) {
    let (start, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    for &at in idle {
        conn.open_stream(Dir::Uni, at).unwrap();
    }
    assert!(
        (ahead * CAP) as u64 >= conn.staging_budget(),
        "the rooms of the idle streams ahead add up to the staging budget"
    );
    let late = conn.open_stream(Dir::Uni, order).unwrap();
    let data = pattern(3 * CAP);
    let mut rest = Bytes::from(data.clone());
    assert_eq!(
        conn.stream(late).unwrap().send(&mut rest),
        Ok(CAP),
        "idle streams reserve none of the staging budget"
    );
    let (mut client, mut server) = (App::default(), App::default());
    let until = pair.now + 10 * RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(client.edges_of(late), [StreamReady::Writable]);
    client.write(late, rest, true);
    while !server.edges_of(late).contains(&StreamReady::Finished) {
        assert!(pair.now < start + 60 * LIMIT, "no progress");
        let until = pair.now + RTT;
        run_apps(&mut pair, until, &mut client, &mut server);
    }
    assert!(server.data[&late] == data, "{late} arrived altered");
}

#[test]
fn idle_sequential_streams_ahead_leave_the_staging_budget_to_a_push_sender_after_them() {
    let at = |order| SendOrder { order, ..ORDER };
    idle_streams_leave_the_staging_budget(&[at(0), at(1), at(2), at(3)], 4, at(4));
}

#[test]
fn idle_incremental_streams_leave_the_staging_budget_to_a_push_sender_after_or_beside_them() {
    let incremental = |urgency| SendOrder {
        urgency,
        incremental: true,
        ..ORDER
    };
    // Four in a bucket ahead, three in the push sender's own bucket.
    let idle = [0, 0, 0, 0, 3, 3, 3].map(incremental);
    idle_streams_leave_the_staging_budget(&idle, 4, incremental(3));
}

#[test]
fn a_push_sender_leaves_the_staging_budget_that_streams_with_demand_ahead_of_it_can_take() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let order = |urgency| SendOrder {
        class: 1,
        urgency,
        incremental: false,
        order: 0,
    };
    // An idle stream ahead of every other, as an HTTP/3 control stream is, does not reserve room;
    // an urgent stream with bytes staged reserves its room.
    conn.open_stream(Dir::Uni, SendOrder { class: 0, ..ORDER })
        .unwrap();
    let urgent = conn.open_stream(Dir::Uni, order(0)).unwrap();
    let staged = 1_000;
    assert_eq!(
        conn.stream(urgent)
            .unwrap()
            .send(&mut Bytes::from(vec![0; staged])),
        Ok(staged)
    );
    let low = [(); 4].map(|()| conn.open_stream(Dir::Uni, order(5)).unwrap());
    let taken = low.map(|id| {
        conn.stream(id)
            .unwrap()
            .send(&mut Bytes::from(vec![0; CAP]))
            .unwrap()
    });
    // The 256 KiB budget less the urgent stream's staged bytes and room is what the
    // low-urgency streams share.
    assert_eq!(taken, [CAP, CAP, CAP, 0]);
    assert_eq!(conn.stream(urgent).unwrap().send_capacity(), CAP - staged);
}

/// Fills the client's 256 KiB staging budget with four finished streams of 64 KiB each at
/// `order`, opens a push sender at `order` after them that is refused, and returns it.
fn a_sender_behind_a_full_staging_budget(conn: &mut Connection, order: SendOrder) -> StreamId {
    for _ in 0..4 {
        let id = conn.open_stream(Dir::Uni, order).unwrap();
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; CAP])), Ok(CAP));
        assert_eq!(stream.finish(), Ok(()));
    }
    let late = conn.open_stream(Dir::Uni, order).unwrap();
    assert_eq!(
        conn.stream(late)
            .unwrap()
            .send(&mut Bytes::from(vec![0; 1_000])),
        Ok(0),
        "the 256 KiB budget is staged"
    );
    late
}

/// Returns what the client's staging budget has free.
fn free(pair: &Pair) -> u64 {
    let conn = pair.client.conn();
    conn.staging_budget() - conn.sources.streams.staged
}

#[test]
fn a_push_sender_held_by_the_staging_budget_hears_writable_at_its_low_water_mark() {
    let (_, mut pair) = handshake(Setup::default().pair());
    // The finished streams are peers of the sender's bucket while they hold bytes, so the
    // sender is entitled to 256 KiB / 5 and its low-water mark is 16 KiB.
    let late = a_sender_behind_a_full_staging_budget(pair.client.conn_mut(), INCREMENTAL);
    pair.step();
    assert!(
        (1..16 * 1024).contains(&free(&pair)),
        "the first flight frees less than the low-water mark: {}",
        free(&pair)
    );
    assert_eq!(edges(pair.client.conn_mut()), [], "too little to wake for");
    assert!(pair.run_until(pair.now + 10 * RTT, |pair| free(pair) >= 16 * 1024));
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(late, StreamReady::Writable)]
    );
}

#[test]
fn a_sequential_push_sender_behind_streams_holding_the_budget_hears_writable_for_its_share() {
    let (_, mut pair) = handshake(Setup::default().pair());
    // The finished streams ahead hold their bytes and do not take more, so what is free is the
    // sender's prefix share, and its low-water mark is no higher than that share.
    let late = a_sender_behind_a_full_staging_budget(pair.client.conn_mut(), ORDER);
    pair.step();
    let share = free(&pair);
    assert!((1..16 * 1024).contains(&share), "{share}");
    let conn = pair.client.conn_mut();
    assert_eq!(edges(conn), [(late, StreamReady::Writable)]);
    assert_eq!(conn.stream(late).unwrap().send_capacity() as u64, share);
}

#[test]
fn a_reset_or_the_peers_stop_sending_drops_an_undelivered_writable_edge() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_uni(0)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let [reset, stopped] = [(); 2].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    for id in [reset, stopped] {
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; 1_000])), Ok(0));
    }
    // Credit wakes both refused senders; before their `Writable` edges are delivered, one resets
    // and the other is stopped by the peer, in a later packet.
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let credit = [reset, stopped].map(|id| Frame::MaxStreamData {
        id,
        max: varint(1_000),
    });
    let stop = [Frame::StopSending {
        id: stopped,
        error_code: varint(7),
    }];
    let packets = [
        Forge::of(server, Space::Data, pn, &credit).seal(server),
        Forge::of(server, Space::Data, pn + 1, &stop).seal(server),
    ];
    let [credit, stop] = packets;
    let now = pair.now;
    let conn = pair.client.conn_mut();
    deliver(conn, now, server_addr(), credit);
    assert_eq!(
        conn.stream(reset).unwrap().reset(AppCode::from_u32(1)),
        Ok(())
    );
    deliver(conn, now, server_addr(), stop);
    assert_eq!(
        edges(conn),
        [(
            stopped,
            StreamReady::Stopped {
                code: AppCode::from_u32(7)
            }
        )]
    );
}

#[test]
fn finishing_a_stream_drops_its_undelivered_writable_edge() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_uni(0)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(vec![0; 1_000])), Ok(0));
    // Credit wakes the refused sender, which finishes before its `Writable` edge is delivered.
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + 10;
    let credit = [Frame::MaxStreamData {
        id: a,
        max: varint(1_000),
    }];
    let packet = Forge::of(server, Space::Data, pn, &credit).seal(server);
    let now = pair.now;
    let conn = pair.client.conn_mut();
    deliver(conn, now, server_addr(), packet);
    let on_demand = |conn: &Connection| {
        let streams = &conn.sources.streams.streams;
        streams.is_on(List::Demand, streams.get(a).unwrap().slot())
    };
    assert!(on_demand(conn), "an undelivered Writable keeps its demand");
    assert_eq!(conn.stream(a).unwrap().finish(), Ok(()));
    assert_eq!(edges(conn), [], "the stream takes no more bytes");
    assert!(!on_demand(conn), "nor holds a share of the staging budget");
}

#[test]
fn a_credit_arm_fails_with_the_reason_on_a_stream_that_sends_no_more_bytes() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let [reset, stopped] = [(); 2].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    assert_eq!(
        conn.stream(reset).unwrap().reset(AppCode::from_u32(1)),
        Ok(())
    );
    let peer_uni = id(Side::Server, Dir::Uni, 0);
    to_client(
        &mut pair,
        &[
            Frame::StopSending {
                id: stopped,
                error_code: varint(7),
            },
            stream_frame(peer_uni, 0, 10, false),
        ],
    );
    let conn = pair.client.conn_mut();
    let code = AppCode::from_u32(7);
    for (id, error) in [
        (reset, SendError::Ended),
        (stopped, SendError::Stopped { code }),
        (peer_uni, SendError::NoSendHalf),
    ] {
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.notify_credit_above(0), Err(error), "{id}");
    }
    assert!(
        edges(conn)
            .iter()
            .all(|(_, edge)| *edge != StreamReady::CreditRaised),
        "a failed arm does not mark an edge"
    );
    assert_eq!(
        conn.state,
        super::State::Open,
        "misuse leaves the connection open"
    );
}

#[test]
fn a_stop_sending_after_every_byte_and_the_fin_are_acknowledged_drops_the_armed_credit() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    stream.send(&mut Bytes::from(pattern(2_000))).unwrap();
    stream.finish().unwrap();
    pair.run(pair.now + RTT);
    assert_eq!(send_state(&pair.client, a), Some(SendState::DataRecvd));
    let conn = pair.client.conn_mut();
    let mut stream = conn.stream(a).unwrap();
    let limit = stream.credit_limit();
    assert_eq!(stream.notify_credit_above(limit), Ok(()));
    let _ = edges(conn);
    // The STOP_SENDING leaves the send half in Data Recvd, since every byte and the FIN are
    // acknowledged, and disarms the credit value: the raise after it in the same packet does not
    // mark an edge.
    to_client(
        &mut pair,
        &[
            Frame::StopSending {
                id: a,
                error_code: varint(7),
            },
            Frame::MaxStreamData {
                id: a,
                max: varint(limit + 1_000),
            },
        ],
    );
    assert_eq!(send_state(&pair.client, a), Some(SendState::DataRecvd));
    let conn = pair.client.conn_mut();
    assert_eq!(
        conn.stream(a).unwrap().credit_limit(),
        limit + 1_000,
        "the raise arrived"
    );
    assert_eq!(
        edges(conn),
        [(
            a,
            StreamReady::Stopped {
                code: AppCode::from_u32(7)
            }
        )]
    );
}

#[test]
fn arming_again_drops_an_undelivered_credit_edge_and_compares_with_the_limit_again() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    let limit = stream.credit_limit();
    assert_eq!(stream.notify_credit_above(limit), Ok(()));
    to_client(
        &mut pair,
        &[Frame::MaxStreamData {
            id: a,
            max: varint(limit + 1_000),
        }],
    );
    // The raise marked an edge. Arming at the new limit replaces the value and drops the edge.
    let conn = pair.client.conn_mut();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.notify_credit_above(limit + 1_000), Ok(()));
    assert_eq!(
        edges(conn),
        [],
        "the limit is not above the value armed now"
    );
    // Arming twice below the limit gives one edge.
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.notify_credit_above(limit), Ok(()));
    assert_eq!(stream.notify_credit_above(limit), Ok(()));
    assert_eq!(edges(conn), [(a, StreamReady::CreditRaised)]);
}

/// Fills the client's 256 KiB staging budget with four finished streams of 64 KiB each.
fn fill_the_staging_budget(conn: &mut Connection) {
    for _ in 0..4 {
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; CAP])), Ok(CAP));
        assert_eq!(stream.finish(), Ok(()));
    }
    assert_eq!(conn.sources.streams.staged, conn.staging_budget());
}

#[test]
fn a_refused_push_sender_off_the_pull_ready_list_hears_writable_all_the_same() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    fill_the_staging_budget(conn);
    let late = conn.open_stream(Dir::Uni, ORDER).unwrap();
    assert_eq!(
        conn.stream(late)
            .unwrap()
            .send(&mut Bytes::from(vec![0; 1_000])),
        Ok(0)
    );
    // A pull driver marks a producer pending when it returns `Pending`.
    let mut stream = conn.sources.streams.streams.stream(late).unwrap();
    stream.set_producer_pending(true);
    drop(stream);
    assert!(pair.run_until(pair.now + 10 * RTT, |pair| {
        pair.client.conn().sources.streams.staged == 0
    }));
    let conn = pair.client.conn_mut();
    assert_eq!(conn.pull_ready().count(), 0, "off the pull-ready list");
    let of_late: Vec<_> = edges(conn).into_iter().filter(|e| e.0 == late).collect();
    assert_eq!(of_late, [(late, StreamReady::Writable)]);
}

#[test]
fn a_woken_push_sender_keeps_its_room_until_it_hears_writable() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_uni(0)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let order = |urgency| SendOrder { urgency, ..ORDER };
    // Four urgent push senders and a low-urgency one, refused at zero stream credit.
    let urgent = [(); 4].map(|()| conn.open_stream(Dir::Uni, order(0)).unwrap());
    let low = conn.open_stream(Dir::Uni, order(5)).unwrap();
    let senders = [urgent[0], urgent[1], urgent[2], urgent[3], low];
    for id in senders {
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; CAP])), Ok(0));
    }
    // Credit for 64 KiB each: the urgent senders' rooms add up to the 256 KiB budget.
    let frames = senders.map(|id| Frame::MaxStreamData {
        id,
        max: varint(CAP as u64),
    });
    to_client(&mut pair, &frames);
    let conn = pair.client.conn_mut();
    assert_eq!(
        conn.stream(low).unwrap().send_capacity(),
        0,
        "the urgent senders are woken, and keep their rooms until they hear it"
    );
    // Once their edges are delivered without a send, the low-urgency sender is woken in turn.
    assert_eq!(
        edges(conn),
        senders.map(|id| (id, StreamReady::Writable)),
        "woken in turn"
    );
    assert_eq!(conn.stream(low).unwrap().send_capacity(), CAP);
}

/// Returns the streams `pull_ready` lists, in order.
fn pull_ready_ids(conn: &mut Connection) -> Vec<StreamId> {
    conn.pull_ready().map(|(id, _)| id).collect()
}

#[test]
fn a_streams_producer_is_pending_until_woken_and_again_once_parked() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let (mut client, mut server) = (App::default(), App::default());
    let local = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let peer = pair.server.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    server.write(peer, &b"hi"[..], false);
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    assert_eq!(
        client.edges_of(peer),
        [StreamReady::Opened, StreamReady::Readable]
    );
    let conn = pair.client.conn_mut();
    assert_eq!(
        pull_ready_ids(conn),
        [],
        "a new stream's producer is pending, local or peer"
    );
    // What a pull driver does when a stream waker fires.
    for id in [local, peer] {
        conn.stream(id).unwrap().wake_producer();
    }
    assert_eq!(pull_ready_ids(conn), [local, peer]);
    // What it does when `poll_send` returns `Pending`.
    conn.stream(local).unwrap().park_producer();
    assert_eq!(pull_ready_ids(conn), [peer]);
}

/// Delivers `frames` to the client in a forged 1-RTT packet of the server's, numbered `skip`
/// past the server's next packet number, so that each packet a test forges has its own number.
/// The pair must not run afterwards: the server never sent this packet number.
fn to_client_numbered(pair: &mut Pair, skip: u64, frames: &[Frame<'_>]) {
    let server = pair.server.conn();
    let pn = server.recovery.space(Space::Data).next_pn() + skip;
    let packet = Forge::of(server, Space::Data, pn, frames).seal(server);
    let now = pair.now;
    let summary = deliver(pair.client.conn_mut(), now, server_addr(), packet);
    assert_eq!(summary.packets, 1);
}

/// Opens 1,024 streams at `ORDER` on a client whose peer grants 200 bytes of credit per stream,
/// each staging 100 bytes as a push sender, then a push sender after them that is refused once
/// its credit is spent, and returns that sender. Each of the 1,024 streams has demand and room
/// that the staging budget covers, so each is ranked with an allowance.
fn many_senders_and_a_refused_one() -> (Pair, StreamId) {
    let setup = Setup {
        server_transport: config(|c| {
            c.max_data(1 << 30)
                .max_streams_uni(2048)
                .max_stream_data_uni(200)
        }),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let ids: Vec<_> = (0..1024)
        .map(|_| conn.open_stream(Dir::Uni, ORDER).unwrap())
        .collect();
    for &id in &ids {
        let mut data = Bytes::from_static(&ZEROS[..100]);
        assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(100));
    }
    let refused = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from_static(&ZEROS[..300]);
    assert_eq!(conn.stream(refused).unwrap().send(&mut data), Ok(200));
    assert_eq!(
        conn.stream(ids[1023]).unwrap().send_capacity(),
        100,
        "the staging budget covers the room of every stream ahead of the refused sender"
    );
    (pair, refused)
}

#[test]
fn wake_writable_reindexes_only_refused_senders() {
    let (mut pair, refused) = many_senders_and_a_refused_one();
    census::reset();
    let credit = [Frame::MaxStreamData {
        id: refused,
        max: varint(1_000),
    }];
    to_client_numbered(&mut pair, 10, &credit);
    let reindexes = census::read().reindexes;
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(refused, StreamReady::Writable)]
    );
    assert!(
        reindexes <= 2,
        "only the credit frame and the wake reindex, both on the refused sender, not each \
         stream with an allowance: {reindexes} reindexes"
    );
}

#[test]
fn pull_ready_without_pull_ready_streams_does_not_rank() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    // Push senders stage bytes, so each has demand, and their producers stay pending.
    let ids = [(); 3].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    for id in ids {
        let mut data = Bytes::from_static(&ZEROS[..1_000]);
        assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(1_000));
    }
    let streams = &conn.sources.streams.streams;
    assert!(
        ids.iter()
            .all(|&id| streams.is_on(List::Demand, streams.get(id).unwrap().slot())),
        "every sender has demand"
    );
    // A woken producer is ranked and listed.
    conn.stream(ids[0]).unwrap().wake_producer();
    census::reset();
    assert_eq!(pull_ready_ids(conn), [ids[0]]);
    assert_eq!(
        census::read().ranks,
        1,
        "a ranking for the pull-ready stream"
    );
    // Once it is parked, no stream is pull-ready, and the list is empty without a ranking.
    conn.stream(ids[0]).unwrap().park_producer();
    census::reset();
    assert_eq!(pull_ready_ids(conn), [], "nothing left from the last list");
    assert_eq!(
        census::read().ranks,
        0,
        "no ranking without a pull-ready stream"
    );
}

#[test]
fn refused_push_senders_across_buckets_hear_writable_in_wire_order() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_uni(0)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let at = |urgency, incremental, order| SendOrder {
        class: 1,
        urgency,
        incremental,
        order,
    };
    // The wire order goes by urgency, then by order and stream ID in a sequential bucket. An
    // incremental bucket goes by its rotation, and its streams outside the rotation follow it in
    // the order they gained demand. The streams open in another order.
    let low = conn.open_stream(Dir::Uni, at(5, false, 0)).unwrap();
    let [unplaced_a, unplaced_b] =
        [(); 2].map(|()| conn.open_stream(Dir::Uni, at(3, true, 0)).unwrap());
    let second = conn.open_stream(Dir::Uni, at(0, false, 2)).unwrap();
    let placed = conn.open_stream(Dir::Uni, at(3, true, 0)).unwrap();
    let first = conn.open_stream(Dir::Uni, at(0, false, 1)).unwrap();
    let busy = conn.open_stream(Dir::Uni, at(0, false, 1)).unwrap();
    let quiet = conn.open_stream(Dir::Uni, at(0, false, 0)).unwrap();
    // `placed` stages bytes, which give it a place in the rotation, and is refused the rest;
    // `busy` stages bytes within its credit and is not refused.
    let credit = [placed, busy].map(|id| Frame::MaxStreamData {
        id,
        max: varint(1_000),
    });
    to_client_numbered(&mut pair, 10, &credit);
    let conn = pair.client.conn_mut();
    let mut data = Bytes::from_static(&ZEROS[..2_000]);
    assert_eq!(conn.stream(placed).unwrap().send(&mut data), Ok(1_000));
    let mut data = Bytes::from_static(&ZEROS[..500]);
    assert_eq!(conn.stream(busy).unwrap().send(&mut data), Ok(500));
    // The others are refused at zero credit, which gives them demand, in yet another order.
    for id in [low, unplaced_b, unplaced_a, second, first, quiet] {
        let mut data = Bytes::from_static(&ZEROS[..1_000]);
        assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(0));
    }
    assert_eq!(edges(conn), [], "no credit came back yet");
    // Credit for every refused sender but `quiet`, which comes first in the wire order and keeps
    // a zero allowance.
    let credit = [
        (placed, 2_000),
        (low, 1_000),
        (unplaced_a, 1_000),
        (unplaced_b, 1_000),
        (second, 1_000),
        (first, 1_000),
    ]
    .map(|(id, max)| Frame::MaxStreamData {
        id,
        max: varint(max),
    });
    to_client_numbered(&mut pair, 11, &credit);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [first, second, placed, unplaced_b, unplaced_a, low].map(|id| (id, StreamReady::Writable)),
        "woken in the wire order"
    );
    let credit = [Frame::MaxStreamData {
        id: quiet,
        max: varint(1_000),
    }];
    to_client_numbered(&mut pair, 12, &credit);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(quiet, StreamReady::Writable)],
        "a refused sender passed over at a zero allowance is woken once credit comes"
    );
}

/// A microbenchmark of a push-mode application's receive and app phase over many streams: 1,024
/// streams hold staged bytes and room, and a refused push sender waits for credit that does not
/// come. Each iteration receives a packet holding a PING and asks for the pull-ready streams.
/// `MVFSTR_PUSH_LOOP_ITERATIONS` sets the number of iterations, 10,000 by default, so the cost of
/// one iteration is the difference between two runs divided by the difference of their counts.
#[test]
#[ignore = "a microbenchmark, run alone under an instruction counter"]
fn push_mode_receive_and_pull_ready_over_1024_streams() {
    let iterations = std::env::var("MVFSTR_PUSH_LOOP_ITERATIONS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(10_000u64);
    let (mut pair, refused) = many_senders_and_a_refused_one();
    let now = pair.now;
    let first = pair.server.conn().recovery.space(Space::Data).next_pn() + 10;
    for pn in first..first + iterations {
        let server = pair.server.conn();
        let packet = Forge::of(server, Space::Data, pn, &[Frame::Ping]).seal(server);
        let conn = pair.client.conn_mut();
        assert_eq!(deliver(conn, now, server_addr(), packet).packets, 1);
        assert_eq!(conn.pull_ready().next(), None);
    }
    let conn = pair.client.conn_mut();
    assert_eq!(edges(conn), [], "{refused} is still refused");
}

/// The frames a poll in [`a_carried_allowance_equals_a_fresh_one_through_a_round`] stages on a
/// stream, in turn: a frame header and a payload each, of HEADERS and of DATA sizes.
const FRAMES: [(usize, usize); 2] = [(2, 40), (3, 1_197)];

/// Polls each of `ids` once, in order, as a pull producer is polled: the poll reads the stream's
/// send capacity once and stages frames of the sizes in [`FRAMES`] through `send_parts_within`,
/// the last cut to what is left, until the carried value runs out, and after each push checks
/// that a fresh send capacity equals the carried value. Without `carried`, the poll stages the
/// same frames through `send_parts`, reading the send capacity before each. Returns the bytes each
/// stream staged.
fn poll_round(conn: &mut Connection, ids: &[StreamId], carried: bool) -> Vec<(StreamId, u64)> {
    let zeros = Bytes::from_static(&[0; 2_000]);
    ids.iter()
        .map(|&id| {
            let mut stream = conn.stream(id).unwrap();
            let mut allowance = stream.send_capacity();
            let mut staged = 0;
            for (header, payload) in FRAMES.into_iter().cycle() {
                if !carried {
                    allowance = stream.send_capacity();
                }
                let len = (header + payload).min(allowance);
                if len == 0 {
                    break;
                }
                let (header, payload) = (
                    zeros.slice(..header.min(len)),
                    zeros.slice(header.min(len)..len),
                );
                if carried {
                    stream
                        .send_parts_within(&mut allowance, header, payload)
                        .unwrap();
                    staged += len as u64;
                    assert_eq!(
                        stream.send_capacity(),
                        allowance,
                        "{id} after {staged} bytes"
                    );
                } else {
                    stream.send_parts(header, payload).unwrap();
                    staged += len as u64;
                }
            }
            (id, staged)
        })
        .collect()
}

/// Opens client streams at `orders` with stream windows of `window` bytes and wakes their
/// producers, then polls them as [`poll_round`] does: the pull-ready ones in the order the
/// listing gives, then the rest in the order they opened. Returns the bytes each stream staged,
/// sorted by stream ID, and the staging budget.
fn staged_by_round(
    orders: &[SendOrder],
    window: u64,
    carried: bool,
) -> (Vec<(StreamId, u64)>, u64) {
    let setup = Setup {
        server_transport: config(|c| c.max_streams_uni(100).max_stream_data_uni(window)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let mut ids: Vec<StreamId> = orders
        .iter()
        .map(|&order| {
            let id = conn.open_stream(Dir::Uni, order).unwrap();
            conn.stream(id).unwrap().wake_producer();
            id
        })
        .collect();
    let mut polled: Vec<StreamId> = conn.pull_ready().map(|(id, _)| id).collect();
    ids.retain(|id| !polled.contains(id));
    polled.extend(ids);
    let budget = conn.staging_budget();
    let mut staged = poll_round(conn, &polled, carried);
    staged.sort_by_key(|&(id, _)| id.into_inner());
    (staged, budget)
}

#[test]
fn a_carried_allowance_equals_a_fresh_one_through_a_round() {
    // 64 sequential streams whose windows add up to more than the staging budget: each takes its
    // window from what the budget has left, until the budget runs out.
    let orders = [ORDER; 64];
    let (staged, budget) = staged_by_round(&orders, 6_000, true);
    let mut left = budget;
    let expected: Vec<u64> = (0..64)
        .map(|_| {
            let take = left.min(6_000);
            left -= take;
            take
        })
        .collect();
    assert!(expected.contains(&0) && expected.iter().any(|&b| b > 0 && b < 6_000));
    assert_eq!(
        staged.iter().map(|&(_, bytes)| bytes).collect::<Vec<_>>(),
        expected,
        "sequential: carried"
    );
    assert_eq!(
        staged,
        staged_by_round(&orders, 6_000, false).0,
        "sequential: through send_parts alone"
    );

    // Incremental buckets of 1, 3 and 8 peers with windows of 40,000 bytes. What the rooms of the
    // first two buckets leave of the budget entitles each peer of the last to an eighth of it,
    // less than its window.
    let incremental = |urgency| SendOrder {
        urgency,
        incremental: true,
        ..ORDER
    };
    let orders: Vec<SendOrder> = [(1, 1), (2, 3), (4, 8)]
        .into_iter()
        .flat_map(|(urgency, peers)| std::iter::repeat_n(incremental(urgency), peers))
        .collect();
    let (staged, budget) = staged_by_round(&orders, 40_000, true);
    let entitled = (budget - 4 * 40_000) / 8;
    assert!(entitled < 40_000);
    let expected: Vec<u64> = [40_000; 4].into_iter().chain([entitled; 8]).collect();
    assert_eq!(
        staged.iter().map(|&(_, bytes)| bytes).collect::<Vec<_>>(),
        expected,
        "incremental: carried"
    );
    assert_eq!(
        staged,
        staged_by_round(&orders, 40_000, false).0,
        "incremental: through send_parts alone"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the carried allowance went stale")]
fn a_stale_carried_allowance_fails_the_debug_check() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    // Finished streams hold all but 15,536 bytes of the 256 KiB staging budget, so what the budget
    // leaves binds the allowance of `a`, and a push on `b` behind it lowers that allowance.
    for len in [CAP, CAP, CAP, 50_000] {
        let id = conn.open_stream(Dir::Uni, ORDER).unwrap();
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; len])), Ok(len));
        stream.finish().unwrap();
    }
    let [a, b] = [(); 2].map(|()| conn.open_stream(Dir::Uni, ORDER).unwrap());
    let mut carried = conn.stream(a).unwrap().send_capacity();
    assert_eq!(carried, 15_536);
    let mut bytes = Bytes::from_static(&[0; 1_000]);
    assert_eq!(conn.stream(b).unwrap().send(&mut bytes), Ok(1_000));
    assert_eq!(conn.stream(a).unwrap().send_capacity(), carried - 1_000);
    let _ = conn.stream(a).unwrap().send_parts_within(
        &mut carried,
        Bytes::from_static(&[0; 15_000]),
        Bytes::new(),
    );
}

/// An incremental order in the default bucket.
const INCREMENTAL: SendOrder = SendOrder {
    incremental: true,
    ..ORDER
};

/// Returns a setup whose windows are far beyond the per-stream cap and the staging budget, so
/// that stream and connection credit do not bound staging.
fn wide_windows() -> Setup {
    Setup {
        server_transport: config(|c| c.max_data(1 << 40).max_stream_data_uni(1 << 30)),
        ..Setup::default()
    }
}

/// Returns the streams the prioritizer schedules, in wire order.
fn wire_order(conn: &Connection) -> Vec<StreamId> {
    let streams = &conn.sources.streams.streams;
    streams
        .prioritizer()
        .iter()
        .filter_map(|slot| streams.get_slot(slot).map(|stream| stream.id()))
        .collect()
}

#[test]
fn pull_ready_follows_the_wire_schedulers_turns_within_an_incremental_bucket() {
    let (_, mut pair) = handshake(wide_windows().pair());
    let conn = pair.client.conn_mut();
    let [a, b, late] = [(); 3].map(|()| conn.open_stream(Dir::Uni, INCREMENTAL).unwrap());
    for id in [a, b] {
        let mut stream = conn.stream(id).unwrap();
        stream.wake_producer();
        assert_eq!(
            stream.send(&mut Bytes::from(vec![0; 32 * 1024])),
            Ok(32 * 1024)
        );
    }
    assert_eq!(wire_order(conn), [a, b]);
    // One datagram at a time until `a` has filled one and goes behind `b`.
    let one = TxLimits {
        max_segments: 1,
        ..pair.limits()
    };
    let conn = pair.client.conn_mut();
    let mut sink = VecSink::new(1500);
    for _ in 0..4 {
        if wire_order(conn) == [b, a] {
            break;
        }
        conn.poll_transmit(&one, &mut sink, &mut InlineSealer);
    }
    assert_eq!(wire_order(conn), [b, a]);
    assert_eq!(pull_ready_ids(conn), [b, a]);
    // A stream that has not staged bytes is outside the rotation and comes after its streams.
    conn.stream(late).unwrap().wake_producer();
    assert_eq!(pull_ready_ids(conn), [b, a, late]);
}

#[test]
fn incremental_streams_take_turns_of_one_datagram_and_join_behind_the_rotation() {
    let (_, mut pair) = handshake(wide_windows().pair());
    let one = TxLimits {
        max_segments: 1,
        ..pair.limits()
    };
    let mut sink = VecSink::new(1500);
    let conn = pair.client.conn_mut();
    let [x, a, b] = [(); 3].map(|()| conn.open_stream(Dir::Uni, INCREMENTAL).unwrap());
    let stage = |conn: &mut Connection, id, len| {
        let mut data = Bytes::from(vec![0; len]);
        assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(len));
    };
    for (id, len) in [(x, 500), (a, 32 * 1024), (b, 32 * 1024)] {
        stage(conn, id, len);
    }
    assert_eq!(wire_order(conn), [x, a, b]);
    // `x` runs out in its first datagram, and `a` fills the rest of it, which is its turn
    // however few bytes it wrote.
    for _ in 0..4 {
        if !wire_order(conn).contains(&x) {
            break;
        }
        conn.poll_transmit(&one, &mut sink, &mut InlineSealer);
    }
    assert_eq!(
        wire_order(conn),
        [b, a],
        "after the datagram `x` ran out in"
    );
    // Refilled, `x` joins behind both, and a new stream joins behind it.
    stage(conn, x, 32 * 1024);
    assert_eq!(wire_order(conn), [b, a, x]);
    let d = conn.open_stream(Dir::Uni, INCREMENTAL).unwrap();
    stage(conn, d, 32 * 1024);
    assert_eq!(wire_order(conn), [b, a, x, d]);
    // A new order within the bucket does not move the stream; a move to another bucket and back
    // puts the stream at the back.
    conn.stream(x).unwrap().set_order(SendOrder {
        order: 9,
        ..INCREMENTAL
    });
    assert_eq!(wire_order(conn), [b, a, x, d], "a new order field");
    conn.stream(a).unwrap().set_order(SendOrder {
        urgency: 6,
        ..INCREMENTAL
    });
    conn.stream(a).unwrap().set_order(INCREMENTAL);
    assert_eq!(wire_order(conn), [b, x, d, a], "back from another bucket");
    // Each full datagram is one turn.
    for _ in 0..4 {
        if wire_order(conn) != [b, x, d, a] {
            break;
        }
        conn.poll_transmit(&one, &mut sink, &mut InlineSealer);
    }
    assert_eq!(wire_order(conn), [x, d, a, b], "after a datagram of `b`");
}

/// What a producer that always has data stages: zeros, shared.
static ZEROS: [u8; CAP] = [0; CAP];

/// Runs a pull driver's app phase: in list order, each stream `pull_ready` lists stages what it
/// takes now, as a producer that always has data does.
fn pull_phase(conn: &mut Connection) {
    let listed: Vec<_> = conn.pull_ready().collect();
    for (id, listed) in listed {
        let mut stream = conn.stream(id).unwrap();
        let allowance = stream.send_capacity();
        assert!(
            allowance <= listed,
            "{id} takes {allowance}, listed with {listed}"
        );
        let mut data = Bytes::from_static(&ZEROS[..allowance]);
        assert_eq!(stream.send(&mut data), Ok(allowance));
    }
}

/// Consumes every byte the connection reports readable, counting the bytes by stream.
fn read_and_count(conn: &mut Connection, read: &mut BTreeMap<StreamId, u64>) {
    loop {
        let next = conn.readiness().next();
        let Some((id, edge)) = next else {
            return;
        };
        if matches!(edge, StreamReady::Opened | StreamReady::Readable)
            && let Ok(mut stream) = conn.stream(id)
        {
            let n = stream.readable().chain_length();
            stream.consume(n).expect("the readable bytes");
            *read.entry(id).or_default() += n as u64;
        }
    }
}

/// Runs one turn of the driver loop: the client's app phase, its transmission, the server
/// reading what arrived, and on to the next delivery or timer.
fn driver_turn(pair: &mut Pair, read: &mut BTreeMap<StreamId, u64>) {
    pull_phase(pair.client.conn_mut());
    pair.step();
    read_and_count(pair.server.conn_mut(), read);
    pair.step();
    let at = pair
        .next_event()
        .expect("transmission goes on while producers have data");
    pair.now = pair.now.max(at);
}

/// Returns the bytes `read` counts for `id` beyond those `before` counts.
fn read_since(
    read: &BTreeMap<StreamId, u64>,
    before: &BTreeMap<StreamId, u64>,
    id: StreamId,
) -> u64 {
    read.get(&id).copied().unwrap_or(0) - before.get(&id).copied().unwrap_or(0)
}

#[test]
fn incremental_pull_streams_with_sustained_demand_share_the_wire_alike() {
    let (start, mut pair) = handshake(wide_windows().pair());
    let conn = pair.client.conn_mut();
    // A window held at 50 datagrams keeps the staging budget at its 256 KiB floor, which eight
    // streams with room for 64 KiB each would more than fill.
    let window = CcConfig {
        max_window_packets: 50,
        ..CcConfig::default()
    };
    conn.cc = Cc::new(CongestionControl::NewReno, &window, 1200).unwrap();
    assert_eq!(conn.staging_budget(), 256 * 1024);
    let mut streams: Vec<_> = (0..8)
        .map(|_| {
            let id = conn.open_stream(Dir::Uni, INCREMENTAL).unwrap();
            conn.stream(id).unwrap().wake_producer();
            id
        })
        .collect();
    // Each of the eight may stage E = 256 KiB / 8 = 32 KiB and is topped up once 16 KiB has gone
    // out, so a stream's bytes do not run more than E ahead of another's.
    let bound = 32 * 1024;
    let mut read = BTreeMap::new();
    let none = BTreeMap::new();
    let spread =
        |read: &BTreeMap<StreamId, u64>, before: &BTreeMap<StreamId, u64>, ids: &[StreamId]| {
            let sent = ids.iter().map(|&id| read_since(read, before, id));
            sent.clone().max().unwrap() - sent.min().unwrap()
        };
    while read.values().sum::<u64>() < 1 << 20 {
        assert!(pair.now < start + 60 * LIMIT, "no progress: {read:?}");
        driver_turn(&mut pair, &mut read);
        assert!(spread(&read, &none, &streams) <= bound, "{read:?}");
    }
    // A ninth stream joins and settles in; then the nine share alike, each entitled to
    // 256 KiB / 9.
    let conn = pair.client.conn_mut();
    let ninth = conn.open_stream(Dir::Uni, INCREMENTAL).unwrap();
    conn.stream(ninth).unwrap().wake_producer();
    streams.push(ninth);
    let joined = read.clone();
    while streams
        .iter()
        .map(|&id| read_since(&read, &joined, id))
        .sum::<u64>()
        < 1 << 19
    {
        driver_turn(&mut pair, &mut read);
    }
    assert!(read_since(&read, &joined, ninth) > 0, "{read:?}");
    let settled = read.clone();
    while streams
        .iter()
        .map(|&id| read_since(&read, &settled, id))
        .sum::<u64>()
        < 1 << 20
    {
        assert!(pair.now < start + 120 * LIMIT, "no progress: {read:?}");
        driver_turn(&mut pair, &mut read);
    }
    assert!(
        spread(&read, &settled, &streams) <= bound,
        "{read:?} since {settled:?}"
    );
}

#[test]
fn a_peer_at_its_cap_still_counts_among_its_buckets_peers() {
    let (_, mut pair) = handshake(wide_windows().pair());
    let conn = pair.client.conn_mut();
    let streams = [(); 8].map(|()| conn.open_stream(Dir::Uni, INCREMENTAL).unwrap());
    // The first stages up to its cap while it is its bucket's only peer.
    let mut capped = conn.stream(streams[0]).unwrap();
    assert_eq!(capped.send(&mut Bytes::from_static(&ZEROS)), Ok(CAP));
    assert_eq!(capped.send_capacity(), 0, "no room at the cap");
    for &id in &streams[1..] {
        conn.stream(id).unwrap().wake_producer();
    }
    // The eight are each entitled to an equal part of the 192 KiB left and the 64 KiB the
    // capped one holds: 32 KiB.
    assert_eq!(
        conn.pull_ready().collect::<Vec<_>>(),
        streams[1..]
            .iter()
            .map(|&id| (id, 32 * 1024))
            .collect::<Vec<_>>()
    );
}

#[test]
fn incremental_streams_of_a_bucket_share_the_staging_budget_alike() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let incremental = SendOrder {
        class: 1,
        urgency: 3,
        incremental: true,
        order: 0,
    };
    let streams = [(); 8].map(|()| conn.open_stream(Dir::Uni, incremental).unwrap());
    for id in streams {
        let mut stream = conn.stream(id).unwrap();
        stream.wake_producer();
        assert_eq!(stream.send(&mut Bytes::from_static(b"x")), Ok(1));
    }
    // Eight peers with a byte staged each are entitled to an equal part of what the 256 KiB
    // budget has left and what they hold, and may stage that less their byte.
    let entitled = 256 * 1024 / 8;
    assert_eq!(
        conn.pull_ready().collect::<Vec<_>>(),
        streams.map(|id| (id, entitled - 1))
    );
    // A stream without demand does not take from their shares; its allowance counts it as a
    // ninth peer.
    let fresh = conn.open_stream(Dir::Uni, incremental).unwrap();
    assert_eq!(conn.stream(fresh).unwrap().send_capacity(), 256 * 1024 / 9);
    assert_eq!(
        conn.stream(streams[7]).unwrap().send_capacity(),
        entitled - 1
    );
    // Woken, it is a peer, and the nine split alike.
    conn.stream(fresh).unwrap().wake_producer();
    let entitled = 256 * 1024 / 9;
    let mut nine: Vec<_> = streams.iter().map(|&id| (id, entitled - 1)).collect();
    nine.push((fresh, entitled));
    assert_eq!(conn.pull_ready().collect::<Vec<_>>(), nine);
}

#[test]
fn pull_ready_lists_streams_with_room_in_wire_order_with_their_share_of_the_staging_budget() {
    // Stream windows larger than the per-stream cap, so that the cap bounds the room.
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(1 << 20)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    let order = |urgency, order| SendOrder {
        class: 1,
        urgency,
        incremental: false,
        order,
    };
    let later = conn.open_stream(Dir::Bi, order(3, 1)).unwrap();
    let urgent = conn.open_stream(Dir::Bi, order(0, 0)).unwrap();
    let first = conn.open_stream(Dir::Bi, order(3, 0)).unwrap();
    for id in [later, urgent, first] {
        conn.stream(id).unwrap().wake_producer();
    }
    let ready = |conn: &mut Connection| conn.pull_ready().collect::<Vec<_>>();
    assert_eq!(ready(conn), [(urgent, CAP), (first, CAP), (later, CAP)]);
    // Near the per-stream cap, a stream is not polled until a quarter of the cap is free again.
    let staged = 60 * 1024;
    let send = |conn: &mut Connection, id, len| {
        let mut stream = conn.stream(id).unwrap();
        assert_eq!(stream.send(&mut Bytes::from(vec![0; len])), Ok(len));
    };
    send(conn, urgent, staged);
    assert_eq!(ready(conn), [(first, CAP), (later, CAP)]);
    // The budget less what is staged goes to the streams with demand in wire order, each taking
    // its room. Streams whose producers are pending are not polled, and the 4 KiB left at the
    // end is what one of them would take.
    assert_eq!(conn.stream(urgent).unwrap().finish(), Ok(()));
    let more = [(); 3].map(|()| conn.open_stream(Dir::Uni, order(5, 0)).unwrap());
    conn.stream(more[0]).unwrap().wake_producer();
    for id in [first, later, more[0]] {
        send(conn, id, 1);
    }
    let room = CAP - 1;
    assert_eq!(ready(conn), [(first, room), (later, room), (more[0], room)]);
    assert_eq!(conn.stream(more[1]).unwrap().send_capacity(), 4 * 1024);
    // Woken, a stream is polled for that 4 KiB, its prefix share, which caps its low-water
    // mark; that takes the rest of the budget, so the stream after it is not polled.
    for id in [more[1], more[2]] {
        conn.stream(id).unwrap().wake_producer();
    }
    assert_eq!(
        ready(conn),
        [
            (first, room),
            (later, room),
            (more[0], room),
            (more[1], 4 * 1024)
        ]
    );
}

/// Sends `len` bytes each way, client to server on a bidirectional stream and server to client
/// on a unidirectional one, both ended with the FIN, and checks both arrive whole.
fn bulk_both_ways(config: PairConfig, len: usize) -> Pair {
    let (epoch, mut pair) = handshake(config);
    let (mut client, mut server) = (App::default(), App::default());
    let up = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let down = pair.server.conn_mut().open_stream(Dir::Uni, ORDER).unwrap();
    client.write(up, pattern(len), true);
    server.write(down, pattern(len), true);
    let done = |app: &App, id| app.edges_of(id).contains(&StreamReady::Finished);
    while !(done(&server, up) && done(&client, down)) {
        assert!(pair.now < epoch + 60 * LIMIT, "no progress");
        let until = pair.now + RTT;
        run_apps(&mut pair, until, &mut client, &mut server);
    }
    for (got, id) in [(&server.data, up), (&client.data, down)] {
        assert_eq!(got[&id].len(), len);
        assert!(got[&id] == pattern(len), "{id} arrived altered");
    }
    for peer in [&pair.client, &pair.server] {
        assert_eq!(
            peer.conn().stats().tx_inconsistent,
            0,
            "every first candidate fits an empty packet"
        );
    }
    pair
}

#[test]
fn bulk_data_crosses_both_ways() {
    bulk_both_ways(Setup::default().pair(), 2 << 20);
}

#[test]
fn bulk_data_crosses_both_ways_over_lossy_links() {
    let mut config = Setup::default().pair();
    for (link, seed) in [(&mut config.to_server, 7), (&mut config.to_client, 8)] {
        link.loss = Loss::Seeded {
            seed,
            per_mille: 30,
        };
    }
    let pair = bulk_both_ways(config, 1 << 20);
    assert!(pair.to_server.lost() > 0 && pair.to_client.lost() > 0);
}

/// Returns the index of the first datagram `peer` sent from `from` on that carries `frame`.
fn datagram_with(peer: &Peer, from: usize, frame: Sent) -> usize {
    (from..peer.sent.len())
        .find(|&i| frames_in(peer, i..i + 1).contains(&frame))
        .expect("the frame was sent")
}

/// Counts how often `sent` holds `frame`.
fn count(sent: &[Sent], frame: Sent) -> usize {
    sent.iter().filter(|&&f| f == frame).count()
}

/// Sends 8,000 bytes from the client into an 8,000-byte stream window and reads them at the
/// server, with the server's datagrams `dropped` lost. Returns the pair, the stream and the first
/// datagram each side sent after the handshake.
fn credit_round(dropped: Vec<usize>) -> (Pair, StreamId, usize, usize) {
    let mut config = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(8_000)),
        ..Setup::default()
    }
    .pair();
    config.to_client.loss = Loss::Drop(dropped);
    let (_, mut pair) = handshake(config);
    let (client_from, server_from) = (pair.client.sent.len(), pair.server.sent.len());
    let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from(pattern(8_000))), Ok(8_000));
    pair.run(pair.now + RTT);
    assert_eq!(read_all(pair.server.conn_mut(), a), CreditDue::Due);
    pair.run(pair.now + 10 * RTT);
    (pair, a, client_from, server_from)
}

#[test]
fn a_lost_credit_update_that_is_still_current_goes_again() {
    let (probe, a, _, server_from) = credit_round(Vec::new());
    let update = Sent::MaxStreamData(a, 16_000);
    let lost = datagram_with(&probe.server, server_from, update);
    let (mut pair, a, _, server_from) = credit_round(vec![lost]);
    assert_eq!(count(&sent_frames(&pair.server, server_from), update), 2);
    assert_eq!(
        pair.client.conn_mut().stream(a).unwrap().send_capacity(),
        8_000
    );
}

#[test]
fn a_lost_blocked_frame_whose_limit_has_since_risen_does_not_go_again() {
    // The client fills an 8,000-byte stream window, with its datagrams `dropped` lost, while
    // the server reads everything at once.
    let round = |dropped: Vec<usize>| {
        let mut config = Setup {
            server_transport: config(|c| c.max_stream_data_bidi_remote(8_000)),
            ..Setup::default()
        }
        .pair();
        config.to_server.loss = Loss::Drop(dropped);
        let (_, mut pair) = handshake(config);
        let (mut client, mut server) = (App::default(), App::default());
        let client_from = pair.client.sent.len();
        let a = pair.client.conn_mut().open_stream(Dir::Bi, ORDER).unwrap();
        client.write(a, pattern(8_000), false);
        let until = pair.now + 10 * RTT;
        run_apps(&mut pair, until, &mut client, &mut server);
        assert_eq!(server.data[&a].len(), 8_000);
        (pair, a, client_from)
    };
    let (probe, a, client_from) = round(Vec::new());
    let blocked = Sent::StreamDataBlocked(a, 8_000);
    let lost = datagram_with(&probe.client, client_from, blocked);
    let (pair, a, client_from) = round(vec![lost]);
    let sent = sent_frames(&pair.client, client_from);
    let blocked_frames = sent
        .iter()
        .filter(|f| matches!(f, Sent::StreamDataBlocked(..)))
        .collect::<Vec<_>>();
    assert_eq!(
        blocked_frames,
        [&Sent::StreamDataBlocked(a, 8_000)],
        "nor at the risen limit"
    );
    assert!(
        pair.client.conn().stats().lost_packets > 0,
        "the loss was detected"
    );
}

#[test]
fn no_stream_opens_after_shutdown_or_close() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let now = pair.now;
    let server = pair.server.conn_mut();
    server.shutdown(now);
    assert_eq!(server.open_stream(Dir::Bi, ORDER), Err(OpenError::Closed));
    let client = pair.client.conn_mut();
    assert!(client.open_stream(Dir::Bi, ORDER).is_ok());
    client.close(now, AppCode::from_u32(0), Bytes::new());
    assert_eq!(client.open_stream(Dir::Uni, ORDER), Err(OpenError::Closed));
}

#[test]
fn send_parts_stages_a_header_and_a_shared_payload_both_or_neither() {
    let setup = Setup {
        server_transport: config(|c| c.max_stream_data_bidi_remote(1_000)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let (mut client, mut server) = (App::default(), App::default());
    let shared = Bytes::from(pattern(600));
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(
        stream.send_parts(Bytes::from_static(b"head"), shared.clone()),
        Ok(())
    );
    assert_eq!(stream.send_capacity(), 1_000 - 604);
    assert_eq!(
        stream.send_parts(Bytes::from_static(b"head"), shared.clone()),
        Err(SendError::OverAllowance),
        "the second payload does not fit"
    );
    assert_eq!(stream.send_capacity(), 1_000 - 604, "nothing was stored");
    stream.finish().unwrap();
    assert_eq!(
        stream.send_parts(Bytes::new(), Bytes::new()),
        Err(SendError::Ended)
    );
    let until = pair.now + RTT;
    run_apps(&mut pair, until, &mut client, &mut server);
    let mut expected = b"head".to_vec();
    expected.extend_from_slice(&shared);
    assert!(server.data[&a] == expected);
}

#[test]
fn an_empty_stream_ends_with_its_fin_and_closes_without_a_read() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Uni, ORDER).unwrap();
    assert_eq!(conn.stream(a).unwrap().finish(), Ok(()));
    pair.run(pair.now + 2 * RTT);
    assert_eq!(
        edges(pair.server.conn_mut()),
        [
            (a, StreamReady::Opened),
            (a, StreamReady::Finished),
            (a, StreamReady::Closed)
        ]
    );
    assert_eq!(edges(pair.client.conn_mut()), [(a, StreamReady::Closed)]);
}

#[test]
fn misuse_of_a_stream_is_a_typed_error() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let own = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = conn.stream(own).unwrap();
    assert_eq!(stream.consume(0), Err(StreamError::NoReceiveHalf));
    assert!(stream.readable().is_empty());
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(
        conn.stream(a).unwrap().consume(1),
        Err(StreamError::BeyondReadable)
    );
    let server = pair.server.conn_mut();
    let theirs = server.open_stream(Dir::Uni, ORDER).unwrap();
    server
        .stream(theirs)
        .unwrap()
        .send(&mut Bytes::from_static(b"x"))
        .unwrap();
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    edges(conn);
    let mut stream = conn.stream(theirs).unwrap();
    assert_eq!(
        stream.send(&mut Bytes::from_static(b"x")),
        Err(SendError::NoSendHalf)
    );
    assert_eq!(stream.finish(), Err(SendError::NoSendHalf));
    assert_eq!(
        stream.reset(AppCode::from_u32(1)),
        Err(SendError::NoSendHalf)
    );
    assert_eq!(stream.send_capacity(), 0);
    assert_eq!(stream.consume(2), Err(StreamError::BeyondReadable));
    assert_eq!(readable(&stream), b"x", "a refused call changes nothing");
}

#[test]
fn sent_end_reports_the_offset_after_the_last_byte_sent() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.sent_end(), 0, "staged, not sent");
    pair.step();
    assert_eq!(pair.client.conn_mut().stream(a).unwrap().sent_end(), 5);
}

#[test]
fn acked_end_reports_the_offset_below_which_every_byte_is_acknowledged() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.step();
    assert_eq!(
        pair.client.conn_mut().stream(a).unwrap().acked_end(),
        0,
        "sent; the ACK is a round trip away"
    );
    pair.run(pair.now + RTT);
    assert_eq!(pair.client.conn_mut().stream(a).unwrap().acked_end(), 5);
}

#[test]
fn progress_is_reported_once_when_the_acknowledged_bytes_reach_the_tracked_offset() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(6), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5);
    assert_eq!(edges(conn), [], "the acknowledged bytes stop short of 6");
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"!")), Ok(1));
    pair.step();
    assert_eq!(edges(pair.client.conn_mut()), [], "sent, not acknowledged");
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 6);
    assert_eq!(edges(conn), [(a, StreamReady::Progress)]);
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"more")), Ok(4));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 10);
    assert_eq!(edges(conn), [], "the offset is reported once");
}

#[test]
fn progress_at_an_offset_acknowledged_already_is_reported_at_once() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5);
    assert_eq!(conn.stream(a).unwrap().track(3), Ok(()));
    assert_eq!(edges(conn), [(a, StreamReady::Progress)]);
}

#[test]
fn progress_past_the_final_size_waits_for_the_fin_to_be_acknowledged() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(
        stream.track(6),
        Ok(()),
        "the FIN counts as the byte at the final size"
    );
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5);
    assert_eq!(
        edges(conn),
        [],
        "every byte is acknowledged, but the FIN is not sent"
    );
    assert_eq!(conn.stream(a).unwrap().finish(), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(
        conn.sources.streams.streams.get(a).unwrap().send_state(),
        Some(SendState::DataRecvd),
        "the FIN is acknowledged"
    );
    assert_eq!(edges(conn), [(a, StreamReady::Progress)]);
}

#[test]
fn a_reset_cancels_the_tracked_offset() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.step();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.track(5), Ok(()));
    assert_eq!(stream.reset(AppCode::from_u32(7)), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert!(
        matches!(
            conn.sources.streams.streams.get(a).unwrap().send_state(),
            Some(SendState::ResetRecvd { .. })
        ),
        "the bytes and the RESET_STREAM are acknowledged"
    );
    assert_eq!(edges(conn), []);
}

#[test]
fn a_reset_drops_an_undelivered_progress_edge() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(5), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5, "the edge is marked");
    assert_eq!(conn.stream(a).unwrap().reset(AppCode::from_u32(7)), Ok(()));
    assert_eq!(edges(conn), []);
}

#[test]
fn a_peer_stop_sending_drops_an_undelivered_progress_edge() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(5), Ok(()));
    pair.run(pair.now + RTT);
    assert_eq!(pair.client.conn_mut().stream(a).unwrap().acked_end(), 5);
    let code = AppCode::from_u32(9);
    let server = pair.server.conn_mut();
    assert_eq!(server.stream(a).unwrap().stop_sending(code), Ok(()));
    pair.run(pair.now + RTT);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(a, StreamReady::Stopped { code })],
        "the STOP_SENDING reset the send half"
    );
}

#[test]
fn track_on_a_stream_without_a_send_half_is_refused() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let server = pair.server.conn_mut();
    let theirs = server.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = server.stream(theirs).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"x")), Ok(1));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(
        edges(conn),
        [
            (theirs, StreamReady::Opened),
            (theirs, StreamReady::Readable)
        ]
    );
    let mut stream = conn.stream(theirs).unwrap();
    assert_eq!(stream.track(0), Err(SendError::NoSendHalf));
    assert_eq!((stream.acked_end(), stream.sent_end()), (0, 0));
    assert_eq!(edges(conn), [], "a refused track marks nothing");
}

#[test]
fn track_after_a_reset_is_refused() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.step();
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.reset(AppCode::from_u32(7)), Ok(()));
    assert_eq!(stream.track(5), Err(SendError::Ended));
    pair.run(pair.now + RTT);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [],
        "the ACK of the bytes reports nothing"
    );
}

#[test]
fn track_after_the_peer_stopped_the_stream_is_refused_with_its_code() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.run(pair.now + RTT);
    let code = AppCode::from_u32(9);
    let server = pair.server.conn_mut();
    assert_eq!(server.stream(a).unwrap().stop_sending(code), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(edges(conn), [(a, StreamReady::Stopped { code })]);
    assert_eq!(
        conn.stream(a).unwrap().track(5),
        Err(SendError::Stopped { code })
    );
}

/// Returns stream `id`'s capacity after parking its producer, or after waking it if `ready`.
fn capacity_when(conn: &mut Connection, id: StreamId, ready: bool) -> usize {
    let mut stream = conn.stream(id).unwrap();
    if ready {
        stream.wake_producer();
    } else {
        stream.park_producer();
    }
    stream.send_capacity()
}

#[test]
fn a_parked_stream_reports_the_capacity_it_has_with_a_ready_producer() {
    let (_, mut pair) = handshake(wide_windows().pair());
    let conn = pair.client.conn_mut();
    let busy = conn.open_stream(Dir::Uni, INCREMENTAL).unwrap();
    assert_eq!(
        conn.stream(busy)
            .unwrap()
            .send(&mut Bytes::from(vec![0; CAP])),
        Ok(CAP)
    );
    let parked = conn.open_stream(Dir::Uni, INCREMENTAL).unwrap();
    assert_eq!(
        capacity_when(conn, parked, false),
        CAP,
        "half of the 256 KiB budget and what the busy peer holds is 128 KiB, so the cap binds"
    );
    assert_eq!(capacity_when(conn, parked, true), CAP);

    let (_, mut pair) = handshake(wide_windows().pair());
    let conn = pair.client.conn_mut();
    fill_the_staging_budget(conn);
    let parked = conn.open_stream(Dir::Uni, ORDER).unwrap();
    assert_eq!(
        capacity_when(conn, parked, false),
        0,
        "the streams ahead hold the whole budget"
    );
    assert_eq!(capacity_when(conn, parked, true), 0);
}

#[test]
fn progress_comes_before_the_closed_edge_of_a_stream_the_acknowledgment_ends() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let uni = conn.open_stream(Dir::Uni, ORDER).unwrap();
    let mut stream = conn.stream(uni).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.finish(), Ok(()));
    assert_eq!(stream.track(6), Ok(()));
    pair.run(pair.now + RTT);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(uni, StreamReady::Progress), (uni, StreamReady::Closed)]
    );
}

#[test]
fn tracking_a_new_offset_drops_the_undelivered_edge_of_the_one_before() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(5), Ok(()));
    pair.run(pair.now + RTT);
    let mut stream = pair.client.conn_mut().stream(a).unwrap();
    assert_eq!(stream.acked_end(), 5, "the edge for 5 is marked");
    assert_eq!(stream.finish(), Ok(()));
    assert_eq!(stream.track(6), Ok(()));
    assert_eq!(
        edges(pair.client.conn_mut()),
        [],
        "the FIN is not acknowledged"
    );
    pair.run(pair.now + RTT);
    assert_eq!(edges(pair.client.conn_mut()), [(a, StreamReady::Progress)]);
}

#[test]
fn each_track_replaces_the_offset_tracked_before() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(10), Ok(()));
    assert_eq!(stream.track(3), Ok(()));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5);
    assert_eq!(edges(conn), [(a, StreamReady::Progress)], "3 replaced 10");
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"world")), Ok(5));
    assert_eq!(
        stream.track(10),
        Ok(()),
        "a reported offset may be followed by another"
    );
    pair.step();
    assert_eq!(edges(pair.client.conn_mut()), [], "sent, not acknowledged");
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 10);
    assert_eq!(edges(conn), [(a, StreamReady::Progress)]);
}

#[test]
fn progress_at_offset_zero_is_reported_at_once() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    assert_eq!(conn.stream(a).unwrap().track(0), Ok(()));
    assert_eq!(edges(conn), [(a, StreamReady::Progress)]);
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(conn.stream(a).unwrap().acked_end(), 5);
    assert_eq!(edges(conn), [], "nothing is tracked after the edge");
}

#[test]
fn a_peer_stop_sending_before_the_ack_cancels_the_tracked_offset() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let server = pair.server.conn_mut();
    let theirs = server.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = server.stream(theirs).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"x")), Ok(1));
    pair.run(pair.now + RTT);
    let conn = pair.client.conn_mut();
    assert_eq!(
        edges(conn),
        [
            (theirs, StreamReady::Opened),
            (theirs, StreamReady::Readable)
        ]
    );
    let mut stream = conn.stream(theirs).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.track(5), Ok(()));
    // Both sides send at the same instant, so the STOP_SENDING reaches the client before the ACK.
    let code = AppCode::from_u32(9);
    let server = pair.server.conn_mut();
    assert_eq!(server.stream(theirs).unwrap().stop_sending(code), Ok(()));
    pair.run(pair.now + RTT);
    assert_eq!(
        send_state(&pair.client, theirs),
        Some(SendState::ResetRecvd {
            code,
            final_size: 5
        }),
        "the bytes went out before the STOP_SENDING arrived, and the RESET_STREAM is acknowledged"
    );
    assert_eq!(
        edges(pair.client.conn_mut()),
        [(theirs, StreamReady::Stopped { code })],
        "the ACK of the bytes reports nothing"
    );
}

#[test]
fn a_stop_sending_after_the_fin_is_acknowledged_keeps_an_undelivered_progress_edge() {
    let (_, mut pair) = handshake(Setup::default().pair());
    let conn = pair.client.conn_mut();
    let a = conn.open_stream(Dir::Bi, ORDER).unwrap();
    let mut stream = conn.stream(a).unwrap();
    assert_eq!(stream.send(&mut Bytes::from_static(b"hello")), Ok(5));
    assert_eq!(stream.finish(), Ok(()));
    assert_eq!(stream.track(6), Ok(()));
    pair.run(pair.now + RTT);
    assert_eq!(
        send_state(&pair.client, a),
        Some(SendState::DataRecvd),
        "the FIN is acknowledged, so the edge is marked"
    );
    to_client(
        &mut pair,
        &[Frame::StopSending {
            id: a,
            error_code: varint(9),
        }],
    );
    let code = AppCode::from_u32(9);
    assert_eq!(
        edges(pair.client.conn_mut()),
        [
            (a, StreamReady::Stopped { code }),
            (a, StreamReady::Progress)
        ],
        "a send half that ended does not reset, so its progress stands"
    );
}
