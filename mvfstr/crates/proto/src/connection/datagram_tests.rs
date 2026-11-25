/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! DATAGRAM frames (RFC 9221) over the pair harness of [`crate::testing`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use super::Connection;
use super::stream_tests::ORDER;
use super::tests::Forge;
use super::tests::LIMIT;
use super::tests::client_addr;
use super::tests::deliver;
use super::tests::handshake;
use super::tests::limits;
use super::tests::local_close;
use super::tests::open_own_one_rtt;
use super::tests::start;
use crate::AppCode;
use crate::ConnEvent;
use crate::DatagramError;
use crate::InlineSealer;
use crate::SendOrder;
use crate::TransportConfig;
use crate::TxLimits;
use crate::recovery::Space;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

/// Delivers a 1-RTT packet holding `frames` from the client to the server of a pair handshaken
/// with `setup`, and returns the server's CONNECTION_CLOSE, if it sent one.
fn server_close_on(
    setup: &Setup,
    frames: &[Frame<'_>],
) -> Option<(TransportErrorCode, Option<VarInt>)> {
    server_close_on_bytes(setup, frames, &[])
}

/// Like [`server_close_on`], with `raw` written after `frames` as it is.
fn server_close_on_bytes(
    setup: &Setup,
    frames: &[Frame<'_>],
    raw: &[u8],
) -> Option<(TransportErrorCode, Option<VarInt>)> {
    let (_, mut pair) = handshake(setup.pair());
    let now = pair.now;
    let client = pair.client.conn();
    let pn = client.recovery.space(Space::Data).next_pn() + 10;
    let mut forge = Forge::of(client, Space::Data, pn, frames);
    forge.raw = raw;
    let packet = forge.seal(client);
    let server = pair.server.conn_mut();
    let summary = deliver(server, now, client_addr(), packet);
    assert_eq!(summary.packets, 1);
    local_close(server)
}

#[test]
fn a_datagram_frame_to_an_endpoint_that_did_not_advertise_them_is_a_protocol_violation() {
    let datagram = Frame::Datagram {
        data: b"unasked",
        with_length: true,
    };
    assert_eq!(
        server_close_on(&Setup::default(), &[datagram]),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(0x31))
        ))
    );
}

/// Returns a setup whose two sides take DATAGRAM frames of up to `max` bytes.
fn datagrams_up_to(max: u64) -> Setup {
    let transport = TransportConfig::builder()
        .max_datagram_frame_size(max)
        .build()
        .unwrap();
    Setup::default().transport(transport)
}

#[test]
fn a_datagram_frame_larger_than_advertised_is_a_protocol_violation() {
    // The limit counts the frame's type and Length field (RFC 9221): 1 + 1 + 48 bytes fit 50.
    let setup = datagrams_up_to(50);
    let violation = Some((
        TransportErrorCode::PROTOCOL_VIOLATION,
        Some(VarInt::from_u32(0x31)),
    ));
    let at_limit = Frame::Datagram {
        data: &[7; 48],
        with_length: true,
    };
    assert_eq!(server_close_on(&setup, &[at_limit]), None);
    let over = Frame::Datagram {
        data: &[7; 49],
        with_length: true,
    };
    assert_eq!(server_close_on(&setup, &[over]), violation);
    // Without a Length field the frame is one byte shorter.
    let no_length = Frame::Datagram {
        data: &[7; 49],
        with_length: false,
    };
    assert_eq!(server_close_on(&setup, &[no_length]), None);
}

#[test]
fn the_size_limit_counts_a_datagram_frames_length_field_as_sent() {
    // RFC 9000 lets a Length field take more bytes than its value needs. The limit is on the frame
    // as received: a 2-byte Length makes 48 bytes of data a 51-byte frame, over a limit of 50.
    let setup = datagrams_up_to(50);
    let frame = |data: usize| [&[0x31, 0x40, data as u8][..], &[7; 48][..data]].concat();
    assert_eq!(server_close_on_bytes(&setup, &[], &frame(47)), None);
    assert_eq!(
        server_close_on_bytes(&setup, &[], &frame(48)),
        Some((
            TransportErrorCode::PROTOCOL_VIOLATION,
            Some(VarInt::from_u32(0x31))
        ))
    );
}

#[test]
fn each_side_sends_datagrams_once_the_other_advertised_them() {
    let (_, pair) = start(datagrams_up_to(65535).pair());
    assert_eq!(
        pair.client.conn().max_datagram_size(),
        0,
        "before the handshake"
    );
    let (_, pair) = handshake(datagrams_up_to(65535).pair());
    for conn in [pair.client.conn(), pair.server.conn()] {
        assert_eq!(conn.peer_max_datagram_frame_size(), 65535);
        // A 1,200-byte datagram holds a short header with an 8-byte connection ID and a 4-byte
        // packet number, the frame and the 16-byte tag; the frame's type and 2-byte Length leave
        // 1,168 bytes of data.
        assert_eq!(conn.max_datagram_size(), 1168);
    }
    // Only the client advertises them: the server may send datagrams, the client may not.
    let setup = Setup {
        server_transport: Arc::new(TransportConfig::default()),
        ..datagrams_up_to(65535)
    };
    let (_, mut pair) = handshake(setup.pair());
    assert_eq!(pair.server.conn().max_datagram_size(), 1168);
    let client = pair.client.conn_mut();
    assert_eq!(client.max_datagram_size(), 0);
    assert_eq!(
        client.send_datagram(&[Bytes::from_static(b"x")], ORDER, None),
        Err(DatagramError::Unsupported)
    );
    pair.server
        .conn_mut()
        .send_datagram(&[Bytes::from_static(b"to the client")], ORDER, None)
        .unwrap();
    let limit = pair.now + LIMIT;
    assert!(pair.run_until(limit, |pair| {
        pair.client.has_event(&ConnEvent::DatagramsReadable)
    }));
    assert_eq!(
        pair.client.conn_mut().read_datagram().as_deref(),
        Some(&b"to the client"[..])
    );
}

#[test]
fn a_datagram_over_the_peers_limit_or_in_more_than_five_parts_is_refused() {
    let (_, mut pair) = handshake(datagrams_up_to(50).pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    // The type and a 1-byte Length leave 48 of the peer's 50 bytes for data.
    assert_eq!(client.max_datagram_size(), 48);
    let data = Bytes::from(vec![9; 49]);
    assert_eq!(
        client.send_datagram(&[data.slice(..9), data.slice(9..)], ORDER, None),
        Err(DatagramError::TooLarge)
    );
    assert_eq!(
        client.send_datagram(&[data.slice(..9), data.slice(9..48)], ORDER, None),
        Ok(())
    );
    let parts = vec![data.slice(..1); 6];
    assert_eq!(
        client.send_datagram(&parts, ORDER, None),
        Err(DatagramError::TooManyParts)
    );
    assert_eq!(client.send_datagram(&parts[..5], ORDER, None), Ok(()));
    client.close(now, AppCode(VarInt::from_u32(0)), Bytes::new());
    assert_eq!(
        client.send_datagram(&parts[..1], ORDER, None),
        Err(DatagramError::Closed)
    );
}

/// Returns the DATAGRAM frames in the 1-RTT packets of the datagrams `conn` sent into `sink`, each
/// as its data and whether it carried a Length field.
fn datagram_frames(conn: &Connection, sink: &mut VecSink) -> Vec<(Vec<u8>, bool)> {
    let mut frames = Vec::new();
    for sent in sink.take() {
        for plaintext in open_own_one_rtt(conn, &sent.data) {
            for frame in Frames::new(&plaintext) {
                if let Ok(Frame::Datagram { data, with_length }) = frame {
                    frames.push((data.to_vec(), with_length));
                }
            }
        }
    }
    frames
}

#[test]
fn a_datagram_is_sealed_from_its_parts_without_an_intermediate_copy() {
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let now = pair.now;
    // A MoQ prefix, a shared object header and two segments of a shared payload.
    let header = Bytes::from(b"a shared object header".to_vec());
    let payload = Bytes::from((0..=255).collect::<Vec<u8>>());
    let parts = [
        Bytes::from_static(&[0x01, 0x2a]),
        header,
        payload.slice(..100),
        payload.slice(200..),
    ];
    let client = pair.client.conn_mut();
    client.send_datagram(&parts, ORDER, None).unwrap();
    let queued = client.sources.streams.datagrams.head_parts();
    assert_eq!(queued.len(), parts.len());
    for (queued, part) in queued.iter().zip(&parts) {
        assert_eq!(
            (queued.as_ptr(), queued.len()),
            (part.as_ptr(), part.len()),
            "the queue holds the caller's buffers"
        );
    }
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    let expected: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
    assert_eq!(datagram_frames(client, &mut sink), [(expected, true)]);
}

#[test]
fn a_received_datagram_is_one_counted_copy_into_a_page_the_connection_owns() {
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let client = pair.client.conn_mut();
    for data in [&b"first"[..], b"second datagram"] {
        client
            .send_datagram(&[Bytes::from_static(data)], ORDER, None)
            .unwrap();
    }
    let limit = pair.now + LIMIT;
    assert!(pair.run_until(limit, |pair| {
        pair.server.has_event(&ConnEvent::DatagramsReadable)
    }));
    let server = pair.server.conn_mut();
    let first = server.read_datagram().unwrap();
    let second = server.read_datagram().unwrap();
    assert_eq!(server.read_datagram(), None);
    assert_eq!(
        (&first[..], &second[..]),
        (&b"first"[..], &b"second datagram"[..])
    );
    // Copied once, back to back into one page, and not slices of the packet buffers.
    assert_eq!(second.as_ptr(), first.as_ptr().wrapping_add(first.len()));
    let stats = server.datagram_stats();
    assert_eq!((stats.received, stats.recv_copied_bytes), (2, 20));
}

#[test]
fn an_expired_datagram_is_dropped_before_any_packet_is_built() {
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let now = pair.now;
    let soon = now + Duration::from_millis(10);
    let client = pair.client.conn_mut();
    client
        .send_datagram(&[Bytes::from_static(b"stale")], ORDER, Some(soon))
        .unwrap();
    client
        .send_datagram(
            &[Bytes::from_static(b"fresh")],
            ORDER,
            Some(soon + Duration::from_millis(1)),
        )
        .unwrap();
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(soon), &mut sink, &mut InlineSealer);
    assert_eq!(
        datagram_frames(client, &mut sink),
        [(b"fresh".to_vec(), true)]
    );
    assert_eq!(client.datagram_stats().expired, 1);
    // A datagram whose expiry has passed is refused.
    assert_eq!(
        client.send_datagram(&[Bytes::from_static(b"late")], ORDER, Some(soon)),
        Err(DatagramError::Expired)
    );
}

#[test]
fn a_full_send_queue_drops_its_oldest_datagram() {
    let transport = TransportConfig::builder()
        .max_datagram_frame_size(65535)
        .datagram_send_queue(2)
        .build()
        .unwrap();
    let (_, mut pair) = handshake(Setup::default().transport(transport).pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    // The oldest is the least urgent, so it is not the first in wire order.
    let later = SendOrder {
        order: ORDER.order + 1,
        ..ORDER
    };
    for (data, order) in [(&b"one"[..], later), (b"two", ORDER), (b"three", ORDER)] {
        client
            .send_datagram(&[Bytes::from_static(data)], order, None)
            .unwrap();
    }
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(
        datagram_frames(client, &mut sink),
        [(b"two".to_vec(), true), (b"three".to_vec(), true)]
    );
    assert_eq!(client.datagram_stats().send_dropped, 1);
}

#[test]
fn a_full_receive_queue_drops_its_oldest_datagram() {
    let transport = TransportConfig::builder()
        .max_datagram_frame_size(65535)
        .datagram_recv_queue(2)
        .build()
        .unwrap();
    let (_, mut pair) = handshake(Setup::default().transport(transport).pair());
    let client = pair.client.conn_mut();
    for data in [&b"one"[..], b"two", b"three"] {
        client
            .send_datagram(&[Bytes::from_static(data)], ORDER, None)
            .unwrap();
    }
    let limit = pair.now + LIMIT;
    assert!(pair.run_until(limit, |pair| {
        pair.server.has_event(&ConnEvent::DatagramsReadable)
    }));
    let server = pair.server.conn_mut();
    let read: Vec<Bytes> = std::iter::from_fn(|| server.read_datagram()).collect();
    assert_eq!(read, [&b"two"[..], b"three"]);
    assert_eq!(server.datagram_stats().recv_dropped, 1);
}

/// Returns the DATAGRAM and STREAM frames in the 1-RTT packets of the datagrams `conn` sent into
/// `sink`, in order, as a datagram's data or "stream".
fn data_frames(conn: &Connection, sink: &mut VecSink) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for sent in sink.take() {
        for plaintext in open_own_one_rtt(conn, &sent.data) {
            for frame in Frames::new(&plaintext) {
                match frame {
                    Ok(Frame::Datagram { data, .. }) => frames.push(data.to_vec()),
                    Ok(Frame::Stream { .. }) => frames.push(b"stream".to_vec()),
                    _ => {}
                }
            }
        }
    }
    frames
}

#[test]
fn datagrams_win_ties_against_streams_of_equal_order_and_wait_for_earlier_ones() {
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from_static(b"stream data");
    client.stream(id).unwrap().send(&mut data).unwrap();
    let later = SendOrder {
        order: ORDER.order + 1,
        ..ORDER
    };
    client
        .send_datagram(&[Bytes::from_static(b"later")], later, None)
        .unwrap();
    client
        .send_datagram(&[Bytes::from_static(b"tie")], ORDER, None)
        .unwrap();
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(
        data_frames(client, &mut sink),
        [&b"tie"[..], b"stream", b"later"]
    );
}

#[test]
fn a_datagram_goes_while_a_more_urgent_stream_waits_for_connection_credit() {
    let datagrams = |max_data: u64| {
        TransportConfig::builder()
            .max_datagram_frame_size(65535)
            .max_data(max_data)
            .build()
            .unwrap()
    };
    let setup = Setup {
        client_transport: datagrams(1 << 20),
        server_transport: datagrams(100),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let id = client.open_stream(Dir::Uni, ORDER).unwrap();
    let mut data = Bytes::from(vec![5; 1000]);
    client.stream(id).unwrap().send(&mut data).unwrap();
    let later = SendOrder {
        order: ORDER.order + 1,
        ..ORDER
    };
    client
        .send_datagram(&[Bytes::from_static(b"later")], later, None)
        .unwrap();
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(data_frames(client, &mut sink), [&b"stream"[..], b"later"]);
}

#[test]
fn a_datagram_too_large_for_the_attempts_datagram_size_is_dropped_rather_than_blocking() {
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let largest = client.max_datagram_size();
    client
        .send_datagram(&[Bytes::from(vec![1; largest])], ORDER, None)
        .unwrap();
    client
        .send_datagram(&[Bytes::from_static(b"small")], ORDER, None)
        .unwrap();
    // The backend takes shorter datagrams than the connection builds.
    let lim = TxLimits {
        max_datagram: 1100,
        ..limits(now)
    };
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&lim, &mut sink, &mut InlineSealer);
    assert_eq!(data_frames(client, &mut sink), [&b"small"[..]]);
    assert_eq!(client.datagram_stats().send_dropped, 1);
}

#[test]
fn the_datagram_allowance_is_the_congestion_window_left_after_queued_datagrams() {
    let (_, pair) = handshake(Setup::default().pair());
    assert_eq!(
        pair.client.conn().datagram_allowance(),
        0,
        "the peer does not take datagrams"
    );
    let (_, mut pair) = handshake(datagrams_up_to(65535).pair());
    let now = pair.now;
    let client = pair.client.conn_mut();
    let window = |client: &Connection| {
        let stats = client.stats();
        usize::try_from(stats.cwnd.saturating_sub(stats.bytes_in_flight)).unwrap()
    };
    let room = window(client);
    assert!(room > 1000, "the window has room after the handshake");
    assert_eq!(client.datagram_allowance(), room);
    client
        .send_datagram(&[Bytes::from(vec![7; 100])], ORDER, None)
        .unwrap();
    // The queued frame counts with its type byte and 2-byte Length.
    assert_eq!(client.datagram_allowance(), room - 103);
    let mut sink = VecSink::new(1500);
    client.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
    assert_eq!(data_frames(client, &mut sink).len(), 1);
    assert_eq!(
        client.datagram_allowance(),
        window(client),
        "a sent datagram counts in flight instead"
    );
    client.close(now, AppCode(VarInt::from_u32(0)), Bytes::new());
    assert_eq!(client.datagram_allowance(), 0, "a closing connection");
}
