/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Frame decoding, encoding and RFC 9000 Table 3.

// ACK ranges here are values, not sequences to collect.
#![allow(clippy::single_range_in_vec_init)]

use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::EcnCounts;
use mvfstr_wire::Frame;
use mvfstr_wire::FrameEncodeError;
use mvfstr_wire::FrameError;
use mvfstr_wire::FrameKind;
use mvfstr_wire::Frames;
use mvfstr_wire::InvalidFrame;
use mvfstr_wire::PacketType;
use mvfstr_wire::ResetToken;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn v(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

fn decode_all(payload: &[u8]) -> Result<Vec<Frame<'_>>, FrameError> {
    Frames::new(payload).collect()
}

/// RFC 9001 App. A.2: the client Initial's CRYPTO frame, padded to a 1,162-byte payload.
const RFC9001_CLIENT_CRYPTO: &str = "
    060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    75300901100f088394c8f03e51570806 048000ffff";

#[test]
fn decodes_the_rfc9001_client_initial_payload() {
    let crypto = hex(RFC9001_CLIENT_CRYPTO);
    let mut payload = crypto.clone();
    payload.resize(1162, 0);
    let frames = decode_all(&payload).unwrap();
    assert_eq!(
        frames,
        [
            Frame::Crypto {
                offset: VarInt::ZERO,
                data: &crypto[4..],
            },
            Frame::Padding { len: 1162 - 245 },
        ]
    );
}

/// RFC 9001 App. A.3: the server Initial's ACK and CRYPTO frames.
const RFC9001_SERVER_PAYLOAD: &str = "
    02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
    88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
    0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
    020304";

#[test]
fn decodes_the_rfc9001_server_initial_payload() {
    let payload = hex(RFC9001_SERVER_PAYLOAD);
    let frames = decode_all(&payload).unwrap();
    assert_eq!(frames.len(), 2);
    let Frame::Ack(ack) = frames[0] else {
        panic!("expected an ACK, got {:?}", frames[0]);
    };
    assert_eq!(ack.largest(), VarInt::ZERO);
    assert_eq!(ack.delay(), VarInt::ZERO);
    assert_eq!(ack.ecn(), None);
    assert!(ack.ranges().eq([0..=0]));
    assert_eq!(
        frames[1],
        Frame::Crypto {
            offset: VarInt::ZERO,
            data: &payload[9..],
        }
    );
}

#[test]
fn ack_ranges_iterate_largest_first() {
    // Largest 100, first range 2 (98..=100); gap 3 skips four packets, length 4 (89..=93);
    // gap 0 skips one, length 0 (87..=87); gap 85 skips 86, length 0 (0..=0).
    let payload = [0x02, 0x40, 100, 0x00, 3, 2, 3, 4, 0, 0, 0x40, 85, 0];
    let frames = decode_all(&payload).unwrap();
    let [Frame::Ack(ack)] = frames[..] else {
        panic!("expected one ACK, got {frames:?}");
    };
    assert_eq!(ack.largest(), v(100));
    let ranges: Vec<_> = ack.ranges().collect();
    assert_eq!(ranges, [98..=100, 89..=93, 87..=87, 0..=0]);
}

#[test]
fn ack_ecn_carries_three_counts() {
    let payload = [0x03, 0x0a, 0x00, 0x00, 0x00, 0x05, 0x40, 0x80, 0x01];
    let frames = decode_all(&payload).unwrap();
    let [Frame::Ack(ack)] = frames[..] else {
        panic!("expected one ACK_ECN, got {frames:?}");
    };
    assert!(ack.ranges().eq([10..=10]));
    assert_eq!(
        ack.ecn(),
        Some(EcnCounts {
            ect0: v(5),
            ect1: v(128),
            ce: v(1),
        })
    );
}

#[test]
fn ack_ranges_below_zero_are_frame_encoding_errors() {
    let first_range_too_big = [0x02, 5, 0, 0, 6];
    let gap_too_big = [0x02, 5, 0, 1, 0, 4, 0];
    let length_too_big = [0x02, 5, 0, 1, 0, 3, 1];
    for payload in [&first_range_too_big[..], &gap_too_big, &length_too_big] {
        let err = decode_all(payload).unwrap_err();
        assert_eq!(
            err.code(),
            TransportErrorCode::FRAME_ENCODING_ERROR,
            "{payload:?}"
        );
        assert_eq!(err.frame_type(), v(0x02));
    }
    // The smallest valid case reaches packet number 0 exactly.
    assert!(decode_all(&[0x02, 5, 0, 1, 0, 3, 0]).is_ok());
}

#[test]
fn decodes_frames_without_fields() {
    assert_eq!(
        decode_all(&[0x01, 0x1e, 0x00, 0x01]).unwrap(),
        [
            Frame::Ping,
            Frame::HandshakeDone,
            Frame::Padding { len: 1 },
            Frame::Ping
        ]
    );
}

#[test]
fn decodes_every_stream_frame_variant() {
    let id = StreamId::from_varint(v(4));
    // 0x08: without an offset, a length or FIN, so the data runs to the end.
    let frames = decode_all(&[0x08, 0x04, b'a', b'b', b'c']).unwrap();
    assert_eq!(
        frames,
        [Frame::Stream {
            id,
            offset: VarInt::ZERO,
            data: b"abc",
            fin: false
        }]
    );
    // 0x0b: length and FIN, followed by a PING.
    let frames = decode_all(&[0x0b, 0x04, 0x02, b'a', b'b', 0x01]).unwrap();
    assert_eq!(
        frames,
        [
            Frame::Stream {
                id,
                offset: VarInt::ZERO,
                data: b"ab",
                fin: true
            },
            Frame::Ping
        ]
    );
    // 0x0c: an offset without a length.
    let frames = decode_all(&[0x0c, 0x04, 0x40, 0x64, b'z']).unwrap();
    assert_eq!(
        frames,
        [Frame::Stream {
            id,
            offset: v(100),
            data: b"z",
            fin: false
        }]
    );
    // 0x0f: offset, length and FIN, with empty data.
    let frames = decode_all(&[0x0f, 0x04, 0x05, 0x00]).unwrap();
    assert_eq!(
        frames,
        [Frame::Stream {
            id,
            offset: v(5),
            data: b"",
            fin: true
        }]
    );
    // 0x09: FIN only; the data runs to the end of the packet.
    let frames = decode_all(&[0x09, 0x04]).unwrap();
    assert_eq!(
        frames,
        [Frame::Stream {
            id,
            offset: VarInt::ZERO,
            data: b"",
            fin: true
        }]
    );
}

#[test]
fn data_ending_beyond_2_pow_62_is_a_frame_encoding_error() {
    // Offset 2^62 - 2 with two bytes of data ends at 2^62, one past the largest offset.
    let max_offset = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];
    let mut stream = vec![0x0e, 0x00];
    stream.extend_from_slice(&max_offset);
    stream.extend_from_slice(&[0x02, b'a', b'b']);
    let mut crypto = vec![0x06];
    crypto.extend_from_slice(&max_offset);
    crypto.extend_from_slice(&[0x02, b'a', b'b']);
    for payload in [&stream, &crypto] {
        let err = decode_all(payload).unwrap_err();
        assert_eq!(err.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
        assert_eq!(err.frame_type(), v(u64::from(payload[0])));
        // One byte of data ends exactly at the limit, which is allowed.
        let mut ok = payload.clone();
        let len_at = ok.len() - 3;
        ok[len_at] = 0x01;
        ok.pop();
        assert!(decode_all(&ok).is_ok(), "{ok:?}");
    }
}

#[test]
fn decodes_reset_stream_and_stop_sending() {
    let payload = [
        0x04, 0x01, 0x41, 0x00, 0x80, 0x01, 0x00, 0x00, 0x05, 0x02, 0x07,
    ];
    assert_eq!(
        decode_all(&payload).unwrap(),
        [
            Frame::ResetStream {
                id: StreamId::from_varint(v(1)),
                error_code: v(0x100),
                final_size: v(0x10000),
            },
            Frame::StopSending {
                id: StreamId::from_varint(v(2)),
                error_code: v(7),
            },
        ]
    );
}

#[test]
fn decodes_limit_and_blocked_frames() {
    let payload = [
        0x10, 0x44, 0x00, // MAX_DATA 1024
        0x11, 0x08, 0x40, 0xff, // MAX_STREAM_DATA stream 8, 255
        0x12, 0x10, // MAX_STREAMS bidi 16
        0x13, 0x03, // MAX_STREAMS uni 3
        0x14, 0x20, // DATA_BLOCKED 32
        0x15, 0x02, 0x21, // STREAM_DATA_BLOCKED stream 2, 33
        0x16, 0x05, // STREAMS_BLOCKED bidi 5
        0x17, 0x06, // STREAMS_BLOCKED uni 6
    ];
    assert_eq!(
        decode_all(&payload).unwrap(),
        [
            Frame::MaxData(v(1024)),
            Frame::MaxStreamData {
                id: StreamId::from_varint(v(8)),
                max: v(255)
            },
            Frame::MaxStreams {
                dir: Dir::Bi,
                max: v(16)
            },
            Frame::MaxStreams {
                dir: Dir::Uni,
                max: v(3)
            },
            Frame::DataBlocked(v(32)),
            Frame::StreamDataBlocked {
                id: StreamId::from_varint(v(2)),
                limit: v(33)
            },
            Frame::StreamsBlocked {
                dir: Dir::Bi,
                limit: v(5)
            },
            Frame::StreamsBlocked {
                dir: Dir::Uni,
                limit: v(6)
            },
        ]
    );
}

#[test]
fn stream_limits_above_2_pow_60_are_frame_encoding_errors() {
    // 2^60 + 1 as an 8-byte varint.
    let too_many = [0xd0, 0, 0, 0, 0, 0, 0, 0x01];
    for ty in [0x12u8, 0x13, 0x16, 0x17] {
        let mut payload = vec![ty];
        payload.extend_from_slice(&too_many);
        let err = decode_all(&payload).unwrap_err();
        assert_eq!(err.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
        assert_eq!(err.frame_type(), v(u64::from(ty)));
        // Exactly 2^60 is allowed.
        payload[8] = 0;
        assert!(decode_all(&payload).is_ok());
    }
}

#[test]
fn decodes_connection_id_frames() {
    let mut payload = vec![0x18, 0x07, 0x03, 0x04, 0xc1, 0xc2, 0xc3, 0xc4];
    payload.extend_from_slice(&[0x5e; 16]);
    payload.extend_from_slice(&[0x19, 0x02]);
    assert_eq!(
        decode_all(&payload).unwrap(),
        [
            Frame::NewConnectionId {
                seq: v(7),
                retire_prior_to: v(3),
                cid: ConnectionId::new(&[0xc1, 0xc2, 0xc3, 0xc4]).unwrap(),
                reset_token: ResetToken([0x5e; 16]),
            },
            Frame::RetireConnectionId { seq: v(2) },
        ]
    );
}

#[test]
fn new_connection_id_rejects_bad_lengths_and_retire_prior_to() {
    let frame = |seq: u8, retire_prior_to: u8, len: u8| {
        let mut payload = vec![0x18, seq, retire_prior_to, len];
        payload.extend(std::iter::repeat_n(0xc1, usize::from(len)));
        payload.extend_from_slice(&[0x5e; 16]);
        payload
    };
    for payload in [frame(1, 0, 0), frame(1, 0, 21), frame(1, 2, 8)] {
        let err = decode_all(&payload).unwrap_err();
        assert_eq!(
            err.code(),
            TransportErrorCode::FRAME_ENCODING_ERROR,
            "{payload:?}"
        );
        assert_eq!(err.frame_type(), v(0x18));
    }
    assert!(decode_all(&frame(2, 2, 20)).is_ok());
}

#[test]
fn decodes_path_frames() {
    let payload = [0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 0x1b, 9, 9, 9, 9, 9, 9, 9, 9];
    assert_eq!(
        decode_all(&payload).unwrap(),
        [
            Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]),
            Frame::PathResponse([9; 8]),
        ]
    );
}

#[test]
fn decodes_both_close_frames() {
    let mut payload = vec![0x1c, 0x07, 0x06, 0x03];
    payload.extend_from_slice(b"bad");
    payload.extend_from_slice(&[0x1d, 0x41, 0x00, 0x00]);
    assert_eq!(
        decode_all(&payload).unwrap(),
        [
            Frame::ConnectionClose {
                error_code: TransportErrorCode::FRAME_ENCODING_ERROR,
                frame_type: v(0x06),
                reason: b"bad",
            },
            Frame::ApplicationClose {
                error_code: v(0x100),
                reason: b"",
            },
        ]
    );
}

#[test]
fn decodes_new_token_and_rejects_an_empty_one() {
    let payload = [0x07, 0x03, 0xaa, 0xbb, 0xcc];
    assert_eq!(
        decode_all(&payload).unwrap(),
        [Frame::NewToken {
            token: &[0xaa, 0xbb, 0xcc]
        }]
    );
    let err = decode_all(&[0x07, 0x00]).unwrap_err();
    assert_eq!(err.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
    assert_eq!(err.frame_type(), v(0x07));
}

#[test]
fn unknown_frame_types_are_frame_encoding_errors() {
    // RESET_STREAM_AT (0x24) and ACK_FREQUENCY (0xaf) are extensions mvfstr does not
    // negotiate; 0x1f is unassigned.
    for (payload, ty) in [
        (&[0x1f][..], 0x1f),
        (&[0x24, 0, 0, 0, 0], 0x24),
        (&[0x40, 0xaf], 0xaf),
    ] {
        let err = decode_all(payload).unwrap_err();
        assert_eq!(err.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
        assert_eq!(err.frame_type(), v(ty));
    }
}

#[test]
fn non_minimal_frame_types_are_protocol_violations() {
    // PING encoded on two bytes, RFC 9000's own example, and on eight.
    for payload in [&[0x40, 0x01][..], &[0xc0, 0, 0, 0, 0, 0, 0, 0x01]] {
        let err = decode_all(payload).unwrap_err();
        assert_eq!(err.code(), TransportErrorCode::PROTOCOL_VIOLATION);
        assert_eq!(err.frame_type(), v(0x01));
    }
}

#[test]
fn decodes_datagram_frames_with_and_without_a_length() {
    // RFC 9221: type 0x30 carries data to the end of the packet, 0x31 a Length field first.
    assert_eq!(
        decode_all(&[0x30, b'x', b'y', 0x01]).unwrap(),
        [Frame::Datagram {
            data: &[b'x', b'y', 0x01],
            with_length: false,
        }]
    );
    assert_eq!(
        decode_all(&[0x31, 0x02, b'x', b'y', 0x01]).unwrap(),
        [
            Frame::Datagram {
                data: b"xy",
                with_length: true,
            },
            Frame::Ping,
        ]
    );
    assert_eq!(
        decode_all(&[0x30]).unwrap(),
        [Frame::Datagram {
            data: b"",
            with_length: false,
        }]
    );
}

/// Returns one complete encoding of every frame type with fields, all with a length-delimited end.
fn frames_with_fields() -> Vec<Vec<u8>> {
    let mut ncid = vec![0x18, 0x01, 0x00, 0x02, 0xc1, 0xc2];
    ncid.extend_from_slice(&[0x5e; 16]);
    vec![
        vec![0x02, 0x40, 100, 0x01, 0x01, 0x02, 0x03, 0x04],
        vec![0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03],
        vec![0x04, 0x01, 0x41, 0x00, 0x05],
        vec![0x05, 0x02, 0x07],
        vec![0x06, 0x00, 0x02, 0xaa, 0xbb],
        vec![0x07, 0x02, 0xaa, 0xbb],
        vec![0x0e, 0x04, 0x01, 0x02, 0xaa, 0xbb],
        vec![0x10, 0x44, 0x00],
        vec![0x11, 0x08, 0x40, 0xff],
        vec![0x12, 0x10],
        vec![0x13, 0x10],
        vec![0x14, 0x20],
        vec![0x15, 0x02, 0x21],
        vec![0x16, 0x05],
        vec![0x17, 0x06],
        ncid,
        vec![0x19, 0x02],
        vec![0x1a, 1, 2, 3, 4, 5, 6, 7, 8],
        vec![0x1b, 1, 2, 3, 4, 5, 6, 7, 8],
        vec![0x1c, 0x07, 0x06, 0x02, b'n', b'o'],
        vec![0x1d, 0x07, 0x02, b'n', b'o'],
        vec![0x31, 0x02, 0xaa, 0xbb],
    ]
}

#[test]
fn truncated_frames_are_frame_encoding_errors() {
    for frame in frames_with_fields() {
        assert_eq!(decode_all(&frame).map(|f| f.len()), Ok(1), "{frame:02x?}");
        for len in 1..frame.len() {
            let err = decode_all(&frame[..len]).unwrap_err();
            assert_eq!(
                err.code(),
                TransportErrorCode::FRAME_ENCODING_ERROR,
                "{frame:02x?} {len}"
            );
            assert_eq!(
                err.frame_type(),
                v(u64::from(frame[0])),
                "{frame:02x?} {len}"
            );
        }
    }
    // A truncated frame type is reported as type 0.
    let err = decode_all(&[0x40]).unwrap_err();
    assert_eq!(err.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
    assert_eq!(err.frame_type(), VarInt::ZERO);
}

#[test]
fn iteration_ends_at_the_first_error() {
    let mut frames = Frames::new(&[0x01, 0x1f, 0x01]);
    assert_eq!(frames.next(), Some(Ok(Frame::Ping)));
    assert!(matches!(frames.next(), Some(Err(_))));
    assert_eq!(frames.next(), None);
    assert_eq!(Frames::new(&[]).next(), None);
}

/// RFC 9000 Table 3, "Pkts" and "Spec" columns, per kind.
const TABLE_3: [(FrameKind, &str, &str); 22] = [
    (FrameKind::Padding, "IH01", "NP"),
    (FrameKind::Ping, "IH01", ""),
    (FrameKind::Ack, "IH_1", "NC"),
    (FrameKind::ResetStream, "__01", ""),
    (FrameKind::StopSending, "__01", ""),
    (FrameKind::Crypto, "IH_1", ""),
    (FrameKind::NewToken, "___1", ""),
    (FrameKind::Stream, "__01", "F"),
    (FrameKind::MaxData, "__01", ""),
    (FrameKind::MaxStreamData, "__01", ""),
    (FrameKind::MaxStreams, "__01", ""),
    (FrameKind::DataBlocked, "__01", ""),
    (FrameKind::StreamDataBlocked, "__01", ""),
    (FrameKind::StreamsBlocked, "__01", ""),
    (FrameKind::NewConnectionId, "__01", "P"),
    (FrameKind::RetireConnectionId, "__01", ""),
    (FrameKind::PathChallenge, "__01", "P"),
    (FrameKind::PathResponse, "___1", "P"),
    // "ih01": only type 0x1c may appear in Initial and Handshake packets.
    (FrameKind::ConnectionClose, "IH01", "N"),
    (FrameKind::ApplicationClose, "__01", "N"),
    (FrameKind::HandshakeDone, "___1", ""),
    // RFC 9221: DATAGRAM goes in 0-RTT and 1-RTT packets and is ack-eliciting.
    (FrameKind::Datagram, "__01", ""),
];

#[test]
fn allowed_packet_types_follow_rfc9000_table_3() {
    assert_eq!(TABLE_3.map(|(kind, _, _)| kind), FrameKind::ALL);
    let types = [
        (PacketType::Initial, 'I'),
        (PacketType::Handshake, 'H'),
        (PacketType::ZeroRtt, '0'),
        (PacketType::OneRtt, '1'),
    ];
    for (kind, pkts, _) in TABLE_3 {
        for (ty, letter) in types {
            assert_eq!(
                kind.allowed_in(ty),
                pkts.contains(letter),
                "{kind:?} in {ty:?}"
            );
        }
    }
}

#[test]
fn ack_eliciting_is_every_kind_not_marked_n() {
    for (kind, _, spec) in TABLE_3 {
        assert_eq!(kind.is_ack_eliciting(), !spec.contains('N'), "{kind:?}");
    }
}

#[test]
fn probing_is_every_kind_marked_p() {
    for (kind, _, spec) in TABLE_3 {
        assert_eq!(kind.is_probing(), spec.contains('P'), "{kind:?}");
    }
}

/// Returns one frame of every kind, with fields of several encoded sizes.
fn one_of_each<'a>(ack_payload: &'a [u8]) -> Vec<Frame<'a>> {
    let Ok(Frame::Ack(ack)) = Frames::new(ack_payload).next().unwrap() else {
        panic!("expected an ACK");
    };
    vec![
        Frame::Padding { len: 7 },
        Frame::Ping,
        Frame::Ack(ack),
        Frame::ResetStream {
            id: StreamId::from_varint(v(0x3fff)),
            error_code: v(0x4000),
            final_size: v(1 << 30),
        },
        Frame::StopSending {
            id: StreamId::from_varint(v(3)),
            error_code: VarInt::MAX,
        },
        Frame::Crypto {
            offset: v(1200),
            data: b"client hello",
        },
        Frame::NewToken { token: &[0x70; 70] },
        Frame::Stream {
            id: StreamId::from_varint(v(8)),
            offset: VarInt::ZERO,
            data: b"first bytes",
            fin: false,
        },
        Frame::Stream {
            id: StreamId::from_varint(v(9)),
            offset: v(1 << 20),
            data: b"",
            fin: true,
        },
        Frame::MaxData(v(1 << 40)),
        Frame::MaxStreamData {
            id: StreamId::from_varint(v(2)),
            max: v(66_560),
        },
        Frame::MaxStreams {
            dir: Dir::Bi,
            max: v(1 << 60),
        },
        Frame::MaxStreams {
            dir: Dir::Uni,
            max: v(2048),
        },
        Frame::DataBlocked(v(1 << 20)),
        Frame::StreamDataBlocked {
            id: StreamId::from_varint(v(6)),
            limit: v(65),
        },
        Frame::StreamsBlocked {
            dir: Dir::Bi,
            limit: v(0),
        },
        Frame::StreamsBlocked {
            dir: Dir::Uni,
            limit: v(100),
        },
        Frame::NewConnectionId {
            seq: v(9),
            retire_prior_to: v(9),
            cid: ConnectionId::new(&[0xc0; 20]).unwrap(),
            reset_token: ResetToken([0xee; 16]),
        },
        Frame::RetireConnectionId { seq: v(64) },
        Frame::PathChallenge(*b"chalenge"),
        Frame::PathResponse(*b"response"),
        Frame::ConnectionClose {
            error_code: TransportErrorCode::crypto(0x78),
            frame_type: v(0x06),
            reason: b"no application protocol",
        },
        Frame::ApplicationClose {
            error_code: v(0x0100),
            reason: b"",
        },
        Frame::HandshakeDone,
        Frame::Datagram {
            data: &[0xd0; 70],
            with_length: true,
        },
        Frame::Datagram {
            data: b"to the end of the packet",
            with_length: false,
        },
    ]
}

/// An ACK_ECN with three ranges and multi-byte fields.
const ACK_PAYLOAD: [u8; 15] = [
    0x03, 0x44, 0x00, 0x40, 0x80, 0x02, 0x05, 0x01, 0x02, 0x00, 0x03, 0x01, 0x02, 0x40, 0x40,
];

#[test]
fn every_frame_kind_round_trips() {
    let frames = one_of_each(&ACK_PAYLOAD);
    let mut kinds: Vec<FrameKind> = frames.iter().map(Frame::kind).collect();
    kinds.dedup();
    assert_eq!(kinds, FrameKind::ALL);
    for frame in &frames {
        let mut out = [0u8; 256];
        let len = frame.encode(&mut out).unwrap();
        assert_eq!(len, frame.encoded_len(), "{frame:?}");
        assert_eq!(decode_all(&out[..len]).unwrap(), [*frame]);
    }
}

#[test]
fn encode_into_a_short_buffer_fails_without_writing() {
    for frame in one_of_each(&ACK_PAYLOAD) {
        let len = frame.encoded_len();
        let mut out = vec![0xaa; len - 1];
        assert_eq!(
            frame.encode(&mut out),
            Err(FrameEncodeError::BufferTooShort),
            "{frame:?}"
        );
        assert!(out.iter().all(|&b| b == 0xaa));
    }
}

/// Asserts that `frame` is refused as `why` without writing, whatever room the buffer has.
#[track_caller]
fn assert_refused(frame: Frame<'_>, why: InvalidFrame) {
    let mut out = [0xaa; 64];
    assert_eq!(frame.encode(&mut out), Err(FrameEncodeError::Invalid(why)));
    assert!(out.iter().all(|&b| b == 0xaa));
    assert_eq!(frame.encode(&mut []), Err(FrameEncodeError::Invalid(why)));
}

#[test]
fn encode_refuses_an_empty_new_token() {
    assert_refused(Frame::NewToken { token: b"" }, InvalidFrame::EmptyToken);
}

#[test]
fn encode_refuses_stream_data_ending_beyond_the_largest_offset() {
    let offset = v(VarInt::MAX.into_inner() - 9);
    let id = StreamId::from_varint(v(4));
    let past = Frame::Stream {
        id,
        offset,
        data: &[7; 10],
        fin: false,
    };
    assert_refused(past, InvalidFrame::DataBeyondMaxOffset);
    let last = Frame::Stream {
        id,
        offset,
        data: &[7; 9],
        fin: true,
    };
    let mut out = [0; 64];
    let len = last.encode(&mut out).unwrap();
    assert_eq!(decode_all(&out[..len]).unwrap(), [last]);
}

#[test]
fn encode_refuses_crypto_data_ending_beyond_the_largest_offset() {
    let offset = v(VarInt::MAX.into_inner() - 9);
    let past = Frame::Crypto {
        offset,
        data: &[7; 10],
    };
    assert_refused(past, InvalidFrame::DataBeyondMaxOffset);
    let last = Frame::Crypto {
        offset,
        data: &[7; 9],
    };
    let mut out = [0; 64];
    let len = last.encode(&mut out).unwrap();
    assert_eq!(decode_all(&out[..len]).unwrap(), [last]);
}

#[test]
fn encode_refuses_max_streams_above_2_pow_60() {
    for dir in [Dir::Bi, Dir::Uni] {
        let over = Frame::MaxStreams {
            dir,
            max: v((1 << 60) + 1),
        };
        assert_refused(over, InvalidFrame::StreamCountAboveLimit);
        let at = Frame::MaxStreams {
            dir,
            max: v(1 << 60),
        };
        assert!(at.encode(&mut [0; 16]).is_ok());
    }
}

#[test]
fn encode_refuses_streams_blocked_above_2_pow_60() {
    for dir in [Dir::Bi, Dir::Uni] {
        let over = Frame::StreamsBlocked {
            dir,
            limit: v((1 << 60) + 1),
        };
        assert_refused(over, InvalidFrame::StreamCountAboveLimit);
        let at = Frame::StreamsBlocked {
            dir,
            limit: v(1 << 60),
        };
        assert!(at.encode(&mut [0; 16]).is_ok());
    }
}

#[test]
fn encode_refuses_retire_prior_to_above_the_sequence_number() {
    let frame = |seq, retire_prior_to| Frame::NewConnectionId {
        seq: v(seq),
        retire_prior_to: v(retire_prior_to),
        cid: ConnectionId::new(&[0xc0; 8]).unwrap(),
        reset_token: ResetToken([0xee; 16]),
    };
    assert_refused(frame(1, 2), InvalidFrame::RetirePriorToAboveSequence);
    assert!(frame(2, 2).encode(&mut [0; 64]).is_ok());
}

#[test]
fn encode_refuses_an_empty_connection_id() {
    let frame = Frame::NewConnectionId {
        seq: v(1),
        retire_prior_to: v(0),
        cid: ConnectionId::new(&[]).unwrap(),
        reset_token: ResetToken([0xee; 16]),
    };
    assert_refused(frame, InvalidFrame::EmptyConnectionId);
}

/// A small deterministic generator, so malformed-input tests are reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn arbitrary_payloads_never_panic() {
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let valid: Vec<Vec<u8>> = frames_with_fields();
    for _ in 0..20_000 {
        // Mutate a valid frame or draw bytes biased toward small values and known types.
        let mut payload = valid[(rng.next() % valid.len() as u64) as usize].clone();
        for _ in 0..rng.next() % 4 {
            let at = (rng.next() % payload.len() as u64) as usize;
            payload[at] = rng.next() as u8;
        }
        let extra = rng.next() % 24;
        payload.extend((0..extra).map(|_| (rng.next() % 0x40) as u8));
        for frame in Frames::new(&payload) {
            match frame {
                Ok(Frame::Ack(ack)) => assert!(ack.ranges().count() >= 1),
                Ok(frame) => assert!(frame.encoded_len() <= payload.len() + 8),
                Err(_) => break,
            }
        }
    }
}
