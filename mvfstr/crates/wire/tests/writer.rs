/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-place packet writer.

// ACK ranges here are values, not sequences to collect.
#![allow(clippy::single_range_in_vec_init)]

use bytes::Bytes;
use mvfstr_wire::AckFrame;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::EcnCounts;
use mvfstr_wire::Frame;
use mvfstr_wire::FrameWriteError;
use mvfstr_wire::Frames;
use mvfstr_wire::Full;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::InvalidFrame;
use mvfstr_wire::PacketLayout;
use mvfstr_wire::PacketType;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::PayloadError;
use mvfstr_wire::ProtectedHeader;
use mvfstr_wire::StreamFit;
use mvfstr_wire::StreamId;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use mvfstr_wire::WriterError;

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

fn cid(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

const TAG: usize = 16;

#[test]
fn writes_the_rfc9001_short_header_packet() {
    // RFC 9001 Appendix A.5: an empty DCID, packet number 654,360,564 on 3 bytes and one PING
    // frame make the smallest possible packet, 21 bytes, without padding.
    let mut slot = [0xaa_u8; 1500];
    let header = HeaderSpec::OneRtt {
        dcid: ConnectionId::EMPTY,
        spin: false,
        key_phase: false,
    };
    let mut w = PacketWriter::new(&mut slot, header, 654_360_564, 3, TAG).unwrap();
    w.frame(&Frame::Ping).unwrap();
    let layout = w.finish();
    assert_eq!(
        layout,
        PacketLayout {
            hdr_len: 4,
            pn_offset: 1,
            payload_len: 1,
            len: 21,
        }
    );
    assert_eq!(slot[..5], hex("4200bff4 01"));
}

/// RFC 9001 Appendix A.3: the server Initial's payload, an ACK and a CRYPTO frame.
const RFC9001_SERVER_PAYLOAD: &str = "
    02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
    88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
    0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
    020304";

#[test]
fn writes_the_rfc9001_server_initial() {
    let payload = hex(RFC9001_SERVER_PAYLOAD);
    let mut slot = [0u8; 1500];
    let header = HeaderSpec::Initial {
        version: Version::V1,
        dcid: ConnectionId::EMPTY,
        scid: cid(&hex("f067a5502a4262b5")),
        token: b"",
    };
    let mut w = PacketWriter::new(&mut slot, header, 1, 2, TAG).unwrap();
    assert_eq!(w.ack(0..=0, [], VarInt::ZERO, None), Ok(1));
    assert_eq!(w.crypto(VarInt::ZERO, &payload[9..]), Ok(90));
    let layout = w.finish();
    let header = hex("c1000000010008f067a5502a4262b50040750001");
    assert_eq!(
        layout,
        PacketLayout {
            hdr_len: header.len(),
            pn_offset: 18,
            payload_len: payload.len(),
            len: header.len() + payload.len() + TAG,
        }
    );
    assert_eq!(slot[..header.len()], header);
    assert_eq!(slot[header.len()..header.len() + payload.len()], payload);
}

/// RFC 9001 Appendix A.2: the client Initial's CRYPTO frame data (the ClientHello).
const RFC9001_CLIENT_HELLO: &str = "
                                                       010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    75300901100f088394c8f03e51570806 048000ffff";

#[test]
fn writes_the_rfc9001_client_initial_padded_to_1200() {
    let hello = hex(RFC9001_CLIENT_HELLO);
    let mut slot = [0xaa_u8; 1500];
    let header = HeaderSpec::Initial {
        version: Version::V1,
        dcid: cid(&hex("8394c8f03e515708")),
        scid: ConnectionId::EMPTY,
        token: b"",
    };
    let mut w = PacketWriter::new(&mut slot, header, 2, 4, TAG).unwrap();
    assert_eq!(w.crypto(VarInt::ZERO, &hello), Ok(241));
    w.pad_to(1200).unwrap();
    let layout = w.finish();
    let header = hex("c300000001088394c8f03e5157080000449e00000002");
    assert_eq!(
        layout,
        PacketLayout {
            hdr_len: 22,
            pn_offset: 18,
            payload_len: 1162,
            len: 1200,
        }
    );
    assert_eq!(slot[..22], header);
    assert_eq!(slot[22..26], hex("060040f1"));
    assert_eq!(slot[26..26 + 241], hello);
    assert!(slot[26 + 241..1184].iter().all(|&b| b == 0));
}

fn parse(packet: &[u8], local_cid_len: usize) -> ProtectedHeader<'_> {
    match Header::parse(packet, local_cid_len) {
        Ok(Header::Protected(header)) => header,
        other => panic!("expected a protected header, got {other:?}"),
    }
}

#[test]
fn every_header_type_round_trips_through_the_parser() {
    let dcid = cid(&[0xd0; 20]);
    let scid = cid(&[0x5c; 5]);
    let token = [0x70_u8; 100];
    let specs = [
        (
            HeaderSpec::Initial {
                version: Version::V1,
                dcid,
                scid,
                token: &token,
            },
            PacketType::Initial,
        ),
        (
            HeaderSpec::ZeroRtt {
                version: Version::MVFST,
                dcid,
                scid,
            },
            PacketType::ZeroRtt,
        ),
        (
            HeaderSpec::Handshake {
                version: Version::V1,
                dcid,
                scid,
            },
            PacketType::Handshake,
        ),
        (
            HeaderSpec::OneRtt {
                dcid,
                spin: true,
                key_phase: true,
            },
            PacketType::OneRtt,
        ),
    ];
    for (spec, ty) in specs {
        for pn_len in 1..=4 {
            let mut slot = [0xaa_u8; 1400];
            let mut w = PacketWriter::new(&mut slot, spec, 0x0102_0304, pn_len, TAG).unwrap();
            w.frame(&Frame::Ping).unwrap();
            let layout = w.finish();
            let datagram = &slot[..layout.len];
            let header = parse(datagram, 20);
            assert_eq!(header.ty(), ty);
            assert_eq!(header.dcid(), &dcid[..]);
            assert_eq!(header.pn_offset(), layout.pn_offset);
            assert_eq!(header.packet_len(), layout.len, "{ty:?} pn_len {pn_len}");
            assert_eq!(layout.hdr_len, layout.pn_offset + pn_len);
            assert_eq!(usize::from(slot[0] & 0x03) + 1, pn_len);
            let pn = &slot[layout.pn_offset..layout.hdr_len];
            assert_eq!(pn, &0x0102_0304_u32.to_be_bytes()[4 - pn_len..]);
            match ty {
                PacketType::OneRtt => {
                    assert_eq!(header.version(), None);
                    // Fixed, spin and key phase bits; reserved bits clear.
                    assert_eq!(slot[0] & 0xfc, 0x40 | 0x20 | 0x04);
                }
                _ => {
                    assert!(header.version().is_some());
                    assert_eq!(header.scid(), &scid[..]);
                    // Reserved bits clear.
                    assert_eq!(slot[0] & 0x0c, 0);
                }
            }
            let expected_token: &[u8] = if ty == PacketType::Initial {
                &token
            } else {
                b""
            };
            assert_eq!(header.token(), expected_token);
        }
    }
}

#[test]
fn new_rejects_bad_packet_number_lengths_and_short_buffers() {
    let short = HeaderSpec::OneRtt {
        dcid: cid(&[1; 8]),
        spin: false,
        key_phase: false,
    };
    let mut slot = [0xaa_u8; 64];
    for pn_len in [0, 5] {
        let err = PacketWriter::new(&mut slot, short, 1, pn_len, TAG).unwrap_err();
        assert_eq!(err, WriterError::InvalidPnLen);
    }
    // A short header with an 8-byte DCID needs 1 + 8 + 4 + 16 bytes for the sample to fit.
    assert_eq!(
        PacketWriter::new(&mut slot[..28], short, 1, 1, TAG).unwrap_err(),
        WriterError::BufferTooShort
    );
    assert!(PacketWriter::new(&mut slot[..29], short, 1, 1, TAG).is_ok());
    slot.fill(0xaa);
    // A long header with a token longer than the buffer.
    let initial = HeaderSpec::Initial {
        version: Version::V1,
        dcid: cid(&[1; 8]),
        scid: ConnectionId::EMPTY,
        token: &[0x70; 100],
    };
    assert_eq!(
        PacketWriter::new(&mut slot, initial, 1, 4, TAG).unwrap_err(),
        WriterError::BufferTooShort
    );
    assert_eq!(slot, [0xaa; 64]);
}

#[test]
fn new_requires_room_for_one_payload_byte() {
    // With a 4-byte packet number and a 16-byte tag the sample fits without payload bytes, but the
    // packet still needs a frame: 1 + 8 + 4 + 1 + 16 bytes.
    let short = HeaderSpec::OneRtt {
        dcid: cid(&[1; 8]),
        spin: false,
        key_phase: false,
    };
    let mut slot = [0xaa_u8; 64];
    assert_eq!(
        PacketWriter::new(&mut slot[..29], short, 1, 4, TAG).unwrap_err(),
        WriterError::BufferTooShort
    );
    let w = PacketWriter::new(&mut slot[..30], short, 1, 4, TAG).unwrap();
    assert_eq!(w.remaining(), 1);
    assert_eq!(w.finish().len, 30);
}

#[test]
fn new_rejects_a_tag_longer_than_any_buffer() {
    let short = HeaderSpec::OneRtt {
        dcid: cid(&[1; 8]),
        spin: false,
        key_phase: false,
    };
    let mut slot = [0xaa_u8; 64];
    for tag_len in [usize::MAX, usize::MAX - 10, 64] {
        assert_eq!(
            PacketWriter::new(&mut slot, short, 1, 1, tag_len).unwrap_err(),
            WriterError::BufferTooShort,
            "{tag_len}"
        );
    }
    assert_eq!(slot, [0xaa; 64]);
}

fn short_writer(slot: &mut [u8]) -> PacketWriter<'_> {
    let header = HeaderSpec::OneRtt {
        dcid: cid(&[0xd0; 8]),
        spin: false,
        key_phase: false,
    };
    PacketWriter::new(slot, header, 7, 2, TAG).unwrap()
}

#[test]
fn frames_are_written_whole_or_not_at_all() {
    let mut slot = [0u8; 60];
    let mut w = short_writer(&mut slot);
    // 60 - (1 + 8 + 2) header - 16 tag.
    assert_eq!(w.remaining(), 33);
    assert!(w.is_empty());
    let close = Frame::ApplicationClose {
        error_code: v(1),
        reason: &[b'x'; 31],
    };
    assert_eq!(close.encoded_len(), 34);
    assert_eq!(w.frame(&close), Err(FrameWriteError::Full));
    assert_eq!(w.remaining(), 33);
    assert!(w.is_empty());
    let close = Frame::ApplicationClose {
        error_code: v(1),
        reason: &[b'x'; 30],
    };
    assert_eq!(w.frame(&close), Ok(()));
    assert_eq!(w.remaining(), 0);
    assert_eq!(w.frame(&Frame::Ping), Err(FrameWriteError::Full));
    let layout = w.finish();
    assert_eq!(layout.len, 60);
    assert_eq!(layout.payload_len, 33);
}

fn frames_of(slot: &[u8], layout: PacketLayout) -> Vec<Frame<'_>> {
    Frames::new(&slot[layout.hdr_len..layout.hdr_len + layout.payload_len])
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn crypto_takes_as_much_data_as_fits() {
    let data = [0x16_u8; 100];
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    // 80 - 11 - 16 = 53 bytes: type, a 2-byte offset and a 1-byte length leave 49 for data.
    assert_eq!(w.remaining(), 53);
    assert_eq!(w.crypto(v(1000), &data), Ok(49));
    assert_eq!(w.remaining(), 0);
    assert!(w.is_ack_eliciting());
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [Frame::Crypto {
            offset: v(1000),
            data: &data[..49]
        }]
    );
}

#[test]
fn crypto_is_full_when_no_data_byte_fits() {
    let data = [0x16_u8; 100];
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    w.frame(&Frame::Padding { len: 50 }).unwrap();
    // Three bytes left: type, offset and length, so data does not fit.
    assert_eq!(w.remaining(), 3);
    assert_eq!(w.crypto(VarInt::ZERO, &data), Err(Full));
    assert_eq!(w.remaining(), 3);
    assert_eq!(w.crypto(VarInt::ZERO, &[]), Ok(0));
    assert_eq!(w.remaining(), 0);
}

#[test]
fn crypto_data_never_ends_beyond_the_largest_offset() {
    // RFC 9000 does not allow crypto data to end beyond 2^62 - 1.
    let max = VarInt::MAX.into_inner();
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    assert_eq!(w.crypto(v(max - 9), &[1; 20]), Err(Full));
    assert_eq!(w.crypto(v(max), &[1, 2, 3]), Err(Full));
    assert!(w.begin_crypto(v(max - 9), usize::MAX).is_err());
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    assert_eq!(w.crypto(v(max - 9), &[1; 9]), Ok(9));
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [Frame::Crypto {
            offset: v(max - 9),
            data: &[1; 9]
        }]
    );
}

#[test]
fn crypto_length_field_shrinks_with_the_data() {
    // 67 bytes for the frame: type and offset leave 65, too few for 64 bytes behind a 2-byte
    // length, so the frame takes 63 behind a 1-byte length.
    let data = [0x16_u8; 200];
    let mut slot = [0u8; 11 + 67 + TAG];
    let mut w = short_writer(&mut slot);
    assert_eq!(w.crypto(VarInt::ZERO, &data), Ok(63));
    assert_eq!(w.remaining(), 1);
}

#[test]
fn stream_frames_that_leave_room_carry_a_length() {
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let id = StreamId::from_varint(v(4));
    assert_eq!(
        w.stream(id, v(100), b"hello", true),
        Ok(StreamFit { len: 5, fin: true })
    );
    assert_eq!(
        w.stream(id, VarInt::ZERO, b"", true),
        Ok(StreamFit { len: 0, fin: true })
    );
    w.frame(&Frame::Ping).unwrap();
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [
            Frame::Stream {
                id,
                offset: v(100),
                data: b"hello",
                fin: true
            },
            Frame::Stream {
                id,
                offset: VarInt::ZERO,
                data: b"",
                fin: true
            },
            Frame::Ping,
        ]
    );
    // Type, ID, 2-byte offset, length and data; then type, ID and length.
    assert_eq!(layout.payload_len, (1 + 1 + 2 + 1 + 5) + (1 + 1 + 1) + 1);
}

#[test]
fn stream_frames_that_fill_the_packet_omit_the_length() {
    let data = [0x5d_u8; 2000];
    let id = StreamId::from_varint(v(3));
    let mut slot = [0u8; 1452];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    // Type, a 1-byte ID and a 2-byte offset; the data runs to the end of the packet.
    let fit = w.stream(id, v(16_383), &data, true).unwrap();
    assert_eq!(
        fit,
        StreamFit {
            len: room - 4,
            fin: false
        }
    );
    assert_eq!(w.remaining(), 0);
    let layout = w.finish();
    assert_eq!(slot[layout.hdr_len] & 0x02, 0, "no LEN bit");
    assert_eq!(
        frames_of(&slot, layout),
        [Frame::Stream {
            id,
            offset: v(16_383),
            data: &data[..room - 4],
            fin: false
        }]
    );

    // Exactly the room left: all of the data fits, so FIN is carried too.
    let mut slot = [0u8; 1452];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    let fit = w.stream(id, VarInt::ZERO, &data[..room - 2], true).unwrap();
    assert_eq!(
        fit,
        StreamFit {
            len: room - 2,
            fin: true
        }
    );
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [Frame::Stream {
            id,
            offset: VarInt::ZERO,
            data: &data[..room - 2],
            fin: true
        }]
    );
}

#[test]
fn stream_data_that_fits_only_without_a_length_is_padded_to_the_end() {
    // 200 - 11 - 16 = 173 bytes: type and ID leave 171, so 170 bytes fit without a Length field
    // but not behind a 2-byte one. One PADDING byte before the frame lets it end the packet and
    // carry all of the data and FIN.
    let data = [0x5d_u8; 170];
    let id = StreamId::from_varint(v(0));
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    assert_eq!(w.remaining(), 173);
    {
        let _unfinished = w.begin_stream(id, VarInt::ZERO, 170, true).unwrap();
    }
    assert_eq!(w.remaining(), 173);
    assert!(w.is_empty());
    assert_eq!(
        w.stream(id, VarInt::ZERO, &data, true),
        Ok(StreamFit {
            len: 170,
            fin: true
        })
    );
    assert_eq!(w.remaining(), 0);
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [
            Frame::Padding { len: 1 },
            Frame::Stream {
                id,
                offset: VarInt::ZERO,
                data: &data,
                fin: true
            }
        ]
    );
}

#[test]
fn stream_is_full_when_neither_data_nor_a_bare_fin_fits() {
    let id = StreamId::from_varint(v(0x4000));
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    w.frame(&Frame::Padding { len: 48 }).unwrap();
    // Five bytes left: the type and a 4-byte ID fill them, so data does not fit.
    assert_eq!(w.remaining(), 5);
    assert_eq!(w.stream(id, VarInt::ZERO, b"data", false), Err(Full));
    assert_eq!(w.stream(id, v(1), b"", true), Err(Full));
    assert_eq!(w.remaining(), 5);
    // A FIN with empty data fits exactly, without a Length field.
    assert_eq!(
        w.stream(id, VarInt::ZERO, b"", true),
        Ok(StreamFit { len: 0, fin: true })
    );
    assert_eq!(w.remaining(), 0);
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout)[1],
        Frame::Stream {
            id,
            offset: VarInt::ZERO,
            data: b"",
            fin: true
        }
    );
}

#[test]
fn stream_data_never_ends_beyond_the_largest_offset() {
    // RFC 9000 does not allow stream data to end beyond 2^62 - 1, however much room is left.
    let max = VarInt::MAX.into_inner();
    let id = StreamId::from_varint(v(4));
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    assert_eq!(w.stream(id, v(max - 9), &[7; 20], true), Err(Full));
    assert_eq!(w.stream(id, v(max), &[7; 3], false), Err(Full));
    assert_eq!(w.stream(id, v(max), &[7; 3], true), Err(Full));
    assert!(w.begin_stream(id, v(max - 9), usize::MAX, false).is_err());
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    // Data ending exactly at 2^62 - 1 is fine, and so is a bare FIN there.
    assert_eq!(
        w.stream(id, v(max - 9), &[7; 9], true),
        Ok(StreamFit { len: 9, fin: true })
    );
    assert_eq!(
        w.stream(id, v(max), b"", true),
        Ok(StreamFit { len: 0, fin: true })
    );
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout),
        [
            Frame::Stream {
                id,
                offset: v(max - 9),
                data: &[7; 9],
                fin: true
            },
            Frame::Stream {
                id,
                offset: v(max),
                data: b"",
                fin: true
            },
        ]
    );
}

#[test]
fn stream_payload_comes_from_shared_buffers() {
    // A per-stream header and a payload shared by many streams, as `send_parts` keeps them.
    let header = Bytes::from_static(b"HDR:");
    let shared = Bytes::from(vec![0x42_u8; 1000]);
    let id = StreamId::from_varint(v(0));
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let mut payload = w.begin_stream(id, VarInt::ZERO, 4 + 50, true).unwrap();
    assert_eq!(payload.fit(), StreamFit { len: 54, fin: true });
    payload.put_payload(&header, 0..4).unwrap();
    payload.put_payload(&shared, 100..130).unwrap();
    assert_eq!(payload.due(), 20);
    payload.put_payload(&shared, 900..920).unwrap();
    assert_eq!(payload.finish(), Ok(StreamFit { len: 54, fin: true }));
    let layout = w.finish();
    let mut expected = b"HDR:".to_vec();
    expected.extend_from_slice(&[0x42; 50]);
    assert_eq!(
        frames_of(&slot, layout)[0],
        Frame::Stream {
            id,
            offset: VarInt::ZERO,
            data: &expected,
            fin: true
        }
    );
}

#[test]
fn unfinished_frame_payloads_are_removed() {
    let data = Bytes::from_static(b"0123456789");
    let id = StreamId::from_varint(v(0));
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    {
        let mut payload = w.begin_crypto(VarInt::ZERO, 8).unwrap();
        assert_eq!(
            payload.put_payload(&data, 5..11),
            Err(PayloadError::OutOfBounds)
        );
        #[allow(clippy::reversed_empty_ranges)]
        let backwards = 6..5;
        assert_eq!(
            payload.put_payload(&data, backwards),
            Err(PayloadError::OutOfBounds)
        );
        assert_eq!(payload.put_payload(&data, 0..9), Err(PayloadError::TooLong));
        assert_eq!(payload.due(), 8);
        payload.put_payload(&data, 0..4).unwrap();
        assert_eq!(payload.finish(), Err(PayloadError::Incomplete));
    }
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    assert!(!w.is_ack_eliciting());
    {
        let mut payload = w.begin_stream(id, VarInt::ZERO, 10, false).unwrap();
        payload.put_payload(&data, 0..3).unwrap();
        // Dropped without finishing.
    }
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    w.frame(&Frame::Ping).unwrap();
    let layout = w.finish();
    assert_eq!(frames_of(&slot, layout)[0], Frame::Ping);
}

#[test]
fn frames_encoded_by_the_caller_are_appended_in_pieces() {
    // A CRYPTO frame (type 0x06, offset 0, length 5) written as its header, then its data.
    let mut slot = [0u8; 60];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    w.put_ack_eliciting_bytes(&[0x06, 0x00, 0x05]).unwrap();
    assert!(
        w.is_ack_eliciting(),
        "CRYPTO bytes make the packet ack-eliciting"
    );
    w.put_ack_eliciting_bytes(b"hello").unwrap();
    assert_eq!(w.remaining(), room - 8);
    // Bytes that do not fit are refused whole and leave the packet as it was.
    let too_long = vec![0u8; w.remaining() + 1];
    assert_eq!(w.put_ack_eliciting_bytes(&too_long), Err(Full));
    assert_eq!(w.remaining(), room - 8);
    let layout = w.finish();
    assert_eq!(
        frames_of(&slot, layout)[0],
        Frame::Crypto {
            offset: VarInt::ZERO,
            data: b"hello"
        }
    );
}

#[test]
fn no_encoded_bytes_leave_the_packet_empty() {
    let mut slot = [0u8; 60];
    let mut w = short_writer(&mut slot);
    w.put_ack_eliciting_bytes(&[]).unwrap();
    assert!(w.is_empty());
    assert!(!w.is_ack_eliciting());
}

/// Ranges as an ACK tracker would hold them, largest first: every tenth packet missing.
fn ack_ranges(count: u64) -> Vec<std::ops::RangeInclusive<u64>> {
    (0..count)
        .map(|i| {
            let top = 100_000 - i * 10;
            top - 8..=top
        })
        .collect()
}

fn ack_of<'s>(slot: &'s [u8], layout: PacketLayout) -> AckFrame<'s> {
    match frames_of(slot, layout)[0] {
        Frame::Ack(ack) => ack,
        other => panic!("expected an ACK, got {other:?}"),
    }
}

#[test]
fn ack_fits_as_many_ranges_as_possible() {
    let ranges = ack_ranges(100);
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    // 53 bytes: type, 4-byte largest, 1-byte delay, 1-byte count and 1-byte first range take 8;
    // each further range takes 2 (gap 0, length 8).
    let written = w
        .ack(ranges[0].clone(), ranges[1..].iter().cloned(), v(3), None)
        .unwrap();
    assert_eq!(written, 1 + 22);
    assert_eq!(w.remaining(), 1);
    let layout = w.finish();
    let ack = ack_of(&slot, layout);
    assert_eq!(ack.largest(), v(100_000));
    assert_eq!(ack.delay(), v(3));
    assert!(ack.ranges().eq(ranges[..23].iter().cloned()));
}

#[test]
fn ack_with_ecn_counts_is_an_ack_ecn_frame() {
    let ecn = EcnCounts {
        ect0: v(5),
        ect1: v(0),
        ce: v(70_000),
    };
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    assert_eq!(w.ack(10..=12, [0..=7], v(0), Some(ecn)), Ok(2));
    assert!(!w.is_empty());
    assert!(!w.is_ack_eliciting());
    let layout = w.finish();
    let ack = ack_of(&slot, layout);
    assert_eq!(ack.ecn(), Some(ecn));
    assert!(ack.ranges().eq([10..=12, 0..=7]));
}

#[test]
fn ack_is_full_when_not_even_the_largest_range_fits() {
    // The 11-byte header leaves 80 - 11 - 16 = 53 bytes; PING takes one and padding the rest
    // but 4, and the smallest ACK here takes 1 + 4 + 1 + 1 + 1 = 8.
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    w.frame(&Frame::Ping).unwrap();
    w.pad_to(80 - 4).unwrap();
    assert_eq!(w.remaining(), 4);
    assert_eq!(w.ack(99_990..=100_000, [0..=7], v(0), None), Err(Full));
    assert_eq!(w.remaining(), 4);
}

#[test]
fn ack_ends_at_the_first_range_out_of_order() {
    // Adjacent, overlapping, rising and inverted ranges cannot be encoded after the one before.
    #[allow(clippy::reversed_empty_ranges)]
    let bad_ranges = [49..=49, 45..=55, 70..=80, 30..=20];
    for bad in bad_ranges {
        let mut slot = [0u8; 80];
        let mut w = short_writer(&mut slot);
        assert_eq!(
            w.ack(50..=60, [bad.clone(), 0..=5], v(0), None),
            Ok(1),
            "{bad:?}"
        );
        let layout = w.finish();
        assert!(ack_of(&slot, layout).ranges().eq([50..=60]), "{bad:?}");
    }
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    assert_eq!(
        w.ack(50..=60, [48..=48, 40..=46, 47..=47], v(0), None),
        Ok(3)
    );
    let layout = w.finish();
    assert!(
        ack_of(&slot, layout)
            .ranges()
            .eq([50..=60, 48..=48, 40..=46])
    );
}

#[test]
fn ack_is_full_for_a_largest_range_it_cannot_encode() {
    let max = VarInt::MAX.into_inner();
    let mut slot = [0u8; 80];
    let mut w = short_writer(&mut slot);
    assert_eq!(w.ack(max..=max + 1, [0..=0], v(0), None), Err(Full));
    #[allow(clippy::reversed_empty_ranges)]
    let inverted = 9..=8;
    assert_eq!(w.ack(inverted, [0..=0], v(0), None), Err(Full));
    assert!(w.is_empty());
    assert_eq!(w.ack(max - 3..=max, [0..=0], v(0), None), Ok(2));
}

#[test]
fn pad_to_stops_at_the_buffer_and_never_shrinks_the_packet() {
    let mut slot = [0xaa_u8; 80];
    let mut w = short_writer(&mut slot);
    w.frame(&Frame::Ping).unwrap();
    assert_eq!(w.pad_to(81), Err(Full));
    assert_eq!(w.remaining(), 80 - 11 - TAG - 1);
    w.pad_to(60).unwrap();
    assert_eq!(w.remaining(), 80 - 60);
    w.pad_to(40).unwrap();
    assert_eq!(w.remaining(), 80 - 60);
    w.pad_to(80).unwrap();
    assert_eq!(w.remaining(), 0);
    let layout = w.finish();
    assert_eq!(layout.len, 80);
    assert_eq!(
        frames_of(&slot, layout),
        [
            Frame::Ping,
            Frame::Padding {
                len: 80 - 11 - TAG - 1
            }
        ]
    );
}

#[test]
fn long_header_length_field_is_sized_for_the_buffer() {
    // A buffer over 16,383 bytes needs a 4-byte Length field; one up to that, 2 bytes.
    let data = vec![0x33_u8; 20_000];
    for (buf_len, length_size) in [(1200, 2), (16_383, 2), (16_384, 4), (20_000, 4)] {
        let mut slot = vec![0xaa_u8; buf_len];
        let spec = HeaderSpec::Handshake {
            version: Version::V1,
            dcid: cid(&[1; 8]),
            scid: cid(&[2; 8]),
        };
        let mut w = PacketWriter::new(&mut slot, spec, 0, 1, TAG).unwrap();
        assert_eq!(
            w.pn_offset(),
            1 + 4 + 1 + 8 + 1 + 8 + length_size,
            "{buf_len}"
        );
        let taken = w.crypto(v(0), &data).unwrap();
        assert_eq!(w.remaining(), 0, "{buf_len}");
        let layout = w.finish();
        assert_eq!(layout.len, buf_len);
        let header = parse(&slot, 8);
        assert_eq!(header.packet_len(), buf_len);
        assert_eq!(
            frames_of(&slot, layout),
            [Frame::Crypto {
                offset: v(0),
                data: &data[..taken]
            }]
        );
    }
}

#[test]
fn tracks_whether_the_packet_is_empty_and_ack_eliciting() {
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    assert!(w.is_empty());
    w.pad_to(60).unwrap();
    assert!(!w.is_empty());
    assert!(!w.is_ack_eliciting());
    w.frame(&Frame::ConnectionClose {
        error_code: mvfstr_wire::TransportErrorCode::NO_ERROR,
        frame_type: v(0),
        reason: b"",
    })
    .unwrap();
    w.frame(&Frame::Padding { len: 3 }).unwrap();
    assert!(!w.is_ack_eliciting());
    w.frame(&Frame::MaxData(v(1))).unwrap();
    assert!(w.is_ack_eliciting());
    w.frame(&Frame::Padding { len: 3 }).unwrap();
    assert!(w.is_ack_eliciting());
}

#[test]
fn finish_never_leaves_a_packet_without_frames() {
    // A 4-byte packet number and a 16-byte tag cover the header-protection sample on their own,
    // but RFC 9000 requires a protected packet to carry at least one frame.
    let mut slot = [0xaa_u8; 200];
    let header = HeaderSpec::OneRtt {
        dcid: cid(&[0xd0; 8]),
        spin: false,
        key_phase: false,
    };
    let w = PacketWriter::new(&mut slot, header, 7, 4, TAG).unwrap();
    let layout = w.finish();
    assert_eq!(layout.payload_len, 1);
    assert_eq!(frames_of(&slot, layout), [Frame::Padding { len: 1 }]);
}

#[test]
fn zero_length_padding_leaves_the_packet_empty() {
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    assert_eq!(w.frame(&Frame::Padding { len: 0 }), Ok(()));
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
}

#[test]
fn frame_refuses_an_invalid_frame_and_leaves_the_packet_unchanged() {
    let mut slot = [0u8; 200];
    let mut w = short_writer(&mut slot);
    let room = w.remaining();
    let token = Frame::NewToken { token: b"" };
    let empty_token = Err(FrameWriteError::Invalid(InvalidFrame::EmptyToken));
    assert_eq!(w.frame(&token), empty_token);
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    assert!(!w.is_ack_eliciting());
    let stream = Frame::Stream {
        id: StreamId::from_varint(v(0)),
        offset: v(VarInt::MAX.into_inner() - 9),
        data: &[7; 20],
        fin: true,
    };
    assert_eq!(
        w.frame(&stream),
        Err(FrameWriteError::Invalid(InvalidFrame::DataBeyondMaxOffset))
    );
    assert_eq!(w.remaining(), room);
    assert!(w.is_empty());
    // An invalid frame is refused as invalid even when it would not fit.
    w.frame(&Frame::Padding { len: room }).unwrap();
    assert_eq!(w.frame(&token), empty_token);
    assert!(!w.is_ack_eliciting());
    let layout = w.finish();
    assert_eq!(frames_of(&slot, layout), [Frame::Padding { len: room }]);
}
