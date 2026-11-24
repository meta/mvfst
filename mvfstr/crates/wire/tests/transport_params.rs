/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The transport parameter codec.

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use bytes::Bytes;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::PreferredAddress;
use mvfstr_wire::ResetToken;
use mvfstr_wire::TransportParameterError;
use mvfstr_wire::TransportParameters;
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

fn cid(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

/// RFC 9001 Appendix A.2: the client's transport parameters in its first Initial.
const RFC9001_CLIENT: &str = "
    0408ffffffffffffffff 05048000ffff 07048000ffff 080110 010480007530 090110
    0f088394c8f03e515708 06048000ffff";

#[test]
fn decodes_the_rfc9001_client_parameters() {
    let params = TransportParameters::decode(&hex(RFC9001_CLIENT), &[]).unwrap();
    assert_eq!(
        params,
        TransportParameters {
            max_idle_timeout: v(30_000),
            initial_max_data: VarInt::MAX,
            initial_max_stream_data_bidi_local: v(0xffff),
            initial_max_stream_data_bidi_remote: v(0xffff),
            initial_max_stream_data_uni: v(0xffff),
            initial_max_streams_bidi: v(16),
            initial_max_streams_uni: v(16),
            initial_source_connection_id: Some(cid(&hex("8394c8f03e515708"))),
            ..TransportParameters::default()
        }
    );
}

#[test]
fn absent_parameters_take_the_rfc_defaults() {
    let params = TransportParameters::decode(&[], &[]).unwrap();
    assert_eq!(params, TransportParameters::default());
    assert_eq!(params.max_udp_payload_size, v(65_527));
    assert_eq!(params.ack_delay_exponent, v(3));
    assert_eq!(params.max_ack_delay, v(25));
    assert_eq!(params.active_connection_id_limit, v(2));
    assert_eq!(params.max_idle_timeout, v(0));
    assert_eq!(params.initial_max_data, v(0));
    assert_eq!(params.initial_max_streams_bidi, v(0));
    assert!(!params.disable_active_migration);
    assert_eq!(params.stateless_reset_token, None);
    assert_eq!(params.preferred_address, None);
    assert_eq!(params.original_destination_connection_id, None);
    assert_eq!(params.initial_source_connection_id, None);
    assert_eq!(params.retry_source_connection_id, None);
    assert!(params.extra.is_empty());
}

/// Every parameter RFC 9000 defines, in id order, each value minimally encoded.
const EVERY_PARAMETER: &str = "
    00 08 0102030405060708
    01 04 8000ea60
    02 10 000102030405060708090a0b0c0d0e0f
    03 02 45ac
    04 04 80100000
    05 04 80010400
    06 04 80010400
    07 08 c0000000ffffffff
    08 02 4800
    09 02 4800
    0a 01 0a
    0b 02 4064
    0c 00
    0d 2d c0000201 1151 20010db8000000000000000000000001 1152 04 aabbccdd
          101112131415161718191a1b1c1d1e1f
    0e 01 05
    0f 05 1112131415
    10 04 21222324";

fn every_parameter() -> TransportParameters {
    TransportParameters {
        original_destination_connection_id: Some(cid(&[1, 2, 3, 4, 5, 6, 7, 8])),
        max_idle_timeout: v(60_000),
        stateless_reset_token: Some(ResetToken(std::array::from_fn(|i| i as u8))),
        max_udp_payload_size: v(1452),
        initial_max_data: v(1 << 20),
        initial_max_stream_data_bidi_local: v(66_560),
        initial_max_stream_data_bidi_remote: v(66_560),
        initial_max_stream_data_uni: v(u64::from(u32::MAX)),
        initial_max_streams_bidi: v(2048),
        initial_max_streams_uni: v(2048),
        ack_delay_exponent: v(10),
        max_ack_delay: v(100),
        disable_active_migration: true,
        preferred_address: Some(PreferredAddress {
            ipv4: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4433),
            ipv6: SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 4434, 0, 0),
            connection_id: cid(&[0xaa, 0xbb, 0xcc, 0xdd]),
            stateless_reset_token: ResetToken(std::array::from_fn(|i| 0x10 + i as u8)),
        }),
        active_connection_id_limit: v(5),
        initial_source_connection_id: Some(cid(&[0x11, 0x12, 0x13, 0x14, 0x15])),
        retry_source_connection_id: Some(cid(&[0x21, 0x22, 0x23, 0x24])),
        extra: Vec::new(),
    }
}

#[test]
fn decodes_every_parameter() {
    let params = TransportParameters::decode(&hex(EVERY_PARAMETER), &[]).unwrap();
    assert_eq!(params, every_parameter());
}

#[test]
fn encodes_every_parameter_in_id_order() {
    let mut out = vec![0xee];
    every_parameter().encode(&mut out).unwrap();
    assert_eq!(out[0], 0xee, "appends");
    assert_eq!(out[1..], hex(EVERY_PARAMETER));
}

#[test]
fn encoding_omits_parameters_at_their_defaults() {
    let mut out = Vec::new();
    TransportParameters::default().encode(&mut out).unwrap();
    assert_eq!(out, b"");
    let params = TransportParameters {
        initial_max_data: v(1),
        ..TransportParameters::default()
    };
    params.encode(&mut out).unwrap();
    assert_eq!(out, hex("04 01 01"));
}

/// The parameters mvfst's tperf client sends with its default flags, in its order, ending with
/// mvfst's ack_receive_timestamps_enabled (0xff0a001) set to 0.
const TPERF_CLIENT: &str = "
    05 04 80010400  06 04 80010400  07 08 c0000000ffffffff  04 04 80100000  08 02 4800
    09 02 4800  01 04 8000ea60  0a 01 03  03 02 45ac  0e 01 02  8ff0a001 01 00";

#[test]
fn decodes_the_tperf_client_parameters_ignoring_the_meta_one() {
    let params = TransportParameters::decode(&hex(TPERF_CLIENT), &[]).unwrap();
    assert_eq!(
        params,
        TransportParameters {
            max_idle_timeout: v(60_000),
            max_udp_payload_size: v(1452),
            initial_max_data: v(1 << 20),
            initial_max_stream_data_bidi_local: v(66_560),
            initial_max_stream_data_bidi_remote: v(66_560),
            initial_max_stream_data_uni: v(u64::from(u32::MAX)),
            initial_max_streams_bidi: v(2048),
            initial_max_streams_uni: v(2048),
            ..TransportParameters::default()
        }
    );
}

#[test]
fn keeps_the_raw_values_of_requested_ids_and_ignores_other_unknown_ones() {
    // RFC 9000 reserves the ids 31 * N + 27, and 0x20 is RFC 9221's max_datagram_frame_size.
    let input = hex(&format!(
        "{RFC9001_CLIENT} 1b 03 616263 20 02 4400 c000000000000078 00 8ff0a001 01 00
         5f3a 01 07"
    ));
    let keep = [v(0xff0a001), v(0x20), v(0x1234)];
    let params = TransportParameters::decode(&input, &keep).unwrap();
    assert_eq!(
        params.extra,
        [
            (v(0x20), Bytes::from_static(&[0x44, 0x00])),
            (v(0xff0a001), Bytes::from_static(&[0]))
        ]
    );
    let without_extra = TransportParameters {
        extra: Vec::new(),
        ..params
    };
    assert_eq!(
        without_extra,
        TransportParameters::decode(&hex(RFC9001_CLIENT), &[]).unwrap()
    );
    assert!(
        TransportParameters::decode(&input, &[])
            .unwrap()
            .extra
            .is_empty()
    );
}

#[test]
fn a_parameter_sent_twice_is_an_error() {
    // RFC 9000 forbids sending a parameter twice, and unknown ids count too.
    for (input, id) in [
        ("04 01 01  01 01 02  04 01 01", 0x04),
        ("0c 00  0c 00", 0x0c),
        ("1b 00  04 01 01  1b 01 07", 0x1b),
        ("8ff0a001 01 00  8ff0a001 01 00", 0xff0a001),
    ] {
        let err = TransportParameters::decode(&hex(input), &[v(0xff0a001)]).unwrap_err();
        assert_eq!(err, TransportParameterError::Duplicate(v(id)), "{input}");
        assert_eq!(
            err.code(),
            mvfstr_wire::TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
    }
}

#[test]
fn input_ending_inside_a_parameter_is_truncated() {
    for input in ["04", "8ff0", "04 01", "04 41", "04 02 01", "0d 2d c0000201"] {
        let err = TransportParameters::decode(&hex(input), &[]).unwrap_err();
        assert_eq!(err, TransportParameterError::Truncated, "{input}");
    }
    let every = hex(EVERY_PARAMETER);
    for len in 0..every.len() {
        let result = TransportParameters::decode(&every[..len], &[]);
        assert!(
            matches!(result, Ok(_) | Err(TransportParameterError::Truncated)),
            "{len}"
        );
    }
}

#[test]
fn values_encoded_wrongly_for_their_id_are_malformed() {
    let cid21 = "00".repeat(21);
    let token15 = "00".repeat(15);
    let addr = "c0000201 1151 20010db8000000000000000000000001 1152";
    let token = "101112131415161718191a1b1c1d1e1f";
    let cases = [
        // Integers are exactly one variable-length integer.
        ("01 00".to_string(), 0x01),
        ("01 02 05 00".to_string(), 0x01),
        ("04 01 40".to_string(), 0x04),
        ("0e 03 4005 00".to_string(), 0x0e),
        (format!("02 0f {token15}"), 0x02),
        (format!("02 11 {token} 00"), 0x02),
        (format!("00 15 {cid21}"), 0x00),
        (format!("0f 15 {cid21}"), 0x0f),
        (format!("10 15 {cid21}"), 0x10),
        ("0c 01 00".to_string(), 0x0c),
        // preferred_address: short, long, and a 21-byte connection ID.
        (
            format!("0d 2c {addr} 04 aabbccdd 101112131415161718191a1b1c1d1e"),
            0x0d,
        ),
        (format!("0d 2e {addr} 04 aabbccdd {token} 00"), 0x0d),
        (format!("0d 3e {addr} 15 {cid21} {token}"), 0x0d),
    ];
    for (input, id) in cases {
        let err = TransportParameters::decode(&hex(&input), &[]).unwrap_err();
        assert_eq!(err, TransportParameterError::Malformed(v(id)), "{input}");
    }
}

#[test]
fn values_outside_the_allowed_range_are_invalid() {
    let addr = "c0000201 1151 20010db8000000000000000000000001 1152";
    let token = "101112131415161718191a1b1c1d1e1f";
    let cases = [
        ("03 02 44af".to_string(), 0x03),
        ("08 08 d000000000000001".to_string(), 0x08),
        ("09 08 d000000000000001".to_string(), 0x09),
        ("0a 01 15".to_string(), 0x0a),
        ("0b 04 80004000".to_string(), 0x0b),
        ("0e 01 01".to_string(), 0x0e),
        ("0e 01 00".to_string(), 0x0e),
        // A preferred address needs a connection ID.
        (format!("0d 29 {addr} 00 {token}"), 0x0d),
    ];
    for (input, id) in cases {
        let err = TransportParameters::decode(&hex(&input), &[]).unwrap_err();
        assert_eq!(err, TransportParameterError::InvalidValue(v(id)), "{input}");
    }
    let limits = "03 02 44b0  08 08 d000000000000000  09 08 d000000000000000  0a 01 14
                  0b 02 7fff  0e 01 02";
    let params = TransportParameters::decode(&hex(limits), &[]).unwrap();
    assert_eq!(params.max_udp_payload_size, v(1200));
    assert_eq!(params.initial_max_streams_bidi, v(1 << 60));
    assert_eq!(params.initial_max_streams_uni, v(1 << 60));
    assert_eq!(params.ack_delay_exponent, v(20));
    assert_eq!(params.max_ack_delay, v((1 << 14) - 1));
}

/// The parameters of a server connection on version 1 with mvfst's defaults: 66,560-byte stream
/// windows, a 1 MiB connection window, 2,048 streams each way, a 60 s idle timeout, a
/// 1,500-byte max_udp_payload_size, and migration disabled.
fn mvfst_server_defaults() -> TransportParameters {
    TransportParameters {
        original_destination_connection_id: Some(cid(&[1, 2, 3, 4, 5, 6, 7, 8])),
        max_idle_timeout: v(60_000),
        stateless_reset_token: Some(ResetToken(std::array::from_fn(|i| i as u8))),
        max_udp_payload_size: v(1500),
        initial_max_data: v(1 << 20),
        initial_max_stream_data_bidi_local: v(66_560),
        initial_max_stream_data_bidi_remote: v(66_560),
        initial_max_stream_data_uni: v(66_560),
        initial_max_streams_bidi: v(2048),
        initial_max_streams_uni: v(2048),
        disable_active_migration: true,
        initial_source_connection_id: Some(cid(&[0x11, 0x12, 0x13, 0x14, 0x15])),
        ..TransportParameters::default()
    }
}

#[test]
fn mvfsts_server_order_writes_the_integers_even_at_their_defaults_then_the_token_and_ids() {
    let mut out = vec![0xee];
    let mut params = mvfst_server_defaults();
    params.extra = vec![(v(0xff0a001), Bytes::from_static(&[0]))];
    params.encode_in_mvfst_server_order(&mut out).unwrap();
    assert_eq!(out[0], 0xee, "appends");
    // ack_delay_exponent and active_connection_id_limit are written at their defaults.
    assert_eq!(
        out[1..],
        hex("
            00 08 0102030405060708
            05 04 80010400  06 04 80010400  07 04 80010400  04 04 80100000  08 02 4800
            09 02 4800  01 04 8000ea60  0a 01 03  03 02 45dc  0e 01 02
            02 10 000102030405060708090a0b0c0d0e0f
            0c 00
            0f 05 1112131415
            8ff0a001 01 00")
    );
    assert_eq!(
        TransportParameters::decode(&out[1..], &[v(0xff0a001)]),
        Ok(params)
    );
}

#[test]
fn mvfsts_server_order_writes_every_parameter_with_the_retry_source_id_after_the_initial_one() {
    let mut params = every_parameter();
    params.extra = vec![(v(0xff0a001), Bytes::from_static(&[0]))];
    let mut out = Vec::new();
    params.encode_in_mvfst_server_order(&mut out).unwrap();
    // mvfst never sends preferred_address; it follows disable_active_migration, as in id order.
    assert_eq!(
        out,
        hex("
            00 08 0102030405060708
            05 04 80010400  06 04 80010400  07 08 c0000000ffffffff  04 04 80100000  08 02 4800
            09 02 4800  01 04 8000ea60  0a 01 0a  0b 02 4064  03 02 45ac  0e 01 05
            02 10 000102030405060708090a0b0c0d0e0f
            0c 00
            0d 2d c0000201 1151 20010db8000000000000000000000001 1152 04 aabbccdd
                  101112131415161718191a1b1c1d1e1f
            0f 05 1112131415
            10 04 21222324
            8ff0a001 01 00")
    );
    assert_eq!(
        TransportParameters::decode(&out, &[v(0xff0a001)]),
        Ok(params)
    );
}

#[test]
fn mvfsts_server_order_writes_max_ack_delay_after_the_exponent_only_away_from_25_ms() {
    let mut params = mvfst_server_defaults();
    params.original_destination_connection_id = None;
    params.stateless_reset_token = None;
    params.disable_active_migration = false;
    params.initial_source_connection_id = None;
    let mut at_default = Vec::new();
    params
        .encode_in_mvfst_server_order(&mut at_default)
        .unwrap();
    params.max_ack_delay = v(31);
    let mut out = Vec::new();
    params.encode_in_mvfst_server_order(&mut out).unwrap();
    assert_eq!(
        out,
        hex("
            05 04 80010400  06 04 80010400  07 04 80010400  04 04 80100000  08 02 4800
            09 02 4800  01 04 8000ea60  0a 01 03  0b 01 1f  03 02 45dc  0e 01 02")
    );
    assert_eq!(at_default.len(), out.len() - 3);
}

#[test]
fn encoding_writes_extra_parameters_after_the_known_ones() {
    let params = TransportParameters {
        initial_max_data: v(1),
        extra: vec![
            (v(0x1b), Bytes::from_static(b"abc")),
            (v(0xff0a001), Bytes::from_static(&[0])),
        ],
        ..TransportParameters::default()
    };
    let mut out = Vec::new();
    params.encode(&mut out).unwrap();
    assert_eq!(out, hex("04 01 01  1b 03 616263  8ff0a001 01 00"));
    assert_eq!(
        TransportParameters::decode(&out, &[v(0x1b), v(0xff0a001)]),
        Ok(params)
    );
}

#[test]
fn encoding_rejects_what_decoding_would_and_leaves_the_output_alone() {
    let extra = |ids: &[u64]| ids.iter().map(|&id| (v(id), Bytes::new())).collect();
    let cases = [
        (
            TransportParameters {
                ack_delay_exponent: v(21),
                ..TransportParameters::default()
            },
            TransportParameterError::InvalidValue(v(0x0a)),
        ),
        (
            TransportParameters {
                extra: extra(&[0x1b, 0x3a, 0x1b]),
                ..TransportParameters::default()
            },
            TransportParameterError::Duplicate(v(0x1b)),
        ),
        // Extra parameters cannot stand in for the ones RFC 9000 defines.
        (
            TransportParameters {
                extra: extra(&[0x04]),
                ..TransportParameters::default()
            },
            TransportParameterError::Duplicate(v(0x04)),
        ),
        (
            TransportParameters {
                extra: extra(&[0x10]),
                ..TransportParameters::default()
            },
            TransportParameterError::Duplicate(v(0x10)),
        ),
    ];
    for (params, expected) in cases {
        let mut out = vec![0xee];
        assert_eq!(params.encode(&mut out), Err(expected));
        assert_eq!(out, [0xee]);
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A value in `lo..=hi`, with every encoded size likely.
    fn int(&mut self, lo: u64, hi: u64) -> VarInt {
        let bits = self.below(63);
        let raw = self.next() & ((1 << bits) - 1);
        v(lo + raw % (hi - lo + 1))
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn cid(&mut self, min_len: u64) -> ConnectionId {
        let len = min_len + self.below(21 - min_len);
        cid(&self.bytes(len as usize))
    }

    fn maybe<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> Option<T> {
        (self.below(2) == 0).then(|| f(self))
    }
}

const KEPT: [u64; 3] = [0x1b, 0x20, 0xff0a001];

fn random_params(rng: &mut XorShift) -> TransportParameters {
    let max = VarInt::MAX.into_inner();
    let token = |rng: &mut XorShift| ResetToken(rng.bytes(16).try_into().unwrap());
    let mut params = TransportParameters {
        original_destination_connection_id: rng.maybe(|rng| rng.cid(0)),
        max_idle_timeout: rng.int(0, max),
        stateless_reset_token: rng.maybe(token),
        max_udp_payload_size: rng.int(1200, max),
        initial_max_data: rng.int(0, max),
        initial_max_stream_data_bidi_local: rng.int(0, max),
        initial_max_stream_data_bidi_remote: rng.int(0, max),
        initial_max_stream_data_uni: rng.int(0, max),
        initial_max_streams_bidi: rng.int(0, 1 << 60),
        initial_max_streams_uni: rng.int(0, 1 << 60),
        ack_delay_exponent: rng.int(0, 20),
        max_ack_delay: rng.int(0, (1 << 14) - 1),
        disable_active_migration: rng.below(2) == 0,
        preferred_address: rng.maybe(|rng| PreferredAddress {
            ipv4: SocketAddrV4::new(Ipv4Addr::from(rng.next() as u32), rng.next() as u16),
            ipv6: SocketAddrV6::new(
                Ipv6Addr::from(u128::from(rng.next()) << 64),
                rng.next() as u16,
                0,
                0,
            ),
            connection_id: rng.cid(1),
            stateless_reset_token: token(rng),
        }),
        active_connection_id_limit: rng.int(2, max),
        initial_source_connection_id: rng.maybe(|rng| rng.cid(0)),
        retry_source_connection_id: rng.maybe(|rng| rng.cid(0)),
        extra: Vec::new(),
    };
    for id in KEPT {
        if rng.below(2) == 0 {
            let len = rng.below(10) as usize;
            params.extra.push((v(id), Bytes::from(rng.bytes(len))));
        }
    }
    params
}

#[test]
fn random_parameters_round_trip() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let keep = KEPT.map(v);
    for _ in 0..5_000 {
        let params = random_params(&mut rng);
        let mut out = Vec::new();
        params.encode(&mut out).unwrap();
        assert_eq!(TransportParameters::decode(&out, &keep), Ok(params));
    }
}

#[test]
fn arbitrary_input_never_panics_and_decodes_stably() {
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let valid = hex(EVERY_PARAMETER);
    let mut decoded = 0;
    for _ in 0..20_000 {
        // Mutate a valid encoding or draw bytes biased toward small ids and lengths.
        let mut input = if rng.below(2) == 0 {
            valid.clone()
        } else {
            Vec::new()
        };
        for _ in 0..rng.below(4) {
            if let Some(len) = std::num::NonZeroUsize::new(input.len()) {
                let at = rng.below(len.get() as u64) as usize;
                input[at] = rng.next() as u8;
            }
        }
        let extra = rng.below(24);
        input.extend((0..extra).map(|_| rng.below(0x14) as u8));
        if let Ok(params) = TransportParameters::decode(&input, &[]) {
            decoded += 1;
            let mut out = Vec::new();
            params.encode(&mut out).unwrap();
            assert_eq!(TransportParameters::decode(&out, &[]), Ok(params));
        }
    }
    assert!(decoded > 100, "{decoded}");
}
