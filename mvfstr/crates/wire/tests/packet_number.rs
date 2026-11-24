/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Packet number encoding and decoding, with the examples of RFC 9000 Appendix A.

use mvfstr_wire::decode_packet_number;
use mvfstr_wire::packet_number_len;

#[test]
fn len_matches_rfc_examples() {
    // RFC 9000 App. A.2: 29,519 packets outstanding need 16 bits, 65,611 need 24.
    assert_eq!(packet_number_len(0xac5c02, Some(0xabe8b3)), 2);
    assert_eq!(packet_number_len(0xace8fe, Some(0xabe8b3)), 3);
}

#[test]
fn len_before_any_ack_counts_from_zero() {
    assert_eq!(packet_number_len(0, None), 1);
    assert_eq!(packet_number_len(126, None), 1);
    // 128 unacknowledged packet numbers need a window of more than 256.
    assert_eq!(packet_number_len(127, None), 2);
    // mvfst starts each space at a random packet number below 2^24.
    assert_eq!(packet_number_len(0x00ab_cdef, None), 4);
    assert_eq!(packet_number_len(0x003f_ffff, None), 3);
}

#[test]
fn len_at_power_of_two_boundaries_and_cap() {
    assert_eq!(packet_number_len(1000 + 127, Some(1000)), 1);
    assert_eq!(packet_number_len(1000 + 128, Some(1000)), 2);
    assert_eq!(packet_number_len(1000 + 32_767, Some(1000)), 2);
    assert_eq!(packet_number_len(1000 + 32_768, Some(1000)), 3);
    assert_eq!(packet_number_len(1000 + (1 << 23), Some(1000)), 4);
    assert_eq!(packet_number_len(1 << 40, Some(0)), 4);
    assert_eq!(packet_number_len((1 << 62) - 1, None), 4);
}

#[test]
fn decode_matches_rfc_example() {
    // RFC 9000 App. A.3.
    assert_eq!(
        decode_packet_number(Some(0xa82f30ea), 0x9b32, 2),
        0xa82f9b32
    );
}

#[test]
fn decode_picks_the_candidate_closest_to_the_next_expected() {
    // Expected 0x1_00: a truncated 0xff is the packet just before, not 0x1ff.
    assert_eq!(decode_packet_number(Some(0xff), 0xff, 1), 0xff);
    assert_eq!(decode_packet_number(Some(0x100), 0xfe, 1), 0xfe);
    // Expected 0x1fe: 0x02 wraps forward into the next window.
    assert_eq!(decode_packet_number(Some(0x1fd), 0x02, 1), 0x202);
    // The window is (expected - 128, expected + 128].
    assert_eq!(decode_packet_number(Some(0x17f), 0x00, 1), 0x200);
    assert_eq!(decode_packet_number(Some(0x180), 0x01, 1), 0x201);
    assert_eq!(decode_packet_number(Some(0x180), 0x00, 1), 0x100 + 0x100);
    assert_eq!(decode_packet_number(Some(0x27e), 0x00, 1), 0x200);
    assert_eq!(decode_packet_number(Some(0x27f), 0x00, 1), 0x300);
}

#[test]
fn decode_stays_inside_the_packet_number_space() {
    const TOP: u64 = (1 << 62) - 1;
    // Wrapping forward would leave the space, so the lower candidate stands.
    assert_eq!(decode_packet_number(Some(TOP - 1), 0x00, 1), TOP - 0xff);
    assert_eq!(decode_packet_number(Some(TOP - 1), 0xff, 1), TOP);
    assert_eq!(decode_packet_number(Some(TOP), 0xffff_ffff, 4), TOP);
    // Before any packet is received, the next expected number is 0.
    assert_eq!(decode_packet_number(None, 0xffff_ffff, 4), 0xffff_ffff);
    assert_eq!(decode_packet_number(None, 0x7f, 1), 0x7f);
    assert_eq!(decode_packet_number(None, 0xab_cdef, 3), 0xab_cdef);
}

#[test]
fn decode_tolerates_out_of_range_arguments() {
    // Lengths come from two header bits and so are 1 to 4; others are clamped, not a panic.
    assert_eq!(decode_packet_number(Some(10), 12, 0), 12);
    assert_eq!(decode_packet_number(Some(10), 12, 9), 12);
    // Bits above the field length are ignored.
    assert_eq!(decode_packet_number(Some(0x1000), 0x1_02, 1), 0x1002);
    assert_eq!(
        decode_packet_number(Some(u64::MAX), 0, 4),
        (1 << 62) - (1 << 32)
    );
}

#[test]
fn chosen_length_decodes_for_any_receiver_state_since_the_ack() {
    // The receiver has processed some packet in [largest_acked, pn - 1]; the chosen length
    // must recover `pn` from every such state.
    let cases = [
        (0u64, 1u64),
        (0, 127),
        (0, 128),
        (1000, 1128),
        (0xabe8b3, 0xac5c02),
        (0xabe8b3, 0xace8fe),
        (5, 5 + 32_768),
        (1 << 40, (1 << 40) + (1 << 23) + 17),
        ((1 << 62) - 300, (1 << 62) - 1),
    ];
    for (largest_acked, pn) in cases {
        let len = packet_number_len(pn, Some(largest_acked));
        let truncated = (pn & ((1u64 << (8 * len)) - 1)) as u32;
        let span = pn - largest_acked;
        for step in 0..=64u64 {
            let received = largest_acked + span * step / 65;
            assert_eq!(
                decode_packet_number(Some(received), truncated, len),
                pn,
                "acked {largest_acked:#x} pn {pn:#x} len {len} received {received:#x}"
            );
        }
    }
}
