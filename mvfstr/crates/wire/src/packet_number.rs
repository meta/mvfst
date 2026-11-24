/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC packet number encoding and decoding (RFC 9000).

/// Returns the Packet Number field length, 1 to 4 bytes, for sending `full_pn` when the peer has
/// acknowledged up to `largest_acked` in the same space (`None` before any acknowledgment).
///
/// This is the shortest encoding that represents more than twice the number of unacknowledged
/// packet numbers, the new one included, as RFC 9000 requires. That is one bit more than the bit
/// length of the count, which at exact powers of two is one bit more than the `log2(count) + 1`
/// of RFC 9000's sample algorithm, whose window would then be exactly twice the range, not more.
/// Senders keep fewer than 2^31 packets unacknowledged, so 4 bytes is the cap.
pub fn packet_number_len(full_pn: u64, largest_acked: Option<u64>) -> usize {
    let unacked = match largest_acked {
        Some(largest) => full_pn.saturating_sub(largest),
        None => full_pn.saturating_add(1),
    };
    let bits = (u64::BITS - unacked.leading_zeros()) as usize + 1;
    bits.div_ceil(8).min(4)
}

/// Recovers a full packet number from the `pn_len`-byte value `truncated` read from a header,
/// given the largest packet number successfully processed in the same space.
///
/// The result is the candidate closest to the next expected packet number, as in RFC 9000's
/// sample decoding algorithm, kept inside the packet number space `0..2^62`. `pn_len` is clamped
/// to 1..=4 and bits of `truncated` above it are ignored, so this never panics.
pub fn decode_packet_number(largest_pn: Option<u64>, truncated: u32, pn_len: usize) -> u64 {
    const LIMIT: u64 = 1 << 62;
    let expected = largest_pn.map_or(0, |largest| largest.min(LIMIT - 1) + 1);
    let window = 1u64 << (8 * pn_len.clamp(1, 4));
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | (u64::from(truncated) & (window - 1));
    if candidate + half <= expected && candidate < LIMIT - window {
        candidate + window
    } else if (candidate > expected + half || candidate >= LIMIT) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}
