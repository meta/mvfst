/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Variable-length integers (RFC 9000).

use std::fmt;

/// A QUIC variable-length integer: a value in `0..2^62`.
///
/// The encoding puts the base-2 logarithm of the encoded length (1, 2, 4 or 8 bytes) in the two
/// most significant bits of the first byte and the value in the remaining bits, in network byte
/// order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest representable value, 2^62 - 1.
    pub const MAX: VarInt = VarInt((1 << 62) - 1);
    /// Zero.
    pub const ZERO: VarInt = VarInt(0);
    /// The longest encoding, in bytes.
    pub const MAX_SIZE: usize = 8;

    /// Converts a `u32`, which always fits.
    pub const fn from_u32(value: u32) -> Self {
        VarInt(value as u64)
    }

    /// Converts a `u64`, failing if it is 2^62 or larger.
    pub const fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        if value <= Self::MAX.0 {
            Ok(VarInt(value))
        } else {
            Err(VarIntBoundsExceeded)
        }
    }

    /// Returns the value.
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Returns the length of the shortest encoding of this value: 1, 2, 4 or 8 bytes.
    pub const fn encoded_size(self) -> usize {
        if self.0 < 1 << 6 {
            1
        } else if self.0 < 1 << 14 {
            2
        } else if self.0 < 1 << 30 {
            4
        } else {
            8
        }
    }

    /// Returns the length of an encoding, read from its first byte.
    pub const fn size_from_first_byte(first: u8) -> usize {
        1 << (first >> 6)
    }

    /// Decodes a value from the start of `input` and returns it with the number of bytes read.
    ///
    /// Encodings longer than necessary are accepted, as RFC 9000 allows; callers that must reject
    /// them, such as the frame type decoder, compare the length read with
    /// [`encoded_size`](Self::encoded_size).
    pub fn decode(input: &[u8]) -> Result<(VarInt, usize), UnexpectedEnd> {
        let first = *input.first().ok_or(UnexpectedEnd)?;
        let size = Self::size_from_first_byte(first);
        let bytes = input.get(..size).ok_or(UnexpectedEnd)?;
        let value = bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, &byte| {
                (value << 8) | u64::from(byte)
            });
        Ok((VarInt(value), size))
    }

    /// Writes the shortest encoding at the start of `out` and returns its length. On error `out` is
    /// unchanged.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, BufferTooShort> {
        let size = self.encoded_size();
        let out = out.get_mut(..size).ok_or(BufferTooShort)?;
        self.write(out);
        Ok(size)
    }

    /// Writes an encoding of exactly `size` bytes (1, 2, 4 or 8) at the start of `out`, as for a
    /// length field reserved before its value is known. On error `out` is unchanged.
    pub fn encode_with_size(self, size: usize, out: &mut [u8]) -> Result<(), VarIntEncodeError> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(VarIntEncodeError::InvalidSize);
        }
        if self.encoded_size() > size {
            return Err(VarIntEncodeError::ValueTooLarge);
        }
        let out = out
            .get_mut(..size)
            .ok_or(VarIntEncodeError::BufferTooShort)?;
        self.write(out);
        Ok(())
    }

    /// Writes the value big-endian over all of `out` (1, 2, 4 or 8 bytes, large enough for the
    /// value) with the length prefix in the top two bits.
    fn write(self, out: &mut [u8]) {
        let prefix = match out.len() {
            1 => 0b00,
            2 => 0b01,
            4 => 0b10,
            _ => 0b11,
        };
        out.copy_from_slice(&self.0.to_be_bytes()[8 - out.len()..]);
        out[0] |= prefix << 6;
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self::from_u32(u32::from(value))
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self::from_u32(u32::from(value))
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::from_u64(u64::try_from(value).map_err(|_| VarIntBoundsExceeded)?)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.into_inner()
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A value is 2^62 or larger, which a variable-length integer cannot encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarIntBoundsExceeded;

impl fmt::Display for VarIntBoundsExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("value does not fit a QUIC variable-length integer (2^62 or larger)")
    }
}

impl std::error::Error for VarIntBoundsExceeded {}

/// The input ended inside an encoded value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnexpectedEnd;

impl fmt::Display for UnexpectedEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("input ended inside a variable-length integer")
    }
}

impl std::error::Error for UnexpectedEnd {}

/// The output buffer is shorter than the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooShort;

impl fmt::Display for BufferTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("output buffer too short for the encoding")
    }
}

impl std::error::Error for BufferTooShort {}

/// Why [`VarInt::encode_with_size`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarIntEncodeError {
    /// The size is not 1, 2, 4 or 8.
    InvalidSize,
    /// The value needs more bytes than the size gives.
    ValueTooLarge,
    /// The output buffer is shorter than the size.
    BufferTooShort,
}

impl fmt::Display for VarIntEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSize => "variable-length integer size must be 1, 2, 4 or 8",
            Self::ValueTooLarge => "value needs a longer variable-length encoding",
            Self::BufferTooShort => "output buffer too short for the encoding",
        })
    }
}

impl std::error::Error for VarIntEncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(value: u64) -> VarInt {
        VarInt::from_u64(value).unwrap()
    }

    // RFC 9000 Appendix A.1.
    const RFC_EXAMPLES: [(&[u8], u64); 5] = [
        (
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            151_288_809_941_952_652,
        ),
        (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
        (&[0x7b, 0xbd], 15_293),
        (&[0x25], 37),
        (&[0x40, 0x25], 37),
    ];

    #[test]
    fn decodes_rfc_examples() {
        for (bytes, value) in RFC_EXAMPLES {
            assert_eq!(
                VarInt::decode(bytes),
                Ok((v(value), bytes.len())),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        assert_eq!(
            VarInt::decode(&[0x7b, 0xbd, 0xff, 0xff]),
            Ok((v(15_293), 2))
        );
    }

    #[test]
    fn encodes_rfc_examples_minimally() {
        // The two-byte encoding of 37 is not minimal, so 37 encodes as the single byte.
        for (bytes, value) in &RFC_EXAMPLES[..4] {
            let mut out = [0u8; 8];
            assert_eq!(v(*value).encode(&mut out), Ok(bytes.len()));
            assert_eq!(&out[..bytes.len()], *bytes);
        }
    }

    #[test]
    fn encoded_size_at_each_boundary() {
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            ((1 << 30) - 1, 4),
            (1 << 30, 8),
            ((1 << 62) - 1, 8),
        ];
        for (value, size) in cases {
            assert_eq!(v(value).encoded_size(), size, "{value}");
        }
    }

    #[test]
    fn size_from_first_byte_reads_the_prefix() {
        assert_eq!(VarInt::size_from_first_byte(0x25), 1);
        assert_eq!(VarInt::size_from_first_byte(0x7b), 2);
        assert_eq!(VarInt::size_from_first_byte(0x9d), 4);
        assert_eq!(VarInt::size_from_first_byte(0xc2), 8);
    }

    #[test]
    fn bounds() {
        assert_eq!(VarInt::from_u64((1 << 62) - 1), Ok(VarInt::MAX));
        assert_eq!(VarInt::from_u64(1 << 62), Err(VarIntBoundsExceeded));
        assert_eq!(VarInt::try_from(u64::MAX), Err(VarIntBoundsExceeded));
        assert_eq!(VarInt::from_u32(u32::MAX).into_inner(), u64::from(u32::MAX));
        assert_eq!(VarInt::MAX.into_inner(), 4_611_686_018_427_387_903);
    }

    #[test]
    fn round_trips_boundaries() {
        for value in [
            0,
            1,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut out = [0u8; 8];
            let n = v(value).encode(&mut out).unwrap();
            assert_eq!(VarInt::decode(&out[..n]), Ok((v(value), n)));
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        assert_eq!(VarInt::decode(&[]), Err(UnexpectedEnd));
        assert_eq!(VarInt::decode(&[0x40]), Err(UnexpectedEnd));
        assert_eq!(VarInt::decode(&[0x9d, 0x7f, 0x3e]), Err(UnexpectedEnd));
        assert_eq!(
            VarInt::decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8]),
            Err(UnexpectedEnd)
        );
    }

    #[test]
    fn encode_into_short_buffer_fails_without_writing() {
        let mut out = [0xaau8; 3];
        assert_eq!(v(494_878_333).encode(&mut out), Err(BufferTooShort));
        assert_eq!(out, [0xaa; 3]);
        assert_eq!(v(0).encode(&mut []), Err(BufferTooShort));
    }

    #[test]
    fn encode_with_size_pads_the_encoding() {
        let mut out = [0u8; 8];
        assert_eq!(v(37).encode_with_size(2, &mut out), Ok(()));
        assert_eq!(out[..2], [0x40, 0x25]);
        assert_eq!(v(37).encode_with_size(8, &mut out), Ok(()));
        assert_eq!(VarInt::decode(&out), Ok((v(37), 8)));
        assert_eq!(v(15_293).encode_with_size(4, &mut out), Ok(()));
        assert_eq!(VarInt::decode(&out[..4]), Ok((v(15_293), 4)));
    }

    #[test]
    fn encode_with_size_rejects_bad_requests_without_writing() {
        let mut out = [0xaau8; 8];
        assert_eq!(
            v(1).encode_with_size(3, &mut out),
            Err(VarIntEncodeError::InvalidSize)
        );
        assert_eq!(
            v(1).encode_with_size(0, &mut out),
            Err(VarIntEncodeError::InvalidSize)
        );
        assert_eq!(
            v(64).encode_with_size(1, &mut out),
            Err(VarIntEncodeError::ValueTooLarge)
        );
        assert_eq!(
            v(16_384).encode_with_size(2, &mut out),
            Err(VarIntEncodeError::ValueTooLarge)
        );
        assert_eq!(
            v(1).encode_with_size(4, &mut out[..3]),
            Err(VarIntEncodeError::BufferTooShort)
        );
        assert_eq!(out, [0xaa; 8]);
    }
}
