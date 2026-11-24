/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Stream identifiers (RFC 9000).

use std::fmt;

use crate::Dir;
use crate::Side;
use crate::VarInt;
use crate::VarIntBoundsExceeded;

/// A stream ID: a 62-bit integer whose low bit names the initiator (0 client, 1 server), whose
/// second bit names the direction (0 bidirectional, 1 unidirectional), and whose remaining bits
/// are the stream's index among streams of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// The largest stream ID, 2^62 - 1.
    pub const MAX: StreamId = StreamId(VarInt::MAX.into_inner());
    /// The number of streams of each type, 2^60.
    pub const INDEX_LIMIT: u64 = 1 << 60;

    /// Returns the ID of the stream with the given initiator, direction and index, or `None` if the
    /// index is [`INDEX_LIMIT`](Self::INDEX_LIMIT) or larger.
    pub const fn new(initiator: Side, dir: Dir, index: u64) -> Option<StreamId> {
        if index >= Self::INDEX_LIMIT {
            return None;
        }
        let initiator_bit = match initiator {
            Side::Client => 0,
            Side::Server => 1,
        };
        let dir_bit = match dir {
            Dir::Bi => 0,
            Dir::Uni => 2,
        };
        Some(StreamId(index << 2 | dir_bit | initiator_bit))
    }

    /// Returns the ID carried by a variable-length integer; every such value is a valid stream ID.
    pub const fn from_varint(value: VarInt) -> StreamId {
        StreamId(value.into_inner())
    }

    /// Returns the ID as an integer.
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Returns the endpoint that opened the stream.
    pub const fn initiator(self) -> Side {
        if self.0 & 1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// Returns the stream's direction.
    pub const fn dir(self) -> Dir {
        if self.0 & 2 == 0 { Dir::Bi } else { Dir::Uni }
    }

    /// Returns the stream's position among streams with the same initiator and direction, from
    /// zero.
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl From<VarInt> for StreamId {
    fn from(value: VarInt) -> Self {
        Self::from_varint(value)
    }
}

impl From<StreamId> for VarInt {
    fn from(id: StreamId) -> Self {
        match VarInt::from_u64(id.0) {
            Ok(value) => value,
            // Every constructor keeps the ID below 2^62.
            Err(_) => unreachable!("stream IDs are below 2^62"),
        }
    }
}

impl From<StreamId> for u64 {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

impl TryFrom<u64> for StreamId {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        VarInt::from_u64(value).map(Self::from_varint)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u64) -> StreamId {
        StreamId::try_from(value).unwrap()
    }

    #[test]
    fn low_bits_name_the_type() {
        // RFC 9000 Table 1.
        let types = [
            (0, Side::Client, Dir::Bi),
            (1, Side::Server, Dir::Bi),
            (2, Side::Client, Dir::Uni),
            (3, Side::Server, Dir::Uni),
        ];
        for (value, initiator, dir) in types {
            assert_eq!(id(value).initiator(), initiator, "{value}");
            assert_eq!(id(value).dir(), dir, "{value}");
            assert_eq!(id(value).index(), 0, "{value}");
            assert_eq!(StreamId::new(initiator, dir, 0), Some(id(value)));
        }
    }

    #[test]
    fn index_counts_streams_of_one_type() {
        // mvfst tperf's server-initiated unidirectional streams.
        for (value, index) in [(3, 0), (7, 1), (11, 2)] {
            assert_eq!(id(value).index(), index);
            assert_eq!(
                StreamId::new(Side::Server, Dir::Uni, index),
                Some(id(value))
            );
        }
        assert_eq!(StreamId::new(Side::Client, Dir::Bi, 5), Some(id(20)));
        assert_eq!(StreamId::new(Side::Server, Dir::Bi, 5), Some(id(21)));
        assert_eq!(StreamId::new(Side::Client, Dir::Uni, 5), Some(id(22)));
    }

    #[test]
    fn index_limit() {
        let last = StreamId::new(Side::Server, Dir::Uni, StreamId::INDEX_LIMIT - 1);
        assert_eq!(last, Some(StreamId::MAX));
        assert_eq!(
            StreamId::new(Side::Client, Dir::Bi, StreamId::INDEX_LIMIT),
            None
        );
        assert_eq!(StreamId::new(Side::Client, Dir::Bi, u64::MAX), None);
    }

    #[test]
    fn converts_from_and_to_integers() {
        assert_eq!(StreamId::try_from(1 << 62), Err(VarIntBoundsExceeded));
        assert_eq!(u64::from(id(11)), 11);
        assert_eq!(VarInt::from(StreamId::MAX), VarInt::MAX);
        assert_eq!(StreamId::from(VarInt::from_u32(7)), id(7));
        assert_eq!(id(7).to_string(), "7");
    }
}
