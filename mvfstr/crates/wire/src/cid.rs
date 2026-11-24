/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection IDs and stateless reset tokens (RFC 9000).

use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::ops::Deref;

/// A connection ID of 0 to 20 bytes, stored inline.
///
/// Bytes past the length are always zero, so the derived comparisons and hash use only the ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; ConnectionId::MAX_LEN],
}

impl ConnectionId {
    /// The longest connection ID QUIC v1 allows.
    pub const MAX_LEN: usize = 20;
    /// The zero-length connection ID.
    pub const EMPTY: ConnectionId = ConnectionId {
        len: 0,
        bytes: [0; ConnectionId::MAX_LEN],
    };

    /// Copies an ID of at most [`MAX_LEN`](Self::MAX_LEN) bytes.
    pub fn new(id: &[u8]) -> Result<Self, CidTooLong> {
        if id.len() > Self::MAX_LEN {
            return Err(CidTooLong);
        }
        let mut bytes = [0; Self::MAX_LEN];
        bytes[..id.len()].copy_from_slice(id);
        Ok(Self {
            len: id.len() as u8,
            bytes,
        })
    }

    /// Returns the ID's bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl TryFrom<&[u8]> for ConnectionId {
    type Error = CidTooLong;

    fn try_from(id: &[u8]) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId({self})")
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// A connection ID longer than [`ConnectionId::MAX_LEN`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidTooLong;

impl fmt::Display for CidTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection ID longer than 20 bytes")
    }
}

impl std::error::Error for CidTooLong {}

/// A 16-byte stateless reset token.
///
/// Equality takes the same time whichever bytes differ, so comparing a received datagram's tail
/// with a token does not leak information about the token, as RFC 9000 requires.
#[derive(Clone, Copy)]
pub struct ResetToken(pub [u8; ResetToken::LEN]);

impl ResetToken {
    /// The token length.
    pub const LEN: usize = 16;
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        let diff = self
            .0
            .iter()
            .zip(&other.0)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        // Keeps the optimizer from turning the fold into an early-exit comparison.
        std::hint::black_box(diff) == 0
    }
}

impl Eq for ResetToken {}

impl Hash for ResetToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for ResetToken {
    // Tokens authenticate resets, so logs do not show their bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResetToken(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_zero_to_twenty_bytes() {
        let twenty: Vec<u8> = (1..=20).collect();
        for len in [0, 1, 8, 20] {
            let id = ConnectionId::new(&twenty[..len]).unwrap();
            assert_eq!(id.as_slice(), &twenty[..len]);
            assert_eq!(id.len(), len);
        }
        assert!(ConnectionId::new(&[]).unwrap().is_empty());
        assert_eq!(ConnectionId::new(&[]).unwrap(), ConnectionId::EMPTY);
    }

    #[test]
    fn rejects_more_than_twenty_bytes() {
        assert_eq!(ConnectionId::new(&[7; 21]), Err(CidTooLong));
        assert_eq!(ConnectionId::try_from(&[7u8; 255][..]), Err(CidTooLong));
    }

    #[test]
    fn equality_is_by_length_and_bytes() {
        let a = ConnectionId::new(&[1, 2, 3, 4]).unwrap();
        assert_eq!(a, ConnectionId::new(&[1, 2, 3, 4]).unwrap());
        assert_ne!(a, ConnectionId::new(&[1, 2, 3]).unwrap());
        assert_ne!(a, ConnectionId::new(&[1, 2, 3, 4, 0]).unwrap());
        assert_ne!(a, ConnectionId::new(&[1, 2, 3, 5]).unwrap());
    }

    #[test]
    fn reset_tokens_are_equal_only_when_every_byte_is() {
        let token = ResetToken(std::array::from_fn(|i| i as u8));
        assert_eq!(token, ResetToken(std::array::from_fn(|i| i as u8)));
        for i in 0..ResetToken::LEN {
            let mut other = token;
            other.0[i] ^= 0x80;
            assert_ne!(token, other, "tokens differing in byte {i} compared equal");
        }
    }

    #[test]
    fn formats_as_hex() {
        let id = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0]).unwrap();
        assert_eq!(id.to_string(), "8394c8f0");
        assert_eq!(format!("{id:?}"), "ConnectionId(8394c8f0)");
        assert_eq!(format!("{:?}", ResetToken([9; 16])), "ResetToken(..)");
    }
}
