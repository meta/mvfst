/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bounds-checked reading and capacity-checked writing of wire fields, shared by the header,
//! frame and transport parameter codecs and the in-place packet writer.

use crate::UnexpectedEnd;
use crate::VarInt;

/// A reader of fields from the front of a byte slice. Every read checks the length and never
/// panics.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes consumed so far.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the unread bytes without consuming them.
    pub(crate) fn peek_rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Consumes and returns every unread byte.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let rest = self.peek_rest();
        self.pos = self.buf.len();
        rest
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], UnexpectedEnd> {
        let bytes = self.peek_rest().get(..len).ok_or(UnexpectedEnd)?;
        self.pos += len;
        Ok(bytes)
    }

    /// Reads `len` bytes, where `len` came off the wire as a variable-length integer.
    pub(crate) fn bytes_varint_len(&mut self, len: VarInt) -> Result<&'a [u8], UnexpectedEnd> {
        let len = usize::try_from(len.into_inner()).map_err(|_| UnexpectedEnd)?;
        self.bytes(len)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], UnexpectedEnd> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, UnexpectedEnd> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, UnexpectedEnd> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, UnexpectedEnd> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn varint(&mut self) -> Result<VarInt, UnexpectedEnd> {
        Ok(self.varint_sized()?.0)
    }

    /// Reads a variable-length integer and the length of its encoding.
    pub(crate) fn varint_sized(&mut self) -> Result<(VarInt, usize), UnexpectedEnd> {
        let (value, len) = VarInt::decode(self.peek_rest())?;
        self.pos += len;
        Ok((value, len))
    }
}

/// A writer of fields into a buffer whose capacity the caller has already checked against the
/// encoded length. Writing past the end is a bug in the caller's size computation and panics.
#[derive(Debug)]
pub(crate) struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Writer<'b> {
    pub(crate) fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes written so far.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn put_slice(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    pub(crate) fn put_u8(&mut self, value: u8) {
        self.put_slice(&[value]);
    }

    pub(crate) fn put_u32(&mut self, value: u32) {
        self.put_slice(&value.to_be_bytes());
    }

    pub(crate) fn put_varint(&mut self, value: VarInt) {
        self.pos += value
            .encode(&mut self.buf[self.pos..])
            .expect("the caller checked the capacity");
    }

    pub(crate) fn put_zeros(&mut self, len: usize) {
        self.buf[self.pos..self.pos + len].fill(0);
        self.pos += len;
    }
}

/// Returns the encoded size of a byte count as a variable-length integer.
pub(crate) fn varint_len_of(len: usize) -> usize {
    varint_from_len(len).encoded_size()
}

/// Converts a byte count to a variable-length integer. Slices and buffers are far shorter than
/// 2^62 bytes on every platform Rust supports, so the conversion cannot fail.
pub(crate) fn varint_from_len(len: usize) -> VarInt {
    VarInt::try_from(len).expect("in-memory lengths are below 2^62")
}
