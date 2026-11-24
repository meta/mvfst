/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Control messages for `sendmsg` and `recvmsg` (cmsg(3)), encoded and parsed over byte
//! buffers.

use std::mem::size_of;

use libc::c_int;

/// The room for one message's control data: enough for UDP_SEGMENT or UDP_GRO, a TOS or traffic
/// class, IPV6_PKTINFO and SCM_TXTIME, 112 bytes together on 64-bit, with slack.
pub(crate) const SPACE: usize = 128;

/// Control data storage for one message, aligned for `cmsghdr`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct CmsgSpace(pub(crate) [u8; SPACE]);

impl Default for CmsgSpace {
    fn default() -> Self {
        Self([0; SPACE])
    }
}

/// Appends control messages to a buffer.
pub(crate) struct Encoder<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Encoder<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Appends one control message. Returns false without writing when it does not fit.
    pub(crate) fn push(&mut self, level: c_int, ty: c_int, data: &[u8]) -> bool {
        let space = space(data.len());
        if self.buf.len() - self.len < space {
            return false;
        }
        let out = &mut self.buf[self.len..self.len + space];
        out.fill(0);
        // SAFETY: `cmsghdr` is a C struct of integers, for which all zeroes is valid.
        let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
        hdr.cmsg_len = (align(HDR) + data.len()) as _;
        hdr.cmsg_level = level;
        hdr.cmsg_type = ty;
        // SAFETY: `out` holds at least `HDR` bytes, since `space` does, and `write_unaligned`
        // accepts any alignment.
        unsafe {
            out.as_mut_ptr()
                .cast::<libc::cmsghdr>()
                .write_unaligned(hdr)
        };
        out[align(HDR)..align(HDR) + data.len()].copy_from_slice(data);
        self.len += space;
        true
    }

    /// Returns the number of bytes written, for `msg_controllen`.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// An iterator over the control messages in a received control buffer, as `(level, type, data)`.
/// It stops at the first malformed header.
pub(crate) struct Decoder<'a> {
    buf: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = (c_int, c_int, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < HDR {
            return None;
        }
        // SAFETY: `buf` holds at least `HDR` bytes, `read_unaligned` accepts any alignment, and
        // every bit pattern is a valid `cmsghdr`.
        let hdr = unsafe { self.buf.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        #[allow(clippy::unnecessary_cast, reason = "cmsg_len is u32 on musl")]
        let len = hdr.cmsg_len as usize;
        if len < align(HDR) || len > self.buf.len() {
            self.buf = &[];
            return None;
        }
        let data = &self.buf[align(HDR)..len];
        self.buf = &self.buf[align(len).min(self.buf.len())..];
        Some((hdr.cmsg_level, hdr.cmsg_type, data))
    }
}

/// The header size; data starts at `align(HDR)`.
const HDR: usize = size_of::<libc::cmsghdr>();

/// Rounds `len` up to the alignment of `size_t`, as `CMSG_ALIGN` does.
const fn align(len: usize) -> usize {
    let a = size_of::<usize>();
    (len + a - 1) & !(a - 1)
}

/// Returns the bytes one control message with `len` data bytes takes, as `CMSG_SPACE` does.
pub(crate) const fn space(len: usize) -> usize {
    align(HDR) + align(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn libc_space(len: usize) -> usize {
        // SAFETY: CMSG_SPACE is arithmetic on its argument.
        unsafe { libc::CMSG_SPACE(len as libc::c_uint) as usize }
    }

    fn libc_len(len: usize) -> usize {
        // SAFETY: CMSG_LEN is arithmetic on its argument.
        unsafe { libc::CMSG_LEN(len as libc::c_uint) as usize }
    }

    #[test]
    fn encodes_with_the_layout_of_the_libc_macros() {
        let mut space = CmsgSpace::default();
        let mut enc = Encoder::new(&mut space.0);
        assert!(enc.push(libc::SOL_UDP, libc::UDP_SEGMENT, &1200u16.to_ne_bytes()));
        assert!(enc.push(libc::IPPROTO_IP, libc::IP_TOS, &2i32.to_ne_bytes()));
        let len = enc.len();
        assert_eq!(len, libc_space(2) + libc_space(4));

        let mut first = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: space.0.as_mut_ptr().cast(),
            msg_controllen: len,
            msg_flags: 0,
        };
        // SAFETY: the header points at `len` initialized control bytes in `space`, which
        // outlives these reads.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&raw mut first);
            assert!(!c.is_null());
            assert_eq!((*c).cmsg_level, libc::SOL_UDP);
            assert_eq!((*c).cmsg_type, libc::UDP_SEGMENT);
            assert_eq!((*c).cmsg_len as usize, libc_len(2));
            assert_eq!(libc::CMSG_DATA(c).cast::<u16>().read_unaligned(), 1200);
            let c = libc::CMSG_NXTHDR(&raw mut first, c);
            assert!(!c.is_null());
            assert_eq!((*c).cmsg_level, libc::IPPROTO_IP);
            assert_eq!((*c).cmsg_type, libc::IP_TOS);
            assert_eq!((*c).cmsg_len as usize, libc_len(4));
            assert_eq!(libc::CMSG_DATA(c).cast::<i32>().read_unaligned(), 2);
            assert!(libc::CMSG_NXTHDR(&raw mut first, c).is_null());
        }
    }

    #[test]
    fn decodes_messages_in_order() {
        let mut space = CmsgSpace::default();
        let mut enc = Encoder::new(&mut space.0);
        assert!(enc.push(libc::SOL_UDP, libc::UDP_GRO, &1452i32.to_ne_bytes()));
        assert!(enc.push(libc::IPPROTO_IP, libc::IP_TOS, &[3]));
        assert!(enc.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &[7; 20]));
        let len = enc.len();
        let got: Vec<_> = Decoder::new(&space.0[..len])
            .map(|(level, ty, data)| (level, ty, data.to_vec()))
            .collect();
        assert_eq!(
            got,
            vec![
                (libc::SOL_UDP, libc::UDP_GRO, 1452i32.to_ne_bytes().to_vec()),
                (libc::IPPROTO_IP, libc::IP_TOS, vec![3]),
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, vec![7; 20]),
            ]
        );
    }

    #[test]
    fn stops_at_a_malformed_header_without_panicking() {
        let mut buf = CmsgSpace::default();
        let mut enc = Encoder::new(&mut buf.0);
        assert!(enc.push(libc::SOL_UDP, libc::UDP_GRO, &1200i32.to_ne_bytes()));
        assert!(enc.push(libc::IPPROTO_IP, libc::IP_TOS, &[2]));
        let len = enc.len();
        let first = space(4);

        // A length running past the buffer ends the walk after the good message.
        let mut long = buf;
        long.0[first..first + size_of::<usize>()].copy_from_slice(&(SPACE * 2).to_ne_bytes());
        assert_eq!(Decoder::new(&long.0[..len]).count(), 1);

        // A length shorter than a header ends it too.
        let mut short = buf;
        short.0[first..first + size_of::<usize>()].copy_from_slice(&3usize.to_ne_bytes());
        assert_eq!(Decoder::new(&short.0[..len]).count(), 1);

        // So does a buffer cut inside the second message.
        assert_eq!(Decoder::new(&buf.0[..first + HDR - 1]).count(), 1);
        assert_eq!(Decoder::new(&buf.0[..first + HDR]).count(), 1);
    }
}
