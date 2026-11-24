/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The receive half of [`MmsgBackend`](crate::MmsgBackend): `recvmmsg` into buffers the
//! backend owns, with UDP_GRO, and the metadata of each buffer.

use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Instant;

use mvfstr_proto::Ecn;
use mvfstr_proto::RxMeta;

use crate::cmsg;
use crate::cmsg::CmsgSpace;
use crate::cmsg::Decoder;
use crate::sys;

/// One receive buffer's state after a batch.
#[derive(Clone, Copy)]
struct Entry {
    meta: RxMeta,
    len: usize,
    valid: bool,
}

pub(crate) struct Rx {
    buf: Box<[u8]>,
    size: usize,
    entries: Vec<Entry>,
    received: usize,
    names: Vec<libc::sockaddr_storage>,
    control: Vec<CmsgSpace>,
    iovs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
}

impl Rx {
    /// Creates `batch` receive buffers of `size` bytes each.
    pub(crate) fn new(batch: usize, size: usize) -> Self {
        let placeholder = Entry {
            meta: RxMeta {
                src: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                dst_ip: None,
                ecn: Ecn::NotEct,
                stride: 0,
                rx_time: Instant::now(),
            },
            len: 0,
            valid: false,
        };
        Self {
            buf: vec![0; batch * size].into_boxed_slice(),
            size,
            entries: vec![placeholder; batch],
            received: 0,
            names: vec![sys::empty_sockaddr(); batch],
            control: vec![CmsgSpace::default(); batch],
            iovs: Vec::with_capacity(batch),
            hdrs: Vec::with_capacity(batch),
        }
    }

    /// Receives one batch. Returns how many buffers hold datagrams, possibly 0.
    pub(crate) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.received = 0;
        self.iovs.clear();
        self.hdrs.clear();
        for buf in self.buf.chunks_exact_mut(self.size) {
            self.iovs.push(libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            });
        }
        for (i, (name, control)) in self.names.iter_mut().zip(&mut self.control).enumerate() {
            let mut hdr = sys::empty_mmsghdr();
            hdr.msg_hdr.msg_name = (&raw mut *name).cast();
            hdr.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
            hdr.msg_hdr.msg_iov = &raw mut self.iovs[i];
            hdr.msg_hdr.msg_iovlen = 1;
            hdr.msg_hdr.msg_control = control.0.as_mut_ptr().cast();
            hdr.msg_hdr.msg_controllen = control.0.len() as _;
            self.hdrs.push(hdr);
        }
        let n = loop {
            // SAFETY: every header points at its own name buffer, control buffer and one iovec
            // over its own receive buffer, all owned by `self` and untouched until the call
            // returns.
            match unsafe { sys::recvmmsg(fd, &mut self.hdrs) } {
                Ok(n) => break n,
                Err(e) if absorbed(&e) => {}
                Err(e) => return Err(e),
            }
        };
        let rx_time = Instant::now();
        let mut valid = 0;
        for i in 0..n {
            let hdr = &self.hdrs[i];
            let len = hdr.msg_len as usize;
            let entry = &mut self.entries[i];
            entry.len = len;
            entry.valid = false;
            // A cut-short datagram, or the tail of a GRO run, cannot be parsed; an empty one does
            // not hold a packet and would have a zero stride. Cut-short control data may have lost
            // the GRO segment size, which would turn a run into one bad datagram. Drop all three.
            if len == 0 || hdr.msg_hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                continue;
            }
            let Some(src) = sys::to_socket_addr(&self.names[i], hdr.msg_hdr.msg_namelen) else {
                continue;
            };
            #[allow(clippy::unnecessary_cast, reason = "msg_controllen is u32 on musl")]
            let control_len = hdr.msg_hdr.msg_controllen as usize;
            let control = &self.control[i].0[..control_len.min(cmsg::SPACE)];
            let cmsgs = Cmsgs::parse(control);
            entry.meta = RxMeta {
                src,
                dst_ip: cmsgs.dst_ip,
                ecn: cmsgs.ecn,
                // The GRO segment size, clamped so that one short datagram is its own stride.
                stride: cmsgs.gro.map_or(len, |gro| gro.min(len)) as u16,
                rx_time,
            };
            entry.valid = true;
            valid += 1;
        }
        self.received = n;
        Ok(valid)
    }

    /// Returns the buffers of the last batch that hold datagrams.
    pub(crate) fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])> {
        self.buf
            .chunks_exact_mut(self.size)
            .zip(self.entries.iter())
            .take(self.received)
            .filter(|(_, entry)| entry.valid)
            .map(|(buf, entry)| (&entry.meta, &mut buf[..entry.len]))
    }
}

/// Returns whether a receive error is one the backend retries past: EINTR, or an ICMP error a
/// connected socket reports on the next call, which that call consumes. These are the errors the
/// kernel leaves pending without IP_RECVERR: the fatal unreachable codes, parameter problems
/// (EPROTO), and frag-needed or packet too big (EMSGSIZE) while path MTU discovery is on. An
/// unreachable peer is left to the connection's own timers.
fn absorbed(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EINTR
                | libc::ECONNREFUSED
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::EHOSTDOWN
                | libc::ENOPROTOOPT
                | libc::EACCES
                | libc::ENONET
                | libc::EPROTO
                | libc::EMSGSIZE
        )
    )
}

/// The fields parsed from a received message's control data.
#[derive(Default)]
struct Cmsgs {
    dst_ip: Option<IpAddr>,
    ecn: Ecn,
    gro: Option<usize>,
}

impl Cmsgs {
    fn parse(control: &[u8]) -> Self {
        let mut out = Self::default();
        for (level, ty, data) in Decoder::new(control) {
            match (level, ty) {
                // struct in_pktinfo { int ipi_ifindex; in_addr ipi_spec_dst; in_addr ipi_addr; }:
                // ipi_addr is the header's destination address.
                (libc::IPPROTO_IP, libc::IP_PKTINFO) if data.len() >= 12 => {
                    let addr: [u8; 4] = data[8..12].try_into().unwrap_or_default();
                    out.dst_ip = Some(IpAddr::from(addr));
                }
                // struct in6_pktinfo { in6_addr ipi6_addr; unsigned ipi6_ifindex; }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) if data.len() >= 16 => {
                    let addr: [u8; 16] = data[..16].try_into().unwrap_or_default();
                    out.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(addr)).to_canonical());
                }
                (libc::SOL_UDP, libc::UDP_GRO) if data.len() >= 4 => {
                    let size = i32::from_ne_bytes(data[..4].try_into().unwrap_or_default());
                    out.gro = usize::try_from(size).ok().filter(|&size| size > 0);
                }
                // IP_TOS arrives as one byte, IPV6_TCLASS as an int.
                (libc::IPPROTO_IP, libc::IP_TOS) if !data.is_empty() => {
                    out.ecn = ecn(data[0]);
                }
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) if data.len() >= 4 => {
                    let tclass = i32::from_ne_bytes(data[..4].try_into().unwrap_or_default());
                    out.ecn = ecn(tclass as u8);
                }
                _ => {}
            }
        }
        out
    }
}

/// Returns the ECN codepoint in the low two bits of a TOS byte or traffic class (RFC 3168).
fn ecn(tos: u8) -> Ecn {
    match tos & 0b11 {
        0b01 => Ecn::Ect1,
        0b10 => Ecn::Ect0,
        0b11 => Ecn::Ce,
        _ => Ecn::NotEct,
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::SocketOptions;

    #[test]
    fn a_datagram_whose_control_data_was_cut_short_is_discarded() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let socket = crate::socket::open(local, None, &SocketOptions::default()).unwrap();
        // The backend's own control messages fit its buffer; these, turned on by whoever made
        // the socket, push the total past it, so the kernel cuts the control data short.
        for (level, name) in [
            (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS),
            (libc::IPPROTO_IP, libc::IP_RECVTTL),
            (libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR),
        ] {
            sys::set_int(&socket, level, name, 1).unwrap();
        }
        let to = socket.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind(local).unwrap();
        sender.send_to(&[1; 10], to).unwrap();
        let mut ready = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout only guards against a hang.
        assert_eq!(unsafe { libc::poll(&raw mut ready, 1, 20_000) }, 1);

        let mut rx = Rx::new(1, 2048);
        assert_eq!(rx.recv(socket.as_raw_fd()).unwrap(), 0);
        assert_eq!(rx.buffers().count(), 0);
    }

    #[test]
    fn every_icmp_error_a_connected_socket_can_return_is_absorbed() {
        // What `udp_err` and `__udp6_lib_err` leave pending on a connected socket without
        // IP_RECVERR: the fatal unreachable codes, parameter problems, and frag-needed or packet
        // too big while path MTU discovery is on.
        for errno in [
            libc::ECONNREFUSED,
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::EHOSTDOWN,
            libc::ENOPROTOOPT,
            libc::EACCES,
            libc::ENONET,
            libc::EPROTO,
            libc::EMSGSIZE,
            libc::EINTR,
        ] {
            let error = io::Error::from_raw_os_error(errno);
            assert!(absorbed(&error), "{error}");
        }
        assert!(!absorbed(&io::Error::from_raw_os_error(libc::EBADF)));
    }
}
