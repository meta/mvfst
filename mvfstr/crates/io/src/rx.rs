/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The receive half of [`MmsgBackend`](crate::MmsgBackend) and
//! [`HostBackend`](crate::HostBackend): `recvmmsg` into buffers the backend owns, with UDP_GRO,
//! and the metadata of each buffer.

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

/// The receive buffers, with one `recvmmsg` header per buffer, built once by `new`. Every pointer
/// in the headers and iovecs comes from the base pointer (`as_mut_ptr`) of a Vec that is never
/// resized, not from a reference, so moving `Rx` or borrowing the Vecs later leaves it valid. A
/// `Box` would not do for `buf`: each move retags it as unique and invalidates older pointers.
pub(crate) struct Rx {
    buf: Vec<u8>,
    size: usize,
    entries: Vec<Entry>,
    /// How many headers the last call filled.
    received: usize,
    names: Vec<libc::sockaddr_storage>,
    control: Vec<CmsgSpace>,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the kernel reads it through the headers")
    )]
    iovs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    /// Whether the socket queues errors (IP_RECVERR or IPV6_RECVERR), whose queue `recv` then
    /// drains.
    error_queue: bool,
    /// Errors read from the socket's error queue, one per queued error: the ICMP errors the kernel
    /// queues, and the local error it also queues for a send it refuses with EMSGSIZE, which that
    /// send's report already covers.
    pub(crate) icmp_errors: u64,
    /// The `recvmmsg` calls made, for tests that count them.
    #[cfg(test)]
    pub(crate) calls: usize,
    /// The `MSG_ERRQUEUE` reads made, those that found the error queue empty included, for tests
    /// that count them.
    #[cfg(test)]
    pub(crate) errqueue_reads: usize,
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
        let mut buf = vec![0; batch * size];
        let mut names = vec![sys::empty_sockaddr(); batch];
        let mut control = vec![CmsgSpace::default(); batch];
        let buf_base = buf.as_mut_ptr();
        let mut iovs: Vec<libc::iovec> = (0..batch)
            .map(|i| libc::iovec {
                // SAFETY: `i < batch`, so the offset is inside `buf`, which holds `batch * size`
                // bytes.
                iov_base: unsafe { buf_base.add(i * size) }.cast(),
                iov_len: size,
            })
            .collect();
        let (names_base, control_base, iovs_base) =
            (names.as_mut_ptr(), control.as_mut_ptr(), iovs.as_mut_ptr());
        let hdrs = (0..batch)
            .map(|i| {
                let mut hdr = sys::empty_mmsghdr();
                // SAFETY: `i < batch`, the length of `names`, `control` and `iovs`, so each offset
                // is inside its Vec, and `&raw mut` takes the control bytes without a reference.
                unsafe {
                    hdr.msg_hdr.msg_name = names_base.add(i).cast();
                    hdr.msg_hdr.msg_iov = iovs_base.add(i);
                    hdr.msg_hdr.msg_control = (&raw mut (*control_base.add(i)).0).cast();
                }
                hdr.msg_hdr.msg_iovlen = 1;
                whole_lengths(&mut hdr.msg_hdr);
                hdr
            })
            .collect();
        Self {
            buf,
            size,
            entries: vec![placeholder; batch],
            received: 0,
            names,
            control,
            iovs,
            hdrs,
            error_queue: false,
            icmp_errors: 0,
            #[cfg(test)]
            calls: 0,
            #[cfg(test)]
            errqueue_reads: 0,
        }
    }

    /// Makes `recv` drain the socket's error queue, for a socket that queues errors. Only for one:
    /// on a socket without an error queue, such as a Unix datagram socket, a read of the error
    /// queue takes an ordinary datagram.
    pub(crate) fn with_error_queue(mut self, queues_errors: bool) -> Self {
        self.error_queue = queues_errors;
        self
    }

    /// Receives one batch. Returns how many buffers hold datagrams, possibly 0.
    ///
    /// On a socket that queues errors, an ICMP error from `recvmmsg` or EAGAIN first drains the
    /// error queue, since a queued error keeps the socket reported readable until it is read. An
    /// ICMP error both sets the socket's pending error, which the next send or receive returns
    /// once, and queues it; EAGAIN is how a queued error shows once a send or an earlier receive
    /// took the pending error. A batch of datagrams costs no read of the error queue.
    pub(crate) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.rearm();
        let mut queue_drained = false;
        let n = loop {
            #[cfg(test)]
            {
                self.calls += 1;
            }
            // SAFETY: every header points at its own name buffer, control buffer and one iovec
            // over its own receive buffer, with their whole lengths. All of them are owned by
            // `self`, and the pointers are valid as the type's doc says. Nothing else touches
            // them until the call returns.
            match unsafe { sys::recvmmsg(fd, &mut self.hdrs) } {
                Ok(n) => break n,
                Err(e) if icmp_error(&e) => {
                    self.drain_errors(fd);
                    queue_drained = true;
                }
                Err(e) if absorbed(&e) => {}
                Err(e) => {
                    // A new ICMP error after the drain would have set the pending error, which
                    // `recvmmsg` returns before EAGAIN, so the queue is still empty.
                    if e.kind() == io::ErrorKind::WouldBlock && !queue_drained {
                        self.drain_errors(fd);
                    }
                    return Err(e);
                }
            }
        };
        Ok(self.parse(n))
    }

    /// Reads every entry of the socket's error queue, counting each, until the read that finds it
    /// empty. Does nothing on a socket that does not queue errors.
    fn drain_errors(&mut self, fd: RawFd) {
        if !self.error_queue {
            return;
        }
        loop {
            #[cfg(test)]
            {
                self.errqueue_reads += 1;
            }
            if sys::recv_error(fd).is_err() {
                return;
            }
            self.icmp_errors += 1;
        }
    }

    /// Gives the headers the last call filled their whole name and control space again. The
    /// headers after them were not shortened.
    fn rearm(&mut self) {
        for hdr in &mut self.hdrs[..self.received] {
            whole_lengths(&mut hdr.msg_hdr);
        }
        self.received = 0;
    }

    /// Reads the metadata of the `n` headers a call filled. Returns how many buffers hold
    /// datagrams.
    fn parse(&mut self, n: usize) -> usize {
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
        valid
    }

    /// Returns whether the last call filled fewer headers than there are: the socket ran out of
    /// datagrams, or an ICMP error arrived during the call, which `recvmmsg` keeps for the next
    /// call. That error woke the socket's pollers after the readiness that led to the call, so on
    /// every host they still report the datagrams left behind.
    pub(crate) fn drained(&self) -> bool {
        self.received < self.hdrs.len()
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

/// Gives a header the whole name and control space of its buffers. The kernel shortens both
/// lengths to what it wrote in every header it fills.
fn whole_lengths(hdr: &mut libc::msghdr) {
    hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_controllen = cmsg::SPACE as _;
}

/// Returns whether a receive error is one the backend retries past: EINTR, or an ICMP error the
/// call consumed (see [`icmp_error`]).
fn absorbed(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EINTR) || icmp_error(error)
}

/// Returns whether a receive error is an ICMP error the socket reports on the next call, which that
/// call consumes. Without IP_RECVERR, only a connected socket reports one, and only for the fatal
/// unreachable codes, parameter problems (EPROTO), and frag-needed or packet too big (EMSGSIZE)
/// while path MTU discovery is on. With IP_RECVERR or IPV6_RECVERR, every socket reports every ICMP
/// error, which adds a failed source route (EOPNOTSUPP) and the soft unreachable codes and time
/// exceeded, whose errors are among those above. An unreachable peer is left to the connection's
/// own timers.
fn icmp_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ECONNREFUSED
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::EHOSTDOWN
                | libc::ENOPROTOOPT
                | libc::EACCES
                | libc::ENONET
                | libc::EPROTO
                | libc::EMSGSIZE
                | libc::EOPNOTSUPP
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
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::ptr;
    use std::slice;

    use socket2::Domain;
    use socket2::Protocol;
    use socket2::SockAddr;
    use socket2::Type;

    use super::*;
    use crate::SocketOptions;
    use crate::cmsg::Encoder;
    use crate::socket;

    /// Binds a plain UDP socket to `local` whose sends carry `tos` (DSCP and ECN).
    fn sender(local: SocketAddr, tos: u32) -> UdpSocket {
        let socket =
            socket2::Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))
                .unwrap();
        if local.is_ipv4() {
            socket.set_tos_v4(tos).unwrap();
        } else {
            socket.set_tclass_v6(tos).unwrap();
        }
        socket.bind(&local.into()).unwrap();
        socket.into()
    }

    /// Sends `payload` from `from` to `to` as one GSO send of `segment`-byte datagrams.
    fn gso_send(from: &UdpSocket, to: SocketAddr, payload: &[u8], segment: u16) {
        let addr = SockAddr::from(to);
        let mut control = CmsgSpace::default();
        let mut encoder = Encoder::new(&mut control.0);
        assert!(encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, &segment.to_ne_bytes()));
        let control_len = encoder.len();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut msg = sys::empty_mmsghdr().msg_hdr;
        msg.msg_name = addr.as_ptr().cast_mut().cast();
        msg.msg_namelen = addr.len();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control_len as _;
        // SAFETY: the header points at `addr`, `iov` (over `payload`) and `control`, all live
        // until `sendmsg` returns.
        let sent = unsafe { libc::sendmsg(from.as_raw_fd(), &raw const msg, 0) };
        assert_eq!(
            sent,
            payload.len() as isize,
            "{}",
            io::Error::last_os_error()
        );
    }

    /// Returns `len` bytes that differ from those of other `seed`s.
    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
    }

    /// What a test compares of one received buffer: its metadata without the receive time, and
    /// its bytes.
    type Got = (SocketAddr, Option<IpAddr>, Ecn, u16, Vec<u8>);

    /// Waits until `fd` is readable, then receives one batch through `rx` and copies it out.
    fn batch(rx: &mut Rx, fd: RawFd) -> Vec<Got> {
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout only guards against a hang.
        assert_eq!(unsafe { libc::poll(&raw mut ready, 1, 20_000) }, 1);
        let valid = rx.recv(fd).unwrap();
        let got: Vec<Got> = rx
            .buffers()
            .map(|(meta, data)| (meta.src, meta.dst_ip, meta.ecn, meta.stride, data.to_vec()))
            .collect();
        assert_eq!(got.len(), valid);
        got
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn headers_built_once_by_new_give_every_batch_its_own_metadata() {
        let loop4 = IpAddr::from(Ipv4Addr::LOCALHOST);
        let loop6 = IpAddr::from(Ipv6Addr::LOCALHOST);
        let s4 = sender(SocketAddr::new(loop4, 0), 0b10);
        let s6 = sender(SocketAddr::new(loop6, 0), 0b01);
        let (from4, from6) = (s4.local_addr().unwrap(), s6.local_addr().unwrap());
        // Without control messages, then with them: a plain socket, a prepared dual-stack socket
        // with GRO, and prepared IPv4 sockets without and with GRO.
        let plain = UdpSocket::bind((loop4, 0)).unwrap();
        plain.set_nonblocking(true).unwrap();
        let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        let dual = socket::open(any6, None, &SocketOptions::default()).unwrap();
        let no_gro = SocketOptions {
            gro: false,
            ..SocketOptions::default()
        };
        let v4_no_gro = socket::open(SocketAddr::new(loop4, 0), None, &no_gro).unwrap();
        let v4 = socket::open(SocketAddr::new(loop4, 0), None, &SocketOptions::default()).unwrap();
        let port =
            |socket: &socket2::Socket| socket.local_addr().unwrap().as_socket().unwrap().port();
        let to_plain = plain.local_addr().unwrap();
        let (dual4, dual6) = (
            SocketAddr::new(loop4, port(&dual)),
            SocketAddr::new(loop6, port(&dual)),
        );
        let to_v4_no_gro = SocketAddr::new(loop4, port(&v4_no_gro));
        let to_v4 = SocketAddr::new(loop4, port(&v4));

        // One receiver with two slots serves every socket in turn. Each kernel call shortens
        // the name and control lengths of the slots it fills to what it wrote, so a slot reused
        // without restoring them cuts the next address short or loses its control messages.
        let mut rx = Rx::new(2, 2048);

        // Both slots: an IPv4 name and no control data.
        s4.send_to(&bytes(1, 10), to_plain).unwrap();
        s4.send_to(&bytes(2, 20), to_plain).unwrap();
        assert_eq!(
            batch(&mut rx, plain.as_raw_fd()),
            vec![
                (from4, None, Ecn::NotEct, 10, bytes(1, 10)),
                (from4, None, Ecn::NotEct, 20, bytes(2, 20)),
            ],
            "a socket without control messages"
        );

        // Slot 0 needs the whole IPv6 name and control space again.
        s4.send_to(&bytes(3, 30), dual4).unwrap();
        assert_eq!(
            batch(&mut rx, dual.as_raw_fd()),
            vec![(from4, Some(loop4), Ecn::Ect0, 30, bytes(3, 30))],
            "an IPv4-mapped source after IPv4 names and no control data"
        );

        // Slot 0 takes a datagram longer than its buffer; slot 1, last used for an IPv4 name
        // without control data, an IPv4-mapped source.
        s6.send_to(&bytes(4, 3000), dual6).unwrap();
        s4.send_to(&bytes(5, 40), dual4).unwrap();
        assert_eq!(
            batch(&mut rx, dual.as_raw_fd()),
            vec![(from4, Some(loop4), Ecn::Ect0, 40, bytes(5, 40))],
            "the cut-short datagram is discarded, and the one after it is whole"
        );

        // The discarded datagram's slot holds a GRO run, which carries one more control message.
        gso_send(&s6, dual6, &bytes(6, 600), 200);
        assert_eq!(
            batch(&mut rx, dual.as_raw_fd()),
            vec![(from6, Some(loop6), Ecn::Ect1, 200, bytes(6, 600))],
            "a GRO run in the slot of a discarded datagram"
        );

        // Slot 1, last filled with a single datagram, holds a GRO run.
        s6.send_to(&bytes(7, 50), dual6).unwrap();
        gso_send(&s4, dual4, &bytes(8, 700), 300);
        assert_eq!(
            batch(&mut rx, dual.as_raw_fd()),
            vec![
                (from6, Some(loop6), Ecn::Ect1, 50, bytes(7, 50)),
                (from4, Some(loop4), Ecn::Ect0, 300, bytes(8, 700)),
            ],
            "a GRO run in a slot that the batch before did not use"
        );

        // A socket without GRO receives a GSO send as single datagrams, in both slots.
        let run = bytes(9, 200);
        gso_send(&s4, to_v4_no_gro, &run, 100);
        assert_eq!(
            batch(&mut rx, v4_no_gro.as_raw_fd()),
            vec![
                (from4, Some(loop4), Ecn::Ect0, 100, run[..100].to_vec()),
                (from4, Some(loop4), Ecn::Ect0, 100, run[100..].to_vec()),
            ],
            "IPv4 names and control data without GRO"
        );
        gso_send(&s4, to_v4, &bytes(10, 600), 200);
        assert_eq!(
            batch(&mut rx, v4.as_raw_fd()),
            vec![(from4, Some(loop4), Ecn::Ect0, 200, bytes(10, 600))],
            "a GRO run after single datagrams"
        );

        // The headers are built by `new`, not by each call: every header points at its own name,
        // control space and iovec with their whole lengths, and every iovec at its own buffer.
        let fresh = Rx::new(2, 2048);
        assert_eq!(fresh.hdrs.len(), 2, "new builds every header");
        for (i, hdr) in fresh.hdrs.iter().enumerate() {
            let msg = &hdr.msg_hdr;
            assert_eq!(msg.msg_name, (&raw const fresh.names[i]).cast_mut().cast());
            assert_eq!(msg.msg_namelen, size_of::<libc::sockaddr_storage>() as _);
            assert_eq!(msg.msg_iov, (&raw const fresh.iovs[i]).cast_mut());
            assert_eq!(msg.msg_iovlen, 1);
            assert_eq!(
                msg.msg_control,
                fresh.control[i].0.as_ptr().cast_mut().cast()
            );
            assert_eq!(msg.msg_controllen, cmsg::SPACE as _);
            let buf = fresh.buf[i * 2048..].as_ptr();
            assert_eq!(fresh.iovs[i].iov_base, buf.cast_mut().cast());
            assert_eq!(fresh.iovs[i].iov_len, 2048);
        }
    }

    /// Moves `rx` through a function, as `ready` and the backends' constructors do.
    fn moved(rx: Rx) -> Rx {
        rx
    }

    /// Writes one datagram into header `i` as `recvmmsg` does, through the pointers the header
    /// holds: the source address into its name, the traffic class into its control space and
    /// `data` into its buffer, then the lengths and flags the kernel writes back.
    fn kernel_fill(rx: &mut Rx, i: usize, src: SocketAddr, tos: u8, data: &[u8]) {
        let name = SockAddr::from(src);
        let mut control = CmsgSpace::default();
        let mut encoder = Encoder::new(&mut control.0);
        let pushed = if src.is_ipv4() {
            encoder.push(libc::IPPROTO_IP, libc::IP_TOS, &[tos])
        } else {
            let tclass = i32::from(tos).to_ne_bytes();
            encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tclass)
        };
        assert!(pushed);
        let control_len = encoder.len();
        let hdr = &mut rx.hdrs[i];
        let msg = &mut hdr.msg_hdr;
        assert_eq!(msg.msg_namelen, size_of::<libc::sockaddr_storage>() as _);
        assert_eq!(msg.msg_controllen, cmsg::SPACE as _);
        // SAFETY: `msg_iov` points at the header's one iovec.
        let iov = unsafe { *msg.msg_iov };
        assert!(data.len() <= iov.iov_len);
        // SAFETY: the header's name, control space and buffer hold the whole lengths asserted
        // above, which bound the name, the control data and `data`, and none of them overlaps
        // the locals copied from.
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                msg.msg_name.cast(),
                name.len() as usize,
            );
            ptr::copy_nonoverlapping(control.0.as_ptr(), msg.msg_control.cast(), control_len);
            ptr::copy_nonoverlapping(data.as_ptr(), iov.iov_base.cast(), data.len());
        }
        msg.msg_namelen = name.len();
        msg.msg_controllen = control_len as _;
        msg.msg_flags = 0;
        hdr.msg_len = data.len() as u32;
    }

    #[test]
    fn the_headers_reach_their_storage_after_rx_moves_and_its_buffers_are_written() {
        // Without a socket, so that it also runs under Miri, which checks that the pointers the
        // headers hold may still write their storage after `Rx` has moved and the driver has
        // written the buffers in place through `buffers()`.
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 4433));
        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
        let mut rx = moved(Rx::new(2, 64));
        for round in 0..3 {
            rx.rearm();
            kernel_fill(&mut rx, 0, v4, 0b10, &bytes(round, 10));
            kernel_fill(&mut rx, 1, v6, 0b01, &bytes(round, 20));
            assert_eq!(rx.parse(2), 2);
            let got: Vec<_> = rx
                .buffers()
                .map(|(meta, data)| {
                    let got = (meta.src, meta.ecn, meta.stride, data.to_vec());
                    data.fill(0xff);
                    got
                })
                .collect();
            assert_eq!(
                got,
                vec![
                    (v4, Ecn::Ect0, 10, bytes(round, 10)),
                    (v6, Ecn::Ect1, 20, bytes(round, 20)),
                ],
                "round {round}"
            );
            rx = moved(rx);
        }
    }

    /// Reads every header of `rx` and, through its pointers, the whole name, control space, iovec
    /// and buffer it reaches. Checks that every length is whole, that each header reaches its own
    /// buffer, and that it holds the source and ECN codepoint of the last datagram written into it,
    /// as `last` records.
    fn read_every_header(rx: &Rx, last: &[Option<(SocketAddr, Ecn)>], at: &str) {
        for (i, hdr) in rx.hdrs.iter().enumerate() {
            let msg = &hdr.msg_hdr;
            assert_eq!(
                (msg.msg_namelen, msg.msg_controllen, msg.msg_iovlen),
                (
                    size_of::<libc::sockaddr_storage>() as _,
                    cmsg::SPACE as _,
                    1
                ),
                "{at}, header {i}"
            );
            // SAFETY: the name and control pointers reach a whole, aligned `sockaddr_storage` and
            // `CmsgSpace`, and the iovec pointer one iovec, all owned by `rx`, which outlives the
            // reads.
            let (name, control, iov) = unsafe {
                (
                    msg.msg_name.cast::<libc::sockaddr_storage>().read(),
                    msg.msg_control.cast::<CmsgSpace>().read(),
                    msg.msg_iov.read(),
                )
            };
            assert_eq!(
                iov.iov_len, rx.size,
                "{at}, header {i}: iov_len stays whole"
            );
            // SAFETY: the iovec reaches its whole buffer in `rx.buf`, which outlives the slice.
            let data = unsafe { slice::from_raw_parts(iov.iov_base.cast::<u8>(), iov.iov_len) };
            assert_eq!(data, &rx.buf[i * rx.size..][..rx.size], "{at}, header {i}");
            let (src, ecn) = last[i].unzip();
            assert_eq!(
                (
                    sys::to_socket_addr(&name, msg.msg_namelen),
                    Cmsgs::parse(&control.0).ecn
                ),
                (src, ecn.unwrap_or(Ecn::NotEct)),
                "{at}, header {i}"
            );
        }
    }

    #[test]
    fn every_header_reaches_its_storage_with_whole_lengths_after_short_and_full_batches() {
        // Without a socket, so that it also runs under Miri, which checks each pointer the headers
        // hold whenever the test writes or reads through it. The kernel shortens the name and
        // control lengths of the headers that each batch fills; `rearm` must restore them, and
        // every header, filled or not, must still reach its own storage after `Rx` has moved.
        const BATCH: usize = 4;
        let v4 = (
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 4433)),
            0b10,
            Ecn::Ect0,
        );
        let v6 = (
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443)),
            0b01,
            Ecn::Ect1,
        );
        // The source, traffic class and ECN codepoint of each datagram one call fills.
        let batches: [&[(SocketAddr, u8, Ecn)]; 4] =
            [&[v4, v6], &[v6, v4, v6, v4], &[v6], &[v4, v4, v6, v6]];
        let mut rx = moved(Rx::new(BATCH, 64));
        let mut last = [None; BATCH];
        read_every_header(&rx, &last, "before the first call");
        for (round, batch) in batches.iter().enumerate() {
            rx.rearm();
            read_every_header(&rx, &last, &format!("round {round}, after rearm"));
            let seed = round as u8;
            for (i, &(src, tos, ecn)) in batch.iter().enumerate() {
                kernel_fill(&mut rx, i, src, tos, &bytes(seed, 10 + i));
                last[i] = Some((src, ecn));
            }
            assert_eq!(rx.parse(batch.len()), batch.len(), "round {round}");
            assert_eq!(rx.drained(), batch.len() < BATCH, "round {round}");
            let whole = (size_of::<libc::sockaddr_storage>() as _, cmsg::SPACE as _);
            for (i, hdr) in rx.hdrs.iter().enumerate() {
                let lengths = (hdr.msg_hdr.msg_namelen, hdr.msg_hdr.msg_controllen);
                assert_eq!(
                    lengths != whole,
                    i < batch.len(),
                    "round {round}, header {i}: the kernel shortens only the headers it fills"
                );
            }
            let got: Vec<_> = rx
                .buffers()
                .map(|(meta, data)| {
                    let got = (meta.src, meta.ecn, data.to_vec());
                    data.fill(0xff);
                    got
                })
                .collect();
            let want: Vec<_> = batch
                .iter()
                .enumerate()
                .map(|(i, &(src, _, ecn))| (src, ecn, bytes(seed, 10 + i)))
                .collect();
            assert_eq!(got, want, "round {round}");
            rx = moved(rx);
        }
        rx.rearm();
        read_every_header(&rx, &last, "after the last rearm");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
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

    #[test]
    fn every_icmp_error_a_socket_with_ip_recverr_can_return_is_absorbed() {
        // With IP_RECVERR or IPV6_RECVERR, `__udp4_lib_err` and `__udp6_lib_err` leave every ICMP
        // error pending, on unconnected sockets and soft errors included: the `icmp_err_convert`
        // and `icmpv6_err_convert` codes, time exceeded (EHOSTUNREACH) and parameter problems.
        for errno in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENOPROTOOPT,
            libc::ECONNREFUSED,
            libc::EMSGSIZE,
            libc::EOPNOTSUPP,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EACCES,
            libc::EPROTO,
        ] {
            let error = io::Error::from_raw_os_error(errno);
            assert!(absorbed(&error), "{error}");
        }
    }
}
