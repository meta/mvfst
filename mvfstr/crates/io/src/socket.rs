/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! UDP socket setup and capability probing.
//!
//! [`open`] creates a non-blocking UDP socket that never fragments, with the receive control
//! messages the backend parses (destination address, TOS or traffic class, GRO segment size),
//! binds it, and connects it for a client. [`probe`] reads back what the socket can do into a
//! [`TxCaps`], once. [`steer_by_connection_id`] makes the kernel deliver each datagram for a
//! group of server sockets to the worker its connection ID names.

use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use libc::c_int;
use mvfstr_proto::ClockEpoch;
use mvfstr_proto::Tick;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;

use crate::ReleaseSupport;
use crate::TxCaps;
use crate::cmsg::CmsgSpace;
use crate::cmsg::Encoder;
use crate::sys;

/// Socket settings for [`open`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketOptions {
    /// Sets SO_REUSEPORT before binding, so each worker binds its own socket to the server
    /// address and the kernel spreads flows across them. Default on.
    pub reuse_port: bool,
    /// Lets a socket bound to an IPv6 address also carry IPv4 (IPV6_V6ONLY=0). Ignored for IPv4
    /// addresses. Default on.
    pub dual_stack: bool,
    /// SO_RCVBUF in bytes; `None` leaves the kernel default. Default `None`, as in mvfst's tperf.
    pub recv_buffer: Option<usize>,
    /// SO_SNDBUF in bytes; `None` leaves the kernel default. Default `None`, as for `recv_buffer`.
    pub send_buffer: Option<usize>,
    /// Turns on UDP_GRO, so the kernel may hand over runs of datagrams in one buffer. Default on.
    pub gro: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_port: true,
            dual_stack: true,
            recv_buffer: None,
            send_buffer: None,
            gro: true,
        }
    }
}

/// Opens a non-blocking UDP socket bound to `local`, connected to `remote` when given.
pub fn open(
    local: SocketAddr,
    remote: Option<SocketAddr>,
    options: &SocketOptions,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    if local.is_ipv6() {
        // Set either way, so that the result does not depend on the net.ipv6.bindv6only sysctl.
        socket.set_only_v6(!options.dual_stack)?;
    }
    if options.reuse_port {
        socket.set_reuse_port(true)?;
    }
    if let Some(bytes) = options.recv_buffer {
        socket.set_recv_buffer_size(bytes)?;
    }
    if let Some(bytes) = options.send_buffer {
        socket.set_send_buffer_size(bytes)?;
    }
    // Before binding, so that every datagram arrives with its control messages.
    prepare(&socket, options.gro);
    socket.bind(&local.into())?;
    if let Some(remote) = remote {
        socket.connect(&remote.into())?;
    }
    Ok(socket)
}

/// Steers every datagram for the SO_REUSEPORT group of `socket` to the socket of the worker its
/// destination connection ID names: a classic BPF program (SO_ATTACH_REUSEPORT_CBPF, which does
/// not need privileges) picks the socket at index `b % workers` of the group, where `b` is the
/// ID's first byte, the byte in which an endpoint that is one of `workers` names its worker. A
/// datagram whose ID the program cannot read, or that names an index past the group's last
/// socket, goes to the socket the kernel's hash picks. The program replaces any the group carried.
///
/// The kernel numbers a group's sockets in the order they bound and, when one leaves, moves the
/// last socket into its index. So the caller binds worker `i`'s socket `i`-th into a group that
/// was empty before, and keeps every socket in the group until all workers have ended. A socket
/// of the same user that already held the address with SO_REUSEPORT would take index 0 and move
/// every worker up one. `workers` must be at least 1, since the kernel refuses a program that
/// divides by zero. Linux 4.5 and later.
pub fn steer_by_connection_id(socket: &Socket, workers: u16) -> io::Result<()> {
    sys::attach_reuseport_cbpf(socket, &steering_program(workers))
}

/// Builds the classic BPF program of [`steer_by_connection_id`]. The kernel runs it on the UDP
/// payload and takes its result as the index of a socket in the group; an index past the group's
/// last socket makes it pick by its hash instead.
fn steering_program(workers: u16) -> [libc::sock_filter; 16] {
    const SHORT: u8 = 12;
    const UNREADABLE: u8 = 15;
    // A jump from the instruction at `at` to the one at `to` skips those in between.
    let skip = |at: u8, to: u8| to - at - 1;
    let workers = u32::from(workers);
    [
        // 0: X = the datagram's length. A load past its end would end the program with 0, so
        // every load is checked first.
        stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_LEN, 0),
        stmt(libc::BPF_MISC | libc::BPF_TAX, 0),
        jump(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            2,
            0,
            skip(2, UNREADABLE),
        ),
        // 3: A = the first byte; a short header goes to SHORT.
        stmt(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0),
        jump(
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            0x80,
            0,
            skip(4, SHORT),
        ),
        // 5: A long header holds its destination connection ID's length at offset 5 and the ID
        // from offset 6, in every QUIC version (RFC 8999).
        stmt(libc::BPF_MISC | libc::BPF_TXA, 0),
        jump(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            7,
            0,
            skip(6, UNREADABLE),
        ),
        stmt(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 5),
        jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            skip(8, UNREADABLE),
            0,
        ),
        stmt(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 6),
        stmt(libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K, workers),
        stmt(libc::BPF_RET | libc::BPF_A, 0),
        // 12, SHORT: a short header's destination connection ID starts at offset 1.
        stmt(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 1),
        stmt(libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K, workers),
        stmt(libc::BPF_RET | libc::BPF_A, 0),
        // 15, UNREADABLE: u32::MAX is past every socket index, so the kernel's hash picks.
        stmt(libc::BPF_RET | libc::BPF_K, u32::MAX),
    ]
}

/// Builds a classic BPF instruction that does not jump.
fn stmt(code: u32, k: u32) -> libc::sock_filter {
    jump(code, k, 0, 0)
}

/// Builds a classic BPF instruction that skips `jt` instructions if its test holds and `jf` if not.
fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

/// Readies a socket for the backend with each setting the socket supports: Don't Fragment, a TOS
/// and traffic class of 0, and the receive control messages the backend parses. [`probe`] reports
/// which of the control messages took effect.
pub(crate) fn prepare(socket: &Socket, gro: bool) {
    // Failures are not errors. A socket that refuses a control message lacks that capability, and
    // `probe` reports it; the other settings are best effort.
    let set = |level, name, value| {
        let _ = sys::set_int(socket, level, name, value);
    };
    let on = |level, name| set(level, name, 1);
    // RFC 9000 forbids IP fragmentation of QUIC datagrams and requires DF on IPv4. PROBE sets DF
    // without limiting sends to a cached path MTU, which one ICMP message can lower, as mvfst's
    // client sockets do. The IPv4 options also cover IPv4 traffic on a dual-stack socket.
    set(
        libc::IPPROTO_IP,
        libc::IP_MTU_DISCOVER,
        libc::IP_PMTUDISC_PROBE,
    );
    // A run with TOS 0 is sent without a TOS control message and takes the socket's own value,
    // which a socket from elsewhere may have set.
    set(libc::IPPROTO_IP, libc::IP_TOS, 0);
    if is_ipv6(socket) {
        set(
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        );
        set(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0);
        on(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
        on(libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS);
        // IPv4 datagrams on a dual-stack socket carry IPV6_PKTINFO with a mapped address, but
        // their TOS byte only with IP_RECVTOS.
        on(libc::IPPROTO_IP, libc::IP_RECVTOS);
    } else {
        on(libc::IPPROTO_IP, libc::IP_PKTINFO);
        on(libc::IPPROTO_IP, libc::IP_RECVTOS);
    }
    if gro {
        on(libc::SOL_UDP, libc::UDP_GRO);
    }
}

/// Probes what `socket` can do. `max_datagram` is the backend's slot size.
pub fn probe(socket: &Socket, max_datagram: u16) -> TxCaps {
    let flag = |level, name| sys::get_int(socket, level, name).is_ok_and(|v| v != 0);
    // Reading UDP_SEGMENT succeeds where the kernel supports UDP GSO (Linux 4.18).
    let gso = sys::get_int(socket, libc::SOL_UDP, libc::UDP_SEGMENT).is_ok();
    let (ecn, pktinfo) = if is_ipv6(socket) {
        let v6only = flag(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY);
        (
            flag(libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
                && (v6only || flag(libc::IPPROTO_IP, libc::IP_RECVTOS)),
            flag(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO),
        )
    } else {
        (
            flag(libc::IPPROTO_IP, libc::IP_RECVTOS),
            flag(libc::IPPROTO_IP, libc::IP_PKTINFO),
        )
    };
    TxCaps {
        max_segments: if gso { kernel_max_segments() } else { 1 },
        max_datagram,
        gro: flag(libc::SOL_UDP, libc::UDP_GRO),
        ecn,
        pktinfo,
        release: ReleaseSupport::None,
        // An unreadable buffer size is reported as 0, as if the socket could not buffer anything.
        send_buffer: socket.send_buffer_size().unwrap_or(0),
    }
}

/// Turns on kernel release for `socket`: SO_TXTIME, with every flag clear, on CLOCK_MONOTONIC, the
/// clock fq reads stamps in. Returns kernel release support with `horizon` and the clock epoch that
/// connections write their releases in. Fails when the socket refuses SO_TXTIME.
pub(crate) fn kernel_release(socket: &Socket, horizon: Duration) -> io::Result<ReleaseSupport> {
    // Failing here fails the open: unstamped sends would silently stop connections building ahead.
    sys::set_txtime(socket, libc::CLOCK_MONOTONIC).map_err(|error| {
        io::Error::new(
            error.kind(),
            TxtimeError {
                cause: error,
                horizon,
            },
        )
    })?;
    // Rust's `Instant` reads CLOCK_MONOTONIC on Linux too, so the pair is off only by the time
    // between the two reads, tens of nanoseconds.
    let instant = Instant::now();
    let tick = Tick(sys::monotonic_ns());
    Ok(ReleaseSupport::Kernel {
        horizon,
        epoch: ClockEpoch { instant, tick },
    })
}

/// A refused SO_TXTIME: the backend cannot hold datagrams until their release.
#[derive(Debug)]
struct TxtimeError {
    cause: io::Error,
    horizon: Duration,
}

impl std::fmt::Display for TxtimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kernel release with a {:?} horizon needs SO_TXTIME on CLOCK_MONOTONIC, which the \
             socket refused: {}",
            self.horizon, self.cause
        )
    }
}

impl std::error::Error for TxtimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

fn is_ipv6(socket: &Socket) -> bool {
    socket
        .local_addr()
        .is_ok_and(|addr| c_int::from(addr.family()) == libc::AF_INET6)
}

/// Returns the kernel's limit on segments per GSO send, UDP_MAX_SEGMENTS: 64, or 128 since
/// Linux 6.16. It is measured once per process by sending one-byte segments to a throwaway
/// loopback socket, which the kernel refuses with EINVAL beyond its limit.
fn kernel_max_segments() -> u16 {
    static MAX: OnceLock<u16> = OnceLock::new();
    *MAX.get_or_init(|| if gso_send_works(128) { 128 } else { 64 })
}

fn gso_send_works(segments: usize) -> bool {
    let addrs = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ];
    let Some(socket) = addrs.iter().find_map(|&addr| {
        let socket =
            Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP)).ok()?;
        socket.set_nonblocking(true).ok()?;
        socket.bind(&addr.into()).ok()?;
        Some(socket)
    }) else {
        return false;
    };
    let Ok(local) = socket.local_addr() else {
        return false;
    };
    let mut payload = vec![0u8; segments];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = CmsgSpace::default();
    let mut enc = Encoder::new(&mut control.0);
    enc.push(libc::SOL_UDP, libc::UDP_SEGMENT, &1u16.to_ne_bytes());
    let control_len = enc.len();
    let mut msg = sys::empty_mmsghdr();
    msg.msg_hdr.msg_name = local.as_ptr().cast_mut().cast();
    msg.msg_hdr.msg_namelen = local.len();
    msg.msg_hdr.msg_iov = &raw mut iov;
    msg.msg_hdr.msg_iovlen = 1;
    msg.msg_hdr.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_hdr.msg_controllen = control_len as _;
    // SAFETY: the header points at `local`, `iov` (over `payload`) and `control`, all live
    // until the call returns.
    let sent = unsafe { sys::sendmmsg(socket.as_raw_fd(), std::slice::from_mut(&mut msg)) };
    matches!(sent, Ok(1))
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use std::net::UdpSocket;

    use super::*;

    const WORKERS: u16 = 4;

    /// Binds [`WORKERS`] sockets one after another to one loopback port, so the socket at index
    /// `i` of the SO_REUSEPORT group is element `i`, and attaches the steering program.
    fn steered_group() -> (Vec<Socket>, SocketAddr) {
        let options = SocketOptions::default();
        let first = open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None, &options).unwrap();
        let addr = first.local_addr().unwrap().as_socket().unwrap();
        let mut group = vec![first];
        group.extend((1..WORKERS).map(|_| open(addr, None, &options).unwrap()));
        steer_by_connection_id(&group[0], WORKERS).unwrap();
        (group, addr)
    }

    /// Sends `datagram` to `addr` from a socket of its own, so each call is a new flow for the
    /// kernel's hash, and returns the index of the socket in `group` that received it.
    fn receiver(group: &[Socket], addr: SocketAddr, datagram: &[u8]) -> usize {
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender.send_to(datagram, addr).unwrap();
        let mut ready: Vec<libc::pollfd> = group
            .iter()
            .map(|socket| libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `ready` is a live array of `pollfd`s of the length passed; the timeout only
        // guards against a hang.
        let n = unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as libc::nfds_t, 20_000) };
        assert_eq!(
            n, 1,
            "exactly one socket of the group receives the datagram"
        );
        let index = ready
            .iter()
            .position(|fd| fd.revents & libc::POLLIN != 0)
            .unwrap();
        let mut buf = [MaybeUninit::uninit(); 2048];
        assert_eq!(group[index].recv(&mut buf).unwrap(), datagram.len());
        index
    }

    #[test]
    fn a_short_header_goes_to_the_worker_its_connection_id_names() {
        let (group, addr) = steered_group();
        for first in (0..=255u8).step_by(7) {
            let mut datagram = vec![0x40, first];
            datagram.resize(30, 0xee);
            assert_eq!(
                receiver(&group, addr, &datagram),
                usize::from(first) % usize::from(WORKERS),
                "a short header whose connection ID starts with {first:#04x}"
            );
        }
    }

    #[test]
    fn a_long_header_goes_to_the_worker_its_destination_connection_id_names() {
        let (group, addr) = steered_group();
        for (first, dcid_len) in (0..=255u8)
            .step_by(11)
            .zip([8u8, 1, 20].into_iter().cycle())
        {
            // Version 1, the ID's length, the ID, then a zero-length source ID and padding.
            let mut datagram = vec![0xc0, 0, 0, 0, 1, dcid_len, first];
            datagram.resize(6 + usize::from(dcid_len), 0x05);
            datagram.push(0);
            datagram.resize(1200, 0);
            assert_eq!(
                receiver(&group, addr, &datagram),
                usize::from(first) % usize::from(WORKERS),
                "a long header whose {dcid_len}-byte connection ID starts with {first:#04x}"
            );
        }
    }

    #[test]
    fn a_datagram_without_a_connection_id_to_read_is_left_to_the_kernels_hash() {
        let (group, addr) = steered_group();
        let unreadable: [(&str, &[u8]); 4] = [
            ("an empty datagram", &[]),
            ("a short header cut before its connection ID", &[0x40]),
            (
                "a long header cut before its connection ID",
                &[0xc0, 0, 0, 0, 1, 8],
            ),
            (
                "a long header with a zero-length connection ID",
                &[0xc0, 0, 0, 0, 1, 0, 0, 7, 7],
            ),
        ];
        for (what, datagram) in unreadable {
            // Classic BPF ends a program that reads past the datagram with 0, which would send
            // every one to the first socket; the kernel's hash spreads flows over the group, and
            // all 16 landing on one socket of 4 has odds of about 1 in 10^9.
            let receivers: std::collections::BTreeSet<usize> =
                (0..16).map(|_| receiver(&group, addr, datagram)).collect();
            assert!(receivers.len() > 1, "{what} went only to {receivers:?}");
        }
    }
}
