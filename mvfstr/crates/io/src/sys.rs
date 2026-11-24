/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Thin wrappers over the system calls the backend makes, and socket address conversion.

use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use libc::c_int;

/// SO_TXTIME's number in the kernel's asm-generic socket header, which x86-64 and arm64 use. The
/// libc crate in use has `sock_txtime` but not this number.
pub(crate) const SO_TXTIME: c_int = 61;

/// SCM_TXTIME, the control message that carries a send's release in nanoseconds of the clock
/// set with SO_TXTIME; the kernel defines it as SO_TXTIME.
pub(crate) const SCM_TXTIME: c_int = SO_TXTIME;

/// Sets an integer socket option.
pub(crate) fn set_int(
    fd: &impl AsRawFd,
    level: c_int,
    name: c_int,
    value: c_int,
) -> io::Result<()> {
    // SAFETY: the option value points at a live `c_int` and its length is passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Reads an integer socket option.
pub(crate) fn get_int(fd: &impl AsRawFd, level: c_int, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes into `value`, a live `c_int`, and updates
    // `len`, a live `socklen_t`.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if rc == 0 {
        Ok(value)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Turns on SO_TXTIME with `clockid` and every flag clear, so sends may carry SCM_TXTIME releases.
pub(crate) fn set_txtime(fd: &impl AsRawFd, clockid: libc::clockid_t) -> io::Result<()> {
    let value = libc::sock_txtime { clockid, flags: 0 };
    // SAFETY: the option value points at a live `sock_txtime` and its length is passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_TXTIME,
            (&raw const value).cast(),
            size_of::<libc::sock_txtime>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Returns CLOCK_MONOTONIC's reading in nanoseconds.
pub(crate) fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the kernel writes one `timespec` into `now`, which is live. CLOCK_MONOTONIC always
    // exists, so the call cannot fail with a valid pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
    // The clock counts from boot, so both fields are non-negative.
    (now.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec as u64)
}

/// Attaches the classic BPF `program` to the SO_REUSEPORT group of `fd`'s socket
/// (SO_ATTACH_REUSEPORT_CBPF), where it picks the socket of each datagram by its index in the
/// group. The kernel copies the program.
pub(crate) fn attach_reuseport_cbpf(
    fd: &impl AsRawFd,
    program: &[libc::sock_filter],
) -> io::Result<()> {
    let len = u16::try_from(program.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BPF program too long"))?;
    let fprog = libc::sock_fprog {
        len,
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: the option value points at a live `sock_fprog`, whose filter points at `len` live
    // instructions that the kernel only reads, and its length is passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            (&raw const fprog).cast(),
            size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Calls `sendmmsg(2)` and returns how many messages the kernel accepted.
///
/// # Safety
///
/// Every pointer in `msgs` (names, iovecs and their buffers, control data) must be valid for
/// reads of the lengths given next to it for the duration of the call.
pub(crate) unsafe fn sendmmsg(fd: RawFd, msgs: &mut [libc::mmsghdr]) -> io::Result<usize> {
    let vlen = msgs.len().min(c_int::MAX as usize) as libc::c_uint;
    // SAFETY: `msgs` is a live slice of `vlen` headers, and the caller guarantees the pointers
    // inside them.
    let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), vlen, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// Calls `recvmmsg(2)` and returns how many messages the kernel filled.
///
/// # Safety
///
/// Every pointer in `msgs` (names, iovecs and their buffers, control data) must be valid for
/// writes of the lengths given next to it for the duration of the call.
pub(crate) unsafe fn recvmmsg(fd: RawFd, msgs: &mut [libc::mmsghdr]) -> io::Result<usize> {
    let vlen = msgs.len().min(c_int::MAX as usize) as libc::c_uint;
    // SAFETY: `msgs` is a live slice of `vlen` headers, and the caller guarantees the pointers
    // inside them. A null timeout makes the call return as soon as the non-blocking socket runs out
    // of datagrams.
    let rc = unsafe { libc::recvmmsg(fd, msgs.as_mut_ptr(), vlen, 0, std::ptr::null_mut()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// Returns an empty `mmsghdr`, without a name, iovecs or control data.
pub(crate) fn empty_mmsghdr() -> libc::mmsghdr {
    // SAFETY: `mmsghdr` is a C struct of integers and raw pointers, for which all zeroes (null
    // pointers, zero lengths) is a valid value.
    unsafe { std::mem::zeroed() }
}

/// Returns an empty socket address buffer for `recvmmsg`.
pub(crate) fn empty_sockaddr() -> libc::sockaddr_storage {
    // SAFETY: `sockaddr_storage` is a C struct of integers, for which all zeroes is valid.
    unsafe { std::mem::zeroed() }
}

/// Returns the socket address in a buffer the kernel filled, with IPv4-mapped IPv6 addresses
/// canonicalized to IPv4, or `None` for other families or a short length.
pub(crate) fn to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    let len = len as usize;
    match c_int::from(storage.ss_family) {
        libc::AF_INET if len >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family shows that the storage holds a `sockaddr_in`, which is smaller
            // than and no more aligned than `sockaddr_storage`.
            let sin = unsafe { &*(&raw const *storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 if len >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family shows that the storage holds a `sockaddr_in6`, which is smaller
            // than and no more aligned than `sockaddr_storage`.
            let sin6 = unsafe { &*(&raw const *storage).cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(match ip.to_ipv4_mapped() {
                Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                None => SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )),
            })
        }
        _ => None,
    }
}
