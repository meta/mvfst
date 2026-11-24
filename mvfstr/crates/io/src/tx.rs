/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The transmit half of [`MmsgBackend`](crate::MmsgBackend).

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use libc::c_int;
use mvfstr_proto::ConnKey;
use mvfstr_proto::DropReason;
use mvfstr_proto::Release;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::SlotId;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;
use mvfstr_proto::TxSeqRange;
use socket2::SockAddr;

use crate::ReleaseSupport;
use crate::TxCaps;
use crate::cmsg::CmsgSpace;
use crate::cmsg::Encoder;
use crate::sys;

/// The most payload one UDP send carries over IPv4: 65,535 bytes less the IPv4 and UDP headers.
/// IPv6 allows 20 bytes more; one limit keeps dual-stack sockets simple.
const MAX_SEND_BYTES: usize = 65_507;

/// How the transmit half is sized, from [`MmsgOptions`](crate::MmsgOptions).
pub(crate) struct TxConfig {
    pub(crate) slots: u32,
    pub(crate) urgent_slots: u16,
    pub(crate) max_unsent: u32,
    pub(crate) batch: usize,
    pub(crate) connected: bool,
    pub(crate) ipv6: bool,
}

/// A slot lent to a sink.
struct Lent {
    slot: u32,
    /// The length of the slice lent.
    len: u16,
    /// Whether it counts against the connection's urgent quota.
    counted: bool,
}

/// One message for `sendmmsg`: a GSO run, or part of one, from one connection.
struct Msg {
    conn: ConnKey,
    dst: SocketAddr,
    src_ip: Option<IpAddr>,
    tos: u8,
    segment_size: u16,
    segments: u16,
    bytes: u32,
    tx: TxSeqRange,
    release: Release,
}

pub(crate) struct Tx {
    caps: TxCaps,
    connected: bool,
    ipv6: bool,
    batch: usize,
    urgent_slots: usize,
    max_unsent: usize,
    slot_size: usize,
    /// Every slot's bytes, `slot_size` each.
    pool: Box<[u8]>,
    /// The datagram length in each slot that holds one.
    lens: Box<[u16]>,
    free: Vec<u32>,
    /// The slot lent by `next_segment`, until `end_segment`.
    lent: Option<Lent>,
    /// The slots of the open run, ended but not yet closed by `end_run`.
    open: Vec<u32>,
    queue: VecDeque<Msg>,
    /// The slots of the queued messages, in queue order.
    queued: VecDeque<u32>,
    reports: Vec<(ConnKey, TxReport)>,
    blocked: bool,
    /// Urgent slots each connection took since the backend began refusing it data.
    urgent_taken: Vec<(ConnKey, u16)>,
    /// The connection of the last sink, and its bytes in queued messages and its open run.
    sink_conn: Option<ConnKey>,
    unsent: usize,
    // Scratch for building one `sendmmsg` call; the headers point into the other three.
    hdrs: Vec<libc::mmsghdr>,
    iovs: Vec<libc::iovec>,
    names: Vec<SockAddr>,
    control: Vec<CmsgSpace>,
}

impl Tx {
    pub(crate) fn new(caps: TxCaps, config: TxConfig) -> Self {
        let slot_size = usize::from(caps.max_datagram);
        let slots = config.slots as usize;
        Self {
            caps,
            connected: config.connected,
            ipv6: config.ipv6,
            batch: config.batch,
            urgent_slots: usize::from(config.urgent_slots),
            max_unsent: config.max_unsent as usize,
            slot_size,
            pool: vec![0; slots * slot_size].into_boxed_slice(),
            lens: vec![0; slots].into_boxed_slice(),
            free: (0..config.slots).rev().collect(),
            lent: None,
            open: Vec::with_capacity(slots),
            queue: VecDeque::with_capacity(slots),
            queued: VecDeque::with_capacity(slots),
            reports: Vec::new(),
            blocked: false,
            urgent_taken: Vec::new(),
            sink_conn: None,
            unsent: 0,
            hdrs: Vec::with_capacity(config.batch),
            iovs: Vec::with_capacity(slots),
            names: Vec::with_capacity(config.batch),
            control: vec![CmsgSpace::default(); config.batch],
        }
    }

    pub(crate) fn caps(&self) -> &TxCaps {
        &self.caps
    }

    pub(crate) fn blocked(&self) -> bool {
        self.blocked
    }

    /// Sends every queued message it can. Returns the datagrams handed to the kernel.
    pub(crate) fn send(&mut self, fd: BorrowedFd<'_>) -> u32 {
        let mut sent = 0;
        while !self.queue.is_empty() {
            let n = self.prepare();
            // SAFETY: `prepare` pointed every header at names, iovecs, control data and slot
            // bytes owned by `self`, and these do not change until the call returns.
            match unsafe { sys::sendmmsg(fd.as_raw_fd(), &mut self.hdrs[..n]) } {
                Ok(accepted) => {
                    for _ in 0..accepted {
                        sent += self.retire_front(Retire::Flushed);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // After EAGAIN the rest stays queued until the socket is writable.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.blocked = true;
                    return sent;
                }
                // `sendmmsg` reports an error only for the first message it was given.
                Err(e) => {
                    self.retire_front(match did_not_leave(&e) {
                        Some(reason) => Retire::Dropped(reason),
                        None => Retire::Unknown,
                    });
                }
            }
        }
        self.blocked = false;
        self.urgent_taken.clear();
        sent
    }

    pub(crate) fn drain_reports(&mut self, mut f: impl FnMut(ConnKey, TxReport)) {
        for (conn, report) in self.reports.drain(..) {
            f(conn, report);
        }
    }

    /// Starts a sink for `conn`: counts the bytes it already has queued.
    fn begin_sink(&mut self, conn: ConnKey) {
        self.sink_conn = Some(conn);
        self.unsent = self
            .queue
            .iter()
            .filter(|msg| msg.conn == conn)
            .map(|msg| msg.bytes as usize)
            .sum();
    }

    fn lend(
        &mut self,
        fd: BorrowedFd<'_>,
        conn: ConnKey,
        max_len: u16,
        class: TxClass,
    ) -> Option<(SlotId, &mut [u8])> {
        self.abandon_lent(conn);
        if !self.has_room(class) && !self.blocked {
            self.send(fd);
        }
        let len = max_len.min(self.caps.max_datagram);
        // Data waits after EAGAIN until the backlog leaves, and while the connection has
        // `max_unsent` bytes built but not sent. Urgent segments may still queue, a few per
        // connection.
        let refusing = self.blocked || self.unsent + usize::from(len) > self.max_unsent;
        if refusing && (class == TxClass::Data || self.urgent_taken(conn) >= self.urgent_slots) {
            return None;
        }
        if !self.has_room(class) {
            return None;
        }
        let slot = self.free.pop()?;
        let counted = refusing;
        if counted {
            match self.urgent_taken.iter_mut().find(|(key, _)| *key == conn) {
                Some((_, taken)) => *taken += 1,
                None => self.urgent_taken.push((conn, 1)),
            }
        }
        self.lent = Some(Lent { slot, len, counted });
        let start = slot as usize * self.slot_size;
        Some((
            SlotId(slot),
            &mut self.pool[start..start + usize::from(len)],
        ))
    }

    fn urgent_taken(&self, conn: ConnKey) -> usize {
        self.urgent_taken
            .iter()
            .find(|(key, _)| *key == conn)
            .map_or(0, |&(_, taken)| usize::from(taken))
    }

    /// Puts a lent slot that was not ended back in the pool, and gives back its urgent quota.
    fn abandon_lent(&mut self, conn: ConnKey) {
        let Some(lent) = self.lent.take() else {
            return;
        };
        self.free.push(lent.slot);
        if lent.counted
            && let Some((_, taken)) = self.urgent_taken.iter_mut().find(|(key, _)| *key == conn)
        {
            *taken = taken.saturating_sub(1);
        }
    }

    /// Returns whether a free slot is left for `class`: data leaves `urgent_slots` behind.
    fn has_room(&self, class: TxClass) -> bool {
        match class {
            TxClass::Urgent => !self.free.is_empty(),
            TxClass::Data => self.free.len() > self.urgent_slots,
        }
    }

    fn end_segment(&mut self, conn: ConnKey, len: u16) {
        if len == 0 {
            self.abandon_lent(conn);
            return;
        }
        let Some(lent) = self.lent.take() else {
            return;
        };
        let len = len.min(lent.len);
        self.lens[lent.slot as usize] = len;
        self.unsent += usize::from(len);
        self.open.push(lent.slot);
    }

    /// Ends a sink: a lent slot returns to the pool; so do the slots of a run never closed,
    /// whose datagrams cannot be sent without their metadata.
    fn end_sink(&mut self, conn: ConnKey) {
        self.abandon_lent(conn);
        if !self.open.is_empty() {
            debug_assert!(
                std::thread::panicking(),
                "a sink was dropped with an open run of {} segments",
                self.open.len()
            );
            self.free.append(&mut self.open);
        }
    }

    fn end_run(&mut self, fd: BorrowedFd<'_>, conn: ConnKey, meta: TxMeta) {
        let segments = self.open.len() as u64;
        debug_assert_eq!(u64::from(meta.segments), segments, "TxMeta::segments");
        debug_assert_eq!(meta.tx.end - meta.tx.start, segments, "TxMeta::tx");
        if let Some(&first) = self.open.first() {
            debug_assert_eq!(
                meta.segment_size, self.lens[first as usize],
                "TxMeta::segment_size"
            );
        }
        // Without release support connections do not build ahead (their build horizon is 0), so
        // every run is sent as soon as possible.
        debug_assert!(
            meta.release == Release::Asap || self.caps.release != ReleaseSupport::None,
            "TxMeta::release {:?} on a backend without release support",
            meta.release
        );
        if !meta.sealed {
            // Unsealed bytes must never leave, and these did not.
            for &slot in &self.open {
                self.unsent -= usize::from(self.lens[slot as usize]);
            }
            self.free.append(&mut self.open);
            self.report(
                conn,
                TxReport::Dropped {
                    tx: meta.tx,
                    reason: DropReason::Error,
                },
            );
            return;
        }
        // Cut the run into GSO sends: each send's segment size is its first segment's length,
        // and a send ends after a shorter segment, before a longer one, at the kernel's segment
        // limit, or before it would carry more than one UDP datagram can.
        let max_segments = self.caps.max_segments.max(1);
        let mut next = meta.tx.start;
        let mut i = 0;
        while i < self.open.len() {
            let size = self.lens[self.open[i] as usize];
            let mut last = size;
            let mut count = 1;
            let mut bytes = usize::from(size);
            i += 1;
            while i < self.open.len() {
                let len = self.lens[self.open[i] as usize];
                if count == max_segments
                    || last < size
                    || len > size
                    || bytes + usize::from(len) > MAX_SEND_BYTES
                {
                    break;
                }
                last = len;
                count += 1;
                bytes += usize::from(len);
                i += 1;
            }
            self.queue.push_back(Msg {
                conn,
                dst: meta.dst,
                src_ip: meta.src_ip,
                tos: meta.tos,
                segment_size: size,
                segments: count,
                bytes: bytes as u32,
                tx: TxSeqRange {
                    start: next,
                    end: next + u64::from(count),
                },
                release: meta.release,
            });
            next += u64::from(count);
        }
        self.queued.extend(self.open.drain(..));
        if self.queue.len() >= self.batch && !self.blocked {
            self.send(fd);
        }
    }

    /// Queues a report, merging a `Flushed` that continues the previous one.
    fn report(&mut self, conn: ConnKey, report: TxReport) {
        if let (Some((last_conn, TxReport::Flushed { tx: last })), TxReport::Flushed { tx }) =
            (self.reports.last_mut(), report)
            && *last_conn == conn
            && last.end == tx.start
        {
            last.end = tx.end;
            return;
        }
        self.reports.push((conn, report));
    }

    /// Builds the headers for the first messages of the queue, at most `batch`; returns how
    /// many.
    fn prepare(&mut self) -> usize {
        let n = self.queue.len().min(self.batch);
        self.iovs.clear();
        self.names.clear();
        self.hdrs.clear();
        // The iovecs and names are complete before any header points into them; neither
        // reallocates, since their capacities are the pool's slots and the batch.
        let mut slots = self.queued.iter();
        for msg in self.queue.iter().take(n) {
            for &slot in slots.by_ref().take(usize::from(msg.segments)) {
                let start = slot as usize * self.slot_size;
                self.iovs.push(libc::iovec {
                    iov_base: self.pool[start..].as_mut_ptr().cast(),
                    iov_len: usize::from(self.lens[slot as usize]),
                });
            }
            if !self.connected {
                self.names.push(SockAddr::from(msg.dst));
            }
        }
        let mut iov = 0;
        for (i, (msg, control)) in self.queue.iter().zip(&mut self.control).take(n).enumerate() {
            let mut hdr = sys::empty_mmsghdr();
            if let Some(name) = self.names.get(i) {
                hdr.msg_hdr.msg_name = name.as_ptr().cast_mut().cast();
                hdr.msg_hdr.msg_namelen = name.len();
            }
            hdr.msg_hdr.msg_iov = self.iovs[iov..].as_mut_ptr();
            hdr.msg_hdr.msg_iovlen = usize::from(msg.segments) as _;
            iov += usize::from(msg.segments);
            let len = encode_cmsgs(&mut control.0, msg, self.ipv6);
            if len > 0 {
                hdr.msg_hdr.msg_control = control.0.as_mut_ptr().cast();
                hdr.msg_hdr.msg_controllen = len as _;
            }
            self.hdrs.push(hdr);
        }
        n
    }

    /// Retires the front message, frees its slots and reports what became of it; returns the
    /// datagrams handed to the kernel.
    fn retire_front(&mut self, how: Retire) -> u32 {
        let Some(msg) = self.queue.pop_front() else {
            return 0;
        };
        self.free
            .extend(self.queued.drain(..usize::from(msg.segments)));
        if Some(msg.conn) == self.sink_conn {
            self.unsent -= msg.bytes as usize;
        }
        match how {
            Retire::Flushed => {
                self.report(msg.conn, TxReport::Flushed { tx: msg.tx });
                u32::from(msg.segments)
            }
            Retire::Dropped(reason) => {
                self.report(msg.conn, TxReport::Dropped { tx: msg.tx, reason });
                0
            }
            Retire::Unknown => 0,
        }
    }
}

/// What became of a message that left the queue.
enum Retire {
    /// The kernel accepted it.
    Flushed,
    /// It certainly did not leave.
    Dropped(DropReason),
    /// It may have left: it is not reported, so its packets stay in flight and loss detection
    /// recovers them.
    Unknown,
}

/// Returns the drop reason for a send error that proves the datagram did not leave, as the kernel
/// refused it before handing anything to a device, or `None` when the error leaves this uncertain.
fn did_not_leave(error: &io::Error) -> Option<DropReason> {
    match error.raw_os_error()? {
        // Without IP_RECVERR, ENOBUFS comes only from failing to allocate the datagram.
        libc::ENOBUFS | libc::ENOMEM => Some(DropReason::LocalQueue),
        // Bad arguments, size or GSO checks, routing and address errors, netfilter refusals,
        // and a pending ICMP error that the failed send consumed on a connected socket.
        libc::EINVAL
        | libc::EMSGSIZE
        | libc::EIO
        | libc::EAFNOSUPPORT
        | libc::EADDRNOTAVAIL
        | libc::EDESTADDRREQ
        | libc::ENOTCONN
        | libc::EACCES
        | libc::EPERM
        | libc::ENETUNREACH
        | libc::EHOSTUNREACH
        | libc::ECONNREFUSED
        | libc::EBADF
        | libc::ENOTSOCK
        | libc::EOPNOTSUPP
        | libc::EFAULT => Some(DropReason::Error),
        _ => None,
    }
}

/// Writes a message's control data: UDP_SEGMENT for a GSO send, its TOS byte, its source
/// address and its release. Returns the length.
fn encode_cmsgs(buf: &mut [u8], msg: &Msg, ipv6_socket: bool) -> usize {
    let mut enc = Encoder::new(buf);
    if msg.segments > 1 {
        enc.push(
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            &msg.segment_size.to_ne_bytes(),
        );
    }
    // IPv4 destinations, mapped ones on a dual-stack socket included, take IPv4 control
    // messages; the kernel ignores IPV6_TCLASS for them.
    let ipv4_path = !ipv6_socket || msg.dst.ip().to_canonical().is_ipv4();
    // The backend zeroes the socket's own TOS and traffic class, so TOS 0 does not need a control
    // message.
    if msg.tos != 0 {
        let tos = c_int::from(msg.tos).to_ne_bytes();
        if ipv4_path {
            enc.push(libc::IPPROTO_IP, libc::IP_TOS, &tos);
        } else {
            enc.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos);
        }
    }
    if let Some(src) = msg.src_ip {
        push_source(&mut enc, ipv4_path, src);
    }
    // One stamp covers the whole GSO send, as one release covers the run.
    if let Release::At(tick) = msg.release {
        let stamped = enc.push(libc::SOL_SOCKET, sys::SCM_TXTIME, &tick.0.to_ne_bytes());
        debug_assert!(stamped, "SCM_TXTIME does not fit in the control space");
    }
    enc.len()
}

/// Appends the control message that picks the source address: `in_pktinfo` with
/// `ipi_spec_dst` on the IPv4 path, `in6_pktinfo` otherwise. Interface 0 lets routing choose.
fn push_source(enc: &mut Encoder<'_>, ipv4_path: bool, src: IpAddr) {
    match (ipv4_path, src.to_canonical()) {
        (true, IpAddr::V4(src)) => {
            let mut info = [0u8; 12];
            info[4..8].copy_from_slice(&src.octets());
            enc.push(libc::IPPROTO_IP, libc::IP_PKTINFO, &info);
        }
        (_, src) => {
            let src = match src {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let mut info = [0u8; 20];
            info[..16].copy_from_slice(&src.octets());
            enc.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info);
        }
    }
}

/// [`MmsgBackend`](crate::MmsgBackend)'s [`SegmentSink`] for one connection.
pub struct MmsgSink<'a> {
    tx: &'a mut Tx,
    fd: BorrowedFd<'a>,
    conn: ConnKey,
}

impl<'a> MmsgSink<'a> {
    pub(crate) fn new(tx: &'a mut Tx, fd: BorrowedFd<'a>, conn: ConnKey) -> Self {
        tx.begin_sink(conn);
        Self { tx, fd, conn }
    }
}

impl Drop for MmsgSink<'_> {
    fn drop(&mut self) {
        self.tx.end_sink(self.conn);
    }
}

impl SegmentSink for MmsgSink<'_> {
    fn next_segment(&mut self, max_len: u16, class: TxClass) -> Option<(SlotId, &mut [u8])> {
        self.tx.lend(self.fd, self.conn, max_len, class)
    }

    fn end_segment(&mut self, len: u16) {
        self.tx.end_segment(self.conn, len);
    }

    fn end_run(&mut self, meta: TxMeta) {
        self.tx.end_run(self.fd, self.conn, meta);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::net::UdpSocket;
    use std::os::fd::AsFd;
    use std::time::Duration;
    use std::time::Instant;

    use mvfstr_proto::ClockEpoch;
    use mvfstr_proto::PathId;
    use mvfstr_proto::Tick;

    use super::*;
    use crate::cmsg::Decoder;

    /// Returns a 44-segment GSO send to `dst` from `src` with a DSCP and ECN byte.
    fn gso_msg(dst: SocketAddr, src: IpAddr, release: Release) -> Msg {
        Msg {
            conn: ConnKey {
                index: 1,
                generation: 1,
            },
            dst,
            src_ip: Some(src),
            tos: 0x2e << 2 | 0b10,
            segment_size: 1452,
            segments: 44,
            bytes: 44 * 1452,
            tx: TxSeqRange { start: 0, end: 44 },
            release,
        }
    }

    fn decoded(msg: &Msg, ipv6_socket: bool) -> Vec<(c_int, c_int, Vec<u8>)> {
        let mut space = CmsgSpace::default();
        let len = encode_cmsgs(&mut space.0, msg, ipv6_socket);
        Decoder::new(&space.0[..len])
            .map(|(level, ty, data)| (level, ty, data.to_vec()))
            .collect()
    }

    #[test]
    fn a_release_time_goes_as_an_scm_txtime_stamp_beside_the_other_control_messages() {
        const SCM_TXTIME: c_int = 61;
        let tick = 1_795_302_827_123_456_789u64;
        let v4 = (
            false,
            SocketAddr::from((Ipv4Addr::new(10, 77, 2, 2), 6666)),
            IpAddr::from(Ipv4Addr::new(10, 77, 1, 1)),
            (libc::IPPROTO_IP, libc::IP_TOS),
            (libc::IPPROTO_IP, libc::IP_PKTINFO),
        );
        let v6 = (
            true,
            SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 6666)),
            IpAddr::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO),
        );
        // IPv6 with every control message is the largest set a message carries.
        for (ipv6_socket, dst, src, tos, pktinfo) in [v4, v6] {
            let stamped = decoded(&gso_msg(dst, src, Release::At(Tick(tick))), ipv6_socket);
            let kinds: Vec<(c_int, c_int)> = stamped.iter().map(|&(l, t, _)| (l, t)).collect();
            assert_eq!(
                kinds,
                vec![
                    (libc::SOL_UDP, libc::UDP_SEGMENT),
                    tos,
                    pktinfo,
                    (libc::SOL_SOCKET, SCM_TXTIME),
                ],
                "{dst}"
            );
            assert_eq!(stamped[3].2, tick.to_ne_bytes(), "a u64 of nanoseconds");

            let asap = decoded(&gso_msg(dst, src, Release::Asap), ipv6_socket);
            assert_eq!(asap, stamped[..3], "Asap adds no stamp: {dst}");
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "SCM_TXTIME")]
    fn a_release_stamp_that_does_not_fit_the_control_space_is_a_bug() {
        let msg = gso_msg(
            SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 6666)),
            IpAddr::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            Release::At(Tick(1)),
        );
        // One byte short of the 112 bytes the full IPv6 set takes: an unstamped run would leave
        // at once, ahead of the connection's runs still waiting in fq.
        let mut buf = [0u8; 111];
        encode_cmsgs(&mut buf, &msg, true);
    }

    /// Returns a transmit half whose GSO sends hold at most `max_segments` segments, with
    /// `release`.
    fn tx(max_segments: u16, release: ReleaseSupport) -> Tx {
        let caps = TxCaps {
            max_segments,
            max_datagram: 1500,
            gro: true,
            ecn: true,
            pktinfo: true,
            release,
            send_buffer: 212_992,
        };
        Tx::new(
            caps,
            TxConfig {
                slots: 64,
                urgent_slots: 4,
                max_unsent: 128 * 1024,
                batch: 64,
                connected: false,
                ipv6: false,
            },
        )
    }

    #[test]
    fn every_gso_send_cut_from_a_stamped_run_carries_its_release() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let fd = socket.as_fd();
        let kernel = ReleaseSupport::Kernel {
            horizon: Duration::from_millis(100),
            epoch: ClockEpoch {
                instant: Instant::now(),
                tick: Tick(1 << 40),
            },
        };
        let mut tx = tx(4, kernel);
        let conn = ConnKey {
            index: 3,
            generation: 1,
        };
        let release = Tick((1 << 40) + 5_000_000);
        tx.begin_sink(conn);
        for _ in 0..10 {
            let (_, slot) = tx.lend(fd, conn, 1452, TxClass::Data).expect("a slot");
            slot.fill(7);
            tx.end_segment(conn, 1452);
        }
        tx.end_run(
            fd,
            conn,
            TxMeta {
                path: PathId(0),
                dst: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                src_ip: None,
                tos: 0,
                segment_size: 1452,
                segments: 10,
                release: Release::At(release),
                class: TxClass::Data,
                tx: TxSeqRange { start: 0, end: 10 },
                sealed: true,
            },
        );
        tx.end_sink(conn);

        let n = tx.prepare();
        assert_eq!(n, 3, "sends of 4, 4 and 2 segments");
        for (i, hdr) in tx.hdrs.iter().enumerate() {
            #[allow(clippy::unnecessary_cast, reason = "msg_controllen is u32 on musl")]
            let control = &tx.control[i].0[..hdr.msg_hdr.msg_controllen as usize];
            let stamps: Vec<Vec<u8>> = Decoder::new(control)
                .filter(|&(level, ty, _)| (level, ty) == (libc::SOL_SOCKET, 61))
                .map(|(_, _, data)| data.to_vec())
                .collect();
            assert_eq!(stamps, vec![release.0.to_ne_bytes().to_vec()], "send {i}");
        }
    }
}
