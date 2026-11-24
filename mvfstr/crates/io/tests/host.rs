/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Loopback socket tests for `HostBackend`, on threads without a tokio runtime.

#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::net::UnixDatagram;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::HostBackend;
use mvfstr_io::HostOptions;
use mvfstr_io::Interest;
use mvfstr_io::IoHost;
use mvfstr_io::ManualHost;
use mvfstr_io::MmsgOptions;
use mvfstr_io::Readiness;
use mvfstr_io::ReleaseSupport;
use mvfstr_io::RxBackend;
use mvfstr_io::TxBackend;
use mvfstr_proto::ConnKey;
use mvfstr_proto::PathId;
use mvfstr_proto::Release;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::Tick;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;
use mvfstr_proto::TxSeqRange;
use socket2::Socket;

/// Fails a test that would otherwise hang; passing runs never reach it.
const HANG_GUARD: Duration = Duration::from_secs(20);

/// Host polls a receive may take before the test gives up on it.
const POLLS: usize = 8;

fn v4(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn options(host: &ManualHost) -> HostOptions<ManualHost> {
    HostOptions {
        host: Some(host.clone()),
        ..HostOptions::default()
    }
}

/// A host the test runs by hand: it keeps each registration's descriptor and readiness, for the
/// test to wait on and set, and counts the requests for write readiness.
#[derive(Clone, Default)]
struct ScriptedHost(Rc<Scripted>);

#[derive(Default)]
struct Scripted {
    registered: RefCell<Vec<(RawFd, Readiness)>>,
    write_watches: Cell<usize>,
    /// Whether requests for write readiness fail.
    refuse_watches: Cell<bool>,
}

impl ScriptedHost {
    fn options(&self) -> HostOptions<Self> {
        HostOptions {
            host: Some(self.clone()),
            ..HostOptions::default()
        }
    }

    /// Returns the descriptor and readiness of the `index`-th registration.
    fn registration(&self, index: usize) -> (RawFd, Readiness) {
        self.0.registered.borrow()[index].clone()
    }

    fn write_watches(&self) -> usize {
        self.0.write_watches.get()
    }

    fn refuse_watches(&self, refuse: bool) {
        self.0.refuse_watches.set(refuse);
    }
}

impl IoHost for ScriptedHost {
    type Registration = ();

    fn register(&self, fd: BorrowedFd<'_>, readiness: Readiness) -> std::io::Result<()> {
        self.0
            .registered
            .borrow_mut()
            .push((fd.as_raw_fd(), readiness));
        Ok(())
    }

    fn watch_writable(&self, _registration: &()) -> std::io::Result<()> {
        self.0.write_watches.set(self.0.write_watches.get() + 1);
        if self.0.refuse_watches.get() {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        Ok(())
    }
}

/// A waker that counts its wakes.
#[derive(Default)]
struct Count(AtomicUsize);

impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn counter() -> (Arc<Count>, Waker) {
    let count = Arc::new(Count::default());
    (Arc::clone(&count), Waker::from(count))
}

fn wakes(count: &Count) -> usize {
    count.0.load(Ordering::Relaxed)
}

/// Waits until `fd` has something to read, so the test depends on the kernel's state, not timing.
fn wait_readable(fd: RawFd) {
    let mut ready = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live `pollfd`; the timeout only guards against a hang.
    let n = unsafe { libc::poll(&raw mut ready, 1, HANG_GUARD.as_millis() as libc::c_int) };
    assert_eq!(n, 1, "readable within the hang guard");
}

fn conn(index: u32) -> ConnKey {
    ConnKey {
        index,
        generation: 1,
    }
}

/// Returns the metadata of a run to `dst` as a connection closes it: data class, TOS 0, sealed.
fn meta(dst: SocketAddr, segments: &[Vec<u8>], first_seq: u64) -> TxMeta {
    TxMeta {
        path: PathId(0),
        dst,
        src_ip: None,
        tos: 0,
        segment_size: segments[0].len() as u16,
        segments: segments.len() as u16,
        release: Release::Asap,
        class: TxClass::Data,
        tx: TxSeqRange {
            start: first_seq,
            end: first_seq + segments.len() as u64,
        },
        sealed: true,
    }
}

/// Writes `segments` through the sink as one run closed with `meta`.
fn send_run(backend: &mut impl TxBackend, conn: ConnKey, segments: &[Vec<u8>], meta: TxMeta) {
    let mut sink = backend.sink(conn);
    for segment in segments {
        let (_, slot) = sink
            .next_segment(segment.len() as u16, meta.class)
            .expect("slot");
        slot[..segment.len()].copy_from_slice(segment);
        sink.end_segment(segment.len() as u16);
    }
    sink.end_run(meta);
}

/// Returns `count` segments of `size` bytes with distinct contents, the last of `last` bytes.
fn segments(count: usize, size: usize, last: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let len = if i + 1 == count { last } else { size };
            (0..len).map(|j| (i * 7 + j) as u8).collect()
        })
        .collect()
}

fn reports(backend: &mut impl TxBackend) -> Vec<(ConnKey, TxReport)> {
    let mut out = Vec::new();
    backend.drain_reports(|conn, report| out.push((conn, report)));
    out
}

/// Receives one batch, running `host` until the backend has one, and copies it out.
fn recv_batch(host: &ManualHost, backend: &mut HostBackend<ManualHost>) -> Vec<(RxMeta, Vec<u8>)> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..POLLS {
        match backend.poll_recv(&mut cx) {
            Poll::Ready(n) => {
                let n = n.expect("recv");
                let got: Vec<_> = backend
                    .buffers()
                    .map(|(meta, data)| (*meta, data.to_vec()))
                    .collect();
                assert_eq!(got.len(), n);
                return got;
            }
            Poll::Pending => {
                host.poll(Some(HANG_GUARD)).expect("host poll");
            }
        }
    }
    panic!("no batch within {POLLS} host polls");
}

/// Sends `payload` as one GSO send of `segment`-byte datagrams, the last possibly shorter.
fn raw_gso_send(socket: &UdpSocket, to: SocketAddr, payload: &[u8], segment: u16) {
    let addr = socket2::SockAddr::from(to);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control = [0u64; 8];
    // SAFETY: the header points at `addr`, `iov` (over `payload`) and `control`, all live until
    // `sendmsg` returns; the control message is written inside `control` with the libc macros.
    let sent = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = addr.as_ptr().cast_mut().cast();
        msg.msg_namelen = addr.len();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(2) as _;
        let c = libc::CMSG_FIRSTHDR(&raw const msg);
        (*c).cmsg_level = libc::SOL_UDP;
        (*c).cmsg_type = libc::UDP_SEGMENT;
        (*c).cmsg_len = libc::CMSG_LEN(2) as _;
        libc::CMSG_DATA(c).cast::<u16>().write_unaligned(segment);
        libc::sendmsg(socket.as_raw_fd(), &raw const msg, 0)
    };
    assert_eq!(
        sent,
        payload.len() as isize,
        "{}",
        std::io::Error::last_os_error()
    );
}

#[test]
fn a_gro_receive_splits_by_its_stride_into_the_datagrams_sent() {
    let host = ManualHost::new().unwrap();
    let mut backend = HostBackend::bind(v4(0), &options(&host)).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    let datagrams: Vec<Vec<u8>> = (0..5u8)
        .map(|i| {
            let len = if i == 4 { 500 } else { 1200 };
            (0..len).map(|j| (j % 251) as u8 ^ i).collect()
        })
        .collect();
    raw_gso_send(&sender, to, &datagrams.concat(), 1200);

    let got = recv_batch(&host, &mut backend);
    assert_eq!(got.len(), 1, "one buffer holds the coalesced run");
    let (meta, buffer) = &got[0];
    assert_eq!(meta.src, sender.local_addr().unwrap());
    assert_eq!(meta.stride, 1200);
    let split: Vec<Vec<u8>> = buffer
        .chunks(usize::from(meta.stride))
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(
        split, datagrams,
        "four full datagrams and the short last one"
    );
}

#[test]
fn a_run_leaves_as_one_gso_send() {
    let host = ManualHost::new().unwrap();
    let mut sender = HostBackend::bind(v4(0), &options(&host)).expect("sender");
    let mut receiver = HostBackend::bind(v4(0), &options(&host)).expect("receiver");
    assert!(sender.caps().max_segments >= 64, "{:?}", sender.caps());
    let to = receiver.local_addr().unwrap();
    let run = segments(7, 1452, 300);
    send_run(&mut sender, conn(3), &run, meta(to, &run, 100));
    assert_eq!(
        sender.flush(Instant::now()),
        FlushOutcome {
            datagrams: 7,
            blocked: false
        }
    );

    // Loopback hands a GSO send to a GRO socket whole, so one send arrives as one buffer.
    let got = recv_batch(&host, &mut receiver);
    assert_eq!(got.len(), 1, "one GRO buffer");
    assert_eq!(got[0].0.src, sender.local_addr().unwrap());
    assert_eq!(got[0].0.stride, 1452);
    assert_eq!(got[0].1, run.concat());
}

#[test]
fn a_loopback_pair_talks_under_a_manual_host_without_a_tokio_runtime() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let host = ManualHost::new().unwrap();
    let mut server = HostBackend::bind(v4(0), &options(&host)).expect("server");
    let server_addr = server.local_addr().unwrap();
    let mut client = HostBackend::connect(server_addr, &options(&host)).expect("client");
    let client_addr = client.local_addr().unwrap();
    assert_eq!(
        client_addr.ip(),
        server_addr.ip(),
        "connected over loopback"
    );

    let hello = segments(1, 1200, 1200);
    send_run(&mut client, conn(1), &hello, meta(server_addr, &hello, 0));
    assert_eq!(client.flush(Instant::now()).datagrams, 1);
    let got = recv_batch(&host, &mut server);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0.src, &got[0].1), (client_addr, &hello[0]));

    let reply = segments(3, 1000, 1000);
    send_run(&mut server, conn(2), &reply, meta(client_addr, &reply, 5));
    assert_eq!(server.flush(Instant::now()).datagrams, 3);
    let got = recv_batch(&host, &mut client);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0.src, got[0].0.stride), (server_addr, 1000));
    assert_eq!(got[0].1, reply.concat());

    assert_eq!(
        reports(&mut client),
        vec![(
            conn(1),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 1 }
            }
        )]
    );
    assert_eq!(
        reports(&mut server),
        vec![(
            conn(2),
            TxReport::Flushed {
                tx: TxSeqRange { start: 5, end: 8 }
            }
        )]
    );
}

#[test]
fn eagain_clears_read_readiness_until_the_host_sets_it_again() {
    let host = ScriptedHost::default();
    let mut backend = HostBackend::bind(v4(0), &host.options()).expect("bind");
    let (fd, readiness) = host.registration(0);
    let (woken, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert!(
        backend.poll_recv(&mut cx).is_pending(),
        "nothing is read before the host reports the socket ready"
    );

    let sender = UdpSocket::bind(v4(0)).unwrap();
    let to = backend.local_addr().unwrap();
    sender.send_to(&[1; 100], to).unwrap();
    wait_readable(fd);
    readiness.set(Interest::Read);
    assert_eq!(wakes(&woken), 1);
    assert!(matches!(backend.poll_recv(&mut cx), Poll::Ready(Ok(1))));
    assert!(backend.poll_recv(&mut cx).is_pending(), "EAGAIN");
    assert!(!readiness.is_set(Interest::Read), "EAGAIN cleared it");

    // A report while the socket is empty costs one empty read, then waits again.
    readiness.set(Interest::Read);
    assert_eq!(wakes(&woken), 2, "EAGAIN registered the task again");
    assert!(backend.poll_recv(&mut cx).is_pending());
    assert!(!readiness.is_set(Interest::Read));

    sender.send_to(&[2; 30], to).unwrap();
    wait_readable(fd);
    readiness.set(Interest::Read);
    assert!(matches!(backend.poll_recv(&mut cx), Poll::Ready(Ok(1))));
    let data: Vec<Vec<u8>> = backend.buffers().map(|(_, data)| data.to_vec()).collect();
    assert_eq!(data, vec![vec![2; 30]]);
}

/// Opens a backend on `host` on one end of a connected Unix datagram pair whose send buffer is as
/// small as the kernel allows. Loopback UDP never returns EAGAIN, because the loopback device
/// detaches each datagram from its socket as it sends it; a Unix datagram stays charged to the
/// sender's SO_SNDBUF until the peer reads it, so a few unread datagrams block the sender.
fn blocked_pair<H: IoHost>(host: H) -> (HostBackend<H>, UnixDatagram) {
    let (a, b) = UnixDatagram::pair().unwrap();
    let a = Socket::from(OwnedFd::from(a));
    a.set_send_buffer_size(1).unwrap();
    b.set_read_timeout(Some(HANG_GUARD)).unwrap();
    let backend = HostBackend::from_socket(a, host, &MmsgOptions::default()).expect("backend");
    (backend, b)
}

/// Reads every datagram the peer has, without waiting.
fn drain_peer(peer: &UnixDatagram) -> Vec<Vec<u8>> {
    peer.set_nonblocking(true).unwrap();
    let mut buf = vec![0; 65_536];
    let mut out = Vec::new();
    while let Ok(len) = peer.recv(&mut buf) {
        out.push(buf[..len].to_vec());
    }
    peer.set_nonblocking(false).unwrap();
    out
}

/// Queues 20 runs of one 1,000-byte datagram for connection `key`, numbered 0 to 19.
fn queue_twenty(backend: &mut impl TxBackend, key: ConnKey) -> Vec<Vec<u8>> {
    let runs: Vec<_> = (0..20u8).map(|i| vec![vec![i; 1000]]).collect();
    for (seq, run) in runs.iter().enumerate() {
        send_run(backend, key, run, meta(v4(9), run, seq as u64));
    }
    runs.concat()
}

#[test]
fn after_eagain_poll_writable_asks_the_host_once_and_sends_the_backlog_when_it_reports() {
    let host = ScriptedHost::default();
    let (mut backend, peer) = blocked_pair(host.clone());
    let (_, readiness) = host.registration(0);
    let sent = queue_twenty(&mut backend, conn(18));
    assert!(backend.flush(Instant::now()).blocked);

    let (woken, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.write_watches(), 1);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.write_watches(), 1, "one request per EAGAIN");

    // A report before the peer reads: the retry meets EAGAIN, so write interest is requested again.
    readiness.set(Interest::Write);
    assert_eq!(wakes(&woken), 1);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.write_watches(), 2);
    assert!(!readiness.is_set(Interest::Write), "EAGAIN cleared it");

    let mut got = drain_peer(&peer);
    let mut reports_needed = 0;
    while backend.poll_writable(&mut cx).is_pending() {
        assert!(reports_needed < 100, "the backlog does not leave");
        reports_needed += 1;
        got.extend(drain_peer(&peer));
        readiness.set(Interest::Write);
    }
    got.extend(drain_peer(&peer));
    assert_eq!(got, sent, "every datagram, in order");
    assert_eq!(
        reports(&mut backend),
        vec![(
            conn(18),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 20 }
            }
        )]
    );
    assert!(
        backend.poll_writable(&mut cx).is_ready(),
        "nothing waits once the backlog is gone"
    );
}

#[test]
fn a_host_that_cannot_watch_for_writability_is_asked_again_at_the_next_poll() {
    let host = ScriptedHost::default();
    let (mut backend, _peer) = blocked_pair(host.clone());
    queue_twenty(&mut backend, conn(19));
    assert!(backend.flush(Instant::now()).blocked);
    host.refuse_watches(true);

    let (woken, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.write_watches(), 1);
    assert_eq!(
        wakes(&woken),
        1,
        "woken to ask again, since no report of writability will come"
    );

    host.refuse_watches(false);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.write_watches(), 2, "asked again");
    assert_eq!(wakes(&woken), 1, "and now waits for the report");
}

#[test]
fn a_manual_host_reports_writability_once_asked_and_then_watches_reads_only() {
    let host = ManualHost::new().unwrap();
    let (mut backend, peer) = blocked_pair(host.clone());
    let sent = queue_twenty(&mut backend, conn(20));
    assert!(backend.flush(Instant::now()).blocked);
    let (woken, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert!(backend.poll_writable(&mut cx).is_pending());
    assert_eq!(host.poll(Some(Duration::ZERO)).unwrap(), 0, "still full");

    let mut got = Vec::new();
    while backend.poll_writable(&mut cx).is_pending() {
        assert!(got.len() < sent.len(), "the backlog does not leave");
        got.extend(drain_peer(&peer));
        let before = wakes(&woken);
        assert_eq!(
            host.poll(Some(HANG_GUARD)).unwrap(),
            1,
            "writable once drained"
        );
        assert_eq!(wakes(&woken), before + 1);
    }
    got.extend(drain_peer(&peer));
    assert_eq!(got, sent);
    assert_eq!(
        host.poll(Some(Duration::ZERO)).unwrap(),
        0,
        "write interest ends with the report"
    );
}

#[test]
fn a_socket_stays_registered_across_receive_cycles() {
    let host = ManualHost::new().unwrap();
    let mut backend = HostBackend::bind(v4(0), &options(&host)).expect("bind");
    assert_eq!(host.epoll_ctls(), 1, "registered once at bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for cycle in 0..1000u32 {
        sender.send_to(&cycle.to_be_bytes(), to).unwrap();
        let got = recv_batch(&host, &mut backend);
        assert_eq!(got[0].1, cycle.to_be_bytes());
        assert!(backend.poll_recv(&mut cx).is_pending(), "read to EAGAIN");
    }
    assert_eq!(
        host.epoll_ctls(),
        1,
        "1000 readiness cycles change no registration"
    );
    drop(backend);
    assert_eq!(host.epoll_ctls(), 2, "deregistered with the backend");
}

#[test]
fn txtime_gives_a_host_backend_kernel_release_and_its_runs_their_stamps() {
    let host = ManualHost::new().unwrap();
    let options = HostOptions {
        host: Some(host.clone()),
        mmsg: MmsgOptions {
            txtime: true,
            txtime_horizon: Duration::from_millis(5),
            ..MmsgOptions::default()
        },
    };
    let mut server = HostBackend::bind(v4(0), &options).expect("server");
    let ReleaseSupport::Kernel { horizon, epoch } = server.caps().release else {
        panic!("{:?}", server.caps().release);
    };
    assert_eq!(horizon, Duration::from_millis(5));
    let client = HostBackend::connect(server.local_addr().unwrap(), &options).expect("client");
    assert_eq!(
        client.caps().release,
        ReleaseSupport::None,
        "a client socket never takes kernel release"
    );

    // The kernel refuses an SCM_TXTIME stamp on a socket without SO_TXTIME, so a run that leaves
    // went out stamped on a socket that has it. Loopback sends it at once, without fq to hold it.
    let receiver = UdpSocket::bind(v4(0)).unwrap();
    receiver.set_read_timeout(Some(HANG_GUARD)).unwrap();
    let run = segments(1, 200, 200);
    let stamped = TxMeta {
        release: Release::At(Tick(epoch.tick.0 + 1_000_000)),
        ..meta(receiver.local_addr().unwrap(), &run, 0)
    };
    send_run(&mut server, conn(4), &run, stamped);
    assert_eq!(server.flush(Instant::now()).datagrams, 1);
    let mut buf = [0; 256];
    assert_eq!(receiver.recv(&mut buf).unwrap(), 200);
    assert_eq!(
        reports(&mut server),
        vec![(
            conn(4),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 1 }
            }
        )]
    );
}

#[test]
fn invalid_options_or_a_missing_host_are_refused_before_anything_is_registered() {
    let host = ScriptedHost::default();
    let invalid = HostOptions {
        mmsg: MmsgOptions {
            tx_slots: 4,
            urgent_slots: 4,
            ..MmsgOptions::default()
        },
        ..host.options()
    };
    let kind = |result: std::io::Result<HostBackend<ScriptedHost>>| result.err().map(|e| e.kind());
    assert_eq!(
        kind(HostBackend::bind(v4(0), &invalid)),
        Some(std::io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        kind(HostBackend::connect(v4(9), &invalid)),
        Some(std::io::ErrorKind::InvalidInput)
    );
    let socket = Socket::from(UdpSocket::bind(v4(0)).unwrap());
    assert_eq!(
        kind(HostBackend::from_socket(
            socket,
            host.clone(),
            &invalid.mmsg
        )),
        Some(std::io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        kind(HostBackend::bind(v4(0), &HostOptions::default())),
        Some(std::io::ErrorKind::InvalidInput),
        "no host"
    );
    assert_eq!(host.0.registered.borrow().len(), 0, "registered");
}
