/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Loopback socket tests for `MmsgBackend` and the socket helpers.

#![cfg(target_os = "linux")]

use std::future::poll_fn;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_io::MmsgSink;
use mvfstr_io::ReleaseSupport;
use mvfstr_io::RxBackend;
use mvfstr_io::SocketOptions;
use mvfstr_io::TxBackend;
use mvfstr_io::TxCounters;
use mvfstr_io::socket;
use mvfstr_proto::ConnKey;
use mvfstr_proto::DropReason;
use mvfstr_proto::Ecn;
use mvfstr_proto::PathId;
use mvfstr_proto::Release;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;
use mvfstr_proto::TxSeqRange;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use tokio::runtime::Runtime;

/// Fails a test that would otherwise hang; passing runs never reach it.
const HANG_GUARD: Duration = Duration::from_secs(20);

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

fn v4(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
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
fn send_run(backend: &mut MmsgBackend, conn: ConnKey, segments: &[Vec<u8>], meta: TxMeta) {
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

fn reports(backend: &mut MmsgBackend) -> Vec<(ConnKey, TxReport)> {
    let mut out = Vec::new();
    backend.drain_reports(|conn, report| out.push((conn, report)));
    out
}

fn receiver(local: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(local).unwrap();
    socket.set_read_timeout(Some(HANG_GUARD)).unwrap();
    socket
}

/// Reads `n` datagrams from a plain socket.
fn recv_plain(socket: &UdpSocket, n: usize) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0; 65_536];
    (0..n)
        .map(|_| {
            let (len, from) = socket.recv_from(&mut buf).expect("datagram");
            (from, buf[..len].to_vec())
        })
        .collect()
}

/// Receives one batch and copies it out.
fn recv_batch(rt: &Runtime, backend: &mut MmsgBackend) -> Vec<(RxMeta, Vec<u8>)> {
    let n = rt
        .block_on(tokio::time::timeout(
            HANG_GUARD,
            poll_fn(|cx| backend.poll_recv(cx)),
        ))
        .expect("hang guard")
        .expect("recv");
    let got: Vec<_> = backend
        .buffers()
        .map(|(meta, data)| (*meta, data.to_vec()))
        .collect();
    assert_eq!(got.len(), n);
    got
}

#[test]
fn binding_probes_gso_gro_ecn_and_pktinfo() {
    let rt = runtime();
    let _guard = rt.enter();
    let backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let caps = *backend.caps();
    assert!(caps.max_segments >= 64, "{caps:?}");
    assert_eq!(caps.max_datagram, 1500);
    assert!(caps.gro, "{caps:?}");
    assert!(caps.ecn, "{caps:?}");
    assert!(caps.pktinfo, "{caps:?}");
}

#[test]
fn receives_a_batch_from_several_senders() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let to = backend.local_addr().expect("addr");
    let a = UdpSocket::bind(v4(0)).expect("a");
    let b = UdpSocket::bind(v4(0)).expect("b");
    a.send_to(&[1; 100], to).expect("send a");
    b.send_to(&[2; 30], to).expect("send b");

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0].0.src, a.local_addr().unwrap());
    assert_eq!(got[0].0.stride, 100);
    assert_eq!(got[0].1, vec![1; 100]);
    assert_eq!(got[1].0.src, b.local_addr().unwrap());
    assert_eq!(got[1].0.stride, 30);
    assert_eq!(got[1].1, vec![2; 30]);
}

/// Binds a plain UDP socket to `local` whose sends carry `tos` (DSCP and ECN).
fn sender_with_tos(local: SocketAddr, tos: u32) -> UdpSocket {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP)).unwrap();
    if local.is_ipv4() {
        socket.set_tos_v4(tos).unwrap();
    } else {
        socket.set_tclass_v6(tos).unwrap();
    }
    socket.bind(&local.into()).unwrap();
    socket.into()
}

#[test]
fn reports_destination_address_ecn_and_receive_time() {
    let rt = runtime();
    let _guard = rt.enter();
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let mut backend = MmsgBackend::bind(any, &MmsgOptions::default()).expect("bind");
    let port = backend.local_addr().unwrap().port();
    let to = SocketAddr::from(([127, 0, 0, 3], port));
    let sender = sender_with_tos(v4(0), 0x2e << 2 | 0b10);
    let before = Instant::now();
    sender.send_to(&[5; 40], to).unwrap();

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1);
    let meta = got[0].0;
    assert_eq!(meta.dst_ip, Some(IpAddr::from([127, 0, 0, 3])));
    assert_eq!(meta.ecn, Ecn::Ect0);
    assert!(meta.rx_time >= before);
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
fn coalesced_datagrams_arrive_as_one_buffer_with_their_stride() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    let payload: Vec<u8> = (0..4 * 1200 + 500).map(|i| (i % 251) as u8).collect();
    raw_gso_send(&sender, to, &payload, 1200);

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0.stride, 1200);
    assert_eq!(got[0].1, payload);
}

#[test]
fn each_batch_receives_into_every_slots_own_buffer_with_its_whole_control_space() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    // The kernel shortens the first slot's control length to what a single datagram's
    // IP_PKTINFO and IP_TOS take; a GRO run adds UDP_GRO.
    let single = vec![vec![1; 100]];
    send_run(&mut sender, conn(20), &single, meta(to, &single, 0));
    sender.flush(Instant::now());
    assert_eq!(recv_batch(&rt, &mut receiver).len(), 1);

    let run = segments(3, 200, 200);
    send_run(&mut sender, conn(20), &run, meta(to, &run, 1));
    let tail = vec![vec![2; 50]];
    send_run(&mut sender, conn(20), &tail, meta(to, &tail, 4));
    sender.flush(Instant::now());
    let mut got = Vec::new();
    while got
        .iter()
        .map(|(_, d): &(RxMeta, Vec<u8>)| d.len())
        .sum::<usize>()
        < 650
    {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let shapes: Vec<_> = got.iter().map(|(m, d)| (m.stride, d.len())).collect();
    assert_eq!(shapes, vec![(200, 600), (50, 50)]);
    assert_eq!(got[0].1, run.concat());
    assert_eq!(got[1].1, tail[0]);
}

#[test]
fn ipv6_sockets_set_v6only_from_the_dual_stack_option() {
    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let dual = socket::open(any6, None, &SocketOptions::default()).expect("dual-stack");
    assert!(!dual.only_v6().unwrap());
    let options = SocketOptions {
        dual_stack: false,
        ..SocketOptions::default()
    };
    let v6only = socket::open(any6, None, &options).expect("v6only");
    assert!(v6only.only_v6().unwrap());
}

#[test]
fn a_dual_stack_backend_receives_ipv4_and_ipv6_with_canonical_addresses() {
    let rt = runtime();
    let _guard = rt.enter();
    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let mut backend = MmsgBackend::bind(any6, &MmsgOptions::default()).expect("bind");
    let port = backend.local_addr().unwrap().port();

    let from4 = sender_with_tos(v4(0), 0b11);
    from4.send_to(&[4; 20], v4(port)).unwrap();
    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0.src, from4.local_addr().unwrap());
    assert_eq!(got[0].0.dst_ip, Some(IpAddr::from(Ipv4Addr::LOCALHOST)));
    assert_eq!(got[0].0.ecn, Ecn::Ce);

    let loop6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let from6 = sender_with_tos(loop6, 0b01);
    from6
        .send_to(&[6; 20], SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
        .unwrap();
    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0.src, from6.local_addr().unwrap());
    assert_eq!(got[0].0.dst_ip, Some(IpAddr::from(Ipv6Addr::LOCALHOST)));
    assert_eq!(got[0].0.ecn, Ecn::Ect1);
}

#[test]
fn reuse_port_lets_two_sockets_share_a_port_only_when_asked() {
    let shared = SocketOptions::default();
    assert!(shared.reuse_port);
    let first = socket::open(v4(0), None, &shared).expect("first");
    let addr = first.local_addr().unwrap().as_socket().unwrap();
    let second = socket::open(addr, None, &shared).expect("second with SO_REUSEPORT");
    assert_eq!(second.local_addr().unwrap().as_socket(), Some(addr));

    let exclusive = SocketOptions {
        reuse_port: false,
        ..SocketOptions::default()
    };
    let lone = socket::open(v4(0), None, &exclusive).expect("lone");
    let addr = lone.local_addr().unwrap().as_socket().unwrap();
    let err = socket::open(addr, None, &exclusive).expect_err("port is taken");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

#[test]
fn buffer_sizes_come_from_options_and_default_to_the_kernel() {
    let plain = UdpSocket::bind(v4(0)).unwrap();
    let plain = Socket::from(std::os::fd::OwnedFd::from(plain));
    let default = socket::open(v4(0), None, &SocketOptions::default()).unwrap();
    assert_eq!(
        default.recv_buffer_size().unwrap(),
        plain.recv_buffer_size().unwrap()
    );
    assert_eq!(
        default.send_buffer_size().unwrap(),
        plain.send_buffer_size().unwrap()
    );

    let options = SocketOptions {
        recv_buffer: Some(300_000),
        send_buffer: Some(150_000),
        ..SocketOptions::default()
    };
    let sized = socket::open(v4(0), None, &options).unwrap();
    // Linux doubles the value to account for its bookkeeping (socket(7)).
    assert_eq!(sized.recv_buffer_size().unwrap(), 600_000);
    assert_eq!(sized.send_buffer_size().unwrap(), 300_000);
}

#[test]
fn sends_a_datagram_and_reports_it_flushed() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let peer = receiver(v4(0));
    let segments = vec![vec![9; 300]];
    send_run(
        &mut backend,
        conn(1),
        &segments,
        meta(peer.local_addr().unwrap(), &segments, 7),
    );
    let out = backend.flush(Instant::now());
    assert_eq!(
        out,
        FlushOutcome {
            datagrams: 1,
            blocked: false
        }
    );

    let got = recv_plain(&peer, 1);
    assert_eq!(got[0], (backend.local_addr().unwrap(), vec![9; 300]));
    assert_eq!(
        reports(&mut backend),
        vec![(
            conn(1),
            TxReport::Flushed {
                tx: TxSeqRange { start: 7, end: 8 }
            }
        )]
    );
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

#[test]
fn a_gso_run_with_a_short_last_segment_round_trips_through_gro() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let run = segments(7, 1452, 300);
    send_run(&mut sender, conn(3), &run, meta(to, &run, 100));
    assert_eq!(sender.flush(Instant::now()).datagrams, 7);

    let got = recv_batch(&rt, &mut receiver);
    assert_eq!(got.len(), 1, "one GRO buffer");
    assert_eq!(got[0].0.src, sender.local_addr().unwrap());
    assert_eq!(got[0].0.stride, 1452);
    assert_eq!(got[0].1, run.concat());
    assert_eq!(
        reports(&mut sender),
        vec![(
            conn(3),
            TxReport::Flushed {
                tx: TxSeqRange {
                    start: 100,
                    end: 107
                }
            }
        )]
    );
}

#[test]
fn a_run_that_breaks_the_size_rule_is_split_into_several_sends() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let run = vec![
        vec![1; 50],
        vec![2; 1200],
        vec![3; 1200],
        vec![4; 800],
        vec![5; 1200],
    ];
    send_run(&mut sender, conn(4), &run, meta(to, &run, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams, 5);

    let mut got = Vec::new();
    while got
        .iter()
        .map(|(_, d): &(RxMeta, Vec<u8>)| d.len())
        .sum::<usize>()
        < 4450
    {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let shapes: Vec<_> = got.iter().map(|(m, d)| (m.stride, d.len())).collect();
    assert_eq!(shapes, vec![(50, 50), (1200, 3200), (1200, 1200)]);
    assert_eq!(
        got.iter().flat_map(|(_, d)| d.clone()).collect::<Vec<_>>(),
        run.concat()
    );
    assert_eq!(
        reports(&mut sender),
        vec![(
            conn(4),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 5 }
            }
        )]
    );
}

#[test]
fn a_run_longer_than_max_segments_is_split_at_the_limit() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let max = usize::from(sender.caps().max_segments);
    let run = segments(max + 2, 100, 100);
    send_run(&mut sender, conn(5), &run, meta(to, &run, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams as usize, max + 2);

    let mut got = Vec::new();
    while got
        .iter()
        .map(|(_, d): &(RxMeta, Vec<u8>)| d.len())
        .sum::<usize>()
        < (max + 2) * 100
    {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let shapes: Vec<_> = got.iter().map(|(m, d)| (m.stride, d.len())).collect();
    assert_eq!(shapes, vec![(100, max * 100), (100, 200)]);
    assert_eq!(
        got.iter().flat_map(|(_, d)| d.clone()).collect::<Vec<_>>(),
        run.concat()
    );
}

#[test]
fn a_run_over_the_gso_byte_limit_is_split() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    // 60 x 1,452 bytes is more than the 65,507 bytes of payload one IPv4 UDP send carries;
    // 45 segments fit.
    let run = segments(60, 1452, 1452);
    send_run(&mut sender, conn(6), &run, meta(to, &run, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams, 60);

    let mut got = Vec::new();
    while got
        .iter()
        .map(|(_, d): &(RxMeta, Vec<u8>)| d.len())
        .sum::<usize>()
        < 60 * 1452
    {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let shapes: Vec<_> = got.iter().map(|(m, d)| (m.stride, d.len())).collect();
    assert_eq!(shapes, vec![(1452, 45 * 1452), (1452, 15 * 1452)]);
    assert_eq!(
        got.iter().flat_map(|(_, d)| d.clone()).collect::<Vec<_>>(),
        run.concat()
    );
}

#[test]
fn each_run_carries_its_own_tos() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    for (seq, tos) in [(0, 46 << 2 | 0b10), (1, 0b11), (2, 0)] {
        let run = vec![vec![seq as u8; 64]];
        send_run(
            &mut sender,
            conn(7),
            &run,
            TxMeta {
                tos,
                ..meta(to, &run, seq)
            },
        );
    }
    sender.flush(Instant::now());

    let mut got = Vec::new();
    while got.len() < 3 {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let ecn: Vec<_> = got.iter().map(|(m, _)| m.ecn).collect();
    assert_eq!(ecn, vec![Ecn::Ect0, Ecn::Ce, Ecn::NotEct]);
}

#[test]
fn one_call_carries_the_runs_of_several_connections_each_with_its_own_tos() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    for (index, tos) in [(1, 0b10), (2, 0b01), (3, 0b10)] {
        let run = vec![vec![index as u8; 64]];
        send_run(
            &mut sender,
            conn(index),
            &run,
            TxMeta {
                tos,
                ..meta(to, &run, 0)
            },
        );
    }
    assert_eq!(sender.flush(Instant::now()).datagrams, 3);

    let mut got = Vec::new();
    while got.len() < 3 {
        got.extend(recv_batch(&rt, &mut receiver));
    }
    let seen: Vec<_> = got.iter().map(|(m, d)| (d[0], m.ecn)).collect();
    assert_eq!(seen, vec![(1, Ecn::Ect0), (2, Ecn::Ect1), (3, Ecn::Ect0)]);
    let counted = sender.take_counters();
    assert_eq!(
        (
            counted.calls,
            counted.messages,
            counted.multi_connection_calls
        ),
        (1, 3, 1),
        "one call carried the three connections' runs"
    );
}

#[test]
fn a_dual_stack_sender_sets_tos_for_ipv4_and_ipv6_destinations() {
    let rt = runtime();
    let _guard = rt.enter();
    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let mut sender = MmsgBackend::bind(any6, &MmsgOptions::default()).expect("sender");
    let mut to4 = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("v4 receiver");
    let loop6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let mut to6 = MmsgBackend::bind(loop6, &MmsgOptions::default()).expect("v6 receiver");
    let run = vec![vec![1; 64]];
    let dst4 = to4.local_addr().unwrap();
    let dst6 = to6.local_addr().unwrap();
    send_run(
        &mut sender,
        conn(8),
        &run,
        TxMeta {
            tos: 0b10,
            ..meta(dst4, &run, 0)
        },
    );
    send_run(
        &mut sender,
        conn(8),
        &run,
        TxMeta {
            tos: 0b01,
            ..meta(dst6, &run, 1)
        },
    );
    assert_eq!(sender.flush(Instant::now()).datagrams, 2);

    let got4 = recv_batch(&rt, &mut to4);
    assert_eq!(got4[0].0.ecn, Ecn::Ect0);
    assert_eq!(got4[0].0.src.port(), sender.local_addr().unwrap().port());
    assert!(got4[0].0.src.is_ipv4());
    let got6 = recv_batch(&rt, &mut to6);
    assert_eq!(got6[0].0.ecn, Ecn::Ect1);
}

#[test]
fn tos_zero_is_sent_as_zero_whatever_the_socket_default() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut to4 = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("v4 receiver");
    let loop6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let mut to6 = MmsgBackend::bind(loop6, &MmsgOptions::default()).expect("v6 receiver");
    let dst4 = to4.local_addr().unwrap();
    let dst6 = to6.local_addr().unwrap();
    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    for local in [v4(0), any6] {
        // A socket from elsewhere whose own TOS and traffic class mark everything CE.
        let socket = Socket::new(Domain::for_address(local), Type::DGRAM, None).unwrap();
        socket.set_tos_v4(0b11).unwrap();
        if local.is_ipv6() {
            socket.set_only_v6(false).unwrap();
            socket.set_tclass_v6(0b11).unwrap();
        }
        socket.bind(&local.into()).unwrap();
        let mut sender = MmsgBackend::from_socket(socket, &MmsgOptions::default()).expect("wrap");
        let run = vec![vec![1; 64]];
        let mut receivers = vec![(dst4, &mut to4)];
        if local.is_ipv6() {
            receivers.push((dst6, &mut to6));
        }
        for (seq, (dst, _)) in receivers.iter().enumerate() {
            send_run(&mut sender, conn(26), &run, meta(*dst, &run, seq as u64));
        }
        sender.flush(Instant::now());
        for (dst, receiver) in receivers {
            let got = recv_batch(&rt, receiver);
            assert_eq!(got[0].0.ecn, Ecn::NotEct, "{local} to {dst}");
        }
    }
}

#[test]
fn each_run_can_choose_its_source_address() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let run = vec![vec![1; 64]];

    let any4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let mut sender4 = MmsgBackend::bind(any4, &MmsgOptions::default()).expect("v4 sender");
    let src = IpAddr::from([127, 0, 0, 2]);
    send_run(
        &mut sender4,
        conn(9),
        &run,
        TxMeta {
            src_ip: Some(src),
            ..meta(to, &run, 0)
        },
    );
    sender4.flush(Instant::now());
    let got = recv_batch(&rt, &mut receiver);
    assert_eq!(got[0].0.src.ip(), src);

    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let mut sender6 = MmsgBackend::bind(any6, &MmsgOptions::default()).expect("v6 sender");
    let src = IpAddr::from([127, 0, 0, 5]);
    send_run(
        &mut sender6,
        conn(9),
        &run,
        TxMeta {
            src_ip: Some(src),
            ..meta(to, &run, 0)
        },
    );
    sender6.flush(Instant::now());
    let got = recv_batch(&rt, &mut receiver);
    assert_eq!(got[0].0.src.ip(), src);
}

#[test]
fn the_backend_flushes_on_its_own_when_its_vector_fills() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        tx_batch: 2,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    for seq in 0..3u8 {
        let run = vec![vec![seq; 10]];
        send_run(&mut sender, conn(10), &run, meta(to, &run, u64::from(seq)));
    }
    // The first two runs filled the vector and left without a flush call.
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);
    let got: Vec<_> = recv_plain(&peer, 3).into_iter().map(|(_, d)| d).collect();
    assert_eq!(got, vec![vec![0; 10], vec![1; 10], vec![2; 10]]);
    assert_eq!(
        reports(&mut sender),
        vec![(
            conn(10),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 3 }
            }
        )]
    );
}

#[test]
fn the_backend_counts_its_sendmmsg_calls_and_the_messages_they_carry() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        tx_batch: 2,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let runs = [vec![vec![0; 10]], segments(3, 10, 10), vec![vec![2; 10]]];
    let mut seq = 0;
    for run in &runs {
        send_run(&mut sender, conn(10), run, meta(to, run, seq));
        seq += run.len() as u64;
    }
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);
    assert_eq!(recv_plain(&peer, 5).len(), 5);

    // The first two runs, one a GSO send of three datagrams, filled the vector and left in one
    // call; the flush sent the third in a second.
    let counted = sender.take_counters();
    assert_eq!(
        (
            counted.calls,
            counted.messages,
            counted.multi_connection_calls
        ),
        (2, 3, 0)
    );
    assert_eq!(
        sender.take_counters(),
        TxCounters::default(),
        "taking the counters starts them again from zero"
    );
}

#[test]
fn the_backend_flushes_on_its_own_when_its_pool_runs_out() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        tx_slots: 4,
        urgent_slots: 0,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    for seq in 0..5u8 {
        let run = vec![vec![seq; 10]];
        send_run(&mut sender, conn(11), &run, meta(to, &run, u64::from(seq)));
    }
    // Lending the fifth slot flushed the four queued runs first.
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);
    let got: Vec<_> = recv_plain(&peer, 5).into_iter().map(|(_, d)| d).collect();
    assert_eq!(got, (0..5u8).map(|i| vec![i; 10]).collect::<Vec<_>>());
}

/// Takes a `len`-byte slot if the sink lends one, and ends it with a datagram of that size.
fn take(sink: &mut impl SegmentSink, len: u16, class: TxClass) -> bool {
    let lent = sink.next_segment(len, class).is_some();
    if lent {
        sink.end_segment(len);
    }
    lent
}

#[test]
fn the_pool_keeps_slots_that_only_urgent_segments_may_take() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        tx_slots: 6,
        urgent_slots: 2,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let to = v4(9);
    let mut sink = sender.sink(conn(12));
    for _ in 0..4 {
        assert!(take(&mut sink, 100, TxClass::Data));
    }
    assert!(
        !take(&mut sink, 100, TxClass::Data),
        "data may not take the reserve"
    );
    assert!(take(&mut sink, 100, TxClass::Urgent));
    assert!(take(&mut sink, 100, TxClass::Urgent));
    assert!(!take(&mut sink, 100, TxClass::Urgent), "the pool is empty");
    let run = segments(6, 100, 100);
    sink.end_run(meta(to, &run, 0));
}

#[test]
fn a_connection_is_refused_data_beyond_max_unsent_bytes_until_a_flush() {
    let rt = runtime();
    let _guard = rt.enter();
    assert_eq!(MmsgOptions::default().max_unsent, 128 * 1024);
    let options = MmsgOptions {
        max_unsent: 3000,
        urgent_slots: 1,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let first = segments(2, 1000, 1000);
    send_run(&mut sender, conn(28), &first, meta(to, &first, 0));

    let mut sink = sender.sink(conn(28));
    assert!(
        take(&mut sink, 1000, TxClass::Data),
        "3,000 bytes is the limit"
    );
    assert!(
        !take(&mut sink, 1000, TxClass::Data),
        "4,000 bytes would pass it"
    );
    // Urgent segments draw on the connection's quota instead.
    assert!(take(&mut sink, 50, TxClass::Urgent));
    let second = segments(2, 1000, 50);
    sink.end_run(meta(to, &second, 2));
    assert!(!take(&mut sink, 50, TxClass::Urgent), "quota used up");
    drop(sink);

    // Other connections are not held back.
    let other = vec![vec![9; 1000]];
    send_run(&mut sender, conn(29), &other, meta(to, &other, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams, 5);

    let mut sink = sender.sink(conn(28));
    assert!(
        take(&mut sink, 1000, TxClass::Data),
        "the flush sent the bytes"
    );
    let third = vec![vec![0; 1000]];
    sink.end_run(meta(to, &third, 4));
    drop(sink);
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);
    assert_eq!(recv_plain(&peer, 6).len(), 6);
}

#[test]
fn an_unsealed_run_is_dropped_and_reported() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let unsealed = segments(2, 100, 100);
    send_run(
        &mut sender,
        conn(13),
        &unsealed,
        TxMeta {
            sealed: false,
            ..meta(to, &unsealed, 0)
        },
    );
    let sealed = vec![vec![42; 30]];
    send_run(&mut sender, conn(13), &sealed, meta(to, &sealed, 2));
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);

    assert_eq!(recv_plain(&peer, 1)[0].1, vec![42; 30]);
    assert_eq!(
        reports(&mut sender),
        vec![
            (
                conn(13),
                TxReport::Dropped {
                    tx: TxSeqRange { start: 0, end: 2 },
                    reason: DropReason::Error,
                }
            ),
            (
                conn(13),
                TxReport::Flushed {
                    tx: TxSeqRange { start: 2, end: 3 }
                }
            ),
        ]
    );
}

#[test]
fn a_run_the_kernel_rejects_is_dropped_and_later_runs_still_leave() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    // An IPv6 destination on an IPv4 socket fails with EAFNOSUPPORT before anything is sent.
    let unreachable = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
    let rejected = segments(3, 100, 100);
    send_run(
        &mut sender,
        conn(14),
        &rejected,
        meta(unreachable, &rejected, 0),
    );
    let fine = vec![vec![7; 20]];
    send_run(&mut sender, conn(14), &fine, meta(to, &fine, 3));
    assert_eq!(sender.flush(Instant::now()).datagrams, 1);

    assert_eq!(recv_plain(&peer, 1)[0].1, vec![7; 20]);
    assert_eq!(
        reports(&mut sender),
        vec![
            (
                conn(14),
                TxReport::Dropped {
                    tx: TxSeqRange { start: 0, end: 3 },
                    reason: DropReason::Error,
                }
            ),
            (
                conn(14),
                TxReport::Flushed {
                    tx: TxSeqRange { start: 3, end: 4 }
                }
            ),
        ]
    );
}

#[test]
fn after_partial_progress_the_rest_of_the_call_goes_again() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    // An IPv6 destination on an IPv4 socket fails with EAFNOSUPPORT, so the kernel accepts only
    // the first of the three messages.
    let unreachable = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
    for (index, dst) in [(1, to), (2, unreachable), (3, to)] {
        let run = vec![vec![index as u8; 20]];
        send_run(&mut sender, conn(index), &run, meta(dst, &run, 0));
    }
    assert_eq!(sender.flush(Instant::now()).datagrams, 2);

    let got: Vec<_> = recv_plain(&peer, 2).into_iter().map(|(_, d)| d).collect();
    assert_eq!(got, vec![vec![1; 20], vec![3; 20]]);
    let tx = TxSeqRange { start: 0, end: 1 };
    assert_eq!(
        reports(&mut sender),
        vec![
            (conn(1), TxReport::Flushed { tx }),
            (
                conn(2),
                TxReport::Dropped {
                    tx,
                    reason: DropReason::Error
                }
            ),
            (conn(3), TxReport::Flushed { tx }),
        ]
    );
    let counted = sender.take_counters();
    assert_eq!(
        (
            counted.calls,
            counted.messages,
            counted.multi_connection_calls
        ),
        (3, 2, 0),
        "the first call took one message, the second failed on the next, the third took the last"
    );
}

/// Opens a backend on a socket that sends without UDP checksums (SO_NO_CHECK). The kernel needs
/// checksums for GSO, so it refuses every GSO send from the socket with EINVAL and sends single
/// datagrams.
fn gso_refusing_backend() -> MmsgBackend {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    let on: libc::c_int = 1;
    // SAFETY: the kernel reads `len` bytes from `on`, which is live.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NO_CHECK,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    socket.bind(&v4(0).into()).unwrap();
    let backend = MmsgBackend::from_socket(socket, &MmsgOptions::default()).expect("backend");
    assert!(backend.caps().max_segments > 1, "the kernel offers GSO");
    backend
}

#[test]
fn a_gso_send_the_kernel_refuses_goes_again_as_single_datagrams() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = gso_refusing_backend();
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let run = segments(3, 100, 40);
    send_run(&mut sender, conn(15), &run, meta(to, &run, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams, 3);

    let got: Vec<_> = recv_plain(&peer, 3).into_iter().map(|(_, d)| d).collect();
    assert_eq!(got, run);
    assert_eq!(
        reports(&mut sender),
        vec![(
            conn(15),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 3 }
            }
        )]
    );
    let counted = sender.take_counters();
    assert_eq!(
        (
            counted.calls,
            counted.messages,
            counted.gso_retries,
            counted.gso_disabled
        ),
        (2, 3, 1, 0),
        "the refused GSO send, then one call with its three datagrams"
    );
}

#[test]
fn after_three_refused_gso_sends_the_socket_sends_without_gso() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = gso_refusing_backend();
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let run = segments(3, 100, 40);
    let mut flush = |conns: &[u32]| {
        for &index in conns {
            send_run(&mut sender, conn(index), &run, meta(to, &run, 0));
        }
        let datagrams = sender.flush(Instant::now()).datagrams as usize;
        assert_eq!(recv_plain(&peer, datagrams).len(), 3 * conns.len());
        let counted = sender.take_counters();
        (
            counted.calls,
            counted.messages,
            counted.gso_retries,
            counted.gso_disabled,
        )
    };

    assert_eq!(flush(&[16]), (2, 3, 1, 0), "the first refusal");
    assert_eq!(flush(&[16]), (2, 3, 1, 0), "the second refusal");
    // The kernel takes the third refused send's datagrams but refuses the GSO send behind them
    // without an error, as it reports one only for a call's first message.
    assert_eq!(
        flush(&[16, 17]),
        (3, 6, 1, 1),
        "the third refusal turns GSO off once its datagrams leave, for the run queued behind it too"
    );
    assert_eq!(
        flush(&[16]),
        (1, 3, 0, 0),
        "a later run leaves as single datagrams without a refusal"
    );
}

#[test]
fn gso_sends_refused_for_a_cause_their_datagrams_share_never_turn_gso_off() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    assert!(sender.caps().max_segments > 1, "the kernel offers GSO");
    let peer = receiver(v4(0));
    let to = peer.local_addr().unwrap();
    let run = segments(3, 100, 40);
    // The kernel refuses every send to port 0 with EINVAL, GSO or not.
    for refused in 1..=4 {
        send_run(&mut sender, conn(18), &run, meta(v4(0), &run, 0));
        assert_eq!(sender.flush(Instant::now()).datagrams, 0);
        let dropped = |start| {
            (
                conn(18),
                TxReport::Dropped {
                    tx: TxSeqRange {
                        start,
                        end: start + 1,
                    },
                    reason: DropReason::Error,
                },
            )
        };
        assert_eq!(
            reports(&mut sender),
            vec![dropped(0), dropped(1), dropped(2)]
        );
        let counted = sender.take_counters();
        assert_eq!(
            (
                counted.calls,
                counted.messages,
                counted.gso_retries,
                counted.gso_disabled
            ),
            (4, 0, 1, 0),
            "refusal {refused}: the GSO send, then each of its datagrams alone"
        );
    }
    send_run(&mut sender, conn(18), &run, meta(to, &run, 0));
    assert_eq!(sender.flush(Instant::now()).datagrams, 3);
    assert_eq!(recv_plain(&peer, 3).len(), 3);
    let counted = sender.take_counters();
    assert_eq!(
        (
            counted.calls,
            counted.messages,
            counted.gso_retries,
            counted.gso_disabled
        ),
        (1, 1, 0, 0),
        "the socket still sends a run as one GSO send"
    );
}

/// Opens a backend on one end of a connected Unix datagram pair whose send buffer is as small as
/// the kernel allows. Loopback UDP never returns EAGAIN, because the loopback device detaches each
/// datagram from its socket as it sends it; a Unix datagram stays charged to the sender's SO_SNDBUF
/// until the peer reads it, so a few unread datagrams block the sender.
fn blocked_pair(options: &MmsgOptions) -> (MmsgBackend, UnixDatagram) {
    let (a, b) = UnixDatagram::pair().unwrap();
    let a = Socket::from(std::os::fd::OwnedFd::from(a));
    a.set_send_buffer_size(1).unwrap();
    b.set_read_timeout(Some(HANG_GUARD)).unwrap();
    (MmsgBackend::from_socket(a, options).expect("backend"), b)
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

#[test]
fn eagain_keeps_runs_queued_refuses_data_and_loses_nothing() {
    let rt = runtime();
    let _guard = rt.enter();
    let (mut backend, peer) = blocked_pair(&MmsgOptions::default());
    let to = v4(9);
    let runs: Vec<_> = (0..20u8).map(|i| vec![vec![i; 1000]]).collect();
    for (seq, run) in runs.iter().enumerate() {
        send_run(&mut backend, conn(15), run, meta(to, run, seq as u64));
    }
    let out = backend.flush(Instant::now());
    assert!(out.blocked, "{out:?}");
    let sent = out.datagrams as u64;
    assert!(sent > 0 && sent < 20, "{out:?}");
    assert_eq!(
        reports(&mut backend),
        vec![(
            conn(15),
            TxReport::Flushed {
                tx: TxSeqRange {
                    start: 0,
                    end: sent
                }
            }
        )]
    );
    assert!(
        backend
            .sink(conn(15))
            .next_segment(1000, TxClass::Data)
            .is_none()
    );

    let mut got = drain_peer(&peer);
    while got.len() < 20 {
        backend.flush(Instant::now());
        got.extend(drain_peer(&peer));
    }
    assert!(!backend.flush(Instant::now()).blocked);
    assert_eq!(got, runs.concat());
    assert_eq!(
        reports(&mut backend),
        vec![(
            conn(15),
            TxReport::Flushed {
                tx: TxSeqRange {
                    start: sent,
                    end: 20
                }
            }
        )]
    );
}

#[test]
fn while_blocked_each_connection_keeps_a_small_urgent_quota() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        urgent_slots: 2,
        ..MmsgOptions::default()
    };
    let (mut backend, peer) = blocked_pair(&options);
    let to = v4(9);
    let data: Vec<_> = (0..10u8).map(|i| vec![vec![i; 1000]]).collect();
    for (seq, run) in data.iter().enumerate() {
        send_run(&mut backend, conn(16), run, meta(to, run, seq as u64));
    }
    assert!(backend.flush(Instant::now()).blocked);

    // Connection 16 may queue two urgent datagrams, connection 17 two more.
    for (key, first_seq) in [(conn(16), 10), (conn(17), 0)] {
        let mut sink = backend.sink(key);
        assert!(take(&mut sink, 50, TxClass::Urgent));
        assert!(take(&mut sink, 50, TxClass::Urgent));
        assert!(!take(&mut sink, 50, TxClass::Urgent), "quota used up");
        let urgent = segments(2, 50, 50);
        sink.end_run(TxMeta {
            class: TxClass::Urgent,
            ..meta(to, &urgent, first_seq)
        });
    }

    let mut got = drain_peer(&peer);
    while got.len() < 14 {
        backend.flush(Instant::now());
        got.extend(drain_peer(&peer));
    }
    let lens: Vec<_> = got.iter().map(Vec::len).collect();
    assert_eq!(
        lens,
        [vec![1000; 10], vec![50; 4]].concat(),
        "urgent runs leave behind the backlog"
    );
    let mut sink = backend.sink(conn(16));
    assert!(take(&mut sink, 50, TxClass::Urgent));
    assert!(take(&mut sink, 50, TxClass::Urgent));
    assert!(
        take(&mut sink, 50, TxClass::Urgent),
        "the quota is gone with the backlog"
    );
    let urgent = segments(3, 50, 50);
    sink.end_run(TxMeta {
        class: TxClass::Urgent,
        ..meta(to, &urgent, 12)
    });
}

#[test]
fn poll_writable_waits_for_the_socket_and_sends_the_backlog() {
    let rt = runtime();
    let _guard = rt.enter();
    let (mut backend, peer) = blocked_pair(&MmsgOptions::default());
    let to = v4(9);
    let runs: Vec<_> = (0..20u8).map(|i| vec![vec![i; 1000]]).collect();
    for (seq, run) in runs.iter().enumerate() {
        send_run(&mut backend, conn(18), run, meta(to, run, seq as u64));
    }
    assert!(backend.flush(Instant::now()).blocked);
    let pending = rt.block_on(poll_fn(|cx| {
        Poll::Ready(backend.poll_writable(cx).is_pending())
    }));
    assert!(pending, "nothing has drained yet");

    let reader = std::thread::spawn(move || {
        let mut buf = vec![0; 65_536];
        (0..20)
            .map(|_| {
                let len = peer.recv(&mut buf).expect("datagram");
                buf[..len].to_vec()
            })
            .collect::<Vec<_>>()
    });
    rt.block_on(tokio::time::timeout(
        HANG_GUARD,
        poll_fn(|cx| backend.poll_writable(cx)),
    ))
    .expect("hang guard");
    assert_eq!(
        backend.flush(Instant::now()),
        FlushOutcome {
            datagrams: 0,
            blocked: false
        }
    );
    assert_eq!(reader.join().unwrap(), runs.concat());
    assert_eq!(
        reports(&mut backend),
        vec![(
            conn(18),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 20 }
            }
        )]
    );
    let mut sink = backend.sink(conn(18));
    assert!(sink.next_segment(1000, TxClass::Data).is_some());
    sink.end_segment(0);
}

#[test]
fn a_connected_client_backend_talks_only_to_its_server() {
    let rt = runtime();
    let _guard = rt.enter();
    for server_addr in [v4(0), SocketAddr::from((Ipv6Addr::LOCALHOST, 0))] {
        let mut server = MmsgBackend::bind(server_addr, &MmsgOptions::default()).expect("server");
        let server_addr = server.local_addr().unwrap();
        let mut client =
            MmsgBackend::connect(server_addr, &MmsgOptions::default()).expect("client");
        let client_addr = client.local_addr().unwrap();
        assert_eq!(client_addr.is_ipv4(), server_addr.is_ipv4());

        let hello = segments(3, 1200, 200);
        send_run(&mut client, conn(19), &hello, meta(server_addr, &hello, 0));
        assert_eq!(client.flush(Instant::now()).datagrams, 3);
        let got = recv_batch(&rt, &mut server);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.src.port(), client_addr.port());
        assert_eq!(got[0].1, hello.concat());

        // A stranger's datagram never reaches the connected socket; the server's reply does.
        let stranger = UdpSocket::bind(SocketAddr::new(server_addr.ip(), 0)).unwrap();
        stranger.send_to(&[0xee; 10], got[0].0.src).unwrap();
        let reply = vec![vec![0x5a; 40]];
        send_run(&mut server, conn(20), &reply, meta(got[0].0.src, &reply, 0));
        server.flush(Instant::now());
        let got = recv_batch(&rt, &mut client);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.src, server_addr);
        assert_eq!(got[0].1, reply.concat());
    }
}

#[test]
fn datagrams_larger_than_a_receive_buffer_are_discarded() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        rx_buffer: 64,
        ..MmsgOptions::default()
    };
    let mut backend = MmsgBackend::bind(v4(0), &options).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    sender.send_to(&[1; 100], to).unwrap();
    sender.send_to(&[2; 10], to).unwrap();

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].1, vec![2; 10]);
}

#[test]
fn empty_datagrams_are_skipped() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    sender.send_to(&[], to).unwrap();
    sender.send_to(&[3; 5], to).unwrap();

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].1, vec![3; 5]);
    assert_eq!(got[0].0.stride, 5);
}

#[test]
fn a_batch_of_only_discarded_datagrams_does_not_end_the_poll() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        rx_batch: 1,
        rx_buffer: 64,
        ..MmsgOptions::default()
    };
    let mut backend = MmsgBackend::bind(v4(0), &options).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    sender.send_to(&[1; 100], to).unwrap();
    sender.send_to(&[2; 10], to).unwrap();

    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].1, vec![2; 10]);
}

#[test]
fn a_flood_of_discarded_datagrams_still_yields_to_the_scheduler() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        rx_batch: 1,
        ..MmsgOptions::default()
    };
    let mut backend = MmsgBackend::bind(v4(0), &options).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    sender.send_to(&[1], to).unwrap();
    for _ in 0..300 {
        sender.send_to(&[], to).unwrap();
    }
    sender.send_to(&[2], to).unwrap();
    // Wait until the socket is marked readable, then poll once with a fresh task budget.
    assert_eq!(recv_batch(&rt, &mut backend)[0].1, vec![1]);
    let yielded = rt.block_on(poll_fn(|cx| {
        Poll::Ready(backend.poll_recv(cx).is_pending())
    }));
    assert!(yielded, "read 300 empty datagrams in one task poll");
    let got = recv_batch(&rt, &mut backend);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, vec![2]);
}

#[test]
fn a_connected_backend_absorbs_icmp_errors_on_receive() {
    let rt = runtime();
    let _guard = rt.enter();
    let closed = UdpSocket::bind(v4(0)).unwrap();
    let port = closed.local_addr().unwrap();
    drop(closed);
    let mut client = MmsgBackend::connect(port, &MmsgOptions::default()).expect("client");
    // The port is closed, so the kernel answers with port unreachable, which leaves ECONNREFUSED
    // pending on the connected socket.
    let probe = vec![vec![1; 20]];
    send_run(&mut client, conn(21), &probe, meta(port, &probe, 0));
    client.flush(Instant::now());

    let mut server = MmsgBackend::bind(port, &MmsgOptions::default()).expect("server on the port");
    let reply = vec![vec![2; 20]];
    send_run(
        &mut server,
        conn(22),
        &reply,
        meta(client.local_addr().unwrap(), &reply, 0),
    );
    server.flush(Instant::now());

    let got = recv_batch(&rt, &mut client);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, vec![2; 20]);
}

#[test]
fn a_busy_socket_yields_to_the_scheduler_when_the_task_budget_is_spent() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        rx_batch: 1,
        ..MmsgOptions::default()
    };
    let mut backend = MmsgBackend::bind(v4(0), &options).expect("bind");
    let to = backend.local_addr().unwrap();
    let sender = UdpSocket::bind(v4(0)).unwrap();
    for i in 0..300u16 {
        sender.send_to(&i.to_be_bytes(), to).unwrap();
    }
    // Wait until the socket is marked readable, then count receives in one task poll.
    recv_batch(&rt, &mut backend);
    let in_one_poll = rt.block_on(poll_fn(|cx| {
        let mut n = 1;
        while let Poll::Ready(result) = backend.poll_recv(cx) {
            result.expect("recv");
            n += 1;
        }
        Poll::Ready(n)
    }));
    assert!(in_one_poll < 300, "received {in_one_poll} without yielding");
    let mut total = in_one_poll;
    while total < 300 {
        total += recv_batch(&rt, &mut backend).len();
    }
    assert_eq!(total, 300);
}

#[test]
fn options_the_backend_cannot_work_with_are_refused() {
    let rt = runtime();
    let _guard = rt.enter();
    let base = MmsgOptions::default();
    let bad = [
        MmsgOptions {
            max_datagram: 0,
            ..base.clone()
        },
        MmsgOptions {
            max_datagram: 65_528,
            ..base.clone()
        },
        MmsgOptions {
            tx_slots: 4,
            urgent_slots: 4,
            ..base.clone()
        },
        MmsgOptions {
            max_unsent: 1499,
            ..base.clone()
        },
        MmsgOptions {
            tx_batch: 0,
            ..base.clone()
        },
        MmsgOptions {
            tx_batch: 1025,
            ..base.clone()
        },
        MmsgOptions {
            rx_batch: 0,
            ..base.clone()
        },
        MmsgOptions {
            rx_buffer: 0,
            ..base.clone()
        },
    ];
    for options in bad {
        let err = MmsgBackend::bind(v4(0), &options).err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::InvalidInput),
            "{options:?}"
        );
    }
}

#[test]
fn opening_a_backend_outside_a_runtime_is_an_error() {
    let err = MmsgBackend::bind(v4(0), &MmsgOptions::default()).err();
    assert!(err.is_some());
}

#[test]
fn a_slot_lent_but_never_ended_returns_to_the_pool() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        tx_slots: 2,
        urgent_slots: 0,
        ..MmsgOptions::default()
    };
    let mut backend = MmsgBackend::bind(v4(0), &options).expect("bind");
    for _ in 0..5 {
        // Lent, then the sink is dropped.
        assert!(
            backend
                .sink(conn(23))
                .next_segment(100, TxClass::Data)
                .is_some()
        );
    }
    let mut sink = backend.sink(conn(23));
    for _ in 0..5 {
        // Lent, then `next_segment` is called again without ending it.
        assert!(sink.next_segment(100, TxClass::Data).is_some());
    }
}

#[test]
fn slots_have_the_asked_length_and_an_abandoned_slot_leaves_the_run_open() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut sender = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let mut sink = sender.sink(conn(24));
    assert_eq!(
        sink.next_segment(2000, TxClass::Data).unwrap().1.len(),
        1500
    );
    sink.end_segment(0);
    let run = segments(3, 1200, 500);
    let fill = |sink: &mut MmsgSink<'_>, data: &[u8]| {
        let (_, slot) = sink.next_segment(1200, TxClass::Data).unwrap();
        assert_eq!(slot.len(), 1200);
        slot[..data.len()].copy_from_slice(data);
        sink.end_segment(data.len() as u16);
    };
    fill(&mut sink, &run[0]);
    // A slot abandoned in the middle of a run is not part of it.
    assert!(sink.next_segment(1200, TxClass::Data).is_some());
    sink.end_segment(0);
    fill(&mut sink, &run[1]);
    fill(&mut sink, &run[2]);
    sink.end_run(meta(to, &run, 0));
    drop(sink);
    assert_eq!(sender.flush(Instant::now()).datagrams, 3);

    let got = recv_batch(&rt, &mut receiver);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0.stride, got[0].1.clone()), (1200, run.concat()));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "open run")]
fn dropping_a_sink_with_an_open_run_is_a_caller_bug() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let mut sink = backend.sink(conn(25));
    assert!(take(&mut sink, 100, TxClass::Data));
    drop(sink);
}

/// Reads an integer socket option.
fn get_int(socket: &impl AsRawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes into `value` and updates `len`, both live.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    value
}

#[test]
fn sockets_set_dont_fragment_and_ignore_the_cached_path_mtu() {
    let rt = runtime();
    let _guard = rt.enter();
    let any6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let v6only = SocketOptions {
        dual_stack: false,
        ..SocketOptions::default()
    };
    for (local, options) in [
        (v4(0), SocketOptions::default()),
        (any6, SocketOptions::default()),
        (any6, v6only),
    ] {
        let opened = socket::open(local, None, &options).expect("open");
        // A socket from elsewhere gets the same setting when it is wrapped.
        let plain = Socket::new(Domain::for_address(local), Type::DGRAM, None).unwrap();
        plain
            .set_only_v6(!options.dual_stack && local.is_ipv6())
            .ok();
        plain.bind(&local.into()).unwrap();
        let wrapped = plain.try_clone().unwrap();
        let _backend = MmsgBackend::from_socket(plain, &MmsgOptions::default()).expect("wrap");
        for socket in [&opened, &wrapped] {
            let mut want = vec![(
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )];
            if local.is_ipv6() {
                let v6 = (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_PROBE,
                );
                if options.dual_stack {
                    want.push(v6);
                } else {
                    want = vec![v6];
                }
            }
            for (level, name, value) in want {
                assert_eq!(
                    get_int(socket, level, name),
                    value,
                    "{local} {level}/{name}"
                );
            }
        }
    }
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "TxMeta::segment_size")]
fn a_run_described_with_the_wrong_segment_size_is_a_caller_bug() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let run = segments(2, 100, 100);
    send_run(
        &mut backend,
        conn(27),
        &run,
        TxMeta {
            segment_size: 99,
            ..meta(v4(9), &run, 0)
        },
    );
}

#[test]
fn an_opened_socket_already_asks_for_its_control_messages() {
    for local in [v4(0), SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))] {
        let opened = socket::open(local, None, &SocketOptions::default()).expect("open");
        let caps = socket::probe(&opened, 1500);
        assert!(caps.pktinfo && caps.ecn && caps.gro, "{local}: {caps:?}");
    }
}

/// Returns the socket's SO_TXTIME setting: the clock its stamps are read in, and its flags.
fn txtime_setting(socket: &impl AsRawFd) -> (libc::clockid_t, u32) {
    let mut value = libc::sock_txtime {
        clockid: 0,
        flags: 0,
    };
    let mut len = std::mem::size_of::<libc::sock_txtime>() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes into `value` and updates `len`, both live.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            61,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    (value.clockid, value.flags)
}

/// Returns CLOCK_MONOTONIC in nanoseconds, the clock SO_TXTIME stamps are read in.
fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the kernel writes a `timespec` into `now`, which is live.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
    assert_eq!(rc, 0);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

/// Returns a bound IPv4 loopback socket and a second handle to it.
fn socket_and_watch() -> (Socket, Socket) {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.bind(&v4(0).into()).unwrap();
    let watch = socket.try_clone().unwrap();
    (socket, watch)
}

#[test]
fn txtime_sets_so_txtime_on_the_monotonic_clock_and_reports_kernel_release() {
    let rt = runtime();
    let _guard = rt.enter();
    let (socket, watch) = socket_and_watch();
    let off = MmsgBackend::from_socket(socket, &MmsgOptions::default()).expect("wrap");
    assert_eq!(off.caps().release, ReleaseSupport::None);
    assert_eq!(
        txtime_setting(&watch),
        (libc::CLOCK_REALTIME, 0),
        "without txtime the socket keeps the kernel's default"
    );

    let options = MmsgOptions {
        txtime: true,
        txtime_horizon: Duration::from_millis(7),
        ..MmsgOptions::default()
    };
    let (socket, watch) = socket_and_watch();
    let (before, mono_before) = (Instant::now(), monotonic_ns());
    let on = MmsgBackend::from_socket(socket, &options).expect("wrap with txtime");
    let (after, mono_after) = (Instant::now(), monotonic_ns());
    assert_eq!(txtime_setting(&watch), (libc::CLOCK_MONOTONIC, 0));
    let ReleaseSupport::Kernel { horizon, epoch } = on.caps().release else {
        panic!("kernel release: {:?}", on.caps());
    };
    assert_eq!(horizon, Duration::from_millis(7));
    assert!(
        (before..=after).contains(&epoch.instant),
        "the epoch is sampled as the backend opens"
    );
    assert!(
        (mono_before..=mono_after).contains(&epoch.tick.0),
        "the epoch's tick reads CLOCK_MONOTONIC: {} not in {mono_before}..={mono_after}",
        epoch.tick.0
    );

    let bound = MmsgBackend::bind(v4(0), &options).expect("bind with txtime");
    assert_eq!(bound.caps().release.horizon(), Duration::from_millis(7));
}

#[test]
fn a_client_socket_never_takes_kernel_release() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        txtime: true,
        ..MmsgOptions::default()
    };
    let server = MmsgBackend::bind(v4(0), &options).expect("bind");
    assert_ne!(server.caps().release, ReleaseSupport::None);
    let client =
        <MmsgBackend as Backend>::connect(server.local_addr().unwrap(), &options).expect("connect");
    assert_eq!(
        client.caps().release,
        ReleaseSupport::None,
        "kernel release is server-side: a client connection's horizon is 0"
    );
}

#[test]
fn txtime_that_the_socket_refuses_fails_the_open_with_a_clear_error() {
    let rt = runtime();
    let _guard = rt.enter();
    // Not a socket, so the setsockopt fails, and the open does not fall back to unstamped sends.
    let (reader, _writer) = std::io::pipe().unwrap();
    let not_a_socket = Socket::from(std::os::fd::OwnedFd::from(reader));
    let options = MmsgOptions {
        txtime: true,
        ..MmsgOptions::default()
    };
    let error = MmsgBackend::from_socket(not_a_socket, &options)
        .err()
        .expect("no backend without the kernel release asked for");
    assert!(error.to_string().contains("SO_TXTIME"), "{error}");
    assert_eq!(
        std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error),
        Some(libc::ENOTSOCK),
        "the kernel's refusal is the cause: {error:?}"
    );
}

#[test]
fn a_txtime_horizon_beyond_one_second_is_refused() {
    let rt = runtime();
    let _guard = rt.enter();
    let options = |horizon| MmsgOptions {
        txtime: true,
        txtime_horizon: horizon,
        ..MmsgOptions::default()
    };
    let too_far = options(Duration::from_secs(1) + Duration::from_nanos(1));
    assert_eq!(
        MmsgBackend::bind(v4(0), &too_far).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    let longest = MmsgBackend::bind(v4(0), &options(Duration::from_secs(1))).expect("1 s");
    assert_eq!(longest.caps().release.horizon(), Duration::from_secs(1));
}

#[test]
fn the_caps_report_the_send_buffer_the_kernel_granted() {
    let rt = runtime();
    let _guard = rt.enter();
    let plain = Socket::from(std::os::fd::OwnedFd::from(UdpSocket::bind(v4(0)).unwrap()));
    let default = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    assert_eq!(
        default.caps().send_buffer,
        plain.send_buffer_size().unwrap()
    );
    let sized = MmsgOptions {
        socket: SocketOptions {
            send_buffer: Some(150_000),
            ..SocketOptions::default()
        },
        ..MmsgOptions::default()
    };
    let backend = MmsgBackend::bind(v4(0), &sized).expect("bind");
    // Linux doubles the value asked for, for its bookkeeping (socket(7)).
    assert_eq!(backend.caps().send_buffer, 300_000);
}

#[test]
fn stamped_44_segment_gso_runs_leave_and_arrive_whole() {
    // lo is noqueue, so the kernel takes the stamps and sends at once; fq would hold each run
    // until its stamp.
    let rt = runtime();
    let _guard = rt.enter();
    let options = MmsgOptions {
        txtime: true,
        // Room for the three runs, built ahead of one flush.
        max_unsent: 256 * 1024,
        ..MmsgOptions::default()
    };
    let mut sender = MmsgBackend::bind(v4(0), &options).expect("sender");
    let mut receiver = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("receiver");
    let to = receiver.local_addr().unwrap();
    let epoch = sender.caps().release.epoch().expect("kernel release");
    let start = Instant::now();
    let runs: Vec<Vec<Vec<u8>>> = (0..3).map(|i| segments(44, 1452, 1452 - i)).collect();
    for (i, run) in runs.iter().enumerate() {
        let release = epoch.tick_at(start + Duration::from_micros(209 * i as u64));
        let stamped = TxMeta {
            release: Release::At(release),
            ..meta(to, run, 44 * i as u64)
        };
        send_run(&mut sender, conn(30), run, stamped);
    }
    assert_eq!(sender.flush(Instant::now()).datagrams, 3 * 44);
    assert_eq!(
        reports(&mut sender),
        vec![(
            conn(30),
            TxReport::Flushed {
                tx: TxSeqRange { start: 0, end: 132 }
            }
        )]
    );

    let want: Vec<u8> = runs.concat().concat();
    let mut got = Vec::new();
    while got.len() < want.len() {
        for (_, data) in recv_batch(&rt, &mut receiver) {
            got.extend(data);
        }
    }
    assert_eq!(got, want);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "TxMeta::release")]
fn a_release_time_on_a_backend_without_release_support_is_a_caller_bug() {
    let rt = runtime();
    let _guard = rt.enter();
    let mut backend = MmsgBackend::bind(v4(0), &MmsgOptions::default()).expect("bind");
    let run = segments(1, 100, 100);
    send_run(
        &mut backend,
        conn(31),
        &run,
        TxMeta {
            release: Release::At(mvfstr_proto::Tick(1)),
            ..meta(v4(9), &run, 0)
        },
    );
}
