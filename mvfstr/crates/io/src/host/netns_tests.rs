/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of IP_RECVERR, per-message ENOBUFS accounting and the ICMP error-queue drain against a
//! real fq qdisc and real ICMP errors. They run only in the throwaway pair of network namespaces
//! that `crates/io/tests/netns/run.sh` builds; a plain `cargo test` skips them.
//!
//! The rig: this namespace sends through the veth [`DEV`] (10.89.0.1 and fd89::1), whose root qdisc
//! is `fq flow_limit 10` and which carries only the tests' traffic, to a peer namespace at its other
//! end (10.89.0.2 and fd89::2). There a peer discards what reaches [`SINK_PORT`] and sends back what
//! reaches [`ECHO_PORT`]; no socket listens on [`CLOSED_PORT`], so a datagram to it draws an ICMP
//! port unreachable. Neighbours are static, so the first datagrams do not wait in an ARP or ND
//! queue, and the peer's ICMP rate limits are off.

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::MutexGuard;

use mvfstr_proto::DropReason;
use mvfstr_proto::PathId;
use mvfstr_proto::Release;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::Tick;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxSeqRange;

use super::*;
use crate::ReleaseSupport;
use crate::SocketOptions;
use crate::sys;

/// The rig's sending device.
const DEV: &str = "mvr-tx";
/// The peer's IPv4 address.
const PEER4: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 2);
/// The peer's IPv6 address.
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd89, 0, 0, 0, 0, 0, 0, 2);
/// The peer's port that discards what it receives.
const SINK_PORT: u16 = 7001;
/// The peer's port that sends each datagram back to its source.
const ECHO_PORT: u16 = 7002;
/// A port of the peer without a socket.
const CLOSED_PORT: u16 = 7003;

/// Datagrams in a burst.
const BURST: u64 = 200;
/// The burst's runs, alternating: a single datagram, then a GSO send of 9.
const RUNS: [u64; 2] = [1, 9];
/// Bytes per datagram.
const DATAGRAM: usize = 1000;
/// How far ahead of the send a stamped burst's release lies, so that fq holds what it takes.
const HOLD: Duration = Duration::from_millis(100);
/// How long an ICMP error has to reach the socket; it takes well under a millisecond.
const ICMP_WAIT: Duration = Duration::from_secs(2);
/// How long a host poll must not report the socket for it to count as quiet.
const QUIET: Duration = Duration::from_millis(200);
/// Receive rounds a socket gets to fall quiet; one whose readiness is reported on and on never does.
const MAX_ROUNDS: usize = 16;
/// Fails a test that would otherwise hang; passing runs never reach it.
const HANG_GUARD: Duration = Duration::from_secs(20);

/// Serializes the tests, which share the device and its qdisc, whatever the harness's threads.
static RIG: Mutex<()> = Mutex::new(());

/// The socket a test sends from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// An AF_INET socket on 0.0.0.0, sending to the peer's IPv4 address.
    V4,
    /// An IPv6-only AF_INET6 socket on ::, sending to the peer's IPv6 address.
    V6,
    /// A dual-stack AF_INET6 socket on :: (IPV6_V6ONLY 0), sending to the peer's IPv4 address,
    /// which the kernel sends as an IPv4-mapped destination. The address is given in canonical IPv4
    /// form, as the driver passes it.
    Dual,
}

impl Family {
    fn local(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Self::V6 | Self::Dual => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        }
    }

    fn peer(self, port: u16) -> SocketAddr {
        match self {
            Self::V4 | Self::Dual => SocketAddr::from((PEER4, port)),
            Self::V6 => SocketAddr::from((PEER6, port)),
        }
    }
}

/// Takes the rig for one test and checks that this namespace is the rig's sending side.
fn rig() -> MutexGuard<'static, ()> {
    let guard = RIG.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        Path::new("/sys/class/net").join(DEV).exists(),
        "no {DEV} in this network namespace: run crates/io/tests/netns/run.sh"
    );
    let json = tc_json();
    assert!(
        json.contains("\"kind\":\"fq\"") && json_number(&json, "flow_limit") == 10,
        "{DEV} needs a root fq qdisc with flow_limit 10: {json}"
    );
    guard
}

/// Returns `tc -s -j qdisc show dev DEV`.
fn tc_json() -> String {
    let out = Command::new("tc")
        .args(["-s", "-j", "qdisc", "show", "dev", DEV])
        .output()
        .expect("tc runs");
    assert!(
        out.status.success(),
        "tc: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("tc prints UTF-8")
}

/// Returns the first number after `"key":` in tc's JSON.
fn json_number(json: &str, key: &str) -> u64 {
    let pattern = format!("\"{key}\":");
    let at = json
        .find(&pattern)
        .unwrap_or_else(|| panic!("no {pattern} in {json}"))
        + pattern.len();
    let digits: String = json[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("{pattern} is not followed by a number in {json}"))
}

/// One reading of the sending device's root qdisc.
#[derive(Debug)]
struct Qdisc {
    /// Packets it dropped, one per skb, so one per GSO send.
    drops: u64,
    /// Packets it holds.
    qlen: u64,
}

fn qdisc() -> Qdisc {
    let json = tc_json();
    Qdisc {
        drops: json_number(&json, "drops"),
        qlen: json_number(&json, "qlen"),
    }
}

/// Waits until the sending device's qdisc is empty, and returns that reading.
fn await_empty_qdisc() -> Qdisc {
    let deadline = Instant::now() + HANG_GUARD;
    loop {
        let reading = qdisc();
        if reading.qlen == 0 {
            return reading;
        }
        assert!(
            Instant::now() < deadline,
            "{DEV}'s qdisc never emptied: {reading:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Opens a backend on `host` with kernel release and GRO off, and with
/// [`MmsgOptions::recv_errors`] if `recv_errors`, with buffers and batches sized for a burst, so
/// that neither the send buffer nor the backend's `max_unsent` refuses one, and a receive batch
/// holds every datagram the peer sends back.
fn open(host: &ManualHost, family: Family, recv_errors: bool) -> HostBackend<ManualHost> {
    let options = HostOptions {
        host: Some(host.clone()),
        mmsg: MmsgOptions {
            socket: SocketOptions {
                dual_stack: family != Family::V6,
                recv_buffer: Some(4 << 20),
                send_buffer: Some(4 << 20),
                gro: false,
                ..SocketOptions::default()
            },
            max_unsent: 1 << 20,
            rx_batch: 256,
            rx_buffer: 2048,
            txtime: true,
            recv_errors,
            ..MmsgOptions::default()
        },
    };
    let backend = HostBackend::bind(family.local(), &options).expect("bind");
    assert!(
        matches!(backend.caps().release, ReleaseSupport::Kernel { .. }),
        "{family:?}: kernel release"
    );
    assert!(backend.caps().max_segments >= 9, "{:?}", backend.caps());
    backend
}

/// IP_RECVERR and IPV6_RECVERR as the socket reports them; `None` where it does not have the
/// option.
fn recverr(backend: &HostBackend<ManualHost>) -> (Option<bool>, Option<bool>) {
    let flag = |level, name| {
        sys::get_int(&backend.socket, level, name)
            .ok()
            .map(|value| value != 0)
    };
    (
        flag(libc::IPPROTO_IP, libc::IP_RECVERR),
        flag(libc::IPPROTO_IPV6, libc::IPV6_RECVERR),
    )
}

/// Checks the error options a `family` socket must carry: IP_RECVERR on an AF_INET socket,
/// IPV6_RECVERR on an AF_INET6 one, and both on a dual-stack one, whose IPv4-mapped sends and ICMP
/// errors obey the IPv4 option.
fn assert_recverr(family: Family, (v4, v6): (Option<bool>, Option<bool>)) {
    match family {
        Family::V4 => assert_eq!(v4, Some(true), "IP_RECVERR on an AF_INET socket"),
        Family::V6 => assert_eq!(v6, Some(true), "IPV6_RECVERR on an AF_INET6 socket"),
        Family::Dual => assert_eq!(
            (v4, v6),
            (Some(true), Some(true)),
            "IP_RECVERR and IPV6_RECVERR on a dual-stack socket"
        ),
    }
}

fn conn(index: u32) -> ConnKey {
    ConnKey {
        index,
        generation: 1,
    }
}

/// Returns datagram `seq`: `DATAGRAM` bytes, starting with `seq`, that differ from every other's.
fn datagram(seq: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..DATAGRAM).map(|i| (i as u8) ^ (seq as u8)).collect();
    bytes[..8].copy_from_slice(&seq.to_be_bytes());
    bytes
}

/// Writes datagrams `seqs` through `backend`'s sink for `conn` as one sealed run to `dst`, released
/// at `release`, numbered from the range's start.
fn queue_run(
    backend: &mut HostBackend<ManualHost>,
    conn: ConnKey,
    dst: SocketAddr,
    seqs: TxSeqRange,
    payload: impl Fn(u64) -> Vec<u8>,
    release: Release,
) {
    let mut sink = backend.sink(conn);
    for seq in seqs.start..seqs.end {
        let bytes = payload(seq);
        let (_, slot) = sink
            .next_segment(bytes.len() as u16, TxClass::Data)
            .expect("a slot: a refused segment means an EAGAIN backlog");
        slot[..bytes.len()].copy_from_slice(&bytes);
        sink.end_segment(bytes.len() as u16);
    }
    sink.end_run(TxMeta {
        path: PathId(0),
        dst,
        src_ip: None,
        tos: 0,
        segment_size: DATAGRAM as u16,
        segments: (seqs.end - seqs.start) as u16,
        release,
        class: TxClass::Data,
        tx: seqs,
        sealed: true,
    });
}

/// Queues the burst for connection 1 to `dst`: 40 runs alternating 1 and 9 datagrams, 200 in all,
/// each run one message (a single datagram or a GSO send). Returns each run's datagrams.
fn queue_burst(
    backend: &mut HostBackend<ManualHost>,
    dst: SocketAddr,
    release: Release,
) -> Vec<TxSeqRange> {
    let mut runs = Vec::new();
    let mut start = 0;
    while start < BURST {
        let end = start + RUNS[runs.len() % RUNS.len()];
        let run = TxSeqRange { start, end };
        queue_run(backend, conn(1), dst, run, datagram, release);
        runs.push(run);
        start = end;
    }
    runs
}

fn drain_reports(backend: &mut HostBackend<ManualHost>) -> Vec<TxReport> {
    let mut reports = Vec::new();
    backend.drain_reports(|_, report| reports.push(report));
    reports
}

/// Copies out the last batch's datagrams with their sources, a GRO run split by its stride.
fn collect(backend: &mut HostBackend<ManualHost>, got: &mut Vec<(SocketAddr, Vec<u8>)>) {
    for (meta, data) in backend.buffers() {
        for datagram in data.chunks(usize::from(meta.stride.max(1))) {
            got.push((meta.src, datagram.to_vec()));
        }
    }
}

/// What a stamped burst into one fq flow left behind.
struct Burst {
    /// `tc -s` drops on the sending device during the burst.
    qdisc_drops: u64,
    counters: TxCounters,
    /// Each run's datagrams, one message each.
    runs: Vec<TxSeqRange>,
    reports: Vec<TxReport>,
    /// Whether the flush met EAGAIN; a refused segment would have failed the test already.
    blocked: bool,
    recverr: (Option<bool>, Option<bool>),
}

/// Sends the burst from a fresh `family` socket, opened with `recv_errors`, to the peer's sink,
/// every run stamped `HOLD` ahead, in one flush. fq holds the first 10 messages of the flow and
/// drops every message after them at its flow limit.
fn burst(family: Family, recv_errors: bool) -> Burst {
    let _rig = rig();
    let host = ManualHost::new().unwrap();
    let mut backend = open(&host, family, recv_errors);
    let before = await_empty_qdisc();
    let release = Release::At(Tick(sys::monotonic_ns() + HOLD.as_nanos() as u64));
    let runs = queue_burst(&mut backend, family.peer(SINK_PORT), release);
    let outcome = backend.flush(Instant::now());
    let qdisc_drops = qdisc().drops - before.drops;
    let counters = backend.take_counters();
    let reports = drain_reports(&mut backend);
    // fq releases what it holds after `HOLD`, so the next test starts on an empty qdisc.
    await_empty_qdisc();
    Burst {
        qdisc_drops,
        counters,
        runs,
        reports,
        blocked: outcome.blocked,
        recverr: recverr(&backend),
    }
}

/// A burst of 200 datagrams, GSO sends included, into fq's flow limit: `tx_enobufs + tx_partial`
/// equals the `tc -s` drop delta exactly, in a run without EAGAIN.
fn qdisc_drops_equal_tx_enobufs_plus_tx_partial(family: Family) {
    let burst = burst(family, true);
    assert!(
        !burst.blocked,
        "{family:?}: a send met EAGAIN; the equality holds only while the qdisc is the only source \
         of send errors"
    );
    assert!(
        burst.qdisc_drops > 0,
        "{family:?}: the burst must overflow fq's flow limit"
    );
    assert_eq!(
        burst.counters.tx_enobufs + burst.counters.tx_partial,
        burst.qdisc_drops,
        "{family:?}: tx_enobufs + tx_partial against the tc -s drop delta; {:?}",
        burst.counters
    );
    assert_recverr(family, burst.recverr);
}

/// In the same burst, every message whose send returned ENOBUFS is reported
/// `Dropped(LocalQueue)`, and only those: one report per call whose first message failed, each
/// covering that message's datagrams, while the message that ended a partial call goes again.
fn every_send_that_returned_enobufs_is_reported_dropped_local_queue(family: Family) {
    let burst = burst(family, true);
    assert!(!burst.blocked, "{family:?}: a send met EAGAIN");
    assert!(
        burst.qdisc_drops > 0,
        "{family:?}: the burst must overflow fq's flow limit"
    );
    let mut reported = vec![0u32; BURST as usize];
    let mut dropped = Vec::new();
    for report in &burst.reports {
        let tx = match *report {
            TxReport::Flushed { tx } => tx,
            TxReport::Dropped { tx, reason } => {
                assert_eq!(
                    reason,
                    DropReason::LocalQueue,
                    "{family:?}: a qdisc drop is a local drop: {tx:?}"
                );
                assert!(
                    burst.runs.contains(&tx),
                    "{family:?}: a drop report covers exactly one message: {tx:?}"
                );
                dropped.push(tx);
                tx
            }
        };
        for seq in tx.start..tx.end {
            reported[seq as usize] += 1;
        }
    }
    assert_eq!(
        dropped.len() as u64 + burst.counters.tx_partial,
        burst.qdisc_drops,
        "{family:?}: each qdisc drop failed a call's first message, whose datagrams are reported \
         dropped, or ended a partial call, whose message went again; {:?}, reports {:?}",
        burst.counters,
        burst.reports
    );
    assert_eq!(
        dropped.len() as u64,
        burst.counters.tx_enobufs,
        "{family:?}: one Dropped(LocalQueue) report per call that failed with ENOBUFS"
    );
    assert!(
        reported.iter().all(|&count| count == 1),
        "{family:?}: every datagram reported once: {:?}",
        burst.reports
    );
}

/// The same burst from a socket opened without [`MmsgOptions::recv_errors`]: fq drops past its flow
/// limit, but UDP reports each dropped send as a success, so every datagram is reported flushed
/// once, and neither send error count moves.
fn without_the_option_fq_drops_are_reported_flushed_and_not_counted(family: Family) {
    let burst = burst(family, false);
    assert!(
        !matches!(burst.recverr, (Some(true), _) | (_, Some(true))),
        "{family:?}: IP_RECVERR and IPV6_RECVERR stay off: {:?}",
        burst.recverr
    );
    assert!(!burst.blocked, "{family:?}: a send met EAGAIN");
    assert!(
        burst.qdisc_drops > 0,
        "{family:?}: the burst must overflow fq's flow limit"
    );
    let mut reported = vec![0u32; BURST as usize];
    for report in &burst.reports {
        let TxReport::Flushed { tx } = *report else {
            panic!("{family:?}: a send fq dropped is reported flushed: {report:?}");
        };
        for seq in tx.start..tx.end {
            reported[seq as usize] += 1;
        }
    }
    assert!(
        reported.iter().all(|&count| count == 1),
        "{family:?}: every datagram reported once: {:?}",
        burst.reports
    );
    assert_eq!(
        (burst.counters.tx_enobufs, burst.counters.tx_partial),
        (0, 0),
        "{family:?}: without IP_RECVERR, a send that fq drops does not fail; {:?}",
        burst.counters
    );
}

/// Receives until `count` datagrams have arrived, running `host` between polls.
fn receive(
    host: &ManualHost,
    backend: &mut HostBackend<ManualHost>,
    count: usize,
) -> Vec<(SocketAddr, Vec<u8>)> {
    let deadline = Instant::now() + HANG_GUARD;
    let mut cx = Context::from_waker(Waker::noop());
    let mut got = Vec::new();
    while got.len() < count {
        match backend.poll_recv(&mut cx) {
            Poll::Ready(Ok(_)) => collect(backend, &mut got),
            Poll::Ready(Err(error)) => panic!("receive failed: {error}"),
            Poll::Pending => {
                let left = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !left.is_zero(),
                    "{} of {count} datagrams arrived",
                    got.len()
                );
                host.poll(Some(left)).unwrap();
            }
        }
    }
    got
}

/// A run without drops or ICMP errors, on a socket with the error options set: the burst, unstamped
/// so that fq does not hold it, to the echo port, and every datagram back. It does not read the
/// error queue. Each receive batch is short, as the batch has more buffers than the burst has
/// datagrams, so every `recvmmsg` follows a host report of a readable socket and returns before
/// EAGAIN.
fn a_clean_run_makes_no_error_queue_reads(family: Family) {
    let _rig = rig();
    let host = ManualHost::new().unwrap();
    let mut backend = open(&host, family, true);
    let before = await_empty_qdisc();
    queue_burst(&mut backend, family.peer(ECHO_PORT), Release::Asap);
    let outcome = backend.flush(Instant::now());
    let counters = backend.take_counters();
    let reports = drain_reports(&mut backend);
    let mut echoes = receive(&host, &mut backend, BURST as usize);
    let quiet = host.poll(Some(QUIET)).unwrap() == 0;
    let qdisc_drops = await_empty_qdisc().drops - before.drops;

    assert_recverr(family, recverr(&backend));
    assert_eq!(qdisc_drops, 0, "{family:?}: a clean run drops nothing");
    assert!(!outcome.blocked, "{family:?}: a send met EAGAIN");
    assert_eq!(
        reports,
        vec![TxReport::Flushed {
            tx: TxSeqRange {
                start: 0,
                end: BURST
            }
        }],
        "{family:?}"
    );
    assert_eq!(
        (counters.tx_enobufs, counters.tx_partial),
        (0, 0),
        "{family:?}"
    );
    echoes.sort();
    let mut sent: Vec<_> = (0..BURST)
        .map(|seq| (family.peer(ECHO_PORT), datagram(seq)))
        .collect();
    sent.sort();
    assert!(echoes == sent, "{family:?}: every datagram came back once");
    assert!(quiet, "{family:?}: nothing more to read");
    assert_eq!(
        backend.rx.errqueue_reads, 0,
        "{family:?}: a clean run makes no error-queue reads"
    );
    assert_eq!(backend.icmp_errors(), 0, "{family:?}");
}

/// Who takes the socket's pending error once the ICMP error has arrived.
#[derive(Clone, Copy, Debug)]
enum Taker {
    /// The next receive.
    Receive,
    /// A send of one datagram to the peer's port, before any receive. If its report says it did
    /// not leave, it goes again once, as a connection would send its bytes again.
    Send(u16),
}

/// The payload of the datagram a [`Taker::Send`] sends, every attempt alike.
fn after_icmp(_seq: u64) -> Vec<u8> {
    datagram(1_000_000)
}

/// What became of a socket after an ICMP port unreachable reached it.
struct IcmpRun {
    /// Whether the host reported the socket readable within `ICMP_WAIT` of the datagram to the
    /// closed port, which only the ICMP error could do.
    reached: bool,
    /// The reports of each attempt of the send that took the error.
    attempts: Vec<Vec<TxReport>>,
    /// `icmp_errors()` after the send that took the error, before any receive.
    icmp_errors_before_receive: u64,
    received: Vec<(SocketAddr, Vec<u8>)>,
    /// Whether a host poll then did not report the socket for `QUIET`, within `MAX_ROUNDS` receive
    /// rounds.
    quiet: bool,
    /// Whether the read readiness was still set at the end.
    readiness_left: bool,
    icmp_errors: u64,
}

/// Sends one datagram from a fresh `family` socket to the peer's closed port, waits for the ICMP
/// port unreachable to reach the socket, lets `taker` take the pending error, and receives until
/// the host stops reporting the socket.
fn icmp_run(family: Family, taker: Taker) -> IcmpRun {
    let _rig = rig();
    let host = ManualHost::new().unwrap();
    let mut backend = open(&host, family, true);
    let one = TxSeqRange { start: 0, end: 1 };
    queue_run(
        &mut backend,
        conn(1),
        family.peer(CLOSED_PORT),
        one,
        datagram,
        Release::Asap,
    );
    assert_eq!(
        backend.flush(Instant::now()).datagrams,
        1,
        "{family:?}: the datagram to the closed port left"
    );
    assert_eq!(
        drain_reports(&mut backend),
        vec![TxReport::Flushed { tx: one }]
    );

    let deadline = Instant::now() + ICMP_WAIT;
    while !backend.readiness.is_set(Interest::Read) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        host.poll(Some(left)).unwrap();
    }
    let reached = backend.readiness.is_set(Interest::Read);

    let mut attempts = Vec::new();
    if let Taker::Send(port) = taker {
        for seq in 0..2 {
            queue_run(
                &mut backend,
                conn(2),
                family.peer(port),
                TxSeqRange {
                    start: seq,
                    end: seq + 1,
                },
                after_icmp,
                Release::Asap,
            );
            backend.flush(Instant::now());
            let reports = drain_reports(&mut backend);
            let left = matches!(reports.as_slice(), [TxReport::Flushed { .. }]);
            attempts.push(reports);
            if left {
                break;
            }
        }
    }
    let icmp_errors_before_receive = backend.icmp_errors();

    let mut cx = Context::from_waker(Waker::noop());
    let mut received = Vec::new();
    let mut quiet = false;
    for _ in 0..MAX_ROUNDS {
        match backend.poll_recv(&mut cx) {
            Poll::Ready(Ok(_)) => collect(&mut backend, &mut received),
            Poll::Ready(Err(error)) => {
                panic!("{family:?}: an ICMP error must not reach the caller: {error}")
            }
            Poll::Pending => {
                if host.poll(Some(QUIET)).unwrap() == 0 {
                    quiet = true;
                    break;
                }
            }
        }
    }
    IcmpRun {
        reached,
        attempts,
        icmp_errors_before_receive,
        received,
        quiet,
        readiness_left: backend.readiness.is_set(Interest::Read),
        icmp_errors: backend.icmp_errors(),
    }
}

/// Checks that the ICMP error reached the socket, was read from the error queue once, and that the
/// host then stopped reporting the socket readable.
fn assert_drained_once(family: Family, run: &IcmpRun) {
    assert!(
        run.reached,
        "{family:?}: the ICMP port unreachable never reached the socket (no read readiness within \
         {ICMP_WAIT:?}); without IP_RECVERR an unconnected socket ignores it"
    );
    assert_eq!(
        run.icmp_errors, 1,
        "{family:?}: the queued ICMP error is read once"
    );
    assert!(
        run.quiet,
        "{family:?}: the host still reports the socket readable after {MAX_ROUNDS} receive rounds; \
         a queued error keeps EPOLLERR asserted until it is read"
    );
    assert!(!run.readiness_left, "{family:?}: read readiness left set");
}

/// An ICMP port unreachable whose pending error the next receive takes, as an ICMP errno from
/// `recvmmsg`, is drained once, after which the read readiness stops being reported.
fn an_icmp_error_the_next_receive_takes_is_drained_once(family: Family) {
    let run = icmp_run(family, Taker::Receive);
    assert_drained_once(family, &run);
    assert!(run.received.is_empty(), "{family:?}: {:?}", run.received);
}

/// An ICMP port unreachable whose pending error a send takes first is drained once by the receive
/// whose `recvmmsg` then meets EAGAIN, after which the read readiness stops being reported. The send
/// path does not read the error queue.
fn an_icmp_error_a_send_takes_is_drained_once_at_eagain(family: Family) {
    let run = icmp_run(family, Taker::Send(SINK_PORT));
    assert_drained_once(family, &run);
    assert_eq!(
        run.icmp_errors_before_receive, 0,
        "{family:?}: the send path reads no error queue"
    );
    assert!(run.received.is_empty(), "{family:?}: {:?}", run.received);
    assert!(
        matches!(
            run.attempts.first().map(Vec::as_slice),
            Some([TxReport::Dropped {
                reason: DropReason::Error,
                ..
            }])
        ),
        "{family:?}: the send takes the pending error and fails with it: {:?}",
        run.attempts
    );
}

/// A send to another peer right after the ICMP error fails at most once with it, and then the
/// datagram goes out: the peer sends it back, once.
fn a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out(family: Family) {
    let run = icmp_run(family, Taker::Send(ECHO_PORT));
    assert!(
        run.reached,
        "{family:?}: the ICMP port unreachable never reached the socket (no read readiness within \
         {ICMP_WAIT:?}); without IP_RECVERR an unconnected socket ignores it"
    );
    match run.attempts.as_slice() {
        [first] => assert!(
            matches!(first.as_slice(), [TxReport::Flushed { .. }]),
            "{family:?}: {first:?}"
        ),
        [first, second] => {
            assert!(
                matches!(
                    first.as_slice(),
                    [TxReport::Dropped {
                        reason: DropReason::Error,
                        ..
                    }]
                ),
                "{family:?}: the first attempt fails only with the pending error: {first:?}"
            );
            assert!(
                matches!(second.as_slice(), [TxReport::Flushed { .. }]),
                "{family:?}: the second attempt goes out: {second:?}"
            );
        }
        attempts => panic!("{family:?}: attempts {attempts:?}"),
    }
    let echoes: Vec<SocketAddr> = run
        .received
        .iter()
        .filter(|(_, bytes)| *bytes == after_icmp(0))
        .map(|&(src, _)| src)
        .collect();
    assert_eq!(
        echoes,
        vec![family.peer(ECHO_PORT)],
        "{family:?}: the datagram reached the other peer once"
    );
    assert_eq!(run.icmp_errors, 1, "{family:?}: the ICMP error read once");
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn fq_drops_equal_tx_enobufs_plus_tx_partial_on_an_ipv4_socket() {
    qdisc_drops_equal_tx_enobufs_plus_tx_partial(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn fq_drops_equal_tx_enobufs_plus_tx_partial_on_an_ipv6_socket() {
    qdisc_drops_equal_tx_enobufs_plus_tx_partial(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn fq_drops_equal_tx_enobufs_plus_tx_partial_on_a_dual_stack_socket_to_an_ipv4_mapped_peer() {
    qdisc_drops_equal_tx_enobufs_plus_tx_partial(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn each_send_that_returned_enobufs_is_reported_dropped_local_queue_on_an_ipv4_socket() {
    every_send_that_returned_enobufs_is_reported_dropped_local_queue(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn each_send_that_returned_enobufs_is_reported_dropped_local_queue_on_an_ipv6_socket() {
    every_send_that_returned_enobufs_is_reported_dropped_local_queue(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn each_send_that_returned_enobufs_is_reported_dropped_local_queue_on_a_dual_stack_socket() {
    every_send_that_returned_enobufs_is_reported_dropped_local_queue(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_clean_run_makes_no_error_queue_reads_on_an_ipv4_socket() {
    a_clean_run_makes_no_error_queue_reads(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_clean_run_makes_no_error_queue_reads_on_an_ipv6_socket() {
    a_clean_run_makes_no_error_queue_reads(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_clean_run_makes_no_error_queue_reads_on_a_dual_stack_socket() {
    a_clean_run_makes_no_error_queue_reads(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_the_next_receive_takes_is_drained_once_on_an_ipv4_socket() {
    an_icmp_error_the_next_receive_takes_is_drained_once(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_the_next_receive_takes_is_drained_once_on_an_ipv6_socket() {
    an_icmp_error_the_next_receive_takes_is_drained_once(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_the_next_receive_takes_is_drained_once_on_a_dual_stack_socket() {
    an_icmp_error_the_next_receive_takes_is_drained_once(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_a_send_takes_is_drained_once_at_eagain_on_an_ipv4_socket() {
    an_icmp_error_a_send_takes_is_drained_once_at_eagain(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_a_send_takes_is_drained_once_at_eagain_on_an_ipv6_socket() {
    an_icmp_error_a_send_takes_is_drained_once_at_eagain(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn an_icmp_error_a_send_takes_is_drained_once_at_eagain_on_a_dual_stack_socket() {
    an_icmp_error_a_send_takes_is_drained_once_at_eagain(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out_on_ipv4() {
    a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out_on_ipv6() {
    a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out_on_dual_stack() {
    a_send_to_another_peer_after_an_icmp_error_fails_at_most_once_then_goes_out(Family::Dual);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn without_the_option_fq_drops_are_reported_flushed_and_not_counted_on_an_ipv4_socket() {
    without_the_option_fq_drops_are_reported_flushed_and_not_counted(Family::V4);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn without_the_option_fq_drops_are_reported_flushed_and_not_counted_on_an_ipv6_socket() {
    without_the_option_fq_drops_are_reported_flushed_and_not_counted(Family::V6);
}

#[test]
#[ignore = "needs the netns rig: crates/io/tests/netns/run.sh"]
fn without_the_option_fq_drops_are_reported_flushed_and_not_counted_on_a_dual_stack_socket() {
    without_the_option_fq_drops_are_reported_flushed_and_not_counted(Family::Dual);
}
