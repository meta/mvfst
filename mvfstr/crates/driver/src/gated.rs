/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A backend for the driver's tests: [`MmsgBackend`] behind a [`Valve`] that the test thread
//! controls. A valve can hold its sockets' flushes behind a simulated EAGAIN, which loopback never
//! returns, drop a run as the backend drops one that must not leave, fail a receive, add GSO and
//! histogram counts to what the sockets count, and hold the worker after an attempt. It records
//! what the sockets did.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_io::MmsgSink;
use mvfstr_io::RxBackend;
use mvfstr_io::TxBackend;
use mvfstr_io::TxCaps;
use mvfstr_io::TxCounters;
use mvfstr_proto::ClockEpoch;
use mvfstr_proto::ConnKey;
use mvfstr_proto::Release;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::SlotId;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;
use mvfstr_proto::TxSeqRange;

use crate::turn::add_buckets;

/// What a gated socket did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// A transmit attempt began.
    Attempt,
    /// The backend refused a segment.
    Refused,
    /// A run was dropped, as set up by [`Valve::drop_next_run_of`].
    Dropped,
    /// A flush ran on a socket that was not blocked.
    Flush,
    /// A flush met the simulated EAGAIN.
    Blocked,
    /// A poll for writability found the socket writable again and sent the backlog, as set up by
    /// [`Valve::block_next_flush_until_polled`].
    SentAtPoll,
    /// Datagrams arrived.
    Received,
    /// A run ended; [`Valve::runs`] has its attempt and release.
    Run,
}

/// A run a gated socket was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    /// The number of its transmit attempt since the record last started afresh, from 0.
    pub(crate) attempt: usize,
    /// When it is to leave.
    pub(crate) release: Release,
    /// How far its release lay ahead of the start of its attempt, on the socket's clock epoch;
    /// zero if not ahead, and `None` for a run without a release time.
    pub(crate) ahead: Option<Duration>,
    /// How far its release lay behind the start of its attempt; zero if not behind, and `None`
    /// for a run without a release time.
    pub(crate) behind: Option<Duration>,
}

/// A transmit attempt on a gated socket: its connection, when it began, the datagrams handed to
/// the valve's sockets before it, and the datagrams the socket's backend held queued as it began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Started {
    pub(crate) conn: ConnKey,
    pub(crate) at: Instant,
    pub(crate) handed: usize,
    pub(crate) queued: u32,
}

#[derive(Default)]
struct State {
    /// The next flush meets the simulated EAGAIN.
    block_next_flush: bool,
    /// The simulated EAGAIN ends at the next poll for writability, which sends the backlog.
    writable_at_poll: bool,
    /// GSO counts the sockets add to what they count when they are next taken.
    gso_retries: u64,
    gso_disabled: u64,
    /// Histogram counts the sockets add, bucket by bucket, to what they count when they are next
    /// taken.
    release_lateness: [u64; 8],
    messages_per_call: [u64; 8],
    /// The sockets keep their queued runs and refuse every segment until the test opens them.
    blocked: bool,
    /// The waker of the last `poll_writable` while blocked.
    writable: Option<Waker>,
    /// The next run whose datagrams are at least this long is dropped.
    drop_run_of: Option<u16>,
    /// The next receive fails.
    fail_next_recv: bool,
    events: Vec<Event>,
    /// Datagrams handed to the sockets so far, each segment of a run counted.
    datagrams: usize,
    /// Transmit attempts since the record last started afresh.
    attempts: usize,
    runs: Vec<Run>,
    /// The transmit attempts since the record last started afresh, in order.
    started: Vec<Started>,
    /// Every run the sockets were handed, with its connection, in order; the record starting
    /// afresh does not clear it.
    handed: Vec<(ConnKey, TxSeqRange)>,
    /// Every report the driver took from the sockets, in order; the record starting afresh does
    /// not clear it.
    reported: Vec<(ConnKey, TxReport)>,
    /// How long the worker is held after each attempt, and for how many attempts more.
    stall: Option<(Duration, usize)>,
}

impl State {
    fn restart(&mut self) {
        self.events.clear();
        self.attempts = 0;
        self.runs.clear();
        self.started.clear();
    }
}

/// The test's control of one kind of socket: the server socket, or every client socket.
#[derive(Default)]
pub(crate) struct Valve {
    state: Mutex<State>,
}

impl Valve {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("nothing panics while it holds the valve")
    }

    fn record(&self, event: Event) {
        self.state().events.push(event);
    }

    /// Makes the next flush meet the simulated EAGAIN: it does not send, and the sockets refuse
    /// segments until [`open`](Self::open).
    pub(crate) fn block_next_flush(&self) {
        self.state().block_next_flush = true;
    }

    /// Makes the next flush meet the simulated EAGAIN, and the poll for writability after it find
    /// the socket writable again and send the backlog itself, as the real backends' polls do.
    pub(crate) fn block_next_flush_until_polled(&self) {
        let mut state = self.state();
        state.block_next_flush = true;
        state.writable_at_poll = true;
    }

    /// Adds `retries` GSO retries and `disabled` GSO disables to the counters the sockets return
    /// when they are next taken, as a socket whose kernel refused GSO sends counts them. A real
    /// refusal needs SO_NO_CHECK on the socket, which takes unsafe code this crate forbids.
    pub(crate) fn count_gso(&self, retries: u64, disabled: u64) {
        let mut state = self.state();
        state.gso_retries += retries;
        state.gso_disabled += disabled;
    }

    /// Adds `release_lateness` and `messages_per_call` bucket by bucket to the histograms the
    /// sockets return when they are next taken.
    pub(crate) fn count_histograms(&self, release_lateness: [u64; 8], messages_per_call: [u64; 8]) {
        let mut state = self.state();
        add_buckets(&mut state.release_lateness, release_lateness);
        add_buckets(&mut state.messages_per_call, messages_per_call);
    }

    /// Returns whether the sockets are blocked and the driver is waiting for them to be writable.
    pub(crate) fn waiting(&self) -> bool {
        let state = self.state();
        state.blocked && state.writable.is_some()
    }

    /// Ends the simulated EAGAIN, clears the record and wakes the driver waiting for the socket.
    pub(crate) fn open(&self) {
        let waker = {
            let mut state = self.state();
            state.blocked = false;
            state.restart();
            state.writable.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Drops the next run whose datagrams are at least `len` bytes, by ending it unsealed: the
    /// backend frees its slots and reports it `Dropped`, as for any run that must not leave.
    /// Clears the record.
    pub(crate) fn drop_next_run_of(&self, len: u16) {
        let mut state = self.state();
        state.drop_run_of = Some(len);
        state.restart();
    }

    /// Makes the next receive on the sockets fail with an error that the backend passes on.
    pub(crate) fn fail_next_recv(&self) {
        self.state().fail_next_recv = true;
    }

    /// Clears the record of what the sockets did.
    pub(crate) fn clear(&self) {
        self.state().restart();
    }

    /// Returns the runs the sockets were handed since the record last started afresh.
    pub(crate) fn runs(&self) -> Vec<Run> {
        self.state().runs.clone()
    }

    /// Returns what the sockets did since the record was last cleared.
    pub(crate) fn events(&self) -> Vec<Event> {
        self.state().events.clone()
    }

    /// Returns the datagrams handed to the sockets so far, each segment of a run counted.
    pub(crate) fn datagrams(&self) -> usize {
        self.state().datagrams
    }

    /// Holds the worker for `hold` after each of the next `attempts` transmit attempts, as a
    /// preemption in the middle of a transmit phase would.
    pub(crate) fn stall(&self, hold: Duration, attempts: usize) {
        self.state().stall = Some((hold, attempts));
    }

    /// Returns the transmit attempts since the record last started afresh, in order.
    pub(crate) fn started(&self) -> Vec<Started> {
        self.state().started.clone()
    }

    /// Returns every run the sockets were handed, with its connection, in order.
    pub(crate) fn handed(&self) -> Vec<(ConnKey, TxSeqRange)> {
        self.state().handed.clone()
    }

    /// Returns every report the driver took from the sockets, in order.
    pub(crate) fn reported(&self) -> Vec<(ConnKey, TxReport)> {
        self.state().reported.clone()
    }
}

/// The valves of a driver pair: one for the server socket and one for every client socket.
#[derive(Default)]
pub(crate) struct Valves {
    pub(crate) server: Valve,
    pub(crate) client: Valve,
}

/// The settings of every [`Gated`] backend a driver opens.
#[derive(Clone, Default)]
pub(crate) struct GatedOptions {
    pub(crate) mmsg: MmsgOptions,
    pub(crate) valves: Arc<Valves>,
}

/// [`MmsgBackend`] behind a [`Valve`]: the server's valve for a bound socket, the client's for a
/// connected one.
pub(crate) struct Gated {
    inner: MmsgBackend,
    valves: Arc<Valves>,
    server: bool,
    /// Whether the last receive call was the failure the valve injected, which filled no buffer.
    failed: bool,
}

impl Gated {
    fn valve(&self) -> &Valve {
        if self.server {
            &self.valves.server
        } else {
            &self.valves.client
        }
    }
}

/// A gated socket's sink: it refuses every segment while its valve is blocked, and drops the run
/// set up by [`Valve::drop_next_run_of`].
pub(crate) struct GatedSink<'a> {
    inner: MmsgSink<'a>,
    valve: &'a Valve,
    conn: ConnKey,
    blocked: bool,
    /// The attempt's number; the attempt began at `started`.
    attempt: usize,
    started: Instant,
    epoch: Option<ClockEpoch>,
}

impl SegmentSink for GatedSink<'_> {
    fn next_segment(&mut self, max_len: u16, class: TxClass) -> Option<(SlotId, &mut [u8])> {
        let lent = if self.blocked {
            None
        } else {
            self.inner.next_segment(max_len, class)
        };
        if lent.is_none() {
            self.valve.record(Event::Refused);
        }
        lent
    }

    fn end_segment(&mut self, len: u16) {
        if len > 0 {
            self.valve.state().datagrams += 1;
        }
        self.inner.end_segment(len);
    }

    fn end_run(&mut self, meta: TxMeta) {
        let dropped = {
            let mut state = self.valve.state();
            let (ahead, behind) = match (meta.release, self.epoch) {
                (Release::At(tick), Some(epoch)) => {
                    let started = epoch.tick_at(self.started).0;
                    (
                        Some(Duration::from_nanos(tick.0.saturating_sub(started))),
                        Some(Duration::from_nanos(started.saturating_sub(tick.0))),
                    )
                }
                _ => (None, None),
            };
            state.runs.push(Run {
                attempt: self.attempt,
                release: meta.release,
                ahead,
                behind,
            });
            state.handed.push((self.conn, meta.tx));
            state.events.push(Event::Run);
            let dropped = state
                .drop_run_of
                .is_some_and(|len| meta.segment_size >= len);
            if dropped {
                state.drop_run_of = None;
                state.events.push(Event::Dropped);
            }
            dropped
        };
        self.inner.end_run(TxMeta {
            sealed: meta.sealed && !dropped,
            ..meta
        });
    }
}

impl Drop for GatedSink<'_> {
    fn drop(&mut self) {
        let hold = match &mut self.valve.state().stall {
            Some((hold, left)) if *left > 0 => {
                *left -= 1;
                Some(*hold)
            }
            _ => None,
        };
        if let Some(hold) = hold {
            std::thread::sleep(hold);
        }
    }
}

impl TxBackend for Gated {
    type Sink<'a> = GatedSink<'a>;

    fn caps(&self) -> &TxCaps {
        self.inner.caps()
    }

    fn sink(&mut self, conn: ConnKey) -> GatedSink<'_> {
        let valve = if self.server {
            &self.valves.server
        } else {
            &self.valves.client
        };
        let started = Instant::now();
        let queued = self.inner.queued_datagrams();
        let (blocked, attempt) = {
            let mut state = valve.state();
            state.events.push(Event::Attempt);
            state.attempts += 1;
            let handed = state.datagrams;
            state.started.push(Started {
                conn,
                at: started,
                handed,
                queued,
            });
            (state.blocked, state.attempts - 1)
        };
        GatedSink {
            epoch: self.inner.caps().release.epoch(),
            inner: self.inner.sink(conn),
            valve,
            conn,
            blocked,
            attempt,
            started,
        }
    }

    fn flush(&mut self, now: Instant) -> FlushOutcome {
        {
            let mut state = self.valve().state();
            if mem::take(&mut state.block_next_flush) {
                state.blocked = true;
            }
            if state.blocked {
                state.events.push(Event::Blocked);
                return FlushOutcome {
                    datagrams: 0,
                    blocked: true,
                };
            }
            state.events.push(Event::Flush);
        }
        self.inner.flush(now)
    }

    fn queued_datagrams(&self) -> u32 {
        self.inner.queued_datagrams()
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let writable_again = {
            let mut state = self.valve().state();
            if state.blocked && !mem::take(&mut state.writable_at_poll) {
                state.writable = Some(cx.waker().clone());
                return Poll::Pending;
            }
            mem::take(&mut state.blocked)
        };
        if writable_again {
            self.valve().record(Event::SentAtPoll);
            self.inner.flush(Instant::now());
        }
        self.inner.poll_writable(cx)
    }

    fn drain_reports(&mut self, mut f: impl FnMut(ConnKey, TxReport)) {
        let valve = if self.server {
            &self.valves.server
        } else {
            &self.valves.client
        };
        self.inner.drain_reports(|conn, report| {
            valve.state().reported.push((conn, report));
            f(conn, report);
        });
    }

    fn take_counters(&mut self) -> TxCounters {
        let mut counted = self.inner.take_counters();
        let mut state = self.valve().state();
        counted.gso_retries += mem::take(&mut state.gso_retries);
        counted.gso_disabled += mem::take(&mut state.gso_disabled);
        add_buckets(
            &mut counted.release_lateness,
            mem::take(&mut state.release_lateness),
        );
        add_buckets(
            &mut counted.messages_per_call,
            mem::take(&mut state.messages_per_call),
        );
        counted
    }
}

impl Gated {
    /// Makes a receive call with `recv`, unless a failure was injected for it, and records a batch
    /// that holds datagrams.
    fn receive(
        &mut self,
        recv: impl FnOnce(&mut MmsgBackend) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        let failed = mem::take(&mut self.valve().state().fail_next_recv);
        self.failed = failed;
        if failed {
            return Poll::Ready(Err(io::Error::other("an injected receive error")));
        }
        let poll = recv(&mut self.inner);
        if matches!(&poll, Poll::Ready(Ok(n)) if *n > 0) {
            self.valve().record(Event::Received);
        }
        poll
    }
}

impl RxBackend for Gated {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.receive(|inner| inner.poll_recv(cx))
    }

    fn poll_recv_now(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.receive(|inner| inner.poll_recv_now(cx))
    }

    /// An injected failure filled no buffer, as a real backend's failed call fills none, so it
    /// does not report the call before it.
    fn last_full(&self) -> bool {
        !self.failed && self.inner.last_full()
    }

    fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])> {
        self.inner.buffers()
    }
}

impl Backend for Gated {
    type Options = GatedOptions;

    fn bind(addr: SocketAddr, options: &GatedOptions) -> io::Result<Self> {
        Ok(Self {
            inner: <MmsgBackend as Backend>::bind(addr, &options.mmsg)?,
            valves: Arc::clone(&options.valves),
            server: true,
            failed: false,
        })
    }

    fn connect(remote: SocketAddr, options: &GatedOptions) -> io::Result<Self> {
        Ok(Self {
            inner: <MmsgBackend as Backend>::connect(remote, &options.mmsg)?,
            valves: Arc::clone(&options.valves),
            server: false,
            failed: false,
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Backend::local_addr(&self.inner)
    }
}
