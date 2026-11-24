/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A backend for the driver's tests: [`MmsgBackend`] behind a [`Valve`] that the test thread
//! controls. A valve can hold its sockets' flushes behind a simulated EAGAIN, which loopback never
//! returns, drop a run as the backend drops one that must not leave, and fail a receive. It records
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
use std::time::Instant;

use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_io::MmsgSink;
use mvfstr_io::RxBackend;
use mvfstr_io::TxBackend;
use mvfstr_io::TxCaps;
use mvfstr_proto::ConnKey;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::SlotId;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;

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
    /// Datagrams arrived.
    Received,
}

#[derive(Default)]
struct State {
    /// The next flush meets the simulated EAGAIN.
    block_next_flush: bool,
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
            state.events.clear();
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
        state.events.clear();
    }

    /// Makes the next receive on the sockets fail with an error that the backend passes on.
    pub(crate) fn fail_next_recv(&self) {
        self.state().fail_next_recv = true;
    }

    /// Clears the record of what the sockets did.
    pub(crate) fn clear(&self) {
        self.state().events.clear();
    }

    /// Returns what the sockets did since the record was last cleared.
    pub(crate) fn events(&self) -> Vec<Event> {
        self.state().events.clone()
    }

    /// Returns the datagrams handed to the sockets so far, each segment of a run counted.
    pub(crate) fn datagrams(&self) -> usize {
        self.state().datagrams
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
    blocked: bool,
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
        let blocked = {
            let mut state = valve.state();
            state.events.push(Event::Attempt);
            state.blocked
        };
        GatedSink {
            inner: self.inner.sink(conn),
            valve,
            blocked,
        }
    }

    fn flush(&mut self, now: Instant) -> FlushOutcome {
        {
            let mut state = self.valve().state();
            if mem::take(&mut state.block_next_flush) {
                state.blocked = true;
            }
            if state.blocked {
                return FlushOutcome {
                    datagrams: 0,
                    blocked: true,
                };
            }
            state.events.push(Event::Flush);
        }
        self.inner.flush(now)
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        {
            let mut state = self.valve().state();
            if state.blocked {
                state.writable = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        self.inner.poll_writable(cx)
    }

    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport)) {
        self.inner.drain_reports(f);
    }
}

impl RxBackend for Gated {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if mem::take(&mut self.valve().state().fail_next_recv) {
            return Poll::Ready(Err(io::Error::other("an injected receive error")));
        }
        let poll = self.inner.poll_recv(cx);
        if matches!(&poll, Poll::Ready(Ok(n)) if *n > 0) {
            self.valve().record(Event::Received);
        }
        poll
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
        })
    }

    fn connect(remote: SocketAddr, options: &GatedOptions) -> io::Result<Self> {
        Ok(Self {
            inner: <MmsgBackend as Backend>::connect(remote, &options.mmsg)?,
            valves: Arc::clone(&options.valves),
            server: false,
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Backend::local_addr(&self.inner)
    }
}
