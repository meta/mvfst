/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A deterministic place to run endpoint drivers in tests: one Roxygen worker on a manual host
//! whose clock moves only when the test moves it or a unit of work charges its cost, and an
//! in-memory network between [`MemBackend`] sockets with a fixed one-way delay.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_io::Backend;
use mvfstr_io::FlushOutcome;
use mvfstr_io::ReleaseSupport;
use mvfstr_io::RxBackend;
use mvfstr_io::TxBackend;
use mvfstr_io::TxCaps;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ClockEpoch;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::Dir;
use mvfstr_proto::DropReason;
use mvfstr_proto::Ecn;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::Release;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::SlotId;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::Tick;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxMeta;
use mvfstr_proto::TxReport;
use roxygen_runtime::driver::WorkerDriver;
use roxygen_runtime::host::Host;
use roxygen_runtime::host::LocalFuture;
use roxygen_runtime::host::LocalHost;
use roxygen_runtime::host::timer::WheelTimer;
use roxygen_runtime::host::timer::WheelWakeup;
use roxygen_runtime::worker::WorkerContext;
use roxygen_runtime::worker::WorkerHandle;

use crate::Conn;
use crate::ConnHandle;
use crate::ConnInfo;
use crate::HostTimers;
use crate::QuicApplication;
use crate::QuicSession;
use crate::Refusal;
use crate::SendSink;
use crate::WorkBudget;
use crate::test_support::ORDER;
use crate::test_support::configs_with;

/// The tick of the lab host's wheel.
const TICK: Duration = Duration::from_millis(1);

/// The one-way delay of every datagram.
pub(crate) const DELAY: Duration = Duration::from_millis(2);

/// The most arrivals one receive takes, as the backends' batch.
const RX_BATCH: usize = 64;

/// The largest datagram a lab socket sends.
const MAX_DATAGRAM: u16 = 1_452;

/// The server's address.
pub(crate) const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

/// The port of the first socket the lab opens without an address of its own.
const FIRST_PORT: u16 = 10_000;

/// Returns the address of the `n`-th socket, from 0, that the lab opens without an address of
/// its own, as a client driver opens one for each connection, in connect order.
pub(crate) fn nth_socket(n: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), FIRST_PORT + n)
}

/// The cost of each kind of work on the test clock, charged when the work runs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Costs {
    /// A transmit attempt, charged when it takes its socket's sink.
    pub(crate) attempt: Duration,
    /// A pass over a received batch, charged when it takes the socket's buffers.
    pub(crate) chunk: Duration,
    /// A `poll_session` call.
    pub(crate) visit: Duration,
    /// A read of the host clock.
    pub(crate) read: Duration,
    /// A datagram a flush sends, charged at the flush.
    pub(crate) flush: Duration,
}

/// An event on a lab socket, logged in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetEvent {
    /// A transmit attempt of a connection began on the socket at this address.
    Attempt(SocketAddr, ConnKey),
    /// A transmit attempt of a connection on the socket at this address built this many
    /// datagrams.
    Built(SocketAddr, ConnKey, u16),
    /// The socket flushed.
    Flush(SocketAddr),
    /// A receive took this many datagrams.
    Recv(SocketAddr, usize),
    /// The driver took the received batch's buffers.
    Chunk(SocketAddr),
    /// A transmit attempt of a connection on the socket at this address ended a run of this many
    /// datagrams with this release.
    Run(SocketAddr, ConnKey, Release, usize),
}

/// Datagrams that reach a socket together: one, or several of `stride` bytes each but the last,
/// coalesced as GRO coalesces them.
#[derive(Clone, Debug)]
pub(crate) struct Arrival {
    pub(crate) src: SocketAddr,
    pub(crate) stride: u16,
    pub(crate) data: Vec<u8>,
}

#[derive(Default)]
struct Port {
    inbox: RefCell<VecDeque<Arrival>>,
    waker: RefCell<Option<Waker>>,
    /// Whether the socket refuses datagrams, as behind an EAGAIN, until it is unblocked.
    blocked: Cell<bool>,
    /// The waker to wake when the socket is unblocked.
    writable: RefCell<Option<Waker>>,
}

struct NetState {
    start: Instant,
    now: Cell<Instant>,
    costs: Cell<Costs>,
    next_port: Cell<u16>,
    ports: RefCell<HashMap<SocketAddr, Rc<Port>>>,
    /// Datagrams on their way, by arrival time and send order.
    flights: RefCell<BTreeMap<(Instant, u64), (SocketAddr, Arrival)>>,
    sent: Cell<u64>,
    events: RefCell<Vec<NetEvent>>,
    /// The address whose datagrams are kept instead of delivered, and the datagrams kept.
    held: RefCell<Option<(SocketAddr, Vec<Arrival>)>>,
}

/// The in-memory network and the test clock.
#[derive(Clone)]
pub(crate) struct Net(Rc<NetState>);

impl Net {
    fn new() -> Self {
        let start = Instant::now();
        Self(Rc::new(NetState {
            start,
            now: Cell::new(start),
            costs: Cell::default(),
            next_port: Cell::new(FIRST_PORT),
            ports: RefCell::default(),
            flights: RefCell::default(),
            sent: Cell::new(0),
            events: RefCell::default(),
            held: RefCell::default(),
        }))
    }

    pub(crate) fn start(&self) -> Instant {
        self.0.start
    }

    pub(crate) fn now(&self) -> Instant {
        self.0.now.get()
    }

    pub(crate) fn costs(&self) -> Costs {
        self.0.costs.get()
    }

    pub(crate) fn set_costs(&self, costs: Costs) {
        self.0.costs.set(costs);
    }

    /// Moves the clock on by `cost`.
    pub(crate) fn charge(&self, cost: Duration) {
        self.0.now.set(self.now() + cost);
    }

    pub(crate) fn events(&self) -> Vec<NetEvent> {
        self.0.events.borrow().clone()
    }

    pub(crate) fn clear_events(&self) {
        self.0.events.borrow_mut().clear();
    }

    fn log(&self, event: NetEvent) {
        self.0.events.borrow_mut().push(event);
    }

    /// Keeps the datagrams sent to `dst` from now on instead of delivering them.
    pub(crate) fn hold(&self, dst: SocketAddr) {
        *self.0.held.borrow_mut() = Some((dst, Vec::new()));
    }

    /// Stops holding and returns the datagrams held.
    pub(crate) fn take_held(&self) -> Vec<Arrival> {
        self.0
            .held
            .borrow_mut()
            .take()
            .map_or_else(Vec::new, |(_, held)| held)
    }

    /// Blocks the socket at `addr`, which then refuses datagrams until [`unblock`](Self::unblock).
    pub(crate) fn block(&self, addr: SocketAddr) {
        self.port(addr).blocked.set(true);
    }

    /// Makes the socket at `addr` writable again and wakes the task waiting for that.
    pub(crate) fn unblock(&self, addr: SocketAddr) {
        let port = self.port(addr);
        port.blocked.set(false);
        if let Some(waker) = port.writable.borrow_mut().take() {
            waker.wake();
        }
    }

    /// Hands `arrival` to the socket at `dst` at once.
    pub(crate) fn inject(&self, dst: SocketAddr, arrival: Arrival) {
        let Some(port) = self.0.ports.borrow().get(&dst).cloned() else {
            return;
        };
        port.inbox.borrow_mut().push_back(arrival);
        if let Some(waker) = port.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    fn send(&self, dst: SocketAddr, arrival: Arrival) {
        if let Some((held_dst, held)) = self.0.held.borrow_mut().as_mut()
            && *held_dst == dst
        {
            held.push(arrival);
            return;
        }
        let seq = self.0.sent.get();
        self.0.sent.set(seq + 1);
        self.0
            .flights
            .borrow_mut()
            .insert((self.now() + DELAY, seq), (dst, arrival));
    }

    /// Delivers every datagram whose arrival time has come.
    fn deliver(&self) {
        loop {
            let due = {
                let mut flights = self.0.flights.borrow_mut();
                match flights.first_key_value() {
                    Some((&(at, _), _)) if at <= self.now() => flights.pop_first(),
                    _ => None,
                }
            };
            let Some((_, (dst, arrival))) = due else {
                return;
            };
            self.inject(dst, arrival);
        }
    }

    fn next_flight(&self) -> Option<Instant> {
        self.0
            .flights
            .borrow()
            .first_key_value()
            .map(|(&(at, _), _)| at)
    }

    fn port(&self, addr: SocketAddr) -> Rc<Port> {
        Rc::clone(self.0.ports.borrow_mut().entry(addr).or_default())
    }

    fn next_addr(&self) -> SocketAddr {
        let port = self.0.next_port.get();
        self.0.next_port.set(port + 1);
        SocketAddr::from(([127, 0, 0, 1], port))
    }
}

/// The settings of a [`MemBackend`].
#[derive(Clone, Default)]
pub(crate) struct MemOptions {
    pub(crate) net: Option<Net>,
    /// Whether the caps have kernel release, with a 2 ms horizon; runs still leave at the flush.
    pub(crate) release: bool,
    /// The most datagrams of one send, 64 if `None`.
    pub(crate) max_segments: Option<u16>,
}

/// A socket on the lab network. Its runs leave at its flush and arrive [`DELAY`] later, it takes
/// up to 64 arrivals per receive, it sends up to 64 datagrams at once unless its options set
/// another limit, and it is writable unless the test blocks it.
pub(crate) struct MemBackend {
    net: Net,
    addr: SocketAddr,
    port: Rc<Port>,
    caps: TxCaps,
    slot: Vec<u8>,
    next_slot: u32,
    runs: Vec<(ConnKey, TxMeta, Vec<Vec<u8>>)>,
    reports: Vec<(ConnKey, TxReport)>,
    batch: Vec<(RxMeta, Vec<u8>)>,
}

impl MemBackend {
    fn open(options: &MemOptions, addr: Option<SocketAddr>) -> io::Result<Self> {
        let net = options
            .net
            .clone()
            .ok_or_else(|| io::Error::other("the options name no lab network"))?;
        let addr = addr.unwrap_or_else(|| net.next_addr());
        let release = if options.release {
            ReleaseSupport::Kernel {
                horizon: Duration::from_millis(2),
                epoch: ClockEpoch {
                    instant: net.start(),
                    tick: Tick(0),
                },
            }
        } else {
            ReleaseSupport::None
        };
        Ok(Self {
            port: net.port(addr),
            net,
            addr,
            caps: TxCaps {
                max_segments: options.max_segments.unwrap_or(64),
                max_datagram: MAX_DATAGRAM,
                gro: true,
                ecn: false,
                pktinfo: false,
                release,
                send_buffer: 1 << 30,
            },
            slot: Vec::new(),
            next_slot: 0,
            runs: Vec::new(),
            reports: Vec::new(),
            batch: Vec::new(),
        })
    }
}

/// A [`MemBackend`]'s view for one connection's transmit attempt.
pub(crate) struct MemSink<'a> {
    backend: &'a mut MemBackend,
    conn: ConnKey,
    run: Vec<Vec<u8>>,
    /// The number of datagrams the attempt built.
    built: u16,
}

impl Drop for MemSink<'_> {
    fn drop(&mut self) {
        let backend = &*self.backend;
        backend
            .net
            .log(NetEvent::Built(backend.addr, self.conn, self.built));
    }
}

impl SegmentSink for MemSink<'_> {
    fn next_segment(&mut self, max_len: u16, _class: TxClass) -> Option<(SlotId, &mut [u8])> {
        let backend = &mut *self.backend;
        if backend.port.blocked.get() {
            return None;
        }
        backend.slot.clear();
        backend
            .slot
            .resize(usize::from(max_len.min(backend.caps.max_datagram)), 0);
        backend.next_slot = backend.next_slot.wrapping_add(1);
        Some((SlotId(backend.next_slot), &mut backend.slot[..]))
    }

    fn end_segment(&mut self, len: u16) {
        if len > 0 {
            self.built += 1;
            self.run
                .push(self.backend.slot[..usize::from(len)].to_vec());
        }
    }

    fn end_run(&mut self, meta: TxMeta) {
        self.backend.net.log(NetEvent::Run(
            self.backend.addr,
            self.conn,
            meta.release,
            self.run.len(),
        ));
        self.backend
            .runs
            .push((self.conn, meta, mem::take(&mut self.run)));
    }
}

impl TxBackend for MemBackend {
    type Sink<'a> = MemSink<'a>;

    fn caps(&self) -> &TxCaps {
        &self.caps
    }

    fn sink(&mut self, conn: ConnKey) -> MemSink<'_> {
        self.net.charge(self.net.costs().attempt);
        self.net.log(NetEvent::Attempt(self.addr, conn));
        MemSink {
            backend: self,
            conn,
            run: Vec::new(),
            built: 0,
        }
    }

    fn flush(&mut self, _now: Instant) -> FlushOutcome {
        self.net.log(NetEvent::Flush(self.addr));
        let mut datagrams = 0;
        for (conn, meta, segments) in self.runs.drain(..) {
            if !meta.sealed {
                self.reports.push((
                    conn,
                    TxReport::Dropped {
                        tx: meta.tx,
                        reason: DropReason::Error,
                    },
                ));
                continue;
            }
            for data in segments {
                datagrams += 1;
                let stride = u16::try_from(data.len()).expect("a datagram fits a stride");
                self.net.send(
                    meta.dst,
                    Arrival {
                        src: self.addr,
                        stride,
                        data,
                    },
                );
            }
            self.reports.push((conn, TxReport::Flushed { tx: meta.tx }));
        }
        self.net.charge(self.net.costs().flush * datagrams);
        FlushOutcome {
            datagrams,
            blocked: self.port.blocked.get(),
        }
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.port.blocked.get() {
            *self.port.writable.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(())
    }

    fn drain_reports(&mut self, mut f: impl FnMut(ConnKey, TxReport)) {
        for (conn, report) in self.reports.drain(..) {
            f(conn, report);
        }
    }
}

impl RxBackend for MemBackend {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.net.deliver();
        let mut inbox = self.port.inbox.borrow_mut();
        if inbox.is_empty() {
            *self.port.waker.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.batch.clear();
        let now = self.net.now();
        let mut datagrams = 0;
        while self.batch.len() < RX_BATCH
            && let Some(arrival) = inbox.pop_front()
        {
            datagrams += arrival
                .data
                .len()
                .div_ceil(usize::from(arrival.stride).max(1));
            let meta = RxMeta {
                src: arrival.src,
                dst_ip: None,
                ecn: Ecn::NotEct,
                stride: arrival.stride,
                rx_time: now,
            };
            self.batch.push((meta, arrival.data));
        }
        self.net.log(NetEvent::Recv(self.addr, datagrams));
        Poll::Ready(Ok(datagrams))
    }

    fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])> {
        self.net.charge(self.net.costs().chunk);
        self.net.log(NetEvent::Chunk(self.addr));
        self.batch
            .iter_mut()
            .map(|(meta, data)| (&*meta, &mut data[..]))
    }
}

impl Backend for MemBackend {
    type Options = MemOptions;

    fn bind(addr: SocketAddr, options: &MemOptions) -> io::Result<Self> {
        Self::open(options, Some(addr))
    }

    fn connect(_remote: SocketAddr, options: &MemOptions) -> io::Result<Self> {
        Self::open(options, None)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// The waker of one lab task: queues the task once until it is polled.
struct TaskWake {
    id: usize,
    queued: AtomicBool,
    ready: Arc<Mutex<VecDeque<usize>>>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::SeqCst) {
            self.ready.lock().expect("the queue").push_back(self.id);
        }
    }
}

/// The wakeup of the lab wheel: the instant it is armed for.
struct WheelAt(Rc<Cell<Option<Instant>>>);

impl WheelWakeup for WheelAt {
    fn arm(&self, deadline: Instant) {
        self.0.set(Some(deadline));
    }

    fn disarm(&self) {
        self.0.set(None);
    }
}

/// The lab's host, which runs its tasks only when the test polls them, on the network's clock.
struct Exec {
    net: Net,
    tasks: RefCell<Vec<Option<LocalFuture>>>,
    wakes: RefCell<Vec<Arc<TaskWake>>>,
    ready: Arc<Mutex<VecDeque<usize>>>,
    wheel: Rc<WheelTimer>,
    wheel_at: Rc<Cell<Option<Instant>>>,
}

impl LocalHost for Exec {
    fn spawn_local(&self, future: LocalFuture) {
        let mut tasks = self.tasks.borrow_mut();
        let wake = Arc::new(TaskWake {
            id: tasks.len(),
            queued: AtomicBool::new(false),
            ready: Arc::clone(&self.ready),
        });
        tasks.push(Some(future));
        wake.wake_by_ref();
        self.wakes.borrow_mut().push(wake);
    }

    fn now(&self) -> Instant {
        self.net.charge(self.net.costs().read);
        self.net.now()
    }

    fn sleep_until(&self, _deadline: Instant) -> LocalFuture {
        panic!("timeouts take a slot on the wheel");
    }

    fn yield_to_io(&self) -> LocalFuture {
        let mut yielded = false;
        Box::pin(poll_fn(move |cx| {
            if mem::replace(&mut yielded, true) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }))
    }

    fn wheel_timer(&self) -> Option<Rc<WheelTimer>> {
        Some(Rc::clone(&self.wheel))
    }
}

/// One Roxygen worker on the lab host, and the lab network.
pub(crate) struct Lab {
    pub(crate) net: Net,
    exec: Rc<Exec>,
    worker: WorkerHandle,
    ctx: WorkerContext,
    root: usize,
    /// Budgets refilled at the start of each iteration of [`settle`](Self::settle).
    budgets: RefCell<Vec<WorkBudget>>,
}

impl Lab {
    pub(crate) fn new() -> Self {
        let net = Net::new();
        let wheel_at = Rc::new(Cell::new(None));
        let wheel = WheelTimer::new(TICK, net.now(), Box::new(WheelAt(Rc::clone(&wheel_at))));
        let exec = Rc::new(Exec {
            net: net.clone(),
            tasks: RefCell::default(),
            wakes: RefCell::default(),
            ready: Arc::default(),
            wheel,
            wheel_at,
        });
        let (worker, driver) =
            WorkerDriver::with_host(64, Host::new(exec.clone())).expect("a hosted worker");
        let ctx = driver.context().clone();
        exec.spawn_local(Box::pin(driver));
        let root = exec.tasks.borrow().len() - 1;
        Self {
            net,
            exec,
            worker,
            ctx,
            root,
            budgets: RefCell::default(),
        }
    }

    /// Refills `budget` at the start of each iteration of [`settle`](Self::settle), as a host
    /// refills its budget once per loop iteration.
    pub(crate) fn refill_each_iteration(&self, budget: &WorkBudget) {
        self.budgets.borrow_mut().push(budget.clone());
    }

    pub(crate) fn ctx(&self) -> &WorkerContext {
        &self.ctx
    }

    /// Returns the host timers of a driver on the lab worker: its wheel, without a fine timer.
    pub(crate) fn timers() -> HostTimers {
        HostTimers::new(TICK, None)
    }

    /// Returns the index of the task spawned last: an endpoint driver's, right after it spawns.
    pub(crate) fn last_spawned(&self) -> usize {
        self.exec.tasks.borrow().len() - 1
    }

    /// Returns whether `task` is woken and waits to be polled.
    pub(crate) fn queued(&self, task: usize) -> bool {
        self.exec.wakes.borrow()[task].queued.load(Ordering::SeqCst)
    }

    /// Polls `task` once if it is queued; returns whether it was.
    pub(crate) fn poll(&self, task: usize) -> bool {
        let wake = Arc::clone(&self.exec.wakes.borrow()[task]);
        if !wake.queued.swap(false, Ordering::SeqCst) {
            return false;
        }
        self.exec
            .ready
            .lock()
            .expect("the queue")
            .retain(|&queued| queued != task);
        let Some(mut future) = self.exec.tasks.borrow_mut()[task].take() else {
            return false;
        };
        let waker = Waker::from(wake);
        if future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
        {
            self.exec.tasks.borrow_mut()[task] = Some(future);
        }
        true
    }

    /// Polls the queued tasks but `skip` until only `skip`, if any, is left queued, in iterations:
    /// each refills the budgets given to [`refill_each_iteration`](Self::refill_each_iteration),
    /// then polls the tasks queued as it starts, in wake order.
    pub(crate) fn settle_except(&self, skip: Option<usize>) {
        for _ in 0..100_000 {
            for budget in self.budgets.borrow().iter() {
                budget.refill();
            }
            let batch: Vec<usize> = {
                let ready = self.exec.ready.lock().expect("the queue");
                ready
                    .iter()
                    .copied()
                    .filter(|&task| Some(task) != skip)
                    .collect()
            };
            if batch.is_empty() {
                return;
            }
            for task in batch {
                self.poll(task);
            }
        }
        panic!("the lab does not settle");
    }

    /// Polls the queued tasks until the queue is empty.
    pub(crate) fn settle(&self) {
        self.settle_except(None);
    }

    /// Moves the clock on by `by`, delivering the datagrams and firing the wheel as they come due.
    pub(crate) fn advance(&self, by: Duration) {
        self.advance_to(self.net.now() + by);
    }

    fn advance_to(&self, at: Instant) {
        if at > self.net.now() {
            self.net.0.now.set(at);
        }
        self.net.deliver();
        if let Some(due) = self.exec.wheel_at.get()
            && due <= self.net.now()
        {
            self.exec.wheel_at.set(None);
            self.exec.wheel.expire(self.net.now());
        }
    }

    /// Runs every task, moving the clock to the next arrival or wheel wake whenever all are idle,
    /// until `done` holds.
    pub(crate) fn run_until(&self, mut done: impl FnMut() -> bool) {
        for _ in 0..100_000 {
            self.settle();
            if done() {
                return;
            }
            let next = self
                .net
                .next_flight()
                .into_iter()
                .chain(self.exec.wheel_at.get())
                .min();
            let Some(next) = next else {
                panic!("the lab stalled before the condition held");
            };
            self.advance_to(next);
        }
        panic!("the condition did not hold within the lab's step cap");
    }

    /// Runs every task, moving the clock to each arrival and wheel wake, until the next one lies
    /// more than `limit` from now.
    pub(crate) fn run_quiet(&self, limit: Duration) {
        let end = self.net.now() + limit;
        loop {
            self.settle();
            let next = self
                .net
                .next_flight()
                .into_iter()
                .chain(self.exec.wheel_at.get())
                .min();
            match next {
                Some(next) if next <= end => self.advance_to(next),
                _ => return,
            }
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        self.worker.begin_shutdown();
        for _ in 0..1_000 {
            self.settle();
            if self.exec.tasks.borrow()[self.root].is_none() {
                return;
            }
            self.advance(TICK);
        }
        panic!("the lab worker did not shut down");
    }
}

/// The state a [`Bulk`] session shares with its test.
#[derive(Default)]
pub(crate) struct Probe {
    pub(crate) handle: RefCell<Option<ConnHandle>>,
    pub(crate) connected: Cell<bool>,
    /// Stream bytes received.
    pub(crate) received: Cell<u64>,
    /// Streams the peer finished.
    pub(crate) finished: Cell<usize>,
    /// The connection's counters after its last callback.
    pub(crate) stats: Cell<ConnStats>,
    /// The number of further `poll_session` calls that mark the connection dirty; each but the
    /// last wakes the session again.
    pub(crate) pokes: Cell<u64>,
    /// `poll_session` calls.
    pub(crate) visits: Cell<u64>,
    /// `poll_send` calls.
    pub(crate) sends: Cell<u64>,
    /// Streams to open in the next `poll_session`.
    open: Cell<usize>,
    /// Whether the connection has closed.
    pub(crate) closed: Cell<bool>,
    /// Whether the next `poll_session` aborts the connection.
    pub(crate) aborts: Cell<bool>,
}

impl Probe {
    /// Marks the connection dirty in its next `poll_session` calls, `pokes` of them.
    pub(crate) fn poke(&self, pokes: u64) {
        self.pokes.set(pokes);
        if let Some(handle) = self.handle.borrow().as_ref() {
            handle.wake().expect("the connection is open");
        }
    }

    /// Opens `streams` more streams in the next `poll_session`.
    pub(crate) fn open_streams(&self, streams: usize) {
        self.open.set(streams);
        if let Some(handle) = self.handle.borrow().as_ref() {
            handle.wake().expect("the connection is open");
        }
    }
}

/// Zeros to send.
static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];

/// A session that, once connected, opens `streams` unidirectional streams and sends `len` bytes
/// and the FIN on each (or sends without end if `len` is `None`), and reads all it receives. Each
/// `poll_session` charges the visit cost.
pub(crate) struct Bulk {
    net: Net,
    probe: Rc<Probe>,
    streams: usize,
    len: Option<usize>,
    sent: HashMap<StreamId, usize>,
}

impl Bulk {
    pub(crate) fn new(net: &Net, streams: usize, len: Option<usize>) -> (Self, Rc<Probe>) {
        let probe = Rc::new(Probe::default());
        let session = Self {
            net: net.clone(),
            probe: Rc::clone(&probe),
            streams,
            len,
            sent: HashMap::new(),
        };
        (session, probe)
    }

    fn open(&mut self, conn: &mut Conn<'_>, streams: usize) {
        for _ in 0..streams {
            let id = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
            self.sent.insert(id, 0);
            conn.stream_waker(id).wake();
        }
        self.probe.stats.set(conn.stats());
    }
}

impl QuicSession for Bulk {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        if matches!(event, ConnEvent::Closed { .. }) {
            self.probe.closed.set(true);
        }
        if event != ConnEvent::Connected {
            return;
        }
        self.probe.connected.set(true);
        *self.probe.handle.borrow_mut() = Some(conn.handle());
        self.open(conn, self.streams);
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        if matches!(ready, StreamReady::Readable | StreamReady::Finished)
            && let Ok(mut stream) = conn.stream(id)
        {
            let len: usize = stream.readable().segments().map(Bytes::len).sum();
            stream.consume(len).expect("the bytes are readable");
            self.probe
                .received
                .set(self.probe.received.get() + len as u64);
            if ready == StreamReady::Finished {
                self.probe.finished.set(self.probe.finished.get() + 1);
            }
        }
        self.probe.stats.set(conn.stats());
    }

    fn poll_send(
        &mut self,
        _: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        self.probe.sends.set(self.probe.sends.get() + 1);
        let Some(sent) = self.sent.get_mut(&id) else {
            return Poll::Pending;
        };
        let left = self.len.map_or(usize::MAX, |len| len - *sent);
        let push = left.min(sink.allowance()).min(ZEROS.len());
        if push > 0 {
            sink.push(Bytes::from_static(&ZEROS[..push]))
                .expect("within the allowance");
            *sent += push;
        }
        if push == left {
            sink.finish().expect("the stream is open");
            self.sent.remove(&id);
        }
        Poll::Ready(())
    }

    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        self.net.charge(self.net.costs().visit);
        self.probe.visits.set(self.probe.visits.get() + 1);
        if self.probe.aborts.take() {
            conn.abort();
            return Poll::Pending;
        }
        let streams = self.probe.open.take();
        self.open(conn, streams);
        self.probe.stats.set(conn.stats());
        let pokes = self.probe.pokes.get();
        if pokes > 0 {
            self.probe.pokes.set(pokes - 1);
            let _ = &mut **conn;
            if pokes > 1 {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}

/// How a [`LabApp`] answers the `n`-th connection attempt, from 0: the session, and the
/// options set for its connection.
type Accept = Box<dyn FnMut(usize, &mut ConnOptions) -> Bulk>;

/// The lab's application, which accepts every attempt, charging each its cost, and counts the
/// accepted ones.
pub(crate) struct LabApp {
    net: Net,
    accept: Accept,
    /// The cost of each accept by its number; later accepts cost the last, or zero if the list is
    /// empty.
    pub(crate) accept_costs: Vec<Duration>,
    pub(crate) accepted: Rc<Cell<usize>>,
}

impl LabApp {
    pub(crate) fn new(
        net: &Net,
        accept: impl FnMut(usize, &mut ConnOptions) -> Bulk + 'static,
    ) -> Self {
        Self {
            net: net.clone(),
            accept: Box::new(accept),
            accept_costs: Vec::new(),
            accepted: Rc::default(),
        }
    }

    /// Returns an application for a driver that only opens connections.
    pub(crate) fn client(net: &Net) -> Self {
        Self::new(net, |_, _| panic!("a client driver accepts nothing"))
    }
}

impl QuicApplication for LabApp {
    type Session = Bulk;

    fn accept(&mut self, _info: &ConnInfo, options: &mut ConnOptions) -> Result<Bulk, Refusal> {
        let n = self.accepted.get();
        let cost = self
            .accept_costs
            .get(n)
            .or(self.accept_costs.last())
            .copied()
            .unwrap_or_default();
        self.net.charge(cost);
        self.accepted.set(n + 1);
        Ok((self.accept)(n, options))
    }
}

/// Returns the lab's configs: an Ed25519 certificate with a fixed serial number, so every run
/// sends handshakes of the same sizes.
pub(crate) fn lab_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<EndpointConfig>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("rcgen makes a key");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen takes the name");
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    configs_with(params, &key)
}

/// Returns transport settings with room for bulk transfers from the first flight, and pacing on
/// or off.
pub(crate) fn transport(pacing: bool) -> Arc<TransportConfig> {
    TransportConfig::builder()
        .initial_window(1_000)
        .initial_rtt(Duration::from_millis(1))
        .max_data(1 << 30)
        .max_stream_data_uni(1 << 26)
        .max_streams_uni(1 << 20)
        .pacing(pacing)
        .build()
        .expect("a transport config")
}
