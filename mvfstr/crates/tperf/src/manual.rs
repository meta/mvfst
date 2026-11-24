/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The event loop of `--host_loop=manual`: a Roxygen worker on its own thread, run by a
//! single-threaded executor over a [`ManualHost`], without a tokio runtime. Endpoints opened by the
//! worker's commands use [`HostBackend`](mvfstr_io::HostBackend) with readiness from that host.

use std::cell::Cell;
use std::cell::OnceCell;
use std::cell::RefCell;
use std::future::Future;
use std::future::poll_fn;
use std::io;
use std::mem;
use std::panic::resume_unwind;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::ManualHost;
use mvfstr_io::Notifier;
use roxygen_runtime::driver::WorkerDriver;
use roxygen_runtime::host::Host;
use roxygen_runtime::host::LocalFuture;
use roxygen_runtime::host::LocalHost;
use roxygen_runtime::host::timer::Timeout;
use roxygen_runtime::host::timer::WheelTimer;
use roxygen_runtime::host::timer::WheelWakeup;
use roxygen_runtime::worker::WorkerHandle;

/// The wheel's tick, the same as a managed worker's.
const WHEEL_TICK: Duration = Duration::from_millis(1);

/// Task polls in a row after which the loop polls the host without blocking, as tokio's
/// scheduler does after its event interval.
const EVENT_INTERVAL: usize = 61;

thread_local! {
    /// The host of the loop this thread runs, for the endpoints its commands open.
    static IO_HOST: RefCell<Option<ManualHost>> = const { RefCell::new(None) };
    /// The address of the running loop's [`Shared`] state, 0 off a loop thread.
    static CURRENT: Cell<usize> = const { Cell::new(0) };
    /// The indices of the tasks woken on the loop's own thread since it last took them.
    static LOCAL_READY: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Returns the host of the manual loop running on this thread, if there is one.
pub(crate) fn io_host() -> Option<ManualHost> {
    IO_HOST.with_borrow(Clone::clone)
}

/// A Roxygen worker on its own thread, run by the manual loop until it is shut down or dropped.
pub(crate) struct ManualWorker {
    handle: WorkerHandle,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl ManualWorker {
    /// Starts a worker whose command queue holds `command_capacity` commands.
    pub(crate) fn new(command_capacity: usize) -> io::Result<Self> {
        let (started_tx, started) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("tperf-manual".to_owned())
            .spawn(move || run_worker(command_capacity, &started_tx))?;
        match started.recv() {
            Ok(Ok(handle)) => Ok(Self {
                handle,
                thread: Some(thread),
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => match thread.join() {
                Ok(result) => Err(result.err().unwrap_or_else(|| {
                    io::Error::other("the manual loop stopped before its worker started")
                })),
                Err(payload) => resume_unwind(payload),
            },
        }
    }

    /// Returns the handle that submits commands to the worker.
    pub(crate) fn handle(&self) -> &WorkerHandle {
        &self.handle
    }

    /// Shuts the worker down and waits for its thread, returning the loop's error if it failed.
    /// Re-raises a panic of the loop.
    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.handle.begin_shutdown();
        self.thread.take().map_or(Ok(()), |thread| {
            thread
                .join()
                .unwrap_or_else(|payload| resume_unwind(payload))
        })
    }
}

impl Drop for ManualWorker {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.handle.begin_shutdown();
            let _ = thread.join();
        }
    }
}

/// Runs the body of a worker's thread: creates the host, the loop and the worker, reports the
/// worker's handle to `started`, and drives the loop until the worker has shut down.
fn run_worker(
    command_capacity: usize,
    started: &mpsc::Sender<io::Result<WorkerHandle>>,
) -> io::Result<()> {
    let io = match ManualHost::new() {
        Ok(io) => io,
        Err(error) => {
            let _ = started.send(Err(error));
            return Ok(());
        }
    };
    let manual = Rc::new(Loop::new(io.clone()));
    let (handle, driver) =
        match WorkerDriver::with_host(command_capacity, Host::new(manual.clone())) {
            Ok(created) => created,
            Err(error) => {
                let _ = started.send(Err(io::Error::other(error)));
                return Ok(());
            }
        };
    let _ = started.send(Ok(handle));
    IO_HOST.set(Some(io));
    let result = manual.run(driver);
    IO_HOST.set(None);
    result
}

/// The executor: tasks in a slab, woken by index.
struct Loop {
    io: ManualHost,
    shared: Arc<Shared>,
    tasks: RefCell<Vec<Option<Task>>>,
    /// Free slab indices.
    free: RefCell<Vec<usize>>,
    /// Futures spawned since the loop last took them.
    spawned: RefCell<Vec<LocalFuture>>,
    wheel: OnceCell<Rc<WheelTimer>>,
    /// The deadline of the wheel's wakeup, if it is armed.
    wake_at: Rc<Cell<Option<Instant>>>,
    /// Host polls so far.
    io_polls: Rc<Cell<u64>>,
    /// The tasks that yielded until the next host poll.
    yielders: Rc<RefCell<Vec<Waker>>>,
}

/// The loop's state that wakers on other threads reach.
struct Shared {
    /// The indices of the tasks woken from other threads.
    remote: Mutex<Vec<usize>>,
    /// Whether `remote` may have indices.
    pending: AtomicBool,
    /// The handle that ends the host's blocking poll when a task is woken from another thread.
    notifier: Notifier,
}

/// A spawned future and its waker.
struct Task {
    future: LocalFuture,
    wake: Arc<TaskWake>,
    waker: Waker,
}

/// The waker of one task.
struct TaskWake {
    index: usize,
    /// Whether the task is queued to be polled.
    queued: AtomicBool,
    shared: Arc<Shared>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        if CURRENT.get() == Arc::as_ptr(&self.shared).addr() {
            LOCAL_READY.with_borrow_mut(|ready| ready.push(self.index));
        } else {
            self.shared
                .remote
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(self.index);
            self.shared.pending.store(true, Ordering::Release);
            self.shared.notifier.notify();
        }
    }
}

impl Loop {
    fn new(io: ManualHost) -> Self {
        let notifier = io.notifier();
        Self {
            io,
            shared: Arc::new(Shared {
                remote: Mutex::new(Vec::new()),
                pending: AtomicBool::new(false),
                notifier,
            }),
            tasks: RefCell::new(Vec::new()),
            free: RefCell::new(Vec::new()),
            spawned: RefCell::new(Vec::new()),
            wheel: OnceCell::new(),
            wake_at: Rc::new(Cell::new(None)),
            io_polls: Rc::new(Cell::new(0)),
            yielders: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Runs `root` and every task it spawns until `root` completes, then drops the tasks left.
    fn run(&self, root: impl Future<Output = ()> + 'static) -> io::Result<()> {
        CURRENT.set(Arc::as_ptr(&self.shared).addr());
        let result = self.drive(Box::pin(root));
        CURRENT.set(0);
        LOCAL_READY.with_borrow_mut(Vec::clear);
        // The tasks hold the host, which holds the loop.
        let tasks = self.tasks.take();
        let spawned = self.spawned.take();
        drop((tasks, spawned));
        result
    }

    /// Polls the tasks and the host until `root` completes. Each iteration polls the tasks that are
    /// ready, then the host: without blocking after [`EVENT_INTERVAL`] task polls in a row or while
    /// a task yields to it, and otherwise, once the tasks are idle, until the wheel's wakeup.
    fn drive(&self, root: LocalFuture) -> io::Result<()> {
        let root = self.admit(root);
        let mut batch = Vec::new();
        let mut since_io = 0;
        loop {
            for future in self.spawned.take() {
                self.admit(future);
            }
            LOCAL_READY.with_borrow_mut(|ready| mem::swap(ready, &mut batch));
            if self.shared.pending.swap(false, Ordering::Acquire) {
                batch.append(&mut self.shared.remote.lock().unwrap_or_else(|p| p.into_inner()));
            }
            for index in batch.drain(..) {
                if self.poll_task(index) && index == root {
                    return Ok(());
                }
                since_io += 1;
            }
            let busy = LOCAL_READY.with_borrow(|ready| !ready.is_empty())
                || !self.spawned.borrow().is_empty()
                || self.shared.pending.load(Ordering::Acquire);
            let yielding = !self.yielders.borrow().is_empty();
            if busy && !yielding && since_io < EVENT_INTERVAL {
                continue;
            }
            since_io = 0;
            let timeout = if busy || yielding {
                Some(Duration::ZERO)
            } else {
                self.wake_at
                    .get()
                    .map(|at| at.saturating_duration_since(Instant::now()))
            };
            self.io.poll(timeout)?;
            self.io_polls.set(self.io_polls.get() + 1);
            for waker in self.yielders.take() {
                waker.wake();
            }
            if let Some(at) = self.wake_at.get() {
                let now = Instant::now();
                if now >= at {
                    self.wake_at.set(None);
                    if let Some(wheel) = self.wheel.get() {
                        wheel.expire(now);
                    }
                }
            }
        }
    }

    /// Returns the loop's wheel, creating it at the first use.
    fn wheel(&self) -> Rc<WheelTimer> {
        let wheel = self.wheel.get_or_init(|| {
            WheelTimer::new(
                WHEEL_TICK,
                Instant::now(),
                Box::new(Wakeup(Rc::clone(&self.wake_at))),
            )
        });
        Rc::clone(wheel)
    }

    /// Puts `future` in the slab and queues it, returning its index.
    fn admit(&self, future: LocalFuture) -> usize {
        let index = self.free.borrow_mut().pop().unwrap_or_else(|| {
            let mut tasks = self.tasks.borrow_mut();
            tasks.push(None);
            tasks.len() - 1
        });
        let wake = Arc::new(TaskWake {
            index,
            queued: AtomicBool::new(true),
            shared: Arc::clone(&self.shared),
        });
        let waker = Waker::from(Arc::clone(&wake));
        self.tasks.borrow_mut()[index] = Some(Task {
            future,
            wake,
            waker,
        });
        LOCAL_READY.with_borrow_mut(|ready| ready.push(index));
        index
    }

    /// Polls the task at `index`, if there is one, and returns whether it completed. A stale
    /// waker of a finished task may name a later task's index, which then takes a spurious poll.
    fn poll_task(&self, index: usize) -> bool {
        let Some(mut task) = self
            .tasks
            .borrow_mut()
            .get_mut(index)
            .and_then(Option::take)
        else {
            return false;
        };
        task.wake.queued.store(false, Ordering::Release);
        let mut cx = Context::from_waker(&task.waker);
        if task.future.as_mut().poll(&mut cx).is_ready() {
            self.free.borrow_mut().push(index);
            return true;
        }
        self.tasks.borrow_mut()[index] = Some(task);
        false
    }
}

impl LocalHost for Loop {
    fn spawn_local(&self, future: LocalFuture) {
        self.spawned.borrow_mut().push(future);
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> LocalFuture {
        let mut timeout = Timeout::with_wheel(self.wheel());
        let mut armed = false;
        Box::pin(poll_fn(move |cx| {
            if !armed {
                timeout.schedule_at(deadline, cx.waker());
                armed = true;
            }
            timeout.poll_expired(cx).map(drop)
        }))
    }

    fn yield_to_io(&self) -> LocalFuture {
        let polls = Rc::clone(&self.io_polls);
        let yielders = Rc::clone(&self.yielders);
        let after = polls.get();
        Box::pin(poll_fn(move |cx| {
            if polls.get() > after {
                return Poll::Ready(());
            }
            yielders.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        }))
    }

    fn wheel_timer(&self) -> Option<Rc<WheelTimer>> {
        Some(self.wheel())
    }
}

/// The wheel's wakeup: the deadline the loop expires the wheel at.
struct Wakeup(Rc<Cell<Option<Instant>>>);

impl WheelWakeup for Wakeup {
    fn arm(&self, deadline: Instant) {
        self.0.set(Some(deadline));
    }

    fn disarm(&self) {
        self.0.set(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails a test that would otherwise hang; passing runs never reach it.
    const HANG_GUARD: Duration = Duration::from_secs(20);

    #[test]
    fn a_command_submitted_from_another_thread_runs_on_the_loop_without_a_tokio_runtime() {
        let worker = ManualWorker::new(4).unwrap();
        let (ran_tx, ran) = mpsc::channel();
        worker
            .handle()
            .submit(move |_| {
                let _ = ran_tx.send((
                    thread::current().id(),
                    tokio::runtime::Handle::try_current().is_err(),
                    io_host().is_some(),
                ));
            })
            .expect("submitted");
        let (thread, no_runtime, host) = ran.recv_timeout(HANG_GUARD).expect("the command ran");
        assert_ne!(thread, thread::current().id());
        assert!(no_runtime, "no tokio runtime on the loop's thread");
        assert!(host, "the loop's host is there for the command's endpoints");
        worker.shutdown().unwrap();
    }

    #[test]
    fn a_sleep_ends_at_or_after_its_deadline() {
        let worker = ManualWorker::new(4).unwrap();
        let (early_tx, early) = mpsc::channel();
        worker
            .handle()
            .spawn_local(move |context| async move {
                let host = context.host().clone();
                let mut early = Vec::new();
                for micros in [0, 300, 1_500, 4_000] {
                    let deadline = host.now() + Duration::from_micros(micros);
                    host.sleep_until(deadline).await;
                    if Instant::now() < deadline {
                        early.push(micros);
                    }
                }
                let _ = early_tx.send(early);
            })
            .expect("submitted");
        assert_eq!(
            early.recv_timeout(HANG_GUARD).expect("the sleeps ended"),
            Vec::<u64>::new(),
            "ended early"
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn a_task_that_yields_to_io_on_an_idle_loop_resumes() {
        let worker = ManualWorker::new(4).unwrap();
        let (resumed_tx, resumed) = mpsc::channel();
        worker
            .handle()
            .spawn_local(move |context| async move {
                let host = context.host().clone();
                for _ in 0..3 {
                    host.yield_to_io().await;
                }
                let _ = resumed_tx.send(());
            })
            .expect("submitted");
        resumed.recv_timeout(HANG_GUARD).expect("the task resumed");
        worker.shutdown().unwrap();
    }
}
