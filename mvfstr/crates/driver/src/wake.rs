/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Wakes from any thread: a stream waker or a connection's own waker sets a bit on the
//! connection's [`ConnWake`], which queues the connection once on the endpoint's ready list and
//! wakes the endpoint task; the next turn takes the bits. A close from a
//! [`ConnHandle`](crate::ConnHandle) waits in a single slot per connection.

#[cfg(test)]
use std::cell::Cell;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::task::Wake;
use std::task::Waker;

use bytes::Bytes;
use mvfstr_proto::AppCode;
use mvfstr_proto::ConnKey;
use mvfstr_proto::StreamId;
use roxygen_runtime::worker::SubmitError;

/// The session's own waker or a [`ConnHandle`](crate::ConnHandle) woke the session.
pub(crate) const APP: u8 = 1;
/// A close is pending.
pub(crate) const CMD: u8 = 1 << 1;
/// The connection's own socket may be readable.
pub(crate) const RX: u8 = 1 << 2;
/// The connection's own socket may be writable again.
pub(crate) const TX: u8 = 1 << 3;
/// A stream waker fired.
pub(crate) const STREAM: u8 = 1 << 4;
/// The session's datagram waker fired.
pub(crate) const DATAGRAM: u8 = 1 << 5;

/// The ready list and task waker that the endpoint task shares with every connection's wakes.
#[derive(Default)]
pub(crate) struct Shared {
    ready: Mutex<Vec<ConnKey>>,
    task: Mutex<Option<Waker>>,
}

impl Shared {
    /// Records the endpoint task's waker.
    pub(crate) fn register(&self, waker: &Waker) {
        let mut task = lock(&self.task);
        if !task.as_ref().is_some_and(|known| known.will_wake(waker)) {
            *task = Some(waker.clone());
        }
    }

    /// Wakes the endpoint task.
    pub(crate) fn wake_task(&self) {
        // Woken outside the lock: the task's waker takes its own locks.
        let waker = lock(&self.task).clone();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Moves the queued connections into `into`.
    pub(crate) fn take_ready(&self, into: &mut Vec<ConnKey>) {
        into.append(&mut lock(&self.ready));
    }

    fn push_ready(&self, key: ConnKey) {
        lock(&self.ready).push(key);
        self.wake_task();
    }
}

/// Locks `mutex`, ignoring poison: code does not panic while it holds these locks, so a poisoned
/// one still holds consistent data.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// A close from a [`ConnHandle`](crate::ConnHandle), with an application CONNECTION_CLOSE.
#[derive(Debug)]
pub(crate) struct Close {
    pub(crate) code: AppCode,
    pub(crate) reason: Bytes,
}

/// One connection's wake state, shared with its wakers and handles.
pub(crate) struct ConnWake {
    shared: Arc<Shared>,
    key: ConnKey,
    queued: AtomicBool,
    bits: AtomicU8,
    closed: AtomicBool,
    /// The stream wakers that fired since the last take, each once.
    streams: Mutex<Vec<Arc<StreamWake>>>,
    pending: Mutex<Option<Close>>,
}

impl ConnWake {
    pub(crate) fn new(shared: Arc<Shared>, key: ConnKey) -> Arc<Self> {
        Arc::new(Self {
            shared,
            key,
            queued: AtomicBool::new(false),
            bits: AtomicU8::new(0),
            closed: AtomicBool::new(false),
            streams: Mutex::new(Vec::new()),
            pending: Mutex::new(None),
        })
    }

    /// Sets `bits` and queues the connection unless it is queued already.
    pub(crate) fn wake(&self, bits: u8) {
        if self.is_closed() {
            return;
        }
        self.bits.fetch_or(bits, Ordering::SeqCst);
        if !self.queued.swap(true, Ordering::SeqCst) {
            self.shared.push_ready(self.key);
        }
    }

    /// Takes the bits set since the last call; a wake after this queues the connection again.
    pub(crate) fn take(&self) -> u8 {
        // Cleared before the bits are read, so a wake racing this call either lands in the bits
        // read or queues the connection again.
        self.queued.store(false, Ordering::SeqCst);
        self.bits.swap(0, Ordering::SeqCst)
    }

    /// Returns a waker that sets `bits`.
    pub(crate) fn waker(self: &Arc<Self>, bits: u8) -> Waker {
        #[cfg(test)]
        BIT_WAKES.with(|built| built.set(built.get() + 1));
        Waker::from(Arc::new(BitWake {
            conn: Arc::clone(self),
            bits,
        }))
    }

    /// Returns a waker that marks stream `id`'s producer ready before the connection's next pull
    /// step: it records `id` and sets [`STREAM`].
    pub(crate) fn stream_waker(self: &Arc<Self>, id: StreamId) -> Waker {
        Waker::from(Arc::new(StreamWake {
            conn: Arc::clone(self),
            id,
            queued: AtomicBool::new(false),
        }))
    }

    /// Moves the streams whose wakers fired into `into`, once per waker.
    pub(crate) fn take_streams(&self, into: &mut Vec<StreamId>) {
        for stream in lock(&self.streams).drain(..) {
            // Cleared under the lock: a wake after this queues the waker again, and one before
            // it is served by this take.
            stream.queued.store(false, Ordering::SeqCst);
            into.push(stream.id);
        }
    }

    /// Puts `close` in the slot and sets [`CMD`], or drops it while an earlier close waits there:
    /// a closing connection ignores later closes. Fails with `Closed` once the connection is gone.
    pub(crate) fn submit(&self, close: Close) -> Result<(), SubmitError> {
        {
            let mut slot = lock(&self.pending);
            // Checked under the lock, so a close never lands after `Self::close` emptied the slot.
            if self.is_closed() {
                return Err(SubmitError::Closed);
            }
            if slot.is_some() {
                return Ok(());
            }
            *slot = Some(close);
        }
        self.wake(CMD);
        Ok(())
    }

    /// Takes the pending close.
    pub(crate) fn take_close(&self) -> Option<Close> {
        lock(&self.pending).take()
    }

    /// Returns whether the connection is gone.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Marks the connection gone: handles fail from now on and wakes are ignored.
    pub(crate) fn close(&self) {
        let mut slot = lock(&self.pending);
        self.closed.store(true, Ordering::SeqCst);
        *slot = None;
        drop(slot);
        lock(&self.streams).clear();
    }
}

impl fmt::Debug for ConnWake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnWake")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
thread_local! {
    /// The number of [`BitWake`]s built on this thread, in tests.
    pub(crate) static BIT_WAKES: Cell<u64> = const { Cell::new(0) };
}

/// A waker that sets bits on a connection.
struct BitWake {
    conn: Arc<ConnWake>,
    bits: u8,
}

impl Wake for BitWake {
    fn wake(self: Arc<Self>) {
        self.conn.wake(self.bits);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.conn.wake(self.bits);
    }
}

/// A waker for one stream's producer.
struct StreamWake {
    conn: Arc<ConnWake>,
    id: StreamId,
    /// Whether this waker is on the connection's list of fired stream wakers.
    queued: AtomicBool,
}

impl StreamWake {
    /// Puts this waker on its connection's list unless it is there already, and sets [`STREAM`].
    fn fire(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::SeqCst) {
            let mut streams = lock(&self.conn.streams);
            // Checked under the lock, so a waker never lands after `close` emptied the list,
            // where it would keep its connection alive through a cycle.
            if self.conn.is_closed() {
                return;
            }
            streams.push(Arc::clone(self));
        }
        self.conn.wake(STREAM);
    }
}

impl Wake for StreamWake {
    fn wake(self: Arc<Self>) {
        self.fire();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.fire();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use std::time::Instant;

    use mvfstr_proto::VarInt;

    use super::*;

    /// A task waker that counts its wakes.
    #[derive(Default)]
    pub(crate) struct CountingWaker(pub(crate) AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const KEY: ConnKey = ConnKey {
        index: 3,
        generation: 7,
    };

    #[test]
    fn a_connection_is_queued_once_until_its_bits_are_taken() {
        let shared = Arc::new(Shared::default());
        let task = Arc::new(CountingWaker::default());
        shared.register(&Waker::from(task.clone()));
        let wake = ConnWake::new(shared.clone(), KEY);

        wake.wake(APP);
        wake.wake(RX);
        let mut ready = Vec::new();
        shared.take_ready(&mut ready);
        assert_eq!(ready, [KEY], "two wakes queue the connection once");
        assert_eq!(task.0.load(Ordering::SeqCst), 1, "and wake the task once");
        assert_eq!(wake.take(), APP | RX);
        assert_eq!(wake.take(), 0, "taking clears the bits");

        ready.clear();
        shared.take_ready(&mut ready);
        assert!(ready.is_empty());
        wake.wake(CMD);
        shared.take_ready(&mut ready);
        assert_eq!(ready, [KEY], "a wake after the take queues it again");
        assert_eq!(wake.take(), CMD);

        wake.close();
        assert!(wake.is_closed());
        ready.clear();
        wake.wake(APP);
        shared.take_ready(&mut ready);
        assert!(ready.is_empty(), "a closed connection is not queued");
    }

    #[test]
    fn stream_wakers_record_each_stream_once_and_set_the_stream_bit() {
        let shared = Arc::new(Shared::default());
        let wake = ConnWake::new(shared.clone(), KEY);
        let four = StreamId::from_varint(VarInt::from_u32(4));
        let eight = StreamId::from_varint(VarInt::from_u32(8));

        let waker = wake.stream_waker(four);
        waker.wake_by_ref();
        waker.wake_by_ref();
        wake.stream_waker(eight).wake();
        assert_eq!(wake.take(), STREAM);
        let mut streams = Vec::new();
        wake.take_streams(&mut streams);
        assert_eq!(streams, [four, eight], "each woken stream once, in order");
        streams.clear();
        wake.take_streams(&mut streams);
        assert!(streams.is_empty());

        wake.waker(APP).wake();
        assert_eq!(wake.take(), APP, "a connection waker sets its own bit");
        let mut ready = Vec::new();
        shared.take_ready(&mut ready);
        assert_eq!(ready, [KEY, KEY], "queued once per take");

        waker.wake();
        wake.take_streams(&mut streams);
        assert_eq!(
            streams,
            [four],
            "a wake after the take records the stream again"
        );
    }

    #[test]
    fn a_stream_waker_that_fires_while_its_connection_closes_leaves_no_cycle() {
        let wake = ConnWake::new(Arc::new(Shared::default()), KEY);
        let stream = Arc::new(StreamWake {
            conn: Arc::clone(&wake),
            id: StreamId::from_varint(VarInt::from_u32(4)),
            queued: AtomicBool::new(false),
        });
        // Holding the list's lock stops the fire after it has claimed its place on the list.
        let mut list = lock(&wake.streams);
        let firing = std::thread::spawn({
            let stream = Arc::clone(&stream);
            move || stream.fire()
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stream.queued.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "the fire never started");
            std::thread::yield_now();
        }
        // What `close` does meanwhile: it marks the connection gone, then empties the list.
        wake.closed.store(true, Ordering::SeqCst);
        list.clear();
        drop(list);
        firing.join().expect("the fire finishes");

        assert!(
            lock(&wake.streams).is_empty(),
            "a stream waker landed on the list after close emptied it"
        );
        drop(stream);
        assert_eq!(
            Arc::strong_count(&wake),
            1,
            "nothing but its owner keeps the connection's wake state alive"
        );
    }

    #[test]
    fn many_closes_first_wins() {
        let shared = Arc::new(Shared::default());
        let wake = ConnWake::new(shared, KEY);
        let close = |code| Close {
            code: AppCode::from_u32(code),
            reason: Bytes::new(),
        };
        for code in 1..=100 {
            assert_eq!(
                wake.submit(close(code)),
                Ok(()),
                "close {code} is refused while the connection is live"
            );
        }
        assert_eq!(wake.take(), CMD);
        let Some(Close { code, .. }) = wake.take_close() else {
            panic!("the first close is missing");
        };
        assert_eq!(code, AppCode::from_u32(1), "the first close wins");
        assert!(wake.take_close().is_none(), "the later closes are not kept");

        wake.submit(close(101)).unwrap();
        wake.close();
        assert!(
            wake.take_close().is_none(),
            "closing drops the pending close"
        );
        assert_eq!(wake.submit(close(102)), Err(SubmitError::Closed));
    }
}
