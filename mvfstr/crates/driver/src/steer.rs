/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Worker steering for a server address that several workers share.
//!
//! The kernel's reuseport program
//! ([`steer_by_connection_id`](mvfstr_io::socket::steer_by_connection_id)) delivers each
//! datagram to the worker its destination connection ID names. A client's first Initial carries
//! an ID the client picked at random, so the worker that receives it picks the connection's
//! worker with a counter the group shares and, when that is another worker, hands the datagram
//! to it through the target's bounded inbox and wakes it. The target accepts the datagram as if
//! its own socket had received it and issues connection IDs that name it. A client takes the
//! server's ID as its destination once a packet from the server arrives, as RFC 9000 requires,
//! so from its second flight on the kernel delivers every packet to the target. The worker that
//! received the first datagram remembers where it sent the client's ID and sends later datagrams
//! carrying it, such as a retransmitted Initial, to the same worker.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ConnectionId;
use mvfstr_proto::RxMeta;
use mvfstr_proto::TransportConfig;

use crate::turn::Waiting;
use crate::wake::Shared;

/// Datagrams a worker's inbox holds. A datagram handed to a full inbox is dropped, and its client
/// sends it again.
pub(crate) const INBOX_CAPACITY: usize = 256;

/// The most IDs a worker remembers; past it the one remembered first is forgotten first, even if
/// later datagrams carried it. A worker that receives more new connections than this within a
/// lifetime forgets IDs by this bound rather than by their lifetime.
const HANDOFFS: usize = 4096;

/// [`Steering::lifetime`] for IDs kept until newer ones take their room.
const FOREVER: u64 = u64::MAX;

/// A bound on the max_ack_delay a peer may advertise: RFC 9000 makes 2^14 ms and more invalid.
const MAX_ACK_DELAY: Duration = Duration::from_millis(1 << 14);

/// Returns how long a worker remembers where it sent a client's first destination connection ID
/// after the last datagram that carried it, for connections with the transport settings
/// `transport`: as long as the connection that took the ID can wait for the client's next
/// datagram. That wait is the connection's idle timeout: at most the one in `transport`, unless
/// RFC 9000's floor of three probe timeouts is longer. A client sends its first ID only until it
/// receives a packet from the server, so until then the connection does not have an RTT sample,
/// and its probe timeout is three initial RTTs plus the client's max_ack_delay, for which this
/// takes the bound [`MAX_ACK_DELAY`]. Without an idle timeout an ID is kept until newer ones take
/// its room. An ID kept too long only sends a late datagram to a worker that accepts it as new;
/// one forgotten too soon can give a client a second connection elsewhere.
pub(crate) fn handoff_lifetime(transport: &TransportConfig) -> Option<Duration> {
    let probe_timeout = 3 * transport.initial_rtt() + MAX_ACK_DELAY;
    transport
        .idle_timeout()
        .map(|idle| idle.max(3 * probe_timeout))
}

/// The state that the drivers of every worker serving one address share to spread new connections
/// over the workers. Built once per address with [`Steering::new`] and given to each worker's
/// driver with [`EndpointDriverBuilder::steering`](crate::EndpointDriverBuilder::steering).
pub struct Steering {
    /// Counts the new connections: the `n`th goes to worker `n % workers`.
    next: Padded<AtomicUsize>,
    inboxes: Box<[Padded<Slot>]>,
    /// How long the members remember where a client's first destination connection ID went after
    /// the last datagram that carried it, in nanoseconds, or [`FOREVER`]: the longest
    /// [`handoff_lifetime`] of the members' server settings and of every connection a member
    /// accepted, since an application may accept a connection with settings of its own. It only
    /// grows.
    lifetime: AtomicU64,
}

/// A value that one worker reads every turn and others write, in cache lines of its own: two
/// 64-byte lines, which the adjacent-line prefetcher fetches as a pair.
#[repr(align(128))]
#[derive(Default)]
struct Padded<T>(T);

/// One worker's inbox.
#[derive(Default)]
struct Slot {
    /// Whether `inbox` holds datagrams, so that a driver whose inbox is empty reads this each
    /// turn without taking the lock. It changes only under the lock, along with the inbox.
    filled: AtomicBool,
    inbox: Mutex<Inbox>,
}

/// The datagrams other workers handed to one worker's driver.
#[derive(Default)]
struct Inbox {
    /// The driver's task while it runs; without one, other workers keep what they would hand over.
    task: Option<Arc<Shared>>,
    datagrams: VecDeque<Waiting>,
}

impl Steering {
    /// Creates a group for `workers` workers.
    pub fn new(workers: u16) -> Arc<Self> {
        Arc::new(Self {
            next: Padded::default(),
            inboxes: (0..workers).map(|_| Padded::default()).collect(),
            lifetime: AtomicU64::new(0),
        })
    }

    /// Returns the number of workers in the group.
    pub fn workers(&self) -> u16 {
        u16::try_from(self.inboxes.len()).expect("should fit: built from a u16")
    }

    /// Makes the driver whose task is `task` worker `index` of the group until the returned
    /// member drops. A worker index has one driver at a time. The member remembers where it sent
    /// each client's first destination connection ID until a lifetime passes without a datagram
    /// that carries it: at least `lifetime`, which is `None` to remember IDs for as long as room
    /// allows, and at least what [`Member::accepted`] reports.
    pub(crate) fn join(
        self: &Arc<Self>,
        index: u16,
        task: Arc<Shared>,
        lifetime: Option<Duration>,
    ) -> Member {
        self.outlast(lifetime);
        if let Some(Padded(slot)) = self.inboxes.get(usize::from(index)) {
            lock(&slot.inbox).task = Some(task);
        }
        Member {
            group: Arc::clone(self),
            index,
            handoffs: RefCell::default(),
            spare: RefCell::default(),
        }
    }

    /// Returns how long the members remember an ID, `None` for as long as room allows.
    pub(crate) fn lifetime(&self) -> Option<Duration> {
        match self.lifetime.load(Ordering::Relaxed) {
            FOREVER => None,
            nanos => Some(Duration::from_nanos(nanos)),
        }
    }

    /// Makes the members remember IDs for at least `lifetime`.
    fn outlast(&self, lifetime: Option<Duration>) {
        let nanos = lifetime.map_or(FOREVER, |lifetime| {
            u64::try_from(lifetime.as_nanos()).unwrap_or(FOREVER)
        });
        // Accepted connections mostly share settings, so most calls leave the line unwritten.
        if self.lifetime.load(Ordering::Relaxed) < nanos {
            self.lifetime.fetch_max(nanos, Ordering::Relaxed);
        }
    }

    /// Picks the worker of the next new connection.
    fn next_worker(&self) -> u16 {
        let next = self.next.0.fetch_add(1, Ordering::Relaxed) % self.inboxes.len().max(1);
        u16::try_from(next).expect("should fit: below the worker count")
    }

    /// Hands `datagram` to worker `target`'s driver, waking it if its inbox was empty.
    fn hand_off(&self, target: u16, datagram: Waiting) -> Result<(), Refused> {
        let Some(Padded(slot)) = self.inboxes.get(usize::from(target)) else {
            return Err(Refused::Gone);
        };
        let mut inbox = lock(&slot.inbox);
        let Some(task) = &inbox.task else {
            return Err(Refused::Gone);
        };
        if inbox.datagrams.len() >= INBOX_CAPACITY {
            return Err(Refused::Full);
        }
        // A driver takes its whole inbox at once, so a non-empty inbox has a wake pending.
        let wake = inbox.datagrams.is_empty().then(|| Arc::clone(task));
        inbox.datagrams.push_back(datagram);
        slot.filled.store(true, Ordering::Release);
        drop(inbox);
        if let Some(task) = wake {
            task.wake_task();
        }
        Ok(())
    }
}

impl fmt::Debug for Steering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Steering")
            .field("workers", &self.inboxes.len())
            .finish_non_exhaustive()
    }
}

/// The outcome of steering a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Steer {
    /// This worker handles it.
    Keep,
    /// Another worker's driver has it.
    HandedOff,
    /// It was for another worker, whose inbox was full.
    Dropped,
}

/// Why a hand-off failed.
enum Refused {
    /// The target's driver does not run.
    Gone,
    /// The target's inbox is full.
    Full,
}

/// Locks `mutex`. Code does not panic while holding these locks, so a poisoned one still holds
/// consistent data.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One driver's place in a [`Steering`] group. Dropping it closes the driver's inbox.
pub(crate) struct Member {
    group: Arc<Steering>,
    index: u16,
    handoffs: RefCell<Handoffs>,
    /// An empty queue whose allocation the next take swaps into the inbox.
    spare: RefCell<VecDeque<Waiting>>,
}

impl Member {
    /// Hands a datagram of a new connection to the worker its client's first destination
    /// connection ID went to, or else to the worker the group's counter picks, unless that is this
    /// worker or its driver does not run.
    pub(crate) fn steer_new(&self, now: Instant, meta: &RxMeta, datagram: &[u8]) -> Steer {
        let cid = long_header_dcid(datagram);
        let lifetime = self.group.lifetime();
        let known = cid.and_then(|cid| self.handoffs.borrow_mut().target(now, lifetime, &cid));
        let target = known.unwrap_or_else(|| self.group.next_worker());
        // Record the IDs this worker keeps too: a retransmission that comes while the first waits
        // for a connection attempt here must not start a second connection elsewhere.
        if let Some(cid) = cid {
            self.handoffs
                .borrow_mut()
                .insert(now, lifetime, cid, target);
        }
        if target == self.index {
            return Steer::Keep;
        }
        let steered = self.hand_off(target, meta, datagram);
        if steered == Steer::Keep
            && let Some(cid) = cid
        {
            self.handoffs
                .borrow_mut()
                .insert(now, lifetime, cid, self.index);
        }
        steered
    }

    /// Hands a long-header datagram for an unknown connection, such as 0-RTT, to the worker its
    /// destination connection ID went to, if it went to another worker.
    pub(crate) fn steer_known(&self, now: Instant, meta: &RxMeta, datagram: &[u8]) -> Steer {
        let lifetime = self.group.lifetime();
        let target = long_header_dcid(datagram)
            .and_then(|cid| self.handoffs.borrow_mut().target(now, lifetime, &cid))
            .filter(|&target| target != self.index);
        match target {
            Some(target) => self.hand_off(target, meta, datagram),
            None => Steer::Keep,
        }
    }

    fn hand_off(&self, target: u16, meta: &RxMeta, datagram: &[u8]) -> Steer {
        let waiting = Waiting {
            meta: *meta,
            datagram: datagram.to_vec(),
        };
        match self.group.hand_off(target, waiting) {
            Ok(()) => Steer::HandedOff,
            Err(Refused::Full) => Steer::Dropped,
            Err(Refused::Gone) => Steer::Keep,
        }
    }

    /// Notes that this worker accepted a connection with the transport settings `transport`,
    /// which its application may have chosen over the server's, so that every member remembers
    /// the IDs it handed off for as long as such a connection can wait for its client.
    pub(crate) fn accepted(&self, transport: &TransportConfig) {
        self.group.outlast(handoff_lifetime(transport));
    }

    /// Passes each datagram other workers handed to this one to `f`, oldest first.
    pub(crate) fn take(&self, mut f: impl FnMut(Waiting)) {
        let Some(Padded(slot)) = self.group.inboxes.get(usize::from(self.index)) else {
            return;
        };
        // A hand-off that fills the inbox after this read finds it empty and so wakes the driver
        // for another turn, which reads the flag set.
        if !slot.filled.load(Ordering::Acquire) {
            return;
        }
        let mut taken = mem::take(&mut *self.spare.borrow_mut());
        {
            let mut inbox = lock(&slot.inbox);
            mem::swap(&mut inbox.datagrams, &mut taken);
            slot.filled.store(false, Ordering::Relaxed);
        }
        taken.drain(..).for_each(&mut f);
        *self.spare.borrow_mut() = taken;
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Some(Padded(slot)) = self.group.inboxes.get(usize::from(self.index)) {
            let mut inbox = lock(&slot.inbox);
            inbox.task = None;
            inbox.datagrams.clear();
            slot.filled.store(false, Ordering::Relaxed);
        }
    }
}

/// Where a worker sent each client's first destination connection ID, at most [`HANDOFFS`] of
/// them, each until a lifetime passes without a datagram that carries it. Each call takes the
/// group's current lifetime, which only grows.
#[derive(Default)]
struct Handoffs {
    /// Each ID's worker and when the last datagram that carried it came.
    targets: HashMap<ConnectionId, (u16, Instant)>,
    /// The IDs in the order they were first remembered.
    order: VecDeque<ConnectionId>,
}

impl Handoffs {
    /// Returns the worker `cid` went to, unless `lifetime` has passed since the last datagram
    /// that carried it; a datagram carries it at `now`.
    fn target(
        &mut self,
        now: Instant,
        lifetime: Option<Duration>,
        cid: &ConnectionId,
    ) -> Option<u16> {
        self.expire(now, lifetime);
        let (target, last) = self.targets.get_mut(cid)?;
        if outlived(*last, now, lifetime) {
            return None;
        }
        *last = now;
        Some(*target)
    }

    /// Records that `cid`, which a datagram carries at `now`, went to `target`.
    fn insert(&mut self, now: Instant, lifetime: Option<Duration>, cid: ConnectionId, target: u16) {
        self.expire(now, lifetime);
        if let Some(known) = self.targets.get_mut(&cid) {
            *known = (target, now);
            return;
        }
        if self.order.len() >= HANDOFFS
            && let Some(oldest) = self.order.pop_front()
        {
            self.targets.remove(&oldest);
        }
        self.targets.insert(cid, (target, now));
        self.order.push_back(cid);
    }

    /// Forgets the oldest IDs that `lifetime` outlived. An ID that later datagrams kept stops the
    /// scan; [`target`](Self::target) checks those behind it.
    fn expire(&mut self, now: Instant, lifetime: Option<Duration>) {
        while let Some(cid) = self.order.front()
            && self
                .targets
                .get(cid)
                .is_none_or(|&(_, last)| outlived(last, now, lifetime))
        {
            self.targets.remove(cid);
            self.order.pop_front();
        }
    }
}

/// Returns whether `lifetime` has passed by `now` since `last`; `None` never passes.
fn outlived(last: Instant, now: Instant, lifetime: Option<Duration>) -> bool {
    lifetime
        .and_then(|lifetime| last.checked_add(lifetime))
        .is_some_and(|until| until <= now)
}

/// Returns the destination connection ID of a long header, which holds the ID's length at offset
/// 5 and the ID from offset 6 in every QUIC version (RFC 8999).
fn long_header_dcid(datagram: &[u8]) -> Option<ConnectionId> {
    if datagram.first()? & 0x80 == 0 {
        return None;
    }
    let len = usize::from(*datagram.get(5)?);
    ConnectionId::new(datagram.get(6..6 + len)?).ok()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;
    use std::task::Waker;
    use std::time::Instant;

    use mvfstr_proto::Ecn;

    use super::*;

    fn meta() -> RxMeta {
        RxMeta {
            src: SocketAddr::from(([127, 0, 0, 1], 50_000)),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride: 1200,
            rx_time: Instant::now(),
        }
    }

    /// Returns the start of a client's first Initial, whose eight-byte destination connection ID
    /// repeats `byte`.
    fn initial(byte: u8) -> Vec<u8> {
        let mut datagram = vec![0xc0, 0, 0, 0, 1, 8];
        datagram.extend([byte; 8]);
        datagram.push(0);
        datagram.resize(1200, 0);
        datagram
    }

    fn task() -> Arc<Shared> {
        Arc::new(Shared::default())
    }

    const LIFETIME: Duration = Duration::from_secs(60);

    #[test]
    fn a_connection_its_receiving_worker_kept_stays_there_when_its_initial_comes_again() {
        let group = Steering::new(2);
        let (zero, _one) = (
            group.join(0, task(), Some(LIFETIME)),
            group.join(1, task(), Some(LIFETIME)),
        );
        // The group's first new connection goes to worker 0, the next to worker 1.
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(2)),
            Steer::Keep
        );
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(2)),
            Steer::Keep,
            "the retransmission goes where its connection is"
        );
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(4)),
            Steer::HandedOff,
            "the next new connection goes to worker 1"
        );
    }

    #[test]
    fn a_connection_kept_because_its_worker_did_not_run_stays_with_the_worker_that_kept_it() {
        let group = Steering::new(2);
        let zero = group.join(0, task(), Some(LIFETIME));
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(2)),
            Steer::Keep
        );
        // The group's second new connection would go to worker 1, whose driver has not started.
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(4)),
            Steer::Keep
        );
        let _one = group.join(1, task(), Some(LIFETIME));
        assert_eq!(
            zero.steer_new(Instant::now(), &meta(), &initial(4)),
            Steer::Keep,
            "the retransmission goes where its connection is"
        );
    }

    #[test]
    fn an_id_is_forgotten_once_its_handshake_can_no_longer_use_it() {
        let start = Instant::now();
        let cid = ConnectionId::new(&[2; 8]).unwrap();
        let remembered = |at| {
            let mut handoffs = Handoffs::default();
            handoffs.insert(start, Some(LIFETIME), cid, 1);
            handoffs.target(at, Some(LIFETIME), &cid)
        };
        assert_eq!(
            remembered(start + LIFETIME - Duration::from_millis(1)),
            Some(1)
        );
        assert_eq!(remembered(start + LIFETIME), None);
    }

    #[test]
    fn an_id_is_remembered_for_a_lifetime_after_the_last_datagram_that_carried_it() {
        let group = Steering::new(2);
        let (_zero, one) = (
            group.join(0, task(), Some(LIFETIME)),
            group.join(1, task(), Some(LIFETIME)),
        );
        let start = Instant::now();
        // The group's first new connection goes to worker 0; while the server does not answer,
        // its client resends its first Initial, each copy less than a lifetime after the last.
        assert_eq!(one.steer_new(start, &meta(), &initial(3)), Steer::HandedOff);
        let gap = LIFETIME * 3 / 4;
        for n in 1..=3 {
            assert_eq!(
                one.steer_new(start + gap * n, &meta(), &initial(3)),
                Steer::HandedOff,
                "copy {n} goes where its connection is"
            );
        }
        // A lifetime after the last copy the ID is forgotten, and the group's next new
        // connection goes to worker 1.
        assert_eq!(
            one.steer_new(start + gap * 3 + LIFETIME, &meta(), &initial(3)),
            Steer::Keep
        );
    }

    #[test]
    fn an_id_is_remembered_as_long_as_connections_accepted_with_their_own_transport_can_wait() {
        let group = Steering::new(2);
        let (zero, one) = (
            group.join(0, task(), Some(LIFETIME)),
            group.join(1, task(), Some(LIFETIME)),
        );
        let start = Instant::now();
        assert_eq!(one.steer_new(start, &meta(), &initial(3)), Steer::HandedOff);
        // Worker 0 accepts it with an application's transport settings, whose idle timeout is
        // twice the lifetime the servers' own settings give; settings whose connections wait less
        // do not shorten it.
        let idle = |timeout| {
            TransportConfig::builder()
                .idle_timeout(Some(timeout))
                .build()
                .unwrap()
        };
        zero.accepted(&idle(LIFETIME * 2));
        zero.accepted(&idle(Duration::from_secs(1)));
        let copy = start + LIFETIME * 3 / 2;
        assert_eq!(
            one.steer_new(copy, &meta(), &initial(3)),
            Steer::HandedOff,
            "a copy past the servers' lifetime goes where its connection is"
        );
        // Once the longer lifetime passes, the ID is forgotten, and the group's next new
        // connection goes to worker 1.
        assert_eq!(
            one.steer_new(copy + LIFETIME * 2, &meta(), &initial(3)),
            Steer::Keep
        );
    }

    #[test]
    fn without_an_idle_timeout_an_id_is_not_forgotten_for_its_age() {
        let group = Steering::new(2);
        let (_zero, one) = (group.join(0, task(), None), group.join(1, task(), None));
        let start = Instant::now();
        assert_eq!(one.steer_new(start, &meta(), &initial(3)), Steer::HandedOff);
        let a_year_later = start + Duration::from_secs(365 * 24 * 3600);
        assert_eq!(
            one.steer_new(a_year_later, &meta(), &initial(3)),
            Steer::HandedOff,
            "the copy goes where its connection is"
        );
    }

    #[test]
    fn a_handed_off_id_is_remembered_as_long_as_its_connection_can_wait_for_the_client() {
        let idle = |timeout| {
            TransportConfig::builder()
                .idle_timeout(timeout)
                .build()
                .unwrap()
        };
        // The default idle timeout of 30 s is below three probe timeouts of a connection without
        // an RTT sample whose client has the largest max_ack_delay: 3 x (3 x 333 + 16,384) ms.
        assert_eq!(
            handoff_lifetime(&TransportConfig::default()),
            Some(Duration::from_millis(52_149))
        );
        assert_eq!(
            handoff_lifetime(&idle(Some(Duration::from_secs(120)))),
            Some(Duration::from_secs(120))
        );
        assert_eq!(handoff_lifetime(&idle(None)), None, "no idle timeout");
    }

    #[test]
    fn past_the_most_ids_remembered_the_oldest_is_forgotten_first() {
        let mut handoffs = Handoffs::default();
        let now = Instant::now();
        let lifetime = Some(LIFETIME);
        let cid = |n: usize| ConnectionId::new(&(n as u64).to_be_bytes()).unwrap();
        for n in 0..=HANDOFFS {
            handoffs.insert(now, lifetime, cid(n), 1);
        }
        assert_eq!(
            handoffs.target(now, lifetime, &cid(0)),
            None,
            "the oldest is forgotten"
        );
        assert_eq!(handoffs.target(now, lifetime, &cid(1)), Some(1));
        assert_eq!(handoffs.target(now, lifetime, &cid(HANDOFFS)), Some(1));
    }

    #[test]
    fn a_worker_whose_driver_does_not_run_is_handed_nothing() {
        let group = Steering::new(2);
        let zero = group.join(0, task(), Some(LIFETIME));
        let now = Instant::now();
        // New connections go to workers 0, 1, 0, 1 and so on.
        assert_eq!(zero.steer_new(now, &meta(), &initial(2)), Steer::Keep);
        assert_eq!(
            zero.steer_new(now, &meta(), &initial(3)),
            Steer::Keep,
            "worker 1's driver has not started"
        );
        let one = group.join(1, task(), Some(LIFETIME));
        assert_eq!(zero.steer_new(now, &meta(), &initial(4)), Steer::Keep);
        assert_eq!(zero.steer_new(now, &meta(), &initial(5)), Steer::HandedOff);
        drop(one);
        assert_eq!(zero.steer_new(now, &meta(), &initial(6)), Steer::Keep);
        assert_eq!(
            zero.steer_new(now, &meta(), &initial(7)),
            Steer::Keep,
            "worker 1's driver has ended"
        );
        let mut taken = 0;
        group.join(1, task(), Some(LIFETIME)).take(|_| taken += 1);
        assert_eq!(taken, 0, "what an ended driver was handed went with it");
    }

    #[test]
    fn a_full_inbox_drops_what_is_handed_to_it() {
        let group = Steering::new(2);
        let (zero, one) = (
            group.join(0, task(), Some(LIFETIME)),
            group.join(1, task(), Some(LIFETIME)),
        );
        for _ in 0..INBOX_CAPACITY {
            assert_eq!(zero.hand_off(1, &meta(), &initial(2)), Steer::HandedOff);
        }
        assert_eq!(zero.hand_off(1, &meta(), &initial(2)), Steer::Dropped);
        let mut taken = 0;
        one.take(|_| taken += 1);
        assert_eq!(taken, INBOX_CAPACITY);
        assert_eq!(
            zero.hand_off(1, &meta(), &initial(2)),
            Steer::HandedOff,
            "an inbox taken has room again"
        );
    }

    /// Counts its wakes.
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_hand_off_wakes_the_target_once_until_it_takes_its_inbox() {
        let group = Steering::new(2);
        let target = task();
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        target.register(&Waker::from(Arc::clone(&wakes)));
        let (zero, one) = (
            group.join(0, task(), Some(LIFETIME)),
            group.join(1, target, Some(LIFETIME)),
        );
        zero.hand_off(1, &meta(), &initial(2));
        zero.hand_off(1, &meta(), &initial(3));
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "the second datagram finds a wake pending"
        );
        one.take(|_| {});
        zero.hand_off(1, &meta(), &initial(4));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    }
}
