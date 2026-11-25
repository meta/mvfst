/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The stream guard.
//!
//! Every per-stream mutation goes through the one crate-private guard. Its `Drop` runs the
//! stream's `reindex()`, which recomputes membership of every per-stream intrusive list
//! (readable, writable and pull-ready, control-pending, demand, scheduler) from state.
//! [`StreamMut`](crate::StreamMut) is its public face.
//!
//! [`Streams`] owns the stream table, the lists and the scheduler, and hands out a stream only
//! as a [`StreamGuard`], so a mutation cannot skip the reindex. A stream's state is its two half
//! state machines, its undelivered readiness edges, its owed control frames and its producer
//! state, plus the data parts (send and receive buffers, flow control) behind [`StreamData`].
//! The lists are:
//!
//! - readiness: an edge is undelivered, or the stream is closed and its `Closed` edge is not
//!   delivered yet;
//! - pull-ready: the send half takes new bytes, the producer is not pending and the data parts
//!   have room. A new stream's producer is pending until it is first woken;
//! - demand: the send half takes new bytes and the stream is pull-ready, has staged bytes or
//!   keeps an undelivered `Writable` edge; these streams share the staging budget;
//! - control: an owed MAX_STREAM_DATA, STOP_SENDING, RESET_STREAM or STREAM_DATA_BLOCKED that
//!   the half states still permit;
//! - the scheduler: the send half may send STREAM frames and the data parts have bytes or a FIN
//!   for the wire. Connection credit is not considered; it is checked when frames are written.
//!
//! The same reindex records each stream on the demand list in the [`Shares`], by bucket of the
//! staging split with its place and holding, so the split reads per-bucket totals. While the
//! stream stays its bucket's only peer, the reindex skips this and the split reads the stream.
//!
//! A closed stream whose `Closed` edge has been delivered is reaped by the same reindex.

use mvfstr_wire::Dir;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;

use super::map::Half;
use super::map::PeerStream;
use super::map::StreamTable;
use super::scheduler::Scheduler;
use super::send_buf::Pending;
use super::share::Holding;
use super::share::Peer;
use super::share::Place;
use super::share::Shares;
use super::share::Standing;
use super::share::share_key;
use super::state::Halves;
use super::state::InvalidTransition;
use super::state::RecvState;
use super::state::SendState;
use super::state::Transition;
use crate::AppCode;
use crate::OpenError;
use crate::SendOrder;
use crate::StreamReady;

/// What a stream's data parts (send and receive buffers, flow control) contribute to its list
/// membership.
pub(crate) trait StreamData {
    /// Returns what the next STREAM frame would carry: lost bytes or a lost FIN, staged bytes
    /// within stream credit, or an unsent FIN alone; `None` if the stream does not have anything
    /// for the wire. Connection credit is not considered.
    fn wire_data(&self) -> Option<Pending>;

    /// Returns whether the stream accepts more application bytes: it has stream credit beyond its
    /// staged bytes, its staged bytes are below the per-stream cap, and the FIN is not staged.
    fn has_pull_room(&self) -> bool;

    /// Returns whether the stream has staged bytes, or its push sender was refused bytes and
    /// waits for `Writable`.
    fn has_demand(&self) -> bool;

    /// Returns what the stream holds of the staging budget's split while it has demand: its room
    /// and staged bytes.
    fn holding(&self) -> Holding;
}

/// A readiness edge the connection marks after updating the data parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Edge {
    /// New in-order bytes are readable.
    Readable,
    /// The FIN arrived and every byte before it is readable.
    Finished,
    /// The allowance rose to the low-water mark (push senders).
    Writable,
    /// The acknowledged bytes reached the tracked offset.
    Progress,
}

/// Undelivered readiness edges, as bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Edges(u8);

impl Edges {
    const OPENED: u8 = 1;
    const READABLE: u8 = 1 << 1;
    const FINISHED: u8 = 1 << 2;
    const RESET: u8 = 1 << 3;
    const STOPPED: u8 = 1 << 4;
    const WRITABLE: u8 = 1 << 5;
    const PROGRESS: u8 = 1 << 6;

    /// Clears `bit`, returning whether it was set.
    fn take(&mut self, bit: u8) -> bool {
        let had = self.0 & bit != 0;
        self.0 &= !bit;
        had
    }
}

/// Control frames owed to the peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Owed(u8);

impl Owed {
    /// A MAX_STREAM_DATA with the current receive limit.
    pub(crate) const MAX_STREAM_DATA: Owed = Owed(1);
    /// A STOP_SENDING with the application's code.
    pub(crate) const STOP_SENDING: Owed = Owed(1 << 1);
    /// A RESET_STREAM with the send half's code and final size.
    pub(crate) const RESET_STREAM: Owed = Owed(1 << 2);
    /// A STREAM_DATA_BLOCKED at the current send limit.
    pub(crate) const STREAM_DATA_BLOCKED: Owed = Owed(1 << 3);

    /// Returns whether every frame in `other` is owed.
    pub(crate) const fn contains(self, other: Owed) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether the set is empty.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The per-stream lists other than the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum List {
    /// Streams with an undelivered readiness edge.
    Readiness = 0,
    /// Streams whose producer should be polled for data.
    PullReady = 1,
    /// Streams with an owed control frame that the half states still permit.
    Control = 2,
    /// Streams that are pull-ready, have demand (see [`StreamData::has_demand`]) or keep an
    /// undelivered `Writable` edge: the peers that share the staging budget in the wire order.
    Demand = 3,
}

const LISTS: usize = 4;

/// The null slot index, at the ends of a list and in an unlinked stream's links.
const NIL: u32 = u32::MAX;

/// One stream's state. Private to this module: every change goes through [`StreamGuard`].
struct Stream<D> {
    order: SendOrder,
    halves: Halves,
    edges: Edges,
    owed: Owed,
    /// The code of our STOP_SENDING, set by [`StreamGuard::stop_sending`].
    stop_code: Option<AppCode>,
    /// The code of the peer's STOP_SENDING, once it arrived.
    peer_stop: Option<AppCode>,
    /// Whether the producer returned `Pending`, or the stream is new, and has not been woken since.
    producer_pending: bool,
    /// Whether the `Closed` edge was delivered.
    closed_delivered: bool,
    data: D,
}

/// A stream with its list links.
struct Entry<D> {
    stream: Stream<D>,
    links: [Link; LISTS],
    /// One bit per [`List`] the stream is on, and [`LOST_DATA`] or [`FIN_ONLY`] while it is counted
    /// in [`Streams::lost`] or [`Streams::fin_only`].
    member: u8,
    /// Whether the shares record the stream as the only peer of its order's bucket; cleared when
    /// the order changes, until the next reindex checks again.
    alone: bool,
}

#[derive(Clone, Copy)]
struct Link {
    prev: u32,
    next: u32,
}

const UNLINKED: Link = Link {
    prev: NIL,
    next: NIL,
};

#[derive(Clone, Copy)]
struct ListHead {
    head: u32,
    tail: u32,
    len: u32,
}

const EMPTY_LIST: ListHead = ListHead {
    head: NIL,
    tail: NIL,
    len: 0,
};

/// The membership a stream's state calls for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Membership {
    /// One bit per [`List`], and [`LOST_DATA`] or [`FIN_ONLY`] if the stream counts in
    /// [`Streams::lost`] or [`Streams::fin_only`].
    lists: u8,
    scheduled: Option<SendOrder>,
    reap: bool,
}

/// The membership bit of a stream whose send buffer holds lost bytes or a lost FIN. It sits
/// beside the [`List`] bits, so a reindex counts the stream without another load.
const LOST_DATA: u8 = 1 << 7;
/// The membership bit of a stream whose next frame is its FIN alone: every byte was sent, and the
/// stream does not have lost data.
const FIN_ONLY: u8 = 1 << 6;
// The list bits sit below `FIN_ONLY` and `LOST_DATA`; bits `LISTS` to 5 are free.
const _: () = assert!(LISTS < 7);

impl List {
    pub(crate) const ALL: [List; LISTS] = [
        List::Readiness,
        List::PullReady,
        List::Control,
        List::Demand,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

impl<D> Stream<D> {
    /// Returns the owed control frames that the half states still permit.
    fn due(&self) -> Owed {
        let (send, recv) = (self.halves.send, self.halves.recv);
        let mut permitted = 0;
        if matches!(send, Some(SendState::ResetSent { .. })) {
            permitted |= Owed::RESET_STREAM.0;
        }
        if send.is_some_and(|s| s.may_send_data_blocked()) {
            permitted |= Owed::STREAM_DATA_BLOCKED.0;
        }
        if recv.is_some_and(|r| r.may_send_stop_sending()) {
            permitted |= Owed::STOP_SENDING.0;
        }
        if recv.is_some_and(|r| r.may_send_max_stream_data()) {
            permitted |= Owed::MAX_STREAM_DATA.0;
        }
        Owed(self.owed.0 & permitted)
    }
}

impl<D: StreamData> Stream<D> {
    fn membership(&self) -> Membership {
        let mut lists = 0;
        if self.edges.0 != 0 || (self.halves.is_closed() && !self.closed_delivered) {
            lists |= List::Readiness.bit();
        }
        let send = self.halves.send;
        if send.is_some_and(|s| s.takes_new_data()) {
            let pull = !self.producer_pending && self.data.has_pull_room();
            if pull {
                lists |= List::PullReady.bit();
            }
            // A ready producer and staged bytes, at the cap or not, are demand, and a refused
            // sender keeps its demand until its `Writable` edge is delivered.
            if pull || self.data.has_demand() || self.edges.0 & Edges::WRITABLE != 0 {
                lists |= List::Demand.bit();
            }
        }
        if !self.due().is_empty() {
            lists |= List::Control.bit();
        }
        // Lost data and a lone FIN are a sendable stream's wire data, so only a scheduled stream
        // carries either bit.
        let wire = if send.is_some_and(|s| s.may_send_stream()) {
            self.data.wire_data()
        } else {
            None
        };
        match wire {
            Some(Pending::Retransmit) => lists |= LOST_DATA,
            Some(Pending::Fin) => lists |= FIN_ONLY,
            Some(Pending::New { .. }) | None => {}
        }
        Membership {
            lists,
            scheduled: wire.is_some().then_some(self.order),
            reap: self.halves.is_closed() && self.closed_delivered && self.edges.0 == 0,
        }
    }
}

/// A connection's streams with their lists, scheduler and shares of the staging budget.
pub(crate) struct Streams<D> {
    table: StreamTable<Entry<D>>,
    lists: [ListHead; LISTS],
    scheduler: Scheduler,
    /// The streams on the demand list, by bucket of the split.
    shares: Shares,
    /// How many streams have lost bytes or a lost FIN in their send buffers, kept by the reindex
    /// that every guard runs when dropped, so every change to a send buffer's lost state is
    /// counted: a loss, a retransmission, an acknowledgment of lost bytes or a reset.
    lost: u32,
    /// How many streams have only an unsent FIN to send, kept by the same reindex.
    fin_only: u32,
    /// The reindexes run so far, one per dropped guard.
    #[cfg(test)]
    reindexes: u64,
}

/// Exclusive access to one stream; dropping it reindexes the stream.
pub(crate) struct StreamGuard<'a, D: StreamData> {
    streams: &'a mut Streams<D>,
    slot: u32,
    id: StreamId,
}

/// Read-only access to one stream, so that frame sources pick candidates without changing state.
pub(crate) struct StreamRef<'a, D> {
    stream: &'a Stream<D>,
    slot: u32,
    id: StreamId,
}

impl<D: StreamData> Streams<D> {
    /// Creates an empty set for the endpoint whose role is `side`, advertising `max_streams_bidi`
    /// and `max_streams_uni`, with incremental streams taking turns every `quantum` bytes.
    pub(crate) fn new(
        side: Side,
        max_streams_bidi: u64,
        max_streams_uni: u64,
        quantum: u64,
    ) -> Self {
        Streams {
            table: StreamTable::new(side, max_streams_bidi, max_streams_uni),
            lists: [EMPTY_LIST; LISTS],
            scheduler: Scheduler::new(quantum),
            shares: Shares::new(),
            lost: 0,
            fin_only: 0,
            #[cfg(test)]
            reindexes: 0,
        }
    }

    /// Returns how many streams have lost bytes or a lost FIN in their send buffers.
    pub(crate) fn lost(&self) -> u32 {
        self.lost
    }

    /// Returns how many streams have only an unsent FIN to send: every byte is sent, and the stream
    /// does not count in [`lost`](Self::lost).
    pub(crate) fn fin_only(&self) -> u32 {
        self.fin_only
    }

    /// Returns how many reindexes ran, one per dropped guard.
    #[cfg(test)]
    pub(crate) fn reindexes(&self) -> u64 {
        self.reindexes
    }

    /// Opens a local stream at `order` with data parts `data`.
    pub(crate) fn open_local(
        &mut self,
        dir: Dir,
        order: SendOrder,
        data: D,
    ) -> Result<StreamGuard<'_, D>, OpenError> {
        let side = self.table.side();
        let (id, key) = self
            .table
            .open_local(dir, |id| Entry::new(Halves::new(side, id), order, data))?;
        Ok(self.guard(key.slot(), id))
    }

    /// Returns the stream a peer frame names (see [`StreamTable::peer_frame`]), or `None` if it
    /// was reaped. A stream the frame opens gets its order and data parts from `make` and an
    /// `Opened` edge.
    pub(crate) fn peer_frame(
        &mut self,
        id: StreamId,
        half: Half,
        make: impl FnOnce(StreamId) -> (SendOrder, D),
    ) -> Result<Option<StreamGuard<'_, D>>, TransportErrorCode> {
        let side = self.table.side();
        let found = self.table.peer_frame(id, half, |id| {
            let (order, data) = make(id);
            Entry::new(Halves::new(side, id), order, data)
        })?;
        Ok(match found {
            PeerStream::Live(key) => Some(self.guard(key.slot(), id)),
            PeerStream::Opened(key) => {
                self.entry_mut(key.slot()).stream.edges.0 |= Edges::OPENED;
                Some(self.guard(key.slot(), id))
            }
            PeerStream::Closed => None,
        })
    }

    /// Materializes `id` if it is a peer stream opened implicitly and not yet named by a frame
    /// (see [`StreamTable::materialize`]), with the order and data parts `make` gives; returns
    /// whether it did. The application looked it up by ID, so it does not get an `Opened` edge.
    pub(crate) fn materialize(
        &mut self,
        id: StreamId,
        make: impl FnOnce(StreamId) -> (SendOrder, D),
    ) -> bool {
        let side = self.table.side();
        let Some(key) = self.table.materialize(id, |id| {
            let (order, data) = make(id);
            Entry::new(Halves::new(side, id), order, data)
        }) else {
            return false;
        };
        self.reindex(key.slot(), id);
        true
    }

    /// Returns every open stream, read-only, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = StreamRef<'_, D>> {
        self.table.map().iter().map(|(key, id, entry)| StreamRef {
            stream: &entry.stream,
            slot: key.slot(),
            id,
        })
    }

    /// Returns `id`'s stream, read-only, if it is open.
    pub(crate) fn get(&self, id: StreamId) -> Option<StreamRef<'_, D>> {
        self.get_slot(self.table.map().key(id)?.slot())
    }

    /// Returns the stream in slab slot `slot`, read-only.
    pub(crate) fn get_slot(&self, slot: u32) -> Option<StreamRef<'_, D>> {
        let (_, id, entry) = self.table.map().get_slot(slot)?;
        Some(StreamRef {
            stream: &entry.stream,
            slot,
            id,
        })
    }

    /// Returns `id`'s stream, or `None` if `id` never opened or was reaped.
    pub(crate) fn stream(&mut self, id: StreamId) -> Option<StreamGuard<'_, D>> {
        let key = self.table.map().key(id)?;
        Some(self.guard(key.slot(), id))
    }

    /// Returns the stream in slab slot `slot`, as named by a list or the scheduler.
    pub(crate) fn by_slot(&mut self, slot: u32) -> Option<StreamGuard<'_, D>> {
        let (_, id, _) = self.table.map().get_slot(slot)?;
        Some(self.guard(slot, id))
    }

    /// Returns the first stream on `list`.
    pub(crate) fn first(&self, list: List) -> Option<u32> {
        let head = self.lists[list as usize].head;
        (head != NIL).then_some(head)
    }

    /// Returns the stream after `slot` on `list`.
    #[cfg(test)]
    pub(crate) fn next_on(&self, list: List, slot: u32) -> Option<u32> {
        let next = self.entry(slot)?.links[list as usize].next;
        (next != NIL).then_some(next)
    }

    /// Returns whether the stream in `slot` is on `list`.
    pub(crate) fn is_on(&self, list: List, slot: u32) -> bool {
        self.entry(slot)
            .is_some_and(|entry| entry.member & list.bit() != 0)
    }

    /// Returns the number of streams on `list`.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn len(&self, list: List) -> usize {
        self.lists[list as usize].len as usize
    }

    /// Returns the wire scheduler, for a packet build to walk with its cursor.
    pub(crate) fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Rotates the scheduler for `bytes` of stream `id`, in `slot`, sealed in a packet or GSO
    /// run, whether or not the build has since unscheduled the stream (see
    /// [`Scheduler::commit`]). The commit may move incremental streams' places, which the shares
    /// follow for peers that are not alone in their buckets; what they hold has not changed since
    /// their guards last reindexed them.
    pub(crate) fn commit(&mut self, slot: u32, id: StreamId, bytes: u64) {
        let moved = self.scheduler.commit(slot, id, bytes);
        // Every guard is closed here, so the shares record each stream's bucket as it stands.
        if moved.committed && self.shares.among(slot) {
            self.replace(slot);
        }
        if let Some(raised) = moved.raised
            && self.shares.among(raised)
        {
            self.replace(raised);
        }
    }

    /// Records the place of the stream in `slot`, a peer among others, in the shares.
    #[inline(never)]
    fn replace(&mut self, slot: u32) {
        if let Some((_, id, entry)) = self.table.map().get_slot(slot) {
            let place = self.place(slot, id, entry.stream.order);
            self.shares.replace(slot, place);
        }
    }

    /// Returns the streams with demand by bucket of the split.
    pub(crate) fn shares(&self) -> &Shares {
        &self.shares
    }

    /// Brings the incremental buckets of the shares up to the scheduler's turns, which listing
    /// their peers in the wire order requires.
    pub(crate) fn settle_shares(&mut self) {
        let scheduler = &self.scheduler;
        self.shares.settle(|(class, urgency, _)| {
            scheduler.turn(SendOrder {
                class,
                urgency,
                incremental: true,
                order: 0,
            })
        });
    }

    /// Returns the limit for peer streams in direction `dir` that the next MAX_STREAMS carries.
    pub(crate) fn max_streams(&self, dir: Dir) -> u64 {
        self.table.max_streams(dir)
    }

    /// Records that a MAX_STREAMS carrying `max` for direction `dir` was sealed (see
    /// [`StreamTable::on_max_streams_sent`]).
    pub(crate) fn on_max_streams_sent(&mut self, dir: Dir, max: u64) {
        self.table.on_max_streams_sent(dir, max);
    }

    /// Returns how many more local streams in direction `dir` can be opened (see
    /// [`StreamTable::openable_local`]).
    pub(crate) fn openable_local(&self, dir: Dir) -> u64 {
        self.table.openable_local(dir)
    }

    /// Returns the peer's limit for `dir` if it stops the next local open.
    pub(crate) fn streams_blocked(&self, dir: Dir) -> Option<u64> {
        self.table.streams_blocked(dir)
    }

    /// Returns the peer's limit on local streams in direction `dir`, and the index of the next one.
    pub(crate) fn local_limit(&self, dir: Dir) -> (u64, u64) {
        self.table.local_limit(dir)
    }

    /// Applies the peer's stream limit for `dir` (see [`StreamTable::on_peer_max_streams`]).
    pub(crate) fn on_peer_max_streams(
        &mut self,
        dir: Dir,
        max: u64,
    ) -> Result<bool, TransportErrorCode> {
        self.table.on_peer_max_streams(dir, max)
    }

    /// Stops new streams (see [`StreamTable::shutdown`]).
    pub(crate) fn shutdown(&mut self) {
        self.table.shutdown();
    }

    fn guard(&mut self, slot: u32, id: StreamId) -> StreamGuard<'_, D> {
        StreamGuard {
            streams: self,
            slot,
            id,
        }
    }

    fn entry(&self, slot: u32) -> Option<&Entry<D>> {
        self.table.map().get_slot(slot).map(|(_, _, entry)| entry)
    }

    fn entry_mut(&mut self, slot: u32) -> &mut Entry<D> {
        match self.table.get_slot_mut(slot) {
            Some((_, _, entry)) => entry,
            // Invariant: guards and list links name only live slots.
            None => unreachable!("slot {slot} is not a live stream"),
        }
    }

    /// Recomputes the stream's list and scheduler membership from its state, and reaps it if
    /// it is closed and its last edge was delivered.
    fn reindex(&mut self, slot: u32, id: StreamId) {
        #[cfg(test)]
        {
            self.reindexes += 1;
            census::count(|c| c.reindexes += 1);
        }
        let Some(entry) = self.entry(slot) else {
            return;
        };
        let want = entry.stream.membership();
        let (have, alone) = (entry.member, entry.alone);
        let changed = want.lists ^ have;
        if changed != 0 {
            for list in List::ALL {
                if changed & list.bit() != 0 {
                    if want.lists & list.bit() != 0 {
                        self.link(list, slot);
                    } else {
                        self.unlink(list, slot);
                    }
                }
            }
            self.entry_mut(slot).member = want.lists;
            if changed & LOST_DATA != 0 {
                if want.lists & LOST_DATA != 0 {
                    self.lost += 1;
                } else {
                    self.lost -= 1;
                }
            }
            if changed & FIN_ONLY != 0 {
                if want.lists & FIN_ONLY != 0 {
                    self.fin_only += 1;
                } else {
                    self.fin_only -= 1;
                }
            }
        }
        let moved = match want.scheduled {
            Some(order) => self.scheduler.insert(slot, id, order),
            None => self.scheduler.remove(slot),
        };
        // The shares do not follow a lone peer that keeps its demand.
        if !alone || want.lists & List::Demand.bit() == 0 {
            self.reshare(slot, id, moved);
        }
        if want.reap {
            debug_assert!(want.lists == 0 && want.scheduled.is_none());
            self.scheduler.forget(slot);
            self.table.reap(id);
        }
    }

    /// Records the stream in `slot` in the shares as it stands, unless it is alone in its bucket:
    /// a lone peer's record is brought up to date only when another stream joins it, and its guard
    /// skips this while it stays alone with demand. An incremental stream that stays a peer of its
    /// bucket keeps its recorded place unless `moved` is set, which means that the scheduler has
    /// just scheduled, moved or unscheduled it. Its place changes otherwise only with a commit,
    /// which refreshes the place, or with its bucket's turn passing it, which [`Shares::settle`]
    /// catches up with.
    #[inline(never)]
    fn reshare(&mut self, slot: u32, id: StreamId, moved: bool) {
        #[cfg(test)]
        census::count(|c| c.reshares += 1);
        if let Some(entry) = self.entry(slot)
            && entry.member & List::Demand.bit() != 0
        {
            let order = entry.stream.order;
            match self.shares.standing(slot, share_key(order)) {
                Standing::Alone => {
                    self.entry_mut(slot).alone = true;
                    return;
                }
                Standing::Among if !moved && order.incremental => {
                    self.shares.hold(slot, entry.stream.data.holding());
                    return;
                }
                Standing::Among | Standing::Out => {}
            }
        }
        let peer = self.peer(slot, id);
        let regrouped = self.shares.update(slot, peer);
        let alone = self.shares.alone(slot);
        self.entry_mut(slot).alone = alone;
        if let Some(left) = regrouped.left {
            self.entry_mut(left).alone = true;
        }
        if let Some(joined) = regrouped.joined
            && let Some((_, id, _)) = self.table.map().get_slot(joined)
        {
            let peer = self.peer(joined, id);
            self.shares.update(joined, peer);
            self.entry_mut(joined).alone = false;
        }
    }

    /// Returns the stream in `slot` as a peer of its bucket of the split, if it is on the demand
    /// list.
    fn peer(&self, slot: u32, id: StreamId) -> Option<Peer> {
        let entry = self.entry(slot)?;
        if entry.member & List::Demand.bit() == 0 {
            return None;
        }
        let order = entry.stream.order;
        Some(Peer {
            key: share_key(order),
            id: id.into_inner(),
            place: self.place(slot, id, order),
            holding: entry.stream.data.holding(),
        })
    }

    /// Returns where the stream in `slot` at `order` stands in its bucket of the split.
    fn place(&self, slot: u32, id: StreamId, order: SendOrder) -> Place {
        if !order.incremental {
            return Place::Sequential(order.order);
        }
        match self.scheduler.place(slot, id, order) {
            // The scheduler would place the stream on the bucket's turn behind every stream on it.
            (_, u64::MAX) => Place::Unplaced,
            (turn, ticket) => Place::Placed { turn, ticket },
        }
    }

    fn link(&mut self, list: List, slot: u32) {
        let tail = self.lists[list as usize].tail;
        self.entry_mut(slot).links[list as usize] = Link {
            prev: tail,
            next: NIL,
        };
        if tail == NIL {
            self.lists[list as usize].head = slot;
        } else {
            #[cfg(test)]
            census::count(|c| c.neighbour_link_writes += 1);
            self.entry_mut(tail).links[list as usize].next = slot;
        }
        let head = &mut self.lists[list as usize];
        head.tail = slot;
        head.len += 1;
    }

    fn unlink(&mut self, list: List, slot: u32) {
        let Link { prev, next } = self.entry_mut(slot).links[list as usize];
        self.entry_mut(slot).links[list as usize] = UNLINKED;
        if prev == NIL {
            self.lists[list as usize].head = next;
        } else {
            #[cfg(test)]
            census::count(|c| c.neighbour_link_writes += 1);
            self.entry_mut(prev).links[list as usize].next = next;
        }
        if next == NIL {
            self.lists[list as usize].tail = prev;
        } else {
            #[cfg(test)]
            census::count(|c| c.neighbour_link_writes += 1);
            self.entry_mut(next).links[list as usize].prev = prev;
        }
        self.lists[list as usize].len -= 1;
    }
}

/// Returns the send half, or the error for an event on a stream that lacks one.
fn send_half<'a>(
    halves: &'a mut Halves,
    event: &'static str,
) -> Result<&'a mut SendState, InvalidTransition> {
    halves.send.as_mut().ok_or(InvalidTransition {
        state: "absent",
        event,
    })
}

/// Returns the receive half, or the error for an event on a stream that lacks one.
fn recv_half<'a>(
    halves: &'a mut Halves,
    event: &'static str,
) -> Result<&'a mut RecvState, InvalidTransition> {
    halves.recv.as_mut().ok_or(InvalidTransition {
        state: "absent",
        event,
    })
}

impl<D> Entry<D> {
    fn new(halves: Halves, order: SendOrder, data: D) -> Self {
        Entry {
            stream: Stream {
                order,
                halves,
                edges: Edges::default(),
                owed: Owed::default(),
                stop_code: None,
                peer_stop: None,
                producer_pending: true,
                closed_delivered: false,
                data,
            },
            links: [UNLINKED; LISTS],
            member: 0,
            alone: false,
        }
    }
}

impl<D: StreamData> StreamGuard<'_, D> {
    /// Returns the stream's ID.
    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    /// Returns the stream's state, read-only.
    pub(crate) fn view(&self) -> StreamRef<'_, D> {
        match self.streams.get_slot(self.slot) {
            Some(view) => view,
            // Invariant: a guard names a live slot; only its own drop reaps it.
            None => unreachable!("guarded slot {} is not live", self.slot),
        }
    }

    fn stream_mut(&mut self) -> &mut Stream<D> {
        &mut self.streams.entry_mut(self.slot).stream
    }

    /// Moves the stream to `order` in the wire order.
    pub(crate) fn set_order(&mut self, order: SendOrder) {
        let entry = self.streams.entry_mut(self.slot);
        entry.stream.order = order;
        entry.alone = false;
    }

    /// Records whether the stream's producer is pending: it returned `Pending`, or it has not
    /// been woken since the stream opened. A pending producer's stream is not pull-ready.
    pub(crate) fn set_producer_pending(&mut self, pending: bool) {
        self.stream_mut().producer_pending = pending;
    }

    /// Records that a STREAM frame (with the FIN bit if `fin`) or a STREAM_DATA_BLOCKED frame
    /// (`fin` false) was sealed.
    pub(crate) fn on_sent(&mut self, fin: bool) -> Result<Transition, InvalidTransition> {
        send_half(&mut self.stream_mut().halves, "on_sent")?.on_sent(fin)
    }

    /// Records that every byte and the FIN are acknowledged.
    pub(crate) fn on_all_acked(&mut self) -> Result<Transition, InvalidTransition> {
        send_half(&mut self.stream_mut().halves, "on_all_acked")?.on_all_acked()
    }

    /// Abandons the send half with RESET_STREAM carrying `code` and `final_size` (the bytes sent
    /// so far), and marks the frame owed. Pending writable and progress edges are dropped: the
    /// half does not take bytes, and the reset cancels the tracked offset.
    pub(crate) fn reset(
        &mut self,
        code: AppCode,
        final_size: u64,
    ) -> Result<Transition, InvalidTransition> {
        let stream = self.stream_mut();
        let transition = send_half(&mut stream.halves, "reset")?.reset(code, final_size)?;
        stream.owed.0 |= Owed::RESET_STREAM.0;
        stream.edges.0 &= !(Edges::WRITABLE | Edges::PROGRESS);
        Ok(transition)
    }

    /// Records that the application staged the FIN, and drops a pending writable edge: the half
    /// does not take more bytes.
    pub(crate) fn on_fin_staged(&mut self) {
        self.stream_mut().edges.0 &= !Edges::WRITABLE;
    }

    /// Records that the application tracks a new offset, and drops a pending progress edge, which
    /// was for the offset tracked before.
    pub(crate) fn on_track(&mut self) {
        self.stream_mut().edges.0 &= !Edges::PROGRESS;
    }

    /// Records that a packet carrying the RESET_STREAM was acknowledged.
    pub(crate) fn on_reset_acked(&mut self) -> Result<Transition, InvalidTransition> {
        let stream = self.stream_mut();
        let transition = send_half(&mut stream.halves, "on_reset_acked")?.on_reset_acked()?;
        stream.owed.0 &= !Owed::RESET_STREAM.0;
        Ok(transition)
    }

    /// Owes `frames`: a receive limit worth advertising, a send limit that blocks staged bytes,
    /// or a lost frame that is due again. A frame the half states no longer permit stays off the
    /// control list. Returns whether any of them became due for the control source to send.
    pub(crate) fn owe(&mut self, frames: Owed) -> bool {
        let stream = self.stream_mut();
        let before = stream.due().0;
        stream.owed.0 |= frames.0;
        stream.due().0 & !before != 0
    }

    /// Records that `frames` were sealed in a packet and are no longer owed.
    pub(crate) fn on_control_sent(&mut self, frames: Owed) {
        self.stream_mut().owed.0 &= !frames.0;
    }

    /// Requests that the peer stop sending: a STOP_SENDING carrying `code` is owed while the
    /// receive half is in Recv or Size Known. Repeat requests are ignored. Ingress is dropped from
    /// now on, and so are pending data edges.
    pub(crate) fn stop_sending(&mut self, code: AppCode) -> Result<Transition, InvalidTransition> {
        let stream = self.stream_mut();
        let recv = recv_half(&mut stream.halves, "stop_sending")?;
        if stream.stop_code.is_some() {
            return Ok(Transition::Unchanged);
        }
        if !recv.may_send_stop_sending() {
            return Err(InvalidTransition {
                state: recv.name(),
                event: "stop_sending",
            });
        }
        stream.stop_code = Some(code);
        stream.owed.0 |= Owed::STOP_SENDING.0;
        stream.edges.0 &= !(Edges::READABLE | Edges::FINISHED);
        Ok(Transition::Moved)
    }

    /// Records that a STREAM frame with the FIN bit arrived.
    pub(crate) fn on_fin(&mut self) -> Transition {
        let stream = self.stream_mut();
        stream
            .halves
            .recv
            .as_mut()
            .map_or(Transition::Unchanged, RecvState::on_fin)
    }

    /// Records that every byte up to the final size has arrived.
    pub(crate) fn on_all_received(&mut self) -> Result<Transition, InvalidTransition> {
        recv_half(&mut self.stream_mut().halves, "on_all_received")?.on_all_received()
    }

    /// Records that the application has read every byte up to the final size.
    pub(crate) fn on_all_data_read(&mut self) -> Result<Transition, InvalidTransition> {
        recv_half(&mut self.stream_mut().halves, "on_all_data_read")?.on_data_read()
    }

    /// Marks a readiness edge after the data parts changed: new in-order bytes, the FIN made
    /// readable, the allowance back at its low-water mark, or the tracked offset acknowledged.
    /// Data edges after the receive half was reset or read to the end, and writable edges after
    /// the send half ended, are dropped; a reset cancels the tracked offset, so a progress edge
    /// is not marked after it.
    pub(crate) fn mark(&mut self, edge: Edge) {
        let stream = self.stream_mut();
        let delivering = matches!(
            stream.halves.recv,
            Some(RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd)
        );
        let (bit, permitted) = match edge {
            Edge::Readable => (Edges::READABLE, delivering),
            Edge::Finished => (Edges::FINISHED, delivering),
            Edge::Writable => (
                Edges::WRITABLE,
                stream.halves.send.is_some_and(|s| s.takes_new_data()),
            ),
            Edge::Progress => (Edges::PROGRESS, true),
        };
        if permitted {
            stream.edges.0 |= bit;
        }
    }

    /// Records that a RESET_STREAM arrived (the table has checked the stream has a receive
    /// half). Unless the receive half already ended, delivery is interrupted: pending data edges
    /// are dropped and a reset edge is marked. The connection releases the unread bytes.
    pub(crate) fn on_reset_received(&mut self, code: AppCode, final_size: u64) -> Transition {
        let stream = self.stream_mut();
        let Some(recv) = stream.halves.recv.as_mut() else {
            return Transition::Unchanged;
        };
        let transition = recv.on_reset(code, final_size);
        if transition == Transition::Moved {
            stream.edges.0 &= !(Edges::READABLE | Edges::FINISHED);
            stream.edges.0 |= Edges::RESET;
        }
        transition
    }

    /// Records that a STOP_SENDING arrived (the table has checked the stream has a send half).
    /// The first one marks a stopped edge in place of a pending writable one, and the send half
    /// resets with the peer's code and `final_size` (the bytes sent so far) unless it already
    /// ended, queueing RESET_STREAM whatever the application does, as RFC 9000 requires until
    /// the FIN is sent, and dropping a pending progress edge.
    pub(crate) fn on_stop_sending(&mut self, code: AppCode, final_size: u64) -> Transition {
        let stream = self.stream_mut();
        let Some(send) = stream.halves.send.as_mut() else {
            return Transition::Unchanged;
        };
        if stream.peer_stop.is_some() {
            return Transition::Unchanged;
        }
        stream.peer_stop = Some(code);
        stream.edges.0 &= !Edges::WRITABLE;
        stream.edges.0 |= Edges::STOPPED;
        if send.reset(code, final_size).is_ok() {
            stream.owed.0 |= Owed::RESET_STREAM.0;
            stream.edges.0 &= !Edges::PROGRESS;
        }
        Transition::Moved
    }

    /// Delivers the stream's next readiness edge, in the order opened, readable, finished,
    /// reset, stopped, writable, progress, and last closed. Delivering a reset moves the receive
    /// half to Reset Read.
    pub(crate) fn take_edge(&mut self) -> Option<StreamReady> {
        let stream = self.stream_mut();
        let edges = &mut stream.edges;
        if edges.take(Edges::OPENED) {
            return Some(StreamReady::Opened);
        }
        if edges.take(Edges::READABLE) {
            return Some(StreamReady::Readable);
        }
        if edges.take(Edges::FINISHED) {
            return Some(StreamReady::Finished);
        }
        // Only a move to Reset Recvd marks the reset edge, and only its delivery leaves it.
        if edges.take(Edges::RESET)
            && let Some(recv) = stream.halves.recv.as_mut()
            && let RecvState::ResetRecvd { code, final_size } = *recv
        {
            let _ = recv.on_reset_read();
            return Some(StreamReady::Reset { code, final_size });
        }
        if edges.take(Edges::STOPPED)
            && let Some(code) = stream.peer_stop
        {
            return Some(StreamReady::Stopped { code });
        }
        if edges.take(Edges::WRITABLE) {
            return Some(StreamReady::Writable);
        }
        if edges.take(Edges::PROGRESS) {
            return Some(StreamReady::Progress);
        }
        if stream.halves.is_closed() && !stream.closed_delivered {
            stream.closed_delivered = true;
            return Some(StreamReady::Closed);
        }
        None
    }

    /// Returns the data parts, mutably: staging, sending, acknowledging and losing bytes,
    /// receiving and consuming them, and credit updates all change them.
    pub(crate) fn data_mut(&mut self) -> &mut D {
        &mut self.stream_mut().data
    }
}

impl<'a, D> StreamRef<'a, D> {
    /// Returns the stream's ID.
    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    /// Returns the stream's slab slot, which the scheduler and the lists name it by.
    pub(crate) fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns the stream's place in the wire order.
    pub(crate) fn order(&self) -> SendOrder {
        self.stream.order
    }

    /// Returns the send half, if the stream has one here.
    pub(crate) fn send_state(&self) -> Option<SendState> {
        self.stream.halves.send
    }

    /// Returns the receive half, if the stream has one here.
    pub(crate) fn recv_state(&self) -> Option<RecvState> {
        self.stream.halves.recv
    }

    /// Returns the stream's owed control frames, whether or not its state still permits them.
    #[cfg(test)]
    pub(crate) fn owed(&self) -> Owed {
        self.stream.owed
    }

    /// Returns the owed control frames its state still permits: what the control source sends.
    pub(crate) fn due(&self) -> Owed {
        self.stream.due()
    }

    /// Returns the code of our STOP_SENDING, set by [`StreamGuard::stop_sending`].
    pub(crate) fn stop_code(&self) -> Option<AppCode> {
        self.stream.stop_code
    }

    /// Returns the code of the peer's STOP_SENDING, once one arrived.
    pub(crate) fn peer_stop(&self) -> Option<AppCode> {
        self.stream.peer_stop
    }

    /// Returns the data parts.
    pub(crate) fn data(&self) -> &'a D {
        &self.stream.data
    }

    /// Returns the stream's own state, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn digest(&self) -> impl std::fmt::Debug {
        let s = self.stream;
        (
            s.order,
            s.halves,
            s.edges,
            s.owed,
            s.stop_code,
            s.peer_stop,
            s.producer_pending,
            s.closed_delivered,
        )
    }
}

impl<D: StreamData> Drop for StreamGuard<'_, D> {
    fn drop(&mut self) {
        self.streams.reindex(self.slot, self.id);
    }
}

/// Counts of the bookkeeping the streams do, kept per thread in tests: a test resets the census,
/// runs an operation and reads how much of each kind of work it did.
#[cfg(test)]
pub(crate) mod census {
    use std::cell::Cell;

    /// What the census counted on this thread since its last [`reset`].
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Census {
        /// Reindexes of a stream: one per dropped guard or materialized stream.
        pub(crate) reindexes: u64,
        /// Calls of the reshare that brings a stream's record in the shares up to date.
        pub(crate) reshares: u64,
        /// Rankings of the streams with demand.
        pub(crate) ranks: u64,
        /// Streams that scheduler walks reached: one per stream a cursor steps onto.
        pub(crate) scheduler_visits: u64,
        /// Moves of a peer to a new place in its bucket of the shares, by a reshare or a commit,
        /// while it stays a peer of that bucket.
        pub(crate) share_rekeys: u64,
        /// Writes to the links of another stream's list entry while a stream joins or leaves a
        /// list.
        pub(crate) neighbour_link_writes: u64,
    }

    thread_local! {
        static COUNTS: Cell<Census> = const {
            Cell::new(Census {
                reindexes: 0,
                reshares: 0,
                ranks: 0,
                scheduler_visits: 0,
                share_rekeys: 0,
                neighbour_link_writes: 0,
            })
        };
    }

    /// Sets every count of this thread to zero.
    pub(crate) fn reset() {
        COUNTS.set(Census::default());
    }

    /// Returns the counts of this thread.
    pub(crate) fn read() -> Census {
        COUNTS.get()
    }

    /// Adds what `f` adds to the counts of this thread.
    pub(crate) fn count(f: impl FnOnce(&mut Census)) {
        COUNTS.with(|counts| {
            let mut census = counts.get();
            f(&mut census);
            counts.set(census);
        });
    }
}

#[cfg(test)]
impl<D: StreamData> Streams<D> {
    /// Checks that every list and the scheduler hold exactly the streams whose state calls for
    /// them, that every list's links are consistent, and that the shares record exactly the
    /// streams on the demand list, each in its place with what it holds.
    pub(crate) fn assert_indexed(&self) {
        for (key, id, entry) in self.table.map().iter() {
            let want = entry.stream.membership();
            assert_eq!(entry.member, want.lists, "lists of stream {id}");
            assert_eq!(
                self.scheduler.order(key.slot()),
                want.scheduled,
                "scheduling of stream {id}"
            );
            assert!(!want.reap, "stream {id} should have been reaped");
            assert_eq!(
                entry.alone,
                self.shares.alone(key.slot()),
                "stream {id} alone in its bucket"
            );
            let peer = self.peer(key.slot(), id);
            let recorded = self.shares.recorded(key.slot()).map(|mut recorded| {
                if let Some(peer) = peer
                    && let Some(bucket) = self.shares.bucket(recorded.key)
                    && bucket.lone() == Some(key.slot())
                {
                    // What a lone peer holds and where it stands are not recorded.
                    (recorded.place, recorded.holding) = (peer.place, peer.holding);
                }
                // A place behind its bucket's turn stays recorded until the next settle moves it
                // among the unplaced peers, where the scheduler already puts it.
                if let Place::Placed { turn, .. } = recorded.place
                    && turn < self.scheduler.turn(entry.stream.order)
                {
                    recorded.place = Place::Unplaced;
                }
                recorded
            });
            assert_eq!(recorded, peer, "share of stream {id}");
        }
        assert_eq!(
            self.shares.assert_consistent(),
            self.len(List::Demand),
            "the shares record the demand list"
        );
        for list in List::ALL {
            let mut count = 0;
            let mut prev = NIL;
            let mut at = self.first(list);
            while let Some(slot) = at {
                let entry = self.entry(slot).expect("list members are live");
                assert_eq!(entry.links[list as usize].prev, prev, "{list:?} links");
                assert_ne!(entry.member & (1 << list as u8), 0, "{list:?} member bit");
                count += 1;
                prev = slot;
                at = self.next_on(list, slot);
            }
            assert_eq!(count, self.len(list), "{list:?} length");
            assert_eq!(self.lists[list as usize].tail, prev, "{list:?} tail");
        }
        assert_eq!(
            self.scheduler.len(),
            self.table
                .map()
                .iter()
                .filter(|(_, _, e)| e.stream.membership().scheduled.is_some())
                .count()
        );
        let lost = self
            .table
            .map()
            .iter()
            .filter(|(_, _, e)| e.member & LOST_DATA != 0)
            .count();
        assert_eq!(self.lost as usize, lost, "streams with lost data");
        let fin_only = self
            .table
            .map()
            .iter()
            .filter(|(_, _, e)| e.member & FIN_ONLY != 0)
            .count();
        assert_eq!(self.fin_only as usize, fin_only, "streams with a lone FIN");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streams::scheduler::Cursor;

    #[derive(Debug, Default)]
    struct Data {
        wire: bool,
        room: bool,
    }

    impl StreamData for Data {
        fn wire_data(&self) -> Option<Pending> {
            self.wire.then_some(Pending::New { bytes: 1 })
        }

        fn has_pull_room(&self) -> bool {
            self.room
        }

        fn has_demand(&self) -> bool {
            false
        }

        fn holding(&self) -> Holding {
            Holding::default()
        }
    }

    const ORDER: SendOrder = SendOrder {
        class: 1,
        urgency: 3,
        incremental: false,
        order: 0,
    };

    const CODE: AppCode = AppCode::from_u32(9);

    /// Returns a server's streams with room for ten streams of each type both ways.
    fn streams() -> Streams<Data> {
        let mut s = Streams::new(Side::Server, 10, 10, 1200);
        s.on_peer_max_streams(Dir::Bi, 10).unwrap();
        s.on_peer_max_streams(Dir::Uni, 10).unwrap();
        s
    }

    /// Where a stream is indexed.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct On {
        readiness: bool,
        pull_ready: bool,
        control: bool,
        scheduled: Option<SendOrder>,
    }

    const NOWHERE: On = On {
        readiness: false,
        pull_ready: false,
        control: false,
        scheduled: None,
    };

    fn on(s: &Streams<Data>, id: StreamId) -> On {
        s.assert_indexed();
        let listed = |list| {
            let mut at = s.first(list);
            while let Some(slot) = at {
                if s.table.map().get_slot(slot).map(|(_, i, _)| i) == Some(id) {
                    return true;
                }
                at = s.next_on(list, slot);
            }
            false
        };
        let key = s.table.map().key(id).expect("stream is live");
        On {
            readiness: listed(List::Readiness),
            pull_ready: listed(List::PullReady),
            control: listed(List::Control),
            scheduled: s.scheduler.order(key.slot()),
        }
    }

    /// Opens a local stream with its producer woken, as at a pull driver's first poll.
    fn open(s: &mut Streams<Data>, dir: Dir, data: Data) -> StreamId {
        let mut stream = s.open_local(dir, ORDER, data).unwrap();
        stream.set_producer_pending(false);
        stream.id()
    }

    #[test]
    fn a_new_stream_with_room_is_pull_ready_once_its_producer_is_woken() {
        let mut s = streams();
        let room = || Data {
            wire: false,
            room: true,
        };
        let with_room = s.open_local(Dir::Uni, ORDER, room()).unwrap().id();
        let without = open(&mut s, Dir::Uni, Data::default());
        assert_eq!(on(&s, with_room), NOWHERE, "its producer starts pending");
        s.stream(with_room).unwrap().set_producer_pending(false);
        assert_eq!(
            on(&s, with_room),
            On {
                pull_ready: true,
                ..NOWHERE
            }
        );
        assert_eq!(on(&s, without), NOWHERE);
    }

    fn peer(s: &mut Streams<Data>, dir: Dir, index: u64) -> StreamId {
        let id = StreamId::new(Side::Client, dir, index).unwrap();
        let guard = s.peer_frame(id, Half::Recv, |_| (ORDER, Data::default()));
        assert!(matches!(guard, Ok(Some(_))));
        id
    }

    fn take_edge(s: &mut Streams<Data>, id: StreamId) -> Option<StreamReady> {
        s.stream(id).unwrap().take_edge()
    }

    #[test]
    fn a_stream_the_peer_opens_is_readable_until_its_opened_edge_is_delivered() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Uni, 0);
        assert_eq!(
            on(&s, id),
            On {
                readiness: true,
                ..NOWHERE
            }
        );
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        assert_eq!(on(&s, id), NOWHERE);
        assert_eq!(take_edge(&mut s, id), None);
        // A later frame for the same stream does not mark a new edge.
        drop(s.peer_frame(id, Half::Recv, |_| unreachable!()).unwrap());
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn bytes_for_the_wire_schedule_the_stream_at_its_order() {
        let mut s = streams();
        let id = open(&mut s, Dir::Uni, Data::default());
        s.stream(id).unwrap().data_mut().wire = true;
        assert_eq!(
            on(&s, id),
            On {
                scheduled: Some(ORDER),
                ..NOWHERE
            }
        );
        let urgent = SendOrder {
            urgency: 0,
            ..ORDER
        };
        s.stream(id).unwrap().set_order(urgent);
        assert_eq!(s.get(id).unwrap().order(), urgent);
        assert_eq!(
            on(&s, id),
            On {
                scheduled: Some(urgent),
                ..NOWHERE
            }
        );
        s.stream(id).unwrap().data_mut().wire = false;
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn a_stream_that_keeps_its_demand_takes_its_share_to_its_new_order() {
        let mut s = streams();
        let ready = Data {
            wire: false,
            room: true,
        };
        let id = open(&mut s, Dir::Uni, ready);
        assert!(
            on(&s, id).pull_ready,
            "a ready producer with room has demand"
        );
        let slot = s.table.map().key(id).unwrap().slot();
        for order in [
            SendOrder {
                urgency: 0,
                ..ORDER
            },
            SendOrder {
                incremental: true,
                ..ORDER
            },
            SendOrder { order: 5, ..ORDER },
        ] {
            s.stream(id).unwrap().set_order(order);
            s.assert_indexed();
            let share = s.shares().recorded(slot).map(|p| p.key);
            assert_eq!(share, Some(share_key(order)), "the share follows {order:?}");
        }
    }

    #[test]
    fn data_edges_are_delivered_once_and_consuming_does_not_redeliver() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Bi, 0);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        s.stream(id).unwrap().mark(Edge::Readable);
        assert!(on(&s, id).readiness);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Readable));
        assert_eq!(take_edge(&mut s, id), None);
        assert!(!on(&s, id).readiness);
        // Consuming changes the data parts but does not mark an edge.
        let mut guard = s.stream(id).unwrap();
        let _ = guard.data_mut();
        drop(guard);
        assert!(!on(&s, id).readiness);
        let mut guard = s.stream(id).unwrap();
        guard.mark(Edge::Writable);
        guard.mark(Edge::Finished);
        guard.mark(Edge::Readable);
        drop(guard);
        assert!(on(&s, id).readiness);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Readable));
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Finished));
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Writable));
        assert_eq!(take_edge(&mut s, id), None);
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn a_peer_reset_replaces_pending_data_edges_and_is_read_on_delivery() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Uni, 0);
        let mut guard = s.stream(id).unwrap();
        guard.mark(Edge::Readable);
        assert_eq!(guard.on_reset_received(CODE, 40), Transition::Moved);
        drop(guard);
        assert!(on(&s, id).readiness);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        // A repeated RESET_STREAM does not mark a new edge.
        assert_eq!(
            s.stream(id).unwrap().on_reset_received(CODE, 40),
            Transition::Unchanged
        );
        assert_eq!(
            take_edge(&mut s, id),
            Some(StreamReady::Reset {
                code: CODE,
                final_size: 40
            })
        );
        assert_eq!(
            s.get(id).unwrap().recv_state(),
            Some(RecvState::ResetRead {
                code: CODE,
                final_size: 40
            })
        );
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Closed));
    }

    #[test]
    fn a_peer_stop_sending_resets_the_send_half_and_owes_reset_stream() {
        let mut s = streams();
        let id = open(
            &mut s,
            Dir::Bi,
            Data {
                wire: true,
                room: true,
            },
        );
        assert_eq!(
            on(&s, id),
            On {
                pull_ready: true,
                scheduled: Some(ORDER),
                ..NOWHERE
            }
        );
        let mut guard = s
            .peer_frame(id, Half::Send, |_| unreachable!())
            .unwrap()
            .unwrap();
        assert_eq!(guard.on_stop_sending(CODE, 100), Transition::Moved);
        drop(guard);
        // The send buffer still holds bytes, but a reset stream does not send STREAM frames.
        assert_eq!(
            on(&s, id),
            On {
                readiness: true,
                control: true,
                ..NOWHERE
            }
        );
        assert_eq!(
            s.get(id).unwrap().send_state(),
            Some(SendState::ResetSent {
                code: CODE,
                final_size: 100
            })
        );
        assert!(s.get(id).unwrap().owed().contains(Owed::RESET_STREAM));
        assert_eq!(
            s.stream(id)
                .unwrap()
                .on_stop_sending(AppCode::from_u32(1), 100),
            Transition::Unchanged
        );
        assert_eq!(
            take_edge(&mut s, id),
            Some(StreamReady::Stopped { code: CODE })
        );
        assert_eq!(take_edge(&mut s, id), None);
        assert_eq!(
            on(&s, id),
            On {
                control: true,
                ..NOWHERE
            }
        );
    }

    #[test]
    fn stop_sending_for_a_stream_without_a_send_half_changes_nothing() {
        // The table rejects such a frame with STREAM_STATE_ERROR before a guard exists for it.
        let mut s = streams();
        let id = peer(&mut s, Dir::Uni, 0);
        assert_eq!(
            s.stream(id).unwrap().on_stop_sending(CODE, 0),
            Transition::Unchanged
        );
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        assert_eq!(take_edge(&mut s, id), None);
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn an_application_reset_owes_reset_stream_until_sent_and_again_only_while_unacknowledged() {
        let mut s = streams();
        let id = open(
            &mut s,
            Dir::Uni,
            Data {
                wire: true,
                room: true,
            },
        );
        assert_eq!(s.stream(id).unwrap().reset(CODE, 7), Ok(Transition::Moved));
        assert_eq!(
            on(&s, id),
            On {
                control: true,
                ..NOWHERE
            }
        );
        s.stream(id).unwrap().on_control_sent(Owed::RESET_STREAM);
        assert_eq!(on(&s, id), NOWHERE);
        // Lost: owed again.
        s.stream(id).unwrap().owe(Owed::RESET_STREAM);
        assert!(on(&s, id).control);
        s.stream(id).unwrap().on_control_sent(Owed::RESET_STREAM);
        assert_eq!(
            s.stream(id).unwrap().on_reset_acked(),
            Ok(Transition::Moved)
        );
        // Once the reset is acknowledged, a lost copy is not sent again.
        s.stream(id).unwrap().owe(Owed::RESET_STREAM);
        assert_eq!(
            on(&s, id),
            On {
                readiness: true,
                ..NOWHERE
            },
            "closed, with its closed edge to deliver"
        );
        assert_eq!(
            s.stream(id).unwrap().reset(CODE, 7),
            Err(InvalidTransition {
                state: "Reset Recvd",
                event: "reset"
            })
        );
    }

    #[test]
    fn stop_sending_is_owed_until_sent_or_every_byte_has_arrived() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Bi, 0);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        assert_eq!(
            s.stream(id).unwrap().stop_sending(CODE),
            Ok(Transition::Moved)
        );
        assert_eq!(s.get(id).unwrap().stop_code(), Some(CODE));
        assert_eq!(
            on(&s, id),
            On {
                control: true,
                ..NOWHERE
            }
        );
        assert_eq!(
            s.stream(id).unwrap().stop_sending(AppCode::from_u32(1)),
            Ok(Transition::Unchanged)
        );
        assert_eq!(s.get(id).unwrap().stop_code(), Some(CODE));
        assert_eq!(s.stream(id).unwrap().on_fin(), Transition::Moved);
        assert!(on(&s, id).control, "still useful in Size Known");
        assert_eq!(
            s.stream(id).unwrap().on_all_received(),
            Ok(Transition::Moved)
        );
        assert_eq!(on(&s, id), NOWHERE);
        // `stop_sending` fails on a stream whose bytes have all arrived.
        let complete = peer(&mut s, Dir::Bi, 1);
        let mut guard = s.stream(complete).unwrap();
        guard.on_fin();
        guard.on_all_received().unwrap();
        assert_eq!(
            guard.stop_sending(CODE),
            Err(InvalidTransition {
                state: "Data Recvd",
                event: "stop_sending"
            })
        );
        drop(guard);
        assert!(!on(&s, complete).control);
        let local_uni = open(&mut s, Dir::Uni, Data::default());
        assert_eq!(
            s.stream(local_uni).unwrap().stop_sending(CODE),
            Err(InvalidTransition {
                state: "absent",
                event: "stop_sending"
            })
        );
    }

    #[test]
    fn max_stream_data_is_owed_only_while_the_final_size_is_unknown() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Uni, 0);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        s.stream(id).unwrap().owe(Owed::MAX_STREAM_DATA);
        assert_eq!(
            on(&s, id),
            On {
                control: true,
                ..NOWHERE
            }
        );
        s.stream(id).unwrap().on_control_sent(Owed::MAX_STREAM_DATA);
        assert_eq!(on(&s, id), NOWHERE);
        s.stream(id).unwrap().owe(Owed::MAX_STREAM_DATA);
        assert!(on(&s, id).control);
        // RFC 9000 permits MAX_STREAM_DATA only in Recv, so not once the FIN has arrived.
        s.stream(id).unwrap().on_fin();
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn stream_data_blocked_is_owed_only_until_the_fin_is_sent() {
        let mut s = streams();
        let id = open(&mut s, Dir::Uni, Data::default());
        s.stream(id).unwrap().owe(Owed::STREAM_DATA_BLOCKED);
        assert_eq!(
            on(&s, id),
            On {
                control: true,
                ..NOWHERE
            }
        );
        assert_eq!(s.stream(id).unwrap().on_sent(false), Ok(Transition::Moved));
        assert!(on(&s, id).control);
        assert_eq!(s.stream(id).unwrap().on_sent(true), Ok(Transition::Moved));
        assert_eq!(s.get(id).unwrap().send_state(), Some(SendState::DataSent));
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn a_pending_producer_is_not_pull_ready_until_woken() {
        let mut s = streams();
        let id = open(
            &mut s,
            Dir::Bi,
            Data {
                wire: false,
                room: true,
            },
        );
        assert!(on(&s, id).pull_ready);
        s.stream(id).unwrap().set_producer_pending(true);
        assert_eq!(on(&s, id), NOWHERE);
        s.stream(id).unwrap().set_producer_pending(false);
        assert!(on(&s, id).pull_ready);
        // Without room (credit or staging space) a woken producer is still not polled.
        s.stream(id).unwrap().data_mut().room = false;
        assert_eq!(on(&s, id), NOWHERE);
    }

    #[test]
    fn lost_bytes_reschedule_a_finished_stream_until_everything_is_acknowledged() {
        let mut s = streams();
        let id = open(
            &mut s,
            Dir::Uni,
            Data {
                wire: true,
                room: false,
            },
        );
        let mut guard = s.stream(id).unwrap();
        guard.on_sent(true).unwrap();
        guard.data_mut().wire = false;
        drop(guard);
        assert_eq!(on(&s, id), NOWHERE);
        // Loss: the retransmission is wire data again.
        s.stream(id).unwrap().data_mut().wire = true;
        assert_eq!(on(&s, id).scheduled, Some(ORDER));
        // The last ACK ends the half, so the stream leaves the scheduler whatever its buffer holds.
        assert_eq!(s.stream(id).unwrap().on_all_acked(), Ok(Transition::Moved));
        assert_eq!(
            on(&s, id),
            On {
                readiness: true,
                ..NOWHERE
            }
        );
    }

    #[test]
    fn a_closed_stream_is_reaped_once_its_closed_edge_is_delivered() {
        let mut s = streams();
        // A local bidirectional stream: both halves end, then the edge goes out.
        let id = open(&mut s, Dir::Bi, Data::default());
        let mut guard = s.stream(id).unwrap();
        guard.on_sent(true).unwrap();
        guard.on_all_acked().unwrap();
        guard.on_fin();
        guard.on_all_received().unwrap();
        guard.mark(Edge::Finished);
        assert_eq!(guard.on_all_data_read(), Ok(Transition::Moved));
        drop(guard);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Finished));
        assert!(on(&s, id).readiness);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Closed));
        assert!(s.stream(id).is_none());
        assert_eq!(s.len(List::Readiness), 0);
        s.assert_indexed();
        // Reaping peer streams returns their credit with MAX_STREAMS (window 5 of 10).
        for index in 0..5 {
            let id = peer(&mut s, Dir::Uni, index);
            s.stream(id).unwrap().on_reset_received(CODE, 0);
            while take_edge(&mut s, id) != Some(StreamReady::Closed) {}
            assert!(s.stream(id).is_none());
            let frame = s.peer_frame(id, Half::Recv, |_| unreachable!());
            assert!(
                matches!(frame, Ok(None)),
                "frames for reaped streams are ignored"
            );
        }
        assert_eq!(s.max_streams(Dir::Uni), 15);
        assert_eq!(s.table.map().len(), 0);
        assert_eq!(s.scheduler().len(), 0);
        s.assert_indexed();
        // The peer may use the new credit once the MAX_STREAMS carrying it is sent.
        let above = StreamId::new(Side::Client, Dir::Uni, 10).unwrap();
        assert!(matches!(
            s.peer_frame(above, Half::Recv, |_| (ORDER, Data::default())),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        ));
        s.on_max_streams_sent(Dir::Uni, 15);
        peer(&mut s, Dir::Uni, 10);
        s.assert_indexed();
    }

    #[test]
    fn data_edges_are_not_marked_on_halves_that_ended() {
        let mut s = streams();
        let id = peer(&mut s, Dir::Bi, 0);
        assert_eq!(take_edge(&mut s, id), Some(StreamReady::Opened));
        let mut guard = s.stream(id).unwrap();
        guard.on_reset_received(CODE, 0);
        guard.reset(CODE, 0).unwrap();
        drop(guard);
        assert!(matches!(
            take_edge(&mut s, id),
            Some(StreamReady::Reset { .. })
        ));
        assert_eq!(take_edge(&mut s, id), None);
        // Bytes arriving after the peer's reset, or credit after our reset, do not mark an edge.
        let mut guard = s.stream(id).unwrap();
        guard.mark(Edge::Readable);
        guard.mark(Edge::Finished);
        guard.mark(Edge::Writable);
        drop(guard);
        assert_eq!(take_edge(&mut s, id), None);
        assert!(!on(&s, id).readiness);
    }

    #[test]
    fn a_build_that_drains_each_stream_it_visits_reaches_every_scheduled_stream() {
        let mut s = streams();
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let wire = || Data {
            wire: true,
            room: false,
        };
        let ids: Vec<_> = [ORDER, ORDER, incremental, incremental, incremental]
            .into_iter()
            .map(|order| s.open_local(Dir::Uni, order, wire()).unwrap().id())
            .collect();
        let mut cursor = Cursor::default();
        let mut written = Vec::new();
        while let Some(slot) = s.scheduler().next(&mut cursor) {
            let mut guard = s.by_slot(slot).unwrap();
            written.push(guard.id());
            guard.data_mut().wire = false;
        }
        assert_eq!(written, ids);
        assert!(s.scheduler().is_empty());
        s.assert_indexed();
    }

    #[test]
    fn a_stream_the_build_drained_is_charged_for_what_it_sealed() {
        // Stream a's GSO run of ten packets drains it, so its guard unschedules it before the
        // run is committed, and its producer refills it before the next run.
        let mut s = streams();
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let wire = || Data {
            wire: true,
            room: false,
        };
        let a = s.open_local(Dir::Uni, incremental, wire()).unwrap().id();
        s.open_local(Dir::Uni, incremental, wire()).unwrap();
        let mut sent = [0u64; 2];
        for _ in 0..1000 {
            let slot = s.scheduler().iter().next().unwrap();
            let mut guard = s.by_slot(slot).unwrap();
            let guard_id = guard.id();
            let drained = guard_id == a;
            if drained {
                guard.data_mut().wire = false;
            }
            drop(guard);
            let bytes = if drained { 12_000 } else { 1_200 };
            s.commit(slot, guard_id, bytes);
            sent[usize::from(!drained)] += bytes;
            s.stream(a).unwrap().data_mut().wire = true;
        }
        assert!(
            sent[0].abs_diff(sent[1]) <= 12_000,
            "bytes per stream: {sent:?}"
        );
        s.assert_indexed();
    }

    #[test]
    fn a_commit_that_raises_the_front_stream_moves_its_share_to_its_new_place() {
        let mut s = streams();
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let ready = || Data {
            wire: true,
            room: true,
        };
        let slots = [(); 4].map(|()| {
            let mut guard = s.open_local(Dir::Uni, incremental, ready()).unwrap();
            guard.set_producer_pending(false);
            let id = guard.id();
            drop(guard);
            (s.table.map().key(id).unwrap().slot(), id)
        });
        let [(f, _), (y, y_id), (z, z_id), (x, x_id)] = slots;
        // Y moves to turn 1 and X to turn 3, with F still on turn 0 in front; X's next commit
        // raises F to a quantum, behind Y on turn 1. Z reaches turn 1 after that, behind F.
        s.commit(y, y_id, 1200);
        s.commit(x, x_id, 3 * 1200);
        s.commit(x, x_id, 1);
        s.commit(z, z_id, 1200);
        let in_order: Vec<_> = s.scheduler().iter().collect();
        assert_eq!(in_order, [y, f, z, x]);
        s.settle_shares();
        let shares = s.shares();
        let bucket = shares.bucket(share_key(incremental)).unwrap();
        let members: Vec<_> = shares.members(bucket).collect();
        assert_eq!(members, in_order, "the shares list the scheduler's order");
    }

    #[test]
    fn a_stream_in_a_reaped_streams_slot_owes_nothing_for_it() {
        let mut s = streams();
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let wire = || Data {
            wire: true,
            room: false,
        };
        let id = s.open_local(Dir::Uni, incremental, wire()).unwrap().id();
        let a = s.get(id).unwrap().slot();
        let b_guard = s.open_local(Dir::Uni, incremental, wire()).unwrap();
        let (b, b_id) = (b_guard.view().slot(), b_guard.id());
        drop(b_guard);
        s.stream(id).unwrap().data_mut().wire = false;
        s.commit(a, id, 5 * 1200);
        let mut guard = s.stream(id).unwrap();
        guard.reset(CODE, 0).unwrap();
        guard.on_reset_acked().unwrap();
        drop(guard);
        while take_edge(&mut s, id) != Some(StreamReady::Closed) {}
        assert!(s.stream(id).is_none());
        let c = s
            .open_local(Dir::Uni, incremental, wire())
            .unwrap()
            .view()
            .slot();
        assert_eq!(c, a, "the slot is reused");
        let order = |s: &Streams<Data>| s.scheduler().iter().collect::<Vec<_>>();
        assert_eq!(order(&s), [b, c]);
        s.commit(b, b_id, 1200);
        assert_eq!(order(&s), [c, b]);
        s.assert_indexed();
    }

    #[test]
    fn a_late_commit_for_a_reaped_stream_charges_no_stream() {
        // Drain, reap, reuse, then a late commit. A commit for a stream that was reaped, before
        // or after another stream takes its slot, does not change the order.
        let mut s = streams();
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let wire = || Data {
            wire: true,
            room: false,
        };
        let open = |s: &mut Streams<Data>| {
            let guard = s.open_local(Dir::Uni, incremental, wire()).unwrap();
            (guard.view().slot(), guard.id())
        };
        let (a, x) = open(&mut s);
        let (z, _) = open(&mut s);
        let (w, w_id) = open(&mut s);
        s.commit(a, x, 10 * 1200);
        s.commit(w, w_id, 3 * 1200);
        let order = |s: &Streams<Data>| s.scheduler().iter().collect::<Vec<_>>();
        assert_eq!(order(&s), [z, w, a]);
        // Stream x drains, ends and is reaped.
        s.stream(x).unwrap().data_mut().wire = false;
        let mut guard = s.stream(x).unwrap();
        guard.reset(CODE, 0).unwrap();
        guard.on_reset_acked().unwrap();
        drop(guard);
        while take_edge(&mut s, x) != Some(StreamReady::Closed) {}
        assert!(s.stream(x).is_none());
        s.commit(a, x, 1200);
        assert_eq!(
            order(&s),
            [z, w],
            "z is not held to the reaped stream's bytes"
        );
        let (c, _) = open(&mut s);
        assert_eq!(c, a, "the slot is reused");
        assert_eq!(order(&s), [z, c, w]);
        s.commit(a, x, 5 * 1200);
        assert_eq!(order(&s), [z, c, w], "the new stream owes nothing for x");
        s.assert_indexed();
    }

    #[test]
    fn credit_from_max_stream_data_reindexes_a_blocked_stream() {
        // MAX_STREAM_DATA must reschedule a blocked stream whatever the connection credit, which
        // the scheduler does not consider.
        let mut s = streams();
        let id = open(&mut s, Dir::Bi, Data::default());
        assert_eq!(on(&s, id), NOWHERE);
        let mut guard = s
            .peer_frame(id, Half::Send, |_| unreachable!())
            .unwrap()
            .unwrap();
        let data = guard.data_mut();
        data.wire = true;
        data.room = true;
        drop(guard);
        assert_eq!(
            on(&s, id),
            On {
                pull_ready: true,
                scheduled: Some(ORDER),
                ..NOWHERE
            }
        );
    }

    #[test]
    fn lists_keep_the_order_streams_joined_them() {
        let mut s = streams();
        let ids: Vec<_> = (0..3)
            .map(|_| open(&mut s, Dir::Bi, Data::default()))
            .collect();
        for &i in [1, 0, 2].iter() {
            s.stream(ids[i]).unwrap().owe(Owed::MAX_STREAM_DATA);
        }
        // Owing more does not move a stream already listed.
        s.stream(ids[1]).unwrap().owe(Owed::STREAM_DATA_BLOCKED);
        let mut listed = Vec::new();
        let mut at = s.first(List::Control);
        while let Some(slot) = at {
            listed.push(s.by_slot(slot).unwrap().id());
            at = s.next_on(List::Control, slot);
        }
        assert_eq!(listed, [ids[1], ids[0], ids[2]]);
        s.assert_indexed();
    }

    #[test]
    fn due_frames_are_the_owed_ones_the_half_states_permit() {
        let mut s = streams();
        let id = open(&mut s, Dir::Bi, Data::default());
        let mut guard = s.stream(id).unwrap();
        for frames in [
            Owed::MAX_STREAM_DATA,
            Owed::STOP_SENDING,
            Owed::RESET_STREAM,
            Owed::STREAM_DATA_BLOCKED,
        ] {
            guard.owe(frames);
        }
        drop(guard);
        let due = s.get(id).unwrap().due();
        assert!(due.contains(Owed::MAX_STREAM_DATA));
        assert!(due.contains(Owed::STOP_SENDING));
        assert!(due.contains(Owed::STREAM_DATA_BLOCKED));
        assert!(!due.contains(Owed::RESET_STREAM), "not reset");
        s.stream(id).unwrap().reset(CODE, 0).unwrap();
        let due = s.get(id).unwrap().due();
        assert!(due.contains(Owed::RESET_STREAM));
        assert!(!due.contains(Owed::STREAM_DATA_BLOCKED), "reset");
        assert!(due.contains(Owed::MAX_STREAM_DATA));
        assert!(on(&s, id).control);
    }

    #[test]
    fn the_census_counts_a_reindex_per_dropped_guard() {
        let mut s = streams();
        census::reset();
        let before = s.reindexes();
        let id = open(&mut s, Dir::Uni, Data::default());
        for _ in 0..3 {
            drop(s.stream(id).unwrap());
        }
        assert_eq!(s.reindexes() - before, 4, "one reindex per guard");
        assert_eq!(census::read().reindexes, 4);
        census::reset();
        assert_eq!(
            census::read(),
            census::Census::default(),
            "a reset zeroes every count"
        );
    }

    /// Opens a local unidirectional stream at `order` whose woken producer has room: it has demand.
    fn open_with_demand(s: &mut Streams<Data>, order: SendOrder, wire: bool) -> (u32, StreamId) {
        let mut guard = s
            .open_local(Dir::Uni, order, Data { wire, room: true })
            .unwrap();
        guard.set_producer_pending(false);
        let id = guard.id();
        drop(guard);
        (s.table.map().key(id).unwrap().slot(), id)
    }

    #[test]
    fn the_census_counts_the_reshares_of_a_peer_among_others_but_not_of_a_lone_one() {
        let mut s = streams();
        let (_, among) = open_with_demand(&mut s, ORDER, false);
        open_with_demand(&mut s, ORDER, false);
        let urgent = SendOrder {
            urgency: 0,
            ..ORDER
        };
        let (_, lone) = open_with_demand(&mut s, urgent, false);
        census::reset();
        for _ in 0..3 {
            drop(s.stream(among).unwrap());
        }
        assert_eq!(
            census::read().reshares,
            3,
            "a peer among others is reshared per reindex"
        );
        for _ in 0..3 {
            drop(s.stream(lone).unwrap());
        }
        assert_eq!(
            census::read().reshares,
            3,
            "a lone peer that keeps its demand is not reshared"
        );
    }

    #[test]
    fn the_census_counts_a_share_rekey_per_move_within_a_bucket() {
        let mut s = streams();
        let (_, a) = open_with_demand(&mut s, ORDER, false);
        open_with_demand(&mut s, ORDER, false);
        let incremental = SendOrder {
            incremental: true,
            ..ORDER
        };
        let (x, x_id) = open_with_demand(&mut s, incremental, true);
        let (y, y_id) = open_with_demand(&mut s, incremental, true);
        census::reset();
        s.stream(a)
            .unwrap()
            .set_order(SendOrder { order: 5, ..ORDER });
        assert_eq!(
            census::read().share_rekeys,
            1,
            "a new order within the bucket"
        );
        drop(s.stream(a).unwrap());
        assert_eq!(
            census::read().share_rekeys,
            1,
            "a reshare in place does not move it"
        );
        s.commit(x, x_id, 1200);
        assert_eq!(
            census::read().share_rekeys,
            2,
            "a commit that moves it to the next turn"
        );
        s.commit(y, y_id, 100);
        assert_eq!(
            census::read().share_rekeys,
            2,
            "a commit within its quantum"
        );
        s.assert_indexed();
    }

    #[test]
    fn the_census_counts_link_writes_into_neighbouring_entries() {
        let mut s = streams();
        let [a, b, c] = [(); 3].map(|()| open(&mut s, Dir::Bi, Data::default()));
        census::reset();
        // Joining writes the old tail's link, except for the first stream on the list.
        for id in [a, b, c] {
            s.stream(id).unwrap().owe(Owed::MAX_STREAM_DATA);
        }
        assert_eq!(census::read().neighbour_link_writes, 2);
        // Leaving from the middle writes both neighbours' links, and from the head the next one's.
        s.stream(b).unwrap().on_control_sent(Owed::MAX_STREAM_DATA);
        s.stream(a).unwrap().on_control_sent(Owed::MAX_STREAM_DATA);
        assert_eq!(census::read().neighbour_link_writes, 5);
        assert_eq!(s.first(List::Control), s.get(c).map(|r| r.slot()));
        s.assert_indexed();
    }
}
