/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The prioritization seam.
//!
//! A [`Prioritizer`] owns a connection's wire order and the split of its staging budget within
//! the buckets of that order. A connection reaches its plug by static dispatch, through the type
//! parameter of [`Connection`](crate::Connection) and [`Endpoint`](crate::Endpoint), whose default
//! is [`FairShare`]; code that names `Connection` alone gets the default. Every plug reads the same
//! priority signal, each stream's [`SendOrder`], so the stream API does not depend on the plug.
//!
//! A plug names streams by their slab slot (see [`StreamKey::slot`](super::map::StreamKey::slot))
//! and reads them through [`Peers`].

use std::fmt;

use mvfstr_wire::StreamId;

pub use super::fair_share::FairShare;
use super::scheduler::SendOrder;

/// The wire order of a connection's streams and the split of its staging budget among the streams
/// on the demand list, by bucket in that order.
///
/// The stream guard keeps the plug up to date: each reindex schedules or unschedules the stream
/// and, while the stream is on the demand list or leaves it, lets the plug record it
/// ([`reshare`](Self::reshare)). A packet build walks the scheduled streams with a cursor, and each
/// sealed packet or GSO run is committed.
pub trait Prioritizer: Sized {
    /// A position in a walk over the scheduled streams in wire order, for one packet; the default
    /// is the start of a walk.
    type Cursor: Clone + Copy + Default + fmt::Debug;

    /// Creates an empty plug. A plug that counts turns in bytes serves an incremental stream
    /// `quantum` bytes per turn.
    fn new(quantum: u64) -> Self;

    /// Returns the number of scheduled streams.
    fn len(&self) -> usize;

    /// Returns true when the plug does not schedule any stream.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Schedules the stream in `slot`, whose ID is `id`, at `order`, or moves it there if it is
    /// scheduled. Returns whether it scheduled or moved the stream: false for a stream already
    /// scheduled at `order`.
    fn insert(&mut self, slot: u32, id: StreamId, order: SendOrder) -> bool;

    /// Unschedules the stream in `slot` and returns whether it was scheduled.
    fn remove(&mut self, slot: u32) -> bool;

    /// Drops what the plug keeps about the stream in `slot` once it is gone for good; the stream
    /// must not be scheduled.
    fn forget(&mut self, slot: u32);

    /// Returns the order the stream in `slot` is scheduled at, if it is scheduled.
    fn order(&self, slot: u32) -> Option<SendOrder>;

    /// Returns the next scheduled stream in wire order after the cursor's position and advances
    /// the cursor. The stream the walk is at, or any other, may leave before the walk moves on.
    /// A stream that joins during the walk may or may not be visited, and one that is committed
    /// during it may be visited twice.
    fn next(&self, cursor: &mut Self::Cursor) -> Option<u32>;

    /// Iterates over the scheduled streams in wire order.
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let mut cursor = Self::Cursor::default();
        std::iter::from_fn(move || self.next(&mut cursor))
    }

    /// Records that `bytes` of stream `id`, in `slot`, were sealed in a packet or GSO run, whether
    /// or not the stream is still scheduled; a commit for a stream the slot no longer holds is
    /// ignored. Every guard is closed, so `streams` reads each stream as its last reindex left it.
    fn commit(&mut self, slot: u32, id: StreamId, bytes: u64, streams: &impl Peers);

    /// Records the stream in `slot` as its reindex left it: on the demand list, or just off it.
    /// `moved` is true when that reindex scheduled, moved or unscheduled the stream. While a
    /// stream marked alone (see [`PeersMut::set_alone`]) keeps its demand and its order, its
    /// reindexes do not call this.
    fn reshare(&mut self, slot: u32, moved: bool, streams: &mut impl PeersMut);

    /// Returns whether the plug holds the stream in `slot` as a peer of the split.
    fn is_peer(&self, slot: u32) -> bool;

    /// Returns what [`split`](Self::split) would give `asker` of `left` free bytes of the staging
    /// budget, counting it among the peers of its bucket whether or not it is on the demand list,
    /// as a stream offering bytes has demand.
    fn allowance(&self, asker: Peer, left: u64, streams: &impl Peers) -> u64;

    /// Splits `left` free bytes of the staging budget among the streams on the demand list. Calls
    /// `f` in wire order with each stream's slot, its [`Peer`], its allowance and its share, the
    /// most the split would give it, which caps its low-water mark. Each allowance is at most
    /// `left`. A sequential bucket's allowances add up to at most what reaches it; an incremental
    /// bucket's may add up to more, but only by what its peers hold beyond an equal part of what
    /// reaches it and what they hold, so the split stays within the staging budget. Once `left`
    /// runs out, the streams after it may be left out.
    fn split(&mut self, left: u64, streams: &impl Peers, f: impl FnMut(u32, Peer, u64, u64));

    /// Returns what the plug keeps about the stream in `slot`, for the empty-attempt digest of
    /// debug builds.
    fn digest(&self, _slot: u32) -> Option<impl fmt::Debug> {
        None::<()>
    }

    /// Checks the plug's record of the open stream `stream`, in `slot`, whose alone mark is
    /// `alone`.
    #[cfg(test)]
    fn assert_stream(&self, slot: u32, alone: bool, stream: Peer);

    /// Checks the plug's own records and returns how many streams it holds as peers of the split.
    #[cfg(test)]
    fn assert_consistent(&self) -> usize;
}

/// A connection's open streams as a prioritizer reads them, by slab slot.
pub trait Peers {
    /// Returns the stream in `slot`, if it is open.
    fn peer(&self, slot: u32) -> Option<Peer>;
}

/// [`Peers`] whose alone marks a [`Prioritizer::reshare`] may set.
pub trait PeersMut: Peers {
    /// Marks the open stream in `slot` alone, or clears its mark. A change of the stream's order
    /// clears the mark too.
    fn set_alone(&mut self, slot: u32, alone: bool);
}

/// A stream as a prioritizer reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The stream ID.
    pub id: StreamId,
    /// The stream's place in the wire order.
    pub order: SendOrder,
    /// Whether the stream is on the demand list, whose streams share the staging budget: its
    /// send half takes new bytes, and it is pull-ready, has staged bytes or keeps an undelivered
    /// `Writable` edge.
    pub demand: bool,
    /// Whether its producer is pull-ready.
    pub pull: bool,
    /// What the split reads of its send half.
    pub figures: Figures,
}

/// What the staging split reads of a stream's send half; zero for a stream without one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Figures {
    /// The bytes it may stage now: its stream credit beyond its staged bytes, up to the
    /// per-stream cap on staged bytes, or zero once the FIN is staged.
    pub room: u64,
    /// Its stream credit beyond its staged bytes, or zero once the FIN is staged.
    pub credit: u64,
    /// Its staged bytes.
    pub staged: u64,
}

/// A plug for tests: `P` with every urgency mirrored, `u` read as `7 - u`, on each [`SendOrder`]
/// that goes into `P` and back on each that comes out of it, for the wire order and the split
/// alike. Its wire order and split are `P`'s with the urgencies reversed, so a test can tell
/// whether a connection's streams follow their plug. Urgencies above 7 count as 7, so tests give
/// it urgencies 0 to 7.
#[cfg(test)]
pub(crate) struct MirroredUrgency<P>(P);

/// Returns `order` with its urgency mirrored, as [`MirroredUrgency`] reads it.
#[cfg(test)]
fn mirror(order: SendOrder) -> SendOrder {
    SendOrder {
        urgency: 7 - order.urgency.min(7),
        ..order
    }
}

/// Returns `peer` with its urgency mirrored.
#[cfg(test)]
fn mirror_peer(peer: Peer) -> Peer {
    Peer {
        order: mirror(peer.order),
        ..peer
    }
}

/// The streams of a [`MirroredUrgency`] plug as its inner plug reads them, with every urgency
/// mirrored.
#[cfg(test)]
struct Mirrored<'a, V: ?Sized>(&'a V);

#[cfg(test)]
impl<V: Peers + ?Sized> Peers for Mirrored<'_, V> {
    fn peer(&self, slot: u32) -> Option<Peer> {
        self.0.peer(slot).map(mirror_peer)
    }
}

/// [`Mirrored`] streams that take alone marks.
#[cfg(test)]
struct MirroredMut<'a, V: ?Sized>(&'a mut V);

#[cfg(test)]
impl<V: Peers + ?Sized> Peers for MirroredMut<'_, V> {
    fn peer(&self, slot: u32) -> Option<Peer> {
        self.0.peer(slot).map(mirror_peer)
    }
}

#[cfg(test)]
impl<V: PeersMut + ?Sized> PeersMut for MirroredMut<'_, V> {
    fn set_alone(&mut self, slot: u32, alone: bool) {
        self.0.set_alone(slot, alone);
    }
}

#[cfg(test)]
impl<P: Prioritizer> Prioritizer for MirroredUrgency<P> {
    type Cursor = P::Cursor;

    fn new(quantum: u64) -> Self {
        MirroredUrgency(P::new(quantum))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn insert(&mut self, slot: u32, id: StreamId, order: SendOrder) -> bool {
        self.0.insert(slot, id, mirror(order))
    }

    fn remove(&mut self, slot: u32) -> bool {
        self.0.remove(slot)
    }

    fn forget(&mut self, slot: u32) {
        self.0.forget(slot);
    }

    fn order(&self, slot: u32) -> Option<SendOrder> {
        self.0.order(slot).map(mirror)
    }

    fn next(&self, cursor: &mut P::Cursor) -> Option<u32> {
        self.0.next(cursor)
    }

    fn commit(&mut self, slot: u32, id: StreamId, bytes: u64, streams: &impl Peers) {
        self.0.commit(slot, id, bytes, &Mirrored(streams));
    }

    fn reshare(&mut self, slot: u32, moved: bool, streams: &mut impl PeersMut) {
        self.0.reshare(slot, moved, &mut MirroredMut(streams));
    }

    fn is_peer(&self, slot: u32) -> bool {
        self.0.is_peer(slot)
    }

    fn allowance(&self, asker: Peer, left: u64, streams: &impl Peers) -> u64 {
        self.0
            .allowance(mirror_peer(asker), left, &Mirrored(streams))
    }

    fn split(&mut self, left: u64, streams: &impl Peers, mut f: impl FnMut(u32, Peer, u64, u64)) {
        self.0
            .split(left, &Mirrored(streams), |slot, peer, allowance, share| {
                f(slot, mirror_peer(peer), allowance, share);
            });
    }

    fn digest(&self, slot: u32) -> Option<impl fmt::Debug> {
        self.0.digest(slot)
    }

    fn assert_stream(&self, slot: u32, alone: bool, stream: Peer) {
        self.0.assert_stream(slot, alone, mirror_peer(stream));
    }

    fn assert_consistent(&self) -> usize {
        self.0.assert_consistent()
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_wire::Dir;
    use mvfstr_wire::Side;

    use super::*;
    use crate::Connection;
    use crate::Endpoint;
    use crate::streams::conn::StreamState;
    use crate::streams::scheduler::Scheduler;

    const QUANTUM: u64 = 1200;

    fn id(slot: u32) -> StreamId {
        StreamId::new(Side::Server, Dir::Uni, u64::from(slot)).unwrap()
    }

    fn order(class: u8, urgency: u8, incremental: bool, order: u128) -> SendOrder {
        SendOrder {
            class,
            urgency,
            incremental,
            order,
        }
    }

    /// A connection without open streams.
    struct NoStreams;

    impl Peers for NoStreams {
        fn peer(&self, _slot: u32) -> Option<Peer> {
            None
        }
    }

    /// One step applied to the plug through the trait and to the scheduler alike.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Insert(u32, SendOrder),
        Remove(u32),
        Forget(u32),
        Commit(u32, u64),
    }

    #[test]
    fn fair_share_is_the_default_plug_and_orders_streams_as_the_scheduler_does() {
        // Code that names the types without a plug gets the byte-fair one.
        let _: fn(Connection) -> Connection<FairShare> = |conn| conn;
        let _: fn(Endpoint) -> Endpoint<FairShare> = |endpoint| endpoint;
        let _: fn(StreamState) -> StreamState<FairShare> = |state| state;

        // Two sequential buckets and two incremental ones, with turns taken, a stream that leaves
        // and comes back with a commit made while it was away, a move, an insert that does not
        // change anything, and a stream gone for good.
        let steps = [
            Step::Insert(0, order(1, 3, false, 5)),
            Step::Insert(1, order(1, 3, false, 2)),
            Step::Insert(2, order(1, 3, true, 0)),
            Step::Insert(3, order(1, 3, true, 0)),
            Step::Insert(4, order(0, 0, false, 0)),
            Step::Insert(5, order(1, 5, true, 0)),
            Step::Insert(6, order(1, 3, true, 0)),
            Step::Commit(2, 1200),
            Step::Commit(3, 600),
            Step::Commit(6, 3000),
            Step::Commit(3, 600),
            Step::Remove(2),
            Step::Commit(2, 1200),
            Step::Commit(3, 1200),
            Step::Insert(2, order(1, 3, true, 0)),
            Step::Commit(0, 1200),
            Step::Insert(1, order(1, 3, false, 9)),
            Step::Insert(1, order(1, 3, false, 9)),
            Step::Insert(5, order(1, 2, true, 0)),
            Step::Commit(5, 1200),
            Step::Remove(4),
            Step::Forget(4),
            Step::Commit(4, 1200),
            Step::Remove(6),
            Step::Commit(6, 1200),
            Step::Insert(6, order(1, 3, true, 0)),
        ];
        let mut plug = <FairShare as Prioritizer>::new(QUANTUM);
        let mut scheduler = Scheduler::new(QUANTUM);
        for (at, step) in steps.into_iter().enumerate() {
            let (got, want) = match step {
                Step::Insert(slot, order) => (
                    plug.insert(slot, id(slot), order),
                    scheduler.insert(slot, id(slot), order),
                ),
                Step::Remove(slot) => (plug.remove(slot), scheduler.remove(slot)),
                Step::Forget(slot) => {
                    plug.forget(slot);
                    scheduler.forget(slot);
                    (true, true)
                }
                Step::Commit(slot, bytes) => {
                    plug.commit(slot, id(slot), bytes, &NoStreams);
                    scheduler.commit(slot, id(slot), bytes);
                    (true, true)
                }
            };
            assert_eq!(got, want, "step {at}, {step:?}");
            assert_eq!(
                plug.iter().collect::<Vec<_>>(),
                scheduler.iter().collect::<Vec<_>>(),
                "the wire order after step {at}, {step:?}"
            );
            assert_eq!(plug.len(), scheduler.len(), "streams after step {at}");
            for slot in 0..7 {
                assert_eq!(
                    plug.order(slot),
                    scheduler.order(slot),
                    "order of slot {slot} after step {at}"
                );
            }
        }
    }
}
