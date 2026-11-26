/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The byte-fair plug: the [`Scheduler`]'s wire order and a split of the staging budget kept in
//! the [`Shares`].
//!
//! The split goes by bucket in wire order, each bucket taking from what the budget has left. A
//! sequential bucket's streams take their rooms in turn; an incremental bucket's peers are each
//! entitled to an equal part of what reaches the bucket and what they hold, and take their rooms
//! up to that. Each sequential bucket ahead of a stream costs one step, read from its totals, each
//! incremental one O(log n), and the rooms ahead of a sequential stream in its own bucket
//! O(log n).
//!
//! The plug does not record what a bucket's only peer holds or where it stands. It marks that
//! stream alone, so the stream's reindexes skip [`reshare`](Prioritizer::reshare) while it keeps
//! its demand; the split reads both from the stream, and the plug records them once another
//! stream joins the bucket.

use mvfstr_wire::StreamId;

use super::prioritizer::Peer;
use super::prioritizer::Peers;
use super::prioritizer::PeersMut;
use super::prioritizer::Prioritizer;
use super::scheduler::Cursor;
use super::scheduler::Scheduler;
use super::scheduler::SendOrder;
use super::share;
use super::share::Bucket;
use super::share::Holding;
use super::share::Place;
use super::share::Shares;
use super::share::Standing;
use super::share::entitlement;
use super::share::holding;
use super::share::incremental_allowance;
use super::share::share_key;

/// The byte-fair plug: the [`Scheduler`]'s wire order, where incremental streams take turns by
/// the bytes they have been served, and a max-min fair split of the staging budget in that order.
pub struct FairShare {
    scheduler: Scheduler,
    /// The streams on the demand list, by bucket of the split.
    shares: Shares,
}

impl FairShare {
    /// Returns the wire scheduler.
    #[cfg(test)]
    pub(crate) fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Returns the streams with demand by bucket of the split.
    #[cfg(test)]
    pub(crate) fn shares(&self) -> &Shares {
        &self.shares
    }

    /// Brings the incremental buckets of the shares up to the scheduler's turns, which listing
    /// their peers in the wire order requires.
    pub(crate) fn settle(&mut self) {
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

    /// Returns `stream`, in `slot`, as a peer of its bucket of the split.
    fn record(&self, slot: u32, stream: Peer) -> share::Peer {
        share::Peer {
            key: share_key(stream.order),
            id: stream.id.into_inner(),
            place: self.place(slot, stream.id, stream.order),
            holding: holding(stream.figures),
        }
    }

    /// Records the place of the stream in `slot`, a peer among others, in the shares.
    #[inline(never)]
    fn replace(&mut self, slot: u32, streams: &impl Peers) {
        if let Some(stream) = streams.peer(slot) {
            let place = self.place(slot, stream.id, stream.order);
            self.shares.replace(slot, place);
        }
    }

    /// Returns what the peers of `bucket` hold, read from the stream for a lone peer, which the
    /// shares do not follow.
    fn held(&self, bucket: &Bucket, streams: &impl Peers) -> Holding {
        match bucket.lone() {
            Some(slot) => streams
                .peer(slot)
                .map_or_else(Holding::default, |stream| holding(stream.figures)),
            None => Holding {
                room: bucket.room(),
                staged: bucket.staged(),
            },
        }
    }

    /// Returns the sum of the rooms of the peers of sequential `bucket` ahead of a stream at
    /// `order` with ID `id`.
    fn room_before(&self, bucket: &Bucket, order: u128, id: StreamId, streams: &impl Peers) -> u64 {
        let Some(lone) = bucket.lone().and_then(|slot| streams.peer(slot)) else {
            return self
                .shares
                .room_before(bucket.key(), order, id.into_inner());
        };
        if (lone.order.order, lone.id.into_inner()) < (order, id.into_inner()) {
            lone.figures.room
        } else {
            0
        }
    }

    /// Returns what the peers of `bucket` take of the `left` bytes that reach it: the sum of the
    /// allowances [`split`](Prioritizer::split) computes for them, up to `left`. An incremental
    /// allowance is also capped at `left`, which changes the sum only when the sum reaches `left`
    /// anyway.
    fn bucket_takes(&self, bucket: &Bucket, left: u64, streams: &impl Peers) -> u64 {
        let held = self.held(bucket, streams);
        if !bucket.key().2 {
            return held.room.min(left);
        }
        let entitled = entitlement(left, held.staged, bucket.peers());
        if bucket.lone().is_some() {
            return incremental_allowance(held, entitled, left);
        }
        self.shares.takes(bucket, entitled).min(left)
    }
}

impl Prioritizer for FairShare {
    type Cursor = Cursor;

    fn new(quantum: u64) -> Self {
        FairShare {
            scheduler: Scheduler::new(quantum),
            shares: Shares::new(),
        }
    }

    fn len(&self) -> usize {
        self.scheduler.len()
    }

    fn insert(&mut self, slot: u32, id: StreamId, order: SendOrder) -> bool {
        self.scheduler.insert(slot, id, order)
    }

    fn remove(&mut self, slot: u32) -> bool {
        self.scheduler.remove(slot)
    }

    fn forget(&mut self, slot: u32) {
        self.scheduler.forget(slot);
    }

    fn order(&self, slot: u32) -> Option<SendOrder> {
        self.scheduler.order(slot)
    }

    fn next(&self, cursor: &mut Cursor) -> Option<u32> {
        self.scheduler.next(cursor)
    }

    /// Rotates the scheduler (see [`Scheduler::commit`]). The commit may move incremental
    /// streams' places, which the shares follow for peers that are not alone in their buckets;
    /// what they hold has not changed since their guards last reindexed them.
    fn commit(&mut self, slot: u32, id: StreamId, bytes: u64, streams: &impl Peers) {
        let moved = self.scheduler.commit(slot, id, bytes);
        // Every guard is closed here, so the shares record each stream's bucket as it stands.
        if moved.committed && self.shares.among(slot) {
            self.replace(slot, streams);
        }
        if let Some(raised) = moved.raised
            && self.shares.among(raised)
        {
            self.replace(raised, streams);
        }
    }

    /// Records the stream in `slot` in the shares as it stands, unless it is alone in its bucket:
    /// a lone peer's record is brought up to date only when another stream joins it, and its guard
    /// skips this while it stays alone with demand. An incremental stream that stays a peer of its
    /// bucket keeps its recorded place unless `moved` is set, which means that the scheduler has
    /// just scheduled, moved or unscheduled it. Its place changes otherwise only with a commit,
    /// which refreshes the place, or with its bucket's turn passing it, which the next split
    /// catches up with.
    #[inline(never)]
    fn reshare(&mut self, slot: u32, moved: bool, streams: &mut impl PeersMut) {
        #[cfg(test)]
        super::guard::census::count(|c| c.reshares += 1);
        let stream = streams.peer(slot).filter(|stream| stream.demand);
        if let Some(stream) = stream {
            match self.shares.standing(slot, share_key(stream.order)) {
                Standing::Alone => {
                    streams.set_alone(slot, true);
                    return;
                }
                Standing::Among if !moved && stream.order.incremental => {
                    self.shares.hold(slot, holding(stream.figures));
                    return;
                }
                Standing::Among | Standing::Out => {}
            }
        }
        let peer = stream.map(|stream| self.record(slot, stream));
        let regrouped = self.shares.update(slot, peer);
        streams.set_alone(slot, self.shares.alone(slot));
        if let Some(left) = regrouped.left {
            streams.set_alone(left, true);
        }
        if let Some(joined) = regrouped.joined
            && let Some(stream) = streams.peer(joined)
        {
            let peer = stream.demand.then(|| self.record(joined, stream));
            self.shares.update(joined, peer);
            streams.set_alone(joined, false);
        }
    }

    fn is_peer(&self, slot: u32) -> bool {
        self.shares.alone(slot) || self.shares.among(slot)
    }

    fn allowance(&self, asker: Peer, left: u64, streams: &impl Peers) -> u64 {
        let (order, key) = (asker.order, share_key(asker.order));
        let shares = &self.shares;
        let mut left = left;
        for ahead in shares.buckets().take_while(|b| b.key() < key) {
            if left == 0 {
                break;
            }
            left = left.saturating_sub(self.bucket_takes(ahead, left, streams));
        }
        let bucket = shares.bucket(key);
        let (peers, held) = bucket.map_or((0, 0), |b| (b.peers(), self.held(b, streams).staged));
        let figures = asker.figures;
        if key.2 {
            let (peers, held) = if asker.demand {
                (peers, held)
            } else {
                (peers + 1, held.saturating_add(figures.staged))
            };
            incremental_allowance(holding(figures), entitlement(left, held, peers), left)
        } else {
            let ahead = bucket.map_or(0, |b| self.room_before(b, order.order, asker.id, streams));
            figures.room.min(left.saturating_sub(ahead))
        }
    }

    /// Splits `left` by bucket in wire order. A sequential bucket's streams take their rooms in
    /// turn from what is left, and its share for each is what is left when its turn comes. An
    /// incremental bucket's peers are each entitled to an equal part of what reaches the bucket
    /// and what they hold, which is their share, and take their rooms up to that. Each takes at
    /// most what reaches the bucket, but when one peer holds more than its share, the others may
    /// together take more than reaches it. Once `left` runs out, the rest of a sequential bucket
    /// and the buckets after it are left out.
    fn split(&mut self, left: u64, streams: &impl Peers, mut f: impl FnMut(u32, Peer, u64, u64)) {
        self.settle();
        let shares = &self.shares;
        let mut left = left;
        for bucket in shares.buckets() {
            if left == 0 {
                break;
            }
            // What reaches an incremental bucket is split before any of it is taken.
            let (reaching, incremental) = (left, bucket.key().2);
            let entitled = entitlement(reaching, self.held(bucket, streams).staged, bucket.peers());
            for slot in shares.members(bucket) {
                if left == 0 && !incremental {
                    break;
                }
                let Some(stream) = streams.peer(slot) else {
                    continue;
                };
                let figures = stream.figures;
                let (allowance, share) = if incremental {
                    let allowance = incremental_allowance(holding(figures), entitled, reaching);
                    (allowance, entitled)
                } else {
                    (figures.room.min(left), left)
                };
                left = left.saturating_sub(allowance);
                f(slot, stream, allowance, share);
            }
        }
    }

    #[cfg(debug_assertions)]
    fn digest(&self, slot: u32) -> Option<impl std::fmt::Debug> {
        self.scheduler.digest(slot)
    }

    #[cfg(test)]
    fn assert_stream(&self, slot: u32, alone: bool, stream: Peer) {
        let id = stream.id;
        assert_eq!(
            alone,
            self.shares.alone(slot),
            "stream {id} alone in its bucket"
        );
        let peer = stream.demand.then(|| self.record(slot, stream));
        let recorded = self.shares.recorded(slot).map(|mut recorded| {
            if let Some(peer) = peer
                && let Some(bucket) = self.shares.bucket(recorded.key)
                && bucket.lone() == Some(slot)
            {
                // What a lone peer holds and where it stands are not recorded.
                (recorded.place, recorded.holding) = (peer.place, peer.holding);
            }
            // A place behind its bucket's turn stays recorded until the next settle moves it
            // among the unplaced peers, where the scheduler already puts it.
            if let Place::Placed { turn, .. } = recorded.place
                && turn < self.scheduler.turn(stream.order)
            {
                recorded.place = Place::Unplaced;
            }
            recorded
        });
        assert_eq!(recorded, peer, "share of stream {id}");
    }

    #[cfg(test)]
    fn assert_consistent(&self) -> usize {
        self.shares.assert_consistent()
    }
}
