/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shares of the staging budget: the streams with demand, grouped into the buckets of the
//! split in the wire order.
//!
//! Each bucket's totals (peers, staged bytes, room) are kept as the streams change, so that a
//! stream's allowance costs a step per sequential bucket ahead of it and O(log n) per incremental
//! one, rather than a walk over every stream with demand. The stream guard updates a stream's
//! entry each time it reindexes it, except while the stream stays its bucket's only peer.
//!
//! A sequential bucket keeps its peers in a treap keyed by `(order, stream ID)` whose nodes sum
//! the rooms below them, so the rooms ahead of a place cost O(log n). An incremental bucket keeps
//! the peers the scheduler has a place for in a treap keyed by `(turn, ticket)`, and the others,
//! which the scheduler would place on the bucket's turn behind every stream on it, in a treap
//! keyed by stream ID; a walk lists them in the scheduler's order without sorting. An incremental
//! peer entitled to `e` bytes takes the part of `[staged, staged + room]` below `e`, so the
//! bucket also keeps its peers in two treaps summing those ends, which give what the whole bucket
//! takes in O(log n).
//!
//! The guard does not record what a bucket's only peer holds or where it stands, which saves an
//! update each time it reindexes that stream: readers take both from the stream, and the guard
//! brings the peer's record up to date when another stream joins the bucket.

use super::scheduler::SendOrder;

/// A bucket of the split: class, urgency, and whether its streams are incremental. Buckets go in
/// this order on the wire, a `(class, urgency)` bucket's sequential streams before its
/// incremental ones.
pub(crate) type ShareKey = (u8, u8, bool);

/// Returns the [`ShareKey`] of a stream at `order`.
pub(crate) fn share_key(order: SendOrder) -> ShareKey {
    (order.class, order.urgency.min(7), order.incremental)
}

/// What a stream with demand holds of the split.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Holding {
    /// The bytes it may stage now.
    pub(crate) room: u64,
    /// Its staged bytes.
    pub(crate) staged: u64,
}

/// Where a stream with demand stands in its bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// A sequential stream at this `order`, then by stream ID.
    Sequential(u128),
    /// An incremental stream at its own place in the scheduler.
    Placed { turn: u64, ticket: u64 },
    /// An incremental stream the scheduler would place on its bucket's turn, behind every stream
    /// on that turn, by stream ID.
    Unplaced,
}

/// A stream with demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) key: ShareKey,
    /// The stream ID.
    pub(crate) id: u64,
    pub(crate) place: Place,
    pub(crate) holding: Holding,
}

/// How the shares record a stream, from [`Shares::standing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// A stream that is not a peer of the given bucket.
    Out,
    /// The only peer of the bucket.
    Alone,
    /// A peer of the bucket among others.
    Among,
}

/// The peers an [`update`](Shares::update) regrouped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Regrouped {
    /// The peer that was alone in the bucket the stream joined.
    pub(crate) joined: Option<u32>,
    /// The peer the stream left alone in the bucket it left.
    pub(crate) left: Option<u32>,
}

/// The index that marks a missing slot or bucket.
const NIL: u32 = u32::MAX;

/// A bucket's order treap of sequential or placed peers.
const PLACED: usize = 0;

/// An incremental bucket's order treap of unplaced peers.
const UNPLACED: usize = 1;

impl Place {
    /// Returns the order treap a peer with ID `id` at this place sits in, and its key there.
    fn slot_key(self, id: u64) -> (usize, (u128, u64)) {
        match self {
            Place::Sequential(order) => (PLACED, (order, id)),
            Place::Placed { turn, ticket } => (PLACED, (u128::from(turn), ticket)),
            Place::Unplaced => (UNPLACED, (u128::from(id), 0)),
        }
    }
}

/// A slot's node in a family of [`Treaps`].
#[derive(Clone, Copy)]
struct Node<K> {
    key: K,
    /// What the node adds to the sums.
    weight: u64,
    /// The number of nodes in its subtree.
    count: u32,
    /// The sum of the weights in its subtree.
    sum: u64,
    left: u32,
    right: u32,
    parent: u32,
    priority: u32,
}

/// Treaps whose nodes are slots, each slot in at most one of them, that count and sum the weights
/// of every subtree. Their roots are kept by the caller.
struct Treaps<K> {
    nodes: Vec<Node<K>>,
    /// The state of the generator of priorities.
    rng: u32,
}

impl<K: Copy + Default + Ord> Treaps<K> {
    fn new() -> Self {
        Treaps {
            nodes: Vec::new(),
            rng: 0x2545_f491,
        }
    }

    fn key(&self, slot: u32) -> K {
        self.nodes[slot as usize].key
    }

    /// Returns the number of nodes and the sum of the weights of the subtree at `slot`, which may
    /// be [`NIL`].
    fn totals(&self, slot: u32) -> (u64, u64) {
        if slot == NIL {
            return (0, 0);
        }
        let node = &self.nodes[slot as usize];
        (u64::from(node.count), node.sum)
    }

    /// Returns the number of nodes of the treap at `root` with keys below `key`, and the sum of
    /// their weights.
    fn below(&self, root: u32, key: K) -> (u64, u64) {
        let (mut count, mut sum, mut cur) = (0, 0, root);
        while cur != NIL {
            let node = &self.nodes[cur as usize];
            if node.key < key {
                let (n, s) = self.totals(node.left);
                count += n + 1;
                sum += s + node.weight;
                cur = node.right;
            } else {
                cur = node.left;
            }
        }
        (count, sum)
    }

    /// Inserts `slot`, which is not in a treap, into the treap at `root` with `key` and `weight`.
    fn insert(&mut self, root: &mut u32, slot: u32, key: K, weight: u64) {
        let at = slot as usize;
        if at >= self.nodes.len() {
            let out = Node {
                key: K::default(),
                weight: 0,
                count: 0,
                sum: 0,
                left: NIL,
                right: NIL,
                parent: NIL,
                priority: 0,
            };
            self.nodes.resize(at + 1, out);
        }
        let priority = self.next_priority();
        let (mut parent, mut cur, mut left) = (NIL, *root, false);
        while cur != NIL {
            let node = &mut self.nodes[cur as usize];
            node.count += 1;
            node.sum += weight;
            parent = cur;
            left = key < node.key;
            cur = if left { node.left } else { node.right };
        }
        self.nodes[at] = Node {
            key,
            weight,
            count: 1,
            sum: weight,
            left: NIL,
            right: NIL,
            parent,
            priority,
        };
        if parent == NIL {
            *root = slot;
        } else if left {
            self.nodes[parent as usize].left = slot;
        } else {
            self.nodes[parent as usize].right = slot;
        }
        loop {
            let parent = self.nodes[at].parent;
            if parent == NIL || self.nodes[parent as usize].priority <= priority {
                break;
            }
            self.rotate_up(root, slot);
        }
    }

    /// Takes `slot` out of the treap at `root`.
    fn remove(&mut self, root: &mut u32, slot: u32) {
        loop {
            let Node { left, right, .. } = self.nodes[slot as usize];
            if left == NIL || right == NIL {
                let child = if left != NIL { left } else { right };
                let parent = self.nodes[slot as usize].parent;
                if child != NIL {
                    self.nodes[child as usize].parent = parent;
                }
                if parent == NIL {
                    *root = child;
                } else if self.nodes[parent as usize].left == slot {
                    self.nodes[parent as usize].left = child;
                } else {
                    self.nodes[parent as usize].right = child;
                }
                let weight = self.nodes[slot as usize].weight;
                let mut at = parent;
                while at != NIL {
                    let node = &mut self.nodes[at as usize];
                    node.count -= 1;
                    node.sum -= weight;
                    at = node.parent;
                }
                let node = &mut self.nodes[slot as usize];
                (node.left, node.right, node.parent) = (NIL, NIL, NIL);
                return;
            }
            let up = if self.nodes[left as usize].priority < self.nodes[right as usize].priority {
                left
            } else {
                right
            };
            self.rotate_up(root, up);
        }
    }

    /// Gives `slot`, in a treap, a new `weight`.
    fn reweigh(&mut self, slot: u32, weight: u64) {
        let old = std::mem::replace(&mut self.nodes[slot as usize].weight, weight);
        let mut at = slot;
        while at != NIL {
            let node = &mut self.nodes[at as usize];
            node.sum = node.sum - old + weight;
            at = node.parent;
        }
    }

    /// Moves `slot`, in the treap at `root`, to `key` with `weight`.
    fn rekey(&mut self, root: &mut u32, slot: u32, key: K, weight: u64) {
        let node = &mut self.nodes[slot as usize];
        if *root == slot && node.left == NIL && node.right == NIL {
            // The only node of its treap: rekeying it cannot break the order.
            (node.key, node.weight, node.sum) = (key, weight, weight);
            return;
        }
        self.remove(root, slot);
        self.insert(root, slot, key, weight);
    }

    /// Returns the first node of the subtree at `slot`, or [`NIL`].
    fn leftmost(&self, mut slot: u32) -> u32 {
        if slot == NIL {
            return NIL;
        }
        while self.nodes[slot as usize].left != NIL {
            slot = self.nodes[slot as usize].left;
        }
        slot
    }

    /// Returns the in-order successor of `slot` in its treap, or [`NIL`].
    fn successor(&self, mut slot: u32) -> u32 {
        let right = self.nodes[slot as usize].right;
        if right != NIL {
            return self.leftmost(right);
        }
        loop {
            let parent = self.nodes[slot as usize].parent;
            if parent == NIL || self.nodes[parent as usize].left == slot {
                return parent;
            }
            slot = parent;
        }
    }

    /// Returns the next value of a xorshift sequence: treap priorities need only be well spread,
    /// not unpredictable.
    fn next_priority(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    /// Recomputes the count and sum of `slot` from its children.
    fn retotal(&mut self, slot: u32) {
        let node = self.nodes[slot as usize];
        let (left, right) = (self.totals(node.left), self.totals(node.right));
        let node = &mut self.nodes[slot as usize];
        // Invariant: a subtree's count is at most the number of slots, which are u32.
        node.count = (1 + left.0 + right.0) as u32;
        node.sum = node.weight + left.1 + right.1;
    }

    /// Rotates `x` above its parent in the treap at `root`, keeping the in-order sequence, the
    /// counts and the sums.
    fn rotate_up(&mut self, root: &mut u32, x: u32) {
        let p = self.nodes[x as usize].parent;
        let g = self.nodes[p as usize].parent;
        if self.nodes[p as usize].left == x {
            let b = self.nodes[x as usize].right;
            self.nodes[p as usize].left = b;
            if b != NIL {
                self.nodes[b as usize].parent = p;
            }
            self.nodes[x as usize].right = p;
        } else {
            let b = self.nodes[x as usize].left;
            self.nodes[p as usize].right = b;
            if b != NIL {
                self.nodes[b as usize].parent = p;
            }
            self.nodes[x as usize].left = p;
        }
        self.nodes[p as usize].parent = x;
        self.nodes[x as usize].parent = g;
        if g == NIL {
            *root = x;
        } else if self.nodes[g as usize].left == p {
            self.nodes[g as usize].left = x;
        } else {
            self.nodes[g as usize].right = x;
        }
        self.retotal(p);
        self.retotal(x);
    }
}

/// A slot's stream as a peer of the split.
#[derive(Clone, Copy)]
struct Entry {
    /// The bucket the stream is a peer of, or [`NIL`].
    bucket: u32,
    /// The order treap it sits in: [`PLACED`] or [`UNPLACED`].
    tree: usize,
    id: u64,
    holding: Holding,
}

impl Entry {
    const OUT: Entry = Entry {
        bucket: NIL,
        tree: PLACED,
        id: 0,
        holding: Holding { room: 0, staged: 0 },
    };
}

/// A bucket of the split with its totals.
pub(crate) struct Bucket {
    key: ShareKey,
    peers: u32,
    staged: u64,
    room: u64,
    /// The roots of the order treaps, [`PLACED`] and [`UNPLACED`].
    order: [u32; 2],
    /// An incremental bucket's root of its peers by staged bytes.
    low: u32,
    /// An incremental bucket's root of its peers by staged bytes plus room.
    high: u32,
    /// The scheduler's turn for the bucket as of the last [`Shares::settle`].
    turn: u64,
}

impl Bucket {
    pub(crate) fn key(&self) -> ShareKey {
        self.key
    }

    /// Returns the number of peers.
    pub(crate) fn peers(&self) -> u64 {
        u64::from(self.peers)
    }

    /// Returns the peers' staged bytes.
    pub(crate) fn staged(&self) -> u64 {
        self.staged
    }

    /// Returns the sum of the peers' rooms.
    pub(crate) fn room(&self) -> u64 {
        self.room
    }

    /// Returns the slot of the bucket's only peer, if it has exactly one.
    pub(crate) fn lone(&self) -> Option<u32> {
        if self.peers != 1 {
            return None;
        }
        Some(if self.order[PLACED] != NIL {
            self.order[PLACED]
        } else {
            self.order[UNPLACED]
        })
    }
}

/// The streams with demand by bucket, indexed by slab slot.
pub(crate) struct Shares {
    entries: Vec<Entry>,
    /// Peers by their place in their bucket, a sequential one weighing its room and an
    /// incremental one zero.
    order: Treaps<(u128, u64)>,
    /// Incremental peers by `(staged, slot)`, weighing their staged bytes.
    low: Treaps<(u64, u32)>,
    /// Incremental peers by `(staged + room, slot)`, weighing their staged bytes plus room.
    high: Treaps<(u64, u32)>,
    /// Buckets in creation order; never removed.
    buckets: Vec<Bucket>,
    /// `(bucket key, position in buckets)`, sorted by key.
    index: Vec<(ShareKey, u32)>,
}

impl Shares {
    pub(crate) fn new() -> Self {
        Shares {
            entries: Vec::new(),
            order: Treaps::new(),
            low: Treaps::new(),
            high: Treaps::new(),
            buckets: Vec::new(),
            index: Vec::new(),
        }
    }

    /// Records that the stream in `slot` is `peer`, or with `None` that it does not have demand,
    /// and returns the peers this regrouped.
    pub(crate) fn update(&mut self, slot: u32, peer: Option<Peer>) -> Regrouped {
        let at = slot as usize;
        if at >= self.entries.len() {
            if peer.is_none() {
                return Regrouped::default();
            }
            self.entries.resize(at + 1, Entry::OUT);
        }
        let entry = self.entries[at];
        let mut regrouped = Regrouped::default();
        let stays = entry.bucket != NIL
            && peer.is_some_and(|p| self.buckets[entry.bucket as usize].key == p.key);
        if entry.bucket != NIL && !stays {
            self.leave(slot);
            regrouped.left = self.buckets[entry.bucket as usize].lone();
        }
        let Some(peer) = peer else {
            return regrouped;
        };
        if !stays {
            let bucket = self.bucket_of(peer.key);
            regrouped.joined = self.buckets[bucket as usize].lone();
            self.join(slot, bucket, peer);
            return regrouped;
        }
        let (tree, key) = peer.place.slot_key(peer.id);
        if entry.tree != tree || self.order.key(slot) != key {
            self.shift(slot, tree, key);
        }
        self.hold(slot, peer.holding);
        regrouped
    }

    /// Returns how the stream in `slot` stands as a peer of bucket `key`.
    pub(crate) fn standing(&self, slot: u32, key: ShareKey) -> Standing {
        match self.bucket_of_slot(slot) {
            Some(b) if b.key == key && b.peers == 1 => Standing::Alone,
            Some(b) if b.key == key => Standing::Among,
            _ => Standing::Out,
        }
    }

    /// Returns whether the stream in `slot` is the only peer of its bucket.
    pub(crate) fn alone(&self, slot: u32) -> bool {
        self.bucket_of_slot(slot).is_some_and(|b| b.peers == 1)
    }

    /// Returns whether the stream in `slot` is a peer of a bucket with other peers.
    pub(crate) fn among(&self, slot: u32) -> bool {
        self.bucket_of_slot(slot).is_some_and(|b| b.peers > 1)
    }

    /// Records that the peer in `slot` stands at `place` now and holds what it held.
    pub(crate) fn replace(&mut self, slot: u32, place: Place) {
        let entry = &self.entries[slot as usize];
        let (tree, at) = place.slot_key(entry.id);
        if entry.tree != tree || self.order.key(slot) != at {
            self.shift(slot, tree, at);
        }
    }

    /// Returns the bucket with key `key`, if a stream was ever a peer of it.
    pub(crate) fn bucket(&self, key: ShareKey) -> Option<&Bucket> {
        let at = self.index.binary_search_by_key(&key, |&(k, _)| k).ok()?;
        Some(&self.buckets[self.index[at].1 as usize])
    }

    /// Iterates over the buckets with peers, in the wire order.
    pub(crate) fn buckets(&self) -> impl Iterator<Item = &Bucket> {
        self.index
            .iter()
            .map(|&(_, at)| &self.buckets[at as usize])
            .filter(|b| b.peers > 0)
    }

    /// Takes each incremental bucket's turn from `turn`: the turn the scheduler places streams on
    /// that join the bucket (see [`Scheduler::place`](super::scheduler::Scheduler::place)).
    /// A placed peer behind the new turn would no longer resume its place, so it joins the
    /// unplaced ones.
    pub(crate) fn settle(&mut self, turn: impl Fn(ShareKey) -> u64) {
        for b in &mut self.buckets {
            if !b.key.2 || b.peers == 0 {
                continue;
            }
            b.turn = turn(b.key);
            let turn = u128::from(b.turn);
            loop {
                let first = self.order.leftmost(b.order[PLACED]);
                if first == NIL || self.order.key(first).0 >= turn {
                    break;
                }
                self.order.remove(&mut b.order[PLACED], first);
                let entry = &mut self.entries[first as usize];
                entry.tree = UNPLACED;
                let key = (u128::from(entry.id), 0);
                self.order.insert(&mut b.order[UNPLACED], first, key, 0);
            }
        }
    }

    /// Iterates over the slots of `bucket`'s peers in the wire order.
    pub(crate) fn members<'a>(&'a self, bucket: &'a Bucket) -> Members<'a> {
        Members {
            order: &self.order,
            turn: u128::from(bucket.turn),
            placed: self.order.leftmost(bucket.order[PLACED]),
            unplaced: self.order.leftmost(bucket.order[UNPLACED]),
        }
    }

    /// Returns the sum of the rooms of the peers of sequential bucket `key` ahead of a stream at
    /// `order` with ID `id`.
    pub(crate) fn room_before(&self, key: ShareKey, order: u128, id: u64) -> u64 {
        self.bucket(key)
            .map_or(0, |b| self.order.below(b.order[PLACED], (order, id)).1)
    }

    /// Returns what the peers of incremental `bucket` take when each is entitled to `entitled`
    /// bytes staged: the sum of their rooms, each up to what `entitled` leaves above its staged
    /// bytes.
    pub(crate) fn takes(&self, bucket: &Bucket, entitled: u64) -> u64 {
        // A peer takes the part of [staged, staged + room] below `entitled`: `entitled - staged`
        // for each peer starting below it, less `entitled - (staged + room)` for each whose room
        // ends below it.
        let (starting, starts) = self.low.below(bucket.low, (entitled, 0));
        let (ended, ends) = self.high.below(bucket.high, (entitled, 0));
        // A peer whose room ends below `entitled` starts below it, and `entitled` is at most the
        // end of the room of each peer that starts below it but does not end, so this arithmetic
        // does not overflow or go below zero.
        entitled * (starting - ended) + ends - starts
    }

    /// Returns the bucket the stream in `slot` is a peer of.
    fn bucket_of_slot(&self, slot: u32) -> Option<&Bucket> {
        // An entry outside every bucket holds `NIL`, past the last bucket.
        let entry = self.entries.get(slot as usize)?;
        self.buckets.get(entry.bucket as usize)
    }

    /// Returns the bucket for `key`, creating it on first use.
    fn bucket_of(&mut self, key: ShareKey) -> u32 {
        match self.index.binary_search_by_key(&key, |&(k, _)| k) {
            Ok(at) => self.index[at].1,
            Err(at) => {
                let bucket = self.buckets.len() as u32;
                self.buckets.push(Bucket {
                    key,
                    peers: 0,
                    staged: 0,
                    room: 0,
                    order: [NIL; 2],
                    low: NIL,
                    high: NIL,
                    turn: 0,
                });
                self.index.insert(at, (key, bucket));
                bucket
            }
        }
    }

    /// Adds the stream in `slot`, which is not a peer, to `bucket` as `peer`.
    fn join(&mut self, slot: u32, bucket: u32, peer: Peer) {
        let (tree, key) = peer.place.slot_key(peer.id);
        let h = peer.holding;
        self.entries[slot as usize] = Entry {
            bucket,
            tree,
            id: peer.id,
            holding: h,
        };
        let b = &mut self.buckets[bucket as usize];
        b.peers += 1;
        b.staged += h.staged;
        b.room += h.room;
        if !b.key.2 {
            self.order.insert(&mut b.order[tree], slot, key, h.room);
            return;
        }
        self.order.insert(&mut b.order[tree], slot, key, 0);
        self.low
            .insert(&mut b.low, slot, (h.staged, slot), h.staged);
        let end = h.staged + h.room;
        self.high.insert(&mut b.high, slot, (end, slot), end);
    }

    /// Takes the stream in `slot` out of its bucket.
    fn leave(&mut self, slot: u32) {
        let entry = std::mem::replace(&mut self.entries[slot as usize], Entry::OUT);
        let b = &mut self.buckets[entry.bucket as usize];
        b.peers -= 1;
        b.staged -= entry.holding.staged;
        b.room -= entry.holding.room;
        self.order.remove(&mut b.order[entry.tree], slot);
        if b.key.2 {
            self.low.remove(&mut b.low, slot);
            self.high.remove(&mut b.high, slot);
        }
    }

    /// Moves the peer in `slot` to `key` in order treap `tree` of its bucket.
    fn shift(&mut self, slot: u32, tree: usize, key: (u128, u64)) {
        #[cfg(test)]
        super::guard::census::count(|c| c.share_rekeys += 1);
        let entry = &mut self.entries[slot as usize];
        let b = &mut self.buckets[entry.bucket as usize];
        let weight = if b.key.2 { 0 } else { entry.holding.room };
        if entry.tree == tree {
            self.order.rekey(&mut b.order[tree], slot, key, weight);
            return;
        }
        self.order.remove(&mut b.order[entry.tree], slot);
        self.order.insert(&mut b.order[tree], slot, key, weight);
        entry.tree = tree;
    }

    /// Records that the peer in `slot` holds `holding` now and keeps its place.
    pub(crate) fn hold(&mut self, slot: u32, holding: Holding) {
        let entry = &mut self.entries[slot as usize];
        if entry.holding == holding {
            return;
        }
        let old = std::mem::replace(&mut entry.holding, holding);
        let b = &mut self.buckets[entry.bucket as usize];
        b.staged = b.staged - old.staged + holding.staged;
        b.room = b.room - old.room + holding.room;
        if !b.key.2 {
            if old.room != holding.room {
                self.order.reweigh(slot, holding.room);
            }
            return;
        }
        if old.staged != holding.staged {
            let staged = holding.staged;
            self.low.rekey(&mut b.low, slot, (staged, slot), staged);
        }
        let end = holding.staged + holding.room;
        if old.staged + old.room != end {
            self.high.rekey(&mut b.high, slot, (end, slot), end);
        }
    }
}

/// The slots of a bucket's peers in the wire order, from [`Shares::members`].
pub(crate) struct Members<'a> {
    order: &'a Treaps<(u128, u64)>,
    /// The bucket's turn.
    turn: u128,
    /// The next sequential or placed peer.
    placed: u32,
    /// The next unplaced peer.
    unplaced: u32,
}

impl Iterator for Members<'_> {
    type Item = u32;

    /// Returns the next slot: placed peers on the bucket's turn, then the unplaced ones, which the
    /// scheduler would place on that turn behind them, then placed peers on later turns.
    fn next(&mut self) -> Option<u32> {
        let placed_first = self.placed != NIL
            && (self.unplaced == NIL || self.order.key(self.placed).0 <= self.turn);
        let next = if placed_first {
            &mut self.placed
        } else {
            &mut self.unplaced
        };
        let at = *next;
        if at == NIL {
            return None;
        }
        *next = self.order.successor(at);
        Some(at)
    }
}

#[cfg(test)]
impl<K: Copy + Default + Ord> Treaps<K> {
    /// Checks the treap at `root`: its links, key and priority order, counts and sums. Returns
    /// its slots in order.
    fn check(&self, root: u32) -> Vec<u32> {
        let mut slots = Vec::new();
        self.check_below(root, NIL, &mut slots);
        assert!(
            slots.windows(2).all(|w| self.key(w[0]) < self.key(w[1])),
            "keys in order"
        );
        slots
    }

    fn check_below(&self, at: u32, parent: u32, slots: &mut Vec<u32>) -> (u64, u64) {
        if at == NIL {
            return (0, 0);
        }
        let node = self.nodes[at as usize];
        assert_eq!(node.parent, parent, "parent of {at}");
        if parent != NIL {
            assert!(
                self.nodes[parent as usize].priority <= node.priority,
                "priority of {at}"
            );
        }
        let left = self.check_below(node.left, at, slots);
        slots.push(at);
        let right = self.check_below(node.right, at, slots);
        let totals = (1 + left.0 + right.0, node.weight + left.1 + right.1);
        assert_eq!(self.totals(at), totals, "count and sum of {at}");
        totals
    }
}

#[cfg(test)]
impl Shares {
    /// Returns the peer recorded for the stream in `slot`, with its place as of the last update
    /// or settle.
    pub(crate) fn recorded(&self, slot: u32) -> Option<Peer> {
        let entry = self
            .entries
            .get(slot as usize)
            .filter(|e| e.bucket != NIL)?;
        let key = self.buckets[entry.bucket as usize].key;
        let (at, ticket) = self.order.key(slot);
        let place = match (key.2, entry.tree) {
            (false, _) => Place::Sequential(at),
            (true, PLACED) => Place::Placed {
                turn: at as u64,
                ticket,
            },
            (true, _) => Place::Unplaced,
        };
        Some(Peer {
            key,
            id: entry.id,
            place,
            holding: entry.holding,
        })
    }

    /// Checks every treap, and every bucket's totals and treaps against its peers' entries.
    /// Returns the number of peers.
    pub(crate) fn assert_consistent(&self) -> usize {
        assert!(
            self.index.windows(2).all(|w| w[0].0 < w[1].0),
            "the index is sorted"
        );
        let mut peers = 0;
        for (at, b) in self.buckets.iter().enumerate() {
            assert!(
                self.index.contains(&(b.key, at as u32)),
                "{:?} is indexed",
                b.key
            );
            let incremental = b.key.2;
            let trees = [
                self.order.check(b.order[PLACED]),
                self.order.check(b.order[UNPLACED]),
            ];
            assert!(incremental || trees[UNPLACED].is_empty(), "{:?}", b.key);
            let (mut staged, mut room) = (0, 0);
            for (tree, slots) in trees.iter().enumerate() {
                for &slot in slots {
                    let Entry {
                        bucket, holding, ..
                    } = self.entries[slot as usize];
                    assert_eq!(
                        (bucket, self.entries[slot as usize].tree),
                        (at as u32, tree),
                        "entry of {slot}"
                    );
                    staged += holding.staged;
                    room += holding.room;
                    let weight = if incremental { 0 } else { holding.room };
                    assert_eq!(self.order.nodes[slot as usize].weight, weight, "{slot}");
                    if incremental {
                        let (low, high) = (
                            &self.low.nodes[slot as usize],
                            &self.high.nodes[slot as usize],
                        );
                        let end = holding.staged + holding.room;
                        assert_eq!(
                            (low.key, low.weight),
                            ((holding.staged, slot), holding.staged),
                            "low of {slot}"
                        );
                        assert_eq!(
                            (high.key, high.weight),
                            ((end, slot), end),
                            "high of {slot}"
                        );
                    }
                }
            }
            let mut members = trees.concat();
            members.sort_unstable();
            let [mut low, mut high] = [self.low.check(b.low), self.high.check(b.high)];
            low.sort_unstable();
            high.sort_unstable();
            let ranked = if incremental { &members[..] } else { &[] };
            assert_eq!((&low[..], &high[..]), (ranked, ranked), "{:?}", b.key);
            assert_eq!(
                (b.peers(), b.staged, b.room),
                (members.len() as u64, staged, room),
                "totals of {:?}",
                b.key
            );
            peers += members.len();
        }
        let entries = self.entries.iter().filter(|e| e.bucket != NIL).count();
        assert_eq!(peers, entries, "every entry is in its bucket");
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestRng;

    const SEQ: ShareKey = (1, 3, false);
    const INC: ShareKey = (1, 3, true);

    fn peer(key: ShareKey, id: u64, place: Place, room: u64, staged: u64) -> Option<Peer> {
        Some(Peer {
            key,
            id,
            place,
            holding: Holding { room, staged },
        })
    }

    fn totals(s: &Shares, key: ShareKey) -> (u64, u64, u64) {
        let b = s.bucket(key).expect("the bucket exists");
        (b.peers(), b.staged(), b.room())
    }

    #[test]
    fn a_bucket_totals_what_its_peers_hold_as_they_change() {
        let mut s = Shares::new();
        s.update(0, peer(SEQ, 0, Place::Sequential(0), 100, 10));
        s.update(1, peer(SEQ, 4, Place::Sequential(0), 50, 0));
        s.update(2, peer(INC, 8, Place::Unplaced, 7, 3));
        assert_eq!(totals(&s, SEQ), (2, 10, 150));
        assert_eq!(totals(&s, INC), (1, 3, 7));
        // Staging moves room to staged bytes; a stream moving to another bucket leaves its old one.
        s.update(1, peer(SEQ, 4, Place::Sequential(0), 20, 30));
        s.update(0, peer(INC, 0, Place::Unplaced, 100, 10));
        assert_eq!(totals(&s, SEQ), (1, 30, 20));
        assert_eq!(totals(&s, INC), (2, 13, 107));
        s.update(2, None);
        s.update(2, None);
        assert_eq!(totals(&s, INC), (1, 10, 100), "a stream leaves once");
        s.update(1, None);
        assert_eq!(totals(&s, SEQ), (0, 0, 0), "an empty bucket stays");
    }

    #[test]
    fn a_stream_stands_out_of_a_bucket_alone_in_it_or_among_other_peers() {
        let mut s = Shares::new();
        assert_eq!(s.standing(0, INC), Standing::Out, "never a peer");
        s.update(0, peer(INC, 0, Place::Unplaced, 1, 0));
        assert_eq!(s.standing(0, INC), Standing::Alone);
        assert_eq!(s.standing(0, SEQ), Standing::Out, "another bucket");
        s.update(1, peer(INC, 1, Place::Unplaced, 1, 0));
        assert_eq!(s.standing(0, INC), Standing::Among);
        s.update(0, None);
        assert_eq!(s.standing(0, INC), Standing::Out, "left");
        assert_eq!(s.standing(1, INC), Standing::Alone, "alone again");
    }

    #[test]
    fn a_stream_joining_a_lone_peer_reports_it() {
        let mut s = Shares::new();
        let lone = |s: &Shares, key| s.bucket(key).and_then(Bucket::lone);
        let joined = |s: &mut Shares, slot, peer| s.update(slot, peer).joined;
        assert_eq!(
            joined(&mut s, 3, peer(INC, 3, placed(1, 0), 10, 0)),
            None,
            "a new bucket"
        );
        assert_eq!(lone(&s, INC), Some(3));
        assert_eq!(
            joined(&mut s, 3, peer(INC, 3, Place::Unplaced, 5, 5)),
            None,
            "the lone peer itself"
        );
        assert_eq!(lone(&s, INC), Some(3), "among the unplaced peers");
        assert_eq!(joined(&mut s, 1, peer(INC, 1, placed(2, 0), 1, 0)), Some(3));
        assert_eq!(lone(&s, INC), None, "two peers");
        assert_eq!(
            joined(&mut s, 2, peer(INC, 2, Place::Unplaced, 1, 0)),
            None,
            "two already"
        );
        s.update(1, None);
        s.update(3, None);
        assert_eq!(lone(&s, INC), Some(2), "alone again");
        s.update(0, peer(SEQ, 0, Place::Sequential(0), 1, 0));
        assert_eq!(lone(&s, SEQ), Some(0));
        assert_eq!(
            joined(&mut s, 0, peer(INC, 0, Place::Unplaced, 1, 0)),
            Some(2),
            "from another bucket"
        );
        assert_eq!(lone(&s, SEQ), None, "no peer");
    }

    #[test]
    fn a_stream_leaving_a_bucket_reports_the_peer_it_leaves_alone() {
        let mut s = Shares::new();
        let left = |s: &mut Shares, slot, peer| s.update(slot, peer).left;
        for slot in 0..3 {
            s.update(slot, peer(INC, u64::from(slot), Place::Unplaced, 1, 0));
        }
        assert_eq!(left(&mut s, 0, None), None, "two peers stay");
        assert_eq!(
            left(&mut s, 1, peer(INC, 1, placed(3, 0), 9, 9)),
            None,
            "a peer that stays in the bucket"
        );
        assert_eq!(
            left(&mut s, 1, peer(SEQ, 1, Place::Sequential(0), 1, 0)),
            Some(2)
        );
        assert_eq!(left(&mut s, 2, None), None, "the last peer");
        s.update(2, peer(INC, 2, Place::Unplaced, 1, 0));
        s.update(3, peer(SEQ, 3, Place::Sequential(0), 1, 0));
        assert_eq!(left(&mut s, 3, None), Some(1), "out of demand");
        assert_eq!(left(&mut s, 7, None), None, "never a peer");
    }

    #[test]
    fn a_sequential_bucket_sums_the_rooms_ahead_of_a_place() {
        let mut s = Shares::new();
        // Slot `i` holds a stream with room `10^i`, at the order and ID given.
        let places = [(2, 0), (0, 8), (1, 4), (0, 4), (2, 12), (1, 0), (0, 0)];
        for (slot, &(order, id)) in places.iter().enumerate() {
            let room = 10u64.pow(slot as u32);
            s.update(
                slot as u32,
                peer(SEQ, id, Place::Sequential(order), room, 0),
            );
        }
        s.update(9, peer(INC, 1, Place::Unplaced, 1 << 40, 0));
        // In the wire order: (0, 0) 10^6, (0, 4) 10^3, (0, 8) 10^1, (1, 0) 10^5, (1, 4) 10^2,
        // (2, 0) 10^0, (2, 12) 10^4.
        let before = |s: &Shares, order, id| s.room_before(SEQ, order, id);
        assert_eq!(before(&s, 0, 0), 0);
        assert_eq!(before(&s, 0, 2), 1_000_000, "a place between two peers");
        assert_eq!(before(&s, 0, 8), 1_001_000);
        assert_eq!(before(&s, 1, 4), 1_101_010);
        assert_eq!(before(&s, 2, 12), 1_101_111);
        assert_eq!(before(&s, 9, 0), 1_111_111, "every peer");
        // Rooms change and peers leave.
        s.update(3, peer(SEQ, 4, Place::Sequential(0), 7_000, 5));
        s.update(5, None);
        assert_eq!(before(&s, 1, 4), 1_007_010);
        assert_eq!(before(&s, 9, 0), 1_017_111);
        assert_eq!(s.room_before((0, 0, false), 9, 0), 0, "no such bucket");
    }

    #[test]
    fn buckets_with_peers_are_listed_in_the_wire_order() {
        let mut s = Shares::new();
        let keys = [
            (1, 5, false),
            (1, 3, true),
            (0, 0, false),
            (1, 3, false),
            (2, 0, true),
        ];
        for (slot, &key) in keys.iter().enumerate() {
            s.update(slot as u32, peer(key, slot as u64, Place::Unplaced, 1, 0));
        }
        s.update(4, None);
        let listed: Vec<_> = s.buckets().map(Bucket::key).collect();
        assert_eq!(
            listed,
            [(0, 0, false), (1, 3, false), (1, 3, true), (1, 5, false)],
            "by class, then urgency, sequential before incremental, without the emptied one"
        );
    }

    fn members(s: &Shares, key: ShareKey) -> Vec<u32> {
        s.members(s.bucket(key).expect("the bucket exists"))
            .collect()
    }

    #[test]
    fn a_sequential_bucket_lists_its_peers_by_order_then_id() {
        let mut s = Shares::new();
        let places = [(2, 0), (0, 8), (1, 4), (0, 4), (2, 12), (1, 0), (0, 0)];
        for (slot, &(order, id)) in places.iter().enumerate() {
            s.update(slot as u32, peer(SEQ, id, Place::Sequential(order), 1, 0));
        }
        assert_eq!(members(&s, SEQ), [6, 3, 1, 5, 2, 0, 4]);
        s.update(5, None);
        s.update(1, peer(SEQ, 8, Place::Sequential(3), 1, 0));
        assert_eq!(
            members(&s, SEQ),
            [6, 3, 2, 0, 4, 1],
            "after a leave and a move"
        );
    }

    fn placed(turn: u64, ticket: u64) -> Place {
        Place::Placed { turn, ticket }
    }

    #[test]
    fn an_incremental_bucket_lists_its_turn_then_the_unplaced_peers_by_id_then_later_turns() {
        let mut s = Shares::new();
        let places = [
            (7, placed(4, 9)),
            (3, placed(5, 2)),
            (5, placed(4, 3)),
            (12, Place::Unplaced),
            (0, Place::Unplaced),
            (1, placed(6, 1)),
        ];
        for (slot, &(id, place)) in places.iter().enumerate() {
            s.update(slot as u32, peer(INC, id, place, 1, 0));
        }
        s.settle(|key| if key == INC { 4 } else { 0 });
        assert_eq!(members(&s, INC), [2, 0, 4, 3, 1, 5]);
        s.settle(|_| 0);
        assert_eq!(
            members(&s, INC),
            [4, 3, 2, 0, 1, 5],
            "on turn 0, the unplaced ones join ahead of every placed one"
        );
    }

    #[test]
    fn placed_peers_behind_the_turn_are_listed_with_the_unplaced_ones_once_settled() {
        let mut s = Shares::new();
        let places = [
            (9, placed(2, 0)),
            (3, placed(3, 5)),
            (6, placed(5, 1)),
            (4, Place::Unplaced),
        ];
        for (slot, &(id, place)) in places.iter().enumerate() {
            s.update(slot as u32, peer(INC, id, place, 10, 1));
        }
        // The scheduler would place the first two on turn 4 behind every stream on it, as it does
        // the unplaced one, so the three go by ID.
        s.settle(|_| 4);
        assert_eq!(members(&s, INC), [1, 3, 0, 2]);
        assert_eq!(totals(&s, INC), (4, 4, 40));
        // Reported unplaced again, a settled peer stays; placed again, it goes back.
        s.update(1, peer(INC, 3, Place::Unplaced, 10, 1));
        s.update(0, peer(INC, 9, placed(4, 7), 10, 1));
        assert_eq!(members(&s, INC), [0, 1, 3, 2]);
    }

    #[test]
    fn an_incremental_bucket_sums_what_its_peers_take_up_to_an_entitlement() {
        let mut s = Shares::new();
        let mut rng = TestRng::new(7);
        let mut held = Vec::new();
        for slot in 0..40u32 {
            let r = rng.next_u64();
            let room = [0, 100, 5_000, r % 70_000][(r >> 32) as usize % 4];
            let staged = [0, 100, (r >> 8) % 70_000][(r >> 40) as usize % 3];
            let place = if slot % 3 == 0 {
                placed(u64::from(slot % 4), u64::from(slot))
            } else {
                Place::Unplaced
            };
            s.update(slot, peer(INC, u64::from(slot), place, room, staged));
            held.push(Holding { room, staged });
        }
        s.update(50, peer(SEQ, 50, Place::Sequential(0), 1 << 30, 1 << 30));
        // Every peer is checked at the ends of its room and either side of them.
        let check = |s: &Shares, held: &[Option<Holding>]| {
            s.assert_consistent();
            let held: Vec<_> = held.iter().flatten().collect();
            let mut entitlements = vec![0, u64::MAX];
            for h in &held {
                for at in [h.staged, h.staged + h.room] {
                    entitlements.extend([at.saturating_sub(1), at, at + 1]);
                }
            }
            let bucket = s.bucket(INC).expect("the bucket exists");
            for entitled in entitlements {
                let want = held
                    .iter()
                    .map(|h| h.room.min(entitled.saturating_sub(h.staged)))
                    .sum::<u64>();
                assert_eq!(s.takes(bucket, entitled), want, "entitled to {entitled}");
            }
        };
        let mut held: Vec<_> = held.into_iter().map(Some).collect();
        check(&s, &held);
        // Staging moves room to staged bytes, credit and acks change rooms, and peers leave or
        // move to another bucket.
        for slot in 0..40u32 {
            let r = rng.next_u64();
            let h = held[slot as usize].expect("every slot holds");
            let next = match r % 5 {
                0 => Some(Holding {
                    room: h.room / 2,
                    staged: h.staged + h.room - h.room / 2,
                }),
                1 => Some(Holding {
                    room: h.room + 3_000,
                    staged: h.staged,
                }),
                2 => Some(Holding {
                    room: h.room,
                    staged: h.staged / 3,
                }),
                3 => None,
                _ => Some(h),
            };
            match next {
                Some(h) => s.update(
                    slot,
                    peer(INC, u64::from(slot), Place::Unplaced, h.room, h.staged),
                ),
                None if r.is_multiple_of(2) => s.update(slot, None),
                None => s.update(slot, peer(SEQ, u64::from(slot), Place::Sequential(1), 9, 9)),
            };
            held[slot as usize] = next;
        }
        check(&s, &held);
        s.settle(|_| 2);
        check(&s, &held);
    }
}
