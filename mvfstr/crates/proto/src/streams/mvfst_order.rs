/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The mvfst-order plug: mvfst's wire order and a split of the staging budget whose incremental
//! buckets are kept in counters.
//!
//! The wire order follows mvfst's. Streams go by class, then urgency. Within a `(class, urgency)`
//! bucket the sequential streams go first, by order and then stream ID, and the first of them
//! keeps the wire until it has nothing to send. The incremental streams take turns of one packet
//! in a rotation: a stream with a STREAM frame in a packet, new data or a retransmission, goes to
//! the back when that packet is committed, if it is still scheduled. A stream that runs out leaves
//! the rotation, and a stream that joins it, new, refilled or moved there by a priority change,
//! joins at the back. A change of only the order field of an incremental stream keeps its place.
//!
//! Every per-stream link lives in a node array indexed by slab slot, so scheduling does not
//! allocate once the array and the buckets in use exist. A bucket's rotation is a circular list
//! through the nodes, its sequential streams sit in a treap keyed by `(order, stream ID)`, and a
//! two-level bitmask over bucket keys finds the first bucket with a scheduled stream.
//!
//! The split goes in wire order, a bucket's sequential streams before its incremental ones, each
//! taking from what the budget has left. The sequential streams take their rooms in turn, from a
//! treap that sums the rooms ahead of a place. The incremental peers of a bucket are each entitled
//! to an equal part of what reaches them and what they hold, and take their rooms up to that; the
//! streams after them get what reaches them less the sum of their rooms, which bounds what they
//! take. Their totals are counters, so a commit does not touch the split.
//!
//! The plug does not record what the only peer of a bucket's sequential or incremental streams
//! holds, or where it stands among them. It marks that stream alone, so the stream's reindexes skip
//! [`reshare`](Prioritizer::reshare) while it keeps its demand; the split reads both from the
//! stream, and the plug records them once another stream joins it.

use mvfstr_wire::StreamId;

use super::prioritizer::Peer;
use super::prioritizer::Peers;
use super::prioritizer::PeersMut;
use super::prioritizer::Prioritizer;
use super::scheduler::KeyMask;
use super::scheduler::SendOrder;
use super::scheduler::bucket_key;
use super::share::Holding;
use super::share::Regrouped;
use super::share::Treaps;
use super::share::entitlement;
use super::share::holding;
use super::share::incremental_allowance;

/// The index that marks a missing slot or bucket.
const NIL: u32 = u32::MAX;

/// A bucket's sequential streams, the first of its [`Bucket::groups`].
const SEQUENTIAL: u8 = 0;

/// A bucket's incremental streams, the second of its [`Bucket::groups`].
const INCREMENTAL: u8 = 1;

/// A node's links in its bucket's rotation, the first of its [`Node::links`].
const ROTATION: usize = 0;

/// A node's links among the incremental peers of its bucket, the second of its [`Node::links`].
const PEERS: usize = 1;

/// The mvfst-order plug: sequential streams by order and stream ID, the head keeping the wire
/// until it is empty, and incremental streams taking turns of one packet each in a rotation that a
/// stream joins at the back.
pub struct MvfstOrder {
    /// Per-stream links and records, by slab slot.
    nodes: Vec<Node>,
    /// Buckets in creation order; never removed.
    buckets: Vec<Bucket>,
    /// `(bucket key, position in buckets)`, sorted by key.
    index: Vec<(u16, u32)>,
    /// The keys of the buckets with a scheduled stream.
    nonempty: KeyMask,
    /// The number of scheduled streams.
    len: usize,
    /// The scheduled sequential streams by `(order, stream ID)`, a treap per bucket.
    wire: Treaps<(u128, u64)>,
    /// The sequential peers of the split by `(order, stream ID)`, weighing their rooms, a treap per
    /// bucket.
    rooms: Treaps<(u128, u64)>,
    /// The next ticket.
    tickets: u64,
}

/// A position in a walk over an [`MvfstOrder`] plug's streams in wire order, from
/// [`Cursor::default`], for one packet: a commit changes where the next walk starts.
///
/// The stream the walk is at may leave before the walk moves on, as a build that drains the
/// stream does, and so may any other stream. A stream that joins a rotation during the walk, or
/// goes to its back, is not visited.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cursor {
    pos: Pos,
    /// The first ticket handed out after the walk started.
    limit: u64,
}

#[derive(Clone, Copy, Debug, Default)]
enum Pos {
    #[default]
    Start,
    /// At the sequential stream in `slot` of `bucket`, whose key was `key`. Once that stream has
    /// left, its successor is looked up by the key.
    Sequential {
        bucket: u32,
        slot: u32,
        key: (u128, u64),
    },
    /// At the incremental stream in `slot` of `bucket`, whose ticket was `ticket`. Once that
    /// stream has left, its successor is the first stream of the rotation with a later ticket.
    Incremental {
        bucket: u32,
        slot: u32,
        ticket: u64,
    },
    Done,
}

/// A slot's links in a circular list.
#[derive(Clone, Copy)]
struct Link {
    prev: u32,
    next: u32,
}

const UNLINKED: Link = Link {
    prev: NIL,
    next: NIL,
};

/// A slot's stream in the wire order and in the split.
#[derive(Clone, Copy)]
struct Node {
    /// The bucket the stream is scheduled in, or [`NIL`].
    bucket: u32,
    /// The bucket among whose sequential or incremental streams the stream is a peer of the
    /// split, or [`NIL`].
    group: u32,
    /// Which of them: [`SEQUENTIAL`] or [`INCREMENTAL`].
    kind: u8,
    /// The order the stream is scheduled at.
    order: SendOrder,
    id: u64,
    /// When an incremental stream joined the back of its rotation: tickets rise from the head of
    /// a rotation to its back.
    ticket: u64,
    /// Links in the bucket's rotation and among the incremental peers of the bucket.
    links: [Link; 2],
    /// What a peer holds, as last recorded.
    holding: Holding,
}

impl Node {
    const OUT: Node = Node {
        bucket: NIL,
        group: NIL,
        kind: SEQUENTIAL,
        order: SendOrder {
            class: 0,
            urgency: 0,
            incremental: false,
            order: 0,
        },
        id: 0,
        ticket: 0,
        links: [UNLINKED; 2],
        holding: Holding { room: 0, staged: 0 },
    };
}

struct Bucket {
    key: u16,
    /// The root of the scheduled sequential streams' treap.
    seq: u32,
    /// The first stream of the rotation, or [`NIL`]; the last is its predecessor.
    head: u32,
    /// The peers of the split among the sequential streams and among the incremental ones.
    groups: [Group; 2],
}

/// The peers of the split among a bucket's sequential or incremental streams, with their totals.
#[derive(Clone, Copy)]
struct Group {
    peers: u32,
    staged: u64,
    room: u64,
    /// The root of the sequential peers' treap of rooms, or the first incremental peer in the
    /// circular list through the peers' links.
    first: u32,
}

const NO_PEERS: Group = Group {
    peers: 0,
    staged: 0,
    room: 0,
    first: NIL,
};

/// Returns the bucket key and the kind of the streams of the split a stream at `order` is a peer
/// among.
fn group_of(order: SendOrder) -> (u16, u8) {
    (bucket_key(order), u8::from(order.incremental))
}

/// Puts `slot` at the back of the circular list through the `list` links of `nodes` whose first
/// slot is `head`.
fn push_back(nodes: &mut [Node], list: usize, head: &mut u32, slot: u32) {
    if *head == NIL {
        nodes[slot as usize].links[list] = Link {
            prev: slot,
            next: slot,
        };
        *head = slot;
        return;
    }
    let last = nodes[*head as usize].links[list].prev;
    nodes[slot as usize].links[list] = Link {
        prev: last,
        next: *head,
    };
    nodes[last as usize].links[list].next = slot;
    nodes[*head as usize].links[list].prev = slot;
}

/// Takes `slot` out of the circular list through the `list` links of `nodes` whose first slot is
/// `head`.
fn unlink(nodes: &mut [Node], list: usize, head: &mut u32, slot: u32) {
    let Link { prev, next } = std::mem::replace(&mut nodes[slot as usize].links[list], UNLINKED);
    if next == slot {
        *head = NIL;
        return;
    }
    nodes[prev as usize].links[list].next = next;
    nodes[next as usize].links[list].prev = prev;
    if *head == slot {
        *head = next;
    }
}

impl MvfstOrder {
    /// Returns the total capacity, in elements, of the plug's growable storage.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.nodes.capacity()
            + self.buckets.capacity()
            + self.index.capacity()
            + self.wire.capacity()
            + self.rooms.capacity()
    }

    fn next_ticket(&mut self) -> u64 {
        let ticket = self.tickets;
        self.tickets += 1;
        ticket
    }

    fn find_bucket(&self, key: u16) -> Option<u32> {
        let at = self.index.binary_search_by_key(&key, |&(k, _)| k).ok()?;
        Some(self.index[at].1)
    }

    /// Returns the bucket for `key`, creating it on first use.
    fn bucket(&mut self, key: u16) -> u32 {
        match self.index.binary_search_by_key(&key, |&(k, _)| k) {
            Ok(at) => self.index[at].1,
            Err(at) => {
                let bucket = self.buckets.len() as u32;
                self.buckets.push(Bucket {
                    key,
                    seq: NIL,
                    head: NIL,
                    groups: [NO_PEERS; 2],
                });
                self.index.insert(at, (key, bucket));
                bucket
            }
        }
    }

    /// Moves the cursor to the first stream it may visit in the first bucket at or above `key`.
    fn enter_from(&self, cursor: &mut Cursor, mut key: u16) -> Option<u32> {
        while let Some(found) = self.nonempty.next_set(key) {
            let bucket = self.find_bucket(found)?;
            let b = &self.buckets[bucket as usize];
            let first = self.wire.leftmost(b.seq);
            if first != NIL {
                return Some(self.at_sequential(cursor, bucket, first));
            }
            if self.visits(cursor, b.head) {
                return Some(self.at_incremental(cursor, bucket, b.head));
            }
            key = found + 1;
        }
        cursor.pos = Pos::Done;
        None
    }

    /// Returns whether the walk visits the incremental stream in `slot`, which may be [`NIL`]: it
    /// was in the rotation when the walk started.
    fn visits(&self, cursor: &Cursor, slot: u32) -> bool {
        slot != NIL && self.nodes[slot as usize].ticket < cursor.limit
    }

    /// Returns the stream behind the incremental stream that had `ticket`, in `slot`, in the
    /// rotation of `bucket`, or [`NIL`].
    fn rotation_after(&self, bucket: u32, slot: u32, ticket: u64) -> u32 {
        let head = self.buckets[bucket as usize].head;
        let node = &self.nodes[slot as usize];
        if node.bucket == bucket && node.order.incremental && node.ticket == ticket {
            let next = node.links[ROTATION].next;
            return if next == head { NIL } else { next };
        }
        // The stream has left. Tickets rise from the head, so the first later one follows it.
        let mut at = head;
        while at != NIL {
            let node = &self.nodes[at as usize];
            if node.ticket > ticket {
                return at;
            }
            at = node.links[ROTATION].next;
            if at == head {
                break;
            }
        }
        NIL
    }

    /// Moves the cursor to the sequential stream in `slot` of `bucket` and returns `slot`.
    fn at_sequential(&self, cursor: &mut Cursor, bucket: u32, slot: u32) -> u32 {
        #[cfg(test)]
        super::guard::census::count(|c| c.scheduler_visits += 1);
        cursor.pos = Pos::Sequential {
            bucket,
            slot,
            key: self.wire.key(slot),
        };
        slot
    }

    /// Moves the cursor to the incremental stream in `slot` of `bucket` and returns `slot`.
    fn at_incremental(&self, cursor: &mut Cursor, bucket: u32, slot: u32) -> u32 {
        #[cfg(test)]
        super::guard::census::count(|c| c.scheduler_visits += 1);
        cursor.pos = Pos::Incremental {
            bucket,
            slot,
            ticket: self.nodes[slot as usize].ticket,
        };
        slot
    }

    fn group(&self, bucket: u32, kind: u8) -> &Group {
        &self.buckets[bucket as usize].groups[usize::from(kind)]
    }

    /// Iterates over the bucket positions, kinds and peers of the split's groups with peers, in
    /// wire order.
    fn groups(&self) -> impl Iterator<Item = (u32, u8, &Group)> {
        self.index
            .iter()
            .flat_map(move |&(_, bucket)| {
                [SEQUENTIAL, INCREMENTAL].map(|kind| (bucket, kind, self.group(bucket, kind)))
            })
            .filter(|(_, _, group)| group.peers > 0)
    }

    /// Returns what the peers of `group` hold, read from the stream for a lone peer, which the
    /// plug does not follow.
    fn held(&self, group: &Group, streams: &impl Peers) -> Holding {
        if group.peers != 1 {
            return Holding {
                room: group.room,
                staged: group.staged,
            };
        }
        streams
            .peer(group.first)
            .map_or_else(Holding::default, |stream| holding(stream.figures))
    }

    /// Returns the sum of the rooms of the sequential peers of `bucket` ahead of a stream at
    /// `order` with ID `id`.
    fn room_before(&self, bucket: u32, order: u128, id: u64, streams: &impl Peers) -> u64 {
        let group = self.group(bucket, SEQUENTIAL);
        if group.peers != 1 {
            return self.rooms.below(group.first, (order, id)).1;
        }
        match streams.peer(group.first) {
            Some(lone) if (lone.order.order, lone.id.into_inner()) < (order, id) => {
                lone.figures.room
            }
            _ => 0,
        }
    }

    /// Returns whether the stream in `slot` is the only peer among its bucket's sequential or
    /// incremental streams.
    fn alone(&self, slot: u32) -> bool {
        self.nodes
            .get(slot as usize)
            .is_some_and(|n| n.group != NIL && self.group(n.group, n.kind).peers == 1)
    }

    /// Returns the only peer of `bucket`'s streams of `kind`, if it has exactly one.
    fn lone(&self, bucket: u32, kind: u8) -> Option<u32> {
        let group = self.group(bucket, kind);
        (group.peers == 1).then_some(group.first)
    }

    /// Records that the stream in `slot` is the peer `stream` of the split, or with `None` that it
    /// is not a peer, and returns the peers this regrouped.
    fn update(&mut self, slot: u32, stream: Option<Peer>) -> Regrouped {
        let at = slot as usize;
        let mut regrouped = Regrouped::default();
        if at >= self.nodes.len() {
            if stream.is_none() {
                return regrouped;
            }
            self.nodes.resize(at + 1, Node::OUT);
        }
        let node = self.nodes[at];
        let from = (node.group != NIL).then(|| (self.buckets[node.group as usize].key, node.kind));
        let to = stream.map(|stream| group_of(stream.order));
        let stays = from.is_some() && from == to;
        if from.is_some() && !stays {
            self.leave(slot);
            regrouped.left = self.lone(node.group, node.kind);
        }
        let (Some(stream), Some((key, kind))) = (stream, to) else {
            return regrouped;
        };
        if !stays {
            let bucket = self.bucket(key);
            regrouped.joined = self.lone(bucket, kind);
            self.join(slot, bucket, kind, stream);
            return regrouped;
        }
        let place = (stream.order.order, stream.id.into_inner());
        if kind == SEQUENTIAL && self.rooms.key(slot) != place {
            #[cfg(test)]
            super::guard::census::count(|c| c.share_rekeys += 1);
            let root = &mut self.buckets[node.group as usize].groups[usize::from(kind)].first;
            self.rooms.rekey(root, slot, place, node.holding.room);
        }
        self.hold(slot, holding(stream.figures));
        regrouped
    }

    /// Adds the stream in `slot`, which is not a peer, to `bucket`'s peers of `kind` as `stream`.
    fn join(&mut self, slot: u32, bucket: u32, kind: u8, stream: Peer) {
        let h = holding(stream.figures);
        let node = &mut self.nodes[slot as usize];
        (node.group, node.kind, node.holding) = (bucket, kind, h);
        let group = &mut self.buckets[bucket as usize].groups[usize::from(kind)];
        group.peers += 1;
        group.staged += h.staged;
        group.room += h.room;
        if kind == SEQUENTIAL {
            let place = (stream.order.order, stream.id.into_inner());
            self.rooms.insert(&mut group.first, slot, place, h.room);
        } else {
            push_back(&mut self.nodes, PEERS, &mut group.first, slot);
        }
    }

    /// Takes the stream in `slot` out of the peers it is among.
    fn leave(&mut self, slot: u32) {
        let node = &mut self.nodes[slot as usize];
        let (bucket, kind, h) = (node.group, node.kind, node.holding);
        (node.group, node.holding) = (NIL, Holding::default());
        let group = &mut self.buckets[bucket as usize].groups[usize::from(kind)];
        group.peers -= 1;
        group.staged -= h.staged;
        group.room -= h.room;
        if kind == SEQUENTIAL {
            self.rooms.remove(&mut group.first, slot);
        } else {
            unlink(&mut self.nodes, PEERS, &mut group.first, slot);
        }
    }

    /// Records that the peer in `slot` holds `holding` now.
    fn hold(&mut self, slot: u32, holding: Holding) {
        let node = &mut self.nodes[slot as usize];
        if node.holding == holding {
            return;
        }
        let old = std::mem::replace(&mut node.holding, holding);
        let kind = node.kind;
        let group = &mut self.buckets[node.group as usize].groups[usize::from(kind)];
        group.staged = group.staged - old.staged + holding.staged;
        group.room = group.room - old.room + holding.room;
        if kind == SEQUENTIAL && old.room != holding.room {
            self.rooms.reweigh(slot, holding.room);
        }
    }

    /// Calls `f` with each incremental peer of `bucket` in wire order: those in the rotation in
    /// its order, then the others, which do not have bytes to send, in the order they joined.
    fn incremental_peers(&self, bucket: u32, mut f: impl FnMut(u32)) {
        let head = self.buckets[bucket as usize].head;
        let mut at = head;
        while at != NIL {
            let node = &self.nodes[at as usize];
            if node.group == bucket && node.kind == INCREMENTAL {
                f(at);
            }
            at = node.links[ROTATION].next;
            if at == head {
                break;
            }
        }
        let first = self.group(bucket, INCREMENTAL).first;
        let mut at = first;
        while at != NIL {
            let node = &self.nodes[at as usize];
            if node.bucket != bucket || !node.order.incremental {
                f(at);
            }
            at = node.links[PEERS].next;
            if at == first {
                break;
            }
        }
    }
}

impl Prioritizer for MvfstOrder {
    type Cursor = Cursor;

    fn new(_quantum: u64) -> Self {
        MvfstOrder {
            nodes: Vec::new(),
            buckets: Vec::new(),
            index: Vec::new(),
            nonempty: KeyMask::default(),
            len: 0,
            wire: Treaps::new(),
            rooms: Treaps::new(),
            tickets: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Schedules the stream: a sequential one at its place by order and stream ID, an incremental
    /// one at the back of its rotation. A stream already scheduled in the rotation of the order's
    /// bucket, or at the order's sequential place, keeps its place and takes the new order.
    fn insert(&mut self, slot: u32, id: StreamId, order: SendOrder) -> bool {
        let at = slot as usize;
        if at >= self.nodes.len() {
            self.nodes.resize(at + 1, Node::OUT);
        }
        let id = id.into_inner();
        let node = &mut self.nodes[at];
        if node.bucket != NIL {
            let same_place = node.id == id
                && group_of(node.order) == group_of(order)
                && (order.incremental || node.order.order == order.order);
            if same_place {
                node.order = order;
                return false;
            }
            self.remove(slot);
        }
        let key = bucket_key(order);
        let bucket = self.bucket(key);
        let ticket = if order.incremental {
            self.next_ticket()
        } else {
            0
        };
        let node = &mut self.nodes[at];
        (node.bucket, node.order, node.id, node.ticket) = (bucket, order, id, ticket);
        let b = &mut self.buckets[bucket as usize];
        if order.incremental {
            push_back(&mut self.nodes, ROTATION, &mut b.head, slot);
        } else {
            self.wire.insert(&mut b.seq, slot, (order.order, id), 0);
        }
        self.nonempty.set(key);
        self.len += 1;
        true
    }

    fn remove(&mut self, slot: u32) -> bool {
        let Some(node) = self.nodes.get_mut(slot as usize) else {
            return false;
        };
        let bucket = std::mem::replace(&mut node.bucket, NIL);
        if bucket == NIL {
            return false;
        }
        let incremental = node.order.incremental;
        let b = &mut self.buckets[bucket as usize];
        if incremental {
            unlink(&mut self.nodes, ROTATION, &mut b.head, slot);
        } else {
            self.wire.remove(&mut b.seq, slot);
        }
        if b.seq == NIL && b.head == NIL {
            self.nonempty.clear(b.key);
        }
        self.len -= 1;
        true
    }

    /// Keeps nothing: an unscheduled stream does not have a place, so a late commit for it is
    /// ignored anyway.
    fn forget(&mut self, slot: u32) {
        debug_assert!(
            self.nodes
                .get(slot as usize)
                .is_none_or(|n| n.bucket == NIL && n.group == NIL),
            "forgetting a scheduled stream or a peer"
        );
    }

    fn order(&self, slot: u32) -> Option<SendOrder> {
        let node = self.nodes.get(slot as usize)?;
        (node.bucket != NIL).then_some(node.order)
    }

    fn next(&self, cursor: &mut Cursor) -> Option<u32> {
        let (bucket, next) = match cursor.pos {
            Pos::Start => {
                cursor.limit = self.tickets;
                return self.enter_from(cursor, 0);
            }
            Pos::Sequential { bucket, slot, key } => {
                let node = &self.nodes[slot as usize];
                let next = if node.bucket == bucket
                    && !node.order.incremental
                    && self.wire.key(slot) == key
                {
                    self.wire.successor(slot)
                } else {
                    self.wire.after(self.buckets[bucket as usize].seq, key)
                };
                if next != NIL {
                    return Some(self.at_sequential(cursor, bucket, next));
                }
                (bucket, self.buckets[bucket as usize].head)
            }
            Pos::Incremental {
                bucket,
                slot,
                ticket,
            } => (bucket, self.rotation_after(bucket, slot, ticket)),
            Pos::Done => return None,
        };
        if self.visits(cursor, next) {
            return Some(self.at_incremental(cursor, bucket, next));
        }
        self.enter_from(cursor, self.buckets[bucket as usize].key + 1)
    }

    /// Sends a still scheduled incremental stream to the back of its rotation, whether or not it is
    /// at the head, whatever `bytes` it sealed, retransmitted bytes included. A stream that runs
    /// out leaves before its commit. O(1).
    fn commit(&mut self, slot: u32, id: StreamId, _bytes: u64, _streams: &impl Peers) {
        let Some(node) = self.nodes.get(slot as usize) else {
            return;
        };
        if node.bucket == NIL || !node.order.incremental || node.id != id.into_inner() {
            return;
        }
        let (bucket, next) = (node.bucket, node.links[ROTATION].next);
        let head = &mut self.buckets[bucket as usize].head;
        if *head == slot {
            *head = next;
        } else if next != *head {
            unlink(&mut self.nodes, ROTATION, head, slot);
            push_back(&mut self.nodes, ROTATION, head, slot);
        }
        let ticket = self.next_ticket();
        self.nodes[slot as usize].ticket = ticket;
    }

    /// Records the stream in the split as it stands, unless it is alone among its bucket's
    /// sequential or incremental streams: a lone peer's record is brought up to date only when
    /// another stream joins it, and its guard skips this while it stays alone with demand. An
    /// incremental peer that stays one updates only its bucket's counters.
    #[inline(never)]
    fn reshare(&mut self, slot: u32, _moved: bool, streams: &mut impl PeersMut) {
        #[cfg(test)]
        super::guard::census::count(|c| c.reshares += 1);
        let stream = streams.peer(slot).filter(|stream| stream.demand);
        if let Some(stream) = stream
            && let Some(&Node { group, kind, .. }) = self.nodes.get(slot as usize)
            && group != NIL
            && (self.buckets[group as usize].key, kind) == group_of(stream.order)
        {
            if self.group(group, kind).peers == 1 {
                streams.set_alone(slot, true);
                return;
            }
            if kind == INCREMENTAL {
                self.hold(slot, holding(stream.figures));
                return;
            }
        }
        let regrouped = self.update(slot, stream);
        streams.set_alone(slot, self.alone(slot));
        if let Some(left) = regrouped.left {
            streams.set_alone(left, true);
        }
        if let Some(joined) = regrouped.joined
            && let Some(stream) = streams.peer(joined)
        {
            self.update(joined, stream.demand.then_some(stream));
            streams.set_alone(joined, false);
        }
    }

    fn is_peer(&self, slot: u32) -> bool {
        self.nodes
            .get(slot as usize)
            .is_some_and(|n| n.group != NIL)
    }

    fn allowance(&self, asker: Peer, left: u64, streams: &impl Peers) -> u64 {
        let (key, kind) = group_of(asker.order);
        let mut left = left;
        for (bucket, ahead, group) in self.groups() {
            if (self.buckets[bucket as usize].key, ahead) >= (key, kind) || left == 0 {
                break;
            }
            left -= self.held(group, streams).room.min(left);
        }
        let bucket = self.find_bucket(key);
        let figures = asker.figures;
        if kind == INCREMENTAL {
            let (peers, held) = bucket.map_or((0, 0), |b| {
                let group = self.group(b, INCREMENTAL);
                (u64::from(group.peers), self.held(group, streams).staged)
            });
            let (peers, held) = if asker.demand {
                (peers, held)
            } else {
                (peers + 1, held.saturating_add(figures.staged))
            };
            incremental_allowance(holding(figures), entitlement(left, held, peers), left)
        } else {
            let (order, id) = (asker.order.order, asker.id.into_inner());
            let ahead = bucket.map_or(0, |b| self.room_before(b, order, id, streams));
            figures.room.min(left.saturating_sub(ahead))
        }
    }

    /// Splits `left` in wire order. A bucket's sequential streams take their rooms in turn from
    /// what is left, and the share of each is what is left when its turn comes; once `left` runs
    /// out, the rest are left out. Its incremental peers are each entitled to an equal part of
    /// what reaches them and what they hold, which is their share, and take their rooms up to that;
    /// the streams after them get what reaches them less the sum of their rooms.
    fn split(&mut self, left: u64, streams: &impl Peers, mut f: impl FnMut(u32, Peer, u64, u64)) {
        let mut left = left;
        for (bucket, kind, group) in self.groups() {
            if left == 0 {
                break;
            }
            if kind == SEQUENTIAL {
                let mut slot = self.rooms.leftmost(group.first);
                while slot != NIL && left > 0 {
                    if let Some(stream) = streams.peer(slot) {
                        let allowance = stream.figures.room.min(left);
                        f(slot, stream, allowance, left);
                        left -= allowance;
                    }
                    slot = self.rooms.successor(slot);
                }
                continue;
            }
            let held = self.held(group, streams);
            let entitled = entitlement(left, held.staged, u64::from(group.peers));
            self.incremental_peers(bucket, |slot| {
                if let Some(stream) = streams.peer(slot) {
                    let allowance = incremental_allowance(holding(stream.figures), entitled, left);
                    f(slot, stream, allowance, entitled);
                }
            });
            left -= held.room.min(left);
        }
    }

    #[cfg(debug_assertions)]
    fn digest(&self, slot: u32) -> Option<impl std::fmt::Debug> {
        let node = self.nodes.get(slot as usize)?;
        Some((node.bucket, node.order, node.id, node.ticket))
    }

    #[cfg(test)]
    fn assert_stream(&self, slot: u32, alone: bool, stream: Peer) {
        let id = stream.id;
        assert_eq!(alone, self.alone(slot), "stream {id} alone among its peers");
        let recorded = self
            .nodes
            .get(slot as usize)
            .filter(|n| n.group != NIL)
            .map(|n| {
                // What a lone peer holds and where it stands are not recorded.
                let lone = self.group(n.group, n.kind).peers == 1;
                let holding = if lone {
                    holding(stream.figures)
                } else {
                    n.holding
                };
                let place = (n.kind == SEQUENTIAL).then(|| {
                    if lone {
                        (stream.order.order, id.into_inner())
                    } else {
                        self.rooms.key(slot)
                    }
                });
                (self.buckets[n.group as usize].key, n.kind, place, holding)
            });
        let want = stream.demand.then(|| {
            let (key, kind) = group_of(stream.order);
            let place = (kind == SEQUENTIAL).then_some((stream.order.order, id.into_inner()));
            (key, kind, place, holding(stream.figures))
        });
        assert_eq!(recorded, want, "share of stream {id}");
    }

    #[cfg(test)]
    fn assert_consistent(&self) -> usize {
        assert!(
            self.index.windows(2).all(|w| w[0].0 < w[1].0),
            "the index is sorted"
        );
        let (mut scheduled, mut peers) = (0, 0);
        for (at, b) in self.buckets.iter().enumerate() {
            let at = at as u32;
            assert!(self.index.contains(&(b.key, at)), "{} is indexed", b.key);
            let sequential = self.wire.check(b.seq);
            for &slot in &sequential {
                let n = &self.nodes[slot as usize];
                assert!(n.bucket == at && !n.order.incremental, "slot {slot}");
                assert_eq!(self.wire.key(slot), (n.order.order, n.id), "slot {slot}");
            }
            let rotation = self.circle(ROTATION, b.head);
            for &slot in &rotation {
                let n = &self.nodes[slot as usize];
                assert!(n.bucket == at && n.order.incremental, "slot {slot}");
            }
            assert!(
                rotation
                    .windows(2)
                    .all(|w| self.nodes[w[0] as usize].ticket < self.nodes[w[1] as usize].ticket),
                "tickets rise along the rotation of {}",
                b.key
            );
            let empty = sequential.is_empty() && rotation.is_empty();
            assert_eq!(
                self.nonempty.next_set(b.key) == Some(b.key),
                !empty,
                "{}",
                b.key
            );
            scheduled += sequential.len() + rotation.len();
            for kind in [SEQUENTIAL, INCREMENTAL] {
                let group = self.group(at, kind);
                let members = if kind == SEQUENTIAL {
                    self.rooms.check(group.first)
                } else {
                    self.circle(PEERS, group.first)
                };
                let (mut staged, mut room) = (0, 0);
                for &slot in &members {
                    let n = &self.nodes[slot as usize];
                    assert_eq!((n.group, n.kind), (at, kind), "peer in slot {slot}");
                    staged += n.holding.staged;
                    room += n.holding.room;
                    if kind == SEQUENTIAL {
                        assert_eq!(self.rooms.weight(slot), n.holding.room, "slot {slot}");
                    }
                }
                assert_eq!(
                    (group.peers as usize, group.staged, group.room),
                    (members.len(), staged, room),
                    "totals of kind {kind} in {}",
                    b.key
                );
                peers += members.len();
            }
        }
        assert_eq!(self.len, scheduled, "scheduled streams");
        let nodes = |f: fn(&Node) -> bool| self.nodes.iter().filter(|n| f(n)).count();
        assert_eq!(
            nodes(|n| n.bucket != NIL),
            scheduled,
            "every stream in its bucket"
        );
        assert_eq!(
            nodes(|n| n.group != NIL),
            peers,
            "every peer among its group"
        );
        peers
    }
}

#[cfg(test)]
impl MvfstOrder {
    /// Returns the slots of the circular list through the `list` links whose first slot is `head`,
    /// checking its links.
    fn circle(&self, list: usize, head: u32) -> Vec<u32> {
        let mut slots = Vec::new();
        let mut at = head;
        while at != NIL {
            let link = self.nodes[at as usize].links[list];
            assert_eq!(
                self.nodes[link.next as usize].links[list].prev, at,
                "links of {at}"
            );
            slots.push(at);
            assert!(
                slots.len() <= self.nodes.len(),
                "the list through {head} is circular"
            );
            at = link.next;
            if at == head {
                break;
            }
        }
        slots
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_wire::Dir;
    use mvfstr_wire::Side;

    use super::*;

    fn id(slot: u32) -> StreamId {
        StreamId::new(Side::Server, Dir::Uni, u64::from(slot)).unwrap()
    }

    fn seq(class: u8, urgency: u8, order: u128) -> SendOrder {
        SendOrder {
            class,
            urgency,
            incremental: false,
            order,
        }
    }

    fn inc(class: u8, urgency: u8) -> SendOrder {
        SendOrder {
            class,
            urgency,
            incremental: true,
            order: 0,
        }
    }

    fn plug() -> MvfstOrder {
        <MvfstOrder as Prioritizer>::new(1200)
    }

    /// Returns the scheduled streams in wire order.
    fn walk(p: &MvfstOrder) -> Vec<u32> {
        p.iter().collect()
    }

    /// A connection without open streams: the wire order does not read the streams.
    struct NoStreams;

    impl Peers for NoStreams {
        fn peer(&self, _slot: u32) -> Option<Peer> {
            None
        }
    }

    /// Commits `bytes` sealed for the stream in `slot`, as a sealed packet does.
    fn commit(p: &mut MvfstOrder, slot: u32, bytes: u64) {
        p.commit(slot, id(slot), bytes, &NoStreams);
    }

    /// Schedules the streams in `slots`, in turn, at `order`.
    fn schedule(p: &mut MvfstOrder, slots: impl IntoIterator<Item = u32>, order: SendOrder) {
        for slot in slots {
            assert!(p.insert(slot, id(slot), order), "slot {slot} is scheduled");
        }
    }

    #[test]
    fn buckets_go_by_class_then_urgency_with_sequential_streams_by_order_then_id_first() {
        let mut p = plug();
        let orders = [
            (0, inc(1, 3)),
            (1, seq(1, 3, 5)),
            (2, seq(1, 3, 2)),
            (3, seq(1, 7, 0)),
            (4, inc(1, 0)),
            (5, seq(0, 9, 0)),
            (6, seq(1, 3, 2)),
            (7, inc(1, 3)),
            // Urgencies above 7 count as 7.
            (8, seq(1, 12, 0)),
        ];
        for (slot, order) in orders {
            assert!(p.insert(slot, id(slot), order), "slot {slot} is scheduled");
        }
        assert_eq!(p.len(), orders.len());
        // Class 0 first; then strict urgency, an incremental bucket at urgency 0 ahead of the
        // sequential streams at urgency 3; at one urgency, the sequential streams by order and
        // then stream ID ahead of the incremental ones, which go in the order they joined.
        assert_eq!(walk(&p), [5, 4, 2, 6, 1, 0, 7, 3, 8]);
        for (slot, order) in orders {
            assert_eq!(p.order(slot), Some(order), "order of slot {slot}");
        }
    }

    #[test]
    fn the_first_sequential_stream_keeps_the_wire_whatever_it_seals() {
        let mut p = plug();
        for slot in 0..3 {
            p.insert(slot, id(slot), seq(1, 3, u128::from(slot)));
        }
        schedule(&mut p, [3, 4], inc(1, 3));
        for bytes in [1200, 1, 64 * 1024] {
            commit(&mut p, 0, bytes);
            assert_eq!(walk(&p), [0, 1, 2, 3, 4], "after a commit of {bytes} bytes");
        }
        commit(&mut p, 1, 1200);
        assert_eq!(
            walk(&p),
            [0, 1, 2, 3, 4],
            "a sequential stream behind it does not move either"
        );
    }

    #[test]
    fn an_incremental_stream_still_scheduled_at_its_commit_goes_to_the_back_whatever_it_sealed() {
        let mut p = plug();
        schedule(&mut p, 0..4, inc(1, 3));
        p.insert(4, id(4), seq(1, 3, 0));
        p.insert(5, id(5), inc(1, 5));
        assert_eq!(walk(&p), [4, 0, 1, 2, 3, 5]);
        // A turn is one packet-filling write, whatever its size.
        commit(&mut p, 0, 1400);
        assert_eq!(walk(&p), [4, 1, 2, 3, 0, 5], "a packet's worth");
        commit(&mut p, 1, 1);
        assert_eq!(walk(&p), [4, 2, 3, 0, 1, 5], "less than a quantum");
        commit(&mut p, 2, 64 * 1024);
        assert_eq!(walk(&p), [4, 3, 0, 1, 2, 5], "many quanta at once");
        // Whichever stream of the rotation the commit names.
        commit(&mut p, 0, 1200);
        assert_eq!(walk(&p), [4, 3, 1, 2, 0, 5], "a stream behind the first");
        // A commit in another bucket leaves this rotation alone.
        commit(&mut p, 5, 1200);
        assert_eq!(walk(&p), [4, 3, 1, 2, 0, 5], "a lone stream of its bucket");
    }

    #[test]
    fn a_stream_that_left_is_not_moved_by_its_commit_and_rejoins_at_the_back() {
        let mut p = plug();
        schedule(&mut p, 0..3, inc(1, 3));
        // A build drains stream 0, and the guard unschedules it before the packet is committed.
        assert!(p.remove(0));
        assert_eq!(p.order(0), None);
        commit(&mut p, 0, 1000);
        commit(&mut p, 1, 200);
        assert_eq!(walk(&p), [2, 1], "the stream that filled the packet");
        // Refilled before the others were served, it still waits for both.
        assert!(p.insert(0, id(0), inc(1, 3)));
        assert_eq!(walk(&p), [2, 1, 0]);
        // A commit after the leave does not count once the stream is back.
        assert!(p.remove(2));
        commit(&mut p, 2, 1200);
        assert!(p.insert(2, id(2), inc(1, 3)));
        assert_eq!(walk(&p), [1, 0, 2]);
        assert!(!p.remove(3), "slot 3 was never scheduled");
    }

    #[test]
    fn a_new_stream_joins_behind_every_stream_in_the_rotation() {
        let mut p = plug();
        schedule(&mut p, 0..3, inc(1, 3));
        commit(&mut p, 0, 1200);
        assert_eq!(walk(&p), [1, 2, 0]);
        // Stream 0 was served in this round and 1 and 2 were not; the new stream waits for all.
        schedule(&mut p, [3], inc(1, 3));
        assert_eq!(walk(&p), [1, 2, 0, 3]);
        commit(&mut p, 1, 1200);
        schedule(&mut p, [4], inc(1, 3));
        assert_eq!(walk(&p), [2, 0, 3, 1, 4]);
        // An emptied bucket starts over with the first stream to join it.
        for slot in 0..5 {
            assert!(p.remove(slot));
        }
        schedule(&mut p, [4, 1], inc(1, 3));
        assert_eq!(walk(&p), [4, 1]);
    }

    #[test]
    fn a_move_to_another_bucket_joins_its_back_and_a_change_within_one_keeps_the_place() {
        let mut p = plug();
        schedule(&mut p, 0..3, inc(1, 3));
        schedule(&mut p, [3, 4], inc(1, 5));
        assert!(
            !p.insert(1, id(1), inc(1, 3)),
            "the same order does not move it"
        );
        assert_eq!(walk(&p), [0, 1, 2, 3, 4]);
        // The order field does not place an incremental stream.
        let reordered = SendOrder {
            order: 9,
            ..inc(1, 3)
        };
        p.insert(1, id(1), reordered);
        assert_eq!(
            walk(&p),
            [0, 1, 2, 3, 4],
            "a new order field keeps its place"
        );
        assert_eq!(p.order(1), Some(reordered));
        assert!(p.insert(1, id(1), inc(1, 5)));
        assert_eq!(
            walk(&p),
            [0, 2, 3, 4, 1],
            "to the back of the urgency 5 rotation"
        );
        commit(&mut p, 3, 1200);
        assert_eq!(walk(&p), [0, 2, 4, 1, 3]);
        assert!(p.insert(4, id(4), seq(1, 5, 0)));
        assert_eq!(
            walk(&p),
            [0, 2, 4, 1, 3],
            "sequential, ahead of the rotation"
        );
        assert!(p.insert(4, id(4), inc(1, 5)));
        assert_eq!(
            walk(&p),
            [0, 2, 1, 3, 4],
            "back in the rotation, at its back"
        );
        // A sequential stream moves by its order.
        p.insert(5, id(5), seq(1, 3, 9));
        p.insert(6, id(6), seq(1, 3, 4));
        assert_eq!(walk(&p), [6, 5, 0, 2, 1, 3, 4]);
        assert!(p.insert(5, id(5), seq(1, 3, 1)));
        assert_eq!(walk(&p), [5, 6, 0, 2, 1, 3, 4]);
        assert_eq!(p.len(), 7);
    }

    #[test]
    fn a_late_commit_for_a_forgotten_or_reused_slot_does_not_move_a_stream() {
        let mut p = plug();
        schedule(&mut p, 0..3, inc(1, 3));
        assert!(p.remove(1));
        p.forget(1);
        commit(&mut p, 1, 1200);
        assert_eq!(walk(&p), [0, 2]);
        // Another stream in the slot joins at the back, and a commit for the stream the slot held
        // before does not move it.
        let other = StreamId::new(Side::Server, Dir::Uni, 100).unwrap();
        assert!(p.insert(1, other, inc(1, 3)));
        assert_eq!(walk(&p), [0, 2, 1]);
        p.commit(1, id(1), 1200, &NoStreams);
        commit(&mut p, 0, 1200);
        assert_eq!(walk(&p), [2, 1, 0]);
        p.commit(1, id(1), 1200, &NoStreams);
        assert_eq!(walk(&p), [2, 1, 0], "the old stream's commit");
        p.commit(1, other, 1200, &NoStreams);
        assert_eq!(walk(&p), [2, 0, 1], "the new stream's commit");
    }

    #[test]
    fn a_walk_visits_each_stream_once_and_goes_on_when_the_stream_it_is_at_leaves() {
        // A build drains most streams it visits, and the guard unschedules each of them before
        // the walk moves on.
        let mut p = plug();
        for slot in 0..3 {
            p.insert(slot, id(slot), seq(1, 3, u128::from(slot)));
        }
        schedule(&mut p, 3..6, inc(1, 3));
        commit(&mut p, 3, 1200);
        p.insert(6, id(6), inc(1, 4));
        p.insert(7, id(7), seq(1, 4, 0));
        assert_eq!(walk(&p), [0, 1, 2, 4, 5, 3, 7, 6]);
        let mut cursor = Cursor::default();
        let mut visited = Vec::new();
        while let Some(slot) = p.next(&mut cursor) {
            visited.push(slot);
            if slot != 1 && slot != 5 {
                assert!(p.remove(slot));
            }
        }
        assert_eq!(visited, [0, 1, 2, 4, 5, 3, 7, 6], "visited");
        assert_eq!(p.next(&mut cursor), None, "a finished walk stays finished");
        assert_eq!(walk(&p), [1, 5]);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn a_walk_skips_the_streams_that_join_a_rotation_or_go_to_its_back_during_it() {
        let mut p = plug();
        schedule(&mut p, 0..3, inc(1, 3));
        schedule(&mut p, [5], inc(1, 5));
        let mut cursor = Cursor::default();
        assert_eq!(p.next(&mut cursor), Some(0));
        // The stream the walk is at goes to the back of its rotation, and new streams join it,
        // the rotation of a later bucket and a bucket of their own.
        commit(&mut p, 0, 1200);
        schedule(&mut p, [3], inc(1, 3));
        schedule(&mut p, [4], inc(1, 5));
        schedule(&mut p, [6], inc(1, 6));
        let mut visited = vec![0];
        while let Some(slot) = p.next(&mut cursor) {
            visited.push(slot);
        }
        assert_eq!(visited, [0, 1, 2, 5], "visited");
        assert_eq!(walk(&p), [1, 2, 0, 3, 5, 4, 6], "the next walk");
    }

    #[test]
    fn scheduling_does_not_allocate_once_warm() {
        let mut p = plug();
        let orders = [seq(0, 0, 1), seq(1, 3, 2), inc(1, 3), inc(1, 5)];
        for slot in 0..64 {
            p.insert(slot, id(slot), orders[slot as usize % 4]);
        }
        assert_eq!(p.len(), 64);
        let warm = p.capacity();
        for round in 0..1000u32 {
            let slot = round % 64;
            let first = p.iter().next().unwrap();
            commit(&mut p, first, 1000);
            p.remove(slot);
            p.insert(slot, id(slot), orders[(round as usize + 1) % 4]);
        }
        assert_eq!(p.len(), 64);
        assert_eq!(p.capacity(), warm);
    }
}
