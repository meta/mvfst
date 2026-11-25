/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The wire scheduler (RFC 9218).
//!
//! The scheduler is the transport's only wire-order queue, for every stream: sparse buckets per
//! `(class, urgency)`, sequential streams ordered by `order` then stream ID, incremental streams
//! round-robin with a quantum of about one packet, a read-only cursor for the attempt and a commit
//! that rotates by the bytes sealed, so the scheduler never rolls back.
//!
//! Streams are named by their slab slot (see [`StreamKey::slot`](super::map::StreamKey::slot)),
//! and every per-stream link lives in a node array indexed by slot, so scheduling does not
//! allocate once the array and the buckets in use exist. Buckets are created on first use and
//! kept; a two-level bitmask over bucket keys finds the first non-empty one. Within a bucket,
//! sequential streams sit in a treap keyed by `(order, stream ID)` and come before the
//! incremental streams (as the derived order of [`SendOrder`] puts `incremental: false` first).
//!
//! Incremental streams share their bucket by bytes. Each counts the bytes it has been served,
//! and they sit in a second treap keyed by turn (bytes served over the quantum), then by when
//! they reached that turn, so a walk visits the stream served least first. A stream keeps its
//! place until it has been served another quantum and then goes behind every stream served as
//! much or less: streams that fill the room they are offered take turns of a quantum each, as
//! round robin does, and a stream served many quanta at once (one commit per GSO run) waits
//! until the others catch up. A packet carries several streams of a bucket when the first
//! writes less than the room it is offered; the bytes of the streams that fill the rest count
//! the same way, and the front stream does not gain a claim on later turns for the room it left
//! (see [`Scheduler::commit`]). So bytes are shared max-min fairly: streams that can use their
//! share get equal bytes, and a stream that writes less than it is offered gets what it writes.
//! A round-robin list cannot order streams by bytes served, which this needs once packets carry
//! several streams; the treap keeps every operation O(log n).
//!
//! What a stream has been served outlives its place in the scheduler. The guard unschedules a
//! stream as soon as a build drains it, before the packet or run is committed, and its producer
//! may refill it before the next run. So an incremental stream that leaves keeps what it has
//! been served, a commit for it still counts, and when it rejoins its bucket it resumes its
//! place unless the bucket's turn has passed it. The bucket's turn is its front stream's turn
//! as of the last commit or removal, kept while the bucket does not have an incremental stream,
//! and it never goes down. A drain therefore does not cancel what a GSO run served, and a stream
//! that was away while the others caught up joins their turn; the turns it missed do not count
//! for or against it. A stream that moves to another bucket, or another stream in its slot,
//! starts on that bucket's turn.

use mvfstr_wire::StreamId;

/// A stream's place in the wire order.
///
/// Lower values go first: streams are served by `class`, then `urgency`; within one
/// `(class, urgency)` bucket, sequential (non-incremental) streams go in `order`, then stream ID,
/// and incremental streams share the bucket round-robin. The transport does not have a default
/// priority: every stream is opened with an explicit order.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SendOrder {
    /// The scheduling class; class 0 (HTTP/3 control and QPACK streams, MoQ control) is served
    /// first.
    pub class: u8,
    /// The RFC 9218 urgency, 0 (most urgent) to 7. Larger values are scheduled as 7.
    pub urgency: u8,
    /// Whether the stream shares its bucket round-robin (RFC 9218 incremental).
    pub incremental: bool,
    /// The sequential order within the bucket; smaller first.
    pub order: u128,
}

/// The wire order of every stream with something to send.
pub struct Scheduler {
    /// Bytes an incremental stream is served on each turn.
    quantum: u64,
    /// Per-stream links, by slab slot.
    nodes: Vec<Node>,
    /// Buckets in creation order; never removed.
    buckets: Vec<Bucket>,
    /// `(bucket key, position in buckets)`, sorted by key.
    index: Vec<(u16, u32)>,
    /// The keys of the non-empty buckets.
    nonempty: KeyMask,
    len: usize,
    /// The state of the generator of treap priorities.
    rng: u32,
    /// The next ticket, which orders incremental streams on the same turn.
    tickets: u64,
}

/// How far, in quanta, the front incremental stream of a bucket may stay behind a stream that
/// sealed bytes after it. The front stream was offered the room first and left some, so the
/// advantage it keeps is capped at this; the slack spares streams that are only taking turns,
/// which can be up to a quantum apart on one turn.
const FRONT_SLACK_QUANTA: u64 = 2;

/// The places of incremental streams a [`Scheduler::commit`] moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Moved {
    /// Whether the committed stream reached another turn.
    pub committed: bool,
    /// The slot of the front stream whose served bytes the commit raised, if any.
    pub raised: Option<u32>,
}

/// A position in a walk over the scheduler in wire order, from [`Cursor::default`], for one
/// packet: a commit changes where the next walk starts.
///
/// The stream the walk is at may leave the scheduler before the walk moves on, as a build that
/// drains the stream does, and so may any other stream. A stream that joins during the walk is
/// visited only if it lands ahead of the walk's position.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cursor {
    pos: Pos,
}

#[derive(Clone, Copy, Debug, Default)]
enum Pos {
    #[default]
    Start,
    /// At the stream in `slot`, in the sequential or incremental treap of `bucket`, whose key
    /// was `key`. Once that stream has left, its successor is looked up by the key.
    At {
        bucket: u32,
        incremental: bool,
        slot: u32,
        key: (u128, u64),
    },
    Done,
}

/// The index that marks a missing slot or bucket.
const NIL: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Node {
    /// Whether the stream is scheduled.
    scheduled: bool,
    /// The bucket the stream is scheduled in. An incremental stream that leaves keeps it, with
    /// its order, ID, bytes served and place, until it is scheduled again; [`NIL`] for any
    /// other unscheduled slot.
    bucket: u32,
    order: SendOrder,
    id: u64,
    /// Bytes an incremental stream has been served, on its bucket's scale: it joins with the
    /// bucket's turn times the quantum.
    served: u64,
    /// An incremental stream's turn, `served / quantum`, which places it in its treap.
    turn: u64,
    /// When an incremental stream reached its turn: earlier tickets go first.
    ticket: u64,
    /// Treap links and heap priority.
    left: u32,
    right: u32,
    parent: u32,
    priority: u32,
}

impl Node {
    const UNSCHEDULED: Node = Node {
        scheduled: false,
        bucket: NIL,
        order: SendOrder {
            class: 0,
            urgency: 0,
            incremental: false,
            order: 0,
        },
        id: 0,
        served: 0,
        turn: 0,
        ticket: 0,
        left: NIL,
        right: NIL,
        parent: NIL,
        priority: 0,
    };

    /// Returns the treap key: `(order, stream ID)` for a sequential stream, `(turn, ticket)` for
    /// an incremental one.
    fn key(&self) -> (u128, u64) {
        if self.order.incremental {
            (u128::from(self.turn), self.ticket)
        } else {
            (self.order.order, self.id)
        }
    }
}

struct Bucket {
    key: u16,
    seq: Treap,
    inc: Treap,
    /// The turn incremental streams join on: the front incremental stream's turn as of the last
    /// commit or removal here, kept while the bucket does not have one. It never goes down.
    turn: u64,
}

impl Bucket {
    fn is_empty(&self) -> bool {
        self.seq.root == NIL && self.inc.root == NIL
    }
}

/// A treap of slots ordered by [`Node::key`], with the smallest priority at the root.
struct Treap {
    root: u32,
}

/// One bit per bucket key, with a summary word of non-zero words.
#[derive(Default)]
struct KeyMask {
    summary: u32,
    words: [u64; 32],
}

/// Returns the bucket key of `order`: class, then urgency (RFC 9218 urgencies are 0 to 7).
fn bucket_key(order: SendOrder) -> u16 {
    u16::from(order.class) << 3 | u16::from(order.urgency.min(7))
}

impl KeyMask {
    fn set(&mut self, key: u16) {
        let word = usize::from(key >> 6);
        self.words[word] |= 1 << (key & 63);
        self.summary |= 1 << word;
    }

    fn clear(&mut self, key: u16) {
        let word = usize::from(key >> 6);
        self.words[word] &= !(1 << (key & 63));
        if self.words[word] == 0 {
            self.summary &= !(1 << word);
        }
    }

    /// Returns the smallest set key at or above `from`.
    fn next_set(&self, from: u16) -> Option<u16> {
        let word = usize::from(from >> 6);
        if word >= self.words.len() {
            return None;
        }
        let bits = self.words[word] & (u64::MAX << (from & 63));
        if bits != 0 {
            return Some((word as u16) << 6 | bits.trailing_zeros() as u16);
        }
        let above = self.summary & u32::MAX.checked_shl(word as u32 + 1).unwrap_or(0);
        if above == 0 {
            return None;
        }
        let word = above.trailing_zeros() as usize;
        Some((word as u16) << 6 | self.words[word].trailing_zeros() as u16)
    }
}

impl Scheduler {
    /// Creates an empty scheduler whose incremental streams take turns every `quantum` bytes
    /// (about one packet).
    pub fn new(quantum: u64) -> Self {
        Scheduler {
            quantum: quantum.max(1),
            nodes: Vec::new(),
            buckets: Vec::new(),
            index: Vec::new(),
            nonempty: KeyMask::default(),
            len: 0,
            rng: 0x9e37_79b9,
            tickets: 0,
        }
    }

    /// Returns the number of scheduled streams.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the scheduler is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Schedules the stream in `slot`, whose ID is `id`, at `order`; a stream already scheduled
    /// moves to the new place. An incremental stream joins its bucket on the bucket's turn,
    /// behind the streams on that turn, as a stream joins the back of a round-robin list. One
    /// that left this bucket and is back resumes its place instead, unless that place is
    /// behind the bucket's turn.
    ///
    /// Returns whether it scheduled or moved the stream: false for a stream already scheduled at
    /// `order`.
    pub fn insert(&mut self, slot: u32, id: StreamId, order: SendOrder) -> bool {
        let at = slot as usize;
        if at >= self.nodes.len() {
            self.nodes.resize(at + 1, Node::UNSCHEDULED);
        }
        let node = &self.nodes[at];
        if node.scheduled {
            if node.order == order && node.id == id.into_inner() {
                return false;
            }
            self.remove(slot);
        }
        let key = bucket_key(order);
        let bucket = self.bucket(key);
        let priority = self.next_priority();
        let (served, turn, ticket) = if order.incremental {
            let turn = self.buckets[bucket as usize].turn;
            let node = &self.nodes[at];
            if node.bucket == bucket && node.id == id.into_inner() && node.turn >= turn {
                (node.served, node.turn, node.ticket)
            } else {
                // A turn is a stream's served bytes over the quantum, so this does not overflow.
                (turn * self.quantum, turn, self.next_ticket())
            }
        } else {
            (0, 0, 0)
        };
        self.nodes[at] = Node {
            scheduled: true,
            bucket,
            order,
            id: id.into_inner(),
            served,
            turn,
            ticket,
            priority,
            ..Node::UNSCHEDULED
        };
        self.treap_insert(bucket, slot);
        self.nonempty.set(key);
        self.len += 1;
        true
    }

    /// Returns what the scheduler keeps for `slot`, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub fn digest(&self, slot: u32) -> Option<impl std::fmt::Debug> {
        let n = self.nodes.get(slot as usize)?;
        Some((
            n.scheduled,
            n.bucket,
            n.order,
            n.id,
            n.served,
            n.turn,
            n.ticket,
        ))
    }

    /// Unschedules the stream in `slot` and returns whether it was scheduled. An incremental
    /// stream keeps what it has been served, so a commit for bytes it sealed before it left still
    /// counts, and [`Scheduler::insert`] can resume it.
    pub fn remove(&mut self, slot: u32) -> bool {
        let Some(node) = self.nodes.get(slot as usize) else {
            return false;
        };
        if !node.scheduled {
            return false;
        }
        let bucket = node.bucket;
        self.treap_remove(bucket, slot);
        let node = &mut self.nodes[slot as usize];
        if node.order.incremental {
            *node = Node {
                scheduled: false,
                left: NIL,
                right: NIL,
                parent: NIL,
                ..*node
            };
        } else {
            *node = Node::UNSCHEDULED;
        }
        let (incremental, turn) = (node.order.incremental, node.turn);
        let b = &mut self.buckets[bucket as usize];
        if incremental && b.inc.root == NIL {
            // The last incremental stream to leave was in front.
            b.turn = b.turn.max(turn);
        } else if incremental {
            self.advance(bucket);
        }
        let b = &self.buckets[bucket as usize];
        if b.is_empty() {
            self.nonempty.clear(b.key);
        }
        self.len -= 1;
        true
    }

    /// Drops what the scheduler keeps about the stream in `slot` once it is gone for good, so a
    /// late commit for it is ignored; the stream must not be scheduled.
    pub fn forget(&mut self, slot: u32) {
        if let Some(node) = self.nodes.get_mut(slot as usize) {
            debug_assert!(!node.scheduled, "forgetting a scheduled stream");
            *node = Node::UNSCHEDULED;
        }
    }

    /// Returns where the incremental stream in `slot`, whose ID is `id`, stands among the
    /// incremental streams of `order`'s bucket, as `(turn, ticket)`, whether or not it is
    /// scheduled: its own place if it is scheduled there or would resume it, and otherwise the
    /// place [`Scheduler::insert`] would give it, on the bucket's turn behind every stream on that
    /// turn (`u64::MAX` for the ticket).
    pub fn place(&self, slot: u32, id: StreamId, order: SendOrder) -> (u64, u64) {
        let bucket = self.find_bucket(bucket_key(order));
        let turn = bucket.map_or(0, |b| self.buckets[b as usize].turn);
        match self.nodes.get(slot as usize) {
            Some(node)
                if bucket == Some(node.bucket)
                    && node.order.incremental
                    && node.id == id.into_inner()
                    && (node.scheduled || node.turn >= turn) =>
            {
                (node.turn, node.ticket)
            }
            _ => (turn, u64::MAX),
        }
    }

    /// Returns the turn that incremental streams joining the bucket of `order`'s class and urgency
    /// are placed on (see [`Scheduler::place`]), or 0 for a bucket not used yet.
    pub fn turn(&self, order: SendOrder) -> u64 {
        self.find_bucket(bucket_key(order))
            .map_or(0, |b| self.buckets[b as usize].turn)
    }

    /// Returns the order the stream in `slot` is scheduled at, if it is scheduled.
    pub fn order(&self, slot: u32) -> Option<SendOrder> {
        let node = self.nodes.get(slot as usize)?;
        node.scheduled.then_some(node.order)
    }

    /// Returns the next stream in wire order after the cursor's position and advances the cursor.
    pub fn next(&self, cursor: &mut Cursor) -> Option<u32> {
        match cursor.pos {
            Pos::Start => self.enter_from(cursor, 0),
            Pos::At {
                bucket,
                incremental,
                slot,
                key,
            } => {
                let next = if self.in_bucket(slot, bucket, incremental)
                    && self.nodes[slot as usize].key() == key
                {
                    self.treap_next(slot)
                } else {
                    self.treap_after(bucket, incremental, key)
                };
                if next != NIL {
                    return Some(self.at(cursor, bucket, incremental, next));
                }
                if !incremental {
                    return self.enter_treap(cursor, bucket, true);
                }
                self.enter_from(cursor, self.buckets[bucket as usize].key + 1)
            }
            Pos::Done => None,
        }
    }

    /// Iterates over the scheduled streams in wire order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let mut cursor = Cursor::default();
        std::iter::from_fn(move || self.next(&mut cursor))
    }

    /// Records that `bytes` of stream `id`, in `slot`, were sealed; a commit for a stream the
    /// slot no longer holds is ignored. Each time an incremental
    /// stream's bytes reach another quantum it goes behind every stream of its bucket served as
    /// much or less, whether or not it was in front. If it was not in front, the front stream
    /// was offered the room first and left some, so it is brought up to within
    /// `FRONT_SLACK_QUANTA` quanta of what this stream had been served: a stream that writes
    /// less than it is offered gets what it writes and does not gain a claim on later turns. A
    /// stream that has left counts as not in front; if it was in front, every other stream had
    /// been served more than a quantum above that floor, so the floor does not raise any of them.
    ///
    /// Commit what a packet, or a whole GSO run, sealed after it is sealed, for every stream
    /// that sealed bytes, in the order they were written, whether or not it is still scheduled;
    /// one commit per GSO run latches the order for the run. The scheduler never rolls back:
    /// bytes not sealed are never committed. O(log n).
    ///
    /// Returns whether the committed stream reached another turn, and the slot of the front
    /// stream whose served bytes it raised, if any: only those places may have changed.
    pub fn commit(&mut self, slot: u32, id: StreamId, bytes: u64) -> Moved {
        let Some(node) = self.nodes.get(slot as usize) else {
            return Moved::default();
        };
        if node.bucket == NIL || !node.order.incremental || node.id != id.into_inner() {
            return Moved::default();
        }
        let (bucket, served) = (node.bucket, node.served);
        let root = self.buckets[bucket as usize].inc.root;
        let mut raised = None;
        if root != NIL {
            let front = self.leftmost(root);
            if front != slot {
                let floor = served.saturating_sub(FRONT_SLACK_QUANTA.saturating_mul(self.quantum));
                if self.nodes[front as usize].served < floor {
                    let _ = self.set_served(bucket, front, floor);
                    raised = Some(front);
                }
            }
        }
        let committed = self.set_served(bucket, slot, served.saturating_add(bytes));
        self.advance(bucket);
        Moved { committed, raised }
    }

    /// Records that the incremental stream in `slot` has been served `served` bytes, no fewer
    /// than before, and moves it behind the streams on its turn if it reached a new one; returns
    /// whether it did.
    fn set_served(&mut self, bucket: u32, slot: u32, served: u64) -> bool {
        let turn = served / self.quantum;
        self.nodes[slot as usize].served = served;
        if turn == self.nodes[slot as usize].turn {
            return false;
        }
        let scheduled = self.nodes[slot as usize].scheduled;
        if scheduled {
            self.treap_remove(bucket, slot);
        }
        let ticket = self.next_ticket();
        let node = &mut self.nodes[slot as usize];
        node.turn = turn;
        node.ticket = ticket;
        if scheduled {
            node.left = NIL;
            node.right = NIL;
            node.parent = NIL;
            self.treap_insert(bucket, slot);
        }
        true
    }

    /// Raises `bucket`'s turn to its front incremental stream's turn. Commits and removals call
    /// this and inserts do not: a stream that rejoins with a debt does not move the turn, so the
    /// streams that join after it do not take on its debt.
    fn advance(&mut self, bucket: u32) {
        let root = self.buckets[bucket as usize].inc.root;
        if root != NIL {
            let front = self.nodes[self.leftmost(root) as usize].turn;
            let b = &mut self.buckets[bucket as usize];
            b.turn = b.turn.max(front);
        }
    }

    /// Returns whether `slot` is still scheduled in `bucket`, among its sequential or incremental
    /// streams.
    fn in_bucket(&self, slot: u32, bucket: u32, incremental: bool) -> bool {
        let node = &self.nodes[slot as usize];
        node.scheduled && node.bucket == bucket && node.order.incremental == incremental
    }

    /// Moves the cursor to the first stream of the first non-empty bucket at or above `key`.
    fn enter_from(&self, cursor: &mut Cursor, key: u16) -> Option<u32> {
        let Some(key) = self.nonempty.next_set(key) else {
            cursor.pos = Pos::Done;
            return None;
        };
        let bucket = self.find_bucket(key)?;
        self.enter_treap(cursor, bucket, false)
    }

    /// Moves the cursor to the first stream of `bucket`'s sequential or incremental treap, or
    /// past it if it is empty.
    fn enter_treap(&self, cursor: &mut Cursor, bucket: u32, incremental: bool) -> Option<u32> {
        let root = self.root(bucket, incremental);
        if root != NIL {
            return Some(self.at(cursor, bucket, incremental, self.leftmost(root)));
        }
        if !incremental {
            return self.enter_treap(cursor, bucket, true);
        }
        self.enter_from(cursor, self.buckets[bucket as usize].key + 1)
    }

    /// Moves the cursor to the stream in `slot` and returns `slot`.
    fn at(&self, cursor: &mut Cursor, bucket: u32, incremental: bool, slot: u32) -> u32 {
        cursor.pos = Pos::At {
            bucket,
            incremental,
            slot,
            key: self.nodes[slot as usize].key(),
        };
        slot
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
                    seq: Treap { root: NIL },
                    inc: Treap { root: NIL },
                    turn: 0,
                });
                self.index.insert(at, (key, bucket));
                bucket
            }
        }
    }

    /// Steps a xorshift sequence: treap priorities need only be well spread, not unpredictable.
    fn next_priority(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    fn next_ticket(&mut self) -> u64 {
        let ticket = self.tickets;
        self.tickets += 1;
        ticket
    }

    /// Returns the root of `bucket`'s sequential or incremental treap.
    fn root(&self, bucket: u32, incremental: bool) -> u32 {
        let b = &self.buckets[bucket as usize];
        if incremental { b.inc.root } else { b.seq.root }
    }

    /// Makes `root`, which may be [`NIL`], the root of `bucket`'s treap for streams like `slot`'s.
    fn set_root(&mut self, bucket: u32, slot: u32, root: u32) {
        let b = &mut self.buckets[bucket as usize];
        if self.nodes[slot as usize].order.incremental {
            b.inc.root = root;
        } else {
            b.seq.root = root;
        }
    }

    /// Inserts `slot`, whose links are unset, into its treap in `bucket`.
    fn treap_insert(&mut self, bucket: u32, slot: u32) {
        let node = &self.nodes[slot as usize];
        let key = node.key();
        let mut parent = NIL;
        let mut cur = self.root(bucket, node.order.incremental);
        let mut left = false;
        while cur != NIL {
            parent = cur;
            left = key < self.nodes[cur as usize].key();
            cur = if left {
                self.nodes[cur as usize].left
            } else {
                self.nodes[cur as usize].right
            };
        }
        self.nodes[slot as usize].parent = parent;
        if parent == NIL {
            self.set_root(bucket, slot, slot);
        } else if left {
            self.nodes[parent as usize].left = slot;
        } else {
            self.nodes[parent as usize].right = slot;
        }
        loop {
            let parent = self.nodes[slot as usize].parent;
            if parent == NIL
                || self.nodes[parent as usize].priority <= self.nodes[slot as usize].priority
            {
                break;
            }
            self.rotate_up(bucket, slot);
        }
    }

    /// Rotates `x` above its parent, keeping the in-order sequence.
    fn rotate_up(&mut self, bucket: u32, x: u32) {
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
            self.set_root(bucket, x, x);
        } else if self.nodes[g as usize].left == p {
            self.nodes[g as usize].left = x;
        } else {
            self.nodes[g as usize].right = x;
        }
    }

    /// Rotates `slot` down below the child with the smaller priority until it has at most one
    /// child, then splices it out.
    fn treap_remove(&mut self, bucket: u32, slot: u32) {
        loop {
            let Node { left, right, .. } = self.nodes[slot as usize];
            if left == NIL || right == NIL {
                let child = if left != NIL { left } else { right };
                let parent = self.nodes[slot as usize].parent;
                if child != NIL {
                    self.nodes[child as usize].parent = parent;
                }
                if parent == NIL {
                    self.set_root(bucket, slot, child);
                } else if self.nodes[parent as usize].left == slot {
                    self.nodes[parent as usize].left = child;
                } else {
                    self.nodes[parent as usize].right = child;
                }
                return;
            }
            let up = if self.nodes[left as usize].priority < self.nodes[right as usize].priority {
                left
            } else {
                right
            };
            self.rotate_up(bucket, up);
        }
    }

    fn leftmost(&self, mut slot: u32) -> u32 {
        while self.nodes[slot as usize].left != NIL {
            slot = self.nodes[slot as usize].left;
        }
        slot
    }

    /// Returns the in-order successor of `slot` in its treap, or [`NIL`].
    fn treap_next(&self, mut slot: u32) -> u32 {
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

    /// Returns the first slot in `bucket`'s sequential or incremental treap whose key is above
    /// `key`, or [`NIL`].
    fn treap_after(&self, bucket: u32, incremental: bool, key: (u128, u64)) -> u32 {
        let mut after = NIL;
        let mut cur = self.root(bucket, incremental);
        while cur != NIL {
            let node = &self.nodes[cur as usize];
            if node.key() > key {
                after = cur;
                cur = node.left;
            } else {
                cur = node.right;
            }
        }
        after
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_wire::Dir;
    use mvfstr_wire::Side;

    use super::*;

    const QUANTUM: u64 = 1200;

    /// Returns a stream ID that sorts in slot order, so ties on `order` are visible.
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

    fn order_of(s: &Scheduler) -> Vec<u32> {
        s.iter().collect()
    }

    #[test]
    fn buckets_go_by_class_then_urgency() {
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), seq(1, 7, 0));
        s.insert(1, id(1), seq(1, 3, 0));
        s.insert(2, id(2), seq(0, 5, 0));
        s.insert(3, id(3), seq(1, 0, 0));
        s.insert(4, id(4), seq(2, 0, 0));
        s.insert(5, id(5), seq(0, 1, 0));
        assert_eq!(s.len(), 6);
        assert_eq!(order_of(&s), [5, 2, 3, 1, 0, 4]);
    }

    #[test]
    fn sequential_streams_go_by_order_then_stream_id() {
        let mut s = Scheduler::new(QUANTUM);
        for (slot, order) in [(4, 5), (1, 2), (7, 9), (0, 2), (3, 0), (6, 2)] {
            s.insert(slot, id(slot), seq(1, 3, order));
        }
        assert_eq!(order_of(&s), [3, 0, 1, 6, 4, 7]);
    }

    #[test]
    fn sequential_streams_precede_incremental_ones_in_a_bucket() {
        let mut s = Scheduler::new(QUANTUM);
        s.insert(5, id(5), inc(1, 3));
        s.insert(9, id(9), seq(1, 3, 7));
        s.insert(2, id(2), inc(1, 3));
        s.insert(1, id(1), seq(1, 3, 3));
        s.insert(8, id(8), inc(1, 2));
        s.insert(0, id(0), seq(1, 4, 0));
        assert_eq!(order_of(&s), [8, 1, 9, 5, 2, 0]);
    }

    #[test]
    fn commit_moves_an_incremental_stream_back_after_each_quantum() {
        let mut s = Scheduler::new(QUANTUM);
        for slot in [3, 1, 2] {
            s.insert(slot, id(slot), inc(1, 3));
        }
        assert_eq!(order_of(&s), [3, 1, 2]);
        s.commit(3, id(3), 700);
        assert_eq!(order_of(&s), [3, 1, 2], "below the quantum");
        s.commit(3, id(3), 500);
        assert_eq!(order_of(&s), [1, 2, 3]);
        // Bytes of a stream behind the front count the same way: four quanta put stream 2
        // behind the streams served less, and it stays there until they catch up.
        s.commit(2, id(2), 5000);
        assert_eq!(order_of(&s), [1, 3, 2]);
        s.commit(1, id(1), QUANTUM);
        assert_eq!(order_of(&s), [3, 1, 2]);
        s.commit(3, id(3), QUANTUM);
        s.commit(1, id(1), QUANTUM);
        assert_eq!(order_of(&s), [3, 1, 2]);
    }

    #[test]
    fn a_commit_behind_the_front_reports_the_front_stream_it_raises() {
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        s.insert(3, id(3), seq(1, 3, 0));
        assert_eq!(
            s.commit(1, id(1), 3 * QUANTUM).raised,
            None,
            "the front was served no less than the slack below this stream"
        );
        assert_eq!(s.commit(0, id(0), 100).raised, None, "the front itself");
        assert_eq!(
            s.commit(3, id(3), QUANTUM).raised,
            None,
            "a sequential stream"
        );
        assert_eq!(
            s.commit(1, id(1), QUANTUM).raised,
            Some(0),
            "slot 1 had been served three quanta, so the front is raised to one"
        );
        assert_eq!(order_of(&s), [3, 2, 0, 1]);
    }

    #[test]
    fn a_commit_reports_whether_the_committed_stream_reached_another_turn() {
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), seq(1, 3, 0));
        let moved =
            |s: &mut Scheduler, slot, stream, bytes| s.commit(slot, id(stream), bytes).committed;
        assert!(!moved(&mut s, 0, 0, QUANTUM - 1), "still on turn 0");
        assert!(moved(&mut s, 0, 0, 1), "on to turn 1");
        assert!(moved(&mut s, 0, 0, 3 * QUANTUM), "on to turn 4 at once");
        assert!(!moved(&mut s, 0, 0, 100), "still on turn 4");
        assert!(
            !moved(&mut s, 1, 1, 5 * QUANTUM),
            "a sequential stream has no turns"
        );
        assert!(
            !moved(&mut s, 0, 2, 5 * QUANTUM),
            "a commit for a stream the slot does not hold"
        );
        s.remove(0);
        assert!(
            moved(&mut s, 0, 0, QUANTUM),
            "a stream that left still counts its bytes"
        );
    }

    #[test]
    fn an_insert_reports_whether_it_scheduled_or_moved_the_stream() {
        let mut s = Scheduler::new(QUANTUM);
        assert!(s.insert(0, id(0), inc(1, 3)), "a new stream");
        assert!(
            !s.insert(0, id(0), inc(1, 3)),
            "already scheduled at that order"
        );
        assert!(s.insert(0, id(0), seq(1, 3, 2)), "moved to another order");
        assert!(
            !s.insert(0, id(0), seq(1, 3, 2)),
            "already scheduled at that order"
        );
        assert!(
            s.insert(0, id(4), seq(1, 3, 2)),
            "another stream in the slot"
        );
        assert!(s.remove(0));
        assert!(s.insert(0, id(4), seq(1, 3, 2)), "scheduled again");
    }

    #[test]
    fn the_turn_new_streams_of_a_bucket_are_placed_on_is_reported() {
        let mut s = Scheduler::new(QUANTUM);
        assert_eq!(s.turn(inc(1, 3)), 0, "no bucket yet");
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.commit(0, id(0), 2 * QUANTUM);
        s.commit(1, id(1), 3 * QUANTUM);
        assert_eq!(
            s.turn(inc(1, 3)),
            2,
            "the front stream, slot 0, is on turn 2"
        );
        assert_eq!(
            s.turn(seq(1, 3, 9)),
            2,
            "the bucket of the class and urgency"
        );
        assert_eq!(s.place(5, id(5), inc(1, 3)), (2, u64::MAX));
        assert_eq!(s.turn(inc(1, 4)), 0);
    }

    #[test]
    fn removal_unlinks_a_stream_wherever_it_is() {
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..6 {
            s.insert(slot, id(slot), seq(1, 3, u128::from(slot)));
        }
        for slot in [6, 7, 8] {
            s.insert(slot, id(slot), inc(1, 3));
        }
        s.insert(9, id(9), seq(0, 0, 0));
        assert_eq!(s.order(9), Some(seq(0, 0, 0)));
        assert!(s.remove(9));
        assert!(!s.remove(9));
        assert!(!s.remove(42));
        assert_eq!(s.order(9), None);
        for slot in [3, 0, 5] {
            assert!(s.remove(slot));
        }
        assert_eq!(order_of(&s), [1, 2, 4, 6, 7, 8]);
        // Removing the front stream does not pass what it was served to the next one.
        s.commit(6, id(6), QUANTUM - 1);
        assert!(s.remove(6));
        assert_eq!(order_of(&s), [1, 2, 4, 7, 8]);
        s.commit(7, id(7), QUANTUM - 1);
        assert_eq!(order_of(&s), [1, 2, 4, 7, 8]);
        assert!(s.remove(8));
        assert_eq!(order_of(&s), [1, 2, 4, 7]);
        for slot in [1, 2, 4, 7] {
            assert!(s.remove(slot));
        }
        assert!(s.is_empty());
        assert_eq!(order_of(&s), [] as [u32; 0]);
    }

    #[test]
    fn inserting_a_scheduled_stream_moves_it_and_the_same_order_changes_nothing() {
        let mut s = Scheduler::new(QUANTUM);
        s.insert(1, id(1), seq(1, 3, 5));
        s.insert(2, id(2), seq(1, 3, 6));
        s.insert(3, id(3), inc(2, 0));
        s.insert(4, id(4), inc(2, 0));
        s.insert(2, id(2), seq(0, 0, 0));
        assert_eq!(s.len(), 4);
        assert_eq!(order_of(&s), [2, 1, 3, 4]);
        s.insert(1, id(1), inc(2, 0));
        assert_eq!(order_of(&s), [2, 3, 4, 1]);
        // Re-inserting a stream at its order keeps its place and what it has been served.
        s.commit(3, id(3), QUANTUM - 1);
        s.insert(3, id(3), inc(2, 0));
        assert_eq!(order_of(&s), [2, 3, 4, 1]);
        s.commit(3, id(3), 1);
        assert_eq!(order_of(&s), [2, 4, 1, 3]);
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn incremental_streams_share_bytes_fairly_whatever_their_frame_sizes() {
        // Each packet carries the first stream in wire order; streams fill packets differently
        // (a short tail, a small producer), but over many turns they get the same bytes.
        let mut s = Scheduler::new(QUANTUM);
        let frame = [1200, 700, 450];
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        let mut sent = [0u64; 3];
        for _ in 0..3000 {
            let slot = s.iter().next().unwrap();
            sent[slot as usize] += frame[slot as usize];
            s.commit(slot, id(slot), frame[slot as usize]);
        }
        let most = sent.iter().max().unwrap();
        let least = sent.iter().min().unwrap();
        assert!(most - least <= 2 * QUANTUM, "bytes per stream: {sent:?}");
    }

    #[test]
    fn a_turn_served_many_quanta_at_once_is_paid_back_in_turns() {
        // Committing once per GSO run can serve the front stream many quanta at once. It waits
        // until the others catch up, so runs of different sizes still share bytes evenly.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        let run = [10 * QUANTUM, QUANTUM];
        let mut sent = [0u64; 2];
        for _ in 0..1000 {
            let slot = s.iter().next().unwrap();
            sent[slot as usize] += run[slot as usize];
            s.commit(slot, id(slot), run[slot as usize]);
        }
        let most = sent.iter().max().unwrap();
        let least = sent.iter().min().unwrap();
        assert!(most - least <= 10 * QUANTUM, "bytes per stream: {sent:?}");
    }

    #[test]
    fn a_stream_its_run_drained_still_pays_its_run_back() {
        // As above, but each run drains stream 0, so the guard unschedules it before the commit
        // and its producer refills it before the next run.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        let run = [10 * QUANTUM, QUANTUM];
        let mut sent = [0u64; 2];
        for _ in 0..1000 {
            let slot = s.iter().next().unwrap();
            sent[slot as usize] += run[slot as usize];
            if slot == 0 {
                s.remove(0);
            }
            s.commit(slot, id(slot), run[slot as usize]);
            s.insert(0, id(0), inc(1, 3));
        }
        let most = sent.iter().max().unwrap();
        let least = sent.iter().min().unwrap();
        assert!(most - least <= 10 * QUANTUM, "bytes per stream: {sent:?}");
    }

    #[test]
    fn a_stream_back_after_the_others_caught_up_owes_and_banks_nothing() {
        // Stream 0 leaves with a run of five quanta committed after it left, and streams 1 and
        // 2 are each served eight before it comes back. Its debt is paid, and it does not get
        // the turns it missed: it joins the back of the current turn.
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        s.remove(0);
        s.commit(0, id(0), 5 * QUANTUM);
        for _ in 0..8 {
            s.commit(1, id(1), QUANTUM);
            s.commit(2, id(2), QUANTUM);
        }
        s.insert(0, id(0), inc(1, 3));
        assert_eq!(order_of(&s), [1, 2, 0]);
        s.commit(1, id(1), QUANTUM);
        assert_eq!(order_of(&s), [2, 0, 1]);
    }

    #[test]
    fn a_bucket_keeps_its_turn_when_it_empties() {
        // Streams 0 and 1 take five turns each. Stream 0 leaves, and stream 1 takes four more
        // turns and leaves too, which empties the bucket. Stream 2 joins it and stream 0 comes
        // back: stream 0 is not held behind stream 2 for the turns stream 1 took.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        for _ in 0..5 {
            s.commit(0, id(0), QUANTUM);
            s.commit(1, id(1), QUANTUM);
        }
        s.remove(0);
        for _ in 0..4 {
            s.commit(1, id(1), QUANTUM);
        }
        s.remove(1);
        s.insert(2, id(2), inc(1, 3));
        s.insert(0, id(0), inc(1, 3));
        assert_eq!(order_of(&s), [2, 0]);
        s.commit(2, id(2), QUANTUM);
        assert_eq!(order_of(&s), [0, 2]);
    }

    #[test]
    fn streams_back_in_an_emptied_bucket_keep_their_places_whatever_order_they_rejoin_in() {
        // One run drains both streams; stream 0 was served five quanta and stream 1 one. The
        // first back must not set the bucket's turn for the other.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.remove(0);
        s.remove(1);
        s.commit(0, id(0), 5 * QUANTUM);
        s.commit(1, id(1), QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        assert_eq!(order_of(&s), [1, 0]);
    }

    #[test]
    fn a_stream_moved_to_another_bucket_starts_on_its_turn() {
        // Stream 0 is served five quanta at once and then moves to another urgency, whose
        // streams have not been served yet. What it was served counts only where it was served.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.insert(2, id(2), inc(1, 4));
        s.insert(3, id(3), inc(1, 4));
        s.commit(0, id(0), 5 * QUANTUM);
        s.insert(0, id(0), inc(1, 4));
        assert_eq!(order_of(&s), [1, 2, 3, 0]);
        s.commit(2, id(2), QUANTUM);
        s.commit(3, id(3), QUANTUM);
        assert_eq!(order_of(&s), [1, 0, 2, 3]);
    }

    #[test]
    fn a_stream_that_reuses_a_slot_owes_nothing_for_its_last_stream() {
        // Stream 0 leaves with five quanta committed after it left and is reaped, and the next
        // stream opened takes its slot.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.remove(0);
        s.commit(0, id(0), 5 * QUANTUM);
        s.insert(0, id(7), inc(1, 3));
        assert_eq!(order_of(&s), [1, 0]);
        s.commit(1, id(1), QUANTUM);
        assert_eq!(order_of(&s), [0, 1]);
    }

    #[test]
    fn reordering_within_a_bucket_keeps_what_an_incremental_stream_was_served() {
        // `order` does not place an incremental stream, so a new one leaves it in its bucket.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.commit(0, id(0), 5 * QUANTUM);
        let reordered = SendOrder {
            order: 9,
            ..inc(1, 3)
        };
        s.insert(0, id(0), reordered);
        assert_eq!(s.order(0), Some(reordered));
        s.commit(1, id(1), QUANTUM);
        assert_eq!(order_of(&s), [1, 0]);
    }

    #[test]
    fn bytes_sealed_behind_the_front_count_against_the_next_turn() {
        // A packet can carry several streams of one bucket; every byte sealed counts, wherever
        // the stream was in the walk.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        s.commit(0, id(0), 100);
        s.commit(1, id(1), 1100);
        s.commit(0, id(0), 1100);
        s.commit(1, id(1), 100);
        // Each has been served a quantum, so the turn is back with the first.
        assert_eq!(order_of(&s), [0, 1], "front");
    }

    #[test]
    fn incremental_streams_share_bytes_fairly_when_packets_carry_several() {
        // Each packet walks the bucket and every stream writes up to its frame size into the
        // room left, so most packets carry two or three streams.
        let mut s = Scheduler::new(QUANTUM);
        let frame = [1200, 700, 450];
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        let mut sent = [0u64; 3];
        for _ in 0..3000 {
            let mut room = QUANTUM;
            let mut sealed = Vec::new();
            let mut cursor = Cursor::default();
            while let Some(slot) = s.next(&mut cursor) {
                let bytes = room.min(frame[slot as usize]);
                room -= bytes;
                sealed.push((slot, bytes));
                if room == 0 {
                    break;
                }
            }
            for (slot, bytes) in sealed {
                sent[slot as usize] += bytes;
                s.commit(slot, id(slot), bytes);
            }
        }
        let most = sent.iter().max().unwrap();
        let least = sent.iter().min().unwrap();
        assert!(most - least <= 2 * QUANTUM, "bytes per stream: {sent:?}");
    }

    /// Builds `packets` packets of `QUANTUM` bytes and commits once per run of `run` packets,
    /// in the order the streams first sealed bytes. Each packet walks a fresh cursor and every
    /// stream it visits writes up to its frame size into the room left; the frames are such
    /// that every packet fills. Returns the bytes each stream sealed in each packet.
    fn fill(s: &mut Scheduler, frame: &[u64], packets: usize, run: usize) -> Vec<Vec<u64>> {
        let mut packets_sealed = Vec::new();
        let mut run_sealed = vec![0u64; frame.len()];
        let mut sealers = Vec::new();
        for packet in 0..packets {
            let mut room = QUANTUM;
            let mut sealed = vec![0u64; frame.len()];
            let mut cursor = Cursor::default();
            while let Some(slot) = s.next(&mut cursor) {
                let bytes = room.min(frame[slot as usize]);
                room -= bytes;
                sealed[slot as usize] += bytes;
                if bytes > 0 && !sealers.contains(&slot) {
                    sealers.push(slot);
                }
                if room == 0 {
                    break;
                }
            }
            assert_eq!(room, 0, "packet {packet} has room left");
            for (total, bytes) in run_sealed.iter_mut().zip(&sealed) {
                *total += bytes;
            }
            packets_sealed.push(sealed);
            if (packet + 1) % run == 0 {
                for slot in sealers.drain(..) {
                    s.commit(
                        slot,
                        id(slot),
                        std::mem::take(&mut run_sealed[slot as usize]),
                    );
                }
            }
        }
        packets_sealed
    }

    /// Returns the bytes each stream sealed over `packets`.
    fn totals(packets: &[Vec<u64>]) -> Vec<u64> {
        let mut sent = vec![0; packets.first().map_or(0, Vec::len)];
        for packet in packets {
            for (total, bytes) in sent.iter_mut().zip(packet) {
                *total += bytes;
            }
        }
        sent
    }

    /// Returns the most consecutive packets in which stream `slot` did not seal any bytes.
    fn longest_wait(packets: &[Vec<u64>], slot: usize) -> usize {
        let (mut longest, mut current) = (0, 0);
        for packet in packets {
            current = if packet[slot] == 0 { current + 1 } else { 0 };
            longest = longest.max(current);
        }
        longest
    }

    #[test]
    fn a_stream_that_filled_behind_a_short_writer_is_not_made_to_wait_for_it() {
        // Stream 0 writes 100 bytes a packet and stays scheduled, and stream 1 fills the rest
        // of each packet. Only stream 1 could use that room, so once stream 0 fills packets too
        // the two soon take turns.
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), inc(1, 3));
        s.insert(1, id(1), inc(1, 3));
        fill(&mut s, &[100, 1200], 3000, 1);
        let after = fill(&mut s, &[1200, 1200], 20, 1);
        let waits = [longest_wait(&after, 0), longest_wait(&after, 1)];
        assert!(
            waits[0] <= 3 && waits[1] <= 3,
            "longest waits {waits:?}, bytes per stream {:?}",
            totals(&after)
        );
    }

    #[test]
    fn streams_filling_behind_a_short_writer_share_the_room_it_leaves() {
        // Stream 0 writes 100 bytes a packet and stays scheduled. Streams 1 and 2 always have
        // data, so they take turns at the rest of each packet.
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        let sent = totals(&fill(&mut s, &[100, 1200, 1200], 3000, 1));
        assert!(
            sent[1].abs_diff(sent[2]) <= 2 * QUANTUM,
            "bytes per stream: {sent:?}"
        );
    }

    #[test]
    fn a_paused_stream_in_front_does_not_stop_the_others_taking_turns() {
        // A paused stream stays scheduled for its lost bytes but does not write new ones.
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        let sent = totals(&fill(&mut s, &[0, 1200, 1200], 3000, 1));
        assert!(
            sent[1].abs_diff(sent[2]) <= 2 * QUANTUM,
            "bytes per stream: {sent:?}"
        );
    }

    #[test]
    fn streams_filling_behind_a_short_writer_take_turns_by_gso_run() {
        // Committing once per GSO run of ten packets: the stream that fills behind stream 0
        // fills the whole run, and the next run goes to the other.
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        let sent = totals(&fill(&mut s, &[100, 1200, 1200], 3000, 10));
        assert!(
            sent[1].abs_diff(sent[2]) <= 10 * QUANTUM,
            "bytes per stream: {sent:?}"
        );
    }

    /// Builds GSO runs of `QUANTUM`-byte packets, `runs` packets at a time, from pull streams
    /// that stage up to `cap` bytes each. Each packet walks a fresh cursor and every stream it
    /// visits writes what it has staged into the room left; a stream that runs out leaves the
    /// scheduler at once, as the guard unschedules it during the build. After each run the
    /// streams that sealed bytes are committed in the order they first wrote, and then every
    /// producer tops its stream up to its cap, which brings a drained stream back. Returns the
    /// bytes each stream sealed.
    fn pull(s: &mut Scheduler, cap: &[u64], runs: impl IntoIterator<Item = usize>) -> Vec<u64> {
        let mut staged = cap.to_vec();
        let mut sent = vec![0u64; cap.len()];
        for (slot, _) in cap.iter().enumerate() {
            s.insert(slot as u32, id(slot as u32), inc(1, 3));
        }
        for packets in runs {
            let mut run_sealed = vec![0u64; cap.len()];
            let mut sealers = Vec::new();
            for _ in 0..packets {
                let mut room = QUANTUM;
                let mut cursor = Cursor::default();
                while let Some(slot) = s.next(&mut cursor) {
                    let at = slot as usize;
                    let bytes = room.min(staged[at]);
                    room -= bytes;
                    staged[at] -= bytes;
                    run_sealed[at] += bytes;
                    if bytes > 0 && !sealers.contains(&slot) {
                        sealers.push(slot);
                    }
                    if staged[at] == 0 {
                        s.remove(slot);
                    }
                    if room == 0 {
                        break;
                    }
                }
            }
            for slot in sealers {
                let bytes = run_sealed[slot as usize];
                sent[slot as usize] += bytes;
                s.commit(slot, id(slot), bytes);
            }
            for (slot, &full) in cap.iter().enumerate() {
                staged[slot] = full;
                s.insert(slot as u32, id(slot as u32), inc(1, 3));
            }
        }
        sent
    }

    #[test]
    fn pull_streams_drained_by_runs_of_alternating_sizes_share_bytes_evenly() {
        // Both streams stage 10 packets, so a long run drains the stream in front, and a short
        // run follows each long one.
        let mut s = Scheduler::new(QUANTUM);
        let runs = (0..2000).map(|run| if run % 2 == 0 { 10 } else { 1 });
        let sent = pull(&mut s, &[10 * QUANTUM, 10 * QUANTUM], runs);
        assert!(
            sent[0].abs_diff(sent[1]) <= 10 * QUANTUM,
            "bytes per stream: {sent:?}"
        );
    }

    #[test]
    fn a_cursor_reads_without_changing_the_scheduler() {
        let mut s = Scheduler::new(QUANTUM);
        s.insert(0, id(0), seq(1, 3, 0));
        s.insert(1, id(1), inc(1, 3));
        s.insert(2, id(2), inc(1, 3));
        s.insert(3, id(3), inc(1, 3));
        s.insert(4, id(4), seq(2, 0, 0));
        let mut cursor = Cursor::default();
        assert_eq!(s.next(&mut cursor), Some(0));
        assert_eq!(s.next(&mut cursor), Some(1));
        // Walking is read-only: a fresh walk starts at the same place.
        assert_eq!(order_of(&s), [0, 1, 2, 3, 4]);
        // When a stream ahead of the walk leaves, the walk still visits the streams after it.
        let mut walk = cursor;
        s.remove(2);
        assert_eq!(s.next(&mut walk), Some(3));
        assert_eq!(s.next(&mut walk), Some(4));
        assert_eq!(s.next(&mut walk), None);
        assert_eq!(s.next(&mut walk), None);
    }

    #[test]
    fn a_walk_goes_on_when_the_stream_it_is_at_leaves() {
        // A build drains most streams it visits, and the guard unschedules each of them before
        // the walk moves on.
        let mut s = Scheduler::new(QUANTUM);
        for slot in 0..3 {
            s.insert(slot, id(slot), seq(1, 3, u128::from(slot)));
        }
        for slot in 3..6 {
            s.insert(slot, id(slot), inc(1, 3));
        }
        s.insert(6, id(6), inc(1, 4));
        s.insert(7, id(7), seq(1, 4, 0));
        let mut cursor = Cursor::default();
        let mut visited = Vec::new();
        while let Some(slot) = s.next(&mut cursor) {
            visited.push(slot);
            if slot != 1 && slot != 4 {
                s.remove(slot);
            }
        }
        assert_eq!(visited, [0, 1, 2, 3, 4, 5, 7, 6], "visited");
        assert_eq!(order_of(&s), [1, 4]);
    }

    /// Returns the depth of the treap rooted at `slot`.
    fn treap_depth(s: &Scheduler, slot: u32) -> usize {
        if slot == NIL {
            return 0;
        }
        let node = &s.nodes[slot as usize];
        1 + treap_depth(s, node.left).max(treap_depth(s, node.right))
    }

    #[test]
    fn many_sequential_streams_stay_ordered_and_balanced() {
        let mut s = Scheduler::new(QUANTUM);
        let mut reference = std::collections::BTreeSet::new();
        let mut rng = 0x1234_5678u32;
        let mut random = move || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };
        for step in 0..4000 {
            let slot = random() % 400;
            if let Some(order) = s.order(slot) {
                assert!(s.remove(slot));
                reference.remove(&(bucket_key(order), order.order, slot));
            } else {
                let order = seq(
                    (random() % 2) as u8,
                    (random() % 2) as u8,
                    u128::from(random() % 50),
                );
                s.insert(slot, id(slot), order);
                reference.insert((bucket_key(order), order.order, slot));
            }
            if step % 97 == 0 {
                let expected: Vec<u32> = reference.iter().map(|&(_, _, slot)| slot).collect();
                assert_eq!(order_of(&s), expected, "step {step}");
            }
        }
        assert_eq!(s.len(), reference.len());
        for bucket in &s.buckets {
            let depth = treap_depth(&s, bucket.seq.root);
            assert!(depth <= 40, "treap depth {depth} for at most 400 streams");
        }
    }

    #[test]
    fn scheduling_allocates_nothing_once_warm() {
        let mut s = Scheduler::new(QUANTUM);
        let orders = [seq(0, 0, 1), seq(1, 3, 2), inc(1, 3), inc(1, 5)];
        for slot in 0..64 {
            s.insert(slot, id(slot), orders[slot as usize % 4]);
        }
        let capacity =
            |s: &Scheduler| (s.nodes.capacity(), s.buckets.capacity(), s.index.capacity());
        let warm = capacity(&s);
        for round in 0..1000u32 {
            let slot = round % 64;
            let first = s.iter().next().unwrap();
            s.commit(first, id(first), 1000);
            s.remove(slot);
            s.insert(slot, id(slot), orders[(round as usize + 1) % 4]);
        }
        assert_eq!(capacity(&s), warm);
    }
}
