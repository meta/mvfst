/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests that every [`Prioritizer`] must pass, run on each plug through the stream guard, which
//! keeps the plug up to date as a connection does.
//!
//! - A walk from the start yields every scheduled stream, each once.
//! - A walk goes on in its order when streams leave during it, as a build that drains the streams
//!   it visits does, and does not yield a stream twice.
//! - A commit for a stream that left does not bring it back or change what the others get, and a
//!   commit for a stream whose slot was reaped does not change the order or the split.
//! - The split of the staging budget hands out more than the budget has left only by the bytes
//!   that peers of an incremental bucket hold beyond an equal part, and streams that stage their
//!   allowances do not take the connection past its budget.
//! - An `Opened`, `Readable` or `Finished` edge taken without a guard leaves nothing for a full
//!   reindex to change, and a connection delivers the same edges in the same order whether it
//!   takes them without a guard or through one.
//!
//! Tests at the end pin what holds only for the default plug: a commit for a stream that left
//! does not change anything a connection could observe later, a stream's allowance falls by
//! exactly what the stream stages, and an incremental stream that keeps filling packets gets a
//! turn within as many packets as its bucket has streams.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportParameters;
use mvfstr_wire::VarInt;

use super::conn::StreamState;
use super::guard::Edge;
use super::guard::List;
use super::guard::StreamData;
use super::guard::Streams;
use super::guard::census;
use super::map::Half;
use super::prioritizer::FairShare;
use super::prioritizer::Figures;
use super::prioritizer::MvfstOrder;
use super::prioritizer::Peer;
use super::prioritizer::Prioritizer;
use super::recv_buf::PagePool;
use super::scheduler::SendOrder;
use super::send_buf::Pending;
use super::state::RecvState;
use super::state::SendState;
use crate::AppCode;
use crate::SendError;
use crate::StreamReady;
use crate::TransportConfig;
use crate::recovery::sent::ControlKind;
use crate::recovery::test_epoch;
use crate::testing::TestRng;

/// The per-stream cap on staged bytes.
const CAP: u64 = 64 * 1024;

/// The most streams a harness keeps open.
const MAX_LIVE: usize = 24;

const CODE: AppCode = AppCode::from_u32(1);

/// Free bytes of the staging budget the split checks try, besides some read from the streams.
const LEFTS: [u64; 6] = [0, 1, 1200, 16 * 1024, 100_000, 1 << 40];

/// A stream's data parts as the tests set them.
#[derive(Clone, Copy, Debug, Default)]
struct Data {
    /// Whether it has bytes for the wire, which schedules it.
    wire: bool,
    /// Whether its push sender was refused bytes, which is demand without staged bytes.
    refused: bool,
    figures: Figures,
}

impl StreamData for Data {
    fn wire_data(&self) -> Option<Pending> {
        self.wire.then_some(Pending::New { bytes: 1 })
    }

    fn has_pull_room(&self) -> bool {
        self.figures.room > 0
    }

    fn has_demand(&self) -> bool {
        self.figures.staged > 0 || self.refused
    }

    fn figures(&self) -> Figures {
        self.figures
    }
}

/// Returns figures for `staged` bytes and `credit` bytes of stream credit beyond them.
fn figures(staged: u64, credit: u64) -> Figures {
    Figures {
        room: credit.min(CAP - staged),
        credit,
        staged,
    }
}

/// The bucket of the split a stream at `order` is a peer of: class, urgency, incremental.
fn bucket(order: SendOrder) -> (u8, u8, bool) {
    (order.class, order.urgency.min(7), order.incremental)
}

/// One call of [`Prioritizer::split`]'s callback: slot, peer, allowance, share.
type Split = (u32, Peer, u64, u64);

/// Returns a random number below `n`.
fn below(rng: &mut TestRng, n: u64) -> u64 {
    rng.next_u64() % n
}

/// Returns a random element of `from`, if it has any.
fn pick<T: Copy>(rng: &mut TestRng, from: &[T]) -> Option<T> {
    if from.is_empty() {
        return None;
    }
    Some(from[below(rng, from.len() as u64) as usize])
}

/// A server's streams ordered by `P`, changed by seeded random operations.
struct Harness<P: Prioritizer> {
    streams: Streams<Data, P>,
    rng: TestRng,
    /// The open streams.
    live: Vec<StreamId>,
    /// The reaped streams with the slots they held.
    reaped: Vec<(u32, StreamId)>,
}

impl<P: Prioritizer> Harness<P> {
    fn new(seed: u64) -> Self {
        let mut streams = Streams::new(Side::Server, 10, 10, 1200);
        streams.on_peer_max_streams(Dir::Uni, 1 << 20).unwrap();
        Harness {
            streams,
            rng: TestRng::new(seed),
            live: Vec::new(),
            reaped: Vec::new(),
        }
    }

    fn below(&mut self, n: u64) -> u64 {
        below(&mut self.rng, n)
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> Option<T> {
        pick(&mut self.rng, from)
    }

    /// Returns a random order: classes 0 and 1, urgencies up to 9 (counted as 7), sequential or
    /// incremental, order fields 0 to 2.
    fn order(&mut self) -> SendOrder {
        let r = self.rng.next_u64();
        SendOrder {
            class: [0, 1, 1, 1][(r % 4) as usize],
            urgency: [0, 3, 3, 5, 7, 9][((r >> 8) % 6) as usize],
            incremental: (r >> 16).is_multiple_of(2),
            order: u128::from((r >> 24) % 3),
        }
    }

    fn figures(&mut self) -> Figures {
        let staged = [0, 0, 1200, 30_000, CAP][self.below(5) as usize];
        let credit = [0, 5_000, 40_000, 1 << 20][self.below(4) as usize];
        figures(staged, credit)
    }

    fn slot(&self, id: StreamId) -> u32 {
        self.streams.get(id).expect("a live stream").slot()
    }

    fn id(&self, slot: u32) -> StreamId {
        self.streams.get_slot(slot).expect("a live slot").id()
    }

    fn data(&self, id: StreamId) -> Data {
        *self.streams.get(id).expect("a live stream").data()
    }

    fn set(&mut self, id: StreamId, f: impl FnOnce(&mut Data)) {
        f(self.streams.stream(id).expect("a live stream").data_mut());
    }

    /// Opens a stream at `order` with `data`, its producer woken unless `pending`.
    fn open_with(&mut self, order: SendOrder, data: Data, pending: bool) -> StreamId {
        let mut stream = self
            .streams
            .open_local(Dir::Uni, order, data)
            .expect("stream credit");
        stream.set_producer_pending(pending);
        let id = stream.id();
        drop(stream);
        self.live.push(id);
        id
    }

    /// Opens a stream at a random order with random data parts, unless the most are open.
    fn open(&mut self, wire: bool) -> Option<StreamId> {
        if self.live.len() >= MAX_LIVE {
            return None;
        }
        let order = self.order();
        let data = Data {
            wire,
            refused: self.below(8) == 0,
            figures: self.figures(),
        };
        let pending = self.below(4) == 0;
        Some(self.open_with(order, data, pending))
    }

    /// Sends every byte the stream has: it leaves the wire order, and its staged bytes are gone.
    fn drain(&mut self, id: StreamId) {
        self.set(id, |d| {
            d.wire = false;
            d.figures = figures(0, d.figures.credit);
        });
    }

    /// Stages bytes on the stream for the wire.
    fn refill(&mut self, id: StreamId) {
        let staged = [1200, 30_000, CAP][self.below(3) as usize];
        self.set(id, |d| {
            d.wire = true;
            d.figures = figures(staged, d.figures.credit);
        });
    }

    /// Resets the stream, acknowledges the reset and delivers its edges, which reaps it.
    fn reap(&mut self, id: StreamId) {
        let slot = self.slot(id);
        let mut stream = self.streams.stream(id).expect("a live stream");
        stream
            .reset(CODE, 0)
            .expect("a send half that takes a reset");
        stream.on_reset_acked().expect("a reset that was sent");
        drop(stream);
        while self.streams.stream(id).expect("a live stream").take_edge()
            != Some(StreamReady::Closed)
        {}
        assert!(self.streams.get(id).is_none(), "stream {id} is reaped");
        self.live.retain(|&live| live != id);
        self.reaped.push((slot, id));
    }

    fn bytes(&mut self) -> u64 {
        [1, 1200, 1500, 12_000, CAP][self.below(5) as usize]
    }

    /// Runs one random operation and returns its name.
    fn step(&mut self) -> &'static str {
        let roll = self.below(100);
        let live = self.live.clone();
        let Some(id) = self.pick(&live).filter(|_| roll >= 12) else {
            let wire = self.below(3) != 0;
            self.open(wire);
            return "open";
        };
        match roll {
            12..30 => {
                if self.data(id).wire {
                    self.drain(id);
                    "drain"
                } else {
                    self.refill(id);
                    "refill"
                }
            }
            30..40 => {
                let order = self.order();
                self.streams
                    .stream(id)
                    .expect("a live stream")
                    .set_order(order);
                "set_order"
            }
            40..52 => {
                let (figures, refused) = (self.figures(), self.below(8) == 0);
                self.set(id, |d| (d.figures, d.refused) = (figures, refused));
                "figures"
            }
            52..58 => {
                let pending = self.below(2) == 0;
                self.streams
                    .stream(id)
                    .expect("a live stream")
                    .set_producer_pending(pending);
                "producer"
            }
            58..84 => {
                let (slot, bytes) = (self.slot(id), self.bytes());
                self.streams.commit(slot, id, bytes);
                "commit"
            }
            84..92 => {
                let reaped = self.reaped.clone();
                if let Some((slot, id)) = self.pick(&reaped) {
                    let bytes = self.bytes();
                    self.streams.commit(slot, id, bytes);
                }
                "late_commit"
            }
            _ => {
                self.reap(id);
                "reap"
            }
        }
    }

    /// Returns the streams a walk from the start yields, in order.
    fn walk(&self) -> Vec<u32> {
        let plug = self.streams.prioritizer();
        let mut cursor = P::Cursor::default();
        let walk: Vec<u32> = std::iter::from_fn(|| plug.next(&mut cursor)).collect();
        assert_eq!(
            plug.next(&mut cursor),
            None,
            "a finished walk stays finished"
        );
        walk
    }

    /// Returns the slots of the streams with bytes for the wire, sorted.
    fn scheduled(&self) -> Vec<u32> {
        let mut slots: Vec<u32> = self
            .live
            .iter()
            .filter(|&&id| self.data(id).wire)
            .map(|&id| self.slot(id))
            .collect();
        slots.sort_unstable();
        slots
    }

    /// Returns the slots of the streams with demand, sorted.
    fn demand(&self) -> Vec<u32> {
        let mut slots: Vec<u32> = self
            .live
            .iter()
            .map(|&id| self.streams.get(id).expect("a live stream").peer())
            .filter(|peer| peer.demand)
            .map(|peer| self.slot(peer.id))
            .collect();
        slots.sort_unstable();
        slots
    }

    /// Returns the sum of the rooms of the streams with demand.
    fn rooms(&self) -> u64 {
        self.demand()
            .iter()
            .map(|&slot| self.streams.get_slot(slot).unwrap().peer().figures.room)
            .sum()
    }

    /// Returns the staged bytes of each stream with demand in the bucket of the split at `key`.
    fn staged_in(&self, key: (u8, u8, bool)) -> Vec<u64> {
        self.live
            .iter()
            .map(|&id| self.streams.get(id).expect("a live stream").peer())
            .filter(|peer| peer.demand && bucket(peer.order) == key)
            .map(|peer| peer.figures.staged)
            .collect()
    }

    /// Returns the calls of the split of `left` free bytes, in order.
    fn split(&mut self, left: u64) -> Vec<Split> {
        let mut calls = Vec::new();
        self.streams.split(left, |slot, peer, allowance, share| {
            calls.push((slot, peer, allowance, share));
        });
        calls
    }

    /// Returns the allowance of every open stream of `left` free bytes, by stream ID.
    fn allowances(&self, left: u64) -> Vec<(StreamId, u64)> {
        let mut out: Vec<_> = self
            .live
            .iter()
            .map(|&id| {
                let peer = self.streams.get(id).expect("a live stream").peer();
                (id, self.streams.allowance(peer, left))
            })
            .collect();
        out.sort_by_key(|&(id, _)| id.into_inner());
        out
    }

    /// Stages bytes for the wire on about half the open streams that do not have any.
    fn refill_some(&mut self) {
        for id in self.live.clone() {
            if !self.data(id).wire && self.below(2) == 0 {
                self.refill(id);
            }
        }
    }
}

/// Returns two harnesses from `seed` after the same `steps` random operations, with bytes for the
/// wire staged on about half the streams that did not have any.
fn twins<P: Prioritizer>(seed: u64, steps: usize) -> (Harness<P>, Harness<P>) {
    let (mut a, mut b) = (Harness::new(seed), Harness::new(seed));
    for _ in 0..steps {
        a.step();
        b.step();
    }
    a.refill_some();
    b.refill_some();
    (a, b)
}

fn sorted(mut slots: Vec<u32>) -> Vec<u32> {
    slots.sort_unstable();
    slots
}

/// Returns the split's calls as `(slot, allowance, share)`, sorted by slot.
fn by_slot(calls: &[Split]) -> Vec<(u32, u64, u64)> {
    let mut out: Vec<_> = calls.iter().map(|&(slot, _, a, s)| (slot, a, s)).collect();
    out.sort_unstable();
    out
}

/// Checks that a walk from the start yields every scheduled stream once, and returns the walk.
fn check_walk<P: Prioritizer>(h: &Harness<P>, at: &str) -> Vec<u32> {
    let walk = h.walk();
    let slots = sorted(walk.clone());
    assert!(
        slots.windows(2).all(|w| w[0] != w[1]),
        "{at}: the walk yields a stream twice: {walk:?}"
    );
    assert_eq!(
        slots,
        h.scheduled(),
        "{at}: the walk yields every scheduled stream"
    );
    assert_eq!(walk.len(), h.streams.prioritizer().len(), "{at}: streams");
    assert_eq!(
        h.streams.prioritizer().iter().collect::<Vec<_>>(),
        walk,
        "{at}: the iterator yields the walk"
    );
    walk
}

/// What a split check found, so that a run that does not reach the interesting states fails.
#[derive(Debug, Default)]
struct SplitSeen {
    /// Splits that handed out an allowance.
    handed: usize,
    /// Incremental buckets with several peers.
    shared: usize,
    /// Incremental buckets with several peers, one of which holds more than an equal part of what
    /// reaches the bucket and what its peers hold.
    held_over: usize,
    /// Splits of some free bytes but fewer than the streams with demand have room for.
    tight: usize,
}

/// Checks the split of `left` free bytes: each stream with demand once, as it reads, and each
/// allowance within its room, its share and what the streams ahead leave. A bucket's sequential
/// streams take their allowances in turn. An incremental bucket's peers each take at most what
/// reaches the bucket, and together more only by what they hold beyond an equal part of what
/// reaches it and what they hold; the split hands out more than `left` only by that. Checks too
/// that each stream's allowance is what the split gives it. Returns the calls.
fn check_split<P: Prioritizer>(
    h: &mut Harness<P>,
    left: u64,
    seen: &mut SplitSeen,
    at: &str,
) -> Vec<Split> {
    let calls = h.split(left);
    let demand = h.demand();
    let mut slots = Vec::new();
    for &(slot, peer, allowance, share) in &calls {
        let stream = h
            .streams
            .get_slot(slot)
            .expect("the split names live streams");
        assert_eq!(
            peer,
            stream.peer(),
            "{at}: the peer the split passes for slot {slot}"
        );
        assert!(peer.demand, "{at}: slot {slot} is split without demand");
        assert!(
            allowance <= peer.figures.room && allowance <= share && allowance <= left,
            "{at}: slot {slot} gets {allowance} of {left}, beyond its room or its share {share}: \
             {peer:?}"
        );
        slots.push(slot);
    }
    let slots = sorted(slots);
    assert!(
        slots.windows(2).all(|w| w[0] != w[1]),
        "{at}: the split names a stream twice: {calls:?}"
    );
    assert!(
        slots.iter().all(|slot| demand.contains(slot)),
        "{at}: the split names a stream without demand"
    );
    if left == 1 << 40 {
        assert_eq!(slots, demand, "{at}: every stream with demand is split");
    }
    seen.tight += usize::from(left > 0 && left < h.rooms());
    seen.handed += usize::from(calls.iter().any(|c| c.2 > 0));
    let runs: Vec<_> = calls
        .chunk_by(|a, b| bucket(a.1.order) == bucket(b.1.order))
        .map(|group| bucket(group[0].1.order))
        .collect();
    assert!(
        runs.windows(2).all(|w| w[0] < w[1]),
        "{at}: each bucket's calls come in one run, in wire order: {runs:?}"
    );
    let (mut remaining, mut beyond) = (left, 0);
    for group in calls.chunk_by(|a, b| bucket(a.1.order) == bucket(b.1.order)) {
        if group[0].1.order.incremental {
            let reach = remaining;
            let key = bucket(group[0].1.order);
            let staged = h.staged_in(key);
            let peers = staged.len() as u64;
            let equal = reach.saturating_add(staged.iter().sum()) / peers.max(1);
            let over: u64 = staged.iter().map(|s| s.saturating_sub(equal)).sum();
            let mut sum = 0u64;
            for &(slot, _, allowance, _) in group {
                assert!(
                    allowance <= reach,
                    "{at}: incremental slot {slot} gets {allowance}, but {reach} reach its bucket"
                );
                sum += allowance;
            }
            assert!(
                sum <= reach + over,
                "{at}: the {peers} peers of {key:?} get {sum}, beyond the {reach} that reach them \
                 and the {over} they hold over an equal part of {equal}"
            );
            seen.shared += usize::from(peers > 1);
            seen.held_over += usize::from(peers > 1 && over > 0);
            remaining -= sum.min(reach);
            beyond += over;
        } else {
            for &(slot, _, allowance, _) in group {
                assert!(
                    allowance <= remaining,
                    "{at}: sequential slot {slot} gets {allowance}, but the streams ahead leave \
                     {remaining}"
                );
                remaining -= allowance;
            }
        }
    }
    let total: u64 = calls.iter().map(|c| c.2).sum();
    assert!(
        total <= left + beyond,
        "{at}: the split hands out {total} of {left}, beyond the {beyond} that incremental peers \
         hold over an equal part"
    );
    for (id, allowance) in h.allowances(left) {
        let slot = h.slot(id);
        let peer = h.streams.get(id).expect("a live stream").peer();
        if peer.demand {
            let split = calls.iter().find(|c| c.0 == slot).map_or(0, |c| c.2);
            assert_eq!(
                allowance, split,
                "{at}: the allowance of {id} is what the split gives it"
            );
        } else {
            assert!(
                allowance <= left.min(peer.figures.room),
                "{at}: {id}, without demand, is allowed {allowance} of {left}"
            );
        }
    }
    calls
}

/// Checks that `a` and `b` order and split their streams alike: the same walk, the same split,
/// the same allowances and what the plugs keep about each slot.
fn assert_same<P: Prioritizer>(a: &mut Harness<P>, b: &mut Harness<P>, at: &str) {
    assert_eq!(a.live, b.live, "{at}: the open streams");
    assert_eq!(a.walk(), b.walk(), "{at}: the walk");
    for left in LEFTS {
        assert_eq!(a.split(left), b.split(left), "{at}: the split of {left}");
        assert_eq!(
            a.allowances(left),
            b.allowances(left),
            "{at}: the allowances of {left}"
        );
    }
    let slots = a.live.iter().map(|&id| a.slot(id));
    let reaped = a.reaped.iter().map(|&(slot, _)| slot);
    for slot in slots.chain(reaped) {
        let digest = |h: &Harness<P>| format!("{:?}", h.streams.prioritizer().digest(slot));
        assert_eq!(
            digest(a),
            digest(b),
            "{at}: what the plug keeps of slot {slot}"
        );
    }
}

fn a_walk_from_the_start_yields_every_scheduled_stream_once<P: Prioritizer>() {
    for seed in 1..=4 {
        let mut h = Harness::<P>::new(seed);
        let (mut longest, mut buckets) = (0, 0);
        for step in 0..600 {
            let op = h.step();
            let at = format!("seed {seed} step {step} {op}");
            h.streams.assert_indexed();
            let walk = check_walk(&h, &at);
            longest = longest.max(walk.len());
            let mut keys: Vec<_> = walk
                .iter()
                .map(|&slot| bucket(h.streams.prioritizer().order(slot).unwrap()))
                .collect();
            keys.dedup();
            buckets = buckets.max(keys.len());
        }
        assert!(
            longest >= 12 && buckets >= 6 && h.reaped.len() >= 20,
            "seed {seed} reached too little: {longest} scheduled, {buckets} buckets, {} reaped",
            h.reaped.len()
        );
    }
}

fn a_walk_goes_on_in_order_when_streams_leave_and_does_not_yield_a_stream_twice<P: Prioritizer>() {
    let (mut left_ahead, mut joined, mut longest) = (0, 0, 0);
    for seed in 11..=14 {
        let mut h = Harness::<P>::new(seed);
        for round in 0..60 {
            for _ in 0..8 {
                h.step();
            }
            h.refill_some();
            let at = format!("seed {seed} round {round}");
            let start = check_walk(&h, &at);
            longest = longest.max(start.len());
            // A build drains most of the streams it visits, and other streams drain or join too.
            let (mut yielded, mut left, mut new) = (Vec::new(), Vec::new(), Vec::new());
            let mut cursor = P::Cursor::default();
            while let Some(slot) = h.streams.prioritizer().next(&mut cursor) {
                assert!(
                    !yielded.contains(&slot),
                    "{at}: slot {slot} is yielded twice, after {yielded:?} from {start:?}"
                );
                yielded.push(slot);
                if h.below(4) != 0 {
                    h.drain(h.id(slot));
                }
                let scheduled = h.scheduled();
                if h.below(3) == 0
                    && let Some(other) = h.pick(&scheduled)
                {
                    h.drain(h.id(other));
                    if start.contains(&other) && !yielded.contains(&other) {
                        left.push(other);
                    }
                }
                if h.below(5) == 0
                    && let Some(id) = h.open(true)
                {
                    new.push(h.slot(id));
                }
                h.streams.assert_indexed();
            }
            assert_eq!(
                h.streams.prioritizer().next(&mut cursor),
                None,
                "{at}: finished"
            );
            let old: Vec<u32> = yielded
                .iter()
                .copied()
                .filter(|slot| start.contains(slot))
                .collect();
            let want: Vec<u32> = start
                .iter()
                .copied()
                .filter(|slot| !left.contains(slot))
                .collect();
            assert_eq!(
                old, want,
                "{at}: the walk yields the streams that did not leave ahead of it, in order"
            );
            assert!(
                yielded.iter().all(|s| start.contains(s) || new.contains(s)),
                "{at}: the walk yields only streams scheduled at its start or new ones"
            );
            left_ahead += left.len();
            joined += new.len();
        }
    }
    assert!(
        left_ahead >= 300 && joined >= 80 && longest >= 12,
        "too little reached: {left_ahead} left ahead of the walk, {joined} joined, {longest} long"
    );
}

fn a_commit_after_a_leave_does_not_bring_the_stream_back<P: Prioritizer>() {
    let (mut incremental, mut sequential, mut with_demand) = (0, 0, 0);
    for seed in 21..=36 {
        let picks = twins::<P>(seed, 120).0.walk().len();
        for pick in 0..picks {
            for bytes in [1, 1200, CAP] {
                let (mut a, mut b) = twins::<P>(seed, 120);
                let slot = a.walk()[pick];
                let id = a.id(slot);
                let at = format!("seed {seed} slot {slot} {bytes} bytes");
                // The build drains the stream and the guard unschedules it before the commit.
                a.drain(id);
                b.drain(id);
                a.streams.commit(slot, id, bytes);
                a.streams.assert_indexed();
                assert_eq!(
                    a.streams.prioritizer().order(slot),
                    None,
                    "{at}: unscheduled"
                );
                let walk = check_walk(&a, &at);
                assert!(!walk.contains(&slot), "{at}: the walk yields it again");
                assert_eq!(
                    sorted(walk),
                    sorted(b.walk()),
                    "{at}: the walk yields the same streams"
                );
                for left in LEFTS {
                    let mut seen = SplitSeen::default();
                    let calls = check_split(&mut a, left, &mut seen, &at);
                    assert_eq!(
                        by_slot(&calls),
                        by_slot(&b.split(left)),
                        "{at}: the split of {left}"
                    );
                    assert_eq!(
                        a.allowances(left),
                        b.allowances(left),
                        "{at}: the allowances of {left}"
                    );
                }
                let peer = a.streams.get(id).unwrap().peer();
                incremental += usize::from(peer.order.incremental);
                sequential += usize::from(!peer.order.incremental);
                with_demand += usize::from(peer.demand);
            }
        }
    }
    assert!(
        incremental >= 100 && sequential >= 100 && with_demand >= 100,
        "too little reached: {incremental} incremental, {sequential} sequential, {with_demand} \
         with demand"
    );
}

fn a_commit_for_a_reaped_stream_does_not_change_the_order_or_the_split<P: Prioritizer>() {
    let (mut reused, mut trials) = (0, 0);
    for seed in 37..=50 {
        let picks = twins::<P>(seed, 120).0.live.len();
        for pick in 0..picks {
            let (mut a, mut b) = twins::<P>(seed, 120);
            let id = a.live[pick];
            let slot = a.slot(id);
            a.reap(id);
            b.reap(id);
            // Another stream may take the slot before the late commit.
            if pick % 2 == 0 {
                let order = SendOrder {
                    class: 1,
                    urgency: (pick % 8) as u8,
                    incremental: pick % 4 == 0,
                    order: 0,
                };
                let data = Data {
                    wire: true,
                    ..Data::default()
                };
                let new = a.open_with(order, data, false);
                b.open_with(order, data, false);
                reused += usize::from(a.slot(new) == slot);
            }
            let at = format!("seed {seed} slot {slot}");
            a.streams.commit(slot, id, 1200);
            a.streams.assert_indexed();
            assert_same(&mut a, &mut b, &at);
            for step in 0..30 {
                a.step();
                b.step();
                assert_same(&mut a, &mut b, &format!("{at}, step {step} after"));
            }
            trials += 1;
        }
    }
    assert!(
        trials >= 60 && reused >= 30,
        "too little reached: {trials} trials, {reused} reused slots"
    );
}

fn the_split_stays_within_the_staging_budget<P: Prioritizer>() {
    let mut seen = SplitSeen::default();
    for seed in 51..=54 {
        let mut h = Harness::<P>::new(seed);
        for step in 0..400 {
            let op = h.step();
            let at = format!("seed {seed} step {step} {op}");
            h.streams.assert_indexed();
            let rooms = h.rooms();
            for left in LEFTS.into_iter().chain([rooms / 3, rooms / 2, rooms]) {
                check_split(&mut h, left, &mut seen, &format!("{at}, {left} left"));
            }
        }
    }
    assert!(
        seen.handed >= 8000 && seen.shared >= 3000 && seen.held_over >= 800 && seen.tight >= 5000,
        "too little reached: {seen:?}"
    );
}

/// Bytes to stage, shared.
static ZEROS: [u8; 80 * 1024] = [0; 80 * 1024];

/// Returns a random order among a few buckets, so that streams often share one.
fn few_buckets(rng: &mut TestRng) -> SendOrder {
    SendOrder {
        class: 1,
        urgency: [3, 3, 5][below(rng, 3) as usize],
        incremental: below(rng, 4) != 0,
        order: u128::from(below(rng, 3)),
    }
}

fn staging_by_allowance_does_not_take_the_connection_past_its_budget<P: Prioritizer>() {
    let (mut full, mut pulled_streams, mut crowded) = (0, 0, 0);
    for seed in 61..=66 {
        let config = TransportConfig::builder()
            .build()
            .expect("a valid transport config");
        let mut s = StreamState::<P>::new(Side::Server, &config, PagePool::new());
        s.on_peer_params(&TransportParameters {
            initial_max_data: VarInt::from_u32(1 << 30),
            initial_max_stream_data_uni: VarInt::from_u32(100_000),
            initial_max_streams_uni: VarInt::from_u32(1000),
            ..TransportParameters::default()
        })
        .unwrap();
        let mut rng = TestRng::new(seed);
        let mut ids: Vec<StreamId> = Vec::new();
        for step in 0..500 {
            let at = format!("seed {seed} step {step}");
            // The budget follows the congestion window up and down.
            let budget =
                [48 * 1024, 128 * 1024, 256 * 1024, 512 * 1024][below(&mut rng, 4) as usize];
            let roll = below(&mut rng, 100);
            if roll < 10 || ids.is_empty() {
                if ids.len() < 40 {
                    let order = few_buckets(&mut rng);
                    let id = s.open(Dir::Uni, order).unwrap();
                    let pending = below(&mut rng, 3) == 0;
                    s.streams.stream(id).unwrap().set_producer_pending(pending);
                    ids.push(id);
                }
            } else if roll < 45 {
                let id = pick(&mut rng, &ids).unwrap();
                let len = below(&mut rng, ZEROS.len() as u64 + 1) as usize;
                let before = s.staged;
                let allowance = s.allowance(id, budget);
                assert!(
                    allowance <= budget.saturating_sub(before),
                    "{at}: {id} is allowed {allowance} with {before} of {budget} staged"
                );
                let _ = s.send(id, &mut Bytes::from_static(&ZEROS[..len]), budget);
                assert!(
                    s.staged <= before.max(budget),
                    "{at}: a send of {id} took {before} to {} past {budget}",
                    s.staged
                );
            } else if roll < 75 {
                s.collect_pull_ready(budget);
                let pulled: Vec<_> = (0..).map_while(|index| s.pulled(index)).collect();
                let left = budget.saturating_sub(s.staged);
                for &(id, allowance) in &pulled {
                    assert!(
                        allowance <= left,
                        "{at}: pull-ready {id} is allowed {allowance} of {left}"
                    );
                }
                // The allowances may add up to more than is left, which the sends check again.
                let rooms: u64 = pulled
                    .iter()
                    .map(|&(id, _)| {
                        s.streams
                            .get(id)
                            .expect("a live stream")
                            .peer()
                            .figures
                            .room
                    })
                    .sum();
                crowded += usize::from(rooms > left);
                for (id, allowance) in pulled {
                    let before = s.staged;
                    let len = (allowance as usize).min(ZEROS.len());
                    let _ = s.send(id, &mut Bytes::from_static(&ZEROS[..len]), budget);
                    assert!(
                        s.staged <= before.max(budget),
                        "{at}: a pulled send of {id} took {before} to {} past {budget}",
                        s.staged
                    );
                    pulled_streams += 1;
                }
            } else if roll < 85 {
                let id = pick(&mut rng, &ids).unwrap();
                let _ = s.reset(id, CODE);
            } else if roll < 93 {
                let id = pick(&mut rng, &ids).unwrap();
                let max = 100_000 + below(&mut rng, 200_000);
                let _ = s.on_max_stream_data(id, max);
            } else {
                let (id, order) = (pick(&mut rng, &ids).unwrap(), few_buckets(&mut rng));
                if let Some(mut stream) = s.streams.stream(id) {
                    stream.set_order(order);
                }
            }
            s.streams.assert_indexed();
            full += usize::from(s.staged + 1200 > budget);
        }
    }
    assert!(
        full >= 1200 && pulled_streams >= 100 && crowded >= 10,
        "too little reached: {full} steps at the budget, {pulled_streams} pulled sends, \
         {crowded} pulls whose streams had room for more than was left"
    );
}

/// What [`a_full_reindex_after_a_list_edge_changes_nothing`] reached.
#[derive(Debug, Default)]
struct ListEdgesSeen {
    /// `Opened`, `Readable` and `Finished` edges checked.
    edges: usize,
    /// Those that took their stream off the readiness list.
    left: usize,
    /// Those of closed streams, which stay on the readiness list for their `Closed` edge.
    closed: usize,
    /// Those of scheduled streams.
    scheduled: usize,
    /// Those of streams with demand that are not alone among their peers, which a guard reshares.
    reshared: usize,
}

impl<P: Prioritizer> Harness<P> {
    /// Opens the client's bidirectional stream `index` with a frame, at a random order with random
    /// data parts, and marks some of its data edges: `Readable`, then the FIN's `Finished`, then
    /// an end of both halves that closes it.
    fn open_peer(&mut self, index: u64) -> StreamId {
        let id = StreamId::new(Side::Client, Dir::Bi, index).expect("a stream index");
        let (order, figures, pending) = (self.order(), self.figures(), self.below(4) == 0);
        let data = Data {
            wire: self.below(3) != 0,
            refused: self.below(8) == 0,
            figures,
        };
        let marks = self.below(4);
        let mut stream = self
            .streams
            .peer_frame(id, Half::Recv, |_| (order, data))
            .expect("a stream within the limit")
            .expect("a new stream");
        stream.set_producer_pending(pending);
        if marks >= 1 {
            stream.mark(Edge::Readable);
        }
        drop(stream);
        if marks >= 2 {
            self.finish_peer(id);
        }
        if marks >= 3 {
            self.close_peer(id);
        }
        id
    }

    /// Delivers the FIN of peer stream `id` and every byte before it.
    fn finish_peer(&mut self, id: StreamId) {
        let mut stream = self.streams.stream(id).expect("a live stream");
        stream.on_fin();
        stream
            .on_all_received()
            .expect("a receive half in Size Known");
        stream.mark(Edge::Finished);
    }

    /// Reads every byte of peer stream `id`, whose FIN and bytes have arrived, and resets its send
    /// half with an acknowledged RESET_STREAM, which closes it.
    fn close_peer(&mut self, id: StreamId) {
        let mut stream = self.streams.stream(id).expect("a live stream");
        stream
            .on_all_data_read()
            .expect("a receive half in Data Recvd");
        stream
            .reset(CODE, 0)
            .expect("a send half that takes a reset");
        stream.on_reset_acked().expect("a reset that was sent");
    }

    /// Changes peer stream `id` at random through its guard: new bytes, its FIN, its close, its
    /// data parts, its order, its producer, or a commit.
    fn peer_step(&mut self, id: StreamId) {
        let stream = self.streams.get(id).expect("a live stream");
        let (recv, send, slot) = (stream.recv_state(), stream.send_state(), stream.slot());
        match self.below(7) {
            0 => self
                .streams
                .stream(id)
                .expect("a live stream")
                .mark(Edge::Readable),
            1 if recv == Some(RecvState::Recv) => self.finish_peer(id),
            2 if recv == Some(RecvState::DataRecvd) && send == Some(SendState::Ready) => {
                self.close_peer(id);
            }
            3 => {
                let (wire, figures, refused) =
                    (self.below(2) == 0, self.figures(), self.below(8) == 0);
                self.set(id, |d| {
                    (d.wire, d.figures, d.refused) = (wire, figures, refused)
                });
            }
            4 => {
                let order = self.order();
                self.streams
                    .stream(id)
                    .expect("a live stream")
                    .set_order(order);
            }
            5 => {
                let pending = self.below(2) == 0;
                let mut stream = self.streams.stream(id).expect("a live stream");
                stream.set_producer_pending(pending);
            }
            _ => {
                let bytes = self.bytes();
                self.streams.commit(slot, id, bytes);
            }
        }
    }
}

/// Checks that the delivery of an `Opened`, `Readable` or `Finished` edge, which takes it without
/// a guard, leaves its stream indexed as a full reindex would: the reindex that follows changes
/// neither the stream's list bits, its alone mark nor what the plug keeps of it, and writes no
/// neighbour's links.
fn a_full_reindex_after_a_list_edge_changes_nothing<P: Prioritizer>() {
    let mut seen = ListEdgesSeen::default();
    for seed in 101..=108 {
        let mut h = Harness::<P>::new(seed);
        for _ in 0..60 {
            h.step();
        }
        let mut peers: Vec<StreamId> = (0..10).map(|index| h.open_peer(index)).collect();
        let mut step = 0;
        while let Some(slot) = h.streams.first(List::Readiness) {
            let at = format!("seed {seed} step {step}");
            let stream = h.streams.get_slot(slot).expect("a listed stream");
            let closed = stream.send_state().is_none_or(|s| s.is_terminal())
                && stream.recv_state().is_none_or(|r| r.is_terminal());
            let (_, alone) = h.streams.marks(slot).expect("a listed stream");
            let demand = h.streams.is_on(List::Demand, slot);
            let scheduled = h.streams.prioritizer().order(slot).is_some();
            // As the connection delivers edges: without a guard where it can, else through one.
            let taken = h.streams.take_list_edge(slot).or_else(|| {
                let mut stream = h.streams.by_slot(slot).expect("a listed stream");
                let id = stream.id();
                stream.take_edge().map(|edge| (id, edge))
            });
            if let Some((id, edge)) = taken
                && matches!(
                    edge,
                    StreamReady::Opened | StreamReady::Readable | StreamReady::Finished
                )
            {
                h.streams.assert_indexed();
                let marks = |h: &Harness<P>| {
                    let digest = format!("{:?}", h.streams.prioritizer().digest(slot));
                    (h.streams.marks(slot), digest)
                };
                let before = marks(&h);
                census::reset();
                drop(
                    h.streams
                        .by_slot(slot)
                        .expect("a data edge leaves its stream live"),
                );
                let writes = census::read().neighbour_link_writes;
                assert_eq!(
                    marks(&h),
                    before,
                    "{at}: a full reindex after the {edge:?} edge of {id}"
                );
                assert_eq!(
                    writes, 0,
                    "{at}: link writes after the {edge:?} edge of {id}"
                );
                h.streams.assert_indexed();
                seen.edges += 1;
                seen.left += usize::from(!h.streams.is_on(List::Readiness, slot));
                seen.closed += usize::from(closed);
                seen.scheduled += usize::from(scheduled);
                seen.reshared += usize::from(demand && !alone);
            }
            peers.retain(|&id| h.streams.get(id).is_some());
            if step < 200 && h.below(2) == 0 {
                if let Some(id) = h.pick(&peers) {
                    h.peer_step(id);
                } else {
                    h.step();
                }
            }
            step += 1;
        }
    }
    assert!(
        seen.edges >= 180
            && seen.left >= 60
            && seen.closed >= 60
            && seen.scheduled >= 80
            && seen.reshared >= 45,
        "too little reached: {seen:?}"
    );
}

/// What the peer sent on one of its streams: the end of the bytes sent in order, the highest end
/// sent, the final size once its FIN went, and whether it reset the stream.
#[derive(Clone, Copy, Debug, Default)]
struct PeerSent {
    next: u64,
    high: u64,
    fin: Option<u64>,
    reset: bool,
}

/// The highest end of the bytes the peer sends on a stream, besides a FIN at the end.
const PEER_BYTES: u64 = 6_000;

/// One step of [`edge_run`]: the operation, the edges delivered after it, the streams on the
/// readiness list in order, and the census so far less the counts of the guard's path and the
/// path without it: reindexes, reshares and edges taken without a guard.
type EdgeStep = (
    &'static str,
    Vec<(StreamId, StreamReady)>,
    Vec<StreamId>,
    census::Census,
);

/// Runs seeded random stream events on a server whose streams `P` orders, taking edges without a
/// guard if `list_edges`, and delivers a random number of edges after each, as a connection's
/// readiness does. Returns the steps and the edges taken without a guard.
fn edge_run<P: Prioritizer>(seed: u64, list_edges: bool) -> (Vec<EdgeStep>, u64) {
    const BUDGET: u64 = 1 << 20;
    let (now, srtt) = (test_epoch(), Duration::from_millis(20));
    let config = TransportConfig::builder()
        .build()
        .expect("a valid transport config");
    let mut s = StreamState::<P>::new(Side::Server, &config, PagePool::new());
    s.on_peer_params(&TransportParameters {
        initial_max_data: VarInt::from_u32(1 << 30),
        initial_max_stream_data_bidi_local: VarInt::from_u32(1 << 20),
        initial_max_stream_data_uni: VarInt::from_u32(1 << 20),
        initial_max_streams_uni: VarInt::from_u32(1000),
        ..TransportParameters::default()
    })
    .unwrap();
    s.streams.set_list_edges(list_edges);
    let mut rng = TestRng::new(seed);
    // The peer's streams with what it sent on them, and the streams with a send half here.
    let (mut peers, mut senders): (Vec<(StreamId, PeerSent)>, Vec<StreamId>) = Default::default();
    let mut opened = [0; 2];
    let frame = |s: &mut StreamState<P>, id, offset: u64, end: u64, fin| {
        let data = &ZEROS[..(end - offset) as usize];
        s.on_stream_frame(id, offset, data, fin, now, srtt)
            .expect("a frame within the limits");
    };
    census::reset();
    let mut steps = Vec::new();
    for _ in 0..300 {
        peers.retain(|&(id, _)| s.streams.get(id).is_some());
        senders.retain(|&id| s.streams.get(id).is_some());
        let peer = pick(&mut rng, &(0..peers.len()).collect::<Vec<_>>());
        let sender = pick(&mut rng, &senders);
        let roll = below(&mut rng, 100);
        let len = 1 + below(&mut rng, 1200);
        let op = match (roll, peer, sender) {
            (0..12, _, _) | (_, None, None) => {
                if below(&mut rng, 3) == 0 {
                    let id = s.open(Dir::Uni, few_buckets(&mut rng)).unwrap();
                    let pending = below(&mut rng, 2) == 0;
                    s.streams.stream(id).unwrap().set_producer_pending(pending);
                    senders.push(id);
                } else {
                    let dir = [Dir::Bi, Dir::Uni][below(&mut rng, 2) as usize];
                    let index = &mut opened[usize::from(dir == Dir::Uni)];
                    let id = StreamId::new(Side::Client, dir, *index).unwrap();
                    *index += 1;
                    let (end, fin) = (below(&mut rng, len), below(&mut rng, 4) == 0);
                    frame(&mut s, id, 0, end, fin);
                    let sent = PeerSent {
                        next: end,
                        high: end,
                        fin: fin.then_some(end),
                        reset: false,
                    };
                    peers.push((id, sent));
                    if dir == Dir::Bi {
                        senders.push(id);
                    }
                }
                "open"
            }
            (12..44, Some(at), _) => {
                let (id, sent) = &mut peers[at];
                if sent.fin.is_some() || sent.reset || sent.high > PEER_BYTES {
                    "none"
                } else if roll < 26 {
                    frame(&mut s, *id, sent.next, sent.next + len, false);
                    sent.next += len;
                    sent.high = sent.high.max(sent.next);
                    "data"
                } else if roll < 34 {
                    let offset = sent.high + len;
                    frame(&mut s, *id, offset, offset + len, false);
                    sent.high = offset + len;
                    "out_of_order"
                } else {
                    frame(&mut s, *id, sent.next, sent.high, true);
                    (sent.next, sent.fin) = (sent.high, Some(sent.high));
                    "fin"
                }
            }
            (44..54, Some(at), _) => {
                let id = peers[at].0;
                let readable = s.readable(id).chain_length() as u64;
                if readable > 0 {
                    let n = 1 + below(&mut rng, readable);
                    s.consume(id, n as usize, now, srtt).unwrap();
                }
                "consume"
            }
            (54..62, Some(at), _) => {
                let (id, sent) = &mut peers[at];
                if !sent.reset {
                    let size = sent.fin.unwrap_or(sent.high);
                    s.on_reset_stream(*id, CODE, size, now, srtt).unwrap();
                    sent.reset = true;
                }
                "reset"
            }
            (62..66, _, Some(id)) => {
                s.on_stop_sending(id, CODE).unwrap();
                "stop"
            }
            (66..78, _, Some(id)) => {
                let allowance = s.allowance(id, BUDGET);
                let refused = below(&mut rng, 3) != 0 || allowance == 0;
                let take = if refused {
                    allowance + 1
                } else {
                    allowance.min(len)
                };
                let bytes = Bytes::from_static(&ZEROS[..take as usize]);
                let _ = s.send_parts(id, bytes, Bytes::new(), BUDGET);
                if refused { "refused_push" } else { "push" }
            }
            (78..84, _, _) => {
                s.wake_writable(BUDGET);
                "writable"
            }
            (84..90, _, Some(id)) => {
                let _ = s.track(id, 0);
                "progress"
            }
            (90.., Some(_), _) | (90.., None, Some(_)) => {
                let (id, sent) = match peer {
                    Some(at) => (peers[at].0, Some(&mut peers[at].1)),
                    None => (sender.expect("a stream to close"), None),
                };
                // The peer ends its half, the application reads it to the end, and the send half
                // here resets with a RESET_STREAM that the peer acknowledges.
                if let Some(sent) = sent
                    && !sent.reset
                {
                    if sent.fin.is_none() {
                        frame(&mut s, id, sent.next, sent.high, true);
                        (sent.next, sent.fin) = (sent.high, Some(sent.high));
                    }
                    let readable = s.readable(id).chain_length();
                    s.consume(id, readable, now, srtt).unwrap();
                }
                let _ = s.reset(id, CODE);
                s.on_control_acked(ControlKind::ResetStream, id.into_inner(), 0);
                "close"
            }
            _ => "none",
        };
        let mut edges = Vec::new();
        let wanted = [0, 1, 2, usize::MAX][below(&mut rng, 4) as usize];
        while edges.len() < wanted {
            // As `Readiness` does: refused senders after a `Writable` edge are woken once the
            // edges run out.
            let Some(edge) = s.next_edge().or_else(|| {
                s.take_rewake().then(|| s.wake_writable(BUDGET))?;
                s.next_edge()
            }) else {
                break;
            };
            edges.push(edge);
        }
        let walk = std::iter::successors(s.streams.first(List::Readiness), |&slot| {
            s.streams.next_on(List::Readiness, slot)
        })
        .map(|slot| s.streams.get_slot(slot).expect("a listed stream").id())
        .collect();
        let counted = census::Census {
            reindexes: 0,
            reshares: 0,
            list_edges: 0,
            ..census::read()
        };
        s.streams.assert_indexed();
        steps.push((op, edges, walk, counted));
    }
    (steps, census::read().list_edges)
}

/// Checks that a connection delivers the same edges in the same order whether it takes the
/// `Opened`, `Readable` and `Finished` edges without a guard or through one, with the same
/// streams on the readiness list after every step and the same bookkeeping besides the guard's
/// own.
fn edges_arrive_in_the_same_order_with_and_without_list_edges<P: Prioritizer>() {
    // Edges delivered with list edges on, by kind in the order a stream's edges go, and the
    // `Closed` edges right after a data edge of their stream.
    let (mut kinds, mut closed_after_data, mut taken) = ([0; 8], 0, 0);
    for seed in 111..=116 {
        let (with, list_edges) = edge_run::<P>(seed, true);
        let (without, none) = edge_run::<P>(seed, false);
        assert_eq!(none, 0, "seed {seed}: list edges while they are off");
        for (step, (a, b)) in with.iter().zip(&without).enumerate() {
            assert_eq!(a, b, "seed {seed} step {step}: with and without list edges");
        }
        let mut last = HashMap::new();
        for (id, edge) in with.iter().flat_map(|step| &step.1) {
            let kind = match edge {
                StreamReady::Opened => 0,
                StreamReady::Readable => 1,
                StreamReady::Finished => 2,
                StreamReady::Reset { .. } => 3,
                StreamReady::Stopped { .. } => 4,
                StreamReady::Writable => 5,
                StreamReady::Progress => 6,
                StreamReady::Closed => 7,
            };
            kinds[kind] += 1;
            closed_after_data += usize::from(kind == 7 && last.get(id).is_some_and(|&k| k < 3));
            last.insert(*id, kind);
        }
        taken += list_edges;
    }
    assert!(
        kinds
            .iter()
            .zip([120, 170, 85, 23, 40, 38, 48, 88])
            .all(|(&n, least)| n >= least)
            && closed_after_data >= 50
            && taken >= 380,
        "too little reached: {kinds:?} by kind, {closed_after_data} Closed after a data edge, \
         {taken} list edges"
    );
}

/// Instantiates each generic test above once per plug.
macro_rules! on_every_plug {
    ($($test:ident),* $(,)?) => {
        mod fair_share {
            $(
                #[test]
                fn $test() {
                    super::$test::<super::FairShare>();
                }
            )*
        }

        mod mvfst_order {
            $(
                #[test]
                fn $test() {
                    super::$test::<super::MvfstOrder>();
                }
            )*
        }
    };
}

on_every_plug!(
    a_walk_from_the_start_yields_every_scheduled_stream_once,
    a_walk_goes_on_in_order_when_streams_leave_and_does_not_yield_a_stream_twice,
    a_commit_after_a_leave_does_not_bring_the_stream_back,
    a_commit_for_a_reaped_stream_does_not_change_the_order_or_the_split,
    the_split_stays_within_the_staging_budget,
    staging_by_allowance_does_not_take_the_connection_past_its_budget,
    a_full_reindex_after_a_list_edge_changes_nothing,
    edges_arrive_in_the_same_order_with_and_without_list_edges,
);

/// What [`an_allowance_falls_by_exactly_what_its_stream_stages`] reached.
#[derive(Debug, Default)]
struct StagedSeen {
    /// Pieces staged.
    pieces: usize,
    /// Pieces staged on an incremental stream whose allowance was below its room and what reached
    /// its bucket: its entitlement bound it.
    entitled: usize,
    /// Pieces staged on a sequential stream whose allowance was below its room: what the budget
    /// left after the rooms ahead bound it.
    behind: usize,
    /// Pushes over the allowance refused between pieces.
    refused: usize,
    /// Streams off the demand list that staged a piece.
    idle: usize,
}

/// Opens up to 24 streams on a new server at orders among a few buckets, with random stream
/// credit, staged bytes and producers, and returns them with a random staging budget.
fn staged_streams<P: Prioritizer>(rng: &mut TestRng) -> (StreamState<P>, Vec<StreamId>, u64) {
    let config = TransportConfig::builder()
        .build()
        .expect("a valid transport config");
    let mut s = StreamState::<P>::new(Side::Server, &config, PagePool::new());
    s.on_peer_params(&TransportParameters {
        initial_max_data: VarInt::from_u32(1 << 30),
        initial_max_stream_data_uni: VarInt::from_u32(5_000),
        initial_max_streams_uni: VarInt::from_u32(1000),
        ..TransportParameters::default()
    })
    .unwrap();
    let ids: Vec<StreamId> = (0..=below(rng, 24))
        .map(|_| {
            let id = s.open(Dir::Uni, few_buckets(rng)).unwrap();
            let credit = [5_000, 40_000, 100_000, 1 << 20][below(rng, 4) as usize];
            s.on_max_stream_data(id, credit).unwrap();
            let staged = [0, 0, 1200, 30_000, CAP as usize][below(rng, 5) as usize];
            let _ = s.send(id, &mut Bytes::from_static(&ZEROS[..staged]), 1 << 30);
            let pending = below(rng, 3) == 0;
            s.streams.stream(id).unwrap().set_producer_pending(pending);
            id
        })
        .collect();
    let budget = [
        48 * 1024,
        128 * 1024,
        256 * 1024,
        512 * 1024,
        s.staged + 20_000,
    ][below(rng, 5) as usize];
    (s, ids, budget)
}

/// Checks the identity that lets a sender carry its allowance through a poll: while the other
/// streams do not stage, a stream that stages bytes within its allowance lowers it by exactly
/// those bytes, and a refused push leaves it unchanged. The byte-fair plug fails this, as what an
/// incremental bucket ahead takes depends on what reaches it, so an allowance behind such a bucket
/// can fall by less.
fn an_allowance_falls_by_exactly_what_its_stream_stages<P: Prioritizer>() {
    let mut seen = StagedSeen::default();
    for seed in 91..=98 {
        let mut rng = TestRng::new(seed);
        for trial in 0..60 {
            let (mut s, ids, budget) = staged_streams::<P>(&mut rng);
            let mut turns = Vec::new();
            let mut next = s.streams.first(List::Demand);
            while let Some(slot) = next {
                turns.push(s.streams.get_slot(slot).expect("a listed stream").id());
                next = s.streams.next_on(List::Demand, slot);
            }
            let listed = turns.len();
            let idle: Vec<StreamId> = ids.into_iter().filter(|id| !turns.contains(id)).collect();
            turns.extend(idle);
            for (turn, &id) in turns.iter().enumerate() {
                let at = format!("seed {seed} trial {trial} stream {id}");
                let first = s.allowance(id, budget);
                let mut staged = 0;
                for piece in 0..4 {
                    let allowance = first - staged;
                    if allowance == 0 {
                        break;
                    }
                    if below(&mut rng, 3) == 0 {
                        let over = Bytes::from_static(&ZEROS[..allowance as usize + 1]);
                        assert_eq!(
                            s.send_parts(id, over, Bytes::new(), budget),
                            Err(SendError::OverAllowance),
                            "{at}: a push of {} over an allowance of {allowance}",
                            allowance + 1
                        );
                        assert_eq!(
                            s.allowance(id, budget),
                            allowance,
                            "{at}: the allowance after a refused push before piece {piece}"
                        );
                        seen.refused += 1;
                    }
                    let peer = s.streams.get(id).expect("a live stream").peer();
                    let left = budget.saturating_sub(s.staged);
                    if peer.order.incremental {
                        seen.entitled += usize::from(allowance < peer.figures.room.min(left));
                    } else {
                        seen.behind += usize::from(allowance < peer.figures.room);
                    }
                    seen.idle += usize::from(turn >= listed && staged == 0);
                    let len = (1 + below(&mut rng, allowance)) as usize;
                    let header = below(&mut rng, len as u64 + 1) as usize;
                    s.send_parts(
                        id,
                        Bytes::from_static(&ZEROS[..header]),
                        Bytes::from_static(&ZEROS[header..len]),
                        budget,
                    )
                    .unwrap_or_else(|e| panic!("{at}: piece {piece} of {len}: {e}"));
                    staged += len as u64;
                    seen.pieces += 1;
                    assert_eq!(
                        s.allowance(id, budget),
                        first - staged,
                        "{at}: the allowance after piece {piece} of {len}, {staged} of {first} staged"
                    );
                }
                s.streams.assert_indexed();
            }
        }
    }
    assert!(
        seen.pieces >= 2500
            && seen.entitled >= 900
            && seen.behind >= 240
            && seen.refused >= 850
            && seen.idle >= 100,
        "too little reached: {seen:?}"
    );
}

#[test]
fn mvfst_order_lowers_an_allowance_by_exactly_what_its_stream_stages() {
    an_allowance_falls_by_exactly_what_its_stream_stages::<MvfstOrder>();
}

/// Checks that a commit for a stream that left does not change anything a connection could observe
/// later: twins that differ only by that commit order and split their streams alike from then on,
/// after the stream comes back and through more random operations. The byte-fair plug fails this,
/// as a commit for a stream that left still counts toward its turn.
fn a_commit_after_a_leave_does_not_change_what_follows<P: Prioritizer>() {
    let mut trials = 0;
    for seed in 71..=86 {
        let picks = twins::<P>(seed, 120).0.walk().len();
        for pick in 0..picks {
            let (mut a, mut b) = twins::<P>(seed, 120);
            let slot = a.walk()[pick];
            let id = a.id(slot);
            let at = format!("seed {seed} slot {slot}");
            a.drain(id);
            b.drain(id);
            a.streams.commit(slot, id, [1, 1200, 12_000, CAP][pick % 4]);
            assert_same(&mut a, &mut b, &at);
            a.refill(id);
            b.refill(id);
            assert_same(&mut a, &mut b, &format!("{at}, back"));
            for step in 0..40 {
                a.step();
                b.step();
                assert_same(&mut a, &mut b, &format!("{at}, step {step} after"));
            }
            trials += 1;
        }
    }
    assert!(trials >= 50, "too little reached: {trials} trials");
}

#[test]
fn mvfst_order_ignores_a_commit_after_a_leave_altogether() {
    a_commit_after_a_leave_does_not_change_what_follows::<MvfstOrder>();
}

#[test]
fn mvfst_order_gives_each_incremental_stream_that_keeps_filling_packets_a_turn_within_a_round() {
    // Five incremental streams in the first bucket keep bytes for the wire, with streams waiting
    // in later buckets. Each packet goes to the first stream of the walk and fills, so the stream
    // is still scheduled at its commit. A sixth stream joins, and one leaves and comes back.
    let mut h = Harness::<MvfstOrder>::new(0);
    let order = |urgency, incremental| SendOrder {
        class: 1,
        urgency,
        incremental,
        order: 0,
    };
    let wire = Data {
        wire: true,
        ..Data::default()
    };
    let mut bucket: Vec<StreamId> = (0..5)
        .map(|_| h.open_with(order(3, true), wire, false))
        .collect();
    h.open_with(order(5, false), wire, false);
    h.open_with(order(6, true), wire, false);
    // Commits since each stream's last turn or since it joined, and the most streams its bucket
    // held meanwhile.
    let mut waits: Vec<(StreamId, usize, usize)> = bucket.iter().map(|&id| (id, 0, 5)).collect();
    let mut turns = [0usize; 8];
    for packet in 0..120 {
        if packet == 40 {
            let id = h.open_with(order(3, true), wire, false);
            bucket.push(id);
            waits.push((id, 0, 0));
        }
        if packet == 70 {
            let id = bucket.remove(2);
            h.drain(id);
            waits.retain(|w| w.0 != id);
        }
        if packet == 80 {
            let id = h.live[2];
            h.refill(id);
            bucket.push(id);
            waits.push((id, 0, 0));
        }
        for wait in &mut waits {
            wait.2 = wait.2.max(bucket.len());
        }
        let head = h.walk()[0];
        let id = h.id(head);
        assert!(
            bucket.contains(&id),
            "packet {packet}: {id} is not in the bucket"
        );
        let bytes = [1200, 1, 1500, CAP][packet % 4];
        h.streams.commit(head, id, bytes);
        for wait in &mut waits {
            if wait.0 == id {
                assert!(
                    wait.1 < wait.2,
                    "packet {packet}: {id} waited {} commits in a bucket of at most {}",
                    wait.1,
                    wait.2
                );
                (wait.1, wait.2) = (0, bucket.len());
            } else {
                wait.1 += 1;
                assert!(
                    wait.1 < wait.2,
                    "packet {packet}: {} waits {} commits in a bucket of at most {}",
                    wait.0,
                    wait.1,
                    wait.2
                );
            }
        }
        turns[h.slot(id) as usize] += 1;
        h.streams.assert_indexed();
    }
    assert_eq!(turns.iter().sum::<usize>(), 120);
    assert_eq!(&turns[5..7], [0, 0], "the streams in later buckets wait");
}
