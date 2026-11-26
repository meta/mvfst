/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A seeded property test of the default staging split: random operations on a client's streams
//! through the pair harness and, after each one, a check of every stream's allowance and send
//! capacity and the pull-ready list against a reference split computed from scratch over the
//! demand list.
//!
//! The reference splits by bucket in wire order. A sequential bucket's streams take their rooms in
//! turn. An incremental bucket's peers are each entitled to an equal part of what reaches the
//! bucket and what they hold, and the buckets after it get what reaches it less the sum of the
//! peers' rooms, however much the peers take. Within an incremental bucket the pull-ready list
//! follows the rotation, and the peers outside it, which do not have bytes to send, come after it
//! in an order the check does not pin.

use std::time::Duration;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::StreamId;

use super::Connection;
use super::State;
use super::stream_tests::config;
use super::tests::every_other_packet;
use super::tests::handshake;
use crate::AppCode;
use crate::Prioritizer;
use crate::SendOrder;
use crate::StreamReady;
use crate::streams::conn::SendPart;
use crate::streams::conn::StreamState;
use crate::streams::guard::List;
use crate::testing::Pair;
use crate::testing::TestRng;
use crate::testing::fixtures::Setup;

/// The per-stream staging cap.
const CAP: u64 = 64 * 1024;

/// The low-water mark before the share and the stream credit lower it.
const LOW_WATER: u64 = 16 * 1024;

/// What the split reads of a stream.
#[derive(Clone, Copy, Debug)]
struct Figures {
    room: u64,
    credit: u64,
    staged: u64,
}

fn figures(send: &SendPart) -> Figures {
    let credit = if send.buf.final_size().is_some() {
        0
    } else {
        send.credit.limit().saturating_sub(send.buf.staged_end())
    };
    let staged = send.buf.staged();
    Figures {
        room: credit.min(CAP.saturating_sub(staged)),
        credit,
        staged,
    }
}

/// A bucket of the split: class, urgency, incremental.
type Key = (u8, u8, bool);

fn key(order: SendOrder) -> Key {
    (order.class, order.urgency.min(7), order.incremental)
}

/// A stream on the demand list.
#[derive(Clone, Copy, Debug)]
struct Peer {
    key: Key,
    /// `(order, id)` for a sequential stream; for an incremental one, `(0, position)` in the wire
    /// order if it is scheduled and `(1, id)` if not.
    place: (u128, u64),
    id: StreamId,
    figures: Figures,
    pull: bool,
    /// Whether the stream is incremental and not scheduled.
    unscheduled: bool,
}

/// Returns the streams on the demand list, sorted into the wire order.
fn peers(state: &StreamState) -> Vec<Peer> {
    let streams = &state.streams;
    let walk: Vec<u32> = streams.prioritizer().iter().collect();
    let mut peers = Vec::new();
    let mut next = streams.first(List::Demand);
    while let Some(slot) = next {
        next = streams.next_on(List::Demand, slot);
        let Some(stream) = streams.get_slot(slot) else {
            continue;
        };
        let Some(send) = stream.data().send.as_ref() else {
            continue;
        };
        let (order, id) = (stream.order(), stream.id());
        let position = walk.iter().position(|&scheduled| scheduled == slot);
        let place = match (order.incremental, position) {
            (false, _) => (order.order, id.into_inner()),
            (true, Some(position)) => (0, position as u64),
            (true, None) => (1, id.into_inner()),
        };
        peers.push(Peer {
            key: key(order),
            place,
            id,
            figures: figures(send),
            pull: streams.is_on(List::PullReady, slot),
            unscheduled: order.incremental && position.is_none(),
        });
    }
    peers.sort_by_key(|p| (p.key, p.place));
    peers
}

fn entitlement(left: u64, held: u64, peers: u64) -> u64 {
    left.saturating_add(held) / peers.max(1)
}

fn incremental(figures: Figures, entitled: u64, left: u64) -> u64 {
    figures
        .room
        .min(entitled.saturating_sub(figures.staged))
        .min(left)
}

/// Returns the allowance of each of a bucket's peers, in wire order, when `left` bytes reach it,
/// with the share that caps its low-water mark; and what the bucket leaves: for an incremental
/// bucket, `left` less the sum of its peers' rooms, which bounds what they take.
fn split(bucket: &[Peer], mut left: u64) -> (Vec<(u64, u64)>, u64) {
    if bucket[0].key.2 {
        let held = bucket
            .iter()
            .fold(0u64, |held, p| held.saturating_add(p.figures.staged));
        let entitled = entitlement(left, held, bucket.len() as u64);
        let out: Vec<_> = bucket
            .iter()
            .map(|p| (incremental(p.figures, entitled, left), entitled))
            .collect();
        let rooms = bucket
            .iter()
            .fold(0u64, |rooms, p| rooms.saturating_add(p.figures.room));
        (out, left.saturating_sub(rooms))
    } else {
        let out = bucket
            .iter()
            .map(|p| {
                let (allowance, share) = (p.figures.room.min(left), left);
                left -= allowance;
                (allowance, share)
            })
            .collect();
        (out, left)
    }
}

/// Returns the pull-ready streams with their allowances, in wire order, when the connection stages
/// at most `budget` bytes.
fn reference_pull_ready(state: &StreamState, budget: u64) -> Vec<(StreamId, u64)> {
    let peers = peers(state);
    let mut left = budget.saturating_sub(state.staged);
    let mut listed = Vec::new();
    for bucket in peers.chunk_by(|a, b| a.key == b.key) {
        let (allowances, after) = split(bucket, left);
        for (p, (allowance, share)) in bucket.iter().zip(allowances) {
            let low_water = LOW_WATER.min(share).min(p.figures.credit);
            if p.pull && allowance > 0 && allowance >= low_water {
                listed.push((p.id, allowance));
            }
        }
        left = after;
    }
    listed
}

/// Returns stream `id`'s allowance when the connection stages at most `budget` bytes: it counts
/// among its bucket's peers in its place, whether or not it has demand.
fn reference_allowance(state: &StreamState, id: StreamId, budget: u64) -> u64 {
    let Some(stream) = state.streams.get(id) else {
        return 0;
    };
    if !stream.send_state().is_some_and(|s| s.takes_new_data()) {
        return 0;
    }
    let Some(asker) = stream.data().send.as_ref().map(figures) else {
        return 0;
    };
    if asker.room == 0 {
        return 0;
    }
    let order = stream.order();
    let key = key(order);
    let peers = peers(state);
    let mut left = budget.saturating_sub(state.staged);
    for bucket in peers
        .chunk_by(|a, b| a.key == b.key)
        .take_while(|bucket| bucket[0].key < key)
    {
        left = split(bucket, left).1;
    }
    let others = peers.iter().filter(|p| p.key == key && p.id != id);
    if key.2 {
        let (n, held) = others.fold((1, asker.staged), |(n, held), p| {
            (n + 1, held.saturating_add(p.figures.staged))
        });
        incremental(asker, entitlement(left, held, n), left)
    } else {
        let ahead = others
            .filter(|p| p.place < (order.order, id.into_inner()))
            .fold(0u64, |sum, p| sum.saturating_add(p.figures.room));
        asker.room.min(left.saturating_sub(ahead))
    }
}

/// Returns pull-ready list `listed` with each run of incremental peers outside the rotation of
/// their bucket sorted by stream ID, as their order is not pinned.
fn normalized(state: &StreamState, listed: &[(StreamId, u64)]) -> Vec<(StreamId, u64)> {
    let peers = peers(state);
    let outside = |id: StreamId| {
        peers
            .iter()
            .find(|p| p.id == id)
            .filter(|p| p.unscheduled)
            .map(|p| p.key)
    };
    let mut out = listed.to_vec();
    let mut start = 0;
    while start < out.len() {
        let key = outside(out[start].0);
        let mut end = start + 1;
        while key.is_some() && end < out.len() && outside(out[end].0) == key {
            end += 1;
        }
        out[start..end].sort_by_key(|&(id, _)| id.into_inner());
        start = end;
    }
    out
}

/// Bytes to stage, shared.
static ZEROS: [u8; 80 * 1024] = [0; 80 * 1024];

/// The orders the client opens its streams at.
#[derive(Clone, Copy, Debug)]
enum Mix {
    /// Up to 24 live streams in random buckets, sequential and incremental.
    Mixed,
    /// Up to 3 live streams in one incremental bucket, as tperf's streams are, so the bucket
    /// often has a single peer.
    OneBucket,
}

/// The streams the test tracks, and its random source.
struct Model {
    rng: TestRng,
    mix: Mix,
    /// Streams the client opened.
    local: Vec<StreamId>,
    /// Streams the server opened, from the client's `Opened` edges.
    peer: Vec<StreamId>,
    /// Streams the server opened.
    served: Vec<StreamId>,
    /// Streams the client opened, from the server's `Opened` edges.
    heard: Vec<StreamId>,
}

impl Model {
    fn below(&mut self, n: u64) -> u64 {
        self.rng.next_u64() % n
    }

    fn pick(&mut self, ids: &[StreamId]) -> Option<StreamId> {
        if ids.is_empty() {
            return None;
        }
        Some(ids[self.below(ids.len() as u64) as usize])
    }

    /// Returns the client's streams that are not reaped, local or peer.
    fn live(&self, conn: &Connection) -> Vec<StreamId> {
        let streams = &conn.sources.streams.streams;
        self.local
            .iter()
            .chain(&self.peer)
            .copied()
            .filter(|&id| streams.get(id).is_some())
            .collect()
    }

    fn order(&mut self) -> SendOrder {
        let r = self.rng.next_u64();
        if let Mix::OneBucket = self.mix {
            return SendOrder {
                class: 1,
                urgency: 3,
                incremental: true,
                order: u128::from(r % 3),
            };
        }
        SendOrder {
            class: [0, 1, 1, 1][(r % 4) as usize],
            urgency: [0, 3, 3, 5][((r >> 8) % 4) as usize],
            incremental: (r >> 16).is_multiple_of(2),
            order: u128::from((r >> 24) % 3),
        }
    }

    /// Returns the most live streams the client keeps.
    fn max_live(&self) -> usize {
        match self.mix {
            Mix::Mixed => 24,
            Mix::OneBucket => 3,
        }
    }

    fn zeros(&mut self, max: u64) -> Bytes {
        let len = self.below(max + 1) as usize;
        Bytes::from_static(&ZEROS[..len.min(ZEROS.len())])
    }
}

/// Drains the client's readiness, reading what arrives and noting the streams the server opens.
fn client_reads(pair: &mut Pair, m: &mut Model) {
    let conn = pair.client.conn_mut();
    while let Some((id, edge)) = conn.readiness().next() {
        if edge == StreamReady::Opened {
            m.peer.push(id);
        }
        if matches!(
            edge,
            StreamReady::Opened | StreamReady::Readable | StreamReady::Finished
        ) && let Ok(mut stream) = conn.stream(id)
        {
            let n = stream.readable().chain_length();
            let _ = stream.consume(n);
        }
    }
}

/// Drains the server's readiness, noting the streams the client opens, and reads every byte of
/// some of the server's streams, which returns credit to the client.
fn server_reads(pair: &mut Pair, m: &mut Model) {
    let conn = pair.server.conn_mut();
    while let Some((id, edge)) = conn.readiness().next() {
        if edge == StreamReady::Opened {
            m.heard.push(id);
        }
    }
    for id in m.heard.clone() {
        if m.below(3) == 0 {
            continue;
        }
        if let Ok(mut stream) = conn.stream(id) {
            let n = stream.readable().chain_length();
            let _ = stream.consume(n);
        }
    }
}

/// Runs what is due now, and sometimes on to the next event that is not far off.
fn network(pair: &mut Pair, m: &mut Model) {
    pair.step();
    server_reads(pair, m);
    pair.step();
    if m.below(2) == 0
        && let Some(at) = pair.next_event()
        && at <= pair.now + Duration::from_millis(200)
    {
        pair.now = pair.now.max(at);
        pair.step();
    }
}

/// Runs one random operation and returns its name.
fn operate(pair: &mut Pair, m: &mut Model) -> &'static str {
    let roll = m.below(100);
    let live = m.live(pair.client.conn());
    if roll < 10 {
        if live.len() < m.max_live() {
            let dir = if m.below(5) == 0 { Dir::Bi } else { Dir::Uni };
            let order = m.order();
            let wake = m.below(2) == 0;
            let conn = pair.client.conn_mut();
            if let Ok(id) = conn.open_stream(dir, order) {
                m.local.push(id);
                if wake {
                    conn.stream(id).unwrap().wake_producer();
                }
            }
        }
        return "open";
    }
    let Some(id) = m.pick(&live) else {
        network(pair, m);
        return "network";
    };
    let conn = pair.client.conn_mut();
    match roll {
        10..23 => {
            let mut data = m.zeros(CAP + 8 * 1024);
            if let Ok(mut stream) = conn.stream(id) {
                let _ = stream.send(&mut data);
            }
            "push"
        }
        23..27 => {
            let (header, shared) = (m.zeros(300), m.zeros(30_000));
            if let Ok(mut stream) = conn.stream(id) {
                let _ = stream.send_parts(header, shared);
            }
            "send_parts"
        }
        27..39 => {
            let listed: Vec<_> = conn.pull_ready().collect();
            for (id, allowance) in listed {
                let take = match m.below(4) {
                    0 => 0,
                    1 => allowance / 2,
                    _ => allowance,
                };
                let mut stream = conn.stream(id).unwrap();
                if take == 0 {
                    stream.park_producer();
                } else {
                    let mut data = Bytes::from_static(&ZEROS[..take.min(ZEROS.len())]);
                    let _ = stream.send(&mut data);
                }
            }
            "pull"
        }
        39..42 => {
            if let Ok(mut stream) = conn.stream(id) {
                let _ = stream.finish();
            }
            "finish"
        }
        42..43 => {
            if let Ok(mut stream) = conn.stream(id) {
                let _ = stream.reset(AppCode::from_u32(3));
            }
            "reset"
        }
        43..49 => {
            let order = m.order();
            if let Ok(mut stream) = conn.stream(id) {
                stream.set_order(order);
            }
            "set_order"
        }
        49..57 => {
            if let Ok(mut stream) = conn.stream(id) {
                stream.wake_producer();
            }
            "wake"
        }
        57..61 => {
            if let Ok(mut stream) = conn.stream(id) {
                stream.park_producer();
            }
            "park"
        }
        61..88 => {
            network(pair, m);
            "network"
        }
        88..93 => {
            client_reads(pair, m);
            "client_reads"
        }
        93..95 => {
            let server = pair.server.conn_mut();
            if m.served.len() < 6
                && let Ok(id) = server.open_stream(
                    Dir::Bi,
                    SendOrder {
                        class: 1,
                        ..m.order()
                    },
                )
            {
                m.served.push(id);
                let mut stream = server.stream(id).unwrap();
                let _ = stream.send(&mut Bytes::from_static(b"hello"));
            }
            "server_open"
        }
        95..97 => {
            let pick = m.pick(&m.heard.clone());
            if let Some(id) = pick
                && let Ok(mut stream) = pair.server.conn_mut().stream(id)
            {
                let _ = stream.stop_sending(AppCode::from_u32(5));
            }
            "server_stop_sending"
        }
        _ => {
            let ids: Vec<_> = m.heard.iter().chain(&m.served).copied().collect();
            let pick = m.pick(&ids);
            if let Some(id) = pick
                && let Ok(mut stream) = pair.server.conn_mut().stream(id)
            {
                let _ = stream.finish();
            }
            "server_finish"
        }
    }
}

/// What the checks recorded, so that a run that never reaches the interesting states fails.
#[derive(Debug, Default)]
struct Seen {
    most_peers: usize,
    incremental_peers: usize,
    listed: usize,
    reaped: usize,
    /// Checks of a sequential and of an incremental bucket with a single peer.
    lone: [usize; 2],
    /// Buckets that went from a single peer to more, or from more to one, between checks.
    regrouped: usize,
    /// The peers of each bucket at the last check.
    last: Vec<(Key, usize)>,
}

/// Checks the client's stream indexes, and every allowance, send capacity and pull-ready list
/// against the reference.
fn check(pair: &mut Pair, m: &Model, seen: &mut Seen, at: &str) {
    let conn = pair.client.conn_mut();
    let budget = conn.staging_budget();
    let budgets = [budget, 48 * 1024, 1 << 20];
    let ids: Vec<_> = m.local.iter().chain(&m.peer).copied().collect();
    let state = &conn.sources.streams;
    state.streams.assert_indexed();
    let all = peers(state);
    seen.most_peers = seen.most_peers.max(all.len());
    let incremental = all.iter().filter(|p| p.key.2).count();
    seen.incremental_peers = seen.incremental_peers.max(incremental);
    let buckets: Vec<_> = all
        .chunk_by(|a, b| a.key == b.key)
        .map(|bucket| (bucket[0].key, bucket.len()))
        .collect();
    let was = |key| seen.last.iter().find(|b| b.0 == key).map_or(0, |b| b.1);
    let regrouped = buckets
        .iter()
        .filter(|&&(key, n)| (was(key) == 1 && n > 1) || (was(key) > 1 && n == 1))
        .count();
    seen.regrouped += regrouped;
    for &(key, n) in &buckets {
        seen.lone[usize::from(key.2)] += usize::from(n == 1);
    }
    seen.last = buckets;
    seen.reaped = ids
        .iter()
        .filter(|&&id| state.streams.get(id).is_none())
        .count();
    for &id in &ids {
        for b in budgets {
            assert_eq!(
                state.allowance(id, b),
                reference_allowance(state, id, b),
                "{at}: allowance of {id} with a budget of {b}"
            );
        }
    }
    let wanted = budgets.map(|b| normalized(state, &reference_pull_ready(state, b)));
    for (b, want) in budgets.into_iter().zip(&wanted) {
        conn.sources.streams.collect_pull_ready(b);
        let got: Vec<_> = (0..)
            .map_while(|i| conn.sources.streams.pulled(i))
            .collect();
        let got = normalized(&conn.sources.streams, &got);
        assert_eq!(&got, want, "{at}: pull-ready with a budget of {b}");
    }
    for &id in &ids {
        if conn.sources.streams.streams.get(id).is_none() {
            continue;
        }
        let want = reference_allowance(&conn.sources.streams, id, budget);
        let capacity = conn.stream(id).unwrap().send_capacity() as u64;
        assert_eq!(capacity, want, "{at}: send capacity of {id}");
    }
    let got: Vec<_> = conn.pull_ready().map(|(id, a)| (id, a as u64)).collect();
    seen.listed = seen.listed.max(got.len());
    let got = normalized(&conn.sources.streams, &got);
    assert_eq!(got, wanted[0], "{at}: pull_ready");
}

/// Runs `steps` random operations from `seed` on streams opened at the orders of `mix`, with
/// stream windows of `window` bytes.
fn run(seed: u64, mix: Mix, window: u64, steps: usize) -> Seen {
    // The seeds reach the states the tests count with both sides acknowledging every other
    // packet.
    let setup = Setup {
        client_transport: config(|c| c.ack_policy(every_other_packet())),
        server_transport: config(|c| {
            c.max_data(4 * window)
                .max_stream_data_uni(window)
                .max_stream_data_bidi_remote(window)
                .ack_policy(every_other_packet())
        }),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let mut m = Model {
        rng: TestRng::new(seed),
        mix,
        local: Vec::new(),
        peer: Vec::new(),
        served: Vec::new(),
        heard: Vec::new(),
    };
    let mut seen = Seen::default();
    for step in 0..steps {
        let op = operate(&mut pair, &mut m);
        check(
            &mut pair,
            &m,
            &mut seen,
            &format!("seed {seed} step {step} {op}"),
        );
    }
    assert!(
        pair.client.conn().state == State::Open,
        "seed {seed}: the connection closed"
    );
    seen
}

#[test]
fn incremental_peers_keep_their_allowances_after_earlier_peers_take_what_reaches_the_bucket() {
    let setup = Setup {
        server_transport: config(|c| c.max_data(1 << 24).max_stream_data_uni(1 << 20)),
        ..Setup::default()
    };
    let (_, mut pair) = handshake(setup.pair());
    let conn = pair.client.conn_mut();
    assert_eq!(conn.staging_budget(), 256 * 1024);
    let order = |urgency, incremental| SendOrder {
        class: 1,
        urgency,
        incremental,
        order: 0,
    };
    let mut stage = |order, len| {
        let id = conn.open_stream(Dir::Uni, order).unwrap();
        let mut data = Bytes::from_static(&ZEROS[..len]);
        assert_eq!(conn.stream(id).unwrap().send(&mut data), Ok(len));
        id
    };
    // 160 KiB staged behind the incremental bucket and 64 KiB, the cap, on one of its peers
    // leave 32 KiB to reach it.
    for len in [64 * 1024, 64 * 1024, 32 * 1024] {
        stage(order(5, false), len);
    }
    stage(order(3, true), 64 * 1024);
    let (y, z) = (stage(order(3, true), 0), stage(order(3, true), 0));
    for id in [y, z] {
        conn.stream(id).unwrap().wake_producer();
    }
    // Three peers holding 64 KiB are entitled to 32 KiB each: either of Y and Z, outside the
    // rotation in an order the split does not pin, may take all 32 KiB that reach the bucket, and
    // the other is still entitled to its own 32 KiB.
    let mut listed: Vec<_> = conn.pull_ready().collect();
    listed.sort_by_key(|&(id, _)| id.into_inner());
    assert_eq!(listed, [(y, 32 * 1024), (z, 32 * 1024)]);
}

#[test]
fn allowances_and_pull_ready_match_a_split_computed_from_scratch() {
    for (seed, window) in [
        (1, 24 * 1024),
        (2, 100 * 1024),
        (3, 1 << 20),
        (4, 64 * 1024),
    ] {
        let seen = run(seed, Mix::Mixed, window, 600);
        assert!(
            seen.most_peers >= 8
                && seen.incremental_peers >= 3
                && seen.listed >= 3
                && seen.reaped >= 3
                && seen.lone[0] >= 100
                && seen.lone[1] >= 100
                && seen.regrouped >= 20,
            "seed {seed} reached too little: {seen:?}"
        );
    }
}

#[test]
fn allowances_and_pull_ready_match_a_split_computed_from_scratch_in_one_incremental_bucket() {
    for (seed, window) in [(5, 1 << 20), (6, 64 * 1024)] {
        let seen = run(seed, Mix::OneBucket, window, 600);
        assert!(
            seen.lone[1] >= 100 && seen.regrouped >= 10 && seen.listed >= 2 && seen.reaped >= 3,
            "seed {seed} reached too little: {seen:?}"
        );
    }
}
