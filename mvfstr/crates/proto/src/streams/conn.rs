/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A connection's streams: the stream table with its lists and scheduler, each stream's data
//! parts (send buffer and credit, receive buffer and window), connection flow control both ways,
//! and the staged bytes, which the application has handed a stream and which are not sent yet.
//!
//! The staging budget ([`staging_budget`]) bounds the staged bytes of all streams. It is split in
//! the wire order among the streams with demand. A stream's allowance, the bytes it may stage now,
//! is its part, within its stream credit and the per-stream cap on staged bytes, [`STREAM_CAP`].
//!
//! The Control and Scheduled frame sources and the connection's receive dispatch work on this
//! state; every per-stream change goes through the stream guard, whose drop recomputes the
//! stream's list and scheduler membership from what [`StreamData`] reports.

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_wire::Dir;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::TransportParameters;
use roxygen_bufqueue::BufQueue;

use super::guard::Edge;
use super::guard::List;
use super::guard::Owed;
use super::guard::StreamData;
use super::guard::Streams;
use super::map::Half;
use super::recv_buf::PagePool;
use super::recv_buf::RecvBuffer;
use super::recv_buf::RecvError;
use super::send_buf::PushError;
use super::send_buf::SendBuffer;
use super::share::Bucket;
use super::share::Holding;
use super::share::share_key;
use super::state::RecvState;
use super::state::Transition;
use crate::AppCode;
use crate::CreditDue;
use crate::OpenError;
use crate::SendError;
use crate::SendOrder;
use crate::StreamError;
use crate::StreamReady;
use crate::TransportConfig;
use crate::connection::ConnError;
use crate::flow_control::RecvWindow;
use crate::flow_control::SendCredit;
use crate::flow_control::StreamRecvFlow;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::SentFrame;
use crate::sources::delivery::IncrementalValue;

/// The bytes an incremental stream is served per turn: about one packet's payload.
const QUANTUM: u64 = 1200;

/// The place of a stream the peer opens until the application moves it: RFC 9218's default
/// urgency 3, not incremental, in the class after the control streams'.
const PEER_ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

/// The per-stream cap: the most bytes one stream stages.
pub(crate) const STREAM_CAP: u64 = 64 * 1024;

/// A stream's low-water mark: the allowance it must have before it is polled or gets a `Writable`
/// edge again, `min(16 KiB, STREAM_CAP / 4)` or less (see [`reaches_low_water`]).
const LOW_WATER: u64 = 16 * 1024;

/// The smallest staging budget of a connection.
const MIN_STAGING_BUDGET: u64 = 256 * 1024;

/// The most out-of-order ranges the receive buffers of a connection's streams hold together;
/// each stream's buffer holds at most [`MAX_RANGES`](super::recv_buf::MAX_RANGES).
const MAX_CONN_RANGES: usize = 8192;

/// The number of the latest reaped streams whose final sizes later frames are still checked
/// against. RFC 9000 makes the check after a stream closes a SHOULD, so older ones are forgotten
/// to bound the memory.
const REAPED_SIZES: usize = 128;

/// Returns the staging budget of a connection with congestion window `cwnd`: the most bytes it
/// stages on all its streams, twice the window and at least [`MIN_STAGING_BUDGET`].
pub(crate) fn staging_budget(cwnd: u64) -> u64 {
    cwnd.saturating_mul(2).max(MIN_STAGING_BUDGET)
}

/// A stream's sending part.
#[derive(Debug)]
pub(crate) struct SendPart {
    pub(crate) buf: SendBuffer,
    /// Credit from the peer's MAX_STREAM_DATA.
    pub(crate) credit: SendCredit,
    /// Whether a push sender was refused bytes and waits for a `Writable` edge.
    pub(crate) push_blocked: bool,
    /// The limit of the last STREAM_DATA_BLOCKED the peer acknowledged.
    blocked_delivered: Option<u64>,
}

impl SendPart {
    /// Returns the stream credit beyond the staged bytes, or zero once the FIN is staged.
    fn credit_room(&self) -> u64 {
        if self.buf.final_size().is_some() {
            return 0;
        }
        self.credit.limit().saturating_sub(self.buf.staged_end())
    }

    /// Returns the bytes the stream itself may stage now: its stream credit beyond the staged
    /// bytes, up to the per-stream cap, or zero once the FIN is staged.
    fn room(&self) -> u64 {
        self.credit_room()
            .min(STREAM_CAP.saturating_sub(self.buf.staged()))
    }

    /// Returns what the split of the staging budget reads of the stream.
    fn figures(&self) -> Figures {
        Figures {
            room: self.room(),
            credit: self.credit_room(),
            staged: self.buf.staged(),
        }
    }
}

/// What the split of the staging budget reads of a stream.
#[derive(Clone, Copy, Debug)]
struct Figures {
    /// The bytes it may stage: [`SendPart::room`].
    room: u64,
    /// Its stream credit beyond its staged bytes.
    credit: u64,
    /// Its staged bytes.
    staged: u64,
}

impl Figures {
    fn holding(self) -> Holding {
        Holding {
            room: self.room,
            staged: self.staged,
        }
    }
}

/// A stream's receiving part.
#[derive(Debug)]
pub(crate) struct RecvPart {
    pub(crate) buf: RecvBuffer,
    pub(crate) flow: StreamRecvFlow,
    /// Whether the peer acknowledged our STOP_SENDING.
    stop_delivered: bool,
}

/// A stream's data parts; a half the stream does not have here is `None`.
#[derive(Debug)]
pub(crate) struct StreamParts {
    pub(crate) send: Option<SendPart>,
    pub(crate) recv: Option<RecvPart>,
}

impl StreamData for StreamParts {
    fn has_wire_data(&self) -> bool {
        self.send
            .as_ref()
            .is_some_and(|send| send.buf.pending(send.credit.limit()).is_some())
    }

    fn has_pull_room(&self) -> bool {
        self.send.as_ref().is_some_and(|send| send.room() > 0)
    }

    fn has_demand(&self) -> bool {
        self.send
            .as_ref()
            .is_some_and(|send| send.buf.staged() > 0 || send.push_blocked)
    }

    fn holding(&self) -> Holding {
        self.send
            .as_ref()
            .map_or_else(Holding::default, |send| send.figures().holding())
    }
}

/// A stream with demand and its allowance, from [`StreamState::rank`].
#[derive(Clone, Copy, Debug)]
struct Ranked {
    id: StreamId,
    /// Whether it is on the pull-ready list.
    pull: bool,
    /// The allowance if it reaches the stream's low-water mark, zero otherwise.
    allowance: u64,
}

/// Initial stream windows of one side, by the kind of stream they apply to.
#[derive(Clone, Copy, Debug, Default)]
struct Windows {
    /// initial_max_stream_data_bidi_local: bidirectional streams the side itself opens.
    bidi_local: u64,
    /// initial_max_stream_data_bidi_remote: bidirectional streams its peer opens.
    bidi_remote: u64,
    /// initial_max_stream_data_uni: unidirectional streams its peer opens.
    uni: u64,
}

/// What a new stream's data parts start from.
#[derive(Clone, Copy, Debug)]
struct PartsConfig {
    side: Side,
    /// Our receive windows.
    local: Windows,
    /// The ceiling our stream receive windows autotune to.
    autotune: Option<u64>,
    /// The peer's receive windows: our send credit.
    peer: Windows,
}

impl PartsConfig {
    /// Returns the data parts of a stream opened by `initiator` in direction `dir`: the halves
    /// it has here, with their initial windows.
    fn parts(&self, initiator: Side, dir: Dir) -> StreamParts {
        let (send, recv) = match (dir, initiator == self.side) {
            (Dir::Bi, true) => (Some(self.peer.bidi_remote), Some(self.local.bidi_local)),
            (Dir::Bi, false) => (Some(self.peer.bidi_local), Some(self.local.bidi_remote)),
            (Dir::Uni, true) => (Some(self.peer.uni), None),
            (Dir::Uni, false) => (None, Some(self.local.uni)),
        };
        StreamParts {
            send: send.map(|limit| SendPart {
                buf: SendBuffer::new(),
                credit: SendCredit::new(limit),
                push_blocked: false,
                blocked_delivered: None,
            }),
            recv: recv.map(|window| RecvPart {
                buf: RecvBuffer::new(),
                flow: StreamRecvFlow::new(window, self.autotune),
                stop_delivered: false,
            }),
        }
    }
}

/// Returns whether an `allowance` reaches its stream's low-water mark: [`LOW_WATER`], but never
/// more than the stream's `share` (an incremental peer's entitlement, or what the streams ahead
/// leave a sequential one) or the stream credit it has beyond its staged bytes (`credit`), so a
/// stream with demand reaches it once its share or credit is free. The per-stream cap does not
/// lower it: a stream near the cap waits until a quarter of the cap is free again.
fn reaches_low_water(allowance: u64, share: u64, credit: u64) -> bool {
    allowance > 0 && allowance >= LOW_WATER.min(share).min(credit)
}

/// Returns what each of `peers` incremental peers of a bucket is entitled to stage: an equal
/// part of what reaches the bucket (`left`) and what the peers already hold (`held`).
fn entitlement(left: u64, held: u64, peers: u64) -> u64 {
    left.saturating_add(held) / peers.max(1)
}

/// Returns an incremental peer's allowance: its room, up to what its `entitled` bytes leave
/// above what it holds, and no more than what reaches its bucket (`left`). A peer holding its
/// entitlement gets an allowance only once it drains.
fn incremental_allowance(holding: Holding, entitled: u64, left: u64) -> u64 {
    holding
        .room
        .min(entitled.saturating_sub(holding.staged))
        .min(left)
}

/// Returns the index of direction `dir` in per-direction arrays.
pub(crate) fn dir_index(dir: Dir) -> usize {
    match dir {
        Dir::Bi => 0,
        Dir::Uni => 1,
    }
}

/// A connection's streams and flow control.
pub(crate) struct StreamState {
    pub(crate) streams: Streams<StreamParts>,
    config: PartsConfig,
    /// Connection send credit from the peer's MAX_DATA.
    pub(crate) conn_send: SendCredit,
    /// The connection receive window our MAX_DATA advertises.
    pub(crate) conn_recv: RecvWindow,
    /// DATA_BLOCKED at the peer's connection limit.
    pub(crate) data_blocked: IncrementalValue,
    /// MAX_STREAMS for peer streams, by direction.
    pub(crate) max_streams: [IncrementalValue; 2],
    /// STREAMS_BLOCKED at the peer's stream limit, by direction.
    pub(crate) streams_blocked: [IncrementalValue; 2],
    /// Whether an open failed at the peer's stream limit, by direction: `StreamsAvailable`
    /// follows a rise.
    open_refused: [bool; 2],
    /// Bytes staged on every stream and not yet sent.
    pub(crate) staged: u64,
    /// The number of streams whose push sender was refused bytes and waits for `Writable`.
    push_blocked: u32,
    /// Whether a `Writable` edge was delivered since the last wake: its stream's demand may have
    /// ended, which raises the shares of the streams after it.
    rewake: bool,
    /// Pages for received stream data.
    pool: PagePool,
    /// The out-of-order ranges the streams' receive buffers hold.
    ranges: usize,
    /// What `readable` shows for a stream without received bytes.
    empty: BufQueue,
    /// The streams of the last [`rank`](Self::rank) in wire order; after
    /// [`collect_pull_ready`](Self::collect_pull_ready), the pull-ready ones with an allowance.
    ranked: Vec<Ranked>,
    /// The final sizes of the latest reaped streams that had a receive half, oldest first.
    reaped_sizes: VecDeque<(StreamId, u64)>,
}

impl std::fmt::Debug for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamState")
            .field("conn_send", &self.conn_send)
            .field("conn_recv", &self.conn_recv)
            .field("staged", &self.staged)
            .finish_non_exhaustive()
    }
}

impl StreamState {
    /// Creates the streams of a new connection at the endpoint whose role is `side`.
    pub(crate) fn new(side: Side, config: &TransportConfig) -> Self {
        Self {
            streams: Streams::new(
                side,
                config.max_streams_bidi(),
                config.max_streams_uni(),
                QUANTUM,
            ),
            config: PartsConfig {
                side,
                local: Windows {
                    bidi_local: config.max_stream_data_bidi_local(),
                    bidi_remote: config.max_stream_data_bidi_remote(),
                    uni: config.max_stream_data_uni(),
                },
                autotune: config.max_stream_data_autotune(),
                peer: Windows::default(),
            },
            conn_send: SendCredit::new(0),
            conn_recv: RecvWindow::new(config.max_data(), config.max_data_autotune()),
            data_blocked: IncrementalValue::idle(),
            max_streams: [
                IncrementalValue::delivered(config.max_streams_bidi()),
                IncrementalValue::delivered(config.max_streams_uni()),
            ],
            streams_blocked: [IncrementalValue::idle(); 2],
            open_refused: [false; 2],
            staged: 0,
            push_blocked: 0,
            rewake: false,
            pool: PagePool::new(),
            ranges: 0,
            empty: BufQueue::new(0),
            ranked: Vec::new(),
            reaped_sizes: VecDeque::new(),
        }
    }

    /// Returns what a later transmit attempt reads of the streams, for the empty-attempt digest:
    /// the connection's flow control and lists, and each stream's state, data parts and scheduler
    /// record.
    #[cfg(debug_assertions)]
    pub(crate) fn digest(&self) -> String {
        use std::fmt::Write;

        let lists = List::ALL.map(|l| self.streams.len(l));
        let mut out = format!(
            "{:?} {:?} {} {} {:?} {:?} {:?} {:?} {}",
            self.conn_send,
            self.conn_recv,
            self.staged,
            self.push_blocked,
            self.data_blocked,
            self.max_streams,
            self.streams_blocked,
            lists,
            self.streams.scheduler().len(),
        );
        for stream in self.streams.iter() {
            let parts = stream.data();
            let send = parts.send.as_ref().map(|send| {
                (
                    send.buf.digest(),
                    send.credit,
                    send.push_blocked,
                    send.blocked_delivered,
                )
            });
            let recv = parts
                .recv
                .as_ref()
                .map(|recv| (recv.buf.digest(), &recv.flow, recv.stop_delivered));
            let _ = write!(
                out,
                "; {} {} {:?} {:?} {:?}",
                stream.id(),
                stream.digest(),
                send,
                recv,
                self.streams.scheduler().digest(stream.slot()),
            );
        }
        out
    }

    /// Takes the peer's transport parameters: our stream limits and send credit. Returns, by
    /// direction, whether `StreamsAvailable` is due, as for MAX_STREAMS. Fails with
    /// TRANSPORT_PARAMETER_ERROR when a stream limit is above 2^60, as RFC 9000 requires.
    pub(crate) fn on_peer_params(
        &mut self,
        peer: &TransportParameters,
    ) -> Result<[bool; 2], TransportErrorCode> {
        self.conn_send = SendCredit::new(peer.initial_max_data.into_inner());
        self.config.peer = Windows {
            bidi_local: peer.initial_max_stream_data_bidi_local.into_inner(),
            bidi_remote: peer.initial_max_stream_data_bidi_remote.into_inner(),
            uni: peer.initial_max_stream_data_uni.into_inner(),
        };
        let mut available = [false; 2];
        for (dir, max) in [
            (Dir::Bi, peer.initial_max_streams_bidi),
            (Dir::Uni, peer.initial_max_streams_uni),
        ] {
            available[dir_index(dir)] = self
                .raise_stream_limit(dir, max.into_inner())
                .map_err(|_| TransportErrorCode::TRANSPORT_PARAMETER_ERROR)?;
        }
        Ok(available)
    }

    /// Returns whether stream `id` is open here, materializing a peer stream opened implicitly
    /// and not yet named by a frame.
    pub(crate) fn is_open(&mut self, id: StreamId) -> bool {
        let config = self.config;
        self.streams.get(id).is_some()
            || self.streams.materialize(id, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
    }

    /// Returns the allowance of stream `id` when the connection stages at most `budget` bytes:
    /// its room, up to its part of what the budget has left as [`rank`](Self::rank) splits it,
    /// counting the stream among its bucket's peers, as a stream offering bytes has demand. Each
    /// sequential bucket ahead costs one step, read from its totals, each incremental one
    /// O(log n), and the rooms ahead of a sequential stream in its own bucket O(log n).
    pub(crate) fn allowance(&self, id: StreamId, budget: u64) -> u64 {
        let Some(stream) = self.streams.get(id) else {
            return 0;
        };
        if !stream.send_state().is_some_and(|s| s.takes_new_data()) {
            return 0;
        }
        let Some(asker) = stream.data().send.as_ref().map(SendPart::figures) else {
            return 0;
        };
        if asker.room == 0 {
            return 0;
        }
        let (order, key) = (stream.order(), share_key(stream.order()));
        let shares = self.streams.shares();
        let mut left = budget.saturating_sub(self.staged);
        for ahead in shares.buckets().take_while(|b| b.key() < key) {
            if left == 0 {
                break;
            }
            left = left.saturating_sub(self.bucket_takes(ahead, left));
        }
        let counted = self.streams.is_on(List::Demand, stream.slot());
        let bucket = shares.bucket(key);
        let (peers, held) = bucket.map_or((0, 0), |b| (b.peers(), self.held(b).staged));
        if key.2 {
            let (peers, held) = if counted {
                (peers, held)
            } else {
                (peers + 1, held.saturating_add(asker.staged))
            };
            incremental_allowance(asker.holding(), entitlement(left, held, peers), left)
        } else {
            let ahead = bucket.map_or(0, |b| self.room_before(b, order.order, id));
            asker.room.min(left.saturating_sub(ahead))
        }
    }

    /// Returns what the peers of `bucket` hold, read from the stream for a lone peer, which the
    /// shares do not follow.
    fn held(&self, bucket: &Bucket) -> Holding {
        match bucket.lone() {
            Some(slot) => self
                .streams
                .get_slot(slot)
                .map_or_else(Holding::default, |stream| stream.data().holding()),
            None => Holding {
                room: bucket.room(),
                staged: bucket.staged(),
            },
        }
    }

    /// Returns the sum of the rooms of the peers of sequential `bucket` ahead of a stream at
    /// `order` with ID `id`.
    fn room_before(&self, bucket: &Bucket, order: u128, id: StreamId) -> u64 {
        let shares = self.streams.shares();
        let Some(lone) = bucket.lone().and_then(|slot| self.streams.get_slot(slot)) else {
            return shares.room_before(bucket.key(), order, id.into_inner());
        };
        if (lone.order().order, lone.id().into_inner()) < (order, id.into_inner()) {
            lone.data().holding().room
        } else {
            0
        }
    }

    /// Returns what the peers of `bucket` take of the `left` bytes that reach it: the sum of the
    /// allowances [`rank`](Self::rank) computes for them before the low-water mark applies, up to
    /// `left`. An incremental allowance is also capped at `left`, which changes the sum only when
    /// the sum reaches `left` anyway.
    fn bucket_takes(&self, bucket: &Bucket, left: u64) -> u64 {
        let held = self.held(bucket);
        if !bucket.key().2 {
            return held.room.min(left);
        }
        let entitled = entitlement(left, held.staged, bucket.peers());
        if bucket.lone().is_some() {
            return incremental_allowance(held, entitled, left);
        }
        self.streams.shares().takes(bucket, entitled).min(left)
    }

    /// Checks that stream `id`'s send half takes bytes, and fails with the reason if not.
    fn check_send(&self, id: StreamId) -> Result<(), SendError> {
        let Some(stream) = self.streams.get(id) else {
            return Err(SendError::Ended);
        };
        let Some(send) = stream.data().send.as_ref() else {
            return Err(SendError::NoSendHalf);
        };
        if let Some(code) = stream.peer_stop() {
            return Err(SendError::Stopped { code });
        }
        if !stream.send_state().is_some_and(|s| s.takes_new_data())
            || send.buf.final_size().is_some()
        {
            return Err(SendError::Ended);
        }
        Ok(())
    }

    /// Stages the longest prefix of `data` that stream `id`'s allowance takes (see
    /// [`allowance`](Self::allowance)) and returns its length.
    pub(crate) fn send(
        &mut self,
        id: StreamId,
        data: &mut Bytes,
        budget: u64,
    ) -> Result<usize, SendError> {
        self.check_send(id)?;
        let allowance = usize::try_from(self.allowance(id, budget)).unwrap_or(usize::MAX);
        let take = allowance.min(data.len());
        let chunk = data.split_to(take);
        self.stage(id, !data.is_empty(), |buf| buf.push(chunk))?;
        Ok(take)
    }

    /// Stages a per-stream `header` and a `shared` payload on stream `id`, both or neither.
    pub(crate) fn send_parts(
        &mut self,
        id: StreamId,
        header: Bytes,
        shared: Bytes,
        budget: u64,
    ) -> Result<(), SendError> {
        self.check_send(id)?;
        let len = header.len() as u64 + shared.len() as u64;
        if len > self.allowance(id, budget) {
            self.stage(id, true, |_| Ok(()))?;
            return Err(SendError::OverAllowance);
        }
        self.stage(id, false, |buf| buf.push_parts(header, shared))
    }

    /// Stages on stream `id`, whose send half takes bytes, what `push` hands its send buffer
    /// within the allowance; `refused` records that some of the sender's bytes were refused, so
    /// it waits for `Writable`.
    fn stage(
        &mut self,
        id: StreamId,
        refused: bool,
        push: impl FnOnce(&mut SendBuffer) -> Result<(), PushError>,
    ) -> Result<(), SendError> {
        let Some(mut stream) = self.streams.stream(id) else {
            return Err(SendError::Ended);
        };
        let Some(send) = stream.data_mut().send.as_mut() else {
            return Err(SendError::NoSendHalf);
        };
        let before = send.buf.staged_end();
        push(&mut send.buf).expect("should take bytes within the allowance of an open send half");
        let staged = send.buf.staged_end() - before;
        let blocked = refused && !std::mem::replace(&mut send.push_blocked, true);
        // Refused with every byte of stream credit sent, as at a zero initial limit: a later STREAM
        // frame does not spend the credit and note the block, so STREAM_DATA_BLOCKED is due now, as
        // RFC 9000 recommends.
        if refused && send.credit.note_blocked().is_some() {
            stream.owe(Owed::STREAM_DATA_BLOCKED);
        }
        drop(stream);
        if blocked {
            self.push_blocked += 1;
        }
        self.staged += staged;
        self.note_conn_blocked();
        Ok(())
    }

    /// Makes DATA_BLOCKED due, once per limit, when staged bytes wait for connection credit alone
    /// (the allowance keeps staged bytes within stream credit).
    pub(crate) fn note_conn_blocked(&mut self) {
        if self.staged > 0
            && let Some(limit) = self.conn_send.note_blocked()
        {
            self.data_blocked.raise(limit);
        }
    }

    /// Marks `Writable` on every stream whose push sender was refused bytes and whose allowance
    /// is back at its low-water mark (see [`rank`](Self::rank)) when the connection stages at
    /// most `budget` bytes, whether or not it is pull-ready: a refused sender has demand, so it
    /// is ranked.
    pub(crate) fn wake_writable(&mut self, budget: u64) {
        self.rewake = false;
        if self.push_blocked == 0 || self.staged >= budget {
            return;
        }
        self.rank(budget);
        for index in 0..self.ranked.len() {
            let ranked = self.ranked[index];
            if ranked.allowance == 0 {
                continue;
            }
            let Some(mut stream) = self.streams.stream(ranked.id) else {
                continue;
            };
            let woken = stream
                .data_mut()
                .send
                .as_mut()
                .is_some_and(|send| std::mem::take(&mut send.push_blocked));
            if woken {
                stream.mark(Edge::Writable);
                self.push_blocked -= 1;
            }
        }
        self.ranked.clear();
    }

    /// Returns whether any stream's producer should be polled for data.
    pub(crate) fn has_pull_ready(&self) -> bool {
        self.streams.first(List::PullReady).is_some()
    }

    /// Collects the pull-ready streams in wire order, an incremental bucket's in the scheduler's
    /// turn order, with their allowances when the connection stages at most `budget` bytes, for
    /// [`pulled`](Self::pulled).
    pub(crate) fn collect_pull_ready(&mut self, budget: u64) {
        self.rank(budget);
        self.ranked.retain(|r| r.pull && r.allowance > 0);
    }

    /// Ranks the streams with demand in wire order with their allowances when the connection
    /// stages at most `budget` bytes: buckets in wire order take from what the budget has left,
    /// `left`. A sequential bucket's streams take their rooms in turn from `left`; an incremental
    /// bucket's peers are each entitled to an equal part of `left` and what they hold, and take
    /// their rooms up to that. An allowance below the stream's low-water mark, 16 KiB capped by
    /// its entitlement (or by `left` in a sequential bucket) and by its stream credit, is zero.
    /// Once `left` runs out, the rest of a sequential bucket and the buckets after it are not
    /// ranked, so their allowances are zero.
    fn rank(&mut self, budget: u64) {
        let mut ranked = std::mem::take(&mut self.ranked);
        ranked.clear();
        self.streams.settle_shares();
        let shares = self.streams.shares();
        let mut left = budget.saturating_sub(self.staged);
        for bucket in shares.buckets() {
            if left == 0 {
                break;
            }
            // What reaches an incremental bucket is split before any of it is taken.
            let (reaching, incremental) = (left, bucket.key().2);
            let entitled = entitlement(reaching, self.held(bucket).staged, bucket.peers());
            for slot in shares.members(bucket) {
                if left == 0 && !incremental {
                    break;
                }
                let Some(stream) = self.streams.get_slot(slot) else {
                    continue;
                };
                let Some(figures) = stream.data().send.as_ref().map(SendPart::figures) else {
                    continue;
                };
                let (allowance, share) = if incremental {
                    let allowance = incremental_allowance(figures.holding(), entitled, reaching);
                    (allowance, entitled)
                } else {
                    (figures.room.min(left), left)
                };
                left = left.saturating_sub(allowance);
                let reached = reaches_low_water(allowance, share, figures.credit);
                ranked.push(Ranked {
                    id: stream.id(),
                    pull: self.streams.is_on(List::PullReady, slot),
                    allowance: if reached { allowance } else { 0 },
                });
            }
        }
        self.ranked = ranked;
    }

    /// Returns the `index`th collected pull-ready stream and its allowance, if any.
    pub(crate) fn pulled(&self, index: usize) -> Option<(StreamId, u64)> {
        self.ranked.get(index).map(|r| (r.id, r.allowance))
    }

    /// Ends stream `id`'s send half after its staged bytes.
    pub(crate) fn finish(&mut self, id: StreamId) -> Result<(), SendError> {
        self.check_send(id)?;
        let Some(mut stream) = self.streams.stream(id) else {
            return Err(SendError::Ended);
        };
        let Some(send) = stream.data_mut().send.as_mut() else {
            return Err(SendError::NoSendHalf);
        };
        send.buf.finish().map_err(|_| SendError::Ended)?;
        let was_blocked = std::mem::take(&mut send.push_blocked);
        stream.on_fin_staged();
        drop(stream);
        self.push_blocked -= u32::from(was_blocked);
        Ok(())
    }

    /// Abandons stream `id`'s send half with RESET_STREAM carrying `code` and the bytes sent so
    /// far as the final size; staged and lost bytes are dropped.
    pub(crate) fn reset(&mut self, id: StreamId, code: AppCode) -> Result<(), SendError> {
        let Some(mut stream) = self.streams.stream(id) else {
            return Err(SendError::Ended);
        };
        let resettable = stream
            .view()
            .send_state()
            .is_some_and(|s| s.may_send_stream());
        let Some(send) = stream.data_mut().send.as_mut() else {
            return Err(SendError::NoSendHalf);
        };
        if !resettable {
            return Err(SendError::Ended);
        }
        let unsent = send.buf.staged();
        let final_size = send.buf.reset();
        let was_blocked = std::mem::take(&mut send.push_blocked);
        let reset = stream.reset(code, final_size);
        debug_assert!(reset.is_ok(), "a send half that may send may reset");
        drop(stream);
        self.drop_staged(unsent);
        self.push_blocked -= u32::from(was_blocked);
        Ok(())
    }

    /// Records that `unsent` staged bytes were dropped without being sent, by a reset or the
    /// peer's STOP_SENDING.
    fn drop_staged(&mut self, unsent: u64) {
        self.staged -= unsent;
        self.drop_stale_data_blocked();
    }

    /// Drops a pending DATA_BLOCKED once zero bytes are staged, since it is no longer current;
    /// bytes that later wait at the same limit make it due again. A copy in flight is checked
    /// again once lost, so it still covers bytes staged before then.
    fn drop_stale_data_blocked(&mut self) {
        if self.staged == 0 && self.data_blocked.pending().is_some() {
            self.data_blocked.cancel();
            self.conn_send.forget_blocked();
        }
    }

    /// Requests that the peer stop sending on stream `id` with `code`, and drops its ingress: the
    /// unread bytes return to the connection window. The receive half ends once every byte up to
    /// the final size or the peer's RESET_STREAM arrives, and until then STOP_SENDING is owed, as
    /// RFC 9000 describes.
    pub(crate) fn stop_sending(
        &mut self,
        id: StreamId,
        code: AppCode,
        now: Instant,
        srtt: Duration,
    ) -> Result<(), StreamError> {
        let Some(mut stream) = self.streams.stream(id) else {
            return Err(StreamError::Closed);
        };
        let view = stream.view();
        let (state, stopped) = (view.recv_state(), view.stop_code().is_some());
        let Some(state) = state else {
            return Err(StreamError::NoReceiveHalf);
        };
        if stopped || !state.may_send_stop_sending() {
            return Err(StreamError::ReceiveEnded);
        }
        let asked = stream.stop_sending(code);
        debug_assert!(
            asked.is_ok(),
            "a receive half in Recv or Size Known may stop"
        );
        stream.on_control_sent(Owed::MAX_STREAM_DATA);
        if let Some(recv) = stream.data_mut().recv.as_mut() {
            recv.buf.stop(&mut self.pool);
            recv.flow.stop(&mut self.conn_recv, now, srtt);
        }
        Ok(())
    }

    /// Returns the in-order bytes of stream `id` not yet consumed.
    pub(crate) fn readable(&self, id: StreamId) -> &BufQueue {
        self.streams
            .get(id)
            .and_then(|stream| stream.data().recv.as_ref())
            .map_or(&self.empty, |recv| recv.buf.readable())
    }

    /// Returns whether the peer's FIN and every byte before it arrived on stream `id`, so that its
    /// receive half is in Data Recvd or Data Read, and this endpoint did not request STOP_SENDING.
    pub(crate) fn peer_finished(&self, id: StreamId) -> bool {
        self.streams.get(id).is_some_and(|stream| {
            stream.stop_code().is_none()
                && matches!(
                    stream.recv_state(),
                    Some(RecvState::DataRecvd | RecvState::DataRead)
                )
        })
    }

    /// Consumes `n` readable bytes of stream `id`, returning their credit to both receive
    /// windows, and returns whether an update is due.
    pub(crate) fn consume(
        &mut self,
        id: StreamId,
        n: usize,
        now: Instant,
        srtt: Duration,
    ) -> Result<CreditDue, StreamError> {
        let Some(mut stream) = self.streams.stream(id) else {
            return Err(StreamError::Closed);
        };
        let Some(recv) = stream.data_mut().recv.as_mut() else {
            return Err(StreamError::NoReceiveHalf);
        };
        recv.buf
            .consume(n, &mut self.pool)
            .map_err(|_| StreamError::BeyondReadable)?;
        let due = recv
            .flow
            .on_consumed(&mut self.conn_recv, n as u64, now, srtt);
        let (wants_update, finished) = (recv.flow.wants_update(), recv.buf.is_finished());
        if wants_update {
            stream.owe(Owed::MAX_STREAM_DATA);
        }
        if finished {
            let _ = stream.on_all_data_read();
        }
        Ok(due)
    }

    /// Returns whether a `Writable` edge was delivered since the last wake (see
    /// [`wake_writable`](Self::wake_writable)), and clears it.
    pub(crate) fn take_rewake(&mut self) -> bool {
        std::mem::take(&mut self.rewake)
    }

    /// Takes the next readiness edge of any stream.
    pub(crate) fn next_edge(&mut self) -> Option<(StreamId, StreamReady)> {
        while let Some(slot) = self.streams.first(List::Readiness) {
            let mut stream = self.streams.by_slot(slot)?;
            if let Some(edge) = stream.take_edge() {
                let id = stream.id();
                let (final_size, held) = stream
                    .view()
                    .data()
                    .recv
                    .as_ref()
                    .map_or((None, 0), |recv| (recv.buf.final_size(), recv.buf.ranges()));
                // Delivering the last edge of a closed stream reaps it.
                drop(stream);
                match edge {
                    StreamReady::Closed => {
                        self.ranges -= held;
                        self.on_reaped(id, final_size);
                    }
                    StreamReady::Writable => self.rewake = true,
                    _ => {}
                }
                return Some((id, edge));
            }
        }
        None
    }

    /// Records that stream `id`, whose receive half ended at `final_size` if it had one, was
    /// reaped: makes MAX_STREAMS due for each direction whose limit that raised, and keeps the
    /// final size.
    fn on_reaped(&mut self, id: StreamId, final_size: Option<u64>) {
        for dir in [Dir::Bi, Dir::Uni] {
            self.max_streams[dir_index(dir)].raise(self.streams.max_streams(dir));
        }
        if let Some(size) = final_size {
            if self.reaped_sizes.len() == REAPED_SIZES {
                self.reaped_sizes.pop_front();
            }
            self.reaped_sizes.push_back((id, size));
        }
    }

    /// Checks a frame for reaped stream `id` whose data ends at `end` against the stream's final
    /// size while it is recorded: the end may not pass it, and must equal it for a FIN or a
    /// RESET_STREAM (`exact`), as RFC 9000 recommends for a closed stream.
    fn check_reaped(&self, id: StreamId, end: u64, exact: bool) -> Result<(), ConnError> {
        let size = self
            .reaped_sizes
            .iter()
            .rev()
            .find_map(|&(of, size)| (of == id).then_some(size));
        match size {
            Some(size) if end > size || (exact && end != size) => Err(ConnError::new(
                TransportErrorCode::FINAL_SIZE_ERROR,
                "a frame for a closed stream against its final size",
            )),
            _ => Ok(()),
        }
    }

    /// Takes the peer's MAX_STREAMS for `dir`; returns whether `StreamsAvailable` is due: the
    /// limit rose after an open failed at it.
    pub(crate) fn on_max_streams(&mut self, dir: Dir, max: u64) -> Result<bool, ConnError> {
        self.raise_stream_limit(dir, max)
            .map_err(|code| ConnError::new(code, "MAX_STREAMS above 2^60"))
    }

    /// Applies the peer's stream limit for `dir`. A rise unblocks the next open, so a pending
    /// STREAMS_BLOCKED is no longer current; returns whether `StreamsAvailable` is due.
    fn raise_stream_limit(&mut self, dir: Dir, max: u64) -> Result<bool, TransportErrorCode> {
        if !self.streams.on_peer_max_streams(dir, max)? {
            return Ok(false);
        }
        self.streams_blocked[dir_index(dir)].cancel();
        Ok(std::mem::take(&mut self.open_refused[dir_index(dir)]))
    }

    /// Takes a STREAM frame for stream `id`: `data` at `offset`, with the FIN if `fin`.
    pub(crate) fn on_stream_frame(
        &mut self,
        id: StreamId,
        offset: u64,
        data: &[u8],
        fin: bool,
        now: Instant,
        srtt: Duration,
    ) -> Result<(), ConnError> {
        let config = self.config;
        let Some(mut stream) = self
            .streams
            .peer_frame(id, Half::Recv, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
            .map_err(|code| ConnError::new(code, "STREAM frame for a stream not open here"))?
        else {
            return self.check_reaped(id, offset.saturating_add(data.len() as u64), fin);
        };
        let Some(recv) = stream.data_mut().recv.as_mut() else {
            return Ok(());
        };
        let end = offset.saturating_add(data.len() as u64);
        recv.flow
            .on_data(&mut self.conn_recv, end, fin, now, srtt)
            .map_err(|e| ConnError::new(e.code(), "STREAM data past the flow control limit"))?;
        let held = recv.buf.ranges();
        let inserted = recv
            .buf
            .insert(offset, data, fin, &mut self.pool)
            .map_err(|e| ConnError::new(e.code(), "STREAM data the receive buffer refuses"))?;
        self.ranges = self.ranges - held + recv.buf.ranges();
        if self.ranges > MAX_CONN_RANGES {
            return Err(ConnError::new(
                RecvError::TooManyRanges.code(),
                "more out-of-order ranges than a connection holds",
            ));
        }
        // Every byte before the FIN was read already, if the stream had any.
        let read = recv.buf.is_finished();
        if inserted.readable > 0 {
            stream.mark(Edge::Readable);
        }
        if fin {
            stream.on_fin();
        }
        if inserted.complete {
            let _ = stream.on_all_received();
            // A stopped receive half does not deliver bytes, so it counts as read once complete.
            if stream.view().stop_code().is_some() {
                let _ = stream.on_all_data_read();
            } else {
                stream.mark(Edge::Finished);
                if read {
                    let _ = stream.on_all_data_read();
                }
            }
        }
        Ok(())
    }

    /// Applies what the frames of a sealed packet change only once sealed: the scheduler rotates
    /// by each stream's bytes.
    pub(crate) fn on_sealed(&mut self, frames: &[SentFrame]) {
        for frame in frames {
            if let SentFrame::Stream { id, len, .. } = *frame
                && let Some(slot) = self.streams.get(id).map(|stream| stream.slot())
            {
                self.streams.commit(slot, id, u64::from(len));
            }
        }
    }

    /// Takes a RESET_STREAM for stream `id` with the peer's `code` and `final_size`. Unless the
    /// receive half already ended, delivery stops and the unread bytes return to the connection
    /// window; either way the final size must agree with what arrived.
    pub(crate) fn on_reset_stream(
        &mut self,
        id: StreamId,
        code: AppCode,
        final_size: u64,
        now: Instant,
        srtt: Duration,
    ) -> Result<(), ConnError> {
        let config = self.config;
        let Some(mut stream) = self
            .streams
            .peer_frame(id, Half::Recv, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
            .map_err(|code| ConnError::new(code, "RESET_STREAM for a stream not open here"))?
        else {
            return self.check_reaped(id, final_size, true);
        };
        let receiving = matches!(
            stream.view().recv_state(),
            Some(RecvState::Recv | RecvState::SizeKnown)
        );
        let Some(recv) = stream.data_mut().recv.as_mut() else {
            return Ok(());
        };
        let final_size_error = || {
            ConnError::new(
                TransportErrorCode::FINAL_SIZE_ERROR,
                "RESET_STREAM against the final size",
            )
        };
        if !receiving {
            return match recv.buf.final_size() {
                Some(size) if size == final_size => Ok(()),
                _ => Err(final_size_error()),
            };
        }
        let held = recv.buf.ranges();
        recv.buf
            .on_reset(final_size, &mut self.pool)
            .map_err(|_| final_size_error())?;
        self.ranges -= held;
        recv.flow
            .on_reset(&mut self.conn_recv, final_size, now, srtt)
            .map_err(|e| ConnError::new(e.code(), "RESET_STREAM past the flow control limit"))?;
        stream.on_reset_received(code, final_size);
        Ok(())
    }

    /// Takes a STOP_SENDING for stream `id` with the peer's `code`: the send half resets with the
    /// peer's code at once, queueing RESET_STREAM whatever the application does, as RFC 9000
    /// requires until the FIN is sent, and the application gets `Stopped`.
    pub(crate) fn on_stop_sending(&mut self, id: StreamId, code: AppCode) -> Result<(), ConnError> {
        let config = self.config;
        let Some(mut stream) = self
            .streams
            .peer_frame(id, Half::Send, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
            .map_err(|code| ConnError::new(code, "STOP_SENDING for a stream not open here"))?
        else {
            return Ok(());
        };
        let resets = stream
            .view()
            .send_state()
            .is_some_and(|s| s.may_send_stream());
        let Some(final_size) = stream
            .view()
            .data()
            .send
            .as_ref()
            .map(|send| send.buf.sent_end())
        else {
            return Ok(());
        };
        if stream.on_stop_sending(code, final_size) == Transition::Moved
            && resets
            && let Some(send) = stream.data_mut().send.as_mut()
        {
            let unsent = send.buf.staged();
            send.buf.reset();
            let was_blocked = std::mem::take(&mut send.push_blocked);
            drop(stream);
            self.drop_staged(unsent);
            self.push_blocked -= u32::from(was_blocked);
        }
        Ok(())
    }

    /// Takes the peer's MAX_DATA; the streams waiting for connection credit never left the
    /// scheduler, so they send again at once.
    pub(crate) fn on_max_data(&mut self, max: u64) {
        if self.conn_send.on_max(max) {
            self.data_blocked.cancel();
        }
    }

    /// Takes the peer's DATA_BLOCKED, which makes our MAX_DATA due.
    pub(crate) fn on_data_blocked(&mut self) {
        self.conn_recv.on_peer_blocked();
    }

    /// Takes the peer's MAX_STREAM_DATA for stream `id`.
    pub(crate) fn on_max_stream_data(&mut self, id: StreamId, max: u64) -> Result<(), ConnError> {
        let config = self.config;
        let Some(mut stream) = self
            .streams
            .peer_frame(id, Half::Send, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
            .map_err(|code| ConnError::new(code, "MAX_STREAM_DATA for a stream not open here"))?
        else {
            return Ok(());
        };
        let rose = stream
            .data_mut()
            .send
            .as_mut()
            .is_some_and(|send| send.credit.on_max(max));
        if rose {
            stream.on_control_sent(Owed::STREAM_DATA_BLOCKED);
        }
        Ok(())
    }

    /// Takes the peer's STREAM_DATA_BLOCKED for stream `id`, which makes our MAX_STREAM_DATA due.
    pub(crate) fn on_stream_data_blocked(&mut self, id: StreamId) -> Result<(), ConnError> {
        let config = self.config;
        let Some(mut stream) = self
            .streams
            .peer_frame(id, Half::Recv, |id| {
                (PEER_ORDER, config.parts(id.initiator(), id.dir()))
            })
            .map_err(|code| {
                ConnError::new(code, "STREAM_DATA_BLOCKED for a stream not open here")
            })?
        else {
            return Ok(());
        };
        let due = stream
            .data_mut()
            .recv
            .as_mut()
            .is_some_and(|recv| recv.flow.on_peer_blocked() == CreditDue::Due);
        if due {
            stream.owe(Owed::MAX_STREAM_DATA);
        }
        Ok(())
    }

    /// Records that a packet carrying stream `id`'s bytes `offset..offset + len` (and its FIN if
    /// `fin`) was acknowledged.
    pub(crate) fn on_stream_acked(&mut self, id: StreamId, offset: u64, len: u16, fin: bool) {
        let Some(mut stream) = self.streams.stream(id) else {
            return;
        };
        let Some(send) = stream.data_mut().send.as_mut() else {
            return;
        };
        send.buf.on_ack(offset, usize::from(len), fin);
        if send.buf.is_acked() {
            let _ = stream.on_all_acked();
        }
    }

    /// Records that a packet carrying stream `id`'s bytes `offset..offset + len` (and its FIN if
    /// `fin`) was lost, or never sealed: they go again unless the send half was reset. Returns
    /// whether any of them became pending again.
    pub(crate) fn on_stream_lost(
        &mut self,
        id: StreamId,
        offset: u64,
        len: u16,
        fin: bool,
    ) -> bool {
        let Some(mut stream) = self.streams.stream(id) else {
            return false;
        };
        if !stream
            .view()
            .send_state()
            .is_some_and(|s| s.may_send_stream())
        {
            return false;
        }
        stream
            .data_mut()
            .send
            .as_mut()
            .is_some_and(|send| send.buf.on_lost(offset, usize::from(len), fin))
    }

    /// Records that a packet carrying a control frame of `kind` about `key` with `value` was
    /// acknowledged.
    pub(crate) fn on_control_acked(&mut self, kind: ControlKind, key: u64, value: u64) {
        match kind {
            ControlKind::MaxData => self.conn_recv.on_update_acked(value),
            ControlKind::MaxStreamData => {
                if let Ok(id) = StreamId::try_from(key)
                    && let Some(mut stream) = self.streams.stream(id)
                    && let Some(recv) = stream.data_mut().recv.as_mut()
                {
                    recv.flow.on_update_acked(value);
                    if !recv.flow.wants_update() {
                        stream.on_control_sent(Owed::MAX_STREAM_DATA);
                    }
                }
            }
            ControlKind::MaxStreamsBidi => self.max_streams[dir_index(Dir::Bi)].on_acked(value),
            ControlKind::MaxStreamsUni => self.max_streams[dir_index(Dir::Uni)].on_acked(value),
            ControlKind::DataBlocked => self.data_blocked.on_acked(value),
            ControlKind::StreamsBlockedBidi => {
                self.streams_blocked[dir_index(Dir::Bi)].on_acked(value);
            }
            ControlKind::StreamsBlockedUni => {
                self.streams_blocked[dir_index(Dir::Uni)].on_acked(value);
            }
            ControlKind::ResetStream => {
                if let Ok(id) = StreamId::try_from(key)
                    && let Some(mut stream) = self.streams.stream(id)
                {
                    let _ = stream.on_reset_acked();
                }
            }
            ControlKind::StreamDataBlocked => {
                if let Ok(id) = StreamId::try_from(key)
                    && let Some(mut stream) = self.streams.stream(id)
                    && let Some(send) = stream.data_mut().send.as_mut()
                    && send.credit.limit() == value
                {
                    send.blocked_delivered = Some(value);
                    stream.on_control_sent(Owed::STREAM_DATA_BLOCKED);
                }
            }
            ControlKind::StopSending => {
                if let Ok(id) = StreamId::try_from(key)
                    && let Some(mut stream) = self.streams.stream(id)
                    && let Some(recv) = stream.data_mut().recv.as_mut()
                {
                    recv.stop_delivered = true;
                    stream.on_control_sent(Owed::STOP_SENDING);
                }
            }
            _ => {}
        }
    }

    /// Records that a packet carrying a control frame of `kind` about `key` with `value` was
    /// lost, or never sealed: the frame is pending again only while `value` is current.
    /// Returns whether it became pending again.
    pub(crate) fn on_control_lost(&mut self, kind: ControlKind, key: u64, value: u64) -> bool {
        let dir = |bidi: bool| if bidi { Dir::Bi } else { Dir::Uni };
        match kind {
            ControlKind::MaxData => self.conn_recv.on_update_lost(value) == CreditDue::Due,
            ControlKind::MaxStreamsBidi | ControlKind::MaxStreamsUni => {
                let dir = dir(kind == ControlKind::MaxStreamsBidi);
                self.max_streams[dir_index(dir)].on_lost(value)
            }
            ControlKind::DataBlocked => {
                if !(self.conn_send.is_blocked_at(value) && self.data_blocked.on_lost(value)) {
                    return false;
                }
                self.drop_stale_data_blocked();
                self.data_blocked.pending().is_some()
            }
            ControlKind::StreamsBlockedBidi | ControlKind::StreamsBlockedUni => {
                let dir = dir(kind == ControlKind::StreamsBlockedBidi);
                self.streams.streams_blocked(dir) == Some(value)
                    && self.streams_blocked[dir_index(dir)].on_lost(value)
            }
            ControlKind::MaxStreamData
            | ControlKind::StreamDataBlocked
            | ControlKind::ResetStream
            | ControlKind::StopSending => self.on_stream_control_lost(kind, key, value),
            _ => false,
        }
    }

    /// Records that a stream's control frame was lost. RESET_STREAM and STOP_SENDING are owed
    /// again and go out while the half states permit them; MAX_STREAM_DATA and STREAM_DATA_BLOCKED
    /// only while their limit is current. A frame is not owed again once the peer acknowledged
    /// another copy.
    fn on_stream_control_lost(&mut self, kind: ControlKind, key: u64, value: u64) -> bool {
        let Ok(id) = StreamId::try_from(key) else {
            return false;
        };
        let Some(mut stream) = self.streams.stream(id) else {
            return false;
        };
        let parts = stream.data_mut();
        let owed = match kind {
            ControlKind::MaxStreamData => parts
                .recv
                .as_mut()
                .is_some_and(|recv| recv.flow.on_update_lost(value) == CreditDue::Due)
                .then_some(Owed::MAX_STREAM_DATA),
            ControlKind::StreamDataBlocked => parts
                .send
                .as_ref()
                .filter(|send| {
                    send.credit.is_blocked_at(value) && send.blocked_delivered != Some(value)
                })
                .map(|_| Owed::STREAM_DATA_BLOCKED),
            ControlKind::ResetStream => Some(Owed::RESET_STREAM),
            ControlKind::StopSending => parts
                .recv
                .as_ref()
                .filter(|recv| !recv.stop_delivered)
                .map(|_| Owed::STOP_SENDING),
            _ => None,
        };
        owed.is_some_and(|owed| stream.owe(owed))
    }

    /// Opens a local stream in direction `dir` at `order`.
    pub(crate) fn open(&mut self, dir: Dir, order: SendOrder) -> Result<StreamId, OpenError> {
        let parts = self.config.parts(self.config.side, dir);
        let opened = self
            .streams
            .open_local(dir, order, parts)
            .map(|stream| stream.id());
        match opened {
            Ok(id) => Ok(id),
            Err(OpenError::StreamLimit) => {
                self.open_refused[dir_index(dir)] = true;
                if let Some(limit) = self.streams.streams_blocked(dir) {
                    self.streams_blocked[dir_index(dir)].raise(limit);
                }
                Err(OpenError::StreamLimit)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::test_epoch;

    fn state() -> StreamState {
        let config = TransportConfig::builder()
            .build()
            .expect("a valid transport config");
        StreamState::new(Side::Server, &config)
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_digest_covers_the_state_of_each_stream() {
        let now = test_epoch();
        let srtt = Duration::from_millis(20);
        let mut s = state();
        let a = StreamId::new(Side::Client, Dir::Bi, 0).unwrap();
        s.on_stream_frame(a, 0, &[0; 10], false, now, srtt).unwrap();
        let before = s.digest();
        s.streams.stream(a).unwrap().set_order(SendOrder {
            urgency: 0,
            ..PEER_ORDER
        });
        let moved = s.digest();
        assert_ne!(moved, before, "the stream's place in the wire order");
        // With the FIN staged, more stream credit does not change list or scheduler membership.
        s.finish(a).unwrap();
        let finished = s.digest();
        s.on_max_stream_data(a, 100).unwrap();
        assert_ne!(s.digest(), finished, "the stream's send credit");
    }

    #[test]
    fn a_late_ack_of_a_frame_declared_lost_keeps_its_resent_copy_from_going_again() {
        let mut s = state();
        let limit = s.max_streams[0].state().0 + 1;
        s.max_streams[0].raise(limit);
        // Written into a packet declared lost, then into another.
        s.max_streams[0].on_written(limit);
        s.on_control_lost(ControlKind::MaxStreamsBidi, 0, limit);
        s.max_streams[0].on_written(limit);
        // The first packet is acknowledged after all, then the second is lost.
        s.on_control_acked(ControlKind::MaxStreamsBidi, 0, limit);
        s.on_control_lost(ControlKind::MaxStreamsBidi, 0, limit);
        assert_eq!(s.max_streams[0].pending(), None, "the peer has the limit");
    }

    #[test]
    fn a_late_ack_of_a_blocked_frame_declared_lost_keeps_its_resent_copy_from_going_again() {
        // Before the peer's transport parameters, the connection credit and the stream limits
        // are zero. A staged byte keeps DATA_BLOCKED owed.
        let mut s = state();
        s.staged = 1;
        assert!(s.conn_send.is_blocked_at(0));
        assert_eq!(s.streams.streams_blocked(Dir::Bi), Some(0));
        s.data_blocked.raise(0);
        s.streams_blocked[0].raise(0);
        fn machine(s: &mut StreamState, kind: ControlKind) -> &mut IncrementalValue {
            match kind {
                ControlKind::DataBlocked => &mut s.data_blocked,
                _ => &mut s.streams_blocked[0],
            }
        }
        for kind in [ControlKind::DataBlocked, ControlKind::StreamsBlockedBidi] {
            machine(&mut s, kind).on_written(0);
            s.on_control_lost(kind, 0, 0);
            machine(&mut s, kind).on_written(0);
            s.on_control_acked(kind, 0, 0);
            s.on_control_lost(kind, 0, 0);
            assert_eq!(
                machine(&mut s, kind).pending(),
                None,
                "the peer has {kind:?}"
            );
        }
    }

    #[test]
    fn a_late_loss_with_nothing_staged_leaves_a_data_blocked_frame_the_peer_has() {
        // Before the peer's transport parameters, the connection credit is zero.
        let mut s = state();
        s.staged = 1;
        s.note_conn_blocked();
        assert_eq!(s.data_blocked.pending(), Some(0));
        // Written into a packet declared lost, then into another; the bytes are dropped, and
        // the first packet is acknowledged after all before the second is lost.
        s.data_blocked.on_written(0);
        s.on_control_lost(ControlKind::DataBlocked, 0, 0);
        s.data_blocked.on_written(0);
        s.drop_staged(1);
        s.on_control_acked(ControlKind::DataBlocked, 0, 0);
        s.on_control_lost(ControlKind::DataBlocked, 0, 0);
        s.staged = 1;
        s.note_conn_blocked();
        assert_eq!(
            s.data_blocked.pending(),
            None,
            "the peer has DATA_BLOCKED(0)"
        );
    }
}
