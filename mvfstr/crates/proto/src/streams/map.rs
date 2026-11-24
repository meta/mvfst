/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The stream map (RFC 9000).
//!
//! [`StreamMap<T>`] keeps per-stream values in a generational slab and finds them by stream ID
//! through one window per stream type: a deque of slab slots indexed by the ID's offset from the
//! window's base. Removing the oldest streams slides the window; a long-lived stream that would
//! hold a window open at more than four times its live entries moves to a small sorted straggler
//! list instead. A stream below the window extends it downward when the window stays within that
//! bound, so lower streams named after a higher one stay in the window. The transport keeps its
//! streams in one, and H3 or MoQ can keep their own per-stream state in another without a hash
//! map.
//!
//! [`StreamTable<T>`] is the connection's stream map: a `StreamMap<T>` plus the stream ID
//! accounting of RFC 9000. It opens local streams under the peer's limit, resolves the stream
//! named by a peer frame (opening lower peer IDs implicitly and materializing them lazily from an
//! interval set, and raising STREAM_LIMIT_ERROR or STREAM_STATE_ERROR), and raises MAX_STREAMS as
//! peer streams are reaped, with mvfst's windowing rule, until shutdown freezes it.

use std::collections::VecDeque;
use std::ops::Range;

use mvfstr_wire::Dir;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;

use crate::OpenError;

/// A handle to a value in a [`StreamMap`], valid until that value is removed: removal bumps the
/// slot's generation, so a lookup by a stale key returns `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamKey {
    slot: u32,
    generation: u32,
}

impl StreamKey {
    /// Returns the slab slot. Per-slot structures such as the scheduler index by it.
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Returns the slot's generation when the key was made.
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// A map from stream ID to `T` over a generational slab, with one ID window per stream type.
pub struct StreamMap<T> {
    slots: Vec<Slot<T>>,
    /// Free slots, reused last-freed first.
    free: Vec<u32>,
    windows: [Window; 4],
    len: usize,
}

struct Slot<T> {
    generation: u32,
    value: Option<(StreamId, T)>,
}

/// Slab slots of one stream type, by stream index.
#[derive(Default)]
struct Window {
    /// The stream index of `entries[0]`.
    base: u64,
    /// A slab slot, or [`EMPTY`], per stream index from `base`.
    entries: VecDeque<u32>,
    /// The number of entries that are not [`EMPTY`].
    live: usize,
    /// `(index, slot)` of live streams below `base`, sorted by index.
    stragglers: Vec<(u64, u32)>,
}

/// The window entry for an index that does not have a live stream.
const EMPTY: u32 = u32::MAX;

/// The windowing fraction, mvfst's default: MAX_STREAMS rises once
/// `initial / MAX_STREAMS_WINDOW_FRACTION` streams of credit are free.
const MAX_STREAMS_WINDOW_FRACTION: u64 = 2;

/// The longest window, in entries, that is never compacted.
const MIN_WINDOW: usize = 64;

impl<T> Default for StreamMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> StreamMap<T> {
    /// Creates an empty map.
    pub fn new() -> Self {
        StreamMap {
            slots: Vec::new(),
            free: Vec::new(),
            windows: Default::default(),
            len: 0,
        }
    }

    /// Returns the number of values.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Stores `value` for `id` and returns its key, or gives `value` back if `id` has one.
    pub fn insert(&mut self, id: StreamId, value: T) -> Result<StreamKey, T> {
        if self.key(id).is_some() {
            return Err(value);
        }
        let slot = match self.free.pop() {
            Some(slot) => {
                self.slots[slot as usize].value = Some((id, value));
                slot
            }
            None => {
                // Invariant: a connection holds far fewer than 2^32 - 1 streams at once (the
                // stream limits bound them), so a slot index fits below EMPTY.
                let slot = u32::try_from(self.slots.len())
                    .ok()
                    .filter(|&slot| slot != EMPTY)
                    .expect("fewer than 2^32 - 1 live streams");
                self.slots.push(Slot {
                    generation: 0,
                    value: Some((id, value)),
                });
                slot
            }
        };
        self.windows[type_index(id)].place(id.index(), slot);
        self.len += 1;
        Ok(StreamKey {
            slot,
            generation: self.slots[slot as usize].generation,
        })
    }

    /// Returns the key of `id`'s value.
    pub fn key(&self, id: StreamId) -> Option<StreamKey> {
        let slot = self.windows[type_index(id)].find(id.index())?;
        Some(StreamKey {
            slot,
            generation: self.slots[slot as usize].generation,
        })
    }

    /// Returns `id`'s value.
    pub fn get(&self, id: StreamId) -> Option<&T> {
        let key = self.key(id)?;
        self.get_by_key(key).map(|(_, value)| value)
    }

    /// Returns `id`'s value, mutably.
    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut T> {
        let key = self.key(id)?;
        self.get_by_key_mut(key).map(|(_, value)| value)
    }

    /// Returns the value that `key` names, unless it was removed since.
    pub fn get_by_key(&self, key: StreamKey) -> Option<(StreamId, &T)> {
        let slot = self.slots.get(key.slot as usize)?;
        if slot.generation != key.generation {
            return None;
        }
        slot.value.as_ref().map(|(id, value)| (*id, value))
    }

    /// Returns the value that `key` names, mutably, unless it was removed since.
    pub fn get_by_key_mut(&mut self, key: StreamKey) -> Option<(StreamId, &mut T)> {
        let slot = self.slots.get_mut(key.slot as usize)?;
        if slot.generation != key.generation {
            return None;
        }
        slot.value.as_mut().map(|(id, value)| (*id, value))
    }

    /// Returns the value in slab slot `slot`, whatever its generation.
    pub fn get_slot(&self, slot: u32) -> Option<(StreamKey, StreamId, &T)> {
        let entry = self.slots.get(slot as usize)?;
        let (id, value) = entry.value.as_ref()?;
        let key = StreamKey {
            slot,
            generation: entry.generation,
        };
        Some((key, *id, value))
    }

    /// Returns the value in slab slot `slot`, mutably, whatever its generation.
    pub fn get_slot_mut(&mut self, slot: u32) -> Option<(StreamKey, StreamId, &mut T)> {
        let entry = self.slots.get_mut(slot as usize)?;
        let (id, value) = entry.value.as_mut()?;
        let key = StreamKey {
            slot,
            generation: entry.generation,
        };
        Some((key, *id, value))
    }

    /// Iterates over every value with its key and ID, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (StreamKey, StreamId, &T)> {
        (0..self.slots.len() as u32).filter_map(|slot| self.get_slot(slot))
    }

    /// Removes `id`'s value, freeing its slot for reuse under a new generation.
    pub fn remove(&mut self, id: StreamId) -> Option<T> {
        let slot = self.windows[type_index(id)].take(id.index())?;
        let entry = &mut self.slots[slot as usize];
        entry.generation = entry.generation.wrapping_add(1);
        let (_, value) = entry.value.take()?;
        self.free.push(slot);
        self.len -= 1;
        Some(value)
    }
}

/// The half of a stream that a peer frame concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    /// Our receiving part: STREAM, RESET_STREAM and STREAM_DATA_BLOCKED.
    Recv,
    /// Our sending part: MAX_STREAM_DATA and STOP_SENDING.
    Send,
}

/// The stream a peer frame names, from [`StreamTable::peer_frame`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStream {
    /// An open stream.
    Live(StreamKey),
    /// A peer stream that this frame opened, or an implicitly opened one that it materialized,
    /// not yet reported to the application.
    Opened(StreamKey),
    /// A stream that was open and has been reaped; apart from final-size checks the frame is
    /// ignored.
    Closed,
}

/// The connection's streams: a [`StreamMap`] plus the stream ID accounting of RFC 9000.
pub struct StreamTable<T> {
    side: Side,
    map: StreamMap<T>,
    /// Streams we open, by direction.
    local: [LocalIds; 2],
    /// Streams the peer opens, by direction.
    peer: [PeerIds; 2],
    /// Whether [`shutdown`](Self::shutdown) has run: local opens fail and MAX_STREAMS stops rising.
    frozen: bool,
}

/// The IDs of one direction of locally opened streams.
#[derive(Default)]
struct LocalIds {
    /// The index of the next stream we open.
    next: u64,
    /// The peer's limit: we may open indices below it.
    limit: u64,
}

/// The IDs of one direction of peer-opened streams.
struct PeerIds {
    /// One past the highest index the peer has opened, explicitly or implicitly.
    next: u64,
    /// The limit for the next MAX_STREAMS.
    max: u64,
    /// The highest limit sent, in the transport parameters or a MAX_STREAMS frame: the peer may
    /// open indices below it. At most `max`.
    sent: u64,
    /// The initial limit, which MAX_STREAMS keeps the open-plus-openable count at.
    initial: u64,
    /// The number of open streams: materialized and not reaped, plus implicitly opened ones.
    open: u64,
    /// The streams opened implicitly and not yet materialized.
    implicit: IntervalSet,
}

/// Disjoint, non-adjacent ranges of stream indices in ascending order.
#[derive(Default)]
struct IntervalSet {
    ranges: Vec<Range<u64>>,
}

fn dir_index(dir: Dir) -> usize {
    match dir {
        Dir::Bi => 0,
        Dir::Uni => 1,
    }
}

impl<T> StreamTable<T> {
    /// Creates an empty table at the endpoint whose role is `side`, advertising `max_streams_bidi`
    /// and `max_streams_uni` (initial_max_streams_bidi and _uni, at most 2^60). The peer's limits
    /// start at zero until [`on_peer_max_streams`](Self::on_peer_max_streams).
    pub fn new(side: Side, max_streams_bidi: u64, max_streams_uni: u64) -> Self {
        let peer = |initial: u64| PeerIds {
            next: 0,
            max: initial,
            sent: initial,
            initial,
            open: 0,
            implicit: IntervalSet::default(),
        };
        StreamTable {
            side,
            map: StreamMap::new(),
            local: Default::default(),
            peer: [peer(max_streams_bidi), peer(max_streams_uni)],
            frozen: false,
        }
    }

    /// Returns this endpoint's role.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Returns the streams.
    pub fn map(&self) -> &StreamMap<T> {
        &self.map
    }

    /// Returns `id`'s stream, mutably. Insertions and removals go through the table.
    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut T> {
        self.map.get_mut(id)
    }

    /// Returns the stream in slab slot `slot`, mutably.
    pub fn get_slot_mut(&mut self, slot: u32) -> Option<(StreamKey, StreamId, &mut T)> {
        self.map.get_slot_mut(slot)
    }

    /// Opens the next local stream in direction `dir` with the value `make` returns for it.
    pub fn open_local(
        &mut self,
        dir: Dir,
        make: impl FnOnce(StreamId) -> T,
    ) -> Result<(StreamId, StreamKey), OpenError> {
        if self.frozen {
            return Err(OpenError::Closed);
        }
        let ids = &mut self.local[dir_index(dir)];
        if ids.next >= ids.limit {
            return Err(OpenError::StreamLimit);
        }
        // The peer's limit is at most 2^60 (checked on receipt), so the index is valid.
        let id = StreamId::new(self.side, dir, ids.next).ok_or(OpenError::StreamLimit)?;
        ids.next += 1;
        let key = self.insert(id, make(id));
        Ok((id, key))
    }

    /// Applies the peer's stream limit for `dir` from a transport parameter or MAX_STREAMS and
    /// returns whether it rose. A limit that does not rise is ignored. One above 2^60 fails with
    /// FRAME_ENCODING_ERROR, which the caller turns into TRANSPORT_PARAMETER_ERROR for a
    /// transport parameter, as RFC 9000 requires.
    pub fn on_peer_max_streams(&mut self, dir: Dir, max: u64) -> Result<bool, TransportErrorCode> {
        if max > StreamId::INDEX_LIMIT {
            return Err(TransportErrorCode::FRAME_ENCODING_ERROR);
        }
        let ids = &mut self.local[dir_index(dir)];
        if max <= ids.limit {
            return Ok(false);
        }
        ids.limit = max;
        Ok(true)
    }

    /// Returns how many more local streams in direction `dir` the peer's limit allows, or 0 after
    /// [`shutdown`](Self::shutdown).
    pub fn openable_local(&self, dir: Dir) -> u64 {
        if self.frozen {
            return 0;
        }
        let ids = &self.local[dir_index(dir)];
        ids.limit.saturating_sub(ids.next)
    }

    /// Returns the peer's limit on local streams in direction `dir`, and the index of the next one.
    pub fn local_limit(&self, dir: Dir) -> (u64, u64) {
        let ids = &self.local[dir_index(dir)];
        (ids.limit, ids.next)
    }

    /// Returns the peer's limit for direction `dir` if it stops the next local open: the value
    /// for a STREAMS_BLOCKED frame.
    pub fn streams_blocked(&self, dir: Dir) -> Option<u64> {
        let ids = &self.local[dir_index(dir)];
        (ids.next >= ids.limit).then_some(ids.limit)
    }

    /// Resolves the stream a peer frame names: an open stream, a peer stream the frame opens, or a
    /// reaped one. As RFC 9000 requires, a peer stream opens with every lower peer ID of its type;
    /// those open implicitly and are materialized only when a frame names them. `make` gives the
    /// value of a stream the frame opens.
    ///
    /// Fails with STREAM_LIMIT_ERROR when the frame names a peer stream at or above the limit we
    /// have sent, even if a higher one is waiting to go out, and with STREAM_STATE_ERROR when it
    /// names a local stream not yet opened or a half the stream does not have here.
    pub fn peer_frame(
        &mut self,
        id: StreamId,
        half: Half,
        make: impl FnOnce(StreamId) -> T,
    ) -> Result<PeerStream, TransportErrorCode> {
        let local = id.initiator() == self.side;
        let has_half = match (id.dir(), half) {
            (Dir::Bi, _) => true,
            (Dir::Uni, Half::Recv) => !local,
            (Dir::Uni, Half::Send) => local,
        };
        if !has_half {
            return Err(TransportErrorCode::STREAM_STATE_ERROR);
        }
        if let Some(key) = self.map.key(id) {
            return Ok(PeerStream::Live(key));
        }
        if local {
            if id.index() >= self.local[dir_index(id.dir())].next {
                return Err(TransportErrorCode::STREAM_STATE_ERROR);
            }
            return Ok(PeerStream::Closed);
        }
        let ids = &mut self.peer[dir_index(id.dir())];
        let index = id.index();
        if index >= ids.sent {
            return Err(TransportErrorCode::STREAM_LIMIT_ERROR);
        }
        if index >= ids.next {
            ids.implicit.push_above(ids.next..index);
            ids.open += index + 1 - ids.next;
            ids.next = index + 1;
        } else if !ids.implicit.remove(index) {
            return Ok(PeerStream::Closed);
        }
        Ok(PeerStream::Opened(self.insert(id, make(id))))
    }

    /// Materializes `id`, if it is a peer stream opened implicitly and not yet materialized, with
    /// the value `make` returns for it, as when the application looks it up before a frame names
    /// it. Returns its key, or `None` if `id` is not such a stream.
    pub fn materialize(
        &mut self,
        id: StreamId,
        make: impl FnOnce(StreamId) -> T,
    ) -> Option<StreamKey> {
        if id.initiator() == self.side
            || !self.peer[dir_index(id.dir())].implicit.remove(id.index())
        {
            return None;
        }
        Some(self.insert(id, make(id)))
    }

    /// Removes a closed stream for good: its slot is freed under a new generation, frames for it
    /// resolve to [`PeerStream::Closed`], and for a peer stream MAX_STREAMS may rise. Returns the
    /// stream's value, or `None` if `id` is not in the table.
    pub fn reap(&mut self, id: StreamId) -> Option<T> {
        let value = self.map.remove(id)?;
        if id.initiator() != self.side {
            let ids = &mut self.peer[dir_index(id.dir())];
            ids.open -= 1;
            // Once the credit the peer lost to open and used streams reaches a window, give it
            // back in one MAX_STREAMS.
            let openable = ids.max - ids.next;
            let credit = ids.initial.saturating_sub(openable + ids.open);
            let window = (ids.initial / MAX_STREAMS_WINDOW_FRACTION).max(1);
            if credit >= window && !self.frozen {
                ids.max = (ids.max + credit).min(StreamId::INDEX_LIMIT);
            }
        }
        Some(value)
    }

    /// Records that a MAX_STREAMS frame carrying `max` for peer streams in direction `dir` was
    /// sealed in a packet, so the peer may now open streams below `max`. A value above
    /// [`max_streams`](Self::max_streams) counts as that limit.
    pub fn on_max_streams_sent(&mut self, dir: Dir, max: u64) {
        let ids = &mut self.peer[dir_index(dir)];
        ids.sent = ids.sent.max(max.min(ids.max));
    }

    /// Stops new streams: local opens fail with [`OpenError::Closed`] and MAX_STREAMS no longer
    /// rises, so the peer can open only what it already may.
    pub fn shutdown(&mut self) {
        self.frozen = true;
    }

    /// Returns the limit for peer streams in direction `dir` that the next MAX_STREAMS carries.
    /// Peer frames are held to it once [`on_max_streams_sent`](Self::on_max_streams_sent)
    /// reports it sent.
    pub fn max_streams(&self, dir: Dir) -> u64 {
        self.peer[dir_index(dir)].max
    }

    /// Returns whether `id` is a peer stream opened implicitly and not yet materialized.
    pub fn implicitly_open(&self, id: StreamId) -> bool {
        id.initiator() != self.side && self.peer[dir_index(id.dir())].implicit.contains(id.index())
    }

    fn insert(&mut self, id: StreamId, value: T) -> StreamKey {
        match self.map.insert(id, value) {
            Ok(key) => key,
            // Invariant: IDs are inserted once, when first opened or materialized, and removed
            // only by reaping, after which they are never inserted again.
            Err(_) => unreachable!("stream {id} inserted twice"),
        }
    }
}

impl IntervalSet {
    /// Adds `range`, which lies above every range in the set.
    fn push_above(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        match self.ranges.last_mut() {
            Some(last) if last.end == range.start => last.end = range.end,
            last => {
                debug_assert!(last.is_none_or(|last| last.end < range.start));
                self.ranges.push(range);
            }
        }
    }

    fn contains(&self, index: u64) -> bool {
        let at = self.ranges.partition_point(|r| r.end <= index);
        self.ranges.get(at).is_some_and(|r| r.start <= index)
    }

    /// Removes `index` and returns whether it was in the set.
    fn remove(&mut self, index: u64) -> bool {
        let at = self.ranges.partition_point(|r| r.end <= index);
        let Some(range) = self.ranges.get_mut(at) else {
            return false;
        };
        if range.start > index {
            return false;
        }
        if range.start == index {
            range.start += 1;
            if range.is_empty() {
                self.ranges.remove(at);
            }
        } else if range.end == index + 1 {
            range.end = index;
        } else {
            let upper = index + 1..range.end;
            range.end = index;
            self.ranges.insert(at + 1, upper);
        }
        true
    }
}

impl<T> StreamMap<T> {
    #[cfg(test)]
    fn window_len(&self, id: StreamId) -> usize {
        self.windows[type_index(id)].entries.len()
    }

    #[cfg(test)]
    fn straggler_count(&self, id: StreamId) -> usize {
        self.windows[type_index(id)].stragglers.len()
    }
}

/// Returns the index of the window for `id`'s type, which the ID's two low bits encode (RFC 9000).
fn type_index(id: StreamId) -> usize {
    (id.into_inner() & 3) as usize
}

impl Window {
    fn end(&self) -> u64 {
        self.base + self.entries.len() as u64
    }

    /// Returns how many entries a window with `live` live entries may span before compaction.
    fn limit(live: usize) -> usize {
        MIN_WINDOW.max(4 * live)
    }

    fn find(&self, index: u64) -> Option<u32> {
        if index < self.base {
            let at = self
                .stragglers
                .binary_search_by_key(&index, |&(i, _)| i)
                .ok()?;
            return Some(self.stragglers[at].1);
        }
        let offset = usize::try_from(index - self.base).ok()?;
        let slot = *self.entries.get(offset)?;
        (slot != EMPTY).then_some(slot)
    }

    /// Records `slot` for `index`, which does not have a live entry.
    fn place(&mut self, index: u64, slot: u32) {
        // Stragglers enter below `base`, and `base` falls only to an index above every straggler,
        // so every straggler is below `base`.
        debug_assert!(self.stragglers.last().is_none_or(|&(i, _)| i < self.base));
        if index < self.base {
            let above_stragglers = self.stragglers.last().is_none_or(|&(i, _)| i < index);
            let fits =
                self.entries.is_empty() || self.end() - index <= Self::limit(self.live + 1) as u64;
            if !above_stragglers || !fits {
                let at = self.stragglers.partition_point(|&(i, _)| i < index);
                self.stragglers.insert(at, (index, slot));
                return;
            }
            if self.entries.is_empty() {
                self.base = index;
            }
            while self.base > index {
                self.entries.push_front(EMPTY);
                self.base -= 1;
            }
        }
        if index >= self.end() {
            // Keep the window within its limit by moving the oldest live entries out, rather
            // than filling a long gap below a far-ahead stream.
            while !self.entries.is_empty() && index - self.base >= Self::limit(self.live + 1) as u64
            {
                self.evict_front();
            }
            if self.entries.is_empty() {
                self.base = index;
            }
            while index >= self.end() {
                self.entries.push_back(EMPTY);
            }
        }
        self.entries[(index - self.base) as usize] = slot;
        self.live += 1;
    }

    /// Clears `index`'s entry and returns its slot, then drops empty entries from both ends and
    /// compacts the window if it spans more than its limit.
    fn take(&mut self, index: u64) -> Option<u32> {
        if index < self.base {
            let at = self
                .stragglers
                .binary_search_by_key(&index, |&(i, _)| i)
                .ok()?;
            return Some(self.stragglers.remove(at).1);
        }
        let slot = self.find(index)?;
        self.entries[(index - self.base) as usize] = EMPTY;
        self.live -= 1;
        self.trim_front();
        while self.entries.back() == Some(&EMPTY) {
            self.entries.pop_back();
        }
        while self.entries.len() > Self::limit(self.live) {
            self.evict_front();
        }
        Some(slot)
    }

    /// Moves the first entry, which is live, to the stragglers.
    fn evict_front(&mut self) {
        if let Some(slot) = self.entries.pop_front() {
            debug_assert_ne!(slot, EMPTY, "the window starts with a live entry");
            self.stragglers.push((self.base, slot));
            self.base += 1;
            self.live -= 1;
            self.trim_front();
        }
    }

    fn trim_front(&mut self) {
        while self.entries.front() == Some(&EMPTY) {
            self.entries.pop_front();
            self.base += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_wire::Dir;
    use mvfstr_wire::Side;

    use super::*;

    fn cb(index: u64) -> StreamId {
        StreamId::new(Side::Client, Dir::Bi, index).unwrap()
    }

    fn su(index: u64) -> StreamId {
        StreamId::new(Side::Server, Dir::Uni, index).unwrap()
    }

    #[test]
    fn map_finds_values_by_id_and_key() {
        let mut map = StreamMap::new();
        let k0 = map.insert(cb(0), "a").unwrap();
        let k1 = map.insert(cb(1), "b").unwrap();
        let k2 = map.insert(su(0), "c").unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(cb(0)), Some(&"a"));
        assert_eq!(map.get(cb(1)), Some(&"b"));
        assert_eq!(map.get(su(0)), Some(&"c"));
        assert_eq!(map.get(cb(2)), None);
        assert_eq!(map.get(su(1)), None);
        assert_eq!(map.key(cb(1)), Some(k1));
        assert_eq!(map.get_by_key(k0), Some((cb(0), &"a")));
        assert_eq!(map.get_by_key(k2), Some((su(0), &"c")));
        *map.get_mut(cb(1)).unwrap() = "B";
        assert_eq!(
            map.get_by_key_mut(k1).map(|(id, v)| (id, *v)),
            Some((cb(1), "B"))
        );
        assert_eq!(map.insert(cb(1), "dup"), Err("dup"));
    }

    #[test]
    fn removal_frees_the_slot_under_a_new_generation() {
        let mut map = StreamMap::new();
        let old = map.insert(cb(0), 1).unwrap();
        map.insert(cb(1), 2).unwrap();
        assert_eq!(map.remove(cb(0)), Some(1));
        assert_eq!(map.remove(cb(0)), None);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(cb(0)), None);
        assert_eq!(map.key(cb(0)), None);
        assert_eq!(map.get_by_key(old), None);
        // The next value reuses the slot; a lookup by the old key still returns `None`.
        let new = map.insert(cb(2), 3).unwrap();
        assert_eq!(new.slot(), old.slot());
        assert_ne!(new.generation(), old.generation());
        assert_eq!(map.get_by_key(old), None);
        assert_eq!(map.get_by_key(new), Some((cb(2), &3)));
        assert_eq!(map.get(cb(1)), Some(&2));
    }

    #[test]
    fn a_long_lived_stream_does_not_hold_the_window_open() {
        let mut map = StreamMap::new();
        map.insert(cb(0), 0).unwrap();
        for index in 1..=1000 {
            map.insert(cb(index), index).unwrap();
            if index > 1 {
                assert_eq!(map.remove(cb(index - 1)), Some(index - 1));
            }
            assert!(
                map.window_len(cb(0)) <= MIN_WINDOW,
                "window of {} entries for 2 live streams",
                map.window_len(cb(0))
            );
        }
        assert_eq!(map.get(cb(0)), Some(&0));
        assert_eq!(map.get(cb(1000)), Some(&1000));
        assert_eq!(map.get(cb(999)), None);
        assert_eq!(map.remove(cb(0)), Some(0));
        assert_eq!(map.get(cb(0)), None);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn far_apart_ids_do_not_fill_the_gap_between_them() {
        let mut map = StreamMap::new();
        map.insert(su(5), 5).unwrap();
        map.insert(su(1_000_000), 1).unwrap();
        assert!(map.window_len(su(0)) <= MIN_WINDOW);
        // An ID below the window still gets its own entry.
        map.insert(su(3), 3).unwrap();
        map.insert(su(999_999), 9).unwrap();
        assert!(map.window_len(su(0)) <= MIN_WINDOW);
        for (index, value) in [(5, 5), (1_000_000, 1), (3, 3), (999_999, 9)] {
            assert_eq!(map.get(su(index)), Some(&value), "{index}");
        }
        for index in [0, 4, 6, 999_998, 1_000_001] {
            assert_eq!(map.get(su(index)), None, "{index}");
        }
        for index in [3, 999_999, 5, 1_000_000] {
            assert!(map.remove(su(index)).is_some(), "{index}");
        }
        assert!(map.is_empty());
    }

    #[test]
    fn streams_named_below_the_window_extend_it_downward() {
        // A peer may name a high stream before the lower ones it opened implicitly.
        let mut map = StreamMap::new();
        for index in (0..1000).rev() {
            map.insert(cb(index), index).unwrap();
        }
        assert_eq!(map.straggler_count(cb(0)), 0);
        assert_eq!(map.window_len(cb(0)), 1000);
        for index in 0..1000 {
            assert_eq!(map.get(cb(index)), Some(&index), "{index}");
        }
        for index in 0..1000 {
            assert_eq!(map.remove(cb(index)), Some(index), "{index}");
        }
        assert!(map.is_empty());
        assert_eq!(map.window_len(cb(0)), 0);
    }

    fn id(side: Side, dir: Dir, index: u64) -> StreamId {
        StreamId::new(side, dir, index).unwrap()
    }

    #[test]
    fn local_opens_count_up_per_direction_under_the_peer_limit() {
        let mut table = StreamTable::new(Side::Server, 10, 10);
        assert_eq!(
            table.open_local(Dir::Uni, |_| ()).map(|(id, _)| id),
            Err(OpenError::StreamLimit)
        );
        assert_eq!(table.on_peer_max_streams(Dir::Uni, 2), Ok(true));
        assert_eq!(table.on_peer_max_streams(Dir::Bi, 1), Ok(true));
        let open =
            |table: &mut StreamTable<()>, dir| table.open_local(dir, |_| ()).map(|(id, _)| id);
        assert_eq!(
            open(&mut table, Dir::Uni),
            Ok(id(Side::Server, Dir::Uni, 0))
        );
        assert_eq!(open(&mut table, Dir::Bi), Ok(id(Side::Server, Dir::Bi, 0)));
        assert_eq!(
            open(&mut table, Dir::Uni),
            Ok(id(Side::Server, Dir::Uni, 1))
        );
        assert_eq!(open(&mut table, Dir::Uni), Err(OpenError::StreamLimit));
        assert_eq!(open(&mut table, Dir::Bi), Err(OpenError::StreamLimit));
        // A lower or equal limit is ignored; a higher one lets the next open through.
        assert_eq!(table.on_peer_max_streams(Dir::Uni, 1), Ok(false));
        assert_eq!(table.on_peer_max_streams(Dir::Uni, 2), Ok(false));
        assert_eq!(open(&mut table, Dir::Uni), Err(OpenError::StreamLimit));
        assert_eq!(table.on_peer_max_streams(Dir::Uni, 3), Ok(true));
        assert_eq!(
            open(&mut table, Dir::Uni),
            Ok(id(Side::Server, Dir::Uni, 2))
        );
        assert_eq!(table.map().len(), 4);
    }

    #[test]
    fn a_peer_limit_above_two_to_the_sixty_is_a_frame_encoding_error() {
        // The caller maps it to TRANSPORT_PARAMETER_ERROR for a transport parameter (RFC 9000).
        let mut table = StreamTable::<()>::new(Side::Client, 0, 0);
        assert_eq!(
            table.on_peer_max_streams(Dir::Bi, StreamId::INDEX_LIMIT + 1),
            Err(TransportErrorCode::FRAME_ENCODING_ERROR)
        );
        assert_eq!(
            table.on_peer_max_streams(Dir::Bi, StreamId::INDEX_LIMIT),
            Ok(true)
        );
    }

    #[test]
    fn a_peer_frame_opens_lower_ids_implicitly_and_materializes_them_lazily() {
        let mut table = StreamTable::new(Side::Server, 10, 10);
        let c = |index| id(Side::Client, Dir::Bi, index);
        let opened = table.peer_frame(c(3), Half::Recv, |id| id.index()).unwrap();
        let PeerStream::Opened(k3) = opened else {
            panic!("{opened:?}");
        };
        assert_eq!(table.map().get_by_key(k3), Some((c(3), &3)));
        // Streams 0 to 2 opened too, but take a slot only when a frame names them.
        assert_eq!(table.map().len(), 1);
        for index in 0..3 {
            assert!(table.implicitly_open(c(index)), "{index}");
        }
        assert!(!table.implicitly_open(c(3)));
        assert!(!table.implicitly_open(c(4)));
        let opened = table.peer_frame(c(1), Half::Send, |id| id.index()).unwrap();
        let PeerStream::Opened(k1) = opened else {
            panic!("{opened:?}");
        };
        assert_eq!(table.map().get_by_key(k1), Some((c(1), &1)));
        assert!(!table.implicitly_open(c(1)));
        assert!(table.implicitly_open(c(0)) && table.implicitly_open(c(2)));
        assert_eq!(
            table.peer_frame(c(3), Half::Recv, |_| unreachable!()),
            Ok(PeerStream::Live(k3))
        );
        assert_eq!(
            table.peer_frame(c(1), Half::Recv, |_| unreachable!()),
            Ok(PeerStream::Live(k1))
        );
        assert_eq!(table.map().len(), 2);
    }

    #[test]
    fn a_peer_stream_at_or_above_our_limit_is_a_stream_limit_error() {
        // With a unidirectional limit of 3 the client may open streams 2, 6 and 10 (RFC 9000).
        let mut table = StreamTable::new(Side::Server, 0, 3);
        let c = |index| id(Side::Client, Dir::Uni, index);
        assert_eq!(
            table.peer_frame(c(3), Half::Recv, |_| ()),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
        assert_eq!(table.map().len(), 0);
        assert!(!table.implicitly_open(c(0)));
        assert!(matches!(
            table.peer_frame(c(2), Half::Recv, |_| ()),
            Ok(PeerStream::Opened(_))
        ));
        assert_eq!(
            table.peer_frame(id(Side::Client, Dir::Bi, 0), Half::Recv, |_| ()),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
    }

    #[test]
    fn frames_for_unopened_local_streams_or_missing_halves_are_stream_state_errors() {
        let mut table = StreamTable::new(Side::Client, 10, 10);
        table.on_peer_max_streams(Dir::Bi, 10).unwrap();
        table.on_peer_max_streams(Dir::Uni, 10).unwrap();
        let (bi, bi_key) = table.open_local(Dir::Bi, |_| ()).unwrap();
        let (uni, _) = table.open_local(Dir::Uni, |_| ()).unwrap();
        let state_error = Err(TransportErrorCode::STREAM_STATE_ERROR);
        // Any frame for a local stream not yet opened; RFC 9000 requires this for STREAM,
        // STOP_SENDING and MAX_STREAM_DATA.
        for half in [Half::Recv, Half::Send] {
            for unopened in [id(Side::Client, Dir::Bi, 1), id(Side::Client, Dir::Uni, 1)] {
                assert_eq!(table.peer_frame(unopened, half, |_| ()), state_error);
            }
        }
        // STREAM, RESET_STREAM or STREAM_DATA_BLOCKED on a send-only stream.
        assert_eq!(table.peer_frame(uni, Half::Recv, |_| ()), state_error);
        assert!(matches!(
            table.peer_frame(uni, Half::Send, |_| ()),
            Ok(PeerStream::Live(_))
        ));
        // MAX_STREAM_DATA or STOP_SENDING on a receive-only stream.
        let peer_uni = id(Side::Server, Dir::Uni, 0);
        assert_eq!(table.peer_frame(peer_uni, Half::Send, |_| ()), state_error);
        assert!(!table.implicitly_open(peer_uni));
        assert_eq!(table.map().len(), 2);
        assert_eq!(
            table.peer_frame(bi, Half::Recv, |_| ()),
            Ok(PeerStream::Live(bi_key))
        );
        assert_eq!(
            table.peer_frame(bi, Half::Send, |_| ()),
            Ok(PeerStream::Live(bi_key))
        );
    }

    #[test]
    fn reaped_streams_resolve_as_closed() {
        let mut table = StreamTable::new(Side::Server, 10, 10);
        table.on_peer_max_streams(Dir::Uni, 10).unwrap();
        let (local, local_key) = table.open_local(Dir::Uni, |_| 'l').unwrap();
        let peer = id(Side::Client, Dir::Bi, 0);
        let Ok(PeerStream::Opened(peer_key)) = table.peer_frame(peer, Half::Recv, |_| 'p') else {
            panic!("not opened");
        };
        assert_eq!(table.reap(local), Some('l'));
        assert_eq!(table.reap(peer), Some('p'));
        assert_eq!(table.reap(peer), None);
        assert!(table.map().is_empty());
        assert_eq!(table.map().get_by_key(local_key), None);
        assert_eq!(table.map().get_by_key(peer_key), None);
        assert_eq!(
            table.peer_frame(local, Half::Send, |_| '!'),
            Ok(PeerStream::Closed)
        );
        assert_eq!(
            table.peer_frame(peer, Half::Recv, |_| '!'),
            Ok(PeerStream::Closed)
        );
        assert_eq!(
            table.peer_frame(peer, Half::Send, |_| '!'),
            Ok(PeerStream::Closed)
        );
        assert!(table.map().is_empty());
    }

    /// Opens peer unidirectional streams `indices` with frames from the client.
    fn peer_opens(table: &mut StreamTable<()>, indices: Range<u64>) {
        for index in indices {
            let opened = table.peer_frame(id(Side::Client, Dir::Uni, index), Half::Recv, |_| ());
            assert!(
                matches!(opened, Ok(PeerStream::Opened(_))),
                "{index}: {opened:?}"
            );
        }
    }

    #[test]
    fn max_streams_rises_on_reap_once_a_window_fraction_is_free() {
        // Once at least initial / 2 streams of credit are free, the limit rises so that open
        // plus openable streams equal the initial limit again.
        let mut table = StreamTable::new(Side::Server, 0, 4);
        let c = |index| id(Side::Client, Dir::Uni, index);
        peer_opens(&mut table, 0..4);
        assert_eq!(table.max_streams(Dir::Uni), 4);
        table.reap(c(0)).unwrap();
        assert_eq!(
            table.max_streams(Dir::Uni),
            4,
            "one free stream is below the window"
        );
        table.reap(c(1)).unwrap();
        assert_eq!(table.max_streams(Dir::Uni), 6);
        table.on_max_streams_sent(Dir::Uni, 6);
        peer_opens(&mut table, 4..6);
        for index in 2..6 {
            table.reap(c(index)).unwrap();
        }
        assert_eq!(table.max_streams(Dir::Uni), 10);
        assert_eq!(table.max_streams(Dir::Bi), 0);
    }

    #[test]
    fn a_raised_limit_binds_the_peer_only_once_it_is_sent() {
        // A stream ID beyond the limit we have sent is a STREAM_LIMIT_ERROR (RFC 9000), even
        // when reaping has already earned the peer more credit.
        let mut table = StreamTable::new(Side::Server, 0, 4);
        let c = |index| id(Side::Client, Dir::Uni, index);
        peer_opens(&mut table, 0..4);
        // Reporting a limit that was never earned does not change what the peer may open.
        table.on_max_streams_sent(Dir::Uni, 100);
        table.reap(c(0)).unwrap();
        table.reap(c(1)).unwrap();
        assert_eq!(table.max_streams(Dir::Uni), 6);
        assert_eq!(
            table.peer_frame(c(4), Half::Recv, |_| ()),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
        table.on_max_streams_sent(Dir::Uni, 6);
        peer_opens(&mut table, 4..6);
        assert_eq!(
            table.peer_frame(c(6), Half::Recv, |_| ()),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
    }

    #[test]
    fn implicitly_opened_streams_hold_credit_until_reaped() {
        let mut table = StreamTable::new(Side::Server, 0, 4);
        let c = |index| id(Side::Client, Dir::Uni, index);
        peer_opens(&mut table, 3..4);
        table.reap(c(3)).unwrap();
        // Streams 0 to 2 are open, implicitly: one stream of credit is free.
        assert_eq!(table.max_streams(Dir::Uni), 4);
        peer_opens(&mut table, 0..1);
        table.reap(c(0)).unwrap();
        assert_eq!(table.max_streams(Dir::Uni), 6);
    }

    #[test]
    fn shutdown_freezes_max_streams_and_refuses_local_opens() {
        let mut table = StreamTable::new(Side::Server, 0, 4);
        table.on_peer_max_streams(Dir::Bi, 5).unwrap();
        peer_opens(&mut table, 0..4);
        table.shutdown();
        assert_eq!(
            table.open_local(Dir::Bi, |_| ()).map(|(id, _)| id),
            Err(OpenError::Closed)
        );
        for index in 0..4 {
            table.reap(id(Side::Client, Dir::Uni, index)).unwrap();
        }
        assert_eq!(table.max_streams(Dir::Uni), 4);
        assert_eq!(
            table.peer_frame(id(Side::Client, Dir::Uni, 4), Half::Recv, |_| ()),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
    }

    #[test]
    fn streams_blocked_names_the_limit_that_stops_the_next_local_open() {
        let mut table = StreamTable::<()>::new(Side::Client, 0, 0);
        assert_eq!(table.streams_blocked(Dir::Bi), Some(0));
        table.on_peer_max_streams(Dir::Bi, 1).unwrap();
        assert_eq!(table.streams_blocked(Dir::Bi), None);
        table.open_local(Dir::Bi, |_| ()).unwrap();
        assert_eq!(table.streams_blocked(Dir::Bi), Some(1));
        assert_eq!(table.streams_blocked(Dir::Uni), Some(0));
    }

    #[test]
    fn interval_set_trims_and_splits_ranges() {
        let mut set = IntervalSet::default();
        set.push_above(0..0);
        assert!(set.ranges.is_empty());
        set.push_above(2..5);
        set.push_above(5..7);
        set.push_above(9..10);
        assert_eq!(set.ranges, [2..7, 9..10]);
        assert!(!set.remove(1) && !set.remove(7) && !set.remove(8));
        assert!(set.remove(2));
        assert!(set.remove(6));
        assert!(set.remove(4));
        assert!(set.remove(9));
        assert_eq!(set.ranges, [3..4, 5..6]);
        assert!(set.contains(3) && set.contains(5));
        assert!(!set.contains(4) && !set.contains(6) && !set.contains(9));
    }

    #[test]
    fn values_are_found_by_slot_and_iterated_in_slot_order() {
        let mut map = StreamMap::new();
        let k0 = map.insert(cb(4), 'a').unwrap();
        let k1 = map.insert(su(2), 'b').unwrap();
        let k2 = map.insert(cb(9), 'c').unwrap();
        map.remove(su(2));
        assert_eq!(map.get_slot(k0.slot()), Some((k0, cb(4), &'a')));
        assert_eq!(map.get_slot(k1.slot()), None);
        assert_eq!(map.get_slot(99), None);
        if let Some((key, id, value)) = map.get_slot_mut(k2.slot()) {
            assert_eq!((key, id), (k2, cb(9)));
            *value = 'C';
        }
        let all: Vec<_> = map
            .iter()
            .map(|(key, id, value)| (key, id, *value))
            .collect();
        assert_eq!(all, [(k0, cb(4), 'a'), (k2, cb(9), 'C')]);
    }
}
