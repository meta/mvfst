/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The per-stream receive buffer (RFC 9000).
//!
//! A [`RecvBuffer`] reassembles one stream's STREAM data, or one encryption level's CRYPTO data.
//! Payloads are copied into the stream's own 16 KiB pages, each covering a fixed, page-aligned span
//! of stream offsets, so every byte is written at its offset's place in whatever order it arrives.
//! In-order bytes are readable as slices of those pages in a `roxygen_bufqueue::BufQueue` until
//! consumed; out-of-order bytes are held in at most [`MAX_RANGES`] disjoint ranges, each byte once
//! whatever the duplicates and overlaps. Pages are never shared between streams, so unread bytes
//! keep only their own stream's pages alive. A page goes back to a [`PagePool`] once consumed, or
//! once the buffer is empty and every slice of it has been dropped. Final sizes are checked as
//! RFC 9000 requires; flow control is counted separately by
//! [`StreamRecvFlow`](crate::flow_control::StreamRecvFlow).

use std::collections::VecDeque;
use std::ops::Range;

use bytes::BytesMut;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;
use roxygen_bufqueue::BufQueue;

use crate::streams::send_buf::RangeSet;

/// The most out-of-order ranges one stream may hold.
pub const MAX_RANGES: usize = 1024;

/// The size of a receive page.
pub const PAGE_SIZE: usize = 16 * 1024;

const PAGE: u64 = PAGE_SIZE as u64;

/// The most free pages a [`PagePool::new`] pool keeps.
const POOL_PAGES: usize = 4;

/// The room for ranges that a buffer keeps once they empty: a container's first allocation, so a
/// stream that fills and drains every read cycle does not allocate again.
const KEPT_SLOTS: usize = 4;

/// The most segments that an emptied readable queue may have held and still keep its container.
/// Each in-order frame takes a slot, so the cap keeps 1-byte frames from pinning more than 32 KiB.
const KEPT_SEGMENTS: usize = 1024;

/// Free receive pages. Receive buffers give pages back as they release them and take pages
/// from here before allocating; a page is pooled only after every slice of it has been dropped.
/// One pool serves a connection or a worker.
#[derive(Debug)]
pub struct PagePool {
    free: Vec<BytesMut>,
    max_free: usize,
    allocated: u64,
}

impl Default for PagePool {
    fn default() -> Self {
        Self::new()
    }
}

impl PagePool {
    /// Creates an empty pool that keeps up to four free pages.
    pub fn new() -> Self {
        Self::with_max_free(POOL_PAGES)
    }

    /// Creates an empty pool that keeps up to `pages` free pages. Streams that empty every read
    /// cycle give their pages back each cycle, so a pool with room for as many streams as are
    /// read in one cycle lets them take the pages again without allocating.
    pub fn with_max_free(pages: usize) -> Self {
        Self {
            free: Vec::new(),
            max_free: pages,
            allocated: 0,
        }
    }

    /// Returns the number of pages allocated so far, rather than reused.
    pub fn pages_allocated(&self) -> u64 {
        self.allocated
    }

    /// Returns the memory held in free pages, in bytes.
    pub fn memory(&self) -> usize {
        self.free.len() * PAGE_SIZE
    }

    fn take(&mut self) -> BytesMut {
        self.free.pop().unwrap_or_else(|| {
            self.allocated += 1;
            BytesMut::with_capacity(PAGE_SIZE)
        })
    }

    /// Takes back a page. It is kept only if the pool has room and `try_reclaim` succeeds, which
    /// it does only after every slice of the page has been dropped.
    fn put(&mut self, mut page: BytesMut) {
        page.clear();
        if self.free.len() < self.max_free && page.try_reclaim(PAGE_SIZE) {
            self.free.push(page);
        }
    }
}

/// What one [`RecvBuffer::insert`] changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inserted {
    /// Bytes that became readable (in order).
    pub readable: usize,
    /// Whether this call completed the stream: every byte up to the final size has arrived
    /// (the Data Recvd state of RFC 9000).
    pub complete: bool,
}

/// One stream's (or one encryption level's CRYPTO) received bytes: the in-order bytes not yet
/// consumed, and out-of-order bytes waiting for the gaps before them.
#[derive(Debug)]
pub struct RecvBuffer {
    readable: BufQueue,
    /// The stream offset of the first readable byte.
    read_offset: u64,
    /// The out-of-order ranges held past the readable bytes.
    pending: RangeSet,
    /// The bytes in `pending`.
    pending_bytes: usize,
    /// The pages written and not yet released, in offset order. A page is released once every
    /// offset it covers is consumed, once the buffer is empty and every slice of the page has
    /// been dropped, or once the stream has been read to its final size.
    pages: VecDeque<Page>,
    final_size: Option<u64>,
    /// The offset after the highest byte received.
    highest: u64,
    /// Whether a reset or `stop` has discarded the stream: ingress is checked, then dropped.
    discarding: bool,
    /// Whether `stop`, not a reset, discarded the stream: dropped ingress still records which
    /// offsets arrived in `pending`, to report when every byte up to the final size has arrived.
    tracking: bool,
    /// Whether the readable queue has held more than [`KEPT_SEGMENTS`] segments since it was last
    /// replaced.
    oversized: bool,
    /// The inserts that wrote and published in-order bytes without touching `pending`.
    #[cfg(test)]
    direct_inserts: usize,
}

/// One page of a stream: it covers offsets `index * PAGE_SIZE..(index + 1) * PAGE_SIZE`.
#[derive(Debug)]
struct Page {
    index: u64,
    /// The page's bytes from the larger of its first offset and the readable end; the bytes
    /// before have been handed to the readable queue. Gaps not yet received hold zeros.
    buf: BytesMut,
}

impl Default for RecvBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvBuffer {
    /// Creates an empty buffer at offset 0.
    pub fn new() -> Self {
        Self {
            readable: BufQueue::new(usize::MAX),
            read_offset: 0,
            pending: RangeSet::default(),
            pending_bytes: 0,
            pages: VecDeque::new(),
            final_size: None,
            highest: 0,
            discarding: false,
            tracking: false,
            oversized: false,
            #[cfg(test)]
            direct_inserts: 0,
        }
    }

    /// Takes the data of a STREAM or CRYPTO frame at `offset` (with the FIN if `fin`; CRYPTO
    /// frames never carry one). Bytes already held or consumed are dropped and the rest copied.
    /// On error the buffer is unchanged and the connection closes with [`RecvError::code`].
    pub fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
        pool: &mut PagePool,
    ) -> Result<Inserted, RecvError> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= VarInt::MAX.into_inner())
            .ok_or(RecvError::OffsetOverflow)?;
        if self
            .final_size
            .is_some_and(|size| end > size || (fin && end != size))
        {
            return Err(RecvError::FinalSize);
        }
        if fin && end < self.highest {
            return Err(RecvError::FinalSize);
        }
        let readable_end = self.readable_end();
        let at = offset.max(readable_end);
        // A frame that neither continues the readable bytes nor touches a held range adds one;
        // `at > readable_end` keeps `at - 1` from underflowing.
        if (!self.discarding || self.tracking)
            && at < end
            && at > readable_end
            && self.pending.len() == MAX_RANGES
            && self.pending.overlapping(at - 1..end + 1).next().is_none()
        {
            return Err(RecvError::TooManyRanges);
        }
        let was_complete = self.is_complete();
        if fin {
            self.final_size = Some(end);
        }
        self.highest = self.highest.max(end);
        if self.discarding {
            if self.tracking && at < end {
                self.pending.insert(at..end);
                if let Some(first) = self.pending.first().filter(|r| r.start == readable_end) {
                    self.pending.pop_first();
                    self.read_offset = first.end;
                }
                self.release_pages(pool);
            }
            return Ok(Inserted {
                readable: 0,
                complete: !was_complete && self.is_complete(),
            });
        }
        if at == readable_end && at < end && self.pending.is_empty() {
            // After the publish the buffer holds unread bytes, its pages lie at or above the read
            // offset and its empty ranges keep at most `KEPT_SLOTS` of room, so `release_pages`
            // would not change anything.
            let new = &data[(at - offset) as usize..];
            Self::write(&mut self.pages, at, new, readable_end, pool);
            self.publish(end);
            #[cfg(test)]
            {
                self.direct_inserts += 1;
            }
            return Ok(Inserted {
                readable: new.len(),
                complete: !was_complete && self.is_complete(),
            });
        }
        if at < end {
            // Copy each gap of `at..end` between the held ranges.
            let pages = &mut self.pages;
            let mut copy = |gap: Range<u64>| {
                let bytes = &data[(gap.start - offset) as usize..(gap.end - offset) as usize];
                Self::write(pages, gap.start, bytes, readable_end, pool);
                bytes.len()
            };
            let mut from = at;
            let mut stored = 0;
            for held in self.pending.overlapping(at..end) {
                if held.start > from {
                    stored += copy(from..held.start);
                }
                from = from.max(held.end);
            }
            if from < end {
                stored += copy(from..end);
            }
            self.pending_bytes += stored;
            self.pending.insert(at..end);
        }
        if let Some(first) = self.pending.first().filter(|r| r.start == readable_end) {
            self.pending.pop_first();
            self.pending_bytes -= (first.end - first.start) as usize;
            self.publish(first.end);
        }
        self.release_pages(pool);
        Ok(Inserted {
            readable: (self.readable_end() - readable_end) as usize,
            complete: !was_complete && self.is_complete(),
        })
    }

    /// Takes the final size of a RESET_STREAM and drops every held byte and all later ingress.
    /// Retransmitted RESET_STREAM frames are fine.
    pub fn on_reset(&mut self, final_size: u64, pool: &mut PagePool) -> Result<(), RecvError> {
        if final_size < self.highest || self.final_size.is_some_and(|size| size != final_size) {
            return Err(RecvError::FinalSize);
        }
        self.final_size = Some(final_size);
        self.discard(pool);
        Ok(())
    }

    /// Stops reading (STOP_SENDING): drops the held bytes and all later ingress, still checking
    /// final sizes and recording which offsets arrived, so [`insert`](Self::insert) still reports
    /// when every byte up to the final size has arrived.
    pub fn stop(&mut self, pool: &mut PagePool) {
        let held = std::mem::take(&mut self.pending);
        self.discard(pool);
        self.pending = held;
        self.tracking = true;
    }

    /// Returns the in-order bytes not yet consumed.
    pub fn readable(&self) -> &BufQueue {
        &self.readable
    }

    /// Consumes the first `n` readable bytes; pages wholly consumed go back to `pool`.
    pub fn consume(&mut self, n: usize, pool: &mut PagePool) -> Result<(), BeyondReadable> {
        self.readable.trim_start(n).map_err(|_| BeyondReadable)?;
        self.read_offset += n as u64;
        self.release_pages(pool);
        Ok(())
    }

    /// Returns the stream offset of the first byte not yet consumed (or discarded).
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Returns the offset after the highest byte received.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Returns the final size, once a FIN or RESET_STREAM gave it.
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// Returns whether every byte up to the final size has arrived (Data Recvd), also after `stop`.
    pub fn is_complete(&self) -> bool {
        (!self.discarding || self.tracking) && self.final_size == Some(self.readable_end())
    }

    /// Returns whether every byte up to the final size has been consumed (Data Read).
    pub fn is_finished(&self) -> bool {
        !self.discarding && self.final_size == Some(self.read_offset)
    }

    /// Returns the buffer's offsets, without its bytes, for the empty-attempt digest.
    #[cfg(debug_assertions)]
    pub(crate) fn digest(&self) -> impl std::fmt::Debug + '_ {
        (
            self.read_offset,
            self.highest,
            self.final_size,
            &self.pending,
            self.readable.chain_length(),
            self.discarding,
            self.tracking,
        )
    }

    /// Returns the number of disjoint out-of-order ranges held.
    pub fn ranges(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of bytes held, readable and out of order.
    pub fn buffered(&self) -> usize {
        self.readable.chain_length() + self.pending_bytes
    }

    /// Returns the offset after the last readable byte.
    fn readable_end(&self) -> u64 {
        self.read_offset + self.readable.chain_length() as u64
    }

    /// Copies `data`, bytes not held yet, to their place at `offset` in `pages`, taking pages
    /// from `pool` as needed.
    fn write(
        pages: &mut VecDeque<Page>,
        mut offset: u64,
        mut data: &[u8],
        readable_end: u64,
        pool: &mut PagePool,
    ) {
        while !data.is_empty() {
            let index = offset / PAGE;
            let n = data.len().min(((index + 1) * PAGE - offset) as usize);
            let i = match pages.binary_search_by_key(&index, |page| page.index) {
                Ok(i) => i,
                Err(i) => {
                    let buf = pool.take();
                    pages.insert(i, Page { index, buf });
                    i
                }
            };
            let buf = &mut pages[i].buf;
            let at = (offset - readable_end.max(index * PAGE)) as usize;
            debug_assert!(at + n <= buf.capacity(), "a page has room for its offsets");
            if buf.len() < at {
                buf.resize(at, 0);
            }
            let overlap = (buf.len() - at).min(n);
            buf[at..at + overlap].copy_from_slice(&data[..overlap]);
            buf.extend_from_slice(&data[overlap..n]);
            offset += n as u64;
            data = &data[n..];
        }
    }

    /// Hands the bytes from the readable end up to `end`, all held, to the readable queue.
    fn publish(&mut self, end: u64) {
        let mut at = self.readable_end();
        let mut i = self.pages.partition_point(|page| page.index < at / PAGE);
        while at < end {
            let page = &mut self.pages[i];
            debug_assert_eq!(page.index, at / PAGE, "held bytes have their page");
            let n = (end.min((page.index + 1) * PAGE) - at) as usize;
            self.readable
                .push_bytes(page.buf.split_to(n).freeze())
                .expect("the readable queue has no limit");
            at += n as u64;
            i += 1;
        }
        self.oversized |= self.readable.segment_count() > KEPT_SEGMENTS;
    }

    /// Gives back to `pool` the pages whose offsets are all consumed, and every page once the
    /// stream has been read to its final size. An empty buffer gives back its last page too,
    /// unless the application still holds a slice of it: the stream's next bytes then fill the
    /// rest of that page instead of pinning another. The page list keeps its room for the next
    /// read cycle until the stream has been read to its end, and so does the readable queue unless
    /// it empties after holding more than [`KEPT_SEGMENTS`] segments. Empty ranges give up their
    /// room at the end of the stream, or once it grew past [`KEPT_SLOTS`].
    fn release_pages(&mut self, pool: &mut PagePool) {
        let all = self.is_finished();
        let empty = self.readable.is_empty() && self.pending.is_empty();
        let read_offset = self.read_offset;
        // `try_reclaim` succeeds only once every slice of the page has been dropped.
        while let Some(page) = self.pages.pop_front_if(|page| {
            all || (page.index + 1) * PAGE <= read_offset
                || (empty && page.buf.try_reclaim(PAGE_SIZE))
        }) {
            pool.put(page.buf);
        }
        if all {
            self.pages = VecDeque::new();
        }
        if all || (self.oversized && self.readable.is_empty()) {
            self.readable = BufQueue::new(usize::MAX);
            self.oversized = false;
        }
        if self.pending.is_empty() && (all || self.pending.capacity() > KEPT_SLOTS) {
            self.pending = RangeSet::default();
        }
    }

    /// Drops every held byte and all later ingress.
    fn discard(&mut self, pool: &mut PagePool) {
        self.read_offset += self.readable.chain_length() as u64;
        self.readable = BufQueue::new(usize::MAX);
        self.oversized = false;
        self.pending = RangeSet::default();
        self.pending_bytes = 0;
        for page in std::mem::take(&mut self.pages) {
            pool.put(page.buf);
        }
        self.discarding = true;
        self.tracking = false;
    }
}

/// A peer error found by [`RecvBuffer`]; the connection closes with [`code`](Self::code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// The frame would leave more than [`MAX_RANGES`] out-of-order ranges.
    TooManyRanges,
    /// The frame contradicts the stream's final size (RFC 9000).
    FinalSize,
    /// The frame's data would end past offset 2^62 - 1 (RFC 9000).
    OffsetOverflow,
}

impl RecvError {
    /// Returns the transport error code that closes the connection. For CRYPTO data the caller
    /// may prefer CRYPTO_BUFFER_EXCEEDED for [`TooManyRanges`](Self::TooManyRanges).
    pub fn code(self) -> TransportErrorCode {
        match self {
            Self::TooManyRanges => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::FinalSize => TransportErrorCode::FINAL_SIZE_ERROR,
            Self::OffsetOverflow => TransportErrorCode::FRAME_ENCODING_ERROR,
        }
    }
}

/// The error of a [`RecvBuffer::consume`] call past the readable bytes; the buffer is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeyondReadable;

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    /// Returns the readable bytes, flattened.
    fn readable(buf: &RecvBuffer) -> Vec<u8> {
        buf.readable().segments().flat_map(|s| s.to_vec()).collect()
    }

    /// Returns the memory the buffer's range and page containers take.
    fn containers(buf: &RecvBuffer) -> usize {
        buf.pending.capacity() * size_of::<Range<u64>>() + buf.pages.capacity() * size_of::<Page>()
    }

    #[test]
    fn in_order_bytes_become_readable_and_consume_advances() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        let got = buf.insert(0, b"hello", false, &mut pool).unwrap();
        assert_eq!(got.readable, 5);
        assert_eq!(readable(&buf), b"hello");
        buf.consume(3, &mut pool).unwrap();
        assert_eq!(readable(&buf), b"lo");
        assert_eq!(buf.read_offset(), 3);
        buf.insert(5, b" world", false, &mut pool).unwrap();
        assert_eq!(readable(&buf), b"lo world");
    }

    #[test]
    fn out_of_order_bytes_wait_for_the_gap_before_them() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        let got = buf.insert(5, b" world", false, &mut pool).unwrap();
        assert_eq!(got.readable, 0);
        assert!(buf.readable().is_empty());
        let got = buf.insert(11, b"!", false, &mut pool).unwrap();
        assert_eq!(got.readable, 0);
        let got = buf.insert(0, b"hello", false, &mut pool).unwrap();
        assert_eq!(got.readable, 12);
        assert_eq!(readable(&buf), b"hello world!");
    }

    #[test]
    fn duplicates_and_overlaps_keep_each_byte_once() {
        let data = b"0123456789abcdefghij";
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(10, &data[10..15], false, &mut pool).unwrap();
        // Overlaps the held segment on both sides.
        buf.insert(8, &data[8..20], false, &mut pool).unwrap();
        // An exact duplicate of held bytes.
        buf.insert(10, &data[10..15], false, &mut pool).unwrap();
        assert_eq!(
            buf.insert(0, &data[0..5], false, &mut pool)
                .unwrap()
                .readable,
            5
        );
        // Overlaps the readable bytes and fills the last gap.
        let got = buf.insert(3, &data[3..9], false, &mut pool).unwrap();
        assert_eq!(got.readable, 15);
        assert_eq!(readable(&buf), data);
        buf.consume(20, &mut pool).unwrap();
        // Everything below the read offset is a duplicate.
        let got = buf.insert(0, &data[..], false, &mut pool).unwrap();
        assert_eq!(got.readable, 0);
        assert!(buf.readable().is_empty());
        buf.insert(15, b"fghij", false, &mut pool).unwrap();
        assert_eq!(
            readable(&buf),
            b"",
            "data below the read offset is not re-read"
        );
    }

    #[test]
    fn more_than_1024_out_of_order_ranges_is_a_peer_error() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        // Ranges at 2, 4, 6, ...: each one byte with a gap before it.
        for k in 1..=MAX_RANGES as u64 {
            buf.insert(2 * k, b"x", false, &mut pool).unwrap();
        }
        assert_eq!(buf.ranges(), MAX_RANGES);
        let held = buf.buffered();
        let past = 2 * (MAX_RANGES as u64 + 1);
        assert_eq!(
            buf.insert(past, b"x", false, &mut pool),
            Err(RecvError::TooManyRanges)
        );
        assert_eq!(buf.ranges(), MAX_RANGES);
        assert_eq!(buf.buffered(), held, "a refused frame stores nothing");
        // Extending a range or joining two does not add one.
        buf.insert(past - 1, b"x", false, &mut pool).unwrap();
        buf.insert(5, b"x", false, &mut pool).unwrap();
        assert_eq!(buf.ranges(), MAX_RANGES - 1);
        // Spanning several ranges merges them into one.
        buf.insert(7, &[b'x'; 10], false, &mut pool).unwrap();
        assert_eq!(buf.ranges(), MAX_RANGES - 6);
        // Filling the first gap makes the first range (the byte at 2) readable.
        let got = buf.insert(0, b"xx", false, &mut pool).unwrap();
        assert_eq!(got.readable, 3);
        assert_eq!(buf.ranges(), MAX_RANGES - 7);
        buf.insert(past + 2, b"x", false, &mut pool).unwrap();
        assert_eq!(buf.ranges(), MAX_RANGES - 6);
    }

    #[test]
    fn data_at_or_beyond_the_final_size_is_a_final_size_error() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", true, &mut pool).unwrap();
        assert_eq!(buf.final_size(), Some(3));
        assert_eq!(
            buf.insert(3, b"d", false, &mut pool),
            Err(RecvError::FinalSize)
        );
        assert_eq!(
            buf.insert(2, b"cd", false, &mut pool),
            Err(RecvError::FinalSize)
        );
        // Retransmitted bytes inside the final size are fine.
        buf.insert(1, b"bc", false, &mut pool).unwrap();
        assert_eq!(readable(&buf), b"abc");
    }

    #[test]
    fn a_fin_that_moves_the_final_size_is_a_final_size_error() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", true, &mut pool).unwrap();
        assert_eq!(
            buf.insert(0, b"ab", true, &mut pool),
            Err(RecvError::FinalSize)
        );
        assert_eq!(buf.final_size(), Some(3));
        // The same FIN again is a retransmission.
        buf.insert(2, b"c", true, &mut pool).unwrap();
        buf.insert(3, b"", true, &mut pool).unwrap();
        assert_eq!(buf.final_size(), Some(3));
    }

    #[test]
    fn a_fin_below_received_data_is_a_final_size_error() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(10, b"x", false, &mut pool).unwrap();
        assert_eq!(buf.highest(), 11);
        assert_eq!(
            buf.insert(0, b"abc", true, &mut pool),
            Err(RecvError::FinalSize)
        );
        assert_eq!(buf.final_size(), None);
        buf.insert(5, b"fghijk", true, &mut pool).unwrap();
        assert_eq!(buf.final_size(), Some(11));
    }

    #[test]
    fn a_reset_must_agree_with_the_final_size() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(10, b"x", false, &mut pool).unwrap();
        assert_eq!(buf.on_reset(10, &mut pool), Err(RecvError::FinalSize));
        assert_eq!(buf.final_size(), None);

        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", true, &mut pool).unwrap();
        assert_eq!(buf.on_reset(4, &mut pool), Err(RecvError::FinalSize));
        assert_eq!(buf.on_reset(2, &mut pool), Err(RecvError::FinalSize));
        assert!(buf.on_reset(3, &mut pool).is_ok());
        assert!(
            buf.on_reset(3, &mut pool).is_ok(),
            "a retransmitted RESET_STREAM"
        );
        assert_eq!(buf.on_reset(5, &mut pool), Err(RecvError::FinalSize));
    }

    #[test]
    fn a_reset_discards_held_bytes_and_later_data() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        buf.insert(5, b"fg", false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 5);
        assert_eq!(buf.on_reset(10, &mut pool), Ok(()));
        assert_eq!(buf.buffered(), 0);
        assert!(buf.readable().is_empty());
        assert_eq!(buf.ranges(), 0);
        let got = buf.insert(3, b"de", false, &mut pool).unwrap();
        assert_eq!(got, Inserted::default());
        assert_eq!(buf.buffered(), 0);
        assert_eq!(
            buf.insert(9, b"jk", false, &mut pool),
            Err(RecvError::FinalSize),
            "the final size still binds"
        );
    }

    #[test]
    fn stop_drops_held_bytes_and_further_ingress() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        buf.insert(5, b"f", false, &mut pool).unwrap();
        buf.consume(1, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 3);
        buf.stop(&mut pool);
        assert_eq!(buf.buffered(), 0);
        assert!(buf.readable().is_empty());
        assert_eq!(
            buf.insert(3, b"def", true, &mut pool),
            Ok(Inserted {
                readable: 0,
                complete: true
            }),
            "nothing is kept, but the buffer knows every byte has arrived"
        );
        assert!(buf.readable().is_empty());
        assert_eq!(
            buf.final_size(),
            Some(6),
            "the FIN is still checked and kept"
        );
        assert_eq!(buf.buffered(), 0);
        assert_eq!(buf.on_reset(7, &mut pool), Err(RecvError::FinalSize));
        assert_eq!(buf.on_reset(6, &mut pool), Ok(()));
    }

    #[test]
    fn data_past_the_largest_stream_offset_is_a_frame_encoding_error() {
        let max = VarInt::MAX.into_inner();
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        assert_eq!(
            buf.insert(max - 1, b"ab", false, &mut pool),
            Err(RecvError::OffsetOverflow)
        );
        assert_eq!(buf.highest(), 0);
        buf.insert(max - 2, b"ab", false, &mut pool).unwrap();
        assert_eq!(buf.highest(), max);
    }

    #[test]
    fn receive_errors_map_to_their_transport_error_codes() {
        assert_eq!(
            RecvError::FinalSize.code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
        assert_eq!(
            RecvError::OffsetOverflow.code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        assert_eq!(
            RecvError::TooManyRanges.code(),
            TransportErrorCode::PROTOCOL_VIOLATION
        );
    }

    #[test]
    fn insert_reports_once_when_every_byte_up_to_the_fin_has_arrived() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        assert!(!buf.insert(3, b"def", true, &mut pool).unwrap().complete);
        assert!(buf.insert(0, b"abc", false, &mut pool).unwrap().complete);
        assert!(!buf.insert(0, b"abc", false, &mut pool).unwrap().complete);
        assert!(buf.is_complete());
        assert!(!buf.is_finished(), "received but not yet read");
        buf.consume(6, &mut pool).unwrap();
        assert!(buf.is_finished());

        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        assert!(buf.insert(3, b"", true, &mut pool).unwrap().complete);

        let mut buf = RecvBuffer::new();
        assert!(buf.insert(0, b"", true, &mut pool).unwrap().complete);
        assert!(buf.is_finished());
    }

    #[test]
    fn a_streams_bytes_fill_its_pages_which_are_reused_once_consumed() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, &[1u8; 100], false, &mut pool).unwrap();
        buf.insert(100, &[2u8; 200], false, &mut pool).unwrap();
        let segs: Vec<&Bytes> = buf.readable().segments().collect();
        assert_eq!(
            segs[0].as_ptr() as usize + segs[0].len(),
            segs[1].as_ptr() as usize,
            "the second payload follows the first in the same page"
        );
        assert_eq!(pool.pages_allocated(), 1);
        // A frame across a page boundary is split between the two pages.
        buf.insert(300, &[3u8; PAGE_SIZE], false, &mut pool)
            .unwrap();
        assert_eq!(pool.pages_allocated(), 2);
        assert_eq!(buf.readable().segment_count(), 4);
        // Once every offset of the first page is consumed, the page goes back to the pool and
        // is reused.
        buf.consume(PAGE_SIZE, &mut pool).unwrap();
        assert_eq!(pool.memory(), PAGE_SIZE);
        buf.insert(PAGE_SIZE as u64 + 300, &[4u8; PAGE_SIZE], false, &mut pool)
            .unwrap();
        assert_eq!(pool.pages_allocated(), 2);
        assert_eq!(pool.memory(), 0);
        let mut expected = vec![3u8; PAGE_SIZE];
        expected.extend_from_slice(&[4u8; PAGE_SIZE]);
        assert_eq!(readable(&buf), &expected[PAGE_SIZE - 300..]);
    }

    #[test]
    fn a_page_the_application_still_holds_is_not_reused() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, &[1u8; PAGE_SIZE], false, &mut pool).unwrap();
        let kept = buf.readable().front().unwrap().clone();
        buf.consume(PAGE_SIZE, &mut pool).unwrap();
        assert!(buf.pages.is_empty(), "the consumed page leaves the buffer");
        assert_eq!(
            pool.memory(),
            0,
            "the page is not pooled while a slice of it lives"
        );
        buf.insert(PAGE_SIZE as u64, &[2u8; PAGE_SIZE], false, &mut pool)
            .unwrap();
        assert_eq!(pool.pages_allocated(), 2);
        assert!(kept.iter().all(|&b| b == 1));
    }

    #[test]
    fn buffered_counts_each_held_byte_once() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(10, &[0u8; 10], false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 10);
        buf.insert(5, &[0u8; 20], false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 20);
        buf.insert(0, &[0u8; 30], false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 30);
        buf.insert(0, &[0u8; 30], false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 30);
        buf.consume(12, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 18);
        buf.insert(40, &[0u8; 5], false, &mut pool).unwrap();
        assert_eq!(buf.buffered(), 23);
        buf.stop(&mut pool);
        assert_eq!(buf.buffered(), 0);
    }

    #[test]
    fn consuming_more_than_is_readable_fails_and_consumes_nothing() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        buf.insert(5, b"fg", false, &mut pool).unwrap();
        assert_eq!(buf.consume(4, &mut pool), Err(BeyondReadable));
        assert_eq!(readable(&buf), b"abc");
        assert_eq!(buf.read_offset(), 0);
        buf.consume(3, &mut pool).unwrap();
        buf.consume(0, &mut pool).unwrap();
        assert_eq!(buf.read_offset(), 3);
    }

    #[test]
    fn a_slow_stream_keeps_only_its_own_pages_alive() {
        // The peer interleaves single bytes on `a`, behind a gap it never fills, with a page of
        // data on `b` that the application reads at once.
        let mut pool = PagePool::new();
        let mut a = RecvBuffer::new();
        let mut b = RecvBuffer::new();
        let chunk = vec![7u8; PAGE_SIZE - 1];
        for k in 0..1000u64 {
            a.insert(1 + k, b"x", false, &mut pool).unwrap();
            b.insert(k * chunk.len() as u64, &chunk, false, &mut pool)
                .unwrap();
            b.consume(chunk.len(), &mut pool).unwrap();
        }
        assert_eq!(a.buffered(), 1000);
        assert_eq!(b.buffered(), 0);
        assert!(
            pool.pages_allocated() <= 3,
            "{} pages allocated for 1,000 held bytes",
            pool.pages_allocated()
        );
    }

    #[test]
    fn single_byte_frames_are_held_in_pages_not_one_piece_each() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        let far = 3 * PAGE_SIZE as u64;
        // Two runs of single-byte frames grown in turn, at 1, 2, ... and at far, far + 1, ...
        for k in 0..5000u64 {
            buf.insert(1 + k, b"a", false, &mut pool).unwrap();
            buf.insert(far + k, b"b", false, &mut pool).unwrap();
        }
        assert_eq!(buf.ranges(), 2);
        buf.insert(0, b"a", false, &mut pool).unwrap();
        let fill = vec![b'c'; (far - 5001) as usize];
        buf.insert(5001, &fill, false, &mut pool).unwrap();
        assert_eq!(buf.readable().chain_length(), far as usize + 5000);
        let mut expected = vec![b'a'; 5001];
        expected.extend_from_slice(&fill);
        expected.extend_from_slice(&[b'b'; 5000]);
        assert_eq!(readable(&buf), expected);
        // One segment per page the bytes span, at most.
        assert!(
            buf.readable().segment_count() <= 5,
            "{} segments",
            buf.readable().segment_count()
        );
    }

    #[test]
    fn a_stream_read_to_its_end_holds_no_pages() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", true, &mut pool).unwrap();
        buf.consume(3, &mut pool).unwrap();
        assert!(buf.is_finished());
        assert_eq!((buf.pages.len(), containers(&buf)), (0, 0));
        assert_eq!(pool.memory(), PAGE_SIZE, "the page went back to the pool");

        // The FIN may come after the last byte was read.
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        buf.consume(3, &mut pool).unwrap();
        assert!(buf.pages.is_empty());
        buf.insert(3, b"", true, &mut pool).unwrap();
        assert!(buf.is_finished());
        assert_eq!(containers(&buf), 0);
    }

    #[test]
    fn a_stream_that_holds_no_byte_gives_its_page_back() {
        let mut pool = PagePool::new();
        let mut streams: Vec<RecvBuffer> = (0..100).map(|_| RecvBuffer::new()).collect();
        for buf in &mut streams {
            buf.insert(0, b"x", false, &mut pool).unwrap();
            buf.consume(1, &mut pool).unwrap();
        }
        assert_eq!(
            pool.pages_allocated(),
            1,
            "each stream's page went back for the next one"
        );
        assert!(streams.iter().all(|buf| buf.pages.is_empty()));
    }

    #[test]
    fn a_page_the_application_still_holds_takes_the_streams_next_bytes() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, &[1u8; 100], false, &mut pool).unwrap();
        let kept = buf.readable().front().unwrap().clone();
        buf.consume(100, &mut pool).unwrap();
        assert_eq!(
            buf.pages.len(),
            1,
            "the page stays with the stream while a slice of it lives"
        );
        buf.insert(100, &[2u8; 100], false, &mut pool).unwrap();
        assert_eq!(pool.pages_allocated(), 1);
        let next = buf.readable().front().unwrap();
        assert_eq!(
            kept.as_ptr() as usize + kept.len(),
            next.as_ptr() as usize,
            "the next bytes follow the kept ones in the same page"
        );
    }

    #[test]
    fn a_pool_with_room_for_the_streams_read_each_cycle_allocates_no_more() {
        let mut pool = PagePool::with_max_free(8);
        let mut streams: Vec<RecvBuffer> = (0..8).map(|_| RecvBuffer::new()).collect();
        for cycle in 0..10u64 {
            // A packet for every stream, then the application reads them all.
            for buf in &mut streams {
                buf.insert(cycle * 1000, &[0u8; 1000], false, &mut pool)
                    .unwrap();
            }
            for buf in &mut streams {
                buf.consume(1000, &mut pool).unwrap();
            }
        }
        assert_eq!(pool.pages_allocated(), 8);
        assert_eq!(pool.memory(), 8 * PAGE_SIZE);
    }

    #[test]
    fn a_reset_or_stop_frees_the_room_held_for_ranges_and_pages() {
        let mut pool = PagePool::new();
        let mut reset = RecvBuffer::new();
        let mut stopped = RecvBuffer::new();
        for k in 1..=MAX_RANGES as u64 {
            reset.insert(2 * k, b"x", false, &mut pool).unwrap();
            stopped.insert(2 * k, b"x", false, &mut pool).unwrap();
        }
        reset.on_reset(4096, &mut pool).unwrap();
        stopped.stop(&mut pool);
        assert_eq!((reset.pages.len(), containers(&reset)), (0, 0));
        // A stopped buffer keeps only which offsets arrived, to report when the rest has arrived.
        assert_eq!(stopped.buffered(), 0);
        assert_eq!(stopped.ranges(), MAX_RANGES);
        assert!(stopped.pages.is_empty(), "no pages");
        stopped
            .insert(0, &[0; 2 * MAX_RANGES + 1], true, &mut pool)
            .unwrap();
        assert!(stopped.is_complete());
        assert_eq!((stopped.pages.len(), containers(&stopped)), (0, 0));
    }

    #[test]
    fn room_grown_for_ranges_is_freed_once_they_empty_and_room_for_pages_is_kept() {
        let pages = 64;
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        // The last byte of each of 64 pages, each behind a gap.
        for k in 1..=pages as u64 {
            buf.insert(k * PAGE - 1, b"x", false, &mut pool).unwrap();
        }
        assert_eq!(buf.ranges(), pages);
        assert!(buf.pending.capacity() > KEPT_SLOTS);
        buf.insert(0, &vec![b'x'; pages * PAGE_SIZE], false, &mut pool)
            .unwrap();
        assert_eq!(buf.ranges(), 0);
        buf.consume(pages * PAGE_SIZE, &mut pool).unwrap();
        assert!(buf.pages.is_empty(), "no page is held");
        assert!(
            buf.pending.capacity() <= KEPT_SLOTS,
            "room for {} ranges kept",
            buf.pending.capacity()
        );
        // The stream's next read cycle may hold as many pages again.
        assert!(
            buf.pages.capacity() >= pages,
            "room for {} pages kept",
            buf.pages.capacity()
        );
    }

    #[test]
    fn in_order_frames_are_published_without_touching_the_held_ranges() {
        let data: Vec<u8> = (0..18_000u32).map(|i| (i % 251) as u8).collect();
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        // Frames of 1,200 bytes in order; the fourteenth crosses the first page boundary.
        for (k, frame) in data.chunks(1200).enumerate() {
            let got = buf
                .insert(1200 * k as u64, frame, false, &mut pool)
                .unwrap();
            assert_eq!(
                got,
                Inserted {
                    readable: 1200,
                    complete: false
                }
            );
        }
        assert_eq!(readable(&buf), data);
        assert_eq!(buf.readable().segment_count(), 16);
        assert_eq!(buf.buffered(), data.len());
        assert_eq!(buf.ranges(), 0);
        assert_eq!(pool.pages_allocated(), 2);
        assert_eq!(
            (buf.direct_inserts, buf.pending.capacity()),
            (15, 0),
            "each frame is published past the held ranges, which stay unallocated"
        );
    }

    #[test]
    fn an_in_order_frame_over_consumed_and_unread_bytes_adds_only_its_new_bytes() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"hello", false, &mut pool).unwrap();
        buf.consume(3, &mut pool).unwrap();
        // Bytes 1..3 are consumed and 3..5 unread. Retransmitted bytes are dropped whatever they
        // hold, so the frame's first four bytes do not overwrite anything.
        let got = buf.insert(1, b"XXXX world", false, &mut pool).unwrap();
        assert_eq!(
            got,
            Inserted {
                readable: 6,
                complete: false
            }
        );
        assert_eq!(readable(&buf), b"lo world");
        buf.consume(8, &mut pool).unwrap();
        let got = buf
            .insert(0, b"XXXXXXXXXXX, again", false, &mut pool)
            .unwrap();
        assert_eq!(got.readable, 7);
        assert_eq!(readable(&buf), b", again");
        // A frame wholly below the readable end does not add any bytes.
        let got = buf.insert(4, b"XXXXXXX", false, &mut pool).unwrap();
        assert_eq!(got, Inserted::default());
        assert_eq!(readable(&buf), b", again");
        assert_eq!(
            (buf.read_offset(), buf.highest(), buf.buffered()),
            (11, 18, 7)
        );
        assert_eq!(buf.direct_inserts, 3);
    }

    #[test]
    fn an_in_order_frame_with_the_fin_completes_the_stream() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"abc", false, &mut pool).unwrap();
        let got = buf.insert(3, b"def", true, &mut pool).unwrap();
        assert_eq!(
            got,
            Inserted {
                readable: 3,
                complete: true
            }
        );
        assert_eq!(buf.final_size(), Some(6));
        assert!(buf.is_complete());
        assert_eq!(
            buf.insert(3, b"def", true, &mut pool),
            Ok(Inserted::default()),
            "a retransmitted FIN"
        );
        assert_eq!(
            buf.insert(3, b"defg", true, &mut pool),
            Err(RecvError::FinalSize)
        );
        buf.consume(6, &mut pool).unwrap();
        assert!(buf.is_finished());
        assert_eq!(pool.memory(), PAGE_SIZE, "the page went back to the pool");
        let first = buf.direct_inserts;

        // An empty FIN gives the final size first; the bytes before it then arrive in order.
        let mut buf = RecvBuffer::new();
        buf.insert(0, b"ab", false, &mut pool).unwrap();
        assert_eq!(buf.insert(6, b"", true, &mut pool), Ok(Inserted::default()));
        assert_eq!((buf.ranges(), buf.highest()), (0, 6));
        assert_eq!(
            buf.insert(2, b"cdefg", false, &mut pool),
            Err(RecvError::FinalSize),
            "past the final size"
        );
        assert_eq!(
            buf.insert(2, b"cd", true, &mut pool),
            Err(RecvError::FinalSize),
            "a FIN that moves the final size"
        );
        assert_eq!(
            readable(&buf),
            b"ab",
            "a refused frame does not store any bytes"
        );
        let got = buf.insert(2, b"cd", false, &mut pool).unwrap();
        assert_eq!(
            got,
            Inserted {
                readable: 2,
                complete: false
            }
        );
        let got = buf.insert(4, b"ef", false, &mut pool).unwrap();
        assert_eq!(
            got,
            Inserted {
                readable: 2,
                complete: true
            }
        );
        assert_eq!(readable(&buf), b"abcdef");
        assert_eq!((first, buf.direct_inserts), (2, 3));
    }

    #[test]
    fn in_order_frames_after_a_filled_gap_are_published_directly() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        buf.insert(5, b"fgh", false, &mut pool).unwrap();
        buf.insert(12, b"mno", false, &mut pool).unwrap();
        assert_eq!(
            buf.insert(0, b"abcde", false, &mut pool).unwrap().readable,
            8
        );
        assert_eq!(buf.ranges(), 1);
        // A range is still held, so this frame joins it.
        assert_eq!(
            buf.insert(8, b"ijkl", false, &mut pool).unwrap().readable,
            7
        );
        assert_eq!(buf.ranges(), 0);
        let held = buf.direct_inserts;
        assert_eq!(buf.insert(15, b"pq", false, &mut pool).unwrap().readable, 2);
        assert_eq!(readable(&buf), b"abcdefghijklmnopq");
        assert_eq!(buf.buffered(), 17);
        assert_eq!((held, buf.direct_inserts), (0, 1));
    }

    #[test]
    fn a_stopped_or_reset_buffer_drops_in_order_frames() {
        let mut pool = PagePool::new();
        let mut stopped = RecvBuffer::new();
        stopped.insert(0, b"abc", false, &mut pool).unwrap();
        stopped.stop(&mut pool);
        assert_eq!(
            stopped.insert(3, b"def", false, &mut pool),
            Ok(Inserted::default())
        );
        assert_eq!(
            stopped.insert(6, b"g", true, &mut pool),
            Ok(Inserted {
                readable: 0,
                complete: true
            })
        );
        assert!(stopped.readable().is_empty());
        assert!(stopped.pages.is_empty());
        assert_eq!((stopped.read_offset(), stopped.buffered()), (7, 0));

        let mut reset = RecvBuffer::new();
        reset.insert(0, b"abc", false, &mut pool).unwrap();
        reset.on_reset(10, &mut pool).unwrap();
        assert_eq!(
            reset.insert(3, b"def", false, &mut pool),
            Ok(Inserted::default())
        );
        assert_eq!(
            reset.insert(3, b"defghijk", false, &mut pool),
            Err(RecvError::FinalSize)
        );
        assert!(reset.readable().is_empty());
        assert!(reset.pages.is_empty());
        assert_eq!(reset.buffered(), 0);
        assert_eq!(
            (stopped.direct_inserts, reset.direct_inserts),
            (1, 1),
            "only the frame before the stream was discarded goes directly"
        );
    }

    #[test]
    fn the_readable_queue_keeps_its_container_until_the_buffer_is_discarded() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        // Single-byte frames in order: one readable segment each.
        for k in 0..10u64 {
            buf.insert(k, b"x", false, &mut pool).unwrap();
        }
        assert_eq!(buf.readable().segment_count(), 10);
        buf.consume(10, &mut pool).unwrap();
        let kept = buf.readable().segment_growth_hint();
        assert!(
            kept >= 10,
            "an emptied queue keeps room for its 10 segments: {kept}"
        );
        for k in 10..13u64 {
            buf.insert(k, b"x", false, &mut pool).unwrap();
        }
        buf.stop(&mut pool);
        assert_eq!(buf.readable().segment_growth_hint(), 0, "stop");

        let mut buf = RecvBuffer::new();
        for k in 0..10u64 {
            buf.insert(k, b"x", false, &mut pool).unwrap();
        }
        buf.consume(4, &mut pool).unwrap();
        buf.on_reset(20, &mut pool).unwrap();
        assert_eq!(buf.readable().segment_growth_hint(), 0, "reset");
    }

    #[test]
    fn a_stream_read_to_its_end_gives_up_its_readable_container() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        for k in 0..10u64 {
            buf.insert(k, b"x", k == 9, &mut pool).unwrap();
        }
        buf.consume(10, &mut pool).unwrap();
        assert!(buf.is_finished());
        assert_eq!(buf.readable().segment_growth_hint(), 0, "read with the FIN");

        // The FIN may come after the last byte was read.
        let mut buf = RecvBuffer::new();
        for k in 0..10u64 {
            buf.insert(k, b"x", false, &mut pool).unwrap();
        }
        buf.consume(10, &mut pool).unwrap();
        assert!(buf.readable().segment_growth_hint() >= 10);
        buf.insert(10, b"", true, &mut pool).unwrap();
        assert!(buf.is_finished());
        assert_eq!(
            buf.readable().segment_growth_hint(),
            0,
            "a FIN after the read"
        );
    }

    #[test]
    fn an_emptied_readable_queue_gives_up_a_container_grown_past_1024_segments() {
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        // A read cycle of `frames` single-byte frames in order, one readable segment each, read to
        // empty. It returns the room that the emptied queue keeps, which the hint caps at 64.
        let mut cycle = |buf: &mut RecvBuffer, frames: u64| {
            let from = buf.read_offset();
            for k in from..from + frames {
                buf.insert(k, b"x", false, &mut pool).unwrap();
            }
            assert_eq!(buf.readable().segment_count(), frames as usize);
            buf.consume(frames as usize, &mut pool).unwrap();
            buf.readable().segment_growth_hint()
        };
        assert_eq!(cycle(&mut buf, 1024), 64, "1,024 segments");
        assert_eq!(cycle(&mut buf, 1025), 0, "1,025 segments");
        assert!(cycle(&mut buf, 10) >= 10, "a new queue keeps its room");
        // A peer that fills a 64 KiB stream window with 1-byte frames.
        assert_eq!(cycle(&mut buf, 65_536), 0, "65,536 segments");
    }

    #[test]
    fn seeded_random_overlapping_frames_reassemble_exactly() {
        let data: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        let mut have = vec![false; data.len()];
        while have.iter().any(|h| !h) {
            let start = next(data.len());
            let end = (start + 1 + next(200)).min(data.len());
            buf.insert(start as u64, &data[start..end], false, &mut pool)
                .unwrap();
            have[start..end].iter_mut().for_each(|h| *h = true);
            // The reference: the prefix received is readable, the runs after it are ranges.
            let prefix = have.iter().position(|h| !h).unwrap_or(have.len());
            let runs = (prefix..have.len())
                .filter(|&i| have[i] && !have[i - 1])
                .count();
            assert_eq!(readable(&buf), data[..prefix]);
            assert_eq!(buf.ranges(), runs);
            assert_eq!(buf.buffered(), have.iter().filter(|h| **h).count());
        }
        assert_eq!(readable(&buf), data);
    }

    /// Feeds a buffer random frames and random reads, a quarter of them whole. Frames start
    /// anywhere in the data or, with `near`, are at most `near` bytes long and start from `near`
    /// bytes before to a quarter of that past the first missing byte. After each step it checks
    /// the readable bytes, the held bytes and the pages held against a byte-map reference.
    /// Returns how often the buffer was empty before the end.
    fn check_reads_against_a_byte_map(mut seed: u64, near: Option<usize>) -> usize {
        let data: Vec<u8> = (0..3 * PAGE_SIZE as u32 + 1000)
            .map(|i| (i * 7 % 251) as u8)
            .collect();
        let mut next = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        let mut pool = PagePool::new();
        let mut buf = RecvBuffer::new();
        let mut have = vec![false; data.len()];
        let mut held = vec![false; data.len().div_ceil(PAGE_SIZE)];
        let mut read = 0;
        let mut emptied = 0;
        while read < data.len() {
            let prefix = have.iter().position(|h| !h).unwrap_or(have.len());
            // Frames may start before 0 and end past the data, then are clipped, so the first
            // and last bytes are as likely to arrive as any other.
            let (first, len) = match near {
                None => (next(data.len() + 3000) as isize - 1500, next(3000)),
                Some(len) => (
                    (prefix + next(len + len / 4)) as isize - len as isize,
                    next(len),
                ),
            };
            let start = first.clamp(0, data.len() as isize) as usize;
            let end = (first + 1 + len as isize).clamp(0, data.len() as isize) as usize;
            buf.insert(start as u64, &data[start..end], false, &mut pool)
                .unwrap();
            // The reference: a page is held from the first byte stored in it until every offset
            // in it is consumed or the buffer is empty.
            for i in start..end {
                held[i / PAGE_SIZE] |= !have[i];
                have[i] = true;
            }
            let n = match next(4) {
                0 => buf.readable().chain_length(),
                _ => next(buf.readable().chain_length() + 1),
            };
            buf.consume(n, &mut pool).unwrap();
            read += n;
            let empty = !have[read..].contains(&true);
            emptied += usize::from(empty && read < data.len());
            for (k, held) in held.iter_mut().enumerate() {
                *held &= !empty && (k + 1) * PAGE_SIZE > read;
            }
            let pages = held.iter().filter(|h| **h).count();
            let prefix = have.iter().position(|h| !h).unwrap_or(have.len());
            assert_eq!(readable(&buf), data[read..prefix]);
            assert_eq!(buf.buffered(), have[read..].iter().filter(|h| **h).count());
            assert_eq!(buf.pages.len(), pages);
        }
        assert!(
            buf.pages.is_empty(),
            "a buffer that holds no byte holds no page"
        );
        emptied
    }

    #[test]
    fn seeded_random_reads_across_pages_keep_the_held_pages_exact() {
        // Out-of-order bytes spread over all four pages.
        check_reads_against_a_byte_map(0x2545_f491_4f6c_dd1d, None);
        // Packet-sized frames close to the readable end, so the buffer often empties and gives
        // its page back.
        let emptied = check_reads_against_a_byte_map(0x9e37_79b9_7f4a_7c15, Some(1200));
        assert!(emptied >= 10, "the buffer emptied {emptied} times");
    }
}
