/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! QUIC DATAGRAM frames (RFC 9221).

use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use bytes::Bytes;
use bytes::BytesMut;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
pub use mvfstr_wire::datagram_frame_len;

use crate::SendOrder;
use crate::streams::recv_buf::PAGE_SIZE;

/// The most parts one datagram is written from: a WebTransport or HTTP/3 quarter stream ID, a MoQ
/// prefix, a shared header and two segments of a shared payload.
pub const MAX_PARTS: usize = 5;

/// Why a datagram was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramError {
    /// The peer does not take DATAGRAM frames with data: it has not advertised
    /// max_datagram_frame_size, its transport parameters have not arrived yet, or the value it
    /// advertised (1 or 2) leaves no room for data.
    Unsupported,
    /// The datagram is longer than [`Connection::max_datagram_size`](crate::Connection::max_datagram_size).
    TooLarge,
    /// The datagram has more than [`MAX_PARTS`] parts.
    TooManyParts,
    /// The datagram's expiry has passed.
    Expired,
    /// The connection is closing or closed.
    Closed,
    /// The datagram's frame is longer than what is left of the allowance of the driver's datagram
    /// sink.
    OverAllowance,
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "the peer does not take DATAGRAM frames",
            Self::TooLarge => "datagram larger than the peer or the path takes",
            Self::TooManyParts => "datagram in more than five parts",
            Self::Expired => "datagram expired",
            Self::Closed => "connection closed",
            Self::OverAllowance => "datagram longer than the sink's allowance",
        })
    }
}

impl std::error::Error for DatagramError {}

/// Datagram counters of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DatagramStats {
    /// Datagrams dropped unsent because their expiry passed.
    pub expired: u64,
    /// Datagrams dropped unsent, oldest first, to make room in a full send queue, or because
    /// their frame did not fit the packets of the transmit attempt that reached them.
    pub send_dropped: u64,
    /// Datagrams received.
    pub received: u64,
    /// Received datagrams dropped unread, oldest first, to make room in a full receive queue.
    pub recv_dropped: u64,
    /// Bytes copied out of received packets: each received datagram is copied once.
    pub recv_copied_bytes: u64,
}

/// A place in the wire order shared by streams and datagrams: class, urgency (RFC 9218 urgencies
/// above 7 count as 7), sequential before incremental, then the sequential order; lower first.
/// Incremental streams share their bucket round-robin, and incremental datagrams go in the order
/// they were queued, so their order does not count.
pub(crate) type WireKey = (u8, u8, bool, u128);

/// Returns the wire key of `order`.
pub(crate) fn wire_key(order: SendOrder) -> WireKey {
    let sequential = if order.incremental { 0 } else { order.order };
    (
        order.class,
        order.urgency.min(7),
        order.incremental,
        sequential,
    )
}

/// A datagram waiting to be sent: its parts, the first `count` of `parts`, their total length,
/// its place in the wire order, when it was queued, and when it expires.
#[derive(Debug)]
struct Queued {
    parts: [Bytes; MAX_PARTS],
    count: usize,
    len: usize,
    key: WireKey,
    seq: u64,
    expiry: Option<Instant>,
}

impl Queued {
    fn is_live(&self, now: Instant) -> bool {
        self.expiry.is_none_or(|expiry| expiry > now)
    }

    fn frame_len(&self) -> usize {
        datagram_frame_len(self.len)
    }
}

/// The datagrams waiting to be sent, in wire order and in the order they were queued among equals,
/// at most `cap` of them: a datagram queued when the queue is full drops the oldest. A datagram
/// whose expiry has passed, or whose frame is longer than the attempt's packets hold, is dropped
/// once it comes first in wire order, as an attempt starts or after the attempt sends the one
/// ahead of it, so within an attempt the first datagram can be sent and an empty queue is the
/// only one with nothing to send.
#[derive(Debug)]
pub(crate) struct SendQueue {
    queue: VecDeque<Queued>,
    cap: usize,
    next_seq: u64,
    /// The longest frame the current attempt's packets hold.
    max_frame: usize,
    /// The bytes of the frames that carry the queued datagrams.
    bytes: usize,
    expired: u64,
    dropped: u64,
}

impl SendQueue {
    /// Creates an empty queue of at most `cap` datagrams, at least one.
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            cap: cap.max(1),
            next_seq: 0,
            max_frame: usize::MAX,
            bytes: 0,
            expired: 0,
            dropped: 0,
        }
    }

    /// Queues a datagram of `len` bytes whose data is `parts`, at most [`MAX_PARTS`], in order,
    /// to be sent at `order` and dropped unsent once `expiry` passes. The parts are kept, not
    /// copied.
    pub(crate) fn push(
        &mut self,
        parts: &[Bytes],
        len: usize,
        order: SendOrder,
        expiry: Option<Instant>,
    ) {
        let mut queued = Queued {
            parts: Default::default(),
            count: parts.len(),
            len,
            key: wire_key(order),
            seq: self.next_seq,
            expiry,
        };
        self.next_seq += 1;
        queued.parts[..parts.len()].clone_from_slice(parts);
        if self.queue.len() >= self.cap {
            let oldest = (0..self.queue.len())
                .min_by_key(|&i| self.queue[i].seq)
                .unwrap_or(0);
            if let Some(oldest) = self.queue.remove(oldest) {
                self.bytes -= oldest.frame_len();
            }
            self.dropped += 1;
        }
        self.bytes += queued.frame_len();
        let at = self.queue.partition_point(|other| other.key <= queued.key);
        self.queue.insert(at, queued);
    }

    /// Returns whether no datagram waits.
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns the bytes of the frames that carry the queued datagrams, those behind the first
    /// that can no longer be sent included until they come first.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Starts an attempt whose packets hold frames of up to `max_frame` bytes, and drops the
    /// first datagrams in wire order while they cannot be sent at `now`.
    pub(crate) fn prune(&mut self, now: Instant, max_frame: usize) {
        self.max_frame = max_frame;
        self.drop_unsendable(now);
    }

    /// Drops the first datagrams in wire order while they have expired at `now` or do not fit
    /// the attempt's packets.
    fn drop_unsendable(&mut self, now: Instant) {
        while let Some(head) = self.queue.front() {
            if !head.is_live(now) {
                self.expired += 1;
            } else if head.frame_len() > self.max_frame {
                self.dropped += 1;
            } else {
                return;
            }
            self.bytes -= head.frame_len();
            self.queue.pop_front();
        }
    }

    /// Returns the first datagram in wire order that can be sent at `now`, behind any that
    /// cannot.
    fn head(&self, now: Instant) -> Option<&Queued> {
        self.queue
            .iter()
            .find(|queued| queued.is_live(now) && queued.frame_len() <= self.max_frame)
    }

    /// Returns the wire key of the first datagram that can be sent at `now`, if any.
    pub(crate) fn head_key(&self, now: Instant) -> Option<WireKey> {
        self.head(now).map(|head| head.key)
    }

    /// Returns the length of the frame that carries the first datagram that can be sent at `now`.
    // Out of line, so the code that sends streams alone stays as small as without datagrams.
    #[inline(never)]
    pub(crate) fn head_frame_len(&self, now: Instant) -> Option<usize> {
        self.head(now).map(Queued::frame_len)
    }

    /// Drops the datagrams that cannot be sent at `now` ahead of the first that can, then writes
    /// that one into `w`, its parts copied straight into the packet, removes it, and drops those
    /// that cannot be sent ahead of the next that can; or returns [`Full`] and keeps it.
    // Out of line, so the code that sends streams alone stays as small as without datagrams.
    #[inline(never)]
    pub(crate) fn write_head(
        &mut self,
        w: &mut PacketWriter<'_>,
        now: Instant,
    ) -> Result<(), Full> {
        self.drop_unsendable(now);
        let head = self.queue.front().ok_or(Full)?;
        w.datagram(&head.parts[..head.count])?;
        self.bytes -= head.frame_len();
        self.queue.pop_front();
        self.drop_unsendable(now);
        Ok(())
    }

    /// Adds the send counters to `stats`.
    pub(crate) fn add_stats(&self, stats: &mut DatagramStats) {
        stats.expired = self.expired;
        stats.send_dropped = self.dropped;
    }

    /// Returns the parts of the first datagram in wire order, for a test.
    #[cfg(test)]
    pub(crate) fn head_parts(&self) -> &[Bytes] {
        self.queue
            .front()
            .map_or(&[], |head| &head.parts[..head.count])
    }
}

/// The datagrams received and not yet read, oldest first, at most `cap` of them: a datagram
/// received when the queue is full drops the oldest.
///
/// A received datagram is copied once, out of the packet decrypted in place in the backend's
/// buffer, into a page this queue owns, and handed out as a slice of it, so many small datagrams
/// share one allocation. A page is freed once every slice of it has been dropped.
#[derive(Debug)]
pub(crate) struct RecvQueue {
    queue: VecDeque<Bytes>,
    cap: usize,
    page: BytesMut,
    received: u64,
    dropped: u64,
    copied_bytes: u64,
}

impl RecvQueue {
    /// Creates an empty queue of at most `cap` datagrams, at least one.
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            cap: cap.max(1),
            page: BytesMut::new(),
            received: 0,
            dropped: 0,
            copied_bytes: 0,
        }
    }

    /// Queues a copy of `data`.
    pub(crate) fn push(&mut self, data: &[u8]) {
        if self.page.capacity() < data.len() {
            self.page = BytesMut::with_capacity(PAGE_SIZE.max(data.len()));
        }
        self.page.extend_from_slice(data);
        if self.queue.len() >= self.cap {
            self.queue.pop_front();
            self.dropped += 1;
        }
        self.queue.push_back(self.page.split().freeze());
        self.received += 1;
        self.copied_bytes += data.len() as u64;
    }

    /// Takes the oldest datagram.
    pub(crate) fn pop(&mut self) -> Option<Bytes> {
        self.queue.pop_front()
    }

    /// Adds the receive counters to `stats`.
    pub(crate) fn add_stats(&self, stats: &mut DatagramStats) {
        stats.received = self.received;
        stats.recv_dropped = self.dropped;
        stats.recv_copied_bytes = self.copied_bytes;
    }
}

/// Returns the most data a DATAGRAM frame with a Length field carries in `room` bytes.
pub(crate) fn max_data(room: usize) -> usize {
    let mut data = room.saturating_sub(2);
    // The Length field shrinks with the data, so this settles within a few steps.
    while data > 0 && datagram_frame_len(data) > room {
        data -= 1;
    }
    data
}
