/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The packets a connection keeps until their keys arrive (RFC 9001), in buffers that the
//! connections of one endpoint, and so of one driver, recycle through a shared pool.

use std::collections::VecDeque;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use super::Space;
use crate::RxMeta;

/// The most spare buffers a pool keeps; it frees any more.
const MAX_SPARE_BUFFERS: usize = 1024;
/// The most spare queues a pool keeps.
const MAX_SPARE_QUEUES: usize = 64;
/// The capacity of a new buffer: enough for the packets of a 1,500-byte datagram, so that a
/// recycled buffer takes the next packet without growing.
const BUFFER_CAPACITY: usize = 1500;

/// A packet kept until its keys arrive.
#[derive(Debug)]
pub(super) struct Buffered {
    pub(super) space: Space,
    pub(super) meta: RxMeta,
    pub(super) datagram_len: usize,
    pub(super) data: Vec<u8>,
}

/// Spare packet buffers and packet queues, shared by the connections of one endpoint.
#[derive(Clone, Debug, Default)]
pub(crate) struct DatagramPool(Arc<Mutex<Spares>>);

#[derive(Debug, Default)]
struct Spares {
    buffers: Vec<Vec<u8>>,
    queues: Vec<VecDeque<Buffered>>,
}

impl DatagramPool {
    fn spares(&self) -> MutexGuard<'_, Spares> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns a buffer that holds a copy of `packet`.
    fn copy(&self, packet: &[u8]) -> Vec<u8> {
        let spare = self.spares().buffers.pop();
        let mut buffer =
            spare.unwrap_or_else(|| Vec::with_capacity(packet.len().max(BUFFER_CAPACITY)));
        buffer.extend_from_slice(packet);
        buffer
    }

    /// Returns an empty queue with room for `limit` packets.
    fn queue(&self, limit: usize) -> VecDeque<Buffered> {
        let mut queue = self.spares().queues.pop().unwrap_or_default();
        queue.reserve(limit);
        queue
    }

    fn recycle(&self, buffer: Vec<u8>) {
        self.recycle_all([buffer]);
    }

    /// Keeps up to [`MAX_SPARE_BUFFERS`] of `buffers`. A buffer that grew past
    /// [`BUFFER_CAPACITY`] for a larger packet goes back to the allocator, so that the pool's
    /// spare buffers hold at most about 1.5 MB.
    fn recycle_all(&self, buffers: impl IntoIterator<Item = Vec<u8>>) {
        let mut spares = self.spares();
        for mut buffer in buffers {
            if buffer.capacity() <= BUFFER_CAPACITY && spares.buffers.len() < MAX_SPARE_BUFFERS {
                buffer.clear();
                spares.buffers.push(buffer);
            }
        }
    }

    /// Takes back `queue` and the buffers of the packets left in it.
    fn recycle_queue(&self, mut queue: VecDeque<Buffered>) {
        self.recycle_all(queue.drain(..).map(|packet| packet.data));
        let mut spares = self.spares();
        if queue.capacity() > 0 && spares.queues.len() < MAX_SPARE_QUEUES {
            spares.queues.push(queue);
        }
    }
}

/// The packets one connection keeps until their keys arrive, oldest first.
#[derive(Debug)]
pub(super) struct BufferedPackets {
    pool: DatagramPool,
    /// The waiting packets; while empty it has zero capacity, so that it does not hold memory.
    queue: VecDeque<Buffered>,
}

impl BufferedPackets {
    pub(super) fn new(pool: DatagramPool) -> Self {
        Self {
            pool,
            queue: VecDeque::new(),
        }
    }

    /// Keeps a copy of `packet` unless `limit` packets wait already; returns whether it did.
    pub(super) fn push(
        &mut self,
        space: Space,
        meta: &RxMeta,
        datagram_len: usize,
        packet: &[u8],
        limit: usize,
    ) -> bool {
        if self.queue.len() >= limit {
            return false;
        }
        if self.queue.capacity() == 0 {
            self.queue = self.pool.queue(limit);
        }
        self.queue.push_back(Buffered {
            space,
            meta: *meta,
            datagram_len,
            data: self.pool.copy(packet),
        });
        true
    }

    /// Takes every waiting packet. Give each packet's buffer back with
    /// [`recycle`](Self::recycle), then the queue with [`recycle_queue`](Self::recycle_queue).
    pub(super) fn take(&mut self) -> VecDeque<Buffered> {
        mem::take(&mut self.queue)
    }

    pub(super) fn recycle(&self, buffer: Vec<u8>) {
        self.pool.recycle(buffer);
    }

    pub(super) fn recycle_queue(&self, queue: VecDeque<Buffered>) {
        self.pool.recycle_queue(queue);
    }

    /// Drops the packets of `space`, whose keys are discarded.
    pub(super) fn discard(&mut self, space: Space) {
        let pool = &self.pool;
        self.queue.retain_mut(|packet| {
            if packet.space != space {
                return true;
            }
            pool.recycle(mem::take(&mut packet.data));
            false
        });
        if self.queue.is_empty() {
            let queue = self.take();
            self.recycle_queue(queue);
        }
    }
}

impl Drop for BufferedPackets {
    fn drop(&mut self) {
        let queue = self.take();
        self.recycle_queue(queue);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    use super::*;
    use crate::Ecn;

    /// Returns `pool`'s spare buffers and queues.
    fn spare(pool: &DatagramPool) -> (usize, usize) {
        let spares = pool.spares();
        (spares.buffers.len(), spares.queues.len())
    }

    /// Returns packets taken from `pool` that wait in `spaces`, in order.
    fn waiting(pool: &DatagramPool, spaces: &[Space]) -> BufferedPackets {
        let meta = RxMeta {
            src: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride: 100,
            rx_time: crate::recovery::test_epoch(),
        };
        let mut packets = BufferedPackets::new(pool.clone());
        for &space in spaces {
            assert!(packets.push(space, &meta, 100, &[0; 100], 20));
        }
        packets
    }

    #[test]
    fn discarding_a_space_gives_its_packets_buffers_and_then_the_queue_to_the_pool() {
        let pool = DatagramPool::default();
        let spaces = [Space::Handshake, Space::Data, Space::Handshake];
        let mut packets = waiting(&pool, &spaces);
        packets.discard(Space::Handshake);
        assert_eq!(spare(&pool), (2, 0), "the 1-RTT packet still waits");
        packets.discard(Space::Data);
        assert_eq!(spare(&pool), (3, 1));
    }

    #[test]
    fn dropping_waiting_packets_gives_their_buffers_and_queue_to_the_pool() {
        let pool = DatagramPool::default();
        drop(waiting(&pool, &[Space::Data, Space::Data]));
        assert_eq!(spare(&pool), (2, 1));
    }

    #[test]
    fn a_new_buffer_has_room_for_any_packet_of_a_1500_byte_datagram() {
        let pool = DatagramPool::default();
        let buffer = pool.copy(&[0; 100]);
        assert!(
            buffer.capacity() >= BUFFER_CAPACITY,
            "so that, recycled, it takes the next packet without growing: {}",
            buffer.capacity()
        );
    }

    #[test]
    fn a_pool_keeps_no_buffer_that_grew_past_the_buffer_capacity() {
        let pool = DatagramPool::default();
        pool.recycle(pool.copy(&[0; 1200]));
        assert_eq!(pool.spares().buffers.len(), 1);
        // A packet can run to the end of a datagram of up to 64 KiB.
        let grown = pool.copy(&[0; 65_000]);
        assert!(grown.capacity() > BUFFER_CAPACITY);
        pool.recycle(grown);
        assert!(
            pool.spares().buffers.is_empty(),
            "a buffer that grew past {BUFFER_CAPACITY} bytes goes back to the allocator"
        );
    }

    #[test]
    fn a_pool_keeps_at_most_1024_spare_buffers() {
        let pool = DatagramPool::default();
        pool.recycle_all((0..=MAX_SPARE_BUFFERS).map(|_| Vec::with_capacity(BUFFER_CAPACITY)));
        assert_eq!(pool.spares().buffers.len(), MAX_SPARE_BUFFERS);
    }

    #[test]
    fn a_pool_keeps_at_most_64_spare_queues() {
        let pool = DatagramPool::default();
        let queues: Vec<_> = (0..=MAX_SPARE_QUEUES).map(|_| pool.queue(20)).collect();
        for queue in queues {
            pool.recycle_queue(queue);
        }
        assert_eq!(pool.spares().queues.len(), MAX_SPARE_QUEUES);
    }
}
