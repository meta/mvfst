/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The objects of paced mode: each starts with a 16-byte header of its length, its sequence
//! number on its stream and its send time, and the rest is the server's shared payload.

use std::collections::VecDeque;

/// The length of an object's header.
pub(crate) const HEADER_LEN: usize = 16;

/// The most objects a stream holds before the server drops the oldest.
pub(crate) const QUEUE_CAP: usize = 64;

/// An object's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectHeader {
    /// The object's length, header included.
    pub(crate) len: u32,
    /// The object's sequence number on its stream.
    pub(crate) seq: u32,
    /// When the server's tick that made the object started, in nanoseconds of the host's
    /// CLOCK_MONOTONIC.
    pub(crate) sent_ns: u64,
}

impl ObjectHeader {
    /// Returns the header's wire form: each field in network byte order.
    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut wire = [0; HEADER_LEN];
        wire[..4].copy_from_slice(&self.len.to_be_bytes());
        wire[4..8].copy_from_slice(&self.seq.to_be_bytes());
        wire[8..].copy_from_slice(&self.sent_ns.to_be_bytes());
        wire
    }

    /// Reads the header at the start of `bytes`, or returns `None` if they are too short.
    pub(crate) fn parse(bytes: &[u8]) -> Option<ObjectHeader> {
        let (len, rest) = bytes.split_first_chunk::<4>()?;
        let (seq, rest) = rest.split_first_chunk::<4>()?;
        let (sent_ns, _) = rest.split_first_chunk::<8>()?;
        Some(ObjectHeader {
            len: u32::from_be_bytes(*len),
            seq: u32::from_be_bytes(*seq),
            sent_ns: u64::from_be_bytes(*sent_ns),
        })
    }
}

/// Returns the host's CLOCK_MONOTONIC in nanoseconds, which every process on the host shares.
#[expect(unsafe_code, reason = "clock_gettime(2) through libc")]
pub(crate) fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a writable `timespec`.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    // CLOCK_MONOTONIC exists on every Linux kernel, so the call fails only on a bad pointer.
    debug_assert_eq!(status, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    let secs = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    secs * 1_000_000_000 + nanos
}

/// What an [`ObjectReader`] finds in a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// An object whose last byte arrived.
    Object(ObjectHeader),
    /// A header whose length is not the object size.
    Bad,
}

/// Splits the bytes of one stream into objects of one size, `--object_size`. A header with
/// another length is a bad object, after which the reader stops: without a length it can trust,
/// it cannot find where the next object starts.
#[derive(Clone, Debug)]
pub(crate) struct ObjectReader {
    /// The length of every object, header included; at least a header.
    size: u32,
    /// The header of the object being read, as far as it has arrived.
    header: [u8; HEADER_LEN],
    /// The bytes of `header` that have arrived.
    filled: usize,
    /// The payload bytes of the object being read still to arrive, once its header has.
    left: u32,
    /// Whether a bad object has arrived.
    stopped: bool,
}

impl ObjectReader {
    /// Creates the reader of a stream whose objects are `size` bytes long, header included.
    pub(crate) fn new(size: u32) -> Self {
        Self {
            size,
            header: [0; HEADER_LEN],
            filled: 0,
            left: 0,
            stopped: false,
        }
    }

    /// Reads `bytes`, the stream's next bytes, and passes `found` each object whose last byte
    /// they hold and the bad object that stops the reader.
    pub(crate) fn feed(&mut self, mut bytes: &[u8], mut found: impl FnMut(Found)) {
        while !bytes.is_empty() && !self.stopped {
            if self.filled < HEADER_LEN {
                let take = (HEADER_LEN - self.filled).min(bytes.len());
                let (head, rest) = bytes.split_at(take);
                self.header[self.filled..self.filled + take].copy_from_slice(head);
                self.filled += take;
                bytes = rest;
                if self.filled < HEADER_LEN {
                    return;
                }
                if self.current().len != self.size {
                    self.stopped = true;
                    found(Found::Bad);
                    return;
                }
                self.left = self.size.saturating_sub(HEADER_LEN as u32);
            } else {
                let take = bytes.len().min(self.left as usize);
                self.left -= take as u32;
                bytes = &bytes[take..];
            }
            if self.left == 0 {
                found(Found::Object(self.current()));
                self.filled = 0;
            }
        }
    }

    /// Returns whether the stream so far ends inside an object: part of one has arrived, and not
    /// its last byte.
    pub(crate) fn inside_object(&self) -> bool {
        self.filled > 0 && !self.stopped
    }

    /// Returns the header of the object being read, once it has arrived.
    fn current(&self) -> ObjectHeader {
        ObjectHeader::parse(&self.header).expect("the header buffer holds a whole header")
    }
}

/// The objects a stream has not taken yet, oldest first.
#[derive(Clone, Debug, Default)]
pub(crate) struct ObjectQueue {
    objects: VecDeque<ObjectHeader>,
}

impl ObjectQueue {
    /// Queues `object`; with [`QUEUE_CAP`] objects already queued, drops the oldest and returns
    /// it.
    pub(crate) fn push(&mut self, object: ObjectHeader) -> Option<ObjectHeader> {
        let dropped = if self.objects.len() >= QUEUE_CAP {
            self.objects.pop_front()
        } else {
            None
        };
        self.objects.push_back(object);
        dropped
    }

    /// Takes the oldest object.
    pub(crate) fn pop(&mut self) -> Option<ObjectHeader> {
        self.objects.pop_front()
    }

    /// Returns the number of objects queued.
    pub(crate) fn len(&self) -> usize {
        self.objects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_its_length_sequence_and_send_time_in_network_byte_order() {
        let header = ObjectHeader {
            len: 1200,
            seq: 7,
            sent_ns: 0x0123_4567_89ab_cdef,
        };
        let wire = header.encode();
        assert_eq!(
            wire,
            [
                0x00, 0x00, 0x04, 0xb0, // length
                0x00, 0x00, 0x00, 0x07, // sequence number
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // send time
            ]
        );
        assert_eq!(ObjectHeader::parse(&wire), Some(header));
        let mut object = wire.to_vec();
        object.extend_from_slice(&[0xff; 32]);
        assert_eq!(
            ObjectHeader::parse(&object),
            Some(header),
            "the payload after the header is not read"
        );
        assert_eq!(ObjectHeader::parse(&wire[..HEADER_LEN - 1]), None);
        assert_eq!(ObjectHeader::parse(&[]), None);
        let largest = ObjectHeader {
            len: u32::MAX,
            seq: u32::MAX,
            sent_ns: u64::MAX,
        };
        assert_eq!(ObjectHeader::parse(&largest.encode()), Some(largest));
    }

    /// Returns a stream that carries objects of `sizes` bytes, numbered from 0, with send times
    /// 1000 ns apart, and their headers.
    fn stream_of(sizes: &[u32]) -> (Vec<u8>, Vec<ObjectHeader>) {
        let mut stream = Vec::new();
        let mut headers = Vec::new();
        for (seq, &len) in (0..).zip(sizes) {
            let header = ObjectHeader {
                len,
                seq,
                sent_ns: 5_000_000 + u64::from(seq) * 1000,
            };
            stream.extend_from_slice(&header.encode());
            stream.resize(stream.len() + len as usize - HEADER_LEN, 0xa5);
            headers.push(header);
        }
        (stream, headers)
    }

    /// Returns what a reader finds in a stream of the objects with `headers`.
    fn objects(headers: &[ObjectHeader]) -> Vec<Found> {
        headers.iter().copied().map(Found::Object).collect()
    }

    #[test]
    fn the_reader_finds_every_object_however_the_stream_is_cut() {
        // Header-only objects, and objects whose headers and payloads straddle the cuts.
        for size in [16, 17, 40, 1200] {
            let (stream, headers) = stream_of(&[size; 5]);
            for chunk in [1, 3, 7, 15, 16, 17, 100, 1199, 1200, 1201, stream.len()] {
                let mut reader = ObjectReader::new(size);
                let mut found = Vec::new();
                for bytes in stream.chunks(chunk) {
                    reader.feed(bytes, |object| found.push(object));
                }
                assert_eq!(
                    found,
                    objects(&headers),
                    "objects of {size} bytes in chunks of {chunk}"
                );
            }
        }
    }

    #[test]
    fn the_reader_reports_an_object_only_with_its_last_byte() {
        let (stream, headers) = stream_of(&[1200, 1200]);
        let mut reader = ObjectReader::new(1200);
        let mut found = Vec::new();
        reader.feed(&stream[..1199], |object| found.push(object));
        assert_eq!(found, [], "the first object lacks its last byte");
        reader.feed(&stream[1199..1200], |object| found.push(object));
        assert_eq!(found, objects(&headers[..1]));
        reader.feed(&stream[1200..2399], |object| found.push(object));
        assert_eq!(found, objects(&headers[..1]));
        reader.feed(&stream[2399..], |object| found.push(object));
        assert_eq!(found, objects(&headers));
    }

    #[test]
    fn a_length_other_than_the_object_size_is_a_bad_object_that_stops_the_reader() {
        // A saturating server's stream of zeros starts with a length of 0.
        let mut reader = ObjectReader::new(1200);
        let mut found = Vec::new();
        reader.feed(&[0; 4096], |object| found.push(object));
        assert_eq!(found, [Found::Bad], "a stream of zeros");

        // Two objects, a header of another length, then what would be another object.
        for len in [0, 15, 16, 1199, 1201, u32::MAX] {
            let (mut stream, headers) = stream_of(&[1200, 1200]);
            let other = ObjectHeader {
                len,
                seq: 2,
                sent_ns: 1,
            };
            stream.extend_from_slice(&other.encode());
            stream.resize(stream.len() + 1200 - HEADER_LEN, 0xa5);
            stream.extend_from_slice(&stream_of(&[1200]).0);
            let mut reader = ObjectReader::new(1200);
            let mut found = Vec::new();
            for bytes in stream.chunks(7) {
                reader.feed(bytes, |object| found.push(object));
            }
            let mut expected = objects(&headers);
            expected.push(Found::Bad);
            assert_eq!(found, expected, "a length of {len}");
        }
    }

    #[test]
    fn the_reader_knows_whether_the_stream_so_far_ends_inside_an_object() {
        let (stream, _) = stream_of(&[1200, 1200]);
        let mut reader = ObjectReader::new(1200);
        assert!(!reader.inside_object(), "nothing read yet");
        let mut read = 0;
        for (end, inside) in [
            (1, true),
            (16, true),
            (17, true),
            (1199, true),
            (1200, false),
            (1201, true),
            (2400, false),
        ] {
            reader.feed(&stream[read..end], |_| {});
            read = end;
            assert_eq!(reader.inside_object(), inside, "after {end} bytes");
        }

        let mut reader = ObjectReader::new(1200);
        reader.feed(&[0; 20], |_| {});
        assert!(
            !reader.inside_object(),
            "a bad object stops the reader, so it has no object to end inside"
        );
    }

    #[test]
    fn a_full_queue_drops_its_oldest_object_for_a_new_one() {
        let object = |seq| ObjectHeader {
            len: 1200,
            seq,
            sent_ns: u64::from(seq),
        };
        let mut queue = ObjectQueue::default();
        for seq in 0..64 {
            assert_eq!(queue.push(object(seq)), None, "object {seq}");
        }
        assert_eq!(queue.len(), QUEUE_CAP);
        assert_eq!(queue.push(object(64)), Some(object(0)));
        assert_eq!(queue.push(object(65)), Some(object(1)));
        assert_eq!(queue.len(), QUEUE_CAP);
        assert_eq!(queue.pop(), Some(object(2)), "oldest first");
        assert_eq!(queue.push(object(66)), None, "room for one again");
        let rest: Vec<u32> = std::iter::from_fn(|| queue.pop())
            .map(|object| object.seq)
            .collect();
        assert_eq!(rest, (3..=66).collect::<Vec<u32>>());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    #[expect(unsafe_code, reason = "clock_gettime(2) through libc, to compare")]
    fn send_times_are_clock_monotonic_in_nanoseconds() {
        // The client's process compares them with its own reading of the same clock.
        let read = || {
            let mut now = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `now` is a writable `timespec`.
            let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
            assert_eq!(status, 0);
            now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
        };
        let before = read();
        let sent = monotonic_ns();
        let after = read();
        assert!(
            before <= sent && sent <= after,
            "{before} <= {sent} <= {after}"
        );
    }
}
