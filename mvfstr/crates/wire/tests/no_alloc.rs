/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Writing and parsing packets does not allocate. A global allocator counts every allocation on
//! the test's thread, and the binary holds only this test.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;

use bytes::Bytes;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::EcnCounts;
use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::Packets;
use mvfstr_wire::StreamId;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: `ptr` came from `System.alloc` with this `layout`; the caller upholds the rest.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn v(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

#[test]
fn writing_and_parsing_coalesced_packets_does_not_allocate() {
    let dcid = ConnectionId::new(&[0xd0; 8]).unwrap();
    let scid = ConnectionId::new(&[0x5c; 8]).unwrap();
    let data = Bytes::from(vec![0x33_u8; 4000]);
    let ranges: Vec<_> = (0..50_u64)
        .map(|i| 9000 - i * 10 - 5..=9000 - i * 10)
        .collect();
    let mut slot = vec![0u8; 1500];
    let before = ALLOCATIONS.with(Cell::get);

    let spec = HeaderSpec::Handshake {
        version: Version::V1,
        dcid,
        scid,
    };
    let mut w = PacketWriter::new(&mut slot[..600], spec, 3, 1, 16).unwrap();
    let ecn = EcnCounts {
        ect0: v(1),
        ect1: v(2),
        ce: v(3),
    };
    w.ack(
        ranges[0].clone(),
        ranges[1..].iter().cloned(),
        v(9),
        Some(ecn),
    )
    .unwrap();
    w.crypto(v(0), &data[..300]).unwrap();
    let handshake_len = w.finish().len;
    let spec = HeaderSpec::OneRtt {
        dcid,
        spin: false,
        key_phase: false,
    };
    let mut w = PacketWriter::new(&mut slot[handshake_len..], spec, 1000, 2, 16).unwrap();
    w.frame(&Frame::MaxData(v(1 << 20))).unwrap();
    let mut payload = w
        .begin_stream(StreamId::from(v(4)), v(0), data.len(), true)
        .unwrap();
    let len = payload.fit().len;
    payload.put_payload(&data, 0..len).unwrap();
    payload.finish().unwrap();
    let one_rtt_len = w.finish().len;

    let mut frames = 0;
    for packet in Packets::new(&slot[..handshake_len + one_rtt_len], 8) {
        let (start, Header::Protected(header)) = packet.unwrap() else {
            panic!("expected protected packets");
        };
        // Header protection is not applied, so the first byte still holds the PN length.
        let pn_len = usize::from(slot[start] & 0x03) + 1;
        let payload_start = start + header.pn_offset() + pn_len;
        let payload = &slot[payload_start..start + header.packet_len() - 16];
        for frame in Frames::new(payload) {
            if let Frame::Ack(ack) = frame.unwrap() {
                frames += ack.ranges().count();
            }
            frames += 1;
        }
    }

    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    assert!(frames > 3);
}
