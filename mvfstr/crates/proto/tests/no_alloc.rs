/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Buffering packets until their keys arrive does not allocate once the endpoint's pool holds
//! buffers, on a server or a client, and neither does queuing and sealing a datagram from shared
//! parts or an attempt that seals a PING. Census tests count what one side of a connected pair
//! allocates on a steady path after a warm-up: bulk send with ACK processing, bulk receive with
//! consume, DATAGRAM receive, and a loss and retransmit cycle, plus a forged Initial through route
//! and accept. Stream censuses count what a receive buffer allocates for in-order read cycles and
//! for a short request, and what a send buffer allocates for in-order ACKs. The census of a path
//! that is already clean asserts 0, and the other censuses assert their count as an upper bound. A
//! global allocator counts every allocation on each test's thread, and the binary holds only these
//! tests.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::AcceptError;
use mvfstr_proto::Bytes;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnKey;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::Connection;
use mvfstr_proto::DatagramSize;
use mvfstr_proto::Dir;
use mvfstr_proto::Ecn;
use mvfstr_proto::Endpoint;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::InlineSealer;
use mvfstr_proto::Inputs;
use mvfstr_proto::Random;
use mvfstr_proto::Route;
use mvfstr_proto::RxDatagram;
use mvfstr_proto::RxMeta;
use mvfstr_proto::SegmentSink;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::Side;
use mvfstr_proto::SlotId;
use mvfstr_proto::Stop;
use mvfstr_proto::StreamId;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::TxClass;
use mvfstr_proto::TxLimits;
use mvfstr_proto::TxMeta;
use mvfstr_proto::config::TransportConfigBuilder;
use mvfstr_proto::streams::recv_buf::PagePool;
use mvfstr_proto::streams::recv_buf::RecvBuffer;
use mvfstr_proto::streams::send_buf::FrameKind;
use mvfstr_proto::streams::send_buf::FrameWriter;
use mvfstr_proto::streams::send_buf::SendBuffer;
use mvfstr_proto::testing::Loss;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
use mvfstr_proto::testing::TestRng;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use mvfstr_wire::Header;
use mvfstr_wire::PacketType;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::UnixTime;

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

/// The copies of a packet each connection buffers.
const COPIES: usize = 8;
/// How long a handshake may take.
const LIMIT: Duration = Duration::from_secs(10);

/// Returns a pair config whose client's second datagram, which carries its Finished, is lost.
fn config() -> PairConfig {
    let mut config = lossless();
    config.to_server.loss = Loss::Drop(vec![1]);
    config
}

/// Returns a pair config whose server's first datagram, which carries its Initial and Handshake
/// packets, is lost.
fn client_config() -> PairConfig {
    let mut config = lossless();
    config.to_client.loss = Loss::Drop(vec![0]);
    config
}

fn lossless() -> PairConfig {
    lossless_with(Arc::new(TransportConfig::default()))
}

/// Returns a lossless pair config whose two sides take DATAGRAM frames.
fn datagram_config() -> PairConfig {
    let transport = TransportConfig::builder()
        .max_datagram_frame_size(65535)
        .build()
        .expect("a transport config");
    lossless_with(transport)
}

fn lossless_with(transport: Arc<TransportConfig>) -> PairConfig {
    // RFC 8410: a PKCS #8 v1 document with the id-Ed25519 algorithm around the seed.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let key = PrivatePkcs8KeyDer::from([&PREFIX[..], b"mvfstr no-alloc test key 0000001"].concat());
    let signing_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
        .expect("rcgen takes the Ed25519 key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .and_then(|params| params.self_signed(&signing_key))
        .expect("rcgen makes a certificate");
    let time = Arc::new(ManualTimeProvider::new(unix_now()));
    // One key share keeps the ClientHello in one datagram.
    let mut provider: CryptoProvider = mvfstr_crypto::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    let server_tls = mvfstr_tls::server_config(
        provider.clone(),
        time.clone(),
        vec![cert.der().clone()],
        key.into(),
        &[b"h3"],
    )
    .expect("a server TLS config");
    let client_tls = mvfstr_tls::client_config(
        provider,
        time,
        ServerVerification::AcceptAnyCertificate,
        &[b"h3"],
    )
    .expect("a client TLS config");
    let server = ServerConfig::builder(Arc::new(server_tls))
        .transport(transport.clone())
        .build()
        .expect("a server config");
    let client = ClientConfig::builder(Arc::new(client_tls))
        .transport(transport)
        .build()
        .expect("a client config");
    let endpoint = EndpointConfig::builder([7; 32])
        .build()
        .expect("an endpoint config");
    PairConfig::new(client, server, endpoint)
}

fn unix_now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000))
}

/// Returns the first packet of type `ty` in `datagram`.
fn packet_of(datagram: &[u8], ty: PacketType) -> Vec<u8> {
    let mut offset = 0;
    while offset < datagram.len() {
        let Ok(Header::Protected(header)) = Header::parse(&datagram[offset..], 8) else {
            panic!("an unparsable packet");
        };
        let len = header.packet_len();
        if header.ty() == ty {
            return datagram[offset..offset + len].to_vec();
        }
        offset += len;
    }
    panic!("no {ty:?} packet");
}

/// Runs the handshake of the pair's connection until the client's Finished is lost, feeds the
/// server [`COPIES`] copies of the 1-RTT PING that followed it, which the server buffers since
/// its handshake is not complete, then completes the handshake. Returns the allocations made
/// while the server buffered the copies.
fn buffer_copies(pair: &mut Pair) -> usize {
    pair.client.conn_mut().ping();
    let limit = pair.now + LIMIT;
    assert!(pair.run_until(limit, |pair| pair.to_server.lost() == 1));
    let packet = packet_of(&pair.client.sent[1].1.data, PacketType::OneRtt);
    let mut copies = vec![packet; COPIES];
    let meta = RxMeta {
        src: pair.client.addr,
        dst_ip: Some(pair.server.addr.ip()),
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: pair.now,
    };
    let now = pair.now;
    let server = pair.server.conn_mut();
    let before = ALLOCATIONS.with(Cell::get);
    for data in &mut copies {
        let summary = server.recv_batch(now, &mut [RxDatagram { meta: &meta, data }]);
        assert_eq!((summary.buffered, summary.packets), (1, 0));
    }
    let allocations = ALLOCATIONS.with(Cell::get) - before;
    assert!(pair.handshake(limit), "the client sends its Finished again");
    allocations
}

/// Runs the handshake of the pair's connection until the server's first datagram is lost, feeds
/// the client [`COPIES`] copies of the Handshake packet in it, which the client buffers since it
/// does not have Handshake keys yet, then completes the handshake. Returns the allocations made
/// while the client buffered the copies.
fn buffer_client_copies(pair: &mut Pair) -> usize {
    let limit = pair.now + LIMIT;
    assert!(pair.run_until(limit, |pair| pair.to_client.lost() == 1));
    let packet = packet_of(&pair.server.sent[0].1.data, PacketType::Handshake);
    let mut copies = vec![packet; COPIES];
    let meta = RxMeta {
        src: pair.server.addr,
        dst_ip: Some(pair.client.addr.ip()),
        ecn: Ecn::NotEct,
        stride: 0,
        rx_time: pair.now,
    };
    let now = pair.now;
    let client = pair.client.conn_mut();
    let before = ALLOCATIONS.with(Cell::get);
    for data in &mut copies {
        let summary = client.recv_batch(now, &mut [RxDatagram { meta: &meta, data }]);
        assert_eq!((summary.buffered, summary.packets), (1, 0));
    }
    let allocations = ALLOCATIONS.with(Cell::get) - before;
    assert!(pair.handshake(limit), "the server sends its flight again");
    allocations
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test needs one real Instant as the epoch of the pair's virtual clock"
)]
fn epoch() -> Instant {
    Instant::now()
}

#[test]
fn buffered_packets_allocate_nothing_once_the_endpoints_pool_holds_buffers() {
    let mut pair = Pair::new(epoch(), unix_now(), config());
    assert!(
        buffer_copies(&mut pair) > 0,
        "the first connection fills the pool"
    );
    pair.reconnect();
    assert_eq!(buffer_copies(&mut pair), 0, "a second connection reuses it");
}

#[test]
fn a_clients_buffered_packets_allocate_nothing_once_its_endpoints_pool_holds_buffers() {
    let mut pair = Pair::new(epoch(), unix_now(), client_config());
    assert!(
        buffer_client_copies(&mut pair) > 0,
        "the first connection fills the pool"
    );
    pair.reconnect();
    assert_eq!(
        buffer_client_copies(&mut pair),
        0,
        "a second connection reuses it"
    );
}

/// A sink over one reused slot that keeps only the length of each datagram, so it does not
/// allocate.
struct FixedSink {
    slot: [u8; 1500],
    lens: Vec<u16>,
}

impl SegmentSink for FixedSink {
    fn next_segment(&mut self, max_len: u16, _class: TxClass) -> Option<(SlotId, &mut [u8])> {
        let len = usize::from(max_len).min(self.slot.len());
        Some((SlotId(0), &mut self.slot[..len]))
    }

    fn end_segment(&mut self, len: u16) {
        if len > 0 {
            self.lens.push(len);
        }
    }

    fn end_run(&mut self, _meta: TxMeta) {}
}

#[test]
fn a_datagram_from_shared_parts_is_queued_and_sealed_without_allocating() {
    let mut pair = Pair::new(epoch(), unix_now(), datagram_config());
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit));
    pair.run(pair.now + Duration::from_millis(200));
    let order = SendOrder {
        class: 1,
        urgency: 3,
        incremental: false,
        order: 0,
    };
    let header = Bytes::from(vec![0x48; 40]);
    let payload = Bytes::from(vec![0x50; 1000]);
    let parts = [
        Bytes::from_static(&[0x01, 0x2a]),
        header,
        payload.slice(..300),
        payload.slice(500..800),
    ];
    let limits = pair.limits();
    let mut sink = FixedSink {
        slot: [0; 1500],
        lens: Vec::with_capacity(16),
    };
    let client = pair.client.conn_mut();
    // A first datagram warms up the queue and the sent-packet records.
    client.send_datagram(&parts, order, None).unwrap();
    client.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    // An attempt that seals a PING does not allocate, even with a debug build's checks.
    client.ping();
    let before = ALLOCATIONS.with(Cell::get);
    client.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    let ping = ALLOCATIONS.with(Cell::get) - before;
    assert_eq!(ping, 0, "an attempt that seals a PING does not allocate");
    sink.lens.clear();
    let before = ALLOCATIONS.with(Cell::get);
    client.send_datagram(&parts, order, None).unwrap();
    assert_eq!(
        ALLOCATIONS.with(Cell::get) - before,
        0,
        "queuing keeps the parts"
    );
    let before = ALLOCATIONS.with(Cell::get);
    let outcome = client.poll_transmit(&limits, &mut sink, &mut InlineSealer);
    let datagram = ALLOCATIONS.with(Cell::get) - before;
    assert_eq!(outcome.datagrams, 1);
    assert!(usize::from(sink.lens[0]) > 2 + 40 + 600, "{:?}", sink.lens);
    assert_eq!(
        datagram, 0,
        "sealing writes the parts straight into the slot"
    );
}

/// The most datagrams a census attempt builds, and the most datagrams a census receive batch
/// holds.
const BATCH: usize = 64;
/// The bytes the census streams and datagrams carry. Static bytes are shared without a reference
/// count, so the applications' handles on them do not allocate.
static PAYLOAD: [u8; 1 << 16] = [0x5a; 1 << 16];
/// The length of each census datagram.
const DATAGRAM_LEN: usize = 1200;
const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

/// Returns a lossless pair config for the census runs: the congestion window stops at [`BATCH`]
/// datagrams, so after the warm-up the data in flight and the batch size do not grow on either
/// side, and the stream window holds more than a window of data.
fn census_config() -> PairConfig {
    census_config_with(TransportConfig::builder())
}

fn census_config_with(transport: TransportConfigBuilder) -> PairConfig {
    let transport = transport
        .max_window(BATCH as u32)
        .max_stream_data_uni(1 << 20)
        .build()
        .expect("a transport config");
    lossless_with(transport)
}

/// Counts what one side's calls allocate once switched on.
struct Census {
    side: Side,
    on: bool,
    allocations: usize,
}

impl Census {
    /// Runs `f` for `side`, counting its allocations if the census is on and counts `side`.
    fn count<R>(&mut self, side: Side, f: impl FnOnce() -> R) -> R {
        if !self.on || side != self.side {
            return f();
        }
        let before = ALLOCATIONS.with(Cell::get);
        let out = f();
        self.allocations += ALLOCATIONS.with(Cell::get) - before;
        out
    }
}

/// A sink over slots allocated up front, so that building datagrams into it does not allocate.
struct SlotSink {
    slots: Vec<[u8; 1500]>,
    lens: Vec<u16>,
}

impl SlotSink {
    fn new() -> Self {
        Self {
            slots: vec![[0; 1500]; BATCH],
            lens: Vec::with_capacity(BATCH),
        }
    }
}

impl SegmentSink for SlotSink {
    fn next_segment(&mut self, max_len: u16, _class: TxClass) -> Option<(SlotId, &mut [u8])> {
        let index = self.lens.len();
        let slot = self.slots.get_mut(index)?;
        let len = usize::from(max_len).min(slot.len());
        Some((SlotId(index as u32), &mut slot[..len]))
    }

    fn end_segment(&mut self, len: u16) {
        if len > 0 {
            self.lens.push(len);
        }
    }

    fn end_run(&mut self, _meta: TxMeta) {}
}

/// Drives a connected pair by hand, one instant at a time, as a driver would: each side routes
/// and receives what arrived in batches of up to [`BATCH`] datagrams, fires a due deadline,
/// drains its events, and then runs its application and transmits until an attempt sends
/// nothing. Its census counts those calls on one side; the links and the copies between them
/// and the sinks are not counted.
struct Driver {
    census: Census,
    sinks: [SlotSink; 2],
    /// The largest receive batch of the counted side while the census was on.
    largest_batch: usize,
}

impl Driver {
    fn new(side: Side) -> Self {
        Self {
            census: Census {
                side,
                on: false,
                allocations: 0,
            },
            sinks: [SlotSink::new(), SlotSink::new()],
            largest_batch: 0,
        }
    }

    /// Runs instant after instant until `done` holds after one.
    fn run_until(
        &mut self,
        pair: &mut Pair,
        app: &mut dyn FnMut(Side, &mut Connection),
        done: impl Fn(&Pair) -> bool,
    ) {
        let limit = pair.now + LIMIT;
        let mut same_instant = 0;
        loop {
            self.instant(pair, app);
            if done(pair) {
                return;
            }
            let next = [
                pair.to_server.next_arrival(),
                pair.to_client.next_arrival(),
                pair.client.conn().next_deadline(),
                pair.server.conn().next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("the pair has a next event");
            assert!(next <= limit, "the run did not finish by {limit:?}");
            if next > pair.now {
                pair.now = next;
                same_instant = 0;
            } else {
                same_instant += 1;
                assert!(same_instant < 1000, "no progress at {:?}", pair.now);
            }
        }
    }

    fn instant(&mut self, pair: &mut Pair, app: &mut dyn FnMut(Side, &mut Connection)) {
        for side in [Side::Server, Side::Client] {
            self.receive(pair, side);
        }
        let now = pair.now;
        for side in [Side::Server, Side::Client] {
            let peer = match side {
                Side::Client => &mut pair.client,
                Side::Server => &mut pair.server,
            };
            let (conn, endpoint, key) = (
                peer.conn.as_mut().expect("the peer has a connection"),
                &mut peer.endpoint,
                peer.key,
            );
            self.census.count(side, || {
                if conn.next_deadline().is_some_and(|at| at <= now) {
                    conn.on_deadline(now);
                }
                while conn.poll_event().is_some() {}
                while let Some(event) = conn.poll_endpoint_event() {
                    endpoint.handle_event(key, event);
                }
            });
            loop {
                let conn = match side {
                    Side::Client => pair.client.conn_mut(),
                    Side::Server => pair.server.conn_mut(),
                };
                self.census.count(side, || app(side, conn));
                if !self.transmit(pair, side) {
                    break;
                }
            }
        }
    }

    /// Hands `side` the datagrams that have arrived.
    fn receive(&mut self, pair: &mut Pair, side: Side) {
        let now = pair.now;
        let (link, peer, src) = match side {
            Side::Client => (&mut pair.to_client, &mut pair.client, pair.server.addr),
            Side::Server => (&mut pair.to_server, &mut pair.server, pair.client.addr),
        };
        let mut datagrams = link.deliver(now);
        let metas: Vec<RxMeta> = datagrams
            .iter()
            .map(|data| RxMeta {
                src,
                dst_ip: Some(peer.addr.ip()),
                ecn: Ecn::NotEct,
                stride: u16::try_from(data.len()).expect("a datagram fits a u16"),
                rx_time: now,
            })
            .collect();
        for (batch, metas) in datagrams.chunks_mut(BATCH).zip(metas.chunks(BATCH)) {
            if self.census.on && side == self.census.side {
                self.largest_batch = self.largest_batch.max(batch.len());
            }
            let (endpoint, key) = (&mut peer.endpoint, peer.key);
            self.census.count(side, || {
                for (data, meta) in batch.iter().zip(metas) {
                    let route = endpoint.route(now, meta, data);
                    assert!(
                        matches!(route, Route::Existing(existing) if existing == key),
                        "a datagram for another connection"
                    );
                }
            });
            let mut rx: Vec<RxDatagram<'_>> = batch
                .iter_mut()
                .zip(metas)
                .map(|(data, meta)| RxDatagram { meta, data })
                .collect();
            let conn = peer.conn.as_mut().expect("the peer has a connection");
            self.census.count(side, || conn.recv_batch(now, &mut rx));
        }
    }

    /// Runs `side`'s transmit attempts until one stops for a reason other than a full batch, and
    /// sends what they built into the link. Returns whether they built a datagram.
    fn transmit(&mut self, pair: &mut Pair, side: Side) -> bool {
        let now = pair.now;
        let limits = TxLimits {
            now,
            max_segments: BATCH as u16,
            max_datagram: 1500,
            max_bytes: u32::MAX,
            epoch: None,
        };
        let (peer, link, sink) = match side {
            Side::Client => (&mut pair.client, &mut pair.to_server, &mut self.sinks[0]),
            Side::Server => (&mut pair.server, &mut pair.to_client, &mut self.sinks[1]),
        };
        let conn = peer.conn.as_mut().expect("the peer has a connection");
        let mut sent = false;
        loop {
            let outcome = self.census.count(side, || {
                conn.poll_transmit(&limits, sink, &mut InlineSealer)
            });
            for (slot, &len) in sink.slots.iter().zip(&sink.lens) {
                link.send(now, slot[..usize::from(len)].to_vec());
            }
            sent |= !sink.lens.is_empty();
            sink.lens.clear();
            if outcome.stop != Stop::BatchFull {
                return sent;
            }
        }
    }
}

/// The application of a bulk transfer from the server to the client on one stream: the server
/// keeps the stream topped up, and the client consumes every readable byte.
struct Bulk {
    id: StreamId,
    chunk: Bytes,
    consumed: usize,
}

impl Bulk {
    /// Opens the server's stream.
    fn start(pair: &mut Pair) -> Self {
        let id = pair
            .server
            .conn_mut()
            .open_stream(Dir::Uni, ORDER)
            .expect("the server opens a stream");
        Self {
            id,
            chunk: Bytes::new(),
            consumed: 0,
        }
    }

    fn run(&mut self, side: Side, conn: &mut Connection) {
        for _edge in conn.readiness() {}
        match side {
            Side::Server => {
                let mut stream = conn.stream(self.id).expect("the server's stream is open");
                while stream.send_capacity() > 0 {
                    if self.chunk.is_empty() {
                        self.chunk = Bytes::from_static(&PAYLOAD);
                    }
                    if stream.send(&mut self.chunk).expect("the stream takes data") == 0 {
                        break;
                    }
                }
            }
            Side::Client => {
                if let Ok(mut stream) = conn.stream(self.id) {
                    let n = stream.readable().chain_length();
                    if n > 0 {
                        stream.consume(n).expect("the readable bytes are consumed");
                        self.consumed += n;
                    }
                }
            }
        }
    }
}

/// Returns a pair whose handshake is complete and whose connections have gone quiet.
fn connected(config: PairConfig) -> Pair {
    let mut pair = Pair::new(epoch(), unix_now(), config);
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit));
    pair.run(pair.now + Duration::from_millis(200));
    pair
}

/// What a bulk census counted while it was on.
struct Window {
    allocations: usize,
    /// The largest receive batch of the counted side.
    largest_batch: usize,
    /// The ACK frames the server received.
    acks: u64,
    /// The packets the server declared lost.
    lost: u64,
}

/// Runs a bulk transfer from the server to the client until the server has sent `warm_up`
/// packets, then counts what `side` allocates until the server has sent `counted` more.
fn bulk_census(mut pair: Pair, side: Side, warm_up: u64, counted: u64) -> Window {
    let mut bulk = Bulk::start(&mut pair);
    let mut driver = Driver::new(side);
    let sent = |pair: &Pair| pair.server.conn().stats().sent_packets;
    let start = sent(&pair);
    driver.run_until(&mut pair, &mut |side, conn| bulk.run(side, conn), |pair| {
        sent(pair) >= start + warm_up
    });
    driver.census.on = true;
    let (start, consumed, before) = (sent(&pair), bulk.consumed, pair.server.conn().stats());
    driver.run_until(&mut pair, &mut |side, conn| bulk.run(side, conn), |pair| {
        sent(pair) >= start + counted
    });
    assert!(bulk.consumed > consumed, "the client consumed data");
    let after = pair.server.conn().stats();
    Window {
        allocations: driver.census.allocations,
        largest_batch: driver.largest_batch,
        acks: after.acks_received - before.acks_received,
        lost: after.lost_packets - before.lost_packets,
    }
}

#[test]
fn census_bulk_send_with_ack_processing_allocates_nothing() {
    let window = bulk_census(connected(census_config()), Side::Server, 2000, 2000);
    assert!(window.acks > 0, "the server processes ACKs");
    assert_eq!(window.allocations, 0, "bulk send with ACK processing");
}

#[test]
fn census_bulk_receive_with_consume_in_batches_of_64() {
    let window = bulk_census(connected(census_config()), Side::Client, 2000, 2048);
    assert_eq!(
        window.largest_batch, BATCH,
        "the client receives full batches"
    );
    // Each read cycle releases more pages than the connection's page pool keeps, so it allocates
    // and shares pages again.
    assert!(
        window.allocations <= 100,
        "bulk receive with consume: {}",
        window.allocations
    );
}

#[test]
fn census_a_loss_and_retransmit_cycle_allocates_nothing() {
    let mut pair = connected(census_config());
    // The server loses one datagram in every 100, through the warm-up and the counted packets.
    let first = pair.to_client.sent() + 50;
    pair.to_client
        .set_loss(Loss::Drop((first..first + 10_000).step_by(100).collect()));
    let window = bulk_census(pair, Side::Server, 2000, 2000);
    assert!(
        window.lost >= 10,
        "the server declares packets lost: {}",
        window.lost
    );
    assert_eq!(window.allocations, 0, "a loss and retransmit cycle");
}

/// The STREAM frames of a census read cycle.
const CYCLE_FRAMES: u64 = 48;
/// The length of each census STREAM frame.
const FRAME_LEN: usize = 1200;

/// Inserts [`CYCLE_FRAMES`] in-order frames into `buf` from `offset`, then consumes every byte.
/// Returns what that allocated and the offset after the cycle.
fn read_cycle(buf: &mut RecvBuffer, pool: &mut PagePool, offset: u64) -> (usize, u64) {
    let before = ALLOCATIONS.with(Cell::get);
    for k in 0..CYCLE_FRAMES {
        let at = offset + k * FRAME_LEN as u64;
        let got = buf
            .insert(at, &PAYLOAD[..FRAME_LEN], false, pool)
            .expect("an in-order frame");
        assert_eq!(got.readable, FRAME_LEN);
    }
    let n = buf.readable().chain_length();
    buf.consume(n, pool)
        .expect("the readable bytes are consumed");
    let allocations = ALLOCATIONS.with(Cell::get) - before;
    (allocations, offset + CYCLE_FRAMES * FRAME_LEN as u64)
}

#[test]
fn census_in_order_read_cycles_allocate_nothing_once_warm() {
    // The pool keeps every page a cycle gives back, so page reuse is not what is counted.
    let mut pool = PagePool::with_max_free(8);
    let mut buf = RecvBuffer::new();
    let mut offset = 0;
    let mut counts = [0; 4];
    for count in &mut counts {
        (*count, offset) = read_cycle(&mut buf, &mut pool, offset);
    }
    // A cycle spans 4 and 5 pages in turn, so the first two warm up.
    assert_eq!(pool.pages_allocated(), 5);
    assert_eq!(counts[2..], [0, 0], "in-order read cycles: {counts:?}");
}

/// Receives a short request, one frame of `request` with the FIN, on a new receive buffer, and
/// consumes it. Returns what that allocated.
fn short_request(request: &[u8], pool: &mut PagePool) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    let mut buf = RecvBuffer::new();
    let got = buf
        .insert(0, request, true, pool)
        .expect("a frame with the FIN");
    assert!(got.complete);
    buf.consume(request.len(), pool)
        .expect("the request is consumed");
    assert!(buf.is_finished());
    drop(buf);
    ALLOCATIONS.with(Cell::get) - before
}

#[test]
fn census_a_short_request_with_its_fin_allocates_only_room_for_its_page() {
    let request = &PAYLOAD[..200];
    let mut pool = PagePool::new();
    // The first request's page goes back to the pool for the second.
    short_request(request, &mut pool);
    let allocations = short_request(request, &mut pool);
    assert_eq!(pool.pages_allocated(), 1);
    assert!(
        allocations <= 1,
        "a short request with its FIN allocates only the page list's room for its page: \
         {allocations}"
    );
}

/// A frame writer over a fixed buffer, so that emitting into it does not allocate.
struct FixedWriter {
    buf: [u8; 1500],
    len: usize,
}

impl FrameWriter for FixedWriter {
    fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    fn put_slice(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn put_payload(&mut self, data: &Bytes, range: Range<usize>) {
        self.put_slice(&data[range]);
    }
}

#[test]
fn census_a_send_buffer_acknowledged_in_order_allocates_nothing() {
    let id = StreamId::try_from(0).expect("a stream ID");
    let mut buf = SendBuffer::new();
    for _ in 0..3 {
        buf.push(Bytes::from_static(&PAYLOAD[..1000]))
            .expect("the buffer takes a chunk");
    }
    buf.finish().expect("the stream ends");
    // One frame per chunk.
    let frames = [1000, 2000, 3000].map(|credit_end| {
        let mut w = FixedWriter {
            buf: [0; 1500],
            len: 0,
        };
        buf.emit(FrameKind::Stream(id), &mut w, usize::MAX, credit_end)
            .expect("a frame")
    });
    assert_eq!(
        frames.map(|f| (f.offset, f.len, f.fin)),
        [(0, 1000, false), (1000, 1000, false), (2000, 1000, true)]
    );
    let before = ALLOCATIONS.with(Cell::get);
    for f in &frames {
        buf.on_ack(f.offset, f.len, f.fin);
    }
    let allocations = ALLOCATIONS.with(Cell::get) - before;
    assert!(buf.is_acked());
    assert_eq!(allocations, 0, "three chunks acknowledged in order");
}

/// The application of a DATAGRAM transfer from the server to the client: the server queues
/// datagrams of [`DATAGRAM_LEN`] bytes while its window has room, up to `target` in all, and the
/// client reads and drops every datagram.
struct Datagrams {
    target: usize,
    queued: usize,
    read: usize,
}

impl Datagrams {
    fn run(&mut self, side: Side, conn: &mut Connection) {
        match side {
            Side::Server => {
                while self.queued < self.target && conn.datagram_allowance() >= DATAGRAM_LEN {
                    let parts = [Bytes::from_static(&PAYLOAD[..DATAGRAM_LEN])];
                    conn.send_datagram(&parts, ORDER, None)
                        .expect("the server queues a datagram");
                    self.queued += 1;
                }
            }
            Side::Client => {
                while let Some(datagram) = conn.read_datagram() {
                    assert_eq!(datagram.len(), DATAGRAM_LEN);
                    self.read += 1;
                }
            }
        }
    }
}

#[test]
fn census_datagram_receive() {
    // Packets at the peer's maximum size carry a 1,200-byte datagram.
    let config = census_config_with(
        TransportConfig::builder()
            .max_datagram_frame_size(65535)
            .datagram_size(DatagramSize::PeerMaximum),
    );
    let mut pair = connected(config);
    let mut app = Datagrams {
        target: 200,
        queued: 0,
        read: 0,
    };
    let mut driver = Driver::new(Side::Client);
    let quiet = |pair: &Pair| pair.server.conn().stats().bytes_in_flight == 0;
    driver.run_until(&mut pair, &mut |side, conn| app.run(side, conn), |pair| {
        quiet(pair)
    });
    assert_eq!(app.read, 200, "the warm-up datagrams arrive");
    driver.census.on = true;
    app.target += 1000;
    driver.run_until(&mut pair, &mut |side, conn| app.run(side, conn), |pair| {
        quiet(pair)
    });
    assert_eq!(app.read, 1200, "every datagram arrives");
    // The receive queue copies each datagram into a 16 KiB page, which holds 13 of them. Each time
    // a page is used up, it allocates a new page and the page's shared header, without reclaiming
    // a page whose datagrams the application has dropped.
    assert!(
        driver.census.allocations <= 154,
        "DATAGRAM receive: {}",
        driver.census.allocations
    );
}

/// Returns a datagram that carries an Initial with a valid header, for a connection ID chosen by
/// `id`, and a random payload, so that its packet does not open.
fn forged_initial(id: u8, rng: &mut TestRng) -> Vec<u8> {
    let mut out = vec![0xc0, 0, 0, 0, 1, 8, 0xf0, id, 1, 1, 1, 1, 1, 1];
    out.extend_from_slice(&[8, 2, 2, 2, 2, 2, 2, 2, 2, 0]);
    let rest = u16::try_from(1200 - out.len() - 2).expect("the length fits");
    out.extend_from_slice(&(0x4000 | rest).to_be_bytes());
    let mut payload = vec![0; 1200 - out.len()];
    rng.fill(&mut payload);
    out.extend_from_slice(&payload);
    out
}

#[test]
fn census_a_forged_initial_through_route_and_accept() {
    let config = census_config();
    let mut endpoint = Endpoint::new(config.endpoint.clone(), Some(config.server.clone()));
    let now = epoch();
    let meta = RxMeta {
        src: "10.0.0.1:50000".parse().expect("an address"),
        dst_ip: Some("10.0.0.2".parse().expect("an address")),
        ecn: Ecn::NotEct,
        stride: 1200,
        rx_time: now,
    };
    let key = ConnKey {
        index: 1,
        generation: 1,
    };
    let (unix_now, mut rng) = (unix_now(), TestRng::new(5));
    let mut forge = |id: u8, rng: &mut TestRng| {
        let datagram = forged_initial(id, rng);
        let before = ALLOCATIONS.with(Cell::get);
        let Route::Accept(incoming) = endpoint.route(now, &meta, &datagram) else {
            panic!("the endpoint offers the Initial for acceptance");
        };
        let mut cx = Inputs { now, unix_now, rng };
        let accepted = endpoint.accept(
            &mut cx,
            key,
            incoming,
            &config.server,
            ConnOptions::default(),
        );
        let allocations = ALLOCATIONS.with(Cell::get) - before;
        assert!(matches!(accepted, Err(AcceptError::Undecryptable)));
        allocations
    };
    // The first forged Initial warms up what an endpoint sets up once.
    forge(0, &mut rng);
    let allocations = forge(1, &mut rng);
    // The route copies the datagram. The accept then builds the whole connection, its rustls
    // session and its Initial keys before it finds that the packet does not open.
    assert!(
        allocations <= 20,
        "a forged Initial through route and accept: {allocations}"
    );
}
