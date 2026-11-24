/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Buffering packets until their keys arrive does not allocate once the endpoint's pool holds
//! buffers, on a server or a client. A global allocator counts every allocation on each test's
//! thread, and the binary holds only these tests.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ClientConfig;
use mvfstr_proto::Ecn;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::RxDatagram;
use mvfstr_proto::RxMeta;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::testing::Loss;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
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
        .build()
        .expect("a server config");
    let client = ClientConfig::builder(Arc::new(client_tls))
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
