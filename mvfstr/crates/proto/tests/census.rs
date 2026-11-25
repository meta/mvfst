/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A census of the heap one connection holds. Each scenario runs a connected pair, takes one
//! side's connection out of it and drops it: the bytes that the drop frees are the heap that this
//! connection alone held. Each scenario prints that number and asserts that it is at most a pinned
//! bound. The scenarios are (a) an idle pair after a handshake without session tickets, with a
//! small certificate and again with a certificate chain the size of a production one, (b) a pair
//! after one request and response, (c) a pair after an HTTP/3-shaped flight, and (d) an idle
//! client after its session tickets arrive. Three more tests count the receive pages that
//! connections allocate: later connections of the same endpoints after a full handshake, and a
//! connection whose 0-RTT was rejected, during its handshake and after it. The endpoints' pools
//! hold the pages that connections give back.
//!
//! A global allocator counts the bytes that each thread has allocated and not freed, and each
//! thread's allocations of exactly 16 KiB, the size of a receive page. The counts are the sizes
//! requested from the allocator. Only Rust allocations count; memory that a crypto library
//! allocates in C does not. The binary holds only these tests.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::Bytes;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::Connection;
use mvfstr_proto::Dir;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::SendOrder;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::Side;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TransportConfig;
use mvfstr_proto::streams::recv_buf::PAGE_SIZE;
use mvfstr_proto::testing::Pair;
use mvfstr_proto::testing::PairConfig;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::UnixTime;

/// The size of a receive page.
const PAGE: usize = PAGE_SIZE;

thread_local! {
    /// The bytes that this thread has allocated and not freed. The count wraps, since a thread may
    /// free what another allocated.
    static LIVE: Cell<usize> = const { Cell::new(0) };
    /// This thread's allocations of exactly [`PAGE`] bytes, reallocations to that size included.
    static PAGES: Cell<u64> = const { Cell::new(0) };
}

/// Adds `size` bytes to this thread's live bytes, and counts a page allocation if `size` is
/// [`PAGE`].
fn allocated(size: usize) {
    LIVE.with(|live| live.set(live.get().wrapping_add(size)));
    if size == PAGE {
        PAGES.with(|pages| pages.set(pages.get() + 1));
    }
}

/// Takes `size` bytes off this thread's live bytes.
fn freed(size: usize) {
    LIVE.with(|live| live.set(live.get().wrapping_sub(size)));
}

struct Counting;

// SAFETY: every call is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        freed(layout.size());
        // SAFETY: `ptr` came from `System.alloc` with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        freed(layout.size());
        allocated(new_size);
        // SAFETY: `ptr` came from `System.alloc` with this `layout`; the caller upholds the rest.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Returns the bytes that this thread has allocated and not freed.
fn live() -> usize {
    LIVE.with(Cell::get)
}

/// Returns this thread's allocations of exactly [`PAGE`] bytes so far.
fn pages() -> u64 {
    PAGES.with(Cell::get)
}

/// The most heap that an idle server holds after a handshake without session tickets.
const IDLE_SERVER: usize = 2_882;
/// The most heap that an idle client holds after a handshake without session tickets.
const IDLE_CLIENT: usize = 6_348;
/// The most heap that a server holds after one request and response.
const REQUEST_SERVER: usize = 7_042;
/// The most heap that a client holds after one request and response.
const REQUEST_CLIENT: usize = 10_508;
/// The most heap that a server holds after an HTTP/3-shaped flight.
const H3_SERVER: usize = 10_818;
/// The most heap that a client holds after an HTTP/3-shaped flight.
const H3_CLIENT: usize = 14_284;
/// The most heap that an idle client holds after its session tickets arrive.
const TICKETS_CLIENT: usize = 6_508;
/// The most heap that an idle server holds after a handshake with a production-size chain: no
/// more than with a small certificate, since the server keeps nothing of its flight.
const CHAIN_IDLE_SERVER: usize = IDLE_SERVER;
/// The most heap that an idle client holds after a handshake with a production-size chain. The
/// client keeps the server's certificates.
const CHAIN_IDLE_CLIENT: usize = 13_829;

/// Returns what ring adds to the heap of a connection on `side` when it is the only crypto
/// backend: ring keeps its keys in Rust allocations, where aws-lc-rs keeps them in C.
fn ring_extra(side: Side) -> usize {
    match side {
        _ if cfg!(feature = "aws-lc-rs") => 0,
        Side::Server => 1_584,
        Side::Client => 2_608,
    }
}

/// How long a handshake may take.
const LIMIT: Duration = Duration::from_secs(10);
/// The bytes the census streams carry. Static bytes are shared without a reference count, so the
/// applications' handles on them do not allocate.
static PAYLOAD: [u8; 1024] = [0x5a; 1024];
/// The length of a request, which ends with the FIN.
const REQUEST: usize = 200;
/// The length of the response to a request, which ends with the FIN.
const RESPONSE: usize = 1024;
/// The lengths of the three unidirectional streams that each side of an HTTP/3 connection opens:
/// the control stream with its SETTINGS, and the two QPACK streams, which carry only their type
/// while the dynamic table is off.
const UNI: [usize; 3] = [12, 1, 1];
const ORDER: SendOrder = SendOrder {
    class: 1,
    urgency: 3,
    incremental: false,
    order: 0,
};

/// A certificate chain, the server's certificate first, and the server's key.
type Identity = (Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>);

/// Returns the Ed25519 key with this seed. Ed25519 signatures have a fixed length and are
/// deterministic, so each certificate, and each handshake, has the same size in every run.
fn ed25519(seed: &[u8; 32]) -> PrivatePkcs8KeyDer<'static> {
    // RFC 8410: a PKCS #8 v1 document with the id-Ed25519 algorithm around the seed.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    PrivatePkcs8KeyDer::from([&PREFIX[..], &seed[..]].concat())
}

fn key_pair(key: &PrivatePkcs8KeyDer<'_>) -> rcgen::KeyPair {
    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(key, &rcgen::PKCS_ED25519)
        .expect("rcgen takes the Ed25519 key")
}

/// Returns a small self-signed certificate for localhost.
fn self_signed() -> Identity {
    let key = ed25519(b"mvfstr census test key 000000001");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .and_then(|params| params.self_signed(&key_pair(&key)))
        .expect("rcgen makes a certificate");
    (vec![cert.der().clone()], key)
}

/// The names in the server certificate of [`production_chain`].
const CHAIN_NAMES: usize = 64;

/// Returns a chain the size of a production one: a server certificate with many names, issued
/// by an intermediate CA that a root CA issued, sent with the intermediate's certificate.
fn production_chain() -> Identity {
    let ca = |name: &str, constraints| {
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("CA params");
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "US");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example Trust Services");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(constraints);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
    };
    let root = rcgen::CertifiedIssuer::self_signed(
        ca("Example Root CA", rcgen::BasicConstraints::Unconstrained),
        key_pair(&ed25519(b"mvfstr census root CA key 000001")),
    )
    .expect("rcgen makes the root certificate");
    let intermediate = rcgen::CertifiedIssuer::signed_by(
        ca(
            "Example TLS Issuing CA 2026",
            rcgen::BasicConstraints::Constrained(0),
        ),
        key_pair(&ed25519(b"mvfstr census issuing CA key 001")),
        &root,
    )
    .expect("the root issues the intermediate certificate");
    let names = std::iter::once("localhost".to_owned())
        .chain(
            (1..CHAIN_NAMES)
                .map(|i| format!("service-{i:02}.frontend-pool.production-example.test")),
        )
        .collect::<Vec<_>>();
    let mut params = rcgen::CertificateParams::new(names).expect("server params");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Example Services");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "edge.example.test");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = ed25519(b"mvfstr census server key 0000001");
    let cert = params
        .signed_by(&key_pair(&key), &intermediate)
        .expect("the intermediate issues the server certificate");
    (vec![cert.der().clone(), intermediate.der().clone()], key)
}

/// Returns a lossless pair config whose server presents `identity`. Its server sends session
/// tickets after each handshake if `tickets`, as rustls does by default.
fn config(tickets: bool, (chain, key): Identity) -> PairConfig {
    let time = Arc::new(ManualTimeProvider::new(unix_now()));
    // One key share keeps the ClientHello in one datagram.
    let mut provider: CryptoProvider = mvfstr_crypto::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    let mut server_tls =
        mvfstr_tls::server_config(provider.clone(), time.clone(), chain, key.into(), &[b"h3"])
            .expect("a server TLS config");
    if !tickets {
        server_tls.send_tls13_tickets = 0;
    }
    let client_tls = mvfstr_tls::client_config(
        provider,
        time,
        ServerVerification::AcceptAnyCertificate,
        &[b"h3"],
    )
    .expect("a client TLS config");
    let transport = Arc::new(TransportConfig::default());
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

/// Returns two pair configs with tickets and a small certificate, whose client sends 0-RTT when it
/// resumes. The first config's server accepts 0-RTT. The second's server shares the first's
/// session tickets and rejects 0-RTT.
fn early_data_configs() -> (PairConfig, PairConfig) {
    let plain = config(true, self_signed());
    let mut client_tls =
        rustls::ClientConfig::clone(plain.client.tls().rustls().expect("a rustls client"));
    client_tls.enable_early_data = true;
    let transport = Arc::new(TransportConfig::default());
    let client = ClientConfig::builder(Arc::new(client_tls))
        .transport(transport.clone())
        .build()
        .expect("a client config");
    let server_tls = plain.server.tls().rustls().expect("a rustls server");
    let server = |accept| {
        ServerConfig::builder(server_tls.clone())
            .transport(transport.clone())
            .accept_early_data(accept)
            .build()
            .expect("a server config")
    };
    let early = |server| PairConfig {
        client: client.clone(),
        server,
        ..plain.clone()
    };
    (early(server(true)), early(server(false)))
}

fn unix_now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test needs one real Instant as the epoch of the pair's virtual clock"
)]
fn epoch() -> Instant {
    Instant::now()
}

/// Returns a pair whose handshake is complete and whose connections have gone quiet.
fn connected(config: PairConfig) -> Pair {
    let mut pair = Pair::new(epoch(), unix_now(), config);
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit));
    pair.run(pair.now + Duration::from_millis(200));
    pair
}

/// Takes `side`'s connection out of the pair and drops it. Returns the bytes that the drop freed:
/// the heap that this connection alone held.
fn held(pair: &mut Pair, side: Side) -> usize {
    let peer = match side {
        Side::Client => &mut pair.client,
        Side::Server => &mut pair.server,
    };
    let conn = peer.conn.take().expect("the peer has a connection");
    let before = live();
    drop(conn);
    before.wrapping_sub(live())
}

/// Prints the census of `scenario` on `side` and checks that it is at most `bound`, plus
/// [`ring_extra`].
fn check(scenario: &str, side: Side, held: usize, bound: usize) {
    let bound = bound + ring_extra(side);
    println!("census {scenario}, {side:?}: {held} bytes held, bound {bound}");
    assert!(
        held > 0,
        "{scenario}, {side:?}: the census did not count the connection's heap"
    );
    assert!(
        held <= bound,
        "{scenario}, {side:?}: {held} bytes held, above the bound of {bound}"
    );
}

/// The applications of both sides. Each reads and consumes every readable byte, and the server
/// answers each request, a bidirectional stream that it has read to the FIN, with [`RESPONSE`]
/// bytes and the FIN.
#[derive(Default)]
struct Apps {
    /// The bytes each side read, by stream: the client's, then the server's.
    read: [BTreeMap<StreamId, usize>; 2],
    /// The streams each side reported closed: the client's, then the server's.
    closed: [Vec<StreamId>; 2],
}

impl Apps {
    fn poll(&mut self, side: Side, conn: &mut Connection) {
        let at = usize::from(side == Side::Server);
        loop {
            let next = conn.readiness().next();
            let Some((id, edge)) = next else {
                return;
            };
            match edge {
                StreamReady::Opened | StreamReady::Readable | StreamReady::Finished => {
                    let mut stream = conn.stream(id).expect("a readable stream is open");
                    let n = stream.readable().chain_length();
                    stream.consume(n).expect("the readable bytes are consumed");
                    *self.read[at].entry(id).or_default() += n;
                    if side == Side::Server && id.dir() == Dir::Bi && edge == StreamReady::Finished
                    {
                        let mut response = Bytes::from_static(&PAYLOAD[..RESPONSE]);
                        assert_eq!(stream.send(&mut response), Ok(RESPONSE));
                        stream.finish().expect("the response ends");
                    }
                }
                StreamReady::Closed => self.closed[at].push(id),
                _ => {}
            }
        }
    }

    /// Checks that the server read the request on `id` and the client its response, and that the
    /// stream closed on both sides while the other streams stayed open.
    fn check_exchange(&self, id: StreamId) {
        let read = [&self.read[1], &self.read[0]].map(|read| read.get(&id).copied());
        assert_eq!(
            read,
            [Some(REQUEST), Some(RESPONSE)],
            "the request and its response"
        );
        assert_eq!(
            self.closed,
            [vec![id], vec![id]],
            "only the request's stream closes, on both sides"
        );
    }

    /// Runs the pair for `duration`, letting both applications act after every step.
    fn run(&mut self, pair: &mut Pair, duration: Duration) {
        let until = pair.now + duration;
        loop {
            pair.step();
            self.poll(Side::Client, pair.client.conn_mut());
            self.poll(Side::Server, pair.server.conn_mut());
            pair.step();
            match pair.next_event() {
                Some(at) if at <= until => {
                    assert!(at > pair.now, "an event at {at:?} did not move on");
                    pair.now = at;
                }
                _ => {
                    pair.now = pair.now.max(until);
                    return;
                }
            }
        }
    }
}

/// Opens a stream from `side` in direction `dir` and sends `len` bytes on it, then the FIN if
/// `fin`. Returns the stream.
fn send(pair: &mut Pair, side: Side, dir: Dir, len: usize, fin: bool) -> StreamId {
    let conn = match side {
        Side::Client => pair.client.conn_mut(),
        Side::Server => pair.server.conn_mut(),
    };
    let id = conn.open_stream(dir, ORDER).expect("a stream opens");
    let mut stream = conn.stream(id).expect("the stream is open");
    let mut data = Bytes::from_static(&PAYLOAD[..len]);
    assert_eq!(stream.send(&mut data), Ok(len));
    if fin {
        stream.finish().expect("the stream ends");
    }
    id
}

/// Runs one request and its response on the pair, as in (b).
fn exchange(pair: &mut Pair) {
    let id = send(pair, Side::Client, Dir::Bi, REQUEST, true);
    let mut apps = Apps::default();
    apps.run(pair, Duration::from_secs(1));
    apps.check_exchange(id);
}

#[test]
fn the_allocator_counts_live_bytes_and_allocations_of_a_page() {
    let (live_before, pages_before) = (live(), pages());
    let counts = || (live().wrapping_sub(live_before), pages() - pages_before);
    let page: Vec<u8> = black_box(Vec::with_capacity(PAGE));
    assert_eq!(counts(), (PAGE, 1), "a page");
    let mut grown: Vec<u8> = black_box(Vec::with_capacity(100));
    assert_eq!(counts(), (PAGE + 100, 1), "a smaller allocation");
    grown.reserve_exact(PAGE);
    assert_eq!(
        counts(),
        (2 * PAGE, 2),
        "a reallocation to the size of a page"
    );
    grown.shrink_to(50);
    assert_eq!(counts(), (PAGE + 50, 2), "a reallocation to a smaller size");
    drop(page);
    drop(grown);
    assert_eq!(counts(), (0, 2), "every byte is freed");
}

#[test]
fn census_of_an_idle_pair_after_a_handshake_without_tickets() {
    let mut pair = connected(config(false, self_signed()));
    println!(
        "census: a Connection takes {} bytes inline, which are not counted",
        size_of::<Connection>()
    );
    let scenario = "(a) idle after a handshake without tickets";
    for (side, bound) in [(Side::Server, IDLE_SERVER), (Side::Client, IDLE_CLIENT)] {
        check(scenario, side, held(&mut pair, side), bound);
    }
}

#[test]
fn census_after_one_request_and_response() {
    let mut pair = connected(config(true, self_signed()));
    let id = send(&mut pair, Side::Client, Dir::Bi, REQUEST, true);
    let mut apps = Apps::default();
    apps.run(&mut pair, Duration::from_secs(1));
    apps.check_exchange(id);
    let scenario = "(b) after one request and response";
    for (side, bound) in [
        (Side::Server, REQUEST_SERVER),
        (Side::Client, REQUEST_CLIENT),
    ] {
        check(scenario, side, held(&mut pair, side), bound);
    }
}

#[test]
fn census_after_an_http3_shaped_flight() {
    let mut pair = connected(config(true, self_signed()));
    // Each side opens its control and QPACK streams, which stay open, and the client sends its
    // request in the same flight.
    let uni = [Side::Client, Side::Server]
        .map(|side| UNI.map(|len| send(&mut pair, side, Dir::Uni, len, false)));
    let id = send(&mut pair, Side::Client, Dir::Bi, REQUEST, true);
    let mut apps = Apps::default();
    apps.run(&mut pair, Duration::from_secs(1));
    // The server reads the client's streams, and the client the server's.
    for (ids, reader) in uni.iter().zip([1, 0]) {
        let read = ids.map(|id| apps.read[reader].get(&id).copied().unwrap_or(0));
        assert_eq!(read, UNI, "the peer reads each unidirectional stream");
    }
    apps.check_exchange(id);
    let scenario = "(c) after an HTTP/3-shaped flight";
    for (side, bound) in [(Side::Server, H3_SERVER), (Side::Client, H3_CLIENT)] {
        check(scenario, side, held(&mut pair, side), bound);
    }
}

#[test]
fn census_of_a_client_after_its_tickets_arrive() {
    let mut pair = connected(config(true, self_signed()));
    let client = held(&mut pair, Side::Client);
    // The next connection resumes, so the client had stored a ticket before it was dropped.
    pair.reconnect();
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit));
    assert_eq!(
        pair.client.conn().tls_info().map(|info| info.resumed),
        Some(true),
        "the next connection resumes"
    );
    let scenario = "(d) idle after the tickets arrive";
    check(scenario, Side::Client, client, TICKETS_CLIENT);
}

#[test]
fn census_of_an_idle_pair_after_a_handshake_with_a_production_size_chain() {
    let identity = production_chain();
    let chain: usize = identity.0.iter().map(|cert| cert.len()).sum();
    println!("census: the production-size chain takes {chain} bytes");
    // A production chain, a server certificate and an intermediate's, takes 3 to 5 KB.
    assert!((3_000..=5_000).contains(&chain), "a chain of {chain} bytes");
    let mut pair = connected(config(false, identity));
    let scenario = "(a) idle after a handshake with a production-size chain";
    for (side, bound) in [
        (Side::Server, CHAIN_IDLE_SERVER),
        (Side::Client, CHAIN_IDLE_CLIENT),
    ] {
        check(scenario, side, held(&mut pair, side), bound);
    }
}

#[test]
fn connections_after_the_first_take_their_receive_pages_from_the_endpoints() {
    let config = config(true, self_signed());
    let before = pages();
    let mut pair = connected(config);
    exchange(&mut pair);
    let mut allocated = vec![pages() - before];
    for _ in 2..=4 {
        let before = pages();
        pair.reconnect();
        let limit = pair.now + LIMIT;
        assert!(pair.handshake(limit));
        pair.run(pair.now + Duration::from_millis(200));
        exchange(&mut pair);
        allocated.push(pages() - before);
    }
    println!("census: receive pages allocated by each of four connections: {allocated:?}");
    assert_eq!(
        allocated[1..],
        [0; 3],
        "connections 2-4 take their STREAM and CRYPTO pages from the pages that connection 1 \
         gave back: {allocated:?}"
    );
    assert_eq!(
        allocated[0], 2,
        "connection 1 allocates one page on each side, which its CRYPTO and STREAM data share"
    );
}

/// Returns a pair whose client resumed with a 0-RTT request that the server rejected, once both
/// sides are quiet after the handshake, and the receive pages allocated since the pair was created.
fn rejected_0rtt() -> (Pair, u64) {
    let (accepting, rejecting) = early_data_configs();
    // The first connection leaves the client a ticket that allows 0-RTT.
    drop(connected(accepting));
    let before = pages();
    let mut pair = Pair::new(epoch(), unix_now(), rejecting);
    send(&mut pair, Side::Client, Dir::Bi, REQUEST, true);
    let limit = pair.now + LIMIT;
    assert!(pair.handshake(limit));
    assert!(
        pair.client
            .has_event(&ConnEvent::EarlyData { accepted: false }),
        "the server rejects the 0-RTT: {:?}",
        pair.client.events
    );
    pair.run(pair.now + Duration::from_millis(200));
    (pair, pages() - before)
}

#[test]
fn a_client_whose_0rtt_was_rejected_takes_its_receive_pages_from_its_endpoint() {
    let (mut pair, _) = rejected_0rtt();
    // Both sides' CRYPTO pages went back to their endpoints' pools during the handshake, so the
    // request and the response take those pages.
    let before = pages();
    exchange(&mut pair);
    assert_eq!(
        pages() - before,
        0,
        "receive pages allocated for a request and its response after a rejected 0-RTT"
    );
}

#[test]
fn a_handshake_whose_0rtt_was_rejected_allocates_one_page_on_each_side() {
    let (_, allocated) = rejected_0rtt();
    assert_eq!(
        allocated, 2,
        "the client's session tickets arrive after its streams are rebuilt for the rejected \
         0-RTT, and take the page of its handshake from the endpoint's pool"
    );
}
