/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Test support: a deterministic in-memory pair harness.
//!
//! A [`Pair`] runs a client and a server, each with its own [`Endpoint`], over two one-way
//! [`Link`]s on a virtual clock. Each link has a one-way delay, an MTU, a drop list or seeded
//! loss, and seeded jitter that reorders datagrams. Datagrams are built into a [`VecSink`],
//! which checks the slot contract of [`SegmentSink`], and sealed by the [`InlineSealer`]. The
//! pair advances from one event (a delivery, a connection deadline or a pacing release) to the
//! next, so a run does not take real time. Not for production use.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;

use crate::ClientConfig;
use crate::ConnEvent;
use crate::ConnKey;
use crate::ConnOptions;
use crate::Connection;
use crate::Ecn;
use crate::Endpoint;
use crate::EndpointConfig;
use crate::InlineSealer;
use crate::Inputs;
use crate::Random;
use crate::Route;
use crate::RxDatagram;
use crate::RxDropReason;
use crate::RxMeta;
use crate::SegmentSink;
use crate::ServerConfig;
use crate::SlotId;
use crate::Stop;
use crate::TxClass;
use crate::TxLimits;
use crate::TxMeta;
use crate::TxOutcome;

/// A seeded random source (SplitMix64): deterministic connection IDs, loss and jitter.
#[derive(Clone, Debug)]
pub struct TestRng(u64);

impl TestRng {
    /// Creates a generator seeded with `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Returns the next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Random for TestRng {
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

/// A datagram a [`VecSink`] took, with the metadata of its run.
#[derive(Clone, Debug)]
pub struct SentDatagram {
    /// The UDP payload.
    pub data: Vec<u8>,
    /// The metadata of the run it was sent in.
    pub meta: TxMeta,
}

/// A `Vec`-backed [`SegmentSink`] that panics on any breach of the slot contract.
#[derive(Debug)]
pub struct VecSink {
    max_datagram: u16,
    refuse: bool,
    slot: Vec<u8>,
    /// The length of the lent slot.
    lent: Option<u16>,
    next_slot: u32,
    run: Vec<Vec<u8>>,
    sent: Vec<SentDatagram>,
    slots_lent: usize,
}

impl VecSink {
    /// Creates a sink for datagrams of up to `max_datagram` bytes.
    pub fn new(max_datagram: u16) -> Self {
        Self {
            max_datagram,
            refuse: false,
            slot: Vec::new(),
            lent: None,
            next_slot: 0,
            run: Vec::new(),
            sent: Vec::new(),
            slots_lent: 0,
        }
    }

    /// Makes the sink refuse every slot, as a backend with an EAGAIN backlog does, or accept
    /// them again.
    pub fn set_refuse(&mut self, refuse: bool) {
        self.refuse = refuse;
    }

    /// Takes the datagrams of every run ended so far.
    pub fn take(&mut self) -> Vec<SentDatagram> {
        std::mem::take(&mut self.sent)
    }

    /// Returns the number of slots lent so far, including abandoned ones.
    pub fn slots_lent(&self) -> usize {
        self.slots_lent
    }
}

impl SegmentSink for VecSink {
    fn next_segment(&mut self, max_len: u16, _class: TxClass) -> Option<(SlotId, &mut [u8])> {
        // Each call abandons a slot that is still lent.
        self.lent = None;
        if self.refuse {
            return None;
        }
        if let Some(first) = self.run.first() {
            assert!(
                usize::from(max_len.min(self.max_datagram)) <= first.len(),
                "asked for a slot larger than the open run's segment size"
            );
        }
        let len = max_len.min(self.max_datagram);
        // Garbage, so a datagram that relies on the slot's old contents shows.
        self.slot.clear();
        self.slot.resize(usize::from(len), 0xa5);
        self.lent = Some(len);
        self.next_slot += 1;
        self.slots_lent += 1;
        Some((SlotId(self.next_slot), &mut self.slot[..]))
    }

    fn end_segment(&mut self, len: u16) {
        let lent = self.lent.take().expect("end_segment without a lent slot");
        if len == 0 {
            return;
        }
        assert!(len <= lent, "segment longer than its slot");
        if let (Some(first), Some(last)) = (self.run.first(), self.run.last()) {
            assert_eq!(
                last.len(),
                first.len(),
                "a segment followed the run's short last segment"
            );
            assert!(
                usize::from(len) <= first.len(),
                "a segment longer than the run's segment size"
            );
        }
        self.run.push(self.slot[..usize::from(len)].to_vec());
    }

    fn end_run(&mut self, meta: TxMeta) {
        assert!(self.lent.is_none(), "end_run with a lent slot");
        assert_eq!(usize::from(meta.segments), self.run.len(), "segment count");
        assert_eq!(
            self.run.first().map(Vec::len),
            Some(usize::from(meta.segment_size)),
            "segment size"
        );
        assert_eq!(
            meta.tx.end - meta.tx.start,
            u64::from(meta.segments),
            "one sequence number per segment"
        );
        assert!(meta.sealed, "unsealed run");
        self.sent
            .extend(self.run.drain(..).map(|data| SentDatagram { data, meta }));
    }
}

impl Drop for VecSink {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.run.is_empty(), "sink dropped with an open run");
        }
    }
}

/// How a link loses datagrams.
#[derive(Clone, Debug, Default)]
pub enum Loss {
    /// It does not lose datagrams.
    #[default]
    None,
    /// It loses the datagrams with these indices, counted from 0 in the order sent.
    Drop(Vec<usize>),
    /// It loses each datagram with probability `per_mille / 1000`.
    Seeded {
        /// The seed.
        seed: u64,
        /// The loss rate in thousandths.
        per_mille: u16,
    },
}

/// One direction of the path.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// The one-way delay.
    pub delay: Duration,
    /// The largest datagram the link carries; larger ones are lost.
    pub mtu: usize,
    /// Which datagrams are lost.
    pub loss: Loss,
    /// Up to this much extra delay per datagram, seeded, which reorders datagrams.
    pub jitter: Duration,
    /// The bottleneck rate in bytes per second: datagrams leave one after another, each after
    /// its serialization time, before the delay. `None`, the default, means instant serialization.
    pub rate: Option<u64>,
    /// With a rate, the most bytes the bottleneck queue holds, the datagram being serialized
    /// included; a datagram that does not fit is lost (drop-tail). `None`, the default, means an
    /// unbounded queue.
    pub buffer: Option<usize>,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            delay: Duration::from_millis(10),
            mtu: 1500,
            loss: Loss::None,
            jitter: Duration::ZERO,
            rate: None,
            buffer: None,
        }
    }
}

/// A one-way link.
#[derive(Debug)]
pub struct Link {
    config: LinkConfig,
    rng: TestRng,
    sent: usize,
    lost: usize,
    reordered: usize,
    /// The highest send index delivered so far.
    newest_delivered: Option<usize>,
    in_flight: Vec<(Instant, usize, Vec<u8>)>,
    /// When the bottleneck finishes serializing the datagrams it has taken.
    busy_until: Option<Instant>,
}

impl Link {
    /// Creates a link with `config`, seeded by [`Loss::Seeded`]'s seed if present, else by `seed`.
    pub fn new(config: LinkConfig, seed: u64) -> Self {
        let seed = match config.loss {
            Loss::Seeded { seed, .. } => seed,
            Loss::None | Loss::Drop(_) => seed,
        };
        Self {
            config,
            rng: TestRng::new(seed),
            sent: 0,
            lost: 0,
            reordered: 0,
            newest_delivered: None,
            in_flight: Vec::new(),
            busy_until: None,
        }
    }

    /// Sends a datagram at `now`.
    pub fn send(&mut self, now: Instant, data: Vec<u8>) {
        let index = self.sent;
        self.sent += 1;
        let lost = data.len() > self.config.mtu
            || match &self.config.loss {
                Loss::None => false,
                Loss::Drop(indices) => indices.contains(&index),
                Loss::Seeded { per_mille, .. } => {
                    self.rng.next_u64() % 1000 < u64::from(*per_mille)
                }
            };
        if lost {
            self.lost += 1;
            return;
        }
        let mut leaves = now;
        if let Some(rate) = self.config.rate {
            let queued = self
                .busy_until
                .map_or(0, |busy| busy.saturating_duration_since(now).as_nanos())
                * u128::from(rate)
                / 1_000_000_000;
            if let Some(buffer) = self.config.buffer
                && queued + data.len() as u128 > buffer as u128
            {
                self.lost += 1;
                return;
            }
            let start = self.busy_until.map_or(now, |busy| busy.max(now));
            let nanos = data.len() as u128 * 1_000_000_000 / u128::from(rate);
            leaves = start + Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
            self.busy_until = Some(leaves);
        }
        let jitter_nanos = u64::try_from(self.config.jitter.as_nanos()).unwrap_or(u64::MAX);
        let jitter = if jitter_nanos == 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(self.rng.next_u64() % jitter_nanos)
        };
        self.in_flight
            .push((leaves + self.config.delay + jitter, index, data));
    }

    /// Changes which datagrams the link loses from now on; [`Loss::Drop`] indices still count
    /// from the first datagram sent.
    pub fn set_loss(&mut self, loss: Loss) {
        self.config.loss = loss;
    }

    /// Returns when the next datagram arrives.
    pub fn next_arrival(&self) -> Option<Instant> {
        self.in_flight.iter().map(|(at, _, _)| *at).min()
    }

    /// Takes the datagrams that have arrived by `now`, in arrival order.
    pub fn deliver(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let (mut due, waiting) = std::mem::take(&mut self.in_flight)
            .into_iter()
            .partition::<Vec<_>, _>(|(at, _, _)| *at <= now);
        self.in_flight = waiting;
        due.sort_by_key(|(at, index, _)| (*at, *index));
        due.into_iter()
            .map(|(_, index, data)| {
                if self.newest_delivered.is_some_and(|newest| index < newest) {
                    self.reordered += 1;
                }
                self.newest_delivered = self.newest_delivered.max(Some(index));
                data
            })
            .collect()
    }

    /// Returns the number of datagrams sent into the link.
    pub fn sent(&self) -> usize {
        self.sent
    }

    /// Returns the number of datagrams the link lost.
    pub fn lost(&self) -> usize {
        self.lost
    }

    /// Returns the number of datagrams delivered after one sent later than them.
    pub fn reordered(&self) -> usize {
        self.reordered
    }
}

/// One side of a [`Pair`].
#[derive(Debug)]
pub struct Peer {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// The connection, once connected or accepted.
    pub conn: Option<Connection>,
    /// The connection's slab key.
    pub key: ConnKey,
    /// The address.
    pub addr: SocketAddr,
    /// Every connection event, in order.
    pub events: Vec<ConnEvent>,
    /// Every datagram sent, with the time it was sent.
    pub sent: Vec<(Instant, SentDatagram)>,
    /// Every attempt's outcome.
    pub outcomes: Vec<TxOutcome>,
    /// Datagrams the endpoint dropped, and why.
    pub drops: Vec<RxDropReason>,
    /// The sink.
    pub sink: VecSink,
    rng: TestRng,
}

impl Peer {
    fn new(endpoint: Endpoint, addr: SocketAddr, index: u32, max_datagram: u16, seed: u64) -> Self {
        Self {
            endpoint,
            conn: None,
            key: ConnKey {
                index,
                generation: 1,
            },
            addr,
            events: Vec::new(),
            sent: Vec::new(),
            outcomes: Vec::new(),
            drops: Vec::new(),
            sink: VecSink::new(max_datagram),
            rng: TestRng::new(seed),
        }
    }

    /// Returns the connection. Panics if the peer does not have one.
    pub fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("the peer has a connection")
    }

    /// Returns the connection mutably. Panics if the peer does not have one.
    pub fn conn_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("the peer has a connection")
    }

    /// Returns whether the connection reported `event`.
    pub fn has_event(&self, event: &ConnEvent) -> bool {
        self.events.contains(event)
    }
}

/// What a [`Pair`] runs with.
#[derive(Clone, Debug)]
pub struct PairConfig {
    /// The client's config.
    pub client: Arc<ClientConfig>,
    /// The server's config.
    pub server: Arc<ServerConfig>,
    /// The endpoints' config.
    pub endpoint: Arc<EndpointConfig>,
    /// The client endpoint's config, when it differs from `endpoint`.
    pub client_endpoint: Option<Arc<EndpointConfig>>,
    /// The client-to-server link.
    pub to_server: LinkConfig,
    /// The server-to-client link.
    pub to_client: LinkConfig,
    /// [`TxLimits::max_datagram`] of both sides.
    pub max_datagram: u16,
    /// [`TxLimits::max_segments`] of both sides.
    pub max_segments: u16,
    /// The seed of the connection IDs, loss and jitter.
    pub seed: u64,
}

impl PairConfig {
    /// Creates a config with lossless default links of 10 ms each way and a 1,500-byte MTU.
    pub fn new(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        endpoint: Arc<EndpointConfig>,
    ) -> Self {
        Self {
            client,
            server,
            endpoint,
            client_endpoint: None,
            to_server: LinkConfig::default(),
            to_client: LinkConfig::default(),
            max_datagram: 1500,
            max_segments: 16,
            seed: 1,
        }
    }
}

/// A client and a server connected by two links on a virtual clock.
#[derive(Debug)]
pub struct Pair {
    /// The virtual time.
    pub now: Instant,
    /// The client.
    pub client: Peer,
    /// The server.
    pub server: Peer,
    /// The client-to-server link.
    pub to_server: Link,
    /// The server-to-client link.
    pub to_client: Link,
    config: PairConfig,
    unix_now: UnixTime,
}

/// The number of rounds after which a step still making progress at one instant is a livelock.
const MAX_STEPS_PER_INSTANT: usize = 10_000;

impl Pair {
    /// Creates the endpoints at `epoch` and starts the client's connection.
    pub fn new(epoch: Instant, unix_now: UnixTime, config: PairConfig) -> Self {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4433);
        let client_endpoint = Endpoint::new(
            config
                .client_endpoint
                .clone()
                .unwrap_or_else(|| config.endpoint.clone()),
            None,
        );
        let server_endpoint = Endpoint::new(config.endpoint.clone(), Some(config.server.clone()));
        let mut pair = Self {
            now: epoch,
            client: Peer::new(
                client_endpoint,
                client_addr,
                1,
                config.max_datagram,
                config.seed,
            ),
            server: Peer::new(
                server_endpoint,
                server_addr,
                2,
                config.max_datagram,
                config.seed.wrapping_add(1),
            ),
            to_server: Link::new(config.to_server.clone(), config.seed.wrapping_add(2)),
            to_client: Link::new(config.to_client.clone(), config.seed.wrapping_add(3)),
            config,
            unix_now,
        };
        let client = &mut pair.client;
        let mut cx = Inputs {
            now: epoch,
            unix_now,
            rng: &mut client.rng,
        };
        let conn = client
            .endpoint
            .connect(
                &mut cx,
                client.key,
                server_addr,
                ServerName::try_from("localhost").expect("a valid DNS name"),
                &pair.config.client,
                ConnOptions::default(),
            )
            .expect("the client config creates a connection");
        client.conn = Some(conn);
        pair
    }

    /// Returns the limits of an attempt at the current time.
    pub fn limits(&self) -> TxLimits {
        TxLimits {
            now: self.now,
            max_segments: self.config.max_segments,
            max_datagram: self.config.max_datagram,
            max_bytes: u32::MAX,
        }
    }

    /// Runs the deliveries, deadlines, transmit attempts and events due at the current time,
    /// round after round, until a round does not make progress. Panics on a livelock.
    pub fn step(&mut self) {
        for _ in 0..MAX_STEPS_PER_INSTANT {
            let mut progress = self.deliver_to_server();
            progress |= self.deliver_to_client();
            for side in [Side::Client, Side::Server] {
                progress |= self.fire_deadline(side);
                progress |= self.transmit(side);
                self.collect_events(side);
            }
            if !progress {
                return;
            }
        }
        panic!("no quiescence at {:?}", self.now);
    }

    /// Returns the time of the next event: a delivery, a connection deadline or a pacing release.
    pub fn next_event(&self) -> Option<Instant> {
        let deadlines = [&self.client, &self.server]
            .into_iter()
            .filter_map(|peer| peer.conn.as_ref()?.next_deadline());
        let releases = [&self.client, &self.server]
            .into_iter()
            .filter_map(|peer| peer.outcomes.last()?.pacing_at);
        [self.to_server.next_arrival(), self.to_client.next_arrival()]
            .into_iter()
            .flatten()
            .chain(deadlines)
            .chain(releases)
            .min()
    }

    /// Steps from event to event until `done` holds or the next event is later than `limit`;
    /// returns whether `done` held.
    pub fn run_until(&mut self, limit: Instant, mut done: impl FnMut(&Pair) -> bool) -> bool {
        loop {
            self.step();
            if done(self) {
                return true;
            }
            match self.next_event() {
                Some(at) if at <= limit => {
                    assert!(at > self.now, "an event at {at:?} did not move on");
                    self.now = at;
                }
                _ => {
                    self.now = self.now.max(limit);
                    return false;
                }
            }
        }
    }

    /// Runs until the pair runs out of events or `limit` passes.
    pub fn run(&mut self, limit: Instant) {
        self.run_until(limit, |_| false);
    }

    /// Runs until both sides have reported `Confirmed` or `limit` passes, and returns whether
    /// they did.
    pub fn handshake(&mut self, limit: Instant) -> bool {
        self.run_until(limit, |pair| {
            pair.client.has_event(&ConnEvent::Confirmed)
                && pair.server.has_event(&ConnEvent::Confirmed)
        })
    }

    fn peer(&mut self, side: Side) -> &mut Peer {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    fn deliver_to_server(&mut self) -> bool {
        let datagrams = self.to_server.deliver(self.now);
        if datagrams.is_empty() {
            return false;
        }
        let (now, unix_now) = (self.now, self.unix_now);
        let src = self.client.addr;
        let server_config = self.config.server.clone();
        let peer = &mut self.server;
        let mut batch = Vec::new();
        for data in datagrams {
            let meta = rx_meta(src, peer.addr, now, data.len());
            match peer.endpoint.route(now, &meta, &data) {
                Route::Existing(key) if key == peer.key => batch.push(data),
                Route::Accept(incoming) if peer.conn.is_none() => {
                    let mut cx = Inputs {
                        now,
                        unix_now,
                        rng: &mut peer.rng,
                    };
                    let conn = peer
                        .endpoint
                        .accept(
                            &mut cx,
                            peer.key,
                            incoming,
                            &server_config,
                            ConnOptions::default(),
                        )
                        .expect("the server accepts the Initial");
                    peer.conn = Some(conn);
                }
                Route::Stateless(reply) => self.to_client.send(now, reply.datagram().to_vec()),
                Route::Drop(reason) => peer.drops.push(reason),
                Route::Existing(_) | Route::Accept(_) => {
                    peer.drops.push(RxDropReason::UnknownConnection)
                }
            }
        }
        recv(peer, now, src, batch);
        true
    }

    fn deliver_to_client(&mut self) -> bool {
        let datagrams = self.to_client.deliver(self.now);
        if datagrams.is_empty() {
            return false;
        }
        let now = self.now;
        let src = self.server.addr;
        let peer = &mut self.client;
        let mut batch = Vec::new();
        for data in datagrams {
            let meta = rx_meta(src, peer.addr, now, data.len());
            match peer.endpoint.route(now, &meta, &data) {
                Route::Existing(key) if key == peer.key => batch.push(data),
                Route::Drop(reason) => peer.drops.push(reason),
                _ => peer.drops.push(RxDropReason::UnknownConnection),
            }
        }
        recv(peer, now, src, batch);
        true
    }

    fn fire_deadline(&mut self, side: Side) -> bool {
        let now = self.now;
        let Some(conn) = self.peer(side).conn.as_mut() else {
            return false;
        };
        if conn.next_deadline().is_some_and(|at| at <= now) {
            conn.on_deadline(now);
            return true;
        }
        false
    }

    fn transmit(&mut self, side: Side) -> bool {
        let limits = self.limits();
        let now = self.now;
        let peer = self.peer(side);
        let Some(conn) = peer.conn.as_mut() else {
            return false;
        };
        loop {
            let outcome = conn.poll_transmit(&limits, &mut peer.sink, &mut InlineSealer);
            peer.outcomes.push(outcome);
            if outcome.stop != Stop::BatchFull {
                break;
            }
        }
        let datagrams = peer.sink.take();
        let sent = !datagrams.is_empty();
        let (peer, link, to) = match side {
            Side::Client => (&mut self.client, &mut self.to_server, self.server.addr),
            Side::Server => (&mut self.server, &mut self.to_client, self.client.addr),
        };
        for datagram in datagrams {
            // A datagram to an address the other peer no longer has is lost.
            if datagram.meta.dst == to {
                link.send(now, datagram.data.clone());
            }
            peer.sent.push((now, datagram));
        }
        sent
    }

    fn collect_events(&mut self, side: Side) {
        let peer = self.peer(side);
        let Some(conn) = peer.conn.as_mut() else {
            return;
        };
        while let Some(event) = conn.poll_event() {
            peer.events.push(event);
        }
        while let Some(event) = conn.poll_endpoint_event() {
            peer.endpoint.handle_event(peer.key, event);
        }
    }
}

/// Which side of a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

fn rx_meta(src: SocketAddr, dst: SocketAddr, now: Instant, len: usize) -> RxMeta {
    RxMeta {
        src,
        dst_ip: Some(dst.ip()),
        ecn: Ecn::NotEct,
        stride: u16::try_from(len).unwrap_or(u16::MAX),
        rx_time: now,
    }
}

/// Hands one receive batch to the peer's connection.
fn recv(peer: &mut Peer, now: Instant, src: SocketAddr, mut batch: Vec<Vec<u8>>) {
    let Some(conn) = peer.conn.as_mut() else {
        return;
    };
    if batch.is_empty() {
        return;
    }
    let metas: Vec<RxMeta> = batch
        .iter()
        .map(|data| rx_meta(src, peer.addr, now, data.len()))
        .collect();
    let mut datagrams: Vec<RxDatagram<'_>> = batch
        .iter_mut()
        .zip(&metas)
        .map(|(data, meta)| RxDatagram { meta, data })
        .collect();
    conn.recv_batch(now, &mut datagrams);
}

/// Configs for tests: a self-signed certificate, rustls configs, and pair configs.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Arc;
    use std::time::Duration;

    use mvfstr_tls::ManualTimeProvider;
    use mvfstr_tls::ServerVerification;
    use mvfstr_wire::Version;
    use rustls::NamedGroup;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::UnixTime;

    use super::PairConfig;
    use crate::AlpnPolicy;
    use crate::ClientConfig;
    use crate::EndpointConfig;
    use crate::ServerConfig;
    use crate::TransportConfig;

    /// Returns the server's fixed Ed25519 key. Ed25519 signatures have a fixed length and are
    /// deterministic, so the certificate is the same in every run and handshakes from one setup
    /// send the same sizes.
    fn server_key() -> PrivatePkcs8KeyDer<'static> {
        // RFC 8410: a PKCS #8 v1 document with the id-Ed25519 algorithm around the seed.
        const PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let seed = b"mvfstr pair harness test key 001";
        PrivatePkcs8KeyDer::from([&PREFIX[..], &seed[..]].concat())
    }

    /// Returns the fixed Unix time that the tests use as the wall clock.
    pub(crate) fn unix_now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000))
    }

    /// Returns mvfstr_crypto's provider with the key exchange groups of [`with_groups`].
    fn provider(pq: bool) -> CryptoProvider {
        with_groups(mvfstr_crypto::default_provider(), pq)
    }

    /// Puts X25519MLKEM768 first with `pq`, so that the ClientHello takes two Initial packets,
    /// and otherwise keeps X25519 only. Only aws-lc-rs has X25519MLKEM768.
    fn with_groups(mut provider: CryptoProvider, pq: bool) -> CryptoProvider {
        if pq {
            provider
                .kx_groups
                .sort_by_key(|group| group.name() != NamedGroup::X25519MLKEM768);
        } else {
            provider
                .kx_groups
                .retain(|group| group.name() == NamedGroup::X25519);
        }
        provider
    }

    /// What differs between the pairs the tests run.
    #[derive(Clone, Debug)]
    pub(crate) struct Setup {
        pub(crate) pq: bool,
        /// The client's versions; it offers the first.
        pub(crate) client_versions: Vec<Version>,
        /// The server's versions, which must include version 1.
        pub(crate) server_versions: Vec<Version>,
        pub(crate) client_transport: Arc<TransportConfig>,
        pub(crate) server_transport: Arc<TransportConfig>,
        pub(crate) client_alpn: &'static [&'static [u8]],
        pub(crate) server_alpn: &'static [&'static [u8]],
        /// The ALPN policy of both sides.
        pub(crate) alpn: AlpnPolicy,
        /// The number of names in the server's certificate, which sets its size.
        pub(crate) cert_names: usize,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                pq: false,
                client_versions: vec![Version::V1],
                server_versions: vec![Version::V1],
                client_transport: Arc::new(TransportConfig::default()),
                server_transport: Arc::new(TransportConfig::default()),
                client_alpn: &[b"h3"],
                server_alpn: &[b"h3"],
                alpn: AlpnPolicy::Required,
                cert_names: 1,
            }
        }
    }

    impl Setup {
        /// Gives both sides `transport`.
        pub(crate) fn transport(mut self, transport: Arc<TransportConfig>) -> Self {
            self.client_transport = transport.clone();
            self.server_transport = transport;
            self
        }

        /// Builds the pair config.
        pub(crate) fn pair(&self) -> PairConfig {
            let names = std::iter::once("localhost".to_owned())
                .chain((1..self.cert_names).map(|i| format!("host-{i:04}.a-rather-long-name.test")))
                .collect::<Vec<_>>();
            let key = server_key();
            let signing_key =
                rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
                    .expect("rcgen takes the Ed25519 key");
            let cert = rcgen::CertificateParams::new(names)
                .and_then(|params| params.self_signed(&signing_key))
                .expect("rcgen makes a certificate");
            let time = Arc::new(ManualTimeProvider::new(unix_now()));
            let server_tls = mvfstr_tls::server_config(
                provider(self.pq),
                time.clone(),
                vec![cert.der().clone()],
                key.clone_key().into(),
                self.server_alpn,
            )
            .expect("a server TLS config");
            let client_tls = mvfstr_tls::client_config(
                provider(self.pq),
                time,
                ServerVerification::AcceptAnyCertificate,
                self.client_alpn,
            )
            .expect("a client TLS config");
            let server = ServerConfig::builder(Arc::new(server_tls))
                .transport(self.server_transport.clone())
                .versions(self.server_versions.clone())
                .alpn(self.alpn)
                .build()
                .expect("a server config");
            let client = ClientConfig::builder(Arc::new(client_tls))
                .transport(self.client_transport.clone())
                .versions(self.client_versions.clone())
                .alpn(self.alpn)
                .build()
                .expect("a client config");
            let endpoint = EndpointConfig::builder([7; 32])
                .build()
                .expect("an endpoint config");
            PairConfig::new(client, server, endpoint)
        }
    }

    #[cfg(feature = "aws-lc-rs")]
    mod tests {
        use super::*;

        fn group_names(provider: &CryptoProvider) -> Vec<NamedGroup> {
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect()
        }

        #[test]
        fn post_quantum_pairs_put_x25519mlkem768_first_whatever_the_providers_order() {
            // rustls's aws-lc-rs provider puts it last when its prefer-post-quantum feature is off.
            let mut provider = mvfstr_crypto::default_provider();
            provider
                .kx_groups
                .sort_by_key(|group| group.name() == NamedGroup::X25519MLKEM768);
            assert_eq!(
                group_names(&provider).last(),
                Some(&NamedGroup::X25519MLKEM768)
            );

            let pq = group_names(&with_groups(provider.clone(), true));
            assert_eq!(pq.first(), Some(&NamedGroup::X25519MLKEM768), "{pq:?}");
            assert_eq!(
                group_names(&with_groups(provider, false)),
                [NamedGroup::X25519]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::test_epoch;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn a_link_with_a_rate_serializes_datagrams_one_after_another() {
        let t0 = test_epoch();
        let config = LinkConfig {
            rate: Some(1_000_000),
            ..LinkConfig::default()
        };
        let mut link = Link::new(config, 1);
        for _ in 0..3 {
            link.send(t0, vec![0; 1000]);
        }
        // 1 ms each at 1,000,000 bytes per second, then the 10 ms delay.
        assert_eq!(link.next_arrival(), Some(t0 + 11 * MS));
        assert_eq!(link.deliver(t0 + 12 * MS).len(), 2);
        assert_eq!(link.next_arrival(), Some(t0 + 13 * MS));
        // An idle bottleneck starts the next datagram at once.
        link.send(t0 + 20 * MS, vec![0; 500]);
        assert_eq!(link.deliver(t0 + 13 * MS).len(), 1);
        assert_eq!(
            link.next_arrival(),
            Some(t0 + 30 * MS + Duration::from_micros(500))
        );
    }

    #[test]
    fn a_full_bottleneck_buffer_drops_the_datagrams_that_do_not_fit() {
        let t0 = test_epoch();
        let config = LinkConfig {
            rate: Some(1_000_000),
            buffer: Some(2_500),
            ..LinkConfig::default()
        };
        let mut link = Link::new(config, 1);
        for _ in 0..4 {
            link.send(t0, vec![0; 1000]);
        }
        // Two fit; the third would make 3,000 bytes.
        assert_eq!(link.lost(), 2);
        // Half a millisecond later 1,500 bytes are left, and another 1,000 fit.
        link.send(t0 + Duration::from_micros(500), vec![0; 1000]);
        assert_eq!(link.lost(), 2);
        link.send(t0 + Duration::from_micros(500), vec![0; 1]);
        assert_eq!(link.lost(), 3);
        assert_eq!(link.deliver(t0 + 20 * MS).len(), 3);
    }
}
