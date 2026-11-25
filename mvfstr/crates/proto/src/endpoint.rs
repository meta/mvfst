/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The endpoint: connection ID routing, connection creation and stateless replies.
//!
//! An [`Endpoint`] maps destination connection IDs to [`ConnKey`]s, recognizes Initials that
//! start new connections, creates connections, and produces stateless replies (Version
//! Negotiation, stateless reset, refusals). It does not own the connections: the driver keeps
//! them in a slab indexed by [`ConnKey`], and connections report routing changes as
//! [`EndpointEvent`]s instead of calling the endpoint.
//!
//! With several workers on one address, every issued connection ID names its worker, and a
//! short-header packet for an unknown ID of another worker is dropped as
//! [`RxDropReason::OtherWorker`] rather than reset, since that worker may still serve the
//! connection and a reset would end it. The endpoint does not forward datagrams between workers.
//! With the driver's steering, the kernel delivers each packet to the worker its ID names, and the
//! driver hands a new connection's first Initial, whose ID the client picked, to the worker it
//! chooses. The endpoint does not route datagrams to takeover predecessors, buffer 0-RTT packets
//! or send Retry.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_crypto::InlineSealer;
use mvfstr_crypto::SealJob;
use mvfstr_crypto::Sealer;
use mvfstr_crypto::SlotId;
use mvfstr_crypto::TAG_LEN;
use mvfstr_tls::TlsError;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Frame;
use mvfstr_wire::Header;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::PacketType;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::ResetToken;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use mvfstr_wire::encode_version_negotiation;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;

use crate::ClientConfig;
use crate::ConnOptions;
use crate::Connection;
use crate::EndpointConfig;
use crate::EndpointEvent;
use crate::RxDatagram;
use crate::RxMeta;
use crate::ServerConfig;
use crate::cid::CidGenerator;
use crate::connection::ConnSetup;
use crate::connection::DatagramPool;
use crate::connection::MIN_DATAGRAM;

/// The driver's slab key of a connection: its slot index and the slot's generation, so a stale
/// key never reaches a newer connection in the same slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    /// The slot index.
    pub index: u32,
    /// The slot's generation when the connection was created.
    pub generation: u32,
}

/// A source of random bytes, supplied by the caller. Production drivers use a CSPRNG; tests use
/// a seeded generator.
pub trait Random {
    /// Fills `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]);
}

/// The inputs of operations that create state: the time and a random source.
#[derive(Debug)]
pub struct Inputs<'a, R: Random> {
    /// The current monotonic time.
    pub now: Instant,
    /// The current Unix time, which rustls reads for certificate validity.
    pub unix_now: UnixTime,
    /// The random source; it seeds the new connection's own generator.
    pub rng: &'a mut R,
}

/// Where a received datagram goes, from [`Endpoint::route`].
#[derive(Debug)]
pub enum Route {
    /// To the existing connection with this key.
    Existing(ConnKey),
    /// It is an Initial for an unknown connection ID: the driver applies admission and calls
    /// [`Endpoint::accept`] or [`Endpoint::refuse`].
    Accept(Incoming),
    /// Answer statelessly and drop it.
    Stateless(StatelessReply),
    /// Drop it.
    Drop(RxDropReason),
}

/// Why [`Endpoint::route`] dropped a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxDropReason {
    /// The datagram is not a well-formed QUIC packet.
    Malformed,
    /// A packet for an unknown connection that does not get a stateless reset: a long header, or a
    /// short header too small for a reset or with a zero-length connection ID.
    UnknownConnection,
    /// An Initial in a datagram smaller than 1200 bytes, which RFC 9000 requires a server to drop.
    ShortInitial,
    /// A long-header packet of a version we do not accept, too small for Version Negotiation.
    UnsupportedVersion,
    /// A new connection, but the endpoint does not have a server config.
    NotListening,
    /// A stateless reply was due, but the rate limit refused it.
    RateLimited,
    /// A short-header packet for an unknown connection ID that names another worker.
    OtherWorker,
    /// A datagram for an unknown connection from a source port on the endpoint's
    /// [`SrcPortBlocklist`].
    InvalidSrcPort,
}

/// The source ports a server does not accept connections from or move connections to: every port
/// below a bound, and a sorted list of others. The endpoint checks the list before it routes a
/// datagram for an unknown connection, and a server connection checks it when its peer's address
/// changes, so a connection accepted before an update keeps its port. mvfst servers block such
/// ports, typically those of well-known services, so that a spoofed source address cannot aim their
/// replies at a service.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SrcPortBlocklist {
    below: u16,
    select: Box<[u16]>,
}

impl SrcPortBlocklist {
    /// Returns a list that blocks every port below `below` and each port in `select`.
    pub fn new(below: u16, select: impl IntoIterator<Item = u16>) -> Self {
        let mut select: Vec<u16> = select.into_iter().filter(|&port| port >= below).collect();
        select.sort_unstable();
        select.dedup();
        Self {
            below,
            select: select.into(),
        }
    }

    /// Returns whether `port` is blocked.
    pub fn blocks(&self, port: u16) -> bool {
        port < self.below || self.select.binary_search(&port).is_ok()
    }
}

/// The source port blocklist an endpoint has in force and the count of datagrams dropped under it.
/// Each server connection the endpoint accepts shares it and checks it when its peer's address
/// changes, so a list posted after the accept applies to that connection too.
#[derive(Debug, Default)]
pub(crate) struct SrcPortState {
    list: Mutex<Option<Arc<SrcPortBlocklist>>>,
    drops: AtomicU64,
}

impl SrcPortState {
    /// Returns whether the list in force blocks `port`, and counts the datagram from it as
    /// dropped if so.
    pub(crate) fn refuses(&self, port: u16) -> bool {
        let blocked = self
            .list
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|list| list.blocks(port));
        if blocked {
            self.count_drop();
        }
        blocked
    }

    fn set(&self, blocklist: Option<Arc<SrcPortBlocklist>>) {
        *self.list.lock().unwrap_or_else(PoisonError::into_inner) = blocklist;
    }

    fn count_drop(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

/// A handle, from [`Endpoint::src_port_drops`], to the count of datagrams an endpoint dropped for
/// their source port: those dropped as [`RxDropReason::InvalidSrcPort`], and those that would have
/// moved one of its server connections to a blocked port. [`get`](Self::get) reads the live count,
/// also while the endpoint is in use.
#[derive(Clone, Debug)]
pub struct SrcPortDrops(Arc<SrcPortState>);

impl SrcPortDrops {
    /// Returns the count.
    pub fn get(&self) -> u64 {
        self.0.drops.load(Ordering::Relaxed)
    }
}

/// An Initial that may start a connection, from [`Route::Accept`]. It holds what
/// [`Endpoint::accept`] needs, including a copy of the datagram.
pub struct Incoming {
    meta: RxMeta,
    version: Version,
    /// The Initial's Destination Connection ID, chosen by the client.
    dcid: ConnectionId,
    /// The Initial's Source Connection ID: the client's connection ID.
    scid: ConnectionId,
    datagram: Vec<u8>,
}

impl Incoming {
    /// Returns the client's address.
    pub fn remote_address(&self) -> SocketAddr {
        self.meta.src
    }

    /// Returns the local address the Initial was sent to, when the socket reports it.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.meta.dst_ip
    }

    /// Returns the version the client offered.
    pub fn version(&self) -> Version {
        self.version
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("remote", &self.meta.src)
            .field("version", &self.version)
            .field("len", &self.datagram.len())
            .finish_non_exhaustive()
    }
}

/// What a stateless reply is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatelessKind {
    /// A Version Negotiation packet (RFC 9000).
    VersionNegotiation,
    /// A stateless reset (RFC 9000).
    Reset,
    /// An Initial carrying CONNECTION_CLOSE, refusing a connection.
    Refusal,
    /// "OK", the answer to the endpoint's health check token.
    HealthCheck,
}

/// A datagram to send without a connection.
#[derive(Clone)]
pub struct StatelessReply {
    dst: SocketAddr,
    src_ip: Option<IpAddr>,
    kind: StatelessKind,
    datagram: Bytes,
}

impl StatelessReply {
    /// Returns the address to send it to.
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }

    /// Returns the local address to send it from: the address the trigger was sent to.
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.src_ip
    }

    /// Returns what kind of reply it is.
    pub fn kind(&self) -> StatelessKind {
        self.kind
    }

    /// Returns the UDP payload.
    pub fn datagram(&self) -> &[u8] {
        &self.datagram
    }
}

impl fmt::Debug for StatelessReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessReply")
            .field("dst", &self.dst)
            .field("kind", &self.kind)
            .field("len", &self.datagram.len())
            .finish_non_exhaustive()
    }
}

/// Why [`Endpoint::accept`] failed. The Initial is dropped.
#[derive(Debug)]
pub enum AcceptError {
    /// rustls refused to create the server session.
    Tls(rustls::Error),
    /// A connection ID of the Initial is already routed to another connection.
    CidInUse(ConnectionId),
    /// The endpoint did not find an unused connection ID of the configured length: with
    /// zero-length IDs it already has a connection, or the random source keeps repeating itself.
    NoConnectionId,
    /// The Initial's datagram did not hold a packet that opens with the Initial keys derived from
    /// its Destination Connection ID.
    Undecryptable,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(error) => write!(f, "TLS session creation failed: {error}"),
            Self::CidInUse(cid) => write!(f, "connection ID {cid} is already in use"),
            Self::NoConnectionId => f.write_str("no unused connection ID"),
            Self::Undecryptable => f.write_str("the Initial does not decrypt"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Why [`Endpoint::connect`] failed. The endpoint did not create a connection.
#[derive(Debug)]
pub enum ConnectError {
    /// rustls refused to create the client session.
    Tls(rustls::Error),
    /// The remote address is unspecified or has port 0.
    InvalidRemoteAddress(SocketAddr),
    /// The endpoint did not find an unused connection ID of the configured length: with
    /// zero-length IDs it already has a connection, or the random source keeps repeating itself.
    NoConnectionId,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(error) => write!(f, "TLS session creation failed: {error}"),
            Self::InvalidRemoteAddress(remote) => write!(f, "invalid remote address {remote}"),
            Self::NoConnectionId => f.write_str("no unused connection ID"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Connection ID routing and connection creation for one set of sockets.
pub struct Endpoint {
    config: Arc<EndpointConfig>,
    server: Option<Arc<ServerConfig>>,
    /// The connection IDs routed to each connection: its own and, for a server, the client's
    /// first Destination Connection ID, which the client's Initials carry until it receives the
    /// server's.
    routes: HashMap<ConnectionId, ConnKey>,
    /// The IDs routed to each connection, removed together when it drains.
    by_key: HashMap<ConnKey, Vec<ConnectionId>>,
    /// The stateless reset tokens of the peer connection IDs each connection sends with, keyed
    /// by the address it sends to under each and the token, so that a reset reaches its
    /// connection.
    peer_tokens: HashMap<(SocketAddr, ResetToken), ConnKey>,
    /// The entries of `peer_tokens` for each connection: its current path's and its alternate
    /// path's.
    token_of: HashMap<ConnKey, [Option<(SocketAddr, ResetToken)>; 2]>,
    cids: CidGenerator,
    limiter: ReplyLimiter,
    /// The longest the backend holds a datagram until its release; zero without release
    /// support.
    release_horizon: Duration,
    /// The source port blocklist in force, which `route` checks once both lookups miss.
    src_ports: Option<Arc<SrcPortBlocklist>>,
    /// The same list and the drop count, shared with the server connections, which check the list
    /// when their peer moves.
    shared_src_ports: Arc<SrcPortState>,
    /// How many host IDs the endpoint truncated to 24 bits.
    host_id_truncations: u64,
    /// Spare buffers for the packets its connections keep until their keys arrive.
    pool: DatagramPool,
}

/// A token bucket for stateless replies: RFC 9000 lets a server limit the Version Negotiation
/// packets it sends, and stateless resets and refusals share the budget.
#[derive(Clone, Copy, Debug, Default)]
struct ReplyLimiter {
    tokens: u32,
    last: Option<Instant>,
}

impl ReplyLimiter {
    /// The replies that may go out at once.
    const BURST: u32 = 64;

    /// Takes a token, refilled at one per millisecond.
    fn allow(&mut self, now: Instant) -> bool {
        let refill = self.last.map_or(Self::BURST, |last| {
            u32::try_from(now.saturating_duration_since(last).as_millis()).unwrap_or(u32::MAX)
        });
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(Self::BURST);
            self.last = Some(now);
        }
        let Some(left) = self.tokens.checked_sub(1) else {
            return false;
        };
        self.tokens = left;
        true
    }
}

/// The version that mvfst lists alone in Version Negotiation to refuse a connection; endpoints do
/// not support it.
pub const MVFST_INVALID: Version = Version(0xface_b00f);

/// The datagram a server answers its health check token with.
pub(crate) const HEALTH_CHECK_ANSWER: &[u8] = b"OK";

/// How many random connection IDs to try before giving up; only zero-length IDs or a broken
/// random source get there.
pub(crate) const CID_ATTEMPTS: usize = 16;

/// The shortest stateless reset (RFC 9000): five bytes that look like a short header, then the
/// token.
pub(crate) const MIN_RESET: usize = 21;
/// The longest stateless reset sent: one byte shorter than a trigger of up to 44 bytes. RFC 9000
/// recommends that for triggers of up to 43 bytes.
const MAX_RESET: usize = 43;

impl Endpoint {
    /// Creates an endpoint. With a server config it accepts connections; without one it only
    /// opens them.
    pub fn new(config: Arc<EndpointConfig>, server: Option<Arc<ServerConfig>>) -> Self {
        Self {
            cids: CidGenerator::new(&config),
            host_id_truncations: u64::from(config.cid_layout().has_wide_host_id()),
            config,
            server,
            routes: HashMap::new(),
            by_key: HashMap::new(),
            peer_tokens: HashMap::new(),
            token_of: HashMap::new(),
            limiter: ReplyLimiter::default(),
            release_horizon: Duration::ZERO,
            src_ports: None,
            shared_src_ports: Arc::default(),
            pool: DatagramPool::default(),
        }
    }

    /// Decides where a received datagram goes, by the destination connection ID of its first
    /// packet.
    pub fn route(&mut self, now: Instant, meta: &RxMeta, datagram: &[u8]) -> Route {
        let header = Header::parse(datagram, self.config.local_cid_len());
        if let Ok(header) = &header
            && let Ok(dcid) = ConnectionId::new(header.dcid())
            && let Some(&key) = self.routes.get(&dcid)
        {
            return Route::Existing(key);
        }
        // A stateless reset need not parse with our ID length; the connection confirms it.
        if let Some((_, tail)) = datagram.split_last_chunk::<{ ResetToken::LEN }>()
            && datagram.len() >= MIN_RESET
            && let Some(&key) = self.peer_tokens.get(&(meta.src, ResetToken(*tail)))
        {
            return Route::Existing(key);
        }
        // The check runs only on a miss. A known connection checks the list only when its peer
        // moves, and drops what would move it to a blocked port.
        if self.refuses_src_port(meta.src.port()) {
            return Route::Drop(RxDropReason::InvalidSrcPort);
        }
        let Ok(header) = header else {
            return self.health_check(meta, datagram);
        };
        match header {
            Header::Protected(h) if h.ty() == PacketType::Initial => {
                let Some(server) = &self.server else {
                    return Route::Drop(RxDropReason::NotListening);
                };
                let version = h.version().unwrap_or(Version::NEGOTIATION);
                if !server.versions().contains(&version) {
                    return self.negotiate(now, meta, datagram.len(), h.dcid(), h.scid());
                }
                // A server drops an Initial in a datagram under 1,200 bytes, as RFC 9000 requires.
                if datagram.len() < usize::from(MIN_DATAGRAM) {
                    return Route::Drop(RxDropReason::ShortInitial);
                }
                // RFC 9000 requires 8 bytes or more in a client's first Destination Connection ID.
                let (Ok(dcid), Ok(scid)) =
                    (ConnectionId::new(h.dcid()), ConnectionId::new(h.scid()))
                else {
                    return Route::Drop(RxDropReason::Malformed);
                };
                if dcid.len() < 8 {
                    return Route::Drop(RxDropReason::Malformed);
                }
                Route::Accept(Incoming {
                    meta: *meta,
                    version,
                    dcid,
                    scid,
                    datagram: datagram.to_vec(),
                })
            }
            Header::UnsupportedVersion(h) => {
                self.negotiate(now, meta, datagram.len(), h.dcid(), h.scid())
            }
            Header::Protected(h)
                if h.ty() == PacketType::OneRtt
                    && self
                        .cids
                        .worker_of(h.dcid())
                        .is_some_and(|worker| worker != self.config.worker().0) =>
            {
                Route::Drop(RxDropReason::OtherWorker)
            }
            Header::Protected(h) if h.ty() == PacketType::OneRtt => {
                self.reset(now, meta, datagram, h.dcid())
            }
            // Version Negotiation and Retry packets only matter to an existing connection, and
            // the sender of a long header may not hold a reset token yet.
            Header::Protected(_) | Header::Retry(_) | Header::VersionNegotiation(_) => {
                Route::Drop(RxDropReason::UnknownConnection)
            }
        }
    }

    /// Answers the health check token, a datagram that is not a QUIC packet, with "OK", and drops
    /// anything else that does not parse. The answer is no longer than the token, so it does not
    /// need a rate limit.
    fn health_check(&self, meta: &RxMeta, datagram: &[u8]) -> Route {
        if self.server.is_none() || self.config.health_check_token() != Some(datagram) {
            return Route::Drop(RxDropReason::Malformed);
        }
        Route::Stateless(StatelessReply {
            dst: meta.src,
            src_ip: meta.dst_ip,
            kind: StatelessKind::HealthCheck,
            datagram: Bytes::from_static(HEALTH_CHECK_ANSWER),
        })
    }

    /// Answers a long-header packet of a version this server does not accept with Version
    /// Negotiation (RFC 9000). Only a datagram large enough for an Initial is answered, so the
    /// reply never amplifies.
    fn negotiate(
        &mut self,
        now: Instant,
        meta: &RxMeta,
        len: usize,
        dcid: &[u8],
        scid: &[u8],
    ) -> Route {
        let Some(server) = &self.server else {
            return Route::Drop(RxDropReason::UnsupportedVersion);
        };
        if len < usize::from(MIN_DATAGRAM) {
            return Route::Drop(RxDropReason::UnsupportedVersion);
        }
        if !self.limiter.allow(now) {
            return Route::Drop(RxDropReason::RateLimited);
        }
        let versions = server.versions();
        match version_negotiation(meta, dcid, scid, versions) {
            Some(reply) => Route::Stateless(reply),
            None => Route::Drop(RxDropReason::Malformed),
        }
    }

    /// Answers a short-header packet for an unknown connection ID with a stateless reset: a short
    /// header of unpredictable bits ending in the ID's token, shorter than the trigger so that two
    /// endpoints that lost state cannot reset each other forever.
    fn reset(&mut self, now: Instant, meta: &RxMeta, datagram: &[u8], dcid: &[u8]) -> Route {
        let len = datagram.len().saturating_sub(1).min(MAX_RESET);
        let Ok(dcid) = ConnectionId::new(dcid) else {
            return Route::Drop(RxDropReason::Malformed);
        };
        // With zero-length IDs every connection would share one token.
        if dcid.is_empty() || len < MIN_RESET {
            return Route::Drop(RxDropReason::UnknownConnection);
        }
        if !self.limiter.allow(now) {
            return Route::Drop(RxDropReason::RateLimited);
        }
        let mut out = vec![0; len];
        let (fill, token) = out.split_at_mut(len - ResetToken::LEN);
        self.cids.reset_fill(datagram, fill);
        fill[0] = (fill[0] & 0x3f) | 0x40;
        token.copy_from_slice(&self.cids.reset_token(&dcid).0);
        Route::Stateless(StatelessReply {
            dst: meta.src,
            src_ip: meta.dst_ip,
            kind: StatelessKind::Reset,
            datagram: Bytes::from(out),
        })
    }

    /// Sets the longest the endpoint's backend holds a datagram until its release. Connections
    /// accepted afterwards build up to the smaller of it and [`EndpointConfig::build_horizon`]
    /// ahead; zero, the default, is for a backend without release support. Set it once, before
    /// any connection.
    pub fn set_release_horizon(&mut self, horizon: Duration) {
        self.release_horizon = horizon;
    }

    /// Replaces the source ports the endpoint refuses; with `None`, the default, it does not refuse
    /// any. A datagram from a blocked port for an unknown connection is dropped, so it does not
    /// start a connection or get a reply. A server connection, whenever accepted, checks the list
    /// in force when its peer's address changes and drops datagrams that would move it to a blocked
    /// port; those from its current address are not checked.
    pub fn set_src_port_blocklist(&mut self, blocklist: Option<Arc<SrcPortBlocklist>>) {
        self.shared_src_ports.set(blocklist.clone());
        self.src_ports = blocklist;
    }

    /// Returns a handle whose [`SrcPortDrops::get`] reads the count of datagrams dropped for their
    /// source port.
    pub fn src_port_drops(&self) -> SrcPortDrops {
        SrcPortDrops(Arc::clone(&self.shared_src_ports))
    }

    /// Returns how many host IDs the endpoint truncated to the 24 bits that a version 2 connection
    /// ID carries: 1 when the `host_id` of its [`CidLayout::MvfstV2`](crate::CidLayout::MvfstV2)
    /// is wider, and 0 otherwise.
    pub fn host_id_truncations(&self) -> u64 {
        self.host_id_truncations
    }

    /// Checks a connection attempt that [`route`](Self::route) returned before the latest
    /// [`set_src_port_blocklist`](Self::set_src_port_blocklist) against the list in force:
    /// returns it unless its source port is blocked, in which case it is dropped and counted as
    /// [`RxDropReason::InvalidSrcPort`].
    pub fn recheck_src_port(&self, incoming: Incoming) -> Option<Incoming> {
        (!self.refuses_src_port(incoming.meta.src.port())).then_some(incoming)
    }

    /// Returns whether the list in force blocks `port`, and counts the datagram from it as
    /// dropped if so.
    fn refuses_src_port(&self, port: u16) -> bool {
        let blocked = self
            .src_ports
            .as_ref()
            .is_some_and(|ports| ports.blocks(port));
        if blocked {
            self.shared_src_ports.count_drop();
        }
        blocked
    }

    /// Creates and routes the server connection for an Initial, to be stored by the driver under
    /// `key`. Fails with [`AcceptError::Undecryptable`] unless a packet of its datagram decrypts.
    pub fn accept<R: Random>(
        &mut self,
        cx: &mut Inputs<'_, R>,
        key: ConnKey,
        incoming: Incoming,
        config: &Arc<ServerConfig>,
        options: ConnOptions,
    ) -> Result<Connection, AcceptError> {
        if self.routes.contains_key(&incoming.dcid) {
            return Err(AcceptError::CidInUse(incoming.dcid));
        }
        let local_cid = self
            .fresh_cid(cx.rng, Some(incoming.dcid))
            .ok_or(AcceptError::NoConnectionId)?;
        let mut rng_seed = [0; 32];
        cx.rng.fill(&mut rng_seed);
        let (without_alpn, alpn) = config.tls_without_alpn(incoming.version);
        let transport = options
            .transport
            .unwrap_or_else(|| config.transport().clone());
        let tls = config.tls_for(&transport);
        let setup = ConnSetup {
            now: cx.now,
            version: incoming.version,
            transport,
            alpn,
            remote: incoming.meta.src,
            local_ip: incoming.meta.dst_ip,
            local_cid,
            remote_cid: incoming.scid,
            original_dcid: incoming.dcid,
            cids: self.cids.clone(),
            rng_seed,
            horizon: self.config.build_horizon().min(self.release_horizon),
            src_ports: Some(Arc::clone(&self.shared_src_ports)),
            pool: self.pool.clone(),
        };
        let mut conn = Connection::server(setup, tls, without_alpn.cloned())
            .map_err(|e| AcceptError::Tls(rustls_error(e)))?;
        let meta = incoming.meta;
        let mut datagram = incoming.datagram;
        let summary = conn.recv_batch(
            cx.now,
            &mut [RxDatagram {
                meta: &meta,
                data: &mut datagram,
            }],
        );
        // Anyone can forge the datagram, so the endpoint keeps state only once a packet opens.
        if summary.packets == 0 {
            return Err(AcceptError::Undecryptable);
        }
        self.insert_route(incoming.dcid, key);
        self.insert_route(local_cid, key);
        Ok(conn)
    }

    /// Creates a client connection to `remote`, to be stored by the driver under `key`.
    /// `server_name` is sent as SNI and checked against the server's certificate.
    pub fn connect<R: Random>(
        &mut self,
        cx: &mut Inputs<'_, R>,
        key: ConnKey,
        remote: SocketAddr,
        server_name: ServerName<'static>,
        config: &Arc<ClientConfig>,
        options: ConnOptions,
    ) -> Result<Connection, ConnectError> {
        if remote.ip().is_unspecified() || remote.port() == 0 {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }
        let local_cid = self
            .fresh_cid(cx.rng, None)
            .ok_or(ConnectError::NoConnectionId)?;
        // At least 8 unpredictable bytes, as RFC 9000 requires.
        let mut dcid = [0; 8];
        cx.rng.fill(&mut dcid);
        let dcid = ConnectionId::new(&dcid).expect("should hold 8 bytes");
        let mut rng_seed = [0; 32];
        cx.rng.fill(&mut rng_seed);
        let setup = ConnSetup {
            now: cx.now,
            version: config.versions().first().copied().unwrap_or(Version::V1),
            transport: options
                .transport
                .unwrap_or_else(|| config.transport().clone()),
            alpn: config.alpn(),
            remote,
            local_ip: None,
            local_cid,
            remote_cid: dcid,
            original_dcid: dcid,
            cids: self.cids.clone(),
            rng_seed,
            // The client's socket is not the endpoint's, so its release support is unknown.
            horizon: Duration::ZERO,
            src_ports: None,
            pool: self.pool.clone(),
        };
        let conn = Connection::client(setup, config.tls(), server_name)
            .map_err(|e| ConnectError::Tls(rustls_error(e)))?;
        self.insert_route(local_cid, key);
        Ok(conn)
    }

    /// Refuses an Initial with an Initial CONNECTION_CLOSE carrying `code`, normally
    /// CONNECTION_REFUSED, subject to the stateless reply rate limit.
    pub fn refuse(
        &mut self,
        now: Instant,
        incoming: Incoming,
        code: TransportErrorCode,
    ) -> Option<StatelessReply> {
        if !self.limiter.allow(now) {
            return None;
        }
        let keys =
            mvfstr_crypto::initial_keys(incoming.version, &incoming.dcid, Side::Server).ok()?;
        // Far smaller than the 1,200-byte Initial it answers, so it cannot amplify.
        let mut out = vec![0; 128];
        let header = HeaderSpec::Initial {
            version: incoming.version,
            dcid: incoming.scid,
            scid: incoming.dcid,
            token: &[],
        };
        let mut w = PacketWriter::new(&mut out, header, 0, 1, TAG_LEN).ok()?;
        w.frame(&Frame::ConnectionClose {
            error_code: code,
            frame_type: VarInt::ZERO,
            reason: &[],
        })
        .ok()?;
        let layout = w.finish();
        let job = SealJob {
            slot: SlotId(0),
            keys: &keys.local,
            pn: 0,
            hdr_len: u16::try_from(layout.hdr_len).ok()?,
            len: u16::try_from(layout.len).ok()?,
        };
        InlineSealer.seal(job, &mut out).ok()?;
        out.truncate(layout.len);
        Some(StatelessReply {
            dst: incoming.meta.src,
            src_ip: incoming.meta.dst_ip,
            kind: StatelessKind::Refusal,
            datagram: Bytes::from(out),
        })
    }

    /// Refuses an Initial with Version Negotiation that lists only [`MVFST_INVALID`], so the client
    /// does not find a version in common and gives up. Subject to the stateless reply rate limit.
    pub fn refuse_by_negotiation(
        &mut self,
        now: Instant,
        incoming: Incoming,
    ) -> Option<StatelessReply> {
        if !self.limiter.allow(now) {
            return None;
        }
        version_negotiation(
            &incoming.meta,
            &incoming.dcid,
            &incoming.scid,
            &[MVFST_INVALID],
        )
    }

    /// Applies a routing change reported by the connection stored under `key`.
    pub fn handle_event(&mut self, key: ConnKey, event: EndpointEvent) {
        match event {
            EndpointEvent::NewLocalCid { cid, .. } => self.insert_route(cid, key),
            EndpointEvent::RetiredLocalCid { cid } => {
                if self.routes.get(&cid) == Some(&key) {
                    self.routes.remove(&cid);
                }
                if let Some(cids) = self.by_key.get_mut(&key) {
                    cids.retain(|other| *other != cid);
                }
            }
            EndpointEvent::PeerResetTokens { current, alternate } => {
                self.forget_peer_tokens(key);
                let entries = [current, alternate];
                for entry in entries.into_iter().flatten() {
                    self.peer_tokens.insert(entry, key);
                }
                self.token_of.insert(key, entries);
            }
            EndpointEvent::Drained => {
                self.forget_peer_tokens(key);
                for cid in self.by_key.remove(&key).unwrap_or_default() {
                    if self.routes.get(&cid) == Some(&key) {
                        self.routes.remove(&cid);
                    }
                }
            }
        }
    }

    fn forget_peer_tokens(&mut self, key: ConnKey) {
        for entry in self.token_of.remove(&key).into_iter().flatten().flatten() {
            if self.peer_tokens.get(&entry) == Some(&key) {
                self.peer_tokens.remove(&entry);
            }
        }
    }

    /// Routes `cid` to `key` unless it already routes elsewhere.
    fn insert_route(&mut self, cid: ConnectionId, key: ConnKey) {
        if *self.routes.entry(cid).or_insert(key) == key {
            self.by_key.entry(key).or_default().push(cid);
        }
    }

    /// Returns a random connection ID of the configured length, naming this worker, that is not
    /// routed yet and is not `taken`, or `None` if the attempts do not find one. This endpoint does
    /// not route zero-length IDs by address, so with them it holds one connection.
    fn fresh_cid<R: Random>(
        &self,
        rng: &mut R,
        taken: Option<ConnectionId>,
    ) -> Option<ConnectionId> {
        (0..CID_ATTEMPTS).find_map(|_| {
            let cid = self.cids.generate(rng);
            (!self.routes.contains_key(&cid) && Some(cid) != taken).then_some(cid)
        })
    }

    /// Returns the number of connection IDs routed, for tests.
    #[cfg(test)]
    pub(crate) fn route_count(&self) -> usize {
        self.routes.len()
    }
}

/// Returns a Version Negotiation packet listing `versions` that answers a long header with
/// connection IDs `dcid` and `scid`, or `None` if an ID is too long to encode.
fn version_negotiation(
    meta: &RxMeta,
    dcid: &[u8],
    scid: &[u8],
    versions: &[Version],
) -> Option<StatelessReply> {
    let mut out = vec![0; 7 + dcid.len() + scid.len() + 4 * versions.len()];
    // The reply swaps the packet's connection IDs, as RFC 9000 requires; its unused bits are
    // arbitrary.
    let written = encode_version_negotiation(&mut out, 0x2a, scid, dcid, versions).ok()?;
    out.truncate(written);
    Some(StatelessReply {
        dst: meta.src,
        src_ip: meta.dst_ip,
        kind: StatelessKind::VersionNegotiation,
        datagram: Bytes::from(out),
    })
}

/// Returns the rustls error behind a failure to create a TLS session.
fn rustls_error(error: TlsError) -> rustls::Error {
    match error {
        TlsError::Config(error) | TlsError::Alert { error, .. } | TlsError::Failed(error) => error,
        TlsError::UnsupportedVersion(_)
        | TlsError::WrongLevel { .. }
        | TlsError::LeftUnread { .. }
        | TlsError::BufferExceeded { .. }
        | TlsError::PostHandshakeAuth
        | TlsError::HostAlert(_)
        | TlsError::NotPending
        | TlsError::InvalidStep => rustls::Error::General(error.to_string()),
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mvfstr_wire::VarInt;

    use super::*;
    use crate::CidLayout;
    use crate::CloseReason;
    use crate::ConnEvent;
    use crate::Ecn;
    use crate::Initiator;
    use crate::MvfstCid;
    use crate::MvfstV2Fields;
    use crate::TxLimits;
    use crate::parse_v2;
    use crate::recovery::test_epoch;
    use crate::testing::TestRng;
    use crate::testing::VecSink;
    use crate::testing::fixtures::Setup;
    use crate::testing::fixtures::unix_now;

    const KEY: ConnKey = ConnKey {
        index: 1,
        generation: 1,
    };

    fn client_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000)
    }

    fn server_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4433)
    }

    fn meta(now: Instant) -> RxMeta {
        RxMeta {
            src: client_addr(),
            dst_ip: Some(server_addr().ip()),
            ecn: Ecn::NotEct,
            stride: 0,
            rx_time: now,
        }
    }

    fn server(setup: &Setup) -> Endpoint {
        let config = setup.pair();
        Endpoint::new(config.endpoint, Some(config.server))
    }

    /// Returns a client connection for `setup` and its first datagram.
    fn client(setup: &Setup, now: Instant) -> (Connection, Vec<u8>) {
        client_seeded(setup, now, 1)
    }

    /// Returns a client connection for `setup` whose connection IDs come from `seed`, and its
    /// first datagram.
    fn client_seeded(setup: &Setup, now: Instant, seed: u64) -> (Connection, Vec<u8>) {
        let config = setup.pair();
        let mut endpoint = Endpoint::new(config.endpoint.clone(), None);
        let mut rng = TestRng::new(seed);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let mut conn = endpoint
            .connect(
                &mut cx,
                KEY,
                server_addr(),
                ServerName::try_from("localhost").unwrap(),
                &config.client,
                ConnOptions::default(),
            )
            .unwrap();
        let mut sink = VecSink::new(1500);
        let limits = TxLimits {
            now,
            max_segments: 1,
            max_datagram: 1500,
            max_bytes: u32::MAX,
            epoch: None,
        };
        conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
        let datagram = sink.take().remove(0).data;
        (conn, datagram)
    }

    /// Returns a version 1 Initial of `len` bytes with a Destination Connection ID of `dcid_len`
    /// bytes; its payload is not encrypted, and routing does not read it.
    fn initial(len: usize, dcid_len: u8) -> Vec<u8> {
        let mut out = vec![0xc0, 0, 0, 0, 1, dcid_len];
        out.extend(std::iter::repeat_n(1, usize::from(dcid_len)));
        out.extend_from_slice(&[8, 2, 2, 2, 2, 2, 2, 2, 2, 0]);
        let rest = u16::try_from(len - out.len() - 2).unwrap();
        out.extend_from_slice(&(0x4000 | rest).to_be_bytes());
        out.resize(len, 0);
        out
    }

    /// Returns a long-header packet of an unknown version, `len` bytes long.
    fn unknown_version(len: usize) -> Vec<u8> {
        let mut out = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
        out.extend_from_slice(&[1; 8]);
        out.push(8);
        out.extend_from_slice(&[2; 8]);
        out.resize(len, 0);
        out
    }

    fn incoming(route: Route) -> Incoming {
        match route {
            Route::Accept(incoming) => incoming,
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    #[test]
    fn an_initial_for_an_unknown_connection_id_is_offered_for_acceptance() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (_, datagram) = client(&setup, now);
        let incoming = incoming(endpoint.route(now, &meta(now), &datagram));
        assert_eq!(incoming.version(), Version::V1);
        assert_eq!(incoming.remote_address(), client_addr());
        assert_eq!(incoming.local_ip(), Some(server_addr().ip()));
        let config = setup.pair().server;
        let mut rng = TestRng::new(2);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let conn = endpoint
            .accept(&mut cx, KEY, incoming, &config, ConnOptions::default())
            .unwrap();
        assert_eq!(conn.side(), Side::Server);
        // The client's chosen ID and the server's own both route to the connection.
        assert_eq!(endpoint.route_count(), 2);
        assert!(matches!(
            endpoint.route(now, &meta(now), &datagram),
            Route::Existing(KEY)
        ));
        endpoint.handle_event(KEY, EndpointEvent::Drained);
        assert_eq!(endpoint.route_count(), 0);
        assert!(matches!(
            endpoint.route(now, &meta(now), &datagram),
            Route::Accept(_)
        ));
    }

    #[test]
    fn an_initial_for_a_routed_connection_id_is_not_accepted_twice() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (_, datagram) = client(&setup, now);
        let first = incoming(endpoint.route(now, &meta(now), &datagram));
        let second = incoming(endpoint.route(now, &meta(now), &datagram));
        let config = setup.pair().server;
        let mut rng = TestRng::new(2);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        endpoint
            .accept(&mut cx, KEY, first, &config, ConnOptions::default())
            .unwrap();
        let other = ConnKey {
            index: 2,
            generation: 1,
        };
        let error = endpoint
            .accept(&mut cx, other, second, &config, ConnOptions::default())
            .unwrap_err();
        assert!(matches!(error, AcceptError::CidInUse(_)));
    }

    #[test]
    fn an_initial_that_does_not_decrypt_leaves_nothing_behind() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        // Its payload is not encrypted, so its packet does not open.
        let incoming = incoming(endpoint.route(now, &meta(now), &initial(1200, 8)));
        let config = setup.pair().server;
        let mut rng = TestRng::new(2);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let error = endpoint
            .accept(&mut cx, KEY, incoming, &config, ConnOptions::default())
            .unwrap_err();
        assert!(matches!(error, AcceptError::Undecryptable), "{error:?}");
        assert_eq!(endpoint.route_count(), 0);
    }

    #[test]
    fn zero_length_connection_ids_leave_room_for_one_connection() {
        let now = test_epoch();
        let setup = Setup::default();
        let config = setup.pair();
        let zero = EndpointConfig::builder([7; 32])
            .local_cid_len(0)
            .build()
            .unwrap();
        let other = ConnKey {
            index: 2,
            generation: 1,
        };
        let mut rng = TestRng::new(3);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let mut endpoint = Endpoint::new(zero.clone(), None);
        let connect = |endpoint: &mut Endpoint, cx: &mut Inputs<'_, TestRng>, key| {
            endpoint.connect(
                cx,
                key,
                server_addr(),
                ServerName::try_from("localhost").unwrap(),
                &config.client,
                ConnOptions::default(),
            )
        };
        connect(&mut endpoint, &mut cx, KEY).unwrap();
        // The empty ID already routes to the first connection.
        let error = connect(&mut endpoint, &mut cx, other).unwrap_err();
        assert!(matches!(error, ConnectError::NoConnectionId), "{error:?}");
        assert_eq!(endpoint.route_count(), 1);
        endpoint.handle_event(KEY, EndpointEvent::Drained);
        connect(&mut endpoint, &mut cx, other).unwrap();

        let mut endpoint = Endpoint::new(zero, Some(config.server.clone()));
        let (_, first) = client_seeded(&setup, now, 1);
        let (_, second) = client_seeded(&setup, now, 2);
        let first = incoming(endpoint.route(now, &meta(now), &first));
        endpoint
            .accept(&mut cx, KEY, first, &config.server, ConnOptions::default())
            .unwrap();
        let second = incoming(endpoint.route(now, &meta(now), &second));
        let error = endpoint
            .accept(
                &mut cx,
                other,
                second,
                &config.server,
                ConnOptions::default(),
            )
            .unwrap_err();
        assert!(matches!(error, AcceptError::NoConnectionId), "{error:?}");
        assert_eq!(endpoint.route_count(), 2);
    }

    fn connect_to_server(endpoint: &mut Endpoint, setup: &Setup, now: Instant, index: u32) {
        let mut rng = TestRng::new(u64::from(index));
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let key = ConnKey {
            index,
            generation: 1,
        };
        endpoint
            .connect(
                &mut cx,
                key,
                server_addr(),
                ServerName::try_from("localhost").unwrap(),
                &setup.pair().client,
                ConnOptions::default(),
            )
            .unwrap();
    }

    fn worker(index: u16, count: u16) -> Endpoint {
        worker_with(index, count, CidLayout::Random)
    }

    /// Returns a short-header packet of `len` bytes for the 8-byte connection ID `dcid`.
    fn short_header(dcid: [u8; 8], len: usize) -> Vec<u8> {
        let mut out = vec![0x41];
        out.extend_from_slice(&dcid);
        out.resize(len, 0x5a);
        out
    }

    #[test]
    fn issued_connection_ids_name_the_worker() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = worker(2, 4);
        for index in 0..20 {
            connect_to_server(&mut endpoint, &setup, now, index);
        }
        assert_eq!(endpoint.route_count(), 20);
        for cid in endpoint.routes.keys() {
            assert_eq!(cid[0] % 4, 2, "{cid}");
        }
    }

    #[test]
    fn short_headers_for_other_workers_are_dropped() {
        let now = test_epoch();
        let mut endpoint = worker(2, 4);
        for first in [0, 1, 3, 4, 7, 255] {
            let packet = short_header([first, 1, 2, 3, 4, 5, 6, 7], 100);
            assert!(
                matches!(
                    endpoint.route(now, &meta(now), &packet),
                    Route::Drop(RxDropReason::OtherWorker)
                ),
                "{first}"
            );
        }
    }

    fn v2_layout(host_id: u32, process: bool) -> CidLayout {
        CidLayout::MvfstV2 {
            host_id,
            prev_host_id: 0,
            process,
        }
    }

    /// Returns a server endpoint that is worker `index` of `count` and issues IDs in `layout`.
    fn worker_with(index: u16, count: u16, layout: CidLayout) -> Endpoint {
        let config = EndpointConfig::builder([7; 32])
            .worker(index, count)
            .cid_layout(layout)
            .build()
            .unwrap();
        Endpoint::new(config, Some(Setup::default().pair().server))
    }

    #[test]
    fn the_first_server_initial_names_the_issuing_worker_and_process_in_its_source_id() {
        // The client addresses its Handshake packets to this source ID, so load balancers and
        // in-host steering route them by it.
        let now = test_epoch();
        let setup = Setup::default();
        for (index, count, process) in [(3, 8, true), (0, 1, false), (255, 256, false)] {
            let mut endpoint = worker_with(index, count, v2_layout(0xab_cdef, process));
            let (_, datagram) = client(&setup, now);
            let incoming = incoming(endpoint.route(now, &meta(now), &datagram));
            let mut rng = TestRng::new(2);
            let mut cx = Inputs {
                now,
                unix_now: unix_now(),
                rng: &mut rng,
            };
            let config = setup.pair().server;
            let mut conn = endpoint
                .accept(&mut cx, KEY, incoming, &config, ConnOptions::default())
                .unwrap();
            let mut sink = VecSink::new(1500);
            let limits = TxLimits {
                now,
                max_segments: 1,
                max_datagram: 1500,
                max_bytes: u32::MAX,
                epoch: None,
            };
            conn.poll_transmit(&limits, &mut sink, &mut InlineSealer);
            let first = sink.take().remove(0).data;
            let Ok(Header::Protected(header)) = Header::parse(&first, 8) else {
                panic!("a long header");
            };
            assert_eq!(header.ty(), PacketType::Initial);
            assert_eq!(
                parse_v2(header.scid()),
                Some(MvfstCid::V2(MvfstV2Fields {
                    host_id: 0xab_cdef,
                    worker: u8::try_from(index).unwrap(),
                    process,
                })),
                "worker {index} of {count}"
            );
        }
    }

    #[test]
    fn under_the_version_2_layout_a_miss_reads_the_worker_in_byte_4_and_a_hit_reads_nothing() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = worker_with(2, 4, v2_layout(0x12_3456, false));
        for index in 0..4 {
            connect_to_server(&mut endpoint, &setup, now, index);
        }
        let routed: Vec<ConnectionId> = endpoint.routes.keys().copied().collect();
        let parses = || crate::cid::V2_PARSES.with(std::cell::Cell::get);
        let before = parses();
        for cid in &routed {
            let packet = short_header(cid[..].try_into().unwrap(), 100);
            assert!(
                matches!(endpoint.route(now, &meta(now), &packet), Route::Existing(_)),
                "{cid}"
            );
        }
        assert_eq!(parses(), before, "a routed ID is not read");
        // Byte 0 is congruent to this worker, so only byte 4 names another one.
        for worker in [1, 3, 5, 255] {
            let packet = short_header([0x82, 0x12, 0x34, 0x56, worker, 0, 1, 2], 100);
            assert!(
                matches!(
                    endpoint.route(now, &meta(now), &packet),
                    Route::Drop(RxDropReason::OtherWorker)
                ),
                "worker byte {worker}"
            );
        }
        // Byte 0 is not, and byte 4 names this worker modulo the count.
        for worker in [2, 6] {
            let packet = short_header([0x81, 0x12, 0x34, 0x56, worker, 0, 1, 2], 100);
            let reset = reply(endpoint.route(now, &meta(now), &packet));
            assert_eq!(reset.kind(), StatelessKind::Reset, "worker byte {worker}");
        }
        assert_eq!(parses(), before + 6, "each miss reads its ID once");
    }

    #[test]
    fn host_ids_wider_than_24_bits_are_truncated_and_counted() {
        let now = test_epoch();
        let mut endpoint = worker_with(0, 1, v2_layout(0x1234_5678, false));
        assert_eq!(endpoint.host_id_truncations(), 1);
        connect_to_server(&mut endpoint, &Setup::default(), now, 1);
        let cid = *endpoint.routes.keys().next().unwrap();
        assert!(
            matches!(
                parse_v2(&cid),
                Some(MvfstCid::V2(MvfstV2Fields {
                    host_id: 0x34_5678,
                    ..
                }))
            ),
            "{cid}"
        );
        // IDs do not carry the previous host ID, so a wide one is not truncated.
        let with_prev = |host_id, prev_host_id| CidLayout::MvfstV2 {
            host_id,
            prev_host_id,
            process: true,
        };
        for (layout, truncations) in [
            (v2_layout(0xff_ffff, false), 0),
            (with_prev(1 << 24, u32::MAX), 1),
            (with_prev(1, u32::MAX), 0),
            (CidLayout::Random, 0),
        ] {
            let endpoint = worker_with(0, 1, layout);
            assert_eq!(endpoint.host_id_truncations(), truncations, "{layout:?}");
        }
    }

    fn reply(route: Route) -> StatelessReply {
        match route {
            Route::Stateless(reply) => reply,
            other => panic!("expected a stateless reply, got {other:?}"),
        }
    }

    #[test]
    fn unknown_short_headers_get_a_smaller_stateless_reset() {
        let now = test_epoch();
        let mut endpoint = worker(2, 4);
        let generator = CidGenerator::new(&endpoint.config);
        let dcid = [6, 1, 2, 3, 4, 5, 6, 7];
        let token = generator.reset_token(&ConnectionId::new(&dcid).unwrap());
        // The reset is one byte shorter than a short trigger and 43 bytes at most.
        for (len, expected) in [(29, 28), (44, 43), (1200, 43)] {
            let reset = reply(endpoint.route(now, &meta(now), &short_header(dcid, len)));
            assert_eq!(reset.kind(), StatelessKind::Reset);
            assert_eq!(reset.dst(), client_addr());
            assert_eq!(reset.src_ip(), Some(server_addr().ip()));
            let datagram = reset.datagram();
            assert_eq!(datagram.len(), expected, "{len}");
            assert_eq!(
                datagram[0] & 0xc0,
                0x40,
                "a short header with the fixed bit"
            );
            assert_eq!(&datagram[expected - 16..], &token.0);
        }
        let mut other = short_header(dcid, 100);
        other[50] ^= 1;
        let first = reply(endpoint.route(now, &meta(now), &short_header(dcid, 100)));
        let second = reply(endpoint.route(now, &meta(now), &other));
        assert_ne!(
            first.datagram()[1..27],
            second.datagram()[1..27],
            "the bytes before the token are unpredictable"
        );
    }

    #[test]
    fn stateless_resets_need_a_connection_id_and_share_the_rate_limit() {
        let now = test_epoch();
        let setup = Setup::default();
        let zero = EndpointConfig::builder([7; 32])
            .local_cid_len(0)
            .build()
            .unwrap();
        let mut endpoint = Endpoint::new(zero, Some(setup.pair().server));
        assert!(matches!(
            endpoint.route(now, &meta(now), &[0x41; 100]),
            Route::Drop(RxDropReason::UnknownConnection)
        ));

        let mut endpoint = server(&setup);
        let trigger = short_header([1; 8], 100);
        for _ in 0..ReplyLimiter::BURST {
            reply(endpoint.route(now, &meta(now), &trigger));
        }
        assert!(matches!(
            endpoint.route(now, &meta(now), &trigger),
            Route::Drop(RxDropReason::RateLimited)
        ));
        assert!(matches!(
            endpoint.route(now, &meta(now), &unknown_version(1200)),
            Route::Drop(RxDropReason::RateLimited)
        ));
        let later = now + std::time::Duration::from_millis(1);
        reply(endpoint.route(later, &meta(later), &trigger));
    }

    #[test]
    fn datagrams_ending_in_a_peer_reset_token_route_to_its_connection() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        let token = ResetToken([9; 16]);
        let event = |token: Option<ResetToken>| EndpointEvent::PeerResetTokens {
            current: token.map(|token| (client_addr(), token)),
            alternate: None,
        };
        endpoint.handle_event(KEY, event(Some(token)));
        let mut reset = vec![0x47; 5];
        reset.extend_from_slice(&token.0);
        let routed = |endpoint: &mut Endpoint, meta: &RxMeta| {
            matches!(endpoint.route(now, meta, &reset), Route::Existing(KEY))
        };
        assert!(routed(&mut endpoint, &meta(now)));
        let stranger = RxMeta {
            src: SocketAddr::new(client_addr().ip(), 50_001),
            ..meta(now)
        };
        assert!(
            !routed(&mut endpoint, &stranger),
            "only the address the connection sends to"
        );
        endpoint.handle_event(KEY, event(None));
        assert!(!routed(&mut endpoint, &meta(now)));
        endpoint.handle_event(KEY, event(Some(ResetToken([8; 16]))));
        endpoint.handle_event(KEY, event(Some(token)));
        assert!(routed(&mut endpoint, &meta(now)));
        endpoint.handle_event(KEY, EndpointEvent::Drained);
        assert!(!routed(&mut endpoint, &meta(now)));
    }

    #[test]
    fn datagrams_ending_in_the_alternate_paths_token_route_from_its_address() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        let alternate = SocketAddr::new(client_addr().ip(), 50_001);
        let (current_token, alternate_token) = (ResetToken([9; 16]), ResetToken([8; 16]));
        let reset = |token: ResetToken| {
            let mut reset = vec![0x47; 5];
            reset.extend_from_slice(&token.0);
            reset
        };
        let routed = |endpoint: &mut Endpoint, src, token| {
            let meta = RxMeta { src, ..meta(now) };
            matches!(
                endpoint.route(now, &meta, &reset(token)),
                Route::Existing(KEY)
            )
        };
        endpoint.handle_event(
            KEY,
            EndpointEvent::PeerResetTokens {
                current: Some((client_addr(), current_token)),
                alternate: Some((alternate, alternate_token)),
            },
        );
        assert!(routed(&mut endpoint, client_addr(), current_token));
        assert!(
            routed(&mut endpoint, alternate, alternate_token),
            "every token in use counts from its own address, as RFC 9000 requires"
        );
        assert!(!routed(&mut endpoint, alternate, current_token));
        endpoint.handle_event(
            KEY,
            EndpointEvent::PeerResetTokens {
                current: Some((client_addr(), current_token)),
                alternate: None,
            },
        );
        assert!(
            !routed(&mut endpoint, alternate, alternate_token),
            "the alternate path is gone"
        );
        assert!(routed(&mut endpoint, client_addr(), current_token));
    }

    /// A random source that gives the same bytes every time.
    struct Stuck;

    impl Random for Stuck {
        fn fill(&mut self, dest: &mut [u8]) {
            dest.fill(3);
        }
    }

    #[test]
    fn a_random_source_that_repeats_itself_gets_no_routed_id() {
        let now = test_epoch();
        let config = Setup::default().pair();
        let mut endpoint = Endpoint::new(config.endpoint.clone(), None);
        let mut rng = Stuck;
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let other = ConnKey {
            index: 2,
            generation: 1,
        };
        for (key, ok) in [(KEY, true), (other, false)] {
            let result = endpoint.connect(
                &mut cx,
                key,
                server_addr(),
                ServerName::try_from("localhost").unwrap(),
                &config.client,
                ConnOptions::default(),
            );
            assert_eq!(result.is_ok(), ok, "{result:?}");
            if let Err(error) = result {
                assert!(matches!(error, ConnectError::NoConnectionId), "{error:?}");
            }
        }
        assert_eq!(endpoint.route_count(), 1);
    }

    #[test]
    fn initials_below_1200_bytes_or_with_short_connection_ids_are_dropped() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        assert!(matches!(
            endpoint.route(now, &meta(now), &initial(1200, 8)),
            Route::Accept(_)
        ));
        assert!(matches!(
            endpoint.route(now, &meta(now), &initial(1199, 8)),
            Route::Drop(RxDropReason::ShortInitial)
        ));
        assert!(matches!(
            endpoint.route(now, &meta(now), &initial(1200, 7)),
            Route::Drop(RxDropReason::Malformed)
        ));
    }

    #[test]
    fn unknown_versions_get_version_negotiation_only_at_1200_bytes() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        let Route::Stateless(reply) = endpoint.route(now, &meta(now), &unknown_version(1200))
        else {
            panic!("no Version Negotiation");
        };
        assert_eq!(reply.kind(), StatelessKind::VersionNegotiation);
        assert_eq!(reply.dst(), client_addr());
        assert_eq!(reply.src_ip(), Some(server_addr().ip()));
        let Ok(Header::VersionNegotiation(vn)) = Header::parse(reply.datagram(), 8) else {
            panic!("not a Version Negotiation packet");
        };
        // The connection IDs are swapped, as RFC 9000 requires.
        assert_eq!(vn.dcid(), [2; 8]);
        assert_eq!(vn.scid(), [1; 8]);
        assert_eq!(vn.versions().collect::<Vec<_>>(), [Version::V1]);
        assert!(matches!(
            endpoint.route(now, &meta(now), &unknown_version(1199)),
            Route::Drop(RxDropReason::UnsupportedVersion)
        ));
    }

    #[test]
    fn mvfsts_experimental_versions_get_version_negotiation_listing_every_accepted_version() {
        let now = test_epoch();
        let accepted = [
            Version::V1,
            Version::MVFST,
            Version::QUIC_V1_ALIAS,
            Version::QUIC_V1_ALIAS2,
            Version::MVFST_ALIAS,
        ];
        let mut endpoint = server(&Setup {
            server_versions: accepted.to_vec(),
            ..Setup::default()
        });
        // mvfst's MVFST_EXPERIMENTAL to MVFST_EXPERIMENTAL5.
        for version in [
            0xface_b00e_u32,
            0xface_b011,
            0xface_b013,
            0xface_b014,
            0xface_b015,
        ] {
            let mut datagram = initial(1200, 8);
            datagram[1..5].copy_from_slice(&version.to_be_bytes());
            let Route::Stateless(reply) = endpoint.route(now, &meta(now), &datagram) else {
                panic!("no Version Negotiation for {version:#x}");
            };
            assert_eq!(reply.kind(), StatelessKind::VersionNegotiation);
            let Ok(Header::VersionNegotiation(vn)) = Header::parse(reply.datagram(), 8) else {
                panic!("not a Version Negotiation packet");
            };
            assert_eq!(vn.dcid(), [2; 8]);
            assert_eq!(vn.scid(), [1; 8]);
            assert_eq!(vn.versions().collect::<Vec<_>>(), accepted, "{version:#x}");
        }
    }

    #[test]
    fn version_negotiation_is_rate_limited() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        let datagram = unknown_version(1200);
        for _ in 0..64 {
            assert!(matches!(
                endpoint.route(now, &meta(now), &datagram),
                Route::Stateless(_)
            ));
        }
        assert!(matches!(
            endpoint.route(now, &meta(now), &datagram),
            Route::Drop(RxDropReason::RateLimited)
        ));
        let later = now + std::time::Duration::from_millis(5);
        assert!(matches!(
            endpoint.route(later, &meta(later), &datagram),
            Route::Stateless(_)
        ));
    }

    #[test]
    fn mvfst_initials_are_accepted_only_when_configured() {
        let now = test_epoch();
        let mvfst = Setup {
            client_versions: vec![Version::MVFST],
            ..Setup::default()
        };
        let (_, datagram) = client(&mvfst, now);
        let mut v1_only = server(&Setup::default());
        let Route::Stateless(reply) = v1_only.route(now, &meta(now), &datagram) else {
            panic!("no Version Negotiation");
        };
        assert_eq!(reply.kind(), StatelessKind::VersionNegotiation);
        let both = Setup {
            server_versions: vec![Version::V1, Version::MVFST],
            ..Setup::default()
        };
        let incoming = incoming(server(&both).route(now, &meta(now), &datagram));
        assert_eq!(incoming.version(), Version::MVFST);
    }

    #[test]
    fn a_client_endpoint_accepts_nothing_and_negotiates_nothing() {
        let now = test_epoch();
        let config = Setup::default().pair();
        let mut endpoint = Endpoint::new(config.endpoint, None);
        assert!(matches!(
            endpoint.route(now, &meta(now), &initial(1200, 8)),
            Route::Drop(RxDropReason::NotListening)
        ));
        assert!(matches!(
            endpoint.route(now, &meta(now), &unknown_version(1200)),
            Route::Drop(RxDropReason::UnsupportedVersion)
        ));
    }

    #[test]
    fn a_refusal_is_an_initial_connection_close_the_client_accepts() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (mut conn, datagram) = client(&setup, now);
        let incoming = incoming(endpoint.route(now, &meta(now), &datagram));
        let reply = endpoint
            .refuse(now, incoming, TransportErrorCode::CONNECTION_REFUSED)
            .unwrap();
        assert_eq!(reply.kind(), StatelessKind::Refusal);
        assert_eq!(reply.dst(), client_addr());
        assert!(reply.datagram().len() < 1200);
        let mut data = reply.datagram().to_vec();
        let server_meta = RxMeta {
            src: server_addr(),
            dst_ip: None,
            ..meta(now)
        };
        conn.recv_batch(
            now,
            &mut [RxDatagram {
                meta: &server_meta,
                data: &mut data,
            }],
        );
        let event = conn.poll_event();
        assert_eq!(
            event,
            Some(ConnEvent::Closed {
                reason: CloseReason::Transport {
                    code: TransportErrorCode::CONNECTION_REFUSED,
                    frame_type: Some(VarInt::ZERO),
                    reason: Bytes::new(),
                },
                initiator: Initiator::Peer,
            })
        );
    }

    #[test]
    fn a_blocklist_blocks_the_ports_below_its_bound_and_those_it_selects() {
        // A typical setting: every port below 1,024, and 1,024 itself selected.
        let production = SrcPortBlocklist::new(1024, [1024]);
        for port in [0, 53, 1023, 1024] {
            assert!(production.blocks(port), "{port}");
        }
        for port in [1025, 4433, 50_000, u16::MAX] {
            assert!(!production.blocks(port), "{port}");
        }
        let unsorted = SrcPortBlocklist::new(0, [8080, 443, 8080, 53]);
        for port in [53, 443, 8080] {
            assert!(unsorted.blocks(port), "{port}");
        }
        for port in [0, 54, 444, 8079, 8081] {
            assert!(!unsorted.blocks(port), "{port}");
        }
        assert!(!SrcPortBlocklist::default().blocks(0), "blocks nothing");
    }

    /// Returns the metadata of a datagram from `port` of the client's IP.
    fn from_port(now: Instant, port: u16) -> RxMeta {
        RxMeta {
            src: SocketAddr::new(client_addr().ip(), port),
            ..meta(now)
        }
    }

    #[test]
    fn an_initial_from_a_blocklisted_source_port_starts_no_connection() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (_, datagram) = client(&setup, now);
        endpoint.set_src_port_blocklist(Some(Arc::new(SrcPortBlocklist::new(1024, [1024]))));
        for port in [53, 1024] {
            let route = endpoint.route(now, &from_port(now, port), &datagram);
            assert!(
                matches!(route, Route::Drop(RxDropReason::InvalidSrcPort)),
                "{port}: {route:?}"
            );
        }
        incoming(endpoint.route(now, &from_port(now, 1025), &datagram));
    }

    /// Returns a server endpoint whose health check token is `token`; proxygen's is "health".
    fn health_checked(token: &[u8]) -> Endpoint {
        let config = EndpointConfig::builder([7; 32])
            .health_check_token(Bytes::copy_from_slice(token))
            .build()
            .unwrap();
        Endpoint::new(config, Some(Setup::default().pair().server))
    }

    #[test]
    fn the_health_check_token_is_answered_with_ok() {
        let now = test_epoch();
        let mut endpoint = health_checked(b"health");
        let answer = reply(endpoint.route(now, &meta(now), b"health"));
        assert_eq!(answer.kind(), StatelessKind::HealthCheck);
        assert_eq!(answer.dst(), client_addr());
        assert_eq!(answer.src_ip(), Some(server_addr().ip()));
        assert_eq!(answer.datagram(), b"OK", "the two bytes mvfst sends");

        for other in [&b"healt"[..], b"healthy", b"HEALTH"] {
            let route = endpoint.route(now, &meta(now), other);
            assert!(
                matches!(route, Route::Drop(RxDropReason::Malformed)),
                "{other:?}: {route:?}"
            );
        }
        let mut unchecked = server(&Setup::default());
        assert!(matches!(
            unchecked.route(now, &meta(now), b"health"),
            Route::Drop(RxDropReason::Malformed)
        ));
        // Only a datagram that does not parse is a health check: a token that parses as a short
        // header for an unknown connection gets the stateless reset any such packet gets.
        let parses = short_header([1; 8], 100);
        let answer = reply(health_checked(&parses).route(now, &meta(now), &parses));
        assert_eq!(answer.kind(), StatelessKind::Reset);
        endpoint.set_src_port_blocklist(Some(Arc::new(SrcPortBlocklist::new(1024, []))));
        let route = endpoint.route(now, &from_port(now, 80), b"health");
        assert!(
            matches!(route, Route::Drop(RxDropReason::InvalidSrcPort)),
            "{route:?}"
        );
    }

    #[test]
    fn the_blocklist_does_not_touch_datagrams_of_known_connections() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (_, datagram) = client(&setup, now);
        let incoming = incoming(endpoint.route(now, &meta(now), &datagram));
        let mut rng = TestRng::new(2);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        let config = setup.pair().server;
        endpoint
            .accept(&mut cx, KEY, incoming, &config, ConnOptions::default())
            .unwrap();
        let blocklist = SrcPortBlocklist::new(0, [client_addr().port()]);
        endpoint.set_src_port_blocklist(Some(Arc::new(blocklist)));
        assert!(matches!(
            endpoint.route(now, &meta(now), &datagram),
            Route::Existing(KEY)
        ));
        assert_eq!(endpoint.src_port_drops().get(), 0);
    }

    #[test]
    fn datagrams_dropped_for_their_source_port_are_counted() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        endpoint.set_src_port_blocklist(Some(Arc::new(SrcPortBlocklist::new(1024, []))));
        for trigger in [initial(1200, 8), unknown_version(1200), b"junk".to_vec()] {
            endpoint.route(now, &from_port(now, 1023), &trigger);
            endpoint.route(now, &from_port(now, 1024), &trigger);
        }
        assert_eq!(
            endpoint.src_port_drops().get(),
            3,
            "one of each from port 1023"
        );
    }

    #[test]
    fn a_client_endpoint_does_not_answer_the_health_check_token() {
        let now = test_epoch();
        let config = EndpointConfig::builder([7; 32])
            .health_check_token(&b"health"[..])
            .build()
            .unwrap();
        let route = Endpoint::new(config, None).route(now, &meta(now), b"health");
        assert!(
            matches!(route, Route::Drop(RxDropReason::Malformed)),
            "{route:?}"
        );
    }

    #[test]
    fn a_blocklisted_source_port_gets_no_stateless_reply() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        endpoint.set_src_port_blocklist(Some(Arc::new(SrcPortBlocklist::new(1024, [1024]))));
        let triggers = [
            ("Version Negotiation", unknown_version(1200)),
            ("stateless reset", short_header([1; 8], 100)),
        ];
        for (kind, trigger) in &triggers {
            let route = endpoint.route(now, &from_port(now, 1024), trigger);
            assert!(
                matches!(route, Route::Drop(RxDropReason::InvalidSrcPort)),
                "{kind}: {route:?}"
            );
            reply(endpoint.route(now, &from_port(now, 1025), trigger));
        }
    }

    #[test]
    fn a_refusal_by_negotiation_lists_only_the_invalid_version_and_turns_the_client_away() {
        let now = test_epoch();
        let setup = Setup::default();
        let mut endpoint = server(&setup);
        let (mut conn, datagram) = client(&setup, now);
        let Ok(Header::Protected(initial)) = Header::parse(&datagram, 8) else {
            panic!("not an Initial");
        };
        let (client_dcid, client_scid) = (initial.dcid().to_vec(), initial.scid().to_vec());
        let incoming = incoming(endpoint.route(now, &meta(now), &datagram));
        let reply = endpoint
            .refuse_by_negotiation(now, incoming)
            .expect("a refusal");
        assert_eq!(reply.kind(), StatelessKind::VersionNegotiation);
        assert_eq!(reply.dst(), client_addr());
        assert_eq!(reply.src_ip(), Some(server_addr().ip()));
        let Ok(Header::VersionNegotiation(vn)) = Header::parse(reply.datagram(), 8) else {
            panic!("not a Version Negotiation packet");
        };
        // The connection IDs are swapped, as RFC 9000 requires.
        assert_eq!(vn.dcid(), &client_scid[..]);
        assert_eq!(vn.scid(), &client_dcid[..]);
        assert_eq!(vn.versions().collect::<Vec<_>>(), [MVFST_INVALID]);

        let mut data = reply.datagram().to_vec();
        let server_meta = RxMeta {
            src: server_addr(),
            dst_ip: None,
            ..meta(now)
        };
        conn.recv_batch(
            now,
            &mut [RxDatagram {
                meta: &server_meta,
                data: &mut data,
            }],
        );
        assert_eq!(
            conn.poll_event(),
            Some(ConnEvent::Closed {
                reason: CloseReason::NoCommonVersion,
                initiator: Initiator::Peer,
            })
        );
    }

    #[test]
    fn refusals_by_negotiation_share_the_stateless_reply_rate_limit() {
        let now = test_epoch();
        let mut endpoint = server(&Setup::default());
        let trigger = initial(1200, 8);
        let refuse = |endpoint: &mut Endpoint, at: Instant| {
            let incoming = incoming(endpoint.route(at, &meta(at), &trigger));
            endpoint.refuse_by_negotiation(at, incoming)
        };
        for _ in 0..ReplyLimiter::BURST {
            assert!(refuse(&mut endpoint, now).is_some());
        }
        assert!(refuse(&mut endpoint, now).is_none(), "the burst is spent");
        assert!(matches!(
            endpoint.route(now, &meta(now), &unknown_version(1200)),
            Route::Drop(RxDropReason::RateLimited)
        ));
        let later = now + Duration::from_millis(1);
        assert!(refuse(&mut endpoint, later).is_some(), "a token refilled");
    }

    #[test]
    fn connect_refuses_an_unspecified_remote_address() {
        let now = test_epoch();
        let config = Setup::default().pair();
        let mut endpoint = Endpoint::new(config.endpoint.clone(), None);
        let mut rng = TestRng::new(1);
        let mut cx = Inputs {
            now,
            unix_now: unix_now(),
            rng: &mut rng,
        };
        for remote in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4433),
            SocketAddr::new(server_addr().ip(), 0),
        ] {
            let error = endpoint
                .connect(
                    &mut cx,
                    KEY,
                    remote,
                    ServerName::try_from("localhost").unwrap(),
                    &config.client,
                    ConnOptions::default(),
                )
                .unwrap_err();
            assert!(matches!(error, ConnectError::InvalidRemoteAddress(r) if r == remote));
        }
        assert_eq!(endpoint.route_count(), 0);
    }
}
