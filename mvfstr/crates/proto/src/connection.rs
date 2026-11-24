/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A QUIC connection and its public operations.
//!
//! A [`Connection`] is plain data driven through `&mut self`. It is `Send`, so it can move between
//! threads, and `!Sync`; it does not use interior mutability or refer to the endpoint or other
//! connections. Every input is a method call, and the connection calls back only into the sink
//! and sealer passed to [`Connection::poll_transmit`].
//!
//! The submodules hold packet processing (`recv`: header protection, decryption, frame dispatch,
//! the TLS glue and key installation), the transmit attempt (`send`), the transport parameters
//! (`params`), 1-RTT key phases (`key_update`, RFC 9001) and path validation with passive migration
//! (`path`, RFC 9000). This module holds the state they share, the timers (one
//! [`Connection::next_deadline`] for loss and PTO, delayed ACKs, the idle timeout, the closing and
//! draining periods, key discard and path validation), the methods that close the connection
//! (RFC 9000), connection ID issuance and the key update policy.

#[cfg(test)]
mod cc_tests;
mod key_update;
#[cfg(test)]
mod manage_tests;
mod params;
mod path;
#[cfg(test)]
mod rate_tests;
mod recv;
mod send;
#[cfg(test)]
mod share_tests;
#[cfg(test)]
mod stream_tests;
mod streams;
#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use key_update::KeyPhases;
use mvfstr_crypto::KeySet;
use mvfstr_crypto::Sealer;
use mvfstr_tls::Level;
use mvfstr_tls::TlsError;
use mvfstr_tls::TlsSession;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::ResetToken;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::TransportParameters;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use path::AltPath;
use rustls::pki_types::ServerName;

use crate::AlpnPolicy;
use crate::AppCode;
use crate::CloseReason;
use crate::ConnEvent;
use crate::EndpointEvent;
use crate::Initiator;
use crate::KeyUpdatePolicy;
use crate::OpenError;
use crate::RecvSummary;
use crate::RxDatagram;
use crate::SegmentSink;
use crate::SendOrder;
use crate::StreamError;
use crate::StreamMut;
use crate::StreamReady;
use crate::TransportConfig;
use crate::TxExplain;
use crate::TxLimits;
use crate::TxOutcome;
use crate::TxReport;
use crate::cc::AckOrLoss;
use crate::cc::AckPart;
use crate::cc::Cc;
use crate::cc::CcConfig;
use crate::cc::CongestionSignal;
use crate::cid::CidGenerator;
use crate::cid::Cids;
use crate::cid::ConnRng;
use crate::cid::LocalCids;
use crate::cid::MAX_LOCAL_CIDS;
use crate::cid::PeerCids;
use crate::pacer::Pacer;
use crate::recovery::LossRecovery;
use crate::recovery::RecoveryConfig;
use crate::recovery::Space;
use crate::recovery::loss::TimeoutOutcome;
use crate::recovery::sent::LossSummary;
use crate::sources::CloseFrame;
use crate::sources::Sources;
use crate::sources::path::ALTERNATE;
use crate::sources::path::CURRENT;
use crate::streams::conn::StreamState;
use crate::streams::recv_buf::PagePool;
use crate::streams::recv_buf::RecvBuffer;

/// The smallest datagram every QUIC path carries, and the size of datagrams carrying a client's
/// Initial or any ack-eliciting Initial (RFC 9000).
pub(crate) const MIN_DATAGRAM: u16 = 1200;
/// The number of ACK ranges kept per space.
const MAX_ACK_RANGES: usize = 32;
/// The most packets kept until their keys arrive; RFC 9001 allows buffering a bounded number.
const MAX_BUFFERED: usize = 16;
/// The out-of-order CRYPTO bytes a level holds past the bytes TLS has read; RFC 9000 requires at
/// least 4,096.
const MAX_CRYPTO_BUFFER: u64 = 64 * 1024;
/// The timer granularity of loss recovery (RFC 9002).
const GRANULARITY: Duration = Duration::from_millis(1);

/// A connection error: the CONNECTION_CLOSE sent for a protocol violation or TLS failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnError {
    pub(crate) code: TransportErrorCode,
    pub(crate) frame_type: Option<VarInt>,
    pub(crate) reason: &'static str,
}

impl ConnError {
    pub(crate) fn new(code: TransportErrorCode, reason: &'static str) -> Self {
        Self {
            code,
            frame_type: None,
            reason,
        }
    }
}

/// One packet number space's keys and received CRYPTO bytes; its frame sources live in
/// [`Sources`].
#[derive(Debug, Default)]
struct PacketSpace {
    keys: Option<KeySet>,
    discarded: bool,
    crypto_recv: RecvBuffer,
}

/// Where the connection is in its life (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Handshaking or established.
    Open,
    /// Sent CONNECTION_CLOSE; answers received packets with it until `deadline`.
    Closing {
        deadline: Instant,
        /// Packets received since closing.
        received: u32,
        /// The received count at which the CLOSE is sent again; doubles each time.
        next_reply: u32,
    },
    /// The peer closed; the connection does not send until `deadline`.
    Draining { deadline: Instant },
    /// Gone: `Drained` has been reported.
    Drained,
}

/// The current path's address validation (RFC 9000).
#[derive(Clone, Copy, Debug, Default)]
struct PathCredit {
    validated: bool,
    received: u64,
    sent: u64,
}

impl PathCredit {
    /// Returns the bytes that may still be sent before validation: three times those received,
    /// less those sent, counting every byte of every datagram.
    fn credit(&self) -> u64 {
        if self.validated {
            u64::MAX
        } else {
            self.received.saturating_mul(3).saturating_sub(self.sent)
        }
    }
}

/// Handshake progress (RFC 9001).
#[derive(Debug, Default)]
struct Handshake {
    complete: bool,
    confirmed: bool,
    peer_params: Option<TransportParameters>,
}

/// The idle timer (RFC 9000).
#[derive(Clone, Copy, Debug)]
struct IdleTimer {
    /// When the timer last restarted.
    base: Instant,
    /// Whether an ack-eliciting packet was sent since the last packet was received; only the
    /// first one restarts the timer.
    sent_since_receive: bool,
}

/// A packet kept until its keys arrive.
#[derive(Debug)]
struct Buffered {
    space: Space,
    meta: crate::RxMeta,
    datagram_len: usize,
    data: Vec<u8>,
}

/// What a connection is created with; the endpoint builds it.
#[derive(Clone, Debug)]
pub(crate) struct ConnSetup {
    pub(crate) now: Instant,
    pub(crate) version: Version,
    pub(crate) transport: Arc<TransportConfig>,
    pub(crate) alpn: AlpnPolicy,
    pub(crate) remote: SocketAddr,
    pub(crate) local_ip: Option<IpAddr>,
    /// This endpoint's connection ID.
    pub(crate) local_cid: ConnectionId,
    /// The peer's connection ID; for a client, the random first Destination Connection ID.
    pub(crate) remote_cid: ConnectionId,
    /// The Destination Connection ID of the client's first Initial.
    pub(crate) original_dcid: ConnectionId,
    /// The generator of the connection's later connection IDs and their reset tokens.
    pub(crate) cids: CidGenerator,
    /// The seed of the connection's random source.
    pub(crate) rng_seed: [u8; 32],
}

/// One QUIC connection, client or server, created by
/// [`Endpoint::accept`](crate::Endpoint::accept) or [`Endpoint::connect`](crate::Endpoint::connect).
///
/// Dropping a connection does not send anything.
pub struct Connection {
    side: Side,
    version: Version,
    config: Arc<TransportConfig>,
    alpn_policy: AlpnPolicy,
    remote: SocketAddr,
    local_ip: Option<IpAddr>,
    local_cid: ConnectionId,
    original_dcid: ConnectionId,
    /// The Source Connection ID of the peer's first Initial, once known; the peer's
    /// initial_source_connection_id must match it (RFC 9000).
    peer_initial_scid: Option<ConnectionId>,
    tls: TlsSession,
    spaces: [PacketSpace; 3],
    sources: Sources,
    cid_gen: CidGenerator,
    rng: ConnRng,
    /// The 1-RTT key phases, once 1-RTT keys exist.
    key_phases: Option<KeyPhases>,
    /// The number of received packets that failed authentication, across all keys (RFC 9001).
    auth_failures: u64,
    /// The smallest integrity limit of the read keys installed so far.
    integrity_limit: u64,
    /// Whether authentication failures exceeded the integrity limit; packets then stay unopened.
    integrity_exceeded: bool,
    recovery: LossRecovery,
    cc: Cc,
    /// Whether the last transmit attempt left the window underused for want of data, so ACKs do
    /// not grow it.
    app_limited: bool,
    pacer: Pacer,
    path: PathCredit,
    alt: Option<AltPath>,
    /// The address a migration not yet validated left.
    migrated_from: Option<SocketAddr>,
    /// The largest 1-RTT packet number received in a packet with a non-probing frame.
    largest_non_probing: Option<u64>,
    /// The Destination Connection ID of the peer's latest such packet on the current path.
    rx_dcid: ConnectionId,
    handshake: Handshake,
    peer_ack_delay_exponent: u8,
    /// The size of the datagrams built.
    mtu: u16,
    idle: IdleTimer,
    state: State,
    shutdown: bool,
    events: VecDeque<ConnEvent>,
    endpoint_events: VecDeque<EndpointEvent>,
    /// The peer reset tokens last reported to the endpoint.
    reported_tokens: [Option<(SocketAddr, ResetToken)>; 2],
    buffered: VecDeque<Buffered>,
    /// Whether keys or handshake progress may have made buffered packets processable.
    replay_due: bool,
    crypto_pool: PagePool,
    /// TLS output, reused.
    tls_out: Vec<u8>,
    /// The sent-frame records of the packets being built, one list per space, reused.
    sent_frames: [Vec<crate::recovery::SentFrame>; 3],
    /// The sequence number of the next datagram built.
    tx_seq: u64,
    stats: ConnStats,
    /// The latest time passed to a receive batch, transmit attempt or timer: the clock of the
    /// stream API's flow-control updates.
    now: Instant,
    /// `Cell` makes the connection `!Sync` while keeping it `Send`.
    _not_sync: PhantomData<Cell<()>>,
}

impl Connection {
    /// Creates a client connection and its ClientHello.
    pub(crate) fn client(
        setup: ConnSetup,
        tls: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, TlsError> {
        let params = params::local_params(
            &setup.transport,
            params::LocalIds {
                initial_scid: setup.local_cid,
                original_dcid: None,
                reset_token: None,
            },
        );
        let session = TlsSession::client(tls, setup.version, server_name, encode(&params))?;
        let mut conn = Self::new(Side::Client, setup, session)?;
        // A client does not need to validate the path, which it chose.
        conn.path.validated = true;
        let now = conn.idle.base;
        if let Err(error) = conn.drain_tls() {
            conn.close_on_error(now, error);
        }
        Ok(conn)
    }

    /// Creates a server connection for a client's first Initial, before processing it. With
    /// `without_alpn`, a ClientHello that does not offer ALPN gets that config instead of `tls`.
    pub(crate) fn server(
        setup: ConnSetup,
        tls: Arc<rustls::ServerConfig>,
        without_alpn: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<Self, TlsError> {
        let params = params::local_params(
            &setup.transport,
            params::LocalIds {
                initial_scid: setup.local_cid,
                original_dcid: Some(setup.original_dcid),
                // With zero-length IDs every connection would share one token.
                reset_token: (!setup.local_cid.is_empty())
                    .then(|| setup.cids.reset_token(&setup.local_cid)),
            },
        );
        let params = encode(&params);
        let session = match without_alpn {
            Some(without_alpn) => {
                TlsSession::server_choosing_by_alpn(tls, without_alpn, setup.version, params)?
            }
            None => TlsSession::server(tls, setup.version, params)?,
        };
        let peer_scid = setup.remote_cid;
        let mut conn = Self::new(Side::Server, setup, session)?;
        conn.peer_initial_scid = Some(peer_scid);
        Ok(conn)
    }

    fn new(side: Side, setup: ConnSetup, tls: TlsSession) -> Result<Self, TlsError> {
        let version = setup.version;
        let initial = mvfstr_crypto::initial_keys(version, &setup.original_dcid, side)
            .map_err(|_| TlsError::UnsupportedVersion(version))?;
        let config = setup.transport;
        let recovery_config = RecoveryConfig {
            initial_rtt: config.initial_rtt(),
            rate_samples: crate::cc::takes_rate_samples(config.congestion_control()),
            ..RecoveryConfig::default()
        };
        let recovery = LossRecovery::new(recovery_config, side, setup.now, [0; 3])
            .expect("should accept the RTT a validated transport config holds");
        let (cc, pacer) = congestion_state(&config, MIN_DATAGRAM, recovery.rtt().smoothed());
        let integrity_limit = initial.remote.integrity_limit();
        let mut spaces: [PacketSpace; 3] = Default::default();
        spaces[Space::Initial.index()].keys = Some(initial);
        let cids = Cids {
            local: LocalCids::new(setup.local_cid, setup.cids.reset_token(&setup.local_cid)),
            peer: PeerCids::new(setup.remote_cid, config.active_connection_id_limit()),
        };
        Ok(Self {
            side,
            version,
            alpn_policy: setup.alpn,
            remote: setup.remote,
            local_ip: setup.local_ip,
            local_cid: setup.local_cid,
            original_dcid: setup.original_dcid,
            peer_initial_scid: None,
            tls,
            spaces,
            sources: Sources::new(MAX_ACK_RANGES, StreamState::new(side, &config), cids),
            cid_gen: setup.cids,
            rng: ConnRng::new(setup.rng_seed),
            key_phases: None,
            auth_failures: 0,
            integrity_limit,
            integrity_exceeded: false,
            recovery,
            cc,
            app_limited: false,
            pacer,
            path: PathCredit::default(),
            alt: None,
            migrated_from: None,
            largest_non_probing: None,
            rx_dcid: setup.local_cid,
            handshake: Handshake::default(),
            peer_ack_delay_exponent: 3,
            mtu: MIN_DATAGRAM,
            idle: IdleTimer {
                base: setup.now,
                sent_since_receive: false,
            },
            state: State::Open,
            shutdown: false,
            events: VecDeque::with_capacity(8),
            endpoint_events: VecDeque::with_capacity(4),
            reported_tokens: [None; 2],
            buffered: VecDeque::new(),
            replay_due: false,
            crypto_pool: PagePool::new(),
            tls_out: Vec::new(),
            sent_frames: Default::default(),
            tx_seq: 0,
            stats: ConnStats::default(),
            now: setup.now,
            config,
            _not_sync: PhantomData,
        })
    }

    /// Processes every datagram routed to this connection in one receive batch: removes header
    /// protection, decrypts in place, discards duplicates, dispatches frames, and makes the
    /// once-per-batch ACK decision. `now` is the batch's processing time; each datagram's
    /// receive time comes from its [`RxMeta`](crate::RxMeta).
    pub fn recv_batch(&mut self, now: Instant, datagrams: &mut [RxDatagram<'_>]) -> RecvSummary {
        self.now = self.now.max(now);
        let summary = self.receive(now, datagrams);
        self.refresh_pacing_rate();
        self.wake_writable();
        summary
    }

    /// Makes one transmit attempt: builds packets into slots from `sink`, seals each with
    /// `sealer`, and stops at the first limit, which the returned [`TxOutcome`] names. An attempt
    /// that does not build a packet does not change any state the next attempt depends on, with
    /// one exception: when sealing fails, the CRYPTO bytes the datagram held go back as lost, as
    /// for a lost packet, and the attempt ends [`Stop::Inconsistent`](crate::Stop::Inconsistent).
    pub fn poll_transmit<S: SegmentSink, Z: Sealer>(
        &mut self,
        limits: &TxLimits,
        sink: &mut S,
        sealer: &mut Z,
    ) -> TxOutcome {
        self.now = self.now.max(limits.now);
        let outcome = self.transmit(limits, sink, sealer);
        self.wake_writable();
        outcome
    }

    /// Applies a backend's report about datagrams this connection built: the packets of dropped
    /// datagrams are declared lost at once, without a congestion response.
    pub fn on_tx_report(&mut self, _now: Instant, report: TxReport) {
        let TxReport::Dropped { tx, .. } = report else {
            return;
        };
        let Self {
            recovery,
            sources,
            stats,
            ..
        } = self;
        let lost = recovery.on_tx_dropped(tx, |event| {
            sources.on_packet_event(None, event, true);
        });
        stats.lost_packets += u64::from(lost.lost_packets);
    }

    /// Describes what [`poll_transmit`](Self::poll_transmit) would do now and why, without
    /// changing anything.
    pub fn explain_transmit(&self, limits: &TxLimits) -> TxExplain {
        self.explain(limits)
    }

    /// Returns the earliest time [`on_deadline`](Self::on_deadline) must run: loss detection or
    /// PTO, ACK delay, idle timeout, drain, key discard and path validation. Pacing is not
    /// included; it comes from [`TxOutcome::pacing_at`].
    pub fn next_deadline(&self) -> Option<Instant> {
        match self.state {
            State::Closing { deadline, .. } | State::Draining { deadline } => {
                return Some(deadline);
            }
            State::Drained => return None,
            State::Open => {}
        }
        let loss = self
            .recovery
            .loss_detection_timer(self.amplification_blocked())
            .map(|(at, _)| at);
        let acks = self.sources.ack.iter().filter_map(|ack| ack.deadline());
        let key_discard = self.key_phases.as_ref().and_then(KeyPhases::discard_at);
        [
            self.idle_deadline(),
            loss,
            key_discard,
            self.path_deadline(),
        ]
        .into_iter()
        .flatten()
        .chain(acks)
        .min()
    }

    /// Runs every timer due at `now`.
    pub fn on_deadline(&mut self, now: Instant) {
        self.now = self.now.max(now);
        match self.state {
            State::Closing { deadline, .. } | State::Draining { deadline } => {
                if now >= deadline {
                    self.drained();
                }
                return;
            }
            State::Drained => return,
            State::Open => {}
        }
        if self.idle_deadline().is_some_and(|at| now >= at) {
            self.push_event(ConnEvent::Closed {
                reason: CloseReason::Silent,
                initiator: Initiator::IdleTimeout,
            });
            self.drained();
            return;
        }
        for ack in &mut self.sources.ack {
            ack.on_deadline(now);
        }
        if let Some(phases) = &mut self.key_phases {
            phases.discard_due(now);
        }
        self.on_path_deadline(now);
        self.check_retire_bound(now);
        if self.state != State::Open {
            return;
        }
        let amplification_blocked = self.amplification_blocked();
        let Self {
            recovery,
            sources,
            stats,
            cc,
            ..
        } = self;
        let outcome = recovery.on_timeout(now, amplification_blocked, |event| {
            sources.on_packet_event(None, event, false);
        });
        match outcome {
            TimeoutOutcome::Lost(_, lost) => {
                stats.lost_packets += u64::from(lost.lost_packets);
                on_losses(cc, now, &lost);
                if recovery.takes_rate_samples() {
                    on_ack_or_loss(cc, recovery, now, None, &lost, 0);
                }
            }
            TimeoutOutcome::Probe(_) => {
                // A probe in a handshake space carries the unacknowledged CRYPTO bytes, so one
                // lost flight does not wait for loss detection (RFC 9002).
                for space in [Space::Initial, Space::Handshake] {
                    if recovery.probes_due(space) > 0 {
                        sources.crypto[space.index()].resend_unacked();
                    }
                }
                // Each 1-RTT probe carries the frames of the oldest packet still in flight that
                // has any left to send, and a PING only when it cannot carry anything else.
                let mut left = recovery.probes_due(Space::Data);
                for packet in recovery.space(Space::Data).outstanding() {
                    if left == 0 {
                        break;
                    }
                    if sources.requeue(packet) {
                        left -= 1;
                    }
                }
            }
            TimeoutOutcome::None => {}
        }
        self.refresh_pacing_rate();
    }

    /// Opens a stream in direction `dir` at place `order` in the wire order.
    pub fn open_stream(&mut self, dir: Dir, order: SendOrder) -> Result<StreamId, OpenError> {
        if self.state != State::Open {
            return Err(OpenError::Closed);
        }
        self.sources.streams.open(dir, order)
    }

    /// Gives mutable access to an open stream.
    pub fn stream(&mut self, id: StreamId) -> Result<StreamMut<'_>, StreamError> {
        if !self.sources.streams.is_open(id) {
            return Err(StreamError::Closed);
        }
        Ok(StreamMut::new(self, id))
    }

    /// Drains the streams whose readiness changed since the last call, each with its edge.
    pub fn readiness(&mut self) -> Readiness<'_> {
        Readiness { conn: self }
    }

    /// Returns the streams whose producer should be polled for data, in wire order, each with its
    /// allowance. A stream with room is listed from [`StreamMut::wake_producer`] until
    /// [`StreamMut::park_producer`].
    pub fn pull_ready(&mut self) -> PullReady<'_> {
        let budget = self.staging_budget();
        self.sources.streams.collect_pull_ready(budget);
        PullReady {
            conn: self,
            index: 0,
        }
    }

    /// Sends a PING in a 1-RTT packet, once 1-RTT keys exist: an application keepalive or RTT
    /// probe.
    pub fn ping(&mut self) {
        if self.state == State::Open {
            self.sources.ping.queue();
        }
    }

    /// Takes the next connection event, if any.
    pub fn poll_event(&mut self) -> Option<ConnEvent> {
        self.events.pop_front()
    }

    /// Takes the next fact for the endpoint's routing table, if any.
    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        // The tokens follow every change of path or peer ID, wherever it happened.
        if self.state != State::Drained {
            let tokens = self.peer_tokens();
            if tokens != self.reported_tokens {
                self.reported_tokens = tokens;
                let [current, alternate] = tokens;
                self.endpoint_events
                    .push_back(EndpointEvent::PeerResetTokens { current, alternate });
            }
        }
        self.endpoint_events.pop_front()
    }

    /// Closes the connection with an application CONNECTION_CLOSE and enters the closing period
    /// of three PTOs, or the draining period if the peer's CONNECTION_CLOSE arrives (RFC 9000).
    pub fn close(&mut self, now: Instant, code: AppCode, reason: Bytes) {
        let frame = CloseFrame::Application {
            code: code.0,
            reason: reason.clone(),
        };
        self.enter_closing(
            now,
            frame,
            CloseReason::Application { code, reason },
            Initiator::Local,
        );
    }

    /// Closes the connection with a transport CONNECTION_CLOSE carrying `code`, such as NO_ERROR
    /// for a graceful shutdown, and enters the closing period.
    pub fn close_transport(&mut self, now: Instant, code: TransportErrorCode, reason: Bytes) {
        let frame = CloseFrame::Transport {
            code,
            frame_type: VarInt::ZERO,
            reason: reason.clone(),
        };
        let close = CloseReason::Transport {
            code,
            frame_type: None,
            reason,
        };
        self.enter_closing(now, frame, close, Initiator::Local);
    }

    /// Stops accepting new streams (MAX_STREAMS is frozen) and lets open streams finish; the
    /// application decides whether to send its own GOAWAY.
    pub fn shutdown(&mut self, _now: Instant) {
        self.shutdown = true;
        self.sources.streams.streams.shutdown();
    }

    /// Ends the connection at once without sending anything: `Closed` and then `Drained` follow.
    pub fn abort(&mut self) {
        match self.state {
            State::Drained => return,
            State::Open => self.push_event(ConnEvent::Closed {
                reason: CloseReason::Silent,
                initiator: Initiator::Local,
            }),
            State::Closing { .. } | State::Draining { .. } => {}
        }
        self.drained();
    }

    /// Returns this endpoint's role.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Returns the negotiated QUIC version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the peer's address on the current path.
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }

    /// Returns the negotiated ALPN protocol, once the handshake has agreed on one.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }

    /// Returns counters and current values for logs and benchmarks.
    pub fn stats(&self) -> ConnStats {
        ConnStats {
            cwnd: self.cc.cwnd(),
            bytes_in_flight: self.recovery.bytes_in_flight(),
            smoothed_rtt: self.recovery.rtt().smoothed(),
            ..self.stats
        }
    }

    /// Paces at the congestion controller's rate for the current window and RTT.
    fn refresh_pacing_rate(&mut self) {
        let rate = self.cc.pacing_rate(self.recovery.rtt().smoothed());
        self.pacer.set_rate(rate);
    }

    /// Returns the peer's connection ID in use on the current path, for a test where it has one.
    #[cfg(test)]
    fn remote_cid(&self) -> ConnectionId {
        self.dcid_of(crate::PathId(0))
            .expect("a test of a current path with a peer ID")
    }

    /// Returns whether `space` has its write key.
    fn has_keys(&self, space: Space) -> bool {
        self.spaces[space.index()].keys.is_some()
    }

    /// Returns, for each space, whether this endpoint holds its keys.
    fn keyed_spaces(&self) -> [bool; 3] {
        Space::ALL.map(|space| self.has_keys(space))
    }

    /// Returns whether a server is at its anti-amplification limit, so that it cannot send a
    /// probe and must not arm the PTO (RFC 9002). A probe carrying an Initial takes a 1,200-byte
    /// datagram; a Handshake probe needs only a short packet.
    fn amplification_blocked(&self) -> bool {
        let probe = if self
            .recovery
            .space(Space::Initial)
            .ack_eliciting_in_flight()
            > 0
        {
            usize::from(MIN_DATAGRAM)
        } else {
            self.min_packet_len(Space::Handshake)
        };
        self.path.credit() < probe as u64
    }

    /// Returns the PTO without backoff, the base of the closing, draining and idle periods.
    fn pto_interval(&self) -> Duration {
        self.recovery.rtt().pto_base(GRANULARITY) + self.peer_max_ack_delay()
    }

    /// Returns the peer's max_ack_delay, 25 ms until its transport parameters arrive (RFC 9000).
    fn peer_max_ack_delay(&self) -> Duration {
        self.handshake
            .peer_params
            .as_ref()
            .map_or(Duration::from_millis(25), |p| {
                Duration::from_millis(p.max_ack_delay.into_inner())
            })
    }

    /// Returns the effective idle timeout: the smaller of both endpoints' non-zero values, and at
    /// least three PTOs (RFC 9000).
    fn idle_timeout(&self) -> Option<Duration> {
        let peer = self
            .handshake
            .peer_params
            .as_ref()
            .map(|p| p.max_idle_timeout.into_inner())
            .filter(|&millis| millis > 0)
            .map(Duration::from_millis);
        let timeout = match (self.config.idle_timeout(), peer) {
            (Some(local), Some(peer)) => local.min(peer),
            (local, peer) => local.or(peer)?,
        };
        Some(timeout.max(3 * self.pto_interval()))
    }

    fn idle_deadline(&self) -> Option<Instant> {
        self.idle_timeout().map(|timeout| self.idle.base + timeout)
    }

    /// Queues a connection event unless an equal one is queued, so the queue stays bounded.
    fn push_event(&mut self, event: ConnEvent) {
        if !self.events.contains(&event) {
            self.events.push_back(event);
        }
    }

    /// Closes the connection on a protocol violation or TLS failure.
    fn close_on_error(&mut self, now: Instant, error: ConnError) {
        let initiator = if error.code == TransportErrorCode::INTERNAL_ERROR {
            Initiator::Internal
        } else {
            Initiator::Local
        };
        let reason = Bytes::from_static(error.reason.as_bytes());
        let frame = CloseFrame::Transport {
            code: error.code,
            frame_type: error.frame_type.unwrap_or(VarInt::ZERO),
            reason: reason.clone(),
        };
        let close = CloseReason::Transport {
            code: error.code,
            frame_type: error.frame_type,
            reason,
        };
        self.enter_closing(now, frame, close, initiator);
    }

    /// Enters the closing state and queues `frame` in every space the peer may have keys for
    /// (RFC 9000).
    fn enter_closing(
        &mut self,
        now: Instant,
        frame: CloseFrame,
        reason: CloseReason,
        initiator: Initiator,
    ) {
        if self.state != State::Open {
            return;
        }
        // A current path that waits for a peer connection ID lacks one for the CLOSE's header,
        // so the connection drains without sending it.
        if self.dcid_of(crate::PathId(0)).is_none() {
            self.enter_draining(now, reason, initiator);
            return;
        }
        self.sources.close.start(frame, self.keyed_spaces());
        self.state = State::Closing {
            deadline: now + 3 * self.pto_interval(),
            received: 0,
            next_reply: 1,
        };
        self.push_event(ConnEvent::Closed { reason, initiator });
    }

    /// Enters the draining state, for three PTOs or until the closing deadline if already closing,
    /// after the peer's CONNECTION_CLOSE, a stateless reset or a close that cannot be sent. A
    /// draining connection does not send (RFC 9000).
    fn enter_draining(&mut self, now: Instant, reason: CloseReason, initiator: Initiator) {
        let deadline = match self.state {
            State::Open => {
                self.push_event(ConnEvent::Closed { reason, initiator });
                now + 3 * self.pto_interval()
            }
            State::Closing { deadline, .. } => deadline,
            State::Draining { .. } | State::Drained => return,
        };
        self.sources.close = Default::default();
        self.state = State::Draining { deadline };
    }

    /// Counts a packet received while closing and queues the CLOSE again after 1, 2, 4, ... such
    /// packets, so a peer that keeps sending cannot make this endpoint amplify (RFC 9000).
    fn on_packet_while_closing(&mut self) {
        let State::Closing {
            received,
            next_reply,
            ..
        } = &mut self.state
        else {
            return;
        };
        *received += 1;
        if *received >= *next_reply {
            *next_reply = next_reply.saturating_mul(2);
            let spaces = self.keyed_spaces();
            self.sources.close.owe_again(spaces);
        }
    }

    /// Ends the connection and reports `Drained` to the application and the endpoint.
    fn drained(&mut self) {
        self.state = State::Drained;
        self.sources.close = Default::default();
        self.push_event(ConnEvent::Drained);
        self.endpoint_events.push_back(EndpointEvent::Drained);
    }

    /// Issues local connection IDs until the peer holds as many as its
    /// active_connection_id_limit allows, at most [`MAX_LOCAL_CIDS`] (RFC 9000). A
    /// zero-length ID cannot be replaced.
    fn issue_cids(&mut self) {
        let Some(peer) = &self.handshake.peer_params else {
            return;
        };
        if self.local_cid.is_empty() {
            return;
        }
        let limit = peer
            .active_connection_id_limit
            .into_inner()
            .min(MAX_LOCAL_CIDS);
        while self.sources.cids.local.active() < limit {
            let Some((cid, reset_token)) = self
                .sources
                .cids
                .local
                .issue_new(&self.cid_gen, &mut self.rng)
            else {
                break;
            };
            self.endpoint_events
                .push_back(EndpointEvent::NewLocalCid { cid, reset_token });
        }
    }

    /// Initiates a key update: the next 1-RTT keys become current in both directions, and the
    /// current read keys stay for delayed packets (RFC 9001).
    fn initiate_key_update(&mut self) {
        let (Some(phases), Some(keys)) = (
            &mut self.key_phases,
            &mut self.spaces[Space::Data.index()].keys,
        ) else {
            return;
        };
        phases.advance(keys, None);
    }

    /// Initiates a key update when the policy and RFC 9001 allow, after packets were sealed with
    /// the current keys; closes the connection when the keys near their confidentiality limit and
    /// cannot be updated.
    fn maybe_update_keys(&mut self, now: Instant) {
        if self.state != State::Open {
            return;
        }
        let Some(phases) = &self.key_phases else {
            return;
        };
        let at_limit = phases.confidentiality_limit / 5 * 4;
        let reason = if self.version == Version::MVFST {
            if phases.sealed < at_limit {
                return;
            }
            "an MVFST connection does not initiate key updates"
        } else {
            let interval = match self.config.key_update() {
                KeyUpdatePolicy::Every(packets) => packets.min(at_limit),
                KeyUpdatePolicy::AtLimit => at_limit,
            };
            if phases.sealed < interval {
                return;
            }
            if self.handshake.confirmed && phases.may_initiate(now, 3 * self.pto_interval()) {
                self.initiate_key_update();
                return;
            }
            if phases.sealed < phases.confidentiality_limit / 10 * 9 {
                return;
            }
            "no key update is allowed before the confidentiality limit"
        };
        self.close_on_error(
            now,
            ConnError::new(TransportErrorCode::AEAD_LIMIT_REACHED, reason),
        );
    }

    /// Returns the stateless reset tokens of the peer IDs in use, each with the address it is used
    /// at: the current path's and the alternate path's (RFC 9000).
    fn peer_tokens(&self) -> [Option<(SocketAddr, ResetToken)>; 2] {
        let ids = &self.sources.cids.peer;
        let current = ids.token_of(CURRENT).map(|token| (self.remote, token));
        let alternate = self
            .alt
            .and_then(|alt| ids.token_of(ALTERNATE).map(|token| (alt.remote, token)));
        [current, alternate]
    }

    /// Discards the keys and all state of `space` (RFC 9001, RFC 9002).
    fn discard_space(&mut self, space: Space, now: Instant) {
        let state = &mut self.spaces[space.index()];
        if state.discarded {
            return;
        }
        state.discarded = true;
        state.keys = None;
        state.crypto_recv = RecvBuffer::new();
        self.sources.discard(space, MAX_ACK_RANGES);
        self.recovery.discard_space(space, now);
        self.buffered.retain(|packet| packet.space != space);
    }
}

/// Returns the state a path starts with: `config`'s congestion controller for datagrams of
/// `max_datagram_size` bytes, and a pacer at its rate for a smoothed RTT of `rtt`.
fn congestion_state(
    config: &TransportConfig,
    max_datagram_size: u16,
    rtt: Duration,
) -> (Cc, Pacer) {
    let windows = CcConfig {
        initial_window_packets: config.initial_window(),
        min_window_packets: config.min_window(),
        max_window_packets: config.max_window(),
        ..CcConfig::default()
    };
    let cc = Cc::new(config.congestion_control(), &windows, max_datagram_size)
        .expect("should accept a validated config's windows and datagrams of at least 1,200 bytes");
    let pacer = Pacer::new(max_datagram_size, GRANULARITY, cc.pacing_rate(rtt));
    (cc, pacer)
}

/// Reports to `cc` the losses loss detection declared at `now`.
fn on_losses(cc: &mut Cc, now: Instant, loss: &LossSummary) {
    if let Some(sent) = loss.largest_lost_sent {
        cc.on_congestion_event(now, sent, CongestionSignal::Loss);
    }
    if loss.persistent_congestion {
        cc.on_persistent_congestion();
    }
}

/// Gives a controller that takes rate samples one ACK frame, with its `ack` part, or one loss
/// timeout, without, as of `now`: `loss` is what loss detection declared and `spurious` the
/// in-flight packets acknowledged after being declared lost. As in mvfst, only an event that
/// newly acknowledged an on-path in-flight packet, declared an in-flight packet lost or
/// acknowledged a spurious loss reaches it. Marks the connection app-limited when the controller
/// returns true.
fn on_ack_or_loss(
    cc: &mut Cc,
    recovery: &mut LossRecovery,
    now: Instant,
    ack: Option<AckPart>,
    loss: &LossSummary,
    spurious: u32,
) {
    if ack.and_then(|a| a.largest_acked_sent).is_none() && loss.newly_lost == 0 && spurious == 0 {
        return;
    }
    let event = AckOrLoss {
        now,
        ack,
        delivered: recovery.delivered(),
        total_sent: recovery.total_sent(),
        bytes_in_flight: recovery.bytes_in_flight(),
        lost: recovery.lost_samples(),
        largest_lost_sent: loss.largest_lost_sent,
        persistent_congestion: loss.persistent_congestion,
        spurious,
        newly_lost: loss.newly_lost,
        declared_lost: recovery.declared_lost(),
    };
    if cc.on_ack_or_loss(&event) {
        recovery.mark_app_limited();
    }
}

/// Returns the space of an encryption level.
fn level_space(level: Level) -> Space {
    match level {
        Level::Initial => Space::Initial,
        Level::Handshake => Space::Handshake,
        Level::OneRtt => Space::Data,
    }
}

/// Encodes transport parameters a validated config produced.
fn encode(params: &TransportParameters) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    params
        .encode(&mut out)
        .expect("should encode the parameters of a validated transport config");
    out
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("version", &self.version)
            .field("remote", &self.remote)
            .field("state", &self.state)
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

/// Streams whose readiness changed, from [`Connection::readiness`].
pub struct Readiness<'a> {
    conn: &'a mut Connection,
}

impl Iterator for Readiness<'_> {
    type Item = (StreamId, StreamReady);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(edge) = self.conn.sources.streams.next_edge() {
            return Some(edge);
        }
        // A sender that got a `Writable` edge but did not stage bytes no longer holds its room, so
        // the refused senders after it may be woken now.
        if !self.conn.sources.streams.take_rewake() {
            return None;
        }
        self.conn.wake_writable();
        self.conn.sources.streams.next_edge()
    }
}

impl fmt::Debug for Readiness<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Readiness").finish_non_exhaustive()
    }
}

/// Streams ready to be polled for data with their allowances, from
/// [`Connection::pull_ready`].
pub struct PullReady<'a> {
    conn: &'a mut Connection,
    /// The index of the next collected stream.
    index: usize,
}

impl Iterator for PullReady<'_> {
    type Item = (StreamId, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let (id, allowance) = self.conn.sources.streams.pulled(self.index)?;
        self.index += 1;
        Some((id, usize::try_from(allowance).unwrap_or(usize::MAX)))
    }
}

impl fmt::Debug for PullReady<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullReady").finish_non_exhaustive()
    }
}

/// Connection counters and current values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// Packets sent.
    pub sent_packets: u64,
    /// Bytes sent in UDP payloads.
    pub sent_bytes: u64,
    /// Packets declared lost.
    pub lost_packets: u64,
    /// Packets received and processed.
    pub recv_packets: u64,
    /// Bytes received in UDP payloads.
    pub recv_bytes: u64,
    /// The congestion window in bytes.
    pub cwnd: u64,
    /// Bytes in flight.
    pub bytes_in_flight: u64,
    /// The smoothed RTT.
    pub smoothed_rtt: Duration,
    /// Candidates that did not fit an empty packet and were skipped; expected to stay zero.
    pub tx_inconsistent: u64,
}
