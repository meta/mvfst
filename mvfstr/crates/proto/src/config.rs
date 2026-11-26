/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Endpoint, transport, server and client configuration.
//!
//! Configs are immutable once built: each builder validates its values and returns an `Arc`,
//! which endpoints and connections share. [`ConnOptions`] carries per-connection overrides,
//! chosen when a connection is accepted or opened.

use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;
use rustls::crypto::SecureRandom;
use rustls::pki_types::ServerName;

use crate::cid::CidLayout;
use crate::endpoint::HEALTH_CHECK_ANSWER;
use crate::recovery::RecoveryConfig;

/// Why a builder refused its values.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigError {
    /// A value is outside the range RFC 9000 or the field allows.
    OutOfRange {
        /// The builder method that set the value.
        field: &'static str,
    },
    /// The version list is empty.
    NoVersions,
    /// The version list names a version mvfstr does not implement.
    UnsupportedVersion(Version),
    /// The version list names a version twice.
    DuplicateVersion(Version),
    /// A server's version list leaves out version 1, which every server accepts.
    Version1Required,
    /// The rustls config's crypto provider does not offer a TLS 1.3 cipher suite usable for QUIC.
    NoQuicCipherSuite,
    /// [`AlpnPolicy::Required`] with a rustls config that does not list any ALPN protocols.
    AlpnRequiredWithoutProtocols,
    /// The rustls config enables early data; 0-RTT is not supported.
    EarlyDataUnsupported,
    /// rustls refuses to create a QUIC connection with the config, for example because it does
    /// not enable TLS 1.3.
    Tls(rustls::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { field } => write!(f, "`{field}` is out of range"),
            Self::NoVersions => f.write_str("no QUIC versions configured"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported QUIC version {version:?}"),
            Self::DuplicateVersion(version) => write!(f, "QUIC version {version:?} listed twice"),
            Self::Version1Required => f.write_str("a server must accept QUIC version 1"),
            Self::NoQuicCipherSuite => f.write_str("no TLS 1.3 cipher suite usable for QUIC"),
            Self::AlpnRequiredWithoutProtocols => {
                f.write_str("ALPN is required but the TLS config lists no protocols")
            }
            Self::EarlyDataUnsupported => f.write_str("0-RTT early data is not supported"),
            Self::Tls(error) => write!(f, "rustls refuses the config for QUIC: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tls(error) => Some(error),
            _ => None,
        }
    }
}

/// The fewest random bytes a [`CidLayout::Random`] ID holds besides the byte that names the worker.
const MIN_RANDOM_CID_BYTES: u8 = 6;

/// Settings shared by every connection of an endpoint.
#[derive(Clone)]
pub struct EndpointConfig {
    local_cid_len: u8,
    reset_key: [u8; 32],
    worker_index: u16,
    worker_count: u16,
    build_horizon: Duration,
    health_check_token: Option<Bytes>,
    cid_layout: CidLayout,
}

impl EndpointConfig {
    /// Starts a builder. `reset_key` is the secret from which stateless reset tokens are derived
    /// (RFC 9000); the core takes randomness only as an input, so the caller supplies it.
    pub fn builder(reset_key: [u8; 32]) -> EndpointConfigBuilder {
        EndpointConfigBuilder {
            config: EndpointConfig {
                local_cid_len: 8,
                reset_key,
                worker_index: 0,
                worker_count: 1,
                build_horizon: Duration::ZERO,
                health_check_token: None,
                cid_layout: CidLayout::Random,
            },
        }
    }

    /// Returns the length of the connection IDs this endpoint issues.
    pub fn local_cid_len(&self) -> usize {
        usize::from(self.local_cid_len)
    }

    /// Returns the stateless reset secret. Keep it out of logs.
    pub fn reset_key(&self) -> &[u8; 32] {
        &self.reset_key
    }

    /// Returns this endpoint's worker index and the number of workers that share its address.
    pub fn worker(&self) -> (u16, u16) {
        (self.worker_index, self.worker_count)
    }

    /// Returns how far ahead of its release a server connection may build a datagram, before the
    /// backend's release horizon caps it.
    pub fn build_horizon(&self) -> Duration {
        self.build_horizon
    }

    /// Returns the datagram a server endpoint answers with "OK", if any.
    pub fn health_check_token(&self) -> Option<&[u8]> {
        self.health_check_token.as_deref()
    }

    /// Returns the layout of the connection IDs this endpoint issues.
    pub fn cid_layout(&self) -> CidLayout {
        self.cid_layout
    }

    /// Returns a builder that starts from these settings, for a config that changes only a few of
    /// them, such as one per worker.
    pub fn to_builder(&self) -> EndpointConfigBuilder {
        EndpointConfigBuilder {
            config: self.clone(),
        }
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointConfig")
            .field("local_cid_len", &self.local_cid_len)
            .field("worker_index", &self.worker_index)
            .field("worker_count", &self.worker_count)
            .field("build_horizon", &self.build_horizon)
            .field("health_check_token", &self.health_check_token)
            .field("cid_layout", &self.cid_layout)
            .finish_non_exhaustive()
    }
}

/// A builder for an [`EndpointConfig`].
#[derive(Clone, Debug)]
pub struct EndpointConfigBuilder {
    config: EndpointConfig,
}

impl EndpointConfigBuilder {
    /// Sets the length of the connection IDs this endpoint issues: 0, or 6 to 20 bytes with one
    /// worker and 7 to 20 with several, so a nonempty [`CidLayout::Random`] ID holds at least 6
    /// random bytes. Default 8. [`CidLayout::MvfstV2`] requires 8, and its IDs hold 29 random bits.
    pub fn local_cid_len(mut self, len: usize) -> Self {
        self.config.local_cid_len = u8::try_from(len).unwrap_or(u8::MAX);
        self
    }

    /// Makes this endpoint worker `index` of `count` workers, at most 256, that share the address.
    /// With several, each ID it issues names the worker in its first byte, or in byte 4 under
    /// [`CidLayout::MvfstV2`], and short-header packets that name another worker are dropped rather
    /// than answered. Default: worker 0 of 1.
    pub fn worker(mut self, index: u16, count: u16) -> Self {
        self.config.worker_index = index;
        self.config.worker_count = count;
        self
    }

    /// Sets how far ahead of its release a connection this endpoint accepts may build a datagram.
    /// Each accepted connection fixes the smaller of this and the release horizon its backend
    /// supports, set with [`Endpoint::set_release_horizon`](crate::Endpoint::set_release_horizon),
    /// at creation, lowered if needed to keep its advertised max_ack_delay below 2^14 ms; without
    /// release support it is 0. Default 0: datagrams are built once due.
    pub fn build_horizon(mut self, horizon: Duration) -> Self {
        self.config.build_horizon = horizon;
        self
    }

    /// Makes a server endpoint answer `token`, sent as a datagram that is not a QUIC packet, with
    /// a datagram of "OK", as mvfst servers answer their health check token; proxygen's is
    /// "health". The token must be at least as long as the answer, so that the answer never
    /// amplifies. By default, the endpoint does not answer health checks.
    pub fn health_check_token(mut self, token: impl Into<Bytes>) -> Self {
        self.config.health_check_token = Some(token.into());
        self
    }

    /// Sets the layout of the connection IDs this endpoint issues. Default [`CidLayout::Random`].
    pub fn cid_layout(mut self, layout: CidLayout) -> Self {
        self.config.cid_layout = layout;
        self
    }

    /// Validates the settings.
    pub fn build(self) -> Result<Arc<EndpointConfig>, ConfigError> {
        if self.config.local_cid_len() > ConnectionId::MAX_LEN {
            return Err(ConfigError::OutOfRange {
                field: "local_cid_len",
            });
        }
        let EndpointConfig {
            local_cid_len,
            worker_index,
            worker_count,
            cid_layout,
            ..
        } = self.config;
        let one_byte_names_the_worker = worker_count <= 256 && worker_index < worker_count;
        if !one_byte_names_the_worker || (worker_count > 1 && local_cid_len == 0) {
            return Err(ConfigError::OutOfRange { field: "worker" });
        }
        if matches!(cid_layout, CidLayout::MvfstV2 { .. }) && local_cid_len != 8 {
            return Err(ConfigError::OutOfRange {
                field: "cid_layout",
            });
        }
        // A connection issues random IDs without access to the endpoint's routes, so only enough
        // randomness keeps its IDs distinct from each other and from other connections' IDs. The
        // version 2 layout has mvfst's 29 random bits instead.
        let random_bytes = if worker_count > 1 {
            local_cid_len.saturating_sub(1)
        } else {
            local_cid_len
        };
        if local_cid_len > 0 && random_bytes < MIN_RANDOM_CID_BYTES {
            return Err(ConfigError::OutOfRange {
                field: "local_cid_len",
            });
        }
        if self
            .config
            .health_check_token
            .as_ref()
            .is_some_and(|token| token.len() < HEALTH_CHECK_ANSWER.len())
        {
            return Err(ConfigError::OutOfRange {
                field: "health_check_token",
            });
        }
        Ok(Arc::new(self.config))
    }
}

/// The congestion controller of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CongestionControl {
    /// NewReno (RFC 9002).
    NewReno,
    /// CUBIC (RFC 9438), the default of mvfst's tperf.
    #[default]
    Cubic,
    /// BBRv3 as mvfst's BBR3 behaves ([`crate::cc::bbr3`]); it needs pacing.
    Bbr3,
}

/// When to acknowledge (RFC 9000). The thresholds and the timer follow mvfst's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckPolicy {
    /// The largest packet number received up to which `before_init` applies; above it,
    /// `after_init` does. Default 100.
    pub init_threshold: u64,
    /// The number of unacknowledged ack-eliciting packets that triggers an acknowledgment while
    /// the largest packet number received is at most `init_threshold`; at least 1. Default 10.
    pub before_init: u16,
    /// The number of unacknowledged ack-eliciting packets that triggers an acknowledgment once
    /// the largest packet number received is above `init_threshold`; at least 1. Default 10.
    pub after_init: u16,
    /// The longest we delay an acknowledgment, advertised as max_ack_delay in whole
    /// milliseconds rounded up; at most 2^14 - 1 ms. Default 25 ms.
    pub max_ack_delay: Duration,
    /// Whether the ACK timer is a quarter of the smoothed RTT, but at least 1 ms. It is at most
    /// max_ack_delay less 1 ms, which is its length when this is false. Default true.
    pub rtt_timer: bool,
    /// The ack_delay_exponent we advertise, at most 20. Default 3.
    pub ack_delay_exponent: u8,
}

impl Default for AckPolicy {
    fn default() -> Self {
        Self {
            init_threshold: 100,
            before_init: 10,
            after_init: 10,
            max_ack_delay: Duration::from_millis(25),
            rtt_timer: true,
            ack_delay_exponent: 3,
        }
    }
}

/// When to initiate a key update (RFC 9001). Peer-initiated updates are always answered. On MVFST
/// connections, but not on those of its alias, mvfstr never initiates and closes with
/// AEAD_LIMIT_REACHED at the limit instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyUpdatePolicy {
    /// Initiate only at 0.8 times the AEAD confidentiality limit.
    #[default]
    AtLimit,
    /// Also initiate after this many packets sealed with one key generation; at least 1.
    Every(u64),
}

/// Whether the TLS handshake must agree on an application protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AlpnPolicy {
    /// The handshake fails unless an ALPN protocol from the rustls config is agreed, as RFC 9001
    /// requires. The rustls config must list at least one protocol.
    #[default]
    Required,
    /// Also proceed when the peer does not offer ALPN (or, for a client, do not offer it when the
    /// rustls config's protocol list is empty). This violates RFC 9001 and exists for mvfst's
    /// tperf, whose client does not offer ALPN.
    AllowMissing,
}

/// The size of the datagrams a connection sends. Path MTU discovery is not supported, so mvfstr
/// does not check that the path carries a larger size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DatagramSize {
    /// 1,200 bytes, the size every QUIC path must carry (RFC 9000).
    #[default]
    Minimum,
    /// Once the peer's transport parameters are processed, the smaller of its
    /// max_udp_payload_size and ours, as mvfst's tperf does with `--override_packet_size`; 1,200
    /// bytes before that.
    PeerMaximum,
}

/// How a server connection lays out the transport parameters it sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ParamsLayout {
    /// In id order, leaving out the parameters at their defaults.
    #[default]
    Rfc,
    /// As an mvfst server sends them, so that the bytes match: in mvfst's order, every integer
    /// parameter written even at its default, max_ack_delay only when it is not 25 ms, and on
    /// MVFST and its alias without the connection ID parameters.
    MvfstServer,
}

/// When a client that is not sending anything else keeps its connection alive with a PING, once
/// the handshake is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepAlive {
    /// A PING whenever the client has not sent an ack-eliciting packet for this long; non-zero and
    /// at most 2^62 - 1 milliseconds, the range of the idle timeout.
    Interval(Duration),
    /// An interval from the negotiated idle timeout, as mvfst computes it: 85% of the smaller
    /// non-zero max_idle_timeout of the two sides, in whole milliseconds. The client does not send
    /// keepalives when neither side has an idle timeout.
    NegotiatedIdle,
}

/// Transport settings of a connection: what it advertises in its transport parameters and how
/// it sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    max_data: u64,
    max_data_autotune: Option<u64>,
    max_stream_data_bidi_local: u64,
    max_stream_data_bidi_remote: u64,
    max_stream_data_uni: u64,
    max_stream_data_autotune: Option<u64>,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    idle_timeout: Option<Duration>,
    max_udp_payload_size: u16,
    ack_policy: AckPolicy,
    congestion_control: CongestionControl,
    pacing: bool,
    pacing_granularity: Duration,
    pacing_min_burst: u16,
    pacing_max_burst: u16,
    initial_window: u32,
    min_window: u32,
    max_window: u32,
    initial_rtt: Duration,
    active_connection_id_limit: u64,
    key_update: KeyUpdatePolicy,
    datagram_size: DatagramSize,
    buffered_packets: usize,
    disable_active_migration: bool,
    params_layout: ParamsLayout,
    extra_params: Vec<(VarInt, Bytes)>,
    keep_alive: Option<KeepAlive>,
    max_ptos: Option<u32>,
    max_datagram_frame_size: u64,
    datagram_send_queue: usize,
    datagram_recv_queue: usize,
    stream_ack_progress: bool,
}

/// The largest transport parameter id RFC 9000 defines, retry_source_connection_id.
const LAST_RFC9000_PARAM: u64 = 0x10;

/// The id of max_datagram_frame_size (RFC 9221).
const MAX_DATAGRAM_FRAME_SIZE_PARAM: u64 = 0x20;

/// mvfst's default stream window, 65 KiB.
const DEFAULT_STREAM_WINDOW: u64 = 65 * 1024;

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_data: 1 << 20,
            max_data_autotune: None,
            max_stream_data_bidi_local: DEFAULT_STREAM_WINDOW,
            max_stream_data_bidi_remote: DEFAULT_STREAM_WINDOW,
            max_stream_data_uni: DEFAULT_STREAM_WINDOW,
            max_stream_data_autotune: None,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            idle_timeout: Some(Duration::from_secs(30)),
            max_udp_payload_size: 1452,
            ack_policy: AckPolicy::default(),
            congestion_control: CongestionControl::default(),
            pacing: false,
            pacing_granularity: Duration::from_millis(1),
            pacing_min_burst: 5,
            pacing_max_burst: 44,
            initial_window: 10,
            min_window: 2,
            max_window: 2000,
            initial_rtt: Duration::from_millis(333),
            active_connection_id_limit: 2,
            key_update: KeyUpdatePolicy::default(),
            datagram_size: DatagramSize::default(),
            buffered_packets: 20,
            disable_active_migration: false,
            params_layout: ParamsLayout::default(),
            extra_params: Vec::new(),
            keep_alive: None,
            max_ptos: None,
            max_datagram_frame_size: 0,
            datagram_send_queue: 1024,
            datagram_recv_queue: 1024,
            stream_ack_progress: false,
        }
    }
}

impl TransportConfig {
    /// The largest active_connection_id_limit accepted. RFC 9000 allows up to 2^62 - 1, but a
    /// connection keeps state for the peer's IDs and their retirements in proportion to the limit,
    /// so the cap bounds the memory a peer can make it hold.
    pub const MAX_ACTIVE_CONNECTION_ID_LIMIT: u64 = 8;

    /// The most packets a connection may keep until their keys arrive.
    pub const MAX_BUFFERED_PACKETS: usize = 256;

    /// Starts a builder from the defaults.
    pub fn builder() -> TransportConfigBuilder {
        TransportConfigBuilder {
            config: TransportConfig::default(),
        }
    }

    /// Returns initial_max_data, the connection receive window we advertise.
    pub fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Returns the ceiling to which the connection receive window may autotune, or `None` for a
    /// fixed window.
    pub fn max_data_autotune(&self) -> Option<u64> {
        self.max_data_autotune
    }

    /// Returns initial_max_stream_data_bidi_local, the receive window of bidirectional streams
    /// we open.
    pub fn max_stream_data_bidi_local(&self) -> u64 {
        self.max_stream_data_bidi_local
    }

    /// Returns initial_max_stream_data_bidi_remote, the receive window of bidirectional streams
    /// the peer opens.
    pub fn max_stream_data_bidi_remote(&self) -> u64 {
        self.max_stream_data_bidi_remote
    }

    /// Returns initial_max_stream_data_uni, the receive window of unidirectional streams the
    /// peer opens.
    pub fn max_stream_data_uni(&self) -> u64 {
        self.max_stream_data_uni
    }

    /// Returns the ceiling to which stream receive windows may autotune, or `None` for fixed
    /// windows.
    pub fn max_stream_data_autotune(&self) -> Option<u64> {
        self.max_stream_data_autotune
    }

    /// Returns initial_max_streams_bidi, how many bidirectional streams the peer may have open.
    pub fn max_streams_bidi(&self) -> u64 {
        self.max_streams_bidi
    }

    /// Returns initial_max_streams_uni, how many unidirectional streams the peer may have open.
    pub fn max_streams_uni(&self) -> u64 {
        self.max_streams_uni
    }

    /// Returns max_idle_timeout, or `None` if idle connections do not time out.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Returns max_udp_payload_size, the largest UDP payload we accept.
    pub fn max_udp_payload_size(&self) -> u16 {
        self.max_udp_payload_size
    }

    /// Returns when to acknowledge.
    pub fn ack_policy(&self) -> AckPolicy {
        self.ack_policy
    }

    /// Returns the congestion controller.
    pub fn congestion_control(&self) -> CongestionControl {
        self.congestion_control
    }

    /// Returns whether datagrams are paced once the 1-RTT keys exist and the path has an RTT
    /// sample.
    pub fn pacing(&self) -> bool {
        self.pacing
    }

    /// Returns the pacer's tick: runs are sized to leave about one tick apart, within the minimum
    /// and maximum burst.
    pub fn pacing_granularity(&self) -> Duration {
        self.pacing_granularity
    }

    /// Returns the fewest datagrams a paced run is sized for.
    pub fn pacing_min_burst(&self) -> u16 {
        self.pacing_min_burst
    }

    /// Returns the most datagrams in a paced run.
    pub fn pacing_max_burst(&self) -> u16 {
        self.pacing_max_burst
    }

    /// Returns the initial congestion window in datagrams.
    pub fn initial_window(&self) -> u32 {
        self.initial_window
    }

    /// Returns the minimum congestion window in datagrams.
    pub fn min_window(&self) -> u32 {
        self.min_window
    }

    /// Returns the maximum congestion window in datagrams.
    pub fn max_window(&self) -> u32 {
        self.max_window
    }

    /// Returns the RTT assumed before the first sample (RFC 9002).
    pub fn initial_rtt(&self) -> Duration {
        self.initial_rtt
    }

    /// Returns active_connection_id_limit, how many connection IDs from the peer we are willing
    /// to store.
    pub fn active_connection_id_limit(&self) -> u64 {
        self.active_connection_id_limit
    }

    /// Returns when to initiate key updates.
    pub fn key_update(&self) -> KeyUpdatePolicy {
        self.key_update
    }

    /// Returns the size of the datagrams sent.
    pub fn datagram_size(&self) -> DatagramSize {
        self.datagram_size
    }

    /// Returns how many packets a connection keeps until their keys arrive.
    pub fn buffered_packets(&self) -> usize {
        self.buffered_packets
    }

    /// Returns whether a connection advertises disable_active_migration.
    pub fn disable_active_migration(&self) -> bool {
        self.disable_active_migration
    }

    /// Returns how a server lays out its transport parameters.
    pub fn params_layout(&self) -> ParamsLayout {
        self.params_layout
    }

    /// Returns the transport parameters advertised as given, after those RFC 9000 defines.
    pub fn extra_params(&self) -> &[(VarInt, Bytes)] {
        &self.extra_params
    }

    /// Returns the keepalive, if any.
    pub fn keep_alive(&self) -> Option<KeepAlive> {
        self.keep_alive
    }

    /// Returns how many consecutive PTO expirations close the connection silently, if set.
    pub fn max_ptos(&self) -> Option<u32> {
        self.max_ptos
    }

    /// Returns max_datagram_frame_size (RFC 9221), the largest DATAGRAM frame this endpoint takes;
    /// 0, which is not advertised, means that it does not take DATAGRAM frames.
    pub fn max_datagram_frame_size(&self) -> u64 {
        self.max_datagram_frame_size
    }

    /// Returns how many datagrams wait to be sent before the oldest is dropped.
    pub fn datagram_send_queue(&self) -> usize {
        self.datagram_send_queue
    }

    /// Returns how many received datagrams wait for the application before the oldest is dropped.
    pub fn datagram_recv_queue(&self) -> usize {
        self.datagram_recv_queue
    }

    /// Returns whether a client connection queues the growths of its send halves' acknowledged
    /// prefixes for [`Connection::poll_stream_acked`](crate::Connection::poll_stream_acked).
    pub fn stream_ack_progress(&self) -> bool {
        self.stream_ack_progress
    }
}

/// A builder for a [`TransportConfig`]. Every setting starts at its default.
#[derive(Clone, Debug)]
pub struct TransportConfigBuilder {
    config: TransportConfig,
}

impl TransportConfigBuilder {
    /// Sets initial_max_data, below 2^62. Default 1 MiB.
    pub fn max_data(mut self, bytes: u64) -> Self {
        self.config.max_data = bytes;
        self
    }

    /// Lets the connection receive window double, up to `ceiling` (at least `max_data`, below
    /// 2^62), when updates come faster than twice the smoothed RTT. Default `None`: fixed.
    pub fn max_data_autotune(mut self, ceiling: Option<u64>) -> Self {
        self.config.max_data_autotune = ceiling;
        self
    }

    /// Sets initial_max_stream_data_bidi_local, below 2^62. Default 65 KiB.
    pub fn max_stream_data_bidi_local(mut self, bytes: u64) -> Self {
        self.config.max_stream_data_bidi_local = bytes;
        self
    }

    /// Sets initial_max_stream_data_bidi_remote, below 2^62. Default 65 KiB.
    pub fn max_stream_data_bidi_remote(mut self, bytes: u64) -> Self {
        self.config.max_stream_data_bidi_remote = bytes;
        self
    }

    /// Sets initial_max_stream_data_uni, below 2^62. Default 65 KiB.
    pub fn max_stream_data_uni(mut self, bytes: u64) -> Self {
        self.config.max_stream_data_uni = bytes;
        self
    }

    /// Lets stream receive windows autotune up to `ceiling` (at least every initial stream
    /// window, below 2^62). Default `None`: fixed.
    pub fn max_stream_data_autotune(mut self, ceiling: Option<u64>) -> Self {
        self.config.max_stream_data_autotune = ceiling;
        self
    }

    /// Sets initial_max_streams_bidi, at most 2^60. Default 100.
    pub fn max_streams_bidi(mut self, streams: u64) -> Self {
        self.config.max_streams_bidi = streams;
        self
    }

    /// Sets initial_max_streams_uni, at most 2^60. Default 100.
    pub fn max_streams_uni(mut self, streams: u64) -> Self {
        self.config.max_streams_uni = streams;
        self
    }

    /// Sets max_idle_timeout: `Some` non-zero duration of whole milliseconds below 2^62, or `None`
    /// to disable. Default 30 s.
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Sets max_udp_payload_size, 1200 to 65527 (RFC 9000). Default 1452, as in mvfst's tperf.
    pub fn max_udp_payload_size(mut self, bytes: u16) -> Self {
        self.config.max_udp_payload_size = bytes;
        self
    }

    /// Sets when to acknowledge.
    pub fn ack_policy(mut self, policy: AckPolicy) -> Self {
        self.config.ack_policy = policy;
        self
    }

    /// Sets the congestion controller. Default CUBIC.
    pub fn congestion_control(mut self, controller: CongestionControl) -> Self {
        self.config.congestion_control = controller;
        self
    }

    /// Sets whether to pace datagrams at the congestion controller's pacing rate, once the 1-RTT
    /// keys exist and the path has an RTT sample. ACK-only and probe datagrams do not take pacing
    /// tokens. Default off, as in mvfst's tperf.
    pub fn pacing(mut self, enabled: bool) -> Self {
        self.config.pacing = enabled;
        self
    }

    /// Sets the pacer's tick, a non-zero whole number of microseconds. A paced run holds the
    /// datagrams of about one tick at the pacing rate, within the minimum and maximum burst.
    /// Default 1 ms, mvfst's library default; mvfst tperf's `--pacing` uses 200 µs.
    pub fn pacing_granularity(mut self, granularity: Duration) -> Self {
        self.config.pacing_granularity = granularity;
        self
    }

    /// Sets the fewest datagrams a paced run is sized for, at least 1. Default 5, as in mvfst.
    pub fn pacing_min_burst(mut self, datagrams: u16) -> Self {
        self.config.pacing_min_burst = datagrams;
        self
    }

    /// Sets the most datagrams in a paced run, at least the minimum burst. Default 44, one GSO
    /// send of mvfst tperf's `--writes_per_loop`.
    pub fn pacing_max_burst(mut self, datagrams: u16) -> Self {
        self.config.pacing_max_burst = datagrams;
        self
    }

    /// Sets the initial congestion window in datagrams, limited to max(this * 1,472, 2 datagrams)
    /// bytes as RFC 9002 recommends, and kept within the minimum and maximum windows. Default 10,
    /// as in mvfst.
    pub fn initial_window(mut self, datagrams: u32) -> Self {
        self.config.initial_window = datagrams;
        self
    }

    /// Sets the minimum congestion window in datagrams, at least 2. Default 2, as in RFC 9002 and
    /// mvfst.
    pub fn min_window(mut self, datagrams: u32) -> Self {
        self.config.min_window = datagrams;
        self
    }

    /// Sets the maximum congestion window in datagrams, at least the minimum window. Default 2,000,
    /// mvfst's library default; mvfst's tperf sets it with `--max_cwnd_mss`, by default to 860,000.
    pub fn max_window(mut self, datagrams: u32) -> Self {
        self.config.max_window = datagrams;
        self
    }

    /// Sets the RTT assumed before the first sample; non-zero and at most an hour
    /// ([`RecoveryConfig::MAX_TIMER_SETTING`]). Default 333 ms, as RFC 9002 recommends.
    pub fn initial_rtt(mut self, rtt: Duration) -> Self {
        self.config.initial_rtt = rtt;
        self
    }

    /// Sets active_connection_id_limit (RFC 9000), from 2 to
    /// [`TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT`]. Default 2.
    pub fn active_connection_id_limit(mut self, limit: u64) -> Self {
        self.config.active_connection_id_limit = limit;
        self
    }

    /// Sets when to initiate key updates. Default [`KeyUpdatePolicy::AtLimit`].
    pub fn key_update(mut self, policy: KeyUpdatePolicy) -> Self {
        self.config.key_update = policy;
        self
    }

    /// Sets the size of the datagrams sent. Default [`DatagramSize::Minimum`].
    pub fn datagram_size(mut self, policy: DatagramSize) -> Self {
        self.config.datagram_size = policy;
        self
    }

    /// Sets how many packets a connection keeps until their keys arrive, as RFC 9001 allows, such
    /// as a client's Handshake packets that come before the ServerHello is read, or 1-RTT packets
    /// that come before the handshake completes. At most
    /// [`TransportConfig::MAX_BUFFERED_PACKETS`]. Default 20.
    pub fn buffered_packets(mut self, count: usize) -> Self {
        self.config.buffered_packets = count;
        self
    }

    /// Sets whether a connection advertises disable_active_migration, under which its peer must
    /// not move the connection to a new address of its choosing (RFC 9000). A server still follows
    /// a client whose address changes, as after a NAT rebinding. Default off.
    pub fn disable_active_migration(mut self, disable: bool) -> Self {
        self.config.disable_active_migration = disable;
        self
    }

    /// Sets how a server lays out its transport parameters. Clients always use
    /// [`ParamsLayout::Rfc`]. Default [`ParamsLayout::Rfc`].
    pub fn params_layout(mut self, layout: ParamsLayout) -> Self {
        self.config.params_layout = layout;
        self
    }

    /// Sets transport parameters to advertise as given, in order, after those RFC 9000 defines,
    /// each id above RFC 9000's and used at most once. mvfstr does not act on them, so they must
    /// not advertise a feature it lacks; mvfst's `ack_receive_timestamps_enabled` of 0, which
    /// turns receive timestamps off, is safe. Default empty.
    pub fn extra_params(mut self, params: Vec<(VarInt, Bytes)>) -> Self {
        self.config.extra_params = params;
        self
    }

    /// Sets the PINGs that keep the connection alive once the handshake is complete. Default none.
    pub fn keep_alive(mut self, keep_alive: Option<KeepAlive>) -> Self {
        self.config.keep_alive = keep_alive;
        self
    }

    /// Sets how many consecutive PTO expirations close the connection silently, without a
    /// CONNECTION_CLOSE, as mvfst's maxNumPTOs does; at least 1. Default none: only the idle
    /// timeout ends an unanswered connection.
    pub fn max_ptos(mut self, max_ptos: Option<u32>) -> Self {
        self.config.max_ptos = max_ptos;
        self
    }

    /// Sets max_datagram_frame_size (RFC 9221), below 2^62: the largest DATAGRAM frame, type and
    /// Length field included, this endpoint takes. A value above 0 is advertised and lets the peer
    /// send DATAGRAM frames; RFC 9221 recommends 65535. Default 0: DATAGRAM frames are refused.
    pub fn max_datagram_frame_size(mut self, bytes: u64) -> Self {
        self.config.max_datagram_frame_size = bytes;
        self
    }

    /// Sets how many datagrams wait to be sent, at least 1; queuing one more drops the oldest.
    /// Default 1024.
    pub fn datagram_send_queue(mut self, datagrams: usize) -> Self {
        self.config.datagram_send_queue = datagrams;
        self
    }

    /// Sets how many received datagrams wait for the application, at least 1; receiving one more
    /// drops the oldest. Default 1024.
    pub fn datagram_recv_queue(mut self, datagrams: usize) -> Self {
        self.config.datagram_recv_queue = datagrams;
        self
    }

    /// Makes a client connection queue the growths of its send halves' acknowledged prefixes for
    /// [`Connection::poll_stream_acked`](crate::Connection::poll_stream_acked), one entry per
    /// stream until it is polled, also after the stream is reaped. A server does not queue them.
    /// Default false: the connection does not queue them.
    pub fn stream_ack_progress(mut self, enabled: bool) -> Self {
        self.config.stream_ack_progress = enabled;
        self
    }

    /// Validates the settings.
    pub fn build(self) -> Result<Arc<TransportConfig>, ConfigError> {
        let c = &self.config;
        let check = |ok: bool, field: &'static str| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::OutOfRange { field })
            }
        };
        varint_field(c.max_data, "max_data")?;
        varint_field(c.max_stream_data_bidi_local, "max_stream_data_bidi_local")?;
        varint_field(c.max_stream_data_bidi_remote, "max_stream_data_bidi_remote")?;
        varint_field(c.max_stream_data_uni, "max_stream_data_uni")?;
        if let Some(ceiling) = c.max_data_autotune {
            varint_field(ceiling, "max_data_autotune")?;
            check(ceiling >= c.max_data, "max_data_autotune")?;
        }
        if let Some(ceiling) = c.max_stream_data_autotune {
            varint_field(ceiling, "max_stream_data_autotune")?;
            let largest = c
                .max_stream_data_bidi_local
                .max(c.max_stream_data_bidi_remote)
                .max(c.max_stream_data_uni);
            check(ceiling >= largest, "max_stream_data_autotune")?;
        }
        // RFC 9000 forbids stream counts above 2^60, which a stream ID cannot encode.
        check(c.max_streams_bidi <= 1 << 60, "max_streams_bidi")?;
        check(c.max_streams_uni <= 1 << 60, "max_streams_uni")?;
        if let Some(timeout) = c.idle_timeout {
            let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            let whole_millis = timeout.subsec_nanos() % 1_000_000 == 0;
            check(
                millis > 0 && whole_millis && VarInt::from_u64(millis).is_ok(),
                "idle_timeout",
            )?;
        }
        check(
            (1200..=65527).contains(&c.max_udp_payload_size),
            "max_udp_payload_size",
        )?;
        let ack = &c.ack_policy;
        check(
            // RFC 9000 allows a max_ack_delay below 2^14 ms. It is advertised in whole
            // milliseconds rounded up, so the ACK timer never runs past the advertised value.
            ack.before_init >= 1
                && ack.after_init >= 1
                && ack.max_ack_delay <= Duration::from_millis((1 << 14) - 1)
                && ack.ack_delay_exponent <= 20,
            "ack_policy",
        )?;
        // Loss recovery refuses anything else, and a connection needs it to start.
        check(
            !c.initial_rtt.is_zero() && c.initial_rtt <= RecoveryConfig::MAX_TIMER_SETTING,
            "initial_rtt",
        )?;
        check(
            (2..=TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT)
                .contains(&c.active_connection_id_limit),
            "active_connection_id_limit",
        )?;
        check(c.key_update != KeyUpdatePolicy::Every(0), "key_update")?;
        check(
            c.buffered_packets <= TransportConfig::MAX_BUFFERED_PACKETS,
            "buffered_packets",
        )?;
        // The congestion controller refuses anything else, and a connection needs it to start.
        check(c.min_window >= 2, "min_window")?;
        check(c.max_window >= c.min_window, "max_window")?;
        // The pacer sizes runs in whole microseconds, as mvfst's pacer does.
        check(
            !c.pacing_granularity.is_zero()
                && c.pacing_granularity.subsec_nanos().is_multiple_of(1000),
            "pacing_granularity",
        )?;
        check(c.pacing_min_burst >= 1, "pacing_min_burst")?;
        check(c.pacing_max_burst >= c.pacing_min_burst, "pacing_max_burst")?;
        // The encoder fails on an id that RFC 9000 defines or that repeats, which decoders reject,
        // and max_datagram_frame_size comes from its own setting.
        let extra_ids_ok = c.extra_params.iter().enumerate().all(|(i, (id, _))| {
            id.into_inner() > LAST_RFC9000_PARAM
                && id.into_inner() != MAX_DATAGRAM_FRAME_SIZE_PARAM
                && c.extra_params[..i].iter().all(|(e, _)| e != id)
        });
        check(extra_ids_ok, "extra_params")?;
        // The idle timeout's range, so that the keepalive deadline is as representable as the
        // idle deadline.
        let keep_alive_ok = match c.keep_alive {
            Some(KeepAlive::Interval(interval)) => {
                !interval.is_zero() && interval <= Duration::from_millis(VarInt::MAX.into_inner())
            }
            Some(KeepAlive::NegotiatedIdle) | None => true,
        };
        check(keep_alive_ok, "keep_alive")?;
        check(c.max_ptos != Some(0), "max_ptos")?;
        varint_field(c.max_datagram_frame_size, "max_datagram_frame_size")?;
        check(c.datagram_send_queue >= 1, "datagram_send_queue")?;
        check(c.datagram_recv_queue >= 1, "datagram_recv_queue")?;
        Ok(Arc::new(self.config))
    }
}

/// The versions mvfstr implements.
pub const SUPPORTED_VERSIONS: [Version; 5] = [
    Version::V1,
    Version::MVFST,
    Version::QUIC_V1_ALIAS,
    Version::QUIC_V1_ALIAS2,
    Version::MVFST_ALIAS,
];

/// Where the connections of a server run their TLS handshakes.
#[derive(Clone, Debug)]
pub enum ServerTls {
    /// On rustls, inside each connection, with this config, which supplies certificates, cipher
    /// suites, key exchange groups, ALPN protocols and whether clients are asked for a
    /// certificate.
    Rustls(Arc<rustls::ServerConfig>),
    /// On a [`TlsHost`](mvfstr_tls::TlsHost) outside the connection, which the caller drives
    /// through [`Connection::tls_input`](crate::Connection::tls_input) and
    /// [`Connection::tls_deliver`](crate::Connection::tls_deliver). The host chooses the
    /// certificates, cipher suites, key exchange groups and ALPN protocol. A host that accepts
    /// 0-RTT applies RFC 9221's rule itself: it accepts early data only when the transport
    /// parameters of [`TlsInput::Start`](mvfstr_tls::TlsInput::Start) advertise at least the
    /// max_datagram_frame_size of the connection that issued the ticket.
    External,
}

impl ServerTls {
    /// Returns the rustls config of a server whose handshakes run on rustls, or `None` for an
    /// External server.
    pub fn rustls(&self) -> Option<&Arc<rustls::ServerConfig>> {
        match self {
            Self::Rustls(tls) => Some(tls),
            Self::External => None,
        }
    }

    /// Returns a random source for the caller's [`Random`](crate::Random): the rustls config's
    /// crypto provider's, or for an External server that of mvfstr_crypto's default provider.
    pub fn secure_random(&self) -> &'static dyn SecureRandom {
        match self {
            Self::Rustls(tls) => tls.crypto_provider().secure_random,
            Self::External => default_secure_random(),
        }
    }
}

impl From<Arc<rustls::ServerConfig>> for ServerTls {
    fn from(tls: Arc<rustls::ServerConfig>) -> Self {
        Self::Rustls(tls)
    }
}

/// Returns the random source of mvfstr_crypto's default provider, built once.
fn default_secure_random() -> &'static dyn SecureRandom {
    static RANDOM: OnceLock<&'static dyn SecureRandom> = OnceLock::new();
    *RANDOM.get_or_init(|| mvfstr_crypto::default_provider().secure_random)
}

/// Settings for accepting connections.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    tls: ServerTls,
    /// The main rustls config without early data, kept when the server accepts 0-RTT.
    tls_without_early_data: Option<ServerTls>,
    transport: Arc<TransportConfig>,
    versions: Vec<Version>,
    alpn: AlpnPolicy,
    mvfst_tls: Option<Arc<rustls::ServerConfig>>,
}

impl ServerConfig {
    /// Starts a builder around where handshakes run, a rustls server config or
    /// [`ServerTls::External`], with the default transport config, version 1 only and
    /// [`AlpnPolicy::Required`].
    pub fn builder(tls: impl Into<ServerTls>) -> ServerConfigBuilder {
        ServerConfigBuilder {
            config: ServerConfig {
                tls: tls.into(),
                tls_without_early_data: None,
                transport: Arc::new(TransportConfig::default()),
                versions: vec![Version::V1],
                alpn: AlpnPolicy::Required,
                mvfst_tls: None,
            },
            accept_early_data: false,
        }
    }

    /// Returns where the handshakes of accepted connections run. On a server that accepts 0-RTT,
    /// a connection that advertises max_datagram_frame_size runs on the main rustls config
    /// without early data instead.
    pub fn tls(&self) -> &ServerTls {
        &self.tls
    }

    /// Returns where the handshake of a connection with `transport` runs: [`tls`](Self::tls),
    /// except that on a server that accepts 0-RTT, a connection that advertises
    /// max_datagram_frame_size runs on the main rustls config without early data.
    pub(crate) fn tls_for(&self, transport: &TransportConfig) -> &ServerTls {
        match &self.tls_without_early_data {
            Some(tls) if transport.max_datagram_frame_size() > 0 => tls,
            _ => &self.tls,
        }
    }

    /// Returns the rustls config that takes a ClientHello without ALPN on a connection of
    /// `version`, in place of [`tls`](Self::tls), and the connection's ALPN policy: the [MVFST
    /// config](ServerConfigBuilder::mvfst_tls) and [`AlpnPolicy::AllowMissing`] for a connection
    /// of MVFST or its alias when that config is set, and otherwise `None` and
    /// [`alpn`](Self::alpn).
    pub fn tls_without_alpn(
        &self,
        version: Version,
    ) -> (Option<&Arc<rustls::ServerConfig>>, AlpnPolicy) {
        match &self.mvfst_tls {
            Some(tls) if version.unaliased() == Version::MVFST => {
                (Some(tls), AlpnPolicy::AllowMissing)
            }
            _ => (None, self.alpn),
        }
    }

    /// Returns the transport settings of accepted connections, unless [`ConnOptions`] overrides
    /// them.
    pub fn transport(&self) -> &Arc<TransportConfig> {
        &self.transport
    }

    /// Returns the versions the server accepts; others get a Version Negotiation packet listing
    /// these.
    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    /// Returns whether ALPN is required.
    pub fn alpn(&self) -> AlpnPolicy {
        self.alpn
    }
}

/// A builder for a [`ServerConfig`].
#[derive(Clone, Debug)]
pub struct ServerConfigBuilder {
    config: ServerConfig,
    accept_early_data: bool,
}

impl ServerConfigBuilder {
    /// Sets the transport settings of accepted connections.
    pub fn transport(mut self, transport: Arc<TransportConfig>) -> Self {
        self.config.transport = transport;
        self
    }

    /// Sets the versions to accept: without repeats, each one mvfstr implements ([`Version::V1`],
    /// [`Version::MVFST`] and mvfst's aliases of them, [`Version::QUIC_V1_ALIAS`],
    /// [`Version::QUIC_V1_ALIAS2`] and [`Version::MVFST_ALIAS`]), and always including version 1.
    /// A Version Negotiation packet lists them in the order given.
    pub fn versions(mut self, versions: Vec<Version>) -> Self {
        self.config.versions = versions;
        self
    }

    /// Sets whether ALPN is required.
    pub fn alpn(mut self, policy: AlpnPolicy) -> Self {
        self.config.alpn = policy;
        self
    }

    /// Sets a rustls config for connections of MVFST or its alias whose ClientHello does not offer
    /// ALPN, which then run with [`AlpnPolicy::AllowMissing`]; a ClientHello of either that offers
    /// ALPN keeps the main config. rustls, following RFC 9001, refuses a ClientHello without ALPN
    /// when its config lists protocols, and one that offers protocols when the list is empty, so a
    /// server that takes both kinds, as mvfst's tperf server does, picks the config by the
    /// ClientHello. By default these connections use the main config. [`build`](Self::build)
    /// refuses it for a [`ServerTls::External`] server, whose host answers such ClientHellos
    /// itself.
    pub fn mvfst_tls(mut self, tls: Arc<rustls::ServerConfig>) -> Self {
        self.config.mvfst_tls = Some(tls);
        self
    }

    /// Sets whether connections on the main rustls config accept 0-RTT: the server then issues
    /// session tickets allowing early data and reads 0-RTT packets that follow the client's
    /// Initial. A connection that advertises max_datagram_frame_size does neither, because
    /// RFC 9221 requires a server that accepts 0-RTT to advertise at least the value of the
    /// connection that issued the ticket, and the tickets do not carry it. Test grade, for
    /// exercising clients: it does not guard against replay beyond rustls's single-use stateful
    /// tickets and does not limit early data. Default false, and the rustls config itself must not
    /// enable early data either way.
    pub fn accept_early_data(mut self, accept: bool) -> Self {
        self.accept_early_data = accept;
        self
    }

    /// Validates the settings and the parts of each rustls config QUIC depends on: a TLS 1.3
    /// cipher suite usable for QUIC, ALPN protocols when required, early data disabled, and
    /// whatever else rustls needs to create a QUIC connection, such as TLS 1.3 being enabled. The
    /// host of a [`ServerTls::External`] server checks its own TLS settings.
    pub fn build(self) -> Result<Arc<ServerConfig>, ConfigError> {
        let c = &self.config;
        check_versions(&c.versions)?;
        if !c.versions.contains(&Version::V1) {
            return Err(ConfigError::Version1Required);
        }
        if let ServerTls::Rustls(tls) = &c.tls {
            check_server_tls(tls, c.alpn)?;
        }
        if let Some(tls) = &c.mvfst_tls {
            // A TLS host answers ClientHellos without ALPN itself.
            if matches!(c.tls, ServerTls::External) {
                return Err(ConfigError::OutOfRange { field: "mvfst_tls" });
            }
            check_server_tls(tls, AlpnPolicy::AllowMissing)?;
        }
        let mut config = self.config;
        if self.accept_early_data
            && let ServerTls::Rustls(tls) = &config.tls
        {
            // rustls's QUIC server accepts only this early data size, the one RFC 9001 requires.
            let mut tls = rustls::ServerConfig::clone(tls);
            tls.max_early_data_size = u32::MAX;
            tls.send_tls13_tickets = tls.send_tls13_tickets.max(1);
            config.tls_without_early_data = Some(config.tls.clone());
            config.tls = ServerTls::Rustls(Arc::new(tls));
        }
        Ok(Arc::new(config))
    }
}

/// Checks a rustls server config as [`ServerConfigBuilder::build`] describes.
fn check_server_tls(tls: &Arc<rustls::ServerConfig>, alpn: AlpnPolicy) -> Result<(), ConfigError> {
    check_tls(
        tls.crypto_provider(),
        &tls.alpn_protocols,
        alpn,
        tls.max_early_data_size != 0,
    )?;
    // rustls keeps its enabled protocol versions private; creating a QUIC connection is the
    // public way to check whether it accepts the config, and a server connection stays idle
    // until it reads a ClientHello.
    rustls::quic::ServerConnection::new(tls.clone(), rustls::quic::Version::V1, Vec::new())
        .map_err(ConfigError::Tls)?;
    Ok(())
}

/// Where the connections of a client run their TLS handshakes.
#[derive(Clone, Debug)]
pub enum ClientTls {
    /// On rustls, inside each connection, with this config, which supplies the certificate
    /// verifier, cipher suites, key exchange groups, the ALPN protocols to offer and any
    /// certificate to present when the server asks for one.
    Rustls(Arc<rustls::ClientConfig>),
    /// On a [`TlsHost`](mvfstr_tls::TlsHost) outside the connection, which the caller drives
    /// through [`Connection::tls_input`](crate::Connection::tls_input) and
    /// [`Connection::tls_deliver`](crate::Connection::tls_deliver). The host verifies the
    /// server and chooses what to offer, and keeps its state for the connection until the
    /// connection closes, so that it reads the server's session tickets.
    External,
}

impl ClientTls {
    /// Returns the rustls config of a client whose handshakes run on rustls, or `None` for an
    /// External client.
    pub fn rustls(&self) -> Option<&Arc<rustls::ClientConfig>> {
        match self {
            Self::Rustls(tls) => Some(tls),
            Self::External => None,
        }
    }

    /// Returns a random source for the caller's [`Random`](crate::Random): the rustls config's
    /// crypto provider's, or for an External client that of mvfstr_crypto's default provider.
    pub fn secure_random(&self) -> &'static dyn SecureRandom {
        match self {
            Self::Rustls(tls) => tls.crypto_provider().secure_random,
            Self::External => default_secure_random(),
        }
    }
}

impl From<Arc<rustls::ClientConfig>> for ClientTls {
    fn from(tls: Arc<rustls::ClientConfig>) -> Self {
        Self::Rustls(tls)
    }
}

/// Settings for opening connections.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    tls: ClientTls,
    transport: Arc<TransportConfig>,
    versions: Vec<Version>,
    alpn: AlpnPolicy,
}

impl ClientConfig {
    /// Starts a builder around where handshakes run, a rustls client config or
    /// [`ClientTls::External`], with the default transport config, version 1 only and
    /// [`AlpnPolicy::Required`].
    pub fn builder(tls: impl Into<ClientTls>) -> ClientConfigBuilder {
        ClientConfigBuilder {
            config: ClientConfig {
                tls: tls.into(),
                transport: Arc::new(TransportConfig::default()),
                versions: vec![Version::V1],
                alpn: AlpnPolicy::Required,
            },
        }
    }

    /// Returns where the handshakes of opened connections run.
    pub fn tls(&self) -> &ClientTls {
        &self.tls
    }

    /// Returns the transport settings of opened connections, unless [`ConnOptions`] overrides them.
    pub fn transport(&self) -> &Arc<TransportConfig> {
        &self.transport
    }

    /// Returns the versions the client accepts. It offers the first.
    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    /// Returns whether ALPN is required.
    pub fn alpn(&self) -> AlpnPolicy {
        self.alpn
    }
}

/// A builder for a [`ClientConfig`].
#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Sets the transport settings of opened connections.
    pub fn transport(mut self, transport: Arc<TransportConfig>) -> Self {
        self.config.transport = transport;
        self
    }

    /// Sets the versions to accept, the first of which is offered: non-empty, without repeats,
    /// each one mvfstr implements (see [`ServerConfigBuilder::versions`]).
    pub fn versions(mut self, versions: Vec<Version>) -> Self {
        self.config.versions = versions;
        self
    }

    /// Sets whether ALPN is required.
    pub fn alpn(mut self, policy: AlpnPolicy) -> Self {
        self.config.alpn = policy;
        self
    }

    /// Validates the settings and the parts of the rustls config QUIC depends on: a TLS 1.3
    /// cipher suite usable for QUIC, ALPN protocols when required, and whatever else rustls
    /// needs to create a QUIC connection, such as TLS 1.3 being enabled. With
    /// `enable_early_data` set, a connection resuming a session that allows early data sends
    /// 0-RTT. The host of a [`ClientTls::External`] client checks its own TLS settings.
    pub fn build(self) -> Result<Arc<ClientConfig>, ConfigError> {
        let c = &self.config;
        check_versions(&c.versions)?;
        if let ClientTls::Rustls(tls) = &c.tls {
            check_client_tls(tls, c.alpn)?;
        }
        Ok(Arc::new(self.config))
    }
}

/// Checks a rustls client config as [`ClientConfigBuilder::build`] describes.
fn check_client_tls(tls: &Arc<rustls::ClientConfig>, alpn: AlpnPolicy) -> Result<(), ConfigError> {
    check_tls(tls.crypto_provider(), &tls.alpn_protocols, alpn, false)?;
    // As for the server, creating a QUIC connection is the check. A client connection writes its
    // ClientHello at once, which draws on the provider's RNG and would take a ticket from the
    // caller's session store, so the probe runs on a copy without resumption.
    let mut probe = rustls::ClientConfig::clone(tls);
    probe.resumption = rustls::client::Resumption::disabled();
    let name = ServerName::try_from("mvfstr.invalid").expect("a valid DNS name");
    rustls::quic::ClientConnection::new(
        Arc::new(probe),
        rustls::quic::Version::V1,
        name,
        Vec::new(),
    )
    .map_err(ConfigError::Tls)?;
    Ok(())
}

/// Per-connection overrides, given to [`Endpoint::accept`](crate::Endpoint::accept) or
/// [`Endpoint::connect`](crate::Endpoint::connect).
#[derive(Clone, Debug, Default)]
pub struct ConnOptions {
    /// Transport settings that replace the server or client config's.
    pub transport: Option<Arc<TransportConfig>>,
}

/// Checks a version list: non-empty, implemented, without repeats.
fn check_versions(versions: &[Version]) -> Result<(), ConfigError> {
    if versions.is_empty() {
        return Err(ConfigError::NoVersions);
    }
    for (i, version) in versions.iter().enumerate() {
        if !SUPPORTED_VERSIONS.contains(version) {
            return Err(ConfigError::UnsupportedVersion(*version));
        }
        if versions[..i].contains(version) {
            return Err(ConfigError::DuplicateVersion(*version));
        }
    }
    Ok(())
}

/// Checks the parts of a rustls config QUIC depends on.
fn check_tls(
    provider: &rustls::crypto::CryptoProvider,
    alpn_protocols: &[Vec<u8>],
    policy: AlpnPolicy,
    early_data: bool,
) -> Result<(), ConfigError> {
    let quic_suite = provider
        .cipher_suites
        .iter()
        .any(|suite| suite.tls13().is_some_and(|suite| suite.quic.is_some()));
    if !quic_suite {
        return Err(ConfigError::NoQuicCipherSuite);
    }
    if policy == AlpnPolicy::Required && alpn_protocols.is_empty() {
        return Err(ConfigError::AlpnRequiredWithoutProtocols);
    }
    if early_data {
        return Err(ConfigError::EarlyDataUnsupported);
    }
    Ok(())
}

/// Checks a value that must fit a variable-length integer.
fn varint_field(value: u64, field: &'static str) -> Result<(), ConfigError> {
    VarInt::from_u64(value)
        .map(|_| ())
        .map_err(|_| ConfigError::OutOfRange { field })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use mvfstr_crypto::default_provider;
    use rustls::CipherSuite;
    use rustls::NamedGroup;
    use rustls::client::ClientSessionStore;
    use rustls::client::Resumption;
    use rustls::client::Tls12ClientSessionValue;
    use rustls::client::Tls13ClientSessionValue;
    use rustls::server::ClientHello;
    use rustls::server::ResolvesServerCert;
    use rustls::sign::CertifiedKey;

    use super::*;

    fn out_of_range(field: &'static str) -> ConfigError {
        ConfigError::OutOfRange { field }
    }

    #[test]
    fn transport_defaults() {
        let config = TransportConfig::builder().build().unwrap();
        assert_eq!(*config, TransportConfig::default());
        assert_eq!(config.max_data(), 1 << 20);
        assert_eq!(config.max_data_autotune(), None);
        assert_eq!(config.max_stream_data_bidi_local(), 66_560);
        assert_eq!(config.max_stream_data_bidi_remote(), 66_560);
        assert_eq!(config.max_stream_data_uni(), 66_560);
        assert_eq!(config.max_stream_data_autotune(), None);
        assert_eq!(config.max_streams_bidi(), 100);
        assert_eq!(config.max_streams_uni(), 100);
        assert_eq!(config.idle_timeout(), Some(Duration::from_secs(30)));
        assert_eq!(config.max_udp_payload_size(), 1452);
        assert_eq!(config.ack_policy(), AckPolicy::default());
        // mvfst's ACK cadence.
        assert_eq!(config.ack_policy().init_threshold, 100);
        assert_eq!(config.ack_policy().before_init, 10);
        assert_eq!(config.ack_policy().after_init, 10);
        assert!(config.ack_policy().rtt_timer);
        assert_eq!(config.ack_policy().max_ack_delay, Duration::from_millis(25));
        assert_eq!(config.ack_policy().ack_delay_exponent, 3);
        assert_eq!(config.congestion_control(), CongestionControl::Cubic);
        assert!(!config.pacing());
        // mvfst's library defaults, and 44 datagrams, one GSO send.
        assert_eq!(config.pacing_granularity(), Duration::from_millis(1));
        assert_eq!(config.pacing_min_burst(), 5);
        assert_eq!(config.pacing_max_burst(), 44);
        assert_eq!(config.initial_window(), 10);
        assert_eq!(config.min_window(), 2);
        assert_eq!(config.max_window(), 2000);
        assert_eq!(config.initial_rtt(), Duration::from_millis(333));
        assert_eq!(config.active_connection_id_limit(), 2);
        assert_eq!(config.key_update(), KeyUpdatePolicy::AtLimit);
        assert_eq!(config.datagram_size(), DatagramSize::Minimum);
    }

    #[test]
    fn transport_builder_sets_every_field() {
        let ack = AckPolicy {
            init_threshold: 1000,
            before_init: 2,
            after_init: 20,
            max_ack_delay: Duration::from_millis(5),
            rtt_timer: false,
            ack_delay_exponent: 8,
        };
        let config = TransportConfig::builder()
            .max_data(3 << 20)
            .max_data_autotune(Some(32 << 20))
            .max_stream_data_bidi_local(1)
            .max_stream_data_bidi_remote(2)
            .max_stream_data_uni(u64::from(u32::MAX))
            .max_stream_data_autotune(Some(u64::from(u32::MAX)))
            .max_streams_bidi(2048)
            .max_streams_uni(0)
            .idle_timeout(None)
            .max_udp_payload_size(1500)
            .ack_policy(ack)
            .congestion_control(CongestionControl::NewReno)
            .pacing(true)
            .pacing_granularity(Duration::from_micros(200))
            .pacing_min_burst(2)
            .pacing_max_burst(64)
            .initial_window(32)
            .min_window(4)
            .max_window(860_000)
            .initial_rtt(Duration::from_millis(50))
            .active_connection_id_limit(5)
            .key_update(KeyUpdatePolicy::Every(1 << 20))
            .datagram_size(DatagramSize::PeerMaximum)
            .build()
            .unwrap();
        assert_eq!(config.max_data(), 3 << 20);
        assert_eq!(config.max_data_autotune(), Some(32 << 20));
        assert_eq!(config.max_stream_data_bidi_local(), 1);
        assert_eq!(config.max_stream_data_bidi_remote(), 2);
        assert_eq!(config.max_stream_data_uni(), u64::from(u32::MAX));
        assert_eq!(config.max_stream_data_autotune(), Some(u64::from(u32::MAX)));
        assert_eq!(config.max_streams_bidi(), 2048);
        assert_eq!(config.max_streams_uni(), 0);
        assert_eq!(config.idle_timeout(), None);
        assert_eq!(config.max_udp_payload_size(), 1500);
        assert_eq!(config.ack_policy(), ack);
        assert_eq!(config.congestion_control(), CongestionControl::NewReno);
        assert!(config.pacing());
        assert_eq!(config.pacing_granularity(), Duration::from_micros(200));
        assert_eq!(config.pacing_min_burst(), 2);
        assert_eq!(config.pacing_max_burst(), 64);
        assert_eq!(config.initial_window(), 32);
        assert_eq!(config.min_window(), 4);
        assert_eq!(config.max_window(), 860_000);
        assert_eq!(config.initial_rtt(), Duration::from_millis(50));
        assert_eq!(config.active_connection_id_limit(), 5);
        assert_eq!(config.key_update(), KeyUpdatePolicy::Every(1 << 20));
        assert_eq!(config.datagram_size(), DatagramSize::PeerMaximum);
    }

    #[test]
    fn transport_builder_accepts_range_limits() {
        let ack = AckPolicy {
            init_threshold: u64::MAX,
            before_init: 1,
            after_init: 1,
            max_ack_delay: Duration::from_millis((1 << 14) - 1),
            rtt_timer: true,
            ack_delay_exponent: 20,
        };
        let limits = [
            TransportConfig::builder().max_udp_payload_size(1200),
            TransportConfig::builder().max_udp_payload_size(65527),
            TransportConfig::builder().max_data((1 << 62) - 1),
            TransportConfig::builder().max_streams_bidi(1 << 60),
            TransportConfig::builder().max_streams_uni(1 << 60),
            TransportConfig::builder().idle_timeout(Some(Duration::from_millis(1))),
            TransportConfig::builder()
                .active_connection_id_limit(TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT),
            TransportConfig::builder().max_data_autotune(Some(1 << 20)),
            TransportConfig::builder().max_stream_data_autotune(Some(66_560)),
            TransportConfig::builder().key_update(KeyUpdatePolicy::Every(1)),
            TransportConfig::builder().ack_policy(ack),
            TransportConfig::builder().min_window(2).max_window(2),
            TransportConfig::builder().max_window(u32::MAX),
            TransportConfig::builder().keep_alive(Some(KeepAlive::Interval(
                Duration::from_millis((1 << 62) - 1),
            ))),
        ];
        for builder in limits {
            assert!(builder.clone().build().is_ok(), "{builder:?}");
        }
    }

    #[test]
    fn transport_builder_rejects_out_of_range_values() {
        let ack = AckPolicy::default();
        let cases = [
            (
                TransportConfig::builder().max_udp_payload_size(1199),
                "max_udp_payload_size",
            ),
            (
                TransportConfig::builder().max_udp_payload_size(65528),
                "max_udp_payload_size",
            ),
            (TransportConfig::builder().max_data(1 << 62), "max_data"),
            (
                TransportConfig::builder().keep_alive(Some(KeepAlive::Interval(Duration::ZERO))),
                "keep_alive",
            ),
            (
                TransportConfig::builder()
                    .keep_alive(Some(KeepAlive::Interval(Duration::from_millis(1 << 62)))),
                "keep_alive",
            ),
            (
                TransportConfig::builder().keep_alive(Some(KeepAlive::Interval(Duration::MAX))),
                "keep_alive",
            ),
            (TransportConfig::builder().max_ptos(Some(0)), "max_ptos"),
            (
                TransportConfig::builder().max_stream_data_bidi_local(1 << 62),
                "max_stream_data_bidi_local",
            ),
            (
                TransportConfig::builder().max_stream_data_bidi_remote(1 << 62),
                "max_stream_data_bidi_remote",
            ),
            (
                TransportConfig::builder().max_stream_data_uni(1 << 62),
                "max_stream_data_uni",
            ),
            (
                TransportConfig::builder().max_streams_bidi((1 << 60) + 1),
                "max_streams_bidi",
            ),
            (
                TransportConfig::builder().max_streams_uni((1 << 60) + 1),
                "max_streams_uni",
            ),
            (
                TransportConfig::builder().idle_timeout(Some(Duration::ZERO)),
                "idle_timeout",
            ),
            (
                TransportConfig::builder().idle_timeout(Some(Duration::from_micros(1500))),
                "idle_timeout",
            ),
            (
                TransportConfig::builder().initial_rtt(Duration::ZERO),
                "initial_rtt",
            ),
            (
                TransportConfig::builder().active_connection_id_limit(1),
                "active_connection_id_limit",
            ),
            (
                TransportConfig::builder().active_connection_id_limit(
                    TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT + 1,
                ),
                "active_connection_id_limit",
            ),
            (
                TransportConfig::builder().active_connection_id_limit(1 << 62),
                "active_connection_id_limit",
            ),
            (
                TransportConfig::builder().key_update(KeyUpdatePolicy::Every(0)),
                "key_update",
            ),
            (
                TransportConfig::builder()
                    .buffered_packets(TransportConfig::MAX_BUFFERED_PACKETS + 1),
                "buffered_packets",
            ),
            (TransportConfig::builder().min_window(1), "min_window"),
            (
                TransportConfig::builder().min_window(4).max_window(3),
                "max_window",
            ),
            (
                TransportConfig::builder().ack_policy(AckPolicy {
                    before_init: 0,
                    ..ack
                }),
                "ack_policy",
            ),
            (
                TransportConfig::builder().ack_policy(AckPolicy {
                    after_init: 0,
                    ..ack
                }),
                "ack_policy",
            ),
            (
                TransportConfig::builder().ack_policy(AckPolicy {
                    max_ack_delay: Duration::from_millis(1 << 14),
                    ..ack
                }),
                "ack_policy",
            ),
            // max_ack_delay is advertised in whole milliseconds rounded up, which would reach
            // 2^14 here.
            (
                TransportConfig::builder().ack_policy(AckPolicy {
                    max_ack_delay: Duration::from_micros(16_383_500),
                    ..ack
                }),
                "ack_policy",
            ),
            (
                TransportConfig::builder().ack_policy(AckPolicy {
                    ack_delay_exponent: 21,
                    ..ack
                }),
                "ack_policy",
            ),
        ];
        for (builder, field) in cases {
            assert_eq!(
                builder.clone().build(),
                Err(out_of_range(field)),
                "{builder:?}"
            );
        }
    }

    #[test]
    fn datagram_settings_are_off_by_default_and_checked() {
        let config = TransportConfig::default();
        assert_eq!(config.max_datagram_frame_size(), 0);
        assert_eq!(config.datagram_send_queue(), 1024);
        assert_eq!(config.datagram_recv_queue(), 1024);
        let config = TransportConfig::builder()
            .max_datagram_frame_size(65535)
            .datagram_send_queue(1)
            .datagram_recv_queue(2)
            .build()
            .unwrap();
        assert_eq!(config.max_datagram_frame_size(), 65535);
        assert_eq!(config.datagram_send_queue(), 1);
        assert_eq!(config.datagram_recv_queue(), 2);
        let max_datagram_frame_size = (VarInt::from_u32(0x20), Bytes::from_static(&[0x40, 0x64]));
        let cases = [
            (
                TransportConfig::builder().max_datagram_frame_size(1 << 62),
                "max_datagram_frame_size",
            ),
            (
                TransportConfig::builder().datagram_send_queue(0),
                "datagram_send_queue",
            ),
            (
                TransportConfig::builder().datagram_recv_queue(0),
                "datagram_recv_queue",
            ),
            // The parameter is advertised from max_datagram_frame_size alone.
            (
                TransportConfig::builder().extra_params(vec![max_datagram_frame_size]),
                "extra_params",
            ),
        ];
        for (builder, field) in cases {
            assert_eq!(
                builder.clone().build(),
                Err(out_of_range(field)),
                "{builder:?}"
            );
        }
    }

    #[test]
    fn stream_ack_progress_is_off_by_default_and_can_be_turned_on() {
        assert!(!TransportConfig::default().stream_ack_progress());
        let config = TransportConfig::builder()
            .stream_ack_progress(true)
            .build()
            .unwrap();
        assert!(config.stream_ack_progress());
    }

    #[test]
    fn pacing_settings_outside_their_range_are_refused() {
        let cases = [
            (
                TransportConfig::builder().pacing_granularity(Duration::ZERO),
                "pacing_granularity",
            ),
            (
                TransportConfig::builder().pacing_granularity(Duration::from_nanos(200_500)),
                "pacing_granularity",
            ),
            (
                TransportConfig::builder().pacing_min_burst(0),
                "pacing_min_burst",
            ),
            (
                TransportConfig::builder()
                    .pacing_min_burst(5)
                    .pacing_max_burst(4),
                "pacing_max_burst",
            ),
        ];
        for (builder, field) in cases {
            assert_eq!(
                builder.clone().build(),
                Err(out_of_range(field)),
                "{builder:?}"
            );
        }
        let edges = [
            TransportConfig::builder().pacing_granularity(Duration::from_micros(1)),
            TransportConfig::builder()
                .pacing_min_burst(1)
                .pacing_max_burst(1),
            TransportConfig::builder()
                .pacing_min_burst(u16::MAX)
                .pacing_max_burst(u16::MAX),
        ];
        for builder in edges {
            assert!(builder.clone().build().is_ok(), "{builder:?}");
        }
    }

    #[test]
    fn the_initial_rtt_is_bounded_by_what_loss_recovery_accepts() {
        let longest = RecoveryConfig::MAX_TIMER_SETTING;
        let config = TransportConfig::builder()
            .initial_rtt(longest)
            .build()
            .unwrap();
        let recovery = RecoveryConfig {
            initial_rtt: config.initial_rtt(),
            ..RecoveryConfig::default()
        };
        assert_eq!(recovery.validate(), Ok(()));
        assert_eq!(
            TransportConfig::builder()
                .initial_rtt(longest + Duration::from_nanos(1))
                .build(),
            Err(out_of_range("initial_rtt"))
        );
    }

    #[test]
    fn autotune_ceilings_cannot_be_below_the_initial_windows() {
        let below_connection = TransportConfig::builder()
            .max_data(1 << 20)
            .max_data_autotune(Some((1 << 20) - 1));
        assert_eq!(
            below_connection.build(),
            Err(out_of_range("max_data_autotune"))
        );
        let above_varint = TransportConfig::builder().max_data_autotune(Some(1 << 62));
        assert_eq!(above_varint.build(), Err(out_of_range("max_data_autotune")));
        let below_a_stream = TransportConfig::builder()
            .max_stream_data_uni(1 << 30)
            .max_stream_data_autotune(Some(1 << 20));
        assert_eq!(
            below_a_stream.build(),
            Err(out_of_range("max_stream_data_autotune"))
        );
        let above_varint = TransportConfig::builder().max_stream_data_autotune(Some(1 << 62));
        assert_eq!(
            above_varint.build(),
            Err(out_of_range("max_stream_data_autotune"))
        );
    }

    #[test]
    fn endpoint_cid_length() {
        let config = EndpointConfig::builder([7; 32]).build().unwrap();
        assert_eq!(config.local_cid_len(), 8);
        assert_eq!(config.reset_key(), &[7; 32]);
        for len in [0, 6, 20] {
            let config = EndpointConfig::builder([0; 32]).local_cid_len(len).build();
            assert_eq!(config.unwrap().local_cid_len(), len);
        }
        for len in [21, 255, 256, usize::MAX] {
            let config = EndpointConfig::builder([0; 32]).local_cid_len(len).build();
            assert_eq!(config.unwrap_err(), out_of_range("local_cid_len"), "{len}");
        }
    }

    #[test]
    fn the_build_horizon_defaults_to_zero_and_survives_a_rebuild() {
        let config = EndpointConfig::builder([0; 32]).build().unwrap();
        assert_eq!(config.build_horizon(), Duration::ZERO);
        let config = EndpointConfig::builder([0; 32])
            .build_horizon(Duration::from_millis(2))
            .build()
            .unwrap();
        assert_eq!(config.build_horizon(), Duration::from_millis(2));
        let worker = config.to_builder().worker(1, 2).build().unwrap();
        assert_eq!(worker.build_horizon(), Duration::from_millis(2));
    }

    #[test]
    fn endpoint_workers() {
        let config = EndpointConfig::builder([0; 32]).build().unwrap();
        assert_eq!(config.worker(), (0, 1));
        for (index, count) in [(0, 2), (3, 5), (255, 256)] {
            let config = EndpointConfig::builder([0; 32])
                .worker(index, count)
                .build()
                .unwrap();
            assert_eq!(config.worker(), (index, count));
        }
        for (index, count) in [(0, 0), (2, 2), (5, 3), (0, 257), (256, 300)] {
            let config = EndpointConfig::builder([0; 32])
                .worker(index, count)
                .build();
            assert_eq!(
                config.unwrap_err(),
                out_of_range("worker"),
                "{index}/{count}"
            );
        }
        let config = EndpointConfig::builder([0; 32])
            .local_cid_len(0)
            .worker(0, 2)
            .build();
        assert_eq!(
            config.unwrap_err(),
            out_of_range("worker"),
            "a zero-length ID cannot name a worker"
        );
    }

    #[test]
    fn a_config_rebuilt_for_another_worker_keeps_its_other_settings() {
        let base = EndpointConfig::builder([9; 32])
            .local_cid_len(12)
            .build()
            .unwrap();
        let config = base.to_builder().worker(3, 4).build().unwrap();
        assert_eq!(config.worker(), (3, 4));
        assert_eq!(config.local_cid_len(), 12);
        assert_eq!(config.reset_key(), &[9; 32]);
        assert_eq!(
            base.to_builder().worker(4, 4).build().unwrap_err(),
            out_of_range("worker"),
            "the rebuilt config is validated"
        );
    }

    #[test]
    fn issued_ids_keep_six_random_bytes_besides_the_worker_byte() {
        let build = |len, count| {
            EndpointConfig::builder([0; 32])
                .local_cid_len(len)
                .worker(0, count)
                .build()
        };
        for (len, count) in [(1, 256), (1, 1), (5, 1), (6, 2), (2, 256)] {
            assert_eq!(
                build(len, count).unwrap_err(),
                out_of_range("local_cid_len"),
                "{len} bytes, {count} workers"
            );
        }
        for (len, count) in [(0, 1), (6, 1), (7, 2), (7, 256), (20, 256)] {
            assert!(build(len, count).is_ok(), "{len} bytes, {count} workers");
        }
    }

    #[test]
    fn the_version_2_layout_needs_8_byte_ids_and_at_most_256_workers() {
        let v2 = CidLayout::MvfstV2 {
            host_id: 1,
            prev_host_id: 0,
            process: false,
        };
        let builder = EndpointConfig::builder([0; 32]).cid_layout(v2);
        for len in [0, 6, 7, 9, 20] {
            assert_eq!(
                builder.clone().local_cid_len(len).build().unwrap_err(),
                out_of_range("cid_layout"),
                "{len} bytes"
            );
        }
        for (index, count) in [(0, 1), (255, 256)] {
            let config = builder.clone().worker(index, count).build().unwrap();
            assert_eq!(config.cid_layout(), v2);
            assert_eq!(config.local_cid_len(), 8);
        }
        assert_eq!(
            builder.clone().worker(0, 257).build().unwrap_err(),
            out_of_range("worker"),
            "byte 4 names at most 256 workers"
        );
        let rebuilt = builder.build().unwrap().to_builder().worker(1, 2).build();
        assert_eq!(rebuilt.unwrap().cid_layout(), v2);
        let default = EndpointConfig::builder([0; 32]).build().unwrap();
        assert_eq!(default.cid_layout(), CidLayout::Random);
    }

    #[test]
    fn a_health_check_token_is_at_least_as_long_as_its_answer() {
        let config = EndpointConfig::builder([0; 32]).build().unwrap();
        assert_eq!(config.health_check_token(), None);
        let config = EndpointConfig::builder([0; 32])
            .health_check_token(&b"health"[..])
            .build()
            .unwrap();
        assert_eq!(config.health_check_token(), Some(&b"health"[..]));
        let worker = config.to_builder().worker(1, 2).build().unwrap();
        assert_eq!(worker.health_check_token(), Some(&b"health"[..]));
        for short in [&b""[..], b"h"] {
            let config = EndpointConfig::builder([0; 32])
                .health_check_token(short)
                .build();
            assert_eq!(
                config.unwrap_err(),
                out_of_range("health_check_token"),
                "{short:?} is shorter than the two-byte answer"
            );
        }
        let two = EndpointConfig::builder([0; 32])
            .health_check_token(&b"hi"[..])
            .build();
        assert!(two.is_ok());
    }

    #[test]
    fn endpoint_debug_hides_the_reset_key() {
        let config = EndpointConfig::builder([0xab; 32]).build().unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("171") && !debug.contains("ab"), "{debug}");
    }

    /// A resolver that never returns a certificate; enough to build a rustls server config.
    #[derive(Debug)]
    struct NoCertificate;

    impl ResolvesServerCert for NoCertificate {
        fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    fn server_tls(alpn: &[&[u8]]) -> rustls::ServerConfig {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        tls
    }

    fn client_tls(alpn: &[&[u8]]) -> rustls::ClientConfig {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        tls
    }

    /// Builds a provider with only TLS 1.2 suites, which QUIC cannot use.
    fn tls12_only_provider() -> Arc<rustls::crypto::CryptoProvider> {
        let mut provider = default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.suite() == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        Arc::new(provider)
    }

    #[test]
    fn server_defaults() {
        let tls = Arc::new(server_tls(&[b"h3"]));
        let config = ServerConfig::builder(tls.clone()).build().unwrap();
        assert!(Arc::ptr_eq(config.tls().rustls().unwrap(), &tls));
        assert_eq!(**config.transport(), TransportConfig::default());
        assert_eq!(config.versions(), [Version::V1]);
        assert_eq!(config.alpn(), AlpnPolicy::Required);
    }

    #[test]
    fn server_builder_sets_every_field() {
        let transport = TransportConfig::builder().pacing(true).build().unwrap();
        let config = ServerConfig::builder(Arc::new(server_tls(&[])))
            .transport(transport.clone())
            .versions(vec![Version::MVFST, Version::V1])
            .alpn(AlpnPolicy::AllowMissing)
            .build()
            .unwrap();
        assert!(Arc::ptr_eq(config.transport(), &transport));
        assert_eq!(config.versions(), [Version::MVFST, Version::V1]);
        assert_eq!(config.alpn(), AlpnPolicy::AllowMissing);
    }

    #[test]
    fn mvfst_client_hellos_without_alpn_use_the_mvfst_tls_config() {
        let tls = Arc::new(server_tls(&[b"quic_test"]));
        let no_alpn = Arc::new(server_tls(&[]));
        let config = ServerConfig::builder(tls.clone())
            .versions(vec![Version::V1, Version::MVFST])
            .mvfst_tls(no_alpn.clone())
            .build()
            .unwrap();
        let (mvfst, policy) = config.tls_without_alpn(Version::MVFST);
        assert!(Arc::ptr_eq(mvfst.unwrap(), &no_alpn));
        assert_eq!(policy, AlpnPolicy::AllowMissing);
        let (v1, policy) = config.tls_without_alpn(Version::V1);
        assert!(v1.is_none());
        assert_eq!(policy, AlpnPolicy::Required);

        // Without an MVFST config, MVFST connections use the main one.
        let config = ServerConfig::builder(tls.clone())
            .versions(vec![Version::V1, Version::MVFST])
            .build()
            .unwrap();
        let (mvfst, policy) = config.tls_without_alpn(Version::MVFST);
        assert!(mvfst.is_none());
        assert_eq!(policy, AlpnPolicy::Required);
    }

    #[test]
    fn the_mvfst_tls_config_serves_mvfsts_alias_and_not_the_aliases_of_version_1() {
        let tls = Arc::new(server_tls(&[b"quic_test"]));
        let no_alpn = Arc::new(server_tls(&[]));
        let config = ServerConfig::builder(tls)
            .versions(SUPPORTED_VERSIONS.to_vec())
            .mvfst_tls(no_alpn.clone())
            .build()
            .unwrap();
        let (alias, policy) = config.tls_without_alpn(Version::MVFST_ALIAS);
        assert!(alias.is_some_and(|alias| Arc::ptr_eq(alias, &no_alpn)));
        assert_eq!(policy, AlpnPolicy::AllowMissing);
        for version in [Version::QUIC_V1_ALIAS, Version::QUIC_V1_ALIAS2] {
            let (tls, policy) = config.tls_without_alpn(version);
            assert!(tls.is_none(), "{version:?}");
            assert_eq!(policy, AlpnPolicy::Required);
        }
    }

    #[test]
    fn external_configs_build_without_rustls_but_take_no_mvfst_tls_config() {
        let server = ServerConfig::builder(ServerTls::External)
            .versions(vec![Version::V1, Version::MVFST])
            .build()
            .unwrap();
        assert!(server.tls().rustls().is_none());
        let (mvfst, policy) = server.tls_without_alpn(Version::MVFST);
        assert!(mvfst.is_none());
        assert_eq!(policy, AlpnPolicy::Required);
        let client = ClientConfig::builder(ClientTls::External).build().unwrap();
        assert!(client.tls().rustls().is_none());
        // The host answers ClientHellos without ALPN itself.
        let mvfst = ServerConfig::builder(ServerTls::External)
            .versions(vec![Version::V1, Version::MVFST])
            .mvfst_tls(Arc::new(server_tls(&[])))
            .build();
        assert_eq!(mvfst.unwrap_err(), out_of_range("mvfst_tls"));
    }

    #[test]
    fn the_mvfst_tls_config_is_checked_like_the_main_one() {
        let main = Arc::new(server_tls(&[b"quic_test"]));
        let build = |mvfst: rustls::ServerConfig| {
            ServerConfig::builder(main.clone())
                .versions(vec![Version::V1, Version::MVFST])
                .mvfst_tls(Arc::new(mvfst))
                .build()
        };
        let mut early = server_tls(&[]);
        early.max_early_data_size = u32::MAX;
        assert_eq!(build(early).unwrap_err(), ConfigError::EarlyDataUnsupported);
        let tls12 = rustls::ServerConfig::builder_with_provider(tls12_only_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        assert_eq!(build(tls12).unwrap_err(), ConfigError::NoQuicCipherSuite);
        let no_tls13 = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        assert_tls13_refused(build(no_tls13).unwrap_err());
        assert!(build(server_tls(&[])).is_ok());
    }

    #[test]
    fn server_versions_must_be_implemented_and_distinct() {
        let tls = Arc::new(server_tls(&[b"h3"]));
        let build = |versions: Vec<Version>| {
            ServerConfig::builder(tls.clone())
                .versions(versions)
                .build()
                .unwrap_err()
        };
        assert_eq!(build(vec![]), ConfigError::NoVersions);
        assert_eq!(
            build(vec![Version::V1, Version(0x6b33_43cf)]),
            ConfigError::UnsupportedVersion(Version(0x6b33_43cf))
        );
        assert_eq!(
            build(vec![Version::NEGOTIATION]),
            ConfigError::UnsupportedVersion(Version::NEGOTIATION)
        );
        assert_eq!(
            build(vec![Version::MVFST, Version::V1, Version::MVFST]),
            ConfigError::DuplicateVersion(Version::MVFST)
        );
    }

    #[test]
    fn a_server_always_accepts_version_1() {
        let tls = Arc::new(server_tls(&[b"h3"]));
        let config = ServerConfig::builder(tls.clone())
            .versions(vec![Version::MVFST])
            .build();
        assert_eq!(config.unwrap_err(), ConfigError::Version1Required);
        let config = ServerConfig::builder(tls)
            .versions(vec![Version::MVFST, Version::V1])
            .build();
        assert!(config.is_ok());
    }

    #[test]
    fn server_required_alpn_needs_protocols() {
        let config = ServerConfig::builder(Arc::new(server_tls(&[]))).build();
        assert_eq!(
            config.unwrap_err(),
            ConfigError::AlpnRequiredWithoutProtocols
        );
        let config = ServerConfig::builder(Arc::new(server_tls(&[b"quic_test"])))
            .alpn(AlpnPolicy::AllowMissing)
            .build();
        assert!(config.is_ok());
    }

    #[test]
    fn server_needs_a_quic_cipher_suite() {
        let tls = rustls::ServerConfig::builder_with_provider(tls12_only_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        let config = ServerConfig::builder(Arc::new(tls))
            .alpn(AlpnPolicy::AllowMissing)
            .build();
        assert_eq!(config.unwrap_err(), ConfigError::NoQuicCipherSuite);
    }

    #[test]
    fn server_rejects_early_data() {
        let mut tls = server_tls(&[b"h3"]);
        tls.max_early_data_size = u32::MAX;
        let config = ServerConfig::builder(Arc::new(tls)).build();
        assert_eq!(config.unwrap_err(), ConfigError::EarlyDataUnsupported);
    }

    #[test]
    fn accept_early_data_lets_tickets_allow_early_data() {
        let tls = Arc::new(server_tls(&[b"h3"]));
        let plain = ServerConfig::builder(tls.clone()).build().unwrap();
        assert_eq!(plain.tls().rustls().unwrap().max_early_data_size, 0);
        let early = ServerConfig::builder(tls)
            .accept_early_data(true)
            .build()
            .unwrap();
        let early = early.tls().rustls().unwrap();
        assert_eq!(early.max_early_data_size, u32::MAX);
        assert!(early.send_tls13_tickets >= 1);
    }

    /// Asserts that rustls refused the config because it does not enable TLS 1.3.
    fn assert_tls13_refused(error: ConfigError) {
        let ConfigError::Tls(tls_error @ rustls::Error::General(reason)) = &error else {
            panic!("{error:?}");
        };
        assert!(reason.contains("TLS 1.3"), "{reason}");
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<rustls::Error>());
        assert_eq!(source, Some(tls_error));
    }

    #[test]
    fn server_needs_tls13_enabled() {
        // The provider keeps its QUIC-capable TLS 1.3 suites; only the version list drops them.
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        let config = ServerConfig::builder(Arc::new(tls))
            .alpn(AlpnPolicy::AllowMissing)
            .build();
        assert_tls13_refused(config.unwrap_err());
    }

    #[test]
    fn client_defaults() {
        let tls = Arc::new(client_tls(&[b"h3"]));
        let config = ClientConfig::builder(tls.clone()).build().unwrap();
        assert!(Arc::ptr_eq(config.tls().rustls().unwrap(), &tls));
        assert_eq!(**config.transport(), TransportConfig::default());
        assert_eq!(config.versions(), [Version::V1]);
        assert_eq!(config.alpn(), AlpnPolicy::Required);
    }

    #[test]
    fn client_builder_validates_like_the_server() {
        let transport = TransportConfig::builder().build().unwrap();
        let config = ClientConfig::builder(Arc::new(client_tls(&[])))
            .transport(transport.clone())
            .versions(vec![Version::MVFST])
            .alpn(AlpnPolicy::AllowMissing)
            .build()
            .unwrap();
        assert!(Arc::ptr_eq(config.transport(), &transport));
        assert_eq!(config.versions(), [Version::MVFST]);
        assert_eq!(config.alpn(), AlpnPolicy::AllowMissing);

        let tls = Arc::new(client_tls(&[b"h3"]));
        let build = |versions: Vec<Version>| {
            ClientConfig::builder(tls.clone())
                .versions(versions)
                .build()
                .unwrap_err()
        };
        assert_eq!(build(vec![]), ConfigError::NoVersions);
        assert_eq!(
            build(vec![Version(2)]),
            ConfigError::UnsupportedVersion(Version(2))
        );
        assert_eq!(
            build(vec![Version::V1, Version::V1]),
            ConfigError::DuplicateVersion(Version::V1)
        );

        let config = ClientConfig::builder(Arc::new(client_tls(&[]))).build();
        assert_eq!(
            config.unwrap_err(),
            ConfigError::AlpnRequiredWithoutProtocols
        );

        let mut early = client_tls(&[b"h3"]);
        early.enable_early_data = true;
        assert!(ClientConfig::builder(Arc::new(early)).build().is_ok());

        let tls12 = rustls::ClientConfig::builder_with_provider(tls12_only_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let config = ClientConfig::builder(Arc::new(tls12))
            .alpn(AlpnPolicy::AllowMissing)
            .build();
        assert_eq!(config.unwrap_err(), ConfigError::NoQuicCipherSuite);
    }

    #[test]
    fn client_needs_tls13_enabled() {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let config = ClientConfig::builder(Arc::new(tls))
            .alpn(AlpnPolicy::AllowMissing)
            .build();
        assert_tls13_refused(config.unwrap_err());
    }

    /// A client session store that counts how often rustls calls it.
    #[derive(Debug, Default)]
    struct CountingStore(AtomicUsize);

    impl CountingStore {
        fn touch(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl ClientSessionStore for CountingStore {
        fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {
            self.touch();
        }

        fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
            self.touch();
            None
        }

        fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {
            self.touch();
        }

        fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
            self.touch();
            None
        }

        fn remove_tls12_session(&self, _: &ServerName<'static>) {
            self.touch();
        }

        fn insert_tls13_ticket(&self, _: ServerName<'static>, _: Tls13ClientSessionValue) {
            self.touch();
        }

        fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
            self.touch();
            None
        }
    }

    #[test]
    fn client_validation_leaves_the_session_store_alone() {
        let store = Arc::new(CountingStore::default());
        let mut tls = client_tls(&[b"h3"]);
        tls.resumption = Resumption::store(store.clone());
        ClientConfig::builder(Arc::new(tls)).build().unwrap();
        assert_eq!(store.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connection_options_default_to_no_overrides() {
        assert!(ConnOptions::default().transport.is_none());
    }

    #[test]
    fn configs_are_shareable_across_workers() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EndpointConfig>();
        assert_send_sync::<TransportConfig>();
        assert_send_sync::<ServerConfig>();
        assert_send_sync::<ClientConfig>();
        assert_send_sync::<ConnOptions>();
    }
}
