/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The External handshake backend: a TLS stack outside the session runs the handshake.
//!
//! An External [`TlsSession`](crate::TlsSession) holds plain data: the CRYPTO bytes waiting for
//! the host, the outputs the host delivered, and what the handshake negotiated. The caller moves
//! work between the session and a [`TlsHost`]: it takes each [`TlsInput`] from
//! [`TlsSession::tls_input`](crate::TlsSession::tls_input), hands it to the host, and gives the
//! host's [`TlsStep`] back with [`TlsSession::deliver`](crate::TlsSession::deliver), at once or
//! later. The host is never called from inside a session method, so its clock, random source and
//! asynchronous work stay outside the session, like a peer's.

use std::collections::VecDeque;
use std::fmt;

use bytes::Bytes;
use mvfstr_crypto::AES_128_GCM;
use mvfstr_crypto::AES_256_GCM;
use mvfstr_crypto::CHACHA20_POLY1305;
use mvfstr_crypto::KeySet;
use mvfstr_crypto::KeyUpdater;
use mvfstr_crypto::PacketKeys;
use mvfstr_crypto::QuicAlgorithm;
use mvfstr_crypto::SecretHash;
use mvfstr_crypto::TrafficSecret;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::Version;
use rustls::AlertDescription;
use rustls::PeerMisbehaved;

use crate::session::ClientHello;
use crate::session::CryptoOutput;
use crate::session::KeyChange;
use crate::session::Level;
use crate::session::PostHandshake;
use crate::session::TlsError;
use crate::session::alert_of;
use crate::session::has_transport_parameters;
use crate::session::parse_client_hello;
use crate::session::refusal;

/// The caller's name for one connection in its calls to a [`TlsHost`]. The session and the host
/// do not interpret it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TlsConnId(pub u64);

/// A TLS 1.3 cipher suite whose QUIC packet protection mvfstr implements (RFC 8446, RFC 9001).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsSuite {
    /// TLS_AES_128_GCM_SHA256, 0x1301.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384, 0x1302.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256, 0x1303.
    Chacha20Poly1305Sha256,
}

impl TlsSuite {
    /// Returns the suite with this TLS codepoint, or `None` for a suite mvfstr does not implement.
    pub fn from_codepoint(codepoint: u16) -> Option<TlsSuite> {
        match codepoint {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Returns the suite's TLS codepoint.
    pub fn codepoint(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Returns the QUIC packet protection of the suite's AEAD.
    pub(crate) fn algorithm(self) -> &'static QuicAlgorithm {
        match self {
            Self::Aes128GcmSha256 => &AES_128_GCM,
            Self::Aes256GcmSha384 => &AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &CHACHA20_POLY1305,
        }
    }

    /// Returns the hash of the suite, whose output length is that of its traffic secrets.
    pub(crate) fn hash(self) -> SecretHash {
        match self {
            Self::Aes256GcmSha384 => SecretHash::Sha384,
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => SecretHash::Sha256,
        }
    }
}

/// The client's and the server's traffic secrets of one encryption level.
#[derive(Debug)]
pub struct SecretPair {
    /// The secret that protects what the client sends.
    pub client: TrafficSecret,
    /// The secret that protects what the server sends.
    pub server: TrafficSecret,
}

/// One piece of work for a [`TlsHost`], from
/// [`TlsSession::tls_input`](crate::TlsSession::tls_input).
#[derive(Debug)]
pub enum TlsInput<'a> {
    /// The first input of a connection: what the host needs to create its TLS state. A client's
    /// host answers with the client's first flight; a server's host does not send anything yet. A
    /// server gets this input once the whole ClientHello has arrived, or as soon as the header of
    /// another message, or of a ClientHello longer than 0xffff bytes, arrives.
    Start {
        /// The role of this endpoint.
        side: Side,
        /// The QUIC version, which picks the transport parameters extension: 0x39 for v1, 0xffa5
        /// for MVFST.
        version: Version,
        /// This endpoint's encoded transport parameters, for the host to send.
        transport_params: &'a [u8],
        /// The name a client asks for (SNI); `None` for a server.
        server_name: Option<&'a str>,
    },
    /// CRYPTO bytes received at `level`, in order, as chunks. A ClientHello comes whole, or only
    /// its start if it is longer than 0xffff bytes.
    Crypto {
        /// The encryption level of the bytes.
        level: Level,
        /// The bytes.
        data: &'a [Bytes],
    },
    /// A server asks its host for a session ticket that carries `app_token`.
    WriteTicket {
        /// The application token to put in the ticket.
        app_token: &'a [u8],
    },
    /// The handshake is confirmed: the host frees its TLS state for the connection.
    Finish,
}

/// What a [`TlsHost`] produced for one [`TlsInput`]: CRYPTO bytes to send, new secrets, what the
/// handshake negotiated, and events.
///
/// Within a step, levels only move forward: the bytes at a level go out before the keys of the
/// next level are installed, so Handshake secrets follow the Initial bytes and 1-RTT secrets follow
/// the Handshake bytes. The 0-RTT keys from `client_early` come with the step's first bytes.
#[derive(Debug, Default)]
pub struct TlsStep {
    /// CRYPTO bytes to send, indexed by [`Level`] (Initial, Handshake, 1-RTT).
    pub crypto: [Vec<u8>; 3],
    /// The negotiated cipher suite, which the secrets of this step belong to. Required with any
    /// secret.
    pub suite: Option<TlsSuite>,
    /// The client's early traffic secret, which keys 0-RTT packets: write keys for a client, read
    /// keys for a server that accepted early data.
    pub client_early: Option<TrafficSecret>,
    /// The handshake traffic secrets.
    pub handshake: Option<SecretPair>,
    /// The first application traffic secrets, which key 1-RTT packets and their key updates.
    pub app: Option<SecretPair>,
    /// The exporter master secret, for keying-material exporters (RFC 8446). The session does not
    /// keep it: a host that serves exporters keeps its own copy, which outlives `Finish`.
    pub exporter: Option<TrafficSecret>,
    /// The transport parameters the peer sent, raw, in wire order.
    pub peer_transport_params: Option<Vec<u8>>,
    /// The negotiated application protocol.
    pub alpn: Option<Vec<u8>>,
    /// Early data is accepted: a server's host accepted the client's 0-RTT, or a client's host
    /// read the server's acceptance.
    pub early_success: bool,
    /// The host has verified the peer's Finished and, with this step's bytes, sent its own.
    pub handshake_success: bool,
    /// The fatal alert the handshake failed with.
    pub alert: Option<u8>,
    /// What the handshake negotiated, for logging and counters.
    pub summary: Option<Box<HandshakeSummary>>,
    /// The host's verdict on the app token of a resumed ticket.
    pub app_token: Option<AppTokenVerdict>,
}

/// What a handshake negotiated, as a TLS host reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandshakeSummary {
    /// The key exchange group, as its TLS NamedGroup codepoint.
    pub group: Option<u16>,
    /// What became of a pre-shared key.
    pub psk: PskOutcome,
    /// The PSK key exchange mode, when a PSK was used.
    pub psk_mode: Option<PskMode>,
    /// What became of early data.
    pub early_data: EarlyDataOutcome,
    /// The replay cache's result for the ClientHello.
    pub replay: ReplayCheck,
    /// What became of Encrypted Client Hello.
    pub ech: EchOutcome,
    /// The server name the client asked for.
    pub sni: Option<String>,
    /// The certificate compression algorithm, as its TLS codepoint (RFC 8879).
    pub cert_compression: Option<u16>,
    /// The difference between the client's and the server's clock, in milliseconds, from a
    /// resumed ticket's age.
    pub clock_skew_ms: Option<i64>,
}

/// What became of a pre-shared key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PskOutcome {
    /// The client did not offer a PSK.
    #[default]
    NotAttempted,
    /// A PSK was offered and refused.
    Rejected,
    /// A resumption PSK from a ticket was used.
    Resumption,
    /// An external PSK was used.
    External,
}

/// A PSK key exchange mode (RFC 8446).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskMode {
    /// psk_ke: the PSK alone.
    Ke,
    /// psk_dhe_ke: the PSK with a Diffie-Hellman exchange.
    DheKe,
}

/// What became of early data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EarlyDataOutcome {
    /// The client did not offer early data.
    #[default]
    NotAttempted,
    /// The server refused the client's early data.
    Rejected,
    /// The server accepted the client's early data.
    Accepted,
}

/// The result of a server's replay cache check on a ClientHello with early data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplayCheck {
    /// The server did not check the cache.
    #[default]
    NotChecked,
    /// The ClientHello is not a replay.
    NotReplay,
    /// The ClientHello may be a replay.
    MaybeReplay,
    /// The ClientHello is a replay.
    DefinitelyReplay,
}

/// What became of Encrypted Client Hello.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EchOutcome {
    /// The client did not offer ECH.
    #[default]
    NotRequested,
    /// The server decrypted the inner ClientHello.
    Accepted,
    /// The server could not decrypt it and used the outer ClientHello.
    Rejected,
}

/// A server host's verdict on the app token of a resumed ticket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppTokenVerdict {
    /// The ticket carried an app token and the host checked it.
    pub present: bool,
    /// The app token allows early data.
    pub accepted: bool,
}

/// Whether a [`TlsHost`] produced a step at once.
#[derive(Debug)]
pub enum TlsPoll {
    /// The step for the input.
    Ready(TlsStep),
    /// The step comes later, from [`TlsHost::poll_ready`].
    Pending,
}

/// A TLS stack outside mvfstr that runs the handshakes of External sessions, for example a C++
/// TLS library behind a small shim.
///
/// The caller hands each connection's inputs to the host in order and gives each step back to the
/// connection's session. A connection has at most one input with the host at a time.
pub trait TlsHost {
    /// Handles one input of connection `conn`.
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll;

    /// Returns a step that completed after [`handle`](Self::handle) returned
    /// [`TlsPoll::Pending`], with the connection it belongs to.
    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)>;

    /// Drops the host's state for `conn`, and any step it has not returned yet.
    fn cancel(&mut self, conn: TlsConnId);
}

/// The most CRYPTO bytes an External session holds for its host besides a server's ClientHello,
/// including those handed with an input the host has not answered: as many as mvfstr_proto keeps
/// out of order at one level.
const MAX_WAITING_BYTES: usize = 64 * 1024;
/// The most chunks it holds them in, so that tiny CRYPTO frames cannot cost a `Bytes` and an
/// allocation each without bound.
const MAX_WAITING_CHUNKS: usize = 1024;

/// The state of a [`TlsSession`](crate::TlsSession) whose handshake runs on a [`TlsHost`].
pub struct ExternalSession {
    side: Side,
    version: Version,
    /// The level of the CRYPTO bytes [`write_crypto`](Self::write_crypto) returns next.
    write_level: Level,
    /// This endpoint's transport parameters and, for a client, the server name, for the host.
    transport_params: Vec<u8>,
    server_name: Option<Box<str>>,
    /// Whether the host has had the `Start` input.
    started: bool,
    /// Whether the host has an input whose step is not delivered.
    pending: bool,
    /// The app token of a ticket a server asked for, and whether the host has the request.
    ticket: Option<Vec<u8>>,
    ticket_handed: bool,
    /// Whether the handshake is confirmed, and whether the host has had the `Finish` input.
    finishing: bool,
    finished: bool,
    /// The start of the ClientHello a server is receiving, not yet waiting for the host.
    partial_hello: Vec<u8>,
    /// Whether a server has queued its ClientHello for the host and not drained the answer yet.
    hello_unanswered: bool,
    post_handshake: PostHandshake,
    /// CRYPTO bytes received at the level the host reads that the host has not consumed, and
    /// their total length.
    waiting: Vec<Bytes>,
    waiting_len: usize,
    /// The number of chunks of `waiting` handed to the host with the last input.
    handed: usize,
    /// Outputs the host delivered and the caller has not drained.
    outputs: VecDeque<Output>,
    /// The write level once every queued output is drained.
    queued_level: Level,
    peer_transport_params: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    /// Whether the host reported the handshake's success.
    handshake_success: bool,
    /// What the host reported about early data, the handshake, and a resumed ticket's app token.
    early_accepted: bool,
    summary: Option<Box<HandshakeSummary>>,
    app_token: Option<AppTokenVerdict>,
    /// The fatal alert the handshake failed with.
    alert: Option<u8>,
}

/// One output of [`write_crypto`](ExternalSession::write_crypto): CRYPTO bytes at a level, then
/// the keys installed after them.
struct Output {
    level: Level,
    bytes: Vec<u8>,
    keys: Option<KeyChange>,
}

impl ExternalSession {
    pub(crate) fn new(
        side: Side,
        version: Version,
        transport_params: Vec<u8>,
        server_name: Option<&str>,
    ) -> Box<ExternalSession> {
        Box::new(ExternalSession {
            side,
            version,
            write_level: Level::Initial,
            transport_params,
            server_name: server_name.map(Box::from),
            started: false,
            pending: false,
            ticket: None,
            ticket_handed: false,
            finishing: false,
            finished: false,
            partial_hello: Vec::new(),
            hello_unanswered: false,
            post_handshake: PostHandshake::default(),
            waiting: Vec::new(),
            waiting_len: 0,
            handed: 0,
            outputs: VecDeque::new(),
            queued_level: Level::Initial,
            peer_transport_params: None,
            alpn: None,
            handshake_success: false,
            early_accepted: false,
            summary: None,
            app_token: None,
            alert: None,
        })
    }

    pub(crate) fn side(&self) -> Side {
        self.side
    }

    pub(crate) fn version(&self) -> Version {
        self.version
    }

    pub(crate) fn read_level(&self) -> Level {
        host_read_level(self.write_level, self.handshake_success)
    }

    pub(crate) fn write_level(&self) -> Level {
        self.write_level
    }

    /// Returns the level the host reads: that of the keys it delivered, drained or not.
    fn host_read_level(&self) -> Level {
        host_read_level(self.queued_level, self.handshake_success)
    }

    pub(crate) fn read_crypto(&mut self, level: Level, data: &[u8]) -> Result<(), TlsError> {
        let expected = self.read_level();
        if level != expected {
            return Err(TlsError::WrongLevel { level, expected });
        }
        if data.is_empty() {
            return Ok(());
        }
        if level == Level::OneRtt
            && let Err(error) = self.post_handshake.read(self.side, data)
        {
            self.alert = alert_of(&error).map(u8::from).or(self.alert);
            return Err(error);
        }
        // A finished session drops the tickets it reads.
        if self.finishing {
            return Ok(());
        }
        let client_hello = level == Level::Initial && self.side == Side::Server;
        // A ClientHello must end its flight (RFC 8446), so bytes that follow it before its answer
        // is drained are refused with unexpected_message, as rustls refuses them.
        if client_hello && self.hello_unanswered {
            return Err(self.refuse(unexpected_message()));
        }
        // The host has delivered the keys of a later level, which the caller has not drained yet.
        if level != self.host_read_level() {
            return Err(TlsError::LeftUnread { level });
        }
        if client_hello {
            return self.read_client_hello(data);
        }
        // mvfstr_proto consumes the bytes the session takes, so its bound on buffered CRYPTO bytes
        // does not cover these.
        let full = self.waiting.len() >= MAX_WAITING_CHUNKS;
        if full || self.waiting_len + data.len() > MAX_WAITING_BYTES {
            return Err(TlsError::BufferExceeded { level });
        }
        self.waiting_len += data.len();
        self.waiting.push(Bytes::copy_from_slice(data));
        Ok(())
    }

    /// Reads a server's Initial bytes: a ClientHello, which the host gets in one input once all
    /// of it has arrived. Bytes that come with it are refused with unexpected_message.
    fn read_client_hello(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.partial_hello.extend_from_slice(data);
        let received = self.partial_hello.len();
        match parse_client_hello(&self.partial_hello) {
            ClientHello::Partial => return Ok(()),
            ClientHello::Whole(body) if !has_transport_parameters(self.version, body) => {
                let alert = AlertDescription::MissingExtension;
                return Err(self.refuse((alert, PeerMisbehaved::MissingQuicTransportParameters)));
            }
            ClientHello::Whole(body) if 4 + body.len() < received => {
                return Err(self.refuse(unexpected_message()));
            }
            ClientHello::Whole(_) | ClientHello::Refused => {}
        }
        let hello = std::mem::take(&mut self.partial_hello);
        self.waiting_len += hello.len();
        self.waiting.push(Bytes::from(hello));
        self.hello_unanswered = true;
        Ok(())
    }

    /// Fails the handshake with `alert` for a peer's misbehaviour.
    fn refuse(&mut self, (alert, why): (AlertDescription, PeerMisbehaved)) -> TlsError {
        self.alert = Some(u8::from(alert));
        refusal(alert, why)
    }

    pub(crate) fn write_crypto(&mut self, buf: &mut Vec<u8>) -> Option<CryptoOutput> {
        let output = self.outputs.pop_front()?;
        self.release();
        // The answer to a ClientHello is drained: a ServerHello or a HelloRetryRequest.
        self.hello_unanswered = false;
        buf.extend_from_slice(&output.bytes);
        match &output.keys {
            Some(KeyChange::Handshake(_)) => self.write_level = Level::Handshake,
            Some(KeyChange::OneRtt { .. }) => self.write_level = Level::OneRtt,
            Some(KeyChange::ZeroRtt(_)) | None => {}
        }
        Some(CryptoOutput {
            level: output.level,
            len: output.bytes.len(),
            keys: output.keys,
        })
    }

    pub(crate) fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_deref()
    }

    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub(crate) fn is_early_data_accepted(&self) -> bool {
        self.early_accepted
    }

    pub(crate) fn handshake_summary(&self) -> Option<&HandshakeSummary> {
        self.summary.as_deref()
    }

    pub(crate) fn app_token_verdict(&self) -> Option<AppTokenVerdict> {
        self.app_token
    }

    pub(crate) fn is_handshake_complete(&self) -> bool {
        self.write_level == Level::OneRtt && self.handshake_success
    }

    pub(crate) fn alert(&self) -> Option<TransportErrorCode> {
        self.alert.map(TransportErrorCode::crypto)
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }

    pub(crate) fn tls_input(&mut self) -> Option<TlsInput<'_>> {
        if self.pending || self.finished {
            return None;
        }
        if let Some(app_token) = &self.ticket {
            self.ticket_handed = true;
            self.pending = true;
            return Some(TlsInput::WriteTicket { app_token });
        }
        if self.finishing {
            self.finished = true;
            self.pending = true;
            return Some(TlsInput::Finish);
        }
        // A server's host starts once the whole ClientHello, or a header TLS refuses, is waiting.
        let can_start = self.side == Side::Client || !self.waiting.is_empty();
        if !self.started && can_start {
            self.started = true;
            self.pending = true;
            return Some(TlsInput::Start {
                side: self.side,
                version: self.version,
                transport_params: &self.transport_params,
                server_name: self.server_name.as_deref(),
            });
        }
        if !self.started || self.waiting.is_empty() {
            return None;
        }
        self.handed = self.waiting.len();
        self.pending = true;
        Some(TlsInput::Crypto {
            level: self.host_read_level(),
            data: &self.waiting,
        })
    }

    pub(crate) fn deliver(&mut self, mut step: TlsStep) -> Result<(), TlsError> {
        if !self.pending {
            return Err(TlsError::NotPending);
        }
        self.pending = false;
        if self.ticket_handed {
            self.ticket = None;
            self.ticket_handed = false;
        }
        let consumed: usize = self
            .waiting
            .drain(..self.handed)
            .map(|chunk| chunk.len())
            .sum();
        self.waiting_len -= consumed;
        self.handed = 0;
        if let Some(alert) = step.alert {
            self.alert = Some(alert);
            return Err(TlsError::HostAlert(alert));
        }
        let queued = self.outputs.len();
        let Some(level) = self.queue_outputs(&mut step) else {
            self.outputs.truncate(queued);
            return Err(TlsError::InvalidStep);
        };
        // When TLS moves to a later level, bytes of the old level it has not read are a
        // PROTOCOL_VIOLATION (RFC 9001).
        let reading = self.host_read_level();
        let success = self.handshake_success || step.handshake_success;
        if !self.waiting.is_empty() && host_read_level(level, success) != reading {
            self.outputs.truncate(queued);
            return Err(TlsError::LeftUnread { level: reading });
        }
        self.queued_level = level;
        if let Some(params) = step.peer_transport_params {
            self.peer_transport_params = Some(params);
        }
        if let Some(alpn) = step.alpn {
            self.alpn = Some(alpn);
        }
        self.handshake_success |= step.handshake_success;
        self.early_accepted |= step.early_success;
        if let Some(summary) = step.summary {
            self.summary = Some(summary);
        }
        if let Some(verdict) = step.app_token {
            self.app_token = Some(verdict);
        }
        self.release();
        Ok(())
    }

    /// Queues a step's CRYPTO bytes and keys as outputs, a level at a time from `queued_level`.
    /// Returns the level they end at, or `None` if a secret does not use the suite's hash, or if
    /// bytes or secrets of the step are left over.
    fn queue_outputs(&mut self, step: &mut TlsStep) -> Option<Level> {
        if let Some(suite) = step.suite {
            let pairs = step.handshake.iter().chain(&step.app);
            let paired = pairs.flat_map(|pair| [&pair.client, &pair.server]);
            let mut secrets = step.client_early.iter().chain(paired);
            if secrets.any(|secret| secret.hash() != suite.hash()) {
                return None;
            }
        }
        let mut level = self.queued_level;
        let mut output = Output {
            level,
            bytes: std::mem::take(&mut step.crypto[level as usize]),
            keys: None,
        };
        if let Some(suite) = step.suite {
            if let Some(early) = step.client_early.take() {
                let keys = PacketKeys::from_traffic_secret(suite.algorithm(), &early);
                output.keys = Some(KeyChange::ZeroRtt(keys));
                self.outputs.push_back(output);
                output = Output {
                    level,
                    bytes: Vec::new(),
                    keys: None,
                };
            }
            loop {
                let keys = match level {
                    Level::Initial => step
                        .handshake
                        .take()
                        .map(|pair| KeyChange::Handshake(self.key_set(suite, &pair))),
                    Level::Handshake => step.app.take().map(|pair| self.one_rtt(suite, pair)),
                    Level::OneRtt => None,
                };
                let Some(keys) = keys else {
                    break;
                };
                output.keys = Some(keys);
                self.outputs.push_back(output);
                level = match level {
                    Level::Initial => Level::Handshake,
                    Level::Handshake | Level::OneRtt => Level::OneRtt,
                };
                output = Output {
                    level,
                    bytes: std::mem::take(&mut step.crypto[level as usize]),
                    keys: None,
                };
            }
        }
        if !output.bytes.is_empty() {
            self.outputs.push_back(output);
        }
        let left_over = step.crypto.iter().any(|bytes| !bytes.is_empty())
            || step.client_early.is_some()
            || step.handshake.is_some()
            || step.app.is_some();
        (!left_over).then_some(level)
    }

    /// Queues a `WriteTicket` input for a complete server handshake, one at a time.
    pub(crate) fn request_ticket(&mut self, app_token: Vec<u8>) {
        let can_ask = self.side == Side::Server && self.is_handshake_complete() && !self.finishing;
        if can_ask && self.ticket.is_none() {
            self.ticket = Some(app_token);
        }
    }

    /// Frees the buffers of a complete handshake and queues the `Finish` input, which lets the
    /// host free its state.
    pub(crate) fn finish(&mut self) {
        if !self.is_handshake_complete() || self.finishing {
            return;
        }
        self.finishing = true;
        self.transport_params = Vec::new();
        self.server_name = None;
        self.partial_hello = Vec::new();
        self.release();
    }

    /// Frees the buffers of a finishing session once its host does not hold an input and every
    /// output is drained. A ticket's step allocates the output queue again, until it is drained.
    fn release(&mut self) {
        if self.finishing && !self.pending && self.outputs.is_empty() {
            self.waiting = Vec::new();
            self.waiting_len = 0;
            self.outputs = VecDeque::new();
        }
    }

    /// Returns this endpoint's local and remote secrets of a pair.
    fn local_remote(&self, pair: SecretPair) -> (TrafficSecret, TrafficSecret) {
        match self.side {
            Side::Client => (pair.client, pair.server),
            Side::Server => (pair.server, pair.client),
        }
    }

    fn key_set(&self, suite: TlsSuite, pair: &SecretPair) -> KeySet {
        let (local, remote) = match self.side {
            Side::Client => (&pair.client, &pair.server),
            Side::Server => (&pair.server, &pair.client),
        };
        KeySet::from_secrets(suite.algorithm(), local, remote)
    }

    fn one_rtt(&self, suite: TlsSuite, pair: SecretPair) -> KeyChange {
        let keys = self.key_set(suite, &pair);
        let (local, remote) = self.local_remote(pair);
        let update = KeyUpdater::from_secrets(suite.algorithm(), local, remote, &keys);
        KeyChange::OneRtt { keys, update }
    }
}

/// Returns the level TLS reads once the keys of `level` are installed: a server reads Handshake
/// bytes until the client's Finished completes the handshake.
fn host_read_level(level: Level, handshake_success: bool) -> Level {
    match level {
        Level::OneRtt if !handshake_success => Level::Handshake,
        level => level,
    }
}

/// Returns the refusal of CRYPTO bytes that come after the last message at their level.
fn unexpected_message() -> (AlertDescription, PeerMisbehaved) {
    let alert = AlertDescription::UnexpectedMessage;
    (alert, PeerMisbehaved::KeyEpochWithPendingFragment)
}

impl fmt::Debug for ExternalSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalSession")
            .field("side", &self.side)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvfstr_crypto::TrafficSecret;
    use mvfstr_wire::Side;
    use mvfstr_wire::TransportErrorCode;
    use mvfstr_wire::Version;

    use crate::ServerVerification;
    use crate::external::AppTokenVerdict;
    use crate::external::HandshakeSummary;
    use crate::external::MAX_WAITING_BYTES;
    use crate::external::MAX_WAITING_CHUNKS;
    use crate::external::Output;
    use crate::external::PskOutcome;
    use crate::external::SecretPair;
    use crate::external::TlsHost;
    use crate::external::TlsStep;
    use crate::external::TlsSuite;
    use crate::session::Level;
    use crate::session::TlsError;
    use crate::session::TlsSession;
    use crate::testing::RustlsHost;
    use crate::testing::fixtures::*;

    /// Runs a handshake to its end and returns both peers.
    fn handshake(mut client: Peer, mut server: Peer) -> (Peer, Peer) {
        run(&mut client, &mut server).unwrap();
        (client, server)
    }

    #[test]
    fn an_external_server_on_rustls_sends_the_bytes_of_an_inline_server() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let client = || Peer::rustls_client(Version::V1, &[b"h3"]);
        let (inline_client, inline_server) =
            handshake(client(), Peer::rustls_server(config(), Version::V1));
        let (client, server) = handshake(client(), Peer::external_server(config(), Version::V1));

        // ServerHello; EncryptedExtensions to Finished; NewSessionTickets.
        let levels: Vec<_> = server.sent.iter().map(|(level, _)| *level).collect();
        assert_eq!(levels, [Level::Initial, Level::Handshake, Level::OneRtt]);
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.sent, inline_client.sent);
        assert_eq!(server.fingerprints(), inline_server.fingerprints());
        assert_eq!(server.fingerprints().len(), 2);

        assert!(server.tls.is_handshake_complete() && client.tls.is_handshake_complete());
        assert_eq!(server.tls.peer_transport_params(), Some(CLIENT_PARAMS));
        assert_eq!(client.tls.peer_transport_params(), Some(SERVER_PARAMS));
        assert_eq!(server.tls.alpn(), Some(&b"h3"[..]));
        assert_eq!(server.tls.side(), Side::Server);
        assert_eq!(server.tls.version(), Version::V1);
        assert_eq!(server.tls.read_level(), Level::OneRtt);
        assert_eq!(server.tls.write_level(), Level::OneRtt);
        let hello_len = inline_client.sent[0].1.len();
        let finished_len = inline_client.sent[1].1.len();
        assert_eq!(
            server.handed,
            [
                Handed::Start(Side::Server),
                Handed::Crypto(Level::Initial, vec![hello_len]),
                Handed::Crypto(Level::Handshake, vec![finished_len]),
            ]
        );
    }

    #[test]
    fn an_external_client_on_rustls_sends_the_bytes_of_an_inline_client() {
        let cert = Cert::new();
        let server =
            || Peer::rustls_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        let (inline_client, inline_server) =
            handshake(Peer::rustls_client(Version::V1, &[b"h3"]), server());
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        // The host writes the ClientHello before any CRYPTO frame arrives.
        assert_eq!(
            client.tls.tls_input().map(|input| Handed::of(&input)),
            Some(Handed::Start(Side::Client))
        );
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server = server();
        run(&mut client, &mut server).unwrap();

        // ClientHello, then Finished.
        let levels: Vec<_> = client.sent.iter().map(|(level, _)| *level).collect();
        assert_eq!(levels, [Level::Initial, Level::Handshake]);
        assert_eq!(client.sent, inline_client.sent);
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.fingerprints(), inline_client.fingerprints());
        assert_eq!(client.fingerprints().len(), 2);

        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        assert_eq!(client.tls.peer_transport_params(), Some(SERVER_PARAMS));
        assert_eq!(server.tls.peer_transport_params(), Some(CLIENT_PARAMS));
        assert_eq!(client.tls.alpn(), Some(&b"h3"[..]));
        assert_eq!(client.tls.side(), Side::Client);
        assert_eq!(client.tls.read_level(), Level::OneRtt);
        assert_eq!(client.tls.write_level(), Level::OneRtt);
    }

    #[test]
    fn an_external_server_hands_its_host_a_client_hello_from_three_datagrams_whole() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let client = || Peer::rustls_client(Version::V1, &[b"h3"]);
        let (inline_client, inline_server) =
            handshake(client(), Peer::rustls_server(config(), Version::V1));
        let (mut client, mut server) = (client(), Peer::external_server(config(), Version::V1));
        client.write(&mut server).unwrap();
        let hello = std::mem::take(&mut server.inbox[Level::Initial as usize]);
        let third = hello.len() / 3;
        for piece in [&hello[..third], &hello[third..2 * third]] {
            server.tls.read_crypto(Level::Initial, piece).unwrap();
            server.run_host().unwrap();
            assert_eq!(
                server.handed,
                [],
                "the host has nothing before the whole hello"
            );
            assert!(!server.write(&mut client).unwrap());
        }
        server
            .tls
            .read_crypto(Level::Initial, &hello[2 * third..])
            .unwrap();
        server.run_host().unwrap();
        assert_eq!(
            server.handed,
            [
                Handed::Start(Side::Server),
                Handed::Crypto(Level::Initial, vec![hello.len()]),
            ]
        );

        run(&mut client, &mut server).unwrap();
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.sent, inline_client.sent);
    }

    #[test]
    fn an_external_server_refuses_a_client_hello_without_the_transport_parameters_of_its_version() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        for (client_version, server_version) in
            [(Version::MVFST, Version::V1), (Version::V1, Version::MVFST)]
        {
            let mut client = Peer::rustls_client(client_version, &[b"h3"]);
            let mut server = Peer::external_server(config(), server_version);
            client.write(&mut server).unwrap();
            let read = server
                .read()
                .map_err(|e| e.transport_error_code().into_inner());
            let alert = server.tls.alert().map(|code| code.into_inner());
            // missing_extension (109), and the hello never reaches the server's host.
            assert_eq!(
                (read, alert),
                (Err(0x016d), Some(0x016d)),
                "{server_version:?}"
            );
            assert_eq!(server.handed, [], "{server_version:?}");
            assert!(!server.write(&mut client).unwrap(), "{server_version:?}");
        }
    }

    #[test]
    fn an_external_server_refuses_bytes_after_a_client_hello_whether_or_not_they_arrive_with_it() {
        let cert = Cert::new();
        let trailing: [&[u8]; 3] = [&[1, 0], &[1, 0, 0, 40, 3, 3], &[20, 0, 0, 0]];
        let mut outcomes = Vec::new();
        for (answer, groups) in [("ServerHello", &[&X25519]), ("HelloRetryRequest", &[&P384])] {
            for bytes in trailing {
                for together in [true, false] {
                    let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
                    let config = server_config(&cert, &[b"h3"], groups);
                    let mut server = Peer::external_server(config, Version::V1);
                    client.write(&mut server).unwrap();
                    let mut hello = std::mem::take(&mut server.inbox[Level::Initial as usize]);
                    let read = if together {
                        hello.extend_from_slice(bytes);
                        server.tls.read_crypto(Level::Initial, &hello)
                    } else {
                        server.tls.read_crypto(Level::Initial, &hello).unwrap();
                        // The host answers, but the answer is not drained yet.
                        server.run_host().unwrap();
                        // An empty read is not a violation.
                        server.tls.read_crypto(Level::Initial, &[]).unwrap();
                        server.tls.read_crypto(Level::Initial, bytes)
                    };
                    let read = read.map_err(|error| error.transport_error_code().into_inner());
                    let alert = server.tls.alert().map(|code| code.into_inner());
                    outcomes.push((answer, bytes, together, read, alert));
                }
            }
        }
        // unexpected_message (10).
        let expected: Vec<_> = outcomes
            .iter()
            .map(|&(answer, bytes, together, ..)| {
                (answer, bytes, together, Err(0x010a), Some(0x010a))
            })
            .collect();
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn an_external_server_on_rustls_retries_as_an_inline_server_does() {
        let cert = Cert::new();
        // P-384 only, which clients offer second: the server asks for another ClientHello.
        let config = || server_config(&cert, &[b"h3"], &[&P384]);
        let client = || Peer::rustls_client(Version::V1, &[b"h3"]);
        let (inline_client, inline_server) =
            handshake(client(), Peer::rustls_server(config(), Version::V1));
        let (client, server) = handshake(client(), Peer::external_server(config(), Version::V1));

        // HelloRetryRequest; ServerHello; EncryptedExtensions to Finished; NewSessionTickets.
        let levels: Vec<_> = server.sent.iter().map(|(level, _)| *level).collect();
        assert_eq!(
            levels,
            [
                Level::Initial,
                Level::Initial,
                Level::Handshake,
                Level::OneRtt
            ]
        );
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.sent, inline_client.sent);
        assert_eq!(server.fingerprints(), inline_server.fingerprints());
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        let lens: Vec<_> = inline_client
            .sent
            .iter()
            .map(|(_, bytes)| bytes.len())
            .collect();
        assert_eq!(
            server.handed,
            [
                Handed::Start(Side::Server),
                Handed::Crypto(Level::Initial, vec![lens[0]]),
                Handed::Crypto(Level::Initial, vec![lens[1]]),
                Handed::Crypto(Level::Handshake, vec![lens[2]]),
            ]
        );
    }

    #[test]
    fn an_external_client_on_rustls_retries_as_an_inline_client_does() {
        let cert = Cert::new();
        // P-384 only, which clients offer second: the server asks for another ClientHello.
        let server = || Peer::rustls_server(server_config(&cert, &[b"h3"], &[&P384]), Version::V1);
        let (inline_client, inline_server) =
            handshake(Peer::rustls_client(Version::V1, &[b"h3"]), server());
        let (client, server) = handshake(Peer::external_client(Version::V1, &[b"h3"]), server());

        // ClientHello; ClientHello after the HelloRetryRequest; Finished.
        let levels: Vec<_> = client.sent.iter().map(|(level, _)| *level).collect();
        assert_eq!(levels, [Level::Initial, Level::Initial, Level::Handshake]);
        assert_eq!(client.sent, inline_client.sent);
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.fingerprints(), inline_client.fingerprints());
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        // The HelloRetryRequest, the ServerHello, the rest of the flight, the tickets.
        let from_server = inline_server.sent.iter();
        let crypto = from_server.map(|(level, bytes)| Handed::Crypto(*level, vec![bytes.len()]));
        let expected: Vec<_> = std::iter::once(Handed::Start(Side::Client))
            .chain(crypto)
            .collect();
        assert_eq!(client.handed, expected);
    }

    #[test]
    fn an_external_server_hands_its_host_a_header_it_will_not_wait_for_at_once() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        // A ServerHello, and the header of a ClientHello longer than TLS buffers.
        for header in [[2, 0, 0, 0], [1, 1, 0, 0]] {
            let mut inline = Peer::rustls_server(config(), Version::V1);
            let inline_error = inline.tls.read_crypto(Level::Initial, &header).unwrap_err();
            let mut server = Peer::external_server(config(), Version::V1);
            server.tls.read_crypto(Level::Initial, &header).unwrap();
            let error = server.run_host().unwrap_err();
            assert_eq!(
                server.handed,
                [
                    Handed::Start(Side::Server),
                    Handed::Crypto(Level::Initial, vec![4])
                ],
                "{header:?}"
            );
            assert_eq!(
                error.transport_error_code(),
                inline_error.transport_error_code(),
                "{header:?}: {error}"
            );
        }
    }

    #[test]
    fn crypto_bytes_at_a_level_an_external_session_is_not_reading_are_refused_unconsumed() {
        let cert = Cert::new();
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server =
            Peer::external_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        client.write(&mut server).unwrap();
        let client_hello = server.inbox[Level::Initial as usize].clone();
        for (peer, side) in [(&mut server, Side::Server), (&mut client, Side::Client)] {
            for level in [Level::Handshake, Level::OneRtt] {
                let error = peer.tls.read_crypto(level, &client_hello).unwrap_err();
                let TlsError::WrongLevel {
                    level: refused,
                    expected,
                } = error
                else {
                    panic!("{side:?}: {error:?}");
                };
                assert_eq!((refused, expected), (level, Level::Initial), "{side:?}");
                assert_eq!(error.transport_error_code().into_inner(), 0x0a);
            }
            assert_eq!(peer.tls.read_level(), Level::Initial, "{side:?}");
        }
        server.run_host().unwrap();
        assert_eq!(server.handed, [], "nothing reached the server's host");
        assert_eq!(client.handed, [Handed::Start(Side::Client)]);
        run(&mut client, &mut server).unwrap();
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
    }

    #[test]
    fn an_empty_read_hands_an_external_host_nothing() {
        let cert = Cert::new();
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server =
            Peer::external_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.write(&mut client).unwrap();
        client.read().unwrap();
        client.write(&mut server).unwrap();
        for (peer, side) in [(&mut client, Side::Client), (&mut server, Side::Server)] {
            assert_eq!(peer.tls.read_level(), Level::Handshake, "{side:?}");
            peer.tls.read_crypto(Level::Handshake, &[]).unwrap();
            let input = peer.tls.tls_input().map(|input| Handed::of(&input));
            assert_eq!(input, None, "{side:?}");
        }
        run(&mut client, &mut server).unwrap();
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        client.tls.read_crypto(Level::OneRtt, &[]).unwrap();
        let input = client.tls.tls_input().map(|input| Handed::of(&input));
        assert_eq!(input, None, "1-RTT");
    }

    #[test]
    fn a_hosts_alert_fails_an_external_session_with_crypto_error_0x0100_plus_the_alert() {
        let cert = Cert::new();
        // The server does not support the client's protocols: no_application_protocol (120).
        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let config = server_config(&cert, &[b"hq-interop"], &[&X25519]);
        let mut server = Peer::external_server(config, Version::V1);
        let (side, error) = run(&mut client, &mut server).unwrap_err();
        assert_eq!(side, Side::Server);
        assert!(matches!(error, TlsError::HostAlert(120)), "{error:?}");
        assert_eq!(error.transport_error_code().into_inner(), 0x0178);
        assert_eq!(
            server.tls.alert().map(|code| code.into_inner()),
            Some(0x0178)
        );
        assert!(!server.tls.is_handshake_complete());

        // The client does not trust any root: unknown_ca (48).
        let roots = ServerVerification::Roots(Arc::new(rustls::RootCertStore::empty()));
        let tls = TlsSession::external_client(Version::V1, "localhost", CLIENT_PARAMS.to_vec());
        let host = RustlsHost::client(client_config_with(roots, &[b"h3"]));
        let mut client = Peer::external(tls.unwrap(), host);
        let mut server =
            Peer::rustls_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        let (side, error) = run(&mut client, &mut server).unwrap_err();
        assert_eq!(side, Side::Client);
        assert!(matches!(error, TlsError::HostAlert(48)), "{error:?}");
        assert_eq!(error.transport_error_code().into_inner(), 0x0130);
        assert_eq!(
            client.tls.alert().map(|code| code.into_inner()),
            Some(0x0130)
        );
        assert!(!client.tls.is_handshake_complete());
    }

    #[test]
    fn an_external_session_waits_for_a_step_its_host_delivers_later() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let client = || Peer::rustls_client(Version::V1, &[b"h3"]);
        let (inline_client, inline_server) =
            handshake(client(), Peer::rustls_server(config(), Version::V1));

        let mut client = client();
        let mut server = Peer::external_server(config(), Version::V1);
        server.host.as_mut().unwrap().set_deferred(true);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        assert_eq!(server.handed, [Handed::Start(Side::Server)]);
        assert!(
            server.tls.tls_input().is_none(),
            "the host still has the Start input"
        );
        assert!(server.tls.is_pending());
        assert!(server.tls.write_crypto(&mut Vec::new()).is_none());
        // Each later step is delivered when the host completes it.
        run(&mut client, &mut server).unwrap();
        assert!(!server.tls.is_pending());
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        assert_eq!(server.sent, inline_server.sent);
        assert_eq!(client.sent, inline_client.sent);
        assert_eq!(server.handed.len(), 3);

        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        client.host.as_mut().unwrap().set_deferred(true);
        let mut server = Peer::rustls_server(config(), Version::V1);
        assert!(!client.write(&mut server).unwrap() || client.sent.is_empty());
        assert!(client.tls.is_pending() && client.sent.is_empty());
        run(&mut client, &mut server).unwrap();
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        assert_eq!(client.sent, inline_client.sent);
    }

    /// Returns a server config that accepts 0-RTT, with a fresh session cache.
    fn early_server_config(cert: &Cert) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::clone(&server_config(cert, &[b"h3"], &[&X25519]));
        config.max_early_data_size = u32::MAX;
        Arc::new(config)
    }

    /// Returns a client config that sends 0-RTT, with a fresh ticket store.
    fn early_client_config() -> Arc<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::clone(&client_config(&[b"h3"]));
        config.enable_early_data = true;
        Arc::new(config)
    }

    /// Runs a full handshake, which leaves the client a ticket, then a resumption with 0-RTT, on
    /// one client config and one server config. Returns the peers of the resumption.
    fn resume(client: impl Fn() -> Peer, server: impl Fn() -> Peer) -> (Peer, Peer) {
        handshake(client(), server());
        let (client, server) = handshake(client(), server());
        assert_eq!(
            server
                .tls
                .rustls()
                .map_or(client.tls.rustls(), Some)
                .unwrap()
                .handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        );
        (client, server)
    }

    #[test]
    fn an_external_session_takes_0rtt_keys_from_its_hosts_client_early_secret() {
        let cert = Cert::new();
        let inline_client = || {
            let config = early_client_config();
            move || {
                let tls = TlsSession::client(
                    config.clone(),
                    Version::V1,
                    localhost(),
                    CLIENT_PARAMS.to_vec(),
                );
                Peer::inline(tls.unwrap())
            }
        };
        let inline_server = || {
            let config = early_server_config(&cert);
            move || Peer::rustls_server(config.clone(), Version::V1)
        };
        let (inline_client_peer, inline_server_peer) = resume(inline_client(), inline_server());

        // A client takes 0-RTT write keys once its ClientHello is out.
        let external_client = {
            let config = early_client_config();
            move || {
                let tls =
                    TlsSession::external_client(Version::V1, "localhost", CLIENT_PARAMS.to_vec());
                Peer::external(tls.unwrap(), RustlsHost::client(config.clone()))
            }
        };
        let (client, server) = resume(external_client, inline_server());
        assert_eq!(client.sent, inline_client_peer.sent);
        let early = server
            .tls
            .rustls()
            .unwrap()
            .zero_rtt_keys()
            .expect("the server took 0-RTT");
        let fingerprints = client.fingerprints();
        assert_eq!(
            fingerprints[0],
            format!("ZeroRtt {:?}", rustls_sealed(&early))
        );
        assert!(fingerprints[1].starts_with("Handshake") && fingerprints.len() == 3);

        // A server that accepts 0-RTT takes the read keys with its ServerHello.
        let external_server = {
            let config = early_server_config(&cert);
            move || Peer::external_server(config.clone(), Version::V1)
        };
        let (client, server) = resume(inline_client(), external_server);
        assert_eq!(server.sent, inline_server_peer.sent);
        let early = client
            .tls
            .rustls()
            .unwrap()
            .zero_rtt_keys()
            .expect("the client sent 0-RTT");
        let fingerprints = server.fingerprints();
        assert_eq!(
            fingerprints[0],
            format!("ZeroRtt {:?}", rustls_sealed(&early))
        );
        assert!(fingerprints[1].starts_with("Handshake") && fingerprints.len() == 3);
    }

    #[test]
    fn finishing_a_rustls_client_keeps_whether_its_early_data_was_accepted() {
        let cert = Cert::new();
        let client = {
            let config = early_client_config();
            move || {
                let tls = TlsSession::client(
                    config.clone(),
                    Version::V1,
                    localhost(),
                    CLIENT_PARAMS.to_vec(),
                );
                Peer::inline(tls.unwrap())
            }
        };
        let server = {
            let config = early_server_config(&cert);
            move || Peer::rustls_server(config.clone(), Version::V1)
        };
        let (mut client, _) = resume(client, server);
        assert!(client.tls.is_early_data_accepted());
        client.tls.finish();
        assert!(client.tls.rustls().is_none());
        assert!(client.tls.is_early_data_accepted(), "kept after finish");
    }

    #[test]
    fn a_step_delivered_while_a_session_waits_for_none_is_refused_and_changes_nothing() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let (inline_client, _) = handshake(
            Peer::rustls_client(Version::V1, &[b"h3"]),
            Peer::rustls_server(config(), Version::V1),
        );
        let stray = || {
            let mut step = TlsStep::default();
            step.crypto[0] = b"stray".to_vec();
            step.handshake_success = true;
            step
        };

        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        assert!(matches!(
            client.tls.deliver(stray()),
            Err(TlsError::NotPending)
        ));
        assert!(client.tls.write_crypto(&mut Vec::new()).is_none());
        let mut server = Peer::rustls_server(config(), Version::V1);
        assert!(matches!(
            server.tls.deliver(stray()),
            Err(TlsError::NotPending)
        ));
        assert_eq!(
            TlsError::NotPending.transport_error_code(),
            TransportErrorCode::INTERNAL_ERROR
        );
        run(&mut client, &mut server).unwrap();
        assert_eq!(client.sent, inline_client.sent);
        assert!(matches!(
            client.tls.deliver(stray()),
            Err(TlsError::NotPending)
        ));
    }

    /// Returns what a session keeps once finished.
    fn negotiated(peer: &Peer) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool, Level, Level) {
        (
            peer.tls.alpn().map(<[u8]>::to_vec),
            peer.tls.peer_transport_params().map(<[u8]>::to_vec),
            peer.tls.is_handshake_complete(),
            peer.tls.read_level(),
            peer.tls.write_level(),
        )
    }

    #[test]
    fn finishing_a_confirmed_handshake_frees_its_state_in_both_arms() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let tickets = tickets(&cert);

        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let mut server = Peer::rustls_server(config(), Version::V1);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.tls.finish();
        assert!(
            server.tls.rustls().is_some(),
            "the handshake is not complete"
        );
        run(&mut client, &mut server).unwrap();
        for peer in [&mut client, &mut server] {
            let kept = negotiated(peer);
            assert_eq!(kept.0.as_deref(), Some(&b"h3"[..]));
            peer.tls.finish();
            assert!(
                peer.tls.rustls().is_none(),
                "the rustls connection is freed"
            );
            assert_eq!(negotiated(peer), kept);
            assert_eq!(peer.tls.alert(), None);
            assert!(peer.tls.write_crypto(&mut Vec::new()).is_none());
        }
        // A ticket that arrives after confirmation is dropped.
        client.tls.read_crypto(Level::OneRtt, &tickets).unwrap();
        assert!(client.tls.write_crypto(&mut Vec::new()).is_none());

        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server = Peer::external_server(config(), Version::V1);
        run(&mut client, &mut server).unwrap();
        for peer in [&mut client, &mut server] {
            let kept = negotiated(peer);
            assert_eq!(kept.0.as_deref(), Some(&b"h3"[..]));
            let handed = peer.handed.len();
            peer.tls.finish();
            peer.run_host().unwrap();
            assert_eq!(peer.handed[handed..], [Handed::Finish]);
            assert_eq!(
                peer.host.as_ref().unwrap().connections(),
                0,
                "the host freed its state"
            );
            assert_eq!(negotiated(peer), kept);
            assert!(peer.tls.tls_input().is_none() && !peer.tls.is_pending());
            assert!(peer.tls.write_crypto(&mut Vec::new()).is_none());
            assert_eq!(buffered(peer), 0, "the session freed its buffers");
        }
        client.tls.read_crypto(Level::OneRtt, &tickets).unwrap();
        assert!(client.tls.tls_input().is_none() && !client.tls.is_pending());
        assert!(client.tls.write_crypto(&mut Vec::new()).is_none());
        assert_eq!(buffered(&client), 0);

        // Finishing while the host works on a ticket frees the buffers once its steps are in.
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server = Peer::external_server(ticketless_config(&cert), Version::V1);
        run(&mut client, &mut server).unwrap();
        client.host.as_mut().unwrap().set_deferred(true);
        client.tls.read_crypto(Level::OneRtt, &tickets).unwrap();
        client.run_host().unwrap();
        assert!(client.tls.is_pending());
        client.tls.finish();
        client.run_host().unwrap();
        client.run_host().unwrap();
        assert_eq!(client.handed.last(), Some(&Handed::Finish));
        assert!(!client.tls.is_pending() && client.tls.write_crypto(&mut Vec::new()).is_none());
        assert_eq!(buffered(&client), 0, "after a pending input");
    }

    /// Returns the bytes an External session holds allocated for CRYPTO bytes and outputs.
    fn buffered(peer: &Peer) -> usize {
        let TlsSession::External(session) = &peer.tls else {
            panic!("an External session");
        };
        session.waiting.capacity() * size_of::<bytes::Bytes>()
            + session.outputs.capacity() * size_of::<Output>()
    }

    /// Returns the NewSessionTickets an inline server sends at 1-RTT.
    fn tickets(cert: &Cert) -> Vec<u8> {
        let config = server_config(cert, &[b"h3"], &[&X25519]);
        let (_, server) = handshake(
            Peer::rustls_client(Version::V1, &[b"h3"]),
            Peer::rustls_server(config, Version::V1),
        );
        let at_one_rtt = server
            .sent
            .iter()
            .filter(|(level, _)| *level == Level::OneRtt);
        at_one_rtt.flat_map(|(_, bytes)| bytes.clone()).collect()
    }

    /// Returns a server config that does not send session tickets.
    fn ticketless_config(cert: &Cert) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::clone(&server_config(cert, &[b"h3"], &[&X25519]));
        config.send_tls13_tickets = 0;
        Arc::new(config)
    }

    #[test]
    fn after_the_handshake_a_session_reads_only_tickets_and_only_as_a_client_finished_or_not() {
        let cert = Cert::new();
        let tickets = tickets(&cert);
        assert!(tickets.len() > 4, "at least one whole ticket");
        let key_update: &[u8] = &[24, 0, 0, 1, 0];
        let certificate_request: &[u8] = &[13, 0, 0, 3, 0, 0, 0];
        let completed = |external: bool| {
            let config = ticketless_config(&cert);
            let (client, server) = if external {
                let client = Peer::external_client(Version::V1, &[b"h3"]);
                (client, Peer::external_server(config, Version::V1))
            } else {
                let client = Peer::rustls_client(Version::V1, &[b"h3"]);
                (client, Peer::rustls_server(config, Version::V1))
            };
            handshake(client, server)
        };
        // What reading 1-RTT bytes gives, including the host's answer to them.
        let read = |peer: &mut Peer, data: &[u8]| {
            let read = peer.tls.read_crypto(Level::OneRtt, data);
            let read = read.and_then(|()| peer.run_host().map(drop));
            read.map_err(|error| error.transport_error_code().into_inner())
        };
        let mut outcomes = Vec::new();
        for external in [false, true] {
            for finished in [false, true] {
                let finish = |peer: &mut Peer| {
                    if finished {
                        peer.tls.finish();
                        peer.run_host().unwrap();
                    }
                };
                // Tickets whose first header is split, across `finish` when finished; then a
                // KeyUpdate, which RFC 9001 forbids in QUIC.
                let (mut client, mut server) = completed(external);
                let start = read(&mut client, &tickets[..2]);
                finish(&mut client);
                let rest = read(&mut client, &tickets[2..]);
                let update = read(&mut client, key_update);
                let alert = client.tls.alert().map(|code| code.into_inner());
                // Post-handshake client authentication, which RFC 9001 forbids.
                let (mut client, _) = completed(external);
                finish(&mut client);
                let request = read(&mut client, certificate_request);
                // A client does not send messages after its Finished.
                finish(&mut server);
                let to_server = read(&mut server, &tickets);
                let outcome = (start, rest, update, alert, request, to_server);
                outcomes.push((external, finished, outcome));
            }
        }
        let unexpected_message = Err(0x010a);
        let expected = (
            Ok(()),
            Ok(()),
            unexpected_message,
            Some(0x010a),
            Err(0x0a),
            unexpected_message,
        );
        let expected: Vec<_> = outcomes
            .iter()
            .map(|&(external, finished, _)| (external, finished, expected))
            .collect();
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn a_ticket_request_hands_the_host_write_ticket_and_sends_its_step_at_1rtt() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let mut server = Peer::external_server(config(), Version::V1);
        server.tls.request_ticket(b"too early".to_vec());
        run(&mut client, &mut server).unwrap();
        assert!(
            !server
                .handed
                .iter()
                .any(|input| matches!(input, Handed::WriteTicket(_)))
        );

        server.tls.request_ticket(b"app token".to_vec());
        server.tls.finish();
        let input = server.tls.tls_input().map(|input| Handed::of(&input));
        assert_eq!(input, Some(Handed::WriteTicket(b"app token".to_vec())));
        assert!(server.tls.tls_input().is_none());
        let mut step = TlsStep::default();
        step.crypto[Level::OneRtt as usize] = b"ticket".to_vec();
        server.tls.deliver(step).unwrap();
        let mut buf = Vec::new();
        let out = server.tls.write_crypto(&mut buf).unwrap();
        assert_eq!(
            (out.level, out.len, buf.as_slice()),
            (Level::OneRtt, 6, &b"ticket"[..])
        );
        assert!(out.keys.is_none());
        // The host frees its state after the ticket.
        let input = server.tls.tls_input().map(|input| Handed::of(&input));
        assert_eq!(input, Some(Handed::Finish));
        server.tls.deliver(TlsStep::default()).unwrap();
        server.tls.request_ticket(b"too late".to_vec());
        assert!(server.tls.tls_input().is_none());
    }

    #[test]
    fn a_step_the_session_cannot_apply_fails_it_with_internal_error() {
        let secrets = || SecretPair {
            client: TrafficSecret::new(&[1; 32]).unwrap(),
            server: TrafficSecret::new(&[2; 32]).unwrap(),
        };
        let no_suite = TlsStep {
            handshake: Some(secrets()),
            ..TlsStep::default()
        };
        let mut bytes_without_keys = TlsStep::default();
        bytes_without_keys.crypto[Level::Handshake as usize] = b"finished".to_vec();
        let skipped_level = TlsStep {
            suite: Some(TlsSuite::Aes128GcmSha256),
            app: Some(secrets()),
            ..TlsStep::default()
        };
        let sha256_secrets_for_a_sha384_suite = TlsStep {
            suite: Some(TlsSuite::Aes256GcmSha384),
            handshake: Some(secrets()),
            ..TlsStep::default()
        };
        let steps = [
            no_suite,
            bytes_without_keys,
            skipped_level,
            sha256_secrets_for_a_sha384_suite,
        ];
        for step in steps {
            let mut tls =
                TlsSession::external_client(Version::V1, "localhost", Vec::new()).unwrap();
            assert!(tls.tls_input().is_some());
            let error = tls.deliver(step).unwrap_err();
            assert!(matches!(error, TlsError::InvalidStep), "{error}");
            assert_eq!(
                error.transport_error_code(),
                TransportErrorCode::INTERNAL_ERROR
            );
            assert!(tls.write_crypto(&mut Vec::new()).is_none());
        }
    }

    #[test]
    fn an_external_session_keeps_what_its_host_reports_about_early_data_and_the_handshake() {
        let cert = Cert::new();
        let external_client = {
            let config = early_client_config();
            move || {
                let tls =
                    TlsSession::external_client(Version::V1, "localhost", CLIENT_PARAMS.to_vec());
                Peer::external(tls.unwrap(), RustlsHost::client(config.clone()))
            }
        };
        let inline_server = {
            let config = early_server_config(&cert);
            move || Peer::rustls_server(config.clone(), Version::V1)
        };
        let (client, _) = handshake(external_client(), inline_server());
        assert!(
            !client.tls.is_early_data_accepted(),
            "a full handshake has no early data"
        );
        let (client, _) = resume(external_client, inline_server);
        assert!(client.tls.is_early_data_accepted());

        let inline_client = {
            let config = early_client_config();
            move || {
                let tls = TlsSession::client(
                    config.clone(),
                    Version::V1,
                    localhost(),
                    CLIENT_PARAMS.to_vec(),
                );
                Peer::inline(tls.unwrap())
            }
        };
        let external_server = {
            let config = early_server_config(&cert);
            move || Peer::external_server(config.clone(), Version::V1)
        };
        let (client, server) = resume(inline_client, external_server);
        assert!(server.tls.is_early_data_accepted());
        assert!(client.tls.is_early_data_accepted(), "as rustls reports it");

        let summary = HandshakeSummary {
            group: Some(0x11ec),
            psk: PskOutcome::Resumption,
            sni: Some("localhost".to_string()),
            ..HandshakeSummary::default()
        };
        let verdict = AppTokenVerdict {
            present: true,
            accepted: false,
        };
        let mut tls = TlsSession::external_client(Version::V1, "localhost", Vec::new()).unwrap();
        assert!(tls.tls_input().is_some());
        let step = TlsStep {
            summary: Some(Box::new(summary.clone())),
            app_token: Some(verdict),
            ..TlsStep::default()
        };
        tls.deliver(step).unwrap();
        assert_eq!(tls.handshake_summary(), Some(&summary));
        assert_eq!(tls.app_token_verdict(), Some(verdict));
    }

    #[test]
    fn external_sessions_exist_for_v1_and_mvfst_only() {
        for version in [Version::V1, Version::MVFST] {
            TlsSession::external_server(version, Vec::new()).unwrap();
            TlsSession::external_client(version, "localhost", Vec::new()).unwrap();
        }
        let draft_29 = Version(0xff00_001d);
        let server = TlsSession::external_server(draft_29, Vec::new());
        assert!(matches!(server, Err(TlsError::UnsupportedVersion(v)) if v == draft_29));
        let client = TlsSession::external_client(draft_29, "localhost", Vec::new());
        assert!(matches!(client, Err(TlsError::UnsupportedVersion(v)) if v == draft_29));
    }

    #[test]
    fn crypto_bytes_left_at_a_level_the_host_has_left_fail_the_session_with_protocol_violation() {
        let cert = Cert::new();
        let config = || server_config(&cert, &[b"h3"], &[&X25519]);
        let code = |error: TlsError| error.transport_error_code();
        let violation = Err(TransportErrorCode::PROTOCOL_VIOLATION);

        // Initial bytes arrive while a client's host works on the ServerHello.
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server = Peer::rustls_server(config(), Version::V1);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.write(&mut client).unwrap();
        client.host.as_mut().unwrap().set_deferred(true);
        client.read().unwrap();
        client.tls.read_crypto(Level::Initial, b"extra").unwrap();
        let (_, step) = client.host.as_mut().unwrap().poll_ready().unwrap();
        assert_eq!(client.tls.deliver(step).map_err(code), violation, "client");
        assert!(client.tls.write_crypto(&mut Vec::new()).is_none());

        // Handshake bytes arrive while a server's host works on the client's Finished.
        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let mut server = Peer::external_server(config(), Version::V1);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.write(&mut client).unwrap();
        // The ServerHello, then the rest of the server's flight; then the client's Finished.
        client.read().unwrap();
        client.write(&mut server).unwrap();
        client.read().unwrap();
        client.write(&mut server).unwrap();
        server.host.as_mut().unwrap().set_deferred(true);
        server.read().unwrap();
        assert!(server.tls.is_pending());
        server.tls.read_crypto(Level::Handshake, b"extra").unwrap();
        let (_, step) = server.host.as_mut().unwrap().poll_ready().unwrap();
        assert_eq!(server.tls.deliver(step).map_err(code), violation, "server");
        assert!(!server.tls.is_handshake_complete());

        // Bytes at a level whose keys the host delivered and the session has not drained yet.
        let mut client = Peer::external_client(Version::V1, &[b"h3"]);
        let mut server = Peer::rustls_server(config(), Version::V1);
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.write(&mut client).unwrap();
        client.read().unwrap();
        assert_eq!(client.tls.read_level(), Level::Initial);
        let read = client.tls.read_crypto(Level::Initial, b"extra");
        assert_eq!(read.map_err(code), violation, "undrained");
    }

    /// Returns the bytes and the chunks an External session holds for its host.
    fn held(peer: &Peer) -> (usize, usize) {
        let TlsSession::External(session) = &peer.tls else {
            panic!("an External session");
        };
        let bytes = session.waiting.iter().map(bytes::Bytes::len).sum();
        (bytes, session.waiting.len())
    }

    /// What a deferred host works on while its session reads more.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Work {
        /// A client's host on the server's flight, verifying its certificate.
        ServerFlight,
        /// A server's host on the client's Finished.
        ClientFinished,
        /// A client's host on the start of a NewSessionTicket.
        Ticket,
    }

    /// Returns a session whose deferred host does `work`, and the level the session reads.
    fn working(cert: &Cert, work: Work) -> (Peer, Level) {
        let config = || ticketless_config(cert);
        let (mut client, mut server) = if work == Work::ClientFinished {
            let client = Peer::rustls_client(Version::V1, &[b"h3"]);
            (client, Peer::external_server(config(), Version::V1))
        } else {
            let client = Peer::external_client(Version::V1, &[b"h3"]);
            (client, Peer::rustls_server(config(), Version::V1))
        };
        if work == Work::Ticket {
            run(&mut client, &mut server).unwrap();
            client.host.as_mut().unwrap().set_deferred(true);
            let header = [4, 0xff, 0xff, 0xff];
            client.tls.read_crypto(Level::OneRtt, &header).unwrap();
            client.run_host().unwrap();
            return (client, Level::OneRtt);
        }
        client.write(&mut server).unwrap();
        server.read().unwrap();
        server.write(&mut client).unwrap();
        client.read().unwrap();
        client.write(&mut server).unwrap();
        if work == Work::ServerFlight {
            client.host.as_mut().unwrap().set_deferred(true);
            client.read().unwrap();
            return (client, Level::Handshake);
        }
        client.read().unwrap();
        client.write(&mut server).unwrap();
        server.host.as_mut().unwrap().set_deferred(true);
        server.read().unwrap();
        (server, Level::Handshake)
    }

    #[test]
    fn a_peer_cannot_make_an_external_session_hold_unbounded_crypto_for_a_working_host() {
        let cert = Cert::new();
        let exceeded = Err(TransportErrorCode::CRYPTO_BUFFER_EXCEEDED);
        let mut outcomes = Vec::new();
        let mut expected = Vec::new();
        for work in [Work::ServerFlight, Work::ClientFinished, Work::Ticket] {
            // Large chunks reach the bound on bytes, and 1-byte chunks the bound on chunks.
            for chunk in [1000, 1] {
                let (mut peer, level) = working(&cert, work);
                assert!(peer.tls.is_pending(), "{work:?}");
                let (bytes, chunks) = held(&peer);
                let fits = if chunk == 1 {
                    MAX_WAITING_CHUNKS - chunks
                } else {
                    (MAX_WAITING_BYTES - bytes) / chunk
                };
                expected.push((work, chunk, exceeded, bytes + fits * chunk, chunks + fits));
                let data = vec![0; chunk];
                let mut read = Ok(());
                // Twice the bound, so that a session without one never refuses.
                for _ in 0..2 * MAX_WAITING_BYTES / chunk {
                    read = peer.tls.read_crypto(level, &data);
                    if read.is_err() {
                        break;
                    }
                }
                let read = read.map_err(|error| error.transport_error_code());
                let (bytes, chunks) = held(&peer);
                outcomes.push((work, chunk, read, bytes, chunks));
            }
        }
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn bytes_its_host_consumed_do_not_count_toward_an_external_sessions_bound() {
        let cert = Cert::new();
        let tickets = tickets(&cert);
        let (mut client, _) = handshake(
            Peer::external_client(Version::V1, &[b"h3"]),
            Peer::rustls_server(ticketless_config(&cert), Version::V1),
        );
        // Tickets worth twice the bound, each consumed by the host before the next arrives.
        let reads = 2 * MAX_WAITING_BYTES / tickets.len() + 1;
        let accepted = (0..reads)
            .take_while(|_| {
                let read = client.tls.read_crypto(Level::OneRtt, &tickets);
                read.and_then(|()| client.run_host()).is_ok()
            })
            .count();
        assert_eq!(accepted, reads);
        assert_eq!(held(&client), (0, 0));
    }
}
