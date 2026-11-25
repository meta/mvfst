/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The TLS session of one QUIC connection (RFC 9001).

use std::fmt;
use std::sync::Arc;

use mvfstr_crypto::KeySet;
use mvfstr_crypto::KeyUpdater;
use mvfstr_crypto::PacketKeys;
use mvfstr_crypto::UnsupportedKeyError;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::Version;
use rustls::AlertDescription;
use rustls::ClientConfig;
use rustls::HandshakeType;
use rustls::PeerMisbehaved;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::quic;

use crate::external::AppTokenVerdict;
use crate::external::ExternalSession;
use crate::external::HandshakeSummary;
use crate::external::TlsInput;
use crate::external::TlsStep;

/// An encryption level that carries CRYPTO frames. 0-RTT packets do not carry them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Initial packets, protected with keys from the client's Destination Connection ID.
    Initial,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets.
    OneRtt,
}

/// New keys from TLS.
#[derive(Debug)]
pub enum KeyChange {
    /// The Handshake keys, in both directions.
    Handshake(KeySet),
    /// The first 1-RTT keys, in both directions, and the secrets that derive later key phases.
    ///
    /// A server receives these before the client's Finished, and RFC 9001 forbids it to open
    /// 1-RTT packets until the handshake is complete.
    OneRtt {
        /// The keys of key phase 0.
        keys: KeySet,
        /// The updater that derives the keys of key phases 1, 2 and on.
        update: KeyUpdater,
    },
    /// The 0-RTT keys, which only an External session reports: a client's write keys, or the read
    /// keys of a server that accepted early data. They leave the CRYPTO level unchanged.
    ZeroRtt(PacketKeys),
}

/// One piece of TLS output, from [`TlsSession::write_crypto`].
#[derive(Debug)]
pub struct CryptoOutput {
    /// The level the CRYPTO bytes are sent at.
    pub level: Level,
    /// The number of bytes appended to the caller's buffer, 0 when only keys changed.
    pub len: usize,
    /// Keys TLS installed after those bytes. Bytes of later calls go out at the new level.
    pub keys: Option<KeyChange>,
}

/// Why a TLS session failed or refused an input.
#[derive(Debug)]
pub enum TlsError {
    /// A QUIC version that mvfstr does not map to a rustls QUIC version.
    UnsupportedVersion(Version),
    /// rustls refused to create the session with this config.
    Config(rustls::Error),
    /// TLS failed with a fatal alert, and the connection closes with CRYPTO_ERROR 0x0100 + alert,
    /// as RFC 9001 requires.
    Alert {
        /// The alert TLS raised, or decode_error for a message rustls refused without one.
        alert: AlertDescription,
        /// What went wrong.
        error: rustls::Error,
    },
    /// TLS failed without an alert, and not on a malformed message.
    Failed(rustls::Error),
    /// CRYPTO bytes at a level TLS is not reading. TLS did not consume them, so bytes for a later
    /// level can be offered again once TLS reaches it.
    WrongLevel {
        /// The level of the bytes.
        level: Level,
        /// The level TLS reads.
        expected: Level,
    },
    /// CRYPTO bytes that the TLS host of an External session did not read before it delivered the
    /// keys of a later level. RFC 9001 makes this a PROTOCOL_VIOLATION.
    LeftUnread {
        /// The level of the bytes.
        level: Level,
    },
    /// More CRYPTO bytes at a level than an External session holds for its TLS host before the
    /// host consumes them. The connection closes with CRYPTO_BUFFER_EXCEEDED, as RFC 9000 allows.
    BufferExceeded {
        /// The level of the bytes.
        level: Level,
    },
    /// A CertificateRequest after the handshake, which RFC 9001 forbids a server to send and makes
    /// a PROTOCOL_VIOLATION.
    PostHandshakeAuth,
    /// The TLS host of an External session failed the handshake with this fatal alert, and the
    /// connection closes with CRYPTO_ERROR 0x0100 + alert.
    HostAlert(u8),
    /// A [`TlsStep`] was delivered to a session that was not waiting for one: a session on rustls,
    /// or one whose host does not hold an input. The session did not change.
    NotPending,
    /// The TLS host of an External session delivered a step the session cannot apply: secrets
    /// without a suite or with a hash other than the suite's, or CRYPTO bytes or secrets for a
    /// level its keys do not reach in order.
    InvalidStep,
    /// rustls installed keys whose AEAD tag or header-protection sample is not 16 bytes, which
    /// mvfstr cannot seal or open packets with.
    UnsupportedKeys(UnsupportedKeyError),
}

impl TlsError {
    /// Returns the transport error a connection closes with for this error.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::Alert { alert, .. } => TransportErrorCode::crypto(u8::from(*alert)),
            Self::HostAlert(alert) => TransportErrorCode::crypto(*alert),
            Self::WrongLevel { .. } | Self::LeftUnread { .. } | Self::PostHandshakeAuth => {
                TransportErrorCode::PROTOCOL_VIOLATION
            }
            Self::BufferExceeded { .. } => TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
            Self::UnsupportedVersion(_)
            | Self::Config(_)
            | Self::Failed(_)
            | Self::NotPending
            | Self::InvalidStep
            | Self::UnsupportedKeys(_) => TransportErrorCode::INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "no TLS mapping for {version:?}"),
            Self::Config(error) => write!(f, "rustls refused the config: {error}"),
            Self::Alert { alert, error } => write!(f, "TLS alert {alert:?}: {error}"),
            Self::Failed(error) => write!(f, "TLS failed: {error}"),
            Self::WrongLevel { level, expected } => {
                write!(f, "CRYPTO data at {level:?} while TLS reads {expected:?}")
            }
            Self::LeftUnread { level } => {
                write!(f, "CRYPTO data at {level:?} left unread when TLS moved on")
            }
            Self::BufferExceeded { level } => {
                write!(f, "more CRYPTO data at {level:?} than is held for TLS")
            }
            Self::PostHandshakeAuth => f.write_str("a CertificateRequest after the handshake"),
            Self::HostAlert(alert) => write!(f, "the TLS host raised alert {alert}"),
            Self::NotPending => {
                f.write_str("a TLS step was delivered while the session waits for none")
            }
            Self::InvalidStep => {
                f.write_str("the TLS host delivered a step the session cannot apply")
            }
            Self::UnsupportedKeys(error) => write!(f, "TLS installed unusable keys: {error}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) | Self::Alert { error, .. } | Self::Failed(error) => Some(error),
            Self::UnsupportedKeys(error) => Some(error),
            Self::UnsupportedVersion(_)
            | Self::WrongLevel { .. }
            | Self::LeftUnread { .. }
            | Self::BufferExceeded { .. }
            | Self::PostHandshakeAuth
            | Self::HostAlert(_)
            | Self::NotPending
            | Self::InvalidStep => None,
        }
    }
}

/// Returns whether a ClientHello body carries the transport parameters extension of `version`.
/// RFC 9001 requires a server to refuse a ClientHello without it, with missing_extension, and
/// rustls does not check this: it accepts either codepoint for any version. A malformed body is
/// left to TLS.
pub(crate) fn has_transport_parameters(version: Version, body: &[u8]) -> bool {
    extension_in(body, transport_parameters_extension(version)) != Some(false)
}

/// Returns the error that refuses a peer's CRYPTO bytes with `alert`.
pub(crate) fn refusal(alert: AlertDescription, why: PeerMisbehaved) -> TlsError {
    TlsError::Alert {
        alert,
        error: why.into(),
    }
}

/// Frames the 1-RTT CRYPTO bytes of a session, which carry the messages TLS 1.3 sends after the
/// handshake, and refuses the messages QUIC forbids there.
///
/// It reads every 1-RTT byte before TLS does, so it tracks where each message starts even after
/// [`TlsSession::finish`] has freed TLS in the middle of one, and the rules still hold then.
#[derive(Debug, Default)]
pub(crate) struct PostHandshake {
    /// The bytes of the current message's header still to come after its type.
    header_left: u8,
    /// The current message's length while its header arrives, then the bytes of its body still
    /// to come.
    body_left: usize,
}

impl PostHandshake {
    /// Reads the next 1-RTT CRYPTO bytes of an endpoint on `side`. After the handshake QUIC
    /// carries only the server's NewSessionTickets: RFC 9001 makes a CertificateRequest a
    /// PROTOCOL_VIOLATION and a KeyUpdate an unexpected_message, and any other message is
    /// unexpected there too.
    pub(crate) fn read(&mut self, side: Side, data: &[u8]) -> Result<(), TlsError> {
        let mut data = data;
        loop {
            if self.header_left == 0 {
                let skip = data.len().min(self.body_left);
                self.body_left -= skip;
                data = &data[skip..];
            }
            let Some((&byte, rest)) = data.split_first() else {
                return Ok(());
            };
            data = rest;
            if self.header_left > 0 {
                self.body_left = self.body_left << 8 | usize::from(byte);
                self.header_left -= 1;
                continue;
            }
            let kind = HandshakeType::from(byte);
            match (side, kind) {
                (Side::Client, HandshakeType::NewSessionTicket) => {}
                (Side::Client, HandshakeType::CertificateRequest) => {
                    return Err(TlsError::PostHandshakeAuth);
                }
                (_, HandshakeType::KeyUpdate) => {
                    let why = PeerMisbehaved::KeyUpdateReceivedInQuicConnection;
                    return Err(refusal(AlertDescription::UnexpectedMessage, why));
                }
                _ => {
                    let expect_types = match side {
                        Side::Client => vec![HandshakeType::NewSessionTicket],
                        Side::Server => Vec::new(),
                    };
                    return Err(TlsError::Alert {
                        alert: AlertDescription::UnexpectedMessage,
                        error: rustls::Error::InappropriateHandshakeMessage {
                            expect_types,
                            got_type: kind,
                        },
                    });
                }
            }
            self.header_left = 3;
        }
    }
}

/// Returns the rustls QUIC version for a QUIC version: `V1` for v1, `V1Draft` (transport
/// parameters in extension 0xffa5) for MVFST, and that of the aliased version for an alias.
pub(crate) fn rustls_version(version: Version) -> Result<quic::Version, TlsError> {
    match version.unaliased() {
        Version::V1 => Ok(quic::Version::V1),
        Version::MVFST => Ok(quic::Version::V1Draft),
        _ => Err(TlsError::UnsupportedVersion(version)),
    }
}

/// Returns the TLS extension that carries the transport parameters of a QUIC version:
/// 0x39 (RFC 9001), or the draft codepoint 0xffa5 for MVFST and its alias.
fn transport_parameters_extension(version: Version) -> u16 {
    if version.unaliased() == Version::MVFST {
        0xffa5
    } else {
        0x39
    }
}

/// The TLS 1.3 handshake of one QUIC connection.
///
/// The connection feeds received CRYPTO bytes in with [`read_crypto`](Self::read_crypto), at
/// [`read_level`](Self::read_level), and drains CRYPTO bytes to send and new keys with
/// [`write_crypto`](Self::write_crypto) after every input. Initial keys do not come from TLS;
/// see [`mvfstr_crypto::initial_keys`].
///
/// Both arms are boxed: a connection holds its session inline, and the rustls state machine is
/// over a kilobyte.
pub enum TlsSession {
    /// rustls runs the handshake inside the session.
    Rustls(Box<RustlsSession>),
    /// A TLS stack outside the session runs the handshake.
    External(Box<ExternalSession>),
}

/// The state of a [`TlsSession`] whose handshake runs on rustls's QUIC state machine.
pub struct RustlsSession {
    state: RustlsState,
    side: Side,
    version: Version,
    write_level: Level,
    /// The alert for a failure that rustls reported without one.
    alert: Option<AlertDescription>,
    /// A server's config for a ClientHello without ALPN, until the ClientHello has arrived.
    alpn_choice: Option<Box<AlpnChoice>>,
    /// The start of the ClientHello a server is receiving, not yet given to rustls.
    partial_hello: Vec<u8>,
    /// Whether a server has given rustls its Initial bytes and not yet drained the answer, a
    /// ServerHello or HelloRetryRequest. Initial bytes that arrive before that answer are refused.
    hello_unanswered: bool,
    post_handshake: PostHandshake,
}

/// The rustls connection, which [`TlsSession::finish`] replaces with what it negotiated.
enum RustlsState {
    Running(Box<quic::Connection>),
    Finished {
        peer_transport_params: Option<Box<[u8]>>,
        alpn: Option<Box<[u8]>>,
        peer_certificates: Option<Box<[CertificateDer<'static>]>>,
        early_data_accepted: bool,
    },
}

/// What a server that chooses its config by the ClientHello's ALPN extension holds until the
/// ClientHello has arrived.
struct AlpnChoice {
    without_alpn: Arc<ServerConfig>,
    transport_params: Vec<u8>,
}

impl TlsSession {
    /// Starts a client handshake on rustls. The ClientHello is ready to drain at once.
    pub fn client(
        config: Arc<ClientConfig>,
        version: Version,
        server_name: ServerName<'static>,
        transport_params: Vec<u8>,
    ) -> Result<TlsSession, TlsError> {
        let quic_version = rustls_version(version)?;
        let conn = quic::ClientConnection::new(config, quic_version, server_name, transport_params)
            .map_err(TlsError::Config)?;
        Ok(TlsSession::Rustls(RustlsSession::new(conn.into(), version)))
    }

    /// Starts a server handshake on rustls, which waits for the ClientHello.
    pub fn server(
        config: Arc<ServerConfig>,
        version: Version,
        transport_params: Vec<u8>,
    ) -> Result<TlsSession, TlsError> {
        Ok(TlsSession::Rustls(RustlsSession::server(
            config,
            version,
            transport_params,
        )?))
    }

    /// Starts a server handshake on rustls that takes `config` for a ClientHello that offers ALPN
    /// and `without_alpn` for one that does not.
    ///
    /// rustls, following RFC 9001, refuses a QUIC ClientHello without ALPN when its config lists
    /// protocols, and one that offers protocols when the list is empty, so a server that takes both
    /// kinds needs one config of each. The session holds the Initial CRYPTO bytes back until the
    /// whole ClientHello has arrived, then gives them to the config that matches it.
    pub fn server_choosing_by_alpn(
        config: Arc<ServerConfig>,
        without_alpn: Arc<ServerConfig>,
        version: Version,
        transport_params: Vec<u8>,
    ) -> Result<TlsSession, TlsError> {
        let mut session = RustlsSession::server(config, version, transport_params.clone())?;
        session.alpn_choice = Some(Box::new(AlpnChoice {
            without_alpn,
            transport_params,
        }));
        Ok(TlsSession::Rustls(session))
    }

    /// Starts a server handshake run by a [`TlsHost`](crate::TlsHost), which waits for the
    /// ClientHello. `transport_params` go to the host with the first [`TlsInput`].
    pub fn external_server(
        version: Version,
        transport_params: Vec<u8>,
    ) -> Result<TlsSession, TlsError> {
        rustls_version(version)?;
        Ok(TlsSession::External(ExternalSession::new(
            Side::Server,
            version,
            transport_params,
            None,
        )))
    }

    /// Starts a client handshake run by a [`TlsHost`](crate::TlsHost). The first [`TlsInput`]
    /// carries `server_name` and `transport_params` for the host's ClientHello.
    pub fn external_client(
        version: Version,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<TlsSession, TlsError> {
        rustls_version(version)?;
        Ok(TlsSession::External(ExternalSession::new(
            Side::Client,
            version,
            transport_params,
            Some(server_name),
        )))
    }

    /// Returns the next input for the [`TlsHost`](crate::TlsHost) of an External session, after
    /// which the session waits for the input's [`TlsStep`], which [`deliver`](Self::deliver) takes.
    /// Returns `None` while the host still has the previous input, when the session does not have
    /// another ready, and on rustls.
    pub fn tls_input(&mut self) -> Option<TlsInput<'_>> {
        match self {
            Self::Rustls(_) => None,
            Self::External(session) => session.tls_input(),
        }
    }

    /// Returns whether [`tls_input`](Self::tls_input) has an input to hand out, without handing
    /// it out.
    pub fn has_tls_input(&self) -> bool {
        match self {
            Self::Rustls(_) => false,
            Self::External(session) => session.has_input(),
        }
    }

    /// Applies the host's step for the input the session last handed out. Drain the step's CRYPTO
    /// bytes and keys with [`write_crypto`](Self::write_crypto) afterwards. A session that is not
    /// waiting for a step refuses it with [`TlsError::NotPending`].
    pub fn deliver(&mut self, step: TlsStep) -> Result<(), TlsError> {
        match self {
            Self::Rustls(_) => Err(TlsError::NotPending),
            Self::External(session) => session.deliver(step),
        }
    }

    /// Returns whether the host of an External session has an input whose step has not been
    /// delivered.
    pub fn is_pending(&self) -> bool {
        match self {
            TlsSession::Rustls(_) => false,
            TlsSession::External(session) => session.is_pending(),
        }
    }

    /// Queues a [`TlsInput::WriteTicket`] for the host of an External server, for a session ticket
    /// that carries `app_token`; the ticket goes out as 1-RTT CRYPTO bytes. The request is ignored
    /// before the handshake is complete, after [`finish`](Self::finish), while an earlier request
    /// is outstanding, for a client, and on rustls, which sends its tickets by itself.
    pub fn request_ticket(&mut self, app_token: Vec<u8>) {
        match self {
            Self::Rustls(_) => {}
            Self::External(session) => session.request_ticket(app_token),
        }
    }

    /// Frees the handshake state once the handshake is confirmed (RFC 9001), keeping what it
    /// negotiated, and queues the `Finish` input for an External session's host. It leaves the
    /// session unchanged before the handshake is complete. Drain
    /// [`write_crypto`](Self::write_crypto) first: a rustls server's queued session tickets go with
    /// its connection. A client drops the session tickets it reads afterwards, and other messages
    /// are still refused.
    pub fn finish(&mut self) {
        match self {
            Self::Rustls(session) => session.finish(),
            Self::External(session) => session.finish(),
        }
    }

    /// Returns this endpoint's role.
    pub fn side(&self) -> Side {
        match self {
            Self::Rustls(session) => session.side(),
            Self::External(session) => session.side(),
        }
    }

    /// Returns the QUIC version the session was created for.
    pub fn version(&self) -> Version {
        match self {
            Self::Rustls(session) => session.version,
            Self::External(session) => session.version(),
        }
    }

    /// Returns the level whose CRYPTO bytes TLS reads next.
    ///
    /// It follows the keys drained from [`write_crypto`](Self::write_crypto), except that a
    /// server keeps reading Handshake bytes after it has 1-RTT keys, until the client's Finished
    /// completes the handshake.
    pub fn read_level(&self) -> Level {
        match self {
            Self::Rustls(session) => session.read_level(),
            Self::External(session) => session.read_level(),
        }
    }

    /// Returns the level of the CRYPTO bytes TLS writes next.
    pub fn write_level(&self) -> Level {
        match self {
            Self::Rustls(session) => session.write_level,
            Self::External(session) => session.write_level(),
        }
    }

    /// Feeds TLS the next in-order CRYPTO bytes received at `level`, which must be the
    /// [`read_level`](Self::read_level).
    ///
    /// A server keeps each ClientHello until all of it has arrived, and refuses one without the
    /// transport parameters extension of its version with missing_extension, as RFC 9001 requires.
    /// rustls does not check this: it accepts either codepoint for any version. A server
    /// [choosing its config by ALPN](Self::server_choosing_by_alpn) then picks the config.
    /// Bytes that follow a ClientHello before its answer is drained with
    /// [`write_crypto`](Self::write_crypto) are refused with unexpected_message, as rustls
    /// refuses them when they come with the ClientHello. At 1-RTT only a client reads messages,
    /// and only NewSessionTicket; the others are refused, after [`finish`](Self::finish) too, as
    /// RFC 9001 and TLS 1.3 require. Apart from a server's ClientHello, which it keeps whole, an
    /// External session holds at most 64 KiB, in at most 1,024 reads, that its host has not
    /// consumed, and refuses more with [`TlsError::BufferExceeded`].
    pub fn read_crypto(&mut self, level: Level, data: &[u8]) -> Result<(), TlsError> {
        match self {
            Self::Rustls(session) => session.read_crypto(level, data),
            Self::External(session) => session.read_crypto(level, data),
        }
    }

    /// Appends the CRYPTO bytes TLS has ready for one level to `buf`, and reports any keys TLS
    /// installed after them. Returns `Ok(None)` once TLS has written everything it has ready; call
    /// it until then after every [`read_crypto`](Self::read_crypto).
    ///
    /// Fails with [`TlsError::UnsupportedKeys`] when rustls installs keys that mvfstr cannot use;
    /// the connection must then close.
    pub fn write_crypto(&mut self, buf: &mut Vec<u8>) -> Result<Option<CryptoOutput>, TlsError> {
        match self {
            Self::Rustls(session) => session.write_crypto(buf),
            Self::External(session) => Ok(session.write_crypto(buf)),
        }
    }

    /// Returns the transport parameters the peer sent. On rustls, a server has them once it has
    /// read the ClientHello, and a client once it has read the server's handshake flight and
    /// drained the 1-RTT keys from [`write_crypto`](Self::write_crypto). An External session has
    /// them once a delivered [`TlsStep`] carries them.
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(session) => session.peer_transport_params(),
            Self::External(session) => session.peer_transport_params(),
        }
    }

    /// Returns the negotiated application protocol, or `None` if the handshake has not
    /// negotiated one.
    pub fn alpn(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(session) => session.alpn(),
            Self::External(session) => session.alpn(),
        }
    }

    /// Returns the certificate chain the peer presented, end-entity certificate first, once TLS has
    /// verified it and the peer's signature over the handshake; on a resumed connection, the chain
    /// is the one verified when the session was first established. A client has the server's chain.
    /// A server has the client's only when it is configured to request client certificates and the
    /// client presented one, and keeps it after [`finish`](Self::finish). An External session
    /// returns `None`: its host does not report the chain.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        match self {
            Self::Rustls(session) => session.peer_certificates(),
            Self::External(_) => None,
        }
    }

    /// Returns whether the handshake is complete (RFC 9001): this endpoint has sent its Finished,
    /// that is, drained it with [`write_crypto`](Self::write_crypto), and verified the peer's.
    pub fn is_handshake_complete(&self) -> bool {
        match self {
            Self::Rustls(session) => session.is_handshake_complete(),
            Self::External(session) => session.is_handshake_complete(),
        }
    }

    /// Returns whether early data is accepted: by this server, or by the server a client sent it
    /// to. On rustls only a client reports it.
    pub fn is_early_data_accepted(&self) -> bool {
        match self {
            Self::Rustls(session) => session.is_early_data_accepted(),
            Self::External(session) => session.is_early_data_accepted(),
        }
    }

    /// Returns what the host of an External session reported the handshake negotiated.
    pub fn handshake_summary(&self) -> Option<&HandshakeSummary> {
        match self {
            Self::Rustls(_) => None,
            Self::External(session) => session.handshake_summary(),
        }
    }

    /// Returns the verdict of an External server's host on the app token of a resumed ticket.
    pub fn app_token_verdict(&self) -> Option<AppTokenVerdict> {
        match self {
            Self::Rustls(_) => None,
            Self::External(session) => session.app_token_verdict(),
        }
    }

    /// Returns the CRYPTO_ERROR for the fatal alert TLS failed with, if any.
    pub fn alert(&self) -> Option<TransportErrorCode> {
        match self {
            Self::Rustls(session) => session.alert(),
            Self::External(session) => session.alert(),
        }
    }

    /// Returns the rustls connection of a session on rustls until [`finish`](Self::finish) frees
    /// it, for what this wrapper does not expose (negotiated suite and key exchange group,
    /// exporters).
    pub fn rustls(&self) -> Option<&quic::Connection> {
        match self {
            Self::Rustls(session) => session.conn(),
            Self::External(_) => None,
        }
    }
}

impl RustlsSession {
    fn new(conn: quic::Connection, version: Version) -> Box<RustlsSession> {
        let side = match conn {
            quic::Connection::Client(_) => Side::Client,
            quic::Connection::Server(_) => Side::Server,
        };
        Box::new(RustlsSession {
            state: RustlsState::Running(Box::new(conn)),
            side,
            version,
            write_level: Level::Initial,
            alert: None,
            alpn_choice: None,
            partial_hello: Vec::new(),
            hello_unanswered: false,
            post_handshake: PostHandshake::default(),
        })
    }

    fn server(
        config: Arc<ServerConfig>,
        version: Version,
        transport_params: Vec<u8>,
    ) -> Result<Box<RustlsSession>, TlsError> {
        let quic_version = rustls_version(version)?;
        let conn = quic::ServerConnection::new(config, quic_version, transport_params)
            .map_err(TlsError::Config)?;
        Ok(RustlsSession::new(conn.into(), version))
    }

    fn side(&self) -> Side {
        self.side
    }

    fn conn(&self) -> Option<&quic::Connection> {
        match &self.state {
            RustlsState::Running(conn) => Some(conn),
            RustlsState::Finished { .. } => None,
        }
    }

    fn conn_mut(&mut self) -> Option<&mut quic::Connection> {
        match &mut self.state {
            RustlsState::Running(conn) => Some(conn),
            RustlsState::Finished { .. } => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.conn().is_some_and(|conn| conn.is_handshaking())
    }

    fn read_level(&self) -> Level {
        match self.write_level {
            Level::OneRtt if self.is_handshaking() => Level::Handshake,
            level => level,
        }
    }

    fn read_crypto(&mut self, level: Level, data: &[u8]) -> Result<(), TlsError> {
        let expected = self.read_level();
        if level != expected {
            return Err(TlsError::WrongLevel { level, expected });
        }
        if level == Level::Initial && self.side() == Side::Server {
            return self.read_client_hello(data);
        }
        if level == Level::OneRtt
            && let Err(error) = self.post_handshake.read(self.side, data)
        {
            self.alert = alert_of(&error).or(self.alert);
            return Err(error);
        }
        // A finished session drops the tickets it reads.
        let Some(conn) = self.conn_mut() else {
            return Ok(());
        };
        let read = conn.read_hs(data);
        read.map_err(|error| self.failure(error))
    }

    /// Reads a server's Initial bytes: a ClientHello, which may be the second one that follows a
    /// HelloRetryRequest, from which rustls then takes the transport parameters. A ClientHello
    /// must end its flight (RFC 8446). rustls refuses bytes that come with it; this function
    /// refuses bytes that come in a later call before the answer is drained, which rustls would
    /// join to the next level's data.
    fn read_client_hello(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if self.hello_unanswered && !data.is_empty() {
            let alert = AlertDescription::UnexpectedMessage;
            self.alert = Some(alert);
            return Err(refusal(alert, PeerMisbehaved::KeyEpochWithPendingFragment));
        }
        let mut hello = std::mem::take(&mut self.partial_hello);
        hello.extend_from_slice(data);
        match parse_client_hello(&hello) {
            ClientHello::Partial => {
                self.partial_hello = hello;
                return Ok(());
            }
            ClientHello::Whole(body) => self.check_client_hello(body)?,
            ClientHello::Refused => {}
        }
        self.hello_unanswered = true;
        let Some(conn) = self.conn_mut() else {
            return Ok(());
        };
        let read = conn.read_hs(&hello);
        read.map_err(|error| self.failure(error))
    }

    /// Checks a whole ClientHello's transport parameters extension, and picks the config of a
    /// server choosing by ALPN.
    fn check_client_hello(&mut self, body: &[u8]) -> Result<(), TlsError> {
        if !has_transport_parameters(self.version, body) {
            let alert = AlertDescription::MissingExtension;
            self.alert = Some(alert);
            return Err(refusal(
                alert,
                PeerMisbehaved::MissingQuicTransportParameters,
            ));
        }
        let Some(choice) = self.alpn_choice.take() else {
            return Ok(());
        };
        // What is not a well-formed ClientHello is left to the config that takes ALPN, which
        // refuses it.
        if extension_in(body, ALPN) == Some(false) {
            let quic_version = rustls_version(self.version)?;
            let conn = quic::ServerConnection::new(
                choice.without_alpn,
                quic_version,
                choice.transport_params,
            )
            .map_err(TlsError::Config)?;
            self.state = RustlsState::Running(Box::new(conn.into()));
        }
        Ok(())
    }

    /// Classifies a rustls failure by the alert TLS raised for it.
    fn failure(&mut self, error: rustls::Error) -> TlsError {
        if let Some(alert) = self.conn().and_then(quic::Connection::alert) {
            return TlsError::Alert { alert, error };
        }
        // rustls refuses a handshake message longer than it can buffer without raising an alert;
        // for every other message it cannot decode it raises decode_error.
        if let rustls::Error::InvalidMessage(_) = error {
            let alert = AlertDescription::DecodeError;
            self.alert = Some(alert);
            return TlsError::Alert { alert, error };
        }
        TlsError::Failed(error)
    }

    fn write_crypto(&mut self, buf: &mut Vec<u8>) -> Result<Option<CryptoOutput>, TlsError> {
        let start = buf.len();
        let level = self.write_level;
        let Some(conn) = self.conn_mut() else {
            return Ok(None);
        };
        // rustls returns the bytes of one level per call, ending where it installs new keys.
        let change = conn.write_hs(buf);
        let len = buf.len() - start;
        let keys = match change {
            None => None,
            Some(quic::KeyChange::Handshake { keys }) => {
                let keys = KeySet::from_rustls(keys).map_err(TlsError::UnsupportedKeys)?;
                self.write_level = Level::Handshake;
                Some(KeyChange::Handshake(keys))
            }
            Some(quic::KeyChange::OneRtt { keys, next }) => {
                let keys = KeySet::from_rustls(keys).map_err(TlsError::UnsupportedKeys)?;
                self.write_level = Level::OneRtt;
                let update = KeyUpdater::new(next, &keys);
                Some(KeyChange::OneRtt { keys, update })
            }
        };
        if len == 0 && keys.is_none() {
            return Ok(None);
        }
        self.hello_unanswered = false;
        Ok(Some(CryptoOutput { level, len, keys }))
    }

    fn peer_transport_params(&self) -> Option<&[u8]> {
        // A resuming rustls client holds the parameters stored with the session, which only 0-RTT
        // may use (RFC 9000), until the server's EncryptedExtensions replaces them. That message
        // comes before the server's Finished, and so before the 1-RTT keys.
        if self.side() == Side::Client && self.write_level != Level::OneRtt {
            return None;
        }
        match &self.state {
            RustlsState::Running(conn) => conn.quic_transport_parameters(),
            RustlsState::Finished {
                peer_transport_params,
                ..
            } => peer_transport_params.as_deref(),
        }
    }

    fn alpn(&self) -> Option<&[u8]> {
        match &self.state {
            RustlsState::Running(conn) => conn.alpn_protocol(),
            RustlsState::Finished { alpn, .. } => alpn.as_deref(),
        }
    }

    fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        match &self.state {
            RustlsState::Running(conn) => conn.peer_certificates(),
            RustlsState::Finished {
                peer_certificates, ..
            } => peer_certificates.as_deref(),
        }
    }

    fn is_early_data_accepted(&self) -> bool {
        match &self.state {
            RustlsState::Running(conn) => match &**conn {
                quic::Connection::Client(conn) => conn.is_early_data_accepted(),
                quic::Connection::Server(_) => false,
            },
            RustlsState::Finished {
                early_data_accepted,
                ..
            } => *early_data_accepted,
        }
    }

    fn is_handshake_complete(&self) -> bool {
        // rustls stops handshaking once it has queued its Finished; the 1-RTT key change comes
        // with those bytes, so it marks them drained.
        self.write_level == Level::OneRtt && !self.is_handshaking()
    }

    fn alert(&self) -> Option<TransportErrorCode> {
        self.conn()
            .and_then(quic::Connection::alert)
            .or(self.alert)
            .map(|alert| TransportErrorCode::crypto(u8::from(alert)))
    }

    /// Drops the rustls connection of a complete handshake, keeping what it negotiated.
    fn finish(&mut self) {
        if !self.is_handshake_complete() {
            return;
        }
        self.state = RustlsState::Finished {
            peer_transport_params: self.peer_transport_params().map(Box::from),
            alpn: self.alpn().map(Box::from),
            peer_certificates: self.peer_certificates().map(Box::from),
            early_data_accepted: self.is_early_data_accepted(),
        };
    }
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustls(session) => session.fmt(f),
            Self::External(session) => session.fmt(f),
        }
    }
}

impl fmt::Debug for RustlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsSession")
            .field("side", &self.side())
            .field("version", &self.version)
            .field("write_level", &self.write_level)
            .finish_non_exhaustive()
    }
}

/// Returns the alert of a refusal that closes the connection with one.
pub(crate) fn alert_of(error: &TlsError) -> Option<AlertDescription> {
    match error {
        TlsError::Alert { alert, .. } => Some(*alert),
        _ => None,
    }
}

/// The longest handshake message rustls buffers; it refuses a longer one as soon as it reads the
/// message header.
const MAX_CLIENT_HELLO: usize = 0xffff;

/// The ALPN extension (RFC 7301).
const ALPN: u16 = 16;

/// What the bytes at the start of a server's Initial CRYPTO data hold (RFC 8446).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHello<'a> {
    /// The start of a ClientHello.
    Partial,
    /// A whole ClientHello, with this body.
    Whole(&'a [u8]),
    /// The header of another message, or of a ClientHello longer than rustls buffers.
    Refused,
}

/// Parses the ClientHello at the start of `bytes`, Initial CRYPTO bytes not yet given to rustls.
pub(crate) fn parse_client_hello(bytes: &[u8]) -> ClientHello<'_> {
    const CLIENT_HELLO: u8 = 1;
    let Some((&[kind, len @ ..], rest)) = bytes.split_first_chunk::<4>() else {
        return ClientHello::Partial;
    };
    let len = len
        .iter()
        .fold(0, |len, &byte| len << 8 | usize::from(byte));
    if kind != CLIENT_HELLO || len > MAX_CLIENT_HELLO {
        return ClientHello::Refused;
    }
    match rest.get(..len) {
        Some(body) => ClientHello::Whole(body),
        None => ClientHello::Partial,
    }
}

/// Returns whether a ClientHello body carries `extension`, or `None` if the body is malformed.
fn extension_in(body: &[u8], extension: u16) -> Option<bool> {
    // legacy_version and random, then legacy_session_id, cipher_suites and
    // legacy_compression_methods.
    let rest = body.get(34..)?;
    let (_, rest) = tls_vector(rest, 1)?;
    let (_, rest) = tls_vector(rest, 2)?;
    let (_, rest) = tls_vector(rest, 1)?;
    let (mut extensions, _) = tls_vector(rest, 2)?;
    while !extensions.is_empty() {
        let (kind, rest) = extensions.split_first_chunk::<2>()?;
        if u16::from_be_bytes(*kind) == extension {
            return Some(true);
        }
        (_, extensions) = tls_vector(rest, 2)?;
    }
    Some(false)
}

/// Splits a TLS vector with a `len_bytes`-byte length off the front of `bytes`: its contents and
/// what follows it.
fn tls_vector(bytes: &[u8], len_bytes: usize) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_at_checked(len_bytes)?;
    let len = len
        .iter()
        .fold(0, |len, &byte| len << 8 | usize::from(byte));
    rest.split_at_checked(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello message with these extensions, each a type and a body.
    fn client_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7; 32]);
        // A one-byte legacy_session_id, one cipher suite and the null compression method.
        body.extend([1, 0xaa, 0, 2, 0x13, 0x01, 1, 0]);
        let extensions: Vec<u8> = extensions
            .iter()
            .flat_map(|(kind, data)| {
                let len = u16::try_from(data.len()).unwrap();
                [kind.to_be_bytes(), len.to_be_bytes()]
                    .concat()
                    .into_iter()
                    .chain(data.iter().copied())
            })
            .collect();
        body.extend(u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend(extensions);
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        [&[1], &len[1..], &body].concat()
    }

    #[test]
    fn a_session_is_two_words_with_both_arms_boxed() {
        assert_eq!(size_of::<TlsSession>(), 2 * size_of::<usize>());
    }

    #[test]
    fn a_client_hello_is_parsed_once_whole_and_its_extensions_are_found() {
        let supported_versions: (u16, &[u8]) = (43, &[2, 3, 4]);
        let alpn: (u16, &[u8]) = (16, &[0, 3, 2, b'h', b'3']);
        let extensions = |hello: &[u8], extension| match parse_client_hello(hello) {
            ClientHello::Whole(body) => extension_in(body, extension),
            parsed => panic!("{parsed:?}"),
        };
        let with_alpn = client_hello(&[supported_versions, alpn]);
        assert_eq!(extensions(&with_alpn, ALPN), Some(true));
        assert_eq!(extensions(&with_alpn, 43), Some(true));
        assert_eq!(extensions(&with_alpn, 0x39), Some(false));
        let without = client_hello(&[supported_versions]);
        assert_eq!(extensions(&without, ALPN), Some(false));
        assert_eq!(extensions(&client_hello(&[]), ALPN), Some(false));
        for len in 0..without.len() {
            assert_eq!(
                parse_client_hello(&without[..len]),
                ClientHello::Partial,
                "{len} of {} bytes",
                without.len()
            );
        }

        let mut not_hello = without.clone();
        not_hello[0] = 2;
        assert_eq!(parse_client_hello(&not_hello), ClientHello::Refused);
        // A ClientHello longer than rustls buffers is not waited for.
        assert_eq!(parse_client_hello(&[1, 1, 0, 0]), ClientHello::Refused);
        let mut long_session_id = without.clone();
        long_session_id[4 + 34] = 0xff;
        assert_eq!(extensions(&long_session_id, ALPN), None);
        // The last extension's length, 3, becomes 9.
        let mut short_extension = without.clone();
        let len_at = short_extension.len() - 4;
        short_extension[len_at] = 9;
        assert_eq!(extensions(&short_extension, ALPN), None);
    }
}
