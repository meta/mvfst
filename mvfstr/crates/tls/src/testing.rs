/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Test support: a [`TlsHost`] that runs each handshake on rustls. Not for production use.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use mvfstr_crypto::TrafficSecret;
use mvfstr_wire::Side;
use rustls::AlertDescription;
use rustls::ClientConfig;
use rustls::KeyLog;
use rustls::ServerConfig;
use rustls::pki_types::ServerName;
use rustls::quic;

use crate::external::SecretPair;
use crate::external::TlsConnId;
use crate::external::TlsHost;
use crate::external::TlsInput;
use crate::external::TlsPoll;
use crate::external::TlsStep;
use crate::external::TlsSuite;
use crate::session::Level;
use crate::session::rustls_version;

/// A [`TlsHost`] that runs each connection's handshake on rustls's QUIC state machine, as an
/// External session's host, so that tests can compare the External backend with the rustls one.
///
/// rustls hands out built packet keys rather than traffic secrets, so the host gives each
/// connection a copy of its config whose key log collects the secrets, and delivers those.
pub struct RustlsHost {
    server: Option<Arc<ServerConfig>>,
    client: Option<Arc<ClientConfig>>,
    conns: HashMap<TlsConnId, Hosted>,
    /// Whether each step waits in `held` until [`poll_ready`](TlsHost::poll_ready).
    deferred: bool,
    held: VecDeque<(TlsConnId, TlsStep)>,
}

/// One connection's rustls state.
struct Hosted {
    conn: quic::Connection,
    log: Arc<SecretLog>,
    /// The level of the bytes rustls writes next.
    level: Level,
    /// Whether the peer's transport parameters and the ALPN went out in a step.
    params_reported: bool,
    /// Whether a step reported the handshake's success, and early data accepted.
    success_reported: bool,
    early_reported: bool,
}

impl RustlsHost {
    /// Builds a host for server connections.
    pub fn server(config: Arc<ServerConfig>) -> RustlsHost {
        RustlsHost {
            server: Some(config),
            client: None,
            conns: HashMap::new(),
            deferred: false,
            held: VecDeque::new(),
        }
    }

    /// Builds a host for client connections.
    pub fn client(config: Arc<ClientConfig>) -> RustlsHost {
        RustlsHost {
            server: None,
            client: Some(config),
            conns: HashMap::new(),
            deferred: false,
            held: VecDeque::new(),
        }
    }

    /// Makes the host answer every later input with [`TlsPoll::Pending`] and return its step from
    /// the next [`poll_ready`](TlsHost::poll_ready), as a host whose work completes
    /// asynchronously does.
    pub fn set_deferred(&mut self, deferred: bool) {
        self.deferred = deferred;
    }

    /// Returns the number of connections whose rustls state the host holds.
    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// Creates the rustls connection for `conn` and puts what it writes first into `step`.
    /// Returns `None` if the host cannot create it.
    fn start(&mut self, conn: TlsConnId, start: Start<'_>, step: &mut TlsStep) -> Option<()> {
        let version = rustls_version(start.version).ok()?;
        let log = Arc::new(SecretLog::default());
        let rustls_conn: quic::Connection = match (start.side, &self.server, &self.client) {
            (Side::Server, Some(config), _) => {
                let mut config = ServerConfig::clone(config);
                log.forward_to(config.key_log.clone());
                config.key_log = log.clone();
                let params = start.transport_params.to_vec();
                quic::ServerConnection::new(Arc::new(config), version, params)
                    .ok()?
                    .into()
            }
            (Side::Client, _, Some(config)) => {
                let mut config = ClientConfig::clone(config);
                log.forward_to(config.key_log.clone());
                config.key_log = log.clone();
                let name = start.server_name.unwrap_or_default().to_string();
                let name = ServerName::try_from(name).ok()?;
                let params = start.transport_params.to_vec();
                quic::ClientConnection::new(Arc::new(config), version, name, params)
                    .ok()?
                    .into()
            }
            _ => return None,
        };
        let mut hosted = Hosted {
            conn: rustls_conn,
            log,
            level: Level::Initial,
            params_reported: false,
            success_reported: false,
            early_reported: false,
        };
        hosted.write(step);
        self.conns.insert(conn, hosted);
        Some(())
    }
}

/// The fields of [`TlsInput::Start`].
struct Start<'a> {
    side: Side,
    version: mvfstr_wire::Version,
    transport_params: &'a [u8],
    server_name: Option<&'a str>,
}

impl Hosted {
    /// Feeds rustls the bytes and puts what it writes into `step`.
    fn read(&mut self, data: &[bytes::Bytes], step: &mut TlsStep) {
        for chunk in data {
            if let Err(error) = self.conn.read_hs(chunk) {
                step.alert = Some(u8::from(self.alert_for(&error)));
                return;
            }
        }
        self.write(step);
        // A resuming client holds the parameters stored with the session until the server's
        // EncryptedExtensions replace them, which happens before its 1-RTT keys.
        let current = match self.conn {
            quic::Connection::Client(_) => self.level == Level::OneRtt,
            quic::Connection::Server(_) => true,
        };
        if !self.params_reported
            && current
            && let Some(params) = self.conn.quic_transport_parameters()
        {
            step.peer_transport_params = Some(params.to_vec());
            step.alpn = self.conn.alpn_protocol().map(<[u8]>::to_vec);
            self.params_reported = true;
        }
        if let quic::Connection::Client(conn) = &self.conn
            && !self.early_reported
            && conn.is_early_data_accepted()
        {
            step.early_success = true;
            self.early_reported = true;
        }
        if !self.success_reported && !self.conn.is_handshaking() {
            step.handshake_success = true;
            self.success_reported = true;
        }
    }

    /// Returns the alert for a rustls failure: the one rustls raised, decode_error for a message
    /// it refused without one (as the rustls backend reports it), and internal_error otherwise,
    /// since a step carries a failure only as an alert.
    fn alert_for(&self, error: &rustls::Error) -> AlertDescription {
        match (self.conn.alert(), error) {
            (Some(alert), _) => alert,
            (None, rustls::Error::InvalidMessage(_)) => AlertDescription::DecodeError,
            (None, _) => AlertDescription::InternalError,
        }
    }

    /// Drains what rustls writes into `step`, replacing its keys with the logged secrets.
    fn write(&mut self, step: &mut TlsStep) {
        // rustls has 0-RTT keys once a client offers early data or a server accepts it.
        if self.conn.zero_rtt_keys().is_some()
            && let Some(early) = self.log.take("CLIENT_EARLY_TRAFFIC_SECRET")
        {
            step.client_early = Some(early);
            step.suite = self.suite();
            // A server has the keys only once it accepts early data.
            if let quic::Connection::Server(_) = self.conn {
                step.early_success = true;
                self.early_reported = true;
            }
        }
        while let Some(change) = self.conn.write_hs(&mut step.crypto[self.level as usize]) {
            match change {
                quic::KeyChange::Handshake { .. } => {
                    self.level = Level::Handshake;
                    step.handshake = Some(self.log.pair("HANDSHAKE_TRAFFIC_SECRET"));
                }
                quic::KeyChange::OneRtt { .. } => {
                    self.level = Level::OneRtt;
                    step.app = Some(self.log.pair("TRAFFIC_SECRET_0"));
                    step.exporter = self.log.take("EXPORTER_SECRET");
                }
            }
            step.suite = self.suite();
        }
    }

    /// Returns the negotiated suite, or the suite of the session a client resumes.
    fn suite(&self) -> Option<TlsSuite> {
        let suite = self.conn.negotiated_cipher_suite()?;
        TlsSuite::from_codepoint(u16::from(suite.suite()))
    }
}

/// A key log that keeps one connection's secrets, by label, and passes them on to the key log
/// of the config it replaced.
#[derive(Default)]
struct SecretLog {
    forward: Mutex<Option<Arc<dyn KeyLog>>>,
    secrets: Mutex<Vec<(String, Vec<u8>)>>,
}

impl SecretLog {
    fn forward_to(&self, log: Arc<dyn KeyLog>) {
        *self.forward.lock().expect("should not be poisoned") = Some(log);
    }

    /// Removes and returns the secret logged under `label`.
    fn take(&self, label: &str) -> Option<TrafficSecret> {
        let mut secrets = self.secrets.lock().expect("should not be poisoned");
        let at = secrets.iter().position(|(logged, _)| logged == label)?;
        let (_, secret) = secrets.swap_remove(at);
        TrafficSecret::new(&secret).ok()
    }

    /// Removes and returns the client's and the server's secrets logged under `suffix`.
    fn pair(&self, suffix: &str) -> SecretPair {
        let take = |side: &str| {
            self.take(&format!("{side}_{suffix}"))
                .expect("rustls logs a secret before it installs its keys")
        };
        SecretPair {
            client: take("CLIENT"),
            server: take("SERVER"),
        }
    }
}

impl KeyLog for SecretLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let forward = self.forward.lock().expect("should not be poisoned");
        if let Some(log) = &*forward
            && log.will_log(label)
        {
            log.log(label, client_random, secret);
        }
        let mut secrets = self.secrets.lock().expect("should not be poisoned");
        secrets.push((label.to_string(), secret.to_vec()));
    }
}

impl fmt::Debug for SecretLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretLog").finish_non_exhaustive()
    }
}

impl TlsHost for RustlsHost {
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        let mut step = TlsStep::default();
        match input {
            TlsInput::Start {
                side,
                version,
                transport_params,
                server_name,
            } => {
                let start = Start {
                    side,
                    version,
                    transport_params,
                    server_name,
                };
                if self.start(conn, start, &mut step).is_none() {
                    step.alert = Some(u8::from(AlertDescription::InternalError));
                }
            }
            TlsInput::Crypto { data, .. } => match self.conns.get_mut(&conn) {
                Some(hosted) => hosted.read(data, &mut step),
                None => step.alert = Some(u8::from(AlertDescription::InternalError)),
            },
            TlsInput::WriteTicket { .. } => {}
            TlsInput::Finish => {
                self.conns.remove(&conn);
            }
        }
        if self.deferred {
            self.held.push_back((conn, step));
            return TlsPoll::Pending;
        }
        TlsPoll::Ready(step)
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        self.held.pop_front()
    }

    fn cancel(&mut self, conn: TlsConnId) {
        self.conns.remove(&conn);
        self.held.retain(|(held, _)| *held != conn);
    }
}

/// Test fixtures shared by the crate's unit tests: a deterministic crypto provider, so that two
/// handshakes with the same inputs write the same bytes, configs over it, and an in-memory
/// handshake harness.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Arc;
    use std::time::Duration;

    use mvfstr_crypto::KeySet;
    use mvfstr_crypto::PacketKeys;
    use mvfstr_crypto::protect_header;
    use mvfstr_wire::Side;
    use mvfstr_wire::Version;
    use rustls::NamedGroup;
    use rustls::crypto::ActiveKeyExchange;
    use rustls::crypto::CryptoProvider;
    use rustls::crypto::GetRandomFailed;
    use rustls::crypto::SecureRandom;
    use rustls::crypto::SharedSecret;
    use rustls::crypto::SupportedKxGroup;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::ServerName;
    use rustls::pki_types::UnixTime;

    use super::RustlsHost;
    use crate::ServerVerification;
    use crate::external::TlsConnId;
    use crate::external::TlsHost;
    use crate::external::TlsPoll;
    use crate::session::KeyChange;
    use crate::session::Level;
    use crate::session::TlsError;
    use crate::session::TlsSession;
    use crate::time::ManualTimeProvider;

    /// 2026-09-21, the Unix time the tests run at.
    pub(crate) const NOW: u64 = 1_790_000_000;

    /// A random source that returns the same bytes every time.
    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = 0x5a ^ i as u8;
            }
            Ok(())
        }
    }

    /// A stand-in key exchange whose key share is fixed and whose shared secret is the two shares
    /// in order. It is not secure at all; it makes handshakes repeatable byte for byte.
    #[derive(Debug)]
    pub(crate) struct FixedKx(NamedGroup, u8);

    struct FixedShare {
        group: NamedGroup,
        share: [u8; 32],
    }

    impl SupportedKxGroup for FixedKx {
        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
            Ok(Box::new(FixedShare {
                group: self.0,
                share: [self.1; 32],
            }))
        }

        fn name(&self) -> NamedGroup {
            self.0
        }
    }

    impl ActiveKeyExchange for FixedShare {
        fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
            let (low, high) = if self.share[..] <= *peer {
                (&self.share[..], peer)
            } else {
                (peer, &self.share[..])
            };
            Ok(SharedSecret::from(&[low, high].concat()[..]))
        }

        fn pub_key(&self) -> &[u8] {
            &self.share
        }

        fn group(&self) -> NamedGroup {
            self.group
        }
    }

    /// A stand-in for X25519, which clients offer first.
    pub(crate) static X25519: FixedKx = FixedKx(NamedGroup::X25519, 0x25);
    /// A stand-in for P-384, which clients offer second, so a server with only this group answers
    /// with a HelloRetryRequest.
    pub(crate) static P384: FixedKx = FixedKx(NamedGroup::secp384r1, 0x38);

    /// Returns the default provider with a fixed random source and stand-in key exchange groups.
    fn provider(groups: &[&'static FixedKx]) -> CryptoProvider {
        let mut provider = mvfstr_crypto::default_provider();
        provider.secure_random = &FixedRandom;
        provider.kx_groups = groups
            .iter()
            .map(|&group| group as &'static dyn SupportedKxGroup)
            .collect();
        provider
    }

    /// An Ed25519 certificate for localhost and its key. Ed25519 signatures are deterministic.
    pub(crate) struct Cert {
        chain: Vec<CertificateDer<'static>>,
        key: PrivatePkcs8KeyDer<'static>,
    }

    impl Cert {
        pub(crate) fn new() -> Cert {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            let cert = params.self_signed(&key).unwrap();
            Cert {
                chain: vec![cert.der().clone()],
                key: PrivatePkcs8KeyDer::from(key.serialize_der()),
            }
        }
    }

    fn time() -> Arc<ManualTimeProvider> {
        Arc::new(ManualTimeProvider::new(UnixTime::since_unix_epoch(
            Duration::from_secs(NOW),
        )))
    }

    /// Returns a server config with a fresh session cache.
    pub(crate) fn server_config(
        cert: &Cert,
        alpn: &[&[u8]],
        groups: &[&'static FixedKx],
    ) -> Arc<rustls::ServerConfig> {
        let key = PrivateKeyDer::from(cert.key.clone_key());
        let config =
            crate::server_config(provider(groups), time(), cert.chain.clone(), key, alpn).unwrap();
        Arc::new(config)
    }

    /// Returns a client config with a fresh ticket store, offering X25519 then P-384.
    pub(crate) fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
        client_config_with(ServerVerification::AcceptAnyCertificate, alpn)
    }

    /// Returns a fresh client config that checks the server's certificate with `verification`.
    pub(crate) fn client_config_with(
        verification: ServerVerification,
        alpn: &[&[u8]],
    ) -> Arc<rustls::ClientConfig> {
        let config =
            crate::client_config(provider(&[&X25519, &P384]), time(), verification, alpn).unwrap();
        Arc::new(config)
    }

    pub(crate) fn localhost() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap()
    }

    pub(crate) const CLIENT_PARAMS: &[u8] = b"client transport parameters";
    pub(crate) const SERVER_PARAMS: &[u8] = b"server transport parameters";

    /// Seals a fixed short-header packet with `keys`, header protection included, so that two key
    /// sets can be compared by what they produce.
    pub(crate) fn sealed(keys: &PacketKeys) -> Vec<u8> {
        let header = [0x41, 0xd1, 0xd1, 0xd1, 0xd1, 0x00, 0x05];
        let mut packet = [&header[..], &[0x42; 32]].concat();
        let tag = keys
            .packet()
            .encrypt_in_place(5, &header, &mut packet[header.len()..])
            .unwrap();
        packet.extend_from_slice(tag.as_ref());
        protect_header(keys.header(), &mut packet, header.len() - 2).unwrap();
        packet
    }

    /// Seals the packet [`sealed`] seals, with rustls's keys.
    pub(crate) fn rustls_sealed(keys: &rustls::quic::DirectionalKeys) -> Vec<u8> {
        let header = [0x41, 0xd1, 0xd1, 0xd1, 0xd1, 0x00, 0x05];
        let mut packet = [&header[..], &[0x42; 32]].concat();
        let tag = keys
            .packet
            .encrypt_in_place(5, &header, &mut packet[header.len()..])
            .unwrap();
        packet.extend_from_slice(tag.as_ref());
        let pn_offset = header.len() - 2;
        let sample = packet[pn_offset + 4..][..keys.header.sample_len()].to_vec();
        let (first, rest) = packet.split_first_mut().unwrap();
        let pn = &mut rest[pn_offset - 1..pn_offset + 1];
        keys.header.encrypt_in_place(&sample, first, pn).unwrap();
        packet
    }

    /// Returns what a key set produces in each direction.
    pub(crate) fn key_set_fingerprint(keys: &KeySet) -> String {
        format!("{:?}/{:?}", sealed(&keys.local), sealed(&keys.remote))
    }

    /// Returns what a key change produces, for comparing two handshakes.
    pub(crate) fn fingerprint(change: &KeyChange) -> String {
        match change {
            KeyChange::Handshake(keys) => format!("Handshake {}", key_set_fingerprint(keys)),
            KeyChange::OneRtt { keys, .. } => format!("OneRtt {}", key_set_fingerprint(keys)),
            KeyChange::ZeroRtt(keys) => format!("ZeroRtt {:?}", sealed(keys)),
        }
    }

    /// One input a peer handed its host: its kind, its level, and its chunk lengths.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Handed {
        Start(Side),
        Crypto(Level, Vec<usize>),
        WriteTicket(Vec<u8>),
        Finish,
    }

    /// One endpoint of an in-memory handshake: its session, the host of an External session,
    /// CRYPTO bytes received per level and not yet read, and what TLS produced.
    pub(crate) struct Peer {
        pub(crate) tls: TlsSession,
        pub(crate) host: Option<RustlsHost>,
        pub(crate) inbox: [Vec<u8>; 3],
        /// Each chunk of CRYPTO bytes sent, with its level, in order.
        pub(crate) sent: Vec<(Level, Vec<u8>)>,
        /// Each key change, in order.
        pub(crate) keys: Vec<KeyChange>,
        /// Each input handed to the host, in order.
        pub(crate) handed: Vec<Handed>,
    }

    pub(crate) const CONN: TlsConnId = TlsConnId(7);

    impl Peer {
        pub(crate) fn inline(tls: TlsSession) -> Peer {
            Peer {
                tls,
                host: None,
                inbox: Default::default(),
                sent: Vec::new(),
                keys: Vec::new(),
                handed: Vec::new(),
            }
        }

        pub(crate) fn external(tls: TlsSession, host: RustlsHost) -> Peer {
            Peer {
                host: Some(host),
                ..Peer::inline(tls)
            }
        }

        pub(crate) fn rustls_client(version: Version, alpn: &[&[u8]]) -> Peer {
            let config = client_config(alpn);
            let tls = TlsSession::client(config, version, localhost(), CLIENT_PARAMS.to_vec());
            Peer::inline(tls.unwrap())
        }

        pub(crate) fn rustls_server(config: Arc<rustls::ServerConfig>, version: Version) -> Peer {
            let tls = TlsSession::server(config, version, SERVER_PARAMS.to_vec());
            Peer::inline(tls.unwrap())
        }

        pub(crate) fn external_server(config: Arc<rustls::ServerConfig>, version: Version) -> Peer {
            let tls = TlsSession::external_server(version, SERVER_PARAMS.to_vec());
            Peer::external(tls.unwrap(), RustlsHost::server(config))
        }

        pub(crate) fn external_client(version: Version, alpn: &[&[u8]]) -> Peer {
            let tls = TlsSession::external_client(version, "localhost", CLIENT_PARAMS.to_vec());
            Peer::external(tls.unwrap(), RustlsHost::client(client_config(alpn)))
        }

        /// Delivers a step the host completed later, then hands the session's inputs to the host
        /// and delivers the steps it returns at once. Returns whether a step was delivered.
        pub(crate) fn run_host(&mut self) -> Result<bool, TlsError> {
            let Some(host) = &mut self.host else {
                return Ok(false);
            };
            let mut delivered = false;
            if let Some((conn, step)) = host.poll_ready() {
                assert_eq!(conn, CONN);
                self.tls.deliver(step)?;
                delivered = true;
            }
            while let Some(input) = self.tls.tls_input() {
                self.handed.push(Handed::of(&input));
                match host.handle(CONN, input) {
                    TlsPoll::Ready(step) => self.tls.deliver(step)?,
                    TlsPoll::Pending => break,
                }
                delivered = true;
            }
            Ok(delivered)
        }

        /// Feeds TLS the bytes waiting at its read level, as QUIC would once it can decrypt them,
        /// and lets the host work on them.
        pub(crate) fn read(&mut self) -> Result<bool, TlsError> {
            let level = self.tls.read_level();
            let data = std::mem::take(&mut self.inbox[level as usize]);
            if data.is_empty() {
                return Ok(false);
            }
            self.tls.read_crypto(level, &data)?;
            self.run_host()?;
            Ok(true)
        }

        /// Drains TLS output into `to`'s inboxes and records it.
        pub(crate) fn write(&mut self, to: &mut Peer) -> Result<bool, TlsError> {
            let mut progressed = self.run_host()?;
            let mut buf = Vec::new();
            while let Some(out) = self.tls.write_crypto(&mut buf) {
                progressed = true;
                let bytes = buf.split_off(buf.len() - out.len);
                if !bytes.is_empty() {
                    to.inbox[out.level as usize].extend_from_slice(&bytes);
                    self.sent.push((out.level, bytes));
                }
                self.keys.extend(out.keys);
            }
            Ok(progressed)
        }

        pub(crate) fn fingerprints(&self) -> Vec<String> {
            self.keys.iter().map(fingerprint).collect()
        }
    }

    impl Handed {
        pub(crate) fn of(input: &crate::external::TlsInput<'_>) -> Handed {
            use crate::external::TlsInput;
            match input {
                TlsInput::Start { side, .. } => Handed::Start(*side),
                TlsInput::Crypto { level, data } => {
                    Handed::Crypto(*level, data.iter().map(|chunk| chunk.len()).collect())
                }
                TlsInput::WriteTicket { app_token } => Handed::WriteTicket(app_token.to_vec()),
                TlsInput::Finish => Handed::Finish,
            }
        }
    }

    /// Runs the handshake while either side makes progress. Returns the first error, with the
    /// side that raised it.
    pub(crate) fn run(client: &mut Peer, server: &mut Peer) -> Result<(), (Side, TlsError)> {
        let client_err = |e| (Side::Client, e);
        let server_err = |e| (Side::Server, e);
        loop {
            let mut progressed = client.write(server).map_err(client_err)?;
            progressed |= server.read().map_err(server_err)?;
            progressed |= server.write(client).map_err(server_err)?;
            progressed |= client.read().map_err(client_err)?;
            if !progressed {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mvfstr_crypto::KeySet;
    use mvfstr_wire::Side;
    use mvfstr_wire::Version;

    use super::fixtures::*;
    use super::*;
    use crate::external::TlsSuite;
    use crate::session::Level;

    fn ready(poll: TlsPoll) -> TlsStep {
        match poll {
            TlsPoll::Ready(step) => step,
            TlsPoll::Pending => panic!("the host answered later"),
        }
    }

    #[test]
    fn a_server_host_answers_a_client_hello_as_an_inline_rustls_server_does() {
        let cert = Cert::new();
        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let mut server =
            Peer::rustls_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        client.write(&mut server).unwrap();
        let hello = server.inbox[Level::Initial as usize].clone();
        server.read().unwrap();
        server.write(&mut client).unwrap();

        let mut host = RustlsHost::server(server_config(&cert, &[b"h3"], &[&X25519]));
        let start = TlsInput::Start {
            side: Side::Server,
            version: Version::V1,
            transport_params: SERVER_PARAMS,
            server_name: None,
        };
        let started = ready(host.handle(CONN, start));
        assert!(started.crypto.iter().all(Vec::is_empty));
        let data = [Bytes::from(hello)];
        let input = TlsInput::Crypto {
            level: Level::Initial,
            data: &data,
        };
        let step = ready(host.handle(CONN, input));

        let inline_bytes = |level: Level| -> Vec<u8> {
            let chunks = server.sent.iter().filter(|(at, _)| *at == level);
            chunks.flat_map(|(_, bytes)| bytes.clone()).collect()
        };
        assert_eq!(step.crypto[0], inline_bytes(Level::Initial), "ServerHello");
        assert_eq!(
            step.crypto[1],
            inline_bytes(Level::Handshake),
            "EncryptedExtensions to Finished"
        );
        assert!(step.crypto[2].is_empty());
        let suite = server
            .tls
            .rustls()
            .unwrap()
            .negotiated_cipher_suite()
            .unwrap();
        let suite = TlsSuite::from_codepoint(u16::from(suite.suite())).unwrap();
        assert_eq!(step.suite, Some(suite));
        assert_eq!(step.peer_transport_params.as_deref(), Some(CLIENT_PARAMS));
        assert_eq!(step.alpn.as_deref(), Some(&b"h3"[..]));
        assert!(!step.handshake_success && step.alert.is_none() && step.client_early.is_none());
        assert!(step.exporter.is_some());

        // The secrets give the keys the inline server installed.
        let alg = suite.algorithm();
        let handshake = step.handshake.as_ref().unwrap();
        let app = step.app.as_ref().unwrap();
        let ours = [
            format!(
                "Handshake {}",
                key_set_fingerprint(&KeySet::from_secrets(
                    alg,
                    &handshake.server,
                    &handshake.client
                ))
            ),
            format!(
                "OneRtt {}",
                key_set_fingerprint(&KeySet::from_secrets(alg, &app.server, &app.client))
            ),
        ];
        assert_eq!(server.fingerprints(), ours);
    }

    /// Returns every CRYPTO byte `peer` sent at `level`.
    fn sent_at(peer: &Peer, level: Level) -> Vec<u8> {
        let chunks = peer.sent.iter().filter(|(at, _)| *at == level);
        chunks.flat_map(|(_, bytes)| bytes.clone()).collect()
    }

    #[test]
    fn a_client_host_writes_the_flights_of_an_inline_rustls_client() {
        let cert = Cert::new();
        let mut client = Peer::rustls_client(Version::V1, &[b"h3"]);
        let mut server =
            Peer::rustls_server(server_config(&cert, &[b"h3"], &[&X25519]), Version::V1);
        run(&mut client, &mut server).unwrap();

        let mut host = RustlsHost::client(client_config(&[b"h3"]));
        let start = TlsInput::Start {
            side: Side::Client,
            version: Version::V1,
            transport_params: CLIENT_PARAMS,
            server_name: Some("localhost"),
        };
        let hello = ready(host.handle(CONN, start));
        assert_eq!(
            hello.crypto[0],
            sent_at(&client, Level::Initial),
            "ClientHello"
        );
        assert!(hello.crypto[1].is_empty() && hello.handshake.is_none() && hello.app.is_none());

        let data = [Bytes::from(sent_at(&server, Level::Initial))];
        let input = TlsInput::Crypto {
            level: Level::Initial,
            data: &data,
        };
        let handshake = ready(host.handle(CONN, input));
        assert!(handshake.crypto.iter().all(Vec::is_empty));
        assert!(handshake.peer_transport_params.is_none() && !handshake.handshake_success);
        let data = [Bytes::from(sent_at(&server, Level::Handshake))];
        let input = TlsInput::Crypto {
            level: Level::Handshake,
            data: &data,
        };
        let finished = ready(host.handle(CONN, input));
        assert_eq!(
            finished.crypto[1],
            sent_at(&client, Level::Handshake),
            "Finished"
        );
        assert!(finished.crypto[0].is_empty() && finished.crypto[2].is_empty());
        assert_eq!(
            finished.peer_transport_params.as_deref(),
            Some(SERVER_PARAMS)
        );
        assert_eq!(finished.alpn.as_deref(), Some(&b"h3"[..]));
        assert!(finished.handshake_success && finished.exporter.is_some());

        let suite = finished.suite.unwrap();
        assert_eq!(handshake.suite, Some(suite));
        let alg = suite.algorithm();
        let handshake = handshake.handshake.as_ref().unwrap();
        let app = finished.app.as_ref().unwrap();
        let ours = [
            format!(
                "Handshake {}",
                key_set_fingerprint(&KeySet::from_secrets(
                    alg,
                    &handshake.client,
                    &handshake.server
                ))
            ),
            format!(
                "OneRtt {}",
                key_set_fingerprint(&KeySet::from_secrets(alg, &app.client, &app.server))
            ),
        ];
        assert_eq!(client.fingerprints(), ours);
    }

    #[test]
    fn a_host_that_cannot_run_a_connection_answers_with_internal_error() {
        let mut host = RustlsHost::client(client_config(&[b"h3"]));
        let mut start = |conn, side, version, server_name| {
            let start = TlsInput::Start {
                side,
                version,
                transport_params: CLIENT_PARAMS,
                server_name,
            };
            ready(host.handle(TlsConnId(conn), start)).alert
        };
        let no_config = start(1, Side::Server, Version::V1, None);
        let draft_29 = start(2, Side::Client, Version(0xff00_001d), Some("localhost"));
        let bad_name = start(3, Side::Client, Version::V1, Some(""));
        let data = [Bytes::from_static(b"hello")];
        let input = TlsInput::Crypto {
            level: Level::Initial,
            data: &data,
        };
        let unknown = ready(host.handle(TlsConnId(4), input)).alert;
        // internal_error (80).
        let alerts = [no_config, draft_29, bad_name, unknown];
        assert_eq!(alerts, [Some(80); 4]);
        assert_eq!(host.connections(), 0);
    }

    #[test]
    fn cancelling_a_connection_drops_its_state_and_any_step_held_for_it() {
        let mut host = RustlsHost::client(client_config(&[b"h3"]));
        host.set_deferred(true);
        let start = |host: &mut RustlsHost, conn| {
            let start = TlsInput::Start {
                side: Side::Client,
                version: Version::V1,
                transport_params: CLIENT_PARAMS,
                server_name: Some("localhost"),
            };
            assert!(matches!(host.handle(conn, start), TlsPoll::Pending));
        };
        start(&mut host, CONN);
        start(&mut host, TlsConnId(8));
        assert_eq!(host.connections(), 2);
        host.cancel(CONN);
        assert_eq!(host.connections(), 1);
        let (conn, _) = host.poll_ready().unwrap();
        assert_eq!(conn, TlsConnId(8));
        assert!(host.poll_ready().is_none());
    }
}
