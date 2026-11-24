/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! In-memory handshakes between client and server `TlsSession`s.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use mvfstr_crypto::CHACHA20_POLY1305;
use mvfstr_crypto::InlineSealer;
use mvfstr_crypto::KeySet;
use mvfstr_crypto::KeyUpdater;
use mvfstr_crypto::PacketKeys;
use mvfstr_crypto::SHA256_LEN;
use mvfstr_crypto::SealJob;
use mvfstr_crypto::Sealer;
use mvfstr_crypto::SlotId;
use mvfstr_crypto::initial_keys;
use mvfstr_crypto::unprotect_header;
use mvfstr_tls::KeyChange;
use mvfstr_tls::Level;
use mvfstr_tls::ManualTimeProvider;
use mvfstr_tls::ServerVerification;
use mvfstr_tls::TlsError;
use mvfstr_tls::TlsSession;
use mvfstr_wire::Side;
use mvfstr_wire::Version;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::quic::PacketKey;

/// 2026-09-21, the Unix time the tests run at.
const NOW: u64 = 1_790_000_000;

fn unix(secs: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

fn self_signed(name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    (vec![certified.cert.der().clone()], key.into())
}

fn server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let (chain, key) = self_signed("localhost");
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Arc::new(mvfstr_tls::server_config(provider, time, chain, key, alpn).unwrap())
}

fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verification = ServerVerification::AcceptAnyCertificate;
    Arc::new(mvfstr_tls::client_config(provider, time, verification, alpn).unwrap())
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

#[test]
fn sessions_exist_for_v1_and_mvfst_only() {
    for version in [Version::V1, Version::MVFST] {
        TlsSession::client(client_config(&[b"h3"]), version, localhost(), Vec::new()).unwrap();
        TlsSession::server(server_config(&[b"h3"]), version, Vec::new()).unwrap();
    }
    let draft_29 = Version(0xff00_001d);
    let client = TlsSession::client(client_config(&[b"h3"]), draft_29, localhost(), Vec::new());
    assert!(matches!(client, Err(TlsError::UnsupportedVersion(v)) if v == draft_29));
    let server = TlsSession::server(server_config(&[b"h3"]), draft_29, Vec::new());
    assert!(matches!(server, Err(TlsError::UnsupportedVersion(v)) if v == draft_29));
}

/// One endpoint of an in-memory handshake: its session, CRYPTO bytes received per level and
/// not yet read, and what TLS produced.
struct Peer {
    tls: TlsSession,
    inbox: [Vec<u8>; 3],
    /// The level of each chunk of CRYPTO bytes the peer sent, in order.
    sent: Vec<(Level, usize)>,
    /// Every CRYPTO byte the peer sent, per level.
    sent_bytes: [Vec<u8>; 3],
    handshake: Option<KeySet>,
    one_rtt: Option<KeySet>,
    update: Option<KeyUpdater>,
}

impl Peer {
    fn new(tls: TlsSession) -> Peer {
        Peer {
            tls,
            inbox: Default::default(),
            sent: Vec::new(),
            sent_bytes: Default::default(),
            handshake: None,
            one_rtt: None,
            update: None,
        }
    }

    /// Feeds TLS the bytes waiting at its read level, as QUIC would once it can decrypt them.
    fn read(&mut self) -> Result<bool, TlsError> {
        let level = self.tls.read_level();
        let data = std::mem::take(&mut self.inbox[level as usize]);
        if data.is_empty() {
            return Ok(false);
        }
        self.tls.read_crypto(level, &data)?;
        Ok(true)
    }

    /// Drains TLS output into the peer's inboxes and installs new keys.
    fn write(&mut self, to: &mut Peer) -> bool {
        let mut progressed = false;
        let mut buf = Vec::new();
        while let Some(out) = self.tls.write_crypto(&mut buf) {
            progressed = true;
            if out.len > 0 {
                let start = buf.len() - out.len;
                to.inbox[out.level as usize].extend_from_slice(&buf[start..]);
                self.sent_bytes[out.level as usize].extend_from_slice(&buf[start..]);
                self.sent.push((out.level, out.len));
            }
            match out.keys {
                Some(KeyChange::Handshake(keys)) => self.handshake = Some(keys),
                Some(KeyChange::OneRtt { keys, update }) => {
                    self.one_rtt = Some(keys);
                    self.update = Some(update);
                }
                None => {}
            }
        }
        progressed
    }
}

/// Runs the handshake while either side makes progress. Returns the first error, with the side
/// that raised it.
fn run(client: &mut Peer, server: &mut Peer) -> Result<(), (Side, TlsError)> {
    loop {
        let mut progressed = client.write(server);
        progressed |= server.read().map_err(|e| (Side::Server, e))?;
        progressed |= server.write(client);
        progressed |= client.read().map_err(|e| (Side::Client, e))?;
        if !progressed {
            return Ok(());
        }
    }
}

fn pair(version: Version, client_alpn: &[&[u8]], server_alpn: &[&[u8]]) -> (Peer, Peer) {
    let client = TlsSession::client(
        client_config(client_alpn),
        version,
        localhost(),
        b"client transport parameters".to_vec(),
    )
    .unwrap();
    let server = TlsSession::server(
        server_config(server_alpn),
        version,
        b"server transport parameters".to_vec(),
    )
    .unwrap();
    (Peer::new(client), Peer::new(server))
}

#[test]
fn a_handshake_with_alpn_h3_completes() {
    let (mut client, mut server) = pair(Version::V1, &[b"h3"], &[b"h3"]);
    assert!(!client.tls.is_handshake_complete());
    run(&mut client, &mut server).unwrap();

    assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
    assert_eq!(client.tls.alpn(), Some(&b"h3"[..]));
    assert_eq!(server.tls.alpn(), Some(&b"h3"[..]));
    assert_eq!(
        client.tls.peer_transport_params(),
        Some(&b"server transport parameters"[..])
    );
    assert_eq!(
        server.tls.peer_transport_params(),
        Some(&b"client transport parameters"[..])
    );
    let levels = |peer: &Peer| {
        peer.sent
            .iter()
            .map(|(level, _)| *level)
            .collect::<Vec<_>>()
    };
    // ClientHello, then Finished.
    assert_eq!(levels(&client), [Level::Initial, Level::Handshake]);
    // ServerHello; EncryptedExtensions to Finished; NewSessionTickets after the client's Finished.
    assert_eq!(
        levels(&server),
        [Level::Initial, Level::Handshake, Level::OneRtt]
    );
    for peer in [&client, &server] {
        assert!(peer.handshake.is_some() && peer.one_rtt.is_some() && peer.update.is_some());
        assert_eq!(peer.tls.read_level(), Level::OneRtt);
        assert_eq!(peer.tls.write_level(), Level::OneRtt);
    }
}

/// Returns whether `messages` holds a TLS extension of type `ext` whose body is `body`.
fn has_extension(messages: &[u8], ext: u16, body: &[u8]) -> bool {
    let mut needle = ext.to_be_bytes().to_vec();
    needle.extend_from_slice(&(body.len() as u16).to_be_bytes());
    needle.extend_from_slice(body);
    messages.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn transport_parameters_use_extension_0x39_for_v1_and_0xffa5_for_mvfst() {
    let client_tp = b"client transport parameters";
    let server_tp = b"server transport parameters";
    for (version, ext, other) in [(Version::V1, 0x39, 0xffa5), (Version::MVFST, 0xffa5, 0x39)] {
        let (mut client, mut server) = pair(version, &[b"h3"], &[b"h3"]);
        run(&mut client, &mut server).unwrap();
        assert!(server.tls.is_handshake_complete(), "{version:?}");
        let client_hello = &client.sent_bytes[Level::Initial as usize];
        let encrypted_extensions = &server.sent_bytes[Level::Handshake as usize];
        assert!(has_extension(client_hello, ext, client_tp), "{version:?}");
        assert!(
            !has_extension(client_hello, other, client_tp),
            "{version:?}"
        );
        assert!(
            has_extension(encrypted_extensions, ext, server_tp),
            "{version:?}"
        );
        assert!(
            !has_extension(encrypted_extensions, other, server_tp),
            "{version:?}"
        );
        assert_eq!(server.tls.peer_transport_params(), Some(&client_tp[..]));
        assert_eq!(client.tls.peer_transport_params(), Some(&server_tp[..]));
        assert_eq!(client.tls.version(), version);
    }
}

#[test]
fn a_server_refuses_a_client_hello_without_the_transport_parameters_of_its_version() {
    // Each server reads the ClientHello of a client of the other version, which carries its
    // transport parameters only under the other version's codepoint.
    let h3: &[&[u8]] = &[b"h3"];
    let cases: [(&str, Version, &[&[u8]], TlsSession); 3] = [
        (
            "v1 server, 0xffa5 only",
            Version::MVFST,
            h3,
            TlsSession::server(server_config(h3), Version::V1, Vec::new()).unwrap(),
        ),
        (
            "MVFST server, 0x39 only",
            Version::V1,
            h3,
            TlsSession::server(server_config(h3), Version::MVFST, Vec::new()).unwrap(),
        ),
        (
            "MVFST server choosing by ALPN, no ALPN and 0x39 only",
            Version::V1,
            &[],
            TlsSession::server_choosing_by_alpn(
                server_config(h3),
                server_config(&[]),
                Version::MVFST,
                Vec::new(),
            )
            .unwrap(),
        ),
    ];
    let outcomes: Vec<_> = cases
        .into_iter()
        .map(|(name, client_version, client_alpn, server)| {
            let client = TlsSession::client(
                client_config(client_alpn),
                client_version,
                localhost(),
                b"client transport parameters".to_vec(),
            );
            let (mut client, mut server) = (Peer::new(client.unwrap()), Peer::new(server));
            client.write(&mut server);
            let read = server
                .read()
                .map_err(|error| error.transport_error_code().into_inner());
            let alert = server.tls.alert().map(|code| code.into_inner());
            let wrote = server.write(&mut client);
            (name, read, alert, wrote)
        })
        .collect();
    // missing_extension (109), and the server does not answer.
    let expected: Vec<_> = outcomes
        .iter()
        .map(|&(name, ..)| (name, Err(0x016d), Some(0x016d), false))
        .collect();
    assert_eq!(outcomes, expected);
}

#[test]
fn a_client_refuses_encrypted_extensions_with_the_transport_parameters_of_another_version() {
    // rustls servers of the other version, which accept the client's codepoint and answer with
    // their own. rustls clients refuse that as an extension they did not offer (RFC 8446).
    for (version, server_version) in [
        (Version::V1, rustls::quic::Version::V1Draft),
        (Version::MVFST, rustls::quic::Version::V1),
    ] {
        let mut client = TlsSession::client(
            client_config(&[b"h3"]),
            version,
            localhost(),
            b"client transport parameters".to_vec(),
        )
        .unwrap();
        let mut server = rustls::quic::ServerConnection::new(
            server_config(&[b"h3"]),
            server_version,
            b"server transport parameters".to_vec(),
        )
        .unwrap();
        let mut hello = Vec::new();
        while client.write_crypto(&mut hello).is_some() {}
        server.read_hs(&hello).unwrap();
        let (mut server_hello, mut encrypted_extensions) = (Vec::new(), Vec::new());
        assert!(server.write_hs(&mut server_hello).is_some());
        assert!(server.write_hs(&mut encrypted_extensions).is_some());

        client.read_crypto(Level::Initial, &server_hello).unwrap();
        while client.write_crypto(&mut Vec::new()).is_some() {}
        let error = client
            .read_crypto(Level::Handshake, &encrypted_extensions)
            .unwrap_err();
        assert!(
            matches!(
                error,
                TlsError::Alert {
                    alert: rustls::AlertDescription::UnsupportedExtension,
                    ..
                }
            ),
            "{version:?}: {error:?}"
        );
        assert_eq!(error.transport_error_code().into_inner(), 0x016e);
        assert_eq!(client.peer_transport_params(), None, "{version:?}");
    }
}

#[test]
fn a_resuming_client_reports_only_the_parameters_of_the_current_connection() {
    let client_config = client_config(&[b"h3"]);
    let server_config = server_config(&[b"h3"]);
    let connect = |server_tp: &[u8]| {
        let client = TlsSession::client(
            client_config.clone(),
            Version::V1,
            localhost(),
            b"client transport parameters".to_vec(),
        );
        let server = TlsSession::server(server_config.clone(), Version::V1, server_tp.to_vec());
        (Peer::new(client.unwrap()), Peer::new(server.unwrap()))
    };
    let (mut client, mut server) = connect(b"first server parameters");
    run(&mut client, &mut server).unwrap();

    // rustls stores the first server's parameters with the session, for 0-RTT.
    let (mut client, mut server) = connect(b"second server parameters");
    assert_eq!(client.tls.peer_transport_params(), None);
    client.write(&mut server);
    server.read().unwrap();
    server.write(&mut client);
    // The ServerHello, but not yet the EncryptedExtensions.
    assert!(client.read().unwrap());
    assert_eq!(client.tls.peer_transport_params(), None);
    run(&mut client, &mut server).unwrap();
    assert_eq!(
        client.tls.rustls().handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert_eq!(
        client.tls.peer_transport_params(),
        Some(&b"second server parameters"[..])
    );
}

/// Seals a packet at one level with `tx` and checks `rx` opens it. `header` is the unprotected
/// header, ending with a packet number whose length is in its first byte.
fn seal_and_open(tx: &Arc<PacketKeys>, rx: &PacketKeys, header: &[u8], pn: u64) {
    let payload: Vec<u8> = (0..64u8).collect();
    let mut packet = [header, &payload, &[0; 16]].concat();
    let job = SealJob {
        slot: SlotId(0),
        keys: tx,
        pn,
        hdr_len: header.len() as u16,
        len: packet.len() as u16,
    };
    InlineSealer.seal(job, &mut packet).unwrap();
    assert_ne!(packet[header.len()..header.len() + 64], payload[..]);

    let pn_len = usize::from(header[0] & 0x03) + 1;
    let pn_offset = header.len() - pn_len;
    assert_eq!(
        unprotect_header(rx.header(), &mut packet, pn_offset),
        Ok(pn_len)
    );
    assert_eq!(&packet[..header.len()], header);
    let (header, body) = packet.split_at_mut(header.len());
    let plain = rx.packet().decrypt_in_place(pn, header, body).unwrap();
    assert_eq!(plain, payload);
}

/// Builds a long header of the given type with 8-byte connection IDs and a 2-byte packet number.
fn long_header(packet_type: u8, pn: u16) -> Vec<u8> {
    let mut header = vec![0xc1 | (packet_type << 4), 0, 0, 0, 1, 8];
    header.extend_from_slice(&[0xd1; 8]);
    header.push(8);
    header.extend_from_slice(&[0x5c; 8]);
    if packet_type == 0 {
        header.push(0); // empty token
    }
    header.extend_from_slice(&[0x40, 0x56]); // length
    header.extend_from_slice(&pn.to_be_bytes());
    header
}

/// Builds a short header with an 8-byte connection ID, the given key phase and a 2-byte packet
/// number.
fn short_header(key_phase: bool, pn: u16) -> Vec<u8> {
    let mut header = vec![0x41 | if key_phase { 0x04 } else { 0 }];
    header.extend_from_slice(&[0xd1; 8]);
    header.extend_from_slice(&pn.to_be_bytes());
    header
}

#[test]
fn keys_of_every_level_interoperate_in_both_directions() {
    let (mut client, mut server) = pair(Version::V1, &[b"h3"], &[b"h3"]);
    run(&mut client, &mut server).unwrap();
    let dcid = [0xd1; 8];
    let client_initial = initial_keys(Version::V1, &dcid, Side::Client).unwrap();
    let server_initial = initial_keys(Version::V1, &dcid, Side::Server).unwrap();
    let levels = [
        (&client_initial, &server_initial, long_header(0, 0)),
        (
            client.handshake.as_ref().unwrap(),
            server.handshake.as_ref().unwrap(),
            long_header(2, 1),
        ),
        (
            client.one_rtt.as_ref().unwrap(),
            server.one_rtt.as_ref().unwrap(),
            short_header(false, 2),
        ),
    ];
    for (client_keys, server_keys, header) in levels {
        seal_and_open(&client_keys.local, &server_keys.remote, &header, 7);
        seal_and_open(&server_keys.local, &client_keys.remote, &header, 9);
    }
    let suite = client.tls.rustls().negotiated_cipher_suite().unwrap();
    assert!(mvfstr_crypto::quic_algorithm(suite.tls13().unwrap()).is_some());
}

#[test]
fn key_updates_derive_matching_keys_and_keep_header_protection() {
    let (mut client, mut server) = pair(Version::V1, &[b"h3"], &[b"h3"]);
    run(&mut client, &mut server).unwrap();
    let server_phase_0 = server.one_rtt.take().unwrap();
    let mut client_update = client.update.take().unwrap();
    let mut server_update = server.update.take().unwrap();

    for (phase, pn) in [(1u16, 20), (2, 30)] {
        let client_keys = client_update.next_keys();
        let server_keys = server_update.next_keys();
        let header = short_header(phase % 2 == 1, pn);
        seal_and_open(
            &client_keys.local,
            &server_keys.remote,
            &header,
            u64::from(pn),
        );
        seal_and_open(
            &server_keys.local,
            &client_keys.remote,
            &header,
            u64::from(pn) + 1,
        );

        // A packet of the new phase does not open under phase 0's packet key, but its header
        // comes off with phase 0's header-protection key.
        let payload = [0x77u8; 32];
        let mut packet = [&header[..], &payload, &[0; 16]].concat();
        let job = SealJob {
            slot: SlotId(0),
            keys: &client_keys.local,
            pn: u64::from(pn),
            hdr_len: header.len() as u16,
            len: packet.len() as u16,
        };
        InlineSealer.seal(job, &mut packet).unwrap();
        let pn_offset = header.len() - 2;
        let remote_0 = &server_phase_0.remote;
        assert_eq!(
            unprotect_header(remote_0.header(), &mut packet, pn_offset),
            Ok(2)
        );
        assert_eq!(&packet[..header.len()], &header[..]);
        let (head, body) = packet.split_at_mut(header.len());
        assert!(
            remote_0
                .packet()
                .decrypt_in_place(u64::from(pn), head, body)
                .is_err()
        );
    }
}

/// The secrets rustls logs, by label.
#[derive(Debug, Default)]
struct SecretLog(Mutex<Vec<(String, Vec<u8>)>>);

impl rustls::KeyLog for SecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let entry = (label.to_string(), secret.to_vec());
        self.0.lock().unwrap().push(entry);
    }
}

impl SecretLog {
    /// Returns the secret logged under `label`, from a SHA-256 suite.
    fn get(&self, label: &str) -> [u8; SHA256_LEN] {
        let entries = self.0.lock().unwrap();
        let entry = entries.iter().find(|(logged, _)| logged == label);
        entry.unwrap().1.as_slice().try_into().unwrap()
    }
}

/// Seals a fixed payload with `key` and returns it, tag included.
fn sealed(key: &dyn PacketKey) -> Vec<u8> {
    let mut payload = [0x42u8; 32];
    let tag = key.encrypt_in_place(5, &short_header(true, 5), &mut payload);
    [&payload[..], tag.unwrap().as_ref()].concat()
}

#[test]
fn key_updates_follow_the_rfc9001_quic_ku_derivation() {
    // TLS_CHACHA20_POLY1305_SHA256, the suite of RFC 9001's ChaCha20-Poly1305 example.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let chacha20 = rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256;
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == chacha20);
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    let verification = ServerVerification::AcceptAnyCertificate;
    let mut config = mvfstr_tls::client_config(provider, time, verification, &[b"h3"]).unwrap();
    let log = Arc::new(SecretLog::default());
    config.key_log = log.clone();
    let client = TlsSession::client(Arc::new(config), Version::V1, localhost(), Vec::new());
    let server = TlsSession::server(server_config(&[b"h3"]), Version::V1, Vec::new());
    let (mut client, mut server) = (Peer::new(client.unwrap()), Peer::new(server.unwrap()));
    run(&mut client, &mut server).unwrap();
    let suite = client.tls.rustls().negotiated_cipher_suite().unwrap();
    assert_eq!(suite.suite(), chacha20);

    let ku = |secret: &[u8; SHA256_LEN]| {
        let mut next = [0; SHA256_LEN];
        mvfstr_crypto::hkdf_expand_label(secret, b"quic ku", &[], &mut next).unwrap();
        next
    };
    let mut client_secret = log.get("CLIENT_TRAFFIC_SECRET_0");
    let mut server_secret = log.get("SERVER_TRAFFIC_SECRET_0");
    let mut update = client.update.take().unwrap();
    for phase in 1..=2 {
        client_secret = ku(&client_secret);
        server_secret = ku(&server_secret);
        let keys = update.next_keys();
        let local = PacketKeys::from_secret(&CHACHA20_POLY1305, &client_secret);
        let remote = PacketKeys::from_secret(&CHACHA20_POLY1305, &server_secret);
        assert_eq!(
            sealed(keys.local.packet()),
            sealed(local.packet()),
            "phase {phase}"
        );
        assert_eq!(
            sealed(keys.remote.packet()),
            sealed(remote.packet()),
            "phase {phase}"
        );
    }
}

#[test]
fn a_server_without_the_clients_protocol_fails_with_crypto_error_0x0178() {
    let (mut client, mut server) = pair(Version::V1, &[b"h3"], &[b"hq-interop"]);
    let (side, error) = run(&mut client, &mut server).unwrap_err();
    assert_eq!(side, Side::Server);
    assert!(
        matches!(
            error,
            TlsError::Alert {
                alert: rustls::AlertDescription::NoApplicationProtocol,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.transport_error_code().into_inner(), 0x0178);
    assert_eq!(
        server.tls.alert().map(|code| code.into_inner()),
        Some(0x0178)
    );
    assert!(!server.tls.is_handshake_complete());
}

#[test]
fn a_server_without_alpn_accepts_a_client_that_offers_none() {
    let (mut client, mut server) = pair(Version::MVFST, &[], &[]);
    run(&mut client, &mut server).unwrap();
    assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
    assert_eq!(client.tls.alpn(), None);
    assert_eq!(server.tls.alpn(), None);

    // A server with a protocol list refuses the same client.
    let (mut client, mut server) = pair(Version::MVFST, &[], &[b"h3"]);
    let (side, error) = run(&mut client, &mut server).unwrap_err();
    assert_eq!(
        (side, error.transport_error_code().into_inner()),
        (Side::Server, 0x0178)
    );
}

/// Returns a client offering `client_alpn` and a server that takes an h3 config for a
/// ClientHello with ALPN and `server` for one without.
fn choosing_pair(client_alpn: &[&[u8]], server: Arc<rustls::ServerConfig>) -> (Peer, Peer) {
    let (client, _) = pair(Version::MVFST, client_alpn, &[]);
    let server = TlsSession::server_choosing_by_alpn(
        server_config(&[b"h3"]),
        server,
        Version::MVFST,
        b"server transport parameters".to_vec(),
    )
    .unwrap();
    (client, Peer::new(server))
}

#[test]
fn a_server_with_a_config_for_client_hellos_without_alpn_takes_both_kinds() {
    let negotiated: [(&[&[u8]], Option<&[u8]>); 2] =
        [(&[b"hq-interop", b"h3"], Some(&b"h3"[..])), (&[], None)];
    for (client_alpn, alpn) in negotiated {
        let (mut client, mut server) = choosing_pair(client_alpn, server_config(&[]));
        run(&mut client, &mut server).unwrap();
        assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
        assert_eq!(server.tls.alpn(), alpn, "{client_alpn:?}");
        assert_eq!(
            server.tls.peer_transport_params(),
            Some(&b"client transport parameters"[..])
        );
    }

    // A client offering only protocols the server lacks fails as against a single config.
    let (mut client, mut server) = choosing_pair(&[b"hq-interop"], server_config(&[]));
    let (side, error) = run(&mut client, &mut server).unwrap_err();
    assert_eq!(
        (side, error.transport_error_code().into_inner()),
        (Side::Server, 0x0178)
    );
}

#[test]
fn the_server_chooses_once_the_whole_client_hello_has_arrived() {
    let (mut client, mut server) = choosing_pair(&[], server_config(&[]));
    client.write(&mut server);
    let hello = std::mem::take(&mut server.inbox[Level::Initial as usize]);
    let (last, head) = hello.split_last().unwrap();
    for byte in head {
        server.tls.read_crypto(Level::Initial, &[*byte]).unwrap();
        assert!(server.tls.write_crypto(&mut Vec::new()).is_none());
    }
    server.tls.read_crypto(Level::Initial, &[*last]).unwrap();
    run(&mut client, &mut server).unwrap();
    assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
    assert_eq!(server.tls.alpn(), None);
}

/// Returns a server config whose only group is P-384, for which the client does not send a key
/// share at first, so the server answers with a HelloRetryRequest.
fn p384_server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP384R1];
    let (chain, key) = self_signed("localhost");
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    Arc::new(mvfstr_tls::server_config(provider, time, chain, key, alpn).unwrap())
}

#[test]
fn the_choice_holds_for_the_client_hello_after_a_retry() {
    let (mut client, mut server) = choosing_pair(&[], p384_server_config(&[]));
    run(&mut client, &mut server).unwrap();
    assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
    assert_eq!(server.tls.alpn(), None);
    let client_hellos = client
        .sent
        .iter()
        .filter(|(level, _)| *level == Level::Initial)
        .count();
    assert_eq!(
        client_hellos, 2,
        "the server asked for a second ClientHello"
    );
}

/// Moves the transport parameters `params` of a v1 ClientHello from extension 0x39 to 0xffa5.
fn move_to_draft_codepoint(hello: &mut [u8], params: &[u8]) {
    let mut extension = vec![0x00, 0x39, 0x00, params.len() as u8];
    extension.extend_from_slice(params);
    let at = hello
        .windows(extension.len())
        .position(|bytes| bytes == extension)
        .unwrap();
    hello[at..at + 2].copy_from_slice(&[0xff, 0xa5]);
}

#[test]
fn a_server_checks_the_client_hello_after_a_retry_too() {
    let client_tp = b"client transport parameters";
    let client = TlsSession::client(
        client_config(&[b"h3"]),
        Version::V1,
        localhost(),
        client_tp.to_vec(),
    );
    let server = TlsSession::server(p384_server_config(&[b"h3"]), Version::V1, Vec::new());
    let (mut client, mut server) = (Peer::new(client.unwrap()), Peer::new(server.unwrap()));
    client.write(&mut server);
    server.read().unwrap();
    // The HelloRetryRequest, then the second ClientHello.
    server.write(&mut client);
    client.read().unwrap();
    client.write(&mut server);

    // The second ClientHello carries the transport parameters under 0xffa5 instead.
    move_to_draft_codepoint(&mut server.inbox[Level::Initial as usize], client_tp);

    let read = server
        .read()
        .map_err(|error| error.transport_error_code().into_inner());
    assert_eq!(read, Err(0x016d));
    assert_eq!(
        server.tls.alert().map(|code| code.into_inner()),
        Some(0x016d)
    );
    assert!(!server.write(&mut client), "the server sends nothing more");
}

#[test]
fn a_server_refuses_bytes_after_a_client_hello_whether_or_not_they_arrive_with_it() {
    // rustls refuses Initial bytes that come with a ClientHello with unexpected_message. A
    // transport may hand them to TLS on their own before it drains the server's answer, a
    // ServerHello or a HelloRetryRequest; the server must refuse them all the same.
    let trailing: [&[u8]; 3] = [&[1, 0], &[1, 0, 0, 40, 3, 3], &[20, 0, 0, 0]];
    let mut outcomes = Vec::new();
    for (server_name, config) in [
        ("ServerHello", server_config(&[b"h3"])),
        ("HelloRetryRequest", p384_server_config(&[b"h3"])),
    ] {
        for bytes in trailing {
            for together in [true, false] {
                let client = TlsSession::client(
                    client_config(&[b"h3"]),
                    Version::V1,
                    localhost(),
                    b"client transport parameters".to_vec(),
                );
                let server = TlsSession::server(config.clone(), Version::V1, Vec::new());
                let (mut client, mut server) =
                    (Peer::new(client.unwrap()), Peer::new(server.unwrap()));
                client.write(&mut server);
                let mut hello = std::mem::take(&mut server.inbox[Level::Initial as usize]);
                let read = if together {
                    hello.extend_from_slice(bytes);
                    server.tls.read_crypto(Level::Initial, &hello)
                } else {
                    server.tls.read_crypto(Level::Initial, &hello).unwrap();
                    // An empty read is not a violation.
                    server.tls.read_crypto(Level::Initial, &[]).unwrap();
                    server.tls.read_crypto(Level::Initial, bytes)
                };
                let read = read.map_err(|error| error.transport_error_code().into_inner());
                let alert = server.tls.alert().map(|code| code.into_inner());
                outcomes.push((server_name, bytes, together, read, alert));
            }
        }
    }
    let expected: Vec<_> = outcomes
        .iter()
        .map(|&(server_name, bytes, together, ..)| {
            (server_name, bytes, together, Err(0x010a), Some(0x010a))
        })
        .collect();
    assert_eq!(outcomes, expected);
}

#[test]
fn crypto_bytes_at_a_level_tls_is_not_reading_are_refused_unconsumed() {
    let (mut client, mut server) = pair(Version::V1, &[b"h3"], &[b"h3"]);
    client.write(&mut server);
    let client_hello = server.inbox[Level::Initial as usize].clone();
    for level in [Level::Handshake, Level::OneRtt] {
        let error = server.tls.read_crypto(level, &client_hello).unwrap_err();
        let TlsError::WrongLevel {
            level: refused,
            expected,
        } = error
        else {
            panic!("{error:?}");
        };
        assert_eq!((refused, expected), (level, Level::Initial));
        assert_eq!(error.transport_error_code().into_inner(), 0x0a);
    }
    assert!(server.tls.write_crypto(&mut Vec::new()).is_none());
    assert_eq!(server.tls.read_level(), Level::Initial);
    run(&mut client, &mut server).unwrap();
    assert!(client.tls.is_handshake_complete() && server.tls.is_handshake_complete());
}

#[test]
fn a_handshake_message_too_long_to_buffer_fails_with_decode_error() {
    let (_, mut server) = pair(Version::V1, &[b"h3"], &[b"h3"]);
    // A ClientHello header that claims 65,536 bytes.
    let error = server
        .tls
        .read_crypto(Level::Initial, &[0x01, 0x01, 0x00, 0x00])
        .unwrap_err();
    assert!(
        matches!(
            error,
            TlsError::Alert {
                alert: rustls::AlertDescription::DecodeError,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.transport_error_code().into_inner(), 0x0132);
    assert_eq!(
        server.tls.alert().map(|code| code.into_inner()),
        Some(0x0132)
    );
}

/// A resolver that serves a fixed certified key, which may pair a certificate with another key.
#[derive(Debug)]
struct FixedCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[test]
fn accepting_any_certificate_still_checks_the_servers_signature() {
    // A certificate for another name is accepted.
    let (chain, key) = self_signed("example.org");
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config =
        mvfstr_tls::server_config(provider.clone(), time, chain.clone(), key, &[b"h3"]).unwrap();
    let mut client = Peer::new(
        TlsSession::client(
            client_config(&[b"h3"]),
            Version::V1,
            localhost(),
            Vec::new(),
        )
        .unwrap(),
    );
    let mut server =
        Peer::new(TlsSession::server(Arc::new(config.clone()), Version::V1, Vec::new()).unwrap());
    run(&mut client, &mut server).unwrap();
    assert!(client.tls.is_handshake_complete());

    // A server that signs with a key other than its certificate's is refused.
    let (_, other_key) = self_signed("example.org");
    let signer = provider.key_provider.load_private_key(other_key).unwrap();
    let mut config = config;
    config.cert_resolver = Arc::new(FixedCert(Arc::new(rustls::sign::CertifiedKey::new(
        chain, signer,
    ))));
    let mut client = Peer::new(
        TlsSession::client(
            client_config(&[b"h3"]),
            Version::V1,
            localhost(),
            Vec::new(),
        )
        .unwrap(),
    );
    let mut server =
        Peer::new(TlsSession::server(Arc::new(config), Version::V1, Vec::new()).unwrap());
    let (side, error) = run(&mut client, &mut server).unwrap_err();
    assert_eq!(side, Side::Client);
    assert!(matches!(error, TlsError::Alert { .. }), "{error:?}");
    assert_eq!(
        error.transport_error_code().into_inner(),
        0x0133,
        "{error:?}"
    );
    assert!(!client.tls.is_handshake_complete());
}

/// Builds a CA certificate and a certificate for `localhost` it issued, valid from 2025 to 2030.
fn ca_and_leaf() -> (
    CertificateDer<'static>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 1, 1);
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    (ca.der().clone(), vec![leaf.der().clone()], key.into())
}

#[test]
fn webpki_verification_checks_the_name_and_expiry_at_the_callers_time() {
    let (ca, chain, key) = ca_and_leaf();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let time = Arc::new(ManualTimeProvider::new(unix(NOW)));
    let server_config = Arc::new(
        mvfstr_tls::server_config(provider.clone(), time.clone(), chain, key, &[b"h3"]).unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let verification = ServerVerification::Roots(Arc::new(roots));
    let client_config = Arc::new(
        mvfstr_tls::client_config(provider, time.clone(), verification, &[b"h3"]).unwrap(),
    );
    let handshake = |name: &str| {
        let name = ServerName::try_from(name.to_string()).unwrap();
        let tls = TlsSession::client(client_config.clone(), Version::V1, name, Vec::new());
        let mut client = Peer::new(tls.unwrap());
        let tls = TlsSession::server(server_config.clone(), Version::V1, Vec::new());
        let mut server = Peer::new(tls.unwrap());
        run(&mut client, &mut server).map(|()| client.tls.is_handshake_complete())
    };
    let crypto_error = |result: Result<bool, (Side, TlsError)>| {
        let (side, error) = result.unwrap_err();
        (side, error.transport_error_code().into_inner())
    };

    assert!(handshake("localhost").unwrap());
    // bad_certificate (42) for another name.
    assert_eq!(
        crypto_error(handshake("example.org")),
        (Side::Client, 0x012a)
    );
    // certificate_expired (45) once the caller's clock passes 2030.
    time.set(unix(1_900_000_000));
    assert_eq!(crypto_error(handshake("localhost")), (Side::Client, 0x012d));
}
