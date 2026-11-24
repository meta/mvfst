/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of connections whose handshake runs on a TLS host outside them, over the pair harness of
//! [`crate::testing`], with [`RustlsHost`] as the host.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_tls::Level;
use mvfstr_tls::testing::RustlsHost;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use super::stream_tests::App;
use super::stream_tests::ORDER;
use super::stream_tests::RTT;
use super::stream_tests::config;
use super::stream_tests::pattern;
use super::stream_tests::run_apps;
use super::tests::Forge;
use super::tests::LIMIT;
use super::tests::deliver;
use crate::AppCode;
use crate::ClientTls;
use crate::CloseReason;
use crate::ConnEvent;
use crate::Initiator;
use crate::ServerTls;
use crate::StreamReady;
use crate::TlsConnId;
use crate::TlsDeliverError;
use crate::TlsHost;
use crate::TlsInput;
use crate::TlsPoll;
use crate::TlsStep;
use crate::recovery::Space;
use crate::testing::Pair;
use crate::testing::Peer;
use crate::testing::fixtures::Setup;
use crate::testing::fixtures::unix_now;

/// The log of a [`Recording`] host: each input's kind, with 1-RTT CRYPTO bytes told apart, the
/// number of cancels, and how many connections its rustls host held after the last call.
#[derive(Debug, Default)]
struct Log {
    inputs: Vec<&'static str>,
    cancels: usize,
    connections: usize,
}

/// A [`RustlsHost`] that logs its work.
struct Recording {
    inner: RustlsHost,
    log: Rc<RefCell<Log>>,
}

impl Recording {
    fn note(&self, input: Option<&'static str>) {
        let mut log = self.log.borrow_mut();
        log.inputs.extend(input);
        log.connections = self.inner.connections();
    }
}

impl TlsHost for Recording {
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        let kind = match &input {
            TlsInput::Start { .. } => "start",
            TlsInput::Crypto {
                level: Level::OneRtt,
                ..
            } => "1-rtt crypto",
            TlsInput::Crypto { .. } => "crypto",
            TlsInput::WriteTicket { .. } => "ticket",
            TlsInput::Finish => "finish",
        };
        let poll = self.inner.handle(conn, input);
        self.note(Some(kind));
        poll
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        let ready = self.inner.poll_ready();
        self.note(None);
        ready
    }

    fn cancel(&mut self, conn: TlsConnId) {
        self.inner.cancel(conn);
        self.log.borrow_mut().cancels += 1;
        self.note(None);
    }
}

/// Starts a pair from `setup` whose sides in `external` run their handshakes on a [`RustlsHost`]
/// with the rustls config that side would otherwise use inline, each step arriving `latency`
/// after the host produced it. Returns the log of each external side's host, in the order given.
fn recorded(
    setup: &Setup,
    external: &[Side],
    latency: Duration,
) -> (Instant, Pair, Vec<Rc<RefCell<Log>>>) {
    let (server_tls, client_tls) = setup.rustls();
    let server = if external.contains(&Side::Server) {
        ServerTls::External
    } else {
        ServerTls::Rustls(server_tls.clone())
    };
    let client = if external.contains(&Side::Client) {
        ClientTls::External
    } else {
        ClientTls::Rustls(client_tls.clone())
    };
    let epoch = crate::recovery::test_epoch();
    let mut pair = Pair::new(epoch, unix_now(), setup.pair_with(server, client));
    let mut logs = Vec::new();
    for &side in external {
        let inner = match side {
            Side::Server => RustlsHost::server(server_tls.clone()),
            Side::Client => RustlsHost::client(client_tls.clone()),
        };
        let log = Rc::new(RefCell::new(Log::default()));
        logs.push(log.clone());
        pair.set_tls_host(side, Box::new(Recording { inner, log }), latency);
    }
    (epoch, pair, logs)
}

/// Like [`recorded`], without the logs.
fn external(setup: &Setup, external: &[Side], latency: Duration) -> (Instant, Pair) {
    let (epoch, pair, _) = recorded(setup, external, latency);
    (epoch, pair)
}

/// Runs the handshake of `pair` to confirmation, then sends 100,000 bytes each way on one
/// bidirectional stream and checks that they arrive.
fn handshake_and_transfer(epoch: Instant, pair: &mut Pair) {
    assert!(
        pair.handshake(epoch + LIMIT),
        "no handshake: client {:?}, server {:?}",
        pair.client.events,
        pair.server.events
    );
    let (mut client, mut server) = (App::default(), App::default());
    let id = pair
        .client
        .conn_mut()
        .open_stream(Dir::Bi, ORDER)
        .expect("a stream opens");
    client.write(id, pattern(100_000), true);
    run_apps(pair, pair.now + 10 * RTT, &mut client, &mut server);
    assert_eq!(server.data.get(&id).map(Vec::len), Some(100_000));
    assert!(server.data[&id] == pattern(100_000));
    server.write(id, pattern(100_000), true);
    run_apps(pair, pair.now + 10 * RTT, &mut client, &mut server);
    assert_eq!(client.data.get(&id).map(Vec::len), Some(100_000));
    assert!(client.data[&id] == pattern(100_000));
    for peer in [&pair.client, &pair.server] {
        assert_eq!(peer.conn().alpn(), Some(&b"h3"[..]));
        assert!(
            !peer
                .events
                .iter()
                .any(|event| matches!(event, ConnEvent::Closed { .. }))
        );
    }
}

#[test]
fn an_external_server_on_a_rustls_host_completes_the_handshake_and_carries_data() {
    let (epoch, mut pair) = external(&Setup::default(), &[Side::Server], Duration::ZERO);
    handshake_and_transfer(epoch, &mut pair);
}

#[test]
fn an_external_client_on_a_rustls_host_completes_the_handshake_with_an_inline_server() {
    let (epoch, mut pair) = external(&Setup::default(), &[Side::Client], Duration::ZERO);
    handshake_and_transfer(epoch, &mut pair);
}

#[test]
fn write_keys_ready_comes_first_then_connected_inline_and_on_a_host() {
    for external_sides in [&[][..], &[Side::Server], &[Side::Client]] {
        let (epoch, mut pair) = external(&Setup::default(), external_sides, Duration::ZERO);
        assert!(
            pair.handshake(epoch + LIMIT),
            "no handshake with {external_sides:?} external"
        );
        for peer in [&pair.client, &pair.server] {
            assert_eq!(
                peer.events[..3],
                [
                    ConnEvent::WriteKeysReady,
                    ConnEvent::Connected,
                    ConnEvent::Confirmed
                ],
                "{external_sides:?} external"
            );
        }
    }
}

#[test]
fn a_receive_says_when_it_left_work_for_the_tls_host() {
    for external_sides in [&[][..], &[Side::Server], &[Side::Client]] {
        let (epoch, mut pair) = external(&Setup::default(), external_sides, Duration::ZERO);
        assert!(
            pair.handshake(epoch + LIMIT),
            "no handshake with {external_sides:?} external"
        );
        for (peer, side) in [(&pair.client, Side::Client), (&pair.server, Side::Server)] {
            assert_eq!(
                peer.recvs.iter().any(|summary| summary.tls_due),
                external_sides.contains(&side),
                "{side:?} with {external_sides:?} external: {:?}",
                peer.recvs
            );
        }
    }
}

#[test]
fn a_receive_that_closes_the_connection_says_when_its_host_has_state_to_cancel() {
    let hour = Duration::from_secs(3600);
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &[Side::Server], hour);
    let log = logs[0].clone();
    assert!(pair.run_until(epoch + LIMIT, |_| log.borrow().inputs.contains(&"start")));
    let now = pair.now;
    pair.client
        .conn_mut()
        .close(now, AppCode(VarInt::from_u32(1)), Bytes::new());
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.server.events.iter().any(|event| {
            matches!(
                event,
                ConnEvent::Closed {
                    initiator: Initiator::Peer,
                    ..
                }
            )
        })
    }));
    let summary = pair.server.recvs.last().expect("the receive of the close");
    assert!(
        summary.tls_due,
        "the host holds the server's state: {summary:?}"
    );
    assert_eq!(log.borrow().cancels, 1);
    let now = pair.now;
    let summary = pair.server.conn_mut().recv_batch(now, &mut []);
    assert!(!summary.tls_due, "the host has nothing left once cancelled");
}

#[test]
fn a_client_acknowledges_the_handshake_packets_its_hosts_step_opens_at_once() {
    const HOST: Duration = Duration::from_millis(50);
    let (epoch, mut pair) = external(&Setup::default(), &[Side::Client], HOST);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.conn().has_keys(Space::Handshake)
    }));
    assert!(buffered(&pair.client) > 0, "{:?}", pair.client.recvs);
    let client = pair.client.conn();
    assert!(
        client.tls.is_pending(),
        "the client's host has the server's Handshake flight"
    );
    assert!(
        !client.sources.ack[Space::Handshake.index()]
            .log
            .frames
            .is_empty(),
        "the client acknowledges the server's Handshake packets as soon as they are opened \
         (RFC 9000)"
    );
}

#[test]
fn a_servers_host_writes_a_ticket_once_complete_and_frees_its_state_once_confirmed() {
    let both = [Side::Server, Side::Client];
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &both, Duration::ZERO);
    handshake_and_transfer(epoch, &mut pair);
    let server = logs[0].borrow();
    assert_eq!(
        server.inputs.last_chunk(),
        Some(&["ticket", "finish"]),
        "{server:?}"
    );
    assert_eq!(server.connections, 0, "{server:?}");
}

#[test]
fn a_server_whose_host_answered_finish_leaves_it_nothing_to_cancel_at_close() {
    let both = [Side::Server, Side::Client];
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &both, Duration::ZERO);
    handshake_and_transfer(epoch, &mut pair);
    let log = logs[0].clone();
    assert_eq!(log.borrow().inputs.last(), Some(&"finish"));
    let now = pair.now;
    pair.client
        .conn_mut()
        .close(now, AppCode(VarInt::from_u32(0)), Bytes::new());
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.server.events.iter().any(|event| {
            matches!(
                event,
                ConnEvent::Closed {
                    initiator: Initiator::Peer,
                    ..
                }
            )
        })
    }));
    let summary = pair.server.recvs.last().expect("the receive of the close");
    assert!(
        !summary.tls_due,
        "the host freed the server's state when it answered Finish: {summary:?}"
    );
    assert_eq!(log.borrow().cancels, 0, "{:?}", log.borrow());
}

#[test]
fn a_closed_connection_hands_its_host_no_input() {
    let setup = Setup::default();
    let (_, client_tls) = setup.rustls();
    let epoch = crate::recovery::test_epoch();
    // Without a host, each connection keeps its first input: a client's Start, and a server's
    // ClientHello.
    let config = setup.pair_with(ServerTls::External, ClientTls::External);
    let mut pair = Pair::new(epoch, unix_now(), config);
    let client = pair.client.conn_mut();
    assert!(client.tls.has_tls_input(), "the client's Start waits");
    client.close(epoch, AppCode(VarInt::from_u32(1)), Bytes::new());
    assert!(client.tls_input().is_none(), "a closed client");
    assert!(!client.take_tls_cancel(), "the host never had the client");
    let config = setup.pair_with(ServerTls::External, ClientTls::Rustls(client_tls));
    let mut pair = Pair::new(epoch, unix_now(), config);
    assert!(pair.run_until(epoch + LIMIT, |pair| pair.server.conn.is_some()));
    let now = pair.now;
    let server = pair.server.conn_mut();
    assert!(server.tls.has_tls_input(), "the ClientHello waits");
    server.close(now, AppCode(VarInt::from_u32(1)), Bytes::new());
    assert!(server.tls_input().is_none(), "a closed server");
    assert!(!server.take_tls_cancel(), "the host never had the server");
}

#[test]
fn a_clients_host_reads_the_servers_tickets_and_keeps_its_state_until_close() {
    for external_sides in [&[Side::Client][..], &[Side::Server, Side::Client]] {
        let (epoch, mut pair, logs) = recorded(&Setup::default(), external_sides, Duration::ZERO);
        let log = logs.last().expect("the client's log").clone();
        handshake_and_transfer(epoch, &mut pair);
        // A server may send a ticket at any time after the client's Finished (RFC 8446), so the
        // client's host keeps its state past confirmation.
        {
            let log = log.borrow();
            assert!(
                log.inputs.contains(&"1-rtt crypto"),
                "{external_sides:?} external: {log:?}"
            );
            assert!(
                !log.inputs.contains(&"finish"),
                "{external_sides:?} external: {log:?}"
            );
            assert_eq!(log.connections, 1, "{external_sides:?} external: {log:?}");
        }
        let now = pair.now;
        pair.client
            .conn_mut()
            .close(now, AppCode(VarInt::from_u32(0)), Bytes::new());
        pair.step();
        let log = log.borrow();
        assert_eq!(
            (log.cancels, log.connections),
            (1, 0),
            "{external_sides:?} external: {log:?}"
        );
    }
}

#[test]
fn an_inline_server_frees_its_rustls_state_once_confirmed_and_a_client_keeps_it() {
    let (epoch, mut pair) = external(&Setup::default(), &[], Duration::ZERO);
    handshake_and_transfer(epoch, &mut pair);
    assert!(pair.server.conn().tls.rustls().is_none());
    assert!(
        pair.client.conn().tls.rustls().is_some(),
        "a client reads the tickets that come after confirmation"
    );
}

/// Returns the packets `peer` buffered until their keys arrived.
fn buffered(peer: &Peer) -> u32 {
    peer.recvs.iter().map(|summary| summary.buffered).sum()
}

#[test]
fn packets_that_wait_for_a_slow_host_are_replayed_as_its_step_arrives() {
    const HOST: Duration = Duration::from_millis(50);
    const LINK: Duration = Duration::from_millis(10);
    let both = [Side::Server, Side::Client];
    let (epoch, mut pair) = external(&Setup::default(), &both, HOST);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.client.has_event(&ConnEvent::Connected)
    }));
    // The client's host answers three inputs (Start, the ServerHello, the server's Handshake
    // flight) and the server's two in between (Start, the ClientHello), with two link crossings.
    assert_eq!(
        pair.now - epoch,
        5 * HOST + 2 * LINK,
        "the client's Handshake packets are opened as soon as their keys arrive"
    );
    assert!(buffered(&pair.client) > 0, "{:?}", pair.client.recvs);
    let (mut client, mut server) = (App::default(), App::default());
    let id = pair
        .client
        .conn_mut()
        .open_stream(Dir::Bi, ORDER)
        .expect("a stream opens");
    client.write(id, &b"early"[..], true);
    let complete = epoch + 6 * HOST + 3 * LINK;
    run_apps(
        &mut pair,
        complete - Duration::from_millis(1),
        &mut client,
        &mut server,
    );
    assert!(!pair.server.has_event(&ConnEvent::Connected));
    assert_eq!(server.data.get(&id), None);
    assert!(buffered(&pair.server) > 0, "{:?}", pair.server.recvs);
    run_apps(&mut pair, complete, &mut client, &mut server);
    assert!(pair.server.has_event(&ConnEvent::Confirmed));
    assert_eq!(
        server.data.get(&id).map(Vec::as_slice),
        Some(&b"early"[..]),
        "the client's 1-RTT packet is opened as soon as the server's handshake completes"
    );
}

#[test]
fn an_external_server_discards_its_handshake_keys_once_a_step_confirms_its_handshake() {
    // Without a buffer, the server drops the 1-RTT packet that comes with the client's Finished,
    // so a replayed packet does not follow the step that confirms its handshake.
    let setup = Setup {
        server_transport: config(|c| c.buffered_packets(0)),
        ..Setup::default()
    };
    let (epoch, mut pair) = external(&setup, &[Side::Server], Duration::ZERO);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.server.has_event(&ConnEvent::Confirmed)
    }));
    let server = pair.server.conn();
    assert!(server.spaces[Space::Initial.index()].discarded);
    assert!(
        server.spaces[Space::Handshake.index()].discarded,
        "a confirmed handshake discards its Handshake keys at once (RFC 9001)"
    );
}

#[test]
fn closing_while_the_host_works_cancels_its_work_and_refuses_its_step() {
    let latency = Duration::from_millis(50);
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &[Side::Server], latency);
    let log = logs[0].clone();
    assert!(
        pair.run_until(epoch + LIMIT, |_| log.borrow().inputs.contains(&"crypto")),
        "the server's host gets the ClientHello"
    );
    assert_eq!(log.borrow().connections, 1);
    let now = pair.now;
    let server = pair.server.conn_mut();
    assert!(server.tls.is_pending());
    server.close(now, AppCode(VarInt::from_u32(1)), Bytes::new());
    assert!(server.tls_input().is_none());
    assert_eq!(
        server.tls_deliver(now, TlsStep::default()),
        Err(TlsDeliverError::Closed)
    );
    pair.step();
    assert_eq!(log.borrow().cancels, 1);
    assert_eq!(log.borrow().connections, 0);
    pair.run(epoch + LIMIT);
    assert_eq!(log.borrow().cancels, 1, "cancelled once");
    assert!(!pair.server.has_event(&ConnEvent::WriteKeysReady));
}

#[test]
fn closing_after_the_host_answered_its_input_cancels_the_state_it_holds() {
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &[Side::Server], Duration::ZERO);
    let log = logs[0].clone();
    assert!(
        pair.run_until(epoch + LIMIT, |_| log.borrow().inputs.contains(&"crypto")),
        "the server's host answers the ClientHello"
    );
    let now = pair.now;
    let server = pair.server.conn_mut();
    assert!(!server.tls.is_pending());
    assert_eq!(log.borrow().connections, 1);
    server.close(now, AppCode(VarInt::from_u32(1)), Bytes::new());
    pair.step();
    let log = log.borrow();
    assert_eq!((log.cancels, log.connections), (1, 0), "{log:?}");
}

#[test]
fn closing_while_the_host_has_its_finish_input_cancels_it() {
    let latency = Duration::from_millis(50);
    let (epoch, mut pair, logs) = recorded(&Setup::default(), &[Side::Server], latency);
    let log = logs[0].clone();
    assert!(pair.run_until(epoch + LIMIT, |_| log.borrow().inputs.contains(&"finish")));
    let now = pair.now;
    let server = pair.server.conn_mut();
    assert!(server.tls.is_pending(), "the step for Finish is on its way");
    server.close(now, AppCode(VarInt::from_u32(1)), Bytes::new());
    pair.step();
    assert_eq!(log.borrow().cancels, 1, "{:?}", log.borrow());
}

#[test]
fn a_servers_timers_run_while_its_host_holds_the_client_hello() {
    let setup = Setup {
        server_transport: config(|c| c.idle_timeout(Some(Duration::from_secs(2)))),
        ..Setup::default()
    };
    let hour = Duration::from_secs(3600);
    let (epoch, mut pair, logs) = recorded(&setup, &[Side::Server], hour);
    pair.run(epoch + Duration::from_secs(60));
    assert_eq!(logs[0].borrow().inputs, ["start"]);
    assert!(
        !pair.server.sent.is_empty(),
        "the server acknowledges the client's Initials"
    );
    assert!(
        pair.server.has_event(&ConnEvent::Closed {
            reason: CloseReason::Silent,
            initiator: Initiator::IdleTimeout,
        }),
        "{:?}",
        pair.server.events
    );
    let log = logs[0].borrow();
    assert_eq!((log.cancels, log.connections), (1, 0), "{log:?}");
}

#[test]
fn timers_run_while_the_host_works_and_an_idle_timeout_cancels_its_work() {
    let setup = Setup {
        client_transport: config(|c| c.idle_timeout(Some(Duration::from_secs(2)))),
        ..Setup::default()
    };
    let hour = Duration::from_secs(3600);
    let (epoch, mut pair, logs) = recorded(&setup, &[Side::Client], hour);
    pair.run(epoch + LIMIT);
    assert_eq!(logs[0].borrow().inputs, ["start"]);
    assert!(
        pair.client.has_event(&ConnEvent::Closed {
            reason: CloseReason::Silent,
            initiator: Initiator::IdleTimeout,
        }),
        "{:?}",
        pair.client.events
    );
    assert_eq!(logs[0].borrow().cancels, 1);
    assert_eq!(logs[0].borrow().connections, 0);
}

/// The TLS handshake_failure alert (RFC 8446).
const HANDSHAKE_FAILURE: u8 = 40;

/// A server's host that refuses every ClientHello with a handshake_failure alert.
struct Refusing;

impl TlsHost for Refusing {
    fn handle(&mut self, _: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        TlsPoll::Ready(TlsStep {
            alert: matches!(input, TlsInput::Crypto { .. }).then_some(HANDSHAKE_FAILURE),
            ..TlsStep::default()
        })
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        None
    }

    fn cancel(&mut self, _: TlsConnId) {}
}

#[test]
fn a_host_alert_closes_the_connection_with_its_crypto_error() {
    let setup = Setup::default();
    let (_, client_tls) = setup.rustls();
    let epoch = crate::recovery::test_epoch();
    let config = setup.pair_with(ServerTls::External, ClientTls::Rustls(client_tls));
    let mut pair = Pair::new(epoch, unix_now(), config);
    pair.set_tls_host(Side::Server, Box::new(Refusing), Duration::ZERO);
    pair.run(epoch + LIMIT);
    let code = TransportErrorCode::crypto(HANDSHAKE_FAILURE);
    let reason = |initiator, reason: &'static [u8]| ConnEvent::Closed {
        reason: CloseReason::Transport {
            code,
            frame_type: None,
            reason: Bytes::from_static(reason),
        },
        initiator,
    };
    assert!(
        pair.server
            .has_event(&reason(Initiator::Local, b"TLS handshake failed")),
        "{:?}",
        pair.server.events
    );
    assert!(
        pair.client.events.iter().any(|event| matches!(
            event,
            ConnEvent::Closed {
                reason: CloseReason::Transport { code: got, .. },
                initiator: Initiator::Peer,
            } if *got == code
        )),
        "{:?}",
        pair.client.events
    );
}

/// A server's host that keeps the transport parameters of each Start input and never answers.
struct Capturing(Rc<RefCell<Vec<Vec<u8>>>>);

impl TlsHost for Capturing {
    fn handle(&mut self, _: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        if let TlsInput::Start {
            transport_params, ..
        } = input
        {
            self.0.borrow_mut().push(transport_params.to_vec());
        }
        TlsPoll::Pending
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        None
    }

    fn cancel(&mut self, _: TlsConnId) {}
}

/// Returns the ids of the transport parameters in `raw`, in order.
fn param_ids(raw: &[u8]) -> Vec<u64> {
    let mut ids = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let (id, len) = VarInt::decode(rest).unwrap();
        let (value_len, len_len) = VarInt::decode(&rest[len..]).unwrap();
        ids.push(id.into_inner());
        rest = &rest[len + len_len + usize::try_from(value_len.into_inner()).unwrap()..];
    }
    ids
}

#[test]
fn a_server_hands_its_host_the_parameters_in_its_configs_layout() {
    let mvfst = crate::TransportConfig::builder()
        .params_layout(crate::ParamsLayout::MvfstServer)
        .disable_active_migration(true)
        .build()
        .unwrap();
    for (version, ids) in [
        (
            mvfstr_wire::Version::V1,
            &[
                0x00, 0x05, 0x06, 0x07, 0x04, 0x08, 0x09, 0x01, 0x0a, 0x03, 0x0e, 0x02, 0x0c, 0x0f,
            ][..],
        ),
        (
            mvfstr_wire::Version::MVFST,
            &[
                0x05, 0x06, 0x07, 0x04, 0x08, 0x09, 0x01, 0x0a, 0x03, 0x0e, 0x02, 0x0c,
            ][..],
        ),
    ] {
        let setup = Setup {
            client_versions: vec![version],
            server_versions: if version == mvfstr_wire::Version::V1 {
                vec![version]
            } else {
                vec![mvfstr_wire::Version::V1, version]
            },
            server_transport: mvfst.clone(),
            ..Setup::default()
        };
        let (_, client_tls) = setup.rustls();
        let epoch = crate::recovery::test_epoch();
        let config = setup.pair_with(ServerTls::External, ClientTls::Rustls(client_tls));
        let mut pair = Pair::new(epoch, unix_now(), config);
        let starts = Rc::new(RefCell::new(Vec::new()));
        pair.set_tls_host(
            Side::Server,
            Box::new(Capturing(starts.clone())),
            Duration::ZERO,
        );
        pair.run(epoch + RTT);
        let starts = starts.borrow();
        assert_eq!(starts.len(), 1, "{version:?}");
        assert_eq!(param_ids(&starts[0]), ids, "{version:?}");
    }
}

#[test]
fn a_step_for_a_connection_that_waits_for_none_is_refused() {
    let hour = Duration::from_secs(3600);
    let (epoch, mut pair) = external(&Setup::default(), &[Side::Server], Duration::ZERO);
    let later = pair.now + hour;
    let client = pair.client.conn_mut();
    let before = client.now;
    assert_eq!(
        client.tls_deliver(later, TlsStep::default()),
        Err(TlsDeliverError::NotPending),
        "an inline client"
    );
    assert_eq!(
        client.now, before,
        "a refused step leaves the client's clock"
    );
    assert!(pair.handshake(epoch + LIMIT));
    let later = pair.now + hour;
    let server = pair.server.conn_mut();
    let before = server.now;
    assert_eq!(
        server.tls_deliver(later, TlsStep::default()),
        Err(TlsDeliverError::NotPending),
        "an External server whose host answered every input"
    );
    assert_eq!(
        server.now, before,
        "a refused step leaves the server's clock"
    );
}

#[test]
fn a_refused_step_says_why() {
    assert_eq!(
        TlsDeliverError::NotPending.to_string(),
        "the connection waits for no TLS step"
    );
    assert_eq!(
        TlsDeliverError::Closed.to_string(),
        "the connection is closed"
    );
}

/// A [`RustlsHost`] whose steps the function changes before the connection gets them.
struct Rewriting<F>(RustlsHost, F);

impl<F: FnMut(&mut TlsStep)> TlsHost for Rewriting<F> {
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        match self.0.handle(conn, input) {
            TlsPoll::Ready(mut step) => {
                (self.1)(&mut step);
                TlsPoll::Ready(step)
            }
            TlsPoll::Pending => TlsPoll::Pending,
        }
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        let (conn, mut step) = self.0.poll_ready()?;
        (self.1)(&mut step);
        Some((conn, step))
    }

    fn cancel(&mut self, conn: TlsConnId) {
        self.0.cancel(conn);
    }
}

/// A server's host that keeps its step for a CRYPTO input at `level` (the ClientHello at Initial,
/// the client's Finished at Handshake) in `held` instead of returning it, so that the test
/// delivers it.
struct Holding {
    inner: RustlsHost,
    level: Level,
    held: Rc<RefCell<Option<TlsStep>>>,
}

impl TlsHost for Holding {
    fn handle(&mut self, conn: TlsConnId, input: TlsInput<'_>) -> TlsPoll {
        let hold = matches!(&input, TlsInput::Crypto { level, .. } if *level == self.level);
        match self.inner.handle(conn, input) {
            TlsPoll::Ready(step) if hold => {
                *self.held.borrow_mut() = Some(step);
                TlsPoll::Pending
            }
            poll => poll,
        }
    }

    fn poll_ready(&mut self) -> Option<(TlsConnId, TlsStep)> {
        self.inner.poll_ready()
    }

    fn cancel(&mut self, conn: TlsConnId) {
        self.inner.cancel(conn);
    }
}

/// Starts a pair from `setup` with an External server whose host holds its step for the first
/// CRYPTO input at `level`, and runs it until the host has that input. Returns the step.
fn held_at(setup: &Setup, level: Level) -> (Instant, Pair, TlsStep) {
    let (server_tls, client_tls) = setup.rustls();
    let epoch = crate::recovery::test_epoch();
    let config = setup.pair_with(ServerTls::External, ClientTls::Rustls(client_tls));
    let mut pair = Pair::new(epoch, unix_now(), config);
    let held = Rc::new(RefCell::new(None));
    let host = Holding {
        inner: RustlsHost::server(server_tls),
        level,
        held: held.clone(),
    };
    pair.set_tls_host(Side::Server, Box::new(host), Duration::ZERO);
    assert!(pair.run_until(epoch + LIMIT, |_| held.borrow().is_some()));
    let step = held.borrow_mut().take().expect("the held step");
    (epoch, pair, step)
}

#[test]
fn a_step_whose_transport_parameters_fail_validation_closes_the_connection() {
    let (epoch, mut pair, mut step) = held_at(&Setup::default(), Level::Initial);
    assert!(
        step.peer_transport_params.is_some(),
        "the step for the ClientHello"
    );
    // Version 1 requires initial_source_connection_id (RFC 9000).
    step.peer_transport_params = Some(Vec::new());
    let now = pair.now;
    let server = pair.server.conn_mut();
    assert_eq!(server.tls_deliver(now, step), Ok(()));
    let events: Vec<_> = std::iter::from_fn(|| server.poll_event()).collect();
    let code = TransportErrorCode::TRANSPORT_PARAMETER_ERROR;
    let closed = ConnEvent::Closed {
        reason: CloseReason::Transport {
            code,
            frame_type: None,
            reason: Bytes::from_static(b"initial_source_connection_id mismatch"),
        },
        initiator: Initiator::Local,
    };
    assert!(
        events.contains(&closed),
        "the step closes the connection: {events:?}"
    );
    assert!(!events.contains(&ConnEvent::Connected));
    pair.run(epoch + LIMIT);
    assert!(
        pair.client.events.iter().any(|event| matches!(
            event,
            ConnEvent::Closed {
                reason: CloseReason::Transport { code: got, .. },
                initiator: Initiator::Peer,
            } if *got == code
        )),
        "{:?}",
        pair.client.events
    );
}

#[test]
fn a_client_opens_no_1rtt_packet_before_its_host_reports_success() {
    let setup = Setup::default();
    let (server_tls, client_tls) = setup.rustls();
    let epoch = crate::recovery::test_epoch();
    let config = setup.pair_with(ServerTls::Rustls(server_tls), ClientTls::External);
    let mut pair = Pair::new(epoch, unix_now(), config);
    // As a TLS stack may hand over the 1-RTT secrets before it completes (RFC 9001).
    let host = Rewriting(RustlsHost::client(client_tls), |step: &mut TlsStep| {
        step.handshake_success = false;
    });
    pair.set_tls_host(Side::Client, Box::new(host), Duration::ZERO);
    assert!(pair.run_until(epoch + LIMIT, |pair| {
        pair.server.has_event(&ConnEvent::Confirmed)
    }));
    pair.run(pair.now + 10 * RTT);
    let client = pair.client.conn();
    assert!(client.has_keys(Space::Data));
    assert!(
        client.sources.ack[Space::Data.index()]
            .log
            .received
            .is_empty(),
        "the client decrypts no 1-RTT packet before its handshake completes (RFC 9001): {:?}",
        pair.client.events
    );
    assert!(buffered(&pair.client) > 0, "{:?}", pair.client.recvs);
    assert!(!pair.client.has_event(&ConnEvent::Connected));
    assert!(!pair.client.has_event(&ConnEvent::Confirmed));
}

/// An External server whose host holds its step for the client's Finished, and what the step
/// will open.
struct Held {
    pair: Pair,
    step: TlsStep,
    /// A stream that sent 1,000 bytes of 0.5-RTT data and was refused the rest for want of
    /// stream credit.
    stream: StreamId,
    /// When the server buffered a client packet that acknowledges those bytes and grants the
    /// stream 3,000 more bytes of credit; it waits, since the handshake is not complete.
    at: Instant,
}

fn held_with_acks_and_credit() -> Held {
    let setup = Setup {
        client_transport: config(|c| c.max_stream_data_uni(1_000)),
        server_transport: config(|c| c.pacing(true)),
        ..Setup::default()
    };
    let (_, mut pair, step) = held_at(&setup, Level::Handshake);
    let server = pair.server.conn_mut();
    let stream = server
        .open_stream(Dir::Uni, ORDER)
        .expect("the client's transport parameters allow a stream");
    let mut data = Bytes::from(pattern(2_000));
    assert_eq!(server.stream(stream).unwrap().send(&mut data), Ok(1_000));
    pair.step();
    let sent = pair.server.conn().recovery.space(Space::Data).next_pn();
    assert!(sent > 0, "the server sends its 0.5-RTT data");
    let client = pair.client.conn();
    let frames = [Frame::MaxStreamData {
        id: stream,
        max: VarInt::from_u32(4_000),
    }];
    let pn = client.recovery.space(Space::Data).next_pn() + 10;
    let mut forge = Forge::of(client, Space::Data, pn, &frames);
    forge.ack = Some(0..=sent - 1);
    let packet = forge.seal(client);
    // Later than the server's samples so far, so the acknowledgment moves the smoothed RTT.
    let at = pair.now + Duration::from_millis(30);
    let src = pair.client.addr;
    let summary = deliver(pair.server.conn_mut(), at, src, packet);
    assert_eq!((summary.buffered, summary.packets), (1, 0));
    Held {
        pair,
        step,
        stream,
        at,
    }
}

#[test]
fn a_hosts_step_paces_at_the_rate_the_packets_it_opens_leave() {
    let Held {
        mut pair, step, at, ..
    } = held_with_acks_and_credit();
    let server = pair.server.conn_mut();
    let before = format!("{:?}", server.pacer);
    assert_eq!(server.tls_deliver(at, step), Ok(()));
    assert!(server.handshake.complete);
    let mut current = server.pacer.clone();
    current.set_rate(server.cc.pacing_rate(server.recovery.rtt().smoothed()));
    let current = format!("{current:?}");
    assert_ne!(
        current, before,
        "the acknowledgment the step opens moves the RTT and the window"
    );
    assert_eq!(
        format!("{:?}", server.pacer),
        current,
        "the pacer takes the rate before the next transmit attempt"
    );
}

#[test]
fn a_hosts_step_wakes_the_senders_the_credit_it_opens_unblocks() {
    let Held {
        mut pair,
        step,
        stream,
        at,
    } = held_with_acks_and_credit();
    let server = pair.server.conn_mut();
    assert_eq!(server.readiness().collect::<Vec<_>>(), []);
    assert_eq!(server.tls_deliver(at, step), Ok(()));
    assert_eq!(
        server.readiness().collect::<Vec<_>>(),
        [(stream, StreamReady::Writable)],
        "before the next transmit attempt"
    );
}

#[test]
fn a_hosts_step_moves_the_connection_clock_to_its_time() {
    let Held {
        mut pair, step, at, ..
    } = held_with_acks_and_credit();
    let later = at + Duration::from_millis(10);
    let server = pair.server.conn_mut();
    assert_eq!(server.tls_deliver(later, step), Ok(()));
    assert_eq!(server.now, later);
}
