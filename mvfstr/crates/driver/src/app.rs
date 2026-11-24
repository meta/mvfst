/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The application traits.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::Version;

use crate::Conn;
use crate::SendSink;

/// The facts about a connection attempt that the driver passes to [`QuicApplication::accept`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnInfo {
    /// The client's address.
    pub remote: SocketAddr,
    /// The local address the client's Initial was sent to, when the socket reports it.
    pub local_ip: Option<IpAddr>,
    /// The QUIC version the client offered.
    pub version: Version,
}

/// How the application turns down a connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Answer with CONNECTION_REFUSED.
    Refuse,
    /// Drop the Initial silently.
    Ignore,
    /// Answer with Version Negotiation that lists only
    /// [`MVFST_INVALID`](mvfstr_proto::MVFST_INVALID), so the client does not find a version in
    /// common and gives up.
    VersionNegotiation,
}

/// The application of one endpoint driver: it decides which connections to accept and creates
/// their sessions. It lives on the driver's worker and need not be `Send`.
pub trait QuicApplication: 'static {
    /// The per-connection state.
    type Session: QuicSession;

    /// Accepts a connection attempt, possibly adjusting its options, or refuses it.
    fn accept(
        &mut self,
        info: &ConnInfo,
        options: &mut ConnOptions,
    ) -> Result<Self::Session, Refusal>;

    /// Handles a graceful shutdown of the driver, which stops accepting connections and calls
    /// [`QuicSession::on_quiesce`] on each open one.
    fn quiesce(&mut self) {}
}

/// The application state of one connection.
///
/// The driver calls these methods only between transport operations, with the connection lent
/// through [`Conn`].
pub trait QuicSession: 'static {
    /// Handles a connection event; `Closed` and then `Drained` are the last.
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent);

    /// Handles a readiness edge of stream `id`.
    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady);

    /// Produces data for stream `id` into `sink` when the driver polls it. A stream is first polled
    /// once its stream waker ([`Conn::stream_waker`]) fires. `Ready`: at least one byte pushed or
    /// `finish` called; a `Ready` without progress is treated as `Pending`. `Pending`: the stream
    /// leaves the pull-ready list until the waker registered from `cx` (a stream waker) fires.
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()>;

    /// Runs session-level work when the session's own waker fires.
    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()>;

    /// Returns the time at which the driver should call `poll_session`, if any.
    fn deadline(&self) -> Option<Instant> {
        None
    }

    /// Handles a graceful shutdown of the driver; an HTTP/3 session sends GOAWAY here.
    fn on_quiesce(&mut self, _conn: &mut Conn<'_>) {}
}
