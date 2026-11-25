/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The application traits, and the router that serves several applications on one endpoint.

use std::cell::RefCell;
use std::fmt;
use std::mem;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_proto::ConnEvent;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamReady;
use mvfstr_proto::TransportErrorCode;
use mvfstr_proto::Version;

use crate::Conn;
use crate::DatagramSink;
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

    /// Produces datagrams into `sink` when the driver polls it, so they are made as the connection
    /// can send them rather than queued ahead. The producer is first polled once its datagram
    /// waker ([`Conn::datagram_waker`]) fires, and only while the connection has a datagram
    /// allowance. `Ready`: the producer has more to push; the driver polls it again while it
    /// pushes and the allowance lasts, within the connection's work for the turn, of which it
    /// leaves half to the connection's pull-ready streams. Otherwise the driver polls it in a
    /// later application phase that finds an allowance: the next turn's when the turn's work cut
    /// it short, also by leaving the sink less than the longest datagram's frame while it pushed
    /// nothing, or else the one after the connection's next receive or after a transmit attempt
    /// that sends a packet or drops expired datagrams. A `Ready` that pushes nothing while the
    /// sink takes the longest datagram is polled again in the connection's next application
    /// phase. `Pending`: the producer waits until the waker registered from `cx` fires.
    fn poll_datagrams(&mut self, _cx: &mut Context<'_>, _sink: &mut DatagramSink<'_>) -> Poll<()> {
        Poll::Pending
    }

    /// Runs session-level work when the session's own waker fires.
    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()>;

    /// Returns the time at which the driver should call `poll_session`, if any.
    fn deadline(&self) -> Option<Instant> {
        None
    }

    /// Handles a graceful shutdown of the driver; an HTTP/3 session sends GOAWAY here.
    fn on_quiesce(&mut self, _conn: &mut Conn<'_>) {}
}

/// Routes each accepted connection to one of two applications by the ALPN protocol that its
/// handshake negotiated, so that applications of several protocols share one endpoint and port.
///
/// The protocol is known only after the driver has called [`accept`](QuicApplication::accept), so
/// the router accepts every connection attempt as the server config sets it up. Once the handshake
/// completes, it calls the `accept` of the application whose protocols include the negotiated one,
/// the first application if both do. The options that this `accept` sets are not applied, as the
/// connection has its transport settings by then. The new session receives the events and stream
/// edges from before the handshake completed, in order, then `Connected`, then
/// [`on_quiesce`](QuicSession::on_quiesce) if the driver began a quiesce meanwhile, and its first
/// [`poll_session`](QuicSession::poll_session) in a later application phase. So it does not send
/// before the handshake completes.
///
/// An application's `accept` thus runs after a full handshake, and for a connection whose
/// handshake was running when a quiesce began, after the application's
/// [`quiesce`](QuicApplication::quiesce). Admission that must run before the handshake, such as a
/// filter on the client's address, belongs in an application that wraps the router.
///
/// A connection whose handshake did not negotiate a protocol, or negotiated one that is not in
/// either list, closes with CONNECTION_REFUSED, and so does one that its application refuses;
/// [`Refusal::Ignore`] ends it without a CONNECTION_CLOSE. For more than two applications, the
/// second application can be another router, listed with the protocols of all its applications.
pub struct AlpnRouter<A: QuicApplication, B: QuicApplication> {
    routes: Rc<RefCell<Routes<A, B>>>,
}

/// The applications of an [`AlpnRouter`], which its sessions share until they are routed.
struct Routes<A, B> {
    first: Route<A>,
    second: Route<B>,
}

/// An application and the ALPN protocols it serves.
struct Route<A> {
    protocols: Box<[Box<[u8]>]>,
    application: A,
}

impl<A> Route<A> {
    fn new<P: AsRef<[u8]>>(protocols: impl IntoIterator<Item = P>, application: A) -> Self {
        Self {
            protocols: protocols
                .into_iter()
                .map(|protocol| Box::from(protocol.as_ref()))
                .collect(),
            application,
        }
    }

    fn serves(&self, alpn: &[u8]) -> bool {
        self.protocols.iter().any(|protocol| **protocol == *alpn)
    }
}

impl<A: QuicApplication, B: QuicApplication> AlpnRouter<A, B> {
    /// Creates a router that gives the connections whose negotiated protocol is one of
    /// `first_protocols` to `first`, and those whose protocol is one of `second_protocols` to
    /// `second`.
    pub fn new<P: AsRef<[u8]>, Q: AsRef<[u8]>>(
        first_protocols: impl IntoIterator<Item = P>,
        first: A,
        second_protocols: impl IntoIterator<Item = Q>,
        second: B,
    ) -> Self {
        Self {
            routes: Rc::new(RefCell::new(Routes {
                first: Route::new(first_protocols, first),
                second: Route::new(second_protocols, second),
            })),
        }
    }
}

impl<A: QuicApplication, B: QuicApplication> fmt::Debug for AlpnRouter<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlpnRouter").finish_non_exhaustive()
    }
}

impl<A: QuicApplication, B: QuicApplication> QuicApplication for AlpnRouter<A, B> {
    type Session = AlpnSession<A, B>;

    fn accept(
        &mut self,
        info: &ConnInfo,
        _options: &mut ConnOptions,
    ) -> Result<AlpnSession<A, B>, Refusal> {
        Ok(AlpnSession {
            state: Routing::Pending(Pending {
                routes: Rc::clone(&self.routes),
                info: *info,
                early: Vec::new(),
                quiesced: false,
            }),
        })
    }

    fn quiesce(&mut self) {
        let mut routes = self.routes.borrow_mut();
        routes.first.application.quiesce();
        routes.second.application.quiesce();
    }
}

/// The session of a connection that an [`AlpnRouter`] serves. It keeps the connection's events
/// until the handshake completes, and from then on passes every call to the session of the
/// application that the connection was routed to.
pub struct AlpnSession<A: QuicApplication, B: QuicApplication> {
    state: Routing<A, B>,
}

/// Where an [`AlpnSession`] stands.
enum Routing<A: QuicApplication, B: QuicApplication> {
    /// The handshake has not completed.
    Pending(Pending<A, B>),
    /// Routed to the first application.
    First(A::Session),
    /// Routed to the second application.
    Second(B::Session),
    /// Turned away; the connection closes.
    Refused,
}

/// What a session that is not routed yet keeps.
struct Pending<A, B> {
    routes: Rc<RefCell<Routes<A, B>>>,
    /// The attempt as the router accepted it.
    info: ConnInfo,
    /// The events and stream edges delivered before the handshake completed, in order.
    early: Vec<Early>,
    /// Whether the session was quiesced.
    quiesced: bool,
}

/// A call that a session receives before it is routed, kept for the routed session.
enum Early {
    Event(ConnEvent),
    Stream(StreamId, StreamReady),
}

impl<A: QuicApplication, B: QuicApplication> Pending<A, B> {
    /// Calls the `accept` of the application that serves the ALPN protocol that the completed
    /// handshake negotiated, and returns the routed state. Closes the connection and returns
    /// `Refused` when the protocol is not in either list or the application refuses the
    /// connection.
    fn route(&self, conn: &mut Conn<'_>) -> Routing<A, B> {
        let mut routes = self.routes.borrow_mut();
        let mut options = ConnOptions::default();
        let routed = match conn.alpn() {
            Some(alpn) if routes.first.serves(alpn) => Some(
                routes
                    .first
                    .application
                    .accept(&self.info, &mut options)
                    .map(Routing::First),
            ),
            Some(alpn) if routes.second.serves(alpn) => Some(
                routes
                    .second
                    .application
                    .accept(&self.info, &mut options)
                    .map(Routing::Second),
            ),
            _ => None,
        };
        drop(routes);
        match routed {
            Some(Ok(state)) => return state,
            Some(Err(Refusal::Ignore)) => conn.abort(),
            Some(Err(Refusal::Refuse | Refusal::VersionNegotiation)) => {
                refuse(conn, "the application refused the connection")
            }
            None => refuse(
                conn,
                "the endpoint does not serve the negotiated ALPN protocol",
            ),
        }
        Routing::Refused
    }
}

impl<A: QuicApplication, B: QuicApplication> AlpnSession<A, B> {
    /// Returns a session that is routed to the first application from the start, as for a
    /// connection that the endpoint opens with
    /// [`EndpointHandle::connect`](crate::EndpointHandle::connect).
    pub fn first(session: A::Session) -> Self {
        Self {
            state: Routing::First(session),
        }
    }

    /// Returns a session that is routed to the second application from the start.
    pub fn second(session: B::Session) -> Self {
        Self {
            state: Routing::Second(session),
        }
    }

    /// Hands a session that was just routed the calls from before the handshake completed, then
    /// `Connected` and a quiesce that came meanwhile, and wakes it for its first poll. `Connected`
    /// is delivered after the replay even if a replayed callback closed the connection.
    fn start(&mut self, conn: &mut Conn<'_>, early: Vec<Early>, quiesced: bool) {
        if matches!(self.state, Routing::Refused) {
            return;
        }
        for call in early {
            match call {
                Early::Event(event) => self.on_event(conn, event),
                Early::Stream(id, ready) => self.on_stream(conn, id, ready),
            }
        }
        self.on_event(conn, ConnEvent::Connected);
        if quiesced {
            self.on_quiesce(conn);
        }
        // The driver polls a new session once; a routed one gets that poll in its next
        // application phase.
        let _ = conn.handle().wake();
    }
}

/// Closes a connection that the router turns away after its handshake with CONNECTION_REFUSED.
fn refuse(conn: &mut Conn<'_>, reason: &'static str) {
    let now = conn.now();
    conn.close_transport(
        now,
        TransportErrorCode::CONNECTION_REFUSED,
        Bytes::from_static(reason.as_bytes()),
    );
}

impl<A: QuicApplication, B: QuicApplication> fmt::Debug for AlpnSession<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.state {
            Routing::Pending(_) => "Pending",
            Routing::First(_) => "First",
            Routing::Second(_) => "Second",
            Routing::Refused => "Refused",
        };
        f.debug_struct("AlpnSession")
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

impl<A: QuicApplication, B: QuicApplication> QuicSession for AlpnSession<A, B> {
    fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
        match &mut self.state {
            Routing::Pending(pending) if event == ConnEvent::Connected => {
                let routed = pending.route(conn);
                let early = mem::take(&mut pending.early);
                let quiesced = pending.quiesced;
                self.state = routed;
                self.start(conn, early, quiesced);
            }
            Routing::Pending(pending) => pending.early.push(Early::Event(event)),
            Routing::Refused => {}
            Routing::First(session) => session.on_event(conn, event),
            Routing::Second(session) => session.on_event(conn, event),
        }
    }

    fn on_stream(&mut self, conn: &mut Conn<'_>, id: StreamId, ready: StreamReady) {
        match &mut self.state {
            Routing::First(session) => session.on_stream(conn, id, ready),
            Routing::Second(session) => session.on_stream(conn, id, ready),
            Routing::Pending(pending) => pending.early.push(Early::Stream(id, ready)),
            Routing::Refused => {}
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        id: StreamId,
        sink: &mut SendSink<'_>,
    ) -> Poll<()> {
        match &mut self.state {
            Routing::First(session) => session.poll_send(cx, id, sink),
            Routing::Second(session) => session.poll_send(cx, id, sink),
            Routing::Pending(_) | Routing::Refused => Poll::Pending,
        }
    }

    fn poll_datagrams(&mut self, cx: &mut Context<'_>, sink: &mut DatagramSink<'_>) -> Poll<()> {
        match &mut self.state {
            Routing::First(session) => session.poll_datagrams(cx, sink),
            Routing::Second(session) => session.poll_datagrams(cx, sink),
            Routing::Pending(_) | Routing::Refused => Poll::Pending,
        }
    }

    fn poll_session(&mut self, cx: &mut Context<'_>, conn: &mut Conn<'_>) -> Poll<()> {
        match &mut self.state {
            Routing::First(session) => session.poll_session(cx, conn),
            Routing::Second(session) => session.poll_session(cx, conn),
            Routing::Pending(_) | Routing::Refused => Poll::Pending,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match &self.state {
            Routing::First(session) => session.deadline(),
            Routing::Second(session) => session.deadline(),
            Routing::Pending(_) | Routing::Refused => None,
        }
    }

    fn on_quiesce(&mut self, conn: &mut Conn<'_>) {
        match &mut self.state {
            Routing::First(session) => session.on_quiesce(conn),
            Routing::Second(session) => session.on_quiesce(conn),
            Routing::Pending(pending) => pending.quiesced = true,
            Routing::Refused => {}
        }
    }
}
