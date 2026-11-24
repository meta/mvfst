/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection, stream and endpoint events.
//!
//! The connection does not call back into the application. Stream readiness comes from intrusive
//! lists, drained through [`Connection::readiness`](crate::Connection::readiness) as
//! `(StreamId, StreamReady)` pairs and edge-triggered. Rare connection facts come from a fixed
//! ring through [`Connection::poll_event`](crate::Connection::poll_event), delivered exactly once
//! and in the same order for both roles, ending with `Closed` then `Drained`; kinds coalesce, so
//! the ring cannot overflow. Facts for the endpoint's routing table come through
//! [`Connection::poll_endpoint_event`](crate::Connection::poll_endpoint_event).

use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::ResetToken;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

/// An application protocol error code, carried by RESET_STREAM, STOP_SENDING and
/// CONNECTION_CLOSE of type 0x1d.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppCode(pub VarInt);

impl AppCode {
    /// Converts a `u32`, which always fits.
    pub const fn from_u32(code: u32) -> Self {
        AppCode(VarInt::from_u32(code))
    }
}

impl fmt::Display for AppCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0.into_inner())
    }
}

/// A rare fact about a connection, from [`Connection::poll_event`](crate::Connection::poll_event).
///
/// The QUIC DATAGRAM extension is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnEvent {
    /// The 1-RTT write keys are installed, so 1-RTT packets can be sent: for a server once it
    /// has written its handshake flight, before the client's Finished; for a client on rustls just
    /// before `Connected`, and for an External client with the step that carries its 1-RTT secrets.
    WriteKeysReady,
    /// A client resuming a session that allows early data holds 0-RTT keys: streams open and
    /// carry data before the handshake completes, within the limits the server remembered with
    /// the session. Queued by `Connection::client`, so it is the first event, ready before the
    /// first transmit attempt; at most once per connection.
    EarlyDataWritable,
    /// The server accepted or rejected the client's 0-RTT, just before `Connected`. On
    /// rejection every stream the client opened is gone without edges, as if never opened, and
    /// stream numbering starts over.
    EarlyData {
        /// Whether the server accepted the early data.
        accepted: bool,
    },
    /// The handshake completed: 1-RTT keys are installed and the peer's transport parameters
    /// validated.
    Connected,
    /// The handshake is confirmed (RFC 9001): HANDSHAKE_DONE sent (server) or received (client).
    Confirmed,
    /// The peer raised its stream limit for `dir`; `open_stream` may succeed again.
    StreamsAvailable {
        /// The direction whose limit rose.
        dir: Dir,
    },
    /// A path changed.
    Path(PathEvent),
    /// The connection does not have an open stream or a packet in flight.
    Quiet,
    /// The connection closed and does not carry streams or data any more. `Drained` follows once
    /// the closing or draining period ends.
    Closed {
        /// What was sent or received.
        reason: CloseReason,
        /// Who or what closed the connection.
        initiator: Initiator,
    },
    /// The connection has released its state and can be dropped. Always the last event.
    Drained,
}

/// A path change after the peer migrated (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathEvent {
    /// The peer's address changed and the new path was validated; packets now go to `remote`.
    Migrated {
        /// The peer's new address.
        remote: SocketAddr,
    },
    /// Validation of a new peer address failed; the connection stays on its previous path.
    ValidationFailed {
        /// The address that failed validation.
        remote: SocketAddr,
    },
}

/// What a closed connection exchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// A CONNECTION_CLOSE of type 0x1c.
    Transport {
        /// The transport error code.
        code: TransportErrorCode,
        /// The type of the frame that triggered the error, if known.
        frame_type: Option<VarInt>,
        /// The reason phrase.
        reason: Bytes,
    },
    /// A CONNECTION_CLOSE of type 0x1d.
    Application {
        /// The application error code.
        code: AppCode,
        /// The reason phrase.
        reason: Bytes,
    },
    /// The endpoints did not exchange CONNECTION_CLOSE: idle timeout, PTO limit, stateless reset
    /// or abort.
    Silent,
    /// The server answered the client's first Initial with a Version Negotiation packet that does
    /// not list any version the client offered.
    NoCommonVersion,
}

/// Who or what closed a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initiator {
    /// The local application (`close`, `abort`) or a protocol error we detected.
    Local,
    /// The peer, with a CONNECTION_CLOSE.
    Peer,
    /// The idle timeout expired.
    IdleTimeout,
    /// The peer sent a stateless reset.
    StatelessReset,
    /// The configured number of consecutive PTOs expired without an acknowledgment.
    PtoLimit,
    /// An internal failure, such as a contained panic.
    Internal,
}

/// A readiness edge of one stream, from [`Connection::readiness`](crate::Connection::readiness).
///
/// Readiness does not report stream deadlines, and RESET_STREAM_AT is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamReady {
    /// The peer opened the stream.
    Opened,
    /// New in-order bytes are readable.
    Readable,
    /// The peer's FIN arrived and every byte before it is readable.
    Finished,
    /// The stream's allowance rose to its low-water mark, for senders that push data.
    Writable,
    /// The peer acknowledged every byte below the offset given to
    /// [`StreamMut::track`](crate::StreamMut::track).
    Progress,
    /// Both halves are terminal; the stream is reaped after this edge.
    Closed,
    /// The peer sent STOP_SENDING.
    Stopped {
        /// The peer's application error code.
        code: AppCode,
    },
    /// The peer sent RESET_STREAM.
    Reset {
        /// The peer's application error code.
        code: AppCode,
        /// The stream's final size.
        final_size: u64,
    },
}

/// A change to the endpoint's routing table, from
/// [`Connection::poll_endpoint_event`](crate::Connection::poll_endpoint_event).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointEvent {
    /// Route a newly issued local connection ID to this connection, and answer unknown packets
    /// for it with this reset token once the connection is gone.
    NewLocalCid {
        /// The connection ID.
        cid: ConnectionId,
        /// Its stateless reset token.
        reset_token: ResetToken,
    },
    /// Stop routing a retired local connection ID.
    RetiredLocalCid {
        /// The connection ID.
        cid: ConnectionId,
    },
    /// The stateless reset tokens of the peer connection IDs the connection now sends with, each
    /// with the address it sends to under it, or `None` for a path without a token. Route
    /// datagrams from that address that end in the token to the connection, which checks for a
    /// stateless reset. They replace the previous ones.
    PeerResetTokens {
        /// The current path's address and token.
        current: Option<(SocketAddr, ResetToken)>,
        /// The alternate path's address and token, while there is one.
        alternate: Option<(SocketAddr, ResetToken)>,
    },
    /// The connection is drained; remove every route to it.
    Drained,
}
