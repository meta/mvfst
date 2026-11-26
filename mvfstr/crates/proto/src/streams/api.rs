/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The public stream API.
//!
//! Every method either succeeds or returns a typed error and leaves the connection unchanged;
//! misuse never closes the connection.

use std::fmt;

use bytes::Bytes;
use mvfstr_wire::StreamId;
use roxygen_bufqueue::BufQueue;

use super::prioritizer::MvfstOrder;
use super::prioritizer::Prioritizer;
use super::send_buf::SendBuffer;
use crate::AppCode;
use crate::Connection;
use crate::SendOrder;

/// Mutable access to one stream of a [`Connection`], from
/// [`Connection::stream`](crate::Connection::stream).
///
/// Dropping the handle recomputes the stream's membership in the connection's readiness,
/// pull and scheduling lists from its state.
pub struct StreamMut<'a, P: Prioritizer = MvfstOrder> {
    conn: &'a mut Connection<P>,
    id: StreamId,
}

impl<'a, P: Prioritizer> StreamMut<'a, P> {
    /// Returns the handle of open stream `id` of `conn`.
    pub(crate) fn new(conn: &'a mut Connection<P>, id: StreamId) -> Self {
        Self { conn, id }
    }
}

impl<P: Prioritizer> StreamMut<'_, P> {
    /// Returns the stream's ID.
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Returns the number of bytes the stream accepts now, its allowance: the smallest of its
    /// stream credit left beyond the staged (accepted but unsent) bytes, the per-stream cap on
    /// staged bytes, and its priority share of the connection's budget for staged bytes.
    pub fn send_capacity(&self) -> usize {
        usize::try_from(self.conn.stream_allowance(self.id)).unwrap_or(usize::MAX)
    }

    /// Takes the longest prefix of `data` the allowance accepts, leaving the rest in `data`, and
    /// returns its length. The bytes are stored as given, without copying.
    pub fn send(&mut self, data: &mut Bytes) -> Result<usize, SendError> {
        self.conn.stream_send(self.id, data)
    }

    /// Stages a per-stream `header` and a `shared` payload as two entries, so the payload is never
    /// copied. Takes both or neither: if together they exceed the allowance, returns
    /// [`SendError::OverAllowance`] without storing either.
    pub fn send_parts(&mut self, header: Bytes, shared: Bytes) -> Result<(), SendError> {
        self.conn.stream_send_parts(self.id, header, shared)
    }

    /// Ends the send half after the staged bytes (a FIN).
    pub fn finish(&mut self) -> Result<(), SendError> {
        self.conn.stream_finish(self.id)
    }

    /// Abandons the send half with RESET_STREAM carrying `code`; staged and lost bytes are
    /// discarded.
    pub fn reset(&mut self, code: AppCode) -> Result<(), SendError> {
        self.conn.stream_reset(self.id, code)
    }

    /// Returns the offset below which the peer has acknowledged every byte of the stream, or zero
    /// without a send half. Once the send half is reset, it is the final size.
    pub fn acked_end(&self) -> u64 {
        self.conn
            .stream_send_buf(self.id)
            .map_or(0, SendBuffer::acked_end)
    }

    /// Returns the offset after the highest byte sent on the stream, its flow-control usage, or
    /// zero without a send half.
    pub fn sent_end(&self) -> u64 {
        self.conn
            .stream_send_buf(self.id)
            .map_or(0, SendBuffer::sent_end)
    }

    /// Tracks `offset`, so that a [`StreamReady::Progress`](crate::StreamReady::Progress) edge is
    /// marked once the peer has acknowledged every byte below it. The FIN counts as the byte at
    /// the final size, so an offset past the final size is reached when every byte and the FIN
    /// are acknowledged, and not before. An offset reached already gives the edge at once. Each
    /// call replaces the offset tracked before, drops an undelivered edge for it, and gives at
    /// most one edge. A reset of the send half, by [`reset`](Self::reset) or the peer's
    /// STOP_SENDING, cancels the offset and drops an undelivered edge. After a reset, it fails
    /// with [`SendError::Stopped`] if the peer sent STOP_SENDING, or else with
    /// [`SendError::Ended`].
    pub fn track(&mut self, offset: u64) -> Result<(), SendError> {
        self.conn.stream_track(self.id, offset)
    }

    /// Moves the stream to a new place in the wire order.
    pub fn set_order(&mut self, order: SendOrder) {
        self.conn.stream_set_order(self.id, order);
    }

    /// Marks the stream's producer ready, as firing the stream's waker does: while the stream
    /// has room, it is on [`Connection::pull_ready`]. A new stream's producer is pending until
    /// this is called.
    pub fn wake_producer(&mut self) {
        self.conn.stream_set_producer_pending(self.id, false);
    }

    /// Marks the stream's producer pending, as `poll_send` returning `Pending` does: the stream
    /// leaves [`Connection::pull_ready`] until [`wake_producer`](Self::wake_producer) is called.
    pub fn park_producer(&mut self) {
        self.conn.stream_set_producer_pending(self.id, true);
    }

    /// Returns the in-order received bytes not yet consumed.
    pub fn readable(&self) -> &BufQueue {
        self.conn.stream_readable(self.id)
    }

    /// Returns whether the peer's FIN has arrived with every byte before it, readable or already
    /// consumed. It turns true before the `Finished` edge, which is delivered after the stream's
    /// `Opened` and `Readable` edges, so a reader of the last bytes can treat them as the last.
    /// False for a stream the peer reset first, and after [`stop_sending`](Self::stop_sending).
    pub fn peer_finished(&self) -> bool {
        self.conn.stream_peer_finished(self.id)
    }

    /// Consumes `n` readable bytes, returning their flow-control credit, and reports whether a
    /// MAX_STREAM_DATA or MAX_DATA update is now due, in which case the driver marks the
    /// connection for transmit. Consuming never re-reports the stream as readable.
    pub fn consume(&mut self, n: usize) -> Result<CreditDue, StreamError> {
        self.conn.stream_consume(self.id, n)
    }

    /// Sends STOP_SENDING carrying `code` and drops further ingress on the stream, releasing its
    /// unread bytes to the connection window.
    pub fn stop_sending(&mut self, code: AppCode) -> Result<(), StreamError> {
        self.conn.stream_stop_sending(self.id, code)
    }
}

impl<P: Prioritizer> fmt::Debug for StreamMut<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamMut")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Whether consuming bytes made a flow-control update due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditDue {
    /// An update is not due, so the driver need not mark the connection for transmit.
    NotDue,
    /// A MAX_STREAM_DATA or MAX_DATA update is due.
    Due,
}

/// Why [`Connection::open_stream`](crate::Connection::open_stream) failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The peer's stream limit for this direction is reached; a
    /// [`ConnEvent::StreamsAvailable`](crate::ConnEvent::StreamsAvailable) event follows when it
    /// rises.
    StreamLimit,
    /// The connection is closing, draining or closed, or `shutdown` was called.
    Closed,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StreamLimit => "the peer's stream limit is reached",
            Self::Closed => "the connection accepts no new streams",
        })
    }
}

impl std::error::Error for OpenError {}

/// Why a stream operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The stream does not exist: never opened, or reaped after both halves ended.
    Closed,
    /// The stream does not have a receive half here (a unidirectional stream we opened).
    NoReceiveHalf,
    /// More bytes were consumed than are readable.
    BeyondReadable,
    /// The receive half already ended or ingress was already stopped.
    ReceiveEnded,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "no such stream",
            Self::NoReceiveHalf => "the stream has no receive half",
            Self::BeyondReadable => "consumed more bytes than are readable",
            Self::ReceiveEnded => "the receive half already ended",
        })
    }
}

impl std::error::Error for StreamError {}

/// Why a send-half operation failed. The stream did not store any bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The stream does not have a send half here (a unidirectional stream the peer opened).
    NoSendHalf,
    /// The send half already ended with `finish` or `reset`.
    Ended,
    /// The peer asked us to stop with STOP_SENDING carrying this code.
    Stopped {
        /// The peer's application error code.
        code: AppCode,
    },
    /// The data exceeds the stream's allowance ([`StreamMut::send_capacity`]).
    OverAllowance,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSendHalf => f.write_str("the stream has no send half"),
            Self::Ended => f.write_str("the send half already ended"),
            Self::Stopped { code } => write!(f, "the peer sent STOP_SENDING with code {code}"),
            Self::OverAllowance => f.write_str("the data exceeds the stream's allowance"),
        }
    }
}

impl std::error::Error for SendError {}
