/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What a session works through: the lent connection, the send sink and the cross-thread handle.

use std::fmt;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::task::Waker;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_proto::AppCode;
use mvfstr_proto::Connection;
use mvfstr_proto::SendError;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamMut;
use roxygen_runtime::worker::SubmitError;

use crate::wake;
use crate::wake::Command;
use crate::wake::ConnWake;

/// A connection lent to a session callback.
///
/// It dereferences to the [`Connection`]; mutable access marks the connection dirty, so the
/// driver makes a transmit attempt for it in the next transmit phase.
pub struct Conn<'a> {
    conn: &'a mut Connection,
    now: Instant,
    wake: &'a Arc<ConnWake>,
    dirty: &'a mut bool,
}

impl<'a> Conn<'a> {
    /// Lends `conn` for one callback at `now`; mutable access sets `dirty`.
    pub(crate) fn new(
        conn: &'a mut Connection,
        now: Instant,
        wake: &'a Arc<ConnWake>,
        dirty: &'a mut bool,
    ) -> Self {
        Self {
            conn,
            now,
            wake,
            dirty,
        }
    }
}

impl Conn<'_> {
    /// Returns the time the driver read when the current phase began.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Returns a waker that marks stream `id`'s producer ready, so the driver polls it while the
    /// stream has room. A new stream, or one whose `poll_send` returned `Pending`, waits for it.
    pub fn stream_waker(&self, id: StreamId) -> Waker {
        self.wake.stream_waker(id)
    }

    /// Returns a handle for reaching this connection from other tasks or threads.
    pub fn handle(&self) -> ConnHandle {
        ConnHandle::new(Arc::clone(self.wake))
    }
}

impl Deref for Conn<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl DerefMut for Conn<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        *self.dirty = true;
        self.conn
    }
}

impl fmt::Debug for Conn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

/// Where [`QuicSession::poll_send`](crate::QuicSession::poll_send) pushes a stream's data.
///
/// Bytes are stored as given in the transport's send buffer; the wire scheduler decides when they
/// leave. Pushing past the allowance fails without storing anything.
pub struct SendSink<'a> {
    stream: StreamMut<'a>,
    progressed: bool,
    /// Bytes stored through this sink.
    staged: u64,
}

impl<'a> SendSink<'a> {
    /// Creates a sink over `stream` for one `poll_send`.
    pub(crate) fn new(stream: StreamMut<'a>) -> Self {
        Self {
            stream,
            progressed: false,
            staged: 0,
        }
    }

    /// Returns whether any byte was stored or the stream finished through this sink.
    pub(crate) fn progressed(&self) -> bool {
        self.progressed
    }

    /// Returns the bytes stored through this sink.
    pub(crate) fn staged(&self) -> u64 {
        self.staged
    }

    /// Takes the stream off the pull-ready list until its stream waker fires.
    pub(crate) fn park_producer(&mut self) {
        self.stream.park_producer();
    }
}

impl SendSink<'_> {
    /// Returns how many bytes the stream accepts now.
    pub fn allowance(&self) -> usize {
        self.stream.send_capacity()
    }

    /// Stages all of `data`, or fails without staging any of it.
    pub fn push(&mut self, data: Bytes) -> Result<(), SinkError> {
        // An empty second part does not add bytes, and `send_parts` takes both parts or neither.
        self.push_parts(data, Bytes::new())
    }

    /// Stages a per-stream header and a shared payload as two entries, so the payload is not
    /// copied. It stages both or fails without staging either.
    pub fn push_parts(&mut self, header: Bytes, shared: Bytes) -> Result<(), SinkError> {
        let len = header.len() + shared.len();
        self.stream
            .send_parts(header, shared)
            .map_err(SinkError::from)?;
        self.progressed |= len > 0;
        self.staged += len as u64;
        Ok(())
    }

    /// Ends the stream after the staged bytes.
    pub fn finish(&mut self) -> Result<(), SinkError> {
        self.stream.finish().map_err(SinkError::from)?;
        self.progressed = true;
        Ok(())
    }
}

impl fmt::Debug for SendSink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendSink").finish_non_exhaustive()
    }
}

/// Why a [`SendSink`] refused data. The data was not stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// The data exceeds the allowance.
    OverAllowance,
    /// The stream's send half has ended, or the peer stopped it.
    Closed,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OverAllowance => "the data exceeds the stream's allowance",
            Self::Closed => "the stream's send half has ended",
        })
    }
}

impl std::error::Error for SinkError {}

impl From<SendError> for SinkError {
    fn from(error: SendError) -> Self {
        match error {
            SendError::OverAllowance => Self::OverAllowance,
            SendError::NoSendHalf | SendError::Ended | SendError::Stopped { .. } => Self::Closed,
        }
    }
}

/// A handle to a connection usable from any thread. Commands go through a bounded queue to the
/// connection's worker, and fail with [`SubmitError::Overloaded`] when it is full.
#[derive(Clone, Debug)]
pub struct ConnHandle {
    wake: Arc<ConnWake>,
}

impl ConnHandle {
    pub(crate) fn new(wake: Arc<ConnWake>) -> Self {
        Self { wake }
    }
}

impl ConnHandle {
    /// Wakes the session: the driver calls
    /// [`QuicSession::poll_session`](crate::QuicSession::poll_session) in its next application
    /// phase.
    pub fn wake(&self) -> Result<(), SubmitError> {
        if self.wake.is_closed() {
            return Err(SubmitError::Closed);
        }
        self.wake.wake(wake::APP);
        Ok(())
    }

    /// Closes the connection with an application CONNECTION_CLOSE.
    pub fn close(&self, code: AppCode, reason: Bytes) -> Result<(), SubmitError> {
        self.wake.submit(Command::Close { code, reason })
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::ConnKey;
    use mvfstr_proto::Dir;

    use super::*;
    use crate::test_support::ORDER;
    use crate::test_support::handshaken_pair;
    use crate::wake::Shared;

    const KEY: ConnKey = ConnKey {
        index: 0,
        generation: 0,
    };

    #[test]
    fn handles_cross_threads() {
        fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
        assert_send_sync_clone::<ConnHandle>();
    }

    #[test]
    fn a_lent_connection_is_dirtied_only_by_mutable_access_and_reaches_its_wakes() {
        let mut pair = handshaken_pair();
        let now = pair.now;
        let wake = ConnWake::new(Arc::new(Shared::default()), KEY);
        let mut dirty = false;

        {
            let conn = Conn::new(pair.client.conn_mut(), now, &wake, &mut dirty);
            assert_eq!(conn.now(), now);
            let _ = conn.stats();
            let _ = conn.remote_address();
        }
        assert!(!dirty, "reads leave the connection clean");

        let id = {
            let mut conn = Conn::new(pair.client.conn_mut(), now, &wake, &mut dirty);
            let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
            conn.handle().wake().expect("the connection is live");
            conn.stream_waker(id).wake();
            id
        };
        assert!(dirty, "opening a stream marks the connection dirty");
        assert_eq!(wake.take(), wake::APP | wake::STREAM);
        let mut streams = Vec::new();
        wake.take_streams(&mut streams);
        assert_eq!(streams, [id]);
    }

    #[test]
    fn a_send_sink_stores_all_or_nothing_and_reports_progress() {
        let mut pair = handshaken_pair();
        let conn = pair.client.conn_mut();
        let id = conn.open_stream(Dir::Bi, ORDER).expect("a stream opens");
        {
            let mut sink = SendSink::new(conn.stream(id).expect("the stream is open"));
            let allowance = sink.allowance();
            assert!(allowance > 100, "a new stream has an allowance");
            assert_eq!(
                sink.push(Bytes::from(vec![0; allowance + 1])),
                Err(SinkError::OverAllowance)
            );
            assert_eq!(
                sink.push_parts(Bytes::from_static(b"h"), Bytes::from(vec![0; allowance])),
                Err(SinkError::OverAllowance)
            );
            assert_eq!(sink.allowance(), allowance, "a refused push stores nothing");
            sink.push(Bytes::new()).expect("an empty push is accepted");
            assert!(!sink.progressed(), "an empty push is no progress");

            sink.push(Bytes::from_static(b"0123456789"))
                .expect("within the allowance");
            assert!(sink.progressed());
            assert!(sink.allowance() <= allowance - 10);
            sink.push_parts(Bytes::from_static(b"hd"), Bytes::from_static(b"payload"))
                .expect("within the allowance");
            sink.finish().expect("the stream finishes");
            assert_eq!(sink.push(Bytes::from_static(b"x")), Err(SinkError::Closed));
            assert_eq!(
                sink.push(Bytes::from(vec![0; allowance + 1])),
                Err(SinkError::Closed),
                "an ended stream reports Closed before the allowance"
            );
            assert_eq!(sink.push(Bytes::new()), Err(SinkError::Closed));
            assert_eq!(sink.finish(), Err(SinkError::Closed));
        }

        let id = conn.open_stream(Dir::Uni, ORDER).expect("a stream opens");
        let mut sink = SendSink::new(conn.stream(id).expect("the stream is open"));
        sink.finish().expect("the stream finishes");
        assert!(sink.progressed(), "a finish alone is progress");
    }

    #[test]
    fn a_handle_queues_closes_and_fails_once_its_connection_is_gone() {
        let wake = ConnWake::new(Arc::new(Shared::default()), KEY);
        let handle = ConnHandle::new(Arc::clone(&wake));
        handle
            .close(AppCode::from_u32(5), Bytes::from_static(b"bye"))
            .expect("the connection is live");
        assert_eq!(wake.take(), wake::CMD);
        let Some(Command::Close { code, reason }) = wake.take_command() else {
            panic!("the close is queued");
        };
        assert_eq!((code, &reason[..]), (AppCode::from_u32(5), &b"bye"[..]));

        wake.close();
        assert_eq!(handle.wake(), Err(SubmitError::Closed));
        assert_eq!(
            handle.close(AppCode::from_u32(6), Bytes::new()),
            Err(SubmitError::Closed)
        );
    }
}
