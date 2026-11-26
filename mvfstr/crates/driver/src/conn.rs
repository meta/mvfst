/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What a session works through: the lent connection, the send and datagram sinks and the
//! cross-thread handle.

use std::fmt;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::task::Waker;
use std::time::Instant;

use bytes::Bytes;
use mvfstr_proto::AppCode;
use mvfstr_proto::Connection;
use mvfstr_proto::DatagramError;
use mvfstr_proto::SendError;
use mvfstr_proto::SendOrder;
use mvfstr_proto::StreamId;
use mvfstr_proto::StreamMut;
use mvfstr_proto::datagram::datagram_frame_len;
use roxygen_runtime::worker::SubmitError;

use crate::wake;
use crate::wake::Close;
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

    /// Returns a waker that marks the session's datagram producer ready, so the driver polls
    /// [`QuicSession::poll_datagrams`](crate::QuicSession::poll_datagrams) while the connection
    /// has a datagram allowance. The producer waits for it at first and after it returns
    /// `Pending`.
    pub fn datagram_waker(&self) -> Waker {
        self.wake.waker(wake::DATAGRAM)
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

/// Where [`QuicSession::poll_datagrams`](crate::QuicSession::poll_datagrams) pushes datagrams.
///
/// A datagram's parts are queued as given, not copied, and copied once, into the packet that
/// carries it. A push stores the whole datagram or nothing.
pub struct DatagramSink<'a> {
    conn: &'a mut Connection,
    now: Instant,
    progressed: bool,
    /// Bytes stored through this sink.
    staged: u64,
    /// What is left of the connection's datagram allowance as the pull step began.
    left: usize,
}

impl<'a> DatagramSink<'a> {
    /// Creates a sink over `conn` for the polls of one pull step at `now`.
    pub(crate) fn new(conn: &'a mut Connection, now: Instant) -> Self {
        let left = conn.datagram_allowance();
        Self {
            conn,
            now,
            progressed: false,
            staged: 0,
            left,
        }
    }

    /// Returns whether a datagram was stored since the last call.
    pub(crate) fn take_progressed(&mut self) -> bool {
        mem::take(&mut self.progressed)
    }

    /// Returns the bytes stored through this sink.
    pub(crate) fn staged(&self) -> u64 {
        self.staged
    }

    /// Lowers what the sink takes to at most `most` bytes. Returns whether the connection's
    /// allowance left it more.
    pub(crate) fn limit(&mut self, most: usize) -> bool {
        let cut = self.left > most;
        self.left = self.left.min(most);
        cut
    }

    /// Returns whether the sink takes the frame of the longest datagram the connection takes.
    pub(crate) fn fits_longest(&self) -> bool {
        self.left >= datagram_frame_len(self.max_size())
    }
}

impl DatagramSink<'_> {
    /// Returns the time the driver read when the current phase began.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Returns how many bytes of datagrams the sink takes now, each counted with its frame's type
    /// and Length ([`datagram_frame_len`](mvfstr_proto::datagram::datagram_frame_len)): what the
    /// congestion window had left after the queued datagrams as the pull step began, at most what
    /// the driver lets the step stage of the connection's work for the turn, less what the sink
    /// has stored since. A datagram a full send queue drops does not give its bytes back.
    pub fn allowance(&self) -> usize {
        self.left
    }

    /// Returns the longest datagram the connection takes, or 0 while the peer does not take
    /// DATAGRAM frames with data.
    pub fn max_size(&self) -> usize {
        self.conn.max_datagram_size()
    }

    /// Queues a datagram whose data is `parts` in order, at most
    /// [`MAX_PARTS`](mvfstr_proto::datagram::MAX_PARTS), to be sent at `order` in the wire order
    /// and dropped unsent once `expiry` passes. It stores the whole datagram or fails without
    /// storing any of it.
    pub fn push_parts(
        &mut self,
        parts: &[Bytes],
        order: SendOrder,
        expiry: Option<Instant>,
    ) -> Result<(), DatagramError> {
        // The connection's clock may lag the driver's, which the producer reads.
        if expiry.is_some_and(|expiry| expiry <= self.now) {
            return Err(DatagramError::Expired);
        }
        let len: usize = parts.iter().map(Bytes::len).sum();
        let frame = datagram_frame_len(len);
        if frame > self.left {
            return Err(DatagramError::OverAllowance);
        }
        self.conn.send_datagram(parts, order, expiry)?;
        self.progressed = true;
        self.staged += len as u64;
        self.left -= frame;
        Ok(())
    }
}

impl fmt::Debug for DatagramSink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramSink").finish_non_exhaustive()
    }
}

/// A handle to a connection usable from any thread. Its calls fail with [`SubmitError::Closed`]
/// once the connection is gone.
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

    /// Closes the connection with an application CONNECTION_CLOSE. The first close wins: later
    /// ones succeed but do not change the connection.
    pub fn close(&self, code: AppCode, reason: Bytes) -> Result<(), SubmitError> {
        self.wake.submit(Close { code, reason })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mvfstr_proto::ConnKey;
    use mvfstr_proto::Dir;

    use super::*;
    use crate::test_support::ORDER;
    use crate::test_support::handshaken_datagram_pair;
    use crate::test_support::handshaken_datagram_pair_with;
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
            assert!(conn.latest_rtt() > Duration::ZERO);
            assert!(conn.openable_streams(Dir::Bi) > 0);
            assert!(conn.peer_transport_params().is_some());
            assert_eq!(conn.peer_max_datagram_frame_size(), 0);
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
    fn a_datagram_sink_stores_whole_datagrams_within_its_allowance() {
        let mut pair = handshaken_datagram_pair();
        let now = pair.now;
        let mut sink = DatagramSink::new(pair.client.conn_mut(), now);
        assert_eq!(sink.now(), now);
        let max = sink.max_size();
        let allowance = sink.allowance();
        assert!(
            max > 1000 && allowance > 2 * max,
            "the window holds a few datagrams"
        );

        let part = Bytes::from(vec![7; 100]);
        sink.push_parts(&[part.clone(), part], ORDER, None)
            .expect("within the allowance");
        assert!(sink.take_progressed());
        assert!(!sink.take_progressed(), "taking clears the progress");
        // The frame's type byte and 2-byte Length count too.
        assert_eq!(sink.allowance(), allowance - 203);
        assert_eq!(sink.staged(), 200);

        let full = Bytes::from(vec![1; max]);
        while sink.allowance() >= datagram_frame_len(max) {
            sink.push_parts(std::slice::from_ref(&full), ORDER, None)
                .expect("within the allowance");
        }
        let left = sink.allowance();
        let staged = sink.staged();
        sink.take_progressed();
        assert_eq!(
            sink.push_parts(&[Bytes::from(vec![2; left + 1])], ORDER, None),
            Err(DatagramError::OverAllowance)
        );
        assert_eq!(sink.allowance(), left, "a refused push stores nothing");
        assert_eq!(sink.staged(), staged);
        assert!(!sink.take_progressed());
    }

    #[test]
    fn a_datagram_sink_charges_each_push_its_frames_type_and_length() {
        let mut pair = handshaken_datagram_pair();
        let now = pair.now;
        let mut sink = DatagramSink::new(pair.client.conn_mut(), now);
        let max = sink.max_size();
        let full = Bytes::from(vec![1; max]);
        while sink.allowance() >= datagram_frame_len(max) {
            sink.push_parts(std::slice::from_ref(&full), ORDER, None)
                .expect("within the allowance");
        }
        // What is left takes a datagram whose frame fits it, not one whose data alone does.
        let left = sink.allowance();
        assert!(left > 3, "{left}");
        assert_eq!(
            sink.push_parts(&[Bytes::from(vec![2; left])], ORDER, None),
            Err(DatagramError::OverAllowance)
        );
        let fits = (0..left)
            .rev()
            .find(|&len| datagram_frame_len(len) <= left)
            .expect("a short datagram fits");
        sink.push_parts(&[Bytes::from(vec![2; fits])], ORDER, None)
            .expect("its frame fits the allowance");
        assert_eq!(sink.allowance(), left - datagram_frame_len(fits));
    }

    #[test]
    fn a_datagram_sinks_allowance_runs_out_though_a_short_send_queue_drops_its_oldest() {
        // A send queue of two drops its oldest datagram on each push past the second, so the
        // queued frames stay at two; the sink still takes no more than the allowance it began
        // with.
        let mut pair = handshaken_datagram_pair_with(|transport| transport.datagram_send_queue(2));
        let now = pair.now;
        let mut sink = DatagramSink::new(pair.client.conn_mut(), now);
        let allowance = sink.allowance();
        let data = Bytes::from(vec![7; 1000]);
        let frame = datagram_frame_len(1000);
        let mut pushed = 0;
        while sink.allowance() >= frame && pushed < 100 {
            sink.push_parts(std::slice::from_ref(&data), ORDER, None)
                .expect("within the allowance");
            pushed += 1;
        }
        assert_eq!(pushed, allowance / frame);
        assert_eq!(sink.allowance(), allowance % frame);
        assert_eq!(
            pair.client.conn().datagram_stats().send_dropped,
            pushed as u64 - 2
        );
    }

    #[test]
    fn a_datagram_sink_refuses_a_datagram_expired_by_the_drivers_clock() {
        let mut pair = handshaken_datagram_pair();
        // The driver read its clock after the connection's last operation.
        let now = pair.now + Duration::from_millis(10);
        let mut sink = DatagramSink::new(pair.client.conn_mut(), now);
        let allowance = sink.allowance();
        let data = [Bytes::from_static(b"stale")];
        for expiry in [now - Duration::from_millis(5), now] {
            assert_eq!(
                sink.push_parts(&data, ORDER, Some(expiry)),
                Err(DatagramError::Expired)
            );
        }
        assert_eq!(sink.allowance(), allowance, "nothing is queued");
        assert!(!sink.take_progressed());
        sink.push_parts(&data, ORDER, Some(now + Duration::from_millis(1)))
            .expect("a live datagram is queued");
        assert!(sink.take_progressed());
    }

    #[test]
    fn a_handle_submits_a_close_and_fails_once_its_connection_is_gone() {
        let wake = ConnWake::new(Arc::new(Shared::default()), KEY);
        let handle = ConnHandle::new(Arc::clone(&wake));
        handle
            .close(AppCode::from_u32(5), Bytes::from_static(b"bye"))
            .expect("the connection is live");
        assert_eq!(wake.take(), wake::CMD);
        let Some(Close { code, reason }) = wake.take_close() else {
            panic!("the close is pending");
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
