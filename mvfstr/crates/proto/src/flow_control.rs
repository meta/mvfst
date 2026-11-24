/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection and stream flow control (RFC 9000).
//!
//! Send credit follows the peer's limits and records the limit at which sending blocked, for the
//! DATA_BLOCKED and STREAM_DATA_BLOCKED frames; retransmissions do not take new credit. Receive
//! windows follow mvfst's update rule (an update once more than half the window is consumed) and
//! autotune (doubling when updates come faster than 2 x SRTT, up to a configured maximum). Each
//! stream's final or highest offset counts toward the connection's receive usage once, and a reset
//! or STOP_SENDING returns the stream's unread bytes to the connection window. Connection credit
//! is checked when new stream bytes are written, so streams blocked on it are not kept in a list.

use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use crate::streams::CreditDue;

/// Send credit from one peer limit: MAX_DATA for the connection, MAX_STREAM_DATA for a stream.
/// `used` is the sum of the streams' highest sent offsets, or the stream's highest sent offset;
/// retransmissions do not take credit.
#[derive(Clone, Copy, Debug)]
pub struct SendCredit {
    limit: u64,
    used: u64,
    /// The limit at which a blocked frame last became due.
    blocked_at: Option<u64>,
}

impl SendCredit {
    /// Creates credit up to the peer's initial `limit`, from its transport parameters.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            blocked_at: None,
        }
    }

    /// Returns the peer's limit.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the credit taken so far.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Returns the credit left.
    pub fn available(&self) -> u64 {
        self.limit - self.used
    }

    /// Takes `n` bytes of credit for new bytes sent; `n` must not exceed
    /// [`available`](Self::available).
    pub fn consume(&mut self, n: u64) {
        debug_assert!(n <= self.available(), "sent past the peer's limit");
        self.used += n;
    }

    /// Returns the offset new bytes may reach: the smaller of this stream credit's limit and its
    /// offset plus the connection credit left. [`SendBuffer::emit`] takes it as `credit_end`.
    ///
    /// [`SendBuffer::emit`]: crate::streams::send_buf::SendBuffer::emit
    pub fn credit_end(&self, conn: &SendCredit) -> u64 {
        self.limit.min(self.used.saturating_add(conn.available()))
    }

    /// Records that bytes wait only for this credit. Returns the limit for a DATA_BLOCKED or
    /// STREAM_DATA_BLOCKED frame the first time the sender is blocked at that limit.
    pub fn note_blocked(&mut self) -> Option<u64> {
        if self.available() > 0 || self.blocked_at == Some(self.limit) {
            return None;
        }
        self.blocked_at = Some(self.limit);
        self.blocked_at
    }

    /// Clears the record that the sender was blocked at the current limit, so that the next
    /// [`note_blocked`](Self::note_blocked) reports it again: the bytes the blocked frame was for
    /// went away before it was sent.
    pub fn forget_blocked(&mut self) {
        self.blocked_at = None;
    }

    /// Returns whether a blocked frame reporting `limit` is still current: the sender is still
    /// at that limit. A lost blocked frame is resent only then.
    pub fn is_blocked_at(&self, limit: u64) -> bool {
        self.limit == limit && self.available() == 0
    }

    /// Takes a new limit from MAX_DATA or MAX_STREAM_DATA; returns whether it rose. A limit that
    /// does not rise is ignored, as RFC 9000 requires.
    pub fn on_max(&mut self, limit: u64) -> bool {
        if limit <= self.limit {
            return false;
        }
        self.limit = limit;
        true
    }
}

/// A receive window: the connection's (sums over its streams) or one stream's (offsets).
///
/// The update rule and autotune follow mvfst's, so an mvfst sender sees the same MAX_DATA cadence
/// from mvfstr as from mvfst.
#[derive(Clone, Debug)]
pub struct RecvWindow {
    /// The limit last advertised to the peer.
    advertised: u64,
    /// The highest limit the peer is sure to have: the initial one or the largest acknowledged one.
    delivered: u64,
    /// Bytes counted toward the limit: highest offsets and final sizes, each once.
    received: u64,
    /// Bytes consumed by the application or released by a reset or STOP_SENDING.
    consumed: u64,
    /// The window size: an update advertises `consumed + window`.
    window: u64,
    /// The ceiling for autotune; equal to `window` when autotune is off.
    max_window: u64,
    /// Whether an update is due and not yet sent.
    pending: bool,
    /// When the last update was sent.
    last_sent: Option<Instant>,
}

impl RecvWindow {
    /// Creates a window of `window` bytes, advertised in the transport parameters, that may
    /// autotune up to `autotune_max`.
    pub fn new(window: u64, autotune_max: Option<u64>) -> Self {
        Self {
            advertised: window,
            delivered: window,
            received: 0,
            consumed: 0,
            window,
            max_window: autotune_max.map_or(window, |max| max.max(window)),
            pending: false,
            last_sent: None,
        }
    }

    /// Returns the current window size.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Returns the limit last advertised to the peer.
    pub fn advertised(&self) -> u64 {
        self.advertised
    }

    /// Returns the bytes counted toward the limit.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Returns the bytes consumed or released.
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Returns whether an update is due and not yet sent.
    pub fn is_update_pending(&self) -> bool {
        self.pending
    }

    /// Returns the limit the next MAX_DATA or MAX_STREAM_DATA carries.
    pub fn next_limit(&self) -> u64 {
        self.advertised.max(self.target())
    }

    /// Counts `n` newly received bytes (growth of a highest offset, or the rest of a final size).
    /// Fails with [`FlowControlError`] if they would pass the advertised limit.
    pub fn on_received(&mut self, n: u64) -> Result<(), FlowControlError> {
        if !self.can_receive(n) {
            return Err(FlowControlError);
        }
        self.received += n;
        Ok(())
    }

    /// Records `n` bytes consumed by the application or released at `now`, and returns whether
    /// an update became due.
    pub fn on_consumed(&mut self, n: u64, now: Instant, srtt: Duration) -> CreditDue {
        self.consumed += n;
        debug_assert!(
            self.consumed <= self.received,
            "consumed bytes never received"
        );
        if self.pending || self.target() == self.advertised {
            return CreditDue::NotDue;
        }
        // An update is due once more than half the window is consumed.
        let remaining = self.advertised - self.consumed;
        if remaining > self.window || self.window - remaining <= self.window / 2 {
            return CreditDue::NotDue;
        }
        self.pending = true;
        self.autotune(now, srtt);
        CreditDue::Due
    }

    /// Records that an update carrying `limit` was sent at `now`.
    pub fn on_update_sent(&mut self, limit: u64, now: Instant) {
        self.advertised = self.advertised.max(limit);
        self.last_sent = Some(now);
        self.pending = false;
    }

    /// Records that an update carrying `limit` was lost; it is due again only if a larger limit
    /// has not been sent since and the peer does not have it from another copy.
    pub fn on_update_lost(&mut self, limit: u64) -> CreditDue {
        if limit < self.advertised || limit <= self.delivered || self.pending {
            return CreditDue::NotDue;
        }
        self.pending = true;
        CreditDue::Due
    }

    /// Records that an update carrying `limit` was acknowledged, possibly after its packet was
    /// declared lost. An update due again only to repeat what the peer now has stops being due.
    pub fn on_update_acked(&mut self, limit: u64) {
        self.delivered = self.delivered.max(limit);
        if self.pending && self.next_limit() <= self.delivered {
            self.pending = false;
        }
    }

    /// Takes a DATA_BLOCKED or STREAM_DATA_BLOCKED from the peer, which makes an update due
    /// whatever the consumption (as mvfst does).
    pub fn on_peer_blocked(&mut self) -> CreditDue {
        if self.pending {
            return CreditDue::NotDue;
        }
        self.pending = true;
        CreditDue::Due
    }

    fn can_receive(&self, n: u64) -> bool {
        n <= self.advertised - self.received
    }

    /// Returns `consumed + window`, capped at the largest varint.
    fn target(&self) -> u64 {
        self.consumed
            .saturating_add(self.window)
            .min(VarInt::MAX.into_inner())
    }

    /// Applies the autotune rule: an update needed less than 2 x SRTT after the previous one was
    /// sent doubles the window, up to the configured maximum. The doubling applies to the update
    /// being made due.
    fn autotune(&mut self, now: Instant, srtt: Duration) {
        let Some(last) = self.last_sent else {
            return;
        };
        if srtt.is_zero() || now <= last || now - last >= srtt.saturating_mul(2) {
            return;
        }
        self.window += self.window.min(self.max_window.saturating_sub(self.window));
    }
}

/// A stream's receive window together with the rules that tie it to the connection's: each
/// stream's highest offset, then its final size, counts toward the connection exactly once, and
/// unread bytes are released to the connection when the stream is reset or stopped.
///
/// Final sizes are checked by [`RecvBuffer`] first; this type only counts them.
///
/// [`RecvBuffer`]: crate::streams::recv_buf::RecvBuffer
#[derive(Clone, Debug)]
pub struct StreamRecvFlow {
    window: RecvWindow,
    /// Whether a reset or STOP_SENDING has discarded the stream: arriving bytes are released at
    /// once and MAX_STREAM_DATA is not sent.
    discarding: bool,
    /// Whether a FIN or RESET_STREAM gave the final size: MAX_STREAM_DATA is not sent (Size Known).
    final_known: bool,
}

impl StreamRecvFlow {
    /// Creates a stream receive window of `window` bytes that may autotune up to `autotune_max`.
    pub fn new(window: u64, autotune_max: Option<u64>) -> Self {
        Self {
            window: RecvWindow::new(window, autotune_max),
            discarding: false,
            final_known: false,
        }
    }

    /// Returns the stream's window.
    pub fn window(&self) -> &RecvWindow {
        &self.window
    }

    /// Returns whether a MAX_STREAM_DATA is due and not yet sent.
    pub fn wants_update(&self) -> bool {
        self.window.is_update_pending()
    }

    /// Takes a STREAM frame ending at offset `end` (with the FIN if `fin`): counts the growth of
    /// the highest offset toward both windows, after checking both limits.
    pub fn on_data(
        &mut self,
        conn: &mut RecvWindow,
        end: u64,
        fin: bool,
        now: Instant,
        srtt: Duration,
    ) -> Result<CreditDue, FlowControlError> {
        let grew = end.saturating_sub(self.window.received);
        self.count(conn, grew)?;
        if fin {
            self.final_known = true;
            self.window.pending = false;
        }
        if self.discarding {
            return Ok(self.release_unread(conn, now, srtt));
        }
        Ok(CreditDue::NotDue)
    }

    /// Records `n` bytes consumed by the application in both windows.
    pub fn on_consumed(
        &mut self,
        conn: &mut RecvWindow,
        n: u64,
        now: Instant,
        srtt: Duration,
    ) -> CreditDue {
        let stream = if self.sends_updates() {
            self.window.on_consumed(n, now, srtt)
        } else {
            self.window.consumed += n;
            CreditDue::NotDue
        };
        let conn = conn.on_consumed(n, now, srtt);
        either(stream, conn)
    }

    /// Takes a RESET_STREAM with `final_size`, already checked against the stream's received
    /// data: counts the rest of the final size toward both windows and releases every byte not
    /// yet consumed to the connection window.
    pub fn on_reset(
        &mut self,
        conn: &mut RecvWindow,
        final_size: u64,
        now: Instant,
        srtt: Duration,
    ) -> Result<CreditDue, FlowControlError> {
        let grew = final_size.saturating_sub(self.window.received);
        self.count(conn, grew)?;
        self.final_known = true;
        self.window.pending = false;
        self.discarding = true;
        Ok(self.release_unread(conn, now, srtt))
    }

    /// Stops reading (local STOP_SENDING): releases the unread bytes to the connection window,
    /// and every byte that arrives later as it arrives.
    pub fn stop(&mut self, conn: &mut RecvWindow, now: Instant, srtt: Duration) -> CreditDue {
        self.window.pending = false;
        self.discarding = true;
        self.release_unread(conn, now, srtt)
    }

    /// Records that a MAX_STREAM_DATA carrying `limit` was sent at `now`.
    pub fn on_update_sent(&mut self, limit: u64, now: Instant) {
        self.window.on_update_sent(limit, now);
    }

    /// Records that a MAX_STREAM_DATA carrying `limit` was acknowledged (see
    /// [`RecvWindow::on_update_acked`]).
    pub fn on_update_acked(&mut self, limit: u64) {
        self.window.on_update_acked(limit);
    }

    /// Records that a MAX_STREAM_DATA carrying `limit` was lost.
    pub fn on_update_lost(&mut self, limit: u64) -> CreditDue {
        if !self.sends_updates() {
            return CreditDue::NotDue;
        }
        self.window.on_update_lost(limit)
    }

    /// Takes a STREAM_DATA_BLOCKED from the peer.
    pub fn on_peer_blocked(&mut self) -> CreditDue {
        if !self.sends_updates() {
            return CreditDue::NotDue;
        }
        self.window.on_peer_blocked()
    }

    /// Returns whether MAX_STREAM_DATA may go out, which RFC 9000 allows only in the Recv state.
    fn sends_updates(&self) -> bool {
        !self.final_known && !self.discarding
    }

    /// Counts `n` more received bytes toward both windows, after checking both limits.
    fn count(&mut self, conn: &mut RecvWindow, n: u64) -> Result<(), FlowControlError> {
        if !self.window.can_receive(n) || !conn.can_receive(n) {
            return Err(FlowControlError);
        }
        self.window.received += n;
        conn.received += n;
        Ok(())
    }

    /// Releases the bytes received but not consumed to the connection window; the stream
    /// window takes them as consumed without sending updates.
    fn release_unread(&mut self, conn: &mut RecvWindow, now: Instant, srtt: Duration) -> CreditDue {
        let unread = self.window.received - self.window.consumed;
        if unread == 0 {
            return CreditDue::NotDue;
        }
        self.window.consumed += unread;
        conn.on_consumed(unread, now, srtt)
    }
}

fn either(a: CreditDue, b: CreditDue) -> CreditDue {
    if a == CreditDue::Due || b == CreditDue::Due {
        CreditDue::Due
    } else {
        CreditDue::NotDue
    }
}

/// The error when the peer sends past an advertised limit, which RFC 9000 forbids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowControlError;

impl FlowControlError {
    /// Returns the transport error code, FLOW_CONTROL_ERROR.
    pub fn code(self) -> TransportErrorCode {
        TransportErrorCode::FLOW_CONTROL_ERROR
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use bytes::Bytes;

    use super::*;
    use crate::streams::send_buf::FrameKind;
    use crate::streams::send_buf::FrameWriter;
    use crate::streams::send_buf::SendBuffer;

    /// Returns a base instant; only offsets from it matter.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests need one base instant and use only offsets from it"
    )]
    fn t0() -> Instant {
        Instant::now()
    }

    const SRTT: Duration = Duration::from_millis(10);

    #[test]
    fn send_credit_counts_down_and_only_rises() {
        let mut credit = SendCredit::new(100);
        assert_eq!(credit.available(), 100);
        credit.consume(60);
        assert_eq!((credit.used(), credit.available()), (60, 40));
        assert!(!credit.on_max(90), "a smaller limit is ignored");
        assert!(!credit.on_max(100), "an equal limit is ignored");
        assert_eq!(credit.limit(), 100);
        assert!(credit.on_max(150));
        assert_eq!((credit.limit(), credit.available()), (150, 90));
    }

    #[test]
    fn a_blocked_frame_is_owed_once_per_limit_while_at_the_limit() {
        let mut credit = SendCredit::new(100);
        assert_eq!(credit.note_blocked(), None, "credit is left");
        credit.consume(100);
        assert_eq!(credit.note_blocked(), Some(100));
        assert_eq!(credit.note_blocked(), None, "already owed at this limit");
        assert!(credit.is_blocked_at(100));
        credit.on_max(200);
        assert!(
            !credit.is_blocked_at(100),
            "the old frame is stale once the limit rises"
        );
        assert_eq!(credit.note_blocked(), None);
        credit.consume(100);
        assert_eq!(credit.note_blocked(), Some(200));
        assert!(credit.is_blocked_at(200));
    }

    #[test]
    fn new_bytes_may_go_up_to_the_smaller_of_stream_and_connection_credit() {
        let mut stream = SendCredit::new(100);
        stream.consume(30);
        let mut conn = SendCredit::new(1000);
        conn.consume(950);
        assert_eq!(stream.credit_end(&conn), 80);
        conn.on_max(2000);
        assert_eq!(stream.credit_end(&conn), 100);
    }

    #[test]
    fn receiving_past_the_advertised_limit_is_a_flow_control_error() {
        let mut win = RecvWindow::new(1000, None);
        assert_eq!(win.advertised(), 1000);
        win.on_received(600).unwrap();
        win.on_received(400).unwrap();
        assert_eq!(win.on_received(1), Err(FlowControlError));
        assert_eq!(win.received(), 1000, "a refused amount is not counted");
        assert_eq!(
            FlowControlError.code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }

    #[test]
    fn an_update_is_due_once_more_than_half_the_window_is_consumed() {
        let now = t0();
        let mut win = RecvWindow::new(1000, None);
        win.on_received(1000).unwrap();
        assert_eq!(
            win.on_consumed(500, now, SRTT),
            CreditDue::NotDue,
            "exactly half"
        );
        assert_eq!(win.on_consumed(1, now, SRTT), CreditDue::Due);
        assert_eq!(win.next_limit(), 1501);
        win.on_update_sent(1501, now);
        assert_eq!(win.advertised(), 1501);
        win.on_received(501).unwrap();
        assert_eq!(win.on_consumed(100, now, SRTT), CreditDue::NotDue);
        assert_eq!(win.on_consumed(401, now, SRTT), CreditDue::Due);
        assert_eq!(win.next_limit(), 2002);
    }

    #[test]
    fn a_pending_update_is_reported_once_and_carries_the_latest_limit() {
        let now = t0();
        let mut win = RecvWindow::new(1000, None);
        win.on_received(1000).unwrap();
        assert_eq!(win.on_consumed(600, now, SRTT), CreditDue::Due);
        assert!(win.is_update_pending());
        assert_eq!(win.on_consumed(100, now, SRTT), CreditDue::NotDue);
        assert_eq!(win.next_limit(), 1700);
        win.on_update_sent(win.next_limit(), now);
        assert!(!win.is_update_pending());
        assert_eq!(win.advertised(), 1700);
    }

    #[test]
    fn autotune_doubles_the_window_when_updates_come_within_two_srtt() {
        let t = t0();
        let ms = Duration::from_millis;
        let mut win = RecvWindow::new(1000, Some(8000));
        win.on_received(1000).unwrap();
        // The first update cannot be compared with a previous one.
        assert_eq!(win.on_consumed(501, t, SRTT), CreditDue::Due);
        assert_eq!(win.window(), 1000);
        win.on_update_sent(win.next_limit(), t);
        assert_eq!(win.advertised(), 1501);
        // Due again 15 ms later, under 2 x SRTT: the window doubles before the update.
        win.on_received(501).unwrap();
        assert_eq!(win.on_consumed(501, t + ms(15), SRTT), CreditDue::Due);
        assert_eq!(win.window(), 2000);
        assert_eq!(win.next_limit(), 1002 + 2000);
        win.on_update_sent(win.next_limit(), t + ms(15));
        // Due again 25 ms later, over 2 x SRTT: the window stays.
        win.on_received(1001).unwrap();
        assert_eq!(win.on_consumed(1001, t + ms(40), SRTT), CreditDue::Due);
        assert_eq!(win.window(), 2000);

        // Without an SRTT sample, or without autotune, the window stays.
        for (srtt, max) in [(Duration::ZERO, Some(8000)), (SRTT, None)] {
            let mut win = RecvWindow::new(1000, max);
            win.on_received(1000).unwrap();
            win.on_consumed(501, t, srtt);
            win.on_update_sent(win.next_limit(), t);
            win.on_received(501).unwrap();
            assert_eq!(win.on_consumed(501, t + ms(1), srtt), CreditDue::Due);
            assert_eq!(win.window(), 1000);
        }
    }

    #[test]
    fn autotune_trajectory_doubles_from_one_to_thirty_two_mib_and_stops() {
        // tperf's client: a 1 MiB connection window autotuned up to 32 MiB.
        const MIB: u64 = 1 << 20;
        let mut now = t0();
        let mut win = RecvWindow::new(MIB, Some(32 * MIB));
        let mut windows = Vec::new();
        for _ in 0..8 {
            // The sender fills the window; the reader consumes until an update is due.
            win.on_received(win.advertised() - win.received()).unwrap();
            let step = win.window() / 2 + 1;
            assert_eq!(win.on_consumed(step, now, SRTT), CreditDue::Due);
            windows.push(win.window() / MIB);
            win.on_update_sent(win.next_limit(), now);
            now += Duration::from_millis(5);
        }
        assert_eq!(windows, vec![1, 2, 4, 8, 16, 32, 32, 32]);
        assert_eq!(win.advertised(), win.consumed() + 32 * MIB);
    }

    #[test]
    fn a_lost_update_is_due_again_only_while_it_is_current() {
        let now = t0();
        let mut win = RecvWindow::new(1000, None);
        win.on_received(1000).unwrap();
        win.on_consumed(501, now, SRTT);
        win.on_update_sent(1501, now);
        assert_eq!(win.on_update_lost(1501), CreditDue::Due);
        assert!(win.is_update_pending());
        assert_eq!(win.next_limit(), 1501);
        win.on_update_sent(1501, now);
        win.on_received(501).unwrap();
        win.on_consumed(501, now, SRTT);
        win.on_update_sent(win.next_limit(), now);
        assert_eq!(
            win.on_update_lost(1501),
            CreditDue::NotDue,
            "a newer limit was sent"
        );
        assert!(!win.is_update_pending());
    }

    #[test]
    fn a_blocked_frame_from_the_peer_makes_an_update_due() {
        let now = t0();
        let mut win = RecvWindow::new(1000, None);
        win.on_received(1000).unwrap();
        win.on_consumed(100, now, SRTT);
        assert!(!win.is_update_pending());
        assert_eq!(win.on_peer_blocked(), CreditDue::Due);
        assert!(win.is_update_pending());
        assert_eq!(win.next_limit(), 1100);
        assert_eq!(win.on_peer_blocked(), CreditDue::NotDue, "already pending");
    }

    #[test]
    fn limits_stop_at_the_largest_varint() {
        let max = VarInt::MAX.into_inner();
        let now = t0();
        let window = max - 100;
        let mut win = RecvWindow::new(window, None);
        win.on_received(window).unwrap();
        assert_eq!(win.on_consumed(window / 2 + 1, now, SRTT), CreditDue::Due);
        assert_eq!(win.next_limit(), max);
        win.on_update_sent(max, now);
        win.on_received(100).unwrap();
        // A larger limit cannot be advertised, so an update is not due.
        assert_eq!(win.on_consumed(window / 2, now, SRTT), CreditDue::NotDue);
    }

    #[test]
    fn a_streams_highest_offset_counts_toward_the_connection_once() {
        let now = t0();
        let mut conn = RecvWindow::new(10_000, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 100, false, now, SRTT).unwrap();
        // A retransmission below the highest offset, then an out-of-order frame past it.
        stream.on_data(&mut conn, 50, false, now, SRTT).unwrap();
        stream.on_data(&mut conn, 300, false, now, SRTT).unwrap();
        stream.on_data(&mut conn, 200, false, now, SRTT).unwrap();
        assert_eq!(stream.window().received(), 300);
        assert_eq!(conn.received(), 300);
    }

    #[test]
    fn stream_and_connection_limits_are_both_enforced_before_counting() {
        let now = t0();
        let mut conn = RecvWindow::new(500, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        assert_eq!(
            stream.on_data(&mut conn, 600, false, now, SRTT),
            Err(FlowControlError),
            "past the connection limit"
        );
        assert_eq!((stream.window().received(), conn.received()), (0, 0));
        let mut conn = RecvWindow::new(5000, None);
        assert_eq!(
            stream.on_data(&mut conn, 1001, false, now, SRTT),
            Err(FlowControlError),
            "past the stream limit"
        );
        assert_eq!((stream.window().received(), conn.received()), (0, 0));
        stream.on_data(&mut conn, 1000, false, now, SRTT).unwrap();
    }

    #[test]
    fn consuming_stream_bytes_feeds_both_windows() {
        let now = t0();
        let mut conn = RecvWindow::new(4000, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 1000, false, now, SRTT).unwrap();
        assert_eq!(
            stream.on_consumed(&mut conn, 501, now, SRTT),
            CreditDue::Due
        );
        assert!(stream.wants_update());
        assert!(
            !conn.is_update_pending(),
            "the connection window is far from half"
        );
        assert_eq!(conn.consumed(), 501);
        assert_eq!(stream.window().next_limit(), 1501);

        let mut conn = RecvWindow::new(1000, None);
        let mut stream = StreamRecvFlow::new(4000, None);
        stream.on_data(&mut conn, 1000, false, now, SRTT).unwrap();
        assert_eq!(
            stream.on_consumed(&mut conn, 501, now, SRTT),
            CreditDue::Due
        );
        assert!(!stream.wants_update());
        assert!(conn.is_update_pending());
    }

    #[test]
    fn a_reset_counts_the_final_size_once_and_releases_unread_bytes() {
        let now = t0();
        let mut conn = RecvWindow::new(800, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 300, false, now, SRTT).unwrap();
        stream.on_consumed(&mut conn, 100, now, SRTT);
        // Final size 500: 200 more count once; 400 unread or unsent bytes are released.
        assert_eq!(
            stream.on_reset(&mut conn, 500, now, SRTT),
            Ok(CreditDue::Due)
        );
        assert_eq!((conn.received(), conn.consumed()), (500, 500));
        assert!(conn.is_update_pending());
        assert!(!stream.wants_update(), "no MAX_STREAM_DATA after a reset");
        // A retransmitted RESET_STREAM and late data leave the counts unchanged.
        assert_eq!(
            stream.on_reset(&mut conn, 500, now, SRTT),
            Ok(CreditDue::NotDue)
        );
        stream.on_data(&mut conn, 450, false, now, SRTT).unwrap();
        assert_eq!((conn.received(), conn.consumed()), (500, 500));
        // The open window is the advertised limit minus consumed-or-released bytes.
        assert_eq!(conn.next_limit() - conn.consumed(), 800);
        // A final size past either limit is a flow-control error.
        let mut stream = StreamRecvFlow::new(1000, None);
        assert_eq!(
            stream.on_reset(&mut conn, 1001, now, SRTT),
            Err(FlowControlError)
        );
    }

    #[test]
    fn stop_sending_releases_unread_bytes_and_every_later_byte() {
        let now = t0();
        let mut conn = RecvWindow::new(10_000, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 300, false, now, SRTT).unwrap();
        stream.on_consumed(&mut conn, 100, now, SRTT);
        stream.stop(&mut conn, now, SRTT);
        assert_eq!((conn.received(), conn.consumed()), (300, 300));
        // Bytes still in flight count toward flow control (RFC 9000) and are released at once.
        stream.on_data(&mut conn, 400, false, now, SRTT).unwrap();
        assert_eq!((conn.received(), conn.consumed()), (400, 400));
        // The reset's final size counts the rest once.
        stream.on_reset(&mut conn, 450, now, SRTT).unwrap();
        assert_eq!((conn.received(), conn.consumed()), (450, 450));
        assert!(!stream.wants_update());
    }

    #[test]
    fn no_stream_update_once_the_final_size_is_known() {
        let now = t0();
        let mut conn = RecvWindow::new(10_000, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 800, true, now, SRTT).unwrap();
        assert_eq!(
            stream.on_consumed(&mut conn, 600, now, SRTT),
            CreditDue::NotDue
        );
        assert!(!stream.wants_update());
        assert_eq!(conn.consumed(), 600);

        // An update already due is dropped when the FIN arrives (Size Known in RFC 9000).
        let mut stream = StreamRecvFlow::new(1000, None);
        let mut conn = RecvWindow::new(10_000, None);
        stream.on_data(&mut conn, 700, false, now, SRTT).unwrap();
        stream.on_consumed(&mut conn, 600, now, SRTT);
        assert!(stream.wants_update());
        stream.on_data(&mut conn, 900, true, now, SRTT).unwrap();
        assert!(!stream.wants_update());
    }

    #[test]
    fn stream_updates_are_sent_resent_and_forced_only_before_the_final_size() {
        let now = t0();
        let mut conn = RecvWindow::new(10_000, None);
        let mut stream = StreamRecvFlow::new(1000, None);
        stream.on_data(&mut conn, 1000, false, now, SRTT).unwrap();
        stream.on_consumed(&mut conn, 501, now, SRTT);
        let limit = stream.window().next_limit();
        stream.on_update_sent(limit, now);
        assert_eq!(stream.window().advertised(), 1501);
        assert_eq!(stream.on_update_lost(limit), CreditDue::Due);
        stream.on_update_sent(limit, now);
        assert_eq!(stream.on_peer_blocked(), CreditDue::Due);
        stream.on_update_sent(limit, now);

        stream.on_data(&mut conn, 1200, true, now, SRTT).unwrap();
        assert_eq!(stream.on_update_lost(limit), CreditDue::NotDue);
        assert_eq!(stream.on_peer_blocked(), CreditDue::NotDue);
        assert!(!stream.wants_update());
    }

    /// A writer with unbounded room for the composition test below.
    struct Sink(Vec<u8>);

    impl FrameWriter for Sink {
        fn remaining(&self) -> usize {
            usize::MAX - self.0.len()
        }

        fn put_slice(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }

        fn put_payload(&mut self, data: &Bytes, range: std::ops::Range<usize>) {
            self.0.extend_from_slice(&data[range]);
        }
    }

    #[test]
    fn only_new_bytes_take_stream_and_connection_credit() {
        let id = FrameKind::Stream(mvfstr_wire::StreamId::try_from(0).unwrap());
        let mut conn = SendCredit::new(150);
        let mut a = SendCredit::new(100);
        let mut b = SendCredit::new(100);
        let mut buf_a = SendBuffer::new();
        let mut buf_b = SendBuffer::new();
        buf_a.push(Bytes::from(vec![1u8; 200])).unwrap();
        buf_b.push(Bytes::from(vec![2u8; 200])).unwrap();
        let send = |buf: &mut SendBuffer, credit: &mut SendCredit, conn: &mut SendCredit| {
            let sent = buf.emit(id, &mut Sink(Vec::new()), 1500, credit.credit_end(conn))?;
            if !sent.retransmit {
                credit.consume(sent.len as u64);
                conn.consume(sent.len as u64);
            }
            Some(sent)
        };
        let first = send(&mut buf_a, &mut a, &mut conn).unwrap();
        assert_eq!(first.len, 100, "stream credit binds");
        assert_eq!(
            send(&mut buf_b, &mut b, &mut conn).unwrap().len,
            50,
            "connection credit binds"
        );
        assert_eq!(send(&mut buf_b, &mut b, &mut conn), None);
        assert_eq!(conn.note_blocked(), Some(150));
        // A retransmission is sent without credit and does not take any.
        buf_a.on_lost(first.offset, first.len, first.fin);
        let again = send(&mut buf_a, &mut a, &mut conn).unwrap();
        assert!(again.retransmit);
        assert_eq!((a.used(), b.used(), conn.used()), (100, 50, 150));
        assert_eq!(a.used() + b.used(), buf_a.sent_end() + buf_b.sent_end());
    }
}
