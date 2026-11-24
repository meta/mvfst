/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Stream state machines (RFC 9000).
//!
//! The send half (Ready, Send, Data Sent, Data Recvd, Reset Sent, Reset Recvd) and the receive
//! half (Recv, Size Known, Data Recvd, Data Read, Reset Recvd, Reset Read) are data-carrying enums,
//! with terminal-state detection for reaping.
//!
//! Events fall in two groups. Frames from the peer can arrive in any state, as RFC 9000 notes, so
//! [`RecvState::on_fin`] and [`RecvState::on_reset`] never fail: a late or repeated frame leaves
//! the state unchanged. Every other event is derived by the connection from its own state, so an
//! event the state does not permit returns [`InvalidTransition`] and leaves the state unchanged;
//! repeating an event in the state it leads to is [`Transition::Unchanged`].

use std::fmt;

use mvfstr_wire::Dir;
use mvfstr_wire::Side;
use mvfstr_wire::StreamId;

use crate::AppCode;

/// The outcome of an event: whether it moved a half to a new state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// The state changed.
    Moved,
    /// The event was a repeat or arrived late; the state is as before.
    Unchanged,
}

/// An event the current state does not permit. The state is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTransition {
    /// The state's name, as in RFC 9000.
    pub state: &'static str,
    /// The event's name.
    pub event: &'static str,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not permitted in {}", self.event, self.state)
    }
}

impl std::error::Error for InvalidTransition {}

/// The sending part of a stream (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendState {
    /// Created; data may be staged, and STREAM or STREAM_DATA_BLOCKED frames have not been sent.
    Ready,
    /// STREAM or STREAM_DATA_BLOCKED frames have been sent.
    Send,
    /// A STREAM frame with the FIN bit has been sent; only retransmissions remain.
    DataSent,
    /// Every byte and the FIN are acknowledged. Terminal.
    DataRecvd,
    /// A RESET_STREAM is pending or in flight.
    ResetSent {
        /// The application error code the RESET_STREAM carries.
        code: AppCode,
        /// The final size the RESET_STREAM carries, fixed when the stream was reset.
        final_size: u64,
    },
    /// A RESET_STREAM is acknowledged. Terminal.
    ResetRecvd {
        /// The application error code the RESET_STREAM carried.
        code: AppCode,
        /// The final size the RESET_STREAM carried.
        final_size: u64,
    },
}

impl SendState {
    /// Returns the state's name, as in RFC 9000.
    pub const fn name(&self) -> &'static str {
        match self {
            SendState::Ready => "Ready",
            SendState::Send => "Send",
            SendState::DataSent => "Data Sent",
            SendState::DataRecvd => "Data Recvd",
            SendState::ResetSent { .. } => "Reset Sent",
            SendState::ResetRecvd { .. } => "Reset Recvd",
        }
    }

    /// Records that a STREAM frame (with the FIN bit if `fin`) or a STREAM_DATA_BLOCKED frame
    /// (`fin` false) was sent. Retransmissions are permitted in Data Sent and leave the half there.
    pub fn on_sent(&mut self, fin: bool) -> Result<Transition, InvalidTransition> {
        match (*self, fin) {
            (SendState::Ready, false) => *self = SendState::Send,
            (SendState::Ready | SendState::Send, true) => *self = SendState::DataSent,
            (SendState::Send, false) | (SendState::DataSent, _) => {
                return Ok(Transition::Unchanged);
            }
            (
                SendState::DataRecvd | SendState::ResetSent { .. } | SendState::ResetRecvd { .. },
                _,
            ) => {
                return Err(self.invalid("on_sent"));
            }
        }
        Ok(Transition::Moved)
    }

    /// Records that every byte and the FIN are acknowledged.
    pub fn on_all_acked(&mut self) -> Result<Transition, InvalidTransition> {
        match self {
            SendState::DataSent => *self = SendState::DataRecvd,
            SendState::DataRecvd => return Ok(Transition::Unchanged),
            _ => return Err(self.invalid("on_all_acked")),
        }
        Ok(Transition::Moved)
    }

    /// Abandons the stream with a RESET_STREAM carrying `code` and `final_size`, after the
    /// application resets the stream or the peer sends STOP_SENDING.
    pub fn reset(
        &mut self,
        code: AppCode,
        final_size: u64,
    ) -> Result<Transition, InvalidTransition> {
        match self {
            SendState::Ready | SendState::Send | SendState::DataSent => {
                *self = SendState::ResetSent { code, final_size };
            }
            _ => return Err(self.invalid("reset")),
        }
        Ok(Transition::Moved)
    }

    /// Records that a packet carrying the RESET_STREAM was acknowledged.
    pub fn on_reset_acked(&mut self) -> Result<Transition, InvalidTransition> {
        match *self {
            SendState::ResetSent { code, final_size } => {
                *self = SendState::ResetRecvd { code, final_size };
            }
            SendState::ResetRecvd { .. } => return Ok(Transition::Unchanged),
            _ => return Err(self.invalid("on_reset_acked")),
        }
        Ok(Transition::Moved)
    }

    fn invalid(&self, event: &'static str) -> InvalidTransition {
        InvalidTransition {
            state: self.name(),
            event,
        }
    }

    /// Returns whether the half is in a terminal state (Data Recvd or Reset Recvd).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, SendState::DataRecvd | SendState::ResetRecvd { .. })
    }

    /// Returns whether STREAM frames, new or retransmitted, may be sent. RFC 9000 forbids them
    /// after RESET_STREAM and in a terminal state.
    pub const fn may_send_stream(&self) -> bool {
        matches!(
            self,
            SendState::Ready | SendState::Send | SendState::DataSent
        )
    }

    /// Returns whether bytes never sent before may still be sent: the FIN has not gone out and
    /// the stream is not reset.
    pub const fn takes_new_data(&self) -> bool {
        matches!(self, SendState::Ready | SendState::Send)
    }

    /// Returns whether STREAM_DATA_BLOCKED may be sent (RFC 9000: only before the FIN is sent).
    pub const fn may_send_data_blocked(&self) -> bool {
        matches!(self, SendState::Ready | SendState::Send)
    }
}

/// The receiving part of a stream (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvState {
    /// Receiving data; the final size is not known.
    Recv,
    /// A FIN arrived, so the final size is known; some bytes are missing.
    SizeKnown,
    /// Every byte up to the final size has arrived; the application has not read them all.
    DataRecvd,
    /// The application has read every byte. Terminal.
    DataRead,
    /// A RESET_STREAM arrived; the application has not been notified.
    ResetRecvd {
        /// The peer's application error code.
        code: AppCode,
        /// The final size the RESET_STREAM carried.
        final_size: u64,
    },
    /// The application has been notified of the reset. Terminal.
    ResetRead {
        /// The peer's application error code.
        code: AppCode,
        /// The final size the RESET_STREAM carried.
        final_size: u64,
    },
}

impl RecvState {
    /// Returns the state's name, as in RFC 9000.
    pub const fn name(&self) -> &'static str {
        match self {
            RecvState::Recv => "Recv",
            RecvState::SizeKnown => "Size Known",
            RecvState::DataRecvd => "Data Recvd",
            RecvState::DataRead => "Data Read",
            RecvState::ResetRecvd { .. } => "Reset Recvd",
            RecvState::ResetRead { .. } => "Reset Read",
        }
    }

    /// Records that a STREAM frame with the FIN bit arrived, so the final size is known. The
    /// receive buffer enforces the final size rules of RFC 9000.
    pub fn on_fin(&mut self) -> Transition {
        match self {
            RecvState::Recv => *self = RecvState::SizeKnown,
            _ => return Transition::Unchanged,
        }
        Transition::Moved
    }

    /// Records that every byte up to the final size has arrived.
    pub fn on_all_received(&mut self) -> Result<Transition, InvalidTransition> {
        match self {
            RecvState::SizeKnown => *self = RecvState::DataRecvd,
            RecvState::Recv => return Err(self.invalid("on_all_received")),
            // After a reset the remaining data may still arrive; delivery stays interrupted
            // (the optional Reset Recvd to Data Recvd edge of RFC 9000 is not taken).
            RecvState::DataRecvd
            | RecvState::DataRead
            | RecvState::ResetRecvd { .. }
            | RecvState::ResetRead { .. } => return Ok(Transition::Unchanged),
        }
        Ok(Transition::Moved)
    }

    /// Records that the application has read every byte up to the final size.
    pub fn on_data_read(&mut self) -> Result<Transition, InvalidTransition> {
        match self {
            RecvState::DataRecvd => *self = RecvState::DataRead,
            RecvState::DataRead => return Ok(Transition::Unchanged),
            _ => return Err(self.invalid("on_data_read")),
        }
        Ok(Transition::Moved)
    }

    /// Records that a RESET_STREAM carrying `code` and `final_size` arrived. The receive buffer
    /// enforces the final size rules of RFC 9000.
    pub fn on_reset(&mut self, code: AppCode, final_size: u64) -> Transition {
        match self {
            RecvState::Recv | RecvState::SizeKnown => {
                *self = RecvState::ResetRecvd { code, final_size };
            }
            _ => return Transition::Unchanged,
        }
        Transition::Moved
    }

    /// Records that the application has been notified of the reset.
    pub fn on_reset_read(&mut self) -> Result<Transition, InvalidTransition> {
        match *self {
            RecvState::ResetRecvd { code, final_size } => {
                *self = RecvState::ResetRead { code, final_size };
            }
            RecvState::ResetRead { .. } => return Ok(Transition::Unchanged),
            _ => return Err(self.invalid("on_reset_read")),
        }
        Ok(Transition::Moved)
    }

    fn invalid(&self, event: &'static str) -> InvalidTransition {
        InvalidTransition {
            state: self.name(),
            event,
        }
    }

    /// Returns whether the half is in a terminal state (Data Read or Reset Read).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, RecvState::DataRead | RecvState::ResetRead { .. })
    }

    /// Returns whether MAX_STREAM_DATA may be sent (RFC 9000: only in Recv).
    pub const fn may_send_max_stream_data(&self) -> bool {
        matches!(self, RecvState::Recv)
    }

    /// Returns whether STOP_SENDING is still useful (RFC 9000: in Recv or Size Known).
    pub const fn may_send_stop_sending(&self) -> bool {
        matches!(self, RecvState::Recv | RecvState::SizeKnown)
    }
}

/// Both halves of one stream; a half the stream does not have here is `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Halves {
    /// The sending part, absent on a unidirectional stream the peer opened.
    pub send: Option<SendState>,
    /// The receiving part, absent on a unidirectional stream this endpoint opened.
    pub recv: Option<RecvState>,
}

impl Halves {
    /// Creates the initial halves of stream `id` at the endpoint whose role is `side`.
    pub fn new(side: Side, id: StreamId) -> Self {
        let local = id.initiator() == side;
        let (sends, receives) = match id.dir() {
            Dir::Bi => (true, true),
            Dir::Uni => (local, !local),
        };
        Halves {
            send: sends.then_some(SendState::Ready),
            recv: receives.then_some(RecvState::Recv),
        }
    }

    /// Returns whether the stream is closed (RFC 9000): every half it has is terminal. A closed
    /// stream is reaped once its last readiness edge is delivered.
    pub fn is_closed(&self) -> bool {
        self.send.is_none_or(|s| s.is_terminal()) && self.recv.is_none_or(|r| r.is_terminal())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: AppCode = AppCode::from_u32(7);

    #[test]
    fn send_data_path_reaches_data_recvd() {
        let mut s = SendState::Ready;
        assert_eq!(s.on_sent(false), Ok(Transition::Moved));
        assert_eq!(s, SendState::Send);
        assert!(!s.is_terminal());
        assert_eq!(s.on_sent(false), Ok(Transition::Unchanged));
        assert_eq!(s.on_sent(true), Ok(Transition::Moved));
        assert_eq!(s, SendState::DataSent);
        assert!(!s.is_terminal());
        // Retransmissions, with or without the FIN, keep Data Sent.
        assert_eq!(s.on_sent(false), Ok(Transition::Unchanged));
        assert_eq!(s.on_sent(true), Ok(Transition::Unchanged));
        assert_eq!(s.on_all_acked(), Ok(Transition::Moved));
        assert_eq!(s, SendState::DataRecvd);
        assert!(s.is_terminal());
    }

    #[test]
    fn send_fin_in_the_first_frame_goes_straight_to_data_sent() {
        // Per RFC 9000, one STREAM frame with FIN moves Ready through Send to Data Sent.
        let mut s = SendState::Ready;
        assert_eq!(s.on_sent(true), Ok(Transition::Moved));
        assert_eq!(s, SendState::DataSent);
    }

    #[test]
    fn send_reset_from_every_open_state_ends_in_reset_recvd() {
        for start in [SendState::Ready, SendState::Send, SendState::DataSent] {
            let mut s = start;
            assert_eq!(s.reset(CODE, 10), Ok(Transition::Moved), "{start:?}");
            assert_eq!(
                s,
                SendState::ResetSent {
                    code: CODE,
                    final_size: 10
                }
            );
            assert!(!s.is_terminal());
            assert_eq!(s.on_reset_acked(), Ok(Transition::Moved), "{start:?}");
            assert_eq!(
                s,
                SendState::ResetRecvd {
                    code: CODE,
                    final_size: 10
                }
            );
            assert!(s.is_terminal(), "{start:?}");
        }
    }

    #[test]
    fn send_rejects_events_its_state_does_not_permit() {
        let reset_sent = SendState::ResetSent {
            code: CODE,
            final_size: 3,
        };
        let reset_recvd = SendState::ResetRecvd {
            code: CODE,
            final_size: 3,
        };
        type Event = fn(&mut SendState) -> Result<Transition, InvalidTransition>;
        let sent: Event = |s| s.on_sent(false);
        let sent_fin: Event = |s| s.on_sent(true);
        let acked: Event = |s| s.on_all_acked();
        let reset: Event = |s| s.reset(CODE, 5);
        let reset_acked: Event = |s| s.on_reset_acked();
        let cases: [(SendState, Event, &str); 14] = [
            // RFC 9000 forbids STREAM and STREAM_DATA_BLOCKED after RESET_STREAM and in a
            // terminal state.
            (SendState::DataRecvd, sent, "on_sent"),
            (SendState::DataRecvd, sent_fin, "on_sent"),
            (reset_sent, sent, "on_sent"),
            (reset_sent, sent_fin, "on_sent"),
            (reset_recvd, sent, "on_sent"),
            // Everything is acknowledged only after the FIN was sent.
            (SendState::Ready, acked, "on_all_acked"),
            (SendState::Send, acked, "on_all_acked"),
            (reset_sent, acked, "on_all_acked"),
            (reset_recvd, acked, "on_all_acked"),
            // A stream cannot be reset from a terminal state or reset twice (RFC 9000).
            (SendState::DataRecvd, reset, "reset"),
            (reset_sent, reset, "reset"),
            (reset_recvd, reset, "reset"),
            // A RESET_STREAM can be acknowledged only once sent.
            (SendState::Send, reset_acked, "on_reset_acked"),
            (SendState::DataRecvd, reset_acked, "on_reset_acked"),
        ];
        for (start, event, name) in cases {
            let mut s = start;
            assert_eq!(
                event(&mut s),
                Err(InvalidTransition {
                    state: start.name(),
                    event: name
                }),
                "{name} in {start:?}"
            );
            assert_eq!(s, start, "{name} in {start:?} changed the state");
        }
    }

    #[test]
    fn send_repeated_acknowledgements_change_nothing() {
        // An ACK for a retransmitted RESET_STREAM or a late ACK after Data Recvd.
        let mut s = SendState::DataRecvd;
        assert_eq!(s.on_all_acked(), Ok(Transition::Unchanged));
        assert_eq!(s, SendState::DataRecvd);
        let recvd = SendState::ResetRecvd {
            code: CODE,
            final_size: 0,
        };
        let mut s = recvd;
        assert_eq!(s.on_reset_acked(), Ok(Transition::Unchanged));
        assert_eq!(s, recvd);
    }

    #[test]
    fn recv_data_path_reaches_data_read() {
        let mut r = RecvState::Recv;
        assert_eq!(r.on_fin(), Transition::Moved);
        assert_eq!(r, RecvState::SizeKnown);
        assert!(!r.is_terminal());
        assert_eq!(r.on_all_received(), Ok(Transition::Moved));
        assert_eq!(r, RecvState::DataRecvd);
        assert!(!r.is_terminal());
        assert_eq!(r.on_data_read(), Ok(Transition::Moved));
        assert_eq!(r, RecvState::DataRead);
        assert!(r.is_terminal());
    }

    #[test]
    fn recv_reset_before_all_data_ends_in_reset_read() {
        for start in [RecvState::Recv, RecvState::SizeKnown] {
            let mut r = start;
            assert_eq!(r.on_reset(CODE, 9), Transition::Moved, "{start:?}");
            assert_eq!(
                r,
                RecvState::ResetRecvd {
                    code: CODE,
                    final_size: 9
                }
            );
            assert!(!r.is_terminal());
            assert_eq!(r.on_reset_read(), Ok(Transition::Moved), "{start:?}");
            assert_eq!(
                r,
                RecvState::ResetRead {
                    code: CODE,
                    final_size: 9
                }
            );
            assert!(r.is_terminal(), "{start:?}");
        }
    }

    #[test]
    fn recv_rejects_events_its_state_does_not_permit() {
        let reset_recvd = RecvState::ResetRecvd {
            code: CODE,
            final_size: 3,
        };
        let reset_read = RecvState::ResetRead {
            code: CODE,
            final_size: 3,
        };
        type Event = fn(&mut RecvState) -> Result<Transition, InvalidTransition>;
        let all_received: Event = |r| r.on_all_received();
        let data_read: Event = |r| r.on_data_read();
        let reset_read_event: Event = |r| r.on_reset_read();
        let cases: [(RecvState, Event, &str); 9] = [
            // All data can have arrived only once the final size is known.
            (RecvState::Recv, all_received, "on_all_received"),
            // The application reads everything only after everything arrived, and never after
            // a reset interrupted delivery.
            (RecvState::Recv, data_read, "on_data_read"),
            (RecvState::SizeKnown, data_read, "on_data_read"),
            (reset_recvd, data_read, "on_data_read"),
            (reset_read, data_read, "on_data_read"),
            // Only a received reset can be read.
            (RecvState::Recv, reset_read_event, "on_reset_read"),
            (RecvState::SizeKnown, reset_read_event, "on_reset_read"),
            (RecvState::DataRecvd, reset_read_event, "on_reset_read"),
            (RecvState::DataRead, reset_read_event, "on_reset_read"),
        ];
        for (start, event, name) in cases {
            let mut r = start;
            assert_eq!(
                event(&mut r),
                Err(InvalidTransition {
                    state: start.name(),
                    event: name
                }),
                "{name} in {start:?}"
            );
            assert_eq!(r, start, "{name} in {start:?} changed the state");
        }
    }

    #[test]
    fn recv_late_or_redundant_frames_change_nothing() {
        // STREAM and RESET_STREAM can arrive in any state. Once every byte has arrived a reset is
        // suppressed, as RFC 9000 allows, so the application still reads all the data.
        let reset_recvd = RecvState::ResetRecvd {
            code: CODE,
            final_size: 3,
        };
        let reset_read = RecvState::ResetRead {
            code: CODE,
            final_size: 3,
        };
        for start in [
            RecvState::DataRecvd,
            RecvState::DataRead,
            reset_recvd,
            reset_read,
        ] {
            let mut r = start;
            assert_eq!(r.on_fin(), Transition::Unchanged, "{start:?}");
            assert_eq!(r.on_reset(AppCode::from_u32(1), 3), Transition::Unchanged);
            assert_eq!(r, start);
        }
        let mut r = RecvState::SizeKnown;
        assert_eq!(r.on_fin(), Transition::Unchanged);
        assert_eq!(r, RecvState::SizeKnown);
    }

    #[test]
    fn frames_each_half_may_send_follow_rfc_9000() {
        let reset_sent = SendState::ResetSent {
            code: CODE,
            final_size: 0,
        };
        let reset_recvd = SendState::ResetRecvd {
            code: CODE,
            final_size: 0,
        };
        // (state, STREAM incl. retransmissions, new bytes, STREAM_DATA_BLOCKED)
        let send = [
            (SendState::Ready, true, true, true),
            (SendState::Send, true, true, true),
            (SendState::DataSent, true, false, false),
            (SendState::DataRecvd, false, false, false),
            (reset_sent, false, false, false),
            (reset_recvd, false, false, false),
        ];
        for (s, stream, new_data, blocked) in send {
            assert_eq!(s.may_send_stream(), stream, "{s:?}");
            assert_eq!(s.takes_new_data(), new_data, "{s:?}");
            assert_eq!(s.may_send_data_blocked(), blocked, "{s:?}");
        }
        let r_reset = RecvState::ResetRecvd {
            code: CODE,
            final_size: 0,
        };
        let r_read = RecvState::ResetRead {
            code: CODE,
            final_size: 0,
        };
        // (state, MAX_STREAM_DATA, STOP_SENDING)
        let recv = [
            (RecvState::Recv, true, true),
            (RecvState::SizeKnown, false, true),
            (RecvState::DataRecvd, false, false),
            (RecvState::DataRead, false, false),
            (r_reset, false, false),
            (r_read, false, false),
        ];
        for (r, max_stream_data, stop_sending) in recv {
            assert_eq!(r.may_send_max_stream_data(), max_stream_data, "{r:?}");
            assert_eq!(r.may_send_stop_sending(), stop_sending, "{r:?}");
        }
    }

    #[test]
    fn halves_follow_the_initiator_and_direction() {
        let both = Halves {
            send: Some(SendState::Ready),
            recv: Some(RecvState::Recv),
        };
        let send_only = Halves {
            send: Some(SendState::Ready),
            recv: None,
        };
        let recv_only = Halves {
            send: None,
            recv: Some(RecvState::Recv),
        };
        for side in [Side::Client, Side::Server] {
            let local = |dir| StreamId::new(side, dir, 4).unwrap();
            let peer = |dir| StreamId::new(side.peer(), dir, 4).unwrap();
            assert_eq!(Halves::new(side, local(Dir::Bi)), both, "{side:?}");
            assert_eq!(Halves::new(side, peer(Dir::Bi)), both, "{side:?}");
            assert_eq!(Halves::new(side, local(Dir::Uni)), send_only, "{side:?}");
            assert_eq!(Halves::new(side, peer(Dir::Uni)), recv_only, "{side:?}");
        }
    }

    #[test]
    fn a_stream_is_closed_once_every_half_it_has_is_terminal() {
        let read = RecvState::ResetRead {
            code: CODE,
            final_size: 0,
        };
        let cases = [
            (Some(SendState::Ready), Some(RecvState::Recv), false),
            (
                Some(SendState::DataRecvd),
                Some(RecvState::DataRecvd),
                false,
            ),
            (Some(SendState::DataSent), Some(RecvState::DataRead), false),
            (Some(SendState::DataRecvd), Some(RecvState::DataRead), true),
            (Some(SendState::DataRecvd), Some(read), true),
            (Some(SendState::Send), None, false),
            (Some(SendState::DataRecvd), None, true),
            (None, Some(RecvState::DataRecvd), false),
            (None, Some(read), true),
        ];
        for (send, recv, closed) in cases {
            assert_eq!(
                Halves { send, recv }.is_closed(),
                closed,
                "{send:?} {recv:?}"
            );
        }
    }
}
