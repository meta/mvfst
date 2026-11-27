/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The admission table and the ranking of the limits that refuse candidates.
//!
//! A frame source's candidate has a [`Class`]; [`may_start`] decides whether it may start a
//! packet and [`may_join`] whether it may join one being built, both from the same [`Gate`].
//! A candidate that may not start names the limit that refused it. [`Blocked`] collects those
//! limits across candidates, and [`Blocked::stop`] picks the highest binding one.

use std::time::Instant;

use crate::transmit::Stop;

/// The class of a frame source's candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// Joins, never starts: an ACK that is not due.
    Piggyback,
    /// A PTO probe.
    Probe,
    /// PATH_RESPONSE or CONNECTION_CLOSE.
    Response,
    /// A due ACK.
    AckOnly,
    /// Retransmitted data.
    Lost,
    /// Control frames and new CRYPTO data.
    Control,
    /// A DATAGRAM frame.
    Datagram,
    /// New stream bytes, which also need connection credit.
    NewStream,
}

impl Class {
    /// Returns whether a packet started by this class takes the backend's urgent slot quota.
    pub(crate) fn is_urgent(self) -> bool {
        matches!(self, Class::AckOnly | Class::Probe | Class::Response)
    }

    /// Returns whether the frames of this class take pacing tokens.
    pub(crate) fn is_paced(self) -> bool {
        matches!(
            self,
            Class::Lost | Class::Control | Class::Datagram | Class::NewStream
        )
    }
}

/// The admission table's inputs: the state of a candidate's space, path and datagram.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Gate {
    /// Whether the space has its write key.
    pub(crate) keys: bool,
    /// The path's anti-amplification credit; `u64::MAX` once the path is validated.
    pub(crate) credit: u64,
    /// The size the datagram is charged if the candidate starts or joins it: 1,200 bytes when it
    /// then carries an ack-eliciting Initial, else what it must at least hold.
    pub(crate) datagram_size: u64,
    /// Probes due in the space.
    pub(crate) probes_due: u8,
    /// Bytes in flight.
    pub(crate) bytes_in_flight: u64,
    /// The congestion window.
    pub(crate) cwnd: u64,
    /// When an attempt can build the next paced run, if the pacer holds it now: its release
    /// less the build horizon.
    pub(crate) pacing: Option<Instant>,
    /// Connection flow control credit for new stream bytes.
    pub(crate) conn_credit: u64,
    /// Whether the egress grant has room for the datagram; data classes need it to start or join.
    pub(crate) grant: bool,
}

/// A limit that refuses a candidate's start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    /// The path's anti-amplification credit is short.
    Amplification,
    /// The space does not have a write key.
    KeysPending,
    /// The congestion window is full.
    Cwnd,
    /// The pacer holds the packet until this time, its release less the build horizon.
    Pacing(Instant),
    /// Connection credit for new stream bytes is used up.
    ConnFlowControl,
    /// The egress grant does not have room for the datagram.
    Endpoint,
}

/// Whether a candidate may start a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Start {
    /// It may.
    Yes,
    /// Its class never starts a packet, whatever the limits.
    Never,
    /// A limit refuses it.
    Blocked(Block),
}

/// Decides whether a candidate may start a packet: the "may start" column of the admission table.
pub(crate) fn may_start(class: Class, gate: &Gate) -> Start {
    if class == Class::Piggyback || (class == Class::Probe && gate.probes_due == 0) {
        return Start::Never;
    }
    if !gate.keys {
        return Start::Blocked(Block::KeysPending);
    }
    if gate.credit < gate.datagram_size {
        return Start::Blocked(Block::Amplification);
    }
    match class {
        Class::Piggyback | Class::Probe | Class::Response | Class::AckOnly => Start::Yes,
        Class::Lost | Class::Control | Class::Datagram | Class::NewStream => {
            if gate.bytes_in_flight >= gate.cwnd {
                return Start::Blocked(Block::Cwnd);
            }
            if let Some(release) = gate.pacing {
                return Start::Blocked(Block::Pacing(release));
            }
            if class == Class::NewStream && gate.conn_credit == 0 {
                return Start::Blocked(Block::ConnFlowControl);
            }
            // Only data starts wait for the grant; other starts are only charged to it.
            if !gate.grant {
                return Start::Blocked(Block::Endpoint);
            }
            Start::Yes
        }
    }
}

/// Decides whether a candidate may join the packet being built: the "may join" column of the
/// admission table. `probe_packet` is whether that packet is a probe, built because its space has
/// probes due; data may then pass the congestion window, which RFC 9002 does not let block a probe,
/// as well as pacing and the egress grant. Otherwise data joins only what its own start test would
/// admit, whatever started the datagram.
///
/// The amplification credit binds every class, since every byte sent before validation is
/// charged to the path: a joiner that would make the datagram an ack-eliciting Initial needs the
/// credit for the 1,200 bytes such a datagram takes at least.
pub(crate) fn may_join(class: Class, gate: &Gate, probe_packet: bool) -> bool {
    if !gate.keys || gate.credit < gate.datagram_size {
        return false;
    }
    let passes = || may_start(class, gate) == Start::Yes;
    match class {
        Class::Piggyback | Class::Probe | Class::Response | Class::AckOnly => true,
        Class::Lost | Class::Control | Class::Datagram => probe_packet || passes(),
        Class::NewStream => gate.conn_credit > 0 && (probe_packet || passes()),
    }
}

/// The limits that refused candidates during one scan of the frame sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Blocked {
    amplification: bool,
    keys_pending: bool,
    cwnd: bool,
    pacing: Option<Instant>,
    conn_flow_control: bool,
    endpoint: bool,
}

impl Blocked {
    /// Records that `block` refused a candidate.
    pub(crate) fn note(&mut self, block: Block) {
        match block {
            Block::Amplification => self.amplification = true,
            Block::KeysPending => self.keys_pending = true,
            Block::Cwnd => self.cwnd = true,
            Block::Pacing(at) => self.pacing = Some(self.pacing.map_or(at, |t| t.min(at))),
            Block::ConnFlowControl => self.conn_flow_control = true,
            Block::Endpoint => self.endpoint = true,
        }
    }

    /// Returns the highest binding limit: Endpoint, then Amplification, KeysPending, Cwnd, Pacing
    /// and ConnFlowControl, or `None` if [`note`](Self::note) was not called. Endpoint comes first
    /// because only its wake, the next grant, retries the slot without new input.
    pub(crate) fn stop(&self) -> Option<Stop> {
        if self.endpoint {
            Some(Stop::Endpoint)
        } else if self.amplification {
            Some(Stop::Amplification)
        } else if self.keys_pending {
            Some(Stop::KeysPending)
        } else if self.cwnd {
            Some(Stop::Cwnd)
        } else if let Some(at) = self.pacing {
            Some(Stop::Pacing(at))
        } else if self.conn_flow_control {
            Some(Stop::ConnFlowControl)
        } else {
            None
        }
    }

    /// Returns when an attempt can next build a pacing-blocked candidate, whatever the stop.
    pub(crate) fn pacing_at(&self) -> Option<Instant> {
        self.pacing
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::recovery::test_epoch;

    /// Returns a gate that admits everything: keys, credit, room in the window and a ready pacer.
    fn open() -> Gate {
        Gate {
            keys: true,
            credit: u64::MAX,
            datagram_size: 1200,
            probes_due: 0,
            bytes_in_flight: 0,
            cwnd: 12_000,
            pacing: None,
            conn_credit: 1 << 20,
            grant: true,
        }
    }

    #[test]
    fn piggyback_joins_but_never_starts() {
        let gate = open();
        assert_eq!(may_start(Class::Piggyback, &gate), Start::Never);
        assert!(may_join(Class::Piggyback, &gate, false));
        let full = Gate {
            bytes_in_flight: 12_000,
            ..gate
        };
        assert!(
            may_join(Class::Piggyback, &full, false),
            "a piggybacked ACK ignores cwnd"
        );
    }

    #[test]
    fn probes_start_only_when_due_and_ignore_cwnd_and_pacing() {
        let held = Gate {
            bytes_in_flight: 20_000,
            pacing: Some(test_epoch() + Duration::from_millis(5)),
            ..open()
        };
        assert_eq!(may_start(Class::Probe, &held), Start::Never);
        let due = Gate {
            probes_due: 1,
            ..held
        };
        assert_eq!(may_start(Class::Probe, &due), Start::Yes);
    }

    #[test]
    fn responses_and_due_acks_need_only_keys_and_credit() {
        let full = Gate {
            bytes_in_flight: 20_000,
            ..open()
        };
        for class in [Class::Response, Class::AckOnly] {
            assert_eq!(may_start(class, &full), Start::Yes);
            let short = Gate {
                credit: 1199,
                ..full
            };
            assert_eq!(
                may_start(class, &short),
                Start::Blocked(Block::Amplification)
            );
            let keyless = Gate {
                keys: false,
                ..full
            };
            assert_eq!(
                may_start(class, &keyless),
                Start::Blocked(Block::KeysPending)
            );
        }
    }

    #[test]
    fn data_classes_need_cwnd_and_the_pacer() {
        let gate = open();
        for class in [Class::Lost, Class::Control] {
            assert_eq!(may_start(class, &gate), Start::Yes);
            let full = Gate {
                bytes_in_flight: 12_000,
                ..gate
            };
            assert_eq!(may_start(class, &full), Start::Blocked(Block::Cwnd));
            assert!(!may_join(class, &full, false));
            assert!(
                may_join(class, &full, true),
                "a probe packet carries data past cwnd"
            );
            let at = test_epoch() + Duration::from_millis(1);
            let paced = Gate {
                pacing: Some(at),
                ..gate
            };
            assert_eq!(may_start(class, &paced), Start::Blocked(Block::Pacing(at)));
        }
    }

    #[test]
    fn new_stream_bytes_also_need_connection_credit() {
        let dry = Gate {
            conn_credit: 0,
            ..open()
        };
        assert_eq!(
            may_start(Class::NewStream, &dry),
            Start::Blocked(Block::ConnFlowControl)
        );
        assert!(!may_join(Class::NewStream, &dry, true));
        assert_eq!(may_start(Class::NewStream, &open()), Start::Yes);
    }

    #[test]
    fn data_joins_only_with_grant_left_unless_the_packet_is_a_probe() {
        let spent = Gate {
            grant: false,
            ..open()
        };
        for class in [Class::Lost, Class::Control, Class::NewStream] {
            assert!(!may_join(class, &spent, false), "{class:?}");
            assert!(
                may_join(class, &spent, true),
                "{class:?}: a probe packet ignores the grant"
            );
        }
        for class in [
            Class::Piggyback,
            Class::Probe,
            Class::Response,
            Class::AckOnly,
        ] {
            assert!(may_join(class, &spent, false), "{class:?}");
        }
    }

    #[test]
    fn only_data_starts_wait_for_the_egress_grant() {
        let spent = Gate {
            grant: false,
            probes_due: 1,
            ..open()
        };
        for class in [Class::Lost, Class::Control, Class::NewStream] {
            assert_eq!(
                may_start(class, &spent),
                Start::Blocked(Block::Endpoint),
                "{class:?}"
            );
        }
        for class in [Class::Probe, Class::Response, Class::AckOnly] {
            assert_eq!(may_start(class, &spent), Start::Yes, "{class:?}");
        }
        let full = Gate {
            bytes_in_flight: 12_000,
            ..spent
        };
        assert_eq!(
            may_start(Class::Lost, &full),
            Start::Blocked(Block::Cwnd),
            "a start the window also refuses waits for an ACK, not for the grant"
        );
    }

    #[test]
    fn a_start_refused_by_the_grant_outranks_every_other_limit() {
        let mut blocked = Blocked::default();
        blocked.note(Block::Amplification);
        blocked.note(Block::Cwnd);
        blocked.note(Block::Endpoint);
        assert_eq!(
            blocked.stop(),
            Some(Stop::Endpoint),
            "only Endpoint keeps the slot dirty until the next grant"
        );
    }

    #[test]
    fn the_credit_binds_every_joiner() {
        let short = Gate {
            credit: 600,
            ..open()
        };
        for class in [Class::Piggyback, Class::Probe, Class::AckOnly, Class::Lost] {
            assert!(!may_join(class, &short, true), "{class:?}");
        }
        let fits = Gate {
            datagram_size: 0,
            ..short
        };
        assert!(may_join(Class::AckOnly, &fits, false));
    }

    #[test]
    fn classify_reports_the_highest_binding_limit_and_the_earliest_release() {
        let mut blocked = Blocked::default();
        assert_eq!(blocked.stop(), None);
        let later = test_epoch() + Duration::from_millis(9);
        let sooner = test_epoch() + Duration::from_millis(3);
        blocked.note(Block::ConnFlowControl);
        assert_eq!(blocked.stop(), Some(Stop::ConnFlowControl));
        blocked.note(Block::Pacing(later));
        blocked.note(Block::Pacing(sooner));
        assert_eq!(blocked.stop(), Some(Stop::Pacing(sooner)));
        blocked.note(Block::Cwnd);
        assert_eq!(blocked.stop(), Some(Stop::Cwnd));
        blocked.note(Block::KeysPending);
        assert_eq!(blocked.stop(), Some(Stop::KeysPending));
        blocked.note(Block::Amplification);
        assert_eq!(blocked.stop(), Some(Stop::Amplification));
        assert_eq!(
            blocked.pacing_at(),
            Some(sooner),
            "pacing_at is reported whatever the stop"
        );
    }
}
