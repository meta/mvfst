/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Path validation and passive migration (RFC 9000).
//!
//! Only the client moves. Once the handshake is confirmed, a server that receives the newest
//! non-probing packet from a new address sends to it at once, under that address's
//! anti-amplification credit, and validates it; the previous path, if validated, stays as the
//! alternate path, is challenged too and is where the connection returns if the new address fails
//! validation. A validated move resets congestion control and the RTT estimate unless only the port
//! changed, and packets sent to the alternate path do not count toward either. A probing packet
//! from a new address makes it the alternate path only when the packet carries PATH_CHALLENGE and
//! the connection does not have a validated alternate path. The alternate path carries only frames
//! of the Path source. A peer that moves under a new connection ID gets one of its unused IDs back
//! on the new path, and an ID a path no longer needs is retired; a zero-length peer ID is used on
//! every path instead. A path left without a usable peer ID does not send until the peer supplies a
//! fresh one.

use std::net::SocketAddr;
use std::time::Instant;

use mvfstr_wire::ConnectionId;
use mvfstr_wire::Side;

use super::Connection;
use super::GRANULARITY;
use super::MIN_DATAGRAM;
use super::PathCredit;
use super::congestion_state;
use crate::CloseReason;
use crate::ConnEvent;
use crate::Initiator;
use crate::PathEvent;
use crate::Prioritizer;
use crate::Random;
use crate::recovery::rtt::RttEstimator;
use crate::sources::path::ALTERNATE;
use crate::sources::path::CHALLENGES;
use crate::sources::path::CURRENT;
use crate::sources::path::PathSlot;

/// The alternate path: the previous path while a migration is validated, or an address the peer
/// probes from.
#[derive(Clone, Copy, Debug)]
pub(super) struct AltPath {
    pub(super) remote: SocketAddr,
    pub(super) credit: PathCredit,
    /// The Destination Connection ID of the peer's latest packet on this path.
    pub(super) rx_dcid: ConnectionId,
}

impl<P: Prioritizer> Connection<P> {
    /// Credits a datagram of `len` bytes from `src`, not the current address, to the alternate
    /// path's anti-amplification budget when it comes from there.
    pub(super) fn credit_received(&mut self, src: SocketAddr, len: u64) {
        if let Some(alt) = &mut self.alt
            && alt.remote == src
        {
            alt.credit.received += len;
        }
    }

    /// Handles a processed 1-RTT packet from `src` to `dcid`, in a datagram of `len` bytes:
    /// `newest` if it is the highest-numbered packet received with a non-probing frame, and
    /// `challenge` the data of its last PATH_CHALLENGE.
    pub(super) fn on_path_packet(
        &mut self,
        now: Instant,
        src: SocketAddr,
        dcid: ConnectionId,
        newest: bool,
        challenge: Option<[u8; 8]>,
        len: usize,
    ) {
        if newest && src == self.remote {
            self.rx_dcid = dcid;
        } else if newest && self.side == Side::Server {
            self.migrate(now, src, dcid, len);
        }
        let Some(data) = challenge else {
            return;
        };
        if src == self.remote {
            self.sources.path.challenged(CURRENT, data);
            return;
        }
        match self.alt {
            Some(alt) if alt.remote == src => {}
            // Two paths at most: the previous validated one is kept over a third address.
            Some(alt) if alt.credit.validated => return,
            _ => {
                // As RFC 9000 requires, a probe under a new connection ID is answered under an
                // unused one, or not at all, unless the peer's ID is zero-length.
                let Some(own_id) = self.sources.cids.peer.own_id_for(dcid != self.rx_dcid) else {
                    return;
                };
                self.drop_alt();
                self.sources.cids.peer.open_alt(own_id);
                self.alt = Some(AltPath {
                    remote: src,
                    credit: PathCredit {
                        received: len as u64,
                        ..PathCredit::default()
                    },
                    rx_dcid: dcid,
                });
            }
        }
        self.sources.path.challenged(ALTERNATE, data);
    }

    /// Moves the current path to `src`, where the peer's newest non-probing packet came from, sent
    /// to `dcid`: packets go there at once. A move back to the validated alternate path is not
    /// validated again; any other new address is validated, and so is the previous path if it was
    /// validated, which stays as the alternate path to return to.
    fn migrate(&mut self, now: Instant, src: SocketAddr, dcid: ConnectionId, len: usize) {
        let [current_slot, alt_slot] = self.sources.path.slots;
        let previous = AltPath {
            remote: self.remote,
            credit: self.path,
            rx_dcid: self.rx_dcid,
        };
        if let Some(alt) = self.alt.filter(|alt| alt.remote == src) {
            self.remote = src;
            self.path = alt.credit;
            self.rx_dcid = dcid;
            self.sources.path.slots = [alt_slot, current_slot];
            self.sources.cids.peer.swap_alt();
            if alt.credit.validated {
                // The challenge that checks the old path is moot once the peer comes back to it.
                self.sources.path.slots[CURRENT].validation = None;
                self.drop_alt();
                self.migrated_from = None;
                return;
            }
        } else {
            // As RFC 9000 requires, a peer that moved under a new connection ID gets an unused one
            // back, and without one the connection cannot send to it there until it provides one.
            // A NAT rebinding keeps the ID, which the previous path then shares, and so does a
            // move of a peer whose ID is zero-length. The previous path, if validated, takes the
            // alternate path's place; otherwise a validated alternate path stays as the one to
            // return to. The old ID stays with the path kept as the alternate one: the previous
            // path, or a kept alternate path that shared it.
            let Some(own_id) = self.sources.cids.peer.own_id_for(dcid != self.rx_dcid) else {
                return;
            };
            let keep_alt =
                !previous.credit.validated && self.alt.is_some_and(|alt| alt.credit.validated);
            if !keep_alt {
                self.drop_alt();
            }
            let ids = &mut self.sources.cids.peer;
            if own_id {
                let moved = ids.move_current(previous.credit.validated || ids.alt_shares());
                debug_assert!(moved, "should find the unused ID it checked for");
            } else if previous.credit.validated {
                ids.open_alt(false);
            }
            self.remote = src;
            self.rx_dcid = dcid;
            self.path = PathCredit {
                received: len as u64,
                ..PathCredit::default()
            };
            self.sources.path.slots[CURRENT] = PathSlot::default();
        }
        if previous.credit.validated {
            self.sources.path.slots[ALTERNATE] = current_slot;
            self.alt = Some(previous);
            self.migrated_from = Some(previous.remote);
            self.validate_path(now, ALTERNATE);
        } else if self
            .alt
            .is_some_and(|alt| alt.remote == src || !alt.credit.validated)
        {
            self.drop_alt();
        }
        self.validate_path(now, CURRENT);
    }

    /// Starts validating the path of `slot`: the challenge data comes from the connection RNG now,
    /// and the validation fails after three times the larger of the current PTO and one computed
    /// from the initial RTT, as RFC 9000 recommends.
    fn validate_path(&mut self, now: Instant, slot: usize) {
        let mut data = [[0; 8]; CHALLENGES];
        for challenge in &mut data {
            self.rng.fill(challenge);
        }
        let initial_pto = RttEstimator::new(self.config.initial_rtt()).pto_base(GRANULARITY)
            + self.peer_max_ack_delay();
        let deadline = now + 3 * self.pto_interval().max(initial_pto);
        self.sources.path.validate(slot, data, deadline);
    }

    /// Handles a PATH_RESPONSE with `data`, received on any path. Once the current path is
    /// validated, a migration is reported and resets congestion control and the RTT estimate
    /// unless only the port changed; a path first validated without a full-size challenge is
    /// validated again, now that its credit allows one.
    pub(super) fn on_path_response(&mut self, now: Instant, data: [u8; 8]) {
        let Some((slot, full_size)) = self.sources.path.answered(data) else {
            return;
        };
        self.sources.path.slots[slot].validation = None;
        if slot == ALTERNATE {
            if let Some(alt) = &mut self.alt {
                alt.credit.validated = true;
            }
            return;
        }
        let first = !self.path.validated;
        self.path.validated = true;
        if let Some(from) = self.migrated_from.take() {
            if from.ip() != self.remote.ip() {
                self.recovery.reset_for_new_path();
                (self.cc, self.pacer) = congestion_state(
                    &self.config,
                    self.mtu,
                    self.horizon,
                    &self.recovery,
                    &mut self.rng,
                );
                self.app_limited = false;
            }
            self.drop_alt();
            self.push_event(ConnEvent::Path(PathEvent::Migrated {
                remote: self.remote,
            }));
        }
        if first && !full_size {
            self.validate_path(now, CURRENT);
        }
    }

    /// Returns the earliest time a challenge goes again or a path validation fails.
    pub(super) fn path_deadline(&self) -> Option<Instant> {
        self.sources
            .path
            .slots
            .iter()
            .filter_map(|slot| slot.validation.map(|v| v.deadline))
            .chain(self.sources.path.retry_at())
            .min()
    }

    /// Fails the path validations due at `now`: a new current address that failed sends the
    /// connection back to the last validated one or, without one, ends it silently; a failed
    /// alternate path is dropped, unless it is that last validated address and the current one
    /// is still being validated.
    pub(super) fn on_path_deadline(&mut self, now: Instant) {
        self.sources.path.on_retry_due(now);
        for slot in [CURRENT, ALTERNATE] {
            let due = self.sources.path.slots[slot]
                .validation
                .is_some_and(|v| now >= v.deadline);
            if !due {
                continue;
            }
            self.sources.path.slots[slot].validation = None;
            if slot == ALTERNATE {
                let fallback =
                    !self.path.validated && self.alt.is_some_and(|alt| alt.credit.validated);
                if !fallback {
                    self.drop_alt();
                }
                continue;
            }
            if self.path.validated {
                continue;
            }
            let failed = self.remote;
            match self.alt.filter(|alt| alt.credit.validated) {
                Some(alt) => {
                    self.remote = alt.remote;
                    self.path = alt.credit;
                    self.rx_dcid = alt.rx_dcid;
                    self.sources.path.swap();
                    self.sources.cids.peer.swap_alt();
                    self.drop_alt();
                    self.migrated_from = None;
                    self.push_event(ConnEvent::Path(PathEvent::ValidationFailed {
                        remote: failed,
                    }));
                }
                None => {
                    self.push_event(ConnEvent::Closed {
                        reason: CloseReason::Silent,
                        initiator: Initiator::Local,
                    });
                    self.drained();
                    return;
                }
            }
        }
    }

    /// Closes the connection once path changes left more peer connection IDs retired without
    /// acknowledgment than twice this endpoint's active_connection_id_limit.
    pub(super) fn check_retire_bound(&mut self, now: Instant) {
        if let Err(error) = self.sources.cids.peer.retire_bound() {
            self.close_on_error(now, error);
        }
    }

    /// Drops the alternate path, its Path source state and its own peer connection ID.
    pub(super) fn drop_alt(&mut self) {
        self.alt = None;
        self.sources.path.slots[ALTERNATE] = PathSlot::default();
        self.sources.cids.peer.drop_alt();
    }

    /// Returns the peer's connection ID in use on `path`, if it has one.
    pub(super) fn dcid_of(&self, path: crate::PathId) -> Option<ConnectionId> {
        debug_assert_eq!(
            self.alt.is_some(),
            self.sources.cids.peer.has_alt(),
            "the connection and its peer IDs agree on the alternate path"
        );
        self.sources
            .cids
            .peer
            .cid_of(usize::from(path.0).min(ALTERNATE))
    }

    /// Returns the bytes `path` may still carry under the anti-amplification limit.
    pub(super) fn credit_of(&self, path: crate::PathId) -> u64 {
        if usize::from(path.0) == CURRENT {
            self.path.credit()
        } else {
            self.alt.map_or(0, |alt| alt.credit.credit())
        }
    }

    /// Returns the address datagrams on `path` go to.
    pub(super) fn remote_of(&self, path: crate::PathId) -> SocketAddr {
        match self.alt {
            Some(alt) if usize::from(path.0) == ALTERNATE => alt.remote,
            _ => self.remote,
        }
    }

    /// Charges a datagram of `len` bytes sealed at `now` to `path`, whose peer connection ID is
    /// now used; for a datagram carrying a PATH_CHALLENGE, records whether it reached 1,200 bytes
    /// and when the next challenge is due.
    pub(super) fn charge_path(
        &mut self,
        now: Instant,
        path: crate::PathId,
        len: usize,
        challenge: bool,
    ) {
        let slot = usize::from(path.0).min(ALTERNATE);
        self.sources.cids.peer.on_sent(slot);
        if slot == CURRENT {
            self.path.sent += len as u64;
        } else if let Some(alt) = &mut self.alt {
            alt.credit.sent += len as u64;
        }
        if challenge {
            let pto = self.pto_interval();
            self.sources
                .path
                .on_challenge_sealed(slot, len >= usize::from(MIN_DATAGRAM), now, pto);
        }
    }
}
