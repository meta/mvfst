/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Key updates and the AEAD limits (RFC 9001).
//!
//! The connection holds the current 1-RTT keys in its Data space, the next phase's keys, derived in
//! advance, and the previous phase's read keys for three PTOs after the first packet under the new
//! ones. A packet whose Key Phase bit differs from the current one opens with the previous keys if
//! its packet number is below every one received in the current phase, else with the next keys,
//! which then become current in both directions. Version 1 connections initiate once the handshake
//! is confirmed and the packets sealed with one key reach the configured interval or 0.8 times the
//! AEAD confidentiality limit, whichever is lower. They also wait until the peer has acknowledged a
//! packet sent with the current keys and, from the second update on, until three PTOs have passed
//! since that acknowledgment. MVFST connections never initiate, following mvfst, and close with
//! AEAD_LIMIT_REACHED at 0.8 times the limit instead.

use std::time::Instant;

use mvfstr_crypto::KeySet;
use mvfstr_crypto::KeyUpdater;
use mvfstr_crypto::PacketKeys;

/// Which read keys open a 1-RTT packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadKey {
    /// The previous phase's, for a delayed packet.
    Previous,
    /// The current phase's.
    Current,
    /// The next phase's: the peer updated.
    Next,
}

/// The previous phase's read keys.
struct Previous {
    remote: PacketKeys,
    /// When they go: three PTOs after the first packet opened with the current keys.
    discard_at: Option<Instant>,
}

/// The 1-RTT key phases of a connection.
pub(super) struct KeyPhases {
    updater: KeyUpdater,
    /// The Key Phase bit of the current keys.
    pub(super) phase: bool,
    /// The number of updates so far.
    pub(super) generation: u64,
    next: KeySet,
    previous: Option<Previous>,
    /// The lowest packet number sent with the current keys.
    first_sent: Option<u64>,
    /// The lowest packet number opened with the current keys.
    first_recv: Option<u64>,
    /// The highest packet number opened with the current keys.
    largest_recv: Option<u64>,
    /// When an acknowledgment first covered a packet sent with the current keys.
    acked_at: Option<Instant>,
    /// Packets sealed with the current write key.
    pub(super) sealed: u64,
    /// The current write key's confidentiality limit (RFC 9001).
    pub(super) confidentiality_limit: u64,
}

impl KeyPhases {
    /// Returns the phases of 1-RTT keys `current`, which `updater` came with.
    pub(super) fn new(mut updater: KeyUpdater, current: &KeySet) -> Self {
        let next = updater.next_keys();
        Self {
            updater,
            phase: false,
            generation: 0,
            next,
            previous: None,
            first_sent: None,
            first_recv: None,
            largest_recv: None,
            acked_at: None,
            sealed: 0,
            confidentiality_limit: current.local.confidentiality_limit(),
        }
    }

    /// Returns the keys that open a 1-RTT packet with Key Phase bit `phase` and packet number `pn`
    /// (RFC 9001).
    pub(super) fn read_key(&self, phase: bool, pn: u64) -> ReadKey {
        if phase == self.phase {
            return ReadKey::Current;
        }
        let delayed = self.first_recv.is_none_or(|first| pn < first);
        if self.previous.is_some() && delayed {
            ReadKey::Previous
        } else {
            ReadKey::Next
        }
    }

    /// Returns the read keys `key` names, if held; `current` are the current ones.
    pub(super) fn remote<'a>(
        &'a self,
        key: ReadKey,
        current: &'a PacketKeys,
    ) -> Option<&'a PacketKeys> {
        match key {
            ReadKey::Previous => self.previous.as_ref().map(|previous| &previous.remote),
            ReadKey::Current => Some(current),
            ReadKey::Next => Some(&self.next.remote),
        }
    }

    /// Moves to the next phase in both directions; `current` are the current keys, which
    /// become the previous read keys. `discard_at` is when those go, if a packet under the new
    /// keys arrived already.
    pub(super) fn advance(&mut self, current: &mut KeySet, discard_at: Option<Instant>) {
        let next = std::mem::replace(&mut self.next, self.updater.next_keys());
        let old = std::mem::replace(current, next);
        self.previous = Some(Previous {
            remote: old.remote,
            discard_at,
        });
        self.phase = !self.phase;
        self.generation += 1;
        self.first_sent = None;
        self.first_recv = None;
        self.largest_recv = None;
        self.acked_at = None;
        self.sealed = 0;
        self.confidentiality_limit = current.local.confidentiality_limit();
    }

    /// Records that a packet with number `pn` was sealed with the current write key.
    pub(super) fn on_sealed(&mut self, pn: u64) {
        self.sealed += 1;
        self.first_sent.get_or_insert(pn);
    }

    /// Records that the peer acknowledged 1-RTT packets up to `largest` at `now`.
    pub(super) fn on_acked(&mut self, largest: u64, now: Instant) {
        if self.acked_at.is_none() && self.first_sent.is_some_and(|first| largest >= first) {
            self.acked_at = Some(now);
        }
    }

    /// Returns whether a packet opened with `read` keys sets the discard time of the previous read
    /// keys: a packet under the next keys does, and so does the first under the current ones while
    /// previous keys are held.
    pub(super) fn sets_discard_time(&self, read: ReadKey) -> bool {
        match read {
            ReadKey::Previous => false,
            ReadKey::Current => self.first_recv.is_none() && self.previous.is_some(),
            ReadKey::Next => true,
        }
    }

    /// Records that a packet with number `pn` opened with the current keys; the previous keys go at
    /// `discard_at` if this is the first. `discard_at` is `None` only where `sets_discard_time` is
    /// false.
    pub(super) fn on_received(&mut self, pn: u64, discard_at: Option<Instant>) {
        if self.first_recv.is_none()
            && let Some(previous) = &mut self.previous
        {
            debug_assert!(
                previous.discard_at.is_some() || discard_at.is_some(),
                "the first packet under the current keys came without a discard time"
            );
            previous.discard_at = previous.discard_at.or(discard_at);
        }
        self.first_recv = Some(self.first_recv.map_or(pn, |first| first.min(pn)));
        self.largest_recv = Some(self.largest_recv.map_or(pn, |largest| largest.max(pn)));
    }

    /// Returns the largest packet number opened with the current keys.
    pub(super) fn largest_recv(&self) -> Option<u64> {
        self.largest_recv
    }

    /// Returns whether RFC 9001 lets this endpoint initiate an update at `now`: a packet sent with
    /// the current keys was acknowledged, `wait` ago for any update after the first.
    pub(super) fn may_initiate(&self, now: Instant, wait: std::time::Duration) -> bool {
        self.acked_at
            .is_some_and(|at| self.generation == 0 || now >= at + wait)
    }

    /// Returns when the previous read keys go, if they are held.
    pub(super) fn discard_at(&self) -> Option<Instant> {
        self.previous.as_ref()?.discard_at
    }

    /// Drops the previous read keys if they are due at `now`.
    pub(super) fn discard_due(&mut self, now: Instant) {
        if self.discard_at().is_some_and(|at| now >= at) {
            self.previous = None;
        }
    }

    /// Returns whether the previous read keys are held.
    #[cfg(test)]
    pub(super) fn has_previous(&self) -> bool {
        self.previous.is_some()
    }
}

impl std::fmt::Debug for KeyPhases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPhases")
            .field("phase", &self.phase)
            .field("generation", &self.generation)
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}
