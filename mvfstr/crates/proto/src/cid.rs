/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection ID management (RFC 9000).
//!
//! It covers issuing local connection IDs with NEW_CONNECTION_ID up to the peer's
//! active_connection_id_limit, stateless reset tokens derived from the endpoint key, the peer's
//! IDs with retire_prior_to and a bounded RETIRE_CONNECTION_ID queue, the peer ID each path sends
//! with or waits for, and the endpoint events that keep routing current.

use mvfstr_crypto::hkdf_expand_label;
use mvfstr_crypto::hkdf_extract_sha256;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Frame;
use mvfstr_wire::Full;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::ResetToken;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;

use crate::EndpointConfig;
use crate::Random;
use crate::TransportConfig;
use crate::connection::ConnError;
use crate::endpoint::CID_ATTEMPTS;
use crate::recovery::Space;
use crate::recovery::sent::ControlKind;
use crate::recovery::sent::SentFrame;
use crate::sources::FrameSource;
use crate::sources::SendCx;
use crate::sources::delivery::Delivery;
use crate::sources::path::CURRENT;
use crate::transmit::admission::Class;

/// A generator of one endpoint's connection IDs and their stateless reset tokens.
///
/// A token is HKDF-Expand-Label of a key extracted once from the endpoint's reset secret, with the
/// connection ID as context, as RFC 9000 suggests, so an endpoint that lost a connection's state
/// can still compute the token of any ID it issued.
#[derive(Clone)]
pub(crate) struct CidGenerator {
    len: u8,
    worker_index: u16,
    worker_count: u16,
    reset_prk: [u8; 32],
}

impl CidGenerator {
    pub(crate) fn new(config: &EndpointConfig) -> Self {
        let (worker_index, worker_count) = config.worker();
        Self {
            len: u8::try_from(config.local_cid_len()).unwrap_or(u8::MAX),
            worker_index,
            worker_count,
            reset_prk: hkdf_extract_sha256(b"mvfstr stateless reset", config.reset_key()),
        }
    }

    /// Returns the stateless reset token of `cid`.
    pub(crate) fn reset_token(&self, cid: &ConnectionId) -> ResetToken {
        let mut token = [0; ResetToken::LEN];
        hkdf_expand_label(&self.reset_prk, b"mvfstr reset", cid, &mut token)
            .expect("should fit: a 32-byte key, a short label and an ID of at most 20 bytes");
        ResetToken(token)
    }

    /// Fills `out` with bytes that only a holder of the endpoint key can predict, derived from the
    /// datagram that triggers a stateless reset.
    pub(crate) fn reset_fill(&self, trigger: &[u8], out: &mut [u8]) {
        let context = &trigger[..trigger.len().min(usize::from(u8::MAX))];
        hkdf_expand_label(&self.reset_prk, b"mvfstr reset fill", context, out)
            .expect("should fit: a reset is at most 43 bytes and the context 255");
    }

    /// Returns a random connection ID of the endpoint's length, whose first byte names its worker
    /// when the endpoint has several.
    pub(crate) fn generate<R: Random>(&self, rng: &mut R) -> ConnectionId {
        let mut bytes = [0; ConnectionId::MAX_LEN];
        let id = &mut bytes[..usize::from(self.len)];
        rng.fill(id);
        if self.worker_count > 1 {
            if let Some(first) = id.first_mut() {
                *first = self.worker_byte(*first);
            }
        }
        ConnectionId::new(id).expect("should fit: the config caps the length")
    }

    /// Returns the worker `cid` names, or `None` when one worker issues every ID.
    pub(crate) fn worker_of(&self, cid: &[u8]) -> Option<u16> {
        if self.worker_count <= 1 {
            return None;
        }
        cid.first()
            .map(|first| u16::from(*first) % self.worker_count)
    }

    /// Returns a first byte congruent to the worker index modulo the worker count, picked by
    /// `random` among all such bytes so the byte stays as unpredictable as the count allows.
    fn worker_byte(&self, random: u8) -> u8 {
        let count = u32::from(self.worker_count);
        let index = u32::from(self.worker_index);
        let choices = (u32::from(u8::MAX) - index) / count + 1;
        let byte = u32::from(random) % choices * count + index;
        u8::try_from(byte).expect("should fit: the choices stop at 255")
    }
}

/// A connection's own random source: HKDF-Expand-Label of a seed the endpoint's random source
/// gave at creation, with a counter as context, so the connection draws connection IDs and
/// PATH_CHALLENGE data without the caller's generator.
#[derive(Clone)]
pub(crate) struct ConnRng {
    seed: [u8; 32],
    counter: u64,
}

impl ConnRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

impl Random for ConnRng {
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(usize::from(u8::MAX)) {
            hkdf_expand_label(
                &self.seed,
                b"mvfstr rng",
                &self.counter.to_be_bytes(),
                chunk,
            )
            .expect("should fit: 255 bytes from a 32-byte key");
            self.counter += 1;
        }
    }
}

impl std::fmt::Debug for ConnRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnRng").finish_non_exhaustive()
    }
}

/// The most local connection IDs a connection keeps issued at once, whatever the peer's
/// active_connection_id_limit allows.
pub(crate) const MAX_LOCAL_CIDS: u64 = 8;

/// One issued local connection ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LocalCid {
    seq: u64,
    cid: ConnectionId,
    token: ResetToken,
    /// The delivery state of its NEW_CONNECTION_ID; the handshake's ID is not sent in one.
    delivery: Delivery,
}

/// The connection IDs this endpoint issued and the peer has not retired (RFC 9000).
#[derive(Clone, Debug, Hash)]
pub(crate) struct LocalCids {
    /// Ascending by sequence number.
    issued: Vec<LocalCid>,
    next_seq: u64,
    /// The largest sequence number sealed in a NEW_CONNECTION_ID frame, or 0 for the handshake's.
    sent: u64,
}

impl LocalCids {
    /// Returns the IDs of a connection whose handshake used `cid`, sequence number 0.
    pub(crate) fn new(cid: ConnectionId, token: ResetToken) -> Self {
        Self {
            issued: vec![LocalCid {
                seq: 0,
                cid,
                token,
                delivery: Delivery::Delivered,
            }],
            next_seq: 1,
            sent: 0,
        }
    }

    /// Returns the number of IDs issued and not retired.
    pub(crate) fn active(&self) -> u64 {
        self.issued.len() as u64
    }

    /// Issues a new ID from `generator` under the next sequence number, to be sent in
    /// NEW_CONNECTION_ID; returns it with its reset token, or `None` if `rng` keeps drawing IDs
    /// still issued, since RFC 9000 forbids issuing an ID twice.
    pub(crate) fn issue_new<R: Random>(
        &mut self,
        generator: &CidGenerator,
        rng: &mut R,
    ) -> Option<(ConnectionId, ResetToken)> {
        let cid = (0..CID_ATTEMPTS)
            .map(|_| generator.generate(rng))
            .find(|cid| self.issued.iter().all(|issued| issued.cid != *cid))?;
        let token = generator.reset_token(&cid);
        self.issue(cid, token);
        Some((cid, token))
    }

    /// Issues `cid` with `token` under the next sequence number, to be sent in NEW_CONNECTION_ID.
    pub(crate) fn issue(&mut self, cid: ConnectionId, token: ResetToken) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.issued.push(LocalCid {
            seq,
            cid,
            token,
            delivery: Delivery::Pending,
        });
        seq
    }

    /// Records that the peer retired sequence number `seq` in a packet sent to `dcid` (RFC 9000);
    /// returns the ID to stop routing, or `None` if it was retired before.
    pub(crate) fn retire(
        &mut self,
        seq: u64,
        dcid: &ConnectionId,
    ) -> Result<Option<ConnectionId>, ConnError> {
        let violation = |reason| {
            Err(ConnError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                reason,
            ))
        };
        // A zero-length ID is never issued beyond sequence number 0, the ID every packet names.
        if seq > self.sent {
            return violation("RETIRE_CONNECTION_ID for an ID never sent");
        }
        let Some(index) = self.issued.iter().position(|issued| issued.seq == seq) else {
            return Ok(None);
        };
        if self.issued[index].cid == *dcid {
            return violation("RETIRE_CONNECTION_ID for the ID its packet was sent to");
        }
        Ok(Some(self.issued.remove(index).cid))
    }

    fn pending(&self) -> Option<&LocalCid> {
        self.issued
            .iter()
            .find(|issued| issued.delivery == Delivery::Pending)
    }

    fn by_seq(&mut self, seq: u64) -> Option<&mut LocalCid> {
        self.issued.iter_mut().find(|issued| issued.seq == seq)
    }
}

/// One of the peer's connection IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerCid {
    seq: u64,
    cid: ConnectionId,
    token: Option<ResetToken>,
    /// Whether a datagram went out with it: only then is its token checked, as RFC 9000 requires.
    used: bool,
}

/// The peer connection ID a path sends with (RFC 9000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PathCid {
    /// The peer's ID with this sequence number, which the other path does not use.
    Own(u64),
    /// The current path's ID: an alternate path at an address the peer reached with the ID it
    /// was already sending to, which RFC 9000 lets the two paths share.
    Shared,
    /// An ID still to come: the path does not send short-header packets until a NEW_CONNECTION_ID
    /// supplies an ID that the other path does not use.
    Waiting,
}

/// The peer's connection IDs this endpoint may send with, the ID each path sends with, and the
/// ones it retires (RFC 9000). RETIRE_CONNECTION_ID frames not yet acknowledged are bounded at
/// twice this endpoint's active_connection_id_limit, and sequence numbers still to come at the
/// limit, which the config caps at [`TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT`], so the
/// memory a peer can make a connection hold stays small.
#[derive(Clone, Debug, Hash)]
pub(crate) struct PeerCids {
    /// Ascending by sequence number.
    active: Vec<PeerCid>,
    /// The ID the current path sends with; never `Shared`.
    current: PathCid,
    /// The ID the alternate path sends with, while there is an alternate path.
    alt: Option<PathCid>,
    /// The largest Retire Prior To received; every number below it is retired.
    retire_prior_to: u64,
    /// The largest sequence number received, or Retire Prior To less one if that is larger.
    largest: u64,
    /// The sequence numbers from Retire Prior To up to `largest` whose IDs have not arrived.
    /// The peer numbers its IDs one after another (RFC 9000), so any other number up to
    /// `largest` that is not active was retired.
    missing: Vec<u64>,
    /// The RETIRE_CONNECTION_ID frames not yet acknowledged.
    retiring: Vec<(u64, Delivery)>,
    /// This endpoint's active_connection_id_limit.
    limit: u64,
}

impl PeerCids {
    /// Returns the peer's IDs when its first is `cid` and this endpoint's
    /// active_connection_id_limit is `limit`.
    pub(crate) fn new(cid: ConnectionId, limit: u64) -> Self {
        debug_assert!(
            limit <= TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT,
            "should be capped by the config: one frame may cost work and memory in proportion to it"
        );
        Self {
            active: vec![PeerCid {
                seq: 0,
                cid,
                token: None,
                used: false,
            }],
            current: PathCid::Own(0),
            alt: None,
            retire_prior_to: 0,
            largest: 0,
            missing: Vec::new(),
            retiring: Vec::new(),
            limit,
        }
    }

    /// Returns the sequence number of the ID the path of `slot` sends with, the current or the
    /// alternate one.
    fn seq_of(&self, slot: usize) -> Option<u64> {
        let path = if slot == CURRENT {
            self.current
        } else {
            self.alt?
        };
        match (path, self.current) {
            (PathCid::Own(seq), _) | (PathCid::Shared, PathCid::Own(seq)) => Some(seq),
            (PathCid::Waiting, _) | (PathCid::Shared, PathCid::Shared | PathCid::Waiting) => None,
        }
    }

    /// Returns the ID the path of `slot` sends with.
    fn entry_of(&self, slot: usize) -> Option<&PeerCid> {
        let seq = self.seq_of(slot)?;
        self.active.iter().find(|peer| peer.seq == seq)
    }

    /// Records that a datagram went out on the path of `slot` with its ID.
    pub(crate) fn on_sent(&mut self, slot: usize) {
        let seq = self.seq_of(slot);
        if let Some(peer) = self.active.iter_mut().find(|peer| Some(peer.seq) == seq) {
            peer.used = true;
        }
    }

    /// Returns the ID the current path sends with and its stateless reset token.
    pub(crate) fn current(&self) -> Option<(ConnectionId, Option<ResetToken>)> {
        self.entry_of(CURRENT).map(|peer| (peer.cid, peer.token))
    }

    /// Returns the ID the path of `slot` sends with, the current or the alternate one.
    pub(crate) fn cid_of(&self, slot: usize) -> Option<ConnectionId> {
        self.entry_of(slot).map(|peer| peer.cid)
    }

    /// Returns the stateless reset token of the ID the path of `slot` sends with, once a datagram
    /// went out with that ID.
    pub(crate) fn token_of(&self, slot: usize) -> Option<ResetToken> {
        self.entry_of(slot).filter(|peer| peer.used)?.token
    }

    /// Returns whether the alternate path shares the current path's ID.
    pub(crate) fn alt_shares(&self) -> bool {
        self.alt == Some(PathCid::Shared)
    }

    /// Returns whether the alternate path sends with an ID of its own.
    #[cfg(test)]
    fn alt_has_own(&self) -> bool {
        matches!(self.alt, Some(PathCid::Own(_)))
    }

    /// Returns whether there is an alternate path.
    pub(crate) fn has_alt(&self) -> bool {
        self.alt.is_some()
    }

    /// Returns whether an unused ID is available.
    fn has_unused(&self) -> bool {
        self.unused().is_some()
    }

    /// Returns whether a path the peer reached under another of this endpoint's IDs than before
    /// (`changed`) takes an ID of its own rather than sharing the current one, or `None` when it
    /// needs one and every ID is in use (RFC 9000). A zero-length ID is used on every path, and
    /// such a peer never supplies another.
    pub(crate) fn own_id_for(&self, changed: bool) -> Option<bool> {
        if !changed || self.zero_length() {
            return Some(false);
        }
        self.has_unused().then_some(true)
    }

    /// Returns whether the peer uses a zero-length ID.
    fn zero_length(&self) -> bool {
        self.current().is_some_and(|(cid, _)| cid.is_empty())
    }

    fn unused(&self) -> Option<u64> {
        self.active
            .iter()
            .map(|peer| peer.seq)
            .find(|&seq| !self.in_use(seq))
    }

    /// Returns whether a path sends with the ID of sequence number `seq`.
    fn in_use(&self, seq: u64) -> bool {
        self.current == PathCid::Own(seq) || self.alt == Some(PathCid::Own(seq))
    }

    /// Moves the current path to an unused ID. The ID it used goes on with the alternate path if
    /// `keep_old`, whose own ID is then retired, and is retired otherwise. Without an unused ID,
    /// the paths keep their IDs and the result is false.
    pub(crate) fn move_current(&mut self, keep_old: bool) -> bool {
        let Some(new) = self.unused() else {
            return false;
        };
        if keep_old {
            let old = std::mem::replace(&mut self.current, PathCid::Own(new));
            if let Some(PathCid::Own(replaced)) = self.alt.replace(old) {
                self.retire(replaced);
            }
        } else {
            if let PathCid::Own(old) = self.current {
                self.retire(old);
            }
            self.current = PathCid::Own(new);
        }
        self.settle();
        true
    }

    /// Opens a new alternate path in place of any other, whose own ID is retired: the new path
    /// takes an unused ID if `own`, and otherwise shares the current one or waits with the current
    /// path. Without an unused ID for it, the paths keep their IDs and the result is false.
    pub(crate) fn open_alt(&mut self, own: bool) -> bool {
        let path = if own {
            let Some(new) = self.unused() else {
                return false;
            };
            PathCid::Own(new)
        } else if self.current == PathCid::Waiting {
            PathCid::Waiting
        } else {
            PathCid::Shared
        };
        if let Some(PathCid::Own(replaced)) = self.alt.replace(path) {
            self.retire(replaced);
        }
        true
    }

    /// Swaps the IDs of the current and alternate paths, or the lack of one; paths that share an ID
    /// keep sharing it.
    pub(crate) fn swap_alt(&mut self) {
        if let Some(alt @ (PathCid::Own(_) | PathCid::Waiting)) = &mut self.alt {
            std::mem::swap(alt, &mut self.current);
        }
    }

    /// Drops the alternate path and retires its own ID, if any.
    pub(crate) fn drop_alt(&mut self) {
        if let Some(PathCid::Own(alt)) = self.alt.take() {
            self.retire(alt);
        }
    }

    /// Stops using `seq` and queues a RETIRE_CONNECTION_ID for it. A path that sent with it
    /// waits for a new ID, and so does an alternate path that shared it: the ID the current path
    /// gets next was never used at the alternate path's address (RFC 9000).
    fn retire(&mut self, seq: u64) {
        self.active.retain(|peer| peer.seq != seq);
        self.queue_retire(seq);
        if self.current == PathCid::Own(seq) {
            self.current = PathCid::Waiting;
            if self.alt == Some(PathCid::Shared) {
                self.alt = Some(PathCid::Waiting);
            }
        }
        if self.alt == Some(PathCid::Own(seq)) {
            self.alt = Some(PathCid::Waiting);
        }
    }

    /// Gives each waiting path, the current one first, an unused ID, if there is one.
    fn settle(&mut self) {
        if self.current == PathCid::Waiting
            && let Some(seq) = self.unused()
        {
            self.current = PathCid::Own(seq);
        }
        if self.alt == Some(PathCid::Waiting)
            && let Some(seq) = self.unused()
        {
            self.alt = Some(PathCid::Own(seq));
        }
    }

    /// Sets the peer's handshake ID, sequence number 0, to `cid`: a client learns it from the
    /// server's first Initial.
    pub(crate) fn set_handshake_cid(&mut self, cid: ConnectionId) {
        if let Some(first) = self.active.iter_mut().find(|peer| peer.seq == 0)
            && first.cid != cid
        {
            first.cid = cid;
            first.used = false;
        }
    }

    /// Records, from the server's transport parameters, the token of its handshake ID and any
    /// preferred_address ID, sequence number 1 (RFC 9000).
    pub(crate) fn on_server_params(
        &mut self,
        token: Option<ResetToken>,
        preferred: Option<(ConnectionId, ResetToken)>,
    ) {
        if let Some(first) = self.active.iter_mut().find(|peer| peer.seq == 0) {
            first.token = token;
        }
        if let Some((cid, token)) = preferred
            && self.largest == 0
        {
            self.largest = 1;
            self.insert(PeerCid {
                seq: 1,
                cid,
                token: Some(token),
                used: false,
            });
        }
    }

    /// Applies a NEW_CONNECTION_ID frame (RFC 9000); returns whether the ID in use changed.
    pub(crate) fn on_new(
        &mut self,
        seq: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        token: ResetToken,
    ) -> Result<bool, ConnError> {
        let violation = |reason| {
            Err(ConnError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                reason,
            ))
        };
        if self.zero_length() {
            return violation("NEW_CONNECTION_ID from a peer with a zero-length ID");
        }
        if let Some(known) = self
            .active
            .iter()
            .find(|peer| peer.seq == seq || peer.cid == cid)
            && (known.seq != seq || known.cid != cid || known.token != Some(token))
        {
            return violation("NEW_CONNECTION_ID contradicts an earlier one");
        }
        let before = self.cid_of(CURRENT);
        // As RFC 9000 requires, the IDs below Retire Prior To are retired before the new one is
        // added. Those whose frames have not arrived are retired too: the peer issued every number
        // below `seq`, so a RETIRE_CONNECTION_ID for each is valid, and when such a frame arrives
        // later, the first or a repeat, its ID is not retired again.
        if retire_prior_to > self.retire_prior_to {
            let unseen = self.largest + 1..retire_prior_to;
            if unseen.end.saturating_sub(unseen.start) > self.limit.saturating_mul(2) {
                return Err(Self::too_many_retired());
            }
            self.retire_prior_to = retire_prior_to;
            while let Some(seq) = self
                .active
                .first()
                .map(|peer| peer.seq)
                .filter(|&seq| seq < retire_prior_to)
            {
                self.retire(seq);
            }
            let mut index = 0;
            while let Some(&missing) = self.missing.get(index) {
                if missing < retire_prior_to {
                    self.missing.swap_remove(index);
                    self.queue_retire(missing);
                } else {
                    index += 1;
                }
            }
            for seq in unseen {
                self.queue_retire(seq);
            }
            self.largest = self.largest.max(retire_prior_to - 1);
        }
        let new = if seq < self.retire_prior_to {
            false
        } else if seq > self.largest {
            let first = self.largest + 1;
            // The missing numbers were issued and not retired, so they count against the limit
            // at the peer, which bounds this record.
            if self.missing.len() as u64 + (seq - first) > self.limit {
                return Err(ConnError::new(
                    TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                    "more connection IDs issued than active_connection_id_limit",
                ));
            }
            self.missing.extend(first..seq);
            self.largest = seq;
            true
        } else if let Some(index) = self.missing.iter().position(|&missing| missing == seq) {
            self.missing.swap_remove(index);
            true
        } else {
            // Active, so a repeat, or retired.
            false
        };
        if new {
            self.insert(PeerCid {
                seq,
                cid,
                token: Some(token),
                used: false,
            });
        }
        self.settle();
        let changed = self.cid_of(CURRENT) != before;
        if self.active.len() as u64 > self.limit {
            return Err(ConnError::new(
                TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                "more connection IDs than active_connection_id_limit",
            ));
        }
        self.retire_bound()?;
        Ok(changed)
    }

    /// Fails with PROTOCOL_VIOLATION when more RETIRE_CONNECTION_ID frames wait for an
    /// acknowledgment than twice the limit.
    pub(crate) fn retire_bound(&self) -> Result<(), ConnError> {
        if self.retiring.len() as u64 > self.limit.saturating_mul(2) {
            return Err(Self::too_many_retired());
        }
        Ok(())
    }

    fn too_many_retired() -> ConnError {
        ConnError::new(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "too many connection IDs retired without acknowledgment",
        )
    }

    fn insert(&mut self, peer: PeerCid) {
        let index = self.active.partition_point(|other| other.seq < peer.seq);
        self.active.insert(index, peer);
    }

    /// Retires `seq` with RETIRE_CONNECTION_ID. Each number is retired once: when it leaves
    /// `active` or `missing`, or when Retire Prior To passes it above `largest`.
    fn queue_retire(&mut self, seq: u64) {
        debug_assert!(
            self.retiring.iter().all(|(retired, _)| *retired != seq),
            "should retire each sequence number once"
        );
        self.retiring.push((seq, Delivery::Pending));
    }

    /// Returns the number of the peer's IDs this endpoint may use.
    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.active.len()
    }

    /// Returns the peer's IDs this endpoint may use, with their sequence numbers and tokens.
    #[cfg(test)]
    pub(crate) fn ids(&self) -> Vec<(u64, ConnectionId, Option<ResetToken>)> {
        self.active
            .iter()
            .map(|peer| (peer.seq, peer.cid, peer.token))
            .collect()
    }

    fn pending_retire(&self) -> Option<u64> {
        self.retiring
            .iter()
            .find(|(_, delivery)| *delivery == Delivery::Pending)
            .map(|(seq, _)| *seq)
    }
}

/// What the connection ID part of the Control source writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CidCand {
    /// NEW_CONNECTION_ID for the local ID with this sequence number.
    New(u64),
    /// RETIRE_CONNECTION_ID for the peer's ID with this sequence number.
    Retire(u64),
}

/// A connection's local and peer connection IDs; the Control source sends their frames.
#[derive(Clone, Debug, Hash)]
pub(crate) struct Cids {
    pub(crate) local: LocalCids,
    pub(crate) peer: PeerCids,
}

impl Cids {
    fn frame(&self, cand: CidCand) -> Option<Frame<'static>> {
        let varint = |value: u64| VarInt::from_u64(value).unwrap_or(VarInt::MAX);
        match cand {
            CidCand::New(seq) => {
                let issued = self.local.issued.iter().find(|issued| issued.seq == seq)?;
                Some(Frame::NewConnectionId {
                    seq: varint(seq),
                    retire_prior_to: VarInt::ZERO,
                    cid: issued.cid,
                    reset_token: issued.token,
                })
            }
            CidCand::Retire(seq) => Some(Frame::RetireConnectionId { seq: varint(seq) }),
        }
    }

    /// Returns the delivery state of the frame of `kind` for sequence number `seq`.
    fn delivery(&mut self, kind: ControlKind, seq: u64) -> Option<&mut Delivery> {
        match kind {
            ControlKind::NewConnectionId => {
                self.local.by_seq(seq).map(|issued| &mut issued.delivery)
            }
            ControlKind::RetireConnectionId => self
                .peer
                .retiring
                .iter_mut()
                .find(|(retired, _)| *retired == seq)
                .map(|(_, delivery)| delivery),
            _ => None,
        }
    }

    /// Records that a NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame for `seq` was sealed.
    pub(crate) fn on_sealed(&mut self, kind: ControlKind, seq: u64) {
        if kind == ControlKind::NewConnectionId {
            self.local.sent = self.local.sent.max(seq);
        }
    }

    /// Records that a NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame for `seq` was acknowledged.
    pub(crate) fn on_acked(&mut self, kind: ControlKind, seq: u64) {
        if kind == ControlKind::RetireConnectionId {
            self.peer.retiring.retain(|(retired, _)| *retired != seq);
        } else if let Some(delivery) = self.delivery(kind, seq) {
            *delivery = Delivery::Delivered;
        }
    }

    /// Records that a NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame for `seq` was lost, or never
    /// sealed: it is pending again while its ID is still issued or still being retired. Returns
    /// whether it became pending again.
    pub(crate) fn on_lost(&mut self, kind: ControlKind, seq: u64) -> bool {
        if let Some(delivery) = self.delivery(kind, seq)
            && *delivery == Delivery::InFlight
        {
            *delivery = Delivery::Pending;
            return true;
        }
        false
    }
}

impl FrameSource for Cids {
    type Cand = CidCand;

    fn next(&self, cx: &SendCx<'_>) -> Option<(Class, CidCand)> {
        if cx.space != Space::Data {
            return None;
        }
        let cand = match self.local.pending() {
            Some(issued) => CidCand::New(issued.seq),
            None => CidCand::Retire(self.peer.pending_retire()?),
        };
        Some((Class::Control, cand))
    }

    fn min_len(&self, cand: CidCand, _cx: &SendCx<'_>) -> usize {
        self.frame(cand).map_or(0, |frame| frame.encoded_len())
    }

    fn write(
        &mut self,
        cand: CidCand,
        w: &mut PacketWriter<'_>,
        cx: &mut SendCx<'_>,
    ) -> Result<(), Full> {
        let frame = self.frame(cand).ok_or(Full)?;
        w.frame(&frame).map_err(|_| Full)?;
        let (kind, seq) = match cand {
            CidCand::New(seq) => (ControlKind::NewConnectionId, seq),
            CidCand::Retire(seq) => (ControlKind::RetireConnectionId, seq),
        };
        if let Some(delivery) = self.delivery(kind, seq) {
            *delivery = Delivery::InFlight;
        }
        cx.sent.push(SentFrame::Control {
            kind,
            key: seq,
            value: 0,
        });
        Ok(())
    }
}

impl std::fmt::Debug for CidGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CidGenerator")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::collections::HashSet;
    use std::hash::DefaultHasher;
    use std::hash::Hash;
    use std::hash::Hasher;
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use super::*;
    use crate::sources::path::ALTERNATE;
    use crate::testing::TestRng;

    fn generator(key: u8) -> CidGenerator {
        let config = EndpointConfig::builder([key; 32]).build().unwrap();
        CidGenerator::new(&config)
    }

    fn cid(bytes: &[u8]) -> ConnectionId {
        ConnectionId::new(bytes).unwrap()
    }

    fn token(byte: u8) -> ResetToken {
        ResetToken([byte; ResetToken::LEN])
    }

    fn code(result: Result<impl std::fmt::Debug, ConnError>) -> TransportErrorCode {
        result.expect_err("a connection error").code
    }

    /// Returns connection IDs whose local handshake ID is `[0; 8]` and the peer's `[100; 8]`, with
    /// an active_connection_id_limit of `limit`.
    fn cids(limit: u64) -> Cids {
        Cids {
            local: LocalCids::new(cid(&[0; 8]), token(0)),
            peer: PeerCids::new(cid(&[100; 8]), limit),
        }
    }

    /// Returns the candidate the Control source would take from `cids` in a 1-RTT packet.
    fn due(cids: &Cids) -> Option<CidCand> {
        let mut sent = Vec::new();
        let cx = send_cx(&mut sent);
        cids.next(&cx).map(|(class, cand)| {
            assert_eq!(class, Class::Control);
            cand
        })
    }

    fn send_cx(sent: &mut Vec<SentFrame>) -> SendCx<'_> {
        SendCx {
            now: crate::recovery::test_epoch(),
            release: crate::recovery::test_epoch(),
            space: Space::Data,
            path: crate::PathId(0),
            probes_due: 0,
            ack_delay_exponent: 3,
            packet: crate::sources::PacketCx::default(),
            sent,
        }
    }

    /// Writes the due candidate into a packet; returns the frame's bytes and its record.
    fn write(cids: &mut Cids) -> (Frame<'static>, SentFrame) {
        let mut sent = Vec::new();
        let mut cx = send_cx(&mut sent);
        let (_, cand) = cids.next(&cx).expect("a frame is due");
        let frame = cids.frame(cand).unwrap();
        let mut buf = vec![0; 200];
        let header = mvfstr_wire::HeaderSpec::OneRtt {
            dcid: cid(&[1; 8]),
            spin: false,
            key_phase: false,
        };
        let mut w = PacketWriter::new(&mut buf, header, 0, 4, mvfstr_crypto::TAG_LEN).unwrap();
        cids.write(cand, &mut w, &mut cx).unwrap();
        (frame, sent.remove(0))
    }

    fn seq_of(record: SentFrame) -> (ControlKind, u64) {
        let SentFrame::Control { kind, key, .. } = record else {
            panic!("a control record");
        };
        (kind, key)
    }

    #[test]
    fn connection_rngs_follow_their_seed_and_never_repeat() {
        let draw = |rng: &mut ConnRng| {
            let mut out = [0; 20];
            rng.fill(&mut out);
            out
        };
        let mut a = ConnRng::new([1; 32]);
        let mut b = ConnRng::new([1; 32]);
        let mut c = ConnRng::new([2; 32]);
        let first = draw(&mut a);
        assert_eq!(first, draw(&mut b));
        assert_ne!(first, draw(&mut c));
        assert_ne!(first, draw(&mut a));
        assert_ne!(first, [0; 20]);
    }

    #[test]
    fn issued_ids_are_sent_until_acknowledged_and_again_when_lost() {
        let mut cids = cids(2);
        assert_eq!(due(&cids), None, "the handshake ID needs no frame");
        let seq = cids.local.issue(cid(&[1; 8]), token(1));
        assert_eq!(seq, 1);
        assert_eq!(cids.local.active(), 2);
        assert_eq!(due(&cids), Some(CidCand::New(1)));
        let (frame, record) = write(&mut cids);
        assert_eq!(
            frame,
            Frame::NewConnectionId {
                seq: VarInt::from_u32(1),
                retire_prior_to: VarInt::ZERO,
                cid: cid(&[1; 8]),
                reset_token: token(1),
            }
        );
        assert_eq!(seq_of(record), (ControlKind::NewConnectionId, 1));
        assert_eq!(due(&cids), None, "in flight");
        cids.on_lost(ControlKind::NewConnectionId, 1);
        assert_eq!(due(&cids), Some(CidCand::New(1)), "lost, so due again");
        write(&mut cids);
        cids.on_acked(ControlKind::NewConnectionId, 1);
        cids.on_lost(ControlKind::NewConnectionId, 1);
        assert_eq!(due(&cids), None, "the peer has it");
    }

    /// A random source that gives zeros for its first `zeros` fills and ones after.
    struct Zeros(usize);

    impl Random for Zeros {
        fn fill(&mut self, dest: &mut [u8]) {
            let byte = if self.0 > 0 { 0 } else { 1 };
            self.0 = self.0.saturating_sub(1);
            dest.fill(byte);
        }
    }

    #[test]
    fn a_new_id_is_never_one_already_issued() {
        let generator = generator(7);
        let mut cids = cids(4);
        let (fresh, reset_token) = cids
            .local
            .issue_new(&generator, &mut Zeros(2))
            .expect("an ID after two draws of the handshake ID");
        assert_eq!(fresh, cid(&[1; 8]));
        assert_eq!(reset_token, generator.reset_token(&fresh));
        assert_eq!(cids.local.active(), 2);
        assert_eq!(
            cids.local.issue_new(&generator, &mut Zeros(usize::MAX)),
            None,
            "a source that only repeats an issued ID issues nothing"
        );
        assert_eq!(cids.local.active(), 2);
    }

    #[test]
    fn the_peer_cannot_retire_an_id_it_was_never_sent() {
        let mut cids = cids(4);
        let dcid = cid(&[0; 8]);
        cids.local.issue(cid(&[1; 8]), token(1));
        assert_eq!(
            code(cids.local.retire(1, &dcid)),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "issued, not sent"
        );
        let (_, record) = write(&mut cids);
        assert_eq!(
            code(cids.local.retire(1, &dcid)),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "in a packet not sealed"
        );
        let (kind, seq) = seq_of(record);
        cids.on_sealed(kind, seq);
        assert_eq!(cids.local.retire(1, &dcid), Ok(Some(cid(&[1; 8]))));
    }

    #[test]
    fn the_peer_retires_issued_ids_but_not_others() {
        let mut cids = cids(2);
        cids.local.issue(cid(&[1; 8]), token(1));
        cids.local.issue(cid(&[2; 8]), token(2));
        let (_, record) = write(&mut cids);
        let (kind, seq) = seq_of(record);
        cids.on_sealed(kind, seq);
        let dcid = cid(&[0; 8]);
        assert_eq!(
            code(cids.local.retire(3, &dcid)),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "never issued"
        );
        assert_eq!(
            code(cids.local.retire(0, &dcid)),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "the ID the packet was sent to"
        );
        assert_eq!(cids.local.retire(1, &dcid), Ok(Some(cid(&[1; 8]))));
        assert_eq!(cids.local.active(), 2);
        assert_eq!(cids.local.retire(1, &dcid), Ok(None), "retired before");
        // The retired ID's NEW_CONNECTION_ID, lost, is not sent again.
        cids.on_lost(ControlKind::NewConnectionId, 1);
        assert_eq!(due(&cids), Some(CidCand::New(2)));
        let (_, record) = write(&mut cids);
        let (kind, seq) = seq_of(record);
        cids.on_sealed(kind, seq);
        assert_eq!(due(&cids), None);
        assert_eq!(cids.local.retire(0, &cid(&[2; 8])), Ok(Some(cid(&[0; 8]))));
    }

    #[test]
    fn peer_ids_join_up_to_the_limit_and_must_not_contradict_each_other() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        assert_eq!(peer.on_new(1, 0, cid(&[101; 8]), token(1)), Ok(false));
        assert_eq!(peer.active(), 2);
        assert_eq!(
            peer.on_new(1, 0, cid(&[101; 8]), token(1)),
            Ok(false),
            "a repeated frame changes nothing"
        );
        assert_eq!(
            code(peer.on_new(2, 0, cid(&[102; 8]), token(2))),
            TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
        );
        let mut peer = PeerCids::new(cid(&[100; 8]), 4);
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert_eq!(
            code(peer.on_new(1, 0, cid(&[109; 8]), token(1))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "one sequence number, two IDs"
        );
        assert_eq!(
            code(peer.on_new(1, 0, cid(&[101; 8]), token(9))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "one ID, two tokens"
        );
        assert_eq!(
            code(peer.on_new(2, 0, cid(&[101; 8]), token(1))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "one ID, two sequence numbers"
        );
        let mut empty = PeerCids::new(ConnectionId::EMPTY, 4);
        assert_eq!(
            code(empty.on_new(1, 0, cid(&[101; 8]), token(1))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "a peer with a zero-length ID sends no NEW_CONNECTION_ID"
        );
    }

    #[test]
    fn retire_prior_to_retires_older_ids_and_moves_the_one_in_use() {
        let mut cids = cids(4);
        cids.peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert_eq!(due(&cids), None);
        assert_eq!(cids.peer.on_new(2, 2, cid(&[102; 8]), token(2)), Ok(true));
        assert_eq!(cids.peer.current(), Some((cid(&[102; 8]), Some(token(2)))));
        assert_eq!(cids.peer.active(), 1);
        assert_eq!(due(&cids), Some(CidCand::Retire(0)));
        let (frame, record) = write(&mut cids);
        assert_eq!(frame, Frame::RetireConnectionId { seq: VarInt::ZERO });
        assert_eq!(seq_of(record), (ControlKind::RetireConnectionId, 0));
        assert_eq!(due(&cids), Some(CidCand::Retire(1)));
        write(&mut cids);
        assert_eq!(due(&cids), None);
        cids.on_lost(ControlKind::RetireConnectionId, 0);
        assert_eq!(due(&cids), Some(CidCand::Retire(0)), "lost, so due again");
        write(&mut cids);
        cids.on_acked(ControlKind::RetireConnectionId, 0);
        cids.on_lost(ControlKind::RetireConnectionId, 0);
        assert_eq!(due(&cids), None);
        // A copy of the frame of an ID that Retire Prior To retired is ignored.
        assert_eq!(cids.peer.on_new(1, 0, cid(&[101; 8]), token(1)), Ok(false));
        assert_eq!(cids.peer.active(), 1);
        cids.on_acked(ControlKind::RetireConnectionId, 1);
        cids.peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert_eq!(due(&cids), None, "retired before");
        // A lower Retire Prior To does not change the ID in use.
        assert_eq!(cids.peer.on_new(3, 1, cid(&[103; 8]), token(3)), Ok(false));
        assert_eq!(cids.peer.current(), Some((cid(&[102; 8]), Some(token(2)))));
        // An ID that Retire Prior To passes before its frame arrives is retired then, and the
        // frame is ignored.
        assert_eq!(cids.peer.on_new(5, 5, cid(&[105; 8]), token(5)), Ok(true));
        assert_eq!(cids.peer.on_new(4, 0, cid(&[104; 8]), token(4)), Ok(false));
        assert_eq!(cids.peer.active(), 1);
        let retiring: Vec<_> = std::iter::from_fn(|| {
            let cand = due(&cids)?;
            write(&mut cids);
            Some(cand)
        })
        .collect();
        assert_eq!(
            retiring,
            [CidCand::Retire(2), CidCand::Retire(3), CidCand::Retire(4)]
        );
    }

    #[test]
    fn a_repeated_new_connection_id_does_not_bring_back_an_id_retired_for_a_path() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert!(peer.open_alt(true));
        peer.drop_alt();
        assert_eq!(
            peer.on_new(1, 0, cid(&[101; 8]), token(1)),
            Ok(false),
            "the same frame again"
        );
        assert!(
            !peer.has_unused(),
            "a retired ID is not used again, as RFC 9000 requires"
        );
        assert_eq!(
            peer.on_new(2, 0, cid(&[102; 8]), token(2)),
            Ok(false),
            "the replacement fits the limit"
        );
        assert_eq!(peer.active(), 2);
    }

    #[test]
    fn a_path_left_without_a_usable_id_waits_for_the_next_new_one() {
        // The alternate path's own ID 1 is retired when the path is dropped, and a repeat of
        // its frame with Retire Prior To 1 retires ID 0, the one in use.
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert!(peer.open_alt(true));
        peer.drop_alt();
        assert_eq!(peer.on_new(1, 1, cid(&[101; 8]), token(1)), Ok(true));
        assert_eq!(peer.current(), None, "no ID to send with");
        assert_eq!(peer.on_new(2, 1, cid(&[102; 8]), token(2)), Ok(true));
        assert_eq!(peer.current(), Some((cid(&[102; 8]), Some(token(2)))));
        // The same after a failed move under a new ID: back on ID 0, with ID 1 retired.
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert!(peer.move_current(true));
        peer.swap_alt();
        peer.drop_alt();
        assert_eq!(peer.on_new(1, 1, cid(&[101; 8]), token(1)), Ok(true));
        assert_eq!(peer.current(), None, "no ID to send with");
    }

    #[test]
    fn a_waiting_current_path_never_takes_the_alternate_paths_id() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert!(peer.open_alt(true));
        // Retire Prior To 1 retires ID 0, the current path's, and leaves the alternate path's.
        assert_eq!(peer.on_new(1, 1, cid(&[101; 8]), token(1)), Ok(true));
        assert_eq!(
            peer.cid_of(CURRENT),
            None,
            "it waits for a fresh one, as RFC 9000 requires"
        );
        assert_eq!(peer.cid_of(ALTERNATE), Some(cid(&[101; 8])));
        peer.on_new(2, 1, cid(&[102; 8]), token(2)).unwrap();
        assert_eq!(peer.cid_of(CURRENT), Some(cid(&[102; 8])));
        assert_eq!(peer.cid_of(ALTERNATE), Some(cid(&[101; 8])));
    }

    #[test]
    fn every_path_shares_a_zero_length_peer_id() {
        let peer = PeerCids::new(ConnectionId::EMPTY, 2);
        assert_eq!(
            peer.own_id_for(true),
            Some(false),
            "a zero-length ID is used on every path, as RFC 9000 requires"
        );
        let peer = PeerCids::new(cid(&[100; 8]), 2);
        assert_eq!(peer.own_id_for(true), None, "no unused ID for the path");
    }

    /// One step of the table test over `PeerCids`: a frame from the peer, or a path change.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// NEW_CONNECTION_ID with sequence number `seq` and Retire Prior To `rpt`, its ID and
        /// token following from `seq` as an honest peer's would.
        New { seq: u64, rpt: u64 },
        /// A probe from a new address, under another of this endpoint's IDs if `changed`.
        Probe { changed: bool },
        /// A move under a new connection ID; the old path stays as the alternate one if
        /// `keep_old`.
        Move { keep_old: bool },
        /// The connection goes back to the alternate path.
        Promote,
        /// The alternate path is abandoned.
        Abandon,
        /// Every pending RETIRE_CONNECTION_ID is acknowledged.
        Ack,
    }

    /// The peer's IDs as the table test drives them, with the facts it tracks besides their state:
    /// the sequence numbers the peer sent and the retirements acknowledged.
    #[derive(Clone)]
    struct Walk {
        cids: Cids,
        sent: BTreeSet<u64>,
        acked: BTreeSet<u64>,
        /// The peer's ID is zero-length.
        zero_length: bool,
    }

    impl Walk {
        /// Applies `step` as the connection would; returns false if the connection closes.
        fn apply(&mut self, step: Step) -> bool {
            let peer = &mut self.cids.peer;
            match step {
                Step::New { seq, rpt } => {
                    self.sent.insert(seq);
                    let byte = 100 + u8::try_from(seq).unwrap();
                    if peer.on_new(seq, rpt, cid(&[byte; 8]), token(byte)).is_err() {
                        return false;
                    }
                }
                Step::Probe { changed } => {
                    if let Some(own) = peer.own_id_for(changed) {
                        peer.drop_alt();
                        peer.open_alt(own);
                    }
                }
                Step::Move { keep_old } => match peer.own_id_for(true) {
                    Some(true) => {
                        peer.move_current(keep_old);
                    }
                    // A move that keeps the ID is a rebinding.
                    Some(false) if keep_old => {
                        peer.open_alt(false);
                    }
                    Some(false) | None => {}
                },
                Step::Promote => peer.swap_alt(),
                Step::Abandon => peer.drop_alt(),
                Step::Ack => {
                    while let Some(seq) = self.cids.peer.pending_retire() {
                        self.cids.on_acked(ControlKind::RetireConnectionId, seq);
                        self.acked.insert(seq);
                    }
                }
            }
            self.cids.peer.retire_bound().is_ok()
        }

        /// Checks the invariants of the peer's IDs and the paths that send with them after the
        /// steps of `trail`, which `before` led up to.
        fn check(&self, before: &Walk, trail: &[Step]) {
            let peer = &self.cids.peer;
            let promoted = matches!(trail.last(), Some(Step::Promote));
            if promoted && before.cids.peer.has_alt() {
                assert_eq!(
                    peer.cid_of(CURRENT),
                    before.cids.peer.cid_of(ALTERNATE),
                    "{trail:?}: the paths trade IDs, or the lack of one"
                );
            }
            if before.cids.peer.alt_has_own() && !promoted {
                assert_ne!(
                    before.cids.peer.cid_of(ALTERNATE),
                    peer.cid_of(CURRENT),
                    "{trail:?}: the current path never takes the alternate path's ID"
                );
            }
            if before.cids.peer.alt_shares() && peer.alt_shares() {
                assert_eq!(
                    before.cids.peer.cid_of(CURRENT),
                    peer.cid_of(CURRENT),
                    "{trail:?}: a shared ID stays the one the paths shared"
                );
            }
            let ids = peer.ids();
            assert!(
                ids.len() as u64 <= peer.limit,
                "{trail:?}: within the limit"
            );
            let active: BTreeSet<_> = ids.iter().map(|(seq, _, _)| *seq).collect();
            for seq in &self.sent {
                let retired = peer.retiring.iter().any(|(retired, _)| retired == seq)
                    || self.acked.contains(seq);
                assert_ne!(
                    active.contains(seq),
                    retired,
                    "{trail:?}: ID {seq} is either active or retired with RETIRE_CONNECTION_ID"
                );
            }
            let current = peer.cid_of(CURRENT);
            let alt = peer.has_alt().then(|| peer.cid_of(ALTERNATE));
            for path in [current, alt.flatten()].into_iter().flatten() {
                assert!(
                    ids.iter().any(|(_, cid, _)| *cid == path),
                    "{trail:?}: a path sends with an active ID"
                );
            }
            if peer.alt_shares() {
                assert!(current.is_some(), "{trail:?}: only an ID in use is shared");
            } else if let (Some(current), Some(Some(alt))) = (current, alt) {
                assert_ne!(current, alt, "{trail:?}: no ID on two paths");
            }
            let waiting = current.is_none() || alt == Some(None);
            assert!(
                !(waiting && peer.has_unused()),
                "{trail:?}: no path waits while an ID is unused"
            );
            if self.zero_length {
                // As RFC 9000 requires, the zero-length ID serves every path and is never retired.
                assert_eq!(
                    peer.cid_of(CURRENT),
                    Some(ConnectionId::EMPTY),
                    "{trail:?}: the current path never waits"
                );
                if peer.has_alt() {
                    assert_eq!(
                        peer.cid_of(ALTERNATE),
                        Some(ConnectionId::EMPTY),
                        "{trail:?}: nor does the alternate path"
                    );
                }
                assert!(peer.retiring.is_empty(), "{trail:?}: nothing is retired");
                if matches!(trail.last(), Some(Step::Probe { .. })) {
                    assert!(peer.has_alt(), "{trail:?}: every probe is answered");
                }
            }
            let _ = (
                peer.current(),
                peer.token_of(CURRENT),
                peer.token_of(ALTERNATE),
            );
        }

        /// Returns whether `step` is a copy of a frame the peer sent before, which does not raise
        /// Retire Prior To and so must leave the state unchanged (RFC 9000).
        fn repeats(&self, step: Step) -> bool {
            let Step::New { seq, rpt } = step else {
                return false;
            };
            self.sent.contains(&seq) && rpt <= self.cids.peer.retire_prior_to
        }

        fn key(&self) -> u64 {
            let mut h = DefaultHasher::new();
            (&self.cids.peer, &self.sent, &self.acked).hash(&mut h);
            h.finish()
        }
    }

    #[test]
    fn every_short_sequence_of_peer_frames_and_path_changes_keeps_the_peer_ids_consistent() {
        let mut steps: Vec<Step> = (1..=5u64)
            .flat_map(|seq| {
                BTreeSet::from([0, seq - 1, seq])
                    .into_iter()
                    .map(move |rpt| Step::New { seq, rpt })
            })
            .collect();
        steps.extend([
            Step::Probe { changed: true },
            Step::Probe { changed: false },
            Step::Move { keep_old: true },
            Step::Move { keep_old: false },
            Step::Promote,
            Step::Abandon,
            Step::Ack,
        ]);
        let start = Walk {
            cids: cids(2),
            sent: BTreeSet::from([0]),
            acked: BTreeSet::new(),
            zero_length: false,
        };
        let mut zero_length = Walk {
            zero_length: true,
            ..start.clone()
        };
        zero_length.cids.peer = PeerCids::new(ConnectionId::EMPTY, 2);
        // After a long history, each frame of which retired the ID before it, acknowledged: the
        // steps' frames are then copies of frames whose IDs were retired long ago.
        let mut history = start.clone();
        for seq in 1..=12 {
            assert!(history.apply(Step::New { seq, rpt: seq }));
            assert!(history.apply(Step::Ack));
        }
        let mut seen = HashSet::from([start.key(), zero_length.key(), history.key()]);
        let mut frontier = vec![
            (start, Vec::new()),
            (zero_length, Vec::new()),
            (history, Vec::new()),
        ];
        // Each distinct state is expanded once, so seven steps stay cheap.
        for _ in 0..7 {
            let mut next = Vec::new();
            for (walk, trail) in &frontier {
                for &step in &steps {
                    let mut after = walk.clone();
                    let mut trail = trail.clone();
                    trail.push(step);
                    let open = catch_unwind(AssertUnwindSafe(|| after.apply(step)))
                        .unwrap_or_else(|_| panic!("{trail:?}: no panic"));
                    if walk.repeats(step) {
                        assert!(open, "{trail:?}: a copy of an earlier frame is no error");
                        assert_eq!(
                            format!("{:?}", after.cids.peer),
                            format!("{:?}", walk.cids.peer),
                            "{trail:?}: a copy of an earlier frame changes nothing"
                        );
                    }
                    if !open {
                        continue;
                    }
                    after.check(walk, &trail);
                    let walk = after;
                    if seen.insert(walk.key()) {
                        next.push((walk, trail));
                    }
                }
            }
            frontier = next;
        }
        assert!(seen.len() > 1000, "{} states", seen.len());
    }

    #[test]
    fn ids_retired_for_paths_stay_retired_however_many_follow_and_overtaken_ones_still_join() {
        let mut cids = cids(2);
        // Each new ID takes over the current path and the one before is retired, acknowledged.
        for seq in 1..=8u8 {
            let seq64 = u64::from(seq);
            cids.peer
                .on_new(seq64, 0, cid(&[100 + seq; 8]), token(seq))
                .unwrap();
            assert!(cids.peer.move_current(false));
            write(&mut cids);
            cids.on_acked(ControlKind::RetireConnectionId, seq64 - 1);
        }
        assert_eq!(
            cids.peer.on_new(1, 0, cid(&[101; 8]), token(1)),
            Ok(false),
            "a late copy of an early frame"
        );
        assert!(
            !cids.peer.has_unused(),
            "a retired ID is not used again, as RFC 9000 requires"
        );
        // A frame overtaken by a later one is a new ID, not a retired one.
        let mut peer = PeerCids::new(cid(&[100; 8]), 4);
        peer.on_new(2, 0, cid(&[102; 8]), token(2)).unwrap();
        peer.on_new(1, 0, cid(&[101; 8]), token(1)).unwrap();
        assert_eq!(peer.active(), 3);
    }

    #[test]
    fn repeats_below_retire_prior_to_change_nothing_however_long_ago_their_ids_were_retired() {
        let mut cids = cids(2);
        // Each frame retires the ID before it, and every retirement is acknowledged.
        for seq in 1..=12u8 {
            let seq64 = u64::from(seq);
            cids.peer
                .on_new(seq64, seq64, cid(&[100 + seq; 8]), token(seq))
                .unwrap();
            write(&mut cids);
            cids.on_acked(ControlKind::RetireConnectionId, seq64 - 1);
        }
        assert_eq!(due(&cids), None);
        // As RFC 9000 requires, copies of earlier frames, all in one round trip, are not an error
        // and do not retire an ID again.
        for seq in 1..=5u8 {
            let seq64 = u64::from(seq);
            assert_eq!(
                cids.peer
                    .on_new(seq64, seq64, cid(&[100 + seq; 8]), token(seq)),
                Ok(false),
                "a late copy of frame {seq}"
            );
        }
        assert_eq!(due(&cids), None, "retired before");
        assert_eq!(cids.peer.ids(), [(12, cid(&[112; 8]), Some(token(12)))]);
    }

    #[test]
    fn numbers_retire_prior_to_passes_before_their_ids_arrive_are_retired_once() {
        let mut cids = cids(2);
        cids.peer.on_new(2, 0, cid(&[102; 8]), token(2)).unwrap();
        // Retire Prior To 4 passes 1, still to come, and 3, above the largest received, as well
        // as the active 0 and 2: the peer issued all of them.
        assert_eq!(cids.peer.on_new(5, 4, cid(&[105; 8]), token(5)), Ok(true));
        let mut retired = Vec::new();
        while let Some(CidCand::Retire(seq)) = due(&cids) {
            write(&mut cids);
            retired.push(seq);
        }
        retired.sort_unstable();
        assert_eq!(retired, [0, 1, 2, 3]);
        for seq in retired {
            cids.on_acked(ControlKind::RetireConnectionId, seq);
        }
        // Their frames, arriving late, first 1 and 3 and then all again, are ignored.
        for seq in [1u8, 3, 1, 2, 3] {
            assert_eq!(
                cids.peer
                    .on_new(u64::from(seq), 0, cid(&[100 + seq; 8]), token(seq)),
                Ok(false),
                "frame {seq}"
            );
            assert_eq!(due(&cids), None, "frame {seq}: retired before");
        }
        assert_eq!(cids.peer.active(), 1);
        assert_eq!(
            cids.peer.on_new(4, 4, cid(&[104; 8]), token(4)),
            Ok(false),
            "4 was still to come"
        );
        assert_eq!(cids.peer.active(), 2);
    }

    #[test]
    fn a_peer_cannot_leave_more_sequence_numbers_unsent_than_the_limit() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        assert_eq!(
            peer.on_new(3, 0, cid(&[103; 8]), token(3)),
            Ok(false),
            "1 and 2 still to come"
        );
        // Every number from Retire Prior To up to the largest was issued and the missing ones were
        // not retired, so the peer has given more IDs than the limit allows.
        assert_eq!(
            code(peer.on_new(10, 2, cid(&[110; 8]), token(10))),
            TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
        );
    }

    #[test]
    fn numbers_still_to_come_below_retire_prior_to_no_longer_count() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_new(3, 0, cid(&[103; 8]), token(3)).unwrap();
        // Retire Prior To 3 retires 1 and 2 before they arrive, as well as 0.
        peer.on_new(4, 3, cid(&[104; 8]), token(4)).unwrap();
        assert_eq!(
            peer.on_new(6, 4, cid(&[106; 8]), token(6)),
            Ok(true),
            "5 is the only number still to come"
        );
    }

    #[test]
    fn unacknowledged_retirements_are_bounded_at_twice_the_limit() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        // Each frame retires the ID before it, and the retirements stay unacknowledged.
        for seq in 1..=4 {
            let byte = 100 + u8::try_from(seq).unwrap();
            assert_eq!(
                peer.on_new(seq, seq, cid(&[byte; 8]), token(byte)),
                Ok(true)
            );
        }
        assert_eq!(
            code(peer.on_new(5, 5, cid(&[105; 8]), token(105))),
            TransportErrorCode::PROTOCOL_VIOLATION
        );
    }

    #[test]
    fn a_retire_prior_to_that_retires_more_than_twice_the_limit_at_once_closes_the_connection() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        assert_eq!(
            peer.on_new(4, 4, cid(&[104; 8]), token(4)),
            Ok(true),
            "0 to 3, four retirements"
        );
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        assert_eq!(
            code(peer.on_new(5, 5, cid(&[105; 8]), token(5))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "0 to 4, five retirements, though only 0 arrived"
        );
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        let far = VarInt::MAX.into_inner();
        assert_eq!(
            code(peer.on_new(far, far, cid(&[109; 8]), token(9))),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "the largest jump fails as quickly"
        );
    }

    #[test]
    fn no_limit_the_config_accepts_lets_one_frame_panic_or_fill_memory() {
        let far = VarInt::MAX.into_inner();
        let cap = TransportConfig::MAX_ACTIVE_CONNECTION_ID_LIMIT;
        for limit in [2, cap, cap + 1, 1 << 20, far] {
            let Ok(config) = TransportConfig::builder()
                .active_connection_id_limit(limit)
                .build()
            else {
                continue;
            };
            let limit = config.active_connection_id_limit();
            for retire_prior_to in [0, far] {
                let mut peer = PeerCids::new(cid(&[100; 8]), limit);
                assert!(
                    peer.on_new(far, retire_prior_to, cid(&[109; 8]), token(9))
                        .is_err(),
                    "limit {limit}, Retire Prior To {retire_prior_to}"
                );
                assert!(
                    peer.missing.is_empty() && peer.retiring.is_empty(),
                    "limit {limit}, Retire Prior To {retire_prior_to}"
                );
            }
        }
    }

    #[test]
    fn server_parameters_give_the_handshake_token_and_the_preferred_id() {
        let mut peer = PeerCids::new(cid(&[100; 8]), 2);
        peer.on_server_params(Some(token(7)), Some((cid(&[101; 8]), token(1))));
        assert_eq!(peer.current(), Some((cid(&[100; 8]), Some(token(7)))));
        assert_eq!(
            peer.active(),
            2,
            "the preferred address's ID is sequence number 1"
        );
        assert_eq!(
            peer.on_new(1, 0, cid(&[101; 8]), token(1)),
            Ok(false),
            "the same ID again"
        );
        assert_eq!(
            code(peer.on_new(2, 0, cid(&[102; 8]), token(2))),
            TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
        );
    }

    #[test]
    fn issued_ids_name_their_worker_and_vary_in_every_byte() {
        let config = EndpointConfig::builder([7; 32])
            .worker(3, 5)
            .build()
            .unwrap();
        let generator = CidGenerator::new(&config);
        let mut rng = TestRng::new(1);
        let ids: Vec<_> = (0..200).map(|_| generator.generate(&mut rng)).collect();
        for id in &ids {
            assert_eq!(id.len(), 8);
            assert_eq!(generator.worker_of(id), Some(3), "{id}");
        }
        for byte in 0..8 {
            let distinct: BTreeSet<_> = ids.iter().map(|id| id[byte]).collect();
            assert!(
                distinct.len() > 10,
                "byte {byte} takes {} values",
                distinct.len()
            );
        }
        assert_eq!(
            generator.worker_of(&[]),
            None,
            "a zero-length ID names no worker"
        );
        let single = CidGenerator::new(&EndpointConfig::builder([7; 32]).build().unwrap());
        assert_eq!(single.worker_of(&ids[0]), None);
    }

    #[test]
    fn reset_tokens_depend_on_the_key_and_the_connection_id_alone() {
        let a = cid(&[1; 8]);
        let b = cid(&[2; 8]);
        assert_eq!(
            generator(7).reset_token(&a),
            generator(7).reset_token(&a),
            "an endpoint that lost its state derives the same token"
        );
        assert_ne!(generator(7).reset_token(&a), generator(7).reset_token(&b));
        assert_ne!(generator(7).reset_token(&a), generator(8).reset_token(&a));
        assert_ne!(
            generator(7).reset_token(&cid(&[1; 7])),
            generator(7).reset_token(&cid(&[1; 8])),
            "a prefix is another ID"
        );
    }
}
