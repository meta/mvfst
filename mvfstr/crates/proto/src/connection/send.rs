/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The transmit attempt.
//!
//! Each datagram starts with the first candidate the admission table lets start, scanning the
//! spaces in order and the sources in their fixed order. A start is charged the packet its
//! candidate needs, so the credit that admits it holds it. Its slot is taken from the sink
//! before any packet number, then a packet is built for the start's space and for each later
//! space with a candidate that may join, coalesced in one datagram (RFC 9000), in the room the
//! start's packet leaves. Only a sealed datagram commits anything: packet numbers, sent-packet
//! records, ACK and CLOSE state, the path's amplification credit. When a datagram ends up empty,
//! its slot goes back and its start's source is skipped for the rest of the attempt; the
//! attempt then ends `Inconsistent` if it did not send any datagram.
//!
//! The datagram is bounded by the path's anti-amplification credit before validation, so every
//! byte sent is charged. A client pads every datagram carrying an Initial packet, and a server
//! every datagram carrying an ack-eliciting one, to 1,200 bytes, as RFC 9000 requires, with
//! PADDING in the datagram's last packet; earlier packets leave room for the later ones.

use std::fmt::Write as _;
use std::time::Duration;
use std::time::Instant;

use mvfstr_crypto::SealJob;
use mvfstr_crypto::Sealer;
use mvfstr_crypto::SlotId;
use mvfstr_crypto::TAG_LEN;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::HeaderSpec;
use mvfstr_wire::PacketLayout;
use mvfstr_wire::PacketWriter;
use mvfstr_wire::Side;
use mvfstr_wire::VarInt;
use mvfstr_wire::packet_number_len;

use super::Connection;
use super::MIN_DATAGRAM;
use super::State;
use crate::ClockEpoch;
use crate::PathId;
use crate::Prioritizer;
use crate::Release;
use crate::SegmentSink;
use crate::Stop;
use crate::TxClass;
use crate::TxExplain;
use crate::TxLimits;
use crate::TxMeta;
use crate::TxOutcome;
use crate::TxSeqRange;
use crate::cc::SentEvent;
use crate::recovery::SentFlags;
use crate::recovery::Space;
use crate::sources::Candidate;
use crate::sources::PacketCx;
use crate::sources::SendCx;
use crate::sources::SourceId;
use crate::transmit::admission::Blocked;
use crate::transmit::admission::Class;
use crate::transmit::admission::Gate;
use crate::transmit::admission::Start;
use crate::transmit::admission::may_join;
use crate::transmit::admission::may_start;

/// The alternate path, which carries only Path frames.
const ALT_PATH: PathId = PathId(1);

/// When a datagram is built, and when its run leaves.
#[derive(Clone, Copy, Debug)]
struct Times {
    now: Instant,
    release: Instant,
}

/// The candidate that starts a datagram; it fixes the datagram's path and first packet's space.
#[derive(Clone, Copy, Debug)]
struct StartCand {
    path: PathId,
    source: SourceId,
    space: Space,
    cand: Candidate,
}

/// What a scan for a start candidate found.
#[derive(Debug)]
struct Scan {
    start: Option<StartCand>,
    blocked: Blocked,
    /// Whether a candidate of a paced class may start, when the scan looked for one.
    paced: bool,
}

/// One packet built into the datagram.
#[derive(Clone, Copy, Debug)]
struct Built {
    space: Space,
    pn: u64,
    offset: usize,
    layout: PacketLayout,
    packet: PacketCx,
    ack_eliciting: bool,
    padded: bool,
    probe: bool,
}

/// The open GSO run: one release, and one pacer debit when it ends.
#[derive(Clone, Copy, Debug)]
struct Run {
    path: PathId,
    first_tx: u64,
    segments: u16,
    segment_size: u16,
    class: TxClass,
    /// When its datagrams leave.
    release: Instant,
    /// Whether it took its release from the pacer's clock, so that it holds at most a burst
    /// and the pacing gate stays open while it does.
    paced: bool,
    /// The datagrams the attempt had room for when it opened.
    room: u16,
    /// The bytes of its paced datagrams.
    paced_bytes: u64,
}

impl Run {
    /// Adds a datagram of `len` bytes, which takes pacing tokens if `paced`.
    fn add(&mut self, len: u16, paced: bool) {
        if self.segments == 0 {
            self.segment_size = len;
        }
        self.segments += 1;
        // An unpaced datagram does not take tokens, in a paced run too.
        if paced {
            self.paced_bytes += u64::from(len);
        }
    }

    /// Returns whether it is a paced run of `burst` datagrams, or of all the attempt had room for.
    fn is_full(&self, burst: u16) -> bool {
        self.paced && self.segments >= burst.min(self.room)
    }
}

/// The sources skipped for the rest of an attempt because their start did not fit.
#[derive(Clone, Copy, Debug, Default)]
struct Skipped([bool; SourceId::ORDER.len()]);

impl Skipped {
    fn contains(&self, id: SourceId) -> bool {
        self.0[id.index()]
    }

    fn any(&self) -> bool {
        self.0.contains(&true)
    }
}

/// What limits the candidates of a datagram besides the admission table: the sources skipped in
/// this attempt, whether the egress grant has room for the datagram, and the pacing gate.
#[derive(Clone, Copy, Debug)]
struct JoinLimits {
    skipped: Skipped,
    grant: bool,
    pacing: Option<Instant>,
}

/// What building one datagram did.
#[derive(Clone, Copy, Debug)]
enum Outcome {
    /// The datagram stayed empty, and the connection did not change.
    Empty,
    /// The sealer failed; the CRYPTO bytes written went back to their buffers as lost.
    Unsealed,
    /// The datagram was sealed and committed; `paced` if the connection is configured to pace
    /// and the datagram carries a paced packet but not a probe.
    Sent { len: u16, paced: bool },
}

impl<P: Prioritizer> Connection<P> {
    /// Makes one transmit attempt, as the module docs describe.
    pub(super) fn transmit<S: SegmentSink, Z: Sealer>(
        &mut self,
        lim: &TxLimits,
        sink: &mut S,
        sealer: &mut Z,
    ) -> TxOutcome {
        // A connection configured without pacing never paces, so its attempts run an instance whose
        // pacing checks fold away at compile time.
        if self.config.pacing() {
            self.attempt::<true, S, Z>(lim, sink, sealer)
        } else {
            self.attempt::<false, S, Z>(lim, sink, sealer)
        }
    }

    /// Makes the transmit attempt, with `PACES` true if the connection is configured to pace.
    fn attempt<const PACES: bool, S: SegmentSink, Z: Sealer>(
        &mut self,
        lim: &TxLimits,
        sink: &mut S,
        sealer: &mut Z,
    ) -> TxOutcome {
        #[cfg(debug_assertions)]
        let before = self.digest();
        #[cfg(debug_assertions)]
        let mut unsealed = false;
        let mut out = TxOutcome {
            datagrams: 0,
            bytes: 0,
            stop: Stop::Idle,
            pacing_at: None,
            ahead: None,
            due: false,
        };
        let mut skipped = Skipped::default();
        let mut run: Option<Run> = None;
        let seg_max = self.mtu.min(lim.max_datagram);
        let pacing = PACES && self.pacing_active();
        let horizon = self.horizon_within(lim);
        // With a horizon, every run carries its release in the backend's clock.
        let stamps = lim.epoch.filter(|_| !horizon.is_zero());
        loop {
            // A paced run holds the pacer's current burst: a send can change the rate (BBR3's
            // restart from idle) after the run opened. Only a pacing attempt opens paced runs.
            if pacing
                && run
                    .as_ref()
                    .is_some_and(|open| open.is_full(self.pacer.burst()))
            {
                self.end_run(sink, &mut run, stamps, lim.now, &mut out);
            }
            let in_paced_run = pacing && run.as_ref().is_some_and(|open| open.paced);
            let joins = JoinLimits {
                skipped,
                grant: u64::from(out.bytes) + u64::from(seg_max) <= u64::from(lim.max_bytes),
                // Only a connection configured to pace can become pacing-active during the
                // attempt (BBR3 once its initial window is out).
                pacing: if in_paced_run || !PACES {
                    None
                } else {
                    self.pacing_gate(lim.now, horizon)
                },
            };
            let predict = pacing && !in_paced_run;
            let alt = self
                .alt
                .is_some()
                .then(|| self.scan(lim.now, ALT_PATH, joins, predict, None))
                .filter(|alt| alt.start.is_some());
            let scan = alt.unwrap_or_else(|| self.scan(lim.now, PathId(0), joins, predict, None));
            let Some(start) = scan.start else {
                (out.stop, out.pacing_at) = self.classify(&scan.blocked);
                break;
            };
            if out.datagrams == lim.max_segments {
                out.stop = Stop::BatchFull;
                break;
            }
            let class = if start.cand.class.is_urgent() {
                TxClass::Urgent
            } else {
                TxClass::Data
            };
            // A run goes to one address. A paced run's scan skipped the pacing gate, so the next
            // run's start is looked for again.
            if let Some(&Run { path, paced, .. }) = run.as_ref()
                && path != start.path
            {
                self.end_run(sink, &mut run, stamps, lim.now, &mut out);
                if paced {
                    continue;
                }
            }
            // A paced datagram never joins an unpaced run.
            let paced = predict && scan.paced && !self.probing();
            if paced {
                self.end_run(sink, &mut run, stamps, lim.now, &mut out);
            }
            if run.is_none() {
                let room = lim.max_segments - out.datagrams;
                let release = if paced {
                    // Only an empty attempt opens a paced run without room for a full burst.
                    if room < self.pacer.burst() && out.datagrams > 0 {
                        out.stop = Stop::BatchFull;
                        break;
                    }
                    self.pacer.next_release(lim.now)
                } else {
                    self.pacer.unpaced_release(lim.now)
                };
                run = Some(Run {
                    path: start.path,
                    first_tx: self.tx_seq,
                    segments: 0,
                    segment_size: 0,
                    class,
                    release,
                    paced,
                    room,
                    paced_bytes: 0,
                });
            }
            // The slot comes before any packet number is taken.
            let Some((slot, buf)) = sink.next_segment(seg_max, class) else {
                out.stop = Stop::Socket;
                break;
            };
            let times = Times {
                now: lim.now,
                release: run.as_ref().map_or(lim.now, |open| open.release),
            };
            match self.build::<PACES, Z>(times, start, joins, slot, buf, sealer) {
                Outcome::Empty => {
                    sink.end_segment(0);
                    skipped.0[start.source.index()] = true;
                    self.stats.tx_inconsistent += 1;
                }
                Outcome::Unsealed => {
                    sink.end_segment(0);
                    #[cfg(debug_assertions)]
                    {
                        unsealed = true;
                    }
                    out.stop = Stop::Inconsistent;
                    break;
                }
                Outcome::Sent { len, paced } => {
                    sink.end_segment(len);
                    if let Some(open) = &mut run {
                        open.add(len, paced && pacing);
                    }
                    out.datagrams += 1;
                    out.bytes += u32::from(len);
                    // A segment shorter than the slot ends its run (the sink's slot contract).
                    if len < seg_max {
                        self.end_run(sink, &mut run, stamps, lim.now, &mut out);
                    }
                }
            }
        }
        self.end_run(sink, &mut run, stamps, lim.now, &mut out);
        if out.datagrams == 0 && skipped.any() {
            out.stop = Stop::Inconsistent;
        }
        self.app_limited = self.is_app_limited(out.stop);
        // Paced bytes that the backend still holds are pending transmissions, which keep the
        // connection from being marked application-limited, as in draft-ietf-ccwg-bbr-07.
        if self.recovery.takes_rate_samples()
            && self.limited_by_app()
            && !self.pacer.has_pending(lim.now)
        {
            self.recovery.mark_app_limited();
        }
        // Unless sealing failed, an attempt that did not send a datagram must not change the
        // state a later attempt reads.
        #[cfg(debug_assertions)]
        if out.datagrams == 0 && !unsealed {
            debug_assert_eq!(
                before,
                self.digest(),
                "an empty attempt changed the connection"
            );
        }
        out
    }

    /// Describes the next attempt: every candidate with its space, class and the admission
    /// table's verdict, the start the attempt would take, and the stop it would report once the
    /// remaining candidates may not start.
    pub(super) fn explain(&self, lim: &TxLimits) -> TxExplain {
        let mut detail = String::new();
        let joins = JoinLimits {
            skipped: Skipped::default(),
            grant: u64::from(self.mtu.min(lim.max_datagram)) <= u64::from(lim.max_bytes),
            pacing: self.pacing_gate(lim.now, self.horizon_within(lim)),
        };
        let scan = self.scan(lim.now, PathId(0), joins, false, Some(&mut detail));
        let (stop, pacing_at) = self.classify(&scan.blocked);
        if let Some(start) = scan.start {
            let _ = writeln!(
                detail,
                "starts with {:?} in {:?} as {:?}",
                start.source, start.space, start.cand.class
            );
        }
        TxExplain {
            stop,
            pacing_at,
            detail,
        }
    }

    /// Finds the first candidate that may start a datagram on `path` within `joins`, scanning every
    /// space and the sources in order, and records what blocked each candidate it scanned; with
    /// `detail` it scans them all. With `find_paced`, it scans on until a candidate of a paced
    /// class may start, and reports whether one may.
    fn scan(
        &self,
        now: Instant,
        path: PathId,
        joins: JoinLimits,
        find_paced: bool,
        mut detail: Option<&mut String>,
    ) -> Scan {
        let mut blocked = Blocked::default();
        let mut start = None;
        let mut paced = false;
        let mut scratch = Vec::new();
        for space in Space::ALL {
            // A discarded space is skipped, as its keys are gone, and so is a space whose packets
            // on `path` would lack a peer connection ID.
            if self.spaces[space.index()].discarded || self.header_dcid(space, path).is_none() {
                continue;
            }
            let times = Times { now, release: now };
            let cx = self.send_cx(times, space, path, &mut scratch);
            for id in SourceId::ORDER {
                if joins.skipped.contains(id) || !self.source_active(id, space, path, &cx.packet) {
                    continue;
                }
                let Some(cand) = self.sources.candidate(id, &cx) else {
                    continue;
                };
                let gate = self.start_gate(space, path, cand, joins);
                let verdict = may_start(cand.class, &gate);
                if let Some(detail) = detail.as_deref_mut() {
                    let _ = writeln!(detail, "{space:?} {id:?} {cand:?}: {verdict:?}");
                }
                match verdict {
                    Start::Yes => {
                        paced |= cand.class.is_paced();
                        start.get_or_insert(StartCand {
                            path,
                            source: id,
                            space,
                            cand,
                        });
                        if detail.is_none() && (paced || !find_paced) {
                            return Scan {
                                start,
                                blocked,
                                paced,
                            };
                        }
                    }
                    Start::Never => {}
                    Start::Blocked(block) => blocked.note(block),
                }
            }
        }
        Scan {
            start,
            blocked,
            paced,
        }
    }

    /// Returns an attempt's stop when it cannot start a datagram, and the earliest pacing release.
    fn classify(&self, blocked: &Blocked) -> (Stop, Option<Instant>) {
        let stop = match self.state {
            State::Open => blocked.stop().unwrap_or(Stop::Idle),
            State::Closing { .. } => blocked.stop().unwrap_or(Stop::Closed),
            State::Draining { .. } | State::Drained => Stop::Closed,
        };
        (stop, blocked.pacing_at())
    }

    /// Returns whether an attempt that ended at `stop` leaves the window underused for want of
    /// data: it ran out of candidates with a datagram of the window unused and did not have a
    /// producer to poll or DATAGRAM frames queued, or connection flow control stopped it, which
    /// RFC 9002 treats the same way.
    fn is_app_limited(&self, stop: Stop) -> bool {
        match stop {
            Stop::Idle => {
                let left = self
                    .cc
                    .cwnd()
                    .saturating_sub(self.recovery.bytes_in_flight());
                !self.sources.streams.has_pull_ready()
                    && self.sources.streams.datagrams.is_empty()
                    && left >= u64::from(self.mtu)
            }
            Stop::ConnFlowControl => true,
            _ => false,
        }
    }

    /// Returns whether the connection is application-limited at the end of an attempt, whatever
    /// its stop, by the rules of mvfst's BBR3: less than a datagram of stream bytes is staged,
    /// those connection flow control holds back included, and DATAGRAM frames queued; push
    /// senders are not waiting for `Writable` and producers are not pull-ready; lost stream and
    /// CRYPTO data are not waiting for retransmission; and the window has room, even less than a
    /// datagram.
    pub(super) fn limited_by_app(&self) -> bool {
        let backlog = self.sources.streams.backlog();
        let datagrams = self.sources.streams.datagrams.bytes() as u64;
        backlog.staged + datagrams < u64::from(self.mtu)
            && !backlog.push_blocked
            && !backlog.pull_ready
            && !backlog.lost
            && !self.sources.crypto.iter().any(|crypto| crypto.has_lost())
            && self.cc.cwnd() > self.recovery.bytes_in_flight()
    }

    /// Returns whether source `id` may write into a packet in `space` on `path` holding `packet`
    /// in the connection's state: the alternate path carries only Path frames, and only while
    /// open; while closing, only CLOSE starts a packet and an ACK joins only a packet holding the
    /// CLOSE (RFC 9000); a draining connection does not send. A 0-RTT packet does not carry ACK,
    /// CRYPTO or path frames (RFC 9000).
    fn source_active(&self, id: SourceId, space: Space, path: PathId, packet: &PacketCx) -> bool {
        if path != PathId(0) {
            return id == SourceId::Path && self.state == State::Open && self.alt.is_some();
        }
        if space == Space::Data && self.zero_rtt_write_keys().is_some() {
            return self.state == State::Open
                && matches!(
                    id,
                    SourceId::Control | SourceId::Probe | SourceId::Scheduled | SourceId::Ping
                );
        }
        match self.state {
            State::Open => true,
            State::Closing { .. } => id == SourceId::Close || (id == SourceId::Ack && packet.close),
            State::Draining { .. } | State::Drained => false,
        }
    }

    /// Returns the context of an empty packet in `space` on `path`.
    fn send_cx<'a>(
        &self,
        times: Times,
        space: Space,
        path: PathId,
        sent: &'a mut Vec<crate::recovery::SentFrame>,
    ) -> SendCx<'a> {
        SendCx {
            now: times.now,
            release: times.release,
            space,
            path,
            probes_due: self.recovery.probes_due(space),
            ack_delay_exponent: self.config.ack_policy().ack_delay_exponent,
            packet: PacketCx::default(),
            sent,
        }
    }

    /// Returns the gate `cand` in `space` must pass to start a datagram on `path`: the datagram is
    /// charged 1,200 bytes if `cand` forces that size, else the packet `cand` needs.
    fn start_gate(&self, space: Space, path: PathId, cand: Candidate, joins: JoinLimits) -> Gate {
        let datagram_size = if full_size(self.side, space, cand.class) {
            u64::from(MIN_DATAGRAM)
        } else {
            self.packet_room(space, path, cand.min_len) as u64
        };
        Gate {
            datagram_size,
            ..self.join_gate(space, self.credit_of(path), joins)
        }
    }

    /// Returns the gate a joiner in `space` must pass in a datagram that may hold `room` bytes
    /// within `joins`; the caller sets the size the joiner would force.
    fn join_gate(&self, space: Space, room: u64, joins: JoinLimits) -> Gate {
        Gate {
            keys: self.can_seal(space),
            credit: room,
            datagram_size: 0,
            probes_due: self.recovery.probes_due(space),
            bytes_in_flight: self.recovery.bytes_in_flight(),
            cwnd: self.cc.cwnd(),
            pacing: joins.pacing,
            conn_credit: self.sources.streams.conn_send.available(),
            grant: joins.grant,
        }
    }

    /// Returns whether the pacer holds back and stamps datagrams: when configured, once the 1-RTT
    /// keys exist, the path has an RTT sample and the controller is ready to pace. Before that
    /// sample the rate would come from the initial RTT alone, and mvfst does not pace then either.
    /// BBR3 sends its initial window unpaced.
    fn pacing_active(&self) -> bool {
        self.config.pacing()
            && self.has_keys(Space::Data)
            && self.recovery.rtt().first_sample_time().is_some()
            && self.cc.pacing_ready()
    }

    /// Returns the build horizon of an attempt within `lim`: H_conn, or zero without the backend's
    /// clock epoch, which a connection with a horizon needs (`poll_transmit` debug-asserts it).
    fn horizon_within(&self, lim: &TxLimits) -> Duration {
        if lim.epoch.is_some() {
            self.horizon
        } else {
            Duration::ZERO
        }
    }

    /// Returns when paced candidates may start again, if the pacer holds them back at `now`: the
    /// next release less `horizon`, since a run is built once its release is at most `horizon`
    /// away.
    fn pacing_gate(&self, now: Instant, horizon: Duration) -> Option<Instant> {
        if !self.pacing_active() {
            return None;
        }
        let release = self.pacer.next_release(now);
        (release > now + horizon).then(|| release - horizon)
    }

    /// Returns whether probes are due in any space, which the next datagram would carry.
    fn probing(&self) -> bool {
        Space::ALL
            .into_iter()
            .any(|space| self.recovery.probes_due(space) > 0)
    }

    /// Returns the room a packet in `space` needs for `payload` bytes of frames, at the largest
    /// packet number and Length field: header protection samples 16 bytes from 4 bytes past the
    /// packet number's start, and the AEAD tag follows the payload.
    pub(super) fn packet_room(&self, space: Space, path: PathId, payload: usize) -> usize {
        let dcid = self.dcid_of(path).map_or(0, |cid| cid.len());
        // Type, version, both connection IDs with their lengths and a Length field of up to 4
        // bytes.
        let long = || 1 + 4 + 1 + dcid + 1 + self.local_cid.len() + 4;
        let pn_offset = match space {
            // An Initial packet's long header also holds the token with its length.
            Space::Initial => {
                let token = self.retry.as_ref().map_or(0, |retry| retry.token.len());
                let token_len = VarInt::from_u64(token as u64).map_or(8, VarInt::encoded_size);
                long() + token_len + token
            }
            Space::Handshake => long(),
            // A 0-RTT packet's long header is laid out as a Handshake packet's.
            Space::Data if self.zero_rtt_write_keys().is_some() => long(),
            Space::Data => 1 + dcid,
        };
        (pn_offset + 4 + TAG_LEN).saturating_add(payload.max(1))
    }

    /// Returns the length of the smallest packet the writer accepts in `space`.
    pub(super) fn min_packet_len(&self, space: Space) -> usize {
        self.packet_room(space, PathId(0), 1)
    }

    /// Plans the packets of the datagram started by `start`, as the room each keeps: the start's
    /// packet, and one for each later space with keys and a candidate that may join a datagram
    /// of `room` bytes, sized for the smallest such candidate. The start's packet keeps its
    /// room first, then each joiner's in order, so a packet does not take the room an earlier
    /// one needs.
    fn plan(
        &self,
        times: Times,
        start: StartCand,
        joins: JoinLimits,
        room: u64,
    ) -> [Option<usize>; 3] {
        let mut plan = [None; 3];
        let first = self.packet_room(start.space, start.path, start.cand.min_len);
        plan[start.space.index()] = Some(first);
        let mut left = room.saturating_sub(first as u64);
        let mut scratch = Vec::new();
        for space in Space::ALL.into_iter().filter(|&space| space > start.space) {
            if !self.can_seal(space) || self.header_dcid(space, start.path).is_none() {
                continue;
            }
            let cx = self.send_cx(times, space, start.path, &mut scratch);
            let gate = self.join_gate(space, room, joins);
            let probe = cx.probes_due > 0;
            let smallest = SourceId::ORDER
                .into_iter()
                .filter(|&id| {
                    !joins.skipped.contains(id)
                        && self.source_active(id, space, start.path, &cx.packet)
                })
                .filter_map(|id| self.sources.candidate(id, &cx))
                .filter(|cand| may_join(cand.class, &gate, probe))
                .map(|cand| self.packet_room(space, start.path, cand.min_len))
                .min();
            if let Some(need) = smallest
                && need as u64 <= left
            {
                plan[space.index()] = Some(need);
                left -= need as u64;
            }
        }
        plan
    }

    /// Builds one datagram into `buf` and commits it once sealed, with `PACES` as in `attempt`.
    fn build<const PACES: bool, Z: Sealer>(
        &mut self,
        times: Times,
        start: StartCand,
        joins: JoinLimits,
        slot: SlotId,
        buf: &mut [u8],
        sealer: &mut Z,
    ) -> Outcome {
        let room = usize::try_from(self.credit_of(start.path))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let buf = &mut buf[..room];
        let plan = self.plan(times, start, joins, room as u64);
        let planned = |space: Space| plan[space.index()].is_some();
        let mut built: [Option<Built>; 3] = [None; 3];
        let mut pos = 0;
        let mut carries_initial = false;
        let mut eliciting_initial = false;
        for space in Space::ALL.into_iter().filter(|&space| planned(space)) {
            let later = Space::ALL
                .into_iter()
                .filter(|&other| other > space && planned(other));
            let reserve: usize = later.clone().filter_map(|other| plan[other.index()]).sum();
            let last = later.count() == 0;
            let end = room.saturating_sub(reserve);
            if end <= pos {
                continue;
            }
            let sent = self.recovery.space(space);
            let pn = sent.next_pn();
            let pn_len = packet_number_len(pn, sent.largest_acked());
            let Some(header) = self.header_spec(space, start.path) else {
                continue;
            };
            let gate = self.join_gate(space, room as u64, joins);
            let side = self.side;
            let admit = move |class: Class| {
                let forces = full_size(side, space, class);
                let gate = Gate {
                    datagram_size: if forces { u64::from(MIN_DATAGRAM) } else { 0 },
                    ..gate
                };
                may_join(class, &gate, gate.probes_due > 0)
            };
            let Ok(mut w) = PacketWriter::new(&mut buf[pos..end], header, pn, pn_len, TAG_LEN)
            else {
                continue;
            };
            let probe = gate.probes_due > 0;
            let mut sent = std::mem::take(&mut self.sent_frames[space.index()]);
            sent.clear();
            let mut cx = SendCx {
                now: times.now,
                release: times.release,
                space,
                path: start.path,
                probes_due: gate.probes_due,
                ack_delay_exponent: self.config.ack_policy().ack_delay_exponent,
                packet: PacketCx::default(),
                sent: &mut sent,
            };
            for id in SourceId::FILL_ORDER {
                if !joins.skipped.contains(id)
                    && self.source_active(id, space, start.path, &cx.packet)
                {
                    self.sources.fill(id, &mut w, &mut cx, admit);
                    if w.remaining() == 0 {
                        break;
                    }
                }
            }
            let packet = cx.packet;
            self.sent_frames[space.index()] = sent;
            let initial_here = space == Space::Initial;
            let needs_full = match side {
                Side::Client => carries_initial || initial_here,
                Side::Server => eliciting_initial || (initial_here && w.is_ack_eliciting()),
            };
            let mut padded = false;
            if last && needs_full && (pos > 0 || !w.is_empty()) {
                padded = w
                    .pad_to(usize::from(MIN_DATAGRAM).saturating_sub(pos))
                    .is_ok();
            }
            // A datagram with Path frames is padded to 1,200 bytes when the path's credit allows,
            // as RFC 9000 requires.
            if last && packet.path && !padded && end >= usize::from(MIN_DATAGRAM) {
                padded = w
                    .pad_to(usize::from(MIN_DATAGRAM).saturating_sub(pos))
                    .is_ok();
            }
            if w.is_empty() {
                continue;
            }
            let ack_eliciting = w.is_ack_eliciting();
            let layout = w.finish();
            carries_initial |= initial_here;
            eliciting_initial |= initial_here && ack_eliciting;
            built[space.index()] = Some(Built {
                space,
                pn,
                offset: pos,
                layout,
                packet,
                ack_eliciting,
                padded,
                probe,
            });
            pos += layout.len;
        }
        if pos == 0 {
            return Outcome::Empty;
        }
        self.commit::<PACES, Z>(times, start.path, slot, buf, &built, pos, sealer)
    }

    /// Seals the datagram's packets, then records them: packet numbers, sent-frame records, the
    /// frames each source no longer has to send, the credit of `path` and the idle timer. Loss
    /// recovery and congestion control take the packets as sent at their run's release.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call site, all inputs of the datagram"
    )]
    fn commit<const PACES: bool, Z: Sealer>(
        &mut self,
        times: Times,
        path: PathId,
        slot: SlotId,
        buf: &mut [u8],
        built: &[Option<Built>; 3],
        len: usize,
        sealer: &mut Z,
    ) -> Outcome {
        for packet in built.iter().flatten() {
            let keys = match &self.spaces[packet.space.index()].keys {
                Some(keys) => &keys.local,
                None => self
                    .zero_rtt_write_keys()
                    .expect("should hold the keys of a space it built a packet in"),
            };
            let job = SealJob {
                slot,
                keys,
                pn: packet.pn,
                hdr_len: packet.layout.hdr_len as u16,
                len: packet.layout.len as u16,
            };
            if sealer.seal(job, &mut buf[packet.offset..]).is_err() {
                for packet in built.iter().flatten() {
                    self.sources
                        .on_unsealed(&self.sent_frames[packet.space.index()]);
                }
                return Outcome::Unsealed;
            }
        }
        let tx = self.tx_seq;
        self.tx_seq += 1;
        let mut ack_eliciting = false;
        let mut handshake_sent = false;
        let mut challenge = false;
        // ACK-only and probe datagrams do not take pacing tokens.
        let mut carries_paced = false;
        let mut carries_probe = false;
        for packet in built.iter().flatten() {
            carries_paced |= packet.packet.paced;
            carries_probe |= packet.probe;
            let mut flags = SentFlags::empty();
            if packet.ack_eliciting {
                flags = flags | SentFlags::ACK_ELICITING | SentFlags::IN_FLIGHT;
                if packet.probe {
                    flags = flags | SentFlags::PROBE;
                }
            }
            if packet.padded {
                flags = flags | SentFlags::IN_FLIGHT;
            }
            if packet.packet.crypto {
                flags = flags | SentFlags::HAS_CRYPTO;
            }
            if path == ALT_PATH {
                flags = flags | SentFlags::OFF_PATH;
            }
            self.sources
                .on_frames_sealed(&self.sent_frames[packet.space.index()]);
            for frame in self.sent_frames[packet.space.index()].drain(..) {
                self.recovery.push_frame(packet.space, frame);
            }
            let size = packet.layout.len as u16;
            let in_flight_before = flags
                .contains(SentFlags::IN_FLIGHT)
                .then(|| self.recovery.bytes_in_flight());
            self.recovery
                .on_packet_sent(packet.space, packet.pn, times.release, size, flags, tx)
                .expect("should record the packet number it peeked");
            if let Some(bytes_in_flight) = in_flight_before {
                self.cc.on_sent(&SentEvent {
                    time_sent: times.release,
                    bytes_in_flight,
                    size,
                    total_sent: self.recovery.total_sent(),
                    on_path: !flags.contains(SentFlags::OFF_PATH),
                });
            }
            self.sources.on_sealed(packet.space, &packet.packet);
            if packet.space == Space::Data
                && let Some(phases) = &mut self.key_phases
            {
                phases.on_sealed(packet.pn);
            }
            self.stats.sent_packets += 1;
            ack_eliciting |= packet.ack_eliciting;
            handshake_sent |= packet.space == Space::Handshake;
            challenge |= packet.packet.challenge;
        }
        // A send can change the pacing rate (BBR3's restart from idle), which the pacer takes
        // before it stamps this datagram.
        if self.cc.take_pacer_refresh() {
            self.refresh_pacing_rate();
        }
        self.stats.sent_bytes += len as u64;
        let now = times.now;
        self.charge_path(now, path, len, challenge);
        // The first ack-eliciting packet sent after a received one restarts the idle timer
        // (RFC 9000).
        if ack_eliciting && !self.idle.sent_since_receive {
            self.idle.base = now;
            self.idle.sent_since_receive = true;
        }
        if ack_eliciting {
            self.keepalive_base = now;
        }
        // A client discards its Initial keys when it first sends a Handshake packet (RFC 9001).
        if handshake_sent && self.side == Side::Client {
            self.discard_space(Space::Initial, now);
        }
        self.maybe_update_keys(now);
        Outcome::Sent {
            // The datagram fits its slot, whose length is a u16.
            len: u16::try_from(len).unwrap_or(u16::MAX),
            paced: PACES && carries_paced && !carries_probe,
        }
    }

    /// Closes the open run, if any, with its metadata, debits the pacer once with its paced
    /// bytes, and records in `out` whether its release is the attempt's reading `now` or later.
    /// With `stamps`, the run carries its release in the backend's clock.
    fn end_run<S: SegmentSink>(
        &mut self,
        sink: &mut S,
        run: &mut Option<Run>,
        stamps: Option<ClockEpoch>,
        now: Instant,
        out: &mut TxOutcome,
    ) {
        let Some(run) = run.take() else {
            return;
        };
        if run.segments == 0 {
            return;
        }
        debug_assert!(
            run.release >= now,
            "a run released at {:?} before the attempt's reading {now:?}",
            run.release
        );
        if run.release > now {
            debug_assert!(
                stamps.is_some(),
                "an unstamped run released at {:?}, after the attempt's reading {now:?}",
                run.release
            );
            out.ahead.get_or_insert(run.release);
        } else {
            out.due = true;
        }
        self.pacer.on_run(run.release, run.paced_bytes);
        sink.end_run(TxMeta {
            path: run.path,
            dst: self.remote_of(run.path),
            src_ip: self.local_ip,
            tos: 0,
            segment_size: run.segment_size,
            segments: run.segments,
            release: stamps.map_or(Release::Asap, |epoch| {
                Release::At(epoch.tick_at(run.release))
            }),
            class: run.class,
            tx: TxSeqRange {
                start: run.first_tx,
                end: run.first_tx + u64::from(run.segments),
            },
            sealed: true,
        });
    }

    /// Returns the Destination Connection ID of a packet in `space` on `path`, if the path has
    /// one: a long header always carries the current path's.
    fn header_dcid(&self, space: Space, path: PathId) -> Option<ConnectionId> {
        match space {
            Space::Initial | Space::Handshake => self.dcid_of(PathId(0)),
            Space::Data => self.dcid_of(path),
        }
    }

    /// Returns the header of a packet in `space` on `path`, if the path has a peer connection ID
    /// to put in it.
    fn header_spec(&self, space: Space, path: PathId) -> Option<HeaderSpec<'_>> {
        let dcid = self.header_dcid(space, path)?;
        Some(match space {
            Space::Initial => HeaderSpec::Initial {
                version: self.version,
                dcid,
                scid: self.local_cid,
                // Every Initial after a Retry carries its token, as RFC 9000 requires.
                token: self.retry.as_ref().map_or(&[], |retry| &retry.token[..]),
            },
            Space::Handshake => HeaderSpec::Handshake {
                version: self.version,
                dcid,
                scid: self.local_cid,
            },
            Space::Data if self.zero_rtt_write_keys().is_some() => HeaderSpec::ZeroRtt {
                version: self.version,
                dcid,
                scid: self.local_cid,
            },
            Space::Data => HeaderSpec::OneRtt {
                dcid,
                spin: false,
                key_phase: self.key_phases.as_ref().is_some_and(|phases| phases.phase),
            },
        })
    }

    /// Returns a hash of the state a later attempt reads, to check that an empty attempt does
    /// not change it.
    #[cfg(debug_assertions)]
    fn digest(&self) -> u64 {
        use std::hash::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        use crate::streams::conn::HashWriter;

        let mut h = DefaultHasher::new();
        for space in Space::ALL {
            let sent = self.recovery.space(space);
            (
                sent.next_pn(),
                sent.bytes_in_flight(),
                sent.tracked(),
                self.recovery.probes_due(space),
            )
                .hash(&mut h);
            let _ = write!(
                HashWriter(&mut h),
                "{:?}",
                self.sources.ack[space.index()].state()
            );
            let crypto = &self.sources.crypto[space.index()];
            let _ = write!(HashWriter(&mut h), "{:?}", crypto.offsets());
            crypto.handshake_done().hash(&mut h);
            self.spaces[space.index()].discarded.hash(&mut h);
        }
        self.sources.close.owed().hash(&mut h);
        self.sources.cids.hash(&mut h);
        self.sources.path.hash(&mut h);
        self.alt
            .map(|alt| (alt.remote, alt.credit.sent))
            .hash(&mut h);
        self.sources.ping.is_pending().hash(&mut h);
        self.sources.streams.digest(&mut h);
        // Only a commit stamps the pacer and reports a send to the controller.
        let _ = write!(HashWriter(&mut h), "{:?} {:?}", self.pacer, self.cc);
        (
            self.tx_seq,
            self.path.sent,
            self.stats.sent_packets,
            self.stats.sent_bytes,
            self.idle.base,
            self.idle.sent_since_receive,
        )
            .hash(&mut h);
        let _ = write!(HashWriter(&mut h), "{:?}", self.state);
        h.finish()
    }
}

/// Returns whether a datagram carrying `class` in `space` must reach 1,200 bytes: a client's
/// datagram with any Initial packet, and an ack-eliciting Initial from either side (RFC 9000).
fn full_size(side: Side, space: Space, class: Class) -> bool {
    let ack_eliciting = !matches!(class, Class::Piggyback | Class::AckOnly | Class::Response);
    space == Space::Initial && (side == Side::Client || ack_eliciting)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mvfstr_wire::Dir;
    use mvfstr_wire::Frame;
    use mvfstr_wire::Frames;

    use super::*;
    use crate::connection::stream_tests::ORDER;
    use crate::connection::stream_tests::pattern;
    use crate::connection::tests::LIMIT;
    use crate::connection::tests::handshake;
    use crate::connection::tests::open_own_one_rtt;
    use crate::testing::fixtures::Setup;

    #[test]
    fn building_a_packet_stops_at_the_frame_that_fills_it() {
        let (_, mut pair) = handshake(Setup::default().pair());
        let from = pair.server.sent.len();
        let server = pair.server.conn_mut();
        let id = server.open_stream(Dir::Uni, ORDER).unwrap();
        let mut short = Bytes::from_static(b"short");
        assert_eq!(server.stream(id).unwrap().send(&mut short), Ok(5));
        server.ping();
        pair.step();
        // A STREAM frame that keeps its Length leaves room for the Ping source after it.
        let server = pair.server.conn();
        let packets: Vec<Vec<u8>> = pair.server.sent[from..]
            .iter()
            .flat_map(|(_, datagram)| open_own_one_rtt(server, &datagram.data))
            .collect();
        assert!(
            packets.iter().any(|plaintext| {
                let frames: Vec<_> = Frames::new(plaintext).map(Result::unwrap).collect();
                frames
                    .windows(2)
                    .any(|pair| matches!(pair, [Frame::Stream { data: b"short", .. }, Frame::Ping]))
            }),
            "the short STREAM frame and a PING after it are not in one packet"
        );

        // Full packets end in a STREAM frame without its Length, which leaves no room.
        let from = pair.server.sent.len();
        let len = 32 * 1024;
        let mut bulk = Bytes::from(pattern(len));
        let server = pair.server.conn_mut();
        assert_eq!(server.stream(id).unwrap().send(&mut bulk), Ok(len));
        pair.run(pair.now + LIMIT);
        let full = pair.server.sent[from..]
            .iter()
            .filter(|(_, datagram)| datagram.data.len() == usize::from(MIN_DATAGRAM))
            .count();
        // 32 KiB take 28 datagrams of 1,200 bytes, each with about 1,170 stream bytes.
        assert!(full >= 25, "only {full} full datagrams");
        assert_eq!(
            pair.server.conn().sources.fills_without_room,
            0,
            "a source was offered a packet without room in it"
        );
    }

    #[test]
    fn an_unpaced_datagram_in_a_paced_run_takes_no_tokens_and_counts_toward_its_burst() {
        let release = crate::recovery::test_epoch();
        let mut run = Run {
            path: PathId(0),
            first_tx: 0,
            segments: 0,
            segment_size: 0,
            class: TxClass::Urgent,
            release,
            paced: true,
            room: 44,
            paced_bytes: 0,
        };
        // An ACK-only datagram, then paced ones, in a burst of 5.
        run.add(1200, false);
        for _ in 0..3 {
            run.add(1200, true);
        }
        assert!(!run.is_full(5));
        run.add(1200, true);
        assert!(run.is_full(5));
        assert_eq!((run.segments, run.paced_bytes), (5, 4 * 1200));
        assert_eq!((run.segment_size, run.release), (1200, release));
        // It holds at most the datagrams the attempt had room for.
        let narrow = Run { room: 3, ..run };
        assert!(narrow.is_full(44));
        // An unpaced run is not limited to a burst.
        let unpaced = Run {
            paced: false,
            ..run
        };
        assert!(!unpaced.is_full(5));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "before the attempt's reading")]
    fn closing_a_run_released_before_the_attempts_reading_is_a_bug() {
        use crate::testing::VecSink;

        // The pacer never releases a run before the reading it is given, so the run is made by
        // hand, with one datagram in the sink.
        let (_, mut pair) = handshake(Setup::default().pair());
        let release = pair.now;
        let conn = pair.server.conn_mut();
        let mut sink = VecSink::new(1500);
        assert!(sink.next_segment(1200, TxClass::Data).is_some());
        sink.end_segment(1200);
        let mut run = Some(Run {
            path: PathId(0),
            first_tx: conn.tx_seq,
            segments: 1,
            segment_size: 1200,
            class: TxClass::Data,
            release,
            paced: false,
            room: 1,
            paced_bytes: 0,
        });
        let mut out = TxOutcome {
            datagrams: 1,
            bytes: 1200,
            stop: Stop::Idle,
            pacing_at: None,
            ahead: None,
            due: false,
        };
        conn.end_run(
            &mut sink,
            &mut run,
            None,
            release + Duration::from_nanos(1),
            &mut out,
        );
    }
}
