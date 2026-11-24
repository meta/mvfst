/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Sent-packet tracking for one packet number space (RFC 9002).

use std::collections::VecDeque;
use std::collections::vec_deque;
use std::fmt;
use std::ops::BitOr;
use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::StreamId;
use mvfstr_wire::TransportErrorCode;

use super::Space;
use crate::transmit::TxSeqRange;

/// What a sent packet carried and counts toward (RFC 9002).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SentFlags(u8);

impl SentFlags {
    /// The packet carried an ack-eliciting frame.
    pub const ACK_ELICITING: SentFlags = SentFlags(1);
    /// The packet counts toward bytes in flight: it is ack-eliciting or carries PADDING.
    pub const IN_FLIGHT: SentFlags = SentFlags(1 << 1);
    /// The packet carried a CRYPTO frame.
    pub const HAS_CRYPTO: SentFlags = SentFlags(1 << 2);
    /// The packet was sent as a PTO probe.
    pub const PROBE: SentFlags = SentFlags(1 << 3);
    /// Reserved for DPLPMTUD probes, which mvfstr does not send.
    pub const MTU_PROBE: SentFlags = SentFlags(1 << 4);
    /// The packet went to the alternate path's address, not the current path's: it does not count
    /// in the current path's bytes in flight or for its RTT or congestion controller.
    pub const OFF_PATH: SentFlags = SentFlags(1 << 5);

    /// Returns the empty set of flags.
    pub const fn empty() -> SentFlags {
        SentFlags(0)
    }

    /// Returns whether every flag of `other` is set.
    pub const fn contains(self, other: SentFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the flags set in `self` or `other`.
    pub const fn union(self, other: SentFlags) -> SentFlags {
        SentFlags(self.0 | other.0)
    }
}

impl BitOr for SentFlags {
    type Output = SentFlags;

    fn bitor(self, rhs: SentFlags) -> SentFlags {
        self.union(rhs)
    }
}

/// A frame a sent packet carried: its source, and enough to retransmit it or to tell its owner it
/// was delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentFrame {
    /// A STREAM frame.
    Stream {
        /// The stream.
        id: StreamId,
        /// The offset of the first byte.
        offset: u64,
        /// The number of bytes.
        len: u16,
        /// Whether the frame carried the FIN bit.
        fin: bool,
    },
    /// A CRYPTO frame.
    Crypto {
        /// The encryption level of the bytes.
        level: Space,
        /// The offset of the first byte.
        offset: u64,
        /// The number of bytes.
        len: u16,
    },
    /// An ACK or ACK_ECN frame.
    Ack {
        /// Its Largest Acknowledged field.
        largest: u64,
    },
    /// A frame of the `Control` source, PATH_* or HANDSHAKE_DONE.
    Control {
        /// Which frame.
        kind: ControlKind,
        /// The stream ID or connection ID sequence number it is about, or 0.
        key: u64,
        /// The value it carried (a limit or PATH_* data), or 0.
        value: u64,
    },
    /// A PING frame.
    Ping,
}

/// The frame type of a [`SentFrame::Control`] record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlKind {
    /// MAX_DATA; `value` is the limit.
    MaxData,
    /// MAX_STREAM_DATA; `key` is the stream, `value` the limit.
    MaxStreamData,
    /// MAX_STREAMS for bidirectional streams; `value` is the limit.
    MaxStreamsBidi,
    /// MAX_STREAMS for unidirectional streams; `value` is the limit.
    MaxStreamsUni,
    /// DATA_BLOCKED; `value` is the limit.
    DataBlocked,
    /// STREAM_DATA_BLOCKED; `key` is the stream, `value` the limit.
    StreamDataBlocked,
    /// STREAMS_BLOCKED for bidirectional streams; `value` is the limit.
    StreamsBlockedBidi,
    /// STREAMS_BLOCKED for unidirectional streams; `value` is the limit.
    StreamsBlockedUni,
    /// NEW_CONNECTION_ID; `key` is the sequence number.
    NewConnectionId,
    /// RETIRE_CONNECTION_ID; `key` is the sequence number.
    RetireConnectionId,
    /// NEW_TOKEN.
    NewToken,
    /// RESET_STREAM; `key` is the stream.
    ResetStream,
    /// STOP_SENDING; `key` is the stream.
    StopSending,
    /// PATH_CHALLENGE; `key` is the path, `value` the data.
    PathChallenge,
    /// PATH_RESPONSE; `key` is the path, `value` the data.
    PathResponse,
    /// HANDSHAKE_DONE.
    HandshakeDone,
}

/// The compact record of one sent packet, 32 bytes. Times are nanoseconds since the epoch of the
/// ring that holds it, so the record does not store an `Instant` (16 bytes).
#[derive(Clone, Copy, Debug)]
pub struct SentPkt {
    pn: u64,
    time_sent: u64,
    tx_seq: u64,
    /// The sequence number of its first record in the frame ring; its last is just before the
    /// next packet's first.
    frames: u32,
    size: u16,
    flags: SentFlags,
    state: PktState,
}

/// Where a sent packet is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PktState {
    /// Sent, neither acknowledged nor declared lost.
    Outstanding,
    /// Acknowledged.
    Acked,
    /// Declared lost; kept a while so a late acknowledgment shows the loss was spurious.
    Lost,
    /// Declared lost because its datagram did not leave, which is not a congestion loss.
    Dropped,
    /// A packet number deliberately never sent; acknowledging it is an optimistic ACK.
    Skipped,
}

const _: () = assert!(size_of::<SentPkt>() == 32);
const _: () = assert!(size_of::<SentFrame>() == 24);

/// API misuse when recording a sent packet; the ring is left unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentError {
    /// The packet number is below the next one: packet numbers never repeat.
    PnReused {
        /// The packet number given.
        pn: u64,
        /// The smallest packet number still unused.
        next: u64,
    },
    /// More than [`SentPackets::MAX_SKIP`] packet numbers would be skipped at once.
    SkipTooLarge,
    /// The packet is ack-eliciting but not in flight; RFC 9002 counts every such packet in flight.
    AckElicitingNotInFlight,
}

impl fmt::Display for SentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PnReused { pn, next } => {
                write!(f, "packet number {pn} is below the next unused one, {next}")
            }
            Self::SkipTooLarge => f.write_str("too many packet numbers skipped at once"),
            Self::AckElicitingNotInFlight => {
                f.write_str("an ack-eliciting packet must count in flight")
            }
        }
    }
}

impl std::error::Error for SentError {}

/// What happened to a sent packet, as ACK processing and loss detection report it.
#[derive(Clone, Debug)]
pub enum PacketEvent<'a> {
    /// The packet was newly acknowledged; its frames were delivered.
    Acked(SentPacket<'a>),
    /// The packet was acknowledged after it had been declared lost: its frames were delivered
    /// after all, and the loss was spurious.
    AckedAfterLoss(SentPacket<'a>),
    /// The packet was declared lost; its frames that still matter must be sent again.
    Lost(SentPacket<'a>),
}

/// An ACK frame that breaks the protocol; both are PROTOCOL_VIOLATION. ACK processing stops at
/// the error and the connection is expected to close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckError {
    /// It acknowledges a packet number not sent yet (RFC 9000).
    UnsentPacket(u64),
    /// It acknowledges a packet number that was skipped on purpose: an optimistic ACK (RFC 9000).
    SkippedPacket(u64),
}

impl AckError {
    /// Returns the transport error to close the connection with.
    pub fn code(self) -> TransportErrorCode {
        TransportErrorCode::PROTOCOL_VIOLATION
    }
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsentPacket(pn) => write!(f, "ACK of unsent packet {pn}"),
            Self::SkippedPacket(pn) => write!(f, "ACK of skipped packet number {pn}"),
        }
    }
}

impl std::error::Error for AckError {}

/// What one ACK frame newly acknowledged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckSummary {
    /// Packets newly acknowledged, in flight or not.
    pub newly_acked: u32,
    /// Bytes of in-flight packets newly acknowledged that went on the current path: those the
    /// current path's congestion controller counts.
    pub acked_bytes: u64,
    /// The packet number and send time of the largest packet newly acknowledged.
    pub largest_newly_acked: Option<(u64, Instant)>,
    /// `latest_rtt` when the frame yields an RTT sample: its Largest Acknowledged is newly
    /// acknowledged and some newly acknowledged packet was ack-eliciting, as RFC 9002 requires.
    /// Also, the ACK did not arrive before the largest packet's recorded send time, and that packet
    /// went on the current path.
    pub rtt_sample: Option<Duration>,
    /// In-flight packets acknowledged after loss detection declared them lost. They are not counted
    /// as newly acknowledged, because RFC 9002 stops tracking a packet declared lost.
    pub spurious: u32,
}

/// The thresholds of one loss detection pass (RFC 9002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossParams {
    /// `max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)`: packets sent this
    /// long before `now` are lost once a later packet is acknowledged.
    pub loss_delay: Duration,
    /// kPacketThreshold: packets this many numbers below the largest acknowledged are lost.
    pub packet_threshold: u64,
    /// When the first RTT sample was taken. Only packets sent after it count toward persistent
    /// congestion, as RFC 9002 recommends.
    pub first_rtt_sample: Option<Instant>,
    /// The persistent congestion duration (RFC 9002).
    pub persistent_congestion: Duration,
}

/// What one loss detection pass declared lost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LossSummary {
    /// Packets declared lost, in flight or not.
    pub lost_packets: u32,
    /// Bytes of in-flight packets declared lost.
    pub lost_bytes: u64,
    /// Of `lost_bytes`, those of packets that went on the current path and were declared lost
    /// by loss detection, not dropped by the backend: the bytes a rate-sampling controller's
    /// C.lost grows by.
    pub on_path_lost_bytes: u64,
    /// In-flight packets loss detection newly declared lost, on any path; dropped datagrams'
    /// packets do not count. This is the population [`AckSummary::spurious`] and
    /// [`SentPackets::declared_lost`] count.
    pub newly_lost: u32,
    /// The send time of the last in-flight packet declared lost that went on the current path,
    /// which starts a congestion event (RFC 9002); losses on another path do not.
    pub largest_lost_sent: Option<Instant>,
    /// Whether the lost packets that went on the current path establish persistent congestion
    /// (RFC 9002).
    pub persistent_congestion: bool,
}

impl LossSummary {
    /// Adds the losses of `other`, from another space.
    pub fn merge(&mut self, other: LossSummary) {
        self.lost_packets += other.lost_packets;
        self.lost_bytes += other.lost_bytes;
        self.on_path_lost_bytes += other.on_path_lost_bytes;
        self.newly_lost += other.newly_lost;
        self.largest_lost_sent = self.largest_lost_sent.max(other.largest_lost_sent);
        self.persistent_congestion |= other.persistent_congestion;
    }
}

/// What a packet's send recorded for the BBR draft's delivery-rate sampling: the connection's
/// delivery state when an on-path in-flight packet was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSnapshot {
    /// P.delivered: the bytes delivered on the connection when the packet was sent.
    pub delivered: u64,
    /// P.first_send_time: the send time that starts the packet's delivery interval.
    pub first_send_time: Instant,
    /// P.delivered_time: the ACK time that starts the packet's delivery interval, with the ACK
    /// Delay taken off, or the send time when the interval starts at a send.
    pub delivered_time: Instant,
    /// Whether the interval starts at a send, a restart or the connection's start rather than at
    /// an ACK; if so, its ACK elapsed time ends at the raw receive time.
    pub from_send: bool,
    /// P.is_app_limited: whether the connection was marked application-limited when it was sent.
    pub app_limited: bool,
    /// P.tx_in_flight: the bytes in flight, the packet included, right after it was sent.
    pub tx_in_flight: u64,
    /// P.lost: the bytes declared lost on the connection when it was sent.
    pub lost: u64,
    /// The bytes sent on the connection through this packet, packets not in flight included and
    /// off-path packets excepted.
    pub total_sent: u64,
}

/// An on-path in-flight packet loss detection declared lost, for the BBR draft's per-packet loss
/// response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LostSample {
    /// Its size in bytes.
    pub size: u16,
    /// Its packet number.
    pub pn: u64,
    /// Its packet number space.
    pub space: Space,
    /// P.tx_in_flight: the bytes in flight, the packet included, right after it was sent.
    pub tx_in_flight: u64,
    /// P.is_app_limited: whether the connection was marked application-limited when it was sent.
    pub is_app_limited: bool,
}

/// A sent packet as recovery reports it, with the frames it carried.
#[derive(Clone, Debug)]
pub struct SentPacket<'a> {
    /// The packet number.
    pub pn: u64,
    /// When it was sent: its release time, the earliest time its datagram may leave.
    pub time_sent: Instant,
    /// Its size in bytes, QUIC header and AEAD tag included.
    pub size: u16,
    /// What it carried.
    pub flags: SentFlags,
    /// The connection's datagram sequence number of the datagram that carried it.
    pub tx_seq: u64,
    /// Whether it went on the current path (see [`SentPackets::start_path`] and
    /// [`SentFlags::OFF_PATH`]); only such packets count for its congestion controller.
    pub on_path: bool,
    /// What its send recorded for delivery-rate sampling, for an on-path in-flight packet sent
    /// while the controller takes rate samples.
    pub snapshot: Option<&'a SendSnapshot>,
    frames: vec_deque::Iter<'a, SentFrame>,
}

impl<'a> SentPacket<'a> {
    /// Returns the frames the packet carried, in the order they were written.
    pub fn frames(&self) -> vec_deque::Iter<'a, SentFrame> {
        self.frames.clone()
    }
}

/// The sent packets of one packet number space: a ring of [`SentPkt`] records indexed by
/// packet number, and a ring of the [`SentFrame`] records they carried. Both rings reuse their
/// capacity, so steady-state sending and acknowledgment do not allocate.
#[derive(Clone, Debug)]
pub struct SentPackets {
    epoch: Instant,
    /// Records in packet-number order without gaps: `pkts[i].pn == pkts[0].pn + i`.
    pkts: VecDeque<SentPkt>,
    next_pn: u64,
    frames: VecDeque<SentFrame>,
    /// The sequence number of `frames[0]`.
    frames_front: u32,
    /// The sequence number just past the last frame of the last recorded packet; frames after
    /// it belong to the packet being built.
    frames_end: u32,
    largest_acked: Option<u64>,
    bytes_in_flight: u64,
    /// The first packet number sent on the current path; earlier packets went on a path the
    /// connection has left.
    path_from: u64,
    /// The part of `bytes_in_flight` not sent on the current path: before `path_from`, or with
    /// [`SentFlags::OFF_PATH`].
    off_path_bytes: u64,
    ack_eliciting_in_flight: u32,
    last_ack_eliciting: Option<u64>,
    loss_time: Option<u64>,
    /// In-flight records declared lost by loss detection and still in the ring.
    declared_lost: u32,
    /// The packet numbers below the largest acknowledged whose records are not acknowledged
    /// (outstanding, lost, dropped or skipped), ascending. ACK processing and loss detection
    /// visit these instead of every record behind a lost packet.
    holes: VecDeque<u64>,
    /// The packet number where loss detection starts; the holes below it are not outstanding.
    loss_scan_from: u64,
    /// The send snapshot, if any, of each packet number from `snapshots_from` through the last
    /// record given one. [`SentPackets::set_last_snapshot`] drops the snapshots of pruned records,
    /// so pruning leaves this ring alone and a connection without snapshots never touches it.
    snapshots: VecDeque<Option<SendSnapshot>>,
    /// The packet number of `snapshots[0]`; every tracked record is at or above it.
    snapshots_from: u64,
    /// Records visited by ACK processing and loss detection, for tests of their cost.
    #[cfg(test)]
    examined: u64,
}

impl SentPackets {
    /// The most packet numbers one call to [`SentPackets::on_sent`] may skip.
    pub const MAX_SKIP: u64 = 256;

    /// Creates an empty ring whose first packet will be `first_pn`. Times are kept as offsets
    /// from `epoch`, which should be no later than the first packet is sent.
    pub fn new(epoch: Instant, first_pn: u64) -> Self {
        Self {
            epoch,
            pkts: VecDeque::new(),
            next_pn: first_pn,
            frames: VecDeque::new(),
            frames_front: 0,
            frames_end: 0,
            largest_acked: None,
            bytes_in_flight: 0,
            path_from: 0,
            off_path_bytes: 0,
            ack_eliciting_in_flight: 0,
            last_ack_eliciting: None,
            loss_time: None,
            declared_lost: 0,
            holes: VecDeque::new(),
            loss_scan_from: 0,
            snapshots: VecDeque::new(),
            snapshots_from: 0,
            #[cfg(test)]
            examined: 0,
        }
    }

    /// Returns the smallest packet number not used yet.
    pub fn next_pn(&self) -> u64 {
        self.next_pn
    }

    /// Records a frame written into the packet being built.
    pub fn push_frame(&mut self, frame: SentFrame) {
        self.frames.push_back(frame);
    }

    /// Forgets the frames pushed since the last recorded packet: the packet was not sealed.
    pub fn abandon_frames(&mut self) {
        let committed = self.frames_end.wrapping_sub(self.frames_front) as usize;
        self.frames.truncate(committed);
    }

    /// Records `snapshot` as the send snapshot of the packet just recorded by
    /// [`SentPackets::on_sent`]. A packet recorded without this call does not get one.
    pub fn set_last_snapshot(&mut self, snapshot: SendSnapshot) {
        let Some(front) = self.pkts.front().map(|p| p.pn) else {
            return;
        };
        // Drop the snapshots of the records pruned since the last call, so that `snapshots[i]`
        // belongs to `pkts[i]` again; records past its end do not have one.
        let pruned = (front - self.snapshots_from).min(self.snapshots.len() as u64);
        self.snapshots.drain(..pruned as usize);
        self.snapshots_from = front;
        self.snapshots.resize(self.pkts.len(), None);
        if let Some(last) = self.snapshots.back_mut() {
            *last = Some(snapshot);
        }
    }

    /// Records a sealed packet carrying the frames pushed since the previous one. A `pn` above
    /// [`SentPackets::next_pn`] skips the numbers between, as RFC 9000 allows.
    pub fn on_sent(
        &mut self,
        pn: u64,
        now: Instant,
        size: u16,
        flags: SentFlags,
        tx_seq: u64,
    ) -> Result<(), SentError> {
        if pn < self.next_pn {
            return Err(SentError::PnReused {
                pn,
                next: self.next_pn,
            });
        }
        if pn - self.next_pn > Self::MAX_SKIP {
            return Err(SentError::SkipTooLarge);
        }
        if flags.contains(SentFlags::ACK_ELICITING) && !flags.contains(SentFlags::IN_FLIGHT) {
            return Err(SentError::AckElicitingNotInFlight);
        }
        let time_sent = self.offset(now);
        let record = |pn, size, flags, state| SentPkt {
            pn,
            time_sent,
            tx_seq,
            frames: self.frames_end,
            size,
            flags,
            state,
        };
        for skipped in self.next_pn..pn {
            self.pkts
                .push_back(record(skipped, 0, SentFlags::empty(), PktState::Skipped));
        }
        self.pkts
            .push_back(record(pn, size, flags, PktState::Outstanding));
        self.next_pn = pn + 1;
        self.frames_end = self.frames_front.wrapping_add(self.frames.len() as u32);
        if flags.contains(SentFlags::IN_FLIGHT) {
            self.bytes_in_flight += u64::from(size);
            if flags.contains(SentFlags::OFF_PATH) {
                self.off_path_bytes += u64::from(size);
            }
        }
        if flags.contains(SentFlags::ACK_ELICITING) {
            self.ack_eliciting_in_flight += 1;
            self.last_ack_eliciting = Some(time_sent);
        }
        Ok(())
    }

    /// Processes the ranges of one ACK frame, largest first, in one pass: each newly
    /// acknowledged packet is reported to `on_event` once, with its frames. Above the previous
    /// largest acknowledged every record is visited; at or below it only the holes are, so ACK
    /// frames repeating old ranges cost little even while a lost packet pins the ring.
    pub fn on_ack<I>(
        &mut self,
        ranges: I,
        now: Instant,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> Result<AckSummary, AckError>
    where
        I: IntoIterator<Item = RangeInclusive<u64>>,
    {
        let mut summary = AckSummary::default();
        let mut frame_largest = None;
        let mut eliciting_acked = false;
        let old_largest = self.largest_acked;
        let above_old = old_largest.map_or(0, |l| l + 1);
        for range in ranges {
            let (lo, hi) = (*range.start(), *range.end());
            if hi >= self.next_pn {
                return Err(AckError::UnsentPacket(hi));
            }
            frame_largest = frame_largest.max(Some(hi));
            let Some(front) = self.pkts.front().map(|p| p.pn) else {
                continue;
            };
            // Records are contiguous from `front` to `next_pn - 1`, and holes lie between
            // `front` and the largest acknowledged, so every index is in range.
            for pn in lo.max(above_old).max(front)..=hi {
                let i = (pn - front) as usize;
                self.ack_record(i, &mut summary, &mut eliciting_acked, &mut on_event)?;
            }
            if let Some(old) = old_largest
                && lo <= old
            {
                let first = self.holes.partition_point(|&h| h < lo);
                let end = self.holes.partition_point(|&h| h <= hi.min(old)).max(first);
                for k in first..end {
                    let i = (self.holes[k] - front) as usize;
                    if let Err(error) =
                        self.ack_record(i, &mut summary, &mut eliciting_acked, &mut on_event)
                    {
                        self.holes.drain(first..k);
                        return Err(error);
                    }
                }
                self.holes.drain(first..end);
            }
        }
        if let Some(largest) = frame_largest
            && largest >= above_old
            && let Some(front) = self.pkts.front().map(|p| p.pn)
        {
            // The records this frame left unacknowledged below its largest are new holes.
            for pn in above_old.max(front)..largest {
                if self.pkts[(pn - front) as usize].state != PktState::Acked {
                    self.holes.push_back(pn);
                }
            }
        }
        self.largest_acked = self.largest_acked.max(frame_largest);
        if let Some((largest, sent)) = summary.largest_newly_acked
            && eliciting_acked
            && Some(largest) == frame_largest
            && self.sent_on_path(largest)
        {
            summary.rtt_sample = now.checked_duration_since(sent);
        }
        Ok(summary)
    }

    /// Returns whether packet `pn`, whose record the ring holds, went on the current path.
    fn sent_on_path(&self, pn: u64) -> bool {
        let Some(front) = self.pkts.front() else {
            return false;
        };
        pn.checked_sub(front.pn)
            .and_then(|i| self.pkts.get(i as usize))
            .is_some_and(|pkt| self.on_path(pkt))
    }

    /// Returns whether `pkt` went on the current path: since the last [`SentPackets::start_path`],
    /// and not to the alternate path's address.
    fn on_path(&self, pkt: &SentPkt) -> bool {
        pkt.pn >= self.path_from && !pkt.flags.contains(SentFlags::OFF_PATH)
    }

    /// Applies an acknowledgment to `pkts[i]`.
    fn ack_record(
        &mut self,
        i: usize,
        summary: &mut AckSummary,
        eliciting_acked: &mut bool,
        on_event: &mut impl FnMut(PacketEvent<'_>),
    ) -> Result<(), AckError> {
        #[cfg(test)]
        {
            self.examined += 1;
        }
        let pkt = self.pkts[i];
        match pkt.state {
            PktState::Outstanding => {
                self.pkts[i].state = PktState::Acked;
                summary.newly_acked += 1;
                if pkt.flags.contains(SentFlags::IN_FLIGHT) && self.on_path(&pkt) {
                    summary.acked_bytes += u64::from(pkt.size);
                }
                *eliciting_acked |= pkt.flags.contains(SentFlags::ACK_ELICITING);
                if summary.largest_newly_acked.is_none_or(|(l, _)| pkt.pn > l) {
                    summary.largest_newly_acked = Some((pkt.pn, self.instant(pkt.time_sent)));
                }
                self.leave_flight(pkt);
                on_event(PacketEvent::Acked(self.view(i)));
            }
            PktState::Lost | PktState::Dropped => {
                self.pkts[i].state = PktState::Acked;
                if pkt.state == PktState::Lost && pkt.flags.contains(SentFlags::IN_FLIGHT) {
                    summary.spurious += 1;
                    self.declared_lost -= 1;
                }
                on_event(PacketEvent::AckedAfterLoss(self.view(i)));
            }
            PktState::Skipped => return Err(AckError::SkippedPacket(pkt.pn)),
            PktState::Acked => {}
        }
        Ok(())
    }

    /// Takes a packet that was outstanding out of the in-flight counters.
    fn leave_flight(&mut self, pkt: SentPkt) {
        if pkt.flags.contains(SentFlags::IN_FLIGHT) {
            self.bytes_in_flight -= u64::from(pkt.size);
            if !self.on_path(&pkt) {
                self.off_path_bytes -= u64::from(pkt.size);
            }
        }
        if pkt.flags.contains(SentFlags::ACK_ELICITING) {
            self.ack_eliciting_in_flight -= 1;
        }
    }

    /// Declares lost every outstanding packet below the largest acknowledged that passed the packet
    /// or time threshold (RFC 9002), reporting each to `on_event`, and sets
    /// [`SentPackets::loss_time`] for the earliest one that has not yet.
    pub fn detect_lost(
        &mut self,
        now: Instant,
        params: &LossParams,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> LossSummary {
        let mut summary = LossSummary::default();
        self.loss_time = None;
        let Some(largest_acked) = self.largest_acked else {
            return summary;
        };
        let loss_delay = duration_nanos(params.loss_delay);
        let now_offset = self.offset(now);
        // Packets sent at or before this are lost by time; `None` while `now` is too close to
        // the epoch for any to be.
        let lost_send_time = now_offset.checked_sub(loss_delay);
        // Persistent congestion: a run of lost ack-eliciting packets, sent on the current path
        // after the first RTT sample, where the peer did not acknowledge any packet between its
        // ends. Only this space is considered, as RFC 9002 allows. A lost packet sent on another
        // path does not join a run, and does not break one either.
        let pc_after = params.first_rtt_sample.map(|t| self.offset(t));
        let pc_duration = duration_nanos(params.persistent_congestion);
        let mut run: Option<(u64, u64)> = None;
        // Below the largest acknowledged only holes can be outstanding, and only from
        // `loss_scan_from` on. A gap between two holes is an acknowledged packet.
        let front = self.pkts.front().map_or(self.next_pn, |p| p.pn);
        let first = self.holes.partition_point(|&h| h < self.loss_scan_from);
        let mut scan_from = largest_acked;
        let mut prev_hole = None;
        for k in first..self.holes.len() {
            let pn = self.holes[k];
            if prev_hole.is_some_and(|prev| pn > prev + 1) {
                run = None;
            }
            prev_hole = Some(pn);
            let i = (pn - front) as usize;
            let pkt = self.pkts[i];
            #[cfg(test)]
            {
                self.examined += 1;
            }
            if pkt.state != PktState::Outstanding {
                continue;
            }
            // Never lost before its release time, even if the peer acknowledged later packets.
            if lost_send_time.is_some_and(|t| pkt.time_sent <= t)
                || (pkt.time_sent <= now_offset
                    && largest_acked >= pkt.pn + params.packet_threshold)
            {
                self.mark_lost(i, PktState::Lost, &mut summary);
                if pkt.flags.contains(SentFlags::ACK_ELICITING)
                    && self.on_path(&pkt)
                    && pc_after.is_some_and(|after| pkt.time_sent > after)
                {
                    let (start, _) = *run.get_or_insert((pkt.time_sent, pkt.time_sent));
                    run = Some((start, pkt.time_sent));
                    summary.persistent_congestion |= pkt.time_sent - start > pc_duration;
                }
                on_event(PacketEvent::Lost(self.view(i)));
            } else {
                let at = pkt.time_sent.saturating_add(loss_delay);
                self.loss_time = Some(self.loss_time.map_or(at, |t| t.min(at)));
                scan_from = scan_from.min(pn);
            }
        }
        self.loss_scan_from = scan_from;
        summary
    }

    /// Returns when the earliest outstanding packet below the largest acknowledged passes the
    /// time threshold, if one is waiting for it.
    pub fn loss_time(&self) -> Option<Instant> {
        self.loss_time.map(|t| self.instant(t))
    }

    /// Declares lost the outstanding packets carried by datagrams `tx`, which a backend reports
    /// certainly did not leave. This is not a congestion signal: the caller retransmits their
    /// frames without a congestion response.
    pub fn on_tx_dropped(
        &mut self,
        tx: TxSeqRange,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> LossSummary {
        let mut summary = LossSummary::default();
        // Datagram sequence numbers grow with packet numbers, and dropped datagrams are recent.
        for i in (0..self.pkts.len()).rev() {
            let pkt = self.pkts[i];
            if pkt.tx_seq < tx.start {
                break;
            }
            if pkt.tx_seq < tx.end && pkt.state == PktState::Outstanding {
                self.mark_lost(i, PktState::Dropped, &mut summary);
                on_event(PacketEvent::Lost(self.view(i)));
            }
        }
        summary
    }

    /// Declares the outstanding `pkts[i]` lost, as `state`, and counts it in `summary`.
    fn mark_lost(&mut self, i: usize, state: PktState, summary: &mut LossSummary) {
        let pkt = self.pkts[i];
        self.pkts[i].state = state;
        self.leave_flight(pkt);
        summary.lost_packets += 1;
        if pkt.flags.contains(SentFlags::IN_FLIGHT) {
            if state == PktState::Lost {
                self.declared_lost += 1;
                summary.newly_lost += 1;
            }
            summary.lost_bytes += u64::from(pkt.size);
            if self.on_path(&pkt) {
                let sent = self.instant(pkt.time_sent);
                summary.largest_lost_sent = summary.largest_lost_sent.max(Some(sent));
                if state == PktState::Lost {
                    summary.on_path_lost_bytes += u64::from(pkt.size);
                }
            }
        }
    }

    /// Drops resolved records from the front of the ring, with their frames: acknowledged packets,
    /// and lost packets, skipped numbers and packets not in flight sent before `forget_before` (a
    /// skipped number also once a later packet is acknowledged). Lost packets are kept until then
    /// so a late acknowledgment can reveal a spurious loss; packets not in flight are declared lost
    /// only once the peer acknowledges a later packet. Returns how many in-flight packets declared
    /// lost were forgotten unacknowledged: their losses were real.
    pub fn prune(&mut self, forget_before: Instant) -> u32 {
        let cutoff = self.offset(forget_before);
        let largest_acked = self.largest_acked;
        let mut forgotten_lost = 0;
        while let Some(front) = self.pkts.front() {
            let old = front.time_sent < cutoff;
            let done = match front.state {
                PktState::Acked => true,
                PktState::Lost | PktState::Dropped => old,
                PktState::Skipped => old || largest_acked.is_some_and(|l| front.pn < l),
                PktState::Outstanding => old && !front.flags.contains(SentFlags::IN_FLIGHT),
            };
            if !done {
                break;
            }
            if front.state == PktState::Lost && front.flags.contains(SentFlags::IN_FLIGHT) {
                forgotten_lost += 1;
            }
            self.pkts.pop_front();
            let next_frames = self.pkts.front().map_or(self.frames_end, |p| p.frames);
            let n = next_frames.wrapping_sub(self.frames_front) as usize;
            self.frames.drain(..n);
            self.frames_front = next_frames;
        }
        let front = self.pkts.front().map_or(self.next_pn, |p| p.pn);
        while self.holes.front().is_some_and(|&pn| pn < front) {
            self.holes.pop_front();
        }
        self.declared_lost -= forgotten_lost;
        forgotten_lost
    }

    /// Forgets every packet because the space's keys were discarded (RFC 9002). Returns the
    /// in-flight bytes removed, which no longer count toward bytes in flight.
    pub fn discard(&mut self) -> u64 {
        let removed = self.bytes_in_flight;
        self.pkts.clear();
        self.snapshots.clear();
        self.frames.clear();
        self.frames_front = 0;
        self.frames_end = 0;
        self.bytes_in_flight = 0;
        self.off_path_bytes = 0;
        self.ack_eliciting_in_flight = 0;
        self.last_ack_eliciting = None;
        self.loss_time = None;
        self.declared_lost = 0;
        self.holes.clear();
        removed
    }

    /// Returns the capacity of the send snapshot ring, for tests that check snapshots are not kept.
    #[cfg(test)]
    pub(crate) fn snapshot_capacity(&self) -> usize {
        self.snapshots.capacity()
    }

    /// Returns how many records the ring holds, resolved or not.
    pub fn tracked(&self) -> usize {
        self.pkts.len()
    }

    /// Returns the largest packet number the peer has acknowledged.
    pub fn largest_acked(&self) -> Option<u64> {
        self.largest_acked
    }

    /// Returns the packet `pn`, if it is still tracked.
    pub fn get(&self, pn: u64) -> Option<SentPacket<'_>> {
        let i = self.index(pn)?;
        (self.pkts[i].state != PktState::Skipped).then(|| self.view(i))
    }

    /// Returns the ack-eliciting packets neither acknowledged nor declared lost, oldest first.
    pub fn outstanding(&self) -> impl Iterator<Item = SentPacket<'_>> + '_ {
        self.pkts
            .iter()
            .enumerate()
            .filter(|(_, pkt)| {
                pkt.state == PktState::Outstanding && pkt.flags.contains(SentFlags::ACK_ELICITING)
            })
            .map(|(i, _)| self.view(i))
    }

    /// Returns the ring index of `pn`.
    fn index(&self, pn: u64) -> Option<usize> {
        let front = self.pkts.front()?.pn;
        let i = usize::try_from(pn.checked_sub(front)?).ok()?;
        (i < self.pkts.len()).then_some(i)
    }

    /// Returns the report view of `pkts[i]`.
    fn view(&self, i: usize) -> SentPacket<'_> {
        let pkt = &self.pkts[i];
        SentPacket {
            pn: pkt.pn,
            time_sent: self.instant(pkt.time_sent),
            size: pkt.size,
            flags: pkt.flags,
            tx_seq: pkt.tx_seq,
            on_path: self.on_path(pkt),
            // Every tracked record is at or above `snapshots_from`.
            snapshot: self
                .snapshots
                .get(pkt.pn.wrapping_sub(self.snapshots_from) as usize)
                .and_then(Option::as_ref),
            frames: frames_of(
                &self.pkts,
                &self.frames,
                self.frames_front,
                self.frames_end,
                i,
            ),
        }
    }

    /// Returns the number of in-flight packets declared lost by loss detection that are still
    /// tracked, so a late acknowledgment may yet show their loss was spurious.
    pub fn declared_lost(&self) -> u32 {
        self.declared_lost
    }

    /// Returns the bytes of in-flight packets neither acknowledged nor declared lost.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Records that the current path is a new one: the packets sent so far stay tracked until
    /// acknowledged or lost, but leave [`SentPackets::path_bytes_in_flight`], stop giving RTT
    /// samples and no longer count for the congestion controller.
    pub fn start_path(&mut self) {
        self.path_from = self.next_pn;
        self.off_path_bytes = self.bytes_in_flight;
    }

    /// Returns the first packet number sent on the current path.
    pub fn path_from(&self) -> u64 {
        self.path_from
    }

    /// Returns the bytes in flight of packets sent on the current path: since the last
    /// [`SentPackets::start_path`], and without [`SentFlags::OFF_PATH`].
    pub fn path_bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight - self.off_path_bytes
    }

    /// Returns the number of ack-eliciting packets neither acknowledged nor declared lost.
    pub fn ack_eliciting_in_flight(&self) -> u32 {
        self.ack_eliciting_in_flight
    }

    /// Returns when the most recent ack-eliciting packet was sent.
    pub fn last_ack_eliciting_time(&self) -> Option<Instant> {
        self.last_ack_eliciting.map(|t| self.instant(t))
    }

    fn instant(&self, offset: u64) -> Instant {
        self.epoch + Duration::from_nanos(offset)
    }

    fn offset(&self, t: Instant) -> u64 {
        // Saturates after 584 years.
        u64::try_from(t.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }
}

fn duration_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Returns the frame records of `pkts[i]`: from its first record to the next packet's first.
fn frames_of<'a>(
    pkts: &VecDeque<SentPkt>,
    frames: &'a VecDeque<SentFrame>,
    frames_front: u32,
    frames_end: u32,
    i: usize,
) -> vec_deque::Iter<'a, SentFrame> {
    let start = pkts[i].frames;
    let end = pkts.get(i + 1).map_or(frames_end, |next| next.frames);
    let start = start.wrapping_sub(frames_front) as usize;
    let end = end.wrapping_sub(frames_front) as usize;
    frames.range(start..end)
}

#[cfg(test)]
#[expect(
    clippy::single_range_in_vec_init,
    reason = "a one-element array of ranges is an ACK frame with one range"
)]
mod tests {
    use mvfstr_wire::Dir;
    use mvfstr_wire::Side;

    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const ELICITING: SentFlags = SentFlags::ACK_ELICITING.union(SentFlags::IN_FLIGHT);

    fn stream_frame(offset: u64) -> SentFrame {
        SentFrame::Stream {
            id: StreamId::new(Side::Server, Dir::Uni, 0).unwrap(),
            offset,
            len: 1000,
            fin: false,
        }
    }

    fn frames(p: &SentPacket<'_>) -> Vec<SentFrame> {
        p.frames().copied().collect()
    }

    #[test]
    fn sent_packets_are_recorded_with_their_frames() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 100);
        assert_eq!(s.next_pn(), 100);
        s.push_frame(stream_frame(0));
        s.push_frame(SentFrame::Ack { largest: 7 });
        s.on_sent(100, t0 + MS, 1200, ELICITING, 7).unwrap();
        s.push_frame(SentFrame::Ack { largest: 9 });
        s.on_sent(101, t0 + 2 * MS, 50, SentFlags::empty(), 8)
            .unwrap();
        assert_eq!(s.next_pn(), 102);
        assert_eq!(s.bytes_in_flight(), 1200);
        assert_eq!(s.ack_eliciting_in_flight(), 1);
        assert_eq!(s.last_ack_eliciting_time(), Some(t0 + MS));

        let p = s.get(100).unwrap();
        assert_eq!(
            (p.pn, p.time_sent, p.size, p.flags, p.tx_seq),
            (100, t0 + MS, 1200, ELICITING, 7)
        );
        assert_eq!(
            frames(&p),
            vec![stream_frame(0), SentFrame::Ack { largest: 7 }]
        );
        let p = s.get(101).unwrap();
        assert_eq!((p.size, p.flags, p.tx_seq), (50, SentFlags::empty(), 8));
        assert_eq!(frames(&p), vec![SentFrame::Ack { largest: 9 }]);
        assert!(s.get(99).is_none());
        assert!(s.get(102).is_none());
    }

    #[test]
    fn frames_of_an_abandoned_packet_are_forgotten() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        s.push_frame(stream_frame(0));
        s.on_sent(0, t0, 1200, ELICITING, 0).unwrap();
        s.push_frame(stream_frame(1000));
        s.push_frame(SentFrame::Ping);
        s.abandon_frames();
        s.push_frame(stream_frame(2000));
        s.on_sent(1, t0, 1200, ELICITING, 1).unwrap();
        assert_eq!(frames(&s.get(0).unwrap()), vec![stream_frame(0)]);
        assert_eq!(frames(&s.get(1).unwrap()), vec![stream_frame(2000)]);
    }

    #[test]
    fn an_ack_eliciting_packet_not_in_flight_is_refused() {
        // Such a record would keep the PTO armed: pruning drops a packet not in flight without
        // taking it out of the ack-eliciting count.
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        s.push_frame(SentFrame::Ping);
        assert_eq!(
            s.on_sent(0, t0, 1200, SentFlags::ACK_ELICITING, 0),
            Err(SentError::AckElicitingNotInFlight)
        );
        assert_eq!(
            (s.next_pn(), s.tracked(), s.ack_eliciting_in_flight()),
            (0, 0, 0)
        );
        // The refused call kept the pending frame.
        s.on_sent(0, t0, 1200, ELICITING, 0).unwrap();
        assert_eq!(frames(&s.get(0).unwrap()), vec![SentFrame::Ping]);
    }

    #[test]
    fn packet_numbers_never_repeat_and_gaps_are_recorded_as_skipped() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 10);
        s.on_sent(10, t0, 1200, ELICITING, 0).unwrap();
        s.push_frame(stream_frame(0));
        assert_eq!(
            s.on_sent(10, t0, 1200, ELICITING, 1),
            Err(SentError::PnReused { pn: 10, next: 11 })
        );
        assert_eq!(
            s.on_sent(11 + SentPackets::MAX_SKIP + 1, t0, 1200, ELICITING, 1),
            Err(SentError::SkipTooLarge)
        );
        assert_eq!(s.next_pn(), 11);
        // The refused calls kept the pending frame; 11 and 12 are skipped.
        s.on_sent(13, t0, 1200, ELICITING, 1).unwrap();
        assert_eq!(s.next_pn(), 14);
        assert!(s.get(11).is_none());
        assert!(s.get(12).is_none());
        assert_eq!(frames(&s.get(13).unwrap()), vec![stream_frame(0)]);
        assert_eq!(s.bytes_in_flight(), 2400);
        assert_eq!(s.ack_eliciting_in_flight(), 2);
    }

    /// Builds a ring holding packets `0..n`, each ack-eliciting, 1,200 bytes, sent `pn` ms after
    /// `t0` with one STREAM frame at offset `1000 * pn`.
    fn ring(t0: Instant, n: u64) -> SentPackets {
        let mut s = SentPackets::new(t0, 0);
        for pn in 0..n {
            s.push_frame(stream_frame(1000 * pn));
            s.on_sent(pn, t0 + pn as u32 * MS, 1200, ELICITING, pn)
                .unwrap();
        }
        s
    }

    /// Applies one ACK frame to `s` and returns its summary and events, sorted by packet number.
    fn ack(
        s: &mut SentPackets,
        ranges: &[RangeInclusive<u64>],
        now: Instant,
    ) -> Result<(AckSummary, Vec<Event>), AckError> {
        let mut events = Vec::new();
        let summary = s.on_ack(ranges.iter().cloned(), now, |e| events.push(event(&e)))?;
        events.sort_by_key(|e| e.1);
        Ok((summary, events))
    }

    /// A packet event as (kind, packet number, frames).
    type Event = (&'static str, u64, Vec<SentFrame>);

    fn event(e: &PacketEvent<'_>) -> Event {
        let (kind, p) = match e {
            PacketEvent::Acked(p) => ("acked", p),
            PacketEvent::AckedAfterLoss(p) => ("acked-after-loss", p),
            PacketEvent::Lost(p) => ("lost", p),
        };
        (kind, p.pn, frames(p))
    }

    #[test]
    fn an_ack_reports_each_newly_acknowledged_packet_once() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 5);
        let (summary, events) = ack(&mut s, &[3..=4, 0..=1], t0 + 10 * MS).unwrap();
        assert_eq!(summary.newly_acked, 4);
        assert_eq!(summary.acked_bytes, 4800);
        let acked: Vec<_> = events.iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(
            acked,
            vec![("acked", 0), ("acked", 1), ("acked", 3), ("acked", 4)]
        );
        assert_eq!(events[2].2, vec![stream_frame(3000)]);
        assert_eq!(s.bytes_in_flight(), 1200);
        assert_eq!(s.ack_eliciting_in_flight(), 1);
        // Ranges repeated by a later ACK frame report only the new packet.
        let (summary, events) = ack(&mut s, &[0..=4], t0 + 11 * MS).unwrap();
        assert_eq!(summary.newly_acked, 1);
        assert_eq!(events, vec![("acked", 2, vec![stream_frame(2000)])]);
        assert_eq!(s.bytes_in_flight(), 0);
        assert_eq!(s.ack_eliciting_in_flight(), 0);
    }

    #[test]
    fn acknowledging_an_unsent_or_skipped_packet_number_is_an_error() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 3);
        assert_eq!(
            ack(&mut s, &[3..=3], t0).unwrap_err(),
            AckError::UnsentPacket(3)
        );
        s.on_sent(4, t0, 1200, ELICITING, 3).unwrap();
        assert_eq!(
            ack(&mut s, &[2..=4], t0).unwrap_err(),
            AckError::SkippedPacket(3)
        );
        assert_eq!(
            AckError::SkippedPacket(3).code(),
            TransportErrorCode::PROTOCOL_VIOLATION
        );
        // Also below the largest acknowledged.
        let mut s = ring(t0, 2);
        s.on_sent(3, t0, 1200, ELICITING, 2).unwrap();
        ack(&mut s, &[3..=3], t0).unwrap();
        assert_eq!(
            ack(&mut s, &[2..=2], t0).unwrap_err(),
            AckError::SkippedPacket(2)
        );
        // Even with an empty ring, an ACK of a number not sent yet is an error.
        let mut empty = SentPackets::new(t0, 50);
        assert_eq!(
            ack(&mut empty, &[50..=50], t0).unwrap_err(),
            AckError::UnsentPacket(50)
        );
    }

    #[test]
    fn an_rtt_sample_needs_a_newly_acknowledged_largest_and_an_ack_eliciting_packet() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 5);
        let (summary, _) = ack(&mut s, &[0..=2], t0 + 10 * MS).unwrap();
        assert_eq!(summary.rtt_sample, Some(8 * MS));
        assert_eq!(summary.largest_newly_acked, Some((2, t0 + 2 * MS)));
        assert_eq!(s.largest_acked(), Some(2));
        let (summary, _) = ack(&mut s, &[3..=3], t0 + 11 * MS).unwrap();
        assert_eq!(summary.rtt_sample, Some(8 * MS));
        s.on_sent(5, t0 + 5 * MS, 1200, ELICITING, 5).unwrap();
        let (summary, _) = ack(&mut s, &[5..=5, 4..=4], t0 + 4 * MS).unwrap();
        // An ACK that arrives before the largest packet's send time does not yield a sample.
        assert_eq!(summary.rtt_sample, None);
        assert_eq!(summary.largest_newly_acked, Some((5, t0 + 5 * MS)));
        assert_eq!(s.largest_acked(), Some(5));

        let mut s = ring(t0, 2);
        let (summary, _) = ack(&mut s, &[1..=1], t0 + 10 * MS).unwrap();
        assert_eq!(summary.rtt_sample, Some(9 * MS));
        // Packet 0 is new but the largest is not, so the ACK does not yield a sample.
        let (summary, _) = ack(&mut s, &[0..=1], t0 + 12 * MS).unwrap();
        assert_eq!(summary.newly_acked, 1);
        assert_eq!(summary.rtt_sample, None);
        assert_eq!(s.largest_acked(), Some(1));

        // A non-eliciting largest yields a sample only with an ack-eliciting packet beside it.
        let mut s = ring(t0, 1);
        s.on_sent(1, t0 + MS, 40, SentFlags::empty(), 1).unwrap();
        s.on_sent(2, t0 + 2 * MS, 40, SentFlags::empty(), 2)
            .unwrap();
        let (summary, _) = ack(&mut s, &[1..=1], t0 + 10 * MS).unwrap();
        assert_eq!(summary.rtt_sample, None);
        let (summary, _) = ack(&mut s, &[2..=2, 0..=0], t0 + 10 * MS).unwrap();
        assert_eq!(summary.rtt_sample, Some(8 * MS));
    }

    fn params(loss_delay: Duration) -> LossParams {
        LossParams {
            loss_delay,
            packet_threshold: 3,
            first_rtt_sample: None,
            persistent_congestion: Duration::from_secs(3600),
        }
    }

    fn detect(s: &mut SentPackets, now: Instant, params: &LossParams) -> (LossSummary, Vec<Event>) {
        let mut events = Vec::new();
        let summary = s.detect_lost(now, params, |e| events.push(event(&e)));
        (summary, events)
    }

    #[test]
    fn packets_three_below_the_largest_acknowledged_are_lost() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 10);
        ack(&mut s, &[5..=5], t0 + 6 * MS).unwrap();
        let (summary, events) = detect(&mut s, t0 + 6 * MS, &params(Duration::from_secs(1)));
        let lost: Vec<_> = events.iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(lost, vec![("lost", 0), ("lost", 1), ("lost", 2)]);
        assert_eq!(events[1].2, vec![stream_frame(1000)]);
        assert_eq!(summary.lost_packets, 3);
        assert_eq!(summary.lost_bytes, 3600);
        assert_eq!(summary.largest_lost_sent, Some(t0 + 2 * MS));
        assert!(!summary.persistent_congestion);
        assert_eq!(s.bytes_in_flight(), 7200);
        assert_eq!(s.ack_eliciting_in_flight(), 6);
        // 3 and 4 wait for the time threshold; packets above the largest acknowledged do not count.
        assert_eq!(s.loss_time(), Some(t0 + 3 * MS + Duration::from_secs(1)));
        // A second pass does not find new losses.
        let (summary, events) = detect(&mut s, t0 + 7 * MS, &params(Duration::from_secs(1)));
        assert_eq!((summary.lost_packets, events.len()), (0, 0));
    }

    #[test]
    fn packets_sent_a_loss_delay_before_now_are_lost() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 3);
        ack(&mut s, &[2..=2], t0 + 10 * MS).unwrap();
        let delay = Duration::from_micros(9_500);
        // Packet 0 was sent 10 ms ago; packet 1, 9 ms ago, waits until 1 + 9.5 ms.
        let (summary, events) = detect(&mut s, t0 + 10 * MS, &params(delay));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), vec![0]);
        assert_eq!(summary.largest_lost_sent, Some(t0));
        assert_eq!(s.loss_time(), Some(t0 + MS + delay));
        // At exactly the loss time the packet is lost (sent at or before now - loss_delay).
        let (_, events) = detect(&mut s, t0 + MS + delay, &params(delay));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), vec![1]);
        assert_eq!(s.loss_time(), None);
        assert_eq!(s.bytes_in_flight(), 0);
    }

    #[test]
    fn a_packet_is_never_declared_lost_before_its_release() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        for pn in 0..4 {
            s.on_sent(pn, t0 + 100 * MS, 1200, ELICITING, pn).unwrap();
        }
        // An ACK of 3 before the recorded release of 0, from a clock error or an early departure.
        ack(&mut s, &[3..=3], t0 + 10 * MS).unwrap();
        let (summary, _) = detect(&mut s, t0 + 10 * MS, &params(Duration::from_secs(1)));
        assert_eq!(summary.lost_packets, 0);
        assert_eq!(s.bytes_in_flight(), 3600);
        assert_eq!(s.loss_time(), Some(t0 + 100 * MS + Duration::from_secs(1)));
        // Once released, the packet threshold applies.
        let (_, events) = detect(&mut s, t0 + 110 * MS, &params(Duration::from_secs(1)));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn a_late_ack_of_a_lost_packet_reports_a_spurious_loss() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 5);
        ack(&mut s, &[4..=4], t0 + 5 * MS).unwrap();
        detect(&mut s, t0 + 5 * MS, &params(Duration::from_secs(1)));
        assert_eq!(s.bytes_in_flight(), 2400);
        let (summary, events) = ack(&mut s, &[4..=4, 0..=0], t0 + 6 * MS).unwrap();
        assert_eq!(events, vec![("acked-after-loss", 0, vec![stream_frame(0)])]);
        assert_eq!(summary.spurious, 1);
        assert_eq!(summary.newly_acked, 0);
        assert_eq!(summary.acked_bytes, 0);
        assert_eq!(summary.rtt_sample, None);
        assert_eq!(s.bytes_in_flight(), 2400);
        // Reported once.
        let (summary, events) = ack(&mut s, &[0..=0], t0 + 7 * MS).unwrap();
        assert_eq!((summary.spurious, events.len()), (0, 0));
    }

    /// Reproduces the persistent congestion example of RFC 9002 with one time unit of 10 ms:
    /// packets 1-7 at t = 0..6, the PTO probes 8 and 9 at t = 8 and 12, packet 1 acknowledged at
    /// t = 1.2 and packet 9 at t = 12.2 with the extra ranges given; the persistent congestion
    /// duration is 2 * 3 = 6 units. Returns what loss detection declares at t = 12.2 when the
    /// first RTT sample was taken at `first_sample` tenths of a unit.
    fn rfc_9002_example(first_sample: u32, extra: &[RangeInclusive<u64>]) -> LossSummary {
        let t0 = crate::recovery::test_epoch();
        let unit = 10 * MS;
        let mut s = SentPackets::new(t0, 1);
        for (pn, t) in (1..=9).zip([0, 1, 2, 3, 4, 5, 6, 8, 12]) {
            s.on_sent(pn, t0 + t * unit, 1200, ELICITING, pn).unwrap();
        }
        ack(&mut s, &[1..=1], t0 + unit * 12 / 10).unwrap();
        let mut ranges = vec![9..=9];
        ranges.extend_from_slice(extra);
        ack(&mut s, &ranges, t0 + unit * 122 / 10).unwrap();
        let params = LossParams {
            loss_delay: unit,
            packet_threshold: 3,
            first_rtt_sample: Some(t0 + unit * first_sample / 10),
            persistent_congestion: 6 * unit,
        };
        let (summary, _) = detect(&mut s, t0 + unit * 122 / 10, &params);
        summary
    }

    #[test]
    fn persistent_congestion_needs_a_long_enough_unacknowledged_run_after_the_first_sample() {
        // Packets 2-8 are lost. With a sample before packet 2 the run spans 8 - 1 = 7 > 6.
        let summary = rfc_9002_example(9, &[]);
        assert_eq!(summary.lost_packets, 7);
        assert!(summary.persistent_congestion);
        // As the RFC's table is written the sample (t = 1.2) follows packet 2 (t = 1), so the RFC's
        // pseudocode leaves packet 2 out: the run is 3-8, 6 units, not more than 6.
        assert!(!rfc_9002_example(12, &[]).persistent_congestion);
        // An acknowledged packet inside the run breaks it.
        let summary = rfc_9002_example(9, &[5..=5]);
        assert_eq!(summary.lost_packets, 6);
        assert!(!summary.persistent_congestion);
    }

    #[test]
    fn resolved_records_leave_the_ring_with_their_frames() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 5);
        ack(&mut s, &[0..=1], t0 + 10 * MS).unwrap();
        s.prune(t0);
        assert_eq!(s.tracked(), 3);
        assert!(s.get(1).is_none());
        assert_eq!(frames(&s.get(2).unwrap()), vec![stream_frame(2000)]);
        // Packet 2 is lost by time and kept until the cutoff passes its send time.
        ack(&mut s, &[4..=4], t0 + 10 * MS).unwrap();
        let (_, events) = detect(&mut s, t0 + 10 * MS, &params(Duration::from_micros(7_500)));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), vec![2]);
        s.prune(t0 + 2 * MS);
        assert_eq!(s.tracked(), 3);
        s.prune(t0 + 3 * MS);
        assert_eq!(s.tracked(), 2);
        assert_eq!(frames(&s.get(3).unwrap()), vec![stream_frame(3000)]);

        // A packet not in flight at the front goes once older than the cutoff.
        let mut s = SentPackets::new(t0, 0);
        s.push_frame(SentFrame::Ack { largest: 1 });
        s.on_sent(0, t0, 40, SentFlags::empty(), 0).unwrap();
        s.push_frame(SentFrame::Ping);
        s.on_sent(1, t0 + MS, 40, ELICITING, 1).unwrap();
        s.prune(t0);
        assert_eq!(s.tracked(), 2);
        s.prune(t0 + MS);
        assert_eq!(s.tracked(), 1);
        assert_eq!(frames(&s.get(1).unwrap()), vec![SentFrame::Ping]);

        // A skipped number stays until a later packet is acknowledged.
        let mut s = ring(t0, 1);
        s.on_sent(2, t0, 1200, ELICITING, 1).unwrap();
        ack(&mut s, &[0..=0], t0 + MS).unwrap();
        s.prune(t0);
        assert_eq!(s.tracked(), 2);
        ack(&mut s, &[2..=2], t0 + MS).unwrap();
        s.prune(t0);
        assert_eq!(s.tracked(), 0);
        s.push_frame(SentFrame::Ping);
        s.on_sent(3, t0 + 2 * MS, 40, ELICITING, 2).unwrap();
        assert_eq!(frames(&s.get(3).unwrap()), vec![SentFrame::Ping]);
    }

    #[test]
    fn discarding_the_space_forgets_every_packet() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 6);
        ack(&mut s, &[5..=5], t0 + 10 * MS).unwrap();
        detect(&mut s, t0 + 10 * MS, &params(Duration::from_secs(1)));
        assert!(s.loss_time().is_some());
        assert_eq!(s.discard(), 2400);
        assert_eq!(s.bytes_in_flight(), 0);
        assert_eq!(s.ack_eliciting_in_flight(), 0);
        assert_eq!(s.tracked(), 0);
        assert_eq!(s.loss_time(), None);
        assert_eq!(s.last_ack_eliciting_time(), None);
        assert!(s.get(3).is_none());
        // Late acknowledgments of discarded packets are ignored.
        let (summary, events) = ack(&mut s, &[0..=5], t0 + 11 * MS).unwrap();
        assert_eq!((summary.newly_acked, events.len()), (0, 0));
    }

    #[test]
    fn packets_sent_before_a_new_path_stay_tracked_but_leave_its_bytes_in_flight() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 4);
        s.start_path();
        assert_eq!((s.bytes_in_flight(), s.path_bytes_in_flight()), (4800, 0));
        assert_eq!(s.path_from(), 4);
        for pn in 4..8 {
            s.push_frame(stream_frame(1000 * pn));
            s.on_sent(pn, t0 + pn as u32 * MS, 1200, ELICITING, pn)
                .unwrap();
        }
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (9600, 4800)
        );

        // Old packets are still acknowledged and declared lost, which leaves the path's count
        // alone. Acknowledging 5 declares 0-2 lost and leaves 3, 4, 6 and 7.
        ack(&mut s, &[5..=5], t0 + 9 * MS).unwrap();
        let (_, events) = detect(&mut s, t0 + 9 * MS, &params(Duration::from_secs(1)));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (4800, 3600)
        );
        let (_, events) = ack(&mut s, &[5..=5, 3..=3], t0 + 9 * MS).unwrap();
        assert_eq!(events, [("acked", 3, vec![stream_frame(3000)])]);
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (3600, 3600)
        );

        // A second new path leaves out everything sent before it, whichever path it went on.
        s.start_path();
        assert_eq!(s.path_from(), 8);
        s.on_sent(8, t0 + 10 * MS, 1200, ELICITING, 8).unwrap();
        ack(&mut s, &[3..=5], t0 + 11 * MS).unwrap();
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (3600, 1200)
        );
        s.on_tx_dropped(TxSeqRange { start: 6, end: 8 }, |_| {});
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (1200, 1200)
        );
        s.on_tx_dropped(TxSeqRange { start: 8, end: 9 }, |_| {});
        assert_eq!((s.bytes_in_flight(), s.path_bytes_in_flight()), (0, 0));
        s.on_sent(9, t0 + 12 * MS, 1200, ELICITING, 9).unwrap();
        s.start_path();
        assert_eq!(s.discard(), 1200);
        assert_eq!((s.bytes_in_flight(), s.path_bytes_in_flight()), (0, 0));
    }

    #[test]
    fn packets_sent_to_another_address_stay_tracked_but_count_neither_in_flight_nor_for_rtt() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        let off_path = ELICITING | SentFlags::OFF_PATH;
        s.on_sent(0, t0, 1200, ELICITING, 0).unwrap();
        s.on_sent(1, t0 + MS, 1200, off_path, 1).unwrap();
        s.on_sent(2, t0 + 2 * MS, 1200, ELICITING, 2).unwrap();
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (3600, 2400)
        );

        // An ACK whose largest packet went to the other address does not give an RTT sample.
        let (summary, events) = ack(&mut s, &[1..=1], t0 + 10 * MS).unwrap();
        assert_eq!(events, [("acked", 1, vec![])]);
        assert_eq!(summary.rtt_sample, None);
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (2400, 2400)
        );
        let (summary, _) = ack(&mut s, &[1..=2], t0 + 12 * MS).unwrap();
        assert_eq!(
            summary.rtt_sample,
            Some(10 * MS),
            "packet 2 went on the path"
        );

        // Such packets are declared lost like any other, and those sent before a new path leave
        // its count only once. Acknowledging 8 declares 0 and 3-5 lost and leaves 6 and 7.
        s.on_sent(3, t0 + 13 * MS, 1200, off_path, 3).unwrap();
        s.on_sent(4, t0 + 14 * MS, 1200, off_path, 4).unwrap();
        s.start_path();
        assert_eq!((s.bytes_in_flight(), s.path_bytes_in_flight()), (3600, 0));
        for pn in 5..9 {
            s.on_sent(pn, t0 + (10 + pn as u32) * MS, 1200, ELICITING, pn)
                .unwrap();
        }
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (8400, 4800)
        );
        ack(&mut s, &[8..=8], t0 + 20 * MS).unwrap();
        let (_, events) = detect(&mut s, t0 + 20 * MS, &params(Duration::from_secs(1)));
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), [0, 3, 4, 5]);
        assert_eq!(
            (s.bytes_in_flight(), s.path_bytes_in_flight()),
            (2400, 2400)
        );
    }

    #[test]
    fn packets_sent_on_another_path_give_the_controller_no_acknowledged_bytes_or_losses() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        let off_path = ELICITING | SentFlags::OFF_PATH;
        // 0 went on the previous path, 1, 4 and 5 to the alternate path's address, and the
        // others on the current path.
        s.on_sent(0, t0, 1200, ELICITING, 0).unwrap();
        s.start_path();
        let sends = [
            (1, off_path, 10),
            (2, ELICITING, 20),
            (3, ELICITING, 25),
            (4, off_path, 30),
            (5, off_path, 40),
            (6, ELICITING, 50),
            (7, ELICITING, 51),
            (8, ELICITING, 52),
        ];
        for (pn, flags, ms) in sends {
            s.on_sent(pn, t0 + ms * MS, 1200, flags, pn).unwrap();
        }
        let on_path: Vec<_> = (0..9).filter(|&pn| s.get(pn).unwrap().on_path).collect();
        assert_eq!(on_path, [2, 3, 6, 7, 8]);

        // An acknowledgment counts only the bytes of packets that went on the current path.
        let (summary, _) = ack(&mut s, &[0..=1], t0 + 60 * MS).unwrap();
        assert_eq!((summary.newly_acked, summary.acked_bytes), (2, 0));
        let (summary, _) = ack(&mut s, &[0..=3], t0 + 60 * MS).unwrap();
        assert_eq!((summary.newly_acked, summary.acked_bytes), (2, 2400));

        // Losses of packets that went elsewhere count as losses, but do not start a congestion
        // event or establish persistent congestion, even in a run long enough to.
        let params = LossParams {
            first_rtt_sample: Some(t0),
            persistent_congestion: Duration::from_micros(500),
            ..params(Duration::from_secs(1))
        };
        ack(&mut s, &[8..=8], t0 + 60 * MS).unwrap();
        let (summary, events) = detect(&mut s, t0 + 60 * MS, &params);
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), [4, 5]);
        assert_eq!((summary.lost_packets, summary.lost_bytes), (2, 2400));
        assert_eq!(summary.largest_lost_sent, None);
        assert!(!summary.persistent_congestion);

        // The same run on the current path does both.
        let (summary, events) = detect(&mut s, t0 + 2000 * MS, &params);
        assert_eq!(events.iter().map(|e| e.1).collect::<Vec<_>>(), [6, 7]);
        assert_eq!(summary.largest_lost_sent, Some(t0 + 51 * MS));
        assert!(summary.persistent_congestion);
    }

    #[test]
    fn packets_in_dropped_datagrams_are_lost_at_once() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 6);
        ack(&mut s, &[4..=4], t0 + 10 * MS).unwrap();
        let mut events = Vec::new();
        let summary = s.on_tx_dropped(TxSeqRange { start: 2, end: 5 }, |e| events.push(event(&e)));
        events.sort_by_key(|e| e.1);
        assert_eq!(
            events,
            vec![
                ("lost", 2, vec![stream_frame(2000)]),
                ("lost", 3, vec![stream_frame(3000)])
            ]
        );
        assert_eq!(summary.lost_packets, 2);
        assert_eq!(summary.lost_bytes, 2400);
        assert_eq!(summary.largest_lost_sent, Some(t0 + 3 * MS));
        assert_eq!(s.bytes_in_flight(), 3600);
        assert_eq!(s.ack_eliciting_in_flight(), 3);
    }

    #[test]
    fn a_late_ack_of_a_packet_in_a_dropped_datagram_is_not_a_spurious_loss() {
        let t0 = crate::recovery::test_epoch();
        let mut s = ring(t0, 3);
        s.on_tx_dropped(TxSeqRange { start: 1, end: 2 }, |_| {});
        assert_eq!(s.declared_lost(), 0);
        // A drop is not a congestion signal, so its acknowledgment does not prove a loss spurious.
        let (summary, events) = ack(&mut s, &[0..=2], t0 + 10 * MS).unwrap();
        assert_eq!(summary.spurious, 0);
        assert_eq!(events[1], ("acked-after-loss", 1, vec![stream_frame(1000)]));
    }

    #[test]
    fn repeated_acks_behind_a_lost_packet_skip_the_records_already_acknowledged() {
        let t0 = crate::recovery::test_epoch();
        let now = t0 + Duration::from_secs(30);
        let mut s = ring(t0, 20_000);
        // Packet 0 is lost and pins the front of the ring for a while.
        ack(&mut s, &[1..=19_999], now).unwrap();
        let (summary, _) = detect(&mut s, now, &params(Duration::from_secs(1)));
        assert_eq!(summary.lost_packets, 1);
        assert_eq!(s.tracked(), 20_000);
        // Processing ACK frames that repeat the ranges, which a peer may send many of in one
        // packet, visits only the records they could still change.
        s.examined = 0;
        for _ in 0..100 {
            let (summary, _) = ack(&mut s, &[1..=19_999], now).unwrap();
            assert_eq!(summary.newly_acked, 0);
            detect(&mut s, now, &params(Duration::from_secs(1)));
        }
        assert!(s.examined <= 100, "{}", s.examined);
        // The lost packet is still found when acknowledged late.
        let (summary, _) = ack(&mut s, &[0..=19_999], now).unwrap();
        assert_eq!(summary.spurious, 1);
    }

    #[test]
    fn steady_state_sending_reuses_the_ring_capacity() {
        let t0 = crate::recovery::test_epoch();
        let mut s = SentPackets::new(t0, 0);
        // Ten packets of two frames each in flight; each round acknowledges the oldest.
        let mut capacity = None;
        for pn in 0..10_000u64 {
            let at = t0 + Duration::from_micros(100 * pn);
            s.push_frame(stream_frame(pn * 1000));
            s.push_frame(SentFrame::Ping);
            s.on_sent(pn, at, 1200, ELICITING, pn).unwrap();
            if pn >= 10 {
                s.on_ack([pn - 10..=pn - 10], at, |_| {}).unwrap();
                s.prune(at);
            }
            if pn == 100 {
                capacity = Some((s.pkts.capacity(), s.frames.capacity()));
            }
        }
        assert_eq!(Some((s.pkts.capacity(), s.frames.capacity())), capacity);
        assert_eq!(s.tracked(), 10);
    }
}
