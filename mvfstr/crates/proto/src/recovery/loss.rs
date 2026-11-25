/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Loss detection for a connection: the sent packets of the three spaces, the RTT estimator,
//! the loss detection timer with PTO backoff, probes and per-space discard (RFC 9002).

use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::Side;

use super::RttEstimator;
use super::Space;
use super::sent::AckError;
use super::sent::AckSummary;
use super::sent::LossParams;
use super::sent::LossSummary;
use super::sent::LostSample;
use super::sent::PacketEvent;
use super::sent::SendSnapshot;
use super::sent::SentError;
use super::sent::SentFlags;
use super::sent::SentFrame;
use super::sent::SentPacket;
use super::sent::SentPackets;
use crate::config::ConfigError;
use crate::transmit::TxSeqRange;

/// Loss detection constants (RFC 9002). The defaults are the RFC's; mvfst's differ where noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryConfig {
    /// kInitialRtt: the RTT assumed before the first sample (`TransportConfig::initial_rtt`),
    /// nonzero and at most [`RecoveryConfig::MAX_TIMER_SETTING`]. RFC 333 ms; mvfst 50 ms.
    pub initial_rtt: Duration,
    /// kPacketThreshold, at least 3 (RFC 9002). RFC and mvfst 3.
    pub packet_threshold: u32,
    /// kTimeThreshold as (numerator, denominator). RFC 9/8; mvfst 5/4.
    pub time_threshold: (u32, u32),
    /// kGranularity, the timer granularity, nonzero and at most
    /// [`RecoveryConfig::MAX_TIMER_SETTING`]. RFC 1 ms; mvfst 10 ms.
    pub granularity: Duration,
    /// kPersistentCongestionThreshold, in PTO periods. RFC 3.
    pub persistent_congestion_threshold: u32,
    /// The probe datagrams due in the space whose PTO expired, 1 or 2 (RFC 9002).
    pub pto_probes: u8,
    /// Whether to keep the per-packet send snapshots and the connection's delivery state that
    /// delivery-rate samples and per-packet losses are built from, for a controller that takes
    /// them ([`crate::cc::takes_rate_samples`]). Off by default.
    pub rate_samples: bool,
}

impl RecoveryConfig {
    /// The largest initial RTT and granularity accepted: far above any real path, and small
    /// enough that the timer arithmetic cannot overflow.
    pub const MAX_TIMER_SETTING: Duration = Duration::from_secs(3600);

    /// Refuses settings that loss detection cannot work with. Fails with
    /// [`ConfigError::OutOfRange`], naming the first field out of range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let check = |ok: bool, field| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::OutOfRange { field })
            }
        };
        let timer = |d: Duration| !d.is_zero() && d <= Self::MAX_TIMER_SETTING;
        check(timer(self.initial_rtt), "initial_rtt")?;
        // A zero RTT sample with a zero granularity would make the PTO period zero, which
        // backoff cannot grow.
        check(timer(self.granularity), "granularity")?;
        check(self.packet_threshold >= 3, "packet_threshold")?;
        check(
            self.time_threshold.0 > 0 && self.time_threshold.1 > 0,
            "time_threshold",
        )?;
        check(
            self.persistent_congestion_threshold >= 1,
            "persistent_congestion_threshold",
        )?;
        check((1..=2).contains(&self.pto_probes), "pto_probes")
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            initial_rtt: Duration::from_millis(333),
            packet_threshold: 3,
            time_threshold: (9, 8),
            granularity: Duration::from_millis(1),
            persistent_congestion_threshold: 3,
            pto_probes: 2,
            rate_samples: false,
        }
    }
}

/// The outcome of one ACK frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckOutcome {
    /// A summary of the packets it newly acknowledged.
    pub ack: AckSummary,
    /// A summary of the packets loss detection then declared lost in the same space.
    pub loss: LossSummary,
    /// Whether it updated the RTT estimate.
    pub rtt_updated: bool,
    /// When it proved every loss of the current loss episode spurious, the episode's start: the
    /// congestion controller may undo the reduction of the recovery period that began then
    /// ([`crate::cc::Cc::on_spurious_loss`], RFC 9438).
    pub spurious_congestion: Option<Instant>,
    /// The send time of the frame's largest newly acknowledged packet that is in flight and went
    /// on the current path; kept only when [`RecoveryConfig::rate_samples`] is on.
    pub largest_in_flight_sent: Option<Instant>,
    /// The frame's delivery-rate sample, when [`RecoveryConfig::rate_samples`] is on and it newly
    /// acknowledged an in-flight packet sent on the current path.
    pub rate: Option<RateSample>,
}

/// One delivery-rate sample of the BBR draft (draft-ietf-ccwg-bbr-07), built per ACK frame from the
/// newest on-path in-flight packet the frame newly acknowledged, as mvfst's BBR3 builds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateSample {
    /// RS.prior_delivered: C.delivered when the newest packet was sent.
    pub prior_delivered: u64,
    /// RS.delivered: the bytes delivered since then, the frame's included.
    pub delivered: u64,
    /// RS.interval: the larger of the send and ACK elapsed times, in whole microseconds.
    pub interval: Duration,
    /// RS.delivery_rate in bytes per second; 0 when the interval is.
    pub delivery_rate: u64,
    /// RS.is_app_limited: whether the sample is application-limited.
    pub is_app_limited: bool,
    /// RS.tx_in_flight: the bytes in flight, the newest packet included, right after it was
    /// sent.
    pub tx_in_flight: u64,
    /// RS.lost: the bytes declared lost since the newest packet was sent, this frame's losses
    /// included.
    pub lost: u64,
    /// The bytes sent on the connection through the newest packet.
    pub total_sent: u64,
}

/// The newest (latest send, then largest number) and the largest-numbered of the on-path packets
/// with send snapshots that an ACK frame newly acknowledges.
#[derive(Default)]
struct AckedSnapshots {
    newest: Option<(Instant, u64, SendSnapshot)>,
    largest: Option<(u64, Instant)>,
}

impl AckedSnapshots {
    /// Takes in a newly acknowledged packet `p` with its `snapshot`. Kept out of line so the
    /// per-packet event path stays small enough to inline for connections without snapshots.
    #[inline(never)]
    fn note(&mut self, p: &SentPacket<'_>, snapshot: &SendSnapshot) {
        if self
            .newest
            .is_none_or(|(sent, pn, _)| (p.time_sent, p.pn) > (sent, pn))
        {
            self.newest = Some((p.time_sent, p.pn, *snapshot));
        }
        if self.largest.is_none_or(|(pn, _)| p.pn > pn) {
            self.largest = Some((p.pn, p.time_sent));
        }
    }
}

/// The event the loss detection timer is set for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossTimer {
    /// An outstanding packet in the space passes the time threshold.
    LossTime(Space),
    /// The probe timeout of the space expires.
    Pto(Space),
}

/// The outcome of [`LossRecovery::on_timeout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// The timer had not expired.
    None,
    /// Time threshold loss detection ran in the space.
    Lost(Space, LossSummary),
    /// The PTO of the space expired: probes are due (see [`LossRecovery::probes_due`]).
    Probe(Space),
}

/// Returns an ACK frame's adjusted ACK time for rate samples: its receive time `now` less its
/// decoded ACK Delay, in every space and without clamping to max_ack_delay. As in mvfst, a delay
/// above 1,000 s counts as 0. mvfst rejects a field whose scaled value overflows with
/// FRAME_ENCODING_ERROR, where mvfstr's ACK decoding gives `u64::MAX` µs, so such a delay counts
/// as 0 too, as does one that would reach back before the clock's origin.
fn adjusted_ack_time(now: Instant, ack_delay: Duration) -> Instant {
    const LONGEST: Duration = Duration::from_secs(1000);
    if ack_delay > LONGEST {
        return now;
    }
    now.checked_sub(ack_delay).unwrap_or(now)
}

/// Loss detection state for one connection and its current path (RFC 9002).
#[derive(Clone, Debug)]
pub struct LossRecovery {
    config: RecoveryConfig,
    side: Side,
    rtt: RttEstimator,
    spaces: [SentPackets; 3],
    handshake_confirmed: bool,
    /// Whether a client has received an acknowledgment of a Handshake packet.
    handshake_acked: bool,
    handshake_keys: bool,
    peer_max_ack_delay: Duration,
    pto_count: u32,
    probes_due: [u8; 3],
    /// The last event that restarts the PTO timer; a client's anti-deadlock PTO runs from it.
    timer_base: Instant,
    /// When the current loss episode began: the `now` of the detection that declared its first
    /// loss, which is when the controller starts the recovery period for it.
    episode_start: Option<Instant>,
    /// Whether a packet declared lost since the current episode began was forgotten unacknowledged,
    /// when old or with its space; if so, the episode's losses cannot all prove spurious.
    loss_confirmed: bool,
    /// The delivery state rate samples are built from, kept while
    /// [`RecoveryConfig::rate_samples`] is on.
    delivery: Delivery,
    /// The per-packet losses of the last ACK frame or loss timeout, reused.
    lost_samples: Vec<LostSample>,
    /// How many times [`LossRecovery::prune`] computed how long records are kept, for tests of
    /// its cost.
    #[cfg(test)]
    keep_computed: u64,
}

/// The connection's delivery state across the spaces, as the BBR draft defines it, with the
/// app-limited state of [`LossRecovery::mark_app_limited`] in place of C.app_limited.
#[derive(Clone, Debug)]
struct Delivery {
    /// C.delivered: bytes of on-path in-flight packets acknowledged before being declared lost.
    delivered: u64,
    /// C.total_sent: bytes of every packet sent on the current path or an earlier one, in flight
    /// or not.
    total_sent: u64,
    /// C.lost: bytes of on-path in-flight packets declared lost by loss detection since the
    /// current path began.
    lost: u64,
    /// The last frame's largest acknowledged packet: its send time (C.first_send_time) and the
    /// frame's adjusted ACK time (C.delivered_time).
    last_ack: Option<(Instant, Instant)>,
    /// The send time of the last packet sent into an empty pipe, which restarts the interval.
    restart: Option<Instant>,
    /// Whether packets sent now are stamped application-limited.
    app_limited: bool,
    /// The mark that [`LossRecovery::mark_app_limited`] sets, kept after the flag clears.
    app_limited_mark: Option<Instant>,
    /// The send time of the latest on-path in-flight packet, kept across a path change.
    last_send: Option<Instant>,
    /// The connection's start, where an interval starts when it does not follow an ACK or restart.
    epoch: Instant,
}

impl Delivery {
    fn new(epoch: Instant) -> Self {
        Self {
            delivered: 0,
            total_sent: 0,
            lost: 0,
            last_ack: None,
            restart: None,
            app_limited: false,
            app_limited_mark: None,
            last_send: None,
            epoch,
        }
    }

    /// Returns the send time, ACK time and kind of the start of the delivery interval of a
    /// packet sent now: the last restart if it came after the last ACK, else the last ACK, else
    /// the connection's start.
    fn interval_start(&self) -> (Instant, Instant, bool) {
        match (self.restart, self.last_ack) {
            (Some(restart), Some((_, acked))) if restart > acked => (restart, restart, true),
            (_, Some((sent, acked))) => (sent, acked, false),
            (Some(restart), None) => (restart, restart, true),
            (None, None) => (self.epoch, self.epoch, true),
        }
    }

    /// Builds the rate sample of an ACK frame received at `now` whose newest packet was sent at
    /// `sent` with `snapshot`; `adjusted` is the frame's receive time less its ACK Delay.
    fn sample(
        &self,
        sent: Instant,
        snapshot: &SendSnapshot,
        now: Instant,
        adjusted: Instant,
    ) -> RateSample {
        let delivered = self.delivered.saturating_sub(snapshot.delivered);
        let send_elapsed = sent.saturating_duration_since(snapshot.first_send_time);
        let ack_time = if snapshot.from_send { now } else { adjusted };
        let ack_elapsed = ack_time.saturating_duration_since(snapshot.delivered_time);
        let interval = send_elapsed.max(ack_elapsed);
        let interval =
            Duration::from_micros(u64::try_from(interval.as_micros()).unwrap_or(u64::MAX));
        // Samples shorter than min_rtt are kept, and a zero interval has a rate of 0.
        let rate = (u128::from(delivered) * 1_000_000)
            .checked_div(interval.as_micros())
            .unwrap_or(0);
        RateSample {
            prior_delivered: snapshot.delivered,
            delivered,
            interval,
            delivery_rate: u64::try_from(rate).unwrap_or(u64::MAX),
            is_app_limited: snapshot.app_limited
                || self
                    .app_limited_mark
                    .is_some_and(|mark| snapshot.first_send_time < mark),
            tx_in_flight: snapshot.tx_in_flight,
            lost: self.lost.saturating_sub(snapshot.lost),
            total_sent: snapshot.total_sent,
        }
    }
}

impl LossRecovery {
    /// The PTO backoff stops doubling here; the idle timeout ends the connection long before.
    const MAX_BACKOFF_SHIFT: u32 = 30;

    /// Creates the state for a new connection on `side`. Packet numbers in each space start at
    /// `first_pn[space]`; times are kept relative to `epoch`, the connection's creation. Fails
    /// with [`ConfigError::OutOfRange`] when [`RecoveryConfig::validate`] refuses `config`.
    pub fn new(
        config: RecoveryConfig,
        side: Side,
        epoch: Instant,
        first_pn: [u64; 3],
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            side,
            rtt: RttEstimator::new(config.initial_rtt),
            spaces: first_pn.map(|pn| SentPackets::new(epoch, pn)),
            handshake_confirmed: false,
            handshake_acked: false,
            handshake_keys: false,
            // RFC 9000's default when the transport parameter is absent.
            peer_max_ack_delay: Duration::from_millis(25),
            pto_count: 0,
            probes_due: [0; 3],
            timer_base: epoch,
            episode_start: None,
            loss_confirmed: false,
            delivery: Delivery::new(epoch),
            lost_samples: Vec::new(),
            #[cfg(test)]
            keep_computed: 0,
        })
    }

    /// Returns whether the delivery state and send snapshots are kept
    /// ([`RecoveryConfig::rate_samples`]).
    pub fn takes_rate_samples(&self) -> bool {
        self.config.rate_samples
    }

    /// Turns rate sampling on for a connection whose controller a test replaced with one that
    /// takes samples; packets already sent do not have a snapshot.
    #[cfg(test)]
    pub(crate) fn enable_rate_samples(&mut self) {
        self.config.rate_samples = true;
    }

    /// Returns C.delivered: bytes of on-path in-flight packets acknowledged before being declared
    /// lost, over the connection's life; 0 while [`RecoveryConfig::rate_samples`] is off.
    pub fn delivered(&self) -> u64 {
        self.delivery.delivered
    }

    /// Returns C.total_sent: bytes of every packet sent over the connection's life, off-path
    /// packets excepted; 0 while [`RecoveryConfig::rate_samples`] is off.
    pub fn total_sent(&self) -> u64 {
        self.delivery.total_sent
    }

    /// Returns C.lost: bytes of on-path in-flight packets declared lost by loss detection since
    /// the current path began; 0 while [`RecoveryConfig::rate_samples`] is off.
    pub fn lost(&self) -> u64 {
        self.delivery.lost
    }

    /// Returns whether packets sent now are stamped application-limited.
    pub fn is_app_limited(&self) -> bool {
        self.delivery.app_limited
    }

    /// Marks the connection application-limited, as mvfst's BBR3 does: packets sent from now on are
    /// stamped so. The mark is one microsecond after the latest on-path in-flight send, if any, and
    /// a sample whose interval starts before it, at that send included, is application-limited. The
    /// flag clears once the largest in-flight packet that an ACK frame newly acknowledges on the
    /// current path was sent at or after the mark.
    pub fn mark_app_limited(&mut self) {
        let d = &mut self.delivery;
        d.app_limited = true;
        d.app_limited_mark = d.last_send.map(|sent| sent + Duration::from_micros(1));
    }

    /// Returns the per-packet losses of the last ACK frame or loss timeout, in send order: the
    /// on-path in-flight packets loss detection declared lost, not those in dropped datagrams.
    pub fn lost_samples(&self) -> &[LostSample] {
        &self.lost_samples
    }

    /// Returns the RTT estimator.
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Starts over for a new current path (RFC 9000): the RTT estimator restarts from the initial
    /// RTT, and Application Data packets sent before no longer give samples, leave
    /// [`LossRecovery::bytes_in_flight`] and do not feed the congestion controller acknowledged
    /// bytes, congestion events or persistent congestion, though loss detection still tracks them.
    /// Packets sent later to the alternate path's address carry [`SentFlags::OFF_PATH`], which
    /// keeps them out the same way.
    pub fn reset_for_new_path(&mut self) {
        self.rtt = RttEstimator::new(self.config.initial_rtt);
        self.spaces[Space::Data.index()].start_path();
        // C.delivered and C.total_sent count over the connection's life, as mvfst's
        // totalBytesAcked and totalBytesSent do; the newest send time is the connection's too.
        let d = &self.delivery;
        self.delivery = Delivery {
            delivered: d.delivered,
            total_sent: d.total_sent,
            last_send: d.last_send,
            ..Delivery::new(d.epoch)
        };
    }

    /// Returns the sent packets of `space`.
    pub fn space(&self, space: Space) -> &SentPackets {
        &self.spaces[space.index()]
    }

    /// Notes that the handshake is confirmed (RFC 9001): ACK delays are clamped to the
    /// peer's max_ack_delay from now on and the Application Data PTO may be armed.
    pub fn set_handshake_confirmed(&mut self) {
        self.handshake_confirmed = true;
    }

    /// Notes that Handshake keys are available: a client's anti-deadlock probe is then a
    /// Handshake packet rather than an Initial one (RFC 9002).
    pub fn set_handshake_keys(&mut self) {
        self.handshake_keys = true;
    }

    /// Sets the peer's max_ack_delay transport parameter.
    pub fn set_peer_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.peer_max_ack_delay = max_ack_delay;
    }

    /// Drops `space` when its keys are discarded (RFC 9002) and returns the bytes that leave
    /// flight, which are not a congestion signal. The PTO backoff resets.
    pub fn discard_space(&mut self, space: Space, now: Instant) -> u64 {
        self.loss_confirmed |= self.spaces[space.index()].declared_lost() > 0;
        self.probes_due[space.index()] = 0;
        self.pto_count = 0;
        self.timer_base = now;
        self.spaces[space.index()].discard()
    }

    /// Forgets the packets of `space` without declaring them lost or signalling congestion, and
    /// returns the bytes that leave flight: a client's 0-RTT packets that the server rejected
    /// (RFC 9001). Packet numbers go on.
    pub fn forget_space(&mut self, space: Space) -> u64 {
        self.probes_due[space.index()] = 0;
        self.spaces[space.index()].discard()
    }

    /// Declares lost, in every space, the outstanding packets carried by datagrams `tx`, which
    /// the backend reports did not leave. Not a congestion signal.
    pub fn on_tx_dropped(
        &mut self,
        tx: TxSeqRange,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> LossSummary {
        let mut summary = LossSummary::default();
        for sent in &mut self.spaces {
            summary.merge(sent.on_tx_dropped(tx, &mut on_event));
        }
        summary
    }

    /// Returns the bytes in flight across the spaces, as the current path's congestion controller
    /// counts them: without the Data packets sent before the last new path or to the alternate
    /// path's address.
    pub fn bytes_in_flight(&self) -> u64 {
        self.spaces
            .iter()
            .map(SentPackets::path_bytes_in_flight)
            .sum()
    }

    /// Records a frame written into the packet being built in `space`.
    pub fn push_frame(&mut self, space: Space, frame: SentFrame) {
        self.spaces[space.index()].push_frame(frame);
    }

    /// Forgets the frames of a packet in `space` that was not sealed.
    pub fn abandon_frames(&mut self, space: Space) {
        self.spaces[space.index()].abandon_frames();
    }

    /// Records a sealed packet in `space`; an ack-eliciting one counts as one of the space's due
    /// probes. Fails with [`SentError`] as [`SentPackets::on_sent`] does, leaving the state
    /// unchanged.
    pub fn on_packet_sent(
        &mut self,
        space: Space,
        pn: u64,
        now: Instant,
        size: u16,
        flags: SentFlags,
        tx_seq: u64,
    ) -> Result<(), SentError> {
        self.spaces[space.index()].on_sent(pn, now, size, flags, tx_seq)?;
        if self.config.rate_samples {
            self.snapshot_send(space, now, size, flags);
        }
        if flags.contains(SentFlags::ACK_ELICITING) {
            let due = &mut self.probes_due[space.index()];
            *due = due.saturating_sub(1);
        }
        if flags.contains(SentFlags::IN_FLIGHT) {
            self.timer_base = now;
        }
        self.prune(space, now);
        Ok(())
    }

    /// Updates the delivery state for a packet of `size` bytes with `flags` just recorded in
    /// `space` at `now`, and records the send snapshot of an on-path in-flight one. Off-path
    /// packets do not feed any of it, since RFC 9000 keeps one path's packets out of another's
    /// congestion control. Every on-path packet counts toward C.total_sent, as toward mvfst's
    /// totalBytesSent; only in-flight ones take part in the samples, as only they are in mvfst's
    /// outstanding packets. Out of line, off the send path of connections without rate samples.
    #[inline(never)]
    fn snapshot_send(&mut self, space: Space, now: Instant, size: u16, flags: SentFlags) {
        if flags.contains(SentFlags::OFF_PATH) {
            return;
        }
        self.delivery.total_sent += u64::from(size);
        if !flags.contains(SentFlags::IN_FLIGHT) {
            return;
        }
        let tx_in_flight = self.bytes_in_flight();
        let d = &mut self.delivery;
        // A packet sent into an empty pipe restarts the interval, as in the BBR draft.
        if tx_in_flight == u64::from(size) {
            d.restart = Some(now);
        }
        d.last_send = Some(now);
        let (first_send_time, delivered_time, from_send) = d.interval_start();
        let snapshot = SendSnapshot {
            delivered: d.delivered,
            first_send_time,
            delivered_time,
            from_send,
            app_limited: d.app_limited,
            tx_in_flight,
            lost: d.lost,
            total_sent: d.total_sent,
        };
        let sent = &mut self.spaces[space.index()];
        sent.set_last_snapshot(snapshot);
        // One ACK frame or loss timeout may declare every packet of the space lost; growing the
        // buffer here keeps the ACK pass free of allocation.
        let records = sent.tracked();
        self.lost_samples
            .reserve(records.saturating_sub(self.lost_samples.len()));
    }

    /// Processes one ACK frame received in `space` (RFC 9002): newly acknowledged packets, the
    /// RTT sample, then loss detection in that space if the frame newly acknowledged a packet or
    /// raised the largest acknowledged. `ack_delay` is the decoded ACK Delay field. Every packet
    /// event goes to `on_event`. Fails with [`AckError`] when the frame acknowledges a packet
    /// number that was not sent or was skipped on purpose.
    pub fn on_ack_received<I>(
        &mut self,
        space: Space,
        ranges: I,
        ack_delay: Duration,
        now: Instant,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> Result<AckOutcome, AckError>
    where
        I: IntoIterator<Item = RangeInclusive<u64>>,
    {
        self.lost_samples.clear();
        let largest_before = self.spaces[space.index()].largest_acked();
        let mut acked = AckedSnapshots::default();
        let ack = self.spaces[space.index()].on_ack(ranges, now, |event| {
            if let PacketEvent::Acked(p) = &event
                && let Some(snapshot) = p.snapshot
                && p.on_path
            {
                acked.note(p, snapshot);
            }
            on_event(event);
        })?;
        let AckedSnapshots { newest, largest } = acked;
        let mut outcome = AckOutcome {
            ack,
            ..AckOutcome::default()
        };
        if self.config.rate_samples {
            self.delivery.delivered += ack.acked_bytes;
        }
        if let Some(latest) = ack.rtt_sample {
            // Initial acknowledgments are not delayed, so their ACK Delay is ignored, as RFC 9002
            // allows; the peer's max_ack_delay applies only once the handshake is confirmed.
            let ack_delay = if space == Space::Initial {
                Duration::ZERO
            } else {
                ack_delay
            };
            let max_ack_delay = self.handshake_confirmed.then_some(self.peer_max_ack_delay);
            self.rtt.update(now, latest, ack_delay, max_ack_delay);
            outcome.rtt_updated = true;
        }
        // Without a new acknowledgment the RTT and the outstanding packets did not change, so the
        // loss time still holds, unless an acknowledgment of a dropped packet raised the largest
        // acknowledged.
        if ack.newly_acked > 0 || self.spaces[space.index()].largest_acked() != largest_before {
            outcome.loss = self.detect_lost(space, now, on_event);
        }
        if self.config.rate_samples {
            let adjusted = adjusted_ack_time(now, ack_delay);
            outcome.largest_in_flight_sent = largest.map(|(_, sent)| sent);
            let d = &mut self.delivery;
            if let Some(sent) = outcome.largest_in_flight_sent
                && d.app_limited_mark.is_none_or(|mark| mark <= sent)
            {
                d.app_limited = false;
            }
            outcome.rate = newest
                .map(|(sent, _, snapshot)| self.delivery.sample(sent, &snapshot, now, adjusted));
            if let Some(sent) = outcome.largest_in_flight_sent {
                self.delivery.last_ack = Some((sent, adjusted));
            }
        }
        if space == Space::Handshake {
            self.handshake_acked = true;
        }
        // As RFC 9002 requires, a client keeps the backoff until an acknowledgment of a Handshake
        // packet or handshake confirmation shows that the server validated its address.
        if ack.newly_acked > 0 {
            if self.peer_completed_address_validation() {
                self.pto_count = 0;
            }
            self.timer_base = now;
        }
        self.prune(space, now);
        // RFC 9438 allows the undo only once the losses are known to be spurious: every packet
        // declared lost has been acknowledged, not merely one of them.
        if ack.spurious > 0 && self.declared_lost() == 0 && !self.loss_confirmed {
            outcome.spurious_congestion = self.episode_start;
        }
        Ok(outcome)
    }

    /// Counts the in-flight packets declared lost, in every space, that may still be acknowledged
    /// late.
    pub fn declared_lost(&self) -> u32 {
        self.spaces.iter().map(SentPackets::declared_lost).sum()
    }

    /// Returns when the loss detection timer fires and why (RFC 9002), or `None` when it is not
    /// armed. `amplification_blocked` is whether a server is at its anti-amplification limit.
    pub fn loss_detection_timer(
        &self,
        amplification_blocked: bool,
    ) -> Option<(Instant, LossTimer)> {
        let mut earliest: Option<(Instant, LossTimer)> = None;
        for space in Space::ALL {
            if let Some(at) = self.spaces[space.index()].loss_time()
                && earliest.is_none_or(|(t, _)| at < t)
            {
                earliest = Some((at, LossTimer::LossTime(space)));
            }
        }
        if earliest.is_some() || amplification_blocked {
            return earliest;
        }
        let in_flight = |space: Space| self.spaces[space.index()].ack_eliciting_in_flight() > 0;
        if !Space::ALL.into_iter().any(in_flight) {
            if self.peer_completed_address_validation() {
                return None;
            }
            // As RFC 9002 requires, the client probes to unblock a server that may be at its
            // anti-amplification limit.
            let space = if self.handshake_keys {
                Space::Handshake
            } else {
                Space::Initial
            };
            return Some((
                self.timer_base + self.pto_period(space),
                LossTimer::Pto(space),
            ));
        }
        for space in Space::ALL {
            let Some(last) = self.spaces[space.index()].last_ack_eliciting_time() else {
                continue;
            };
            if !in_flight(space) {
                continue;
            }
            if space == Space::Data && !self.handshake_confirmed {
                break;
            }
            let at = last + self.pto_period(space);
            if earliest.is_none_or(|(t, _)| at < t) {
                earliest = Some((at, LossTimer::Pto(space)));
            }
        }
        earliest
    }

    /// Returns the probe timeout period of `space` (RFC 9002).
    pub fn pto_period(&self, space: Space) -> Duration {
        let mut period = self.rtt.pto_base(self.config.granularity);
        if space == Space::Data {
            period += self.peer_max_ack_delay;
        }
        period.saturating_mul(1 << self.pto_count.min(Self::MAX_BACKOFF_SHIFT))
    }

    /// Handles the loss detection timer at `now` (RFC 9002); a call before the timer expires
    /// leaves the state unchanged. Packets declared lost go to `on_event`.
    pub fn on_timeout(
        &mut self,
        now: Instant,
        amplification_blocked: bool,
        on_event: impl FnMut(PacketEvent<'_>),
    ) -> TimeoutOutcome {
        let Some((at, timer)) = self.loss_detection_timer(amplification_blocked) else {
            return TimeoutOutcome::None;
        };
        if at > now {
            return TimeoutOutcome::None;
        }
        self.lost_samples.clear();
        // RFC 9002's pseudocode rearms the timer either way, which restarts the anti-deadlock PTO.
        self.timer_base = now;
        match timer {
            LossTimer::LossTime(space) => {
                TimeoutOutcome::Lost(space, self.detect_lost(space, now, on_event))
            }
            LossTimer::Pto(space) => {
                // Probe the expired space and, as RFC 9002 recommends, the other spaces with data
                // in flight too, since the peer may hold keys for only one of them.
                for other in Space::ALL {
                    if self.spaces[other.index()].ack_eliciting_in_flight() > 0 {
                        let due = &mut self.probes_due[other.index()];
                        *due = (*due).max(1);
                    }
                }
                self.probes_due[space.index()] = self.config.pto_probes;
                self.pto_count += 1;
                TimeoutOutcome::Probe(space)
            }
        }
    }

    /// Returns the number of PTO expirations since an acknowledgment or a discarded space last
    /// reset the backoff.
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Returns the number of ack-eliciting probe packets due in `space`; each ack-eliciting packet
    /// sealed in the space counts as one.
    pub fn probes_due(&self, space: Space) -> u8 {
        self.probes_due[space.index()]
    }

    /// Forgets the records of `space` too old to matter: an acknowledgment of a lost packet sent
    /// more than a loss delay and a PTO period ago is no longer expected. A loss declared after
    /// that, as one found after a PTO usually is, is forgotten at once and counts as real: the
    /// ACK that declared it lost would have covered the packet had it reached the peer in time.
    fn prune(&mut self, space: Space, now: Instant) {
        if self.spaces[space.index()].front_in_flight() {
            return;
        }
        #[cfg(test)]
        {
            self.keep_computed += 1;
        }
        let keep = self.loss_delay()
            + self.rtt.pto_base(self.config.granularity)
            + self.peer_max_ack_delay;
        if let Some(forget_before) = now.checked_sub(keep) {
            self.loss_confirmed |= self.spaces[space.index()].prune(forget_before) > 0;
        }
    }

    /// Returns whether the peer has validated this endpoint's address (RFC 9002).
    fn peer_completed_address_validation(&self) -> bool {
        self.side == Side::Server || self.handshake_acked || self.handshake_confirmed
    }

    /// Runs loss detection in `space`; persistent congestion also resets min_rtt (RFC 9002).
    /// Each loss with a send snapshot adds a [`LostSample`] and grows C.lost.
    fn detect_lost(
        &mut self,
        space: Space,
        now: Instant,
        mut on_event: impl FnMut(PacketEvent<'_>),
    ) -> LossSummary {
        let params = self.loss_params();
        let Self {
            spaces,
            delivery,
            lost_samples,
            ..
        } = self;
        let loss = spaces[space.index()].detect_lost(now, &params, |event| {
            if let PacketEvent::Lost(p) = &event
                && let Some(snapshot) = p.snapshot
                && p.on_path
            {
                delivery.lost += u64::from(p.size);
                lost_samples.push(LostSample {
                    size: p.size,
                    pn: p.pn,
                    space,
                    tx_in_flight: snapshot.tx_in_flight,
                    is_app_limited: snapshot.app_limited,
                });
            }
            on_event(event);
        });
        // As in RFC 9002, the controller ignores a loss of a packet sent before its recovery
        // period began and keeps that period's reduction, so the loss stays in the episode; only
        // a later packet's loss starts a new reduction and a new episode.
        if let Some(sent) = loss.largest_lost_sent
            && self.episode_start.is_none_or(|start| sent > start)
        {
            self.episode_start = Some(now);
            self.loss_confirmed = false;
        }
        if loss.persistent_congestion {
            self.rtt.on_persistent_congestion();
        }
        loss
    }

    /// Returns the time threshold for loss: max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
    /// kGranularity) (RFC 9002).
    fn loss_delay(&self) -> Duration {
        let (num, den) = self.config.time_threshold;
        let rtt = self.rtt.smoothed().max(self.rtt.latest());
        (rtt * num / den).max(self.config.granularity)
    }

    fn loss_params(&self) -> LossParams {
        // The persistent congestion duration includes max_ack_delay whatever the space (RFC 9002).
        let pto = self.rtt.pto_base(self.config.granularity) + self.peer_max_ack_delay;
        LossParams {
            loss_delay: self.loss_delay(),
            packet_threshold: u64::from(self.config.packet_threshold),
            first_rtt_sample: self.rtt.first_sample_time(),
            persistent_congestion: pto * self.config.persistent_congestion_threshold,
        }
    }
}

#[cfg(test)]
mod rate_tests;

#[cfg(test)]
#[expect(
    clippy::single_range_in_vec_init,
    reason = "a one-element array of ranges is an ACK frame with one range"
)]
mod tests {
    use super::*;
    use crate::cc::AckEvent;
    use crate::cc::Cc;
    use crate::cc::CcConfig;
    use crate::cc::CongestionSignal;
    use crate::cc::SentEvent;
    use crate::config::CongestionControl;

    const MS: Duration = Duration::from_millis(1);
    const ELICITING: SentFlags = SentFlags::ACK_ELICITING.union(SentFlags::IN_FLIGHT);

    fn recovery(side: Side, t0: Instant) -> LossRecovery {
        LossRecovery::new(RecoveryConfig::default(), side, t0, [0, 0, 0]).unwrap()
    }

    /// Sends `count` ack-eliciting 1,200-byte packets in `space` at `at`.
    fn send(r: &mut LossRecovery, space: Space, count: u64, at: Instant) {
        for _ in 0..count {
            let pn = r.space(space).next_pn();
            r.on_packet_sent(space, pn, at, 1200, ELICITING, pn)
                .unwrap();
        }
    }

    fn ack(
        r: &mut LossRecovery,
        space: Space,
        ranges: &[RangeInclusive<u64>],
        ack_delay: Duration,
        now: Instant,
    ) -> AckOutcome {
        r.on_ack_received(space, ranges.iter().cloned(), ack_delay, now, |_| {})
            .unwrap()
    }

    #[test]
    fn settings_that_cannot_work_are_refused() {
        let t0 = crate::recovery::test_epoch();
        let ok = RecoveryConfig::default();
        let refused = |config| LossRecovery::new(config, Side::Server, t0, [0, 0, 0]).unwrap_err();
        let out_of_range = |field| ConfigError::OutOfRange { field };
        let zero_rtt = RecoveryConfig {
            initial_rtt: Duration::ZERO,
            ..ok
        };
        assert_eq!(refused(zero_rtt), out_of_range("initial_rtt"));
        // RFC 9002 advises against a packet threshold below 3.
        let reorder = RecoveryConfig {
            packet_threshold: 2,
            ..ok
        };
        assert_eq!(refused(reorder), out_of_range("packet_threshold"));
        for time_threshold in [(9, 0), (0, 8)] {
            let time = RecoveryConfig {
                time_threshold,
                ..ok
            };
            assert_eq!(refused(time), out_of_range("time_threshold"));
        }
        let persistent = RecoveryConfig {
            persistent_congestion_threshold: 0,
            ..ok
        };
        assert_eq!(
            refused(persistent),
            out_of_range("persistent_congestion_threshold")
        );
        for pto_probes in [0, 3] {
            let probes = RecoveryConfig { pto_probes, ..ok };
            assert_eq!(refused(probes), out_of_range("pto_probes"));
        }
    }

    #[test]
    fn a_zero_granularity_is_refused() {
        // With a zero RTT sample, as over a zero-delay link, the PTO period would be zero, which
        // backoff cannot grow.
        let t0 = crate::recovery::test_epoch();
        let config = RecoveryConfig {
            granularity: Duration::ZERO,
            ..RecoveryConfig::default()
        };
        assert_eq!(
            LossRecovery::new(config, Side::Server, t0, [0, 0, 0]).unwrap_err(),
            ConfigError::OutOfRange {
                field: "granularity"
            }
        );
    }

    #[test]
    fn timer_settings_above_an_hour_are_refused() {
        let t0 = crate::recovery::test_epoch();
        let ok = RecoveryConfig::default();
        let new = |config| LossRecovery::new(config, Side::Server, t0, [0, 0, 0]);
        let hour = Duration::from_secs(3600);
        for (initial_rtt, granularity) in [(hour, ok.granularity), (ok.initial_rtt, hour)] {
            assert!(
                new(RecoveryConfig {
                    initial_rtt,
                    granularity,
                    ..ok
                })
                .is_ok()
            );
        }
        // Duration::MAX would overflow the loss delay on the first packet sent.
        for initial_rtt in [hour + Duration::from_nanos(1), Duration::MAX] {
            let config = RecoveryConfig { initial_rtt, ..ok };
            assert_eq!(
                new(config).unwrap_err(),
                ConfigError::OutOfRange {
                    field: "initial_rtt"
                }
            );
        }
        for granularity in [hour + Duration::from_nanos(1), Duration::MAX] {
            let config = RecoveryConfig { granularity, ..ok };
            assert_eq!(
                new(config).unwrap_err(),
                ConfigError::OutOfRange {
                    field: "granularity"
                }
            );
        }
    }

    #[test]
    fn the_largest_timer_settings_accepted_do_not_overflow() {
        let t0 = crate::recovery::test_epoch();
        let hour = RecoveryConfig::MAX_TIMER_SETTING;
        let config = RecoveryConfig {
            initial_rtt: hour,
            granularity: hour,
            ..RecoveryConfig::default()
        };
        let mut r = LossRecovery::new(config, Side::Client, t0, [0, 0, 0]).unwrap();
        r.set_handshake_confirmed();
        // The largest valid max_ack_delay, 2^14 - 1 ms (RFC 9000).
        r.set_peer_max_ack_delay(Duration::from_millis(16_383));
        send(&mut r, Space::Data, 1, t0);
        let mut now = t0;
        for _ in 0..3 {
            now = r.loss_detection_timer(false).unwrap().0;
            assert_eq!(
                r.on_timeout(now, false, |_| {}),
                TimeoutOutcome::Probe(Space::Data)
            );
            send(&mut r, Space::Data, 1, now);
        }
        // The last probe is acknowledged an hour later: an RTT sample, loss detection of the
        // three earlier packets, and pruning.
        let outcome = ack(&mut r, Space::Data, &[3..=3], Duration::ZERO, now + hour);
        assert!(outcome.rtt_updated);
        assert_eq!(outcome.loss.lost_packets, 3);
        // The PTO at the largest backoff: (1 h + max(4 * 30 min, 1 h) + 16.383 s) * 2^30.
        send(&mut r, Space::Data, 1, now + hour);
        r.pto_count = u32::MAX;
        let period = Duration::from_millis(10_816_383) * (1 << 30);
        assert_eq!(r.pto_period(Space::Data), period);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((now + hour + period, LossTimer::Pto(Space::Data)))
        );
    }

    #[test]
    fn acks_update_the_rtt_with_ack_delay_except_in_the_initial_space() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Client, t0);
        send(&mut r, Space::Initial, 1, t0);
        // Initial: the 10 ms ACK delay is ignored, but this is the first sample anyway.
        assert!(ack(&mut r, Space::Initial, &[0..=0], 10 * MS, t0 + 100 * MS).rtt_updated);
        assert_eq!(r.rtt().smoothed(), 100 * MS);
        send(&mut r, Space::Initial, 1, t0 + 100 * MS);
        ack(&mut r, Space::Initial, &[1..=1], 20 * MS, t0 + 220 * MS);
        // adjusted = 120 (delay ignored): smoothed = 87.5 + 15.
        assert_eq!(r.rtt().smoothed(), Duration::from_micros(102_500));
        // Handshake: the delay is used unclamped before confirmation; adjusted = 150 - 40,
        // smoothed = (7 * 102.5 + 110) / 8.
        send(&mut r, Space::Handshake, 1, t0 + 300 * MS);
        ack(&mut r, Space::Handshake, &[0..=0], 40 * MS, t0 + 450 * MS);
        assert_eq!(r.rtt().smoothed(), Duration::from_nanos(103_437_500));
        // Application Data after confirmation: clamped to max_ack_delay 25 ms; adjusted = 125,
        // smoothed = (7 * 103.4375 + 125) / 8, truncated to whole nanoseconds.
        r.set_handshake_confirmed();
        send(&mut r, Space::Data, 1, t0 + 500 * MS);
        ack(&mut r, Space::Data, &[0..=0], 40 * MS, t0 + 650 * MS);
        assert_eq!(r.rtt().smoothed(), Duration::from_nanos(106_132_812));
        // An ACK of the same range does not newly acknowledge a packet, so the RTT is not updated.
        assert!(!ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 700 * MS).rtt_updated);
    }

    fn send_one(r: &mut LossRecovery, space: Space, at: Instant) -> u64 {
        let pn = r.space(space).next_pn();
        r.on_packet_sent(space, pn, at, 1200, ELICITING, pn)
            .unwrap();
        pn
    }

    #[test]
    fn acks_run_loss_detection_with_the_updated_rtt() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Data, t0);
        ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
        send_one(&mut r, Space::Data, t0 + 100 * MS);
        send_one(&mut r, Space::Data, t0 + 190 * MS);
        send_one(&mut r, Space::Data, t0 + 200 * MS);
        // latest = smoothed = 100 ms, so the loss delay is 112.5 ms: packet 1 (sent at 100) is
        // lost at 300, packet 2 (sent at 190) waits until 302.5.
        let outcome = ack(&mut r, Space::Data, &[3..=3], Duration::ZERO, t0 + 300 * MS);
        assert_eq!(outcome.loss.lost_packets, 1);
        assert_eq!(outcome.loss.lost_bytes, 1200);
        assert_eq!(
            r.space(Space::Data).loss_time(),
            Some(t0 + Duration::from_micros(302_500))
        );
    }

    #[test]
    fn only_acknowledging_every_pending_loss_proves_the_congestion_spurious() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send(&mut r, Space::Data, 30, t0);
        ack(&mut r, Space::Data, &[0..=9], Duration::ZERO, t0 + 100 * MS);
        // The network dropped 10-15 and reordered 16: 10-16 are declared lost.
        let outcome = ack(
            &mut r,
            Space::Data,
            &[17..=29, 0..=9],
            Duration::ZERO,
            t0 + 110 * MS,
        );
        assert_eq!(outcome.loss.lost_packets, 7);
        // The late acknowledgment of 16 does not make the other six losses spurious.
        let outcome = ack(
            &mut r,
            Space::Data,
            &[16..=29, 0..=9],
            Duration::ZERO,
            t0 + 120 * MS,
        );
        assert_eq!(outcome.ack.spurious, 1);
        assert_eq!(outcome.spurious_congestion, None);
        // Once all seven are acknowledged, all seven losses prove spurious.
        let outcome = ack(
            &mut r,
            Space::Data,
            &[0..=29],
            Duration::ZERO,
            t0 + 130 * MS,
        );
        assert_eq!(outcome.ack.spurious, 6);
        // The episode, and the controller's recovery period, began with the losses at 110 ms.
        assert_eq!(outcome.spurious_congestion, Some(t0 + 110 * MS));
    }

    #[test]
    fn a_loss_forgotten_unacknowledged_keeps_its_episode_from_proving_spurious() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Data, t0);
        ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
        send_one(&mut r, Space::Data, t0 + 100 * MS);
        send(&mut r, Space::Data, 4, t0 + 600 * MS);
        // 1 and 2 are lost. Records sent before 312.5 ms (now - loss delay 112.5 ms - PTO
        // 250 ms - max_ack_delay 25 ms) are forgotten, so 1 goes unacknowledged: a real loss.
        let outcome = ack(&mut r, Space::Data, &[5..=5], Duration::ZERO, t0 + 700 * MS);
        assert_eq!(outcome.loss.lost_packets, 2);
        assert!(r.space(Space::Data).get(1).is_none());
        let outcome = ack(&mut r, Space::Data, &[2..=5], Duration::ZERO, t0 + 710 * MS);
        assert_eq!(outcome.ack.spurious, 1);
        assert_eq!(outcome.spurious_congestion, None);
        // A loss of a packet sent after that episode began starts a new one, which may prove
        // spurious.
        send(&mut r, Space::Data, 4, t0 + 800 * MS);
        let outcome = ack(&mut r, Space::Data, &[9..=9], Duration::ZERO, t0 + 900 * MS);
        assert_eq!(outcome.loss.lost_packets, 1);
        let outcome = ack(&mut r, Space::Data, &[6..=9], Duration::ZERO, t0 + 910 * MS);
        assert_eq!(outcome.ack.spurious, 1);
        assert_eq!(outcome.spurious_congestion, Some(t0 + 900 * MS));

        // Losses dropped with their space are not known to be spurious either.
        let mut r = recovery(Side::Server, t0);
        send(&mut r, Space::Initial, 5, t0);
        send(&mut r, Space::Data, 5, t0);
        ack(
            &mut r,
            Space::Initial,
            &[4..=4],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        ack(&mut r, Space::Data, &[4..=4], Duration::ZERO, t0 + 100 * MS);
        r.discard_space(Space::Initial, t0 + 105 * MS);
        let outcome = ack(&mut r, Space::Data, &[0..=4], Duration::ZERO, t0 + 110 * MS);
        assert_eq!(outcome.ack.spurious, 2);
        assert_eq!(outcome.spurious_congestion, None);
    }

    /// Feeds one ACK frame's outcome to `cc` as the connection does. The ACKs of these tests do not
    /// acknowledge packets on both sides of a recovery period's start, so `acked_in_recovery` is 0.
    fn feed(cc: &mut Cc, r: &LossRecovery, outcome: &AckOutcome, now: Instant) {
        if let Some(sent) = outcome.loss.largest_lost_sent {
            cc.on_congestion_event(now, sent, CongestionSignal::Loss);
        }
        if outcome.loss.persistent_congestion {
            cc.on_persistent_congestion();
        }
        if let Some((_, sent)) = outcome.ack.largest_newly_acked {
            cc.on_ack(&AckEvent {
                now,
                acked_bytes: outcome.ack.acked_bytes,
                acked_in_recovery: 0,
                largest_acked_sent: sent,
                rtt: r.rtt().smoothed(),
                rtt_sample: outcome.ack.rtt_sample,
                app_limited: false,
            });
        }
        if let Some(start) = outcome.spurious_congestion {
            cc.on_spurious_loss(start);
        }
    }

    /// Sends a Data packet at `at`, reporting the send to `cc` first.
    fn send_at(r: &mut LossRecovery, cc: &mut Cc, at: Instant) {
        cc.on_sent(&SentEvent {
            time_sent: at,
            bytes_in_flight: r.bytes_in_flight(),
            size: 1200,
            total_sent: 0,
            on_path: true,
        });
        send_one(r, Space::Data, at);
    }

    /// Processes a Data ACK frame at `now` and feeds its outcome to `cc`.
    fn ack_fed(
        r: &mut LossRecovery,
        cc: &mut Cc,
        ranges: &[RangeInclusive<u64>],
        now: Instant,
    ) -> AckOutcome {
        let outcome = ack(r, Space::Data, ranges, Duration::ZERO, now);
        feed(cc, r, &outcome, now);
        outcome
    }

    #[test]
    fn a_reordered_loss_in_the_recovery_period_of_a_real_loss_does_not_undo_it() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        r.set_handshake_confirmed();
        let mut cc = Cc::new(CongestionControl::Cubic, &CcConfig::default(), 1200).unwrap();
        send_at(&mut r, &mut cc, t0);
        ack_fed(&mut r, &mut cc, &[0..=0], t0 + 100 * MS);
        assert_eq!(cc.cwnd(), 13_200);
        // The tail packet 1 is really lost. Its PTO, 100 + 4 * 50 + 25 ms after it, sends probes
        // 2 and 3, then new data 4 and 5-7.
        send_at(&mut r, &mut cc, t0 + 101 * MS);
        let pto = t0 + 426 * MS;
        assert_eq!(timeout(&mut r, pto), TimeoutOutcome::Probe(Space::Data));
        for at in [
            pto,
            pto,
            t0 + 430 * MS,
            t0 + 440 * MS,
            t0 + 440 * MS,
            t0 + 440 * MS,
        ] {
            send_at(&mut r, &mut cc, at);
        }
        // Packet 1 is lost by time and reduces the window. Its record is forgotten at once: it
        // was sent more than loss delay + PTO + max_ack_delay (387.5 ms) ago, so its loss is
        // real.
        let outcome = ack_fed(&mut r, &mut cc, &[2..=3], t0 + 526 * MS);
        assert_eq!(outcome.loss.lost_packets, 1);
        assert!(r.space(Space::Data).get(1).is_none());
        assert_eq!(cc.cwnd(), 9240);
        // Packet 4, sent before that reduction, is reordered and declared lost: the controller
        // counts it in the same recovery period.
        let outcome = ack_fed(&mut r, &mut cc, &[5..=7, 2..=3], t0 + 540 * MS);
        assert_eq!(outcome.loss.lost_packets, 1);
        assert_eq!(cc.cwnd(), 9240);
        // Its late acknowledgment does not make packet 1's loss spurious.
        let outcome = ack_fed(&mut r, &mut cc, &[2..=7], t0 + 545 * MS);
        assert_eq!(outcome.ack.spurious, 1);
        assert_eq!(outcome.spurious_congestion, None);
        assert_eq!(cc.cwnd(), 9240);
    }

    #[test]
    fn a_spurious_episode_after_a_real_loss_undoes_only_its_own_reduction() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        r.set_handshake_confirmed();
        let mut cc = Cc::new(CongestionControl::Cubic, &CcConfig::default(), 1200).unwrap();
        send_at(&mut r, &mut cc, t0);
        ack_fed(&mut r, &mut cc, &[0..=0], t0 + 100 * MS);
        for _ in 1..=4 {
            send_at(&mut r, &mut cc, t0 + 100 * MS);
        }
        // Packet 1 is lost: 13,200 * 0.7.
        ack_fed(&mut r, &mut cc, &[2..=4, 0..=0], t0 + 200 * MS);
        assert_eq!(cc.cwnd(), 9240);
        // Sending at 600 ms forgets it unacknowledged (sent more than 387.5 ms ago): a real loss.
        for _ in 5..=8 {
            send_at(&mut r, &mut cc, t0 + 600 * MS);
        }
        assert!(r.space(Space::Data).get(1).is_none());
        // Packet 5, sent after that reduction, is lost and reduces the window again.
        ack_fed(&mut r, &mut cc, &[6..=8, 0..=4], t0 + 700 * MS);
        assert_eq!(cc.cwnd(), 6468);
        // Its late acknowledgment undoes the second reduction, not the first.
        let outcome = ack_fed(&mut r, &mut cc, &[0..=8], t0 + 710 * MS);
        assert_eq!(outcome.spurious_congestion, Some(t0 + 700 * MS));
        assert_eq!(cc.cwnd(), 9240);
    }

    #[test]
    fn an_ack_of_nothing_new_leaves_loss_detection_to_the_timer() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Data, t0);
        send_one(&mut r, Space::Data, t0 + 10 * MS);
        // The 90 ms sample makes the loss delay 101.25 ms: packet 0 waits for the loss timer.
        ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 100 * MS);
        let loss_time = t0 + Duration::from_micros(101_250);
        // As in RFC 9002's pseudocode, an ACK frame that does not newly acknowledge a packet
        // does not run loss detection, even after the loss time.
        let outcome = ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 200 * MS);
        assert_eq!(outcome.loss.lost_packets, 0);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((loss_time, LossTimer::LossTime(Space::Data)))
        );
    }

    #[test]
    fn persistent_congestion_resets_min_rtt() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Data, t0);
        ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
        assert_eq!(r.rtt().min(), 100 * MS);
        send_one(&mut r, Space::Data, t0 + 200 * MS);
        send_one(&mut r, Space::Data, t0 + 1500 * MS);
        send_one(&mut r, Space::Data, t0 + 1600 * MS);
        // The 200 ms sample makes smoothed 112.5 ms and rttvar 62.5 ms, so the persistent
        // congestion duration is (112.5 + 250 + 25) * 3 = 1162.5 ms; packets 1 and 2 are lost by
        // time (225 ms) and span 1300 ms.
        let outcome = ack(
            &mut r,
            Space::Data,
            &[3..=3],
            Duration::ZERO,
            t0 + 1800 * MS,
        );
        assert_eq!(outcome.loss.lost_packets, 2);
        assert!(outcome.loss.persistent_congestion);
        assert_eq!(r.rtt().min(), 200 * MS);
    }

    #[test]
    fn resetting_the_rtt_forgets_every_sample() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Data, t0);
        ack(&mut r, Space::Data, &[0..=0], Duration::ZERO, t0 + 100 * MS);
        assert_eq!(r.rtt().smoothed(), 100 * MS);
        r.reset_for_new_path();
        let initial = RecoveryConfig::default().initial_rtt;
        assert_eq!(r.rtt().smoothed(), initial);
        assert_eq!(r.rtt().var(), initial / 2);
        assert_eq!(r.rtt().min(), Duration::ZERO);
        assert_eq!(r.rtt().first_sample_time(), None);
    }

    #[test]
    fn the_pto_is_the_earliest_space_with_max_ack_delay_only_for_confirmed_data() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        // smoothed 100 ms, rttvar 50 ms: the base PTO period is 300 ms. The only packet sent is
        // acknowledged.
        assert_eq!(r.loss_detection_timer(false), None);
        send_one(&mut r, Space::Data, t0 + 110 * MS);
        // Application Data is not armed before the handshake is confirmed.
        assert_eq!(r.loss_detection_timer(false), None);
        send_one(&mut r, Space::Handshake, t0 + 150 * MS);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 450 * MS, LossTimer::Pto(Space::Handshake)))
        );
        r.set_handshake_confirmed();
        // 110 + 300 + 25 (max_ack_delay) is earlier than 450.
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 435 * MS, LossTimer::Pto(Space::Data)))
        );
    }

    #[test]
    fn a_pending_loss_time_takes_precedence_over_the_pto() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Handshake, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        send_one(&mut r, Space::Data, t0 + 250 * MS);
        send_one(&mut r, Space::Data, t0 + 260 * MS);
        ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 330 * MS);
        // The 70 ms sample: smoothed 96.25 ms, rttvar 45 ms. The Handshake PTO is at 276.25 ms,
        // but Data packet 0 passes the 108.28125 ms time threshold at 358.28125 ms.
        assert_eq!(
            r.loss_detection_timer(false),
            Some((
                t0 + Duration::from_nanos(358_281_250),
                LossTimer::LossTime(Space::Data)
            ))
        );
    }

    #[test]
    fn no_pto_is_armed_at_the_anti_amplification_limit() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Initial, t0);
        assert!(r.loss_detection_timer(false).is_some());
        assert_eq!(r.loss_detection_timer(true), None);
    }

    fn timeout(r: &mut LossRecovery, now: Instant) -> TimeoutOutcome {
        r.on_timeout(now, false, |_| {})
    }

    #[test]
    fn pto_expiry_doubles_the_period_and_owes_probes() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        send_one(&mut r, Space::Handshake, t0 + 100 * MS);
        send_one(&mut r, Space::Initial, t0 + 150 * MS);
        // Base PTO period 300 ms: Handshake at 400, Initial at 450.
        assert_eq!(timeout(&mut r, t0 + 399 * MS), TimeoutOutcome::None);
        assert_eq!(r.pto_count(), 0);
        assert_eq!(
            timeout(&mut r, t0 + 400 * MS),
            TimeoutOutcome::Probe(Space::Handshake)
        );
        assert_eq!(r.pto_count(), 1);
        // Two probes in the expired space, one in the other space with data in flight.
        assert_eq!(r.probes_due(Space::Handshake), 2);
        assert_eq!(r.probes_due(Space::Initial), 1);
        assert_eq!(r.probes_due(Space::Data), 0);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 700 * MS, LossTimer::Pto(Space::Handshake)))
        );
        assert_eq!(
            timeout(&mut r, t0 + 700 * MS),
            TimeoutOutcome::Probe(Space::Handshake)
        );
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 1300 * MS, LossTimer::Pto(Space::Handshake)))
        );
        // max_ack_delay backs off too.
        assert_eq!(r.pto_period(Space::Data), 1300 * MS);
    }

    #[test]
    fn the_loss_timer_declares_packets_lost_by_time() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        send_one(&mut r, Space::Data, t0 + 250 * MS);
        send_one(&mut r, Space::Data, t0 + 260 * MS);
        ack(&mut r, Space::Data, &[1..=1], Duration::ZERO, t0 + 330 * MS);
        // Data packet 0 passes the 108.28125 ms time threshold at 358.28125 ms.
        let at = t0 + Duration::from_nanos(358_281_250);
        let mut lost = Vec::new();
        assert_eq!(
            r.on_timeout(at - Duration::from_nanos(1), false, |_| {}),
            TimeoutOutcome::None
        );
        let outcome = r.on_timeout(at, false, |e| {
            if let PacketEvent::Lost(p) = e {
                lost.push(p.pn);
            }
        });
        let TimeoutOutcome::Lost(Space::Data, summary) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(summary.lost_packets, 1);
        assert_eq!(lost, [0]);
        assert_eq!(r.pto_count(), 0);
        assert_eq!(r.loss_detection_timer(false), None);
    }

    #[test]
    fn the_anti_deadlock_timer_restarts_when_the_loss_timer_fires() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Client, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        send_one(&mut r, Space::Initial, t0 + 200 * MS);
        send_one(&mut r, Space::Initial, t0 + 210 * MS);
        ack(
            &mut r,
            Space::Initial,
            &[2..=2],
            Duration::ZERO,
            t0 + 310 * MS,
        );
        // Packet 1 passes the 112.5 ms time threshold at 312.5 ms, and bytes in flight fall to 0.
        let at = t0 + Duration::from_micros(312_500);
        assert!(matches!(
            timeout(&mut r, at),
            TimeoutOutcome::Lost(Space::Initial, _)
        ));
        // RFC 9002's pseudocode rearms the timer then, so the probe runs a PTO (250 ms) from it.
        assert_eq!(
            r.loss_detection_timer(false),
            Some((at + 250 * MS, LossTimer::Pto(Space::Initial)))
        );
    }

    #[test]
    fn acks_reset_the_backoff_once_the_peer_validated_the_address() {
        let t0 = crate::recovery::test_epoch();
        let second = t0 + Duration::from_millis(999);
        // A server's address is validated by the client from the start.
        let mut server = recovery(Side::Server, t0);
        send_one(&mut server, Space::Initial, t0);
        assert_eq!(
            timeout(&mut server, second),
            TimeoutOutcome::Probe(Space::Initial)
        );
        send_one(&mut server, Space::Initial, second);
        ack(
            &mut server,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            second + 10 * MS,
        );
        assert_eq!(server.pto_count(), 0);

        // A client keeps the backoff until a Handshake packet is acknowledged.
        let mut client = recovery(Side::Client, t0);
        send_one(&mut client, Space::Initial, t0);
        assert_eq!(
            timeout(&mut client, second),
            TimeoutOutcome::Probe(Space::Initial)
        );
        send_one(&mut client, Space::Initial, second);
        ack(
            &mut client,
            Space::Initial,
            &[0..=1],
            Duration::ZERO,
            second + 100 * MS,
        );
        assert_eq!(client.pto_count(), 1);
        send_one(&mut client, Space::Handshake, second + 100 * MS);
        ack(
            &mut client,
            Space::Handshake,
            &[0..=0],
            Duration::ZERO,
            second + 200 * MS,
        );
        assert_eq!(client.pto_count(), 0);
    }

    #[test]
    fn an_ack_of_nothing_new_keeps_the_backoff() {
        let t0 = crate::recovery::test_epoch();
        let second = t0 + Duration::from_millis(999);
        let mut server = recovery(Side::Server, t0);
        send_one(&mut server, Space::Initial, t0);
        send_one(&mut server, Space::Initial, t0);
        ack(
            &mut server,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 10 * MS,
        );
        // Base PTO 30 ms after the 10 ms sample.
        assert_eq!(
            timeout(&mut server, t0 + 30 * MS),
            TimeoutOutcome::Probe(Space::Initial)
        );
        ack(
            &mut server,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            second,
        );
        assert_eq!(server.pto_count(), 1);
    }

    #[test]
    fn a_client_probes_with_nothing_in_flight_until_the_server_validated_it() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Client, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        // The only packet is acknowledged, but the server may be blocked by its amplification
        // limit: the PTO runs from the last timer event, the ACK at 100 ms.
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 400 * MS, LossTimer::Pto(Space::Initial)))
        );
        r.set_handshake_keys();
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 400 * MS, LossTimer::Pto(Space::Handshake)))
        );
        assert_eq!(
            timeout(&mut r, t0 + 400 * MS),
            TimeoutOutcome::Probe(Space::Handshake)
        );
        assert_eq!(r.probes_due(Space::Handshake), 2);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 1000 * MS, LossTimer::Pto(Space::Handshake)))
        );
        r.set_handshake_confirmed();
        assert_eq!(r.loss_detection_timer(false), None);
    }

    #[test]
    fn each_sealed_ack_eliciting_packet_pays_one_probe() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send_one(&mut r, Space::Initial, t0);
        send_one(&mut r, Space::Handshake, t0);
        let pto = t0 + Duration::from_millis(999);
        assert_eq!(timeout(&mut r, pto), TimeoutOutcome::Probe(Space::Initial));
        assert_eq!(
            (r.probes_due(Space::Initial), r.probes_due(Space::Handshake)),
            (2, 1)
        );
        // An ACK-only packet is not a probe.
        r.on_packet_sent(Space::Initial, 1, pto, 50, SentFlags::empty(), 1)
            .unwrap();
        assert_eq!(r.probes_due(Space::Initial), 2);
        send_one(&mut r, Space::Initial, pto);
        assert_eq!(r.probes_due(Space::Initial), 1);
        send_one(&mut r, Space::Initial, pto);
        send_one(&mut r, Space::Initial, pto);
        assert_eq!(r.probes_due(Space::Initial), 0);
        assert_eq!(r.probes_due(Space::Handshake), 1);
        send_one(&mut r, Space::Handshake, pto);
        assert_eq!(r.probes_due(Space::Handshake), 0);
    }

    #[test]
    fn an_in_flight_packet_restarts_the_anti_deadlock_timer() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Client, t0);
        send_one(&mut r, Space::Initial, t0);
        ack(
            &mut r,
            Space::Initial,
            &[0..=0],
            Duration::ZERO,
            t0 + 100 * MS,
        );
        // A PADDING-only datagram counts in flight but is not ack-eliciting.
        r.on_packet_sent(
            Space::Initial,
            1,
            t0 + 200 * MS,
            1200,
            SentFlags::IN_FLIGHT,
            1,
        )
        .unwrap();
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 500 * MS, LossTimer::Pto(Space::Initial)))
        );
    }

    #[test]
    fn discarding_a_space_drops_its_packets_and_resets_the_backoff() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send(&mut r, Space::Initial, 2, t0);
        send_one(&mut r, Space::Handshake, t0 + 10 * MS);
        let pto = t0 + Duration::from_millis(999);
        assert_eq!(timeout(&mut r, pto), TimeoutOutcome::Probe(Space::Initial));
        assert_eq!(r.discard_space(Space::Initial, pto), 2400);
        assert_eq!(r.space(Space::Initial).bytes_in_flight(), 0);
        assert_eq!(r.space(Space::Initial).tracked(), 0);
        assert_eq!(r.pto_count(), 0);
        assert_eq!(r.probes_due(Space::Initial), 0);
        assert_eq!(r.probes_due(Space::Handshake), 1);
        assert_eq!(
            r.loss_detection_timer(false),
            Some((t0 + 1009 * MS, LossTimer::Pto(Space::Handshake)))
        );
    }

    #[test]
    fn dropped_datagrams_lose_their_packets_in_every_space() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        // Datagram 7 coalesces Initial 0 and Handshake 0; datagram 8 carries Handshake 1.
        r.on_packet_sent(Space::Initial, 0, t0, 600, ELICITING, 7)
            .unwrap();
        r.on_packet_sent(Space::Handshake, 0, t0, 600, ELICITING, 7)
            .unwrap();
        r.on_packet_sent(Space::Handshake, 1, t0, 1200, ELICITING, 8)
            .unwrap();
        assert_eq!(r.bytes_in_flight(), 2400);
        let mut lost = Vec::new();
        let summary = r.on_tx_dropped(TxSeqRange { start: 7, end: 8 }, |e| {
            if let PacketEvent::Lost(p) = e {
                lost.push(p.pn);
            }
        });
        assert_eq!(summary.lost_packets, 2);
        assert_eq!(summary.lost_bytes, 1200);
        assert_eq!(lost, [0, 0]);
        assert_eq!(r.bytes_in_flight(), 1200);
    }

    #[test]
    fn acks_forget_old_lost_and_acknowledged_packets() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send(&mut r, Space::Data, 4, t0);
        // Packet 0 is lost by the packet threshold, 1 and 2 stay outstanding.
        assert_eq!(
            ack(&mut r, Space::Data, &[3..=3], Duration::ZERO, t0 + 100 * MS)
                .loss
                .lost_packets,
            1
        );
        assert_eq!(r.space(Space::Data).tracked(), 4);
        // Long after: packet 0 is too old to be acknowledged spuriously any more.
        ack(
            &mut r,
            Space::Data,
            &[1..=3],
            Duration::ZERO,
            t0 + 2000 * MS,
        );
        assert_eq!(r.space(Space::Data).tracked(), 0);
    }

    #[test]
    fn a_receiver_sending_only_acks_keeps_a_bounded_ring() {
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Client, t0);
        for pn in 0..10_000 {
            let at = t0 + Duration::from_millis(pn);
            r.on_packet_sent(Space::Data, pn, at, 50, SentFlags::empty(), pn)
                .unwrap();
        }
        // With the initial RTT, packets are kept for loss_delay + PTO, about 1.4 s.
        assert!(
            r.space(Space::Data).tracked() < 1500,
            "{}",
            r.space(Space::Data).tracked()
        );
    }

    #[test]
    fn sends_behind_an_in_flight_front_skip_the_prune_time_math() {
        // On the send path the oldest record is usually outstanding and in flight, so pruning has
        // nothing to drop and does not compute how long records are kept.
        let t0 = crate::recovery::test_epoch();
        let mut r = recovery(Side::Server, t0);
        send(&mut r, Space::Data, 100, t0);
        assert_eq!(r.keep_computed, 0);
        assert_eq!(r.space(Space::Data).tracked(), 100);
        // After an ACK that leaves the in-flight front unacknowledged, pruning skips that math too.
        ack(&mut r, Space::Data, &[1..=2], Duration::ZERO, t0 + 100 * MS);
        assert_eq!((r.keep_computed, r.space(Space::Data).tracked()), (0, 100));
        // An acknowledged front is pruned at once.
        ack(
            &mut r,
            Space::Data,
            &[0..=99],
            Duration::ZERO,
            t0 + 200 * MS,
        );
        assert_eq!((r.keep_computed, r.space(Space::Data).tracked()), (1, 0));

        // An ACK-only sender's records age out only when it sends, so each of its sends prunes.
        let mut r = recovery(Side::Client, t0);
        for pn in 0..100 {
            let at = t0 + pn as u32 * MS;
            r.on_packet_sent(Space::Data, pn, at, 50, SentFlags::empty(), pn)
                .unwrap();
        }
        assert_eq!(r.keep_computed, 100);
    }
}
