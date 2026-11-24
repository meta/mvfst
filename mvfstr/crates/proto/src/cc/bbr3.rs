/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! BBRv3 with draft-ietf-ccwg-bbr-07's structure, states, gains, filters and function names.
//!
//! Where mvfst's BBR3 behaves differently from -07, mvfstr matches mvfst, not the draft, so that
//! the two controllers behave alike in a benchmark. The comments note each such difference.
//!
//! The controller takes one event per ACK frame or loss timeout, in mvfst's order: the undo of a
//! spurious loss episode first, then the loss response, then the draft's per-ACK steps with an
//! empty sample if the frame did not produce one, or only the control outputs for a loss timeout.
//! cwnd lives in the shared `Window`, so admission and the maximum window work as for NewReno and
//! CUBIC, except that BBR.MinPipeCwnd, four datagrams, wins over a smaller maximum. It is meant to
//! run with pacing on: the initial window goes out unpaced, and later sends are paced at
//! C.pacing_rate.

use std::time::Duration;
use std::time::Instant;

use super::AckOrLoss;
use super::AckPart;
use super::CcStart;
use super::SentEvent;
use super::Window;
use crate::recovery::loss::RateSample;
use crate::recovery::sent::LostSample;

#[cfg(test)]
pub(crate) mod tests;

/// Gains in hundredths; mvfst uses the draft's values.
const STARTUP_PACING_GAIN: u64 = 277;
const DEFAULT_CWND_GAIN: u64 = 200;
const DRAIN_PACING_GAIN: u64 = 50;
const PROBE_BW_DOWN_PACING_GAIN: u64 = 90;
const PROBE_BW_CRUISE_PACING_GAIN: u64 = 100;
const PROBE_BW_REFILL_PACING_GAIN: u64 = 100;
const PROBE_BW_UP_PACING_GAIN: u64 = 125;
const PROBE_BW_UP_CWND_GAIN: u64 = 225;
const PROBE_RTT_PACING_GAIN: u64 = 100;
const PROBE_RTT_CWND_GAIN: u64 = 50;
/// MinRTTFilterLen.
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// BBR.inflight_longterm's headroom in percent.
const HEADROOM: u64 = 15;
/// The probe wait is 2 s plus a uniform whole number of milliseconds below PROBE_WAIT_JITTER_MS.
const MIN_PROBE_WAIT: Duration = Duration::from_secs(2);
const PROBE_WAIT_JITTER_MS: u64 = 1000;
const MAX_PROBE_UP_ROUNDS: u32 = 30;
/// ExtraAckedFilterLen in rounds.
const EXTRA_ACKED_ROUNDS: u64 = 10;
/// BBR.LossThresh in percent, and the loss events a round needs before its loss counts as too high.
const LOSS_THRESH: u64 = 2;
const STARTUP_FULL_LOSS_COUNT: u64 = 6;
const PROBE_BW_FULL_LOSS_COUNT: u64 = 2;
/// BBR.Beta in percent.
const BETA: u64 = 70;
/// The most full rounds Drain lasts.
const MAX_DRAIN_ROUNDS: u64 = 3;
/// BBR.full_bw growth that counts as growth, in percent, and the rounds without it that
/// fill the pipe.
const FULL_BW_GROWTH: u64 = 125;
const FULL_BW_ROUNDS: u64 = 3;
/// BBR.MinPipeCwnd in datagrams.
const MIN_PIPE_PACKETS: u64 = 4;
/// The offload budget in send quanta, as in mvfst, and the largest send quantum.
const OFFLOAD_SEND_QUANTA: u64 = 3;
const MAX_SEND_QUANTUM: u64 = 64 * 1024;

/// Returns `bytes` scaled by a gain in hundredths.
fn gain(bytes: u64, hundredths: u64) -> u64 {
    mul_div(bytes, hundredths, 100)
}

/// Returns `a * b / c` without overflow, saturating.
fn mul_div(a: u64, b: u64, c: u64) -> u64 {
    u64::try_from(u128::from(a) * u128::from(b) / u128::from(c.max(1))).unwrap_or(u64::MAX)
}

/// Returns the bytes `bw` bytes per second deliver in `rtt`.
fn bdp(bw: u64, rtt: Duration) -> u64 {
    let nanos = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
    mul_div(bw, nanos, 1_000_000_000)
}

/// Returns the rate in bytes per second of `bytes` per `rtt`.
fn rate_of(bytes: u64, rtt: Duration) -> u64 {
    let nanos = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
    mul_div(bytes, 1_000_000_000, nanos)
}

/// BBR.max_bw's filter: the largest delivery rate of the current and the previous ProbeBW
/// cycle (MaxBwFilterLen = 2). Like the draft's windowed filter, it ages only on an update.
#[derive(Clone, Copy, Debug, Default)]
struct MaxBwFilter {
    cycle: u64,
    current: u64,
    previous: u64,
}

impl MaxBwFilter {
    fn update(&mut self, bw: u64, cycle: u64) {
        if cycle != self.cycle {
            self.previous = if cycle == self.cycle + 1 {
                self.current
            } else {
                0
            };
            self.current = 0;
            self.cycle = cycle;
        }
        self.current = self.current.max(bw);
    }

    fn best(&self) -> u64 {
        self.current.max(self.previous)
    }
}

/// Returns whether more than LossThresh of `tx_in_flight` was lost, in at least `min_events`
/// loss events: the draft's IsInflightTooHigh() with the loss event condition added.
fn too_high(lost: u64, tx_in_flight: u64, events: u64, min_events: u64) -> bool {
    events >= min_events
        && u128::from(lost) * 100 > u128::from(tx_in_flight) * u128::from(LOSS_THRESH)
}

/// Returns the inflight at which the loss rate crossed LossThresh, the draft's InflightAtLoss(),
/// where `lost` includes `lost_packet`. The prefix is 0 if earlier losses already crossed it.
fn inflight_at_loss(lost_packet: &LostSample, lost: u64) -> u64 {
    let size = u64::from(lost_packet.size);
    let inflight_prev = lost_packet.tx_in_flight.saturating_sub(size);
    let lost_prev = u128::from(lost.saturating_sub(size));
    let prefix = (u128::from(inflight_prev) * u128::from(LOSS_THRESH))
        .saturating_sub(lost_prev * 100)
        / u128::from(100 - LOSS_THRESH);
    inflight_prev.saturating_add(u64::try_from(prefix).unwrap_or(u64::MAX))
}

/// Loss events as mvfst counts them, each a run of consecutive lost packet numbers in one space.
#[derive(Clone, Copy, Debug, Default)]
struct LossEvents {
    count: u64,
    largest: [Option<u64>; 3],
}

impl LossEvents {
    fn add(&mut self, lost: &LostSample) {
        let largest = &mut self.largest[lost.space.index()];
        if largest.is_none_or(|largest| lost.pn > largest + 1) {
            self.count += 1;
        }
        *largest = Some(largest.map_or(lost.pn, |largest| largest.max(lost.pn)));
    }
}

/// A loss episode, as in mvfst: losses that may yet be acknowledged as spurious, and the state that
/// undoing them restores.
#[derive(Clone, Copy, Debug)]
struct LossEpisode {
    prior_cwnd: u64,
    bw_shortterm: Option<u64>,
    inflight_shortterm: Option<u64>,
    inflight_longterm: Option<u64>,
    /// Declared losses not yet acknowledged as spurious.
    pending: u32,
    /// The newest send time when it opened; losses of packets sent by then join it.
    start: Option<Instant>,
    /// The state its losses ended, Startup or UP, if they ended one.
    undo_target: Option<State>,
}

/// Returns the larger of two bounds, where `None` is infinite.
fn max_bound(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    Some(a?.max(b?))
}

/// BBR.extra_acked's filter: the largest excess per round over the last few rounds.
#[derive(Clone, Copy, Debug, Default)]
struct ExtraAckedFilter {
    rounds: [(u64, u64); EXTRA_ACKED_ROUNDS as usize],
}

impl ExtraAckedFilter {
    /// Adds `extra` for `round` and returns the largest over the last `len` rounds. With one
    /// round, as in Startup, older rounds are dropped.
    fn update(&mut self, extra: u64, round: u64, len: u64) -> u64 {
        let slot = &mut self.rounds[(round % EXTRA_ACKED_ROUNDS) as usize];
        if slot.0 != round {
            *slot = (round, 0);
        }
        slot.1 = slot.1.max(extra);
        for slot in &mut self.rounds {
            if round - slot.0 >= len {
                *slot = (round, 0);
            }
        }
        self.rounds
            .iter()
            .map(|&(_, extra)| extra)
            .max()
            .unwrap_or(0)
    }
}

/// The states of the BBR state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

/// The BBRv3 controller.
#[derive(Clone, Debug)]
pub struct Bbr3 {
    pub(super) window: Window,
    /// The state of the generator behind the probe wait.
    rng: u64,
    /// The pacer's granularity and pacing horizon.
    granularity: Duration,
    horizon: Duration,
    state: State,
    /// C.pacing_gain in hundredths.
    pacing_gain: u64,
    /// C.cwnd_gain in hundredths.
    cwnd_gain: u64,
    max_bw: MaxBwFilter,
    /// BBR.cycle_count, which ages max_bw.
    cycle_count: u64,
    /// BBR.bw in bytes per second.
    bw: u64,
    next_round_delivered: u64,
    round_start: bool,
    round_count: u64,
    full_bw_reached: bool,
    full_bw_now: bool,
    full_bw: u64,
    full_bw_count: u64,
    drain_start_round: u64,
    /// When the current ProbeBW cycle started.
    cycle_stamp: Option<Instant>,
    bw_probe_wait: Duration,
    bw_probe_up_rounds: u32,
    bw_probe_up_acked: u64,
    probe_up_acked_per_inc: u64,
    /// Whether ProbeBW responds to each lost packet.
    check_probe_loss: bool,
    /// Set in DOWN until the probe's samples end at a round start.
    is_bw_probe_stopping: bool,
    /// BBR.bw_shortterm, BBR.inflight_shortterm and BBR.inflight_longterm; `None` is infinite.
    bw_shortterm: Option<u64>,
    inflight_shortterm: Option<u64>,
    inflight_longterm: Option<u64>,
    /// C.total_sent as of the newest packet that inflight_longterm did not cap, one sent in Startup
    /// or Drain or before a probe's loss set it. As in mvfst, samples of packets sent by then do
    /// not raise inflight_longterm.
    uncapped_sent: Option<u64>,
    /// C.is_cwnd_limited within the current round.
    cwnd_limited_in_round: bool,
    /// BBR.min_rtt; empty until the first RTT sample, as in mvfst.
    min_rtt: Option<Duration>,
    min_rtt_stamp: Option<Instant>,
    min_rtt_expired: bool,
    /// BBR.probe_rtt_cwnd, saved when min_rtt expires.
    probe_rtt_cwnd: Option<u64>,
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    /// BBR.idle_restart.
    idle_restart: bool,
    /// C.delivered as of the latest ACK frame or loss timeout.
    delivered: u64,
    /// C.pacing_rate in bytes per second.
    pacing_rate: u64,
    /// Whether the initial pacing rate was set again from the first min_rtt.
    has_seen_rtt: bool,
    /// C.send_quantum in bytes.
    send_quantum: u64,
    /// Whether pacing has started; the initial window goes out unpaced.
    pacing_ready: bool,
    /// Whether a send changed C.pacing_rate since the pacer last took it.
    pacer_refresh: bool,
    /// BBR.extra_acked.
    extra_acked: u64,
    extra_acked_filter: ExtraAckedFilter,
    extra_acked_interval_start: Option<Instant>,
    extra_acked_delivered: u64,
    prior_cwnd: u64,
    bw_latest: u64,
    inflight_latest: u64,
    loss_round_start: bool,
    loss_round_delivered: u64,
    /// BBR.loss_in_round.
    loss_in_round: bool,
    /// The bytes lost and the loss events in the current round, and the loss events in the
    /// current loss round.
    bytes_lost_in_round: u64,
    losses_in_round: LossEvents,
    losses_in_loss_round: LossEvents,
    /// Whether the controller is in recovery, and its start: the newest send at the latest loss.
    in_recovery: bool,
    recovery_start: Option<Instant>,
    /// The newest send time.
    last_send: Option<Instant>,
    loss_episode: Option<LossEpisode>,
}

impl Bbr3 {
    pub(super) fn new(window: Window, start: &CcStart) -> Self {
        let mut bbr = Self {
            window,
            rng: start.seed,
            granularity: start.pacing_granularity,
            horizon: start.horizon,
            state: State::Startup,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: DEFAULT_CWND_GAIN,
            max_bw: MaxBwFilter::default(),
            cycle_count: 0,
            bw: 0,
            next_round_delivered: 0,
            round_start: false,
            round_count: 0,
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0,
            full_bw_count: 0,
            drain_start_round: 0,
            cycle_stamp: None,
            bw_probe_wait: Duration::ZERO,
            bw_probe_up_rounds: 0,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: u64::MAX,
            check_probe_loss: false,
            is_bw_probe_stopping: false,
            bw_shortterm: None,
            inflight_shortterm: None,
            inflight_longterm: None,
            uncapped_sent: None,
            cwnd_limited_in_round: false,
            min_rtt: None,
            min_rtt_stamp: None,
            min_rtt_expired: false,
            probe_rtt_cwnd: None,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            idle_restart: false,
            delivered: 0,
            pacing_rate: 0,
            has_seen_rtt: false,
            send_quantum: 0,
            pacing_ready: false,
            pacer_refresh: false,
            extra_acked: 0,
            extra_acked_filter: ExtraAckedFilter::default(),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            prior_cwnd: 0,
            bw_latest: 0,
            inflight_latest: 0,
            loss_round_start: false,
            loss_round_delivered: 0,
            loss_in_round: false,
            bytes_lost_in_round: 0,
            losses_in_round: LossEvents::default(),
            losses_in_loss_round: LossEvents::default(),
            in_recovery: false,
            recovery_start: None,
            last_send: None,
            loss_episode: None,
        };
        bbr.pacing_ready = start.total_sent >= bbr.window.initial;
        bbr.send_quantum = 2 * bbr.window.mss;
        // The initial window may be below MinPipeCwnd when max_window is.
        bbr.bound_cwnd_to_window();
        // The initial rate uses the path's smoothed RTT if it has a sample, else 1 ms.
        bbr.init_pacing_rate(start.srtt.unwrap_or(Duration::from_millis(1)));
        bbr
    }

    /// Sets C.pacing_rate to InitialCwnd per `rtt` at Startup's gain, the draft's InitPacingRate().
    fn init_pacing_rate(&mut self, rtt: Duration) {
        self.pacing_rate = gain(rate_of(self.window.initial, rtt), STARTUP_PACING_GAIN);
    }

    pub(super) fn on_sent(&mut self, sent: &SentEvent) {
        if !sent.on_path {
            return;
        }
        self.last_send = Some(sent.time_sent);
        if matches!(self.state, State::Startup | State::Drain) {
            self.uncapped_sent = Some(sent.total_sent);
        }
        // As in mvfst, any send into an empty pipe restarts from idle, app-limited or not.
        if sent.bytes_in_flight == 0 {
            self.handle_restart_from_idle(sent.time_sent);
        }
        // C.is_cwnd_limited: admission lets a datagram start below cwnd, so a sender the window
        // limits reaches it.
        if sent.bytes_in_flight + u64::from(sent.size) >= self.window.cwnd {
            self.cwnd_limited_in_round = true;
        }
    }

    /// Restarts from idle as the draft's HandleRestartFromIdle() does, and also zeroes the bytes
    /// counted in the ACK aggregation interval before the idle period.
    fn handle_restart_from_idle(&mut self, now: Instant) {
        self.idle_restart = true;
        self.extra_acked_interval_start = Some(now);
        self.extra_acked_delivered = 0;
        if self.is_in_probe_bw() {
            let rate = self.pacing_rate;
            self.set_pacing_rate_with_gain(100);
            self.pacer_refresh |= self.pacing_rate != rate;
        } else if self.state == State::ProbeRtt {
            self.check_probe_rtt_done(now, self.delivered);
        }
    }

    pub(super) fn on_ack_or_loss(&mut self, event: &AckOrLoss<'_>) -> bool {
        self.delivered = event.delivered;
        self.resolve_loss_episode(event);
        let newly_acked = event
            .ack
            .is_some_and(|ack| ack.largest_acked_sent.is_some());
        if !newly_acked && event.lost.is_empty() {
            return false;
        }
        if !event.lost.is_empty() {
            self.on_loss(event);
        }
        match &event.ack {
            Some(ack) => self.on_ack(event, ack),
            None => {
                self.update_control_parameters(event, 0);
                false
            }
        }
    }

    /// Responds to losses: enters recovery, which emulates TCP's as in mvfst, or moves its
    /// start, then handles each lost packet in send order.
    fn on_loss(&mut self, event: &AckOrLoss<'_>) {
        self.update_loss_episode(event);
        if !self.in_recovery {
            self.save_cwnd();
            self.in_recovery = true;
        }
        self.recovery_start = self.last_send.or(event.largest_lost_sent);
        for lost in event.lost {
            self.handle_lost_packet(lost, event);
        }
        if event.persistent_congestion {
            self.on_persistent_congestion();
        }
    }

    /// Adds the event's losses to the open loss episode if every lost packet was sent by its start,
    /// or else ends it and may open a new one. Persistent congestion ends it.
    fn update_loss_episode(&mut self, event: &AckOrLoss<'_>) {
        if event.persistent_congestion {
            self.loss_episode = None;
            return;
        }
        if let Some(episode) = &mut self.loss_episode
            && event
                .largest_lost_sent
                .zip(episode.start)
                .is_some_and(|(sent, start)| sent <= start)
        {
            episode.pending += event.newly_lost;
            return;
        }
        self.loss_episode = None;
        // An episode is undone as a whole, so a new one does not open while older losses or their
        // recovery are pending.
        if event.declared_lost != event.newly_lost || self.in_recovery || self.loss_in_round {
            return;
        }
        self.save_cwnd();
        self.loss_episode = Some(LossEpisode {
            prior_cwnd: self.prior_cwnd,
            bw_shortterm: self.bw_shortterm,
            inflight_shortterm: self.inflight_shortterm,
            inflight_longterm: self.inflight_longterm,
            pending: event.newly_lost,
            start: self.last_send,
            undo_target: None,
        });
    }

    /// Undoes the loss episode once its losses are all acknowledged as spurious. The declared-lost
    /// count already has this frame's spurious losses out and this event's new losses in; any other
    /// change to it ends the episode.
    fn resolve_loss_episode(&mut self, event: &AckOrLoss<'_>) {
        let Some(episode) = &mut self.loss_episode else {
            return;
        };
        let (pending, declared) = (episode.pending, event.declared_lost);
        if event.spurious > pending
            || event.newly_lost > declared
            || pending - event.spurious != declared - event.newly_lost
        {
            self.loss_episode = None;
            return;
        }
        episode.pending -= event.spurious;
        if episode.pending == 0 {
            let episode = *episode;
            self.loss_episode = None;
            self.handle_spurious_loss_detection(&episode);
        }
    }

    /// Undoes a spurious loss episode, the draft's HandleSpuriousLossDetection().
    fn handle_spurious_loss_detection(&mut self, episode: &LossEpisode) {
        self.window.cwnd = self.window.cwnd.max(episode.prior_cwnd);
        self.in_recovery = false;
        self.loss_in_round = false;
        self.losses_in_loss_round = LossEvents::default();
        self.bytes_lost_in_round = 0;
        self.losses_in_round = LossEvents::default();
        self.reset_full_bw();
        self.bw_shortterm = max_bound(self.bw_shortterm, episode.bw_shortterm);
        self.inflight_shortterm = max_bound(self.inflight_shortterm, episode.inflight_shortterm);
        let longterm = max_bound(self.inflight_longterm, episode.inflight_longterm);
        if longterm != self.inflight_longterm {
            self.uncapped_sent = None;
        }
        self.inflight_longterm = longterm;
        if episode.undo_target == Some(State::Startup) && self.state != State::Startup {
            self.full_bw_reached = false;
            // Startup does not respond to each lost packet, nor does a ProbeRTT that ends in it.
            self.check_probe_loss = false;
            if self.state != State::ProbeRtt {
                self.enter_startup();
            }
        } else if episode.undo_target == Some(State::ProbeBwUp)
            && !matches!(self.state, State::ProbeBwUp | State::ProbeRtt)
        {
            self.start_probe_bw_refill(self.delivered);
        }
        self.bound_bw_for_model();
        self.set_pacing_rate();
        self.set_send_quantum();
        self.bound_cwnd();
    }

    /// Records a lost packet, the draft's HandleLostPacket() with NoteLoss(). As in mvfst, a
    /// probe's loss is too high when the round's lost bytes exceed LossThresh of P.tx_in_flight in
    /// at least two loss events.
    fn handle_lost_packet(&mut self, lost: &LostSample, event: &AckOrLoss<'_>) {
        if !self.loss_in_round {
            self.loss_round_delivered = event.delivered;
            self.save_cwnd();
        }
        self.loss_in_round = true;
        self.losses_in_loss_round.add(lost);
        self.losses_in_round.add(lost);
        self.bytes_lost_in_round += u64::from(lost.size);
        if self.check_probe_loss
            && too_high(
                self.bytes_lost_in_round,
                lost.tx_in_flight,
                self.losses_in_round.count,
                PROBE_BW_FULL_LOSS_COUNT,
            )
        {
            let inflight = inflight_at_loss(lost, self.bytes_lost_in_round);
            self.handle_inflight_too_high(inflight, lost.is_app_limited, event);
        }
    }

    /// Responds to too much loss in a bandwidth probe, the draft's HandleInflightTooHigh().
    fn handle_inflight_too_high(
        &mut self,
        tx_in_flight: u64,
        app_limited: bool,
        event: &AckOrLoss<'_>,
    ) {
        // Only one response per bandwidth probe.
        self.check_probe_loss = false;
        if !app_limited {
            self.inflight_longterm = Some(tx_in_flight.max(gain(self.target_inflight(), BETA)));
            self.uncapped_sent = Some(event.total_sent);
        }
        if self.state == State::ProbeBwUp {
            if let Some(episode) = &mut self.loss_episode {
                episode.undo_target = Some(State::ProbeBwUp);
            }
            self.start_probe_bw_down(event.now, event.delivered);
        }
    }

    /// Responds to persistent congestion as mvfst does, in place of the draft's OnEnterRTO().
    fn on_persistent_congestion(&mut self) {
        self.save_cwnd();
        self.reset_full_bw();
        if !self.is_probing_bw() && self.inflight_shortterm.is_none() {
            self.inflight_shortterm = Some(self.window.cwnd.max(self.prior_cwnd));
        }
        self.window.cwnd = self.min_pipe_cwnd();
    }

    /// Runs the draft's UpdateOnACK(), ending recovery after the model update: the ACK that ends
    /// recovery usually also starts the loss round that Startup's loss exit checks.
    fn on_ack(&mut self, event: &AckOrLoss<'_>, ack: &AckPart) -> bool {
        let app_limited = self.update_model_and_state(event, ack);
        if self.in_recovery
            && ack
                .largest_acked_sent
                .is_some_and(|sent| self.recovery_start.is_none_or(|start| sent > start))
        {
            self.in_recovery = false;
            self.restore_cwnd();
        }
        self.update_control_parameters(event, ack.acked_bytes);
        if self.round_start {
            self.cwnd_limited_in_round = false;
        }
        app_limited
    }

    /// Saves cwnd in prior_cwnd, the draft's SaveCwnd().
    fn save_cwnd(&mut self) {
        self.prior_cwnd = if !self.in_recovery && self.state != State::ProbeRtt {
            self.window.cwnd
        } else {
            self.prior_cwnd.max(self.window.cwnd)
        };
    }

    /// Restores cwnd from prior_cwnd, the draft's RestoreCwnd().
    fn restore_cwnd(&mut self) {
        self.window.cwnd = self.window.cwnd.max(self.prior_cwnd);
    }

    /// Updates the model and the state from an ACK, the draft's UpdateModelAndState(). Returns
    /// whether to mark the connection app-limited, as the draft's HandleProbeRTT() does.
    fn update_model_and_state(&mut self, event: &AckOrLoss<'_>, ack: &AckPart) -> bool {
        let rs = ack.rate.as_ref();
        self.update_latest_delivery_signals(rs, event.delivered);
        // The draft's UpdateCongestionSignals().
        self.update_max_bw(rs, event.delivered);
        if self.loss_round_start {
            self.adapt_lower_bounds_from_congestion();
            self.loss_in_round = false;
        }
        self.update_ack_aggregation(ack.acked_bytes, event.now);
        self.check_full_bw_reached(rs);
        self.check_startup_high_loss(rs);
        self.check_startup_done();
        self.check_drain_done(event);
        self.update_probe_bw_cycle_phase(rs, ack.acked_bytes, event);
        self.update_min_rtt(ack.rtt_sample, event.now);
        let app_limited = self.check_probe_rtt(rs, event);
        self.advance_latest_delivery_signals(rs);
        self.bound_bw_for_model();
        app_limited
    }

    /// Updates the latest delivery signals, the draft's UpdateLatestDeliverySignals().
    fn update_latest_delivery_signals(&mut self, rs: Option<&RateSample>, delivered: u64) {
        self.loss_round_start = false;
        let Some(rs) = rs else { return };
        self.bw_latest = self.bw_latest.max(rs.delivery_rate);
        self.inflight_latest = self.inflight_latest.max(rs.delivered);
        if rs.prior_delivered >= self.loss_round_delivered {
            self.loss_round_delivered = delivered;
            self.loss_round_start = true;
        }
    }

    /// Advances the latest delivery signals, the draft's AdvanceLatestDeliverySignals().
    fn advance_latest_delivery_signals(&mut self, rs: Option<&RateSample>) {
        if let Some(rs) = rs
            && self.loss_round_start
        {
            self.bw_latest = rs.delivery_rate;
            self.inflight_latest = rs.delivered;
            self.losses_in_loss_round = LossEvents::default();
        }
    }

    /// Marks the pipe full on too much loss, the draft's CheckStartupHighLoss(), only at the end
    /// of a loss round in recovery with at least six loss events in it.
    fn check_startup_high_loss(&mut self, rs: Option<&RateSample>) {
        let Some(rs) = rs else { return };
        if self.full_bw_reached
            || !self.loss_round_start
            || !self.in_recovery
            || !too_high(
                rs.lost,
                rs.tx_in_flight,
                self.losses_in_loss_round.count,
                STARTUP_FULL_LOSS_COUNT,
            )
        {
            return;
        }
        if let Some(episode) = &mut self.loss_episode {
            episode.undo_target = Some(State::Startup);
        }
        self.full_bw_reached = true;
        self.inflight_longterm = Some(self.bdp_multiple(self.bw, 100).max(self.inflight_latest));
    }

    /// Sets the pacing rate, send quantum and cwnd, the draft's UpdateControlParameters().
    fn update_control_parameters(&mut self, event: &AckOrLoss<'_>, newly_acked: u64) {
        self.set_pacing_rate();
        // As in mvfst, pacing starts at the first update after InitialCwnd bytes were sent.
        self.pacing_ready |= event.total_sent >= self.window.initial;
        self.set_send_quantum();
        self.set_cwnd(newly_acked, event.delivered);
    }

    /// Sets C.send_quantum, the draft's SetSendQuantum() over the pacer's granularity rather
    /// than 1 ms, as in mvfst. It feeds only the offload budget.
    fn set_send_quantum(&mut self) {
        let quantum = bdp(self.pacing_rate, self.granularity);
        self.send_quantum = quantum.min(MAX_SEND_QUANTUM).max(2 * self.window.mss);
    }

    /// Updates the round and max_bw, the draft's UpdateMaxBw() with UpdateRound().
    fn update_max_bw(&mut self, rs: Option<&RateSample>, delivered: u64) {
        self.round_start = rs.is_some_and(|rs| rs.prior_delivered >= self.next_round_delivered);
        if self.round_start {
            self.start_round(delivered);
            self.round_count += 1;
        }
        // As in mvfst, an app-limited sample enters only if strictly greater than max_bw.
        if let Some(rs) = rs
            && rs.delivery_rate > 0
            && (rs.delivery_rate > self.max_bw.best() || !rs.is_app_limited)
        {
            self.max_bw.update(rs.delivery_rate, self.cycle_count);
        }
    }

    /// Starts a round, the draft's StartRound(), and clears the round's losses.
    fn start_round(&mut self, delivered: u64) {
        self.next_round_delivered = delivered;
        self.bytes_lost_in_round = 0;
        self.losses_in_round = LossEvents::default();
    }

    /// Updates extra_acked, the draft's UpdateACKAggregation().
    fn update_ack_aggregation(&mut self, newly_acked: u64, now: Instant) {
        let start = *self.extra_acked_interval_start.get_or_insert(now);
        let mut expected = bdp(self.bw, now.saturating_duration_since(start));
        if self.extra_acked_delivered <= expected {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(now);
            expected = 0;
        }
        self.extra_acked_delivered += newly_acked;
        let extra = (self.extra_acked_delivered - expected).min(self.window.cwnd);
        let len = if self.full_bw_reached {
            EXTRA_ACKED_ROUNDS
        } else {
            1
        };
        self.extra_acked = self.extra_acked_filter.update(extra, self.round_count, len);
    }

    /// Counts rounds without bandwidth growth, the draft's CheckFullBWReached().
    fn check_full_bw_reached(&mut self, rs: Option<&RateSample>) {
        if self.full_bw_now || !self.round_start || rs.is_none_or(|rs| rs.is_app_limited) {
            return;
        }
        // As in mvfst, the plateau check compares max_bw, not the sample's delivery rate.
        let max_bw = self.max_bw.best();
        if max_bw >= mul_div(self.full_bw, FULL_BW_GROWTH, 100) {
            self.reset_full_bw();
            self.full_bw = max_bw;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= FULL_BW_ROUNDS;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// Resets the full-bw check, the draft's ResetFullBW().
    fn reset_full_bw(&mut self) {
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// Enters Drain once the pipe is full, the draft's CheckStartupDone().
    fn check_startup_done(&mut self) {
        if self.state == State::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// Enters Startup, the draft's EnterStartup().
    fn enter_startup(&mut self) {
        self.state = State::Startup;
        self.set_gains(STARTUP_PACING_GAIN, DEFAULT_CWND_GAIN);
    }

    /// Enters Drain, the draft's EnterDrain().
    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.set_gains(DRAIN_PACING_GAIN, DEFAULT_CWND_GAIN);
        // As in mvfst, a round already under way does not count.
        self.drain_start_round = self.round_count + u64::from(!self.round_start);
    }

    /// Moves from Drain to DOWN, the draft's CheckDrainDone(), once inflight is at most
    /// Inflight(1.0) or after MAX_DRAIN_ROUNDS full rounds.
    fn check_drain_done(&mut self, event: &AckOrLoss<'_>) {
        if self.state == State::Drain
            && (event.bytes_in_flight <= self.inflight(self.bw, 100)
                || self.round_count >= self.drain_start_round + MAX_DRAIN_ROUNDS)
        {
            self.start_probe_bw_down(event.now, event.delivered);
        }
    }

    /// Advances the ProbeBW cycle, the draft's UpdateProbeBWCyclePhase().
    fn update_probe_bw_cycle_phase(
        &mut self,
        rs: Option<&RateSample>,
        newly_acked: u64,
        event: &AckOrLoss<'_>,
    ) {
        if !self.full_bw_reached {
            return;
        }
        self.adapt_long_term_model(rs, newly_acked);
        let (now, delivered) = (event.now, event.delivered);
        match self.state {
            State::ProbeBwDown => {
                if !self.is_time_to_probe_bw(now, delivered) && self.is_time_to_cruise(event) {
                    self.start_probe_bw_cruise();
                }
            }
            State::ProbeBwCruise => {
                self.is_time_to_probe_bw(now, delivered);
            }
            State::ProbeBwRefill => {
                if self.round_start {
                    self.check_probe_loss = true;
                    self.start_probe_bw_up(delivered);
                }
            }
            State::ProbeBwUp => {
                if self.is_time_to_go_down() {
                    self.start_probe_bw_down(now, delivered);
                }
            }
            State::Startup | State::Drain | State::ProbeRtt => {}
        }
    }

    /// Adapts the long-term model, the draft's AdaptLongTermModel(). As in mvfst, precautionary
    /// acceleration never fires.
    fn adapt_long_term_model(&mut self, rs: Option<&RateSample>, newly_acked: u64) {
        if self.is_bw_probe_stopping && self.round_start {
            // The probe's samples have ended.
            self.check_probe_loss = false;
            self.is_bw_probe_stopping = false;
            if self.is_in_probe_bw() && rs.is_some_and(|rs| !rs.is_app_limited) {
                self.cycle_count += 1;
            }
        }
        let (Some(rs), Some(longterm)) = (rs, self.inflight_longterm) else {
            return;
        };
        // Drain, which inflight_longterm does not cap, and packets it did not cap do not raise it.
        if self.state == State::Drain
            || self.uncapped_sent.is_some_and(|sent| rs.total_sent <= sent)
            || too_high(
                rs.lost,
                rs.tx_in_flight,
                self.losses_in_round.count,
                PROBE_BW_FULL_LOSS_COUNT,
            )
        {
            return;
        }
        self.inflight_longterm = Some(longterm.max(rs.tx_in_flight));
        if self.state == State::ProbeBwUp {
            self.probe_inflight_longterm_upward(newly_acked);
        }
    }

    /// Raises inflight_longterm in UP, the draft's ProbeInflightLongtermUpward().
    fn probe_inflight_longterm_upward(&mut self, newly_acked: u64) {
        let Some(longterm) = self.inflight_longterm else {
            return;
        };
        if !self.cwnd_limited_in_round || self.window.cwnd < longterm {
            return;
        }
        self.bw_probe_up_acked += newly_acked;
        if self.bw_probe_up_acked >= self.probe_up_acked_per_inc {
            let delta = self.bw_probe_up_acked / self.probe_up_acked_per_inc;
            self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
            // At most to the maximum window.
            self.inflight_longterm =
                Some((longterm + delta * self.window.mss).min(self.window.max));
        }
        if self.round_start {
            self.raise_inflight_longterm_slope();
        }
    }

    /// Enters DOWN, the draft's StartProbeBW_DOWN(), which also stands in for EnterProbeBW().
    fn start_probe_bw_down(&mut self, now: Instant, delivered: u64) {
        self.reset_congestion_signals();
        self.probe_up_acked_per_inc = u64::MAX;
        self.pick_probe_wait();
        self.cycle_stamp = Some(now);
        self.is_bw_probe_stopping = true;
        self.start_round(delivered);
        self.state = State::ProbeBwDown;
        self.set_gains(PROBE_BW_DOWN_PACING_GAIN, DEFAULT_CWND_GAIN);
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = State::ProbeBwCruise;
        self.set_gains(PROBE_BW_CRUISE_PACING_GAIN, DEFAULT_CWND_GAIN);
    }

    fn start_probe_bw_refill(&mut self, delivered: u64) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        self.is_bw_probe_stopping = false;
        self.start_round(delivered);
        self.state = State::ProbeBwRefill;
        self.set_gains(PROBE_BW_REFILL_PACING_GAIN, DEFAULT_CWND_GAIN);
    }

    fn start_probe_bw_up(&mut self, delivered: u64) {
        self.start_round(delivered);
        // The plateau check starts from max_bw.
        self.reset_full_bw();
        self.full_bw = self.max_bw.best();
        self.state = State::ProbeBwUp;
        self.set_gains(PROBE_BW_UP_PACING_GAIN, PROBE_BW_UP_CWND_GAIN);
        self.raise_inflight_longterm_slope();
    }

    /// Starts REFILL once the probe wait has passed and returns whether it did: the draft's
    /// IsTimeToProbeBW() without the Reno-coexistence bound, which mvfst leaves off.
    fn is_time_to_probe_bw(&mut self, now: Instant, delivered: u64) -> bool {
        if self
            .cycle_stamp
            .is_some_and(|stamp| now > stamp + self.bw_probe_wait)
        {
            self.start_probe_bw_refill(delivered);
            return true;
        }
        false
    }

    /// Picks the probe wait, the draft's PickProbeWait(): 2 s plus 0-999 ms.
    fn pick_probe_wait(&mut self) {
        let jitter = self.random() % PROBE_WAIT_JITTER_MS;
        self.bw_probe_wait = MIN_PROBE_WAIT + Duration::from_millis(jitter);
    }

    /// Draws the next SplitMix64 value from the connection's seed.
    fn random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns whether DOWN may cruise, the draft's IsTimeToCruise(), with Inflight(max_bw, 1.0)
    /// read as mvfst does, quantization budget included.
    fn is_time_to_cruise(&self, event: &AckOrLoss<'_>) -> bool {
        let inflight = event.bytes_in_flight;
        inflight <= self.inflight_with_headroom()
            && inflight <= self.inflight(self.max_bw.best(), 100)
    }

    /// Returns whether to end UP, the draft's IsTimeToGoDown() without precautionary deceleration.
    fn is_time_to_go_down(&mut self) -> bool {
        if self.cwnd_limited_in_round
            && self
                .inflight_longterm
                .is_some_and(|longterm| self.window.cwnd >= longterm)
        {
            // inflight_longterm limits the bandwidth. Restart the plateau check from max_bw.
            self.reset_full_bw();
            self.full_bw = self.max_bw.best();
            return false;
        }
        self.full_bw_now
    }

    /// Raises the slope of inflight_longterm's growth, the draft's RaiseInflightLongtermSlope().
    fn raise_inflight_longterm_slope(&mut self) {
        let growth_this_round = 1u64 << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds = (self.bw_probe_up_rounds + 1).min(MAX_PROBE_UP_ROUNDS);
        self.probe_up_acked_per_inc = (self.window.cwnd / growth_this_round).max(self.window.mss);
    }

    /// Returns inflight_longterm less its headroom, the draft's InflightWithHeadroom().
    fn inflight_with_headroom(&self) -> u64 {
        let Some(longterm) = self.inflight_longterm else {
            return u64::MAX;
        };
        let headroom = self.window.mss.max(longterm * HEADROOM / 100);
        longterm.saturating_sub(headroom).max(self.min_pipe_cwnd())
    }

    /// Clears the congestion signals, the draft's ResetCongestionSignals(), and restarts the loss
    /// round's event count.
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.losses_in_loss_round = LossEvents::default();
        self.bw_latest = 0;
        self.inflight_latest = 0;
    }

    /// Sets the short-term bounds after a loss round with loss outside a probe, the draft's
    /// AdaptLowerBoundsFromCongestion() with InitLowerBounds() and LossLowerBounds().
    fn adapt_lower_bounds_from_congestion(&mut self) {
        if self.is_probing_bw() || !self.loss_in_round {
            return;
        }
        let bw = self.bw_shortterm.unwrap_or(self.max_bw.best());
        let inflight = self.inflight_shortterm.unwrap_or(self.window.cwnd);
        self.bw_shortterm = Some(self.bw_latest.max(gain(bw, BETA)));
        self.inflight_shortterm = Some(self.inflight_latest.max(gain(inflight, BETA)));
    }

    /// Clears the short-term model, the draft's ResetShortTermModel().
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = None;
        self.inflight_shortterm = None;
    }

    /// Returns whether the state probes for bandwidth, the draft's IsProbingBW().
    fn is_probing_bw(&self) -> bool {
        matches!(
            self.state,
            State::Startup | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    fn is_in_probe_bw(&self) -> bool {
        matches!(
            self.state,
            State::ProbeBwDown | State::ProbeBwCruise | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    fn set_gains(&mut self, pacing_gain: u64, cwnd_gain: u64) {
        self.pacing_gain = pacing_gain;
        self.cwnd_gain = cwnd_gain;
    }

    /// Sets bw, the draft's BoundBWForModel().
    fn bound_bw_for_model(&mut self) {
        self.bw = self
            .max_bw
            .best()
            .min(self.bw_shortterm.unwrap_or(u64::MAX));
    }

    /// Updates min_rtt, the draft's UpdateMinRTT().
    fn update_min_rtt(&mut self, rtt: Option<Duration>, now: Instant) {
        let stamp = *self.min_rtt_stamp.get_or_insert(now);
        self.min_rtt_expired = now > stamp + MIN_RTT_FILTER_LEN;
        if self.min_rtt_expired {
            self.probe_rtt_cwnd = Some(self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN));
        }
        if let Some(rtt) = rtt
            && (self.min_rtt.is_none_or(|min| rtt < min) || self.min_rtt_expired)
        {
            self.min_rtt = Some(rtt);
            self.min_rtt_stamp = Some(now);
        }
    }

    /// Enters ProbeRTT once min_rtt has expired, the draft's CheckProbeRTT() with EnterProbeRTT().
    /// Returns whether HandleProbeRTT() ran, which marks the connection app-limited.
    fn check_probe_rtt(&mut self, rs: Option<&RateSample>, event: &AckOrLoss<'_>) -> bool {
        if self.state != State::ProbeRtt && self.min_rtt_expired && !self.idle_restart {
            self.save_cwnd();
            self.state = State::ProbeRtt;
            self.set_gains(PROBE_RTT_PACING_GAIN, PROBE_RTT_CWND_GAIN);
            self.probe_rtt_done_stamp = None;
            self.is_bw_probe_stopping = true;
            self.start_round(event.delivered);
        }
        let in_probe_rtt = self.state == State::ProbeRtt;
        if in_probe_rtt {
            self.handle_probe_rtt(event);
        }
        if rs.is_some_and(|rs| rs.delivered > 0) {
            self.idle_restart = false;
        }
        in_probe_rtt
    }

    /// Runs ProbeRTT's step, the draft's HandleProbeRTT() without the app-limited mark, which the
    /// caller applies.
    fn handle_probe_rtt(&mut self, event: &AckOrLoss<'_>) {
        match self.probe_rtt_done_stamp {
            None if event.bytes_in_flight <= self.probe_rtt_cwnd() => {
                self.probe_rtt_done_stamp = Some(event.now + PROBE_RTT_DURATION);
                self.probe_rtt_round_done = false;
                self.start_round(event.delivered);
            }
            None => {}
            Some(_) => {
                self.probe_rtt_round_done |= self.round_start;
                if self.probe_rtt_round_done {
                    self.check_probe_rtt_done(event.now, event.delivered);
                }
            }
        }
    }

    /// Leaves ProbeRTT once its wait has passed, the draft's CheckProbeRTTDone().
    fn check_probe_rtt_done(&mut self, now: Instant, delivered: u64) {
        if self.probe_rtt_done_stamp.is_some_and(|done| now > done) {
            // The next ProbeRTT is due MinRTTFilterLen from now.
            self.min_rtt_stamp = Some(now);
            self.restore_cwnd();
            self.exit_probe_rtt(now, delivered);
        }
    }

    /// Leaves ProbeRTT for CRUISE, or Startup if the pipe was not full, the draft's ExitProbeRTT().
    fn exit_probe_rtt(&mut self, now: Instant, delivered: u64) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down(now, delivered);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// Returns ProbeRTT's cwnd, the draft's ProbeRTTCwnd().
    fn probe_rtt_cwnd(&self) -> u64 {
        self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN)
            .min(self.probe_rtt_cwnd.unwrap_or(u64::MAX))
            .max(self.min_pipe_cwnd())
    }

    /// Sets the pacing rate from the current gain, the draft's SetPacingRate().
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// Sets the pacing rate with `pacing_gain` in hundredths, the draft's SetPacingRateWithGain().
    fn set_pacing_rate_with_gain(&mut self, pacing_gain: u64) {
        // The initial rate is set again once, from the first min_rtt.
        if !self.has_seen_rtt
            && let Some(rtt) = self.min_rtt
        {
            self.has_seen_rtt = true;
            self.init_pacing_rate(rtt);
        }
        // As in mvfst, the rate is not discounted by a pacing margin.
        let rate = gain(self.bw, pacing_gain);
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// Returns C.pacing_rate in bytes per second.
    pub(super) fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Grows and bounds cwnd, the draft's SetCwnd().
    fn set_cwnd(&mut self, newly_acked: u64, delivered: u64) {
        let max_inflight = self.max_inflight();
        let cwnd = self.window.cwnd;
        if self.full_bw_reached {
            self.window.cwnd = (cwnd + newly_acked).min(max_inflight);
        } else if cwnd < max_inflight || delivered < self.window.initial {
            self.window.cwnd = cwnd + newly_acked;
        }
        self.bound_cwnd();
    }

    /// Bounds cwnd as the draft's SetCwnd() does after growth, then to max_window as mvfst does.
    fn bound_cwnd(&mut self) {
        self.window.cwnd = self.window.cwnd.max(self.min_pipe_cwnd());
        // The draft's BoundCwndForProbeRTT().
        if self.state == State::ProbeRtt {
            self.window.cwnd = self.window.cwnd.min(self.probe_rtt_cwnd());
        }
        self.bound_cwnd_for_model();
        self.bound_cwnd_to_window();
    }

    /// Caps cwnd by the model, the draft's BoundCwndForModel(). As in mvfst and the draft's
    /// pseudocode, inflight_longterm does not cap Drain, though the draft's table of states does.
    fn bound_cwnd_for_model(&mut self) {
        let cap = match self.state {
            State::ProbeBwDown | State::ProbeBwRefill | State::ProbeBwUp => self.inflight_longterm,
            State::ProbeBwCruise | State::ProbeRtt => Some(self.inflight_with_headroom()),
            State::Startup | State::Drain => None,
        };
        let cap = cap
            .unwrap_or(u64::MAX)
            .min(self.inflight_shortterm.unwrap_or(u64::MAX))
            .max(self.min_pipe_cwnd());
        self.window.cwnd = self.window.cwnd.min(cap);
    }

    /// Bounds cwnd to at most max_window datagrams and at least MinPipeCwnd, the floor winning.
    /// It avoids `clamp`, which panics when max_window is below MinPipeCwnd.
    fn bound_cwnd_to_window(&mut self) {
        let min_pipe = self.min_pipe_cwnd();
        let w = &mut self.window;
        w.cwnd = w.cwnd.min(w.max).max(min_pipe);
    }

    /// Returns BBR.MinPipeCwnd for the current datagram size.
    fn min_pipe_cwnd(&self) -> u64 {
        MIN_PIPE_PACKETS * self.window.mss
    }

    /// Returns the BDP at `bw` scaled by `hundredths`, the draft's BDPMultiple(), or InitialCwnd
    /// until there is a min_rtt.
    fn bdp_multiple(&self, bw: u64, hundredths: u64) -> u64 {
        match self.min_rtt {
            None => self.window.initial,
            Some(rtt) => gain(bdp(bw, rtt), hundredths),
        }
    }

    /// Returns the draft's TargetInflight(): the BDP, at most cwnd.
    fn target_inflight(&self) -> u64 {
        self.bdp_multiple(self.bw, 100).min(self.window.cwnd)
    }

    /// Returns the offload budget: three send quanta plus the pacing rate times the pacing horizon.
    pub(crate) fn offload_budget(&self) -> u64 {
        (OFFLOAD_SEND_QUANTA * self.send_quantum)
            .saturating_add(bdp(self.pacing_rate, self.horizon))
    }

    /// Returns `inflight_cap` with the draft's QuantizationBudget(), using an offload budget of
    /// three send quanta plus the pacing rate times the pacing horizon.
    fn quantization_budget(&self, inflight_cap: u64) -> u64 {
        let budget = inflight_cap
            .max(self.offload_budget())
            .max(self.min_pipe_cwnd());
        if self.state == State::ProbeBwUp {
            budget.saturating_add(2 * self.window.mss)
        } else {
            budget
        }
    }

    /// Returns the in-flight target for `bw` and gain `hundredths`, the draft's Inflight().
    fn inflight(&self, bw: u64, hundredths: u64) -> u64 {
        self.quantization_budget(self.bdp_multiple(bw, hundredths))
    }

    /// Returns max_inflight, the draft's UpdateMaxInflight(). As in mvfst, extra_acked joins only
    /// once the pipe is full.
    fn max_inflight(&self) -> u64 {
        let mut inflight_cap = self.bdp_multiple(self.bw, self.cwnd_gain);
        if self.full_bw_reached {
            inflight_cap += self.extra_acked;
        }
        self.quantization_budget(inflight_cap)
    }

    /// Returns whether the pacer should pace.
    pub(super) fn pacing_ready(&self) -> bool {
        self.pacing_ready
    }

    /// Returns and clears whether a send changed the pacing rate since the pacer last took it.
    pub(super) fn take_pacer_refresh(&mut self) -> bool {
        std::mem::take(&mut self.pacer_refresh)
    }

    /// Returns whether a packet sent at `sent` belongs to the current recovery.
    pub(super) fn in_recovery(&self, sent: Instant) -> bool {
        self.in_recovery && self.recovery_start.is_some_and(|start| sent <= start)
    }

    #[cfg(test)]
    pub(crate) fn rng(&self) -> u64 {
        self.rng
    }

    /// Returns the pacing granularity and horizon, which feed the send quantum and offload budget.
    #[cfg(test)]
    pub(crate) fn pacing_inputs(&self) -> (Duration, Duration) {
        (self.granularity, self.horizon)
    }

    #[cfg(test)]
    pub(crate) fn send_quantum(&self) -> u64 {
        self.send_quantum
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// Bounds cwnd again after a datagram size change, which may have left it below MinPipeCwnd
    /// for the new size.
    pub(super) fn on_max_datagram_size(&mut self) {
        self.bound_cwnd_to_window();
    }
}
