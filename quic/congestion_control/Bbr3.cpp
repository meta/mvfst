/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr3.h>

#include <folly/Random.h>
#include <folly/lang/Assume.h>
#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>

#include <algorithm>

namespace quic {

namespace {

constexpr float kStartupPacingGain = 2.77;
constexpr float kDefaultCwndGain = 2.0;
constexpr float kDrainPacingGain = 0.5;
constexpr float kProbeBwDownPacingGain = 0.9;
constexpr float kProbeBwCruisePacingGain = 1.0;
constexpr float kProbeBwRefillPacingGain = 1.0;
constexpr float kProbeBwUpPacingGain = 1.25;
constexpr float kProbeBwUpCwndGain = 2.25;
constexpr float kProbeRttPacingGain = 1.0;
constexpr float kProbeRttCwndGain = 0.5;

constexpr double kLossThresh = 0.02;
constexpr float kBeta = 0.7;
constexpr float kHeadroom = 0.15;
constexpr float kFullBwGrowth = 1.25;
constexpr uint64_t kFullBwRounds = 3;
constexpr uint64_t kStartupFullLossCount = 6;
// Like QUICHE, loss ends a bandwidth probe, or stops inflight_longterm from
// growing, only after two loss events in the round.
constexpr uint64_t kProbeBwFullLossCount = 2;
constexpr uint64_t kMaxDrainRounds = 3;

// WindowedFilter keeps a sample while its age is at most the window length, so
// a filter over N units uses a window length of N - 1.
constexpr uint64_t kMaxBwFilterLen = 2; // ProbeBW cycles
constexpr uint64_t kExtraAckedFilterLen = 10; // Round trips

constexpr std::chrono::microseconds kMinRttFilterLen = 10s;
constexpr std::chrono::microseconds kProbeRttDuration = 200ms;
constexpr std::chrono::microseconds kMinProbeWait = 2s;
constexpr uint32_t kProbeWaitJitterMs = 1000;
constexpr uint64_t kMaxRenoCoexistenceRounds = 63;
constexpr uint64_t kMaxProbeUpRounds = 30;

// Like bbr2, pacing has no margin. Like bbr2 and Linux, the offload budget is
// three send quanta.
constexpr uint8_t kPacingMarginPercent = 0;
constexpr uint64_t kOffloadBudgetSendQuanta = 3;
constexpr uint64_t kMaxSendQuantum = 64 * 1024;
// The pacer paces a window over an interval. It does not pace intervals shorter
// than its tick, paces at least a few packets per interval, and rounds the
// window down to whole packets. A window of this many packets keeps all three
// from changing the rate.
constexpr uint64_t kPacerWindowPackets = 64;

// Like QUICHE's IsInflightTooHigh(), loss is too high only after enough loss
// events. QUIC always has selective acknowledgments.
bool isInflightTooHigh(
    uint64_t lost,
    uint64_t txInFlight,
    uint64_t lossEvents,
    uint64_t minLossEvents) {
  return lossEvents >= minLossEvents &&
      static_cast<double>(lost) > static_cast<double>(txInFlight) * kLossThresh;
}

// InflightAtLoss(), where lost includes the lost packet. Like Linux, the prefix
// is empty when earlier losses already crossed the threshold.
uint64_t inflightAtLoss(const Bbr3LostPacketSample& lostPacket, uint64_t lost) {
  const auto size = lostPacket.size;
  const double inflightPrev =
      lostPacket.txInFlight > size ? lostPacket.txInFlight - size : 0;
  const double lostPrev = lost > size ? lost - size : 0;
  const double lostPrefix = std::max(
      0.0, (kLossThresh * inflightPrev - lostPrev) / (1 - kLossThresh));
  return static_cast<uint64_t>(inflightPrev + lostPrefix);
}

// An empty bound is infinite.
template <typename T>
Optional<T> maxBound(const Optional<T>& lhs, const Optional<T>& rhs) {
  if (!lhs || !rhs) {
    return std::nullopt;
  }
  return std::max(*lhs, *rhs);
}

} // namespace

Bbr3CongestionController::Bbr3CongestionController(
    QuicConnectionStateBase& conn)
    : Bbr3CongestionController(conn, [] { return folly::Random::rand32(); }) {}

Bbr3CongestionController::Bbr3CongestionController(
    QuicConnectionStateBase& conn,
    RandomFn random)
    : conn_(conn),
      random_(std::move(random)),
      sampler_(conn),
      maxBwFilter_(kMaxBwFilterLen - 1, Bandwidth(), 0),
      extraAckedFilter_(0, 0, 0),
      cwnd_(initialCwnd()),
      sendQuantum_(2 * conn.udpSendPacketLen),
      // Recovery, loss episodes and the app-limited mark start at the newest
      // send, which can come before a controller built mid-connection.
      lastSendTime_(
          conn.lossState.maybeLastPacketSentTime.value_or(TimePoint())) {
  MVCHECK(random_);
  // min_rtt starts empty, since mvfst can build the controller for a migrated
  // path before it resets the old path's SRTT.
  resetCongestionSignals();
  resetShortTermModel();
  resetFullBw();
  const auto srtt = conn_.lossState.srtt;
  initPacingRate(srtt != 0us ? srtt : 1ms);
  enterStartup();

  if (!conn_.pacer) {
    MVLOG_WARNING << "BBR3 was initialized on a connection without a pacer";
    return;
  }
  // The pacing gains set the whole pacing rate, so the pacer must not scale it.
  conn_.pacer->setRttFactor(1, 1);
  if (conn_.transportSettings.ccaConfig.paceInitCwnd) {
    applyPacingRate();
  } else {
    conn_.pacer->refreshPacingRate(cwnd_, 0us);
  }
}

void Bbr3CongestionController::onRemoveBytesFromInflight(
    uint64_t /* bytesToRemove */) {}

void Bbr3CongestionController::onPacketSent(
    const OutstandingPacketWrapper& packet) {
  sampler_.onPacketSent(packet);
  lastSendTime_ = packet.metadata.time;
  if (state_ == State::Startup || state_ == State::Drain) {
    uncappedSent_ = packet.metadata.totalBytesSent;
  }
  // Like QUICHE, a packet sent with nothing else in flight restarts from idle.
  // mvfst does not mark the connection app-limited when its data runs out with
  // the cwnd full.
  if (packet.metadata.inflightBytes == packet.metadata.encodedSize) {
    handleRestartFromIdle(packet.metadata.time);
  }
  // C.is_cwnd_limited. The transport rounds the writable bytes up to a whole
  // packet, so a cwnd-limited sender reaches the cwnd.
  if (packet.metadata.inflightBytes >= cwnd_) {
    cwndLimitedInRound_ = true;
  }
}

void Bbr3CongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  const bool undone = resolveLossEpisode(ackEvent, lossEvent);
  const bool hasLoss = lossEvent && lossEvent->lostPackets > 0;
  const bool hasNewAck = ackEvent && ackEvent->largestNewlyAckedPacket;
  if (!hasLoss && !hasNewAck) {
    if (undone) {
      logState();
    }
    return;
  }

  const auto now = ackEvent ? ackEvent->ackTime : lossEvent->lossTime;
  const auto priorInflight = conn_.lossState.inflightBytes +
      (ackEvent ? ackEvent->ackedBytes : 0) +
      (hasLoss ? lossEvent->lostBytes : 0);
  if (hasLoss) {
    onLoss(*lossEvent, now);
  }
  if (ackEvent && !ackEvent->implicit) {
    onAck(*ackEvent, now, priorInflight);
  } else {
    // Implicit ACKs and loss-only events do not update the model, but a loss
    // response can still change the pacing rate and the cwnd bounds.
    updateControlParameters(Bbr3RateSample{});
  }
  logState();
}

uint64_t Bbr3CongestionController::getWritableBytes() const noexcept {
  return cwnd_ > conn_.lossState.inflightBytes
      ? cwnd_ - conn_.lossState.inflightBytes
      : 0;
}

uint64_t Bbr3CongestionController::getCongestionWindow() const noexcept {
  return cwnd_;
}

CongestionControlType Bbr3CongestionController::type() const noexcept {
  return CongestionControlType::BBR3;
}

bool Bbr3CongestionController::isAppLimited() const {
  return appLimited_;
}

Optional<Bandwidth> Bbr3CongestionController::getBandwidth() const {
  return bw_;
}

uint64_t Bbr3CongestionController::getBDP() const {
  return bdp();
}

void Bbr3CongestionController::setAppLimited() noexcept {
  markAppLimited();
  QLOG(conn_, addAppLimitedUpdate);
}

void Bbr3CongestionController::getStats(
    CongestionControllerStats& stats) const {
  stats.bbr2Stats.state = static_cast<uint8_t>(state_);
}

Bbr3CongestionController::State Bbr3CongestionController::getState()
    const noexcept {
  return state_;
}

void Bbr3CongestionController::onLoss(
    const LossEvent& lossEvent,
    TimePoint now) {
  updateLossEpisode(lossEvent);
  if (!inRecovery_) {
    saveCwnd();
    inRecovery_ = true;
  }
  // Like bbr2, each loss extends recovery. Recovery ends once a packet sent
  // after the loss is acknowledged. The ACK time can come from the socket's
  // receive timestamp, so the boundary is the newest send time.
  recoveryStart_ = lastSendTime_;
  // The transport lists lost packets in send order. InflightAtLoss() depends on
  // that, since it treats the round's earlier losses as sent before this one.
  const auto space =
      lossEvent.packetNumberSpace.value_or(PacketNumberSpace::AppData);
  for (const auto& lostPacket : lossEvent.lostPacketDetails) {
    handleLostPacket(lostPacket, space, now);
  }
  if (lossEvent.persistentCongestion) {
    onPersistentCongestion();
  }
}

void Bbr3CongestionController::onAck(
    const AckEvent& ackEvent,
    TimePoint now,
    uint64_t priorInflight) {
  if (appLimited_ && appLimitedMark_ &&
      *appLimitedMark_ <= ackEvent.largestNewlyAckedPacketSentTime) {
    appLimited_ = false;
    QLOG(conn_, addAppUnlimitedUpdate);
  }
  const auto rs = sampler_.onAck(ackEvent, appLimitedMark_);
  updateModelAndState(rs, now, priorInflight);
  // In QUIC, the ACK that ends recovery also ends the loss round, and the
  // Startup loss exit checks for recovery at the end of the loss round.
  updateRecoveryOnAck(ackEvent);
  updateControlParameters(rs);
  if (roundStart_) {
    cwndLimitedInRound_ = false;
  }
}

void Bbr3CongestionController::handleLostPacket(
    const LossEvent::LostPacket& lostPacket,
    PacketNumberSpace space,
    TimePoint now) {
  // NoteLoss(). The other undo values are saved per loss episode.
  if (!isLossInRound_) {
    lossRoundDelivered_ = conn_.lossState.totalBytesAcked;
    saveCwnd();
  }
  isLossInRound_ = true;
  lostRangesInLossRound_.add(space, lostPacket.packetNum);
  lostRangesInRound_.add(space, lostPacket.packetNum);
  bytesLostInRound_ += lostPacket.encodedSize;

  // The draft's prose sets a loss rate per round trip. Like bbr2 and QUICHE,
  // this check counts the bytes lost in the current round. The pseudocode
  // counts the bytes lost since the packet was sent, which spans a full flight
  // at every loss and so trips more often on random loss.
  const auto sample = sampler_.onPacketLost(lostPacket, space, checkProbeLoss_);
  if (!sample ||
      !isInflightTooHigh(
          bytesLostInRound_,
          sample->txInFlight,
          lostRangesInRound_.count,
          kProbeBwFullLossCount)) {
    return;
  }
  handleInflightTooHigh(
      inflightAtLoss(*sample, bytesLostInRound_), sample->isAppLimited, now);
}

void Bbr3CongestionController::LostRangeCounter::add(
    PacketNumberSpace space,
    PacketNum packetNum) {
  auto& spaceLargest = largest[space];
  if (!spaceLargest || packetNum > *spaceLargest + 1) {
    ++count;
  }
  spaceLargest = std::max(packetNum, spaceLargest.value_or(0));
}

void Bbr3CongestionController::LostRangeCounter::reset() {
  count = 0;
  largest = {};
}

void Bbr3CongestionController::onPersistentCongestion() {
  saveCwnd();
  resetFullBw();
  // Like Linux, keep the cwnd from before the collapse for the next lower
  // bound update.
  if (!isProbingBw() && !inflightShortTerm_) {
    inflightShortTerm_ = std::max(cwnd_, priorCwnd_);
  }
  // QUIC's persistent congestion stands in for TCP's RTO. Like bbr2, the cwnd
  // drops to BBR's minimum, and leaving recovery restores the saved cwnd, as
  // the draft does when TCP leaves RTO recovery.
  cwnd_ = minPipeCwnd();
}

void Bbr3CongestionController::updateRecoveryOnAck(const AckEvent& ackEvent) {
  if (inRecovery_ &&
      ackEvent.largestNewlyAckedPacketSentTime > recoveryStart_) {
    inRecovery_ = false;
    restoreCwnd();
  }
}

void Bbr3CongestionController::updateLossEpisode(const LossEvent& lossEvent) {
  if (!conn_.transportSettings.ccaConfig.enableSpuriousLossRecovery ||
      lossEvent.persistentCongestion) {
    lossEpisode_.reset();
    return;
  }
  // Losses of packets sent before the episode started belong to it.
  if (lossEpisode_ && lossEvent.largestLostSentTime &&
      *lossEvent.largestLostSentTime <= lossEpisode_->start) {
    lossEpisode_->pendingLostPackets += lossEvent.lostPackets;
    return;
  }
  lossEpisode_.reset();
  // An episode is only undone as a whole, so it cannot start while older
  // losses or their recovery are still pending.
  if (conn_.outstandings.declaredLostCount != lossEvent.lostPackets ||
      inRecovery_ || isLossInRound_) {
    return;
  }
  saveCwnd();
  lossEpisode_ = LossEpisode{
      .priorCwnd = priorCwnd_,
      .bwShortTerm = bwShortTerm_,
      .inflightShortTerm = inflightShortTerm_,
      .inflightLongTerm = inflightLongTerm_,
      .pendingLostPackets = lossEvent.lostPackets,
      .start = lastSendTime_,
  };
}

bool Bbr3CongestionController::resolveLossEpisode(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  if (!conn_.transportSettings.ccaConfig.enableSpuriousLossRecovery) {
    lossEpisode_.reset();
    return false;
  }
  if (!lossEpisode_) {
    return false;
  }
  // The transport has already removed this ACK's spurious losses from the
  // declared-lost count and added this event's new losses. Any other change,
  // such as old lost packets being dropped, ends the episode.
  const uint64_t spuriouslyAcked =
      ackEvent ? ackEvent->numPacketsSpuriouslyAcked : 0;
  const uint64_t newlyLost = lossEvent ? lossEvent->lostPackets : 0;
  const auto declaredLost = conn_.outstandings.declaredLostCount;
  auto& pending = lossEpisode_->pendingLostPackets;
  if (spuriouslyAcked > pending || newlyLost > declaredLost ||
      pending - spuriouslyAcked != declaredLost - newlyLost) {
    lossEpisode_.reset();
    return false;
  }
  pending -= spuriouslyAcked;
  if (pending != 0) {
    return false;
  }
  const auto episode = *lossEpisode_;
  lossEpisode_.reset();
  handleSpuriousLossDetection(episode);
  return true;
}

void Bbr3CongestionController::handleSpuriousLossDetection(
    const LossEpisode& episode) {
  cwnd_ = std::max(cwnd_, episode.priorCwnd);
  inRecovery_ = false;
  isLossInRound_ = false;
  lostRangesInLossRound_.reset();
  bytesLostInRound_ = 0;
  lostRangesInRound_.reset();
  resetFullBw();
  bwShortTerm_ = maxBound(bwShortTerm_, episode.bwShortTerm);
  inflightShortTerm_ = maxBound(inflightShortTerm_, episode.inflightShortTerm);
  const auto inflightLongTerm =
      maxBound(inflightLongTerm_, episode.inflightLongTerm);
  if (inflightLongTerm != inflightLongTerm_) {
    uncappedSent_.reset();
  }
  inflightLongTerm_ = inflightLongTerm;
  if (episode.undoTarget == UndoTarget::Startup && state_ != State::Startup) {
    fullBwReached_ = false;
    // Only ProbeBW responds to individual lost packets.
    checkProbeLoss_ = false;
    if (state_ != State::ProbeRtt) {
      enterStartup();
    }
  } else if (
      episode.undoTarget == UndoTarget::ProbeBwUp &&
      state_ != State::ProbeBwUp && state_ != State::ProbeRtt) {
    startProbeBwRefill();
  }
  boundBwForModel();
  setPacingRateWithGain(pacingGain_);
  applyPacingRate();
  setSendQuantum();
  boundCwnd();
}

void Bbr3CongestionController::handleRestartFromIdle(TimePoint now) {
  idleRestart_ = true;
  extraAckedIntervalStart_ = now;
  // Like Linux, also restart the ACK aggregation count, which otherwise
  // carries data delivered before the idle period into the new interval.
  extraAckedDelivered_ = 0;
  if (isInProbeBwState()) {
    setPacingRateWithGain(1.0);
    applyPacingRate();
  } else if (state_ == State::ProbeRtt) {
    checkProbeRttDone(now);
  }
}

void Bbr3CongestionController::markAppLimited() {
  appLimited_ = true;
  // Packets sent after the latest send are past the mark.
  appLimitedMark_ = lastSendTime_ + 1us;
}

void Bbr3CongestionController::updateModelAndState(
    const Bbr3RateSample& rs,
    TimePoint now,
    uint64_t priorInflight) {
  updateLatestDeliverySignals(rs);
  updateCongestionSignals(rs);
  updateAckAggregation(rs, now);
  checkFullBwReached(rs);
  checkStartupDone(rs);
  checkDrainDone(now);
  updateProbeBwCyclePhase(rs, now, priorInflight);
  updateMinRtt(rs, now);
  checkProbeRtt(rs, now);
  advanceLatestDeliverySignals(rs);
  boundBwForModel();
}

void Bbr3CongestionController::updateControlParameters(
    const Bbr3RateSample& rs) {
  setPacingRateWithGain(pacingGain_);
  applyPacingRate();
  setSendQuantum();
  setCwnd(rs.newlyAcked);
}

void Bbr3CongestionController::updateLatestDeliverySignals(
    const Bbr3RateSample& rs) {
  lossRoundStart_ = false;
  bwLatest_ = std::max(bwLatest_, rs.deliveryRate);
  inflightLatest_ = std::max(inflightLatest_, rs.delivered);
  if (rs.hasData && rs.priorDelivered >= lossRoundDelivered_) {
    lossRoundDelivered_ = conn_.lossState.totalBytesAcked;
    lossRoundStart_ = true;
  }
}

void Bbr3CongestionController::updateCongestionSignals(
    const Bbr3RateSample& rs) {
  updateMaxBw(rs);
  if (!lossRoundStart_) {
    return;
  }
  adaptLowerBoundsFromCongestion();
  isLossInRound_ = false;
}

void Bbr3CongestionController::updateMaxBw(const Bbr3RateSample& rs) {
  updateRound(rs);
  // As the draft's prose says, an app-limited sample enters the filter only if
  // it is larger than max_bw.
  if (rs.deliveryRate &&
      (rs.deliveryRate > maxBwFilter_.GetBest() || !rs.isAppLimited)) {
    maxBwFilter_.Update(rs.deliveryRate, cycleCount_);
  }
}

void Bbr3CongestionController::updateRound(const Bbr3RateSample& rs) {
  if (rs.hasData && rs.priorDelivered >= nextRoundDelivered_) {
    startRound();
    ++roundCount_;
    ++roundsSinceProbeUp_;
    roundStart_ = true;
  } else {
    roundStart_ = false;
  }
}

void Bbr3CongestionController::startRound() {
  nextRoundDelivered_ = conn_.lossState.totalBytesAcked;
  bytesLostInRound_ = 0;
  lostRangesInRound_.reset();
}

void Bbr3CongestionController::adaptLowerBoundsFromCongestion() {
  if (isProbingBw() || !isLossInRound_) {
    return;
  }
  if (!bwShortTerm_) {
    bwShortTerm_ = maxBwFilter_.GetBest();
  }
  if (!inflightShortTerm_) {
    inflightShortTerm_ = cwnd_;
  }
  bwShortTerm_ = std::max(bwLatest_, *bwShortTerm_ * kBeta);
  inflightShortTerm_ = std::max(
      inflightLatest_, static_cast<uint64_t>(*inflightShortTerm_ * kBeta));
}

void Bbr3CongestionController::advanceLatestDeliverySignals(
    const Bbr3RateSample& rs) {
  if (!lossRoundStart_) {
    return;
  }
  bwLatest_ = rs.deliveryRate;
  inflightLatest_ = rs.delivered;
  lostRangesInLossRound_.reset();
}

void Bbr3CongestionController::resetCongestionSignals() {
  isLossInRound_ = false;
  lostRangesInLossRound_.reset();
  bwLatest_ = Bandwidth();
  inflightLatest_ = 0;
}

void Bbr3CongestionController::resetShortTermModel() {
  bwShortTerm_.reset();
  inflightShortTerm_.reset();
}

void Bbr3CongestionController::boundBwForModel() {
  const auto previousBw = bw_;
  bw_ = maxBwFilter_.GetBest();
  if (bwShortTerm_ && !conn_.transportSettings.ccaConfig.ignoreShortTerm) {
    bw_ = std::min(bw_, *bwShortTerm_);
  }
  if (bw_ != previousBw) {
    QLOG(conn_, addBandwidthEstUpdate, bw_.units, bw_.interval);
  }
}

void Bbr3CongestionController::updateAckAggregation(
    const Bbr3RateSample& rs,
    TimePoint now) {
  if (!extraAckedIntervalStart_) {
    extraAckedIntervalStart_ = now;
  }
  const auto interval = now > *extraAckedIntervalStart_
      ? std::chrono::duration_cast<std::chrono::microseconds>(
            now - *extraAckedIntervalStart_)
      : 0us;
  uint64_t expectedDelivered = bw_ * interval;
  if (extraAckedDelivered_ <= expectedDelivered) {
    extraAckedDelivered_ = 0;
    extraAckedIntervalStart_ = now;
    expectedDelivered = 0;
  }
  extraAckedDelivered_ += rs.newlyAcked;
  const auto extra = std::min(extraAckedDelivered_ - expectedDelivered, cwnd_);
  // In Startup, the filter holds only the current round's samples.
  extraAckedFilter_.SetWindowLength(
      fullBwReached_ ? kExtraAckedFilterLen - 1 : 0);
  extraAckedFilter_.Update(extra, roundCount_);
}

void Bbr3CongestionController::checkFullBwReached(const Bbr3RateSample& rs) {
  if (fullBwNow_ || !roundStart_ || rs.isAppLimited) {
    return;
  }
  // Like bbr2 and QUICHE, the plateau check uses max_bw, which is steadier
  // than a single delivery rate sample.
  const auto maxBw = maxBwFilter_.GetBest();
  if (maxBw >= fullBw_ * kFullBwGrowth) {
    resetFullBw();
    fullBw_ = maxBw;
    return;
  }
  ++fullBwCount_;
  fullBwNow_ = fullBwCount_ >= kFullBwRounds;
  if (fullBwNow_) {
    fullBwReached_ = true;
  }
}

void Bbr3CongestionController::resetFullBw() {
  fullBw_ = Bandwidth();
  fullBwCount_ = 0;
  fullBwNow_ = false;
}

void Bbr3CongestionController::checkStartupDone(const Bbr3RateSample& rs) {
  checkStartupHighLoss(rs);
  if (state_ == State::Startup && fullBwReached_) {
    enterDrain();
  }
}

void Bbr3CongestionController::checkStartupHighLoss(const Bbr3RateSample& rs) {
  if (!conn_.transportSettings.ccaConfig.exitStartupOnLoss || fullBwReached_ ||
      !lossRoundStart_ || !inRecovery_) {
    return;
  }
  if (!isInflightTooHigh(
          rs.lost,
          rs.txInFlight,
          lostRangesInLossRound_.count,
          kStartupFullLossCount)) {
    return;
  }
  if (lossEpisode_) {
    lossEpisode_->undoTarget = UndoTarget::Startup;
  }
  fullBwReached_ = true;
  inflightLongTerm_ = std::max(bdp(), inflightLatest_);
}

void Bbr3CongestionController::enterStartup() {
  state_ = State::Startup;
  setGains(kStartupPacingGain, kDefaultCwndGain);
}

void Bbr3CongestionController::enterDrain() {
  state_ = State::Drain;
  setGains(kDrainPacingGain, kDefaultCwndGain);
  // Like QUICHE and Linux, Drain lasts at most kMaxDrainRounds full rounds. A
  // round that is already under way does not count.
  drainStartRound_ = roundStart_ ? roundCount_ : roundCount_ + 1;
}

void Bbr3CongestionController::checkDrainDone(TimePoint now) {
  if (state_ != State::Drain) {
    return;
  }
  if (conn_.lossState.inflightBytes <= inflightWithGain(bw_, 1.0) ||
      roundCount_ >= drainStartRound_ + kMaxDrainRounds) {
    enterProbeBw(now);
  }
}

void Bbr3CongestionController::enterProbeBw(TimePoint now) {
  startProbeBwDown(now);
}

void Bbr3CongestionController::updateProbeBwCyclePhase(
    const Bbr3RateSample& rs,
    TimePoint now,
    uint64_t priorInflight) {
  if (!fullBwReached_ || adaptLongTermModel(rs)) {
    return;
  }
  switch (state_) {
    case State::ProbeBwDown:
      if (!isTimeToProbeBw(now) && isTimeToCruise()) {
        startProbeBwCruise();
      }
      break;
    case State::ProbeBwCruise:
      isTimeToProbeBw(now);
      break;
    case State::ProbeBwRefill:
      if (roundStart_) {
        checkProbeLoss_ = true;
        startProbeBwUp();
      }
      break;
    case State::ProbeBwUp:
      if (isTimeToGoDown(priorInflight)) {
        prevProbeTooHigh_ = false;
        startProbeBwDown(now);
      }
      break;
    case State::Startup:
    case State::Drain:
    case State::ProbeRtt:
      break;
  }
}

bool Bbr3CongestionController::adaptLongTermModel(const Bbr3RateSample& rs) {
  if (isBwProbeStopping_ && roundStart_) {
    // The samples from the bandwidth probe have ended.
    checkProbeLoss_ = false;
    isBwProbeStopping_ = false;
    if (isInProbeBwState() && !rs.isAppLimited) {
      ++cycleCount_;
    }
    // Precautionary acceleration.
    if (isInProbeBwState() && prevProbePrecautionary_ && !prevProbeTooHigh_) {
      startProbeBwRefill();
      return true;
    }
  }
  // Like QUICHE, inflight_longterm does not grow in Drain, since it does not
  // cap Drain's cwnd. It also does not grow from packets that it did not cap.
  // Entering DOWN restarts the round's loss count, so the count cannot block
  // those samples.
  if (state_ == State::Drain ||
      (uncappedSent_ && rs.totalSent <= *uncappedSent_) ||
      isInflightTooHigh(
          rs.lost,
          rs.txInFlight,
          lostRangesInRound_.count,
          kProbeBwFullLossCount) ||
      !inflightLongTerm_) {
    return false;
  }
  if (rs.txInFlight > *inflightLongTerm_) {
    inflightLongTerm_ = rs.txInFlight;
  }
  if (state_ == State::ProbeBwUp) {
    probeInflightLongTermUpward(rs);
  }
  return false;
}

void Bbr3CongestionController::startProbeBwDown(TimePoint now) {
  resetCongestionSignals();
  probeUpAckedPerInc_ = std::numeric_limits<uint64_t>::max();
  pickProbeWait();
  cycleStamp_ = now;
  isBwProbeStopping_ = true;
  startRound();
  state_ = State::ProbeBwDown;
  setGains(kProbeBwDownPacingGain, kDefaultCwndGain);
}

void Bbr3CongestionController::startProbeBwCruise() {
  state_ = State::ProbeBwCruise;
  setGains(kProbeBwCruisePacingGain, kDefaultCwndGain);
}

void Bbr3CongestionController::startProbeBwRefill() {
  resetShortTermModel();
  bwProbeUpRounds_ = 0;
  bwProbeUpAcked_ = 0;
  prevProbePrecautionary_ = false;
  isBwProbeStopping_ = false;
  startRound();
  state_ = State::ProbeBwRefill;
  setGains(kProbeBwRefillPacingGain, kDefaultCwndGain);
}

void Bbr3CongestionController::startProbeBwUp() {
  startRound();
  resetFullBw();
  fullBw_ = maxBwFilter_.GetBest();
  state_ = State::ProbeBwUp;
  setGains(kProbeBwUpPacingGain, kProbeBwUpCwndGain);
  raiseInflightLongTermSlope();
}

bool Bbr3CongestionController::isTimeToProbeBw(TimePoint now) {
  if (now > cycleStamp_ + bwProbeWait_ || isRenoCoexistenceProbeTime()) {
    startProbeBwRefill();
    return true;
  }
  return false;
}

bool Bbr3CongestionController::isTimeToCruise() const {
  const auto inflight = conn_.lossState.inflightBytes;
  return inflight <= inflightWithHeadroom() &&
      inflight <= inflightWithGain(maxBwFilter_.GetBest(), 1.0);
}

bool Bbr3CongestionController::isTimeToGoDown(uint64_t priorInflight) {
  // Precautionary deceleration. Like Linux, this uses the bytes in flight
  // before the ACK. inflight_longterm caps the cwnd, so the bytes in flight
  // after the ACK cannot reach it.
  if (conn_.transportSettings.ccaConfig.enablePrecautionaryBandwidthProbing &&
      prevProbeTooHigh_ && inflightLongTerm_ &&
      priorInflight >= *inflightLongTerm_) {
    prevProbePrecautionary_ = true;
    return true;
  }
  if (cwndLimitedInRound_ && inflightLongTerm_ && cwnd_ >= *inflightLongTerm_) {
    // inflight_longterm limits the bandwidth.
    resetFullBw();
    fullBw_ = maxBwFilter_.GetBest();
    return false;
  }
  return fullBwNow_;
}

void Bbr3CongestionController::pickProbeWait() {
  roundsSinceProbeUp_ = random_() % 2;
  bwProbeWait_ =
      kMinProbeWait + std::chrono::milliseconds(random_() % kProbeWaitJitterMs);
}

bool Bbr3CongestionController::isRenoCoexistenceProbeTime() const {
  if (!conn_.transportSettings.ccaConfig.enableRenoCoexistence) {
    return false;
  }
  // A Reno flow grows its cwnd by one packet per round. Like Linux, the target
  // includes the quantization budget, so a BDP below one packet still waits a
  // few rounds.
  const auto renoRounds =
      std::min(inflightWithGain(bw_, 1.0), cwnd_) / conn_.udpSendPacketLen;
  return roundsSinceProbeUp_ >= std::min(renoRounds, kMaxRenoCoexistenceRounds);
}

void Bbr3CongestionController::raiseInflightLongTermSlope() {
  const auto growthThisRound = uint64_t{1} << bwProbeUpRounds_;
  bwProbeUpRounds_ = std::min(bwProbeUpRounds_ + 1, kMaxProbeUpRounds);
  probeUpAckedPerInc_ =
      std::max(cwnd_ / growthThisRound, uint64_t{conn_.udpSendPacketLen});
}

void Bbr3CongestionController::probeInflightLongTermUpward(
    const Bbr3RateSample& rs) {
  if (!cwndLimitedInRound_ || !inflightLongTerm_ ||
      cwnd_ < *inflightLongTerm_) {
    return;
  }
  bwProbeUpAcked_ += rs.newlyAcked;
  if (bwProbeUpAcked_ >= probeUpAckedPerInc_) {
    const auto delta = bwProbeUpAcked_ / probeUpAckedPerInc_;
    bwProbeUpAcked_ -= delta * probeUpAckedPerInc_;
    inflightLongTerm_ = std::min(
        *inflightLongTerm_ + delta * conn_.udpSendPacketLen,
        conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen);
  }
  if (roundStart_) {
    raiseInflightLongTermSlope();
  }
}

void Bbr3CongestionController::handleInflightTooHigh(
    uint64_t txInFlight,
    bool isAppLimited,
    TimePoint now) {
  prevProbeTooHigh_ = true;
  checkProbeLoss_ = false;
  if (!isAppLimited) {
    inflightLongTerm_ =
        std::max(txInFlight, static_cast<uint64_t>(targetInflight() * kBeta));
    uncappedSent_ = conn_.lossState.totalBytesSent;
  }
  if (state_ == State::ProbeBwUp) {
    if (lossEpisode_) {
      lossEpisode_->undoTarget = UndoTarget::ProbeBwUp;
    }
    startProbeBwDown(now);
  }
}

void Bbr3CongestionController::updateMinRtt(
    const Bbr3RateSample& rs,
    TimePoint now) {
  if (!minRttStamp_) {
    minRttStamp_ = now;
  }
  minRttExpired_ = now > *minRttStamp_ + kMinRttFilterLen;
  if (minRttExpired_) {
    probeRttCwnd_ = bdpMultiple(bw_, kProbeRttCwndGain);
  }
  if (rs.rtt && (!minRtt_ || *rs.rtt < *minRtt_ || minRttExpired_)) {
    minRtt_ = *rs.rtt;
    minRttStamp_ = now;
  }
}

void Bbr3CongestionController::checkProbeRtt(
    const Bbr3RateSample& rs,
    TimePoint now) {
  if (state_ != State::ProbeRtt && minRttExpired_ && !idleRestart_) {
    saveCwnd();
    state_ = State::ProbeRtt;
    setGains(kProbeRttPacingGain, kProbeRttCwndGain);
    probeRttDoneStamp_.reset();
    isBwProbeStopping_ = true;
    startRound();
  }
  if (state_ == State::ProbeRtt) {
    handleProbeRtt(now);
  }
  if (rs.delivered > 0) {
    idleRestart_ = false;
  }
}

void Bbr3CongestionController::handleProbeRtt(TimePoint now) {
  // Rate samples taken during ProbeRTT are app-limited.
  markAppLimited();
  if (!probeRttDoneStamp_ && conn_.lossState.inflightBytes <= probeRttCwnd()) {
    probeRttDoneStamp_ = now + kProbeRttDuration;
    probeRttRoundDone_ = false;
    startRound();
  } else if (probeRttDoneStamp_) {
    if (roundStart_) {
      probeRttRoundDone_ = true;
    }
    if (probeRttRoundDone_) {
      checkProbeRttDone(now);
    }
  }
}

void Bbr3CongestionController::checkProbeRttDone(TimePoint now) {
  if (probeRttDoneStamp_ && now > *probeRttDoneStamp_) {
    // Schedule the next ProbeRTT.
    minRttStamp_ = now;
    restoreCwnd();
    exitProbeRtt(now);
  }
}

void Bbr3CongestionController::exitProbeRtt(TimePoint now) {
  resetShortTermModel();
  if (fullBwReached_) {
    startProbeBwDown(now);
    startProbeBwCruise();
  } else {
    enterStartup();
  }
}

uint64_t Bbr3CongestionController::probeRttCwnd() const {
  auto cwnd = bdpMultiple(bw_, kProbeRttCwndGain);
  if (probeRttCwnd_) {
    cwnd = std::min(cwnd, *probeRttCwnd_);
  }
  return std::max(cwnd, minPipeCwnd());
}

void Bbr3CongestionController::initPacingRate(std::chrono::microseconds rtt) {
  pacingRate_ = Bandwidth(initialCwnd(), rtt) * kStartupPacingGain;
}

void Bbr3CongestionController::setPacingRateWithGain(float pacingGain) {
  // The initial pacing rate is set again from the first RTT sample this
  // controller takes. The SRTT it started from can belong to an earlier path,
  // and a rate that is too high would stay until the bandwidth estimate caught
  // up with it.
  if (!hasSeenRtt_ && minRtt_) {
    hasSeenRtt_ = true;
    initPacingRate(*minRtt_);
  }
  const auto rate = bw_ * (pacingGain * (100 - kPacingMarginPercent) / 100);
  if (fullBwReached_ || rate > pacingRate_) {
    pacingRate_ = rate;
  }
}

void Bbr3CongestionController::applyPacingRate() {
  if (!conn_.pacer) {
    return;
  }
  // Like bbr2, the initial window goes out unpaced unless paceInitCwnd is set.
  if (!conn_.transportSettings.ccaConfig.paceInitCwnd &&
      conn_.lossState.totalBytesSent < initialCwnd()) {
    return;
  }
  const auto bytesPerSecond = pacingRate_.normalize();
  if (bytesPerSecond == 0) {
    return;
  }
  const uint64_t windowBytes = kPacerWindowPackets * conn_.udpSendPacketLen;
  const auto windowInterval = std::chrono::microseconds(
      (windowBytes * 1'000'000 + bytesPerSecond - 1) / bytesPerSecond);
  const auto interval =
      std::max(windowInterval, conn_.transportSettings.pacingTickInterval);
  // Another controller type can change the shared pacer's factor, for example
  // before a migration back restores this controller.
  conn_.pacer->setRttFactor(1, 1);
  conn_.pacer->refreshPacingRate(pacingRate_ * interval, interval);
}

void Bbr3CongestionController::setSendQuantum() {
  // The quantum covers one pacer tick, 1ms by default as in the draft.
  const uint64_t quantum =
      pacingRate_ * conn_.transportSettings.pacingTickInterval;
  sendQuantum_ =
      std::max(std::min(quantum, kMaxSendQuantum), 2 * conn_.udpSendPacketLen);
}

void Bbr3CongestionController::setCwnd(uint64_t newlyAcked) {
  const auto maxInflightBytes = maxInflight();
  if (fullBwReached_) {
    cwnd_ = std::min(cwnd_ + newlyAcked, maxInflightBytes);
  } else if (
      cwnd_ < maxInflightBytes ||
      conn_.lossState.totalBytesAcked < initialCwnd()) {
    cwnd_ += newlyAcked;
  }
  boundCwnd();
}

void Bbr3CongestionController::boundCwnd() {
  cwnd_ = std::max(cwnd_, minPipeCwnd());
  if (state_ == State::ProbeRtt) {
    cwnd_ = std::min(cwnd_, probeRttCwnd());
  }

  const auto& ccaConfig = conn_.transportSettings.ccaConfig;
  auto cap = std::numeric_limits<uint64_t>::max();
  if (!ccaConfig.ignoreInflightLongTerm) {
    if (isInProbeBwState() && state_ != State::ProbeBwCruise) {
      cap = inflightLongTerm_.value_or(cap);
    } else if (state_ == State::ProbeRtt || state_ == State::ProbeBwCruise) {
      cap = inflightWithHeadroom();
    }
  }
  if (inflightShortTerm_ && !ccaConfig.ignoreShortTerm) {
    cap = std::min(cap, *inflightShortTerm_);
  }
  cwnd_ = std::min(cwnd_, std::max(cap, minPipeCwnd()));
  cwnd_ = boundedCwnd(
      cwnd_,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      kMinCwndInMssForBbr);
}

void Bbr3CongestionController::saveCwnd() {
  if (!inRecovery_ && state_ != State::ProbeRtt) {
    priorCwnd_ = cwnd_;
  } else {
    priorCwnd_ = std::max(priorCwnd_, cwnd_);
  }
}

void Bbr3CongestionController::restoreCwnd() {
  cwnd_ = std::max(cwnd_, priorCwnd_);
}

uint64_t Bbr3CongestionController::bdpMultiple(Bandwidth bw, float gain) const {
  if (!minRtt_) {
    return initialCwnd();
  }
  return static_cast<uint64_t>(
      static_cast<double>(gain) * static_cast<double>(bw * *minRtt_));
}

uint64_t Bbr3CongestionController::bdp() const {
  return bdpMultiple(bw_, 1.0);
}

uint64_t Bbr3CongestionController::targetInflight() const {
  return std::min(bdp(), cwnd_);
}

uint64_t Bbr3CongestionController::inflightWithGain(Bandwidth bw, float gain)
    const {
  return quantizationBudget(bdpMultiple(bw, gain));
}

uint64_t Bbr3CongestionController::inflightWithHeadroom() const {
  if (!inflightLongTerm_) {
    return std::numeric_limits<uint64_t>::max();
  }
  const auto headroom = std::max<uint64_t>(
      conn_.udpSendPacketLen,
      static_cast<uint64_t>(kHeadroom * *inflightLongTerm_));
  const auto withHeadroom =
      *inflightLongTerm_ > headroom ? *inflightLongTerm_ - headroom : 0;
  return std::max(withHeadroom, minPipeCwnd());
}

uint64_t Bbr3CongestionController::quantizationBudget(
    uint64_t inflightCap) const {
  inflightCap = std::max(inflightCap, kOffloadBudgetSendQuanta * sendQuantum_);
  inflightCap = std::max(inflightCap, minPipeCwnd());
  if (state_ == State::ProbeBwUp) {
    inflightCap += 2 * conn_.udpSendPacketLen;
  }
  return inflightCap;
}

uint64_t Bbr3CongestionController::maxInflight() const {
  auto inflightCap = bdpMultiple(bw_, cwndGain_);
  if (fullBwReached_ ||
      conn_.transportSettings.ccaConfig.enableAckAggregationInStartup) {
    inflightCap += extraAckedFilter_.GetBest();
  }
  return quantizationBudget(inflightCap);
}

bool Bbr3CongestionController::isInProbeBwState() const {
  return state_ == State::ProbeBwDown || state_ == State::ProbeBwCruise ||
      state_ == State::ProbeBwRefill || state_ == State::ProbeBwUp;
}

bool Bbr3CongestionController::isProbingBw() const {
  return state_ == State::Startup || state_ == State::ProbeBwRefill ||
      state_ == State::ProbeBwUp;
}

uint64_t Bbr3CongestionController::initialCwnd() const {
  return conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen;
}

uint64_t Bbr3CongestionController::minPipeCwnd() const {
  return kMinCwndInMssForBbr * conn_.udpSendPacketLen;
}

void Bbr3CongestionController::setGains(float pacingGain, float cwndGain) {
  pacingGain_ = pacingGain;
  cwndGain_ = cwndGain;
}

void Bbr3CongestionController::logState() const {
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      cwnd_,
      conn_.lossState.inflightBytes,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      conn_.lossState.ptoCount);
  QLOG(
      conn_,
      addCongestionStateUpdate,
      std::nullopt,
      bbr3StateToString(state_),
      kCongestionPacketAck);
  QLOG(
      conn_,
      addNetworkPathModelUpdate,
      inflightLongTerm_.value_or(0),
      inflightShortTerm_.value_or(0),
      0,
      std::chrono::microseconds(1),
      bwShortTerm_ ? bwShortTerm_->units : 0,
      bwShortTerm_ ? bwShortTerm_->interval : std::chrono::microseconds(1));
  MVVLOG(6) << "BBR3 state=" << bbr3StateToString(state_)
            << " inflight=" << conn_.lossState.inflightBytes
            << " cwnd=" << cwnd_ << " bw=" << bw_.normalizedDescribe();
}

std::string bbr3StateToString(Bbr3CongestionController::State state) {
  switch (state) {
    case Bbr3CongestionController::State::Startup:
      return "Startup";
    case Bbr3CongestionController::State::Drain:
      return "Drain";
    case Bbr3CongestionController::State::ProbeBwDown:
      return "ProbeBw_Down";
    case Bbr3CongestionController::State::ProbeBwCruise:
      return "ProbeBw_Cruise";
    case Bbr3CongestionController::State::ProbeBwRefill:
      return "ProbeBw_Refill";
    case Bbr3CongestionController::State::ProbeBwUp:
      return "ProbeBw_Up";
    case Bbr3CongestionController::State::ProbeRtt:
      return "ProbeRTT";
  }
  folly::assume_unreachable();
}

} // namespace quic
