/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/C4.h>

#include <folly/lang/Assume.h>
#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>

#include <algorithm>
#include <cmath>

namespace quic {

namespace {

constexpr float kInitialGain = 2.0;
constexpr float kRecoveryGain = 15.0 / 16;
constexpr float kDeepRecoveryGain = 7.0 / 8;
constexpr float kDrainGain = 3.0 / 4;
constexpr float kCruiseGain = 1.0;
// Added to the Cruising gain below 1 ms of RTT, where late pacer wakeups keep
// the send rate under the pacing rate.
constexpr float kLowRttCruiseBoost = 3.0 / 64;
constexpr float kProbeGain = 17.0 / 16;
constexpr float kPushGain = 5.0 / 4;

constexpr float kMaxBeta = 1.0 / 4;

// Sensitivity grows from 0 at kLowRate to kMidRateSensitivity at kMidRate, and
// then to 1 at kHighRate. Rates are in bytes per second.
constexpr uint64_t kLowRate = 50'000;
constexpr uint64_t kMidRate = 1'000'000;
constexpr uint64_t kHighRate = 10'000'000;
constexpr float kMidRateSensitivity = 0.94;

constexpr float kMinDelayFraction = 1.0 / 16;
constexpr float kDelayFractionSlope = 3.0 / 16;
constexpr std::chrono::microseconds kMaxDelayThreshold = 25ms;

constexpr float kMinLossThreshold = 0.02;
constexpr float kLossThresholdSlope = 0.5;
constexpr float kLossRateGain = 1.0 / 16;
constexpr PacketNum kLossRateMaxGap = 32;

constexpr std::chrono::microseconds kMinMaxRtt = 1ms;
constexpr std::chrono::microseconds kMaxJitter = 250ms;
constexpr std::chrono::microseconds kMaxCwndMargin = 15ms;
constexpr std::chrono::microseconds kMinRateInterval = 1ms;

constexpr uint64_t kInitialMinPacingRate = 131'072; // bytes per second
constexpr uint64_t kInitialErasWithoutGrowth = 3;
constexpr uint64_t kInitialEventsBeforeLossExit = 20;

constexpr uint64_t kDefaultProbeLevel = 1;
constexpr uint64_t kMaxProbeLevel = 3;
constexpr uint64_t kCruiseErasBeforeProbe = 2;

// Initial is re-entered when the max RTT is far above the min RTT, which can
// mean that Initial ended early because of jitter or competing flows.
constexpr std::chrono::microseconds kReinitMinMaxRtt = 50ms;
constexpr uint64_t kReinitMaxRate = 1'000'000; // bytes per second
constexpr std::chrono::microseconds kReinitMinInterval = 1s;

// The pacer derives the rate from a window and an interval. A one second
// interval keeps the pacer's minimum window from raising low rates.
constexpr std::chrono::microseconds kPacingInterval = 1s;

Bandwidth bytesPerSecond(uint64_t bytes, std::chrono::microseconds interval) {
  return Bandwidth(bytes * 1'000'000 / interval.count(), 1s);
}

} // namespace

C4CongestionController::C4CongestionController(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwndBytes_(
          conn_.udpSendPacketLen * conn_.transportSettings.initCwndInMss) {
  if (conn_.pacer) {
    conn_.pacer->setRttFactor(1, 1);
  } else {
    MVLOG_WARNING << "C4 was initialized on a connection without a pacer";
  }
  enterInitial();
  setCwndAndPacing(conn_.connectionTime);
}

void C4CongestionController::onRemoveBytesFromInflight(
    uint64_t /* bytesToRemove */) {}

void C4CongestionController::onPacketSent(
    const OutstandingPacketWrapper& /* packet */) {}

void C4CongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  const AckEvent* ack = ackEvent && !ackEvent->implicit &&
          ackEvent->packetNumberSpace == PacketNumberSpace::AppData
      ? ackEvent
      : nullptr;
  // A loss event that comes with an ACK is in the ACK's packet number space.
  const LossEvent* loss = lossEvent &&
          lossEvent->packetNumberSpace == PacketNumberSpace::AppData &&
          (ack || !ackEvent)
      ? lossEvent
      : nullptr;
  TimePoint eventTime;
  if (ack) {
    eventTime = ack->ackTime;
  } else if (loss) {
    eventTime = loss->lossTime;
  } else {
    return;
  }

  // Only ACKs that newly acknowledge their largest packet carry an RTT sample,
  // and C4 handles only those. Losses found by an ACK count before the ACK
  // itself, so that they can extend Recovery.
  if (ack) {
    maybeExitAppLimited(*ack);
    if (ack->rttSample.has_value()) {
      onRttSample(*ack);
    }
  }
  if (loss) {
    for (const auto packetNum : loss->lostPacketNumbers()) {
      onLostPacket(packetNum);
    }
  }
  if (ack && ack->rttSample.has_value()) {
    onAck(*ack);
  }

  setCwndAndPacing(eventTime);
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      getCongestionWindow(),
      conn_.lossState.inflightBytes,
      std::nullopt,
      std::nullopt,
      pacingRate_.normalize(),
      conn_.lossState.ptoCount);
}

uint64_t C4CongestionController::getWritableBytes() const noexcept {
  return cwndBytes_ > conn_.lossState.inflightBytes
      ? cwndBytes_ - conn_.lossState.inflightBytes
      : 0;
}

uint64_t C4CongestionController::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

CongestionControlType C4CongestionController::type() const noexcept {
  return CongestionControlType::C4;
}

bool C4CongestionController::isAppLimited() const {
  return appLimited_;
}

Optional<Bandwidth> C4CongestionController::getBandwidth() const {
  if (!nominalRate_) {
    return std::nullopt;
  }
  return nominalRate_;
}

uint64_t C4CongestionController::getBDP() const {
  return nominalRate_ * nominalMaxRtt_;
}

void C4CongestionController::setAppLimited() noexcept {
  appLimitedPacketNum_ = nextPacketNum();
  if (!appLimited_) {
    appLimited_ = true;
    QLOG(conn_, addAppLimitedUpdate);
  }
}

void C4CongestionController::getStats(CongestionControllerStats& stats) const {
  stats.c4Stats.state = static_cast<uint8_t>(state_);
}

C4CongestionController::State C4CongestionController::getState()
    const noexcept {
  return state_;
}

void C4CongestionController::maybeExitAppLimited(const AckEvent& ackEvent) {
  if (appLimited_ && ackEvent.largestNewlyAckedPacket &&
      *ackEvent.largestNewlyAckedPacket >= appLimitedPacketNum_) {
    appLimited_ = false;
    QLOG(conn_, addAppUnlimitedUpdate);
  }
}

void C4CongestionController::onRttSample(const AckEvent& ackEvent) {
  auto rtt = *ackEvent.rttSample;
  // RFC 9002 caps the ACK delay at the peer's max_ack_delay.
  const auto ackDelay = std::min(ackEvent.ackDelay, conn_.peerMaxAckDelay);
  if (rtt > ackDelay && rtt - ackDelay > conn_.lossState.mrtt) {
    rtt -= ackDelay;
  }
  latestRtt_ = rtt;
  eraMaxRtt_ = std::max(eraMaxRtt_, rtt);
  eraMinRtt_ = std::min(eraMinRtt_, rtt);
  runningMinRtt_ = std::min(runningMinRtt_, rtt);
  if (nominalMaxRtt_ == 0us) {
    nominalMaxRtt_ = std::max(rtt, kMinMaxRtt);
    delayExcess_ = 0us;
  } else {
    const auto target = nominalMaxRtt_ + delayThreshold();
    delayExcess_ = rtt > target ? rtt - target : 0us;
  }

  if (state_ == State::Initial) {
    if (canExitInitialOnSignal()) {
      exitInitial(Signal::Delay);
    }
  } else if (delayExcess_ > 0us && eraPacingGain_ > 1) {
    notifyCongestion(Signal::Delay);
  }
}

void C4CongestionController::onAck(const AckEvent& ackEvent) {
  updateRate(ackEvent);
  updatePeakRate(ackEvent);
  const bool eraEnded = ackEvent.largestNewlyAckedPacket &&
      *ackEvent.largestNewlyAckedPacket >= eraStartPacketNum_;
  if (state_ == State::Initial) {
    onInitialAck(ackEvent.ackedBytes, eraEnded);
  } else if (eraEnded) {
    onEraEnd(ackEvent.ackTime);
  } else if (state_ == State::Pushing && evaluateGrowth() == Growth::Fast) {
    resetGrowth();
    resetEra();
  }
}

void C4CongestionController::updateRate(const AckEvent& ackEvent) {
  const auto* packet = ackEvent.getLargestNewlyAckedPacket();
  if (!packet) {
    return;
  }
  const auto& prior = packet->lastAckedPacketInfo;
  const auto sentTime = packet->outstandingPacketMetadata.time;
  const uint64_t delivered =
      ackEvent.totalBytesAcked - (prior ? prior->totalBytesAcked : 0);
  if (prior && sentTime >= rateEstimateSentTime_) {
    // The reported ACK delays come out of the ACK times, so that ACKs that the
    // peer held for different times do not shorten the interval.
    const auto ackElapsed = ackEvent.adjustedAckTime - prior->adjustedAckTime;
    if (ackElapsed > kMinRateInterval) {
      const auto interval = std::max(ackElapsed, sentTime - prior->sentTime);
      rateEstimate_ = bytesPerSecond(
          delivered,
          std::chrono::duration_cast<std::chrono::microseconds>(interval));
      rateEstimateSentTime_ = sentTime;
    }
  }
  if (delivered == 0) {
    return;
  }

  if (rateEstimate_ > recentMaxRate_) {
    recentMaxRate_ = rateEstimate_;
  }
  if (rateEstimate_ > nominalRate_ &&
      !(state_ == State::Recovery && congestionNotified_)) {
    rateWasNotLimited_ = true;
    nominalRate_ = rateEstimate_;
    backlog_ = 0;
  } else if (delivered > nominalRate_ * runningMinRtt_) {
    // The rate did not grow, but more than a min RTT worth of data was
    // delivered, so the network limited the rate, not the sender.
    rateWasNotLimited_ = true;
  }
}

void C4CongestionController::updatePeakRate(const AckEvent& ackEvent) {
  const DeliveryCheckpoint checkpoint{
      .totalBytesAcked = ackEvent.totalBytesAcked,
      .adjustedAckTime = ackEvent.adjustedAckTime,
      .sentTime = ackEvent.largestNewlyAckedPacketSentTime};
  if (!peakCheckpoint_) {
    peakCheckpoint_ = checkpoint;
    return;
  }
  if (checkpoint.sentTime < peakCheckpoint_->sentTime) {
    return;
  }
  const auto ackElapsed =
      checkpoint.adjustedAckTime - peakCheckpoint_->adjustedAckTime;
  if (ackElapsed <= kMinRateInterval) {
    return;
  }
  const auto interval =
      std::max(ackElapsed, checkpoint.sentTime - peakCheckpoint_->sentTime);
  const auto sample = bytesPerSecond(
      checkpoint.totalBytesAcked - peakCheckpoint_->totalBytesAcked,
      std::chrono::duration_cast<std::chrono::microseconds>(interval));
  if (sample > peakRate_) {
    peakRate_ = sample;
  }
  peakCheckpoint_ = checkpoint;
}

void C4CongestionController::onLostPacket(PacketNum packetNum) {
  // Packets sent before the latest Recovery were sent at the old rate.
  if (packetNum < recoveryStartPacketNum_) {
    return;
  }
  updateLossRate(packetNum);
  if (smoothedLossRate_ <= lossThreshold()) {
    return;
  }
  if (state_ != State::Initial) {
    notifyCongestion(Signal::Loss);
  } else if (++initialEvents_ > kInitialEventsBeforeLossExit) {
    exitInitial(Signal::Loss);
  }
}

void C4CongestionController::updateLossRate(PacketNum packetNum) {
  if (packetNum <= lastLostPacketNum_) {
    return;
  }
  // Every packet number since the previous loss counts as delivered.
  const auto gap = std::min(packetNum - lastLostPacketNum_, kLossRateMaxGap);
  smoothedLossRate_ *= std::pow(1 - kLossRateGain, static_cast<float>(gap));
  smoothedLossRate_ += (1 - smoothedLossRate_) * kLossRateGain;
  lastLostPacketNum_ = packetNum;
}

void C4CongestionController::updateMaxRtt() {
  eraMaxRtt_ = std::max(eraMaxRtt_, latestRtt_);
  eraMinRtt_ = std::min(eraMinRtt_, latestRtt_);
  // Eras that pushed above the nominal rate inflate the RTT with their own
  // queue, so only the others update the RTT estimates.
  if (eraPacingGain_ <= 1) {
    runningMinRtt_ = eraMinRtt_ < runningMinRtt_
        ? eraMinRtt_
        : (7 * runningMinRtt_ + eraMinRtt_) / 8;
    const auto eraMaxRtt = std::min(eraMaxRtt_, runningMinRtt_ + kMaxJitter);
    nominalMaxRtt_ = eraMaxRtt > nominalMaxRtt_
        ? eraMaxRtt
        : (7 * nominalMaxRtt_ + eraMaxRtt) / 8;
  } else if (nominalMaxRtt_ == 0us) {
    nominalMaxRtt_ = eraMaxRtt_;
  }
  if (nominalMaxRtt_ < kMinMaxRtt) {
    nominalMaxRtt_ = kMinMaxRtt;
    backlog_ = 0;
  }
}

void C4CongestionController::notifyCongestion(Signal signal) {
  congestionNotified_ = true;
  float beta = kMaxBeta;
  if (signal == Signal::Loss) {
    beta = (1 + sensitivity()) / 8;
  }
  if (signal == Signal::Delay) {
    beta = std::min(
        kMaxBeta,
        static_cast<float>(delayExcess_.count()) /
            static_cast<float>(delayThreshold().count()));
  } else {
    delayExcess_ = 0us;
  }

  if (state_ == State::Recovery) {
    // A second signal means that queues are still building, so drain longer.
    if (pacingGain_ == kRecoveryGain) {
      pacingGain_ = kDeepRecoveryGain;
      eraStartPacketNum_ = nextPacketNum();
      recoveryStartPacketNum_ = eraStartPacketNum_;
    }
    return;
  }
  // Probing and Pushing only reach above the nominal rate, which stays valid.
  if (state_ != State::Probing && state_ != State::Pushing) {
    nominalRate_ = nominalRate_ * (1 - beta);
    if (signal == Signal::Loss) {
      nominalMaxRtt_ = std::max(
          kMinMaxRtt,
          std::chrono::duration_cast<std::chrono::microseconds>(
              nominalMaxRtt_ * (1 - beta)));
    }
  }
  enterRecovery(triggerName(signal));
}

void C4CongestionController::enterInitial() {
  setState(State::Initial, kCongestionPacketAck);
  nominalMaxRtt_ = conn_.lossState.srtt;
  initialCwnd_ = nominalRate_ ? nominalRate_ * nominalMaxRtt_ : cwndBytes_;
  initialExitTime_.reset();
  probeLevel_ = kDefaultProbeLevel;
  pacingGain_ = kInitialGain;
  initialEvents_ = 0;
  resetEra();
  erasWithoutGrowth_ = 0;
  resetGrowth();
}

void C4CongestionController::exitInitial(Signal signal) {
  if (!nominalRate_) {
    return;
  }
  // Half of the Initial window at the nominal rate estimates the max RTT, and
  // the other half is the queue that Recovery drains over one era.
  const uint64_t halfInitialCwnd = initialCwnd_ / 2;
  nominalMaxRtt_ = std::chrono::microseconds(
      halfInitialCwnd * nominalRate_.interval.count() / nominalRate_.units);
  backlog_ = 1;
  if (nominalMaxRtt_ < kMinMaxRtt) {
    nominalMaxRtt_ = kMinMaxRtt;
    backlog_ = 0;
  } else if (conn_.lossState.srtt < kMinMaxRtt) {
    backlog_ = 0;
  }
  erasWithoutGrowth_ = 0;
  probeLevel_ = kDefaultProbeLevel;
  // The signal that ended Initial shows only in the qlog.
  enterRecovery(triggerName(signal));
}

bool C4CongestionController::canExitInitialOnSignal() const {
  return delayExcess_ > 0us && erasWithoutGrowth_ > 1 &&
      growthBaseRate_ >= nominalRate_;
}

void C4CongestionController::onInitialAck(uint64_t ackedBytes, bool eraEnded) {
  initialEvents_++;
  // Reno-like growth that slows down after eras without rate growth.
  initialCwnd_ += ackedBytes >> (3 * erasWithoutGrowth_);
  if (!eraEnded) {
    return;
  }
  if (evaluateGrowth() != Growth::None) {
    erasWithoutGrowth_ = 0;
  } else if (rateWasNotLimited_ && nominalRate_) {
    erasWithoutGrowth_++;
  }
  resetEra();
  if (erasWithoutGrowth_ >= kInitialErasWithoutGrowth) {
    exitInitial(Signal::None);
    return;
  }
  resetGrowth();
}

void C4CongestionController::enterRecovery(std::string_view trigger) {
  if (state_ == State::Initial) {
    resetGrowth();
  }
  if (state_ == State::Recovery) {
    return;
  }
  if (backlog_ <= 1 - kRecoveryGain || nominalMaxRtt_ <= kMinMaxRtt) {
    pacingGain_ = kRecoveryGain;
  } else if (backlog_ <= 1 - kDeepRecoveryGain) {
    pacingGain_ = kDeepRecoveryGain;
  } else {
    pacingGain_ = kDrainGain;
  }
  setState(State::Recovery, trigger);
  resetEra();
  recoveryStartPacketNum_ = eraStartPacketNum_;
}

void C4CongestionController::exitRecovery(TimePoint now) {
  const auto growth = evaluateGrowth();
  if (!initialExitTime_) {
    initialExitTime_ = now;
  }
  backlog_ = std::max(0.0f, backlog_ - (1 - pacingGain_));
  if (growth == Growth::None) {
    updateRatesWithoutGrowth();
  } else {
    probeLevel_++;
    recentCongestions_ = 0;
    previousMaxRate_ = recentMaxRate_;
  }
  recentMaxRate_ = Bandwidth();
  resetGrowth();
  delayExcess_ = 0us;
  smoothedLossRate_ = 0;

  if (probeLevel_ > kMaxProbeLevel) {
    enterInitial();
  } else if (probeLevel_ > kDefaultProbeLevel) {
    enterPushing();
  } else {
    enterCruising();
  }
}

void C4CongestionController::updateRatesWithoutGrowth() {
  if (rateWasNotLimited_) {
    probeLevel_ = kDefaultProbeLevel;
  }
  if (congestionNotified_) {
    // Two congestion signals in a row mean that the nominal rate is above
    // what the path delivered recently.
    if (++recentCongestions_ >= 2 && recentMaxRate_ &&
        nominalRate_ > recentMaxRate_) {
      nominalRate_ = recentMaxRate_;
      recentCongestions_ = 0;
    }
    previousMaxRate_ = recentMaxRate_;
    return;
  }
  recentCongestions_ = 0;
  if (!rateWasNotLimited_) {
    return;
  }
  // Trim a nominal rate that the last two eras did not deliver.
  const auto maxRate = std::max(recentMaxRate_, previousMaxRate_);
  if (maxRate && nominalRate_ > maxRate && conn_.lossState.srtt > kMinMaxRtt) {
    nominalRate_ = maxRate;
  }
  previousMaxRate_ = recentMaxRate_;
}

void C4CongestionController::enterCruising() {
  resetEra();
  if (cruiseErasLeft_ == 0) {
    cruiseErasLeft_ = kCruiseErasBeforeProbe;
  }
  pacingGain_ = kCruiseGain;
  if (conn_.lossState.srtt < kMinMaxRtt) {
    pacingGain_ += kLowRttCruiseBoost;
  }
  setState(State::Cruising, kCongestionPacketAck);
}

void C4CongestionController::enterProbing() {
  pacingGain_ = kProbeGain;
  growthGain_ = pacingGain_;
  resetEra();
  setState(State::Probing, kCongestionPacketAck);
}

void C4CongestionController::enterPushing() {
  pacingGain_ = kPushGain;
  setState(State::Pushing, kCongestionPacketAck);
  resetGrowth();
  resetEra();
}

void C4CongestionController::onEraEnd(TimePoint now) {
  updateMaxRtt();
  if (shouldReenterInitial(now)) {
    enterInitial();
    return;
  }
  switch (state_) {
    case State::Initial:
      break;
    case State::Recovery:
      exitRecovery(now);
      break;
    case State::Cruising:
      if (cruiseErasLeft_ > 0) {
        cruiseErasLeft_--;
      }
      resetEra();
      if (cruiseErasLeft_ == 0 && !appLimited_) {
        enterProbing();
      }
      break;
    case State::Probing:
      enterRecovery(kCongestionPacketAck);
      break;
    case State::Pushing:
      // Every era in Pushing starts at the push gain, so a push without fast
      // growth ends at the first era end.
      if (evaluateGrowth() == Growth::Fast) {
        resetGrowth();
        resetEra();
      } else {
        backlog_ += pacingGain_ - 1;
        enterRecovery(kCongestionPacketAck);
      }
      break;
  }
}

bool C4CongestionController::shouldReenterInitial(TimePoint now) const {
  return nominalMaxRtt_ > kReinitMinMaxRtt &&
      nominalRate_ < Bandwidth(kReinitMaxRate, 1s) &&
      5 * runningMinRtt_ < 2 * nominalMaxRtt_ && initialExitTime_ &&
      now > *initialExitTime_ + kReinitMinInterval;
}

void C4CongestionController::resetEra() {
  eraStartPacketNum_ = nextPacketNum();
  eraMaxRtt_ = 0us;
  eraMinRtt_ = std::chrono::microseconds::max();
  eraPacingGain_ = pacingGain_;
}

void C4CongestionController::resetGrowth() {
  congestionNotified_ = false;
  rateWasNotLimited_ = false;
  growthBaseRate_ = nominalRate_;
  growthGain_ = pacingGain_;
}

C4CongestionController::Growth C4CongestionController::evaluateGrowth() const {
  // Small gains cannot show measurable growth, so any rate increase without a
  // congestion signal counts as fast growth.
  if (growthGain_ <= kProbeGain) {
    return nominalRate_ > growthBaseRate_ && !congestionNotified_
        ? Growth::Fast
        : Growth::None;
  }
  if (nominalRate_ < growthBaseRate_ * ((3 + growthGain_) / 4)) {
    return Growth::None;
  }
  return nominalRate_ > growthBaseRate_ * ((1 + 3 * growthGain_) / 4)
      ? Growth::Fast
      : Growth::Slow;
}

float C4CongestionController::sensitivity() const {
  const uint64_t rate = nominalRate_.normalize();
  if (rate < kLowRate) {
    return 0;
  }
  if (rate > kHighRate) {
    return 1;
  }
  if (rate < kMidRate) {
    return kMidRateSensitivity * static_cast<float>(rate - kLowRate) /
        static_cast<float>(kMidRate - kLowRate);
  }
  return kMidRateSensitivity +
      (1 - kMidRateSensitivity) * static_cast<float>(rate - kMidRate) /
      static_cast<float>(kHighRate - kMidRate);
}

std::chrono::microseconds C4CongestionController::delayThreshold() const {
  const float fraction =
      kMinDelayFraction + (1 - sensitivity()) * kDelayFractionSlope;
  return std::min(
      kMaxDelayThreshold,
      std::chrono::duration_cast<std::chrono::microseconds>(
          nominalMaxRtt_ * fraction));
}

float C4CongestionController::lossThreshold() const {
  return kMinLossThreshold + kLossThresholdSlope * (1 - sensitivity());
}

PacketNum C4CongestionController::nextPacketNum() const {
  return conn_.ackStates.appDataAckState.nextPacketNum;
}

void C4CongestionController::setCwndAndPacing(TimePoint eventTime) {
  pacingRate_ = nominalRate_ * pacingGain_;
  uint64_t targetCwnd =
      conn_.transportSettings.initCwndInMss * conn_.udpSendPacketLen;
  if (nominalRate_ && nominalMaxRtt_ > 0us) {
    targetCwnd = pacingRate_ * nominalMaxRtt_;
  }
  if (state_ == State::Initial) {
    targetCwnd = std::max(targetCwnd, initialCwnd_);
    if (initialEvents_ > 0) {
      pacingRate_ = std::max(pacingRate_, Bandwidth(kInitialMinPacingRate, 1s));
      if (peakRate_ > pacingRate_) {
        pacingRate_ = Bandwidth(
            (pacingRate_.normalize() + peakRate_.normalize()) / 2, 1s);
        targetCwnd = std::max(targetCwnd, peakRate_ * conn_.lossState.srtt / 2);
      }
    }
  } else {
    // The margin keeps the cwnd from limiting sending below the pacing rate.
    // When the cwnd limits sending, the margin would only add to the queue.
    if (burstFitsRtt()) {
      targetCwnd += pacingRate_ * std::min(nominalMaxRtt_ / 4, kMaxCwndMargin);
    }
    // Keep room for at least one more packet when probing above the nominal
    // rate.
    if (state_ == State::Probing || state_ == State::Pushing) {
      const uint64_t probeBytes =
          nominalRate_ * (pacingGain_ - 1) * nominalMaxRtt_;
      if (probeBytes < conn_.udpSendPacketLen) {
        targetCwnd += conn_.udpSendPacketLen - probeBytes;
      }
    }
  }
  cwndBytes_ = boundedCwnd(
      targetCwnd,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);

  if (!conn_.pacer) {
    return;
  }
  if (shouldPace()) {
    conn_.pacer->refreshPacingRate(
        pacingRate_ * kPacingInterval, kPacingInterval, eventTime);
  } else {
    conn_.pacer->refreshPacingRate(cwndBytes_, 0us, eventTime);
  }
}

bool C4CongestionController::shouldPace() const {
  if (!pacingRate_) {
    return false;
  }
  // The pacer sends bursts of at least minBurstPackets. A burst that is more
  // than one max RTT of data, and that the cwnd cannot hold on top of that
  // data, gets cut short by the cwnd, and the path idles until the next burst.
  // The cwnd and the ACK clock then limit sending.
  return burstFitsRtt() ||
      cwndBytes_ >= pacingRate_ * nominalMaxRtt_ + minBurstBytes();
}

bool C4CongestionController::burstFitsRtt() const {
  return pacingRate_ * nominalMaxRtt_ >= minBurstBytes();
}

uint64_t C4CongestionController::minBurstBytes() const {
  return conn_.transportSettings.minBurstPackets * conn_.udpSendPacketLen;
}

void C4CongestionController::setState(State state, std::string_view trigger) {
  if (state == state_) {
    return;
  }
  QLOG(
      conn_,
      addCongestionStateUpdate,
      c4StateToString(state_),
      c4StateToString(state),
      std::string(trigger));
  state_ = state;
}

std::string_view C4CongestionController::triggerName(Signal signal) {
  switch (signal) {
    case Signal::None:
      return kCongestionPacketAck;
    case Signal::Delay:
      return "delay";
    case Signal::Loss:
      return kCongestionPacketLoss;
  }
  folly::assume_unreachable();
}

std::string c4StateToString(C4CongestionController::State state) {
  switch (state) {
    case C4CongestionController::State::Initial:
      return "Initial";
    case C4CongestionController::State::Recovery:
      return "Recovery";
    case C4CongestionController::State::Cruising:
      return "Cruising";
    case C4CongestionController::State::Probing:
      return "Probing";
    case C4CongestionController::State::Pushing:
      return "Pushing";
  }
  folly::assume_unreachable();
}

} // namespace quic
