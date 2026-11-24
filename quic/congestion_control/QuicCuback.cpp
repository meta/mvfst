/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/QuicCuback.h>

#include <folly/lang/Assume.h>
#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>

#include <algorithm>
#include <cmath>

namespace quic {

namespace {

constexpr double kBetaCubic = 0.7;
constexpr double kAlphaCubic = 3 * (1 - kBetaCubic) / (1 + kBetaCubic);
// In segments per second cubed.
constexpr double kCubicC = 0.4;

constexpr std::chrono::microseconds kMinRttThresh = 4ms;
constexpr std::chrono::microseconds kMaxRttThresh = 16ms;
// RFC 9406 recommends 8. With 16, slow start ends with a shorter queue.
constexpr int64_t kMinRttDivisor = 16;
constexpr uint64_t kRttSamplesPerRound = 8;
constexpr uint64_t kCssGrowthDivisor = 4;
constexpr uint64_t kCssRounds = 5;
// Pacing at twice cwnd over srtt keeps the pacing rate after a reduction above
// the send rate before it.
constexpr uint64_t kPacingGain = 2;

constexpr auto kEcnTrigger = "ecn";
constexpr auto kDelayIncreaseTrigger = "delay increase";
constexpr auto kDelayDecreaseTrigger = "delay decrease";
constexpr auto kCssRoundsTrigger = "css rounds";
constexpr auto kSsthreshTrigger = "ssthresh";
constexpr auto kRecoveryEndTrigger = "recovery end";
constexpr auto kSpuriousLossTrigger = "spurious loss";

// The Reno-friendly curve uses alpha_cubic below cwnd_prior and 1 above it.
double renoAckedBytes(const CubackEpoch& epoch, double w, double smss) {
  const double knee = std::max(epoch.cwndPrior, epoch.cwndEpoch);
  const double belowKnee = std::min(w, knee);
  double bytes = (belowKnee - epoch.cwndEpoch) *
      (belowKnee + epoch.cwndEpoch - smss) / (2 * kAlphaCubic * smss);
  if (w > knee) {
    bytes += (w - knee) * (w + knee - smss) / (2 * smss);
  }
  return bytes;
}

double cubicAckedBytes(const CubackEpoch& epoch, double w, double smss) {
  const double k = std::cbrt((epoch.wMax - epoch.cwndEpoch) / (kCubicC * smss));
  return epoch.bandwidth * (k + std::cbrt((w - epoch.wMax) / (kCubicC * smss)));
}

} // namespace

double cubackAckedBytes(const CubackEpoch& epoch, double w, double smss) {
  return std::min(
      cubicAckedBytes(epoch, w, smss), renoAckedBytes(epoch, w, smss));
}

double cubackIncreaseBytes(const CubackEpoch& epoch, double w, double smss) {
  return std::max(
      2 * smss,
      cubackAckedBytes(epoch, w + smss, smss) -
          cubackAckedBytes(epoch, w, smss));
}

Cuback::Cuback(QuicConnectionStateBase& conn)
    : conn_(conn),
      cwndBytes_(boundedCwnd(
          conn.transportSettings.initCwndInMss * conn.udpSendPacketLen,
          conn.udpSendPacketLen,
          conn.transportSettings.maxCwndInMss,
          conn.transportSettings.minCwndInMss)),
      ecnCeCount_(conn.ackStates.appDataAckState.ecnCECountEchoed),
      hystartRoundEndPacketNum_(conn.ackStates.appDataAckState.nextPacketNum) {
  if (conn_.pacer) {
    conn_.pacer->setRttFactor(1, 1);
  }
}

void Cuback::onRemoveBytesFromInflight(uint64_t /* bytesToRemove */) {}

void Cuback::onPacketSent(const OutstandingPacketWrapper& /* packet */) {
  if (conn_.lossState.inflightBytes < cwndBytes_) {
    return;
  }
  cwndLimitedEndPacketNum_ = std::numeric_limits<PacketNum>::max();
  if (appLimited_) {
    appLimited_ = false;
    QLOG(conn_, addAppUnlimitedUpdate);
  }
}

void Cuback::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  // Recovery and the cwnd limited state are tracked by packet number, which
  // orders packets only within a space, so only AppData drives Cuback.
  const AckEvent* ack = ackEvent && !ackEvent->implicit &&
          ackEvent->packetNumberSpace == PacketNumberSpace::AppData
      ? ackEvent
      : nullptr;
  const LossEvent* loss =
      lossEvent && lossEvent->packetNumberSpace == PacketNumberSpace::AppData
      ? lossEvent
      : nullptr;
  if (!ack && !loss) {
    return;
  }

  if (ack) {
    onSpuriousLosses(*ack);
    onEcnCounts(*ack);
  }
  if (loss) {
    onLoss(*loss);
  }
  if (ack && ack->largestNewlyAckedPacket) {
    onAck(*ack);
  }

  setPacingRate();
  QLOG(
      conn_,
      addMetricUpdate,
      conn_.lossState.lrtt,
      conn_.lossState.mrtt,
      conn_.lossState.srtt,
      conn_.lossState.maybeLrttAckDelay.value_or(0us),
      conn_.lossState.rttvar,
      cwndBytes_,
      conn_.lossState.inflightBytes,
      ssthreshBytes_ == std::numeric_limits<uint64_t>::max()
          ? std::nullopt
          : Optional<uint64_t>(ssthreshBytes_),
      std::nullopt,
      conn_.lossState.srtt > 0us ? Optional<uint64_t>(
                                       cwndBytes_ * kPacingGain * 1'000'000 /
                                       conn_.lossState.srtt.count())
                                 : std::nullopt,
      conn_.lossState.ptoCount);
}

uint64_t Cuback::getWritableBytes() const noexcept {
  return cwndBytes_ > conn_.lossState.inflightBytes
      ? cwndBytes_ - conn_.lossState.inflightBytes
      : 0;
}

uint64_t Cuback::getCongestionWindow() const noexcept {
  return cwndBytes_;
}

CongestionControlType Cuback::type() const noexcept {
  return CongestionControlType::Cuback;
}

bool Cuback::isAppLimited() const noexcept {
  return appLimited_;
}

void Cuback::setAppLimited() noexcept {
  if (cwndLimitedEndPacketNum_ == std::numeric_limits<PacketNum>::max() &&
      conn_.lossState.inflightBytes < cwndBytes_) {
    cwndLimitedEndPacketNum_ = nextPacketNum();
  }
  if (!appLimited_) {
    appLimited_ = true;
    QLOG(conn_, addAppLimitedUpdate);
  }
}

void Cuback::getStats(CongestionControllerStats& stats) const {
  stats.cubackStats.state = static_cast<uint8_t>(state_);
  stats.cubackStats.ssthresh = ssthreshBytes_;
}

Cuback::State Cuback::getState() const noexcept {
  return state_;
}

void Cuback::onSpuriousLosses(const AckEvent& ack) {
  if (!undo_ || ack.numPacketsSpuriouslyAcked == 0) {
    return;
  }
  if (ack.numPacketsSpuriouslyAcked > undo_->lostPackets) {
    undo_.reset();
    return;
  }
  undo_->lostPackets -= ack.numPacketsSpuriouslyAcked;
  if (undo_->lostPackets > 0) {
    return;
  }
  // Once cwnd is back above cwnd_prior, the current values stay.
  if (cwndBytes_ < undo_->cwndBytes) {
    setCwnd(undo_->cwndBytes);
    ssthreshBytes_ = undo_->ssthreshBytes;
    epoch_ = undo_->epoch;
    pendingBytes_ = undo_->pendingBytes;
    recoveryEndPacketNum_ = undo_->recoveryEndPacketNum;
    setState(undo_->state, kSpuriousLossTrigger);
  }
  undo_.reset();
}

void Cuback::onEcnCounts(const AckEvent& ack) {
  // The transport keeps running maxima of the echoed counts.
  const uint64_t ceCount = conn_.ackStates.appDataAckState.ecnCECountEchoed;
  if (ceCount <= ecnCeCount_) {
    return;
  }
  ecnCeCount_ = ceCount;
  const bool ecnValidated = conn_.ecnState == ECNState::ValidatedECN ||
      conn_.ecnState == ECNState::ValidatedL4S;
  if (ecnValidated && ack.largestAckedPacket >= recoveryEndPacketNum_) {
    undo_.reset();
    onCongestionEvent(kEcnTrigger);
  }
}

void Cuback::onLoss(const LossEvent& loss) {
  if (loss.largestLostPacketNum &&
      *loss.largestLostPacketNum >= recoveryEndPacketNum_) {
    auto undo = undoState(loss);
    onCongestionEvent(kCongestionPacketLoss);
    undo_ = std::move(undo);
  } else if (undo_) {
    undo_->lostPackets += loss.lostPackets;
  }
  if (loss.persistentCongestion) {
    undo_.reset();
    onPersistentCongestion();
  }
}

void Cuback::onAck(const AckEvent& ack) {
  if (state_ == State::Recovery) {
    if (*ack.largestNewlyAckedPacket < recoveryEndPacketNum_) {
      return;
    }
    setState(State::CongestionAvoidance, kRecoveryEndTrigger);
  }
  const uint64_t ackedBytes = ackedBytesAfterRecovery(ack);
  const bool grow = isCwndLimited(ack);
  switch (state_) {
    case State::SlowStart:
    case State::ConservativeSlowStart:
      onSlowStartAck(ack, ackedBytes, grow);
      break;
    case State::CongestionAvoidance:
      if (grow) {
        growInCongestionAvoidance(ackedBytes);
      }
      break;
    case State::Recovery:
      break;
  }
}

void Cuback::onCongestionEvent(std::string_view trigger) {
  const auto cwnd = static_cast<double>(cwndBytes_);
  // Fast convergence: a flow that peaks below its last W_max lowers W_max.
  epoch_.wMax = cwnd < epoch_.wMax ? cwnd * (1 + kBetaCubic) / 2 : cwnd;
  epoch_.cwndPrior = cwnd;
  epoch_.bandwidth = bandwidth(cwndBytes_);
  ssthreshBytes_ = boundedCwnd(
      static_cast<uint64_t>(cwnd * kBetaCubic),
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);
  setCwnd(ssthreshBytes_);
  epoch_.cwndEpoch = static_cast<double>(cwndBytes_);
  pendingBytes_ = 0;
  recoveryEndPacketNum_ = nextPacketNum();
  setState(State::Recovery, trigger);
}

void Cuback::onPersistentCongestion() {
  setCwnd(conn_.transportSettings.minCwndInMss * conn_.udpSendPacketLen);
  pendingBytes_ = 0;
  // The packets that were in flight still belong to the congestion event, so
  // their losses do not reduce cwnd again.
  recoveryEndPacketNum_ = nextPacketNum();
  if (cwndBytes_ >= ssthreshBytes_) {
    enterCongestionAvoidance(kPersistentCongestion);
  } else {
    setState(State::SlowStart, kPersistentCongestion);
  }
}

void Cuback::onSlowStartAck(
    const AckEvent& ack,
    uint64_t ackedBytes,
    bool grow) {
  const uint64_t growth = grow ? ackedBytes : 0;
  if (ssthreshBytes_ != std::numeric_limits<uint64_t>::max()) {
    // HyStart++ runs only in the first slow start. Later ones end at ssthresh,
    // and the bytes past it count toward congestion avoidance.
    const uint64_t slowStartGrowth =
        std::min(growth, ssthreshBytes_ - std::min(ssthreshBytes_, cwndBytes_));
    setCwnd(cwndBytes_ + slowStartGrowth);
    if (cwndBytes_ >= ssthreshBytes_) {
      enterCongestionAvoidance(kSsthreshTrigger);
      growInCongestionAvoidance(growth - slowStartGrowth);
    }
    return;
  }

  // Growth per ACK stays uncapped without pacing, where RFC 9406 recommends 8
  // segments.
  setCwnd(
      cwndBytes_ +
      (state_ == State::ConservativeSlowStart ? growth / kCssGrowthDivisor
                                              : growth));

  if (ack.rttSample) {
    currentRoundMinRtt_ = std::min(currentRoundMinRtt_, *ack.rttSample);
    rttSampleCount_++;
  }
  if (rttSampleCount_ >= kRttSamplesPerRound) {
    if (state_ == State::SlowStart &&
        currentRoundMinRtt_ != std::chrono::microseconds::max() &&
        lastRoundMinRtt_ != std::chrono::microseconds::max()) {
      const auto rttThresh = std::clamp(
          lastRoundMinRtt_ / kMinRttDivisor, kMinRttThresh, kMaxRttThresh);
      if (currentRoundMinRtt_ >= lastRoundMinRtt_ + rttThresh) {
        cssBaselineMinRtt_ = currentRoundMinRtt_;
        cssRounds_ = 0;
        setState(State::ConservativeSlowStart, kDelayIncreaseTrigger);
      }
    } else if (
        state_ == State::ConservativeSlowStart &&
        currentRoundMinRtt_ < cssBaselineMinRtt_) {
      cssBaselineMinRtt_ = std::chrono::microseconds::max();
      setState(State::SlowStart, kDelayDecreaseTrigger);
    }
  }
  if (*ack.largestNewlyAckedPacket >= hystartRoundEndPacketNum_) {
    onHystartRoundEnd();
  }
}

void Cuback::onHystartRoundEnd() {
  // The round in which CSS started counts toward its rounds.
  if (state_ == State::ConservativeSlowStart && ++cssRounds_ >= kCssRounds) {
    ssthreshBytes_ = cwndBytes_;
    epoch_.cwndPrior = static_cast<double>(cwndBytes_);
    enterCongestionAvoidance(kCssRoundsTrigger);
    return;
  }
  startHystartRound();
}

void Cuback::startHystartRound() {
  lastRoundMinRtt_ = currentRoundMinRtt_;
  currentRoundMinRtt_ = std::chrono::microseconds::max();
  rttSampleCount_ = 0;
  hystartRoundEndPacketNum_ = nextPacketNum();
}

void Cuback::growInCongestionAvoidance(uint64_t ackedBytes) {
  const uint64_t maxCwnd =
      conn_.transportSettings.maxCwndInMss * conn_.udpSendPacketLen;
  if (ackedBytes == 0 || cwndBytes_ >= maxCwnd) {
    return;
  }
  pendingBytes_ += ackedBytes;
  while (pendingBytes_ >= increaseBytes()) {
    pendingBytes_ -= increaseBytes();
    setCwnd(cwndBytes_ + conn_.udpSendPacketLen);
    if (cwndBytes_ >= maxCwnd) {
      pendingBytes_ = 0;
      return;
    }
  }
}

void Cuback::enterCongestionAvoidance(std::string_view trigger) {
  // Without a reduction, the epoch starts at W_max, so K is zero.
  epoch_.wMax = static_cast<double>(cwndBytes_);
  epoch_.cwndEpoch = static_cast<double>(cwndBytes_);
  epoch_.bandwidth = bandwidth(cwndBytes_);
  pendingBytes_ = 0;
  increaseBytes_.reset();
  setState(State::CongestionAvoidance, trigger);
}

Optional<Cuback::UndoState> Cuback::undoState(const LossEvent& loss) const {
  // While losses of an earlier event are pending, the spurious ACK counts of
  // the two events are indistinguishable.
  if (!conn_.transportSettings.ccaConfig.enableSpuriousLossRecovery ||
      conn_.outstandings.declaredLostCount != loss.lostPackets) {
    return std::nullopt;
  }
  return UndoState{
      .cwndBytes = cwndBytes_,
      .ssthreshBytes = ssthreshBytes_,
      .epoch = epoch_,
      .pendingBytes = pendingBytes_,
      .state = state_,
      .recoveryEndPacketNum = recoveryEndPacketNum_,
      .lostPackets = loss.lostPackets};
}

bool Cuback::isCwndLimited(const AckEvent& ack) const {
  return std::ranges::any_of(ack.ackedPackets, [this](const auto& packet) {
    return packet.packetNum < cwndLimitedEndPacketNum_;
  });
}

uint64_t Cuback::ackedBytesAfterRecovery(const AckEvent& ack) const {
  uint64_t bytes = 0;
  for (const auto& packet : ack.ackedPackets) {
    if (packet.packetNum >= recoveryEndPacketNum_) {
      bytes += packet.outstandingPacketMetadata.encodedSize;
    }
  }
  return bytes;
}

uint64_t Cuback::increaseBytes() {
  if (!increaseBytes_) {
    // Without an RTT sample the epoch's bandwidth is unknown, and cwnd grows
    // like Reno.
    const double bytes = epoch_.bandwidth > 0
        ? cubackIncreaseBytes(
              epoch_,
              static_cast<double>(cwndBytes_),
              static_cast<double>(conn_.udpSendPacketLen))
        : static_cast<double>(cwndBytes_);
    increaseBytes_ = static_cast<uint64_t>(std::ceil(bytes));
  }
  return *increaseBytes_;
}

double Cuback::bandwidth(uint64_t window) const {
  if (conn_.lossState.srtt == 0us) {
    return 0;
  }
  return static_cast<double>(window) * 1'000'000 /
      static_cast<double>(conn_.lossState.srtt.count());
}

PacketNum Cuback::nextPacketNum() const {
  return conn_.ackStates.appDataAckState.nextPacketNum;
}

void Cuback::setCwnd(uint64_t cwndBytes) {
  cwndBytes_ = boundedCwnd(
      cwndBytes,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);
  increaseBytes_.reset();
}

void Cuback::setPacingRate() {
  if (conn_.pacer) {
    conn_.pacer->refreshPacingRate(
        cwndBytes_ * kPacingGain, conn_.lossState.srtt);
  }
}

void Cuback::setState(State state, std::string_view trigger) {
  if (state == state_) {
    return;
  }
  QLOG(
      conn_,
      addCongestionStateUpdate,
      std::string(cubackStateToString(state_)),
      std::string(cubackStateToString(state)),
      std::string(trigger));
  state_ = state;
}

std::string_view cubackStateToString(Cuback::State state) {
  switch (state) {
    case Cuback::State::SlowStart:
      return "SlowStart";
    case Cuback::State::ConservativeSlowStart:
      return "ConservativeSlowStart";
    case Cuback::State::Recovery:
      return "Recovery";
    case Cuback::State::CongestionAvoidance:
      return "CongestionAvoidance";
  }
  folly::assume_unreachable();
}

} // namespace quic
