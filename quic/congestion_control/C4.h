/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/StateData.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace quic {

// C4 congestion control, as specified in draft-huitema-ccwg-c4-spec-05.
class C4CongestionController : public CongestionController {
 public:
  enum class State : uint8_t {
    Initial = 0,
    Recovery = 1,
    Cruising = 2,
    Probing = 3,
    Pushing = 4,
  };

  explicit C4CongestionController(QuicConnectionStateBase& conn);

  void onRemoveBytesFromInflight(uint64_t bytesToRemove) override;

  void onPacketSent(const OutstandingPacketWrapper& packet) override;

  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override;

  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override;

  [[nodiscard]] CongestionControlType type() const noexcept override;

  [[nodiscard]] bool isAppLimited() const override;

  [[nodiscard]] Optional<Bandwidth> getBandwidth() const override;

  [[nodiscard]] uint64_t getBDP() const override;

  void setAppLimited() noexcept override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  void getStats(CongestionControllerStats& stats) const override;

  [[nodiscard]] State getState() const noexcept;

 private:
  enum class Signal : uint8_t { None, Delay, Loss, Ecn };
  enum class Growth : uint8_t { None, Slow, Fast };

  struct DeliveryCheckpoint {
    uint64_t totalBytesAcked;
    TimePoint adjustedAckTime;
    TimePoint sentTime;
  };

  void onRttSample(const AckEvent& ackEvent);
  void onAck(const AckEvent& ackEvent);
  void onLostPacket(PacketNum packetNum);
  void onEcnCounts();
  void updateRate(const AckEvent& ackEvent);
  void updatePeakRate(const AckEvent& ackEvent);
  void updateLossRate(PacketNum packetNum);
  void updateEcnAlpha();
  void updateMaxRtt();
  void maybeExitAppLimited(const AckEvent& ackEvent);
  void notifyCongestion(Signal signal);

  void enterInitial();
  void exitInitial(Signal signal);
  [[nodiscard]] bool canExitInitialOnSignal() const;
  void onInitialAck(uint64_t ackedBytes, bool eraEnded);
  void enterRecovery(Signal signal, std::string_view trigger);
  void exitRecovery(TimePoint now);
  void updateRatesWithoutGrowth();
  void enterCruising();
  void enterProbing();
  void enterPushing();
  void onEraEnd(TimePoint now);
  [[nodiscard]] bool shouldReenterInitial(TimePoint now) const;

  void resetEra();
  void resetGrowth();
  [[nodiscard]] Growth evaluateGrowth() const;

  [[nodiscard]] float sensitivity() const;
  [[nodiscard]] std::chrono::microseconds delayThreshold() const;
  [[nodiscard]] float lossThreshold() const;
  [[nodiscard]] float ecnThreshold() const;
  [[nodiscard]] PacketNum nextPacketNum() const;

  void setCwndAndPacing(TimePoint eventTime);
  [[nodiscard]] bool shouldPace() const;
  [[nodiscard]] bool burstFitsRtt() const;
  [[nodiscard]] uint64_t minBurstBytes() const;
  void setState(State state, std::string_view trigger);
  [[nodiscard]] static std::string_view triggerName(Signal signal);

  QuicConnectionStateBase& conn_;
  State state_{State::Initial};
  uint64_t cwndBytes_;
  Bandwidth pacingRate_;

  Bandwidth nominalRate_;
  std::chrono::microseconds nominalMaxRtt_{0us};
  float pacingGain_{1.0};
  // Pacing gain when the current era started.
  float eraPacingGain_{1.0};

  Bandwidth rateEstimate_;
  TimePoint rateEstimateSentTime_;
  Optional<DeliveryCheckpoint> peakCheckpoint_;
  Bandwidth peakRate_;
  Bandwidth recentMaxRate_;
  Bandwidth previousMaxRate_;

  std::chrono::microseconds latestRtt_{0us};
  std::chrono::microseconds runningMinRtt_{std::chrono::microseconds::max()};
  std::chrono::microseconds eraMaxRtt_{0us};
  std::chrono::microseconds eraMinRtt_{std::chrono::microseconds::max()};
  std::chrono::microseconds delayExcess_{0us};

  PacketNum eraStartPacketNum_{0};
  // First packet of the latest Recovery era. Losses of earlier packets do not
  // count, even when they are declared after Recovery ends.
  PacketNum recoveryStartPacketNum_{0};
  Bandwidth growthBaseRate_;
  float growthGain_{1.0};
  bool congestionNotified_{false};
  bool rateWasNotLimited_{false};

  uint64_t initialCwnd_{0};
  uint64_t initialEvents_{0};
  uint64_t erasWithoutGrowth_{0};
  // Set when Recovery first ends after entering Initial.
  Optional<TimePoint> initialExitTime_;

  // Queue left by Initial or by the last push, as a fraction of an era.
  float backlog_{0};
  uint64_t probeLevel_{1};
  uint64_t cruiseErasLeft_{0};
  uint64_t recentCongestions_{0};
  // CE marks started the current Recovery or signaled congestion during it.
  bool excessCe_{false};

  float smoothedLossRate_{0};
  PacketNum lastLostPacketNum_{0};

  // Average fraction of CE among the ECT(1) and CE marks.
  float ecnAlpha_{0};
  // Echoed ECT(1) and CE counts at the last alpha update.
  uint64_t ecnEct1Count_{0};
  uint64_t ecnCeCount_{0};

  bool appLimited_{false};
  PacketNum appLimitedPacketNum_{0};
};

std::string c4StateToString(C4CongestionController::State state);

} // namespace quic
