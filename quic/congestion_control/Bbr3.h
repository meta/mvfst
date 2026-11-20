/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/Bbr3RateSampler.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>

namespace quic {

// BBRv3, as specified in draft-ietf-ccwg-bbr.
class Bbr3CongestionController : public CongestionController {
  friend class Bbr3TestPeer;

 public:
  // The values match Bbr2CongestionController::State for stats.
  enum class State : uint8_t {
    Startup = 0,
    Drain = 1,
    ProbeBwDown = 2,
    ProbeBwCruise = 3,
    ProbeBwRefill = 4,
    ProbeBwUp = 5,
    ProbeRtt = 6,
  };

  using RandomFn = std::function<uint32_t()>;

  explicit Bbr3CongestionController(QuicConnectionStateBase& conn);
  Bbr3CongestionController(QuicConnectionStateBase& conn, RandomFn random);

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

  void getStats(CongestionControllerStats& stats) const override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  [[nodiscard]] State getState() const noexcept;

 private:
  // The draft's undo_state.
  enum class UndoTarget : uint8_t {
    None,
    Startup,
    ProbeBwUp,
  };

  // The cwnd and bounds from before a loss episode, restored if every loss in
  // it turns out to be spurious.
  struct LossEpisode {
    uint64_t priorCwnd{0};
    Optional<Bandwidth> bwShortTerm;
    Optional<uint64_t> inflightShortTerm;
    Optional<uint64_t> inflightLongTerm;
    UndoTarget undoTarget{UndoTarget::None};
    uint64_t pendingLostPackets{0};
    // The newest send time when the episode started.
    TimePoint start;
  };

  // Counts loss events as discontiguous ranges of lost packet numbers. Like
  // bbr2, bbr3 counts them this way, which matches TCP's fast recovery loss
  // events better than single packets do. A contiguous run counts once however
  // long it is. Packet numbers that never become outstanding, such as those of
  // ACK-only packets, can split one burst into two ranges. Each packet number
  // space has its own packet numbers, so ranges are tracked per space.
  struct LostRangeCounter {
    uint64_t count{0};
    EnumArray<PacketNumberSpace, Optional<PacketNum>> largest{};

    void add(PacketNumberSpace space, PacketNum packetNum);
    void reset();
  };

  void onLoss(const LossEvent& lossEvent, TimePoint now);
  void onAck(const AckEvent& ackEvent, TimePoint now, uint64_t priorInflight);
  void handleLostPacket(
      const LossEvent::LostPacket& lostPacket,
      PacketNumberSpace space,
      TimePoint now);
  void onPersistentCongestion();
  void updateRecoveryOnAck(const AckEvent& ackEvent);

  void updateLossEpisode(const LossEvent& lossEvent);
  // Returns true if it undid the episode's loss response.
  bool resolveLossEpisode(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent);
  void handleSpuriousLossDetection(const LossEpisode& episode);

  void handleRestartFromIdle(TimePoint now);
  void markAppLimited();

  void updateModelAndState(
      const Bbr3RateSample& rs,
      TimePoint now,
      uint64_t priorInflight);
  void updateControlParameters(const Bbr3RateSample& rs);

  void updateLatestDeliverySignals(const Bbr3RateSample& rs);
  void updateCongestionSignals(const Bbr3RateSample& rs);
  void updateMaxBw(const Bbr3RateSample& rs);
  void updateRound(const Bbr3RateSample& rs);
  void startRound();
  void adaptLowerBoundsFromCongestion();
  void advanceLatestDeliverySignals(const Bbr3RateSample& rs);
  void resetCongestionSignals();
  void resetShortTermModel();
  void boundBwForModel();
  void updateAckAggregation(const Bbr3RateSample& rs, TimePoint now);

  void checkFullBwReached(const Bbr3RateSample& rs);
  void resetFullBw();
  void checkStartupDone(const Bbr3RateSample& rs);
  void checkStartupHighLoss(const Bbr3RateSample& rs);
  void enterStartup();
  void enterDrain();
  void checkDrainDone(TimePoint now);

  void enterProbeBw(TimePoint now);
  void updateProbeBwCyclePhase(
      const Bbr3RateSample& rs,
      TimePoint now,
      uint64_t priorInflight);
  // Returns true if it started REFILL.
  bool adaptLongTermModel(const Bbr3RateSample& rs);
  void startProbeBwDown(TimePoint now);
  void startProbeBwCruise();
  void startProbeBwRefill();
  void startProbeBwUp();
  bool isTimeToProbeBw(TimePoint now);
  [[nodiscard]] bool isTimeToCruise() const;
  bool isTimeToGoDown(uint64_t priorInflight);
  void pickProbeWait();
  [[nodiscard]] bool isRenoCoexistenceProbeTime() const;
  void raiseInflightLongTermSlope();
  void probeInflightLongTermUpward(const Bbr3RateSample& rs);
  void
  handleInflightTooHigh(uint64_t txInFlight, bool isAppLimited, TimePoint now);

  void updateMinRtt(const Bbr3RateSample& rs, TimePoint now);
  void checkProbeRtt(const Bbr3RateSample& rs, TimePoint now);
  void handleProbeRtt(TimePoint now);
  void checkProbeRttDone(TimePoint now);
  void exitProbeRtt(TimePoint now);
  [[nodiscard]] uint64_t probeRttCwnd() const;

  void initPacingRate(std::chrono::microseconds rtt);
  void setPacingRateWithGain(float pacingGain);
  void applyPacingRate();
  void setSendQuantum();
  void setCwnd(uint64_t newlyAcked);
  void boundCwnd();
  void saveCwnd();
  void restoreCwnd();

  [[nodiscard]] uint64_t bdpMultiple(Bandwidth bw, float gain) const;
  [[nodiscard]] uint64_t bdp() const;
  [[nodiscard]] uint64_t targetInflight() const;
  [[nodiscard]] uint64_t inflightWithGain(Bandwidth bw, float gain) const;
  [[nodiscard]] uint64_t inflightWithHeadroom() const;
  [[nodiscard]] uint64_t quantizationBudget(uint64_t inflightCap) const;
  [[nodiscard]] uint64_t maxInflight() const;

  [[nodiscard]] bool isInProbeBwState() const;
  [[nodiscard]] bool isProbingBw() const;
  [[nodiscard]] uint64_t initialCwnd() const;
  [[nodiscard]] uint64_t minPipeCwnd() const;
  void setGains(float pacingGain, float cwndGain);
  void logState() const;

  QuicConnectionStateBase& conn_;
  RandomFn random_;
  Bbr3RateSampler sampler_;

  State state_{State::Startup};
  float pacingGain_{1.0};
  float cwndGain_{1.0};

  // Model of the network path. An empty bound or min RTT is infinite.
  WindowedFilter<Bandwidth, MaxFilter<Bandwidth>, uint64_t, uint64_t>
      maxBwFilter_;
  uint64_t cycleCount_{0};
  Bandwidth bw_;
  Optional<Bandwidth> bwShortTerm_;
  Bandwidth bwLatest_;
  uint64_t inflightLatest_{0};
  Optional<uint64_t> inflightLongTerm_;
  Optional<uint64_t> inflightShortTerm_;
  Optional<std::chrono::microseconds> minRtt_;
  Optional<TimePoint> minRttStamp_;
  bool minRttExpired_{false};
  WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t>
      extraAckedFilter_;
  Optional<TimePoint> extraAckedIntervalStart_;
  uint64_t extraAckedDelivered_{0};

  uint64_t nextRoundDelivered_{0};
  bool roundStart_{false};
  uint64_t roundCount_{0};
  // Bytes and ranges declared lost since the latest startRound() or
  // spurious-loss undo, so entering DOWN, REFILL or UP, and ProbeRTT's early
  // round starts, also clear them. The loss-round counter below restarts at the
  // first loss instead.
  uint64_t bytesLostInRound_{0};
  LostRangeCounter lostRangesInRound_;

  bool fullBwReached_{false};
  bool fullBwNow_{false};
  Bandwidth fullBw_;
  uint64_t fullBwCount_{0};
  // The first round that counts toward the Drain time limit.
  uint64_t drainStartRound_{0};

  TimePoint cycleStamp_;
  std::chrono::microseconds bwProbeWait_{0};
  uint64_t roundsSinceProbeUp_{0};
  uint64_t bwProbeUpRounds_{0};
  uint64_t bwProbeUpAcked_{0};
  uint64_t probeUpAckedPerInc_{std::numeric_limits<uint64_t>::max()};
  bool checkProbeLoss_{false};
  bool prevProbeTooHigh_{false};
  bool prevProbePrecautionary_{false};
  bool isBwProbeStopping_{false};
  // Bytes sent through the newest packet that the current inflight_longterm
  // did not cap: one sent in Startup or Drain, or before a probe's loss cut.
  // Samples of packets sent by then cannot raise inflight_longterm.
  Optional<uint64_t> uncappedSent_;

  bool lossRoundStart_{false};
  uint64_t lossRoundDelivered_{0};
  bool isLossInRound_{false};
  LostRangeCounter lostRangesInLossRound_;

  Optional<TimePoint> probeRttDoneStamp_;
  bool probeRttRoundDone_{false};
  Optional<uint64_t> probeRttCwnd_;
  bool idleRestart_{false};

  uint64_t cwnd_;
  uint64_t priorCwnd_{0};
  Bandwidth pacingRate_;
  bool hasSeenRtt_{false};
  uint64_t sendQuantum_;
  bool cwndLimitedInRound_{false};

  bool inRecovery_{false};
  // The newest send time when recovery started.
  TimePoint recoveryStart_;
  Optional<LossEpisode> lossEpisode_;

  bool appLimited_{false};
  Optional<TimePoint> appLimitedMark_;
  TimePoint lastSendTime_;
};

std::string bbr3StateToString(Bbr3CongestionController::State state);

} // namespace quic
