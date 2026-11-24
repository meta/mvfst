/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/state/StateData.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <string_view>

namespace quic {

// The congestion avoidance parameters that stay fixed until the next
// congestion event. Windows are in bytes and the bandwidth in bytes per second.
struct CubackEpoch {
  double wMax{0};
  double cwndPrior{0};
  double cwndEpoch{0};
  double bandwidth{0};
};

// Bytes that have to be acknowledged, counted from the start of the epoch, for
// the window to reach w.
[[nodiscard]] double
cubackAckedBytes(const CubackEpoch& epoch, double w, double smss);

// Bytes that have to be acknowledged for the window to grow from w by one SMSS.
[[nodiscard]] double
cubackIncreaseBytes(const CubackEpoch& epoch, double w, double smss);

// Cuback, as specified in draft-kazuho-ccwg-cuback-01: CUBIC (RFC 9438) whose
// congestion avoidance is driven by acknowledged bytes. Slow start is HyStart++
// (RFC 9406). On an L4S path, its response to CE marks follows Prague
// (draft-briscoe-iccrg-prague-congestion-control-04).
class Cuback : public CongestionController {
 public:
  enum class State : uint8_t {
    SlowStart = 0,
    ConservativeSlowStart = 1,
    Recovery = 2,
    CongestionAvoidance = 3,
  };

  explicit Cuback(QuicConnectionStateBase& conn);

  void onRemoveBytesFromInflight(uint64_t bytesToRemove) override;

  void onPacketSent(const OutstandingPacketWrapper& packet) override;

  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) override;

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override;

  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override;

  [[nodiscard]] CongestionControlType type() const noexcept override;

  [[nodiscard]] bool isAppLimited() const noexcept override;

  void setAppLimited() noexcept override;

  void setAppIdle(bool, TimePoint) noexcept override {}

  void getStats(CongestionControllerStats& stats) const override;

  [[nodiscard]] State getState() const noexcept;

 private:
  // The state before the latest loss-triggered congestion event, kept until
  // its losses turn out spurious or real.
  struct UndoState {
    uint64_t cwndBytes;
    uint64_t ssthreshBytes;
    CubackEpoch epoch;
    uint64_t pendingBytes;
    State state;
    PacketNum recoveryEndPacketNum;
    bool l4sEpoch;
    // Packets of the event that are declared lost and not acknowledged.
    uint64_t lostPackets;
  };

  void onSpuriousLosses(const AckEvent& ack);
  void onEcnCounts(const AckEvent& ack);
  void onL4sCe(const AckEvent& ack);
  void endL4sEpoch();
  void onLoss(const LossEvent& loss);
  void onAck(const AckEvent& ack);
  void restartL4sWeight(const AckEvent& ack);
  void onCongestionEvent(std::string_view trigger);
  void onPersistentCongestion();

  void onSlowStartAck(const AckEvent& ack, uint64_t ackedBytes, bool grow);
  void onHystartRoundEnd();
  void startHystartRound();
  void growInCongestionAvoidance(uint64_t ackedBytes);
  void enterCongestionAvoidance(std::string_view trigger);

  [[nodiscard]] Optional<UndoState> undoState(const LossEvent& loss) const;
  [[nodiscard]] bool isCwndLimited(const AckEvent& ack) const;
  [[nodiscard]] uint64_t ackedBytesAfterRecovery(const AckEvent& ack) const;
  [[nodiscard]] uint64_t unmarkedBytes(uint64_t ackedBytes) const;
  [[nodiscard]] bool isL4s() const;
  [[nodiscard]] uint64_t increaseBytes();
  [[nodiscard]] double bandwidth(uint64_t window) const;
  [[nodiscard]] PacketNum nextPacketNum() const;

  void setCwnd(uint64_t cwndBytes);
  void setPacingRate();
  void setState(State state, std::string_view trigger);

  QuicConnectionStateBase& conn_;
  State state_{State::SlowStart};
  uint64_t cwndBytes_;
  uint64_t ssthreshBytes_{std::numeric_limits<uint64_t>::max()};

  CubackEpoch epoch_;
  uint64_t pendingBytes_{0};
  // The bytes that the next increase consumes, until cwnd changes.
  Optional<uint64_t> increaseBytes_;

  // Losses of packets below this number and ACKs of them belong to the latest
  // congestion event.
  PacketNum recoveryEndPacketNum_{0};
  // ACKs of packets below this number count as cwnd limited. It is the max
  // value while the sender is cwnd limited.
  PacketNum cwndLimitedEndPacketNum_{0};
  bool appLimited_{false};
  uint64_t ecnCeCount_{0};
  uint64_t ecnEct1Count_{0};
  // The marks that the latest ACK added to the echoed counts.
  uint64_t newCeMarks_{0};
  uint64_t newEct1Marks_{0};
  // Set by a reduction on L4S marks and cleared by a loss. While set, cwnd
  // grows by Prague's additive increase.
  bool l4sEpoch_{false};
  // L4S marks before this time do not reduce cwnd.
  TimePoint ignoreCeUntil_;
  // Set when slow start ends. The first ACK in congestion avoidance then
  // restarts the tracker's weight, so that the marks of slow start's overshoot
  // do not count toward it.
  bool l4sRestartPending_{false};
  Optional<UndoState> undo_;

  PacketNum hystartRoundEndPacketNum_{0};
  std::chrono::microseconds lastRoundMinRtt_{std::chrono::microseconds::max()};
  std::chrono::microseconds currentRoundMinRtt_{
      std::chrono::microseconds::max()};
  std::chrono::microseconds cssBaselineMinRtt_{
      std::chrono::microseconds::max()};
  uint64_t rttSampleCount_{0};
  uint64_t cssRounds_{0};
};

std::string_view cubackStateToString(Cuback::State state);

} // namespace quic
