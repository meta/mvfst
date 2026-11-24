/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/PacketProcessor.h>
#include <quic/state/StateData.h>

namespace quic {

// This class tracks the L4S weight (alpha) according to the latest Prague
// Congestion Control Draft
// (https://datatracker.ietf.org/doc/draft-briscoe-iccrg-prague-congestion-control/)
class EcnL4sTracker : public PacketProcessor {
 public:
  explicit EcnL4sTracker(QuicConnectionStateBase& conn);

  void onPacketAck(const AckEvent* FOLLY_NULLABLE /* ackEvent */) override;

  // The latest l4s weight calculated by the tracker.
  [[nodiscard]] double getL4sWeight() const;

  // The latest l4s weight normalized by the RTT. This is the value
  // the congestion controller uses to react to the ECN markings once per RTT.
  [[nodiscard]] double getNormalizedL4sWeight() const;

  // The period of the weight updates: srtt, but at least 25ms.
  [[nodiscard]] std::chrono::microseconds getRttVirt() const;

  // Measures the weight anew from `now`. The first update after this sets the
  // weight to the CE fraction since `now`. From then on, a first CE mark does
  // not set the weight to 1.
  void restart(TimePoint now);

  // Whether the first update after restart() is still to come.
  [[nodiscard]] bool isRestarting() const;

 private:
  QuicConnectionStateBase& conn_;
  std::chrono::microseconds rttVirt_;

  double l4sWeight_{0.0};
  TimePoint lastUpdateTime_{Clock::now()};
  uint64_t lastECT1Echoed_{0};
  uint64_t lastCEEchoed_{0};
  bool restarted_{false};
  bool restarting_{false};
};

} // namespace quic
