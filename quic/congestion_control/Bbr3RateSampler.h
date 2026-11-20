/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/CircularDeque.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/state/AckEvent.h>
#include <quic/state/LossEvent.h>
#include <quic/state/StateData.h>

#include <chrono>
#include <cstdint>

namespace quic {

// The rate sample ("RS") that BBRv3 builds for each ACK.
struct Bbr3RateSample {
  uint64_t newlyAcked{0};
  // False when the ACK did not newly acknowledge a packet with a nonzero
  // encoded size.
  bool hasData{false};
  // C.delivered when the newest acknowledged packet was sent.
  uint64_t priorDelivered{0};
  uint64_t delivered{0};
  std::chrono::microseconds interval{0};
  // Zero when the interval is zero.
  Bandwidth deliveryRate{};
  bool isAppLimited{false};
  // C.inflight when the newest acknowledged packet was sent, including it.
  uint64_t txInFlight{0};
  // Bytes sent on the connection through the newest acknowledged packet.
  uint64_t totalSent{0};
  // Bytes declared lost since the newest acknowledged packet was sent.
  uint64_t lost{0};
  OptionalMicros rtt;
};

// The send state of a declared-lost packet, for BBRv3's per-packet loss
// response.
struct Bbr3LostPacketSample {
  uint64_t size{0};
  uint64_t txInFlight{0};
  bool isAppLimited{false};
};

// Builds BBRv3 rate samples from the send state that the transport already
// records for each packet. The transport does not count lost bytes per packet,
// so this keeps the cumulative lost bytes (C.lost) and recovers each packet's
// value at send time from checkpoints keyed by total bytes sent.
//
// Packets that are acknowledged after being declared lost are left out of the
// acknowledged packets and the delivered bytes, so they never produce a sample.
class Bbr3RateSampler {
 public:
  explicit Bbr3RateSampler(const QuicConnectionStateBase& conn);

  void onPacketSent(const OutstandingPacketWrapper& packet);

  // Adds a lost packet to C.lost. Report an event's lost packets before the
  // event's ACK. Returns the packet's send state when withSendState is true and
  // the transport still tracks the packet.
  Optional<Bbr3LostPacketSample> onPacketLost(
      const LossEvent::LostPacket& lostPacket,
      PacketNumberSpace space,
      bool withSendState);

  // Samples whose interval starts before appLimitedMark, the time of the
  // latest app-limited mark, are app-limited.
  [[nodiscard]] Bbr3RateSample onAck(
      const AckEvent& ack,
      Optional<TimePoint> appLimitedMark);

  [[nodiscard]] uint64_t totalLost() const noexcept {
    return totalLost_;
  }

 private:
  struct LossCheckpoint {
    uint64_t totalBytesSent{0};
    uint64_t totalLost{0};
  };

  [[nodiscard]] Bbr3RateSample sampleAck(
      const AckEvent& ack,
      Optional<TimePoint> appLimitedMark) const;
  [[nodiscard]] const OutstandingPacketWrapper* findLostPacket(
      const LossEvent::LostPacket& lostPacket,
      PacketNumberSpace space) const;
  [[nodiscard]] uint64_t lostAtSend(uint64_t packetTotalBytesSent) const;
  [[nodiscard]] uint64_t oldestTrackedBytesSent() const;
  void prune();

  const QuicConnectionStateBase& conn_;
  uint64_t totalLost_{0};
  // C.lost before the oldest retained checkpoint.
  uint64_t lostBeforeCheckpoints_{0};
  CircularDeque<LossCheckpoint> lossCheckpoints_;
  // Send time of the latest packet sent while nothing else was in flight.
  Optional<TimePoint> restartTime_;
  Optional<PacketNum> largestHandshakePacketNum_;
};

} // namespace quic
