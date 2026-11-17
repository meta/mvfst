/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/common/Optional.h>
#include <quic/state/OutstandingPacket.h>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>
#include <vector>

namespace quic {

// Helper struct to group multiple lost packets into one event.
struct LossEvent {
  struct LostPacket {
    PacketNum packetNum{0};
    uint64_t encodedSize{0};
  };

  // Non-owning view over the packet numbers in lostPacketDetails. Do not store
  // this beyond the lifetime of the LossEvent that produced it.
  class LostPacketNumbers {
   public:
    class Iterator {
     public:
      using iterator_category = std::input_iterator_tag;
      using value_type = PacketNum;
      using difference_type = std::ptrdiff_t;
      using pointer = void;
      using reference = PacketNum;

      explicit Iterator(std::vector<LostPacket>::const_iterator it) : it_(it) {}

      PacketNum operator*() const {
        return it_->packetNum;
      }

      Iterator& operator++() {
        ++it_;
        return *this;
      }

      bool operator!=(const Iterator& other) const {
        return it_ != other.it_;
      }

      bool operator==(const Iterator& other) const {
        return it_ == other.it_;
      }

     private:
      std::vector<LostPacket>::const_iterator it_;
    };

    using value_type = PacketNum;
    using difference_type = std::ptrdiff_t;
    using iterator = Iterator;
    using const_iterator = Iterator;
    using reference = PacketNum;
    using const_reference = PacketNum;

    explicit LostPacketNumbers(const std::vector<LostPacket>& lostPackets)
        : lostPackets_(lostPackets) {}

    [[nodiscard]] Iterator begin() const {
      return Iterator(lostPackets_.begin());
    }

    [[nodiscard]] Iterator end() const {
      return Iterator(lostPackets_.end());
    }

   private:
    const std::vector<LostPacket>& lostPackets_;
  };

  Optional<PacketNum> largestLostPacketNum;
  std::vector<LostPacket> lostPacketDetails;
  uint64_t lostBytes{0};
  uint32_t lostPackets{0};
  const TimePoint lossTime;
  // The packet sent time of the lost packet with largest packet sent time in
  // this LossEvent.
  Optional<TimePoint> largestLostSentTime;
  // The packet sent time of the lost packet with smallest packet sent time in
  // this LossEvent.
  Optional<TimePoint> smallestLostSentTime;
  // Whether this LossEvent also indicates persistent congestion.
  bool persistentCongestion{false};
  // Loss detection runs per packet number space, so all the lost packets share
  // this space.
  Optional<PacketNumberSpace> packetNumberSpace;

  explicit LossEvent(TimePoint time = Clock::now()) : lossTime(time) {}

  [[nodiscard]] LostPacketNumbers lostPacketNumbers() const {
    return LostPacketNumbers(lostPacketDetails);
  }

  void addLostPacket(const OutstandingPacketWrapper& packet) {
    if (std::numeric_limits<uint64_t>::max() - lostBytes <
        packet.metadata.encodedSize) {
      throw QuicInternalException(
          "LossEvent: lostBytes overflow", LocalErrorCode::LOST_BYTES_OVERFLOW);
    }
    PacketNum packetNum = packet.packet.header.getPacketSequenceNum();
    packetNumberSpace = packet.packet.header.getPacketNumberSpace();
    largestLostPacketNum =
        std::max(packetNum, largestLostPacketNum.value_or(packetNum));
    lostPacketDetails.push_back(
        {.packetNum = packetNum, .encodedSize = packet.metadata.encodedSize});
    lostBytes += packet.metadata.encodedSize;
    lostPackets++;
    largestLostSentTime = std::max(
        packet.metadata.time,
        largestLostSentTime.value_or(packet.metadata.time));
    smallestLostSentTime = std::min(
        packet.metadata.time,
        smallestLostSentTime.value_or(packet.metadata.time));
  }
};

} // namespace quic
