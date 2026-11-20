/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr3RateSampler.h>

#include <algorithm>
#include <iterator>

namespace quic {

namespace {

bool isNewerPacket(
    const AckEvent::AckPacket& lhs,
    const AckEvent::AckPacket& rhs) {
  const auto lhsTime = lhs.outstandingPacketMetadata.time;
  const auto rhsTime = rhs.outstandingPacketMetadata.time;
  return lhsTime > rhsTime ||
      (lhsTime == rhsTime && lhs.packetNum > rhs.packetNum);
}

PacketNum packetNumOf(const OutstandingPacketWrapper& packet) {
  return packet.packet.header.getPacketSequenceNum();
}

} // namespace

Bbr3RateSampler::Bbr3RateSampler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

void Bbr3RateSampler::onPacketSent(const OutstandingPacketWrapper& packet) {
  if (packet.packet.header.getPacketNumberSpace() !=
      PacketNumberSpace::AppData) {
    largestHandshakePacketNum_ =
        std::max(packetNumOf(packet), largestHandshakePacketNum_.value_or(0));
  }
  // A packet sent with nothing else in flight starts a new delivery interval.
  // Declared-lost packets do not count, because one that is acknowledged later
  // is left out of the samples.
  if (packet.metadata.inflightBytes == packet.metadata.encodedSize) {
    restartTime_ = packet.metadata.time;
  }
}

Optional<Bbr3LostPacketSample> Bbr3RateSampler::onPacketLost(
    const LossEvent::LostPacket& lostPacket,
    PacketNumberSpace space,
    bool withSendState) {
  totalLost_ += lostPacket.encodedSize;
  const auto totalBytesSent = conn_.lossState.totalBytesSent;
  if (!lossCheckpoints_.empty() &&
      lossCheckpoints_.back().totalBytesSent == totalBytesSent) {
    lossCheckpoints_.back().totalLost = totalLost_;
  } else {
    lossCheckpoints_.push_back(
        {.totalBytesSent = totalBytesSent, .totalLost = totalLost_});
  }

  if (!withSendState) {
    return std::nullopt;
  }
  const auto* packet = findLostPacket(lostPacket, space);
  if (!packet) {
    return std::nullopt;
  }
  return Bbr3LostPacketSample{
      .size = packet->metadata.encodedSize,
      .txInFlight = packet->metadata.inflightBytes,
      .isAppLimited = packet->isAppLimited,
  };
}

Bbr3RateSample Bbr3RateSampler::onAck(
    const AckEvent& ack,
    Optional<TimePoint> appLimitedMark) {
  // Implicit ACKs remove packets whose keys were dropped. They were not
  // delivered.
  if (ack.implicit) {
    return {};
  }
  auto sample = sampleAck(ack, appLimitedMark);
  prune();
  return sample;
}

Bbr3RateSample Bbr3RateSampler::sampleAck(
    const AckEvent& ack,
    Optional<TimePoint> appLimitedMark) const {
  Bbr3RateSample sample;
  sample.newlyAcked = ack.ackedBytes;
  sample.rtt = ack.rttSample;

  const AckEvent::AckPacket* newest = nullptr;
  for (const auto& ackedPacket : ack.ackedPackets) {
    if (ackedPacket.outstandingPacketMetadata.encodedSize == 0) {
      continue;
    }
    if (!newest || isNewerPacket(ackedPacket, *newest)) {
      newest = &ackedPacket;
    }
  }
  if (!newest) {
    return sample;
  }

  // The ACK elapsed time is measured between ACK times with the ACK delay
  // removed when it starts at an earlier ACK. When it starts at a send time,
  // there is no ACK delay to cancel, so it ends at the raw ACK time.
  const auto& metadata = newest->outstandingPacketMetadata;
  const auto& lastAcked = newest->lastAckedPacketInfo;
  auto firstSendTime = conn_.connectionTime;
  auto deliveredTime = conn_.connectionTime;
  auto ackTime = ack.ackTime;
  if (lastAcked) {
    firstSendTime = lastAcked->sentTime;
    deliveredTime = lastAcked->adjustedAckTime;
    ackTime = ack.adjustedAckTime;
  }
  if (restartTime_ && *restartTime_ <= metadata.time &&
      *restartTime_ > deliveredTime) {
    firstSendTime = *restartTime_;
    deliveredTime = *restartTime_;
    ackTime = ack.ackTime;
  }

  sample.hasData = true;
  sample.priorDelivered = lastAcked ? lastAcked->totalBytesAcked : 0;
  sample.delivered = ack.totalBytesAcked > sample.priorDelivered
      ? ack.totalBytesAcked - sample.priorDelivered
      : 0;
  sample.isAppLimited = newest->isAppLimited ||
      (appLimitedMark && firstSendTime < *appLimitedMark);
  sample.txInFlight = metadata.inflightBytes;
  sample.totalSent = metadata.totalBytesSent;
  sample.lost = totalLost_ - lostAtSend(metadata.totalBytesSent);

  const auto sendElapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(
          metadata.time - firstSendTime);
  const auto ackElapsed = std::chrono::duration_cast<std::chrono::microseconds>(
      ackTime - deliveredTime);
  sample.interval = std::max(sendElapsed, ackElapsed);
  // Like bbr2 and QUICHE, this keeps samples shorter than the minimum RTT,
  // which the draft's pseudocode drops for TCP's ambiguous ACKs. They are rare
  // here, since the interval covers at least one packet's RTT.
  if (sample.interval > std::chrono::microseconds::zero()) {
    sample.deliveryRate =
        Bandwidth(sample.delivered, sample.interval, sample.isAppLimited);
  }
  return sample;
}

const OutstandingPacketWrapper* Bbr3RateSampler::findLostPacket(
    const LossEvent::LostPacket& lostPacket,
    PacketNumberSpace space) const {
  // Loss detection keeps declared-lost packets in the outstanding packets so
  // that it can recognize spurious losses. They are sorted by packet number.
  // Each packet number space has its own packet numbers, so the same number can
  // appear once per space.
  const auto& packets = conn_.outstandings.packets;
  auto it = std::lower_bound(
      packets.begin(),
      packets.end(),
      lostPacket.packetNum,
      [](const OutstandingPacketWrapper& packet, PacketNum packetNum) {
        return packetNumOf(packet) < packetNum;
      });
  for (; it != packets.end() && packetNumOf(*it) == lostPacket.packetNum;
       ++it) {
    if (it->declaredLost && it->packet.header.getPacketNumberSpace() == space) {
      return &*it;
    }
  }
  return nullptr;
}

uint64_t Bbr3RateSampler::lostAtSend(uint64_t packetTotalBytesSent) const {
  // A checkpoint taken after a packet was sent has a total bytes sent of at
  // least the packet's own value, which includes the packet.
  auto it = std::lower_bound(
      lossCheckpoints_.begin(),
      lossCheckpoints_.end(),
      packetTotalBytesSent,
      [](const LossCheckpoint& checkpoint, uint64_t value) {
        return checkpoint.totalBytesSent < value;
      });
  return it == lossCheckpoints_.begin() ? lostBeforeCheckpoints_
                                        : std::prev(it)->totalLost;
}

uint64_t Bbr3RateSampler::oldestTrackedBytesSent() const {
  // Initial and Handshake packets can sort behind AppData packets that were
  // sent after them. Past the largest Initial or Handshake packet number, only
  // AppData packets remain, in send order.
  uint64_t oldest = conn_.lossState.totalBytesSent + 1;
  for (const auto& packet : conn_.outstandings.packets) {
    oldest = std::min(oldest, packet.metadata.totalBytesSent);
    if (!largestHandshakePacketNum_ ||
        packetNumOf(packet) > *largestHandshakePacketNum_) {
      break;
    }
  }
  return oldest;
}

void Bbr3RateSampler::prune() {
  // Only packets the transport still tracks can be sampled.
  const auto oldestTracked = oldestTrackedBytesSent();
  while (!lossCheckpoints_.empty() &&
         lossCheckpoints_.front().totalBytesSent < oldestTracked) {
    lostBeforeCheckpoints_ = lossCheckpoints_.front().totalLost;
    lossCheckpoints_.pop_front();
  }
}

} // namespace quic
