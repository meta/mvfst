/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr3RateSampler.h>

#include <tuple>

using namespace testing;

namespace quic::test {
namespace {

constexpr uint64_t kPacketSize = 1000;
constexpr TimePoint kStart = TimePoint() + 1000s;

using LastAckedPacketInfo = OutstandingPacketWrapper::LastAckedPacketInfo;

LastAckedPacketInfo
lastAckedInfo(TimePoint sentTime, TimePoint ackTime, uint64_t totalBytesAcked) {
  return LastAckedPacketInfo(
      sentTime, ackTime, ackTime, /*totalBytesSentIn=*/0, totalBytesAcked);
}

LossEvent::LostPacket lostPacket(PacketNum packetNum) {
  return {.packetNum = packetNum, .encodedSize = kPacketSize};
}

class Bbr3RateSamplerTest : public Test {
 protected:
  OutstandingPacketWrapper makePacket(
      PacketNum packetNum,
      TimePoint sentTime,
      uint64_t totalBytesSent,
      Optional<LastAckedPacketInfo> lastAcked = std::nullopt,
      uint64_t inflightBytes = kPacketSize) {
    auto packet = makeTestingWritePacket(
        packetNum,
        kPacketSize,
        totalBytesSent,
        sentTime,
        /*pathId=*/0,
        inflightBytes);
    packet.lastAckedPacketInfo = std::move(lastAcked);
    return packet;
  }

  OutstandingPacketWrapper makeHandshakePacket(
      PacketNum packetNum,
      TimePoint sentTime,
      uint64_t totalBytesSent) {
    LongHeader header(
        LongHeader::Types::Handshake,
        getTestConnectionId(1),
        getTestConnectionId(),
        packetNum,
        QuicVersion::MVFST);
    return OutstandingPacketWrapper(
        RegularQuicWritePacket(std::move(header)),
        sentTime,
        /*pathIdIn=*/0,
        kPacketSize,
        /*encodedBodySizeIn=*/0,
        totalBytesSent,
        /*inflightBytesIn=*/kPacketSize,
        LossState(),
        /*writeCount=*/0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  AckEvent makeAckFor(
      std::initializer_list<OutstandingPacketWrapper*> packets,
      TimePoint ackTime,
      uint64_t totalBytesAcked,
      std::chrono::microseconds ackDelay = 0us) {
    auto ack = AckEvent::Builder()
                   .setAckTime(ackTime)
                   .setAdjustedAckTime(ackTime - ackDelay)
                   .setAckDelay(ackDelay)
                   .setPacketNumberSpace(PacketNumberSpace::AppData)
                   .setLargestAckedPacket(0)
                   .build();
    for (auto* packet : packets) {
      ack.ackedPackets.push_back(
          AckEvent::AckPacket::Builder()
              .setPacketNum(packet->packet.header.getPacketSequenceNum())
              .setOutstandingPacketMetadata(packet->metadata)
              .setLastAckedPacketInfo(
                  packet->lastAckedPacketInfo
                      ? &packet->lastAckedPacketInfo.value()
                      : nullptr)
              .setAppLimited(packet->isAppLimited)
              .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
              .build());
      ack.ackedBytes += packet->metadata.encodedSize;
    }
    ack.totalBytesAcked = totalBytesAcked;
    return ack;
  }

  void detectLoss(uint64_t lostBytes, uint64_t totalBytesSentAtDetection) {
    conn_.lossState.totalBytesSent = totalBytesSentAtDetection;
    sampler_.onPacketLost(
        {.packetNum = 0, .encodedSize = lostBytes},
        PacketNumberSpace::AppData,
        /*withSendState=*/false);
  }

  void sendPacket(OutstandingPacketWrapper packet) {
    conn_.outstandings.packets.push_back(std::move(packet));
    sampler_.onPacketSent(conn_.outstandings.packets.back());
  }

  QuicConnectionStateBase conn_{QuicNodeType::Server};
  Bbr3RateSampler sampler_{conn_};
};

TEST_F(Bbr3RateSamplerTest, SamplesTheNewestAckedPacket) {
  auto older = makePacket(
      2, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  auto newer = makePacket(
      1,
      kStart + 30ms,
      3000,
      lastAckedInfo(kStart + 10ms, kStart + 15ms, 2500));

  auto sample = sampler_.onAck(
      makeAckFor({&older, &newer}, kStart + 50ms, 4000), std::nullopt);

  EXPECT_TRUE(sample.hasData);
  EXPECT_EQ(sample.newlyAcked, 2 * kPacketSize);
  EXPECT_EQ(sample.priorDelivered, 2500);
  EXPECT_EQ(sample.delivered, 1500);
  EXPECT_EQ(sample.totalSent, 3000);
  // The ACK elapsed time (35ms) is longer than the send elapsed time (20ms).
  EXPECT_EQ(sample.interval, 35ms);
  EXPECT_EQ(sample.deliveryRate, Bandwidth(1500, 35ms));
}

TEST_F(Bbr3RateSamplerTest, BreaksSendTimeTiesWithThePacketNumber) {
  auto first = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  auto second = makePacket(
      2, kStart + 20ms, 3000, lastAckedInfo(kStart, kStart + 5ms, 2000));

  auto sample = sampler_.onAck(
      makeAckFor({&second, &first}, kStart + 50ms, 4000), std::nullopt);

  EXPECT_EQ(sample.priorDelivered, 2000);
}

TEST_F(Bbr3RateSamplerTest, UsesTheSendElapsedTimeWhenItIsLonger) {
  auto packet = makePacket(
      1, kStart + 40ms, 2000, lastAckedInfo(kStart, kStart + 30ms, 1000));

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 45ms, 3000), std::nullopt);

  EXPECT_EQ(sample.interval, 40ms);
  EXPECT_EQ(sample.deliveryRate, Bandwidth(2000, 40ms));
}

TEST_F(Bbr3RateSamplerTest, KeepsTheRateWhenTheIntervalIsBelowMinRtt) {
  conn_.lossState.mrtt = 40ms;
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 40ms, 3000), std::nullopt);

  EXPECT_EQ(sample.interval, 35ms);
  EXPECT_EQ(sample.deliveryRate, Bandwidth(2000, 35ms));
}

TEST_F(Bbr3RateSamplerTest, ReportsNoDataWithoutAckedPackets) {
  auto ack = AckEvent::Builder()
                 .setAckTime(kStart)
                 .setAdjustedAckTime(kStart)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();

  auto sample = sampler_.onAck(ack, std::nullopt);

  EXPECT_FALSE(sample.hasData);
  EXPECT_FALSE(sample.deliveryRate);
}

TEST_F(Bbr3RateSamplerTest, IgnoresImplicitAcks) {
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  auto ack = makeAckFor({&packet}, kStart + 40ms, 3000);
  ack.implicit = true;

  auto sample = sampler_.onAck(ack, std::nullopt);

  EXPECT_FALSE(sample.hasData);
  EXPECT_EQ(sample.newlyAcked, 0);
}

TEST_F(Bbr3RateSamplerTest, MarksAppLimitedPackets) {
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  packet.isAppLimited = true;

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 40ms, 3000), std::nullopt);

  EXPECT_TRUE(sample.isAppLimited);
  EXPECT_TRUE(sample.deliveryRate.isAppLimited);
}

TEST_F(Bbr3RateSamplerTest, MarksIntervalsThatStartBeforeTheAppLimitedMark) {
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  const auto ack = makeAckFor({&packet}, kStart + 40ms, 3000);

  EXPECT_TRUE(sampler_.onAck(ack, kStart + 1ms).isAppLimited);
  EXPECT_FALSE(sampler_.onAck(ack, kStart).isAppLimited);
}

TEST_F(Bbr3RateSamplerTest, CountsOnlyLossesDetectedAfterThePacketWasSent) {
  detectLoss(500, 1000);
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  detectLoss(700, 3000);

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 40ms, 3000), std::nullopt);

  EXPECT_EQ(sampler_.totalLost(), 1200);
  EXPECT_EQ(sample.lost, 700);
}

TEST_F(Bbr3RateSamplerTest, CountsLossesDetectedRightAfterThePacketWasSent) {
  // The last packet sent before a loss was detected has the same total bytes
  // sent as the detection point.
  auto packet = makePacket(
      1, kStart + 20ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  detectLoss(500, 2000);

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 40ms, 3000), std::nullopt);

  EXPECT_EQ(sample.lost, 500);
}

TEST_F(Bbr3RateSamplerTest, SamplesDeclaredLostPacketsTheTransportTracks) {
  auto packet =
      makePacket(5, kStart + 20ms, 6000, std::nullopt, /*inflightBytes=*/10000);
  packet.isAppLimited = true;
  packet.declaredLost = true;
  conn_.outstandings.packets.push_back(std::move(packet));
  conn_.lossState.totalBytesSent = 6000;

  auto sample = sampler_.onPacketLost(
      lostPacket(5), PacketNumberSpace::AppData, /*withSendState=*/true);

  ASSERT_TRUE(sample.has_value());
  EXPECT_EQ(sample->size, kPacketSize);
  EXPECT_EQ(sample->txInFlight, 10000);
  EXPECT_TRUE(sample->isAppLimited);
  EXPECT_FALSE(sampler_
                   .onPacketLost(
                       lostPacket(6),
                       PacketNumberSpace::AppData,
                       /*withSendState=*/true)
                   .has_value());
}

TEST_F(Bbr3RateSamplerTest, DoesNotSampleOutstandingPacketsThatAreNotLost) {
  conn_.outstandings.packets.push_back(makePacket(5, kStart, 6000));

  EXPECT_FALSE(sampler_
                   .onPacketLost(
                       lostPacket(5),
                       PacketNumberSpace::AppData,
                       /*withSendState=*/true)
                   .has_value());
}

TEST_F(Bbr3RateSamplerTest, SamplesEachLostPacketFromItsOwnSpace) {
  // Both spaces have a lost packet 5, with different bytes in flight.
  auto handshakePacket = makeHandshakePacket(5, kStart, 1000);
  handshakePacket.declaredLost = true;
  auto appDataPacket =
      makePacket(5, kStart + 1ms, 2000, std::nullopt, /*inflightBytes=*/2000);
  appDataPacket.declaredLost = true;
  conn_.outstandings.packets.push_back(std::move(handshakePacket));
  conn_.outstandings.packets.push_back(std::move(appDataPacket));

  auto handshakeSample = sampler_.onPacketLost(
      lostPacket(5), PacketNumberSpace::Handshake, /*withSendState=*/true);
  auto appDataSample = sampler_.onPacketLost(
      lostPacket(5), PacketNumberSpace::AppData, /*withSendState=*/true);

  ASSERT_TRUE(handshakeSample.has_value());
  EXPECT_EQ(handshakeSample->txInFlight, kPacketSize);
  ASSERT_TRUE(appDataSample.has_value());
  EXPECT_EQ(appDataSample->txInFlight, 2000);
}

TEST_F(Bbr3RateSamplerTest, PruningKeepsCheckpointsTakenAfterTheOldestPacket) {
  // The loss was detected right after the oldest tracked packet was sent.
  sendPacket(makePacket(
      2, kStart + 10ms, 2000, lastAckedInfo(kStart, kStart + 5ms, 1000)));
  detectLoss(200, 2000);
  auto acked = makePacket(
      3, kStart + 30ms, 3000, lastAckedInfo(kStart, kStart + 5ms, 1000));
  std::ignore =
      sampler_.onAck(makeAckFor({&acked}, kStart + 60ms, 2000), std::nullopt);

  auto sample = sampler_.onAck(
      makeAckFor({&conn_.outstandings.packets.front()}, kStart + 70ms, 3000),
      std::nullopt);

  EXPECT_EQ(sample.lost, 200);
}

TEST_F(Bbr3RateSamplerTest, PruningKeepsCheckpointsForOlderHandshakePackets) {
  // AppData packet 0 sorts ahead of Handshake packet 3, which was sent first.
  sendPacket(makeHandshakePacket(3, kStart, 1000));
  detectLoss(500, 1500);
  conn_.outstandings.packets.push_front(makePacket(0, kStart + 10ms, 2000));
  auto acked = makePacket(
      4, kStart + 20ms, 2500, lastAckedInfo(kStart, kStart + 5ms, 1000));
  std::ignore =
      sampler_.onAck(makeAckFor({&acked}, kStart + 60ms, 2000), std::nullopt);

  auto sample = sampler_.onAck(
      makeAckFor({&conn_.outstandings.packets.back()}, kStart + 70ms, 3000),
      std::nullopt);

  EXPECT_EQ(sample.lost, 500);
}

TEST_F(Bbr3RateSamplerTest, RestartsTheIntervalAfterIdle) {
  // The previous ACK arrived long before this packet was sent.
  sendPacket(makePacket(
      1, kStart + 1s, 2000, lastAckedInfo(kStart, kStart + 10ms, 1000)));
  auto& packet = conn_.outstandings.packets.back();

  auto sample = sampler_.onAck(
      makeAckFor({&packet}, kStart + 1030ms, 2000), std::nullopt);

  EXPECT_EQ(sample.interval, 30ms);
  EXPECT_EQ(sample.deliveryRate, Bandwidth(1000, 30ms));
}

TEST_F(Bbr3RateSamplerTest, MeasuresRestartSamplesFromTheRawAckTime) {
  // A restarted interval starts at a send time, so it keeps the ACK delay.
  sendPacket(makePacket(
      1, kStart + 1s, 2000, lastAckedInfo(kStart, kStart + 10ms, 1000)));
  auto& packet = conn_.outstandings.packets.back();

  auto sample = sampler_.onAck(
      makeAckFor({&packet}, kStart + 1030ms, 2000, /*ackDelay=*/10ms),
      std::nullopt);

  EXPECT_EQ(sample.interval, 30ms);
  EXPECT_EQ(sample.deliveryRate, Bandwidth(1000, 30ms));
}

TEST_F(Bbr3RateSamplerTest, RestartsWhileDeclaredLostPacketsAreTracked) {
  auto lost = makePacket(1, kStart + 900ms, 1000);
  lost.declaredLost = true;
  conn_.outstandings.packets.push_back(std::move(lost));
  sendPacket(makePacket(
      2, kStart + 1s, 2000, lastAckedInfo(kStart, kStart + 10ms, 1000)));
  auto& packet = conn_.outstandings.packets.back();

  auto sample = sampler_.onAck(
      makeAckFor({&packet}, kStart + 1030ms, 2000), std::nullopt);

  EXPECT_EQ(sample.interval, 30ms);
}

TEST_F(Bbr3RateSamplerTest, DoesNotRestartWhilePacketsAreInFlight) {
  sendPacket(makePacket(
      2,
      kStart + 1s,
      2000,
      lastAckedInfo(kStart, kStart + 10ms, 1000),
      /*inflightBytes=*/2 * kPacketSize));
  auto& packet = conn_.outstandings.packets.back();

  auto sample = sampler_.onAck(
      makeAckFor({&packet}, kStart + 1030ms, 2000), std::nullopt);

  EXPECT_EQ(sample.interval, 1020ms);
}

TEST_F(Bbr3RateSamplerTest, IgnoresARestartBeforeTheLastAck) {
  sendPacket(makePacket(1, kStart + 1s, 1000));
  // This packet was sent after the ACK of the packet that restarted the
  // interval.
  sendPacket(makePacket(
      2,
      kStart + 1040ms,
      2000,
      lastAckedInfo(kStart + 1s, kStart + 1030ms, 1000),
      /*inflightBytes=*/2 * kPacketSize));
  auto& packet = conn_.outstandings.packets.back();

  auto sample = sampler_.onAck(
      makeAckFor({&packet}, kStart + 1070ms, 2000), std::nullopt);

  EXPECT_EQ(sample.interval, 40ms);
}

TEST_F(Bbr3RateSamplerTest, StartsTheFirstFlightAtTheFirstPacket) {
  conn_.connectionTime = kStart;
  sendPacket(makePacket(1, kStart + 100ms, 1000));
  sendPacket(makePacket(
      2, kStart + 110ms, 2000, std::nullopt, /*inflightBytes=*/2000));
  auto& packet = conn_.outstandings.packets.back();

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 150ms, 2000), std::nullopt);

  EXPECT_EQ(sample.interval, 50ms);
}

TEST_F(Bbr3RateSamplerTest, StartsAtTheConnectionTimeWithoutARestart) {
  conn_.connectionTime = kStart;
  auto packet =
      makePacket(1, kStart + 100ms, 1000, std::nullopt, /*inflightBytes=*/2000);

  auto sample =
      sampler_.onAck(makeAckFor({&packet}, kStart + 150ms, 1000), std::nullopt);

  EXPECT_EQ(sample.interval, 150ms);
}

} // namespace
} // namespace quic::test
