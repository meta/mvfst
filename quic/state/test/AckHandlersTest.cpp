/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/QuicConstants.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/logging/test/Mocks.h>
#include <quic/mvfst-config.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/stream/StreamStateFunctions.h>
#include <quic/state/test/AckEventTestUtil.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

#include <algorithm>
#include <numeric>

#include <array>
#include <functional>

using namespace testing;

namespace quic::test {

namespace {
void connPacketDestroyFn(void* ctx, const OutstandingPacketWrapper& pkt) {
  auto* conn = static_cast<QuicConnectionStateBase*>(ctx);
  for (auto& packetProcessor : conn->packetProcessors) {
    packetProcessor->onPacketDestroyed(pkt);
  }
}
} // namespace

struct AckHandlersTestParam {
  PacketNumberSpace pnSpace;
  FrameType frameType;
};

class AckHandlersTest : public TestWithParam<AckHandlersTestParam> {};

template <typename T>
uint64_t ul(T val) {
  return static_cast<uint64_t>(val);
}

auto testLossHandler(std::vector<PacketNum>& lostPackets) -> decltype(auto) {
  return [&lostPackets](QuicConnectionStateBase&, auto, auto& packet, bool)
             -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPackets.push_back(packetNum);
    return {};
  };
}

auto emplacePackets(
    QuicServerConnectionState& conn,
    PacketNum lastPacketNum,
    TimePoint startTime,
    PacketNumberSpace pnSpace) {
  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint sentTime;
  std::vector<TimePoint> packetRcvTime;
  while (packetNum < lastPacketNum) {
    auto regularPacket = createNewPacket(packetNum, pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);
    sentTime = startTime + std::chrono::milliseconds(packetNum);
    packetRcvTime.emplace_back(sentTime);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        packetNum + 1,
        quic::LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
    conn.outstandings.packets.emplace_back(std::move(sentPacket));
    packetNum++;
  }
}

auto getAckPacketMatcher(
    PacketNum packetNum,
    uint64_t writeCount,
    TimePoint sentTime) {
  return testing::AllOf(
      testing::Field(&AckEvent::AckPacket::packetNum, packetNum),
      testing::Field(
          &AckEvent::AckPacket::outstandingPacketMetadata,
          testing::AllOf(
              testing::Field(&OutstandingPacketMetadata::time, sentTime),
              testing::Field(
                  &OutstandingPacketMetadata::totalBytesSent,
                  1 * (packetNum + 1)),
              testing::Field(
                  &OutstandingPacketMetadata::writeCount, writeCount))));
}

auto testAckEventReceiveTimestampsAll(
    const AckEvent& ackEvent,
    const UnorderedMap<PacketNum, uint64_t>& expectedReceiveTimestamps) {
  // Lambda function to create a map from ackedPackets
  auto createReceiveTimestampsMap =
      [](const std::vector<AckEvent::AckPacket>& ackedPackets) {
        UnorderedMap<PacketNum, uint64_t> receiveTimestampsMap;
        for (const auto& packet : ackedPackets) {
          if (packet.receiveRelativeTimeStampUsec.has_value()) {
            receiveTimestampsMap.emplace(
                packet.packetNum,
                packet.receiveRelativeTimeStampUsec.value().count());
          }
        }
        return receiveTimestampsMap;
      };

  // Create a map from ackedPackets
  auto receiveTimestampsMap = createReceiveTimestampsMap(ackEvent.ackedPackets);
  // Compare the two maps
  EXPECT_EQ(expectedReceiveTimestamps, receiveTimestampsMap);
}

auto getNumAckReceiveTimestamps(const AckEvent& ackEvent) {
  int numTimestamps = 0;
  for (const auto& packet : ackEvent.ackedPackets) {
    if (packet.receiveRelativeTimeStampUsec.has_value()) {
      numTimestamps++;
    }
  }
  return numTimestamps;
}

TEST_P(AckHandlersTest, SpuriousOnlyAckNotifiesCongestionController) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto* rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto* rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  constexpr PacketNum kPacketNum = 7;
  auto packet = createNewPacket(kPacketNum, GetParam().pnSpace);
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      Clock::now() - 1ms,
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.back().declaredLost = true;
  conn.outstandings.declaredLostCount = 1;
  getAckState(conn, GetParam().pnSpace).nextPacketNum = kPacketNum + 1;

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, IsNull()))
      .WillOnce([expectedPacketNumberSpace = GetParam().pnSpace](
                    const AckEvent* ack, const LossEvent*) {
        ASSERT_NE(nullptr, ack);
        EXPECT_FALSE(ack->largestNewlyAckedPacket.has_value());
        EXPECT_EQ(expectedPacketNumberSpace, ack->packetNumberSpace);
        EXPECT_EQ(1, ack->numPacketsSpuriouslyAcked);
      });
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(0);
  EXPECT_CALL(*rawPacketProcessor, onPacketAckOrLoss(_, _)).Times(0);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = kPacketNum;
  ackFrame.ackBlocks.emplace_back(kPacketNum, kPacketNum);
  auto result = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());

  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(1, result.value().numPacketsSpuriouslyAcked);
  EXPECT_EQ(0, conn.outstandings.declaredLostCount);
}

TEST_P(AckHandlersTest, ImplicitAckIsNotSpuriousLossProof) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto* rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  constexpr PacketNum kPacketNum = 7;
  auto packet = createNewPacket(kPacketNum, GetParam().pnSpace);
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      Clock::now() - 1ms,
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.back().declaredLost = true;
  conn.outstandings.declaredLostCount = 1;
  getAckState(conn, GetParam().pnSpace).nextPacketNum = kPacketNum + 1;

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = kPacketNum;
  ackFrame.ackBlocks.emplace_back(kPacketNum, kPacketNum);
  ackFrame.implicit = true;
  auto result = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());

  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(0, result.value().numPacketsSpuriouslyAcked);
  EXPECT_EQ(0, conn.outstandings.declaredLostCount);
}

// Build a timestamp map of received packets with relative timestamps using a
// given timestamp range for later matching.
uint64_t buildExpectedReceiveTimestamps(
    const RecvdPacketsTimestampsRange& timestampsRange,
    UnorderedMap<PacketNum, uint64_t>& expectedReceiveTimestamps,
    quic::PacketNum latestReceivedUdpPacketWithAddedGap,
    uint64_t lastReceiveTimestamp,
    uint64_t maxTimestamps) {
  if (timestampsRange.timestamp_delta_count == 0 ||
      timestampsRange.deltas.empty()) {
    return lastReceiveTimestamp;
  }
  auto receiveTimestamp = lastReceiveTimestamp;
  auto receivedPacketNum =
      latestReceivedUdpPacketWithAddedGap - timestampsRange.gap;
  uint64_t timestampsProcessed = 0;
  for (const auto& delta : timestampsRange.deltas) {
    receiveTimestamp -= delta;
    expectedReceiveTimestamps[receivedPacketNum] = receiveTimestamp;
    receivedPacketNum--;
    if (++timestampsProcessed >= maxTimestamps) {
      break;
    }
  }
  // Return the last parsed receive timestamp.
  return receiveTimestamp;
}

TEST_P(AckHandlersTest, TestAckMultipleSequentialBlocks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 85;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  const StreamId startStreamId = 10;
  StreamId currentStreamId = startStreamId;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 101;
  // ACK packet ranges 21 - 101
  for (PacketNum packetNum = 101; packetNum > 30; packetNum -= 20) {
    ackFrame.ackBlocks.emplace_back(packetNum - 20, packetNum);
  }

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 81;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .WillRepeatedly(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(ul(101), ack->largestAckedPacket);
          EXPECT_EQ(ul(101), ack->largestNewlyAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedBytes, ack->totalBytesAcked);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&,
              const auto& packetFrame) -> quic::Expected<void, QuicError> {
            auto& stream = *packetFrame.asWriteStreamFrame();
            streams.emplace_back(stream);
            return {};
          },
          testLossHandler(lostPackets),
          Clock::now())
          .hasError());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId nextExpectedStream = 21; // packets (streams) 21 - 101 are ACKed
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, nextExpectedStream);
    nextExpectedStream++;
  }
  // only unacked packets should be remaining
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_GT(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, lostPackets.size());
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.outstandings.packets.size(), numDeclaredLost + 5);
}

TEST_P(AckHandlersTest, TestAckWithECN) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  auto packetSendTime = Clock::now();
  auto packet = createNewPacket(5, GetParam().pnSpace);
  conn.outstandings.packetCount[packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      packetSendTime,
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  // To enable accounting of sent marked packets
  conn.ecnState = ECNState::ValidatedL4S;

  ReadAckFrame ackFrame;
  auto ackReceiveTime = packetSendTime + 1ms;
  ackFrame.largestAcked = 5;
  ackFrame.ackBlocks.emplace_back(5, 5);
  ackFrame.ecnECT0Count = 100;
  ackFrame.ecnECT1Count = 200;
  ackFrame.ecnCECount = 300;

  auto ackEvent = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackReceiveTime);
  ASSERT_FALSE(ackEvent.hasError());
  auto ackEventValue = ackEvent.value();

  EXPECT_EQ(ackEventValue.ecnECT0Count, 100);
  EXPECT_EQ(ackEventValue.ecnECT1Count, 200);
  EXPECT_EQ(ackEventValue.ecnCECount, 300);

  if (GetParam().pnSpace == PacketNumberSpace::AppData) {
    auto& ackState = getAckState(conn, GetParam().pnSpace);
    EXPECT_EQ(ackState.minimumExpectedEcnMarksEchoed, 1);
    EXPECT_EQ(ackState.ecnECT0CountEchoed, 100);
    EXPECT_EQ(ackState.ecnECT1CountEchoed, 200);
    EXPECT_EQ(ackState.ecnCECountEchoed, 300);
  }
}

TEST_P(AckHandlersTest, TestPacketDestructionAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  conn.lossState.reorderingThreshold = 15;

  for (PacketNum packetNum = 1; packetNum <= 3; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        &conn,
        &connPacketDestroyFn);
  }
  EXPECT_EQ(conn.outstandings.packets.size(), 3);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 3;
  ackFrame.ackBlocks.emplace_back(1, 3);

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  std::unordered_set<quic::PacketNum> packetNumsDestroyed;
  EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
      .Times(3)
      .WillRepeatedly(Invoke([&](auto& outstandingPacket) {
        packetNumsDestroyed.insert(
            outstandingPacket.packet.header.getPacketSequenceNum());
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_THAT(packetNumsDestroyed, UnorderedElementsAre(1, 2, 3));

  EXPECT_EQ(conn.outstandings.packets.size(), 0);
}

TEST_P(AckHandlersTest, TestPacketDestructionSpuriousLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  TimePoint startTime = Clock::now();
  // setting a very high reordering threshold to force loss by timeout only
  conn.lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which
  // detectLossPackets is called to make sure the first packet timeout
  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 150ms;
  conn.transportSettings.timeReorderingThreshDividend = 1.0;
  conn.transportSettings.timeReorderingThreshDivisor = 1.0;

  StreamId currentStreamId = 10;
  //   conn.lossState.reorderingThreshold = 1;

  for (PacketNum packetNum = 1; packetNum <= 3; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        startTime + std::chrono::milliseconds((packetNum - 1) * 100),
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        &conn,
        &connPacketDestroyFn);
  }
  EXPECT_EQ(conn.outstandings.packets.size(), 3);
  // Update the ackState
  // Both largestAckedByPeer (packet num) and
  // exercise loss by reorder path
  auto& ackState = getAckState(conn, GetParam().pnSpace);
  ackState.largestAckedByPeer = 3;
  ASSERT_FALSE(detectLossPackets(
                   conn,
                   ackState,
                   [](auto&, auto, auto&, bool)
                       -> quic::Expected<void, quic::QuicError> { return {}; },
                   startTime + 250ms,
                   GetParam().pnSpace)
                   .hasError());

  // now we get late acks for #2 and #3, triggering #1 to be marked lost.
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 3;
  ackFrame.ackBlocks.emplace_back(2, 3);

  std::unordered_set<quic::PacketNum> packetsDestroyed;

  EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](auto& outstandingPacket) {
        packetsDestroyed.insert(
            outstandingPacket.packet.header.getPacketSequenceNum());
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          startTime + 260ms)
          .hasError());

  EXPECT_THAT(packetsDestroyed, UnorderedElementsAre(2, 3));

  // Send and ACK another packet #4, which should clear both #1 and #4.
  {
    PacketNum packetNum = 4;
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        startTime + std::chrono::milliseconds((packetNum - 1) * 100),
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        &conn,
        &connPacketDestroyFn);
  }

  // Send ACK for #4, which should clear # 1 as well.
  ReadAckFrame ackFrame1;
  ackFrame1.largestAcked = 4;
  ackFrame1.ackBlocks.emplace_back(4, 4);

  std::unordered_map<quic::PacketNum, bool> packetNumToDeclaredLost;

  EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](auto& outstandingPacket) {
        quic::PacketNum packetNum =
            outstandingPacket.packet.header.getPacketSequenceNum();
        bool declatedLost = outstandingPacket.declaredLost;
        packetNumToDeclaredLost[packetNum] = declatedLost;
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame1,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          startTime + 600ms)
          .hasError());

  EXPECT_THAT(
      packetNumToDeclaredLost,
      UnorderedElementsAre(Pair(1, true), Pair(4, false)));

  EXPECT_EQ(conn.outstandings.packets.size(), 0);
}

TEST_P(AckHandlersTest, TestPacketDestructionBigDeque) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  conn.lossState.reorderingThreshold = 15;

  // send 1000 packets, starting at packet 1
  for (PacketNum packetNum = 1; packetNum <= 1000; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream(),
        0us,
        &conn,
        &connPacketDestroyFn);
  }
  EXPECT_EQ(conn.outstandings.packets.size(), 1000);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 999;
  ackFrame.ackBlocks.emplace_back(2, 999);

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  EXPECT_CALL(
      *rawPacketProcessor,
      onPacketDestroyed(
          testing::Property(
              &OutstandingPacket::getPacketSequenceNum,
              AllOf(Lt(1000), Gt(1)))))
      .Times(998);

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());

  // Shrink the deque to the remaining packets.
  conn.outstandings.packets.shrink_to_fit();

  ReadAckFrame ackFrame1;
  ackFrame1.largestAcked = 1;
  ackFrame1.ackBlocks.emplace_back(1, 1);

  EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
      .Times(1)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(1, outstandingPacket.packet.header.getPacketSequenceNum());
        EXPECT_EQ(true, outstandingPacket.declaredLost);
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame1,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());

  ReadAckFrame ackFrame2;
  ackFrame2.largestAcked = 1000;
  ackFrame2.ackBlocks.emplace_back(1000, 1000);

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);
  EXPECT_CALL(*rawPacketProcessor, onPacketDestroyed(_))
      .Times(1)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(1000, outstandingPacket.packet.header.getPacketSequenceNum());
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame2,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());

  EXPECT_EQ(conn.outstandings.packets.size(), 0);
}

TEST_P(AckHandlersTest, TestAckMultipleSequentialBlocksLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 85;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  auto sentTime = Clock::now();
  for (PacketNum packetNum = 10; packetNum <= 101; packetNum++) {
    RegularQuicWritePacket regularPacket =
        createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 101;
  // ACK packet ranges 21 - 101
  for (PacketNum packetNum = 101; packetNum > 30; packetNum -= 20) {
    ackFrame.ackBlocks.emplace_back(packetNum - 20, packetNum);
  }

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 81;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(3)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(ul(101), ack->largestAckedPacket);
          EXPECT_EQ(ul(101), ack->largestNewlyAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedBytes, ack->totalBytesAcked);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }))
      .WillRepeatedly(Invoke([](auto, auto) {}));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(3);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto& packetFrame)
              -> quic::Expected<void, quic::QuicError> {
            auto& stream = *packetFrame.asWriteStreamFrame();
            streams.emplace_back(stream);
            return {};
          },
          testLossHandler(lostPackets),
          Clock::now())
          .hasError());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId nextExpectedStream = 21; // packets (streams) 21 - 101 are ACKed
  for (auto& stream : streams) {
    EXPECT_EQ(stream.streamId, nextExpectedStream);
    nextExpectedStream++;
  }

  // only unacked packets should be remaining
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_GT(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, lostPackets.size());
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.outstandings.packets.size(), numDeclaredLost + 5);
  PacketNum lostPackt = 10;
  for (auto& pkt : lostPackets) {
    EXPECT_EQ(pkt, lostPackt++);
  }
  PacketNum packetNum = 16;
  for (auto& packet : conn.outstandings.packets) {
    if (packet.declaredLost) {
      continue;
    }
    auto currentPacketNum = packet.packet.header.getPacketSequenceNum();
    EXPECT_EQ(currentPacketNum, packetNum);
    packetNum++;
  }

  // 15 is lost, 16 is not, if we get an ack covering both both should be
  // cleared.
  auto itr = std::ranges::find_if(conn.outstandings.packets, [](auto& op) {
    auto seqno = op.packet.header.getPacketSequenceNum();
    return seqno == 15 || seqno == 16;
  });
  EXPECT_TRUE(itr != conn.outstandings.packets.end());
  EXPECT_TRUE(itr->declaredLost);
  EXPECT_EQ(itr->packet.header.getPacketSequenceNum(), 15);
  itr++;
  EXPECT_TRUE(itr != conn.outstandings.packets.end());
  EXPECT_FALSE(itr->declaredLost);
  EXPECT_EQ(itr->packet.header.getPacketSequenceNum(), 16);
  EXPECT_EQ(conn.lossState.totalPacketsSpuriouslyMarkedLost, 0);
  ackFrame.ackBlocks.emplace_back(15, 16);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          [](auto&, auto, auto&, auto)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  itr = std::ranges::find_if(conn.outstandings.packets, [](auto& op) {
    auto seqno = op.packet.header.getPacketSequenceNum();
    return seqno == 15 || seqno == 16;
  });
  EXPECT_TRUE(itr == conn.outstandings.packets.end());

  // Duplicate ACK much later, should clear out declared lost.
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          [](auto&, auto, auto&, auto)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now() + 2 * calculatePTO(conn))
          .hasError());

  numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(numDeclaredLost, 0);
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  EXPECT_EQ(conn.lossState.totalPacketsSpuriouslyMarkedLost, 1);
}

TEST_P(AckHandlersTest, TestAckBlocksWithGaps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 30;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId currentStreamId = 10;
  for (PacketNum packetNum = 10; packetNum < 51; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(currentStreamId++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 45;
  ackFrame.ackBlocks.emplace_back(45, 45);
  ackFrame.ackBlocks.emplace_back(33, 44);
  ackFrame.ackBlocks.emplace_back(12, 21);

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  uint64_t expectedAckedBytes = 21 - 12 + 1 + 44 - 33 + 1 + 45 - 45 + 1;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  size_t lostPacketsCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .WillRepeatedly(Invoke([&](auto ack, auto loss) {
        if (ack) {
          EXPECT_EQ(ul(45), ack->largestAckedPacket);
          EXPECT_EQ(ul(45), ack->largestNewlyAckedPacket);
          EXPECT_EQ(expectedAckedBytes, ack->ackedBytes);
          EXPECT_EQ(expectedAckedBytes, ack->totalBytesAcked);
          EXPECT_EQ(expectedAckedPackets, ack->ackedPackets.size());
        }
        if (loss) {
          lostPacketsCounter++;
        }
      }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto& packetFrame)
              -> quic::Expected<void, quic::QuicError> {
            auto& stream = *packetFrame.asWriteStreamFrame();
            streams.emplace_back(stream);
            return {};
          },
          testLossHandler(lostPackets),
          Clock::now())
          .hasError());
  EXPECT_EQ(lostPacketsCounter, lostPackets.empty() ? 0 : 1);

  StreamId start = 45;
  std::vector<StreamId> ids(45 - 33 + 1);
  std::ranges::generate(ids, [&]() { return start--; });
  EXPECT_TRUE(
      std::equal(
          streams.rbegin(),
          streams.rbegin() + (45 - 33 + 1),
          ids.begin(),
          ids.end(),
          [](const auto& frame, auto id) { return frame.streamId == id; }));

  start = 21;
  std::vector<StreamId> ids2(10);
  std::ranges::generate(ids2, [&]() { return start--; });
  EXPECT_TRUE(
      std::equal(
          streams.rbegin() + (45 - 33 + 1),
          streams.rend(),
          ids2.begin(),
          ids2.end(),
          [](const auto& frame, auto id) { return frame.streamId == id; }));

  std::vector<PacketNum> remainingPackets(11 + 5);
  std::iota(remainingPackets.begin(), remainingPackets.begin() + 11, 22);
  std::iota(remainingPackets.begin() + 11, remainingPackets.end(), 46);

  std::vector<PacketNum> actualPacketNumbers;
  for (auto& op : conn.outstandings.packets) {
    if (!op.declaredLost) {
      actualPacketNumbers.push_back(op.packet.header.getPacketSequenceNum());
    }
  }
  EXPECT_TRUE(std::ranges::equal(actualPacketNumbers, remainingPackets));

  std::vector<PacketNum> actualLostPackets = {10, 11};

  EXPECT_TRUE(std::ranges::equal(actualLostPackets, lostPackets));
}

TEST_P(AckHandlersTest, TestNonSequentialPacketNumbers) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.lossState.reorderingThreshold = 10;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  StreamId current = 10;
  for (PacketNum packetNum = 10; packetNum < 20; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(current++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  for (PacketNum packetNum = 20; packetNum < 40; packetNum += 3) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(current, 0, 0, true);
    current += 3;
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        1,
        0,
        packetNum,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 26;
  ackFrame.ackBlocks.emplace_back(26, 26);
  // This intentionally acks an unsent packet. When we start enforcing
  // unsent packets then disable this.
  ackFrame.ackBlocks.emplace_back(5, 20);

  std::vector<WriteStreamFrame> streams;
  std::vector<PacketNum> lostPackets;
  // Only 26 and [10, 20] are acked:
  uint64_t expectedAckedBytes = 20 - 10 + 1 + 1;
  uint64_t expectedAckedPackets = expectedAckedBytes; // each packet size is 1
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(ul(26), ackEvent->largestAckedPacket);
        EXPECT_EQ(ul(26), ackEvent->largestNewlyAckedPacket);
        EXPECT_EQ(expectedAckedBytes, ackEvent->ackedBytes);
        EXPECT_EQ(expectedAckedBytes, ackEvent->totalBytesAcked);
        EXPECT_EQ(expectedAckedPackets, ackEvent->ackedPackets.size());
      }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&,
              const auto& packetFrame) -> quic::Expected<void, QuicError> {
            auto& stream = *packetFrame.asWriteStreamFrame();
            streams.emplace_back(stream);
            return {};
          },
          testLossHandler(lostPackets),
          Clock::now())
          .hasError());

  EXPECT_EQ(26, streams.rbegin()->streamId);

  StreamId start = 20;
  std::vector<StreamId> ids(20 - 10 + 1);
  std::ranges::generate(ids, [&]() { return start--; });
  EXPECT_TRUE(
      std::equal(
          streams.rbegin() + 1,
          streams.rend(),
          ids.begin(),
          ids.end(),
          [](const auto& frame, auto id) { return frame.streamId == id; }));

  std::vector<PacketNum> remainingPackets(5);
  remainingPackets[0] = 23;
  int remainingIdx = 1;
  for (PacketNum num = 29; num < 40; num += 3) {
    remainingPackets[remainingIdx++] = num;
  }

  std::vector<PacketNum> actualPacketNumbers;
  std::ranges::transform(
      conn.outstandings.packets,
      std::back_insert_iterator<decltype(actualPacketNumbers)>(
          actualPacketNumbers),
      [](const auto& packet) {
        return packet.packet.header.getPacketSequenceNum();
      });

  EXPECT_TRUE(std::ranges::equal(actualPacketNumbers, remainingPackets));
}

TEST_P(AckHandlersTest, AckVisitorForAckTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.connectionTime = Clock::now();
  auto firstPacket = createNewPacket(100 /* packetNum */, GetParam().pnSpace);
  WriteAckFrame firstAckFrame;
  firstAckFrame.ackBlocks.emplace_back(900, 1000);
  firstAckFrame.ackBlocks.emplace_back(500, 700);
  conn.ackStates.appDataAckState.acks.insert(900, 1000);
  conn.ackStates.appDataAckState.acks.insert(500, 700);
  firstPacket.frames.emplace_back(std::move(firstAckFrame));
  conn.outstandings.packetCount[firstPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(firstPacket),
      Clock::now(),
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  auto secondPacket = createNewPacket(101 /* packetNum */, GetParam().pnSpace);
  WriteAckFrame secondAckFrame;
  secondAckFrame.ackBlocks.emplace_back(1100, 2000);
  secondAckFrame.ackBlocks.emplace_back(1002, 1090);
  conn.ackStates.appDataAckState.acks.insert(1100, 2000);
  conn.ackStates.appDataAckState.acks.insert(1002, 1090);
  secondPacket.frames.emplace_back(std::move(secondAckFrame));
  conn.outstandings.packetCount[secondPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(secondPacket),
      Clock::now(),
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame firstReceivedAck;
  firstReceivedAck.largestAcked = 100;
  firstReceivedAck.ackBlocks.emplace_back(100, 100);
  ASSERT_FALSE(processAckFrame(
                   conn,
                   GetParam().pnSpace,
                   firstReceivedAck,
                   [](const auto&) -> quic::Expected<void, quic::QuicError> {
                     return {};
                   },
                   [&](const auto& outstandingPacket, const auto& packetFrame)
                       -> quic::Expected<void, QuicError> {
                     auto ackedPacketNum =
                         outstandingPacket.packet.header.getPacketSequenceNum();
                     EXPECT_EQ(ackedPacketNum, firstReceivedAck.largestAcked);
                     const WriteAckFrame* frame = packetFrame.asWriteAckFrame();
                     if (frame) {
                       commonAckVisitorForAckFrame(
                           conn.ackStates.appDataAckState, *frame);
                     }
                     return {};
                   },
                   [](auto& /* conn */,
                      auto /*pathId*/,
                      auto& /* packet */,
                      bool /* processed */
                      ) -> quic::Expected<void, quic::QuicError> { return {}; },
                   Clock::now())
                   .hasError());
  EXPECT_EQ(2, conn.ackStates.appDataAckState.acks.size());
  EXPECT_EQ(
      Interval<PacketNum>(1002, 1090),
      conn.ackStates.appDataAckState.acks.front());
  EXPECT_EQ(
      Interval<PacketNum>(1100, 2000),
      conn.ackStates.appDataAckState.acks.back());

  ReadAckFrame secondReceivedAck;
  secondReceivedAck.largestAcked = 101;
  secondReceivedAck.ackBlocks.emplace_back(101, 101);
  ASSERT_FALSE(processAckFrame(
                   conn,
                   GetParam().pnSpace,
                   secondReceivedAck,
                   [](const auto&) -> quic::Expected<void, quic::QuicError> {
                     return {};
                   },
                   [&](const auto&, const auto& packetFrame)
                       -> quic::Expected<void, QuicError> {
                     const WriteAckFrame* frame = packetFrame.asWriteAckFrame();
                     if (frame) {
                       commonAckVisitorForAckFrame(
                           conn.ackStates.appDataAckState, *frame);
                     }
                     return {};
                   },
                   [](auto& /* conn */,
                      auto /* pathId*/,
                      auto& /* packet */,
                      bool /* processed */
                      ) -> quic::Expected<void, quic::QuicError> { return {}; },
                   Clock::now())
                   .hasError());
  EXPECT_TRUE(conn.ackStates.appDataAckState.acks.empty());
}

TEST_P(AckHandlersTest, NoNewAckedPacket) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  auto rawController = mockController.get();
  conn.congestionController = std::move(mockController);

  conn.lossState.ptoCount = 1;
  PacketNum packetAfterRtoNum = 10;
  auto packetAfterRto = createNewPacket(packetAfterRtoNum, GetParam().pnSpace);
  conn.outstandings.packetCount[packetAfterRto.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(packetAfterRto),
      Clock::now(),
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 5;
  EXPECT_CALL(*rawController, onPacketAckOrLoss(_, _)).Times(0);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&) -> quic::Expected<void, QuicError> {
            return {};
          },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(conn.lossState.ptoCount, 1);
  EXPECT_TRUE(!conn.ackStates.appDataAckState.largestAckedByPeer.has_value());
}

TEST_P(AckHandlersTest, LossByAckedRecovered) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockController);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 10;
  ackFrame.ackBlocks.emplace_back(5, 10);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&) -> quic::Expected<void, QuicError> {
            return {};
          },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
}

TEST_P(AckHandlersTest, AckPacketNumDoesNotExist) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockController);
  // Get the time based loss detection out of the way
  conn.lossState.srtt = 10s;

  PacketNum packetNum1 = 9;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam().pnSpace);
  conn.outstandings.packetCount[regularPacket1.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket1),
      Clock::now(),
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  PacketNum packetNum2 = 10;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam().pnSpace);
  conn.outstandings.packetCount[regularPacket2.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket2),
      Clock::now(),
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  // Ack a packet one higher than the packet so that we don't trigger
  // reordering threshold.
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 1000;
  ackFrame.ackBlocks.emplace_back(1000, 1000);
  ackFrame.ackBlocks.emplace_back(10, 10);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&) -> quic::Expected<void, QuicError> {
            return {};
          },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(1, conn.outstandings.packets.size());
}

TEST_P(AckHandlersTest, TestHandshakeCounterUpdate) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId stream = 1;
  for (PacketNum packetNum = 0; packetNum < 10; packetNum++) {
    auto regularPacket = createNewPacket(
        packetNum,
        (packetNum % 2 ? GetParam().pnSpace : PacketNumberSpace::AppData));
    WriteStreamFrame frame(
        stream, 100 * packetNum + 0, 100 * packetNum + 100, false);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        0,
        0,
        packetNum / 2,
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(3, 7);

  std::vector<PacketNum> lostPackets;
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto&) -> quic::Expected<void, QuicError> {
            return {};
          },
          testLossHandler(lostPackets),
          Clock::now())
          .hasError());
  // When [3, 7] are acked, [0, 2] may also be marked loss if they are in the
  // same packet number space, due to reordering threshold
  auto numDeclaredLost = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(numDeclaredLost, conn.outstandings.declaredLostCount);
  if (GetParam().pnSpace == PacketNumberSpace::Initial) {
    EXPECT_EQ(numDeclaredLost, 1);
    EXPECT_EQ(1, conn.outstandings.packetCount[PacketNumberSpace::Initial]);
    // AppData packets won't be acked by an ack in Initial space:
    // So 0, 2, 4, 6, 8 and 9 are left in OP list
    EXPECT_EQ(numDeclaredLost + 6, conn.outstandings.packets.size());
  } else if (GetParam().pnSpace == PacketNumberSpace::Handshake) {
    EXPECT_EQ(numDeclaredLost, 1);
    EXPECT_EQ(1, conn.outstandings.packetCount[PacketNumberSpace::Handshake]);
    // AppData packets won't be acked by an ack in Handshake space:
    // So 0, 2, 4, 6, 8 and 9 are left in OP list
    EXPECT_EQ(numDeclaredLost + 6, conn.outstandings.packets.size());
  } else {
    EXPECT_EQ(numDeclaredLost + 2, conn.outstandings.packets.size());
  }
}

TEST_P(AckHandlersTest, PurgeAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(900, 1000);
  ackFrame.ackBlocks.emplace_back(500, 700);
  conn.ackStates.initialAckState->acks.insert(900, 1200);
  conn.ackStates.initialAckState->acks.insert(500, 800);
  auto expectedTime = Clock::now();
  conn.ackStates.initialAckState->largestRecvdPacketTime = expectedTime;
  commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);
  // We should have purged old packets in ack state
  EXPECT_EQ(conn.ackStates.initialAckState->acks.size(), 1);
  EXPECT_EQ(conn.ackStates.initialAckState->acks.front().start, 1001);
  EXPECT_EQ(conn.ackStates.initialAckState->acks.front().end, 1200);
  EXPECT_EQ(
      expectedTime, *conn.ackStates.initialAckState->largestRecvdPacketTime);
}

TEST_P(AckHandlersTest, BoundsRetainedRangesAfterAckOfAckSplit) {
  constexpr size_t kExpectedMaxRetainedAckRanges = 1024;

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto& ackState = *conn.ackStates.initialAckState;
  ackState.acks.insert(100, 120);
  for (size_t index = 0; index < kExpectedMaxRetainedAckRanges - 1; ++index) {
    const PacketNum packetNum = 200 + (2 * index);
    ackState.acks.insert(packetNum, packetNum);
  }
  ASSERT_EQ(ackState.acks.size(), kExpectedMaxRetainedAckRanges);
  ASSERT_TRUE(ackState.acks.contains(105, 105));
  const auto newestRange = ackState.acks.back();

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(105, 105);
  commonAckVisitorForAckFrame(ackState, ackFrame);

  EXPECT_FALSE(ackState.acks.contains(105, 105));
  EXPECT_TRUE(ackState.acks.contains(106, 120));
  EXPECT_EQ(ackState.acks.back().start, newestRange.start);
  EXPECT_EQ(ackState.acks.back().end, newestRange.end);
  EXPECT_LE(ackState.acks.size(), kExpectedMaxRetainedAckRanges);
  const auto pressureFloor = ackState.minimumReceivedPacketNum;
  EXPECT_EQ(pressureFloor, 105);

  WriteAckFrame clearFrame;
  clearFrame.ackBlocks.emplace_back(105, newestRange.end);
  commonAckVisitorForAckFrame(ackState, clearFrame);
  EXPECT_TRUE(ackState.acks.empty());
  EXPECT_EQ(ackState.minimumReceivedPacketNum, pressureFloor);
}

TEST_P(AckHandlersTest, purgeAckReceiveTimestamps) {
  // Case 1: No timestamps
  {
    QuicServerConnectionState conn(
        FizzServerQuicHandshakeContext::Builder().build());
    WriteAckFrame ackFrame;
    ackFrame.ackBlocks.emplace_back(15, 40);
    conn.ackStates.initialAckState->acks.insert(15, 40);

    auto expectedTime = Clock::now();
    conn.ackStates.initialAckState->largestRecvdPacketTime = expectedTime;

    commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.size(), 0);
    EXPECT_EQ(conn.ackStates.initialAckState->recvdPacketInfos.size(), 0);
  }

  // Case 2: purge all receive timestamps
  {
    QuicServerConnectionState conn(
        FizzServerQuicHandshakeContext::Builder().build());
    WriteAckFrame ackFrame;
    ackFrame.ackBlocks.emplace_back(15, 40);
    conn.ackStates.initialAckState->acks.insert(15, 40);

    auto expectedTime = Clock::now();
    conn.ackStates.initialAckState->largestRecvdPacketTime = expectedTime;
    // Fill up the last 25 timestamps ending at PN 40.
    for (PacketNum pktNum = 15; pktNum <= 40; ++pktNum) {
      ReceivedUdpPacket::Timings timings;
      timings.receiveTimePoint = expectedTime;
      conn.ackStates.initialAckState->recvdPacketInfos.emplace_back(
          WriteAckFrameState::ReceivedPacket{pktNum, timings});
    }

    commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.size(), 0);
    EXPECT_EQ(conn.ackStates.initialAckState->recvdPacketInfos.size(), 0);
  }
  // Case 3: Purge only some old timestamps in the front.
  {
    QuicServerConnectionState conn(
        FizzServerQuicHandshakeContext::Builder().build());
    WriteAckFrame ackFrame;
    // Local ACK state has ACKs for {1, 20}, {25, 40}
    conn.ackStates.initialAckState->acks.insert(25, 40);
    conn.ackStates.initialAckState->acks.insert(1, 20);
    auto expectedTime = Clock::now();
    conn.ackStates.initialAckState->largestRecvdPacketTime = expectedTime;

    // Local ACK state has timestamps for {15, 40}
    for (PacketNum pktNum = 15; pktNum <= 40; ++pktNum) {
      ReceivedUdpPacket::Timings timings;
      timings.receiveTimePoint = expectedTime;
      conn.ackStates.initialAckState->recvdPacketInfos.emplace_back(
          WriteAckFrameState::ReceivedPacket{pktNum, timings});
    }
    // ACK frame in the ACKed packet has ACKs for {10, 20}, {25, 35}
    ackFrame.ackBlocks.emplace_back(10, 20);
    ackFrame.ackBlocks.emplace_back(25, 35);

    commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);
    // We should have purged old packets in ack state
    ASSERT_EQ(conn.ackStates.initialAckState->acks.size(), 1);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.front().start, 36);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.front().end, 40);
    // Should have purged all timestamps that are purged in ackState and only
    // (36,40) remain.
    ASSERT_EQ(conn.ackStates.initialAckState->recvdPacketInfos.size(), 5);
    EXPECT_EQ(
        conn.ackStates.initialAckState->recvdPacketInfos.front().pktNum, 36);
    EXPECT_EQ(
        conn.ackStates.initialAckState->recvdPacketInfos.back().pktNum, 40);
  }

  // Case 4: Purge some timestamps in the middle.
  {
    QuicServerConnectionState conn(
        FizzServerQuicHandshakeContext::Builder().build());
    WriteAckFrame ackFrame;
    // Local ACK state has ACKs for {1, 20}, {25, 40}
    conn.ackStates.initialAckState->acks.insert(25, 40);
    conn.ackStates.initialAckState->acks.insert(10, 20);

    auto expectedTime = Clock::now();
    conn.ackStates.initialAckState->largestRecvdPacketTime = expectedTime;

    // Local ACK state has timestamps for {15, 40}
    for (PacketNum pktNum = 15; pktNum <= 40; ++pktNum) {
      ReceivedUdpPacket::Timings timings;
      timings.receiveTimePoint = expectedTime;
      conn.ackStates.initialAckState->recvdPacketInfos.emplace_back(
          WriteAckFrameState::ReceivedPacket{pktNum, timings});
    }
    // Selectively ACK some packets in the middle - {18, 20}, {25, 35}
    ackFrame.ackBlocks.emplace_back(25, 35);
    ackFrame.ackBlocks.emplace_back(18, 20);

    commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);
    // We should have purged old packets in ack state
    ASSERT_EQ(conn.ackStates.initialAckState->acks.size(), 1);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.front().start, 36);
    EXPECT_EQ(conn.ackStates.initialAckState->acks.front().end, 40);
    // Should have purged some timestamps in the middle of recvdPacketInfos.
    ASSERT_EQ(conn.ackStates.initialAckState->recvdPacketInfos.size(), 8);
    EXPECT_EQ(
        conn.ackStates.initialAckState->recvdPacketInfos.front().pktNum, 15);
    EXPECT_EQ(
        conn.ackStates.initialAckState->recvdPacketInfos.back().pktNum, 40);
  }
}

// Purge correctly handles a `recvdPacketInfos` deque whose packet numbers
// are non-monotonic (receive-time-ordered storage may interleave pktNums).
TEST_P(AckHandlersTest, PurgeAckReceiveTimestampsWithUnsortedPktNums) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  WriteAckFrame ackFrame;
  // Local ACK state still tracks {10, 20}.
  conn.ackStates.initialAckState->acks.insert(10, 20);
  auto expectedTime = Clock::now();

  // Receive-time-ordered storage with non-monotonic packet numbers.
  const std::vector<PacketNum> receiveOrder = {15, 18, 11, 20, 14, 12, 17};
  for (auto pktNum : receiveOrder) {
    ReceivedUdpPacket::Timings timings;
    timings.receiveTimePoint = expectedTime;
    conn.ackStates.initialAckState->recvdPacketInfos.emplace_back(
        WriteAckFrameState::ReceivedPacket{pktNum, timings});
  }

  // ACK frame in the ACKed packet covers {11, 15}: those entries should be
  // purged regardless of their position in the unsorted deque.
  ackFrame.ackBlocks.emplace_back(11, 15);
  commonAckVisitorForAckFrame(*conn.ackStates.initialAckState, ackFrame);

  // {15, 11, 14, 12} purged; {18, 20, 17} retained in original receive
  // order.
  ASSERT_EQ(conn.ackStates.initialAckState->recvdPacketInfos.size(), 3);
  EXPECT_EQ(conn.ackStates.initialAckState->recvdPacketInfos[0].pktNum, 18);
  EXPECT_EQ(conn.ackStates.initialAckState->recvdPacketInfos[1].pktNum, 20);
  EXPECT_EQ(conn.ackStates.initialAckState->recvdPacketInfos[2].pktNum, 17);
}

TEST_P(AckHandlersTest, NoSkipAckVisitor) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.encodedSize);
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.totalBytesSent);
      }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);
  uint16_t ackVisitorCounter = 0;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */)
      -> quic::Expected<void, quic::QuicError> {
    ackVisitorCounter++;
    return {};
  };
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [](auto& /* conn */,
             auto /* pathId */,
             auto& /* packet */,
             bool /* processed */
             ) -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, SkipAckVisitor) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent, auto) {
        EXPECT_EQ(1, ackEvent->ackedPackets.size());
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.encodedSize);
        EXPECT_EQ(
            1,
            ackEvent->ackedPackets.front()
                .outstandingPacketMetadata.totalBytesSent);
      }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  OutstandingPacketWrapper outstandingPacket(
      std::move(regularPacket),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  // Give this outstandingPacket an maybeClonedPacketIdentifier that's not in
  // outstandings.clonedPacketIdentifiers
  outstandingPacket.maybeClonedPacketIdentifier.emplace(GetParam().pnSpace, 0);
  conn.outstandings.packets.push_back(std::move(outstandingPacket));
  conn.outstandings.clonedPacketCount[GetParam().pnSpace]++;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);
  uint16_t ackVisitorCounter = 0;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */)
      -> quic::Expected<void, quic::QuicError> {
    ackVisitorCounter++;
    return {};
  };
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [](auto& /* conn */,
             auto /* pathId */,
             auto& /* packet */,
             bool /* processed */
             ) -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, MultiplePacketProcessors) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  auto mockPacketProcessor1 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor1 = mockPacketProcessor1.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor1));

  auto mockPacketProcessor2 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor2 = mockPacketProcessor2.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor2));

  StreamId streamid = 0;

  // Write 10 packets
  for (PacketNum packetNum = 0; packetNum < 10; packetNum++) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);

    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    conn.outstandings.packets.emplace_back(
        std::move(regularPacket),
        Clock::now(),
        0,
        1,
        0,
        1 * (packetNum + 1),
        0,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);

  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_EQ(10, ack.ackedPackets.size());
  };

  EXPECT_CALL(*rawPacketProcessor1, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ack) {
        ASSERT_THAT(ack, Not(IsNull()));
        checkAck(*ack);
      }));
  EXPECT_CALL(*rawPacketProcessor2, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ack) {
        ASSERT_THAT(ack, Not(IsNull()));
        checkAck(*ack);
      }));

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
}

TEST_P(AckHandlersTest, NoDoubleProcess) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController.reset();

  WriteStreamFrame frame(0, 0, 0, true);
  PacketNum packetNum1 = 0, packetNum2 = 1;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam().pnSpace),
       regularPacket2 = createNewPacket(packetNum2, GetParam().pnSpace);
  regularPacket1.frames.push_back(frame);
  regularPacket2.frames.push_back(frame);

  OutstandingPacketWrapper outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  outstandingPacket1.maybeClonedPacketIdentifier.emplace(
      GetParam().pnSpace, packetNum1);

  OutstandingPacketWrapper outstandingPacket2(
      std::move(regularPacket2),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  // The seconds packet has the same ClonedPacketIdentifier
  outstandingPacket2.maybeClonedPacketIdentifier.emplace(
      GetParam().pnSpace, packetNum1);

  conn.outstandings.packetCount[GetParam().pnSpace]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));
  conn.outstandings.packets.push_back(std::move(outstandingPacket2));
  conn.outstandings.clonedPacketCount[GetParam().pnSpace] += 2;
  conn.outstandings.clonedPacketIdentifiers.emplace(
      GetParam().pnSpace, packetNum1);

  // A counting ack visitor
  uint16_t ackVisitorCounter = 0;
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */)
      -> quic::Expected<void, quic::QuicError> {
    ackVisitorCounter++;
    return {};
  };

  // First ack. This will ack first packet, and trigger a ack visiting.
  ReadAckFrame ackFrame1;
  ackFrame1.largestAcked = 0;
  ackFrame1.ackBlocks.emplace_back(0, 0);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame1,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [](auto& /* conn */,
             auto /* pathId */,
             auto& /* packet */,
             bool /* processed */
             ) -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(1, ackVisitorCounter);

  // Second ack that acks the second packet.  This won't trigger a visit.
  ReadAckFrame ackFrame2;
  ackFrame2.largestAcked = 1;
  ackFrame2.ackBlocks.emplace_back(1, 1);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame2,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [&](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(1, ackVisitorCounter);
}

TEST_P(AckHandlersTest, ClonedPacketsCounter) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto pnSpace = GetParam().pnSpace;
  conn.congestionController = nullptr;
  WriteStreamFrame frame(0, 0, 0, true);
  auto packetNum1 = getAckState(conn, pnSpace).nextPacketNum++;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam().pnSpace);
  regularPacket1.frames.push_back(frame);
  OutstandingPacketWrapper outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  outstandingPacket1.maybeClonedPacketIdentifier.emplace(
      GetParam().pnSpace, packetNum1);

  auto packetNum2 = getAckState(conn, pnSpace).nextPacketNum++;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam().pnSpace);
  regularPacket2.frames.push_back(frame);
  OutstandingPacketWrapper outstandingPacket2(
      std::move(regularPacket2),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  conn.outstandings
      .packetCount[outstandingPacket1.packet.header.getPacketNumberSpace()]++;
  conn.outstandings
      .packetCount[outstandingPacket2.packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));
  conn.outstandings.packets.push_back(std::move(outstandingPacket2));
  conn.outstandings.clonedPacketCount[GetParam().pnSpace] = 1;
  conn.outstandings.clonedPacketIdentifiers.emplace(
      GetParam().pnSpace, packetNum1);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum2;
  ackFrame.ackBlocks.emplace_back(packetNum1, packetNum2);

  uint16_t ackVisitorCounter = 0;
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */)
      -> quic::Expected<void, quic::QuicError> {
    ackVisitorCounter++;
    return {};
  };
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [&](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(2, ackVisitorCounter);
  EXPECT_EQ(0, conn.outstandings.numClonedPackets());
}

TEST_P(AckHandlersTest, UpdateMaxAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr;
  conn.lossState.mrtt = 200us;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
  auto sentTime = Clock::now();
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket),
      sentTime,
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame ackFrame;
  // ackDelay has no effect on mrtt
  ackFrame.ackDelay = 50us;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);

  auto receiveTime = sentTime + 10us;
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          receiveTime)
          .hasError());
  EXPECT_EQ(10us, conn.lossState.mrtt);
}

// Ack only acks packets aren't outstanding, but TimeReordering still finds
// loss
TEST_P(AckHandlersTest, AckNotOutstandingButLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn.qLogger = mockQLogger;

  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 150ms;
  // Packet 2 has been sent and acked:
  if (GetParam().pnSpace == PacketNumberSpace::Initial) {
    conn.ackStates.initialAckState->largestAckedByPeer = 2;
  } else if (GetParam().pnSpace == PacketNumberSpace::Handshake) {
    conn.ackStates.handshakeAckState->largestAckedByPeer = 2;
  } else {
    conn.ackStates.appDataAckState.largestAckedByPeer = 2;
  }
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const CongestionController::AckEvent* FOLLY_NULLABLE ackEvent,
              const LossEvent* FOLLY_NULLABLE lossEvent) {
            EXPECT_FALSE(
                CHECK_NOTNULL(ackEvent)->largestNewlyAckedPacket.has_value());
            EXPECT_TRUE(
                CHECK_NOTNULL(lossEvent)->largestLostPacketNum.has_value());
          }));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);
  EXPECT_CALL(*rawPacketProcessor, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const AckEvent* FOLLY_NULLABLE ackEvent,
                           const LossEvent* FOLLY_NULLABLE lossEvent) {
        EXPECT_FALSE(
            CHECK_NOTNULL(ackEvent)->largestNewlyAckedPacket.has_value());
        EXPECT_TRUE(CHECK_NOTNULL(lossEvent)->largestLostPacketNum.has_value());
      }));
  // But packet 1 has been outstanding for longer than delayUntilLost:
  PacketNum packetNum = 1;
  auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
  // We need to at least have one frame to trigger ackVisitor
  WriteStreamFrame frame(0, 0, 0, true);
  regularPacket.frames.emplace_back(std::move(frame));
  auto delayUntilLost = 200ms *
      conn.transportSettings.timeReorderingThreshDividend /
      conn.transportSettings.timeReorderingThreshDivisor;
  OutstandingPacketWrapper outstandingPacket(
      std::move(regularPacket),
      Clock::now() - delayUntilLost - 20ms,
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packets.push_back(std::move(outstandingPacket));
  conn.outstandings.packetCount[GetParam().pnSpace]++;

  EXPECT_CALL(*mockQLogger, addPacketsLost(1, 1, 1));

  // Peer acks 2 again:
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 2;
  ackFrame.ackBlocks.emplace_back(2, 2);
  uint16_t ackVisitorCounter = 0;
  conn.lossState.largestSent = 2;
  // A counting ack visitor
  auto countingAckVisitor = [&](const auto& /* outstandingPacket */,
                                const auto& /* packetFrame */)
      -> quic::Expected<void, quic::QuicError> {
    ackVisitorCounter++;
    return {};
  };
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          countingAckVisitor,
          [](auto& /* conn */,
             auto /* pathId */,
             auto& /* packet */,
             bool /* processed */
             ) -> quic::Expected<void, quic::QuicError> { return {}; },
          Clock::now())
          .hasError());
  EXPECT_EQ(0, ackVisitorCounter);
}

TEST_P(AckHandlersTest, UpdatePendingAckStates) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr;
  conn.lossState.totalBytesSent = 2468;
  conn.lossState.totalBodyBytesSent = 2000;
  conn.lossState.totalBytesAcked = 1357;
  conn.lossState.totalBodyBytesAcked = 1000;
  PacketNum packetNum = 0;
  auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
  auto sentTime = Clock::now() - 1500ms;
  conn.outstandings.packetCount[regularPacket.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(regularPacket),
      sentTime,
      0,
      111,
      100,
      conn.lossState.totalBytesSent + 111,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  conn.lossState.totalBytesSent += 111;
  conn.lossState.totalBodyBytesSent += 100;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 0;
  ackFrame.ackBlocks.emplace_back(0, 0);

  auto receiveTime = Clock::now() - 200ms;
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          receiveTime)
          .hasError());
  EXPECT_EQ(2468 + 111, conn.lossState.totalBytesSentAtLastAck);
  EXPECT_EQ(1357 + 111, conn.lossState.totalBytesAckedAtLastAck);
  EXPECT_EQ(sentTime, *conn.lossState.lastAckedPacketSentTime);
  EXPECT_EQ(receiveTime, *conn.lossState.lastAckedTime);
  EXPECT_EQ(111 + 1357, conn.lossState.totalBytesAcked);
  EXPECT_EQ(100 + 1000, conn.lossState.totalBodyBytesAcked);
}

TEST_P(AckHandlersTest, AckEventCreation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;

  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_EQ(10, ack.totalBytesAcked);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam().pnSpace, ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        ASSERT_THAT(ack, Not(IsNull()));
        EXPECT_THAT(loss, IsNull());
        checkAck(*ack);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));
  EXPECT_CALL(*rawCongestionController, getBandwidth())
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  // check the AckEvent returned by processAckFrame so everything is filled
  // out
  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);
  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();
  checkAck(ackEvent);
  ASSERT_TRUE(ackEvent.ccState.has_value());
  EXPECT_EQ(writableBytes, ackEvent.ccState.value().writableBytes);
  EXPECT_EQ(congestionWindow, ackEvent.ccState.value().congestionWindowBytes);
}

TEST_P(AckHandlersTest, AckEventCreationSingleWrite) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  // all packets written in a single write
  auto getWriteCount = [](PacketNum /* packetNum */) { return 1; };
  auto getSentTime = [&startTime](PacketNum /* packetNum */) {
    return startTime + std::chrono::milliseconds(10ms);
  };

  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0, /* pathId */
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;

  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getLargestAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_EQ(10, ack.totalBytesAcked);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam().pnSpace, ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto loss) {
        EXPECT_THAT(ack, Not(IsNull()));
        EXPECT_THAT(loss, IsNull());
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));
  EXPECT_CALL(*rawCongestionController, getBandwidth())
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  // check the AckEvent returned by processAckFrame so everything is filled
  // out
  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);
  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();
  checkAck(ackEvent);
  ASSERT_TRUE(ackEvent.ccState.has_value());
  EXPECT_EQ(writableBytes, ackEvent.ccState.value().writableBytes);
  EXPECT_EQ(congestionWindow, ackEvent.ccState.value().congestionWindowBytes);
}

TEST_P(AckHandlersTest, AckEventCreationNoCongestionController) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.congestionController = nullptr; // no congestion control

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = getSentTime(9) + 10ms;
  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackTime, ack.ackTime);
    EXPECT_EQ(ackTime - ackFrame.ackDelay, ack.adjustedAckTime);
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);

    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(ul(9), ack.largestNewlyAckedPacket);
    EXPECT_EQ(getSentTime(9), ack.largestNewlyAckedPacketSentTime);
    EXPECT_THAT(
        ack.getLargestNewlyAckedPacket(),
        Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

    EXPECT_EQ(10, ack.ackedBytes);
    EXPECT_EQ(10, ack.totalBytesAcked);
    EXPECT_TRUE(ack.largestNewlyAckedPacketAppLimited);
    EXPECT_EQ(GetParam().pnSpace, ack.packetNumberSpace);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(ackTime - getSentTime(9)),
        ack.rttSample);
    EXPECT_EQ(
        std::chrono::ceil<std::chrono::microseconds>(
            ackTime - getSentTime(9) - ackFrame.ackDelay),
        ack.rttSampleNoAckDelay);
    EXPECT_THAT(ack.ackedPackets, SizeIs(10));
    EXPECT_THAT(
        ack.ackedPackets,
        ElementsAre(
            getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
            getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
            getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
            getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
            getAckPacketMatcher(4, getWriteCount(4), getSentTime(4)),
            getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
            getAckPacketMatcher(6, getWriteCount(6), getSentTime(6)),
            getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
            getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
            getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
  };

  // check the AckEvent returned by processAckFrame so everything is filled
  // out
  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);
  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();
  checkAck(ackEvent);
  ASSERT_FALSE(ackEvent.ccState.has_value()); // no congestion control
}

TEST_P(AckHandlersTest, AckEventReceiveTimestamps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.connectionTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  const TimePoint startTime = Clock::now();

  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);

  ReadAckFrame ackFrame;
  ackFrame.frameType = GetParam().frameType;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = startTime + 10ms + ackFrame.ackDelay;

  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;
  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        AckReceiveTimestampsConfig{
            .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};
    ackFrame.maybeLatestRecvdPacketNum = 9;
    ackFrame.maybeLatestRecvdPacketTime = 500ms;
    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
        .gap = 0,
        .timestamp_delta_count = 10,
        .deltas = {500000, 0, 100, 100, 100, 150000, 0, 100, 300, 400}};
    ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
    // Build the expected received timestamps.  buildExpectedReceiveTimestamps
    // always decrements the delta from the last timestamp, so just double the
    // first timestamp which is relative to connection start time.
    buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange1,
        expectedReceiveTimestamps,
        9 + recvdPacketsTimestampsRange1.gap,
        2 * 500000,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);
  }

  // check the AckEvent returned by processAckFrame so everything is filled
  // out
  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
          -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);
  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();

  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // Check the AckEvent is populated with the right receive
    // timestamps.
    testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
  } else {
    EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
    EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsGaps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  TimePoint startTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);

  ReadAckFrame ackFrame;
  ackFrame.frameType = GetParam().frameType;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(8, 9);
  ackFrame.ackBlocks.emplace_back(4, 6);
  ackFrame.ackBlocks.emplace_back(0, 1);
  ackFrame.ackDelay = 5ms;
  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;

  const auto ackTime = startTime + 10ms + ackFrame.ackDelay;
  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        AckReceiveTimestampsConfig{
            .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};
    ackFrame.maybeLatestRecvdPacketNum = 9;
    ackFrame.maybeLatestRecvdPacketTime = 500ms;
    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
        .gap = 0, .timestamp_delta_count = 2, .deltas = {500000, 100}};
    // Build the expected received timestamps. buildExpectedReceiveTimestamps
    // always decrements the delta from the last timestamp, so just double the
    // first timestamp which is relative to connection start time.
    auto lastReceiveTimestamp = buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange1,
        expectedReceiveTimestamps,
        9 + recvdPacketsTimestampsRange1.gap,
        2 * 500000,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);
    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange2 = {
        .gap = 0, .timestamp_delta_count = 3, .deltas = {100000, 100, 400}};

    lastReceiveTimestamp = buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange2,
        expectedReceiveTimestamps,
        6 + recvdPacketsTimestampsRange2.gap,
        lastReceiveTimestamp,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);

    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange3 = {
        .gap = 1, .timestamp_delta_count = 2, .deltas = {100000, 300}};

    lastReceiveTimestamp = buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange3,
        expectedReceiveTimestamps,
        1 + recvdPacketsTimestampsRange3.gap,
        lastReceiveTimestamp,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);

    ackFrame.recvdPacketsTimestampRanges = {
        recvdPacketsTimestampsRange1,
        recvdPacketsTimestampsRange2,
        recvdPacketsTimestampsRange3};
  }

  auto checkAck = [&](auto ack) {
    EXPECT_EQ(ackFrame.ackDelay, ack.ackDelay);
    EXPECT_EQ(ul(9), ack.largestAckedPacket);
    EXPECT_EQ(7, ack.ackedBytes);
    EXPECT_THAT(ack.ackedPackets, SizeIs(7));
  };

  // check the AckEvent returned by processAckFrame so everything is filled
  // out
  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
          -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);
  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();
  checkAck(ackEvent);

  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // Check the AckEvent is populated with the right receive
    // timestamps.
    testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
  } else {
    EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
    EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsDuplicatesAll) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  TimePoint startTime = Clock::now();

  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);
  ReadAckFrame ackFrame;
  ackFrame.frameType = GetParam().frameType;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  auto ackTime = startTime + 10ms + ackFrame.ackDelay;

  // Build the expected received timestamps map.
  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;
  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        AckReceiveTimestampsConfig{
            .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};
    ackFrame.maybeLatestRecvdPacketNum = 9;
    ackFrame.maybeLatestRecvdPacketTime = 500ms;
    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
        .gap = 0,
        .timestamp_delta_count = 10,
        .deltas = {500000, 0, 100, 200, 300, 150000, 0, 100, 300, 40}};
    buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange1,
        expectedReceiveTimestamps,
        9 + recvdPacketsTimestampsRange1.gap,
        2 * 500000,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);
    ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
  }
  {
    auto ackEventResult = processAckFrame(
        conn,
        GetParam().pnSpace,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
            -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackTime);
    ASSERT_FALSE(ackEventResult.hasError());
    auto ackEvent = ackEventResult.value();

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // All packets should be populated with timestamps.
      EXPECT_EQ(expectedReceiveTimestamps.size(), 10);
      testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
    }
  }

  {
    // Ack Events are not generated for fully duplicate ACKs since these
    // packets are already removed from outstanding queue. To test duplicate
    // receive timestamp detection, it's sufficient to verify new timestamps
    // were processed.
    // Send a duplicate ACK with the same ACK blocks and timestamps (assuming
    // this ACK was lost).
    auto ackEventResult2 = processAckFrame(
        conn,
        GetParam().pnSpace,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
            -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackTime);
    ASSERT_FALSE(ackEventResult2.hasError());
    auto ackEvent2 = ackEventResult2.value();

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // No new timestamps were processed.
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent2), 0);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      // No new timestamps were processed.
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent2), 0);
    }
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsPartialDuplicates) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  TimePoint startTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);
  // Build the expected received timestamps map.
  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;
  {
    ReadAckFrame ackFrame;
    ackFrame.frameType = GetParam().frameType;
    ackFrame.largestAcked = 5;
    ackFrame.ackBlocks.emplace_back(0, 5);
    ackFrame.ackDelay = 5ms;
    auto ackTime = startTime + 10ms + ackFrame.ackDelay;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
          AckReceiveTimestampsConfig{
              .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};
      ackFrame.maybeLatestRecvdPacketNum = 5;
      ackFrame.maybeLatestRecvdPacketTime = 500ms;
      RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
          .gap = 0,
          .timestamp_delta_count = 6,
          .deltas = {500000, 0, 100, 200, 300, 400}};

      ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
      buildExpectedReceiveTimestamps(
          recvdPacketsTimestampsRange1,
          expectedReceiveTimestamps,
          5 + recvdPacketsTimestampsRange1.gap,
          2 * 500000,
          conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value()
              .maxReceiveTimestampsPerAck);
    }
    // check the AckEvent returned by processAckFrame so everything is filled
    // out
    auto ackEventResult = processAckFrame(
        conn,
        GetParam().pnSpace,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
            -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackTime);
    ASSERT_FALSE(ackEventResult.hasError());
    auto ackEvent = ackEventResult.value();

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // All packets should be populated with timestamps.
      EXPECT_EQ(expectedReceiveTimestamps.size(), 6);
      // Check the AckEvent is populated with the right receive
      // timestamps.
      testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
    }
  }
  // Send a second ACK with Rx timestamps for the remaining packets but
  // include all 10 timestamps
  {
    ReadAckFrame ackFrame2;
    ackFrame2.frameType = GetParam().frameType;
    ackFrame2.largestAcked = 9;
    ackFrame2.ackBlocks.emplace_back(6, 9);
    ackFrame2.ackDelay = 5ms;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      ackFrame2.maybeLatestRecvdPacketNum = 9;
      ackFrame2.maybeLatestRecvdPacketTime = 700ms;
      RecvdPacketsTimestampsRange recvdPacketsTimestampsRange2 = {
          .gap = 0,
          .timestamp_delta_count = 10,
          .deltas = {700000, 0, 100, 200, 199700, 0, 100, 200, 300, 400}};
      ackFrame2.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange2};

      // Clear out the old timestamps.
      expectedReceiveTimestamps.clear();
      buildExpectedReceiveTimestamps(
          recvdPacketsTimestampsRange2,
          expectedReceiveTimestamps,
          9 + recvdPacketsTimestampsRange2.gap,
          2 * 700000,
          4);
    }

    UnorderedMap<PacketNum, uint64_t> receivedTimestamps;
    auto res =
        parseAckReceiveTimestamps(conn, ackFrame2, receivedTimestamps, 6);
    ASSERT_FALSE(res.hasError());
    // Ack Event will not have the old packets anyway so to unit-test
    // duplicate  detection, we will directly call parseAckReceiveTimestamps
    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // Check the AckEvent is populated with the right receive
      // timestamps for only the new packets.
      EXPECT_EQ(receivedTimestamps, expectedReceiveTimestamps);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      EXPECT_EQ(receivedTimestamps.size(), 0);
    }
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsOutOfOrderAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  TimePoint startTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.lossState.srtt = 1ms;
  conn.lossState.lrtt = 1ms;
  conn.lossState.reorderingThreshold = 20;
  conn.transportSettings.timeReorderingThreshDividend = 1000;
  conn.transportSettings.timeReorderingThreshDivisor = 1;
  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);
  // Build the expected received timestamps map.
  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;

  {
    // First send an ACK for (6-9) and not (0-5) with 6-9 timestamps. This is
    // unlikely to happen since 0-5 timestamps would probably also be in the
    // timestamp range but this depends on the max timestamps config.
    ReadAckFrame ackFrame;
    ackFrame.frameType = GetParam().frameType;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(5, 9);
    ackFrame.ackDelay = 5ms;
    auto ackTime = startTime + 10ms + ackFrame.ackDelay;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
          AckReceiveTimestampsConfig{
              .maxReceiveTimestampsPerAck = 5, .receiveTimestampsExponent = 3};
      ackFrame.maybeLatestRecvdPacketNum = 9;
      ackFrame.maybeLatestRecvdPacketTime = 500ms;
      RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
          .gap = 0,
          .timestamp_delta_count = 4,
          .deltas = {500000, 0, 100, 200, 300}};

      ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
      buildExpectedReceiveTimestamps(
          recvdPacketsTimestampsRange1,
          expectedReceiveTimestamps,
          9 + recvdPacketsTimestampsRange1.gap,
          2 * 500000,
          conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value()
              .maxReceiveTimestampsPerAck);
    }
    // check the AckEvent returned by processAckFrame so everything is filled
    // out
    auto ackEventResult = processAckFrame(
        conn,
        GetParam().pnSpace,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
            -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackTime);
    ASSERT_FALSE(ackEventResult.hasError());
    auto ackEvent = ackEventResult.value();

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // All packets should be populated with timestamps.
      EXPECT_EQ(expectedReceiveTimestamps.size(), 5);
      // Check the AckEvent is populated with the right receive
      // timestamps.
      testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
    }
  }
  // Send the out of order ACK for 0-4 now, which was originally sent first by
  // the client.
  {
    ReadAckFrame ackFrame2;
    ackFrame2.frameType = GetParam().frameType;
    ackFrame2.largestAcked = 4;
    ackFrame2.ackBlocks.emplace_back(0, 4);
    ackFrame2.ackDelay = 5ms;
    const auto ackTime = startTime + 10ms + 10ms + ackFrame2.ackDelay;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      ackFrame2.maybeLatestRecvdPacketNum = 4;
      ackFrame2.maybeLatestRecvdPacketTime = 300ms;
      RecvdPacketsTimestampsRange recvdPacketsTimestampsRange2 = {
          .gap = 0,
          .timestamp_delta_count = 10,
          .deltas = {300000, 0, 100, 200, 0}};
      ackFrame2.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange2};

      // Clear out the old timestamps.
      expectedReceiveTimestamps.clear();
      buildExpectedReceiveTimestamps(
          recvdPacketsTimestampsRange2,
          expectedReceiveTimestamps,
          4 + recvdPacketsTimestampsRange2.gap,
          2 * 300000,
          conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
              .value()
              .maxReceiveTimestampsPerAck);
    }

    // check the AckEvent returned by processAckFrame
    auto ackEventResult2 = processAckFrame(
        conn,
        GetParam().pnSpace,
        ackFrame2,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
            -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackTime);
    ASSERT_FALSE(ackEventResult2.hasError());
    auto ackEvent2 = ackEventResult2.value();

    EXPECT_EQ(ackEvent2.ackedPackets.size(), 5);
    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      // All packets should be populated with timestamps.
      EXPECT_EQ(expectedReceiveTimestamps.size(), 5);
      // The first six packets should be populated with timestamps.
      EXPECT_EQ(
          ackEvent2.ackedPackets.size(), expectedReceiveTimestamps.size());
      // Check the AckEvent is populated with the right receive
      // timestamps.
      testAckEventReceiveTimestampsAll(ackEvent2, expectedReceiveTimestamps);
    } else {
      EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
      EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent2), 0);
    }
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsMaxCheck) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.connectionTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  const TimePoint startTime = Clock::now();

  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);

  ReadAckFrame ackFrame;
  ackFrame.frameType = GetParam().frameType;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = 5ms;
  const auto ackTime = startTime + 10ms + ackFrame.ackDelay;
  // Build the expected received timestamps map for all ACK frame types.
  UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;
  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // Set max requested receive timestamps to 5 and send more than that.
    conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        AckReceiveTimestampsConfig{
            .maxReceiveTimestampsPerAck = 5, .receiveTimestampsExponent = 3};
    ackFrame.maybeLatestRecvdPacketNum = 9;
    ackFrame.maybeLatestRecvdPacketTime = 100ms;
    // Send 10 timestamps, more than requested.
    RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
        .gap = 0,
        .timestamp_delta_count = 10,
        .deltas = {500000, 0, 100, 100, 100, 150000, 0, 100, 300, 400}};
    ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
    // Build the expected received timestamps.  buildExpectedReceiveTimestamps
    // always decrements the delta from the last timestamp, so just double the
    // first timestamp which is relative to connection start time.
    buildExpectedReceiveTimestamps(
        recvdPacketsTimestampsRange1,
        expectedReceiveTimestamps,
        9 + recvdPacketsTimestampsRange1.gap,
        2 * 500000,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);
  }

  auto ackEventResult = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto& /*outstandingPacket*/, const auto& /*frame*/)
          -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackTime);

  ASSERT_FALSE(ackEventResult.hasError());
  auto ackEvent = ackEventResult.value();

  if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    // Number of packets with timestamps should be max(5).
    EXPECT_EQ(
        expectedReceiveTimestamps.size(),
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
            .maxReceiveTimestampsPerAck);
    EXPECT_NE(ackEvent.ackedPackets.size(), expectedReceiveTimestamps.size());
    // Check the AckEvent is populated with the right receive
    // timestamps (5-9 only). 0-4 should not be present.
    testAckEventReceiveTimestampsAll(ackEvent, expectedReceiveTimestamps);
  } else {
    EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
    EXPECT_EQ(getNumAckReceiveTimestamps(ackEvent), 0);
  }
}

TEST_P(AckHandlersTest, AckEventReceiveTimestampsInvalidCases) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  TimePoint startTime = Clock::now();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  // send 10 packets
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);
  auto firstPacketNum = 0;

  /**
   * Manufacture invalid ACK_RECEIVE_TIMESTAMPS frames and test the parsing
   * logic. There is no value in checking the final AckEvent as that is
   * dependent on the timestamp parsing logic anyway.
   */
  // Case 1: Missing timestamp ranges
  {
    ReadAckFrame ackFrame;
    ackFrame.frameType = GetParam().frameType;
    ackFrame.largestAcked = 5;
    ackFrame.ackBlocks.emplace_back(0, 5);
    ackFrame.ackDelay = 5ms;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
          AckReceiveTimestampsConfig{
              .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};
      ackFrame.maybeLatestRecvdPacketNum = 5;
      ackFrame.maybeLatestRecvdPacketTime = 100ms;
    }

    UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;

    auto res = parseAckReceiveTimestamps(
        conn, ackFrame, expectedReceiveTimestamps, firstPacketNum);
    ASSERT_FALSE(res.hasError());
    // No packets should be parsed/stored.
    EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
  }

  // Case 2: Missing timestamp deltas
  {
    ReadAckFrame ackFrame;
    ackFrame.frameType = GetParam().frameType;
    ackFrame.largestAcked = 5;
    ackFrame.ackBlocks.emplace_back(0, 5);
    ackFrame.ackDelay = 5ms;

    if (GetParam().frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
      ackFrame.maybeLatestRecvdPacketNum = 5;
      ackFrame.maybeLatestRecvdPacketTime = 100ms;
      RecvdPacketsTimestampsRange recvdPacketsTimestampsRange1 = {
          .gap = 0, .timestamp_delta_count = 6, .deltas = {}};
      ackFrame.recvdPacketsTimestampRanges = {recvdPacketsTimestampsRange1};
    }

    UnorderedMap<PacketNum, uint64_t> expectedReceiveTimestamps;
    auto res = parseAckReceiveTimestamps(
        conn, ackFrame, expectedReceiveTimestamps, firstPacketNum);
    ASSERT_FALSE(res.hasError());
    // No packets should be stored.
    EXPECT_EQ(expectedReceiveTimestamps.size(), 0);
  }
}

TEST_P(AckHandlersTest, AckEventCreationInvalidAckDelay) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = propDelay + 1ms; // impossible given ack and send time
  const auto ackTime = getSentTime(9) + propDelay; // do not include ack delay
  const auto writableBytes = 10;
  const auto congestionWindow = 20;

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
        EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(
            std::chrono::ceil<std::chrono::microseconds>(
                ackTime - getSentTime(9)),
            ack->rttSample);
        EXPECT_EQ(
            std::nullopt, // ack delay > RTT, so not set
            ack->rttSampleNoAckDelay);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));
  EXPECT_CALL(*rawCongestionController, getBandwidth())
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          ackTime)
          .hasError());
}

TEST_P(AckHandlersTest, AckEventCreationRttMinusAckDelayIsZero) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.ackDelay = propDelay; // equals prop delay
  const auto ackTime = getSentTime(9) + propDelay; // subtracting propDelay = 0
  const auto writableBytes = 10;
  const auto congestionWindow = 20;

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);
        EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
        EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(
            std::chrono::ceil<std::chrono::microseconds>(
                ackTime - getSentTime(9)),
            ack->rttSample);
        EXPECT_EQ(0ms, ack->rttSampleNoAckDelay);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));
  EXPECT_CALL(*rawCongestionController, getBandwidth())
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          ackTime)
          .hasError());
}

TEST_P(AckHandlersTest, AckEventCreationReorderingLargestPacketAcked) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController =
      std::make_unique<StrictMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  conn.lossState.srtt = 1ms;
  conn.lossState.lrtt = 1ms;
  conn.lossState.reorderingThreshold = 10;
  conn.transportSettings.timeReorderingThreshDividend = 1000;
  conn.transportSettings.timeReorderingThreshDivisor = 1;

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum packetNum) {
    return (packetNum <= 4) ? 1 : 2;
  };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime +
        std::chrono::milliseconds(10ms * ((packetNum <= 4) ? 1 : 2));
  };

  // write 10 packets, with half in write #1, the other half in write #2
  // packets in each write have the same timestamp and writeCount
  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  // AckFrame acking packets (0 -> 3, 7 -> 9)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(7, 9);
    ackFrame.ackBlocks.emplace_back(0, 3);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;

    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
          EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(
              ack->getLargestAckedPacket(),
              Pointee(
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

          EXPECT_EQ(propDelay + ackFrame.ackDelay, ack->rttSample);
          EXPECT_EQ(
              std::chrono::ceil<std::chrono::microseconds>(
                  ackTime - getSentTime(9)),
              ack->rttSample);
          EXPECT_EQ(propDelay, ack->rttSampleNoAckDelay);
          EXPECT_THAT(ack->ackedPackets, SizeIs(7));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(0, getWriteCount(0), getSentTime(0)),
                  getAckPacketMatcher(1, getWriteCount(1), getSentTime(1)),
                  getAckPacketMatcher(2, getWriteCount(2), getSentTime(2)),
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3)),
                  getAckPacketMatcher(7, getWriteCount(7), getSentTime(7)),
                  getAckPacketMatcher(8, getWriteCount(8), getSentTime(8)),
                  getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));
    EXPECT_CALL(*rawCongestionController, getBandwidth())
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackTime)
            .hasError());
  }

  // AckFrame acking packets (0 -> 4, 7 -> 9)
  // (e.g., packet 4 arrived later)
  //
  // no RTT sample as packet 9 acked (removed from OutstandingPackets) earlier
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(7, 9);
    ackFrame.ackBlocks.emplace_back(0, 4);
    ackFrame.ackDelay = 0ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay + 1ms;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;

    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(4), ack->largestNewlyAckedPacket); // 4 = newly acked
          EXPECT_EQ(getSentTime(4), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(ack->getLargestAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(4, getWriteCount(4), getSentTime(4))));

          EXPECT_EQ(std::nullopt, ack->rttSample); // no RTT sample
          EXPECT_EQ(std::nullopt, ack->rttSampleNoAckDelay); // no RTT sample
          EXPECT_THAT(ack->ackedPackets, SizeIs(1));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(4, getWriteCount(4), getSentTime(4))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));
    EXPECT_CALL(*rawCongestionController, getBandwidth())
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackTime)
            .hasError());
  }

  // AckFrame acking packets (0 -> 9)
  // (e.g., packet 5, 6 arrived later)
  //
  // no RTT sample as packet 9 acked (removed from OutstandingPackets) earlier
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(0, 9);
    ackFrame.ackDelay = 5ms;
    const auto ackTime = getSentTime(9) + propDelay + ackFrame.ackDelay + 2ms;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;

    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto /* loss */) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(9), ack->largestAckedPacket);
          EXPECT_EQ(ul(6), ack->largestNewlyAckedPacket); // 6 = newly acked
          EXPECT_EQ(getSentTime(6), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(ack->getLargestAckedPacket(), IsNull()); // unavailable
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(6, getWriteCount(6), getSentTime(6))));

          EXPECT_EQ(std::nullopt, ack->rttSample); // no RTT sample
          EXPECT_EQ(std::nullopt, ack->rttSampleNoAckDelay); // no RTT sample
          EXPECT_THAT(ack->ackedPackets, SizeIs(2));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(5, getWriteCount(5), getSentTime(5)),
                  getAckPacketMatcher(6, getWriteCount(6), getSentTime(6))));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));
    EXPECT_CALL(*rawCongestionController, getBandwidth())
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackTime)
            .hasError());
  }
}

TEST_P(AckHandlersTest, AckEventCreationNoMatchingPacketDueToLoss) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController =
      std::make_unique<StrictMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));

  // setting a very low reordering threshold to force loss by reorder
  conn.lossState.reorderingThreshold = 1;

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum /* packetNum */) { return 1; };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime + std::chrono::milliseconds(10ms * packetNum);
  };

  // write 4 packets
  while (packetNum < 4) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = false;
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }
  EXPECT_EQ(4, conn.outstandings.numOutstanding());

  // propagation delay used for this test
  const auto propDelay = 10ms;

  // AckFrame acking packets (0, 2, 3)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 3;
    ackFrame.ackBlocks.emplace_back(2, 3);
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(3) + propDelay + ackFrame.ackDelay;
    const auto writableBytes = 10;
    const auto congestionWindow = 20;

    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
        .Times(1)
        .WillOnce(Invoke([&](auto ack, auto loss) {
          EXPECT_EQ(ackTime, ack->ackTime);
          EXPECT_EQ(ackTime - ackFrame.ackDelay, ack->adjustedAckTime);
          EXPECT_EQ(ackFrame.ackDelay, ack->ackDelay);

          EXPECT_EQ(ul(3), ack->largestAckedPacket);
          EXPECT_EQ(ul(3), ack->largestNewlyAckedPacket);
          EXPECT_EQ(getSentTime(3), ack->largestNewlyAckedPacketSentTime);
          EXPECT_THAT(
              ack->getLargestAckedPacket(),
              Pointee(
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3))));
          EXPECT_THAT(
              ack->getLargestNewlyAckedPacket(),
              Pointee(
                  getAckPacketMatcher(3, getWriteCount(3), getSentTime(3))));

          EXPECT_EQ(propDelay + ackFrame.ackDelay, ack->rttSample);
          EXPECT_EQ(
              std::chrono::ceil<std::chrono::microseconds>(
                  ackTime - getSentTime(3)),
              ack->rttSample);
          EXPECT_EQ(propDelay, ack->rttSampleNoAckDelay);
          EXPECT_THAT(ack->ackedPackets, SizeIs(3));
          EXPECT_THAT(
              ack->ackedPackets,
              ElementsAre(
                  getAckPacketMatcher(0, 1 /* writeCount */, getSentTime(0)),
                  getAckPacketMatcher(2, 1 /* writeCount */, getSentTime(2)),
                  getAckPacketMatcher(3, 1 /* writeCount */, getSentTime(3))));

          // should have a loss as well
          EXPECT_THAT(loss, Not(IsNull()));
        }));
    EXPECT_CALL(*rawCongestionController, getWritableBytes())
        .WillOnce(Return(writableBytes));
    EXPECT_CALL(*rawCongestionController, getCongestionWindow())
        .WillOnce(Return(congestionWindow));
    EXPECT_CALL(*rawCongestionController, getBandwidth())
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackTime)
            .hasError());
  }

  // should have zero outstanding at this point
  EXPECT_EQ(0, conn.outstandings.numOutstanding());

  // AckFrame acking packets (0 -> 3)
  // (e.g., packet 1 arrived later)
  //
  // because packet 1 was already declared lost, no event
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 3;
    ackFrame.ackBlocks.emplace_back(2, 3);
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ackDelay = 10ms;
    const auto ackTime = getSentTime(3) + propDelay + ackFrame.ackDelay + 5ms;
    EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackTime)
            .hasError());
  }
}

TEST_P(AckHandlersTest, ImplictAckEventCreation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  conn.packetProcessors.push_back(std::move(mockPacketProcessor));
  conn.lossState.totalBytesAcked =
      100; // start with some bytes acked before the implicit ack

  const TimePoint startTime = Clock::now();
  PacketNum packetNum = 0;
  StreamId streamid = 0;

  auto getWriteCount = [](PacketNum /* packetNum */) { return 0; };
  auto getSentTime = [&startTime](PacketNum packetNum) {
    return startTime + std::chrono::milliseconds(10ms * packetNum);
  };

  while (packetNum < 10) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        getSentTime(packetNum),
        0 /* pathId */,
        1 /* encodedSizeIn */,
        0 /* encodedBodySizeIn */,
        1 * (packetNum + 1) /* totalBytesSentIn */,
        0 /* inflightBytesIn */,
        LossState(),
        getWriteCount(packetNum) /* writeCountIn */,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = (packetNum % 2);
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  // propagation delay used for this test
  const auto propDelay = 10ms;

  const auto srttBefore = conn.lossState.srtt;
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 9;
  ackFrame.ackBlocks.emplace_back(0, 9);
  ackFrame.implicit = true;
  const auto ackTime = getSentTime(9) + propDelay;
  const auto writableBytes = 10;
  const auto congestionWindow = 20;

  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](auto ack, auto /* loss */) {
        EXPECT_EQ(ackTime, ack->ackTime);

        EXPECT_EQ(ul(9), ack->largestAckedPacket);
        EXPECT_EQ(ul(9), ack->largestNewlyAckedPacket);
        EXPECT_EQ(getSentTime(9), ack->largestNewlyAckedPacketSentTime);
        EXPECT_TRUE(ack->largestNewlyAckedPacketAppLimited);
        EXPECT_THAT(
            ack->getLargestAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));
        EXPECT_THAT(
            ack->getLargestNewlyAckedPacket(),
            Pointee(getAckPacketMatcher(9, getWriteCount(9), getSentTime(9))));

        EXPECT_EQ(10, ack->ackedBytes);
        EXPECT_EQ(
            100,
            ack->totalBytesAcked); // implicit ack doesn't add new acked bytes
        EXPECT_TRUE(ack->implicit);
        EXPECT_FALSE(ack->rttSample.has_value());
        EXPECT_EQ(srttBefore, conn.lossState.srtt);
      }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(writableBytes));
  EXPECT_CALL(*rawCongestionController, getCongestionWindow())
      .WillOnce(Return(congestionWindow));
  EXPECT_CALL(*rawCongestionController, getBandwidth())
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_)).Times(1);

  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          ackTime)
          .hasError());
}

TEST_P(AckHandlersTest, ObserverRttSample) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::rttSamples);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send packet numbers 0 -> 29
  PacketNum packetNum = 0;
  StreamId streamid = 0;
  TimePoint sentTime;
  std::vector<TimePoint> packetRcvTime;
  while (packetNum < 30) {
    auto regularPacket = createNewPacket(packetNum, GetParam().pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(std::move(frame));
    sentTime = Clock::now() - 100ms + std::chrono::milliseconds(packetNum);
    packetRcvTime.emplace_back(sentTime);
    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;
    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        sentTime,
        0,
        1,
        0,
        packetNum,
        packetNum + 1,
        LossState(),
        0,
        OutstandingPacketMetadata::DetailsPerStream());
    sentPacket.isAppLimited = false;
    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    packetNum++;
  }

  struct AckFrameWithTestData {
    PacketNum startSeq, endSeq;
    std::chrono::milliseconds ackDelay;
    TimePoint ackTime;
    ReadAckFrame ackFrame;

    explicit AckFrameWithTestData(
        PacketNum startSeqIn,
        PacketNum endSeqIn,
        std::chrono::milliseconds ackDelayIn)
        : startSeq(startSeqIn),
          endSeq(endSeqIn),
          ackDelay(ackDelayIn),
          ackTime(Clock::now() + 5ms) {
      ackFrame.largestAcked = endSeq;
      ackFrame.ackDelay = ackDelay;
      ackFrame.ackBlocks.emplace_back(startSeq, endSeq);
    }
  };

  // See each emplace as the ACK Block [X, Y] with size (Y-X+1)
  std::vector<AckFrameWithTestData> ackVec;
  // Sequential test
  ackVec.emplace_back(0, 5, 4ms);
  ackVec.emplace_back(6, 10, 5ms);
  ackVec.emplace_back(11, 15, 6ms);
  // Out-of-order test
  ackVec.emplace_back(18, 18, 0ms);
  ackVec.emplace_back(16, 17, 2ms);
  ackVec.emplace_back(19, 29, 12ms);

  // Setup expectations, then process the actual ACKs
  for (const auto& ackData : ackVec) {
    auto rttSample = std::chrono::ceil<std::chrono::microseconds>(
        ackData.ackTime - packetRcvTime[ackData.endSeq]);
    EXPECT_CALL(
        *obs1,
        rttSampleGenerated(
            socket.get(),
            AllOf(
                Field(
                    &SocketObserverInterface::PacketRTT::rcvTime,
                    ackData.ackTime),
                Field(
                    &SocketObserverInterface::PacketRTT::rttSample, rttSample),
                Field(
                    &SocketObserverInterface::PacketRTT::ackDelay,
                    ackData.ackDelay),
                Field(
                    &SocketObserverInterface::PacketRTT::metadata,
                    Field(
                        &quic::OutstandingPacketMetadata::inflightBytes,
                        ackData.endSeq + 1)))));
  }
  for (const auto& ackData : ackVec) {
    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackData.ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackData.ackTime)
            .hasError());
  }

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, ObserverSpuriousLostEventReorderThreshold) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::lossEvents,
      SocketObserverInterface::Events::spuriousLossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send 10 packets
  TimePoint startTime = Clock::now();
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);

  // from [0, 9], [3, 4] already acked
  auto beginPacket = getFirstOutstandingPacket(conn, GetParam().pnSpace);
  conn.outstandings.packets.erase(beginPacket + 3, beginPacket + 5);
  conn.outstandings.packetCount[GetParam().pnSpace] -= 4;

  // setting a very low reordering threshold to force loss by reorder
  conn.lossState.reorderingThreshold = 1;
  // setting time out parameters higher than the time at which
  // detectLossPackets is called to make sure there are no losses by timeout
  conn.lossState.srtt = 400ms;
  conn.lossState.lrtt = 350ms;
  conn.transportSettings.timeReorderingThreshDividend = 1.0;
  conn.transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = startTime + 20ms;

  // expect packets to be marked lost on call to detectLostPackets
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(0, true, false),
                  MockLegacyObserver::getLossPacketMatcher(1, true, false),
                  MockLegacyObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);
  // Update the ackState
  // Both largestAckedByPeer (packet num) and
  // exercise loss by reorder path
  auto& ackState = getAckState(conn, GetParam().pnSpace);
  ackState.largestAckedByPeer = 4;
  ASSERT_FALSE(detectLossPackets(
                   conn,
                   ackState,
                   [](auto&, auto, auto&, bool)
                       -> quic::Expected<void, quic::QuicError> { return {}; },
                   checkTime,
                   GetParam().pnSpace)
                   .hasError());

  // now we get acks for packets marked lost, triggering spuriousLossDetected
  EXPECT_CALL(
      *obs1,
      spuriousLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(0, true, false),
                  MockLegacyObserver::getLossPacketMatcher(1, true, false),
                  MockLegacyObserver::getLossPacketMatcher(2, true, false)))))
      .Times(1);
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 2;
    ackFrame.ackBlocks.emplace_back(0, 2);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            startTime + 30ms)
            .hasError());
  }

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, ObserverSpuriousLostEventTimeout) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);
  conn.observerContainer = observerContainer;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::lossEvents,
      SocketObserverInterface::Events::spuriousLossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(obs1.get());

  // send 10 packets
  TimePoint startTime = Clock::now();
  emplacePackets(conn, 10, startTime, GetParam().pnSpace);

  // from [0, 9], [0, 4] already acked
  auto beginPacket = getFirstOutstandingPacket(conn, GetParam().pnSpace);
  conn.outstandings.packets.erase(beginPacket, beginPacket + 5);
  conn.outstandings.packetCount[GetParam().pnSpace] -= 5;

  // setting a very high reordering threshold to force loss by timeout only
  conn.lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which
  // detectLossPackets is called to make sure all packets timeout
  conn.lossState.srtt = 400ms;
  conn.lossState.lrtt = 350ms;
  conn.transportSettings.timeReorderingThreshDividend = 1.0;
  conn.transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = startTime + 500ms;

  // expect packets to be marked lost on call to detectLostPackets
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(5, false, true),
                  MockLegacyObserver::getLossPacketMatcher(6, false, true),
                  MockLegacyObserver::getLossPacketMatcher(7, false, true),
                  MockLegacyObserver::getLossPacketMatcher(8, false, true),
                  MockLegacyObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);

  // Update the ackState
  // Both largestAckedByPeer (packet num) and
  // exercise loss by reorder path
  auto& ackState = getAckState(conn, GetParam().pnSpace);
  ackState.largestAckedByPeer = 10;
  ASSERT_FALSE(detectLossPackets(
                   conn,
                   ackState,
                   [](auto&, auto, auto&, bool)
                       -> quic::Expected<void, quic::QuicError> { return {}; },
                   checkTime,
                   GetParam().pnSpace)
                   .hasError());

  // now we get acks for packets marked lost, triggering spuriousLossDetected
  EXPECT_CALL(
      *obs1,
      spuriousLossDetected(
          socket.get(),
          Field(
              &SocketObserverInterface::SpuriousLossEvent::spuriousPackets,
              UnorderedElementsAre(
                  MockLegacyObserver::getLossPacketMatcher(5, false, true),
                  MockLegacyObserver::getLossPacketMatcher(6, false, true),
                  MockLegacyObserver::getLossPacketMatcher(7, false, true),
                  MockLegacyObserver::getLossPacketMatcher(8, false, true),
                  MockLegacyObserver::getLossPacketMatcher(9, false, true)))))
      .Times(1);
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 9;
    ackFrame.ackBlocks.emplace_back(5, 9);

    ASSERT_FALSE(
        processAckFrame(
            conn,
            GetParam().pnSpace,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            startTime + 510ms)
            .hasError());
  }

  observerContainer->removeObserver(obs1.get());
}

TEST_P(AckHandlersTest, SubMicrosecondRTT) {
  // Verify that an ackReceive timestamp that is less than 1 us
  // after the packet send timestamp results in an rtt sample rounded up to 1
  // us rather than rounded down to 0. <1 us differences could occur because
  // we mix socket-provided timestamps for incoming packets (which can move
  // backwards) with steady_clock timestamps for outgoing packets. Clock
  // adjustments are more likely to result in < 1us differences when the
  // clients are close.
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  auto packetSendTime = Clock::now();
  auto packet = createNewPacket(5, GetParam().pnSpace);
  conn.outstandings.packetCount[packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      packetSendTime,
      0,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  ReadAckFrame ackFrame;
  auto ackReceiveTime = packetSendTime + 400ns;
  ackFrame.largestAcked = 5;
  ackFrame.ackBlocks.emplace_back(5, 5);
  ASSERT_FALSE(
      processAckFrame(
          conn,
          GetParam().pnSpace,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [](const auto&, const auto&)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          [](auto&, auto, auto&, bool)
              -> quic::Expected<void, quic::QuicError> { return {}; },
          ackReceiveTime)
          .hasError());
  EXPECT_EQ(conn.lossState.lrtt, 1us);
}

class AckEventForAppDataTest : public Test {
 public:
  void SetUp() override {
    aead_ = test::createNoOpAead();
    headerCipher_ = test::createNoOpHeaderCipher().value();
    conn_ = createConn();
  }

  static std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    // Disable packet number skipping. These tests are simpler to write for
    // contiguous packet numbers
    conn->transportSettings.skipOneInNPacketSequenceNumber = 0;
    conn->initialWriteCipher = createNoOpAead();
    conn->initialHeaderCipher = createNoOpHeaderCipher().value();
    CHECK(
        !conn->streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!conn->streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
    initializePathManagerState(*conn);
    return conn;
  }

  auto writeDataToQuicStreamAndGetFrame(
      QuicStreamState& stream,
      BufPtr&& data,
      const bool eof) {
    const auto offset = getLargestWriteOffsetSeen(stream);
    const auto len = data->computeChainDataLength();
    auto result = writeDataToQuicStream(stream, data->clone(), eof);
    CHECK(!result.hasError()) << result.error();
    return WriteStreamFrame(stream.id, offset, len, eof);
  }

  auto writeDataToQuicStreamAndGetFrame(
      const StreamId streamId,
      BufPtr&& data,
      const bool eof) {
    auto stream = conn_->streamManager->findStream(streamId);
    CHECK_NOTNULL(stream);
    return writeDataToQuicStreamAndGetFrame(*stream, std::move(data), eof);
  }

  auto writeDataToQuicStreamAndGetFrame(
      const StreamId streamId,
      const std::string& str,
      const bool eof) {
    return writeDataToQuicStreamAndGetFrame(
        streamId, folly::IOBuf::copyBuffer(str), eof);
  }

  auto buildEmptyPacket(
      const PacketNumberSpace pnSpace,
      const bool shortHeader = false) {
    Optional<PacketHeader> header;
    if (shortHeader) {
      header = ShortHeader(
          ProtectionType::KeyPhaseZero,
          *conn_->clientConnectionId,
          conn_->ackStates.appDataAckState.nextPacketNum);
    } else {
      if (pnSpace == PacketNumberSpace::Initial) {
        header = LongHeader(
            LongHeader::Types::Initial,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.initialAckState->nextPacketNum,
            *conn_->version);
      } else if (pnSpace == PacketNumberSpace::Handshake) {
        header = LongHeader(
            LongHeader::Types::Handshake,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.handshakeAckState->nextPacketNum,
            *conn_->version);
      } else if (pnSpace == PacketNumberSpace::AppData) {
        header = LongHeader(
            LongHeader::Types::ZeroRtt,
            *conn_->clientConnectionId,
            *conn_->serverConnectionId,
            conn_->ackStates.appDataAckState.nextPacketNum,
            *conn_->version);
      }
    }
    RegularQuicPacketBuilder builder(
        conn_->udpSendPacketLen,
        std::move(*header),
        getAckState(*conn_, pnSpace).largestAckedByPeer.value_or(0));
    auto result = builder.encodePacketHeader();
    CHECK(!result.hasError()) << result.error();
    DCHECK(builder.canBuildPacket());
    return std::move(builder).buildPacket();
  }

  uint64_t getEncodedSize(const RegularQuicPacketBuilder::Packet& packet) {
    // calculate size as the plaintext size
    uint32_t encodedSize = 0;
    if (!packet.header.empty()) {
      encodedSize += packet.header.computeChainDataLength();
    }
    if (!packet.body.empty()) {
      encodedSize += packet.body.computeChainDataLength();
    }
    return encodedSize;
  }

  uint64_t getEncodedBodySize(const RegularQuicPacketBuilder::Packet& packet) {
    // calculate size as the plaintext size
    uint32_t encodedBodySize = 0;
    if (!packet.body.empty()) {
      encodedBodySize += packet.body.computeChainDataLength();
    }
    return encodedBodySize;
  }

  void sendAppDataPacket(
      const RegularQuicPacketBuilder::Packet& packet,
      const TimePoint timepoint = Clock::now()) {
    auto pathInfo = conn_->pathManager->getPath(conn_->currentPathId);
    ASSERT_TRUE(pathInfo);
    CHECK(!updateConnection(
               *conn_,
               *pathInfo,
               std::nullopt,
               packet.packet,
               timepoint,
               getEncodedSize(packet),
               getEncodedBodySize(packet))
               .hasError());
  }

  auto deliverAckForAppDataPackets(
      const quic::AckBlocks& ackBlocks,
      const TimePoint timepoint = Clock::now(),
      const std::chrono::microseconds ackDelay = 0us,
      const std::function<void(ReadAckFrame&)>& customizeAckFrame = nullptr) {
    ReadAckFrame ackFrame = {};
    ackFrame.largestAcked = ackBlocks.back().end;
    ackFrame.ackDelay = ackDelay;

    // ack blocks are ordered based on the end packet number in the interval
    auto it = ackBlocks.crbegin();
    while (it != ackBlocks.crend()) {
      ackFrame.ackBlocks.emplace_back(it->start, it->end);
      it++;
    }
    if (customizeAckFrame) {
      customizeAckFrame(ackFrame);
    }

    auto result = processAckFrame(
        *conn_,
        PacketNumberSpace::AppData,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [&](const OutstandingPacketWrapper& /* packet */,
            const QuicWriteFrame& packetFrame)
            -> quic::Expected<void, QuicError> {
          switch (packetFrame.type()) {
            case QuicWriteFrame::Type::WriteStreamFrame: {
              const WriteStreamFrame& frame = *packetFrame.asWriteStreamFrame();
              MVVLOG(4) << "Received ack for stream=" << frame.streamId
                        << " offset=" << frame.offset << " fin=" << frame.fin
                        << " len=" << frame.len << " " << *conn_;
              auto ackedStreamResult =
                  conn_->streamManager->getStream(frame.streamId);
              CHECK(!ackedStreamResult.hasError()) << ackedStreamResult.error();
              auto& ackedStream = ackedStreamResult.value();
              if (ackedStream) {
                auto ackedSMHandlerResult =
                    sendAckSMHandler(*ackedStream, frame);
                CHECK(!ackedSMHandlerResult.hasError())
                    << ackedSMHandlerResult.error();
              }
            } break;
            case QuicWriteFrame::Type::WriteCryptoFrame: {
              const auto& frame = *packetFrame.asWriteCryptoFrame();
              return processCryptoStreamAck(
                  conn_->cryptoState->oneRttStream, frame.offset, frame.len);
            }
            default:
              CHECK(false);
          }
          return {};
        },
        [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        timepoint);
    CHECK(!result.hasError()) << result.error();
    return result.value();
  }

  auto deliverAckForAppDataPackets(
      const quic::PacketNum intervalStart,
      const quic::PacketNum intervalEnd,
      const TimePoint timepoint = Clock::now(),
      const std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks = {{intervalStart, intervalEnd}};
    return deliverAckForAppDataPackets(acks, timepoint, ackDelay);
  }

  auto getConn() {
    return conn_.get();
  }

 private:
  std::unique_ptr<Aead> aead_;
  std::unique_ptr<PacketNumberCipher> headerCipher_;
  std::unique_ptr<QuicServerConnectionState> conn_;
};

TEST_F(AckEventForAppDataTest, SpuriousAckProcessesUnifiedStreamData) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(nullptr, stream);
  ASSERT_TRUE(stream->streamSendBuffer.has_value());

  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream->id, "data", false);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  auto& outstanding = getConn()->outstandings.packets.back();
  outstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  EXPECT_TRUE(
      stream->streamSendBuffer->markLoss({frame.offset, frame.len, frame.fin}));
  EXPECT_TRUE(stream->streamSendBuffer->hasPendingLoss());

  const auto ack = deliverAckForAppDataPackets(packetNum, packetNum);

  EXPECT_EQ(1, ack.numPacketsSpuriouslyAcked);
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(0, stream->streamSendBuffer->outstandingBytes());
  EXPECT_EQ(frame.offset + frame.len - 1, getLargestDeliverableOffset(*stream));
  EXPECT_TRUE(getConn()->streamManager->deliverableContains(stream->id));

  // The packet is not reported in ackedPackets; the bytes its ACK delivered
  // are reported with the spurious-loss details.
  EXPECT_TRUE(ack.ackedPackets.empty());
  const auto& details = ack.spuriousLossDetailsPerStream.at(stream->id);
  EXPECT_EQ(frame.len, details.streamBytesAcked);
  const AckEvent::AckPacket::StreamDetails::StreamIntervals expected{
      {frame.offset, frame.offset + frame.len - 1}};
  EXPECT_EQ(expected, details.newlyDeliveredStreamIntervals);
}

class RecordingOopsLogger : public proto_oops::OopsLogger {
 public:
  using proto_oops::OopsLogger::log;

  void log(proto_oops::OopsFields fields) override {
    logged.push_back(std::move(fields));
  }

  std::vector<proto_oops::OopsFields> logged;
};

/**
 * A visitor that bypasses a live stream's ACK handler leaves the frame
 * unhandled: nothing is credited, and the server soft-reports it.
 */
TEST_F(AckEventForAppDataTest, UnhandledLiveStreamFrameAckIsSoftReported) {
  RecordingOopsLogger oopsLogger;
  getConn()->oopsLogger = &oopsLogger;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream->id, "data", false);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  ReadAckFrame ackFrame = {};
  ackFrame.largestAcked = packetNum;
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  const auto ack = processAckFrame(
      *getConn(),
      PacketNumberSpace::AppData,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const OutstandingPacketWrapper&, const QuicWriteFrame&)
          -> quic::Expected<void, QuicError> { return {}; },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());

  ASSERT_FALSE(ack.hasError());
  ASSERT_EQ(1, ack->ackedPackets.size());
  EXPECT_TRUE(ack->ackedPackets.front().detailsPerStream.empty());
  ASSERT_EQ(1, oopsLogger.logged.size());
  EXPECT_EQ(stream->id, oopsLogger.logged.front().streamId);
  EXPECT_THAT(
      oopsLogger.logged.front().errorMessage, HasSubstr("was not handled"));
  getConn()->oopsLogger = nullptr;
}

/**
 * The ACK of a frame whose stream was already removed is skipped by the ACK
 * visitor; that is expected and is not soft-reported.
 */
TEST_F(AckEventForAppDataTest, AckOfRemovedStreamFrameIsNotSoftReported) {
  RecordingOopsLogger oopsLogger;
  getConn()->oopsLogger = &oopsLogger;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  const auto streamId = stream->id;
  const auto frame = writeDataToQuicStreamAndGetFrame(streamId, "data", false);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(
      getConn()->streamManager->removeClosedStream(streamId).hasError());
  ASSERT_EQ(nullptr, getConn()->streamManager->findStream(streamId));

  const auto ack = deliverAckForAppDataPackets(packetNum, packetNum);

  ASSERT_EQ(1, ack.ackedPackets.size());
  EXPECT_TRUE(ack.ackedPackets.front().detailsPerStream.empty());
  EXPECT_THAT(oopsLogger.logged, IsEmpty());
  getConn()->oopsLogger = nullptr;
}

/**
 * Streams report increasing intervals within the ACKed frame, possibly ending
 * on its last byte. Reports outside the frame or out of order are clamped so
 * only frame bytes are credited, each once, and the violation is returned.
 */
TEST(AckEventDetailsPerStreamTest, RecordFrameDeliveryClampsToFrame) {
  const StreamId streamId = 4;
  const WriteStreamFrame frame(
      streamId, 10 /* offset */, 10 /* len */, false /* fin */);
  using StreamIntervals = AckEvent::AckPacket::StreamDetails::StreamIntervals;
  const auto delivered =
      [](std::initializer_list<std::pair<uint64_t, uint64_t>> intervals) {
        StreamFrameAckDelivery delivery;
        delivery.handled = true;
        for (const auto& [start, end] : intervals) {
          delivery.newlyDeliveredIntervals.emplace_back(start, end);
        }
        return delivery;
      };

  {
    AckEvent::AckPacket::DetailsPerStream details;
    EXPECT_TRUE(details.recordFrameDelivery(
        frame, delivered({{15, 19}}), false /* retransmission */));
    const StreamIntervals expected{{15, 19}};
    EXPECT_EQ(expected, details.at(streamId).newlyDeliveredStreamIntervals);
    EXPECT_EQ(5, details.at(streamId).streamBytesAcked);
  }

  {
    AckEvent::AckPacket::DetailsPerStream details;
    EXPECT_FALSE(details.recordFrameDelivery(
        frame, delivered({{5, 12}, {18, 25}}), false /* retransmission */));
    const StreamIntervals expected{{10, 12}, {18, 19}};
    EXPECT_EQ(expected, details.at(streamId).newlyDeliveredStreamIntervals);
    EXPECT_EQ(5, details.at(streamId).streamBytesAcked);
  }

  {
    AckEvent::AckPacket::DetailsPerStream details;
    EXPECT_FALSE(details.recordFrameDelivery(
        frame, delivered({{14, 16}, {12, 17}}), false /* retransmission */));
    const StreamIntervals expected{{14, 17}};
    EXPECT_EQ(expected, details.at(streamId).newlyDeliveredStreamIntervals);
    EXPECT_EQ(4, details.at(streamId).streamBytesAcked);
  }
}

TEST_F(AckEventForAppDataTest, SpuriousAckProcessesUnifiedCryptoData) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  getConn()->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = getConn()->cryptoState->oneRttStream;
  writeDataToQuicStream(
      *getConn(), cryptoStream, folly::IOBuf::copyBuffer("ticket"));
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData, true);
  packet.packet.frames.emplace_back(WriteCryptoFrame(0, 6));
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  auto& outstanding = getConn()->outstandings.packets.back();
  outstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markLoss({0, 6, false}));

  const auto ack = deliverAckForAppDataPackets(packetNum, packetNum);

  EXPECT_EQ(ack.numPacketsSpuriouslyAcked, 1);
  EXPECT_FALSE(cryptoStream.streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(cryptoStream.streamSendBuffer->outstandingBytes(), 0);
}

TEST_F(AckEventForAppDataTest, DuplicateSpuriousAckIsIdempotent) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(nullptr, stream);
  ASSERT_TRUE(stream->streamSendBuffer.has_value());

  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream->id, "data", false);
  auto firstPacket = buildEmptyPacket(PacketNumberSpace::AppData);
  firstPacket.packet.frames.emplace_back(frame);
  sendAppDataPacket(firstPacket);
  const auto firstPacketNum = firstPacket.packet.header.getPacketSequenceNum();
  auto& firstOutstanding = getConn()->outstandings.packets.back();
  firstOutstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  ASSERT_TRUE(
      stream->streamSendBuffer->markLoss({frame.offset, frame.len, frame.fin}));

  auto secondPacket = buildEmptyPacket(PacketNumberSpace::AppData);
  secondPacket.packet.frames.emplace_back(frame);
  sendAppDataPacket(secondPacket);
  const auto secondPacketNum =
      secondPacket.packet.header.getPacketSequenceNum();
  auto& secondOutstanding = getConn()->outstandings.packets.back();
  secondOutstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  ASSERT_TRUE(
      stream->streamSendBuffer->markLoss({frame.offset, frame.len, frame.fin}));

  deliverAckForAppDataPackets(firstPacketNum, firstPacketNum);
  const auto versionAfterFirstAck =
      stream->streamSendBuffer->ackInsertVersion();
  deliverAckForAppDataPackets(secondPacketNum, secondPacketNum);

  EXPECT_EQ(versionAfterFirstAck, stream->streamSendBuffer->ackInsertVersion());
  EXPECT_EQ(0, stream->streamSendBuffer->outstandingBytes());
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());
}

TEST_F(AckEventForAppDataTest, SpuriousAckProcessesUnifiedFinOnly) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(nullptr, stream);
  ASSERT_TRUE(stream->streamSendBuffer.has_value());

  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream->id, std::string(), true);
  ASSERT_EQ(0, frame.len);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  auto& outstanding = getConn()->outstandings.packets.back();
  outstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  EXPECT_TRUE(
      stream->streamSendBuffer->markLoss({frame.offset, frame.len, frame.fin}));
  EXPECT_TRUE(stream->streamSendBuffer->finLost());

  deliverAckForAppDataPackets(packetNum, packetNum);

  EXPECT_TRUE(stream->streamSendBuffer->finAcked());
  EXPECT_FALSE(stream->streamSendBuffer->finLost());
  EXPECT_EQ(StreamSendState::Closed, stream->sendState);
}

TEST_F(AckEventForAppDataTest, SpuriousAckDoesNotReplayControlFrames) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(nullptr, stream);
  ASSERT_TRUE(stream->streamSendBuffer.has_value());

  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream->id, "data", false);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  packet.packet.frames.emplace_back(PingFrame());
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  auto& outstanding = getConn()->outstandings.packets.back();
  outstanding.declaredLost = true;
  ++getConn()->outstandings.declaredLostCount;
  --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
  ASSERT_TRUE(
      stream->streamSendBuffer->markLoss({frame.offset, frame.len, frame.fin}));

  uint64_t streamFramesVisited = 0;
  uint64_t controlFramesVisited = 0;
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum;
  ackFrame.ackBlocks.emplace_back(packetNum, packetNum);
  auto result = processAckFrame(
      *getConn(),
      PacketNumberSpace::AppData,
      ackFrame,
      [](const auto&) -> quic::Expected<void, QuicError> { return {}; },
      [&](const auto&,
          const QuicWriteFrame& ackedFrame) -> quic::Expected<void, QuicError> {
        if (const auto* streamFrame = ackedFrame.asWriteStreamFrame()) {
          ++streamFramesVisited;
          return sendAckSMHandler(*stream, *streamFrame);
        }
        ++controlFramesVisited;
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, QuicError> {
        return {};
      },
      Clock::now());

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(1, streamFramesVisited);
  EXPECT_EQ(0, controlFramesVisited);
}

/**
 * Check AckEvent::ackTime, adjustedAckTime, and rttSample.
 *
 * Two packets sent, ACKed in single ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventAckTimeAndMrttSample) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  TimePoint startTime = Clock::now();

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  const auto packet1SendTime = startTime + 500ms;
  sendAppDataPacket(packet1, packet1SendTime);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  const auto packet2SendTime = packet1SendTime + 7ms;
  sendAppDataPacket(packet2, packet2SendTime);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1 and packet2
  const auto ackArrivalTime = packet2SendTime + 50ms;
  const auto ackDelay = 11ms;
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent[0],
      appDataPacketNumSent[1],
      ackArrivalTime,
      ackDelay);

  // check ackTime and adjustedAckTime
  EXPECT_EQ(ackArrivalTime, ackEvent.ackTime);
  EXPECT_EQ(ackArrivalTime - ackDelay, ackEvent.adjustedAckTime);

  // check mrtt sample (includes ack delay)
  EXPECT_EQ(ackArrivalTime - packet2SendTime, ackEvent.rttSample);
}

/**
 * Check AckEvent::ackedBytes, verify it includes bytes even if spurious.
 *
 * Two packets sent, ACKed in single ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventAckedBytes) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  sendAppDataPacket(packet1);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  sendAppDataPacket(packet2);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1 and packet2
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent[0], appDataPacketNumSent[1]);

  // check ackedBytes
  EXPECT_EQ(
      getEncodedSize(packet1) + getEncodedSize(packet2), ackEvent.ackedBytes);
  EXPECT_EQ(
      getEncodedSize(packet1) + getEncodedSize(packet2),
      ackEvent.totalBytesAcked);
}

/**
 * Check AckEvent::ackedBytes, verify it includes bytes even if spurious.
 *
 * Two packets sent, ACKed in two separate ACKs.
 */
TEST_F(AckEventForAppDataTest, AckEventAckedBytesSeparateAcks) {
  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  auto packet1 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(s1f1);
  sendAppDataPacket(packet1);
  appDataPacketNumSent.push_back(packet1.packet.header.getPacketSequenceNum());

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  // mimics a retransmission
  auto packet2 = buildEmptyPacket(PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(s1f1);
  packet2.packet.frames.push_back(s2f1);
  sendAppDataPacket(packet2);
  appDataPacketNumSent.push_back(packet2.packet.header.getPacketSequenceNum());

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedBytes
    EXPECT_EQ(getEncodedSize(packet1), ackEvent.ackedBytes);
    EXPECT_EQ(getEncodedSize(packet1), ackEvent.totalBytesAcked);
  }

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedBytes
    EXPECT_EQ(getEncodedSize(packet2), ackEvent.ackedBytes);
    EXPECT_EQ(
        getEncodedSize(packet1) + getEncodedSize(packet2),
        ackEvent.totalBytesAcked);
  }
}

/**
 * Verify that AckEventStreamDetailsMatcherBuilder matcher works correctly.
 */
TEST_F(AckEventForAppDataTest, AckEventStreamDetailsMatcher) {
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up?", false);

  // anon lambda to enable us to construct detailsPerStream and keep it const
  // this ensures the rest of our test does not modify it inadvertently
  const auto detailsPerStream = [&]() {
    AckEvent::AckPacket::DetailsPerStream detailsPerStreamL;
    const auto deliveredWholeFrame = [](const WriteStreamFrame& frame) {
      StreamFrameAckDelivery delivery;
      delivery.handled = true;
      delivery.newlyDeliveredIntervals.emplace_back(
          frame.offset, frame.offset + frame.len - 1);
      return delivery;
    };
    StreamFrameAckDelivery deliveredNothing;
    deliveredNothing.handled = true;
    detailsPerStreamL.recordFrameDelivery(
        s1f1, deliveredNothing, false /* retransmission */);
    detailsPerStreamL.recordFrameDelivery(
        s1f2, deliveredWholeFrame(s1f2), false /* retransmission */);
    detailsPerStreamL.recordFrameDelivery(
        s1f3, deliveredWholeFrame(s1f3), true /* retransmission */);
    return detailsPerStreamL;
  }();

  // default matcher builder
  const auto&& getDefaultBuilder = [&]() {
    return AckEventStreamDetailsMatcherBuilder()
        .setStreamID(s1Id)
        .setStreamBytesAcked(s1f2.len + s1f3.len)
        .setStreamBytesAckedByRetrans(s1f3.len)
        .addRedeliveredStreamInterval(s1f1.offset, s1f1.offset + s1f1.len - 1);
  };

  // correct
  {
    EXPECT_THAT(
        detailsPerStream, UnorderedElementsAre(getDefaultBuilder().build()));
  }

  // wrong stream id
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().setStreamID(s2Id).build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(getDefaultBuilder().setStreamID(s1Id).build()));
  }

  // wrong stream bytes acked
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .setStreamBytesAcked(s1f2.len + s1f3.len + 1)
                .build())));

    // prove that matcher works if fixed
    EXPECT_THAT(
        detailsPerStream,
        UnorderedElementsAre(
            getDefaultBuilder()
                .setStreamBytesAcked(s1f2.len + s1f3.len)
                .build()));
  }

  // wrong stream bytes acked (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().setStreamBytesAcked(0).build())));
  }

  // wrong stream bytes acked by retransmission
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .setStreamBytesAckedByRetrans(s1f3.len + 1)
                .build())));
  }

  // wrong redelivered stream intervals (add f3)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .addRedeliveredStreamInterval(
                    s1f3.offset, s1f3.offset + s1f3.len - 1) // wrong
                .build())));
  }

  // wrong redelivered stream intervals (clear and add f1 wrong)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder()
                .clearRedeliveredStreamIntervals()
                .addRedeliveredStreamInterval(
                    s1f1.offset, s1f1.offset + s1f1.len) // wrong
                .build())));
  }

  // wrong redelivered stream intervals (empty)
  {
    EXPECT_THAT(
        detailsPerStream,
        Not(UnorderedElementsAre(
            getDefaultBuilder().clearRedeliveredStreamIntervals().build())));
  }
}

TEST_F(
    AckEventForAppDataTest,
    PartialOverlapCountsOnlyNewBytesAsRetransmitted) {
  const auto streamId =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  const auto frame =
      writeDataToQuicStreamAndGetFrame(streamId, "0123456789", false);
  const auto overlapStart = frame.offset + 2;
  const auto overlapEnd = frame.offset + 5;
  StreamFrameAckDelivery delivery;
  delivery.handled = true;
  delivery.newlyDeliveredIntervals.emplace_back(frame.offset, overlapStart - 1);
  delivery.newlyDeliveredIntervals.emplace_back(
      overlapEnd + 1, frame.offset + frame.len - 1);

  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivery(
      frame, delivery, true /* retransmission */);

  const auto overlapLength = overlapEnd - overlapStart + 1;
  EXPECT_THAT(
      detailsPerStream,
      UnorderedElementsAre(
          AckEventStreamDetailsMatcherBuilder()
              .setStreamID(streamId)
              .setStreamBytesAcked(frame.len - overlapLength)
              .setStreamBytesAckedByRetrans(frame.len - overlapLength)
              .addRedeliveredStreamInterval(overlapStart, overlapEnd)
              .build()));
}

/**
 * Verify handling of stream details: five packets, one ACK for all five.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketSingleAck) {
  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // deliver an ACK with all five packets at once
  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));
  const auto ackEvent = deliverAckForAppDataPackets(
      appDataPacketNumSent.front(), appDataPacketNumSent.back());

  // check ackedPackets
  EXPECT_THAT(
      ackEvent.ackedPackets,
      ElementsAre(
          // pkt1
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f1.len)
                      .build(),
                  // s2f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f1.len)
                      .build())),
          // pkt2
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f2
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f2.len)
                      .build(),
                  // s2f2
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f2.len)
                      .build())),
          // pkt3
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f3
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f3.len)
                      .build(),
                  // s2f3
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f3.len)
                      .build())),
          // pkt4
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s3f1
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s3Id)
                      .setStreamBytesAcked(s3f1.len)
                      .build())),
          // pkt5
          Field(
              &AckEvent::AckPacket::detailsPerStream,
              UnorderedElementsAre(
                  // s1f4 w/ EOR
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s1Id)
                      .setStreamBytesAcked(s1f4.len)
                      .build(),
                  // s2f4 w/ EOR
                  AckEventStreamDetailsMatcherBuilder()
                      .setStreamID(s2Id)
                      .setStreamBytesAcked(s2f4.len)
                      .build()))));
}

/**
 * Verify handling of stream details: five packets, five ACKs.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketIndividualAcks) {
  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet 3
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[2], appDataPacketNumSent[2]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .build()))));
  }

  // deliver ACK for packet 5
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[4], appDataPacketNumSent[4]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet one arriving late.
 *
 * No delivery offset updates for stream 1 or stream 2 until packet 1 arrives.
 * Stream 3 won't be affected
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketOneOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 2 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[1], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f1 not received yet
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f1 not received yet
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f1 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f1 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f1 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f1 not received yet
                        .build()))));
  }

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet two arriving late.
 *
 * No delivery offset updates for stream 1 or stream 2 for frames in packets 4
 * and 5 until ACK for packet 2 arrives. Stream 3 won't be affected.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketTwoOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        // not affected by out of order
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet four arriving late.
 *
 * Since packet four contains only bytes for stream 3, and is the first packet
 * with bytes for stream 3, there should be no impact on delivery offsets.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketFourOutOfOrder) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1 - 3, and 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[2]);
    blocks.insert(appDataPacketNumSent[4], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .build()))));
  }
}

/**
 * Deliver packets out of order, with packet two arriving late.
 *
 * Each packet is ACKed individually.
 *
 * No delivery offset updates for stream 1 or stream 2 for frames in packets 4
 * and 5 until ACK for packet 2 arrives. Stream 3 won't be affected.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketTwoAcksPacketTwoOutOfOrderIndividualAcks) {
  getConn()->lossState.srtt = 1s;
  getConn()->lossState.lrtt = 1s;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet 3
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[2], appDataPacketNumSent[2]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        .build()))));
  }

  // deliver ACK for packet 5
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[4], appDataPacketNumSent[4]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet six ACKed, packet two never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventMultiStreamPacketPacketTwoRetrans) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        // not affected by out of order
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet two and packet six ACKed at the same time.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission)
 * for packet six, since packet two already arrived. We will however record
 * frames as having been duplicate ACKed for packet six.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        // not affected by out of order
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packets 2 and 6
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[1], appDataPacketNumSent[1]);
    blocks.insert(appDataPacketNumSent[5], appDataPacketNumSent[5]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build())),
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no change, since already ACKed by original
                        // retrans ACKed after original, so f2's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no change, since already ACKed by original
                        // retrans ACKed after original, so f2's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet six ACKed, then two ACKed.
 *
 * Stream bytes should be recorded for packet six as ACKed by retransmission.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission)
 * for packet two, since packet six already arrived. We will however record
 * frames as having been duplicate ACKed for packet two.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        // not affected by out of order
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f2.len)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f2.len)
                        .setStreamBytesAckedByRetrans(s2f2.len)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0)
                        .setStreamBytesAckedByRetrans(0)
                        // no change, since already ACKed by retrans
                        // original ACKed after retransmission, so f2's interval
                        // was redelivered
                        .addRedeliveredStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(0)
                        .setStreamBytesAckedByRetrans(0)
                        // no change, since already ACKed by retrans
                        // original ACKed after retransmission, so f2's interval
                        // was redelivered
                        .addRedeliveredStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frames in packet two retransmitted in packet six.
 * Packet two ACKed, then six ACKed.
 *
 * No stream bytes should be recorded as ACKed (including by retransmission)
 * for packet six, since packet two already arrived. We will however record
 * frames as having been duplicate ACKed for packet six.
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventMultiStreamPacketPacketTwoRetransSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two streams, both writing "hey whats up!" split across four frames
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "hey ", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s2f2 = writeDataToQuicStreamAndGetFrame(s2Id, "whats ", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up-", false);
  auto s2f3 = writeDataToQuicStreamAndGetFrame(s2Id, "up ", false);
  auto s1f4 = writeDataToQuicStreamAndGetFrame(s1Id, "!", true);
  auto s2f4 = writeDataToQuicStreamAndGetFrame(s2Id, "!", true);

  // third stream in which "yt??" is written in a single frame
  auto s3Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s3f1 = writeDataToQuicStreamAndGetFrame(s3Id, "yt??", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    packet.packet.frames.push_back(s2f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 4, frame 1 from stream 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s3f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 5, frame 4 from streams 1 & 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f4);
    packet.packet.frames.push_back(s2f4);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(5));

  // deliver ACK for packets 1, 3 - 5
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[4]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f3
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build())),
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s3f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s3Id)
                        // not affected by out of order
                        .build())),
            // pkt5
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no update due to out of order, f2 not received yet
                        .build(),
                    // s2f4 w/ EOR
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no update due to out of order, f2 not received yet
                        .build()))));
  }

  // packet 6, frame 2 from streams 1 & 2 (retrans of frame packet 1)
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    packet.packet.frames.push_back(s2f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(6));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // f1 - f4 now done, delivery offset = end of f4
                        .build()))));
  }

  // deliver ACK for packet 6
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[5], appDataPacketNumSent[5]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt6
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no change, since already ACKed by original
                        // retrans ACKed after original, so f2's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s1f2.offset, s1f2.offset + s1f2.len - 1)
                        .build(),
                    // s2f1
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        // no change, since already ACKed by original
                        // retrans ACKed after original, so f2's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s2f2.offset, s2f2.offset + s2f2.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same
 * stream. Second packet ACKed, original never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransHasNewFrame) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    // s1f1 + s1f2
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len + s1f2.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .build()))));
  }
}

TEST_F(
    AckEventForAppDataTest,
    PartiallyOverlappingFrameCreditsOnlyNewSubrange) {
  const auto streamId =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  const auto originalFrame =
      writeDataToQuicStreamAndGetFrame(streamId, "0123456789", false);
  const auto previouslyDeliveredStart =
      originalFrame.offset + originalFrame.len / 2;
  const auto previouslyDeliveredEnd =
      originalFrame.offset + originalFrame.len - 1;

  auto originalPacket = buildEmptyPacket(PacketNumberSpace::AppData);
  originalPacket.packet.frames.push_back(originalFrame);
  sendAppDataPacket(originalPacket);
  const auto originalPacketNum =
      originalPacket.packet.header.getPacketSequenceNum();

  auto* stream = getConn()->streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  stream->ackedIntervals.insert(
      previouslyDeliveredStart, previouslyDeliveredEnd);

  const auto originalAck =
      deliverAckForAppDataPackets(originalPacketNum, originalPacketNum);
  EXPECT_THAT(
      originalAck.ackedPackets,
      ElementsAre(Field(
          &AckEvent::AckPacket::detailsPerStream,
          UnorderedElementsAre(
              AckEventStreamDetailsMatcherBuilder()
                  .setStreamID(streamId)
                  .setStreamBytesAcked(originalFrame.len / 2)
                  .addRedeliveredStreamInterval(
                      previouslyDeliveredStart, previouslyDeliveredEnd)
                  .build()))));
}

TEST_F(
    AckEventForAppDataTest,
    UnifiedSendBufferPartiallyOverlappingFrameCreditsOnlyNewSubrange) {
  getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream =
      getConn()->streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  const auto originalFrame =
      writeDataToQuicStreamAndGetFrame(stream->id, "0123456789", false);
  const auto previouslyDeliveredLen = originalFrame.len / 2;
  const auto previouslyDeliveredStart =
      originalFrame.offset + originalFrame.len - previouslyDeliveredLen;
  const auto previouslyDeliveredEnd =
      originalFrame.offset + originalFrame.len - 1;

  auto originalPacket = buildEmptyPacket(PacketNumberSpace::AppData);
  originalPacket.packet.frames.push_back(originalFrame);
  sendAppDataPacket(originalPacket);
  const auto originalPacketNum =
      originalPacket.packet.header.getPacketSequenceNum();

  // Delivery of the second half was already credited before this ACK. The
  // unified send buffer, not QuicStreamState::ackedIntervals, records it.
  ASSERT_TRUE(stream->streamSendBuffer
                  ->markAcked(
                      {.offset = previouslyDeliveredStart,
                       .len = previouslyDeliveredLen,
                       .fin = false})
                  .has_value());
  ASSERT_TRUE(stream->ackedIntervals.empty());

  const auto originalAck =
      deliverAckForAppDataPackets(originalPacketNum, originalPacketNum);
  EXPECT_THAT(
      originalAck.ackedPackets,
      ElementsAre(Field(
          &AckEvent::AckPacket::detailsPerStream,
          UnorderedElementsAre(
              AckEventStreamDetailsMatcherBuilder()
                  .setStreamID(stream->id)
                  .setStreamBytesAcked(
                      originalFrame.len - previouslyDeliveredLen)
                  .setStreamBytesAckedByRetrans(0)
                  .addRedeliveredStreamInterval(
                      previouslyDeliveredStart, previouslyDeliveredEnd)
                  .build()))));
  const AckEvent::AckPacket::StreamDetails::StreamIntervals
      expectedNewlyDelivered{
          {originalFrame.offset, previouslyDeliveredStart - 1}};
  EXPECT_EQ(
      expectedNewlyDelivered,
      originalAck.ackedPackets.front()
          .detailsPerStream.at(stream->id)
          .newlyDeliveredStreamIntervals);
}

// Every byte of an ACKed frame is credited once, as inclusive intervals: a
// 100-byte frame [0, 99] credits [0, 99] and 100 bytes, and a frame whose first
// half was already delivered credits exactly its second half. Both send buffers
// must agree; the unified one reports half-open ranges internally.
TEST_F(AckEventForAppDataTest, AckCreditsEveryFrameByteAsInclusiveIntervals) {
  using StreamIntervals = AckEvent::AckPacket::StreamDetails::StreamIntervals;
  const std::string data(100, 'x');
  for (const bool unified : {false, true}) {
    SCOPED_TRACE(unified ? "unified send buffer" : "legacy send buffer");
    getConn()->transportSettings.useUnifiedAppStreamSendBuffer = unified;
    for (const bool firstHalfDelivered : {false, true}) {
      SCOPED_TRACE(firstHalfDelivered ? "first half delivered" : "whole frame");
      auto* stream =
          getConn()->streamManager->createNextBidirectionalStream().value();
      ASSERT_EQ(unified, stream->streamSendBuffer.has_value());
      const auto frame =
          writeDataToQuicStreamAndGetFrame(stream->id, data, false);
      ASSERT_EQ(0, frame.offset);
      ASSERT_EQ(100, frame.len);
      auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
      packet.packet.frames.push_back(frame);
      sendAppDataPacket(packet);
      const auto packetNum = packet.packet.header.getPacketSequenceNum();
      if (firstHalfDelivered) {
        if (unified) {
          ASSERT_TRUE(stream->streamSendBuffer
                          ->markAcked({.offset = 0, .len = 50, .fin = false})
                          .has_value());
        } else {
          stream->ackedIntervals.insert(0, 49);
        }
      }

      const auto ack = deliverAckForAppDataPackets(packetNum, packetNum);

      ASSERT_EQ(1, ack.ackedPackets.size());
      const auto details =
          ack.ackedPackets.front().detailsPerStream.at(stream->id);
      const StreamIntervals expected{
          firstHalfDelivered ? Interval<uint64_t>(50, 99)
                             : Interval<uint64_t>(0, 99)};
      EXPECT_EQ(expected, details.newlyDeliveredStreamIntervals);
      EXPECT_EQ(firstHalfDelivered ? 50 : 100, details.streamBytesAcked);
    }
  }
}

class AckEventForUnifiedSendBufferRetransmissionTest
    : public AckEventForAppDataTest {
 protected:
  void SetUp() override {
    AckEventForAppDataTest::SetUp();
    getConn()->transportSettings.useUnifiedAppStreamSendBuffer = true;
    stream_ = getConn()->streamManager->createNextBidirectionalStream().value();
    ASSERT_NE(stream_, nullptr);
    ASSERT_TRUE(stream_->streamSendBuffer.has_value());
    frame_ = writeDataToQuicStreamAndGetFrame(stream_->id, "data", false);

    // Send the frame, declare that packet lost, then retransmit the frame.
    auto originalPacket = buildEmptyPacket(PacketNumberSpace::AppData);
    originalPacket.packet.frames.emplace_back(*frame_);
    sendAppDataPacket(originalPacket);
    originalPacketNum_ = originalPacket.packet.header.getPacketSequenceNum();
    auto& originalOutstanding = getConn()->outstandings.packets.back();
    originalOutstanding.declaredLost = true;
    ++getConn()->outstandings.declaredLostCount;
    --getConn()->outstandings.packetCount[PacketNumberSpace::AppData];
    ASSERT_TRUE(stream_->streamSendBuffer->markLoss(
        {.offset = frame_->offset, .len = frame_->len, .fin = frame_->fin}));

    auto retransmissionPacket = buildEmptyPacket(PacketNumberSpace::AppData);
    retransmissionPacket.packet.frames.emplace_back(*frame_);
    sendAppDataPacket(retransmissionPacket);
    retransmissionPacketNum_ =
        retransmissionPacket.packet.header.getPacketSequenceNum();
    ASSERT_EQ(
        WriteStreamFrame::Origin::LossRetransmission,
        getConn()
            ->outstandings.packets.back()
            .packet.frames.front()
            .asWriteStreamFrame()
            ->origin);
    ASSERT_FALSE(stream_->streamSendBuffer->hasPendingLoss());
  }

  QuicStreamState* stream_{nullptr};
  Optional<WriteStreamFrame> frame_;
  PacketNum originalPacketNum_{0};
  PacketNum retransmissionPacketNum_{0};
};

TEST_F(
    AckEventForUnifiedSendBufferRetransmissionTest,
    RetransmissionAckCreditsRetransmittedBytes) {
  const auto retransmissionAck = deliverAckForAppDataPackets(
      retransmissionPacketNum_, retransmissionPacketNum_);
  EXPECT_THAT(
      retransmissionAck.ackedPackets,
      ElementsAre(Field(
          &AckEvent::AckPacket::detailsPerStream,
          UnorderedElementsAre(
              AckEventStreamDetailsMatcherBuilder()
                  .setStreamID(stream_->id)
                  .setStreamBytesAcked(frame_->len)
                  .setStreamBytesAckedByRetrans(frame_->len)
                  .build()))));
}

TEST_F(
    AckEventForUnifiedSendBufferRetransmissionTest,
    RetransmissionAckAfterSpuriousAckReportsRedelivery) {
  // Bytes delivered by the spurious ACK are not attributed to any AckEvent
  // per-stream detail.
  const auto originalAck =
      deliverAckForAppDataPackets(originalPacketNum_, originalPacketNum_);
  EXPECT_EQ(1, originalAck.numPacketsSpuriouslyAcked);
  EXPECT_THAT(originalAck.ackedPackets, IsEmpty());

  const auto retransmissionAck = deliverAckForAppDataPackets(
      retransmissionPacketNum_, retransmissionPacketNum_);
  EXPECT_THAT(
      retransmissionAck.ackedPackets,
      ElementsAre(Field(
          &AckEvent::AckPacket::detailsPerStream,
          UnorderedElementsAre(
              AckEventStreamDetailsMatcherBuilder()
                  .setStreamID(stream_->id)
                  .setStreamBytesAcked(0)
                  .setStreamBytesAckedByRetrans(0)
                  .addRedeliveredStreamInterval(
                      frame_->offset, frame_->offset + frame_->len - 1)
                  .build()))));
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same
 * stream. Original and second packet ACKed at same time (spurious).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packets 1 and 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        .setStreamBytesAckedByRetrans(0)
                        // moved forward to f2
                        // retrans ACKed after original, so f1's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same
 * stream. Original packet ACKed then second packet ACKed (spurious retrans).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .build()))));
  }

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f2.len)
                        // p1 ACKed earlier, so f1's interval was redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for same
 * stream. Second packet ACKed, then original packet ACKed (spurious + out of
 * order).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewFrameSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frames 1 and 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len + s1f2.len)
                        .build()))));
  }

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(0)
                        // no change, since already advanced by p2
                        // original ACKed after retransmission, so f1's interval
                        // was redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Second packet ACKed, original never ACKed.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransHasNewStreamFrame) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .setStreamBytesAcked(s1f1.len)
                        .setStreamBytesAckedByRetrans(s1f1.len)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .setStreamBytesAcked(s2f1.len)
                        .setStreamBytesAckedByRetrans(0)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Original and second packet ACKed at same time (spurious).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousOrigAckedSameTime) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packets 1 and 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build())),
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // retrans ACKed after original, so f1's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Original packet ACKed then second packet ACKed (spurious retrans).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousOrigThenRetransAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet 1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build()))));
  }

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // retrans ACKed after original, so f1's interval was
                        // redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }
}

/**
 * Frame retransmitted in a packet with a new frame (new data) for new stream.
 * Second packet ACKed, then original packet ACKed (spurious + out of order).
 */
TEST_F(
    AckEventForAppDataTest,
    AckEventRetransHasNewStreamFrameSpuriousRetransThenOrigAcked) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // two writes to two different streams
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s2Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s2f1 = writeDataToQuicStreamAndGetFrame(s2Id, "whats-", false);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 1 from stream 1 and frame 1 from stream 2
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s2f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(2));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build(),
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s2Id)
                        .build()))));
  }

  // deliver ACK for packet1
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[0], appDataPacketNumSent[0]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // no change, since already advanced by p2
                        // original ACKed after retransmission, so f1's interval
                        // was redelivered
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .build()))));
  }
}

/**
 * Scenario where there are multiple redelivered intervals on a packet ACK.
 */
TEST_F(AckEventForAppDataTest, AckEventRetransMultipleRedeliveries) {
  // prevent packets from being marked as lost
  // must initialize srtt and lrtt in parallel
  getConn()->lossState.srtt = 1ms;
  getConn()->lossState.lrtt = 1ms;
  getConn()->lossState.reorderingThreshold = 10;
  getConn()->transportSettings.timeReorderingThreshDividend = 1000;
  getConn()->transportSettings.timeReorderingThreshDivisor = 1;

  // three writes to a single stream
  auto s1Id =
      getConn()->streamManager->createNextBidirectionalStream().value()->id;
  auto s1f1 = writeDataToQuicStreamAndGetFrame(s1Id, "hey-", false);
  auto s1f2 = writeDataToQuicStreamAndGetFrame(s1Id, "whats-", false);
  auto s1f3 = writeDataToQuicStreamAndGetFrame(s1Id, "up?", true);

  std::vector<PacketNum> appDataPacketNumSent;

  // packet 1, frame 1 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 2, frame 2 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f2);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  // packet 3, frame 3 from stream 1
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(3));

  // deliver ACK for packet 2
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[1], appDataPacketNumSent[1]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt2
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // missing f1, so delivery offset cannot increase
                        .build()))));
  }

  // packet 4, retransmission of frame 1 and frame 3
  {
    auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
    packet.packet.frames.push_back(s1f1);
    packet.packet.frames.push_back(s1f3);
    sendAppDataPacket(packet);
    appDataPacketNumSent.push_back(packet.packet.header.getPacketSequenceNum());
  }

  ASSERT_THAT(appDataPacketNumSent, SizeIs(4));

  // deliver ACK for packet 1 and packet 3
  {
    AckBlocks blocks;
    blocks.insert(appDataPacketNumSent[0], appDataPacketNumSent[0]);
    blocks.insert(appDataPacketNumSent[2], appDataPacketNumSent[2]);
    const auto ackEvent = deliverAckForAppDataPackets(blocks);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt1
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // since f2 ACKed already, advance to there
                        .build())),
            // pkt3
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        .build()))));
  }

  // deliver ACK for packet 4
  {
    const auto ackEvent = deliverAckForAppDataPackets(
        appDataPacketNumSent[3], appDataPacketNumSent[3]);

    // check ackedPackets
    EXPECT_THAT(
        ackEvent.ackedPackets,
        ElementsAre(
            // pkt4
            Field(
                &AckEvent::AckPacket::detailsPerStream,
                UnorderedElementsAre(
                    AckEventStreamDetailsMatcherBuilder()
                        .setStreamID(s1Id)
                        // retrans ACKed after original, so its intervals were
                        // redelivered
                        // for both f1 and f3 (in ACKed packets p1 and p3)
                        .addRedeliveredStreamInterval(
                            s1f1.offset, s1f1.offset + s1f1.len - 1)
                        .addRedeliveredStreamInterval(
                            s1f3.offset, s1f3.offset + s1f3.len - 1)
                        .build()))));
  }
}

TEST_P(AckHandlersTest, SkippedPacketAckedProtocolViolation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto pnSpace = GetParam().pnSpace;
  conn.congestionController = nullptr;
  WriteStreamFrame frame(0, 0, 0, true);
  auto packetNum1 = getAckState(conn, pnSpace).nextPacketNum++;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam().pnSpace);
  regularPacket1.frames.push_back(frame);
  OutstandingPacketWrapper outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  outstandingPacket1.maybeClonedPacketIdentifier.emplace(
      GetParam().pnSpace, packetNum1);

  // Skip a packet number
  getAckState(conn, pnSpace).skippedPacketNum =
      getAckState(conn, pnSpace).nextPacketNum++;

  auto packetNum2 = getAckState(conn, pnSpace).nextPacketNum++;
  auto regularPacket2 = createNewPacket(packetNum2, GetParam().pnSpace);
  regularPacket2.frames.push_back(frame);
  OutstandingPacketWrapper outstandingPacket2(
      std::move(regularPacket2),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  conn.outstandings
      .packetCount[outstandingPacket1.packet.header.getPacketNumberSpace()]++;
  conn.outstandings
      .packetCount[outstandingPacket2.packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));
  conn.outstandings.packets.push_back(std::move(outstandingPacket2));

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum2;
  ackFrame.ackBlocks.emplace_back(packetNum1, packetNum2);

  auto result = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::PROTOCOL_VIOLATION);
}

TEST_P(AckHandlersTest, FuturePacketAckedProtocolViolation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto pnSpace = GetParam().pnSpace;
  conn.congestionController = nullptr;

  auto packetNum1 = getAckState(conn, pnSpace).nextPacketNum;
  auto packetNum2 = packetNum1 + 100;

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum2;
  ackFrame.ackBlocks.emplace_back(packetNum1, packetNum2);

  auto result = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::PROTOCOL_VIOLATION);
}

TEST_P(AckHandlersTest, SkippedPacketNumberClearedAfterDistance) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto pnSpace = GetParam().pnSpace;
  conn.congestionController = nullptr;
  WriteStreamFrame frame(0, 0, 0, true);

  // Skip a packet number
  getAckState(conn, pnSpace).skippedPacketNum =
      getAckState(conn, pnSpace).nextPacketNum++;

  getAckState(conn, pnSpace).nextPacketNum =
      getAckState(conn, pnSpace).nextPacketNum +
      kDistanceToClearSkippedPacketNumber;

  auto packetNum1 = getAckState(conn, pnSpace).nextPacketNum++;
  auto regularPacket1 = createNewPacket(packetNum1, GetParam().pnSpace);
  regularPacket1.frames.push_back(frame);
  OutstandingPacketWrapper outstandingPacket1(
      std::move(regularPacket1),
      Clock::now(),
      0,
      1,
      0,
      1,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  conn.outstandings
      .packetCount[outstandingPacket1.packet.header.getPacketNumberSpace()]++;
  conn.outstandings.packets.push_back(std::move(outstandingPacket1));

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = packetNum1;
  ackFrame.ackBlocks.emplace_back(packetNum1, packetNum1);

  auto result = processAckFrame(
      conn,
      GetParam().pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [&](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [&](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      Clock::now());
  ASSERT_FALSE(result.hasError());
  // Acking a genuine packet at sufficient distance from the skipped packet
  // should clear the skippedPacketNumber.
  ASSERT_FALSE(getAckState(conn, pnSpace).skippedPacketNum.has_value());
}

TEST_P(AckHandlersTest, InflightBytesDecrementOnAckIncludesLostBytes) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  // Avoid triggering time-based losses; force reordering-based loss.
  conn.lossState.srtt = 10s;
  conn.lossState.reorderingThreshold = 1;

  const auto pnSpace = GetParam().pnSpace;
  auto startTime = Clock::now();

  // Create 4 outstanding packets of equal encoded size (100 bytes each).
  const uint16_t kPktSize = 100;
  uint32_t inflightAtSend = 0;
  StreamId streamid = 100;
  for (PacketNum packetNum = 0; packetNum < 4; ++packetNum) {
    auto regularPacket = createNewPacket(packetNum, pnSpace);
    WriteStreamFrame frame(streamid++, 0, 0, true);
    regularPacket.frames.emplace_back(frame);

    conn.outstandings
        .packetCount[regularPacket.header.getPacketNumberSpace()]++;

    OutstandingPacketWrapper sentPacket(
        std::move(regularPacket),
        startTime + std::chrono::milliseconds(packetNum),
        /* pathId */ 0,
        /* encodedSizeIn */ kPktSize,
        /* encodedBodySizeIn */ 0,
        /* totalBytesSentIn */ static_cast<uint64_t>(packetNum + 1),
        /* inflightBytesIn */ inflightAtSend + kPktSize,
        LossState(),
        /* writeCountIn */ 0,
        OutstandingPacketMetadata::DetailsPerStream());

    conn.outstandings.packets.emplace_back(std::move(sentPacket));

    inflightAtSend += kPktSize;
  }

  // Initialize connection inflight bytes to the sum of outstanding packet
  // sizes. 4 packets * 100 bytes each = 400 bytes.
  conn.lossState.inflightBytes = inflightAtSend;

  // ACK packets 2 and 3. With reorderingThreshold = 1, packets 0 and 1
  // should be declared lost by reordering.
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 3;
  ackFrame.ackBlocks.emplace_back(2, 3);
  ackFrame.ackDelay = 0ms;

  auto res = processAckFrame(
      conn,
      pnSpace,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      startTime + 10ms);
  ASSERT_FALSE(res.hasError());

  // Inflight should be decremented by acked bytes (200) + lost bytes (200)
  // = 400, to 0.
  EXPECT_EQ(conn.lossState.inflightBytes, 0);
}

TEST_P(AckHandlersTest, ParseAckTimestampsWithNulloptLatestRecvdPacketNum) {
  // When maybeLatestRecvdPacketNum is std::nullopt,
  // parseAckReceiveTimestamps should crash via MVDCHECK (debug, server/desktop)
  // or return early via the fallback guard (release or mobile).
  // parseAckReceiveTimestamps is only called for AppData, so we hardcode it.
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());

  auto packetSendTime = Clock::now();

  // Send a packet in AppData space
  auto packet = createNewPacket(5, PacketNumberSpace::AppData);
  conn.outstandings.packetCount[PacketNumberSpace::AppData]++;
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      packetSendTime,
      0,
      1,
      0,
      5,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());

  // Enable receive timestamps config so parseAckReceiveTimestamps is exercised
  conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 3};

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = 5;
  ackFrame.ackBlocks.emplace_back(5, 5);

  // Set timestamp ranges but leave maybeLatestRecvdPacketNum as nullopt
  // This exercises the DCHECK fallback in parseAckReceiveTimestamps
  ackFrame.maybeLatestRecvdPacketNum = std::nullopt;
  ackFrame.maybeLatestRecvdPacketTime = 500ms;
  RecvdPacketsTimestampsRange range;
  range.gap = 0;
  range.timestamp_delta_count = 1;
  range.deltas.push_back(100);
  ackFrame.recvdPacketsTimestampRanges.push_back(range);

  auto ackReceiveTime = packetSendTime + 10ms;

#if !defined(NDEBUG) && !defined(_WIN32)
  // On server/desktop debug builds, MVDCHECK maps to DCHECK which aborts.
  EXPECT_DEATH(
      {
        (void)processAckFrame(
            conn,
            PacketNumberSpace::AppData,
            ackFrame,
            [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
            [](const auto&, const auto&)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            [](auto&, auto, auto&, bool)
                -> quic::Expected<void, quic::QuicError> { return {}; },
            ackReceiveTime);
      },
      "");
#else
  // In release or mobile builds, MVDCHECK is a no-op;
  // the fallback guard returns early without crashing.
  auto result = processAckFrame(
      conn,
      PacketNumberSpace::AppData,
      ackFrame,
      [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
      [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
        return {};
      },
      ackReceiveTime);
  ASSERT_FALSE(result.hasError());
#endif
}

INSTANTIATE_TEST_SUITE_P(
    AckHandlersTests,
    AckHandlersTest,
    Values(
        AckHandlersTestParam{PacketNumberSpace::Initial, FrameType::ACK},
        AckHandlersTestParam{PacketNumberSpace::Handshake, FrameType::ACK},
        AckHandlersTestParam{PacketNumberSpace::AppData, FrameType::ACK},
        AckHandlersTestParam{
            PacketNumberSpace::AppData,
            FrameType::ACK_RECEIVE_TIMESTAMPS}));

// draft-ietf-quic-receive-ts-02 ACK processing dispatch tests.
// `parseAckReceiveTimestamps` dispatches on `ReadAckFrame::timestampsVersion`.

namespace {

ReadAckFrame makeDraft02AckFrame(
    PacketNum largestAcked,
    Draft02ReceiveTimestampsRangeVec ranges) {
  ReadAckFrame frame;
  frame.frameType = FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02;
  frame.largestAcked = largestAcked;
  frame.ackBlocks.emplace_back(0, largestAcked);
  frame.timestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;
  frame.draft02RecvdPacketsTimestampRanges = std::move(ranges);
  return frame;
}

void setReceiveTimestampsConfig(
    QuicServerConnectionState& conn,
    uint64_t maxReceiveTimestamps) {
  conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = maxReceiveTimestamps,
          .receiveTimestampsExponent = 0};
}

struct LegacyAckFrameSpec {
  PacketNum largestAcked;
  PacketNum latestRecvdPacketNum;
  RecvdPacketsTimestampsRangeVec ranges;
};

ReadAckFrame makeLegacyAckFrame(LegacyAckFrameSpec spec) {
  ReadAckFrame frame;
  frame.frameType = FrameType::ACK_RECEIVE_TIMESTAMPS;
  frame.largestAcked = spec.largestAcked;
  frame.ackBlocks.emplace_back(0, spec.largestAcked);
  frame.timestampsVersion = AckReceiveTimestampsVersion::LegacyMvfst;
  frame.maybeLatestRecvdPacketNum = spec.latestRecvdPacketNum;
  frame.maybeLatestRecvdPacketTime = 500us;
  frame.recvdPacketsTimestampRanges = std::move(spec.ranges);
  return frame;
}

UnorderedMap<PacketNum, uint64_t> timestampsByPacketNum(
    std::initializer_list<std::pair<const PacketNum, uint64_t>> entries) {
  UnorderedMap<PacketNum, uint64_t> timestamps;
  timestamps.insert(entries);
  return timestamps;
}

} // namespace

TEST(Draft02AckProcessing, UsesDraft02ParserAndComputesPktNumsFromDelta) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // Single range: deltaLargestAcked = 0 (range top == largestAcked),
  // 3 deltas -> packets {100, 99, 98} with timestamps {500, 490, 485}.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 3,
        .deltas = {500, 10, 5}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  ASSERT_EQ(out.size(), 3);
  EXPECT_EQ(out[100], 500);
  EXPECT_EQ(out[99], 490);
  EXPECT_EQ(out[98], 485);
}

TEST(Draft02AckProcessing, NonMonotonicPktNumAcrossRanges) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // largestAcked = 100. Two ranges:
  //   range 1: deltaLargestAcked = 5  -> range top = 95, deltas [200] -> pkt 95
  //   range 2: deltaLargestAcked = 0  -> range top = 100, deltas [180] -> pkt
  //   100
  // Per spec, ranges are descending receive-time order but packet numbers can
  // be non-monotonic (range 2's pktNum > range 1's because range 2 was
  // received earlier in time but has a higher pktNum).
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 5,
        .timestamp_delta_count = 1,
        .deltas = {200}},
       {.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 1,
        .deltas = {20}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  ASSERT_EQ(out.size(), 2);
  EXPECT_EQ(out[95], 200);
  EXPECT_EQ(out[100], 180); // 200 - 20 (previousTimestamp chains across ranges)
}

TEST(Draft02AckProcessing, ChainedTimestampDeltasAcrossRangeBoundary) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // Range 1: pkt 100, 99 -> timestamps {500, 490}
  // Range 2: pkt 50 -> timestamp 490 - 5 = 485 (chained from range 1's last).
  // No extra decrement between ranges.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 2,
        .deltas = {500, 10}},
       {.deltaLargestAcknowledged = 50,
        .timestamp_delta_count = 1,
        .deltas = {5}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  ASSERT_EQ(out.size(), 3);
  EXPECT_EQ(out[100], 500);
  EXPECT_EQ(out[99], 490);
  EXPECT_EQ(out[50], 485);
}

TEST(Draft02AckProcessing, OverLimitReturnsFrameEncodingError) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, /*maxReceiveTimestamps=*/3);
  // Total deltas across ranges = 4 > advertised max 3.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 2,
        .deltas = {500, 10}},
       {.deltaLargestAcknowledged = 5,
        .timestamp_delta_count = 2,
        .deltas = {5, 5}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST(LegacyAckProcessing, OverLimitDoesNotError) {
  // Legacy parser preserves the soft-log/return behavior: over-limit must
  // not surface as FRAME_ENCODING_ERROR.
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, /*maxReceiveTimestamps=*/3);
  ReadAckFrame frame;
  frame.frameType = FrameType::ACK_RECEIVE_TIMESTAMPS;
  frame.largestAcked = 100;
  frame.ackBlocks.emplace_back(0, 100);
  frame.timestampsVersion = AckReceiveTimestampsVersion::LegacyMvfst;
  frame.maybeLatestRecvdPacketNum = 100;
  frame.maybeLatestRecvdPacketTime = 500us;
  // 4 deltas total in one range (exceeds max=3).
  frame.recvdPacketsTimestampRanges = {
      {.gap = 0, .timestamp_delta_count = 4, .deltas = {500, 10, 10, 10}}};
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  // Legacy soft-return stops at the advertised max (no error).
  EXPECT_LE(out.size(), 3u);
}

TEST(Draft02AckProcessing, IgnoresPreviouslyAckedTimestamps) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // largestAcked = 100; firstPacketNum = 99 means packets below 99 were
  // already acked. Per spec, their timestamps must be ignored but processing
  // must continue for the still-outstanding packets.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 3,
        .deltas = {500, 10, 5}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/99);
  ASSERT_FALSE(res.hasError());
  // pkts 100 and 99 still outstanding -> kept; pkt 98 < 99 -> dropped.
  EXPECT_EQ(out.count(100), 1);
  EXPECT_EQ(out.count(99), 1);
  EXPECT_EQ(out.count(98), 0);
}

TEST(
    Draft02AckProcessing,
    CapturesOutstandingPacketsInLaterRangesAfterAllAckedRange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // largestAcked = 100; firstPacketNum = 50.
  //   range 1: deltaLargestAcked = 70 -> range top = 30, deltas [600, 5, 5]
  //            covers packets {30, 29, 28}. All below firstPacketNum (50),
  //            all skipped.
  //   range 2: deltaLargestAcked = 40 -> range top = 60, deltas [100, 5, 5]
  //            covers packets {60, 59, 58}. All >= firstPacketNum (50), all
  //            captured. Timestamps chain from range 1's previousTimestamp.
  // The draft-02 parser must SKIP (continue) past acked packets rather than
  // RETURN like the legacy parser, so range 2's outstanding packets are
  // captured.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 70,
        .timestamp_delta_count = 3,
        .deltas = {600, 5, 5}},
       {.deltaLargestAcknowledged = 40,
        .timestamp_delta_count = 3,
        .deltas = {100, 5, 5}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/50);
  ASSERT_FALSE(res.hasError());
  ASSERT_EQ(out.size(), 3);
  // range 1 packets all dropped (below firstPacketNum).
  EXPECT_EQ(out.count(30), 0);
  EXPECT_EQ(out.count(29), 0);
  EXPECT_EQ(out.count(28), 0);
  // previousTimestamp progression across both ranges:
  //   range 1: 600 -> 595 -> 590  (computed but skipped, packets < 50)
  //   range 2: 590 - 100 = 490 -> 485 -> 480
  EXPECT_EQ(out[60], 490);
  EXPECT_EQ(out[59], 485);
  EXPECT_EQ(out[58], 480);
}

TEST(Draft02AckProcessing, RejectsTimestampUnderflow) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // Second delta (200) exceeds previousTimestamp (100): `100 - 200` would
  // underflow uint64_t. A valid peer cannot encode a negative timestamp, so
  // this is a protocol violation.
  auto frame = makeDraft02AckFrame(
      100,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 2,
        .deltas = {100, 200}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST(LegacyAckProcessing, AnchorsRangesOnLargestAcked) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // Packets 99 and 100 overtook packet 98, so the last packet to arrive is not
  // the highest-numbered one and `maybeLatestRecvdPacketNum` trails Largest
  // Acknowledged. The peer still seeds the walk at Largest Acknowledged, so the
  // timestamped run starts at 100 - gap == 98.
  auto frame = makeLegacyAckFrame(
      {.largestAcked = 100,
       .latestRecvdPacketNum = 98,
       .ranges = {
           {.gap = 2, .timestamp_delta_count = 3, .deltas = {500, 10, 20}}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(out, timestampsByPacketNum({{98, 500}, {97, 490}, {96, 470}}));
}

TEST(LegacyAckProcessing, DecodesTwoRangesTheEncoderWould) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  setReceiveTimestampsConfig(conn, 10);
  // Gaps as `fillFrameWithPacketReceiveTimestamps()` computes them for
  // timestamped runs [97,98] and [91,92] under Largest Acknowledged 100:
  //   range 1 is seeded from largestAcked:   gap = 100 - 98        == 2
  //   range 2 chains off the previous
  //   range's start, less the implicit -1
  //   on each side of the boundary:          gap = 97 - 2 - 92     == 3
  // `latestRecvdPacketNum` is the last packet to *arrive*, picked
  // independently of the first range's end, and the parser only checks it for
  // presence -- so its value does not affect the expectation below.
  // Decoding those two gaps must land back on 98 and 92.
  auto frame = makeLegacyAckFrame(
      {.largestAcked = 100,
       .latestRecvdPacketNum = 98,
       .ranges = {
           {.gap = 2, .timestamp_delta_count = 2, .deltas = {500, 10}},
           {.gap = 3, .timestamp_delta_count = 2, .deltas = {40, 20}}}});
  UnorderedMap<PacketNum, uint64_t> out;
  auto res = parseAckReceiveTimestamps(conn, frame, out, /*firstPacketNum=*/0);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(
      out, timestampsByPacketNum({{98, 500}, {97, 490}, {92, 450}, {91, 430}}));
}

class AckEventUndeliveredStreamFrameTest
    : public AckEventForAppDataTest,
      public WithParamInterface<bool /* useUnifiedSendBuffer */> {
 protected:
  void SetUp() override {
    AckEventForAppDataTest::SetUp();
    getConn()->transportSettings.useUnifiedAppStreamSendBuffer = GetParam();
    stream_ = getConn()->streamManager->createNextBidirectionalStream().value();
    ASSERT_NE(stream_, nullptr);
    ASSERT_EQ(GetParam(), stream_->streamSendBuffer.has_value());
  }

  QuicStreamState* stream_{nullptr};
};

INSTANTIATE_TEST_SUITE_P(
    SendBufferModes,
    AckEventUndeliveredStreamFrameTest,
    Values(false, true),
    [](const TestParamInfo<bool>& info) {
      return info.param ? "Unified" : "Legacy";
    });

TEST_P(AckEventUndeliveredStreamFrameTest, AckAfterResetCreditsNothing) {
  const auto frame =
      writeDataToQuicStreamAndGetFrame(stream_->id, "data", false);
  auto packet = buildEmptyPacket(PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(frame);
  sendAppDataPacket(packet);
  const auto packetNum = packet.packet.header.getPacketSequenceNum();

  // The reset discards the stream's send state, so the ACK below does not
  // mark the frame's bytes delivered.
  ASSERT_FALSE(resetQuicStream(*stream_, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());

  const auto ack = deliverAckForAppDataPackets(packetNum, packetNum);
  ASSERT_EQ(1, ack.ackedPackets.size());
  EXPECT_TRUE(ack.ackedPackets.front()
                  .detailsPerStream.at(stream_->id)
                  .newlyDeliveredStreamIntervals.empty());
  EXPECT_THAT(
      ack.ackedPackets,
      ElementsAre(Field(
          &AckEvent::AckPacket::detailsPerStream,
          UnorderedElementsAre(
              AckEventStreamDetailsMatcherBuilder()
                  .setStreamID(stream_->id)
                  .setStreamBytesAcked(0)
                  .addRedeliveredStreamInterval(
                      frame.offset, frame.offset + frame.len - 1)
                  .build()))));
}

class AckEventFirstArrivalTest : public AckEventUndeliveredStreamFrameTest {
 protected:
  using FirstArrival = AckEvent::AckPacket::FirstArrival;

  // Sends the original packet carrying `frame_`, then a clone of it, the way
  // the cloning scheduler does: both carry the same ClonedPacketIdentifier.
  void sendOriginalAndClone() {
    frame_ = writeDataToQuicStreamAndGetFrame(stream_->id, "hello", false);
    auto original = buildEmptyPacket(PacketNumberSpace::AppData);
    original.packet.frames.emplace_back(*frame_);
    sendAppDataPacket(original);
    originalPacketNum_ = original.packet.header.getPacketSequenceNum();

    auto& originalOutstanding = getConn()->outstandings.packets.back();
    const ClonedPacketIdentifier cloneId(
        PacketNumberSpace::AppData, originalPacketNum_);
    originalOutstanding.maybeClonedPacketIdentifier = cloneId;
    getConn()->outstandings.clonedPacketIdentifiers.insert(cloneId);
    ++getConn()->outstandings.clonedPacketCount[PacketNumberSpace::AppData];

    auto clone = buildEmptyPacket(PacketNumberSpace::AppData);
    clone.packet.frames.emplace_back(*frame_);
    auto pathInfo = getConn()->pathManager->getPath(getConn()->currentPathId);
    ASSERT_TRUE(pathInfo);
    ASSERT_FALSE(updateConnection(
                     *getConn(),
                     *pathInfo,
                     cloneId,
                     clone.packet,
                     Clock::now(),
                     getEncodedSize(clone),
                     getEncodedBodySize(clone),
                     PacketTransmissionReason::PtoProbe)
                     .hasError());
    clonePacketNum_ = clone.packet.header.getPacketSequenceNum();
    ASSERT_EQ(originalPacketNum_ + 1, clonePacketNum_);
  }

  // ACKs both copies in one ACK frame. With `deltas`, the peer reports
  // receive timestamps for the clone, then the original.
  AckEvent ackBothCopies(Optional<std::array<uint64_t, 2>> deltas) {
    if (deltas) {
      getConn()->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
          AckReceiveTimestampsConfig{
              .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 0};
    }
    return deliverAckForAppDataPackets(
        {{originalPacketNum_, clonePacketNum_}},
        Clock::now(),
        0us,
        [&](ReadAckFrame& ackFrame) {
          if (!deltas) {
            return;
          }
          ackFrame.frameType = FrameType::ACK_RECEIVE_TIMESTAMPS;
          ackFrame.timestampsVersion = AckReceiveTimestampsVersion::LegacyMvfst;
          ackFrame.maybeLatestRecvdPacketNum = clonePacketNum_;
          ackFrame.maybeLatestRecvdPacketTime = 1ms;
          ackFrame.recvdPacketsTimestampRanges = {RecvdPacketsTimestampsRange{
              .gap = 0,
              .timestamp_delta_count = 2,
              .deltas = {(*deltas)[0], (*deltas)[1]}}};
        });
  }

  const AckEvent::AckPacket& ackedPacket(
      const AckEvent& ack,
      PacketNum packetNum) {
    const auto it =
        std::ranges::find_if(ack.ackedPackets, [packetNum](const auto& packet) {
          return packet.packetNum == packetNum;
        });
    CHECK(it != ack.ackedPackets.end());
    return *it;
  }

  uint64_t creditedBytes(const AckEvent& ack) {
    uint64_t total = 0;
    for (const auto& packet : ack.ackedPackets) {
      const auto it = packet.detailsPerStream.find(stream_->id);
      if (it != packet.detailsPerStream.end()) {
        total += it->second.streamBytesAcked;
      }
    }
    return total;
  }

  Optional<WriteStreamFrame> frame_;
  PacketNum originalPacketNum_{0};
  PacketNum clonePacketNum_{0};
};

INSTANTIATE_TEST_SUITE_P(
    SendBufferModes,
    AckEventFirstArrivalTest,
    Values(false, true),
    [](const TestParamInfo<bool>& info) {
      return info.param ? "Unified" : "Legacy";
    });

TEST_P(AckEventFirstArrivalTest, CloneAckedAfterOriginalIsNotFirstArrival) {
  sendOriginalAndClone();

  const auto originalAck =
      deliverAckForAppDataPackets(originalPacketNum_, originalPacketNum_);
  const auto& original = ackedPacket(originalAck, originalPacketNum_);
  EXPECT_TRUE(original.framesProcessed);
  EXPECT_EQ(FirstArrival::Yes, original.firstArrival);
  EXPECT_EQ(frame_->len, creditedBytes(originalAck));

  const auto cloneAck =
      deliverAckForAppDataPackets(clonePacketNum_, clonePacketNum_);
  const auto& clone = ackedPacket(cloneAck, clonePacketNum_);
  EXPECT_FALSE(clone.framesProcessed);
  EXPECT_EQ(FirstArrival::No, clone.firstArrival);
  EXPECT_EQ(0, creditedBytes(cloneAck));
}

TEST_P(AckEventFirstArrivalTest, SameAckWithoutTimestampsHasUnknownOrder) {
  sendOriginalAndClone();

  const auto ack = ackBothCopies(std::nullopt);
  EXPECT_EQ(
      FirstArrival::Unknown, ackedPacket(ack, originalPacketNum_).firstArrival);
  EXPECT_EQ(
      FirstArrival::Unknown, ackedPacket(ack, clonePacketNum_).firstArrival);
  // mvfst processes the frames of one copy, so the bytes are credited once.
  EXPECT_EQ(frame_->len, creditedBytes(ack));
}

TEST_P(AckEventFirstArrivalTest, SameAckTimestampsOrderCopies) {
  sendOriginalAndClone();

  // The original was received 300us before the clone.
  const auto ack = ackBothCopies(std::array<uint64_t, 2>{1000, 300});
  EXPECT_EQ(
      FirstArrival::Yes, ackedPacket(ack, originalPacketNum_).firstArrival);
  EXPECT_EQ(FirstArrival::No, ackedPacket(ack, clonePacketNum_).firstArrival);
  EXPECT_EQ(frame_->len, creditedBytes(ack));
}

TEST_P(AckEventFirstArrivalTest, SameAckEqualTimestampsHaveUnknownOrder) {
  sendOriginalAndClone();

  const auto ack = ackBothCopies(std::array<uint64_t, 2>{1000, 0});
  EXPECT_EQ(
      FirstArrival::Unknown, ackedPacket(ack, originalPacketNum_).firstArrival);
  EXPECT_EQ(
      FirstArrival::Unknown, ackedPacket(ack, clonePacketNum_).firstArrival);
}

class AckReceiveTimestampsStatsTest : public Test {
 protected:
  void SetUp() override {
    conn_.statsCallback = &quicStats_;
    setReceiveTimestampsConfig(conn_, 10);
    emplacePackets(conn_, 10, startTime_, PacketNumberSpace::AppData);
  }

  quic::Expected<AckEvent, QuicError> processAck(const ReadAckFrame& frame) {
    return processAckFrame(
        conn_,
        PacketNumberSpace::AppData,
        frame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        startTime_ + 10ms);
  }

  NiceMock<MockQuicStats> quicStats_;
  QuicServerConnectionState conn_{
      FizzServerQuicHandshakeContext::Builder().build()};
  const TimePoint startTime_{Clock::now()};
};

TEST_F(AckReceiveTimestampsStatsTest, ReportsTimestampsStoredFromAck) {
  auto frame = makeDraft02AckFrame(
      9,
      {{.deltaLargestAcknowledged = 0,
        .timestamp_delta_count = 3,
        .deltas = {500, 10, 5}}});

  EXPECT_CALL(
      quicStats_,
      onAckReceiveTimestampsReceived(
          3, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02));
  ASSERT_FALSE(processAck(frame).hasError());
}

TEST_F(AckReceiveTimestampsStatsTest, DoesNotReportAckWithoutTimestamps) {
  ReadAckFrame frame;
  frame.largestAcked = 9;
  frame.ackBlocks.emplace_back(0, 9);

  EXPECT_CALL(quicStats_, onAckReceiveTimestampsReceived(_, _)).Times(0);
  ASSERT_FALSE(processAck(frame).hasError());
}

} // namespace quic::test
