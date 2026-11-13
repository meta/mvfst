/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <quic/api/test/Mocks.h>
#include <quic/api/test/QuicTypedTransportTestUtil.h>
#include <quic/codec/Types.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/test/AckEventTestUtil.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace testing;

namespace {

using TransportTypes = testing::Types<
    quic::test::QuicClientTransportTestBase,
    quic::test::QuicServerTransportTestBase>;

class TransportTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    // we have to remove "::" from the string that we return here,
    // or gtest will silently refuse to run these tests!
    auto str = folly::demangle(typeid(T)).toStdString();
    if (str.find_last_of("::") != str.npos) {
      return str.substr(str.find_last_of("::") + 1);
    }
    return str;
  }
};

enum class StreamRetransmissionTrigger : std::uint8_t {
  PacketThreshold,
  TimeThreshold,
};

bool hasStreamFrame(const quic::RegularQuicWritePacket::Vec& frames) {
  return std::ranges::any_of(frames, [](const auto& frame) {
    return frame.type() == quic::QuicWriteFrame::Type::WriteStreamFrame;
  });
}

bool hasRstStreamFrame(const quic::RegularQuicWritePacket::Vec& frames) {
  return std::ranges::any_of(frames, [](const auto& frame) {
    return frame.type() == quic::QuicWriteFrame::Type::RstStreamFrame;
  });
}

bool hasDatagramFrame(const quic::RegularQuicWritePacket::Vec& frames) {
  return std::ranges::any_of(frames, [](const auto& frame) {
    return frame.type() == quic::QuicWriteFrame::Type::DatagramFrame;
  });
}

const quic::TimestampFrame* findTimestampFrame(
    const quic::RegularQuicWritePacket::Vec& frames) {
  for (const auto& frame : frames) {
    if (const auto* timestampFrame = frame.asTimestampFrame()) {
      return timestampFrame;
    }
  }
  return nullptr;
}

size_t countTimestampFrames(const quic::RegularQuicWritePacket::Vec& frames) {
  return std::ranges::count_if(frames, [](const auto& frame) {
    return frame.asTimestampFrame() != nullptr;
  });
}

// Config wrapper for datagram tests to parameterize
// scheduleDatagramsWithStreams
template <typename Transport, bool ScheduleWithStreams>
struct DatagramTransportConfig {
  using TransportType = Transport;
  static constexpr bool scheduleDatagramsWithStreams = ScheduleWithStreams;
};

using DatagramTransportTypes = testing::Types<
    DatagramTransportConfig<quic::test::QuicClientTransportTestBase, false>,
    DatagramTransportConfig<quic::test::QuicClientTransportTestBase, true>,
    DatagramTransportConfig<quic::test::QuicServerTransportTestBase, false>,
    DatagramTransportConfig<quic::test::QuicServerTransportTestBase, true>>;

using DatagramWithStreamsTransportTypes = testing::Types<
    DatagramTransportConfig<quic::test::QuicClientTransportTestBase, true>,
    DatagramTransportConfig<quic::test::QuicServerTransportTestBase, true>>;

class DatagramTransportTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    std::string name =
        TransportTypeNames::GetName<typename T::TransportType>(0);
    name += T::scheduleDatagramsWithStreams ? "_WithStreams" : "_NoStreams";
    return name;
  }
};

} // namespace

namespace quic::test {

template <typename T>
class QuicTypedTransportTest : public virtual testing::Test,
                               public QuicTypedTransportTestBase<T> {
 public:
  ~QuicTypedTransportTest() override = default;

  void SetUp() override {
    // trigger setup of the underlying transport
    QuicTypedTransportTestBase<T>::SetUp();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTest,
    ::TransportTypes,
    ::TransportTypeNames);

/**
 * Verify that connection start time is properly stored in TransportInfo.
 */
TYPED_TEST(QuicTypedTransportTest, TransportInfoConnectionTime) {
  TestFixture::startTransport();
  const auto afterStartTs = std::chrono::steady_clock::now();
  EXPECT_LE(
      std::chrono::steady_clock::time_point().time_since_epoch().count(),
      this->getTransport()
          ->getTransportInfo()
          .connectionTime.time_since_epoch()
          .count());
  EXPECT_GE(
      afterStartTs.time_since_epoch().count(),
      this->getTransport()
          ->getTransportInfo()
          .connectionTime.time_since_epoch()
          .count());
  this->destroyTransport();
}

TYPED_TEST(QuicTypedTransportTest, UnifiedSendBufferRetransmitsDeclaredLoss) {
  TestFixture::startTransport();
  auto& conn = this->getNonConstConn();
  conn.outstandings.reset();
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;

  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->usesUnifiedSendBuffer());

  constexpr std::string_view kData = "unified retransmission";
  ASSERT_FALSE(this->getTransport()
                   ->writeChain(streamId, IOBuf::copyBuffer(kData), false)
                   .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());

  auto originalPacketIt =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData);
  ASSERT_NE(originalPacketIt, conn.outstandings.packets.rend());
  ASSERT_TRUE(hasStreamFrame(originalPacketIt->packet.frames));
  const auto originalPacketNum =
      originalPacketIt->packet.header.getPacketSequenceNum();
  const auto originalPathId = originalPacketIt->metadata.pathId;
  const auto retransmittedBefore = conn.lossState.totalBytesRetransmitted;

  EXPECT_CALL(*this->quicStats_, onPacketRetransmission()).Times(1);
  auto lossResult =
      markPacketLoss(conn, originalPathId, originalPacketIt->packet, false);
  ASSERT_FALSE(lossResult.hasError());
  ASSERT_TRUE(stream->streamSendBuffer->hasPendingLoss());

  this->getTestTransport()->writeLooper()->run(true);
  ASSERT_TRUE(this->loopForWrites().has_value());

  const auto* retransmission = this->getNewestAppDataOutstandingPacket();
  ASSERT_NE(retransmission, nullptr);
  EXPECT_NE(
      retransmission->packet.header.getPacketSequenceNum(), originalPacketNum);
  EXPECT_TRUE(hasStreamFrame(retransmission->packet.frames));
  EXPECT_FALSE(retransmission->maybeClonedPacketIdentifier.has_value());
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(
      conn.lossState.totalBytesRetransmitted - retransmittedBefore,
      kData.size());

  this->destroyTransport();
}

enum class AppStreamSendBufferMode : std::uint8_t {
  Legacy,
  Unified,
};

template <typename T>
class QuicTypedTransportLargestDeliverableOffsetTest
    : public QuicTypedTransportTest<T> {
 protected:
  // Drives real ACKs through the transport and checks the contiguous ACK
  // frontier reported by getStreamTransportInfo. Both send-buffer modes must
  // report identical values.
  void verifyLargestDeliverableOffsetTracksContiguousAcks(
      const AppStreamSendBufferMode mode) {
    constexpr auto kAckRtt = 27ms;
    constexpr uint64_t kChunkLen = 10;

    this->startTransport();
    this->ackAllOutstandingPackets();
    auto& conn = this->getNonConstConn();
    conn.transportSettings.useUnifiedAppStreamSendBuffer =
        mode == AppStreamSendBufferMode::Unified;
    // Packet number skipping would make write intervals non-contiguous.
    conn.transportSettings.skipOneInNPacketSequenceNumber = 0;
    // Disable packet- and time-threshold loss detection so that ACKing a
    // later packet never declares the unACKed hole lost.
    conn.lossState.reorderingThreshold = 100;
    conn.transportSettings.timeReorderingThreshDividend = 1000000;
    conn.transportSettings.timeReorderingThreshDivisor = 1;

    auto transport = this->getTransport();
    const auto streamId = transport->createBidirectionalStream().value();
    auto* stream = conn.streamManager->findStream(streamId);
    ASSERT_NE(stream, nullptr);
    ASSERT_EQ(
        mode == AppStreamSendBufferMode::Unified,
        stream->usesUnifiedSendBuffer());

    const auto writeOnePacket = [&](BufPtr data, const bool eof) {
      CHECK(!transport->writeChain(streamId, std::move(data), eof).hasError());
      const auto packets = this->loopForWrites();
      CHECK(packets.has_value());
      CHECK_EQ(packets->start, packets->end);
      return *packets;
    };
    const auto ackPacket = [&](const auto& packets) {
      this->deliverPacketNoWrites(
          this->buildAckPacketForSentAppDataPackets(packets),
          packets.sentTime + kAckRtt);
    };
    const auto largestDeliverableOffset = [&]() {
      const auto streamInfo = transport->getStreamTransportInfo(streamId);
      CHECK(!streamInfo.hasError());
      return streamInfo->maybeLargestDeliverableOffset;
    };

    // Stream bytes [0, 30) in three packets, then a FIN-only packet.
    const auto first =
        writeOnePacket(IOBuf::copyBuffer(std::string(kChunkLen, 'a')), false);
    const auto second =
        writeOnePacket(IOBuf::copyBuffer(std::string(kChunkLen, 'b')), false);
    const auto third =
        writeOnePacket(IOBuf::copyBuffer(std::string(kChunkLen, 'c')), false);
    const auto fin = writeOnePacket(nullptr, true);

    EXPECT_FALSE(largestDeliverableOffset().has_value());

    ackPacket(first);
    EXPECT_EQ(Optional<uint64_t>(kChunkLen - 1), largestDeliverableOffset());

    // The frontier does not jump the hole left by the second packet.
    ackPacket(third);
    EXPECT_EQ(Optional<uint64_t>(kChunkLen - 1), largestDeliverableOffset());

    ackPacket(second);
    EXPECT_EQ(
        Optional<uint64_t>(3 * kChunkLen - 1), largestDeliverableOffset());

    // Once the FIN is ACKed, the frontier is the final offset, one past the
    // last stream byte.
    ackPacket(fin);
    EXPECT_EQ(Optional<uint64_t>(3 * kChunkLen), largestDeliverableOffset());

    this->destroyTransport();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportLargestDeliverableOffsetTest,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportLargestDeliverableOffsetTest, LegacySendBuffer) {
  this->verifyLargestDeliverableOffsetTracksContiguousAcks(
      AppStreamSendBufferMode::Legacy);
}

TYPED_TEST(QuicTypedTransportLargestDeliverableOffsetTest, UnifiedSendBuffer) {
  this->verifyLargestDeliverableOffsetTracksContiguousAcks(
      AppStreamSendBufferMode::Unified);
}

template <typename T>
class QuicTypedTransportAfterStartTest : public QuicTypedTransportTest<T> {
 public:
  ~QuicTypedTransportAfterStartTest() override = default;

  void SetUp() override {
    QuicTypedTransportTest<T>::SetUp();
    QuicTypedTransportTestBase<T>::startTransport();
  }
};

struct TimestampRetransmissionPolicy {
  TimestampFrameWriteMode mode;
  TimestampFramePacketSelection packetSelection;
  bool peerCanReceive;
  bool ackReceiveTimestamps;
  bool suppressForAckReceiveTimestamps;
  bool expectTimestamp;
};

struct TimestampRetransmissionCase {
  const char* name;
  bool clonePacket;
  bool writeStreamData;
  TimestampRetransmissionPolicy original;
  TimestampRetransmissionPolicy retry;
};

constexpr auto kAllEligible = TimestampFramePacketSelection::AllEligiblePackets;
constexpr auto kAckEliciting =
    TimestampFramePacketSelection::AckElicitingPackets;
constexpr auto kStream = TimestampFramePacketSelection::StreamPackets;
constexpr auto kEnabled = TimestampFrameWriteMode::Prioritized;
constexpr auto kDisabled = TimestampFrameWriteMode::Disabled;

constexpr TimestampRetransmissionPolicy kAllEligibleEnabled{
    .mode = kEnabled,
    .packetSelection = kAllEligible,
    .peerCanReceive = true,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = true};
constexpr TimestampRetransmissionPolicy kAllEligibleDisabled{
    .mode = kDisabled,
    .packetSelection = kAllEligible,
    .peerCanReceive = true,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = false};
constexpr TimestampRetransmissionPolicy kAllEligiblePeerUnsupported{
    .mode = kEnabled,
    .packetSelection = kAllEligible,
    .peerCanReceive = false,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = false};
constexpr TimestampRetransmissionPolicy kAllEligibleAckAllowed{
    .mode = kEnabled,
    .packetSelection = kAllEligible,
    .peerCanReceive = true,
    .ackReceiveTimestamps = true,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = true};
constexpr TimestampRetransmissionPolicy kAllEligibleAckSuppressed{
    .mode = kEnabled,
    .packetSelection = kAllEligible,
    .peerCanReceive = true,
    .ackReceiveTimestamps = true,
    .suppressForAckReceiveTimestamps = true,
    .expectTimestamp = false};
constexpr TimestampRetransmissionPolicy kStreamIncluded{
    .mode = kEnabled,
    .packetSelection = kStream,
    .peerCanReceive = true,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = true};
constexpr TimestampRetransmissionPolicy kStreamExcluded{
    .mode = kEnabled,
    .packetSelection = kStream,
    .peerCanReceive = true,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = false};
constexpr TimestampRetransmissionPolicy kAckElicitingIncluded{
    .mode = kEnabled,
    .packetSelection = kAckEliciting,
    .peerCanReceive = true,
    .ackReceiveTimestamps = false,
    .suppressForAckReceiveTimestamps = false,
    .expectTimestamp = true};

constexpr std::array kTimestampRetransmissionCases{
    TimestampRetransmissionCase{
        .name = "CloneEnabledToEnabled",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligibleEnabled},
    TimestampRetransmissionCase{
        .name = "LossEnabledToEnabled",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligibleEnabled},
    TimestampRetransmissionCase{
        .name = "CloneEnabledToDisabled",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligibleDisabled},
    TimestampRetransmissionCase{
        .name = "LossEnabledToDisabled",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligibleDisabled},
    TimestampRetransmissionCase{
        .name = "CloneEnabledToPeerUnsupported",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligiblePeerUnsupported},
    TimestampRetransmissionCase{
        .name = "LossEnabledToPeerUnsupported",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleEnabled,
        .retry = kAllEligiblePeerUnsupported},
    TimestampRetransmissionCase{
        .name = "CloneDisabledToEnabled",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleDisabled,
        .retry = kAllEligibleEnabled},
    TimestampRetransmissionCase{
        .name = "LossDisabledToEnabled",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleDisabled,
        .retry = kAllEligibleEnabled},
    TimestampRetransmissionCase{
        .name = "CloneAckAllowedToSuppressed",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleAckAllowed,
        .retry = kAllEligibleAckSuppressed},
    TimestampRetransmissionCase{
        .name = "LossAckAllowedToSuppressed",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleAckAllowed,
        .retry = kAllEligibleAckSuppressed},
    TimestampRetransmissionCase{
        .name = "CloneAckSuppressedToAllowed",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kAllEligibleAckSuppressed,
        .retry = kAllEligibleAckAllowed},
    TimestampRetransmissionCase{
        .name = "LossAckSuppressedToAllowed",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kAllEligibleAckSuppressed,
        .retry = kAllEligibleAckAllowed},
    TimestampRetransmissionCase{
        .name = "CloneStreamSelectionIncludesStream",
        .clonePacket = true,
        .writeStreamData = true,
        .original = kStreamIncluded,
        .retry = kStreamIncluded},
    TimestampRetransmissionCase{
        .name = "LossStreamSelectionIncludesStream",
        .clonePacket = false,
        .writeStreamData = true,
        .original = kStreamIncluded,
        .retry = kStreamIncluded},
    TimestampRetransmissionCase{
        .name = "CloneStreamSelectionExcludesReset",
        .clonePacket = true,
        .writeStreamData = false,
        .original = kAllEligibleEnabled,
        .retry = kStreamExcluded},
    TimestampRetransmissionCase{
        .name = "LossAckElicitingSelectionIncludesReset",
        .clonePacket = false,
        .writeStreamData = false,
        .original = kStreamExcluded,
        .retry = kAckElicitingIncluded},
};

template <typename Transport, size_t CaseIndex>
struct TimestampRetransmissionConfig {
  using TransportType = Transport;
  static constexpr size_t caseIndex = CaseIndex;
};

template <typename T>
class TimestampRetransmissionTypedTest
    : public QuicTypedTransportTest<typename T::TransportType> {
 public:
  using TransportType = typename T::TransportType;

  void SetUp() override {
    QuicTypedTransportTest<TransportType>::SetUp();
    QuicTypedTransportTestBase<TransportType>::startTransport();
  }

  void runCase(const TimestampRetransmissionCase& testCase) {
    auto& conn = this->getNonConstConn();
    conn.outstandings.reset();
    conn.transportSettings.timestampFrameTimestampExponent = 3;
    conn.connectionTime = Clock::now() - 1s;

    auto applyPolicy = [&](const TimestampRetransmissionPolicy& policy) {
      conn.transportSettings.oneRttTimestampFrameWriteMode = policy.mode;
      conn.transportSettings.oneRttTimestampFramePacketSelection =
          policy.packetSelection;
      conn.transportSettings
          .suppressOneRttTimestampFrameWhenAckReceiveTimestampsWritten =
          policy.suppressForAckReceiveTimestamps;
      conn.peerTimestampFrameState.canReceive = policy.peerCanReceive;
    };
    auto scheduleTimestampedAck = [&] {
      auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
      ackState.acks.insert(10);
      WriteAckFrameState::ReceivedPacket receivedPacket;
      receivedPacket.pktNum = 10;
      receivedPacket.timings.receiveTimePoint = Clock::now();
      const auto receiveTime = receivedPacket.timings.receiveTimePoint;
      ackState.recvdPacketInfos.emplace_back(std::move(receivedPacket));
      ackState.largestRecvdPacketNum = 10;
      ackState.largestRecvdPacketTime = receiveTime;
      ackState.needsToSendAckImmediately = true;
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
          AckReceiveTimestampsConfig();
      conn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
          .version = AckReceiveTimestampsVersion::LegacyMvfst,
          .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
          .exponent = 0};
      conn.negotiatedAckReceiveTimestampSupport = true;
    };

    applyPolicy(testCase.original);
    if (testCase.original.ackReceiveTimestamps) {
      scheduleTimestampedAck();
    }

    const auto streamId =
        this->getTransport()->createBidirectionalStream().value();
    if (testCase.writeStreamData) {
      ASSERT_FALSE(
          this->getTransport()
              ->writeChain(streamId, IOBuf::copyBuffer("timestamp"), false)
              .hasError());
    } else {
      ASSERT_FALSE(
          this->getTransport()
              ->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
              .hasError());
    }
    ASSERT_TRUE(this->loopForWrites().has_value());

    const auto* originalPacket = this->getNewestAppDataOutstandingPacket();
    ASSERT_NE(originalPacket, nullptr);
    if (originalPacket == nullptr) {
      return;
    }
    EXPECT_EQ(
        hasStreamFrame(originalPacket->packet.frames),
        testCase.writeStreamData);
    EXPECT_EQ(
        hasRstStreamFrame(originalPacket->packet.frames),
        !testCase.writeStreamData);
    const auto originalPacketNum =
        originalPacket->packet.header.getPacketSequenceNum();
    const auto originalPathId = originalPacket->metadata.pathId;
    const auto* originalTimestampFrame =
        findTimestampFrame(originalPacket->packet.frames);
    EXPECT_EQ(
        originalTimestampFrame != nullptr, testCase.original.expectTimestamp);
    const auto originalTimestamp = originalTimestampFrame
        ? Optional<uint64_t>(originalTimestampFrame->timestamp)
        : std::nullopt;

    conn.connectionTime -= std::chrono::microseconds(uint64_t{2} << 3);
    applyPolicy(testCase.retry);
    if (testCase.retry.ackReceiveTimestamps) {
      auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
      ackState.largestAckScheduled = std::nullopt;
      ackState.needsToSendAckImmediately = true;
      if (!testCase.original.ackReceiveTimestamps) {
        scheduleTimestampedAck();
      }
    }
    const auto minFreshTimestamp =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - conn.connectionTime)
                .count()) >>
        3;

    if (testCase.clonePacket) {
      conn.pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
    } else {
      auto originalPacketIt =
          getLastOutstandingPacket(conn, PacketNumberSpace::AppData);
      ASSERT_NE(originalPacketIt, conn.outstandings.packets.rend());
      auto lossResult =
          markPacketLoss(conn, originalPathId, originalPacketIt->packet, false);
      ASSERT_FALSE(lossResult.hasError());
    }
    this->getTestTransport()->writeLooper()->run(true);
    ASSERT_TRUE(this->loopForWrites().has_value());

    const auto* retransmission = this->getNewestAppDataOutstandingPacket();
    ASSERT_NE(retransmission, nullptr);
    if (retransmission == nullptr) {
      return;
    }
    const auto maxFreshTimestamp =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - conn.connectionTime)
                .count()) >>
        3;
    EXPECT_NE(
        retransmission->packet.header.getPacketSequenceNum(),
        originalPacketNum);
    EXPECT_EQ(
        hasStreamFrame(retransmission->packet.frames),
        testCase.writeStreamData);
    EXPECT_EQ(
        hasRstStreamFrame(retransmission->packet.frames),
        !testCase.writeStreamData);
    if (testCase.clonePacket) {
      ASSERT_TRUE(retransmission->maybeClonedPacketIdentifier.has_value());
      EXPECT_EQ(
          *retransmission->maybeClonedPacketIdentifier,
          ClonedPacketIdentifier(
              PacketNumberSpace::AppData, originalPacketNum));
    } else {
      EXPECT_FALSE(retransmission->maybeClonedPacketIdentifier.has_value());
    }

    EXPECT_EQ(
        countTimestampFrames(retransmission->packet.frames),
        testCase.retry.expectTimestamp ? 1 : 0);
    if (testCase.retry.expectTimestamp) {
      const auto* timestampFrame =
          findTimestampFrame(retransmission->packet.frames);
      ASSERT_NE(timestampFrame, nullptr);
      if (timestampFrame == nullptr) {
        return;
      }
      EXPECT_GE(timestampFrame->timestamp, minFreshTimestamp);
      EXPECT_LE(timestampFrame->timestamp, maxFreshTimestamp);
      if (originalTimestamp) {
        EXPECT_NE(timestampFrame->timestamp, *originalTimestamp);
      }
    }
  }
};

template <typename T>
class QuicTypedTransportSconeTest : public QuicTypedTransportAfterStartTest<T> {
 public:
  ~QuicTypedTransportSconeTest() override = default;

  void SetUp() override {
    QuicTypedTransportAfterStartTest<T>::SetUp();
    this->getNonConstConn().transportSettings.advertiseSconeSupport = true;
    this->getNonConstConn().transportSettings.enableSconeSend = true;
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTest,
    ::TransportTypes,
    ::TransportTypeNames);

template <typename IndexSequence>
struct TimestampRetransmissionConfigs;

template <size_t... CaseIndexes>
struct TimestampRetransmissionConfigs<std::index_sequence<CaseIndexes...>> {
  using type = Types<
      TimestampRetransmissionConfig<
          QuicClientTransportTestBase,
          CaseIndexes>...,
      TimestampRetransmissionConfig<
          QuicServerTransportTestBase,
          CaseIndexes>...>;
};

using TimestampRetransmissionTypes = typename TimestampRetransmissionConfigs<
    std::make_index_sequence<kTimestampRetransmissionCases.size()>>::type;

class TimestampRetransmissionTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    return ::TransportTypeNames::GetName<typename T::TransportType>(0) + "_" +
        kTimestampRetransmissionCases[T::caseIndex].name;
  }
};

TYPED_TEST_SUITE(
    TimestampRetransmissionTypedTest,
    TimestampRetransmissionTypes,
    TimestampRetransmissionTypeNames);

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    TimestampFrameAcceptedWithoutLocalAdvertisement) {
  auto& ackState = this->getNonConstConn().ackStates.appDataAckState;
  ackState.numRxPacketsRecvd = 0;
  ackState.numNonRxPacketsRecvd = 0;
  ackState.needsToSendAckImmediately = false;
  this->getNonConstConn().pendingEvents.scheduleAckTimeout = false;

  this->deliverPacket(
      this->buildPeerPacketWithTimestampFrame(1234), Clock::now(), 0, false);

  EXPECT_FALSE(this->getConn().localConnectionError.has_value());
  EXPECT_EQ(ackState.numRxPacketsRecvd, 0);
  EXPECT_EQ(ackState.numNonRxPacketsRecvd, 1);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_FALSE(this->getConn().pendingEvents.scheduleAckTimeout);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    NoTimestampFrameAfterTimestampFrameWritingDisabled) {
  this->getNonConstConn().outstandings.reset();
  this->getNonConstConn().transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Opportunistic;
  this->getNonConstConn().peerTimestampFrameState.canReceive = true;

  this->getTransport()->disableTimestampFrameWriting();

  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();
  ASSERT_FALSE(this->getTransport()
                   ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                   .hasError());
  const auto maybeWrittenPackets = this->loopForWrites();
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));

  const auto* packet = this->getNewestAppDataOutstandingPacket();
  ASSERT_NE(packet, nullptr);
  if (packet == nullptr) {
    return;
  }
  EXPECT_EQ(findTimestampFrame(packet->packet.frames), nullptr);

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    TimestampFrameWrittenWithStreamDataUsesConnectionClock) {
  this->getNonConstConn().outstandings.reset();
  this->getNonConstConn().transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Opportunistic;
  this->getNonConstConn().peerTimestampFrameState.canReceive = true;
  this->getNonConstConn().connectionTime = Clock::now() - 5ms;
  const auto minTimestamp = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          Clock::now() - this->getConn().connectionTime)
          .count());

  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();
  ASSERT_FALSE(this->getTransport()
                   ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                   .hasError());

  const auto maybeWrittenPackets = this->loopForWrites();
  const auto maxTimestamp = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          Clock::now() - this->getConn().connectionTime)
          .count());
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));

  const auto* packet = this->getNewestAppDataOutstandingPacket();
  ASSERT_NE(packet, nullptr);
  if (packet == nullptr) {
    return;
  }
  const auto* timestampFrame = findTimestampFrame(packet->packet.frames);
  ASSERT_NE(timestampFrame, nullptr);
  if (timestampFrame == nullptr) {
    return;
  }
  EXPECT_GE(timestampFrame->timestamp, minTimestamp);
  EXPECT_LE(timestampFrame->timestamp, maxTimestamp);

  this->destroyTransport();
}

TYPED_TEST(
    TimestampRetransmissionTypedTest,
    ReappliesCurrentPolicyForCloneAndLoss) {
  const auto& testCase = kTimestampRetransmissionCases[TypeParam::caseIndex];
  SCOPED_TRACE(testCase.name);
  this->runCase(testCase);
  this->destroyTransport();
}

/**
 * Verify that RTT signals are properly passed through to TransportInfo.
 *
 * Currently tests mrtt, mrttNoAckDelay, lrttRaw, lrttRawAckDelay
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, TransportInfoRttSignals) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 31ms (5 ms) |     26ms      ||   31   |       26       | (both)
  //    2  | 30ms (3 ms) |     27ms      ||   30   |       26       | (1)
  //    3  | 30ms (8 ms) |     22ms      ||   30   |       22       | (2)
  //    4  | 37ms (8 ms) |     29ms      ||   30   |       22       | (none)
  //    5  | 25ms (0 ms) |     29ms      ||   25   |       22       | (1)
  //    6  | 25ms (4 ms) |     29ms      ||   25   |       21       | (2)
  //    7  | 20ms (0 ms) |     29ms      ||   20   |       20       | (both)

  // case 1 [31ms (5 ms)]
  {
    const auto rtt = 31ms;
    const auto ackDelay = 5ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 31ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 2 [30ms (3 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 3ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 3 [30ms (8 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 4 [37ms (8 ms)]
  {
    const auto rtt = 37ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 5 [25ms (0 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 6 [25ms (4 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 4ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 21ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 7 [20ms (0 ms)]
  {
    const auto rtt = 20ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 20ms;
    const auto expectedMinRttNoAckDelay = 20ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is equal to the RTT sample.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleAckDelayEqual) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (25 ms)|     25ms      ||   25   |       0        | (both)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 25ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 0ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is greater than the RTT sample.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleAckDelayGreater) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (26 ms)|     25ms      ||   25   |  std::nullopt   | (1)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 26ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(std::nullopt, tInfo.maybeMinRttNoAckDelay); // unavailable
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the RTT sample has zero time based on socket RX timestamp.
 *
 * In this case, we should fallback to using system clock timestamp, and thus
 * should end up with a non-zero RTT.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleZeroTime) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    auto typedTestWriteChain4 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 0ms (0 ms)  |     0ms       ||   >0   |      >0        | (both)
  {
    const auto rtt = 0ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_LE(0ms, tInfo.maybeLrtt.value());
      EXPECT_GE(500ms, tInfo.maybeLrtt.value());
      EXPECT_EQ(0ms, tInfo.maybeLrttAckDelay.value());
      EXPECT_EQ(tInfo.maybeLrtt, tInfo.maybeMinRtt);
      EXPECT_EQ(tInfo.maybeMinRtt, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstanding) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain5 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlight) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain6 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // write some more bytes into the same stream
  auto typedTestWriteChain7 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets ACKed in reverse to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlightReverse) {
  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain8 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // write some more bytes into the same stream
  auto typedTestWriteChain9 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify PacketProcessor callbacks when sending a packet and its ack
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorSendSingleDataPacketWithAck) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
      .Times(1)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
      }));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain10 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent) {
        ASSERT_THAT(ackEvent, Not(IsNull()));
        if (ackEvent) {
          EXPECT_EQ(1, ackEvent->ackedPackets.size());
          EXPECT_EQ(44, ackEvent->ackedBytes);
          EXPECT_EQ(44, ackEvent->totalBytesAcked);
          EXPECT_EQ(
              this->getNonConstConn().lossState.totalBytesAcked,
              ackEvent->totalBytesAcked);
          EXPECT_EQ(lastPacketNum, ackEvent->largestAckedPacket);
          EXPECT_EQ(lastPacketNum, ackEvent->largestNewlyAckedPacket);
        }
      }));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());
  this->destroyTransport();
}

/**
 * Verify PacketProcessor send and ACK callbacks.
 *
 * Send two packets and receive one ACK.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorSendTwoDataPacketsWithAck) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();
  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
      .Times(2)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
      }))
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(4, outstandingPacket.metadata.writeCount);
      }));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain11 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain12 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent two packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
  EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent) {
        ASSERT_THAT(ackEvent, Not(IsNull()));
        if (ackEvent) {
          EXPECT_EQ(2, ackEvent->ackedPackets.size());
          EXPECT_EQ(2 * 44, ackEvent->ackedBytes);
          EXPECT_EQ(2 * 44, ackEvent->totalBytesAcked);
          EXPECT_EQ(
              this->getNonConstConn().lossState.totalBytesAcked,
              ackEvent->totalBytesAcked);
          EXPECT_EQ(lastPacketNum, ackEvent->largestAckedPacket);
          EXPECT_EQ(lastPacketNum, ackEvent->largestNewlyAckedPacket);
        }
      }));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(
      std::vector<Optional<typename TestFixture::NewOutstandingPacketInterval>>{
          maybeWrittenPackets1, maybeWrittenPackets2}));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorAckOrLossCarriesLostPacketDetails) {
  this->getNonConstConn().outstandings.reset();
  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;
  this->getNonConstConn().lossState.reorderingThreshold = 1;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      100000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain1 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  auto typedTestWriteChain2 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  auto typedTestWriteChain3 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("again"), false);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  const auto firstPacketNum = maybeWrittenPackets1->start;
  const auto thirdPacketNum = maybeWrittenPackets3->start;

  EXPECT_CALL(*rawPacketProcessor, onPacketAckOrLoss(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto* ackEvent, const auto* lossEvent) {
        ASSERT_THAT(ackEvent, Not(IsNull()));
        EXPECT_EQ(thirdPacketNum, ackEvent->largestAckedPacket);
        ASSERT_THAT(lossEvent, Not(IsNull()));
        EXPECT_EQ(1, lossEvent->lostPackets);
        EXPECT_EQ(1, lossEvent->lostPacketDetails.size());
        EXPECT_THAT(
            lossEvent->lostPacketDetails,
            ElementsAre(AllOf(
                Field(&LossEvent::LostPacket::packetNum, firstPacketNum),
                Field(&LossEvent::LostPacket::encodedSize, 44))));
      }));

  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(thirdPacketNum),
      std::chrono::steady_clock::time_point());
  this->destroyTransport();
}

/**
 * Verify app limited time tracking and annotation.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, TotalAppLimitedTime) {
  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // prevent packets from being marked as lost for at least 100ms, regardless
  // of the RTT measured by the test
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      100000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 7000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  // install PacketProcessor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  // write 1700 bytes to stream to generate two packets back to back
  // both packets should have the same app limited time
  auto firstPacketTotalAppLimitedTimeUsecs = 0us;
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(2)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
          EXPECT_NE(0us, outstandingPacket.metadata.totalAppLimitedTimeUsecs);
          firstPacketTotalAppLimitedTimeUsecs =
              outstandingPacket.metadata.totalAppLimitedTimeUsecs;
        }))
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
          EXPECT_EQ(
              firstPacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto bufLength = 1700;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain13 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets1 = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);
  }

  // next, we wait for 10ms to get 10ms (or more) of app limited time.
  //
  // TODO(bschlinker): We should accomplish this by advancing a mock clock, but
  // this will also require being able to mock the timers set up on the
  // EventBase so that they are aligned with the mock clock.
  //
  // A loss detection alarm was scheduled for the previous write but even if
  // the machine running this test is slow, the following operation should be
  // executed before the loss alarm given that we've inflated the loss timeout
  // so that the alarm timeout is >= 100ms
  std::this_thread::sleep_for(10ms);

  // write 10000 bytes to stream to generate multiple packets back to back
  // not all will be sent at once because our CWND is only 7000 bytes, and
  // we already used 1700 bytes+ in previous send
  //
  // when (eventually) sent, all packets should have
  //   - the same app limited time
  //   - app limited time >= 10ms + firstPacketTotalAppLimitedTimeUsecs
  auto thirdPacketTotalAppLimitedTimeUsecs = 0us;
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(4)
        .WillOnce(Invoke(
            [&firstPacketTotalAppLimitedTimeUsecs,
             &thirdPacketTotalAppLimitedTimeUsecs](auto& outstandingPacket) {
              EXPECT_EQ(4, outstandingPacket.metadata.writeCount);
              EXPECT_LE(
                  firstPacketTotalAppLimitedTimeUsecs + 10ms,
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs);
              thirdPacketTotalAppLimitedTimeUsecs =
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs;
            }))
        .WillRepeatedly(Invoke(
            [&thirdPacketTotalAppLimitedTimeUsecs](auto& outstandingPacket) {
              EXPECT_EQ(
                  thirdPacketTotalAppLimitedTimeUsecs,
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs);
            }));

    const auto bufLength = 10000;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain14 = this->getTransport()->writeChain(
        streamId, std::move(buf), false /* eof */);

    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent four or five packets
    //
    // we allow five packets in the case where a loss detection alarm fires and
    // probe packets are sent (would only happen if test execution is slow)
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    const auto packetsSent = lastPacketNum - firstPacketNum + 1;

    EXPECT_THAT(packetsSent, AnyOf(Eq(4), Eq(5)));
  }

  // deliver an ACK for all of the outstanding packets
  this->ackAllOutstandingPackets();

  // after the ACK, we'll be able to send the rest of the data
  // all sent packets should have the same app limited time as packet #3
  //
  // regardless of whether we sent four or five packets above, we will end up
  // sending three packets here, as the amount of outstanding data remains the
  // same (when we send probe packets, two packets contain same new data)
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(3)
        .WillRepeatedly(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(
              thirdPacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);
  }

  // deliver an ACK for all of the outstanding packets
  this->ackAllOutstandingPackets();

  // now we're going to be application limited again for 10ms (or more)
  // there's no packets in flight, so no need to worry about loss detection
  std::this_thread::sleep_for(10ms);

  // finally, write 1700 bytes again, and verify we see a new app limited time
  {
    auto penultimatePacketTotalAppLimitedTimeUsecs = 0us;
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(2)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_LE(
              thirdPacketTotalAppLimitedTimeUsecs + 10ms,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
          penultimatePacketTotalAppLimitedTimeUsecs =
              outstandingPacket.metadata.totalAppLimitedTimeUsecs;
        }))
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(
              penultimatePacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto bufLength = 1700;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain15 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets1 = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

/**
 * Verify PacketProcessor prewrite requests are collected
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPrewriteRequestQueried) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // First packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));
  EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{.level = IPPROTO_IPV6, .optname = IPV6_HOPLIMIT}, 255}};
    return req;
  });

  // Second packet processor
  auto mockPacketProcessor2 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor2 = mockPacketProcessor2.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor2));

  EXPECT_CALL(*rawPacketProcessor2, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{.level = IPPROTO_IPV6, .optname = IPV6_DONTFRAG}, 1}};
    return req;
  });

  // Third packet processor whose cmsgs will not be applied because priority is
  // given to the cmsg value from the second one.
  auto mockPacketProcessor3 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor3 = mockPacketProcessor3.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor3));

  EXPECT_CALL(*rawPacketProcessor3, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{.level = IPPROTO_IPV6, .optname = IPV6_DONTFRAG}, 0}};
    return req;
  });

  auto streamId = this->getTransport()->createBidirectionalStream().value();
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  auto typedTestWriteChain16 =
      this->getTransport()->writeChain(streamId, std::move(buf), false);
  this->loopForWrites();
  ASSERT_FALSE(this->getConn().outstandings.packets.empty());

  auto pkt = this->getConn().outstandings.packets.rbegin();
  EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor prewrite requests apply to each write
 * and are honored for each packet
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPrewriteRequestMultiple) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // Packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  auto packetsSent = 0;
  {
    // Send two packets with the same marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      PacketProcessor::PrewriteRequest req;
      req.cmsgs = {{{.level = IPPROTO_IPV6, .optname = IPV6_HOPLIMIT}, 255}};
      return req;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain17 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify both packets are marked
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  }

  {
    // Send two packets with no marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      return std::nullopt;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain18 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify the last two packets have no marks
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::NONE);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::NONE);
  }

  {
    // Send two packets with the same marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      PacketProcessor::PrewriteRequest req;
      req.cmsgs = {{{.level = IPPROTO_IPV6, .optname = IPV6_HOPLIMIT}, 255}};
      return req;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain19 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify the last two packets are marked
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  }

  this->destroyTransport();
}

/**
 * Verify PacketProcessor postwrite methods are invoked on all
 * attached processors.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, PacketProcessorPostwriteInvoked) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // First packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));
  bool postWriteFlagOne = false;
  EXPECT_CALL(*rawPacketProcessor, postwrite())
      .Times(1)
      .WillOnce([&postWriteFlagOne]() { postWriteFlagOne = true; });

  // Second packet processor
  auto mockPacketProcessor2 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor2 = mockPacketProcessor2.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor2));

  bool postWriteFlagTwo = false;
  EXPECT_CALL(*rawPacketProcessor2, postwrite())
      .Times(1)
      .WillOnce([&postWriteFlagTwo]() { postWriteFlagTwo = true; });

  auto streamId = this->getTransport()->createBidirectionalStream().value();
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  auto typedTestWriteChain16 =
      this->getTransport()->writeChain(streamId, std::move(buf), false);
  this->loopForWrites();
  ASSERT_FALSE(this->getConn().outstandings.packets.empty());
  EXPECT_TRUE(postWriteFlagOne);
  EXPECT_TRUE(postWriteFlagTwo);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor postwrite methods are invoked even
 * on error cases resuling in early exits.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPostwriteInvokedOnError) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // First packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));
  bool postWriteFlag = false;
  EXPECT_CALL(*rawPacketProcessor, postwrite())
      .Times(1)
      .WillOnce([&postWriteFlag]() { postWriteFlag = true; });

  EXPECT_CALL(*rawPacketProcessor, onPacketSent(_)).WillRepeatedly([]() {
    throw std::runtime_error("Intentionally fail");
  });

  auto streamId = this->getTransport()->createBidirectionalStream().value();
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  auto typedTestWriteChain16 =
      this->getTransport()->writeChain(streamId, std::move(buf), false);
  // The write-loop itself will not throw, but as a result of immediately
  // throwing, it will not produce any outstanding packets.
  this->loopForWrites();
  ASSERT_TRUE(this->getConn().outstandings.packets.empty());
  // Now, ensure it also still executed the postwrite even though it threw
  // an exception.
  EXPECT_TRUE(postWriteFlag);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor preread and postread methods are invoked on all
 * attached processors when a packet is received.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPrereadPostreadInvoked) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // First packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  bool prereadFlagOne = false;
  bool postreadFlagOne = false;
  EXPECT_CALL(*rawPacketProcessor, preread())
      .Times(1)
      .WillOnce([&prereadFlagOne]() { prereadFlagOne = true; });
  EXPECT_CALL(*rawPacketProcessor, postread())
      .Times(1)
      .WillOnce([&postreadFlagOne]() { postreadFlagOne = true; });

  // Second packet processor
  auto mockPacketProcessor2 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor2 = mockPacketProcessor2.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor2));

  bool prereadFlagTwo = false;
  bool postreadFlagTwo = false;
  EXPECT_CALL(*rawPacketProcessor2, preread())
      .Times(1)
      .WillOnce([&prereadFlagTwo]() { prereadFlagTwo = true; });
  EXPECT_CALL(*rawPacketProcessor2, postread())
      .Times(1)
      .WillOnce([&postreadFlagTwo]() { postreadFlagTwo = true; });

  // Send a packet so we can deliver an ACK
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto buf = buildRandomInputData(1000);
  this->getTransport()->writeChain(streamId, std::move(buf), false);
  const auto maybeWrittenPackets = this->loopForWrites();
  ASSERT_TRUE(maybeWrittenPackets.has_value());

  // Deliver an ACK packet — this triggers onNetworkData and the read path
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());

  EXPECT_TRUE(prereadFlagOne);
  EXPECT_TRUE(postreadFlagOne);
  EXPECT_TRUE(prereadFlagTwo);
  EXPECT_TRUE(postreadFlagTwo);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor postread is still invoked even if onReadData
 * encounters an error (guaranteed by SCOPE_EXIT).
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPostreadInvokedOnError) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  bool postreadFlag = false;
  EXPECT_CALL(*rawPacketProcessor, postread())
      .Times(1)
      .WillOnce([&postreadFlag]() { postreadFlag = true; });

  // Deliver a garbage packet — it will fail to parse but postread should
  // still be called via SCOPE_EXIT
  this->deliverPacket(
      IOBuf::copyBuffer("garbage"), std::chrono::steady_clock::time_point());

  EXPECT_TRUE(postreadFlag);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor onPacketRead is called for each received UDP packet.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorOnPacketReadInvoked) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  EXPECT_CALL(*rawPacketProcessor, onPacketRead(_)).Times(1);

  // Send a packet so we can deliver an ACK
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto buf = buildRandomInputData(1000);
  this->getTransport()->writeChain(streamId, std::move(buf), false);
  const auto maybeWrittenPackets = this->loopForWrites();
  ASSERT_TRUE(maybeWrittenPackets.has_value());

  // Deliver a single ACK packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacks) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();
  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("hello");
  auto typedTestWriteChain20 =
      this->getTransport()->writeChain(streamId, data1->clone(), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto data2 = IOBuf::copyBuffer("world");
  auto typedTestWriteChain21 =
      this->getTransport()->writeChain(streamId, data2->clone(), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  data1->appendToChain(std::move(data2));
  auto combined = std::move(data1);

  // should have sent two packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
  EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

  MockDeliveryCallback cb;
  for (uint64_t offset = 0; offset < combined->computeChainDataLength();
       offset++) {
    auto typedTestRegisterDelivery1 =
        this->getTransport()->registerDeliveryCallback(streamId, offset, &cb);
    EXPECT_CALL(cb, onDeliveryAck(streamId, offset, _)).Times(1);
  }
  auto typedTestRegisterDelivery2 =
      this->getTransport()->registerDeliveryCallback(
          streamId, combined->computeChainDataLength(), &cb);
  EXPECT_CALL(
      cb, onDeliveryAck(streamId, combined->computeChainDataLength(), _))
      .Times(0);
  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(
      std::vector<Optional<typename TestFixture::NewOutstandingPacketInterval>>{
          maybeWrittenPackets1, maybeWrittenPackets2}));
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  // The largest ACKed offset is the size of the stream data - 1
  EXPECT_EQ(
      stream->ackedIntervals.front().end,
      combined->computeChainDataLength() - 1);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacksFinOnly) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain22 =
      this->getTransport()->writeChain(streamId, nullptr, true);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  MockDeliveryCallback cb;
  auto typedTestRegisterDelivery3 =
      this->getTransport()->registerDeliveryCallback(streamId, 0, &cb);
  EXPECT_CALL(cb, onDeliveryAck(streamId, 0, _));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  EXPECT_EQ(stream->ackedIntervals.front().end, 0);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacksSingleByteNoFin) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain23 = this->getTransport()->writeChain(
      streamId, folly::IOBuf::copyBuffer("a"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  MockDeliveryCallback cb;
  auto typedTestRegisterDelivery4 =
      this->getTransport()->registerDeliveryCallback(streamId, 0, &cb);
  EXPECT_CALL(cb, onDeliveryAck(streamId, 0, _));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  EXPECT_EQ(stream->ackedIntervals.front().end, 0);
  this->destroyTransport();
}

/**
 * Handle a successful incoming key update. This verifies that the write phase
 * is advanced whenever a key update is detected.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, HandleIncomingKeyUpdate) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send a packet in the current phase
    auto typedTestWriteChain24 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);
  }

  {
    // Receive a packet in the current phase. Both read and writer ciphers
    // should remain in phase zero
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Receive a packet in the next phase. This is a key update that should
    // update both the read and write ciphers to phase one.
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello3"), ProtectionType::KeyPhaseOne));
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);

    // No packets have been written in phase one yet.
    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);
  }

  {
    // Send a packet. The connection should stay in phase one and increment the
    // number of packets written in this phase.
    auto typedTestWriteChain25 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello4"), false);
    this->loopForWrites();
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);
  }

  {
    // Receive an out-of-order packet in the previous phase. It should increment
    // total number of bytes received but the current phase shouldn't change.
    auto tmpData = IOBuf::copyBuffer("hello out of order");
    auto pktBuf = quic::test::packetToBuf(createStreamPacket(
        this->getSrcConnectionId(),
        this->getDstConnectionId(),
        this->peerPacketNumStore.nextAppDataPacketNum - 2, // older packet
        streamId,
        *tmpData /* stream data */,
        0 /* cipherOverhead */,
        0 /* largest acked */,
        // // the following technically ignores lost ACK packets from peer, but
        // // should meet the needs of the majority of tests...
        // getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(0),
        std::nullopt /* longHeaderOverride */,
        false /* eof */,
        ProtectionType::KeyPhaseZero));
    pktBuf->coalesce();

    auto receivedBytesBeforePacket = this->getConn().lossState.totalBytesRecvd;

    this->deliverPacket(std::move(pktBuf));
    // Read and Write phases don't advance.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);

    // The bytes from the old packet were received successfully.
    EXPECT_GT(
        this->getConn().lossState.totalBytesRecvd, receivedBytesBeforePacket);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate a key update - Successful attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateKeyUpdateSuccess) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain26 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;
    // Only do the period updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain27 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Another key update should not be allowed until this one is verified
    QuicConnectionStateBase& conn = this->getNonConstConn();
    EXPECT_FALSE(conn.readCodec->canInitiateKeyUpdate());
    EXPECT_FALSE(conn.readCodec->advanceOneRttReadPhase());
  }

  {
    // Receiving a packet in the new phase verifies the pending key update
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello4"), ProtectionType::KeyPhaseOne));

    EXPECT_TRUE(this->getConn().readCodec->canInitiateKeyUpdate());
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate a key update - Failed attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateKeyUpdateFailure) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain28 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update.
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;
    // Only do the period updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain29 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    ASSERT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
    // const auto packetSentTime =
    //     CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Send a packet in the new phase.
    auto typedTestWriteChain30 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    ASSERT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    // The peer acks the new packet in the old phase. This is a CRYPTO_ERROR.
    auto oldestOutstandingPkt =
        this->getOldestOutstandingPacket(PacketNumberSpace::AppData);
    auto newestOutstandingPkt =
        this->getNewestOutstandingPacket(PacketNumberSpace::AppData);
    quic::AckBlocks acks = {
        {oldestOutstandingPkt->packet.header.getPacketSequenceNum(),
         newestOutstandingPkt->packet.header.getPacketSequenceNum()}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(acks)
            .setAckDelay(0us)
            .setShortHeaderProtectionType(ProtectionType::KeyPhaseZero)
            .build());
    buf->coalesce();

    // Crypto error: Packet with key update was acked in the wrong phase
    EXPECT_THROW(this->deliverPacket(std::move(buf)), std::runtime_error);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate the first key update - Successful attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateFirstKeyUpdateSuccess) {
  // Use QUIC_V1 for the server since MVFST has special handling to accommodate
  // older client versions without key update support. That behavior is covered
  // in another test
  if (this->getConn().nodeType == QuicNodeType::Server) {
    this->getNonConstConn().version = QuicVersion::QUIC_V1;
  }

  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain31 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update through the firstKeyUpdatePacketCount
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Trigger this update as a first update
    conn.transportSettings.firstKeyUpdatePacketCount =
        numberOfWrittenPacketsInPhase;
    // Periodic interval is high enough not to be triggered
    conn.transportSettings.keyUpdatePacketCountInterval =
        kDefaultKeyUpdatePacketCountInterval;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain32 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Another key update should not be allowed until this one is verified
    QuicConnectionStateBase& conn = this->getNonConstConn();
    EXPECT_FALSE(conn.readCodec->canInitiateKeyUpdate());
    EXPECT_FALSE(conn.readCodec->advanceOneRttReadPhase());
  }

  {
    // Receiving a packet in the new phase verifies the pending key update
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello4"), ProtectionType::KeyPhaseOne));

    EXPECT_TRUE(this->getConn().readCodec->canInitiateKeyUpdate());
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * As a server, do not initiate key updates for QuicVersion::MVFST unless the
 * client has performed a key update.
 * (Old versions of MVFST did not support key updates)
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    ServerInitiateKeyUpdateForMvfstClient) {
  if (this->getConn().nodeType != QuicNodeType::Server) {
    // This test is for the server behavior only
    return;
  }

  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  this->getNonConstConn().version = QuicVersion::MVFST;

  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain33 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // First key update is due but it shouldn't trigger one because connection
    // is for QuicVersion::MVFST and the peer hasn't initiated a key update yet

    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Trigger this update as a first update
    conn.transportSettings.firstKeyUpdatePacketCount =
        numberOfWrittenPacketsInPhase;
    // Periodic interval is high enough not to be triggered
    conn.transportSettings.keyUpdatePacketCountInterval =
        kDefaultKeyUpdatePacketCountInterval;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain34 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should still be at Phase Zero
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  // Clear firstKeyUpdatePacketCount to indicate that a key update was performed
  // by the peer.
  this->getNonConstConn().transportSettings.firstKeyUpdatePacketCount.reset();

  {
    // Now that the peer had initiated a key update, the server can trigger one
    // too.
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Indicate that a regular update is due
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain35 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Read and writer ciphers should advance to Key Phase One
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

template <typename T>
struct AckEventMatcherBuilder {
  using Builder = AckEventMatcherBuilder;

  Builder&& setExpectedAckedIntervals(
      std::vector<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
          expectedAckedIntervals) {
    maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
    return std::move(*this);
  }

  Builder&& setExpectedAckedIntervals(
      std::vector<Optional<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
          expectedAckedIntervalsOpt) {
    std::vector<
        typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
        expectedAckedIntervals;
    for (const auto& maybeInterval : expectedAckedIntervalsOpt) {
      CHECK(maybeInterval.has_value());
      expectedAckedIntervals.push_back(maybeInterval.value());
    }
    maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
    return std::move(*this);
  }

  Builder&& setExpectedNumAckedPackets(const uint64_t expectedNumAckedPackets) {
    maybeExpectedNumAckedPackets = expectedNumAckedPackets;
    return std::move(*this);
  }

  Builder&& setAckTime(TimePoint ackTime) {
    maybeAckTime = ackTime;
    return std::move(*this);
  }

  Builder&& setAckDelay(std::chrono::microseconds ackDelay) {
    maybeAckDelay = ackDelay;
    return std::move(*this);
  }

  Builder&& setLargestAckedPacket(quic::PacketNum largestAckedPacketIn) {
    maybeLargestAckedPacket = largestAckedPacketIn;
    return std::move(*this);
  }

  Builder&& setLargestNewlyAckedPacket(
      quic::PacketNum largestNewlyAckedPacketIn) {
    maybeLargestNewlyAckedPacket = largestNewlyAckedPacketIn;
    return std::move(*this);
  }

  Builder&& setRtt(const OptionalMicros& rttIn) {
    maybeRtt = rttIn;
    CHECK(!noRtt);
    return std::move(*this);
  }

  Builder&& setRttNoAckDelay(const OptionalMicros& rttNoAckDelayIn) {
    maybeRttNoAckDelay = rttNoAckDelayIn;
    CHECK(!noRtt);
    CHECK(!noRttWithNoAckDelay);
    return std::move(*this);
  }

  Builder&& setNoRtt() {
    noRtt = true;
    CHECK(!maybeRtt);
    CHECK(!maybeRttNoAckDelay);
    return std::move(*this);
  }

  Builder&& setNoRttWithNoAckDelay() {
    noRttWithNoAckDelay = true;
    CHECK(!maybeRttNoAckDelay);
    return std::move(*this);
  }

  auto build() && {
    CHECK(
        noRtt ||
        (maybeRtt.has_value() &&
         (noRttWithNoAckDelay || maybeRttNoAckDelay.has_value())));

    CHECK(maybeExpectedAckedIntervals.has_value());
    const auto& expectedAckedIntervals = *maybeExpectedAckedIntervals;
    CHECK_LT(0, expectedAckedIntervals.size());

    CHECK(maybeExpectedNumAckedPackets.has_value());
    const auto& expectedNumAckedPackets = *maybeExpectedNumAckedPackets;

    CHECK(maybeAckTime.has_value());
    const auto& ackTime = *maybeAckTime;

    CHECK(maybeAckDelay.has_value());
    const auto& ackDelay = *maybeAckDelay;

    CHECK(maybeLargestAckedPacket.has_value());
    const auto& largestAckedPacket = *maybeLargestAckedPacket;

    CHECK(maybeLargestNewlyAckedPacket.has_value());
    const auto& largestNewlyAckedPacket = *maybeLargestNewlyAckedPacket;

    // sanity check expectedNumAckedPackets and expectedAckedIntervals
    // reduces potential of error in test design
    {
      uint64_t expectedNumAckedPacketsFromIntervals = 0;
      std::vector<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
          processedExpectedAckedIntervals;

      for (const auto& interval : expectedAckedIntervals) {
        CHECK_LE(interval.start, interval.end);
        CHECK_LE(0, interval.end);
        expectedNumAckedPacketsFromIntervals +=
            interval.end - interval.start + 1;

        // should not overlap with existing intervals
        for (const auto& processedInterval : processedExpectedAckedIntervals) {
          CHECK(
              processedInterval.end < interval.start ||
              processedInterval.start < interval.end);
        }

        processedExpectedAckedIntervals.push_back(interval);
      }
      CHECK_EQ(expectedNumAckedPacketsFromIntervals, expectedNumAckedPackets);
    }

    if constexpr (std::is_base_of_v<T, QuicClientTransportTestBase>) {
      return testing::Property(
          &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(
              testing::AllOf(
                  // ack time, adjusted ack time, RTT not supported for client
                  // now
                  testing::Field(
                      &quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
                  testing::Field(
                      &quic::AckEvent::largestAckedPacket,
                      testing::Eq(largestAckedPacket)),
                  testing::Field(
                      &quic::AckEvent::largestNewlyAckedPacket,
                      testing::Eq(largestNewlyAckedPacket)),
                  testing::Field(
                      &quic::AckEvent::ackedPackets,
                      testing::SizeIs(expectedNumAckedPackets)))));
    } else if constexpr (std::is_base_of_v<T, QuicServerTransportTestBase>) {
      return testing::Property(
          &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(
              testing::AllOf(
                  testing::Field(
                      &quic::AckEvent::ackTime, testing::Eq(ackTime)),
                  testing::Field(
                      &quic::AckEvent::adjustedAckTime,
                      testing::Eq(ackTime - ackDelay)),
                  testing::Field(
                      &quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
                  testing::Field(
                      &quic::AckEvent::largestAckedPacket,
                      testing::Eq(largestAckedPacket)),
                  testing::Field(
                      &quic::AckEvent::largestNewlyAckedPacket,
                      testing::Eq(largestNewlyAckedPacket)),
                  testing::Field(
                      &quic::AckEvent::ackedPackets,
                      testing::SizeIs(expectedNumAckedPackets)),
                  testing::Field(
                      &quic::AckEvent::rttSample, testing::Eq(maybeRtt)),
                  testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::Eq(maybeRttNoAckDelay)))));
    } else {
      FAIL(); // unhandled typed test
    }
  }

  explicit AckEventMatcherBuilder() = default;

  Optional<std::vector<
      typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
      maybeExpectedAckedIntervals;
  OptionalIntegral<uint64_t> maybeExpectedNumAckedPackets;
  Optional<TimePoint> maybeAckTime;
  OptionalMicros maybeAckDelay;
  OptionalIntegral<quic::PacketNum> maybeLargestAckedPacket;
  OptionalIntegral<quic::PacketNum> maybeLargestNewlyAckedPacket;
  OptionalMicros maybeRtt;
  OptionalMicros maybeRttNoAckDelay;
  bool noRtt{false};
  bool noRttWithNoAckDelay{false};
};

template <typename T>
struct ReceivedUdpPacketMatcherBuilder {
  using Builder = ReceivedUdpPacketMatcherBuilder;
  using Obj =
      quic::SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket;

  Builder&& setExpectedPacketReceiveTime(
      const TimePoint expectedPacketReceiveTime) {
    maybeExpectedPacketReceiveTime = expectedPacketReceiveTime;
    return std::move(*this);
  }

  Builder&& setExpectedPacketNumBytes(const uint64_t expectedPacketNumBytes) {
    maybeExpectedPacketNumBytes = expectedPacketNumBytes;
    return std::move(*this);
  }

  Builder&& setExpectedTosValue(const uint8_t expectedTosValue) {
    maybeExpectedTosValue = expectedTosValue;
    return std::move(*this);
  }

  auto build() && {
    CHECK(maybeExpectedPacketReceiveTime.has_value());
    const auto& packetReceiveTime = *maybeExpectedPacketReceiveTime;

    CHECK(maybeExpectedPacketNumBytes.has_value());
    const auto& packetNumBytes = *maybeExpectedPacketNumBytes;

    CHECK(maybeExpectedTosValue.has_value());
    const auto& packetTosValue = *maybeExpectedTosValue;

    if constexpr (std::is_base_of_v<T, QuicClientTransportTestBase>) {
      return testing::AllOf(
          // client does not currently support socket RX timestamps, so we
          // expect ts >= now() at time of matcher build
          testing::Field(
              &Obj::packetReceiveTime,
              testing::AnyOf(
                  testing::Eq(packetReceiveTime),
                  testing::Ge(TimePoint::clock::now()))),
          testing::Field(&Obj::packetNumBytes, testing::Eq(packetNumBytes)),
          testing::Field(&Obj::packetTos, testing::Eq(packetTosValue)));
    } else if constexpr (std::is_base_of_v<T, QuicServerTransportTestBase>) {
      return testing::AllOf(
          testing::Field(
              "packetReceiveTime",
              &Obj::packetReceiveTime,
              testing::Eq(packetReceiveTime)),
          testing::Field(
              "packetNumBytes",
              &Obj::packetNumBytes,
              testing::Eq(packetNumBytes)),
          testing::Field(
              "packetTos", &Obj::packetTos, testing::Eq(packetTosValue)));
    } else {
      FAIL(); // unhandled typed test
    }
  }

  explicit ReceivedUdpPacketMatcherBuilder() = default;

  Optional<TimePoint> maybeExpectedPacketReceiveTime;
  OptionalIntegral<uint64_t> maybeExpectedPacketNumBytes;
  Optional<uint8_t> maybeExpectedTosValue;
};

template <typename T>
class QuicTypedTransportTestForObservers : public QuicTypedTransportTest<T> {
 public:
  void SetUp() override {
    QuicTypedTransportTest<T>::SetUp();
  }

  auto getStreamEventMatcherOpt(
      const StreamId streamId,
      const StreamInitiator streamInitiator,
      const StreamDirectionality streamDirectionality) {
    return testing::AllOf(
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamId,
            testing::Eq(streamId)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamInitiator,
            testing::Eq(streamInitiator)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamDirectionality,
            testing::Eq(streamDirectionality)));
  }
};

template <typename T>
class QuicTypedTransportAfterStartTestForObservers
    : public QuicTypedTransportTestForObservers<T> {
 public:
  ~QuicTypedTransportAfterStartTestForObservers() override = default;

  void SetUp() override {
    QuicTypedTransportTestForObservers<T>::SetUp();
    QuicTypedTransportTestForObservers<T>::startTransport();
  }

  void verifyMixedNewAndRetransmittedStreamBytesAcked(
      const StreamRetransmissionTrigger trigger) {
    // This is an arbitrary positive RTT used to make ACK timing deterministic;
    // the selected loss threshold is configured explicitly below.
    constexpr auto kAckRtt = 27ms;

    auto transport = this->getTransport();
    this->ackAllOutstandingPackets();
    ASSERT_TRUE(this->getConn().outstandings.packets.empty());
    // Packet number skipping would make write intervals non-contiguous.
    this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber =
        0;

    const auto streamId = transport->createBidirectionalStream().value();
    auto retransmittedBody = IOBuf::copyBuffer("hello");
    const auto retransmittedBodyLength =
        retransmittedBody->computeChainDataLength();
    auto writeResult =
        transport->writeChain(streamId, std::move(retransmittedBody), false);
    ASSERT_FALSE(writeResult.hasError());
    const auto originalPackets = this->loopForWrites();
    ASSERT_TRUE(originalPackets.has_value());
    ASSERT_EQ(originalPackets->start, originalPackets->end);

    auto& conn = this->getNonConstConn();
    Optional<
        typename QuicTypedTransportTestBase<T>::NewOutstandingPacketInterval>
        mixedPackets;
    auto newBody = IOBuf::copyBuffer("world");
    const auto newBodyLength = newBody->computeChainDataLength();

    const auto triggerStreamId = transport->createBidirectionalStream().value();
    writeResult =
        transport->writeChain(triggerStreamId, IOBuf::copyBuffer("a"), false);
    ASSERT_FALSE(writeResult.hasError());
    const auto firstTriggerPackets = this->loopForWrites();
    ASSERT_TRUE(firstTriggerPackets.has_value());
    ASSERT_EQ(firstTriggerPackets->start, firstTriggerPackets->end);

    auto lossTriggerPackets = firstTriggerPackets;
    bool lostByReorderThreshold = false;
    bool lostByTimeout = false;
    switch (trigger) {
      case StreamRetransmissionTrigger::PacketThreshold: {
        writeResult = transport->writeChain(
            triggerStreamId, IOBuf::copyBuffer("b"), false);
        ASSERT_FALSE(writeResult.hasError());
        const auto secondTriggerPackets = this->loopForWrites();
        ASSERT_TRUE(secondTriggerPackets.has_value());
        ASSERT_EQ(secondTriggerPackets->start, secondTriggerPackets->end);
        ASSERT_EQ(originalPackets->end + 1, firstTriggerPackets->start);
        ASSERT_EQ(firstTriggerPackets->end + 1, secondTriggerPackets->start);
        lossTriggerPackets.emplace(*secondTriggerPackets);

        conn.lossState.reorderingThreshold = 1;
        conn.transportSettings.timeReorderingThreshDividend = 1000000;
        conn.transportSettings.timeReorderingThreshDivisor = 1;
        lostByReorderThreshold = true;
        break;
      }
      case StreamRetransmissionTrigger::TimeThreshold:
        // The ACK below triggers QUIC's time-threshold loss detection. PTO is
        // unsuitable here because it schedules probe clones without declaring
        // the original packet lost or moving its data into the loss buffer.
        conn.lossState.reorderingThreshold = 10;
        conn.transportSettings.timeReorderingThreshDividend = 1;
        conn.transportSettings.timeReorderingThreshDivisor = 1000000;
        lostByTimeout = true;
        break;
    }

    LegacyObserver::EventSet eventSet;
    eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);
    eventSet.enable(SocketObserverInterface::Events::lossEvents);
    auto observer = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
    EXPECT_CALL(*observer, observerAttach(transport));
    transport->addObserver(observer.get());

    const auto ackDelay = 0us;
    const auto lossTriggerAckTime = lossTriggerPackets->sentTime + kAckRtt;
    const auto lossTriggerAckMatcher =
        AckEventMatcherBuilder<T>()
            .setExpectedAckedIntervals({lossTriggerPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(lossTriggerAckTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(lossTriggerPackets->end)
            .setLargestNewlyAckedPacket(lossTriggerPackets->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(kAckRtt))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    kAckRtt - ackDelay))
            .build();
    EXPECT_CALL(*observer, acksProcessed(transport, lossTriggerAckMatcher));
    EXPECT_CALL(
        *observer,
        packetLossDetected(
            transport,
            testing::Field(
                &SocketObserverInterface::LossEvent::lostPackets,
                testing::ElementsAre(
                    MockLegacyObserver::getLossPacketMatcher(
                        originalPackets->end,
                        lostByReorderThreshold,
                        lostByTimeout)))));

    this->deliverPacketNoWrites(
        this->buildAckPacketForSentAppDataPackets(*lossTriggerPackets),
        lossTriggerAckTime);

    const auto originalPacket = std::find_if(
        conn.outstandings.packets.begin(),
        conn.outstandings.packets.end(),
        [&](const auto& packet) {
          return packet.packet.header.getPacketSequenceNum() ==
              originalPackets->end;
        });
    ASSERT_NE(originalPacket, conn.outstandings.packets.end());
    ASSERT_TRUE(originalPacket->declaredLost);
    conn.lossState.reorderingThreshold = 10;

    writeResult = transport->writeChain(streamId, std::move(newBody), false);
    ASSERT_FALSE(writeResult.hasError());
    const auto writtenPackets = this->loopForWrites();
    ASSERT_TRUE(writtenPackets.has_value());
    mixedPackets.emplace(*writtenPackets);

    ASSERT_TRUE(mixedPackets.has_value());
    ASSERT_EQ(mixedPackets->start, mixedPackets->end);
    ASSERT_GT(mixedPackets->start, originalPackets->end);

    const auto sentTime = mixedPackets->sentTime;
    const auto ackRecvTime = sentTime + kAckRtt;
    const auto mixedAckMatcher = testing::AllOf(
        AckEventMatcherBuilder<T>()
            .setExpectedAckedIntervals({mixedPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(mixedPackets->end)
            .setLargestNewlyAckedPacket(mixedPackets->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build(),
        testing::Property(
            &SocketObserverInterface::AcksProcessedEvent::getAckEvents,
            testing::ElementsAre(
                testing::Field(
                    &AckEvent::ackedPackets,
                    testing::ElementsAre(
                        testing::Field(
                            &AckEvent::AckPacket::detailsPerStream,
                            testing::UnorderedElementsAre(
                                AckEventStreamDetailsMatcherBuilder()
                                    .setStreamID(streamId)
                                    .setStreamBytesAcked(
                                        retransmittedBodyLength + newBodyLength)
                                    .setStreamBytesAckedByRetrans(
                                        retransmittedBodyLength)
                                    .build())))))));
    EXPECT_CALL(*observer, acksProcessed(transport, mixedAckMatcher));

    // This observer assertion intentionally fails if mvfst starts extending a
    // retransmitted frame with new bytes instead of emitting a separate frame.
    this->deliverPacketNoWrites(
        this->buildAckPacketForSentAppDataPackets(*mixedPackets, ackDelay),
        ackRecvTime);
    this->destroyTransport();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportTestForObservers, AttachThenDetach) {
  this->startTransport();

  InSequence s;
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_EQ(1, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  EXPECT_CALL(*observer, detached(transport));
  EXPECT_TRUE(transport->removeObserver(observer.get()));
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoDrainNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = false;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoErrorDrainEnabled_DrainThenDestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  transport->close(std::nullopt);

  // wait for the drain
  EXPECT_CALL(*observer, closing(transport, _));
  auto follyEvb = transport->getEventBase()
                      ->template getTypedEventBase<FollyQuicEventBase>()
                      ->getBackingEventBase();
  follyEvb->timer().scheduleTimeoutFn(
      [&] { transport->getEventBase()->terminateLoopSoon(); },
      std::chrono::ceil<std::chrono::milliseconds>(
          1ms + kDrainFactor * calculatePTO(this->getConn())));
  transport->getEventBase()->loop();
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoErrorDrainEnabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(observer.get());

  // destroy transport without waiting for drain
  EXPECT_CALL(*observer, closing(transport, _));
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseWithErrorDrainDisabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = false;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{testError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseWithErrorDrainEnabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));

  // because of the error, we won't wait for the drain despite it being enabled.
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{testError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain36 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // local sends goodbye with EOF, gets the ACK
  auto typedTestWriteChain37 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye1"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStreamImmediateEofLocal) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  auto typedTestWriteChain38 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  auto typedTestWriteChain39 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote with an EOF
  // stream should close on arrival of packet from remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedUniStreamRstSentThenAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalUnidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createUnidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain40 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local writes a reset
  const auto result = this->getTransport()->resetStream(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  // //
  // this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for the data sent in first write
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver ACK for the reset packet sent by local
  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedUniStreamRstSentThenAckedBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalUnidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createUnidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain41 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local writes a reset
  const auto result = this->getTransport()->resetStream(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  // //
  // this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for the reset packet sent by local
  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  auto typedTestWriteChain42 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // one more message from the peer, this time with EOF
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye1")));

  // local sends goodbye with EOF too, get the ACK, stream should close
  auto typedTestWriteChain43 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye2"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEofRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data, see a packet be written, get the ACK
  auto typedTestWriteChain44 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // local sends goodbye with EOF too, get the ACK, stream should close
  auto typedTestWriteChain45 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data with EOF, see a packet be written, get the ACK
  auto typedTestWriteChain46 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamStopSendingPlusRstTriggersRst) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  auto typedTestWriteChain47 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamStopSendingPlusRstTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  auto typedTestWriteChain48 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEorStopSendingTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  auto typedTestWriteChain49 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsAckEventsPeerOpenedBiStreamImmediateEorStopSendingTriggersRstBytesInFlightPartiallyAckedAfterRstSent) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written
  auto typedTestWriteChain50 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local sends some more stream data, see another packet be written
  auto typedTestWriteChain51 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacketNoWrites(
      this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeWrittenPackets3 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets3));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for first packet
  // despite reset being sent, observer should still be notified of ACK
  {
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    const auto& writtenPackets1 = maybeWrittenPackets1.value();
    const auto sentTime = writtenPackets1.sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 0us;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                std::vector<typename TestFixture::NewOutstandingPacketInterval>{
                    writtenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(writtenPackets1.end)
            .setLargestNewlyAckedPacket(writtenPackets1.end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*obs1, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*obs2, acksProcessed(transport, matcher));
    EXPECT_CALL(*obs3, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {writtenPackets1.start, writtenPackets1.end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver ACK for rst packet, then stream should close
  {
    ASSERT_TRUE(maybeWrittenPackets3.has_value());
    const auto& writtenPackets3 = maybeWrittenPackets3.value();
    const auto sentTime = writtenPackets3.sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 0us;
    const auto ackEventMatcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                std::vector<typename TestFixture::NewOutstandingPacketInterval>{
                    writtenPackets3})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(writtenPackets3.end)
            .setLargestNewlyAckedPacket(writtenPackets3.end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*obs1, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*obs2, acksProcessed(transport, ackEventMatcher));
    EXPECT_CALL(*obs3, acksProcessed(transport, ackEventMatcher));

    const auto streamEventMatcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, streamEventMatcher));
    EXPECT_CALL(*obs3, streamClosed(transport, streamEventMatcher));

    const quic::AckBlocks ackBlocks = {
        {writtenPackets3.start, writtenPackets3.end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSent) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 10000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes - strLength))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes - strLength))));

    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
  }

  // open a stream and write string
  {
    auto typedTestWriteChain52 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentInvokeForEach) {
  struct InvokedOutstandingPacketFields {
    PacketNumberSpace pnSpace{PacketNumberSpace::Initial};
    PacketNum packetNum{0};
  };

  InSequence s;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(obs1.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // first write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain53 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum))));
  }

  // second write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain54 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("goodbye"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum))));
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingMultiplePacketsSentInvokeForEach) {
  struct InvokedOutstandingPacketFields {
    PacketNumberSpace pnSpace{PacketNumberSpace::Initial};
    PacketNum packetNum{0};
  };

  InSequence s;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(obs1.get()));

  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // first write of two packets worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto buf = buildRandomInputData(2000 /* bufLength */);
    auto typedTestWriteChain55 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    lastPacketNum))));
  }

  // second write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain56 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("goodbye"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum))));
  }

  // third write of three packets worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto buf = buildRandomInputData(3000 /* bufLength */);
    auto typedTestWriteChain57 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent three packets
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum + 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    lastPacketNum))));
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentWroteMoreThanCwnd) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController with a CWND < MSS
  const auto cwndInBytes = 800;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // we're going to write 1000 bytes with a smaller CWND
  // because MSS > CWND, we're going to overshoot
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_GT(bufLength, cwndInBytes);

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(0))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce(), expect overshoot CWND
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::AllOf(testing::Gt(bufLength), testing::Gt(cwndInBytes))));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
  }

  // open a stream and write string
  {
    auto typedTestWriteChain58 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // TODO(bschlinker): Check for appRateLimited on ACK so that we get an
  // appRateLimited signal when the outstanding packet is ACKed.

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketsSentCwndLimited) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());
  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 7000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // we're going to write 10000 bytes with a CWND of 7000
  const auto bufLength = 10000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_EQ(7000, cwndInBytes);

  // setup matchers for first write, write the entire buffer, trigger loop
  // we will NOT become app limited after this write, as CWND limited
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 5;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(0))), // CWND exhausted
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Ge(cwndInBytes))); // full CWND written
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    auto typedTestWriteChain59 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // make sure we wrote
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  // ACK all outstanding packets
  this->ackAllOutstandingPackets();

  // setup matchers for second write, then trigger loop
  // we will become app limited after this write
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 2;

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Lt(cwndInBytes)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });

    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentNoCongestionController) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // remove congestion controller
  this->getNonConstConn().congestionController = nullptr;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // no congestion controller == no startWritingFromAppLimited events
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, startWritingFromAppLimited(_, _)).Times(0);

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(std::nullopt))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(std::nullopt))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // no congestion controller == no appRateLimited events
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, appRateLimited(_, _)).Times(0);
  }

  // open a stream and write str1
  {
    auto typedTestWriteChain60 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedNoAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto streamBody = IOBuf::copyBuffer("hello");
  const auto streamBodyLength = streamBody->computeChainDataLength();
  auto typedTestWriteChain61 =
      this->getTransport()->writeChain(streamId, std::move(streamBody), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 0us;
  const auto matcher = testing::AllOf(
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build(),
      testing::Property(
          &SocketObserverInterface::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(
              testing::Field(
                  &AckEvent::ackedPackets,
                  testing::ElementsAre(
                      testing::Field(
                          &AckEvent::AckPacket::detailsPerStream,
                          testing::UnorderedElementsAre(
                              AckEventStreamDetailsMatcherBuilder()
                                  .setStreamID(streamId)
                                  .setStreamBytesAcked(streamBodyLength)
                                  .setStreamBytesAckedByRetrans(0)
                                  .build())))))));
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsMixedNewAndPacketReorderingRetransmittedStreamBytesAcked) {
  this->verifyMixedNewAndRetransmittedStreamBytesAcked(
      StreamRetransmissionTrigger::PacketThreshold);
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsMixedNewAndTimeThresholdRetransmittedStreamBytesAcked) {
  this->verifyMixedNewAndRetransmittedStreamBytesAcked(
      StreamRetransmissionTrigger::TimeThreshold);
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain62 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelayEqRtt) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain63 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime - sentTime; // ack delay == RTT!
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime))
          .setRttNoAckDelay(0us)
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(
                      testing::AllOf(
                          testing::Field(
                              &quic::AckEvent::rttSampleNoAckDelay,
                              testing::AnyOf(
                                  testing::Eq(0ms),
                                  testing::Eq(std::nullopt)))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(
                      testing::AllOf(
                          testing::Field(
                              &quic::AckEvent::rttSampleNoAckDelay,
                              testing::AnyOf(
                                  testing::Eq(0ms),
                                  testing::Eq(std::nullopt)))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithTooLargeAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain64 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime + 1ms - sentTime; // ack delay >> RTT!
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime))
          .setNoRttWithNoAckDelay()
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(
                      testing::AllOf(
                          testing::Field(
                              &quic::AckEvent::rttSampleNoAckDelay,
                              testing::Eq(std::nullopt))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(
                      testing::AllOf(
                          testing::Field(
                              &quic::AckEvent::rttSampleNoAckDelay,
                              testing::Eq(std::nullopt))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAllAckedAtOnce) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain65 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain66 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain67 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets3->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals(
              {maybeWrittenPackets1,
               maybeWrittenPackets2,
               maybeWrittenPackets3})
          .setExpectedNumAckedPackets(3)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets3->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
          .setRtt(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentAndAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream, write some bytes, send packet, deliver ACK
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain68 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // write some more bytes into the same stream, send packet, deliver ACK
  auto typedTestWriteChain69 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 443ms;
    const auto ackDelay = 7ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // third and final write, this time with EOF, send packet, deliver ACK
  auto typedTestWriteChain70 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // Packet number skipping would make write intervals non-contiguous.
  this->getNonConstConn().transportSettings.skipOneInNPacketSequenceNumber = 0;

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain71 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain72 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain73 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 122ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    const auto sentTime = maybeWrittenPackets2->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 1ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets2})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets2->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets2->start, maybeWrittenPackets2->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 82ms;
    const auto ackDelay = 20ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets3})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedSequentiallyThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain74 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain75 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain76 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 11ms;
    const auto ackDelay = 4ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedAtOnceThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain77 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain78 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain79 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1 and 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime; // 3 is latest sent
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                {maybeWrittenPackets1, maybeWrittenPackets3})
            .setExpectedNumAckedPackets(2)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    PacketsReceivedEventsSingle) {
  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  const auto pkt1RecvTime = TimePoint::clock::now();
  const auto pkt1NumBytes = pkt1->computeChainDataLength();

#ifndef _WIN32
  const uint8_t packetTosValue = kEcnECT0;
#else
  uint8_t packetTosValue = kEcnECT0;
  if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    // QuicClientTransport does not support reading ECN bits using the default
    // recvmsg read path.
    packetTosValue = 0;
  }
#endif

  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt1NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pkt1RecvTime)
                    .setExpectedPacketNumBytes(pkt1NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt1), pkt1RecvTime, packetTosValue);

  // deliver pkt2 with stream data from the remote
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt2RecvTime = pkt1RecvTime + 50ms;
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt2NumBytes, pkt1NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pkt2RecvTime)
                    .setExpectedPacketNumBytes(pkt2NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt2), pkt2RecvTime, packetTosValue);

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    PacketsReceivedEventsMulti) {
  // skip for client transport tests for now as supporting test foundation
  // does not properly support batch delivery
  if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    return;
  }

  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 and pkt2 at same time with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt1NumBytes = pkt1->computeChainDataLength();
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt1NumBytes, pkt2NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch1;
  pktBatch1.emplace_back(std::move(pkt1));
  pktBatch1.emplace_back(std::move(pkt2));
  const auto pktBatch1RecvTime = TimePoint::clock::now();
  const auto pktBatch1NumBytes = pkt1NumBytes + pkt2NumBytes;

  const uint8_t packetTosValue = kEcnECT1;
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            "receiveLoopTime",
            &Event::receiveLoopTime,
            testing::Ge(TimePoint::clock::now())),
        testing::Field(
            "numPacketsReceived", &Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            "numBytesReceived",
            &Event::numBytesReceived,
            testing::Eq(pktBatch1NumBytes)),
        testing::Field(
            "receivedPacketsCount",
            &Event::receivedPackets,
            testing::SizeIs(2)),
        testing::Field(
            "receivedPacketsElements",
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt1NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build(),
                // pkt2
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt2NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch1), pktBatch1RecvTime, packetTosValue);

  // deliver pkt3 and pkt4 at same time with stream data from the remote
  auto pkt3 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(200));
  auto pkt4 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(800));
  const auto pkt3NumBytes = pkt3->computeChainDataLength();
  const auto pkt4NumBytes = pkt4->computeChainDataLength();
  EXPECT_NE(pkt3NumBytes, pkt4NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch2;
  pktBatch2.emplace_back(std::move(pkt3));
  pktBatch2.emplace_back(std::move(pkt4));
  const auto pktBatch2RecvTime = pktBatch1RecvTime + 50ms;
  const auto pktBatch2NumBytes = pkt3NumBytes + pkt4NumBytes;
  EXPECT_NE(pktBatch1NumBytes, pktBatch2NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            &Event::numBytesReceived, testing::Eq(pktBatch2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(2)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt3NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build(),
                // pkt2
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt4NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch2), pktBatch2RecvTime, packetTosValue);

  this->destroyTransport();
}

template <typename T>
class QuicTypedTransportAfterStartTestDatagram
    : public QuicTypedTransportAfterStartTest<typename T::TransportType> {
 public:
  ~QuicTypedTransportAfterStartTestDatagram() override = default;

  void SetUp() override {
    QuicTypedTransportAfterStartTest<typename T::TransportType>::SetUp();

    // Clear outstanding packets
    this->getNonConstConn().outstandings.reset();

    // Enable DATAGRAM support by setting maxWriteFrameSize > 0
    this->getNonConstConn().transportSettings.datagramConfig.enabled = true;
    this->getNonConstConn().datagramState.maxWriteFrameSize = 1200;

    // Set scheduleDatagramsWithStreams based on test config
    this->getNonConstConn()
        .transportSettings.datagramConfig.scheduleDatagramsWithStreams =
        T::scheduleDatagramsWithStreams;

    // Set up mock congestion controller
    auto mockCongestionController =
        std::make_unique<MockCongestionController>();
    mockCongestionController_ = mockCongestionController.get();
    this->getNonConstConn().congestionController =
        std::move(mockCongestionController);
    ON_CALL(*mockCongestionController_, getWritableBytes())
        .WillByDefault(Return(1000));
  }

  void setWritableBytes(uint64_t writableBytes) {
    ON_CALL(*mockCongestionController_, getWritableBytes())
        .WillByDefault(Return(writableBytes));
  }

  [[nodiscard]] MockCongestionController* getMockCongestionController() const {
    return mockCongestionController_;
  }

  struct State {
    uint64_t bytesSent{0};
    uint64_t bodyBytesSent{0};
    uint64_t bytesInFlight{0};
    uint64_t totalPacketsSent{0};
    size_t outstandingPackets{0};
    TimePoint lastRetransmittablePacketSentTime;
    Optional<TimePoint> maybeLastPacketSentTime;
    auto operator<=>(const State&) const = default;
  };

  State buildState() {
    return State{
        .bytesSent = this->getTransport()->getTransportInfo().bytesSent,
        .bodyBytesSent = this->getTransport()->getTransportInfo().bodyBytesSent,
        .bytesInFlight = this->getTransport()->getTransportInfo().bytesInFlight,
        .totalPacketsSent =
            this->getTransport()->getTransportInfo().totalPacketsSent,
        .outstandingPackets = this->getConn().outstandings.packets.size(),
        .lastRetransmittablePacketSentTime =
            this->getConn().lossState.lastRetransmittablePacketSentTime,
        .maybeLastPacketSentTime =
            this->getConn().lossState.maybeLastPacketSentTime};
  }

  struct WriteResult {
    std::string bufWritten;
  };

  WriteResult writeToNewStream() {
    const std::string bufToWrite = "StreamData";
    const auto maybeStreamId =
        this->getTransport()->createBidirectionalStream();
    CHECK(maybeStreamId.has_value());
    const auto& streamId = maybeStreamId.value();
    // Set stream priority before writing: priority=0, incremental=false
    // Datagram flows now always use the default, which is priority=3. Mixed
    // tests assumed streams are higher pri than datagrams.
    this->getTransport()->setStreamPriority(
        streamId, HTTPPriorityQueue::Priority(0, false));
    const auto mvfstWriteStreamResult = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer(bufToWrite), false /* eof */);
    CHECK(mvfstWriteStreamResult.has_value());
    return WriteResult{.bufWritten = bufToWrite};
  }

  WriteResult writeDatagram() {
    const std::string bufToWrite = "DatagramBuf";
    const auto mvfstWriteDatagramResult = this->getTransport()->writeDatagram(
        folly::IOBuf::copyBuffer(bufToWrite));
    CHECK(mvfstWriteDatagramResult.has_value())
        << "DATAGRAM write should always succeed";
    return WriteResult{.bufWritten = bufToWrite};
  }

 private:
  MockCongestionController* mockCongestionController_{nullptr};
};

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTestDatagram,
    ::DatagramTransportTypes,
    ::DatagramTransportTypeNames);

template <typename T>
class QuicTypedTransportAfterStartTestDatagramWithStreams
    : public QuicTypedTransportAfterStartTestDatagram<T> {
 public:
  ~QuicTypedTransportAfterStartTestDatagramWithStreams() override = default;
};

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTestDatagramWithStreams,
    ::DatagramWithStreamsTransportTypes,
    ::DatagramTransportTypeNames);

/**
 * Test DATAGRAM congestion control mode.
 *
 * If nothing is written, then initial state should == post loop state.
 */
TYPED_TEST(QuicTypedTransportAfterStartTestDatagram, NoWritesJustLoop) {
  const auto initialState = this->buildState();
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);
  this->loopForWrites();
  const auto postLoopState = this->buildState();
  EXPECT_EQ(initialState, postLoopState);
  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = Constrained.
 * PacketContents = Datagram only.
 * WritableBytes = 1000.
 *
 * DATAGRAM-only packets SHOULD NOT be inserted into outstandings, congestion
 * controller SHOULD NOT be notified, but we SHOULD observe bytes written.
 *
 * lastRetransmittablePacketSentTime SHOULD be updated.
 * maybeLastPacketSentTime SHOULD be updated.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    Constrained_DatagramOnlyPacket_WritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::Constrained;
  this->setWritableBytes(1000);

  const auto initialState = this->buildState();
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);
  const auto datagramWriteResult = this->writeDatagram();
  this->loopForWrites();
  const auto postLoopState = this->buildState();
  EXPECT_NE(initialState, postLoopState);

  // Verify that packets and data was written
  EXPECT_GE(
      postLoopState.bytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size());
  EXPECT_GE(
      postLoopState.bodyBytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size());
  EXPECT_EQ(postLoopState.totalPacketsSent, initialState.totalPacketsSent + 1);

  // Verify no packets were added to outstandings
  EXPECT_TRUE(this->getConn().outstandings.packets.empty());

  // Verify loss state updates
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_NE(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = Constrained.
 * PacketContents = Datagram only.
 * WritableBytes = 0.
 *
 * With no writable bytes, NO packets should be written.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    Constrained_DatagramOnlyPacket_NoWritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::Constrained;
  this->setWritableBytes(0);

  const auto initialState = this->buildState();
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);
  const auto datagramWriteResult = this->writeDatagram();
  this->loopForWrites();
  const auto postLoopState = this->buildState();

  // With no writable bytes, no packets should be sent
  EXPECT_EQ(initialState.bytesSent, postLoopState.bytesSent);
  EXPECT_EQ(initialState.bodyBytesSent, postLoopState.bodyBytesSent);
  EXPECT_EQ(initialState.totalPacketsSent, postLoopState.totalPacketsSent);

  // Verify no packets were added to outstandings
  EXPECT_TRUE(this->getConn().outstandings.packets.empty());

  // Verify loss state remains unchanged
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_EQ(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = ConstrainedAndTracked.
 * PacketContents = Datagram only.
 * WritableBytes = 1000.
 *
 * DATAGRAM-only packets SHOULD be inserted into outstandings, congestion
 * controller SHOULD be notified, and we SHOULD observe bytes written.
 *
 * lastRetransmittablePacketSentTime SHOULD NOT be updated.
 * maybeLastPacketSentTime SHOULD be updated.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    ConstrainedAndTracked_DatagramOnlyPacket_WritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::ConstrainedAndTracked;
  this->setWritableBytes(1000);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // On loop, congestion controller should be notified
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_))
      .Times(1)
      .WillOnce(Invoke([datagramWriteResult](const auto& pkt) {
        // Verify the packet has encoded size > the buffer
        EXPECT_GT(
            pkt.metadata.encodedSize, datagramWriteResult.bufWritten.size());

        // Verify the packet has an encoded body size >= the buffer
        EXPECT_GE(
            pkt.metadata.encodedBodySize,
            datagramWriteResult.bufWritten.size());
      }));

  // Loop, and inspect the write interval (based on outstandings)
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();
  EXPECT_NE(initialState, postLoopState);

  // Verify that packets and data was written
  EXPECT_GE(
      postLoopState.bytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size());
  EXPECT_GE(
      postLoopState.bodyBytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size());
  EXPECT_EQ(postLoopState.totalPacketsSent, initialState.totalPacketsSent + 1);

  // Verify one packet was added to outstandings
  EXPECT_THAT(this->getConn().outstandings.packets, SizeIs(1));

  // Verify loss state updates
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_NE(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = ConstrainedAndTracked.
 * PacketContents = Datagram only.
 * WritableBytes = 0.
 *
 * With no writable bytes, NO packets should be written.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    ConstrainedAndTracked_DatagramOnlyPacket_NoWritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::ConstrainedAndTracked;
  this->setWritableBytes(0);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // Loop, no packets should be written
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(0, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();

  // With no writable bytes, no packets should be sent
  EXPECT_EQ(initialState.bytesSent, postLoopState.bytesSent);
  EXPECT_EQ(initialState.bodyBytesSent, postLoopState.bodyBytesSent);
  EXPECT_EQ(initialState.totalPacketsSent, postLoopState.totalPacketsSent);

  // Verify no packets were added to outstandings
  EXPECT_TRUE(this->getConn().outstandings.packets.empty());

  // Verify loss state remains unchanged
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_EQ(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = Constrained.
 * PacketContents = Mixed (datagram frame + stream data).
 * WritableBytes = 1000.
 *
 * Mixed packets SHOULD ALWAYS be inserted into outstandings, congestion
 * controller SHOULD ALWAYS be notified, and we SHOULD observe bytes written.
 *
 * lastRetransmittablePacketSentTime SHOULD NOT be updated.
 * maybeLastPacketSentTime SHOULD be updated.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    Constrained_MixedPacket_WritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::Constrained;
  this->setWritableBytes(1000);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  const auto streamWriteResult = this->writeToNewStream();

  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // On loop, congestion controller should be notified
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_))
      .Times(1)
      .WillOnce(
          Invoke([datagramWriteResult, streamWriteResult](const auto& pkt) {
            // Verify the packet has encoded size > the buffer
            EXPECT_GT(
                pkt.metadata.encodedSize,
                datagramWriteResult.bufWritten.size() +
                    streamWriteResult.bufWritten.size());

            // Verify the packet has an encoded body size >= the buffer
            EXPECT_GE(
                pkt.metadata.encodedBodySize,
                datagramWriteResult.bufWritten.size() +
                    streamWriteResult.bufWritten.size());
          }));

  // Loop, and inspect the write interval (based on outstandings)
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();
  EXPECT_NE(initialState, postLoopState);

  // Verify that packets and data was written
  EXPECT_GE(
      postLoopState.bytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size() +
          streamWriteResult.bufWritten.size());
  EXPECT_GE(
      postLoopState.bodyBytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size() +
          streamWriteResult.bufWritten.size());
  EXPECT_EQ(postLoopState.totalPacketsSent, initialState.totalPacketsSent + 1);

  // Verify mixed packet in outstandings
  EXPECT_THAT(
      this->getConn().outstandings.packets,
      UnorderedElementsAre(Field(
          &OutstandingPacketWrapper::packet,
          Field(
              &RegularQuicWritePacket::frames,
              AllOf(Truly(hasStreamFrame), Truly(hasDatagramFrame))))));

  // Verify loss state updates
  EXPECT_NE(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_NE(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * Mode = Constrained.
 * PacketContents = Mixed (datagram frame + stream data).
 * WritableBytes = 0.
 *
 * With no writable bytes, NO packets should be written.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    Constrained_MixedPacket_NoWritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::Constrained;
  this->setWritableBytes(0);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  const auto streamWriteResult = this->writeToNewStream();

  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // Loop, no packets should be written
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(0, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();

  // With no writable bytes, no packets should be sent
  EXPECT_EQ(initialState.bytesSent, postLoopState.bytesSent);
  EXPECT_EQ(initialState.bodyBytesSent, postLoopState.bodyBytesSent);
  EXPECT_EQ(initialState.totalPacketsSent, postLoopState.totalPacketsSent);

  // Verify no packets were added to outstandings
  EXPECT_TRUE(this->getConn().outstandings.packets.empty());

  // Verify loss state remains unchanged
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_EQ(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * CongestionControlMode = ConstrainedAndTracked.
 * PacketContents = Mixed (datagram frame + stream data).
 * WritableBytes = 1000.
 *
 * Mixed packets SHOULD ALWAYS be inserted into outstandings, congestion
 * controller SHOULD ALWAYS be notified, and we SHOULD observe bytes written.
 *
 * lastRetransmittablePacketSentTime SHOULD be updated.
 * maybeLastPacketSentTime SHOULD be updated.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    ConstrainedAndTracked_MixedPacket_WritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::ConstrainedAndTracked;
  this->setWritableBytes(1000);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  const auto streamWriteResult = this->writeToNewStream();

  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // On loop, congestion controller should be notified
  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_))
      .Times(1)
      .WillOnce(
          Invoke([datagramWriteResult, streamWriteResult](const auto& pkt) {
            // Verify the packet has encoded size > the buffer
            EXPECT_GT(
                pkt.metadata.encodedSize,
                datagramWriteResult.bufWritten.size() +
                    streamWriteResult.bufWritten.size());

            // Verify the packet has an encoded body size >= the buffer
            EXPECT_GE(
                pkt.metadata.encodedBodySize,
                datagramWriteResult.bufWritten.size() +
                    streamWriteResult.bufWritten.size());
          }));

  // Loop, and inspect the write interval (based on outstandings)
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();
  EXPECT_NE(initialState, postLoopState);

  // Verify that packets and data was written
  EXPECT_GE(
      postLoopState.bytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size() +
          streamWriteResult.bufWritten.size());
  EXPECT_GE(
      postLoopState.bodyBytesSent,
      initialState.bodyBytesSent + datagramWriteResult.bufWritten.size() +
          streamWriteResult.bufWritten.size());
  EXPECT_EQ(postLoopState.totalPacketsSent, initialState.totalPacketsSent + 1);

  // Verify one packet was added to outstandings
  EXPECT_THAT(this->getConn().outstandings.packets, SizeIs(1));

  // Verify loss state updates
  EXPECT_NE(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_NE(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * Test handling of DATAGRAM frames.
 *
 * CongestionControlMode = ConstrainedAndTracked.
 * PacketContents = Mixed (datagram frame + stream data).
 * WritableBytes = 0.
 *
 * With no writable bytes, NO packets should be written.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    ConstrainedAndTracked_MixedPacket_NoWritableBytes) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::ConstrainedAndTracked;
  this->setWritableBytes(0);

  const auto initialState = this->buildState();
  const auto datagramWriteResult = this->writeDatagram();
  const auto streamWriteResult = this->writeToNewStream();

  EXPECT_CALL(*this->getMockCongestionController(), onPacketSent(_)).Times(0);

  // Loop, no packets should be written
  auto maybeWriteInterval = this->loopForWrites();
  EXPECT_EQ(0, this->getNumPacketsWritten(maybeWriteInterval));
  const auto postLoopState = this->buildState();

  // With no writable bytes, no packets should be sent
  EXPECT_EQ(initialState.bytesSent, postLoopState.bytesSent);
  EXPECT_EQ(initialState.bodyBytesSent, postLoopState.bodyBytesSent);
  EXPECT_EQ(initialState.totalPacketsSent, postLoopState.totalPacketsSent);

  // Verify no packets were added to outstandings
  EXPECT_TRUE(this->getConn().outstandings.packets.empty());

  // Verify loss state remains unchanged
  EXPECT_EQ(
      initialState.lastRetransmittablePacketSentTime,
      postLoopState.lastRetransmittablePacketSentTime);
  EXPECT_EQ(
      initialState.maybeLastPacketSentTime,
      postLoopState.maybeLastPacketSentTime);

  this->destroyTransport();
}

/**
 * End-to-end test for prioritized datagram flow APIs.
 *
 * Exercises the full public API path:
 *   createDatagramFlowId() -> writeDatagram(flowId, buf) ->
 *   setDatagramFlowPriority(flowId, priority)
 * and verifies that datagram frames are scheduled between a higher-priority
 * stream and a lower-priority stream when scheduleDatagramsWithStreams is
 * enabled.
 *
 * Expected priority order: highStream (urgency 1) > datagram flow (urgency 3)
 *                          > lowStream (urgency 5)
 * Expected frame order: WriteStreamFrame(highStream), DatagramFrame,
 *                       WriteStreamFrame(lowStream)
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagramWithStreams,
    DatagramFlowPriorityScheduledBetweenStreams) {
  this->getNonConstConn().transportSettings.datagramConfig.trackingMode =
      DatagramConfig::CongestionControlMode::ConstrainedAndTracked;
  this->setWritableBytes(2000);

  // Create a datagram flow via the public API
  auto maybeFlowId = this->getTransport()->createDatagramFlowId();
  ASSERT_TRUE(maybeFlowId.has_value());
  auto flowId = maybeFlowId.value();

  // Write a datagram to the flow (creates the flow entry in FlowManager)
  auto dgWriteResult = this->getTransport()->writeDatagram(
      flowId, folly::IOBuf::copyBuffer("DatagramPayload"));
  ASSERT_TRUE(dgWriteResult.has_value());

  // Set medium priority (urgency 3) on the datagram flow
  auto setPriResult = this->getTransport()->setDatagramFlowPriority(
      flowId, HTTPPriorityQueue::Priority(3, false));
  ASSERT_TRUE(setPriResult.has_value());

  // Create a high-priority stream (urgency 1)
  auto maybeHighStreamId = this->getTransport()->createBidirectionalStream();
  ASSERT_TRUE(maybeHighStreamId.has_value());
  auto highStreamId = maybeHighStreamId.value();
  this->getTransport()->setStreamPriority(
      highStreamId, HTTPPriorityQueue::Priority(1, false));
  auto highWriteResult = this->getTransport()->writeChain(
      highStreamId, IOBuf::copyBuffer("HighPriStream"), false);
  ASSERT_TRUE(highWriteResult.has_value());

  // Create a low-priority stream (urgency 5)
  auto maybeLowStreamId = this->getTransport()->createBidirectionalStream();
  ASSERT_TRUE(maybeLowStreamId.has_value());
  auto lowStreamId = maybeLowStreamId.value();
  this->getTransport()->setStreamPriority(
      lowStreamId, HTTPPriorityQueue::Priority(5, false));
  auto lowWriteResult = this->getTransport()->writeChain(
      lowStreamId, IOBuf::copyBuffer("LowPriStream"), false);
  ASSERT_TRUE(lowWriteResult.has_value());

  // Trigger the write loop
  this->loopForWrites();

  // Inspect frames across all sent packets and verify priority ordering:
  //   highStream (urgency 1) before datagram (urgency 3) before
  //   lowStream (urgency 5)
  enum class FrameType { HighStream, Datagram, LowStream };
  std::vector<FrameType> frameOrder;
  for (const auto& pkt : this->getConn().outstandings.packets) {
    for (const auto& frame : pkt.packet.frames) {
      if (auto* sf = frame.asWriteStreamFrame()) {
        if (sf->streamId == highStreamId) {
          frameOrder.push_back(FrameType::HighStream);
        } else if (sf->streamId == lowStreamId) {
          frameOrder.push_back(FrameType::LowStream);
        }
      } else if (frame.asDatagramFrame()) {
        frameOrder.push_back(FrameType::Datagram);
      }
    }
  }

  ASSERT_EQ(frameOrder.size(), 3);
  EXPECT_EQ(frameOrder[0], FrameType::HighStream);
  EXPECT_EQ(frameOrder[1], FrameType::Datagram);
  EXPECT_EQ(frameOrder[2], FrameType::LowStream);

  this->destroyTransport();
}

/**
 * Verify that setDatagramFlowPriority succeeds on a flow that has been
 * created via createDatagramFlowId() but has not yet had any datagrams
 * written to it.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    SetPriorityBeforeFirstWrite) {
  // Create a datagram flow
  auto maybeFlowId = this->getTransport()->createDatagramFlowId();
  ASSERT_TRUE(maybeFlowId.has_value());
  auto flowId = maybeFlowId.value();

  // Set priority BEFORE writing any datagrams — this should succeed
  auto setPriResult = this->getTransport()->setDatagramFlowPriority(
      flowId, HTTPPriorityQueue::Priority(3, false));
  ASSERT_TRUE(setPriResult.has_value());

  this->destroyTransport();
}

/**
 * Verify that writeDatagram rejects a flowId that was not created via
 * createDatagramFlowId().
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    WriteToUncreatedFlowReturnsError) {
  // Write to a flowId that was never created
  auto result = this->getTransport()->writeDatagram(
      12345, folly::IOBuf::copyBuffer("payload"));
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());

  this->destroyTransport();
}

/**
 * The default flow backs writeDatagram(BufPtr) and has no id for the caller to
 * discard, so closing it is refused. Erasing it would only invite the next
 * default-flow write to reopen it.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    CloseDefaultDatagramFlowReturnsError) {
  ASSERT_TRUE(this->getTransport()
                  ->writeDatagram(folly::IOBuf::copyBuffer("Default"))
                  .has_value());

  auto closeResult =
      this->getTransport()->closeDatagramFlow(kDefaultDatagramFlowId);
  ASSERT_TRUE(closeResult.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, closeResult.error());

  auto closeNowResult =
      this->getTransport()->closeDatagramFlowNow(kDefaultDatagramFlowId);
  ASSERT_TRUE(closeNowResult.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, closeNowResult.error());

  // The default flow is untouched, so the queued datagram still goes out.
  EXPECT_EQ(
      1, this->getNonConstConn().datagramState.flowManager.getDatagramCount());

  this->destroyTransport();
}

/**
 * With sendDropOldDataFirst, a write into a full buffer drops the oldest
 * queued datagram. When that datagram is the only one on an ephemeral flow,
 * the flow manager retires the flow -- so the flow id must come out of the
 * write queue too. Left behind, the scheduler picks it up and pops from a flow
 * that no longer exists.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagramWithStreams,
    DropOldestRetiresEphemeralFlowFromWriteQueue) {
  auto& conn = this->getNonConstConn();
  conn.transportSettings.datagramConfig.sendDropOldDataFirst = true;
  conn.datagramState.maxWriteBufferSize = 1;

  // Ephemeral flow, urgency 1: one datagram, and the flow goes away with it.
  ASSERT_TRUE(this->getTransport()
                  ->writeDatagram(
                      HTTPPriorityQueue::Priority(1, false),
                      folly::IOBuf::copyBuffer("Ephemeral"))
                  .has_value());
  ASSERT_EQ(1, conn.datagramState.flowManager.getFlowCount());

  // The buffer is full, so this write drops the ephemeral datagram, which
  // empties and retires the ephemeral flow.
  ASSERT_TRUE(this->getTransport()
                  ->writeDatagram(folly::IOBuf::copyBuffer("Default"))
                  .has_value());
  ASSERT_TRUE(
      this->getTransport()
          ->setDatagramFlowPriority(
              kDefaultDatagramFlowId, HTTPPriorityQueue::Priority(3, false))
          .has_value());

  ASSERT_EQ(1, conn.datagramState.flowManager.getDatagramCount());
  ASSERT_TRUE(conn.datagramState.flowManager.hasDatagramsForFlow(
      kDefaultDatagramFlowId));
  // The ephemeral flow is gone; only the default flow is left.
  EXPECT_EQ(1, conn.datagramState.flowManager.getFlowCount());

  // The default flow is the only writable one, so it has to be what the
  // scheduler sees next. The retired ephemeral flow outranks it (urgency 1 vs
  // 3), so a leftover queue entry surfaces here.
  const auto nextId = conn.streamManager->writeQueue().peekNextScheduledID();
  ASSERT_TRUE(nextId.isDatagramFlowID());
  EXPECT_EQ(kDefaultDatagramFlowId, nextId.asDatagramFlowID())
      << "write queue still schedules the retired ephemeral flow";

  // A stale entry makes this pop from a flow that is not in the write buffer.
  this->loopForWrites();

  EXPECT_EQ(0, conn.datagramState.flowManager.getDatagramCount());
  EXPECT_TRUE(conn.streamManager->writeQueue().empty());

  this->destroyTransport();
}

/**
 * A gracefully closed flow stays in the write buffer while it drains, so a
 * write to it has to be refused up front. Left to addDatagram, a full buffer
 * would first drop another flow's datagram to make room for a write that then
 * fails anyway.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    WriteToDrainingFlowDropsNothing) {
  auto& conn = this->getNonConstConn();
  conn.transportSettings.datagramConfig.sendDropOldDataFirst = true;
  conn.datagramState.maxWriteBufferSize = 2;

  auto flowId = this->getTransport()->createDatagramFlowId();
  ASSERT_TRUE(flowId.has_value());
  ASSERT_TRUE(this->getTransport()
                  ->writeDatagram(*flowId, folly::IOBuf::copyBuffer("Draining"))
                  .has_value());
  ASSERT_TRUE(this->getTransport()
                  ->writeDatagram(folly::IOBuf::copyBuffer("Default"))
                  .has_value());
  ASSERT_TRUE(this->getTransport()->closeDatagramFlow(*flowId).has_value());
  ASSERT_EQ(2, conn.datagramState.flowManager.getDatagramCount());

  auto result = this->getTransport()->writeDatagram(
      *flowId, folly::IOBuf::copyBuffer("Rejected"));
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
  // Both queued datagrams survive the rejected write.
  EXPECT_EQ(2, conn.datagramState.flowManager.getDatagramCount());

  this->destroyTransport();
}

/**
 * A zero-sized write buffer is full with nothing in it, so the drop-oldest
 * path has no victim to find.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTestDatagram,
    WriteWithZeroSizedBufferFails) {
  auto& conn = this->getNonConstConn();
  conn.transportSettings.datagramConfig.sendDropOldDataFirst = true;
  conn.datagramState.maxWriteBufferSize = 0;

  auto result =
      this->getTransport()->writeDatagram(folly::IOBuf::copyBuffer("Nowhere"));
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_WRITE_DATA, result.error());
  EXPECT_EQ(0, conn.datagramState.flowManager.getDatagramCount());

  this->destroyTransport();
}

TYPED_TEST_SUITE(
    QuicTypedTransportSconeTest,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportSconeTest, TestSconeFlag) {
  EXPECT_TRUE(this->getNonConstConn().transportSettings.advertiseSconeSupport);
  EXPECT_TRUE(this->getNonConstConn().transportSettings.enableSconeSend);
}

namespace {

// Whether frames include STOP_SENDING for streamId.
bool hasStopSending(
    const std::vector<QuicWriteFrame>& frames,
    StreamId streamId) {
  return std::ranges::any_of(frames, [&](const auto& frame) {
    const auto* simpleFrame = frame.asQuicSimpleFrame();
    const auto* stopSending =
        simpleFrame ? simpleFrame->asStopSendingFrame() : nullptr;
    return stopSending && stopSending->streamId == streamId;
  });
}

// The frame among frames that carries streamId's data from offset, if any.
const WriteStreamFrame* findStreamFrame(
    const std::vector<QuicWriteFrame>& frames,
    StreamId streamId,
    uint64_t offset) {
  for (const auto& frame : frames) {
    const auto* streamFrame = frame.asWriteStreamFrame();
    if (streamFrame && streamFrame->streamId == streamId &&
        streamFrame->offset == offset) {
      return streamFrame;
    }
  }
  return nullptr;
}

// Reads everything streamId has buffered.
std::string readAll(QuicTransportBase& transport, StreamId streamId) {
  auto result = transport.read(streamId, 0);
  if (result.hasError() || !result->first) {
    return "";
  }
  return result->first->moveToFbString().toStdString();
}

} // namespace

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressDropsUnreadPeerData) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("unread")));

  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto written = this->loopForWrites();

  ASSERT_TRUE(written.has_value());
  EXPECT_TRUE(hasStopSending(this->getFramesInWrites(*written), streamId));
  StrictMock<MockReadCallback> readCb;
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  ASSERT_FALSE(transport->setReadCallback(streamId, &readCb).hasError());
  this->deliverPacket(this->buildPeerPacketWithStreamDataAt(
      streamId, IOBuf::copyBuffer(" more"), 6 /* offset */, false /* eof */));
  ASSERT_FALSE(transport->setReadCallback(streamId, nullptr).hasError());
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressForAllStreamsRetiresAPeerStreamOpenedLater) {
  auto transport = this->getTransport();
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());

  // The peer opens a stream only after the call, and the application reads it.
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  StrictMock<MockReadCallback> readCb;
  EXPECT_CALL(this->getConnCallback(), onNewUnidirectionalStream(streamId))
      .WillOnce([&](StreamId id) {
        EXPECT_FALSE(transport->setReadCallback(id, &readCb).hasError());
      });
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  // The STOP_SENDING goes out with the transport's response to the packet.
  const auto written = this->writesDuring([&] {
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("late")));
  });

  ASSERT_TRUE(written.has_value());
  EXPECT_TRUE(hasStopSending(this->getFramesInWrites(*written), streamId));
  ASSERT_FALSE(transport->setReadCallback(streamId, nullptr).hasError());
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressForAllStreamsRetiresAStreamWhoseCallbackIsPending) {
  auto transport = this->getTransport();
  const auto firstStreamId = this->getNextPeerUnidirectionalStreamId();
  const auto secondStreamId = firstStreamId + detail::kStreamIncrement;

  // Both streams arrive in one read, so the application handles the first
  // stream while the second stream's new-stream callback is still pending.
  StrictMock<MockReadCallback> readCb;
  EXPECT_CALL(this->getConnCallback(), onNewUnidirectionalStream(firstStreamId))
      .WillOnce([&](StreamId) {
        EXPECT_FALSE(transport
                         ->stopSendingAndDropIngressForAllStreams(
                             GenericApplicationErrorCode::NO_ERROR)
                         .hasError());
      });
  EXPECT_CALL(
      this->getConnCallback(), onNewUnidirectionalStream(secondStreamId))
      .WillOnce([&](StreamId id) {
        EXPECT_FALSE(transport->setReadCallback(id, &readCb).hasError());
      });
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  std::vector<BufPtr> packets;
  packets.push_back(this->buildPeerPacketWithStreamData(
      firstStreamId, IOBuf::copyBuffer("first")));
  packets.push_back(this->buildPeerPacketWithStreamData(
      secondStreamId, IOBuf::copyBuffer("second")));
  const auto written =
      this->writesDuring([&] { this->deliverPackets(std::move(packets)); });

  ASSERT_TRUE(written.has_value());
  const auto frames = this->getFramesInWrites(*written);
  for (const auto streamId : {firstStreamId, secondStreamId}) {
    EXPECT_TRUE(hasStopSending(frames, streamId));
  }
  ASSERT_FALSE(transport->setReadCallback(secondStreamId, nullptr).hasError());
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressRetiresAnOpenPeerStreamWithoutState) {
  auto transport = this->getTransport();
  const auto firstStreamId = this->getNextPeerUnidirectionalStreamId();
  const auto secondStreamId = firstStreamId + detail::kStreamIncrement;
  // Data on the peer's second stream opens its first stream too, without
  // creating state for it.
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      secondStreamId, IOBuf::copyBuffer("second")));

  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       firstStreamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto written = this->loopForWrites();

  ASSERT_TRUE(written.has_value());
  EXPECT_TRUE(hasStopSending(this->getFramesInWrites(*written), firstStreamId));
  StrictMock<MockReadCallback> readCb;
  EXPECT_CALL(readCb, readAvailable(_)).Times(0);
  ASSERT_FALSE(transport->setReadCallback(firstStreamId, &readCb).hasError());
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      firstStreamId, IOBuf::copyBuffer("first")));
  ASSERT_FALSE(transport->setReadCallback(firstStreamId, nullptr).hasError());
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressForAllStreamsRetiresAnOpenPeerStreamWithoutState) {
  auto transport = this->getTransport();
  const auto firstStreamId = this->getNextPeerUnidirectionalStreamId();
  const auto secondStreamId = firstStreamId + detail::kStreamIncrement;
  // Data on the peer's second stream opens its first stream too, without
  // creating state for it.
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      secondStreamId, IOBuf::copyBuffer("second")));

  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto written = this->loopForWrites();

  ASSERT_TRUE(written.has_value());
  const auto frames = this->getFramesInWrites(*written);
  for (const auto streamId : {firstStreamId, secondStreamId}) {
    EXPECT_TRUE(hasStopSending(frames, streamId));
  }
  this->destroyTransport();
}

// Stopping one stream leaves the peer's other streams, open or opened later,
// delivering as before.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressLeavesOtherStreamsAlone) {
  auto transport = this->getTransport();
  const auto stoppedStreamId = this->getNextPeerUnidirectionalStreamId();
  const auto otherStreamId = stoppedStreamId + detail::kStreamIncrement;
  const auto laterStreamId = otherStreamId + detail::kStreamIncrement;
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      stoppedStreamId, IOBuf::copyBuffer("stopped")));
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      otherStreamId, IOBuf::copyBuffer("other")));

  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       stoppedStreamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto written = this->loopForWrites();

  ASSERT_TRUE(written.has_value());
  const auto frames = this->getFramesInWrites(*written);
  EXPECT_TRUE(hasStopSending(frames, stoppedStreamId));
  EXPECT_FALSE(hasStopSending(frames, otherStreamId));
  // The other stream still delivers what it has and what arrives next.
  this->deliverPacket(this->buildPeerPacketWithStreamDataAt(
      otherStreamId,
      IOBuf::copyBuffer(" more"),
      5 /* offset */,
      false /* eof */));
  EXPECT_EQ(readAll(*transport, otherStreamId), "other more");
  // So does a stream the peer opens later, and neither gets a STOP_SENDING.
  EXPECT_CALL(
      this->getConnCallback(), onNewUnidirectionalStream(laterStreamId));
  const auto laterWritten = this->writesDuring([&] {
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        laterStreamId, IOBuf::copyBuffer("later")));
  });
  EXPECT_EQ(readAll(*transport, laterStreamId), "later");
  if (laterWritten.has_value()) {
    const auto laterFrames = this->getFramesInWrites(*laterWritten);
    EXPECT_FALSE(hasStopSending(laterFrames, otherStreamId));
    EXPECT_FALSE(hasStopSending(laterFrames, laterStreamId));
  }
  this->destroyTransport();
}

// Data the peer sends only after the call is discarded too, and the end of
// the stream reaches nobody.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressDropsPeerDataThatArrivesAfterTheCall) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  // The application has read everything the peer sent so far.
  this->deliverPacket(
      this->buildPeerPacketWithStreamData(streamId, IOBuf::copyBuffer("read")));
  ASSERT_EQ(readAll(*transport, streamId), "read");

  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto written = this->loopForWrites();

  ASSERT_TRUE(written.has_value());
  EXPECT_TRUE(hasStopSending(this->getFramesInWrites(*written), streamId));
  // A strict mock with no expectations: no data, EOF or error may arrive.
  StrictMock<MockReadCallback> readCb;
  ASSERT_FALSE(transport->setReadCallback(streamId, &readCb).hasError());
  this->deliverPacket(this->buildPeerPacketWithStreamDataAt(
      streamId, IOBuf::copyBuffer("late"), 4 /* offset */, true /* eof */));
  this->loopForWrites();
  ASSERT_FALSE(transport->setReadCallback(streamId, nullptr).hasError());
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressRejectsAStreamThatCannotReceive) {
  auto transport = this->getTransport();
  const auto localStreamId = transport->createUnidirectionalStream().value();

  const auto result = transport->stopSendingAndDropIngress(
      localStreamId, GenericApplicationErrorCode::NO_ERROR);

  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error(), LocalErrorCode::INVALID_OPERATION);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressRejectsAStreamThePeerHasNotOpened) {
  auto transport = this->getTransport();

  const auto result = transport->stopSendingAndDropIngress(
      this->getNextPeerUnidirectionalStreamId(),
      GenericApplicationErrorCode::NO_ERROR);

  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_NOT_EXISTS);
  this->destroyTransport();
}

// Once the peer has finished a stream and the application has read all of it,
// the stream is gone.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressRejectsAStreamThatHasEnded) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  // The application reads the whole stream, through its end.
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(this->getConnCallback(), onNewUnidirectionalStream(streamId))
      .WillOnce([&](StreamId id) {
        EXPECT_FALSE(transport->setReadCallback(id, &readCb).hasError());
      });
  std::string received;
  bool endReceived = false;
  EXPECT_CALL(readCb, readAvailable(streamId)).WillRepeatedly([&](auto id) {
    auto result = transport->read(id, 0);
    ASSERT_FALSE(result.hasError());
    if (result->first) {
      received += result->first->moveToFbString().toStdString();
    }
    endReceived = endReceived || result->second;
  });
  // Once its end is delivered, the finished stream is reaped.
  EXPECT_CALL(this->getConnCallback(), onStreamPreReaped(streamId));
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("done")));
  ASSERT_TRUE(endReceived);
  EXPECT_EQ(received, "done");

  const auto result = transport->stopSendingAndDropIngress(
      streamId, GenericApplicationErrorCode::NO_ERROR);

  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_NOT_EXISTS);
  this->destroyTransport();
}

// A stream the peer has reset still exists while the reset is being reported,
// and the call then succeeds without a STOP_SENDING, since nothing more can
// arrive.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressAfterThePeerResetTheStreamSendsNoStopSending) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(this->getConnCallback(), onNewUnidirectionalStream(streamId))
      .WillOnce([&](StreamId id) {
        EXPECT_FALSE(transport->setReadCallback(id, &readCb).hasError());
      });
  this->deliverPacket(
      this->buildPeerPacketWithStreamData(streamId, IOBuf::copyBuffer("data")));
  Optional<quic::Expected<void, LocalErrorCode>> stopResult;
  EXPECT_CALL(readCb, readError(streamId, _)).WillOnce([&](auto, const auto&) {
    stopResult = transport->stopSendingAndDropIngress(
        streamId, GenericApplicationErrorCode::NO_ERROR);
  });

  const auto written = this->writesDuring([&] {
    this->deliverPacket(
        this->buildPeerPacketWithRstStreamFrame(streamId, 4 /* offset */));
  });

  ASSERT_TRUE(stopResult.has_value());
  EXPECT_FALSE(stopResult->hasError());
  if (written.has_value()) {
    EXPECT_FALSE(hasStopSending(this->getFramesInWrites(*written), streamId));
  }
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressTwiceSendsOneStopSending) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  this->deliverPacket(
      this->buildPeerPacketWithStreamData(streamId, IOBuf::copyBuffer("data")));
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto firstWrite = this->loopForWrites();
  ASSERT_TRUE(firstWrite.has_value());
  ASSERT_TRUE(hasStopSending(this->getFramesInWrites(*firstWrite), streamId));

  EXPECT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto secondWrite = this->loopForWrites();

  if (secondWrite.has_value()) {
    EXPECT_FALSE(
        hasStopSending(this->getFramesInWrites(*secondWrite), streamId));
  }
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StopSendingAndDropIngressFailsOnceTheConnectionIsClosing) {
  auto transport = this->getTransport();
  const auto streamId = this->getNextPeerUnidirectionalStreamId();
  this->deliverPacket(
      this->buildPeerPacketWithStreamData(streamId, IOBuf::copyBuffer("data")));
  // The peer's stream holds the graceful close open.
  transport->closeGracefully();

  const auto oneStream = transport->stopSendingAndDropIngress(
      streamId, GenericApplicationErrorCode::NO_ERROR);
  const auto allStreams = transport->stopSendingAndDropIngressForAllStreams(
      GenericApplicationErrorCode::NO_ERROR);

  ASSERT_TRUE(oneStream.hasError());
  EXPECT_EQ(oneStream.error(), LocalErrorCode::CONNECTION_CLOSED);
  ASSERT_TRUE(allStreams.hasError());
  EXPECT_EQ(allStreams.error(), LocalErrorCode::CONNECTION_CLOSED);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseIsNotHeldOpenByAPeerStreamOpenedAfterTheDiscard) {
  auto transport = this->getTransport();
  // Unacknowledged data on a local stream keeps the graceful close pending.
  const auto localStreamId = transport->createUnidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(localStreamId, IOBuf::copyBuffer("bye"), true /* eof */)
          .hasError());
  this->loopForWrites();
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();

  // The peer opens a stream while the close is pending.
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      this->getNextPeerUnidirectionalStreamId(), IOBuf::copyBuffer("late")));
  Mock::VerifyAndClearExpectations(observer.get());

  // Once the local stream is acknowledged, nothing holds the close open, and
  // the transport starts closing the connection.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  const auto* oldest =
      this->getOldestOutstandingPacket(PacketNumberSpace::AppData);
  const auto* newest =
      this->getNewestOutstandingPacket(PacketNumberSpace::AppData);
  ASSERT_NE(oldest, nullptr);
  ASSERT_NE(newest, nullptr);
  // The ACK finishes the close, which deliverPacket() would report as an
  // error.
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentPackets(
              PacketNumberSpace::AppData,
              oldest->packet.header.getPacketSequenceNum(),
              newest->packet.header.getPacketSequenceNum()),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// On a stream whose receive side is retired, a graceful close waits until the
// peer has acknowledged every byte of the send side through the FIN. It waits
// neither for the peer's side of the stream nor for the peer to acknowledge
// the STOP_SENDING.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressWaitsForThePeerToAckOurFin) {
  auto transport = this->getTransport();
  const auto streamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(streamId, IOBuf::copyBuffer("first"), false /* eof */)
          .hasError());
  const auto dataWrite = this->loopForWrites();
  ASSERT_TRUE(dataWrite.has_value());
  ASSERT_FALSE(
      transport->writeChain(streamId, IOBuf::copyBuffer("last"), true /* eof */)
          .hasError());
  const auto finWrite = this->loopForWrites();
  ASSERT_TRUE(finWrite.has_value());
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  const auto stopSendingWrite = this->loopForWrites();
  ASSERT_TRUE(stopSendingWrite.has_value());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();

  // The data before the FIN is acknowledged, but the FIN is not.
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(dataWrite));
  Mock::VerifyAndClearExpectations(observer.get());

  // Acknowledging the FIN finishes the close, which deliverPacket() would
  // report as an error. The STOP_SENDING is still unacknowledged.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentAppDataPackets(finWrite),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// If the peer never acknowledges the FIN, the close does not wait forever: the
// idle timeout ends the connection.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressEndsOnIdleTimeout) {
  auto transport = this->getTransport();
  const auto streamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport->writeChain(streamId, IOBuf::copyBuffer("bye"), true /* eof */)
          .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, closeStarted(transport, _));
  this->fireIdleTimeout();
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// While the FIN goes unacknowledged, each probe timeout retransmits it, until
// the transport gives up after the maximum number of probe timeouts.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressGivesUpAfterTheMaximumProbeTimeouts) {
  auto transport = this->getTransport();
  const auto streamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport->writeChain(streamId, IOBuf::copyBuffer("bye"), true /* eof */)
          .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  bool closed = false;
  EXPECT_CALL(*observer, closeStarted(transport, _))
      .WillOnce([&](auto, const auto&) { closed = true; });
  transport->closeGracefully();
  ASSERT_FALSE(closed);

  size_t finRetransmissions = 0;
  for (size_t timeouts = 0; timeouts <= kDefaultMaxNumPTO && !closed;
       ++timeouts) {
    const auto probe = this->fireLossTimeout();
    if (probe.has_value()) {
      const auto frames = this->getFramesInWrites(*probe);
      const auto* fin = findStreamFrame(frames, streamId, 0);
      finRetransmissions += fin && fin->fin ? 1 : 0;
    }
  }

  EXPECT_TRUE(closed);
  EXPECT_GT(finRetransmissions, 0);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// Loss recovery keeps running while a graceful close is pending: when the
// packet carrying the FIN is lost, the FIN is retransmitted, and the close
// finishes once the peer acknowledges the retransmission.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressRetransmitsALostFin) {
  auto transport = this->getTransport();
  // A bidirectional stream, so the close depends on its retired receive side
  // and its send side rather than on the stream being gone.
  const auto byeStreamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(byeStreamId, IOBuf::copyBuffer("bye"), true /* eof */)
          .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());
  // Three more packets, so acknowledging them declares the FIN's packet lost.
  const auto otherStreamId = transport->createUnidirectionalStream().value();
  std::vector<typename TestFixture::NewOutstandingPacketInterval> laterWrites;
  for (const bool eof : {false, false, true}) {
    ASSERT_FALSE(
        transport->writeChain(otherStreamId, IOBuf::copyBuffer("later"), eof)
            .hasError());
    const auto write = this->loopForWrites();
    ASSERT_TRUE(write.has_value());
    laterWrites.push_back(*write);
  }
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();

  // The later packets are acknowledged, the FIN's packet is declared lost, and
  // the FIN is retransmitted.
  const auto firstRetransmission =
      getNextPacketNum(this->getConn(), PacketNumberSpace::AppData);
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(laterWrites));
  const auto nextPacket =
      getNextPacketNum(this->getConn(), PacketNumberSpace::AppData);
  ASSERT_GT(nextPacket, firstRetransmission);
  Mock::VerifyAndClearExpectations(observer.get());

  // Acknowledging the retransmission finishes the close, which deliverPacket()
  // would report as an error.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentPackets(
              PacketNumberSpace::AppData, firstRetransmission, nextPacket - 1),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// A lost packet with data before the FIN is retransmitted too, and the close
// waits until the retransmission is acknowledged.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressRetransmitsLostData) {
  auto transport = this->getTransport();
  const auto byeStreamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(byeStreamId, IOBuf::copyBuffer("data"), false /* eof */)
          .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());
  ASSERT_FALSE(
      transport->writeChain(byeStreamId, nullptr, true /* eof */).hasError());
  const auto finWrite = this->loopForWrites();
  ASSERT_TRUE(finWrite.has_value());
  // Three more packets, so acknowledging them declares the data's packet lost.
  const auto otherStreamId = transport->createUnidirectionalStream().value();
  std::vector<typename TestFixture::NewOutstandingPacketInterval> acknowledged{
      *finWrite};
  for (const bool eof : {false, false, true}) {
    ASSERT_FALSE(
        transport->writeChain(otherStreamId, IOBuf::copyBuffer("later"), eof)
            .hasError());
    const auto write = this->loopForWrites();
    ASSERT_TRUE(write.has_value());
    acknowledged.push_back(*write);
  }
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngressForAllStreams(
                       GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();

  // Everything but the data's packet is acknowledged, so the data is declared
  // lost and retransmitted.
  const auto retransmission = this->writesDuring([&] {
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(acknowledged));
  });
  ASSERT_TRUE(retransmission.has_value());
  const auto retransmittedFrames = this->getFramesInWrites(*retransmission);
  const auto* retransmitted =
      findStreamFrame(retransmittedFrames, byeStreamId, 0);
  ASSERT_NE(retransmitted, nullptr);
  EXPECT_EQ(retransmitted->len, 4);
  EXPECT_FALSE(retransmitted->fin);
  Mock::VerifyAndClearExpectations(observer.get());

  // Acknowledging the retransmission finishes the close, which deliverPacket()
  // would report as an error.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentAppDataPackets(retransmission),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// A RESET_STREAM abandons the data the peer has not acknowledged, so once the
// application resets the send side of a stream whose receive side is retired,
// a graceful close waits only for the peer to acknowledge the reset.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressWaitsForThePeerToAckOurReset) {
  auto transport = this->getTransport();
  const auto streamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(
              streamId, IOBuf::copyBuffer("abandoned"), false /* eof */)
          .hasError());
  ASSERT_TRUE(this->loopForWrites().has_value());
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  ASSERT_FALSE(
      transport->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  const auto resetWrite = this->loopForWrites();
  ASSERT_TRUE(resetWrite.has_value());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();
  Mock::VerifyAndClearExpectations(observer.get());

  // Acknowledging the reset finishes the close, which deliverPacket() would
  // report as an error. The data it abandoned is never acknowledged.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentAppDataPackets(resetWrite),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

// A reliable reset abandons only the data after its reliable size, so a
// graceful close also waits for the peer to acknowledge the data before it.
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    GracefulCloseWithRetiredIngressWaitsForTheReliablePrefixOfAReliableReset) {
  auto transport = this->getTransport();
  // Both endpoints advertised support for reliable resets.
  this->getNonConstConn()
      .transportSettings.advertisedReliableResetStreamSupport = true;
  this->getNonConstConn().peerAdvertisedReliableStreamResetSupport = true;
  const auto streamId = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport
          ->writeChain(streamId, IOBuf::copyBuffer("reliable"), false /* eof */)
          .hasError());
  ASSERT_FALSE(
      transport->updateReliableDeliveryCheckpoint(streamId).hasError());
  const auto reliableWrite = this->loopForWrites();
  ASSERT_TRUE(reliableWrite.has_value());
  ASSERT_FALSE(transport
                   ->stopSendingAndDropIngress(
                       streamId, GenericApplicationErrorCode::NO_ERROR)
                   .hasError());
  ASSERT_FALSE(
      transport
          ->resetStreamReliably(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  const auto resetWrite = this->loopForWrites();
  ASSERT_TRUE(resetWrite.has_value());
  auto observer = std::make_unique<NiceMock<MockObserver>>();
  transport->addObserver(observer.get());
  EXPECT_CALL(*observer, closeStarted(transport, _)).Times(0);
  transport->closeGracefully();

  // The reset is acknowledged, but the reliable prefix is not.
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(resetWrite));
  Mock::VerifyAndClearExpectations(observer.get());

  // Acknowledging the reliable prefix finishes the close, which deliverPacket()
  // would report as an error. The ACK covers every packet sent since the
  // prefix, in case the prefix was declared lost and retransmitted.
  EXPECT_CALL(*observer, closeStarted(transport, _));
  const auto* newest =
      this->getNewestOutstandingPacket(PacketNumberSpace::AppData);
  ASSERT_NE(newest, nullptr);
  this->deliverDataWithoutErrorCheck(
      NetworkData(
          this->buildAckPacketForSentPackets(
              PacketNumberSpace::AppData,
              reliableWrite->start,
              newest->packet.header.getPacketSequenceNum()),
          TimePoint::clock::now(),
          0 /* tosValue */),
      false /* writes */);
  Mock::VerifyAndClearExpectations(observer.get());
  this->destroyTransport();
}

/**
 * The cases the connection-end tests run, shared by the client and server
 * fixtures below.
 */
class ConnectionEndTestCases {
 public:
  // How a test starts closing the connection.
  enum class CloseStart : uint8_t {
    CloseWithoutError,
    CloseWithError,
    CloseGracefully,
    CloseGracefullyThenIdleTimeout,
    CloseNow,
    PeerConnectionClose,
    DestroyTransport,
  };

  struct Case {
    CloseStart closeStart;
    bool reportLocalClose;
    bool useConnectionEndWithErrorCallback;
  };

  static std::vector<Case> allCases() {
    std::vector<Case> cases;
    for (const auto closeStart :
         {CloseStart::CloseWithoutError,
          CloseStart::CloseWithError,
          CloseStart::CloseGracefully,
          CloseStart::CloseGracefullyThenIdleTimeout,
          CloseStart::CloseNow,
          CloseStart::PeerConnectionClose,
          CloseStart::DestroyTransport}) {
      for (const bool reportLocalClose : {false, true}) {
        for (const bool useConnectionEndWithErrorCallback : {false, true}) {
          cases.push_back(
              {.closeStart = closeStart,
               .reportLocalClose = reportLocalClose,
               .useConnectionEndWithErrorCallback =
                   useConnectionEndWithErrorCallback});
        }
      }
    }
    return cases;
  }

  static std::string caseName(const testing::TestParamInfo<Case>& info) {
    static constexpr std::array<std::string_view, 7> kCloseStartNames{
        "CloseWithoutError",
        "CloseWithError",
        "CloseGracefully",
        "CloseGracefullyThenIdleTimeout",
        "CloseNow",
        "PeerConnectionClose",
        "DestroyTransport"};
    std::string name{
        kCloseStartNames.at(static_cast<size_t>(info.param.closeStart))};
    name +=
        info.param.reportLocalClose ? "_ReportLocalClose" : "_DefaultOptions";
    name += info.param.useConnectionEndWithErrorCallback ? "_EndWithError"
                                                         : "_EndOrError";
    return name;
  }

 protected:
  // How the transport reports the end of the connection: the error code, and
  // whether it goes to onConnectionError() rather than onConnectionEnd() when
  // useConnectionEndWithErrorCallback is off.
  struct ExpectedEnd {
    QuicErrorCode code;
    bool reportedAsError;
  };

  static inline const QuicErrorCode kPeerCloseErrorCode{
      static_cast<ApplicationErrorCode>(17)};

  static Optional<ExpectedEnd> expectedEndFor(const Case& testCase) {
    // The application never dropped the callbacks on these paths.
    if (testCase.closeStart == CloseStart::CloseNow) {
      return ExpectedEnd{
          .code = QuicErrorCode(GenericApplicationErrorCode::NO_ERROR),
          .reportedAsError = false};
    }
    if (testCase.closeStart == CloseStart::PeerConnectionClose) {
      return ExpectedEnd{.code = kPeerCloseErrorCode, .reportedAsError = true};
    }
    if (!testCase.reportLocalClose) {
      return std::nullopt;
    }
    switch (testCase.closeStart) {
      case CloseStart::CloseWithoutError:
        return ExpectedEnd{
            .code = QuicErrorCode(GenericApplicationErrorCode::NO_ERROR),
            .reportedAsError = false};
      case CloseStart::CloseWithError:
        return ExpectedEnd{
            .code = QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
            .reportedAsError = true};
      case CloseStart::CloseGracefully:
        return ExpectedEnd{
            .code = QuicErrorCode(LocalErrorCode::NO_ERROR),
            .reportedAsError = false};
      case CloseStart::CloseGracefullyThenIdleTimeout:
        return ExpectedEnd{
            .code = QuicErrorCode(LocalErrorCode::IDLE_TIMEOUT),
            .reportedAsError = false};
      case CloseStart::DestroyTransport:
        return ExpectedEnd{
            .code = QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
            .reportedAsError = false};
      case CloseStart::CloseNow:
      case CloseStart::PeerConnectionClose:
        break;
    }
    return std::nullopt;
  }

  class MockConnectionEndCallback : public MockConnectionCallback {
   public:
    using MockConnectionCallback::onConnectionEnd;

    void onConnectionEnd(QuicError error) noexcept override {
      onConnectionEndWithError(std::move(error));
    }

    MOCK_METHOD((void), onConnectionEndWithError, (QuicError), (noexcept));
  };
};

/**
 * gtest cannot combine typed and value-parameterized tests, so the same
 * value-parameterized fixture is instantiated once per transport type below.
 */
template <typename T>
class QuicTypedTransportConnectionEndTest
    : public QuicTypedTransportTest<T>,
      public ConnectionEndTestCases,
      public testing::WithParamInterface<ConnectionEndTestCases::Case> {
 public:
  bool getUseConnectionEndWithErrorCallback() override {
    return GetParam().useConnectionEndWithErrorCallback;
  }

 protected:
  void runConnectionEndTest();

 private:
  // Unlike deliverPacket(), touches nothing on the transport afterwards, which
  // the connection-end callback may have released.
  void deliverPacketWithoutErrorCheck(BufPtr buf) {
    this->deliverDataWithoutErrorCheck(
        NetworkData(std::move(buf), Clock::now(), 0), false /* writes */);
  }
};

template <typename T>
void QuicTypedTransportConnectionEndTest<T>::runConnectionEndTest() {
  const auto& param = GetParam();
  const auto expectedEnd = expectedEndFor(param);
  auto* transport = this->getTransport();
  this->startTransport();
  const std::weak_ptr<void> weakTransport = this->getTestTransport();

  // The transport is the only owner of these callbacks.
  auto ownedSetupCallback =
      std::make_shared<NiceMock<MockConnectionSetupCallback>>();
  auto ownedConnCallback =
      std::make_shared<NiceMock<MockConnectionEndCallback>>();
  const std::weak_ptr<MockConnectionSetupCallback> setupCallback =
      ownedSetupCallback;
  const std::weak_ptr<MockConnectionEndCallback> connCallback =
      ownedConnCallback;
  transport->setConnectionSetupCallback(ownedSetupCallback);
  transport->setConnectionCallback(
      ownedConnCallback, {.reportLocalClose = param.reportLocalClose});

  const auto streamId = this->createBidirectionalStream();
  StrictMock<MockReadCallback> readCallback;
  ASSERT_FALSE(transport->setReadCallback(streamId, &readCallback).hasError());
  const auto& readCallbacks = this->getTestTransport()->getReadCallbacks();

  bool readErrorReported = false;
  int connectionEndReports = 0;
  EXPECT_CALL(readCallback, readError(streamId, _))
      .WillOnce([&](auto, const auto& /* error */) {
        EXPECT_TRUE(readCallbacks.contains(streamId));
        EXPECT_EQ(connectionEndReports, 0);
        readErrorReported = true;
      });

  const bool destroying = param.closeStart == CloseStart::DestroyTransport;
  const auto onConnectionEnd =
      [&, transport, destroying](const Optional<QuicError>& error) {
        ++connectionEndReports;
        EXPECT_TRUE(readErrorReported);
        EXPECT_TRUE(readCallbacks.empty());
        EXPECT_FALSE(connCallback.expired());
        if (error) {
          EXPECT_EQ(error->code, expectedEnd->code);
        }
        // Closing again from the report does nothing, so the managed callback
        // stays installed until the transport clears it after the report.
        transport->close(std::nullopt);
        transport->closeNow(std::nullopt);
        transport->closeGracefully();
        EXPECT_FALSE(connCallback.expired());
        if (!destroying) {
          // Release the last reference to the transport from inside its report.
          this->destroyTransport();
        }
      };
  const bool withError = param.useConnectionEndWithErrorCallback;
  const bool reportedAsError = expectedEnd && expectedEnd->reportedAsError;
  EXPECT_CALL(*ownedConnCallback, onConnectionEndWithError(_))
      .Times(expectedEnd && withError ? 1 : 0)
      .WillRepeatedly([&](const QuicError& error) { onConnectionEnd(error); });
  EXPECT_CALL(*ownedConnCallback, onConnectionEnd())
      .Times(expectedEnd && !withError && !reportedAsError ? 1 : 0)
      .WillRepeatedly([&] { onConnectionEnd(std::nullopt); });
  EXPECT_CALL(*ownedConnCallback, onConnectionError(_))
      .Times(expectedEnd && !withError && reportedAsError ? 1 : 0)
      .WillRepeatedly([&](const QuicError& error) { onConnectionEnd(error); });
  EXPECT_CALL(*ownedSetupCallback, onConnectionSetupError(_)).Times(0);
  ownedSetupCallback.reset();
  ownedConnCallback.reset();
  // Run the callback update scheduled by setConnectionCallback().
  T::loopForWrites();

  switch (param.closeStart) {
    case CloseStart::CloseWithoutError:
      transport->close(std::nullopt);
      break;
    case CloseStart::CloseWithError:
      transport->close(QuicError(
          QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
          std::string("stopping")));
      break;
    case CloseStart::CloseGracefully: {
      ASSERT_FALSE(
          transport->writeChain(streamId, IOBuf::copyBuffer("bye"), true)
              .hasError());
      const auto writeInterval = this->loopForWrites();
      ASSERT_TRUE(writeInterval.has_value());
      transport->closeGracefully();
      EXPECT_EQ(connectionEndReports, 0);
      EXPECT_EQ(connCallback.expired(), !param.reportLocalClose);
      // The peer finishes its side, but our data is not acknowledged yet.
      this->deliverPacketNoWrites(this->buildPeerPacketWithStreamDataAndEof(
          streamId, IOBuf::copyBuffer("ok")));
      EXPECT_EQ(connectionEndReports, 0);
      deliverPacketWithoutErrorCheck(
          this->buildAckPacketForSentAppDataPackets(writeInterval));
      break;
    }
    case CloseStart::CloseGracefullyThenIdleTimeout: {
      auto& idleTimeout = this->getTestTransport()->idleTimeout();
      transport->closeGracefully();
      EXPECT_EQ(connectionEndReports, 0);
      EXPECT_EQ(connCallback.expired(), !param.reportLocalClose);
      idleTimeout.timeoutExpired();
      break;
    }
    case CloseStart::CloseNow:
      transport->closeNow(std::nullopt);
      break;
    case CloseStart::PeerConnectionClose:
      deliverPacketWithoutErrorCheck(
          this->buildPeerPacketWithConnectionCloseFrame(
              kPeerCloseErrorCode, "peer closing"));
      break;
    case CloseStart::DestroyTransport:
      this->destroyTransport();
      break;
  }
  T::loopForWrites();

  EXPECT_EQ(connectionEndReports, expectedEnd ? 1 : 0);
  EXPECT_TRUE(readErrorReported);
  EXPECT_TRUE(setupCallback.expired());
  EXPECT_TRUE(connCallback.expired());
  if (this->getTestTransport()) {
    this->destroyTransport();
  }
  EXPECT_TRUE(weakTransport.expired());
}

using QuicClientTransportConnectionEndTest =
    QuicTypedTransportConnectionEndTest<QuicClientTransportTestBase>;
using QuicServerTransportConnectionEndTest =
    QuicTypedTransportConnectionEndTest<QuicServerTransportTestBase>;

/**
 * With reportLocalClose, the connection callback learns exactly
 * once how the connection ended, after every read callback was retired, and
 * the transport releases it right after. Without the setting, a local close
 * or destruction reports nothing, as before.
 */
TEST_P(QuicClientTransportConnectionEndTest, ReportsConnectionEnd) {
  runConnectionEndTest();
}

TEST_P(QuicServerTransportConnectionEndTest, ReportsConnectionEnd) {
  runConnectionEndTest();
}

INSTANTIATE_TEST_SUITE_P(
    QuicTypedTransportTest,
    QuicClientTransportConnectionEndTest,
    ValuesIn(ConnectionEndTestCases::allCases()),
    ConnectionEndTestCases::caseName);

INSTANTIATE_TEST_SUITE_P(
    QuicTypedTransportTest,
    QuicServerTransportConnectionEndTest,
    ValuesIn(ConnectionEndTestCases::allCases()),
    ConnectionEndTestCases::caseName);

template <typename T>
class QuicTypedTransportCloneAckAfterLossTest
    : public QuicTypedTransportTest<T> {
 protected:
  // The original packet is declared lost while its PTO clone is outstanding,
  // the clone is then ACKed, and the retransmission that follows is ACKed
  // too. ACK processing skips the clone's frames, so the bytes must be
  // credited once, to the retransmission.
  void verifyBytesCreditedOnce(const bool useUnifiedSendBuffer) {
    constexpr auto kAckRtt = 27ms;
    constexpr std::string_view kData = "hello";

    this->startTransport();
    this->ackAllOutstandingPackets();
    auto& conn = this->getNonConstConn();
    conn.transportSettings.useUnifiedAppStreamSendBuffer = useUnifiedSendBuffer;
    // Packet number skipping would make write intervals non-contiguous.
    conn.transportSettings.skipOneInNPacketSequenceNumber = 0;
    // Only packet-threshold loss detection, configured below, declares the
    // original packet lost.
    conn.lossState.reorderingThreshold = 100;
    conn.transportSettings.timeReorderingThreshDividend = 1000000;
    conn.transportSettings.timeReorderingThreshDivisor = 1;

    auto transport = this->getTransport();
    const auto streamId = transport->createBidirectionalStream().value();
    auto* stream = conn.streamManager->findStream(streamId);
    ASSERT_NE(stream, nullptr);
    ASSERT_EQ(useUnifiedSendBuffer, stream->usesUnifiedSendBuffer());

    ASSERT_FALSE(
        transport->writeChain(streamId, IOBuf::copyBuffer(kData), false)
            .hasError());
    const auto original = this->loopForWrites();
    ASSERT_TRUE(original.has_value());
    ASSERT_EQ(original->start, original->end);
    const auto originalPacketNum = original->start;

    // Returns the newest AppData packet in the interval that carries stream
    // data, or nullptr.
    const auto findStreamPacket =
        [&](const auto& interval) -> const OutstandingPacketWrapper* {
      const OutstandingPacketWrapper* found = nullptr;
      for (const auto& packet : conn.outstandings.packets) {
        const auto packetNum = packet.packet.header.getPacketSequenceNum();
        if (packet.packet.header.getPacketNumberSpace() ==
                PacketNumberSpace::AppData &&
            packetNum >= interval.start && packetNum <= interval.end &&
            hasStreamFrame(packet.packet.frames)) {
          found = &packet;
        }
      }
      return found;
    };

    conn.pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
    this->getTestTransport()->writeLooper()->run(true);
    const auto probes = this->loopForWrites();
    ASSERT_TRUE(probes.has_value());
    const auto* clonePacket = findStreamPacket(*probes);
    ASSERT_NE(clonePacket, nullptr);
    ASSERT_TRUE(clonePacket->maybeClonedPacketIdentifier.has_value());
    const auto clonePacketNum =
        clonePacket->packet.header.getPacketSequenceNum();
    const auto cloneSentTime = clonePacket->metadata.time;

    // ACKing a later packet on another stream declares the original packet,
    // but not its clone, lost by packet threshold.
    const auto triggerStreamId = transport->createBidirectionalStream().value();
    ASSERT_FALSE(
        transport->writeChain(triggerStreamId, IOBuf::copyBuffer("a"), false)
            .hasError());
    const auto trigger = this->loopForWrites();
    ASSERT_TRUE(trigger.has_value());
    ASSERT_EQ(trigger->start, trigger->end);
    ASSERT_GT(clonePacketNum, originalPacketNum);
    // A packet is lost by reordering when the ACKed packet is more than
    // `reorderingThreshold` packets after it.
    conn.lossState.reorderingThreshold =
        static_cast<uint32_t>(trigger->end - originalPacketNum - 1);

    LegacyObserver::EventSet eventSet;
    eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);
    auto observer = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
    EXPECT_CALL(*observer, observerAttach(transport));
    transport->addObserver(observer.get());

    struct AckedPacketSummary {
      bool framesProcessed{false};
      AckEvent::AckPacket::FirstArrival firstArrival{
          AckEvent::AckPacket::FirstArrival::Unknown};
      uint64_t streamBytesAcked{0};
      std::vector<Interval<uint64_t>> carriedStreamIntervals;
    };

    std::map<PacketNum, AckedPacketSummary> ackedPackets;
    EXPECT_CALL(*observer, acksProcessed(transport, _))
        .WillRepeatedly(Invoke(
            [&](auto,
                const SocketObserverInterface::AcksProcessedEvent& event) {
              for (const auto& ackEvent : event.getAckEvents()) {
                for (const auto& ackedPacket : ackEvent.ackedPackets) {
                  auto& summary = ackedPackets[ackedPacket.packetNum];
                  summary.framesProcessed = ackedPacket.framesProcessed;
                  summary.firstArrival = ackedPacket.firstArrival;
                  const auto carried = ackedPacket.outstandingPacketMetadata
                                           .detailsPerStream.find(streamId);
                  if (carried !=
                      ackedPacket.outstandingPacketMetadata.detailsPerStream
                          .end()) {
                    summary.carriedStreamIntervals.assign(
                        carried->second.streamIntervals.begin(),
                        carried->second.streamIntervals.end());
                  }
                  const auto it = ackedPacket.detailsPerStream.find(streamId);
                  if (it != ackedPacket.detailsPerStream.end()) {
                    summary.streamBytesAcked += it->second.streamBytesAcked;
                  }
                }
              }
            }));

    this->deliverPacketNoWrites(
        this->buildAckPacketForSentAppDataPackets(trigger),
        trigger->sentTime + kAckRtt);
    const auto originalPacketIt = std::find_if(
        conn.outstandings.packets.begin(),
        conn.outstandings.packets.end(),
        [&](const auto& packet) {
          return packet.packet.header.getPacketSequenceNum() ==
              originalPacketNum;
        });
    ASSERT_NE(originalPacketIt, conn.outstandings.packets.end());
    ASSERT_TRUE(originalPacketIt->declaredLost);
    conn.lossState.reorderingThreshold = 100;

    this->deliverPacketNoWrites(
        this->buildAckPacketForSentAppDataPacket(clonePacketNum),
        cloneSentTime + kAckRtt);

    this->getTestTransport()->writeLooper()->run(true);
    const auto retransmissions = this->loopForWrites();
    ASSERT_TRUE(retransmissions.has_value());
    const auto* retransmissionPacket = findStreamPacket(*retransmissions);
    ASSERT_NE(retransmissionPacket, nullptr);
    ASSERT_FALSE(retransmissionPacket->maybeClonedPacketIdentifier.has_value());
    const auto retransmissionPacketNum =
        retransmissionPacket->packet.header.getPacketSequenceNum();
    this->deliverPacketNoWrites(
        this->buildAckPacketForSentAppDataPacket(retransmissionPacketNum),
        retransmissionPacket->metadata.time + kAckRtt);

    // The clone physically delivered the bytes first, but mvfst skipped its
    // frames and credits the bytes when the retransmission delivers them.
    using FirstArrival = AckEvent::AckPacket::FirstArrival;
    ASSERT_TRUE(ackedPackets.contains(clonePacketNum));
    const auto& clone = ackedPackets.at(clonePacketNum);
    EXPECT_FALSE(clone.framesProcessed);
    EXPECT_EQ(FirstArrival::Yes, clone.firstArrival);
    EXPECT_EQ(0, clone.streamBytesAcked);
    EXPECT_THAT(
        clone.carriedStreamIntervals,
        ElementsAre(Interval<uint64_t>(0, kData.size() - 1)));
    ASSERT_TRUE(ackedPackets.contains(retransmissionPacketNum));
    EXPECT_TRUE(ackedPackets.at(retransmissionPacketNum).framesProcessed);
    EXPECT_EQ(
        FirstArrival::Yes,
        ackedPackets.at(retransmissionPacketNum).firstArrival);
    EXPECT_EQ(
        kData.size(),
        ackedPackets.at(retransmissionPacketNum).streamBytesAcked);
    uint64_t totalStreamBytesAcked = 0;
    for (const auto& [packetNum, summary] : ackedPackets) {
      totalStreamBytesAcked += summary.streamBytesAcked;
    }
    EXPECT_EQ(kData.size(), totalStreamBytesAcked);
    this->destroyTransport();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportCloneAckAfterLossTest,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportCloneAckAfterLossTest, LegacySendBuffer) {
  this->verifyBytesCreditedOnce(false /* useUnifiedSendBuffer */);
}

TYPED_TEST(QuicTypedTransportCloneAckAfterLossTest, UnifiedSendBuffer) {
  this->verifyBytesCreditedOnce(true /* useUnifiedSendBuffer */);
}

} // namespace quic::test
