/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/MvfstLogging.h>

#include <quic/api/QuicPacketScheduler.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/test/MockQuicStats.h>
#include <chrono>
#include <optional>

using namespace quic;
using namespace testing;

enum PacketBuilderType { Regular, Inplace };

namespace {

PacketNum addInitialOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
  ConnectionId srcConnId = ConnectionId::createZeroLength();
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      Clock::now(),
      conn.currentPathId,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState(),
      conn.writeCount,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packetCount[PacketNumberSpace::Initial]++;
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  return nextPacketNum;
}

PacketNum addHandshakeOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum =
      getNextPacketNum(conn, PacketNumberSpace::Handshake);

  ConnectionId srcConnId = ConnectionId::createZeroLength();
  LongHeader header(
      LongHeader::Types::Handshake,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      Clock::now(),
      conn.currentPathId,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState(),
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  conn.outstandings.packetCount[PacketNumberSpace::Handshake]++;
  increaseNextPacketNum(conn, PacketNumberSpace::Handshake);
  return nextPacketNum;
}

PacketNum addOutstandingPacket(QuicConnectionStateBase& conn) {
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum);
  RegularQuicWritePacket packet(std::move(header));
  conn.outstandings.packets.emplace_back(
      std::move(packet),
      Clock::now(),
      conn.currentPathId,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState(),
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  increaseNextPacketNum(conn, PacketNumberSpace::AppData);
  return nextPacketNum;
}

using namespace quic::test;

auto createStream(
    QuicClientConnectionState& conn,
    std::optional<HTTPPriorityQueue::Priority> priority = std::nullopt) {
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  if (priority) {
    stream->priority = *priority;
  }
  return stream->id;
}

RegularQuicPacketBuilder createPacketBuilder(QuicClientConnectionState& conn) {
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  MVCHECK(!builder.encodePacketHeader().hasError());
  return builder;
}

std::unique_ptr<folly::IOBuf> createLargeBuffer(size_t size) {
  auto largeBuf = folly::IOBuf::createChain(size, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  return largeBuf;
}

WriteStreamFrame writeDataToStream(
    QuicClientConnectionState& conn,
    StreamId streamId,
    const std::string& data) {
  auto stream = conn.streamManager->findStream(streamId);
  auto length = data.size();
  MVCHECK(stream);
  auto result =
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(data), false);
  MVCHECK(!result.hasError());
  return {streamId, 0, length, false};
}

// Helper function to write data to a stream
WriteStreamFrame writeDataToStream(
    QuicClientConnectionState& conn,
    StreamId streamId,
    std::unique_ptr<folly::IOBuf> buf) {
  auto stream = conn.streamManager->findStream(streamId);
  auto length = buf->computeChainDataLength();
  auto result = writeDataToQuicStream(*stream, std::move(buf), false);
  MVCHECK(!result.hasError());
  return {streamId, 0, length, false};
}

std::unique_ptr<MockQuicPacketBuilder> setupMockPacketBuilder() {
  auto builder = std::make_unique<NiceMock<MockQuicPacketBuilder>>();
  EXPECT_CALL(*builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(*builder, appendFrame(_))
      .WillRepeatedly(Invoke([builder = builder.get()](auto f) {
        builder->frames_.push_back(f);
      }));
  return builder;
}

void verifyStreamFrames(
    MockQuicPacketBuilder& builder,
    const std::vector<WriteStreamFrame>& expectedFrames) {
  ASSERT_EQ(builder.frames_.size(), expectedFrames.size());
  for (size_t i = 0; i < expectedFrames.size(); ++i) {
    ASSERT_TRUE(builder.frames_[i].asWriteStreamFrame());
    EXPECT_EQ(*builder.frames_[i].asWriteStreamFrame(), expectedFrames[i]);
  }
  if (expectedFrames.size() == builder.frames_.size()) {
    builder.frames_.clear();
  } else {
    builder.frames_.erase(
        builder.frames_.begin(),
        builder.frames_.begin() + expectedFrames.size());
  }
}

size_t countTimestampFrames(const RegularQuicWritePacket::Vec& frames) {
  size_t count = 0;
  for (const auto& frame : frames) {
    if (frame.asTimestampFrame()) {
      ++count;
    }
  }
  return count;
}

void addAckReceiveTimestampState(
    QuicConnectionStateBase& conn,
    AckReceiveTimestampsVersion version =
        AckReceiveTimestampsVersion::LegacyMvfst) {
  auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
  ackState.acks.insert(10);
  WriteAckFrameState::ReceivedPacket rpi;
  rpi.pktNum = 10;
  rpi.timings.receiveTimePoint = Clock::now();
  auto receiveTime = rpi.timings.receiveTimePoint;
  ackState.recvdPacketInfos.emplace_back(std::move(rpi));
  ackState.largestRecvdPacketNum = 10;
  ackState.largestRecvdPacketTime = receiveTime;
  conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();
  conn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = version,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  if (version == AckReceiveTimestampsVersion::DraftIetf02) {
    conn.transportSettings.enableIetfAckReceiveTimestamps = true;
    updateNegotiatedAckFeatures(conn);
  } else {
    conn.negotiatedAckReceiveTimestampSupport = true;
  }
}

void addPlainAckState(QuicConnectionStateBase& conn) {
  auto& ackState = getAckState(conn, PacketNumberSpace::AppData);
  ackState.acks.insert(10);
  ackState.largestRecvdPacketNum = 10;
  ackState.largestRecvdPacketTime = Clock::now();
}
} // namespace

namespace quic::test {

class QuicPacketSchedulerTestBase {
 public:
  QuicVersion version{QuicVersion::MVFST};
  std::unique_ptr<BufAccessor> bufAccessor_{std::make_unique<BufAccessor>(
      kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize)};

  std::unique_ptr<QuicClientConnectionState> createConn(
      uint32_t maxStreams,
      uint64_t maxOffset,
      uint64_t initialMaxOffset,
      bool = false) {
    auto conn = std::make_unique<QuicClientConnectionState>(
        FizzClientQuicHandshakeContext::Builder().build());
    auto result =
        conn->streamManager->refreshTransportSettings(transportSettings);
    MVCHECK(!result.hasError(), "Failed to refresh transport settings");
    result = conn->streamManager->setMaxLocalBidirectionalStreams(maxStreams);
    MVCHECK(
        !result.hasError(), "Failed to set max local bidirectional streams");
    conn->flowControlState.peerAdvertisedMaxOffset = maxOffset;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        initialMaxOffset;

    initializePathManagerState(*conn);
    return conn;
  }

  TransportSettings transportSettings;
};

class QuicPacketSchedulerTest : public QuicPacketSchedulerTestBase,
                                public testing::TestWithParam<bool> {
 public:
  StreamId nextScheduledStreamID(QuicConnectionStateBase& conn) {
    return conn.streamManager->writeQueue().peekNextScheduledID().asStreamID();
  }

  // Configure a connection for datagram flow priority scheduling.
  void setupDatagramFlowConn(
      QuicClientConnectionState& conn,
      uint32_t maxWriteFrameSize = 1000) {
    conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
    conn.flowControlState.peerAdvertisedMaxOffset = 100000;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        100000;
    conn.transportSettings.datagramConfig.enabled = true;
    conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
    conn.datagramState.maxWriteFrameSize = maxWriteFrameSize;
    conn.datagramState.maxWriteBufferSize = 100;
  }
};

enum class TimestampAckKind : uint8_t {
  Plain,
  LegacyReceiveTimestamps,
  Draft02ReceiveTimestamps,
  ExtendedReceiveTimestamps,
};

struct TimestampAckPolicyCase {
  const char* name;
  TimestampAckKind ackKind;
  bool suppressForAckReceiveTimestamps;
  bool expectedTimestamp;
  FrameType expectedAckType;
};

class TimestampAckPolicyTest
    : public QuicPacketSchedulerTestBase,
      public testing::TestWithParam<TimestampAckPolicyCase> {};

enum class TimestampAckOnlyFrame : uint8_t { Ack, ImmediateAck };

struct TimestampAckOnlyPolicyCase {
  const char* name;
  TimestampAckOnlyFrame frame;
  TimestampFrameWriteMode mode;
  std::optional<TimestampFramePacketSelection> packetSelection;
  bool expectedTimestamp;
};

class TimestampAckOnlyPolicyTest
    : public QuicPacketSchedulerTestBase,
      public testing::TestWithParam<TimestampAckOnlyPolicyCase> {};

struct TimestampCapacityPolicyCase {
  const char* name;
  TimestampFrameWriteMode mode;
  bool fillPacket;
  bool validClock;
  bool expectedTimestamp;
};

class TimestampCapacityPolicyTest
    : public QuicPacketSchedulerTestBase,
      public testing::TestWithParam<TimestampCapacityPolicyCase> {};

TEST_F(QuicPacketSchedulerTest, CryptoPaddingInitialPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler cryptoOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("chlo"));
  auto result = cryptoOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, PaddingInitialPureAcks) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  conn.ackStates.initialAckState->largestRecvdPacketTime = Clock::now();
  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.initialAckState->acks.insert(10);
  FrameScheduler acksOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "AcksOnlyScheduler")
              .ackFrames())
          .build();
  auto result = acksOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, InitialPaddingDoesNotUseWrapper) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  size_t cipherOverhead = 30;
  LongHeader longHeader(
      LongHeader::Types::Initial,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  conn.ackStates.initialAckState->largestRecvdPacketTime = Clock::now();
  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.initialAckState->acks.insert(10);
  FrameScheduler acksOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "AcksOnlyScheduler")
              .ackFrames())
          .build();
  auto result = acksOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoServerInitialPadded) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
  LongHeader longHeader1(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(longHeader1),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo"));
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, PadTwoInitialPackets) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  PacketNum nextPacketNum = getNextPacketNum(conn, PacketNumberSpace::Initial);
  LongHeader longHeader1(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(longHeader1),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo"));
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);

  increaseNextPacketNum(conn, PacketNumberSpace::Initial);
  LongHeader longHeader2(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(longHeader2),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  writeDataToQuicStream(
      conn.cryptoState->initialStream, folly::IOBuf::copyBuffer("shlo again"));
  auto result2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen);
  ASSERT_FALSE(result2.hasError());
  packetLength = result2.value().packet->header.computeChainDataLength() +
      result2.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoPaddingRetransmissionClientInitial) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  BufPtr helloBuf = folly::IOBuf::copyBuffer("chlo");
  ChainedByteRangeHead clientHelloData(helloBuf);
  conn.cryptoState->initialStream.lossBuffer.push_back(
      WriteStreamBuffer{std::move(clientHelloData), 0, false});
  auto result = std::move(scheduler).scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, CryptoSchedulerOnlySingleLossFits) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Handshake,
      connId,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Handshake),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  PacketBuilderWrapper builderWrapper(builder, 13);
  CryptoStreamScheduler scheduler(
      conn, *getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake));

  BufPtr helloBuf = folly::IOBuf::copyBuffer("shlo");
  BufPtr certBuf = folly::IOBuf::copyBuffer(
      "certificatethatisverylongseriouslythisisextremelylongandcannotfitintoapacket");

  conn.cryptoState->handshakeStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(helloBuf), 0, false);
  conn.cryptoState->handshakeStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(certBuf), 7, false);
  auto result = scheduler.writeCryptoData(builderWrapper);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(result.value());
}

TEST_P(QuicPacketSchedulerTest, CryptoWritePartialLossBuffer) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  LongHeader longHeader(
      LongHeader::Types::Initial,
      ConnectionId::createZeroLength(),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      25,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(
          conn.ackStates.initialAckState->nextPacketNum));
  FrameScheduler cryptoOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "CryptoOnlyScheduler")
              .cryptoFrames())
          .build();
  BufPtr lossBuffer =
      folly::IOBuf::copyBuffer("return the special duration value max");
  conn.cryptoState->initialStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(lossBuffer), 0, false);
  auto result = cryptoOnlyScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result->packet->header.computeChainDataLength() +
      result->packet->body.computeChainDataLength();
  EXPECT_LE(packetLength, 25);
  EXPECT_TRUE(result->packet->packet.frames[0].asWriteCryptoFrame() != nullptr);
  EXPECT_FALSE(conn.cryptoState->initialStream.lossBuffer.empty());
}

TEST_P(QuicPacketSchedulerTest, CryptoSchedulerReadsOwningSendBuffer) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn.transportSettings.useNonCloningPto = true;
  writeDataToQuicStream(
      conn,
      conn.cryptoState->handshakeStream,
      folly::IOBuf::copyBuffer("handshake"));
  LongHeader header(
      LongHeader::Types::Handshake,
      getTestConnectionId(1),
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::Handshake),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));
  auto scheduler = std::move(
                       FrameScheduler::Builder(
                           conn,
                           EncryptionLevel::Handshake,
                           PacketNumberSpace::Handshake,
                           "CryptoOnlyScheduler")
                           .cryptoFrames())
                       .build();

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  const auto* frame =
      result->packet->packet.frames.front().asWriteCryptoFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteCryptoFrame(0, 9), *frame);
  EXPECT_EQ(
      conn.cryptoState->handshakeStream.streamSendBuffer->nextUnsentOffset(),
      0);
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerExists) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto connId = getTestConnectionId();
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builder).hasError());
  EXPECT_LT(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, StreamFrameNoSpace) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto connId = getTestConnectionId();
  auto stream = conn.streamManager->createNextBidirectionalStream().value();

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  PacketBuilderWrapper builderWrapper(builder, 2);
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(stream->id);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builderWrapper).hasError());
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerStreamNotExists) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto connId = getTestConnectionId();
  StreamId nonExistentStream = 11;

  WindowUpdateScheduler scheduler(conn);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  auto originalSpace = builder.remainingSpaceInPkt();
  conn.streamManager->queueWindowUpdate(nonExistentStream);
  ASSERT_FALSE(scheduler.writeWindowUpdates(builder).hasError());
  EXPECT_EQ(builder.remainingSpaceInPkt(), originalSpace);
}

TEST_P(QuicPacketSchedulerTest, CloningSchedulerTest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(packetNum, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, AppDataPtoSchedulerPrefersOrdinaryUnifiedLoss) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("ordinary-loss"), false)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 13, false}));
  ASSERT_TRUE(stream->streamSendBuffer->markLoss({0, 13, false}));
  conn.streamManager->updateWritableStreams(*stream);

  auto frameScheduler = std::move(
                            FrameScheduler::Builder(
                                conn,
                                EncryptionLevel::AppData,
                                PacketNumberSpace::AppData,
                                "AppDataFrameScheduler")
                                .streamFrames())
                            .build();
  AppDataPtoScheduler scheduler(frameScheduler, conn, "AppDataPtoScheduler");
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  const auto frameIt = std::find_if(
      result->packet->packet.frames.begin(),
      result->packet->packet.frames.end(),
      [](const auto& frame) { return frame.asWriteStreamFrame() != nullptr; });
  ASSERT_NE(frameIt, result->packet->packet.frames.end());
  const auto* frame = frameIt->asWriteStreamFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteStreamFrame(streamId, 0, 13, false), *frame);
  EXPECT_EQ(PacketTransmissionReason::PtoProbe, result->transmissionReason);
  EXPECT_FALSE(result->isPtoRetransmission);
}

TEST_P(
    QuicPacketSchedulerTest,
    AppDataPtoSchedulerSelectsOldestUnackedRangesOnce) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("abcdefghij"), true)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 10, true}));
  ASSERT_TRUE(stream->streamSendBuffer->markAcked({0, 2, false}).has_value());

  addOutstandingPacket(conn);
  conn.outstandings.packets.back().declaredLost = true;
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteStreamFrame(streamId, 0, 2, false));
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteStreamFrame(streamId, 0, 6, false));
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteStreamFrame(streamId, 6, 4, true));

  FrameScheduler noopScheduler("frame", conn);
  AppDataPtoScheduler scheduler(noopScheduler, conn, "AppDataPtoScheduler");
  const auto schedule = [&]() {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        getTestConnectionId(),
        getNextPacketNum(conn, PacketNumberSpace::AppData));
    RegularQuicPacketBuilder builder(
        static_cast<uint32_t>(conn.udpSendPacketLen),
        std::move(header),
        conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
    return scheduler.scheduleFramesForPacket(
        std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));
  };

  auto first = schedule();
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(first->packet.has_value());
  ASSERT_EQ(1, first->packet->packet.frames.size());
  const auto* firstFrame =
      first->packet->packet.frames.front().asWriteStreamFrame();
  ASSERT_NE(firstFrame, nullptr);
  EXPECT_EQ(WriteStreamFrame(streamId, 2, 4, false), *firstFrame);
  EXPECT_FALSE(first->clonedPacketIdentifier.has_value());
  EXPECT_EQ(PacketTransmissionReason::PtoProbe, first->transmissionReason);
  EXPECT_TRUE(first->isPtoRetransmission);

  const auto encodedSize = first->packet->header.computeChainDataLength() +
      first->packet->body.computeChainDataLength();
  ASSERT_TRUE(updateConnection(
      conn,
      *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
      std::nullopt,
      std::move(first->packet->packet),
      Clock::now(),
      encodedSize,
      first->packet->body.computeChainDataLength(),
      first->transmissionReason,
      first->isPtoRetransmission));
  EXPECT_EQ(
      PacketTransmissionReason::PtoProbe,
      conn.outstandings.packets.back().metadata.transmissionReason);
  EXPECT_FALSE(
      conn.outstandings.packets.back().maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(8, stream->streamSendBuffer->outstandingBytes());
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());

  auto second = schedule();
  ASSERT_TRUE(second.has_value());
  ASSERT_TRUE(second->packet.has_value());
  ASSERT_EQ(1, second->packet->packet.frames.size());
  const auto* secondFrame =
      second->packet->packet.frames.front().asWriteStreamFrame();
  ASSERT_NE(secondFrame, nullptr);
  EXPECT_EQ(WriteStreamFrame(streamId, 6, 4, true), *secondFrame);

  auto third = schedule();
  ASSERT_TRUE(third.has_value());
  ASSERT_TRUE(third->packet.has_value());
  ASSERT_EQ(1, third->packet->packet.frames.size());
  EXPECT_NE(third->packet->packet.frames.front().asPingFrame(), nullptr);
  EXPECT_FALSE(third->isPtoRetransmission);
}

TEST_P(QuicPacketSchedulerTest, AppDataPtoSchedulerWritesFinOnlyProbe) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_FALSE(writeDataToQuicStream(*stream, nullptr, true).hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 0, true}));
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteStreamFrame(streamId, 0, 0, true));

  FrameScheduler noopScheduler("frame", conn);
  AppDataPtoScheduler scheduler(noopScheduler, conn, "AppDataPtoScheduler");
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  ASSERT_EQ(1, result->packet->packet.frames.size());
  const auto* frame =
      result->packet->packet.frames.front().asWriteStreamFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteStreamFrame(streamId, 0, 0, true), *frame);
  EXPECT_TRUE(result->isPtoRetransmission);
}

TEST_P(QuicPacketSchedulerTest, AppDataPtoSchedulerSkipsDisabledStream) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("disabled"), false)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 8, false}));
  stream->retransmissionDisabled_ = true;
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteStreamFrame(streamId, 0, 8, false));

  FrameScheduler noopScheduler("frame", conn);
  AppDataPtoScheduler scheduler(noopScheduler, conn, "AppDataPtoScheduler");
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  ASSERT_EQ(1, result->packet->packet.frames.size());
  EXPECT_NE(result->packet->packet.frames.front().asPingFrame(), nullptr);
  EXPECT_FALSE(result->isPtoRetransmission);
}

TEST_P(
    QuicPacketSchedulerTest,
    CryptoPtoSchedulerWritesUnackedInitialRangeWithoutMutation) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn.transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn.cryptoState->initialStream;
  writeDataToQuicStream(
      conn, cryptoStream, folly::IOBuf::copyBuffer("initial"));
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markNewDataSent({0, 7, false}));
  ASSERT_TRUE(
      cryptoStream.streamSendBuffer->markAcked({0, 2, false}).has_value());
  addInitialOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteCryptoFrame(0, 7));
  FrameScheduler noopScheduler("frame", conn);
  CryptoPtoScheduler scheduler(
      noopScheduler, conn, EncryptionLevel::Initial, "CryptoPtoScheduler");
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  const auto* frame =
      result->packet->packet.frames.front().asWriteCryptoFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteCryptoFrame(2, 5), *frame);
  EXPECT_TRUE(result->isPtoRetransmission);
  EXPECT_EQ(cryptoStream.streamSendBuffer->outstandingBytes(), 5);
  EXPECT_FALSE(cryptoStream.streamSendBuffer->hasPendingLoss());
}

TEST_P(QuicPacketSchedulerTest, CryptoPtoSchedulerUsesHandshakeSpace) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn.transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn.cryptoState->handshakeStream;
  writeDataToQuicStream(conn, cryptoStream, folly::IOBuf::copyBuffer("hs"));
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markNewDataSent({0, 2, false}));
  addHandshakeOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteCryptoFrame(0, 2));
  FrameScheduler noopScheduler("frame", conn);
  CryptoPtoScheduler scheduler(
      noopScheduler, conn, EncryptionLevel::Handshake, "CryptoPtoScheduler");
  LongHeader header(
      LongHeader::Types::Handshake,
      getTestConnectionId(1),
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::Handshake),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.handshakeAckState->largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  const auto* frame =
      result->packet->packet.frames.front().asWriteCryptoFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteCryptoFrame(0, 2), *frame);
  EXPECT_TRUE(result->isPtoRetransmission);
}

TEST_P(QuicPacketSchedulerTest, AppDataPtoSchedulerWritesOneRttCrypto) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn.transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn.cryptoState->oneRttStream;
  writeDataToQuicStream(conn, cryptoStream, folly::IOBuf::copyBuffer("ticket"));
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markNewDataSent({0, 6, false}));
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.emplace_back(
      WriteCryptoFrame(0, 6));
  FrameScheduler noopScheduler("frame", conn);
  AppDataPtoScheduler scheduler(noopScheduler, conn, "AppDataPtoScheduler");
  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), static_cast<uint32_t>(conn.udpSendPacketLen));

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  const auto* frame =
      result->packet->packet.frames.front().asWriteCryptoFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(WriteCryptoFrame(0, 6), *frame);
  EXPECT_TRUE(result->isPtoRetransmission);
}

TEST_P(QuicPacketSchedulerTest, WriteOnlyOutstandingPacketsTest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder regularBuilder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Create few frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.");
  MaxStreamsFrame maxStreamFrame(999, true);
  PingFrame pingFrame;
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};

  // Write those framses with a regular builder
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder).hasError());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamFrame), regularBuilder).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder).hasError());
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder).hasError());

  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(regularBuilder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(packetNum, result->clonedPacketIdentifier->packetNumber);
  // written packet should not have any frame in the builder
  auto& writtenPacket = *result->packet;
  auto shortHeader = writtenPacket.packet.header.asShort();
  MVCHECK(shortHeader);
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader->getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader->getPacketSequenceNum());

  // Test that the only frame that's written is maxdataframe
  EXPECT_GE(writtenPacket.packet.frames.size(), 1);
  auto& writtenFrame = writtenPacket.packet.frames.at(0);
  auto maxDataFrame = writtenFrame.asMaxDataFrame();
  MVCHECK(maxDataFrame);
  for (auto& frame : writtenPacket.packet.frames) {
    bool present = false;
    /* the next four frames should not be written */
    present |= frame.asConnectionCloseFrame() ? true : false;
    present |= frame.asQuicSimpleFrame() ? true : false;
    present |= frame.asQuicSimpleFrame() ? true : false;
    present |= frame.asWriteAckFrame() ? true : false;
    ASSERT_FALSE(present);
  }
}

TEST_P(QuicPacketSchedulerTest, DoNotCloneProcessedClonedPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, but then mark the first one processed by
  // adding a ClonedPacketIdentifier that's missing from the
  // outstandings.clonedPacketIdentifiers set
  addOutstandingPacket(conn);
  conn.outstandings.packets.back().maybeClonedPacketIdentifier =
      ClonedPacketIdentifier(PacketNumberSpace::AppData, 1);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  PacketNum expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(expected, result->clonedPacketIdentifier->packetNumber);
}

// Verifies the hardcoded "no duplicate clones in the same write loop"
// behavior of the cloning scheduler. With multiple outstanding CRYPTO
// packets, when the first packet has already been cloned in the current
// write loop, scheduling another probe should pick the next un-cloned
// packet rather than re-cloning the first one. This is the property that
// the (now-removed) cloneAllPacketsWithCryptoFrame +
// cloneCryptoPacketsAtMostOnce settings used to gate, and that we want to
// preserve as the default behavior.
TEST_P(
    QuicPacketSchedulerTest,
    CloneSchedulerSkipsAlreadyClonedPacketInSameWriteLoop) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "cryptoClone", 0);
  conn.writeCount = 0;

  // Add two original outstanding CRYPTO packets in writeCount==0.
  PacketNum firstPacketNum = addInitialOutstandingPacket(conn);
  {
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, firstPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // It is not processed yet
    conn.outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  PacketNum secondPacketNum = addInitialOutstandingPacket(conn);
  {
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, secondPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // It is not processed yet
    conn.outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  // Move into a new write loop and add a clone of the first packet in this
  // new loop, simulating that we just cloned the first packet as part of
  // the current PTO probing.
  ++(conn.writeCount);
  {
    addInitialOutstandingPacket(conn);
    conn.outstandings.packets.back().packet.frames.push_back(
        WriteCryptoFrame(0, 1));
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::Initial, firstPacketNum);
    conn.outstandings.packets.back().maybeClonedPacketIdentifier =
        clonedPacketIdentifier;
    // There needs to have retransmittable frame for the rebuilder to work
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  }

  // Schedule another probe in the same write loop. The scheduler should
  // skip the first packet (already cloned in this write loop) and pick the
  // second CRYPTO packet instead, ensuring distinct probe content for
  // crypto handshakes.
  ConnectionId srcConnId = ConnectionId::createZeroLength();
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(secondPacketNum, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, DoNotSkipUnclonedCryptoPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "cryptoClone", 0);

  // First packet has a crypto frame
  PacketNum firstPacketNum = addInitialOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.push_back(
      WriteCryptoFrame(0, 1));
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  addInitialOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ConnectionId srcConnId = ConnectionId::createZeroLength();
  LongHeader header(
      LongHeader::Types::Initial,
      srcConnId,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(firstPacketNum, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addHandshakeOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

/**
 * This test case covers the following scenario:
   1) conn sent out a handshake packet that did not get acked yet
   2) conn received some handshake data that needs to be acked
   3) imitate that we're emitting a PTO packet (that is generated via cloning
      scheduler)
   4) emitted cloned packet MUST have both cloned crypto data AND ack
      frame(s)

    There was a bug that would result in mvfst emit a "empty" PTO packet with
    acks; this is the test case to cover that scenario.
 */
TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasHandshakeDataAndAcks) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  conn.version = QuicVersion::MVFST_EXPERIMENTAL2;

  FrameScheduler noopScheduler = std::move(
                                     FrameScheduler::Builder(
                                         conn,
                                         EncryptionLevel::Handshake,
                                         PacketNumberSpace::Handshake,
                                         "testScheduler")
                                         .ackFrames())
                                     .build();
  addHandshakeOutstandingPacket(conn);

  // Add some crypto data for the outstanding packet to make it look legit.
  // This is so cloning scheduler can actually copy something.
  BufPtr cryptoBuf = folly::IOBuf::copyBuffer("test");
  ChainedByteRangeHead cryptoRch(cryptoBuf);
  getCryptoStream(*conn.cryptoState, EncryptionLevel::Handshake)
      ->retransmissionBuffer.emplace(
          0,
          std::make_unique<WriteStreamBuffer>(std::move(cryptoRch), 0, false));
  conn.outstandings.packets.back().packet.frames.push_back(
      WriteCryptoFrame(0, 4));

  // Make it look like we received some acks from the peer.
  conn.ackStates.handshakeAckState->acks.insert(10);
  conn.ackStates.handshakeAckState->largestRecvdPacketTime = Clock::now();

  // Create cloning scheduler.
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_TRUE(cloningScheduler.hasData());

  // Get the packet builder going for the clone packet.
  PacketNum nextPacketNum =
      getNextPacketNum(conn, PacketNumberSpace::Handshake);

  ConnectionId srcConnId = ConnectionId::createZeroLength();
  LongHeader header(
      LongHeader::Types::Handshake,
      srcConnId,
      conn.clientConnectionId.value_or(quic::test::getTestConnectionId()),
      nextPacketNum,
      QuicVersion::MVFST);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Clone the packet.
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(result->clonedPacketIdentifier.has_value());
  EXPECT_TRUE(result->packet.has_value());

  // Cloned packet has to have crypto data and no acks.
  bool hasAckFrame = false;
  bool hasCryptoFrame = false;
  for (auto iter = result->packet->packet.frames.cbegin();
       iter != result->packet->packet.frames.cend();
       iter++) {
    const QuicWriteFrame& frame = *iter;
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame:
        hasAckFrame = true;
        break;
      case QuicWriteFrame::Type::WriteCryptoFrame:
        hasCryptoFrame = true;
        break;
      default:
        break;
    }
  }
  EXPECT_FALSE(hasAckFrame);
  EXPECT_TRUE(hasCryptoFrame);
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasInitialData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addInitialOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerHasAppDataData) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  EXPECT_FALSE(cloningScheduler.hasData());

  addOutstandingPacket(conn);
  EXPECT_TRUE(cloningScheduler.hasData());
}

TEST_P(QuicPacketSchedulerTest, DoNotCloneHandshake) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "CopyCat", 0);
  // Add two outstanding packets, with second one being handshake
  auto expected = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  addHandshakeOutstandingPacket(conn);
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result->clonedPacketIdentifier.has_value() && result->packet.has_value());
  EXPECT_EQ(expected, result->clonedPacketIdentifier->packetNumber);
}

TEST_P(QuicPacketSchedulerTest, CloneSchedulerUseNormalSchedulerFirst) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.version = QuicVersion::MVFST_EXPERIMENTAL2;
  NiceMock<MockFrameScheduler> mockScheduler(&conn);
  CloningScheduler cloningScheduler(mockScheduler, conn, "Mocker", 0);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  EXPECT_CALL(mockScheduler, hasImmediateData())
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_CALL(mockScheduler, _scheduleFramesForPacket(_, _))
      .Times(1)
      .WillOnce(Invoke(
          [&, headerCopy = header](PacketBuilderInterface*, uint32_t) mutable {
            RegularQuicWritePacket packet(std::move(headerCopy));
            packet.frames.push_back(MaxDataFrame(2832));
            RegularQuicPacketBuilder::Packet builtPacket(
                std::move(packet),
                folly::IOBuf(
                    folly::IOBuf::CopyBufferOp::COPY_BUFFER,
                    "if you are the dealer"),
                folly::IOBuf(
                    folly::IOBuf::CopyBufferOp::COPY_BUFFER,
                    "I'm out of the game"));
            return SchedulingResult(std::nullopt, std::move(builtPacket));
          }));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(std::nullopt, result->clonedPacketIdentifier);
  EXPECT_EQ(result->packet->packet.header.getHeaderForm(), HeaderForm::Short);
  ShortHeader& shortHeader = *result->packet->packet.header.asShort();
  EXPECT_EQ(ProtectionType::KeyPhaseOne, shortHeader.getProtectionType());
  EXPECT_EQ(
      conn.ackStates.appDataAckState.nextPacketNum,
      shortHeader.getPacketSequenceNum());
  EXPECT_EQ(1, result->packet->packet.frames.size());
  MaxDataFrame* maxDataFrame =
      result->packet->packet.frames.front().asMaxDataFrame();
  ASSERT_NE(maxDataFrame, nullptr);
  EXPECT_EQ(2832, maxDataFrame->maximumData);
  EXPECT_TRUE(
      folly::IOBufEqualTo{}(
          *folly::IOBuf::copyBuffer("if you are the dealer"),
          result->packet->header));
  EXPECT_TRUE(
      folly::IOBufEqualTo{}(
          *folly::IOBuf::copyBuffer("I'm out of the game"),
          result->packet->body));
}

TEST_P(QuicPacketSchedulerTest, CloneWillGenerateNewWindowUpdate) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  auto result = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(result.hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  FrameScheduler noopScheduler("frame", conn);
  CloningScheduler cloningScheduler(noopScheduler, conn, "GiantsShoulder", 0);
  ClonedPacketIdentifier expectedClonedPacketIdentifier(
      PacketNumberSpace::AppData, addOutstandingPacket(conn));
  ASSERT_EQ(1, conn.outstandings.packets.size());
  conn.outstandings.packets.back().packet.frames.push_back(MaxDataFrame(1000));
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxStreamDataFrame(stream->id, 1000));
  conn.flowControlState.advertisedMaxOffset = 1000;
  stream->flowControlState.advertisedMaxOffset = 1000;

  conn.flowControlState.sumCurReadOffset = 300;
  conn.flowControlState.windowSize = 3000;
  stream->currentReadOffset = 200;
  stream->flowControlState.releasedReadOffset = 200;
  stream->flowControlState.windowSize = 1500;

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(packetResult.hasError());
  EXPECT_EQ(
      expectedClonedPacketIdentifier, *packetResult->clonedPacketIdentifier);
  int32_t verifyConnWindowUpdate = 1, verifyStreamWindowUpdate = 1;
  for (const auto& frame : packetResult->packet->packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        EXPECT_EQ(stream->id, maxStreamDataFrame.streamId);
        verifyStreamWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        verifyConnWindowUpdate--;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        break;
      }
      default:
        // should never happen
        EXPECT_TRUE(false);
    }
  }
  EXPECT_EQ(0, verifyStreamWindowUpdate);
  EXPECT_EQ(0, verifyConnWindowUpdate);

  // Verify the built out packet has refreshed window update values
  EXPECT_GE(packetResult->packet->packet.frames.size(), 2);
  uint32_t streamWindowUpdateCounter = 0;
  uint32_t connWindowUpdateCounter = 0;
  for (auto& frame : packetResult->packet->packet.frames) {
    auto streamFlowControl = frame.asMaxStreamDataFrame();
    if (!streamFlowControl) {
      continue;
    }
    streamWindowUpdateCounter++;
    EXPECT_EQ(1700, streamFlowControl->maximumData);
  }
  for (auto& frame : packetResult->packet->packet.frames) {
    auto connFlowControl = frame.asMaxDataFrame();
    if (!connFlowControl) {
      continue;
    }
    connWindowUpdateCounter++;
    EXPECT_EQ(3300, connFlowControl->maximumData);
  }
  EXPECT_EQ(1, connWindowUpdateCounter);
  EXPECT_EQ(1, streamWindowUpdateCounter);
}

TEST_P(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilder) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "93MillionMiles", 0);
  auto packetNum = addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      result.value().clonedPacketIdentifier.has_value() &&
      result.value().packet.has_value());
  EXPECT_EQ(packetNum, result.value().clonedPacketIdentifier->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_GT(buf->length(), 10);
}

TEST_P(QuicPacketSchedulerTest, CloningSchedulerWithInplaceBuilderFullPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  initializePathManagerState(conn);
  auto streamResult = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(streamResult.hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(conn.udpSendPacketLen);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;
  auto stream = *conn.streamManager->createNextBidirectionalStream();
  auto inBuf = buildRandomInputData(conn.udpSendPacketLen * 10);
  auto writeResult = writeDataToQuicStream(*stream, inBuf->clone(), false);
  ASSERT_FALSE(writeResult.hasError());

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();
  auto packetNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(scheduler.hasData());
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto bufferLength = result->packet->header.computeChainDataLength() +
      result->packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, bufferLength);
  auto updateResult = updateConnection(
      conn,
      *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
      std::nullopt,
      result->packet->packet,
      Clock::now(),
      bufferLength,
      0);
  ASSERT_FALSE(updateResult.hasError());
  buf = bufAccessor.obtain();
  ASSERT_EQ(conn.udpSendPacketLen, buf->length());
  buf->clear();
  bufAccessor.release(std::move(buf));

  FrameScheduler noopScheduler("noopScheduler", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "93MillionMiles", 0);
  EXPECT_TRUE(cloningScheduler.hasData());
  ASSERT_FALSE(noopScheduler.hasData());
  // Exact same header, so header encoding should be the same
  ShortHeader dupHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  InplaceQuicPacketBuilder internalBuilder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(dupHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto cloneResult = cloningScheduler.scheduleFramesForPacket(
      std::move(internalBuilder), conn.udpSendPacketLen);
  ASSERT_FALSE(cloneResult.hasError());
  EXPECT_TRUE(
      cloneResult->clonedPacketIdentifier.has_value() &&
      cloneResult->packet.has_value());
  EXPECT_EQ(packetNum, cloneResult->clonedPacketIdentifier->packetNumber);

  // Something was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), conn.udpSendPacketLen);

  constexpr uint32_t kReservedBytes = 64;
  const auto udpSendPacketLen = static_cast<uint32_t>(conn.udpSendPacketLen);
  buf->clear();
  buf->append(kReservedBytes);
  bufAccessor.release(std::move(buf));

  ShortHeader boundedHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  InplaceQuicPacketBuilder boundedBuilder(
      bufAccessor,
      udpSendPacketLen - kReservedBytes,
      std::move(boundedHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto boundedCloneResult = cloningScheduler.scheduleFramesForPacket(
      std::move(boundedBuilder), udpSendPacketLen);
  ASSERT_FALSE(boundedCloneResult.hasError());
  EXPECT_FALSE(boundedCloneResult->clonedPacketIdentifier.has_value());
  EXPECT_FALSE(boundedCloneResult->packet.has_value());

  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), kReservedBytes);
}

TEST_P(
    QuicPacketSchedulerTest,
    CloningSchedulerRespectsBuilderPacketSizeLimit) {
  constexpr uint32_t kReservedDatagramBytes = 2;
  constexpr uint8_t kCipherOverhead = 16;

  for (const auto dataPathType :
       {DataPathType::ChainedMemory, DataPathType::ContinuousMemory}) {
    SCOPED_TRACE(
        dataPathType == DataPathType::ChainedMemory ? "chained" : "inplace");
    QuicClientConnectionState conn(
        FizzClientQuicHandshakeContext::Builder().build());
    conn.transportSettings.dataPathType = dataPathType;

    std::unique_ptr<BufAccessor> bufAccessor;
    if (dataPathType == DataPathType::ContinuousMemory) {
      bufAccessor = std::make_unique<BufAccessor>(conn.udpSendPacketLen);
      conn.bufAccessor = bufAccessor.get();
    }

    FrameScheduler noopScheduler("noopScheduler", conn);
    CloningScheduler cloningScheduler(
        noopScheduler, conn, "CopyCat", kCipherOverhead);
    auto packetNum = addInitialOutstandingPacket(conn);
    conn.outstandings.packets.back().packet.frames.push_back(
        MaxDataFrame(conn.flowControlState.advertisedMaxOffset));

    ConnectionId srcConnId = ConnectionId::createZeroLength();
    LongHeader header(
        LongHeader::Types::Initial,
        srcConnId,
        conn.clientConnectionId.value_or(getTestConnectionId()),
        getNextPacketNum(conn, PacketNumberSpace::Initial),
        QuicVersion::MVFST);
    const uint32_t packetSizeLimit =
        conn.udpSendPacketLen - kReservedDatagramBytes;
    std::unique_ptr<PacketBuilderInterface> builder;
    if (dataPathType == DataPathType::ChainedMemory) {
      builder = std::make_unique<RegularQuicPacketBuilder>(
          packetSizeLimit,
          std::move(header),
          conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
    } else {
      builder = std::make_unique<InplaceQuicPacketBuilder>(
          *bufAccessor,
          packetSizeLimit,
          std::move(header),
          conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));
    }
    builder->accountForCipherOverhead(kCipherOverhead);

    auto cloneResult = cloningScheduler.scheduleFramesForPacket(
        std::move(*builder), conn.udpSendPacketLen - kCipherOverhead);
    ASSERT_FALSE(cloneResult.hasError());
    ASSERT_TRUE(
        cloneResult->clonedPacketIdentifier.has_value() &&
        cloneResult->packet.has_value());
    EXPECT_EQ(packetNum, cloneResult->clonedPacketIdentifier->packetNumber);
    EXPECT_EQ(
        packetSizeLimit,
        cloneResult->packet->header.computeChainDataLength() +
            cloneResult->packet->body.computeChainDataLength() +
            kCipherOverhead);
  }
}

TEST_P(QuicPacketSchedulerTest, CloneLargerThanOriginalPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  conn.udpSendPacketLen = 1000;
  auto result = conn.streamManager->setMaxLocalBidirectionalStreams(10);
  ASSERT_FALSE(result.hasError());
  initializePathManagerState(conn);

  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto inputData = buildRandomInputData(conn.udpSendPacketLen * 10);
  auto writeResult = writeDataToQuicStream(*stream, inputData->clone(), false);
  ASSERT_FALSE(writeResult.hasError());
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();
  auto cipherOverhead = 16;
  PacketNum packetNum = 0;
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(packetResult.hasError());
  auto encodedSize = packetResult->packet->body.computeChainDataLength() +
      packetResult->packet->header.computeChainDataLength() + cipherOverhead;
  EXPECT_EQ(encodedSize, conn.udpSendPacketLen);
  auto updateResult = updateConnection(
      conn,
      *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
      std::nullopt,
      packetResult->packet->packet,
      Clock::now(),
      encodedSize,
      0);
  ASSERT_FALSE(updateResult.hasError());

  // make packetNum too larger to be encoded into the same size:
  packetNum += 0xFF;
  ShortHeader cloneHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum);
  RegularQuicPacketBuilder throwawayBuilder(
      conn.udpSendPacketLen,
      std::move(cloneHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  throwawayBuilder.accountForCipherOverhead(cipherOverhead);
  FrameScheduler noopScheduler("noopScheduler", conn);
  CloningScheduler cloningScheduler(
      noopScheduler, conn, "CopyCat", cipherOverhead);
  auto cloneResult = cloningScheduler.scheduleFramesForPacket(
      std::move(throwawayBuilder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(cloneResult.hasError());
  EXPECT_FALSE(cloneResult->packet.has_value());
  EXPECT_FALSE(cloneResult->clonedPacketIdentifier.has_value());
}

class AckSchedulingTest : public TestWithParam<PacketNumberSpace> {};

TEST_P(QuicPacketSchedulerTest, AckStateHasAcksToSchedule) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.initialAckState));
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));
  EXPECT_FALSE(hasAcksToSchedule(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(hasAcksToSchedule(*conn.ackStates.initialAckState));

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));

  conn.ackStates.handshakeAckState->largestAckScheduled = std::nullopt;
  EXPECT_TRUE(hasAcksToSchedule(*conn.ackStates.handshakeAckState));
}

TEST_P(QuicPacketSchedulerTest, AckSchedulerHasAcksToSchedule) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  AckScheduler initialAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Initial));
  AckScheduler handshakeAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Handshake));
  AckScheduler appDataAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::AppData));
  EXPECT_FALSE(initialAckScheduler.hasPendingAcks());
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());
  EXPECT_FALSE(appDataAckScheduler.hasPendingAcks());

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(initialAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->largestAckScheduled = std::nullopt;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_P(TimestampAckPolicyTest, SuppressesOnlyAcksThatCarryTimestamps) {
  const auto& testCase = GetParam();
  auto connPtr = createConn(10, 100000, 100000);
  ASSERT_NE(connPtr, nullptr);
  if (connPtr == nullptr) {
    return;
  }
  auto& conn = *connPtr;
  conn.transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Opportunistic;
  conn.transportSettings
      .suppressOneRttTimestampFrameWhenAckReceiveTimestampsWritten =
      testCase.suppressForAckReceiveTimestamps;
  conn.peerTimestampFrameState.canReceive = true;
  conn.connectionTime = Clock::now() - std::chrono::milliseconds(5);

  switch (testCase.ackKind) {
    case TimestampAckKind::Plain:
      addPlainAckState(conn);
      break;
    case TimestampAckKind::LegacyReceiveTimestamps:
      addAckReceiveTimestampState(conn);
      break;
    case TimestampAckKind::Draft02ReceiveTimestamps:
      addAckReceiveTimestampState(
          conn, AckReceiveTimestampsVersion::DraftIetf02);
      break;
    case TimestampAckKind::ExtendedReceiveTimestamps:
      addAckReceiveTimestampState(conn);
      conn.negotiatedExtendedAckFeatures =
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
      break;
  }

  auto stream = createStream(conn);
  writeDataToStream(conn, stream, "some data");
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "timestampAckPolicy")
                                     .ackFrames()
                                     .streamFrames()
                                     .timestampFrames())
                                 .build();
  const auto writableBytes = static_cast<uint32_t>(conn.udpSendPacketLen);
  RegularQuicPacketBuilder builder(
      writableBytes,
      ShortHeader(
          ProtectionType::KeyPhaseOne,
          conn.clientConnectionId.value_or(getTestConnectionId()),
          getNextPacketNum(conn, PacketNumberSpace::AppData)),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result =
      scheduler.scheduleFramesForPacket(std::move(builder), writableBytes);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  EXPECT_EQ(
      countTimestampFrames(result->packet->packet.frames),
      testCase.expectedTimestamp ? 1 : 0);
  const auto* ackFrame = result->packet->packet.frames[0].asWriteAckFrame();
  ASSERT_NE(ackFrame, nullptr);
  if (ackFrame == nullptr) {
    return;
  }
  EXPECT_EQ(ackFrame->frameType, testCase.expectedAckType);
}

INSTANTIATE_TEST_SUITE_P(
    AckEncodingPolicy,
    TimestampAckPolicyTest,
    testing::Values(
        TimestampAckPolicyCase{
            "PlainAckSuppressionOn",
            TimestampAckKind::Plain,
            true,
            true,
            FrameType::ACK},
        TimestampAckPolicyCase{
            "LegacySuppressionOn",
            TimestampAckKind::LegacyReceiveTimestamps,
            true,
            false,
            FrameType::ACK_RECEIVE_TIMESTAMPS},
        TimestampAckPolicyCase{
            "LegacySuppressionOff",
            TimestampAckKind::LegacyReceiveTimestamps,
            false,
            true,
            FrameType::ACK_RECEIVE_TIMESTAMPS},
        TimestampAckPolicyCase{
            "Draft02SuppressionOn",
            TimestampAckKind::Draft02ReceiveTimestamps,
            true,
            false,
            FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02},
        TimestampAckPolicyCase{
            "Draft02SuppressionOff",
            TimestampAckKind::Draft02ReceiveTimestamps,
            false,
            true,
            FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02},
        TimestampAckPolicyCase{
            "ExtendedSuppressionOn",
            TimestampAckKind::ExtendedReceiveTimestamps,
            true,
            false,
            FrameType::ACK_EXTENDED},
        TimestampAckPolicyCase{
            "ExtendedSuppressionOff",
            TimestampAckKind::ExtendedReceiveTimestamps,
            false,
            true,
            FrameType::ACK_EXTENDED}),
    [](const testing::TestParamInfo<TimestampAckPolicyCase>& info) {
      return info.param.name;
    });

TEST_P(TimestampAckOnlyPolicyTest, AppliesSelectionToAckOnlyPackets) {
  const auto& testCase = GetParam();
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.oneRttTimestampFrameWriteMode = testCase.mode;
  if (testCase.packetSelection) {
    conn.transportSettings.oneRttTimestampFramePacketSelection =
        *testCase.packetSelection;
  }
  conn.peerTimestampFrameState.canReceive = true;
  conn.connectionTime = Clock::now() - std::chrono::milliseconds(5);

  FrameScheduler scheduler = [&] {
    if (testCase.frame == TimestampAckOnlyFrame::Ack) {
      conn.ackStates.appDataAckState.largestRecvdPacketTime = Clock::now();
      conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
      conn.ackStates.appDataAckState.acks.insert(10);
      return std::move(
                 FrameScheduler::Builder(
                     conn,
                     EncryptionLevel::AppData,
                     PacketNumberSpace::AppData,
                     "timestampAckOnlyPolicy")
                     .ackFrames()
                     .timestampFrames())
          .build();
    }
    conn.pendingEvents.requestImmediateAck = true;
    return std::move(
               FrameScheduler::Builder(
                   conn,
                   EncryptionLevel::AppData,
                   PacketNumberSpace::AppData,
                   "timestampImmediateAckPolicy")
                   .immediateAckFrames()
                   .timestampFrames())
        .build();
  }();
  const auto writableBytes = static_cast<uint32_t>(conn.udpSendPacketLen);
  RegularQuicPacketBuilder builder(
      writableBytes,
      ShortHeader(
          ProtectionType::KeyPhaseOne,
          conn.clientConnectionId.value_or(getTestConnectionId()),
          getNextPacketNum(conn, PacketNumberSpace::AppData)),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder),
      testCase.frame == TimestampAckOnlyFrame::Ack ? 0 : writableBytes);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  EXPECT_EQ(
      countTimestampFrames(result->packet->packet.frames),
      testCase.expectedTimestamp ? 1 : 0);
  EXPECT_EQ(
      std::count_if(
          result->packet->packet.frames.begin(),
          result->packet->packet.frames.end(),
          [&](const QuicWriteFrame& frame) {
            return testCase.frame == TimestampAckOnlyFrame::Ack
                ? frame.asWriteAckFrame() != nullptr
                : frame.asImmediateAckFrame() != nullptr;
          }),
      1);
}

INSTANTIATE_TEST_SUITE_P(
    AckOnlySelectionPolicy,
    TimestampAckOnlyPolicyTest,
    testing::Values(
        TimestampAckOnlyPolicyCase{
            "AckDefaultAllEligibleOpportunistic",
            TimestampAckOnlyFrame::Ack,
            TimestampFrameWriteMode::Opportunistic,
            std::nullopt,
            true},
        TimestampAckOnlyPolicyCase{
            "AckAckEliciting",
            TimestampAckOnlyFrame::Ack,
            TimestampFrameWriteMode::Prioritized,
            TimestampFramePacketSelection::AckElicitingPackets,
            false},
        TimestampAckOnlyPolicyCase{
            "AckStream",
            TimestampAckOnlyFrame::Ack,
            TimestampFrameWriteMode::Prioritized,
            TimestampFramePacketSelection::StreamPackets,
            false},
        TimestampAckOnlyPolicyCase{
            "ImmediateAckAllEligible",
            TimestampAckOnlyFrame::ImmediateAck,
            TimestampFrameWriteMode::Prioritized,
            TimestampFramePacketSelection::AllEligiblePackets,
            true},
        TimestampAckOnlyPolicyCase{
            "ImmediateAckAckEliciting",
            TimestampAckOnlyFrame::ImmediateAck,
            TimestampFrameWriteMode::Prioritized,
            TimestampFramePacketSelection::AckElicitingPackets,
            true},
        TimestampAckOnlyPolicyCase{
            "ImmediateAckStream",
            TimestampAckOnlyFrame::ImmediateAck,
            TimestampFrameWriteMode::Prioritized,
            TimestampFramePacketSelection::StreamPackets,
            false}),
    [](const testing::TestParamInfo<TimestampAckOnlyPolicyCase>& info) {
      return info.param.name;
    });

TEST_P(TimestampCapacityPolicyTest, AppliesWriteModeWhenCarrierFillsPacket) {
  const auto& testCase = GetParam();
  auto connPtr = createConn(10, 100000, 100000);
  ASSERT_NE(connPtr, nullptr);
  if (connPtr == nullptr) {
    return;
  }
  auto& conn = *connPtr;
  conn.transportSettings.oneRttTimestampFrameWriteMode = testCase.mode;
  conn.peerTimestampFrameState.canReceive = true;
  conn.connectionTime = testCase.validClock
      ? Clock::now() - std::chrono::milliseconds(5)
      : Clock::now() + std::chrono::seconds(1);

  auto stream = createStream(conn);
  if (testCase.fillPacket) {
    writeDataToStream(
        conn, stream, buildRandomInputData(conn.udpSendPacketLen * 2));
  } else {
    writeDataToStream(conn, stream, "some data");
  }
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "timestampCapacityPolicy")
                                     .streamFrames()
                                     .timestampFrames())
                                 .build();
  const auto writableBytes = static_cast<uint32_t>(conn.udpSendPacketLen);
  RegularQuicPacketBuilder builder(
      writableBytes,
      ShortHeader(
          ProtectionType::KeyPhaseOne,
          conn.clientConnectionId.value_or(getTestConnectionId()),
          getNextPacketNum(conn, PacketNumberSpace::AppData)),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  auto result =
      scheduler.scheduleFramesForPacket(std::move(builder), writableBytes);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->packet.has_value());
  EXPECT_TRUE(
      std::any_of(
          result->packet->packet.frames.begin(),
          result->packet->packet.frames.end(),
          [](const auto& frame) {
            return frame.asWriteStreamFrame() != nullptr;
          }));
  EXPECT_EQ(
      countTimestampFrames(result->packet->packet.frames),
      testCase.expectedTimestamp ? 1 : 0);
}

INSTANTIATE_TEST_SUITE_P(
    WriteModeAndSpacePolicy,
    TimestampCapacityPolicyTest,
    testing::Values(
        TimestampCapacityPolicyCase{
            "DisabledWithSpace",
            TimestampFrameWriteMode::Disabled,
            false,
            true,
            false},
        TimestampCapacityPolicyCase{
            "OpportunisticWithSpace",
            TimestampFrameWriteMode::Opportunistic,
            false,
            true,
            true},
        TimestampCapacityPolicyCase{
            "OpportunisticPacketFull",
            TimestampFrameWriteMode::Opportunistic,
            true,
            true,
            false},
        TimestampCapacityPolicyCase{
            "PrioritizedWithSpace",
            TimestampFrameWriteMode::Prioritized,
            false,
            true,
            true},
        TimestampCapacityPolicyCase{
            "PrioritizedPacketFull",
            TimestampFrameWriteMode::Prioritized,
            true,
            true,
            true},
        TimestampCapacityPolicyCase{
            "PrioritizedInvalidClock",
            TimestampFrameWriteMode::Prioritized,
            false,
            false,
            false}),
    [](const testing::TestParamInfo<TimestampCapacityPolicyCase>& info) {
      return info.param.name;
    });

TEST_P(
    QuicPacketSchedulerTest,
    PrioritizedTimestampReservationDoesNotSuppressOnlyFittingDatagram) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Prioritized;
  conn.peerTimestampFrameState.canReceive = true;
  conn.datagramState.maxWriteFrameSize = std::numeric_limits<uint16_t>::max();

  constexpr uint64_t kDatagramPayloadSize = 1;
  (void)conn.datagramState.flowManager.addDatagram(
      folly::IOBuf::copyBuffer("d"), kDefaultDatagramFlowId);

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "tinyDatagramTimestampScheduler")
                                     .datagramFrames()
                                     .timestampFrames())
                                 .build();

  const auto connId = getTestConnectionId();
  const auto packetNum = getNextPacketNum(conn, PacketNumberSpace::AppData);
  const auto largestAcked =
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0);
  const auto packetNumberEncoding = encodePacketNumber(packetNum, largestAcked);
  const auto datagramFrameSize = kDatagramFrameTypeSize +
      getQuicIntegerSize(kDatagramPayloadSize).value() + kDatagramPayloadSize;
  const auto writableBytes = static_cast<uint32_t>(
      1 + connId.size() + packetNumberEncoding.length + datagramFrameSize);

  ShortHeader header(ProtectionType::KeyPhaseOne, connId, packetNum);
  RegularQuicPacketBuilder builder(
      static_cast<uint32_t>(conn.udpSendPacketLen),
      std::move(header),
      largestAcked);
  auto result =
      scheduler.scheduleFramesForPacket(std::move(builder), writableBytes);

  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(result->packet.has_value());
  EXPECT_EQ(countTimestampFrames(result->packet->packet.frames), 0);
  ASSERT_EQ(result->packet->packet.frames.size(), 1);
  EXPECT_NE(result->packet->packet.frames[0].asDatagramFrame(), nullptr);
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 0);
}

TEST_P(QuicPacketSchedulerTest, LargestAckToSend) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  EXPECT_EQ(std::nullopt, largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(std::nullopt, largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(std::nullopt, largestAckToSend(conn.ackStates.appDataAckState));

  conn.ackStates.initialAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(0, 50);
  conn.ackStates.handshakeAckState->acks.insert(75, 150);

  EXPECT_EQ(50, *largestAckToSend(*conn.ackStates.initialAckState));
  EXPECT_EQ(150, *largestAckToSend(*conn.ackStates.handshakeAckState));
  EXPECT_EQ(std::nullopt, largestAckToSend(conn.ackStates.appDataAckState));
}

TEST_P(QuicPacketSchedulerTest, NeedsToSendAckWithoutAcksAvailable) {
  // This covers the scheduler behavior when an IMMEDIATE_ACK frame is received.
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  AckScheduler initialAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Initial));
  AckScheduler handshakeAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::Handshake));
  AckScheduler appDataAckScheduler(
      conn, getAckState(conn, PacketNumberSpace::AppData));
  EXPECT_FALSE(initialAckScheduler.hasPendingAcks());
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());
  EXPECT_FALSE(appDataAckScheduler.hasPendingAcks());

  conn.ackStates.initialAckState->needsToSendAckImmediately = true;
  conn.ackStates.handshakeAckState->needsToSendAckImmediately = true;
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;

  conn.ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(initialAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->acks.insert(0, 100);
  conn.ackStates.handshakeAckState->largestAckScheduled = 200;
  EXPECT_FALSE(handshakeAckScheduler.hasPendingAcks());

  conn.ackStates.handshakeAckState->largestAckScheduled = std::nullopt;
  EXPECT_TRUE(handshakeAckScheduler.hasPendingAcks());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerAllFit) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto f1 = writeDataToStream(conn, stream1, "some data");
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  auto builder = setupMockPacketBuilder();
  auto result4 = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result4.hasError());

  verifyStreamFrames(*builder, {f1, f2, f3});
  EXPECT_TRUE(conn.streamManager->writeQueue().empty());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobin) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // write a normal size packet from stream1
  auto builder = createPacketBuilder(conn);
  auto result = scheduler.writeStreams(builder);
  ASSERT_FALSE(result.hasError());

  // Should write frames for stream2, stream3, followed by stream1 again.
  auto builder2 = setupMockPacketBuilder();
  auto result2 = scheduler.writeStreams(*builder2);
  ASSERT_FALSE(result2.hasError());
  verifyStreamFrames(*builder2, {f2, f3, f1});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinStreamPerPacket) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.streamFramePerPacket = true;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder = createPacketBuilder(conn);
  ASSERT_FALSE(scheduler.writeStreams(builder).hasError());
  EXPECT_EQ(nextScheduledStreamID(conn), stream2);

  // Should write frames for stream2, stream3, followed by stream1 again.
  auto builder2 = setupMockPacketBuilder();
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());
  verifyStreamFrames(*builder2, {f2});
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());
  verifyStreamFrames(*builder2, {f3});
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());
  verifyStreamFrames(*builder2, {f1});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerSequential) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn, HTTPPriorityQueue::Priority(0, false));
  auto stream2 = createStream(conn, HTTPPriorityQueue::Priority(0, false));
  auto stream3 = createStream(conn, HTTPPriorityQueue::Priority(0, false));

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder1 = createPacketBuilder(conn);
  auto result = scheduler.writeStreams(builder1);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(nextScheduledStreamID(conn), stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  auto builder2 = setupMockPacketBuilder();
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());

  verifyStreamFrames(*builder2, {f1, f2, f3});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerSequentialDefault) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.defaultPriority =
      HTTPPriorityQueue::Priority(0, false);
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");

  // Write a normal size packet from stream1
  auto builder1 = createPacketBuilder(conn);
  auto result = scheduler.writeStreams(builder1);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(nextScheduledStreamID(conn), stream1);

  // Should write frames for stream1, stream2, stream3, in that order.
  auto builder2 = setupMockPacketBuilder();
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());

  verifyStreamFrames(*builder2, {f1, f2, f3});
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRoundRobinControl) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);
  auto stream3 = createStream(conn);
  auto stream4 = createStream(conn);

  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream2));
  conn.streamManager->setStreamAsControl(
      *conn.streamManager->findStream(stream4));

  auto largeBuf = createLargeBuffer(conn.udpSendPacketLen * 2);
  auto f1 = writeDataToStream(conn, stream1, std::move(largeBuf));
  auto f2 = writeDataToStream(conn, stream2, "some data");
  auto f3 = writeDataToStream(conn, stream3, "some data");
  auto f4 = writeDataToStream(conn, stream4, "some data");

  // This writes a normal size packet with 2, 4, 1
  auto builder1 = createPacketBuilder(conn);
  auto result = scheduler.writeStreams(builder1);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(nextScheduledStreamID(conn), stream3);
  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);

  // 2 and 4 did not get removed from writable, so they get repeated here
  // Should write frames for stream2, stream4, followed by stream 3 then 1.
  auto builder2 = setupMockPacketBuilder();
  ASSERT_FALSE(scheduler.writeStreams(*builder2).hasError());

  verifyStreamFrames(*builder2, {f2, f4, f3, f1});

  EXPECT_EQ(conn.schedulingState.nextScheduledControlStream, stream2);
  EXPECT_TRUE(conn.streamManager->writeQueue().empty());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerOneStream) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  writeDataToStream(conn, stream1, "some data");

  auto builder1 = createPacketBuilder(conn);
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());

  EXPECT_TRUE(conn.streamManager->writeQueue().empty());
}

TEST_P(QuicPacketSchedulerTest, StreamFrameSchedulerRemoveOne) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto stream1 = createStream(conn);
  auto stream2 = createStream(conn);

  auto f1 = writeDataToStream(conn, stream1, "some data");
  auto f2 = writeDataToStream(conn, stream2, "some data");

  auto builder = setupMockPacketBuilder();
  auto result4 = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result4.hasError());

  verifyStreamFrames(*builder, {f1, f2});

  // Manually remove a stream and set the next scheduled to that stream.
  conn.streamManager->removeWritable(*conn.streamManager->findStream(stream1));
  // the queue is empty, reload it
  conn.streamManager->updateWritableStreams(
      *conn.streamManager->findStream(stream2));

  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(builder->frames_.size(), 1);
  verifyStreamFrames(*builder, {f2});
}

TEST_P(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderDoNotEncodeHeaderWithoutBuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "Little Hurry", 0);
  addOutstandingPacket(conn);
  // There needs to have retransmittable frame for the rebuilder to work
  conn.outstandings.packets.back().packet.frames.push_back(
      MaxDataFrame(conn.flowControlState.advertisedMaxOffset));
  // Lie about the encodedSize to let the Cloner skip it:
  conn.outstandings.packets.back().metadata.encodedSize =
      kDefaultUDPSendPacketLen * 2;
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result.value().clonedPacketIdentifier.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_P(
    QuicPacketSchedulerTest,
    CloningSchedulerWithInplaceBuilderRollbackBufWhenFailToRebuild) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  BufAccessor bufAccessor(2000);
  auto buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
  bufAccessor.release(std::move(buf));
  conn.bufAccessor = &bufAccessor;

  FrameScheduler noopScheduler("frame", conn);
  ASSERT_FALSE(noopScheduler.hasData());
  CloningScheduler cloningScheduler(noopScheduler, conn, "HotPot", 0);
  addOutstandingPacket(conn);
  // Not adding frame to this outstanding packet so that rebuild will fail:
  ASSERT_TRUE(conn.outstandings.packets.back().packet.frames.empty());
  EXPECT_TRUE(cloningScheduler.hasData());

  ASSERT_FALSE(noopScheduler.hasData());
  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  InplaceQuicPacketBuilder builder(
      bufAccessor,
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto result = cloningScheduler.scheduleFramesForPacket(
      std::move(builder), kDefaultUDPSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result.value().clonedPacketIdentifier.has_value());

  // Nothing was written into the buffer:
  EXPECT_TRUE(bufAccessor.ownsBuffer());
  buf = bufAccessor.obtain();
  EXPECT_EQ(buf->length(), 0);
}

TEST_P(QuicPacketSchedulerTest, HighPriNewDataBeforeLowPriLossData) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto lowPriStreamId =
      createStream(conn, HTTPPriorityQueue::Priority(5, false));
  auto highPriStreamId =
      createStream(conn, HTTPPriorityQueue::Priority(0, false));

  writeDataToStream(conn, lowPriStreamId, "Onegin");
  writeDataToStream(
      conn, highPriStreamId, buildRandomInputData(conn.udpSendPacketLen * 10));

  auto builder1 = createPacketBuilder(conn);
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());

  auto packet = std::move(builder1).buildPacket().packet;
  EXPECT_EQ(1, packet.frames.size());
  auto& writeStreamFrame = *packet.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame.streamId);
}

TEST_P(QuicPacketSchedulerTest, UnifiedSendBufferWritesChainedNewData) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->usesUnifiedSendBuffer());

  auto data = folly::IOBuf::copyBuffer("abc");
  data->appendToChain(folly::IOBuf::copyBuffer("def"));
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());

  std::string writtenData;
  auto builder = setupMockPacketBuilder();
  EXPECT_CALL(*builder, _insertRange(_))
      .WillRepeatedly([&writtenData](ByteRange range) {
        writtenData.append(
            reinterpret_cast<const char*>(range.data()), range.size());
      });

  StreamFrameScheduler scheduler(conn);
  ASSERT_FALSE(scheduler.writeStreams(*builder).hasError());

  verifyStreamFrames(*builder, {WriteStreamFrame(streamId, 0, 6, true)});
  EXPECT_EQ(writtenData, "abcdef");
  EXPECT_EQ(stream->streamSendBuffer->nextUnsentOffset(), 0);
}

TEST_P(QuicPacketSchedulerTest, UnifiedSendBufferWritesFinOnly) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 0, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->usesUnifiedSendBuffer());
  ASSERT_FALSE(writeDataToQuicStream(*stream, nullptr, true).hasError());

  auto builder = setupMockPacketBuilder();
  EXPECT_CALL(*builder, _insertRange(_)).Times(0);

  StreamFrameScheduler scheduler(conn);
  ASSERT_FALSE(scheduler.writeStreams(*builder).hasError());

  verifyStreamFrames(*builder, {WriteStreamFrame(streamId, 0, 0, true)});
}

TEST_P(QuicPacketSchedulerTest, UnifiedSendBufferWritesAllLossBeforeNewData) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->usesUnifiedSendBuffer());
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("abcdefghi"), false)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 6, .fin = false}));
  stream->streamSendBuffer->markLoss({.offset = 0, .len = 2, .fin = false});
  stream->streamSendBuffer->markLoss({.offset = 4, .len = 2, .fin = false});
  conn.streamManager->updateWritableStreams(*stream);

  std::string writtenData;
  auto builder = setupMockPacketBuilder();
  EXPECT_CALL(*builder, _insertRange(_))
      .WillRepeatedly([&writtenData](ByteRange range) {
        writtenData.append(
            reinterpret_cast<const char*>(range.data()), range.size());
      });

  StreamFrameScheduler scheduler(conn);
  ASSERT_FALSE(scheduler.writeStreams(*builder).hasError());

  verifyStreamFrames(
      *builder,
      {
          WriteStreamFrame(streamId, 0, 2, false),
          WriteStreamFrame(streamId, 4, 2, false),
          WriteStreamFrame(streamId, 6, 3, false),
      });
  EXPECT_EQ(writtenData, "abefghi");
  const StreamSendBuffer::SendRange expectedLoss{
      .offset = 0, .len = 2, .fin = false};
  const StreamSendBuffer::SendRange expectedNewData{
      .offset = 6, .len = 3, .fin = false};
  EXPECT_EQ(stream->streamSendBuffer->nextLoss(100), expectedLoss);
  EXPECT_EQ(stream->streamSendBuffer->nextNewData(100), expectedNewData);
}

TEST_P(
    QuicPacketSchedulerTest,
    UnifiedSendBufferWritesLossWithoutConnectionFlowControl) {
  transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto connPtr = createConn(10, 0, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = createStream(conn);
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);
  ASSERT_TRUE(stream->usesUnifiedSendBuffer());
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("lossnew"), false)
          .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 4, .fin = false}));
  stream->streamSendBuffer->markLoss({.offset = 0, .len = 4, .fin = false});
  conn.streamManager->updateWritableStreams(*stream);

  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ASSERT_FALSE(scheduler.writeStreams(*builder).hasError());

  verifyStreamFrames(*builder, {WriteStreamFrame(streamId, 0, 4, false)});
  EXPECT_FALSE(conn.streamManager->hasWritable());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.streamManager->onMaxData();
  EXPECT_TRUE(conn.streamManager->hasWritable());
}

TEST_P(QuicPacketSchedulerTest, WriteLossWithoutFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;
  initializePathManagerState(conn);

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());
  conn.streamManager->updateWritableStreams(*stream);

  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packet1,
          Clock::now(),
          1000,
          0)
          .hasError());
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->pendingWrites.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  // Move the bytes to loss buffer:
  stream->lossBuffer.emplace_back(std::move(*stream->retransmissionBuffer[0]));
  stream->retransmissionBuffer.clear();
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_TRUE(scheduler.hasPendingData());

  // Write again
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  ASSERT_FALSE(scheduler.writeStreams(builder2).hasError());
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packet2,
          Clock::now(),
          1000,
          0)
          .hasError());
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, WriteLossWithoutFlowControlSequential) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;
  initializePathManagerState(conn);

  auto streamId = (*conn.streamManager->createNextBidirectionalStream())->id;
  conn.streamManager->setStreamPriority(
      streamId, HTTPPriorityQueue::Priority(0, false));
  auto stream = conn.streamManager->findStream(streamId);
  auto data = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), true).hasError());
  conn.streamManager->updateWritableStreams(*stream);

  StreamFrameScheduler scheduler(conn);
  EXPECT_TRUE(scheduler.hasPendingData());
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packet1,
          Clock::now(),
          1000,
          0)
          .hasError());
  EXPECT_EQ(1, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream->pendingWrites.chainLength());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());

  // Move the bytes to loss buffer:
  stream->lossBuffer.emplace_back(std::move(*stream->retransmissionBuffer[0]));
  stream->retransmissionBuffer.clear();
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_TRUE(scheduler.hasPendingData());

  // Write again
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder2.encodePacketHeader().hasError());
  ASSERT_FALSE(scheduler.writeStreams(builder2).hasError());
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packet2,
          Clock::now(),
          1000,
          0)
          .hasError());
  EXPECT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame2 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId, writeStreamFrame2.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, MultipleStreamsRunOutOfFlowControl) {
  auto connPtr = createConn(10, 1000, 2000, GetParam());
  auto& conn = *connPtr;
  conn.udpSendPacketLen = 2000;

  auto highPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto lowPriStreamId =
      (*conn.streamManager->createNextBidirectionalStream())->id;
  auto highPriStream = conn.streamManager->findStream(highPriStreamId);
  auto lowPriStream = conn.streamManager->findStream(lowPriStreamId);

  // Write new data to high priority stream in excess of max data
  auto newData = buildRandomInputData(2000);
  ASSERT_TRUE(writeDataToQuicStream(*highPriStream, std::move(newData), true));
  conn.streamManager->updateWritableStreams(
      *highPriStream, /*connFlowControlOpen=*/true);

  // Fake a loss data for low priority stream
  lowPriStream->currentWriteOffset = 201;
  auto lossData = buildRandomInputData(200);
  lowPriStream->lossBuffer.emplace_back(
      ChainedByteRangeHead(lossData), 0, true);
  conn.streamManager->updateWritableStreams(
      *lowPriStream, /*connFlowControlOpen=*/true);

  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(builder1.encodePacketHeader());
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_TRUE(updateConnection(
      conn,
      *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
      std::nullopt,
      packet1,
      Clock::now(),
      1200,
      0));
  ASSERT_EQ(2, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(1000, highPriStream->pendingWrites.chainLength());
  EXPECT_EQ(1, highPriStream->retransmissionBuffer.size());
  EXPECT_EQ(1000, highPriStream->retransmissionBuffer[0]->data.chainLength());

  auto& writeStreamFrame2 = *packet1.frames[1].asWriteStreamFrame();
  EXPECT_EQ(lowPriStreamId, writeStreamFrame2.streamId);
  EXPECT_EQ(200, writeStreamFrame2.len);
  EXPECT_TRUE(lowPriStream->lossBuffer.empty());
  EXPECT_EQ(1, lowPriStream->retransmissionBuffer.size());
  EXPECT_EQ(200, lowPriStream->retransmissionBuffer[0]->data.chainLength());

  // Simulate additional flow control granted
  conn.flowControlState.peerAdvertisedMaxOffset = 2000;
  conn.streamManager->onMaxData();
  // Don't need to call updateWritableStreams, onMaxData updates the state for
  // any stream blocked on conn flow control

  // Write remaining data for high priority stream
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_TRUE(builder2.encodePacketHeader());
  ASSERT_FALSE(scheduler.writeStreams(builder2).hasError());
  auto packet2 = std::move(builder2).buildPacket().packet;
  ASSERT_TRUE(updateConnection(
      conn,
      *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
      std::nullopt,
      packet2,
      Clock::now(),
      1000,
      0));
  ASSERT_EQ(1, packet2.frames.size());
  auto& writeStreamFrame3 = *packet2.frames[0].asWriteStreamFrame();
  EXPECT_EQ(highPriStreamId, writeStreamFrame3.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(
      1000, highPriStream->retransmissionBuffer[1000]->data.chainLength());
  EXPECT_EQ(1000, writeStreamFrame3.len);
}

TEST_P(QuicPacketSchedulerTest, RunOutFlowControlDuringStreamWrite) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 1000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 1000;
  conn.udpSendPacketLen = 2000;
  initializePathManagerState(conn);

  auto streamId1 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto streamId2 = (*conn.streamManager->createNextBidirectionalStream())->id;
  auto stream1 = conn.streamManager->findStream(streamId1);
  auto stream2 = conn.streamManager->findStream(streamId2);
  auto newData = buildRandomInputData(1000);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, std::move(newData), true).hasError());
  conn.streamManager->updateWritableStreams(*stream1);

  // Fake a loss data for stream2:
  stream2->currentWriteOffset = 201;
  auto lossData = buildRandomInputData(200);
  stream2->lossBuffer.emplace_back(ChainedByteRangeHead(lossData), 0, true);
  conn.streamManager->updateWritableStreams(*stream2);

  StreamFrameScheduler scheduler(conn);
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero,
      getTestConnectionId(),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder1.encodePacketHeader().hasError());
  ASSERT_FALSE(scheduler.writeStreams(builder1).hasError());
  auto packet1 = std::move(builder1).buildPacket().packet;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packet1,
          Clock::now(),
          1200,
          0)
          .hasError());
  ASSERT_EQ(2, packet1.frames.size());
  auto& writeStreamFrame1 = *packet1.frames[0].asWriteStreamFrame();
  EXPECT_EQ(streamId1, writeStreamFrame1.streamId);
  EXPECT_EQ(0, getSendConnFlowControlBytesWire(conn));
  EXPECT_EQ(0, stream1->pendingWrites.chainLength());
  EXPECT_EQ(1, stream1->retransmissionBuffer.size());
  EXPECT_EQ(1000, stream1->retransmissionBuffer[0]->data.chainLength());

  auto& writeStreamFrame2 = *packet1.frames[1].asWriteStreamFrame();
  EXPECT_EQ(streamId2, writeStreamFrame2.streamId);
  EXPECT_EQ(200, writeStreamFrame2.len);
  EXPECT_TRUE(stream2->lossBuffer.empty());
  EXPECT_EQ(1, stream2->retransmissionBuffer.size());
  EXPECT_EQ(200, stream2->retransmissionBuffer[0]->data.chainLength());
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerMultipleFramesPerPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = false;
  DatagramFrameScheduler scheduler(conn);
  // Add datagrams
  std::string s1(conn.udpSendPacketLen / 3, '*');
  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer(s1));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1), kDefaultDatagramFlowId);
  std::string s2(conn.udpSendPacketLen / 3, '%');
  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer(s2));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2), kDefaultDatagramFlowId);
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(2)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  // Call scheduler
  auto& frames = builder.frames_;
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 2);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerOneFramePerPacket) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = true;
  DatagramFrameScheduler scheduler(conn);
  // Add datagrams
  std::string s1(conn.udpSendPacketLen / 3, '*');
  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer(s1));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1), kDefaultDatagramFlowId);
  std::string s2(conn.udpSendPacketLen / 3, '%');
  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer(s2));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2), kDefaultDatagramFlowId);
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  // Call scheduler
  auto& frames = builder.frames_;
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 1);
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 2);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameWriteWhenRoomAvailable) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = true;
  DatagramFrameScheduler scheduler(conn);
  // Add datagram
  std::string s(conn.udpSendPacketLen / 3, '*');
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer(s));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf), kDefaultDatagramFlowId);
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt())
      .WillRepeatedly(Return(conn.udpSendPacketLen / 4));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  // Call scheduler
  auto& frames = builder.frames_;
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 0);
  EXPECT_CALL(builder, remainingSpaceInPkt())
      .WillRepeatedly(Return(conn.udpSendPacketLen / 2));
  EXPECT_CALL(quicStats, onDatagramWrite(_))
      .Times(1)
      .WillRepeatedly(Invoke([](uint64_t bytes) { EXPECT_GT(bytes, 0); }));
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  ASSERT_EQ(frames.size(), 1);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerDrainsNonDefaultFlow) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = false;
  DatagramFrameScheduler scheduler(conn);
  // Nothing on the default flow; both datagrams live on a named flow.
  constexpr uint32_t kNamedFlowId = 7;
  std::string s1(conn.udpSendPacketLen / 3, '*');
  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer(s1));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1), kNamedFlowId);
  std::string s2(conn.udpSendPacketLen / 3, '%');
  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer(s2));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2), kNamedFlowId);
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  EXPECT_CALL(quicStats, onDatagramWrite(_)).Times(2);
  auto& frames = builder.frames_;
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  EXPECT_EQ(frames.size(), 2);
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 0);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerDrainsAllFlows) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = false;
  DatagramFrameScheduler scheduler(conn);
  // One datagram on the default flow and one on each of two named flows.
  for (uint32_t flowId : {kDefaultDatagramFlowId, 7u, 9u}) {
    std::string s(conn.udpSendPacketLen / 8, '*');
    BufQueue buf;
    buf.append(folly::IOBuf::copyBuffer(s));
    (void)conn.datagramState.flowManager.addDatagram(std::move(buf), flowId);
  }
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly(Invoke([&](auto f) {
    builder.frames_.push_back(f);
  }));
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  EXPECT_CALL(quicStats, onDatagramWrite(_)).Times(3);
  auto& frames = builder.frames_;
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());
  EXPECT_EQ(frames.size(), 3);
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 0);
}

TEST_P(QuicPacketSchedulerTest, DatagramFrameSchedulerStatsExpiredDatagrams) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState.maxReadFrameSize = std::numeric_limits<uint16_t>::max();
  conn.datagramState.maxReadBufferSize = 10;
  conn.transportSettings.datagramConfig.framePerPacket = false;
  DatagramFrameScheduler scheduler(conn);
  // Two datagrams that will age out before the scheduler runs.
  constexpr uint32_t kFlowId = 7;
  auto maxQueueTime = std::chrono::milliseconds(1);
  for (char fill : {'*', '%'}) {
    std::string s(conn.udpSendPacketLen / 8, fill);
    BufQueue buf;
    buf.append(folly::IOBuf::copyBuffer(s));
    (void)conn.datagramState.flowManager.addDatagram(
        std::move(buf), kFlowId, std::nullopt, false, maxQueueTime);
  }
  NiceMock<MockQuicPacketBuilder> builder;
  EXPECT_CALL(builder, remainingSpaceInPkt()).WillRepeatedly(Return(4096));
  EXPECT_CALL(builder, appendFrame(_)).WillRepeatedly([&](const auto& f) {
    builder.frames_.push_back(f);
  });
  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;
  EXPECT_CALL(quicStats, onDatagramWrite(_)).Times(0);
  EXPECT_CALL(quicStats, onDatagramDroppedOnWrite()).Times(2);

  /* sleep override */
  std::this_thread::sleep_for(maxQueueTime * 5);
  ASSERT_FALSE(scheduler.writeDatagramFrames(builder).hasError());

  EXPECT_TRUE(builder.frames_.empty());
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 0);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingWithSpaceForPadding) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  size_t paddingModulo = 16;
  conn.transportSettings.paddingModulo = paddingModulo;
  // create enough input data to partially fill packet
  size_t inputDataLength1 = conn.udpSendPacketLen / 2;
  size_t inputDataLength2 = inputDataLength1 + 1;
  auto inputData1 = buildRandomInputData(inputDataLength1);
  auto inputData2 = buildRandomInputData(inputDataLength2);

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();

  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(shortHeader1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(shortHeader2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  DatagramFrame frame1(inputDataLength1, std::move(inputData1));
  DatagramFrame frame2(inputDataLength2, std::move(inputData2));
  ASSERT_FALSE(writeFrame(frame1, builder1).hasError());
  ASSERT_FALSE(writeFrame(frame2, builder2).hasError());

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result1 = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen);
  ASSERT_FALSE(result1.hasError());
  EXPECT_GT(result1.value().shortHeaderPadding, 0);
  auto result2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen);
  ASSERT_FALSE(result2.hasError());
  EXPECT_GT(result2.value().shortHeaderPadding, 0);

  auto headerLength1 = result1.value().packet->header.computeChainDataLength();
  auto bodyLength1 = result1.value().packet->body.computeChainDataLength();
  auto packetLength1 = headerLength1 + bodyLength1;
  auto expectedPadding1 =
      (conn.udpSendPacketLen - (inputDataLength1 + headerLength1)) %
      paddingModulo;

  auto headerLength2 = result2.value().packet->header.computeChainDataLength();
  auto bodyLength2 = result2.value().packet->body.computeChainDataLength();
  auto packetLength2 = headerLength2 + bodyLength2;
  auto expectedPadding2 =
      (conn.udpSendPacketLen - (inputDataLength2 + headerLength2)) %
      paddingModulo;

  EXPECT_EQ(packetLength1, headerLength1 + inputDataLength1 + expectedPadding1);
  EXPECT_EQ(packetLength2, headerLength2 + inputDataLength2 + expectedPadding2);
  // ensure two similar size input data get padded up to same length
  EXPECT_EQ(packetLength1, packetLength2);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderFixedPaddingAtStart) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.fixedShortHeaderPadding = 2;
  conn.transportSettings.paddingModulo = 16;
  conn.flowControlState.peerAdvertisedMaxOffset = 1000000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      1000000;

  // Create stream and write data
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto data = buildRandomInputData(50); // Small enough to fit in one packet
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), false).hasError());

  // Set up scheduler and builder
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Schedule frames
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());

  // Verify padding frames were added at start
  EXPECT_TRUE(result.value().packet.has_value());
  const auto& frames = result.value().packet->packet.frames;
  ASSERT_EQ(frames.size(), 3);
  EXPECT_TRUE(frames[0].asPaddingFrame());
  EXPECT_TRUE(frames[1].asWriteStreamFrame());
  EXPECT_TRUE(frames[2].asPaddingFrame());
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingNearMaxPacketLength) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  size_t paddingModulo = 50;
  conn.transportSettings.paddingModulo = paddingModulo;
  // create enough input data to almost fill packet
  size_t inputDataLength = conn.udpSendPacketLen - 20;
  auto inputData = buildRandomInputData(inputDataLength);

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  DatagramFrame frame(inputDataLength, std::move(inputData));
  ASSERT_FALSE(writeFrame(frame, builder).hasError());

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_GT(result.value().shortHeaderPadding, 0);

  auto headerLength = result.value().packet->header.computeChainDataLength();
  auto bodyLength = result.value().packet->body.computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  auto expectedPadding =
      (conn.udpSendPacketLen - (inputDataLength + headerLength)) %
      paddingModulo;

  EXPECT_EQ(packetLength, headerLength + inputDataLength + expectedPadding);
  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, ShortHeaderPaddingMaxPacketLength) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.udpSendPacketLen = 1000;
  size_t paddingModulo = 50;
  conn.transportSettings.paddingModulo = paddingModulo;

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  size_t largestAckedPacketNum =
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0);
  auto packetNumberEncoding = encodePacketNumber(
      shortHeader.getPacketSequenceNum(), largestAckedPacketNum);
  auto connectionIdSize = shortHeader.getConnectionId().size();

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(shortHeader), largestAckedPacketNum);

  // create enough input data to fully fill packet
  while (builder.remainingSpaceInPkt() >
         connectionIdSize + packetNumberEncoding.length + 1) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }

  NiceMock<MockQuicStats> quicStats;
  conn.statsCallback = &quicStats;

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(result.value().shortHeaderPadding, 0);

  auto headerLength = result.value().packet->header.computeChainDataLength();
  auto bodyLength = result.value().packet->body.computeChainDataLength();

  auto packetLength = headerLength + bodyLength;

  EXPECT_EQ(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerOnRequest) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.pendingEvents.requestImmediateAck = true;
  auto connId = getTestConnectionId();

  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));

  FrameScheduler immediateAckOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "ImmediateAckOnlyScheduler")
              .immediateAckFrames())
          .build();

  auto result =
      std::move(immediateAckOnlyScheduler)
          .scheduleFramesForPacket(std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(conn.udpSendPacketLen, packetLength);
}

TEST_P(QuicPacketSchedulerTest, ImmediateAckFrameSchedulerNotRequested) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.pendingEvents.requestImmediateAck = false;
  auto connId = getTestConnectionId();

  LongHeader longHeader(
      LongHeader::Types::Initial,
      getTestConnectionId(1),
      connId,
      getNextPacketNum(conn, PacketNumberSpace::Initial),
      QuicVersion::MVFST);
  increaseNextPacketNum(conn, PacketNumberSpace::Initial);

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(longHeader),
      conn.ackStates.initialAckState->largestAckedByPeer.value_or(0));

  FrameScheduler immediateAckOnlyScheduler =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::Initial,
              LongHeader::typeToPacketNumberSpace(LongHeader::Types::Initial),
              "ImmediateAckOnlyScheduler")
              .immediateAckFrames())
          .build();

  auto result =
      std::move(immediateAckOnlyScheduler)
          .scheduleFramesForPacket(std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());
  auto packetLength = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  // The immediate ACK scheduler was not triggered. This packet has no
  // frames and it shouldn't get padded.
  EXPECT_LT(packetLength, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, RstStreamSchedulerReliableReset) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  initializePathManagerState(conn);
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("cupcake");
  auto bufLen = buf->computeChainDataLength();
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), false).hasError());

  // Reliable reset with reliableSize = bufLen
  conn.pendingEvents.resets.emplace(
      stream->id, RstStreamFrame(stream->id, 0, bufLen, bufLen));

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames()
                                     .resetFrames())
                                 .build();
  auto cipherOverhead = 16;
  PacketNum packetNum1 = 0;
  ShortHeader header1(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum1);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(header1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult1 = scheduler.scheduleFramesForPacket(
      std::move(builder1), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(packetResult1.hasError());
  auto encodedSize1 =
      packetResult1.value().packet->body.computeChainDataLength() +
      packetResult1.value().packet->header.computeChainDataLength() +
      cipherOverhead;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packetResult1.value().packet->packet,
          Clock::now(),
          encodedSize1,
          0)
          .hasError());

  // We shouldn't send the reliable reset just yet, because we haven't yet
  // egressed all the stream data upto the reliable offset.
  EXPECT_TRUE(conn.pendingEvents.resets.contains(stream->id));

  PacketNum packetNum2 = 1;
  ShortHeader header2(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      packetNum2);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(header2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  auto packetResult2 = scheduler.scheduleFramesForPacket(
      std::move(builder2), conn.udpSendPacketLen - cipherOverhead);
  ASSERT_FALSE(packetResult2.hasError());
  auto encodedSize2 =
      packetResult1.value().packet->body.computeChainDataLength() +
      packetResult2.value().packet->header.computeChainDataLength() +
      cipherOverhead;
  ASSERT_FALSE(
      updateConnection(
          conn,
          *MVCHECK_NOTNULL(conn.pathManager->getPath(conn.currentPathId)),
          std::nullopt,
          packetResult2.value().packet->packet,
          Clock::now(),
          encodedSize2,
          0)
          .hasError());

  // Now we should have egressed all the stream data upto the reliable offset,
  // so we should have sent the reliable reset.
  EXPECT_FALSE(conn.pendingEvents.resets.contains(stream->id));
}

TEST_P(QuicPacketSchedulerTest, UnifiedRstSchedulerWaitsForReliableData) {
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  auto data = folly::IOBuf::copyBuffer("cupcake");
  const auto dataLen = data->computeChainDataLength();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), false).hasError());
  conn.pendingEvents.resets.emplace(
      stream->id, RstStreamFrame(stream->id, 0, dataLen, dataLen));
  RstStreamScheduler scheduler(conn);

  auto blockedBuilder = setupMockPacketBuilder();
  auto blockedResult = scheduler.writeRsts(*blockedBuilder);
  ASSERT_FALSE(blockedResult.hasError());
  EXPECT_FALSE(blockedResult.value());
  EXPECT_TRUE(blockedBuilder->frames_.empty());

  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, dataLen, false}));
  auto readyBuilder = setupMockPacketBuilder();
  auto readyResult = scheduler.writeRsts(*readyBuilder);
  ASSERT_FALSE(readyResult.hasError());
  EXPECT_TRUE(readyResult.value());
  ASSERT_EQ(readyBuilder->frames_.size(), 1);
  EXPECT_NE(readyBuilder->frames_.front().asRstStreamFrame(), nullptr);
}

TEST_P(QuicPacketSchedulerTest, PausedPriorityEnabled) {
  static const auto kSequentialPriority = HTTPPriorityQueue::Priority(3, false);
  static const HTTPPriorityQueue::Priority kPausedPriority =
      HTTPPriorityQueue::Priority::PAUSED;

  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto pausedStreamId = createStream(conn, kPausedPriority);
  auto regularStreamId = createStream(conn, kSequentialPriority);

  auto pausedFrame = writeDataToStream(conn, pausedStreamId, "paused_data");
  auto regularFrame = writeDataToStream(conn, regularStreamId, "regular_data");

  // Should write frames for only regular stream.
  auto builder = setupMockPacketBuilder();
  auto result4 = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result4.hasError());

  verifyStreamFrames(*builder, {regularFrame});

  conn.streamManager->removeWritable(
      *conn.streamManager->findStream(regularStreamId));

  // Unpause the stream. Expect the scheduleor to write the data.
  conn.streamManager->setStreamPriority(pausedStreamId, kSequentialPriority);
  auto result2 = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result2.hasError());

  verifyStreamFrames(*builder, {pausedFrame});

  // Pause the stream again. Expect no more data writable.
  conn.streamManager->setStreamPriority(pausedStreamId, kPausedPriority);
  ASSERT_FALSE(conn.streamManager->hasWritable());
}

TEST_P(QuicPacketSchedulerTest, PausedPriorityDisabled) {
  static const auto kSequentialPriority = HTTPPriorityQueue::Priority(3, false);
  static const HTTPPriorityQueue::Priority kPausedPriority =
      HTTPPriorityQueue::Priority::PAUSED;

  transportSettings.disablePausedPriority = true;
  auto connPtr = createConn(10, 100000, 100000, GetParam());
  auto& conn = *connPtr;
  StreamFrameScheduler scheduler(conn);

  auto pausedStreamId = createStream(conn, kPausedPriority);
  auto regularStreamId = createStream(conn, kSequentialPriority);

  auto pausedFrame = writeDataToStream(conn, pausedStreamId, "paused_data");
  auto regularFrame = writeDataToStream(conn, regularStreamId, "regular_data");

  auto builder = setupMockPacketBuilder();
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());
  verifyStreamFrames(*builder, {regularFrame, pausedFrame});
}

TEST_P(QuicPacketSchedulerTest, FixedShortHeaderPadding) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.transportSettings.fixedShortHeaderPadding = 2;
  conn.transportSettings.paddingModulo = 0;
  conn.flowControlState.peerAdvertisedMaxOffset = 1000000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      1000000;

  // Create stream and write data
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto data = buildRandomInputData(50); // Small enough to fit in one packet
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(data), false).hasError());
  conn.streamManager->updateWritableStreams(*stream);

  // Set up scheduler and builder
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "streamScheduler")
                                     .streamFrames())
                                 .build();

  ShortHeader header(
      ProtectionType::KeyPhaseOne,
      conn.clientConnectionId.value_or(getTestConnectionId()),
      getNextPacketNum(conn, PacketNumberSpace::AppData));

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(header),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  // Schedule frames
  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());

  // Verify padding frames were added
  // at start
  EXPECT_TRUE(result.value().packet.has_value());
  const auto& frames = result.value().packet->packet.frames;
  ASSERT_EQ(frames.size(), 2);
  EXPECT_TRUE(frames[0].asPaddingFrame());
  EXPECT_TRUE(frames[1].asWriteStreamFrame());
}

// This test class sets up a connection with all the fields that can be included
// in an ACK. The fixtures for this class confirm that the scheduler writes the
// correct frame type and fields enabled by the connection state.
class QuicAckSchedulerTest : public QuicPacketSchedulerTestBase, public Test {
 protected:
  QuicAckSchedulerTest()
      : conn_(createConn(10, 100000, 100000)),
        ackState_(getAckState(*conn_, PacketNumberSpace::AppData)),
        builder_(setupMockPacketBuilder()) {}

  void SetUp() override {
    // One ack block
    ackState_.acks.insert(1, 10);

    // One receive timestamps
    WriteAckFrameState::ReceivedPacket rpi;
    rpi.pktNum = 10;
    rpi.timings.receiveTimePoint = Clock::now();
    auto receiveTime = rpi.timings.receiveTimePoint;
    ackState_.recvdPacketInfos.emplace_back(std::move(rpi));
    ackState_.largestRecvdPacketNum = 10;
    ackState_.largestRecvdPacketTime = receiveTime;

    // Non-zero ECN values
    ackState_.ecnECT0CountReceived = 1;
    ackState_.ecnECT1CountReceived = 2;
    ackState_.ecnCECountReceived = 3;

    auto connId = getTestConnectionId();
    mockPacketHeader_ = std::make_unique<PacketHeader>(ShortHeader(
        ProtectionType::KeyPhaseZero,
        connId,
        getNextPacketNum(*conn_, PacketNumberSpace::AppData)));

    EXPECT_CALL(*builder_, getPacketHeader())
        .WillRepeatedly(ReturnRef(*mockPacketHeader_));
  }

  std::unique_ptr<QuicClientConnectionState> conn_;
  AckState& ackState_;
  std::unique_ptr<MockQuicPacketBuilder> builder_;
  std::unique_ptr<PacketHeader> mockPacketHeader_;
};

TEST_F(QuicAckSchedulerTest, DefaultAckFrame) {
  // Default config writes ACK frame.
  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, WriteAckEcnWhenReadingEcnOnEgress) {
  conn_->transportSettings.readEcnOnIngress = true;

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, WriteAckReceiveTimestampsWhenEnabled) {
  conn_->transportSettings.readEcnOnIngress = false;

  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  updateNegotiatedAckFeatures(*conn_);
  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckEcnTakesPrecedenceOverReceiveTimestamps) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfNotSupported) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures =
      3; // ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures = 0;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfNotEnabled) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures = 0;
  conn_->peerAdvertisedExtendedAckFeatures = 3; // ECN + ReceiveTimestamps;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(
    QuicAckSchedulerTest,
    AckExtendedNotSentIfReceiveTimestampFeatureNotSupported) {
  conn_->transportSettings.readEcnOnIngress = true;

  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      2; // Peer supports ReceiveTimestamps but not ECN in extended ack
  // Peer sent ART config
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  // We don't have an ART config (i.e. we can't sent ART)
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      std::nullopt;
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_ECN);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedNotSentIfECNFeatureNotSupported) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      1; // Peer supports ECN but not ReceiveTimestamps in extended ack

  // ART support negotiated
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckExtendedWithAllFeatures) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      3; // Peer supports ECN + ReceiveTimestamps

  // ART support negotiated
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, AckExtendedTakesPrecedenceOverECN) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      2; // Peer supports extended ack with only ReceiveTimestamps

  // ART support negotiated
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->recvdPacketsTimestampRanges[0].timestamp_delta_count, 1);

  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
  EXPECT_EQ(ackFrame->ecnECT1Count, 0);
  EXPECT_EQ(ackFrame->ecnCECount, 0);
}

TEST_F(QuicAckSchedulerTest, AckExtendedTakesPrecedenceOverReceiveTimestamps) {
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      1; // Peer supports extended ack with only ECN

  // ART support negotiated
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].start, 1);
  EXPECT_EQ(ackFrame->ackBlocks[0].end, 10);

  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, IetfReceiveModeDoesNotWriteLegacyTimestamps) {
  conn_->transportSettings.readEcnOnIngress = false;
  conn_->transportSettings.enableIetfAckReceiveTimestamps = true;

  // Peer requested legacy receive timestamps
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);
  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());
}

TEST_F(
    QuicAckSchedulerTest,
    IetfReceiveModeWritesAckExtendedWithoutTimestamps) {
  conn_->transportSettings.enableIetfAckReceiveTimestamps = true;
  conn_->transportSettings.enableExtendedAckFeatures =
      3; // We support ECN + ReceiveTimestamps
  conn_->peerAdvertisedExtendedAckFeatures =
      3; // Peer supports ECN + ReceiveTimestamps

  // Peer requested legacy receive timestamps
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig();

  // We can read ECN
  conn_->transportSettings.readEcnOnIngress = true;

  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);

  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_EXTENDED);
  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());

  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

// draft-ietf-quic-receive-ts-02 scheduler dispatch. The scheduler emits the
// draft-02 frame type at highest priority when
// `negotiatedOutgoingAckReceiveTimestampsVersion == DraftIetf02`. The `_ECN`
// variant is selected by the same predicate as `ACK_ECN` over `ACK`
// (read-ECN enabled + any ECN count received).

namespace {
void setDraft02PeerReceiveTimestamps(
    QuicClientConnectionState& conn,
    uint64_t max = kMaxReceivedPktsTimestampsStored,
    uint64_t exponent = 0) {
  conn.transportSettings.enableIetfAckReceiveTimestamps = true;
  conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = max,
          .receiveTimestampsExponent = exponent};
  conn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::DraftIetf02,
      .maxReceiveTimestampsPerAck = max,
      .exponent = exponent};
}
} // namespace

TEST_F(QuicAckSchedulerTest, Draft02NegotiatedProducesDraft02Frame) {
  conn_->transportSettings.readEcnOnIngress = false;
  setDraft02PeerReceiveTimestamps(*conn_);
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  EXPECT_TRUE(ackFrame->recvdPacketsTimestampRanges.empty());
  ASSERT_EQ(ackFrame->draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->ecnECT0Count, 0);
}

TEST_F(QuicAckSchedulerTest, Draft02WithEcnProducesDraft02EcnFrame) {
  conn_->transportSettings.readEcnOnIngress = true;
  setDraft02PeerReceiveTimestamps(*conn_);
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(
      ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
  ASSERT_EQ(ackFrame->draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(ackFrame->ecnECT0Count, 1);
  EXPECT_EQ(ackFrame->ecnECT1Count, 2);
  EXPECT_EQ(ackFrame->ecnCECount, 3);
}

TEST_F(QuicAckSchedulerTest, Draft02TakesPrecedenceOverAckExtendedAndAckEcn) {
  // Peer advertises ACK_EXTENDED with ECN+RT bits AND draft-02. Local enables
  // all three. Expected: a single draft-02_ECN frame; no ACK_EXTENDED.
  conn_->transportSettings.readEcnOnIngress = true;
  conn_->transportSettings.enableExtendedAckFeatures = 3;
  conn_->peerAdvertisedExtendedAckFeatures = 3;
  setDraft02PeerReceiveTimestamps(*conn_);
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(
      ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
}

TEST_F(QuicAckSchedulerTest, Draft02NotEmittedWhenLocalKnobDisabled) {
  // Peer advertises draft-02 but local `sendDraft02AckReceiveTimestamps` is
  // off, so the negotiated outgoing version stays None and no draft-02
  // frame is emitted.
  conn_->transportSettings.readEcnOnIngress = false;
  conn_->transportSettings.sendDraft02AckReceiveTimestamps = false;
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::DraftIetf02,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{};
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_NE(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  EXPECT_NE(
      ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);
}

// Per spec, ACK_RECEIVE_TIMESTAMPS frames (draft-02 and legacy mvfst) are
// 1-RTT only. The scheduler must not emit them in Initial/Handshake spaces;
// it falls through to plain ACK / ACK_ECN. Without the space gate this
// crashed `writeAckFrameDraft02`'s DCHECK.
TEST_F(
    QuicAckSchedulerTest,
    Draft02NegotiatedButInitialSpaceFallsBackToPlainAck) {
  conn_->transportSettings.readEcnOnIngress = false;
  setDraft02PeerReceiveTimestamps(*conn_);
  updateNegotiatedAckFeatures(*conn_);
  // Use an Initial-space LongHeader instead of the AppData-space header
  // from `SetUp()`.
  mockPacketHeader_ = std::make_unique<PacketHeader>(LongHeader(
      LongHeader::Types::Initial,
      ConnectionId::createZeroLength(),
      getTestConnectionId(),
      getNextPacketNum(*conn_, PacketNumberSpace::Initial),
      QuicVersion::MVFST));
  EXPECT_CALL(*builder_, getPacketHeader())
      .WillRepeatedly(ReturnRef(*mockPacketHeader_));

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());
  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_EQ(builder_->frames_.size(), 1);
  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);
}

// Inconsistent state: the negotiated outgoing version is draft-02 but the peer
// config is absent. `updateNegotiatedAckFeatures` normally keeps these in
// sync; the scheduler must guard the deref locally and degrade to a plain ACK
// instead of dereferencing a nullopt peer config.
TEST_F(
    QuicAckSchedulerTest,
    Draft02NegotiatedButPeerConfigMissingDegradesToPlainAck) {
  conn_->transportSettings.readEcnOnIngress = false;
  conn_->negotiatedOutgoingAckReceiveTimestampsVersion =
      AckReceiveTimestampsVersion::DraftIetf02;
  conn_->maybePeerReceiveTimestampsConfig = std::nullopt;

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());
  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);
  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_NE(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  EXPECT_NE(
      ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);
}

TEST_F(
    QuicAckSchedulerTest,
    LegacyNegotiatedButHandshakeSpaceFallsBackToPlainAck) {
  conn_->transportSettings.readEcnOnIngress = false;
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{};
  updateNegotiatedAckFeatures(*conn_);
  mockPacketHeader_ = std::make_unique<PacketHeader>(LongHeader(
      LongHeader::Types::Handshake,
      ConnectionId::createZeroLength(),
      getTestConnectionId(),
      getNextPacketNum(*conn_, PacketNumberSpace::Handshake),
      QuicVersion::MVFST));
  EXPECT_CALL(*builder_, getPacketHeader())
      .WillRepeatedly(ReturnRef(*mockPacketHeader_));

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());
  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_EQ(builder_->frames_.size(), 1);
  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK);
}

TEST_F(QuicAckSchedulerTest, LegacyPeerProducesLegacyFrame) {
  // Peer advertises LegacyMvfst (and no draft-02 support); local does not
  // enable draft-02. Scheduler emits the legacy ACK_RECEIVE_TIMESTAMPS frame
  // and sources `peerRequestedTimestampsCount` from the versioned config.
  conn_->transportSettings.readEcnOnIngress = false;
  conn_->maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::LegacyMvfst,
      .maxReceiveTimestampsPerAck = kMaxReceivedPktsTimestampsStored,
      .exponent = 0};
  conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
      AckReceiveTimestampsConfig{};
  updateNegotiatedAckFeatures(*conn_);

  AckScheduler ackScheduler(*conn_, ackState_);
  ASSERT_TRUE(ackScheduler.hasPendingAcks());

  auto writeResult = ackScheduler.writeNextAcks(*builder_);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(writeResult.value() != std::nullopt);
  ASSERT_EQ(builder_->frames_.size(), 1);

  auto ackFrame = builder_->frames_[0].asWriteAckFrame();
  ASSERT_TRUE(ackFrame != nullptr);
  EXPECT_EQ(ackFrame->frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);
  ASSERT_EQ(ackFrame->recvdPacketsTimestampRanges.size(), 1);
}

// Tests for Expected result handling bug fix
// These tests verify that the schedulers correctly handle writeFrame returning
// Expected<size_t, QuicError> where size_t can be 0 (no bytes written) but
// still be successful (no error).

TEST_P(QuicPacketSchedulerTest, RstStreamSchedulerNoSpaceHandling) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  // Set up a stream with pending reset
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  conn.pendingEvents.resets.emplace(
      stream->id, RstStreamFrame(stream->id, 0, 100, 100));

  RstStreamScheduler scheduler(conn);
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // Use PacketBuilderWrapper with very limited space to simulate scenario
  // where writeFrame returns success but 0 bytes written
  PacketBuilderWrapper builderWrapper(builder, 1); // Very limited space

  // Call writeRsts - should handle 0 bytes gracefully when no space available
  auto result = scheduler.writeRsts(builderWrapper);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(result.value()); // Should return false (no RST written)

  // Reset should still be pending since it wasn't written
  EXPECT_TRUE(conn.pendingEvents.resets.contains(stream->id));
}

TEST_P(QuicPacketSchedulerTest, WindowUpdateSchedulerNoSpaceHandling) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.pendingEvents.connWindowUpdate = true;

  WindowUpdateScheduler scheduler(conn);
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // Use PacketBuilderWrapper with very limited space
  PacketBuilderWrapper builderWrapper(builder, 1);

  // Call writeWindowUpdates - should handle 0 bytes gracefully
  auto result = scheduler.writeWindowUpdates(builderWrapper);
  ASSERT_FALSE(result.hasError());

  // Should still be pending since no bytes were written
  EXPECT_TRUE(conn.pendingEvents.connWindowUpdate);
}

TEST_P(QuicPacketSchedulerTest, BlockedSchedulerNoSpaceHandling) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.pendingEvents.sendDataBlocked = true;

  BlockedScheduler scheduler(conn);
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // Use PacketBuilderWrapper with very limited space
  PacketBuilderWrapper builderWrapper(builder, 1);

  // Call writeBlockedFrames - should handle 0 bytes gracefully and return early
  auto result = scheduler.writeBlockedFrames(builderWrapper);
  ASSERT_FALSE(result.hasError());

  // Should still be pending since no bytes were written
  EXPECT_TRUE(conn.pendingEvents.sendDataBlocked);
}

TEST_P(QuicPacketSchedulerTest, PathValidationHasPendingFrames) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  // Register two real paths so prepareChallengeForSending has somewhere to
  // mint into; the scheduler routes by these path ids.
  auto pathId1Res = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_TRUE(pathId1Res.has_value());
  auto pathId1 = pathId1Res.value();
  auto pathId2Res = conn.pathManager->addPath(
      quic::SocketAddress("::", 33333), quic::SocketAddress("::", 44444));
  ASSERT_TRUE(pathId2Res.has_value());
  auto pathId2 = pathId2Res.value();

  // No entries initially
  PathValidationFrameScheduler scheduler1(conn, pathId1);
  EXPECT_FALSE(scheduler1.hasPendingPathValidationFrames());

  // Add response for a different path; still false for pathId1
  conn.pendingEvents.pathResponses.emplace(
      pathId2, PathResponseFrame(0xdeadbeef));
  EXPECT_FALSE(scheduler1.hasPendingPathValidationFrames());

  // Flag pathId1 for a challenge; becomes true
  conn.pendingEvents.pathChallenges.insert(pathId1);
  EXPECT_TRUE(scheduler1.hasPendingPathValidationFrames());

  // Also true for a scheduler pointed at pathId2 due to response
  PathValidationFrameScheduler scheduler2(conn, pathId2);
  EXPECT_TRUE(scheduler2.hasPendingPathValidationFrames());
}

TEST_P(QuicPacketSchedulerTest, WritePathValidationFramesSpecificPathAndOrder) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  // Register two real paths so the scheduler can mint a challenge for the
  // target path via the path manager.
  auto targetPathRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_TRUE(targetPathRes.has_value());
  auto targetPath = targetPathRes.value();
  auto otherPathRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 33333), quic::SocketAddress("::", 44444));
  ASSERT_TRUE(otherPathRes.has_value());
  auto otherPath = otherPathRes.value();

  // Populate both challenge and response for target path. The challenge
  // payload is minted at write time, so we just flag the path id.
  PathResponseFrame resp(0xbeef);
  conn.pendingEvents.pathResponses.emplace(targetPath, resp);
  conn.pendingEvents.pathChallenges.insert(targetPath);

  // And unrelated entries for another path (should be ignored)
  conn.pendingEvents.pathResponses.emplace(
      otherPath, PathResponseFrame(0x9999));
  conn.pendingEvents.pathChallenges.insert(otherPath);

  auto builder = setupMockPacketBuilder();

  PathValidationFrameScheduler scheduler(conn, targetPath);
  ASSERT_TRUE(scheduler.hasPendingPathValidationFrames());
  EXPECT_TRUE(scheduler.writePathValidationFrames(*builder));

  // Expect exactly 2 frames written: PathResponse then PathChallenge (by impl)
  ASSERT_EQ(builder->frames_.size(), 2);
  auto f0 = builder->frames_[0].asQuicSimpleFrame();
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f0->asPathResponseFrame(), nullptr);
  EXPECT_EQ(f0->asPathResponseFrame()->pathData, resp.pathData);

  auto f1 = builder->frames_[1].asQuicSimpleFrame();
  ASSERT_NE(f1, nullptr);
  ASSERT_NE(f1->asPathChallengeFrame(), nullptr);
  // The minted payload should be the one in-flight on the target path.
  auto* path = conn.pathManager->getPath(targetPath);
  ASSERT_NE(path, nullptr);
  ASSERT_EQ(path->outstandingChallenges.size(), 1u);
  EXPECT_EQ(
      f1->asPathChallengeFrame()->pathData,
      path->outstandingChallenges.front().pathData);
}

TEST_P(
    QuicPacketSchedulerTest,
    PathValidationSchedulerDoesNotSpinAfterValidation) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_TRUE(pathIdRes.has_value());
  auto pathId = pathIdRes.value();

  conn.pendingEvents.pathChallenges.insert(pathId);

  auto challengeRes = conn.pathManager->prepareChallengeForSending(pathId);
  ASSERT_TRUE(challengeRes.has_value());
  PathResponseFrame response(challengeRes.value().pathData);
  ASSERT_NE(
      conn.pathManager->onPathResponseReceived(response, pathId), nullptr);

  PathValidationFrameScheduler scheduler(conn, pathId);
  EXPECT_FALSE(scheduler.hasPendingPathValidationFrames());
  auto builder = setupMockPacketBuilder();
  EXPECT_FALSE(scheduler.writePathValidationFrames(*builder));
  EXPECT_TRUE(builder->frames_.empty());
}

TEST_P(QuicPacketSchedulerTest, PathValidationSchedulerRespectsPathId) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  auto pathWithDataRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_TRUE(pathWithDataRes.has_value());
  auto pathWithData = pathWithDataRes.value();
  PathIdType emptyPath = pathWithData + 1; // a path id never registered

  conn.pendingEvents.pathChallenges.insert(pathWithData);

  PathValidationFrameScheduler scheduler(conn, emptyPath);
  EXPECT_FALSE(scheduler.hasPendingPathValidationFrames());
  auto builder = setupMockPacketBuilder();
  EXPECT_FALSE(scheduler.writePathValidationFrames(*builder));
  EXPECT_TRUE(builder->frames_.empty());
}

TEST_P(QuicPacketSchedulerTest, PathValidationCausesPaddingToFullPacket) {
  // Using real builder via FrameScheduler to verify padding behavior
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());

  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_TRUE(pathIdRes.has_value());
  auto pathId = pathIdRes.value();
  conn.pendingEvents.pathChallenges.insert(pathId);

  // Create a short header packet builder (AppData)
  auto connId = getTestConnectionId();
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(conn, PacketNumberSpace::AppData));
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(shortHeader),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "PathValidationScheduler")
                                     .pathValidationFrames(pathId))
                                 .build();

  auto result = scheduler.scheduleFramesForPacket(
      std::move(builder), conn.udpSendPacketLen);
  ASSERT_FALSE(result.hasError());

  // Verify we padded out to full UDP packet length
  auto pktLen = result.value().packet->header.computeChainDataLength() +
      result.value().packet->body.computeChainDataLength();
  EXPECT_EQ(pktLen, conn.udpSendPacketLen);
}

TEST_P(QuicPacketSchedulerTest, DatagramDoubleSchedulerBug) {
  // Regression test for production CHECK failure:
  // "popDatagramIfFits called for flow with no datagrams"
  //
  // Original bug scenario (before fix):
  // 1. When both streamFrames and datagramFrames schedulers are enabled with
  //    scheduleDatagramsWithStreams=true and framePerPacket=true
  // 2. StreamFrameScheduler writes 1 datagram via priority queue, then stops
  // (framePerPacket)
  // 3. DatagramFrameScheduler writes remaining datagram(s), emptying the flow
  // 4. But the flow ID remains in the priority queue
  // 5. Next packet with a stream causes scheduler to try popping from empty
  // flow -> CRASH
  //
  // Fix: Prevent datagramFrameScheduler from running when
  // scheduleDatagramsWithStreams=true, since datagrams are being handled
  // exclusively by streamFrameScheduler via priority queue.

  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.datagramState = QuicConnectionStateBase::DatagramState();
  conn.datagramState.maxWriteFrameSize = std::numeric_limits<uint16_t>::max();

  // Allow stream creation and set flow control
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;

  // Enable both schedulers
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.transportSettings.datagramConfig.framePerPacket =
      true; // KEY: stops after 1 datagram

  // Add 2 small datagrams
  (void)conn.datagramState.flowManager.addDatagram(
      folly::IOBuf::copyBuffer("d1"));
  (void)conn.datagramState.flowManager.addDatagram(
      folly::IOBuf::copyBuffer("d2"));

  // Add to priority queue
  auto dgId =
      PriorityQueue::Identifier::fromDatagramFlowID(kDefaultDatagramFlowId);
  conn.streamManager->writeQueue().insertOrUpdate(
      dgId, kDefaultDatagramPriority);

  // Packet 1: Both schedulers run, consuming both datagrams but leaving flow ID
  // in queue
  auto connId = getTestConnectionId();
  PacketNum pn1 = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header1(ProtectionType::KeyPhaseZero, connId, pn1);
  RegularQuicPacketBuilder builder1(
      conn.udpSendPacketLen,
      std::move(header1),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  FrameScheduler scheduler1 =
      std::move(
          FrameScheduler::Builder(
              conn,
              EncryptionLevel::AppData,
              PacketNumberSpace::AppData,
              "Scheduler1")
              .streamFrames() // Writes 1 datagram via pqueue, stops
              .datagramFrames()) // Writes remaining datagram(s)
          .build();

  ASSERT_FALSE(
      scheduler1
          .scheduleFramesForPacket(std::move(builder1), conn.udpSendPacketLen)
          .hasError());

  // After fix: Only stream scheduler runs (datagram scheduler is disabled).
  // With framePerPacket=true, only 1 datagram is written per packet.
  // So we expect 1 datagram remaining and flow ID still in queue.
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 1);
  EXPECT_TRUE(conn.streamManager->writeQueue().contains(dgId));

  // Packet 2: Write the remaining datagram
  PacketNum pn2 = getNextPacketNum(conn, PacketNumberSpace::AppData);
  ShortHeader header2(ProtectionType::KeyPhaseZero, connId, pn2);
  RegularQuicPacketBuilder builder2(
      conn.udpSendPacketLen,
      std::move(header2),
      conn.ackStates.appDataAckState.largestAckedByPeer.value_or(0));

  FrameScheduler scheduler2 = std::move(
                                  FrameScheduler::Builder(
                                      conn,
                                      EncryptionLevel::AppData,
                                      PacketNumberSpace::AppData,
                                      "Scheduler2")
                                      .streamFrames())
                                  .build();

  ASSERT_FALSE(
      scheduler2
          .scheduleFramesForPacket(std::move(builder2), conn.udpSendPacketLen)
          .hasError());

  // After packet 2: All datagrams written, flow ID removed from queue
  EXPECT_EQ(conn.datagramState.flowManager.getDatagramCount(), 0);
  EXPECT_FALSE(conn.streamManager->writeQueue().contains(dgId));
}

TEST_F(QuicPacketSchedulerTest, DatagramFlowPriorityScheduling) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn);

  // Create a stream with priority 3
  auto streamId = createStream(conn, HTTPPriorityQueue::Priority(3, false));

  // Write some data to the stream
  writeDataToStream(conn, streamId, "stream data");

  // Create a datagram flow with priority 7 (lower priority than stream)
  uint32_t datagramFlowId = 100;
  BufQueue datagramBuf;
  datagramBuf.append(folly::IOBuf::copyBuffer("datagram data"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(datagramBuf), datagramFlowId);
  (void)conn.datagramState.flowManager.setFlowPriority(
      datagramFlowId, HTTPPriorityQueue::Priority(7, false));
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(datagramFlowId),
      HTTPPriorityQueue::Priority(7, false));

  // Build a packet and verify stream data is sent first (higher priority)
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // First frame should be from the stream (priority 3), not the datagram
  // (priority 7)
  bool foundStreamFrame = false;
  bool foundDatagramFrame = false;
  for (const auto& frame : builder->frames_) {
    if (frame.asWriteStreamFrame()) {
      foundStreamFrame = true;
      // Stream should come before datagram due to higher priority
      EXPECT_FALSE(foundDatagramFrame);
    } else if (frame.asDatagramFrame()) {
      foundDatagramFrame = true;
    }
  }

  EXPECT_TRUE(foundStreamFrame);
}

TEST_F(QuicPacketSchedulerTest, MultipleDatagramFlowsWithPriorities) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn);

  HTTPPriorityQueue::Priority highPri(1, false);
  HTTPPriorityQueue::Priority midPri(5, false);
  HTTPPriorityQueue::Priority lowPri(9, false);

  // Create three datagram flows with different priorities
  uint32_t highPriorityFlow = 100;
  uint32_t midPriorityFlow = 200;
  uint32_t lowPriorityFlow = 300;

  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer("high priority datagram"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1), highPriorityFlow);
  (void)conn.datagramState.flowManager.setFlowPriority(
      highPriorityFlow, highPri);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(highPriorityFlow), highPri);

  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer("mid priority datagram"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2), midPriorityFlow);
  (void)conn.datagramState.flowManager.setFlowPriority(midPriorityFlow, midPri);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(midPriorityFlow), midPri);

  BufQueue buf3;
  buf3.append(folly::IOBuf::copyBuffer("low priority datagram"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf3), lowPriorityFlow);
  (void)conn.datagramState.flowManager.setFlowPriority(lowPriorityFlow, lowPri);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(lowPriorityFlow), lowPri);

  // Schedule and verify high priority datagram is scheduled first
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Should have scheduled the high priority datagram first
  ASSERT_GE(builder->frames_.size(), 1);
  EXPECT_TRUE(builder->frames_[0].asDatagramFrame());
}

TEST_F(QuicPacketSchedulerTest, InterleavedStreamsAndDatagramsRespectPriority) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn, /*maxWriteFrameSize=*/100);

  HTTPPriorityQueue::Priority pri1(1, false);
  HTTPPriorityQueue::Priority pri3(3, false);
  HTTPPriorityQueue::Priority pri5(5, false);
  HTTPPriorityQueue::Priority pri7(7, false);

  // Create interleaved streams and datagram flows with different priorities
  // Priority order: stream1(1) > datagram100(3) > stream2(5) > datagram200(7)

  auto stream1 = createStream(conn, pri1);
  writeDataToStream(conn, stream1, "s1");

  auto stream2 = createStream(conn, pri5);
  writeDataToStream(conn, stream2, "s2");

  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer("d1"));
  (void)conn.datagramState.flowManager.addDatagram(std::move(buf1), 100);
  (void)conn.datagramState.flowManager.setFlowPriority(100, pri3);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(100), pri3);

  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer("d2"));
  (void)conn.datagramState.flowManager.addDatagram(std::move(buf2), 200);
  (void)conn.datagramState.flowManager.setFlowPriority(200, pri7);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(200), pri7);

  // Schedule and verify correct ordering
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Verify we got frames in priority order
  ASSERT_GE(builder->frames_.size(), 1);
  // First should be stream1 (priority 1)
  if (builder->frames_[0].asWriteStreamFrame()) {
    EXPECT_EQ(stream1, builder->frames_[0].asWriteStreamFrame()->streamId);
  }
}

TEST_F(QuicPacketSchedulerTest, DatagramFlowCloseNowDropsPendingDatagrams) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn);

  uint32_t flowId = 100;

  // Add multiple datagrams to the flow
  for (int i = 0; i < 3; ++i) {
    BufQueue buf;
    buf.append(folly::IOBuf::copyBuffer("datagram " + std::to_string(i)));
    (void)conn.datagramState.flowManager.addDatagram(std::move(buf), flowId);
  }

  EXPECT_EQ(3, conn.datagramState.flowManager.getDatagramCount());
  EXPECT_TRUE(conn.datagramState.flowManager.hasDatagramsForFlow(flowId));

  // Close the flow
  auto result = conn.datagramState.flowManager.closeFlowNow(flowId);
  ASSERT_TRUE(result.has_value());

  // All datagrams should be dropped
  EXPECT_EQ(0, conn.datagramState.flowManager.getDatagramCount());
  EXPECT_FALSE(conn.datagramState.flowManager.hasDatagramsForFlow(flowId));
}

TEST_F(QuicPacketSchedulerTest, CloseNonExistentDatagramFlowReturnsError) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.datagramConfig.enabled = true;
  conn.datagramState.maxWriteFrameSize = 1000;

  // Try to close a non-existent flow
  auto result = conn.datagramState.flowManager.closeFlow(999);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(QuicPacketSchedulerTest, SetPriorityOnNonExistentFlowReturnsError) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.transportSettings.datagramConfig.enabled = true;
  conn.datagramState.maxWriteFrameSize = 1000;

  HTTPPriorityQueue::Priority pri(5, false);
  auto result = conn.datagramState.flowManager.setFlowPriority(999, pri);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(QuicPacketSchedulerTest, DatagramFlowPriorityCanBeUpdated) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn);

  uint32_t flowId = 100;
  HTTPPriorityQueue::Priority initialPri(7, false);
  HTTPPriorityQueue::Priority newPri(3, false);

  // Add datagram with initial priority
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer("datagram"));
  (void)conn.datagramState.flowManager.addDatagram(std::move(buf), flowId);
  (void)conn.datagramState.flowManager.setFlowPriority(flowId, initialPri);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(flowId), initialPri);

  // Update priority
  auto result = conn.datagramState.flowManager.setFlowPriority(flowId, newPri);
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(result.value()); // Flow should not be empty

  // Update in priority queue too
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(flowId), newPri);

  // Datagram should still be there with new priority
  EXPECT_TRUE(conn.datagramState.flowManager.hasDatagramsForFlow(flowId));
}

TEST_F(QuicPacketSchedulerTest, ClosingFlowWithDatagramsRemovesFromQueue) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  setupDatagramFlowConn(conn);

  uint32_t flow1 = 100;
  uint32_t flow2 = 200;

  // Add datagrams to two flows
  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer("flow1-data"));
  (void)conn.datagramState.flowManager.addDatagram(std::move(buf1), flow1);

  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer("flow2-data"));
  (void)conn.datagramState.flowManager.addDatagram(std::move(buf2), flow2);

  EXPECT_EQ(2, conn.datagramState.flowManager.getDatagramCount());

  // Close flow1
  auto result = conn.datagramState.flowManager.closeFlowNow(flow1);
  ASSERT_TRUE(result.has_value());

  // flow1 should be gone, flow2 should remain
  EXPECT_EQ(1, conn.datagramState.flowManager.getDatagramCount());
  EXPECT_FALSE(conn.datagramState.flowManager.hasDatagramsForFlow(flow1));
  EXPECT_TRUE(conn.datagramState.flowManager.hasDatagramsForFlow(flow2));
}

TEST_F(QuicPacketSchedulerTest, EphemeralDatagramFlowCleanup) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.datagramConfig.enabled = true;
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.datagramState.maxWriteFrameSize = 1000;
  conn.datagramState.maxWriteBufferSize = 100;

  // Create an ephemeral flow with priority 5
  uint32_t ephemeralFlowId = 0; // Ephemeral flows count up from 0
  BufQueue datagramBuf;
  datagramBuf.append(folly::IOBuf::copyBuffer("ephemeral datagram"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(datagramBuf),
      ephemeralFlowId,
      HTTPPriorityQueue::Priority(5, false),
      true /* ephemeral */);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(ephemeralFlowId),
      HTTPPriorityQueue::Priority(5, false));

  // Verify flow exists
  EXPECT_EQ(conn.datagramState.flowManager.getFlowCount(), 1);
  EXPECT_TRUE(conn.datagramState.flowManager.isFlowDraining(ephemeralFlowId));

  // Write the datagram
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Verify datagram was written
  bool foundDatagramFrame = false;
  for (const auto& frame : builder->frames_) {
    if (frame.asDatagramFrame()) {
      foundDatagramFrame = true;
    }
  }
  EXPECT_TRUE(foundDatagramFrame);

  // Verify ephemeral flow was cleaned up (removed from writeBuffer)
  EXPECT_EQ(conn.datagramState.flowManager.getFlowCount(), 0);
}

TEST_F(QuicPacketSchedulerTest, MultipleEphemeralFlowsWithPriorities) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.datagramConfig.enabled = true;
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.datagramState.maxWriteFrameSize = 1000;
  conn.datagramState.maxWriteBufferSize = 100;

  // Create three ephemeral flows with different priorities
  uint32_t highPriFlow = 0;
  uint32_t midPriFlow = 1;
  uint32_t lowPriFlow = 2;

  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer("high"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1),
      highPriFlow,
      HTTPPriorityQueue::Priority(1, false),
      true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(highPriFlow),
      HTTPPriorityQueue::Priority(1, false));

  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer("mid"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2), midPriFlow, HTTPPriorityQueue::Priority(5, false), true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(midPriFlow),
      HTTPPriorityQueue::Priority(5, false));

  BufQueue buf3;
  buf3.append(folly::IOBuf::copyBuffer("low"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf3), lowPriFlow, HTTPPriorityQueue::Priority(9, false), true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(lowPriFlow),
      HTTPPriorityQueue::Priority(9, false));

  EXPECT_EQ(3, conn.datagramState.flowManager.getFlowCount());

  // Schedule - should send all datagrams and clean up all flows
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Verify at least one datagram was sent
  bool foundDatagramFrame = false;
  for (const auto& frame : builder->frames_) {
    if (frame.asDatagramFrame()) {
      foundDatagramFrame = true;
    }
  }
  EXPECT_TRUE(foundDatagramFrame);

  // Note: In a single packet builder call, we may not send all datagrams
  // The test verifies cleanup happens correctly for what was sent
}

TEST_F(QuicPacketSchedulerTest, EphemeralFlowNotCleanedWhenNotSent) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.datagramConfig.enabled = true;
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.datagramState.maxWriteFrameSize = 50; // Small size
  conn.datagramState.maxWriteBufferSize = 100;

  // Create ephemeral flow with a datagram that won't fit
  uint32_t ephemeralFlowId = 0;
  std::string largeData(1000, 'x'); // Large datagram
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer(largeData));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf),
      ephemeralFlowId,
      HTTPPriorityQueue::Priority(5, false),
      true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(ephemeralFlowId),
      HTTPPriorityQueue::Priority(5, false));

  EXPECT_EQ(1, conn.datagramState.flowManager.getFlowCount());
  EXPECT_TRUE(conn.datagramState.flowManager.isFlowDraining(ephemeralFlowId));

  // Try to schedule - datagram won't fit
  auto builder = setupMockPacketBuilder();
  EXPECT_CALL(*builder, remainingSpaceInPkt()).WillRepeatedly(Return(100));
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);

  // Ephemeral flow should still exist (not sent, so not cleaned up)
  EXPECT_EQ(1, conn.datagramState.flowManager.getFlowCount());
  EXPECT_EQ(1, conn.datagramState.flowManager.getDatagramCount());
  EXPECT_TRUE(conn.datagramState.flowManager.isFlowDraining(ephemeralFlowId));
}

TEST_F(QuicPacketSchedulerTest, MixedEphemeralAndPersistentFlows) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.datagramConfig.enabled = true;
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.datagramState.maxWriteFrameSize = 1000;
  conn.datagramState.maxWriteBufferSize = 100;

  // Create ephemeral flow
  uint32_t ephemeralFlow = 0;
  BufQueue buf1;
  buf1.append(folly::IOBuf::copyBuffer("ephemeral"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf1),
      ephemeralFlow,
      HTTPPriorityQueue::Priority(5, false),
      true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(ephemeralFlow),
      HTTPPriorityQueue::Priority(5, false));

  // Create persistent flow
  uint32_t persistentFlow = 100;
  BufQueue buf2;
  buf2.append(folly::IOBuf::copyBuffer("persistent"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf2),
      persistentFlow,
      HTTPPriorityQueue::Priority(5, false),
      false);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(persistentFlow),
      HTTPPriorityQueue::Priority(5, false));

  EXPECT_EQ(2, conn.datagramState.flowManager.getFlowCount());
  EXPECT_TRUE(conn.datagramState.flowManager.isFlowDraining(ephemeralFlow));
  EXPECT_FALSE(conn.datagramState.flowManager.isFlowDraining(persistentFlow));

  // Schedule datagrams
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Verify datagrams were sent
  int datagramCount = 0;
  for (const auto& frame : builder->frames_) {
    if (frame.asDatagramFrame()) {
      datagramCount++;
    }
  }
  EXPECT_GT(datagramCount, 0);

  // Check which flows were cleaned up based on what was sent
  // Ephemeral flows get cleaned when empty, persistent flows don't
  if (!conn.datagramState.flowManager.hasDatagramsForFlow(ephemeralFlow)) {
    // Ephemeral was sent and cleaned up
    EXPECT_FALSE(conn.datagramState.flowManager.isFlowDraining(
        ephemeralFlow)); // Doesn't exist
  }
  if (!conn.datagramState.flowManager.hasDatagramsForFlow(persistentFlow)) {
    // Persistent was sent but still exists
    EXPECT_FALSE(conn.datagramState.flowManager.isFlowDraining(persistentFlow));
  }
}

TEST_F(QuicPacketSchedulerTest, EphemeralFlowWithStreamInterleaving) {
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  conn.streamManager->setMaxLocalBidirectionalStreams(10).value();
  conn.flowControlState.peerAdvertisedMaxOffset = 100000;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote = 100000;
  conn.transportSettings.datagramConfig.enabled = true;
  conn.transportSettings.datagramConfig.scheduleDatagramsWithStreams = true;
  conn.datagramState.maxWriteFrameSize = 1000;
  conn.datagramState.maxWriteBufferSize = 100;

  // Create stream with priority 3
  auto streamId = createStream(conn, HTTPPriorityQueue::Priority(3, false));
  writeDataToStream(conn, streamId, "stream data");

  // Create ephemeral datagram flow with priority 5 (lower than stream)
  uint32_t ephemeralFlowId = 0;
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer("ephemeral"));
  (void)conn.datagramState.flowManager.addDatagram(
      std::move(buf),
      ephemeralFlowId,
      HTTPPriorityQueue::Priority(5, false),
      true);
  conn.streamManager->writeQueue().insertOrUpdate(
      PriorityQueue::Identifier::fromDatagramFlowID(ephemeralFlowId),
      HTTPPriorityQueue::Priority(5, false));

  EXPECT_EQ(1, conn.datagramState.flowManager.getFlowCount());

  // Schedule - stream should be sent first, then datagram
  auto builder = setupMockPacketBuilder();
  StreamFrameScheduler scheduler(conn);
  auto result = scheduler.writeStreams(*builder);
  ASSERT_FALSE(result.hasError());

  // Verify both were sent
  bool foundStream = false;
  bool foundDatagram = false;
  for (const auto& frame : builder->frames_) {
    if (frame.asWriteStreamFrame()) {
      foundStream = true;
      // Stream should come before datagram
      EXPECT_FALSE(foundDatagram);
    } else if (frame.asDatagramFrame()) {
      foundDatagram = true;
    }
  }

  EXPECT_TRUE(foundStream);
  EXPECT_TRUE(foundDatagram);

  // Ephemeral flow should be cleaned up
  EXPECT_EQ(0, conn.datagramState.flowManager.getFlowCount());
}

INSTANTIATE_TEST_SUITE_P(
    QuicPacketSchedulerTest,
    QuicPacketSchedulerTest,
    ::testing::Values(true));

} // namespace quic::test
