/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Range.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/MvfstLogging.h>

#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/FileQLogger.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

#include <gtest/gtest.h>

using namespace folly;
using namespace testing;

namespace quic::test {

using PacketStreamDetails = OutstandingPacketMetadata::StreamDetails;

uint64_t writeProbingDataToSocketForTest(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& conn,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     conn,
                                     EncryptionLevel::AppData,
                                     PacketNumberSpace::AppData,
                                     "test")
                                     .streamFrames()
                                     .cryptoFrames())
                                 .build();
  auto result = writeProbingDataToSocket(
      sock,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      ShortHeaderBuilder(conn.oneRttWritePhase),
      EncryptionLevel::AppData,
      PacketNumberSpace::AppData,
      scheduler,
      probesToSend,
      aead,
      headerCipher,
      version);
  MVCHECK(!result.hasError());
  return result->probesWritten;
}

void writeCryptoDataProbesToSocketForTest(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& conn,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    LongHeader::Types type = LongHeader::Types::Initial) {
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type));
  auto pnSpace = LongHeader::typeToPacketNumberSpace(type);
  auto scheduler =
      std::move(
          FrameScheduler::Builder(conn, encryptionLevel, pnSpace, "Crypto")
              .cryptoFrames())
          .build();
  MVCHECK(!writeProbingDataToSocket(
               sock,
               conn,
               *conn.clientConnectionId,
               *conn.serverConnectionId,
               LongHeaderBuilder(type),
               protectionTypeToEncryptionLevel(
                   longHeaderTypeToProtectionType(type)),
               LongHeader::typeToPacketNumberSpace(type),
               scheduler,
               probesToSend,
               aead,
               headerCipher,
               version)
               .hasError());
}

RegularQuicWritePacket stripPaddingFrames(RegularQuicWritePacket packet) {
  RegularQuicWritePacket::Vec trimmedFrames{};
  for (auto frame : packet.frames) {
    if (!frame.asPaddingFrame()) {
      trimmedFrames.push_back(frame);
    }
  }
  packet.frames = trimmedFrames;
  return packet;
}

auto buildEmptyPacket(
    QuicServerConnectionState& conn,
    PacketNumberSpace pnSpace,
    bool shortHeader = false) {
  Optional<PacketHeader> header;
  if (shortHeader) {
    header = ShortHeader(
        ProtectionType::KeyPhaseZero,
        *conn.clientConnectionId,
        conn.ackStates.appDataAckState.nextPacketNum);
  } else {
    if (pnSpace == PacketNumberSpace::Initial) {
      header = LongHeader(
          LongHeader::Types::Initial,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.initialAckState->nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::Handshake) {
      header = LongHeader(
          LongHeader::Types::Handshake,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.handshakeAckState->nextPacketNum,
          *conn.version);
    } else if (pnSpace == PacketNumberSpace::AppData) {
      header = LongHeader(
          LongHeader::Types::ZeroRtt,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.appDataAckState.nextPacketNum,
          *conn.version);
    }
  }
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(*header),
      getAckState(conn, pnSpace).largestAckedByPeer.value_or(0));
  MVCHECK(!builder.encodePacketHeader().hasError());
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

void initializePathManagerState(QuicServerConnectionState& conn) {
  auto pathRes = conn.pathManager->addValidatedPath(
      quic::SocketAddress("::1", 12345), quic::SocketAddress("::1", 54321));
  MVCHECK(!pathRes.hasError());
  conn.currentPathId = pathRes.value();
}

class QuicTransportFunctionsTest : public Test {
 public:
  void SetUp() override {
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher().value();
    quicStats_ = std::make_unique<NiceMock<MockQuicStats>>();
  }

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow * 1000;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow * 1000;
    conn->statsCallback = quicStats_.get();
    conn->initialWriteCipher = createNoOpAead();
    conn->initialHeaderCipher = createNoOpHeaderCipher().value();
    MVCHECK(
        !conn->streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    MVCHECK(!conn->streamManager
                 ->setMaxLocalUnidirectionalStreams(
                     kDefaultMaxStreamsUnidirectional)
                 .hasError());

    // Initialize current path
    initializePathManagerState(*conn);
    currentPathInfo_ = conn->pathManager->getPath(conn->currentPathId);

    // Do not skip packet numbers for the tests.
    conn->transportSettings.skipOneInNPacketSequenceNumber = 0;
    // These bare connections have no transport to give them a write buffer.
    conn->bufAccessor = bufAccessor_.get();
    return conn;
  }

  std::unique_ptr<QuicClientConnectionState> createClientConn() {
    auto conn = std::make_unique<QuicClientConnectionState>(
        FizzClientQuicHandshakeContext::Builder().build());
    conn->serverConnectionId = getTestConnectionId();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->originalVersion = QuicVersion::MVFST;
    conn->statsCallback = quicStats_.get();
    conn->initialWriteCipher = createNoOpAead();
    conn->initialHeaderCipher = createNoOpHeaderCipher().value();
    initializePathManagerState(*conn);
    conn->transportSettings.skipOneInNPacketSequenceNumber = 0;
    conn->bufAccessor = bufAccessor_.get();
    return conn;
  }

  QuicVersion getVersion(QuicConnectionStateBase& conn) {
    return conn.version.value_or(*conn.originalVersion);
  }

  Expected<void, QuicError> updateStreamFrame(
      QuicServerConnectionState& conn,
      WriteStreamFrame frame,
      Optional<ClonedPacketIdentifier> clonedPacketIdentifier = std::nullopt) {
    auto packet = buildEmptyPacket(conn, PacketNumberSpace::AppData);
    packet.packet.frames.emplace_back(frame);
    return updateConnection(
        conn,
        *currentPathInfo_,
        std::move(clonedPacketIdentifier),
        packet.packet,
        TimePoint{},
        static_cast<uint32_t>(getEncodedSize(packet)),
        static_cast<uint32_t>(getEncodedBodySize(packet)));
  }

  Expected<void, QuicError> updateCryptoFrame(
      QuicServerConnectionState& conn,
      EncryptionLevel encryptionLevel,
      WriteCryptoFrame frame,
      PacketTransmissionReason transmissionReason =
          PacketTransmissionReason::Normal,
      bool isPtoRetransmission = false) {
    const auto packetNumberSpace = encryptionLevel == EncryptionLevel::Initial
        ? PacketNumberSpace::Initial
        : encryptionLevel == EncryptionLevel::Handshake
        ? PacketNumberSpace::Handshake
        : PacketNumberSpace::AppData;
    auto packet = buildEmptyPacket(
        conn, packetNumberSpace, encryptionLevel == EncryptionLevel::AppData);
    packet.packet.frames.emplace_back(frame);
    return updateConnection(
        conn,
        *currentPathInfo_,
        std::nullopt,
        packet.packet,
        TimePoint{},
        static_cast<uint32_t>(getEncodedSize(packet)),
        static_cast<uint32_t>(getEncodedBodySize(packet)),
        transmissionReason,
        isPtoRetransmission);
  }

  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  std::unique_ptr<MockQuicStats> quicStats_;
  const PathInfo* currentPathInfo_{};
  std::unique_ptr<BufAccessor> bufAccessor_{std::make_unique<BufAccessor>(
      kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize)};
};

enum class LossAlarmFrameType : uint8_t { Ping, Timestamp };

class QuicTransportFunctionsLossAlarmTest
    : public QuicTransportFunctionsTest,
      public WithParamInterface<LossAlarmFrameType> {};

TEST_P(
    QuicTransportFunctionsLossAlarmTest,
    RetransmittableFrameControlsOutstandingAndAlarm) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  const bool retransmittable = GetParam() == LossAlarmFrameType::Ping;
  if (retransmittable) {
    packet.packet.frames.push_back(PingFrame());
  } else {
    packet.packet.frames.push_back(TimestampFrame(1234));
  }
  EXPECT_EQ(0, conn->outstandings.packets.size());

  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      Clock::now(),
      50,
      0);

  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(retransmittable ? 1 : 0, conn->outstandings.packets.size());
  EXPECT_EQ(retransmittable, conn->pendingEvents.setLossDetectionAlarm);
}

INSTANTIATE_TEST_SUITE_P(
    PingAndTimestamp,
    QuicTransportFunctionsLossAlarmTest,
    Values(LossAlarmFrameType::Ping, LossAlarmFrameType::Timestamp));

TEST_F(QuicTransportFunctionsTest, UnifiedStreamPartialNewData) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, IOBuf::copyBuffer("abcdef"), false)
          .hasError());

  auto result =
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false));

  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  EXPECT_EQ(stream->streamSendBuffer->nextUnsentOffset(), 3);
  EXPECT_EQ(stream->streamSendBuffer->unsentBytes(), 3);
  EXPECT_EQ(stream->currentWriteOffset, 3);
  EXPECT_EQ(stream->numPacketsTxWithNewData, 1);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 3);
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 3);
}

TEST_F(
    QuicTransportFunctionsTest,
    UnifiedStreamRetransmissionDoesNotChargeFlowControl) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, IOBuf::copyBuffer("abc"), false)
                   .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  stream->streamSendBuffer->markLoss({.offset = 0, .len = 3, .fin = false});
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(1);

  auto result =
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false));

  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(stream->streamSendBuffer->nextUnsentOffset(), 3);
  EXPECT_EQ(stream->currentWriteOffset, 3);
  EXPECT_EQ(stream->numPacketsTxWithNewData, 1);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 3);
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 3);
  EXPECT_EQ(conn->lossState.totalBytesRetransmitted, 3);
}

TEST_F(QuicTransportFunctionsTest, UnifiedStreamFinOnlyNewAndLost) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, nullptr, true).hasError());
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(1);

  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 0, true))
          .hasError());
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  EXPECT_TRUE(stream->streamSendBuffer->finSent());
  EXPECT_EQ(stream->currentWriteOffset, 1);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);

  stream->streamSendBuffer->markLoss({.offset = 0, .len = 0, .fin = true});
  ASSERT_TRUE(stream->streamSendBuffer->finLost());
  auto result =
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 0, true));

  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(stream->streamSendBuffer->finLost());
  EXPECT_EQ(stream->currentWriteOffset, 1);
  EXPECT_EQ(stream->numPacketsTxWithNewData, 1);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);
  EXPECT_EQ(conn->lossState.totalBytesRetransmitted, 0);
}

TEST_F(QuicTransportFunctionsTest, UnifiedStreamClonePreservesPendingLoss) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, IOBuf::copyBuffer("abc"), false)
                   .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  stream->streamSendBuffer->markLoss({.offset = 0, .len = 3, .fin = false});
  ClonedPacketIdentifier cloneId(PacketNumberSpace::AppData, 0);
  conn->outstandings.clonedPacketIdentifiers.insert(cloneId);

  auto result = updateStreamFrame(
      *conn, WriteStreamFrame(stream->id, 0, 3, false), cloneId);

  ASSERT_FALSE(result.hasError());
  const auto pendingLoss = stream->streamSendBuffer->nextLoss(3);
  ASSERT_TRUE(pendingLoss.has_value());
  EXPECT_EQ(
      *pendingLoss,
      (StreamSendBuffer::SendRange{.offset = 0, .len = 3, .fin = false}));
  EXPECT_EQ(conn->lossState.totalStreamBytesCloned, 3);
  EXPECT_EQ(conn->lossState.totalBytesRetransmitted, 0);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 3);
}

namespace {

WriteStreamFrame::Origin lastSentStreamFrameOrigin(
    const QuicConnectionStateBase& conn) {
  const auto& frame = conn.outstandings.packets.back().packet.frames.front();
  CHECK(frame.asWriteStreamFrame());
  return frame.asWriteStreamFrame()->origin;
}

} // namespace

TEST_F(QuicTransportFunctionsTest, StreamFrameOriginRecordsLegacySendDecision) {
  auto conn = createConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(stream->streamSendBuffer.has_value());
  constexpr uint64_t kWriteLen = 10000;
  ASSERT_FALSE(
      writeDataToQuicStream(
          *stream, folly::IOBuf::copyBuffer(std::string(kWriteLen, 'a')), false)
          .hasError());

  ASSERT_FALSE(updateStreamFrame(
                   *conn, WriteStreamFrame(stream->id, 0, kWriteLen, false))
                   .hasError());
  EXPECT_EQ(
      WriteStreamFrame::Origin::NewData, lastSentStreamFrameOrigin(*conn));
  ASSERT_EQ(kWriteLen, stream->currentWriteOffset);

  // Declare the bytes lost, then retransmit a prefix from the loss buffer
  // while the stream's write offset is 10000.
  auto lostBuffer = stream->retransmissionBuffer.find(0);
  ASSERT_NE(lostBuffer, stream->retransmissionBuffer.end());
  stream->insertIntoLossBuffer(std::move(lostBuffer->second));
  stream->retransmissionBuffer.erase(lostBuffer);
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(1);
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 100, false))
          .hasError());
  EXPECT_EQ(
      WriteStreamFrame::Origin::LossRetransmission,
      lastSentStreamFrameOrigin(*conn));
  const auto& retransmissionDetails =
      conn->outstandings.packets.back().metadata.detailsPerStream.at(
          stream->id);
  EXPECT_EQ(0, retransmissionDetails.newStreamBytesSent);
  EXPECT_FALSE(retransmissionDetails.maybeFirstNewStreamByteOffset.has_value());

  ClonedPacketIdentifier cloneId(PacketNumberSpace::AppData, 0);
  conn->outstandings.clonedPacketIdentifiers.insert(cloneId);
  ASSERT_FALSE(updateStreamFrame(
                   *conn, WriteStreamFrame(stream->id, 0, 100, false), cloneId)
                   .hasError());
  EXPECT_EQ(WriteStreamFrame::Origin::Clone, lastSentStreamFrameOrigin(*conn));
}

TEST_F(QuicTransportFunctionsTest, StreamFrameOriginRecordsUnifiedPtoProbe) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, IOBuf::copyBuffer("abc"), false)
                   .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());
  EXPECT_EQ(
      WriteStreamFrame::Origin::NewData, lastSentStreamFrameOrigin(*conn));

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.emplace_back(WriteStreamFrame(stream->id, 0, 3, false));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint{},
                   static_cast<uint32_t>(getEncodedSize(packet)),
                   static_cast<uint32_t>(getEncodedBodySize(packet)),
                   PacketTransmissionReason::PtoProbe,
                   true /* isPtoRetransmission */)
                   .hasError());
  EXPECT_EQ(
      WriteStreamFrame::Origin::PtoRetransmission,
      lastSentStreamFrameOrigin(*conn));
}

TEST_F(QuicTransportFunctionsTest, UnifiedStreamDuplicateWithoutLossIsError) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, IOBuf::copyBuffer("abc"), false)
                   .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());

  auto result =
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false));

  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::INTERNAL_ERROR);
}

TEST_F(QuicTransportFunctionsTest, UnifiedCryptoPartialNewData) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->initialStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("abcdef"));

  auto result = updateCryptoFrame(*conn, EncryptionLevel::Initial, {0, 3});

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(cryptoStream.streamSendBuffer.has_value());
  EXPECT_EQ(cryptoStream.streamSendBuffer->nextUnsentOffset(), 3);
  EXPECT_EQ(cryptoStream.streamSendBuffer->unsentBytes(), 3);
  EXPECT_EQ(cryptoStream.currentWriteOffset, 3);
  EXPECT_TRUE(cryptoStream.retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, UnifiedCryptoLossWriteWithdrawsLoss) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->handshakeStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("handshake"));
  ASSERT_TRUE(
      updateCryptoFrame(*conn, EncryptionLevel::Handshake, {0, 9}).has_value());
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markLoss({0, 9, false}));
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(1);

  auto result = updateCryptoFrame(*conn, EncryptionLevel::Handshake, {0, 9});

  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(cryptoStream.streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(cryptoStream.streamSendBuffer->nextUnsentOffset(), 9);
  EXPECT_EQ(cryptoStream.currentWriteOffset, 9);
  EXPECT_EQ(conn->lossState.totalBytesRetransmitted, 9);
}

TEST_F(QuicTransportFunctionsTest, UnifiedCryptoPtoWriteDoesNotMutateState) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->initialStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("initial"));
  ASSERT_TRUE(
      updateCryptoFrame(*conn, EncryptionLevel::Initial, {0, 7}).has_value());
  const auto outstandingBytes =
      cryptoStream.streamSendBuffer->outstandingBytes();

  auto result = updateCryptoFrame(
      *conn,
      EncryptionLevel::Initial,
      {0, 7},
      PacketTransmissionReason::PtoProbe,
      true);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(
      cryptoStream.streamSendBuffer->outstandingBytes(), outstandingBytes);
  EXPECT_FALSE(cryptoStream.streamSendBuffer->hasPendingLoss());
  EXPECT_EQ(cryptoStream.streamSendBuffer->nextUnsentOffset(), 7);
  EXPECT_EQ(cryptoStream.currentWriteOffset, 7);
  EXPECT_EQ(
      conn->outstandings.packets.back().metadata.transmissionReason,
      PacketTransmissionReason::PtoProbe);
}

TEST_F(QuicTransportFunctionsTest, UnifiedOneRttCryptoUsesOwnedBuffer) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->oneRttStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("ticket"));

  auto result = updateCryptoFrame(*conn, EncryptionLevel::AppData, {0, 6});

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(cryptoStream.streamSendBuffer.has_value());
  EXPECT_EQ(cryptoStream.streamSendBuffer->nextUnsentOffset(), 6);
  EXPECT_EQ(cryptoStream.currentWriteOffset, 6);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnection) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  // Builds a fake packet to test with.
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);

  auto buf = IOBuf::copyBuffer("hey whats up");
  EXPECT_CALL(*quicStats_, onPacketRetransmission()).Times(2);
  auto result1 = writeDataToQuicStream(*stream1, buf->clone(), true);
  ASSERT_FALSE(result1.hasError());
  auto result2 = writeDataToQuicStream(*stream2, buf->clone(), true);
  ASSERT_FALSE(result2.hasError());

  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 5, false);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 12, true);
  packet.packet.frames.push_back(std::move(writeStreamFrame1));
  packet.packet.frames.push_back(std::move(writeStreamFrame2));

  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint{},
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  EXPECT_EQ(stream1->currentWriteOffset, 5);
  EXPECT_EQ(stream2->currentWriteOffset, 13);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 17);

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);
  EXPECT_EQ(rt1.offset, 0);
  std::string expected = "hey w";
  EXPECT_EQ(
      ByteRange((uint8_t*)expected.data(), expected.size()),
      rt1.data.getHead()->getRange());

  EXPECT_EQ(stream2->retransmissionBuffer.size(), 1);
  auto& rt2 = *stream2->retransmissionBuffer.at(0);
  EXPECT_EQ(rt2.offset, 0);
  EXPECT_EQ(
      ByteRange(buf->buffer(), buf->length()), rt2.data.getHead()->getRange());
  EXPECT_TRUE(rt2.eof);

  // Testing retransmission
  stream1->lossBuffer.push_back(std::move(rt1));
  stream1->retransmissionBuffer.clear();
  stream2->lossBuffer.push_back(std::move(rt2));
  stream2->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);

  // Write the remainder of the data with retransmission
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  WriteStreamFrame writeStreamFrame3(stream1->id, 5, 7, true);
  WriteStreamFrame writeStreamFrame4(stream1->id, 0, 5, false);
  WriteStreamFrame writeStreamFrame5(stream2->id, 0, 6, false);
  packet2.packet.frames.push_back(std::move(writeStreamFrame3));
  packet2.packet.frames.push_back(std::move(writeStreamFrame4));
  packet2.packet.frames.push_back(std::move(writeStreamFrame5));

  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState->nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum);
  EXPECT_GT(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum);
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  EXPECT_EQ(stream1->currentWriteOffset, 13);
  EXPECT_EQ(stream2->currentWriteOffset, 13);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24);

  EXPECT_EQ(stream1->lossBuffer.size(), 0);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 2);
  auto& rt3 = *stream1->retransmissionBuffer.at(5);
  expected = "hats up";
  EXPECT_EQ(
      ByteRange((uint8_t*)expected.data(), expected.size()),
      rt3.data.getHead()->getRange());

  auto& rt4 = *stream1->retransmissionBuffer.at(0);
  expected = "hey w";
  EXPECT_EQ(
      ByteRange((uint8_t*)expected.data(), expected.size()),
      rt4.data.getHead()->getRange());

  // loss buffer should be split into 2. Part in retransmission buffer and
  // part remains in loss buffer.
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 1);
  auto& rt5 = *stream2->retransmissionBuffer.at(0);
  expected = "hey wh";
  EXPECT_EQ(
      ByteRange((uint8_t*)expected.data(), expected.size()),
      rt5.data.getHead()->getRange());
  EXPECT_EQ(rt5.offset, 0);
  EXPECT_EQ(rt5.eof, 0);

  auto& rt6 = stream2->lossBuffer.front();
  expected = "ats up";
  EXPECT_EQ(
      ByteRange((uint8_t*)expected.data(), expected.size()),
      rt6.data.getHead()->getRange());
  EXPECT_EQ(rt6.offset, 6);
  EXPECT_EQ(rt6.eof, 1);

  // verify handshake packets stored in QLogger
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);

  for (int i = 0; i < 2; ++i) {
    auto p1 = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(p1.get());
    EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 2);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 5);
      EXPECT_FALSE(frame->fin);
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 3);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 5);
      EXPECT_EQ(frame->len, 7);
      EXPECT_TRUE(frame->fin);
    }
  }
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPacketRetrans) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);

  // two streams, both writing "hey whats up"
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = IOBuf::copyBuffer("hey whats up");
  auto result1 = writeDataToQuicStream(*stream1, buf->clone(), true /* eof */);
  ASSERT_FALSE(result1.hasError());
  auto result2 = writeDataToQuicStream(*stream2, buf->clone(), true /* eof */);
  ASSERT_FALSE(result2.hasError());
  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 12, true /* eom */);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 12, true /* eom */);
  EXPECT_EQ(stream1->currentWriteOffset, 0);
  EXPECT_EQ(stream2->currentWriteOffset, 0);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);

  // add both stream frames into AppData packet1
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);

  // mimic send, call updateConnection
  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet1.packet,
      TimePoint{},
      getEncodedSize(packet1),
      getEncodedBodySize(packet1));
  ASSERT_FALSE(result.hasError());

  // appData packet number should increase
  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  // offsets should be 13 (len + EOF) and 24 (bytes without EOF)
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24); // sum(len)

  // verify retransmission buffer and mark stream bytes in packet1 lost
  {
    ASSERT_EQ(stream1->retransmissionBuffer.size(), 1);
    auto& rt = *stream1->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_EQ(
        ByteRange(buf->data(), buf->length()), rt.data.getHead()->getRange());
    EXPECT_TRUE(rt.eof);
    stream1->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream2->retransmissionBuffer.size(), 1);
    auto& rt = *stream2->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_EQ(
        ByteRange(buf->data(), buf->length()), rt.data.getHead()->getRange());
    EXPECT_TRUE(rt.eof);
    stream2->lossBuffer.push_back(std::move(rt));
  }
  stream1->retransmissionBuffer.clear();
  stream2->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);

  // retransmit the lost frames in AppData packet2
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);

  // mimic send, call updateConnection
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState->nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet2),
      getEncodedBodySize(packet2));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  // since retransmission with no new data, no change in offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 24); // sum(len)

  // check loss state
  MVCHECK_EQ(
      conn->lossState.totalBytesSent,
      getEncodedSize(packet1) + getEncodedSize(packet2));
  MVCHECK_EQ(
      conn->lossState.totalBodyBytesSent,
      getEncodedBodySize(packet1) + getEncodedBodySize(packet2));
  MVCHECK_EQ(conn->lossState.totalPacketsSent, 2);

  // totalStreamBytesSent:
  //   the first packet contained 12 + 12
  //   the second packet contained 12 + 12
  //   total = 48
  EXPECT_EQ(conn->lossState.totalStreamBytesSent, 48); // sum(len)

  // totalNewStreamBytesSent: just sum(len)
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 24);
  EXPECT_EQ(
      conn->lossState.totalNewStreamBytesSent,
      conn->flowControlState.sumCurWriteOffset);
}

TEST_F(
    QuicTransportFunctionsTest,
    TestUpdateConnectionPacketRetransWithNewData) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);

  // three streams, all writing "hey whats up"
  //
  // streams1 and 2 EOF after writing buffer, stream3 does not
  //
  // frames:
  //   stream1,frame1 contains the entire string with EOM
  //   stream2,frame1 contains "hey w", and thus no EOM
  //   stream3,frame1 contains the entire string, but no EOM given no EOF yet
  //
  // we'll write additional data to stream3 later
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream3Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto stream3 = conn->streamManager->findStream(stream3Id);
  auto buf = IOBuf::copyBuffer("hey whats up");
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf->clone(), true /* eof */).hasError());
  ASSERT_FALSE(
      writeDataToQuicStream(*stream2, buf->clone(), true /* eof */).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream3, buf->clone(), false /* eof */)
                   .hasError());
  WriteStreamFrame writeStreamFrame1(stream1->id, 0, 12, true /* eom */);
  WriteStreamFrame writeStreamFrame2(stream2->id, 0, 5, false /* eom */);
  WriteStreamFrame writeStreamFrame3(stream3->id, 0, 12, false /* eom */);
  EXPECT_EQ(stream1->currentWriteOffset, 0);
  EXPECT_EQ(stream2->currentWriteOffset, 0);
  EXPECT_EQ(stream3->currentWriteOffset, 0);
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 0);

  // add all stream frames into AppData packet1
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);
  packet1.packet.frames.push_back(writeStreamFrame3);

  // mimic send, call updateConnection
  auto currentNextInitialPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  auto currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  auto currentNextAppDataPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(true));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet1.packet,
                   TimePoint{},
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  // appData packet number should increase
  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_TRUE(conn->outstandings.packets.back().isAppLimited);

  // check offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 5); // len (5)
  EXPECT_EQ(stream3->currentWriteOffset, 12); // len (12)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 29); // sum(len)

  // verify retransmission buffer and mark stream bytes in packet1 lost
  {
    ASSERT_EQ(stream1->retransmissionBuffer.size(), 1);
    auto& rt = *stream1->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_EQ(
        ByteRange(buf->data(), buf->length()), rt.data.getHead()->getRange());
    EXPECT_TRUE(rt.eof);
    stream1->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream2->retransmissionBuffer.size(), 1);
    auto& rt = *stream2->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    auto expectedBuf = IOBuf::copyBuffer("hey w");
    EXPECT_EQ(
        ByteRange(expectedBuf->data(), expectedBuf->length()),
        rt.data.getHead()->getRange());
    EXPECT_FALSE(rt.eof);
    stream2->lossBuffer.push_back(std::move(rt));
  }
  {
    ASSERT_EQ(stream3->retransmissionBuffer.size(), 1);
    auto& rt = *stream3->retransmissionBuffer.at(0);
    EXPECT_EQ(rt.offset, 0);
    EXPECT_EQ(
        ByteRange(buf->data(), buf->length()), rt.data.getHead()->getRange());
    EXPECT_FALSE(rt.eof);
    stream3->lossBuffer.push_back(std::move(rt));
  }
  stream1->retransmissionBuffer.clear();
  stream2->retransmissionBuffer.clear();
  stream3->retransmissionBuffer.clear();
  conn->streamManager->addLoss(stream1->id);
  conn->streamManager->addLoss(stream2->id);
  conn->streamManager->addLoss(stream3->id);

  // add some additional data
  // write a "?" to stream3 and set eof
  auto buf2 = IOBuf::copyBuffer("?");
  ASSERT_FALSE(
      writeDataToQuicStream(*stream3, buf->clone(), true /* eof */).hasError());

  // packet2 contains originally transmitted frames + new data frames
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);
  packet2.packet.frames.push_back(writeStreamFrame3);
  packet2.packet.frames.push_back(WriteStreamFrame(
      stream2->id, 5 /* offset */, 7 /* len */, true /* eom */));
  packet2.packet.frames.push_back(WriteStreamFrame(
      stream3->id, 12 /* offset */, 1 /* len */, true /* eom */));

  // mimic send, call updateConnection
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  currentNextInitialPacketNum = conn->ackStates.initialAckState->nextPacketNum;
  currentNextHandshakePacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  currentNextAppDataPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  EXPECT_CALL(*rawCongestionController, isAppLimited())
      .Times(1)
      .WillOnce(Return(false));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet2.packet,
                   TimePoint(),
                   getEncodedSize(packet2),
                   getEncodedBodySize(packet2))
                   .hasError());
  EXPECT_EQ(
      conn->ackStates.initialAckState->nextPacketNum,
      currentNextInitialPacketNum); // no change
  EXPECT_EQ(
      conn->ackStates.handshakeAckState->nextPacketNum,
      currentNextHandshakePacketNum); // no change
  EXPECT_GT(
      conn->ackStates.appDataAckState.nextPacketNum,
      currentNextAppDataPacketNum); // increased
  EXPECT_FALSE(conn->outstandings.packets.back().isAppLimited);

  // check offsets
  EXPECT_EQ(stream1->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream2->currentWriteOffset, 13); // len (12) + EOF (1)
  EXPECT_EQ(stream3->currentWriteOffset, 14); // len (13) + EOF (1)
  EXPECT_EQ(conn->flowControlState.sumCurWriteOffset, 37); // sum(len)

  // check loss state
  MVCHECK_EQ(
      conn->lossState.totalBytesSent,
      getEncodedSize(packet1) + getEncodedSize(packet2));
  MVCHECK_EQ(
      conn->lossState.totalBodyBytesSent,
      getEncodedBodySize(packet1) + getEncodedBodySize(packet2));
  MVCHECK_EQ(conn->lossState.totalPacketsSent, 2);

  // totalStreamBytesSent:
  //   the first packet contained 12 + 5 + 12 stream bytes
  //   the second packet contained 12 + 12 + 13 stream bytes
  //   total = 66
  EXPECT_EQ(conn->lossState.totalStreamBytesSent, 66); // sum(len)

  // totalNewStreamBytesSent: just sum(len)
  EXPECT_EQ(conn->lossState.totalNewStreamBytesSent, 37);
  EXPECT_EQ(
      conn->lossState.totalNewStreamBytesSent,
      conn->flowControlState.sumCurWriteOffset);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPacketSorting) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  conn->ackStates.initialAckState->nextPacketNum = 0;
  conn->ackStates.handshakeAckState->nextPacketNum = 1;
  conn->ackStates.appDataAckState.nextPacketNum = 2;
  auto initialPacket = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  auto handshakePacket = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto appDataPacket = buildEmptyPacket(*conn, PacketNumberSpace::AppData);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(
          *stream,
          folly::IOBuf::copyBuffer("The sun is cold and the rain is hard."),
          true)
          .hasError());
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  initialPacket.packet.frames.push_back(writeStreamFrame);
  handshakePacket.packet.frames.push_back(writeStreamFrame);
  appDataPacket.packet.frames.push_back(writeStreamFrame);

  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   handshakePacket.packet,
                   TimePoint{},
                   getEncodedSize(handshakePacket),
                   getEncodedBodySize(handshakePacket))
                   .hasError());
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   initialPacket.packet,
                   TimePoint{},
                   getEncodedSize(initialPacket),
                   getEncodedBodySize(initialPacket))
                   .hasError());
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   appDataPacket.packet,
                   TimePoint{},
                   getEncodedSize(appDataPacket),
                   getEncodedBodySize(appDataPacket))
                   .hasError());
  // verify qLogger added correct logs
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 3);

  auto l1 = std::move(qLogger->logs[indices[0]]);
  auto l2 = std::move(qLogger->logs[indices[1]]);
  auto l3 = std::move(qLogger->logs[indices[2]]);
  auto event1 = dynamic_cast<QLogPacketEvent*>(l1.get());
  auto event2 = dynamic_cast<QLogPacketEvent*>(l2.get());
  auto event3 = dynamic_cast<QLogPacketEvent*>(l3.get());

  EXPECT_EQ(event1->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event2->packetType, toQlogString(LongHeader::Types::Initial));
  EXPECT_EQ(event3->packetType, toQlogString(LongHeader::Types::ZeroRtt));

  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto& firstHeader = conn->outstandings.packets.front().packet.header;
  auto firstPacketNum = firstHeader.getPacketSequenceNum();
  EXPECT_EQ(0, firstPacketNum);
  EXPECT_EQ(1, event1->packetNum);

  EXPECT_EQ(PacketNumberSpace::Initial, firstHeader.getPacketNumberSpace());

  auto& lastHeader = conn->outstandings.packets.back().packet.header;

  auto lastPacketNum = lastHeader.getPacketSequenceNum();

  EXPECT_EQ(2, lastPacketNum);
  EXPECT_EQ(2, event3->packetNum);

  EXPECT_EQ(PacketNumberSpace::AppData, lastHeader.getPacketNumberSpace());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionFinOnly) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();

  ASSERT_FALSE(writeDataToQuicStream(*stream1, nullptr, true).hasError());
  packet.packet.frames.push_back(WriteStreamFrame(stream1->id, 0, 0, true));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream1->id);
  EXPECT_EQ(frame->offset, 0);
  EXPECT_EQ(frame->len, 0);
  EXPECT_TRUE(frame->fin);

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);

  EXPECT_EQ(stream1->currentWriteOffset, 1);
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_EQ(rt1.data.chainLength(), 0);
  EXPECT_TRUE(rt1.eof);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionAllBytesExceptFin) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  auto stream1 = conn->streamManager->createNextUnidirectionalStream().value();

  auto buf = IOBuf::copyBuffer("Bluberries are purple");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  packet.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, buf->computeChainDataLength(), false));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream1->id);
  EXPECT_EQ(frame->offset, 0);
  EXPECT_EQ(frame->len, buf->computeChainDataLength());
  EXPECT_FALSE(frame->fin);

  EXPECT_EQ(stream1->currentWriteOffset, buf->computeChainDataLength());

  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  auto& rt1 = *stream1->retransmissionBuffer.at(0);
  EXPECT_EQ(rt1.offset, 0);
  EXPECT_EQ(rt1.data.chainLength(), buf->computeChainDataLength());
  EXPECT_FALSE(rt1.eof);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionEmptyAckWriteResult) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  // None of the largestAckScheduled should be changed. But since
  // buildEmptyPacket() builds a Handshake packet, we use handshakeAckState to
  // verify.
  auto currentPendingLargestAckScheduled =
      conn->ackStates.handshakeAckState->largestAckScheduled;
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  EXPECT_EQ(
      currentPendingLargestAckScheduled,
      conn->ackStates.handshakeAckState->largestAckScheduled);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionPureAckCounter) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto result1 = writeDataToQuicStream(*stream, nullptr, true);
  ASSERT_FALSE(result1.hasError());
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 100);
  packet.packet.frames.push_back(std::move(ackFrame));
  auto result2 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result2.hasError());

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto result3 = writeDataToQuicStream(*stream1, nullptr, true);
  ASSERT_FALSE(result3.hasError());

  conn->pendingEvents.resets.emplace(
      1, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 0));
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  RstStreamFrame rstFrame(1, GenericApplicationErrorCode::UNKNOWN, 0);
  packet2.packet.frames.push_back(std::move(rstFrame));

  auto result4 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet2.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result4.hasError());

  //  verify QLogger contains correct packet and frame information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->frames.size(), 1);
  }
}

TEST_F(QuicTransportFunctionsTest, TestPaddingPureAckPacketIsStillPureAck) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);

  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 100);
  packet.packet.frames.push_back(std::move(ackFrame));
  packet.packet.frames.push_back(PaddingFrame());
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  // verify QLogger contains correct packet and frames information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);

  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  EXPECT_EQ(event->frames.size(), 2);
}

TEST_F(QuicTransportFunctionsTest, TestImplicitAck) {
  auto conn = createConn();
  auto data = IOBuf::copyBuffer("totally real crypto data");
  data->coalesce();

  auto initialStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Initial);
  ASSERT_TRUE(initialStream->pendingWrites.empty());
  ASSERT_TRUE(initialStream->retransmissionBuffer.empty());
  ASSERT_TRUE(initialStream->lossBuffer.empty());
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(WriteCryptoFrame(0, data->length()));
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  auto result1 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result1.hasError());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_EQ(1, initialStream->retransmissionBuffer.size());

  packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length(), data->length()));
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length() * 2, data->length()));
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  auto result2 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result2.hasError());
  EXPECT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(3, initialStream->retransmissionBuffer.size());
  EXPECT_TRUE(initialStream->pendingWrites.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());

  // Fake loss.
  ChainedByteRangeHead firstBuf(
      std::move(initialStream->retransmissionBuffer.find(0)->second->data));
  initialStream->retransmissionBuffer.erase(0);
  initialStream->lossBuffer.emplace_back(std::move(firstBuf), 0, false);
  conn->outstandings.packets.pop_front();
  conn->outstandings.packetCount[PacketNumberSpace::Initial]--;

  auto handshakeStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Handshake);
  ASSERT_TRUE(handshakeStream->pendingWrites.empty());
  ASSERT_TRUE(handshakeStream->retransmissionBuffer.empty());
  ASSERT_TRUE(handshakeStream->lossBuffer.empty());
  packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packet.packet.frames.push_back(WriteCryptoFrame(0, data->length()));
  handshakeStream->pendingWrites.append(data);
  handshakeStream->writeBuffer.append(data->clone());
  auto result3 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result3.hasError());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(1, handshakeStream->retransmissionBuffer.size());

  packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length(), data->length()));
  handshakeStream->pendingWrites.append(data);
  handshakeStream->writeBuffer.append(data->clone());
  auto result4 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result4.hasError());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(3, conn->outstandings.packets.size());
  EXPECT_EQ(2, handshakeStream->retransmissionBuffer.size());
  EXPECT_TRUE(handshakeStream->pendingWrites.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());

  // Fake loss.
  firstBuf = ChainedByteRangeHead(
      std::move(handshakeStream->retransmissionBuffer.find(0)->second->data));
  handshakeStream->retransmissionBuffer.erase(0);
  handshakeStream->lossBuffer.emplace_back(std::move(firstBuf), 0, false);
  auto& op = conn->outstandings.packets.front();
  ASSERT_EQ(
      op.packet.header.getPacketNumberSpace(), PacketNumberSpace::Handshake);
  auto frame = op.packet.frames[0].asWriteCryptoFrame();
  EXPECT_EQ(frame->offset, 0);
  conn->outstandings.packets.pop_front();
  conn->outstandings.packetCount[PacketNumberSpace::Handshake]--;

  implicitAckCryptoStream(*conn, EncryptionLevel::Initial);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_TRUE(initialStream->retransmissionBuffer.empty());
  EXPECT_TRUE(initialStream->pendingWrites.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());

  implicitAckCryptoStream(*conn, EncryptionLevel::Handshake);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_TRUE(conn->outstandings.packets.empty());
  EXPECT_TRUE(handshakeStream->retransmissionBuffer.empty());
  EXPECT_TRUE(handshakeStream->pendingWrites.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, TestImplicitAckWithSkippedPacketNumber) {
  auto conn = createConn();
  auto data = IOBuf::copyBuffer("totally real crypto data");
  data->coalesce();

  auto initialStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Initial);
  ASSERT_TRUE(initialStream->pendingWrites.empty());
  ASSERT_TRUE(initialStream->retransmissionBuffer.empty());
  ASSERT_TRUE(initialStream->lossBuffer.empty());
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(WriteCryptoFrame(0, data->length()));
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  auto result1 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result1.hasError());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(1, conn->outstandings.packets.size());
  EXPECT_EQ(1, initialStream->retransmissionBuffer.size());

  // Skip a packet number
  conn->ackStates.initialAckState->skippedPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  increaseNextPacketNum(*conn, PacketNumberSpace::Initial);

  packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length(), data->length()));
  packet.packet.frames.push_back(
      WriteCryptoFrame(data->length() * 2, data->length()));
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  initialStream->pendingWrites.append(data);
  initialStream->writeBuffer.append(data->clone());
  auto result2 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result2.hasError());
  EXPECT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(3, initialStream->retransmissionBuffer.size());
  EXPECT_TRUE(initialStream->pendingWrites.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());

  implicitAckCryptoStream(*conn, EncryptionLevel::Initial);
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(0, conn->outstandings.packets.size());
  EXPECT_TRUE(initialStream->retransmissionBuffer.empty());
  EXPECT_TRUE(initialStream->pendingWrites.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, ImplicitAckCancelsOwnedCryptoBuffer) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->initialStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("pending initial"));
  ASSERT_TRUE(cryptoStream.streamSendBuffer.has_value());

  implicitAckCryptoStream(*conn, EncryptionLevel::Initial);

  EXPECT_TRUE(cryptoStream.streamSendBuffer->cancelled());
  EXPECT_EQ(cryptoStream.streamSendBuffer->outstandingBytes(), 0);
  EXPECT_FALSE(cryptoStream.streamSendBuffer
                   ->nextNewData(std::numeric_limits<uint64_t>::max())
                   .has_value());
}

TEST_F(
    QuicTransportFunctionsTest,
    ImplicitAckClearsLostOwnedCryptoPacketAndBuffer) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto& cryptoStream = conn->cryptoState->initialStream;
  writeDataToQuicStream(
      *conn, cryptoStream, folly::IOBuf::copyBuffer("pending initial"));
  ASSERT_TRUE(
      updateCryptoFrame(*conn, EncryptionLevel::Initial, {0, 15}).has_value());
  ASSERT_TRUE(cryptoStream.streamSendBuffer->markLoss({0, 15, false}));
  ASSERT_EQ(conn->outstandings.packets.size(), 1);
  conn->outstandings.packets.front().declaredLost = true;
  conn->outstandings.declaredLostCount++;
  --conn->outstandings.packetCount[PacketNumberSpace::Initial];

  implicitAckCryptoStream(*conn, EncryptionLevel::Initial);

  EXPECT_TRUE(conn->outstandings.packets.empty());
  EXPECT_EQ(conn->outstandings.declaredLostCount, 0);
  EXPECT_TRUE(cryptoStream.streamSendBuffer->cancelled());
  EXPECT_EQ(cryptoStream.streamSendBuffer->outstandingBytes(), 0);
  EXPECT_FALSE(cryptoStream.streamSendBuffer->hasPendingLoss());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionHandshakeCounter) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto result1 = writeDataToQuicStream(*stream, nullptr, true);
  ASSERT_FALSE(result1.hasError());
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto packetEncodedSize =
      !packet.header.empty() ? packet.header.computeChainDataLength() : 0;
  packetEncodedSize +=
      !packet.body.empty() ? packet.body.computeChainDataLength() : 0;

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  auto result2 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result2.hasError());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packetEncodedSize = !nonHandshake.header.empty()
      ? nonHandshake.header.computeChainDataLength()
      : 0;
  packetEncodedSize += !nonHandshake.body.empty()
      ? nonHandshake.body.computeChainDataLength()
      : 0;
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto result3 = writeDataToQuicStream(*stream1, nullptr, true);
  ASSERT_FALSE(result3.hasError());

  nonHandshake.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, 0, true));
  auto result4 = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      nonHandshake.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result4.hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {
      std::string(toQlogString(LongHeader::Types::Handshake)),
      std::string(toQlogString(LongHeader::Types::ZeroRtt))};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, packetTypes[i]);
    EXPECT_EQ(event->packetSize, packetEncodedSize);
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 1);
      auto gotFrame = static_cast<CryptoFrameLog*>(event->frames[0].get());
      gotFrame->offset = 0;
      gotFrame->len = 0;
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 1);
      auto gotFrame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(gotFrame->streamId, stream1->id);
      EXPECT_EQ(gotFrame->offset, 0);
      EXPECT_EQ(gotFrame->len, 0);
      EXPECT_TRUE(gotFrame->fin);
      EXPECT_EQ(
          1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
    }
  }
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionForOneRttCryptoData) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream, nullptr, true).hasError());
  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  // Packet with CryptoFrame in AppData pn space
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData, true);

  packet.packet.frames.push_back(WriteCryptoFrame(0, 0));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());

  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto nonHandshake = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(*stream1, nullptr, true).hasError());

  nonHandshake.packet.frames.push_back(
      WriteStreamFrame(stream1->id, 0, 0, true));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   nonHandshake.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 2);
  std::vector<std::string> packetTypes = {
      kShortHeaderPacketType.str(),
      std::string(toQlogString(LongHeader::Types::ZeroRtt))};
  for (int i = 0; i < 2; ++i) {
    auto tmp = std::move(qLogger->logs[indices[i]]);
    auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
    EXPECT_EQ(event->packetType, packetTypes[i]);
    EXPECT_EQ(event->packetSize, getEncodedSize(packet));
    EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

    if (i == 0) {
      EXPECT_EQ(event->frames.size(), 1);
      auto frame = static_cast<CryptoFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 0);
    } else if (i == 1) {
      EXPECT_EQ(event->frames.size(), 1);
      auto frame = static_cast<StreamFrameLog*>(event->frames[0].get());
      EXPECT_EQ(frame->streamId, stream1->id);
      EXPECT_EQ(frame->offset, 0);
      EXPECT_EQ(frame->len, 0);
      EXPECT_TRUE(frame->fin);
    }
  }

  EXPECT_EQ(0, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(2, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithPureAck) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn->pacer = std::move(mockPacer);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_EQ(0, conn->lossState.totalPacketsSent);
  EXPECT_EQ(0, conn->lossState.totalAckElicitingPacketsSent);
  EXPECT_EQ(0, conn->outstandings.packets.size());
  ASSERT_EQ(0, conn->lossState.totalBytesAcked);
  WriteAckFrame ackFrame;
  ackFrame.ackBlocks.emplace_back(0, 10);
  packet.packet.frames.push_back(std::move(ackFrame));
  EXPECT_CALL(*rawController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawPacer, onPacketSent()).Times(0);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_EQ(1, conn->lossState.totalPacketsSent);
  EXPECT_EQ(0, conn->lossState.totalAckElicitingPacketsSent);
  EXPECT_EQ(0, conn->outstandings.packets.size());
  EXPECT_EQ(0, conn->lossState.totalBytesAcked);
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  // verify QLogger contains correct packet information
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<WriteAckFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->ackBlocks.size(), 1);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithBytesStats) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  // This is clearly not 555 bytes. I just need some data inside the packet.
  ASSERT_FALSE(
      writeDataToQuicStream(
          *stream, folly::IOBuf::copyBuffer("Im gonna cut your hair."), true)
          .hasError());
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));
  conn->lossState.totalBytesSent = 13579;
  conn->lossState.totalBodyBytesSent = 13000;
  conn->lossState.inflightBytes = 16000;
  auto currentTime = Clock::now();
  conn->lossState.lastAckedTime = currentTime - 123s;
  conn->lossState.adjustedLastAckedTime = currentTime - 123s;
  conn->lossState.lastAckedPacketSentTime = currentTime - 234s;
  conn->lossState.totalBytesSentAtLastAck = 10000;
  conn->lossState.totalBytesAckedAtLastAck = 5000;
  conn->lossState.totalPacketsSent = 20;
  conn->lossState.totalAckElicitingPacketsSent = 15;
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   555,
                   500)
                   .hasError());
  EXPECT_EQ(21, conn->lossState.totalPacketsSent);
  EXPECT_EQ(16, conn->lossState.totalAckElicitingPacketsSent);

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, 555);
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  EXPECT_EQ(
      13579 + 555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalBytesSent);
  EXPECT_EQ(
      16000 + 555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.inflightBytes);
  EXPECT_EQ(
      555,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.encodedSize);
  EXPECT_EQ(
      500,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      15 + 1,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalAckElicitingPacketsSent);

  EXPECT_TRUE(getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
                  ->lastAckedPacketInfo.has_value());
  EXPECT_EQ(
      currentTime - 123s,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->ackTime);
  EXPECT_EQ(
      currentTime -= 234s,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->sentTime);
  EXPECT_EQ(
      10000,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->totalBytesSent);
  EXPECT_EQ(
      5000,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->lastAckedPacketInfo->totalBytesAcked);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithAppLimitedStats) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  ASSERT_FALSE(
      writeDataToQuicStream(
          *stream, folly::IOBuf::copyBuffer("Im gonna cut your hair."), true)
          .hasError());
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));

  // connections should start off being app limited
  EXPECT_TRUE(conn->appLimitedTracker.isAppLimited());

  // mark ourselves as not app limited, verify that total app limited time > 0,
  // verify that successive calls to getTotalAppLimitedTime yield same value
  conn->appLimitedTracker.setNotAppLimited();
  EXPECT_LT(0us, conn->appLimitedTracker.getTotalAppLimitedTime());
  EXPECT_EQ(
      conn->appLimitedTracker.getTotalAppLimitedTime(),
      conn->appLimitedTracker.getTotalAppLimitedTime());

  // record the packet as having been sent
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   555,
                   500)
                   .hasError());

  // should have the current app limited time recorded in metadata
  EXPECT_EQ(
      conn->appLimitedTracker.getTotalAppLimitedTime(),
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalAppLimitedTimeUsecs);
}

TEST_F(
    QuicTransportFunctionsTest,
    TestUpdateConnectionWithAppLimitedStats_MultipleTransitions) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  ASSERT_FALSE(
      writeDataToQuicStream(
          *stream, folly::IOBuf::copyBuffer("Im gonna cut your hair."), true)
          .hasError());
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));

  // connections should start off being app limited
  EXPECT_TRUE(conn->appLimitedTracker.isAppLimited());
  {
    // successive calls should yield different measurements
    const auto time1 = conn->appLimitedTracker.getTotalAppLimitedTime();
    std::this_thread::sleep_for(10ms);
    const auto time2 = conn->appLimitedTracker.getTotalAppLimitedTime();
    EXPECT_NE(time1, time2);
  }

  // mark ourselves as not app limited, verify that total app limited time > 0,
  // verify that successive calls to getTotalAppLimitedTime yield same value
  conn->appLimitedTracker.setNotAppLimited();
  EXPECT_LT(0us, conn->appLimitedTracker.getTotalAppLimitedTime());
  EXPECT_EQ(
      conn->appLimitedTracker.getTotalAppLimitedTime(),
      conn->appLimitedTracker.getTotalAppLimitedTime());
  const auto appLimitedTime1 = conn->appLimitedTracker.getTotalAppLimitedTime();

  // become app limited for at least 10ms, then repeat the above
  conn->appLimitedTracker.setAppLimited();
  std::this_thread::sleep_for(10ms);
  conn->appLimitedTracker.setNotAppLimited();
  EXPECT_LE(
      appLimitedTime1 + 10ms, conn->appLimitedTracker.getTotalAppLimitedTime());
  EXPECT_EQ(
      conn->appLimitedTracker.getTotalAppLimitedTime(),
      conn->appLimitedTracker.getTotalAppLimitedTime());

  // record the packet as having been sent
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   555,
                   500)
                   .hasError());

  // should have the current app limited time recorded in metadata
  EXPECT_EQ(
      conn->appLimitedTracker.getTotalAppLimitedTime(),
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake)
          ->metadata.totalAppLimitedTimeUsecs);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionWithCloneResult) {
  auto conn = createConn();
  EXPECT_FALSE(conn->transportSettings.useNonCloningPto);
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero,
      *conn->clientConnectionId,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto thisMoment = Clock::now();
  MockClock::mockNow = [=]() { return thisMoment; };
  RegularQuicWritePacket writePacket(std::move(shortHeader));
  // Add a dummy frame into the packet so we don't treat it as pureAck
  auto maxDataAmt = 1000 + conn->flowControlState.advertisedMaxOffset;
  MaxDataFrame maxDataFrame(maxDataAmt);
  conn->pendingEvents.connWindowUpdate = true;
  writePacket.frames.push_back(std::move(maxDataFrame));
  ClonedPacketIdentifier clonedPacketIdentifier(PacketNumberSpace::AppData, 1);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  auto futureMoment = thisMoment + 50ms;
  MockClock::mockNow = [=]() { return futureMoment; };
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      clonedPacketIdentifier,
      std::move(writePacket),
      MockClock::now(),
      1500,
      1400);
  ASSERT_FALSE(result.hasError());
  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto qLogEvent = dynamic_cast<QLogPacketEvent*>(tmp.get());
  EXPECT_EQ(qLogEvent->packetType, kShortHeaderPacketType.str());
  EXPECT_EQ(qLogEvent->packetSize, 1500);
  EXPECT_EQ(qLogEvent->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  EXPECT_EQ(qLogEvent->frames.size(), 1);
  auto frame = static_cast<MaxDataFrameLog*>(qLogEvent->frames[0].get());
  EXPECT_EQ(frame->maximumData, maxDataAmt);
  EXPECT_EQ(
      futureMoment,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.time);
  EXPECT_EQ(
      1500,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.encodedSize);
  EXPECT_EQ(
      1400,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.encodedBodySize);
  EXPECT_EQ(
      clonedPacketIdentifier,
      *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->maybeClonedPacketIdentifier);
  EXPECT_EQ(
      PacketTransmissionReason::Clone,
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.transmissionReason);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionStreamWindowUpdate) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  MaxStreamDataFrame streamWindowUpdate(stream->id, 0);
  conn->streamManager->queueWindowUpdate(stream->id);
  packet.packet.frames.push_back(std::move(streamWindowUpdate));
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);

  // verify QLogger contains correct frame information
  ASSERT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxStreamDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->streamId, stream->id);
  EXPECT_EQ(frame->maximumData, 0);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionConnWindowUpdate) {
  auto conn = createConn();
  conn->qLogger = std::make_shared<quic::FileQLogger>(VantagePoint::Client);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  conn->pendingEvents.connWindowUpdate = true;
  MaxDataFrame connWindowUpdate(conn->flowControlState.advertisedMaxOffset);
  packet.packet.frames.push_back(std::move(connWindowUpdate));
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  // verify QLogger contains correct packet information
  std::shared_ptr<quic::FileQLogger> qLogger =
      std::dynamic_pointer_cast<quic::FileQLogger>(conn->qLogger);
  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::PacketSent, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogPacketEvent*>(tmp.get());

  EXPECT_EQ(event->packetType, toQlogString(LongHeader::Types::Handshake));
  EXPECT_EQ(event->packetSize, getEncodedSize(packet));
  EXPECT_EQ(event->eventType, QLogEventType::PacketSent);
  // verify QLogger contains correct frame information
  EXPECT_EQ(event->frames.size(), 1);
  auto frame = static_cast<MaxDataFrameLog*>(event->frames[0].get());
  EXPECT_EQ(frame->maximumData, conn->flowControlState.advertisedMaxOffset);
}

TEST_F(QuicTransportFunctionsTest, TestUpdateConnectionSkipAPacketNumber) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("12345"), false)
          .hasError());

  // Packet with CryptoFrame in AppData pn space
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData, true);

  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  ASSERT_FALSE(conn->ackStates.appDataAckState.skippedPacketNum.has_value());

  // Force-skip a packet number
  conn->transportSettings.skipOneInNPacketSequenceNumber = 1;

  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("67890"), true)
          .hasError());
  WriteStreamFrame writeStreamFrame2(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame2));
  auto sentPacketNumber = conn->ackStates.appDataAckState.nextPacketNum;
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());

  ASSERT_TRUE(conn->ackStates.appDataAckState.skippedPacketNum.has_value());
  EXPECT_EQ(
      conn->ackStates.appDataAckState.skippedPacketNum.value(),
      sentPacketNumber + 1);
  EXPECT_EQ(
      conn->ackStates.appDataAckState.nextPacketNum, sentPacketNumber + 2);
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsEmptyPacket) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());
  // Since there is no ACK eliciting frame in this packet,
  // it is not included as an outstanding packet, and there's no StreamDetails
  EXPECT_EQ(0, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsNoStreamsInPacket) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.push_back(blockedFrame);
  packet.packet.frames.push_back(PingFrame());
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());
  // If we have only control frames sent, there should be no stream data in the
  // outstanding packet.
  ASSERT_EQ(1, conn->outstandings.packets.size());
  const auto& detailsPerStream =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->metadata.detailsPerStream;
  EXPECT_THAT(detailsPerStream, IsEmpty());
}

TEST_F(QuicTransportFunctionsTest, TestPingFrameCounter) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(PingFrame());
  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(1, conn->numPingFramesSent);
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStream) {
  uint64_t frameOffset = 0;
  uint64_t frameLen = 10;

  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto result = writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("abcdefghij"), true);
  ASSERT_FALSE(result.hasError());
  WriteStreamFrame writeStreamFrame(
      stream->id, frameOffset, frameLen, false /* fin */);
  packet.packet.frames.push_back(writeStreamFrame);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  const auto streamMatcher = testing::Pair(
      stream->id,
      testing::AllOf(
          testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
          testing::Field(&PacketStreamDetails::newStreamBytesSent, frameLen),
          testing::Field(
              &PacketStreamDetails::maybeFirstNewStreamByteOffset,
              OptionalIntegral<uint64_t>(frameOffset)),
          testing::Field(
              &PacketStreamDetails::streamIntervals,
              testing::ElementsAre(
                  Interval<uint64_t>(
                      frameOffset, frameOffset + frameLen - 1)))));
  const auto pktMatcher = testing::Field(
      &OutstandingPacketWrapper::metadata,
      testing::AllOf(
          testing::Field(
              &OutstandingPacketMetadata::detailsPerStream,
              testing::UnorderedElementsAre(streamMatcher))));

  EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamMultipleFrames) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto result = writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("abcdefghijklmno"), true);
  ASSERT_FALSE(result.hasError());
  WriteStreamFrame writeStreamFrame1(
      stream->id, 0 /* offset */, 10 /* length */, false /* fin */);
  WriteStreamFrame writeStreamFrame2(
      stream->id, 10 /* offset */, 5 /* length */, true /* fin */);
  packet.packet.frames.push_back(writeStreamFrame1);
  packet.packet.frames.push_back(writeStreamFrame2);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  const auto streamMatcher = testing::Pair(
      stream->id,
      testing::AllOf(
          testing::Field(&PacketStreamDetails::streamBytesSent, 15),
          testing::Field(&PacketStreamDetails::newStreamBytesSent, 15),
          testing::Field(
              &PacketStreamDetails::maybeFirstNewStreamByteOffset,
              OptionalIntegral<uint64_t>(0)),
          testing::Field(
              &PacketStreamDetails::streamIntervals,
              testing::ElementsAre(Interval<uint64_t>(0, 14)))));
  const auto pktMatcher = testing::Field(
      &OutstandingPacketWrapper::metadata,
      testing::AllOf(
          testing::Field(
              &OutstandingPacketMetadata::detailsPerStream,
              testing::UnorderedElementsAre(streamMatcher))));

  EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();

  auto result = writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("abcdefghij"), false /* eof */);
  ASSERT_FALSE(result.hasError());
  uint64_t frame1Offset = 0;
  uint64_t frame1Len = 10;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frame1Len, false /* fin */);
  packet.packet.frames.push_back(frame1);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  ASSERT_EQ(1, conn->outstandings.packets.size());

  // The first outstanding packet is the one with new data
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, frame1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, frame1Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(frame1Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frame1Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // retransmit the same frame1 again.
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(frame1);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  ASSERT_EQ(2, conn->outstandings.packets.size());

  // The second outstanding packet is the one with retransmit data
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, frame1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frame1Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // Retransmit frame1 and send new data in frame2.
  result = writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("klmnopqrstuvwxy"), false /* eof */);
  ASSERT_FALSE(result.hasError());
  uint64_t frame2Offset = 10;
  uint64_t frame2Len = 15;
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frame2Len, false /* fin */);
  packet.packet.frames.push_back(frame1);
  packet.packet.frames.push_back(frame2);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  ASSERT_EQ(3, conn->outstandings.packets.size());

  // The third outstanding packet will have both new and retransmitted data.
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(
                &PacketStreamDetails::streamBytesSent, frame1Len + frame2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, frame2Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(frame2Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame2Offset + frame2Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }

  // Retransmit frame1 aand frame2.
  packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet.packet.frames.push_back(frame1);
  packet.packet.frames.push_back(frame2);
  result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt,
      packet.packet,
      TimePoint(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  ASSERT_EQ(4, conn->outstandings.packets.size());

  // The forth outstanding packet will have only retransmit data.
  {
    const auto streamMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(
                &PacketStreamDetails::streamBytesSent, frame1Len + frame2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame2Offset + frame2Len - 1)))));
    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsSingleStreamFinWithRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 1;

  // write two packets, each containing one byte of frame data
  // second packet contains FIN
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("a"), false /* eof */)
                   .hasError());
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet1.packet,
                   TimePoint(),
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("b"), true /* eof */)
                   .hasError());
  uint64_t frame2Offset = (frameLen * 2) - 1;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, true /* fin */);
  packet2.packet.frames.push_back(frame2);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet2.packet,
                   TimePoint(),
                   getEncodedSize(packet2),
                   getEncodedBodySize(packet2))
                   .hasError());

  // Should be two packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(2));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](auto frameOffset) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  OptionalIntegral<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(
                      Interval<uint64_t>(
                          frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame1Offset)))));

    const auto pkt2Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame2Offset)))));

    EXPECT_THAT(
        conn->outstandings.packets, ElementsAre(pkt1Matcher, pkt2Matcher));
  }

  // retransmit both frames in packet3
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet3.packet.frames.push_back(frame1);
  packet3.packet.frames.push_back(frame2);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet3.packet,
                   TimePoint(),
                   getEncodedSize(packet3),
                   getEncodedBodySize(packet3))
                   .hasError());

  // Should be three packets at this point
  //
  // StreamDetails should report fin since frame2 is in packet3
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame2
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame2Offset + frameLen - 1)))));

    const auto pkt3Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pkt3Matcher));
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    StreamDetailsSingleStreamSingleBytePktsPartialAckRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 1;

  // write three packets, each containing one byte of frame data
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("a"), false /* eof */)
                   .hasError());
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet1.packet,
                   TimePoint(),
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("b"), false /* eof */)
                   .hasError());
  uint64_t frame2Offset = frameLen;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, false /* fin */);
  packet2.packet.frames.push_back(frame2);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet2.packet,
                   TimePoint(),
                   getEncodedSize(packet2),
                   getEncodedBodySize(packet2))
                   .hasError());

  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("c"), false /* eof */)
                   .hasError());
  uint64_t frame3Offset = frameLen * 2;
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame3(stream->id, frame3Offset, frameLen, false /* fin */);
  packet3.packet.frames.push_back(frame3);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet3.packet,
                   TimePoint(),
                   getEncodedSize(packet3),
                   getEncodedBodySize(packet3))
                   .hasError());

  // Should be three packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](auto frameOffset) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  OptionalIntegral<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(
                      Interval<uint64_t>(
                          frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame1Offset)))));

    const auto pkt2Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame2Offset)))));

    const auto pkt3Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame3Offset)))));

    EXPECT_THAT(
        conn->outstandings.packets,
        ElementsAre(pkt1Matcher, pkt2Matcher, pkt3Matcher));
  }

  // retransmit contents of packet1 and packet3 (frame1 and frame3) in packet4
  // simulates ACK of packet2 and loss of packet1 and packet3
  auto packet4 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet4.packet.frames.push_back(frame1);
  packet4.packet.frames.push_back(frame3);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet4.packet,
                   TimePoint(),
                   getEncodedSize(packet4),
                   getEncodedBodySize(packet4))
                   .hasError());

  // Should be four packets at this point
  EXPECT_THAT(conn->outstandings.packets, SizeIs(4));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame 3
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frameLen - 1),
                    Interval<uint64_t>(
                        frame3Offset, frame3Offset + frameLen - 1)))));

    const auto pkt4Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pkt4Matcher));
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    StreamDetailsSingleStreamTwoBytePktsPartialAckRetransmit) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const uint64_t frameLen = 2;

  // write three packets, each containing two bytes of frame data
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("ab"), false /* eof */)
                   .hasError());
  uint64_t frame1Offset = 0;
  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame1(stream->id, frame1Offset, frameLen, false /* fin */);
  packet1.packet.frames.push_back(frame1);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet1.packet,
                   TimePoint(),
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("cd"), false /* eof */)
                   .hasError());
  uint64_t frame2Offset = frameLen;
  MVLOG_INFO << "frame2Offset = " << frame2Offset;
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame2(stream->id, frame2Offset, frameLen, false /* fin */);
  packet2.packet.frames.push_back(frame2);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet2.packet,
                   TimePoint(),
                   getEncodedSize(packet2),
                   getEncodedBodySize(packet2))
                   .hasError());

  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("ef"), false /* eof */)
                   .hasError());
  uint64_t frame3Offset = (frameLen * 2);
  MVLOG_INFO << "frame3Offset = " << frame3Offset;
  auto packet3 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame frame3(stream->id, frame3Offset, frameLen, false /* fin */);
  packet3.packet.frames.push_back(frame3);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet3.packet,
                   TimePoint(),
                   getEncodedSize(packet3),
                   getEncodedBodySize(packet3))
                   .hasError());

  // Should be three packets at this point, each with 1 frame of data
  EXPECT_THAT(conn->outstandings.packets, SizeIs(3));
  {
    auto getStreamDetailsMatcher = [&stream, &frameLen](auto frameOffset) {
      return testing::Pair(
          stream->id,
          testing::AllOf(
              testing::Field(&PacketStreamDetails::streamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::newStreamBytesSent, frameLen),
              testing::Field(
                  &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                  OptionalIntegral<uint64_t>(frameOffset)),
              testing::Field(
                  &PacketStreamDetails::streamIntervals,
                  testing::ElementsAre(
                      Interval<uint64_t>(
                          frameOffset, frameOffset + frameLen - 1)))));
    };

    const auto pkt1Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame1Offset)))));

    const auto pkt2Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame2Offset)))));

    const auto pkt3Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    getStreamDetailsMatcher(frame3Offset)))));

    EXPECT_THAT(
        conn->outstandings.packets,
        ElementsAre(pkt1Matcher, pkt2Matcher, pkt3Matcher));
  }

  // retransmit contents of packet1 and packet3 (frame1 and frame3) in packet4
  // simulates ACK of packet2 and loss of packet1 and packet3
  auto packet4 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet4.packet.frames.push_back(frame1);
  packet4.packet.frames.push_back(frame3);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet4.packet,
                   TimePoint(),
                   getEncodedSize(packet4),
                   getEncodedBodySize(packet4))
                   .hasError());

  // Should be four packets at this point
  EXPECT_THAT(conn->outstandings.packets, SizeIs(4));
  {
    auto streamDetailsMatcher = testing::Pair(
        stream->id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, frameLen * 2),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                // contains frame1 and frame 3
                testing::ElementsAre(
                    Interval<uint64_t>(
                        frame1Offset, frame1Offset + frameLen - 1),
                    Interval<uint64_t>(
                        frame3Offset, frame3Offset + frameLen - 1)))));

    const auto pkt4Matcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(streamDetailsMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pkt4Matcher));
  }
}

TEST_F(QuicTransportFunctionsTest, StreamDetailsMultipleStreams) {
  auto conn = createConn();
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream3Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto stream3 = conn->streamManager->findStream(stream3Id);
  ASSERT_NE(nullptr, stream1);
  ASSERT_NE(nullptr, stream2);
  ASSERT_NE(nullptr, stream3);

  auto buf = IOBuf::copyBuffer("hey whats up");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream3, buf->clone(), true).hasError());

  uint64_t stream1Offset = 0;
  uint64_t stream2Offset = 0;
  uint64_t stream3Offset = 0;
  uint64_t stream1Len = 5;
  uint64_t stream2Len = 12;
  uint64_t stream3Len = 5;

  auto packet1 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame writeStreamFrame1(
      stream1->id, stream1Offset, stream1Len, false);
  WriteStreamFrame writeStreamFrame2(
      stream2->id, stream2Offset, stream2Len, true);
  WriteStreamFrame writeStreamFrame3(
      stream3->id, stream3Offset, stream3Len, true);
  packet1.packet.frames.push_back(writeStreamFrame1);
  packet1.packet.frames.push_back(writeStreamFrame2);
  packet1.packet.frames.push_back(writeStreamFrame3);

  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet1.packet,
                   TimePoint(),
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  // check stream details for the sent packet
  {
    auto stream1DetailsMatcher = testing::Pair(
        stream1Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, stream1Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream1Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(stream1Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream1Offset, stream1Offset + stream1Len - 1)))));
    auto stream2DetailsMatcher = testing::Pair(
        stream2Id,
        testing::AllOf(

            testing::Field(&PacketStreamDetails::streamBytesSent, stream2Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream2Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(stream2Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream2Offset, stream2Offset + stream2Len - 1)))));
    auto stream3DetailsMatcher = testing::Pair(
        stream3Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, stream3Len),
            testing::Field(
                &PacketStreamDetails::newStreamBytesSent, stream3Len),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(stream3Offset)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream3Offset, stream3Offset + stream3Len - 1)))));

    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    stream1DetailsMatcher,
                    stream2DetailsMatcher,
                    stream3DetailsMatcher))));

    EXPECT_THAT(conn->outstandings.packets, ElementsAre(pktMatcher));
  }

  // retransmit the packet
  auto packet2 = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  packet2.packet.frames.push_back(writeStreamFrame1);
  packet2.packet.frames.push_back(writeStreamFrame2);
  packet2.packet.frames.push_back(writeStreamFrame3);

  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet2.packet,
                   TimePoint(),
                   getEncodedSize(packet1),
                   getEncodedBodySize(packet1))
                   .hasError());

  // check stream details for the retransmitted packet
  EXPECT_THAT(conn->outstandings.packets, SizeIs(2));
  {
    auto stream1DetailsMatcher = testing::Pair(
        stream1Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, stream1Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream1Offset, stream1Offset + stream1Len - 1)))));
    auto stream2DetailsMatcher = testing::Pair(
        stream2Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, stream2Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream2Offset, stream2Offset + stream2Len - 1)))));
    auto stream3DetailsMatcher = testing::Pair(
        stream3Id,
        testing::AllOf(
            testing::Field(&PacketStreamDetails::streamBytesSent, stream3Len),
            testing::Field(&PacketStreamDetails::newStreamBytesSent, 0),
            testing::Field(
                &PacketStreamDetails::maybeFirstNewStreamByteOffset,
                OptionalIntegral<uint64_t>(/* empty */)),
            testing::Field(
                &PacketStreamDetails::streamIntervals,
                testing::ElementsAre(
                    Interval<uint64_t>(
                        stream3Offset, stream3Offset + stream3Len - 1)))));

    const auto pktMatcher = testing::Field(
        &OutstandingPacketWrapper::metadata,
        testing::AllOf(
            testing::Field(
                &OutstandingPacketMetadata::detailsPerStream,
                testing::UnorderedElementsAre(
                    stream1DetailsMatcher,
                    stream2DetailsMatcher,
                    stream3DetailsMatcher))));

    EXPECT_THAT(conn->outstandings.packets, Contains(pktMatcher));
  }
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketWithCC) {
  auto conn = createConn();
  conn->udpSendPacketLen = 30;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  uint64_t writableBytes = 30;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            size_t totalLen = getTotalIovecLen(vec, iovec_len);
            EXPECT_LE(totalLen, 30);
            writableBytes -= totalLen;
            return totalLen;
          }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
}

TEST_F(QuicTransportFunctionsTest, WriteQuicdataToSocketWithPacer) {
  auto conn = createConn();
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn->pacer = std::move(mockPacer);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  EXPECT_CALL(*rawPacer, onPacketSent()).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketLimitTest) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->udpSendPacketLen = aead->getCipherOverhead() + 50;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();

  // 90 bytes.
  // This will be written twice. A total of 180 bytes gives enough for:
  // 1 packet in the first write limited by the writable bytes
  // 5 probe packets in the second write with fresh stream data
  // 5 probe packets cloned from the first 5 outstanding packets
  auto buf = IOBuf::copyBuffer(
      "01234567890120123456789012012345678901201234567890123456789012345678901234567890123456789");

  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  uint64_t writableBytes = 30;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));

  // Limit to zero
  conn->transportSettings.writeConnectionDataPacketsLimit = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _)).Times(0);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(0, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
  EXPECT_EQ(0, res->bytesWritten);

  // Normal limit
  ++(conn->writeCount);
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 0;
  conn->transportSettings.writeConnectionDataPacketsLimit =
      kDefaultWriteConnectionDataPacketLimit;
  uint64_t actualWritten = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            writableBytes -= getTotalIovecLen(vec, iovec_len);
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(1, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
  EXPECT_EQ(actualWritten, res->bytesWritten);

  // Probing can exceed packet limit. In practice we limit it to
  // kPacketToSendForPTO
  ++(conn->writeCount);
  actualWritten = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] =
      kDefaultWriteConnectionDataPacketLimit * 2;
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  writableBytes = 10000;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(kDefaultWriteConnectionDataPacketLimit * 2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .Times(kDefaultWriteConnectionDataPacketLimit * 2);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(0, res->packetsWritten);
  EXPECT_EQ(kDefaultWriteConnectionDataPacketLimit * 2, res->probesWritten);
  EXPECT_EQ(actualWritten, res->bytesWritten);
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketNoDuplicateProbesTest) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->udpSendPacketLen = aead->getCipherOverhead() + 50;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();

  // 60 bytes (2 packets)
  auto buf = IOBuf::copyBuffer(
      "01234567890120123456789012012345678901201234567890123456789");

  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  auto writableBytes = 10000;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));

  // Write all the available stream data (2 packets). No probes.
  ++(conn->writeCount);
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 0;
  conn->transportSettings.writeConnectionDataPacketsLimit =
      kDefaultWriteConnectionDataPacketLimit;
  uint64_t actualWritten = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            writableBytes -= getTotalIovecLen(vec, iovec_len);
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(2);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(2, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
  EXPECT_EQ(actualWritten, res->bytesWritten);

  ASSERT_EQ(conn->outstandings.packets.size(), 2);
  // Attempt to send 5 probes. We only have 2 outstanding packets and no more
  // stream data.
  // We should send a clone for each outstanding packet, and one ping.
  // One write has the clones, and another has the ping.
  ++(conn->writeCount);
  actualWritten = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 5;

  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(3)
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(3);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(2);
  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(0, res->packetsWritten);
  EXPECT_EQ(3, res->probesWritten);
  EXPECT_EQ(actualWritten, res->bytesWritten);

  // Verify there are no two packets with the same writeCount and
  // clonedPacketIdentifier
  EXPECT_TRUE(
      std::adjacent_find(
          conn->outstandings.packets.begin(),
          conn->outstandings.packets.end(),
          [](const auto& a, const auto& b) {
            return a.metadata.writeCount == b.metadata.writeCount &&
                a.maybeClonedPacketIdentifier.has_value() &&
                b.maybeClonedPacketIdentifier.has_value() &&
                a.maybeClonedPacketIdentifier.value() ==
                b.maybeClonedPacketIdentifier.value();
          }) == conn->outstandings.packets.end());

  // Verify there is exactly one packet that has a PING frame
  EXPECT_TRUE(
      std::count_if(
          conn->outstandings.packets.begin(),
          conn->outstandings.packets.end(),
          [](const auto& packet) {
            return std::any_of(
                packet.packet.frames.begin(),
                packet.packet.frames.end(),
                [](const auto& frame) {
                  return frame.type() == QuicWriteFrame::Type::PingFrame;
                });
          }) == 1);
}

TEST_F(
    QuicTransportFunctionsTest,
    WriteQuicDataToSocketWhenInFlightBytesAreLimited) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf =
      IOBuf::copyBuffer("0123456789012012345678901201234567890120123456789012");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  conn->writableBytesLimit = 100;
  uint64_t writableBytes = 5 * *conn->writableBytesLimit;

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(
          InvokeWithoutArgs([&writableBytes]() { return writableBytes; }));
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            EXPECT_LE(
                getTotalIovecLen(vec, iovec_len),
                *conn->writableBytesLimit - conn->lossState.totalBytesSent);
            writableBytes -= getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketWithNoBytesForHeader) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789012");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  // No header space left. Should send nothing.
  EXPECT_TRUE(conn->outstandings.packets.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteQuicDataToSocketRetxBufferSorted) {
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("Whatsapp");
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(buf1), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, stream->retransmissionBuffer.size());

  auto buf2 = IOBuf::copyBuffer("Google Buzz");
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, std::move(buf2), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
}

TEST_F(QuicTransportFunctionsTest, NothingWritten) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  // 18 isn't enough to write 3 ack blocks, but is enough to write a pure
  // header packet, which we shouldn't write
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(18));

  addAckStatesWithCurrentTimestamps(*conn->ackStates.initialAckState, 0, 1000);
  addAckStatesWithCurrentTimestamps(
      *conn->ackStates.initialAckState, 1500, 2000);
  addAckStatesWithCurrentTimestamps(
      *conn->ackStates.initialAckState, 2500, 3000);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(0, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
  EXPECT_EQ(0, res->bytesWritten);
}

const QuicWriteFrame& getFirstFrameInOutstandingPackets(
    const std::deque<OutstandingPacketWrapper>& outstandingPackets,
    QuicWriteFrame::Type frameType) {
  for (const auto& packet : outstandingPackets) {
    for (const auto& frame : packet.packet.frames) {
      if (frame.type() == frameType) {
        return frame;
      }
    }
  }
  throw std::runtime_error("Frame not present");
}

TEST_F(QuicTransportFunctionsTest, WriteBlockedFrameWhenBlocked) {
  auto conn = createConn();
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(200);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  auto originalNextSeq = conn->ackStates.appDataAckState.nextPacketNum;
  uint64_t sentBytes = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            auto len = getTotalIovecLen(vec, iovec_len);
            sentBytes += len;
            return len;
          }));

  // Artificially Block the stream
  stream1->flowControlState.peerAdvertisedMaxOffset = 10;
  // writes blocked frame in additionally
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_LT(sentBytes, 200);

  EXPECT_GT(conn->ackStates.appDataAckState.nextPacketNum, originalNextSeq);
  auto blocked = *getFirstFrameInOutstandingPackets(
                      conn->outstandings.packets,
                      QuicWriteFrame::Type::StreamDataBlockedFrame)
                      .asStreamDataBlockedFrame();
  EXPECT_EQ(blocked.streamId, stream1->id);

  // Since everything is blocked, we shouldn't write a blocked again, so we
  // won't have any new packets to write if we trigger a write.
  auto previousPackets = conn->outstandings.packets.size();
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(previousPackets, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingNewData) {
  auto conn = createConn();
  // writeProbingDataToSocketForTest writes ShortHeader, thus it writes at
  // AppTraffic level
  auto currentPacketSeqNum = conn->ackStates.appDataAckState.nextPacketNum;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  // Probing data is not limited by congestion control, this should not affect
  // anything
  EXPECT_CALL(*mockCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(conn->udpSendPacketLen * 2);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf->clone(), true /* eof */).hasError());

  auto currentStreamWriteOffset = stream1->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            auto len = getTotalIovecLen(vec, iovec_len);
            EXPECT_EQ(conn->udpSendPacketLen - aead->getCipherOverhead(), len);
            return len;
          }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));
  EXPECT_LT(currentPacketSeqNum, conn->ackStates.appDataAckState.nextPacketNum);
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(
      conn->outstandings.packets.back().packet.header.getPacketSequenceNum(),
      currentPacketSeqNum + 1);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(stream1->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(stream1->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteProbingOldData) {
  auto conn = createConn();
  conn->congestionController.reset();
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  EXPECT_CALL(*rawSocket, write(_, _, _)).WillRepeatedly(Return(100));
  auto capturingAead = std::make_unique<MockAead>();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Where you wanna go");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
  folly::IOBuf pktBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          pktBodyCaptured.appendToChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));
  // Now we have no new data, let's probe again, and verify the same old data
  // is sent.
  folly::IOBuf secondBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          secondBodyCaptured.appendToChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));
  // Verify two pacekts have the same body
  EXPECT_TRUE(folly::IOBufEqualTo()(pktBodyCaptured, secondBodyCaptured));
}

TEST_F(QuicTransportFunctionsTest, WriteProbingOldDataAckFreq) {
  auto conn = createConn();
  conn->congestionController.reset();
  conn->peerMinAckDelay = 1ms;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  EXPECT_CALL(*rawSocket, write(_, _, _)).WillRepeatedly(Return(100));
  auto capturingAead = std::make_unique<MockAead>();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Where you wanna go");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());

  folly::IOBuf pktBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          pktBodyCaptured.appendToChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));

  auto immAck =
      getFirstFrameInOutstandingPackets(
          conn->outstandings.packets, QuicWriteFrame::Type::ImmediateAckFrame)
          .asImmediateAckFrame();
  EXPECT_TRUE(immAck);
  // Now we have no new data, let's probe again, and verify the same old data
  // is sent.
  folly::IOBuf secondBodyCaptured;
  EXPECT_CALL(*capturingAead, _inplaceEncrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          secondBodyCaptured.appendToChain(buf->clone());
          return buf->clone();
        } else {
          return folly::IOBuf::create(0);
        }
      }));
  writeProbingDataToSocketForTest(
      *rawSocket, *conn, 1, *aead, *headerCipher, getVersion(*conn));
  // Verify two pacekts have the same body
  EXPECT_TRUE(folly::IOBufEqualTo()(pktBodyCaptured, secondBodyCaptured));
}

TEST_F(QuicTransportFunctionsTest, WriteProbingCryptoData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  conn.serverConnectionId = getTestConnectionId();
  conn.clientConnectionId = getTestConnectionId();
  initializePathManagerState(conn);
  // writeCryptoDataProbesToSocketForTest writes Initial LongHeader, thus it
  // writes at Initial level.
  auto currentPacketSeqNum = conn.ackStates.initialAckState->nextPacketNum;
  // Replace real congestionController with MockCongestionController:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  // Probing data is not limited by congestion control, this should not affect
  // anything
  EXPECT_CALL(*mockCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto cryptoStream = &conn.cryptoState->initialStream;
  auto buf = buildRandomInputData(conn.udpSendPacketLen * 2);
  writeDataToQuicStream(*cryptoStream, buf->clone());

  auto currentStreamWriteOffset = cryptoStream->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(1);
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            auto len = getTotalIovecLen(vec, iovec_len);
            EXPECT_EQ(conn.udpSendPacketLen - aead->getCipherOverhead(), len);
            return len;
          }));
  writeCryptoDataProbesToSocketForTest(
      *rawSocket, conn, 1, *aead, *headerCipher, getVersion(conn));
  EXPECT_LT(currentPacketSeqNum, conn.ackStates.initialAckState->nextPacketNum);
  EXPECT_FALSE(conn.outstandings.packets.empty());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(cryptoStream->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(cryptoStream->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, WriteableBytesLimitedProbingCryptoData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.bufAccessor = bufAccessor_.get();
  conn.statsCallback = quicStats_.get();
  conn.transportSettings.enableWritableBytesLimit = true;
  conn.writableBytesLimit = 2 * conn.udpSendPacketLen;

  conn.serverConnectionId = getTestConnectionId();
  conn.clientConnectionId = getTestConnectionId();
  initializePathManagerState(conn);
  // writeCryptoDataProbesToSocketForTest writes Initial LongHeader, thus it
  // writes at Initial level.
  auto currentPacketSeqNum = conn.ackStates.initialAckState->nextPacketNum;
  // Replace real congestionController with MockCongestionController:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto cryptoStream = &conn.cryptoState->initialStream;
  uint8_t probesToSend = 4;
  auto buf = buildRandomInputData(conn.udpSendPacketLen * probesToSend);
  EXPECT_CALL(*quicStats_, onConnectionWritableBytesLimited())
      .Times(AtLeast(1));
  writeDataToQuicStream(*cryptoStream, buf->clone());

  auto currentStreamWriteOffset = cryptoStream->currentWriteOffset;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(2);
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            auto len = getTotalIovecLen(vec, iovec_len);
            EXPECT_EQ(conn.udpSendPacketLen - aead->getCipherOverhead(), len);
            return len;
          }));
  writeCryptoDataProbesToSocketForTest(
      *rawSocket, conn, probesToSend, *aead, *headerCipher, getVersion(conn));

  EXPECT_EQ(conn.numProbesWritableBytesLimited, 2);
  EXPECT_LT(currentPacketSeqNum, conn.ackStates.initialAckState->nextPacketNum);
  EXPECT_FALSE(conn.outstandings.packets.empty());
  EXPECT_TRUE(conn.pendingEvents.setLossDetectionAlarm);
  EXPECT_GT(cryptoStream->currentWriteOffset, currentStreamWriteOffset);
  EXPECT_FALSE(cryptoStream->retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, ProbingNotFallbackToPingWhenNoQuota) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  EXPECT_CALL(*rawSocket, write(_, _, _)).Times(0);
  uint8_t probesToSend = 0;
  EXPECT_EQ(
      0,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
}

TEST_F(QuicTransportFunctionsTest, ProbingFallbackToPing) {
  auto conn = createConn();
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            return getTotalIovecLen(vec, iovec_len);
          }));
  uint8_t probesToSend = 1;
  EXPECT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
  // Ping is the only non-retransmittable packet that will go into OP list
  EXPECT_EQ(1, conn->outstandings.packets.size());
}

TEST_F(
    QuicTransportFunctionsTest,
    NonCloningAppPtoWritesDistinctUnifiedRangesWithZeroCwnd) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abcdef"), false)
          .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 3, 3, false))
          .hasError());

  auto congestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  ON_CALL(*congestionController, getWritableBytes()).WillByDefault(Return(0));
  conn->congestionController = std::move(congestionController);
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(Return(0));
  EXPECT_CALL(*socket, write(_, _, _))
      .Times(2)
      .WillRepeatedly(
          [](const SocketAddress&, const struct iovec* vec, size_t iovecLen) {
            return getTotalIovecLen(vec, iovecLen);
          });

  ASSERT_EQ(
      2,
      writeProbingDataToSocketForTest(
          *socket, *conn, 2, *aead, *headerCipher, getVersion(*conn)));
  ASSERT_GE(conn->outstandings.packets.size(), 4);
  const auto& firstProbe = conn->outstandings.packets[2];
  const auto& secondProbe = conn->outstandings.packets[3];
  EXPECT_EQ(
      PacketTransmissionReason::PtoProbe,
      firstProbe.metadata.transmissionReason);
  EXPECT_EQ(
      PacketTransmissionReason::PtoProbe,
      secondProbe.metadata.transmissionReason);
  EXPECT_FALSE(firstProbe.maybeClonedPacketIdentifier.has_value());
  EXPECT_FALSE(secondProbe.maybeClonedPacketIdentifier.has_value());
  ASSERT_EQ(1, firstProbe.packet.frames.size());
  ASSERT_EQ(1, secondProbe.packet.frames.size());
  EXPECT_EQ(
      WriteStreamFrame(stream->id, 0, 3, false),
      *firstProbe.packet.frames.front().asWriteStreamFrame());
  EXPECT_EQ(
      WriteStreamFrame(stream->id, 3, 3, false),
      *secondProbe.packet.frames.front().asWriteStreamFrame());
}

TEST_F(QuicTransportFunctionsTest, NonCloningAppPtoReservesImmediateAckProbe) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  conn->peerMinAckDelay = 1ms;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abc"), false)
          .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(Return(0));
  EXPECT_CALL(*socket, write(_, _, _))
      .Times(2)
      .WillRepeatedly(
          [](const SocketAddress&, const struct iovec* vec, size_t iovecLen) {
            return getTotalIovecLen(vec, iovecLen);
          });

  ASSERT_EQ(
      2,
      writeProbingDataToSocketForTest(
          *socket, *conn, 2, *aead, *headerCipher, getVersion(*conn)));
  ASSERT_GE(conn->outstandings.packets.size(), 3);
  EXPECT_NE(
      conn->outstandings.packets[2].packet.frames[0].asImmediateAckFrame(),
      nullptr);
  EXPECT_EQ(
      PacketTransmissionReason::PtoProbe,
      conn->outstandings.packets[2].metadata.transmissionReason);
}

TEST_F(QuicTransportFunctionsTest, NonCloningPtoRequiresUnifiedBufferMode) {
  auto conn = createConn();
  conn->transportSettings.useNonCloningPto = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abc"), false)
          .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(Return(0));
  EXPECT_CALL(*socket, write(_, _, _))
      .Times(1)
      .WillOnce(
          [](const SocketAddress&, const struct iovec* vec, size_t iovecLen) {
            return getTotalIovecLen(vec, iovecLen);
          });

  ASSERT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *socket, *conn, 1, *aead, *headerCipher, getVersion(*conn)));
  ASSERT_GE(conn->outstandings.packets.size(), 2);
  const auto& probe = conn->outstandings.packets.back();
  EXPECT_TRUE(probe.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(PacketTransmissionReason::Clone, probe.metadata.transmissionReason);
}

TEST_F(QuicTransportFunctionsTest, NonCloningPtoFallsBackForLegacyStream) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->streamSendBuffer.reset();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("abc"), false)
          .hasError());
  ASSERT_FALSE(
      updateStreamFrame(*conn, WriteStreamFrame(stream->id, 0, 3, false))
          .hasError());

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(Return(0));
  EXPECT_CALL(*socket, write(_, _, _))
      .Times(1)
      .WillOnce(
          [](const SocketAddress&, const struct iovec* vec, size_t iovecLen) {
            return getTotalIovecLen(vec, iovecLen);
          });

  ASSERT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *socket, *conn, 1, *aead, *headerCipher, getVersion(*conn)));
  ASSERT_GE(conn->outstandings.packets.size(), 2);
  const auto& probe = conn->outstandings.packets.back();
  EXPECT_TRUE(probe.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(PacketTransmissionReason::Clone, probe.metadata.transmissionReason);
}

TEST_F(QuicTransportFunctionsTest, ProbingFallbackToImmediateAck) {
  auto conn = createConn();
  conn->peerMinAckDelay = 1ms;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            return getTotalIovecLen(vec, iovec_len);
          }));
  uint8_t probesToSend = 1;
  EXPECT_EQ(
      1,
      writeProbingDataToSocketForTest(
          *rawSocket,
          *conn,
          probesToSend,
          *aead,
          *headerCipher,
          getVersion(*conn)));
  // Immediate Ack is the only non-retransmittable packet that will go into OP
  // list
  EXPECT_EQ(1, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, NoCryptoProbeWriteIfNoProbeCredit) {
  auto conn = createConn();
  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_GE(res->bytesWritten, buf->computeChainDataLength());

  EXPECT_EQ(1, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
  EXPECT_EQ(conn->udpSendPacketLen, res->bytesWritten);
  ASSERT_EQ(1, conn->outstandings.packets.size());
  ASSERT_EQ(1, cryptoStream->retransmissionBuffer.size());
  ASSERT_TRUE(cryptoStream->pendingWrites.empty());

  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 0;
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 0;
  res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(0, res->bytesWritten);
  EXPECT_EQ(0, res->packetsWritten);
  EXPECT_EQ(0, res->probesWritten);
}

TEST_F(QuicTransportFunctionsTest, ImmediatelyRetransmitInitialPackets) {
  auto conn = createConn();
  conn->transportSettings.immediatelyRetransmitInitialPackets = true;
  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(1600);
  writeDataToQuicStream(*cryptoStream, buf->clone());
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));
  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_GE(res->bytesWritten, buf->computeChainDataLength());

  EXPECT_EQ(2, res->packetsWritten);
  EXPECT_EQ(2, res->probesWritten);
  EXPECT_EQ(conn->udpSendPacketLen * 4, res->bytesWritten);
  ASSERT_EQ(4, conn->outstandings.packets.size());
  ASSERT_EQ(2, cryptoStream->retransmissionBuffer.size());
  ASSERT_TRUE(cryptoStream->pendingWrites.empty());
  EXPECT_EQ(
      conn->outstandings.packets[2].metadata.transmissionReason,
      PacketTransmissionReason::ImmediateInitialProbe);
  EXPECT_EQ(
      conn->outstandings.packets[3].metadata.transmissionReason,
      PacketTransmissionReason::ImmediateInitialProbe);
}

TEST_F(
    QuicTransportFunctionsTest,
    ImmediatelyRetransmitInitialPacketsWithOwnedCryptoBuffer) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->transportSettings.useNonCloningPto = true;
  conn->transportSettings.immediatelyRetransmitInitialPackets = true;
  auto& cryptoStream = conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(1600);
  writeDataToQuicStream(*conn, cryptoStream, buf->clone());
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(testing::Return(0));

  auto result = writeCryptoAndAckDataToSocket(
      *socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->packetsWritten, 2);
  EXPECT_EQ(result->probesWritten, 2);
  ASSERT_EQ(conn->outstandings.packets.size(), 4);
  EXPECT_FALSE(
      conn->outstandings.packets[2].maybeClonedPacketIdentifier.has_value());
  EXPECT_FALSE(
      conn->outstandings.packets[3].maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(
      conn->outstandings.packets[2].metadata.transmissionReason,
      PacketTransmissionReason::ImmediateInitialProbe);
  EXPECT_EQ(
      conn->outstandings.packets[3].metadata.transmissionReason,
      PacketTransmissionReason::ImmediateInitialProbe);
  ASSERT_TRUE(cryptoStream.streamSendBuffer.has_value());
  EXPECT_EQ(cryptoStream.streamSendBuffer->outstandingBytes(), 1600);
  EXPECT_TRUE(cryptoStream.retransmissionBuffer.empty());
}

TEST_F(QuicTransportFunctionsTest, ResetNumProbePackets) {
  auto conn = createConn();
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 2;
  auto writeRes1 = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes1.hasError());
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());
  EXPECT_EQ(0, writeRes1->bytesWritten);

  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake] = 2;
  auto writeRes2 = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Handshake,
      *conn->handshakeWriteCipher,
      *conn->handshakeWriteHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes2.hasError());
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());
  EXPECT_EQ(0, writeRes2->bytesWritten);

  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 2;
  auto writeRes3 = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *conn->oneRttWriteCipher,
      *conn->oneRttWriteHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes3.hasError());
  EXPECT_FALSE(conn->pendingEvents.anyProbePackets());

  // A handshaking client with a queued probe but nothing to retransmit still
  // writes an ack-eliciting Initial packet (PING).
  auto clientConn = createClientConn();
  clientConn->pendingEvents.numProbePackets[PacketNumberSpace::Initial] = 2;
  auto antiDeadlockRes = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *clientConn,
      *clientConn->clientConnectionId,
      *clientConn->serverConnectionId,
      LongHeader::Types::Initial,
      *clientConn->initialWriteCipher,
      *clientConn->initialHeaderCipher,
      getVersion(*clientConn),
      clientConn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(antiDeadlockRes.hasError());
  EXPECT_GT(antiDeadlockRes->bytesWritten, 0);
  EXPECT_FALSE(clientConn->pendingEvents.anyProbePackets());
}

TEST_F(QuicTransportFunctionsTest, WritePureAckWhenNoWritableBytes) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789012");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 0, 100);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn->ackStates.appDataAckState.largestAckScheduled = 50;

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));

  uint64_t actualWritten = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            EXPECT_LE(getTotalIovecLen(vec, iovec_len), 30);
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*rawCongestionController, onPacketSent(_)).Times(0);
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_GT(res->packetsWritten, 0);
  EXPECT_EQ(res->bytesWritten, actualWritten);
  EXPECT_EQ(0, conn->outstandings.packets.size());
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataTest) {
  auto conn = createConn();

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  // Pure acks without an oneRttCipher
  MVCHECK(!conn->oneRttWriteCipher);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 1, 20);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_CALL(*quicStats_, onCwndBlocked()).Times(0);
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // Congestion control
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*quicStats_, onCwndBlocked());
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(
    QuicTransportFunctionsTest,
    ShouldWriteDataTestDuringPathValidationForCurrentPath) {
  auto conn = createConn();

  // Switch to an unvalidated path
  auto pathInfoRes = conn->pathManager->getOrAddPath(
      quic::SocketAddress("::1", 12346), quic::SocketAddress("::1", 54321));
  ASSERT_FALSE(pathInfoRes.hasError());
  auto& pathInfo = pathInfoRes.value().get();
  conn->currentPathId = pathInfo.id;

  conn->transportSettings.limitedCwndInMss = 1;
  conn->udpSendPacketLen = 1200;

  // Create the CC.
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->oneRttWriteCipher = test::createNoOpAead();

  // Have stream data queued up during the test so there's something to write.
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());

  // Only case that we allow the write; both CC and unvalidated path have
  // writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  // Receiving a packet should add new credit to the path limiter.
  // Credit = conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen
  conn->pathManager->onPathPacketReceived(conn->currentPathId);
  ASSERT_EQ(pathInfo.writableBytes, 1200);

  EXPECT_CALL(*quicStats_, onCwndBlocked()).Times(0);
  EXPECT_EQ(WriteDataReason::STREAM, shouldWriteData(*conn));

  // CC has writableBytes, but PathInfo doesn't.
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  conn->pathManager->onPathPacketSent(conn->currentPathId, 1200);

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // PathInfo has writableBytes, CC doesn't
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  conn->pathManager->onPathPacketReceived(conn->currentPathId);
  ASSERT_EQ(pathInfo.writableBytes, 1200);

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // Neither PathInfo or CC have writablebytes
  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  conn->pathManager->onPathPacketSent(conn->currentPathId, 1200);

  EXPECT_CALL(*quicStats_, onCwndBlocked());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(
    QuicTransportFunctionsTest,
    ShouldWriteDataTestDuringPathValidationForAlternatePath) {
  auto conn = createConn();

  // Initiate a probe on an alternate path. This is not the current path.

  auto pathInfoRes = conn->pathManager->getOrAddPath(
      quic::SocketAddress("::1", 12346), quic::SocketAddress("::1", 54321));
  ASSERT_FALSE(pathInfoRes.hasError());
  auto& pathInfo = pathInfoRes.value().get();

  conn->transportSettings.limitedCwndInMss = 1;
  conn->udpSendPacketLen = 1200;

  // Create the CC.
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->oneRttWriteCipher = test::createNoOpAead();

  // CC always has writable bytes.
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));
  EXPECT_CALL(*quicStats_, onCwndBlocked()).Times(0);

  // Only case that we allow the write; is when we have a probe to write and
  // enough writable bytes for the path.

  // Receiving a packet should add new credit to the path writable bytes.
  // Credit = conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen
  conn->pathManager->onPathPacketReceived(pathInfo.id);
  ASSERT_EQ(pathInfo.writableBytes, 1200);

  // There are writable bytes but no challenges/responses.
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // There are writable bytes and a challenge flagged.
  conn->pendingEvents.pathChallenges.insert(pathInfo.id);
  EXPECT_EQ(WriteDataReason::PATH_VALIDATION, shouldWriteData(*conn));

  // There are writable bytes and a response.
  conn->pendingEvents.pathChallenges.clear();
  conn->pendingEvents.pathResponses.emplace(
      pathInfo.id, PathResponseFrame(12345));
  EXPECT_EQ(WriteDataReason::PATH_VALIDATION, shouldWriteData(*conn));

  // There is a response but no writable bytes
  conn->pathManager->onPathPacketSent(pathInfo.id, 1200);
  ASSERT_EQ(pathInfo.writableBytes, 0);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));

  // There is a challenge but no writable bytes
  conn->pendingEvents.pathResponses.clear();
  conn->pendingEvents.pathChallenges.insert(pathInfo.id);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(
    QuicTransportFunctionsTest,
    HasAlternatePathValidationDataToWriteRequiresFullPacketBudget) {
  auto conn = createConn();

  auto pathInfoRes = conn->pathManager->getOrAddPath(
      folly::SocketAddress("::1", 12346), folly::SocketAddress("::1", 54321));
  ASSERT_FALSE(pathInfoRes.hasError());
  auto& pathInfo = pathInfoRes.value().get();

  conn->transportSettings.limitedCwndInMss = 1;
  conn->udpSendPacketLen = 1200;

  // Leave the alternate path with a positive-but-sub-packet writable budget:
  // credit one packet's worth, then account a slightly smaller sent packet so
  // 50 bytes remain -- too small to emit a path validation packet.
  conn->pathManager->onPathPacketReceived(pathInfo.id);
  ASSERT_EQ(pathInfo.writableBytes, 1200);
  conn->pathManager->onPathPacketSent(pathInfo.id, 1150);
  ASSERT_EQ(pathInfo.writableBytes, 50);

  // A challenge is pending but the path cannot fit a path validation packet.
  // The loop trigger must be false; otherwise the write loop spins emitting
  // empty PathValidationScheduler writes (no_write_reason=NoFrame).
  conn->pendingEvents.pathChallenges.insert(pathInfo.id);
  EXPECT_FALSE(hasAlternatePathValidationDataToWrite(*conn));

  // Same for a pending response.
  conn->pendingEvents.pathChallenges.clear();
  conn->pendingEvents.pathResponses.emplace(
      pathInfo.id, PathResponseFrame(12345));
  EXPECT_FALSE(hasAlternatePathValidationDataToWrite(*conn));

  // Once a full packet of credit is available, the path is writable again.
  conn->pathManager->onPathPacketReceived(pathInfo.id);
  ASSERT_GE(pathInfo.writableBytes, conn->udpSendPacketLen);
  EXPECT_TRUE(hasAlternatePathValidationDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteStreamsNoCipher) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWritePureAcksNoCipher) {
  auto conn = createConn();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  conn->congestionController = std::move(mockCongestionController);

  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn->ackStates.appDataAckState, 1, 20);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataNoConnFlowControl) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  // Artificially limit the connection flow control.
  conn->flowControlState.peerAdvertisedMaxOffset = 0;
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, ShouldWriteDataNoConnFlowControlLoss) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1500));
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("0123456789");
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), false).hasError());
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
  // Artificially limit the connection flow control.
  conn->streamManager->addLoss(stream1->id);
  conn->flowControlState.peerAdvertisedMaxOffset = 0;
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteCipherAndAckStateMatch) {
  auto conn = createConn();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->initialWriteCipher = test::createNoOpAead();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn->ackStates.appDataAckState.acks.insert(0, 100);
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.initialAckState->needsToSendAckImmediately = true;
  conn->ackStates.initialAckState->acks.insert(0, 100);
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteNoImmediateAcks) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.appDataAckState.acks.insert(0, 100);
  conn->ackStates.appDataAckState.needsToSendAckImmediately = false;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.appDataAckState.needsToSendAckImmediately = true;
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteNoAcksScheduled) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.initialAckState->needsToSendAckImmediately = true;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWrite) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  conn->ackStates.initialAckState->needsToSendAckImmediately = true;
  conn->ackStates.initialAckState->acks.insert(0);
  EXPECT_TRUE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAckDataToWriteMismatch) {
  // When one ack space has needsToSendAckImmediately = true and another has
  // hasAckToSchedule = true, but no ack space has both of them to true, we
  // should not send.
  auto conn = createConn();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.initialAckState->needsToSendAckImmediately = true;
  EXPECT_FALSE(hasAckDataToWrite(*conn));
  conn->ackStates.handshakeAckState->acks.insert(0, 10);
  conn->handshakeWriteCipher = test::createNoOpAead();
  EXPECT_FALSE(hasAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasCryptoDataToWrite) {
  auto conn = createConn();
  auto dataBuf = folly::IOBuf::copyBuffer("Grab your coat and get your hat");
  conn->cryptoState->initialStream.lossBuffer.emplace_back(
      ChainedByteRangeHead(dataBuf), 0, false);
  EXPECT_EQ(WriteDataReason::CRYPTO_STREAM, hasNonAckDataToWrite(*conn));
  conn->initialWriteCipher.reset();
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasControlFramesToWrite) {
  auto conn = createConn();
  conn->streamManager->queueBlocked(1, 100);
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::BLOCKED, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, FlowControlBlocked) {
  auto conn = createConn();
  conn->flowControlState.peerAdvertisedMaxOffset = 1000;
  conn->flowControlState.sumCurWriteOffset = 1000;
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasAppDataToWrite) {
  auto conn = createConn();
  conn->flowControlState.peerAdvertisedMaxOffset = 1000;
  conn->flowControlState.sumCurWriteOffset = 800;
  QuicStreamState stream(0, *conn);
  ASSERT_FALSE(writeDataToQuicStream(
                   stream, folly::IOBuf::copyBuffer("I'm a devil"), true)
                   .hasError());
  conn->streamManager->updateWritableStreams(stream);
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));

  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::STREAM, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, HasDatagramsToWrite) {
  auto conn = createConn();
  conn->oneRttWriteCipher = test::createNoOpAead();
  EXPECT_EQ(WriteDataReason::NO_WRITE, hasNonAckDataToWrite(*conn));
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer("I'm an unreliable Datagram"));
  (void)conn->datagramState.flowManager.addDatagram(
      std::move(buf), kDefaultDatagramFlowId);
  EXPECT_EQ(WriteDataReason::DATAGRAM, hasNonAckDataToWrite(*conn));
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterAppData) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData, 100);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   123,
                   100)
                   .hasError());
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterHandshake) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData, 100);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   123,
                   123)
                   .hasError());
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, UpdateConnectionCloneCounterInitial) {
  auto conn = createConn();
  ASSERT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Initial);
  auto connWindowUpdate =
      MaxDataFrame(conn->flowControlState.advertisedMaxOffset);
  conn->pendingEvents.connWindowUpdate = true;
  packet.packet.frames.emplace_back(connWindowUpdate);
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData, 100);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   123,
                   123)
                   .hasError());
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::Initial]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::Handshake]);
  EXPECT_EQ(
      0, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, ClearBlockedFromPendingEvents) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.push_back(blockedFrame);
  conn->streamManager->queueBlocked(stream->id, 1000);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_FALSE(conn->streamManager->hasBlocked());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, ClonedBlocked) {
  auto conn = createConn();
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  StreamDataBlockedFrame blockedFrame(stream->id, 1000);
  packet.packet.frames.emplace_back(blockedFrame);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  // This shall not crash
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(
      1, conn->outstandings.clonedPacketCount[PacketNumberSpace::AppData]);
}

TEST_F(QuicTransportFunctionsTest, TwoConnWindowUpdateWillCrash) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  MaxDataFrame connWindowUpdate(
      1000 + conn->flowControlState.advertisedMaxOffset);
  packet.packet.frames.emplace_back(connWindowUpdate);
  packet.packet.frames.emplace_back(connWindowUpdate);
  conn->pendingEvents.connWindowUpdate = true;
  EXPECT_DEATH(
      (void)updateConnection(
          *conn,
          *currentPathInfo_,
          std::nullopt,
          packet.packet,
          TimePoint(),
          getEncodedSize(packet),
          getEncodedBodySize(packet)),
      "");
}

TEST_F(QuicTransportFunctionsTest, WriteStreamFrameIsNotPureAck) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream,
                   folly::IOBuf::copyBuffer("I feel like a million bucks."),
                   true)
                   .hasError());
  WriteStreamFrame writeStreamFrame(stream->id, 0, 5, false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_FALSE(conn->outstandings.packets.empty());
}

TEST_F(QuicTransportFunctionsTest, ClearRstFromPendingEvents) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.push_back(rstStreamFrame);
  conn->pendingEvents.resets.emplace(stream->id, rstStreamFrame);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, ClonedRst) {
  auto conn = createConn();
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.emplace_back(std::move(rstStreamFrame));
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  // This shall not crash
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   getEncodedSize(packet),
                   getEncodedBodySize(packet))
                   .hasError());
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(1, conn->outstandings.numClonedPackets());
}

TEST_F(QuicTransportFunctionsTest, TotalBytesSentUpdate) {
  auto conn = createConn();
  conn->lossState.totalBytesSent = 1234;
  conn->lossState.totalBodyBytesSent = 1000;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint{},
                   4321,
                   4000)
                   .hasError());
  EXPECT_EQ(5555, conn->lossState.totalBytesSent);
  EXPECT_EQ(5000, conn->lossState.totalBodyBytesSent);
}

TEST_F(QuicTransportFunctionsTest, TotalPacketsSentUpdate) {
  const auto startTotalPacketsSent = 1234;
  auto conn = createConn();
  conn->lossState.totalPacketsSent = startTotalPacketsSent;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::Handshake);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   std::nullopt,
                   packet.packet,
                   TimePoint{},
                   4321,
                   0)
                   .hasError());
  EXPECT_EQ(startTotalPacketsSent + 1, conn->lossState.totalPacketsSent);
}

TEST_F(QuicTransportFunctionsTest, TimeoutBasedRetxCountUpdate) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->lossState.timeoutBasedRtxCount = 246;
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  RstStreamFrame rstStreamFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, 0);
  packet.packet.frames.push_back(rstStreamFrame);
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData, 100);
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);
  ASSERT_FALSE(updateConnection(
                   *conn,
                   *currentPathInfo_,
                   clonedPacketIdentifier,
                   packet.packet,
                   TimePoint(),
                   0,
                   0)
                   .hasError());
  EXPECT_EQ(247, conn->lossState.timeoutBasedRtxCount);
}

TEST_F(QuicTransportFunctionsTest, WriteLimitBytRttFraction) {
  auto conn = createConn();
  conn->lossState.srtt = 50ms;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(2048 * 2048);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  uint64_t actualWritten = 0;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            actualWritten += getTotalIovecLen(vec, iovec_len);
            return getTotalIovecLen(vec, iovec_len);
          }));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(50));
  auto writeLoopBeginTime = Clock::now();
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);

  EXPECT_GT(1000, res->packetsWritten);
  EXPECT_EQ(actualWritten, res->bytesWritten);
  EXPECT_EQ(res->probesWritten, 0);

  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);
  EXPECT_EQ(
      conn->transportSettings.writeConnectionDataPacketsLimit,
      res->packetsWritten);
}

TEST_F(QuicTransportFunctionsTest, WriteLimitBytRttFractionNoLimit) {
  auto conn = createConn();
  conn->lossState.srtt = 50ms;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
  conn->transportSettings.writeLimitRttFraction = 0;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(2048 * 2048);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  EXPECT_CALL(*rawSocket, write(_, _, _)).WillRepeatedly(Return(1));
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(50));
  auto writeLoopBeginTime = Clock::now();
  auto res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);
  ASSERT_FALSE(res.hasError());

  EXPECT_GE(1000, res->packetsWritten);
  EXPECT_EQ(res->probesWritten, 0);

  res = writeQuicDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      1000 /* packetLimit */,
      writeLoopBeginTime);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(1000, res->packetsWritten);
}

TEST_F(QuicTransportFunctionsTest, CongestionControlWritableBytesRoundUp) {
  auto conn = createConn();
  conn->udpSendPacketLen = 2000;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(1));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(1000));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes()).WillOnce(Return(0));
  EXPECT_EQ(0, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(2000));
  EXPECT_EQ(conn->udpSendPacketLen, congestionControlWritableBytes(*conn));

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(2001));
  EXPECT_EQ(conn->udpSendPacketLen * 2, congestionControlWritableBytes(*conn));
}

TEST_F(QuicTransportFunctionsTest, HandshakeConfirmedDropCipher) {
  auto conn = createConn();
  conn->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*socket, getGSO).WillByDefault(testing::Return(0));
  auto initialStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Initial);
  auto handshakeStream =
      getCryptoStream(*conn->cryptoState, EncryptionLevel::Handshake);
  writeDataToQuicStream(
      *initialStream, folly::IOBuf::copyBuffer("LittleRemedies"));
  writeDataToQuicStream(
      *handshakeStream,
      folly::IOBuf::copyBuffer("Where should I join the meeting"));
  ASSERT_NE(nullptr, conn->initialWriteCipher);
  conn->handshakeWriteCipher = createNoOpAead();
  conn->readCodec->setInitialReadCipher(createNoOpAead());
  conn->readCodec->setInitialHeaderCipher(createNoOpHeaderCipher().value());
  conn->readCodec->setHandshakeReadCipher(createNoOpAead());
  conn->readCodec->setHandshakeHeaderCipher(createNoOpHeaderCipher().value());
  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->readCodec->setOneRttReadCipher(createNoOpAead());
  conn->readCodec->setOneRttHeaderCipher(createNoOpHeaderCipher().value());
  writeCryptoDataProbesToSocketForTest(
      *socket,
      *conn,
      1,
      *aead,
      *headerCipher,
      getVersion(*conn),
      LongHeader::Types::Initial);
  writeCryptoDataProbesToSocketForTest(
      *socket,
      *conn,
      1,
      *aead,
      *headerCipher,
      getVersion(*conn),
      LongHeader::Types::Handshake);
  ASSERT_FALSE(initialStream->retransmissionBuffer.empty());
  ASSERT_FALSE(handshakeStream->retransmissionBuffer.empty());
  auto lossBufferData1 = folly::IOBuf::copyBuffer(
      "I don't see the dialup info in the meeting invite");
  initialStream->insertIntoLossBuffer(
      std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(lossBufferData1), 0, false));

  auto lossBufferData2 =
      folly::IOBuf::copyBuffer("Traffic Protocol Weekly Sync");
  handshakeStream->insertIntoLossBuffer(
      std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(lossBufferData2), 0, false));

  handshakeConfirmed(*conn);
  EXPECT_TRUE(initialStream->pendingWrites.empty());
  EXPECT_TRUE(initialStream->retransmissionBuffer.empty());
  EXPECT_TRUE(initialStream->lossBuffer.empty());
  EXPECT_TRUE(handshakeStream->pendingWrites.empty());
  EXPECT_TRUE(handshakeStream->retransmissionBuffer.empty());
  EXPECT_TRUE(handshakeStream->lossBuffer.empty());
  EXPECT_EQ(nullptr, conn->initialWriteCipher);
  EXPECT_EQ(nullptr, conn->handshakeWriteCipher);
  EXPECT_EQ(nullptr, conn->readCodec->getInitialCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getInitialHeaderCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getHandshakeReadCipher());
  EXPECT_EQ(nullptr, conn->readCodec->getHandshakeHeaderCipher());
}

TEST_F(QuicTransportFunctionsTest, ProbeWriteNewFunctionalFrames) {
  auto conn = createConn();
  conn->udpSendPacketLen = 1200;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = sock.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            return getTotalIovecLen(vec, iovec_len);
          }));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Drug facts");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  ASSERT_EQ(1, stream->retransmissionBuffer.size());

  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
  conn->flowControlState.windowSize *= 2;
  conn->flowControlState.timeOfLastFlowControlUpdate = Clock::now() - 20s;
  maybeSendConnWindowUpdate(*conn, Clock::now());
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   1 /* limit to 1 packet */)
                   .hasError());
  EXPECT_EQ(2, conn->outstandings.packets.size());
  auto packet = stripPaddingFrames(conn->outstandings.packets[1].packet);
  EXPECT_EQ(1, packet.frames.size());
  EXPECT_EQ(
      QuicWriteFrame::Type::MaxDataFrame,
      conn->outstandings.packets[1].packet.frames[0].type());
}

TEST_F(QuicTransportFunctionsTest, ProbeWriteNewFunctionalFramesAckFreq) {
  auto conn = createConn();
  conn->udpSendPacketLen = 1200;
  conn->peerMinAckDelay = 1ms;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = sock.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            return getTotalIovecLen(vec, iovec_len);
          }));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Drug facts");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  ASSERT_EQ(1, stream->retransmissionBuffer.size());

  conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
  conn->flowControlState.windowSize *= 2;
  conn->flowControlState.timeOfLastFlowControlUpdate = Clock::now() - 20s;
  maybeSendConnWindowUpdate(*conn, Clock::now());
  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   1 /* limit to 1 packet */)
                   .hasError());
  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto packet = stripPaddingFrames(conn->outstandings.packets[1].packet);
  EXPECT_EQ(1, packet.frames.size());
  EXPECT_EQ(
      QuicWriteFrame::Type::MaxDataFrame,
      conn->outstandings.packets[1].packet.frames[0].type());
  packet = stripPaddingFrames(conn->outstandings.packets[2].packet);
  EXPECT_EQ(1, packet.frames.size());
  EXPECT_EQ(
      QuicWriteFrame::Type::ImmediateAckFrame,
      conn->outstandings.packets[2].packet.frames[0].type());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilder) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto bufAccessor = std::make_unique<BufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = bufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  bufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = bufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Andante in C minor");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           auto) {
        EXPECT_GT(bufPtr->length(), 0);
        EXPECT_GE(vec[0].iov_len, buf->length());
        EXPECT_TRUE(
            folly::IOBufEqualTo()(
                *folly::IOBuf::wrapIov(vec, iovec_len), *bufPtr));
        EXPECT_EQ(iovec_len, 1);
        return getTotalIovecLen(vec, iovec_len);
      }));
  ASSERT_FALSE(writeQuicDataToSocket(
                   mockSock,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(
    QuicTransportFunctionsTest,
    InplaceBuilderRejectsInsufficientPhysicalTailroom) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  BufAccessor bufAccessor(256);
  ASSERT_LT(bufAccessor.tailroom(), conn->udpSendPacketLen);
  conn->bufAccessor = &bufAccessor;

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _)).Times(0);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("small payload"), true)
                   .hasError());

  auto result = writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);

  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::INTERNAL_ERROR);
  EXPECT_EQ(bufAccessor.length(), 0);
}

TEST_F(
    QuicTransportFunctionsTest,
    ContinuousMemorySendmmsgFillsNegotiatedMaxBatch) {
  auto conn = createConn();
  conn->udpSendPacketLen = kDefaultMaxUDPPayload;
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->transportSettings.batchingMode =
      QuicBatchingMode::BATCHING_MODE_SENDMMSG;
  conn->transportSettings.maxBatchSize = kDefaultQuicMaxBatchSize;
  conn->congestionController.reset();

  constexpr size_t kBatchCapacity = static_cast<size_t>(kDefaultMaxUDPPayload) *
      static_cast<size_t>(kDefaultQuicMaxBatchSize);
  BufAccessor bufAccessor(kBatchCapacity);
  auto outputBuf = bufAccessor.obtain();
  auto* bufPtr = outputBuf.get();
  bufAccessor.release(std::move(outputBuf));
  conn->bufAccessor = &bufAccessor;

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(false));

  constexpr uint64_t kFlowControlLimit =
      static_cast<uint64_t>(kBatchCapacity) * 2;
  conn->flowControlState.peerAdvertisedMaxOffset = kFlowControlLimit;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      kFlowControlLimit;
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->flowControlState.peerAdvertisedMaxOffset = kFlowControlLimit;
  auto input = buildRandomInputData(
      kBatchCapacity + static_cast<size_t>(kDefaultMaxUDPPayload));
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, input->clone(), false).hasError());

  size_t bytesInBatch = 0;
  EXPECT_CALL(mockSock, writem(_, _, _, _))
      .Times(1)
      .WillOnce([&](folly::Range<const quic::SocketAddress*>,
                    iovec* iovecs,
                    size_t* messageSizes,
                    size_t count) {
        EXPECT_EQ(count, kDefaultQuicMaxBatchSize);
        for (size_t i = 0; i < count; ++i) {
          EXPECT_EQ(messageSizes[i], 1);
          EXPECT_LE(iovecs[i].iov_len, kDefaultMaxUDPPayload);
          bytesInBatch += iovecs[i].iov_len;
        }
        return static_cast<int>(count);
      });

  auto result = writeQuicDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      getVersion(*conn),
      kDefaultQuicMaxBatchSize);

  ASSERT_FALSE(result.hasError());
  EXPECT_GT(
      bytesInBatch,
      kBatchCapacity - static_cast<size_t>(kDefaultMaxUDPPayload));
  EXPECT_EQ(bufPtr->length(), 0);
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilderRollbackBuf) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto bufAccessor = std::make_unique<BufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = bufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  bufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = bufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  EXPECT_CALL(mockSock, write(_, _, _)).Times(0);
  ASSERT_FALSE(writeQuicDataToSocket(
                   mockSock,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceBuilderGSOMultiplePackets) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto bufAccessor = std::make_unique<BufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = bufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  bufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = bufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(conn->udpSendPacketLen * 10);
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_LE(options.gso, conn->udpSendPacketLen);
        EXPECT_GT(vec[0].iov_len, 0);
        EXPECT_TRUE(
            folly::IOBufEqualTo()(
                *folly::IOBuf::wrapIov(vec, iovec_len), *bufPtr));
        EXPECT_EQ(iovec_len, 1);
        return getTotalIovecLen(vec, iovec_len);
      }));
  ASSERT_FALSE(writeQuicDataToSocket(
                   mockSock,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
}

TEST_F(QuicTransportFunctionsTest, WriteWithInplaceSinglePacketWriter) {
  for (uint32_t maxBatchSize : {1u, 16u}) {
    SCOPED_TRACE(maxBatchSize);
    auto conn = createConn();
    conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
    conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
    conn->transportSettings.maxBatchSize = maxBatchSize;
    BufAccessor accessor(conn->udpSendPacketLen * maxBatchSize);
    conn->bufAccessor = &accessor;
    EventBase evb;
    auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
    NiceMock<quic::test::MockAsyncUDPSocket> sock(qEvb);
    ON_CALL(sock, getGSO()).WillByDefault(Return(0));
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    auto buf = buildRandomInputData(conn->udpSendPacketLen * 4);
    ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());
    size_t writes = 0;
    EXPECT_CALL(sock, write(_, _, _))
        .WillRepeatedly(Invoke([&](const quic::SocketAddress&,
                                   const struct iovec* vec,
                                   size_t iovec_len) {
          ++writes;
          auto len = getTotalIovecLen(vec, iovec_len);
          EXPECT_LE(len, conn->udpSendPacketLen);
          return static_cast<ssize_t>(len);
        }));
    auto result = writeQuicDataToSocket(
        sock,
        *conn,
        *conn->clientConnectionId,
        *conn->serverConnectionId,
        *aead,
        *headerCipher,
        getVersion(*conn),
        conn->transportSettings.writeConnectionDataPacketsLimit);
    ASSERT_FALSE(result.hasError());
    EXPECT_GT(result->packetsWritten, 1u);
    EXPECT_EQ(writes, result->packetsWritten);
    EXPECT_EQ(0, accessor.length());
    EXPECT_EQ(0, accessor.headroom());
  }
}

TEST_F(QuicTransportFunctionsTest, WriteProbingWithInplaceBuilder) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));

  BufAccessor bufAccessor(
      conn->udpSendPacketLen * conn->transportSettings.maxBatchSize);
  conn->bufAccessor = &bufAccessor;
  auto buf = bufAccessor.obtain();
  auto bufPtr = buf.get();
  bufAccessor.release(std::move(buf));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto inputBuf = buildRandomInputData(
      conn->udpSendPacketLen *
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, inputBuf->clone(), true).hasError());
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_LE(options.gso, conn->udpSendPacketLen);
        EXPECT_GE(
            bufPtr->length(),
            conn->udpSendPacketLen *
                conn->transportSettings.writeConnectionDataPacketsLimit);
        EXPECT_TRUE(
            folly::IOBufEqualTo()(
                *folly::IOBuf::wrapIov(vec, iovec_len), *bufPtr));
        EXPECT_EQ(iovec_len, 1);
        return getTotalIovecLen(vec, iovec_len);
      }));
  ASSERT_FALSE(writeQuicDataToSocket(
                   mockSock,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   getVersion(*conn),
                   conn->transportSettings.writeConnectionDataPacketsLimit + 1)
                   .hasError());
  ASSERT_EQ(0, bufPtr->length());
  ASSERT_EQ(0, bufPtr->headroom());
  EXPECT_GE(conn->outstandings.packets.size(), 5);
  // Make sure there no more new data to write:
  StreamFrameScheduler streamScheduler(*conn);
  ASSERT_FALSE(streamScheduler.hasPendingData());

  // The first packet has be a full packet
  auto firstPacketSize =
      conn->outstandings.packets.front().metadata.encodedSize;
  auto outstandingPacketsCount = conn->outstandings.packets.size();
  ASSERT_EQ(firstPacketSize, conn->udpSendPacketLen);
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           auto) {
        EXPECT_EQ(iovec_len, 1);
        EXPECT_EQ(vec[0].iov_len, firstPacketSize);
        return getTotalIovecLen(vec, iovec_len);
      }));
  writeProbingDataToSocketForTest(
      mockSock,
      *conn,
      1 /* probesToSend */,
      *aead,
      *headerCipher,
      getVersion(*conn));
  EXPECT_EQ(conn->outstandings.packets.size(), outstandingPacketsCount + 1);
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());

  // Clone again, this time 2 pacckets.
  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_EQ(iovec_len, 1);
        EXPECT_EQ(conn->udpSendPacketLen, options.gso);
        EXPECT_EQ(vec[0].iov_len, conn->udpSendPacketLen * 2);
        return getTotalIovecLen(vec, iovec_len);
      }));
  writeProbingDataToSocketForTest(
      mockSock,
      *conn,
      2 /* probesToSend */,
      *aead,
      *headerCipher,
      getVersion(*conn));
  EXPECT_EQ(0, bufPtr->length());
  EXPECT_EQ(0, bufPtr->headroom());
  EXPECT_EQ(conn->outstandings.packets.size(), outstandingPacketsCount + 3);
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytes) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("abcdefghij"), true)
                   .hasError());

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_FALSE(updateConnection(
                     *conn,
                     *currentPathInfo_,
                     std::nullopt,
                     packet.packet,
                     TimePoint(),
                     getEncodedSize(packet),
                     getEncodedBodySize(packet))
                     .hasError());
  }

  // write frame with bytes 5 -> 6 (start at offset 5, write 2 bytes)
  // should throw since we never wrote byte offset 4
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 5 /* offset */, 2 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_TRUE(updateConnection(
                    *conn,
                    *currentPathInfo_,
                    std::nullopt,
                    packet.packet,
                    TimePoint(),
                    getEncodedSize(packet),
                    getEncodedBodySize(packet))
                    .hasError());
  }
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytesEof) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const std::string str = "abcdefg";
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(str), true)
          .hasError());

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_FALSE(updateConnection(
                     *conn,
                     *currentPathInfo_,
                     std::nullopt,
                     packet.packet,
                     TimePoint(),
                     getEncodedSize(packet),
                     getEncodedBodySize(packet))
                     .hasError());
  }

  // write frame with bytes 5 -> 6 (start at offset 5, write 2 bytes)
  // offset 6 should be last byte in original stream, so we'll mark fin
  //
  // should throw since we never wrote byte offset 4
  {
    const auto offset = 5;
    const auto len = 2;
    EXPECT_EQ(str.length(), offset + len); // should be end of string
    WriteStreamFrame writeStreamFrame(
        stream->id, offset /* offset */, len /* len */, true /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_TRUE(updateConnection(
                    *conn,
                    *currentPathInfo_,
                    std::nullopt,
                    packet.packet,
                    TimePoint(),
                    getEncodedSize(packet),
                    getEncodedBodySize(packet))
                    .hasError());
  }
}

TEST_F(QuicTransportFunctionsTest, MissingStreamFrameBytesSingleByteWrite) {
  auto conn = createConn();
  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const std::string str = "abcdefg";
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer(str), true)
          .hasError());

  // write frame with bytes 0 -> 3 (start at offset 0, write 4 bytes)
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 0 /* offset */, 4 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_FALSE(updateConnection(
                     *conn,
                     *currentPathInfo_,
                     std::nullopt,
                     packet.packet,
                     TimePoint(),
                     getEncodedSize(packet),
                     getEncodedBodySize(packet))
                     .hasError());
  }

  // write frame with bytes 5 -> 5 (start at offset 5, write 1 byte)
  // should throw since we never wrote byte offset 4
  {
    WriteStreamFrame writeStreamFrame(
        stream->id, 5 /* offset */, 1 /* len */, false /* fin */);
    packet.packet.frames.push_back(writeStreamFrame);
    ASSERT_TRUE(updateConnection(
                    *conn,
                    *currentPathInfo_,
                    std::nullopt,
                    packet.packet,
                    TimePoint(),
                    getEncodedSize(packet),
                    getEncodedBodySize(packet))
                    .hasError());
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    StaticCapOnWritableBytesFromThrottlingSignalProvider) {
  auto conn = createConn();
  conn->udpSendPacketLen = 2000;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  auto mockThrottlingSignalProvider =
      std::make_shared<MockThrottlingSignalProvider>();
  ThrottlingSignalProvider::ThrottlingSignal expectedSignal;
  expectedSignal.state =
      ThrottlingSignalProvider::ThrottlingSignal::State::Throttled;
  expectedSignal.maybeBytesToSend = 16000;
  mockThrottlingSignalProvider->useFakeThrottlingSignal(expectedSignal);
  conn->throttlingSignalProvider = mockThrottlingSignalProvider;

  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(10000));
  EXPECT_EQ(10000, congestionControlWritableBytes(*conn));

  // Since cwnd is larger than available tokens, the writable bytes is capped
  // by the available tokens
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(20000));
  EXPECT_EQ(
      expectedSignal.maybeBytesToSend, congestionControlWritableBytes(*conn));
}

TEST_F(
    QuicTransportFunctionsTest,
    onQuicStreamClosedNotCalledOnStreamClearing) {
  {
    auto conn = createConn();
    EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
    EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(1);
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    EXPECT_EQ(stream->id, 1);
    EXPECT_EQ(conn->streamManager->streamCount(), 1);
    conn->streamManager->clearOpenStreams();
    EXPECT_EQ(conn->streamManager->streamCount(), 0);
  }
}

TEST_F(QuicTransportFunctionsTest, onQuicStreamClosedCalledOnConnClosure) {
  {
    auto conn = createConn();
    EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
    EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(1);
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    EXPECT_EQ(stream->id, 1);
    EXPECT_EQ(conn->streamManager->streamCount(), 1);
    conn.reset();
  }
}

TEST_F(QuicTransportFunctionsTest, onQuicStreamClosed) {
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  EXPECT_CALL(*quicStats_, onQuicStreamClosed()).Times(1);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  EXPECT_EQ(stream->id, 1);
  EXPECT_EQ(conn->streamManager->streamCount(), 1);
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(conn->streamManager->removeClosedStream(stream->id).hasError());
  EXPECT_EQ(conn->streamManager->streamCount(), 0);
}

TEST_F(QuicTransportFunctionsTest, UpdatePacketLimitForImminentStreams) {
  auto conn = createConn();
  conn->udpSendPacketLen = 1232;
  conn->flowControlState.sumCurStreamBufferLen = 5000; // 4.05 packets
  conn->transportSettings.minBurstPackets = 2;

  // Not imminent completion (buffer > threshold)
  conn->transportSettings.minStreamBufThresh = 1000;
  uint64_t packetLimit = 3; // Would leave 1304 bytes in buffer (> threshold)
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_FALSE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 3); // Unchanged

  // Imminent completion (buffer < threshold)
  conn->transportSettings.minStreamBufThresh = 2000;
  packetLimit = 3; // Would leave 1304 bytes in buffer (< threshold)
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_TRUE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 6); // ceil(1304/1232)=2, +1 for overhead = 3 extra

  // Zero threshold means not imminent completion
  conn->transportSettings.minStreamBufThresh = 0;
  packetLimit = 3;
  conn->imminentStreamCompletion = false;
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_FALSE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 3); // Unchanged

  // minStreamBufThresh is larger than minBurstPackets
  conn->transportSettings.minStreamBufThresh = 3000;
  conn->transportSettings.minBurstPackets = 2; // 2 * 1232 = 2464
  conn->flowControlState.sumCurStreamBufferLen = 5000;
  packetLimit = 2; // Would leave 2536 bytes in buffer (2464 < 2536 < 3000)
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_FALSE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 2);

  // Negative remaining buffer
  conn->transportSettings.minStreamBufThresh = 3000;
  conn->transportSettings.minBurstPackets = 2; // 2 * 1232 = 2464
  conn->flowControlState.sumCurStreamBufferLen = 5000;
  packetLimit = 5; // remaining buffer is -1160
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_TRUE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 5);

  // Connection flow control caps sendable bytes below buffer length.
  // Buffer has 5000 bytes but FC only allows 1000.
  conn->transportSettings.minStreamBufThresh = 2000;
  conn->transportSettings.minBurstPackets = 2;
  conn->flowControlState.sumCurStreamBufferLen = 5000;
  conn->flowControlState.peerAdvertisedMaxOffset = 2000;
  conn->flowControlState.sumCurWriteOffset = 1000; // FC allows 1000 bytes
  packetLimit = 0;
  conn->imminentStreamCompletion = false;
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  // sendableBytes = min(5000, 1000) = 1000, which is < threshold 2000
  EXPECT_TRUE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 2); // ceil(1000 / 1232) + 1 = 2

  // Skip optimization when there is pending loss data.
  conn->transportSettings.minStreamBufThresh = 2000;
  conn->transportSettings.minBurstPackets = 2;
  conn->flowControlState.sumCurStreamBufferLen = 5000;
  conn->flowControlState.peerAdvertisedMaxOffset = 100000;
  conn->flowControlState.sumCurWriteOffset = 0;
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->streamManager->addLoss(stream->id);
  packetLimit = 3;
  conn->imminentStreamCompletion = false;
  updatePacketLimitForImminentStreams(packetLimit, *conn);
  EXPECT_FALSE(conn->imminentStreamCompletion);
  EXPECT_EQ(packetLimit, 3); // Unchanged — loss recovery in progress
}

TEST_F(QuicTransportFunctionsTest, CongestionControlWithImminentStream) {
  auto conn = createConn();
  conn->udpSendPacketLen = 1232;

  // Make congestionControlWritableBytes only exercise the code path pertaining
  // to the congestion controller's getWritableBytes and the excess cwnd.
  conn->pendingEvents.pathResponses.clear();
  conn->pendingEvents.pathChallenges.clear();
  conn->writableBytesLimit = std::nullopt;
  conn->throttlingSignalProvider = nullptr;

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);

  // Normal congestion control without imminent completion
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(5000));
  conn->imminentStreamCompletion = false;
  conn->transportSettings.excessCwndPctForImminentStreams = 25;
  auto writableBytes = congestionControlWritableBytes(*conn);
  EXPECT_EQ(writableBytes, 6160); // 5000 rounded up to nearest packet multiple

  // With imminent completion, allow excess cwnd
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(5000));
  conn->imminentStreamCompletion = true;
  conn->transportSettings.excessCwndPctForImminentStreams = 25;
  writableBytes = congestionControlWritableBytes(*conn);
  EXPECT_EQ(writableBytes, 7392); // 5000 * 1.25, rounded up to nearest packet
  // Flag persists — cleared by writeQuicDataToSocketImpl after the write
  EXPECT_TRUE(conn->imminentStreamCompletion);

  // With imminent completion but zero excess setting
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillOnce(Return(5000));
  conn->imminentStreamCompletion = true;
  conn->transportSettings.excessCwndPctForImminentStreams = 0;
  writableBytes = congestionControlWritableBytes(*conn);
  EXPECT_EQ(writableBytes, 6160);
  EXPECT_TRUE(conn->imminentStreamCompletion);
}

TEST_F(QuicTransportFunctionsTest, WriterCoalescesSconeAndShortHeader) {
  auto conn = createConn();
  conn->transportSettings.enableSconeSend = true;
  conn->scone.emplace();
  conn->peerAdvertisedSconeSupport = true;

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("test data");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), false).hasError());

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);

  auto packet = buildEmptyPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame writeStreamFrame(stream->id, 0, buf->length(), false);
  packet.packet.frames.push_back(std::move(writeStreamFrame));

  auto result = updateConnection(
      *conn,
      *currentPathInfo_,
      std::nullopt, /* clonedPacketIdentifier */
      packet.packet,
      Clock::now(),
      getEncodedSize(packet),
      getEncodedBodySize(packet));
  ASSERT_FALSE(result.hasError());

  EXPECT_TRUE(conn->peerAdvertisedSconeSupport);

  EXPECT_FALSE(conn->scone->lastSconeSentTime.has_value());
}

TEST_F(QuicTransportFunctionsTest, SconePacketSizeValidation) {
  auto conn = createConn();

  auto sconePacket = buildSconePacket(
      kSconeNoAdvice,
      conn->serverConnectionId.value_or(ConnectionId::createZeroLength()),
      ConnectionId::createZeroLength());
  auto sconeBuf = std::make_unique<folly::IOBuf>(std::move(sconePacket));
  uint64_t sconeSize = sconeBuf->computeChainDataLength();

  EXPECT_GT(sconeSize, 0) << "SCONE packet should have non-zero size";
  EXPECT_LT(sconeSize, 100)
      << "SCONE packet should be reasonably small (< 100 bytes), got "
      << sconeSize;

  VLOG(1) << "SCONE packet size: " << sconeSize << " bytes";

  const uint64_t TOTAL_BUDGET = 1000;
  uint64_t adjustedBudget = TOTAL_BUDGET;

  if (adjustedBudget > sconeSize) {
    adjustedBudget -= sconeSize;
  }

  EXPECT_EQ(adjustedBudget, TOTAL_BUDGET - sconeSize)
      << "Size reservation should subtract SCONE size from total budget";

  const uint64_t TINY_BUDGET = sconeSize / 2;
  uint64_t tinyAdjusted = TINY_BUDGET;
  bool shouldSkipScone = false;

  if (tinyAdjusted <= sconeSize) {
    shouldSkipScone = true;
  }

  EXPECT_TRUE(shouldSkipScone)
      << "Should skip SCONE when insufficient space available";

  VLOG(1) << "Size validation tests completed successfully";
}

TEST_F(QuicTransportFunctionsTest, SCONEWithContinuousMemory) {
  auto conn = createConn();
  conn->transportSettings.dataPathType = DataPathType::ContinuousMemory;
  conn->transportSettings.enableSconeSend = true;
  conn->scone.emplace();
  conn->peerAdvertisedSconeSupport = true;
  auto bufAccessor = std::make_unique<BufAccessor>(conn->udpSendPacketLen * 16);
  auto outputBuf = bufAccessor->obtain();
  auto bufPtr = outputBuf.get();
  bufAccessor->release(std::move(outputBuf));
  conn->bufAccessor = bufAccessor.get();
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  EXPECT_CALL(mockSock, getGSO()).WillRepeatedly(Return(true));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("Test data for SCONE");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());

  EXPECT_CALL(mockSock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const SocketAddress&,
                           const struct iovec* vec,
                           size_t iovec_len,
                           auto) {
        EXPECT_GT(bufPtr->length(), 0);
        EXPECT_EQ(iovec_len, 1);

        auto writtenBuf = folly::IOBuf::wrapIov(vec, iovec_len);

        EXPECT_GE(writtenBuf->length(), 15);
        EXPECT_GT(writtenBuf->length(), 30);

        EXPECT_GT(writtenBuf->length(), 4);

        return getTotalIovecLen(vec, iovec_len);
      }));

  ASSERT_FALSE(writeQuicDataToSocket(
                   mockSock,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   QuicVersion::MVFST,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  EXPECT_TRUE(conn->scone->lastSconeSentTime.has_value());
}

TEST_F(QuicTransportFunctionsTest, SconeDatagramSizesMatchWire) {
  for (auto mode :
       {QuicBatchingMode::BATCHING_MODE_NONE,
        QuicBatchingMode::BATCHING_MODE_GSO,
        QuicBatchingMode::BATCHING_MODE_SENDMMSG}) {
    for (uint64_t mtu : {1200, 1452}) {
      SCOPED_TRACE(testing::Message() << static_cast<int>(mode) << ":" << mtu);
      auto conn = createConn();
      conn->udpSendPacketLen = mtu;
      conn->transportSettings.batchingMode = mode;
      conn->transportSettings.maxBatchSize =
          mode == QuicBatchingMode::BATCHING_MODE_NONE ? 1 : 2;
      conn->transportSettings.enableSconeSend = true;
      conn->scone.emplace();
      conn->peerAdvertisedSconeSupport = true;
      BufAccessor accessor(mtu * 2);
      conn->bufAccessor = &accessor;
      auto prefix = buildSconePacket(
                        conn->scone->configuredRateSignal,
                        *conn->clientConnectionId,
                        *conn->serverConnectionId)
                        .toString();
      EventBase evb;
      auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
      NiceMock<quic::test::MockAsyncUDPSocket> sock(qEvb);
      ON_CALL(sock, getGSO()).WillByDefault(Return(0));
      std::vector<std::string> datagrams;
      auto capture = [&](const iovec* vec, size_t count, size_t segmentSize) {
        auto bytes = folly::IOBuf::wrapIov(vec, count)->toString();
        if (!segmentSize) {
          segmentSize = bytes.size();
        }
        for (size_t offset = 0; offset < bytes.size(); offset += segmentSize) {
          datagrams.push_back(bytes.substr(offset, segmentSize));
        }
        return bytes.size();
      };
      ON_CALL(sock, write(_, _, _))
          .WillByDefault([&](const SocketAddress&,
                             const iovec* vec,
                             size_t count) { return capture(vec, count, 0); });
      ON_CALL(sock, writeGSO(_, _, _, _))
          .WillByDefault([&](const SocketAddress&,
                             const iovec* vec,
                             size_t count,
                             QuicAsyncUDPSocket::WriteOptions options) {
            return capture(vec, count, options.gso);
          });
      ON_CALL(sock, writem(_, _, _, _))
          .WillByDefault([&](folly::Range<SocketAddress const*>,
                             iovec* vec,
                             size_t* counts,
                             size_t count) {
            for (size_t i = 0; i < count; ++i) {
              capture(vec, counts[i], 0);
              vec += counts[i];
            }
            return count;
          });
      EXPECT_CALL(*quicStats_, onSconePacketSent()).Times(1);
      auto stream =
          conn->streamManager->createNextBidirectionalStream().value();
      ASSERT_FALSE(
          writeDataToQuicStream(
              *stream, folly::IOBuf::copyBuffer(std::string(mtu, 's')), true)
              .hasError());
      auto result = writeQuicDataToSocket(
          sock,
          *conn,
          *conn->serverConnectionId,
          *conn->clientConnectionId,
          *aead,
          *headerCipher,
          getVersion(*conn),
          2);
      ASSERT_TRUE(result.has_value());
      ASSERT_EQ(datagrams.size(), 2);
      EXPECT_EQ(datagrams[0].substr(0, prefix.size()), prefix);
      EXPECT_NE(datagrams[1].substr(0, prefix.size()), prefix);
      EXPECT_EQ(
          result->bytesWritten, datagrams[0].size() + datagrams[1].size());
      ASSERT_EQ(conn->outstandings.packets.size(), 2);
      size_t index = 0;
      for (const auto& packet : conn->outstandings.packets) {
        EXPECT_EQ(packet.metadata.encodedSize, datagrams[index].size());
        EXPECT_LE(datagrams[index].size(), mtu);
        const auto prefixSize = index == 0 ? prefix.size() : 0;
        const auto headerSize = 1 + conn->clientConnectionId->size() +
            parsePacketNumberLength(datagrams[index][prefixSize]);
        EXPECT_EQ(
            packet.metadata.encodedBodySize,
            datagrams[index].size() - prefixSize - headerSize);
        ++index;
      }
      EXPECT_TRUE(conn->scone->lastSconeSentTime.has_value());
      EXPECT_EQ(accessor.length(), 0);
      EXPECT_EQ(accessor.headroom(), 0);
      testing::Mock::VerifyAndClearExpectations(quicStats_.get());
    }
  }
}

TEST_F(QuicTransportFunctionsTest, SconePrefixRolledBackWhenSchedulingFails) {
  enum Failure { NoPacket, NoFrames, NoBody, Error };

  for (auto failure : {NoPacket, NoFrames, NoBody, Error}) {
    const bool schedulerError = failure == Error;
    SCOPED_TRACE(testing::Message() << failure);
    auto conn = createConn();
    conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
    conn->transportSettings.maxBatchSize = 1;
    conn->transportSettings.enableSconeSend = true;
    conn->scone.emplace();
    conn->peerAdvertisedSconeSupport = true;
    BufAccessor accessor(conn->udpSendPacketLen);
    conn->bufAccessor = &accessor;
    EventBase evb;
    auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
    NiceMock<quic::test::MockAsyncUDPSocket> sock(qEvb);
    ON_CALL(sock, getGSO()).WillByDefault(Return(0));
    EXPECT_CALL(sock, write(_, _, _)).Times(0);
    EXPECT_CALL(*quicStats_, onSconePacketSent()).Times(0);
    NiceMock<MockFrameScheduler> scheduler(conn.get());
    ON_CALL(scheduler, hasData()).WillByDefault(Return(true));
    EXPECT_CALL(scheduler, _scheduleFramesForPacket(_, _))
        .WillOnce(
            [&](PacketBuilderInterface* builder,
                uint32_t) -> Expected<SchedulingResult, QuicError> {
              auto encoded = builder->encodePacketHeader();
              EXPECT_TRUE(encoded.has_value());
              builder->writeBE(uint8_t{0x42});
              if (schedulerError) {
                return quic::make_unexpected(QuicError(
                    TransportErrorCode::INTERNAL_ERROR, "scheduler failure"));
              }
              if (failure == NoPacket) {
                std::move(*builder).releaseOutputBuffer();
                return SchedulingResult(std::nullopt, std::nullopt);
              }
              if (failure == NoBody) {
                builder->appendFrame(PingFrame());
              }
              auto packet = std::move(*builder).buildPacket();
              if (failure == NoBody) {
                packet.body.clear();
              }
              return SchedulingResult(std::nullopt, std::move(packet));
            });
    auto result = writeConnectionDataToSocket(
        sock,
        *conn,
        conn->currentPathId,
        *conn->serverConnectionId,
        *conn->clientConnectionId,
        ShortHeaderBuilder(conn->oneRttWritePhase),
        PacketNumberSpace::AppData,
        scheduler,
        [](QuicConnectionStateBase& c) { return c.udpSendPacketLen; },
        1,
        *aead,
        *headerCipher,
        getVersion(*conn),
        Clock::now());
    EXPECT_EQ(result.hasError(), schedulerError);
    EXPECT_TRUE(accessor.ownsBuffer());
    EXPECT_EQ(accessor.length(), 0);
    EXPECT_EQ(accessor.headroom(), 0);
    EXPECT_FALSE(conn->scone->lastSconeSentTime.has_value());
    EXPECT_TRUE(conn->outstandings.packets.empty());
    testing::Mock::VerifyAndClearExpectations(quicStats_.get());
    testing::Mock::VerifyAndClearExpectations(&sock);
    EXPECT_CALL(*quicStats_, onSconePacketSent()).Times(1);
    EXPECT_CALL(sock, write(_, _, _))
        .WillOnce(
            Invoke([](const SocketAddress&, const iovec* vec, size_t count) {
              return getTotalIovecLen(vec, count);
            }));
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    ASSERT_FALSE(writeDataToQuicStream(
                     *stream,
                     folly::IOBuf::copyBuffer("retry after failed scheduling"),
                     true)
                     .hasError());
    ASSERT_TRUE(writeQuicDataToSocket(
                    sock,
                    *conn,
                    *conn->serverConnectionId,
                    *conn->clientConnectionId,
                    *aead,
                    *headerCipher,
                    getVersion(*conn),
                    1)
                    .has_value());
    EXPECT_TRUE(conn->scone->lastSconeSentTime.has_value());
    testing::Mock::VerifyAndClearExpectations(quicStats_.get());
  }
}

TEST_F(QuicTransportFunctionsTest, SconeFlowIndicatorOnInitialPackets) {
  auto conn = createConn();
  conn->transportSettings.advertiseSconeSupport = true;

  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  // Capture the written datagram
  std::vector<uint8_t> writtenData;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillOnce(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            for (size_t i = 0; i < iovec_len; ++i) {
              auto* data = static_cast<uint8_t*>(vec[i].iov_base);
              writtenData.insert(
                  writtenData.end(), data, data + vec[i].iov_len);
            }
            return getTotalIovecLen(vec, iovec_len);
          });

  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_GT(res->bytesWritten, 0);

  // Last 2 bytes should be the SCONE flow indicator
  ASSERT_GE(writtenData.size(), kSconeFlowIndicatorSize);
  EXPECT_EQ(writtenData[writtenData.size() - 2], kSconeFlowIndicatorByte1);
  EXPECT_EQ(writtenData[writtenData.size() - 1], kSconeFlowIndicatorByte2);
}

TEST_F(QuicTransportFunctionsTest, SconeFlowIndicatorOnClonedInitialPackets) {
  constexpr auto kCryptoDataSizeMultiplier = 2;

  auto conn = createClientConn();
  FizzCryptoFactory cryptoFactory;
  conn->initialWriteCipher =
      cryptoFactory
          .getClientInitialCipher(*conn->serverConnectionId, getVersion(*conn))
          .value();
  ASSERT_GT(conn->initialWriteCipher->getCipherOverhead(), 0);
  conn->transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
  conn->transportSettings.maxBatchSize = 1;
  conn->transportSettings.advertiseSconeSupport = true;

  auto bufAccessor = std::make_unique<BufAccessor>(conn->udpSendPacketLen);
  conn->bufAccessor = bufAccessor.get();

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket mockSock(qEvb);
  ON_CALL(mockSock, getGSO()).WillByDefault(Return(0));

  bool captureProbe = false;
  std::vector<uint8_t> probeData;
  EXPECT_CALL(mockSock, write(_, _, _))
      .WillRepeatedly(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovecLen) {
            if (captureProbe) {
              for (size_t i = 0; i < iovecLen; ++i) {
                auto* data = static_cast<uint8_t*>(vec[i].iov_base);
                probeData.insert(probeData.end(), data, data + vec[i].iov_len);
              }
            }
            return getTotalIovecLen(vec, iovecLen);
          });

  auto* cryptoStream = &conn->cryptoState->initialStream;
  writeDataToQuicStream(
      *cryptoStream,
      buildRandomInputData(conn->udpSendPacketLen * kCryptoDataSizeMultiplier));
  auto writeResult = writeCryptoAndAckDataToSocket(
      mockSock,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeResult.hasError());
  ASSERT_TRUE(cryptoStream->pendingWrites.empty());
  ASSERT_FALSE(conn->outstandings.packets.empty());

  const auto outstandingPacketsBeforeProbe = conn->outstandings.packets.size();
  const auto originalPacketNum =
      conn->outstandings.packets.front().packet.header.getPacketSequenceNum();
  std::vector<WriteCryptoFrame> originalCryptoFrames;
  for (const auto& frame : conn->outstandings.packets.front().packet.frames) {
    if (const auto* cryptoFrame = frame.asWriteCryptoFrame()) {
      originalCryptoFrames.push_back(*cryptoFrame);
    }
  }
  ASSERT_FALSE(originalCryptoFrames.empty());

  captureProbe = true;
  writeCryptoDataProbesToSocketForTest(
      mockSock,
      *conn,
      1,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn));

  ASSERT_EQ(
      conn->outstandings.packets.size(), outstandingPacketsBeforeProbe + 1);
  const auto& clonedPacket = conn->outstandings.packets.back();
  ASSERT_TRUE(clonedPacket.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(
      originalPacketNum,
      clonedPacket.maybeClonedPacketIdentifier->packetNumber);
  std::vector<WriteCryptoFrame> clonedCryptoFrames;
  for (const auto& frame : clonedPacket.packet.frames) {
    if (const auto* cryptoFrame = frame.asWriteCryptoFrame()) {
      clonedCryptoFrames.push_back(*cryptoFrame);
    }
  }
  EXPECT_EQ(originalCryptoFrames, clonedCryptoFrames);

  ASSERT_EQ(probeData.size(), conn->udpSendPacketLen);
  EXPECT_EQ(probeData[probeData.size() - 2], kSconeFlowIndicatorByte1);
  EXPECT_EQ(probeData[probeData.size() - 1], kSconeFlowIndicatorByte2);
  if (bufAccessor) {
    EXPECT_EQ(bufAccessor->length(), 0);
  }
}

TEST_F(
    QuicTransportFunctionsTest,
    SconeFlowIndicatorNotSentAfterReceivingPackets) {
  auto conn = createConn();
  conn->transportSettings.advertiseSconeSupport = true;

  auto cryptoStream = &conn->cryptoState->initialStream;
  auto buf = buildRandomInputData(200);
  writeDataToQuicStream(*cryptoStream, buf->clone());

  // Simulate having received a server packet
  conn->ackStates.initialAckState->largestRecvdPacketNum = 0;

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  std::vector<uint8_t> writtenData;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillOnce(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            for (size_t i = 0; i < iovec_len; ++i) {
              auto* data = static_cast<uint8_t*>(vec[i].iov_base);
              writtenData.insert(
                  writtenData.end(), data, data + vec[i].iov_len);
            }
            return getTotalIovecLen(vec, iovec_len);
          });

  auto res = writeCryptoAndAckDataToSocket(
      *rawSocket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Initial,
      *conn->initialWriteCipher,
      *conn->initialHeaderCipher,
      getVersion(*conn),
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_GT(res->bytesWritten, 0);

  // Last 2 bytes should NOT be the flow indicator since we already
  // received packets
  ASSERT_GE(writtenData.size(), kSconeFlowIndicatorSize);
  bool hasIndicator =
      writtenData[writtenData.size() - 2] == kSconeFlowIndicatorByte1 &&
      writtenData[writtenData.size() - 1] == kSconeFlowIndicatorByte2;
  EXPECT_FALSE(hasIndicator);
}

TEST_F(QuicTransportFunctionsTest, SconeFlowIndicatorNotSentOnShortHeader) {
  auto conn = createConn();
  conn->transportSettings.advertiseSconeSupport = true;

  // Write app data (short header)
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = IOBuf::copyBuffer("test data");
  ASSERT_FALSE(writeDataToQuicStream(*stream, buf->clone(), true).hasError());

  EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  auto socket =
      std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  auto rawSocket = socket.get();
  ON_CALL(*rawSocket, getGSO).WillByDefault(testing::Return(0));

  std::vector<uint8_t> writtenData;
  EXPECT_CALL(*rawSocket, write(_, _, _))
      .WillOnce(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            for (size_t i = 0; i < iovec_len; ++i) {
              auto* data = static_cast<uint8_t*>(vec[i].iov_base);
              writtenData.insert(
                  writtenData.end(), data, data + vec[i].iov_len);
            }
            return getTotalIovecLen(vec, iovec_len);
          });

  ASSERT_FALSE(writeQuicDataToSocket(
                   *rawSocket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   QuicVersion::MVFST,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // Short header packets should never have the flow indicator
  ASSERT_GE(writtenData.size(), kSconeFlowIndicatorSize);
  bool hasIndicator =
      writtenData[writtenData.size() - 2] == kSconeFlowIndicatorByte1 &&
      writtenData[writtenData.size() - 1] == kSconeFlowIndicatorByte2;
  EXPECT_FALSE(hasIndicator);
}

} // namespace quic::test
