/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/stream/StreamStateFunctions.h>

using namespace folly;
using namespace testing;

namespace quic::test {

void verifyStreamReset(
    const QuicStreamState& stream,
    uint64_t readOffsetExpected) {
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_TRUE(stream.finalReadOffset.has_value());
  EXPECT_EQ(readOffsetExpected, stream.finalReadOffset.value());
}

std::unique_ptr<QuicServerConnectionState> createConn(
    BufAccessor* bufAccessor = nullptr) {
  auto conn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder().build());
  conn->bufAccessor = bufAccessor;
  conn->clientConnectionId = getTestConnectionId();
  conn->version = QuicVersion::MVFST;
  conn->ackStates.initialAckState->nextPacketNum = 1;
  conn->ackStates.handshakeAckState->nextPacketNum = 1;
  conn->ackStates.appDataAckState.nextPacketNum = 1;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      kDefaultStreamFlowControlWindow;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      kDefaultStreamFlowControlWindow;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      kDefaultStreamFlowControlWindow;
  conn->flowControlState.peerAdvertisedMaxOffset =
      kDefaultConnectionFlowControlWindow;
  CHECK(!conn->streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
  CHECK(
      !conn->streamManager
           ->setMaxLocalUnidirectionalStreams(kDefaultMaxStreamsUnidirectional)
           .hasError());
  initializePathManagerState(*conn);
  return conn;
}

class QuicOpenStateTest : public Test {};

TEST_F(QuicOpenStateTest, ReadStreamDataNotFin) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  uint64_t offset = 0;
  bool fin = false;
  ReadStreamFrame frame(id, offset, fin);
  frame.data = IOBuf::copyBuffer("hey");
  auto result = receiveReadStreamFrameSMHandler(stream, std::move(frame));
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(stream.hasReadableData());
  EXPECT_TRUE(stream.hasPeekableData());
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, ReadInvalidData) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  uint64_t offset1 = 0;
  bool fin1 = false;

  // EOF in middle of stream
  ReadStreamFrame frame1(id, offset1, fin1);
  frame1.data = IOBuf::copyBuffer("hey");
  auto result1 = receiveReadStreamFrameSMHandler(stream, std::move(frame1));
  ASSERT_FALSE(result1.hasError());
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);

  uint64_t offset2 = 1;
  bool fin2 = true;
  ReadStreamFrame frame2(id, offset2, fin2);
  frame2.data = IOBuf::copyBuffer("e");
  auto result = receiveReadStreamFrameSMHandler(stream, std::move(frame2));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicOpenStateTest, ReadStreamDataBeyondFlowControlRejected) {
  // Regression for T279928027: receiveReadStreamFrameSMHandler must surface a
  // FLOW_CONTROL_ERROR when a fragment's end offset exceeds the advertised
  // stream window, rather than silently buffering it.
  auto conn = createConn();
  StreamId id = 0x00;
  QuicStreamState stream(id, *conn);
  stream.flowControlState.advertisedMaxOffset = 100;

  ReadStreamFrame frame(id, /*offsetIn=*/100, /*finIn=*/false);
  frame.data = IOBuf::copyBuffer("x");
  auto result = receiveReadStreamFrameSMHandler(stream, std::move(frame));
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::FLOW_CONTROL_ERROR);
  EXPECT_TRUE(stream.readBuffer.empty());
}

TEST_F(QuicOpenStateTest, InvalidEvent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame frame(1, GenericApplicationErrorCode::UNKNOWN, 0);
  auto result = sendRstAckSMHandler(stream, std::nullopt);
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->recvState, StreamRecvState::Closed);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We received FIN, but we haven't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicOpenStateTest, AckStream) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      true);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto& streamFrame =
      *getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->packet.frames.front()
           .asWriteStreamFrame();

  auto result1 = sendAckSMHandler(*stream, streamFrame);
  ASSERT_FALSE(result1.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);

  auto result2 = sendAckSMHandler(*stream, streamFrame);
  ASSERT_FALSE(result2.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
}

// A stream marks an ACKed frame handled only where it does delivery
// bookkeeping: a closed stream accounts for the frame with nothing newly
// delivered, while a stream in an invalid send state rejects it unhandled.
TEST_F(QuicOpenStateTest, AckDeliveryHandledOnlyWhereBookkeepingRuns) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  const WriteStreamFrame frame(stream->id, 0, 5, false);

  StreamFrameAckDelivery closedDelivery;
  conn->streamFrameAckDelivery = &closedDelivery;
  stream->sendState = StreamSendState::Closed;
  ASSERT_FALSE(sendAckSMHandler(*stream, frame).hasError());
  EXPECT_TRUE(closedDelivery.handled);
  EXPECT_TRUE(closedDelivery.newlyDeliveredIntervals.empty());

  StreamFrameAckDelivery invalidDelivery;
  conn->streamFrameAckDelivery = &invalidDelivery;
  stream->sendState = StreamSendState::Invalid;
  EXPECT_TRUE(sendAckSMHandler(*stream, frame).hasError());
  EXPECT_FALSE(invalidDelivery.handled);
  conn->streamFrameAckDelivery = nullptr;
}

// The unified send buffer reports newly ACKed ranges as half-open
// [begin, end); the stream reports them as inclusive delivery intervals that
// cover every newly ACKed byte, including the last one.
TEST_F(QuicOpenStateTest, UnifiedAckReportsInclusiveDeliveryIntervals) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_TRUE(stream->streamSendBuffer->append(
      IOBuf::copyBuffer(std::string(200, 'x')), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 200, false}));
  const auto ackFrame = [&](uint64_t offset, uint64_t len) {
    StreamFrameAckDelivery delivery;
    conn->streamFrameAckDelivery = &delivery;
    EXPECT_FALSE(sendAckSMHandler(
                     *stream, WriteStreamFrame(stream->id, offset, len, false))
                     .hasError());
    conn->streamFrameAckDelivery = nullptr;
    return std::vector<Interval<uint64_t>>(
        delivery.newlyDeliveredIntervals.begin(),
        delivery.newlyDeliveredIntervals.end());
  };

  EXPECT_THAT(ackFrame(0, 100), ElementsAre(Interval<uint64_t>(0, 99)));
  // A frame [100, 199] whose second half an earlier ACK already delivered.
  EXPECT_THAT(ackFrame(150, 50), ElementsAre(Interval<uint64_t>(150, 199)));
  EXPECT_THAT(ackFrame(100, 100), ElementsAre(Interval<uint64_t>(100, 149)));
}

TEST_F(QuicOpenStateTest, AckStreamMulti) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *IOBuf::copyBuffer("world"),
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *IOBuf::copyBuffer("this is bob"),
      false);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 3);
  EXPECT_EQ(3, conn->outstandings.packets.size());

  auto& streamFrame3 =
      *conn->outstandings.packets[2].packet.frames[0].asWriteStreamFrame();

  auto result1 = sendAckSMHandler(*stream, streamFrame3);
  ASSERT_FALSE(result1.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 10);
  ASSERT_EQ(stream->ackedIntervals.front().end, 20);

  auto& streamFrame2 =
      *conn->outstandings.packets[1].packet.frames[0].asWriteStreamFrame();

  auto result2 = sendAckSMHandler(*stream, streamFrame2);
  ASSERT_FALSE(result2.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 5);
  ASSERT_EQ(stream->ackedIntervals.front().end, 20);

  auto& streamFrame1 =
      *conn->outstandings.packets[0].packet.frames[0].asWriteStreamFrame();

  auto result3 = sendAckSMHandler(*stream, streamFrame1);
  ASSERT_FALSE(result3.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Open);
  ASSERT_EQ(stream->ackedIntervals.front().start, 0);
  ASSERT_EQ(stream->ackedIntervals.front().end, 20);
}

TEST_F(QuicOpenStateTest, UnifiedAckHandlesReorderingAndDuplicates) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_TRUE(
      stream->streamSendBuffer->append(IOBuf::copyBuffer("abcdef"), true));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 6, true}));

  const WriteStreamFrame tailFrame(stream->id, 3, 3, true);
  ASSERT_FALSE(sendAckSMHandler(*stream, tailFrame).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->streamSendBuffer->ackInsertVersion(), 1);
  EXPECT_FALSE(stream->streamSendBuffer->largestDeliverableOffset());
  EXPECT_TRUE(conn->streamManager->deliverableContains(stream->id));

  ASSERT_FALSE(sendAckSMHandler(*stream, tailFrame).hasError());
  EXPECT_EQ(stream->streamSendBuffer->ackInsertVersion(), 1);

  const WriteStreamFrame headFrame(stream->id, 0, 3, false);
  ASSERT_FALSE(sendAckSMHandler(*stream, headFrame).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_EQ(stream->streamSendBuffer->ackInsertVersion(), 2);
  ASSERT_TRUE(stream->streamSendBuffer->largestDeliverableOffset().has_value());
  EXPECT_EQ(6u, *stream->streamSendBuffer->largestDeliverableOffset());
  EXPECT_EQ(stream->streamSendBuffer->outstandingBytes(), 0);

  std::string retiredData;
  EXPECT_FALSE(
      stream->streamSendBuffer->writeAt(0, 6, [&retiredData](ByteRange range) {
        retiredData.append(
            reinterpret_cast<const char*>(range.data()), range.size());
        return true;
      }));
  EXPECT_TRUE(retiredData.empty());
}

TEST_F(QuicOpenStateTest, UnifiedAckHandlesFinOnly) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_TRUE(stream->streamSendBuffer->append(nullptr, true));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 0, true}));

  const WriteStreamFrame finFrame(stream->id, 0, 0, true);
  ASSERT_FALSE(sendAckSMHandler(*stream, finFrame).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_TRUE(stream->streamSendBuffer->finAcked());

  const auto ackVersion = stream->streamSendBuffer->ackInsertVersion();
  ASSERT_FALSE(sendAckSMHandler(*stream, finFrame).hasError());
  EXPECT_EQ(stream->streamSendBuffer->ackInsertVersion(), ackVersion);
}

TEST_F(QuicOpenStateTest, UnifiedAckClearsStreamManagerLossState) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_TRUE(
      stream->streamSendBuffer->append(IOBuf::copyBuffer("abcdef"), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 6, false}));
  ASSERT_TRUE(stream->streamSendBuffer->markLoss({0, 6, false}));
  conn->streamManager->updateWritableStreams(*stream);
  ASSERT_TRUE(conn->streamManager->hasLoss());

  ASSERT_FALSE(
      sendAckSMHandler(*stream, WriteStreamFrame(stream->id, 0, 6, false))
          .hasError());

  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());
  EXPECT_FALSE(conn->streamManager->hasLoss());
}

#if !defined(NDEBUG) && !defined(_WIN32)
TEST_F(QuicOpenStateTest, ClosedUnifiedAckRejectsPendingData) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(IOBuf::copyBuffer("abcdef"), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 3, false}));
  stream->sendState = StreamSendState::Closed;

  const WriteStreamFrame frame(stream->id, 0, 3, false);
  EXPECT_DEATH({ (void)sendAckSMHandler(*stream, frame); }, "");
}

TEST_F(QuicOpenStateTest, ClosedUnifiedAckRejectsLostData) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(IOBuf::copyBuffer("abcdef"), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 6, false}));
  ASSERT_TRUE(stream->streamSendBuffer->markLoss({3, 3, false}));
  stream->sendState = StreamSendState::Closed;

  const WriteStreamFrame frame(stream->id, 0, 3, false);
  EXPECT_DEATH({ (void)sendAckSMHandler(*stream, frame); }, "");
}

TEST_F(QuicOpenStateTest, ClosedUnifiedAckRejectsOutstandingData) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(IOBuf::copyBuffer("abcdef"), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 6, false}));
  stream->sendState = StreamSendState::Closed;

  const WriteStreamFrame frame(stream->id, 0, 3, false);
  EXPECT_DEATH({ (void)sendAckSMHandler(*stream, frame); }, "");
}

TEST_F(QuicOpenStateTest, ClosedUnifiedAckRejectsUnackedFin) {
  auto conn = createConn();
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer->append(IOBuf::copyBuffer("abc"), true));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 3, true}));
  stream->sendState = StreamSendState::Closed;

  const WriteStreamFrame frame(stream->id, 0, 3, false);
  EXPECT_DEATH({ (void)sendAckSMHandler(*stream, frame); }, "");
}
#endif
TEST_F(QuicOpenStateTest, RetxBufferSortedAfterAck) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;

  auto buf1 = IOBuf::copyBuffer("Alice");
  auto buf2 = IOBuf::copyBuffer("Bob");
  auto buf3 = IOBuf::copyBuffer("NSA");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf1,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf2,
      false);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      socket,
      *stream,
      *buf3,
      false);

  EXPECT_EQ(3, stream->retransmissionBuffer.size());
  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto streamFrame = *conn->outstandings.packets[std::rand() % 3]
                          .packet.frames.front()
                          .asWriteStreamFrame();
  auto result = sendAckSMHandler(*stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
}

class QuicResetSentStateTest : public Test {};

TEST_F(QuicResetSentStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  auto result = sendRstAckSMHandler(stream, std::nullopt);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
  EXPECT_EQ(*stream.minReliableSizeAcked, 0);
}

// A reset with a reliable size of 3 was previously ACKed.
// Now, we're getting an ACK for a reset with a reliable size of 5,
// and should therefore not see a reduction in minReliableSizeAcked
TEST_F(QuicResetSentStateTest, ReliableRstAckNoReduction) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.minReliableSizeAcked = 3;
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_TRUE(stream.updateAckedIntervals(0, 3, false).has_value());
  auto result = sendRstAckSMHandler(stream, 5);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
  EXPECT_EQ(*stream.minReliableSizeAcked, 3);
}

// A reset with a reliable size of 3 was previously ACKed.
// Now, we're getting an ACK for a reset with a reliable size
// of 1, and should therefore see a reduction in minReliableSizeAcked
TEST_F(QuicResetSentStateTest, ReliableRstAckReduction) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.minReliableSizeAcked = 3;
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_TRUE(stream.updateAckedIntervals(0, 1, false).has_value());
  auto result = sendRstAckSMHandler(stream, 1);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
  EXPECT_EQ(*stream.minReliableSizeAcked, 1);
}

// There were no previously ACKed resets. Therefore, when we get an
// ACK for a reset with a reliable size of 1, we should set the
// minReliableSizeAcked to 1.
TEST_F(QuicResetSentStateTest, ReliableRstAckFirstTime) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  auto result = sendRstAckSMHandler(stream, 1);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
  EXPECT_EQ(*stream.minReliableSizeAcked, 1);
}

// A reset with a reliable size of 3 was previously ACKed.
// Now, we're getting an ACK for a non-reliable reset, and should
// therefore set the minReliableSizeAcked to 0.
TEST_F(QuicResetSentStateTest, RstAfterReliableRst) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  stream.minReliableSizeAcked = 3;
  stream.sendState = StreamSendState::ResetSent;
  stream.currentReadOffset = 0xABCD;
  stream.finalWriteOffset = 0xACDC;
  stream.readBuffer.emplace_back(
      folly::IOBuf::copyBuffer("One more thing"), 0xABCD, false);
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  auto result = sendRstAckSMHandler(stream, std::nullopt);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_FALSE(stream.finalReadOffset);
  EXPECT_FALSE(stream.readBuffer.empty());
  EXPECT_EQ(*stream.minReliableSizeAcked, 0);
}

// A reliable RESET has been ACKed, and all bytes till the reliable
// size have been ACKed.
TEST_F(QuicResetSentStateTest, ResetSentToClosedTransition1) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  ASSERT_TRUE(stream.updateAckedIntervals(0, 5, false).has_value());
  auto result = sendRstAckSMHandler(stream, 5);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

// A reliable RESET has been ACKed, but not all bytes till the
// reliable size have been ACKed.
TEST_F(QuicResetSentStateTest, ResetSentToClosedTransition2) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  ASSERT_TRUE(stream.updateAckedIntervals(0, 4, false).has_value());
  auto result = sendRstAckSMHandler(stream, 5);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

// A reliable RESET with a reliable size was ACKed previously, and
// now we're getting an ACK for stream data until that reliable size
TEST_F(QuicResetSentStateTest, ResetSentToClosedTransition3) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.minReliableSizeAcked = 7;
  WriteStreamFrame streamFrame(id, 0, 7, false);
  auto buf = folly::IOBuf::create(7);
  buf->append(7);
  stream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 0, false)));
  auto result = sendAckSMHandler(stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

// A reliable RESET with a reliable size was ACKed previously, and
// now we're getting an ACK for stream data, but not until the
// reliable size
TEST_F(QuicResetSentStateTest, ResetSentToClosedTransition4) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.minReliableSizeAcked = 8;
  WriteStreamFrame streamFrame(id, 0, 7, false);
  auto buf = folly::IOBuf::create(7);
  buf->append(7);
  stream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 0, false)));
  auto result = sendAckSMHandler(stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

void ackFramesStraddlingReliableSize(
    bool unified,
    const std::vector<uint64_t>& chunkLens,
    bool fin,
    uint64_t reliableSize) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);
  conn->transportSettings.useUnifiedAppStreamSendBuffer = unified;
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));

  std::vector<WriteStreamFrame> sentFrames;
  for (size_t i = 0; i < chunkLens.size(); ++i) {
    auto buf = IOBuf::create(chunkLens[i]);
    buf->append(chunkLens[i]);
    const auto& packet = writeQuicPacket(
        *conn,
        *conn->clientConnectionId,
        *serverChosenConnId,
        *sock,
        *stream,
        *buf,
        fin && i + 1 == chunkLens.size());
    const WriteStreamFrame* streamFrame = nullptr;
    for (const auto& frame : packet.frames) {
      if (const auto* f = frame.asWriteStreamFrame()) {
        ASSERT_EQ(streamFrame, nullptr);
        streamFrame = f;
      }
    }
    ASSERT_NE(streamFrame, nullptr);
    ASSERT_EQ(streamFrame->len, chunkLens[i]);
    sentFrames.push_back(*streamFrame);
  }

  ASSERT_FALSE(sendRstSMHandler(
                   *stream, GenericApplicationErrorCode::UNKNOWN, reliableSize)
                   .hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::ResetSent);
  ASSERT_EQ(stream->reliableSizeToPeer, reliableSize);
  if (!unified) {
    const auto straddleOffset = sentFrames.back().offset;
    ASSERT_LT(straddleOffset, reliableSize);
    auto straddle = stream->retransmissionBuffer.find(straddleOffset);
    ASSERT_NE(straddle, stream->retransmissionBuffer.end());
    EXPECT_EQ(
        straddle->second->data.chainLength(), reliableSize - straddleOffset);
    EXPECT_FALSE(straddle->second->eof);
  }

  for (auto it = sentFrames.rbegin(); it != sentFrames.rend(); ++it) {
    ASSERT_FALSE(sendAckSMHandler(*stream, *it).hasError());
  }
  EXPECT_TRUE(stream->allBytesAckedTill(reliableSize - 1));
  if (!unified) {
    EXPECT_FALSE(stream->allBytesAckedTill(reliableSize));
  }

  ASSERT_FALSE(sendRstAckSMHandler(*stream, reliableSize).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
}

TEST_F(QuicResetSentStateTest, AckFrameTruncatedByReliableReset) {
  ackFramesStraddlingReliableSize(false, {517}, false, 3);
}

TEST_F(QuicResetSentStateTest, AckFrameTruncatedByReliableResetFin) {
  ackFramesStraddlingReliableSize(false, {517}, true, 3);
}

TEST_F(QuicResetSentStateTest, AckNonZeroOffsetFrameTruncatedByReliableReset) {
  ackFramesStraddlingReliableSize(false, {100, 417}, false, 150);
}

TEST_F(QuicResetSentStateTest, LostFinTruncatedByReliableReset) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  Optional<ConnectionId> serverChosenConnId = *conn->clientConnectionId;
  serverChosenConnId.value().data()[0] ^= 0x01;
  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));

  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *IOBuf::copyBuffer("0123456789"),
      true);
  // Move the sent buffer to the loss buffer, as markPacketLoss does.
  auto sent = stream->retransmissionBuffer.find(0);
  ASSERT_NE(sent, stream->retransmissionBuffer.end());
  ASSERT_TRUE(sent->second->eof);
  stream->insertIntoLossBuffer(std::move(sent->second));
  stream->retransmissionBuffer.erase(sent);

  ASSERT_FALSE(
      sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 5)
          .hasError());
  ASSERT_EQ(stream->lossBuffer.size(), 1);
  EXPECT_EQ(stream->lossBuffer.front().offset, 0);
  EXPECT_EQ(stream->lossBuffer.front().data.chainLength(), 5);
  EXPECT_FALSE(stream->lossBuffer.front().eof);
}

TEST_F(QuicResetSentStateTest, UnifiedAckFrameTruncatedByReliableReset) {
  ackFramesStraddlingReliableSize(true, {517}, false, 3);
  ackFramesStraddlingReliableSize(true, {517}, true, 3);
  ackFramesStraddlingReliableSize(true, {100, 417}, false, 150);
}

class QuicClosedStateTest : public Test {};

TEST_F(QuicClosedStateTest, RstAck) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  RstStreamFrame frame(id, GenericApplicationErrorCode::UNKNOWN, 0);
  auto result = sendRstAckSMHandler(stream, std::nullopt);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

class QuicHalfClosedLocalStateTest : public Test {};

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We received FIN and everything:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Closed);
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithFINReadbuffHole) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We received FIN, but we haven't received anything between 100 and 200:
  ReadStreamFrame receivedStreamFrame(stream->id, 200, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

TEST_F(QuicHalfClosedLocalStateTest, ReceiveStreamFrameWithoutFIN) {
  auto conn = createConn();

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Open;
  stream->currentReadOffset = 100;

  // We haven't received FIN:
  ReadStreamFrame receivedStreamFrame(stream->id, 100, false);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(*stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());

  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
  ASSERT_EQ(stream->recvState, StreamRecvState::Open);
}

class QuicHalfClosedRemoteStateTest : public Test {};

TEST_F(QuicHalfClosedRemoteStateTest, AckStream) {
  BufAccessor bufAccessor(kDefaultMaxUDPPayload * kDefaultQuicMaxBatchSize);
  auto conn = createConn(&bufAccessor);
  // create server chosen connId with processId = 0 and workerId = 0
  ServerConnectionIdParams params(0, 0, 0);
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  auto serverChosenConnId = connIdAlgo->encodeConnectionId(params);
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->sendState = StreamSendState::Open;
  stream->recvState = StreamRecvState::Closed;

  EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto sock = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  ON_CALL(*sock, getGSO).WillByDefault(testing::Return(0));

  auto buf = IOBuf::copyBuffer("hello");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *serverChosenConnId,
      *sock,
      *stream,
      *buf,
      true);

  EXPECT_EQ(stream->retransmissionBuffer.size(), 1);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto& streamFrame =
      *getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->packet.frames.front()
           .asWriteStreamFrame();

  auto result = sendAckSMHandler(*stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);

  result = sendAckSMHandler(*stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(stream->sendState, StreamSendState::Closed);
}

class QuicSendResetTest : public Test {};

TEST_F(QuicSendResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

TEST_F(QuicSendResetTest, FromHalfCloseRemote) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;

  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
}

TEST_F(QuicSendResetTest, FromHalfCloseLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());

  // You cannot send a reset after FIN has been acked
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
}

TEST_F(QuicSendResetTest, FromClosed) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;

  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
}

TEST_F(QuicSendResetTest, FromResetSent) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
}

TEST_F(QuicSendResetTest, RstAfterReliableRst) {
  for (bool unified : {false, true}) {
    SCOPED_TRACE(unified ? "unified send buffer" : "legacy send buffer");
    auto conn = createConn();
    conn->transportSettings.useUnifiedAppStreamSendBuffer = unified;
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    ASSERT_FALSE(
        writeDataToQuicStream(*stream, IOBuf::copyBuffer("0123456789"), false)
            .hasError());

    ASSERT_FALSE(
        sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 6)
            .hasError());
    EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
    EXPECT_EQ(stream->reliableSizeToPeer, 6u);
    EXPECT_EQ(stream->pendingWriteBytes(), 6);
    EXPECT_EQ(conn->pendingEvents.resets.at(stream->id).reliableSize, 6u);

    ASSERT_FALSE(sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN)
                     .hasError());
    EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
    EXPECT_FALSE(stream->reliableSizeToPeer.has_value());
    EXPECT_EQ(stream->pendingWriteBytes(), 0);
    ASSERT_EQ(conn->pendingEvents.resets.size(), 1);
    EXPECT_FALSE(
        conn->pendingEvents.resets.at(stream->id).reliableSize.has_value());
  }
}

TEST_F(QuicSendResetTest, ReduceReliableSize) {
  for (bool unified : {false, true}) {
    SCOPED_TRACE(unified ? "unified send buffer" : "legacy send buffer");
    auto conn = createConn();
    conn->transportSettings.useUnifiedAppStreamSendBuffer = unified;
    auto stream = conn->streamManager->createNextBidirectionalStream().value();
    ASSERT_FALSE(
        writeDataToQuicStream(*stream, IOBuf::copyBuffer("0123456789"), false)
            .hasError());

    ASSERT_FALSE(
        sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 6)
            .hasError());
    ASSERT_FALSE(
        sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 3)
            .hasError());
    EXPECT_EQ(stream->reliableSizeToPeer, 3u);
    EXPECT_EQ(stream->pendingWriteBytes(), 3);
    EXPECT_EQ(conn->pendingEvents.resets.at(stream->id).reliableSize, 3u);
  }
}

TEST_F(QuicSendResetTest, StopSendingAfterReliableRst) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, IOBuf::copyBuffer("0123456789"), false)
          .hasError());
  ASSERT_FALSE(
      sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 6)
          .hasError());

  ASSERT_FALSE(
      sendStopSendingSMHandler(
          *stream,
          StopSendingFrame(stream->id, GenericApplicationErrorCode::NO_ERROR))
          .hasError());
  EXPECT_THAT(
      conn->streamManager->stopSendingStreams(),
      ElementsAre(Pair(stream->id, GenericApplicationErrorCode::NO_ERROR)));
}

TEST_F(QuicSendResetTest, StopSendingAfterRst) {
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_FALSE(sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());

  ASSERT_FALSE(
      sendStopSendingSMHandler(
          *stream,
          StopSendingFrame(stream->id, GenericApplicationErrorCode::NO_ERROR))
          .hasError());
  EXPECT_TRUE(conn->streamManager->stopSendingStreams().empty());
}

class QuicRecvResetTest : public Test {};

TEST_F(QuicRecvResetTest, FromOpen) {
  auto conn = createConn();
  StreamId id = 5;
  StreamId rstStream = 1;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(rstStream, GenericApplicationErrorCode::UNKNOWN, 100);
  auto result = receiveRstStreamSMHandler(stream, std::move(rst));
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromOpenReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;

  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(1, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.finalReadOffset = 1024;
  auto result = receiveRstStreamSMHandler(stream, std::move(rst));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteNoReadOffsetYet) {
  StreamId id = 5;
  auto conn = createConn();
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100));
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 100);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1024;

  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1024));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 1024);
}

TEST_F(QuicRecvResetTest, FromHalfClosedRemoteReadOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1024;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 100));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocal) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromHalfClosedLocalReadEOFMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 2014;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicRecvResetTest, FromResetSentNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;

  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 200;

  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::ResetSent);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromResetSentOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Open;
  stream.finalReadOffset = 300;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicRecvResetTest, FromClosedNoReadOffsetYet) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 200));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 200);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 1234;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  verifyStreamReset(stream, 1234);
}

TEST_F(QuicRecvResetTest, FromClosedOffsetMismatch) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Closed;
  stream.recvState = StreamRecvState::Closed;
  stream.finalReadOffset = 123;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

class QuicReliableResetTransitionTest : public Test {};

TEST_F(QuicReliableResetTransitionTest, FromOpenReliableDataNotYetReceived) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100, 10);
  stream.currentReadOffset = 9;
  auto result = receiveRstStreamSMHandler(stream, rst);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);
}

TEST_F(QuicReliableResetTransitionTest, FromOpenReliableDataReceived) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100, 10);
  stream.currentReadOffset = 10;
  auto result = receiveRstStreamSMHandler(stream, rst);
  ASSERT_FALSE(result.hasError());

  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicReliableResetTransitionTest, DataReceivedTillReliableSize) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.reliableSizeFromPeer = 10;
  stream.currentReadOffset = 1;
  auto result = receiveReadStreamFrameSMHandler(
      stream,
      ReadStreamFrame(id, 1, folly::IOBuf::copyBuffer("999999999"), false));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicReliableResetTransitionTest, DataNotReceivedTillReliableSize) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  stream.reliableSizeFromPeer = 10;
  stream.currentReadOffset = 1;
  auto result = receiveReadStreamFrameSMHandler(
      stream,
      ReadStreamFrame(id, 1, folly::IOBuf::copyBuffer("99999999"), false));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Open);
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);
}

TEST_F(QuicReliableResetTransitionTest, RetiredIngressClosesOnReliableReset) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  ASSERT_FALSE(retireIngress(stream).hasError());
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100, 10);

  ASSERT_FALSE(receiveRstStreamSMHandler(stream, rst).hasError());

  // The reliable bytes would never be buffered, so they are not waited for.
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  EXPECT_EQ(stream.currentReadOffset, 100);
  EXPECT_EQ(conn->flowControlState.sumCurReadOffset, 100);
}

TEST_F(QuicOpenStateTest, RetiredIngressClosesOnFin) {
  auto conn = createConn();
  StreamId id = 5;
  QuicStreamState stream(id, *conn);
  ASSERT_FALSE(retireIngress(stream).hasError());
  ReadStreamFrame frame(id, 0, true);
  frame.data = IOBuf::copyBuffer("hey");

  ASSERT_FALSE(
      receiveReadStreamFrameSMHandler(stream, std::move(frame)).hasError());

  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_FALSE(stream.hasReadableData());
  EXPECT_EQ(stream.currentReadOffset, 4);
  EXPECT_EQ(conn->flowControlState.sumCurReadOffset, 3);
}

class QuicUnidirectionalStreamTest : public Test {};

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  auto result =
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;

  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  WriteStreamFrame ackedFrame(id, 0, 0, false);
  auto result = sendAckSMHandler(stream, ackedFrame);
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, OpenInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  auto result = sendStopSendingSMHandler(
      stream, StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  auto result =
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidSendReset) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;
  auto result = sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;

  WriteStreamFrame ackedFrame(id, 0, 0, false);
  auto result = sendAckSMHandler(stream, ackedFrame);
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ClosedInvalidStopSending) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Closed;
  auto result = sendStopSendingSMHandler(
      stream, StopSendingFrame(id, GenericApplicationErrorCode::UNKNOWN));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, OpenReadStreamFin) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;
  stream.currentReadOffset = 100;
  ReadStreamFrame receivedStreamFrame(stream.id, 100, true);
  receivedStreamFrame.data = folly::IOBuf::create(10);
  receivedStreamFrame.data->append(10);
  auto result =
      receiveReadStreamFrameSMHandler(stream, std::move(receivedStreamFrame));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicUnidirectionalStreamTest, OpenRstStream) {
  auto conn = createConn();
  StreamId id = 0b110;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::Invalid;
  stream.recvState = StreamRecvState::Open;

  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
}

TEST_F(QuicUnidirectionalStreamTest, OpenFinalAckStreamFrame) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  WriteStreamFrame streamFrame(id, 1, 1, false);
  stream.sendState = StreamSendState::Open;
  stream.recvState = StreamRecvState::Invalid;
  stream.finalWriteOffset = 1;
  stream.currentWriteOffset = 2;
  auto buf = folly::IOBuf::create(1);
  buf->append(1);
  stream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(1),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 1, false)));
  auto result = sendAckSMHandler(stream, streamFrame);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(stream.sendState, StreamSendState::Closed);
  EXPECT_EQ(stream.recvState, StreamRecvState::Invalid);
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidReadStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Invalid;
  auto result =
      receiveReadStreamFrameSMHandler(stream, ReadStreamFrame(id, 1, false));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

TEST_F(QuicUnidirectionalStreamTest, ResetSentInvalidRstStream) {
  auto conn = createConn();
  StreamId id = 0b111;
  QuicStreamState stream(id, *conn);
  stream.sendState = StreamSendState::ResetSent;
  stream.recvState = StreamRecvState::Invalid;
  auto result = receiveRstStreamSMHandler(
      stream, RstStreamFrame(1, GenericApplicationErrorCode::UNKNOWN, 1234));
  ASSERT_TRUE(result.hasError());
  EXPECT_NE(result.error().code.asTransportErrorCode(), nullptr);
}

} // namespace quic::test
