/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamStateFunctions.h>

#include <gtest/gtest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>

using namespace ::testing;

namespace quic::test {

namespace {

std::unique_ptr<QuicServerConnectionState> createUnifiedConn() {
  auto conn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder().build());
  conn->transportSettings.useUnifiedAppStreamSendBuffer = true;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      kDefaultStreamFlowControlWindow;
  conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      kDefaultStreamFlowControlWindow;
  conn->flowControlState.peerAdvertisedMaxOffset =
      kDefaultConnectionFlowControlWindow;
  CHECK(!conn->streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
  return conn;
}

} // namespace

class StreamStateFunctionsTests : public Test {};

TEST_F(StreamStateFunctionsTests, BasicResetTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId streamId = 0xbaad;
  QuicStreamState stream(streamId, conn);
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream, StreamBuffer(folly::IOBuf::copyBuffer("It is a hotdog!"), 0))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer(" It is not a hotdog."), 15))
          .hasError());
  ASSERT_FALSE(writeDataToQuicStream(
                   stream, folly::IOBuf::copyBuffer("What is it then?"), false)
                   .hasError());

  std::string retxBufData = "How would I know?";
  BufPtr retxBuf = folly::IOBuf::copyBuffer(retxBufData);
  stream.retransmissionBuffer.emplace(
      34,
      std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(retxBuf), 34));
  auto currentWriteOffset = stream.currentWriteOffset;
  auto currentReadOffset = stream.currentReadOffset;
  EXPECT_TRUE(stream.writable());

  ASSERT_FALSE(sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());

  // Something are cleared:
  EXPECT_TRUE(stream.writeBuffer.empty());
  EXPECT_TRUE(stream.retransmissionBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());

  // The rest are untouched:
  EXPECT_EQ(stream.id, streamId);
  EXPECT_EQ(currentReadOffset, stream.currentReadOffset);
  EXPECT_EQ(currentWriteOffset, stream.currentWriteOffset);
  EXPECT_FALSE(stream.writable());
}

TEST_F(StreamStateFunctionsTests, BasicReliableResetTest) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId streamId = 0xbaad;
  QuicStreamState stream(streamId, conn);
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream, StreamBuffer(folly::IOBuf::copyBuffer("It is a hotdog!"), 0))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer(" It is not a hotdog."), 15))
          .hasError());
  ASSERT_FALSE(writeDataToQuicStream(
                   stream, folly::IOBuf::copyBuffer("What is it then?"), false)
                   .hasError());

  std::string retxBufData = "How would I know?";
  BufPtr retxBuf = folly::IOBuf::copyBuffer(retxBufData);
  stream.retransmissionBuffer.emplace(
      34,
      std::make_unique<WriteStreamBuffer>(ChainedByteRangeHead(retxBuf), 34));
  auto currentWriteOffset = stream.currentWriteOffset;
  auto currentReadOffset = stream.currentReadOffset;
  EXPECT_TRUE(stream.writable());

  ASSERT_FALSE(sendRstSMHandler(stream, GenericApplicationErrorCode::UNKNOWN, 5)
                   .hasError());

  // The writeBuffer is going to have bytes 0-4 because the reliableSize is 5.
  EXPECT_EQ(stream.writeBuffer.chainLength(), 5);
  EXPECT_TRUE(stream.retransmissionBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());

  EXPECT_EQ(stream.id, streamId);
  EXPECT_EQ(currentReadOffset, stream.currentReadOffset);
  EXPECT_EQ(currentWriteOffset, stream.currentWriteOffset);
  EXPECT_FALSE(stream.writable());

  // We set the finalWriteOffset to the maximum of the reliableSize (5) and the
  // amount of data we have written to the wire (0).
  EXPECT_EQ(conn.pendingEvents.resets.at(stream.id).finalSize, 5);

  EXPECT_EQ(*stream.reliableSizeToPeer, 5);
  EXPECT_EQ(*stream.appErrorCodeToPeer, GenericApplicationErrorCode::UNKNOWN);
}

TEST_F(StreamStateFunctionsTests, UnifiedResetUsesLargestSentOffset) {
  auto conn = createUnifiedConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("0123456789"), true)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 4, false}));
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(*stream, 4).hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markLoss({0, 4, false}));
  conn->streamManager->updateWritableStreams(*stream);
  ASSERT_TRUE(conn->streamManager->hasLoss());

  ASSERT_FALSE(sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());

  const auto& reset = conn->pendingEvents.resets.at(stream->id);
  EXPECT_EQ(reset.finalSize, 4);
  EXPECT_FALSE(reset.reliableSize.has_value());
  EXPECT_EQ(conn->flowControlState.sumCurStreamBufferLen, 0);
  EXPECT_TRUE(stream->streamSendBuffer->cancelled());
  EXPECT_EQ(stream->streamSendBuffer->tailOffset(), 4);
  EXPECT_EQ(stream->streamSendBuffer->outstandingBytes(), 0);
  EXPECT_FALSE(stream->hasLoss());
  EXPECT_FALSE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writeQueue().contains(
      PriorityQueue::Identifier::fromStreamID(stream->id)));
  EXPECT_FALSE(stream->writable());

  EXPECT_FALSE(
      sendAckSMHandler(*stream, WriteStreamFrame(stream->id, 0, 4, false))
          .hasError());

  ASSERT_FALSE(sendRstAckSMHandler(*stream, std::nullopt).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_FALSE(
      sendAckSMHandler(*stream, WriteStreamFrame(stream->id, 0, 4, false))
          .hasError());
}

TEST_F(
    StreamStateFunctionsTests,
    UnifiedReliableResetBelowSentOffsetPreservesFinalSize) {
  auto conn = createUnifiedConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("0123456789"), true)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 8, false}));
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(*stream, 8).hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markLoss({0, 8, false}));
  conn->streamManager->updateWritableStreams(*stream);

  ASSERT_FALSE(
      sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 5)
          .hasError());

  const auto& reset = conn->pendingEvents.resets.at(stream->id);
  EXPECT_EQ(reset.finalSize, 8);
  ASSERT_TRUE(reset.reliableSize.has_value());
  EXPECT_EQ(*reset.reliableSize, 5);
  EXPECT_EQ(conn->flowControlState.sumCurStreamBufferLen, 0);
  EXPECT_EQ(stream->streamSendBuffer->tailOffset(), 8);
  EXPECT_EQ(stream->streamSendBuffer->nextUnsentOffset(), 8);
  EXPECT_EQ(stream->streamSendBuffer->outstandingBytes(), 5);
  EXPECT_EQ(
      stream->streamSendBuffer->nextLoss(10),
      StreamSendBuffer::SendRange(0, 5, false));
}

TEST_F(StreamStateFunctionsTests, UnifiedReliableResetAcceptsLateFinAck) {
  auto conn = createUnifiedConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("01234567"), true)
          .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 8, .fin = true}));
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(*stream, 8).hasError());

  ASSERT_FALSE(
      sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 5)
          .hasError());
  EXPECT_TRUE(stream->streamSendBuffer->finSent());
  EXPECT_FALSE(stream->streamSendBuffer->finBuffered());
  EXPECT_FALSE(stream->streamSendBuffer->hasPendingLoss());

  ASSERT_FALSE(sendRstAckSMHandler(*stream, std::nullopt).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);

  auto ackResult =
      sendAckSMHandler(*stream, WriteStreamFrame(stream->id, 0, 8, true));

  ASSERT_FALSE(ackResult.hasError());
  EXPECT_TRUE(stream->streamSendBuffer->finAcked());
}

TEST_F(
    StreamStateFunctionsTests,
    UnifiedReliableResetAboveSentOffsetRetainsRequiredData) {
  auto conn = createUnifiedConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  ASSERT_FALSE(writeDataToQuicStream(
                   *stream, folly::IOBuf::copyBuffer("0123456789"), true)
                   .hasError());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent({0, 3, false}));
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(*stream, 3).hasError());

  ASSERT_FALSE(
      sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN, 5)
          .hasError());

  const auto& reset = conn->pendingEvents.resets.at(stream->id);
  EXPECT_EQ(reset.finalSize, 5);
  ASSERT_TRUE(reset.reliableSize.has_value());
  EXPECT_EQ(*reset.reliableSize, 5);
  EXPECT_EQ(conn->flowControlState.sumCurStreamBufferLen, 2);
  EXPECT_EQ(stream->streamSendBuffer->tailOffset(), 5);
  EXPECT_EQ(stream->streamSendBuffer->nextUnsentOffset(), 3);
  EXPECT_EQ(
      stream->streamSendBuffer->nextNewData(10),
      StreamSendBuffer::SendRange(3, 2, false));
  EXPECT_TRUE(conn->streamManager->writeQueue().contains(
      PriorityQueue::Identifier::fromStreamID(stream->id)));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedEmptyStream) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferHasHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(appendDataToReadBuffer(
                   stream,
                   StreamBuffer(
                       folly::IOBuf::copyBuffer("Your read buffer has a hole"),
                       150,
                       true))
                   .hasError());
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferNoHoleNoFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(
              folly::IOBuf::copyBuffer("Your haven't seen FIN yet"), 100))
          .hasError());
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferEmptyBufferFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(appendDataToReadBuffer(
                   stream, StreamBuffer(folly::IOBuf::create(0), 100, true))
                   .hasError());
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedReadBufferBufferFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(
              folly::IOBuf::copyBuffer("you may say im a dreamer"), 100, true))
          .hasError());
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedMultipleStreamDataNoHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream, StreamBuffer(folly::IOBuf::copyBuffer("0123456789"), 100))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer("01234567890123456789"), 110))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer("Counting is hard"), 130, true))
          .hasError());
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedMultipleStreamDataHasHole) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 100;
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream, StreamBuffer(folly::IOBuf::copyBuffer("0123456789"), 100))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer("01234567890123456789"), 115))
          .hasError());
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream,
          StreamBuffer(folly::IOBuf::copyBuffer("Counting is hard"), 130, true))
          .hasError());
  EXPECT_FALSE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, IsAllDataReceivedAllDataRead) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 3;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 101;
  stream.finalReadOffset = 100;
  EXPECT_TRUE(isAllDataReceived(stream));
}

TEST_F(StreamStateFunctionsTests, SendReset) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  // Set an initial flow control.
  conn.flowControlState.peerAdvertisedMaxOffset = 1024;
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  auto initialConnWindow = getSendConnFlowControlBytesAPI(conn);
  EXPECT_EQ(initialConnWindow, 1024);
  ASSERT_FALSE(
      writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true)
          .hasError());
  EXPECT_EQ(conn.flowControlState.sumCurStreamBufferLen, 5);
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow - 5);
  ASSERT_FALSE(appendDataToReadBuffer(
                   stream, StreamBuffer(folly::IOBuf::copyBuffer("hi"), 0))
                   .hasError());
  EXPECT_FALSE(stream.writeBuffer.empty());
  EXPECT_FALSE(stream.readBuffer.empty());
  ASSERT_FALSE(
      resetQuicStream(stream, GenericApplicationErrorCode::UNKNOWN).hasError());
  EXPECT_EQ(getSendConnFlowControlBytesAPI(conn), initialConnWindow);
  EXPECT_TRUE(stream.writeBuffer.empty());
}

TEST_F(StreamStateFunctionsTests, ResetNoFlowControlGenerated) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  ASSERT_FALSE(
      writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true)
          .hasError());
  EXPECT_GT(conn.flowControlState.sumCurStreamBufferLen, 0);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 90);

  stream.currentReadOffset = 80;
  stream.flowControlState.releasedReadOffset = 80;
  stream.maxOffsetObserved = 90;
  stream.flowControlState.advertisedMaxOffset = 100;

  conn.flowControlState.advertisedMaxOffset = 10000;
  conn.flowControlState.sumMaxObservedOffset = 90;
  conn.flowControlState.sumCurReadOffset = 80;
  conn.flowControlState.windowSize = 10000;

  ASSERT_FALSE(onResetQuicStream(stream, std::move(rst)).hasError());
  EXPECT_EQ(stream.currentReadOffset, 90);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 90);
  EXPECT_FALSE(conn.pendingEvents.connWindowUpdate);
}

TEST_F(StreamStateFunctionsTests, ResetFlowControlGenerated) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  conn.qLogger = qLogger;

  StreamId id = 1;
  QuicStreamState stream(id, conn);
  ASSERT_FALSE(
      writeDataToQuicStream(stream, folly::IOBuf::copyBuffer("hello"), true)
          .hasError());
  EXPECT_GT(conn.flowControlState.sumCurStreamBufferLen, 0);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.currentReadOffset = 80;
  stream.flowControlState.releasedReadOffset = 80;
  stream.maxOffsetObserved = 90;
  stream.flowControlState.advertisedMaxOffset = 100;

  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.sumMaxObservedOffset = 90;
  conn.flowControlState.sumCurReadOffset = 80;
  conn.flowControlState.windowSize = 100;

  ASSERT_FALSE(onResetQuicStream(stream, std::move(rst)).hasError());
  EXPECT_EQ(stream.currentReadOffset, 100);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 100);
  EXPECT_TRUE(conn.pendingEvents.connWindowUpdate);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetNotMatch) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 100;
  stream.finalReadOffset = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  auto result = onResetQuicStream(stream, std::move(rst));
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetFinalSizeChange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.finalReadOffset = 11;
  stream.streamReadError = GenericApplicationErrorCode::UNKNOWN;
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  auto result = onResetQuicStream(stream, rst);
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetErrorCodeChange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.finalReadOffset = 10;
  stream.streamReadError = GenericApplicationErrorCode::UNKNOWN + 1;
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 10);
  auto result = onResetQuicStream(stream, rst);
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::STREAM_STATE_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetLessThanMaxObserved) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 30);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  auto result = onResetQuicStream(stream, std::move(rst));
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::FINAL_SIZE_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetGreaterThanStreamFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 200);
  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 30;
  stream.flowControlState.advertisedMaxOffset = 100;
  auto result = onResetQuicStream(stream, std::move(rst));
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::FLOW_CONTROL_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetOffsetGreaterThanConnFlowControl) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 200);

  stream.currentReadOffset = 20;
  stream.maxOffsetObserved = 30;
  stream.flowControlState.advertisedMaxOffset = 300;
  stream.flowControlState.windowSize = 100;

  conn.flowControlState.sumCurReadOffset = 20;
  conn.flowControlState.sumMaxObservedOffset = 30;
  conn.flowControlState.advertisedMaxOffset = 100;
  conn.flowControlState.windowSize = 100;
  auto result = onResetQuicStream(stream, std::move(rst));
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::FLOW_CONTROL_ERROR);
}

TEST_F(StreamStateFunctionsTests, ResetAfterReadingAllBytesTillFin) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  RstStreamFrame rst(id, GenericApplicationErrorCode::UNKNOWN, 100);
  stream.currentReadOffset = 101;
  stream.finalReadOffset = 100;
  stream.maxOffsetObserved = 100;
  stream.flowControlState.advertisedMaxOffset = 300;
  ASSERT_FALSE(onResetQuicStream(stream, std::move(rst)).hasError());
  EXPECT_EQ(stream.currentReadOffset, 101);
  EXPECT_FALSE(conn.streamManager->hasWindowUpdates());
  EXPECT_FALSE(conn.pendingEvents.connWindowUpdate);
}

// The application has already read all data until the specified
// offset.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil1) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  EXPECT_TRUE(isAllDataReceivedUntil(stream, 0));
}

// The application has not read all data until the specified
// offset, and the data isn't available in the read buffer either.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil2) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 1, false));
  EXPECT_FALSE(isAllDataReceivedUntil(stream, 2));
}

// The application has not read all data until the specified
// offset, but the data is available in the read buffer.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil3) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 1, false));
  EXPECT_TRUE(isAllDataReceivedUntil(stream, 1));
}

// There's a "hole" in the data received.
TEST_F(StreamStateFunctionsTests, isAllDataReceivedUntil4) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.currentReadOffset = 1;
  stream.readBuffer.emplace_back(
      StreamBuffer(folly::IOBuf::copyBuffer("1"), 2, false));
  EXPECT_FALSE(isAllDataReceivedUntil(stream, 2));
}

TEST_F(StreamStateFunctionsTests, RetireIngressWaitsForFinalSize) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  ASSERT_FALSE(appendDataToReadBuffer(
                   stream, StreamBuffer(folly::IOBuf::copyBuffer("hello"), 0))
                   .hasError());

  ASSERT_FALSE(retireIngress(stream).hasError());

  EXPECT_TRUE(stream.ingressRetired);
  EXPECT_TRUE(stream.stopSendingRequested);
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_EQ(stream.recvState, StreamRecvState::Open);
  EXPECT_EQ(stream.currentReadOffset, 0);
  EXPECT_EQ(conn.flowControlState.sumMaxObservedOffset, 5);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 0);
  EXPECT_FALSE(conn.streamManager->readableStreams().contains(id));
  EXPECT_FALSE(conn.streamManager->peekableStreams().contains(id));
}

TEST_F(StreamStateFunctionsTests, RetireIngressClosesWhenFinalSizeKnown) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  // A small window, so that crediting the stream would normally queue a
  // stream window update.
  stream.flowControlState.windowSize = 16;
  stream.flowControlState.advertisedMaxOffset = 16;
  // The FIN arrived, but the first five bytes are still missing.
  ASSERT_FALSE(
      appendDataToReadBuffer(
          stream, StreamBuffer(folly::IOBuf::copyBuffer("world"), 5, true))
          .hasError());
  ASSERT_EQ(conn.flowControlState.sumMaxObservedOffset, 10);

  ASSERT_FALSE(retireIngress(stream).hasError());

  // Every byte up to the final size is credited, including the missing ones,
  // and the FIN is consumed.
  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  EXPECT_TRUE(stream.readBuffer.empty());
  EXPECT_EQ(stream.currentReadOffset, 11);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 10);
  EXPECT_FALSE(stream.hasReadableData());
  EXPECT_FALSE(conn.streamManager->pendingWindowUpdate(id));
}

TEST_F(StreamStateFunctionsTests, RetireIngressAccountsReliableResetFinalSize) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  // None of the reliable bytes have arrived, so the reset does not account
  // for its final size yet.
  ASSERT_FALSE(
      onResetQuicStream(
          stream,
          RstStreamFrame(id, GenericApplicationErrorCode::UNKNOWN, 100, 50))
          .hasError());
  ASSERT_EQ(conn.flowControlState.sumMaxObservedOffset, 0);

  ASSERT_FALSE(retireIngress(stream).hasError());

  EXPECT_EQ(stream.recvState, StreamRecvState::Closed);
  EXPECT_EQ(stream.maxOffsetObserved, 100);
  EXPECT_EQ(conn.flowControlState.sumMaxObservedOffset, 100);
  EXPECT_EQ(conn.flowControlState.sumCurReadOffset, 100);
  // The reset is still reported to the application, so no FIN is consumed.
  EXPECT_EQ(stream.currentReadOffset, 100);
}

TEST_F(StreamStateFunctionsTests, RetireIngressRejectsFinalSizeAboveWindow) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  StreamId id = 1;
  QuicStreamState stream(id, conn);
  stream.flowControlState.advertisedMaxOffset = 100;
  ASSERT_FALSE(
      onResetQuicStream(
          stream,
          RstStreamFrame(id, GenericApplicationErrorCode::UNKNOWN, 200, 50))
          .hasError());

  auto result = retireIngress(stream);
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::FLOW_CONTROL_ERROR);
}

TEST_F(StreamStateFunctionsTests, ReadBufferRangesReleasedOnResetAndRetire) {
  auto conn = createUnifiedConn();
  const auto resetId =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  const auto retireId =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  ASSERT_FALSE(appendDataToReadBuffer(
                   *conn->streamManager->findStream(resetId),
                   StreamBuffer(folly::IOBuf::copyBuffer("r"), 1))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(
                   *conn->streamManager->findStream(resetId),
                   StreamBuffer(folly::IOBuf::copyBuffer("r"), 3))
                   .hasError());
  ASSERT_FALSE(appendDataToReadBuffer(
                   *conn->streamManager->findStream(retireId),
                   StreamBuffer(folly::IOBuf::copyBuffer("r"), 1))
                   .hasError());
  const auto expectExactReadBufferRangeCount = [&] {
    EXPECT_EQ(
        conn->streamManager->numReadBufferRanges(),
        conn->streamManager->findStream(resetId)->readBuffer.size() +
            conn->streamManager->findStream(retireId)->readBuffer.size());
  };
  expectExactReadBufferRangeCount();

  ASSERT_FALSE(
      onResetQuicStream(
          *conn->streamManager->findStream(resetId),
          RstStreamFrame(resetId, GenericApplicationErrorCode::UNKNOWN, 4, 2))
          .hasError());
  EXPECT_EQ(conn->streamManager->findStream(resetId)->readBuffer.size(), 1);
  expectExactReadBufferRangeCount();
  ASSERT_FALSE(
      retireIngress(*conn->streamManager->findStream(retireId)).hasError());
  expectExactReadBufferRangeCount();
  ASSERT_FALSE(
      retireIngress(*conn->streamManager->findStream(resetId)).hasError());

  expectExactReadBufferRangeCount();
}
} // namespace quic::test
