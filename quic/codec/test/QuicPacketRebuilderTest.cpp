/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <chrono>
#include <string>

#include <folly/portability/GTest.h>

#include <quic/codec/Decode.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamSendHandlers.h>

using namespace testing;
using namespace std::chrono_literals;

namespace quic::test {

OutstandingPacketWrapper makeDummyOutstandingPacket(
    RegularQuicWritePacket writePacket,
    uint64_t totalBytesSentOnConnection) {
  OutstandingPacketWrapper packet(
      std::move(writePacket),
      Clock::now(),
      0 /* pathId */,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      totalBytesSentOnConnection,
      0 /* inflightBytes */,
      LossState(),
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  return packet;
}

// Decodes a built packet's body the way the peer would.
std::vector<QuicFrame> decodeWireFrames(
    const PacketBuilderInterface::Packet& packet) {
  // The read path decodes from one contiguous buffer.
  auto body = packet.body.clone();
  body->coalesce();
  BufQueue queue;
  queue.append(std::move(body));
  const CodecParameters params(kDefaultAckDelayExponent, QuicVersion::MVFST);
  std::vector<QuicFrame> frames;
  while (!queue.empty()) {
    auto frame = quic::parseFrame(queue, packet.packet.header, params);
    if (frame.hasError()) {
      ADD_FAILURE() << "peer cannot decode frame: " << frame.error().message;
      break;
    }
    frames.push_back(std::move(*frame));
  }
  return frames;
}

// The peer must decode the rebuilt STREAM data with its recorded length and
// every recorded TIMESTAMP as its own frame.
void expectPeerDecodesStreamAndTimestamps(
    const PacketBuilderInterface::Packet& packet) {
  std::vector<const QuicWriteFrame*> recorded;
  for (const auto& frame : packet.packet.frames) {
    if (frame.asWriteStreamFrame() || frame.asTimestampFrame()) {
      recorded.push_back(&frame);
    }
  }
  std::vector<QuicFrame> decoded;
  for (auto& frame : decodeWireFrames(packet)) {
    if (frame.asReadStreamFrame() || frame.asTimestampFrame()) {
      decoded.push_back(std::move(frame));
    }
  }
  ASSERT_EQ(decoded.size(), recorded.size());
  for (size_t i = 0; i < recorded.size(); ++i) {
    if (const auto* written = recorded[i]->asWriteStreamFrame()) {
      const auto* read = decoded[i].asReadStreamFrame();
      ASSERT_NE(read, nullptr);
      EXPECT_EQ(read->offset, written->offset);
      EXPECT_EQ(
          read->data ? read->data->computeChainDataLength() : 0, written->len);
    } else {
      const auto* read = decoded[i].asTimestampFrame();
      ASSERT_NE(read, nullptr);
      EXPECT_EQ(read->timestamp, recorded[i]->asTimestampFrame()->timestamp);
    }
  }
}

PacketBuilderInterface::Packet buildSingleStreamPacket(
    StreamId streamId,
    uint64_t offset,
    folly::StringPiece data,
    bool fin,
    bool addTrailingPing = false,
    uint32_t packetCapacity = kDefaultUDPSendPacketLen) {
  RegularQuicPacketBuilder builder(
      packetCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  CHECK(!builder.encodePacketHeader().hasError());
  auto headerResult = writeStreamFrameHeader(
      builder,
      streamId,
      offset,
      data.size(),
      data.size(),
      fin,
      data.empty() ? Optional<bool>(false) : Optional<bool>(!addTrailingPing));
  CHECK(!headerResult.hasError());
  CHECK(headerResult.value().has_value());
  CHECK_EQ(*headerResult.value(), data.size());
  if (!data.empty()) {
    builder.push(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  }
  if (addTrailingPing) {
    CHECK(writeFrame(PingFrame{}, builder).has_value());
  }
  return std::move(builder).buildPacket();
}

class QuicPacketRebuilderTest : public Test {};

TEST_F(QuicPacketRebuilderTest, RebuildEmpty) {
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder, conn);
  auto packet = std::move(regularBuilder).buildPacket();
  EXPECT_TRUE(packet.packet.frames.empty());
  EXPECT_FALSE(packet.header.empty());
  EXPECT_TRUE(packet.body.empty());
}

TEST_F(QuicPacketRebuilderTest, RebuildSmallInitial) {
  auto srcConnId = getTestConnectionId(0);
  auto dstConnId = getTestConnectionId(1);
  QuicVersion version = QuicVersion::MVFST;
  PacketNum num = 1;
  LongHeader initialHeader1(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version, "");
  LongHeader initialHeader2(
      LongHeader::Types::Initial, srcConnId, dstConnId, num + 1, version, "");

  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(initialHeader1), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(initialHeader2), 0);

  PingFrame pingFrame{};
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  MaxStreamsFrame maxStreamsFrame(4321, true);
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamsFrame), regularBuilder1).hasError());
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto packet = std::move(regularBuilder1).buildPacket();
  auto outstanding = makeDummyOutstandingPacket(packet.packet, 1000);
  EXPECT_FALSE(packet.header.empty());
  ASSERT_EQ(packet.packet.frames.size(), 2);
  EXPECT_FALSE(packet.body.empty());
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto rebuilt = std::move(regularBuilder2).buildPacket();
  EXPECT_FALSE(rebuilt.header.empty());
  ASSERT_EQ(rebuilt.packet.frames.size(), 3);
  auto padding = rebuilt.packet.frames.back().asPaddingFrame();
  ASSERT_TRUE(padding != nullptr);
  EXPECT_GT(padding->numFrames, 1000);
  EXPECT_FALSE(rebuilt.body.empty());
  EXPECT_GT(rebuilt.body.computeChainDataLength(), 1200);
}

TEST_F(QuicPacketRebuilderTest, RebuildPacket) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  MaxStreamsFrame maxStreamsFrame(4321, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  //   WriteAckFrameMetaData ackMeta(ackBlocks, 0us, kDefaultAckDelayExponent);
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  MaxDataFrame maxDataFrame(1000);
  MaxStreamDataFrame maxStreamDataFrame(streamId, 2000);
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  PingFrame pingFrame{};
  // Write them with a regular builder
  // Write the ACK frame first since it has special rebuilder handling.
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder1).hasError());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamsFrame), regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  ASSERT_FALSE(writeFrame(maxDataFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(maxStreamDataFrame, regularBuilder1).hasError());
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(8, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 0, true)));
  conn.cryptoState->oneRttStream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(cryptoBuf), 0, true)));
  // Write an updated ackState that should be used when rebuilding the AckFrame
  conn.ackStates.appDataAckState.acks.insert(1000, 1200);
  conn.ackStates.appDataAckState.largestRecvdPacketTime = quic::Clock::now();

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  auto expectedConnFlowControlValue = std::max(
      conn.flowControlState.sumCurReadOffset + conn.flowControlState.windowSize,
      conn.flowControlState.advertisedMaxOffset);
  auto expectedStreamFlowControlValue = std::max(
      stream->currentReadOffset + stream->flowControlState.windowSize,
      stream->flowControlState.advertisedMaxOffset);
  for (const auto& frame : packet2.packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::ConnectionCloseFrame: {
        const ConnectionCloseFrame& closeFrame =
            *frame.asConnectionCloseFrame();
        const TransportErrorCode* transportErrorCode =
            closeFrame.errorCode.asTransportErrorCode();
        EXPECT_EQ(
            TransportErrorCode::FRAME_ENCODING_ERROR, *transportErrorCode);
        EXPECT_EQ("The sun is in the sky.", closeFrame.reasonPhrase);
        EXPECT_EQ(FrameType::ACK, closeFrame.closingFrameType);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        EXPECT_NE(frame.asPingFrame(), nullptr);
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        switch (simpleFrame.type()) {
          case QuicSimpleFrame::Type::MaxStreamsFrame: {
            const MaxStreamsFrame* maxStreamFrame =
                simpleFrame.asMaxStreamsFrame();
            EXPECT_NE(maxStreamFrame, nullptr);
            EXPECT_EQ(4321, maxStreamFrame->maxStreams);
            break;
          }
          default:
            EXPECT_TRUE(false); /* fail if this happens */
        }
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& ack = *frame.asWriteAckFrame();
        EXPECT_EQ(1, ack.ackBlocks.size());
        EXPECT_EQ(Interval<PacketNum>(1000, 1200), ack.ackBlocks.back());
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        EXPECT_EQ(streamId, streamFrame.streamId);
        EXPECT_EQ(0, streamFrame.offset);
        EXPECT_EQ(buf->computeChainDataLength(), streamFrame.len);
        EXPECT_EQ(true, streamFrame.fin);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& cryptoFrame = *frame.asWriteCryptoFrame();
        EXPECT_EQ(cryptoFrame.offset, cryptoOffset);
        EXPECT_EQ(cryptoFrame.len, cryptoBuf->computeChainDataLength());
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        const MaxDataFrame& maxData = *frame.asMaxDataFrame();
        EXPECT_EQ(expectedConnFlowControlValue, maxData.maximumData);
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamData = *frame.asMaxStreamDataFrame();
        EXPECT_EQ(streamId, maxStreamData.streamId);
        EXPECT_EQ(expectedStreamFlowControlValue, maxStreamData.maximumData);
        break;
      }
      default:
        EXPECT_TRUE(false); /* should never happen*/
    }
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
  // TODO: I don't have a good way to verify body without decode them
}

TEST_F(QuicPacketRebuilderTest, RebuildAfterResetStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf = folly::IOBuf::copyBuffer("A million miles away.");
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());

  // Then we reset the stream
  ASSERT_FALSE(sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, FinOnlyStreamRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;

  // Write them with a regular builder
  (void)writeStreamFrameHeader(
      regularBuilder1, streamId, 0, 0, 0, true, std::nullopt /* skipLenHint */);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(), 0, true)));

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 2000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  EXPECT_TRUE(
      0 ==
      memcmp(
          packet1.packet.frames.data(),
          packet2.packet.frames.data(),
          packet1.packet.frames.size()));
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
  // Once we start to use the correct ack delay value in AckFrames, this needs
  // to be changed:
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.body, packet2.body));
}

TEST_F(QuicPacketRebuilderTest, RebuildDataStreamAndEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  StreamId streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(2, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 0, true)));
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size() + 1);
  for (const auto& frame : packet2.packet.frames) {
    const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
    if (!streamFrame) {
      EXPECT_TRUE(false); /* should never happen*/
    }
    EXPECT_EQ(streamId, streamFrame->streamId);
    EXPECT_EQ(0, streamFrame->offset);
    EXPECT_EQ(buf->computeChainDataLength(), streamFrame->len);
    EXPECT_EQ(true, streamFrame->fin);
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
}

TEST_F(QuicPacketRebuilderTest, CannotRebuildEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, CannotRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  StreamsBlockedFrame maxStreamIdFrame(0x1024, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  PingFrame pingFrame;
  // Write them with a regular builder
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(maxStreamIdFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder1).hasError());
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(5, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf), 0, true)));

  // new builder has a much smaller writable bytes limit
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      (packet1.header.computeChainDataLength() +
       packet1.body.computeChainDataLength()) /
          2,
      std::move(shortHeader2),
      0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, CloneCounter) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  MaxDataFrame maxDataFrame(31415926);
  ASSERT_FALSE(writeFrame(maxDataFrame, regularBuilder).hasError());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1000);
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  ASSERT_FALSE(rebuilder.rebuildFromPacket(outstandingPacket).hasError());
  EXPECT_TRUE(outstandingPacket.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(1, conn.outstandings.numClonedPackets());
}

TEST_F(QuicPacketRebuilderTest, PurePingWillRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  PingFrame pingFrame;
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder).hasError());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 50);
  EXPECT_EQ(1, outstandingPacket.packet.frames.size());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  EXPECT_TRUE(outstandingPacket.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(1, conn.outstandings.numClonedPackets());
}

TEST_F(QuicPacketRebuilderTest, TimestampFrameIsDroppedDuringRebuild) {
  ShortHeader originalHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder originalBuilder(
      kDefaultUDPSendPacketLen, std::move(originalHeader), 0);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(PingFrame(), originalBuilder).hasError());
  ASSERT_FALSE(writeFrame(TimestampFrame(1234), originalBuilder).hasError());
  auto originalPacket = std::move(originalBuilder).buildPacket();
  auto outstandingPacket =
      makeDummyOutstandingPacket(originalPacket.packet, 50);

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ShortHeader rebuiltHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 1);
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen, std::move(rebuiltHeader), 0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  ASSERT_EQ(rebuiltPacket.packet.frames.size(), 1);
  EXPECT_NE(rebuiltPacket.packet.frames.front().asPingFrame(), nullptr);
}

struct TimestampRebuildPolicyCase {
  const char* name;
  TimestampFrameWriteMode writeMode;
  bool originalHasTimestamp;
  bool fillPacket;
  bool expectFreshTimestamp;
};

class TimestampRebuildPolicyTest
    : public QuicPacketRebuilderTest,
      public WithParamInterface<TimestampRebuildPolicyCase> {};

TEST_P(TimestampRebuildPolicyTest, PreservesRebuiltStreamBeforeFreshTimestamp) {
  const auto& testCase = GetParam();
  constexpr uint64_t kOriginalTimestamp = 1;
  constexpr uint64_t kPacketCapacity = 128;

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_NE(conn.streamManager, nullptr);
  if (conn.streamManager == nullptr) {
    return;
  }
  auto& streamManager = *conn.streamManager;
  ASSERT_FALSE(streamManager.setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = streamManager.createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);
  if (stream == nullptr) {
    return;
  }

  // Like CloningScheduler, account for the AEAD tag so that buildPacket() does
  // not pad these small bodies for header protection.
  constexpr uint8_t kCipherOverhead = 16;
  RegularQuicPacketBuilder originalBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  originalBuilder.accountForCipherOverhead(kCipherOverhead);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());

  PacketBuilderInterface* streamBuilder = &originalBuilder;
  Optional<PacketBuilderWrapper> timestampReservation;
  if (testCase.fillPacket && testCase.originalHasTimestamp) {
    auto timestampSize =
        getTimestampFrameEncodedSize(TimestampFrame(kOriginalTimestamp));
    ASSERT_FALSE(timestampSize.hasError());
    ASSERT_GE(originalBuilder.remainingSpaceInPkt(), timestampSize.value());
    timestampReservation.emplace(
        originalBuilder,
        originalBuilder.remainingSpaceInPkt() - timestampSize.value());
    streamBuilder = &*timestampReservation;
  }

  const uint64_t requestedDataLength =
      testCase.fillPacket ? kPacketCapacity : 1;
  auto streamResult = writeStreamFrameHeader(
      *streamBuilder,
      stream->id,
      0,
      requestedDataLength,
      requestedDataLength,
      false,
      !testCase.originalHasTimestamp);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.value().has_value());
  const auto streamLength = *streamResult.value();
  ASSERT_GT(streamLength, 0);
  auto streamData = folly::IOBuf::copyBuffer(std::string(streamLength, 'x'));
  ASSERT_NE(streamData, nullptr);
  if (streamData == nullptr) {
    return;
  }
  writeStreamFrameData(*streamBuilder, streamData->clone(), streamLength);

  if (testCase.originalHasTimestamp) {
    ASSERT_FALSE(writeFrame(TimestampFrame(kOriginalTimestamp), originalBuilder)
                     .hasError());
  }
  if (testCase.fillPacket) {
    EXPECT_EQ(0, originalBuilder.remainingSpaceInPkt());
  }
  auto originalPacket = std::move(originalBuilder).buildPacket();
  ASSERT_EQ(
      testCase.originalHasTimestamp ? 2 : 1,
      originalPacket.packet.frames.size());
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 50);

  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(streamData), 0, false)));
  conn.peerTimestampFrameState.canReceive = true;
  conn.transportSettings.oneRttTimestampFrameWriteMode = testCase.writeMode;
  conn.transportSettings.timestampFrameTimestampExponent = 0;
  conn.connectionTime = Clock::now() - 1s;
  const auto minimumFreshTimestamp = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          Clock::now() - conn.connectionTime)
          .count());
  if (testCase.fillPacket && testCase.originalHasTimestamp) {
    auto originalSize =
        getTimestampFrameEncodedSize(TimestampFrame(kOriginalTimestamp));
    auto freshSize =
        getTimestampFrameEncodedSize(TimestampFrame(minimumFreshTimestamp));
    ASSERT_FALSE(originalSize.hasError());
    ASSERT_FALSE(freshSize.hasError());
    ASSERT_GT(freshSize.value(), originalSize.value());
  }

  RegularQuicPacketBuilder rebuiltBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  rebuiltBuilder.accountForCipherOverhead(kCipherOverhead);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());

  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  ASSERT_EQ(
      testCase.expectFreshTimestamp ? 2 : 1,
      rebuiltPacket.packet.frames.size());
  size_t timestampCount = 0;
  const WriteStreamFrame* rebuiltStream = nullptr;
  for (const auto& frame : rebuiltPacket.packet.frames) {
    if (const auto* timestampFrame = frame.asTimestampFrame()) {
      ++timestampCount;
      if (testCase.originalHasTimestamp) {
        EXPECT_NE(kOriginalTimestamp, timestampFrame->timestamp);
      }
      EXPECT_GE(timestampFrame->timestamp, minimumFreshTimestamp);
    } else if (const auto* streamFrame = frame.asWriteStreamFrame()) {
      rebuiltStream = streamFrame;
    }
  }
  ASSERT_NE(nullptr, rebuiltStream);
  if (rebuiltStream == nullptr) {
    return;
  }
  EXPECT_EQ(streamLength, rebuiltStream->len);
  EXPECT_EQ(testCase.expectFreshTimestamp ? 1 : 0, timestampCount);
  expectPeerDecodesStreamAndTimestamps(rebuiltPacket);
}

INSTANTIATE_TEST_SUITE_P(
    WriteModeAndCapacity,
    TimestampRebuildPolicyTest,
    Values(
        // The original's last frame is a STREAM frame without a length, so the
        // rebuilt one also extends to the end of the packet and no TIMESTAMP
        // can follow it.
        TimestampRebuildPolicyCase{
            "OpportunisticRoomWithoutOriginal",
            TimestampFrameWriteMode::Opportunistic,
            false,
            false,
            false},
        TimestampRebuildPolicyCase{
            "OpportunisticRoomWithOriginal",
            TimestampFrameWriteMode::Opportunistic,
            true,
            false,
            true},
        TimestampRebuildPolicyCase{
            "OpportunisticFullWithoutOriginal",
            TimestampFrameWriteMode::Opportunistic,
            false,
            true,
            false},
        TimestampRebuildPolicyCase{
            "OpportunisticFullWithSmallerOriginal",
            TimestampFrameWriteMode::Opportunistic,
            true,
            true,
            false},
        TimestampRebuildPolicyCase{
            "PrioritizedRoomWithoutOriginal",
            TimestampFrameWriteMode::Prioritized,
            false,
            false,
            false},
        TimestampRebuildPolicyCase{
            "PrioritizedRoomWithOriginal",
            TimestampFrameWriteMode::Prioritized,
            true,
            false,
            true},
        TimestampRebuildPolicyCase{
            "PrioritizedFullWithoutOriginal",
            TimestampFrameWriteMode::Prioritized,
            false,
            true,
            false},
        TimestampRebuildPolicyCase{
            "PrioritizedFullWithSmallerOriginal",
            TimestampFrameWriteMode::Prioritized,
            true,
            true,
            false}),
    [](const TestParamInfo<TimestampRebuildPolicyCase>& info) {
      return info.param.name;
    });

class TimestampAfterLengthlessStreamTest
    : public QuicPacketRebuilderTest,
      public WithParamInterface<TimestampFrameWriteMode> {};

// Rebuilding drops the DATAGRAM ahead of a packet-filling STREAM frame, which
// leaves room for a TIMESTAMP. The rebuilt STREAM frame still has no length,
// so a TIMESTAMP after it would be decoded as stream data.
TEST_P(TimestampAfterLengthlessStreamTest, RoomLeftByDroppedFrame) {
  constexpr uint64_t kPacketCapacity = 128;
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  RegularQuicPacketBuilder originalBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());
  constexpr size_t kDatagramLength = 20;
  ASSERT_FALSE(
      writeFrame(
          DatagramFrame(
              kDatagramLength,
              folly::IOBuf::copyBuffer(std::string(kDatagramLength, 'd'))),
          originalBuilder)
          .hasError());
  auto streamResult = writeStreamFrameHeader(
      originalBuilder,
      stream->id,
      0,
      kPacketCapacity,
      kPacketCapacity,
      false,
      std::nullopt);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.value().has_value());
  const auto streamLength = *streamResult.value();
  auto streamData = folly::IOBuf::copyBuffer(std::string(streamLength, 'x'));
  writeStreamFrameData(originalBuilder, streamData->clone(), streamLength);
  ASSERT_EQ(0, originalBuilder.remainingSpaceInPkt());
  auto originalPacket = std::move(originalBuilder).buildPacket();
  ASSERT_EQ(2, originalPacket.packet.frames.size());
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 50);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(streamData), 0, false)));

  conn.peerTimestampFrameState.canReceive = true;
  conn.transportSettings.oneRttTimestampFrameWriteMode = GetParam();
  conn.connectionTime = Clock::now() - 1s;
  RegularQuicPacketBuilder rebuiltBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  ASSERT_GT(rebuiltBuilder.remainingSpaceInPkt(), kDatagramLength);

  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  ASSERT_EQ(1, rebuiltPacket.packet.frames.size());
  const auto* rebuiltStream =
      rebuiltPacket.packet.frames[0].asWriteStreamFrame();
  ASSERT_NE(rebuiltStream, nullptr);
  EXPECT_EQ(streamLength, rebuiltStream->len);
  expectPeerDecodesStreamAndTimestamps(rebuiltPacket);
}

INSTANTIATE_TEST_SUITE_P(
    WriteModes,
    TimestampAfterLengthlessStreamTest,
    Values(
        TimestampFrameWriteMode::Opportunistic,
        TimestampFrameWriteMode::Prioritized));

struct TimestampAheadOfStreamCase {
  std::string name;
  TimestampFrameWriteMode mode;
  // The original TIMESTAMP value. The fresh one is about 5 seconds in
  // microseconds, a 4-byte varint.
  uint64_t originalTimestamp;
  bool expectFreshTimestamp;
};

class TimestampAheadOfStreamTest
    : public QuicPacketRebuilderTest,
      public WithParamInterface<TimestampAheadOfStreamCase> {};

// Prioritized writes its TIMESTAMP ahead of a STREAM frame that fills the
// packet, so the STREAM frame omits its length. The clone puts a fresh
// TIMESTAMP in the same place when it and the STREAM frame both fit, and
// otherwise drops it; either way the rebuilt STREAM frame still ends the
// packet.
TEST_P(TimestampAheadOfStreamTest, FreshTimestampKeepsStreamFrameLast) {
  constexpr uint64_t kPacketCapacity = 128;
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  RegularQuicPacketBuilder originalBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());
  ASSERT_FALSE(
      writeFrame(TimestampFrame(GetParam().originalTimestamp), originalBuilder)
          .hasError());
  auto streamResult = writeStreamFrameHeader(
      originalBuilder,
      stream->id,
      0,
      kPacketCapacity,
      kPacketCapacity,
      false,
      std::nullopt);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.value().has_value());
  const auto streamLength = *streamResult.value();
  auto streamData = folly::IOBuf::copyBuffer(std::string(streamLength, 'x'));
  writeStreamFrameData(originalBuilder, streamData->clone(), streamLength);
  ASSERT_EQ(0, originalBuilder.remainingSpaceInPkt());
  auto originalPacket = std::move(originalBuilder).buildPacket();
  ASSERT_EQ(2, originalPacket.packet.frames.size());
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 50);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(streamData), 0, false)));

  conn.peerTimestampFrameState.canReceive = true;
  conn.transportSettings.oneRttTimestampFrameWriteMode = GetParam().mode;
  conn.connectionTime = Clock::now() - 5s;
  RegularQuicPacketBuilder rebuiltBuilder(
      kPacketCapacity,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());

  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  const auto& frames = rebuiltPacket.packet.frames;
  ASSERT_EQ(frames.size(), GetParam().expectFreshTimestamp ? 2 : 1);
  if (GetParam().expectFreshTimestamp) {
    const auto* timestamp = frames[0].asTimestampFrame();
    ASSERT_NE(timestamp, nullptr);
    EXPECT_GT(timestamp->timestamp, GetParam().originalTimestamp);
  }
  const auto* rebuiltStream = frames.back().asWriteStreamFrame();
  ASSERT_NE(rebuiltStream, nullptr);
  EXPECT_EQ(streamLength, rebuiltStream->len);
  expectPeerDecodesStreamAndTimestamps(rebuiltPacket);
}

INSTANTIATE_TEST_SUITE_P(
    TimestampAheadOfStreamTests,
    TimestampAheadOfStreamTest,
    Values(
        TimestampAheadOfStreamCase{
            "PrioritizedSameSize",
            TimestampFrameWriteMode::Prioritized,
            1000000,
            true},
        TimestampAheadOfStreamCase{
            "OpportunisticSameSize",
            TimestampFrameWriteMode::Opportunistic,
            1000000,
            true},
        TimestampAheadOfStreamCase{
            "PrioritizedFreshWouldGrow",
            TimestampFrameWriteMode::Prioritized,
            1000,
            false}),
    [](const TestParamInfo<TimestampAheadOfStreamCase>& info) {
      return info.param.name;
    });

// A TIMESTAMP ahead of a FIN-only final STREAM frame: the rebuilt frame keeps
// its length field, so no fresh TIMESTAMP goes ahead of it.
TEST_F(QuicPacketRebuilderTest, NoTimestampAheadOfStreamFrameWithLength) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  RegularQuicPacketBuilder originalBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(TimestampFrame(1000000), originalBuilder).hasError());
  auto streamResult = writeStreamFrameHeader(
      originalBuilder, stream->id, 0, 0, 0, true, std::nullopt);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.value().has_value());
  ASSERT_EQ(*streamResult.value(), 0);
  auto originalPacket = std::move(originalBuilder).buildPacket();
  ASSERT_EQ(2, originalPacket.packet.frames.size());
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 50);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(), 0, true)));

  conn.peerTimestampFrameState.canReceive = true;
  conn.transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Prioritized;
  conn.connectionTime = Clock::now() - 5s;
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());

  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  const auto& frames = rebuiltPacket.packet.frames;
  ASSERT_FALSE(frames.empty());
  const auto* rebuiltStream = frames[0].asWriteStreamFrame();
  ASSERT_NE(rebuiltStream, nullptr);
  EXPECT_EQ(rebuiltStream->len, 0);
  EXPECT_TRUE(rebuiltStream->fin);
  expectPeerDecodesStreamAndTimestamps(rebuiltPacket);
}

TEST_F(QuicPacketRebuilderTest, TimestampOnlyPacketDoesNotRebuild) {
  RegularQuicPacketBuilder originalBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0);
  ASSERT_FALSE(originalBuilder.encodePacketHeader().hasError());
  ASSERT_FALSE(writeFrame(TimestampFrame(1), originalBuilder).hasError());
  auto originalPacket = std::move(originalBuilder).buildPacket();
  ASSERT_EQ(1, originalPacket.packet.frames.size());
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 50);

  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerTimestampFrameState.canReceive = true;
  conn.transportSettings.oneRttTimestampFrameWriteMode =
      TimestampFrameWriteMode::Opportunistic;
  conn.connectionTime = Clock::now() - 1s;
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
  EXPECT_FALSE(outstanding.maybeClonedPacketIdentifier.has_value());
  EXPECT_TRUE(std::move(rebuiltBuilder).buildPacket().packet.frames.empty());
}

TEST_F(QuicPacketRebuilderTest, LastStreamFrameSkipLen) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(100).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf1 =
      folly::IOBuf::copyBuffer("Remember your days are fully numbered.");
  auto buf2 = folly::IOBuf::copyBuffer("Just march on");

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      false,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf1->clone(), buf1->computeChainDataLength());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      buf1->computeChainDataLength(),
      buf2->computeChainDataLength(),
      buf2->computeChainDataLength(),
      true,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf2->clone(), buf2->computeChainDataLength());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1200);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf1), 0, false)));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(buf1->computeChainDataLength()),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf2),
              buf1->computeChainDataLength(),
              true)));
  MockQuicPacketBuilder mockBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(mockBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // write data twice
  EXPECT_CALL(mockBuilder, _insertRch(_, _))
      .Times(2)
      .WillRepeatedly(Invoke([&](const ChainedByteRangeHead&, size_t limit) {
        packetLimit -= limit;
      }));
  // Append frame twice
  EXPECT_CALL(mockBuilder, appendFrame(_)).Times(2);
  // initial byte:
  EXPECT_CALL(mockBuilder, writeBEUint8(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](uint8_t) { packetLimit--; }));
  // Write streamId twice, offset once, then data len only once:
  EXPECT_CALL(mockBuilder, write(_))
      .Times(4)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        auto sizeResult = quicInt.getSize();
        ASSERT_FALSE(sizeResult.hasError());
        packetLimit -= sizeResult.value();
      }));

  PacketRebuilder rebuilder(mockBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, LastStreamFrameFinOnlySkipLen) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(100).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf1 =
      folly::IOBuf::copyBuffer("Remember your days are fully numbered.");

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      false,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf1->clone(), buf1->computeChainDataLength());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      buf1->computeChainDataLength(),
      0,
      0,
      true,
      std::nullopt);
  writeStreamFrameData(regularBuilder, ChainedByteRangeHead(), 0);
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1200);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(buf1), 0, false)));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(buf1->computeChainDataLength()),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(), buf1->computeChainDataLength(), true)));

  MockQuicPacketBuilder mockBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(mockBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // write data only
  EXPECT_CALL(mockBuilder, _insertRch(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const ChainedByteRangeHead&, size_t limit) {
        packetLimit -= limit;
      }));
  // Append frame twice
  EXPECT_CALL(mockBuilder, appendFrame(_)).Times(2);
  // initial byte:
  EXPECT_CALL(mockBuilder, writeBEUint8(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](uint8_t) { packetLimit--; }));
  // Write streamId twice, offset once, then data len twice:
  EXPECT_CALL(mockBuilder, write(_))
      .Times(5)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        auto sizeResult = quicInt.getSize();
        ASSERT_FALSE(sizeResult.hasError());
        packetLimit -= sizeResult.value();
      }));

  PacketRebuilder rebuilder(mockBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
}

TEST_F(
    QuicPacketRebuilderTest,
    UnifiedStreamCloneWritesOriginalChainedSubrange) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  stream->streamSendBuffer.emplace();
  auto sendData = folly::IOBuf::copyBuffer("0123");
  sendData->appendChain(folly::IOBuf::copyBuffer("456789"));
  ASSERT_TRUE(stream->streamSendBuffer->append(std::move(sendData), true));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 10, .fin = true}));

  auto originalPacket = buildSingleStreamPacket(stream->id, 3, "3456789", true);
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  ASSERT_EQ(1, rebuiltPacket.packet.frames.size());
  const auto* rebuiltFrame =
      rebuiltPacket.packet.frames.front().asWriteStreamFrame();
  ASSERT_NE(rebuiltFrame, nullptr);
  EXPECT_EQ(stream->id, rebuiltFrame->streamId);
  EXPECT_EQ(3, rebuiltFrame->offset);
  EXPECT_EQ(7, rebuiltFrame->len);
  EXPECT_TRUE(rebuiltFrame->fin);
  EXPECT_TRUE(folly::IOBufEqualTo()(originalPacket.body, rebuiltPacket.body));
}

TEST_F(QuicPacketRebuilderTest, UnifiedStreamCloneSkipsPartiallyAckedFrame) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  stream->streamSendBuffer.emplace();
  auto sendData = folly::IOBuf::copyBuffer("0123");
  sendData->appendChain(folly::IOBuf::copyBuffer("456789"));
  ASSERT_TRUE(stream->streamSendBuffer->append(std::move(sendData), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 10, .fin = false}));
  auto ackResult = stream->streamSendBuffer->markAcked(
      {.offset = 3, .len = 2, .fin = false});
  ASSERT_TRUE(ackResult.has_value());
  EXPECT_EQ(2, ackResult->newlyAckedBytes);

  auto originalPacket = buildSingleStreamPacket(stream->id, 3, "34567", false);
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  EXPECT_TRUE(rebuiltPacket.packet.frames.empty());
  EXPECT_TRUE(rebuiltPacket.body.empty());
}

TEST_F(QuicPacketRebuilderTest, UnifiedStreamClonePreservesFinOnlyFrame) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  stream->streamSendBuffer.emplace();
  ASSERT_TRUE(stream->streamSendBuffer->append(nullptr, true));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = 0, .fin = true}));

  auto originalPacket = buildSingleStreamPacket(stream->id, 0, "", true);
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  ASSERT_EQ(1, rebuiltPacket.packet.frames.size());
  const auto* rebuiltFrame =
      rebuiltPacket.packet.frames.front().asWriteStreamFrame();
  ASSERT_NE(rebuiltFrame, nullptr);
  EXPECT_EQ(0, rebuiltFrame->len);
  EXPECT_TRUE(rebuiltFrame->fin);
  EXPECT_TRUE(folly::IOBufEqualTo()(originalPacket.body, rebuiltPacket.body));
}

TEST_F(QuicPacketRebuilderTest, UnifiedStreamCloneRequiresCompleteCapacity) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  constexpr folly::StringPiece kData = "0123456789";
  stream->streamSendBuffer.emplace();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(folly::IOBuf::copyBuffer(kData), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = kData.size(), .fin = false}));

  auto originalPacket = buildSingleStreamPacket(stream->id, 0, kData, false);
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  const auto rebuiltCapacity =
      originalPacket.header.computeChainDataLength() + kData.size();
  RegularQuicPacketBuilder rebuiltBuilder(
      static_cast<uint32_t>(rebuiltCapacity),
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  EXPECT_TRUE(rebuiltPacket.packet.frames.empty());
  EXPECT_TRUE(rebuiltPacket.body.empty());
}

TEST_F(
    QuicPacketRebuilderTest,
    UnifiedStreamCloneRejectsLengthEncodingBoundaryWithoutMutation) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  const std::string data(kTwoByteLimit - 1, 'x');
  stream->streamSendBuffer.emplace();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(folly::IOBuf::copyBuffer(data), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = data.size(), .fin = false}));

  auto originalPacket = buildSingleStreamPacket(
      stream->id,
      0,
      data,
      false,
      true,
      static_cast<uint32_t>(data.size() + 64));
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  const auto streamIdSize = QuicInteger(stream->id).getSize();
  ASSERT_FALSE(streamIdSize.hasError());
  const auto rebuiltCapacity = originalPacket.header.computeChainDataLength() +
      sizeof(uint8_t) + streamIdSize.value() + 2 + data.size();
  RegularQuicPacketBuilder rebuiltBuilder(
      static_cast<uint32_t>(rebuiltCapacity),
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);

  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  EXPECT_TRUE(rebuiltPacket.packet.frames.empty());
  EXPECT_TRUE(rebuiltPacket.body.empty());
}

TEST_F(QuicPacketRebuilderTest, UnifiedStreamCloneSkipsRetiredData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(1).hasError());
  auto* stream = conn.streamManager->createNextBidirectionalStream().value();
  ASSERT_NE(stream, nullptr);

  constexpr folly::StringPiece kData = "retired";
  stream->streamSendBuffer.emplace();
  ASSERT_TRUE(
      stream->streamSendBuffer->append(folly::IOBuf::copyBuffer(kData), false));
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(
      {.offset = 0, .len = kData.size(), .fin = false}));
  ASSERT_TRUE(stream->streamSendBuffer->abandon(
      {.offset = 0, .len = kData.size(), .fin = false}));

  auto originalPacket = buildSingleStreamPacket(stream->id, 0, kData, false);
  auto outstanding = makeDummyOutstandingPacket(originalPacket.packet, 1000);
  RegularQuicPacketBuilder rebuiltBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1),
      0);
  ASSERT_FALSE(rebuiltBuilder.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(rebuiltBuilder, conn);

  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
  auto rebuiltPacket = std::move(rebuiltBuilder).buildPacket();
  EXPECT_TRUE(rebuiltPacket.packet.frames.empty());
  EXPECT_TRUE(rebuiltPacket.body.empty());
}
} // namespace quic::test
