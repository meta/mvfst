/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Decode.h>

#include <folly/Random.h>
#include <folly/container/Array.h>
#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/test/TestUtils.h>
#include <ctime>
#include <string>

using namespace testing;

namespace quic::test {

using UnderlyingFrameType = std::underlying_type<FrameType>::type;

class DecodeTest : public Test {};

ShortHeader makeHeader() {
  PacketNum packetNum = 100;
  return {ProtectionType::KeyPhaseZero, getTestConnectionId(), packetNum};
}

// Long header in a non-AppData packet-number space (Initial). draft-02 ACK
// receive-timestamp frames are 1-RTT only and must be rejected here.
LongHeader makeLongHeader(LongHeader::Types type = LongHeader::Types::Initial) {
  PacketNum packetNum = 100;
  return LongHeader(
      type,
      getTestConnectionId(),
      getTestConnectionId(),
      packetNum,
      QuicVersion::MVFST);
}

// NormalizedAckBlocks are in order needed.
struct NormalizedAckBlock {
  QuicInteger gap; // Gap to previous AckBlock
  QuicInteger blockLen;

  NormalizedAckBlock(QuicInteger gapIn, QuicInteger blockLenIn)
      : gap(gapIn), blockLen(blockLenIn) {}
};

template <class LargestAckedType = uint64_t>
std::unique_ptr<folly::IOBuf> createAckFrame(
    Optional<QuicInteger> largestAcked,
    Optional<QuicInteger> ackDelay = std::nullopt,
    Optional<QuicInteger> numAdditionalBlocks = std::nullopt,
    Optional<QuicInteger> firstAckBlockLength = std::nullopt,
    std::vector<NormalizedAckBlock> ackBlocks = {},
    bool useRealValuesForLargestAcked = false,
    bool useRealValuesForAckDelay = false,
    bool addEcnCounts = false,
    bool useExtendedAck = false) {
  std::unique_ptr<folly::IOBuf> ackFrame = folly::IOBuf::create(0);
  BufAppender wcursor(ackFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (largestAcked) {
    if (useRealValuesForLargestAcked) {
      wcursor.writeBE<LargestAckedType>(largestAcked->getValue());
    } else {
      largestAcked->encode(appenderOp);
    }
  }
  if (ackDelay) {
    if (useRealValuesForAckDelay) {
      wcursor.writeBE(ackDelay->getValue());
    } else {
      ackDelay->encode(appenderOp);
    }
  }
  if (numAdditionalBlocks) {
    numAdditionalBlocks->encode(appenderOp);
  }
  if (firstAckBlockLength) {
    firstAckBlockLength->encode(appenderOp);
  }
  for (size_t i = 0; i < ackBlocks.size(); ++i) {
    ackBlocks[i].gap.encode(appenderOp);
    ackBlocks[i].blockLen.encode(appenderOp);
  }
  if (useExtendedAck) {
    // Write extended ack with ECN if enabled.
    QuicInteger extendedAckFeatures(
        addEcnCounts ? static_cast<ExtendedAckFeatureMaskType>(
                           ExtendedAckFeatureMask::ECN_COUNTS)
                     : 0);
    extendedAckFeatures.encode(appenderOp);
  }
  if (addEcnCounts) {
    QuicInteger ect0(1); // ECT-0 count
    QuicInteger ect1(2); // ECT-1 count
    QuicInteger ce(3); // CE count
    ect0.encode(appenderOp);
    ect1.encode(appenderOp);
    ce.encode(appenderOp);
  }
  ackFrame->coalesce();
  return ackFrame;
}

std::unique_ptr<folly::IOBuf> createRstStreamFrame(
    StreamId streamId,
    ApplicationErrorCode errorCode,
    uint64_t finalSize,
    Optional<uint64_t> reliableSize = std::nullopt) {
  std::unique_ptr<folly::IOBuf> rstStreamFrame = folly::IOBuf::create(0);
  BufAppender wcursor(rstStreamFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };

  FrameType frameType =
      reliableSize ? FrameType::RST_STREAM_AT : FrameType::RST_STREAM;

  // Write the frame type
  QuicInteger frameTypeQuicInt(static_cast<uint64_t>(frameType));
  frameTypeQuicInt.encode(appenderOp);

  // Write the stream id
  QuicInteger streamIdQuicInt(streamId);
  streamIdQuicInt.encode(appenderOp);

  // Write the error code
  QuicInteger errorCodeQuicInt(static_cast<uint64_t>(errorCode));
  errorCodeQuicInt.encode(appenderOp);

  // Write the final size
  QuicInteger finalSizeQuicInt(finalSize);
  finalSizeQuicInt.encode(appenderOp);

  if (reliableSize) {
    // Write the reliable size
    QuicInteger reliableSizeQuicInt(*reliableSize);
    reliableSizeQuicInt.encode(appenderOp);
  }

  rstStreamFrame->coalesce();

  return rstStreamFrame;
}

template <class StreamIdType = StreamId>
std::unique_ptr<folly::IOBuf> createStreamFrame(
    Optional<QuicInteger> streamId,
    Optional<QuicInteger> offset = std::nullopt,
    Optional<QuicInteger> dataLength = std::nullopt,
    BufPtr data = nullptr,
    bool useRealValuesForStreamId = false,
    Optional<QuicInteger> groupId = std::nullopt) {
  std::unique_ptr<folly::IOBuf> streamFrame = folly::IOBuf::create(0);
  BufAppender wcursor(streamFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (streamId) {
    if (useRealValuesForStreamId) {
      wcursor.writeBE<StreamIdType>(streamId->getValue());
    } else {
      streamId->encode(appenderOp);
    }
  }
  if (groupId) {
    groupId->encode(appenderOp);
  }
  if (offset) {
    offset->encode(appenderOp);
  }
  if (dataLength) {
    dataLength->encode(appenderOp);
  }
  if (data) {
    wcursor.insert(std::move(data));
  }
  streamFrame->coalesce();
  return streamFrame;
}

std::unique_ptr<folly::IOBuf> createCryptoFrame(
    Optional<QuicInteger> offset = std::nullopt,
    Optional<QuicInteger> dataLength = std::nullopt,
    BufPtr data = nullptr) {
  std::unique_ptr<folly::IOBuf> cryptoFrame = folly::IOBuf::create(0);
  BufAppender wcursor(cryptoFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (offset) {
    offset->encode(appenderOp);
  }
  if (dataLength) {
    dataLength->encode(appenderOp);
  }
  if (data) {
    wcursor.insert(std::move(data));
  }
  cryptoFrame->coalesce();
  return cryptoFrame;
}

std::unique_ptr<folly::IOBuf> createAckFrequencyFrame(
    Optional<QuicInteger> sequenceNumber,
    Optional<QuicInteger> packetTolerance,
    Optional<QuicInteger> maxAckDelay,
    Optional<QuicInteger> reorderThreshold) {
  QuicInteger intFrameType(static_cast<uint64_t>(FrameType::ACK_FREQUENCY));
  std::unique_ptr<folly::IOBuf> ackFrequencyFrame = folly::IOBuf::create(0);
  BufAppender wcursor(ackFrequencyFrame.get(), 50);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (sequenceNumber) {
    sequenceNumber->encode(appenderOp);
  }
  if (packetTolerance) {
    packetTolerance->encode(appenderOp);
  }
  if (maxAckDelay) {
    maxAckDelay->encode(appenderOp);
  }
  if (reorderThreshold) {
    reorderThreshold->encode(appenderOp);
  }
  ackFrequencyFrame->coalesce();
  return ackFrequencyFrame;
}

TEST_F(DecodeTest, VersionNegotiationPacketDecodeTest) {
  ConnectionId srcCid = getTestConnectionId(0),
               destCid = getTestConnectionId(1);
  std::vector<QuicVersion> versions{
      {static_cast<QuicVersion>(1234),
       static_cast<QuicVersion>(4321),
       static_cast<QuicVersion>(2341),
       static_cast<QuicVersion>(3412),
       static_cast<QuicVersion>(4123)}};
  auto packet =
      VersionNegotiationPacketBuilder(srcCid, destCid, versions).buildPacket();
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->destinationConnectionId, destCid);
  EXPECT_EQ(versionPacket->sourceConnectionId, srcCid);
  EXPECT_EQ(versionPacket->versions.size(), versions.size());
  EXPECT_EQ(versionPacket->versions, versions);
}

TEST_F(DecodeTest, DifferentCIDLength) {
  ConnectionId sourceConnectionId = getTestConnectionId();
  ConnectionId destinationConnectionId =
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4, 5, 6});
  std::vector<QuicVersion> versions{
      {static_cast<QuicVersion>(1234),
       static_cast<QuicVersion>(4321),
       static_cast<QuicVersion>(2341),
       static_cast<QuicVersion>(3412),
       static_cast<QuicVersion>(4123)}};
  auto packet = VersionNegotiationPacketBuilder(
                    sourceConnectionId, destinationConnectionId, versions)
                    .buildPacket();
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->sourceConnectionId, sourceConnectionId);
  EXPECT_EQ(versionPacket->destinationConnectionId, destinationConnectionId);
  EXPECT_EQ(versionPacket->versions.size(), versions.size());
  EXPECT_EQ(versionPacket->versions, versions);
}

TEST_F(DecodeTest, VersionNegotiationPacketBadPacketTest) {
  ConnectionId connId = getTestConnectionId();
  auto version = static_cast<QuicVersionType>(QuicVersion::MVFST);

  auto buf = folly::IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE<uint8_t>(kHeaderFormMask);
  appender.push(connId.data(), connId.size());
  appender.writeBE<QuicVersionType>(
      static_cast<QuicVersionType>(QuicVersion::VERSION_NEGOTIATION));
  appender.push((uint8_t*)&version, sizeof(QuicVersion) - 1);

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(buf));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_EQ(packet.regularPacket(), nullptr);

  buf = folly::IOBuf::create(0);
  packetQueue = bufToQueue(std::move(buf));
  packet = codec->parsePacket(packetQueue, ackStates);
  // Packet with empty versions
  EXPECT_EQ(packet.regularPacket(), nullptr);
}

TEST_F(DecodeTest, ValidAckFrame) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);
}

TEST_F(DecodeTest, AckEcnFrame) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true); // addEcnCounts
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrameWithECN(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res->asReadAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  // These values are hardcoded in the createAckFrame function
  EXPECT_EQ(ackFrame.ecnECT0Count, 1);
  EXPECT_EQ(ackFrame.ecnECT1Count, 2);
  EXPECT_EQ(ackFrame.ecnCECount, 3);
}

TEST_F(DecodeTest, AckExtendedFrameWithECN) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true, // addEcnCounts
      true); // useExtendedAck
  ContiguousReadCursor cursor(result->data(), result->length());
  auto ackFrameRes = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          std::nullopt,
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::ECN_COUNTS)));
  ASSERT_TRUE(ackFrameRes.has_value());
  auto ackFrame = *ackFrameRes;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  EXPECT_EQ(ackFrame.frameType, FrameType::ACK_EXTENDED);

  // These values are hardcoded in the createAckFrame function
  EXPECT_EQ(ackFrame.ecnECT0Count, 1);
  EXPECT_EQ(ackFrame.ecnECT1Count, 2);
  EXPECT_EQ(ackFrame.ecnCECount, 3);
}

TEST_F(DecodeTest, AckExtendedFrameWithNoFeatures) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      false, // addEcnCounts
      true); // useExtendedAck
  ContiguousReadCursor cursor(result->data(), result->length());
  auto ackFrameRes = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(ackFrameRes.has_value());
  auto ackFrame = *ackFrameRes;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  EXPECT_EQ(ackFrame.frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame.ecnECT0Count, 0);
  EXPECT_EQ(ackFrame.ecnECT1Count, 0);
  EXPECT_EQ(ackFrame.ecnCECount, 0);
}

TEST_F(DecodeTest, AckExtendedFrameThrowsWithUnsupportedFeatures) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true, // addEcnCounts
      true); // useExtendedAck
  ContiguousReadCursor cursor(result->data(), result->length());

  // Try to decode extended ack with ECN but we only support Timestamps
  auto decodeResult = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          std::nullopt,
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)));
  EXPECT_TRUE(decodeResult.hasError());
  EXPECT_EQ(
      decodeResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameLargestAckExceedsRange) {
  // An integer larger than the representable range of quic integer.
  QuicInteger largestAcked(std::numeric_limits<uint64_t>::max());
  QuicInteger ackDelay(10);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      true);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res;
  // it will interpret this as a 8 byte range with the max value.
  EXPECT_EQ(ackFrame.largestAcked, 4611686018427387903);
}

TEST_F(DecodeTest, AckFrameLargestAckInvalid) {
  // An integer larger than the representable range of quic integer.
  QuicInteger largestAcked(std::numeric_limits<uint64_t>::max());
  QuicInteger ackDelay(10);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame<uint8_t>(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      true);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameDelayEncodingInvalid) {
  QuicInteger largestAcked(1000);
  // Maximal representable value by quic integer.
  QuicInteger ackDelay(4611686018427387903);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      false,
      true);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameDelayExceedsRange) {
  QuicInteger largestAcked(1000);
  // Maximal representable value by quic integer.
  QuicInteger ackDelay(4611686018427387903);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameAdditionalBlocksUnderflow) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameAdditionalBlocksOverflow) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());
  ASSERT_FALSE(
      decodeAckFrame(
          cursor,
          makeHeader(),
          CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST))
          .hasError());
}

TEST_F(DecodeTest, AckFrameBlockCountExceedsRemainingBytes) {
  // Attacker-controlled additional-block count is the max QUIC varint but the
  // wire only carries firstAckBlockLength and no block bytes. The decoder must
  // reject the count up front ("Bad ack block count") rather than entering the
  // unbounded ackBlocks growth loop and only failing later ("Bad gap").
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(kEightByteLimit);
  QuicInteger firstAckBlockLength(10);

  auto result = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
  EXPECT_EQ(res.error().message, "Bad ack block count");
}

TEST_F(DecodeTest, AckFrameMissingFields) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result1 = createAckFrame(
      largestAcked,
      std::nullopt,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor1(result1->data(), result1->length());

  auto res = decodeAckFrame(
      cursor1,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result2 = createAckFrame(
      largestAcked, ackDelay, std::nullopt, firstAckBlockLength, ackBlocks);
  ContiguousReadCursor cursor2(result2->data(), result2->length());
  res = decodeAckFrame(
      cursor2,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result3 = createAckFrame(
      largestAcked, ackDelay, std::nullopt, firstAckBlockLength, ackBlocks);
  ContiguousReadCursor cursor3(result3->data(), result3->length());
  res = decodeAckFrame(
      cursor3,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result4 = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, std::nullopt, ackBlocks);
  ContiguousReadCursor cursor4(result4->data(), result4->length());
  res = decodeAckFrame(
      cursor4,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result5 = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength, {});
  ContiguousReadCursor cursor5(result5->data(), result5->length());
  res = decodeAckFrame(
      cursor5,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameFirstBlockLengthInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(2000);

  auto result = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockLengthInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(1000));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockGapInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(1000), QuicInteger(0));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockLengthZero) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(3);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(0));
  ackBlocks.emplace_back(QuicInteger(0), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  ContiguousReadCursor cursor(result->data(), result->length());

  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto readAckFrame = *res;
  EXPECT_EQ(readAckFrame.ackBlocks[0].endPacket, 1000);
  EXPECT_EQ(readAckFrame.ackBlocks[0].startPacket, 990);
  EXPECT_EQ(readAckFrame.ackBlocks[1].endPacket, 978);
  EXPECT_EQ(readAckFrame.ackBlocks[1].startPacket, 968);
  EXPECT_EQ(readAckFrame.ackBlocks[2].endPacket, 956);
  EXPECT_EQ(readAckFrame.ackBlocks[2].startPacket, 956);
  EXPECT_EQ(readAckFrame.ackBlocks[3].endPacket, 954);
  EXPECT_EQ(readAckFrame.ackBlocks[3].startPacket, 944);
}

TEST_F(DecodeTest, StreamDecodeSuccess) {
  QuicInteger streamId(10);
  QuicInteger offset(10);
  QuicInteger length(1);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, offset, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto decodedFrameRes = decodeStreamFrame(queue, streamType);
  ASSERT_TRUE(decodedFrameRes.has_value());
  auto decodedFrame = decodedFrameRes.value();
  EXPECT_EQ(decodedFrame.offset, 10);
  EXPECT_EQ(decodedFrame.data->computeChainDataLength(), 1);
  EXPECT_EQ(decodedFrame.streamId, 10);
  EXPECT_TRUE(decodedFrame.fin);
}

TEST_F(DecodeTest, StreamLengthStreamIdInvalid) {
  QuicInteger streamId(std::numeric_limits<uint64_t>::max());
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame<uint8_t>(
      streamId, std::nullopt, std::nullopt, nullptr, true);
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamOffsetNotPresent) {
  QuicInteger streamId(10);
  QuicInteger length(1);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, std::nullopt, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamIncorrectDataLength) {
  QuicInteger streamId(10);
  QuicInteger offset(10);
  QuicInteger length(10);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, offset, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamNoRemainingData) {
  // assume after parsing the frame type (stream frame), there was no remaining
  // data
  quic::BufPtr buf = folly::IOBuf::copyBuffer("test");
  BufQueue queue(std::move(buf));
  queue.trimStartAtMost(4);

  const auto streamType =
      StreamTypeField(static_cast<uint8_t>(FrameType::STREAM));
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, DatagramNoRemainingData) {
  // assume after parsing the frame type (datagram frame), there was no
  // remaining data
  quic::BufPtr buf = folly::IOBuf::copyBuffer("test");
  BufQueue queue(std::move(buf));
  queue.trimStartAtMost(4);

  // invalid len
  auto result = decodeDatagramFrame(queue, true);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, DatagramLenPreservesEncodedSizeAcrossVarintBoundaries) {
  for (const size_t payloadSize : {63, 64, 16383, 16384}) {
    SCOPED_TRACE(payloadSize);
    auto buf = folly::IOBuf::create(0);
    BufAppender appender(buf.get(), payloadSize + sizeof(uint64_t));
    auto appenderOp = [&](auto val) { appender.writeBE(val); };
    const QuicInteger encodedLength(payloadSize);
    encodedLength.encode(appenderOp);
    const std::string payload(payloadSize, 'd');
    appender.push(
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    buf->coalesce();
    BufQueue queue(std::move(buf));

    auto result = decodeDatagramFrame(queue, true);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, payloadSize);
    EXPECT_EQ(
        *result->encodedSize,
        kDatagramFrameTypeSize + encodedLength.getSize().value() + payloadSize);
  }
}

TEST_F(DecodeTest, DatagramWithoutLengthPreservesEncodedSize) {
  constexpr size_t kPayloadSize = 64;
  BufQueue queue(folly::IOBuf::copyBuffer(std::string(kPayloadSize, 'd')));

  auto result = decodeDatagramFrame(queue, false);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->length, kPayloadSize);
  EXPECT_EQ(*result->encodedSize, kDatagramFrameTypeSize + kPayloadSize);
}

TEST_F(DecodeTest, DatagramPreservesActualFrameTypeWidth) {
  constexpr size_t kPayloadSize = 64;
  for (const auto frameType : {FrameType::DATAGRAM, FrameType::DATAGRAM_LEN}) {
    for (const size_t frameTypeSize : {1, 2, 4, 8}) {
      SCOPED_TRACE(static_cast<uint64_t>(frameType));
      SCOPED_TRACE(frameTypeSize);
      auto buf = folly::IOBuf::create(0);
      BufAppender appender(buf.get(), kPayloadSize + 16);
      const auto type = static_cast<uint64_t>(frameType);
      switch (frameTypeSize) {
        case 1:
          appender.writeBE<uint8_t>(type);
          break;
        case 2:
          appender.writeBE<uint16_t>((uint16_t{1} << 14) | type);
          break;
        case 4:
          appender.writeBE<uint32_t>((uint32_t{2} << 30) | type);
          break;
        case 8:
          appender.writeBE<uint64_t>((uint64_t{3} << 62) | type);
          break;
      }
      if (frameType == FrameType::DATAGRAM_LEN) {
        auto appenderOp = [&](auto value) { appender.writeBE(value); };
        QuicInteger(kPayloadSize).encode(appenderOp);
      }
      const std::string payload(kPayloadSize, 'd');
      appender.push(
          reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
      buf->coalesce();
      BufQueue queue(std::move(buf));

      auto result = parseFrame(
          queue,
          makeHeader(),
          CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));

      ASSERT_TRUE(result.has_value());
      const auto* datagram = result->asDatagramFrame();
      ASSERT_NE(datagram, nullptr);
      ASSERT_TRUE(datagram->encodedSize.has_value());
      const auto lengthSize = frameType == FrameType::DATAGRAM_LEN ? 2 : 0;
      EXPECT_EQ(
          *datagram->encodedSize, frameTypeSize + lengthSize + kPayloadSize);
    }
  }
}

std::unique_ptr<folly::IOBuf> CreateMaxStreamsIdFrame(
    unsigned long long maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = folly::IOBuf::create(sizeof(QuicInteger));
  BufAppender wcursor(buf.get(), sizeof(QuicInteger));
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  QuicInteger maxStreamsIdVal(maxStreamsId);
  maxStreamsIdVal.encode(appenderOp);
  return buf;
}

// Uni and BiDi have same max limits so uses single 'frame' to check both.
void MaxStreamsIdCheckSuccess(StreamId maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = CreateMaxStreamsIdFrame(maxStreamsId);

  ContiguousReadCursor cursorBiDi(buf->data(), buf->length());
  auto maxStreamsBiDiFrameRes = decodeBiDiMaxStreamsFrame(cursorBiDi);
  ASSERT_TRUE(maxStreamsBiDiFrameRes.has_value());
  EXPECT_EQ(maxStreamsBiDiFrameRes->maxStreams, maxStreamsId);

  ContiguousReadCursor cursorUni(buf->data(), buf->length());
  auto maxStreamsUniFrameRes = decodeUniMaxStreamsFrame(cursorUni);
  ASSERT_TRUE(maxStreamsUniFrameRes.has_value());
  EXPECT_EQ(maxStreamsUniFrameRes->maxStreams, maxStreamsId);
}

// Uni and BiDi have same max limits so uses single 'frame' to check both.
void MaxStreamsIdCheckInvalid(StreamId maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = CreateMaxStreamsIdFrame(maxStreamsId);

  ContiguousReadCursor cursorBiDi(buf->data(), buf->length());
  auto bidiResult = decodeBiDiMaxStreamsFrame(cursorBiDi);
  EXPECT_TRUE(bidiResult.hasError());
  EXPECT_EQ(bidiResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  ContiguousReadCursor cursorUni(buf->data(), buf->length());
  auto uniResult = decodeUniMaxStreamsFrame(cursorUni);
  EXPECT_TRUE(uniResult.hasError());
  EXPECT_EQ(uniResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, MaxStreamsIdChecks) {
  MaxStreamsIdCheckSuccess(0);
  MaxStreamsIdCheckSuccess(123);
  MaxStreamsIdCheckSuccess(kMaxMaxStreams);

  MaxStreamsIdCheckInvalid(kMaxMaxStreams + 1);
  MaxStreamsIdCheckInvalid(kMaxMaxStreams + 123);
  MaxStreamsIdCheckInvalid(kMaxStreamId - 1);
}

TEST_F(DecodeTest, CryptoDecodeSuccess) {
  QuicInteger offset(10);
  QuicInteger length(1);
  auto cryptoFrame =
      createCryptoFrame(offset, length, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(cryptoFrame->data(), cryptoFrame->length());
  auto decodedFrame = decodeCryptoFrame(cursor);
  EXPECT_EQ(decodedFrame->offset, 10);
  EXPECT_EQ(decodedFrame->data->computeChainDataLength(), 1);
}

TEST_F(DecodeTest, CryptoOffsetNotPresent) {
  QuicInteger length(1);
  auto cryptoFrame =
      createCryptoFrame(std::nullopt, length, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(cryptoFrame->data(), cryptoFrame->length());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, CryptoLengthNotPresent) {
  QuicInteger offset(0);
  auto cryptoFrame = createCryptoFrame(offset, std::nullopt, nullptr);
  ContiguousReadCursor cursor(cryptoFrame->data(), cryptoFrame->length());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, CryptoIncorrectDataLength) {
  QuicInteger offset(10);
  QuicInteger length(10);
  auto cryptoFrame =
      createCryptoFrame(offset, length, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(cryptoFrame->data(), cryptoFrame->length());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, PaddingFrameTest) {
  auto buf = folly::IOBuf::create(sizeof(UnderlyingFrameType));
  buf->append(1);
  memset(buf->writableData(), 0, 1);

  ContiguousReadCursor cursor(buf->data(), buf->length());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
}

TEST_F(DecodeTest, PaddingFrameNoBytesTest) {
  auto buf = folly::IOBuf::create(sizeof(UnderlyingFrameType));

  ContiguousReadCursor cursor(buf->data(), buf->length());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
}

class TimestampFrameDecodeTest : public DecodeTest,
                                 public WithParamInterface<uint8_t> {};

TEST_P(TimestampFrameDecodeTest, AppliesNegotiatedExponent) {
  auto buf = folly::IOBuf::create(0);
  BufAppender appender(buf.get(), 10);
  QuicInteger timestamp(1234);
  timestamp.encode([&](auto val) { appender.writeBE(val); });
  buf->coalesce();

  ContiguousReadCursor cursor(buf->data(), buf->length());
  CodecParameters codecParams(kDefaultAckDelayExponent, QuicVersion::MVFST);
  codecParams.peerTimestampFrameTimestampExponent = GetParam();
  auto result = decodeTimestampFrame(cursor, codecParams);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->timestamp, uint64_t{1234} << GetParam());
  EXPECT_EQ(cursor.remaining(), 0);
}

INSTANTIATE_TEST_SUITE_P(
    TimestampExponent,
    TimestampFrameDecodeTest,
    Values(0, 2, kMaxTimestampFrameTimestampExponent),
    [](const TestParamInfo<uint8_t>& info) {
      return "Exponent" + std::to_string(info.param);
    });

TEST_F(DecodeTest, TimestampFrameParseSuccess) {
  auto buf = folly::IOBuf::create(0);
  BufAppender appender(buf.get(), 10);
  QuicInteger frameType(static_cast<uint64_t>(FrameType::TIMESTAMP));
  QuicInteger timestamp(5678);
  frameType.encode([&](auto val) { appender.writeBE(val); });
  timestamp.encode([&](auto val) { appender.writeBE(val); });
  buf->coalesce();

  BufQueue queue(std::move(buf));
  auto result = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(result.has_value());
  auto frame = result->asTimestampFrame();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->timestamp, 5678);
  EXPECT_EQ(queue.chainLength(), 0);
}

TEST_F(DecodeTest, DecodeMultiplePaddingInterleavedTest) {
  auto buf = folly::IOBuf::create(20);
  buf->append(10);
  memset(buf->writableData(), 0, 10);
  buf->append(1);
  // something which is not padding
  memset(buf->writableData() + 10, 5, 1);

  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto result = decodePaddingFrame(cursor);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->numFrames, 11);
  EXPECT_EQ(cursor.remaining(), 1);
}

TEST_F(DecodeTest, DecodeMultiplePaddingTest) {
  auto buf = folly::IOBuf::create(20);
  buf->append(10);
  memset(buf->writableData(), 0, 10);

  ContiguousReadCursor cursor(buf->data(), buf->length());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
  EXPECT_EQ(cursor.remaining(), 0);
}

class PaddingRunDecodeTest : public DecodeTest,
                             public WithParamInterface<size_t> {};

TEST_P(PaddingRunDecodeTest, ConsumesRunBeforePing) {
  const auto paddingCount = GetParam();
  std::string bytes(paddingCount, '\0');
  bytes.push_back('\x01');
  BufQueue queue(folly::IOBuf::copyBuffer(bytes));
  const PacketHeader header(makeHeader());
  const CodecParameters params(kDefaultAckDelayExponent, QuicVersion::MVFST);
  auto result = parseFrame(queue, header, params);
  ASSERT_TRUE(result.has_value());
  ASSERT_NE(result->asPaddingFrame(), nullptr);
  EXPECT_EQ(
      result->asPaddingFrame()->numFrames, static_cast<uint16_t>(paddingCount));
  EXPECT_EQ(queue.chainLength(), 1);
  EXPECT_EQ(queue.front()->data()[0], 0x01);

  auto ping = parseFrame(queue, header, params);
  ASSERT_TRUE(ping.has_value());
  EXPECT_NE(ping->asPingFrame(), nullptr);
  EXPECT_EQ(queue.chainLength(), 0);
}

INSTANTIATE_TEST_SUITE_P(
    PaddingRuns,
    PaddingRunDecodeTest,
    Values(1, 16, 1200, 65535, 65536));

TEST_F(DecodeTest, PaddingRunCountsAcrossFrames) {
  // A two-byte PADDING type separates byte runs that share one decoded frame.
  const std::string bytes("\x00\x00\x40\x00\x00\x00\x01\x00\x00\x00", 10);
  auto result = decodeRegularPacket(
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST),
      folly::IOBuf::copyBuffer(bytes));
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->frames.size(), 3);
  ASSERT_NE(result->frames[0].asPaddingFrame(), nullptr);
  EXPECT_EQ(result->frames[0].asPaddingFrame()->numFrames, 5);
  EXPECT_NE(result->frames[1].asPingFrame(), nullptr);
  ASSERT_NE(result->frames[2].asPaddingFrame(), nullptr);
  EXPECT_EQ(result->frames[2].asPaddingFrame()->numFrames, 3);
}

class NewConnectionIdDecodeTest : public DecodeTest,
                                  public WithParamInterface<QuicVersion> {};

TEST_P(NewConnectionIdDecodeTest, ValidatesLength) {
  StatelessResetToken token;
  token.fill(0x5a);
  for (const uint8_t length : {0, 1, 20, 21}) {
    SCOPED_TRACE(static_cast<unsigned>(length));
    std::string bytes("\x18\x01\x00", 3);
    bytes.push_back(static_cast<char>(length));
    bytes.append(length, '\x42');
    bytes.append(token.size(), '\x5a');
    BufQueue queue(folly::IOBuf::copyBuffer(bytes));
    auto result = parseFrame(
        queue,
        makeHeader(),
        CodecParameters(kDefaultAckDelayExponent, GetParam()));
    if (length == 0 || length > kMaxConnectionIdSize) {
      EXPECT_TRUE(result.hasError());
      if (result.hasError()) {
        EXPECT_EQ(
            result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
      }
      continue;
    }
    ASSERT_TRUE(result.has_value());
    ASSERT_NE(result->asQuicSimpleFrame(), nullptr);
    auto frame = result->asQuicSimpleFrame()->asNewConnectionIdFrame();
    ASSERT_NE(frame, nullptr);
    EXPECT_EQ(frame->sequenceNumber, 1);
    EXPECT_EQ(frame->retirePriorTo, 0);
    EXPECT_EQ(frame->connectionId.size(), length);
    EXPECT_EQ(frame->token, token);
    EXPECT_EQ(queue.chainLength(), 0);
  }
}

TEST_P(NewConnectionIdDecodeTest, RejectsTruncatedIdAndToken) {
  for (const auto& bytes :
       {std::string("\x18\x01\x00\x04\x42\x42", 6),
        std::string("\x18\x01\x00\x04", 4) + std::string(4, '\x42') +
            std::string(15, '\x5a')}) {
    SCOPED_TRACE(bytes.size());
    BufQueue queue(folly::IOBuf::copyBuffer(bytes));
    auto result = parseFrame(
        queue,
        makeHeader(),
        CodecParameters(kDefaultAckDelayExponent, GetParam()));
    ASSERT_TRUE(result.hasError());
    EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
  }
}

INSTANTIATE_TEST_SUITE_P(
    Versions,
    NewConnectionIdDecodeTest,
    Values(QuicVersion::QUIC_V1, QuicVersion::MVFST));

std::unique_ptr<folly::IOBuf> createNewTokenFrame(
    Optional<QuicInteger> tokenLength = std::nullopt,
    BufPtr token = nullptr) {
  std::unique_ptr<folly::IOBuf> newTokenFrame = folly::IOBuf::create(0);
  BufAppender wcursor(newTokenFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (tokenLength) {
    tokenLength->encode(appenderOp);
  }
  if (token) {
    wcursor.insert(std::move(token));
  }
  newTokenFrame->coalesce();
  return newTokenFrame;
}

TEST_F(DecodeTest, NewTokenDecodeSuccess) {
  QuicInteger length(1);
  auto newTokenFrame =
      createNewTokenFrame(length, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(newTokenFrame->data(), newTokenFrame->length());
  auto decodedFrame = decodeNewTokenFrame(cursor);
  EXPECT_EQ(decodedFrame->token->computeChainDataLength(), 1);
}

TEST_F(DecodeTest, NewTokenLengthNotPresent) {
  auto newTokenFrame =
      createNewTokenFrame(std::nullopt, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(newTokenFrame->data(), newTokenFrame->length());
  auto result = decodeNewTokenFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, NewTokenIncorrectDataLength) {
  QuicInteger length(10);
  auto newTokenFrame =
      createNewTokenFrame(length, folly::IOBuf::copyBuffer("a"));
  ContiguousReadCursor cursor(newTokenFrame->data(), newTokenFrame->length());
  auto result = decodeNewTokenFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, ParsePlaintextNewToken) {
  folly::IPAddress clientIp("127.0.0.1");
  uint64_t timestampInMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  NewToken newToken(clientIp, timestampInMs);
  BufPtr plaintextNewToken = newToken.getPlaintextToken();

  ContiguousReadCursor cursor(
      plaintextNewToken->data(), plaintextNewToken->length());

  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  EXPECT_TRUE(parseResult.has_value());

  EXPECT_EQ(parseResult.value(), timestampInMs);
}

TEST_F(DecodeTest, ParsePlaintextRetryToken) {
  ConnectionId odcid = getTestConnectionId();
  folly::IPAddress clientIp("109.115.3.49");
  uint16_t clientPort = 42069;
  uint64_t timestampInMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  RetryToken retryToken(odcid, clientIp, clientPort, timestampInMs);
  BufPtr plaintextRetryToken = retryToken.getPlaintextToken();

  ContiguousReadCursor cursor(
      plaintextRetryToken->data(), plaintextRetryToken->length());

  /**
   * Now we continue with the parsing logic here.
   */
  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  EXPECT_TRUE(parseResult.has_value());

  EXPECT_EQ(parseResult.value(), timestampInMs);
}

TEST_F(DecodeTest, AckFrequencyFrameDecodeValid) {
  QuicInteger sequenceNumber(1);
  QuicInteger packetTolerance(100);
  QuicInteger maxAckDelay(100000); // 100 ms
  QuicInteger reorderThreshold(50);
  auto ackFrequencyFrame = createAckFrequencyFrame(
      sequenceNumber, packetTolerance, maxAckDelay, reorderThreshold);
  ASSERT_NE(ackFrequencyFrame, nullptr);

  ContiguousReadCursor cursor(
      ackFrequencyFrame->data(), ackFrequencyFrame->length());
  auto res = decodeAckFrequencyFrame(cursor);
  EXPECT_TRUE(res.has_value());
  auto decodedFrame = *res->asAckFrequencyFrame();
  EXPECT_EQ(decodedFrame.sequenceNumber, 1);
  EXPECT_EQ(decodedFrame.packetTolerance, 100);
  EXPECT_EQ(decodedFrame.updateMaxAckDelay, 100000);
  EXPECT_EQ(decodedFrame.reorderThreshold, 50);
}

TEST_F(DecodeTest, AckFrequencyFrameDecodeInvalidReserved) {
  QuicInteger sequenceNumber(1);
  QuicInteger packetTolerance(100);
  QuicInteger maxAckDelay(100000); // 100 ms
  auto ackFrequencyFrame = createAckFrequencyFrame(
      sequenceNumber, packetTolerance, maxAckDelay, std::nullopt);
  ASSERT_NE(ackFrequencyFrame, nullptr);

  ContiguousReadCursor cursor(
      ackFrequencyFrame->data(), ackFrequencyFrame->length());
  auto res = decodeAckFrequencyFrame(cursor);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, RstStreamFrame) {
  auto buf = createRstStreamFrame(0, 0, 10);
  BufQueue queue(std::move(buf));
  auto frame = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto rstStreamFrame = frame->asRstStreamFrame();
  EXPECT_EQ(rstStreamFrame->streamId, 0);
  EXPECT_EQ(rstStreamFrame->errorCode, 0);
  EXPECT_EQ(rstStreamFrame->finalSize, 10);
  EXPECT_FALSE(rstStreamFrame->reliableSize.has_value());
}

TEST_F(DecodeTest, RstStreamAtFrame) {
  auto buf = createRstStreamFrame(0, 0, 10, 9);
  BufQueue queue(std::move(buf));
  auto frame = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto rstStreamFrameRes = frame->asRstStreamFrame();
  ASSERT_TRUE(rstStreamFrameRes);
  auto rstStreamFrame = *rstStreamFrameRes;
  EXPECT_EQ(rstStreamFrame.streamId, 0);
  EXPECT_EQ(rstStreamFrame.errorCode, 0);
  EXPECT_EQ(rstStreamFrame.finalSize, 10);
  EXPECT_EQ(*rstStreamFrame.reliableSize, 9);
}

TEST_F(DecodeTest, RstStreamAtFrameRelSizeGreaterThanOffset) {
  auto buf = createRstStreamFrame(0, 0, 10, 11);
  BufQueue queue(std::move(buf));
  auto result = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, RstStreamAtTruncated) {
  auto buf = createRstStreamFrame(0, 0, 10, 9);
  buf->coalesce();
  buf->trimEnd(1);
  BufQueue queue(std::move(buf));
  auto result = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

// draft-ietf-quic-receive-ts-02 decoder tests. The hand-built wire bytes
// avoid any dependency on the encoder; the helper writes everything after
// the frame-type varint:
//   - base ACK: largestAcked, ackDelay, ackBlockCount, firstAckBlockLength,
//     additional blocks
//   - [optional ECN counts for `_ECN` variant]
//   - timestamp range count
//   - per range: deltaLargestAcknowledged, timestampDeltaCount, deltas

namespace {

struct Draft02NormalizedTimestampRange {
  QuicInteger deltaLargestAcknowledged;
  std::vector<QuicInteger> deltas;
};

// Builds the post-type bytes of a draft-02 ACK_RECEIVE_TIMESTAMPS frame.
// Caller writes the frame-type varint or passes the buffer to a function
// that already knows the frame type.
std::unique_ptr<folly::IOBuf> createDraft02AckFrame(
    QuicInteger largestAcked,
    QuicInteger ackDelay,
    QuicInteger numAdditionalBlocks,
    QuicInteger firstAckBlockLength,
    const std::vector<NormalizedAckBlock>& ackBlocks,
    bool addEcnCounts,
    const std::vector<Draft02NormalizedTimestampRange>& timestampRanges) {
  auto buf = folly::IOBuf::create(0);
  BufAppender wcursor(buf.get(), 32);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };

  largestAcked.encode(appenderOp);
  ackDelay.encode(appenderOp);
  numAdditionalBlocks.encode(appenderOp);
  firstAckBlockLength.encode(appenderOp);
  for (const auto& b : ackBlocks) {
    b.gap.encode(appenderOp);
    b.blockLen.encode(appenderOp);
  }
  if (addEcnCounts) {
    QuicInteger(1).encode(appenderOp); // ECT-0
    QuicInteger(2).encode(appenderOp); // ECT-1
    QuicInteger(3).encode(appenderOp); // CE
  }
  QuicInteger rangeCount(timestampRanges.size());
  rangeCount.encode(appenderOp);
  for (const auto& range : timestampRanges) {
    range.deltaLargestAcknowledged.encode(appenderOp);
    QuicInteger(range.deltas.size()).encode(appenderOp);
    for (const auto& delta : range.deltas) {
      delta.encode(appenderOp);
    }
  }
  buf->coalesce();
  return buf;
}

// Build CodecParameters with a local advertised draft-02 config.
CodecParameters draft02Params(
    uint64_t advertisedMax = 10,
    uint8_t advertisedExponent = 0) {
  return CodecParameters(
      kDefaultAckDelayExponent,
      QuicVersion::MVFST,
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = advertisedMax,
          .receiveTimestampsExponent = advertisedExponent},
      /*extendedAckFeaturesIn=*/0);
}

} // namespace

TEST_F(DecodeTest, Draft02AckZeroRangesIsValid) {
  auto buf = createDraft02AckFrame(
      QuicInteger(1000),
      QuicInteger(100),
      QuicInteger(0), // numAdditionalBlocks
      QuicInteger(10), // firstAckBlockLength
      /*ackBlocks=*/{},
      /*addEcnCounts=*/false,
      /*timestampRanges=*/{});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  EXPECT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 0);
  EXPECT_EQ(frame.timestampsVersion, AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(frame.frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
}

TEST_F(DecodeTest, Draft02AckBasicSingleRange) {
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas = {QuicInteger(380), QuicInteger(10), QuicInteger(10)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(4), // largestAcked - 4 = 96 ... 100
      {},
      /*addEcnCounts=*/false,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 1);
  const auto& decodedRange = frame.draft02RecvdPacketsTimestampRanges[0];
  EXPECT_EQ(decodedRange.deltaLargestAcknowledged, 0);
  EXPECT_EQ(decodedRange.timestamp_delta_count, 3);
  EXPECT_EQ(decodedRange.deltas, std::vector<uint64_t>({380, 10, 10}));
}

TEST_F(DecodeTest, Draft02AckMultipleRanges) {
  std::vector<Draft02NormalizedTimestampRange> ranges{
      {.deltaLargestAcknowledged = QuicInteger(0),
       .deltas = {QuicInteger(1), QuicInteger(2)}},
      {.deltaLargestAcknowledged = QuicInteger(5), .deltas = {QuicInteger(3)}},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(20),
      {},
      false,
      ranges);
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 2);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltaLargestAcknowledged, 0);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[1].deltaLargestAcknowledged, 5);
  EXPECT_EQ(frame.draft02RecvdPacketsTimestampRanges[1].deltas.size(), 1);
}

TEST_F(DecodeTest, Draft02AckEcnVariantDecodesEcnBeforeTimestamps) {
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas = {QuicInteger(100)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      /*addEcnCounts=*/true,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  EXPECT_EQ(frame.ecnECT0Count, 1);
  EXPECT_EQ(frame.ecnECT1Count, 2);
  EXPECT_EQ(frame.ecnCECount, 3);
  EXPECT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(frame.frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
}

TEST_F(DecodeTest, Draft02AckExponentDefaultZeroWhenNoLocalConfig) {
  // No local AckReceiveTimestampsConfig: draft-02 default exponent is 0, not
  // the legacy mvfst default of 3.
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas = {QuicInteger(7)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      false,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(frame.draft02RecvdPacketsTimestampRanges[0].deltas[0], 7);
}

TEST_F(DecodeTest, Draft02AckExponentScalingApplied) {
  // Local advertised exponent = 3, peer encodes delta as 5, decoded as 40us.
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas = {QuicInteger(5)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      false,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/3),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  const auto& frame = *res->asReadAckFrame();
  EXPECT_EQ(frame.draft02RecvdPacketsTimestampRanges[0].deltas[0], 40);
}

TEST_F(DecodeTest, Draft02AckOverLimitReturnsFrameEncodingError) {
  // Advertised max = 3; frame carries 4 deltas total, must error.
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas =
          {QuicInteger(1), QuicInteger(2), QuicInteger(3), QuicInteger(4)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      false,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/3, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, Draft02AckSetsTimestampsVersionDraftIetf02) {
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      false,
      {});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(
      res->asReadAckFrame()->timestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);
}

// `ACK_EXTENDED` with the `RECEIVE_TIMESTAMPS` feature bit must set
// `ReadAckFrame::timestampsVersion = LegacyMvfst` so consumers dispatch on
// one source of truth regardless of which legacy carrier (`0xB0` or `0xB1`
// with feature bit) delivered the timestamps.
TEST_F(
    DecodeTest,
    AckExtendedWithReceiveTimestampsFeatureSetsLegacyMvfstVersion) {
  std::unique_ptr<folly::IOBuf> buf = folly::IOBuf::create(0);
  BufAppender wcursor(buf.get(), 64);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  QuicInteger(100).encode(appenderOp); // largestAcked
  QuicInteger(0).encode(appenderOp); // ackDelay
  QuicInteger(0).encode(appenderOp); // numAdditionalBlocks
  QuicInteger(0).encode(appenderOp); // firstAckBlockLength
  // Extended-ack feature bits: RECEIVE_TIMESTAMPS only (no ECN).
  const auto features = static_cast<ExtendedAckFeatureMaskType>(
      ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  QuicInteger(features).encode(appenderOp);
  QuicInteger(100).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  buf->coalesce();

  ContiguousReadCursor cursor(buf->data(), buf->length());
  CodecParameters params(
      kDefaultAckDelayExponent,
      QuicVersion::MVFST,
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 0},
      /*extendedAckFeaturesIn=*/features);
  auto res = decodeAckExtendedFrame(cursor, makeHeader(), params);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->timestampsVersion, AckReceiveTimestampsVersion::LegacyMvfst);
}

// A peer-controlled giant `Timestamp Range Count` must not trigger a large
// pre-allocation before per-range parsing surfaces the error. A count of
// 2^61 with no range bytes must return FRAME_ENCODING_ERROR fast.
TEST_F(DecodeTest, Draft02AckOverLargeRangeCountFailsFastWithoutOOM) {
  auto buf = folly::IOBuf::create(0);
  BufAppender wcursor(buf.get(), 32);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  QuicInteger(100).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  // Huge range count, no range bytes follow.
  QuicInteger(uint64_t{1} << 61).encode(appenderOp);
  buf->coalesce();

  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

// A range with `timestamp_delta_count == 0` consumes ~32 bytes per
// materialized range vs ~2 wire bytes. A malformed peer could push
// allocation past `kMaxReceiveTimestampsHardLimit` without the over-limit
// check firing (it keys on total deltas, not range count). Skip empty
// ranges instead of storing them. The spec's "0 or more receive timestamps"
// allowance applies to the total count (covered by
// `Draft02AckZeroRangesIsValid`), not per-range.
TEST_F(DecodeTest, Draft02AckEmptyRangeSkipped) {
  // Single range with 0 deltas.
  std::vector<Draft02NormalizedTimestampRange> ranges{
      {.deltaLargestAcknowledged = QuicInteger(0), .deltas = {}},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      /*addEcnCounts=*/false,
      ranges);
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  EXPECT_TRUE(cursor.isAtEnd());
  EXPECT_TRUE(
      res->asReadAckFrame()->draft02RecvdPacketsTimestampRanges.empty());
}

// A frame declaring many empty ranges must skip them
// rather than materializing all of them, guarding against memory
// amplification.
TEST_F(DecodeTest, Draft02AckManyEmptyRangesSkipped) {
  std::vector<Draft02NormalizedTimestampRange> ranges;
  ranges.reserve(1001);
  for (int i = 0; i < 1000; ++i) {
    ranges.push_back(
        {.deltaLargestAcknowledged = QuicInteger(0), .deltas = {}});
  }
  ranges.push_back(
      {.deltaLargestAcknowledged = QuicInteger(5), .deltas = {QuicInteger(7)}});
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      /*addEcnCounts=*/false,
      ranges);
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.has_value());
  EXPECT_TRUE(cursor.isAtEnd());
  const auto& frame = *res->asReadAckFrame();
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltaLargestAcknowledged, 5);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{7}));
}

// The over-limit check sums delta counts across ranges. Two ranges of 2
// deltas each (total 4) against advertised max 3 must fail with
// FRAME_ENCODING_ERROR.
TEST_F(DecodeTest, Draft02AckCrossRangeOverLimitReturnsFrameEncodingError) {
  std::vector<Draft02NormalizedTimestampRange> ranges{
      {.deltaLargestAcknowledged = QuicInteger(0),
       .deltas = {QuicInteger(1), QuicInteger(2)}},
      {.deltaLargestAcknowledged = QuicInteger(5),
       .deltas = {QuicInteger(3), QuicInteger(4)}},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      /*addEcnCounts=*/false,
      ranges);
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeHeader(),
      draft02Params(/*advertisedMax=*/3, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

// draft-ietf-quic-receive-ts-02 ACK frames are 1-RTT only. A draft-02 frame
// in a non-AppData packet-number space (Initial/Handshake) must be rejected
// with FRAME_ENCODING_ERROR rather than silently decoded as a plain ACK.
TEST_F(DecodeTest, Draft02AckInNonAppDataSpaceRejected) {
  Draft02NormalizedTimestampRange range{
      .deltaLargestAcknowledged = QuicInteger(0),
      .deltas = {QuicInteger(100)},
  };
  auto buf = createDraft02AckFrame(
      QuicInteger(100),
      QuicInteger(0),
      QuicInteger(0),
      QuicInteger(0),
      {},
      /*addEcnCounts=*/false,
      {range});
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameDraft02WithReceiveTimestamps(
      cursor,
      makeLongHeader(LongHeader::Types::Initial),
      draft02Params(/*advertisedMax=*/10, /*advertisedExponent=*/0),
      FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  ASSERT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, LegacyAckSetsTimestampsVersionLegacyMvfst) {
  std::unique_ptr<folly::IOBuf> buf = folly::IOBuf::create(0);
  BufAppender wcursor(buf.get(), 32);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  QuicInteger(100).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  // Legacy timestamp prefix: latest packet number + latest time + range count.
  QuicInteger(100).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  QuicInteger(0).encode(appenderOp);
  buf->coalesce();
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckFrameWithReceivedTimestamps(
      cursor, makeHeader(), draft02Params(), FrameType::ACK_RECEIVE_TIMESTAMPS);
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(
      res->asReadAckFrame()->timestampsVersion,
      AckReceiveTimestampsVersion::LegacyMvfst);
}

// Byte-exact wire vectors, matching QuicWriteCodecTest. The draft-02 vectors
// are the examples in draft-ietf-quic-receive-ts-03 Section 8 (exponent 0).
// The legacy mvfst and ACK_EXTENDED vectors pin those formats.
namespace {

ReadAckFrame parseWireBytesAsAck(
    const std::vector<uint8_t>& bytes,
    const CodecParameters& params) {
  BufQueue queue(folly::IOBuf::copyBuffer(bytes.data(), bytes.size()));
  const PacketHeader header(makeHeader());
  auto result = parseFrame(queue, header, params);
  if (!result.has_value() || !result->asReadAckFrame()) {
    ADD_FAILURE() << "Failed to parse an ACK frame from the wire bytes";
    return ReadAckFrame{};
  }
  EXPECT_EQ(queue.chainLength(), 0);
  return *result->asReadAckFrame();
}

CodecParameters legacyWireVectorParams() {
  return CodecParameters(
      kDefaultAckDelayExponent,
      QuicVersion::MVFST,
      AckReceiveTimestampsConfig{
          .maxReceiveTimestampsPerAck = 10, .receiveTimestampsExponent = 0},
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS) |
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS));
}

} // namespace

TEST_F(DecodeTest, Draft02AckSpecExampleWireBytes) {
  const std::vector<uint8_t> bytes = {
      0x83, 0x17, 0x83, 0x07, // Type
      0x40, 0x64, 0x00, 0x01, 0x04, 0x03, 0x04, // ACK fields
      0x02, // Timestamp Range Count
      0x00, 0x05, 0x41, 0x7c, 0x0a, 0x0a, 0x05, 0x05, // Range 1
      0x09, 0x05, 0x14, 0x0a, 0x0a, 0x05, 0x05, // Range 2
  };

  auto frame = parseWireBytesAsAck(bytes, draft02Params());

  EXPECT_EQ(frame.frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02);
  EXPECT_EQ(frame.largestAcked, 100);
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 2);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltaLargestAcknowledged, 0);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{380, 10, 10, 5, 5}));
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[1].deltaLargestAcknowledged, 9);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[1].deltas,
      (std::vector<uint64_t>{20, 10, 10, 5, 5}));
}

TEST_F(DecodeTest, Draft02AckSpecOutOfOrderExampleWireBytes) {
  const std::vector<uint8_t> bytes = {
      0x83, 0x17, 0x83, 0x07, // Type
      0x40, 0x64, 0x00, 0x00, 0x0d, // ACK fields
      0x03, // Timestamp Range Count
      0x05, 0x04, 0x41, 0x8b, 0x01, 0x02, 0x02, // Range 1
      0x00, 0x05, 0x0a, 0x0a, 0x0a, 0x05, 0x05, // Range 2
      0x09, 0x05, 0x14, 0x0a, 0x0a, 0x05, 0x05, // Range 3
  };

  auto frame = parseWireBytesAsAck(bytes, draft02Params(/*advertisedMax=*/14));

  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 3);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltaLargestAcknowledged, 5);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{395, 1, 2, 2}));
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[1].deltaLargestAcknowledged, 0);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[1].deltas,
      (std::vector<uint64_t>{10, 10, 10, 5, 5}));
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[2].deltaLargestAcknowledged, 9);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[2].deltas,
      (std::vector<uint64_t>{20, 10, 10, 5, 5}));
}

TEST_F(DecodeTest, Draft02EcnAckWireBytes) {
  const std::vector<uint8_t> bytes = {
      0x83, 0x17, 0x83, 0x08, // Type
      0x40, 0x64, 0x00, 0x00, 0x04, // ACK fields
      0x01, 0x02, 0x03, // ECN Counts
      0x01, // Timestamp Range Count
      0x00, 0x05, 0x40, 0x8c, 0x0a, 0x0a, 0x0a, 0x0a, // Range 1
  };

  auto frame = parseWireBytesAsAck(bytes, draft02Params());

  EXPECT_EQ(frame.frameType, FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);
  EXPECT_EQ(frame.ecnECT0Count, 1);
  EXPECT_EQ(frame.ecnECT1Count, 2);
  EXPECT_EQ(frame.ecnCECount, 3);
  ASSERT_EQ(frame.draft02RecvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(
      frame.draft02RecvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{140, 10, 10, 10, 10}));
}

TEST_F(DecodeTest, LegacyAckReceiveTimestampsWireBytes) {
  const std::vector<uint8_t> bytes = {
      0x40, 0xb0, // Type
      0x40, 0x64, 0x00, 0x00, 0x04, // ACK fields
      0x40, 0x64, // Latest Received Packet Number
      0x40, 0x8c, // Latest Received Packet Time (us, unscaled)
      0x01, // Timestamp Range Count
      0x00, 0x05, 0x40, 0x8c, 0x0a, 0x0a, 0x0a, 0x0a, // Range 1
  };

  auto frame = parseWireBytesAsAck(bytes, legacyWireVectorParams());

  EXPECT_EQ(frame.frameType, FrameType::ACK_RECEIVE_TIMESTAMPS);
  ASSERT_TRUE(frame.maybeLatestRecvdPacketNum.has_value());
  EXPECT_EQ(frame.maybeLatestRecvdPacketNum.value(), 100);
  ASSERT_TRUE(frame.maybeLatestRecvdPacketTime.has_value());
  EXPECT_EQ(
      frame.maybeLatestRecvdPacketTime.value(), std::chrono::microseconds(140));
  ASSERT_EQ(frame.recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(frame.recvdPacketsTimestampRanges[0].gap, 0);
  EXPECT_EQ(
      frame.recvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{140, 10, 10, 10, 10}));
}

TEST_F(DecodeTest, AckExtendedWireBytes) {
  const std::vector<uint8_t> bytes = {
      0x40, 0xb1, // Type
      0x40, 0x64, 0x00, 0x00, 0x04, // ACK fields
      0x03, // Extended Ack Features
      0x00, 0x00, 0x00, // ECN Counts
      0x40, 0x64, // Latest Received Packet Number
      0x40, 0x8c, // Latest Received Packet Time (us, unscaled)
      0x01, // Timestamp Range Count
      0x00, 0x05, 0x40, 0x8c, 0x0a, 0x0a, 0x0a, 0x0a, // Range 1
  };

  auto frame = parseWireBytesAsAck(bytes, legacyWireVectorParams());

  EXPECT_EQ(frame.frameType, FrameType::ACK_EXTENDED);
  ASSERT_TRUE(frame.maybeLatestRecvdPacketNum.has_value());
  EXPECT_EQ(frame.maybeLatestRecvdPacketNum.value(), 100);
  ASSERT_EQ(frame.recvdPacketsTimestampRanges.size(), 1);
  EXPECT_EQ(
      frame.recvdPacketsTimestampRanges[0].deltas,
      (std::vector<uint64_t>{140, 10, 10, 10, 10}));
}

} // namespace quic::test
