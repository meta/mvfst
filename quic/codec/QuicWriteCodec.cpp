/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicWriteCodec.h>
#include <quic/common/MvfstLogging.h>

#include <algorithm>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <cstdint>

namespace {

/**
 * A helper function to check if there are enough space to write in the packet.
 * Return: true if there is enough space, false otherwise
 */
bool packetSpaceCheck(uint64_t limit, size_t require) {
  return (static_cast<uint64_t>(require) <= limit);
}

// Receive-time-descending, packet-number-descending order for received-packet
// timestamps. Shared by the legacy and draft-02 receive-timestamp encoders: a
// single named comparator type makes std::stable_sort instantiate once for the
// whole TU instead of once per call-site lambda closure.
struct RecvTimeDescComparator {
  bool operator()(
      const quic::WriteAckFrameState::ReceivedPacket* a,
      const quic::WriteAckFrameState::ReceivedPacket* b) const {
    if (a->timings.receiveTimePoint != b->timings.receiveTimePoint) {
      return a->timings.receiveTimePoint > b->timings.receiveTimePoint;
    }
    return a->pktNum > b->pktNum;
  }
};
} // namespace

namespace quic {
Optional<uint64_t> getStreamFrameDataLengthSize(uint64_t dataLen) {
  if (dataLen <= kOneByteLimit - 1) {
    return 1;
  }
  if (dataLen <= kTwoByteLimit - 2) {
    return 2;
  }
  if (dataLen <= kFourByteLimit - 4) {
    return 4;
  }
  if (dataLen <= kEightByteLimit - 8) {
    return 8;
  }
  return std::nullopt;
}

quic::Expected<Optional<uint64_t>, QuicError> writeStreamFrameHeader(
    PacketBuilderInterface& builder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin,
    Optional<bool> skipLenHint,
    bool appendFrame) {
  if (builder.remainingSpaceInPkt() == 0) {
    return std::nullopt;
  }
  if (writeBufferLen == 0 && !fin) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "No data or fin supplied when writing stream."));
  }
  StreamTypeField::Builder streamTypeBuilder;
  QuicInteger idInt(id);

  // First account for the things that are non-optional: frame type, stream id.
  auto idIntSize = idInt.getSize();
  if (idIntSize.hasError()) {
    return quic::make_unexpected(idIntSize.error());
  }
  uint64_t headerSize = sizeof(uint8_t) + idIntSize.value();
  if (builder.remainingSpaceInPkt() < headerSize) {
    MVVLOG(4) << "No space in packet for stream header. stream=" << id
              << " remaining=" << builder.remainingSpaceInPkt();
    return std::nullopt;
  }
  QuicInteger offsetInt(offset);
  if (offset != 0) {
    streamTypeBuilder.setOffset();
    auto offsetIntSize = offsetInt.getSize();
    if (offsetIntSize.hasError()) {
      return quic::make_unexpected(offsetIntSize.error());
    }
    headerSize += offsetIntSize.value();
  }
  // Next we have to deal with the data length. This is trickier. The length of
  // data we are able to send depends on 3 things: how much we have in the
  // buffer, how much flow control we have, and the remaining size in the
  // packet. If the amount we want to send is >= the remaining packet size after
  // the header so far we can omit the length field and consume the rest of the
  // packet. If it is not then we need to use the minimal varint encoding
  // possible to avoid sending not-full packets.
  // Note: we don't bother with one potential optimization, which is writing
  // a zero length fin-only stream frame and omitting the length field.
  uint64_t dataLen = std::min(writeBufferLen, flowControlLen);
  uint64_t dataLenLen = 0;
  bool shouldSkipLengthField;
  if (skipLenHint) {
    shouldSkipLengthField = *skipLenHint;
  } else {
    // Check if we can fill the entire packet with the rest of this stream frame
    shouldSkipLengthField =
        dataLen > 0 && dataLen >= builder.remainingSpaceInPkt() - headerSize;
  }
  // At most we can write the minimal between data length and what the packet
  // builder allows us to write.
  dataLen = std::min(dataLen, builder.remainingSpaceInPkt() - headerSize);
  if (!shouldSkipLengthField) {
    const auto lengthFieldSize = getStreamFrameDataLengthSize(dataLen);
    if (!lengthFieldSize) {
      // This should never really happen as dataLen is bounded by the remaining
      // space in the packet which should be << kEightByteLimit.
      return quic::make_unexpected(QuicError(
          LocalErrorCode::INTERNAL_ERROR, "Stream frame length too large."));
    }
    dataLenLen = *lengthFieldSize;
  }
  if (dataLenLen > 0) {
    if (dataLen != 0 &&
        headerSize + dataLenLen >= builder.remainingSpaceInPkt()) {
      MVVLOG(4) << "No space in packet for stream header. stream=" << id
                << " remaining=" << builder.remainingSpaceInPkt();
      return std::nullopt;
    }
    // We have to encode the actual data length in the header.
    headerSize += dataLenLen;
    if (builder.remainingSpaceInPkt() < dataLen + headerSize) {
      dataLen = builder.remainingSpaceInPkt() - headerSize;
    }
  }
  bool shouldSetFin = fin && dataLen == writeBufferLen;
  if (dataLen == 0 && !shouldSetFin) {
    // This would be an empty non-fin stream frame.
    return std::nullopt;
  }
  if (builder.remainingSpaceInPkt() < headerSize) {
    MVVLOG(4) << "No space in packet for stream header. stream=" << id
              << " remaining=" << builder.remainingSpaceInPkt();
    return std::nullopt;
  }

  // Done with the accounting, set the bits and write the actual frame header.
  if (dataLenLen > 0) {
    streamTypeBuilder.setLength();
  }
  if (shouldSetFin) {
    streamTypeBuilder.setFin();
  }
  auto streamType = streamTypeBuilder.build();
  builder.writeBE(streamType.fieldValue());
  builder.write(idInt);
  if (offset != 0) {
    builder.write(offsetInt);
  }
  if (dataLenLen > 0) {
    builder.write(QuicInteger(dataLen));
  }
  if (appendFrame) {
    builder.appendFrame(
        WriteStreamFrame(id, offset, dataLen, streamType.hasFin()));
  } else {
    builder.markNonEmpty();
  }
  return dataLen;
}

void writeStreamFrameData(
    PacketBuilderInterface& builder,
    const ChainedByteRangeHead& writeBuffer,
    uint64_t dataLen) {
  if (dataLen > 0) {
    builder.insert(writeBuffer, dataLen);
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
quic::Expected<Optional<WriteCryptoFrame>, QuicError> writeCryptoFrameHeader(
    uint64_t offsetIn,
    uint64_t dataLen,
    PacketBuilderInterface& builder) {
  uint64_t spaceLeftInPkt = builder.remainingSpaceInPkt();
  QuicInteger intFrameType(static_cast<uint64_t>(FrameType::CRYPTO_FRAME));
  auto intFrameTypeRes = intFrameType.getSize();
  if (intFrameTypeRes.hasError()) {
    return quic::make_unexpected(intFrameTypeRes.error());
  }

  QuicInteger offsetInteger(offsetIn);
  auto offsetIntegerRes = offsetInteger.getSize();
  if (offsetIntegerRes.hasError()) {
    return quic::make_unexpected(offsetIntegerRes.error());
  }

  size_t lengthBytes = 2;
  size_t cryptoFrameHeaderSize =
      intFrameTypeRes.value() + offsetIntegerRes.value() + lengthBytes;

  if (spaceLeftInPkt <= cryptoFrameHeaderSize) {
    MVVLOG(3) << "No space left in packet to write cryptoFrame header of size: "
              << cryptoFrameHeaderSize << ", space left=" << spaceLeftInPkt;
    return Optional<WriteCryptoFrame>(std::nullopt);
  }
  size_t spaceRemaining = spaceLeftInPkt - cryptoFrameHeaderSize;
  size_t writableData = static_cast<size_t>(
      std::min<uint64_t>(dataLen, static_cast<uint64_t>(spaceRemaining)));

  QuicInteger lengthVarInt(writableData);
  auto lengthVarIntSizeRes = lengthVarInt.getSize();
  if (lengthVarIntSizeRes.hasError()) {
    return quic::make_unexpected(lengthVarIntSizeRes.error());
  }

  MVCHECK(
      lengthVarIntSizeRes.value() <= lengthBytes,
      "Length bytes representation exceeds allocated space");
  builder.write(intFrameType);
  builder.write(offsetInteger);
  builder.write(lengthVarInt);
  builder.appendFrame(WriteCryptoFrame(offsetIn, lengthVarInt.getValue()));
  return Optional<WriteCryptoFrame>(
      WriteCryptoFrame(offsetIn, lengthVarInt.getValue()));
}

quic::Expected<Optional<WriteCryptoFrame>, QuicError> writeCryptoFrame(
    uint64_t offsetIn,
    const ChainedByteRangeHead& data,
    PacketBuilderInterface& builder) {
  auto result = writeCryptoFrameHeader(offsetIn, data.chainLength(), builder);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }
  if (*result) {
    builder.insert(data, (*result)->len);
  }
  return result;
}

/*
 * This function will fill the parameter ack frame with ack blocks from the
 * parameter ackBlocks until it runs out of space (bytesLimit). The largest
 * ack block should have been inserted by the caller.
 */
[[nodiscard]] static quic::Expected<size_t, QuicError> fillFrameWithAckBlocks(
    const AckBlocks& ackBlocks,
    WriteAckFrame& ackFrame,
    uint64_t bytesLimit) {
  PacketNum currentSeqNum = ackBlocks.crbegin()->start;

  // starts off with 0 which is what we assumed the initial ack block to be for
  // the largest acked.
  size_t numAdditionalAckBlocks = 0;
  size_t previousNumAckBlocks = 0;

  // Skip the largest, as it has already been emplaced.
  for (auto blockItr = ackBlocks.crbegin() + 1; blockItr != ackBlocks.crend();
       ++blockItr) {
    const auto& currBlock = *blockItr;
    // These must be true because of the properties of the interval set.
    MVCHECK_GE(currentSeqNum, currBlock.end + 2);
    PacketNum gap = currentSeqNum - currBlock.end - 2;
    PacketNum currBlockLen = currBlock.end - currBlock.start;

    // TODO this is still extra work, as we end up duplicating these
    // calculations in the caller, we could store the results so they
    // can be reused by the caller when writing the frame.
    auto gapSizeRes = getQuicIntegerSize(gap);
    if (gapSizeRes.hasError()) {
      return quic::make_unexpected(gapSizeRes.error());
    }

    auto currBlockLenSizeRes = getQuicIntegerSize(currBlockLen);
    if (currBlockLenSizeRes.hasError()) {
      return quic::make_unexpected(currBlockLenSizeRes.error());
    }

    auto numAdditionalAckBlocksSizeRes =
        getQuicIntegerSize(numAdditionalAckBlocks + 1);
    if (numAdditionalAckBlocksSizeRes.hasError()) {
      return quic::make_unexpected(numAdditionalAckBlocksSizeRes.error());
    }

    auto previousNumAckBlocksSizeRes = getQuicIntegerSize(previousNumAckBlocks);
    if (previousNumAckBlocksSizeRes.hasError()) {
      return quic::make_unexpected(previousNumAckBlocksSizeRes.error());
    }

    size_t additionalSize = gapSizeRes.value() + currBlockLenSizeRes.value() +
        (numAdditionalAckBlocksSizeRes.value() -
         previousNumAckBlocksSizeRes.value());
    if (bytesLimit < additionalSize) {
      break;
    }
    numAdditionalAckBlocks++;
    bytesLimit -= additionalSize;
    previousNumAckBlocks = numAdditionalAckBlocks;
    currentSeqNum = currBlock.start;
    ackFrame.ackBlocks.emplace_back(currBlock.start, currBlock.end);
  }
  return numAdditionalAckBlocks;
}

quic::Expected<size_t, QuicError> computeSizeUsedByRecvdTimestamps(
    WriteAckFrame& ackFrame) {
  size_t usedSize = 0;
  for (auto& recvdPacketsTimestampRanges :
       ackFrame.recvdPacketsTimestampRanges) {
    auto gapSize = getQuicIntegerSize(recvdPacketsTimestampRanges.gap);
    if (gapSize.hasError()) {
      return quic::make_unexpected(gapSize.error());
    }
    usedSize += gapSize.value();

    auto countSize =
        getQuicIntegerSize(recvdPacketsTimestampRanges.timestamp_delta_count);
    if (countSize.hasError()) {
      return quic::make_unexpected(countSize.error());
    }
    usedSize += countSize.value();

    for (auto& timestampDelta : recvdPacketsTimestampRanges.deltas) {
      auto deltaSize = getQuicIntegerSize(timestampDelta);
      if (deltaSize.hasError()) {
        return quic::make_unexpected(deltaSize.error());
      }
      usedSize += deltaSize.value();
    }
  }
  return usedSize;
}

[[nodiscard]] static quic::Expected<size_t, QuicError>
fillFrameWithPacketReceiveTimestamps(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    uint64_t largestAckedPacketNum,
    uint64_t spaceLeft,
    uint64_t receiveTimestampsExponent,
    uint64_t maxRecvTimestampsToSend) {
  if (ackFrameMetaData.ackState.recvdPacketInfos.size() == 0) {
    return 0;
  }
  // Storage is in arrival order and may contain out-of-order packet numbers
  // AND out-of-order receive times. The legacy wire format requires monotonic
  // decreasing packet numbers AND non-negative inter-packet time deltas
  // across the iteration. Sort by receive-time desc, then take the prefix
  // whose pktNum stays strictly less than the last included.
  std::vector<const WriteAckFrameState::ReceivedPacket*> legacyView;
  legacyView.reserve(ackFrameMetaData.ackState.recvdPacketInfos.size());
  {
    std::vector<const WriteAckFrameState::ReceivedPacket*> sortedByTime;
    sortedByTime.reserve(ackFrameMetaData.ackState.recvdPacketInfos.size());
    for (const auto& rpi : ackFrameMetaData.ackState.recvdPacketInfos) {
      sortedByTime.push_back(&rpi);
    }
    // Lexicographic (receiveTime desc, pktnum desc): without the pktnum
    // tie-break, equal-time batches arrive in pktnum-ASCENDING order, the
    // pktnum-monotonic filter picks pkt 1 first, and pkts 2..N are silently
    // dropped because they fail the `pktnum < lastIncluded` check.
    // std::ranges::stable_sort is unavailable on the arvr clang21 toolchain
    // stdlib, so the portable std::stable_sort is used deliberately.
    // NOLINTNEXTLINE(modernize-use-ranges,boost-use-ranges)
    std::stable_sort(
        sortedByTime.begin(), sortedByTime.end(), RecvTimeDescComparator{});
    PacketNum lastIncludedPktNum = std::numeric_limits<PacketNum>::max();
    for (auto* rpi : sortedByTime) {
      if (rpi->pktNum < lastIncludedPktNum) {
        legacyView.push_back(rpi);
        lastIncludedPktNum = rpi->pktNum;
      }
    }
  }
  if (legacyView.empty()) {
    return 0;
  }

  uint64_t pktsAdded = 0;
  IntervalSet<PacketNum> receivedPktNumsIntervalSet;
  for (auto* recvdPkt : legacyView) {
    // Add up to the peer requested max ack receive timestamps;
    if (pktsAdded == maxRecvTimestampsToSend) {
      break;
    }
    auto insertResult = receivedPktNumsIntervalSet.tryInsert(recvdPkt->pktNum);
    if (insertResult.hasError()) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          "Failed to insert packet number into interval set"));
    }
    pktsAdded++;
  }
  auto prevPktNum = largestAckedPacketNum;
  auto timestampIt = legacyView.cbegin();
  size_t cumUsedSpace = 0;
  // We start from the latest timestamp intervals
  bool outOfSpace = false;
  for (auto timestampIntervalsIt = receivedPktNumsIntervalSet.crbegin();
       timestampIntervalsIt != receivedPktNumsIntervalSet.crend();
       timestampIntervalsIt++) {
    RecvdPacketsTimestampsRange nextTimestampRange;
    size_t nextTimestampRangeUsedSpace = 0;
    // Compute pktNum gap for each time-stamp range
    if (ackFrame.recvdPacketsTimestampRanges.empty()) {
      nextTimestampRange.gap = prevPktNum - timestampIntervalsIt->end;
    } else {
      nextTimestampRange.gap = prevPktNum - 2 - timestampIntervalsIt->end;
    }
    // Initialize spaced used by the next candidate time-stamp range
    auto gapSizeResult = getQuicIntegerSize(nextTimestampRange.gap);
    if (gapSizeResult.hasError()) {
      return quic::make_unexpected(gapSizeResult.error());
    }
    nextTimestampRangeUsedSpace += gapSizeResult.value();

    // Advances timestampIt in tandem with the outer timestampIntervalsIt;
    // range-for can't express a two-iterator walk, and the suggested fixit
    // (iterator '.' instead of '->') won't compile.
    // NOLINTBEGIN(modernize-loop-convert)
    while (timestampIt != legacyView.cend() &&
           (*timestampIt)->pktNum >= timestampIntervalsIt->start &&
           (*timestampIt)->pktNum <= timestampIntervalsIt->end) {
      std::chrono::microseconds deltaDuration;
      if (timestampIt == legacyView.cbegin()) {
        deltaDuration = ((*timestampIt)->timings.receiveTimePoint >
                         ackFrameMetaData.connTime)
            ? std::chrono::duration_cast<std::chrono::microseconds>(
                  (*timestampIt)->timings.receiveTimePoint -
                  ackFrameMetaData.connTime)
            : 0us;
      } else {
        deltaDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            (*(timestampIt - 1))->timings.receiveTimePoint -
            (*timestampIt)->timings.receiveTimePoint);
      }
      auto delta = deltaDuration.count() >> receiveTimestampsExponent;

      // Check if adding a new time-stamp delta from the current time-stamp
      // interval Will allow us to run out of space. Since adding a new delta
      // impacts cumulative counts of deltas these are not already incorporated
      // into nextTimestampRangeUsedSpace.
      auto deltaSizeResult = getQuicIntegerSize(delta);
      if (deltaSizeResult.hasError()) {
        return quic::make_unexpected(deltaSizeResult.error());
      }

      auto deltasCountSizeResult =
          getQuicIntegerSize(nextTimestampRange.deltas.size() + 1);
      if (deltasCountSizeResult.hasError()) {
        return quic::make_unexpected(deltasCountSizeResult.error());
      }

      auto rangesCountSizeResult =
          getQuicIntegerSize(ackFrame.recvdPacketsTimestampRanges.size() + 1);
      if (rangesCountSizeResult.hasError()) {
        return quic::make_unexpected(rangesCountSizeResult.error());
      }

      if (spaceLeft < (cumUsedSpace + nextTimestampRangeUsedSpace +
                       deltaSizeResult.value() + deltasCountSizeResult.value() +
                       rangesCountSizeResult.value())) {
        outOfSpace = true;
        break;
      }
      nextTimestampRange.deltas.push_back(delta);
      nextTimestampRangeUsedSpace += deltaSizeResult.value();
      timestampIt++;
    }
    // NOLINTEND(modernize-loop-convert)
    if (nextTimestampRange.deltas.size() > 0) {
      nextTimestampRange.timestamp_delta_count =
          nextTimestampRange.deltas.size();

      auto deltasCountSizeResult =
          getQuicIntegerSize(nextTimestampRange.deltas.size());
      if (deltasCountSizeResult.hasError()) {
        return quic::make_unexpected(deltasCountSizeResult.error());
      }

      cumUsedSpace +=
          nextTimestampRangeUsedSpace + deltasCountSizeResult.value();
      ackFrame.recvdPacketsTimestampRanges.push_back(nextTimestampRange);
      prevPktNum = timestampIntervalsIt->start;
      PROTO_OOPS_LOG_IF(
          cumUsedSpace > spaceLeft,
          proto_oops::getThreadLocalOopsLogger(),
          "quic_write_codec",
          "invariant_violation: ACK receive timestamp encoding exceeded "
          "available packet space");
      MVDCHECK(cumUsedSpace <= spaceLeft);
    }
    if (outOfSpace) {
      break;
    }
  }

  auto computedSizeResult = computeSizeUsedByRecvdTimestamps(ackFrame);
  if (computedSizeResult.hasError()) {
    return quic::make_unexpected(computedSizeResult.error());
  }
  PROTO_OOPS_LOG_IF(
      cumUsedSpace != computedSizeResult.value(),
      proto_oops::getThreadLocalOopsLogger(),
      "quic_write_codec",
      "invariant_violation: ACK receive timestamp encoded size mismatch");
  MVDCHECK(cumUsedSpace == computedSizeResult.value());
  return ackFrame.recvdPacketsTimestampRanges.size();
}

[[nodiscard]] static quic::Expected<Optional<WriteAckFrame>, QuicError>
maybeWriteAckBaseFields(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType,
    uint64_t maxSpaceToUse) {
  auto spaceLeft = maxSpaceToUse;
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  // The last block must be the largest block.
  auto largestAckedPacket = ackState.acks.back().end;
  // ackBlocks are already an interval set so each value is naturally
  // non-overlapping.
  auto firstAckBlockLength = largestAckedPacket - ackState.acks.back().start;
  // We could technically split the range if the size of the representation of
  // the integer is too large, but that gets super tricky and is of dubious
  // value.
  QuicInteger largestAckedPacketInt(largestAckedPacket);
  QuicInteger firstAckBlockLengthInt(firstAckBlockLength);
  // Convert ackDelay to unsigned value explicitly before right shifting to
  // avoid issues with right shifting signed values.
  uint64_t encodedAckDelay = ackFrameMetaData.ackDelay.count();
  encodedAckDelay = encodedAckDelay >> ackFrameMetaData.ackDelayExponent;
  QuicInteger ackDelayInt(encodedAckDelay);
  QuicInteger minAdditionalAckBlockCount(0);

  // Required fields are Type, LargestAcked, AckDelay, AckBlockCount,
  // firstAckBlockLength. FrameType encodes as the full underlying type
  // (uint64_t); draft-ietf-quic-receive-ts-02 frame types are above 0xFF
  // (e.g. 0x03178307) and would silently truncate if down-cast to uint8_t.
  QuicInteger encodedintFrameType(
      static_cast<std::underlying_type_t<FrameType>>(frameType));

  auto largestAckedPacketIntSize = largestAckedPacketInt.getSize();
  if (largestAckedPacketIntSize.hasError()) {
    return quic::make_unexpected(largestAckedPacketIntSize.error());
  }

  auto ackDelayIntSize = ackDelayInt.getSize();
  if (ackDelayIntSize.hasError()) {
    return quic::make_unexpected(ackDelayIntSize.error());
  }

  auto minAdditionalAckBlockCountSize = minAdditionalAckBlockCount.getSize();
  if (minAdditionalAckBlockCountSize.hasError()) {
    return quic::make_unexpected(minAdditionalAckBlockCountSize.error());
  }

  auto firstAckBlockLengthIntSize = firstAckBlockLengthInt.getSize();
  if (firstAckBlockLengthIntSize.hasError()) {
    return quic::make_unexpected(firstAckBlockLengthIntSize.error());
  }

  auto encodedintFrameTypeSize = encodedintFrameType.getSize();
  if (encodedintFrameTypeSize.hasError()) {
    return quic::make_unexpected(encodedintFrameTypeSize.error());
  }

  uint64_t headerSize = encodedintFrameTypeSize.value() +
      largestAckedPacketIntSize.value() + ackDelayIntSize.value() +
      minAdditionalAckBlockCountSize.value() +
      firstAckBlockLengthIntSize.value();

  if (spaceLeft < headerSize) {
    return Optional<WriteAckFrame>(std::nullopt);
  }
  WriteAckFrame ackFrame;
  ackFrame.frameType = frameType;

  // Reserve the number of ack blocks we could fit in the remaining space.
  ackFrame.ackBlocks.reserve(spaceLeft / 4);

  // Account for the header size
  spaceLeft -= headerSize;

  ackFrame.ackBlocks.push_back(ackState.acks.back());
  auto numAdditionalAckBlocksResult =
      fillFrameWithAckBlocks(ackState.acks, ackFrame, spaceLeft);
  if (numAdditionalAckBlocksResult.hasError()) {
    return quic::make_unexpected(numAdditionalAckBlocksResult.error());
  }

  QuicInteger numAdditionalAckBlocksInt(numAdditionalAckBlocksResult.value());
  builder.write(encodedintFrameType);
  builder.write(largestAckedPacketInt);
  builder.write(ackDelayInt);
  builder.write(numAdditionalAckBlocksInt);
  builder.write(firstAckBlockLengthInt);

  PacketNum currentSeqNum = ackState.acks.back().start;
  for (auto it = ackFrame.ackBlocks.cbegin() + 1;
       it != ackFrame.ackBlocks.cend();
       ++it) {
    MVCHECK_GE(currentSeqNum, it->end + 2);
    PacketNum gap = currentSeqNum - it->end - 2;
    PacketNum currBlockLen = it->end - it->start;
    QuicInteger gapInt(gap);
    QuicInteger currentBlockLenInt(currBlockLen);
    builder.write(gapInt);
    builder.write(currentBlockLenInt);
    currentSeqNum = it->start;
  }
  ackFrame.ackDelay = ackFrameMetaData.ackDelay;

  return Optional<WriteAckFrame>(std::move(ackFrame));
}

[[nodiscard]] static quic::Expected<uint64_t, QuicError>
computeEcnRequiredSpace(const quic::WriteAckFrameMetaData& ackFrameMetaData) {
  QuicInteger ecnECT0Count(ackFrameMetaData.ackState.ecnECT0CountReceived);
  QuicInteger ecnECT1Count(ackFrameMetaData.ackState.ecnECT1CountReceived);
  QuicInteger ecnCECount(ackFrameMetaData.ackState.ecnCECountReceived);

  auto ecnECT0Size = ecnECT0Count.getSize();
  if (ecnECT0Size.hasError()) {
    return quic::make_unexpected(ecnECT0Size.error());
  }

  auto ecnECT1Size = ecnECT1Count.getSize();
  if (ecnECT1Size.hasError()) {
    return quic::make_unexpected(ecnECT1Size.error());
  }

  auto ecnCESize = ecnCECount.getSize();
  if (ecnCESize.hasError()) {
    return quic::make_unexpected(ecnCESize.error());
  }

  return ecnECT0Size.value() + ecnECT1Size.value() + ecnCESize.value();
}

[[nodiscard]] static quic::Expected<uint64_t, QuicError>
computeReceiveTimestampsMinimumSpace(
    const quic::WriteAckFrameMetaData& ackFrameMetaData) {
  // Compute minimum size requirements for 3 fields that must be sent
  // in every ACK_RECEIVE_TIMESTAMPS frame
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  uint64_t countTimestampRanges = 0;
  uint64_t maybeLastPktNum = 0;
  std::chrono::microseconds maybeLastPktTsDelta = 0us;
  if (ackState.lastRecvdPacketInfo) {
    maybeLastPktNum = ackState.lastRecvdPacketInfo.value().pktNum;

    maybeLastPktTsDelta =
        (ackState.lastRecvdPacketInfo.value().timings.receiveTimePoint >
                 ackFrameMetaData.connTime
             ? std::chrono::duration_cast<std::chrono::microseconds>(
                   ackState.lastRecvdPacketInfo.value()
                       .timings.receiveTimePoint -
                   ackFrameMetaData.connTime)
             : 0us);
  }

  auto countRangesSize = getQuicIntegerSize(countTimestampRanges);

  auto lastPktNumSize = getQuicIntegerSize(maybeLastPktNum);

  auto lastPktTsDeltaSize = getQuicIntegerSize(maybeLastPktTsDelta.count());

  return countRangesSize.value_or(0) + lastPktNumSize.value_or(0) +
      lastPktTsDeltaSize.value_or(0);
}

static void writeECNFieldsToAck(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    PacketBuilderInterface& builder) {
  ackFrame.ecnECT0Count = ackFrameMetaData.ackState.ecnECT0CountReceived;
  ackFrame.ecnECT1Count = ackFrameMetaData.ackState.ecnECT1CountReceived;
  ackFrame.ecnCECount = ackFrameMetaData.ackState.ecnCECountReceived;
  QuicInteger ecnECT0Count(ackFrameMetaData.ackState.ecnECT0CountReceived);
  QuicInteger ecnECT1Count(ackFrameMetaData.ackState.ecnECT1CountReceived);
  QuicInteger ecnCECount(ackFrameMetaData.ackState.ecnCECountReceived);
  builder.write(ecnECT0Count);
  builder.write(ecnECT1Count);
  builder.write(ecnCECount);
}

namespace {
struct AckReceiveTimesStampsWritten {
  size_t TimestampRangesWritten{0};
  size_t TimestampWritten{0};
};
} // namespace

[[nodiscard]] quic::Expected<AckReceiveTimesStampsWritten, QuicError>
writeReceiveTimestampFieldsToAck(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    WriteAckFrame& ackFrame,
    PacketBuilderInterface& builder,
    const AckReceiveTimestampsConfig& recvTimestampsConfig,
    uint64_t maxRecvTimestampsToSend) {
  const WriteAckFrameState& ackState = ackFrameMetaData.ackState;
  uint64_t spaceLeft = builder.remainingSpaceInPkt();
  uint64_t lastPktNum = 0;
  std::chrono::microseconds lastPktTsDelta = 0us;
  if (ackState.lastRecvdPacketInfo) {
    lastPktNum = ackState.lastRecvdPacketInfo.value().pktNum;
    lastPktTsDelta =
        (ackState.lastRecvdPacketInfo.value().timings.receiveTimePoint >
                 ackFrameMetaData.connTime
             ? std::chrono::duration_cast<std::chrono::microseconds>(
                   ackState.lastRecvdPacketInfo.value()
                       .timings.receiveTimePoint -
                   ackFrameMetaData.connTime)
             : 0us);
  }
  QuicInteger lastRecvdPacketNumInt(lastPktNum);
  builder.write(lastRecvdPacketNumInt);
  ackFrame.maybeLatestRecvdPacketNum = lastRecvdPacketNumInt.getValue();
  QuicInteger lastRecvdPacketTimeInt(lastPktTsDelta.count());
  builder.write(lastRecvdPacketTimeInt);
  ackFrame.maybeLatestRecvdPacketTime =
      std::chrono::microseconds(lastRecvdPacketTimeInt.getValue());

  size_t countTimestampRanges = 0;
  size_t countTimestamps = 0;
  spaceLeft = builder.remainingSpaceInPkt();
  if (spaceLeft > 0) {
    auto largestAckedPacket = ackState.acks.back().end;
    uint64_t receiveTimestampsExponentToUse =
        recvTimestampsConfig.receiveTimestampsExponent;
    auto countTimestampRangesResult = fillFrameWithPacketReceiveTimestamps(
        ackFrameMetaData,
        ackFrame,
        largestAckedPacket,
        spaceLeft,
        receiveTimestampsExponentToUse,
        maxRecvTimestampsToSend);
    if (countTimestampRangesResult.hasError()) {
      return quic::make_unexpected(countTimestampRangesResult.error());
    }
    countTimestampRanges = countTimestampRangesResult.value();
    if (countTimestampRanges > 0) {
      QuicInteger timeStampRangeCountInt(
          ackFrame.recvdPacketsTimestampRanges.size());
      builder.write(timeStampRangeCountInt);
      for (auto& recvdPacketsTimestampRanges :
           ackFrame.recvdPacketsTimestampRanges) {
        QuicInteger gapInt(recvdPacketsTimestampRanges.gap);
        QuicInteger timestampDeltaCountInt(
            recvdPacketsTimestampRanges.timestamp_delta_count);
        builder.write(gapInt);
        builder.write(timestampDeltaCountInt);
        for (auto& timestamp : recvdPacketsTimestampRanges.deltas) {
          QuicInteger deltaInt(timestamp);
          builder.write(deltaInt);
          countTimestamps++;
        }
      }
    } else {
      QuicInteger timeStampRangeCountInt(0);
      builder.write(timeStampRangeCountInt);
    }
  }
  return AckReceiveTimesStampsWritten{countTimestampRanges, countTimestamps};
}

quic::Expected<Optional<WriteAckFrameResult>, QuicError> writeAckFrame(
    const quic::WriteAckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType,
    const AckReceiveTimestampsConfig& recvTimestampsConfig,
    uint64_t maxRecvTimestampsToSend,
    ExtendedAckFeatureMaskType extendedAckFeatures) {
  if (ackFrameMetaData.ackState.acks.empty()) {
    return Optional<WriteAckFrameResult>(std::nullopt);
  }
  uint64_t beginningSpace = builder.remainingSpaceInPkt();
  uint64_t spaceLeft = beginningSpace;

  bool ecnEnabled = (frameType == FrameType::ACK_ECN) ||
      (extendedAckFeatures &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::ECN_COUNTS));

  bool receiveTimestampsEnabled =
      (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) ||
      (extendedAckFeatures &
       static_cast<ExtendedAckFeatureMaskType>(
           ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS));

  // Reserve space for ACK_EXTENDED header
  if (frameType == FrameType::ACK_EXTENDED) {
    auto extendedAckRequiredSpaceResult =
        QuicInteger(extendedAckFeatures).getSize();
    if (extendedAckRequiredSpaceResult.hasError()) {
      return quic::make_unexpected(extendedAckRequiredSpaceResult.error());
    }
    auto extendedAckRequiredSpace = extendedAckRequiredSpaceResult.value();
    if (spaceLeft < extendedAckRequiredSpace) {
      return Optional<WriteAckFrameResult>(std::nullopt);
    }
    spaceLeft -= extendedAckRequiredSpace;
  }

  // Reserve space for ECN counts if enabled
  if (ecnEnabled) {
    auto ecnRequiredSpaceResult = computeEcnRequiredSpace(ackFrameMetaData);
    if (ecnRequiredSpaceResult.hasError()) {
      return quic::make_unexpected(ecnRequiredSpaceResult.error());
    }
    auto ecnRequiredSpace = ecnRequiredSpaceResult.value();
    if (spaceLeft < ecnRequiredSpace) {
      return Optional<WriteAckFrameResult>(std::nullopt);
    }
    spaceLeft -= ecnRequiredSpace;
  }

  // Reserve space for receive timestamps if enabled
  if (receiveTimestampsEnabled) {
    auto receiveTimestampsMinimumSpaceResult =
        computeReceiveTimestampsMinimumSpace(ackFrameMetaData);
    if (receiveTimestampsMinimumSpaceResult.hasError()) {
      return quic::make_unexpected(receiveTimestampsMinimumSpaceResult.error());
    }
    auto receiveTimestampsMinimumSpace =
        receiveTimestampsMinimumSpaceResult.value();
    if (spaceLeft < receiveTimestampsMinimumSpace) {
      return Optional<WriteAckFrameResult>(std::nullopt);
    }
    spaceLeft -= receiveTimestampsMinimumSpace;
  }

  // Start writing fields to the builder

  // 1. Write the base ack fields
  auto maybeAckFrameResult =
      maybeWriteAckBaseFields(ackFrameMetaData, builder, frameType, spaceLeft);
  if (maybeAckFrameResult.hasError()) {
    return quic::make_unexpected(maybeAckFrameResult.error());
  }
  auto& maybeAckFrame = maybeAckFrameResult.value();
  if (!maybeAckFrame.has_value()) {
    return Optional<WriteAckFrameResult>(std::nullopt);
  }
  auto& ackFrame = maybeAckFrame.value();

  // 2. Write extended ack header if enabled
  if (frameType == FrameType::ACK_EXTENDED) {
    QuicInteger quicExtendedAckFeatures(extendedAckFeatures);
    builder.write(quicExtendedAckFeatures);
  }

  // 3. Write ECN fields if enabled
  if (ecnEnabled) {
    writeECNFieldsToAck(ackFrameMetaData, ackFrame, builder);
  }

  // 4. Write receive timestamp fields if enabled
  AckReceiveTimesStampsWritten receiveTimestampsWritten;
  if (receiveTimestampsEnabled) {
    auto receiveTimestampsResult = writeReceiveTimestampFieldsToAck(
        ackFrameMetaData,
        ackFrame,
        builder,
        recvTimestampsConfig,
        maxRecvTimestampsToSend);
    if (receiveTimestampsResult.hasError()) {
      return quic::make_unexpected(receiveTimestampsResult.error());
    }
    receiveTimestampsWritten = receiveTimestampsResult.value();
  }
  // Everything written
  auto ackFrameWriteResult = WriteAckFrameResult(
      beginningSpace - builder.remainingSpaceInPkt(),
      ackFrame,
      ackFrame.ackBlocks.size(),
      receiveTimestampsWritten.TimestampRangesWritten,
      receiveTimestampsWritten.TimestampWritten,
      extendedAckFeatures);

  builder.appendFrame(std::move(ackFrame));
  return Optional<WriteAckFrameResult>(std::move(ackFrameWriteResult));
}

// === draft-ietf-quic-receive-ts-02 encoder helpers ===

namespace {

// Minimum space the draft-02 timestamp section consumes: just the Timestamp
// Range Count varint (1 byte for `0`).
quic::Expected<uint64_t, QuicError>
computeDraft02ReceiveTimestampsMinimumSpace() {
  auto sz = getQuicIntegerSize(uint64_t{0});
  if (sz.hasError()) {
    return quic::make_unexpected(sz.error());
  }
  return sz.value();
}

// Build draft-02 ranges from `recvdPacketInfos` into `outRanges`, respecting
// the peer's max count and the available wire-byte budget. Returns the total
// number of timestamps written (sum across all ranges).
//
// Traverses `recvdPacketInfos` in reverse order (newest receive time first)
// so truncation drops oldest. Groups consecutive packets where
// `pktNum == expectedNextPkt` into one range; non-contiguous packet numbers
// close the current range and open a new one with a fresh
// `deltaLargestAcknowledged`.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): the ordered
// (largestAcked, spaceLeft, peerExponent, peerMaxReceiveTimestampsPerAck)
// signature mirrors the wire field order in draft-ietf-quic-receive-ts-02.
quic::Expected<size_t, QuicError> fillFrameWithDraft02PacketReceiveTimestamps(
    const WriteAckFrameMetaData& metaData,
    Draft02ReceiveTimestampsRangeVec& outRanges,
    PacketNum largestAcked,
    uint64_t spaceLeft,
    uint64_t peerExponent,
    uint64_t peerMaxReceiveTimestampsPerAck) {
  const auto& recvdPacketInfos = metaData.ackState.recvdPacketInfos;
  if (recvdPacketInfos.empty() || peerMaxReceiveTimestampsPerAck == 0) {
    return 0;
  }
  const TimePoint basis = metaData.connTime;
  // Clamp peerExponent so the `>> peerExponent` below cannot become UB if a
  // TP-parser regression sneaks an out-of-range exponent past the validated
  // cap. Bound matches kDraft02MaxReceiveTimestampsExponent in QuicConstants.h.
  peerExponent = std::min(peerExponent, kDraft02MaxReceiveTimestampsExponent);

  // Build a receive-time-descending view. Storage is in arrival order and may
  // contain out-of-order receive times; sorting once here lets the inner walk
  // assume monotonic non-increasing receive times across iterations, so
  // chained deltas are always non-negative without a clamp. n is bounded by
  // kMaxReceivedPktsTimestampsStored (default ~10), so O(n log n) is trivial.
  std::vector<const WriteAckFrameState::ReceivedPacket*> sortedView;
  sortedView.reserve(recvdPacketInfos.size());
  for (const auto& rpi : recvdPacketInfos) {
    sortedView.push_back(&rpi);
  }
  // Lexicographic (receiveTime desc, pktnum desc): the pktnum tie-break is
  // required so equal-time batches sort into a single pktnum-monotonic run
  // that the contiguity grouping can coalesce. Without it, stable_sort
  // preserves arrival order on equal keys and the pktnum=N+1, N+2... follow-up
  // packets break the expectedNext=N-1 chain.
  std::ranges::stable_sort(sortedView, RecvTimeDescComparator{});

  size_t totalTimestamps = 0;
  size_t cumUsedSpace = 0;
  // Range-count varint widens at 63->64, 16383->16384, etc.; charge the
  // delta when crossing instead of pre-reserving the max width.
  size_t chargedRangeCountSize = 0;
  TimePoint previousTimestamp{};
  bool firstDeltaOverall = true;

  auto it = sortedView.cbegin();
  while (it != sortedView.cend() &&
         totalTimestamps < peerMaxReceiveTimestampsPerAck) {
    // `recvdPacketInfos` invariant: must not contain pkts above
    // `largestAcked` for this frame.
    if ((*it)->pktNum > largestAcked) {
      ++it;
      continue;
    }
    Draft02ReceiveTimestampsRange range;
    range.deltaLargestAcknowledged = largestAcked - (*it)->pktNum;

    PacketNum expectedNext = (*it)->pktNum;
    bool outOfSpace = false;
    while (it != sortedView.cend() && (*it)->pktNum == expectedNext &&
           totalTimestamps < peerMaxReceiveTimestampsPerAck) {
      uint64_t deltaUs = 0;
      if (firstDeltaOverall) {
        // Clamp to 0 when the receive time precedes connTime. MVDCHECK is a
        // no-op in opt builds, so an unclamped negative duration would cast to
        // a huge unsigned delta on the wire. Mirrors the legacy encoder.
        deltaUs = ((*it)->timings.receiveTimePoint > basis)
            ? static_cast<uint64_t>(
                  std::chrono::duration_cast<std::chrono::microseconds>(
                      (*it)->timings.receiveTimePoint - basis)
                      .count())
            : 0;
      } else {
        MVDCHECK(previousTimestamp >= (*it)->timings.receiveTimePoint);
        deltaUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                previousTimestamp - (*it)->timings.receiveTimePoint)
                .count());
      }
      const uint64_t scaledDelta = deltaUs >> peerExponent;

      // Tentative space accounting for adding this delta.
      const auto deltaSize = getQuicIntegerSize(scaledDelta);
      if (deltaSize.hasError()) {
        return quic::make_unexpected(deltaSize.error());
      }
      const auto deltaCountSize = getQuicIntegerSize(range.deltas.size() + 1);
      if (deltaCountSize.hasError()) {
        return quic::make_unexpected(deltaCountSize.error());
      }
      // Charge the size delta only when crossing a varint-width threshold;
      // non-zero only when opening a new range (first delta in the range).
      uint64_t rangeCountSizeDelta = 0;
      if (range.deltas.empty()) {
        const auto newRangeCountSize = getQuicIntegerSize(outRanges.size() + 1);
        if (newRangeCountSize.hasError()) {
          return quic::make_unexpected(newRangeCountSize.error());
        }
        rangeCountSizeDelta = newRangeCountSize.value() - chargedRangeCountSize;
      }
      uint64_t tentativeAdd = deltaSize.value();
      if (range.deltas.empty()) {
        const auto deltaLargestAckedSize =
            getQuicIntegerSize(range.deltaLargestAcknowledged);
        if (deltaLargestAckedSize.hasError()) {
          return quic::make_unexpected(deltaLargestAckedSize.error());
        }
        tentativeAdd += deltaLargestAckedSize.value() + deltaCountSize.value();
      } else {
        // Replace prior deltaCountSize estimate with new one (count grew).
        const auto priorDeltaCountSize =
            getQuicIntegerSize(range.deltas.size());
        if (priorDeltaCountSize.hasError()) {
          return quic::make_unexpected(priorDeltaCountSize.error());
        }
        tentativeAdd += (deltaCountSize.value() - priorDeltaCountSize.value());
      }
      if (cumUsedSpace + tentativeAdd + rangeCountSizeDelta > spaceLeft) {
        outOfSpace = true;
        break;
      }
      range.deltas.push_back(scaledDelta);
      cumUsedSpace += tentativeAdd + rangeCountSizeDelta;
      if (rangeCountSizeDelta > 0) {
        chargedRangeCountSize += rangeCountSizeDelta;
      }
      previousTimestamp = (*it)->timings.receiveTimePoint;
      firstDeltaOverall = false;
      totalTimestamps++;
      expectedNext = (*it)->pktNum - 1;
      ++it;
    }
    if (!range.deltas.empty()) {
      range.timestamp_delta_count = range.deltas.size();
      outRanges.emplace_back(std::move(range));
    }
    if (outOfSpace) {
      break;
    }
  }
  return totalTimestamps;
}

void writeDraft02ReceiveTimestampFieldsToAck(
    const Draft02ReceiveTimestampsRangeVec& ranges,
    PacketBuilderInterface& builder) {
  builder.write(QuicInteger(ranges.size()));
  for (const auto& range : ranges) {
    builder.write(QuicInteger(range.deltaLargestAcknowledged));
    builder.write(QuicInteger(range.timestamp_delta_count));
    for (const auto& d : range.deltas) {
      builder.write(QuicInteger(d));
    }
  }
}

} // namespace

quic::Expected<Optional<WriteAckFrameResult>, QuicError> writeAckFrameDraft02(
    const WriteAckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType,
    uint64_t peerExponent,
    uint64_t peerMaxReceiveTimestampsPerAck) {
  CHECK(
      frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02 ||
      frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN)
      << "writeAckFrameDraft02 frameType must be a draft-02 ACK type";
  // Per draft-ietf-quic-receive-ts-02: ACK_RECEIVE_TIMESTAMPS frames are
  // 1-RTT only.
  DCHECK_EQ(
      builder.getPacketHeader().getPacketNumberSpace(),
      PacketNumberSpace::AppData)
      << "draft-02 ACK_RECEIVE_TIMESTAMPS frames are 1-RTT only";
  // Defensive guard for the shift below; TP parser already rejects exponent
  // above `kDraft02MaxReceiveTimestampsExponent = 20`.
  DCHECK_LT(peerExponent, sizeof(uint64_t) * 8);
  if (ackFrameMetaData.ackState.acks.empty()) {
    return Optional<WriteAckFrameResult>(std::nullopt);
  }
  const uint64_t beginningSpace = builder.remainingSpaceInPkt();
  uint64_t spaceLeft = beginningSpace;

  const bool ecnEnabled =
      (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN);

  if (ecnEnabled) {
    auto ecnSizeRes = computeEcnRequiredSpace(ackFrameMetaData);
    if (ecnSizeRes.hasError()) {
      return quic::make_unexpected(ecnSizeRes.error());
    }
    if (spaceLeft < ecnSizeRes.value()) {
      return Optional<WriteAckFrameResult>(std::nullopt);
    }
    spaceLeft -= ecnSizeRes.value();
  }

  auto tsMinSpaceRes = computeDraft02ReceiveTimestampsMinimumSpace();
  if (tsMinSpaceRes.hasError()) {
    return quic::make_unexpected(tsMinSpaceRes.error());
  }
  if (spaceLeft < tsMinSpaceRes.value()) {
    return Optional<WriteAckFrameResult>(std::nullopt);
  }
  spaceLeft -= tsMinSpaceRes.value();

  // 1. Write base ACK fields.
  auto baseRes =
      maybeWriteAckBaseFields(ackFrameMetaData, builder, frameType, spaceLeft);
  if (baseRes.hasError()) {
    return quic::make_unexpected(baseRes.error());
  }
  if (!baseRes.value().has_value()) {
    return Optional<WriteAckFrameResult>(std::nullopt);
  }
  WriteAckFrame ackFrame = std::move(*baseRes.value());
  ackFrame.timestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;

  // 2. ECN counts BEFORE timestamps for the _ECN variant.
  if (ecnEnabled) {
    writeECNFieldsToAck(ackFrameMetaData, ackFrame, builder);
  }

  // 3. Build + write the draft-02 timestamp section.
  const PacketNum largestAcked = ackFrameMetaData.ackState.acks.back().end;
  const uint64_t tsBudget = builder.remainingSpaceInPkt();
  auto fillRes = fillFrameWithDraft02PacketReceiveTimestamps(
      ackFrameMetaData,
      ackFrame.draft02RecvdPacketsTimestampRanges,
      largestAcked,
      tsBudget,
      peerExponent,
      peerMaxReceiveTimestampsPerAck);
  if (fillRes.hasError()) {
    return quic::make_unexpected(fillRes.error());
  }
  const size_t totalTimestamps = fillRes.value();
  writeDraft02ReceiveTimestampFieldsToAck(
      ackFrame.draft02RecvdPacketsTimestampRanges, builder);

  auto result = WriteAckFrameResult(
      beginningSpace - builder.remainingSpaceInPkt(),
      ackFrame,
      ackFrame.ackBlocks.size(),
      ackFrame.draft02RecvdPacketsTimestampRanges.size(),
      totalTimestamps,
      /*extendedAckFeaturesEnabledIn=*/0);

  builder.appendFrame(std::move(ackFrame));
  return Optional<WriteAckFrameResult>(std::move(result));
}

quic::Expected<size_t, QuicError> writeSimpleFrame(
    QuicSimpleFrame&& frame,
    PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::STOP_SENDING));
      QuicInteger streamId(stopSendingFrame.streamId);
      QuicInteger errorCode(static_cast<uint64_t>(stopSendingFrame.errorCode));
      auto errorSizeRes = errorCode.getSize();
      if (errorSizeRes.hasError()) {
        return quic::make_unexpected(errorSizeRes.error());
      }
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamIdSize = streamId.getSize();
      if (streamIdSize.hasError()) {
        return quic::make_unexpected(streamIdSize.error());
      }
      auto stopSendingFrameSize = intFrameTypeSize.value() +
          streamIdSize.value() + errorSizeRes.value();
      if (packetSpaceCheck(spaceLeft, stopSendingFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(errorCode);
        builder.appendFrame(QuicSimpleFrame(std::move(stopSendingFrame)));
        return stopSendingFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      const PathChallengeFrame& pathChallengeFrame =
          *frame.asPathChallengeFrame();
      QuicInteger frameType(static_cast<uint64_t>(FrameType::PATH_CHALLENGE));
      auto frameTypeSize = frameType.getSize();
      if (frameTypeSize.hasError()) {
        return quic::make_unexpected(frameTypeSize.error());
      }
      auto pathChallengeFrameSize =
          frameTypeSize.value() + sizeof(pathChallengeFrame.pathData);
      if (packetSpaceCheck(spaceLeft, pathChallengeFrameSize)) {
        builder.write(frameType);
        builder.writeBE(pathChallengeFrame.pathData);
        builder.appendFrame(QuicSimpleFrame(std::move(pathChallengeFrame)));
        return pathChallengeFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      const PathResponseFrame& pathResponseFrame = *frame.asPathResponseFrame();
      QuicInteger frameType(static_cast<uint64_t>(FrameType::PATH_RESPONSE));
      auto frameTypeSize = frameType.getSize();
      if (frameTypeSize.hasError()) {
        return quic::make_unexpected(frameTypeSize.error());
      }
      auto pathResponseFrameSize =
          frameTypeSize.value() + sizeof(pathResponseFrame.pathData);
      if (packetSpaceCheck(spaceLeft, pathResponseFrameSize)) {
        builder.write(frameType);
        builder.writeBE(pathResponseFrame.pathData);
        builder.appendFrame(QuicSimpleFrame(std::move(pathResponseFrame)));
        return pathResponseFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame: {
      const NewConnectionIdFrame& newConnectionIdFrame =
          *frame.asNewConnectionIdFrame();
      QuicInteger frameType(
          static_cast<uint64_t>(FrameType::NEW_CONNECTION_ID));
      QuicInteger sequenceNumber(newConnectionIdFrame.sequenceNumber);
      QuicInteger retirePriorTo(newConnectionIdFrame.retirePriorTo);

      auto frameTypeSize = frameType.getSize();
      if (frameTypeSize.hasError()) {
        return quic::make_unexpected(frameTypeSize.error());
      }
      auto sequenceNumberSize = sequenceNumber.getSize();
      if (sequenceNumberSize.hasError()) {
        return quic::make_unexpected(sequenceNumberSize.error());
      }
      auto retirePriorToSize = retirePriorTo.getSize();
      if (retirePriorToSize.hasError()) {
        return quic::make_unexpected(retirePriorToSize.error());
      }

      // Include an 8-bit unsigned integer containing the length of the connId
      auto newConnectionIdFrameSize = frameTypeSize.value() +
          sequenceNumberSize.value() + retirePriorToSize.value() +
          sizeof(uint8_t) + newConnectionIdFrame.connectionId.size() +
          newConnectionIdFrame.token.size();
      if (packetSpaceCheck(spaceLeft, newConnectionIdFrameSize)) {
        builder.write(frameType);
        builder.write(sequenceNumber);
        builder.write(retirePriorTo);
        builder.writeBE(newConnectionIdFrame.connectionId.size());
        builder.push(
            newConnectionIdFrame.connectionId.data(),
            newConnectionIdFrame.connectionId.size());
        builder.push(
            newConnectionIdFrame.token.data(),
            newConnectionIdFrame.token.size());
        builder.appendFrame(QuicSimpleFrame(std::move(newConnectionIdFrame)));
        return newConnectionIdFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::MaxStreamsFrame: {
      const MaxStreamsFrame& maxStreamsFrame = *frame.asMaxStreamsFrame();
      auto frameType = maxStreamsFrame.isForBidirectionalStream()
          ? FrameType::MAX_STREAMS_BIDI
          : FrameType::MAX_STREAMS_UNI;
      QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
      QuicInteger streamCount(maxStreamsFrame.maxStreams);

      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamCountSize = streamCount.getSize();
      if (streamCountSize.hasError()) {
        return quic::make_unexpected(streamCountSize.error());
      }

      auto maxStreamsFrameSize =
          intFrameTypeSize.value() + streamCountSize.value();
      if (packetSpaceCheck(spaceLeft, maxStreamsFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamCount);
        builder.appendFrame(QuicSimpleFrame(maxStreamsFrame));
        return maxStreamsFrameSize;
      }
      return size_t(0);
    }
    case QuicSimpleFrame::Type::RetireConnectionIdFrame: {
      const RetireConnectionIdFrame& retireConnectionIdFrame =
          *frame.asRetireConnectionIdFrame();
      QuicInteger frameType(
          static_cast<uint64_t>(FrameType::RETIRE_CONNECTION_ID));
      QuicInteger sequence(retireConnectionIdFrame.sequenceNumber);

      auto frameTypeSize = frameType.getSize();
      if (frameTypeSize.hasError()) {
        return quic::make_unexpected(frameTypeSize.error());
      }
      auto sequenceSize = sequence.getSize();
      if (sequenceSize.hasError()) {
        return quic::make_unexpected(sequenceSize.error());
      }

      auto retireConnectionIdFrameSize =
          frameTypeSize.value() + sequenceSize.value();
      if (packetSpaceCheck(spaceLeft, retireConnectionIdFrameSize)) {
        builder.write(frameType);
        builder.write(sequence);
        builder.appendFrame(QuicSimpleFrame(retireConnectionIdFrame));
        return retireConnectionIdFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      const HandshakeDoneFrame& handshakeDoneFrame =
          *frame.asHandshakeDoneFrame();
      MVCHECK(builder.getPacketHeader().asShort());
      QuicInteger intFrameType(
          static_cast<uint64_t>(FrameType::HANDSHAKE_DONE));

      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }

      if (packetSpaceCheck(spaceLeft, intFrameTypeSize.value())) {
        builder.write(intFrameType);
        builder.appendFrame(QuicSimpleFrame(handshakeDoneFrame));
        return intFrameTypeSize.value();
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::KnobFrame: {
      const KnobFrame& knobFrame = *frame.asKnobFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::KNOB));
      QuicInteger intKnobSpace(knobFrame.knobSpace);
      QuicInteger intKnobId(knobFrame.id);
      QuicInteger intKnobLen(knobFrame.len);

      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto intKnobSpaceSize = intKnobSpace.getSize();
      if (intKnobSpaceSize.hasError()) {
        return quic::make_unexpected(intKnobSpaceSize.error());
      }
      auto intKnobIdSize = intKnobId.getSize();
      if (intKnobIdSize.hasError()) {
        return quic::make_unexpected(intKnobIdSize.error());
      }
      auto intKnobLenSize = intKnobLen.getSize();
      if (intKnobLenSize.hasError()) {
        return quic::make_unexpected(intKnobLenSize.error());
      }

      size_t knobFrameLen = intFrameTypeSize.value() +
          intKnobSpaceSize.value() + intKnobIdSize.value() +
          intKnobLenSize.value() + intKnobLen.getValue();
      if (packetSpaceCheck(spaceLeft, knobFrameLen)) {
        builder.write(intFrameType);
        builder.write(intKnobSpace);
        builder.write(intKnobId);
        builder.write(intKnobLen);
        builder.insert(knobFrame.blob->clone());
        builder.appendFrame(QuicSimpleFrame(knobFrame));
        return knobFrameLen;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::AckFrequencyFrame: {
      const auto ackFrequencyFrame = frame.asAckFrequencyFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::ACK_FREQUENCY));
      QuicInteger intSequenceNumber(ackFrequencyFrame->sequenceNumber);
      QuicInteger intPacketTolerance(ackFrequencyFrame->packetTolerance);
      QuicInteger intUpdateMaxAckDelay(ackFrequencyFrame->updateMaxAckDelay);
      QuicInteger intReorderThreshold(ackFrequencyFrame->reorderThreshold);

      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto intSequenceNumberSize = intSequenceNumber.getSize();
      if (intSequenceNumberSize.hasError()) {
        return quic::make_unexpected(intSequenceNumberSize.error());
      }
      auto intPacketToleranceSize = intPacketTolerance.getSize();
      if (intPacketToleranceSize.hasError()) {
        return quic::make_unexpected(intPacketToleranceSize.error());
      }
      auto intUpdateMaxAckDelaySize = intUpdateMaxAckDelay.getSize();
      if (intUpdateMaxAckDelaySize.hasError()) {
        return quic::make_unexpected(intUpdateMaxAckDelaySize.error());
      }
      auto intReorderThresholdSize = intReorderThreshold.getSize();
      if (intReorderThresholdSize.hasError()) {
        return quic::make_unexpected(intReorderThresholdSize.error());
      }

      size_t ackFrequencyFrameLen = intFrameTypeSize.value() +
          intSequenceNumberSize.value() + intPacketToleranceSize.value() +
          intUpdateMaxAckDelaySize.value() + intReorderThresholdSize.value();
      if (packetSpaceCheck(spaceLeft, ackFrequencyFrameLen)) {
        builder.write(intFrameType);
        builder.write(intSequenceNumber);
        builder.write(intPacketTolerance);
        builder.write(intUpdateMaxAckDelay);
        builder.write(intReorderThreshold);
        builder.appendFrame(QuicSimpleFrame(*ackFrequencyFrame));
        return ackFrequencyFrameLen;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicSimpleFrame::Type::NewTokenFrame: {
      const auto newTokenFrame = frame.asNewTokenFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::NEW_TOKEN));

      auto& token = newTokenFrame->token;
      QuicInteger tokenLength(token->computeChainDataLength());

      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto tokenLengthSize = tokenLength.getSize();
      if (tokenLengthSize.hasError()) {
        return quic::make_unexpected(tokenLengthSize.error());
      }

      auto newTokenFrameLength = intFrameTypeSize.value() +
          /*encoding token length*/ tokenLengthSize.value() +
          tokenLength.getValue();

      if (packetSpaceCheck(spaceLeft, newTokenFrameLength)) {
        builder.write(intFrameType);
        builder.write(tokenLength);
        builder.insert(token->clone());
        builder.appendFrame(QuicSimpleFrame(*newTokenFrame));
        return newTokenFrameLength;
      }
      // no space left in packet
      return size_t(0);
    }
  }
  folly::assume_unreachable();
}

quic::Expected<size_t, QuicError> getTimestampFrameEncodedSize(
    const TimestampFrame& frame) {
  auto frameTypeSize =
      QuicInteger(static_cast<uint64_t>(FrameType::TIMESTAMP)).getSize();
  if (frameTypeSize.hasError()) {
    return quic::make_unexpected(frameTypeSize.error());
  }
  auto timestampSize = QuicInteger(frame.timestamp).getSize();
  if (timestampSize.hasError()) {
    return quic::make_unexpected(timestampSize.error());
  }
  return frameTypeSize.value() + timestampSize.value();
}

quic::Expected<size_t, QuicError> writeFrame(
    QuicWriteFrame&& frame,
    PacketBuilderInterface& builder) {
  using FrameTypeType = std::underlying_type<FrameType>::type;

  uint64_t spaceLeft = builder.remainingSpaceInPkt();

  switch (frame.type()) {
    case QuicWriteFrame::Type::PaddingFrame: {
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::PADDING));
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      if (packetSpaceCheck(spaceLeft, intFrameTypeSize.value())) {
        builder.write(intFrameType);
        builder.appendPaddingFrame();
        return intFrameTypeSize.value();
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::RstStreamFrame: {
      RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
      QuicInteger intFrameType(
          static_cast<uint8_t>(
              rstStreamFrame.reliableSize ? FrameType::RST_STREAM_AT
                                          : FrameType::RST_STREAM));
      QuicInteger streamId(rstStreamFrame.streamId);
      QuicInteger finalSize(rstStreamFrame.finalSize);
      QuicInteger errorCode(static_cast<uint64_t>(rstStreamFrame.errorCode));
      Optional<QuicInteger> maybeReliableSize = std::nullopt;
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamIdSize = streamId.getSize();
      if (streamIdSize.hasError()) {
        return quic::make_unexpected(streamIdSize.error());
      }
      auto finalSizeSize = finalSize.getSize();
      if (finalSizeSize.hasError()) {
        return quic::make_unexpected(finalSizeSize.error());
      }
      auto errorSize = errorCode.getSize();
      if (errorSize.hasError()) {
        return quic::make_unexpected(errorSize.error());
      }
      auto rstStreamFrameSize = intFrameTypeSize.value() + errorSize.value() +
          streamIdSize.value() + finalSizeSize.value();
      if (rstStreamFrame.reliableSize) {
        maybeReliableSize = QuicInteger(*rstStreamFrame.reliableSize);
        auto reliableSize = maybeReliableSize->getSize();
        if (reliableSize.hasError()) {
          return quic::make_unexpected(reliableSize.error());
        }
        rstStreamFrameSize += reliableSize.value();
      }
      if (packetSpaceCheck(spaceLeft, rstStreamFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(errorCode);
        builder.write(finalSize);
        if (maybeReliableSize) {
          builder.write(*maybeReliableSize);
        }
        builder.appendFrame(std::move(rstStreamFrame));
        return rstStreamFrameSize;
      }
      // no space left in packet
      return size_t(0);
    }
    case QuicWriteFrame::Type::MaxDataFrame: {
      MaxDataFrame& maxDataFrame = *frame.asMaxDataFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::MAX_DATA));
      QuicInteger maximumData(maxDataFrame.maximumData);
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto maximumDataSize = maximumData.getSize();
      if (maximumDataSize.hasError()) {
        return quic::make_unexpected(maximumDataSize.error());
      }
      auto frameSize = intFrameTypeSize.value() + maximumDataSize.value();
      if (packetSpaceCheck(spaceLeft, frameSize)) {
        builder.write(intFrameType);
        builder.write(maximumData);
        builder.appendFrame(std::move(maxDataFrame));
        return frameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::MaxStreamDataFrame: {
      MaxStreamDataFrame& maxStreamDataFrame = *frame.asMaxStreamDataFrame();
      QuicInteger intFrameType(
          static_cast<uint64_t>(FrameType::MAX_STREAM_DATA));
      QuicInteger streamId(maxStreamDataFrame.streamId);
      QuicInteger maximumData(maxStreamDataFrame.maximumData);
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamIdSize = streamId.getSize();
      if (streamIdSize.hasError()) {
        return quic::make_unexpected(streamIdSize.error());
      }
      auto maximumDataSize = maximumData.getSize();
      if (maximumDataSize.hasError()) {
        return quic::make_unexpected(maximumDataSize.error());
      }
      auto maxStreamDataFrameSize = intFrameTypeSize.value() +
          streamIdSize.value() + maximumDataSize.value();
      if (packetSpaceCheck(spaceLeft, maxStreamDataFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(maximumData);
        builder.appendFrame(std::move(maxStreamDataFrame));
        return maxStreamDataFrameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::DataBlockedFrame: {
      DataBlockedFrame& blockedFrame = *frame.asDataBlockedFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::DATA_BLOCKED));
      QuicInteger dataLimit(blockedFrame.dataLimit);
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto dataLimitSize = dataLimit.getSize();
      if (dataLimitSize.hasError()) {
        return quic::make_unexpected(dataLimitSize.error());
      }
      auto blockedFrameSize = intFrameTypeSize.value() + dataLimitSize.value();
      if (packetSpaceCheck(spaceLeft, blockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(dataLimit);
        builder.appendFrame(std::move(blockedFrame));
        return blockedFrameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::StreamDataBlockedFrame: {
      StreamDataBlockedFrame& streamBlockedFrame =
          *frame.asStreamDataBlockedFrame();
      QuicInteger intFrameType(
          static_cast<uint64_t>(FrameType::STREAM_DATA_BLOCKED));
      QuicInteger streamId(streamBlockedFrame.streamId);
      QuicInteger dataLimit(streamBlockedFrame.dataLimit);
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamIdSize = streamId.getSize();
      if (streamIdSize.hasError()) {
        return quic::make_unexpected(streamIdSize.error());
      }
      auto dataLimitSize = dataLimit.getSize();
      if (dataLimitSize.hasError()) {
        return quic::make_unexpected(dataLimitSize.error());
      }
      auto blockedFrameSize = intFrameTypeSize.value() + streamIdSize.value() +
          dataLimitSize.value();
      if (packetSpaceCheck(spaceLeft, blockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.write(dataLimit);
        builder.appendFrame(std::move(streamBlockedFrame));
        return blockedFrameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::StreamsBlockedFrame: {
      StreamsBlockedFrame& streamsBlockedFrame = *frame.asStreamsBlockedFrame();
      auto frameType = streamsBlockedFrame.isForBidirectionalStream()
          ? FrameType::STREAMS_BLOCKED_BIDI
          : FrameType::STREAMS_BLOCKED_UNI;
      QuicInteger intFrameType(static_cast<FrameTypeType>(frameType));
      QuicInteger streamId(streamsBlockedFrame.streamLimit);
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto streamIdSize = streamId.getSize();
      if (streamIdSize.hasError()) {
        return quic::make_unexpected(streamIdSize.error());
      }
      auto streamBlockedFrameSize =
          intFrameTypeSize.value() + streamIdSize.value();
      if (packetSpaceCheck(spaceLeft, streamBlockedFrameSize)) {
        builder.write(intFrameType);
        builder.write(streamId);
        builder.appendFrame(std::move(streamsBlockedFrame));
        return streamBlockedFrameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::ConnectionCloseFrame: {
      ConnectionCloseFrame& connectionCloseFrame =
          *frame.asConnectionCloseFrame();
      const TransportErrorCode* isTransportErrorCode =
          connectionCloseFrame.errorCode.asTransportErrorCode();
      const ApplicationErrorCode* isApplicationErrorCode =
          connectionCloseFrame.errorCode.asApplicationErrorCode();

      QuicInteger intFrameType(
          static_cast<uint8_t>(
              isTransportErrorCode ? FrameType::CONNECTION_CLOSE
                                   : FrameType::CONNECTION_CLOSE_APP_ERR));

      QuicInteger reasonLength(connectionCloseFrame.reasonPhrase.size());
      Optional<QuicInteger> closingFrameType;
      if (isTransportErrorCode) {
        closingFrameType = QuicInteger(
            static_cast<FrameTypeType>(connectionCloseFrame.closingFrameType));
      }

      QuicInteger errorCode(
          isTransportErrorCode
              ? static_cast<uint64_t>(TransportErrorCode(*isTransportErrorCode))
              : static_cast<uint64_t>(
                    ApplicationErrorCode(*isApplicationErrorCode)));
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      auto errorSize = errorCode.getSize();
      if (errorSize.hasError()) {
        return quic::make_unexpected(errorSize.error());
      }
      auto reasonLengthSize = reasonLength.getSize();
      if (reasonLengthSize.hasError()) {
        return quic::make_unexpected(reasonLengthSize.error());
      }
      quic::Expected<size_t, QuicError> closingFrameTypeSize = [&]() {
        if (closingFrameType) {
          auto result = closingFrameType.value().getSize();
          if (result.hasError()) {
            return result;
          }
          return result;
        } else {
          return quic::Expected<size_t, QuicError>(0);
        }
      }();

      if (closingFrameType && closingFrameTypeSize.hasError()) {
        return quic::make_unexpected(closingFrameTypeSize.error());
      }

      size_t closingFrameTypeSizeValue =
          closingFrameType ? closingFrameTypeSize.value() : 0;

      auto connCloseFrameSize = intFrameTypeSize.value() + errorSize.value() +
          closingFrameTypeSizeValue + reasonLengthSize.value() +
          connectionCloseFrame.reasonPhrase.size();
      if (packetSpaceCheck(spaceLeft, connCloseFrameSize)) {
        builder.write(intFrameType);
        builder.write(errorCode);
        if (closingFrameType) {
          builder.write(closingFrameType.value());
        }
        builder.write(reasonLength);
        builder.push(
            (const uint8_t*)connectionCloseFrame.reasonPhrase.data(),
            connectionCloseFrame.reasonPhrase.size());
        builder.appendFrame(std::move(connectionCloseFrame));
        return connCloseFrameSize;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::PingFrame: {
      const PingFrame& pingFrame = *frame.asPingFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::PING));
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      if (packetSpaceCheck(spaceLeft, intFrameTypeSize.value())) {
        builder.write(intFrameType);
        builder.appendFrame(pingFrame);
        return intFrameTypeSize.value();
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::QuicSimpleFrame: {
      return writeSimpleFrame(std::move(*frame.asQuicSimpleFrame()), builder);
    }
    case QuicWriteFrame::Type::DatagramFrame: {
      const DatagramFrame& datagramFrame = *frame.asDatagramFrame();
      QuicInteger frameTypeQuicInt(
          static_cast<uint64_t>(FrameType::DATAGRAM_LEN));
      QuicInteger datagramLenInt(datagramFrame.length);
      auto frameTypeQuicIntSize = frameTypeQuicInt.getSize();
      if (frameTypeQuicIntSize.hasError()) {
        return quic::make_unexpected(frameTypeQuicIntSize.error());
      }
      auto datagramLenIntSize = datagramLenInt.getSize();
      if (datagramLenIntSize.hasError()) {
        return quic::make_unexpected(datagramLenIntSize.error());
      }
      auto datagramFrameLength = frameTypeQuicIntSize.value() +
          datagramFrame.length + datagramLenIntSize.value();
      if (packetSpaceCheck(spaceLeft, datagramFrameLength)) {
        builder.write(frameTypeQuicInt);
        builder.write(datagramLenInt);
        builder.insert(std::move(datagramFrame.data), datagramFrame.length);
        builder.appendFrame(datagramFrame);
        return datagramFrameLength;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::TimestampFrame: {
      TimestampFrame& timestampFrame = *frame.asTimestampFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::TIMESTAMP));
      QuicInteger intTimestamp(timestampFrame.timestamp);
      auto timestampFrameLenResult =
          getTimestampFrameEncodedSize(timestampFrame);
      if (timestampFrameLenResult.hasError()) {
        return quic::make_unexpected(timestampFrameLenResult.error());
      }
      const auto timestampFrameLen = timestampFrameLenResult.value();
      if (packetSpaceCheck(spaceLeft, timestampFrameLen)) {
        builder.write(intFrameType);
        builder.write(intTimestamp);
        builder.appendFrame(std::move(timestampFrame));
        return timestampFrameLen;
      }
      return size_t(0);
    }
    case QuicWriteFrame::Type::ImmediateAckFrame: {
      const ImmediateAckFrame& immediateAckFrame = *frame.asImmediateAckFrame();
      QuicInteger intFrameType(static_cast<uint64_t>(FrameType::IMMEDIATE_ACK));
      auto intFrameTypeSize = intFrameType.getSize();
      if (intFrameTypeSize.hasError()) {
        return quic::make_unexpected(intFrameTypeSize.error());
      }
      if (packetSpaceCheck(spaceLeft, intFrameTypeSize.value())) {
        builder.write(intFrameType);
        builder.appendFrame(immediateAckFrame);
        return intFrameTypeSize.value();
      }
      return size_t(0);
    }
    default: {
      MVCHECK(false, "Unknown / unsupported frame type received");
    }
  }
}
} // namespace quic
