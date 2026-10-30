/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Decode.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/MvfstLogging.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <algorithm>
#include <chrono>

namespace {

quic::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketGap(
    quic::PacketNum packetNum,
    uint64_t gap) noexcept {
  // Gap cannot overflow because of the definition of quic integer encoding, so
  // we can just add to gap.
  uint64_t adjustedGap = gap + 2;
  if (packetNum < adjustedGap) {
    return quic::make_unexpected(
        quic::QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
  }
  return packetNum - adjustedGap;
}

quic::Expected<quic::PacketNum, quic::QuicError> nextAckedPacketLen(
    quic::PacketNum packetNum,
    uint64_t ackBlockLen) noexcept {
  // Going to allow 0 as a valid value.
  if (packetNum < ackBlockLen) {
    return quic::make_unexpected(
        quic::QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
  }
  return packetNum - ackBlockLen;
}

// Decode a QUIC variable-length integer from the cursor, returning the decoded
// value or a FRAME_ENCODING_ERROR with the given field name on failure.
quic::Expected<uint64_t, quic::QuicError> decodeQuicIntegerOrError(
    quic::ContiguousReadCursor& cursor,
    std::string_view fieldName) {
  auto val = quic::decodeQuicInteger(cursor);
  if (!val) {
    return quic::make_unexpected(
        quic::QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR,
            fmt::format("Bad {}", fieldName)));
  }
  return val->first;
}

// Convenience macro: decode a QUIC integer into `var`, returning early on
// error. After this macro, `var` is a uint64_t holding the decoded value.
#define QUIC_TRY_DECODE_INT(var, cursor, fieldName)           \
  auto QUIC_TRY_DECODE_INT_result_##var =                     \
      decodeQuicIntegerOrError(cursor, fieldName);            \
  if (QUIC_TRY_DECODE_INT_result_##var.hasError()) {          \
    return quic::make_unexpected(                             \
        std::move(QUIC_TRY_DECODE_INT_result_##var).error()); \
  }                                                           \
  auto var = *QUIC_TRY_DECODE_INT_result_##var

// Helper to decode a frame using contiguousCursor, check for errors, trim the
// queue, and wrap the result in QuicFrame. Eliminates repeated boilerplate in
// the parseFrame switch. The cursor is always passed as the first argument to
// the decode function, followed by any additional arguments.
template <typename DecodeFn, typename... Args>
quic::Expected<quic::QuicFrame, quic::QuicError> decodeFrameAndTrimBufQueue(
    quic::BufQueue& queue,
    quic::ContiguousReadCursor& cursor,
    DecodeFn&& decodeFn,
    Args&&... args) {
  auto res =
      std::forward<DecodeFn>(decodeFn)(cursor, std::forward<Args>(args)...);
  if (!res.has_value()) {
    return quic::make_unexpected(res.error());
  }
  queue.trimStart(cursor.getCurrentPosition());
  return quic::QuicFrame(*res);
}

} // namespace

namespace quic {

quic::Expected<PaddingFrame, QuicError> decodePaddingFrame(
    ContiguousReadCursor& cursor) {
  static_assert(
      static_cast<int>(FrameType::PADDING) == 0, "Padding value is 0");
  ByteRange paddingBytes = cursor.peekBytes();
  size_t numPaddingBytes = 0;
  while (numPaddingBytes < paddingBytes.size() &&
         paddingBytes.data()[numPaddingBytes] == 0) {
    ++numPaddingBytes;
  }
  cursor.skip(numPaddingBytes);
  PaddingFrame frame;
  // The caller has already consumed the first PADDING frame's type.
  frame.numFrames =
      static_cast<uint16_t>(1 + static_cast<uint16_t>(numPaddingBytes));
  return frame;
}

quic::Expected<PingFrame, QuicError> decodePingFrame(ContiguousReadCursor&) {
  return PingFrame();
}

quic::Expected<QuicFrame, QuicError> decodeKnobFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(knobSpace, cursor, "knob space");
  QUIC_TRY_DECODE_INT(knobId, cursor, "knob id");
  QUIC_TRY_DECODE_INT(knobLen, cursor, "knob len");
  BufPtr knobBlob =
      BufHelpers::create(std::min(knobLen, (uint64_t)cursor.remaining()));
  size_t amountRead = cursor.pullAtMost(knobBlob->writableData(), knobLen);
  knobBlob->append(amountRead);
  return QuicFrame(KnobFrame(knobSpace, knobId, std::move(knobBlob)));
}

quic::Expected<QuicSimpleFrame, QuicError> decodeAckFrequencyFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(sequenceNumber, cursor, "sequence number");
  QUIC_TRY_DECODE_INT(packetTolerance, cursor, "packet tolerance");
  QUIC_TRY_DECODE_INT(updateMaxAckDelay, cursor, "update max ack delay");
  QUIC_TRY_DECODE_INT(reorderThreshold, cursor, "reorder threshold");

  AckFrequencyFrame frame;
  frame.sequenceNumber = sequenceNumber;
  frame.packetTolerance = packetTolerance;
  frame.updateMaxAckDelay = updateMaxAckDelay;
  frame.reorderThreshold = reorderThreshold;
  return QuicSimpleFrame(frame);
}

quic::Expected<ImmediateAckFrame, QuicError> decodeImmediateAckFrame(
    ContiguousReadCursor&) {
  return ImmediateAckFrame();
}

quic::Expected<uint64_t, QuicError> convertEncodedDurationToMicroseconds(
    uint8_t exponentToUse,
    uint64_t encodedDuration) noexcept {
  uint64_t durationOverflowMask = 0xFFFFFFFFFFFFFFFF;

  constexpr uint8_t durationValueWidth = sizeof(encodedDuration) * 8;
  if (exponentToUse == 0 || exponentToUse >= durationValueWidth) {
    return encodedDuration;
  }
  uint8_t leftShift = (durationValueWidth - exponentToUse);
  durationOverflowMask = durationOverflowMask << leftShift;
  if ((encodedDuration & durationOverflowMask) != 0) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Decoded duration overflows"));
  }
  uint64_t adjustedDuration = encodedDuration << exponentToUse;
  if (adjustedDuration >
      static_cast<uint64_t>(
          std::numeric_limits<std::chrono::microseconds::rep>::max())) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad duration"));
  }
  return adjustedDuration;
}

quic::Expected<TimestampFrame, QuicError> decodeTimestampFrame(
    ContiguousReadCursor& cursor,
    const CodecParameters& params) {
  QUIC_TRY_DECODE_INT(timestamp, cursor, "timestamp");
  auto scaled = convertEncodedDurationToMicroseconds(
      params.peerTimestampFrameTimestampExponent, timestamp);
  if (scaled.hasError()) {
    return quic::make_unexpected(scaled.error());
  }
  return TimestampFrame(*scaled);
}

quic::Expected<ReadAckFrame, QuicError> decodeAckFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  ReadAckFrame frame;
  frame.frameType = frameType;
  auto largestAckedInt = quic::decodeQuicInteger(cursor);
  if (!largestAckedInt) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad largest acked"));
  }
  PacketNum largestAcked = largestAckedInt->first;
  auto ackDelay = quic::decodeQuicInteger(cursor);
  if (!ackDelay) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack delay"));
  }
  auto additionalAckBlocks = quic::decodeQuicInteger(cursor);
  // Each additional block requires >=2 encoded bytes (gap + len varints).
  // Bound the declared count by physically available bytes to reject
  // maliciously large counts before unbounded ackBlocks growth (T259150635).
  if (!additionalAckBlocks ||
      additionalAckBlocks->first > cursor.remaining() / 2) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ack block count"));
  }
  auto firstAckBlockLen = quic::decodeQuicInteger(cursor);
  if (!firstAckBlockLen) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad first block"));
  }
  // Using default ack delay for long header packets. Before negotiating
  // and ack delay, the sender has to use something, so they use the default
  // ack delay. To keep it consistent the protocol specifies using the same
  // ack delay for all the long header packets.
  uint8_t ackDelayExponentToUse = (header.getHeaderForm() == HeaderForm::Long)
      ? kDefaultAckDelayExponent
      : params.peerAckDelayExponent;
  PROTO_OOPS_LOG_IF(
      ackDelayExponentToUse >= sizeof(ackDelay->first) * 8,
      proto_oops::getThreadLocalOopsLogger(),
      "quic_read_codec",
      "invariant_violation: ACK delay exponent exceeds encoded ACK delay "
      "width");
  DCHECK_LT(ackDelayExponentToUse, sizeof(ackDelay->first) * 8);

  auto res = nextAckedPacketLen(largestAcked, firstAckBlockLen->first);
  if (res.hasError()) {
    return quic::make_unexpected(res.error());
  }
  PacketNum currentPacketNum = *res;
  frame.largestAcked = largestAcked;

  auto delayRes = convertEncodedDurationToMicroseconds(
      ackDelayExponentToUse, ackDelay->first);
  if (delayRes.hasError()) {
    return quic::make_unexpected(delayRes.error());
  }
  auto adjustedDelay = *delayRes;

  if (UNLIKELY(adjustedDelay > 1000 * 1000 * 1000 /* 1000s */)) {
    MVLOG_ERROR << "Quic recvd long ack delay=" << adjustedDelay
                << " frame type: " << static_cast<uint64_t>(frameType);
    adjustedDelay = 0;
  }
  frame.ackDelay = std::chrono::microseconds(adjustedDelay);

  frame.ackBlocks.emplace_back(currentPacketNum, largestAcked);
  for (uint64_t numBlocks = 0; numBlocks < additionalAckBlocks->first;
       ++numBlocks) {
    auto currentGap = quic::decodeQuicInteger(cursor);
    if (!currentGap) {
      return quic::make_unexpected(
          QuicError(quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad gap"));
    }
    auto blockLen = quic::decodeQuicInteger(cursor);
    if (!blockLen) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad block len"));
    }
    res = nextAckedPacketGap(currentPacketNum, currentGap->first);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    PacketNum nextEndPacket = *res;
    res = nextAckedPacketLen(nextEndPacket, blockLen->first);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    currentPacketNum = *res;
    // We don't need to add the entry when the block length is zero since we
    // already would have processed it in the previous iteration.
    frame.ackBlocks.emplace_back(currentPacketNum, nextEndPacket);
  }

  return frame;
}

static quic::Expected<void, QuicError> decodeReceiveTimestampsInAck(
    ReadAckFrame& frame,
    ContiguousReadCursor& cursor,
    const CodecParameters& params) {
  auto latestRecvdPacketNum = quic::decodeQuicInteger(cursor);
  if (!latestRecvdPacketNum) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad latest received packet number"));
  }
  frame.maybeLatestRecvdPacketNum = latestRecvdPacketNum->first;

  auto latestRecvdPacketTimeDelta = quic::decodeQuicInteger(cursor);
  if (!latestRecvdPacketTimeDelta) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive packet timestamp delta"));
  }
  frame.maybeLatestRecvdPacketTime =
      std::chrono::microseconds(latestRecvdPacketTimeDelta->first);

  auto timeStampRangeCount = quic::decodeQuicInteger(cursor);
  if (!timeStampRangeCount) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad receive timestamps range count"));
  }
  for (uint64_t numRanges = 0; numRanges < timeStampRangeCount->first;
       numRanges++) {
    RecvdPacketsTimestampsRange timeStampRange;
    auto receiveTimeStampsGap = quic::decodeQuicInteger(cursor);
    if (!receiveTimeStampsGap) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad receive timestamps gap"));
    }
    timeStampRange.gap = receiveTimeStampsGap->first;
    auto receiveTimeStampsLen = quic::decodeQuicInteger(cursor);
    if (!receiveTimeStampsLen) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad receive timestamps block length"));
    }
    timeStampRange.timestamp_delta_count = receiveTimeStampsLen->first;
    uint8_t receiveTimestampsExponentToUse =
        (params.maybeAckReceiveTimestampsConfig)
        ? params.maybeAckReceiveTimestampsConfig.value()
              .receiveTimestampsExponent
        : kDefaultReceiveTimestampsExponent;
    for (uint64_t i = 0; i < receiveTimeStampsLen->first; i++) {
      auto delta = quic::decodeQuicInteger(cursor);
      if (!delta) {
        return quic::make_unexpected(QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR,
            "Bad receive timestamps delta"));
      }
      PROTO_OOPS_LOG_IF(
          receiveTimestampsExponentToUse >= sizeof(delta->first) * 8,
          proto_oops::getThreadLocalOopsLogger(),
          "quic_read_codec",
          "invariant_violation: receive timestamp exponent exceeds encoded "
          "delta width");
      DCHECK_LT(receiveTimestampsExponentToUse, sizeof(delta->first) * 8);
      auto res = convertEncodedDurationToMicroseconds(
          receiveTimestampsExponentToUse, delta->first);
      if (res.hasError()) {
        return quic::make_unexpected(res.error());
      }
      auto adjustedDelta = *res;
      timeStampRange.deltas.push_back(adjustedDelta);
    }
    frame.recvdPacketsTimestampRanges.emplace_back(timeStampRange);
  }
  return {};
}

static quic::Expected<void, QuicError> decodeEcnCountsInAck(
    ReadAckFrame& frame,
    ContiguousReadCursor& cursor) {
  auto ect_0 = quic::decodeQuicInteger(cursor);
  auto ect_1 = quic::decodeQuicInteger(cursor);
  auto ce = quic::decodeQuicInteger(cursor);
  if (!ect_0 || !ect_1 || !ce) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad ECN value"));
  }
  frame.ecnECT0Count = ect_0->first;
  frame.ecnECT1Count = ect_1->first;
  frame.ecnCECount = ce->first;
  return {};
}

quic::Expected<ReadAckFrame, QuicError> decodeAckExtendedFrame(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  auto res = decodeAckFrame(cursor, header, params, FrameType::ACK_EXTENDED);
  if (res.hasError()) {
    return quic::make_unexpected(res.error());
  }
  ReadAckFrame frame = std::move(*res);
  auto extendedAckFeatures = quic::decodeQuicInteger(cursor);
  if (!extendedAckFeatures) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad extended ACK features field"));
  }
  auto includedFeatures = extendedAckFeatures->first;
  if ((includedFeatures | params.extendedAckFeatures) !=
      params.extendedAckFeatures) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Extended ACK has unexpected features"));
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS)) {
    auto ecnResult = decodeEcnCountsInAck(frame, cursor);
    if (ecnResult.hasError()) {
      return quic::make_unexpected(ecnResult.error());
    }
  }
  if (includedFeatures &
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)) {
    auto tsResult = decodeReceiveTimestampsInAck(frame, cursor, params);
    if (tsResult.hasError()) {
      return quic::make_unexpected(tsResult.error());
    }
    frame.timestampsVersion = AckReceiveTimestampsVersion::LegacyMvfst;
  }
  return frame;
}

quic::Expected<QuicFrame, QuicError> decodeAckFrameWithReceivedTimestamps(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  auto ack = decodeAckFrame(cursor, header, params, frameType);
  if (ack.hasError()) {
    return quic::make_unexpected(ack.error());
  }
  ReadAckFrame frame = std::move(*ack);
  frame.frameType = frameType;

  auto ts = decodeReceiveTimestampsInAck(frame, cursor, params);
  if (ts.hasError()) {
    return quic::make_unexpected(ts.error());
  }
  frame.timestampsVersion = AckReceiveTimestampsVersion::LegacyMvfst;

  return QuicFrame(frame);
}

static quic::Expected<void, QuicError> decodeDraft02ReceiveTimestampsInAck(
    ReadAckFrame& frame,
    ContiguousReadCursor& cursor,
    const CodecParameters& params) {
  auto timestampRangeCount = quic::decodeQuicInteger(cursor);
  if (!timestampRangeCount) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad draft-02 timestamp range count"));
  }
  // Exponent this endpoint advertised (TP 0x4ac26); the peer scaled its
  // deltas by it. Absent local config falls back to draft-02's default of 0
  // (not the legacy mvfst default of 3).
  const uint8_t exponent = params.maybeAckReceiveTimestampsConfig
      ? static_cast<uint8_t>(
            params.maybeAckReceiveTimestampsConfig->receiveTimestampsExponent)
      : 0;
  // Defense-in-depth: absent local config caps at the hard limit so an
  // attacker can't exploit the absent branch to bypass the per-frame max.
  const uint64_t effectiveMax = params.maybeAckReceiveTimestampsConfig
      ? params.maybeAckReceiveTimestampsConfig->maxReceiveTimestampsPerAck
      : kMaxReceiveTimestampsHardLimit;
  uint64_t totalDeltaCount = 0;
  // Cap the reserve by `rangeCount`, the effective max, AND the hard limit so
  // a peer-controlled varint up to 2^62 can't drive a giant allocation before
  // per-range parsing finds the real violation. When local config is present
  // `effectiveMax` is an unconstrained peer-advertised value, so the hard
  // limit must bound the reserve too.
  frame.draft02RecvdPacketsTimestampRanges.reserve(
      std::min(
          {timestampRangeCount->first,
           effectiveMax,
           kMaxReceiveTimestampsHardLimit}));
  for (uint64_t r = 0; r < timestampRangeCount->first; r++) {
    Draft02ReceiveTimestampsRange range;
    auto deltaLargestAcked = quic::decodeQuicInteger(cursor);
    if (!deltaLargestAcked) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad draft-02 delta_largest_acknowledged"));
    }
    range.deltaLargestAcknowledged = deltaLargestAcked->first;
    auto deltaCount = quic::decodeQuicInteger(cursor);
    if (!deltaCount) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Bad draft-02 timestamp_delta_count"));
    }
    // Skip zero-delta ranges: the total-delta limit below keys on actual
    // deltas, so empty ranges would bypass it and allow memory amplification.
    if (deltaCount->first == 0) {
      continue;
    }
    range.timestamp_delta_count = deltaCount->first;
    // Per draft-ietf-quic-receive-ts-02: total delta count across all ranges
    // MUST NOT exceed max_receive_timestamps_per_ack. Check BEFORE adding so a
    // pair of near-2^62 counts can't wrap the uint64 sum below `effectiveMax`
    // and slip past the guard. `effectiveMax - totalDeltaCount` cannot
    // underflow: `totalDeltaCount <= effectiveMax` is an invariant maintained
    // by this check on every prior iteration (it starts at 0).
    if (deltaCount->first > effectiveMax - totalDeltaCount) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          fmt::format(
              "draft-02 timestamp count {} exceeds max {}",
              totalDeltaCount + deltaCount->first,
              effectiveMax)));
    }
    totalDeltaCount += deltaCount->first;
    // Intentionally NOT calling `range.deltas.reserve(deltaCount->first)`:
    // peer-controlled varint up to 2^62. Vector growth bounded by what the
    // cursor actually contains.
    for (uint64_t i = 0; i < deltaCount->first; i++) {
      auto delta = quic::decodeQuicInteger(cursor);
      if (!delta) {
        return quic::make_unexpected(QuicError(
            quic::TransportErrorCode::FRAME_ENCODING_ERROR,
            "Bad draft-02 timestamp delta"));
      }
      DCHECK_LT(exponent, sizeof(delta->first) * 8);
      auto scaled =
          convertEncodedDurationToMicroseconds(exponent, delta->first);
      if (scaled.hasError()) {
        return quic::make_unexpected(scaled.error());
      }
      range.deltas.push_back(*scaled);
    }
    frame.draft02RecvdPacketsTimestampRanges.emplace_back(std::move(range));
  }
  return {};
}

quic::Expected<QuicFrame, QuicError> decodeAckFrameDraft02WithReceiveTimestamps(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params,
    FrameType frameType) {
  // draft-ietf-quic-receive-ts-02 frames are 1-RTT only. Reject them in
  // Initial/Handshake space (the outbound writer DCHECKs AppData; this is the
  // inbound counterpart) so a malformed frame isn't silently accepted as a
  // plain ACK with its timestamp section dropped.
  if (header.getPacketNumberSpace() != PacketNumberSpace::AppData) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "draft-02 receive-timestamps ACK outside AppData space"));
  }
  auto ack = decodeAckFrame(cursor, header, params, frameType);
  if (ack.hasError()) {
    return quic::make_unexpected(ack.error());
  }
  ReadAckFrame frame = std::move(*ack);
  frame.frameType = frameType;

  // _ECN variant interleaves ECN counts between the base ACK fields and the
  // timestamp section.
  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN) {
    auto ecn = decodeEcnCountsInAck(frame, cursor);
    if (ecn.hasError()) {
      return quic::make_unexpected(ecn.error());
    }
  }

  auto ts = decodeDraft02ReceiveTimestampsInAck(frame, cursor, params);
  if (ts.hasError()) {
    return quic::make_unexpected(ts.error());
  }
  frame.timestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;

  return QuicFrame(frame);
}

quic::Expected<QuicFrame, QuicError> decodeAckFrameWithECN(
    ContiguousReadCursor& cursor,
    const PacketHeader& header,
    const CodecParameters& params) {
  auto ack = decodeAckFrame(cursor, header, params);
  if (ack.hasError()) {
    return quic::make_unexpected(ack.error());
  }
  ReadAckFrame readAckFrame = std::move(*ack);
  readAckFrame.frameType = FrameType::ACK_ECN;

  auto ecn = decodeEcnCountsInAck(readAckFrame, cursor);
  if (ecn.hasError()) {
    return quic::make_unexpected(ecn.error());
  }

  return QuicFrame(readAckFrame);
}

quic::Expected<RstStreamFrame, QuicError> decodeRstStreamFrame(
    ContiguousReadCursor& cursor,
    bool reliable) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "streamId");
  QUIC_TRY_DECODE_INT(varCode, cursor, "error code");
  auto errorCode = static_cast<ApplicationErrorCode>(varCode);
  QUIC_TRY_DECODE_INT(finalSize, cursor, "final size");
  Optional<uint64_t> reliableSizeVal = std::nullopt;
  if (reliable) {
    QUIC_TRY_DECODE_INT(reliableSize, cursor, "reliable size");
    if (reliableSize > finalSize) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Reliable size is greater than final size"));
    }
    reliableSizeVal = reliableSize;
  }
  return RstStreamFrame(streamId, errorCode, finalSize, reliableSizeVal);
}

quic::Expected<StopSendingFrame, QuicError> decodeStopSendingFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "streamId");
  QUIC_TRY_DECODE_INT(varCode, cursor, "error code");
  auto errorCode = static_cast<ApplicationErrorCode>(varCode);
  return StopSendingFrame(streamId, errorCode);
}

quic::Expected<ReadCryptoFrame, QuicError> decodeCryptoFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(offset, cursor, "offset");
  QUIC_TRY_DECODE_INT(dataLength, cursor, "length");
  if (cursor.remaining() < dataLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad length mismatch"));
  }

  BufPtr data = BufHelpers::create(dataLength);
  size_t cloned = cursor.pullAtMost(data->writableData(), dataLength);
  if (cloned < dataLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad data clone"));
  }
  data->append(dataLength);

  return ReadCryptoFrame(offset, std::move(data));
}

quic::Expected<ReadNewTokenFrame, QuicError> decodeNewTokenFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(tokenLength, cursor, "token length");
  if (cursor.remaining() < tokenLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad token length mismatch"));
  }
  BufPtr token = BufHelpers::create(tokenLength);
  size_t cloned = cursor.pullAtMost(token->writableData(), tokenLength);
  if (cloned < tokenLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad token clone"));
  }
  token->append(tokenLength);

  return ReadNewTokenFrame(std::move(token));
}

quic::Expected<ReadStreamFrame, QuicError> decodeStreamFrame(
    BufQueue& queue,
    StreamTypeField frameTypeField) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());

  auto streamId = quic::decodeQuicInteger(cursor);
  if (!streamId) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid stream id"));
  }

  uint64_t offset = 0;
  if (frameTypeField.hasOffset()) {
    auto optionalOffset = quic::decodeQuicInteger(cursor);
    if (!optionalOffset) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid offset"));
    }
    offset = optionalOffset->first;
  }
  auto fin = frameTypeField.hasFin();
  Optional<std::pair<uint64_t, size_t>> dataLength;
  if (frameTypeField.hasDataLength()) {
    dataLength = quic::decodeQuicInteger(cursor);
    if (!dataLength) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid length"));
    }
  }
  BufPtr data;

  // Calculate how much to trim from the start of the queue
  size_t trimAmount = cursor.getCurrentPosition();
  if (trimAmount > 0) {
    size_t trimmed = queue.trimStartAtMost(trimAmount);
    if (trimmed < trimAmount) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to trim queue"));
    }
  }

  if (dataLength.has_value()) {
    if (queue.chainLength() < dataLength->first) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Length mismatch"));
    }
    data = queue.splitAtMost(dataLength->first);
    if (!data || data->computeChainDataLength() < dataLength->first) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  } else {
    // Missing Data Length field doesn't mean no data. It means the rest of the
    // frame are all data.
    data = queue.move();
    if (!data) {
      return quic::make_unexpected(QuicError(
          quic::TransportErrorCode::FRAME_ENCODING_ERROR,
          "Failed to extract data"));
    }
  }
  return ReadStreamFrame(streamId->first, offset, std::move(data), fin);
}

quic::Expected<MaxDataFrame, QuicError> decodeMaxDataFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(maximumData, cursor, "max data");
  return MaxDataFrame(maximumData);
}

quic::Expected<MaxStreamDataFrame, QuicError> decodeMaxStreamDataFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "streamId");
  QUIC_TRY_DECODE_INT(offset, cursor, "offset");
  return MaxStreamDataFrame(streamId, offset);
}

quic::Expected<MaxStreamsFrame, QuicError> decodeBiDiMaxStreamsFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamCount, cursor, "bi-directional stream count");
  if (streamCount > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad bi-directional stream count"));
  }
  return MaxStreamsFrame(streamCount, true /* isBidirectional*/);
}

quic::Expected<MaxStreamsFrame, QuicError> decodeUniMaxStreamsFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamCount, cursor, "uni-directional stream count");
  if (streamCount > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad uni-directional stream count"));
  }
  return MaxStreamsFrame(streamCount, false /* isUnidirectional */);
}

quic::Expected<DataBlockedFrame, QuicError> decodeDataBlockedFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(dataLimit, cursor, "data limit");
  return DataBlockedFrame(dataLimit);
}

quic::Expected<StreamDataBlockedFrame, QuicError> decodeStreamDataBlockedFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "streamId");
  QUIC_TRY_DECODE_INT(dataLimit, cursor, "data limit");
  return StreamDataBlockedFrame(streamId, dataLimit);
}

quic::Expected<StreamsBlockedFrame, QuicError> decodeBiDiStreamsBlockedFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "bi-directional streamId");
  return StreamsBlockedFrame(streamId, true /* isBidirectional */);
}

quic::Expected<StreamsBlockedFrame, QuicError> decodeUniStreamsBlockedFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(streamId, cursor, "uni-directional streamId");
  return StreamsBlockedFrame(streamId, false /* isBidirectional */);
}

quic::Expected<NewConnectionIdFrame, QuicError> decodeNewConnectionIdFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(sequenceNumber, cursor, "sequence number");
  QUIC_TRY_DECODE_INT(retirePriorTo, cursor, "retire prior to");
  uint8_t connIdLen = 0;
  if (!cursor.tryReadBE(connIdLen)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read Dest. ConnectionId"));
  }
  if (cursor.remaining() < connIdLen) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR, "Bad connid"));
  }
  if (connIdLen == 0 || connIdLen > kMaxConnectionIdSize) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "ConnectionId invalid length"));
  }

  auto connIdResult = ConnectionId::create(cursor, connIdLen);
  if (connIdResult.hasError()) {
    return quic::make_unexpected(connIdResult.error());
  }
  ConnectionId connId = connIdResult.value();

  StatelessResetToken statelessResetToken;
  size_t bytesRead =
      cursor.pullAtMost(statelessResetToken.data(), statelessResetToken.size());
  if (bytesRead < statelessResetToken.size()) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Failed to read StatelessResetToken"));
  }

  return NewConnectionIdFrame(
      sequenceNumber,
      retirePriorTo,
      std::move(connId),
      std::move(statelessResetToken));
}

quic::Expected<RetireConnectionIdFrame, QuicError>
decodeRetireConnectionIdFrame(ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(sequenceNum, cursor, "sequence num");
  return RetireConnectionIdFrame(sequenceNum);
}

quic::Expected<PathChallengeFrame, QuicError> decodePathChallengeFrame(
    ContiguousReadCursor& cursor) {
  uint64_t pathData = 0;
  if (!cursor.tryReadBE<uint64_t>(pathData)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path challenge frame."));
  }
  return PathChallengeFrame(pathData);
}

quic::Expected<PathResponseFrame, QuicError> decodePathResponseFrame(
    ContiguousReadCursor& cursor) {
  uint64_t pathData = 0;
  if (!cursor.tryReadBE<uint64_t>(pathData)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Not enough input bytes to read path response frame."));
  }
  return PathResponseFrame(pathData);
}

quic::Expected<ConnectionCloseFrame, QuicError> decodeConnectionCloseFrame(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(varCode, cursor, "error code");
  auto errorCode = static_cast<TransportErrorCode>(varCode);

  // frameTypeField needs ->second for size check, so use raw decodeQuicInteger
  auto frameTypeField = quic::decodeQuicInteger(cursor);
  if (!frameTypeField || frameTypeField->second != sizeof(uint8_t)) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad connection close triggering frame type value"));
  }
  auto triggeringFrameType = static_cast<FrameType>(frameTypeField->first);

  QUIC_TRY_DECODE_INT(reasonPhraseLength, cursor, "reason phrase length");
  if (reasonPhraseLength > kMaxReasonPhraseLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  auto len = static_cast<size_t>(reasonPhraseLength);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase), triggeringFrameType);
}

quic::Expected<ConnectionCloseFrame, QuicError> decodeApplicationClose(
    ContiguousReadCursor& cursor) {
  QUIC_TRY_DECODE_INT(varCode, cursor, "error code");
  auto errorCode = static_cast<ApplicationErrorCode>(varCode);

  QUIC_TRY_DECODE_INT(reasonPhraseLength, cursor, "reason phrase length");
  if (reasonPhraseLength > kMaxReasonPhraseLength) {
    return quic::make_unexpected(QuicError(
        quic::TransportErrorCode::FRAME_ENCODING_ERROR,
        "Bad reason phrase length"));
  }

  std::string reasonPhrase;
  auto len = static_cast<size_t>(reasonPhraseLength);
  auto bytes = cursor.peekBytes();
  size_t available = std::min(bytes.size(), len);
  reasonPhrase.append(reinterpret_cast<const char*>(bytes.data()), available);
  cursor.skip(available);

  return ConnectionCloseFrame(
      QuicErrorCode(errorCode), std::move(reasonPhrase));
}

quic::Expected<HandshakeDoneFrame, QuicError> decodeHandshakeDoneFrame(
    ContiguousReadCursor& /*cursor*/) {
  return HandshakeDoneFrame();
}

/**
 * Both retry and new tokens have the same plaintext encoding: timestamp. We
 * differentiate tokens based on the success of decrypting with differing aead
 * associated data.
 */
quic::Expected<uint64_t, TransportErrorCode> parsePlaintextRetryOrNewToken(
    ContiguousReadCursor& cursor) {
  // Read in the timestamp
  uint64_t timestampInMs = 0;
  if (!cursor.tryReadBE<uint64_t>(timestampInMs)) {
    return quic::make_unexpected(TransportErrorCode::INVALID_TOKEN);
  }

  return timestampInMs;
}

static quic::Expected<DatagramFrame, QuicError> decodeDatagramFrameWithTypeSize(
    BufQueue& queue,
    bool hasLen,
    size_t frameTypeSize) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());
  size_t length = cursor.remaining();
  size_t encodedSize = frameTypeSize;
  if (hasLen) {
    auto decodeLength = quic::decodeQuicInteger(cursor);
    if (!decodeLength) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram len"));
    }
    length = decodeLength->first;
    if (cursor.remaining() < length) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid datagram frame"));
    }
    encodedSize += decodeLength->second;
    queue.trimStart(decodeLength->second);
  }
  encodedSize += length;
  return DatagramFrame(length, encodedSize, queue.splitAtMost(length));
}

quic::Expected<DatagramFrame, QuicError> decodeDatagramFrame(
    BufQueue& queue,
    bool hasLen) {
  return decodeDatagramFrameWithTypeSize(queue, hasLen, kDatagramFrameTypeSize);
}

quic::Expected<QuicFrame, QuicError> parseFrame(
    BufQueue& queue,
    const PacketHeader& header,
    const CodecParameters& params) {
  ContiguousReadCursor contiguousCursor(
      queue.front()->data(), queue.front()->length());
  auto frameTypeInt = quic::decodeQuicInteger(contiguousCursor);
  if (!frameTypeInt) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FRAME_ENCODING_ERROR, "Invalid frame-type field"));
  }
  queue.trimStart(contiguousCursor.getCurrentPosition());
  contiguousCursor.reset(queue.front()->data(), queue.front()->length());
  auto frameType = static_cast<FrameType>(frameTypeInt->first);

  // No more try/catch, just use Expected/make_unexpected pattern
  switch (frameType) {
    case FrameType::PADDING:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodePaddingFrame);
    case FrameType::PING:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodePingFrame);
    case FrameType::ACK: {
      auto ackFrameRes = decodeAckFrame(contiguousCursor, header, params);
      if (ackFrameRes.hasError()) {
        return ackFrameRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackFrameRes;
    }
    case FrameType::ACK_ECN: {
      auto ackFrameWithEcnRes =
          decodeAckFrameWithECN(contiguousCursor, header, params);
      if (ackFrameWithEcnRes.hasError()) {
        return ackFrameWithEcnRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackFrameWithEcnRes;
    }
    case FrameType::RST_STREAM:
    case FrameType::RST_STREAM_AT:
      return decodeFrameAndTrimBufQueue(
          queue,
          contiguousCursor,
          decodeRstStreamFrame,
          frameType == FrameType::RST_STREAM_AT);
    case FrameType::STOP_SENDING:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeStopSendingFrame);
    case FrameType::CRYPTO_FRAME:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeCryptoFrame);
    case FrameType::NEW_TOKEN:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeNewTokenFrame);
    case FrameType::STREAM:
    case FrameType::STREAM_FIN:
    case FrameType::STREAM_LEN:
    case FrameType::STREAM_LEN_FIN:
    case FrameType::STREAM_OFF:
    case FrameType::STREAM_OFF_FIN:
    case FrameType::STREAM_OFF_LEN:
    case FrameType::STREAM_OFF_LEN_FIN: {
      auto streamRes =
          decodeStreamFrame(queue, StreamTypeField(frameTypeInt->first));
      if (!streamRes.has_value()) {
        return quic::make_unexpected(streamRes.error());
      }
      return QuicFrame(*streamRes);
    }
    case FrameType::MAX_DATA:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeMaxDataFrame);
    case FrameType::MAX_STREAM_DATA:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeMaxStreamDataFrame);
    case FrameType::MAX_STREAMS_BIDI:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeBiDiMaxStreamsFrame);
    case FrameType::MAX_STREAMS_UNI:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeUniMaxStreamsFrame);
    case FrameType::DATA_BLOCKED:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeDataBlockedFrame);
    case FrameType::STREAM_DATA_BLOCKED:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeStreamDataBlockedFrame);
    case FrameType::STREAMS_BLOCKED_BIDI:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeBiDiStreamsBlockedFrame);
    case FrameType::STREAMS_BLOCKED_UNI:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeUniStreamsBlockedFrame);
    case FrameType::NEW_CONNECTION_ID:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeNewConnectionIdFrame);
    case FrameType::RETIRE_CONNECTION_ID:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeRetireConnectionIdFrame);
    case FrameType::PATH_CHALLENGE:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodePathChallengeFrame);
    case FrameType::PATH_RESPONSE:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodePathResponseFrame);
    case FrameType::CONNECTION_CLOSE:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeConnectionCloseFrame);
    case FrameType::CONNECTION_CLOSE_APP_ERR:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeApplicationClose);
    case FrameType::HANDSHAKE_DONE:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeHandshakeDoneFrame);
    case FrameType::DATAGRAM: {
      auto datagramRes = decodeDatagramFrameWithTypeSize(
          queue, false /* hasLen */, frameTypeInt->second);
      if (!datagramRes.has_value()) {
        return quic::make_unexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::DATAGRAM_LEN: {
      auto datagramRes = decodeDatagramFrameWithTypeSize(
          queue, true /* hasLen */, frameTypeInt->second);
      if (!datagramRes.has_value()) {
        return quic::make_unexpected(datagramRes.error());
      }
      return QuicFrame(*datagramRes);
    }
    case FrameType::KNOB:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeKnobFrame);
    case FrameType::ACK_FREQUENCY:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeAckFrequencyFrame);
    case FrameType::IMMEDIATE_ACK:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeImmediateAckFrame);
    case FrameType::TIMESTAMP:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeTimestampFrame, params);
    case FrameType::ACK_RECEIVE_TIMESTAMPS: {
      auto ackWithReceiveTiemstampsRes = decodeAckFrameWithReceivedTimestamps(
          contiguousCursor, header, params, FrameType::ACK_RECEIVE_TIMESTAMPS);
      if (ackWithReceiveTiemstampsRes.hasError()) {
        return ackWithReceiveTiemstampsRes;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return ackWithReceiveTiemstampsRes;
    }
    case FrameType::ACK_EXTENDED:
      return decodeFrameAndTrimBufQueue(
          queue, contiguousCursor, decodeAckExtendedFrame, header, params);
    case FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02:
    case FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN: {
      auto draft02Res = decodeAckFrameDraft02WithReceiveTimestamps(
          contiguousCursor, header, params, frameType);
      if (draft02Res.hasError()) {
        return draft02Res;
      }
      queue.trimStart(contiguousCursor.getCurrentPosition());
      return draft02Res;
    }
  }

  return quic::make_unexpected(QuicError(
      TransportErrorCode::FRAME_ENCODING_ERROR,
      fmt::format("Unknown frame, type={}", frameTypeInt->first)));
}

// Parse packet

quic::Expected<RegularQuicPacket, QuicError> decodeRegularPacket(
    PacketHeader&& header,
    const CodecParameters& params,
    BufPtr packetData) {
  RegularQuicPacket packet(std::move(header));
  BufQueue queue;
  queue.append(std::move(packetData));
  if (UNLIKELY(queue.chainLength() == 0)) {
    return packet;
  }
  // Parse out one packet before any conditionals.
  auto frameRes = parseFrame(queue, packet.header, params);
  if (!frameRes.has_value()) {
    return quic::make_unexpected(frameRes.error());
  }
  packet.frames.push_back(std::move(*frameRes));

  while (queue.chainLength() > 0) {
    auto fRes = parseFrame(queue, packet.header, params);
    if (!fRes.has_value()) {
      return quic::make_unexpected(fRes.error());
    }
    if (packet.frames.back().asPaddingFrame() && fRes->asPaddingFrame()) {
      auto& numFrames = packet.frames.back().asPaddingFrame()->numFrames;
      numFrames =
          static_cast<uint16_t>(numFrames + fRes->asPaddingFrame()->numFrames);
    } else {
      packet.frames.push_back(std::move(*fRes));
    }
  }
  return packet;
}

Optional<VersionNegotiationPacket> decodeVersionNegotiation(
    const ParsedLongHeaderInvariant& longHeaderInvariant,
    ContiguousReadCursor& cursor) {
  auto cursorLength = cursor.remaining();

  if (cursorLength < sizeof(QuicVersionType) ||
      cursorLength % sizeof(QuicVersionType)) {
    MVVLOG(4) << "Version negotiation packet invalid";
    return std::nullopt;
  }

  VersionNegotiationPacket packet(
      longHeaderInvariant.initialByte,
      longHeaderInvariant.invariant.srcConnId,
      longHeaderInvariant.invariant.dstConnId);

  while (!cursor.isAtEnd()) {
    QuicVersionType versionType = 0;
    cursor.tryReadBE(versionType);
    auto quicVersion = static_cast<QuicVersion>(versionType);
    packet.versions.push_back(quicVersion);
  }

  return packet;
}

ParsedLongHeaderResult::ParsedLongHeaderResult(
    bool isVersionNegotiationIn,
    Optional<ParsedLongHeader> parsedLongHeaderIn)
    : isVersionNegotiation(isVersionNegotiationIn),
      parsedLongHeader(std::move(parsedLongHeaderIn)) {
  MVCHECK(isVersionNegotiation || parsedLongHeader);
}

ParsedLongHeaderInvariant::ParsedLongHeaderInvariant(
    uint8_t initialByteIn,
    LongHeaderInvariant headerInvariant,
    size_t length)
    : initialByte(initialByteIn),
      invariant(std::move(headerInvariant)),
      invariantLength(length) {}

quic::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
parseLongHeaderInvariant(uint8_t initialByte, ContiguousReadCursor& cursor) {
  size_t initialLength = cursor.remaining();
  QuicVersionType versionType = 0;
  if (!cursor.tryReadBE(versionType)) {
    MVVLOG(5) << "Not enough input bytes to read Version or connection-id";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto version = static_cast<QuicVersion>(versionType);
  uint8_t destConnIdLen = 0;
  if (!cursor.tryReadBE(destConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Dest. ConnectionId length";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (destConnIdLen > kMaxConnectionIdSize) {
    MVVLOG(5) << "destConnIdLen > kMaxConnectionIdSize: " << destConnIdLen;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(destConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Dest. ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto destConnIdResult = ConnectionId::create(cursor, destConnIdLen);
  if (destConnIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId destConnId = destConnIdResult.value();
  uint8_t srcConnIdLen = 0;
  if (!cursor.tryReadBE(srcConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Source ConnectionId length";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (srcConnIdLen > kMaxConnectionIdSize) {
    MVVLOG(5) << "srcConnIdLen > kMaxConnectionIdSize: " << srcConnIdLen;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(srcConnIdLen)) {
    MVVLOG(5) << "Not enough input bytes to read Source ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto srcConnIdResult = ConnectionId::create(cursor, srcConnIdLen);
  if (srcConnIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId srcConnId = srcConnIdResult.value();
  size_t currentLength = cursor.remaining();
  size_t bytesRead = initialLength - currentLength;
  return ParsedLongHeaderInvariant(
      initialByte,
      LongHeaderInvariant(version, std::move(srcConnId), std::move(destConnId)),
      bytesRead);
}

LongHeader::Types parseLongHeaderType(uint8_t initialByte) {
  return static_cast<LongHeader::Types>(
      (initialByte & LongHeader::kPacketTypeMask) >> LongHeader::kTypeShift);
}

size_t parsePacketNumberLength(uint8_t initialByte) {
  static_assert(
      LongHeader::kPacketNumLenMask == ShortHeader::kPacketNumLenMask,
      "Expected both pn masks are the same");
  return (initialByte & LongHeader::kPacketNumLenMask) + 1;
}

/**
 * Returns the packet number and the length of the packet number
 */
std::pair<PacketNum, size_t> parsePacketNumber(
    uint8_t initialByte,
    ByteRange packetNumberRange,
    PacketNum expectedNextPacketNum) {
  size_t packetNumLen = parsePacketNumberLength(initialByte);
  uint32_t encodedPacketNum = 0;
  memcpy(
      reinterpret_cast<char*>(&encodedPacketNum) + sizeof(uint32_t) -
          packetNumLen,
      packetNumberRange.data(),
      packetNumLen);
  uint32_t bigEncodedPacketNum = folly::Endian::big(encodedPacketNum);
  return std::make_pair(
      decodePacketNumber(
          bigEncodedPacketNum, packetNumLen, expectedNextPacketNum),
      packetNumLen);
}

quic::Expected<ParsedLongHeaderResult, TransportErrorCode> parseLongHeader(
    uint8_t initialByte,
    ContiguousReadCursor& cursor) {
  if (getHeaderForm(initialByte) != HeaderForm::Long) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  LongHeader::Types type = parseLongHeaderType(initialByte);
  switch (type) {
    case LongHeader::Types::Initial:
    case LongHeader::Types::Retry:
    case LongHeader::Types::Handshake:
    case LongHeader::Types::ZeroRtt:
      break;
    default:
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto parsedLongHeaderInvariant =
      parseLongHeaderInvariant(initialByte, cursor);
  if (!parsedLongHeaderInvariant) {
    MVVLOG(5) << "Bad invariants fields in long header";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  auto version = parsedLongHeaderInvariant->invariant.version;
  if (version == QuicVersion::VERSION_NEGOTIATION) {
    return ParsedLongHeaderResult(true, std::nullopt);
  }
  auto parsedHeader = parseLongHeaderVariants(
      type, std::move(*parsedLongHeaderInvariant), cursor);
  if (!parsedHeader) {
    return quic::make_unexpected(parsedHeader.error());
  }
  return ParsedLongHeaderResult(false, std::move(*parsedHeader));
}

quic::Expected<ParsedLongHeader, TransportErrorCode> parseLongHeaderVariants(
    LongHeader::Types type,
    ParsedLongHeaderInvariant parsedLongHeaderInvariant,
    ContiguousReadCursor& cursor,
    QuicNodeType nodeType) {
  if (type == LongHeader::Types::Retry) {
    // The integrity tag is kRetryIntegrityTagLen bytes in length, and the
    // token must be at least one byte, so the remaining length must
    // be > kRetryIntegrityTagLen.
    if (cursor.remaining() <= kRetryIntegrityTagLen) {
      MVVLOG(5) << "Not enough bytes for retry token";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    size_t retryTokenLen = cursor.remaining() - kRetryIntegrityTagLen;
    BufPtr token = BufHelpers::create(retryTokenLen);
    MVCHECK(cursor.tryPull(token->writableData(), retryTokenLen));
    token->append(retryTokenLen);

    return ParsedLongHeader(
        LongHeader(
            type,
            std::move(parsedLongHeaderInvariant.invariant),
            token ? token->toString() : std::string()),
        PacketLength(0, 0));
  }

  // TODO Checking kMinInitialDestinationConnIdLength isn't necessary
  // if this packet is in response to a retry.
  if (type == LongHeader::Types::Initial && nodeType == QuicNodeType::Server &&
      parsedLongHeaderInvariant.invariant.dstConnId.size() <
          kMinInitialDestinationConnIdLength) {
    MVVLOG(5)
        << "Dest Conn-Id length in client initial packet must be >= 8 bytes.";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  BufPtr token;
  if (type == LongHeader::Types::Initial) {
    auto tokenLen = quic::decodeQuicInteger(cursor);
    if (!tokenLen) {
      MVVLOG(5) << "Token len not found in Long header";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    if (!cursor.canAdvance(tokenLen->first)) {
      MVVLOG(5) << "Not enough input bytes to read input token";
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }

    if (tokenLen->first > 0) {
      BufPtr tokenBuf = BufHelpers::create(tokenLen->first);
      MVCHECK(cursor.tryPull(tokenBuf->writableData(), tokenLen->first));
      tokenBuf->append(tokenLen->first);
      token = std::move(tokenBuf);
    }
  }
  auto pktLen = quic::decodeQuicInteger(cursor);
  if (!pktLen) {
    MVVLOG(5) << "Packet len not found in Long header";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!cursor.canAdvance(pktLen->first)) {
    MVVLOG(5) << "Not enough input bytes to read packet number";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  size_t packetNumLen =
      parsePacketNumberLength(parsedLongHeaderInvariant.initialByte);
  if (!cursor.canAdvance(packetNumLen)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (packetNumLen > kMaxPacketNumEncodingSize) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  return ParsedLongHeader(
      LongHeader(
          type,
          std::move(parsedLongHeaderInvariant.invariant),
          token ? token->toString() : std::string()),
      PacketLength(pktLen->first, pktLen->second));
}

quic::Expected<ShortHeaderInvariant, TransportErrorCode>
parseShortHeaderInvariants(
    uint8_t initialByte,
    ContiguousReadCursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  // TODO(t39154014, yangchi): read the length from the connection state in
  // draft-17
  if (dstConnIdSize > kMaxConnectionIdSize) {
    MVVLOG(5) << "dstConnIdSize > kMaxConnectionIdSize: " << dstConnIdSize;
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!cursor.canAdvance(dstConnIdSize)) {
    MVVLOG(5) << "Not enough input bytes for ConnectionId";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto connIdResult = ConnectionId::create(cursor, dstConnIdSize);
  if (connIdResult.hasError()) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  ConnectionId connId = connIdResult.value();
  return ShortHeaderInvariant(std::move(connId));
}

quic::Expected<ShortHeader, TransportErrorCode> parseShortHeader(
    uint8_t initialByte,
    ContiguousReadCursor& cursor,
    size_t dstConnIdSize) {
  if (getHeaderForm(initialByte) != HeaderForm::Short) {
    MVVLOG(5) << "Bad header form bit";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (!(initialByte & ShortHeader::kFixedBitMask)) {
    MVVLOG(5) << "Fixed bit in ShortHeader is 0";
    // Specs doesn't say which error code to use
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (initialByte & ShortHeader::kReservedBitsMask) {
    MVVLOG(5) << "Non-zero reserved bits in ShortHeader";
    // Specs asks this to be PROTOCOL_VIOLATION
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto invariant =
      parseShortHeaderInvariants(initialByte, cursor, dstConnIdSize);
  if (!invariant) {
    MVVLOG(5) << "Error parsing short header invariant";
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  auto protectionType = initialByte & ShortHeader::kKeyPhaseMask
      ? ProtectionType::KeyPhaseOne
      : ProtectionType::KeyPhaseZero;
  return ShortHeader(protectionType, std::move(invariant->destinationConnId));
}

} // namespace quic
