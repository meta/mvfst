/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/QuicStreamFunctions.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/flowcontrol/QuicFlowController.h>

#include <algorithm>

namespace {
void prependToBuf(quic::BufPtr& buf, quic::BufPtr toAppend) {
  if (buf) {
    buf->appendToChain(std::move(toAppend));
  } else {
    buf = std::move(toAppend);
  }
}

} // namespace

namespace quic {
quic::Expected<void, QuicError>
writeDataToQuicStream(QuicStreamState& stream, BufPtr data, bool eof) {
  uint64_t len = 0;
  if (data) {
    len = data->computeChainDataLength();
  }
  const bool hadPendingWrites = stream.pendingWriteBytes() > 0;
  if (stream.streamSendBuffer) {
    if (!stream.streamSendBuffer->append(std::move(data), eof)) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INVALID_WRITE_DATA),
          "Cannot append data to the unified stream send buffer"));
    }
    if (eof) {
      stream.finalWriteOffset = stream.streamSendBuffer->tailOffset();
    }
  } else {
    stream.pendingWrites.append(data);
    stream.writeBuffer.append(std::move(data));
    if (eof) {
      auto bufferSize = stream.pendingWrites.chainLength();
      stream.finalWriteOffset = stream.currentWriteOffset + bufferSize;
    }
  }
  if (len > 0) {
    maybeWriteBlockAfterAPIWrite(stream, hadPendingWrites);
  }
  auto result = updateFlowControlOnWriteToStream(stream, len);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }
  stream.conn.streamManager->updateWritableStreams(stream);
  return {};
}

void writeDataToQuicStream(QuicCryptoStream& stream, BufPtr data) {
  stream.pendingWrites.append(data);
  stream.writeBuffer.append(std::move(data));
}

void writeDataToQuicStream(
    QuicConnectionStateBase& conn,
    QuicCryptoStream& stream,
    BufPtr data) {
  if (!stream.streamSendBuffer) {
    const bool useOwnedSendBuffer =
        conn.transportSettings.useUnifiedAppStreamSendBuffer &&
        conn.transportSettings.useNonCloningPto &&
        stream.pendingWrites.empty() && stream.writeBuffer.empty() &&
        stream.retransmissionBuffer.empty() && stream.lossBuffer.empty() &&
        stream.currentWriteOffset == 0;
    if (!useOwnedSendBuffer) {
      writeDataToQuicStream(stream, std::move(data));
      return;
    }
    stream.streamSendBuffer.emplace();
  }
  MVCHECK(
      stream.streamSendBuffer->append(std::move(data), false),
      "Cannot append data to the crypto stream send buffer");
}

static bool
retainReadBuffer(const Buf& buffer, size_t length, size_t allocationSize) {
  return length >= (allocationSize + 1) / 2 &&
      buffer.capacity() - length <= length;
}

static void copyReadBuffer(const Buf& src, uint8_t* dst) {
  const auto* current = &src;
  do {
    memcpy(dst, current->data(), current->length());
    dst += current->length();
    current = current->next();
  } while (current != &src);
}

static Buf* appendReadBuffer(BufPtr& dst, BufPtr src) {
  auto* appended = src.get();
  if (dst) {
    dst->appendToChain(std::move(src));
  } else {
    dst = std::move(src);
  }
  return appended;
}

static void pushToTail(BufPtr& dst, BufPtr src, size_t allocationSize) {
  size_t copied = 0;
  while (copied < src->length()) {
    const auto remaining = src->length() - copied;
    auto* tail = dst ? dst->prev() : nullptr;
    if (!tail || tail->tailroom() == 0 || tail->isSharedOne()) {
      if (retainReadBuffer(*src, remaining, allocationSize)) {
        src->trimStart(copied);
        appendReadBuffer(dst, std::move(src));
        return;
      }
      tail = appendReadBuffer(
          dst, BufHelpers::createCombined(std::max(allocationSize, remaining)));
    }
    const auto toCopy = std::min(tail->tailroom(), remaining);
    memcpy(tail->writableTail(), src->data() + copied, toCopy);
    tail->append(toCopy);
    copied += toCopy;
  }
}

static void pushToTail(BufQueue& dst, BufQueue&& src, size_t allocationSize) {
  const auto length = dst.chainLength() + src.chainLength();
  auto dstData = dst.move();
  auto srcData = src.move();
  if (allocationSize == 0) {
    appendReadBuffer(dstData, std::move(srcData));
  } else {
    while (srcData) {
      auto rest = srcData->pop();
      pushToTail(dstData, std::move(srcData), allocationSize);
      srcData = std::move(rest);
    }
  }
  dst = BufQueue(std::move(dstData), length);
}

static void pushToHead(BufQueue& dst, BufQueue&& src, size_t allocationSize) {
  MVCHECK_GT(allocationSize, 0, "Invalid coalescing allocation size");
  const auto sourceLength = src.chainLength();
  const auto length = dst.chainLength() + sourceLength;
  auto dstData = dst.move();
  auto prefix = src.move();

  if (dstData && !dstData->isSharedOne() &&
      dstData->headroom() >= sourceLength) {
    dstData->prepend(sourceLength);
    copyReadBuffer(*prefix, dstData->writableData());
    dst = BufQueue(std::move(dstData), length);
    return;
  }

  if (prefix->isChained() ||
      !retainReadBuffer(*prefix, sourceLength, allocationSize)) {
    const auto capacity = std::max(allocationSize, sourceLength);
    auto compact = BufHelpers::createCombined(capacity);
    compact->advance(capacity - sourceLength);
    copyReadBuffer(*prefix, compact->writableTail());
    compact->append(sourceLength);
    prefix = std::move(compact);
  }
  if (dstData) {
    prefix->appendToChain(std::move(dstData));
  }
  dstData = std::move(prefix);
  dst = BufQueue(std::move(dstData), length);
}

static void
mergeReadBufferData(BufQueue& left, BufQueue&& right, size_t allocationSize) {
  const auto leftLength = left.chainLength();
  const auto rightLength = right.chainLength();
  if (allocationSize > 0 && leftLength < allocationSize) {
    pushToHead(right, std::move(left), allocationSize);
    left = std::move(right);
    return;
  }
  if (allocationSize > 0 && rightLength < allocationSize) {
    pushToTail(left, std::move(right), allocationSize);
    return;
  }
  auto data = left.move();
  appendReadBuffer(data, right.move());
  left = BufQueue(std::move(data), leftLength + rightLength);
}

static void compactReadBufferData(
    StreamBuffer& buffer,
    uint32_t coalescingSize) {
  if (coalescingSize == 0 || buffer.data.empty()) {
    return;
  }
  const auto allocationSize =
      std::min<size_t>(coalescingSize, buffer.data.chainLength());
  BufQueue compact;
  pushToTail(compact, std::move(buffer.data), allocationSize);
  buffer.data = std::move(compact);
}

quic::Expected<void, QuicError> appendDataToReadBufferCommon(
    QuicStreamLike& stream,
    StreamBuffer buffer,
    uint32_t coalescingSize,
    size_t maxReadBufferRanges,
    FunctionRef<quic::Expected<void, QuicError>(uint64_t, uint64_t)>
        connFlowControlVisitor) {
  auto& readBuffer = stream.readBuffer;
  auto it = readBuffer.begin();

  auto bufferEndOffset = buffer.offset + buffer.data.chainLength();

  Optional<uint64_t> bufferEofOffset;
  if (buffer.eof) {
    bufferEofOffset = bufferEndOffset;
  } else if (buffer.data.chainLength() == 0) {
    MVVLOG(10) << "Empty stream without EOF";
    return {};
  }

  if (stream.finalReadOffset && bufferEofOffset &&
      *stream.finalReadOffset != *bufferEofOffset) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
        std::string("Invalid EOF")));
  } else if (bufferEofOffset) {
    // Do some consistency checks on the stream.
    if (stream.maxOffsetObserved > *bufferEofOffset) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
          std::string("EOF in middle of stream")));
    }
  } else if (stream.finalReadOffset) {
    // We did not receive a segment with an EOF set.
    if (buffer.offset + buffer.data.chainLength() > *stream.finalReadOffset) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
          std::string("Invalid data after EOF")));
    }
  }
  // Update the flow control information before changing max offset observed on
  // the stream. This runs after the consistency checks but before any stream
  // mutation, so a violation leaves the stream state untouched.
  auto flowControlResult =
      connFlowControlVisitor(stream.maxOffsetObserved, bufferEndOffset);
  if (!flowControlResult.has_value()) {
    return quic::make_unexpected(flowControlResult.error());
  }
  if (bufferEofOffset) {
    stream.finalReadOffset = bufferEofOffset;
  }
  stream.maxOffsetObserved =
      std::max(stream.maxOffsetObserved, bufferEndOffset);

  if (buffer.data.chainLength() == 0 || stream.stopSendingRequested) {
    // Nothing more to do since we already processed the EOF case.
    return {};
  }

  if (buffer.offset < stream.currentReadOffset) {
    // trim the buffer to start from stream read offset.
    buffer.data.trimStartAtMost(stream.currentReadOffset - buffer.offset);
    buffer.offset = stream.currentReadOffset;
    if (buffer.data.chainLength() == 0) {
      return {};
    }
  }

  // Nothing in the buffer, just append it.
  if (it == readBuffer.end()) {
    compactReadBufferData(buffer, coalescingSize);
    readBuffer.emplace_back(std::move(buffer));
    return {};
  }

  // Start overlap will point to the first buffer that overlaps with the
  // current buffer and End overlap will point to the last buffer that overlaps.
  // They must always be set together.
  Optional<decltype(stream.readBuffer)::iterator> startOverlap;
  Optional<decltype(stream.readBuffer)::iterator> endOverlap;

  StreamBuffer* current = &buffer;
  bool currentAlreadyInserted = false;
  bool currentDataCompacted = false;
  bool done = false;
  it = std::lower_bound(
      it,
      readBuffer.end(),
      current->offset,
      [](const StreamBuffer& listValue, uint64_t offset) {
        // First element where the end offset is > start offset of the buffer.
        return (listValue.offset + listValue.data.chainLength()) < offset;
      });

  // The invariant we're trying to maintain here is that individual
  // elements of the readBuffer are assuredly non contiguous sections
  // of the stream.
  for (; it != readBuffer.end() && !done; ++it) {
    auto currentEnd = current->offset + current->data.chainLength();
    auto itEnd = it->offset + it->data.chainLength();
    if (current->offset == it->offset && currentEnd == itEnd) {
      // Exact overlap. Done.
      done = true;
    } else if (current->offset >= it->offset && currentEnd <= itEnd) {
      // Subset overlap
      done = true;
    } else if (
        current->offset <= it->offset && currentEnd >= it->offset &&
        currentEnd <= itEnd) {
      // Left overlap. Done.
      it->data.trimStartAtMost(currentEnd - it->offset);
      if (!currentAlreadyInserted && !startOverlap && coalescingSize > 0) {
        pushToHead(it->data, std::move(current->data), coalescingSize);
        it->offset = current->offset;
        it->eof = it->eof || current->eof;
        return {};
      }
      current->eof = current->eof || it->eof;
      if (it->data.chainLength() > 0) {
        if (!currentAlreadyInserted) {
          compactReadBufferData(*current, coalescingSize);
          currentDataCompacted = true;
        }
        mergeReadBufferData(current->data, std::move(it->data), coalescingSize);
      }
      if (!startOverlap) {
        startOverlap = it;
      }
      endOverlap = it + 1;
      done = true;
    } else if (current->offset < it->offset && currentEnd < it->offset) {
      // Left, no overlap. Done.
      if (!startOverlap) {
        startOverlap = it;
        endOverlap = it;
      }
      done = true;
    } else if (current->offset <= it->offset && currentEnd > it->offset) {
      // Complete overlap. Need to move on.
      if (!startOverlap) {
        startOverlap = it;
      }
      endOverlap = it + 1;
    } else if (
        current->offset >= it->offset && current->offset <= itEnd &&
        currentEnd > itEnd) {
      // Right overlap. Not done.
      current->data.trimStartAtMost(itEnd - current->offset);
      pushToTail(it->data, std::move(current->data), coalescingSize);
      it->eof = it->eof || current->eof;
      current = &(*it);
      currentAlreadyInserted = true;
      PROTO_OOPS_LOG_IF(
          startOverlap,
          proto_oops::getThreadLocalOopsLogger(),
          "quic_stream_functions",
          "read buffer overlap state already set");
      MVDCHECK(!startOverlap);
      startOverlap = it + 1;
      endOverlap = it + 1;
    }
  }

  // Could have also been completely to the right of the last element.
  if (startOverlap && !currentAlreadyInserted) {
    PROTO_OOPS_LOG_IF(
        !endOverlap,
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "missing read buffer overlap end");
    MVDCHECK(endOverlap);
    PROTO_OOPS_LOG_IF(
        endOverlap && *startOverlap == readBuffer.end() &&
            *endOverlap != readBuffer.end(),
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "invalid read buffer overlap range");
    MVDCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    if (*startOverlap == *endOverlap && maxReadBufferRanges > 0 &&
        readBuffer.size() >= maxReadBufferRanges) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
          "Stream read buffer range limit exceeded"));
    }
    if (!currentDataCompacted) {
      compactReadBufferData(*current, coalescingSize);
    }
    auto insertIt = readBuffer.erase(*startOverlap, *endOverlap);
    readBuffer.emplace(insertIt, std::move(*current));
    return {};
  } else if (currentAlreadyInserted) {
    PROTO_OOPS_LOG_IF(
        !startOverlap,
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "missing read buffer overlap start");
    MVDCHECK(startOverlap);
    PROTO_OOPS_LOG_IF(
        !endOverlap,
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "missing read buffer overlap end");
    MVDCHECK(endOverlap);
    PROTO_OOPS_LOG_IF(
        startOverlap && endOverlap && *startOverlap == readBuffer.end() &&
            *endOverlap != readBuffer.end(),
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "invalid read buffer overlap range");
    MVDCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    readBuffer.erase(*startOverlap, *endOverlap);
    return {};
  }
  auto last = readBuffer.end() - 1;
  if (current->offset > last->offset + last->data.chainLength()) {
    if (maxReadBufferRanges > 0 && readBuffer.size() >= maxReadBufferRanges) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
          "Stream read buffer range limit exceeded"));
    }
    compactReadBufferData(*current, coalescingSize);
    readBuffer.emplace_back(std::move(*current));
  }
  return {};
}

quic::Expected<void, QuicError> appendDataToReadBuffer(
    QuicStreamState& stream,
    StreamBuffer buffer) {
  const auto rangesBefore = stream.readBuffer.size();
  auto result = appendDataToReadBufferCommon(
      stream,
      std::move(buffer),
      kReadBufferCoalescingSize,
      kMaxStreamReadBufferRanges,
      [&stream](uint64_t previousMaxOffsetObserved, uint64_t bufferEndOffset) {
        return updateFlowControlOnStreamData(
            stream, previousMaxOffsetObserved, bufferEndOffset);
      });
  auto& streamManager = *stream.conn.streamManager;
  streamManager.updateReadBufferRanges(rangesBefore, stream.readBuffer.size());
  if (!result.has_value()) {
    return result;
  }
  if (streamManager.numReadBufferRanges() > kMaxConnectionReadBufferRanges) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
        "Connection read buffer range limit exceeded"));
  }
  return {};
}

quic::Expected<void, QuicError> appendDataToReadBuffer(
    QuicCryptoStream& stream,
    StreamBuffer buffer) {
  // Check crypto buffer size limit
  auto bufferEndOffset = buffer.offset + buffer.data.chainLength();
  if (bufferEndOffset > stream.currentReadOffset &&
      bufferEndOffset - stream.currentReadOffset >
          kDefaultMaxCryptoStreamBufferSize) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
        "crypto read buffer limit exceeded"));
  }
  return appendDataToReadBufferCommon(
      stream,
      std::move(buffer),
      0,
      0,
      [](uint64_t, uint64_t) -> quic::Expected<void, QuicError> { return {}; });
}

std::pair<BufPtr, bool> readDataInOrderFromReadBuffer(
    QuicStreamLike& stream,
    uint64_t amount,
    bool sinkData) {
  auto remaining = amount;
  bool eof = false;
  BufPtr data;
  while ((amount == 0 || remaining != 0) && !stream.readBuffer.empty()) {
    auto curr = stream.readBuffer.begin();
    if (curr->offset > stream.currentReadOffset) {
      // The buffer is sorted in order of the left edge of the range,
      // if we find an item that is beyond the one we needed to read,
      // we should quit.
      break;
    }
    size_t currSize = curr->data.chainLength();

    // In the algorithm for the append function, we maintain the invariant that
    // the individual ranges are non-overlapping, thus if we get to this point,
    // we must have an offset which matches the read offset.
    PROTO_OOPS_LOG_IF(
        curr->offset != stream.currentReadOffset,
        proto_oops::getThreadLocalOopsLogger(),
        "quic_stream_functions",
        "read buffer offset mismatch");
    MVCHECK_EQ(curr->offset, stream.currentReadOffset);

    uint64_t toRead =
        std::min<uint64_t>(currSize, amount == 0 ? currSize : remaining);
    BufPtr splice;
    if (sinkData) {
      curr->data.trimStart(toRead);
    } else {
      splice = curr->data.splitAtMost(toRead);
      PROTO_OOPS_LOG_IF(
          splice->computeChainDataLength() != toRead,
          proto_oops::getThreadLocalOopsLogger(),
          "quic_stream_functions",
          "read buffer split length mismatch");
      MVDCHECK_EQ(splice->computeChainDataLength(), toRead);
    }
    curr->offset += toRead;
    if (curr->data.chainLength() == 0) {
      eof = curr->eof;
      stream.readBuffer.pop_front();
    }
    if (!sinkData) {
      prependToBuf(data, std::move(splice));
    }
    if (amount != 0) {
      remaining -= toRead;
    }
    stream.currentReadOffset += toRead;
  }
  return std::make_pair(std::move(data), eof);
}

BufPtr readDataFromCryptoStream(QuicCryptoStream& stream, uint64_t amount) {
  return readDataInOrderFromReadBuffer(stream, amount).first;
}

quic::Expected<std::pair<BufPtr, bool>, QuicError> readDataFromQuicStream(
    QuicStreamState& stream,
    uint64_t amount) {
  auto eof = stream.finalReadOffset &&
      stream.currentReadOffset >= *stream.finalReadOffset;
  if (eof) {
    if (stream.currentReadOffset == *stream.finalReadOffset) {
      stream.currentReadOffset += 1;
    }
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
    return std::make_pair(nullptr, true);
  }

  uint64_t lastReadOffset = stream.currentReadOffset;

  BufPtr data;
  const auto rangesBefore = stream.readBuffer.size();
  std::tie(data, eof) = readDataInOrderFromReadBuffer(stream, amount);
  stream.conn.streamManager->updateReadBufferRanges(
      rangesBefore, stream.readBuffer.size());
  // Update flow control before handling eof as eof is not subject to flow
  // control
  auto flowControlResult =
      updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  if (!flowControlResult.has_value()) {
    return quic::make_unexpected(flowControlResult.error());
  }
  eof = stream.finalReadOffset &&
      stream.currentReadOffset == *stream.finalReadOffset;
  if (eof) {
    stream.currentReadOffset += 1;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updatePeekableStreams(stream);
  return std::make_pair(std::move(data), eof);
}

void peekDataFromQuicStream(
    QuicStreamState& stream,
    FunctionRef<void(StreamId id, const folly::Range<PeekIterator>&)>
        peekCallback) {
  if (peekCallback) {
    peekCallback(
        stream.id,
        folly::Range<PeekIterator>(
            stream.readBuffer.cbegin(), stream.readBuffer.size()));
  }
}

/**
 * Same as readDataFromQuicStream(),
 * only releases existing data instead of returning it.
 */
quic::Expected<void, QuicError> consumeDataFromQuicStream(
    QuicStreamState& stream,
    uint64_t amount) {
  bool eof = stream.finalReadOffset &&
      stream.currentReadOffset >= *stream.finalReadOffset;
  if (eof) {
    if (stream.currentReadOffset == *stream.finalReadOffset) {
      stream.currentReadOffset++;
    }
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
    return {};
  }

  uint64_t lastReadOffset = stream.currentReadOffset;

  const auto rangesBefore = stream.readBuffer.size();
  readDataInOrderFromReadBuffer(stream, amount, true /* sinkData */);
  stream.conn.streamManager->updateReadBufferRanges(
      rangesBefore, stream.readBuffer.size());
  // Update flow control before handling eof as eof is not subject to flow
  // control
  auto flowControlResult =
      updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  if (!flowControlResult.has_value()) {
    return quic::make_unexpected(flowControlResult.error());
  }
  eof = stream.finalReadOffset &&
      stream.currentReadOffset == *stream.finalReadOffset;
  if (eof) {
    stream.currentReadOffset += 1;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updatePeekableStreams(stream);
  return {};
}

bool allBytesTillFinAcked(const QuicStreamState& stream) {
  /**
   * All bytes are acked if the following conditions are met:
   * 1. The app wrote a FIN
   * 2. We wrote the fin out to the network
   * 3. We have no bytes remaining to retransmit.
   * 4. We have no bytes left to write
   * 5. We have no bytes that are detected as lost.
   */
  if (stream.streamSendBuffer) {
    return stream.streamSendBuffer->finBuffered() &&
        stream.streamSendBuffer->allBytesAckedTill(
            stream.streamSendBuffer->tailOffset());
  }
  return stream.hasSentFIN() && stream.retransmissionBuffer.empty() &&
      stream.pendingWrites.empty() && !stream.hasLoss();
}

void appendPendingStreamReset(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    Optional<uint64_t> reliableSize) {
  /*
   * The spec mandates that with multiple RESET_STREAM_AT or RESET_STREAM
   * frames, we must use the same value of finalSize. Although we don't store
   * previous values of finalSize to ensure that we use that same value
   * throughout, we still maintain this property, due to the following facts:
   *
   * 1. We only egress a RESET_STREAM_AT or RESET_STREAM frame when all data
   * upto the reliable reset offset has been egressed.
   * 2. Subsequent resets can only reduce the reliable size, and the next
   * offset to write never moves backwards.
   *
   * Therefore, once a reset has been egressed, the next offset to write equals
   * its finalSize, and any later reset computes the same value. A reset that
   * was never egressed may be replaced with a different finalSize, since it
   * never reached the peer.
   */
  uint64_t finalSize = stream.nextOffsetToWrite();
  if (reliableSize) {
    // It's possible that we've queued up data at the socket, but haven't yet
    // written it out to the wire, so stream.currentWriteOffset could be
    // lagging behind reliableSize
    finalSize = std::max(finalSize, *reliableSize);
  }
  finalSize = std::min(
      finalSize,
      stream.finalWriteOffset.value_or(std::numeric_limits<uint64_t>::max()));

  // A later reset with a smaller reliable size replaces one that has not been
  // written yet.
  conn.pendingEvents.resets.insert_or_assign(
      stream.id, RstStreamFrame(stream.id, errorCode, finalSize, reliableSize));
}

uint64_t getLargestWriteOffsetSeen(const QuicStreamState& stream) {
  return stream.finalWriteOffset.value_or(stream.writeBufferEndOffset());
}

Optional<uint64_t> getLargestWriteOffsetTxed(const QuicStreamState& stream) {
  if (stream.streamSendBuffer && stream.streamSendBuffer->finSent()) {
    return stream.streamSendBuffer->tailOffset();
  }
  const auto nextWriteOffset = stream.nextOffsetToWrite();
  // nextWriteOffset is the next offset to transmit.
  // when 0, it indicates nothing has been written yet
  if (nextWriteOffset == 0) {
    return std::nullopt;
  }
  return nextWriteOffset - 1;
}

Optional<uint64_t> getLargestDeliverableOffset(const QuicStreamState& stream) {
  if (stream.streamSendBuffer) {
    return stream.streamSendBuffer->largestDeliverableOffset();
  }
  // If the acked intervals is not empty, then the furthest acked interval
  // starting at zero is the next offset. If there is no interval starting at
  // zero then we cannot deliver any offsets.
  if (stream.ackedIntervals.empty() ||
      stream.ackedIntervals.front().start != 0) {
    return std::nullopt;
  }
  return stream.ackedIntervals.front().end;
}

uint64_t getAckIntervalSetVersion(const QuicStreamState& stream) {
  return stream.streamSendBuffer ? stream.streamSendBuffer->ackInsertVersion()
                                 : stream.ackedIntervals.insertVersion();
}

uint64_t getNumPacketsTxWithNewData(const QuicStreamState& stream) {
  return stream.numPacketsTxWithNewData;
}

QuicCryptoStream* getCryptoStream(
    QuicCryptoState& cryptoState,
    EncryptionLevel encryptionLevel) {
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      return &cryptoState.initialStream;
    case EncryptionLevel::Handshake:
      return &cryptoState.handshakeStream;
    case EncryptionLevel::EarlyData:
      // TODO: remove this when we implement EOED for
      // draft-17.
      return &cryptoState.handshakeStream;
    case EncryptionLevel::AppData:
      return &cryptoState.oneRttStream;
    default:
      MVCHECK(false, "Unhandled EncryptionLevel");
  }
  folly::assume_unreachable();
}

quic::Expected<void, QuicError> processCryptoStreamAck(
    QuicCryptoStream& cryptoStream,
    uint64_t offset,
    uint64_t len) {
  if (cryptoStream.streamSendBuffer) {
    const auto ackResult = cryptoStream.streamSendBuffer->markAcked(
        {.offset = offset, .len = len, .fin = false});
    if (!ackResult.has_value()) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          "ACK range is not valid for the crypto stream send buffer"));
    }
    return {};
  }
  auto ackedBuffer = cryptoStream.retransmissionBuffer.find(offset);
  if (ackedBuffer == cryptoStream.retransmissionBuffer.end() ||
      ackedBuffer->second->offset != offset ||
      ackedBuffer->second->data.chainLength() != len) {
    // It's possible retransmissions of crypto data were canceled.
    return {};
  }
  cryptoStream.retransmissionBuffer.erase(ackedBuffer);
  return {};
}

void processTxStopSending(QuicStreamState& stream) {
  /**
   * The application is longer interested in ingress; this flag
   * (stopSendingRequested) ensures future ingress data will no longer be
   * buffered by the quic transport. The RecvState must still be OPEN, as we
   * need to account for flow control.
   */
  if (stream.conn.transportSettings.dropIngressOnStopSending) {
    stream.stopSendingRequested = true;
    stream.conn.streamManager->updateReadBufferRanges(
        stream.readBuffer.size(), 0);
    stream.readBuffer.clear();
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
  }
}

} // namespace quic
