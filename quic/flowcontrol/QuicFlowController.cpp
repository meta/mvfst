/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/flowcontrol/QuicFlowController.h>

#include <fmt/format.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>

#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/StreamData.h>
#include <algorithm>
#include <limits>

namespace quic {
namespace {
uint64_t addAndClampToMaxVarInt(uint64_t offset, uint64_t windowSize) {
  if (offset >= kMaxVarInt || windowSize >= kMaxVarInt - offset) {
    return kMaxVarInt;
  }
  return offset + windowSize;
}

bool hasElapsedMoreThanRttMultiple(
    TimePoint startTime,
    TimePoint endTime,
    std::chrono::microseconds srtt,
    uint16_t multiple) {
  if (endTime <= startTime) {
    return false;
  }
  if (multiple == 0 || srtt <= 0us) {
    return true;
  }
  using Rep = std::chrono::microseconds::rep;
  if (srtt.count() > std::numeric_limits<Rep>::max() / multiple) {
    return false;
  }
  const auto threshold =
      std::chrono::microseconds(srtt.count() * static_cast<Rep>(multiple));
  const auto elapsed = endTime - startTime;
  const auto elapsedMicroseconds =
      std::chrono::duration_cast<std::chrono::microseconds>(elapsed);
  if (elapsedMicroseconds != threshold) {
    return elapsedMicroseconds > threshold;
  }
  return elapsed >
      std::chrono::duration_cast<TimePoint::duration>(elapsedMicroseconds);
}

Optional<uint64_t> calculateNewWindowUpdate(
    uint64_t curReadOffset,
    uint64_t curAdvertisedOffset,
    uint64_t windowSize,
    const std::chrono::microseconds& srtt,
    const TransportSettings& transportSettings,
    bool autotuneReceiveFlowControl,
    const Optional<TimePoint>& lastSendTime,
    const TimePoint& updateTime) {
  DCHECK_LE(curReadOffset, curAdvertisedOffset);
  auto nextAdvertisedOffset = addAndClampToMaxVarInt(curReadOffset, windowSize);
  if (nextAdvertisedOffset == std::min(curAdvertisedOffset, kMaxVarInt)) {
    // No change in flow control
    return std::nullopt;
  }
  bool enoughTimeElapsed = lastSendTime &&
      hasElapsedMoreThanRttMultiple(
                               *lastSendTime,
                               updateTime,
                               srtt,
                               transportSettings.flowControlRttFrequency);
  // If we are autotuning then frequent updates aren't required.
  if (!transportSettings.disableFlowControlTimeBasedUpdates &&
      enoughTimeElapsed && !autotuneReceiveFlowControl) {
    return nextAdvertisedOffset;
  }
  // The logic here is that we want to send updates when we have read
  // windowSize / flowControlWindowFrequency bytes.
  auto remaining = curAdvertisedOffset - curReadOffset;
  bool enoughWindowElapsed = [&]() {
    if (remaining > windowSize) {
      return false;
    }
    const auto frequency = transportSettings.flowControlWindowFrequency;
    return frequency != 0 && windowSize - remaining > windowSize / frequency;
  }();
  if (enoughWindowElapsed) {
    return nextAdvertisedOffset;
  }
  return std::nullopt;
}

template <typename T>
[[nodiscard]] inline quic::Expected<void, QuicError> incrementWithOverFlowCheck(
    T& num,
    T diff) {
  if (num > std::numeric_limits<T>::max() - diff) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
        "flow control state overflow"));
  }
  num += diff;
  return {};
}

template <typename T>
[[nodiscard]] inline quic::Expected<void, QuicError> decrementWithOverFlowCheck(
    T& num,
    T diff) {
  if (num < std::numeric_limits<T>::min() + diff) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
        "flow control state overflow"));
  }
  num -= diff;
  return {};
}

inline uint64_t calculateMaximumData(const QuicStreamState& stream) {
  return std::min(
      kMaxVarInt,
      std::max(
          addAndClampToMaxVarInt(
              stream.flowControlState.releasedReadOffset,
              stream.flowControlState.windowSize),
          stream.flowControlState.advertisedMaxOffset));
}

void maybeIncreaseFlowControlWindowWithLimit(
    const Optional<TimePoint>& timeOfLastFlowControlUpdate,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t maximumWindowSize,
    uint64_t& windowSize) {
  if (!timeOfLastFlowControlUpdate || srtt <= 0us ||
      updateTime <= *timeOfLastFlowControlUpdate) {
    return;
  }
  using Rep = std::chrono::microseconds::rep;
  const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
      updateTime - *timeOfLastFlowControlUpdate);
  const bool lessThanTwoRtts =
      srtt.count() > std::numeric_limits<Rep>::max() / 2 ||
      elapsed < std::chrono::microseconds(srtt.count() * 2);
  const auto windowLimit = std::min(maximumWindowSize, kMaxVarInt);
  if (lessThanTwoRtts && windowSize < windowLimit) {
    MVVLOG(10) << "increasing flow control window";
    windowSize += std::min(windowSize, windowLimit - windowSize);
  }
}

} // namespace

void maybeIncreaseFlowControlWindow(
    const Optional<TimePoint>& timeOfLastFlowControlUpdate,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t& windowSize) {
  maybeIncreaseFlowControlWindowWithLimit(
      timeOfLastFlowControlUpdate, updateTime, srtt, kMaxVarInt, windowSize);
}

namespace {

void maybeIncreaseConnectionFlowControlWindowWithLimit(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t maximumWindowSize) {
  maybeIncreaseFlowControlWindowWithLimit(
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime,
      srtt,
      maximumWindowSize,
      flowControlState.windowSize);
}

void maybeIncreaseStreamFlowControlWindowWithLimit(
    QuicStreamState::StreamFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t maximumWindowSize) {
  maybeIncreaseFlowControlWindowWithLimit(
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime,
      srtt,
      maximumWindowSize,
      flowControlState.windowSize);
}

} // namespace

void maybeIncreaseConnectionFlowControlWindow(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt) {
  maybeIncreaseConnectionFlowControlWindowWithLimit(
      flowControlState,
      updateTime,
      srtt,
      kDefaultMaxAutotunedReceiveConnFlowControlWindow);
}

void maybeIncreaseStreamFlowControlWindow(
    QuicStreamState::StreamFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt) {
  maybeIncreaseStreamFlowControlWindowWithLimit(
      flowControlState,
      updateTime,
      srtt,
      kDefaultMaxAutotunedReceiveStreamFlowControlWindow);
}

bool maybeSendConnWindowUpdate(
    QuicConnectionStateBase& conn,
    TimePoint updateTime) {
  if (conn.pendingEvents.connWindowUpdate) {
    // There is a pending flow control event already, and no point sending
    // again.
    return false;
  }
  auto& flowControlState = conn.flowControlState;
  auto newAdvertisedOffset = calculateNewWindowUpdate(
      flowControlState.sumCurReadOffset,
      flowControlState.advertisedMaxOffset,
      flowControlState.windowSize,
      conn.lossState.srtt,
      conn.transportSettings,
      conn.transportSettings.autotuneReceiveConnFlowControl,
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime);
  if (newAdvertisedOffset) {
    conn.pendingEvents.connWindowUpdate = true;
    QUIC_STATS(conn.statsCallback, onConnFlowControlUpdate);
    // Note: Flow control updates are redundant - MAX_DATA frames already
    // logged in packet events
    if (conn.transportSettings.autotuneReceiveConnFlowControl) {
      maybeIncreaseConnectionFlowControlWindowWithLimit(
          flowControlState,
          updateTime,
          conn.lossState.srtt,
          conn.transportSettings.maxAutotunedReceiveConnFlowControlWindow);
    }
    return true;
  }
  return false;
}

bool maybeSendStreamWindowUpdate(
    QuicStreamState& stream,
    TimePoint updateTime) {
  auto& flowControlState = stream.flowControlState;
  if (!stream.shouldSendFlowControl()) {
    return false;
  }
  if (stream.conn.streamManager->pendingWindowUpdate(stream.id)) {
    return false;
  }
  auto newAdvertisedOffset = calculateNewWindowUpdate(
      flowControlState.releasedReadOffset,
      flowControlState.advertisedMaxOffset,
      flowControlState.windowSize,
      stream.conn.lossState.srtt,
      stream.conn.transportSettings,
      stream.conn.transportSettings.autotuneReceiveStreamFlowControl,
      flowControlState.timeOfLastFlowControlUpdate,
      updateTime);
  if (newAdvertisedOffset) {
    if (stream.conn.transportSettings.autotuneReceiveStreamFlowControl) {
      maybeIncreaseStreamFlowControlWindowWithLimit(
          flowControlState,
          updateTime,
          stream.conn.lossState.srtt,
          stream.conn.transportSettings
              .maxAutotunedReceiveStreamFlowControlWindow);
    }
    MVVLOG(10) << "Queued flow control update for stream=" << stream.id
               << " offset=" << *newAdvertisedOffset;
    stream.conn.streamManager->queueWindowUpdate(stream.id);
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlUpdate);
    return true;
  }
  return false;
}

quic::Expected<void, QuicError> updateFlowControlOnStreamData(
    QuicStreamState& stream,
    uint64_t previousMaxOffsetObserved,
    uint64_t bufferEndOffset) {
  if (stream.flowControlState.advertisedMaxOffset < bufferEndOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FLOW_CONTROL_ERROR,
        fmt::format("Stream flow control violation on stream {}", stream.id)));
  }
  auto curMaxOffsetObserved =
      std::max(previousMaxOffsetObserved, bufferEndOffset);
  auto& connFlowControlState = stream.conn.flowControlState;
  uint64_t connMaxObservedOffset = connFlowControlState.sumMaxObservedOffset;
  auto incrementResult = incrementWithOverFlowCheck(
      connMaxObservedOffset, curMaxOffsetObserved - previousMaxOffsetObserved);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  if (connMaxObservedOffset > connFlowControlState.advertisedMaxOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FLOW_CONTROL_ERROR,
        "Connection flow control violation"));
  }
  return incrementWithOverFlowCheck(
      connFlowControlState.sumMaxObservedOffset,
      curMaxOffsetObserved - previousMaxOffsetObserved);
}

quic::Expected<void, QuicError> releaseConnReadFlowControl(
    QuicConnectionStateBase& conn,
    uint64_t bytes,
    TimePoint releaseTime) {
  auto incrementResult =
      incrementWithOverFlowCheck(conn.flowControlState.sumCurReadOffset, bytes);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  if (maybeSendConnWindowUpdate(conn, releaseTime)) {
    MVVLOG(4) << "Release trigger conn window update "
              << " readOffset=" << conn.flowControlState.sumCurReadOffset
              << " maxOffset=" << conn.flowControlState.advertisedMaxOffset
              << " window=" << conn.flowControlState.windowSize;
  }
  return {};
}

namespace {
// Releases stream and connection receive credit up to newReleasedOffset.
quic::Expected<void, QuicError> releaseReadFlowControl(
    QuicStreamState& stream,
    uint64_t newReleasedOffset,
    TimePoint releaseTime) {
  auto& releasedOffset = stream.flowControlState.releasedReadOffset;
  DCHECK_GE(newReleasedOffset, releasedOffset);
  auto bytes = newReleasedOffset - releasedOffset;
  releasedOffset = newReleasedOffset;
  auto connResult = releaseConnReadFlowControl(stream.conn, bytes, releaseTime);
  if (!connResult.has_value()) {
    return connResult;
  }
  if (maybeSendStreamWindowUpdate(stream, releaseTime)) {
    MVVLOG(4) << "Release trigger stream window update stream=" << stream.id
              << " readOffset=" << releasedOffset
              << " maxOffset=" << stream.flowControlState.advertisedMaxOffset
              << " window=" << stream.flowControlState.windowSize;
  }
  return {};
}
} // namespace

quic::Expected<void, QuicError> updateFlowControlOnRead(
    QuicStreamState& stream,
    uint64_t lastReadOffset,
    TimePoint readTime) {
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          stream.currentReadOffset < lastReadOffset,
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      "flow control read offset regression");
  DCHECK_GE(stream.currentReadOffset, lastReadOffset);
  if (stream.reliableSizeFromPeer &&
      stream.currentReadOffset >= *stream.reliableSizeFromPeer) {
    PROTO_OOPS_LOG_BUILDER_IF(
        stream.conn.nodeType == QuicNodeType::Server &&
            !stream.finalReadOffset.has_value(),
        stream.conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
            .setStreamId(stream.id)
            .setErrorCode(
                static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
        "quic_flow_controller",
        "missing final read offset on flow control read");
    MVCHECK(
        stream.finalReadOffset.has_value(),
        "We got a reset from the peer, but the finalReadOffset is not set.");
    // We've read all reliable bytes, so we can advance the currentReadOffset
    // to the final size and release everything, even in manualRead mode.
    stream.currentReadOffset = *stream.finalReadOffset;
    stream.flowControlState.manualRead = false;
    return releaseReadFlowControl(stream, *stream.finalReadOffset, readTime);
  }
  if (stream.flowControlState.manualRead) {
    return {};
  }
  return releaseReadFlowControl(stream, stream.currentReadOffset, readTime);
}

quic::Expected<void, QuicError> releaseManualReadFlowControl(
    QuicStreamState& stream,
    uint64_t bytes,
    TimePoint releaseTime) {
  DCHECK(stream.flowControlState.manualRead);
  DCHECK_LE(bytes, stream.unreleasedReadBytes());
  return releaseReadFlowControl(
      stream, stream.flowControlState.releasedReadOffset + bytes, releaseTime);
}

quic::Expected<void, QuicError> endManualReadFlowControl(
    QuicStreamState& stream,
    TimePoint releaseTime) {
  if (!stream.flowControlState.manualRead) {
    return {};
  }
  stream.flowControlState.manualRead = false;
  return releaseReadFlowControl(
      stream, stream.deliveredReadOffset(), releaseTime);
}

quic::Expected<void, QuicError> updateFlowControlOnReceiveReset(
    QuicStreamState& stream,
    TimePoint resetTime) {
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          !stream.reliableSizeFromPeer.has_value(),
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      "missing reliable size on flow control reset");
  MVCHECK(
      stream.reliableSizeFromPeer.has_value(),
      "updateFlowControlOnReceiveReset has been called, "
          << "but reliableSizeFromPeer has not been set");
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          !stream.finalReadOffset.has_value(),
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      "missing final read offset on flow control reset");
  MVCHECK(
      stream.finalReadOffset.has_value(),
      "updateFlowControlOnReceiveReset has been called, "
          << "but finalReadOffset has not been set");
  if (stream.currentReadOffset >= *stream.reliableSizeFromPeer) {
    // We only advance the currentReadOffset to the final size if the
    // application has read all of the reliable bytes. We don't do this
    // earlier because we'll buffer additional data that arrives. In manualRead
    // mode this also releases bytes that the app read but hadn't released.
    auto& releasedOffset = stream.flowControlState.releasedReadOffset;
    auto diff = *stream.finalReadOffset - releasedOffset;
    releasedOffset = *stream.finalReadOffset;
    stream.currentReadOffset = *stream.finalReadOffset;
    stream.flowControlState.manualRead = false;
    return releaseConnReadFlowControl(stream.conn, diff, resetTime);
  }
  return {};
}

quic::Expected<void, QuicError> updateFlowControlOnWriteToSocket(
    QuicStreamState& stream,
    uint64_t length) {
  auto incrementResult = incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurWriteOffset, length);
  if (!incrementResult.has_value()) {
    return incrementResult;
  }
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          stream.conn.flowControlState.sumCurStreamBufferLen < length,
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      fmt::format(
          "stream buffer underflow after socket write: "
          "sumCurStreamBufferLen={} length={}",
          stream.conn.flowControlState.sumCurStreamBufferLen,
          length));
  DCHECK_GE(stream.conn.flowControlState.sumCurStreamBufferLen, length);
  stream.conn.flowControlState.sumCurStreamBufferLen -= length;
  if (stream.conn.flowControlState.sumCurWriteOffset ==
      stream.conn.flowControlState.peerAdvertisedMaxOffset) {
    // Note: Flow control blocked events are redundant
    QUIC_STATS(stream.conn.statsCallback, onConnFlowControlBlocked);
  }
  return {};
}

quic::Expected<void, QuicError> updateFlowControlOnWriteToStream(
    QuicStreamState& stream,
    uint64_t length) {
  return incrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen, length);
}

quic::Expected<void, QuicError> updateFlowControlOnResetStream(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize) {
  uint64_t decrementAmount = 0;
  if (reliableSize && *reliableSize > 0) {
    // This is the amount of pending data that we are "throwing away"
    if (stream.writeBufferEndOffset() > *reliableSize) {
      decrementAmount += stream.writeBufferEndOffset() -
          std::max(*reliableSize, stream.nextOffsetToWrite());
    }
  } else {
    decrementAmount = stream.pendingWriteBytes();
  }

  return decrementWithOverFlowCheck(
      stream.conn.flowControlState.sumCurStreamBufferLen, decrementAmount);
}

void maybeWriteBlockAfterAPIWrite(QuicStreamState& stream) {
  maybeWriteBlockAfterAPIWrite(stream, stream.pendingWriteBytes() > 0);
}

void maybeWriteBlockAfterAPIWrite(
    QuicStreamState& stream,
    bool hadPendingWrites) {
  // Only write blocked when stream becomes blocked
  if (getSendStreamFlowControlBytesWire(stream) == 0 && !hadPendingWrites) {
    stream.conn.streamManager->queueBlocked(
        stream.id, stream.flowControlState.peerAdvertisedMaxOffset);
    // Note: Flow control blocked events are redundant
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlBlocked);
  }
}

void maybeWriteDataBlockedAfterSocketWrite(QuicConnectionStateBase& conn) {
  if (getSendConnFlowControlBytesWire(conn) == 0) {
    conn.pendingEvents.sendDataBlocked = true;
  }
  return;
}

void maybeWriteBlockAfterSocketWrite(QuicStreamState& stream) {
  // Only write blocked when the flow control bytes are used up and there are
  // still pending data
  if (stream.streamWriteError && !stream.reliableSizeToPeer) {
    // Note that we don't want to return prematurely if we've sent a reliable
    // reset to the peer, because there could still be data that we want to
    // write on the stream and we might be blocked on flow control.
    return;
  }
  if (stream.finalWriteOffset && stream.hasSentFIN()) {
    return;
  }

  bool shouldEmitStreamBlockedFrame = false;
  if (stream.conn.transportSettings.useNewStreamBlockedCondition) {
    // If we've exhausted the flow control window after the write, emit a
    // preemptive stream blocked frame.
    shouldEmitStreamBlockedFrame =
        getSendStreamFlowControlBytesWire(stream) == 0;
  } else {
    shouldEmitStreamBlockedFrame =
        getSendStreamFlowControlBytesWire(stream) == 0 &&
        stream.pendingWriteBytes() > 0;
  }

  if (shouldEmitStreamBlockedFrame &&
      !stream.flowControlState.pendingBlockedFrame) {
    stream.conn.streamManager->queueBlocked(
        stream.id, stream.flowControlState.peerAdvertisedMaxOffset);
    stream.flowControlState.pendingBlockedFrame = true;
    // Note: Flow control blocked events are redundant
    QUIC_STATS(stream.conn.statsCallback, onStreamFlowControlBlocked);
  }
}

void handleStreamWindowUpdate(
    QuicStreamState& stream,
    uint64_t maximumData,
    [[maybe_unused]] PacketNum packetNum) {
  if (stream.sendState == StreamSendState::Closed ||
      stream.sendState == StreamSendState::ResetSent) {
    // Flow control updates are not meaningful.
    return;
  }
  if (stream.flowControlState.peerAdvertisedMaxOffset <= maximumData) {
    stream.flowControlState.peerAdvertisedMaxOffset = maximumData;
    stream.flowControlState.pendingBlockedFrame = false;
    if (stream.flowControlState.peerAdvertisedMaxOffset >
        stream.writeBufferEndOffset()) {
      updateFlowControlList(stream);
    }
    stream.conn.streamManager->updateWritableStreams(
        stream, getSendConnFlowControlBytesWire(stream.conn) > 0);
    // Note: Stream window updates are redundant - MAX_STREAM_DATA frames
    // already logged in packet events
  }
  // Peer sending a smaller max offset than previously advertised is legal but
  // ignored.
}

void handleConnWindowUpdate(
    QuicConnectionStateBase& conn,
    const MaxDataFrame& frame,
    [[maybe_unused]] PacketNum packetNum) {
  if (conn.flowControlState.peerAdvertisedMaxOffset <= frame.maximumData) {
    conn.flowControlState.peerAdvertisedMaxOffset = frame.maximumData;
    conn.streamManager->onMaxData();
    // Note: Connection window updates are redundant - MAX_DATA frames already
    // logged in packet events
  }
  // Peer sending a smaller max offset than previously advertised is legal but
  // ignored.
}

void handleConnBlocked(QuicConnectionStateBase& conn) {
  conn.pendingEvents.connWindowUpdate = true;
  MVVLOG(4) << "Blocked triggered conn window update";
}

void handleStreamBlocked(QuicStreamState& stream) {
  stream.conn.streamManager->queueWindowUpdate(stream.id);
  MVVLOG(4) << "Blocked triggered stream window update stream=" << stream.id;
}

uint64_t getSendStreamFlowControlBytesWire(const QuicStreamState& stream) {
  const auto peerAdvertisedMaxOffset =
      stream.flowControlState.peerAdvertisedMaxOffset;
  const auto nextOffsetToWrite = stream.nextOffsetToWrite();
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          peerAdvertisedMaxOffset < nextOffsetToWrite,
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      fmt::format(
          "send stream flow control budget underflow: "
          "peerAdvertisedMaxOffset={} nextOffsetToWrite={} "
          "finalWriteOffset={}",
          peerAdvertisedMaxOffset,
          nextOffsetToWrite,
          stream.finalWriteOffset ? fmt::format("{}", *stream.finalWriteOffset)
                                  : std::string("none")));
  DCHECK_GE(peerAdvertisedMaxOffset, nextOffsetToWrite);
  return peerAdvertisedMaxOffset - nextOffsetToWrite;
}

uint64_t getSendStreamFlowControlBytesAPI(const QuicStreamState& stream) {
  auto sendFlowControlBytes = getSendStreamFlowControlBytesWire(stream);
  auto dataInBuffer = stream.pendingWriteBytes();
  if (dataInBuffer > sendFlowControlBytes) {
    return 0;
  } else {
    return sendFlowControlBytes - dataInBuffer;
  }
}

uint64_t getSendConnFlowControlBytesWire(const QuicConnectionStateBase& conn) {
  const auto peerAdvertisedMaxOffset =
      conn.flowControlState.peerAdvertisedMaxOffset;
  const auto sumCurWriteOffset = conn.flowControlState.sumCurWriteOffset;
  PROTO_OOPS_LOG_BUILDER_IF(
      conn.nodeType == QuicNodeType::Server &&
          peerAdvertisedMaxOffset < sumCurWriteOffset,
      conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn).setErrorCode(
          static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      fmt::format(
          "send conn flow control budget underflow: "
          "peerAdvertisedMaxOffset={} sumCurWriteOffset={}",
          peerAdvertisedMaxOffset,
          sumCurWriteOffset));
  DCHECK_GE(peerAdvertisedMaxOffset, sumCurWriteOffset);
  return peerAdvertisedMaxOffset - sumCurWriteOffset;
}

uint64_t getSendConnFlowControlBytesAPI(const QuicConnectionStateBase& conn) {
  auto connFlowControlBytes = getSendConnFlowControlBytesWire(conn);
  if (conn.flowControlState.sumCurStreamBufferLen > connFlowControlBytes) {
    return 0;
  } else {
    return connFlowControlBytes - conn.flowControlState.sumCurStreamBufferLen;
  }
}

uint64_t getRecvStreamFlowControlBytes(const QuicStreamState& stream) {
  const auto advertisedMaxOffset = stream.flowControlState.advertisedMaxOffset;
  const auto releasedOffset = stream.flowControlState.releasedReadOffset;
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          advertisedMaxOffset < releasedOffset,
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      fmt::format(
          "recv stream flow control budget underflow: "
          "advertisedMaxOffset={} releasedReadOffset={}",
          advertisedMaxOffset,
          releasedOffset));
  DCHECK_GE(advertisedMaxOffset, releasedOffset);
  return advertisedMaxOffset > releasedOffset
      ? advertisedMaxOffset - releasedOffset
      : 0;
}

uint64_t getRecvConnFlowControlBytes(const QuicConnectionStateBase& conn) {
  const auto advertisedMaxOffset = conn.flowControlState.advertisedMaxOffset;
  const auto sumCurReadOffset = conn.flowControlState.sumCurReadOffset;
  PROTO_OOPS_LOG_BUILDER_IF(
      conn.nodeType == QuicNodeType::Server &&
          advertisedMaxOffset < sumCurReadOffset,
      conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn).setErrorCode(
          static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      fmt::format(
          "recv conn flow control budget underflow: "
          "advertisedMaxOffset={} sumCurReadOffset={}",
          advertisedMaxOffset,
          sumCurReadOffset));
  DCHECK_GE(advertisedMaxOffset, sumCurReadOffset);
  return advertisedMaxOffset - sumCurReadOffset;
}

void onConnWindowUpdateSent(
    QuicConnectionStateBase& conn,
    uint64_t maximumDataSent,
    TimePoint sentTime) {
  PROTO_OOPS_LOG_BUILDER_IF(
      conn.nodeType == QuicNodeType::Server &&
          maximumDataSent < conn.flowControlState.advertisedMaxOffset,
      conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn).setErrorCode(
          static_cast<uint64_t>(LocalErrorCode::INTERNAL_ERROR)),
      "quic_flow_controller",
      "conn window update moved backward");
  DCHECK_GE(maximumDataSent, conn.flowControlState.advertisedMaxOffset);
  conn.flowControlState.advertisedMaxOffset = maximumDataSent;
  conn.flowControlState.timeOfLastFlowControlUpdate = sentTime;
  conn.pendingEvents.connWindowUpdate = false;
  MVVLOG(4) << "sent window for conn";
}

void onStreamWindowUpdateSent(
    QuicStreamState& stream,
    uint64_t maximumDataSent,
    TimePoint sentTime) {
  stream.flowControlState.advertisedMaxOffset = maximumDataSent;
  stream.flowControlState.timeOfLastFlowControlUpdate = sentTime;
  stream.conn.streamManager->removeWindowUpdate(stream.id);
  MVVLOG(4) << "sent window for stream=" << stream.id;
}

void onConnWindowUpdateLost(QuicConnectionStateBase& conn) {
  conn.pendingEvents.connWindowUpdate = true;
  MVVLOG(4) << "Loss triggered conn window update";
}

void onStreamWindowUpdateLost(QuicStreamState& stream) {
  if (!stream.shouldSendFlowControl()) {
    return;
  }
  stream.conn.streamManager->queueWindowUpdate(stream.id);
  MVVLOG(4) << "Loss triggered stream window update stream=" << stream.id;
}

void onBlockedLost(QuicStreamState& stream) {
  maybeWriteBlockAfterSocketWrite(stream);
}

void onDataBlockedLost(QuicConnectionStateBase& conn) {
  maybeWriteDataBlockedAfterSocketWrite(conn);
}

void updateFlowControlList(QuicStreamState& stream) {
  stream.conn.streamManager->queueFlowControlUpdated(stream.id);
}

void updateFlowControlStateWithSettings(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    const TransportSettings& transportSettings) {
  flowControlState.windowSize =
      transportSettings.advertisedInitialConnectionFlowControlWindow;
  flowControlState.advertisedMaxOffset =
      transportSettings.advertisedInitialConnectionFlowControlWindow;
}

MaxDataFrame generateMaxDataFrame(const QuicConnectionStateBase& conn) {
  return MaxDataFrame(
      std::min(
          kMaxVarInt,
          std::max(
              addAndClampToMaxVarInt(
                  conn.flowControlState.sumCurReadOffset,
                  conn.flowControlState.windowSize),
              conn.flowControlState.advertisedMaxOffset)));
}

MaxStreamDataFrame generateMaxStreamDataFrame(const QuicStreamState& stream) {
  return {stream.id, calculateMaximumData(stream)};
}

} // namespace quic
