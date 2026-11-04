/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/QLogger.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/StateData.h>
#include <functional>

namespace quic {

/**
 * Updates the head of line blocked time for the stream. This should be called
 * on new data received or even data being read from the stream.
 * There are 2 cases when you can become head of line blocked:
 * 1. You're not previously holb. You receive new data which cannot be read.
 * 2. You are not head of line blocked. You read data from the stream, but you
 *    discover a hole.
 *
 * You can become not head of line blocked if the following conditions happen:
 * 1. You were head of line blocked, and you receive something that allows you
 *    to read from the stream.
 * 2. You were head of line blocked, but you receive a reset from the peer.
 */
static void updateHolBlockedTime(QuicStreamState& stream) {
  if (stream.readBuffer.empty() ||
      (stream.currentReadOffset == stream.readBuffer.front().offset)) {
    if (stream.lastHolbTime) {
      stream.totalHolbTime +=
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - *stream.lastHolbTime);
      stream.lastHolbTime.reset();
    }
    return;
  }

  if (stream.lastHolbTime) {
    return;
  }
  stream.lastHolbTime = Clock::now();
  stream.holbCount++;
}

static bool isStreamUnopened(
    StreamId streamId,
    StreamId nextAcceptableStreamId) {
  return streamId >= nextAcceptableStreamId;
}

static void recordNewStream(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream) {
  QUIC_STATS(conn.statsCallback, onNewQuicStream);
  if (stream.usesUnifiedSendBuffer()) {
    QUIC_STATS(conn.statsCallback, onNewUnifiedAppStream);
  }
}

// If a stream is un-opened, these automatically creates all lower streams.
// Returns false if the stream is closed or already opened.
static LocalErrorCode openPeerStreamIfNotClosed(
    StreamId streamId,
    StreamIdSet& openStreams,
    StreamId& nextAcceptableStreamId,
    StreamId maxStreamId,
    std::vector<StreamId>* newStreams) {
  if (streamId < nextAcceptableStreamId) {
    return LocalErrorCode::CREATING_EXISTING_STREAM;
  }
  if (streamId >= maxStreamId) {
    return LocalErrorCode::STREAM_LIMIT_EXCEEDED;
  }

  StreamId start = nextAcceptableStreamId;
  auto numNewStreams = (streamId - start) / detail::kStreamIncrement;
  if (newStreams) {
    newStreams->reserve(newStreams->size() + numNewStreams);
  }
  openStreams.add(start, streamId);
  while (start <= streamId) {
    if (newStreams) {
      newStreams->push_back(start);
    }
    start += detail::kStreamIncrement;
  }

  if (streamId >= nextAcceptableStreamId) {
    nextAcceptableStreamId = streamId + detail::kStreamIncrement;
  }
  return LocalErrorCode::NO_ERROR;
}

static LocalErrorCode openLocalStreamIfNotClosed(
    StreamId streamId,
    StreamIdSet& openStreams,
    StreamId& nextAcceptableStreamId,
    StreamId maxStreamId) {
  if (streamId < nextAcceptableStreamId) {
    return LocalErrorCode::CREATING_EXISTING_STREAM;
  }
  if (streamId >= maxStreamId) {
    return LocalErrorCode::STREAM_LIMIT_EXCEEDED;
  }

  openStreams.add(nextAcceptableStreamId, streamId);
  if (streamId >= nextAcceptableStreamId) {
    nextAcceptableStreamId = streamId + detail::kStreamIncrement;
  }
  return LocalErrorCode::NO_ERROR;
}

QuicStreamManager::QuicStreamManager(
    QuicConnectionStateBase& conn,
    QuicNodeType nodeType,
    const TransportSettings& transportSettings)
    : conn_(conn), nodeType_(nodeType), transportSettings_(&transportSettings) {
  if (nodeType == QuicNodeType::Server) {
    nextAcceptablePeerBidirectionalStreamId_ = 0x00;
    nextAcceptablePeerUnidirectionalStreamId_ = 0x02;
    nextAcceptableLocalBidirectionalStreamId_ = 0x01;
    nextAcceptableLocalUnidirectionalStreamId_ = 0x03;
    nextBidirectionalStreamId_ = 0x01;
    nextUnidirectionalStreamId_ = 0x03;
    initialLocalBidirectionalStreamId_ = 0x01;
    initialLocalUnidirectionalStreamId_ = 0x03;
    initialRemoteBidirectionalStreamId_ = 0x00;
    initialRemoteUnidirectionalStreamId_ = 0x02;
  } else {
    nextAcceptablePeerBidirectionalStreamId_ = 0x01;
    nextAcceptablePeerUnidirectionalStreamId_ = 0x03;
    nextAcceptableLocalBidirectionalStreamId_ = 0x00;
    nextAcceptableLocalUnidirectionalStreamId_ = 0x02;
    nextBidirectionalStreamId_ = 0x00;
    nextUnidirectionalStreamId_ = 0x02;
    initialLocalBidirectionalStreamId_ = 0x00;
    initialLocalUnidirectionalStreamId_ = 0x02;
    initialRemoteBidirectionalStreamId_ = 0x01;
    initialRemoteUnidirectionalStreamId_ = 0x03;
  }
  openBidirectionalLocalStreams_ =
      StreamIdSet(initialLocalBidirectionalStreamId_);
  openUnidirectionalLocalStreams_ =
      StreamIdSet(initialLocalUnidirectionalStreamId_);
  openBidirectionalPeerStreams_ =
      StreamIdSet(initialRemoteBidirectionalStreamId_);
  openUnidirectionalPeerStreams_ =
      StreamIdSet(initialRemoteUnidirectionalStreamId_);

  // Call refreshTransportSettings which now returns Expected
  auto refreshResult = refreshTransportSettings(transportSettings);
  if (refreshResult.hasError()) {
    // Constructor cannot return error easily. Log or handle internally.
    MVLOG_ERROR << "Failed initial transport settings refresh: "
                << refreshResult.error().message;
    // Consider throwing here if construction must fail, or setting an error
    // state. For now, logging is consistent with previous changes.
  }
}

QuicStreamManager::QuicStreamManager(
    QuicConnectionStateBase& conn,
    QuicNodeType nodeType,
    const TransportSettings& transportSettings,
    QuicStreamManager&& other)
    : conn_(conn), nodeType_(nodeType), transportSettings_(&transportSettings) {
  nextAcceptablePeerBidirectionalStreamId_ =
      other.nextAcceptablePeerBidirectionalStreamId_;
  nextAcceptablePeerUnidirectionalStreamId_ =
      other.nextAcceptablePeerUnidirectionalStreamId_;
  nextAcceptableLocalBidirectionalStreamId_ =
      other.nextAcceptableLocalBidirectionalStreamId_;
  nextAcceptableLocalUnidirectionalStreamId_ =
      other.nextAcceptableLocalUnidirectionalStreamId_;
  nextBidirectionalStreamId_ = other.nextBidirectionalStreamId_;
  nextUnidirectionalStreamId_ = other.nextUnidirectionalStreamId_;
  maxLocalBidirectionalStreamId_ = other.maxLocalBidirectionalStreamId_;
  maxLocalUnidirectionalStreamId_ = other.maxLocalUnidirectionalStreamId_;
  maxRemoteBidirectionalStreamId_ = other.maxRemoteBidirectionalStreamId_;
  maxRemoteUnidirectionalStreamId_ = other.maxRemoteUnidirectionalStreamId_;
  initialLocalBidirectionalStreamId_ = other.initialLocalBidirectionalStreamId_;
  initialLocalUnidirectionalStreamId_ =
      other.initialLocalUnidirectionalStreamId_;
  initialRemoteBidirectionalStreamId_ =
      other.initialRemoteBidirectionalStreamId_;
  initialRemoteUnidirectionalStreamId_ =
      other.initialRemoteUnidirectionalStreamId_;

  streamLimitWindowingFraction_ = other.streamLimitWindowingFraction_;
  remoteBidirectionalStreamLimitUpdate_ =
      other.remoteBidirectionalStreamLimitUpdate_;
  remoteUnidirectionalStreamLimitUpdate_ =
      other.remoteUnidirectionalStreamLimitUpdate_;
  numControlStreams_ = other.numControlStreams_;
  openBidirectionalPeerStreams_ =
      std::move(other.openBidirectionalPeerStreams_);
  openUnidirectionalPeerStreams_ =
      std::move(other.openUnidirectionalPeerStreams_);
  openBidirectionalLocalStreams_ =
      std::move(other.openBidirectionalLocalStreams_);
  openUnidirectionalLocalStreams_ =
      std::move(other.openUnidirectionalLocalStreams_);
  newPeerStreams_ = std::move(other.newPeerStreams_);
  newPeerStreamStopSendingError_ = other.newPeerStreamStopSendingError_;
  blockedStreams_ = std::move(other.blockedStreams_);
  stopSendingStreams_ = std::move(other.stopSendingStreams_);
  windowUpdates_ = std::move(other.windowUpdates_);
  flowControlUpdated_ = std::move(other.flowControlUpdated_);
  numStreamsWithLoss_ = other.numStreamsWithLoss_;
  other.numStreamsWithLoss_ = 0;
  numReadBufferRanges_ = other.numReadBufferRanges_;
  other.numReadBufferRanges_ = 0;
  readableStreams_ = std::move(other.readableStreams_);
  peekableStreams_ = std::move(other.peekableStreams_);
  writeQueue_ = std::move(other.writeQueue_);
  controlWriteQueue_ = std::move(other.controlWriteQueue_);
  txStreams_ = std::move(other.txStreams_);
  deliverableStreams_ = std::move(other.deliverableStreams_);
  closedStreams_ = std::move(other.closedStreams_);
  isAppIdle_ = other.isAppIdle_;
  maxLocalBidirectionalStreamIdIncreased_ =
      other.maxLocalBidirectionalStreamIdIncreased_;
  maxLocalUnidirectionalStreamIdIncreased_ =
      other.maxLocalUnidirectionalStreamIdIncreased_;

  for (auto& pair : other.streams_) {
    streams_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(pair.first),
        std::forward_as_tuple(
            conn_, // Use the new conn ref
            std::move(pair.second)));
  }
  // Call refreshTransportSettings which now returns Expected
  auto refreshResult = refreshTransportSettings(transportSettings);
  if (refreshResult.hasError()) {
    // Constructor cannot return error easily. Log or handle internally.
    MVLOG_ERROR << "Failed initial transport settings refresh: "
                << refreshResult.error().message;
    // Consider throwing here if construction must fail, or setting an error
    // state. For now, logging is consistent with previous changes.
  }
}

uint64_t QuicStreamManager::openableLocalBidirectionalStreams() {
  MVCHECK_GE(
      maxLocalBidirectionalStreamId_,
      nextAcceptableLocalBidirectionalStreamId_);
  return (maxLocalBidirectionalStreamId_ -
          nextAcceptableLocalBidirectionalStreamId_) /
      detail::kStreamIncrement;
}

uint64_t QuicStreamManager::openableLocalUnidirectionalStreams() {
  MVCHECK_GE(
      maxLocalUnidirectionalStreamId_,
      nextAcceptableLocalUnidirectionalStreamId_);
  return (maxLocalUnidirectionalStreamId_ -
          nextAcceptableLocalUnidirectionalStreamId_) /
      detail::kStreamIncrement;
}

uint64_t QuicStreamManager::openableRemoteBidirectionalStreams() {
  MVCHECK_GE(
      maxRemoteBidirectionalStreamId_,
      nextAcceptablePeerBidirectionalStreamId_);
  return (maxRemoteBidirectionalStreamId_ -
          nextAcceptablePeerBidirectionalStreamId_) /
      detail::kStreamIncrement;
}

uint64_t QuicStreamManager::openableRemoteUnidirectionalStreams() {
  MVCHECK_GE(
      maxRemoteUnidirectionalStreamId_,
      nextAcceptablePeerUnidirectionalStreamId_);
  return (maxRemoteUnidirectionalStreamId_ -
          nextAcceptablePeerUnidirectionalStreamId_) /
      detail::kStreamIncrement;
}

Optional<StreamId>
QuicStreamManager::nextAcceptablePeerBidirectionalStreamId() {
  const auto max = maxRemoteBidirectionalStreamId_;
  const auto next = nextAcceptablePeerBidirectionalStreamId_;
  MVCHECK_GE(max, next);
  if (max == next) {
    return std::nullopt;
  }
  return next;
}

Optional<StreamId>
QuicStreamManager::nextAcceptablePeerUnidirectionalStreamId() {
  const auto max = maxRemoteUnidirectionalStreamId_;
  const auto next = nextAcceptablePeerUnidirectionalStreamId_;
  MVCHECK_GE(max, next);
  if (max == next) {
    return std::nullopt;
  }
  return next;
}

Optional<StreamId>
QuicStreamManager::nextAcceptableLocalBidirectionalStreamId() {
  const auto max = maxLocalBidirectionalStreamId_;
  const auto next = nextAcceptableLocalBidirectionalStreamId_;
  MVCHECK_GE(max, next);
  if (max == next) {
    return std::nullopt;
  }
  return next;
}

Optional<StreamId>
QuicStreamManager::nextAcceptableLocalUnidirectionalStreamId() {
  const auto max = maxLocalUnidirectionalStreamId_;
  const auto next = nextAcceptableLocalUnidirectionalStreamId_;
  MVCHECK_GE(max, next);
  if (max == next) {
    return std::nullopt;
  }
  return next;
}

void QuicStreamManager::streamStateForEach(
    FunctionRef<void(QuicStreamState&)> f) {
  for (auto& s : streams_) {
    f(s.second);
  }
}

std::vector<StreamId> QuicStreamManager::openReceiveStreamIds() const {
  std::vector<StreamId> streamIds;
  streamIds.reserve(
      openBidirectionalPeerStreams_.size() +
      openUnidirectionalPeerStreams_.size() +
      openBidirectionalLocalStreams_.size());
  openBidirectionalPeerStreams_.appendTo(streamIds);
  openUnidirectionalPeerStreams_.appendTo(streamIds);
  openBidirectionalLocalStreams_.appendTo(streamIds);
  return streamIds;
}

void QuicStreamManager::updateReadBufferRanges(size_t before, size_t after) {
  if (after >= before) {
    numReadBufferRanges_ += after - before;
    return;
  }
  const auto decrement = before - after;
  PROTO_OOPS_LOG_IF(
      decrement > numReadBufferRanges_,
      proto_oops::getThreadLocalOopsLogger(),
      "quic_stream_manager",
      "read buffer range count underflow");
  MVDCHECK_GE(numReadBufferRanges_, decrement);
  numReadBufferRanges_ -= decrement;
}

void QuicStreamManager::removeLoss(StreamId id) {
  auto* stream = findStream(id);
  if (stream && stream->inLossSet_) {
    stream->inLossSet_ = false;
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && numStreamsWithLoss_ == 0,
        conn_.oopsLogger,
        proto_oops::OopsFieldsBuilder().setStreamId(id),
        "quic_stream_manager",
        "loss stream count underflow");
    MVCHECK_GT(numStreamsWithLoss_, 0);
    numStreamsWithLoss_--;
  }
}

void QuicStreamManager::addLoss(StreamId id) {
  auto* stream = findStream(id);
  if (stream && !stream->inLossSet_) {
    stream->inLossSet_ = true;
    numStreamsWithLoss_++;
  }
}

void QuicStreamManager::removeWritable(const QuicStreamState& stream) {
  if (stream.isControl) {
    controlWriteQueue_.erase(stream.id);
  } else {
    writeQueue().erase(PriorityQueue::Identifier::fromStreamID(stream.id));
    connFlowControlBlocked_.erase(stream.id);
  }
  // Note: Loss counter is handled separately via removeLoss() when the stream
  // is actually being cleaned up. We don't update it here because:
  // 1. The stream is const so we can't update inLossSet_
  // 2. removeLoss() needs to be called to properly sync the flag and counter
}

void QuicStreamManager::clearWritable() {
  writeQueue().clear();
  controlWriteQueue_.clear();
}

void QuicStreamManager::setStreamLimitWindowingFraction(uint64_t fraction) {
  if (fraction > 0) {
    streamLimitWindowingFraction_ = fraction;
  }
}

Optional<uint64_t> QuicStreamManager::remoteBidirectionalStreamLimitUpdate() {
  auto ret = remoteBidirectionalStreamLimitUpdate_;
  remoteBidirectionalStreamLimitUpdate_.reset();
  return ret;
}

Optional<uint64_t> QuicStreamManager::remoteUnidirectionalStreamLimitUpdate() {
  auto ret = remoteUnidirectionalStreamLimitUpdate_;
  remoteUnidirectionalStreamLimitUpdate_.reset();
  return ret;
}

Optional<StreamId> QuicStreamManager::popDeliverable() {
  auto itr = deliverableStreams_.begin();
  if (itr == deliverableStreams_.end()) {
    return std::nullopt;
  }
  StreamId ret = *itr;
  deliverableStreams_.erase(itr);
  return ret;
}

Optional<StreamId> QuicStreamManager::popTx() {
  auto itr = txStreams_.begin();
  if (itr == txStreams_.end()) {
    return std::nullopt;
  } else {
    StreamId ret = *itr;
    txStreams_.erase(itr);
    return ret;
  }
}

std::vector<StreamId> QuicStreamManager::consumeFlowControlUpdated() {
  std::vector<StreamId> result(
      flowControlUpdated_.begin(), flowControlUpdated_.end());
  flowControlUpdated_.clear();
  return result;
}

Optional<StreamId> QuicStreamManager::popFlowControlUpdated() {
  auto itr = flowControlUpdated_.begin();
  if (itr == flowControlUpdated_.end()) {
    return std::nullopt;
  } else {
    StreamId ret = *itr;
    flowControlUpdated_.erase(itr);
    return ret;
  }
}

std::vector<StreamId> QuicStreamManager::consumeNewPeerStreams() {
  std::vector<StreamId> res{std::move(newPeerStreams_)};
  return res;
}

std::vector<std::pair<const StreamId, const ApplicationErrorCode>>
QuicStreamManager::consumeStopSending() {
  std::vector<std::pair<const StreamId, const ApplicationErrorCode>> result(
      stopSendingStreams_.begin(), stopSendingStreams_.end());
  stopSendingStreams_.clear();
  return result;
}

void QuicStreamManager::clearActionable() {
  deliverableStreams_.clear();
  txStreams_.clear();
  readableStreams_.clear();
  peekableStreams_.clear();
  flowControlUpdated_.clear();
}

void QuicStreamManager::addConnFCBlockedStream(StreamId id) {
  connFlowControlBlocked_.insert(id);
}

void QuicStreamManager::onMaxData() {
  for (auto id : connFlowControlBlocked_) {
    auto stream = findStream(id);
    // Skip streams that drained (or were reset) while blocked: re-adding one
    // with nothing to write leaves a stale write-queue entry that spins the
    // write loop (shouldWriteData keeps returning STREAM).
    if (stream && stream->hasSchedulableData(true)) {
      writeQueue().insertOrUpdate(
          PriorityQueue::Identifier::fromStreamID(id), stream->priority);
    }
  }
  connFlowControlBlocked_.clear();
}

bool QuicStreamManager::streamExists(StreamId streamId) {
  if (isLocalStream(nodeType_, streamId)) {
    if (isUnidirectionalStream(streamId)) {
      return openUnidirectionalLocalStreams_.contains(streamId);
    } else {
      return openBidirectionalLocalStreams_.contains(streamId);
    }
  } else {
    if (isUnidirectionalStream(streamId)) {
      return openUnidirectionalPeerStreams_.contains(streamId);
    } else {
      return openBidirectionalPeerStreams_.contains(streamId);
    }
  }
}

QuicStreamState* QuicStreamManager::findStream(StreamId streamId) {
  auto lookup = streams_.find(streamId);
  if (lookup == streams_.end()) {
    return nullptr;
  } else {
    return &lookup->second;
  }
}

QuicStreamState* QuicStreamManager::getStreamIfExists(StreamId streamId) {
  // Fast path: state already materialized (common case)
  auto* stream = findStream(streamId);
  if (stream) {
    return stream;
  }

  // Slow path: check if stream exists but state not materialized
  if (!streamExists(streamId)) {
    return nullptr; // Stream doesn't exist or was closed
  }

  // Stream exists in open set but state needs lazy materialization
  auto result = getStream(streamId);
  if (!result.has_value()) {
    // Error materializing state (should be rare)
    return nullptr;
  }
  // At this point result.value() should never be nullptr because:
  // - We verified streamExists() is true (stream is in open set)
  // - getStream() only returns nullptr for closed streams
  // - Closed streams are removed from open sets
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && result.value() == nullptr,
      conn_.oopsLogger,
      proto_oops::OopsFieldsBuilder().setStreamId(streamId),
      "quic_stream_manager",
      "known stream materialized as null");
  MVDCHECK(result.value() != nullptr);
  return result.value();
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxLocalBidirectionalStreams(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialLocalBidirectionalStreamId_;
  if (force || maxStreamId > maxLocalBidirectionalStreamId_) {
    maxLocalBidirectionalStreamId_ = maxStreamId;
    maxLocalBidirectionalStreamIdIncreased_ = true;
  }
  return {};
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxLocalUnidirectionalStreams(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialLocalUnidirectionalStreamId_;
  if (force || maxStreamId > maxLocalUnidirectionalStreamId_) {
    maxLocalUnidirectionalStreamId_ = maxStreamId;
    maxLocalUnidirectionalStreamIdIncreased_ = true;
  }
  return {};
}

// Public API now returns Expected to propagate internal errors
quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteBidirectionalStreams(uint64_t maxStreams) {
  return setMaxRemoteBidirectionalStreamsInternal(maxStreams, false);
}

// Public API now returns Expected to propagate internal errors
quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteUnidirectionalStreams(uint64_t maxStreams) {
  return setMaxRemoteUnidirectionalStreamsInternal(maxStreams, false);
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteBidirectionalStreamsInternal(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialRemoteBidirectionalStreamId_;
  if (force || maxStreamId > maxRemoteBidirectionalStreamId_) {
    maxRemoteBidirectionalStreamId_ = maxStreamId;
  }
  return {};
}

quic::Expected<void, QuicError>
QuicStreamManager::setMaxRemoteUnidirectionalStreamsInternal(
    uint64_t maxStreams,
    bool force) {
  if (maxStreams > kMaxMaxStreams) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Attempt to set maxStreams beyond the max allowed."));
  }
  StreamId maxStreamId = maxStreams * detail::kStreamIncrement +
      initialRemoteUnidirectionalStreamId_;
  if (force || maxStreamId > maxRemoteUnidirectionalStreamId_) {
    maxRemoteUnidirectionalStreamId_ = maxStreamId;
  }
  return {};
}

bool QuicStreamManager::consumeMaxLocalBidirectionalStreamIdIncreased() {
  bool res = maxLocalBidirectionalStreamIdIncreased_;
  maxLocalBidirectionalStreamIdIncreased_ = false;
  return res;
}

bool QuicStreamManager::consumeMaxLocalUnidirectionalStreamIdIncreased() {
  bool res = maxLocalUnidirectionalStreamIdIncreased_;
  maxLocalUnidirectionalStreamIdIncreased_ = false;
  return res;
}

quic::Expected<void, LocalErrorCode> QuicStreamManager::setPriorityQueue(
    std::unique_ptr<PriorityQueue> queue) {
  // Drain-and-reinsert in one pass by moving items directly into the new queue.
  // Use default (uninitialized) priority
  auto newQueue = std::move(queue);
  while (!writeQueue().empty()) {
    auto id = writeQueue().peekNextScheduledID();
    newQueue->insertOrUpdate(id, PriorityQueue::Priority{});
    writeQueue().erase(id);
  }
  writeQueue_ = std::move(newQueue);
  return {};
}

bool QuicStreamManager::setStreamPriority(
    StreamId id,
    const PriorityQueue::Priority& newPriority,
    bool connFlowControlOpen) {
  auto stream = findStream(id);
  if (stream) {
    if (writeQueue().equalPriority(stream->priority, newPriority)) {
      return false;
    }
    stream->priority = newPriority;
    updateWritableStreams(*stream, connFlowControlOpen);
    QLOG(
        conn_,
        addPriorityUpdate,
        id,
        writeQueue().toLogFields(stream->priority));
    return true;
  }
  return false;
}

quic::Expected<void, QuicError> QuicStreamManager::refreshTransportSettings(
    const TransportSettings& settings) {
  transportSettings_ = &settings;
  auto resultBidi = setMaxRemoteBidirectionalStreamsInternal(
      transportSettings_->advertisedInitialMaxStreamsBidi, true);
  if (!resultBidi.has_value()) {
    // Propagate the error
    return quic::make_unexpected(resultBidi.error());
  }
  auto resultUni = setMaxRemoteUnidirectionalStreamsInternal(
      transportSettings_->advertisedInitialMaxStreamsUni, true);
  if (!resultUni.has_value()) {
    // Propagate the error
    return quic::make_unexpected(resultUni.error());
  }

  if (!writeQueue_) {
    auto queue = std::make_unique<HTTPPriorityQueue>();
    queue->setDisablePausedPriority(transportSettings_->disablePausedPriority);
    writeQueue_ = std::move(queue);
  } else if (
      auto* httpQueue = dynamic_cast<HTTPPriorityQueue*>(writeQueue_.get())) {
    httpQueue->setDisablePausedPriority(
        transportSettings_->disablePausedPriority);
  }
  return {};
}

quic::Expected<QuicStreamState*, QuicError>
QuicStreamManager::getOrCreateOpenedLocalStream(StreamId streamId) {
  auto& openLocalStreams = isUnidirectionalStream(streamId)
      ? openUnidirectionalLocalStreams_
      : openBidirectionalLocalStreams_;
  if (openLocalStreams.contains(streamId)) {
    auto it = streams_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(streamId),
        std::forward_as_tuple(streamId, conn_));
    if (!it.second) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR, "Creating an active stream"));
    }
    recordNewStream(conn_, it.first->second);
    return &it.first->second;
  }
  return nullptr;
}

quic::Expected<QuicStreamState*, QuicError> QuicStreamManager::getStream(
    StreamId streamId) {
  if (isRemoteStream(nodeType_, streamId)) {
    auto streamResult = getOrCreatePeerStream(streamId);
    // If successful (has value, which could be nullptr or a valid ptr), update
    // state.
    if (streamResult.has_value()) {
      updateAppIdleState();
    }
    // Propagate error, or return the contained value (ptr or nullptr)
    return streamResult;
  }

  // Handle local streams
  auto it = streams_.find(streamId);
  if (it != streams_.end()) {
    // Stream state already exists
    updateAppIdleState();
    return &it->second;
  }

  // Try to get/create state for an already opened (but not instantiated) local
  // stream
  auto streamResult = getOrCreateOpenedLocalStream(streamId);
  if (!streamResult.has_value()) {
    // This indicates an internal error during lazy creation
    // Propagate as QuicError
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to create local stream state"));
  }
  auto* stream = streamResult.value(); // Can be nullptr if not in open set

  // Check if the stream is genuinely unopened locally
  auto nextAcceptableStreamId = isUnidirectionalStream(streamId)
      ? nextAcceptableLocalUnidirectionalStreamId_
      : nextAcceptableLocalBidirectionalStreamId_;
  if (!stream && isStreamUnopened(streamId, nextAcceptableStreamId)) {
    // The stream ID is higher than the next acceptable one, meaning it hasn't
    // been opened yet. This was previously a throw -> return error.
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Trying to get unopened local stream"));
  }

  // If stream is null here, it means streamId < nextAcceptableStreamId
  // but it wasn't found in the `streams_` map and wasn't lazily created.
  // This implies it was previously closed and removed.
  // Returning nullptr is the correct behavior in this case.

  updateAppIdleState();
  return stream; // Can be nullptr if stream was closed
}

// Note: This function returns LocalErrorCode because it's primarily used
// internally or by APIs that expect local errors for stream creation failures.
// However, the underlying call to createStream returns QuicError, which we must
// handle.
quic::Expected<QuicStreamState*, LocalErrorCode>
QuicStreamManager::createNextBidirectionalStream() {
  auto streamResult = createStream(nextBidirectionalStreamId_);
  if (streamResult.has_value()) {
    nextBidirectionalStreamId_ += detail::kStreamIncrement;
    return streamResult.value();
  } else {
    // createStream failed, map the QuicError to a suitable LocalErrorCode
    // This mapping loses original error detail but fits the expected return
    // type. Callers needing the precise QuicError should call createStream
    // directly.
    auto& error = streamResult.error();
    MVLOG_WARNING << "createStream failed: "
                  << error.message; // Log the original error
    if (error.code == TransportErrorCode::STREAM_LIMIT_ERROR) {
      return quic::make_unexpected(LocalErrorCode::STREAM_LIMIT_EXCEEDED);
    } else if (error.code == TransportErrorCode::STREAM_STATE_ERROR) {
      return quic::make_unexpected(
          LocalErrorCode::CREATING_EXISTING_STREAM); // Or other state error?
    } else {
      return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }
}

// Note: Similar to createNextBidirectionalStream regarding LocalErrorCode
// return.
quic::Expected<QuicStreamState*, LocalErrorCode>
QuicStreamManager::createNextUnidirectionalStream() {
  auto streamResult = createStream(nextUnidirectionalStreamId_);
  if (streamResult.has_value()) {
    nextUnidirectionalStreamId_ += detail::kStreamIncrement;
    return streamResult.value();
  } else {
    // Map QuicError to LocalErrorCode
    auto& error = streamResult.error();
    MVLOG_WARNING << "createStream failed: " << error.message;
    if (error.code == TransportErrorCode::STREAM_LIMIT_ERROR) {
      return quic::make_unexpected(LocalErrorCode::STREAM_LIMIT_EXCEEDED);
    } else if (error.code == TransportErrorCode::STREAM_STATE_ERROR) {
      return quic::make_unexpected(LocalErrorCode::CREATING_EXISTING_STREAM);
    } else {
      return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }
}

QuicStreamState* FOLLY_NULLABLE
QuicStreamManager::instantiatePeerStream(StreamId streamId) {
  // Use try_emplace to avoid potential double-check issues if called directly
  auto [it, inserted] = streams_.try_emplace(streamId, streamId, conn_);

  if (inserted) {
    recordNewStream(conn_, it->second);
    if (newPeerStreamStopSendingError_) {
      it->second.markIngressRetired();
      conn_.pendingEvents.frames.emplace_back(
          StopSendingFrame(streamId, *newPeerStreamStopSendingError_));
    }
  }
  return &it->second;
}

// Returns QuicError for transport-level issues (limits, state), nullptr if
// closed.
quic::Expected<QuicStreamState*, QuicError>
QuicStreamManager::getOrCreatePeerStream(StreamId streamId) {
  // Validate stream direction based on node type
  if (nodeType_ == QuicNodeType::Client && isClientStream(streamId)) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted getting client peer stream on client"));
  } else if (nodeType_ == QuicNodeType::Server && isServerStream(streamId)) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted getting server peer stream on server"));
  } else if (!isClientStream(streamId) && !isServerStream(streamId)) {
    // Validate stream ID format itself
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR, "Invalid stream ID format"));
  }

  // Check if stream state already exists in the map
  auto peerStreamIt = streams_.find(streamId);
  if (peerStreamIt != streams_.end()) {
    return &peerStreamIt->second;
  }

  // Check if stream was previously opened (in the StreamIdSet)
  auto& openPeerStreams = isUnidirectionalStream(streamId)
      ? openUnidirectionalPeerStreams_
      : openBidirectionalPeerStreams_;
  if (openPeerStreams.contains(streamId)) {
    // Stream was already open, create the state for it lazily.
    auto* streamPtr = instantiatePeerStream(streamId);
    if (!streamPtr) {
      // Propagate internal inconsistency as QuicError
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          "Failed to instantiate known open peer stream"));
    }
    return streamPtr;
  }

  // Stream state doesn't exist and it's not marked as open yet.
  // Try to open it (and streams below it) now.
  auto& nextAcceptableStreamId = isUnidirectionalStream(streamId)
      ? nextAcceptablePeerUnidirectionalStreamId_
      : nextAcceptablePeerBidirectionalStreamId_;
  auto maxStreamId = isUnidirectionalStream(streamId)
      ? maxRemoteUnidirectionalStreamId_
      : maxRemoteBidirectionalStreamId_;

  // openPeerStreamIfNotClosed checks limits and adds to the StreamIdSet
  auto openedResult = openPeerStreamIfNotClosed(
      streamId,
      openPeerStreams,
      nextAcceptableStreamId,
      maxStreamId,
      &newPeerStreams_);

  // Check if the peer exceeded the stream limit
  if (openedResult == LocalErrorCode::STREAM_LIMIT_EXCEEDED) {
    // This was previously a throw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR, "Peer exceeded stream limit."));
  }

  // Check if stream ID was below nextAcceptable (already seen/closed)
  if (openedResult == LocalErrorCode::CREATING_EXISTING_STREAM) {
    // This means streamId < nextAcceptableStreamId, but it wasn't found in
    // streams_ map and wasn't in openPeerStreams set -> implies it was closed.
    return nullptr; // Correctly indicates a closed stream
  }

  // If we reached here, openedResult must be NO_ERROR.
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          openedResult != LocalErrorCode::NO_ERROR,
      conn_.oopsLogger,
      proto_oops::OopsFieldsBuilder().setStreamId(streamId),
      "quic_stream_manager",
      "unexpected peer stream open result");
  MVDCHECK(openedResult == LocalErrorCode::NO_ERROR);

  // Check if peer saturated the limit *after* opening this stream
  if (nextAcceptableStreamId >= maxStreamId && conn_.statsCallback) {
    auto limitSaturatedFn = isBidirectionalStream(streamId)
        ? &QuicTransportStatsCallback::onPeerMaxBidiStreamsLimitSaturated
        : &QuicTransportStatsCallback::onPeerMaxUniStreamsLimitSaturated;
    std::invoke(limitSaturatedFn, conn_.statsCallback);
  }

  // Stream(s) successfully marked as open, now instantiate the specific one
  // requested.
  auto* streamPtr = instantiatePeerStream(streamId);
  if (!streamPtr) {
    // Propagate internal inconsistency as QuicError
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to instantiate newly opened peer stream"));
  }
  return streamPtr;
}

// Returns QuicError for transport-level issues (limits, state, internal)
quic::Expected<QuicStreamState*, QuicError> QuicStreamManager::createStream(
    StreamId streamId) {
  // Validate stream direction based on node type
  if (nodeType_ == QuicNodeType::Client && !isClientStream(streamId)) {
    // Previously threw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted creating non-client stream on client"));
  } else if (nodeType_ == QuicNodeType::Server && !isServerStream(streamId)) {
    // Previously threw -> return error
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Attempted creating non-server stream on server"));
  }
  bool isUni = isUnidirectionalStream(streamId);

  // Check if stream was already implicitly opened but not yet instantiated
  auto openedStreamResult = getOrCreateOpenedLocalStream(streamId);
  if (!openedStreamResult.has_value()) {
    // Propagate internal error as QuicError
    return openedStreamResult;
  }
  if (openedStreamResult.value()) {
    // Stream was opened, now instantiated.
    return openedStreamResult.value();
  }
  // Stream doesn't exist and wasn't previously opened; try to open it now.
  auto& nextAcceptableStreamId = isUni
      ? nextAcceptableLocalUnidirectionalStreamId_
      : nextAcceptableLocalBidirectionalStreamId_;
  auto maxStreamId =
      isUni ? maxLocalUnidirectionalStreamId_ : maxLocalBidirectionalStreamId_;
  auto& openLocalStreams =
      isUni ? openUnidirectionalLocalStreams_ : openBidirectionalLocalStreams_;

  // Use openLocalStreamIfNotClosed to check limits and mark as open in
  // StreamIdSet
  auto openedResultCode = openLocalStreamIfNotClosed(
      streamId, openLocalStreams, nextAcceptableStreamId, maxStreamId);

  if (openedResultCode == LocalErrorCode::STREAM_LIMIT_EXCEEDED) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_LIMIT_ERROR,
        "Cannot create stream: limit exceeded"));
  }
  if (openedResultCode == LocalErrorCode::CREATING_EXISTING_STREAM) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Cannot create stream: already exists or closed"));
  }
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          openedResultCode != LocalErrorCode::NO_ERROR,
      conn_.oopsLogger,
      proto_oops::OopsFieldsBuilder().setStreamId(streamId),
      "quic_stream_manager",
      "unexpected local stream open result");
  MVDCHECK(openedResultCode == LocalErrorCode::NO_ERROR);

  // Stream is now officially open, instantiate its state in the map.
  auto [it, inserted] = streams_.try_emplace(streamId, streamId, conn_);

  if (!inserted) {
    // Propagate internal error as QuicError
    MVLOG_ERROR << "Failed to emplace stream " << streamId
                << " after opening check";
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to emplace stream state after opening"));
  }

  recordNewStream(conn_, it->second);
  updateAppIdleState();
  return &it->second;
}

quic::Expected<void, QuicError> QuicStreamManager::removeClosedStream(
    StreamId streamId) {
  auto it = streams_.find(streamId);
  if (it == streams_.end()) {
    MVVLOG(10) << "Trying to remove already closed stream=" << streamId;
    return {};
  }
  MVVLOG(10) << "Removing closed stream=" << streamId;
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && !it->second.inTerminalStates(),
      conn_.oopsLogger,
      proto_oops::OopsFieldsBuilder().setStreamId(streamId),
      "quic_stream_manager",
      "removing non-terminal stream");
  MVDCHECK(it->second.inTerminalStates());

  // Clear from various tracking sets
  if (conn_.pendingEvents.resets.contains(streamId)) {
    conn_.pendingEvents.resets.erase(streamId);
  }
  readableStreams_.erase(streamId);
  peekableStreams_.erase(streamId);
  removeWritable(it->second);
  // Handle loss counter - we have mutable access to the stream here
  if (it->second.inLossSet_) {
    it->second.inLossSet_ = false;
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && numStreamsWithLoss_ == 0,
        conn_.oopsLogger,
        proto_oops::OopsFieldsBuilder().setStreamId(streamId),
        "quic_stream_manager",
        "loss stream count underflow");
    MVCHECK_GT(numStreamsWithLoss_, 0);
    numStreamsWithLoss_--;
  }
  blockedStreams_.erase(streamId);
  deliverableStreams_.erase(streamId);
  txStreams_.erase(streamId);
  windowUpdates_.erase(streamId);
  stopSendingStreams_.erase(streamId);
  flowControlUpdated_.erase(streamId);
  connFlowControlBlocked_.erase(streamId);
  // Adjust control stream count if needed
  if (it->second.isControl) {
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && numControlStreams_ == 0,
        conn_.oopsLogger,
        proto_oops::OopsFieldsBuilder().setStreamId(streamId),
        "quic_stream_manager",
        "control stream count underflow");
    MVDCHECK_GT(numControlStreams_, 0);
    numControlStreams_--;
  }

  updateReadBufferRanges(it->second.readBuffer.size(), 0);

  // Erase the main stream state
  streams_.erase(it);
  QUIC_STATS(conn_.statsCallback, onQuicStreamClosed);

  // Handle stream limit updates for remote streams
  if (isRemoteStream(nodeType_, streamId)) {
    auto& openPeerStreams = isUnidirectionalStream(streamId)
        ? openUnidirectionalPeerStreams_
        : openBidirectionalPeerStreams_;
    openPeerStreams.remove(streamId);
    // Check if we should send a stream limit update. We need to send an
    // update every time we've closed a number of streams >= the set windowing
    // fraction.
    uint64_t initialStreamLimit = isUnidirectionalStream(streamId)
        ? transportSettings_->advertisedInitialMaxStreamsUni
        : transportSettings_->advertisedInitialMaxStreamsBidi;
    uint64_t streamWindow = initialStreamLimit / streamLimitWindowingFraction_;

    uint64_t openableRemoteStreams = isUnidirectionalStream(streamId)
        ? openableRemoteUnidirectionalStreams()
        : openableRemoteBidirectionalStreams();
    // The "credit" here is how much available stream space we have based on
    // what the initial stream limit was set to.
    uint64_t streamCredit =
        initialStreamLimit - openableRemoteStreams - openPeerStreams.size();
    if (streamCredit >= streamWindow) {
      if (isUnidirectionalStream(streamId)) {
        uint64_t maxStreams = (maxRemoteUnidirectionalStreamId_ -
                               initialRemoteUnidirectionalStreamId_) /
            detail::kStreamIncrement;
        auto result =
            setMaxRemoteUnidirectionalStreams(maxStreams + streamCredit);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
        remoteUnidirectionalStreamLimitUpdate_ = maxStreams + streamCredit;

      } else {
        uint64_t maxStreams = (maxRemoteBidirectionalStreamId_ -
                               initialRemoteBidirectionalStreamId_) /
            detail::kStreamIncrement;
        auto result =
            setMaxRemoteBidirectionalStreams(maxStreams + streamCredit);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
        remoteBidirectionalStreamLimitUpdate_ = maxStreams + streamCredit;
      }
    }
  } else {
    // Local stream closed, remove from local open set
    auto& openLocalStreams = isUnidirectionalStream(streamId)
        ? openUnidirectionalLocalStreams_
        : openBidirectionalLocalStreams_;
    openLocalStreams.remove(streamId);
  }

  updateAppIdleState();
  return {};
}

void QuicStreamManager::addToReadableStreams(const QuicStreamState& stream) {
  readableStreams_.emplace(stream.id);
}

void QuicStreamManager::removeFromReadableStreams(
    const QuicStreamState& stream) {
  readableStreams_.erase(stream.id);
}

void QuicStreamManager::updateReadableStreams(QuicStreamState& stream) {
  updateHolBlockedTime(stream);
  if (stream.hasReadableData() || stream.streamReadError.has_value()) {
    addToReadableStreams(stream);
  } else {
    removeFromReadableStreams(stream);
  }
}

void QuicStreamManager::updateWritableStreams(
    QuicStreamState& stream,
    bool connFlowControlOpen) {
  // Check for terminal write errors first
  if (stream.streamWriteError.has_value() && !stream.reliableSizeToPeer) {
    MVCHECK(!stream.hasLoss());
    removeWritable(stream);
    return;
  }

  // Update loss counter using state transition logic
  bool newHasLoss = stream.hasLoss();
  if (!stream.inLossSet_ && newHasLoss) {
    stream.inLossSet_ = true;
    numStreamsWithLoss_++;
  } else if (stream.inLossSet_ && !newHasLoss) {
    stream.inLossSet_ = false;
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && numStreamsWithLoss_ == 0,
        conn_.oopsLogger,
        proto_oops::OopsFieldsBuilder().setStreamId(stream.id),
        "quic_stream_manager",
        "loss stream count underflow");
    MVCHECK_GT(numStreamsWithLoss_, 0);
    numStreamsWithLoss_--;
  }

  // Update the actual scheduling queues (PriorityQueue or control set)
  if (stream.hasSchedulableData(connFlowControlOpen)) {
    if (stream.isControl) {
      controlWriteQueue_.emplace(stream.id);
    } else {
      writeQueue().insertOrUpdate(
          PriorityQueue::Identifier::fromStreamID(stream.id), stream.priority);
    }
  } else {
    // Not schedulable, remove from queues
    if (stream.isControl) {
      controlWriteQueue_.erase(stream.id);
    } else {
      writeQueue().erase(PriorityQueue::Identifier::fromStreamID(stream.id));
    }
  }
}

void QuicStreamManager::updatePeekableStreams(QuicStreamState& stream) {
  // Stream is peekable if it has data OR a read error to report via peekError()
  if (stream.hasPeekableData() || stream.streamReadError.has_value()) {
    peekableStreams_.emplace(stream.id);
  } else {
    peekableStreams_.erase(stream.id);
  }
}

void QuicStreamManager::updateAppIdleState() {
  bool currentNonCtrlStreams = hasNonCtrlStreams();
  if (isAppIdle_ && !currentNonCtrlStreams) {
    // We were app limited, and we continue to be app limited.
    return;
  } else if (!isAppIdle_ && currentNonCtrlStreams) {
    // We were not app limited, and we continue to be not app limited.
    return;
  }
  isAppIdle_ = !currentNonCtrlStreams;
  if (conn_.congestionController) {
    conn_.congestionController->setAppIdle(isAppIdle_, Clock::now());
  }
}

void QuicStreamManager::setStreamAsControl(QuicStreamState& stream) {
  if (!stream.isControl) {
    stream.isControl = true;
    numControlStreams_++;
  }
  updateAppIdleState();
}

bool QuicStreamManager::isAppIdle() const {
  return isAppIdle_;
}

void QuicStreamManager::clearOpenStreams() {
  // Call stats callback before clearing
  QUIC_STATS_FOR_EACH(
      streams().cbegin(),
      streams().cend(),
      conn_.statsCallback,
      onQuicStreamClosed);

  // Clear all stream sets and maps
  openBidirectionalLocalStreams_.clear();
  openUnidirectionalLocalStreams_.clear();
  openBidirectionalPeerStreams_.clear();
  openUnidirectionalPeerStreams_.clear();
  streams_.clear();
  numReadBufferRanges_ = 0;
}

} // namespace quic
