/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstLogging.h>
#include <quic/mvfst-config.h>

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/common/FunctionRef.h>
#include <quic/priority/PriorityQueue.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>
#include <functional>
#include <numeric>
#include <set>
#include <vector>

namespace quic {
class QLogger;

// Default priority for datagrams when scheduling with streams
extern const PriorityQueue::Priority kDefaultDatagramPriority;

namespace detail {

constexpr uint8_t kStreamIncrement = 0x04;

} // namespace detail

/*
 * Class for containing a set of stream IDs, which wraps a IntervalSet.
 * This saves space when the set contains "contiguous" stream IDs for a given
 * type. For example, 0, 4, 8, ... 400 is internally represented by a single
 * entry, [0, 400].
 */
class StreamIdSet {
 public:
  explicit StreamIdSet(StreamId base) : base_(static_cast<uint8_t>(base)) {}

  StreamIdSet() : base_(0) {}

  void add(StreamId id) {
    add(id, id);
  }

  void remove(StreamId id) {
    id -= base_;
    MVCHECK_EQ(id % detail::kStreamIncrement, 0);
    id /= detail::kStreamIncrement;
    streams_.withdraw(Interval<StreamId>(id, id));
  }

  void add(StreamId first, StreamId last) {
    first -= base_;
    last -= base_;
    MVCHECK_EQ(first % detail::kStreamIncrement, 0);
    MVCHECK_EQ(last % detail::kStreamIncrement, 0);
    first /= detail::kStreamIncrement;
    last /= detail::kStreamIncrement;
    streams_.insert(first, last);
  }

  [[nodiscard]] bool contains(StreamId id) const {
    id -= base_;
    id /= detail::kStreamIncrement;
    return streams_.contains(id, id);
  }

  [[nodiscard]] size_t size() const {
    size_t ret = 0;
    for (const auto& [start, end] : streams_) {
      ret += end - start + 1;
    }
    return ret;
  }

  void appendTo(std::vector<StreamId>& streamIds) const {
    for (const auto& [start, end] : streams_) {
      auto current = start;
      while (true) {
        streamIds.push_back(current * detail::kStreamIncrement + base_);
        if (current == end) {
          break;
        }
        ++current;
      }
    }
  }

  void clear() {
    streams_.clear();
  }

 private:
  IntervalSet<StreamId, 1, std::vector> streams_;
  uint8_t base_;
};

class QuicStreamManager {
 public:
  QuicStreamManager(
      QuicConnectionStateBase& conn,
      QuicNodeType nodeType,
      const TransportSettings& transportSettings);

  /**
   * Constructor to facilitate migration of a QuicStreamManager to another
   * QuicConnectionStateBase
   */
  QuicStreamManager(
      QuicConnectionStateBase& conn,
      QuicNodeType nodeType,
      const TransportSettings& transportSettings,
      QuicStreamManager&& other);

  /*
   * Create the state for a stream if it does not exist and return it.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError> createStream(
      StreamId streamId);

  /*
   * Create and return the state for the next available bidirectional stream.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, LocalErrorCode>
  createNextBidirectionalStream();

  /*
   * Create and return the state for the next available unidirectional stream.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, LocalErrorCode>
  createNextUnidirectionalStream();

  /*
   * Return the stream state or create it if the state has not yet been created.
   */
  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError> getStream(
      StreamId streamId);

  /*
   * Remove all the state for a stream that is being closed.
   */
  [[nodiscard]] quic::Expected<void, QuicError> removeClosedStream(
      StreamId streamId);

  /*
   * Update the current readable streams for the given stream state.
   */
  void updateReadableStreams(QuicStreamState& stream);

  /*
   * Update the current peehable streams for the given stream state.
   */
  void updatePeekableStreams(QuicStreamState& stream);

  /*
   * Update the current writable streams for the given stream state.
   */
  void updateWritableStreams(
      QuicStreamState& stream,
      bool connFlowControlOpen = true);

  /*
   * Find a open and active (we have created state for it) stream and return its
   * state.
   */
  QuicStreamState* FOLLY_NULLABLE findStream(StreamId streamId);

  /*
   * Check whether the stream exists.
   */
  bool streamExists(StreamId streamId);

  /*
   * Optimized stream lookup that handles lazy state materialization.
   *
   * Fast path: If stream state is already materialized, returns it immediately.
   * Slow path: If stream exists but state not materialized, creates state.
   *
   * Returns:
   * - Pointer to stream state if stream exists (may materialize state lazily)
   * - nullptr if stream doesn't exist or was closed
   *
   * This is the recommended replacement for streamExists() + getStream()
   * pattern. Safe for both local and remote streams.
   */
  QuicStreamState* FOLLY_NULLABLE getStreamIfExists(StreamId streamId);

  uint64_t openableLocalBidirectionalStreams();
  uint64_t openableLocalUnidirectionalStreams();
  uint64_t openableRemoteBidirectionalStreams();
  uint64_t openableRemoteUnidirectionalStreams();

  Optional<StreamId> nextAcceptablePeerBidirectionalStreamId();
  Optional<StreamId> nextAcceptablePeerUnidirectionalStreamId();
  Optional<StreamId> nextAcceptableLocalBidirectionalStreamId();
  Optional<StreamId> nextAcceptableLocalUnidirectionalStreamId();

  /*
   * Clear all the currently open streams.
   */
  void clearOpenStreams();

  /*
   * Return a const reference to the underlying container holding the stream
   * state.
   */
  [[nodiscard]] const auto& streams() const {
    return streams_;
  }

  /*
   * Call the given function on every currently open stream's state.
   */
  void streamStateForEach(FunctionRef<void(QuicStreamState&)> f);

  /*
   * Snapshot every currently open receive-capable stream ID, including peer
   * streams whose state has not yet been materialized.
   */
  [[nodiscard]] std::vector<StreamId> openReceiveStreamIds() const;

  [[nodiscard]] bool hasLoss() const noexcept {
    return numStreamsWithLoss_ > 0;
  }

  [[nodiscard]] size_t numReadBufferRanges() const noexcept {
    return numReadBufferRanges_;
  }

  void updateReadBufferRanges(size_t before, size_t after);

  void removeLoss(StreamId id);
  void addLoss(StreamId id);

  quic::Expected<void, LocalErrorCode> setPriorityQueue(
      std::unique_ptr<PriorityQueue> queue);

  /**
   * Update stream priority if the stream indicated by id exists.
   */
  bool setStreamPriority(
      StreamId id,
      const PriorityQueue::Priority& priority,
      bool connFlowControlOpen = true);

  auto& controlWriteQueue() {
    return controlWriteQueue_;
  }

  auto& writeQueue() {
    return *writeQueue_;
  }

  [[nodiscard]] bool hasWritable() const noexcept {
    return !writeQueue_->empty() || !controlWriteQueue_.empty();
  }

  void removeWritable(const QuicStreamState& stream);
  void clearWritable();

  [[nodiscard]] const auto& blockedStreams() const {
    return blockedStreams_;
  }

  void queueBlocked(StreamId streamId, uint64_t offset) {
    blockedStreams_.emplace(streamId, offset);
  }

  void removeBlocked(StreamId streamId) {
    blockedStreams_.erase(streamId);
  }

  [[nodiscard]] bool hasBlocked() const noexcept {
    return !blockedStreams_.empty();
  }

  /*
   * Set the max number of local bidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError> setMaxLocalBidirectionalStreams(
      uint64_t maxStreams,
      bool force = false);

  /*
   * Set the max number of local unidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxLocalUnidirectionalStreams(uint64_t maxStreams, bool force = false);

  /*
   * Set the max number of remote bidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteBidirectionalStreams(uint64_t maxStreams);

  /*
   * Set the max number of remote unidirectional streams.
   */
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteUnidirectionalStreams(uint64_t maxStreams);

  bool consumeMaxLocalBidirectionalStreamIdIncreased();
  bool consumeMaxLocalUnidirectionalStreamIdIncreased();

  // This function messes with the connection state and you should think very
  // hard before calling it
  [[nodiscard]] quic::Expected<void, QuicError> refreshTransportSettings(
      const TransportSettings& settings);

  void setStreamLimitWindowingFraction(uint64_t fraction);

  Optional<uint64_t> remoteBidirectionalStreamLimitUpdate();
  Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate();

  [[nodiscard]] const auto& windowUpdates() const {
    return windowUpdates_;
  }

  bool pendingWindowUpdate(StreamId streamId) {
    return windowUpdates_.count(streamId) > 0;
  }

  void queueWindowUpdate(StreamId streamId) {
    windowUpdates_.emplace(streamId);
  }

  void removeWindowUpdate(StreamId streamId) {
    windowUpdates_.erase(streamId);
  }

  [[nodiscard]] bool hasWindowUpdates() const noexcept {
    return !windowUpdates_.empty();
  }

  auto& closedStreams() {
    return closedStreams_;
  }

  void addClosed(StreamId streamId) {
    closedStreams_.insert(streamId);
  }

  [[nodiscard]] const auto& deliverableStreams() const {
    return deliverableStreams_;
  }

  void addDeliverable(StreamId streamId) {
    deliverableStreams_.insert(streamId);
  }

  void removeDeliverable(StreamId streamId) {
    deliverableStreams_.erase(streamId);
  }

  Optional<StreamId> popDeliverable();

  [[nodiscard]] bool hasDeliverable() const noexcept {
    return !deliverableStreams_.empty();
  }

  [[nodiscard]] bool deliverableContains(StreamId streamId) const noexcept {
    return deliverableStreams_.count(streamId) > 0;
  }

  [[nodiscard]] const auto& txStreams() const {
    return txStreams_;
  }

  void addTx(StreamId streamId) {
    txStreams_.insert(streamId);
  }

  void removeTx(StreamId streamId) {
    txStreams_.erase(streamId);
  }

  Optional<StreamId> popTx();

  [[nodiscard]] bool hasTx() const noexcept {
    return !txStreams_.empty();
  }

  [[nodiscard]] bool txContains(StreamId streamId) const noexcept {
    return txStreams_.count(streamId) > 0;
  }

  auto& readableStreams() {
    return readableStreams_;
  }

  auto& peekableStreams() {
    return peekableStreams_;
  }

  const auto& flowControlUpdated() {
    return flowControlUpdated_;
  }

  std::vector<StreamId> consumeFlowControlUpdated();

  void queueFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.emplace(streamId);
  }

  Optional<StreamId> popFlowControlUpdated();

  void removeFlowControlUpdated(StreamId streamId) {
    flowControlUpdated_.erase(streamId);
  }

  bool flowControlUpdatedContains(StreamId streamId) {
    return flowControlUpdated_.count(streamId) > 0;
  }

  void clearFlowControlUpdated() {
    flowControlUpdated_.clear();
  }

  auto& openBidirectionalPeerStreams() {
    return openBidirectionalPeerStreams_;
  }

  auto& openUnidirectionalPeerStreams() {
    return openUnidirectionalPeerStreams_;
  }

  auto& openUnidirectionalLocalStreams() {
    return openUnidirectionalLocalStreams_;
  }

  auto& openBidirectionalLocalStreams() {
    return openBidirectionalLocalStreams_;
  }

  auto& newPeerStreams() {
    return newPeerStreams_;
  }

  /*
   * Retires the receive side of every peer stream opened from now on.
   *
   * Each such stream's state is created retired, before any frame is applied
   * to it, and a STOP_SENDING with `error` is queued for it.
   * stopSendingAndDropIngressForAllStreams() calls this once the application
   * will read nothing more on the connection, so it cannot be undone, and a
   * later call keeps the first error.
   */
  void retireIngressOfNewPeerStreams(ApplicationErrorCode error) {
    if (!newPeerStreamStopSendingError_) {
      newPeerStreamStopSendingError_ = error;
    }
  }

  // The STOP_SENDING error that new peer streams are retired with, once
  // retireIngressOfNewPeerStreams() has been called.
  [[nodiscard]] Optional<ApplicationErrorCode> newPeerStreamStopSendingError()
      const {
    return newPeerStreamStopSendingError_;
  }

  std::vector<StreamId> consumeNewPeerStreams();

  size_t streamCount() {
    return streams_.size();
  }

  [[nodiscard]] const auto& stopSendingStreams() const {
    return stopSendingStreams_;
  }

  std::vector<std::pair<const StreamId, const ApplicationErrorCode>>
  consumeStopSending();

  void clearStopSending() {
    stopSendingStreams_.clear();
  }

  void addStopSending(StreamId streamId, ApplicationErrorCode error) {
    stopSendingStreams_.emplace(streamId, error);
  }

  bool hasNonCtrlStreams() {
    return streams_.size() != numControlStreams_;
  }

  auto numControlStreams() {
    return numControlStreams_;
  }

  void setStreamAsControl(QuicStreamState& stream);

  void clearActionable();

  [[nodiscard]] bool isAppIdle() const;

  void addConnFCBlockedStream(StreamId id);

  void onMaxData();

 private:
  void updateAppIdleState();

  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError>
  getOrCreateOpenedLocalStream(StreamId streamId);

  [[nodiscard]] quic::Expected<QuicStreamState*, QuicError>
  getOrCreatePeerStream(StreamId streamId);

  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteBidirectionalStreamsInternal(uint64_t maxStreams, bool force);
  [[nodiscard]] quic::Expected<void, QuicError>
  setMaxRemoteUnidirectionalStreamsInternal(uint64_t maxStreams, bool force);

  QuicStreamState* FOLLY_NULLABLE instantiatePeerStream(StreamId streamId);

  void addToReadableStreams(const QuicStreamState& stream);
  void removeFromReadableStreams(const QuicStreamState& stream);

  QuicConnectionStateBase& conn_;
  QuicNodeType nodeType_;

  StreamId nextAcceptablePeerBidirectionalStreamId_{0};
  StreamId nextAcceptablePeerUnidirectionalStreamId_{0};
  StreamId nextAcceptableLocalBidirectionalStreamId_{0};
  StreamId nextAcceptableLocalUnidirectionalStreamId_{0};
  StreamId nextBidirectionalStreamId_{0};
  StreamId nextUnidirectionalStreamId_{0};

  StreamId maxLocalBidirectionalStreamId_{0};
  StreamId maxLocalUnidirectionalStreamId_{0};
  StreamId maxRemoteBidirectionalStreamId_{0};
  StreamId maxRemoteUnidirectionalStreamId_{0};

  StreamId initialLocalBidirectionalStreamId_{0};
  StreamId initialLocalUnidirectionalStreamId_{0};
  StreamId initialRemoteBidirectionalStreamId_{0};
  StreamId initialRemoteUnidirectionalStreamId_{0};

  uint64_t streamLimitWindowingFraction_{2};
  Optional<uint64_t> remoteBidirectionalStreamLimitUpdate_;
  Optional<uint64_t> remoteUnidirectionalStreamLimitUpdate_;

  uint64_t numControlStreams_{0};

  StreamIdSet openBidirectionalPeerStreams_;
  StreamIdSet openUnidirectionalPeerStreams_;
  StreamIdSet openBidirectionalLocalStreams_;
  StreamIdSet openUnidirectionalLocalStreams_;

  UnorderedMap<StreamId, QuicStreamState> streams_;

  std::vector<StreamId> newPeerStreams_;

  Optional<ApplicationErrorCode> newPeerStreamStopSendingError_;

  UnorderedMap<StreamId, uint64_t> blockedStreams_; // StreamId -> offset
  UnorderedMap<StreamId, ApplicationErrorCode> stopSendingStreams_;
  UnorderedSet<StreamId> windowUpdates_;
  UnorderedSet<StreamId> flowControlUpdated_;

  // Streams that were removed from the write queue because they are blocked
  // on connection flow control.
  UnorderedSet<StreamId> connFlowControlBlocked_;

  // Counter of streams that have bytes in loss buffer
  size_t numStreamsWithLoss_{0};
  size_t numReadBufferRanges_{0};
  UnorderedSet<StreamId> readableStreams_;
  UnorderedSet<StreamId> peekableStreams_;

  std::unique_ptr<PriorityQueue> writeQueue_;
  std::set<StreamId> controlWriteQueue_;
  UnorderedSet<StreamId> txStreams_;
  UnorderedSet<StreamId> deliverableStreams_;
  UnorderedSet<StreamId> closedStreams_;

  bool isAppIdle_{false};
  const TransportSettings* FOLLY_NONNULL transportSettings_;
  bool maxLocalBidirectionalStreamIdIncreased_{false};
  bool maxLocalUnidirectionalStreamIdIncreased_{false};
};

} // namespace quic
