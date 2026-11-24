/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/common/BufUtil.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/Expected.h>
#include <quic/priority/PriorityQueue.h>
#include <chrono>

namespace quic {

// Forward declaration
extern const PriorityQueue::Priority kDefaultDatagramPriority;

/**
 * Manages buffering and scheduling of datagrams across multiple flows.
 * This class is independent of the underlying transport (QUIC, HTTP/2, etc.)
 * and can be reused for different WebTransport implementations.
 */
class DatagramFlowManager {
 public:
  // Timestamped datagram with enqueue time for expiration. A datagram queued
  // while its flow had no deadline keeps max(): a deadline set later does not
  // reach back to age it, and a flow that never sets one never reads the
  // clock.
  struct QueuedDatagram {
    // User-provided, not `= default`: writeBuffer_ instantiates F14FastMap over
    // these nested types before gcc has evaluated their member initializers.
    // NOLINTNEXTLINE(modernize-use-equals-default)
    QueuedDatagram() {}

    BufQueue buf;
    TimePoint enqueueTime{TimePoint::max()};
    // Orders this datagram against others in the same flow; lower is sent
    // first. Equal values retain enqueue order.
    uint64_t intraFlowPriority{0};
  };

  // Per-flow datagram storage
  // Stores single datagram inline, allocates CircularDeque only when needed
  struct DatagramFlowQueue {
    QueuedDatagram single;
    std::unique_ptr<CircularDeque<QueuedDatagram>> multi;
    PriorityQueue::Priority priority{kDefaultDatagramPriority};
    std::chrono::milliseconds maxQueueTime{0}; // 0 = no timeout
    // Closing: rejects further writes and is erased once its last datagram is
    // popped. Set by closeFlow(), and at creation for ephemeral flows.
    bool draining{false};

    // NOLINTNEXTLINE(modernize-use-equals-default)
    DatagramFlowQueue() {} // Not `= default`; see QueuedDatagram above.

    ~DatagramFlowQueue() = default;

    // Move-only
    DatagramFlowQueue(DatagramFlowQueue&&) noexcept = default;
    DatagramFlowQueue& operator=(DatagramFlowQueue&&) noexcept = default;
    DatagramFlowQueue(const DatagramFlowQueue&) = delete;
    DatagramFlowQueue& operator=(const DatagramFlowQueue&) = delete;

    [[nodiscard]] bool empty() const {
      return multi ? multi->empty() : single.buf.empty();
    }

    [[nodiscard]] size_t size() const {
      return multi ? multi->size() : (single.buf.empty() ? 0 : 1);
    }

    // Inserts in ascending intraFlowPriority order, stably.
    void push(QueuedDatagram datagram);
    QueuedDatagram& front();
    void pop();
  };

  // Result of popping a datagram from a flow
  struct DatagramPopResult {
    BufPtr buf; // The datagram buffer (nullptr if doesn't fit or no datagram)
    bool flowEmpty; // True if the flow is now empty after pop
    uint64_t datagramLen; // Length of the datagram (0 if buf is nullptr)
    uint64_t numExpired{0}; // Datagrams dropped for exceeding maxQueueTime
  };

  // Longest deadline that means anything. A datagram queue drains or overflows
  // in milliseconds, so a longer deadline is indistinguishable from none.
  static constexpr std::chrono::milliseconds kMaxQueueTime =
      std::chrono::hours(24);

  DatagramFlowManager() = default;
  ~DatagramFlowManager() = default;

  // Move-only
  DatagramFlowManager(DatagramFlowManager&&) noexcept = default;
  DatagramFlowManager& operator=(DatagramFlowManager&&) noexcept = default;
  DatagramFlowManager(const DatagramFlowManager&) = delete;
  DatagramFlowManager& operator=(const DatagramFlowManager&) = delete;

  // Function type to calculate framing overhead for datagrams
  using OverheadCalculator = std::function<uint64_t(uint64_t datagramLen)>;

  /**
   * Set the overhead calculator for this flow manager.
   * This should be called once during initialization.
   */
  void setOverheadCalculator(OverheadCalculator calc) {
    overheadCalculator_ = std::move(calc);
  }

  // Helper to check if there are any pending datagrams
  [[nodiscard]] bool hasDatagramsToSend() const {
    return datagramCount_ > 0;
  }

  [[nodiscard]] size_t getDatagramCount() const {
    return datagramCount_;
  }

  /**
   * Create an empty flow entry in the write buffer.
   * No-op if the flow already exists.
   */
  void createFlow(uint32_t flowId) {
    writeBuffer_.try_emplace(flowId);
  }

  /**
   * Check if a flow exists in the write buffer (created or has datagrams).
   */
  [[nodiscard]] bool hasFlow(uint32_t flowId) const {
    return writeBuffer_.find(flowId) != writeBuffer_.end();
  }

  [[nodiscard]] size_t getFlowCount() const {
    return writeBuffer_.size();
  }

  [[nodiscard]] bool isFlowDraining(uint32_t flowId) const {
    auto it = writeBuffer_.find(flowId);
    return it != writeBuffer_.end() && it->second.draining;
  }

  /**
   * Add a datagram to a flow's write buffer.
   * Does a single map lookup and handles priority setting if provided.
   * Returns the flow's priority (either newly set or existing).
   * Pass draining for an ephemeral flow: one that takes this datagram and is
   * erased once it is written.
   * maxQueueTime is applied to the flow like setMaxQueueTime() would: nullopt
   * leaves the flow's current setting alone, and 0 clears it.
   * Returns error if the flow is already draining - a closed flow id is
   * finished, and the caller must allocate a new one.
   * intraFlowPriority orders this datagram against the others already queued
   * on the flow; lower is sent first and equal values stay FIFO.
   */
  quic::Expected<PriorityQueue::Priority, LocalErrorCode> addDatagram(
      BufQueue buf,
      uint32_t flowId = kDefaultDatagramFlowId,
      std::optional<PriorityQueue::Priority> priority = std::nullopt,
      bool draining = false,
      std::optional<std::chrono::milliseconds> maxQueueTime = std::nullopt,
      uint64_t intraFlowPriority = 0);

  /**
   * Set priority for an existing flow.
   * Returns error if flow doesn't exist, otherwise returns whether flow is
   * empty.
   */
  quic::Expected<bool, LocalErrorCode> setFlowPriority(
      uint32_t flowId,
      PriorityQueue::Priority priority);

  /**
   * Set max queue time for an existing flow. Anything longer than kMaxQueueTime
   * is stored as 0, meaning no timeout. Returns error if flow doesn't exist.
   * Any datagrams enqueued while the flow had no queue time set never expire.
   */
  quic::Expected<void, LocalErrorCode> setMaxQueueTime(
      uint32_t flowId,
      std::chrono::milliseconds maxQueueTime);

  /**
   * Only reads the clock if any datagram queue for this connection ever had an
   * expiration time.
   */
  [[nodiscard]] TimePoint nowForExpiration() const {
    return usesExpiration_ ? Clock::now() : TimePoint();
  }

  /**
   * Pop a datagram from a flow if it fits in the available space.
   * @param flowId The flow to pop from
   * @param availableSpace Available space in bytes
   * @param now From nowForExpiration(). Required rather than defaulted: a
   *        write loop pops from several flows and must judge them all
   *        against one reading, not one per call.
   */
  DatagramPopResult
  popDatagramIfFits(uint32_t flowId, uint64_t availableSpace, TimePoint now);

  /**
   * Drop a datagram from the first non-empty flow. Returns the id of the flow
   * this retired - a draining flow whose last datagram it was - so the caller
   * can drop whatever scheduling state it holds for that flow. Returns nullopt
   * if the flow is still around.
   */
  std::optional<uint32_t> popDatagram();

  /**
   * Check if a flow exists and is not empty.
   */
  [[nodiscard]] bool hasDatagramsForFlow(uint32_t flowId) const;

  /**
   * Id of an arbitrary flow holding at least one datagram, or nullopt if
   * every flow is empty. Flows are unordered, so repeated calls may return
   * different ids; callers that need priority ordering must schedule via the
   * PriorityQueue instead.
   */
  [[nodiscard]] std::optional<uint32_t> firstNonEmptyFlowId() const;

  /**
   * Close a datagram flow, draining whatever is already queued on it. A flow
   * with nothing queued is erased immediately; otherwise it is marked
   * draining and erased once the scheduler pops its last datagram. A draining
   * flow rejects addDatagram(), but an erased one reads as an unused id and
   * addDatagram() would quietly reopen it, so discard a closed id rather than
   * relying on this to reject writes.
   * Use hasFlow() to tell whether the flow is already gone.
   * Returns error if the flow doesn't exist.
   */
  quic::Expected<void, LocalErrorCode> closeFlow(uint32_t flowId);

  /**
   * Close a datagram flow immediately, discarding anything still queued on
   * it. Prefer closeFlow() unless the queued datagrams are known to be
   * worthless - this drops data the peer will never see.
   * Returns error if the flow doesn't exist.
   */
  quic::Expected<void, LocalErrorCode> closeFlowNow(uint32_t flowId);

 private:
  [[nodiscard]] static std::chrono::milliseconds sanitizeMaxQueueTime(
      std::chrono::milliseconds maxQueueTime) {
    return (maxQueueTime.count() < 0 || maxQueueTime > kMaxQueueTime)
        ? std::chrono::milliseconds(0)
        : maxQueueTime;
  }

  // Buffers Outgoing Datagrams per-flow
  folly::F14FastMap<uint32_t, DatagramFlowQueue> writeBuffer_;
  // Total count of datagrams across all flows
  size_t datagramCount_{0};
  // Whether any flow has ever carried a deadline. See nowForExpiration().
  bool usesExpiration_{false};
  // Function to calculate framing overhead for datagrams
  OverheadCalculator overheadCalculator_;
};

} // namespace quic
