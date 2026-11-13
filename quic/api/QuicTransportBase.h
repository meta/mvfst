/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/state/StateData.h>

#include <folly/ExceptionWrapper.h>

namespace quic {

/**
 * Base class for the QUIC Transport. Implements common behavior for both
 * clients and servers. QuicTransportBase assumes the following:
 * 1. It is intended to be sub-classed and used via the subclass directly.
 * 2. Assumes that the sub-class manages its ownership via a shared_ptr.
 *    This is needed in order for QUIC to be able to live beyond the lifetime
 *    of the object that holds it to send graceful close messages to the peer.
 */
class QuicTransportBase : public QuicSocket,
                          virtual public QuicTransportBaseLite {
 public:
  QuicTransportBase(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBase() override;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  [[nodiscard]] Optional<ConnectionId> getClientConnectionId() const override;

  [[nodiscard]] Optional<ConnectionId> getServerConnectionId() const override;

  [[nodiscard]] Optional<ConnectionId> getClientChosenDestConnectionId()
      const override;

  // QuicSocket interface
  [[nodiscard]] bool replaySafe() const override;

  void closeGracefully() override;

  [[nodiscard]] quic::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const override;
  [[nodiscard]] quic::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const override;
  [[nodiscard]] quic::Expected<size_t, LocalErrorCode>
  getStreamWriteBufferedBytes(StreamId id) const override;

  [[nodiscard]] quic::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const override;

  [[nodiscard]] quic::Expected<uint64_t, LocalErrorCode> getMaxWritableOnStream(
      StreamId id) const override;

  quic::Expected<void, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) override;

  quic::Expected<void, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) override;

  void unsetAllReadCallbacks() override;
  void unsetAllPeekCallbacks() override;
  void unsetAllDeliveryCallbacks() override;

  quic::Expected<void, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) override;

  quic::Expected<void, LocalErrorCode> pausePeek(StreamId id) override;
  quic::Expected<void, LocalErrorCode> resumePeek(StreamId id) override;

  quic::Expected<void, LocalErrorCode> peek(
      StreamId id,
      FunctionRef<void(StreamId id, const folly::Range<PeekIterator>&)>
          peekCallback) override;

  quic::Expected<void, LocalErrorCode> consume(StreamId id, size_t amount)
      override;

  quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) override;

  quic::Expected<void, LocalErrorCode> maybeResetStreamFromReadError(
      StreamId id,
      QuicErrorCode error) override;

  quic::Expected<void, LocalErrorCode> setPingCallback(
      PingCallback* cb) override;

  void sendPing(std::chrono::milliseconds pingTimeout) override;

  [[nodiscard]] const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  virtual void setAckRxTimestampsEnabled(bool enableAckRxTimestamps);

  // Passing false turns off TIMESTAMP frame writing on this connection; passing
  // true leaves the configured write mode unchanged.
  virtual void setTimestampFrameWritingEnabled(bool enabled);

  void setEarlyDataAppParamsHandler(EarlyDataAppParamsHandler* handler) final;

  bool isDetachable() override;

  void detachEventBase() override;

  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;

  // Subclass API.

  quic::Expected<PriorityQueue::Priority, LocalErrorCode> getStreamPriority(
      StreamId id) override;

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   */
  quic::Expected<void, LocalErrorCode> registerTxCallback(
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  /**
   * Reset or send a stop sending on all non-control streams. Leaves the
   * connection otherwise unmodified. Note this will also trigger the
   * onStreamWriteError and readError callbacks immediately.
   */
  void resetNonControlStreams(
      ApplicationErrorCode error,
      folly::StringPiece errorMsg) override;

  void setLoopDetectorCallback(std::shared_ptr<LoopDetectorCallback> callback) {
    conn_->loopDetectorCallback = std::move(callback);
  }

  using QuicTransportBaseLite::writeDatagram;

  quic::Expected<void, LocalErrorCode> writeDatagram(
      PriorityQueue::Priority priority,
      BufPtr buf,
      std::optional<std::chrono::milliseconds> maxQueueTime =
          std::nullopt) override;

  quic::Expected<uint32_t, LocalErrorCode> createDatagramFlowId() override;

  quic::Expected<void, LocalErrorCode> writeDatagram(
      uint32_t flowId,
      BufPtr buf,
      uint64_t intraFlowPriority = 0) override;

  quic::Expected<void, LocalErrorCode> setDatagramFlowPriority(
      uint32_t flowId,
      PriorityQueue::Priority priority) override;

  quic::Expected<void, LocalErrorCode> setDatagramFlowMaxQueueTime(
      uint32_t flowId,
      std::chrono::milliseconds maxTime) override;

  quic::Expected<void, LocalErrorCode> closeDatagramFlow(
      uint32_t flowId) override;

  quic::Expected<void, LocalErrorCode> closeDatagramFlowNow(
      uint32_t flowId) override;

  /**
   * This is used in conjunction with reliable resets. When we send data on a
   * stream and want to mark which offset will constitute the reliable size in a
   * future call to resetStreamReliably, we call this function. This function
   * can potentially be called multiple times on a stream to advance the offset,
   * but it is an error to call it after sending a reset.
   */
  quic::Expected<void, LocalErrorCode> updateReliableDeliveryCheckpoint(
      StreamId id) override;

  /**
   * Send a reliable reset to the peer. The reliable size sent to the peer is
   * determined by when checkpoint(streamId) was last called. If reliable resets
   * are not supported on this connection, a regular reset is sent instead.
   */
  quic::Expected<void, LocalErrorCode> resetStreamReliably(
      StreamId id,
      ApplicationErrorCode error) override;

  [[nodiscard]] bool isReliableResetSupported() const override;

  /**
   * Set control messages to be sent for socket_ write, note that it's for this
   * specific transport and does not change the other sockets sharing the same
   * fd.
   */
  void setCmsgs(const folly::SocketCmsgMap& options);

  void appendCmsgs(const folly::SocketCmsgMap& options);

  /**
   * Sets whether retransmissions are disabled for a specific stream.
   */
  quic::Expected<void, LocalErrorCode> setStreamRetransmissionDisabled(
      StreamId id,
      bool disabled) noexcept override;

  [[nodiscard]] QuicAsyncUDPSocket* getUdpSocket() const {
    return socket_.get();
  }

 protected:
  quic::Expected<void, LocalErrorCode> pauseOrResumePeek(
      StreamId id,
      bool resume);
  quic::Expected<void, LocalErrorCode> setPeekCallbackInternal(
      StreamId id,
      PeekCallback* cb) noexcept;

  void schedulePingTimeout(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout);

  void updatePeekLooper() override;
  void invokePeekDataAndCallbacks() override;
  void handlePingCallbacks() override;
  void cleanupPeekPingDatagramResources() override;
  void cancelPeekPingDatagramCallbacks(const QuicError& err) override;
  bool hasPeekCallback(StreamId id) override;
  void pingTimeoutExpired() noexcept;

  class PingTimeout : public QuicTimerCallback {
   public:
    ~PingTimeout() override = default;

    explicit PingTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pingTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore, as this happens only when event base dies
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  struct PeekCallbackData {
    PeekCallback* peekCb;
    bool resumed{true};

    PeekCallbackData(PeekCallback* peekCallback) : peekCb(peekCallback) {}
  };

  PingCallback* pingCallback_{nullptr};
  PingTimeout pingTimeout_;
  UnorderedMap<StreamId, PeekCallbackData> peekCallbacks_;
  TransportLooper::Ptr peekLooper_;

  bool handshakeDoneNotified_{false};

  // Next datagram flow ID to allocate (counts up from kDefaultDatagramFlowId +
  // 1)
  uint32_t nextDatagramFlowId_{kDefaultDatagramFlowId + 1};
};

} // namespace quic
