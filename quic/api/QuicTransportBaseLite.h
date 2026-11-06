/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicSocketLite.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/FunctionRef.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>

#include <folly/io/async/DelayedDestruction.h>

namespace proto_oops {
class OopsLogger;
} // namespace proto_oops

namespace quic {

enum class LooperType : uint8_t {
  ReadLooper = 1,
  PeekLooper = 2,
  WriteLooper = 3
};

std::ostream& operator<<(std::ostream& out, const LooperType& rhs);

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

// Async operation types for enum-based dispatch (reduces binary size vs
// std::function)
enum class AsyncOpType : uint8_t {
  ProcessCallbacksAfterNetworkData,
  ConnectionWriteReady,
  StreamWriteReady,
  ByteEventReady,
  TransportReady,
  MarkZeroRttPacketsLost,
  AsyncClose,
  RemoveNonCurrentPathClient,
};

// Data for async operations - captures needed state without type erasure
struct AsyncOpData {
  AsyncOpType type;
  StreamId streamId{0};
  uint64_t offset{0};
  ByteEvent::Type byteEventType{ByteEvent::Type::TX};
  ByteEventCallback* callback{nullptr};
  PathIdType pathId{0};
  Optional<QuicError> error{};
};

class QuicTransportBaseLite : virtual public QuicSocketLite,
                              QuicAsyncUDPSocket::WriteCallback {
 public:
  QuicTransportBaseLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBaseLite() override;

  /**
   * Invoked when we have to write some data to the wire.
   * The subclass may use this to start writing data to the socket.
   * It may also throw an exception in case of an error in which case the
   * connection will be closed.
   */
  [[nodiscard]] virtual quic::Expected<void, QuicError> writeData() = 0;

  // Interface with the Transport layer when data is available.
  // This is invoked when new data is received from the UDP socket.
  virtual void onNetworkData(
      const quic::SocketAddress& localAddress,
      NetworkData&& data) noexcept;

  /**
   * Invoked when a new packet is read from the network.
   * The sub-class may throw an exception if there was an error in processing
   * the packet in which case the connection will be closed.
   */
  virtual quic::Expected<void, QuicError> onReadData(
      const quic::SocketAddress& localAddress,
      ReceivedUdpPacket&& udpPacket) = 0;

  void close(Optional<QuicError> error) override;

  void closeNow(Optional<QuicError> error) override;

  void sendPing(std::chrono::milliseconds pingTimeout = {}) override;

  quic::Expected<void, LocalErrorCode> stopSending(
      StreamId id,
      ApplicationErrorCode error) override;
  quic::Expected<void, LocalErrorCode> stopSendingAndDropIngress(
      StreamId id,
      ApplicationErrorCode error) override;
  quic::Expected<void, LocalErrorCode> stopSendingAndDropIngressForAllStreams(
      ApplicationErrorCode error) override;

  quic::Expected<StreamId, LocalErrorCode> createBidirectionalStream(
      bool replaySafe = true) override;
  quic::Expected<StreamId, LocalErrorCode> createUnidirectionalStream(
      bool replaySafe = true) override;
  [[nodiscard]] uint64_t getNumOpenableBidirectionalStreams() const override;
  [[nodiscard]] uint64_t getNumOpenableUnidirectionalStreams() const override;

  WriteResult writeChain(
      StreamId id,
      BufPtr data,
      bool eof,
      ByteEventCallback* cb = nullptr) override;

  quic::Expected<void, LocalErrorCode> registerDeliveryCallback(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb) override;

  quic::Expected<void, LocalErrorCode> notifyPendingWriteOnStream(
      StreamId id,
      StreamWriteCallback* wcb) override;

  quic::Expected<void, LocalErrorCode> notifyPendingWriteOnConnection(
      ConnectionWriteCallback* wcb) override;

  quic::Expected<void, LocalErrorCode> unregisterStreamWriteCallback(
      StreamId id) override;

  quic::Expected<void, LocalErrorCode> resetStream(
      StreamId id,
      ApplicationErrorCode errorCode) override;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId.
   */
  void cancelDeliveryCallbacksForStream(StreamId id) override;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId for
   * offsets lower than the offset provided.
   */
  void cancelDeliveryCallbacksForStream(StreamId id, uint64_t offset) override;

  /**
   * Cancel byte event callbacks for given stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const StreamId id,
      const Optional<uint64_t>& offsetUpperBound = std::nullopt) override;

  /**
   * Cancel byte event callbacks for given type and stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id,
      const Optional<uint64_t>& offsetUpperBound = std::nullopt) override;

  /**
   * Register a byte event to be triggered when specified event type occurs for
   * the specified stream and offset.
   */
  quic::Expected<void, LocalErrorCode> registerByteEventCallback(
      const ByteEvent::Type type,
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  [[nodiscard]] bool good() const override;

  [[nodiscard]] bool error() const override;

  [[nodiscard]] uint64_t bufferSpaceAvailable() const;

  /**
   * Returns whether or not the connection has a write cipher. This will be used
   * to decide to return the onTransportReady() callbacks.
   */
  [[nodiscard]] virtual bool hasWriteCipher() const = 0;

  void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) final;

  void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback,
      ConnectionCallbackOptions options = {}) final;

  Optional<LocalErrorCode> setControlStream(StreamId id) override;

  quic::Expected<void, LocalErrorCode> setReadCallback(
      StreamId id,
      ReadCallback* cb,
      Optional<ApplicationErrorCode> err =
          GenericApplicationErrorCode::NO_ERROR) override;

  quic::Expected<void, LocalErrorCode> setStopSendingCallback(
      StreamId id,
      StopSendingCallback* ss) noexcept override;

  quic::Expected<void, LocalErrorCode> pauseRead(StreamId id) override;
  quic::Expected<void, LocalErrorCode> resumeRead(StreamId id) override;

  quic::Expected<void, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) override;

  [[nodiscard]] uint16_t getDatagramSizeLimit() const override;

  quic::Expected<void, LocalErrorCode> writeDatagram(BufPtr buf) override;

  quic::Expected<std::vector<ReadDatagram>, LocalErrorCode> readDatagrams(
      size_t atMost = 0) override;

  quic::Expected<std::vector<BufPtr>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) override;

  quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxLen) override;

  quic::Expected<void, LocalErrorCode> setStreamManualRead(
      StreamId id) override;

  quic::Expected<void, LocalErrorCode> releaseManualReadFlowControl(
      StreamId id,
      uint64_t bytes) override;

  virtual void setQLogger(std::shared_ptr<QLogger> qLogger);

  [[nodiscard]] const std::shared_ptr<QLogger> getQLogger() const;

  virtual void setOopsLogger(proto_oops::OopsLogger* oopsLogger);

  void setReceiveWindow(StreamId, size_t /*recvWindowSize*/) override {}

  void setSendBuffer(StreamId, size_t /*maxUnacked*/, size_t /*maxUnsent*/)
      override {}

  /**
   * Set the initial flow control window for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings) override;

  // If you don't set it, the default is Cubic
  void setCongestionControl(CongestionControlType type) override;

  virtual void setSupportedVersions(const std::vector<QuicVersion>& versions);

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection.
   * Deletes current congestion controller instance, to create new controller
   * call setCongestionControl() or setTransportSettings().
   */
  virtual void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  /**
   * Install a per-connection `BatchWriterFactoryOverride` on the underlying
   * `QuicConnectionStateBase`. The override is consulted by
   * `BatchWriterFactory::makeBatchWriter` before the default switch.
   *
   * Pass an empty `std::function` (the default) to clear.
   */
  virtual void setBatchWriterFactoryOverride(
      quic::BatchWriterFactoryOverride override);

  void addPacketProcessor(
      std::shared_ptr<PacketProcessor> packetProcessor) override;

  /**
   * Set a "knob". This will emit a knob frame to the peer, which the peer
   * application can act on by e.g. changing transport settings during the
   * connection.
   */
  quic::Expected<void, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, BufPtr knobBlob) override;

  /**
   * Can Knob Frames be exchanged with the peer on this connection?
   */
  [[nodiscard]] bool isKnobSupported() const override;

  quic::Expected<void, LocalErrorCode> setPriorityQueue(
      std::unique_ptr<PriorityQueue> queue) override;

  quic::Expected<void, LocalErrorCode> setStreamPriority(
      StreamId id,
      PriorityQueue::Priority priority) override;

  /**
   * Sets the maximum pacing rate in Bytes per second to be used
   * if pacing is enabled.
   */
  quic::Expected<void, LocalErrorCode> setMaxPacingRate(
      uint64_t maxRateBytesPerSec) override;

  void setThrottlingSignalProvider(
      std::shared_ptr<ThrottlingSignalProvider>) override;

  [[nodiscard]] uint64_t maxWritableOnStream(const QuicStreamState&) const;

  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  [[nodiscard]] quic::Expected<StreamTransportInfo, LocalErrorCode>
  getStreamTransportInfo(StreamId id) const override;

  [[nodiscard]] const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  [[nodiscard]] const quic::SocketAddress& getPeerAddress() const override;

  [[nodiscard]] const quic::SocketAddress& getOriginalPeerAddress()
      const override;

  [[nodiscard]] Optional<std::string> getAppProtocol() const override;

  [[nodiscard]] uint64_t getConnectionBufferAvailable() const override;

  [[nodiscard]] quic::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const override;

  /**
   * Retrieve the transport settings
   */
  [[nodiscard]] const TransportSettings& getTransportSettings() const override;

  [[nodiscard]] uint64_t maxWritableOnConn() const override;

  virtual void cancelAllAppCallbacks(const QuicError& error) noexcept;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout);

  class ExcessWriteTimeout : public QuicTimerCallback {
   public:
    ~ExcessWriteTimeout() override = default;

    explicit ExcessWriteTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->excessWriteTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // Do nothing.
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  // Timeout functions
  class LossTimeout : public QuicTimerCallback {
   public:
    ~LossTimeout() override = default;

    explicit LossTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->lossTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class IdleTimeout : public QuicTimerCallback {
   public:
    ~IdleTimeout() override = default;

    explicit IdleTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      ++transport_->idleTimeoutFiredCount_;
      transport_->idleTimeoutExpired(true /* drain */);
    }

    void callbackCanceled() noexcept override {
      // skip drain when canceling the timeout, to avoid scheduling a new
      // drain timeout
      transport_->idleTimeoutExpired(false /* drain */);
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class KeepaliveTimeout : public QuicTimerCallback {
   public:
    ~KeepaliveTimeout() override = default;

    explicit KeepaliveTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->keepaliveTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // Specifically do nothing since if we got canceled we shouldn't write.
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class AckTimeout : public QuicTimerCallback {
   public:
    ~AckTimeout() override = default;

    explicit AckTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->ackTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class PathValidationTimeout : public QuicTimerCallback {
   public:
    ~PathValidationTimeout() override = default;

    explicit PathValidationTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pathValidationTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  // DrainTimeout holds a raw pointer to the transport. This is fine because the
  // DrainTimeout is owned by the transport, and destroying the DrainTimeout
  // cancels it. I.e., destroying the transport destroys the DrainTimeout, which
  // cancels the timeout callback.
  // NOTE: The logic for canceling the callback is in the implementation of the
  // QuicTimer. So as a safeguard, we explicitly cancel this timeout in the
  // transport destructor.
  class DrainTimeout : public QuicTimerCallback {
   public:
    ~DrainTimeout() override = default;

    explicit DrainTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      [[maybe_unused]] auto self = transport_->sharedGuard();
      transport_->drainTimeoutExpired();
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  /**
   * TransportLooper manages event loop callbacks for the transport.
   */
  class TransportLooper : public QuicEventBaseLoopCallback,
                          public QuicTimerCallback,
                          public folly::DelayedDestruction {
   public:
    using Ptr =
        std::unique_ptr<TransportLooper, folly::DelayedDestruction::Destructor>;

    explicit TransportLooper(
        std::shared_ptr<QuicEventBase> evb,
        QuicTransportBaseLite* transport,
        LooperType type);

    void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

    void runLoopCallback() noexcept override;

    /**
     * Starts running the loop callback in each loop iteration.
     * If this is already scheduled to run, run() will continue to run it.
     */
    void run(bool thisIteration = false) noexcept;

    /**
     * Enables pacing callback - will call transport's getLooperPacingDelay().
     */
    void enablePacingCallback() noexcept;

    /**
     * Stops running the loop in each loop iteration.
     */
    void stop() noexcept;

    /**
     * Whether the looper is running or not. This is not thread-safe and should
     * only be called on the looper's evb.
     */
    [[nodiscard]] bool isRunning() const;

    /**
     * Whether the pacing timer is scheduled or not. This is not thread-safe and
     * should only be called on the looper's evb.
     */
    [[nodiscard]] bool isPacingScheduled();

    /**
     * Whether the loop callback is scheduled or not. This is not thread-safe
     * and should only be called on the looper's evb.
     */
    [[nodiscard]] bool isLoopCallbackScheduled();

    /**
     * Attaches a new event base to the looper. Must be invoked on the
     * evb that the looper is to be attached to.
     */
    void attachEventBase(std::shared_ptr<QuicEventBase> evb);

    /**
     * Detaches the current event base from the looper. Must be called on
     * the current event base thread.
     */
    void detachEventBase();

    void timeoutExpired() noexcept override;

    void callbackCanceled() noexcept override;

    [[nodiscard]] OptionalMicros getTimerTickInterval() noexcept;

    /*
     * Controls whether to fire a loop early when the pacing timer has been
     * missed or is scheduled to fire "soon" (within 1ms).
     */
    void setFireLoopEarly(bool val) {
      fireLoopEarly_ = val;
    }

   private:
    ~TransportLooper() override = default;
    void commonLoopBody() noexcept;
    bool schedulePacingTimeout() noexcept;

    std::shared_ptr<QuicEventBase> evb_;
    QuicTransportBaseLite* transport_;
    QuicTimer::SharedPtr pacingTimer_;
    TimePoint nextPacingTime_;
    const LooperType type_;

    struct {
      bool running_ : 1;
      bool inLoopBody_ : 1;
      bool fireLoopEarly_ : 1;
      bool hasPacingCallback_ : 1;
    };
  };

  void scheduleLossTimeout(std::chrono::milliseconds timeout);

  void cancelLossTimeout();

  bool isLossTimeoutScheduled();

  /**
   * Get the number of pending byte events for the given stream.
   */
  [[nodiscard]] size_t getNumByteEventCallbacksForStream(
      const StreamId id) const override;

  /**
   * Get the number of pending byte events of specified type for given stream.
   */
  [[nodiscard]] size_t getNumByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id) const override;

  /**
   * Cancel all byte event callbacks of all streams.
   */
  void cancelAllByteEventCallbacks() override;

  /**
   * Cancel all byte event callbacks of all streams of the given type.
   */
  void cancelByteEventCallbacks(const ByteEvent::Type type) override;

  /**
   * closeTransport is invoked on the sub-class when the transport is closed.
   * The sub-class may clean up any state during this call. The transport
   * may still be draining after this call.
   */
  virtual void closeTransport() = 0;

  /**
   * Invoked after the drain timeout has exceeded and the connection state will
   * be destroyed.
   */
  virtual void unbindConnection() = 0;

  [[nodiscard]] QuicNodeType getNodeType() const noexcept final;

  [[nodiscard]] QuicConnectionStats getConnectionsStats() const override;

  Optional<SconeRateInfo> consumePendingSconeRate() override;

  /**
   * Returns a shared_ptr which can be used as a guard to keep this
   * object alive.
   */
  virtual std::shared_ptr<QuicTransportBaseLite> sharedGuard() = 0;

  void describe(std::ostream& os) const;

  /*
   * Creates buf accessor for use with in-place batch writer.
   */
  virtual void createBufAccessor(size_t /* capacity */) {}

  [[nodiscard]] TransportInfo getTransportInfo() const override;

  [[nodiscard]] const quic::SocketAddress& getLocalAddress() const override;

 protected:
  void setConnectionCallbackFromCtor(
      folly::MaybeManagedPtr<ConnectionCallback> callback);

  /**
   * A wrapper around writeSocketData
   *
   * writeSocketDataAndCatch protects writeSocketData in a try-catch. It also
   * dispatch the next write loop.
   */
  void writeSocketDataAndCatch();

  /**
   * Paced write data to socket when connection is paced.
   *
   * Whether connection is paced will be decided by TransportSettings and
   * congection controller. When the connection is paced, this function writes
   * out a burst size of packets and let the writeLooper schedule a callback to
   * write another burst after a pacing interval if there are more data to
   * write. When the connection isn't paced, this function does a normal write.
   */
  void pacedWriteDataToSocket();

  /**
   * write data to socket
   *
   * At transport layer, this is the simplest form of write. It writes data
   * out to the network, and schedule necessary timers (ack, idle, loss). It is
   * both pacing oblivious and writeLooper oblivious. Caller needs to explicitly
   * invoke updateWriteLooper afterwards if that's desired.
   */
  [[nodiscard]] quic::Expected<void, QuicError> writeSocketData();

  void closeImpl(
      Optional<QuicError> error,
      bool drainConnection = true,
      bool sendCloseImmediately = true);

  /**
   * Handles an exception by logging, setting exceptionCloseWhat_, and closing
   * the connection. Returns the appropriate LocalErrorCode for the caller.
   *
   * @param ex The caught exception (must be std::exception or derived)
   * @param contextMsg Message to include in QuicError (e.g., "writeChain()
   *                   error")
   * @param streamId Optional stream ID for logging context
   * @return LocalErrorCode to return to caller (for Expected-returning
   *         functions)
   */
  LocalErrorCode handleExceptionAndClose(
      const std::exception& ex,
      folly::StringPiece contextMsg,
      Optional<StreamId> streamId = std::nullopt);

  void processCallbacksAfterNetworkData();

  quic::Expected<void, LocalErrorCode> resetStreamInternal(
      StreamId id,
      ApplicationErrorCode errorCode,
      bool reliable);

  // Only remove byte event callbacks if offsetFilter returns true.
  void cancelByteEventCallbacksForStreamInternal(
      const ByteEvent::Type type,
      const StreamId id,
      FunctionRef<bool(uint64_t)> offsetFilter);

  void onSocketWritable() noexcept override;

  void handleNewStreamCallbacks(std::vector<StreamId>& newPeerStreams);
  void handleKnobCallbacks();
  void handleAckEventCallbacks();
  void handleCancelByteEventCallbacks();
  void invokeStreamsAvailableCallbacks();
  void handleDeliveryCallbacks();
  void handleStreamFlowControlUpdatedCallbacks(
      std::vector<StreamId>& streamStorage);
  void handleStreamStopSendingCallbacks();
  void handleConnWritable();
  void cleanupAckEventState();

  [[nodiscard]] quic::Expected<WriteQuicDataResult, QuicError>
  handleInitialWriteDataCommon(
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      uint64_t packetLimit,
      const std::string& token = "");

  [[nodiscard]] quic::Expected<WriteQuicDataResult, QuicError>
  handleHandshakeWriteDataCommon(
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      uint64_t packetLimit);

  void closeUdpSocket();

  quic::Expected<StreamId, LocalErrorCode> createStreamInternal(
      bool bidirectional);

  // Enum-based async dispatch for binary size optimization
  void runOnEvbAsyncOp(AsyncOpData data);
  virtual void dispatchAsyncOp(AsyncOpData data);

  // Template-based async dispatch for complex cases with custom captures
  template <typename F>
  void runOnEvbAsync(F&& func) {
    auto evb = getEventBase();
    evb->runInLoop(
        [self = sharedGuard(), func = std::forward<F>(func), evb]() mutable {
          if (self->getEventBase() != evb) {
            return;
          }
          func(std::move(self));
        },
        true);
  }

  void updateWriteLooper(bool thisIteration);
  void updateReadLooper();

  void maybeStopWriteLooperAndArmSocketWritableEvent();

  void checkForClosedStream();

  /**
   * Whether a graceful close can finish: no remaining stream needs anything
   * more from the peer.
   *
   * That is the case once every remaining stream has its receive side retired
   * with stopSendingAndDropIngress() and its send side, if any, closed. Without
   * retired streams, it means no stream remains.
   *
   * A send side closes once the peer has acknowledged all of its data through
   * the FIN; until then, loss recovery keeps retransmitting it. The graceful
   * close never resets a stream, but a send side the application reset itself
   * closes once the peer acknowledges that RESET_STREAM, and for a reliable
   * reset the data before its reliable size.
   *
   * Nothing is waited for on a retired receive side: neither the peer's
   * acknowledgment of the STOP_SENDING nor the peer's FIN or RESET_STREAM.
   *
   * The scan stops at the first stream that still needs the peer, so it only
   * walks past streams the application has retired.
   */
  [[nodiscard]] bool canFinishGracefulClose() const;

  void cancelTimeout(QuicTimerCallback* callback);

  void excessWriteTimeoutExpired() noexcept;
  void lossTimeoutExpired() noexcept;
  void idleTimeoutExpired(bool drain) noexcept;
  void keepaliveTimeoutExpired() noexcept;
  void ackTimeoutExpired() noexcept;
  void pathValidationTimeoutExpired() noexcept;
  void drainTimeoutExpired() noexcept;

  // Virtual methods for Peek/Ping/Datagram functionality
  // Empty implementations in Lite, overridden in Base
  virtual void updatePeekLooper();
  virtual void invokePeekDataAndCallbacks();
  virtual void handlePingCallbacks();
  virtual void cleanupPeekPingDatagramResources();
  virtual void cancelPeekPingDatagramCallbacks(const QuicError& err);
  virtual bool hasPeekCallback(StreamId id);
  virtual void invokeDatagramCallbackIfSet();

  // Virtual callback methods for TransportLooper
  // Called by TransportLooper to dispatch to the appropriate handler
  virtual void onLooperCallback(LooperType type);
  virtual std::chrono::microseconds getLooperPacingDelay();

  bool isTimeoutScheduled(QuicTimerCallback* callback) const;

  void invokeReadDataAndCallbacks(bool updateLoopersAndCheckForClosedStream);

  quic::Expected<void, LocalErrorCode> setReadCallbackInternal(
      StreamId id,
      ReadCallback* cb,
      Optional<ApplicationErrorCode> err) noexcept;

  quic::Expected<void, LocalErrorCode> pauseOrResumeRead(
      StreamId id,
      bool resume);

  /**
   * Internal helper for writing datagrams with common validation logic.
   */
  quic::Expected<void, LocalErrorCode> writeDatagramInternal(
      BufPtr buf,
      uint32_t flowId,
      std::optional<PriorityQueue::Priority> priority,
      bool ephemeralFlow,
      std::optional<std::chrono::milliseconds> maxQueueTime,
      uint64_t intraFlowPriority = 0);

  void maybeEraseDatagramFlowFromWriteQueue(uint32_t flowId);

  /**
   * The callback function for AsyncUDPSocket to provide the additional cmsgs
   * required by this QuicSocket's packet processors.
   */
  Optional<folly::SocketCmsgMap> getAdditionalCmsgsForAsyncUDPSocket();

  /**
   * Helper function that calls passed function for each ByteEvent type.
   *
   * Removes number of locations to update when a byte event is added.
   */
  void invokeForEachByteEventType(FunctionRef<void(const ByteEvent::Type)> fn) {
    for (const auto& type : ByteEvent::kByteEventTypes) {
      fn(type);
    }
  }

  void invokeForEachByteEventTypeConst(
      FunctionRef<void(const ByteEvent::Type)> fn) const {
    for (const auto& type : ByteEvent::kByteEventTypes) {
      fn(type);
    }
  }

  // Helpers to notify all registered observers about specific events during
  // socket write (if enabled in the observer's config).
  void notifyStartWritingFromAppRateLimited();
  void notifyPacketsWritten(
      const uint64_t /* numPacketsWritten */,
      const uint64_t /* numAckElicitingPacketsWritten */,
      const uint64_t /* numBytesWritten */);
  void notifyAppRateLimited();

  /**
   * Callback when we receive a transport knob
   */
  virtual void onTransportKnobs(BufPtr knobBlob);

  void processCallbacksAfterWriteData();

  void setIdleTimer();
  void scheduleAckTimeout();
  void schedulePathValidationTimeout();

  // Tells the connection callbacks that the application closed the transport
  // or is destroying it.
  void onApplicationClose() {
    connectionCallbacks_.onApplicationClose();
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

  void updateCongestionControlSettings(
      const TransportSettings& transportSettings);

  void validateCongestionAndPacing(CongestionControlType& type);

  void updateSocketTosSettings(uint8_t dscpValue);

  /**
   * Helper function to validate that the number of ECN packet marks match the
   * expected value, depending on the ECN state of the connection.
   *
   * If ECN is enabled, this function validates it's working correctly. If ECN
   * is not enabled or has already failed validation, this function does
   * nothing.
   */
  [[nodiscard]] quic::Expected<void, QuicError> validateECNState();

  /**
   * Returns the SocketObserverContainer. Lite implementation returns nullptr.
   * Full implementation (QuicTransportBase) overrides this to return actual
   * observer container.
   */
  [[nodiscard]] SocketObserverContainer* getSocketObserverContainer()
      const override {
    return nullptr;
  }

  std::shared_ptr<QuicEventBase> evb_;
  std::unique_ptr<QuicAsyncUDPSocket> socket_;

  // TODO: This is silly. We need a better solution.
  // Uninitialied local address as a fallback answer when socket isn't bound.
  quic::SocketAddress localFallbackAddress;

  CloseState closeState_{CloseState::OPEN};

  /**
   * The application's connection callbacks, as far as the transport may still
   * call them.
   *
   * The application installs them with setConnectionSetupCallback() and
   * setConnectionCallback(). After that, the transport only tells this class
   * what happened to the connection, and reads the callbacks back through
   * setup() and connection(), which return null once a callback must not be
   * called anymore.
   *
   * A close the application starts, including destroying the transport, ends
   * the setup callback at once, because the application may destroy it as
   * soon as the call returns. It ends the connection callback too, unless the
   * application installed it with reportLocalClose: then the callback stays
   * until closeImpl() has reported how the connection ended. Reporting that
   * end, or destroying the transport, ends both for good.
   */
  class ConnectionCallbacks {
   public:
    [[nodiscard]] const folly::MaybeManagedPtr<ConnectionSetupCallback>& setup()
        const {
      return setup_;
    }

    [[nodiscard]] const folly::MaybeManagedPtr<ConnectionCallback>& connection()
        const {
      return connection_;
    }

   private:
    friend class QuicTransportBaseLite;

    void setSetupCallback(
        folly::MaybeManagedPtr<ConnectionSetupCallback> callback) {
      setup_ = std::move(callback);
    }

    void setConnectionCallback(
        folly::MaybeManagedPtr<ConnectionCallback> callback,
        ConnectionCallbackOptions options) {
      connection_ = std::move(callback);
      connectionOptions_ = options;
    }

    void onApplicationClose() {
      setup_ = nullptr;
      if (!connectionOptions_.reportLocalClose) {
        connection_ = nullptr;
      }
    }

    void onEndReported() {
      end();
    }

    void onTransportDestroyed() {
      end();
    }

    void end() {
      setup_ = nullptr;
      connection_ = nullptr;
    }

    folly::MaybeManagedPtr<ConnectionSetupCallback> setup_{nullptr};
    folly::MaybeManagedPtr<ConnectionCallback> connection_{nullptr};
    ConnectionCallbackOptions connectionOptions_;
  };

  ConnectionCallbacks connectionCallbacks_;
  // A flag telling transport if the new onConnectionEnd(error) cb must be used.
  bool useConnectionEndWithErrorCallback_{false};

  bool transportReadyNotified_{false};
  bool writeCipherAvailableNotified_{false};

  struct ReadCallbackData {
    ReadCallback* readCb;
    bool resumed{true};
    bool deliveredEOM{false};

    ReadCallbackData(ReadCallback* readCallback) : readCb(readCallback) {}
  };

  UnorderedMap<StreamId, ReadCallbackData> readCallbacks_;

  ConnectionWriteCallback* connWriteCallback_{nullptr};
  DatagramCallback* datagramCallback_{nullptr};
  UnorderedMap<StreamId, StreamWriteCallback*> pendingWriteCallbacks_;
  UnorderedMap<StreamId, StopSendingCallback*> stopSendingCallbacks_;

  struct ByteEventDetail {
    ByteEventDetail(uint64_t offsetIn, ByteEventCallback* callbackIn)
        : offset(offsetIn), callback(callbackIn) {}

    uint64_t offset;
    ByteEventCallback* callback;
  };

  using ByteEventMap = UnorderedMap<StreamId, CircularDeque<ByteEventDetail>>;
  ByteEventMap& getByteEventMap(const ByteEvent::Type type);
  [[nodiscard]] const ByteEventMap& getByteEventMapConst(
      const ByteEvent::Type type) const;

  ByteEventMap deliveryCallbacks_;
  ByteEventMap txCallbacks_;

  LossTimeout lossTimeout_;
  ExcessWriteTimeout excessWriteTimeout_;
  IdleTimeout idleTimeout_;
  KeepaliveTimeout keepaliveTimeout_;
  Optional<TimePoint> idleTimeoutDeadline_;
  uint64_t idleTimeoutFiredCount_{0};
  uint64_t keepaliveTimeoutFiredCount_{0};
  uint64_t keepaliveExpiredIdleDeadlineCount_{0};
  Optional<std::chrono::milliseconds> lastIdleDeadlineOverdue_;
  AckTimeout ackTimeout_;
  PathValidationTimeout pathValidationTimeout_;
  DrainTimeout drainTimeout_;

  TransportLooper::Ptr writeLooper_;
  TransportLooper::Ptr readLooper_;

  Optional<std::string> exceptionCloseWhat_;

  std::
      unique_ptr<QuicConnectionStateBase, folly::DelayedDestruction::Destructor>
          conn_;

  /**
   * Container for use in QuicTransportBase implementations.
   *
   * Contains a SocketObserverContainer and hands out weak or raw pointers.
   *
   * Weak pointers are used to meet the needs of QuicConnectionStateBase:
   *   - QuicConnectionStateBase needs a pointer to the SocketObserverContainer
   *     so that loss / ACK / other processing logic can access the observer
   *     container and send the observers notifications. There may not be a
   *     SocketObserverContainer if the QuicTransportBase implementation does
   *     not support it.
   *
   *   - A SocketObserverContainer must not outlive the instance of the
   *     QuicTransportBase implementation that it is associated with. This is
   *     because observers are notified that the object being observed has been
   *     destroyed when the container is destroyed, and thus if the container
   *     outlives the lifetime of the transport, then the observers will think
   *     the transport is still alive when it is in fact dead.

   *   - By storing a weak pointer to the SocketObserverContainer in the
   *     QuicConnectionStateBase, we provide access to the observer container
   *     without extending its lifetime. In parallel, because it is a managed
   *     pointer, we avoid the possibility of dereferencing a stale pointer
   *     (e.g., a pointer pointing to an object that has since been destroyed).
   *
   * We store a shared_ptr inside of this container and then distribute weak_ptr
   * to reduce the risk of a shared_ptr<SocketObserverContainer> mistakenly
   * being held elsewhere.
   */
  class WrappedSocketObserverContainer {
   public:
    explicit WrappedSocketObserverContainer(QuicSocketLite* socket)
        : observerContainer_(
              std::make_shared<SocketObserverContainer>(socket)) {}

    [[nodiscard]] SocketObserverContainer* getPtr() const {
      return observerContainer_.get();
    }

    [[nodiscard]] std::weak_ptr<SocketObserverContainer> getWeakPtr() const {
      return observerContainer_;
    }

    // deleted constructors (unnecessary, difficult to safely support)
    WrappedSocketObserverContainer(const WrappedSocketObserverContainer&) =
        delete;
    WrappedSocketObserverContainer(WrappedSocketObserverContainer&&) = delete;
    WrappedSocketObserverContainer& operator=(
        const WrappedSocketObserverContainer&) = delete;
    WrappedSocketObserverContainer& operator=(
        WrappedSocketObserverContainer&& rhs) = delete;

   private:
    std::shared_ptr<SocketObserverContainer> observerContainer_;
  };

 private:
  /**
   * Helper functions to handle new streams.
   */
  void handleNewStreams(std::vector<StreamId>& newPeerStreams);

  /**
   * Helper to log new stream event to observer.
   */
  void logStreamOpenEvent(StreamId streamId);

  [[nodiscard]] bool hasDeliveryCallbacksToCall(
      StreamId streamId,
      uint64_t maxOffsetToDeliver) const;

  /**
   * Helper function to collect prewrite requests from the PacketProcessors
   * Currently this collects cmsgs to be written. The Cmsgs will be stored in
   * the connection state and passed to AsyncUDPSocket in the next
   * additionalCmsgs callback
   */
  void updatePacketProcessorsPrewriteRequests();

  // Releases the unreleased read bytes held for a removed stream.
  quic::Expected<void, LocalErrorCode> releaseRemovedStreamReadBytes(
      StreamId id);

  uint64_t qlogRefcnt_{0};
};

std::ostream& operator<<(std::ostream& os, const QuicTransportBaseLite& qt);

} // namespace quic
