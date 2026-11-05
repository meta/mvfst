/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Random.h>
#include <folly/container/EvictingCacheMap.h>
#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <atomic>
#include <cstdint>
#include <limits>
#include <type_traits>

#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/events/HighResQuicTimer.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/server/RateLimiter.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class AcceptObserver;
class QuicServerWorker;

struct DispatchTarget {
  QuicServerWorker* worker = nullptr;
};

struct WorkerEndpoint {
  folly::EventBase* evb = nullptr;
  std::shared_ptr<DispatchTarget> target;
};

struct RunState {
  static constexpr uint64_t kNoStopRequest =
      std::numeric_limits<uint64_t>::max();

  std::vector<WorkerEndpoint> peers;
  std::atomic<uint64_t> stopReason{kNoStopRequest};

  void requestStop(LocalErrorCode reason);

  [[nodiscard]] bool stopRequested() const {
    return stopReason.load(std::memory_order_relaxed) != kNoStopRequest;
  }

  [[nodiscard]] LocalErrorCode latchedStopReason(
      LocalErrorCode fallback = LocalErrorCode::SHUTTING_DOWN) const {
    auto value = stopReason.load(std::memory_order_relaxed);
    return value == kNoStopRequest ? fallback
                                   : static_cast<LocalErrorCode>(value);
  }

  bool latchStop(LocalErrorCode reason) {
    auto expected = kNoStopRequest;
    return stopReason.compare_exchange_strong(
        expected, static_cast<uint64_t>(reason), std::memory_order_relaxed);
  }
};

class QuicServerWorker : public FollyAsyncUDPSocketAlias::ReadCallback,
                         public QuicServerTransport::RoutingCallback,
                         public QuicServerTransport::HandshakeFinishedCallback,
                         public ServerConnectionIdRejector,
                         public folly::HHWheelTimer::Callback {
 public:
  static int getUnfinishedHandshakeCount();

  using TransportSettingsOverrideFn =
      std::function<void(quic::TransportSettings&)>;

  QuicServerWorker(
      RunState* runState,
      size_t workerIndex,
      TransportSettings transportSettings = TransportSettings());

  ~QuicServerWorker() override;

  [[nodiscard]] folly::EventBase* getEventBase() const;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /**
   * Sets the listening socket
   */
  void setSocket(std::unique_ptr<FollyAsyncUDPSocketAlias> socket);

  /**
   * Enable SO_ZEROCOPY on the worker's listener socket so the listener
   * and all per-connection writers that share its fd can issue
   * MSG_ZEROCOPY sends. Must be called from the worker's eventbase
   * thread after setSocket().
   *
   * After this returns, makeTransport() routes per-connection writer
   * creation through `QuicUDPSocketFactory::makeAlias`, whose default
   * implementation calls `folly::AsyncUDPSocket::createPeerOnSameFd`
   * to wire up FDOwnership::SHARED, share the listener's per-fd
   * ZeroCopyFdBookkeeping, and call setZeroCopy(true). The listener
   * remains the sole socket draining POLLERR for the shared fd, and
   * its onCompletion routes IOBuf release callbacks back to whichever
   * per-conn writer originally registered the buf.
   */
  quic::Expected<void, QuicError> enableZeroCopy();

  /**
   * Sets the socket options
   */
  void setSocketOptions(folly::SocketOptionMap* options) {
    socketOptions_ = options;
  }

  /**
   * Binds to the given address
   */
  void bind(
      const quic::SocketAddress& address,
      FollyAsyncUDPSocketAlias::BindOptions bindOptions =
          FollyAsyncUDPSocketAlias::BindOptions());

  void prepareForStart();

  /**
   * start reading data from the socket
   */
  void start();

  [[nodiscard]] bool isStopping() const noexcept {
    return stopping_;
  }

  /*
   * Pause reading from the listening socket this worker is bound to
   */
  void pauseRead();

  /**
   * Returns listening address of this server
   */
  [[nodiscard]] const quic::SocketAddress& getAddress() const;

  /*
   * Returns the File Descriptor of the listening socket
   */
  int getFD();

  /**
   * Returns this worker's listener `folly::AsyncUDPSocket` (the same socket
   * passed to `setSocket()` and bound by `bind()`), or `nullptr` if no
   * listener socket has been set yet (e.g. before `start()`).
   *
   * Intended for observability consumers (e.g. tperf MSG_ZEROCOPY counter
   * aggregation) that want to read per-fd accessors on `folly::AsyncUDPSocket`
   * — for example `getZeroCopyCompletionsZc()` / `zeroCopyEnabled()` — across
   * all of a `QuicServer`'s workers via `QuicServer::forEachListenerSocket`.
   * The returned pointer is owned by this worker; do not free it.
   */
  [[nodiscard]] FollyAsyncUDPSocketAlias* getListenerSocket() const noexcept {
    return socket_.get();
  }

  /*
   * Apply all the socket options (pre/post bind).
   * Called after takeover.
   */
  void applyAllSocketOptions();

  /**
   * Initialize and bind given listening socket to the given takeover address
   * so that this server can accept and process misrouted packets forwarded
   * by other server
   */
  void allowBeingTakenOver(
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const quic::SocketAddress& address);

  /**
   * Override listening address for takeover packets
   * Returns const ref to SocketAddress representing the address it is bound to.
   */
  const quic::SocketAddress& overrideTakeoverHandlerAddress(
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const quic::SocketAddress& address);

  /**
   * Setup address that the taken over quic server is listening to forward
   * misrouted packets belonging to the old server.
   */
  void startPacketForwarding(const quic::SocketAddress& destAddr);

  /**
   * Stop forwarding of packets and clean up any allocated resources
   */
  void stopPacketForwarding();

  void stopPacketForwardingAfter(std::chrono::milliseconds delay);

  void resetTakeoverHandler();

  /*
   * Returns the File Descriptor of the listening socket that handles the
   * packets routed from another quic server.
   */
  int getTakeoverHandlerSocketFD();

  [[nodiscard]] TakeoverProtocolVersion getTakeoverProtocolVersion()
      const noexcept;

  /*
   * Sets the id of the server, that is later used in the routing of the packets
   * The id will be used to set a bit in the ConnectionId for routing.
   */
  void setProcessId(enum ProcessId id) noexcept;

  /*
   * Get the id of the server.
   * The id will be used to set a bit in the ConnectionId for routing (which is
   * later used in the routing of the packets)
   */
  [[nodiscard]] ProcessId getProcessId() const noexcept;

  /**
   * Set the id for this worker thread. Server can make routing decision by
   * setting this id in the ConnectionId
   */
  void setWorkerId(uint8_t id) noexcept;

  /**
   * Returns the id for this worker thread.
   */
  [[nodiscard]] uint8_t getWorkerId() const noexcept;

  /**
   * Set the id for the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint32_t hostId) noexcept;

  /**
   * Set version of connection ID used by quic server.
   */
  void setConnectionIdVersion(ConnectionIdVersion cidVersion) noexcept;

  void setNewConnectionSocketFactory(QuicUDPSocketFactory* factory);

  void setTransportFactory(QuicServerTransportFactory* factory);

  void setSupportedVersions(const std::vector<QuicVersion>& supportedVersions);

  /**
   * If true, start to reject any new connection during handshake
   */
  void rejectNewConnections(
      std::function<bool(const quic::SocketAddress&)> rejectNewConnections);

  /**
   * Set callback to determine if MVFST_PRIMING protocol version is enabled
   */
  void setPrimingEnabledCallback(std::function<bool()> isPrimingEnabled);

  /**
   * If true, begin rejecting connections with block listed source ports
   */
  void setIsBlockListedSrcPort(
      std::function<bool(uint16_t)> isBlockListedSrcPort_);

  /**
   * Set a health-check token that can be used to ping if the server is alive
   */
  void setHealthCheckToken(const std::string& healthCheckToken);

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently and per thread, it is
   * important that the implementation is efficient.
   * NOTE: Quic does not synchronize across threads before calling it.
   */
  void setTransportStatsCallback(
      std::unique_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  /**
   * Return callback for recording various transport stats info.
   */
  [[nodiscard]] QuicTransportStatsCallback* getTransportStatsCallback()
      const noexcept;

  /**
   * Set ConnectionIdAlgo implementation to encode and decode ConnectionId with
   * various info, such as routing related info.
   */
  void setConnectionIdAlgo(
      std::unique_ptr<ConnectionIdAlgo> connIdAlgo) noexcept;

  /**
   * Set the rate limiter which will be used to rate limit new connections.
   */
  void setRateLimiter(std::unique_ptr<RateLimiter> rateLimiter);

  void setUnfinishedHandshakeLimit(std::function<int()> limitFn);

  // Read callback
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const quic::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;

  // Routing callback
  /**
   * Called when a connection id is available for a new connection (i.e flow)
   * The connection-id here is chosen by this server
   */
  void onConnectionIdAvailable(
      QuicServerTransport::Ptr transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connection id has been retired by the peer thru a
   * RETIRE_CONNECTION_ID frame.
   */
  void onConnectionIdRetired(
      QuicServerTransport::Ref transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connection id is bound and ip address should not
   * be used any more for routing.
   */
  void onConnectionIdBound(
      QuicServerTransport::Ptr transport) noexcept override;

  /**
   * source: Source address and source CID
   * connectionId: destination CID (i.e. server chosen connection-id)
   */
  void onConnectionUnbound(
      QuicServerTransport* transport,
      const QuicServerTransport::SourceIdentity& source,
      const std::vector<ConnectionIdData>& connectionIdData) noexcept override;

  void onHandshakeFinished() noexcept override;

  void onHandshakeUnfinished() noexcept override;

  // From ServerConnectionIdRejector:
  [[nodiscard]] bool rejectConnectionId(
      const ConnectionId& candidate) const noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

  // Adapter for the QuicAsyncUDPSocket::ReadCallback (shouldOnlyNotify)
  // interface. Forwards onNotifyDataAvailable to onSocketReadable on the
  // worker; delegates onReadError / onReadClosed to the worker.
  class QuicReadCallbackAdapter : public QuicAsyncUDPSocket::ReadCallback {
   public:
    explicit QuicReadCallbackAdapter(QuicServerWorker* worker)
        : worker_(worker) {}

    bool shouldOnlyNotify() override {
      return true;
    }

    void getReadBuffer(void** /*buf*/, size_t* /*len*/) noexcept override {
      folly::terminate_with<std::runtime_error>(
          "QuicServerWorker::QuicReadCallbackAdapter::getReadBuffer "
          "unsupported on shouldOnlyNotify path");
    }

    void onDataAvailable(
        const quic::SocketAddress& /*client*/,
        size_t /*len*/,
        bool /*truncated*/,
        OnDataAvailableParams /*params*/) noexcept override {
      folly::terminate_with<std::runtime_error>(
          "QuicServerWorker::QuicReadCallbackAdapter::onDataAvailable "
          "unsupported on shouldOnlyNotify path");
    }

    void onNotifyDataAvailable(QuicAsyncUDPSocket& sock) noexcept override {
      worker_->onSocketReadable(sock);
    }

    void onReadError(const folly::AsyncSocketException& ex) noexcept override {
      worker_->onReadError(ex);
    }

    void onReadClosed() noexcept override {
      worker_->onReadClosed();
    }

   private:
    QuicServerWorker* worker_;
  };

  void dispatchPacketData(
      const quic::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      Optional<QuicVersion> quicVersion,
      bool isForwardedData = false) noexcept;

  void routeOrDispatch(
      const quic::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      const Optional<QuicVersion>& quicVersion,
      bool isForwardedData);

  using ConnIdToTransportMap = folly::
      F14FastMap<ConnectionId, QuicServerTransport::Ptr, ConnectionIdHash>;

  struct SourceIdentityHash {
    size_t operator()(const QuicServerTransport::SourceIdentity& sid) const;
  };

  using SrcToTransportMap = folly::F14FastMap<
      QuicServerTransport::SourceIdentity,
      QuicServerTransport::Ptr,
      SourceIdentityHash>;

  [[nodiscard]] const ConnIdToTransportMap& getConnectionIdMap() const;

  [[nodiscard]] const SrcToTransportMap& getSrcToTransportMap() const;

  void stopLocal(LocalErrorCode error);

  void shutdownAllConnections(LocalErrorCode error);

  // for unit test
  FollyAsyncUDPSocketAlias::ReadCallback* getTakeoverHandlerCallback() {
    return takeoverCB_.get();
  }

  // Handle the network data for a udp packet. Caller must populate
  // packet.peerAddress with the datagram source. Public so tests can call it.
  void handleNetworkData(
      ReceivedUdpPacket& packet,
      bool isForwardedData = false) noexcept;

  /**
   * Try handling the data as a health check.
   */
  bool tryHandlingAsHealthCheck(
      const quic::SocketAddress& client,
      const Buf& data);

  /**
   * Return Infocallback ptr for various transport stats (such as packet
   * received, dropped etc). Since the callback is invoked very frequently and
   * per thread, it is important that the implementation is efficient.
   * NOTE: QuicServer does not synchronize across threads before calling it
   */
  QuicTransportStatsCallback* getStatsCallback() {
    return statsCallback_.get();
  }

  /**
   * Adds observer for accept events.
   *
   * Can be used to install socket observers and instrumentation without
   * changing / interfering with application-specific acceptor logic.
   *
   * @param observer     Observer to add (implements AcceptObserver).
   */
  virtual void addAcceptObserver(AcceptObserver* observer) {
    observerList_.add(observer);
  }

  /**
   * Remove observer for accept events.
   *
   * @param observer     Observer to remove.
   * @return             Whether observer found and removed from list.
   */
  virtual bool removeAcceptObserver(AcceptObserver* observer) {
    return observerList_.remove(observer);
  }

  void getAllConnectionsStats(std::vector<QuicConnectionStats>& stats);

  void timeoutExpired() noexcept override;
  void logTimeBasedStats();

 private:
  /**
   * Creates accepting socket from this server's listening address.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<FollyAsyncUDPSocketAlias> makeSocket(
      folly::EventBase* evb) const;

  /**
   * Creates accepting socket from the listening address denoted by given fd.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<FollyAsyncUDPSocketAlias> makeSocket(
      folly::EventBase* evb,
      int fd) const;

  /**
   * Creates a per-connection writer that shares the listener's kernel
   * fd via `QuicUDPSocketFactory::makeAlias`. Used when
   * `enableZeroCopy()` is set so all per-conn writers share the
   * listener's per-fd `ZeroCopyFdBookkeeping`. Parallels `makeSocket`
   * — invokes `mvfst_hook_on_socket_create` on the returned fd so
   * integrators observing newly-created per-conn UDP fds see the alias
   * path on equal footing with the non-zero-copy path.
   */
  [[nodiscard]] std::unique_ptr<FollyAsyncUDPSocketAlias> makeAlias() const;

  /**
   * Tries to get the encrypted retry token from a client initial packet
   */
  Optional<std::string> maybeGetEncryptedToken(ContiguousReadCursor& cursor);

  /**
   * Returns the original destination connection id if encryptedToken is a
   * valid retry token for an Initial from clientIp to dstConnId.
   */
  Optional<ConnectionId> validateRetryToken(
      std::string& encryptedToken,
      const ConnectionId& dstConnId,
      const folly::IPAddress& clientIp);

  bool validNewToken(
      std::string& encryptedToken,
      const folly::IPAddress& clientIp);

  void sendRetryPacket(
      const quic::SocketAddress& client,
      QuicVersion version,
      const ConnectionId& dstConnId,
      const ConnectionId& srcConnId);

  /**
   * Returns a Retry source connection id, encoded with this worker's routing
   * params when possible so the client's next Initial is routed back to this
   * worker.
   */
  ConnectionId makeRetrySourceConnId(const ConnectionId& clientDstConnId);

  void sendResetPacket(
      const HeaderForm& headerForm,
      const quic::SocketAddress& client,
      const NetworkData& networkData,
      const ConnectionId& connId);

  bool maybeSendVersionNegotiationPacketOrDrop(
      const quic::SocketAddress& client,
      bool isInitial,
      LongHeaderInvariant& invariant,
      size_t datagramLen);

  void sendVersionNegotiationPacket(
      const quic::SocketAddress& client,
      LongHeaderInvariant& invariant);

  void recordRxDelay(
      const std::chrono::system_clock::time_point& currentTime,
      const timespec& socketRxTime);

  /**
   * Helper method to extract and log routing info from the given (dest) connId
   */
  [[nodiscard]] std::string logRoutingInfo(const ConnectionId& connId) const;

  bool hasTimestamping() {
    return (socket_ && (socket_->getTimestamping() > 0));
  }

  /**
   * Forward data to the right worker or to the takeover socket
   */
  void forwardNetworkData(
      const quic::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      const Optional<QuicVersion>& quicVersion,
      bool isForwardedData = false);

  // Create transport and invoke appropriate setters
  QuicServerTransport::Ptr makeTransport(
      QuicVersion quicVersion,
      const quic::SocketAddress& client,
      const Optional<ConnectionId>& srcConnId,
      const ConnectionId& dstConnId,
      bool validNewToken,
      const Optional<ConnectionId>& retryOriginalDstConnId);

  // Parses the dst conn id to determine if packet was incorrectly routed to
  // this host/process.
  PacketDropReason isDstConnIdMisrouted(
      const ConnectionId& dstConnId,
      const quic::SocketAddress& client);

  // Read handler for the shouldOnlyNotify path. Calls recvmmsgNetworkData,
  // then dispatches each packet to handleNetworkData using its peerAddress.
  void onSocketReadable(QuicAsyncUDPSocket& sock) noexcept;

  std::unique_ptr<FollyAsyncUDPSocketAlias> socket_;
  std::shared_ptr<FollyQuicAsyncUDPSocket> quicSocket_;
  std::unique_ptr<QuicReadCallbackAdapter> quicReadCallbackAdapter_;
  folly::SocketOptionMap* socketOptions_{nullptr};
  RunState* runState_{nullptr};
  size_t workerIndex_{0};
  bool stopping_{false};
  bool prepared_{false};
  bool started_{false};
  folly::EventBase* eventBase_{nullptr};
  folly::Executor::KeepAlive<folly::EventBase> evb_;

  // Set by enableZeroCopy(); selects the makeAlias() factory path in
  // makeTransport() so per-conn writers share the listener's fd and
  // ZC bookkeeping.
  bool zeroCopyEnabled_{false};

  // factories are owned by quic server
  QuicUDPSocketFactory* socketFactory_{nullptr};
  QuicServerTransportFactory* transportFactory_{nullptr};

  ConnIdToTransportMap connectionIdMap_;
  SrcToTransportMap sourceAddressMap_;

  folly::EvictingCacheMap<
      ConnectionId,
      SmallVec<
          NetworkData,
          kDefaultMaxBufferedPackets,
          folly::small_vector_policy::policy_in_situ_only<true>>,
      ConnectionIdHash>
      pending0RttData_{20};

  // Contains every unique transport that is mapped in connectionIdMap_.
  folly::F14FastMap<QuicServerTransport*, std::weak_ptr<QuicServerTransport>>
      boundServerTransports_;

  BufPtr readBuffer_;
  bool shutdown_{false};
  std::vector<QuicVersion> supportedVersions_;
  const TransportSettings transportSettings_;
  // Same value as transportSettings_.numGROBuffers_ if the kernel
  // supports GRO. otherwise 1
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  Optional<BufPtr> healthCheckToken_;
  std::function<bool(const quic::SocketAddress&)> rejectNewConnections_{
      [](const quic::SocketAddress&) { return false; }};
  std::function<bool()> isPrimingEnabled_{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort_{
      [](uint16_t) { return false; }};
  uint8_t workerId_{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  uint32_t hostId_{0};
  uint32_t prevHostId_{0};
  ConnectionIdVersion cidVersion_{ConnectionIdVersion::V1};
  // QuicServerWorker maintains ownership of the info stats callback
  std::unique_ptr<QuicTransportStatsCallback> statsCallback_;
  std::chrono::seconds timeLoggingSamplingInterval_{1};

  // Handle takeover between processes
  std::unique_ptr<TakeoverHandlerCallback> takeoverCB_;

  enum ProcessId processId_ { ProcessId::ZERO };

  TakeoverPacketHandler takeoverPktHandler_;
  bool packetForwardingEnabled_{false};
  QuicTimer::SharedPtr pacingTimer_;

  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;

  // Output buffer to be used for continuous memory GSO write
  std::unique_ptr<BufAccessor> bufAccessor_;

  // Rate limits the creation of new connections for this worker.
  std::unique_ptr<RateLimiter> newConnRateLimiter_;

  Optional<std::function<int()>> unfinishedHandshakeLimitFn_;

  int unfinishedHandshakes_{0};

  // Wrapper around list of AcceptObservers to handle cleanup on destruction
  class AcceptObserverList {
   public:
    explicit AcceptObserverList(QuicServerWorker* worker);

    /**
     * Destructor, triggers observerDetach for any attached observers.
     */
    ~AcceptObserverList();

    /**
     * Add observer and trigger observerAttach.
     */
    void add(AcceptObserver* observer);

    /**
     * Remove observer and trigger observerDetach.
     */
    bool remove(AcceptObserver* observer);

    /**
     * Get reference to vector containing observers.
     */
    [[nodiscard]] const std::vector<AcceptObserver*>& getAll() const {
      return observers_;
    }

   private:
    QuicServerWorker* worker_{nullptr};
    std::vector<AcceptObserver*> observers_;
  };

  // List of AcceptObservers
  AcceptObserverList observerList_;

  TimePoint largestPacketReceiveTime_{TimePoint::min()};
};

} // namespace quic
