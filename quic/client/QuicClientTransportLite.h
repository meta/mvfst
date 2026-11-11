/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <chrono>

#include <folly/Random.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstCheck.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/observer/SocketObserverMacros.h> // QUIC_SOCKET_OBSERVERS_ENABLED
#include <quic/state/QuicConnectionStats.h>

namespace quic {

class ClientHandshakeFactory;
class QuicTokenCache;

struct ConnectionLifecycleDebugState {
  std::chrono::milliseconds connectionAge{0};
  std::chrono::milliseconds lastRxAge{0};
  std::chrono::milliseconds lastTxAge{0};
  Optional<std::chrono::milliseconds> idleDeadlineDelta;
  Optional<std::chrono::milliseconds> lastIdleDeadlineOverdue;
  uint64_t idleTimeoutFiredCount{0};
  uint64_t keepaliveTimeoutFiredCount{0};
  uint64_t keepaliveExpiredIdleDeadlineCount{0};
};

class QuicClientTransportLite
    : virtual public QuicTransportBaseLite,
      public QuicAsyncUDPSocket::ReadCallback,
      public QuicAsyncUDPSocket::ErrMessageCallback,
      public QuicPathManager::PathValidationCallback,
      public std::enable_shared_from_this<QuicClientTransportLite> {
 public:
  QuicClientTransportLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false);

  // Testing only API:
  QuicClientTransportLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize,
      PacketNum startingPacketNum,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicClientTransportLite() override;

  /**
   * Returns an un-connected QuicClientTransportLite which is self-owning.
   * The transport is cleaned up when the app calls close() or closeNow() on the
   * transport, or on receiving a terminal ConnectionCallback supplied on
   * start().
   * The transport is self owning in this case is to be able to
   * deal with cases where the app wants to dispose of the transport, however
   * the peer is still sending us packets. If we do not keep the transport alive
   * for this period, the kernel will generate unwanted ICMP echo messages.
   */
  template <class TransportType = QuicClientTransportLite>
  static std::shared_ptr<TransportType> newClient(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> sock,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false) {
    auto client = std::make_shared<TransportType>(
        evb,
        std::move(sock),
        std::move(handshakeFactory),
        connectionIdSize,
        useConnectionEndWithErrorCallback);
    client->setSelfOwning();
    return client;
  }

  /**
   * Supply the hostname to use to validate the server. Must be set before
   * start().
   */
  void setHostname(const std::string& hostname);

  /**
   * Supplies a new peer address to use for the connection. This must be called
   * at least once before start().
   */
  void addNewPeerAddress(quic::SocketAddress peerAddress);
  /**
   * Supplies the local address to use for the connection. Calling this is
   * optional. If not called, INADDR_ANY will be used.
   */
  void setLocalAddress(quic::SocketAddress localAddress);

  /**
   * Starts the connection.
   */
  virtual void start(
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb);

  /**
   * Returns whether or not TLS is resumed.
   */
  virtual bool isTLSResumed() const;

  /*
   * Export the underlying TLS key material.
   * label is the label argument for the TLS exporter.
   * context is the context value argument for the TLS exporter.
   * keyLength is the length of the exported key.
   */
  Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& label,
      const Optional<ByteRange>& context,
      uint16_t keyLength) const override {
    return clientConn_->clientHandshakeLayer->getExportedKeyingMaterial(
        label, context, keyLength);
  }

  int64_t getCertificateVerifyStartTimeMS() const {
    return clientConn_->clientHandshakeLayer->getCertificateVerifyStartTimeMS();
  }

  int64_t getCertificateVerifyEndTimeMS() const {
    return clientConn_->clientHandshakeLayer->getCertificateVerifyEndTimeMS();
  }

  enum class ZeroRttAttemptState : uint8_t {
    NotAttempted = 0,
    Accepted,
    Rejected
  };

  /**
   * Returns the state of the 0RTT attempt if there was one.
   */
  virtual ZeroRttAttemptState getZeroRttState() {
    if (!clientConn_->zeroRttRejected.has_value()) {
      return ZeroRttAttemptState::NotAttempted;
    }
    return *clientConn_->zeroRttRejected ? ZeroRttAttemptState::Rejected
                                         : ZeroRttAttemptState::Accepted;
  }

  bool hasZeroRttWriteCipher() const;

  /**
   * Runs the scheduled write now, while only 0-RTT application keys are
   * available. Does nothing on a priming connection.
   */
  void flushPendingZeroRttData();

  // Called with the failed address when Happy Eyeballs gives up on the first
  // address. It runs synchronously from the transport's write and socket-error
  // paths, so it must not throw or close/destroy the transport.
  void setHappyEyeballsFirstAddressFailureCallback(
      std::function<void(const quic::SocketAddress&)> callback) {
    clientConn_->happyEyeballsState.firstAddressFailureCallback =
        std::move(callback);
  }

  // From QuicTransportBase
  quic::Expected<void, QuicError> onReadData(
      const quic::SocketAddress& localAddress,
      ReceivedUdpPacket&& udpPacket) override;
  quic::Expected<void, QuicError> writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBaseLite> sharedGuard() override;
  std::shared_ptr<QuicClientTransportLite> sharedGuardClient();

  // QuicAsyncUDPSocket::ReadCallback
  void onReadClosed() noexcept override {}

  void onReadError(const folly::AsyncSocketException&) noexcept override;

  // QuicAsyncUDPSocket::ErrMessageCallback
  void errMessage(const cmsghdr& cmsg) noexcept override;

  void errMessageError(const folly::AsyncSocketException&) noexcept override {}

  void setSupportedVersions(const std::vector<QuicVersion>& versions) override;

  void setCongestionControl(CongestionControlType type) override;

  /**
   * Set socket options for the underlying socket.
   * Options are being set before and after bind, and not at the time of
   * invoking this function.
   */
  void setSocketOptions(const folly::SocketOptionMap& options) noexcept {
    socketOptions_ = options;
  }

  /**
   * Make QuicClient transport self owning.
   */
  void setSelfOwning();

  void onNetworkSwitch(std::unique_ptr<QuicAsyncUDPSocket> newSock) override;

  quic::Expected<PathIdType, QuicError> startPathProbe(
      std::unique_ptr<QuicAsyncUDPSocket> probeSocket,
      QuicPathManager::PathValidationCallback* probeResultCallback = nullptr);

  // Migrate to the path with the given id. The previous path is kept until a
  // packet is received on the new path, then cleaned up.
  quic::Expected<void, QuicError> migrateConnection(
      PathIdType pathId,
      bool resetCongestionControllerAndRtt = true);

  quic::Expected<void, QuicError> removePath(PathIdType pathId);

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently, it is
   * important that the implementation is efficient.
   */
  void setTransportStatsCallback(
      std::shared_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  /**
   * Set a token cache to store NEW_TOKEN frames received from the server.
   * The cache's putToken() will be called with the hostname and token.
   * The cache must outlive the transport.
   */
  void setTokenCache(QuicTokenCache* tokenCache) noexcept {
    tokenCache_ = tokenCache;
  }

  /**
   * Set a new token to be included in the initial packet. Must be set before
   * attempting to connect.
   */
  void setNewToken(std::string token) noexcept {
    clientConn_->newToken = std::move(token);
  }

  void createBufAccessor(size_t capacity) override {
    bufAccessor_ = std::make_unique<BufAccessor>(capacity);
    conn_->bufAccessor = bufAccessor_.get();
  }

  Optional<std::vector<TransportParameter>> getPeerTransportParams()
      const override;

  uint64_t getNumAckFramesSent() const;

  uint64_t getNumFlowControlFramesSent() const;

  uint64_t getNumPingFramesSent() const;

  uint64_t getEagainOrEwouldblockCount() const;

  uint64_t getEnobufsCount() const;

  std::chrono::milliseconds getConnectionIdleDuration() const;

  ConnectionLifecycleDebugState getConnectionLifecycleDebugState() const;

  int64_t getNetworkReadCallbackStartTimeMs() const;

  uint64_t getReceivedUdpDatagramCount() const;

  uint64_t getPtoCount() const;
  uint64_t getTotalPtoCount() const;
  uint64_t getPacketsSentCount() const;
  bool canRead() const;
  std::optional<int32_t> getHandshakeStatus() const;
  size_t getInitialReadBufferSize() const;
  size_t getHandshakeReadBufferSize() const;
  size_t getAppDataReadBufferSize() const;
  EncryptionLevel getReadEncryptionLevel() const;
  bool waitingForHandshakeData() const;

  const std::shared_ptr<const fizz::Cert> getPeerCertificate() const override;

  Optional<Handshake::TLSSummary> getTLSSummary() const override;

 protected:
  // From QuicSocket
  SocketObserverContainer* getSocketObserverContainer() const override {
#if QUIC_SOCKET_OBSERVERS_ENABLED
    return observerContainer_ ? observerContainer_->getPtr() : nullptr;
#else
    return nullptr;
#endif
  }

#if QUIC_SOCKET_OBSERVERS_ENABLED
  // Lazy: create the container (and publish a weak_ptr into conn_) on first
  // addObserver. undoAllClientStateForRetry preserves observerContainer.
  // Must be called on the same event base thread as the transport.
  SocketObserverContainer* ensureSocketObserverContainer() override {
    MVDCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
    if (!observerContainer_) {
      observerContainer_ =
          std::make_unique<WrappedSocketObserverContainer>(this);
      conn_->observerContainer = observerContainer_->getWeakPtr();
    }
    return observerContainer_->getPtr();
  }
#endif

  // From QuicAsyncUDPSocket::ReadCallback
  void getReadBuffer(void** buf, size_t* len) noexcept override;
  void onDataAvailable(
      const quic::SocketAddress& server,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;
  bool shouldOnlyNotify() override;
  void onNotifyDataAvailable(QuicAsyncUDPSocket& sock) noexcept override;

  [[nodiscard]] quic::Expected<void, QuicError> recvMsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      int numPackets,
      NetworkData& networkData,
      size_t& totalData);

  /**
   * Process a single UDP packet.
   *
   * A single UDP packet can contain multiple QUIC packets due to UDP packet
   * coalescing (see RFC 9000, section 12.2). When invoked, this function
   * attempts to transform the UDP packet data into one or more QUIC packets
   *
   * @param localAddress      The local address the socket was bound to.
   * @param networkData       UDP packet (peer address is on udpPacket).
   */
  quic::Expected<void, QuicError> processUdpPacket(
      const quic::SocketAddress& localAddress,
      ReceivedUdpPacket&& udpPacket);

  /**
   * Process data within a single UDP packet.
   *
   * A single UDP packet can contain multiple QUIC packets due to UDP packet
   * coalescing (see RFC 9000, section 12.2). When invoked, this function takes
   * UDP packet data and extracts a single QUIC packet from it. If there is
   * still data left over, it will remain in `udpPacketData` and can be
   * extracted by invoking this function again.
   *
   * Since all QUIC packets are extracted from the same UDP packet, the packet
   * timings associated with that UDP packet are used for all QUIC packets.
   *
   * @param localAddress  The address of the local socket.
   * @param udpPacket     The data received from the UDP socket along with
   *                      timings (peer address is on udpPacket).
   */
  quic::Expected<void, QuicError> processUdpPacketData(
      const quic::SocketAddress& localAddress,
      ReceivedUdpPacket& udpPacket);

  [[nodiscard]] quic::Expected<void, QuicError> startCryptoHandshake();

  virtual void happyEyeballsConnAttemptDelayTimeoutExpired() noexcept;

  virtual void cleanupHappyEyeballsState();

  virtual void startHappyEyeballsIfEnabled();

  virtual void happyEyeballsOnDataReceivedIfEnabled(
      const quic::SocketAddress& peerAddress);

  virtual void cancelHappyEyeballsConnAttemptDelayTimeout();

  [[nodiscard]] virtual bool happyEyeballsAddPeerAddressIfEnabled(
      const quic::SocketAddress& peerAddress);

  void handleAckFrame(
      const OutstandingPacketWrapper& outstandingPacket,
      const QuicWriteFrame& packetFrame,
      const ReadAckFrame&);

  [[nodiscard]] virtual quic::Expected<void, QuicError> processPackets(
      const quic::SocketAddress& localAddress,
      NetworkData&& networkData);

  [[nodiscard]] quic::Expected<void, QuicError> readWithRecvmsgSinglePacketLoop(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize);

  Optional<std::string> hostname_;

  QuicClientConnectionState* clientConn_;

  void maybeQlogDatagram(size_t len);

  void trackDatagramsReceived(uint32_t totalDatagrams, uint32_t totalDataLen);

  void asyncClose(QuicError error);

  void recordNetworkReadCallbackStart();

  quic::Expected<void, QuicError> maybeIssueConnectionIds();

  void onPathValidationResult(const PathInfo& pathInfo) override;

  // Same value as conn_->transportSettings.numGROBuffers_ if the kernel
  // supports GRO. otherwise kDefaultNumGROBuffers
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};

  // Path ID from the most recent migration. Cleaned up when a packet is
  // received on the new path, or immediately if another migration occurs.
  Optional<PathIdType> previousPathId_;

  // Override dispatchAsyncOp to handle client-specific operations
  void dispatchAsyncOp(AsyncOpData data) override;

  // Template-based async dispatch for complex cases with custom captures
  template <typename F>
  void runOnEvbAsync(F&& func) {
    auto evb = getEventBase();
    evb->runInLoop(
        [self = sharedGuardClient(),
         func = std::forward<F>(func),
         evb]() mutable {
          if (self->getEventBase() != evb) {
            return;
          }
          func(std::move(self));
        },
        true);
  }

  folly::SocketOptionMap socketOptions_;

 private:
  [[nodiscard]] quic::Expected<void, QuicError> adjustGROBuffers();

  /**
   * Send quic transport knobs defined by transportSettings.knobs to peer. This
   * calls setKnobs() internally.
   */
  quic::Expected<void, QuicError> maybeSendTransportKnobs();

  bool replaySafeNotified_{false};
  TimePoint networkReadCallbackStartTime_{};
  uint64_t receivedUdpDatagramCount_{0};
  // Set it QuicClientTransportLite is in a self owning mode. This will be
  // cleaned up when the caller invokes a terminal call to the transport.
  std::shared_ptr<QuicClientTransportLite> selfOwning_;
  std::vector<TransportParameter> customTransportParameters_;
  std::shared_ptr<QuicTransportStatsCallback> statsCallback_;
  // We will only send transport knobs once, this flag keeps track of it
  bool transportKnobsSent_{false};
  // Token cache for storing NEW_TOKEN frames from the server
  QuicTokenCache* tokenCache_{nullptr};

  // Output buf/accessor to be used for continuous memory writes.
  std::unique_ptr<BufAccessor> bufAccessor_;

  using PathValidationCallbackMap =
      UnorderedMap<PathIdType, QuicPathManager::PathValidationCallback*>;
  PathValidationCallbackMap pathValidationCallbacks_;

  // Track pending SCONE rate signal for conditional usage per spec
  Optional<QuicConnectionStateBase::SconeRateSignal> pendingSconeRateSignal_;

#if QUIC_SOCKET_OBSERVERS_ENABLED
  // MUST be the last member: destroyed first so observers can inspect
  // transport state during teardown.
  std::unique_ptr<WrappedSocketObserverContainer> observerContainer_;
#endif
};
} // namespace quic
