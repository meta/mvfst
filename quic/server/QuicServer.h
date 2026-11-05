/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <limits>
#include <memory>
#include <vector>

#include <folly/Function.h>
#include <folly/container/F14Map.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicTransportStatsCallback.h>

FOLLY_GFLAGS_DECLARE_int32(qs_conn_id_version);

namespace quic {

namespace test {
class QuicServerTest;
class QuicServerMultiWorkerRoutingTest;
} // namespace test

// Construction-time server configuration. Application policy (TLS context,
// congestion-controller factory, batch-writer override, transport knob and
// experiment hooks, session setup) lives on the transport factory, not here.
struct ServerOptions {
  TransportSettings transportSettings;
  std::vector<QuicVersion> supportedVersions{
      {QuicVersion::MVFST,
       QuicVersion::MVFST_EXPERIMENTAL,
       QuicVersion::MVFST_EXPERIMENTAL2,
       QuicVersion::MVFST_EXPERIMENTAL3,
       QuicVersion::MVFST_EXPERIMENTAL4,
       QuicVersion::MVFST_EXPERIMENTAL5,
       QuicVersion::MVFST_ALIAS,
       QuicVersion::QUIC_V1,
       QuicVersion::QUIC_V1_ALIAS,
       QuicVersion::QUIC_V1_ALIAS2,
       QuicVersion::MVFST_PRIMING}};
  folly::SocketOptionMap socketOptions;
  FollyAsyncUDPSocketAlias::BindOptions bindOptions;
  ProcessId processId{ProcessId::ZERO};
  uint32_t hostId{0};
  Optional<ConnectionIdVersion> cidVersion;
  Optional<std::string> healthCheckToken;
  std::chrono::seconds rateLimitWindow{0};

  // Owned factories create worker-local resources during bind.
  std::unique_ptr<QuicUDPSocketFactory> listenerSocketFactory;
  std::unique_ptr<QuicUDPSocketFactory> socketFactory;
  std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory;
  std::unique_ptr<QuicTransportStatsCallbackFactory> transportStatsFactory;

  // Evaluated on worker EventBases. Callbacks shared by workers must support
  // concurrent invocation; they must not block or call server control methods.
  std::function<bool(const quic::SocketAddress&)> rejectNewConnections{
      [](const quic::SocketAddress&) { return false; }};
  std::function<bool()> isPrimingEnabled{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort{
      [](uint16_t) { return false; }};
  std::function<uint64_t()> rateLimitCount;
  std::function<int()> unfinishedHandshakeLimitFn{[]() { return 1048576; }};
  std::function<void(quic::TransportSettings&)> transportSettingsOverrideFn;
};

// Synchronous lifecycle owner for a fixed set of EventBase-local listeners.
//
// QuicServer always borrows its EventBases and transport factories; both
// must outlive the server (or its completed shutdown()). Control methods
// (bind/start/pauseRead/all-worker updates/shutdown and the destructor) form
// a single externally serialized sequence and, with more than one worker,
// must not run on a worker EventBase or from within a worker callback.
// Worker callbacks may only requestShutdown() asynchronously.
class QuicServer {
 public:
  using TransportSettingsOverrideFn =
      std::function<void(quic::TransportSettings&)>;

  // Worker ids are encoded in 8 bits of the connection id.
  static constexpr size_t kMaxWorkers = std::numeric_limits<uint8_t>::max() + 1;

  static std::shared_ptr<QuicServer> createQuicServer(ServerOptions options) {
    return std::make_shared<QuicServer>(std::move(options));
  }

  explicit QuicServer(ServerOptions options);

  ~QuicServer();

  QuicServer(const QuicServer&) = delete;
  QuicServer& operator=(const QuicServer&) = delete;
  QuicServer(QuicServer&&) = delete;
  QuicServer& operator=(QuicServer&&) = delete;

  enum class State : uint8_t { Created, Bound, Running, Paused, Stopped };

  [[nodiscard]] State state() const noexcept {
    return phase_;
  }

  [[nodiscard]] bool stopping() const noexcept {
    return runState_.stopRequested() && phase_ != State::Stopped;
  }

  // Creates one worker per EventBase and binds its listener. Throws on
  // failure after rolling back on the correct EventBases. inheritedFds are
  // takeover listening fds, one per worker (-1 entries bind normally).
  void bind(
      const quic::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs,
      const std::vector<int>& inheritedFds = {});

  // Attaches a borrowed transport factory to the worker on evb. Completes
  // on the destination EventBase; only before the first start().
  void addTransportFactory(
      folly::EventBase* evb,
      QuicServerTransportFactory* factory);

  bool addAcceptObserver(folly::EventBase* evb, AcceptObserver* observer);
  bool removeAcceptObserver(folly::EventBase* evb, AcceptObserver* observer);

  // Bound -> Running; Paused -> Running. Every worker is prepared (factory,
  // socket, zero-copy, startup observers) before any read is enabled.
  void start();

  // Pauses reading on the primary listeners; Running -> Paused.
  void pauseRead();

  // Latches an asynchronous stop request; safe from worker callbacks.
  void requestShutdown(LocalErrorCode error = LocalErrorCode::SHUTTING_DOWN);

  // Completes shutdown: closes connections and destroys workers on their
  // EventBases before returning.
  void shutdown(LocalErrorCode error = LocalErrorCode::SHUTTING_DOWN);

  // Bound address by value (cold-path snapshot). Requires bind().
  [[nodiscard]] quic::SocketAddress getAddress() const;

  [[nodiscard]] std::vector<folly::EventBase*> getWorkerEvbs() const noexcept;

  [[nodiscard]] const TransportSettings& getTransportSettings() const noexcept;

  [[nodiscard]] ProcessId getProcessId() const noexcept;

  // Live controls: copied to each worker on its EventBase.
  void setHostId(uint32_t hostId) noexcept;

  void rejectNewConnections(
      std::function<bool(const quic::SocketAddress&)> rejectFn);

  void setPrimingEnabledCallback(std::function<bool()> isPrimingEnabled);

  void blockListedSrcPort(std::function<bool(uint16_t)> isBlockListedSrcPort);

  void setHealthCheckToken(const std::string& healthCheckToken);

  // Takeover operations.
  void allowBeingTakenOver(const quic::SocketAddress& addr);

  quic::SocketAddress overrideTakeoverHandlerAddress(
      const quic::SocketAddress& addr);

  void startPacketForwarding(const quic::SocketAddress& destAddr);

  void stopPacketForwarding(std::chrono::milliseconds delay);

  [[nodiscard]] int getListeningSocketFD() const;

  [[nodiscard]] std::vector<int> getAllListeningSocketFDs() const noexcept;

  [[nodiscard]] int getTakeoverHandlerSocketFD() const;

  [[nodiscard]] TakeoverProtocolVersion getTakeoverProtocolVersion()
      const noexcept;

  // Enables SO_ZEROCOPY on every worker listener; see QuicServerWorker.
  quic::Expected<void, QuicError> enableZeroCopy();

  void getAllConnectionsStats(std::vector<QuicConnectionStats>& stats);

  // Invokes fn once per bound worker listener, synchronously on the
  // owning worker's EventBase; stopped workers are skipped. Pointers are
  // worker-owned and must not outlive the callback; observation only.
  void forEachListenerSocket(
      folly::FunctionRef<void(const folly::AsyncUDPSocket*)> fn) const;

 private:
  friend class test::QuicServerTest;
  friend class test::QuicServerMultiWorkerRoutingTest;
  friend class ThreadedQuicServer;

  QuicServerWorker* FOLLY_NULLABLE findWorkerForEvb(folly::EventBase* evb);

  static TransportSettings validateTransportSettings(
      TransportSettings transportSettings);

  void bindImpl(
      const quic::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs,
      const std::vector<int>& inheritedFds);

  void createWorkers();

  std::unique_ptr<QuicServerWorker> newWorkerWithoutSocket(size_t workerIndex);

  void bindWorkersToSocket(const quic::SocketAddress& address);

  // Synchronous: completes on each worker EventBase before returning.
  void runOnAllWorkersSync(const std::function<void(QuicServerWorker*)>& func);

  std::vector<QuicVersion> supportedVersions_{{
      QuicVersion::MVFST,
      QuicVersion::MVFST_EXPERIMENTAL,
      QuicVersion::MVFST_EXPERIMENTAL2,
      QuicVersion::MVFST_EXPERIMENTAL3,
      QuicVersion::MVFST_EXPERIMENTAL4,
      QuicVersion::MVFST_EXPERIMENTAL5,
      QuicVersion::MVFST_ALIAS,
      QuicVersion::QUIC_V1,
      QuicVersion::QUIC_V1_ALIAS,
      QuicVersion::QUIC_V1_ALIAS2,
      QuicVersion::MVFST_PRIMING,
  }};

  State phase_{State::Created};
  const TransportSettings transportSettings_;
  std::mutex startMutex_;
  std::atomic<bool> takeoverHandlerInitialized_{false};

  // Borrowed worker EventBases, fixed at bind().
  std::vector<folly::EventBase*> workerEvbs_;

  RunState runState_;
  std::vector<std::unique_ptr<QuicServerWorker>> workers_;
  folly::F14FastMap<folly::EventBase*, QuicServerWorker*> evbToWorkers_;
  std::unique_ptr<QuicUDPSocketFactory> listenerSocketFactory_;
  std::unique_ptr<QuicUDPSocketFactory> socketFactory_;

  Optional<std::string> healthCheckToken_;
  std::vector<int> listeningFDs_;
  ProcessId processId_{ProcessId::ZERO};
  uint32_t hostId_{0};
  ConnectionIdVersion cidVersion_{ConnectionIdVersion::V1};
  std::function<bool(const quic::SocketAddress&)> rejectNewConnections_{
      [](const quic::SocketAddress&) { return false; }};
  std::function<bool()> isPrimingEnabled_{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort_{
      [](uint16_t) { return false; }};
  std::unique_ptr<QuicTransportStatsCallbackFactory> transportStatsFactory_;
  std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory_;
  TransportSettingsOverrideFn transportSettingsOverrideFn_;
  quic::SocketAddress boundAddress_;
  folly::SocketOptionMap socketOptions_;

  struct RateLimit {
    RateLimit(std::function<uint64_t()> c, std::chrono::seconds w)
        : count(std::move(c)), window(w) {}

    std::function<uint64_t()> count;
    std::chrono::seconds window;
  };

  Optional<RateLimit> rateLimit_;

  std::function<int()> unfinishedHandshakeLimitFn_{[]() { return 1048576; }};

  FollyAsyncUDPSocketAlias::BindOptions bindOptions_;
};

} // namespace quic
