/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/server/QuicServer.h>

#include <folly/Random.h>
#include <folly/portability/GFlags.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/server/QuicReusePortUDPSocketFactory.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/server/SlidingWindowRateLimiter.h>
#include <iterator>
#include <stdexcept>
#include <string>

FOLLY_GFLAGS_DEFINE_int32(
    qs_conn_id_version,
    0,
    "connection id format version quic server used for encoding. only non-zero version is honored");

namespace {
using namespace quic;

[[maybe_unused]] constexpr std::string_view kQuicServerNotBound =
    "Quic server is not bound. Consider calling bind() prior to: ";

void validateHealthCheckToken(const std::string& healthCheckToken) {
  // Make sure the token satisfies the required properties, i.e. it is not a
  // valid quic header.
  auto parsed = parseHeader(*BufHelpers::copyBuffer(healthCheckToken));
  MVCHECK(!parsed.has_value());
  MVCHECK_GT(healthCheckToken.size(), kMinHealthCheckTokenSize);
}

} // namespace

//
namespace quic {

QuicServer::QuicServer(ServerOptions options)
    : transportSettings_(
          validateTransportSettings(std::move(options.transportSettings))) {
#ifdef _WIN32
  listenerSocketFactory_ = std::make_unique<QuicReusePortUDPSocketFactory>(
      true /* reusePort*/, true /* reuseAddr */);
#else
  listenerSocketFactory_ = std::make_unique<QuicReusePortUDPSocketFactory>();
#endif
  socketFactory_ = std::make_unique<QuicSharedUDPSocketFactory>();
  if (FLAGS_qs_conn_id_version) {
    // only set cidVersion_ if gflag is non-zero. otherwise,
    // cidVersion_ is V1 by default
    cidVersion_ = (ConnectionIdVersion)FLAGS_qs_conn_id_version;
  }
  supportedVersions_ = std::move(options.supportedVersions);
  socketOptions_ = std::move(options.socketOptions);
  bindOptions_ = options.bindOptions;
  processId_ = options.processId;
  hostId_ = options.hostId;
  if (options.cidVersion && !FLAGS_qs_conn_id_version) {
    cidVersion_ = *options.cidVersion;
  }
  if (options.listenerSocketFactory) {
    listenerSocketFactory_ = std::move(options.listenerSocketFactory);
  }
  if (options.socketFactory) {
    socketFactory_ = std::move(options.socketFactory);
  }
  connIdAlgoFactory_ = std::move(options.connIdAlgoFactory);
  transportStatsFactory_ = std::move(options.transportStatsFactory);
  rejectNewConnections_ = std::move(options.rejectNewConnections);
  isPrimingEnabled_ = std::move(options.isPrimingEnabled);
  isBlockListedSrcPort_ = std::move(options.isBlockListedSrcPort);
  if (options.healthCheckToken) {
    validateHealthCheckToken(*options.healthCheckToken);
  }
  healthCheckToken_ = std::move(options.healthCheckToken);
  if (options.rateLimitCount) {
    rateLimit_.emplace(
        std::move(options.rateLimitCount), options.rateLimitWindow);
  }
  unfinishedHandshakeLimitFn_ = std::move(options.unfinishedHandshakeLimitFn);
  transportSettingsOverrideFn_ = std::move(options.transportSettingsOverrideFn);
}

void QuicServer::forEachListenerSocket(
    folly::FunctionRef<void(const folly::AsyncUDPSocket*)> fn) const {
  if (phase_ == State::Stopped) {
    return;
  }
  const auto peers = runState_.peers;
  std::exception_ptr failure;
  for (const auto& peer : peers) {
    if (peer.evb == nullptr || peer.target == nullptr) {
      continue;
    }
    peer.evb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [target = peer.target, fn, &failure] {
          try {
            auto* worker = target->worker;
            if (worker == nullptr || worker->isStopping()) {
              return;
            }
            if (const auto* sock = worker->getListenerSocket()) {
              fn(sock);
            }
          } catch (...) {
            if (!failure) {
              failure = std::current_exception();
            }
          }
        });
  }
  if (failure) {
    std::rethrow_exception(failure);
  }
}

ProcessId QuicServer::getProcessId() const noexcept {
  return processId_;
}

void QuicServer::bind(
    const quic::SocketAddress& address,
    const std::vector<folly::EventBase*>& evbs,
    const std::vector<int>& inheritedFds) {
  bindImpl(address, evbs, inheritedFds);
}

void QuicServer::bindImpl(
    const quic::SocketAddress& address,
    const std::vector<folly::EventBase*>& evbs,
    const std::vector<int>& inheritedFds) {
  MVCHECK(phase_ == State::Created, "QuicServer::bind requires Created state");
  if (evbs.size() > kMaxWorkers) {
    throw std::invalid_argument(
        "Quic Server does not support more than " +
        std::to_string(kMaxWorkers) + " workers");
  }
  MVCHECK(!evbs.empty());
  {
    folly::F14FastSet<folly::EventBase*> seen;
    for (auto* evb : evbs) {
      MVCHECK(evb, "QuicServer::bind requires non-null EventBases");
      MVCHECK(
          seen.insert(evb).second,
          "QuicServer::bind requires distinct EventBases");
    }
  }
  if (runState_.stopRequested()) {
    shutdown(runState_.latchedStopReason());
    throw std::runtime_error(
        "QuicServer::bind called after shutdown was requested");
  }
  listeningFDs_ = inheritedFds;

  // if the connid algo factory is not set, use default impl
  if (!connIdAlgoFactory_) {
    connIdAlgoFactory_ = std::make_unique<DefaultConnectionIdAlgoFactory>();
  }

  workerEvbs_ = evbs;
  try {
    createWorkers();
    bindWorkersToSocket(address);
  } catch (...) {
    shutdown(LocalErrorCode::INTERNAL_ERROR);
    throw;
  }
  phase_ = State::Bound;
}

void QuicServer::createWorkers() {
  MVVLOG(4) << "Initializing workers";
  MVCHECK(workers_.empty());
  runState_.peers.clear();
  runState_.peers.reserve(workerEvbs_.size());
  for (auto* evb : workerEvbs_) {
    runState_.peers.push_back(
        WorkerEndpoint{
            .evb = evb, .target = std::make_shared<DispatchTarget>()});
  }
}

std::unique_ptr<QuicServerWorker> QuicServer::newWorkerWithoutSocket(
    size_t workerIndex) {
  auto worker = std::make_unique<QuicServerWorker>(
      &runState_, workerIndex, transportSettings_);
  worker->setNewConnectionSocketFactory(socketFactory_.get());
  worker->setSupportedVersions(supportedVersions_);
  worker->rejectNewConnections(rejectNewConnections_);
  worker->setPrimingEnabledCallback(isPrimingEnabled_);
  worker->setIsBlockListedSrcPort(isBlockListedSrcPort_);
  worker->setProcessId(processId_);
  worker->setHostId(hostId_);
  worker->setConnectionIdVersion(cidVersion_);
  if (healthCheckToken_) {
    worker->setHealthCheckToken(*healthCheckToken_);
  }
  if (transportStatsFactory_) {
    auto statsCallback = transportStatsFactory_->make();
    if (!statsCallback) {
      throw std::runtime_error(
          "QuicServer transport stats factory returned null");
    }
    worker->setTransportStatsCallback(std::move(statsCallback));
  }
  auto connIdAlgo = connIdAlgoFactory_->make();
  if (!connIdAlgo) {
    throw std::runtime_error(
        "QuicServer connection id algo factory returned null");
  }
  worker->setConnectionIdAlgo(std::move(connIdAlgo));
  if (rateLimit_) {
    worker->setRateLimiter(
        std::make_unique<SlidingWindowRateLimiter>(
            rateLimit_->count, rateLimit_->window));
  }
  worker->setUnfinishedHandshakeLimit(unfinishedHandshakeLimitFn_);
  worker->setTransportSettingsOverrideFn(transportSettingsOverrideFn_);
  return worker;
}

void QuicServer::bindWorkersToSocket(const quic::SocketAddress& address) {
  boundAddress_ = address;
  std::exception_ptr failure;
  for (size_t i = 0; i < workerEvbs_.size(); ++i) {
    auto* workerEvb = workerEvbs_[i];
    // Synchronous: `this` outlives the call. The AndWait boundary is
    // noexcept, so capture failures and rethrow below; bindImpl rolls back.
    workerEvb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [this, workerEvb, processId = processId_, idx = i, &failure] {
          std::lock_guard<std::mutex> guard(startMutex_);
          if (failure) {
            return;
          }
          try {
            if (runState_.stopRequested()) {
              throw std::runtime_error(
                  "QuicServer bind aborted: shutdown was requested");
            }
            auto worker = newWorkerWithoutSocket(idx);
            worker->setWorkerId(static_cast<uint8_t>(idx));
            auto workerSocket = listenerSocketFactory_->make(workerEvb, -1);
            int takeoverOverFd = -1;
            if (listeningFDs_.size() > idx) {
              takeoverOverFd = listeningFDs_[idx];
            }
            worker->setSocketOptions(&socketOptions_);
            // dup the takenover socket on only one worker and bind the rest
            if (takeoverOverFd >= 0) {
              workerSocket->setFD(
                  folly::NetworkSocket::fromFd(::dup(takeoverOverFd)),
                  // set ownership to OWNS to allow ::close()'ing of of the fd
                  // when this server goes away
                  FollyAsyncUDPSocketAlias::FDOwnership::OWNS);
              worker->setSocket(std::move(workerSocket));
              if (idx == 0) {
                boundAddress_ = worker->getAddress();
              }
              MVVLOG(4) << "Set up dup()'ed fd for address=" << boundAddress_
                        << " on workerId=" << (int)worker->getWorkerId();
              worker->applyAllSocketOptions();
            } else {
              MVVLOG(4) << "No valid takenover fd found for address="
                        << boundAddress_
                        << ". binding on worker=" << worker.get()
                        << " workerId=" << (int)worker->getWorkerId()
                        << " processId=" << (int)processId;
              worker->setSocket(std::move(workerSocket));
              worker->bind(boundAddress_, bindOptions_);
              if (idx == 0) {
                boundAddress_ = worker->getAddress();
              }
            }
            auto* workerPtr = worker.get();
            evbToWorkers_.emplace(workerEvb, workerPtr);
            workers_.push_back(std::move(worker));
            runState_.peers[idx].target->worker = workerPtr;
          } catch (...) {
            if (!failure) {
              failure = std::current_exception();
            }
          }
        });
    if (failure) {
      break;
    }
    if (runState_.stopRequested()) {
      failure = std::make_exception_ptr(
          std::runtime_error(
              "QuicServer bind aborted: shutdown was requested"));
      break;
    }
  }
  if (failure) {
    std::rethrow_exception(failure);
  }
  if (runState_.stopRequested()) {
    throw std::runtime_error("QuicServer bind aborted: shutdown was requested");
  }
}

void QuicServer::start() {
  if (phase_ == State::Running) {
    return;
  }
  MVCHECK(
      phase_ == State::Bound || phase_ == State::Paused,
      kQuicServerNotBound << __func__);
  std::exception_ptr failure;
  if (runState_.stopRequested()) {
    failure = std::make_exception_ptr(
        std::runtime_error(
            "QuicServer::start called after shutdown was requested"));
  }
  if (!failure && phase_ == State::Bound) {
    for (auto& worker : workers_) {
      worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
        try {
          worker->prepareForStart();
        } catch (...) {
          if (!failure) {
            failure = std::current_exception();
          }
        }
      });
      if (failure) {
        break;
      }
      if (runState_.stopRequested()) {
        failure = std::make_exception_ptr(
            std::runtime_error(
                "QuicServer::start aborted: shutdown was requested"));
        break;
      }
    }
  }
  if (!failure && runState_.stopRequested()) {
    failure = std::make_exception_ptr(
        std::runtime_error(
            "QuicServer::start aborted: shutdown was requested"));
  }
  if (!failure) {
    for (auto& worker : workers_) {
      worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
        try {
          worker->start();
        } catch (...) {
          if (!failure) {
            failure = std::current_exception();
          }
        }
      });
      if (failure) {
        break;
      }
      if (runState_.stopRequested()) {
        failure = std::make_exception_ptr(
            std::runtime_error(
                "QuicServer::start aborted: shutdown was requested"));
        break;
      }
    }
  }
  if (failure) {
    shutdown(LocalErrorCode::INTERNAL_ERROR);
    std::rethrow_exception(failure);
  }
  if (runState_.stopRequested()) {
    shutdown(LocalErrorCode::INTERNAL_ERROR);
    throw std::runtime_error(
        "QuicServer::start aborted: shutdown was requested");
  }
  phase_ = State::Running;
}

quic::Expected<void, QuicError> QuicServer::enableZeroCopy() {
  if (workers_.empty()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "QuicServer::enableZeroCopy called before workers initialized"));
  }
  Optional<QuicError> firstError;
  for (auto& worker : workers_) {
    worker->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&worker, &firstError]() mutable {
          auto result = worker->enableZeroCopy();
          if (result.hasError() && !firstError.has_value()) {
            firstError = result.error();
          }
        });
  }
  if (firstError.has_value()) {
    return quic::make_unexpected(*firstError);
  }
  return {};
}

void QuicServer::allowBeingTakenOver(const quic::SocketAddress& addr) {
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  MVCHECK(!workers_.empty());
  MVCHECK(!runState_.stopRequested());

  // this function shouldn't be called from worker's thread
  for ([[maybe_unused]] auto& worker : workers_) {
    MVDCHECK(
        // if the eventbase is not running, it returns true for isInEvbThread()
        !worker->getEventBase()->isRunning() ||
        !worker->getEventBase()->isInEventBaseThread());
  }
  // TODO workers_ (vector) is not protected against concurrent modifications
  auto numWorkers = workers_.size();
  std::exception_ptr failure;
  for (size_t i = 0; i < numWorkers; ++i) {
    auto workerEvb = workers_[i]->getEventBase();
    workerEvb->runInEventBaseThreadAndWait([&] {
      std::scoped_lock guard(startMutex_);
      if (failure) {
        return;
      }
      try {
        auto it = evbToWorkers_.find(workerEvb);
        MVCHECK(it != evbToWorkers_.end());
        auto worker = it->second;
        if (worker->isStopping()) {
          throw std::runtime_error(
              "QuicServer takeover setup on a stopping worker");
        }
        auto localListenSocket = listenerSocketFactory_->make(workerEvb, -1);
        worker->allowBeingTakenOver(std::move(localListenSocket), addr);
      } catch (...) {
        if (!failure) {
          failure = std::current_exception();
        }
      }
    });
    if (failure) {
      break;
    }
  }
  if (failure) {
    for (auto& worker : workers_) {
      worker->getEventBase()->runInEventBaseThreadAndWait(
          [&] { worker->resetTakeoverHandler(); });
    }
    std::rethrow_exception(failure);
  }
  MVVLOG(4) << "Bind all workers in the eventbase to takeover handler port";
  takeoverHandlerInitialized_ = true;
}

quic::SocketAddress QuicServer::overrideTakeoverHandlerAddress(
    const quic::SocketAddress& addr) {
  // synchronously bind workers to takeover handler port.
  // This method should not be called from a worker
  MVCHECK(!workers_.empty());
  MVCHECK(!runState_.stopRequested());
  MVCHECK(takeoverHandlerInitialized_, "TakeoverHanders are not initialized. ");

  // this function shouldn't be called from worker's thread
  for ([[maybe_unused]] auto& worker : workers_) {
    MVDCHECK(
        // if the eventbase is not running, it returns true for isInEvbThread()
        !worker->getEventBase()->isRunning() ||
        !worker->getEventBase()->isInEventBaseThread());
  }
  quic::SocketAddress boundAddress;
  std::exception_ptr failure;
  for (auto& worker : workers_) {
    worker->getEventBase()->runInEventBaseThreadAndWait([&] {
      std::scoped_lock guard(startMutex_);
      if (failure) {
        return;
      }
      try {
        if (worker->isStopping()) {
          throw std::runtime_error(
              "QuicServer takeover setup on a stopping worker");
        }
        auto workerEvb = worker->getEventBase();
        auto localListenSocket = listenerSocketFactory_->make(workerEvb, -1);
        boundAddress = worker->overrideTakeoverHandlerAddress(
            std::move(localListenSocket), addr);
      } catch (...) {
        if (!failure) {
          failure = std::current_exception();
        }
      }
    });
    if (failure) {
      break;
    }
  }
  if (failure) {
    std::rethrow_exception(failure);
  }
  return boundAddress;
}

void QuicServer::pauseRead() {
  runOnAllWorkersSync([&](auto worker) mutable { worker->pauseRead(); });
  if (phase_ == State::Running) {
    phase_ = State::Paused;
  }
}

void QuicServer::requestShutdown(LocalErrorCode error) {
  runState_.requestStop(error);
}

QuicServerWorker* FOLLY_NULLABLE
QuicServer::findWorkerForEvb(folly::EventBase* evb) {
  for (auto& worker : workers_) {
    if (worker->getEventBase() == evb) {
      return worker.get();
    }
  }
  return nullptr;
}

QuicServer::~QuicServer() {
  shutdown(LocalErrorCode::SHUTTING_DOWN);
}

void QuicServer::shutdown(LocalErrorCode error) {
  if (phase_ == State::Stopped) {
    return;
  }
  runState_.latchStop(error);
  auto reason = runState_.latchedStopReason(error);
  if (phase_ == State::Created && workers_.empty()) {
    evbToWorkers_.clear();
    runState_.peers.clear();
    phase_ = State::Stopped;
    return;
  }
  for (size_t i = 0; i < workers_.size(); ++i) {
    auto& worker = workers_[i];
    workerEvbs_[i]->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&] { worker->stopLocal(reason); });
    // protecting the erase in map with the mutex since
    // the erase could potentially affect concurrent accesses from other threads
    std::scoped_lock guard(startMutex_);
    evbToWorkers_.erase(workerEvbs_[i]);
  }
  for (size_t i = 0; i < workers_.size(); ++i) {
    auto& worker = workers_[i];
    workerEvbs_[i]->runImmediatelyOrRunInEventBaseThreadAndWait(
        [&worker] { worker.reset(); });
  }
  workers_.clear();
  evbToWorkers_.clear();
  runState_.peers.clear();
  phase_ = State::Stopped;
}

void QuicServer::runOnAllWorkersSync(
    const std::function<void(QuicServerWorker*)>& func) {
  std::vector<WorkerEndpoint> peers;
  {
    std::scoped_lock guard(startMutex_);
    if (runState_.stopRequested()) {
      return;
    }
    peers = runState_.peers;
  }
  for (const auto& peer : peers) {
    if (peer.evb == nullptr || peer.target == nullptr) {
      continue;
    }
    peer.evb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [target = peer.target, this, &func] {
          auto* worker = target->worker;
          if (worker == nullptr || worker->isStopping() ||
              runState_.stopRequested()) {
            return;
          }
          func(worker);
        });
  }
}

void QuicServer::setHostId(uint32_t hostId) noexcept {
  if (hostId_ == hostId) {
    MVLOG_WARNING << "HostId is already set to " << hostId;
    return;
  }
  hostId_ = hostId;
  MVVLOG(4) << "Setting hostId to " << hostId_ << " for quic server ";
  if (!workers_.empty()) {
    runOnAllWorkersSync(
        [hostId](auto worker) mutable { worker->setHostId(hostId); });
  }
}

void QuicServer::setHealthCheckToken(const std::string& healthCheckToken) {
  validateHealthCheckToken(healthCheckToken);
  healthCheckToken_ = healthCheckToken;
  runOnAllWorkersSync([healthCheckToken](auto worker) mutable {
    worker->setHealthCheckToken(healthCheckToken);
  });
}

const TransportSettings& QuicServer::getTransportSettings() const noexcept {
  return transportSettings_;
}

void QuicServer::rejectNewConnections(
    std::function<bool(const quic::SocketAddress&)> rejectFn) {
  rejectNewConnections_ = rejectFn;
  runOnAllWorkersSync([rejectFn](auto worker) mutable {
    worker->rejectNewConnections(rejectFn);
  });
}

void QuicServer::setPrimingEnabledCallback(
    std::function<bool()> isPrimingEnabled) {
  isPrimingEnabled_ = isPrimingEnabled;
  runOnAllWorkersSync([isPrimingEnabled](auto worker) mutable {
    worker->setPrimingEnabledCallback(isPrimingEnabled);
  });
}

void QuicServer::blockListedSrcPort(
    std::function<bool(uint16_t)> isBlockListedSrcPort) {
  isBlockListedSrcPort_ = isBlockListedSrcPort;
  runOnAllWorkersSync([isBlockListedSrcPort](auto worker) mutable {
    worker->setIsBlockListedSrcPort(isBlockListedSrcPort);
  });
}

void QuicServer::startPacketForwarding(const quic::SocketAddress& destAddr) {
  if (!workers_.empty()) {
    runOnAllWorkersSync([destAddr](auto worker) mutable {
      worker->startPacketForwarding(destAddr);
    });
  }
}

void QuicServer::stopPacketForwarding(std::chrono::milliseconds delay) {
  if (workers_.empty() || runState_.stopRequested()) {
    return;
  }
  runOnAllWorkersSync(
      [delay](auto worker) { worker->stopPacketForwardingAfter(delay); });
}

void QuicServer::addTransportFactory(
    folly::EventBase* evb,
    QuicServerTransportFactory* acceptor) {
  if (phase_ == State::Stopped) {
    return;
  }
  MVCHECK(evb);
  MVCHECK(acceptor);
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::scoped_lock guard(startMutex_);
    if (runState_.stopRequested()) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->setTransportFactory(acceptor);
    } else {
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase";
    }
  });
}

quic::SocketAddress QuicServer::getAddress() const {
  MVCHECK(phase_ != State::Created, kQuicServerNotBound << __func__);
  return boundAddress_;
}

int QuicServer::getListeningSocketFD() const {
  if (phase_ == State::Stopped || stopping()) {
    return -1;
  }
  const auto peers = runState_.peers;
  if (peers.empty()) {
    return -1;
  }
  const auto& peer = peers[0];
  if (peer.evb == nullptr || peer.target == nullptr) {
    return -1;
  }
  int fd = -1;
  peer.evb->runImmediatelyOrRunInEventBaseThreadAndWait(
      [target = peer.target, &fd] {
        auto* worker = target->worker;
        if (worker == nullptr || worker->isStopping()) {
          return;
        }
        fd = worker->getFD();
      });
  return fd;
}

std::vector<int> QuicServer::getAllListeningSocketFDs() const noexcept {
  if (phase_ == State::Stopped || stopping()) {
    return {};
  }
  const auto peers = runState_.peers;
  std::vector<int> sockets(peers.size(), -1);
  for (const auto& peer : peers) {
    if (peer.evb == nullptr || peer.target == nullptr) {
      continue;
    }
    peer.evb->runImmediatelyOrRunInEventBaseThreadAndWait(
        [target = peer.target, &sockets] {
          auto* worker = target->worker;
          if (worker == nullptr || worker->isStopping()) {
            return;
          }
          const int fd = worker->getFD();
          const size_t workerId = worker->getWorkerId();
          if (fd != -1 && workerId < sockets.size()) {
            sockets[workerId] = fd;
          }
        });
  }
  return sockets;
}

void QuicServer::getAllConnectionsStats(
    std::vector<QuicConnectionStats>& stats) {
  runOnAllWorkersSync(
      [&stats](auto worker) mutable { worker->getAllConnectionsStats(stats); });
}

TakeoverProtocolVersion QuicServer::getTakeoverProtocolVersion()
    const noexcept {
  if (phase_ == State::Stopped || stopping() || workers_.empty() ||
      !workers_[0]) {
    return TakeoverProtocolVersion::V0;
  }
  return workers_[0]->getTakeoverProtocolVersion();
}

int QuicServer::getTakeoverHandlerSocketFD() const {
  if (phase_ == State::Stopped || stopping()) {
    return -1;
  }
  MVCHECK(takeoverHandlerInitialized_, "TakeoverHanders are not initialized. ");
  const auto peers = runState_.peers;
  if (peers.empty()) {
    return -1;
  }
  const auto& peer = peers[0];
  if (peer.evb == nullptr || peer.target == nullptr) {
    return -1;
  }
  int fd = -1;
  peer.evb->runImmediatelyOrRunInEventBaseThreadAndWait(
      [target = peer.target, &fd] {
        auto* worker = target->worker;
        if (worker == nullptr || worker->isStopping()) {
          return;
        }
        fd = worker->getTakeoverHandlerSocketFD();
      });
  return fd;
}

std::vector<folly::EventBase*> QuicServer::getWorkerEvbs() const noexcept {
  if (phase_ == State::Stopped) {
    return {};
  }
  MVCHECK(phase_ != State::Created, kQuicServerNotBound << __func__);
  std::vector<folly::EventBase*> ebvs;
  for (const auto& worker : workers_) {
    if (worker == nullptr) {
      continue;
    }
    if (auto* evb = worker->getEventBase()) {
      ebvs.push_back(evb);
    }
  }
  return ebvs;
}

bool QuicServer::addAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  if (phase_ == State::Stopped) {
    return false;
  }
  MVCHECK(phase_ != State::Created, kQuicServerNotBound << __func__);
  MVCHECK(evb);
  bool success = false;
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::scoped_lock guard(startMutex_);
    if (runState_.stopRequested()) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      it->second->addAcceptObserver(observer);
      success = true;
    } else {
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase, "
                << "unable to add AcceptObserver";
      success = false;
    }
  });
  return success;
}

bool QuicServer::removeAcceptObserver(
    folly::EventBase* evb,
    AcceptObserver* observer) {
  if (phase_ == State::Stopped) {
    return false;
  }
  MVCHECK(phase_ != State::Created, kQuicServerNotBound << __func__);
  MVCHECK(evb);
  bool success = false;
  evb->runImmediatelyOrRunInEventBaseThreadAndWait([&] {
    std::scoped_lock guard(startMutex_);
    if (runState_.stopRequested()) {
      return;
    }
    auto it = evbToWorkers_.find(evb);
    if (it != evbToWorkers_.end()) {
      success = it->second->removeAcceptObserver(observer);
    } else {
      MVVLOG(3) << "Couldn't find associated worker for the given eventbase, "
                << "unable to remove AcceptObserver";
      success = false;
    }
  });
  return success;
}

// STATIC
TransportSettings QuicServer::validateTransportSettings(
    TransportSettings transportSettings) {
  // setting default stateless reset token if not set
  if (!transportSettings.statelessResetTokenSecret) {
    std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
    folly::Random::secureRandom(secret.data(), secret.size());
    transportSettings.statelessResetTokenSecret = secret;
  }
  return transportSettings;
}

} // namespace quic
