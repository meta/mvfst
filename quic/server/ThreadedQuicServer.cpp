/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/ThreadedQuicServer.h>

#include <folly/system/HardwareConcurrency.h>
#include <quic/common/MvfstLogging.h>
#include <quic/server/QuicServerBackend.h>

#include <algorithm>

namespace quic {

ThreadedQuicServer::ThreadedQuicServer(
    ServerOptions options,
    std::unique_ptr<QuicServerTransportFactory> factory)
    : options_(std::move(options)), factory_(std::move(factory)) {
  MVCHECK(factory_);
}

ThreadedQuicServer::~ThreadedQuicServer() {
  shutdown();
  // The factory outlives shutdown() because callers keep raw factory pointers
  // that must stay valid while this object lives; it is destroyed here, after
  // the core shutdown has completed and before the worker threads are joined.
  factory_.reset();
  // Worker threads (and their EventBases) outlive shutdown() so borrowers of
  // worker EventBases can finish teardown; they are joined here.
  threads_.clear();
  evbs_.clear();
}

size_t ThreadedQuicServer::numWorkersToCreate(
    size_t maxWorkers,
    size_t numCpu) noexcept {
  if (maxWorkers == 0) {
    maxWorkers = numCpu;
  }
  const auto numWorkers = std::min(numCpu, maxWorkers);
  if (numWorkers > QuicServer::kMaxWorkers) {
    MVLOG_WARNING << "QuicServer supports at most " << QuicServer::kMaxWorkers
                  << " workers; capping requested " << numWorkers;
    return QuicServer::kMaxWorkers;
  }
  return numWorkers;
}

SocketAddress ThreadedQuicServer::bind(
    const SocketAddress& address,
    size_t numWorkers) {
  MVCHECK(!bound_ && !stopped_);
  size_t workers =
      numWorkersToCreate(numWorkers, folly::available_concurrency());
  MVCHECK_GT(workers, 0);
  auto const backendDetails = getEventBaseBackendDetails();
  threads_.reserve(workers);
  evbs_.reserve(workers);
  try {
    for (size_t i = 0; i < workers; ++i) {
      threads_.push_back(
          std::make_unique<folly::ScopedEventBaseThread>(
              folly::EventBase::Options().setBackendFactory(
                  backendDetails.factory),
              nullptr,
              ""));
      evbs_.push_back(threads_.back()->getEventBase());
    }
    server_ = std::make_unique<QuicServer>(std::move(options_));
    server_->bind(address, evbs_);
    for (auto* evb : evbs_) {
      server_->addTransportFactory(evb, factory_.get());
    }
  } catch (...) {
    shutdown();
    throw;
  }
  bound_ = true;
  return server_->getAddress();
}

void ThreadedQuicServer::start() {
  MVCHECK(bound_ && !stopped_);
  try {
    server_->start();
  } catch (...) {
    shutdown();
    throw;
  }
}

SocketAddress ThreadedQuicServer::start(
    const SocketAddress& address,
    size_t numWorkers) {
  auto bound = bind(address, numWorkers);
  start();
  return bound;
}

void ThreadedQuicServer::shutdown() {
  if (stopped_) {
    return;
  }
  stopped_ = true;
  if (server_) {
    server_->shutdown();
    server_.reset();
  }
}

} // namespace quic
