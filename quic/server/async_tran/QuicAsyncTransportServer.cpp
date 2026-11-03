/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/system/HardwareConcurrency.h>
#include <quic/common/MvfstLogging.h>
#include <quic/server/async_tran/QuicAsyncTransportServer.h>

namespace quic {

QuicAsyncTransportServer::QuicAsyncTransportServer(
    QuicAsyncTransportAcceptor::AsyncTransportHook asyncTransportHook,
    quic::TransportSettings ts)
    : asyncTransportHook_(std::move(asyncTransportHook)),
      transportSettings_(std::move(ts)) {
  MVCHECK(asyncTransportHook_);
}

QuicAsyncTransportServer::~QuicAsyncTransportServer() {
  shutdown();
}

void QuicAsyncTransportServer::setFizzContext(
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  fizzCtx_ = std::move(ctx);
  for (auto& acceptor : acceptors_) {
    acceptor->setFizzContext(fizzCtx_);
  }
}

void QuicAsyncTransportServer::start(
    const quic::SocketAddress& address,
    size_t numThreads) {
  if (numThreads == 0) {
    numThreads = folly::available_concurrency();
  }
  if (numThreads > QuicServer::kMaxWorkers) {
    MVLOG_WARNING << "QuicServer supports at most " << QuicServer::kMaxWorkers
                  << " workers; capping requested " << numThreads;
    numThreads = QuicServer::kMaxWorkers;
  }
  std::vector<folly::EventBase*> evbs;
  for (size_t i = 0; i < numThreads; ++i) {
    auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
    evbs.push_back(scopedEvb->getEventBase());
    workerEvbs_.push_back(std::move(scopedEvb));
  }

  start(address, std::move(evbs));
}

void QuicAsyncTransportServer::start(
    const quic::SocketAddress& address,
    std::vector<folly::EventBase*> evbs) {
  quic::ServerOptions options;
  options.transportSettings = transportSettings_;
  quicServer_ = quic::QuicServer::createQuicServer(std::move(options));
  quicServer_->bind(address, evbs);
  createAcceptors(evbs);
  quicServer_->start();
}

void QuicAsyncTransportServer::createAcceptors(
    std::vector<folly::EventBase*>& evbs) {
  for (auto evb : evbs) {
    auto acceptor = std::make_unique<QuicAsyncTransportAcceptor>(
        evb, [this](folly::AsyncTransport::UniquePtr tran) {
          asyncTransportHook_(std::move(tran));
        });
    acceptor->setFizzContext(fizzCtx_);
    quicServer_->addTransportFactory(evb, acceptor.get());
    acceptors_.push_back(std::move(acceptor));
  }
}

void QuicAsyncTransportServer::shutdown() {
  if (quicServer_) {
    quicServer_->shutdown();
    quicServer_.reset();
  }
  acceptors_.clear();
  workerEvbs_.clear();
}
} // namespace quic
