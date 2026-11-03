/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/ScopedEventBaseThread.h>
#include <quic/server/QuicServer.h>
#include <quic/server/async_tran/QuicAsyncTransportAcceptor.h>

namespace quic {

/**
 * QUIC server with single stream connections wrapped into folly:AsyncTransport
 * adaptor. For experiments with QUIC in existing code using
 * folly::AsyncServerSocket and wangle::Acceptor.
 */
class QuicAsyncTransportServer {
 public:
  explicit QuicAsyncTransportServer(
      QuicAsyncTransportAcceptor::AsyncTransportHook asyncTransportHook,
      quic::TransportSettings ts = quic::TransportSettings());
  virtual ~QuicAsyncTransportServer();

  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  // Zero uses the available CPU count.
  // Capped at QuicServer::kMaxWorkers.
  void start(const quic::SocketAddress& address, size_t numThreads = 0);

  // Borrows the EventBases, which must satisfy QuicServer::bind's contract.
  void start(
      const quic::SocketAddress& address,
      std::vector<folly::EventBase*> evbs);

  quic::QuicServer& quicServer() {
    return *quicServer_;
  }

  void shutdown();

 protected:
  void createAcceptors(std::vector<folly::EventBase*>& evbs);

  QuicAsyncTransportAcceptor::AsyncTransportHook asyncTransportHook_;
  quic::TransportSettings transportSettings_;
  std::shared_ptr<quic::QuicServer> quicServer_;
  std::vector<std::unique_ptr<QuicAsyncTransportAcceptor>> acceptors_;
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  std::shared_ptr<const fizz::server::FizzServerContext> fizzCtx_;
};

} // namespace quic
