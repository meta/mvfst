/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Synchronized.h>
#include <quic/common/MvfstLogging.h>

#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/server/ThreadedQuicServer.h>

#include <utility>

namespace quic::samples {

class EchoServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~EchoServerTransportFactory() override {
    draining_ = true;
    echoHandlers_.withWLock([](auto& echoHandlers) {
      while (!echoHandlers.empty()) {
        auto& handler = echoHandlers.back();
        handler->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
            [&] {
              // The evb should be performing a sequential consistency atomic
              // operation already, so we can bank on that to make sure the
              // writes propagate to all threads.
              echoHandlers.pop_back();
            });
      }
    });
  }

  explicit EchoServerTransportFactory(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      bool useDatagrams = false)
      : useDatagrams_(useDatagrams), ctx_(std::move(ctx)) {}

  // Configure before starting workers; this sample does not support rotation.
  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
    ctx_ = std::move(ctx);
  }

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> sock,
      const quic::SocketAddress&,
      QuicVersion) noexcept override {
    CHECK_EQ(evb, sock->getEventBase());
    if (draining_) {
      return nullptr;
    }
    auto echoHandler = std::make_unique<EchoHandler>(evb, useDatagrams_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), echoHandler.get(), echoHandler.get(), ctx_);
    static auto ccFactory =
        std::make_shared<quic::ServerCongestionControllerFactory>();
    transport->setCongestionControllerFactory(ccFactory);
    echoHandler->setQuicSocket(transport);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    return transport;
  }

 private:
  bool useDatagrams_;
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  folly::Synchronized<std::vector<std::unique_ptr<EchoHandler>>> echoHandlers_;
  bool draining_{false};
};

class EchoServer {
 public:
  explicit EchoServer(
      std::vector<std::string> alpns,
      std::string host = "::1",
      uint16_t port = 6666,
      bool useDatagrams = false,
      uint64_t activeConnIdLimit = 10,
      bool enableMigration = true)
      : host_(std::move(host)), port_(port), alpns_(std::move(alpns)) {
    quic::ServerOptions options;
    options.transportSettings.datagramConfig.enabled = useDatagrams;
    options.transportSettings.selfActiveConnectionIdLimit = activeConnIdLimit;
    options.transportSettings.disableMigration = !enableMigration;
    options.transportStatsFactory = std::make_unique<LogQuicStatsFactory>();

    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    serverCtx->setSupportedAlpns(std::move(alpns_));
    server_ = std::make_unique<quic::ThreadedQuicServer>(
        std::move(options),
        std::make_unique<EchoServerTransportFactory>(serverCtx, useDatagrams));
  }

  ~EchoServer() {
    server_->shutdown();
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    quic::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    server_->start(addr1, 0);
    MVLOG_INFO << "Echo server started at: " << addr1.describe();
    eventbase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
  std::unique_ptr<quic::ThreadedQuicServer> server_;
  std::vector<std::string> alpns_;
};
} // namespace quic::samples
