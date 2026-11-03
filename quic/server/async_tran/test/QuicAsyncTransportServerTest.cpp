/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>
#include <atomic>
#include <stdexcept>

#include <folly/futures/Future.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <folly/system/HardwareConcurrency.h>

#include <folly/io/async/AsyncTransport.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientAsyncTransport.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>
#include <quic/server/async_tran/QuicAsyncTransportServer.h>
#include <quic/server/test/Mocks.h>

using namespace testing;

namespace quic::test {

class TestAsyncTransportServer : public QuicAsyncTransportServer {
 public:
  using QuicAsyncTransportServer::QuicAsyncTransportServer;

  size_t numWorkerThreads() const {
    return workerEvbs_.size();
  }

  size_t numAcceptors() const {
    return acceptors_.size();
  }
};

class QuicAsyncTransportServerTest : public TestWithParam<size_t> {
 public:
  void SetUp() override {
    clientEvb_ = std::make_shared<FollyQuicEventBase>(&evb);
    ASSERT_NO_THROW(createServer());
    createClient();
  }

  void createServer() {
    EXPECT_CALL(serverReadCB_, isBufferMovable_())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(serverReadCB_, getReadBuffer(_, _))
        .WillRepeatedly(Invoke([&](void** buf, size_t* len) {
          *buf = serverBuf_.data();
          *len = serverBuf_.size();
        }));
    EXPECT_CALL(serverReadCB_, readDataAvailable_(_))
        .WillOnce(Invoke([&](auto len) {
          auto echoData = folly::IOBuf::wrapBuffer(serverBuf_.data(), len);
          echoData->appendChain(folly::IOBuf::copyBuffer(" ding dong"));
          serverAsyncWrapper_->writeChain(&serverWriteCB_, std::move(echoData));
          serverAsyncWrapper_->shutdownWrite();
        }));
    EXPECT_CALL(serverReadCB_, readEOF_()).WillOnce(Return());
    EXPECT_CALL(serverWriteCB_, writeSuccess_()).WillOnce(Return());

    server_ = std::make_shared<TestAsyncTransportServer>([this](auto sock) {
      sock->setReadCB(&serverReadCB_);
      serverAsyncWrapper_ = std::move(sock);
    });
    server_->setFizzContext(test::createServerCtx());
    quic::SocketAddress addr("::1", 0);
    server_->start(addr, GetParam());
    const auto expectedWorkers = std::min<size_t>(
        GetParam() == 0 ? folly::available_concurrency() : GetParam(), 256);
    EXPECT_EQ(server_->numWorkerThreads(), expectedWorkers);
    EXPECT_EQ(server_->numAcceptors(), expectedWorkers);
    EXPECT_EQ(
        server_->quicServer().getAllListeningSocketFDs().size(),
        expectedWorkers);
    serverAddr_ = server_->quicServer().getAddress();
  }

  void createClient() {
    clientEvbThread_ = std::thread([&]() { clientEvb_->loopForever(); });

    EXPECT_CALL(clientReadCB_, isBufferMovable_())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(clientReadCB_, getReadBuffer(_, _))
        .WillRepeatedly(Invoke([&](void** buf, size_t* len) {
          *buf = clientBuf_.data();
          *len = clientBuf_.size();
        }));
    EXPECT_CALL(clientReadCB_, readDataAvailable_(_))
        .WillOnce(Invoke([&](auto len) {
          clientReadPromise_.setValue(
              std::string(reinterpret_cast<char*>(clientBuf_.data()), len));
        }));
    EXPECT_CALL(clientReadCB_, readEOF_()).WillOnce(Return());
    EXPECT_CALL(clientWriteCB_, writeSuccess_()).WillOnce(Return());

    clientEvb_->runInEventBaseThreadAndWait([&]() {
      auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(clientEvb_);
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setFizzClientContext(test::createClientCtx())
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .build();
      client_ = std::make_shared<QuicClientTransport>(
          clientEvb_, std::move(sock), std::move(fizzClientContext));
      client_->setHostname("echo.com");
      client_->addNewPeerAddress(serverAddr_);
      clientAsyncWrapper_.reset(new QuicClientAsyncTransport(client_));
      clientAsyncWrapper_->setReadCB(&clientReadCB_);
    });
  }

  void TearDown() override {
    if (server_) {
      server_->shutdown();
      EXPECT_EQ(server_->numWorkerThreads(), 0);
      EXPECT_EQ(server_->numAcceptors(), 0);
      server_ = nullptr;
    }
    if (clientEvbThread_.joinable()) {
      clientEvb_->runInEventBaseThreadAndWait([&] {
        clientAsyncWrapper_ = nullptr;
        client_ = nullptr;
      });
      clientEvb_->terminateLoopSoon();
      clientEvbThread_.join();
    }
  }

 protected:
  std::shared_ptr<TestAsyncTransportServer> server_;
  quic::SocketAddress serverAddr_;
  folly::AsyncTransport::UniquePtr serverAsyncWrapper_;
  folly::test::MockWriteCallback serverWriteCB_;
  folly::test::MockReadCallback serverReadCB_;
  std::array<uint8_t, 1024> serverBuf_;

  std::shared_ptr<QuicClientTransport> client_;
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> clientEvb_;
  std::thread clientEvbThread_;
  QuicClientAsyncTransport::UniquePtr clientAsyncWrapper_;
  folly::test::MockWriteCallback clientWriteCB_;
  folly::test::MockReadCallback clientReadCB_;
  std::array<uint8_t, 1024> clientBuf_;
  folly::Promise<std::string> clientReadPromise_;
};

TEST_P(QuicAsyncTransportServerTest, ReadWrite) {
  auto [promise, future] = folly::makePromiseContract<std::string>();
  clientReadPromise_ = std::move(promise);

  std::string msg = "jaja";
  clientEvb_->runInEventBaseThreadAndWait([&] {
    clientAsyncWrapper_->write(&clientWriteCB_, msg.data(), msg.size());
    clientAsyncWrapper_->shutdownWrite();
  });

  std::string clientReadString = std::move(future).get(1s);
  EXPECT_EQ(clientReadString, "jaja ding dong");
}

INSTANTIATE_TEST_SUITE_P(
    WorkerCounts,
    QuicAsyncTransportServerTest,
    Values(0, 1, 257));

TEST(QuicAsyncTransportServerWorkerTest, RejectsOversizedBorrowedWorkers) {
  folly::ScopedEventBaseThread evbThread;
  TestAsyncTransportServer server([](auto) {});
  EXPECT_THROW(
      server.start(
          quic::SocketAddress("::1", 0),
          std::vector<folly::EventBase*>(257, evbThread.getEventBase())),
      std::invalid_argument);
  EXPECT_EQ(server.numWorkerThreads(), 0);
  EXPECT_EQ(server.numAcceptors(), 0);
  EXPECT_TRUE(server.quicServer().getAllListeningSocketFDs().empty());
}

TEST(QuicAsyncTransportServerWorkerTest, BorrowedWorkersRemainCallerOwned) {
  folly::ScopedEventBaseThread first;
  folly::ScopedEventBaseThread second;
  TestAsyncTransportServer server([](auto) {});
  server.setFizzContext(test::createServerCtx());
  std::vector<folly::EventBase*> evbs{
      first.getEventBase(), second.getEventBase()};
  server.start(quic::SocketAddress("::1", 0), evbs);
  EXPECT_EQ(server.numWorkerThreads(), 0);
  EXPECT_EQ(server.numAcceptors(), evbs.size());
  EXPECT_EQ(server.quicServer().getAllListeningSocketFDs().size(), evbs.size());
  server.shutdown();
  EXPECT_EQ(server.numAcceptors(), 0);
  for (auto* evb : evbs) {
    bool ran = false;
    evb->runInEventBaseThreadAndWait([&] { ran = true; });
    EXPECT_TRUE(ran);
  }
}

TEST(QuicAsyncTransportServerRotateTest, RotateAfterStartUsesNewContext) {
  std::atomic<bool> serverAccepted{false};
  folly::AsyncTransport::UniquePtr serverWrapper;
  auto server = std::make_shared<QuicAsyncTransportServer>(
      [&](folly::AsyncTransport::UniquePtr sock) {
        serverAccepted.store(true);
        serverWrapper = std::move(sock);
      });
  server->setFizzContext(test::createServerCtx());
  server->start(quic::SocketAddress("::1", 0), 1);
  auto serverAddr = server->quicServer().getAddress();

  // Rotate after start to a context the test client cannot negotiate. The
  // next handshake must fail, proving the new context is in use.
  auto badCtx = test::createServerCtx();
  badCtx->setSupportedAlpns({"bad_alpn"});
  badCtx->setAlpnMode(fizz::server::AlpnMode::Required);
  server->setFizzContext(badCtx);

  folly::EventBase evb;
  auto clientEvb = std::make_shared<FollyQuicEventBase>(&evb);
  std::thread clientThread([&]() { clientEvb->loopForever(); });

  auto [promise, future] = folly::makePromiseContract<folly::Unit>();
  auto failPromise =
      std::make_shared<folly::Promise<folly::Unit>>(std::move(promise));
  auto clientFailed = std::make_shared<std::atomic<bool>>(false);
  auto signalFailure = [clientFailed, failPromise]() {
    if (!clientFailed->exchange(true)) {
      failPromise->setValue(folly::unit);
    }
  };

  NiceMock<folly::test::MockReadCallback> readCB;
  NiceMock<folly::test::MockWriteCallback> writeCB;
  std::array<uint8_t, 1024> clientBuf{};
  ON_CALL(readCB, isBufferMovable_()).WillByDefault(Return(false));
  ON_CALL(readCB, getReadBuffer(_, _))
      .WillByDefault([&](void** buf, size_t* len) {
        *buf = clientBuf.data();
        *len = clientBuf.size();
      });
  EXPECT_CALL(readCB, readErr_(_)).WillRepeatedly([&](auto&&...) {
    signalFailure();
  });
  EXPECT_CALL(writeCB, writeErr_(_, _)).WillRepeatedly([&](auto&&...) {
    signalFailure();
  });

  std::shared_ptr<QuicClientTransport> client;
  QuicClientAsyncTransport::UniquePtr clientWrapper;
  clientEvb->runInEventBaseThreadAndWait([&]() {
    auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(clientEvb);
    auto fizzClientContext =
        FizzClientQuicHandshakeContext::Builder()
            .setFizzClientContext(test::createClientCtx())
            .setCertificateVerifier(test::createTestCertificateVerifier())
            .build();
    client = std::make_shared<QuicClientTransport>(
        clientEvb, std::move(sock), std::move(fizzClientContext));
    client->setHostname("echo.com");
    client->addNewPeerAddress(serverAddr);
    clientWrapper.reset(new QuicClientAsyncTransport(client));
    clientWrapper->setReadCB(&readCB);
    clientWrapper->writeChain(&writeCB, folly::IOBuf::copyBuffer("jaja"));
  });

  EXPECT_NO_THROW(std::move(future).get(5s));
  server->shutdown();
  EXPECT_FALSE(serverAccepted.load());

  clientEvb->runInEventBaseThreadAndWait([&] {
    clientWrapper = nullptr;
    client = nullptr;
  });
  clientEvb->terminateLoopSoon();
  clientThread.join();
  server = nullptr;
  EXPECT_EQ(serverWrapper, nullptr);
  serverWrapper = nullptr;
}

} // namespace quic::test
