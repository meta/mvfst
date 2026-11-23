/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <utility>

#include <quic/common/MvfstLogging.h>

#include <folly/FileUtil.h>
#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/compression/ZlibCertificateDecompressor.h>
#include <fizz/compression/ZstdCertificateDecompressor.h>
#include <fizz/util/Status.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/samples/echo/LogQuicStats.h>

namespace quic::samples {

class EchoClient : public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback,
                   public quic::QuicSocket::DatagramCallback {
 public:
  EchoClient(
      std::string host,
      uint16_t port,
      bool useDatagrams,
      uint64_t activeConnIdLimit,
      bool enableMigration,
      std::vector<std::string> alpns,
      bool connectOnly,
      std::string clientCertPath,
      std::string clientKeyPath)
      : host_(std::move(host)),
        port_(port),
        useDatagrams_(useDatagrams),
        activeConnIdLimit_(activeConnIdLimit),
        enableMigration_(enableMigration),
        alpns_(std::move(alpns)),
        connectOnly_(connectOnly),
        clientCertPath_(std::move(clientCertPath)),
        clientKeyPath_(std::move(clientKeyPath)) {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      MVLOG_ERROR << "EchoClient failed read from stream=" << streamId
                  << ", error=" << (uint32_t)readData.error();
    }
    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    MVLOG_INFO << "Client received data=" << copy->toString()
               << " on stream=" << streamId;
  }

  void readError(quic::StreamId streamId, QuicError error) noexcept override {
    MVLOG_ERROR << "EchoClient failed read from stream=" << streamId
                << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
    handleError(std::move(error));
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "EchoClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "EchoClient: new unidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override {
    MVVLOG(10) << "EchoClient got StopSending stream id=" << id;
  }

  void onConnectionEnd() noexcept override {
    MVLOG_INFO << "EchoClient connection end";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    MVLOG_ERROR << "EchoClient error: " << toString(error.code)
                << "; errStr=" << error.message;
    handleError(std::move(error));
  }

  void onTransportReady() noexcept override {
    if (!connectOnly_) {
      connectionBaton_.post();
    }
  }

  void onReplaySafe() noexcept override {
    if (connectOnly_) {
      MVVLOG(3) << "Connected successfully";
      connectionBaton_.post();
    }
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    MVLOG_INFO << "EchoClient socket is write ready with maxToSend="
               << maxToSend;
    sendMessage(id, pendingOutput_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    MVLOG_ERROR << "EchoClient write error with stream=" << id
                << " error=" << toString(error);
    handleError(std::move(error));
  }

  void onDatagramsAvailable() noexcept override {
    auto res = quicClient_->readDatagrams();
    if (res.hasError()) {
      MVLOG_ERROR << "EchoClient failed reading datagrams; error="
                  << res.error();
      return;
    }
    for (const auto& datagram : *res) {
      MVLOG_INFO << "Client received datagram ="
                 << datagram.bufQueue().front()->cloneCoalesced()->toString();
    }
  }

  void handleError(QuicError error) noexcept {
    connectionError_ = error;
    quicClient_->closeNow(connectionError_.value());
    connectionBaton_.post();
  }

  quic::Expected<void, QuicError> start(std::string token) {
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
    quic::SocketAddress addr(host_.c_str(), port_);

    evb->runInEventBaseThreadAndWait([&] {
      auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
      auto fizzCLientCtx = createFizzClientContext();
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .setFizzClientContext(std::move(fizzCLientCtx))
              .build();
      quicClient_ = std::make_shared<quic::QuicClientTransport>(
          qEvb, std::move(sock), std::move(fizzClientContext));
      quicClient_->setHostname("echo.com");
      quicClient_->addNewPeerAddress(addr);
      if (!token.empty()) {
        quicClient_->setNewToken(token);
      }
      if (useDatagrams_) {
        auto res = quicClient_->setDatagramCallback(this);
        CHECK(res.has_value()) << res.error();
      }

      TransportSettings settings;
      settings.datagramConfig.enabled = useDatagrams_;
      settings.selfActiveConnectionIdLimit = activeConnIdLimit_;
      settings.disableMigration = !enableMigration_;
      quicClient_->setTransportSettings(settings);

      quicClient_->setTransportStatsCallback(
          std::make_shared<LogQuicStats>("client"));

      MVLOG_INFO << "EchoClient connecting to " << addr.describe();
      quicClient_->start(this, this);
    });

    connectionBaton_.wait();
    connectionBaton_.reset();

    if (connectionError_.has_value()) {
      return quic::make_unexpected(connectionError_.value());
    }

    if (connectOnly_) {
      evb->runInEventBaseThreadAndWait(
          [this] { quicClient_->closeNow(std::nullopt); });
      return quic::Expected<void, QuicError>{};
    }

    std::string message;
    bool closed = false;
    auto client = quicClient_;

    auto sendMessageInStream = [&]() {
      if (message == "/close") {
        quicClient_->close(std::nullopt);
        closed = true;
        return;
      }

      // create new stream for each message
      auto streamId = client->createBidirectionalStream().value();
      client->setReadCallback(streamId, this);
      pendingOutput_[streamId].append(BufHelpers::copyBuffer(message));
      sendMessage(streamId, pendingOutput_[streamId]);
    };

    std::thread input_thread([&]() {
      // loop until Ctrl+D
      while (!closed && std::getline(std::cin, message)) {
        if (message.empty()) {
          continue;
        }
        evb->runInEventBaseThreadAndWait([&] { sendMessageInStream(); });
      };
    });
    input_thread.detach();

    connectionBaton_.wait();

    MVLOG_INFO << "EchoClient stopping client";

    return connectionError_.has_value()
        ? quic::make_unexpected(connectionError_.value())
        : quic::Expected<void, QuicError>{};
  }

  ~EchoClient() override = default;

 private:
  void sendMessage(quic::StreamId id, BufQueue& data) {
    auto message = data.move();
    auto res = useDatagrams_
        ? quicClient_->writeDatagram(message->clone())
        : quicClient_->writeChain(id, message->clone(), true);
    if (res.hasError()) {
      MVLOG_ERROR << "EchoClient writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->toString();
      MVLOG_INFO << "EchoClient wrote \"" << str << "\""
                 << ", len=" << str.size() << " on stream=" << id;
      // sent whole message
      pendingOutput_.erase(id);
    }
  }

  std::shared_ptr<fizz::client::FizzClientContext> createFizzClientContext() {
    auto fizzCLientCtx = std::make_shared<fizz::client::FizzClientContext>();

    // ALPNs.
    fizzCLientCtx->setSupportedAlpns(std::move(alpns_));

    if (!clientCertPath_.empty() && !clientKeyPath_.empty()) {
      // Client cert.
      std::string certData;
      folly::readFile(clientCertPath_.c_str(), certData);
      std::string keyData;
      folly::readFile(clientKeyPath_.c_str(), keyData);
      std::unique_ptr<fizz::SelfCert> cert;
      fizz::Error err;
      FIZZ_THROW_ON_ERROR(
          fizz::openssl::CertUtils::makeSelfCert(cert, err, certData, keyData),
          err);

      auto certManager = std::make_shared<fizz::client::CertManager>();
      certManager->addCert(std::move(cert));
      fizzCLientCtx->setClientCertManager(std::move(certManager));
    }

    // Compression settings.
    auto mgr = std::make_shared<fizz::CertDecompressionManager>();
    mgr->setDecompressors(
        {std::make_shared<fizz::ZstdCertificateDecompressor>(),
         std::make_shared<fizz::ZlibCertificateDecompressor>()});
    fizzCLientCtx->setCertDecompressionManager(std::move(mgr));

    return fizzCLientCtx;
  }

  std::string host_;
  uint16_t port_;
  bool useDatagrams_;
  uint64_t activeConnIdLimit_;
  bool enableMigration_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;
  folly::fibers::Baton connectionBaton_;
  std::optional<QuicError> connectionError_;
  std::vector<std::string> alpns_;
  bool connectOnly_{false};
  std::string clientCertPath_;
  std::string clientKeyPath_;
};
} // namespace quic::samples
