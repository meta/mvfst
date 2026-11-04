/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fizz/client/test/Mocks.h>
#include <fizz/crypto/test/TestUtil.h>
#include <fizz/protocol/test/Mocks.h>
#include <fizz/server/test/Mocks.h>

#include <folly/io/async/SSLContext.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/StringUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientExtensions.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/state/StateData.h>

#include <algorithm>
#include <memory>

using namespace std;
using namespace testing;

static constexpr folly::StringPiece kTestHostname = "www.facebook.com";

namespace quic::test {
class MockServerHandshakeCallback : public ServerHandshake::HandshakeCallback {
 public:
  ~MockServerHandshakeCallback() override = default;

  MOCK_METHOD(void, onCryptoEventAvailable, (), (noexcept));
};

struct TestingServerConnectionState : public QuicServerConnectionState {
  explicit TestingServerConnectionState(
      std::shared_ptr<FizzServerQuicHandshakeContext> context)
      : QuicServerConnectionState(std::move(context)) {}

  [[nodiscard]] uint32_t getDestructorGuardCount() const {
    return folly::DelayedDestruction::getDestructorGuardCount();
  }
};

class ServerHandshakeTest : public Test {
 public:
  ~ServerHandshakeTest() override = default;

  virtual void setupClientAndServerContext() {}

  QuicVersion getVersion() {
    return QuicVersion::MVFST;
  }

  virtual void initialize() {
    handshake->initialize(
        &evb, &serverCallback, folly::make_optional(getVersion()));
  }

  void SetUp() override {
    // This client context is used outside the context of QUIC in this test, so
    // we have to manually configure the QUIC record customizations.
    clientCtx = quic::test::createClientCtx();
    clientCtx->setOmitEarlyRecordLayer(true);
    clientCtx->setFactory(std::make_shared<QuicFizzFactory>());
    serverCtx = quic::test::createServerCtx();
    setupClientAndServerContext();
    auto fizzServerContext = FizzServerQuicHandshakeContext::Builder()
                                 .setFizzServerContext(serverCtx)
                                 .build();
    conn.reset(new TestingServerConnectionState(fizzServerContext));
    cryptoState = conn->cryptoState.get();
    handshake = conn->serverHandshakeLayer;
    hostname = kTestHostname.str();
    verifier = std::make_shared<fizz::test::MockCertificateVerifier>();

    uint64_t initialMaxData = kDefaultConnectionFlowControlWindow;
    uint64_t initialMaxStreamDataBidiLocal = kDefaultStreamFlowControlWindow;
    uint64_t initialMaxStreamDataBidiRemote = kDefaultStreamFlowControlWindow;
    uint64_t initialMaxStreamDataUni = kDefaultStreamFlowControlWindow;
    uint64_t initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional;
    uint64_t initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional;
    auto clientExtensions =
        std::make_shared<ClientTransportParametersExtension>(
            getVersion(),
            initialMaxData,
            initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni,
            initialMaxStreamsBidi,
            initialMaxStreamsUni,
            kDefaultIdleTimeout,
            kDefaultAckDelayExponent,
            kDefaultUDPSendPacketLen,
            kDefaultActiveConnectionIdLimit,
            ConnectionId::createZeroLength());
    fizzClient = std::make_unique<fizz::client::FizzClient<
        ServerHandshakeTest,
        fizz::client::ClientStateMachine>>(
        clientState, clientReadBuffer, readAeadOptions, *this, dg.get());
    std::vector<QuicVersion> supportedVersions = {getVersion()};
    auto params = std::make_shared<ServerTransportParametersExtension>(
        getVersion(),
        initialMaxData,
        initialMaxStreamDataBidiLocal,
        initialMaxStreamDataBidiRemote,
        initialMaxStreamDataUni,
        initialMaxStreamsBidi,
        initialMaxStreamsUni,
        /*disableMigration=*/true,
        kDefaultIdleTimeout,
        kDefaultAckDelayExponent,
        kDefaultUDPSendPacketLen,
        kDefaultActiveConnectionIdLimit,
        generateStatelessResetToken(),
        ConnectionId::createAndMaybeCrash(
            std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
        ConnectionId::createZeroLength(),
        *conn);
    initialize();
    handshake->accept(params);

    ON_CALL(serverCallback, onCryptoEventAvailable())
        .WillByDefault(Invoke([this]() {
          MVVLOG(1) << "onCryptoEventAvailable";
          processCryptoEvents();
        }));
    auto cachedPsk = clientCtx->getPsk(hostname);
    fizzClient->connect(
        clientCtx,
        verifier,
        hostname,
        cachedPsk,
        folly::Optional<std::vector<fizz::ech::ParsedECHConfig>>(folly::none),
        std::make_shared<FizzClientExtensions>(clientExtensions, 0));
  }

  void processCryptoEvents() {
    auto handshakeStateResult = setHandshakeState();
    if (handshakeStateResult.hasError()) {
      MVVLOG(1) << "server exception " << handshakeStateResult.error().message;
      ex = quic::make_unexpected(handshakeStateResult.error());
      if (!inRoundScope_ && !handshakeCv.ready()) {
        MVVLOG(1) << "Posting handshake cv";
        handshakeCv.post();
      }
      return;
    }

    waitForData = false;
    do {
      auto writableBytes = getHandshakeWriteBytes();
      if (writableBytes->empty()) {
        break;
      }
      MVVLOG(1) << "server->client bytes="
                << writableBytes->computeChainDataLength();
      clientReadBuffer.append(std::move(writableBytes));
      fizzClient->newTransportData();
    } while (!waitForData);

    if (!inRoundScope_ && !handshakeCv.ready()) {
      MVVLOG(1) << "Posting handshake cv";
      handshakeCv.post();
    }
  }

  void clientServerRound() {
    SCOPE_EXIT {
      inRoundScope_ = false;
    };
    inRoundScope_ = true;
    evb.loop();
    for (auto& clientWrite : clientWrites) {
      for (auto& content : clientWrite.contents) {
        auto encryptionLevel =
            getEncryptionLevelFromFizz(content.encryptionLevel);
        auto result =
            handshake->doHandshake(std::move(content.data), encryptionLevel);
        if (result.hasError()) {
          ex = quic::make_unexpected(result.error());
        }
      }
    }
    processCryptoEvents();
    evb.loopIgnoreKeepAlive();
  }

  void serverClientRound() {
    SCOPE_EXIT {
      inRoundScope_ = false;
    };
    inRoundScope_ = true;
    evb.loop();
    waitForData = false;
    do {
      auto writableBytes = getHandshakeWriteBytes();
      if (writableBytes->empty()) {
        break;
      }
      MVVLOG(1) << "server->client bytes="
                << writableBytes->computeChainDataLength();
      clientReadBuffer.append(std::move(writableBytes));
      fizzClient->newTransportData();
    } while (!waitForData);
    evb.loop();
  }

  [[nodiscard]] quic::Expected<void, QuicError> setHandshakeState() {
    auto oneRttWriteCipherTmp = handshake->getFirstOneRttWriteCipher();
    if (oneRttWriteCipherTmp.hasError()) {
      return quic::make_unexpected(oneRttWriteCipherTmp.error());
    }
    auto oneRttReadCipherTmp = handshake->getFirstOneRttReadCipher();
    if (oneRttReadCipherTmp.hasError()) {
      return quic::make_unexpected(oneRttReadCipherTmp.error());
    }
    auto zeroRttReadCipherTmp = handshake->getZeroRttReadCipher();
    if (zeroRttReadCipherTmp.hasError()) {
      return quic::make_unexpected(zeroRttReadCipherTmp.error());
    }
    auto handshakeWriteCipherTmp = std::move(conn->handshakeWriteCipher);
    auto handshakeReadCipherTmp = handshake->getHandshakeReadCipher();
    if (handshakeReadCipherTmp.hasError()) {
      return quic::make_unexpected(handshakeReadCipherTmp.error());
    }
    if (oneRttWriteCipherTmp.value()) {
      oneRttWriteCipher = std::move(oneRttWriteCipherTmp.value());
    }
    if (oneRttReadCipherTmp.value()) {
      oneRttReadCipher = std::move(oneRttReadCipherTmp.value());
    }
    if (zeroRttReadCipherTmp.value()) {
      zeroRttReadCipher = std::move(zeroRttReadCipherTmp.value());
    }
    if (handshakeReadCipherTmp.value()) {
      handshakeReadCipher = std::move(handshakeReadCipherTmp.value());
    }
    if (handshakeWriteCipherTmp) {
      handshakeWriteCipher = std::move(handshakeWriteCipherTmp);
    }
    return {};
  }

  void expectOneRttReadCipher(bool expected) {
    EXPECT_EQ(oneRttReadCipher.get() != nullptr, expected);
  }

  void expectOneRttWriteCipher(bool expected) {
    EXPECT_EQ(oneRttWriteCipher.get() != nullptr, expected);
  }

  void expectOneRttCipher(bool expected) {
    expectOneRttWriteCipher(expected);
    expectOneRttReadCipher(expected);

    if (expected) {
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    } else {
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    }
  }

  void expectZeroRttCipher(bool expected, bool oneRttRead) {
    CHECK(expected || !oneRttRead) << "invalid condition supplied";
    EXPECT_NE(oneRttWriteCipher.get(), nullptr);
    if (expected) {
      if (oneRttRead) {
        EXPECT_NE(oneRttReadCipher.get(), nullptr);
      } else {
        EXPECT_EQ(oneRttReadCipher.get(), nullptr);
      }
      EXPECT_NE(zeroRttReadCipher.get(), nullptr);
    } else {
      EXPECT_EQ(oneRttReadCipher.get(), nullptr);
      EXPECT_EQ(zeroRttReadCipher.get(), nullptr);
    }
  }

  BufPtr getHandshakeWriteBytes() {
    auto buf = folly::IOBuf::create(0);
    switch (clientState.readRecordLayer()->getEncryptionLevel()) {
      case fizz::EncryptionLevel::Plaintext:
        if (!cryptoState->initialStream.writeBuffer.empty()) {
          buf->appendToChain(cryptoState->initialStream.writeBuffer.move());
        }
        break;
      case fizz::EncryptionLevel::Handshake:
      case fizz::EncryptionLevel::EarlyData:
        if (!cryptoState->handshakeStream.writeBuffer.empty()) {
          buf->appendToChain(cryptoState->handshakeStream.writeBuffer.move());
        }
        break;
      case fizz::EncryptionLevel::AppTraffic:
        if (!cryptoState->oneRttStream.writeBuffer.empty()) {
          buf->appendToChain(cryptoState->oneRttStream.writeBuffer.move());
        }
    }
    return buf;
  }

  void operator()(fizz::DeliverAppData&) {}

  void operator()(fizz::WriteToSocket& write) {
    clientWrites.push_back(std::move(write));
  }

  void operator()(fizz::client::ReportEarlyHandshakeSuccess&) {
    earlyHandshakeSuccess = true;
  }

  void operator()(fizz::client::ReportHandshakeSuccess&) {
    handshakeSuccess = true;
  }

  void operator()(fizz::client::ReportEarlyWriteFailed&) {
    earlyWriteFailed = true;
  }

  void operator()(fizz::ReportError&) {
    error = true;
  }

  void operator()(fizz::WaitForData&) {
    waitForData = true;
    fizzClient->waitForData();
  }

  void operator()(fizz::client::MutateState& mutator) {
    mutator(clientState);
  }

  void operator()(fizz::client::NewCachedPsk& newCachedPsk) {
    clientCtx->putPsk(hostname, std::move(newCachedPsk.psk));
  }

  void operator()(fizz::SecretAvailable&) {}

  void operator()(fizz::EndOfData&) {}

  void operator()(fizz::client::ECHRetryAvailable&) {}

  class DelayedHolder : public folly::DelayedDestruction {};

  std::unique_ptr<DelayedHolder, folly::DelayedDestruction::Destructor> dg;

  folly::EventBase evb;
  std::unique_ptr<
      TestingServerConnectionState,
      folly::DelayedDestruction::Destructor>
      conn{nullptr};
  ServerHandshake* handshake;
  QuicCryptoState* cryptoState;

  fizz::client::State clientState;
  std::unique_ptr<fizz::client::FizzClient<
      ServerHandshakeTest,
      fizz::client::ClientStateMachine>>
      fizzClient;
  quic::IOBufQueue clientReadBuffer{quic::IOBufQueue::cacheChainLength()};
  bool earlyHandshakeSuccess{false};
  bool handshakeSuccess{false};
  bool earlyWriteFailed{false};
  bool error{false};
  fizz::Aead::AeadOptions readAeadOptions;

  std::vector<fizz::WriteToSocket> clientWrites;
  MockServerHandshakeCallback serverCallback;

  std::unique_ptr<Aead> oneRttWriteCipher;
  std::unique_ptr<Aead> oneRttReadCipher;
  std::unique_ptr<Aead> zeroRttReadCipher;
  std::unique_ptr<Aead> handshakeWriteCipher;
  std::unique_ptr<Aead> handshakeReadCipher;

  quic::Expected<void, QuicError> ex{};
  std::string hostname;
  std::shared_ptr<fizz::test::MockCertificateVerifier> verifier;
  std::shared_ptr<fizz::client::FizzClientContext> clientCtx;
  std::shared_ptr<fizz::server::FizzServerContext> serverCtx;
  folly::Baton<> handshakeCv;
  bool inRoundScope_{false};
  bool waitForData{false};
};

TEST_F(ServerHandshakeTest, TestGetExportedKeyingMaterial) {
  // Sanity check. getExportedKeyingMaterial() should return nullptr prior to
  // an handshake.
  auto ekm = handshake->getExportedKeyingMaterial(
      "EXPORTER-Some-Label", std::nullopt, 32);
  EXPECT_TRUE(!ekm.has_value());

  clientServerRound();
  serverClientRound();
  ekm = handshake->getExportedKeyingMaterial(
      "EXPORTER-Some-Label", std::nullopt, 32);
  ASSERT_TRUE(ekm.has_value());
  EXPECT_EQ(ekm->size(), 32);

  ekm = handshake->getExportedKeyingMaterial(
      "EXPORTER-Some-Label", ByteRange(), 32);
  ASSERT_TRUE(ekm.has_value());
  EXPECT_EQ(ekm->size(), 32);
}

TEST_F(ServerHandshakeTest, TestHandshakeSuccess) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  ASSERT_FALSE(ex.hasError());
  expectOneRttCipher(true);
  EXPECT_EQ(handshake->getApplicationProtocol(), "quic_test");
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ServerHandshakeTest, TestRejectInitialDataAfterClientHello) {
  clientServerRound();
  ASSERT_FALSE(ex.hasError());
  ASSERT_EQ(
      handshake->getState().readRecordLayer()->getEncryptionLevel(),
      fizz::EncryptionLevel::Handshake);

  auto result = handshake->doHandshake(
      folly::IOBuf::copyBuffer("unexpected crypto data"),
      EncryptionLevel::Initial);

  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::PROTOCOL_VIOLATION);
}

TEST_F(ServerHandshakeTest, TestRejectHandshakeDataAfterClientFinished) {
  clientServerRound();
  serverClientRound();
  clientServerRound();
  ASSERT_FALSE(ex.hasError());
  ASSERT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);

  auto result = handshake->doHandshake(
      folly::IOBuf::copyBuffer("unexpected crypto data"),
      EncryptionLevel::Handshake);

  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::PROTOCOL_VIOLATION);
}

TEST_F(ServerHandshakeTest, TestHandshakeSuccessIgnoreNonHandshakeWrite) {
  fizz::WriteToSocket write;
  fizz::TLSContent content;
  content.contentType = fizz::ContentType::alert;
  auto contentDataOpt = quic::unhexlify("01000000");
  CHECK(contentDataOpt.has_value()) << "Failed to unhexlify content data";
  content.data = folly::IOBuf::copyBuffer(contentDataOpt.value());
  content.encryptionLevel = fizz::EncryptionLevel::Plaintext;
  write.contents.push_back(std::move(content));
  handshake->onWriteData(write);
  EXPECT_TRUE(cryptoState->initialStream.writeBuffer.empty());
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  ASSERT_FALSE(ex.hasError());
  expectOneRttCipher(true);
  EXPECT_EQ(handshake->getApplicationProtocol(), "quic_test");
  EXPECT_TRUE(handshakeSuccess);
}

TEST_F(ServerHandshakeTest, TestMalformedHandshakeMessage) {
  fizz::WriteToSocket write;
  fizz::TLSContent content;
  content.contentType = fizz::ContentType::handshake;
  auto contentDataOpt2 = quic::unhexlify("01000000");
  CHECK(contentDataOpt2.has_value()) << "Failed to unhexlify content data";
  content.data = folly::IOBuf::copyBuffer(contentDataOpt2.value());
  content.encryptionLevel = fizz::EncryptionLevel::Plaintext;
  write.contents.push_back(std::move(content));
  clientWrites.clear();
  clientWrites.push_back(std::move(write));
  clientServerRound();

  EXPECT_TRUE(ex.hasError());
}

class AsyncRejectingTicketCipher : public fizz::server::TicketCipher {
 public:
  ~AsyncRejectingTicketCipher() override = default;

  folly::SemiFuture<folly::Optional<
      std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>
  encrypt(fizz::server::ResumptionState) const override {
    if (!encryptAsync_) {
      return std::make_pair(folly::IOBuf::create(0), 2s);
    } else {
      encryptAsync_ = false;
      return std::move(encryptFuture_).deferValue([](auto&&) {
        MVVLOG(1) << "got ticket async";
        return folly::makeSemiFuture<folly::Optional<
            std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>(
            std::make_pair(folly::IOBuf::create(0), 2s));
      });
    }
  }

  void setDecryptAsync(bool async, folly::SemiFuture<folly::Unit> future) {
    decryptAsync_ = async;
    decryptFuture_ = std::move(future);
  }

  void setEncryptAsync(bool async, folly::SemiFuture<folly::Unit> future) {
    encryptAsync_ = async;
    encryptFuture_ = std::move(future);
  }

  void setDecryptError(bool error) {
    error_ = error;
  }

  folly::SemiFuture<
      std::pair<fizz::PskType, folly::Optional<fizz::server::ResumptionState>>>
  decrypt(std::unique_ptr<folly::IOBuf>) const override {
    if (!decryptAsync_) {
      if (error_) {
        throw std::runtime_error("test decrypt error");
      }
      return std::make_pair(fizz::PskType::Rejected, folly::none);
    } else {
      decryptAsync_ = false;
      return std::move(decryptFuture_).deferValue([&](auto&&) {
        MVVLOG(1) << "triggered reject";
        if (error_) {
          throw std::runtime_error("test decrypt error");
        }
        return folly::makeSemiFuture<std::pair<
            fizz::PskType,
            folly::Optional<fizz::server::ResumptionState>>>(
            std::make_pair(fizz::PskType::Rejected, folly::none));
      });
    }
  }

 private:
  mutable folly::SemiFuture<folly::Unit> decryptFuture_;
  mutable folly::SemiFuture<folly::Unit> encryptFuture_;
  mutable bool decryptAsync_{true};
  mutable bool encryptAsync_{false};
  bool error_{false};
};

class ServerHandshakeWriteNSTTest : public ServerHandshakeTest {
 public:
  void setupClientAndServerContext() override {
    serverCtx->setSendNewSessionTicket(false);
    ticketCipher_ = std::make_shared<fizz::server::test::MockTicketCipher>();
    ticketCipher_->setDefaults();
    serverCtx->setTicketCipher(ticketCipher_);
    cache_ = std::make_shared<fizz::client::BasicPskCache>();
    clientCtx->setPskCache(cache_);
    clientCtx->setSupportedAlpns({"h3"});
    serverCtx->setSupportedAlpns({"h3", "hq"});
  }

 protected:
  std::shared_ptr<fizz::client::BasicPskCache> cache_;
  std::shared_ptr<fizz::server::test::MockTicketCipher> ticketCipher_;
};

TEST_F(ServerHandshakeWriteNSTTest, TestWriteNST) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);

  AppToken appToken;

  EXPECT_FALSE(cache_->getPsk(kTestHostname.str()));
  EXPECT_CALL(*ticketCipher_, _encrypt(_))
      .WillOnce(Invoke([&appToken](fizz::server::ResumptionState& resState) {
        EXPECT_TRUE(
            folly::IOBufEqualTo()(resState.appToken, encodeAppToken(appToken)));
        return std::make_pair(folly::IOBuf::copyBuffer("appToken"), 100s);
      }));
  ASSERT_FALSE(handshake->writeNewSessionTicket(appToken).hasError());
  processCryptoEvents();
  evb.loop();
  EXPECT_TRUE(cache_->getPsk(kTestHostname.str()));
}

class ServerHandshakePskTest : public ServerHandshakeTest {
 public:
  ~ServerHandshakePskTest() override = default;

  void SetUp() override {
    cache = std::make_shared<fizz::client::BasicPskCache>();
    psk.psk = std::string("psk");
    psk.secret = std::string("secret");
    psk.type = fizz::PskType::Resumption;
    psk.version = fizz::ProtocolVersion::tls_1_3;
    psk.cipher = fizz::CipherSuite::TLS_AES_128_GCM_SHA256;
    psk.group = fizz::NamedGroup::x25519;
    psk.serverCert = std::make_shared<fizz::test::MockCert>();
    psk.alpn = std::string("h3");
    psk.ticketAgeAdd = 1;
    psk.ticketIssueTime = std::chrono::system_clock::time_point();
    psk.ticketExpirationTime =
        std::chrono::system_clock::time_point(std::chrono::seconds(20));
    psk.ticketHandshakeTime = std::chrono::system_clock::time_point();
    psk.maxEarlyDataSize = 2;
    ServerHandshakeTest::SetUp();
  }

  void setupClientAndServerContext() override {
    cache->putPsk(kTestHostname.str(), psk);
    ticketCipher = makeTicketCipher();
    serverCtx->setTicketCipher(ticketCipher);
    clientCtx->setPskCache(cache);
    clientCtx->setSupportedAlpns({"h3"});
    serverCtx->setSupportedAlpns({"h3", "hq"});
  }

  virtual std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() = 0;

  std::shared_ptr<fizz::client::BasicPskCache> cache;
  folly::Promise<folly::Unit> promise;
  std::shared_ptr<fizz::server::TicketCipher> ticketCipher;
  fizz::client::CachedPsk psk;
};

class ServerHandshakeAsyncDecryptTest : public ServerHandshakePskTest {
 public:
  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(true, promise.getFuture());
    return cipher;
  }
};

TEST_F(
    ServerHandshakeAsyncDecryptTest,
    TestRejectInitialDataBufferedDuringClientHello) {
  clientServerRound();
  ASSERT_FALSE(ex.hasError());
  ASSERT_EQ(
      handshake->getState().readRecordLayer()->getEncryptionLevel(),
      fizz::EncryptionLevel::Plaintext);
  ASSERT_FALSE(handshake
                   ->doHandshake(
                       folly::IOBuf::copyBuffer("unexpected crypto data"),
                       EncryptionLevel::Initial)
                   .hasError());

  EXPECT_CALL(serverCallback, onCryptoEventAvailable()).WillOnce(Invoke([&] {
    auto result = handshake->getFirstOneRttReadCipher();
    ASSERT_TRUE(result.hasError());
    EXPECT_EQ(result.error().code, TransportErrorCode::PROTOCOL_VIOLATION);
  }));
  promise.setValue();
  evb.loop();

  EXPECT_EQ(conn->getDestructorGuardCount(), 0);
}

class ServerHandshakeHRRTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeHRRTest() override = default;

  void setupClientAndServerContext() override {
    // Make a group mismatch happen.
    psk.group = fizz::NamedGroup::secp256r1;
    clientCtx->setSupportedGroups(
        {fizz::NamedGroup::secp256r1, fizz::NamedGroup::x25519});
    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setDefaultShares({fizz::NamedGroup::secp256r1});
    serverCtx->setSupportedGroups({fizz::NamedGroup::x25519});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setSupportedAlpns({"h3"});
    serverCtx->setSupportedAlpns({"h3", "hq"});
    ServerHandshakePskTest::setupClientAndServerContext();
  }

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(true, promise.getFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeHRRTest, TestHRR) {
  auto rejectingCipher =
      dynamic_cast<AsyncRejectingTicketCipher*>(ticketCipher.get());
  rejectingCipher->setDecryptAsync(false, folly::makeFuture());
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);

  expectOneRttReadCipher(false);
  expectOneRttWriteCipher(true);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h3");
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeHRRTest, TestAsyncHRR) {
  // Make an async ticket decryption operation.
  clientServerRound();

  promise.setValue();
  evb.loop();

  expectOneRttCipher(false);

  handshakeCv.wait();
  handshakeCv.reset();
  clientServerRound();
  serverClientRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  EXPECT_EQ(handshake->getApplicationProtocol(), "h3");
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeHRRTest, TestAsyncCancel) {
  // Make an async ticket decryption operation.
  clientServerRound();

  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();

  EXPECT_EQ(handshake->getApplicationProtocol(), std::nullopt);
  expectOneRttCipher(false);
}

class ServerHandshakeAsyncTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeAsyncTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(false, folly::makeFuture());
    cipher->setEncryptAsync(true, promise.getFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeAsyncTest, TestAsyncCancel) {
  // Make an async ticket decryption operation.
  clientServerRound();
  serverClientRound();
  clientServerRound();

  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();

  EXPECT_EQ(conn->getDestructorGuardCount(), 0);
}

class ServerHandshakeAsyncErrorTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeAsyncErrorTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptAsync(true, promise.getFuture());
    cipher->setDecryptError(true);
    return cipher;
  }
};

TEST_F(ServerHandshakeAsyncErrorTest, TestAsyncError) {
  clientServerRound();

  bool error = false;
  EXPECT_CALL(serverCallback, onCryptoEventAvailable())
      .WillRepeatedly(Invoke([&] {
        if (handshake->getFirstOneRttReadCipher().hasError()) {
          error = true;
        }
      }));
  promise.setValue();
  evb.loop();
  EXPECT_TRUE(error);
}

TEST_F(ServerHandshakeAsyncErrorTest, TestCancelOnAsyncError) {
  clientServerRound();

  EXPECT_CALL(serverCallback, onCryptoEventAvailable())
      .WillRepeatedly(Invoke([&] {
        handshake->cancel();
        // Let's destroy the crypto state to make sure it is not referenced.
        conn->cryptoState.reset();
      }));
  promise.setValue();
  evb.loop();
  EXPECT_TRUE(handshake->getFirstOneRttReadCipher().hasError());
}

TEST_F(ServerHandshakeAsyncErrorTest, TestCancelWhileWaitingAsyncError) {
  clientServerRound();
  handshake->cancel();
  // Let's destroy the crypto state to make sure it is not referenced.
  conn->cryptoState.reset();

  promise.setValue();
  evb.loop();
  EXPECT_TRUE(handshake->getFirstOneRttReadCipher().hasError());
}

class ServerHandshakeSyncErrorTest : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeSyncErrorTest() override = default;

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AsyncRejectingTicketCipher>();
    cipher->setDecryptError(true);
    cipher->setDecryptAsync(false, folly::makeFuture());
    return cipher;
  }
};

TEST_F(ServerHandshakeSyncErrorTest, TestError) {
  // Make an async ticket decryption operation.
  clientServerRound();
  evb.loop();
  EXPECT_TRUE(handshake->getFirstOneRttReadCipher().hasError());
}

class ServerHandshakeZeroRttDefaultAppTokenValidatorTest
    : public ServerHandshakePskTest {
 public:
  ~ServerHandshakeZeroRttDefaultAppTokenValidatorTest() override = default;

  /**
   * This cipher can currently resume only 1 connection.
   */
  class AcceptingTicketCipher : public fizz::server::TicketCipher {
   public:
    ~AcceptingTicketCipher() override = default;

    folly::SemiFuture<folly::Optional<
        std::pair<std::unique_ptr<folly::IOBuf>, std::chrono::seconds>>>
    encrypt(fizz::server::ResumptionState) const override {
      // Fake handshake, no need todo anything here.
      return std::make_pair(folly::IOBuf::create(0), 2s);
    }

    void setPsk(fizz::client::CachedPsk psk) {
      resState.version = psk.version;
      resState.cipher = psk.cipher;
      resState.resumptionSecret = folly::IOBuf::copyBuffer(psk.secret);
      resState.alpn = psk.alpn;
      resState.ticketIssueTime = std::chrono::system_clock::time_point();
      resState.handshakeTime = std::chrono::system_clock::time_point();
      resState.serverCert = psk.serverCert;
    }

    folly::SemiFuture<std::pair<
        fizz::PskType,
        folly::Optional<fizz::server::ResumptionState>>>
    decrypt(std::unique_ptr<folly::IOBuf>) const override {
      return std::make_pair(fizz::PskType::Resumption, std::move(resState));
    }

   private:
    mutable fizz::server::ResumptionState resState;
  };

  void setupClientAndServerContext() override {
    clientCtx->setSendEarlyData(true);
    serverCtx->setEarlyDataSettings(
        true,
        fizz::server::ClockSkewTolerance{.before = -1000ms, .after = 1000ms},
        std::make_shared<fizz::server::AllowAllReplayReplayCache>());

    clientCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    serverCtx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
    clientCtx->setSupportedAlpns({"h3"});
    serverCtx->setSupportedAlpns({"h3", "hq"});
    ServerHandshakePskTest::setupClientAndServerContext();
  }

  std::shared_ptr<fizz::server::TicketCipher> makeTicketCipher() override {
    auto cipher = std::make_shared<AcceptingTicketCipher>();
    cipher->setPsk(psk);
    return cipher;
  }
};

TEST_F(
    ServerHandshakeZeroRttDefaultAppTokenValidatorTest,
    TestDefaultAppTokenValidatorRejectZeroRtt) {
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}

class ServerHandshakeZeroRttTest
    : public ServerHandshakeZeroRttDefaultAppTokenValidatorTest {
  void initialize() override {
    auto validator =
        std::make_unique<fizz::server::test::MockAppTokenValidator>();
    validator_ = validator.get();
    handshake->initialize(
        &evb,
        &serverCallback,
        folly::make_optional(getVersion()),
        std::move(validator));
  }

 protected:
  fizz::server::test::MockAppTokenValidator* validator_;
};

TEST_F(ServerHandshakeZeroRttTest, TestResumption) {
  EXPECT_CALL(*validator_, validate(_)).WillOnce(Return(true));
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::KeysDerived);
  expectZeroRttCipher(true, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectZeroRttCipher(true, true);
}

TEST_F(ServerHandshakeZeroRttTest, TestRejectZeroRttNotEnabled) {
  auto realServerCtx =
      dynamic_cast<FizzServerHandshake*>(handshake)->getContext();
  auto nonConstServerCtx =
      const_cast<fizz::server::FizzServerContext*>(realServerCtx);
  nonConstServerCtx->setEarlyDataSettings(
      false, fizz::server::ClockSkewTolerance(), nullptr);
  EXPECT_CALL(*validator_, validate(_)).Times(0);
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}

TEST_F(ServerHandshakeZeroRttTest, TestRejectZeroRttInvalidToken) {
  EXPECT_CALL(*validator_, validate(_)).WillOnce(Return(false));
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Handshake);
  expectZeroRttCipher(false, false);
  serverClientRound();
  clientServerRound();
  EXPECT_EQ(handshake->getPhase(), ServerHandshake::Phase::Established);
  expectOneRttCipher(true);
}

// The server state machine skips ServerHandshake::accept() when it rejects the
// client's Initial packet, but the application can still be called back on that
// error path and query the peer transport parameters. Querying them before
// accept() must degrade to an empty Optional rather than dereference null.
TEST(ServerHandshakeNoAcceptTest, GetClientTransportParamsBeforeAccept) {
  auto fizzServerContext =
      FizzServerQuicHandshakeContext::Builder()
          .setFizzServerContext(quic::test::createServerCtx())
          .build();
  std::unique_ptr<
      QuicServerConnectionState,
      folly::DelayedDestruction::Destructor>
      conn(new QuicServerConnectionState(std::move(fizzServerContext)));

  EXPECT_FALSE(
      conn->serverHandshakeLayer->getClientTransportParams().has_value());
}

namespace {
size_t countPskKe(const std::vector<fizz::PskKeyExchangeMode>& modes) {
  return std::ranges::count(modes, fizz::PskKeyExchangeMode::psk_ke);
}
} // namespace

// The priming context overrides the base PSK-mode policy to prefer pure PSK
// (psk_ke) with an ECDHE-PSK fallback, even when the base context is restricted
// to psk_dhe_ke only, without mutating the base context that non-priming (e.g.
// MVFST/QUIC_V1) connections use.
TEST(
    FizzServerQuicHandshakeContextPrimingTest,
    OverridesModesWhenBaseRestricted) {
  auto serverCtx = quic::test::createServerCtx();
  serverCtx->setSupportedPskModes({fizz::PskKeyExchangeMode::psk_dhe_ke});
  auto ctx = FizzServerQuicHandshakeContext::Builder()
                 .setFizzServerContext(serverCtx)
                 .build();

  EXPECT_THAT(
      ctx->getPrimingContext()->getSupportedPskModes(),
      ElementsAre(
          fizz::PskKeyExchangeMode::psk_ke,
          fizz::PskKeyExchangeMode::psk_dhe_ke));

  // The base context (used by non-priming versions) is left untouched.
  EXPECT_THAT(
      ctx->getContext()->getSupportedPskModes(),
      ElementsAre(fizz::PskKeyExchangeMode::psk_dhe_ke));
}

// The override replaces the base modes wholesale: the priming context always
// prefers psk_ke first regardless of the base's mode set or preference order.
TEST(
    FizzServerQuicHandshakeContextPrimingTest,
    OverridesModesRegardlessOfBaseOrder) {
  auto serverCtx = quic::test::createServerCtx();
  serverCtx->setSupportedPskModes(
      {fizz::PskKeyExchangeMode::psk_dhe_ke, fizz::PskKeyExchangeMode::psk_ke});
  auto ctx = FizzServerQuicHandshakeContext::Builder()
                 .setFizzServerContext(serverCtx)
                 .build();

  EXPECT_THAT(
      ctx->getPrimingContext()->getSupportedPskModes(),
      ElementsAre(
          fizz::PskKeyExchangeMode::psk_ke,
          fizz::PskKeyExchangeMode::psk_dhe_ke));
}

// The priming context is cached: repeated calls return the same instance and do
// not accumulate duplicate psk_ke entries.
TEST(FizzServerQuicHandshakeContextPrimingTest, IsCachedAndIdempotent) {
  auto serverCtx = quic::test::createServerCtx();
  serverCtx->setSupportedPskModes({fizz::PskKeyExchangeMode::psk_dhe_ke});
  auto ctx = FizzServerQuicHandshakeContext::Builder()
                 .setFizzServerContext(serverCtx)
                 .build();

  auto first = ctx->getPrimingContext();
  auto second = ctx->getPrimingContext();
  EXPECT_EQ(first.get(), second.get());
  EXPECT_EQ(countPskKe(second->getSupportedPskModes()), 1);
}
} // namespace quic::test
