/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/server/QuicServer.h>
#include <quic/server/ThreadedQuicServer.h>

#include <folly/ScopeGuard.h>
#include <folly/futures/Promise.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <folly/system/HardwareConcurrency.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/SlidingWindowRateLimiter.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/test/Mocks.h>
#include <quic/state/test/MockQuicStats.h>

#include <memory>
#include <set>
#include <type_traits>

using namespace testing;
using namespace folly;

using OnDataAvailableParams =
    quic::FollyAsyncUDPSocketAlias::ReadCallback::OnDataAvailableParams;

const quic::SocketAddress kClientAddr(folly::IPAddress("1.2.3.4"), 1234);
const quic::SocketAddress kClientAddr2(folly::IPAddress("1.2.3.5"), 1235);
const quic::SocketAddress kClientAddr3(folly::IPAddress("1.2.3.6"), 1236);

namespace quic::test {

MATCHER_P(NetworkDataMatches, networkData, "") {
  for (size_t i = 0; i < arg.getPackets().size(); ++i) {
    folly::IOBufEqualTo eq;
    bool equals = eq(*arg.getPackets()[i].buf.front(), networkData);
    if (equals) {
      return true;
    }
  }
  return false;
}

MATCHER_P2(NetworkDataMatchesWithPeer, networkData, peerAddress, "") {
  for (size_t i = 0; i < arg.getPackets().size(); ++i) {
    folly::IOBufEqualTo eq;
    const auto& packet = arg.getPackets()[i];
    if (eq(*packet.buf.front(), networkData) &&
        packet.peerAddress.has_value() && *packet.peerAddress == peerAddress) {
      return true;
    }
  }
  return false;
}

/**
 * QuicServerWorker test without a connection to drive any real behavior. Use
 * QuicServerWorkerTest for most cases.
 */
class SimpleQuicServerWorkerTest : public Test {
 protected:
  folly::EventBase eventbase_;
  std::unique_ptr<RunState> runState_;
  std::unique_ptr<QuicServerWorker> worker_;
  folly::test::MockAsyncUDPSocketT<>* rawSocket_{nullptr};
};

TEST_F(SimpleQuicServerWorkerTest, RejectCid) {
  quic::SocketAddress addr("::1", 0);
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(addr));
  MockConnectionSetupCallback mockConnectionSetupCallback;
  MockConnectionCallback mockConnectionCallback;

  auto qEvb = std::make_shared<FollyQuicEventBase>(&eventbase_);
  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(mockSock));
  MockQuicTransport::Ptr transportPtr = std::make_shared<MockQuicTransport>(
      qEvb,
      std::move(qSock),
      &mockConnectionSetupCallback,
      &mockConnectionCallback,
      nullptr);
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_));
  auto includeCid = getTestConnectionId(0);
  auto excludeCid = getTestConnectionId(1);
  EXPECT_FALSE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));

  worker_->onConnectionIdAvailable(transportPtr, includeCid);

  EXPECT_TRUE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));

  QuicServerTransport::SourceIdentity sourceId(addr, includeCid);
  std::vector<ConnectionIdData> cidDataVec;
  cidDataVec.emplace_back(includeCid, 0);

  EXPECT_CALL(*transportPtr, setRoutingCallback(nullptr)).Times(1);
  worker_->onConnectionUnbound(transportPtr.get(), sourceId, cidDataVec);
  EXPECT_FALSE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));
}

TEST_F(SimpleQuicServerWorkerTest, TurnOffPMTU) {
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  rawSocket_ = sock.get();
  DCHECK(sock->getEventBase());
  EXPECT_CALL(*sock, getNetworkSocket())
      .WillRepeatedly(Return(folly::NetworkSocket()));
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(sock));
  quic::SocketAddress addr("::1", 0);
  // We check versions in bind()
  worker_->setSupportedVersions({QuicVersion::MVFST});
  EXPECT_CALL(*rawSocket_, setDFAndTurnOffPMTU()).Times(1);
  worker_->bind(addr);
}

TEST_F(SimpleQuicServerWorkerTest, EnableZeroCopy) {
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  rawSocket_ = sock.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(sock));

  EXPECT_CALL(*rawSocket_, setZeroCopy(true)).WillOnce(Return(true));

  auto result = worker_->enableZeroCopy();
  ASSERT_FALSE(result.hasError());
}

TEST_F(SimpleQuicServerWorkerTest, EnableZeroCopyFailsWhenSetZeroCopyFails) {
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  rawSocket_ = sock.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(sock));

  EXPECT_CALL(*rawSocket_, setZeroCopy(true)).WillOnce(Return(false));

  auto result = worker_->enableZeroCopy();
  ASSERT_TRUE(result.hasError());
}

TEST_F(SimpleQuicServerWorkerTest, EnableZeroCopyFailsWithoutSocket) {
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  auto result = worker_->enableZeroCopy();
  ASSERT_TRUE(result.hasError());
}

TEST_F(
    SimpleQuicServerWorkerTest,
    GetListenerSocketReturnsNullBeforeSetSocket) {
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  EXPECT_EQ(worker_->getListenerSocket(), nullptr);
}

TEST_F(SimpleQuicServerWorkerTest, GetListenerSocketReturnsBoundSocket) {
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* expectedSock = sock.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(sock));
  EXPECT_EQ(worker_->getListenerSocket(), expectedSock);
}

std::unique_ptr<folly::IOBuf> createData(size_t size) {
  std::string data;
  data.resize(size);
  return folly::IOBuf::copyBuffer(data);
}

class QuicServerWorkerTest : public Test {
 public:
  QuicServerWorkerTest() {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&eventbase_);
  }

  void SetUp() override {
    TransportSettings settings;
    settings.statelessResetTokenSecret = getRandSecret();
    tokenSecret_ = getRandSecret();
    settings.retryTokenSecret = tokenSecret_;

    initializeWorker(settings);
  }

  void initializeWorker(const TransportSettings& settings) {
    fakeAddress_ = quic::SocketAddress("111.111.111.111", 44444);
    auto sock =
        std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
    EXPECT_CALL(*sock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
    DCHECK(sock->getEventBase());
    socketPtr_ = sock.get();
    worker_.reset();
    runState_ = makeSingleWorkerRunState(&eventbase_);

    worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0, settings);
    publishSingleWorker(*runState_, worker_.get());
    worker_->setSupportedVersions({QuicVersion::MVFST});
    auto quicStats = std::make_unique<NiceMock<MockQuicStats>>();
    worker_->setTransportStatsCallback(std::move(quicStats));
    worker_->setSocket(std::move(sock));
    worker_->setWorkerId(42);
    worker_->setProcessId(ProcessId::ONE);
    worker_->setHostId(hostId_);
    worker_->setConnectionIdAlgo(std::make_unique<DefaultConnectionIdAlgo>());
    quicStats_ = (MockQuicStats*)worker_->getTransportStatsCallback();

    socketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    EXPECT_CALL(*socketFactory_, _make(_, _)).WillRepeatedly(Return(nullptr));
    worker_->setNewConnectionSocketFactory(socketFactory_.get());
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    std::unique_ptr<folly::test::MockAsyncUDPSocketT<>> mockSock =
        std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
    auto qSock = std::make_unique<quic::FollyQuicAsyncUDPSocket>(
        qEvb_, std::move(mockSock));
    transport_ = std::make_shared<MockQuicTransport>(
        qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    EXPECT_CALL(*transport_, getEventBase()).WillRepeatedly(Return(qEvb_));
    EXPECT_CALL(*transport_, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(kClientAddr));
    EXPECT_CALL(*transport_, hasShutdown())
        .WillRepeatedly(ReturnPointee(&hasShutdown_));
    worker_->setTransportFactory(factory_.get());
    EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(0);
  }

  void createQuicConnection(
      const quic::SocketAddress& addr,
      ConnectionId connId,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void expectConnectionCreation(
      const quic::SocketAddress& addr,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void testSendReset(
      BufPtr packet,
      ConnectionId connId,
      ShortHeader shortHeader,
      PacketDropReason dropReason);

  void expectConnCreateRefused();
  void createQuicConnectionDuringShedding(
      const quic::SocketAddress& addr,
      ConnectionId connId);

 protected:
  quic::SocketAddress fakeAddress_;
  folly::EventBase eventbase_;
  std::shared_ptr<quic::FollyQuicEventBase> qEvb_;
  std::unique_ptr<RunState> runState_;
  std::unique_ptr<QuicServerWorker> worker_;
  MockQuicTransport::Ptr transport_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  std::unique_ptr<MockQuicUDPSocketFactory> listenerSocketFactory_;
  std::unique_ptr<MockQuicUDPSocketFactory> socketFactory_;
  MockQuicStats* quicStats_{nullptr};
  folly::test::MockAsyncUDPSocketT<>* socketPtr_{nullptr};
  uint16_t hostId_{49};
  bool hasShutdown_{false};
  TokenSecret tokenSecret_;
};

void QuicServerWorkerTest::expectConnectionCreation(
    const quic::SocketAddress& addr,
    MockQuicTransport::Ptr transportOverride) {
  MockQuicTransport::Ptr transport = transport_;
  if (transportOverride) {
    transport = transportOverride;
  }
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(transport));
  EXPECT_CALL(*transport, setSupportedVersions(_));
  EXPECT_CALL(*transport, setOriginalPeerAddress(addr));
  EXPECT_CALL(*transport, setRoutingCallback(worker_.get()));
  EXPECT_CALL(*transport, setConnectionIdAlgo(_));

  EXPECT_CALL(*transport, setServerConnectionIdParams(_))
      .WillOnce(Invoke([](ServerConnectionIdParams params) {
        EXPECT_EQ(params.processId, 1);
        EXPECT_EQ(params.workerId, 42);
      }));
  EXPECT_CALL(*transport, setTransportSettings(_));
  EXPECT_CALL(*transport, accept(_));
  EXPECT_CALL(*transport, setTransportStatsCallback(quicStats_));
}

void QuicServerWorkerTest::expectConnCreateRefused() {
  MockQuicTransport::Ptr transport = transport_;
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(nullptr));
  EXPECT_CALL(*transport, setSupportedVersions(_)).Times(0);
  EXPECT_CALL(*transport, setOriginalPeerAddress(_)).Times(0);
  EXPECT_CALL(*transport, setRoutingCallback(worker_.get())).Times(0);
  EXPECT_CALL(*transport, setConnectionIdAlgo(_)).Times(0);
  EXPECT_CALL(*transport, setServerConnectionIdParams(_)).Times(0);
  EXPECT_CALL(*transport, setTransportSettings(_)).Times(0);
  EXPECT_CALL(*transport, accept(_)).Times(0);
  EXPECT_CALL(*transport, setTransportStatsCallback(quicStats_)).Times(0);
  EXPECT_CALL(*transport, onNetworkData(_, _)).Times(0);
}

void QuicServerWorkerTest::createQuicConnectionDuringShedding(
    const quic::SocketAddress& addr,
    ConnectionId connId) {
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  RoutingData routingData(HeaderForm::Long, true, false, connId, connId);

  auto data = createData(kMinInitialPacketSize + 10);
  expectConnCreateRefused();
  worker_->dispatchPacketData(
      addr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_FALSE(addrMap.contains(std::make_pair(addr, connId)));
  eventbase_.loopIgnoreKeepAlive();
}

void QuicServerWorkerTest::createQuicConnection(
    const quic::SocketAddress& addr,
    ConnectionId connId,
    MockQuicTransport::Ptr transportOverride) {
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  RoutingData routingData(HeaderForm::Long, true, false, connId, connId);

  auto data = createData(kMinInitialPacketSize + 10);
  MockQuicTransport::Ptr transport = transport_;
  if (transportOverride) {
    transport = transportOverride;
  }
  expectConnectionCreation(addr, transport);
  EXPECT_CALL(
      *transport, onNetworkData(_, NetworkDataMatchesWithPeer(*data, addr)));
  worker_->dispatchPacketData(
      addr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_TRUE(addrMap.contains(std::make_pair(addr, connId)));
  eventbase_.loopIgnoreKeepAlive();
}

void QuicServerWorkerTest::testSendReset(
    BufPtr packet,
    ConnectionId,
    ShortHeader shortHeader,
    PacketDropReason dropReason) {
  EXPECT_CALL(*quicStats_, onPacketDropped(dropReason)).Times(1);
  // should write reset packet
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(1);
  EXPECT_CALL(*quicStats_, onStatelessReset()).Times(1);

  // verify that the packet that gets written is stateless reset packet
  EXPECT_CALL(*socketPtr_, write(_, _))
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& buf) {
        QuicReadCodec codec(QuicNodeType::Client);
        auto aead = createNoOpAead();
        // Make the decrypt fail
        EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
            .WillRepeatedly(
                Invoke([&](auto&, auto, auto) { return std::nullopt; }));
        codec.setOneRttReadCipher(std::move(aead));
        codec.setOneRttHeaderCipher(test::createNoOpHeaderCipher().value());
        StatelessResetToken token = generateStatelessResetToken();
        codec.setStatelessResetToken(token);
        FizzCryptoFactory cryptoFactory;
        codec.setCryptoEqual(cryptoFactory.getCryptoEqualFunction());
        overridePacketWithToken(*buf, token);
        AckStates ackStates;
        auto packetQueue = bufToQueue(buf->clone());
        auto res = codec.parsePacket(packetQueue, ackStates);
        EXPECT_NE(res.statelessReset(), nullptr);
        return buf->computeChainDataLength();
      }));

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeader.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(packet->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, HostIdMismatchTestReset) {
  auto data = folly::IOBuf::copyBuffer("data_longer_than_minimum_length");
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  PacketNum num = 2;
  // create packet with connId with different hostId encoded
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_ + 1), num);
  testSendReset(
      std::move(data),
      getTestConnectionId(hostId_ + 1),
      std::move(shortHeaderConnId),
      PacketDropReason::ROUTING_ERROR_WRONG_HOST);
}

TEST_F(QuicServerWorkerTest, NoConnFoundTestReset) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto data = folly::IOBuf::copyBuffer("data_longer_than_minimum_length");
  PacketNum num = 2;
  // create packet with connId with different hostId encoded
  worker_->stopPacketForwarding();
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_), num);
  testSendReset(
      std::move(data),
      getTestConnectionId(hostId_),
      std::move(shortHeaderConnId),
      PacketDropReason::CANNOT_FORWARD_DATA);
}

TEST_F(QuicServerWorkerTest, SmallPacketTestNoReset) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto data = folly::IOBuf::copyBuffer("data_short");
  PacketNum num = 2;
  // create packet with connId with different hostId encoded
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_ + 1), num);
  PacketDropReason dropReason = PacketDropReason::ROUTING_ERROR_WRONG_HOST;

  EXPECT_CALL(*quicStats_, onPacketDropped(dropReason)).Times(1);
  EXPECT_CALL(*socketPtr_, write(_, _)).Times(0);

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, RateLimit) {
  worker_->setRateLimiter(
      std::make_unique<SlidingWindowRateLimiter>([]() { return 2; }, 60s));
  EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);

  NiceMock<MockConnectionSetupCallback> connSetupCb1;
  NiceMock<MockConnectionCallback> connCb1;
  auto mockSock1 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock1, address()).WillRepeatedly(ReturnRef(fakeAddress_));

  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock1));
  MockQuicTransport::Ptr testTransport1 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock), &connSetupCb1, &connCb1, nullptr);
  EXPECT_CALL(*testTransport1, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport1, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId1 = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;
  RoutingData routingData(HeaderForm::Long, true, false, connId1, connId1);

  auto data = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport1,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)));
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(testTransport1));

  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_TRUE(addrMap.contains(std::make_pair(kClientAddr, connId1)));
  eventbase_.loopIgnoreKeepAlive();

  auto caddr2 = quic::SocketAddress("2.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb2;
  NiceMock<MockConnectionCallback> connCb2;
  auto mockSock2 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock2, address()).WillRepeatedly(ReturnRef(caddr2));

  auto qSock2 =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock2));
  MockQuicTransport::Ptr testTransport2 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock2), &connSetupCb2, &connCb2, nullptr);
  EXPECT_CALL(*testTransport2, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr2));
  ConnectionId connId2 =
      ConnectionId::createAndMaybeCrash({2, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData2(HeaderForm::Long, true, false, connId2, connId2);

  auto data2 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport2,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data2, caddr2)));
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(testTransport2));
  worker_->dispatchPacketData(
      caddr2,
      std::move(routingData2),
      NetworkData(data2->clone(), Clock::now(), 0),
      version);

  EXPECT_TRUE(addrMap.contains(std::make_pair(caddr2, connId2)));
  eventbase_.loopIgnoreKeepAlive();

  auto caddr3 = quic::SocketAddress("3.3.4.5", 1234);
  auto mockSock3 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  ConnectionId connId3 =
      ConnectionId::createAndMaybeCrash({8, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData3(HeaderForm::Long, true, false, connId3, connId3);
  auto data3 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  worker_->dispatchPacketData(
      caddr3,
      std::move(routingData3),
      NetworkData(data2->clone(), Clock::now(), 0),
      version);

  EXPECT_FALSE(addrMap.contains(std::make_pair(caddr3, connId3)));
  EXPECT_EQ(addrMap.size(), 2);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, UnfinishedHandshakeLimit) {
  // When running this test with other tests, the global unfinished handshake
  // count is affected. We need to offset the count appropriately.
  auto currentUnfinishedHandshakeCount = worker_->getUnfinishedHandshakeCount();

  worker_->setUnfinishedHandshakeLimit([currentUnfinishedHandshakeCount]() {
    return currentUnfinishedHandshakeCount + 2;
  });
  EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);

  NiceMock<MockConnectionSetupCallback> connSetupCb1;
  NiceMock<MockConnectionCallback> connCb1;
  auto mockSock1 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock1, address()).WillRepeatedly(ReturnRef(fakeAddress_));

  auto qSock1 =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock1));
  MockQuicTransport::Ptr testTransport1 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock1), &connSetupCb1, &connCb1, nullptr);
  EXPECT_CALL(*testTransport1, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport1, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId1 = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;
  RoutingData routingData(HeaderForm::Long, true, false, connId1, connId1);

  auto data = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport1,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)));
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(testTransport1));

  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_TRUE(addrMap.contains(std::make_pair(kClientAddr, connId1)));
  eventbase_.loopIgnoreKeepAlive();

  auto caddr2 = quic::SocketAddress("2.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb2;
  NiceMock<MockConnectionCallback> connCb2;
  auto mockSock2 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock2, address()).WillRepeatedly(ReturnRef(caddr2));

  auto qSock2 =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock2));
  MockQuicTransport::Ptr testTransport2 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock2), &connSetupCb2, &connCb2, nullptr);
  EXPECT_CALL(*testTransport2, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr2));
  ConnectionId connId2 =
      ConnectionId::createAndMaybeCrash({2, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData2(HeaderForm::Long, true, false, connId2, connId2);

  auto data2 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport2,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data2, caddr2)));
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(testTransport2));
  worker_->dispatchPacketData(
      caddr2,
      std::move(routingData2),
      NetworkData(data2->clone(), Clock::now(), 0),
      version);

  EXPECT_TRUE(addrMap.contains(std::make_pair(caddr2, connId2)));
  eventbase_.loopIgnoreKeepAlive();

  auto caddr3 = quic::SocketAddress("3.3.4.5", 1234);
  auto mockSock3 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  ConnectionId connId3 =
      ConnectionId::createAndMaybeCrash({3, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData3(HeaderForm::Long, true, false, connId3, connId3);
  auto data3 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  worker_->dispatchPacketData(
      caddr3,
      std::move(routingData3),
      NetworkData(data3->clone(), Clock::now(), 0),
      version);

  EXPECT_FALSE(addrMap.contains(std::make_pair(caddr3, connId3)));
  EXPECT_EQ(addrMap.size(), 2);
  eventbase_.loopIgnoreKeepAlive();

  // Finish a handshake.
  worker_->onHandshakeFinished();
  auto caddr4 = quic::SocketAddress("4.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb4;
  NiceMock<MockConnectionCallback> connCb4;
  auto mockSock4 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock4, address()).WillRepeatedly(ReturnRef(caddr4));

  auto qSock4 =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock4));
  MockQuicTransport::Ptr testTransport4 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock4), &connSetupCb4, &connCb4, nullptr);
  EXPECT_CALL(*testTransport4, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport4, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr4));
  ConnectionId connId4 =
      ConnectionId::createAndMaybeCrash({4, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData4(HeaderForm::Long, true, false, connId4, connId4);

  auto data4 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport4,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data4, caddr4)));
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(testTransport4));
  worker_->dispatchPacketData(
      caddr4,
      std::move(routingData4),
      NetworkData(data4->clone(), Clock::now(), 0),
      version);

  EXPECT_TRUE(addrMap.contains(std::make_pair(caddr4, connId4)));
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, QuicServerWorkerUnbindBeforeCidAvailable) {
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));

  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
  MockQuicTransport::Ptr testTransport = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
  EXPECT_CALL(*testTransport, getEventBase()).WillRepeatedly(Return(qEvb_));

  EXPECT_CALL(*testTransport, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId, testTransport);

  // Otherwise the mock of _make will hold on to a shared_ptr to the transport
  Mock::VerifyAndClearExpectations(factory_.get());

  auto& srcAddrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(1, srcAddrMap.size());
  EXPECT_EQ(srcAddrMap.begin()->second.get(), testTransport.get());
  auto& srcIdentity = srcAddrMap.begin()->first;
  auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(0, connIdMap.size());

  auto* rawTransport = testTransport.get();
  // This is fine, server worker still has at one shared_ptr in its map.
  testTransport.reset();

  EXPECT_CALL(*rawTransport, setRoutingCallback(nullptr)).Times(1);
  // Now remove it from the maps. Nothing should crash.
  auto cidDataOnHeap = std::make_shared<std::vector<ConnectionIdData>>();
  const auto& cidRef = *cidDataOnHeap;
  EXPECT_CALL(*rawTransport, customDestructor())
      .Times(1)
      .WillOnce(
          Invoke([cid = std::move(cidDataOnHeap)]() mutable { cid.reset(); }));
  worker_->onConnectionUnbound(rawTransport, srcIdentity, cidRef);
  EXPECT_EQ(0, srcAddrMap.size());
}

TEST_F(QuicServerWorkerTest, Drop0RttReplayWithPeerMismatch) {
  // Buffer 0-RTT from clientA for a CID before any Initial arrives, then
  // send an Initial with the same CID from a different clientB (NAT
  // rebind, network switch, etc.). The lambda's 0-RTT replay loop must
  // drop the buffered 0-RTT instead of forwarding it to the transport,
  // where it would trip the ServerStateMachine migration check and
  // synchronously close the connection.
  quic::SocketAddress clientA("1.2.3.4", 11111);
  quic::SocketAddress clientB("5.6.7.8", 22222);
  auto connId = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;

  // Step 1: 0-RTT from clientA. No transport for connId, so the worker
  // buffers it in pending0RttData_[connId].
  {
    RoutingData routingData0Rtt(
        HeaderForm::Long, false /*isInitial*/, true /*is0Rtt*/, connId, connId);
    auto data0Rtt = createData(kMinInitialPacketSize);
    EXPECT_CALL(*quicStats_, onZeroRttBuffered()).Times(1);
    worker_->dispatchPacketData(
        clientA,
        std::move(routingData0Rtt),
        NetworkData(data0Rtt->clone(), Clock::now(), 0),
        version);
  }

  // Step 2: Initial from clientB for the same connId. Worker creates a
  // new transport for clientB and runs the 0-RTT replay loop. The
  // buffered 0-RTT (peer=clientA) must be dropped, not replayed.
  {
    RoutingData routingDataInit(
        HeaderForm::Long, true /*isInitial*/, false /*is0Rtt*/, connId, connId);
    auto dataInit = createData(kMinInitialPacketSize + 10);
    expectConnectionCreation(clientB);
    // The transport sees onNetworkData exactly once -- for the current
    // Initial. The buffered 0-RTT (peer=clientA) must NOT reach it.
    EXPECT_CALL(
        *transport_,
        onNetworkData(_, NetworkDataMatchesWithPeer(*dataInit, clientB)))
        .Times(1);
    // The mismatched buffered 0-RTT is dropped, recorded as
    // PEER_ADDRESS_CHANGE in the worker's packet-drop stats.
    PacketDropReason dropReason = PacketDropReason::PEER_ADDRESS_CHANGE;
    EXPECT_CALL(*quicStats_, onPacketDropped(dropReason)).Times(1);

    worker_->dispatchPacketData(
        clientB,
        std::move(routingDataInit),
        NetworkData(dataInit->clone(), Clock::now(), 0),
        version);
    eventbase_.loopIgnoreKeepAlive();

    const auto& addrMap = worker_->getSrcToTransportMap();
    EXPECT_TRUE(addrMap.contains(std::make_pair(clientB, connId)));
  }

  // Cleanup at test teardown: worker destruction iterates remaining
  // transports and unwinds their callbacks.
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr))
      .Times(testing::AnyNumber());
}

TEST_F(QuicServerWorkerTest, QuicServerMultipleConnIdsRouting) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  ShortHeader shortHeaderConnId(ProtectionType::KeyPhaseZero, connId, num);

  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_.get()->onConnectionIdAvailable(transport_, connId);
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_TRUE(connIdMap.contains(connId));

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_FALSE(addrMap.contains(std::make_pair(kClientAddr, connId)));

  // routing by connid after connid available.
  EXPECT_CALL(
      *transport_,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)))
      .Times(1);
  RoutingData routingData2(
      HeaderForm::Short, false, false, connId, std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData2),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();

  auto connId2 = connId;
  connId2.data()[7] ^= 0x1;
  worker_.get()->onConnectionIdAvailable(transport_, connId2);

  EXPECT_EQ(connIdMap.size(), 2);

  EXPECT_CALL(
      *transport_,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)))
      .Times(1);
  RoutingData routingData3(
      HeaderForm::Short, false, false, connId2, std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData3),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, connId),
      std::vector<ConnectionIdData>{
          ConnectionIdData{connId, 0}, ConnectionIdData{connId2, 1}});
  EXPECT_FALSE(connIdMap.contains(connId));
  EXPECT_FALSE(addrMap.contains(std::make_pair(kClientAddr, connId)));

  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
}

TEST_F(QuicServerWorkerTest, RetireConnIds) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  const auto& connIdMap = worker_->getConnectionIdMap();
  const auto& addrMap = worker_->getSrcToTransportMap();

  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_->onConnectionIdAvailable(transport_, connId);
  EXPECT_TRUE(connIdMap.contains(connId));

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  EXPECT_FALSE(addrMap.contains(std::make_pair(kClientAddr, connId)));

  // create two additional conn ids
  auto connId2 = connId;
  connId2.data()[7] ^= 0x1;
  worker_->onConnectionIdAvailable(transport_, connId2);

  auto connId3 = connId;
  connId3.data()[7] ^= 0x2;
  worker_->onConnectionIdAvailable(transport_, connId3);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_EQ(connIdMap.size(), 3);

  // retiring invalid conn id should not change map size
  auto invalidConnId = connId;
  invalidConnId.data()[0] ^= 0x1;
  worker_->onConnectionIdRetired(*transport_, invalidConnId);
  EXPECT_EQ(connIdMap.size(), 3);

  // retiring valid conn ids should decrease map size by one each time
  worker_->onConnectionIdRetired(*transport_, connId2);
  EXPECT_EQ(connIdMap.size(), 2);

  worker_->onConnectionIdRetired(*transport_, connId3);
  EXPECT_EQ(connIdMap.size(), 1);

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, connId),
      std::vector<ConnectionIdData>{ConnectionIdData{connId, 0}});
  EXPECT_FALSE(connIdMap.contains(connId));
  EXPECT_FALSE(addrMap.contains(std::make_pair(kClientAddr, connId)));
  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
}

TEST_F(QuicServerWorkerTest, QuicServerNewConnection) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  MVLOG_ERROR << "from test CID: " << int(connId.size());
  createQuicConnection(kClientAddr, connId);

  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_), num);

  // Routing by connid before conn id available on a short packet.
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();

  ConnectionId newConnId = getTestConnectionId(hostId_);

  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_.get()->onConnectionIdAvailable(transport_, newConnId);
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_TRUE(connIdMap.contains(getTestConnectionId(hostId_)));

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_FALSE(addrMap.contains(
      std::make_pair(kClientAddr, getTestConnectionId(hostId_))));

  // routing by connid after connid available.
  EXPECT_CALL(
      *transport_,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)));
  RoutingData routingData2(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData2),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();

  // routing by address after transport_'s connid available, but before
  // transport2's connid available.
  ConnectionId connId2 =
      ConnectionId::createAndMaybeCrash({2, 4, 5, 6, 7, 8, 9, 10});
  quic::SocketAddress clientAddr2("2.3.4.5", 2345);
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);

  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));

  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
  MockQuicTransport::Ptr transport2 = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
  EXPECT_CALL(*transport2, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*transport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  createQuicConnection(clientAddr2, connId2, transport2);

  ShortHeader shortHeaderConnId2(ProtectionType::KeyPhaseZero, connId2, num);

  // Will be dropped
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  RoutingData routingData3(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId2.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      clientAddr2,
      std::move(routingData3),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  eventbase_.loopIgnoreKeepAlive();

  // Called for transport_'s own unbind and for the wrong-owner unbind
  // attempt against transport2's source below.
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, getTestConnectionId(hostId_)),
      std::vector<ConnectionIdData>{ConnectionIdData{connId, 0}});
  // A wrong-owner unbind must not erase transport2's source entry.
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(clientAddr2, connId2),
      std::vector<ConnectionIdData>{ConnectionIdData{connId2, 0}});
  EXPECT_TRUE(addrMap.contains(std::make_pair(clientAddr2, connId2)));
  EXPECT_CALL(*transport2, setRoutingCallback(nullptr));
  worker_->onConnectionUnbound(
      transport2.get(),
      std::make_pair(clientAddr2, connId2),
      std::vector<ConnectionIdData>{ConnectionIdData{connId2, 0}});
  EXPECT_FALSE(addrMap.contains(std::make_pair(clientAddr2, connId2)));
  EXPECT_FALSE(connIdMap.contains(getTestConnectionId(hostId_)));
  EXPECT_FALSE(addrMap.contains(
      std::make_pair(kClientAddr, getTestConnectionId(hostId_))));

  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
}

TEST_F(QuicServerWorkerTest, InitialPacketTooSmall) {
  auto data = createData(kMinInitialPacketSize - 100);
  auto connId = getTestConnectionId(hostId_);
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(hostId_ + 1),
      connId,
      num,
      version);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPacketDropped(_));
  RoutingData routingData(
      HeaderForm::Long,
      true,
      false,
      header.getDestinationConnId(),
      header.getSourceConnId());
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, QuicShedTest) {
  auto connId = getTestConnectionId(hostId_);
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(
          PacketDropReason(PacketDropReason::CANNOT_MAKE_TRANSPORT)));
  Optional<VersionNegotiationPacket> versionPacket;
  EXPECT_CALL(*socketPtr_, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
        auto packetQueue = bufToQueue(writtenData->clone());
        versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
        return packetQueue.chainLength();
      }));

  createQuicConnectionDuringShedding(kClientAddr, connId);
  EXPECT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->destinationConnectionId, connId);
}

TEST_F(QuicServerWorkerTest, BlockedSourcePort) {
  quic::SocketAddress blockedSrcPort("1.2.3.4", 443);
  worker_->setIsBlockListedSrcPort([](uint16_t port) { return port == 443; });
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId::createZeroLength();
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(PacketDropReason(PacketDropReason::INVALID_SRC_PORT)));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToReceivedUdpPacket(std::move(builder).buildPacket());
  packet.peerAddress = blockedSrcPort;
  worker_->handleNetworkData(packet);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ZeroLengthConnectionId) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId::createZeroLength();
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToReceivedUdpPacket(std::move(builder).buildPacket());
  packet.peerAddress = kClientAddr;
  worker_->handleNetworkData(packet);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ClientInitialCounting) {
  auto srcConnId = getTestConnectionId(0);
  auto destConnId = getTestConnectionId(1);
  QuicVersion version = QuicVersion::MVFST;
  PacketNum num = 1;
  LongHeader initialHeader(
      LongHeader::Types::Initial, srcConnId, destConnId, num, version);
  RegularQuicPacketBuilder initialBuilder(
      kDefaultUDPSendPacketLen, std::move(initialHeader), 0);
  ASSERT_FALSE(initialBuilder.encodePacketHeader().hasError());
  auto initialPacket =
      packetToReceivedUdpPacket((std::move(initialBuilder).buildPacket()));
  EXPECT_CALL(*quicStats_, onClientInitialReceived(QuicVersion::MVFST))
      .Times(1);
  initialPacket.peerAddress = kClientAddr;
  worker_->handleNetworkData(initialPacket);
  eventbase_.loopIgnoreKeepAlive();

  // Initial with any packet number should also increate the counting
  PacketNum bignum = 200;
  LongHeader initialHeaderBigNum(
      LongHeader::Types::Initial, srcConnId, destConnId, bignum, version);
  RegularQuicPacketBuilder initialBuilderBigNum(
      kDefaultUDPSendPacketLen, std::move(initialHeaderBigNum), 0);
  ASSERT_FALSE(initialBuilderBigNum.encodePacketHeader().hasError());
  auto initialPacketBigNum = packetToReceivedUdpPacket(
      (std::move(initialBuilderBigNum).buildPacket()));
  EXPECT_CALL(*quicStats_, onClientInitialReceived(QuicVersion::MVFST))
      .Times(1);
  initialPacketBigNum.peerAddress = kClientAddr;
  worker_->handleNetworkData(initialPacketBigNum);
  eventbase_.loopIgnoreKeepAlive();

  LongHeader handshakeHeader(
      LongHeader::Types::Handshake, srcConnId, destConnId, num, version);
  RegularQuicPacketBuilder handshakeBuilder(
      kDefaultUDPSendPacketLen, std::move(handshakeHeader), 0);
  ASSERT_FALSE(handshakeBuilder.encodePacketHeader().hasError());
  auto handshakePacket =
      packetToReceivedUdpPacket((std::move(handshakeBuilder).buildPacket()));
  EXPECT_CALL(*quicStats_, onClientInitialReceived(_)).Times(0);
  handshakePacket.peerAddress = kClientAddr;
  worker_->handleNetworkData(handshakePacket);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooShort) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId::createAndMaybeCrash({1});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToReceivedUdpPacket((std::move(builder).buildPacket()));
  packet.peerAddress = kClientAddr;
  worker_->handleNetworkData(packet);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, FailToParseConnectionId) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto srcConnId = getTestConnectionId(0);
  auto dstConnId = getTestConnectionId(1);
  auto mockConnIdAlgo = std::make_unique<MockConnectionIdAlgo>();
  auto rawConnIdAlgo = mockConnIdAlgo.get();
  worker_->setConnectionIdAlgo(std::move(mockConnIdAlgo));

  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  // To force dropping path, set initial to false
  RoutingData routingData(
      HeaderForm::Long, false /* isInitial */, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now(), 0);

  EXPECT_CALL(*rawConnIdAlgo, canParseNonConst(_)).WillOnce(Return(true));
  EXPECT_CALL(*rawConnIdAlgo, parseConnectionId(dstConnId))
      .WillOnce(Return(
          quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR, "This CID has COVID-19"))));
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooShortDispatch) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto dstConnId = ConnectionId::createAndMaybeCrash({3});
  auto srcConnId = ConnectionId::createAndMaybeCrash({3});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  RoutingData routingData(HeaderForm::Long, true, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now(), 0);
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooLargeDispatch) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto dstConnId = ConnectionId::createAndMaybeCrash({21});
  auto srcConnId = ConnectionId::createAndMaybeCrash({3});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  while (builder.remainingSpaceInPkt() > 0) {
    ASSERT_FALSE(writeFrame(PaddingFrame(), builder).hasError());
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  RoutingData routingData(HeaderForm::Long, true, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now(), 0);
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ShutdownQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_TRUE(connIdMap.contains(getTestConnectionId(hostId_)));

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, closeNow(_)).Times(1).WillOnce([this](const auto&) {
    hasShutdown_ = true;
  });
  std::thread t([&] { eventbase_.loopForever(); });
  eventbase_.runInEventBaseThreadAndWait([&] { worker_.reset(); });
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, ShutdownTransportWithDuplicateConnectionId) {
  const auto initialCid = getTestConnectionId(hostId_);
  const auto serverCid = getTestConnectionId(hostId_ + 1);
  auto firstSocket =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*firstSocket, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto firstTransport = std::make_shared<MockQuicTransport>(
      qEvb_,
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(firstSocket)),
      nullptr,
      nullptr,
      nullptr);
  createQuicConnection(kClientAddr, initialCid);
  worker_->onConnectionIdAvailable(firstTransport, serverCid);
  worker_->onConnectionIdAvailable(transport_, serverCid);
  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillOnce(Return(initialCid));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->getSrcToTransportMap().empty());
  EXPECT_EQ(worker_->getConnectionIdMap().at(serverCid), firstTransport);

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setHandshakeFinishedCallback(nullptr)).Times(1);
  worker_->shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}

TEST_F(QuicServerWorkerTest, PacketAfterShutdown) {
  std::thread t([&] { eventbase_.loopForever(); });
  worker_->shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
  auto connId = getTestConnectionId(hostId_);
  PacketNum packetNum = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, connId, connId, packetNum, version);
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  auto packet = packetToReceivedUdpPacket((std::move(builder).buildPacket()));
  packet.peerAddress = kClientAddr;
  worker_->handleNetworkData(packet);
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, DestroyQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_TRUE(connIdMap.contains(getTestConnectionId(hostId_)));

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setHandshakeFinishedCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, closeNow(_)).Times(1).WillOnce([this](const auto&) {
    hasShutdown_ = true;
  });
  std::thread t([&] { eventbase_.loopForever(); });
  eventbase_.runInEventBaseThreadAndWait([&] { worker_.reset(); });
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, AssignBufAccessor) {
  TransportSettings transportSettings;
  transportSettings.dataPathType = DataPathType::ContinuousMemory;
  transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  initializeWorker(transportSettings);

  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);

  EXPECT_CALL(*transport_, setBufAccessor(_))
      .Times(1)
      .WillOnce(Invoke(
          [](BufAccessor* accessor) { EXPECT_TRUE(accessor != nullptr); }));
  createQuicConnection(kClientAddr, connId);

  // From shutdownAllConnections:
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
}

class MockAcceptObserver : public AcceptObserver {
 public:
  MOCK_METHOD(void, accept, (QuicTransportBase* const), (noexcept));
  MOCK_METHOD(void, acceptorDestroy, (QuicServerWorker*), (noexcept));
  MOCK_METHOD(void, observerAttach, (QuicServerWorker*), (noexcept));
  MOCK_METHOD(void, observerDetach, (QuicServerWorker*), (noexcept));
};

struct SelfOwningAcceptObserverState {
  size_t acceptorDestroyCalls{0};
  size_t observerDetachCalls{0};
  size_t destructorCalls{0};
};

class ThreadCheckingAcceptObserver final : public AcceptObserver {
 public:
  explicit ThreadCheckingAcceptObserver(folly::EventBase* expectedEvb)
      : expectedEvb_(expectedEvb) {}

  void accept(QuicTransportBase* const) noexcept override {}

  void acceptorDestroy(QuicServerWorker*) noexcept override {}

  void observerAttach(QuicServerWorker*) noexcept override {
    attachRanOnExpectedEvb = expectedEvb_->isInEventBaseThread();
  }

  void observerDetach(QuicServerWorker*) noexcept override {}

  bool attachRanOnExpectedEvb{false};

 private:
  folly::EventBase* expectedEvb_;
};

class SelfOwningAcceptObserver final : public AcceptObserver {
 public:
  explicit SelfOwningAcceptObserver(SelfOwningAcceptObserverState& state)
      : state_(state) {}

  ~SelfOwningAcceptObserver() override {
    ++state_.destructorCalls;
  }

  void accept(QuicTransportBase* const) noexcept override {}

  void acceptorDestroy(QuicServerWorker*) noexcept override {
    ++state_.acceptorDestroyCalls;
    delete this;
  }

  void observerAttach(QuicServerWorker*) noexcept override {}

  void observerDetach(QuicServerWorker*) noexcept override {
    ++state_.observerDetachCalls;
    delete this;
  }

 private:
  SelfOwningAcceptObserverState& state_;
};

TEST_F(QuicServerWorkerTest, AcceptObserver) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());

  auto initTestSocketAndTransport = [this]() {
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    auto mockSock =
        std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));

    auto qSock =
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
    MockQuicTransport::Ptr mockTransport = std::make_shared<MockQuicTransport>(
        qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
    EXPECT_CALL(*mockTransport, setRoutingCallback(nullptr));
    EXPECT_CALL(*mockTransport, setTransportStatsCallback(nullptr));
    EXPECT_CALL(*mockTransport, getEventBase()).WillRepeatedly(Return(qEvb_));
    EXPECT_CALL(*mockTransport, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(kClientAddr));
    return std::make_pair(std::move(mockSock), std::move(mockTransport));
  };

  // add first connection, expect events
  const auto [sock1, transport1] = initTestSocketAndTransport();
  EXPECT_CALL(*cb, accept(transport1.get()));
  createQuicConnection(kClientAddr, getTestConnectionId(hostId_), transport1);
  Mock::VerifyAndClearExpectations(cb.get());

  // add second connection, expect events
  const auto [sock2, transport2] = initTestSocketAndTransport();
  EXPECT_CALL(*cb, accept(transport2.get()));
  createQuicConnection(kClientAddr2, getTestConnectionId(hostId_), transport2);
  Mock::VerifyAndClearExpectations(cb.get());

  // remove AcceptObserver
  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());

  // add third connection, no events
  const auto [sock3, transport3] = initTestSocketAndTransport();
  createQuicConnection(kClientAddr3, getTestConnectionId(hostId_), transport3);
}

TEST_F(QuicServerWorkerTest, AcceptObserverDetachedDuringAcceptNotInvoked) {
  auto cbA = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cbA, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cbA.get());

  auto cbB = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cbB, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cbB.get());
  Mock::VerifyAndClearExpectations(cbA.get());
  Mock::VerifyAndClearExpectations(cbB.get());

  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
  MockQuicTransport::Ptr mockTransport = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
  EXPECT_CALL(*mockTransport, setRoutingCallback(nullptr));
  EXPECT_CALL(*mockTransport, setTransportStatsCallback(nullptr));
  EXPECT_CALL(*mockTransport, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*mockTransport, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));

  // B is detached from inside A's accept() and must not be invoked for
  // this connection afterwards.
  EXPECT_CALL(*cbB, observerDetach(worker_.get())).Times(1);
  EXPECT_CALL(*cbB, accept(_)).Times(0);
  EXPECT_CALL(*cbA, accept(mockTransport.get()))
      .WillOnce(Invoke([&](QuicTransportBase* const) {
        EXPECT_TRUE(worker_->removeAcceptObserver(cbB.get()));
      }));
  createQuicConnection(
      kClientAddr, getTestConnectionId(hostId_), mockTransport);
  Mock::VerifyAndClearExpectations(cbA.get());
  Mock::VerifyAndClearExpectations(cbB.get());

  EXPECT_CALL(*cbA, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cbA.get()));
}

TEST_F(QuicServerWorkerTest, AcceptObserverUnbindBeforeCidClearsSourceMap) {
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
  MockQuicTransport::Ptr testTransport = std::make_shared<MockQuicTransport>(
      qEvb_, std::move(qSock), &connSetupCb, &connCb, nullptr);
  EXPECT_CALL(*testTransport, getEventBase()).WillRepeatedly(Return(qEvb_));
  EXPECT_CALL(*testTransport, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  EXPECT_CALL(*testTransport, setTransportStatsCallback(nullptr))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*testTransport, setRoutingCallback(nullptr))
      .Times(testing::AnyNumber());

  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_CALL(*cb, accept(testTransport.get()))
      .WillOnce(Invoke([&](QuicTransportBase* const) {
        // Simulate a synchronous close during accept notification, before
        // any server CID exists. The mocked setRoutingCallback() call in
        // makeTransport() does not install the real callback, so install
        // it directly first.
        testTransport->QuicServerTransport::setRoutingCallback(worker_.get());
        testTransport->unbindConnection();
      }));

  auto connId = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;
  RoutingData routingData(HeaderForm::Long, true, false, connId, connId);
  auto data = createData(kMinInitialPacketSize + 10);
  expectConnectionCreation(kClientAddr, testTransport);
  EXPECT_CALL(*testTransport, setConnectionIdAlgo(nullptr))
      .Times(testing::AnyNumber());
  EXPECT_CALL(
      *testTransport,
      onNetworkData(_, NetworkDataMatchesWithPeer(*data, kClientAddr)));
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      version);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_TRUE(worker_->getSrcToTransportMap().empty());

  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemove) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemoveMissing) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_FALSE(worker_->removeAcceptObserver(cb.get()));
}

TEST_F(QuicServerWorkerTest, AcceptObserverDestroyWorker) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  // destroy the acceptor while the AcceptObserver is installed
  EXPECT_CALL(*cb, acceptorDestroy(worker_.get()));
  worker_ = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleRemove) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb1, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());

  EXPECT_CALL(*cb2, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleRemoveReverse) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb2, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb1, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleAcceptorDestroyed) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  // destroy the acceptor while the AcceptObserver is installed
  EXPECT_CALL(*cb1, acceptorDestroy(worker_.get()));
  EXPECT_CALL(*cb2, acceptorDestroy(worker_.get()));
  worker_ = nullptr;
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemoveCallbackThenDestroyWorker) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());

  worker_ = nullptr;
}

TEST_F(QuicServerWorkerTest, SelfOwningAcceptObserverRemoveThenDestroyWorker) {
  SelfOwningAcceptObserverState state;
  auto* cb = new SelfOwningAcceptObserver(state);
  worker_->addAcceptObserver(cb);

  EXPECT_TRUE(worker_->removeAcceptObserver(cb));
  EXPECT_EQ(state.observerDetachCalls, 1);
  EXPECT_EQ(state.acceptorDestroyCalls, 0);
  EXPECT_EQ(state.destructorCalls, 1);

  worker_ = nullptr;
  EXPECT_EQ(state.observerDetachCalls, 1);
  EXPECT_EQ(state.acceptorDestroyCalls, 0);
  EXPECT_EQ(state.destructorCalls, 1);
}

TEST_F(QuicServerWorkerTest, SelfOwningAcceptObserverDestroyWorker) {
  SelfOwningAcceptObserverState state;
  auto* cb = new SelfOwningAcceptObserver(state);
  worker_->addAcceptObserver(cb);

  worker_ = nullptr;
  EXPECT_EQ(state.observerDetachCalls, 0);
  EXPECT_EQ(state.acceptorDestroyCalls, 1);
  EXPECT_EQ(state.destructorCalls, 1);
}

TEST_F(QuicServerWorkerTest, PacketWithZeroHostIdFromExistingConnection) {
  // create a connection with host id 0
  auto connId = getTestConnectionId(0);
  createQuicConnection(kClientAddr, connId);
  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_->onConnectionIdAvailable(transport_, connId);
  PacketNum num = 1;
  auto data = folly::IOBuf::copyBuffer("data");

  // a non-initial packet with a different connection id while its host id is
  // also 0
  auto newConnId = connId;
  newConnId.data()[7] = 0;
  ShortHeader shortHeaderConnId(ProtectionType::KeyPhaseZero, newConnId, num);

  // instead of reporting the drop reason ROUTING_ERROR_WRONG_HOST, it should
  // be CANNOT_FORWARD_DATA
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(PacketDropReason(PacketDropReason::CANNOT_FORWARD_DATA)));

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      std::nullopt);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now(), 0),
      std::nullopt);
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
}

auto createInitialStream(
    ConnectionId srcConnId,
    ConnectionId destConnId,
    StreamId streamId,
    folly::IOBuf& data,
    QuicVersion version,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  PacketNum packetNum = 1;
  LongHeader header(pktHeaderType, srcConnId, destConnId, packetNum, version);
  LongHeader headerRetry(
      pktHeaderType,
      srcConnId,
      destConnId,
      packetNum,
      version,
      std::string("this is a retry token :)"));
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      pktHeaderType == LongHeader::Types::Retry ? std::move(headerRetry)
                                                : std::move(header),
      0 /* largestAcked */);
  CHECK(!builder.encodePacketHeader().hasError());
  auto streamData = data.clone();
  auto res = writeStreamFrameHeader(
      builder,
      streamId,
      0,
      streamData->computeChainDataLength(),
      streamData->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  EXPECT_TRUE(res.has_value());
  auto dataLen = *res;
  EXPECT_TRUE(dataLen);
  writeStreamFrameData(builder, std::move(streamData), *dataLen);
  return packetToBuf(std::move(builder).buildPacket());
}

auto createInitialStream(
    StreamId streamId,
    folly::IOBuf& data,
    QuicVersion version,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  return createInitialStream(
      getTestConnectionId(),
      getTestConnectionId(1),
      streamId,
      data,
      version,
      pktHeaderType);
}

std::unique_ptr<folly::IOBuf> writeTestDataOnWorkersBuf(
    ConnectionId srcConnId,
    ConnectionId destConnId,
    size_t& lenOut,
    QuicServerWorker* worker,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  StreamId id = 1;
  auto buf = pktHeaderType == LongHeader::Types::Initial
      ? createData(kMinInitialPacketSize)
      : folly::IOBuf::copyBuffer("hello, world!");
  auto packet = createInitialStream(
      srcConnId, destConnId, id, *buf, MVFST1, pktHeaderType);
  packet->coalesce();
  auto data = std::move(packet);
  uint8_t* workerBuf = nullptr;
  size_t workerBufLen = 0;
  worker->getReadBuffer((void**)&workerBuf, &workerBufLen);
  lenOut = std::min(workerBufLen, data->computeChainDataLength());
  memcpy(workerBuf, data->buffer(), lenOut);
  data->coalesce();
  return data;
}

ConnectionId createConnIdForServer(ProcessId server) {
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  uint8_t processId = (server == ProcessId::ONE) ? 1 : 0;
  ServerConnectionIdParams params(0, processId, 0);
  return *connIdAlgo->encodeConnectionId(params);
}

TEST_F(QuicServerWorkerTest, OnDataAvailableRecordsPacketTtl) {
  // writeTestDataOnWorkersBuf builds an MVFST1 packet.
  worker_->setSupportedVersions({QuicVersion::MVFST, MVFST1});
  auto connId = createConnIdForServer(ProcessId::ONE);
  size_t len{0};
  writeTestDataOnWorkersBuf(
      getTestConnectionId(hostId_), connId, len, worker_.get());

  expectConnectionCreation(kClientAddr);
  OptionalIntegral<uint8_t> routedTtl;
  EXPECT_CALL(*transport_, onNetworkData(_, _))
      .WillOnce(
          Invoke([&](const quic::SocketAddress&, const NetworkData& data) {
            ASSERT_EQ(data.getPackets().size(), 1);
            routedTtl = data.getPackets()[0].ttlValue;
          }));

  OnDataAvailableParams params;
  params.ttl = 64;
  worker_->onDataAvailable(kClientAddr, len, false, params);

  ASSERT_TRUE(routedTtl.has_value());
  EXPECT_EQ(*routedTtl, 64);
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr));
  EXPECT_CALL(*transport_, setHandshakeFinishedCallback(nullptr));
  EXPECT_CALL(*transport_, closeNow(_));
}

class QuicServerWorkerRetryTest : public QuicServerWorkerTest {
 public:
  // Helper method to send a client initial that may contain the retry token to
  // the server in response to the retry packet
  void testSendInitial(
      const ConnectionId& clientSrcConnId,
      const ConnectionId& dstConnId,
      const quic::SocketAddress& clientAddr,
      const std::string& retryToken = "",
      QuicVersion version = QuicVersion::MVFST) {
    PacketNum num = 1;
    LongHeader initialHeader(
        LongHeader::Types::Initial,
        clientSrcConnId,
        dstConnId,
        num,
        version,
        retryToken);

    RegularQuicPacketBuilder initialBuilder(
        kDefaultUDPSendPacketLen, std::move(initialHeader), 0);
    CHECK(!initialBuilder.encodePacketHeader().hasError());
    while (initialBuilder.remainingSpaceInPkt() > 0) {
      CHECK(!writeFrame(PaddingFrame(), initialBuilder).hasError());
    }
    auto initialPacket = packetToBuf(std::move(initialBuilder).buildPacket());
    RoutingData routingData(
        HeaderForm::Long, true, false, dstConnId, clientSrcConnId);
    worker_->dispatchPacketData(
        clientAddr,
        std::move(routingData),
        NetworkData(initialPacket->clone(), Clock::now(), 0),
        version);
    eventbase_.loopIgnoreKeepAlive();
  }

  /**
   * Sends a client Initial that the server is expected to answer with a Retry,
   * and returns that Retry.
   */
  RetryPacket testSendInitialExpectingRetry(
      const ConnectionId& clientSrcConnId,
      const ConnectionId& dstConnId,
      const quic::SocketAddress& clientAddr,
      const std::string& retryToken = "",
      QuicVersion version = QuicVersion::MVFST) {
    EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);
    EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
    EXPECT_CALL(*quicStats_, onPacketSent()).Times(1);

    Optional<RetryPacket> retry;
    EXPECT_CALL(*socketPtr_, write(_, _))
        .WillOnce([&retry](
                      const quic::SocketAddress&,
                      const std::unique_ptr<folly::IOBuf>& buf) {
          QuicReadCodec codec(QuicNodeType::Client);
          auto packetQueue = bufToQueue(buf->clone());
          AckStates ackStates;
          auto parsedPacket = codec.parsePacket(packetQueue, ackStates);
          auto* retryPacket = parsedPacket.retryPacket();
          CHECK(retryPacket);
          retry = *retryPacket;
          return buf->computeChainDataLength();
        });
    testSendInitial(
        clientSrcConnId, dstConnId, clientAddr, retryToken, version);
    CHECK(retry.has_value());
    return std::move(retry.value());
  }

  void expectRetriedConnectionCreation() {
    expectConnectionCreation(kClientAddr, transport_);
    EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
    EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr));
  }

  const QuicServerConnectionState& getTransportState() {
    return *static_cast<const QuicServerConnectionState*>(
        transport_->getState());
  }

  /**
   * Sends a client Initial that gets a Retry, then sends the next Initial with
   * the retry token to the Retry's source connection id.
   */
  void testRetryValidInitial(QuicVersion version) {
    auto dstConnId = getTestConnectionId(hostId_);
    auto srcConnId = getTestConnectionId(0);

    auto retry = testSendInitialExpectingRetry(
        srcConnId, dstConnId, kClientAddr, "", version);
    const auto& retrySrcConnId = retry.header.getSourceConnId();
    EXPECT_EQ(retry.header.getVersion(), version);
    EXPECT_EQ(retry.header.getDestinationConnId(), srcConnId);
    EXPECT_NE(retrySrcConnId, dstConnId);
    auto params = DefaultConnectionIdAlgo().parseConnectionId(retrySrcConnId);
    ASSERT_TRUE(params.has_value());
    EXPECT_EQ(params->hostId, hostId_);
    EXPECT_EQ(params->processId, 1);
    EXPECT_EQ(params->workerId, 42);

    // The transport parameters must still carry the original destination
    // connection id.
    expectRetriedConnectionCreation();
    testSendInitial(
        srcConnId,
        retrySrcConnId,
        kClientAddr,
        retry.header.getToken(),
        version);
    EXPECT_EQ(getTransportState().retryOriginalDstConnId, dstConnId);
    EXPECT_EQ(getTransportState().clientChosenDestConnectionId, retrySrcConnId);
  }

  void enableRateLimiterForRetry() {
    // Retry packet will only be sent if rate-limiting is configured
    worker_->setRateLimiter(
        std::make_unique<SlidingWindowRateLimiter>([]() { return 0; }, 60s));
  }

  void enableUnfinishedHandshakeLimitForRetry() {
    worker_->setUnfinishedHandshakeLimit([]() { return 0; });
  }
};

// Validate that when the worker receives a valid NewToken, it invokes
// transportInfo->onNewTokenReceived().
TEST_F(QuicServerWorkerRetryTest, TestNewTokenStatsCallback) {
  EXPECT_CALL(*quicStats_, onNewTokenReceived());

  NewToken newToken(kClientAddr.getIPAddress());
  // Create the encrypted retry token
  TokenGenerator generator(tokenSecret_);
  auto encryptedToken = generator.encryptToken(newToken);

  CHECK(encryptedToken.has_value());
  std::string encryptedTokenStr = encryptedToken.value()->toString();

  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  testSendInitial(srcConnId, dstConnId, kClientAddr, encryptedTokenStr);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryValidInitial) {
  // The second client initial packet with the retry token is valid
  // as the client IP is the same as the one stored in the retry token
  enableRateLimiterForRetry();
  testRetryValidInitial(QuicVersion::MVFST);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryValidInitialQuicV1) {
  enableRateLimiterForRetry();
  testRetryValidInitial(QuicVersion::QUIC_V1);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryUnfinishedValidInitial) {
  // The second client initial packet with the retry token is valid
  // as the client IP is the same as the one stored in the retry token
  enableUnfinishedHandshakeLimitForRetry();
  testRetryValidInitial(QuicVersion::MVFST);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidInitialClientIp) {
  // The second client initial packet with the retry token is invalid
  // as the client IP is different from the one stored in the retry token
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  auto retry = testSendInitialExpectingRetry(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different client addr to verify it's invalid (i.e. will send another retry
  // packet)
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  testSendInitialExpectingRetry(
      srcConnId,
      retry.header.getSourceConnId(),
      kClientAddr2,
      retry.header.getToken());
}

TEST_F(QuicServerWorkerRetryTest, TestRetryUnfinishedInvalidInitialClientIp) {
  // The second client initial packet with the retry token is invalid
  // as the client IP is different from the one stored in the retry token
  enableUnfinishedHandshakeLimitForRetry();

  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  auto retry = testSendInitialExpectingRetry(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different client addr to verify it's invalid
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  testSendInitialExpectingRetry(
      srcConnId,
      retry.header.getSourceConnId(),
      kClientAddr2,
      retry.header.getToken());
}

TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidInitialDstConnId) {
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  auto retry = testSendInitialExpectingRetry(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different dst conn id to verify it's invalid (i.e. will send another retry
  // packet)
  auto invalidDstConnId = getTestConnectionId(1);
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  testSendInitialExpectingRetry(
      srcConnId, invalidDstConnId, kClientAddr, retry.header.getToken());
}

TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidInitialOriginalDstConnId) {
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  auto retry = testSendInitialExpectingRetry(srcConnId, dstConnId, kClientAddr);

  // The token is bound to the Retry's source connection id
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  testSendInitialExpectingRetry(
      srcConnId, dstConnId, kClientAddr, retry.header.getToken());
}

TEST_F(QuicServerWorkerRetryTest, TestRetryRandomSrcConnIdOnEncodeFailure) {
  enableRateLimiterForRetry();
  auto connIdAlgo = std::make_unique<NiceMock<MockConnectionIdAlgo>>();
  ON_CALL(*connIdAlgo, encodeConnectionId(_))
      .WillByDefault(Return(
          quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, "encode failed"))));
  worker_->setConnectionIdAlgo(std::move(connIdAlgo));
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  auto retry = testSendInitialExpectingRetry(srcConnId, dstConnId, kClientAddr);
  const auto& retrySrcConnId = retry.header.getSourceConnId();
  EXPECT_NE(retrySrcConnId, dstConnId);

  expectRetriedConnectionCreation();
  testSendInitial(
      srcConnId, retrySrcConnId, kClientAddr, retry.header.getToken());
  EXPECT_EQ(getTransportState().retryOriginalDstConnId, dstConnId);
}

// Servers that reused the client's destination connection id as the Retry's
// source connection id minted tokens without the original one.
TEST_F(QuicServerWorkerRetryTest, TestRetryLegacyToken) {
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);
  auto legacyToken =
      TokenGenerator(tokenSecret_)
          .encryptToken(RetryToken(dstConnId, kClientAddr.getIPAddress(), 0));
  CHECK(legacyToken.has_value());

  expectRetriedConnectionCreation();
  testSendInitial(
      srcConnId, dstConnId, kClientAddr, legacyToken.value()->toString());
  EXPECT_EQ(getTransportState().retryOriginalDstConnId, dstConnId);
}

// Without its token's original destination connection id, a retried Initial
// would get transport parameters that QUIC v1 clients reject.
TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidTokenDropped) {
  int unfinishedHandshakeLimit = 0;
  worker_->setUnfinishedHandshakeLimit(
      [&unfinishedHandshakeLimit]() { return unfinishedHandshakeLimit; });
  auto srcConnId = getTestConnectionId(0);
  auto retry = testSendInitialExpectingRetry(
      srcConnId,
      getTestConnectionId(hostId_),
      kClientAddr,
      "",
      QuicVersion::QUIC_V1);
  unfinishedHandshakeLimit = std::numeric_limits<int>::max();
  auto token = retry.header.getToken();
  token.back() ^= 1;

  EXPECT_CALL(*quicStats_, onTokenDecryptFailure());
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(PacketDropReason(PacketDropReason::INVALID_RETRY_TOKEN)));
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  testSendInitial(
      srcConnId,
      retry.header.getSourceConnId(),
      kClientAddr,
      token,
      QuicVersion::QUIC_V1);
}

// MVFST versions don't send the connection id transport parameters.
TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidTokenMvfst) {
  int unfinishedHandshakeLimit = 0;
  worker_->setUnfinishedHandshakeLimit(
      [&unfinishedHandshakeLimit]() { return unfinishedHandshakeLimit; });
  auto srcConnId = getTestConnectionId(0);
  auto retry = testSendInitialExpectingRetry(
      srcConnId, getTestConnectionId(hostId_), kClientAddr);
  unfinishedHandshakeLimit = std::numeric_limits<int>::max();
  auto token = retry.header.getToken();
  token.back() ^= 1;

  EXPECT_CALL(*quicStats_, onTokenDecryptFailure());
  expectRetriedConnectionCreation();
  testSendInitial(
      srcConnId, retry.header.getSourceConnId(), kClientAddr, token);
}

// A token sent to a client-chosen destination connection id can be a stale
// NEW_TOKEN token, so failing to validate it doesn't stop the handshake.
TEST_F(QuicServerWorkerRetryTest, TestInvalidTokenClientChosenDstConnId) {
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure());
  expectRetriedConnectionCreation();
  testSendInitial(
      getTestConnectionId(0),
      getTestConnectionId(hostId_ + 1),
      kClientAddr,
      "invalid token",
      QuicVersion::QUIC_V1);
}

TEST_F(QuicServerWorkerRetryTest, TestNewTokenIsNotRetry) {
  EXPECT_CALL(*quicStats_, onNewTokenReceived());
  auto newToken = TokenGenerator(tokenSecret_)
                      .encryptToken(NewToken(kClientAddr.getIPAddress()));
  CHECK(newToken.has_value());
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  expectRetriedConnectionCreation();
  testSendInitial(
      srcConnId, dstConnId, kClientAddr, newToken.value()->toString());
  EXPECT_FALSE(getTransportState().retryOriginalDstConnId.has_value());
}

class QuicServerWorkerTakeoverTest : public Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
    DCHECK(sock->getEventBase());
    EXPECT_CALL(*sock, getNetworkSocket())
        .WillRepeatedly(Return(folly::NetworkSocket()));
    EXPECT_CALL(*sock, pauseRead());
    EXPECT_CALL(*sock, address()).WillRepeatedly(ReturnRef(clientAddr));
    takeoverRunState_ = makeSingleWorkerRunState(&evb_);
    takeoverWorker_ =
        std::make_unique<QuicServerWorker>(takeoverRunState_.get(), 0);
    publishSingleWorker(*takeoverRunState_, takeoverWorker_.get());
    takeoverWorker_->setSupportedVersions(supportedVersions);
    takeoverWorker_->setSocket(std::move(sock));
    takeoverSocketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    takeoverWorker_->setNewConnectionSocketFactory(
        takeoverSocketFactory_.get());
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    takeoverWorker_->setTransportFactory(factory_.get());
    auto quicStats = std::make_unique<NiceMock<MockQuicStats>>();
    takeoverWorker_->setConnectionIdAlgo(
        std::make_unique<DefaultConnectionIdAlgo>());
    takeoverWorker_->setTransportStatsCallback(std::move(quicStats));
    quicStats_ = (MockQuicStats*)takeoverWorker_->getTransportStatsCallback();

    auto takeoverSock =
        std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
    takeoverSocket_ = takeoverSock.get();
    quic::SocketAddress takeoverAddr;
    EXPECT_CALL(*takeoverSocket_, bind(_, _));
    EXPECT_CALL(*takeoverSocket_, resumeRead(_)).Times(0);
    takeoverWorker_->allowBeingTakenOver(std::move(takeoverSock), takeoverAddr);
  }

  void testPacketForwarding(BufPtr data, size_t len, ConnectionId connId);

  void testNoPacketForwarding(BufPtr data, size_t len, ConnectionId connId);

  MockQuicTransport::Ptr makeMockTransport() {
    auto mockSock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(clientAddr));
    auto qSock =
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(mockSock));
    auto transport = std::make_shared<MockQuicTransport>(
        qEvb_, std::move(qSock), &connSetupCb_, &connCb_, nullptr);
    EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb_));
    EXPECT_CALL(*transport, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(clientAddr));
    return transport;
  }

 protected:
  folly::test::MockAsyncUDPSocketT<>* takeoverSocket_;
  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  NiceMock<MockConnectionSetupCallback> connSetupCb_;
  NiceMock<MockConnectionCallback> connCb_;
  std::unique_ptr<RunState> takeoverRunState_;
  std::unique_ptr<QuicServerWorker> takeoverWorker_;
  folly::IOBufEqualTo eq;
  quic::SocketAddress clientAddr{kClientAddr};
  std::unique_ptr<MockQuicUDPSocketFactory> takeoverSocketFactory_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  MockQuicStats* quicStats_{nullptr};
  std::vector<QuicVersion> supportedVersions{QuicVersion::MVFST, MVFST1};
  uint16_t clientHostId_{25};
};

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverReInitHandler) {
  auto takeoverSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
  quic::SocketAddress takeoverAddr;
  EXPECT_CALL(*takeoverSocket_, pauseRead());

  EXPECT_CALL(*takeoverSock, bind(_, _));
  EXPECT_CALL(*takeoverSock, resumeRead(_)).Times(0);
  EXPECT_CALL(*takeoverSock, address()).WillOnce(ReturnRef(takeoverAddr));
  takeoverWorker_->overrideTakeoverHandlerAddress(
      std::move(takeoverSock), takeoverAddr);
  takeoverSocket_ = takeoverSock.get();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverNoForwarding) {
  ConnectionId connId = createConnIdForServer(ProcessId::ONE),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId, connId, len, takeoverWorker_.get());
  // enable packet forwarding
  takeoverWorker_->startPacketForwarding(kClientAddr);

  // this packet belongs to this server, so it should write unaltered packet
  // to the actual client. Also test different variations in header type Also
  // verify that the packet is not forwarded for all packet types
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Initial),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Retry),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Handshake),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::ZeroRtt),
      len,
      connId);
}

void QuicServerWorkerTakeoverTest::testNoPacketForwarding(
    BufPtr data,
    size_t len,
    ConnectionId connId) {
  auto parsedHeader = parseHeader(*data);
  ASSERT_TRUE(parsedHeader.has_value());
  auto& header = parsedHeader->parsedHeader;
  auto* longHeader = header->asLong();
  ASSERT_NE(longHeader, nullptr);
  const bool isInitial =
      longHeader->getHeaderType() == LongHeader::Types::Initial;

  MockQuicTransport::Ptr transport;
  if (isInitial) {
    // Positive delivery check: a locally-owned Initial creates a transport
    // and is delivered with the original client address and payload intact.
    transport = makeMockTransport();
    EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Return(transport));
    EXPECT_CALL(*transport, setSupportedVersions(_));
    EXPECT_CALL(*transport, setOriginalPeerAddress(clientAddr));
    EXPECT_CALL(*transport, setRoutingCallback(takeoverWorker_.get()));
    EXPECT_CALL(*transport, setConnectionIdAlgo(_));
    EXPECT_CALL(*transport, setServerConnectionIdParams(_));
    EXPECT_CALL(*transport, setTransportSettings(_));
    EXPECT_CALL(*transport, accept(_));
    EXPECT_CALL(*transport, setTransportStatsCallback(quicStats_));
    // Buffered 0-RTT for this DCID may be replayed right after the Initial.
    EXPECT_CALL(*transport, onNetworkData(_, _)).Times(testing::AnyNumber());
    EXPECT_CALL(
        *transport,
        onNetworkData(_, NetworkDataMatchesWithPeer(*data, clientAddr)))
        .Times(1);
  } else {
    EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  }
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillRepeatedly(Invoke([](folly::EventBase* evb, int) {
        return new folly::test::MockAsyncUDPSocketT<>(evb);
      }));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(0);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());

  if (transport) {
    // Drop the source-map entry so later calls stay independent.
    EXPECT_CALL(*transport, setRoutingCallback(nullptr)).Times(1);
    takeoverWorker_->onConnectionUnbound(
        transport.get(),
        std::make_pair(clientAddr, connId),
        std::vector<ConnectionIdData>{});
  }
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverForwarding) {
  // now try for packets that belongs to different server
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};

  auto pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Handshake);
  testPacketForwarding(std::move(pkt), len, connId);

  pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::ZeroRtt);
  testNoPacketForwarding(std::move(pkt), len, connId);

  // verify that the Initial packet type is not forwarded even if the
  // server-bit is different
  pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Initial);
  testNoPacketForwarding(std::move(pkt), len, connId);
}

void QuicServerWorkerTakeoverTest::testPacketForwarding(
    BufPtr data,
    size_t len,
    ConnectionId connId) {
  data->coalesce();
  auto writeSock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_, _));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress& /* unused */,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        writtenData->coalesce();
        // the writtenData contains actual client address + time of ack + data
        EXPECT_FALSE(eq(*data, *writtenData));
        // extract and verify the encoded client address
        folly::io::Cursor cursor(writtenData.get());
        uint32_t protocotVersion = (cursor.readBE<uint32_t>());
        EXPECT_EQ(protocotVersion, 0x0000001);
        uint16_t addrLen = (cursor.readBE<uint16_t>());
        struct sockaddr* sockaddr = nullptr;
        auto addrData = cursor.peek();
        EXPECT_GE(addrData.size(), addrLen);
        sockaddr = (struct sockaddr*)addrData.data();
        cursor.skip(addrLen);

        quic::SocketAddress actualClient;
        actualClient.setFromSockaddr(sockaddr, addrLen);
        EXPECT_EQ(actualClient.getIPAddress(), clientAddr.getIPAddress());
        EXPECT_EQ(actualClient.getPort(), clientAddr.getPort());
        auto pktReceiveEpoch = cursor.readBE<uint64_t>();

        // the encoded time should be strictly less than 'now'
        EXPECT_LT(pktReceiveEpoch, Clock::now().time_since_epoch().count());

        // skip to the start of the packet
        writtenData->trimStart(
            sizeof(uint32_t) + sizeof(uint16_t) + addrLen + sizeof(uint64_t));
        EXPECT_TRUE(eq(*data, *writtenData));
        // parse header and check connId to verify the integrity of the packet
        auto parsedHeader = parseHeader(*writtenData);
        auto& header = parsedHeader->parsedHeader;
        LongHeader* longHeader = header->asLong();
        if (longHeader) {
          EXPECT_EQ(connId, longHeader->getDestinationConnId());
        } else {
          EXPECT_EQ(connId, header->asShort()->getConnectionId());
        }
        return data->computeChainDataLength();
      }));
  takeoverWorker_->startPacketForwarding(kClientAddr);

  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(1);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
  takeoverWorker_->stopPacketForwarding();
  // release this resource since MockQuicUDPSocketFactory::_make() hands its
  // ownership to it's caller (i.e. QuicServerWorker)
  writeSock.release();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverProcessForwardedPkt) {
  // packet belongs to different server
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Handshake);
  takeoverWorker_->startPacketForwarding(kClientAddr);

  // the packet will be forwarded
  auto writeSock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_, _));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress& client,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        // the writtenData contains actual client address + time of ack + data
        EXPECT_FALSE(eq(*data, *writtenData));

        // flip the server id to 'own' the packet (else it'll keep forwarding)
        takeoverWorker_->setProcessId(ProcessId::ZERO);

        // now invoke the Takeover Handler callback
        FollyAsyncUDPSocketAlias::ReadCallback* takeoverCb =
            takeoverWorker_->getTakeoverHandlerCallback();
        uint8_t* workerBuf = nullptr;
        size_t workerBufLen = 0;
        takeoverCb->getReadBuffer((void**)&workerBuf, &workerBufLen);
        writtenData->coalesce();
        size_t bufLen =
            std::min(workerBufLen, writtenData->computeChainDataLength());
        memcpy(workerBuf, writtenData->buffer(), bufLen);

        // The forwarded packet must reach the owning transport with the
        // decoded original client address and payload intact. Use a
        // takeover-peer (outer) sender address distinct from both the
        // encapsulated client address and the forwarding destination so
        // that an implementation using the outer sender would fail.
        const quic::SocketAddress takeoverPeerAddr(
            folly::IPAddress("9.9.9.9"), 9999);
        EXPECT_NE(takeoverPeerAddr, clientAddr);
        EXPECT_NE(takeoverPeerAddr, client);
        auto transport = makeMockTransport();
        takeoverWorker_->onConnectionIdAvailable(transport, connId);
        EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
        EXPECT_CALL(
            *transport,
            onNetworkData(_, NetworkDataMatchesWithPeer(*data, clientAddr)))
            .Times(1);

        takeoverCb->onDataAvailable(
            takeoverPeerAddr, bufLen, false, OnDataAvailableParams());
        return bufLen;
      }));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(1);
  EXPECT_CALL(*quicStats_, onForwardedPacketReceived()).Times(1);
  EXPECT_CALL(*quicStats_, onForwardedPacketProcessed()).Times(1);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
  // release this resource since MockQuicUDPSocketFactory::_make() hands its
  // ownership to it's caller (i.e. QuicServerWorker)
  writeSock.release();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadClose) {
  FollyAsyncUDPSocketAlias::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  takeoverCb->onReadClosed();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadError) {
  FollyAsyncUDPSocketAlias::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  EXPECT_CALL(*takeoverSocket_, pauseRead());
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::AsyncSocketExceptionType::UNKNOWN, "");
  takeoverCb->onReadError(ex);
  evb_.loopIgnoreKeepAlive();
}

class QuicServerTest : public Test {
 public:
  void SetUp() override {
    transportSettings_.advertisedInitialConnectionFlowControlWindow =
        kDefaultConnectionFlowControlWindow * 2;
    transportSettings_.advertisedInitialBidiLocalStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    transportSettings_.advertisedInitialBidiRemoteStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    transportSettings_.advertisedInitialUniStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    transportSettings_.statelessResetTokenSecret = getRandSecret();

    createAndConfigureServer();
  }

  // Recreates factory_ and server_ from the current transportSettings_.
  // initializeServer() may recreate server_ with a stats factory.
  void createAndConfigureServer() {
    shutdownServer();
    threaded_.reset();
    ownedFactory_ = std::make_unique<MockQuicServerTransportFactory>();
    factory_ = ownedFactory_.get();
    serverCtx_ = quic::test::createServerCtx();
    server_ = QuicServer::createQuicServer(buildOptions());
  }

  ServerOptions buildOptions(
      std::unique_ptr<QuicTransportStatsCallbackFactory> statsFactory =
          nullptr) {
    ServerOptions options;
    options.transportSettings = transportSettings_;
    options.hostId = serverHostId_;
    options.cidVersion = quic::ConnectionIdVersion::V2;
    options.connIdAlgoFactory =
        std::make_unique<DefaultConnectionIdAlgoFactory>();
    if (!healthCheckToken_.empty()) {
      options.healthCheckToken = healthCheckToken_;
    }
    if (rejectNewConnections_) {
      options.rejectNewConnections = rejectNewConnections_;
    }
    if (isBlockListedSrcPort_) {
      options.isBlockListedSrcPort = isBlockListedSrcPort_;
    }
    options.transportStatsFactory = std::move(statsFactory);
    return options;
  }

  void startOwned(const quic::SocketAddress& addr, size_t numWorkers) {
    threaded_ = std::make_unique<ThreadedQuicServer>(
        buildOptions(), std::move(ownedFactory_));
    threaded_->start(addr, numWorkers);
  }

  quic::SocketAddress serverAddress() const {
    return threaded_ ? threaded_->getAddress() : server_->getAddress();
  }

  std::vector<folly::EventBase*> workerEvbs() const {
    return threaded_ ? threaded_->getWorkerEvbs() : boundEvbs_;
  }

  void shutdownServer() {
    if (threaded_) {
      threaded_->shutdown();
    }
    if (server_) {
      server_->shutdown();
      server_.reset();
    }
  }

  void TearDown() override {
    shutdownServer();
    threaded_.reset();
  }

  QuicServerWorker* workerForEvb(folly::EventBase* evb) {
    return server_->findWorkerForEvb(evb);
  }

  void setUpTransportFactoryForWorkers(std::vector<folly::EventBase*> evbs) {
    for (auto ev : evbs) {
      server_->addTransportFactory(ev, factory_);
    }
  }

  quic::SocketAddress initializeServer(
      std::vector<folly::EventBase*> evbs,
      MockQuicStats* stats = nullptr) {
    quic::SocketAddress addr("::1", 0);
    // test that the transportStatsFactory works as expected

    auto transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    transportStatsFactory_ = transportStatsFactory.get();

    if (stats) {
      CHECK_EQ(evbs.size(), 1);
      EXPECT_CALL(*transportStatsFactory_, make())
          .WillRepeatedly(Invoke(
              [stats]() { return std::unique_ptr<MockQuicStats>(stats); }));
    } else {
      EXPECT_CALL(*transportStatsFactory_, make()).WillRepeatedly(Invoke([&]() {
        auto mockInfoCb = std::make_unique<NiceMock<MockQuicStats>>();
        return mockInfoCb;
      }));
    }
    if (evbs.empty()) {
      threaded_ = std::make_unique<ThreadedQuicServer>(
          buildOptions(std::move(transportStatsFactory)),
          std::move(ownedFactory_));
      threaded_->start(addr, 2);
    } else {
      server_ = QuicServer::createQuicServer(
          buildOptions(std::move(transportStatsFactory)));
      boundEvbs_ = evbs;
      server_->bind(addr, evbs);
      setUpTransportFactoryForWorkers(evbs);
      server_->start();
    }

    return serverAddress();
  }

  std::shared_ptr<MockQuicTransport> createNewTransport(
      folly::EventBase* eventBase,
      FollyAsyncUDPSocketAlias& client,
      quic::SocketAddress serverAddr) {
    // create payload
    StreamId id = 1;
    auto clientConnId = getTestConnectionId(clientHostId_);
    auto serverConnId =
        getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
    auto buf = createData(kMinInitialPacketSize);
    auto packet = createInitialStream(
        clientConnId, serverConnId, id, *buf, QuicVersion::MVFST);
    auto data = std::move(packet);
    std::mutex m;
    std::condition_variable cv;
    bool calledOnNetworkData = false;

    // create mock transport
    std::shared_ptr<MockQuicTransport> transport;
    eventBase->runInEventBaseThreadAndWait([&] {
      NiceMock<MockConnectionSetupCallback> connSetupcb;
      NiceMock<MockConnectionCallback> connCb;
      std::unique_ptr<folly::test::MockAsyncUDPSocketT<>> mockSock =
          std::make_unique<folly::test::MockAsyncUDPSocketT<>>(eventBase);
      EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(serverAddr));

      auto qEvb = std::make_shared<FollyQuicEventBase>(eventBase);
      auto qSock =
          std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(mockSock));
      transport = std::make_shared<MockQuicTransport>(
          qEvb,
          std::move(qSock),
          &connSetupcb,
          &connCb,
          quic::test::createServerCtx());
    });

    auto makeTransport = [&](folly::EventBase* evb,
                             std::unique_ptr<
                                 FollyAsyncUDPSocketAlias>& /* socket */,
                             const quic::SocketAddress&) noexcept {
      // set proper expectations for the transport after its creation
      auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
      EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb));
      EXPECT_CALL(*transport, setTransportStatsCallback(_))
          .WillOnce(Invoke([&](QuicTransportStatsCallback* statsCallback) {
            CHECK(statsCallback);
          }));
      EXPECT_CALL(*transport, setTransportSettings(_))
          .WillRepeatedly(Invoke([&](auto transportSettings) {
            EXPECT_EQ(
                transportSettings_
                    .advertisedInitialBidiLocalStreamFlowControlWindow,
                transportSettings
                    .advertisedInitialBidiLocalStreamFlowControlWindow);
            EXPECT_EQ(
                transportSettings_
                    .advertisedInitialBidiRemoteStreamFlowControlWindow,
                transportSettings
                    .advertisedInitialBidiRemoteStreamFlowControlWindow);
            EXPECT_EQ(
                transportSettings_.advertisedInitialUniStreamFlowControlWindow,
                transportSettings.advertisedInitialUniStreamFlowControlWindow);
            EXPECT_EQ(
                transportSettings_.advertisedInitialConnectionFlowControlWindow,
                transportSettings.advertisedInitialConnectionFlowControlWindow);
          }));
      ON_CALL(*transport, onNetworkData(_, _))
          .WillByDefault(Invoke(
              [&, expected = std::shared_ptr<folly::IOBuf>(data->clone())](
                  auto, const auto& networkData) mutable {
                EXPECT_GT(networkData.getPackets().size(), 0);
                EXPECT_TRUE(
                    folly::IOBufEqualTo()(
                        *networkData.getPackets()[0].buf.front(), *expected));
                std::unique_lock<std::mutex> lg(m);
                calledOnNetworkData = true;
                cv.notify_one();
              }));
      return transport;
    };
    EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Invoke(makeTransport));
    // send packets to the server
    std::unique_lock<std::mutex> lg(m);
    size_t tries = 0;
    if (!calledOnNetworkData && tries < 3) {
      tries++;
      size_t ret = 0;
      evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] { //
        ret = client.write(serverAddr, data->clone());
      });
      CHECK_EQ(ret, data->computeChainDataLength());
      cv.wait_until(lg, std::chrono::system_clock::now() + 1s, [&] {
        return calledOnNetworkData;
      });
    }
    CHECK(calledOnNetworkData);
    return transport;
  }

  std::unique_ptr<FollyAsyncUDPSocketAlias> makeUdpClient() {
    quic::SocketAddress addr2("::1", 0);
    std::unique_ptr<FollyAsyncUDPSocketAlias> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<FollyAsyncUDPSocketAlias>(evbThread_.getEventBase());
      client->bind(addr2);
    });
    return client;
  }

  void closeUdpClient(std::unique_ptr<FollyAsyncUDPSocketAlias> client) {
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { std::exchange(client, {})->close(); });
  }

  void runTest(std::vector<folly::EventBase*> evbs) {
    auto serverAddr = initializeServer(evbs);
    auto client = makeUdpClient();
    folly::EventBase* evb = workerEvbs().back();
    auto transport = createNewTransport(evb, *client, serverAddr);
    EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));
    EXPECT_CALL(*transport, setRoutingCallback(nullptr));
    EXPECT_CALL(*transport, closeNow(_));
    shutdownServer();
    closeUdpClient(std::move(client));
    // cleanup transport
    transport->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transport.reset(); });
  }

  void testReset(BufPtr packet);

 protected:
  folly::ScopedEventBaseThread evbThread_;
  std::shared_ptr<QuicServer> server_;
  std::unique_ptr<ThreadedQuicServer> threaded_;
  std::unique_ptr<MockQuicServerTransportFactory> ownedFactory_;
  std::shared_ptr<const fizz::server::FizzServerContext> serverCtx_;
  std::vector<folly::EventBase*> boundEvbs_;
  std::string healthCheckToken_;
  std::function<bool(const quic::SocketAddress&)> rejectNewConnections_;
  std::function<bool(uint16_t)> isBlockListedSrcPort_;
  MockQuicServerTransportFactory* factory_;
  TransportSettings transportSettings_;
  MockQuicStatsFactory* transportStatsFactory_;
  uint32_t clientHostId_{0}, serverHostId_{0xAABBCC};
}; // namespace test

TEST_F(QuicServerTest, NetworkTest) {
  runTest(std::vector<folly::EventBase*>());
}

// runTest with shouldUseWrapperRecvmmsgForBatchRecv = true.
TEST_F(QuicServerTest, NetworkTestWithWrapperRecvmmsg) {
  transportSettings_.shouldUseWrapperRecvmmsgForBatchRecv = true;
  createAndConfigureServer();
  runTest(std::vector<folly::EventBase*>());
}

TEST_F(QuicServerTest, OtherEvbs) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};
  runTest(evbs);
}

TEST_F(QuicServerTest, AddAcceptObserverAttachesOnWorkerEventBaseThread) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  initializeServer({evb});
  ThreadCheckingAcceptObserver observer(evb);

  EXPECT_TRUE(server_->addAcceptObserver(evb, &observer));
  EXPECT_TRUE(observer.attachRanOnExpectedEvb);
  EXPECT_TRUE(server_->removeAcceptObserver(evb, &observer));
  shutdownServer();
}

TEST_F(QuicServerTest, DontRouteDataAfterShutdown) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  auto* stats = new MockQuicStats();
  auto serverAddr = initializeServer(evbs, stats);
  auto client = makeUdpClient();
  auto transport =
      createNewTransport(evbThread.getEventBase(), *client, serverAddr);
  EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));

  EXPECT_CALL(*transport, closeNow(_)).WillOnce(InvokeWithoutArgs([&] {
    PacketNum packetNum = 1;
    QuicVersion version = QuicVersion::MVFST;
    ConnectionId connId = getTestConnectionId();
    LongHeader header(
        LongHeader::Types::Initial,
        getTestConnectionId(1),
        connId,
        packetNum,
        version);
    // Simulate receiving a packet before the worker shutdown.

    EXPECT_CALL(
        *stats,
        onPacketDropped(PacketDropReason(PacketDropReason::SERVER_SHUTDOWN)));
    NetworkData networkData(folly::IOBuf::copyBuffer("wat"), Clock::now(), 0);
    RoutingData routingData(
        HeaderForm::Long,
        true,
        false,
        header.getDestinationConnId(),
        header.getSourceConnId());
    workerForEvb(evbThread.getEventBase())
        ->routeOrDispatch(
            kClientAddr,
            std::move(routingData),
            std::move(networkData),
            version,
            /*isForwardedData=*/false);
  }));
  std::thread t([&] { shutdownServer(); });
  t.join();
  closeUdpClient(std::move(client));
  // cleanup transport
  transport->getEventBase()->runInEventBaseThreadAndWait(
      [&] { transport.reset(); });
}

TEST_F(QuicServerTest, RouteDataFromDifferentThread) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  auto* stats = new MockQuicStats();
  auto serverAddr = initializeServer(evbs, stats);
  auto client = makeUdpClient();
  auto transport =
      createNewTransport(evbThread.getEventBase(), *client, serverAddr);
  EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));
  EXPECT_CALL(
      *stats,
      onPacketDropped(PacketDropReason(PacketDropReason::SERVER_SHUTDOWN)))
      .Times(0);
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  PacketNum packetNum = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial,
      clientConnId,
      serverConnId,
      packetNum,
      version);
  auto initialData = std::shared_ptr<folly::IOBuf>(
      folly::IOBuf::create(kMinInitialPacketSize));
  initialData->append(kMinInitialPacketSize);
  memset(initialData->writableData(), 'd', kMinInitialPacketSize);
  NetworkData networkData(initialData->clone(), Clock::now(), 0);
  RoutingData routingData(
      HeaderForm::Long,
      true,
      false,
      header.getDestinationConnId(),
      header.getSourceConnId());

  EXPECT_CALL(*transport, onNetworkData(_, _))
      .WillOnce(Invoke([&](auto, const auto& networkData) {
        EXPECT_GT(networkData.getPackets().size(), 0);
        EXPECT_TRUE(
            folly::IOBufEqualTo()(
                *networkData.getPackets()[0].buf.front(), *initialData));
      }));

  evbThread.getEventBase()->runInEventBaseThreadAndWait([&] {
    workerForEvb(evbThread.getEventBase())
        ->routeOrDispatch(
            client->address(),
            std::move(routingData),
            std::move(networkData),
            version,
            /*isForwardedData=*/false);
  });

  // cleanup transport
  transport->getEventBase()->runInEventBaseThreadAndWait(
      [&] { transport.reset(); });
  closeUdpClient(std::move(client));
  std::thread t([&] { shutdownServer(); });
  t.join();
}

class QuicServerMultiWorkerRoutingTest : public QuicServerTest {
 protected:
  void runMultiWorkerRoutingTest(
      uint32_t encodedHostId,
      uint8_t encodedWorkerId,
      folly::EventBase* injectFromEvb,
      folly::EventBase* expectedFactoryEvb) {
    folly::Baton<> baton;
    folly::EventBase* factoryEvb = nullptr;
    auto shutdownGuard = folly::makeGuard([&] {
      std::thread shutdownThread([&] { shutdownServer(); });
      shutdownThread.join();
    });

    DefaultConnectionIdAlgo algo;
    auto dcid =
        algo
            .encodeConnectionId(ServerConnectionIdParams(
                ConnectionIdVersion::V2, encodedHostId, 0, encodedWorkerId))
            .value();
    ASSERT_TRUE(algo.canParse(dcid));

    auto srcConnId =
        ConnectionId::createAndMaybeCrash({1, 2, 3, 4, 5, 6, 7, 8});
    auto data = createData(kMinInitialPacketSize + 10);

    EXPECT_CALL(*factory_, _make(_, _, _))
        .WillOnce(
            Invoke([&](folly::EventBase* evb,
                       std::unique_ptr<FollyAsyncUDPSocketAlias>& /*sock*/,
                       const folly::SocketAddress& /*addr*/) {
              factoryEvb = evb;
              baton.post();
              return nullptr;
            }));

    injectFromEvb->runInEventBaseThreadAndWait([&] {
      RoutingData routingData(HeaderForm::Long, true, false, dcid, srcConnId);
      workerForEvb(injectFromEvb)
          ->routeOrDispatch(
              kClientAddr,
              std::move(routingData),
              NetworkData(data->clone(), Clock::now(), 0),
              QuicVersion::MVFST,
              /*isForwardedData=*/false);
    });

    ASSERT_TRUE(baton.try_wait_for(std::chrono::seconds(5)));
    EXPECT_EQ(factoryEvb, expectedFactoryEvb);
  }
};

// Bug repro: server-issued DCID (matches our hostId) routed via
// connIdAlgo to the owning worker, not the kernel-routed worker.
// numWorkers=2 and encodedWorkerId=1: getWorkerToRouteTo gives 1 % 2 = 1
// (worker B); injecting from worker A's thread means workerPtr_ would
// have chosen A. The test fails iff routing collapses to workerPtr_.
TEST_F(
    QuicServerMultiWorkerRoutingTest,
    ServerChosenInitialRoutedToOwningWorker) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  std::vector<folly::EventBase*> evbs{
      evbThreadA.getEventBase(), evbThreadB.getEventBase()};
  initializeServer(evbs);

  runMultiWorkerRoutingTest(
      /*encodedHostId=*/serverHostId_,
      /*encodedWorkerId=*/1,
      /*injectFromEvb=*/evbThreadA.getEventBase(),
      /*expectedFactoryEvb=*/evbThreadB.getEventBase());
}

// DCID whose encoded hostId is not ours stays on the kernel-routed
// worker, avoiding a cross-thread hop on every new connection.
TEST_F(
    QuicServerMultiWorkerRoutingTest,
    RandomInitialStaysOnKernelRoutedWorker) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  std::vector<folly::EventBase*> evbs{
      evbThreadA.getEventBase(), evbThreadB.getEventBase()};
  initializeServer(evbs);

  runMultiWorkerRoutingTest(
      /*encodedHostId=*/serverHostId_ ^ 0xDEAD,
      /*encodedWorkerId=*/1,
      /*injectFromEvb=*/evbThreadA.getEventBase(),
      /*expectedFactoryEvb=*/evbThreadA.getEventBase());
}

// After a host-id rotation, a retransmitted Initial bearing the previous
// host id is still server-issued and steers to the CID-owning worker.
TEST_F(
    QuicServerMultiWorkerRoutingTest,
    PrevHostIdInitialRoutedToOwningWorker) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  std::vector<folly::EventBase*> evbs{
      evbThreadA.getEventBase(), evbThreadB.getEventBase()};
  initializeServer(evbs);

  const uint32_t prevHostId = serverHostId_;
  server_->setHostId(prevHostId + 1);

  runMultiWorkerRoutingTest(
      /*encodedHostId=*/prevHostId,
      /*encodedWorkerId=*/1,
      /*injectFromEvb=*/evbThreadA.getEventBase(),
      /*expectedFactoryEvb=*/evbThreadB.getEventBase());
}

TEST_F(QuicServerMultiWorkerRoutingTest, AllWorkerIdsInUseRouteToOwningWorker) {
  constexpr size_t kNumWorkers = 256;
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> threads;
  std::vector<folly::EventBase*> evbs;
  for (size_t i = 0; i < kNumWorkers; ++i) {
    threads.push_back(std::make_unique<folly::ScopedEventBaseThread>());
    evbs.push_back(threads.back()->getEventBase());
  }
  initializeServer(evbs);

  const auto fds = server_->getAllListeningSocketFDs();
  const std::set<int> distinctFds(fds.begin(), fds.end());
  EXPECT_EQ(distinctFds.size(), kNumWorkers);
  EXPECT_EQ(distinctFds.count(-1), 0);

  runMultiWorkerRoutingTest(
      /*encodedHostId=*/serverHostId_,
      /*encodedWorkerId=*/kNumWorkers - 1,
      /*injectFromEvb=*/evbs.front(),
      /*expectedFactoryEvb=*/evbs.back());
}

TEST_F(QuicServerTest, OverrideTakeoverAddressTest) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  auto serverAddr = initializeServer(evbs);
  quic::SocketAddress takeoverAddr("::1", 0);
  server_->allowBeingTakenOver(takeoverAddr);
  uint8_t bindAttempt = 0;
  quic::SocketAddress boundAddr;
  while (bindAttempt < 5) {
    boundAddr = server_->overrideTakeoverHandlerAddress(takeoverAddr);
    bindAttempt++;
  }
  EXPECT_TRUE(boundAddr.isInitialized());
  std::thread t([&] { shutdownServer(); });
  t.join();
}

class QuicServerTakeoverTest : public Test {
 public:
  void SetUp() override {
    transportSettings_.advertisedInitialConnectionFlowControlWindow =
        kDefaultConnectionFlowControlWindow * 2;
    transportSettings_.advertisedInitialBidiLocalStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    transportSettings_.advertisedInitialBidiRemoteStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    transportSettings_.advertisedInitialUniStreamFlowControlWindow =
        kDefaultStreamFlowControlWindow * 2;
    setUpServer(oldServer_, ProcessId::ZERO);
    setUpServer(newServer_, ProcessId::ONE);
  }

  void setUpServer(std::shared_ptr<QuicServer>& /*server*/, ProcessId id) {
    // Construction is deferred to startServer() so the stats factory staged
    // in runTest() can move into ServerOptions.
    auto factory = std::make_unique<MockQuicServerTransportFactory>();
    if (id == ProcessId::ZERO) {
      oldFactory_ = factory.get();
      oldOwnedFactory_ = std::move(factory);
    } else {
      newFactory_ = factory.get();
      newOwnedFactory_ = std::move(factory);
    }
    serverCtx_ = quic::test::createServerCtx();
  }

  std::shared_ptr<QuicServer> startServer(
      ProcessId id,
      std::unique_ptr<QuicTransportStatsCallbackFactory> statsFactory,
      const quic::SocketAddress& addr,
      const std::vector<folly::EventBase*>& evbs,
      MockQuicServerTransportFactory* factory,
      const std::vector<int>& inheritedFds = {}) {
    ServerOptions options;
    options.transportSettings = transportSettings_;
    options.processId = id;
    options.transportStatsFactory = std::move(statsFactory);
    auto server = QuicServer::createQuicServer(std::move(options));
    server->bind(addr, evbs, inheritedFds);
    for (auto ev : evbs) {
      server->addTransportFactory(ev, factory);
    }
    server->start();
    return server;
  }

  std::shared_ptr<MockQuicTransport> initTransport(
      MockQuicServerTransportFactory* factory,
      ConnectionId& clientConnId,
      BufPtr& data,
      folly::Baton<>& baton) {
    std::shared_ptr<MockQuicTransport> transport;
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    auto makeTransport = [&](folly::EventBase* eventBase,
                             std::unique_ptr<FollyAsyncUDPSocketAlias>& socket,
                             const quic::SocketAddress&) noexcept {
      auto qEvb = std::make_shared<FollyQuicEventBase>(eventBase);
      auto qSock =
          std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(socket));
      transport = std::make_shared<MockQuicTransport>(
          qEvb, std::move(qSock), &connSetupCb, &connCb, serverCtx_);
      transport->setClientConnectionId(clientConnId);
      // setup expectations
      EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb));
      EXPECT_CALL(*transport, setTransportSettings(_));
      EXPECT_CALL(*transport, accept(_));
      EXPECT_CALL(*transport, setSupportedVersions(_));
      EXPECT_CALL(*transport, setRoutingCallback(_));
      EXPECT_CALL(*transport, setOriginalPeerAddress(_));
      EXPECT_CALL(*transport, setTransportStatsCallback(_));
      EXPECT_CALL(*transport, setServerConnectionIdParams(_))
          .WillOnce(Invoke([&](ServerConnectionIdParams params) {
            EXPECT_EQ(params.processId, 0);
            EXPECT_EQ(params.workerId, 0);
          }));
      EXPECT_CALL(*transport, onNetworkData(_, _))
          .WillOnce(
              Invoke([&, expected = data.get()](auto, const auto& networkData) {
                EXPECT_GT(networkData.getPackets().size(), 0);
                EXPECT_TRUE(
                    folly::IOBufEqualTo()(
                        *networkData.getPackets()[0].buf.front(), *expected));
                baton.post();
              }));
      return transport;
    };
    EXPECT_CALL(*factory, _make(_, _, _)).WillOnce(Invoke(makeTransport));
    return transport;
  }

  void runTest(
      std::vector<folly::EventBase*> evbs1,
      std::vector<folly::EventBase*> evbs2) {
    folly::Baton<> b;
    ConnectionId clientConnId = getTestConnectionId(clientHostId_);
    // create a packet to send to the old server and verify that it accepts it
    StreamId id = 1;
    auto buf = createData(kMinInitialPacketSize);
    ConnectionId connId = createConnIdForServer(ProcessId::ZERO);
    auto packet =
        createInitialStream(clientConnId, connId, id, *buf, QuicVersion::MVFST);
    auto data = std::move(packet);
    auto transportCbForOldServer =
        initTransport(oldFactory_, clientConnId, data, b);
    quic::SocketAddress addr("::1", 0);
    // setup mock transport stats factory
    auto transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    auto makeCbForOldServer = [&]() {
      oldTransInfoCb_ = new NiceMock<MockQuicStats>();
      std::unique_ptr<MockQuicStats> quicStats;
      quicStats.reset(oldTransInfoCb_);
      return quicStats;
    };
    EXPECT_CALL(*transportStatsFactory, make())
        .WillOnce(Invoke(makeCbForOldServer));
    oldServer_ = startServer(
        ProcessId::ZERO,
        std::move(transportStatsFactory),
        addr,
        evbs1,
        oldFactory_);
    auto serverAddr = oldServer_->getAddress();
    quic::SocketAddress takeoverAddr("::1", 0);
    oldServer_->allowBeingTakenOver(takeoverAddr);

    quic::SocketAddress clientAddr("::1", 0);
    std::unique_ptr<FollyAsyncUDPSocketAlias> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<FollyAsyncUDPSocketAlias>(evbThread_.getEventBase());
      client->bind(clientAddr);
    });
    // send packet to the server and wait
    EXPECT_CALL(*oldTransInfoCb_, onPacketReceived());
    EXPECT_CALL(*oldTransInfoCb_, onRead(_));
    client->write(serverAddr, data->clone());
    b.wait();

    // spin another server and verify that the old server gets the packet
    // that is routed to the new server
    int takeoverListeningFd = oldServer_->getTakeoverHandlerSocketFD();
    auto inheritedFds = oldServer_->getAllListeningSocketFDs();
    quic::SocketAddress newAddr("::1", 0);
    // setup mock transport stats factory
    transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    auto makeCbForNewServer = [&]() {
      newTransInfoCb_ = new NiceMock<MockQuicStats>();
      std::unique_ptr<MockQuicStats> quicStats;
      quicStats.reset(newTransInfoCb_);
      return quicStats;
    };
    EXPECT_CALL(*transportStatsFactory, make())
        .WillOnce(Invoke(makeCbForNewServer));
    newServer_ = startServer(
        ProcessId::ONE,
        std::move(transportStatsFactory),
        newAddr,
        evbs2,
        newFactory_,
        inheritedFds);
    quic::SocketAddress destAddr;
    destAddr.setFromLocalAddress(
        folly::NetworkSocket::fromFd(takeoverListeningFd));
    newServer_->startPacketForwarding(destAddr);
    auto newServerAddr = newServer_->getAddress();
    CHECK(newServerAddr != destAddr);

    packet = createInitialStream(
        clientConnId,
        connId,
        id,
        *buf,
        QuicVersion::MVFST,
        LongHeader::Types::Retry);
    data = std::move(packet);

    folly::Baton<> b1;
    // onNetworkData(_, _) shouldn't be called on the newServer_ transport,
    // but should be routed to oldServer_
    EXPECT_CALL(*transportCbForOldServer, onNetworkData(_, _))
        .WillOnce(
            Invoke([&, expected = data.get()](auto, const auto& networkData) {
              EXPECT_GT(networkData.getPackets().size(), 0);
              EXPECT_TRUE(
                  folly::IOBufEqualTo()(
                      *networkData.getPackets()[0].buf.front(), *expected));
              b1.post();
            }));
    // new quic server receives the packet and forwards it
    EXPECT_CALL(*newTransInfoCb_, onPacketReceived());
    EXPECT_CALL(*newTransInfoCb_, onRead(_));
    EXPECT_CALL(*newTransInfoCb_, onPacketForwarded());
    EXPECT_CALL(*newTransInfoCb_, onPacketProcessed()).Times(0);
    // verify takeover related counters on the old quic server
    EXPECT_CALL(*oldTransInfoCb_, onForwardedPacketReceived());
    EXPECT_CALL(*oldTransInfoCb_, onForwardedPacketProcessed());
    // the old server should then handle it as usual
    EXPECT_CALL(*oldTransInfoCb_, onPacketDropped(_)).Times(0);

    // pause the old server so that we can deterministically route to the new
    // server
    oldServer_->pauseRead();
    client->write(newServerAddr, data->clone());
    b1.wait();
    b1.reset();

    EXPECT_CALL(*transportCbForOldServer, setRoutingCallback(nullptr));
    EXPECT_CALL(*transportCbForOldServer, closeNow(_));

    // Disable packet forwarding on the new server and send packet
    // This packet should be dropped since it's not an initial packet
    newServer_->stopPacketForwarding(0ms);
    // Add synchronization barrier to ensure stopPacketForwarding completes
    // before sending test packets.
    for (auto* evb : evbs2) {
      evb->runInEventBaseThreadAndWait([]() {
        // Barrier ensures all pending async operations complete
      });
    }
    std::atomic<bool> posted{false};
    EXPECT_CALL(*newTransInfoCb_, onPacketReceived())
        .WillRepeatedly(Invoke([&] {
          if (posted) {
            return;
          }
          posted = true;
          b1.post();
        }));
    EXPECT_CALL(*newTransInfoCb_, onRead(_)).Times(AtLeast(1));
    EXPECT_CALL(*newTransInfoCb_, onPacketForwarded()).Times(0);
    EXPECT_CALL(*newTransInfoCb_, onPacketDropped(_)).Times(AtLeast(1));
    client->write(newServerAddr, data->clone());
    client->write(newServerAddr, data->clone());

    b1.wait();

    EXPECT_CALL(*transportCbForOldServer, setTransportStatsCallback(nullptr));
    oldServer_->shutdown();
    // 'transport' never gets created for the newServer_
    // so no callback on closeNow()
    newServer_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { client->close(); });
    // cleanup transport
    transportCbForOldServer->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transportCbForOldServer.reset(); });
  }

 protected:
  folly::ScopedEventBaseThread evbThread_;
  std::shared_ptr<QuicServer> oldServer_;
  std::shared_ptr<QuicServer> newServer_;
  std::unique_ptr<MockQuicServerTransportFactory> oldOwnedFactory_;
  std::unique_ptr<MockQuicServerTransportFactory> newOwnedFactory_;
  std::shared_ptr<const fizz::server::FizzServerContext> serverCtx_;
  MockQuicServerTransportFactory* oldFactory_;
  MockQuicServerTransportFactory* newFactory_;
  MockQuicStats* oldTransInfoCb_;
  MockQuicStats* newTransInfoCb_;
  TransportSettings transportSettings_;
  MockQuicStatsFactory* transportStatsFactory_;
  uint16_t clientHostId_{25};
};

TEST_F(QuicServerTakeoverTest, TakeoverTest) {
  folly::ScopedEventBaseThread evbThread1;
  auto evb1 = evbThread1.getEventBase();
  std::vector<folly::EventBase*> evbs1{evb1};
  folly::ScopedEventBaseThread evbThread2;
  auto evb2 = evbThread2.getEventBase();
  std::vector<folly::EventBase*> evbs2{evb2};
  runTest(evbs1, evbs2);
}

struct UDPReader : public FollyAsyncUDPSocketAlias::ReadCallback {
  UDPReader() {
    bufPromise_ =
        std::make_unique<folly::Promise<std::unique_ptr<folly::IOBuf>>>();
  }

  ~UDPReader() override = default;

  void start(EventBase* evb, SocketAddress addr) {
    evb_ = evb;
    evb_->runInEventBaseThreadAndWait([&] {
      client = std::make_unique<FollyAsyncUDPSocketAlias>(evb_);
      client->bind(addr);
      client->resumeRead(this);
    });
  }

  AsyncUDPSocket& getSocket() {
    return *client;
  }

  void getReadBuffer(void** buf, size_t* len) noexcept override {
    if (!buf_) {
      buf_ = IOBuf::create(kDefaultUDPReadBufferSize);
    }
    *buf = buf_->writableData();
    *len = kDefaultUDPReadBufferSize;
  }

  void onDataAvailable(
      const quic::SocketAddress&,
      size_t len,
      bool truncated,
      OnDataAvailableParams /*params*/) noexcept override {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (truncated) {
      bufPromise_->setException(std::runtime_error("truncated buf"));
      return;
    }
    if (bufPromise_) {
      buf_->append(len);
      bufPromise_->setValue(std::move(buf_));
    }
  }

  void onReadError(const AsyncSocketException& ex) noexcept override {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (bufPromise_) {
      bufPromise_->setException(ex);
    }
  }

  void onReadClosed() noexcept override {
    if (bufPromise_) {
      bufPromise_->setException(std::runtime_error("closed"));
    }
  }

  folly::Future<std::unique_ptr<folly::IOBuf>> readOne() {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (!bufPromise_) {
      bufPromise_ =
          std::make_unique<folly::Promise<std::unique_ptr<folly::IOBuf>>>();
    }
    return bufPromise_->getFuture().ensure([&]() { bufPromise_ = nullptr; });
  }

 private:
  std::unique_ptr<folly::IOBuf> buf_;
  std::mutex bufLock_;
  std::unique_ptr<folly::Promise<std::unique_ptr<folly::IOBuf>>> bufPromise_;
  std::unique_ptr<FollyAsyncUDPSocketAlias> client;
  EventBase* evb_;
};

TEST_F(QuicServerTest, NetworkTestVersionNegotiation) {
  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 2);
  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize + 10);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get(200ms);

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  auto packetQueue = bufToQueue(std::move(serverData));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());

  EXPECT_EQ(versionPacket->destinationConnectionId, clientConnId);
}

TEST_F(QuicServerTest, NetworkTestVersionNegotiationMinLength) {
  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 2);
  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize - 100);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

TEST_F(QuicServerTest, NetworkTestNoVersionNegotiation) {
  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 2);
  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = createInitialStream(
      clientConnId, serverConnId, id, *buf, QuicVersion::VERSION_NEGOTIATION);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

TEST_F(QuicServerTest, TestRejectNewConnections) {
  // test that Version Negotiation fails if the server is rejecting all
  // new connections
  folly::Promise<quic::SocketAddress> clientAddressPromise;
  auto clientAddressFuture = clientAddressPromise.getFuture();
  rejectNewConnections_ =
      [&clientAddressPromise](const quic::SocketAddress& client) {
        clientAddressPromise.setValue(client);
        return true;
      };

  auto* stats = new NiceMock<MockQuicStats>();
  EXPECT_CALL(*stats, onNewConnectionAttemptRejected()).Times(1);
  auto serverAddr = initializeServer({evbThread_.getEventBase()}, stats);

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get(200ms);
  EXPECT_EQ(
      std::move(clientAddressFuture).get(200ms), reader->getSocket().address());

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);

  auto packetQueue = bufToQueue(std::move(serverData));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());

  EXPECT_EQ(versionPacket->destinationConnectionId, clientConnId);
  EXPECT_EQ(versionPacket->sourceConnectionId, serverConnId);
  EXPECT_EQ(versionPacket->versions.size(), 1);
  EXPECT_EQ(versionPacket->versions.at(0), QuicVersion::MVFST_INVALID);
}

TEST_F(QuicServerTest, ServerOptionsBlockListedSrcPortDropsFirstPacket) {
  folly::Promise<uint16_t> blockedPortPromise;
  auto blockedPortFuture = blockedPortPromise.getFuture();
  isBlockListedSrcPort_ = [&blockedPortPromise](uint16_t port) mutable {
    blockedPortPromise.setValue(port);
    return true;
  };

  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);

  auto* stats = new NiceMock<MockQuicStats>();
  EXPECT_CALL(
      *stats,
      onPacketDropped(PacketDropReason(PacketDropReason::INVALID_SRC_PORT)))
      .Times(1);
  auto serverAddr = initializeServer({evbThread_.getEventBase()}, stats);

  quic::SocketAddress addr2("::1", 0);
  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  reader->getSocket().write(serverAddr, packet->clone());

  EXPECT_EQ(
      std::move(blockedPortFuture).get(200ms),
      reader->getSocket().address().getPort());
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

TEST_F(QuicServerTest, NetworkTestHealthCheck) {
  quic::SocketAddress addr("::1", 0);
  std::string healthCheckToken = "health";
  std::string notHealthCheckToken = "health2";

  healthCheckToken_ = healthCheckToken;

  startOwned(addr, 2);
  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };
  reader->getSocket().write(serverAddr, IOBuf::copyBuffer(healthCheckToken));
  auto serverData = reader->readOne().get();
  EXPECT_EQ(serverData->toString(), std::string("OK"));

  reader->getSocket().write(serverAddr, IOBuf::copyBuffer(notHealthCheckToken));
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

void QuicServerTest::testReset(BufPtr packet) {
  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 2);
  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  reader->getSocket().write(serverAddr, packet->clone());

  auto serverData = reader->readOne().get(1000ms);
  EXPECT_LE(serverData->computeChainDataLength(), kDefaultUDPSendPacketLen);

  QuicReadCodec codec(QuicNodeType::Client);
  auto aead = createNoOpAead();
  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return std::nullopt; }));
  codec.setOneRttReadCipher(std::move(aead));
  codec.setOneRttHeaderCipher(test::createNoOpHeaderCipher().value());
  StatelessResetToken token = generateStatelessResetToken();
  codec.setStatelessResetToken(token);
  FizzCryptoFactory cryptoFactory;
  codec.setCryptoEqual(cryptoFactory.getCryptoEqualFunction());
  AckStates ackStates;
  auto packetBuf = serverData->clone();
  overridePacketWithToken(*packetBuf, token);
  auto packetQueue = bufToQueue(std::move(packetBuf));
  auto res = codec.parsePacket(packetQueue, ackStates);
  EXPECT_NE(res.statelessReset(), nullptr);
}

TEST_F(QuicServerTest, NetworkTestReset) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto data = std::move(packet);
  testReset(data->clone());
}

TEST_F(QuicServerTest, NetworkTestResetLargePacket) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::create(kDefaultUDPSendPacketLen + 3);
  buf->append(kDefaultUDPSendPacketLen + 3);
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  ASSERT_LE(packet->computeChainDataLength(), kDefaultUDPSendPacketLen);
  testReset(std::move(packet));
}

TEST_F(QuicServerTest, NetworkTestResetLongHeader) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  EXPECT_THROW(testReset(std::move(packet)), folly::FutureTimeout);
}

TEST_F(QuicServerTest, ZeroRttPacketRoute) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};

  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 1);

  std::shared_ptr<MockQuicTransport> transport;
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  folly::Baton<> b;
  // create payload
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize + 10);
  auto packet = createInitialStream(
      clientConnId, serverConnId, id, *buf, QuicVersion::MVFST);
  auto data = std::move(packet);

  auto makeTransport = [&](folly::EventBase* eventBase,
                           std::unique_ptr<FollyAsyncUDPSocketAlias>& socket,
                           const quic::SocketAddress&) noexcept {
    auto qEvb = std::make_shared<FollyQuicEventBase>(eventBase);
    auto qSock =
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(socket));
    transport = std::make_shared<MockQuicTransport>(
        qEvb, std::move(qSock), &connSetupCb, &connCb, serverCtx_);
    EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb));
    EXPECT_CALL(*transport, setSupportedVersions(_));
    EXPECT_CALL(*transport, setOriginalPeerAddress(_));
    EXPECT_CALL(*transport, setTransportSettings(_));
    EXPECT_CALL(*transport, setServerConnectionIdParams(_));
    EXPECT_CALL(*transport, accept(_));
    // post baton upon receiving the data
    EXPECT_CALL(*transport, onNetworkData(_, _))
        .WillOnce(
            Invoke([&, expected = data.get()](auto, const auto& networkData) {
              EXPECT_GT(networkData.getPackets().size(), 0);
              EXPECT_TRUE(
                  folly::IOBufEqualTo()(
                      *networkData.getPackets()[0].buf.front(), *expected));
              b.post();
            }));
    return transport;
  };
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Invoke(makeTransport));

  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
    transport->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transport.reset(); });
  };

  // send an initial packet - that should create a new 'connection'
  reader->getSocket().write(serverAddr, data->clone());
  b.wait();

  // now send 0-rtt packet, and verify that it gets routed properly
  PacketNum packetNum = 20;
  packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  data = std::move(packet);
  folly::Baton<> b1;
  auto verifyZeroRtt = [&](const quic::SocketAddress& /*local*/,
                           const NetworkData& networkData) noexcept {
    EXPECT_GT(networkData.getPackets().size(), 0);
    const auto& routedPacket = networkData.getPackets()[0];
    ASSERT_TRUE(routedPacket.peerAddress.has_value());
    EXPECT_EQ(*routedPacket.peerAddress, reader->getSocket().address());
    EXPECT_TRUE(folly::IOBufEqualTo()(*data, *routedPacket.buf.front()));
    b1.post();
  };
  EXPECT_CALL(*transport, onNetworkData(_, _)).WillOnce(Invoke(verifyZeroRtt));
  reader->getSocket().write(serverAddr, data->clone());
  b1.wait();
}

TEST_F(QuicServerTest, ZeroRttBeforeInitial) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};

  quic::SocketAddress addr("::1", 0);
  startOwned(addr, 1);

  std::shared_ptr<MockQuicTransport> transport;
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  folly::Baton<> b;
  // create payload
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto initialBuf = createData(kMinInitialPacketSize + 10);
  auto initialPacket = createInitialStream(
      clientConnId, serverConnId, id, *initialBuf, QuicVersion::MVFST);
  auto initialData = std::move(initialPacket);

  std::vector<BufPtr> receivedData;
  auto makeTransport = [&](folly::EventBase* eventBase,
                           std::unique_ptr<FollyAsyncUDPSocketAlias>& socket,
                           const quic::SocketAddress&) noexcept {
    auto qEvb = std::make_shared<FollyQuicEventBase>(eventBase);
    auto qSock =
        std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(socket));
    transport = std::make_shared<MockQuicTransport>(
        qEvb, std::move(qSock), &connSetupCb, &connCb, serverCtx_);
    EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb));
    EXPECT_CALL(*transport, setSupportedVersions(_));
    EXPECT_CALL(*transport, setOriginalPeerAddress(_));
    EXPECT_CALL(*transport, setTransportSettings(_));
    EXPECT_CALL(*transport, setServerConnectionIdParams(_));
    EXPECT_CALL(*transport, accept(_));
    // post baton upon receiving the data
    EXPECT_CALL(*transport, onNetworkData(_, _))
        .Times(2)
        .WillRepeatedly(Invoke([&](const auto&, auto& networkData) {
          for (const auto& packet : networkData.getPackets()) {
            receivedData.emplace_back(packet.buf.clone());
          }
          if (receivedData.size() == 2) {
            b.post();
          }
        }));
    return transport;
  };
  EXPECT_CALL(*factory_, _make(_, _, _)).WillOnce(Invoke(makeTransport));

  auto serverAddr = serverAddress();

  quic::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    shutdownServer();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
    transport->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transport.reset(); });
  };

  // send 0-rtt packet, it should be buffered
  PacketNum packetNum = 20;
  auto zeroRttBuf = folly::IOBuf::copyBuffer("blah blah blah blah");
  auto zeroRttPacket = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *zeroRttBuf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  auto zeroRttData = std::move(zeroRttPacket);
  reader->getSocket().write(serverAddr, zeroRttData->clone());

  // send an initial packet - that should create a new 'connection'
  reader->getSocket().write(serverAddr, initialData->clone());
  b.wait();
  ASSERT_EQ(receivedData.size(), 2);
  ASSERT_EQ(
      initialData->computeChainDataLength(),
      receivedData[0]->computeChainDataLength());
  ASSERT_EQ(
      zeroRttData->computeChainDataLength(),
      receivedData[1]->computeChainDataLength());
  EXPECT_TRUE(folly::IOBufEqualTo()(*initialData, *receivedData[0]));
  EXPECT_TRUE(folly::IOBufEqualTo()(*zeroRttData, *receivedData[1]));
}

TEST_F(QuicServerTest, OneEVB) {
  folly::EventBase evb;

  quic::SocketAddress addr("::1", 0);
  server_ = QuicServer::createQuicServer(buildOptions());
  server_->bind(addr, {&evb});
  server_->addTransportFactory(&evb, factory_);
  server_->start();
  evb.runAfterDelay([this] { shutdownServer(); }, 100);
  evb.loop();
}

TEST(QuicServerWorkerCountTest, RequestedCountIsCappedByCpuCount) {
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(0, 8), size_t(8));
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(4, 8), size_t(4));
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(64, 8), size_t(8));
}

TEST(QuicServerWorkerCountTest, DerivedCountIsCappedAtTheStartLimit) {
  const size_t limit = std::numeric_limits<uint8_t>::max() + 1;
  EXPECT_EQ(
      ThreadedQuicServer::numWorkersToCreate(limit - 1, limit + 1), limit - 1);
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(limit, limit + 1), limit);
  EXPECT_EQ(
      ThreadedQuicServer::numWorkersToCreate(limit + 1, limit + 1), limit);
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(0, limit), limit);
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(0, limit + 1), limit);
  // An H100 host has 384 cpus (D76638451).
  EXPECT_EQ(ThreadedQuicServer::numWorkersToCreate(0, 384), limit);
}

namespace {
class LifetimeRecordingFactory : public QuicServerTransportFactory {
 public:
  explicit LifetimeRecordingFactory(int& destroyedCount)
      : destroyedCount_(destroyedCount) {}

  ~LifetimeRecordingFactory() override {
    ++destroyedCount_;
  }

  QuicServerTransport::Ptr make(
      folly::EventBase* /*evb*/,
      std::unique_ptr<FollyAsyncUDPSocketAlias> /*socket*/,
      const quic::SocketAddress& /*addr*/,
      QuicVersion /*version*/) noexcept override {
    return nullptr;
  }

  int value() const {
    return 42;
  }

 private:
  int& destroyedCount_;
};
} // namespace

TEST(ThreadedQuicServerFactoryLifetimeTest, FactoryOutlivesShutdown) {
  int destroyedCount = 0;
  auto factory = std::make_unique<LifetimeRecordingFactory>(destroyedCount);
  auto* rawFactory = factory.get();
  auto server =
      std::make_unique<ThreadedQuicServer>(ServerOptions{}, std::move(factory));
  server->start(quic::SocketAddress("::1", 0), 1);
  server->shutdown();
  // Callers keep raw factory pointers; they must stay valid until the
  // ThreadedQuicServer itself is destroyed.
  EXPECT_EQ(destroyedCount, 0);
  EXPECT_EQ(rawFactory->value(), 42);
  server.reset();
  EXPECT_EQ(destroyedCount, 1);
}

TEST(QuicServerWorkerCountTest, EveryWorkerIdRoundTripsThroughAConnectionId) {
  const auto numWorkers = ThreadedQuicServer::numWorkersToCreate(0, 384);
  DefaultConnectionIdAlgo connIdAlgo;

  for (auto version :
       {ConnectionIdVersion::V1,
        ConnectionIdVersion::V2,
        ConnectionIdVersion::V3}) {
    std::set<size_t> parsedWorkerIds;
    for (size_t i = 0; i < numWorkers; ++i) {
      // What QuicServer hands QuicServerWorker at bind().
      ServerConnectionIdParams params(
          version, /*hostIdIn=*/1, /*processIdIn=*/0, static_cast<uint8_t>(i));
      auto connId = connIdAlgo.encodeConnectionId(params);
      ASSERT_FALSE(connId.hasError());
      auto parsed = connIdAlgo.parseConnectionId(connId.value());
      ASSERT_FALSE(parsed.hasError());
      parsedWorkerIds.insert(parsed.value().workerId);
    }
    EXPECT_EQ(parsedWorkerIds.size(), numWorkers);
  }
}

class ThreadRecordingStatsFactory : public QuicTransportStatsCallbackFactory {
 public:
  explicit ThreadRecordingStatsFactory(std::vector<folly::EventBase*> evbs)
      : evbs_(std::move(evbs)) {}

  std::unique_ptr<QuicTransportStatsCallback> make() override {
    folly::EventBase* current = nullptr;
    for (auto* evb : evbs_) {
      if (evb->isInEventBaseThread()) {
        current = evb;
        break;
      }
    }
    {
      std::scoped_lock lock(mutex_);
      recordedEvbs_.push_back(current);
    }
    return std::make_unique<NiceMock<MockQuicStats>>();
  }

  std::vector<folly::EventBase*> recordedEvbs() {
    std::scoped_lock lock(mutex_);
    return recordedEvbs_;
  }

 private:
  std::vector<folly::EventBase*> evbs_;
  std::mutex mutex_;
  std::vector<folly::EventBase*> recordedEvbs_;
};

class ThrowOnCallStatsFactory : public QuicTransportStatsCallbackFactory {
 public:
  explicit ThrowOnCallStatsFactory(int throwOnCall)
      : throwOnCall_(throwOnCall) {}

  std::unique_ptr<QuicTransportStatsCallback> make() override {
    if (++calls_ == throwOnCall_) {
      throw std::runtime_error("stats factory failure");
    }
    return std::make_unique<NiceMock<MockQuicStats>>();
  }

 private:
  int throwOnCall_;
  int calls_{0};
};

class QueuedListenerSocketFactory : public QuicUDPSocketFactory {
 public:
  void addSocket(std::unique_ptr<FollyAsyncUDPSocketAlias> socket) {
    sockets_.push_back(std::move(socket));
  }

  std::unique_ptr<FollyAsyncUDPSocketAlias> make(
      folly::EventBase* /*evb*/,
      int /*fd*/) override {
    CHECK_LT(next_, sockets_.size());
    return std::move(sockets_[next_++]);
  }

 private:
  std::vector<std::unique_ptr<FollyAsyncUDPSocketAlias>> sockets_;
  size_t next_{0};
};

class FailOnNthListenerSocketFactory : public QuicUDPSocketFactory {
 public:
  explicit FailOnNthListenerSocketFactory(size_t failOnCall)
      : failOnCall_(failOnCall) {}

  std::unique_ptr<FollyAsyncUDPSocketAlias> make(
      folly::EventBase* evb,
      int /*fd*/) override {
    if (++calls_ == failOnCall_) {
      throw std::runtime_error("listener factory failure");
    }
    auto sock = std::make_unique<FollyAsyncUDPSocketAlias>(evb);
    sock->setReusePort(true);
    sock->setReuseAddr(false);
    return sock;
  }

 private:
  size_t failOnCall_;
  size_t calls_{0};
};

TEST_F(QuicServerTest, QueriesAfterShutdownReturnUnavailable) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  server_->allowBeingTakenOver(quic::SocketAddress("::1", 0));
  EXPECT_GE(server_->getListeningSocketFD(), 0);
  EXPECT_GE(server_->getTakeoverHandlerSocketFD(), 0);
  EXPECT_EQ(server_->getTakeoverProtocolVersion(), TakeoverProtocolVersion::V0);
  EXPECT_EQ(server_->getWorkerEvbs().size(), 1);
  server_->shutdown();
  EXPECT_EQ(server_->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server_->getListeningSocketFD(), -1);
  EXPECT_EQ(server_->getTakeoverHandlerSocketFD(), -1);
  EXPECT_EQ(server_->getTakeoverProtocolVersion(), TakeoverProtocolVersion::V0);
  EXPECT_TRUE(server_->getWorkerEvbs().empty());
  ThreadCheckingAcceptObserver observer(evb);
  EXPECT_FALSE(server_->addAcceptObserver(evb, &observer));
  EXPECT_FALSE(server_->removeAcceptObserver(evb, &observer));
  EXPECT_NO_THROW(server_->addTransportFactory(evb, factory_));
}

TEST(QuicServerLifecycleContractTest, QueriesAfterShutdownWithoutBind) {
  auto server = QuicServer::createQuicServer(ServerOptions{});
  server->shutdown();
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
  EXPECT_EQ(server->getTakeoverHandlerSocketFD(), -1);
  EXPECT_EQ(server->getTakeoverProtocolVersion(), TakeoverProtocolVersion::V0);
  EXPECT_TRUE(server->getWorkerEvbs().empty());
}

TEST_F(QuicServerTest, BindAfterRequestShutdownThrows) {
  folly::ScopedEventBaseThread evbThread;
  server_->requestShutdown();
  quic::SocketAddress addr("::1", 0);
  EXPECT_THROW(
      server_->bind(addr, {evbThread.getEventBase()}), std::runtime_error);
  EXPECT_EQ(server_->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerTest, RepeatedStartIsNoop) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  EXPECT_NO_THROW(server_->start());
  EXPECT_EQ(server_->state(), QuicServer::State::Running);
  server_->shutdown();
  EXPECT_EQ(server_->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerTest, BindRejectsMoreThan256Workers) {
  std::vector<std::unique_ptr<folly::EventBase>> owned;
  std::vector<folly::EventBase*> evbs;
  owned.reserve(257);
  evbs.reserve(257);
  for (int i = 0; i < 257; ++i) {
    owned.push_back(std::make_unique<folly::EventBase>());
    evbs.push_back(owned.back().get());
  }
  quic::SocketAddress addr("::1", 0);
  EXPECT_THROW(server_->bind(addr, evbs), std::invalid_argument);
  EXPECT_EQ(server_->state(), QuicServer::State::Created);
}

TEST_F(QuicServerTest, StartAfterRequestShutdownFailsCleanly) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  ASSERT_EQ(server_->state(), QuicServer::State::Bound);
  server_->requestShutdown();
  EXPECT_THROW(server_->start(), std::runtime_error);
  EXPECT_EQ(server_->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerTest, StartWithoutFactoryOnOneWorkerFails) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  auto* evbA = evbThreadA.getEventBase();
  auto* evbB = evbThreadB.getEventBase();
  quic::SocketAddress boundAddr("::1", 10000);
  std::unique_ptr<FollyAsyncUDPSocketAlias> sockA;
  std::unique_ptr<FollyAsyncUDPSocketAlias> sockB;
  folly::test::MockAsyncUDPSocketT<>* rawA = nullptr;
  folly::test::MockAsyncUDPSocketT<>* rawB = nullptr;
  evbA->runInEventBaseThreadAndWait([&] {
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(evbA);
    rawA = sock.get();
    sockA = std::move(sock);
  });
  evbB->runInEventBaseThreadAndWait([&] {
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(evbB);
    rawB = sock.get();
    sockB = std::move(sock);
  });
  EXPECT_CALL(*rawA, address()).WillRepeatedly(ReturnRef(boundAddr));
  EXPECT_CALL(*rawB, address()).WillRepeatedly(ReturnRef(boundAddr));
  // Prepare must validate every worker before any listener is activated:
  // neither worker may resume reads when one worker lacks a factory.
  EXPECT_CALL(*rawA, resumeRead(_)).Times(0);
  EXPECT_CALL(*rawB, resumeRead(_)).Times(0);
  EXPECT_CALL(*rawA, pauseRead()).Times(testing::AnyNumber());
  EXPECT_CALL(*rawB, pauseRead()).Times(testing::AnyNumber());
  EXPECT_CALL(*factory_, _make(_, _, _)).Times(0);
  ServerOptions options;
  auto listenerFactory = std::make_unique<QueuedListenerSocketFactory>();
  listenerFactory->addSocket(std::move(sockA));
  listenerFactory->addSocket(std::move(sockB));
  options.listenerSocketFactory = std::move(listenerFactory);
  auto server = QuicServer::createQuicServer(std::move(options));
  server->bind(quic::SocketAddress("::1", 0), {evbA, evbB});
  ASSERT_EQ(server->state(), QuicServer::State::Bound);
  server->addTransportFactory(evbA, factory_);
  // Deliberately omit the factory for evbB.
  EXPECT_THROW(server->start(), std::runtime_error);
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
}

TEST(QuicServerLifecycleContractTest, StartActivationFailureRollsBack) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  auto* evbA = evbThreadA.getEventBase();
  auto* evbB = evbThreadB.getEventBase();
  quic::SocketAddress boundAddr("::1", 10000);
  std::unique_ptr<FollyAsyncUDPSocketAlias> sockA;
  std::unique_ptr<FollyAsyncUDPSocketAlias> sockB;
  folly::test::MockAsyncUDPSocketT<>* rawA = nullptr;
  folly::test::MockAsyncUDPSocketT<>* rawB = nullptr;
  evbA->runInEventBaseThreadAndWait([&] {
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(evbA);
    rawA = sock.get();
    sockA = std::move(sock);
  });
  evbB->runInEventBaseThreadAndWait([&] {
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(evbB);
    rawB = sock.get();
    sockB = std::move(sock);
  });
  EXPECT_CALL(*rawA, address()).WillRepeatedly(ReturnRef(boundAddr));
  EXPECT_CALL(*rawB, address()).WillRepeatedly(ReturnRef(boundAddr));
  // Worker A activates, worker B fails, and rollback must pause A before
  // start() returns. No connection is accepted on either worker.
  {
    InSequence seq;
    EXPECT_CALL(*rawA, resumeRead(_)).Times(1);
    EXPECT_CALL(*rawB, resumeRead(_))
        .WillOnce(Throw(std::runtime_error("resume failed")));
    EXPECT_CALL(*rawA, pauseRead()).Times(AtLeast(1));
  }
  EXPECT_CALL(*rawB, pauseRead()).Times(testing::AnyNumber());
  MockQuicServerTransportFactory transportFactory;
  EXPECT_CALL(transportFactory, _make(_, _, _)).Times(0);
  ServerOptions options;
  auto listenerFactory = std::make_unique<QueuedListenerSocketFactory>();
  listenerFactory->addSocket(std::move(sockA));
  listenerFactory->addSocket(std::move(sockB));
  options.listenerSocketFactory = std::move(listenerFactory);
  auto server = QuicServer::createQuicServer(std::move(options));
  quic::SocketAddress addr("::1", 0);
  server->bind(addr, {evbA, evbB});
  ASSERT_EQ(server->state(), QuicServer::State::Bound);
  server->addTransportFactory(evbA, &transportFactory);
  server->addTransportFactory(evbB, &transportFactory);
  EXPECT_THROW(server->start(), std::runtime_error);
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
  int listenersAfterRollback = 0;
  server->forEachListenerSocket(
      [&](const folly::AsyncUDPSocket*) { ++listenersAfterRollback; });
  EXPECT_EQ(listenersAfterRollback, 0);
  EXPECT_NO_THROW(server->shutdown());
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
}

TEST(
    QuicServerLifecycleContractTest,
    StartWithoutTransportFactoryThrowsAndRollsBack) {
  folly::ScopedEventBaseThread evbThread;
  auto server = QuicServer::createQuicServer(ServerOptions{});
  server->bind(quic::SocketAddress("::1", 0), {evbThread.getEventBase()});
  ASSERT_EQ(server->state(), QuicServer::State::Bound);
  EXPECT_THROW(server->start(), std::runtime_error);
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
  EXPECT_NO_THROW(server->shutdown());
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerTest, LiveControlCompletesSynchronouslyOnIdleEvb) {
  folly::EventBase evb;
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {&evb});
  server_->addTransportFactory(&evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  auto* worker = workerForEvb(&evb);
  ASSERT_NE(worker, nullptr);
  quic::SocketAddress client("::1", 1234);
  auto token = folly::IOBuf::copyBuffer("health");
  EXPECT_FALSE(worker->tryHandlingAsHealthCheck(client, *token));
  server_->setHealthCheckToken("health");
  EXPECT_TRUE(worker->tryHandlingAsHealthCheck(client, *token));
  server_->shutdown();
  EXPECT_EQ(server_->state(), QuicServer::State::Stopped);
  evb.loopIgnoreKeepAlive();
}

TEST_F(QuicServerTest, ForEachListenerSocketRunsOnWorkerEvbs) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  auto* evbA = evbThreadA.getEventBase();
  auto* evbB = evbThreadB.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evbA, evbB});
  server_->addTransportFactory(evbA, factory_);
  server_->addTransportFactory(evbB, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  std::atomic<int> count{0};
  std::atomic<bool> allOnOwningEvb{true};
  std::atomic<bool> allNonNull{true};
  std::mutex observedMutex;
  std::set<folly::EventBase*> observedEvbs;
  server_->forEachListenerSocket([&](const folly::AsyncUDPSocket* sock) {
    if (sock == nullptr) {
      allNonNull = false;
      ++count;
      return;
    }
    auto* owningEvb = sock->getEventBase();
    if (owningEvb == nullptr || !owningEvb->isInEventBaseThread()) {
      allOnOwningEvb = false;
    } else {
      std::scoped_lock lock(observedMutex);
      observedEvbs.insert(owningEvb);
    }
    ++count;
  });
  EXPECT_EQ(count.load(), 2);
  EXPECT_TRUE(allOnOwningEvb.load());
  EXPECT_TRUE(allNonNull.load());
  {
    std::scoped_lock lock(observedMutex);
    EXPECT_EQ(observedEvbs.size(), 2);
    EXPECT_TRUE(observedEvbs.contains(evbA));
    EXPECT_TRUE(observedEvbs.contains(evbB));
  }
  server_->shutdown();
  count = 0;
  server_->forEachListenerSocket(
      [&](const folly::AsyncUDPSocket* /*sock*/) { ++count; });
  EXPECT_EQ(count.load(), 0);
}

TEST_F(QuicServerTest, ForEachListenerSocketPropagatesThrow) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  auto* evbA = evbThreadA.getEventBase();
  auto* evbB = evbThreadB.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evbA, evbB});
  server_->addTransportFactory(evbA, factory_);
  server_->addTransportFactory(evbB, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  std::atomic<int> count{0};
  bool caught = false;
  try {
    server_->forEachListenerSocket([&](const folly::AsyncUDPSocket* /*sock*/) {
      ++count;
      throw std::runtime_error("observer boom");
    });
  } catch (const std::runtime_error& ex) {
    caught = true;
    EXPECT_STREQ(ex.what(), "observer boom");
  }
  EXPECT_TRUE(caught);
  EXPECT_EQ(count.load(), 2);
  server_->shutdown();
}

TEST(QuicServerLifecycleContractTest, StatsFactoryRunsOnWorkerEventBases) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  std::vector<folly::EventBase*> evbs{
      evbThreadA.getEventBase(), evbThreadB.getEventBase()};
  ServerOptions options;
  auto statsFactory = std::make_unique<ThreadRecordingStatsFactory>(evbs);
  auto* rawFactory = statsFactory.get();
  options.transportStatsFactory = std::move(statsFactory);
  auto server = QuicServer::createQuicServer(std::move(options));
  server->bind(quic::SocketAddress("::1", 0), evbs);
  auto recorded = rawFactory->recordedEvbs();
  ASSERT_EQ(recorded.size(), 2);
  // Bind creates workers in evbs order, so the first callback must have
  // run on evbs[0] and the second on evbs[1]; running both on one
  // EventBase would fail here.
  EXPECT_EQ(recorded[0], evbs[0]);
  EXPECT_EQ(recorded[1], evbs[1]);
  EXPECT_NE(recorded[0], recorded[1]);
  server->shutdown();
}

TEST(QuicServerLifecycleContractTest, BindConstructionFailureRollsBack) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  std::vector<folly::EventBase*> evbs{
      evbThreadA.getEventBase(), evbThreadB.getEventBase()};
  ServerOptions options;
  options.transportStatsFactory = std::make_unique<ThrowOnCallStatsFactory>(2);
  auto server = QuicServer::createQuicServer(std::move(options));
  EXPECT_THROW(
      server->bind(quic::SocketAddress("::1", 0), evbs), std::runtime_error);
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
  server->shutdown();
}

TEST_F(QuicServerTest, TakeoverBindFailureSurfacesWithoutKillingServer) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  folly::ScopedEventBaseThread holderThread;
  auto* holderEvb = holderThread.getEventBase();
  std::unique_ptr<FollyAsyncUDPSocketAlias> holder;
  quic::SocketAddress holderAddr;
  holderEvb->runInEventBaseThreadAndWait([&] {
    holder = std::make_unique<FollyAsyncUDPSocketAlias>(holderEvb);
    holder->bind(quic::SocketAddress("::1", 0));
    holderAddr = holder->address();
  });
  ASSERT_TRUE(holderAddr.isInitialized());
  EXPECT_THROW(server_->allowBeingTakenOver(holderAddr), std::exception);
  EXPECT_EQ(server_->state(), QuicServer::State::Running);
  holderEvb->runInEventBaseThreadAndWait([&] {
    holder->close();
    holder.reset();
  });
  EXPECT_NO_THROW(server_->allowBeingTakenOver(quic::SocketAddress("::1", 0)));
  EXPECT_GE(server_->getTakeoverHandlerSocketFD(), 0);
  server_->shutdown();
}

TEST_F(QuicServerWorkerTakeoverTest, SetDestinationCancelsPendingStop) {
  takeoverWorker_->setProcessId(ProcessId::ONE);
  takeoverWorker_->startPacketForwarding(kClientAddr);
  takeoverWorker_->stopPacketForwardingAfter(std::chrono::milliseconds(20));
  takeoverWorker_->startPacketForwarding(kClientAddr2);
  evb_.runAfterDelay([&] { evb_.terminateLoopSoon(); }, 60);
  evb_.loop();
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO);
  ConnectionId clientConnId = getTestConnectionId(clientHostId_);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Handshake);
  data->coalesce();
  auto writeSock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _)).WillOnce([&](auto*, int) {
    return writeSock.release();
  });
  EXPECT_CALL(*writeSock, bind(_, _));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Return(static_cast<ssize_t>(data->computeChainDataLength())));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(1);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
  takeoverWorker_->stopPacketForwarding();
}

TEST_F(SimpleQuicServerWorkerTest, TakeoverPausedUntilStart) {
  auto listener =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* listenerPtr = listener.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(listener));
  MockQuicServerTransportFactory transportFactory;
  worker_->setTransportFactory(&transportFactory);
  auto takeoverSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* takeoverPtr = takeoverSock.get();
  quic::SocketAddress takeoverAddr("::1", 0);
  EXPECT_CALL(*takeoverPtr, bind(_, _)).Times(1);
  EXPECT_CALL(*takeoverPtr, resumeRead(_)).Times(0);
  worker_->allowBeingTakenOver(std::move(takeoverSock), takeoverAddr);
  Mock::VerifyAndClearExpectations(takeoverPtr);
  EXPECT_CALL(*listenerPtr, resumeRead(_)).Times(1);
  EXPECT_CALL(*takeoverPtr, resumeRead(_)).Times(1);
  worker_->start();
  auto takeoverSock2 =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* takeoverPtr2 = takeoverSock2.get();
  EXPECT_CALL(*takeoverPtr, pauseRead()).Times(1);
  EXPECT_CALL(*takeoverPtr2, bind(_, _)).Times(1);
  EXPECT_CALL(*takeoverPtr2, resumeRead(_)).Times(1);
  EXPECT_CALL(*takeoverPtr2, address()).WillOnce(ReturnRef(takeoverAddr));
  worker_->overrideTakeoverHandlerAddress(
      std::move(takeoverSock2), takeoverAddr);
  worker_.reset();
  runState_.reset();
}

TEST_F(SimpleQuicServerWorkerTest, TakeoverBindFailureCleansUpAndRetries) {
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  quic::SocketAddress takeoverAddr("::1", 0);
  auto badSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*badSock, bind(_, _))
      .WillOnce(Throw(std::runtime_error("bind failed")));
  EXPECT_THROW(
      worker_->allowBeingTakenOver(std::move(badSock), takeoverAddr),
      std::runtime_error);
  EXPECT_EQ(worker_->getTakeoverHandlerCallback(), nullptr);
  auto goodSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*goodSock, bind(_, _)).Times(1);
  EXPECT_CALL(*goodSock, resumeRead(_)).Times(0);
  EXPECT_NO_THROW(
      worker_->allowBeingTakenOver(std::move(goodSock), takeoverAddr));
  EXPECT_NE(worker_->getTakeoverHandlerCallback(), nullptr);
  worker_.reset();
  runState_.reset();
}

TEST_F(SimpleQuicServerWorkerTest, TakeoverResumeErrorOnBindFailsAndRetries) {
  auto listener =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* listenerPtr = listener.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(listener));
  MockQuicServerTransportFactory transportFactory;
  worker_->setTransportFactory(&transportFactory);
  EXPECT_CALL(*listenerPtr, resumeRead(_)).Times(1);
  worker_->start();
  auto failResume = [](folly::AsyncUDPSocket::ReadCallback* cb) {
    cb->onReadError(
        folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "injected takeover read activation failure"));
  };
  quic::SocketAddress takeoverAddr("::1", 0);
  auto badSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* badPtr = badSock.get();
  EXPECT_CALL(*badPtr, bind(_, _)).Times(1);
  EXPECT_CALL(*badPtr, resumeRead(_)).WillOnce(Invoke(failResume));
  EXPECT_CALL(*badPtr, pauseRead()).Times(1);
  EXPECT_THROW(
      worker_->allowBeingTakenOver(std::move(badSock), takeoverAddr),
      std::runtime_error);
  EXPECT_EQ(worker_->getTakeoverHandlerCallback(), nullptr);
  eventbase_.loopOnce();
  auto goodSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  EXPECT_CALL(*goodSock, bind(_, _)).Times(1);
  EXPECT_CALL(*goodSock, resumeRead(_)).Times(1);
  EXPECT_NO_THROW(
      worker_->allowBeingTakenOver(std::move(goodSock), takeoverAddr));
  EXPECT_NE(worker_->getTakeoverHandlerCallback(), nullptr);
  worker_.reset();
  runState_.reset();
}

TEST_F(SimpleQuicServerWorkerTest, TakeoverResumeErrorOnRebindFails) {
  auto listener =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* listenerPtr = listener.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(listener));
  MockQuicServerTransportFactory transportFactory;
  worker_->setTransportFactory(&transportFactory);
  EXPECT_CALL(*listenerPtr, resumeRead(_)).Times(1);
  worker_->start();
  quic::SocketAddress takeoverAddr("::1", 0);
  auto oldSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* oldPtr = oldSock.get();
  EXPECT_CALL(*oldPtr, bind(_, _)).Times(1);
  EXPECT_CALL(*oldPtr, resumeRead(_)).Times(1);
  worker_->allowBeingTakenOver(std::move(oldSock), takeoverAddr);
  Mock::VerifyAndClearExpectations(oldPtr);
  auto failResume = [](folly::AsyncUDPSocket::ReadCallback* cb) {
    cb->onReadError(
        folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "injected takeover read activation failure"));
  };
  auto newSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* newPtr = newSock.get();
  EXPECT_CALL(*newPtr, bind(_, _)).Times(1);
  EXPECT_CALL(*oldPtr, pauseRead()).Times(1);
  EXPECT_CALL(*newPtr, resumeRead(_)).WillOnce(Invoke(failResume));
  EXPECT_CALL(*newPtr, pauseRead()).Times(1);
  EXPECT_THROW(
      worker_->overrideTakeoverHandlerAddress(std::move(newSock), takeoverAddr),
      std::runtime_error);
  EXPECT_NE(worker_->getTakeoverHandlerCallback(), nullptr);
  EXPECT_EQ(worker_->getTakeoverHandlerSocketFD(), -1);
  eventbase_.loopOnce();
  worker_.reset();
  runState_.reset();
}

TEST_F(SimpleQuicServerWorkerTest, TakeoverResumeErrorOnStartFails) {
  auto listener =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* listenerPtr = listener.get();
  runState_ = makeSingleWorkerRunState(&eventbase_);
  worker_ = std::make_unique<QuicServerWorker>(runState_.get(), 0);
  publishSingleWorker(*runState_, worker_.get());
  worker_->setSocket(std::move(listener));
  MockQuicServerTransportFactory transportFactory;
  worker_->setTransportFactory(&transportFactory);
  quic::SocketAddress takeoverAddr("::1", 0);
  auto takeoverSock =
      std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&eventbase_);
  auto* takeoverPtr = takeoverSock.get();
  EXPECT_CALL(*takeoverPtr, bind(_, _)).Times(1);
  EXPECT_CALL(*takeoverPtr, resumeRead(_)).Times(0);
  worker_->allowBeingTakenOver(std::move(takeoverSock), takeoverAddr);
  Mock::VerifyAndClearExpectations(takeoverPtr);
  auto failResume = [](folly::AsyncUDPSocket::ReadCallback* cb) {
    cb->onReadError(
        folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "injected takeover read activation failure"));
  };
  EXPECT_CALL(*listenerPtr, resumeRead(_)).Times(1);
  EXPECT_CALL(*takeoverPtr, resumeRead(_)).WillOnce(Invoke(failResume));
  EXPECT_CALL(*takeoverPtr, pauseRead()).Times(1);
  EXPECT_THROW(worker_->start(), std::runtime_error);
  eventbase_.loopOnce();
  worker_.reset();
  runState_.reset();
}

TEST_F(QuicServerTest, QueriesAfterRequestShutdownReturnUnavailable) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  server_->allowBeingTakenOver(quic::SocketAddress("::1", 0));
  EXPECT_GE(server_->getListeningSocketFD(), 0);
  auto allFds = server_->getAllListeningSocketFDs();
  ASSERT_EQ(allFds.size(), 1);
  EXPECT_GE(allFds[0], 0);
  EXPECT_GE(server_->getTakeoverHandlerSocketFD(), 0);
  EXPECT_EQ(server_->getTakeoverProtocolVersion(), TakeoverProtocolVersion::V0);
  server_->requestShutdown();
  EXPECT_TRUE(server_->stopping());
  evb->runInEventBaseThreadAndWait([] {});
  EXPECT_EQ(server_->getListeningSocketFD(), -1);
  EXPECT_TRUE(server_->getAllListeningSocketFDs().empty());
  EXPECT_EQ(server_->getTakeoverHandlerSocketFD(), -1);
  EXPECT_EQ(server_->getTakeoverProtocolVersion(), TakeoverProtocolVersion::V0);
  server_->shutdown();
}

TEST_F(QuicServerTest, ObserverAttachConcurrentWithSetHostId) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  quic::SocketAddress addr("::1", 0);
  server_->bind(addr, {evb});
  server_->addTransportFactory(evb, factory_);
  server_->start();
  ASSERT_EQ(server_->state(), QuicServer::State::Running);
  ThreadCheckingAcceptObserver observer(evb);
  constexpr int kRounds = 100;
  std::atomic<bool> observerOk{true};
  std::thread observerThread([&] {
    for (int i = 0; i < kRounds; ++i) {
      if (!server_->addAcceptObserver(evb, &observer)) {
        observerOk = false;
      }
      if (!server_->removeAcceptObserver(evb, &observer)) {
        observerOk = false;
      }
    }
  });
  for (int i = 0; i < kRounds; ++i) {
    server_->setHostId(serverHostId_ + 1 + (i % 2));
  }
  observerThread.join();
  EXPECT_TRUE(observerOk.load());
  EXPECT_TRUE(observer.attachRanOnExpectedEvb);
  server_->shutdown();
}

class QuicServerLifecycleTest : public Test {
 protected:
  std::shared_ptr<QuicServer> makeServer(ServerOptions options = {}) {
    return QuicServer::createQuicServer(std::move(options));
  }

  MockQuicServerTransportFactory factory_;
  quic::SocketAddress addr_{"::1", 0};
};

TEST_F(QuicServerLifecycleTest, BindFailureRollsBackToStopped) {
  folly::ScopedEventBaseThread evbThreadA;
  folly::ScopedEventBaseThread evbThreadB;
  ServerOptions options;
  options.listenerSocketFactory =
      std::make_unique<FailOnNthListenerSocketFactory>(2);
  auto server = makeServer(std::move(options));
  // The first worker binds a real listener; the injected factory failure
  // on the second worker must roll the whole bind back.
  EXPECT_THROW(
      server->bind(
          addr_, {evbThreadA.getEventBase(), evbThreadB.getEventBase()}),
      std::runtime_error);
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_EQ(server->getListeningSocketFD(), -1);
  // The first worker really bound, and rollback released its socket: the
  // port can be bound again without any reuse flags.
  auto firstWorkerAddr = server->getAddress();
  ASSERT_NE(firstWorkerAddr.getPort(), 0);
  folly::ScopedEventBaseThread probeThread;
  auto* probeEvb = probeThread.getEventBase();
  bool rebound = false;
  probeEvb->runInEventBaseThreadAndWait([&] {
    try {
      FollyAsyncUDPSocketAlias probe(probeEvb);
      probe.setReusePort(false);
      probe.setReuseAddr(false);
      probe.bind(firstWorkerAddr);
      rebound = true;
      probe.close();
    } catch (...) {
      rebound = false;
    }
  });
  EXPECT_TRUE(rebound);
  EXPECT_NO_THROW(server->shutdown());
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerLifecycleTest, StateTransitionsAndIdempotentShutdown) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  auto server = makeServer();
  EXPECT_EQ(server->state(), QuicServer::State::Created);
  EXPECT_FALSE(server->stopping());

  server->bind(addr_, {evb});
  EXPECT_EQ(server->state(), QuicServer::State::Bound);

  server->addTransportFactory(evb, &factory_);
  server->start();
  EXPECT_EQ(server->state(), QuicServer::State::Running);

  server->pauseRead();
  EXPECT_EQ(server->state(), QuicServer::State::Paused);

  server->start();
  EXPECT_EQ(server->state(), QuicServer::State::Running);

  server->requestShutdown();
  EXPECT_TRUE(server->stopping());

  server->shutdown();
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
  EXPECT_FALSE(server->stopping());

  // Completed shutdown is idempotent.
  server->shutdown();
  EXPECT_EQ(server->state(), QuicServer::State::Stopped);
}

TEST_F(QuicServerLifecycleTest, AddressSnapshotByValue) {
  folly::ScopedEventBaseThread evbThread;
  auto* evb = evbThread.getEventBase();
  auto server = makeServer();
  static_assert(
      std::is_same_v<decltype(server->getAddress()), quic::SocketAddress>);
  server->bind(addr_, {evb});

  auto snapshot = server->getAddress();
  EXPECT_NE(snapshot.getPort(), 0);
  EXPECT_EQ(snapshot, server->getAddress());

  server->addTransportFactory(evb, &factory_);
  server->start();
  EXPECT_EQ(snapshot, server->getAddress());

  server->shutdown();
  // The snapshot is a value: it outlives the stopped server unchanged.
  EXPECT_EQ(snapshot.getPort(), server->getAddress().getPort());
}

TEST_F(QuicServerLifecycleTest, EnableZeroCopyBeforeBindFails) {
  auto server = makeServer();
  auto result = server->enableZeroCopy();
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(server->state(), QuicServer::State::Created);
}

TEST(QuicServerLifecycleDeathTest, BindDuplicateEventBase) {
  EXPECT_DEATH(
      {
        folly::EventBase evb;
        auto server = QuicServer::createQuicServer(ServerOptions());
        server->bind(quic::SocketAddress("::1", 0), {&evb, &evb});
      },
      "");
}

TEST(QuicServerLifecycleDeathTest, BindNullEventBase) {
  EXPECT_DEATH(
      {
        auto server = QuicServer::createQuicServer(ServerOptions());
        server->bind(
            quic::SocketAddress("::1", 0),
            {static_cast<folly::EventBase*>(nullptr)});
      },
      "");
}

TEST(QuicServerLifecycleDeathTest, BindTwice) {
  EXPECT_DEATH(
      {
        folly::EventBase evb;
        auto server = QuicServer::createQuicServer(ServerOptions());
        server->bind(quic::SocketAddress("::1", 0), {&evb});
        server->bind(quic::SocketAddress("::1", 0), {&evb});
      },
      "");
}

TEST(QuicServerLifecycleDeathTest, StartBeforeBind) {
  EXPECT_DEATH(
      {
        auto server = QuicServer::createQuicServer(ServerOptions());
        server->start();
      },
      "");
}

TEST(QuicServerLifecycleDeathTest, GetAddressBeforeBind) {
  EXPECT_DEATH(
      {
        auto server = QuicServer::createQuicServer(ServerOptions());
        (void)server->getAddress();
      },
      "");
}

class TwoWorkerRoutingTest : public Test {
 protected:
  void SetUp() override {
    runState_ = std::make_unique<RunState>();
    runState_->peers.push_back(
        WorkerEndpoint{
            .evb = &evb0_, .target = std::make_shared<DispatchTarget>()});
    runState_->peers.push_back(
        WorkerEndpoint{
            .evb = &evb1_, .target = std::make_shared<DispatchTarget>()});
    worker0_ = makeWorker(0, factory0_, socketFactory0_);
    worker1_ = makeWorker(1, factory1_, socketFactory1_);
    runState_->peers[0].target->worker = worker0_.get();
    runState_->peers[1].target->worker = worker1_.get();
  }

  std::unique_ptr<QuicServerWorker> makeWorker(
      size_t index,
      MockQuicServerTransportFactory& factory,
      MockQuicUDPSocketFactory& socketFactory) {
    auto worker = std::make_unique<QuicServerWorker>(runState_.get(), index);
    worker->setWorkerId(static_cast<uint8_t>(index));
    worker->setHostId(kHostId);
    worker->setProcessId(ProcessId::ONE);
    worker->setConnectionIdVersion(ConnectionIdVersion::V2);
    worker->setConnectionIdAlgo(std::make_unique<DefaultConnectionIdAlgo>());
    worker->setSupportedVersions({QuicVersion::MVFST});
    worker->setTransportStatsCallback(
        std::make_unique<NiceMock<MockQuicStats>>());
    worker->setSocket(
        std::make_unique<folly::test::MockAsyncUDPSocketT<>>(
            runState_->peers[index].evb));
    worker->setTransportFactory(&factory);
    worker->setNewConnectionSocketFactory(&socketFactory);
    return worker;
  }

  ConnectionId serverCidForWorker(uint8_t workerId) {
    DefaultConnectionIdAlgo algo;
    auto encoded = algo.encodeConnectionId(ServerConnectionIdParams(
        ConnectionIdVersion::V2,
        kHostId,
        static_cast<uint8_t>(ProcessId::ONE),
        workerId));
    CHECK(!encoded.hasError());
    return encoded.value();
  }

  static constexpr uint32_t kHostId = 49;
  folly::EventBase evb0_;
  folly::EventBase evb1_;
  std::unique_ptr<RunState> runState_;
  std::unique_ptr<QuicServerWorker> worker0_;
  std::unique_ptr<QuicServerWorker> worker1_;
  NiceMock<MockQuicServerTransportFactory> factory0_;
  NiceMock<MockQuicServerTransportFactory> factory1_;
  NiceMock<MockQuicUDPSocketFactory> socketFactory0_;
  NiceMock<MockQuicUDPSocketFactory> socketFactory1_;
};

// A cross-worker dispatch is delivered through the destination handle:
// while the destination is live the packet reaches its transport factory,
// and a dispatch still queued when the destination is destroyed is
// dropped instead of dereferencing the dead worker.
TEST_F(TwoWorkerRoutingTest, HeldDispatchAfterPeerStopIsDropped) {
  EXPECT_CALL(factory0_, _make(_, _, _)).Times(0);

  auto routeInitialToWorker1 =
      [this](const quic::SocketAddress& client, ConnectionId sourceCid) {
        RoutingData routingData(
            HeaderForm::Long,
            true /* isInitial */,
            false /* is0Rtt */,
            serverCidForWorker(1),
            sourceCid);
        auto data = createData(kMinInitialPacketSize + 10);
        worker0_->routeOrDispatch(
            client,
            std::move(routingData),
            NetworkData(data->clone(), Clock::now(), 0),
            QuicVersion::MVFST,
            false /* isForwardedData */);
      };

  // Positive control: the same Initial, dispatched while the destination
  // is live, is delivered to its transport factory.
  EXPECT_CALL(factory1_, _make(_, _, _)).Times(1).WillOnce(Return(nullptr));
  routeInitialToWorker1(kClientAddr, getTestConnectionId(7));
  evb1_.loopOnce(EVLOOP_NONBLOCK);
  evb1_.loopOnce(EVLOOP_NONBLOCK);
  Mock::VerifyAndClearExpectations(&factory1_);

  // Queue another dispatch, then destroy the destination before its
  // EventBase runs the held callback.
  EXPECT_CALL(factory1_, _make(_, _, _)).Times(0);
  routeInitialToWorker1(kClientAddr2, getTestConnectionId(8));
  worker1_.reset();
  EXPECT_EQ(runState_->peers[1].target->worker, nullptr);

  evb1_.loopOnce(EVLOOP_NONBLOCK);
  evb1_.loopOnce(EVLOOP_NONBLOCK);
}

// RunState::requestStop enqueues stop callbacks through the same handles;
// a peer that already stopped must not be called again.
TEST_F(TwoWorkerRoutingTest, RequestStopAfterPeerStopIsSafe) {
  worker1_->stopLocal(LocalErrorCode::SHUTTING_DOWN);
  EXPECT_TRUE(worker1_->isStopping());

  runState_->requestStop(LocalErrorCode::SHUTTING_DOWN);
  evb0_.loopOnce();
  evb1_.loopOnce();

  EXPECT_TRUE(worker0_->isStopping());
  EXPECT_TRUE(worker1_->isStopping());
}

TEST(ConfigureForAcceptTest, AppliesBundleInOrder) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto mockSock = std::make_unique<folly::test::MockAsyncUDPSocketT<>>(&evb);
  quic::SocketAddress sockAddr("::1", 0);
  ON_CALL(*mockSock, address()).WillByDefault(ReturnRef(sockAddr));
  auto qSock =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(mockSock));
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto transport = std::make_shared<MockQuicTransport>(
      qEvb, std::move(qSock), &connSetupCb, &connCb, nullptr);
  EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(qEvb));

  BufAccessor bufAccessor(1024);
  DefaultConnectionIdAlgo connIdAlgo;
  std::vector<QuicVersion> versions{QuicVersion::MVFST, QuicVersion::QUIC_V1};
  auto clientCid = getTestConnectionId(3);
  Optional<ConnectionId> clientCidOpt = clientCid;
  auto chosenDestCid = getTestConnectionId(4);
  QuicTimer::SharedPtr pacingTimer;

  // The bundle is applied synchronously, BufAccessor before settings so a
  // ContinuousMemory data path never observes settings without its buffer.
  InSequence seq;
  EXPECT_CALL(*transport, setBufAccessor(&bufAccessor));
  EXPECT_CALL(*transport, setSupportedVersions(versions));
  EXPECT_CALL(*transport, setOriginalPeerAddress(kClientAddr));
  EXPECT_CALL(*transport, setTransportSettings(_));
  EXPECT_CALL(*transport, setConnectionIdAlgo(&connIdAlgo));

  transport->configureForAccept(
      ServerAcceptParams{
          .transportSettings = TransportSettings(),
          .supportedVersions = versions,
          .originalPeerAddress = kClientAddr,
          .validNewToken = false,
          .clientConnectionId = clientCidOpt,
          .clientChosenDestConnectionId = chosenDestCid,
          .serverConnectionIdParams =
              ServerConnectionIdParams(ConnectionIdVersion::V2, 49, 1, 0),
          .connIdAlgo = &connIdAlgo,
          .connIdRejector = nullptr,
          .bufAccessor = &bufAccessor,
          .pacingTimer = pacingTimer,
          .statsCallback = nullptr});

  // The default congestion-controller factory is installed by
  // configureForAccept when the application factory installed none.
  EXPECT_NE(transport->congestionControllerFactoryForTest(), nullptr);
}

class ThreadedQuicServerTest : public Test {
 protected:
  class NullFactory : public QuicServerTransportFactory {
   public:
    QuicServerTransport::Ptr make(
        folly::EventBase*,
        std::unique_ptr<FollyAsyncUDPSocketAlias>,
        const quic::SocketAddress&,
        QuicVersion) noexcept override {
      return nullptr;
    }
  };
};

TEST_F(ThreadedQuicServerTest, StartReturnsBoundAddressAndWorkers) {
  ThreadedQuicServer server(ServerOptions(), std::make_unique<NullFactory>());
  auto bound = server.start(quic::SocketAddress("::1", 0), 2);
  EXPECT_NE(bound.getPort(), 0);
  EXPECT_EQ(bound, server.getAddress());
  EXPECT_EQ(
      server.getWorkerEvbs().size(),
      ThreadedQuicServer::numWorkersToCreate(
          2, folly::available_concurrency()));
  server.shutdown();
}

TEST_F(ThreadedQuicServerTest, BindFailureCleansUp) {
  // The injected listener failure must complete shutdown of the
  // partially started core and stay destructible.
  ServerOptions options;
  options.listenerSocketFactory =
      std::make_unique<FailOnNthListenerSocketFactory>(1);
  EXPECT_THROW(
      {
        ThreadedQuicServer server(
            std::move(options), std::make_unique<NullFactory>());
        server.start(quic::SocketAddress("::1", 0), 2);
      },
      std::runtime_error);
}

} // namespace quic::test
