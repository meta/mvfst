/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>

using namespace testing;

namespace quic::test {

class QuicTransportCryptoTest : public QuicServerTransportTestBase {
 public:
  void SetUpChild() override {
    auto& conn = server->getNonConstConn();
    auto handshake =
        std::move(*getFizzServerContext()).makeServerHandshake(&conn);
    conn.serverHandshakeLayer = handshake.get();
    conn.handshakeLayer = std::move(handshake);
    fakeHandshake = nullptr;

    auto clientSocket = std::make_unique<NiceMock<MockAsyncUDPSocket>>(qEvb_);
    ON_CALL(*clientSocket, address()).WillByDefault(Return(clientAddr));
    EXPECT_CALL(*clientSocket, write(_, _, _))
        .WillRepeatedly(Invoke([&](const quic::SocketAddress&,
                                   const struct iovec* vec,
                                   size_t count) {
          clientWrites_.push_back(copyChain(folly::IOBuf::wrapIov(vec, count)));
          return getTotalIovecLen(vec, count);
        }));
    auto context = FizzClientQuicHandshakeContext::Builder()
                       .setFizzClientContext(createClientCtx())
                       .setCertificateVerifier(createTestCertificateVerifier())
                       .build();
    client_ = std::make_shared<TestingQuicClientTransport>(
        qEvb_, std::move(clientSocket), std::move(context));
    client_->setSupportedVersions({QuicVersion::MVFST});
    client_->setHostname("Fizz");
    client_->addNewPeerAddress(serverAddr);
    clientConnectionId = client_->getConn().clientConnectionId;
    initialDestinationConnectionId =
        client_->getConn().initialDestinationConnectionId;
    server->setClientConnectionId(*clientConnectionId);
    server->setClientChosenDestConnectionId(*initialDestinationConnectionId);
    server->accept(QuicVersion::MVFST);
    client_->start(&clientSetupCallback_, &clientCallback_);

    loopForWrites();
    deliverClientWrites();
    ASSERT_FALSE(serverWrites.empty());
    auto writes = std::move(serverWrites);
    serverWrites.clear();
    for (auto& packet : writes) {
      NetworkData data(ReceivedUdpPacket(std::move(packet)));
      data.setPeerAddressForAllPackets(serverAddr);
      client_->onNetworkData(clientAddr, std::move(data));
    }
    loopForWrites();
    ASSERT_EQ(
        client_->getConn().clientHandshakeLayer->getPhase(),
        ClientHandshake::Phase::OneRttKeysDerived);
    deliverClientWrites();
    ASSERT_EQ(
        conn.serverHandshakeLayer->getPhase(),
        ServerHandshake::Phase::Established);
    ASSERT_NE(conn.readCodec->getHandshakeReadCipher(), nullptr);
    ASSERT_NE(client_->getConn().handshakeWriteCipher, nullptr);
    ASSERT_FALSE(server->isClosed());
  }

  void TearDown() override {
    client_->closeNow(std::nullopt);
    server->closeNow(std::nullopt);
  }

  void deliverClientWrites() {
    ASSERT_FALSE(clientWrites_.empty());
    auto writes = std::move(clientWrites_);
    clientWrites_.clear();
    for (auto& packet : writes) {
      deliverData(std::move(packet));
    }
  }

  BufPtr makeClientHandshakePacket(uint64_t offset, const BufPtr& data) {
    const auto& conn = client_->getConn();
    auto packetNum =
        client_->getNonConstConn().ackStates.handshakeAckState->nextPacketNum++;
    ChainedByteRangeHead bytes(data);
    return packetToBufCleartext(
        createCryptoPacket(
            *conn.clientConnectionId,
            *conn.serverConnectionId,
            packetNum,
            QuicVersion::MVFST,
            ProtectionType::Handshake,
            bytes,
            *conn.handshakeWriteCipher,
            0,
            offset),
        *conn.handshakeWriteCipher,
        *conn.handshakeWriteHeaderCipher,
        packetNum);
  }

 protected:
  NiceMock<MockConnectionSetupCallback> clientSetupCallback_;
  NiceMock<MockConnectionCallback> clientCallback_;
  std::vector<BufPtr> clientWrites_;
  std::shared_ptr<TestingQuicClientTransport> client_;
};

TEST_F(
    QuicTransportCryptoTest,
    RejectNewHandshakeCryptoButAllowRetransmission) {
  const auto& stream = server->getConn().cryptoState->handshakeStream;
  const auto consumed = stream.currentReadOffset;
  ASSERT_GT(consumed, 0);
  auto& retransmissions =
      client_->getNonConstConn()
          .cryptoState->handshakeStream.retransmissionBuffer;
  ASSERT_FALSE(retransmissions.empty());
  auto finished =
      folly::IOBuf::copyBuffer(retransmissions.begin()->second->data.toStr());
  ASSERT_EQ(finished->computeChainDataLength(), consumed);

  deliverData(makeClientHandshakePacket(0, finished));
  EXPECT_FALSE(server->isClosed());
  EXPECT_EQ(stream.currentReadOffset, consumed);
  EXPECT_TRUE(stream.readBuffer.empty());

  auto unexpected = folly::IOBuf::copyBuffer("unexpected crypto data");
  deliverDataWithoutErrorCheck(makeClientHandshakePacket(consumed, unexpected));
  EXPECT_TRUE(server->isClosed());
  ASSERT_TRUE(server->getConn().localConnectionError.has_value());
  EXPECT_EQ(
      server->getConn().localConnectionError->code,
      TransportErrorCode::PROTOCOL_VIOLATION);
}

} // namespace quic::test
