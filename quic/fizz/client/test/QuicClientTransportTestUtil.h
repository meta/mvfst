/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/api/QuicTransportBase.h>

#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>
#include <quic/state/test/MockQuicStats.h>

#include <utility>

namespace quic::test {

class TestingQuicClientTransport : public QuicClientTransport {
 public:
  class DestructionCallback
      : public std::enable_shared_from_this<DestructionCallback> {
   public:
    void markDestroyed() {
      destroyed_ = true;
    }

    bool isDestroyed() {
      return destroyed_;
    }

   private:
    bool destroyed_{false};
  };

  TestingQuicClientTransport(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connIdSize = kDefaultConnectionIdSize,
      bool useConnectionEndWithErrorCallback = false)
      : QuicTransportBaseLite(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicClientTransport(
            evb,
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
            std::move(handshakeFactory),
            connIdSize,
            useConnectionEndWithErrorCallback) {}

  ~TestingQuicClientTransport() override {
    if (destructionCallback_) {
      destructionCallback_->markDestroyed();
    }
  }

  QuicTransportBase* getTransport() {
    return this;
  }

  const QuicClientConnectionState& getConn() const {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  QuicClientConnectionState& getNonConstConn() {
    return *dynamic_cast<QuicClientConnectionState*>(conn_.get());
  }

  const auto& getReadCallbacks() const {
    return readCallbacks_;
  }

  const auto& getDeliveryCallbacks() const {
    return deliveryCallbacks_;
  }

  auto getConnPendingWriteCallback() const {
    return connWriteCallback_;
  }

  auto getStreamPendingWriteCallbacks() const {
    return pendingWriteCallbacks_;
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  auto& writeLooper() {
    return writeLooper_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& ackTimeout() {
    return ackTimeout_;
  }

  auto& happyEyeballsConnAttemptDelayTimeout() {
    return happyEyeballsConnAttemptDelayTimeout_;
  }

  auto& drainTimeout() {
    return drainTimeout_;
  }

  bool isClosed() const {
    return closeState_ == CloseState::CLOSED;
  }

  bool isDraining() {
    return drainTimeout_.isTimerCallbackScheduled();
  }

  auto& serverInitialParamsSet() {
    return getNonConstConn().serverInitialParamsSet_;
  }

  auto& peerAdvertisedInitialMaxData() {
    return getConn().peerAdvertisedInitialMaxData;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiLocal() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiLocal;
  }

  auto& peerAdvertisedInitialMaxStreamDataBidiRemote() const {
    return getConn().peerAdvertisedInitialMaxStreamDataBidiRemote;
  }

  auto& peerAdvertisedInitialMaxStreamDataUni() const {
    return getConn().peerAdvertisedInitialMaxStreamDataUni;
  }

  void setDestructionCallback(
      std::shared_ptr<DestructionCallback> destructionCallback) {
    destructionCallback_ = std::move(destructionCallback);
  }

  void invokeOnNotifyDataAvailable(QuicAsyncUDPSocket& sock) {
    onNotifyDataAvailable(sock);
  }

 private:
  std::shared_ptr<DestructionCallback> destructionCallback_;
};

// Simulates a simple 1rtt handshake without needing to get any handshake bytes
// from the server.
class FakeOneRttHandshakeLayer : public FizzClientHandshake {
 public:
  explicit FakeOneRttHandshakeLayer(
      QuicClientConnectionState* conn,
      std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
      : FizzClientHandshake(
            conn,
            std::move(fizzContext),
            std::make_unique<FizzCryptoFactory>()) {}

  quic::Expected<Optional<CachedServerTransportParameters>, QuicError>
  connectImpl(Optional<std::string> hostname) override {
    // Look up psk
    auto quicCachedPsk = getPsk(hostname);

    Optional<CachedServerTransportParameters> transportParams;
    if (quicCachedPsk) {
      transportParams = quicCachedPsk->transportParams;
    }

    if (hostname.has_value()) {
      const_cast<fizz::client::State&>(getState()).sni() = hostname.value();
    } else {
      const_cast<fizz::client::State&>(getState()).sni() = folly::none;
    }

    connected_ = true;
    writeDataToQuicStream(
        getClientConn()->cryptoState->initialStream,
        folly::IOBuf::copyBuffer("CHLO"));
    createServerTransportParameters();
    return transportParams;
  }

  void createServerTransportParameters() {
    auto maxStreamDataBidiLocalResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_local,
        maxInitialStreamData);
    CHECK(!maxStreamDataBidiLocalResult.hasError())
        << "Failed to encode initial_max_stream_data_bidi_local";

    auto maxStreamDataBidiRemoteResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_bidi_remote,
        maxInitialStreamData);
    CHECK(!maxStreamDataBidiRemoteResult.hasError())
        << "Failed to encode initial_max_stream_data_bidi_remote";

    auto maxStreamDataUniResult = encodeIntegerParameter(
        TransportParameterId::initial_max_stream_data_uni,
        maxInitialStreamData);
    CHECK(!maxStreamDataUniResult.hasError())
        << "Failed to encode initial_max_stream_data_uni";

    auto maxStreamsBidiResult = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_bidi, maxInitialStreamsBidi);
    CHECK(!maxStreamsBidiResult.hasError())
        << "Failed to encode initial_max_streams_bidi";

    auto maxStreamsUniResult = encodeIntegerParameter(
        TransportParameterId::initial_max_streams_uni, maxInitialStreamsUni);
    CHECK(!maxStreamsUniResult.hasError())
        << "Failed to encode initial_max_streams_uni";

    auto maxDataResult = encodeIntegerParameter(
        TransportParameterId::initial_max_data, connWindowSize);
    CHECK(!maxDataResult.hasError()) << "Failed to encode initial_max_data";

    std::vector<TransportParameter> parameters;
    parameters.push_back(std::move(maxStreamDataBidiLocalResult.value()));
    parameters.push_back(std::move(maxStreamDataBidiRemoteResult.value()));
    parameters.push_back(std::move(maxStreamDataUniResult.value()));
    parameters.push_back(std::move(maxStreamsBidiResult.value()));
    parameters.push_back(std::move(maxStreamsUniResult.value()));
    parameters.push_back(std::move(maxDataResult.value()));

    auto idleTimeoutResult = encodeIntegerParameter(
        TransportParameterId::idle_timeout, kDefaultIdleTimeout.count());
    CHECK(!idleTimeoutResult.hasError()) << "Failed to encode idle_timeout";
    parameters.push_back(std::move(idleTimeoutResult.value()));

    auto maxPacketSizeResult = encodeIntegerParameter(
        TransportParameterId::max_packet_size, maxRecvPacketSize);
    CHECK(!maxPacketSizeResult.hasError())
        << "Failed to encode max_packet_size";
    parameters.push_back(std::move(maxPacketSizeResult.value()));
    ServerTransportParameters params;
    StatelessResetToken testStatelessResetToken = generateStatelessResetToken();
    TransportParameter statelessReset;
    statelessReset.parameter = TransportParameterId::stateless_reset_token;
    statelessReset.value = folly::IOBuf::copyBuffer(testStatelessResetToken);
    parameters.push_back(std::move(statelessReset));

    params.parameters = std::move(parameters);
    params_ = std::move(params);
  }

  void setServerTransportParams(ServerTransportParameters params) {
    params_ = std::move(params);
  }

  void setOneRttWriteCipher(std::unique_ptr<Aead> oneRttWriteCipher) {
    oneRttWriteCipher_ = std::move(oneRttWriteCipher);
    writeTrafficSecret_ = folly::IOBuf::copyBuffer(getRandSecret());
  }

  void setOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher) {
    getClientConn()->readCodec->setOneRttReadCipher(
        std::move(oneRttReadCipher));
    readTrafficSecret_ = folly::IOBuf::copyBuffer(getRandSecret());
  }

  void setNextOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher) {
    getClientConn()->readCodec->setNextOneRttReadCipher(
        std::move(oneRttReadCipher));
  }

  void setHandshakeReadCipher(std::unique_ptr<Aead> handshakeReadCipher) {
    getClientConn()->readCodec->setHandshakeReadCipher(
        std::move(handshakeReadCipher));
  }

  void setHandshakeWriteCipher(std::unique_ptr<Aead> handshakeWriteCipher) {
    getClientConn()->handshakeWriteCipher = std::move(handshakeWriteCipher);
  }

  void setZeroRttWriteCipher(std::unique_ptr<Aead> zeroRttWriteCipher) {
    getClientConn()->zeroRttWriteCipher = std::move(zeroRttWriteCipher);
  }

  void setZeroRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher) {
    getClientConn()->zeroRttWriteHeaderCipher =
        std::move(zeroRttWriteHeaderCipher);
  }

  void setHandshakeReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher) {
    getClientConn()->readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }

  void setHandshakeWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher) {
    getClientConn()->handshakeWriteHeaderCipher =
        std::move(handshakeWriteHeaderCipher);
  }

  void setOneRttWriteHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher) {
    oneRttWriteHeaderCipher_ = std::move(oneRttWriteHeaderCipher);
  }

  void setOneRttReadHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher) {
    getClientConn()->readCodec->setOneRttHeaderCipher(
        std::move(oneRttReadHeaderCipher));
  }

  void setZeroRttRejected(bool rejected, bool canResendZeroRtt) {
    setZeroRttRejectedForTest(rejected);
    setCanResendZeroRttForTest(canResendZeroRtt);
    if (rejected) {
      createServerTransportParameters();
    }
  }

  quic::Expected<void, QuicError> doHandshake(
      std::unique_ptr<folly::IOBuf> buf,
      EncryptionLevel level) override {
    EXPECT_EQ(writeBuf.get(), nullptr);
    QuicClientConnectionState* conn = getClientConn();
    if (!conn->oneRttWriteCipher) {
      conn->oneRttWriteCipher = std::move(oneRttWriteCipher_);
      conn->oneRttWriteHeaderCipher = std::move(oneRttWriteHeaderCipher_);
    }
    if (getPhase() == Phase::Initial) {
      conn->handshakeWriteCipher = test::createNoOpAead();
      conn->handshakeWriteHeaderCipher = test::createNoOpHeaderCipherNoThrow();
      conn->readCodec->setHandshakeReadCipher(test::createNoOpAead());
      conn->readCodec->setHandshakeHeaderCipher(
          test::createNoOpHeaderCipherNoThrow());
      writeDataToQuicStream(
          conn->cryptoState->handshakeStream,
          folly::IOBuf::copyBuffer("ClientFinished"));
      handshakeInitiated();
    }
    readBuffers[level].append(std::move(buf));
    return {};
  }

  bool connectInvoked() {
    return connected_;
  }

  const Optional<ServerTransportParameters>& getServerTransportParams()
      override {
    return params_;
  }

  quic::Expected<BufPtr, QuicError> getNextTrafficSecret(
      ByteRange /*secret*/) const override {
    return folly::IOBuf::copyBuffer(getRandSecret());
  }

  void triggerOnNewCachedPsk() {
    fizz::client::NewCachedPsk psk;
    onNewCachedPsk(psk);
  }

  std::unique_ptr<folly::IOBuf> writeBuf;

  bool connected_{false};
  QuicVersion negotiatedVersion{QuicVersion::MVFST};
  uint64_t maxRecvPacketSize{kDefaultMaxUDPPayload};
  uint64_t maxInitialStreamData{kDefaultStreamFlowControlWindow};
  uint64_t connWindowSize{kDefaultConnectionFlowControlWindow};
  uint64_t maxInitialStreamsBidi{std::numeric_limits<uint32_t>::max()};
  uint64_t maxInitialStreamsUni{std::numeric_limits<uint32_t>::max()};
  Optional<ServerTransportParameters> params_;
  EnumArray<EncryptionLevel, BufQueue> readBuffers{};

  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
  Optional<std::string> alpn_{std::nullopt};

  FizzCryptoFactory cryptoFactory_;

  const CryptoFactory& getCryptoFactory() const override {
    return cryptoFactory_;
  }

  // Implement virtual methods we don't intend to use.
  bool isTLSResumed() const override {
    throw std::runtime_error("isTLSResumed not implemented");
  }

  EncryptionLevel getReadRecordLayerEncryptionLevel() override {
    throw std::runtime_error(
        "getReadRecordLayerEncryptionLevel not implemented");
  }

  const Optional<std::string>& getApplicationProtocol() const override {
    return alpn_;
  }

  void processSocketData(quic::IOBufQueue&) override {
    throw std::runtime_error("processSocketData not implemented");
  }

  bool matchEarlyParameters() override {
    throw std::runtime_error("matchEarlyParameters not implemented");
  }

  quic::Expected<std::unique_ptr<Aead>, QuicError> buildAead(
      CipherKind,
      ByteRange) override {
    return createNoOpAead();
  }

  quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  buildHeaderCipher(ByteRange) override {
    return createNoOpHeaderCipher();
  }
};

class QuicClientTransportTestBase : public virtual testing::Test {
 public:
  QuicClientTransportTestBase()
      : eventbase_(std::make_unique<folly::EventBase>()),
        qEvb_(std::make_shared<FollyQuicEventBase>(eventbase_.get())) {}

  virtual ~QuicClientTransportTestBase() = default;

  struct TestReadData {
    ReceivedUdpPacket udpPacket;
    quic::SocketAddress addr;
    Optional<int> err;

    TestReadData(ByteRange dataIn, quic::SocketAddress addrIn)
        : udpPacket(folly::IOBuf::copyBuffer(dataIn)),
          addr(std::move(addrIn)) {}

    TestReadData(
        const ReceivedUdpPacket&& udpPacketIn,
        quic::SocketAddress addrIn)
        : udpPacket(
              udpPacketIn.buf.clone(),
              udpPacketIn.timings,
              udpPacketIn.tosValue),
          addr(std::move(addrIn)) {}

    explicit TestReadData(int errIn) : err(errIn) {}
  };

  std::shared_ptr<FizzClientQuicHandshakeContext> getFizzClientContext() {
    if (!fizzClientContext) {
      fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(createTestCertificateVerifier())
              .setPskCache(getPskCache())
              .build();
    }

    return fizzClientContext;
  }

  virtual std::shared_ptr<QuicPskCache> getPskCache() {
    return nullptr;
  }

  virtual bool getUseConnectionEndWithErrorCallback() {
    return false;
  }

  void SetUp() {
    auto socket =
        std::make_unique<testing::NiceMock<quic::test::MockAsyncUDPSocket>>(
            qEvb_);
    sock = socket.get();
    EXPECT_CALL(*sock, setAdditionalCmsgsFunc(testing::_))
        .WillRepeatedly(testing::Return(quic::Expected<void, QuicError>{}));
    EXPECT_CALL(*sock, close())
        .WillRepeatedly(testing::Return(quic::Expected<void, QuicError>{}));

    client = TestingQuicClientTransport::newClient<TestingQuicClientTransport>(
        qEvb_,
        std::move(socket),
        getFizzClientContext(),
        0 /* connectionIdSize */,
        getUseConnectionEndWithErrorCallback());
    destructionCallback =
        std::make_shared<TestingQuicClientTransport::DestructionCallback>();
    client->setDestructionCallback(destructionCallback);
    client->setSupportedVersions(
        {QuicVersion::MVFST,
         MVFST1,
         QuicVersion::QUIC_V1,
         QuicVersion::QUIC_V1_ALIAS});
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    ON_CALL(*sock, resumeRead(testing::_))
        .WillByDefault(testing::SaveArg<0>(&networkReadCallback));
    ON_CALL(*sock, address()).WillByDefault(testing::Return(serverAddr));
    ON_CALL(*sock, recvmsg(testing::_, testing::_))
        .WillByDefault(testing::Invoke([&](struct msghdr* msg, int) -> ssize_t {
          DCHECK_GT(msg->msg_iovlen, 0);
          if (socketReads.empty()) {
            errno = EAGAIN;
            return -1;
          }
          if (socketReads[0].err) {
            errno = *socketReads[0].err;
            return -1;
          }
          auto& udpPacket = socketReads[0].udpPacket;
          auto testData = std::move(udpPacket.buf.front());
          size_t testDataLen = testData->length();
          memcpy(
              msg->msg_iov[0].iov_base, testData->data(), testData->length());
          if (msg->msg_name) {
            socklen_t msg_len = socketReads[0].addr.getAddress(
                static_cast<sockaddr_storage*>(msg->msg_name));
            msg->msg_namelen = msg_len;
          }
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
          // Populate ToS control message as IPv6 TClass
          auto cmsg = CMSG_FIRSTHDR(msg);
          cmsg->cmsg_level = SOL_IPV6;
          cmsg->cmsg_type = IPV6_TCLASS;
          memcpy(
              CMSG_DATA(cmsg), &udpPacket.tosValue, sizeof(udpPacket.tosValue));
#endif
          socketReads.pop_front();
          return testDataLen;
        }));
    ON_CALL(*sock, getRecvTos()).WillByDefault(testing::Return(true));
    ON_CALL(*sock, getGSO()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, getGRO()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, getTimestamping()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, setTosOrTrafficClass(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, init(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, bind(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, connect(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, close())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setReuseAddr(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setDFAndTurnOffPMTU())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setErrMessageCallback(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, applyOptions(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setReusePort(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setRcvBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setSndBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, resumeWrite(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setGRO(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setRecvTos(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, appendCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setFD(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    EXPECT_EQ(client->getConn().selfConnectionIds.size(), 1);
    EXPECT_EQ(
        client->getConn().selfConnectionIds[0].connId,
        *client->getConn().clientConnectionId);
    EXPECT_EQ(client->getConn().peerConnectionIds.size(), 0);
    quicStats_ = std::make_shared<testing::NiceMock<MockQuicStats>>();
    client->setTransportStatsCallback(quicStats_);
    SetUpChild();
  }

  virtual void SetUpChild() {}

  void startTransport() {
    client->addNewPeerAddress(serverAddr);
    client->setHostname(hostname_);
    ON_CALL(*sock, write(testing::_, testing::_, testing::_))
        .WillByDefault(
            testing::Invoke([&](const quic::SocketAddress&,
                                const struct iovec* vec,
                                size_t iovec_len) {
              socketWrites.push_back(
                  copyChain(folly::IOBuf::wrapIov(vec, iovec_len)));
              return getTotalIovecLen(vec, iovec_len);
            }));
    ON_CALL(*sock, address()).WillByDefault(testing::Return(serverAddr));

    setupCryptoLayer();
    start();
    CHECK(!client->getNonConstConn()
               .streamManager
               ->setMaxLocalBidirectionalStreams(
                   std::numeric_limits<uint32_t>::max())
               .hasError());
    CHECK(!client->getNonConstConn()
               .streamManager
               ->setMaxLocalUnidirectionalStreams(
                   std::numeric_limits<uint32_t>::max())
               .hasError());
  }

  void destroyTransport() {
    client->unbindConnection();
    client = nullptr;
  }

  QuicTransportBase* getTransport() {
    return client->getTransport();
  }

  std::shared_ptr<TestingQuicClientTransport> getTestTransport() {
    return client;
  }

  const QuicClientConnectionState& getConn() const {
    return client->getConn();
  }

  QuicClientConnectionState& getNonConstConn() {
    return client->getNonConstConn();
  }

  MockConnectionSetupCallback& getConnSetupCallback() {
    return clientConnSetupCallback;
  }

  MockConnectionCallback& getConnCallback() {
    return clientConnCallback;
  }

  virtual void setupCryptoLayer() {
    // Fake that the handshake has already occurred and fix the keys.
    mockClientHandshake = new FakeOneRttHandshakeLayer(
        &client->getNonConstConn(), getFizzClientContext());
    client->getNonConstConn().clientHandshakeLayer = mockClientHandshake;
    client->getNonConstConn().handshakeLayer.reset(mockClientHandshake);
    setFakeHandshakeCiphers();
    // Allow ignoring path mtu for testing negotiation.
    client->getNonConstConn().transportSettings.canIgnorePathMTU = true;
  }

  virtual void setFakeHandshakeCiphers() {
    auto readAead = test::createNoOpAead();
    auto nextReadAead = test::createNoOpAead();
    auto writeAead = test::createNoOpAead();
    auto handshakeReadAead = test::createNoOpAead();
    auto handshakeWriteAead = test::createNoOpAead();
    mockClientHandshake->setHandshakeReadCipher(std::move(handshakeReadAead));
    mockClientHandshake->setHandshakeWriteCipher(std::move(handshakeWriteAead));
    mockClientHandshake->setOneRttReadCipher(std::move(readAead));
    mockClientHandshake->setNextOneRttReadCipher(std::move(nextReadAead));
    mockClientHandshake->setOneRttWriteCipher(std::move(writeAead));

    mockClientHandshake->setHandshakeReadHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setHandshakeWriteHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setOneRttWriteHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
    mockClientHandshake->setOneRttReadHeaderCipher(
        test::createNoOpHeaderCipherNoThrow());
  }

  virtual void setUpSocketExpectations() {
    EXPECT_CALL(*sock, setReuseAddr(false));
    EXPECT_CALL(*sock, bind(testing::_));
    EXPECT_CALL(*sock, setDFAndTurnOffPMTU());
    EXPECT_CALL(*sock, setErrMessageCallback(client.get()));
    EXPECT_CALL(*sock, resumeRead(client.get()));
    EXPECT_CALL(*sock, setErrMessageCallback(nullptr));
    EXPECT_CALL(*sock, write(testing::_, testing::_, testing::_))
        .Times(testing::AtLeast(1));
  }

  virtual void start() {
    EXPECT_CALL(clientConnSetupCallback, onTransportReady());
    EXPECT_CALL(clientConnSetupCallback, onReplaySafe());
    setUpSocketExpectations();
    client->start(&clientConnSetupCallback, &clientConnCallback);
    setConnectionIds();
    EXPECT_TRUE(client->idleTimeout().isTimerCallbackScheduled());

    EXPECT_EQ(socketWrites.size(), 1);
    EXPECT_TRUE(
        verifyLongHeader(*socketWrites.at(0), LongHeader::Types::Initial));
    socketWrites.clear();
    performFakeHandshake();
    EXPECT_TRUE(
        !client->getConn().readCodec->getStatelessResetTokens().empty());
    EXPECT_TRUE(client->getConn().statelessResetToken.has_value());
  }

  void setConnectionIds() {
    originalConnId = client->getConn().clientConnectionId;
    ConnectionIdData clientCidData(*originalConnId, 0);
    client->getNonConstConn().selfConnectionIds.emplace_back(clientCidData);
    ServerConnectionIdParams params(0, 0, 0);
    serverChosenConnId = *connIdAlgo_->encodeConnectionId(params);
  }

  void recvServerHello(const quic::SocketAddress& addr) {
    auto serverHello = folly::IOBuf::copyBuffer("Fake SHLO");
    ChainedByteRangeHead serverHelloRch(serverHello);
    PacketNum nextPacketNum = initialPacketNum++;
    auto& aead = getInitialCipher();
    auto packet = packetToBufCleartext(
        createCryptoPacket(
            *serverChosenConnId,
            *originalConnId,
            nextPacketNum,
            version,
            ProtectionType::Initial,
            serverHelloRch,
            aead,
            0 /* largestAcked */),
        aead,
        getInitialHeaderCipher(),
        nextPacketNum);
    deliverData(addr, packet->coalesce());
  }

  ConnectionId recvServerRetry(
      const quic::SocketAddress& addr,
      const std::string& retryToken = "token",
      bool corruptIntegrityTag = false) {
    // Make the server send a retry packet to the client. The server chooses a
    // connection id that the client must use in all future initial packets.
    std::vector<uint8_t> serverConnIdVec = {
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
    ConnectionId serverCid = ConnectionId::createAndMaybeCrash(serverConnIdVec);

    // Draft-29 has no QuicVersion member; the tag generator maps every non-V1
    // version to the draft-29 retry key.
    constexpr QuicVersionType kRetryVersion = 0xFF00001D;
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    const auto retryVersion = static_cast<QuicVersion>(kRetryVersion);
    PseudoRetryPacketBuilder pseudoBuilder(
        0xFF,
        serverCid,
        ConnectionId::createZeroLength(),
        *client->getConn().originalDestinationConnectionId,
        retryVersion,
        folly::IOBuf::copyBuffer(retryToken));
    auto pseudoPacket = std::move(pseudoBuilder).buildPacket();
    FizzRetryIntegrityTagGenerator tagGenerator;
    auto integrityTag =
        tagGenerator.getRetryIntegrityTag(retryVersion, pseudoPacket.get());
    if (corruptIntegrityTag) {
      integrityTag->writableData()[0] ^= 0x01;
    }

    folly::IOBuf retryPacketBuf;
    BufAppender appender(&retryPacketBuf, 100);
    appender.writeBE<uint8_t>(0xFF);
    appender.writeBE<QuicVersionType>(kRetryVersion);
    appender.writeBE<uint8_t>(0);
    appender.writeBE<uint8_t>(serverConnIdVec.size());
    appender.push(serverConnIdVec.data(), serverConnIdVec.size());
    appender.push((const uint8_t*)retryToken.data(), retryToken.size());
    appender.push(integrityTag->data(), integrityTag->length());
    deliverData(addr, retryPacketBuf.coalesce());
    return serverCid;
  }

  void recvServerHello() {
    recvServerHello(serverAddr);
  }

  void recvTicket(Optional<uint64_t> offsetOverride = std::nullopt) {
    auto negotiatedVersion = *client->getConn().version;
    auto ticket = folly::IOBuf::copyBuffer("NST");
    ChainedByteRangeHead ticketRch(ticket);
    auto packet = packetToBuf(createCryptoPacket(
        *serverChosenConnId,
        *originalConnId,
        appDataPacketNum++,
        negotiatedVersion,
        ProtectionType::KeyPhaseZero,
        ticketRch,
        *createNoOpAead(),
        0 /* largestAcked */,
        offsetOverride
            ? *offsetOverride
            : client->getConn().cryptoState->oneRttStream.currentReadOffset));
    deliverData(packet->coalesce());
  }

  void performFakeHandshake(const quic::SocketAddress& addr) {
    // Create a fake server response to trigger fetching keys.
    recvServerHello(addr);
    assertWritten(false, LongHeader::Types::Handshake);

    verifyTransportParameters(
        kDefaultConnectionFlowControlWindow,
        kDefaultStreamFlowControlWindow,
        kDefaultIdleTimeout,
        kDefaultAckDelayExponent,
        mockClientHandshake->maxRecvPacketSize);
    verifyCiphers();
    socketWrites.clear();
  }

  void performFakeHandshake() {
    performFakeHandshake(serverAddr);
  }

  void verifyTransportParameters(
      uint64_t connFlowControl,
      uint64_t initialStreamFlowControl,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxPacketSize) {
    EXPECT_EQ(
        client->getConn().flowControlState.peerAdvertisedMaxOffset,
        connFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
        initialStreamFlowControl);
    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
        initialStreamFlowControl);

    EXPECT_EQ(
        client->getConn()
            .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
        initialStreamFlowControl);
    EXPECT_EQ(client->getConn().peerIdleTimeout.count(), idleTimeout.count());
    EXPECT_EQ(client->getConn().peerAckDelayExponent, ackDelayExponent);
    EXPECT_EQ(client->getConn().udpSendPacketLen, maxPacketSize);
  }

  void verifyCiphers() {
    EXPECT_NE(client->getConn().oneRttWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteCipher, nullptr);
    EXPECT_NE(client->getConn().handshakeWriteHeaderCipher, nullptr);
    EXPECT_NE(client->getConn().oneRttWriteHeaderCipher, nullptr);

    EXPECT_NE(client->getConn().readCodec->getHandshakeHeaderCipher(), nullptr);
    EXPECT_NE(client->getConn().readCodec->getOneRttHeaderCipher(), nullptr);
  }

  void deliverNetworkError(int err) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(err);
    networkReadCallback->onNotifyDataAvailable(*sock);
  }

  void deliverDataWithoutErrorCheck(
      const quic::SocketAddress& addr,
      ByteRange data,
      bool writes = true) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(data, addr);
    networkReadCallback->onNotifyDataAvailable(*sock);
    if (writes) {
      loopForWrites();
    }
  }

  void deliverDataWithoutErrorCheck(
      ByteRange data,
      bool writes = true,
      quic::SocketAddress* peer = nullptr) {
    deliverDataWithoutErrorCheck(
        peer == nullptr ? serverAddr : *peer, data, writes);
  }

  void deliverDataWithoutErrorCheck(
      NetworkData&& data,
      bool writes = true,
      quic::SocketAddress* peer = nullptr) {
    for (const auto& packet : data.getPackets()) {
      deliverDataWithoutErrorCheck(
          peer == nullptr ? serverAddr : *peer,
          packet.buf.clone()->coalesce(),
          writes);
    }
  }

  void deliverData(
      const quic::SocketAddress& addr,
      ByteRange data,
      bool writes = true) {
    deliverDataWithoutErrorCheck(addr, data, writes);
    if (client->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          client->getConn().localConnectionError->code.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(*client->getConn().localConnectionError));
      }
    }
  }

  void deliverData(
      ByteRange data,
      bool writes = true,
      quic::SocketAddress* peer = nullptr) {
    deliverData(peer == nullptr ? serverAddr : *peer, data, writes);
  }

  void deliverDataWithoutErrorCheck(
      const quic::SocketAddress& addr,
      const ReceivedUdpPacket&& udpPacket,
      bool writes = true) {
    ASSERT_TRUE(networkReadCallback);
    socketReads.emplace_back(std::move(udpPacket), addr);
    networkReadCallback->onNotifyDataAvailable(*sock);
    if (writes) {
      loopForWrites();
    }
  }

  void deliverData(
      const quic::SocketAddress& addr,
      const ReceivedUdpPacket&& udpPacket,
      bool writes = true) {
    deliverDataWithoutErrorCheck(addr, std::move(udpPacket), writes);
    if (client->getConn().localConnectionError) {
      bool idleTimeout = false;
      const LocalErrorCode* localError =
          client->getConn().localConnectionError->code.asLocalErrorCode();
      if (localError) {
        idleTimeout = (*localError == LocalErrorCode::IDLE_TIMEOUT);
      }
      if (!idleTimeout) {
        throw std::runtime_error(
            toString(client->getConn().localConnectionError->code));
      }
    }
  }

  void deliverData(
      NetworkData&& data,
      bool writes = true,
      quic::SocketAddress* peer = nullptr) {
    for (const auto& packet : data.getPackets()) {
      deliverData(
          peer == nullptr ? serverAddr : *peer, std::move(packet), writes);
    }
  }

  // Expires the loss detection timeout as if its time had come.
  void fireLossTimeout() {
    client->lossTimeout().cancelTimerCallback();
    client->lossTimeout().timeoutExpired();
  }

  // Expires the idle timeout as if its time had come.
  void fireIdleTimeout() {
    client->idleTimeout().cancelTimerCallback();
    client->idleTimeout().timeoutExpired();
  }

  void loopForWrites() {
    // Loop the evb once to give writes some time to do their thing.
    eventbase_->loopOnce(EVLOOP_NONBLOCK);
  }

  void assertWritten(bool shortHeader, Optional<LongHeader::Types> longHeader) {
    size_t numShort = 0;
    size_t numLong = 0;
    size_t numOthers = 0;
    if (!socketWrites.empty()) {
      auto& write = socketWrites.back();
      if (shortHeader && verifyShortHeader(*write)) {
        numShort++;
      } else if (longHeader && verifyLongHeader(*write, *longHeader)) {
        numLong++;
      } else {
        numOthers++;
      }
    }
    if (shortHeader) {
      EXPECT_GT(numShort, 0);
    }
    if (longHeader) {
      EXPECT_GT(numLong, 0);
    }
    EXPECT_EQ(numOthers, 0);
  }

  RegularQuicPacket* parseRegularQuicPacket(CodecResult& codecResult) {
    return codecResult.regularPacket();
  }

  void verifyShortPackets(AckBlocks& sentPackets) {
    AckStates ackStates;
    for (auto& write : socketWrites) {
      auto packetQueue = bufToQueue(write->clone());
      auto codecResult =
          makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
      auto parsedPacket = parseRegularQuicPacket(codecResult);
      if (!parsedPacket) {
        continue;
      }
      PacketNum packetNumSent = parsedPacket->header.getPacketSequenceNum();
      sentPackets.insert(packetNumSent);
      verifyShortHeader(*write);
    }
  }

  bool verifyLongHeader(
      folly::IOBuf& buf,
      typename LongHeader::Types headerType) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    auto longHeader = parsedPacket->header.asLong();
    return longHeader && longHeader->getHeaderType() == headerType;
  }

  bool verifyShortHeader(folly::IOBuf& buf) {
    AckStates ackStates;
    auto packetQueue = bufToQueue(buf.clone());
    auto codecResult =
        makeEncryptedCodec(true)->parsePacket(packetQueue, ackStates);
    auto parsedPacket = parseRegularQuicPacket(codecResult);
    if (!parsedPacket) {
      return false;
    }
    return parsedPacket->header.asShort();
  }

  std::unique_ptr<QuicReadCodec> makeHandshakeCodec() {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    codec->setClientConnectionId(*originalConnId);
    codec->setInitialReadCipher(
        cryptoFactory
            .getClientInitialCipher(
                *client->getConn().initialDestinationConnectionId,
                QuicVersion::MVFST)
            .value());
    codec->setInitialHeaderCipher(
        cryptoFactory
            .makeClientInitialHeaderCipher(
                *client->getConn().initialDestinationConnectionId,
                QuicVersion::MVFST)
            .value());
    codec->setHandshakeReadCipher(test::createNoOpAead());
    codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher().value());
    return codec;
  }

  std::unique_ptr<QuicReadCodec> makeEncryptedCodec(
      bool handshakeCipher = false) {
    FizzCryptoFactory cryptoFactory;
    auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    std::unique_ptr<Aead> handshakeReadCipher;
    codec->setClientConnectionId(*originalConnId);
    codec->setOneRttReadCipher(test::createNoOpAead());
    codec->setOneRttHeaderCipher(test::createNoOpHeaderCipher().value());
    codec->setZeroRttReadCipher(test::createNoOpAead());
    codec->setZeroRttHeaderCipher(test::createNoOpHeaderCipher().value());
    if (handshakeCipher) {
      auto initialReadCipher = cryptoFactory.getClientInitialCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST);
      CHECK(initialReadCipher.has_value());
      codec->setInitialReadCipher(std::move(initialReadCipher.value()));

      auto initialHeaderCipher = cryptoFactory.makeClientInitialHeaderCipher(
          *client->getConn().initialDestinationConnectionId,
          QuicVersion::MVFST);
      CHECK(initialHeaderCipher.has_value());
      codec->setInitialHeaderCipher(std::move(initialHeaderCipher.value()));

      codec->setHandshakeReadCipher(test::createNoOpAead());
      codec->setHandshakeHeaderCipher(test::createNoOpHeaderCipher().value());
    }
    return codec;
  }

  const Aead& getInitialCipher() {
    return *client->getConn().readCodec->getInitialCipher();
  }

  const PacketNumberCipher& getInitialHeaderCipher() {
    return *client->getConn().readCodec->getInitialHeaderCipher();
  }

  void expectQuicStatsPacketDrop(PacketDropReason expectedReason) {
    quicStats_ = std::make_shared<testing::NiceMock<MockQuicStats>>();
    EXPECT_CALL(*quicStats_, onPacketDropped(testing::_))
        .WillOnce(testing::Invoke([=](PacketDropReason reason) {
          EXPECT_EQ(expectedReason, reason);
        }));
    client->setTransportStatsCallback(quicStats_);
  }

 protected:
  std::vector<std::unique_ptr<folly::IOBuf>> socketWrites;
  std::deque<TestReadData> socketReads;
  testing::NiceMock<MockDeliveryCallback> deliveryCallback;
  testing::NiceMock<MockReadCallback> readCb;
  testing::NiceMock<MockConnectionSetupCallback> clientConnSetupCallback;
  testing::NiceMock<MockConnectionCallback> clientConnCallback;
  quic::test::MockAsyncUDPSocket* sock;
  std::shared_ptr<TestingQuicClientTransport::DestructionCallback>
      destructionCallback;
  std::unique_ptr<folly::EventBase> eventbase_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  quic::SocketAddress serverAddr{"127.0.0.1", 443};
  QuicAsyncUDPSocket::ReadCallback* networkReadCallback{nullptr};
  FakeOneRttHandshakeLayer* mockClientHandshake;
  std::shared_ptr<FizzClientQuicHandshakeContext> fizzClientContext;
  std::shared_ptr<TestingQuicClientTransport> client;
  PacketNum initialPacketNum{0}, handshakePacketNum{0}, appDataPacketNum{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  Optional<ConnectionId> originalConnId;
  Optional<ConnectionId> serverChosenConnId;
  QuicVersion version{QuicVersion::QUIC_V1};
  std::shared_ptr<testing::NiceMock<MockQuicStats>> quicStats_;
  std::string hostname_{"TestHost"};
};

class QuicClientTransportAfterStartTestBase
    : public QuicClientTransportTestBase {
 public:
  void SetUpChild() override {
    startTransport();
  }
};

std::unique_ptr<testing::NiceMock<quic::test::MockAsyncUDPSocket>>
getMockSocketWithExpectations(std::shared_ptr<FollyQuicEventBase> qEvb) {
  using testing::_;
  auto newSocket =
      std::make_unique<testing::NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
  ON_CALL(*newSocket, setReuseAddr(_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setAdditionalCmsgsFunc(_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setDFAndTurnOffPMTU())
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setErrMessageCallback(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setTosOrTrafficClass(_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, init(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, applyOptions(testing::_, testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, bind(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, connect(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, close())
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, resumeWrite(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setGRO(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setRecvTos(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, getRecvTos()).WillByDefault(testing::Return(false));
  ON_CALL(*newSocket, setCmsgs(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, appendCmsgs(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, getTimestamping()).WillByDefault(testing::Return(0));
  ON_CALL(*newSocket, setReusePort(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setRcvBuf(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setSndBuf(testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
  ON_CALL(*newSocket, setFD(testing::_, testing::_))
      .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));

  return newSocket;
}

} // namespace quic::test
