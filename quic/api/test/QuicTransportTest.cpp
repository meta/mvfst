/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/api/test/TestQuicTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/HighResQuicTimer.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/logging/test/Mocks.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/Mocks.h>

#include <memory>

using namespace folly;
// using namespace folly::test;
using namespace testing;

namespace quic::test {

namespace {
template <typename Transport>
void dispatchNetworkData(
    Transport& t,
    const quic::SocketAddress& localAddr,
    NetworkData networkData,
    const quic::SocketAddress& peerAddr) {
  networkData.setPeerAddressForAllPackets(peerAddr);
  t.onNetworkData(localAddr, std::move(networkData));
}
} // namespace

/**
 * A DeliveryCallback that closes your transport when it's canceled, or when
 * the targetOffset is delivered. Booyah!
 */
class TransportClosingDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  explicit TransportClosingDeliveryCallback(
      TestQuicTransport* transport,
      uint64_t targetOffset)
      : transport_(transport), targetOffset_(targetOffset) {}

  void onDeliveryAck(StreamId, uint64_t offset, std::chrono::microseconds)
      override {
    if (offset >= targetOffset_) {
      transport_->close(std::nullopt);
    }
  }

  void onCanceled(StreamId, uint64_t) override {
    transport_->close(std::nullopt);
  }

 private:
  TestQuicTransport* transport_{nullptr};
  uint64_t targetOffset_;
};

class QuicTransportTest : public Test {
 public:
  QuicTransportTest() {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
  }

  ~QuicTransportTest() override = default;

  void SetUp() override {
    std::unique_ptr<MockAsyncUDPSocket> sock =
        std::make_unique<NiceMock<MockAsyncUDPSocket>>(qEvb_);
    socket_ = sock.get();
    ON_CALL(*socket_, setAdditionalCmsgsFunc(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setTosOrTrafficClass(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, close())
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, getGSO()).WillByDefault(Return(0));
    ON_CALL(*socket_, init(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, bind(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, connect(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setRecvTos(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setReuseAddr(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setReusePort(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setRcvBuf(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setSndBuf(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, setErrMessageCallback(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket_, applyOptions(_, _))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    transport_ = std::make_shared<TestQuicTransport>(
        qEvb_, std::move(sock), &connSetupCallback_, &connCallback_);
    // Set the write handshake state to tell the client that the handshake has
    // a cipher.
    auto aead = createNoOpAead();
    aead_ = aead.get();
    EXPECT_CALL(*aead_, _inplaceEncrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    EXPECT_CALL(*aead_, _decrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    transport_->getConnectionState().oneRttWriteCipher = std::move(aead);
    auto tempHeaderCipher = test::createNoOpHeaderCipher().value();
    tempHeaderCipher->setDefaultKey();
    transport_->getConnectionState().oneRttWriteHeaderCipher =
        std::move(tempHeaderCipher);
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    transport_->getConnectionState().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    CHECK(
        !transport_->getConnectionState()
             .streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!transport_->getConnectionState()
               .streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
  }

  void loopForWrites() {
    // loop once to allow writes to take effect.
    evb_.loopOnce(EVLOOP_NONBLOCK);
  }

  auto getTxMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getTxMatcher(id, offset);
  }

  StreamId nextScheduledStreamID(QuicConnectionStateBase& conn) {
    return conn.streamManager->writeQueue().peekNextScheduledID().asStreamID();
  }

 protected:
  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  MockAsyncUDPSocket* socket_;
  NiceMock<MockConnectionSetupCallback> connSetupCallback_;
  NiceMock<MockConnectionCallback> connCallback_;
  NiceMock<MockWriteCallback> writeCallback_;
  MockAead* aead_;
  std::shared_ptr<TestQuicTransport> transport_;
};

RegularQuicWritePacket stripPaddingFrames(RegularQuicWritePacket packet) {
  RegularQuicWritePacket::Vec trimmedFrames{};
  for (auto frame : packet.frames) {
    if (!frame.asPaddingFrame()) {
      trimmedFrames.push_back(frame);
    }
  }
  packet.frames = trimmedFrames;
  return packet;
}

void dropPackets(QuicConnectionStateBase& conn) {
  for (const auto& packet : conn.outstandings.packets) {
    for (const auto& frame : packet.packet.frames) {
      const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
      if (!streamFrame) {
        continue;
      }
      auto stream = conn.streamManager->findStream(streamFrame->streamId);
      ASSERT_TRUE(stream);
      auto itr = stream->retransmissionBuffer.find(streamFrame->offset);
      ASSERT_TRUE(itr != stream->retransmissionBuffer.end());
      stream->lossBuffer.insert(
          std::upper_bound(
              stream->lossBuffer.begin(),
              stream->lossBuffer.end(),
              itr->second->offset,
              [](const auto& offset, const auto& buffer) {
                return offset < buffer.offset;
              }),
          std::move(*itr->second));
      stream->retransmissionBuffer.erase(itr);
      conn.streamManager->updateWritableStreams(*stream);
    }
  }
  conn.outstandings.reset();
}

// Helper function to verify the data of buffer is written to outstanding
// packets
void verifyCorrectness(
    const QuicConnectionStateBase& conn,
    size_t originalWriteOffset,
    StreamId id,
    const folly::IOBuf& expected,
    bool finExpected = false,
    bool writeAll = true) {
  uint64_t endOffset = 0;
  size_t totalLen = 0;
  bool finSet = false;
  std::vector<uint64_t> offsets;
  for (const auto& packet : conn.outstandings.packets) {
    for (const auto& frame : packet.packet.frames) {
      auto streamFrame = frame.asWriteStreamFrame();
      if (!streamFrame) {
        continue;
      }
      if (streamFrame->streamId != id) {
        continue;
      }
      offsets.push_back(streamFrame->offset);
      endOffset = std::max(endOffset, streamFrame->offset + streamFrame->len);
      totalLen += streamFrame->len;
      finSet |= streamFrame->fin;
    }
  }
  auto stream = conn.streamManager->findStream(id);
  ASSERT_TRUE(stream);
  if (writeAll) {
    EXPECT_TRUE(stream->pendingWrites.empty());
  }
  EXPECT_EQ(stream->currentWriteOffset, endOffset + (finSet ? 1 : 0));
  EXPECT_EQ(
      stream->currentWriteOffset,
      originalWriteOffset + totalLen + (finSet ? 1 : 0));
  EXPECT_EQ(totalLen, expected.computeChainDataLength());
  EXPECT_EQ(finExpected, finSet);
  // Verify retransmissionBuffer:
  EXPECT_FALSE(stream->retransmissionBuffer.empty());
  BufQueue retxBufCombined;
  std::vector<StreamBuffer> rtxCopy;
  for (auto& itr : stream->retransmissionBuffer) {
    rtxCopy.emplace_back(
        folly::IOBuf::copyBuffer(itr.second->data.getHead()->getRange()),
        itr.second->offset,
        itr.second->eof);
  }
  std::sort(rtxCopy.begin(), rtxCopy.end(), [](auto& s1, auto& s2) {
    return s1.offset < s2.offset;
  });
  for (auto& s : rtxCopy) {
    retxBufCombined.append(s.data.move());
  }
  EXPECT_TRUE(IOBufEqualTo()(expected, *retxBufCombined.move()));
  EXPECT_EQ(finExpected, stream->retransmissionBuffer.at(offsets.back())->eof);
  std::vector<uint64_t> retxBufOffsets;
  for (const auto& b : stream->retransmissionBuffer) {
    retxBufOffsets.push_back(b.second->offset);
  }
  std::sort(retxBufOffsets.begin(), retxBufOffsets.end());
  EXPECT_EQ(offsets, retxBufOffsets);
}

TEST_F(QuicTransportTest, WriteDataWithProbing) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen * 2);
  conn.pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
  // Probing won't ask about getWritableBytes. Then regular write may ask
  // multiple times:
  int getWritableBytesCounter = 0;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        getWritableBytesCounter++;
        return kDefaultUDPSendPacketLen;
      }));
  // Probing will invoke onPacketSent once. Then regular write may invoke
  // multiple times:
  int onPacketSentCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(
          Invoke([&](const auto& /* packet */) { onPacketSentCounter++; }));
  // Probing will send out one. Then regular write may send out multiple ones:
  int socketWriteCounter = 0;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(Invoke(
          [&](const SocketAddress&, const struct iovec* vec, size_t iovec_len) {
            socketWriteCounter++;
            return getTotalIovecLen(vec, iovec_len);
          }));
  auto writeChain1 = transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLoss) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto lossStream = transport_->createBidirectionalStream().value();
  auto lossStreamState = conn.streamManager->findStream(lossStream);
  ASSERT_TRUE(lossStreamState);
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 20, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  ChainedByteRangeHead largeBufRch(largeBuf);
  lossStreamState->lossBuffer.emplace_back(std::move(largeBufRch), 31, false);
  conn.streamManager->updateWritableStreams(*lossStreamState);
  auto writeChain2 = transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, NotAppLimitedWithNoWritableBytes) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        if (conn.outstandings.packets.empty()) {
          return 5000;
        }
        return 0;
      }));

  auto stream = transport_->createBidirectionalStream().value();
  auto writeChain3 = transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLargeBuffer) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100 * 2000);
  auto writeChain4 =
      transport_->writeChain(stream, buf->clone(), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, AppLimited) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  transport_->setTransportReadyNotified(true);
  auto stream = transport_->createBidirectionalStream().value();
  auto writeChain5 = transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(1);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(1);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, ObserverNotAppLimitedWithNoWritableBytes) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        if (conn.outstandings.packets.empty()) {
          return 5000;
        }
        return 0;
      }));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto stream = transport_->createBidirectionalStream().value();
  auto writeChain6 = transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _)).Times(0);
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _)).Times(0);
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb3, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb3, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverNotAppLimitedWithLargeBuffer) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100 * 2000);
  auto writeChain7 =
      transport_->writeChain(stream, buf->clone(), false, nullptr);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _)).Times(0);
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _)).Times(0);
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb3, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb3, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverAppLimited) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto writeChain8 = transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(1);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _));
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  Mock::VerifyAndClearExpectations(cb3.get());
  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb3, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb3, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverPacketsWrittenCycleCheckDetails) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();
  uint64_t writeNum = 1;

  /**
   * part 1: write of non-ACK eliciting packet triggered by scheduled ACK.
   */

  // expectations:
  //   - write number is 1.
  //   - one packet sent, zero ACK eliciting packets sent.
  //   - no outstanding packets from this write or previous writes.
  {
    const auto writeEventMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(0)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)));
    const auto packetsWrittenEventMatcher = AllOf(
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(transport_.get(), writeEventMatcher));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
             MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              packetsWritten(
                  transport_.get(),
                  AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), writeEventMatcher));
        }));
  }

  // schedule the ACK
  {
    PacketNum start = 10;
    PacketNum end = 15;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  /**
   * part 2: write of ACK eliciting packets triggered by stream write.
   *
   * multiple writes back to back.
   */

  // expectations:
  //   - two writes will be triggered, write numbers 2 and 3
  //   - five ACK eliciting packets sent first write, two sent on second write
  //   - total of seven outstanding packets
  {
    // part 2.1, we go from app limited to writing, no outstandings yet
    writeNum++;
    EXPECT_EQ(2, writeNum);
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(0)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));

      invokeForEachObserverWithTestEvents(([this, &writeEventMatcher](
                                               MockLegacyObserver& observer) {
        EXPECT_CALL(
            observer,
            startWritingFromAppLimited(transport_.get(), writeEventMatcher));
      }));
    }

    // part 2.2, we write five ACK eliciting packets
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(5)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(5)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(5)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
    }

    // part 2.3, we write two ACK eliciting packets, then become app limited
    writeNum++;
    EXPECT_EQ(3, writeNum);
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(7)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(2)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(2)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher](MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer, appRateLimited(transport_.get(), writeEventMatcher));
          }));
    }
  }

  // write some data
  auto stream = transport_->createBidirectionalStream().value();
  auto writeChain9 = transport_->writeChain(
      stream, buildRandomInputData(8000), false, nullptr);

  // loop twice to get all packets cleared out
  transport_->updateWriteLooper(true);
  loopForWrites();
  loopForWrites();

  /**
   * part 3: write of ACK eliciting frames with non-ACK eliciting frames.
   *   - ACK eliciting frames triggered by stream write.
   *   - non-ACK eliciting frames triggered by pending ACK.
   *   - all packets will be ACK eliciting.
   */

  // expectations:
  //   - write number is 4.
  //   - two ACK eliciting packets written.
  //   - total of nine outstanding packets.
  {
    writeNum++;
    EXPECT_EQ(4, writeNum);

    // part 3.1, we go from app limited to writing, previous outstandings
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(7)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));

      invokeForEachObserverWithTestEvents(([this, &writeEventMatcher](
                                               MockLegacyObserver& observer) {
        EXPECT_CALL(
            observer,
            startWritingFromAppLimited(transport_.get(), writeEventMatcher));
      }));
    }

    // part 3.2, we write two ACK eliciting packets, then become app limited
    // one of the ACK eliciting packets contains an ACK frame
    {
      // older versions of gtest do not seem to accept lambdas for ResultOf
      // matcher, so define an std::function
      std::function<uint64_t(const SocketObserverInterface::WriteEvent&)>
          countPacketsWithAckFrames =
              [](const SocketObserverInterface::WriteEvent& event) -> uint64_t {
        uint64_t packetsWithAckFrames = 0;
        for (auto& outstandingPacket : event.outstandingPackets) {
          bool hasAckFrame = false;
          for (auto& frame : outstandingPacket.packet.frames) {
            if (frame.asWriteAckFrame()) {
              hasAckFrame = true;
            }
          }

          if (hasAckFrame) {
            packetsWithAckFrames++;
          }
        }
        return packetsWithAckFrames;
      };

      const auto writeEventMatcher = AllOf(
          testing::ResultOf(countPacketsWithAckFrames, 1),
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(9)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(2)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(2)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher](MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer, appRateLimited(transport_.get(), writeEventMatcher));
          }));
    }
  }

  // schedule the ACK
  {
    PacketNum start = 20;
    PacketNum end = 25;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // write some more data
  auto writeChain10 = transport_->writeChain(
      stream, buildRandomInputData(2000), false, nullptr);

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  /**
   * part 4: write of non-ACK eliciting packet triggered by scheduled ACK.
   *
   * (repeat of part 1, writing only non-ACK eliciting packets)
   */

  // expectations:
  //   - write number is 5.
  //   - one packet sent, zero ACK eliciting packets sent.
  //   - outstanding packets from previous write remain
  {
    writeNum++;
    EXPECT_EQ(5, writeNum);

    const auto writeEventMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(9)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)));
    const auto packetsWrittenEventMatcher = AllOf(
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(transport_.get(), writeEventMatcher));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
             MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              packetsWritten(
                  transport_.get(),
                  AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), writeEventMatcher));
        }));
  }

  // schedule the ACK
  {
    PacketNum start = 30;
    PacketNum end = 35;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closeStarted(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closing(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverPacketsWrittenCheckBytesSent) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();
  uint64_t writeNum = 1;

  // write of 4000 stream bytes
  {
    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(4000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    auto writeChain11 = transport_->writeChain(
        stream, buildRandomInputData(4000), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();
  }

  // another write of 1000 stream bytes
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(1000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    auto writeChain12 = transport_->writeChain(
        stream, buildRandomInputData(1000), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  // send an ACK
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    PacketNum start = 20;
    PacketNum end = 25;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  // another write of 1000 stream bytes AND some ACKs in same packet
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(6)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(1000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    PacketNum start = 30;
    PacketNum end = 35;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
    auto stream = transport_->createBidirectionalStream().value();
    auto writeChain13 = transport_->writeChain(
        stream, buildRandomInputData(1000), false, nullptr);

    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closeStarted(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closing(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverWriteEventsCheckCwndPacketsWritable) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();

  // install StaticCwndCongestionController
  const auto cwndInBytes = 10000;
  conn.congestionController = std::make_unique<StaticCwndCongestionController>(
      conn, StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  // update writeNum and upperBoundCurrentBytesWritable after each write/ACK
  uint64_t writeNum = 1;
  uint64_t upperBoundCurrentBytesWritable = cwndInBytes;

  // write of 4000 stream bytes
  {
    const auto bytesToWrite = 4000;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(bytesToWrite)));

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))));

    invokeForEachObserverWithTestEvents(
        ([this,
          &startWritingFromAppLimitedMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(
                  transport_.get(), startWritingFromAppLimitedMatcher));
        }));

    invokeForEachObserverWithTestEvents(
        ([this,
          &packetsWrittenMatcher,
          cwndInBytes,
          oldTInfo =
              transport_->getTransportInfo()](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, packetsWritten(transport_.get(), packetsWrittenMatcher))
              .WillOnce(([cwndInBytes, oldTInfo](
                             const auto& socket, const auto& event) {
                EXPECT_EQ(
                    cwndInBytes - socket->getTransportInfo().bytesSent -
                        oldTInfo.bytesSent,
                    event.maybeWritableBytes);
              }));
        }));

    invokeForEachObserverWithTestEvents(
        ([this,
          &appRateLimitedMatcher,
          cwndInBytes,
          oldTInfo =
              transport_->getTransportInfo()](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), appRateLimitedMatcher))
              .WillOnce(([cwndInBytes, oldTInfo](
                             const auto& socket, const auto& event) {
                EXPECT_EQ(
                    cwndInBytes - socket->getTransportInfo().bytesSent -
                        oldTInfo.bytesSent,
                    event.maybeWritableBytes);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    auto writeChain14 = transport_->writeChain(
        stream, buildRandomInputData(bytesToWrite), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();

    // remove bytesToWrite from upperBoundCurrentBytesWritable
    upperBoundCurrentBytesWritable -= bytesToWrite;
    writeNum++;
  }

  // another write of 1000 stream bytes
  {
    const auto bytesToWrite = 1000;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(upperBoundCurrentBytesWritable))));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(bytesToWrite)));

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))));

    invokeForEachObserverWithTestEvents(
        ([this,
          &startWritingFromAppLimitedMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(
                  transport_.get(), startWritingFromAppLimitedMatcher));
        }));

    invokeForEachObserverWithTestEvents(([this,
                                          &packetsWrittenMatcher,
                                          oldTInfo =
                                              transport_->getTransportInfo()](
                                             MockLegacyObserver& observer) {
      EXPECT_CALL(
          observer, packetsWritten(transport_.get(), packetsWrittenMatcher))
          .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
            EXPECT_EQ(
                oldTInfo.writableBytes -
                    (socket->getTransportInfo().bytesSent - oldTInfo.bytesSent),
                event.maybeWritableBytes);
          }));
    }));

    invokeForEachObserverWithTestEvents(([this,
                                          &appRateLimitedMatcher,
                                          oldTInfo =
                                              transport_->getTransportInfo()](
                                             MockLegacyObserver& observer) {
      EXPECT_CALL(
          observer, appRateLimited(transport_.get(), appRateLimitedMatcher))
          .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
            EXPECT_EQ(
                oldTInfo.writableBytes -
                    (socket->getTransportInfo().bytesSent - oldTInfo.bytesSent),
                event.maybeWritableBytes);
          }));
    }));

    auto stream = transport_->createBidirectionalStream().value();
    auto writeChain15 = transport_->writeChain(
        stream, buildRandomInputData(bytesToWrite), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();

    // remove bytesToWrite from upperBoundCurrentBytesWritable
    upperBoundCurrentBytesWritable -= bytesToWrite;
    writeNum++;
  }

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closeStarted(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, closing(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(std::nullopt);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventBidirectionalLocalOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x01;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Local, StreamDirectionality::Bidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  EXPECT_EQ(id, transport_->createBidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));
  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventBidirectionalRemoteOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x00;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Remote, StreamDirectionality::Bidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventUnidirectionalLocalOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x03;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Local, StreamDirectionality::Unidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  EXPECT_EQ(id, transport_->createUnidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventUnidirectionalRemoteOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x02;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Remote, StreamDirectionality::Unidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_CALL(*cb1, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport_.get(), _));
  EXPECT_CALL(*cb1, closing(transport_.get(), _));
  EXPECT_CALL(*cb2, closing(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, StreamBidirectionalLocal) {
  const auto id = 0x01;
  EXPECT_EQ(id, transport_->createBidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamBidirectionalRemote) {
  const auto id = 0x00;
  // trigger tracking of new remote stream via getStream()
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamUnidirectionalLocal) {
  const auto id = 0x03;
  EXPECT_EQ(id, transport_->createUnidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamUnidirectionalRemote) {
  const auto id = 0x02;
  // trigger tracking of new remote stream via getStream()
  auto streamExpected =
      transport_->getConnectionState().streamManager->getStream(id);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  ASSERT_NE(stream, nullptr);

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, WriteSmall) {
  // Testing writing a small buffer that could be fit in a single packet
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain16 = transport_->writeChain(stream, buf->clone(), false);
  auto setPriority1 = transport_->setStreamPriority(
      stream, HTTPPriorityQueue::Priority(0, false));
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());

  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteLarge) {
  // Testing writing a large buffer that would span multiple packets
  constexpr int NumFullPackets = 3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf =
      buildRandomInputData(NumFullPackets * kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain17 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(NumFullPackets + 1, conn.outstandings.packets.size());
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  EXPECT_EQ(NumFullPackets + 1, conn.outstandings.packets.size());
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleTimes) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain18 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  size_t originalWriteOffset =
      conn.streamManager->findStream(stream)->currentWriteOffset;
  verifyCorrectness(conn, 0, stream, *buf);

  conn.outstandings.reset();
  conn.streamManager->findStream(stream)->retransmissionBuffer.clear();
  buf = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain19 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  verifyCorrectness(conn, originalWriteOffset, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleStreams) {
  // Testing writing to multiple streams
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain20 = transport_->writeChain(s1, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, s1, *buf);

  auto buf2 = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain21 = transport_->writeChain(s2, buf2->clone(), false);
  loopForWrites();
  verifyCorrectness(conn, 0, s2, *buf2);

  dropPackets(conn);

  // Should retransmit lost streams in a single packet
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  verifyCorrectness(conn, 0, s1, *buf);
  verifyCorrectness(conn, 0, s2, *buf2);
}

TEST_F(QuicTransportTest, WriteFlowControl) {
  auto& conn = transport_->getConnectionState();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn.qLogger = mockQLogger;

  auto streamId = transport_->createBidirectionalStream().value();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto& stream = streamResult.value();
  stream->flowControlState.peerAdvertisedMaxOffset = 100;
  stream->currentWriteOffset = 100;
  stream->conn.flowControlState.sumCurWriteOffset = 100;
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 220;

  auto buf = buildRandomInputData(150);
  folly::IOBuf passedIn;
  // Write stream blocked frame
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain22 = transport_->writeChain(streamId, buf->clone(), false);

  loopForWrites();
  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  const auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool blockedFound = false;
  bool dataBlockedFound = false;
  for (auto& frame : packet.frames) {
    auto blocked = frame.asStreamDataBlockedFrame();
    auto dataBlocked = frame.asDataBlockedFrame();
    if (!blocked && !dataBlocked) {
      continue;
    }
    if (blocked) {
      EXPECT_EQ(blocked->streamId, streamId);
      blockedFound = true;
    }
  }
  EXPECT_TRUE(blockedFound);
  EXPECT_FALSE(dataBlockedFound);
  conn.outstandings.reset();

  // Stream flow control
  auto buf1 = buf->clone();
  buf1->trimEnd(50);
  stream->flowControlState.peerAdvertisedMaxOffset = 200;
  // Reset the pendingBlockedFrame as if we received a flow control update.
  stream->flowControlState.pendingBlockedFrame = false;
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  verifyCorrectness(conn, 100, streamId, *buf1, false, false);

  // Connection flow controlled
  auto num_outstandings = conn.outstandings.packets.size();
  stream->flowControlState.peerAdvertisedMaxOffset = 300;
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _, _))
      .Times(2)
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes2 = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes2.hasError());
  auto buf2 = buf->clone();
  buf2->trimEnd(30);
  verifyCorrectness(conn, 100, streamId, *buf2, false, false);

  // Verify that there is one Data Blocked frame emitted.
  EXPECT_EQ(conn.outstandings.packets.size(), num_outstandings + 2);
  const auto& packet2 =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  dataBlockedFound = false;
  for (auto& frame : packet2.frames) {
    auto dataBlocked = frame.asDataBlockedFrame();
    if (!dataBlocked) {
      continue;
    }
    EXPECT_FALSE(dataBlockedFound);
    EXPECT_EQ(dataBlocked->dataLimit, 220);
    dataBlockedFound = true;
  }
  EXPECT_TRUE(dataBlockedFound);

  // Try again, verify that there should not be any Data blocked frame emitted
  // again.
  EXPECT_CALL(*socket_, write(_, _, _)).Times(0);
  auto writeRes3 = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes3.hasError());

  // Flow control lifted
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 300;
  conn.streamManager->onMaxData();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes4 = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes4.hasError());
  verifyCorrectness(conn, 100, streamId, *buf, false, false);
}

TEST_F(QuicTransportTest, WriteErrorEagain) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  auto writeChain23 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
}

TEST_F(QuicTransportTest, WriteErrorBad) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  auto writeChain24 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_TRUE(transport_->closed);
}

TEST_F(QuicTransportTest, WriteInvalid) {
  // Test writing to invalid stream
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  auto res = transport_->writeChain(stream + 2, buf->clone(), false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, res.error());
}

TEST_F(QuicTransportTest, WriteFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain25 = transport_->writeChain(stream, buf->clone(), true);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteOnlyFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain26 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain27 = transport_->writeChain(stream, nullptr, true);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteDataWithRetransmission) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain28 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  dropPackets(conn);
  auto buf2 = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain29 = transport_->writeChain(stream, buf2->clone(), false);
  loopForWrites();
  // The first packet was lost. We should expect this packet contains both
  // lost data and new data
  buf->appendChain(std::move(buf2));
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteImmediateAcks) {
  auto& conn = transport_->getConnectionState();
  PacketNum start = 10;
  PacketNum end = 15;
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeRes = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(writeRes.hasError());
  EXPECT_TRUE(conn.outstandings.packets.empty());
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);
  EXPECT_FALSE(conn.ackStates.appDataAckState.needsToSendAckImmediately);
  EXPECT_EQ(0, conn.ackStates.appDataAckState.numNonRxPacketsRecvd);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WritePendingAckIfHavingData) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  PacketNum start = 10;
  PacketNum end = 15;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = false;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  // We should write acks if there is data pending
  auto writeChain30 = transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 2);

  bool ackFound = false;
  for (auto& frame : packet.frames) {
    auto ackFrame = frame.asWriteAckFrame();
    if (!ackFrame) {
      continue;
    }
    EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
    EXPECT_EQ(ackFrame->ackBlocks.front().start, start);
    EXPECT_EQ(ackFrame->ackBlocks.front().end, end);
    ackFound = true;
  }
  EXPECT_TRUE(ackFound);
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);

  // Verify ack state after writing
  auto pnSpace = packet.header.getPacketNumberSpace();
  auto& ackState = getAckState(conn, pnSpace);
  EXPECT_EQ(ackState.largestAckScheduled, end);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(0, ackState.numNonRxPacketsRecvd);
}

TEST_F(QuicTransportTest, RstStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto resetStream1 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool rstFound = false;
  for (auto& frame : packet.frames) {
    auto rstFrame = frame.asRstStreamFrame();
    if (!rstFrame) {
      continue;
    }
    EXPECT_EQ(streamId, rstFrame->streamId);
    EXPECT_EQ(0, rstFrame->finalSize);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstFrame->errorCode);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->pendingWrites.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_TRUE(stream->pendingWrites.empty());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));
}

TEST_F(QuicTransportTest, CheckpointBeforeAnyWrites) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamState =
      transport_->getConnectionState().streamManager->findStream(streamId);

  auto updateCheckpoint1 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint1.hasError());

  EXPECT_EQ(streamState->reliableResetCheckpoint, 0);
}

TEST_F(QuicTransportTest, UnifiedWriteQueriesAndCheckpoint) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.useUnifiedAppStreamSendBuffer = true;
  auto streamId = transport_->createBidirectionalStream().value();
  auto* stream = conn.streamManager->findStream(streamId);
  ASSERT_NE(stream, nullptr);

  ASSERT_FALSE(
      transport_->writeChain(streamId, IOBuf::copyBuffer("abcdef"), true)
          .hasError());

  EXPECT_EQ(transport_->getStreamWriteOffset(streamId).value(), 0);
  EXPECT_EQ(transport_->getStreamWriteBufferedBytes(streamId).value(), 6);
  ASSERT_FALSE(
      transport_->updateReliableDeliveryCheckpoint(streamId).hasError());
  EXPECT_EQ(stream->reliableResetCheckpoint, 6);

  ASSERT_TRUE(stream->streamSendBuffer.has_value());
  auto range = stream->streamSendBuffer->nextNewData(6);
  ASSERT_TRUE(range.has_value());
  ASSERT_TRUE(stream->streamSendBuffer->markNewDataSent(*range));

  EXPECT_EQ(transport_->getStreamWriteOffset(streamId).value(), 7);
  EXPECT_EQ(transport_->getStreamWriteBufferedBytes(streamId).value(), 0);
}

TEST_F(QuicTransportTest, CheckpointAfterWriteBuffered) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamState =
      transport_->getConnectionState().streamManager->findStream(streamId);

  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  auto writeChain32 = transport_->writeChain(streamId, std::move(buf1), false);
  EXPECT_EQ(streamState->pendingWrites.chainLength(), 10);

  auto updateCheckpoint2 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint2.hasError());

  EXPECT_EQ(streamState->reliableResetCheckpoint, 10);
}

TEST_F(QuicTransportTest, CheckpointAfterWriteWrittenToWire) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamState =
      transport_->getConnectionState().streamManager->findStream(streamId);

  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  auto writeChain33 = transport_->writeChain(streamId, std::move(buf1), false);
  EXPECT_EQ(streamState->pendingWrites.chainLength(), 10);

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  loopForWrites();

  EXPECT_TRUE(streamState->pendingWrites.empty());

  auto updateCheckpoint3 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint3.hasError());

  EXPECT_EQ(streamState->reliableResetCheckpoint, 10);
}

TEST_F(QuicTransportTest, CheckpointAfterWritePartiallyWrittenToWire) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamState =
      transport_->getConnectionState().streamManager->findStream(streamId);

  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  auto writeChain34 = transport_->writeChain(streamId, std::move(buf1), false);
  EXPECT_EQ(streamState->pendingWrites.chainLength(), 10);

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  loopForWrites();
  EXPECT_TRUE(streamState->pendingWrites.empty());

  auto buf2 = IOBuf::create(5);
  buf2->append(5);
  auto writeChain35 = transport_->writeChain(streamId, std::move(buf2), false);
  EXPECT_EQ(streamState->pendingWrites.chainLength(), 5);

  auto updateCheckpoint4 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint4.hasError());

  EXPECT_EQ(streamState->reliableResetCheckpoint, 15);
}

TEST_F(QuicTransportTest, CheckpointMultipleTimes) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamState =
      transport_->getConnectionState().streamManager->findStream(streamId);

  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  auto writeChain36 = transport_->writeChain(streamId, std::move(buf1), false);
  auto updateCheckpoint5 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint5.hasError());
  EXPECT_EQ(streamState->reliableResetCheckpoint, 10);

  auto buf2 = IOBuf::create(7);
  buf2->append(7);
  auto writeChain37 = transport_->writeChain(streamId, std::move(buf2), false);
  auto updateCheckpoint6 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint6.hasError());
  EXPECT_EQ(streamState->reliableResetCheckpoint, 17);

  auto buf3 = IOBuf::create(2);
  buf3->append(2);
  auto writeChain38 = transport_->writeChain(streamId, std::move(buf3), false);
  auto updateCheckpoint7 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_FALSE(updateCheckpoint7.hasError());
  EXPECT_EQ(streamState->reliableResetCheckpoint, 19);
}

TEST_F(QuicTransportTest, CheckpointAfterSendingReset) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto resetStream2 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  auto updateCheckpoint8 =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  EXPECT_TRUE(updateCheckpoint8.hasError());
}

TEST_F(QuicTransportTest, RstStreamReliably) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.advertisedReliableResetStreamSupport = true;
  conn.peerAdvertisedReliableStreamResetSupport = true;

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  // Write 10 bytes to the transport
  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  auto writeChain39 = transport_->writeChain(streamId, std::move(buf1), false);
  // Egress the 10 bytes
  loopForWrites();
  // Write 2 bytes to the transport
  auto buf2 = IOBuf::create(2);
  buf2->append(2);
  auto writeChain40 = transport_->writeChain(streamId, std::move(buf2), false);
  // Make a checkpoint, so that we set the reliable size to 12 bytes
  auto updateCheckpoint_tmp =
      transport_->updateReliableDeliveryCheckpoint(streamId);
  // Write 3 bytes to the transport
  auto buf3 = IOBuf::create(3);
  buf3->append(3);
  auto writeChain41 = transport_->writeChain(streamId, std::move(buf3), false);
  EXPECT_EQ(stream->pendingWrites.chainLength(), 5);

  auto resetResult = transport_->resetStreamReliably(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_FALSE(resetResult.hasError());

  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  // We should discard the data that doesn't have to be reliably sent, so
  // we should just have 2 bytes of write data pending.
  EXPECT_EQ(stream->pendingWrites.chainLength(), 2);
  EXPECT_FALSE(stream->writable());
  // Egress the 2 bytes that are pending
  loopForWrites();

  // ACK all frames in all packets
  for (auto& packet : conn.outstandings.packets) {
    for (auto& frame : packet.packet.frames) {
      auto maybeWriteStreamFrame = frame.asWriteStreamFrame();
      if (maybeWriteStreamFrame) {
        auto ackResult = sendAckSMHandler(*stream, *maybeWriteStreamFrame);
        ASSERT_FALSE(ackResult.hasError());
      }
    }
  }

  // We shouldn't yet transition to Closed because the peer hasn't ACKed
  // the reliable reset.
  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);

  // ACK the reliable reset
  auto rstAckResult = sendRstAckSMHandler(*stream, 12);
  ASSERT_FALSE(rstAckResult.hasError());

  // We should transition to Closed because the peer has ACKed the reliable
  // reset, and has also ACKed all of the reliable bytes.
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
}

TEST_F(QuicTransportTest, RstStreamReliablyFallsBackWithoutPeerSupport) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.advertisedReliableResetStreamSupport = true;
  conn.peerAdvertisedReliableStreamResetSupport = false;
  EXPECT_FALSE(transport_->isReliableResetSupported());

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->findStream(streamId);
  auto buf = IOBuf::create(10);
  buf->append(10);
  ASSERT_FALSE(
      transport_->writeChain(streamId, std::move(buf), false).hasError());
  ASSERT_FALSE(
      transport_->updateReliableDeliveryCheckpoint(streamId).hasError());

  auto resetResult = transport_->resetStreamReliably(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_FALSE(resetResult.hasError());

  // A regular reset discards the checkpointed data.
  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_FALSE(stream->reliableSizeToPeer.has_value());
  EXPECT_EQ(stream->pendingWrites.chainLength(), 0);

  conn.peerAdvertisedReliableStreamResetSupport = true;
  EXPECT_TRUE(transport_->isReliableResetSupported());
}

TEST_F(QuicTransportTest, RstStreamAfterRstStreamReliably) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.advertisedReliableResetStreamSupport = true;
  conn.peerAdvertisedReliableStreamResetSupport = true;

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->findStream(streamId);

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto buf1 = IOBuf::create(10);
  buf1->append(10);
  ASSERT_FALSE(
      transport_->writeChain(streamId, std::move(buf1), false).hasError());
  ASSERT_FALSE(
      transport_->updateReliableDeliveryCheckpoint(streamId).hasError());
  auto buf2 = IOBuf::create(5);
  buf2->append(5);
  ASSERT_FALSE(
      transport_->writeChain(streamId, std::move(buf2), false).hasError());

  ASSERT_FALSE(
      transport_
          ->resetStreamReliably(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  loopForWrites();

  auto findReset = [&]() -> Optional<RstStreamFrame> {
    auto& packet =
        getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
    for (auto& frame : packet.frames) {
      if (auto* rst = frame.asRstStreamFrame()) {
        return *rst;
      }
    }
    return std::nullopt;
  };
  auto reliableRst = findReset();
  ASSERT_TRUE(reliableRst.has_value());
  EXPECT_EQ(reliableRst->reliableSize, 10u);
  EXPECT_EQ(reliableRst->finalSize, 10u);

  // The downgrade keeps the first reset's error code.
  ASSERT_FALSE(
      transport_->resetStream(streamId, GenericApplicationErrorCode::NO_ERROR)
          .hasError());
  EXPECT_FALSE(stream->reliableSizeToPeer.has_value());
  loopForWrites();

  auto rst = findReset();
  ASSERT_TRUE(rst.has_value());
  EXPECT_FALSE(rst->reliableSize.has_value());
  EXPECT_EQ(rst->finalSize, 10u);
  EXPECT_EQ(rst->errorCode, GenericApplicationErrorCode::UNKNOWN);

  // A reliable reset can't follow a non-reliable one.
  EXPECT_EQ(
      transport_
          ->resetStreamReliably(streamId, GenericApplicationErrorCode::UNKNOWN)
          .error(),
      LocalErrorCode::INVALID_OPERATION);

  // ACKing the RESET_STREAM closes the stream without the reliable bytes.
  ASSERT_FALSE(sendRstAckSMHandler(*stream, std::nullopt).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
}

TEST_F(QuicTransportTest, StopSending) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto stopSending_tmp =
      transport_->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallbackDefault) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto setReadCallback1 = transport_->setReadCallback(streamId, &readCb);
  auto setReadCallback2 = transport_->setReadCallback(streamId, nullptr);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::NO_ERROR, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallback) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto setReadCallback3 = transport_->setReadCallback(streamId, &readCb);
  auto setReadCallback4 = transport_->setReadCallback(
      streamId, nullptr, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallbackNone) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  auto setReadCallback5 = transport_->setReadCallback(streamId, &readCb);
  auto setReadCallback6 =
      transport_->setReadCallback(streamId, nullptr, std::nullopt);
  loopForWrites();
  EXPECT_EQ(0, transport_->getConnectionState().outstandings.packets.size());
}

TEST_F(QuicTransportTest, NoStopSendingReadCallback) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  auto setReadCallback7 = transport_->setReadCallback(streamId, &readCb);
  loopForWrites();
  EXPECT_EQ(0, transport_->getConnectionState().outstandings.packets.size());
  auto setReadCallback8 =
      transport_->setReadCallback(streamId, nullptr, std::nullopt);
}

TEST_F(QuicTransportTest, SendPathChallenge) {
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  // Start with a new (Not Valid) path.
  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);

  // Grant writable bytes for the path
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  // Flag the path as needing a challenge; the scheduler mints the payload at
  // write time.
  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);

  ASSERT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  ASSERT_EQ(path->status, PathStatus::NotValid);
  ASSERT_FALSE(
      transport_->getPathValidationTimeout().isTimerCallbackScheduled());

  loopForWrites();
  ASSERT_TRUE(conn.pendingEvents.pathChallenges.empty());
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_EQ(path->status, PathStatus::Validating);
  EXPECT_TRUE(
      transport_->getPathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundPathChallenge = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const PathChallengeFrame* pathChallengeFrame =
        simpleFrame->asPathChallengeFrame();
    if (!pathChallengeFrame) {
      continue;
    }
    // The challenge that landed in the packet should match the one in-flight
    // on the path.
    ASSERT_EQ(path->outstandingChallenges.size(), 1u);
    EXPECT_EQ(
        pathChallengeFrame->pathData,
        path->outstandingChallenges.front().pathData);
    foundPathChallenge = true;
  }
  EXPECT_TRUE(foundPathChallenge);
}

TEST_F(
    QuicTransportTest,
    AlternatePathValidationDoesNotSpinWithSubPacketBudget) {
  // The path validation packet is written exactly once -- in the second loop,
  // after a full packet of credit is available. The first loop (sub-packet
  // budget) must write nothing.
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));

  auto& conn = transport_->getConnectionState();

  // The fixture already has a validated current path. Add an alternate
  // (probing) path that is not the current path.
  auto altPathRes = conn.pathManager->addPath(
      folly::SocketAddress("::", 11111), folly::SocketAddress("::", 22222));
  ASSERT_FALSE(altPathRes.hasError());
  auto altPathId = altPathRes.value();
  ASSERT_NE(altPathId, conn.currentPathId);
  auto* altPath = conn.pathManager->getPath(altPathId);
  ASSERT_TRUE(altPath);

  conn.udpSendPacketLen = 1200;
  conn.transportSettings.limitedCwndInMss = 1;

  // Leave the alternate path with a positive-but-sub-packet writable budget:
  // credit one packet's worth, then account a slightly smaller sent packet.
  conn.pathManager->onPathPacketReceived(altPathId);
  conn.pathManager->onPathPacketSent(altPathId, 1150);
  ASSERT_EQ(altPath->writableBytes, 50);

  conn.pendingEvents.pathChallenges.insert(altPathId);

  // First loop: with a sub-packet budget the dedicated path validation writer
  // cannot emit a packet, so it must write nothing and leave the challenge
  // pending rather than spinning the write loop.
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(altPathId));
  EXPECT_EQ(0, conn.outstandings.packets.size());

  // Second loop: a full packet of credit makes the path writable and the
  // challenge is sent.
  conn.pathManager->onPathPacketReceived(altPathId);
  ASSERT_GE(altPath->writableBytes, conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_TRUE(conn.pendingEvents.pathChallenges.empty());
  EXPECT_EQ(1, conn.outstandings.packets.size());
}

TEST_F(QuicTransportTest, PathValidationTimeoutExpired) {
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  // Start with a new (Not Valid) path.
  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);

  // Grant writable bytes for the path
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);

  ASSERT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  ASSERT_EQ(path->status, PathStatus::NotValid);
  ASSERT_FALSE(
      transport_->getPathValidationTimeout().isTimerCallbackScheduled());

  loopForWrites();
  ASSERT_TRUE(conn.pendingEvents.pathChallenges.empty());
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_EQ(path->status, PathStatus::Validating);
  EXPECT_TRUE(
      transport_->getPathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());

  transport_->getPathValidationTimeout().cancelTimerCallback();
  conn.pathManager->onPathValidationTimeoutExpired(
      conn.pathManager->getEarliestChallengeTimeout().value() + 1s);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_EQ(path->status, PathStatus::NotValid);
  // Reaction to the path being invalid is the responsibility of the
  // client/server transport. It's not covered here.
}

TEST_F(QuicTransportTest, RetransmitPathChallengeKeepsBothInFlight) {
  auto& conn = transport_->getConnectionState();
  // Start with a new (Not Valid) path.
  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);

  // Grant writable bytes for the path
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(path->status, PathStatus::Validating);
  ASSERT_EQ(path->outstandingChallenges.size(), 1u);
  auto firstPayload = path->outstandingChallenges.front().pathData;
  ASSERT_TRUE(conn.pathManager->getEarliestChallengeTimeout().has_value());
  auto timeout = conn.pathManager->getEarliestChallengeTimeout().value();

  // Re-flag the path (simulating a loss-driven retransmit). The next write
  // mints a fresh payload, but the validation timeout is unchanged because
  // it's anchored to the first in-flight challenge.
  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pathManager->getEarliestChallengeTimeout().value(), timeout);
  ASSERT_EQ(path->outstandingChallenges.size(), 2u);
  auto secondPayload = path->outstandingChallenges.back().pathData;
  EXPECT_NE(firstPayload, secondPayload);

  // Both payloads remain routable so a delayed response to either send still
  // produces a valid match.
  EXPECT_NE(conn.pathManager->getPathByChallengeData(firstPayload), nullptr);
  EXPECT_NE(conn.pathManager->getPathByChallengeData(secondPayload), nullptr);
}

TEST_F(QuicTransportTest, DoNotClonePathChallengeOnCurrentValidatingPath) {
  // PATH_CHALLENGE is never cloned for any path state. Cloning would
  // duplicate the in-flight payload and break the uniqueness guarantee that
  // makes RTT computation unambiguous after retransmissions.
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);

  // Grant writable bytes for the path
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(path->status, PathStatus::Validating);

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());
  EXPECT_EQ(numPathChallengePackets, 1);

  // Force a timeout to drive the cloning scheduler. The PATH_CHALLENGE must
  // not be cloned even though it's still validating.
  transport_->lossTimeout().timeoutExpired();
  numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());
  EXPECT_EQ(numPathChallengePackets, 1);
}

TEST_F(QuicTransportTest, ResendPathChallengeOnLossForCurrentValidatingPath) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  // Start with a new (Not Valid) path.
  auto pathIdRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 11111), quic::SocketAddress("::", 22222));
  ASSERT_FALSE(pathIdRes.hasError());
  conn.currentPathId = pathIdRes.value();
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);

  // Grant writable bytes for the path
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  conn.pendingEvents.pathChallenges.insert(conn.currentPathId);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(path->status, PathStatus::Validating);
  ASSERT_FALSE(conn.pendingEvents.pathChallenges.contains(path->id));
  ASSERT_EQ(path->outstandingChallenges.size(), 1u);
  auto firstPayload = path->outstandingChallenges.front().pathData;

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto outstandingPacket = getLastOutstandingPacket(
      transport_->getConnectionState(), PacketNumberSpace::AppData);

  // Mark the packet as lost
  auto result = markPacketLoss(
      conn,
      outstandingPacket->metadata.pathId,
      outstandingPacket->packet,
      false);
  ASSERT_FALSE(result.hasError());

  // The path should be re-flagged so the next write mints a fresh challenge.
  // The lost payload remains in outstandingChallenges so a delayed response
  // can still be matched.
  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(path->id));
  EXPECT_NE(conn.pathManager->getPathByChallengeData(firstPayload), nullptr);
}

TEST_F(QuicTransportTest, SendPathResponse) {
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  conn.pendingEvents.pathResponses.emplace(conn.currentPathId, pathResponse);
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 0);

  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool foundPathResponse = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const PathResponseFrame* response = simpleFrame->asPathResponseFrame();
    if (!response) {
      continue;
    }
    EXPECT_EQ(*response, pathResponse);
    foundPathResponse = true;
  }
  EXPECT_TRUE(foundPathResponse);
}

TEST_F(QuicTransportTest, CloneAfterRecvReset) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  auto writeChain42 = transport_->writeChain(streamId, IOBuf::create(0), true);
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto& stream = streamResult.value();
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(0, stream->retransmissionBuffer.at(0)->data.chainLength());
  EXPECT_TRUE(stream->retransmissionBuffer.at(0)->eof);
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->currentWriteOffset);
  EXPECT_EQ(0, *stream->finalWriteOffset);

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  ASSERT_FALSE(
      receiveRstStreamSMHandler(*stream, std::move(rstFrame)).hasError());

  // This will clone twice. :/ Maybe we should change this to clone only once in
  // the future, thus the EXPECT were written with LT and LE. But it will clone
  // for sure and we shouldn't crash.
  transport_->lossTimeout().timeoutExpired();
  EXPECT_LT(1, conn.outstandings.packets.size());
  size_t cloneCounter = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](const auto& packet) {
        return packet.maybeClonedPacketIdentifier.has_value();
      });
  EXPECT_LE(1, cloneCounter);
}

TEST_F(QuicTransportTest, ClonePathResponse) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  conn.pendingEvents.pathResponses.emplace(conn.currentPathId, pathResponse);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 0);

  auto numPathResponsePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponsePackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  numPathResponsePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponsePackets, 2);
}

TEST_F(QuicTransportTest, ResendPathResponseOnLossValidPath) {
  auto& conn = transport_->getConnectionState();
  auto& outstandingPackets = conn.outstandings.packets;

  conn.pendingEvents.pathResponses.emplace(
      conn.currentPathId, PathResponseFrame(folly::Random::rand64()));
  transport_->updateWriteLooper(true);
  loopForWrites();

  // pathResponseFrame should no longer be in pendingEvents
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 0);
  // verify presence of frame in outstanding packet
  ASSERT_EQ(outstandingPackets.size(), 1);
  auto& packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  auto numPathResponseFrames = std::count_if(
      outstandingPackets.begin(),
      outstandingPackets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponseFrames, 1);

  // pathResponseFrame should be queued for re-tx on packet loss for Valid Path
  auto result = markPacketLoss(conn, conn.currentPathId, packet, false);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(
      conn.pendingEvents.pathResponses.find(conn.currentPathId) ==
      conn.pendingEvents.pathResponses.end());
}

TEST_F(QuicTransportTest, ResendPathResponseOnLossNotValidPath) {
  auto& conn = transport_->getConnectionState();
  auto pathRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 12345), quic::SocketAddress("::", 54321));
  ASSERT_FALSE(pathRes.hasError());
  conn.currentPathId = pathRes.value();
  conn.pathManager->onPathPacketReceived(conn.currentPathId);
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);
  ASSERT_EQ(path->status, PathStatus::NotValid);

  auto& outstandingPackets = conn.outstandings.packets;

  conn.pendingEvents.pathResponses.emplace(
      conn.currentPathId, PathResponseFrame(folly::Random::rand64()));
  transport_->updateWriteLooper(true);
  loopForWrites();

  // pathResponseFrame should no longer be in pendingEvents
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 0);
  // verify presence of frame in outstanding packet
  ASSERT_EQ(outstandingPackets.size(), 1);
  auto& packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  auto numPathResponseFrames = std::count_if(
      outstandingPackets.begin(),
      outstandingPackets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponseFrames, 1);

  // The path response should not be requeued on a NotValid path.
  auto result = markPacketLoss(conn, conn.currentPathId, packet, false);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(
      conn.pendingEvents.pathResponses.find(conn.currentPathId) ==
      conn.pendingEvents.pathResponses.end());
}

TEST_F(QuicTransportTest, ResendPathResponseOnLossValidatingPath) {
  auto& conn = transport_->getConnectionState();
  auto pathRes = conn.pathManager->addPath(
      quic::SocketAddress("::", 12345), quic::SocketAddress("::", 54321));
  ASSERT_FALSE(pathRes.hasError());
  conn.currentPathId = pathRes.value();
  // Give the path writable bytes
  conn.pathManager->onPathPacketReceived(conn.currentPathId);

  // Transition the path to validating state by minting a challenge.
  auto challengeRes =
      conn.pathManager->prepareChallengeForSending(conn.currentPathId);
  ASSERT_FALSE(challengeRes.hasError());
  auto path = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(path);
  ASSERT_EQ(path->status, PathStatus::Validating);

  auto& outstandingPackets = conn.outstandings.packets;

  conn.pendingEvents.pathResponses.emplace(
      conn.currentPathId, PathResponseFrame(folly::Random::rand64()));
  transport_->updateWriteLooper(true);
  loopForWrites();

  // pathResponseFrame should no longer be in pendingEvents
  EXPECT_EQ(conn.pendingEvents.pathResponses.size(), 0);
  // verify presence of frame in outstanding packet
  ASSERT_EQ(outstandingPackets.size(), 1);
  auto& packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  auto numPathResponseFrames = std::count_if(
      outstandingPackets.begin(),
      outstandingPackets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponseFrames, 1);

  // The path response should be requeued on a Validating path
  auto result = markPacketLoss(conn, conn.currentPathId, packet, false);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(
      conn.pendingEvents.pathResponses.find(conn.currentPathId) ==
      conn.pendingEvents.pathResponses.end());
}

TEST_F(QuicTransportTest, SendNewConnectionIdFrame) {
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundNewConnectionId = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const NewConnectionIdFrame* connIdFrame =
        simpleFrame->asNewConnectionIdFrame();
    if (!connIdFrame) {
      continue;
    }
    EXPECT_EQ(*connIdFrame, newConnId);
    foundNewConnectionId = true;
  }
  EXPECT_TRUE(foundNewConnectionId);
}

TEST_F(QuicTransportTest, CloneNewConnectionIdFrame) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numNewConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdPackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  EXPECT_EQ(conn.outstandings.packets.size(), 2);
  numNewConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdPackets, 2);
}

TEST_F(QuicTransportTest, BusyWriteLoopDetection) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);
  ASSERT_FALSE(conn.writeDebugState.needsWriteLoopDetect);
  ASSERT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));

  // There should be no data to send at this point
  transport_->updateWriteLooper(true);
  EXPECT_FALSE(conn.writeDebugState.needsWriteLoopDetect);
  EXPECT_EQ(WriteDataReason::NO_WRITE, conn.writeDebugState.writeDataReason);
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  loopForWrites();

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  auto writeChain43 = transport_->writeChain(stream, buf->clone(), true);
  transport_->updateWriteLooper(true);
  EXPECT_TRUE(conn.writeDebugState.needsWriteLoopDetect);
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  EXPECT_EQ(WriteDataReason::STREAM, conn.writeDebugState.writeDataReason);
  EXPECT_CALL(*socket_, write(_, _, _)).WillOnce(Return(1000));
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);

  // Queue a window update for a stream doesn't exist
  conn.streamManager->queueWindowUpdate(stream + 1);
  transport_->updateWriteLooper(true);
  EXPECT_TRUE(
      WriteDataReason::STREAM_WINDOW_UPDATE ==
      conn.writeDebugState.writeDataReason);
  EXPECT_CALL(*socket_, write(_, _, _)).Times(0);
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousWriteLoops(1, WriteDataReason::STREAM_WINDOW_UPDATE, _, _))
      .Times(1);
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  EXPECT_EQ(1, conn.writeDebugState.currentEmptyLoopCount);

  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, ResendNewConnectionIdOnLoss) {
  auto& conn = transport_->getConnectionState();

  NewConnectionIdFrame newConnId(
      1,
      0,
      ConnectionId::createAndMaybeCrash({2, 4, 2, 3}),
      StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  auto result = markPacketLoss(conn, conn.currentPathId, packet, false);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  NewConnectionIdFrame* connIdFrame =
      conn.pendingEvents.frames.front().asNewConnectionIdFrame();
  ASSERT_NE(connIdFrame, nullptr);
  EXPECT_EQ(*connIdFrame, newConnId);
}

TEST_F(QuicTransportTest, SendRetireConnectionIdFrame) {
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundRetireConnectionId = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const RetireConnectionIdFrame* retireFrame =
        simpleFrame->asRetireConnectionIdFrame();
    if (!retireFrame) {
      continue;
    }
    EXPECT_EQ(*retireFrame, retireConnId);
    foundRetireConnectionId = true;
  }
  EXPECT_TRUE(foundRetireConnectionId);
}

TEST_F(QuicTransportTest, CloneRetireConnectionIdFrame) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numRetireConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::RetireConnectionIdFrame>());
  EXPECT_EQ(numRetireConnIdPackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  EXPECT_EQ(conn.outstandings.packets.size(), 2);
  numRetireConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::RetireConnectionIdFrame>());
  EXPECT_EQ(numRetireConnIdPackets, 2);
}

TEST_F(QuicTransportTest, ResendRetireConnectionIdOnLoss) {
  auto& conn = transport_->getConnectionState();

  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  auto result = markPacketLoss(conn, conn.currentPathId, packet, false);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  RetireConnectionIdFrame* retireFrame =
      conn.pendingEvents.frames.front().asRetireConnectionIdFrame();
  ASSERT_NE(retireFrame, nullptr);
  EXPECT_EQ(*retireFrame, retireConnId);
}

TEST_F(QuicTransportTest, NonWritableStreamAPI) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto& streamState = streamResult.value();

  // write EOF
  auto writeChain44 = transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  EXPECT_FALSE(streamState->writable());

  // add a streamFlowControl event
  conn.streamManager->queueFlowControlUpdated(streamState->id);
  // check that no flow control update or onConnectionWriteReady callback gets
  // called on the stream after this
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState->id)).Times(0);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(streamState->id, _)).Times(0);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  // Check that write-side APIs return an error
  auto res2 = transport_->notifyPendingWriteOnStream(streamId, &writeCallback_);
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res2.error());
  auto res3 = transport_->setStreamPriority(
      streamId, HTTPPriorityQueue::Priority(0, false));
  EXPECT_FALSE(res3.hasError());
}

TEST_F(QuicTransportTest, RstWrittenStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  auto writeChain45 = transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto resetStream3 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  // 2 packets are outstanding: one for Stream frame one for RstStream frame:
  ASSERT_EQ(2, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_EQ(currentWriteOffset, rstStream->finalSize);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->pendingWrites.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailNonFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  auto resetStream4 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);

  // Though fail to write RstStream frame to the socket, we still should mark
  // this steam unwriable and drop current writeBuffer and
  // retransmissionBuffer:
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->pendingWrites.empty());
  EXPECT_FALSE(stream->writable());
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  auto resetStream5 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_TRUE(transport_->getConnectionState().outstandings.packets.empty());

  // Streams should be empty now since the connection will be closed.
  EXPECT_EQ(transport_->getConnectionState().streamManager->streamCount(), 0);
}

TEST_F(QuicTransportTest, WriteAfterSendRst) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  auto writeChain46 = transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto resetStream6 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->pendingWrites.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));

  // Write again:
  buf = buildRandomInputData(50);
  // This shall fail:
  auto res = transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res.error());

  // only 2 packets are outstanding: one for Stream frame one for RstStream
  // frame. The 2nd writeChain won't write anything.
  EXPECT_EQ(2, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstFrame = frame.asRstStreamFrame();
    if (!rstFrame) {
      continue;
    }
    EXPECT_EQ(streamId, rstFrame->streamId);
    EXPECT_EQ(currentWriteOffset, rstFrame->finalSize);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstFrame->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  // writeOffset isn't moved by the 2nd write:
  EXPECT_EQ(currentWriteOffset, stream->currentWriteOffset);
}

TEST_F(QuicTransportTest, DoubleReset) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto resetStream7 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_FALSE(resetStream7.hasError());
  loopForWrites();

  // Then reset again, which is a no-op:
  auto resetStream8 =
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  EXPECT_FALSE(resetStream8.hasError());
}

TEST_F(QuicTransportTest, WriteStreamDataSetLossAlarm) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(1);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain47 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, WriteAckNotSetLossAlarm) {
  auto& conn = transport_->getConnectionState();
  addAckStatesWithCurrentTimestamps(
      conn.ackStates.appDataAckState, 0 /* start */, 100 /* ind */);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(1, res->packetsWritten); // Write one packet out
  EXPECT_FALSE(transport_->isLossTimeoutScheduled()); // no alarm scheduled
}

TEST_F(QuicTransportTest, WriteWindowUpdate) {
  auto& conn = transport_->getConnectionState();
  conn.flowControlState.windowSize = 100;
  conn.flowControlState.advertisedMaxOffset = 0;
  conn.pendingEvents.connWindowUpdate = true;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(1, res->packetsWritten); // Write one packet out
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool connWindowFound = false;
  for (auto& frame : packet.frames) {
    auto connWindowUpdate = frame.asMaxDataFrame();
    if (!connWindowUpdate) {
      continue;
    }
    EXPECT_EQ(100, connWindowUpdate->maximumData);
    connWindowFound = true;
  }

  EXPECT_TRUE(connWindowFound);
  EXPECT_EQ(conn.flowControlState.advertisedMaxOffset, 100);
  conn.outstandings.reset();
  auto stream = transport_->createBidirectionalStream().value();
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto& streamState = streamResult.value();
  streamState->flowControlState.windowSize = 100;
  streamState->flowControlState.advertisedMaxOffset = 0;
  MaxStreamDataFrame frame(stream, 100);
  conn.streamManager->queueWindowUpdate(stream);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *conn.oneRttWriteHeaderCipher,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_FALSE(res.hasError());
  EXPECT_EQ(1, res->packetsWritten); // Write one packet out
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet1 =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  const MaxStreamDataFrame* streamWindowUpdate =
      packet1.frames.front().asMaxStreamDataFrame();
  EXPECT_TRUE(streamWindowUpdate);
}

TEST_F(QuicTransportTest, FlowControlCallbacks) {
  auto stream = transport_->createBidirectionalStream().value();
  auto stream2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamState1 = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamState1.hasError());
  auto streamState2 = conn.streamManager->getStream(stream2);
  ASSERT_FALSE(streamState2.hasError());

  conn.streamManager->queueFlowControlUpdated(streamState1.value()->id);
  conn.streamManager->queueFlowControlUpdated(streamState2.value()->id);
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState1.value()->id));
  // We should be able to create streams from this callback.
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState2.value()->id))
      .WillOnce(Invoke([&](auto) {
        ASSERT_FALSE(transport_->createBidirectionalStream().hasError());
      }));
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_FALSE(conn.streamManager->popFlowControlUpdated().has_value());
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesClosedTransport) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain48 = transport_->writeChain(stream1, buf1->clone(), true, &dc);
  loopForWrites();
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesTransportOnDelivered) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 0);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery_tmp =
      transport_->registerDeliveryCallback(stream1, 0, &dc);
  auto writeChain49 = transport_->writeChain(stream1, buf1->clone(), true);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(stream1);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  conn.streamManager->addDeliverable(stream1);
  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 19);
  // This will invoke the DeliveryClalback::onDelivered
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksNothingDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery_tmp =
      transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  auto writeChain50 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();

  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);
  streamState->ackedIntervals.insert(0, 19);

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  auto writeChain51 = transport_->writeChain(stream, buf2->clone(), true);
  streamState->ackedIntervals.insert(20, 99);
  loopForWrites();

  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData2), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksAllDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery_tmp =
      transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  auto writeChain52 = transport_->writeChain(stream, buf->clone(), true);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->retransmissionBuffer.clear();
  streamState->ackedIntervals.insert(0, 1);

  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksPartialDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery1 = transport_->registerDeliveryCallback(
      stream, 50, &mockedDeliveryCallback1);
  auto registerDelivery2 = transport_->registerDeliveryCallback(
      stream, 150, &mockedDeliveryCallback2);
  auto writeChain53 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->retransmissionBuffer.clear();

  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 99);
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  auto writeChain54 = transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(100, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData2), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksRetxBuffer) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery3 = transport_->registerDeliveryCallback(
      stream, 50, &mockedDeliveryCallback1);
  auto registerDelivery4 = transport_->registerDeliveryCallback(
      stream, 150, &mockedDeliveryCallback2);
  auto writeChain55 = transport_->writeChain(stream, buf->clone(), false);

  loopForWrites();
  auto& conn = transport_->getConnectionState();
  // Faking a delivery and retx:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->retransmissionBuffer.clear();
  auto retxBufferData = folly::IOBuf::copyBuffer("But i'm not delivered yet");
  streamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(51),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(retxBufferData), 51, false)));

  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 49);
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  auto writeChain56 = transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(50, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData2), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksLossAndRetxBuffer) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2, mockedDeliveryCallback3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto registerDelivery5 = transport_->registerDeliveryCallback(
      stream, 30, &mockedDeliveryCallback1);
  auto registerDelivery6 = transport_->registerDeliveryCallback(
      stream, 50, &mockedDeliveryCallback2);
  auto registerDelivery7 = transport_->registerDeliveryCallback(
      stream, 150, &mockedDeliveryCallback3);
  auto writeChain57 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery, retx and loss:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  auto retxBufferData = folly::IOBuf::copyBuffer("But i'm not delivered yet");
  streamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(51),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              ChainedByteRangeHead(retxBufferData), 51, false)));
  auto lossBufferData = folly::IOBuf::copyBuffer("And I'm lost");
  ChainedByteRangeHead lossBufferRch(lossBufferData);
  streamState->lossBuffer.emplace_back(std::move(lossBufferRch), 31, false);
  streamState->ackedIntervals.insert(0, 30);

  quic::SocketAddress lAddr, rAddr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 30, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData), rAddr);

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  auto writeChain58 = transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(31, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  EXPECT_CALL(mockedDeliveryCallback3, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(emptyData2), rAddr);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksSingleByte) {
  // register all possible ways to get a DeliveryCb
  //
  // applications built atop QUIC may capture both first and last byte timings,
  // which in this test are the same byte
  StrictMock<MockDeliveryCallback> writeChainDeliveryCb;
  StrictMock<MockDeliveryCallback> firstByteDeliveryCb;
  StrictMock<MockDeliveryCallback> lastByteDeliveryCb;
  StrictMock<MockDeliveryCallback> unsentByteDeliveryCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  auto writeChain59 = transport_->writeChain(
      stream, buf->clone(), false /* eof */, &writeChainDeliveryCb);
  auto registerDelivery1 =
      transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  auto registerDelivery2 =
      transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  auto registerDelivery3 =
      transport_->registerDeliveryCallback(stream, 1, &unsentByteDeliveryCb);

  // writeChain, first, last byte callbacks triggered after delivery
  auto& conn = transport_->getConnectionState();
  quic::SocketAddress lAddr, rAddr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->ackedIntervals.insert(0, 0);
  EXPECT_CALL(writeChainDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(networkData), rAddr);
  Mock::VerifyAndClearExpectations(&writeChainDeliveryCb);
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // try to set both offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  auto registerDelivery4 =
      transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  auto registerDelivery5 =
      transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // unsentByteDeliveryCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(unsentByteDeliveryCb, onCanceled(stream, 1)).Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&unsentByteDeliveryCb);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksSingleByteWithFin) {
  // register all possible ways to get a DeliveryCb
  //
  // applications built atop QUIC may capture both first and last byte timings,
  // which in this test are the same byte
  StrictMock<MockDeliveryCallback> writeChainDeliveryCb;
  StrictMock<MockDeliveryCallback> firstByteDeliveryCb;
  StrictMock<MockDeliveryCallback> lastByteDeliveryCb;
  StrictMock<MockDeliveryCallback> finDeliveryCb;
  StrictMock<MockDeliveryCallback> unsentByteDeliveryCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  auto writeChain60 = transport_->writeChain(
      stream, buf->clone(), true /* eof */, &writeChainDeliveryCb);
  auto registerDelivery6 =
      transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  auto registerDelivery7 =
      transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  auto registerDelivery8 =
      transport_->registerDeliveryCallback(stream, 1, &finDeliveryCb);
  auto registerDelivery9 =
      transport_->registerDeliveryCallback(stream, 2, &unsentByteDeliveryCb);

  // writeChain, first, last byte, fin callbacks triggered after delivery
  auto& conn = transport_->getConnectionState();
  quic::SocketAddress lAddr, rAddr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->ackedIntervals.insert(0, 1);
  EXPECT_CALL(writeChainDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(finDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(networkData), rAddr);
  Mock::VerifyAndClearExpectations(&writeChainDeliveryCb);
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // try to set all three offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(finDeliveryCb, onDeliveryAck(stream, 1, _)).Times(1);
  auto registerDelivery10 =
      transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  auto registerDelivery11 =
      transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  auto registerDelivery12 =
      transport_->registerDeliveryCallback(stream, 1, &finDeliveryCb);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&finDeliveryCb);

  // unsentByteDeliveryCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(unsentByteDeliveryCb, onCanceled(stream, 2)).Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&unsentByteDeliveryCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksSingleByte) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  auto writeChain61 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  auto transportRegisterTxCallback1 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback2 =
      transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  auto transportRegisterTxCallback3 =
      transport_->registerTxCallback(stream, 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first and last byte TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // try to set the first and last byte offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  auto transportRegisterTxCallback4 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback5 =
      transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // Even if we register pastlastByte again, it shouldn't trigger
  // onByteEventRegistered because this is a duplicate registration.
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(0);
  auto ret = transport_->registerTxCallback(stream, 1, &pastlastByteTxCb);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  // Even though we attempted to register the ByteEvent twice,  it resulted in
  // an error. So, onByteEventCanceled should be called only once.
  EXPECT_CALL(pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, 1)))
      .Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksSingleByteWithFin) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> finTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  auto writeChain62 =
      transport_->writeChain(stream, buf->clone(), true /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(finTxCb, onByteEventRegistered(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 2)))
      .Times(1);
  auto transportRegisterTxCallback6 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback7 =
      transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  auto transportRegisterTxCallback8 =
      transport_->registerTxCallback(stream, 1, &finTxCb);
  auto transportRegisterTxCallback9 =
      transport_->registerTxCallback(stream, 2, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // first, last byte, and fin TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(finTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // try to set all three offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(finTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(finTxCb, onByteEventRegistered(getTxMatcher(stream, 1))).Times(1);
  auto transportRegisterTxCallback10 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback11 =
      transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  auto transportRegisterTxCallback12 =
      transport_->registerTxCallback(stream, 1, &finTxCb);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, 2)))
      .Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytes) {
  const uint64_t streamBytes = 10;
  const uint64_t lastByte = streamBytes - 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  auto writeChain63 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  EXPECT_CALL(
      pastlastByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  auto transportRegisterTxCallback13 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback14 =
      transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  auto transportRegisterTxCallback15 =
      transport_->registerTxCallback(stream, lastByte + 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first and last byte TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // try to set the first and last byte offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  auto transportRegisterTxCallback16 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback17 =
      transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(
      pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytesWriteRateLimited) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketByteOffsetTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  const uint64_t streamBytes = kDefaultUDPSendPacketLen * 4;
  const uint64_t lastByte = streamBytes - 1;
  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  auto writeChain64 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);

  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      secondPacketByteOffsetTxCb,
      onByteEventRegistered(getTxMatcher(stream, kDefaultUDPSendPacketLen * 2)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  EXPECT_CALL(
      pastlastByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  auto transportRegisterTxCallback18 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  ASSERT_FALSE(
      transport_
          ->registerTxCallback(
              stream, kDefaultUDPSendPacketLen * 2, &secondPacketByteOffsetTxCb)
          .hasError());
  auto transportRegisterTxCallback20 =
      transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  auto transportRegisterTxCallback21 =
      transport_->registerTxCallback(stream, lastByte + 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketByteOffsetTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first byte gets TXed on first call to loopForWrites
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);

  // second packet byte offset gets TXed on second call to loopForWrites
  EXPECT_CALL(
      secondPacketByteOffsetTxCb,
      onByteEvent(getTxMatcher(stream, kDefaultUDPSendPacketLen * 2)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // nothing happens on third or fourth call to loopForWrites
  loopForWrites();
  loopForWrites();

  // due to overhead, last byte gets TXed on fifth call to loopForWrites
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(
      pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytesMultipleWrites) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> txCb1;
  StrictMock<MockByteEventCallback> txCb2;
  StrictMock<MockByteEventCallback> txCb3;
  auto stream = transport_->createBidirectionalStream().value();

  // call writeChain, writing 10 bytes
  {
    auto buf = buildRandomInputData(10);
    auto writeChain65 =
        transport_->writeChain(stream, buf->clone(), false /* eof */);
  }
  EXPECT_CALL(txCb1, onByteEventRegistered(getTxMatcher(stream, 0))).Times(1);
  auto transportRegisterTxCallback21 =
      transport_->registerTxCallback(stream, 0, &txCb1);
  Mock::VerifyAndClearExpectations(&txCb1);
  EXPECT_CALL(txCb1, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb1);

  // call writeChain and write another 10 bytes
  {
    auto buf = buildRandomInputData(10);
    auto writeChain66 =
        transport_->writeChain(stream, buf->clone(), false /* eof */);
  }
  EXPECT_CALL(txCb2, onByteEventRegistered(getTxMatcher(stream, 10))).Times(1);
  auto transportRegisterTxCallback22 =
      transport_->registerTxCallback(stream, 10, &txCb2);
  Mock::VerifyAndClearExpectations(&txCb2);
  EXPECT_CALL(txCb2, onByteEvent(getTxMatcher(stream, 10))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb2);

  // write the fin
  {
    auto buf = buildRandomInputData(0);
    auto writeChain67 =
        transport_->writeChain(stream, buf->clone(), true /* eof */);
  }
  EXPECT_CALL(txCb3, onByteEventRegistered(getTxMatcher(stream, 20))).Times(1);
  auto transportRegisterTxCallback23 =
      transport_->registerTxCallback(stream, 20, &txCb3);
  Mock::VerifyAndClearExpectations(&txCb3);
  EXPECT_CALL(txCb3, onByteEvent(getTxMatcher(stream, 20))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb3);
}

TEST_F(
    QuicTransportTest,
    InvokeTxAndDeliveryCallbacksMultipleBytesMultipleWrites) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> txCb1;
  StrictMock<MockByteEventCallback> txCb2;
  StrictMock<MockByteEventCallback> txCb3;

  StrictMock<MockDeliveryCallback> deliveryCb1;
  StrictMock<MockDeliveryCallback> deliveryCb2;
  StrictMock<MockDeliveryCallback> deliveryCb3;
  auto stream = transport_->createBidirectionalStream().value();

  // call writeChain, writing 10 bytes
  {
    auto buf = buildRandomInputData(10);
    auto writeChain68 = transport_->writeChain(
        stream, buf->clone(), false /* eof */, &deliveryCb1);
  }
  EXPECT_CALL(txCb1, onByteEventRegistered(getTxMatcher(stream, 0))).Times(1);
  auto transportRegisterTxCallback24 =
      transport_->registerTxCallback(stream, 0, &txCb1);
  Mock::VerifyAndClearExpectations(&txCb1);
  EXPECT_CALL(txCb1, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb1);

  // call writeChain and write another 10 bytes
  {
    auto buf = buildRandomInputData(10);
    auto writeChain69 = transport_->writeChain(
        stream, buf->clone(), false /* eof */, &deliveryCb2);
  }
  EXPECT_CALL(txCb2, onByteEventRegistered(getTxMatcher(stream, 10))).Times(1);
  auto transportRegisterTxCallback25 =
      transport_->registerTxCallback(stream, 10, &txCb2);
  Mock::VerifyAndClearExpectations(&txCb2);
  EXPECT_CALL(txCb2, onByteEvent(getTxMatcher(stream, 10))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb2);

  // write the fin
  {
    auto buf = buildRandomInputData(0);
    auto writeChain70 = transport_->writeChain(
        stream, buf->clone(), true /* eof */, &deliveryCb3);
  }
  EXPECT_CALL(txCb3, onByteEventRegistered(getTxMatcher(stream, 20))).Times(1);
  auto transportRegisterTxCallback26 =
      transport_->registerTxCallback(stream, 20, &txCb3);
  Mock::VerifyAndClearExpectations(&txCb3);
  EXPECT_CALL(txCb3, onByteEvent(getTxMatcher(stream, 20))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb3);
  quic::SocketAddress lAddr, rAddr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamResult = conn.streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  auto streamState = streamResult.value();
  streamState->ackedIntervals.insert(0, 20);
  EXPECT_CALL(deliveryCb1, onDeliveryAck(stream, 9, 100us)).Times(1);
  EXPECT_CALL(deliveryCb2, onDeliveryAck(stream, 19, 100us)).Times(1);
  EXPECT_CALL(deliveryCb3, onDeliveryAck(stream, 20, 100us)).Times(1);
  dispatchNetworkData(*transport_, lAddr, std::move(networkData), rAddr);
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnImmediate) {
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  auto transportNotifyPendingWrite1 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnWritableBytesBacpressure) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.backpressureHeadroomFactor = 1;
  EXPECT_CALL(
      writeCallback_, onConnectionWriteReady(10 * kDefaultUDPSendPacketLen));
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(10 * kDefaultUDPSendPacketLen));
  auto transportNotifyPendingWrite2 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();
  Mock::VerifyAndClearExpectations(&writeCallback_);
  EXPECT_CALL(
      writeCallback_, onConnectionWriteReady(20 * kDefaultUDPSendPacketLen));
  conn.transportSettings.backpressureHeadroomFactor = 2;
  auto transportNotifyPendingWrite3 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamImmediate) {
  auto stream = transport_->createBidirectionalStream().value();
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream, _));
  auto transportNotifyPendingWriteStream1 =
      transport_->notifyPendingWriteOnStream(stream, &writeCallback_);
  evb_.loop();

  StreamId nonExistentStream = 3;
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(nonExistentStream, &writeCallback_)
          .hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnAsync) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the conn flow control to have no bytes remaining.
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  auto transportNotifyPendingWrite4 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, HandleConnWritableReentrantStreamWriteRegistration) {
  auto& conn = transport_->getConnectionState();

  // Two streams whose write callbacks will be pending purely on connection
  // flow control.
  auto streamId1 = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();

  // Exhaust connection flow control so the write callbacks stay pending until
  // the peer grants more connection flow control.
  auto blockerId = transport_->createBidirectionalStream().value();
  auto blocker = conn.streamManager->getStream(blockerId).value();
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *blocker, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  // The first callback re-registers these mid-iteration, growing (and
  // rehashing) pendingWriteCallbacks_ from inside handleConnWritable().
  std::vector<StreamId> reentrantStreamIds;
  reentrantStreamIds.reserve(32);
  for (int i = 0; i < 32; ++i) {
    reentrantStreamIds.push_back(
        transport_->createBidirectionalStream().value());
  }

  NiceMock<MockWriteCallback> reentrantCb;
  NiceMock<MockWriteCallback> writeCallback;
  bool reregistered = false;
  ON_CALL(writeCallback, onStreamWriteReady(_, _))
      .WillByDefault([&](StreamId, uint64_t) {
        if (!reregistered) {
          reregistered = true;
          for (auto id : reentrantStreamIds) {
            transport_->notifyPendingWriteOnStream(id, &reentrantCb);
          }
        }
      });

  ASSERT_FALSE(transport_->notifyPendingWriteOnStream(streamId1, &writeCallback)
                   .hasError());
  ASSERT_FALSE(transport_->notifyPendingWriteOnStream(streamId2, &writeCallback)
                   .hasError());
  evb_.loop();

  // Both original callbacks must fire even though the first one rehashes the
  // map from inside handleConnWritable().
  EXPECT_CALL(writeCallback, onStreamWriteReady(streamId1, _)).Times(1);
  EXPECT_CALL(writeCallback, onStreamWriteReady(streamId2, _)).Times(1);

  PacketNum num = 10;
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 100000),
      num);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  // Drain the re-registered async ops while the mock callbacks are still in
  // scope so none dangle into transport teardown.
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferFreeUpSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // Fill up the buffer to its limit
  ASSERT_FALSE(updateFlowControlOnWriteToStream(*stream, 100).hasError());
  auto transportNotifyPendingWrite5 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Write 10 bytes to the socket to free up space
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(*stream, 10).hasError());
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NoPacingTimerStillPaced) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transport_->setTransportSettings(transportSettings);
  transport_->getConnectionState().canBePaced = true;
  EXPECT_TRUE(isConnectionPaced(transport_->getConnectionState()));
}

TEST_F(QuicTransportTest, SetPacingTimerThenEnablesPacing) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transport_->setPacingTimer(
      std::make_shared<HighResQuicTimer>(
          &evb_, transportSettings.pacingTimerResolution));
  transport_->setTransportSettings(transportSettings);
  transport_->getConnectionState().canBePaced = true;
  EXPECT_TRUE(isConnectionPaced(transport_->getConnectionState()));
}

TEST_F(
    QuicTransportTest,
    SetTransportSettingsAfterHandshakePreservesCanBePaced) {
  // Initial setup with pacing enabled
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transport_->setPacingTimer(
      std::make_shared<HighResQuicTimer>(
          &evb_, transportSettings.pacingTimerResolution));
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();

  // Simulate post-handshake state where updatePacingOnKeyEstablished() was
  // called
  conn.transportParametersEncoded = true;
  conn.canBePaced = true;
  EXPECT_TRUE(isConnectionPaced(conn));

  // Get current settings, modify burst settings (like SocketOptionRule does),
  // and call setTransportSettings again
  auto updatedSettings = transport_->getTransportSettings();
  updatedSettings.minBurstPackets = 25;
  updatedSettings.writeConnectionDataPacketsLimit = 25;
  transport_->setTransportSettings(updatedSettings);

  // canBePaced should still be true after calling setTransportSettings
  // post-handshake
  EXPECT_TRUE(conn.canBePaced);
  EXPECT_TRUE(isConnectionPaced(conn));
}

TEST_F(QuicTransportTest, NoPacingNoBbr) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::BBR;
  transportSettings.pacingEnabled = false;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  EXPECT_FALSE(isConnectionPaced(transport_->getConnectionState()));
  EXPECT_NE(
      CongestionControlType::BBR,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, NoPacingNoC4) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::C4;
  transportSettings.pacingEnabled = false;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  EXPECT_EQ(
      CongestionControlType::Cubic,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, PacedC4) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::C4;
  transportSettings.pacingEnabled = true;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setPacingTimer(
      std::make_shared<HighResQuicTimer>(
          &evb_, transportSettings.pacingTimerResolution));
  transport_->setTransportSettings(transportSettings);
  EXPECT_NE(transport_->getConnectionState().pacer, nullptr);
  EXPECT_EQ(
      CongestionControlType::C4,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, NoPacingNoBbr3) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::BBR3;
  transportSettings.pacingEnabled = false;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  EXPECT_EQ(
      CongestionControlType::Cubic,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, PacedBbr3) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::BBR3;
  transportSettings.pacingEnabled = true;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setPacingTimer(
      std::make_shared<HighResQuicTimer>(
          &evb_, transportSettings.pacingTimerResolution));
  transport_->setTransportSettings(transportSettings);
  EXPECT_NE(transport_->getConnectionState().pacer, nullptr);
  EXPECT_EQ(
      CongestionControlType::BBR3,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferUseTotalSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // Fill up the buffer to its limit
  ASSERT_FALSE(updateFlowControlOnWriteToStream(*stream, 100).hasError());
  auto transportNotifyPendingWrite6 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferOveruseSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // Fill up the buffer to its limit
  ASSERT_FALSE(updateFlowControlOnWriteToStream(*stream, 1000).hasError());
  auto transportNotifyPendingWrite7 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(
    QuicTransportTest,
    NotifyPendingWriteConnBufferGreaterThanConnFlowWindow) {
  auto& conn = transport_->getConnectionState();
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable =
      conn.flowControlState.peerAdvertisedMaxOffset + 1;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // Use up the entire flow control (but not the buffer space)
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());
  auto transportNotifyPendingWrite8 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Give the conn some headroom, but don't free up any buffer space
  PacketNum num = 10;
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncConnBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the conn flow control to have no bytes remaining.
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  auto transportNotifyPendingWriteStream2 =
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamWritableBytesBackpressure) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.backpressureHeadroomFactor = 1;

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the conn flow control to have no bytes remaining.
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());
  ASSERT_FALSE(updateFlowControlOnWriteToSocket(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  auto transportNotifyPendingWriteStream3 =
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();
  Mock::VerifyAndClearExpectations(&writeCallback_);

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(10 * kDefaultUDPSendPacketLen));

  EXPECT_CALL(
      writeCallback_,
      onStreamWriteReady(stream->id, 10 * kDefaultUDPSendPacketLen));

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(
          conn.flowControlState.peerAdvertisedMaxOffset +
          1000 * kDefaultUDPSendPacketLen),
      num);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncStreamBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  auto transportNotifyPendingWriteStream4 =
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));
  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));

  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the conn flow control to have no bytes remaining.
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  auto transportNotifyPendingWrite9 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  EXPECT_FALSE(transportNotifyPendingWrite9.hasError());
  evb_.loop();
  auto transportNotifyPendingWrite10 =
      transport_->notifyPendingWriteOnConnection(&writeCallback_);
  EXPECT_TRUE(transportNotifyPendingWrite10.hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  EXPECT_FALSE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  // Artificially restrict the conn flow control to have no bytes remaining.
  ASSERT_FALSE(updateFlowControlOnWriteToStream(
                   *stream, conn.flowControlState.peerAdvertisedMaxOffset)
                   .hasError());

  auto transportNotifyPendingWriteStream5 =
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  auto transportNotifyPendingWriteStream6 =
      transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  EXPECT_CALL(writeCallback_, onStreamWriteReady(_, _))
      .WillOnce(Invoke([&](auto id, auto) {
        if (id == streamId) {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
        } else {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId, _));
        }
        transport_->close(std::nullopt);
      }));
  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  auto streamResult2 = conn.streamManager->getStream(streamId2);
  ASSERT_FALSE(streamResult2.hasError());
  auto stream2 = streamResult2.value();
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;
  stream2->currentWriteOffset =
      stream2->flowControlState.peerAdvertisedMaxOffset;

  auto transportNotifyPendingWriteStream7 =
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  auto transportNotifyPendingWriteStream8 =
      transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);

  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));
  EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _))
      .WillOnce(Invoke([&](auto, auto) { transport_->close(std::nullopt); }));
  dispatchNetworkData(
      *transport_,
      SocketAddress("::", 10001),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10000));
}

TEST_F(QuicTransportTest, WriteStreamFromMiddleOfMap) {
  // Testing writing to multiple streams
  auto& conn = transport_->getConnectionState();
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  uint64_t writableBytes = kDefaultUDPSendPacketLen - 100;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        auto res = writableBytes;
        writableBytes = 0;
        return res;
      }));

  auto streamResult1 = conn.streamManager->getStream(s1);
  ASSERT_FALSE(streamResult1.hasError());
  auto stream1 = streamResult1.value();
  auto buf1 = buildRandomInputData(kDefaultUDPSendPacketLen);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf1->clone(), false).hasError());

  auto buf2 = buildRandomInputData(kDefaultUDPSendPacketLen);
  auto streamResult2 = conn.streamManager->getStream(s2);
  ASSERT_FALSE(streamResult2.hasError());
  auto stream2 = streamResult2.value();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream2, buf2->clone(), false).hasError());

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *socket_,
                   conn,
                   *conn.clientConnectionId,
                   *conn.serverConnectionId,
                   *aead_,
                   *conn.oneRttWriteHeaderCipher,
                   transport_->getVersion(),
                   conn.transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& packet = *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(1, packet.packet.frames.size());
  auto& frame = packet.packet.frames.front();
  const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame);
  EXPECT_EQ(streamFrame->streamId, s1);
  conn.outstandings.reset();

  // Queue already points to stream2
  EXPECT_EQ(nextScheduledStreamID(conn), stream2->id);
  writableBytes = kDefaultUDPSendPacketLen - 100;

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *socket_,
                   conn,
                   *conn.clientConnectionId,
                   *conn.serverConnectionId,
                   *aead_,
                   *conn.oneRttWriteHeaderCipher,
                   transport_->getVersion(),
                   conn.transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& outstandingPacket2 =
      *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  auto packet2 = stripPaddingFrames(outstandingPacket2.packet);
  EXPECT_EQ(1, packet2.frames.size());
  auto& frame2 = packet2.frames.front();
  const WriteStreamFrame* streamFrame2 = frame2.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame2);
  EXPECT_EQ(streamFrame2->streamId, s2);
  conn.outstandings.reset();

  // Test wrap around by skipping a stream
  conn.streamManager->writeQueue().getNextScheduledID(std::nullopt);
  writableBytes = kDefaultUDPSendPacketLen;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  ASSERT_FALSE(writeQuicDataToSocket(
                   *socket_,
                   conn,
                   *conn.clientConnectionId,
                   *conn.serverConnectionId,
                   *aead_,
                   *conn.oneRttWriteHeaderCipher,
                   transport_->getVersion(),
                   conn.transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& outstandingPacket3 =
      *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  auto packet3 = stripPaddingFrames(outstandingPacket3.packet);
  EXPECT_EQ(2, packet3.frames.size());
  auto& frame3 = packet3.frames.front();
  auto& frame4 = packet3.frames.back();
  const WriteStreamFrame* streamFrame3 = frame3.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame3);
  EXPECT_EQ(streamFrame3->streamId, s2);
  const WriteStreamFrame* streamFrame4 = frame4.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame4);
  EXPECT_EQ(streamFrame4->streamId, s1);
  transport_->close(std::nullopt);
}

TEST_F(QuicTransportTest, NoStream) {
  auto& conn = transport_->getConnectionState();
  EventBase evb;
  ASSERT_FALSE(writeQuicDataToSocket(
                   *socket_,
                   conn,
                   *conn.clientConnectionId,
                   *conn.serverConnectionId,
                   *aead_,
                   *conn.oneRttWriteHeaderCipher,
                   transport_->getVersion(),
                   conn.transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_TRUE(conn.outstandings.packets.empty());
}

TEST_F(QuicTransportTest, CancelAckTimeout) {
  qEvb_->scheduleTimeout(transport_->getAckTimeout(), 1000000ms);
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = false;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10128),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10129));
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
}

TEST_F(QuicTransportTest, ScheduleAckTimeout) {
  // Make srtt large so we will use kMinAckTimeout
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10003),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10004));
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  EXPECT_NEAR(
      transport_->getAckTimeout()->getTimerCallbackTimeRemaining().count(),
      25,
      5);
}

TEST_F(QuicTransportTest, ScheduleAckTimeoutSRTTFactor) {
  transport_->getConnectionState().lossState.srtt = 50ms;
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10003),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10004));
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  EXPECT_NEAR(
      transport_->getAckTimeout()->getTimerCallbackTimeRemaining().count(),
      50 / 4,
      2);
}

TEST_F(QuicTransportTest, ScheduleAckTimeoutAckFreq) {
  transport_->getConnectionState().lossState.srtt = 50ms;
  transport_->getConnectionState().transportSettings.minAckDelay = 1ms;
  transport_->getConnectionState()
      .ackStates.appDataAckState.ackFrequencySequenceNumber = 1;
  transport_->getConnectionState().ackStates.maxAckDelay = 50ms / 3;
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10003),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10004));
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  EXPECT_NEAR(
      transport_->getAckTimeout()->getTimerCallbackTimeRemaining().count(),
      50 / 3,
      2);
}

TEST_F(QuicTransportTest, ScheduleAckTimeoutFromMaxAckDelay) {
  // Make srtt large so we will use maxAckDelay
  transport_->getConnectionState().lossState.srtt = 25000000us;
  transport_->getConnectionState().ackStates.maxAckDelay = 10ms;
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10003),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10004));
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  EXPECT_NEAR(
      transport_->getAckTimeout()->getTimerCallbackTimeRemaining().count(),
      10,
      5);
}

TEST_F(QuicTransportTest, CloseTransportCancelsAckTimeout) {
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  dispatchNetworkData(
      *transport_,
      SocketAddress("::1", 10003),
      NetworkData(ReceivedUdpPacket(IOBuf::copyBuffer("fake data"))),
      SocketAddress("::1", 10004));
  EXPECT_TRUE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  // We need to send some packets, otherwise loss timer won't be scheduled
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(testing::WithArgs<1, 2>(Invoke(getTotalIovecLen)));
  auto writeChain71 = transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  transport_->scheduleLossTimeout(500ms);
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());

  transport_->closeNow(std::nullopt);
  EXPECT_FALSE(transport_->getAckTimeout()->isTimerCallbackScheduled());
  EXPECT_FALSE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, DrainTimeoutExpired) {
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, CloseWithDrainWillKeepSocketAround) {
  EXPECT_CALL(*socket_, pauseRead()).Times(0);
  EXPECT_CALL(*socket_, close()).Times(0);
  transport_->close(std::nullopt);

  // Manual shut it, otherwise transport_'s dtor will shut the socket and mess
  // up the EXPECT_CALLs above
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, IdleTimeoutMin) {
  transport_->getConnectionState().transportSettings.idleTimeout = 60s;
  transport_->getConnectionState().peerIdleTimeout = 15s;
  transport_->setIdleTimerNow();
  EXPECT_NEAR(
      transport_->idleTimeout().getTimerCallbackTimeRemaining().count(),
      15000,
      1000);
}

TEST_F(QuicTransportTest, IdleTimeoutLocalDisabled) {
  transport_->getConnectionState().transportSettings.idleTimeout = 0s;
  transport_->getConnectionState().peerIdleTimeout = 15s;
  transport_->setIdleTimerNow();
  EXPECT_FALSE(transport_->idleTimeout().isTimerCallbackScheduled());
}

TEST_F(QuicTransportTest, IdleTimeoutPeerDisabled) {
  transport_->getConnectionState().transportSettings.idleTimeout = 60s;
  transport_->getConnectionState().peerIdleTimeout = 0s;
  transport_->setIdleTimerNow();
  ASSERT_TRUE(transport_->idleTimeout().isTimerCallbackScheduled());
  EXPECT_NEAR(
      transport_->idleTimeout().getTimerCallbackTimeRemaining().count(),
      60000,
      1000);
}

TEST_F(QuicTransportTest, PacedWriteNoDataToWrite) {
  ASSERT_EQ(
      WriteDataReason::NO_WRITE,
      shouldWriteData(transport_->getConnectionState()));
  EXPECT_CALL(*socket_, write(_, _, _)).Times(0);
  transport_->pacedWrite();
}

class QuicTransportPacingTest : public QuicTransportTest,
                                public WithParamInterface<bool> {};

INSTANTIATE_TEST_SUITE_P(
    WritableEvents,
    QuicTransportPacingTest,
    Values(false, true));

TEST_P(QuicTransportPacingTest, PacingWillBurstFirst) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transportSettings.useSockWritableEvents = GetParam();
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();
  conn.udpSendPacketLen = 100;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  auto writeChain72 = transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _, _))
      .WillOnce(Invoke([](const auto&, const iovec* vec, size_t count) {
        return getTotalIovecLen(vec, count);
      }));
  EXPECT_CALL(*socket_, resumeWrite(_)).Times(GetParam() ? 1 : 0);
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*rawPacer, getTimeUntilNextWrite(_)).WillRepeatedly(Return(0us));
  transport_->pacedWrite();
  EXPECT_NE(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_EQ(!GetParam(), transport_->writeLooper().isRunning());
}

TEST_P(QuicTransportPacingTest, AlreadyScheduledPacingNoWrite) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transportSettings.useSockWritableEvents = GetParam();
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();
  conn.udpSendPacketLen = 100;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));

  auto buf = buildRandomInputData(400);
  auto streamId = transport_->createBidirectionalStream().value();
  auto writeChain73 = transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _, _))
      .Times(2)
      .WillRepeatedly(Invoke([](const auto&, const iovec* vec, size_t count) {
        return getTotalIovecLen(vec, count);
      }));
  EXPECT_CALL(*socket_, resumeWrite(_)).Times(0);
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*rawPacer, getTimeUntilNextWrite(_))
      .WillRepeatedly(Return(3600000ms));
  EXPECT_FALSE(transport_->isPacingScheduled());
  transport_->pacedWrite();
  EXPECT_FALSE(transport_->isPacingScheduled());
  loopForWrites();

  ASSERT_NE(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_TRUE(transport_->isPacingScheduled());
  EXPECT_FALSE(transport_->writeLooper().isLoopCallbackScheduled());
  EXPECT_CALL(*socket_, write(_, _, _)).Times(0);
  EXPECT_CALL(*rawPacer, getTimeUntilNextWrite(_)).WillRepeatedly(Return(0us));
  loopForWrites();
  transport_->pacedWrite();
  EXPECT_TRUE(transport_->isPacingScheduled());
  EXPECT_FALSE(transport_->writeLooper().isLoopCallbackScheduled());

  EXPECT_CALL(*socket_, write(_, _, _))
      .WillRepeatedly(Invoke([](const auto&, const iovec* vec, size_t count) {
        return getTotalIovecLen(vec, count);
      }));
  EXPECT_CALL(*rawPacer, getTimeUntilNextWrite(_))
      .WillRepeatedly(Return(3600000ms));
  transport_->writeLooper().cancelTimerCallback();
  transport_->writeLooper().timeoutExpired();
  EXPECT_TRUE(transport_->isPacingScheduled());
  EXPECT_FALSE(transport_->writeLooper().isLoopCallbackScheduled());

  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(10));
  transport_->writeLooper().cancelTimerCallback();
  transport_->writeLooper().timeoutExpired();
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_FALSE(transport_->isPacingScheduled());
  EXPECT_FALSE(transport_->writeLooper().isRunning());
}

TEST_F(QuicTransportTest, NoScheduleIfNoNewData) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  auto writeChain74 = transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  // This will write out everything. After that because there is no new data,
  // FunctionLooper won't schedule a pacing timeout.
  transport_->pacedWrite();

  ASSERT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_FALSE(transport_->isPacingScheduled());
}

TEST_F(QuicTransportTest, SaneCwndSettings) {
  TransportSettings transportSettings;
  transportSettings.minCwndInMss = 1;
  transportSettings.initCwndInMss = 0;
  transportSettings.defaultCongestionController = CongestionControlType::BBR;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(
      conn.udpSendPacketLen * kInitCwndInMss,
      conn.congestionController->getCongestionWindow());
}

TEST_F(QuicTransportTest, GetStreamPackestTxedSingleByte) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  auto writeChain75 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  auto transportRegisterTxCallback27 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);

  // when first byte TX callback gets invoked, numPacketsTxWithNewData should be
  // one
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
}

TEST_F(QuicTransportTest, GetStreamTransportInfoAckDeliveryOffset) {
  const auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamResult = conn.streamManager->getStream(streamId);
  ASSERT_FALSE(streamResult.hasError());
  auto* stream = streamResult.value();

  auto streamInfo = transport_->getStreamTransportInfo(streamId);
  ASSERT_FALSE(streamInfo.hasError());
  EXPECT_FALSE(streamInfo->maybeLargestDeliverableOffset.has_value());

  stream->ackedIntervals.insert(4, 9);
  streamInfo = transport_->getStreamTransportInfo(streamId);
  ASSERT_FALSE(streamInfo.hasError());
  EXPECT_FALSE(streamInfo->maybeLargestDeliverableOffset.has_value());

  stream->ackedIntervals.insert(0, 3);
  streamInfo = transport_->getStreamTransportInfo(streamId);
  ASSERT_FALSE(streamInfo.hasError());
  ASSERT_TRUE(streamInfo->maybeLargestDeliverableOffset.has_value());
  EXPECT_EQ(*streamInfo->maybeLargestDeliverableOffset, 9);

  // Once the FIN is ACKed, the frontier is the final offset, one past the
  // last stream byte (9).
  ASSERT_FALSE(stream->updateAckedIntervals(4, 6, true /* eof */).hasError());
  streamInfo = transport_->getStreamTransportInfo(streamId);
  ASSERT_FALSE(streamInfo.hasError());
  ASSERT_TRUE(streamInfo->maybeLargestDeliverableOffset.has_value());
  EXPECT_EQ(*streamInfo->maybeLargestDeliverableOffset, 10);
}

TEST_F(QuicTransportTest, GetStreamPacketsTxedMultipleBytes) {
  const uint64_t streamBytes = 10;
  const uint64_t lastByte = streamBytes - 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  auto writeChain76 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  auto transportRegisterTxCallback28 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  auto transportRegisterTxCallback29 =
      transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // when first and last byte TX callback fired, numPacketsTxWithNewData should
  // be 1
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
}

TEST_F(QuicTransportTest, GetStreamPacketsTxedMultiplePackets) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  const uint64_t streamBytes = kDefaultUDPSendPacketLen * 4;
  const uint64_t lastByte = streamBytes - 1;

  // 20 bytes overhead per packet should be more than enough
  const uint64_t firstPacketNearTailByte = kDefaultUDPSendPacketLen - 20;
  const uint64_t secondPacketNearHeadByte = kDefaultUDPSendPacketLen;
  const uint64_t secondPacketNearTailByte = kDefaultUDPSendPacketLen * 2 - 40;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> firstPacketNearTailByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketNearHeadByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketNearTailByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  auto writeChain77 =
      transport_->writeChain(stream, buf->clone(), false /* eof */);

  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      firstPacketNearTailByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, firstPacketNearTailByte)))
      .Times(1);
  EXPECT_CALL(
      secondPacketNearHeadByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, secondPacketNearHeadByte)))
      .Times(1);
  EXPECT_CALL(
      secondPacketNearTailByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, secondPacketNearTailByte)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  auto transportRegisterTxCallback30 =
      transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  ASSERT_FALSE(
      transport_
          ->registerTxCallback(
              stream, firstPacketNearTailByte, &firstPacketNearTailByteTxCb)
          .hasError());
  ASSERT_FALSE(
      transport_
          ->registerTxCallback(
              stream, secondPacketNearHeadByte, &secondPacketNearHeadByteTxCb)
          .hasError());
  ASSERT_FALSE(
      transport_
          ->registerTxCallback(
              stream, secondPacketNearTailByte, &secondPacketNearTailByteTxCb)
          .hasError());
  auto transportRegisterTxCallback31 =
      transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);

  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstPacketNearTailByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearHeadByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearTailByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // first byte and first packet last bytes get Txed on first loopForWrites
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  EXPECT_CALL(
      firstPacketNearTailByteTxCb,
      onByteEvent(getTxMatcher(stream, firstPacketNearTailByte)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstPacketNearTailByteTxCb);

  // second packet should be send on the second loopForWrites
  EXPECT_CALL(
      secondPacketNearHeadByteTxCb,
      onByteEvent(getTxMatcher(stream, secondPacketNearHeadByte)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 2);
      }));
  EXPECT_CALL(
      secondPacketNearTailByteTxCb,
      onByteEvent(getTxMatcher(stream, secondPacketNearTailByte)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 2);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&secondPacketNearHeadByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearTailByteTxCb);

  // last byte will be sent on the fifth loopForWrites
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1)
      .WillOnce(Invoke([&](ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 5);
      }));
  loopForWrites();
  loopForWrites();
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
}

TEST_F(QuicTransportTest, PrioritySetAndGet) {
  auto stream = transport_->createBidirectionalStream().value();
  PriorityQueue::Priority basePri;
  HTTPPriorityQueue::Priority defaultPri(basePri);
  EXPECT_EQ(
      defaultPri,
      HTTPPriorityQueue::Priority(
          transport_->getStreamPriority(stream).value()));
  auto setPriority2 = transport_->setStreamPriority(
      stream, HTTPPriorityQueue::Priority(0, false));
  EXPECT_EQ(
      HTTPPriorityQueue::Priority(0, false),
      HTTPPriorityQueue::Priority(
          transport_->getStreamPriority(stream).value()));
  auto nonExistStreamPri = transport_->getStreamPriority(stream + 4);
  EXPECT_TRUE(nonExistStreamPri.hasError());
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, nonExistStreamPri.error());
  transport_->close(std::nullopt);
  auto closedConnStreamPri = transport_->getStreamPriority(stream);
  EXPECT_TRUE(closedConnStreamPri.hasError());
  EXPECT_EQ(LocalErrorCode::CONNECTION_CLOSED, closedConnStreamPri.error());
}

TEST_F(QuicTransportTest, GetSetReceiveWindowOnIncomingUnidirectionalStream) {
  auto& conn = transport_->getConnectionState();
  // Stream ID is for a peer-initiated unidirectional stream
  StreamId id = 0b110;
  uint64_t windowSize = 1500;
  auto streamResult = conn.streamManager->getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();
  EXPECT_FALSE(stream->writable());
  EXPECT_TRUE(stream->shouldSendFlowControl());
  auto res1 = transport_->setStreamFlowControlWindow(id, windowSize);
  EXPECT_FALSE(res1.hasError());
  EXPECT_EQ(windowSize, stream->flowControlState.windowSize);
  auto res2 = transport_->getStreamFlowControl(id);
  EXPECT_FALSE(res2.hasError());
}

TEST_F(QuicTransportTest, SetMaxPacingRateWithAndWithoutPacing) {
  auto settings = transport_->getTransportSettings();
  EXPECT_FALSE(settings.pacingEnabled);
  auto res1 = transport_->setMaxPacingRate(125000);
  EXPECT_TRUE(res1.hasError());
  EXPECT_EQ(LocalErrorCode::PACER_NOT_AVAILABLE, res1.error());
  settings.pacingEnabled = true;
  transport_->setPacingTimer(
      std::make_shared<HighResQuicTimer>(
          &evb_, settings.pacingTimerResolution));
  transport_->setTransportSettings(settings);
  auto res2 = transport_->setMaxPacingRate(125000);
  EXPECT_FALSE(res2.hasError());
}

TEST_F(QuicTransportTest, GetMaxWritableInvalidStream) {
  // Stream ID is for a peer-initiated bidirectional stream that doesn't exist
  StreamId id = 0b100;
  auto maxWritable = transport_->getMaxWritableOnStream(id);
  // max writable on non-existent stream returns an error
  EXPECT_TRUE(maxWritable.hasError());
}

TEST_F(QuicTransportTest, GetMaxWritableOnIncomingUnidirectionalStream) {
  auto& conn = transport_->getConnectionState();
  // Stream ID is for a peer-initiated unidirectional stream
  StreamId id = 0b110;
  auto streamResult = conn.streamManager->getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  auto maxWritable = transport_->getMaxWritableOnStream(id);
  // max writable on receive only stream returns an error
  EXPECT_TRUE(maxWritable.hasError());
}

TEST_F(QuicTransportTest, GetMaxWritableStreamFlowControlLimited) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream ID is for a peer-initiated bidirectional stream
  StreamId id = 0b100;
  auto streamResult = conn.streamManager->getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // set stream fcw < both conn fc and total buffer space available, such that
  // we're limited by stream fcw
  stream->flowControlState.peerAdvertisedMaxOffset = 1500;
  conn.flowControlState.peerAdvertisedMaxOffset = 2000;
  transportSettings.totalBufferSpaceAvailable = 2000;
  transport_->setTransportSettings(transportSettings);

  auto maxWritable = transport_->getMaxWritableOnStream(id);
  EXPECT_FALSE(maxWritable.hasError());
  EXPECT_EQ(*maxWritable, stream->flowControlState.peerAdvertisedMaxOffset);
}

TEST_F(QuicTransportTest, GetMaxWritableConnFlowControlLimited) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream ID is for a peer-initiated bidirectional stream
  StreamId id = 0b100;
  auto streamResult = conn.streamManager->getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // set conn fcw < both stream fcw and buffer space, such that we're conn fcw
  // limited
  conn.flowControlState.peerAdvertisedMaxOffset = 1500;
  transportSettings.totalBufferSpaceAvailable = 2000;
  transport_->setTransportSettings(transportSettings);
  stream->flowControlState.peerAdvertisedMaxOffset = 2000;

  auto maxWritable = transport_->getMaxWritableOnStream(id);
  EXPECT_FALSE(maxWritable.hasError());
  EXPECT_EQ(*maxWritable, conn.flowControlState.peerAdvertisedMaxOffset);
}

TEST_F(QuicTransportTest, GetMaxWritableBufferSpaceLimited) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream ID is for a peer-initiated bidirectional stream
  StreamId id = 0b100;
  auto streamResult = conn.streamManager->getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  auto stream = streamResult.value();

  // set total buffer space available < stream and conn fcw, such that
  // we're limited by buffer space
  transportSettings.totalBufferSpaceAvailable = 1500;
  transport_->setTransportSettings(transportSettings);
  stream->flowControlState.peerAdvertisedMaxOffset = 2000;
  conn.flowControlState.peerAdvertisedMaxOffset = 2000;

  auto maxWritable = transport_->getMaxWritableOnStream(id);
  EXPECT_FALSE(maxWritable.hasError());
  EXPECT_EQ(*maxWritable, transportSettings.totalBufferSpaceAvailable);
}

TEST_F(QuicTransportTest, GetMaxWritableStreamFlowControlLimitedTwoStreams) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream IDs are for a peer-initiated bidirectional stream
  StreamId id1 = 0b100;
  StreamId id2 = 0b1100;

  // let's assume we have 1k bytes left in each window
  auto streamResult1 = conn.streamManager->getStream(id1);
  ASSERT_FALSE(streamResult1.hasError());
  auto stream1 = streamResult1.value();
  stream1->currentWriteOffset = 1000;
  stream1->flowControlState.peerAdvertisedMaxOffset = 2000;

  auto streamResult2 = conn.streamManager->getStream(id2);
  ASSERT_FALSE(streamResult2.hasError());
  auto stream2 = streamResult2.value();
  stream2->currentWriteOffset = 1000;
  stream2->flowControlState.peerAdvertisedMaxOffset = 2000;

  // set sum of write offset accordingly
  conn.flowControlState.sumCurWriteOffset = 2000;

  // set stream fcw < both conn fcw and total buffer space available, such that
  // we're limited by stream fcw
  conn.flowControlState.peerAdvertisedMaxOffset = 4000;
  transportSettings.totalBufferSpaceAvailable = 2000;
  transport_->setTransportSettings(transportSettings);

  auto maxWritable1 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable1.hasError());
  EXPECT_EQ(*maxWritable1, 1000);

  auto maxWritable2 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable2.hasError());
  EXPECT_EQ(*maxWritable2, 1000);
}

TEST_F(QuicTransportTest, GetMaxWritableConnFlowControlLimitedTwoStreams) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream IDs are for a peer-initiated bidirectional stream
  StreamId id1 = 0b100;
  StreamId id2 = 0b1100;

  // let's assume we have 1k bytes left in each window
  auto streamResult1 = conn.streamManager->getStream(id1);
  ASSERT_FALSE(streamResult1.hasError());
  auto stream1 = streamResult1.value();
  stream1->currentWriteOffset = 1000;
  stream1->flowControlState.peerAdvertisedMaxOffset = 2000;

  auto streamResult2 = conn.streamManager->getStream(id2);
  ASSERT_FALSE(streamResult2.hasError());
  auto stream2 = streamResult2.value();
  stream2->currentWriteOffset = 1000;
  stream2->flowControlState.peerAdvertisedMaxOffset = 2000;

  // set sum of write offset accordingly
  conn.flowControlState.sumCurWriteOffset = 2000;

  // set conn fcw < both stream fcw and total buffer space available, such that
  // we're limited by conn fcw
  conn.flowControlState.peerAdvertisedMaxOffset = 2500;
  transportSettings.totalBufferSpaceAvailable = 800;
  transport_->setTransportSettings(transportSettings);

  auto maxWritable1 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable1.hasError());
  EXPECT_EQ(*maxWritable1, 500);

  auto maxWritable2 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable2.hasError());
  EXPECT_EQ(*maxWritable2, 500);
}

TEST_F(QuicTransportTest, GetMaxWritableBufferSpaceLimitedTwoStreams) {
  auto& conn = transport_->getConnectionState();
  auto transportSettings = transport_->getTransportSettings();
  // Stream IDs are for a peer-initiated bidirectional stream
  StreamId id1 = 0b100;
  StreamId id2 = 0b1100;

  // let's assume we have 1k bytes left in each window
  auto streamResult1 = conn.streamManager->getStream(id1);
  ASSERT_FALSE(streamResult1.hasError());
  auto stream1 = streamResult1.value();
  stream1->currentWriteOffset = 1000;
  stream1->flowControlState.peerAdvertisedMaxOffset = 2000;

  auto streamResult2 = conn.streamManager->getStream(id2);
  ASSERT_FALSE(streamResult2.hasError());
  auto stream2 = streamResult2.value();
  stream2->currentWriteOffset = 1000;
  stream2->flowControlState.peerAdvertisedMaxOffset = 2000;

  // set sum of write offset accordingly
  conn.flowControlState.sumCurWriteOffset = 2000;

  // set total buffer space available < stream and conn fcw, such that we're
  // limited by buffer space
  transportSettings.totalBufferSpaceAvailable = 500;
  transport_->setTransportSettings(transportSettings);
  conn.flowControlState.peerAdvertisedMaxOffset = 3000;

  auto maxWritable1 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable1.hasError());
  EXPECT_EQ(*maxWritable1, transportSettings.totalBufferSpaceAvailable);

  auto maxWritable2 = transport_->getMaxWritableOnStream(id1);
  EXPECT_FALSE(maxWritable2.hasError());
  EXPECT_EQ(*maxWritable2, transportSettings.totalBufferSpaceAvailable);
}

TEST_F(QuicTransportTest, UpdateSocketTosSettingsNoECN) {
  // Pretend the socket is bound so the transport can attempt to set ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(true));

  EXPECT_CALL(*socket_, setRecvTos).Times(0);
  EXPECT_CALL(*socket_, setTosOrTrafficClass(_)).Times(0);

  TransportSettings transportSettings;
  transportSettings.readEcnOnIngress = false;
  transportSettings.enableEcnOnEgress = false;
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  EXPECT_EQ(conn.ecnState, ECNState::NotAttempted);
}

TEST_F(QuicTransportTest, UpdateSocketTosSettingsClassicECN) {
  // Pretend the socket is bound so the transport can attempt to set ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(true));

  EXPECT_CALL(*socket_, setRecvTos).Times(0);
  EXPECT_CALL(*socket_, setTosOrTrafficClass(kEcnECT0)).Times(1);

  TransportSettings transportSettings;
  transportSettings.readEcnOnIngress = false;
  transportSettings.enableEcnOnEgress = true;
  transportSettings.useL4sEcn = false;
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.socketTos.fields.ecn, kEcnECT0);
  EXPECT_EQ(conn.ecnState, ECNState::AttemptingECN);
}

TEST_F(QuicTransportTest, UpdateSocketTosSettingsL4SECN) {
  // Pretend the socket is bound so the transport can attempt to set ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(true));

  EXPECT_CALL(*socket_, setRecvTos).Times(0);
  EXPECT_CALL(*socket_, setTosOrTrafficClass(kEcnECT1)).Times(1);

  TransportSettings transportSettings;
  transportSettings.readEcnOnIngress = false;
  transportSettings.enableEcnOnEgress = true;
  transportSettings.useL4sEcn = true;
  transport_->setTransportSettings(transportSettings);

  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.socketTos.fields.ecn, kEcnECT1);
  EXPECT_EQ(conn.ecnState, ECNState::AttemptingL4S);

  // Setting the same transport settings should not trigger any calls to the
  // socket
  EXPECT_CALL(*socket_, setTosOrTrafficClass(_)).Times(0);
  transport_->setTransportSettings(transportSettings);

  // Disabling ECN should trigger a call to update the socket's tos.
  EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
  transportSettings.enableEcnOnEgress = false;
  transport_->setTransportSettings(transportSettings);
  EXPECT_EQ(conn.ecnState, ECNState::NotAttempted);
}

TEST_F(QuicTransportTest, UpdateSocketTosSettingsDoNotSetTosOnUnboundSocket) {
  // Pretend the socket is not bound so the transport does not attempt to set
  // ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(false));

  EXPECT_CALL(*socket_, setRecvTos).Times(0);
  EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(0);

  TransportSettings transportSettings;
  transportSettings.readEcnOnIngress = false;
  transportSettings.enableEcnOnEgress = true;
  transportSettings.useL4sEcn = false;
  transport_->setTransportSettings(transportSettings);

  // The socket tos should still have been updated
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.socketTos.fields.ecn, kEcnECT0);
}

TEST_F(QuicTransportTest, ValidateECNValidationNotNeeded) {
  // All the tests here should not change anything about the socket state.
  EXPECT_CALL(*socket_, setRecvTos).Times(0);
  EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(0);

  auto& conn = transport_->getConnectionState();

  // This is the default.
  ASSERT_EQ(conn.ecnState, ECNState::NotAttempted);
  transport_->validateECN();
  EXPECT_EQ(conn.ecnState, ECNState::NotAttempted);

  // If validation already failed, nothing should happen either.
  conn.ecnState = ECNState::FailedValidation;
  transport_->validateECN();
  EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
}

TEST_F(QuicTransportTest, ValidateECNSuccess) {
  auto& conn = transport_->getConnectionState();

  {
    conn.ecnState = ECNState::AttemptingECN;
    // Not enough packets to validate ECN
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::AttemptingECN);
  }
  // ==== From attempting to validated ===========
  {
    conn.ecnState = ECNState::AttemptingECN;
    // Marked exactly equal expected.
    // Expected 10. 9 ECT0 + 1 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 1;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedECN);
  }

  {
    conn.ecnState = ECNState::AttemptingECN;
    // Marked more than expected and less than total sent
    // Expected 10. 15 ECT0 + 4 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 15;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 4;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedECN);
  }

  // ==== Already validated ===========

  {
    conn.ecnState = ECNState::ValidatedECN;
    // Marked exactly equal expected.
    // Expected 10. 9 ECT0 + 1 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 1;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedECN);
  }

  {
    conn.ecnState = ECNState::ValidatedECN;
    // Marked more than expected and less than total sent
    // Expected 10. 15 ECT0 + 4 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 15;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 4;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedECN);
  }
}

TEST_F(QuicTransportTest, ValidateECNFailure) {
  auto& conn = transport_->getConnectionState();

  // Pretend the socket is bound so the transport can attempt to set ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(true));

  // ==== From attempting to failed ===========
  {
    conn.ecnState = ECNState::AttemptingECN;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Marked less than expected.
    // Expected 10. 9 ECT0 + 0 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::AttemptingECN;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Marked more than total.
    // Expected 10. 19 ECT0 + 2 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 19;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 2;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::AttemptingECN;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Wrong ECT marking received
    // Expected 10. 1 ECT1
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 1;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  // ==== From valdiated to failed ===========
  {
    conn.ecnState = ECNState::ValidatedECN;
    conn.ecnL4sTracker = std::make_shared<EcnL4sTracker>(conn);
    conn.socketTos.fields.ecn = kEcnECT0;
    // Marked less than expected.
    // Expected 10. 9 ECT0 + 0 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
    EXPECT_FALSE(conn.ecnL4sTracker);
  }

  {
    conn.ecnState = ECNState::ValidatedECN;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Marked more than total.
    // Expected 10. 19 ECT0 + 2 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 19;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 2;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::ValidatedECN;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Wrong ECT marking received
    // Expected 10. 1 ECT1
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 1;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }
}

TEST_F(QuicTransportTest, ValidateL4SSuccess) {
  auto& conn = transport_->getConnectionState();
  ASSERT_FALSE(conn.ecnL4sTracker);

  {
    conn.ecnState = ECNState::AttemptingL4S;
    // Not enough packets to validate L4S
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::AttemptingL4S);
  }
  // ==== From attempting to validated ===========
  {
    conn.ecnState = ECNState::AttemptingL4S;
    // Marked exactly equal expected.
    // Expected 10. 9 ECT1 + 1 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 1;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedL4S);
    EXPECT_TRUE(conn.ecnL4sTracker);
  }

  {
    conn.ecnState = ECNState::AttemptingL4S;
    // Marked more than expected and less than total sent
    // Expected 10. 15 ECT1 + 4 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 15;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 4;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedL4S);
  }

  // ==== Already validated ===========

  {
    conn.ecnState = ECNState::ValidatedL4S;
    // Marked exactly equal expected.
    // Expected 10. 9 ECT1 + 1 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 1;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedL4S);
  }

  {
    conn.ecnState = ECNState::ValidatedL4S;
    // Marked more than expected and less than total sent
    // Expected 10. 15 ECT1 + 4 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 15;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 4;
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::ValidatedL4S);
  }
}

TEST_F(QuicTransportTest, ValidateL4SFailure) {
  auto& conn = transport_->getConnectionState();

  // Pretend the socket is bound so the transport can attempt to set ToS.
  EXPECT_CALL(*socket_, isBound).WillRepeatedly(Return(true));

  // ==== From attempting to failed ===========
  {
    conn.ecnState = ECNState::AttemptingL4S;
    conn.socketTos.fields.ecn = kEcnECT1;
    // Marked less than expected.
    // Expected 10. 9 ECT1 + 0 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::AttemptingL4S;
    conn.socketTos.fields.ecn = kEcnECT1;
    // Marked more than total.
    // Expected 10. 19 ECT1 + 2 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 19;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 2;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::AttemptingL4S;
    conn.socketTos.fields.ecn = kEcnECT1;
    // Wrong ECT marking received
    // Expected 10. 1 ECT0
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 1;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  // ==== From valdiated to failed ===========
  {
    conn.ecnState = ECNState::ValidatedL4S;
    conn.socketTos.fields.ecn = kEcnECT1;
    // Marked less than expected.
    // Expected 10. 9 ECT1 + 0 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 9;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::ValidatedL4S;
    conn.socketTos.fields.ecn = kEcnECT1;
    // Marked more than total.
    // Expected 10. 19 ECT1 + 2 CE
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 19;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 2;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }

  {
    conn.ecnState = ECNState::ValidatedL4S;
    conn.socketTos.fields.ecn = kEcnECT0;
    // Wrong ECT marking received
    // Expected 10. 1 ECT0
    conn.lossState.totalPacketsSent = 20;
    conn.ackStates.appDataAckState.minimumExpectedEcnMarksEchoed = 10;
    conn.ackStates.appDataAckState.ecnECT0CountEchoed = 1;
    conn.ackStates.appDataAckState.ecnECT1CountEchoed = 0;
    conn.ackStates.appDataAckState.ecnCECountEchoed = 0;
    EXPECT_CALL(*socket_, setTosOrTrafficClass(0)).Times(1);
    transport_->validateECN();
    EXPECT_EQ(conn.ecnState, ECNState::FailedValidation);
    EXPECT_EQ(conn.socketTos.fields.ecn, 0);
  }
}

} // namespace quic::test
