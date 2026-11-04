/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/stream/StreamStateFunctions.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

using namespace testing;

namespace quic::test {

// Fake PriorityQueue that records insertOrUpdate calls for verification
class FakePriorityQueue : public PriorityQueue {
 public:
  struct InsertRecord {
    Identifier id;
    Priority priority;
  };

  [[nodiscard]] bool contains(Identifier) const noexcept override {
    return false;
  }

  [[nodiscard]] bool empty() const noexcept override {
    return true;
  }

  [[nodiscard]] PriorityLogFields toLogFields(const Priority&) const override {
    return {};
  }

  [[nodiscard]] bool equalPriority(const Priority&, const Priority&)
      const override {
    return true;
  }

  void insertOrUpdate(Identifier id, Priority priority) override {
    inserts.push_back({id, priority});
  }

  void updateIfExist(Identifier, Priority) override {}

  void erase(Identifier) override {}

  void clear() override {}

  Identifier getNextScheduledID(quic::Optional<uint64_t>) override {
    return {};
  }

  [[nodiscard]] Identifier peekNextScheduledID() const override {
    return {};
  }

  [[nodiscard]] Priority headPriority() const override {
    return {};
  }

  void consume(quic::Optional<uint64_t>) override {}

  Transaction beginTransaction() override {
    return makeTransaction();
  }

  void commitTransaction(Transaction&&) override {}

  void rollbackTransaction(Transaction&&) override {}

  std::vector<InsertRecord> inserts;
};

struct StreamManagerTestParam {
  bool isUnidirectional{false};
};

class QuicStreamManagerTest
    : public Test,
      public WithParamInterface<StreamManagerTestParam> {
 public:
  QuicStreamManagerTest()
      : conn(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;

    // Use ASSERT checks in SetUp as failure here invalidates subsequent tests
    ASSERT_TRUE(
        conn.streamManager
            ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
            .has_value());
    ASSERT_TRUE(
        conn.streamManager
            ->setMaxLocalUnidirectionalStreams(kDefaultMaxStreamsUnidirectional)
            .has_value());

    auto congestionController =
        std::make_unique<NiceMock<MockCongestionController>>();
    mockController = congestionController.get();
    conn.congestionController = std::move(congestionController);

    ASSERT_TRUE(
        conn.streamManager->refreshTransportSettings(conn.transportSettings)
            .has_value());
  }

  QuicServerConnectionState conn;
  MockCongestionController* mockController;
};

TEST_P(QuicStreamManagerTest, SkipRedundantPriorityUpdate) {
  auto& manager = *conn.streamManager;
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  auto streamId = stream->id;
  HTTPPriorityQueue::Priority currentPriority(stream->priority);
  EXPECT_TRUE(manager.setStreamPriority(
      streamId,
      HTTPPriorityQueue::Priority(
          (currentPriority->urgency + 1) % (kDefaultMaxPriority + 1),
          !currentPriority->incremental)));
  EXPECT_FALSE(manager.setStreamPriority(
      streamId,
      HTTPPriorityQueue::Priority(
          (currentPriority->urgency + 1) % (kDefaultMaxPriority + 1),
          !currentPriority->incremental)));
}

TEST_P(QuicStreamManagerTest, OnMaxDataSkipsDrainedConnFcBlockedStream) {
  auto& manager = *conn.streamManager;
  auto* stream = manager.createNextBidirectionalStream().value();
  auto id = PriorityQueue::Identifier::fromStreamID(stream->id);

  stream->pendingWrites =
      ChainedByteRangeHead(folly::IOBuf::copyBuffer(std::string(100, 'a')));
  manager.updateWritableStreams(*stream);
  ASSERT_TRUE(manager.writeQueue().contains(id));

  // Stream gets conn-FC-blocked, then its data drains before MAX_DATA arrives.
  manager.writeQueue().erase(id);
  manager.addConnFCBlockedStream(stream->id);
  stream->pendingWrites = ChainedByteRangeHead();
  manager.updateWritableStreams(*stream);
  ASSERT_FALSE(manager.writeQueue().contains(id));

  // onMaxData must not re-add the drained stream, else it spins the write loop.
  manager.onMaxData();
  EXPECT_TRUE(manager.writeQueue().empty());
  EXPECT_FALSE(manager.hasWritable());
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateBidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  // The app limited state did not change.
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  StreamId id = stream->id;
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_FALSE(getResult.hasError());
  ASSERT_TRUE(getResult.has_value());
  EXPECT_EQ(getResult.value(), nullptr); // Check stream is gone (nullptr)
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreateUnidiStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);
  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  // Force transition to closed state
  EXPECT_CALL(*mockController, setAppIdle(true, _));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingLocalStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(stream->id);
  ASSERT_TRUE(getResult.has_value());
  EXPECT_NE(getResult.value(), nullptr); // Stream should still exist
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleStreamAsControl) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());

  auto streamResult = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  auto streamResult2 = manager.createNextUnidirectionalStream();
  ASSERT_TRUE(streamResult2.has_value());
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleCreatePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(false, _));
  StreamId id2 = 4;
  auto streamResult2 = manager.getStream(id2);
  ASSERT_TRUE(streamResult2.has_value());
  ASSERT_NE(streamResult2.value(), nullptr);
  EXPECT_FALSE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleExistingPeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_TRUE(getResult.has_value());
  EXPECT_NE(getResult.value(), nullptr);
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, TestAppIdleClosePeerStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());

  auto getResult = manager.getStream(id);
  ASSERT_FALSE(getResult.hasError());
  ASSERT_TRUE(getResult.has_value());
  EXPECT_EQ(getResult.value(), nullptr); // Check stream is gone
}

TEST_P(QuicStreamManagerTest, TestAppIdleCloseControlStream) {
  auto& manager = *conn.streamManager;
  EXPECT_FALSE(manager.isAppIdle());
  EXPECT_CALL(*mockController, setAppIdle(false, _)).Times(0);

  StreamId id = 0;
  auto streamResult = manager.getStream(id);
  ASSERT_FALSE(streamResult.hasError());
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();
  ASSERT_NE(stream, nullptr);
  EXPECT_FALSE(manager.isAppIdle());

  EXPECT_CALL(*mockController, setAppIdle(true, _));
  manager.setStreamAsControl(*stream);
  EXPECT_TRUE(manager.isAppIdle());

  // Force transition to closed state
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  EXPECT_TRUE(manager.isAppIdle());
}

TEST_P(QuicStreamManagerTest, PeerMaxStreamsLimitSaturated) {
  MockQuicStats mockStats;
  conn.statsCallback = &mockStats;
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 10;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 10;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(1);

  // open 9 streams which is just below the limit, should not invoke callback
  EXPECT_CALL(mockStats, onPeerMaxBidiStreamsLimitSaturated).Times(0);
  EXPECT_CALL(mockStats, onPeerMaxUniStreamsLimitSaturated).Times(0);
  uint8_t idx = 0;
  for (idx = 0; idx < 9; idx++) {
    ASSERT_FALSE(manager.getStream(idx * detail::kStreamIncrement).hasError());
    ASSERT_FALSE(
        manager.getStream(2 + idx * detail::kStreamIncrement).hasError());
  }
  // peer saturating all bidi & uni streams should invoke callback
  EXPECT_CALL(mockStats, onPeerMaxBidiStreamsLimitSaturated).Times(1);
  EXPECT_CALL(mockStats, onPeerMaxUniStreamsLimitSaturated).Times(1);
  // create last stream that will saturate the limit
  ASSERT_FALSE(manager.getStream(idx * detail::kStreamIncrement).hasError());
  ASSERT_FALSE(
      manager.getStream(2 + idx * detail::kStreamIncrement).hasError());

  // close all opened streams will send peer max streams credit
  for (idx = 0; idx < 10; idx++) {
    auto streamResult1 = manager.getStream(idx * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult1.hasError());
    ASSERT_TRUE(streamResult1.has_value());
    auto* stream1 = streamResult1.value();
    ASSERT_NE(stream1, nullptr);
    stream1->sendState = StreamSendState::Closed;
    stream1->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream1->id).hasError());

    auto streamResult2 = manager.getStream(2 + idx * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult2.hasError());
    ASSERT_TRUE(streamResult2.has_value());
    auto* stream2 = streamResult2.value();
    ASSERT_NE(stream2, nullptr);
    stream2->sendState = StreamSendState::Closed;
    stream2->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream2->id).hasError());
  }

  // validate transport will advertise an update
  auto bidiUpdate = manager.remoteBidirectionalStreamLimitUpdate();
  auto uniUpdate = manager.remoteUnidirectionalStreamLimitUpdate();
  ASSERT_TRUE(bidiUpdate.has_value());
  ASSERT_TRUE(uniUpdate.has_value());
  EXPECT_EQ(bidiUpdate.value(), 20);
  EXPECT_EQ(uniUpdate.value(), 20);

  // should not advertise again since no streams were consumed
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
    ASSERT_FALSE(
        manager.getStream(2 + i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 25; i++) {
    auto streamResult1 = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult1.hasError());
    ASSERT_TRUE(streamResult1.has_value());
    auto* stream1 = streamResult1.value();
    ASSERT_NE(stream1, nullptr);
    stream1->sendState = StreamSendState::Closed;
    stream1->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream1->id).hasError());

    auto streamResult2 = manager.getStream(2 + i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult2.hasError());
    ASSERT_TRUE(streamResult2.has_value());
    auto* stream2 = streamResult2.value();
    ASSERT_NE(stream2, nullptr);
    stream2->sendState = StreamSendState::Closed;
    stream2->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream2->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());

  update = manager.remoteUnidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 125);
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitNoWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 24; i++) {
    auto streamResult = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult.hasError());
    ASSERT_TRUE(streamResult.has_value());
    auto* stream = streamResult.value();
    ASSERT_NE(stream, nullptr);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  EXPECT_FALSE(update.has_value());
}

TEST_P(QuicStreamManagerTest, StreamLimitManyWindowedUpdate) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 100;
  ASSERT_FALSE(
      manager.refreshTransportSettings(conn.transportSettings).hasError());
  manager.setStreamLimitWindowingFraction(4);
  for (int i = 0; i < 100; i++) {
    ASSERT_FALSE(manager.getStream(i * detail::kStreamIncrement).hasError());
  }
  for (int i = 0; i < 50; i++) {
    auto streamResult = manager.getStream(i * detail::kStreamIncrement);
    ASSERT_FALSE(streamResult.hasError());
    ASSERT_TRUE(streamResult.has_value());
    auto* stream = streamResult.value();
    ASSERT_NE(stream, nullptr);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    ASSERT_FALSE(manager.removeClosedStream(stream->id).hasError());
  }
  auto update = manager.remoteBidirectionalStreamLimitUpdate();
  ASSERT_TRUE(update.has_value());
  EXPECT_EQ(update.value(), 150);
  EXPECT_FALSE(manager.remoteBidirectionalStreamLimitUpdate());
  EXPECT_FALSE(manager.remoteUnidirectionalStreamLimitUpdate());
}

TEST_P(QuicStreamManagerTest, StreamLimitIncrementBidi) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(100, true).has_value());
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());
  StreamId max;
  for (int i = 0; i < 100; i++) {
    auto result = manager.createNextBidirectionalStream();
    ASSERT_TRUE(result.has_value());
    max = result.value()->id;
  }
  auto errorResult = manager.createNextBidirectionalStream();
  EXPECT_TRUE(errorResult.hasError());
  EXPECT_EQ(errorResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);

  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(200).has_value());
  auto s = manager.createNextBidirectionalStream();
  EXPECT_TRUE(s.has_value());
  EXPECT_EQ(s.value()->id, max + detail::kStreamIncrement);
}

TEST_P(QuicStreamManagerTest, ConsumeStopSending) {
  auto& manager = *conn.streamManager;
  manager.addStopSending(0, GenericApplicationErrorCode::NO_ERROR);
  EXPECT_EQ(manager.stopSendingStreams().size(), 1);
  auto result = manager.consumeStopSending();
  ASSERT_EQ(result.size(), 1);
  EXPECT_EQ(result.front().first, 0);
  EXPECT_EQ(result.front().second, GenericApplicationErrorCode::NO_ERROR);
  EXPECT_TRUE(manager.stopSendingStreams().empty());
}

TEST_P(QuicStreamManagerTest, StreamLimitIncrementUni) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(100, true).has_value());
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());
  StreamId max;
  for (int i = 0; i < 100; i++) {
    auto result = manager.createNextUnidirectionalStream();
    ASSERT_TRUE(result.has_value());
    max = result.value()->id;
  }
  auto errorResult = manager.createNextUnidirectionalStream();
  EXPECT_TRUE(errorResult.hasError());
  EXPECT_EQ(errorResult.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);

  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(200).has_value());
  auto s = manager.createNextUnidirectionalStream();
  EXPECT_TRUE(s.has_value());
  EXPECT_EQ(s.value()->id, max + detail::kStreamIncrement);
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;
  const StreamId serverStreamId3 =
      serverStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(
      serverStreamId3, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalUnidirectionalStreams(2, true).has_value());

  const StreamId serverStreamId1 = 0x03;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalUnidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptableLocalUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptableLocalBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  ASSERT_TRUE(manager.setMaxLocalBidirectionalStreams(2, true).has_value());

  const StreamId serverStreamId1 = 0x01;
  const StreamId serverStreamId2 = serverStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      serverStreamId1, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId1).has_value());
  EXPECT_EQ(
      serverStreamId2, manager.nextAcceptableLocalBidirectionalStreamId());

  ASSERT_TRUE(manager.createStream(serverStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptableLocalBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(
      clientStreamId3, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamId) {
  auto& manager = *conn.streamManager;

  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;
  const StreamId clientStreamId3 =
      clientStreamId1 + (detail::kStreamIncrement * 2);

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(clientStreamId3, manager.nextAcceptablePeerBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerUnidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsUni = 2;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId clientStreamId1 = 0x02;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(
      clientStreamId1, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(
      clientStreamId2, manager.nextAcceptablePeerUnidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptablePeerUnidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, NextAcceptablePeerBidirectionalStreamIdLimit) {
  auto& manager = *conn.streamManager;
  conn.transportSettings.advertisedInitialMaxStreamsBidi = 2;
  ASSERT_TRUE(
      manager.refreshTransportSettings(conn.transportSettings).has_value());

  const StreamId clientStreamId1 = 0x00;
  const StreamId clientStreamId2 = clientStreamId1 + detail::kStreamIncrement;

  EXPECT_EQ(clientStreamId1, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId1).has_value());
  EXPECT_EQ(clientStreamId2, manager.nextAcceptablePeerBidirectionalStreamId());

  ASSERT_TRUE(manager.getStream(clientStreamId2).has_value());
  EXPECT_EQ(std::nullopt, manager.nextAcceptablePeerBidirectionalStreamId());
}

TEST_P(QuicStreamManagerTest, TestClearActionable) {
  auto& manager = *conn.streamManager;

  StreamId id = 1;
  auto stream = manager.createNextUnidirectionalStream().value();

  stream->readBuffer.emplace_back(folly::IOBuf::copyBuffer("blah blah"), 0);
  manager.queueFlowControlUpdated(id);
  manager.addDeliverable(id);
  manager.updateReadableStreams(*stream);
  manager.updatePeekableStreams(*stream);
  EXPECT_TRUE(manager.flowControlUpdatedContains(id));
  EXPECT_TRUE(manager.deliverableContains(id));
  EXPECT_FALSE(manager.readableStreams().empty());

  EXPECT_FALSE(manager.peekableStreams().empty());
  manager.clearActionable();
  EXPECT_FALSE(manager.flowControlUpdatedContains(id));
  EXPECT_FALSE(manager.deliverableContains(id));
  EXPECT_TRUE(manager.readableStreams().empty());

  EXPECT_TRUE(manager.peekableStreams().empty());
}

TEST_P(QuicStreamManagerTest, RemoveResetsUponClosure) {
  auto& manager = *conn.streamManager;
  auto streamResult = manager.createNextBidirectionalStream();
  ASSERT_TRUE(streamResult.has_value());
  auto* stream = streamResult.value();

  auto streamId = stream->id;
  conn.pendingEvents.resets.emplace(
      streamId,
      RstStreamFrame(streamId, GenericApplicationErrorCode::NO_ERROR, 0));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;

  EXPECT_TRUE(conn.pendingEvents.resets.contains(streamId));
  ASSERT_FALSE(manager.removeClosedStream(streamId).hasError());
  EXPECT_FALSE(conn.pendingEvents.resets.contains(streamId));
}

BufPtr createBuffer(uint32_t len) {
  auto buf = folly::IOBuf::create(len);
  buf->append(len);
  return buf;
}

TEST_P(QuicStreamManagerTest, TestReliableResetBasic) {
  auto& manager = *conn.streamManager;

  auto maybeQuicStreamState = manager.createNextBidirectionalStream();
  ASSERT_TRUE(maybeQuicStreamState.has_value());
  auto* quicStreamState = maybeQuicStreamState.value();

  // Assume we've written out 5 bytes to the wire already, and have
  // received acknowledgements for the same.
  quicStreamState->writeBufferStartOffset = 5;
  quicStreamState->currentWriteOffset = 5;
  quicStreamState->ackedIntervals.insert(0, 4);

  // Assume that the application has written an additional 8 bytes to
  // the transport layer
  auto buf = createBuffer(8);
  quicStreamState->pendingWrites = ChainedByteRangeHead(buf->clone());
  quicStreamState->writeBuffer.append(std::move(buf));
  ASSERT_FALSE(
      updateFlowControlOnWriteToStream(*quicStreamState, 8).hasError());

  // A frame of length 4 has been written to the wire
  quicStreamState->currentWriteOffset += 4;
  ChainedByteRangeHead bufWritten1(
      quicStreamState->pendingWrites.splitAtMost(4));
  quicStreamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(5),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              std::move(bufWritten1), 5, false)));
  ASSERT_FALSE(
      updateFlowControlOnWriteToSocket(*quicStreamState, 4).hasError());

  // A frame of length 2 has been written to the wire
  quicStreamState->currentWriteOffset += 2;
  ChainedByteRangeHead bufWritten2(
      quicStreamState->pendingWrites.splitAtMost(2));
  quicStreamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(9),
      std::forward_as_tuple(
          std::make_unique<WriteStreamBuffer>(
              std::move(bufWritten2), 9, false)));
  ASSERT_FALSE(
      updateFlowControlOnWriteToSocket(*quicStreamState, 2).hasError());

  // The frame of length 4 has been lost
  auto bufferItr = quicStreamState->retransmissionBuffer.find(5);
  ASSERT_NE(bufferItr, quicStreamState->retransmissionBuffer.end());
  quicStreamState->insertIntoLossBuffer(std::move(bufferItr->second));
  quicStreamState->retransmissionBuffer.erase(bufferItr);

  // We send a reliable reset with a reliable size of 7
  ASSERT_FALSE(resetQuicStream(
                   *quicStreamState, GenericApplicationErrorCode::NO_ERROR, 7)
                   .hasError());

  EXPECT_EQ(quicStreamState->writeBuffer.chainLength(), 2);
  EXPECT_EQ(quicStreamState->pendingWrites.chainLength(), 0);
  EXPECT_TRUE(quicStreamState->retransmissionBuffer.empty());
  EXPECT_EQ(quicStreamState->lossBuffer.size(), 1);
  EXPECT_EQ(quicStreamState->lossBuffer[0].offset, 5);
  EXPECT_EQ(quicStreamState->lossBuffer[0].data.chainLength(), 2);
  EXPECT_EQ(quicStreamState->conn.flowControlState.sumCurStreamBufferLen, 0);

  // We send a reliable reset with a reliable size of 6
  ASSERT_FALSE(resetQuicStream(
                   *quicStreamState, GenericApplicationErrorCode::NO_ERROR, 6)
                   .hasError());

  EXPECT_EQ(quicStreamState->writeBuffer.chainLength(), 1);
  EXPECT_EQ(quicStreamState->pendingWrites.chainLength(), 0);
  EXPECT_TRUE(quicStreamState->retransmissionBuffer.empty());
  EXPECT_EQ(quicStreamState->lossBuffer.size(), 1);
  EXPECT_EQ(quicStreamState->lossBuffer[0].offset, 5);
  EXPECT_EQ(quicStreamState->lossBuffer[0].data.chainLength(), 1);
  EXPECT_EQ(quicStreamState->conn.flowControlState.sumCurStreamBufferLen, 0);
}

TEST_P(QuicStreamManagerTest, SetPriorityQueueEmpty) {
  auto& manager = *conn.streamManager;
  auto mockQueue = std::make_unique<FakePriorityQueue>();
  auto* mockPtr = mockQueue.get();
  auto result = manager.setPriorityQueue(std::move(mockQueue));
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(mockPtr->inserts.empty());
  EXPECT_EQ(&manager.writeQueue(), mockPtr);
}

TEST_P(QuicStreamManagerTest, SetPriorityQueueDrainsWithUninitPriority) {
  auto& manager = *conn.streamManager;

  // Insert streams directly into the write queue
  auto id1 = PriorityQueue::Identifier::fromStreamID(0);
  auto id2 = PriorityQueue::Identifier::fromStreamID(4);
  manager.writeQueue().insertOrUpdate(
      id1, HTTPPriorityQueue::Priority(3, true));
  manager.writeQueue().insertOrUpdate(
      id2, HTTPPriorityQueue::Priority(5, false));

  ASSERT_FALSE(manager.writeQueue().empty());
  ASSERT_TRUE(manager.writeQueue().contains(id1));
  ASSERT_TRUE(manager.writeQueue().contains(id2));

  // Replace with mock queue
  auto mockQueue = std::make_unique<FakePriorityQueue>();
  auto* mockPtr = mockQueue.get();
  auto result = manager.setPriorityQueue(std::move(mockQueue));
  ASSERT_FALSE(result.hasError());

  // Verify all streams were drained with uninitialized priority
  ASSERT_EQ(mockPtr->inserts.size(), 2);
  // Order depends on HTTPPriorityQueue scheduling; just check both are present
  // with uninitialized priority
  for (const auto& record : mockPtr->inserts) {
    EXPECT_FALSE(record.priority.isInitialized());
  }
  EXPECT_NE(mockPtr->inserts[0].id, mockPtr->inserts[1].id);
}

TEST_P(QuicStreamManagerTest, OpenReceiveStreamIdsIncludesImplicitPeerStreams) {
  auto& manager = *conn.streamManager;
  const auto localBidiId = manager.createNextBidirectionalStream().value()->id;
  ASSERT_TRUE(manager.createNextUnidirectionalStream().has_value());
  // Opening a peer stream implicitly opens the lower ones of the same type
  // without creating their state.
  ASSERT_NE(manager.getStream(4).value(), nullptr);
  ASSERT_NE(manager.getStream(10).value(), nullptr);
  ASSERT_FALSE(manager.streams().contains(2));

  const std::vector<StreamId> expectedIds{localBidiId, 0, 4, 2, 6, 10};
  EXPECT_THAT(
      manager.openReceiveStreamIds(), UnorderedElementsAreArray(expectedIds));
}

// After retireIngressOfNewPeerStreams(), only peer streams created afterwards
// are retired, each with one STOP_SENDING.
TEST_P(
    QuicStreamManagerTest,
    RetireIngressOfNewPeerStreamsRetiresOnlyPeerStreamsCreatedLater) {
  auto& manager = *conn.streamManager;
  constexpr ApplicationErrorCode kError{7};
  ASSERT_NE(manager.getStream(0).value(), nullptr);

  manager.retireIngressOfNewPeerStreams(kError);
  const auto localStreamId =
      manager.createNextBidirectionalStream().value()->id;
  ASSERT_NE(manager.getStream(4).value(), nullptr);

  // Creating streams can move the others, so look each one up afterwards.
  EXPECT_FALSE(CHECK_NOTNULL(manager.findStream(0))->ingressRetired);
  EXPECT_FALSE(
      CHECK_NOTNULL(manager.findStream(localStreamId))->ingressRetired);
  EXPECT_TRUE(CHECK_NOTNULL(manager.findStream(4))->ingressRetired);
  ASSERT_EQ(conn.pendingEvents.frames.size(), 1);
  const auto* stopSending =
      conn.pendingEvents.frames.front().asStopSendingFrame();
  ASSERT_NE(stopSending, nullptr);
  EXPECT_EQ(stopSending->streamId, 4);
  EXPECT_EQ(stopSending->errorCode, kError);
}

TEST_P(QuicStreamManagerTest, RetireIngressOfNewPeerStreamsKeepsTheFirstError) {
  auto& manager = *conn.streamManager;
  manager.retireIngressOfNewPeerStreams(ApplicationErrorCode{7});
  manager.retireIngressOfNewPeerStreams(ApplicationErrorCode{9});

  EXPECT_EQ(
      manager.newPeerStreamStopSendingError(),
      Optional<ApplicationErrorCode>{ApplicationErrorCode{7}});
}

// A stream manager moved to another connection state keeps retiring new peer
// streams.
TEST_P(QuicStreamManagerTest, RetiringNewPeerStreamsSurvivesMovingTheManager) {
  conn.streamManager->retireIngressOfNewPeerStreams(ApplicationErrorCode{7});

  const QuicStreamManager moved(
      conn,
      conn.nodeType,
      conn.transportSettings,
      std::move(*conn.streamManager));

  EXPECT_EQ(
      moved.newPeerStreamStopSendingError(),
      Optional<ApplicationErrorCode>{ApplicationErrorCode{7}});
}

TEST_P(QuicStreamManagerTest, ReadBufferRangeAccountingSurvivesMoveAndClear) {
  auto& manager = *conn.streamManager;
  auto* stream = manager.createNextBidirectionalStream().value();
  const auto streamId = stream->id;
  stream->readBuffer.emplace_back(folly::IOBuf::copyBuffer("data"), 1);
  manager.updateReadBufferRanges(0, 1);

  QuicStreamManager moved(
      conn, conn.nodeType, conn.transportSettings, std::move(manager));

  EXPECT_EQ(conn.streamManager->numReadBufferRanges(), 0);
  ASSERT_NE(moved.findStream(streamId), nullptr);
  EXPECT_EQ(
      moved.numReadBufferRanges(),
      moved.findStream(streamId)->readBuffer.size());
  moved.clearOpenStreams();
  EXPECT_EQ(moved.numReadBufferRanges(), 0);
}

INSTANTIATE_TEST_SUITE_P(
    QuicStreamManagerTest,
    QuicStreamManagerTest,
    ::testing::Values(
        StreamManagerTestParam{false})); // isUnidirectional = false

} // namespace quic::test
