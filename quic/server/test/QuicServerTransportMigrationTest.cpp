/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/test/QuicServerTransportTestUtil.h>

#include <quic/QuicConstants.h>
#include <quic/codec/QuicPacketBuilder.h>

#include <quic/logging/FileQLogger.h>
#include <quic/priority/HTTPPriorityQueue.h>

#include <quic/state/test/Mocks.h>

using namespace testing;
using namespace folly;

namespace quic {
class PathManagerTestAccessor {
 public:
  static PathInfo& getNonConstPathInfo(
      QuicConnectionStateBase& conn,
      PathIdType pathId) {
    return conn.pathManager->pathIdToInfo_.at(pathId);
  }
};
} // namespace quic

namespace quic::test {

struct MigrationParam {
  Optional<uint64_t> clientSentActiveConnIdTransportParam;
};

class QuicServerTransportAllowMigrationTest
    : public QuicServerTransportAfterStartTestBase,
      public WithParamInterface<MigrationParam> {
 public:
  void SetUpChild() override {
    QuicServerTransportAfterStartTestBase::SetUpChild();
    // Add peer connection IDs
    server->getNonConstConn().peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({5, 6, 7, 8}), 1);
    server->getNonConstConn().peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash({9, 10, 11, 12}), 2);
  }

  void TearDown() override {
    if (server) {
      server->closeNow(std::nullopt);
    }
  }

  bool getDisableMigration() override {
    return false;
  }

  void initializeServerHandshake() override {
    fakeHandshake = new FakeServerHandshake(
        server->getNonConstConn(),
        FizzServerQuicHandshakeContext::Builder().build(),
        false,
        false,
        GetParam().clientSentActiveConnIdTransportParam);
    ON_CALL(*fakeHandshake, writeNewSessionTicket)
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
  }

  PathChallengeFrame* getFirstOutstandingPathChallenge() {
    auto match =
        findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>();
    auto outstandingPacket =
        findOutstandingPacket(server->getConnectionState(), match);
    if (outstandingPacket) {
      auto& packet = outstandingPacket->packet;
      auto& frames = packet.frames;
      for (auto& frame : frames) {
        if (auto simpleFrame = frame.asQuicSimpleFrame()) {
          if (simpleFrame->type() ==
              QuicSimpleFrame::Type::PathChallengeFrame) {
            return simpleFrame->asPathChallengeFrame();
          }
        }
      }
    }
    return nullptr;
  }

  PathResponseFrame* getFirstOutstandingPathResponse() {
    auto match =
        findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>();
    auto outstandingPacket =
        findOutstandingPacket(server->getConnectionState(), match);
    if (outstandingPacket) {
      auto& packet = outstandingPacket->packet;
      auto& frames = packet.frames;
      for (auto& frame : frames) {
        if (auto simpleFrame = frame.asQuicSimpleFrame()) {
          if (simpleFrame->type() == QuicSimpleFrame::Type::PathResponseFrame) {
            return simpleFrame->asPathResponseFrame();
          }
        }
      }
    }
    return nullptr;
  }

  quic::PacketBuilderInterface::Packet makePacketWithPathChallegeFrame(
      uint64_t pathChallengeData) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        static_cast<uint32_t>(server->getConn().udpSendPacketLen),
        std::move(header),
        0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    CHECK(!writeSimpleFrame(PathChallengeFrame(pathChallengeData), builder)
               .hasError());
    auto packet = std::move(builder).buildPacket();
    return packet;
  }

  quic::PacketBuilderInterface::Packet makePacketWithPathResponseFrame(
      uint64_t pathChallengeData) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        server->getConn().udpSendPacketLen,
        std::move(header),
        0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    CHECK(!writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
               .hasError());
    auto packet = std::move(builder).buildPacket();
    return packet;
  }

  quic::PacketBuilderInterface::Packet makePacketWithTimestampFrame() {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        static_cast<uint32_t>(server->getConn().udpSendPacketLen),
        std::move(header),
        0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    CHECK(!writeFrame(TimestampFrame(1234), builder).hasError());
    return std::move(builder).buildPacket();
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicServerTransportMigrationTests,
    QuicServerTransportAllowMigrationTest,
    Values(
        MigrationParam{std::nullopt},
        MigrationParam{2},
        MigrationParam{4},
        MigrationParam{9},
        MigrationParam{50}));

TEST_P(QuicServerTransportAllowMigrationTest, TimestampFrameIsNotPathProbing) {
  auto& conn = server->getConn();
  const auto initialPathId = conn.currentPathId;
  quic::SocketAddress newPeer("100.101.102.103", 23456);

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);

  auto packetData = packetToBuf(makePacketWithTimestampFrame());
  deliverData(std::move(packetData), false, &newPeer);

  EXPECT_NE(conn.currentPathId, initialPathId);
  EXPECT_EQ(conn.peerAddress, newPeer);
}

TEST_P(QuicServerTransportAllowMigrationTest, TimestampFrameIsCounted) {
  EXPECT_CALL(*quicStats_, onTimestampFrameReceived()).Times(1);

  deliverData(packetToBuf(makePacketWithTimestampFrame()));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    SendsCorrectNumberOfNewConnectionIdsBasedOnParam) {
  auto& conn = server->getNonConstConn();

  auto expectedPeerLimit =
      GetParam().clientSentActiveConnIdTransportParam.value_or(
          kDefaultActiveConnectionIdLimit);
  ASSERT_EQ(conn.peerActiveConnectionIdLimit, expectedPeerLimit);

  // The server should issue active_connection_id_limit - 1
  // NEW_CONNECTION_IDs, since one is in use for the handshake.
  auto expectedCountCIDIssued =
      std::min(kMaxActiveConnectionIdLimit, expectedPeerLimit) - 1;
  ASSERT_GE(expectedCountCIDIssued, 0);

  // Count the number of NEW_CONNECTION_ID frames in outstanding packets.
  size_t numNewConnIdFrames = 0;
  for (const auto& pkt : conn.outstandings.packets) {
    for (const auto& frame : pkt.packet.frames) {
      if (auto simpleFrame = frame.asQuicSimpleFrame()) {
        if (simpleFrame->type() ==
            QuicSimpleFrame::Type::NewConnectionIdFrame) {
          ++numNewConnIdFrames;
        }
      }
    }
  }

  EXPECT_EQ(numNewConnIdFrames, expectedCountCIDIssued);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithoutMigratingLongGracePeriod) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Deliver a path response to validate the new peer
  {
    // Set a very high srtt to ensure that the new path is not immediately
    // deleted. The grace period for the client to migrate is
    // kProbedPathGracePeriodInSRTT * SRTT
    conn.lossState.srtt = 10s;

    auto packet =
        makePacketWithPathResponseFrame(outstandingChallenge->pathData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_TRUE(newPath->pathValidationTime.has_value());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithoutMigratingShortGracePeriod) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  auto newPathId = newPath->id;
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Deliver a path response to validate the new peer
  {
    // Set no grace period for the client to migrate. This should immediately
    // delete the validated non primary path.
    conn.lossState.srtt = 0s;

    auto packet =
        makePacketWithPathResponseFrame(outstandingChallenge->pathData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }
  // The client didn't migrate before the grace period so the path was deleted.
  EXPECT_FALSE(conn.pathManager->getPath(newPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveProbeFromNewPeerAddressWithMigrating) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;
  conn.transportSettings.disableMigration = false;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_GE(newPath->writableBytes, conn.udpSendPacketLen);

  // A path response and a new path challege should be outstanding for the path
  auto outstandingResponse = getFirstOutstandingPathResponse();
  ASSERT_TRUE(outstandingResponse);
  EXPECT_EQ(outstandingResponse->pathData, incomingPathChallengeData);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  // The outstanding challenge data can be used to retrieve the path
  auto sameNewpath =
      conn.pathManager->getPathByChallengeData(outstandingChallenge->pathData);
  ASSERT_TRUE(sameNewpath);
  EXPECT_EQ(sameNewpath->id, newPath->id);

  // Step 2: Client migrates to the new path before the server's path is
  // validated
  {
    auto data = IOBuf::copyBuffer("migration migration migration");
    auto streamPacket = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(streamPacket), true, &newPeer);
  }
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Step 3: Client sends the path response
  {
    auto packetData = packetToBuf(
        makePacketWithPathResponseFrame(outstandingChallenge->pathData));
    deliverData(std::move(packetData), true, &newPeer);
  }
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceiveReorderedDataFromChangedPeerAddress) {
  auto& conn = server->getConn();
  auto initialPathId = conn.currentPathId;

  auto data = IOBuf::copyBuffer("bad data");
  auto firstPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto secondPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(0);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);

  // Receive second packet first
  deliverData(std::move(secondPacket));
  EXPECT_EQ(conn.currentPathId, initialPathId);

  auto peerAddress = server->getConn().peerAddress;

  // Receive first packet later from a different address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(firstPacket), true, &newPeer);

  // No migration for reordered packet
  EXPECT_EQ(conn.peerAddress, peerAddress);
  EXPECT_EQ(conn.currentPathId, initialPathId);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToNewPeerAndBackWithoutProbing) {
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto& conn = server->getConn();

  ASSERT_FALSE(conn.fallbackPathId.has_value());

  auto peerAddress = conn.peerAddress;
  auto firstPathId = conn.currentPathId;
  auto firstCongestionController = conn.congestionController.get();
  auto firstSrtt = conn.lossState.srtt;
  auto firstLrtt = conn.lossState.lrtt;
  auto firstRttvar = conn.lossState.rttvar;
  auto firstMrtt = conn.lossState.mrtt;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(2);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(2);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);

  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPathId = conn.currentPathId;
  ASSERT_NE(firstPathId, newPathId);
  auto newPath = conn.pathManager->getPath(newPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_TRUE(conn.fallbackPathId.has_value());
  EXPECT_EQ(conn.fallbackPathId.value(), firstPathId);

  ASSERT_TRUE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_EQ(conn.lossState.mrtt, kDefaultMinRtt);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  auto firstPath = conn.pathManager->getPath(firstPathId);
  ASSERT_TRUE(firstPath);
  EXPECT_EQ(firstPath->status, PathStatus::Validated);
  EXPECT_EQ(firstPath->peerAddress, clientAddr);
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, firstSrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, firstLrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, firstRttvar);
  EXPECT_EQ(firstPath->cachedCCAndRttState->mrtt, firstMrtt);

  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_NE(newPath->writableBytes, 0);

  // The challenge payload is minted at write time; pull it from the actual
  // outstanding PATH_CHALLENGE.
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  auto pathChallengeData = outstandingChallenge->pathData;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *conn.serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // Loop once to allow any paths to be removed (this happens in the eventbase)
  evb.loopOnce();
  ASSERT_FALSE(conn.fallbackPathId.has_value());

  // The first path should be removed because we are now on a validated path
  EXPECT_FALSE(conn.pathManager->getPath(firstPathId));

  // receiving data from the original peer address would trigger another
  // migration and a new path validation since the path was deleted.
  auto nextPacketData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *conn.serverConnectionId,
      clientNextAppDataPacketNum++,
      6,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  deliverData(std::move(nextPacketData), false);
  ASSERT_NE(conn.currentPathId, firstPathId);
  ASSERT_NE(conn.currentPathId, newPathId);

  // Path will need revalidation
  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(conn.currentPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrateToNewPeerRespondOnFallbackPath) {
  auto data = IOBuf::copyBuffer("migration data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto& conn = server->getConn();

  ASSERT_FALSE(conn.fallbackPathId.has_value());

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  auto peerAddress = conn.peerAddress;
  auto firstPathId = conn.currentPathId;
  auto firstCongestionController = conn.congestionController.get();
  auto firstSrtt = conn.lossState.srtt;
  auto firstLrtt = conn.lossState.lrtt;
  auto firstRttvar = conn.lossState.rttvar;
  auto firstMrtt = conn.lossState.mrtt;

  // Step 1: Client migrates to new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPathId = conn.currentPathId;
  ASSERT_NE(firstPathId, newPathId);
  auto newPath = conn.pathManager->getPath(newPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_TRUE(conn.fallbackPathId.has_value());
  EXPECT_EQ(conn.fallbackPathId.value(), firstPathId);

  ASSERT_TRUE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_EQ(conn.lossState.mrtt, kDefaultMinRtt);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  auto firstPath = conn.pathManager->getPath(firstPathId);
  ASSERT_TRUE(firstPath);
  EXPECT_EQ(firstPath->status, PathStatus::Validated);
  EXPECT_EQ(firstPath->peerAddress, clientAddr);
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, firstSrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, firstLrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, firstRttvar);
  EXPECT_EQ(firstPath->cachedCCAndRttState->mrtt, firstMrtt);

  // Step 2: Server sends path challenge
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPathId));
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  EXPECT_NE(newPath->writableBytes, 0);

  // The challenge payload is minted at write time; pull it from the actual
  // outstanding PATH_CHALLENGE.
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  auto pathChallengeData = outstandingChallenge->pathData;

  // Step 3: Client responds with path response on the fallback (initial) path
  packetData = packetToBuf(makePacketWithPathResponseFrame(pathChallengeData));
  // Deliver the path response on the fallback (original) path, not the new path
  deliverData(std::move(packetData), false, &clientAddr);

  // Allow any path removal to execute (it is scheduled on the eventbase)
  evb.loopOnce();

  // The new path should be validated even though the response came on a
  // different path
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // The current path should still be the new path
  EXPECT_EQ(conn.currentPathId, newPathId);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // The fallback path should be removed since the current path is validated.
  EXPECT_FALSE(conn.fallbackPathId.has_value());
  EXPECT_FALSE(conn.pathManager->getPath(firstPathId));
}

TEST_P(QuicServerTransportAllowMigrationTest, ResetPathRttPathResponse) {
  auto& conn = server->getConn();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;
  auto srtt = server->getConn().lossState.srtt;
  auto lrtt = server->getConn().lossState.lrtt;
  auto rttvar = server->getConn().lossState.rttvar;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(newPath->peerAddress, newPeer);
  // We haven't written the path challenge yet, so the path is not validating
  // yet
  EXPECT_EQ(newPath->status, PathStatus::NotValid);

  ASSERT_TRUE(conn.pendingEvents.pathChallenges.contains(newPath->id));
  EXPECT_EQ(conn.peerAddress, newPeer);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);

  ASSERT_TRUE(firstPath->cachedCCAndRttState);
  EXPECT_EQ(firstPath->cachedCCAndRttState->srtt, srtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->lrtt, lrtt);
  EXPECT_EQ(firstPath->cachedCCAndRttState->rttvar, rttvar);

  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPath->id));
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // Read the actual sent challenge payload from the outstanding packet.
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);
  auto pathChallengeData = outstandingChallenge->pathData;

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      server->getConn().udpSendPacketLen,
      std::move(header),
      0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());

  ASSERT_FALSE(writeSimpleFrame(PathResponseFrame(pathChallengeData), builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();
  deliverData(packetToBuf(packet), false, &newPeer);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());

  // After Pathresponse frame is received, srtt,lrtt = sampleRtt;
  // sampleRtt = time from send of PathChallenge to receiving PathResponse
  EXPECT_NE(conn.lossState.srtt, 0us);
  EXPECT_NE(conn.lossState.lrtt, 0us);
  EXPECT_NE(conn.lossState.rttvar, 0us);
}

TEST_P(QuicServerTransportAllowMigrationTest, IgnoreInvalidPathResponse) {
  auto& conn = server->getConn();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;

  quic::SocketAddress newPeer("100.101.102.103", 23456);
  ASSERT_FALSE(conn.pathManager->getPath(server->getLocalAddress(), newPeer));

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(0);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  ASSERT_EQ(conn.currentPathId, newPath->id);

  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(newPath->id));
  EXPECT_GE(newPath->writableBytes, conn.udpSendPacketLen);
  EXPECT_EQ(conn.peerAddress, newPeer);

  loopForWrites();
  ASSERT_EQ(newPath->status, PathStatus::Validating);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  auto invalidPathResponsePkt =
      makePacketWithPathResponseFrame(outstandingChallenge->pathData ^ 1);
  deliverData(packetToBuf(invalidPathResponsePkt), false, &newPeer);

  // The invalid response should not impact the state of the path
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ReceivePathResponseFromDifferentPeerAddress) {
  auto& conn = server->getConn();
  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto peerAddress = server->getConn().peerAddress;

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(2);
  EXPECT_CALL(*quicStats_, onPathValidationSuccess).Times(1);
  EXPECT_CALL(*quicStats_, onPathValidationFailure).Times(0);

  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), false, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  ASSERT_EQ(conn.currentPathId, newPath->id);

  EXPECT_TRUE(conn.pendingEvents.pathChallenges.contains(newPath->id));
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPath->id));
  ASSERT_EQ(newPath->status, PathStatus::Validating);

  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  quic::SocketAddress newPeer2("200.101.102.103", 23456);
  auto pathResponsePkt =
      makePacketWithPathResponseFrame(outstandingChallenge->pathData);
  deliverData(packetToBuf(pathResponsePkt), false, &newPeer2);

  // The response should be accepted. The spec says that the peer initiating the
  // path validation MUST NOT enforce that the response come on the same path.
  // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(server->pathValidationTimeout().isTimerCallbackScheduled());
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringConnIdIssuesNewIds) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  auto initialServerConnId = conn.selfConnectionIds[0];
  auto nextConnId = conn.selfConnectionIds[1].connId;
  EXPECT_EQ(initialServerConnId.sequenceNumber, 0);

  auto data = IOBuf::copyBuffer("hi there!");
  auto packetStreamData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  ShortHeader header(
      ProtectionType::KeyPhaseZero, nextConnId, clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring the initial server conn id
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(initialServerConnId.sequenceNumber);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  /**
   * Deliver both packets (one containing stream data and the other
   containing a
   * RETIRE_CONNECTION_ID frame). The RETIRE_CONNECTION_ID frame should
   result
   * in invoking onConnectionIdRetired().
   */
  EXPECT_CALL(
      routingCallback, onConnectionIdRetired(_, initialServerConnId.connId));
  deliverData(std::move(packetStreamData), false);
  deliverData(packetToBuf(retireConnIdPacket));
  // received a RETIRE_CONN_ID frame for seq no 0, expect next seq to be 1
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 1);

  // server should have written NEW_CONNECTION_ID frame since we've retired one
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 1);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetiringInvalidConnId) {
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring an invalid conn id / seq no
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(conn.nextSelfConnectionIdSequence);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // retiring invalid conn id should not invoke onConnectionIdRetired()
  EXPECT_CALL(routingCallback, onConnectionIdRetired(_, _)).Times(0);
  deliverData(packetToBuf(retireConnIdPacket));
  // no changes should have been made to selfConnectionIds
  EXPECT_EQ(conn.selfConnectionIds[0].sequenceNumber, 0);
  EXPECT_TRUE(conn.connIdsRetiringSoon->empty());

  // verify that we don't issue a new conn id
  auto numNewConnIdFrames = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdFrames, 0);
}

TEST_P(QuicServerTransportAllowMigrationTest, RetireConnIdOfContainingPacket) {
  /**
   * From RFC9000:
   * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT
   * refer to the Destination Connection ID field of the packet in which the
   * frame is contained.  The peer MAY treat this as a connection error of
   type
   * PROTOCOL_VIOLATION.
   */

  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a frame retiring conn id of containing packet
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RetiredConnIdIsUnboundAfterLaterFrameError) {
  auto& conn = server->getNonConstConn();
  const auto retiredConnId = conn.selfConnectionIds[0];
  const auto packetDestinationConnId = conn.selfConnectionIds[1];

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      packetDestinationConnId.connId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());
  ASSERT_TRUE(builder.canBuildPacket());
  ASSERT_FALSE(writeSimpleFrame(
                   QuicSimpleFrame(
                       RetireConnectionIdFrame(retiredConnId.sequenceNumber)),
                   builder)
                   .hasError());
  ASSERT_FALSE(writeSimpleFrame(
                   QuicSimpleFrame(RetireConnectionIdFrame(
                       packetDestinationConnId.sequenceNumber)),
                   builder)
                   .hasError());
  auto packet = std::move(builder).buildPacket();

  EXPECT_CALL(routingCallback, onConnectionIdRetired(_, retiredConnId.connId));
  EXPECT_THROW(deliverData(packetToBuf(packet)), std::runtime_error);
  server->unbindConnection();
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RetireConnIdFrameZeroLengthSrcConnId) {
  /**
   * From RFC9000:
   * An endpoint cannot send this frame if it was provided with a zero-length
   * connection ID by its peer. An endpoint that provides a zero- length
   * connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a
   * connection error of type PROTOCOL_VIOLATION.
   */
  auto& conn = server->getNonConstConn();
  // reset queued packets
  conn.outstandings.reset();
  // simulate that the client has a zero-length conn id
  conn.clientConnectionId = ConnectionId::createZeroLength();

  ShortHeader header(
      ProtectionType::KeyPhaseZero,
      *serverConnectionId,
      clientNextAppDataPacketNum++);
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen, std::move(header), 0 /* largestAcked */);
  ASSERT_FALSE(builder.encodePacketHeader().hasError());

  // build packet containing a RETIRE_CONNECTION_ID frame
  ASSERT_TRUE(builder.canBuildPacket());
  RetireConnectionIdFrame retireConnIdFrame(0);
  ASSERT_FALSE(
      writeSimpleFrame(QuicSimpleFrame(retireConnIdFrame), builder).hasError());
  auto retireConnIdPacket = std::move(builder).buildPacket();

  // parsing packet should throw an error
  EXPECT_THROW(
      deliverData(packetToBuf(retireConnIdPacket)), std::runtime_error);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    RestoreCachedStateOnlyForValidatedPaths) {
  auto& conn = server->getNonConstConn();
  auto initialPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(initialPath);
  ASSERT_TRUE(initialPath->status == PathStatus::Validated);
  conn.lossState.srtt = 200ms;
  conn.lossState.lrtt = 220ms;
  conn.lossState.rttvar = 20ms;
  auto firstCongestionController = conn.congestionController.get();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Migrate to unvalidated peer
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  // The cached state is empty. cca is reset. rtt is unchanged.
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
  conn.lossState.srtt = 100ms;
  conn.lossState.lrtt = 110ms;
  conn.lossState.rttvar = 10ms;

  // Migrate back to validated peer
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &clientAddr);
  // The cached state is restored since the path is validated
  ASSERT_EQ(conn.peerAddress, clientAddr);
  ASSERT_EQ(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.congestionController.get(), firstCongestionController);

  // The unvalidated path has cached state
  EXPECT_EQ(newPath->cachedCCAndRttState->srtt, 100ms);
  EXPECT_EQ(newPath->cachedCCAndRttState->lrtt, 110ms);
  EXPECT_EQ(newPath->cachedCCAndRttState->rttvar, 10ms);
  EXPECT_NE(newPath->cachedCCAndRttState->congestionController.get(), nullptr);
  EXPECT_NE(
      newPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);

  // Migrate to unvalidated peer again
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &newPeer);
  // The cached state is not used since the path is not validated. cca is reset.
  // rtt is unchanged.
  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 200ms);
  EXPECT_EQ(conn.lossState.lrtt, 220ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, MigrateToStaleValidatedPeer) {
  auto& conn = server->getNonConstConn();
  auto initialPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(initialPath);
  ASSERT_TRUE(initialPath->status == PathStatus::Validated);
  auto firstCongestionController = conn.congestionController.get();

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  // Migrate to unvalidated peer
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  deliverData(std::move(packetData), true, &newPeer);

  ASSERT_EQ(conn.peerAddress, newPeer);
  ASSERT_NE(conn.currentPathId, initialPath->id);
  auto newPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(newPath);
  // The cached state is empty. The rtt/cca state is reset
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);
  EXPECT_EQ(
      conn.congestionController->type(), firstCongestionController->type());

  // Make the cached state stale for the initial path.
  auto& nonConstInitialPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, initialPath->id);
  nonConstInitialPath.cachedCCAndRttState->srtt = 200ms;
  nonConstInitialPath.cachedCCAndRttState->lrtt = 220ms;
  nonConstInitialPath.cachedCCAndRttState->rttvar = 20ms;
  nonConstInitialPath.cachedCCAndRttState->congestionController =
      conn.congestionControllerFactory->makeCongestionController(
          conn, CongestionControlType::NewReno);
  auto cachedCongestionController =
      nonConstInitialPath.cachedCCAndRttState->congestionController.get();
  nonConstInitialPath.cachedCCAndRttState->recordTime =
      Clock::now() - 2 * kTimeToRetainLastCongestionAndRttState;

  // Migrate back to validated peer
  packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  deliverData(std::move(packetData), true, &clientAddr);
  // The cached state is not restored because it's too old
  ASSERT_EQ(conn.peerAddress, clientAddr);
  ASSERT_EQ(conn.currentPathId, initialPath->id);
  EXPECT_EQ(conn.lossState.srtt, 0us);
  EXPECT_EQ(conn.lossState.lrtt, 0us);
  EXPECT_EQ(conn.lossState.rttvar, 0us);
  EXPECT_TRUE(conn.congestionController);
  EXPECT_NE(conn.congestionController.get(), cachedCongestionController);
  EXPECT_EQ(
      conn.congestionController->type(),
      conn.transportSettings.defaultCongestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientPortChangeNATRebinding) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      ++clientNextAppDataPacketNum,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  quic::SocketAddress newPeer(
      clientAddr.getIPAddress(), clientAddr.getPort() + 1);
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // No state is cached for the first path
  EXPECT_FALSE(firstPath->cachedCCAndRttState);
  // The cc and rtt state is maintained for nat rebinding
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);

  EXPECT_EQ(conn.congestionController.get(), congestionController);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathChallengeNotBlockedByStreamData) {
  auto& conn = server->getNonConstConn();

  // Queue a large stream payload (much larger than a single packet) so
  // that every packet build during/after the migration has stream data
  // competing for wrapper space. We do NOT loopForWrites here — we want
  // the rebound packet to be the trigger that drives the next write loop.
  StreamId streamId = server->createBidirectionalStream().value();
  auto bigData = folly::IOBuf::create(64 * 1024);
  bigData->append(64 * 1024);
  memset(bigData->writableData(), 'A', 64 * 1024);
  ASSERT_FALSE(
      server->writeChain(streamId, std::move(bigData), false).hasError());

  serverWrites.clear();

  // Construct a small stream packet from a new peer port to trigger
  // NAT-rebinding migration.
  auto rebindData = folly::IOBuf::copyBuffer("ping");
  auto rebindPacket = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      clientNextAppDataPacketNum++,
      2,
      *rebindData,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  quic::SocketAddress newPeer(
      clientAddr.getIPAddress(), clientAddr.getPort() + 1);
  deliverData(std::move(rebindPacket), /*writes=*/true, &newPeer);

  // Migration happened.
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // Sanity: server actually wrote at least one packet on the new path.
  ASSERT_FALSE(serverWrites.empty());

  // Per RFC 9000 §8.2 the server MUST send a PATH_CHALLENGE on the new
  // path. status==Validating means the challenge was actually written;
  // pendingEvents.pathChallenges no longer holding the entry means it
  // was consumed by the writer (see updateSimpleFrameOnPacketSent).
  //
  // This ensures that the PATH_CHALLENGE was written to the packet and fit it
  // before stream data.
  EXPECT_EQ(newPath->status, PathStatus::Validating)
      << "PATH_CHALLENGE was queued but never written; stream frames "
         "packed the wrapper full before pathValidationFrameScheduler ran.";
  EXPECT_FALSE(conn.pendingEvents.pathChallenges.contains(newPath->id))
      << "PATH_CHALLENGE for new path is still pending in pendingEvents.";
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientAddressChangeNATRebinding) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      ++clientNextAppDataPacketNum,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  // Current address is 127.0.0.1:1000
  quic::SocketAddress newPeer("127.0.0.100", clientAddr.getPort());
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // No state is cached for the first path
  EXPECT_FALSE(firstPath->cachedCCAndRttState);
  // The cc and rtt state is maintained for nat rebinding
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);

  EXPECT_EQ(conn.congestionController.get(), congestionController);
}

TEST_P(QuicServerTransportAllowMigrationTest, ClientAddressChangeOutOfSubnet) {
  auto& conn = server->getNonConstConn();

  StreamId streamId = server->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("Aloha");
  auto serverWriteChain10 = server->writeChain(streamId, data1->clone(), false);
  loopForWrites();
  PacketNum packetNum1 =
      getFirstOutstandingPacket(
          server->getNonConstConn(), PacketNumberSpace::AppData)
          ->packet.header.getPacketSequenceNum();
  AckBlocks acks = {{packetNum1, packetNum1}};
  auto packet1 = createAckPacket(
      server->getNonConstConn(),
      ++clientNextAppDataPacketNum,
      acks,
      PacketNumberSpace::AppData);
  deliverData(packetToBuf(packet1));
  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  auto data = IOBuf::copyBuffer("bad data");
  auto packetData = packetToBuf(createStreamPacket(
      *clientConnectionId,
      *server->getConn().serverConnectionId,
      ++clientNextAppDataPacketNum,
      2,
      *data,
      0 /* cipherOverhead */,
      0 /* largestAcked */));

  auto congestionController = server->getConn().congestionController.get();
  conn.lossState.lrtt = 100ms;
  conn.lossState.srtt = 120ms;
  conn.lossState.rttvar = 20ms;
  conn.lossState.mrtt = 80ms;

  // Current address is 127.0.0.1:1000. New address is out of the /24 subnet.
  // This won't count as NAT rebinding.
  quic::SocketAddress newPeer("127.0.1.1", clientAddr.getPort());
  deliverData(std::move(packetData), true, &newPeer);

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_EQ(conn.peerAddress, newPeer);

  // State is cached for the first path
  EXPECT_TRUE(firstPath->cachedCCAndRttState);
  // The rtt state is unchanged since we have nothing to restore. cca is reset.
  EXPECT_EQ(conn.lossState.lrtt, 100ms);
  EXPECT_EQ(conn.lossState.srtt, 120ms);
  EXPECT_EQ(conn.lossState.rttvar, 20ms);
  EXPECT_EQ(conn.lossState.mrtt, 80ms);
  EXPECT_NE(conn.congestionController.get(), congestionController);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForNonPrimaryPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a path challenge from a new peer address
  auto incomingPathChallengeData = 123;
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  auto newPathId = newPath->id;
  EXPECT_NE(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_FALSE(newPath->outstandingChallenges.empty());

  // A path challenge was sent out
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  // Cancel the timeout and trigger it immediately to test its impact
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  EXPECT_EQ(newPath->status, PathStatus::NotValid);
  EXPECT_TRUE(newPath->outstandingChallenges.empty());

  // This is a probe path that failed validation. It will be removed at the end
  // of the event loop.
  evb.loopOnce();
  EXPECT_FALSE(conn.pathManager->getPath(newPathId));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForCurrentPathWithFallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);
  auto firstCongestionController = conn.congestionController.get();

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);
  EXPECT_FALSE(newPath->outstandingChallenges.empty());

  // First congestion controller is cached
  EXPECT_EQ(
      firstPath->cachedCCAndRttState->congestionController.get(),
      firstCongestionController);
  EXPECT_NE(conn.congestionController.get(), firstCongestionController);

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  EXPECT_EQ(newPath->status, PathStatus::NotValid);
  EXPECT_TRUE(newPath->outstandingChallenges.empty());

  // The connection falls back to the firstPath
  EXPECT_EQ(conn.currentPathId, firstPath->id);
  // Congestion controller is restored
  EXPECT_EQ(conn.congestionController.get(), firstCongestionController);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutForCurrentPathWithNoFallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // The fallback path is reaped
  ASSERT_FALSE(conn.pathManager->removePath(firstPath->id).hasError());

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // There is no fallback path. The connection is closed
  ASSERT_TRUE(server->isClosed());
  EXPECT_EQ(
      server->getConn().localConnectionError->code,
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION));
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PathValidationTimeoutResetUnderlyingTransportInCallback) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Add additional peer id so PathResponse completes.
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Deliver a stream packet from a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Step 1: New path is created and is validating
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Deliver a path probe packet from a new peer address
  auto incomingPathChallengeData = 123;
  quic::SocketAddress newPeer2("100.101.102.104", 23456);
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer2);
  }

  // The fallback path is reaped
  ASSERT_FALSE(conn.pathManager->removePath(firstPath->id).hasError());

  // Delete the underlying transport in the PathValidationResult path.
  // This will crash if the pathValidationTimeout does not keep a pointer to the
  // transport.
  EXPECT_CALL(routingCallback, onConnectionUnbound(_, _, _))
      .WillOnce(Invoke([&](QuicServerTransport*, const auto&, const auto&) {
        server.reset();
      }));

  // Cancel the path validation timeout and trigger it immediately
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // The server transport has been deleted.
  ASSERT_EQ(server.get(), nullptr);
}

TEST_P(QuicServerTransportAllowMigrationTest, ReapOldValidatedPaths) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), quic::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path was validated but is old
  path.status = PathStatus::Validated;
  path.pathValidationTime = Clock::now() - kTimeToRetainOldPaths * 2;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_FALSE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, ReapUnusedNotValidPaths) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), quic::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path was validated but is old
  path.status = PathStatus::NotValid;

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_FALSE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, DoNotReapUnusedValidatingPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), quic::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path is validating. A path challenge frame has been sent for it.
  path.status = PathStatus::Validating;
  path.outstandingChallenges.push_back({123, Clock::now()});

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_TRUE(pathFound);
}

TEST_P(QuicServerTransportAllowMigrationTest, DoNotReapUnusedNewPath) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Server);
  auto& conn = server->getNonConstConn();
  conn.qLogger = qLogger;

  auto pathIdRes = conn.pathManager->addPath(
      server->getLocalAddress(), quic::SocketAddress("1.2.3.4", 23456));
  ASSERT_FALSE(pathIdRes.hasError());
  auto& path =
      PathManagerTestAccessor::getNonConstPathInfo(conn, pathIdRes.value());
  // Path is new. It has been flagged for a challenge but the scheduler
  // hasn't minted/sent it yet.
  path.status = PathStatus::NotValid;
  conn.pendingEvents.pathChallenges.insert(pathIdRes.value());

  // Deliver any data to the socket. This should trigger the reaping logic.
  {
    auto data = IOBuf::copyBuffer("bad data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));

    // Migrate to unvalidated peer
    deliverData(std::move(packetData), true, &clientAddr);
  }

  auto pathFound = conn.pathManager->getPath(pathIdRes.value());
  EXPECT_TRUE(pathFound);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrationUpdatesDestinationConnectionId) {
  auto& conn = server->getNonConstConn();

  // Add multiple peer connection IDs
  auto newCid1 = ConnectionId::createAndMaybeCrash({1, 2, 3, 4});
  auto newCid2 = ConnectionId::createAndMaybeCrash({5, 6, 7, 8});
  conn.peerConnectionIds.emplace_back(newCid1, 1);
  conn.peerConnectionIds.emplace_back(newCid2, 2);

  // Create a new path
  quic::SocketAddress newPeer("100.101.102.103", 23456);

  // Deliver a path challenge from the new peer address
  auto incomingPathChallengeData = 456;
  {
    auto packet = makePacketWithPathChallegeFrame(incomingPathChallengeData);
    auto packetData = packetToBuf(packet);
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Verify new path was created
  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_NE(conn.currentPathId, newPath->id);

  // Verify a destination CID was assigned to the new path
  // (This should happen automatically during path validation)
  EXPECT_TRUE(newPath->destinationConnectionId.has_value());

  // Get the challenge to send back
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  // Client migrates and validates the path
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto streamPacket = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(streamPacket), true, &newPeer);
  }

  // Send path response to validate
  {
    auto packetData = packetToBuf(
        makePacketWithPathResponseFrame(outstandingChallenge->pathData));
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Verify migration succeeded
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validated);
}

TEST_P(QuicServerTransportAllowMigrationTest, InitialClientCidMarkedInUse) {
  auto& conn = server->getNonConstConn();

  // Verify the initial client connection ID is marked as in use
  ASSERT_FALSE(conn.peerConnectionIds.empty());

  // The initial CID should be in the peerConnectionIds and marked as in use
  bool foundInUseCid = false;
  for (const auto& cidData : conn.peerConnectionIds) {
    if (cidData.connId == *conn.clientConnectionId &&
        cidData.sequenceNumber == kInitialConnectionIdSequenceNumber) {
      EXPECT_TRUE(cidData.inUse);
      foundInUseCid = true;
      break;
    }
  }
  EXPECT_TRUE(foundInUseCid);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ConsecutiveMigrationFailuresIncrementsCounter) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so migration can occur
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Initial counter should be zero
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);

  // Migrate to a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer);
  }

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Trigger path validation timeout (migration failure)
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // Counter should be incremented
  EXPECT_EQ(conn.consecutiveMigrationFailures, 1);

  // Should have reverted to fallback path
  EXPECT_EQ(conn.currentPathId, firstPath->id);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    ConnectionClosesAfterMaxConsecutiveMigrationFailures) {
  auto& conn = server->getNonConstConn();

  // Add additional peer ids so migrations can occur
  for (uint32_t i = 1; i <= 6; ++i) {
    conn.peerConnectionIds.emplace_back(
        ConnectionId::createAndMaybeCrash(
            std::vector<uint8_t>{
                static_cast<uint8_t>(i),
                static_cast<uint8_t>(i + 1),
                static_cast<uint8_t>(i + 2),
                static_cast<uint8_t>(i + 3)}),
        i);
  }

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Perform 5 consecutive migration failures
  for (uint32_t i = 0; i < kMaxConsecutiveMigrationFailures; ++i) {
    // Create a new peer address for each migration attempt
    quic::SocketAddress newPeer(
        "100.101.102." + std::to_string(100 + i), 23456 + i);

    // Migrate to new peer
    {
      auto data = IOBuf::copyBuffer("migration data " + std::to_string(i));
      auto packetData = packetToBuf(createStreamPacket(
          *clientConnectionId,
          *server->getConn().serverConnectionId,
          clientNextAppDataPacketNum++,
          2,
          *data,
          0 /* cipherOverhead */,
          0 /* largestAcked */));
      deliverData(std::move(packetData), true, &newPeer);
    }

    auto newPath =
        conn.pathManager->getPath(server->getLocalAddress(), newPeer);
    ASSERT_TRUE(newPath);

    // For the last iteration, connection should close during timeout
    if (i == kMaxConsecutiveMigrationFailures - 1) {
      // Counter should be at the limit - 1 before the timeout
      EXPECT_EQ(
          conn.consecutiveMigrationFailures,
          kMaxConsecutiveMigrationFailures - 1);

      // Trigger path validation timeout - this should close the connection
      ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
      server->pathValidationTimeout().cancelTimerCallback();
      auto& nonConstNewPath =
          quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
      nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
      server->pathValidationTimeout().timeoutExpired();

      // Connection should be closed
      EXPECT_TRUE(server->isClosed());
      break;
    } else {
      // Trigger path validation timeout
      ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
      server->pathValidationTimeout().cancelTimerCallback();
      auto& nonConstNewPath =
          quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
      nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
      server->pathValidationTimeout().timeoutExpired();

      // Counter should be incremented
      EXPECT_EQ(conn.consecutiveMigrationFailures, i + 1);

      // Should have reverted to fallback path
      EXPECT_EQ(conn.currentPathId, firstPath->id);
    }
  }
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrationFailureCounterResetsOnPacketReception) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so migration can occur
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Initial failure counter should be zero
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);

  // Migrate to a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer);
  }

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);

  // Trigger path validation timeout (migration failure)
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // Counter should be incremented, packet counter reset after revert
  EXPECT_EQ(conn.consecutiveMigrationFailures, 1);

  // Should have reverted to fallback path
  EXPECT_EQ(conn.currentPathId, firstPath->id);

  // Send a packet on the current (fallback) path
  {
    auto data = IOBuf::copyBuffer("fallback data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), false);
  }

  // After first packet on current path, failure counter should reset
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    PingScheduledAfterMigrationFailureAndRevert) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so migration can occur
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Clear any pending pings
  conn.pendingEvents.sendPing = false;

  // Migrate to a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer);
  }

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);

  // Trigger path validation timeout (migration failure)
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath->id);
  nonConstNewPath.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // Should have reverted to fallback path
  EXPECT_EQ(conn.currentPathId, firstPath->id);

  // Ping should be scheduled to confirm client is on fallback path
  EXPECT_TRUE(conn.pendingEvents.sendPing);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    SuccessfulMigrationDoesNotIncrementFailureCounter) {
  auto& conn = server->getNonConstConn();

  // Add additional peer id so migration can occur
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);

  // Initial counter should be zero
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);

  // Migrate to a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer);
  }

  auto newPath = conn.pathManager->getPath(server->getLocalAddress(), newPeer);
  ASSERT_TRUE(newPath);
  EXPECT_EQ(conn.currentPathId, newPath->id);
  EXPECT_EQ(newPath->status, PathStatus::Validating);

  // Get the challenge to validate the path
  auto outstandingChallenge = getFirstOutstandingPathChallenge();
  ASSERT_TRUE(outstandingChallenge);

  // Send path response to validate the migration
  {
    auto packetData = packetToBuf(
        makePacketWithPathResponseFrame(outstandingChallenge->pathData));
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Path should be validated
  EXPECT_EQ(newPath->status, PathStatus::Validated);

  // Counter should still be zero (no failure occurred)
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    MigrationFailureCounterResetsOnMigrationToFallback) {
  auto& conn = server->getNonConstConn();

  // Add additional peer ids so migrations can occur
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4}), 1);
  conn.peerConnectionIds.emplace_back(
      ConnectionId::createAndMaybeCrash({5, 6, 7, 8}), 2);

  auto firstPath = conn.pathManager->getPath(conn.currentPathId);
  ASSERT_TRUE(firstPath);

  // Initial failure counter should be zero
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);

  // First migration that will fail
  quic::SocketAddress newPeer1("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data 1");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer1);
  }

  auto newPath1 =
      conn.pathManager->getPath(server->getLocalAddress(), newPeer1);
  ASSERT_TRUE(newPath1);
  EXPECT_EQ(conn.currentPathId, newPath1->id);

  // Trigger path validation timeout for first migration
  ASSERT_TRUE(server->pathValidationTimeout().isTimerCallbackScheduled());
  server->pathValidationTimeout().cancelTimerCallback();
  auto& nonConstNewPath1 =
      quic::PathManagerTestAccessor::getNonConstPathInfo(conn, newPath1->id);
  nonConstNewPath1.pathResponseDeadline = Clock::now() - 1ms;
  server->pathValidationTimeout().timeoutExpired();

  // Should have incremented counter and reverted to fallback
  EXPECT_EQ(conn.consecutiveMigrationFailures, 1);
  EXPECT_EQ(conn.currentPathId, firstPath->id);

  // Second migration to a different peer
  quic::SocketAddress newPeer2("100.101.102.104", 23457);
  {
    auto data = IOBuf::copyBuffer("migration data 2");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer2);
  }

  auto newPath2 =
      conn.pathManager->getPath(server->getLocalAddress(), newPeer2);
  ASSERT_TRUE(newPath2);
  EXPECT_EQ(conn.currentPathId, newPath2->id);

  // Path validation is in progress, but before it times out,
  // client sends a packet on the fallback path
  {
    auto data = IOBuf::copyBuffer("fallback data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &clientAddr);
  }

  // Should have migrated back to fallback path
  EXPECT_EQ(conn.currentPathId, firstPath->id);

  // Since the fallback path is validated, and we just received a packet on it
  // (which triggered the migration), the failure counter should be reset
  // immediately
  EXPECT_EQ(conn.consecutiveMigrationFailures, 0);
}

TEST_P(
    QuicServerTransportAllowMigrationTest,
    SessionTicketSourceAddressesUpdatedAfterMigration) {
  // This test verifies that after connection migration, a new session ticket
  // is written with the new peer address included in the source addresses.
  auto& conn = server->getNonConstConn();
  conn.transportSettings.disableMigration = false;

  // Set up initial source addresses (simulating previous 0-RTT validation)
  auto initialIP = clientAddr.getIPAddress();
  conn.tokenSourceAddresses = {initialIP};

  // Set up expectation to capture the source addresses from
  // writeNewSessionTicket
  std::vector<folly::IPAddress> capturedSourceAddresses;
  bool tokenCaptured = false;
  EXPECT_CALL(*fakeHandshake, writeNewSessionTicket(_))
      .WillOnce(
          [&capturedSourceAddresses, &tokenCaptured](const AppToken& appToken) {
            capturedSourceAddresses = appToken.sourceAddresses;
            tokenCaptured = true;
            return quic::Expected<void, QuicError>{};
          });

  EXPECT_CALL(*quicStats_, onConnectionMigration).Times(1);
  EXPECT_CALL(*quicStats_, onPathAdded).Times(1);

  // Trigger migration by sending data from a new peer address
  quic::SocketAddress newPeer("100.101.102.103", 23456);
  {
    auto data = IOBuf::copyBuffer("migration data");
    auto packetData = packetToBuf(createStreamPacket(
        *clientConnectionId,
        *server->getConn().serverConnectionId,
        clientNextAppDataPacketNum++,
        2,
        *data,
        0 /* cipherOverhead */,
        0 /* largestAcked */));
    deliverData(std::move(packetData), true, &newPeer);
  }

  // Verify migration occurred
  EXPECT_EQ(conn.peerAddress, newPeer);

  // Verify session ticket was written with new address
  ASSERT_TRUE(tokenCaptured)
      << "Session ticket should be written after migration";

  auto newPeerIP = newPeer.getIPAddress();
  auto it = std::find(
      capturedSourceAddresses.begin(),
      capturedSourceAddresses.end(),
      newPeerIP);
  EXPECT_NE(it, capturedSourceAddresses.end())
      << "New peer address should be in session ticket source addresses";

  // Verify the new address is at the end (most recently used)
  EXPECT_EQ(capturedSourceAddresses.back(), newPeerIP)
      << "New peer address should be at the end of source addresses";

  // Verify we don't exceed the max number of addresses
  EXPECT_LE(capturedSourceAddresses.size(), kMaxNumTokenSourceAddresses);

  // Verify the connection state was also updated
  auto stateIt = std::find(
      conn.tokenSourceAddresses.begin(),
      conn.tokenSourceAddresses.end(),
      newPeerIP);
  EXPECT_NE(stateIt, conn.tokenSourceAddresses.end())
      << "Connection state tokenSourceAddresses should also contain new address";
}

} // namespace quic::test
