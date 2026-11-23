/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/state/ServerStateMachine.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/test/Mocks.h>
#include <quic/state/test/MockQuicStats.h>
#include <array>
#include <chrono>
#include <limits>

using namespace testing;

namespace quic {

namespace {
void assertServerConnIdParamsEq(
    ServerConnectionIdParams& first,
    ServerConnectionIdParams& second) {
  EXPECT_EQ(first.version, second.version);
  EXPECT_EQ(first.hostId, second.hostId);
  EXPECT_EQ(first.processId, second.processId);
  EXPECT_EQ(first.workerId, second.workerId);
}
} // namespace

namespace test {
TEST(ServerStateMachineTest, TestAddConnId) {
  QuicServerConnectionState serverState(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerConnectionIdParams originalParams(12, 1, 37);

  auto algo = std::make_unique<DefaultConnectionIdAlgo>();

  serverState.connIdAlgo = algo.get();
  serverState.serverConnIdParams = originalParams;
  serverState.serverAddr = quic::SocketAddress("0.0.0.0", 42069);
  quic::MockQuicStats mockQuicStats;
  serverState.statsCallback = &mockQuicStats;

  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverState.transportSettings.statelessResetTokenSecret = secret;
  EXPECT_EQ(serverState.selfConnectionIds.size(), 0);
  serverState.peerActiveConnectionIdLimit = 2;
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
  auto newConnId1 = serverState.createAndAddNewSelfConnId();
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
  auto newConnId2 = serverState.createAndAddNewSelfConnId();
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(1)).Times(1);
  auto newConnId3 = serverState.createAndAddNewSelfConnId();

  // Sequence numbers correctly set.
  EXPECT_EQ(newConnId1->sequenceNumber, 0);
  EXPECT_EQ(newConnId2->sequenceNumber, 1);
  EXPECT_EQ(newConnId3->sequenceNumber, 2);

  // All three conn ids are different from each other.
  EXPECT_NE(newConnId1->connId, newConnId2->connId);
  EXPECT_NE(newConnId2->connId, newConnId3->connId);
  EXPECT_NE(newConnId3->connId, newConnId1->connId);

  EXPECT_EQ(newConnId1->token->size(), kStatelessResetTokenLength);
  EXPECT_EQ(newConnId2->token->size(), kStatelessResetTokenLength);
  EXPECT_EQ(newConnId3->token->size(), kStatelessResetTokenLength);

  auto params1 = *serverState.connIdAlgo->parseConnectionId(newConnId1->connId);
  auto params2 = *serverState.connIdAlgo->parseConnectionId(newConnId2->connId);
  auto params3 = *serverState.connIdAlgo->parseConnectionId(newConnId3->connId);

  // Server connection id params are correctly encoded/decoded.
  assertServerConnIdParamsEq(originalParams, params1);
  assertServerConnIdParamsEq(params1, params2);
  assertServerConnIdParamsEq(params2, params3);

  EXPECT_EQ(serverState.selfConnectionIds.size(), 3);
  EXPECT_EQ(serverState.nextSelfConnectionIdSequence, 3);
}

TEST(ServerStateMachineTest, TestCidRejected) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = quic::SocketAddress("0.0.0.0", 225);
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

  auto firstCid = getTestConnectionId(0);
  auto secondCid = getTestConnectionId(1);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillOnce(Return(firstCid))
      .WillOnce(Return(secondCid));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, secondCid);
        return false;
      }));
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(2)).Times(1);
  serverConn.createAndAddNewSelfConnId();
}

TEST(ServerStateMachineTest, TestCidRejectedThenFail) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = quic::SocketAddress("0.0.0.0", 770);
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

  auto firstCid = getTestConnectionId(0);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillOnce(Return(firstCid))
      .WillOnce(Return(
          quic::make_unexpected(QuicError(
              quic::TransportErrorCode::INTERNAL_ERROR, "Tumbledown"))));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillOnce(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }));
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(_)).Times(0);
  serverConn.createAndAddNewSelfConnId();
}

TEST(ServerStateMachineTest, TestCidRejectedGiveUp) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  MockServerConnectionIdRejector mockRejector;
  ServerConnectionIdParams serverCidParams(10, 11, 12);
  MockConnectionIdAlgo mockCidAlgo;

  serverConn.connIdAlgo = &mockCidAlgo;
  serverConn.connIdRejector = &mockRejector;
  serverConn.serverConnIdParams = serverCidParams;
  serverConn.peerActiveConnectionIdLimit = 10;
  std::array<uint8_t, kStatelessResetTokenSecretLength> secret;
  serverConn.transportSettings.statelessResetTokenSecret = secret;
  serverConn.serverAddr = quic::SocketAddress("0.0.0.0", 770);
  quic::MockQuicStats mockQuicStats;
  serverConn.statsCallback = &mockQuicStats;

  auto firstCid = getTestConnectionId(0);
  EXPECT_CALL(mockCidAlgo, encodeConnectionId(serverCidParams))
      .WillRepeatedly(Return(firstCid));
  EXPECT_CALL(mockRejector, rejectConnectionIdNonConst(_))
      .WillRepeatedly(Invoke([&](const ConnectionId& inputCid) {
        EXPECT_EQ(inputCid, firstCid);
        return true;
      }));
  EXPECT_CALL(mockQuicStats, onConnectionIdCreated(32)).Times(1);
  serverConn.createAndAddNewSelfConnId();
}

TEST(ServerStateMachineTest, TestProcessMaxRecvPacketSizeParamBelowMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1000);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, TestMaxUdpSendPayloadSizeCapsSendMtu) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.canIgnorePathMTU = true;
  serverConn.transportSettings.maxUdpSendPayloadSize = 1338;
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1472);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // min(peer advertised 1472, configured cap 1338) == 1338.
  EXPECT_EQ(serverConn.udpSendPacketLen, 1338);
}

TEST(ServerStateMachineTest, TestMaxUdpSendPayloadSizeBelowFloorClampedToMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.canIgnorePathMTU = true;
  // Below the floor: a misconfigured tiny value must not drive the send MTU
  // below the QUIC minimum.
  serverConn.transportSettings.maxUdpSendPayloadSize = 800;
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1472);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // Configured cap 800 is clamped up to kMinMaxUDPPayload (1200), not 800.
  EXPECT_EQ(serverConn.udpSendPacketLen, kMinMaxUDPPayload);
}

TEST(ServerStateMachineTest, TestMaxUdpSendPayloadSizeUnsetUsesDefaultCap) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.canIgnorePathMTU = true;
  // maxUdpSendPayloadSize left at its default of 0 (unset).
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_packet_size, 1472);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // min(peer advertised 1472, kDefaultMaxUDPPayload 1452) == 1452.
  EXPECT_EQ(serverConn.udpSendPacketLen, kDefaultMaxUDPPayload);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(
      serverConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.datagramState.maxWriteFrameSize, 0);
}

TEST(ServerStateMachineTest, TestProcessMaxDatagramSizeAboveUint32Max) {
  for (uint64_t maxDatagramFrameSize :
       {1ULL << 32,
        (1ULL << 32) + 1,
        (1ULL << 32) + kMaxDatagramPacketOverhead}) {
    SCOPED_TRACE(maxDatagramFrameSize);
    QuicServerConnectionState serverConn(
        FizzServerQuicHandshakeContext::Builder().build());
    std::vector<TransportParameter> transportParams;
    auto encodeResult = encodeIntegerParameter(
        TransportParameterId::max_datagram_frame_size, maxDatagramFrameSize);
    ASSERT_FALSE(encodeResult.hasError());
    transportParams.push_back(encodeResult.value());
    ClientTransportParameters clientTransportParams = {
        std::move(transportParams)};
    auto result = processClientInitialParams(serverConn, clientTransportParams);
    ASSERT_FALSE(result.hasError());
    EXPECT_EQ(
        serverConn.datagramState.maxWriteFrameSize,
        std::numeric_limits<uint32_t>::max());
  }
}

TEST(ServerStateMachineTest, TestProcessMinAckDelayNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerMinAckDelay.has_value());
}

TEST(ServerStateMachineTest, TestProcessMinAckDelaySet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::min_ack_delay, 1000);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(serverConn.peerMinAckDelay.has_value());
  ASSERT_EQ(
      serverConn.peerMinAckDelay.value(), std::chrono::microseconds(1000));
}

TEST(ServerStateMachineTest, TestProcessMaxAckDelayBoundary) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto encoded = encodeIntegerParameter(
      TransportParameterId::max_ack_delay, kMaxAckDelay - 1);
  ASSERT_FALSE(encoded.hasError());
  ClientTransportParameters clientTransportParams = {
      {std::move(encoded.value())}};

  ASSERT_FALSE(
      processClientInitialParams(serverConn, clientTransportParams).hasError());
  EXPECT_EQ(
      std::chrono::milliseconds(kMaxAckDelay - 1), serverConn.peerMaxAckDelay);
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.minAckDelay = std::chrono::microseconds(1000);
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  auto minAckDelayParamResult = getIntegerParameter(
      TransportParameterId::min_ack_delay, customTransportParams);
  ASSERT_FALSE(minAckDelayParamResult.hasError());
  auto minAckDelayParam = minAckDelayParamResult.value();
  ASSERT_TRUE(minAckDelayParam.has_value());
  EXPECT_EQ(minAckDelayParam.value(), 1000);
}

TEST(ServerStateMachineTest, TestEncodeMinAckDelayParamNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::min_ack_delay)))));
}

TEST(ServerStateMachineTest, TestProcessKnobFramesSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerAdvertisedKnobFrameSupport);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  auto knobFrameSupportedParamResult = getIntegerParameter(
      TransportParameterId::knob_frames_supported, customTransportParams);
  ASSERT_FALSE(knobFrameSupportedParamResult.hasError());
  auto knobFrameSupportedParam = knobFrameSupportedParamResult.value();
  ASSERT_TRUE(knobFrameSupportedParam.has_value());
  EXPECT_EQ(knobFrameSupportedParam.value(), 1);
}

TEST(ServerStateMachineTest, TestEncodeKnobFrameSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedKnobFrameSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::knob_frames_supported)))));
}

TEST(ServerStateMachineTest, TestProcessQuicExperimentParamSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::quic_experiment, 42);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  ASSERT_TRUE(serverConn.peerQuicExperimentId.has_value());
  EXPECT_EQ(*serverConn.peerQuicExperimentId, 42);
}

TEST(ServerStateMachineTest, TestProcessQuicExperimentParamNotSent) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerQuicExperimentId.has_value());
}

TEST(ServerStateMachineTest, TestEncodeQuicExperimentParamNonZero) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.quicExperimentId = 42;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  auto quicExperimentParamResult = getIntegerParameter(
      TransportParameterId::quic_experiment, customTransportParams);
  ASSERT_FALSE(quicExperimentParamResult.hasError());
  const auto& quicExperimentParam = quicExperimentParamResult.value();
  ASSERT_TRUE(quicExperimentParam.has_value());
  EXPECT_EQ(quicExperimentParam.value(), 42);
}

TEST(ServerStateMachineTest, TestEncodeQuicExperimentParamZero) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::quic_experiment)))));
}

TEST(ServerStateMachineTest, TestProcessExtendedAckSupportParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::extended_ack_features, 7);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.peerAdvertisedExtendedAckFeatures, 7);
}

TEST(ServerStateMachineTest, TestProcessExtendedAckSupportParamNotSent) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.peerAdvertisedExtendedAckFeatures, 0);
}

TEST(
    ServerStateMachineTest,
    TestProcessReliableStreamResetSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeEmptyParameter(TransportParameterId::reliable_stream_reset));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(serverConn.peerAdvertisedReliableStreamResetSupport);
}

TEST(
    ServerStateMachineTest,
    TestProcessReliableStreamResetSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_FALSE(serverConn.peerAdvertisedReliableStreamResetSupport);
}

TEST(ServerStateMachineTest, TestProcessReliableStreamResetNonEmptyParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::reliable_stream_reset, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, TestProcessReliableStreamResetLegacyParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeEmptyParameter(TransportParameterId::reliable_stream_reset_legacy));
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_TRUE(serverConn.peerAdvertisedReliableStreamResetSupport);
}

TEST(
    ServerStateMachineTest,
    TestProcessReliableStreamResetLegacyNonEmptyParam) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::reliable_stream_reset_legacy, 0);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(
    ServerStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedReliableResetStreamSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset))));
  auto it = findParameter(
      customTransportParams, TransportParameterId::reliable_stream_reset);
  EXPECT_TRUE(it->value->empty());
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(
                  TransportParameterId::reliable_stream_reset_legacy)))));
}

TEST(
    ServerStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertisedReliableResetStreamSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(serverConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset)))));
}

TEST(ServerStateMachineTest, TestProcessActiveConnectionIdLimitNotSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // Check that the value is the default specified in RFC9000 when the transport
  // parameter is absent
  // https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-6.2.1
  EXPECT_EQ(serverConn.peerActiveConnectionIdLimit, 2);
}

TEST(ServerStateMachineTest, TestProcessActiveConnectionIdLimitSet) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto encodeResult = encodeIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      kMaxActiveConnectionIdLimit + 1);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  // This tests for max + 1. The maximum value will be enforced on sending the
  // new connection id frames, not in parsing the parameters.
  EXPECT_EQ(
      serverConn.peerActiveConnectionIdLimit, kMaxActiveConnectionIdLimit + 1);
}

// draft-ietf-quic-receive-ts-02 transport-parameter parsing on the server.
// Exercises `processClientInitialParams` and asserts the versioned
// `maybePeerReceiveTimestampsConfig` field.

namespace {
ClientTransportParameters buildClientTpsWithTimestampParams(
    Optional<uint64_t> legacyEnabled,
    Optional<uint64_t> legacyMax,
    Optional<uint64_t> legacyExponent,
    Optional<uint64_t> draftMax,
    Optional<uint64_t> draftExponent) {
  std::vector<TransportParameter> transportParams;
  auto push = [&](TransportParameterId id, Optional<uint64_t> value) {
    if (!value.has_value()) {
      return;
    }
    auto r = encodeIntegerParameter(id, *value);
    CHECK(!r.hasError());
    transportParams.push_back(std::move(r.value()));
  };
  push(TransportParameterId::ack_receive_timestamps_enabled, legacyEnabled);
  push(TransportParameterId::max_receive_timestamps_per_ack, legacyMax);
  push(TransportParameterId::receive_timestamps_exponent, legacyExponent);
  push(TransportParameterId::draft_02_max_receive_timestamps_per_ack, draftMax);
  push(
      TransportParameterId::draft_02_receive_timestamps_exponent,
      draftExponent);
  return ClientTransportParameters{std::move(transportParams)};
}
} // namespace

TEST(ServerStateMachineTest, ProcessClientParamsDraft02MaxOnly) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, /*draftMax=*/4, std::nullopt);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 0);
}

TEST(ServerStateMachineTest, ProcessClientParamsDraft02MaxAndExponent) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/8,
      /*draftExponent=*/5);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      8);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 5);
}

TEST(ServerStateMachineTest, ProcessClientParamsDraft02ExponentTooLarge) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/4,
      /*draftExponent=*/21);

  auto result = processClientInitialParams(serverConn, clientParams);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST(ServerStateMachineTest, ProcessClientParamsDraft02ExponentWithoutMax) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/std::nullopt,
      /*draftExponent=*/3);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  EXPECT_FALSE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST(
    ServerStateMachineTest,
    ProcessClientParamsDraft02InvalidExponentIgnoredWithoutMax) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/0,
      /*draftExponent=*/21);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  EXPECT_FALSE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST(ServerStateMachineTest, ProcessClientParamsLegacyOnly) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto clientParams = buildClientTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      std::nullopt,
      std::nullopt);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      9);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST(ServerStateMachineTest, ProcessClientParamsBothFormatsDraftPreferred) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto clientParams = buildClientTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      /*draftMax=*/4,
      /*draftExponent=*/2);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 2);
}

// When the peer advertises draft-02 with max=0 (it does not actually want
// draft-02 timestamps) AND legacy with max>0, selection must NOT classify the
// connection as DraftIetf02{max=0} — that would make the outbound gate (which
// requires max>0) negotiate None and silently drop the legacy timestamps the
// peer requested. The draft-02 branch must require max>0; with max=0 it falls
// through to the legacy branch and negotiates LegacyMvfst.
TEST(
    ServerStateMachineTest,
    ProcessClientParamsDraft02MaxZeroFallsBackToLegacy) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto clientParams = buildClientTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      /*draftMax=*/0,
      /*draftExponent=*/2);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      9);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST(ServerStateMachineTest, ProcessClientParamsNoTimestampTps) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  EXPECT_FALSE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
}

// Reset the peer-receive-timestamps field before populate so stale state
// cannot leak through a caller that bypasses once-per-handshake TP
// processing.
TEST(ServerStateMachineTest, ProcessClientParamsClearsStalePeerConfig) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
      .version = AckReceiveTimestampsVersion::DraftIetf02,
      .maxReceiveTimestampsPerAck = 5,
      .exponent = 2,
  };
  auto clientParams = buildClientTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  EXPECT_FALSE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
}

// Without `enableIetfAckReceiveTimestamps`, an incoming
// ACK_RECEIVE_TIMESTAMPS_DRAFT_02[_ECN] frame on the 1-RTT receive path must
// close the connection with PROTOCOL_VIOLATION.
//
// TODO(Task #21): re-enable after the gate moves to the decoder-dispatch
// boundary; the current gate inside `onServerReadDataFromOpen`'s frame loop
// is only reachable via an encrypted 1-RTT packet routed through the server
// receive path.
TEST(ServerStateMachineTest, DISABLED_RejectsDraft02FrameWhenNotAdvertised) {
  GTEST_SKIP() << "blocked on Task #21 (move gate to dispatch boundary)";
}

// With `enableIetfAckReceiveTimestamps=true` but local config's
// `maxReceiveTimestampsPerAck=0`, an incoming ACK_RECEIVE_TIMESTAMPS_DRAFT_02
// frame must close the connection with PROTOCOL_VIOLATION. Peer that
// advertised max=0 should not be sending these frames per spec; if it does
// anyway, reject. Same reachability blocker as the test above.
TEST(ServerStateMachineTest, DISABLED_RejectsDraft02FrameWhenLocalMaxIsZero) {
  GTEST_SKIP() << "blocked on Task #21 (move gate to dispatch boundary)";
}

// When the client advertises both legacy and draft-02 TPs but the server
// has `sendDraft02AckReceiveTimestamps=false`, the parser populates
// `maybePeerReceiveTimestampsConfig` with the legacy version so the
// negotiated outgoing version settles to LegacyMvfst.
TEST(
    ServerStateMachineTest,
    ProcessClientParamsBothFormatsDraftDisabledFallsBackToLegacy) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.sendDraft02AckReceiveTimestamps = false;
  auto clientParams = buildClientTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/7,
      /*legacyExponent=*/3,
      /*draftMax=*/9,
      /*draftExponent=*/0);

  ASSERT_FALSE(processClientInitialParams(serverConn, clientParams).hasError());

  ASSERT_TRUE(serverConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      serverConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      7);
  EXPECT_EQ(serverConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST(ServerStateMachineTest, TestProcessAckDelayExponentUpdatesReadCodec) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  std::vector<TransportParameter> transportParams;
  auto encodeResult =
      encodeIntegerParameter(TransportParameterId::ack_delay_exponent, 8);
  ASSERT_FALSE(encodeResult.hasError());
  transportParams.push_back(encodeResult.value());
  ClientTransportParameters clientTransportParams = {
      std::move(transportParams)};
  auto result = processClientInitialParams(serverConn, clientTransportParams);
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(serverConn.peerAckDelayExponent, 8);

  // A 1-RTT ACK frame: Largest Acknowledged 5, ACK Delay 1, no more ranges.
  constexpr std::array<uint8_t, 4> ackFrame = {0x05, 0x01, 0x00, 0x00};
  ContiguousReadCursor cursor(ackFrame.data(), ackFrame.size());
  PacketHeader header{
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1)};
  auto ack = decodeAckFrame(
      cursor, header, serverConn.readCodec->getCodecParameters());
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(ack->ackDelay.count(), 1 << 8);
}

} // namespace test
} // namespace quic
