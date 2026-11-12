/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/Types.h>
#include <fizz/util/Status.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/CachedServerTransportParametersSerialization.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/PacerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/handshake/TransportParameters.h>

using namespace ::testing;

namespace quic::test {

namespace {
// Use non-default values to test for nops
constexpr auto idleTimeout = kDefaultIdleTimeout + 1s;
constexpr auto maxRecvPacketSize = 1420;
constexpr auto initialMaxData = kDefaultConnectionFlowControlWindow + 2;
constexpr auto initialMaxStreamDataBidiLocal =
    kDefaultStreamFlowControlWindow + 3;
constexpr auto initialMaxStreamDataBidiRemote =
    kDefaultStreamFlowControlWindow + 4;
constexpr auto initialMaxStreamDataUni = kDefaultStreamFlowControlWindow + 5;
constexpr auto initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional + 6;
constexpr auto initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional + 7;
constexpr auto knobFrameSupport = true;
constexpr auto extendedAckSupport = 3;
constexpr auto ackReceiveTimestampsEnabled = true;
constexpr auto maxReceiveTimestampsPerAck = 10;
constexpr auto ackReceiveTimestampsExponent = 0;
const CachedServerTransportParameters kParams{
    .idleTimeout = std::chrono::milliseconds(idleTimeout).count(),
    .maxRecvPacketSize = maxRecvPacketSize,
    .initialMaxData = initialMaxData,
    .initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal,
    .initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote,
    .initialMaxStreamDataUni = initialMaxStreamDataUni,
    .initialMaxStreamsBidi = initialMaxStreamsBidi,
    .initialMaxStreamsUni = initialMaxStreamsUni,
    .maxReceiveTimestampsPerAck = maxReceiveTimestampsPerAck,
    .receiveTimestampsExponent = ackReceiveTimestampsExponent,
    .extendedAckFeatures = extendedAckSupport,
    .knobFrameSupport = knobFrameSupport,
    .ackReceiveTimestampsEnabled = ackReceiveTimestampsEnabled};
} // namespace

class ClientStateMachineTest : public Test {
 public:
  void SetUp() override {
    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, makeClientHandshakeImpl(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              auto handshake = std::make_unique<MockClientHandshake>(conn);
              mockHandshake_ = handshake.get();
              return handshake;
            }));
    client_ = std::make_unique<QuicClientConnectionState>(mockFactory_);
  }

  std::shared_ptr<MockClientHandshakeFactory> mockFactory_;
  MockClientHandshake* mockHandshake_;
  std::unique_ptr<QuicClientConnectionState> client_;
};

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsNotIgnorePathMTU) {
  ASSERT_FALSE(
      updateTransportParamsFromCachedEarlyParams(*client_, kParams).hasError());
  EXPECT_EQ(client_->udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsFromCachedEarlyParams) {
  client_->transportSettings.canIgnorePathMTU = true;
  client_->peerAdvertisedKnobFrameSupport = false;
  client_->peerAdvertisedExtendedAckFeatures = 0;

  ASSERT_FALSE(
      updateTransportParamsFromCachedEarlyParams(*client_, kParams).hasError());
  EXPECT_EQ(client_->peerIdleTimeout, idleTimeout);
  EXPECT_NE(client_->udpSendPacketLen, maxRecvPacketSize);
  EXPECT_EQ(client_->flowControlState.peerAdvertisedMaxOffset, initialMaxData);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
      initialMaxStreamDataBidiLocal);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
      initialMaxStreamDataBidiRemote);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
      initialMaxStreamDataUni);
  EXPECT_EQ(client_->peerAdvertisedKnobFrameSupport, knobFrameSupport);
  EXPECT_EQ(client_->peerAdvertisedExtendedAckFeatures, extendedAckSupport);

  for (unsigned long i = 0; i < initialMaxStreamsBidi; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextBidirectionalStream().has_value());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextBidirectionalStream().hasError());
  for (unsigned long i = 0; i < initialMaxStreamsUni; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextUnidirectionalStream().has_value());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextUnidirectionalStream().hasError());
}

TEST_F(ClientStateMachineTest, PreserveHappyeyabllsDuringUndo) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();
  client_->happyEyeballsState.finished = true;
  client_->happyEyeballsState.secondSocket =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_TRUE(newConn->happyEyeballsState.finished);
  EXPECT_NE(nullptr, newConn->happyEyeballsState.secondSocket);
}

TEST_F(ClientStateMachineTest, PreservePacingStateDuringUndo) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();
  client_->transportSettings.pacingEnabled = true;
  client_->transportSettings.defaultCongestionController =
      CongestionControlType::BBR2Modular;
  client_->canBePaced = true;
  client_->pacer = createPacer(*client_, kMinCwndInMssForBbr);
  client_->congestionControllerFactory =
      std::make_shared<DefaultCongestionControllerFactory>();
  client_->congestionController =
      client_->congestionControllerFactory->makeCongestionController(
          *client_, CongestionControlType::BBR2Modular);
  const auto* originalPacer = client_->pacer.get();

  auto newConn = undoAllClientStateForRetry(std::move(client_));

  ASSERT_NE(nullptr, newConn->pacer);
  EXPECT_NE(originalPacer, newConn->pacer.get());
  EXPECT_TRUE(newConn->canBePaced);
  ASSERT_NE(nullptr, newConn->congestionController);
  EXPECT_EQ(
      CongestionControlType::BBR2Modular,
      newConn->congestionController->type());
}

TEST_F(ClientStateMachineTest, PreserveSconeReceiveStateDuringUndo) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();
  client_->transportSettings.advertiseSconeSupport = true;
  client_->scone.emplace();
  client_->scone->configuredRateSignal = 42;

  auto newConn = undoAllClientStateForRetry(std::move(client_));

  ASSERT_TRUE(newConn->scone.has_value());
  EXPECT_EQ(newConn->scone->configuredRateSignal, kSconeNoAdvice);
}

TEST_F(ClientStateMachineTest, PreserveSconeSendStateDuringUndo) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();
  client_->transportSettings.enableSconeSend = true;
  client_->scone.emplace();

  auto newConn = undoAllClientStateForRetry(std::move(client_));

  EXPECT_TRUE(newConn->scone.has_value());
}

TEST_F(ClientStateMachineTest, KeepSconeDisabledDuringUndo) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();

  auto newConn = undoAllClientStateForRetry(std::move(client_));

  EXPECT_FALSE(newConn->scone.has_value());
}

TEST_F(ClientStateMachineTest, PreserveObserverContainer) {
  auto socket = std::make_shared<MockQuicSocket>();
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(socket.get());
  SocketObserverContainer::ManagedObserver obs;
  observerContainer->addObserver(&obs);
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();

  client_->observerContainer = observerContainer;
  EXPECT_EQ(
      1,
      CHECK_NOTNULL(client_->observerContainer.lock().get())->numObservers());
  EXPECT_THAT(
      CHECK_NOTNULL(client_->observerContainer.lock().get())->findObservers(),
      UnorderedElementsAre(&obs));

  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_EQ(newConn->observerContainer.lock(), observerContainer);
  EXPECT_EQ(
      1,
      CHECK_NOTNULL(newConn->observerContainer.lock().get())->numObservers());
  EXPECT_THAT(
      CHECK_NOTNULL(newConn->observerContainer.lock().get())->findObservers(),
      UnorderedElementsAre(&obs));
}

TEST_F(ClientStateMachineTest, PreserveObserverContainerNullptr) {
  auto randomCid = ConnectionId::createRandom(8);
  ASSERT_TRUE(randomCid.has_value());
  client_->clientConnectionId = randomCid.value();

  ASSERT_THAT(client_->observerContainer.lock(), IsNull());

  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_THAT(newConn->observerContainer.lock(), IsNull());
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};

  auto result =
      processServerInitialParams(clientConn, serverTransportParams, 0);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.datagramState.maxWriteFrameSize, 0);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult = encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(
      clientConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST_F(ClientStateMachineTest, TestProcessMaxAckDelayBoundary) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto encoded = encodeIntegerParameter(
      TransportParameterId::max_ack_delay, kMaxAckDelay - 1);
  ASSERT_FALSE(encoded.hasError());
  ServerTransportParameters serverTransportParams = {
      {std::move(encoded.value())}};

  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(
      std::chrono::milliseconds(kMaxAckDelay - 1), clientConn.peerMaxAckDelay);
}

TEST_F(ClientStateMachineTest, TestProcessMaxAckDelayRejectsProtocolLimit) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto encoded =
      encodeIntegerParameter(TransportParameterId::max_ack_delay, kMaxAckDelay);
  ASSERT_FALSE(encoded.hasError());
  ServerTransportParameters serverTransportParams = {
      {std::move(encoded.value())}};

  auto result =
      processServerInitialParams(clientConn, serverTransportParams, 0);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, result.error().code);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 1);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_TRUE(clientConn.peerAdvertisedKnobFrameSupport);
}

TEST_F(ClientStateMachineTest, TestProcessKnobFramesSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::knob_frames_supported, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_FALSE(clientConn.peerAdvertisedKnobFrameSupport);
}

TEST_F(ClientStateMachineTest, TestProcessExtendedAckSupportedParam) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::extended_ack_features, 3);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.peerAdvertisedExtendedAckFeatures, 3);
}

TEST_F(ClientStateMachineTest, TestProcessExtendedAckSupportedParamDefault) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_EQ(clientConn.peerAdvertisedExtendedAckFeatures, 0);
}

TEST_F(
    ClientStateMachineTest,
    TestProcessReliableStreamResetSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeEmptyParameter(TransportParameterId::reliable_stream_reset));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_TRUE(clientConn.peerAdvertisedReliableStreamResetSupport);
}

TEST_F(
    ClientStateMachineTest,
    TestProcessReliableStreamResetSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  ASSERT_FALSE(processServerInitialParams(clientConn, serverTransportParams, 0)
                   .hasError());
  EXPECT_FALSE(clientConn.peerAdvertisedReliableStreamResetSupport);
}

TEST_F(ClientStateMachineTest, TestProcessReliableStreamResetNonEmptyParam) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::reliable_stream_reset, 0);
  ASSERT_FALSE(paramResult.hasError());
  transportParams.push_back(std::move(paramResult.value()));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  auto result =
      processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(
    ClientStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.advertisedReliableResetStreamSupport = true;
  auto customTransportParams = getSupportedExtTransportParams(clientConn);
  EXPECT_THAT(
      customTransportParams,
      Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset))));
  auto it = findParameter(
      customTransportParams, TransportParameterId::reliable_stream_reset);
  EXPECT_TRUE(it->value->empty());
}

TEST_F(
    ClientStateMachineTest,
    TestEncodeReliableStreamResetSupportedParamDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.advertisedReliableResetStreamSupport = false;
  auto customTransportParams = getSupportedExtTransportParams(clientConn);
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(
          testing::Field(
              &TransportParameter::parameter,
              testing::Eq(TransportParameterId::reliable_stream_reset)))));
}

// draft-ietf-quic-receive-ts-02 transport-parameter parsing on the client.

namespace {
// Builds a `ServerTransportParameters` blob with the requested timestamp TPs
// encoded; `std::nullopt` skips that TP.
ServerTransportParameters buildServerTpsWithTimestampParams(
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
  return ServerTransportParameters{std::move(transportParams)};
}
} // namespace

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02MaxOnly) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/std::nullopt,
      /*legacyMax=*/std::nullopt,
      /*legacyExponent=*/std::nullopt,
      /*draftMax=*/4,
      /*draftExponent=*/std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 0);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02MaxAndExponent) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/8,
      /*draftExponent=*/5);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      8);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 5);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02ExponentTooLarge) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/4,
      /*draftExponent=*/21);

  auto result = processServerInitialParams(clientConn, serverParams, 0);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsDraft02ExponentWithoutMax) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/std::nullopt,
      /*draftExponent=*/3);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST_F(
    ClientStateMachineTest,
    ProcessServerParamsDraft02InvalidExponentIgnoredWithoutMax) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt,
      std::nullopt,
      std::nullopt,
      /*draftMax=*/0,
      /*draftExponent=*/21);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

TEST_F(ClientStateMachineTest, ProcessServerParamsLegacyOnly) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      std::nullopt,
      std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      9);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsBothFormatsDraftPreferred) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      /*draftMax=*/4,
      /*draftExponent=*/2);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      4);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 2);
}

// When the peer advertises draft-02 with max=0 (it does not actually want
// draft-02 timestamps) AND legacy with max>0, selection must NOT classify the
// connection as DraftIetf02{max=0} — that would make the outbound gate (which
// requires max>0) negotiate None and silently drop the legacy timestamps the
// peer requested. The draft-02 branch must require max>0; with max=0 it falls
// through to the legacy branch and negotiates LegacyMvfst.
TEST_F(
    ClientStateMachineTest,
    ProcessServerParamsDraft02MaxZeroFallsBackToLegacy) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.enableIetfAckReceiveTimestamps = true;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/9,
      /*legacyExponent=*/3,
      /*draftMax=*/0,
      /*draftExponent=*/2);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      9);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

TEST_F(ClientStateMachineTest, ProcessServerParamsNoTimestampTps) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto serverParams = buildServerTpsWithTimestampParams(
      std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  EXPECT_FALSE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
}

// A legacy cache without the draft-02 trailer must throw inside
// `readCachedServerTransportParameters`. The production caller
// (`PersistentQuicPskCache::getPsk`) feeds a cursor whose tail contains app
// params written via `fizz::detail::writeBuf<uint16_t>`; making the trailer
// optional via `canAdvance` would silently consume the app-params length
// bytes as the trailer and corrupt both. The outer `try/catch` discards the
// cache, and the next connection does a full handshake.
TEST_F(ClientStateMachineTest, DeserializeLegacyCachedTransportParamsThrows) {
  // Build a legacy buffer using the same fizz primitives as the production
  // writer. `to<std::string>()` collects chained IOBufs into a contiguous
  // byte range, mirroring `PersistentQuicPskCache::putPsk`.
  auto legacyOut = folly::IOBuf::create(0);
  {
    folly::io::Appender appender(legacyOut.get(), 512);
    fizz::Error err;
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{12345}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{1450}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{65536}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, uint64_t{32768}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{100}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{100}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint8_t{1}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint8_t{1}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{7}, appender), err);
    FIZZ_THROW_ON_ERROR(fizz::detail::write(err, uint64_t{3}, appender), err);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::write(err, ExtendedAckFeatureMaskType{2}, appender), err);
    // Intentionally no draft-02 trailer.
  }
  auto legacyBytes = legacyOut->to<std::string>();

  auto buf = folly::IOBuf::wrapBuffer(legacyBytes.data(), legacyBytes.length());
  folly::io::Cursor cursor(buf.get());
  CachedServerTransportParameters params;
  EXPECT_ANY_THROW(readCachedServerTransportParameters(cursor, params));
}

// A buffer written with the draft-02 trailer round-trips with all trailer
// fields preserved.
TEST_F(
    ClientStateMachineTest,
    RoundTripCachedTransportParamsWithDraft02Trailer) {
  CachedServerTransportParameters in;
  in.idleTimeout = 12345;
  in.maxRecvPacketSize = 1450;
  in.ackReceiveTimestampsEnabled = true;
  in.maxReceiveTimestampsPerAck = 7;
  in.receiveTimestampsExponent = 3;
  in.extendedAckFeatures = 2;
  in.cachedReceiveTimestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;
  in.draft02MaxReceiveTimestampsPerAck = 11;
  in.draft02ReceiveTimestampsExponent = 5;

  auto out = folly::IOBuf::create(0);
  {
    folly::io::Appender appender(out.get(), 512);
    writeCachedServerTransportParameters(in, appender);
  }
  auto bytes = out->to<std::string>();

  auto buf = folly::IOBuf::wrapBuffer(bytes.data(), bytes.length());
  folly::io::Cursor cursor(buf.get());
  CachedServerTransportParameters roundTripped;
  ASSERT_NO_THROW(readCachedServerTransportParameters(cursor, roundTripped));

  EXPECT_EQ(roundTripped.idleTimeout, 12345);
  EXPECT_EQ(roundTripped.maxReceiveTimestampsPerAck, 7);
  EXPECT_EQ(
      roundTripped.cachedReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(roundTripped.draft02MaxReceiveTimestampsPerAck, 11);
  EXPECT_EQ(roundTripped.draft02ReceiveTimestampsExponent, 5);
}

// When the peer advertises both legacy and draft-02 TPs but the local
// endpoint has `sendDraft02AckReceiveTimestamps=false`, the parser must
// populate `maybePeerReceiveTimestampsConfig` with the legacy version. Local
// does not send draft-02, so picking it would strand the negotiated outgoing
// version at None even though legacy is mutually supported.
TEST_F(
    ClientStateMachineTest,
    ProcessServerParamsBothFormatsDraftDisabledFallsBackToLegacy) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.sendDraft02AckReceiveTimestamps = false;
  auto serverParams = buildServerTpsWithTimestampParams(
      /*legacyEnabled=*/1,
      /*legacyMax=*/7,
      /*legacyExponent=*/3,
      /*draftMax=*/9,
      /*draftExponent=*/0);

  ASSERT_FALSE(
      processServerInitialParams(clientConn, serverParams, 0).hasError());

  ASSERT_TRUE(clientConn.maybePeerReceiveTimestampsConfig.has_value());
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->version,
      AckReceiveTimestampsVersion::LegacyMvfst);
  EXPECT_EQ(
      clientConn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck,
      7);
  EXPECT_EQ(clientConn.maybePeerReceiveTimestampsConfig->exponent, 3);
}

// The convenience wrapper must return a coalesced IOBuf so callers can use
// `data()`/`length()` directly. `Appender(buf, 512)` allocates a fresh chunk
// when the head has no tailroom; `IOBuf::create(0)` produces a zero-capacity
// head, so without explicit coalescing the head bytes are empty and naive
// callers silently lose every byte.
TEST_F(
    ClientStateMachineTest,
    ConvenienceWrappersRoundTripThroughHeadBytesOnly) {
  CachedServerTransportParameters in;
  in.idleTimeout = 12345;
  in.maxRecvPacketSize = 1450;
  in.initialMaxData = 1024 * 1024;
  in.initialMaxStreamDataBidiLocal = 512 * 1024;
  in.initialMaxStreamDataBidiRemote = 512 * 1024;
  in.initialMaxStreamDataUni = 256 * 1024;
  in.initialMaxStreamsBidi = 100;
  in.initialMaxStreamsUni = 100;
  in.knobFrameSupport = true;
  in.ackReceiveTimestampsEnabled = true;
  in.maxReceiveTimestampsPerAck = 7;
  in.receiveTimestampsExponent = 3;
  in.extendedAckFeatures = 2;
  in.cachedReceiveTimestampsVersion = AckReceiveTimestampsVersion::DraftIetf02;
  in.draft02MaxReceiveTimestampsPerAck = 11;
  in.draft02ReceiveTimestampsExponent = 5;

  auto serialized = serializeCachedServerTransportParameters(in);
  ASSERT_NE(serialized, nullptr);
  EXPECT_FALSE(serialized->isChained());
  EXPECT_GT(serialized->length(), 0u);

  CachedServerTransportParameters roundTripped;
  ASSERT_TRUE(deserializeCachedServerTransportParameters(
      folly::ByteRange(serialized->data(), serialized->length()),
      roundTripped));

  EXPECT_EQ(roundTripped.idleTimeout, 12345);
  EXPECT_EQ(roundTripped.maxRecvPacketSize, 1450);
  EXPECT_EQ(roundTripped.initialMaxData, 1024u * 1024u);
  EXPECT_EQ(roundTripped.maxReceiveTimestampsPerAck, 7);
  EXPECT_EQ(roundTripped.receiveTimestampsExponent, 3);
  EXPECT_EQ(roundTripped.extendedAckFeatures, 2);
  EXPECT_EQ(
      roundTripped.cachedReceiveTimestampsVersion,
      AckReceiveTimestampsVersion::DraftIetf02);
  EXPECT_EQ(roundTripped.draft02MaxReceiveTimestampsPerAck, 11);
  EXPECT_EQ(roundTripped.draft02ReceiveTimestampsExponent, 5);
}

} // namespace quic::test
