/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/Types.h>
#include <quic/common/MvfstLogging.h>
#include <quic/loss/QuicLossFunctions.h>

#include <quic/QuicConstants.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/codec/Decode.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/PacerFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/StateData.h>

namespace quic {

std::unique_ptr<QuicClientConnectionState> undoAllClientStateForRetry(
    std::unique_ptr<QuicClientConnectionState> conn) {
  // Create a new connection state and copy over properties that don't change
  // across stateless retry.
  auto newConn = std::make_unique<QuicClientConnectionState>(
      std::move(conn->handshakeFactory));
  newConn->observerContainer = conn->observerContainer;
  newConn->qLogger = conn->qLogger;
  newConn->clientConnectionId = conn->clientConnectionId;
  newConn->selfConnectionIds = conn->selfConnectionIds;
  newConn->initialDestinationConnectionId =
      conn->initialDestinationConnectionId;
  newConn->originalDestinationConnectionId =
      conn->originalDestinationConnectionId;
  // TODO: don't carry server connection id over to the new connection.
  newConn->serverConnectionId = conn->serverConnectionId;
  newConn->ackStates.initialAckState->nextPacketNum =
      conn->ackStates.initialAckState->nextPacketNum;
  newConn->ackStates.handshakeAckState->nextPacketNum =
      conn->ackStates.handshakeAckState->nextPacketNum;
  newConn->ackStates.appDataAckState.nextPacketNum =
      conn->ackStates.appDataAckState.nextPacketNum;
  newConn->version = conn->version;
  newConn->originalVersion = conn->originalVersion;
  newConn->originalPeerAddress = conn->originalPeerAddress;
  newConn->peerAddress = conn->peerAddress;
  newConn->udpSendPacketLen = conn->udpSendPacketLen;
  newConn->supportedVersions = conn->supportedVersions;
  newConn->transportSettings = conn->transportSettings;
  if (newConn->transportSettings.advertiseSconeSupport ||
      newConn->transportSettings.enableSconeSend) {
    newConn->scone.emplace(QuicConnectionStateBase::SconeState{});
  }
  newConn->datagramState.maxReadFrameSize =
      conn->datagramState.maxReadFrameSize;
  newConn->datagramState.maxWriteFrameSize =
      conn->datagramState.maxWriteFrameSize;
  newConn->datagramState.maxReadBufferSize =
      conn->datagramState.maxReadBufferSize;
  newConn->datagramState.maxWriteBufferSize =
      conn->datagramState.maxWriteBufferSize;
  newConn->initialWriteCipher = std::move(conn->initialWriteCipher);
  newConn->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
  newConn->readCodec->setClientConnectionId(*conn->clientConnectionId);
  CodecParameters codecParams(
      conn->peerAckDelayExponent,
      conn->originalVersion.value(),
      conn->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
      conn->transportSettings.advertisedExtendedAckFeatures);
  codecParams.peerTimestampFrameTimestampExponent =
      conn->peerTimestampFrameState.sendExponent;
  newConn->readCodec->setCodecParameters(std::move(codecParams));
  newConn->earlyDataAppParamsHandler = conn->earlyDataAppParamsHandler;
  newConn->happyEyeballsState = std::move(conn->happyEyeballsState);
  newConn->flowControlState = std::move(conn->flowControlState);
  newConn->bufAccessor = conn->bufAccessor;
  newConn->pendingOneRttData.reserve(
      newConn->transportSettings.maxPacketsToBuffer);
  const auto congestionControlType = conn->congestionController
      ? conn->congestionController->type()
      : newConn->transportSettings.defaultCongestionController;
  newConn->canBePaced = conn->canBePaced;
  if (newConn->transportSettings.pacingEnabled) {
    const bool useBbrMinCwnd =
        congestionControlType == CongestionControlType::BBR ||
        congestionControlType == CongestionControlType::BBR2 ||
        congestionControlType == CongestionControlType::BBR2Modular ||
        congestionControlType == CongestionControlType::C4;
    const auto minCwnd = useBbrMinCwnd
        ? kMinCwndInMssForBbr
        : newConn->transportSettings.minCwndInMss;
    newConn->pacer = createPacer(*newConn, minCwnd);
  }
  if (conn->congestionControllerFactory) {
    newConn->congestionControllerFactory = conn->congestionControllerFactory;
    if (conn->congestionController) {
      // we have to recreate congestion controller
      // because it holds references to the old state
      newConn->congestionController =
          newConn->congestionControllerFactory->makeCongestionController(
              *newConn, congestionControlType);
    }
  }

  // only copy over zero-rtt data
  for (auto& outstandingPacket : conn->outstandings.packets) {
    auto& packetHeader = outstandingPacket.packet.header;
    if (packetHeader.getPacketNumberSpace() == PacketNumberSpace::AppData &&
        packetHeader.getProtectionType() == ProtectionType::ZeroRtt) {
      newConn->outstandings.packets.push_back(std::move(outstandingPacket));
      newConn->outstandings.packetCount[PacketNumberSpace::AppData]++;
    }
  }

  newConn->lossState = conn->lossState;
  newConn->nodeType = conn->nodeType;
  newConn->streamManager = std::make_unique<QuicStreamManager>(
      *newConn,
      newConn->nodeType,
      newConn->transportSettings,
      std::move(*conn->streamManager));

  newConn->pathManager = std::make_unique<QuicPathManager>(*newConn);
  auto currentPath = conn->pathManager->getPath(conn->currentPathId);
  if (currentPath) {
    auto pathIdRes = newConn->pathManager->addValidatedPath(
        currentPath->localAddress, currentPath->peerAddress);
    MVCHECK(
        !pathIdRes.hasError(),
        "error adding validated path to a retry connection. "
            << toString(pathIdRes.error()));
    newConn->currentPathId = pathIdRes.value();
    if (newConn->serverConnectionId.has_value()) {
      auto setCidRes = newConn->pathManager->setDestinationCidForPath(
          newConn->currentPathId, newConn->serverConnectionId.value());
      MVCHECK(
          !setCidRes.hasError(),
          "error setting destination connection id in a retry connection. "
              << toString(setCidRes.error()));
    }
  }

  auto result = markZeroRttPacketsLost(*newConn, markPacketLoss);
  MVCHECK(
      !result.hasError(),
      "error marking packets lost. " << toString(result.error()));

  return newConn;
}

quic::Expected<void, QuicError> processServerReceiveTimestampsParams(
    QuicClientConnectionState& conn,
    const ServerTransportParameters& serverParams) {
  auto isAckReceiveTimestampsEnabledResult = getIntegerParameter(
      TransportParameterId::ack_receive_timestamps_enabled,
      serverParams.parameters);
  if (isAckReceiveTimestampsEnabledResult.hasError()) {
    return quic::make_unexpected(isAckReceiveTimestampsEnabledResult.error());
  }
  auto isAckReceiveTimestampsEnabled =
      isAckReceiveTimestampsEnabledResult.value();

  auto maxReceiveTimestampsPerAckResult = getIntegerParameter(
      TransportParameterId::max_receive_timestamps_per_ack,
      serverParams.parameters);
  if (maxReceiveTimestampsPerAckResult.hasError()) {
    return quic::make_unexpected(maxReceiveTimestampsPerAckResult.error());
  }
  auto maxReceiveTimestampsPerAck = maxReceiveTimestampsPerAckResult.value();

  auto receiveTimestampsExponentResult = getIntegerParameter(
      TransportParameterId::receive_timestamps_exponent,
      serverParams.parameters);
  if (receiveTimestampsExponentResult.hasError()) {
    return quic::make_unexpected(receiveTimestampsExponentResult.error());
  }
  auto receiveTimestampsExponent = receiveTimestampsExponentResult.value();

  auto draft02MaxResult = getIntegerParameter(
      TransportParameterId::draft_02_max_receive_timestamps_per_ack,
      serverParams.parameters);
  if (draft02MaxResult.hasError()) {
    return quic::make_unexpected(draft02MaxResult.error());
  }
  auto draft02MaxReceiveTimestampsPerAck = draft02MaxResult.value();

  auto draft02ExpResult = getIntegerParameter(
      TransportParameterId::draft_02_receive_timestamps_exponent,
      serverParams.parameters);
  if (draft02ExpResult.hasError()) {
    return quic::make_unexpected(draft02ExpResult.error());
  }
  auto draft02ReceiveTimestampsExponent = draft02ExpResult.value();
  if (draft02MaxReceiveTimestampsPerAck.value_or(0) > 0 &&
      draft02ReceiveTimestampsExponent.has_value() &&
      *draft02ReceiveTimestampsExponent >
          kDraft02MaxReceiveTimestampsExponent) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        fmt::format(
            "draft-02 receive_timestamps_exponent above max: {} > {}",
            *draft02ReceiveTimestampsExponent,
            kDraft02MaxReceiveTimestampsExponent)));
  }

  // Draft-02 wins when peer advertises a positive draft-02 max AND local
  // sends draft-02 (`sendDraft02AckReceiveTimestamps`); otherwise fall back
  // to legacy. Selection keys on max>0 (not
  // mere presence): a draft-02 max of 0 means the peer is not requesting
  // draft-02 timestamps, so a peer advertising draft-02 max=0 alongside a
  // legacy max>0 must negotiate LegacyMvfst rather than DraftIetf02{max=0}
  // (which the outbound gate would downgrade to None, silently dropping the
  // legacy timestamps the peer asked for). This matches the wire-TP parser
  // (`getSupportedExtTransportParams`) and the outbound gate, both of which
  // gate on max>0. "Exponent without max" in draft-02 is ignored per spec.
  // Peer max is capped by the local stored max so an attacker-controlled
  // value can't drive unbounded scheduler allocations.
  const uint64_t storedCap =
      conn.transportSettings.maxReceiveTimestampsPerAckStored;
  if (draft02MaxReceiveTimestampsPerAck.has_value() &&
      *draft02MaxReceiveTimestampsPerAck > 0 &&
      conn.transportSettings.sendDraft02AckReceiveTimestamps) {
    conn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
        .version = AckReceiveTimestampsVersion::DraftIetf02,
        .maxReceiveTimestampsPerAck =
            std::min(*draft02MaxReceiveTimestampsPerAck, storedCap),
        .exponent = draft02ReceiveTimestampsExponent.value_or(0),
    };
  } else if (
      isAckReceiveTimestampsEnabled.has_value() &&
      isAckReceiveTimestampsEnabled.value() == 1 &&
      maxReceiveTimestampsPerAck.has_value() &&
      receiveTimestampsExponent.has_value()) {
    conn.maybePeerReceiveTimestampsConfig = PeerReceiveTimestampsConfig{
        .version = AckReceiveTimestampsVersion::LegacyMvfst,
        .maxReceiveTimestampsPerAck =
            std::min(*maxReceiveTimestampsPerAck, storedCap),
        .exponent = *receiveTimestampsExponent,
    };
  }
  return {};
}

quic::Expected<void, QuicError> processServerInitialParams(
    QuicClientConnectionState& conn,
    const ServerTransportParameters& serverParams,
    PacketNum packetNum) {
  auto maxDataResult = getIntegerParameter(
      TransportParameterId::initial_max_data, serverParams.parameters);
  if (maxDataResult.hasError()) {
    return quic::make_unexpected(maxDataResult.error());
  }
  auto maxData = maxDataResult.value();

  auto maxStreamDataBidiLocalResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      serverParams.parameters);
  if (maxStreamDataBidiLocalResult.hasError()) {
    return quic::make_unexpected(maxStreamDataBidiLocalResult.error());
  }
  auto maxStreamDataBidiLocal = maxStreamDataBidiLocalResult.value();

  auto maxStreamDataBidiRemoteResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      serverParams.parameters);
  if (maxStreamDataBidiRemoteResult.hasError()) {
    return quic::make_unexpected(maxStreamDataBidiRemoteResult.error());
  }
  auto maxStreamDataBidiRemote = maxStreamDataBidiRemoteResult.value();

  auto maxStreamDataUniResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      serverParams.parameters);
  if (maxStreamDataUniResult.hasError()) {
    return quic::make_unexpected(maxStreamDataUniResult.error());
  }
  auto maxStreamDataUni = maxStreamDataUniResult.value();

  auto idleTimeoutResult = getIntegerParameter(
      TransportParameterId::idle_timeout, serverParams.parameters);
  if (idleTimeoutResult.hasError()) {
    return quic::make_unexpected(idleTimeoutResult.error());
  }
  auto idleTimeout = idleTimeoutResult.value();

  auto maxStreamsBidiResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, serverParams.parameters);
  if (maxStreamsBidiResult.hasError()) {
    return quic::make_unexpected(maxStreamsBidiResult.error());
  }
  auto maxStreamsBidi = maxStreamsBidiResult.value();

  auto maxStreamsUniResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, serverParams.parameters);
  if (maxStreamsUniResult.hasError()) {
    return quic::make_unexpected(maxStreamsUniResult.error());
  }
  auto maxStreamsUni = maxStreamsUniResult.value();

  auto ackDelayExponentResult = getIntegerParameter(
      TransportParameterId::ack_delay_exponent, serverParams.parameters);
  if (ackDelayExponentResult.hasError()) {
    return quic::make_unexpected(ackDelayExponentResult.error());
  }
  auto ackDelayExponent = ackDelayExponentResult.value();

  auto maxAckDelayResult = getIntegerParameter(
      TransportParameterId::max_ack_delay, serverParams.parameters);
  if (maxAckDelayResult.hasError()) {
    return quic::make_unexpected(maxAckDelayResult.error());
  }
  auto maxAckDelay = maxAckDelayResult.value();

  auto packetSizeResult = getIntegerParameter(
      TransportParameterId::max_packet_size, serverParams.parameters);
  if (packetSizeResult.hasError()) {
    return quic::make_unexpected(packetSizeResult.error());
  }
  auto packetSize = packetSizeResult.value();

  auto statelessResetTokenResult =
      getStatelessResetTokenParameter(serverParams.parameters);
  if (statelessResetTokenResult.hasError()) {
    return quic::make_unexpected(statelessResetTokenResult.error());
  }
  auto statelessResetToken = statelessResetTokenResult.value();

  auto activeConnectionIdLimitResult = getIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      serverParams.parameters);
  if (activeConnectionIdLimitResult.hasError()) {
    return quic::make_unexpected(activeConnectionIdLimitResult.error());
  }
  auto activeConnectionIdLimit = activeConnectionIdLimitResult.value();

  auto maxDatagramFrameSizeResult = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size, serverParams.parameters);
  if (maxDatagramFrameSizeResult.hasError()) {
    return quic::make_unexpected(maxDatagramFrameSizeResult.error());
  }
  auto maxDatagramFrameSize = maxDatagramFrameSizeResult.value();

  auto minAckDelayResult = getIntegerParameter(
      TransportParameterId::min_ack_delay, serverParams.parameters);
  if (minAckDelayResult.hasError()) {
    return quic::make_unexpected(minAckDelayResult.error());
  }
  auto minAckDelay = minAckDelayResult.value();

  auto receiveTimestampsResult =
      processServerReceiveTimestampsParams(conn, serverParams);
  if (receiveTimestampsResult.hasError()) {
    return quic::make_unexpected(receiveTimestampsResult.error());
  }

  auto knobFrameSupportedResult = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::knob_frames_supported),
      serverParams.parameters);
  if (knobFrameSupportedResult.hasError()) {
    return quic::make_unexpected(knobFrameSupportedResult.error());
  }
  auto knobFrameSupported = knobFrameSupportedResult.value();

  auto extendedAckFeaturesResult = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::extended_ack_features),
      serverParams.parameters);
  if (extendedAckFeaturesResult.hasError()) {
    return quic::make_unexpected(extendedAckFeaturesResult.error());
  }
  auto extendedAckFeatures = extendedAckFeaturesResult.value();

  auto timestampFrameSupportedResult = getIntegerParameter(
      TransportParameterId::timestamp_frame_supported, serverParams.parameters);
  if (timestampFrameSupportedResult.hasError()) {
    return quic::make_unexpected(timestampFrameSupportedResult.error());
  }
  auto timestampFrameSupported = timestampFrameSupportedResult.value();

  auto timestampFrameTimestampExponentResult = getIntegerParameter(
      TransportParameterId::timestamp_frame_timestamp_exponent,
      serverParams.parameters);
  if (timestampFrameTimestampExponentResult.hasError()) {
    return quic::make_unexpected(timestampFrameTimestampExponentResult.error());
  }
  auto timestampFrameTimestampExponent =
      timestampFrameTimestampExponentResult.value();

  auto reliableResetTpIter = findParameter(
      serverParams.parameters,
      static_cast<TransportParameterId>(
          TransportParameterId::reliable_stream_reset));
  if (reliableResetTpIter != serverParams.parameters.end()) {
    if (!reliableResetTpIter->value->empty()) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Reliable reset transport parameter must be empty"));
    }
    conn.peerAdvertisedReliableStreamResetSupport = true;
  } else {
    conn.peerAdvertisedReliableStreamResetSupport = false;
  }

  auto disableActiveMigrationTpIter = findParameter(
      serverParams.parameters,
      static_cast<TransportParameterId>(
          TransportParameterId::disable_migration));
  if (disableActiveMigrationTpIter != serverParams.parameters.end()) {
    if (!disableActiveMigrationTpIter->value->empty()) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Disable active migration parameter must be empty"));
    }
    conn.peerSupportsActiveConnectionMigration = false;
  } else {
    conn.peerSupportsActiveConnectionMigration = true;
  }

  if (conn.version == QuicVersion::QUIC_V1 ||
      conn.version == QuicVersion::QUIC_V1_ALIAS ||
      conn.version == QuicVersion::QUIC_V1_ALIAS2 ||
      conn.version == QuicVersion::MVFST_PRIMING) {
    auto initialSourceConnIdResult = getConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        serverParams.parameters);
    if (initialSourceConnIdResult.hasError()) {
      return quic::make_unexpected(initialSourceConnIdResult.error());
    }
    auto initialSourceConnId = initialSourceConnIdResult.value();

    auto originalDestinationConnIdResult = getConnIdParameter(
        TransportParameterId::original_destination_connection_id,
        serverParams.parameters);
    if (originalDestinationConnIdResult.hasError()) {
      return quic::make_unexpected(originalDestinationConnIdResult.error());
    }
    auto originalDestinationConnId = originalDestinationConnIdResult.value();

    if (!initialSourceConnId || !originalDestinationConnId ||
        initialSourceConnId.value() !=
            conn.readCodec->getServerConnectionId() ||
        originalDestinationConnId.value() !=
            conn.originalDestinationConnectionId) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Initial CID does not match."));
    }
  }

  if (activeConnectionIdLimit.has_value() &&
      activeConnectionIdLimit < kDefaultActiveConnectionIdLimit) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        fmt::format(
            "Active connection id limit too small. received limit = {}",
            *activeConnectionIdLimit)));
  }

  if (!packetSize || *packetSize == 0) {
    packetSize = kDefaultUDPSendPacketLen;
  }
  if (*packetSize < kMinMaxUDPPayload) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        fmt::format(
            "Max packet size too small. received max_packetSize = {}",
            *packetSize)));
  }

  MVVLOG(10) << "Client advertised flow control ";
  MVVLOG(10) << "conn=" << maxData.value_or(0);
  MVVLOG(10) << " stream bidi local=" << maxStreamDataBidiLocal.value_or(0)
             << " ";
  MVVLOG(10) << " stream bidi remote=" << maxStreamDataBidiRemote.value_or(0)
             << " ";
  MVVLOG(10) << " stream uni=" << maxStreamDataUni.value_or(0) << " ";
  MVVLOG(10) << conn;
  conn.flowControlState.peerAdvertisedMaxOffset = maxData.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      maxStreamDataBidiLocal.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      maxStreamDataBidiRemote.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      maxStreamDataUni.value_or(0);
  auto resultBidi = conn.streamManager->setMaxLocalBidirectionalStreams(
      maxStreamsBidi.value_or(0));
  if (resultBidi.hasError()) {
    return quic::make_unexpected(resultBidi.error());
  }
  conn.peerAdvertisedInitialMaxStreamsBidi = maxStreamsBidi.value_or(0);
  auto resultUni = conn.streamManager->setMaxLocalUnidirectionalStreams(
      maxStreamsUni.value_or(0));
  if (resultUni.hasError()) {
    return quic::make_unexpected(resultUni.error());
  }
  conn.peerAdvertisedInitialMaxStreamsUni = maxStreamsUni.value_or(0);
  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout = timeMin(conn.peerIdleTimeout, kMaxIdleTimeout);
  if (ackDelayExponent && *ackDelayExponent > kMaxAckDelayExponent) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "ack_delay_exponent too large"));
  }
  if (maxAckDelay && *maxAckDelay >= kMaxAckDelay) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Max Ack Delay is greater than or equal to 2^14"));
  }
  conn.peerAckDelayExponent =
      ackDelayExponent.value_or(kDefaultAckDelayExponent);
  conn.peerMaxAckDelay = maxAckDelay.has_value()
      ? std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::milliseconds(*maxAckDelay))
      : kMaxAckTimeout;
  if (minAckDelay.has_value()) {
    conn.peerMinAckDelay = std::chrono::microseconds(minAckDelay.value());
  }
  if (conn.transportSettings.canIgnorePathMTU) {
    *packetSize = std::min<uint64_t>(*packetSize, kDefaultMaxUDPPayload);
    conn.udpSendPacketLen = *packetSize;
  }

  conn.peerActiveConnectionIdLimit =
      activeConnectionIdLimit.value_or(kDefaultActiveConnectionIdLimit);

  conn.statelessResetToken = std::move(statelessResetToken);
  // Update the existing streams, because we allow streams to be created before
  // the connection is established.
  conn.streamManager->streamStateForEach(
      [&conn, &packetNum](QuicStreamState& s) {
        auto windowSize = isUnidirectionalStream(s.id)
            ? conn.transportSettings.advertisedInitialUniStreamFlowControlWindow
            : isLocalStream(conn.nodeType, s.id)
            ? conn.transportSettings
                  .advertisedInitialBidiLocalStreamFlowControlWindow
            : conn.transportSettings
                  .advertisedInitialBidiRemoteStreamFlowControlWindow;
        handleStreamWindowUpdate(s, windowSize, packetNum);
      });
  if (maxDatagramFrameSize.has_value()) {
    if (maxDatagramFrameSize.value() > 0 &&
        maxDatagramFrameSize.value() <= kMaxDatagramPacketOverhead) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "max_datagram_frame_size too small"));
    }
    conn.datagramState.maxWriteFrameSize = maxDatagramFrameSize.value();
  }

  conn.peerAdvertisedKnobFrameSupport = knobFrameSupported.value_or(0) > 0;
  conn.peerTimestampFrameState.canReceive =
      timestampFrameSupported.value_or(0) > 0;
  if (timestampFrameTimestampExponent &&
      *timestampFrameTimestampExponent > kMaxTimestampFrameTimestampExponent) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        fmt::format(
            "timestamp_frame_timestamp_exponent above max: {} > {}",
            *timestampFrameTimestampExponent,
            kMaxTimestampFrameTimestampExponent)));
  }
  conn.peerTimestampFrameState.sendExponent =
      static_cast<uint8_t>(timestampFrameTimestampExponent.value_or(
          kDefaultTimestampFrameTimestampExponent));
  if (conn.readCodec) {
    auto codecParams = conn.readCodec->getCodecParameters();
    codecParams.peerTimestampFrameTimestampExponent =
        conn.peerTimestampFrameState.sendExponent;
    conn.readCodec->setCodecParameters(std::move(codecParams));
  }
  conn.peerAdvertisedExtendedAckFeatures = extendedAckFeatures.value_or(0);

  return {};
}

void cacheServerInitialParams(
    QuicClientConnectionState& conn,
    uint64_t peerAdvertisedInitialMaxData,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote,
    uint64_t peerAdvertisedInitialMaxStreamDataUni,
    uint64_t peerAdvertisedInitialMaxStreamsBidi,
    uint64_t peerAdvertisedInitialMaxStreamUni,
    bool peerAdvertisedKnobFrameSupport,
    bool peerAdvertisedReliableStreamResetSupport,
    ExtendedAckFeatureMaskType peerAdvertisedExtendedAckFeatures) {
  conn.serverInitialParamsSet_ = true;
  conn.peerAdvertisedInitialMaxData = peerAdvertisedInitialMaxData;
  conn.peerAdvertisedInitialMaxStreamDataBidiLocal =
      peerAdvertisedInitialMaxStreamDataBidiLocal;
  conn.peerAdvertisedInitialMaxStreamDataBidiRemote =
      peerAdvertisedInitialMaxStreamDataBidiRemote;
  conn.peerAdvertisedInitialMaxStreamDataUni =
      peerAdvertisedInitialMaxStreamDataUni;
  conn.peerAdvertisedInitialMaxStreamsBidi =
      peerAdvertisedInitialMaxStreamsBidi;
  conn.peerAdvertisedInitialMaxStreamsUni = peerAdvertisedInitialMaxStreamUni;
  conn.peerAdvertisedKnobFrameSupport = peerAdvertisedKnobFrameSupport;
  conn.peerAdvertisedReliableStreamResetSupport =
      peerAdvertisedReliableStreamResetSupport;
  conn.peerAdvertisedExtendedAckFeatures = peerAdvertisedExtendedAckFeatures;
  // `maybePeerReceiveTimestampsConfig` is populated by
  // `processServerReceiveTimestampsParams`; not mirrored here.
}

CachedServerTransportParameters getServerCachedTransportParameters(
    const QuicClientConnectionState& conn) {
  MVDCHECK(conn.serverInitialParamsSet_);

  CachedServerTransportParameters transportParams;

  transportParams.idleTimeout = conn.peerIdleTimeout.count();
  transportParams.maxRecvPacketSize = conn.udpSendPacketLen;
  transportParams.initialMaxData = conn.peerAdvertisedInitialMaxData;
  transportParams.initialMaxStreamDataBidiLocal =
      conn.peerAdvertisedInitialMaxStreamDataBidiLocal;
  transportParams.initialMaxStreamDataBidiRemote =
      conn.peerAdvertisedInitialMaxStreamDataBidiRemote;
  transportParams.initialMaxStreamDataUni =
      conn.peerAdvertisedInitialMaxStreamDataUni;
  transportParams.initialMaxStreamsBidi =
      conn.peerAdvertisedInitialMaxStreamsBidi;
  transportParams.initialMaxStreamsUni =
      conn.peerAdvertisedInitialMaxStreamsUni;
  transportParams.knobFrameSupport = conn.peerAdvertisedKnobFrameSupport;
  transportParams.reliableStreamResetSupport =
      conn.peerAdvertisedReliableStreamResetSupport;
  transportParams.extendedAckFeatures = conn.peerAdvertisedExtendedAckFeatures;

  // Legacy cache fields are populated only when the negotiated version was
  // LegacyMvfst, so binaries that pre-date the version trailer still find
  // the fields they expect.
  if (conn.maybePeerReceiveTimestampsConfig.has_value()) {
    const auto& cfg = *conn.maybePeerReceiveTimestampsConfig;
    transportParams.cachedReceiveTimestampsVersion = cfg.version;
    if (cfg.version == AckReceiveTimestampsVersion::LegacyMvfst) {
      transportParams.ackReceiveTimestampsEnabled = true;
      transportParams.maxReceiveTimestampsPerAck =
          cfg.maxReceiveTimestampsPerAck;
      transportParams.receiveTimestampsExponent = cfg.exponent;
    } else if (cfg.version == AckReceiveTimestampsVersion::DraftIetf02) {
      transportParams.draft02MaxReceiveTimestampsPerAck =
          cfg.maxReceiveTimestampsPerAck;
      transportParams.draft02ReceiveTimestampsExponent = cfg.exponent;
    }
  }

  return transportParams;
}

quic::Expected<void, QuicError> updateTransportParamsFromCachedEarlyParams(
    QuicClientConnectionState& conn,
    const CachedServerTransportParameters& transportParams) {
  conn.peerIdleTimeout = std::chrono::milliseconds(transportParams.idleTimeout);
  conn.flowControlState.peerAdvertisedMaxOffset =
      transportParams.initialMaxData;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      transportParams.initialMaxStreamDataBidiLocal;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      transportParams.initialMaxStreamDataBidiRemote;
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      transportParams.initialMaxStreamDataUni;
  auto resultBidi = conn.streamManager->setMaxLocalBidirectionalStreams(
      transportParams.initialMaxStreamsBidi);
  if (resultBidi.hasError()) {
    return quic::make_unexpected(resultBidi.error());
  }
  auto resultUni = conn.streamManager->setMaxLocalUnidirectionalStreams(
      transportParams.initialMaxStreamsUni);
  if (resultUni.hasError()) {
    return quic::make_unexpected(resultUni.error());
  }
  conn.peerAdvertisedKnobFrameSupport = transportParams.knobFrameSupport;
  conn.peerAdvertisedReliableStreamResetSupport =
      transportParams.reliableStreamResetSupport;
  conn.peerAdvertisedExtendedAckFeatures = transportParams.extendedAckFeatures;

  return {};
}
} // namespace quic
