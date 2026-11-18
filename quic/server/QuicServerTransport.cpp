/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/DefaultAppTokenValidator.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/TransportSettingsFunctions.h>

#include <quic/common/Optional.h>
#include <quic/common/TransportKnobs.h>
#include <chrono>
#include <memory>

namespace quic {

QuicServerTransport::QuicServerTransport(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> sock,
    folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCb,
    folly::MaybeManagedPtr<ConnectionCallback> connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    PacketNum startingPacketNum)
    : QuicServerTransport(
          std::move(evb),
          std::move(sock),
          connSetupCb,
          connStreamsCb,
          std::move(ctx),
          std::move(cryptoFactory)) {
  conn_->ackStates = AckStates(startingPacketNum);
}

QuicServerTransport::QuicServerTransport(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> sock,
    folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCb,
    folly::MaybeManagedPtr<ConnectionCallback> connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBaseLite(
          evb,
          std::move(sock),
          useConnectionEndWithErrorCallback),
      QuicTransportBase(
          std::move(evb),
          nullptr /* Initialized through the QuicTransportBaseLite constructor
                   */
          ,
          useConnectionEndWithErrorCallback),
      ctx_(std::move(ctx)),
      wrappedObserverContainer_(this) {
  auto tempConn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder()
          .setFizzServerContext(ctx_)
          .setCryptoFactory(std::move(cryptoFactory))
          .build());
  auto addrResult = socket_->address();
  MVCHECK(addrResult.has_value());
  tempConn->serverAddr = addrResult.value();
  serverConn_ = tempConn.get();
  conn_.reset(tempConn.release());
  conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  setConnectionSetupCallback(connSetupCb);
  setConnectionCallbackFromCtor(connStreamsCb);
  conn_->pathManager->setPathValidationCallback(this);
}

QuicServerTransport::~QuicServerTransport() {
  MVVLOG(10) << "Destroyed connection to client=" << *this;
  onApplicationClose();
  closeImpl(
      QuicError(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from server destructor")),
      false /* drainConnection */);
  // closeImpl may have been called earlier with drain = true, so force close.
  closeUdpSocket();
}

QuicServerTransport::Ptr QuicServerTransport::make(
    folly::EventBase* evb,
    std::unique_ptr<FollyAsyncUDPSocketAlias> sock,
    const folly::MaybeManagedPtr<ConnectionSetupCallback>& connSetupCb,
    const folly::MaybeManagedPtr<ConnectionCallback>& connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    bool useConnectionEndWithErrorCallback) {
  auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
  auto qSock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(sock));
  return std::make_shared<QuicServerTransport>(
      std::move(qEvb),
      std::move(qSock),
      connSetupCb,
      connStreamsCb,
      ctx,
      nullptr /* cryptoFactory */,
      useConnectionEndWithErrorCallback);
}

void QuicServerTransport::setRoutingCallback(
    RoutingCallback* callback) noexcept {
  routingCb_ = callback;
}

void QuicServerTransport::setHandshakeFinishedCallback(
    HandshakeFinishedCallback* callback) noexcept {
  handshakeFinishedCb_ = callback;
}

void QuicServerTransport::setOriginalPeerAddress(
    const quic::SocketAddress& addr) {
  conn_->originalPeerAddress = addr;
}

void QuicServerTransport::setServerConnectionIdParams(
    ServerConnectionIdParams params) noexcept {
  serverConn_->serverConnIdParams = std::move(params);
}

void QuicServerTransport::setTransportStatsCallback(
    QuicTransportStatsCallback* statsCallback) noexcept {
  if (conn_) {
    conn_->statsCallback = statsCallback;
    if (conn_->readCodec) {
      conn_->readCodec->setConnectionStatsCallback(statsCallback);
    }
  }
}

void QuicServerTransport::setConnectionIdAlgo(
    ConnectionIdAlgo* connIdAlgo) noexcept {
  if (serverConn_) {
    serverConn_->connIdAlgo = connIdAlgo;
  }
}

void QuicServerTransport::setServerConnectionIdRejector(
    ServerConnectionIdRejector* connIdRejector) noexcept {
  if (serverConn_) {
    serverConn_->connIdRejector = connIdRejector;
  }
}

quic::Expected<void, QuicError> QuicServerTransport::onReadData(
    const quic::SocketAddress& localAddress,
    ReceivedUdpPacket&& udpPacket) {
  ServerEvents::ReadData readData;
  MVCHECK(udpPacket.peerAddress.has_value());
  readData.peerAddress = *udpPacket.peerAddress;
  readData.localAddress = localAddress;
  readData.udpPacket = std::move(udpPacket);
  bool waitingForFirstPacket = !hasReceivedUdpPackets(*conn_);
  uint64_t prevWritableBytes = serverConn_->writableBytesLimit
      ? *serverConn_->writableBytesLimit
      : std::numeric_limits<uint64_t>::max();
  auto readDataResult = onServerReadData(*serverConn_, readData);
  if (readDataResult.hasError()) {
    return quic::make_unexpected(readDataResult.error());
  }
  if (!quicExperimentApplied_ && quicExperimentHandlerFn_ &&
      serverConn_->peerQuicExperimentId.has_value() &&
      *serverConn_->peerQuicExperimentId != 0) {
    quicExperimentHandlerFn_(*conn_, *serverConn_->peerQuicExperimentId);
    quicExperimentApplied_ = true;
  }
  processPendingData(true);

  if (closeState_ == CloseState::CLOSED) {
    return {};
  }
  if (!notifiedRouting_ && routingCb_ && conn_->serverConnectionId) {
    notifiedRouting_ = true;
    routingCb_->onConnectionIdAvailable(
        shared_from_this(), *conn_->serverConnectionId);
  }
  if (connectionCallbacks_.setup() && waitingForFirstPacket &&
      hasReceivedUdpPackets(*conn_)) {
    connectionCallbacks_.setup()->onFirstPeerPacketProcessed();
  }

  uint64_t curWritableBytes = serverConn_->writableBytesLimit
      ? *serverConn_->writableBytesLimit
      : std::numeric_limits<uint64_t>::max();

  // If we've increased our writable bytes limit after processing incoming data
  // and we were previously blocked from writing probes, fire the PTO alarm
  if (serverConn_->transportSettings.enableWritableBytesLimit &&
      serverConn_->numProbesWritableBytesLimited &&
      prevWritableBytes < curWritableBytes) {
    auto ptoAlarmResult = onPTOAlarm(*serverConn_);
    if (ptoAlarmResult.hasError()) {
      return ptoAlarmResult;
    }
    serverConn_->numProbesWritableBytesLimited = 0;
  }

  auto sessionTicketResult = maybeWriteNewSessionTicket();
  if (sessionTicketResult.hasError()) {
    return sessionTicketResult;
  }
  const bool retimeOnTransportReady =
      serverConn_->transportSettings.retimeOnTransportReady;
  maybeNotifyConnectionIdBound();
  if (!retimeOnTransportReady) {
    // Legacy ordering: handshake-done before transport-ready.
    maybeNotifyHandshakeFinished();
  }
  maybeNotifyConnectionIdRetired();
  maybeIssueConnectionIds();
  maybeNotifyWriteCipherAvailable();
  // onWriteCipherAvailable() can also synchronously close the connection once a
  // consumer does write-dependent setup there (e.g. the H3 ALPN check); bail
  // before transport-ready so it isn't delivered on a closed transport. This
  // only happens in the retimed flow (onWriteCipherAvailable() is itself gated
  // on retimeOnTransportReady), so scope the bail to it and leave the legacy
  // flow unchanged.
  if (retimeOnTransportReady && closeState_ == CloseState::CLOSED) {
    return {};
  }
  maybeNotifyTransportReady();
  // Retimed ordering: transport-ready before handshake-done. onTransportReady()
  // can synchronously close the connection (e.g. an H3 ALPN mismatch), so guard
  // the deferred callback — it must not run on a closed transport.
  if (retimeOnTransportReady && closeState_ != CloseState::CLOSED) {
    maybeNotifyHandshakeFinished();
  }
  conn_->pathManager->maybeReapUnusedPaths();
  return {};
}

void QuicServerTransport::configureForAccept(ServerAcceptParams&& params) {
  if (!conn_->congestionControllerFactory) {
    // The application factory owns congestion-control policy; keep the
    // historical shared default when it does not install one.
    static auto defaultCcFactory =
        std::make_shared<ServerCongestionControllerFactory>();
    setCongestionControllerFactory(defaultCcFactory);
  }
  if (params.bufAccessor) {
    setBufAccessor(params.bufAccessor);
  }
  setPacingTimer(params.pacingTimer);
  setSupportedVersions(params.supportedVersions);
  setOriginalPeerAddress(params.originalPeerAddress);
  if (params.validNewToken) {
    verifiedClientAddress();
  }
  setTransportStatsCallback(params.statsCallback);
  if (conn_->congestionController) {
    conn_->congestionController.reset();
  }
  setTransportSettings(std::move(params.transportSettings));
  setConnectionIdAlgo(params.connIdAlgo);
  setServerConnectionIdRejector(params.connIdRejector);
  if (params.clientConnectionId) {
    setClientConnectionId(*params.clientConnectionId);
  }
  setClientChosenDestConnectionId(params.clientChosenDestConnectionId);
  setServerConnectionIdParams(params.serverConnectionIdParams);
}

void QuicServerTransport::accept(folly::Optional<QuicVersion> quicVersion) {
  MVCHECK(conn_->bufAccessor);
  registerAllTransportKnobParamHandlers();
  setIdleTimer();
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);
  // Override zeroRttSourceTokenMatchingPolicy for MVFST_PRIMING
  if (quicVersion && *quicVersion == QuicVersion::MVFST_PRIMING) {
    serverConn_->transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  }
  serverConn_->serverHandshakeLayer->initialize(
      getFollyEventbase(),
      this,
      std::move(quicVersion),
      std::make_unique<DefaultAppTokenValidator>(serverConn_));
}

quic::Expected<void, QuicError> QuicServerTransport::writeData() {
  if (!conn_->clientConnectionId || !conn_->serverConnectionId) {
    return {};
  }
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  const ConnectionId& srcConnId = *conn_->serverConnectionId;
  const ConnectionId& destConnId = *conn_->clientConnectionId;
  if (closeState_ == CloseState::CLOSED) {
    if (conn_->peerConnectionError &&
        hasReceivedUdpPacketsAtLastCloseSent(*conn_)) {
      // The peer sent us an error, we are in draining state now.
      return {};
    }
    if (hasReceivedUdpPacketsAtLastCloseSent(*conn_) &&
        hasNotReceivedNewPacketsSinceLastCloseSent(*conn_)) {
      // We did not receive any new packets, do not sent a new close frame.
      return {};
    }
    updateLargestReceivedUdpPacketsAtLastCloseSent(*conn_);
    if (conn_->oneRttWriteCipher) {
      PROTO_OOPS_LOG_BUILDER_IF(
          !conn_->oneRttWriteHeaderCipher,
          conn_->oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
          "quic_server_transport",
          "invariant_violation: one-rtt write cipher missing header cipher");
      MVCHECK(conn_->oneRttWriteHeaderCipher);
      writeShortClose(
          *socket_,
          *conn_,
          destConnId,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    }
    if (conn_->handshakeWriteCipher) {
      PROTO_OOPS_LOG_BUILDER_IF(
          !conn_->handshakeWriteHeaderCipher,
          conn_->oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
          "quic_server_transport",
          "invariant_violation: handshake write cipher missing header cipher");
      MVCHECK(conn_->handshakeWriteHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Handshake,
          conn_->localConnectionError,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version);
    }
    if (conn_->initialWriteCipher) {
      PROTO_OOPS_LOG_BUILDER_IF(
          !conn_->initialHeaderCipher,
          conn_->oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
          "quic_server_transport",
          "invariant_violation: initial write cipher missing header cipher");
      MVCHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Initial,
          conn_->localConnectionError,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version);
    }
    return {};
  }
  uint64_t packetLimit =
      (isConnectionPaced(*conn_)
           ? conn_->pacer->updateAndGetWriteBatchSize(Clock::now())
           : conn_->transportSettings.writeConnectionDataPacketsLimit);
  // At the end of this function, clear out any probe packets credit we didn't
  // use.
  SCOPE_EXIT {
    conn_->pendingEvents.numProbePackets = {};
  };
  if (conn_->initialWriteCipher) {
    auto res = handleInitialWriteDataCommon(srcConnId, destConnId, packetLimit);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    packetLimit -= res->packetsWritten;
    serverConn_->numHandshakeBytesSent += res->bytesWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (conn_->handshakeWriteCipher) {
    auto res =
        handleHandshakeWriteDataCommon(srcConnId, destConnId, packetLimit);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    packetLimit -= res->packetsWritten;
    serverConn_->numHandshakeBytesSent += res->bytesWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (conn_->oneRttWriteCipher) {
    PROTO_OOPS_LOG_BUILDER_IF(
        !conn_->oneRttWriteHeaderCipher,
        conn_->oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
        "quic_server_transport",
        "invariant_violation: one-rtt write cipher missing header cipher");
    MVCHECK(conn_->oneRttWriteHeaderCipher);
    auto writeLoopBeginTime = Clock::now();
    auto nonDsrPath =
        [&](auto limit) -> quic::Expected<WriteQuicDataResult, QuicError> {
      auto result = writeQuicDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher,
          version,
          limit,
          writeLoopBeginTime);
      if (result.hasError()) {
        return quic::make_unexpected(result.error());
      }
      return result.value();
    };
    auto pathValidationWrites =
        [&](auto limit) -> quic::Expected<WriteQuicDataResult, QuicError> {
      auto result = writePathValidationDataForAlternatePaths(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher,
          version,
          limit,
          writeLoopBeginTime);
      if (result.hasError()) {
        return quic::make_unexpected(result.error());
      }
      return result.value();
    };
    // We need a while loop because we might get empty writes.
    while (packetLimit) {
      auto totalSentBefore = conn_->lossState.totalBytesSent;
      auto written = nonDsrPath(packetLimit);
      if (written.hasError()) {
        return quic::make_unexpected(written.error());
      }
      packetLimit -= written->bytesWritten / conn_->udpSendPacketLen;
      if (totalSentBefore == conn_->lossState.totalBytesSent) {
        // We haven't written anything, so we're done.
        break;
      }
    }
    auto written = pathValidationWrites(packetLimit);
    if (written.hasError()) {
      return quic::make_unexpected(written.error());
    }
  }

  return maybeInitiateKeyUpdate(*conn_);
}

void QuicServerTransport::closeTransport() {
  [[maybe_unused]] auto self = weak_from_this().lock();
  const bool handshakeDone =
      serverConn_->serverHandshakeLayer->isHandshakeDone();
  if (!handshakeDone) {
    QUIC_STATS(conn_->statsCallback, onServerUnfinishedHandshake);
  }
  if (auto* handshakeCb = std::exchange(handshakeFinishedCb_, nullptr)) {
    if (handshakeDone) {
      handshakeCb->onHandshakeFinished();
    } else {
      handshakeCb->onHandshakeUnfinished();
    }
  }
  serverConn_->serverHandshakeLayer->cancel();
  // Clear out pending data.
  serverConn_->pendingZeroRttData.reset();
  serverConn_->pendingOneRttData.reset();
  onServerClose(*serverConn_);
}

void QuicServerTransport::unbindConnection() {
  [[maybe_unused]] auto self = weak_from_this().lock();
  setTransportStatsCallback(nullptr);
  setConnectionIdAlgo(nullptr);
  setServerConnectionIdRejector(nullptr);
  conn_->bufAccessor = nullptr;
  if (auto* handshakeCb = std::exchange(handshakeFinishedCb_, nullptr)) {
    if (serverConn_->serverHandshakeLayer->isHandshakeDone()) {
      handshakeCb->onHandshakeFinished();
    } else {
      handshakeCb->onHandshakeUnfinished();
    }
  }
  auto* routingCb = std::exchange(routingCb_, nullptr);
  if (!routingCb) {
    return;
  }
  // Snapshot arguments before callbacks; callbacks may delete `this`.
  auto retiringConnIds = *conn_->connIdsRetiringSoon;
  conn_->connIdsRetiringSoon->clear();
  PROTO_OOPS_LOG_BUILDER_IF(
      !conn_->clientChosenDestConnectionId,
      conn_->oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
      "quic_server_transport",
      "invariant_violation: unbind missing client-chosen destination "
      "connection id");
  MVCHECK(conn_->clientChosenDestConnectionId);
  auto source = std::make_pair(
      getOriginalPeerAddress(), *conn_->clientChosenDestConnectionId);
  auto connectionIds = conn_->selfConnectionIds;
  for (const auto& connId : retiringConnIds) {
    routingCb->onConnectionIdRetired(*this, connId);
  }
  routingCb->onConnectionUnbound(this, source, connectionIds);
}

bool QuicServerTransport::hasWriteCipher() const {
  return conn_->oneRttWriteCipher != nullptr;
}

bool QuicServerTransport::hasReadCipher() const {
  return conn_->readCodec != nullptr &&
      conn_->readCodec->getOneRttReadCipher() != nullptr;
}

std::shared_ptr<QuicTransportBaseLite> QuicServerTransport::sharedGuard() {
  return shared_from_this();
}

void QuicServerTransport::setClientConnectionId(
    const ConnectionId& clientConnectionId) {
  conn_->clientConnectionId = clientConnectionId;
  auto& cid = conn_->peerConnectionIds.emplace_back(
      clientConnectionId, kInitialConnectionIdSequenceNumber);
  cid.inUse = true;
}

void QuicServerTransport::setClientChosenDestConnectionId(
    const ConnectionId& clientChosenDestConnectionId) {
  conn_->clientChosenDestConnectionId = clientChosenDestConnectionId;
}

void QuicServerTransport::setRetryOriginalDstConnId(
    const ConnectionId& originalDstConnId) {
  if (serverConn_) {
    serverConn_->retryOriginalDstConnId = originalDstConnId;
  }
}

void QuicServerTransport::onCryptoEventAvailable() noexcept {
  try {
    MVVLOG(10) << "onCryptoEventAvailable " << *this;
    if (closeState_ != CloseState::OPEN) {
      MVVLOG(10) << "Got crypto event after connection closed " << *this;
      return;
    }
    [[maybe_unused]] auto self = sharedGuard();
    auto handshakeResult = updateHandshakeState(*serverConn_);
    if (handshakeResult.hasError()) {
      closeImpl(handshakeResult.error());
      return;
    }
    if (!quicExperimentApplied_ && quicExperimentHandlerFn_ &&
        serverConn_->peerQuicExperimentId.has_value() &&
        *serverConn_->peerQuicExperimentId != 0) {
      quicExperimentHandlerFn_(*conn_, *serverConn_->peerQuicExperimentId);
      quicExperimentApplied_ = true;
    }
    processPendingData(false);
    // pending data may contain connection close
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
    auto sessionTicketResult = maybeWriteNewSessionTicket();
    if (sessionTicketResult.hasError()) {
      closeImpl(sessionTicketResult.error());
      return;
    }
    const bool retimeOnTransportReady =
        serverConn_->transportSettings.retimeOnTransportReady;
    maybeNotifyConnectionIdBound();
    if (!retimeOnTransportReady) {
      // Legacy ordering: handshake-done before transport-ready.
      maybeNotifyHandshakeFinished();
    }
    maybeIssueConnectionIds();
    auto writeResult = writeSocketData();
    if (writeResult.hasError()) {
      closeImpl(writeResult.error());
      return;
    }
    maybeNotifyWriteCipherAvailable();
    // onWriteCipherAvailable() can also synchronously close the connection once
    // a consumer does write-dependent setup there (e.g. the H3 ALPN check);
    // bail before transport-ready so it isn't delivered on a closed transport.
    // This only happens in the retimed flow (onWriteCipherAvailable() is itself
    // gated on retimeOnTransportReady), so scope the bail to it and leave the
    // legacy flow unchanged.
    if (retimeOnTransportReady && closeState_ == CloseState::CLOSED) {
      return;
    }
    maybeNotifyTransportReady();
    // Retimed ordering: transport-ready before handshake-done.
    // onTransportReady() can synchronously close the connection (e.g. an H3
    // ALPN mismatch), so guard the deferred callback — it must not run on a
    // closed transport.
    if (retimeOnTransportReady && closeState_ != CloseState::CLOSED) {
      maybeNotifyHandshakeFinished();
    }
  } catch (const QuicTransportException& ex) {
    MVVLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    MVVLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    MVLOG_ERROR << "read() error " << ex.what() << " " << *this;
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
  }
}

void QuicServerTransport::handleTransportKnobParams(
    const TransportKnobParams& params) {
  for (const auto& param : params) {
    auto maybeParamHandler = transportKnobParamHandlers_.find(param.id);
    TransportKnobParamId knobParamId = TransportKnobParamId::UNKNOWN;
    if (TransportKnobParamId::_is_valid(param.id)) {
      knobParamId = TransportKnobParamId::_from_integral(param.id);
    }
    if (maybeParamHandler != transportKnobParamHandlers_.end()) {
      auto result = (maybeParamHandler->second)(*this, param.val);
      if (result.has_value()) {
        QUIC_STATS(conn_->statsCallback, onTransportKnobApplied, knobParamId);
      } else {
        QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
      }
    } else {
      QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
    }
  }
}

void QuicServerTransport::processPendingData(bool async) {
  // The case when both 0-rtt and 1-rtt pending data are ready to be processed
  // but neither had been shouldn't happen.
  // This is shared pointer because the lamda below (auto func) does a copy
  // for std::function for a reason not understood.
  std::shared_ptr<std::vector<ServerEvents::ReadData>> pendingData;
  if (conn_->readCodec && conn_->readCodec->getOneRttReadCipher()) {
    pendingData = std::move(serverConn_->pendingOneRttData);
    // It's possible that 0-rtt packets are received after CFIN, we are not
    // dealing with that much level of reordering.
    serverConn_->pendingZeroRttData.reset();
  } else if (conn_->readCodec && conn_->readCodec->getZeroRttReadCipher()) {
    pendingData = std::move(serverConn_->pendingZeroRttData);
  }
  if (pendingData) {
    // Move the pending data out so that we don't ever add new data to the
    // pending data.
    VLOG_IF(10, !pendingData->empty())
        << "Processing pending data size=" << pendingData->size() << " "
        << *this;
    auto func = [pendingData = std::move(pendingData), this](auto) {
      for (auto& pendingPacket : *pendingData) {
        pendingPacket.udpPacket.peerAddress = pendingPacket.peerAddress;
        onNetworkData(
            pendingPacket.localAddress,
            NetworkData(std::move(pendingPacket.udpPacket)));
        if (closeState_ == CloseState::CLOSED) {
          // The pending data could potentially contain a connection close, or
          // the app could have triggered a connection close with an error. It
          // is not useful to continue the handshake.
          return;
        }
        // The app could have triggered a graceful close from the callbacks,
        // in which case we should continue with the handshake and processing
        // the remaining data because it could potentially have a FIN which
        // could end the graceful close.
      }
    };
    if (async) {
      runOnEvbAsync(std::move(func));
    } else {
      func(shared_from_this());
    }
  }
}

bool QuicServerTransport::shouldWriteNewSessionTicket() {
  if (!newSessionTicketWrittenTimestamp_) {
    // No session ticket has been written yet, we should write one.
    return true;
  }

  // Check if current peer address differs from the most recent source address.
  // This triggers a new session ticket after connection migration to ensure
  // the client gets a ticket with the new address for future 0-RTT attempts.
  if (!serverConn_->tokenSourceAddresses.empty() &&
      serverConn_->tokenSourceAddresses.back() !=
          conn_->peerAddress.getIPAddress()) {
    return true;
  }

  // Conditions for writing more session tickets after the first one:
  // 1. includeCwndHintsInSessionTicket transport setting is set
  // 2. The current BDP is either smaller than or more than twice
  // the last one we sent in a session ticket
  // 3. We haven't sent any session ticket in the last
  // kMinIntervalBetweenSessionTickets

  if (conn_->transportSettings.includeCwndHintsInSessionTicket &&
      conn_->congestionController) {
    const auto& targetBDP = conn_->congestionController->getBDP();
    bool bdpChangedSinceLastHint =
        !newSessionTicketWrittenCwndHint_.has_value() ||
        targetBDP / 2 > *newSessionTicketWrittenCwndHint_ ||
        targetBDP < *newSessionTicketWrittenCwndHint_;
    if (bdpChangedSinceLastHint &&
        Clock::now() - newSessionTicketWrittenTimestamp_.value() >
            kMinIntervalBetweenSessionTickets) {
      return true;
    }
  }
  return false;
}

quic::Expected<void, QuicError>
QuicServerTransport::maybeWriteNewSessionTicket() {
  if (shouldWriteNewSessionTicket() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    newSessionTicketWrittenTimestamp_ = Clock::now();
    if (conn_->transportSettings.includeCwndHintsInSessionTicket &&
        conn_->congestionController) {
      const auto& bdp = conn_->congestionController->getBDP();
      newSessionTicketWrittenCwndHint_ = std::max(
          bdp,
          conn_->udpSendPacketLen * conn_->transportSettings.initCwndInMss);
    }
    AppToken appToken;
    Optional<uint64_t> rttHintMs;
    if (conn_->lossState.srtt > 0us) {
      rttHintMs = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              conn_->lossState.srtt)
              .count());
    }
    auto transportParamsResult = createTicketTransportParameters(
        conn_->transportSettings.idleTimeout.count(),
        conn_->transportSettings.maxRecvPacketSize,
        conn_->transportSettings.advertisedInitialConnectionFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiLocalStreamFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialUniStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialMaxStreamsBidi,
        conn_->transportSettings.advertisedInitialMaxStreamsUni,
        conn_->transportSettings.advertisedExtendedAckFeatures,
        newSessionTicketWrittenCwndHint_,
        rttHintMs);
    if (transportParamsResult.hasError()) {
      return quic::make_unexpected(transportParamsResult.error());
    }
    appToken.transportParams = std::move(transportParamsResult.value());
    appToken.sourceAddresses = serverConn_->tokenSourceAddresses;
    appToken.version = conn_->version.value();

    // Ensure the current peer address is always in the source addresses list.
    // This handles:
    // 1. First connection without 0-RTT (tokenSourceAddresses is empty)
    // 2. Connection migration (new address may not be in tokenSourceAddresses)
    auto currentPeerIP = conn_->peerAddress.getIPAddress();
    auto it = std::find(
        appToken.sourceAddresses.begin(),
        appToken.sourceAddresses.end(),
        currentPeerIP);

    if (it == appToken.sourceAddresses.end()) {
      // Current peer address not in the list, add it
      if (appToken.sourceAddresses.size() >= kMaxNumTokenSourceAddresses) {
        // Remove oldest address (front of list) to make room
        appToken.sourceAddresses.erase(appToken.sourceAddresses.begin());
      }
      appToken.sourceAddresses.push_back(currentPeerIP);
    } else if (it != appToken.sourceAddresses.end() - 1) {
      // Move current address to the end (most recent) if not already there
      appToken.sourceAddresses.erase(it);
      appToken.sourceAddresses.push_back(currentPeerIP);
    }

    // Keep connection state in sync with what was written to the session ticket
    serverConn_->tokenSourceAddresses = appToken.sourceAddresses;
    if (conn_->earlyDataAppParamsHandler) {
      appToken.appParams = conn_->earlyDataAppParamsHandler->get();
    }
    auto result =
        serverConn_->serverHandshakeLayer->writeNewSessionTicket(appToken);
    if (result.hasError()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

void QuicServerTransport::maybeNotifyConnectionIdRetired() {
  if (!conn_->transportSettings.disableMigration && routingCb_ &&
      !conn_->connIdsRetiringSoon->empty() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    for (const auto& connId : *conn_->connIdsRetiringSoon) {
      routingCb_->onConnectionIdRetired(*this, connId);
    }
    conn_->connIdsRetiringSoon->clear();
  }
}

void QuicServerTransport::maybeNotifyConnectionIdBound() {
  // make this connId bound only when the keys are available
  if (!notifiedConnIdBound_ && routingCb_ &&
      conn_->serverConnectionId.has_value() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    notifiedConnIdBound_ = true;
    routingCb_->onConnectionIdBound(shared_from_this());
  }
}

void QuicServerTransport::maybeNotifyHandshakeFinished() {
  if (serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    if (auto* handshakeCb = std::exchange(handshakeFinishedCb_, nullptr)) {
      handshakeCb->onHandshakeFinished();
    }
    if (connectionCallbacks_.setup() && !handshakeDoneNotified_) {
      connectionCallbacks_.setup()->onFullHandshakeDone();
      handshakeDoneNotified_ = true;
    }
  }
}

void QuicServerTransport::maybeIssueConnectionIds() {
  // If the peer specifies that they have a limit of 1,000,000 connection
  // ids then only issue a small number at first, since the server still
  // needs to be able to search through all issued ids for routing.
  const uint64_t maximumIdsToIssue = maximumConnectionIdsToIssue(*conn_);
  if (!conn_->transportSettings.disableMigration &&
      (conn_->selfConnectionIds.size() < maximumIdsToIssue) &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    PROTO_OOPS_LOG_BUILDER_IF(
        !conn_->transportSettings.statelessResetTokenSecret.has_value(),
        conn_->oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
        "quic_server_transport",
        "invariant_violation: stateless reset token secret is not set");
    MVCHECK(conn_->transportSettings.statelessResetTokenSecret.has_value());

    // Make sure size of selfConnectionIds is not larger than maximumIdsToIssue
    for (size_t i = conn_->selfConnectionIds.size(); i < maximumIdsToIssue;
         ++i) {
      auto newConnIdData = serverConn_->createAndAddNewSelfConnId();
      if (!newConnIdData.has_value()) {
        return;
      }

      PROTO_OOPS_LOG_BUILDER_IF(
          !routingCb_,
          conn_->oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
          "quic_server_transport",
          "invariant_violation: connection id available without routing "
          "callback");
      MVCHECK(routingCb_);
      routingCb_->onConnectionIdAvailable(
          shared_from_this(), newConnIdData->connId);

      NewConnectionIdFrame frame(
          newConnIdData->sequenceNumber,
          0,
          newConnIdData->connId,
          *newConnIdData->token);
      sendSimpleFrame(*conn_, std::move(frame));
    }
  }
}

void QuicServerTransport::maybeNotifyWriteCipherAvailable() {
  // The dual-phase callback flow (onWriteCipherAvailable() at write-cipher
  // availability + onTransportReady() retimed to the handshake milestone) is
  // enabled as a whole by retimeOnTransportReady. With retiming off we stay on
  // the legacy single-callback flow where onTransportReady() itself fires at
  // write-cipher availability, so onWriteCipherAvailable() is not delivered.
  if (serverConn_->transportSettings.retimeOnTransportReady &&
      !writeCipherAvailableNotified_ && connectionCallbacks_.setup() &&
      hasWriteCipher()) {
    writeCipherAvailableNotified_ = true;
    connectionCallbacks_.setup()->onWriteCipherAvailable();
  }
}

void QuicServerTransport::maybeNotifyTransportReady() {
  // One-shot: return before computing readiness (incl. the handshake-layer
  // checks below) once transport-ready has already fired, to avoid per-read
  // overhead on the post-handshake hot path.
  if (transportReadyNotified_ || !connectionCallbacks_.setup()) {
    return;
  }
  // When retiming is enabled, drive onTransportReady() from the Fizz handshake
  // report milestones; otherwise fall back to raw write-cipher availability.
  const bool ready = serverConn_->transportSettings.retimeOnTransportReady
      ? (serverConn_->serverHandshakeLayer
             ->hasReportedEarlyHandshakeSuccess() ||
         serverConn_->serverHandshakeLayer->hasReportedHandshakeSuccess())
      : hasWriteCipher();
  if (!ready) {
    return;
  }
  transportReadyNotified_ = true;
  connectionCallbacks_.setup()->onTransportReady();

  // This is a new connection. Update QUIC Stats
  QUIC_STATS(conn_->statsCallback, onNewConnection);
}

void QuicServerTransport::setShouldRegisterKnobParamHandlerFn(
    ShouldRegisterKnobParamHandlerFn fn) {
  shouldRegisterKnobParamHandlerFn_ = std::move(fn);
}

void QuicServerTransport::setQuicExperimentHandlerFn(
    QuicExperimentHandlerFn fn) {
  quicExperimentHandlerFn_ = std::move(fn);
}

void QuicServerTransport::registerTransportKnobParamHandler(
    uint64_t paramId,
    std::function<quic::Expected<void, QuicError>(
        QuicServerTransport&,
        TransportKnobParam::Val)>&& handler) {
  // No validation callback, allow all parameters
  if (!shouldRegisterKnobParamHandlerFn_) {
    transportKnobParamHandlers_.emplace(paramId, std::move(handler));
    return;
  }
  // Register based on validation callback
  if (TransportKnobParamId::_is_valid(paramId) &&
      shouldRegisterKnobParamHandlerFn_(
          TransportKnobParamId::_from_integral(paramId))) {
    transportKnobParamHandlers_.emplace(paramId, std::move(handler));
  }
}

void QuicServerTransport::setBufAccessor(BufAccessor* bufAccessor) {
  MVCHECK(bufAccessor);
  conn_->bufAccessor = bufAccessor;
}

const std::shared_ptr<const fizz::Cert>
QuicServerTransport::getPeerCertificate() const {
  const auto handshakeLayer = serverConn_->serverHandshakeLayer;
  if (handshakeLayer) {
    return handshakeLayer->getState().clientCert();
  }
  return nullptr;
}

const std::shared_ptr<const fizz::Cert>
QuicServerTransport::getSelfCertificate() const {
  const auto handshakeLayer = serverConn_->serverHandshakeLayer;
  if (handshakeLayer) {
    return handshakeLayer->getState().serverCert();
  }
  return nullptr;
}

void QuicServerTransport::onTransportKnobs(BufPtr knobBlob) {
  if (knobBlob->length() > 0) {
    auto serializedKnobs = knobBlob->to<std::string>();
    MVVLOG(4) << "Received transport knobs: " << serializedKnobs;
    auto params = parseTransportKnobs(serializedKnobs);
    if (params.has_value()) {
      handleTransportKnobParams(*params);
    } else {
      QUIC_STATS(
          conn_->statsCallback,
          onTransportKnobError,
          TransportKnobParamId::UNKNOWN);
    }
  }
}

void QuicServerTransport::verifiedClientAddress() {
  if (serverConn_) {
    serverConn_->isClientAddrVerified = true;
    conn_->writableBytesLimit.reset();
  }
}

void QuicServerTransport::registerAllTransportKnobParamHandlers() {
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        if (static_cast<bool>(std::get<uint64_t>(val))) {
          server_conn->udpSendPacketLen = server_conn->peerMaxUdpPayloadSize;
          MVVLOG(3)
              << "Knob param received, udpSendPacketLen is forcibly set to max UDP payload size advertised by peer";
        }
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto* strVal = std::get_if<std::string>(&val);
        if (!strVal) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "CC_ALGORITHM_KNOB: expected string value"));
        }
        auto maybeCctype = congestionControlStrToType(*strVal);
        if (!maybeCctype) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              fmt::format(
                  "Unknown congestion control algorithm: {}", *strVal)));
        }
        auto cctype = *maybeCctype;
        if (cctype == CongestionControlType::None ||
            cctype == CongestionControlType::StaticCwnd ||
            cctype == CongestionControlType::Custom) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              fmt::format(
                  "Unsupported congestion control algorithm: {}", *strVal)));
        }
        MVVLOG(3) << "Knob param received, set congestion control type to "
                  << congestionControlTypeToString(cctype);
        if (server_conn->congestionController &&
            cctype == server_conn->congestionController->type()) {
          return {};
        }
        serverTransport.setCongestionControl(cctype);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto val = std::get<uint64_t>(value);
        uint8_t numerator = (val / 100);
        uint8_t denominator = (val - (numerator * 100));
        MVVLOG(3) << "Knob param received, set STARTUP rtt factor to ("
                  << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.startupRttFactor =
            std::make_pair(numerator, denominator);
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto val = std::get<uint64_t>(value);
        auto numerator = (uint8_t)(val / 100);
        auto denominator = (uint8_t)(val - (numerator * 100));
        MVVLOG(3) << "Knob param received, set DEFAULT rtt factor to ("
                  << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.defaultRttFactor =
            std::make_pair(numerator, denominator);
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        // Safely check if value is a uint64_t
        const uint64_t* valPtr = std::get_if<uint64_t>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for MAX_PACING_RATE_KNOB KnobParam: expected uint64_t";
          MVVLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const uint64_t val = *valPtr;

        auto& maxPacingRateKnobState =
            serverTransport.serverConn_->maxPacingRateKnobState;
        if (maxPacingRateKnobState.frameOutOfOrderDetected) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB frame out of order detected"));
        }

        if (maxPacingRateKnobState.lastMaxRateBytesPerSec ==
                std::numeric_limits<uint64_t>::max() &&
            maxPacingRateKnobState.lastMaxRateBytesPerSec == val) {
          maxPacingRateKnobState.frameOutOfOrderDetected = true;
          QUIC_STATS(
              serverTransport.serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB);
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB frame out of order detected"));
        }

        MVVLOG(3) << "Knob param received, set max pacing rate to ("
                  << unsigned(val) << " bytes per second)";
        (void)serverTransport.setMaxPacingRate(val);
        maxPacingRateKnobState.lastMaxRateBytesPerSec = val;
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        // Safely check if value is a string
        const std::string* valPtr = std::get_if<std::string>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for MAX_PACING_RATE_KNOB_SEQUENCED KnobParam: expected string";
          MVVLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const std::string& val = *valPtr;
        std::string rateBytesPerSecStr, seqNumStr;
        if (!folly::split(',', val, rateBytesPerSecStr, seqNumStr)) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame value {} is not in expected format: "
              "{{rate}},{{sequenceNumber}}",
              val);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        auto maybeRateBytesPerSec = folly::tryTo<uint64_t>(rateBytesPerSecStr);
        if (maybeRateBytesPerSec.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid rate {}",
              rateBytesPerSecStr);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        auto expectedSeqNum = folly::tryTo<uint64_t>(seqNumStr);
        if (expectedSeqNum.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid sequence number {}",
              seqNumStr);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        if (serverTransport.serverConn_->maybeLastMaxPacingRateKnobSeqNum >=
            make_optional(expectedSeqNum.value())) {
          QUIC_STATS(
              serverTransport.serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received out of order"));
        }

        MVVLOG(3) << fmt::format(
            "MAX_PACING_RATE_KNOB_SEQUENCED frame received with rate {} bytes/sec "
            "and sequence number {}",
            maybeRateBytesPerSec.value(),
            expectedSeqNum.value());
        (void)serverTransport.setMaxPacingRate(maybeRateBytesPerSec.value());
        serverTransport.serverConn_->maybeLastMaxPacingRateKnobSeqNum =
            expectedSeqNum.value();
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::KEEPALIVE_ENABLED),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        MVVLOG(3) << "KEEPALIVE_ENABLED KnobParam received: " << val;
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.enableKeepalive = static_cast<bool>(val);
        if (val >= 5000) {
          server_conn->transportSettings.keepAliveTimeout =
              std::chrono::milliseconds(val);
        }
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACING_TIMER_TICK),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.pacingTickInterval =
            std::chrono::microseconds(val);
        MVVLOG(3) << "PACING_TIMER_TICK KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<std::string>(value);
        try {
          serverTransport.conn_->transportSettings.ccaConfig =
              parseCongestionControlConfig(val);
          MVVLOG(3) << "CC_CONFIG KnobParam received: " << val;
          return {};
        } catch (const std::exception& ex) {
          std::string errorMsg = fmt::format(
              "Failed to parse congestion control config: {}", ex.what());
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR, std::move(errorMsg)));
        }
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CONNECTION_MIGRATION),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto server_conn = serverTransport.serverConn_;
        // This intentionally lets the peer enable migration even if the server
        // disabled it: the knob exists so clients can control migration, and
        // the setting only affects this connection.
        server_conn->transportSettings.disableMigration =
            !static_cast<bool>(val);
        MVVLOG(3) << "CONNECTION_MIGRATION KnobParam received: "
                  << static_cast<bool>(val);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::KEY_UPDATE_INTERVAL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        if (val < 1000 || val > 8ul * 1000 * 1000) {
          std::string errMsg = fmt::format(
              "KEY_UPDATE_INTERVAL KnobParam received with invalid value: {}",
              val);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.initiateKeyUpdate = val > 0;
        server_conn->transportSettings.keyUpdatePacketCountInterval = val;
        MVVLOG(3) << "KEY_UPDATE_INTERVAL KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::AUTOTUNE_RECV_STREAM_FLOW_CONTROL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool autotuneReceiveStreamFlowControl =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.autotuneReceiveStreamFlowControl =
            autotuneReceiveStreamFlowControl;
        MVVLOG(3) << "AUTOTUNE_RECV_STREAM_FLOW_CONTROL KnobParam received: "
                  << autotuneReceiveStreamFlowControl;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACER_MIN_BURST_PACKETS),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.minBurstPackets =
            val <= kMinBurstPacketsLimit ? val : kMinBurstPacketsLimit;
        MVVLOG(3) << "PACER_MIN_BURST_PACKETS KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_WRITE_CONN_DATA_PKT_LIM),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.writeConnectionDataPacketsLimit =
            val <= kMaxWriteConnectionDataPacketLimit
            ? val
            : kMaxWriteConnectionDataPacketLimit;
        MVVLOG(3) << "MAX_WRITE_CONN_DATA_PKT_LIM KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MIN_STREAM_BUF_THRESH),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = static_cast<uint16_t>(std::get<uint64_t>(value));
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.minStreamBufThresh =
            val <= kMinStreamBufThreshLimit ? val : kMinStreamBufThreshLimit;
        MVVLOG(3) << "MIN_STREAM_BUF_THRESH KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::EXCESS_CWND_PCT_FOR_IMMINENT_STREAMS),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = static_cast<uint16_t>(std::get<uint64_t>(value));
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.excessCwndPctForImminentStreams =
            val <= kMaxExcessCwndPctForImminentStreams
            ? val
            : kMaxExcessCwndPctForImminentStreams;
        MVVLOG(3) << "EXCESS_CWND_PCT_FOR_IMMINENT_STREAMS KnobParam received: "
                  << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::SEND_CLOSE_ON_IDLE_TIMEOUT),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool sendCloseOnIdleTimeout =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.alwaysSendConnectionCloseOnIdleTimeout =
            sendCloseOnIdleTimeout;
        MVVLOG(3) << "SEND_CLOSE_ON_IDLE_TIMEOUT KnobParam received: "
                  << sendCloseOnIdleTimeout;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_PTO),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto maxPTOCount = std::get<uint64_t>(value);
        if (maxPTOCount < 3 || maxPTOCount > 15) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PTO KnobParam value out of bounds"));
        }
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.maxNumPTOs = maxPTOCount;
        MVVLOG(3) << "MAX_PTO KnobParam received: " << maxPTOCount;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::ADAPTIVE_LOSS_REORDERING_THRESHOLDS),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        const auto* val = std::get_if<uint64_t>(&value);
        if (!val || *val > 1) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "ADAPTIVE_LOSS_REORDERING_THRESHOLDS KnobParam expects 0 or 1"));
        }
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.useAdaptiveLossReorderingThresholds =
            *val == 1;
        MVVLOG(3) << "ADAPTIVE_LOSS_REORDERING_THRESHOLDS KnobParam received: "
                  << *val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::SCONE_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        const uint64_t* valPtr = std::get_if<uint64_t>(&value);
        if (!valPtr) {
          return quic::make_unexpected(QuicError(
              QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
              "SCONE_KNOB: Expected uint64_t value"));
        }
        auto& conn = *serverTransport.conn_;
        uint64_t bps = *valPtr;
        uint8_t rateSignal = bpsToSconeRateSignal(bps);
        conn.transportSettings.enableSconeSend = true;
        if (!conn.scone) {
          conn.scone.emplace();
        }
        conn.scone->configuredRateSignal = rateSignal;
        // Reset the send timer so a SCONE packet is sent with the very next
        // outgoing packet, reflecting the new rate signal immediately.
        conn.scone->lastSconeSentTime.reset();
        VLOG(3) << "SCONE_KNOB: Enabled SCONE send with rate signal "
                << static_cast<int>(rateSignal) << " from " << bps << " bps";
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::RX_PACKETS_BEFORE_ACK),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        const std::string* valPtr = std::get_if<std::string>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for RX_PACKETS_BEFORE_ACK KnobParam: expected string";
          MVVLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const std::string& val = *valPtr;
        uint16_t beforeInit = 0;
        uint16_t afterInit = 0;
        bool parseSuccess = false;
        try {
          parseSuccess = folly::split(',', val, beforeInit, afterInit);
          parseSuccess = parseSuccess && beforeInit >= 2 && afterInit >= 2;
        } catch (std::exception&) {
          parseSuccess = false;
        }
        if (parseSuccess) {
          MVVLOG(3) << fmt::format(
              "RX_PACKETS_BEFORE_ACK KnobParam received, "
              "beforeInit={}, afterInit={}",
              beforeInit,
              afterInit);
          auto serverConn = serverTransport.serverConn_;
          serverConn->transportSettings.rxPacketsBeforeAckBeforeInit =
              beforeInit;
          serverConn->transportSettings.rxPacketsBeforeAckAfterInit = afterInit;
        } else {
          auto errMsg = fmt::format(
              "Received invalid KnobParam for RX_PACKETS_BEFORE_ACK: {}", val);
          MVVLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }
        return {};
      });
}

QuicConnectionStats QuicServerTransport::getConnectionsStats() const {
  QuicConnectionStats connStats = QuicTransportBase::getConnectionsStats();
  if (serverConn_) {
    connStats.localAddress = serverConn_->serverAddr;
  }
  return connStats;
}

CipherInfo QuicServerTransport::getOneRttCipherInfo() const {
  return {
      .trafficKey = *conn_->oneRttWriteCipher->getKey(),
      .cipherSuite = *serverConn_->serverHandshakeLayer->getState().cipher(),
      .packetProtectionKey = conn_->oneRttWriteHeaderCipher->getKey()->clone()};
}

Optional<std::string> QuicServerTransport::getSni() {
  auto logging =
      serverConn_->serverHandshakeLayer->getState().handshakeLogging();
  if (!logging || !logging->clientSni.has_value()) {
    return std::nullopt;
  }

  return logging->clientSni.value();
}

void QuicServerTransport::logTimeBasedStats() const {
  if (!conn_ || !conn_->statsCallback) {
    return;
  }
  // Ignore 0 inflight bytes samples for now to not affect sampling.
  if (conn_->lossState.inflightBytes > 0) {
    QUIC_STATS(
        conn_->statsCallback,
        onInflightBytesSample,
        conn_->lossState.inflightBytes);
  }
  // Only consider RTT sample if handshake is done.
  if (serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    QUIC_STATS(
        conn_->statsCallback,
        onRttSample,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            conn_->lossState.srtt)
            .count());
  }
  if (conn_->congestionController) {
    // We only log the bandwidth if it's available and the units are bytes/s.
    auto bandwidth = conn_->congestionController->getBandwidth();
    if (bandwidth.has_value() &&
        bandwidth->unitType == Bandwidth::UnitType::BYTES) {
      uint64_t bitsPerSecSample = bandwidth->normalize() * 8;
      QUIC_STATS(conn_->statsCallback, onBandwidthSample, bitsPerSecSample);
    }
  }
}

Optional<std::vector<TransportParameter>>
QuicServerTransport::getPeerTransportParams() const {
  if (serverConn_ && serverConn_->serverHandshakeLayer) {
    auto maybeParams =
        serverConn_->serverHandshakeLayer->getClientTransportParams();
    if (maybeParams) {
      return maybeParams->parameters;
    }
  }
  return std::nullopt;
}

void QuicServerTransport::setCongestionControl(CongestionControlType type) {
  if (!conn_->congestionControllerFactory) {
    // If you are hitting this, update your application to call
    // setCongestionControllerFactory() on the transport to share one factory
    // for all transports.
    conn_->congestionControllerFactory =
        std::make_shared<ServerCongestionControllerFactory>();
    MVLOG_WARNING
        << "A congestion controller factory is not set. Using a default per-transport instance.";
  }
  QuicTransportBase::setCongestionControl(type);
}

void QuicServerTransport::onPathValidationResult(const PathInfo& pathInfo) {
  // NOLINTBEGIN
  /*
   * There are four cases to handle in the result of path validation:
   *
   *                    Path Validation Result
   *                              |
   *              +---------------+---------------+
   *              |                               |
   *         Path Valid                    Path NotValid
   *              |                               |
   *    +---------+---------+           +---------+--------+
   *    |                   |           |                  |
   *   (1)                 (2)         (3)                (4)
   * Current Path      Probing Path   Current Path   Probing Path
   *    |                   |           |                  |
   *    v                   v           v                  |
   * Remove            Remove after   Switch to            |
   * fallback          grace period   fallback             |
   * path              if client      path OR              |
   *                   doesn't        close conn           |
   *                   switch              |               |
   *                                       +-------+-------+
   *                                               |
   *                                               v
   *                                          Remove path
   */
  // NOLINTEND

  auto removeIfNotCurrentFunc = [conn = shared_from_this()](
                                    PathIdType pathToRemove,
                                    const std::string& pathType) {
    if (conn->conn_->currentPathId == pathToRemove) {
      return;
    }
    auto removePathRes = conn->conn_->pathManager->removePath(pathToRemove);
    if (removePathRes.hasError()) {
      // This is best effort since the path could have already been reaped.
      MVVLOG(4) << "Removing " + pathType + " path error: "
                << removePathRes.error();
    }
  };

  if (pathInfo.status == PathStatus::Validated) {
    QUIC_STATS(conn_->statsCallback, onPathValidationSuccess);
    if (pathInfo.id == conn_->currentPathId) {
      // Case (1): Validated Current Path
      // remove the fallback path if it exists
      if (conn_->fallbackPathId) {
        runOnEvbAsync([conn = shared_from_this(),
                       pathId = conn_->fallbackPathId.value(),
                       removeFunc = std::move(removeIfNotCurrentFunc),
                       type = "fallback"](auto) {
          removeFunc(pathId, type);
          if (conn->conn_->fallbackPathId.has_value() &&
              conn->conn_->fallbackPathId.value() == pathId) {
            conn->conn_->fallbackPathId.reset();
          }
        });
      }
    } else {
      // Case (2): Validated Probe Path
      // remove it after the grace period if the client hasn't
      // migrated to it.
      auto gracePeriod = kProbedPathGracePeriodInSRTT *
          std::chrono::ceil<std::chrono::milliseconds>(conn_->lossState.srtt)
              .count();
      evb_->runAfterDelay(
          [pathId = pathInfo.id,
           removeFunc = std::move(removeIfNotCurrentFunc),
           type = "unused validated probe"]() { removeFunc(pathId, type); },
          gracePeriod);
    }
  } else {
    QUIC_STATS(conn_->statsCallback, onPathValidationFailure);
    if (pathInfo.id == conn_->currentPathId) {
      // Case (3): Invalid Current Path
      // We should fallback to the previously validated path or close the
      // connection if we don't have one.

      // Increment consecutive migration failure counter
      ++serverConn_->consecutiveMigrationFailures;

      // Close connection if we've exceeded the limit
      if (serverConn_->consecutiveMigrationFailures >=
          kMaxConsecutiveMigrationFailures) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
            std::string("Too many consecutive migration failures")));
        return;
      }

      // This will reverse what ServerStateMachine::onConnectionMigration()
      // did. The reason it's here is that we want to be able to close the
      // connection, which is only possible from the transport.
      auto migrationReverted = false;
      if (conn_->fallbackPathId) {
        auto fallbackPath = conn_->pathManager->getPath(*conn_->fallbackPathId);
        conn_->fallbackPathId.reset();
        if (fallbackPath) {
          auto switchPathRes =
              conn_->pathManager->switchCurrentPath(fallbackPath->id);
          if (switchPathRes.hasError()) {
            MVLOG_WARNING << "Failed to switch to fallback path: "
                          << switchPathRes.error();
          } else {
            auto ccaRestored =
                conn_->pathManager
                    ->maybeRestoreCongestionControlAndRttStateForCurrentPath();
            if (!ccaRestored) {
              conn_->congestionController =
                  conn_->congestionControllerFactory->makeCongestionController(
                      *conn_,
                      conn_->transportSettings.defaultCongestionController);
            }
            conn_->fallbackPathId.reset();
            migrationReverted = true;
            // Schedule ping to confirm client is on fallback path
            conn_->pendingEvents.sendPing = true;
          }
        }
      }
      if (!migrationReverted) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
            std::string(
                "Path validation timed out. No fallback path available")));
      }
    }

    // Remove path for cases (3) and (4)
    if (closeState_ == CloseState::OPEN) {
      runOnEvbAsync(
          [pathId = pathInfo.id,
           removeFunc = std::move(removeIfNotCurrentFunc),
           type = "failed probe"](auto) { removeFunc(pathId, type); });
    }
  }
}

} // namespace quic
