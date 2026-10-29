/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/congestion_control/PacerFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/observer/SocketObserverMacros.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/stream/StreamStateFunctions.h>
#include <chrono>
#include <cmath>
#include <limits>

#include <folly/ScopeGuard.h>
#include <folly/lang/CheckedMath.h>

#include <sstream>

namespace {
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;

quic::QuicError maybeSetGenericAppError(
    quic::Optional<quic::QuicError>&& error) {
  return std::move(error).value_or(
      quic::QuicError{APP_NO_ERROR, quic::toString(APP_NO_ERROR)});
}

// Formats the stream-scheduler state for the temporary STREAM/NoFrame
// empty-write-loop diagnostic OOPS. Includes the head writable stream (control
// queue first, then the priority write queue) so the offending stream's state
// is captured, not just aggregate counts.
// TODO(jbeshay): remove together with the diagnostic OOPS
[[maybe_unused]] std::string formatStreamNoFrameLoopDiag(
    quic::QuicConnectionStateBase& conn,
    uint64_t emptyLoops) {
  auto& sm = *conn.streamManager;
  const quic::QuicStreamState* head = nullptr;
  quic::StreamId headId = 0;
  bool haveHead = false;
  if (!sm.controlWriteQueue().empty()) {
    headId = *sm.controlWriteQueue().begin();
    haveHead = true;
    head = sm.findStream(headId);
  } else if (!sm.writeQueue().empty()) {
    auto id = sm.writeQueue().peekNextScheduledID();
    if (id.isStreamID()) {
      headId = id.asStreamID();
      haveHead = true;
      head = sm.findStream(headId);
    }
  }
  std::string headPart = "none";
  if (head != nullptr) {
    headPart = fmt::format(
        "id={} ctrl={} hasWritable={} hasWritableNoFc={} hasLoss={} pending={} streamFc={} writeErr={} sendState={}",
        headId,
        head->isControl,
        head->hasWritableData(true),
        head->hasWritableData(false),
        head->hasLoss(),
        head->pendingWriteBytes(),
        head->flowControlState.peerAdvertisedMaxOffset >=
                head->nextOffsetToWrite()
            ? head->flowControlState.peerAdvertisedMaxOffset -
                head->nextOffsetToWrite()
            : 0,
        head->streamWriteError.has_value(),
        static_cast<int>(head->sendState));
  } else if (haveHead) {
    headPart = fmt::format("id={} missing", headId);
  }
  return fmt::format(
      "stream_noframe_empty_write_loop hasLoss={} wqEmpty={} cwqSz={} connFC={} cwnd={} loops={} head=[{}]",
      sm.hasLoss(),
      sm.writeQueue().empty(),
      sm.controlWriteQueue().size(),
      quic::getSendConnFlowControlBytesWire(conn),
      conn.congestionController ? conn.congestionController->getWritableBytes()
                                : std::numeric_limits<uint64_t>::max(),
      emptyLoops,
      headPart);
}
} // namespace

namespace quic {

inline std::ostream& operator<<(
    std::ostream& os,
    const CloseState& closeState) {
  switch (closeState) {
    case CloseState::OPEN:
      os << "OPEN";
      break;
    case CloseState::GRACEFUL_CLOSING:
      os << "GRACEFUL_CLOSING";
      break;
    case CloseState::CLOSED:
      os << "CLOSED";
      break;
  }
  return os;
}

std::ostream& operator<<(std::ostream& out, const LooperType& rhs) {
  switch (rhs) {
    case LooperType::ReadLooper:
      out << "ReadLooper";
      break;
    case LooperType::PeekLooper:
      out << "PeekLooper";
      break;
    case LooperType::WriteLooper:
      out << "WriteLooper";
      break;
    default:
      out << "unknown";
      break;
  }
  return out;
}

using namespace std::chrono_literals;

// TransportLooper implementation

QuicTransportBaseLite::TransportLooper::TransportLooper(
    std::shared_ptr<QuicEventBase> evb,
    QuicTransportBaseLite* transport,
    LooperType type)
    : evb_(std::move(evb)),
      transport_(transport),
      type_(type),
      running_(false),
      inLoopBody_(false),
      fireLoopEarly_(false),
      hasPacingCallback_(false) {
  DCHECK(transport_);
}

void QuicTransportBaseLite::TransportLooper::setPacingTimer(
    QuicTimer::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

void QuicTransportBaseLite::TransportLooper::enablePacingCallback() noexcept {
  hasPacingCallback_ = true;
}

void QuicTransportBaseLite::TransportLooper::commonLoopBody() noexcept {
  inLoopBody_ = true;
  SCOPE_EXIT {
    inLoopBody_ = false;
  };
  auto hasBeenRunning = running_;
  transport_->onLooperCallback(type_);
  // callback could cause us to stop ourselves.
  // Someone could have also called run() in the callback.
  MVVLOG(10) << __func__ << ": " << type_
             << " hasBeenRunning=" << hasBeenRunning
             << " running_=" << running_;
  if (!running_) {
    return;
  }
  if (!schedulePacingTimeout()) {
    evb_->runInLoop(this);
  }
}

bool QuicTransportBaseLite::TransportLooper::schedulePacingTimeout() noexcept {
  if (hasPacingCallback_ && (pacingTimer_ || evb_) &&
      !isTimerCallbackScheduled()) {
    auto timeUntilWrite = transport_->getLooperPacingDelay();
    if (timeUntilWrite != 0us) {
      nextPacingTime_ = Clock::now() + timeUntilWrite;
      if (pacingTimer_) {
        pacingTimer_->scheduleTimeout(this, timeUntilWrite);
        return true;
      }
      if (evb_) {
        evb_->scheduleTimeoutHighRes(this, timeUntilWrite);
        return true;
      }
    }
  }
  return false;
}

void QuicTransportBaseLite::TransportLooper::runLoopCallback() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody();
}

void QuicTransportBaseLite::TransportLooper::run(bool thisIteration) noexcept {
  MVVLOG(10) << __func__ << ": " << type_;
  running_ = true;
  // Caller can call run() in the callback. But if we are in pacing mode, we
  // should prevent such loop.
  if ((pacingTimer_ || hasPacingCallback_) && inLoopBody_) {
    MVVLOG(4) << __func__ << ": " << type_
              << " in loop body and using pacing - not rescheduling";
    return;
  }
  if (isLoopCallbackScheduled() ||
      (!fireLoopEarly_ && hasPacingCallback_ && isTimerCallbackScheduled())) {
    MVVLOG(10) << __func__ << ": " << type_ << " already scheduled";
    return;
  }
  // If we are pacing, we're about to write again, if it's close, just write
  // now.
  if (hasPacingCallback_ && isTimerCallbackScheduled()) {
    auto n = Clock::now();
    auto timeUntilWrite = nextPacingTime_ < n
        ? 0us
        : std::chrono::duration_cast<std::chrono::milliseconds>(
              nextPacingTime_ - n);
    if (timeUntilWrite <= 1ms) {
      cancelTimerCallback();
      // The next loop is good enough
      thisIteration = false;
    } else {
      return;
    }
  }
  evb_->runInLoop(this, thisIteration);
}

void QuicTransportBaseLite::TransportLooper::stop() noexcept {
  MVVLOG(10) << __func__ << ": " << type_;
  running_ = false;
  if (evb_) {
    cancelLoopCallback();
  }
  cancelTimerCallback();
}

bool QuicTransportBaseLite::TransportLooper::isRunning() const {
  return running_;
}

bool QuicTransportBaseLite::TransportLooper::isPacingScheduled() {
  return hasPacingCallback_ && isTimerCallbackScheduled();
}

bool QuicTransportBaseLite::TransportLooper::isLoopCallbackScheduled() {
  return QuicEventBaseLoopCallback::isLoopCallbackScheduled();
}

void QuicTransportBaseLite::TransportLooper::attachEventBase(
    std::shared_ptr<QuicEventBase> evb) {
  MVVLOG(10) << __func__ << ": " << type_;
  DCHECK(!evb_);
  DCHECK(evb && evb->isInEventBaseThread());
  evb_ = std::move(evb);
}

void QuicTransportBaseLite::TransportLooper::detachEventBase() {
  MVVLOG(10) << __func__ << ": " << type_;
  DCHECK(evb_ && evb_->isInEventBaseThread());
  stop();
  cancelTimerCallback();
  evb_ = nullptr;
}

void QuicTransportBaseLite::TransportLooper::timeoutExpired() noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  commonLoopBody();
}

void QuicTransportBaseLite::TransportLooper::callbackCanceled() noexcept {
  return;
}

OptionalMicros
QuicTransportBaseLite::TransportLooper::getTimerTickInterval() noexcept {
  if (pacingTimer_) {
    return pacingTimer_->getTickInterval();
  }
  return std::nullopt;
}

QuicTransportBaseLite::QuicTransportBaseLite(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    bool useConnectionEndWithErrorCallback)
    : evb_(std::move(evb)),
      socket_(std::move(socket)),
      useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback),
      lossTimeout_(this),
      excessWriteTimeout_(this),
      idleTimeout_(this),
      keepaliveTimeout_(this),
      ackTimeout_(this),
      pathValidationTimeout_(this),
      drainTimeout_(this),
      writeLooper_(new TransportLooper(evb_, this, LooperType::WriteLooper)),
      readLooper_(new TransportLooper(evb_, this, LooperType::ReadLooper)) {}

QuicTransportBaseLite::~QuicTransportBaseLite() {
  connectionCallbacks_.onTransportDestroyed();
  cancelTimeout(&drainTimeout_);

  // closeImpl and closeUdpSocket should have been triggered by destructor of
  // derived class to ensure that observers are properly notified
  MVDCHECK_NE(CloseState::OPEN, closeState_);
  MVDCHECK(!socket_.get()); // should be no socket
}

void QuicTransportBaseLite::onLooperCallback(LooperType type) {
  switch (type) {
    case LooperType::WriteLooper:
      pacedWriteDataToSocket();
      break;
    case LooperType::ReadLooper:
      invokeReadDataAndCallbacks(true);
      break;
    case LooperType::PeekLooper:
      invokePeekDataAndCallbacks();
      break;
  }
}

std::chrono::microseconds QuicTransportBaseLite::getLooperPacingDelay() {
  if (isConnectionPaced(*conn_)) {
    return conn_->pacer->getTimeUntilNextWrite();
  }
  return std::chrono::microseconds::zero();
}

void QuicTransportBaseLite::onNetworkData(
    const quic::SocketAddress& localAddress,
    NetworkData&& networkData) noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    if (!conn_->transportSettings.networkDataPerSocketRead) {
      checkForClosedStream();
      updateReadLooper();
      updatePeekLooper();
      updateWriteLooper(true);
    }
  };
  try {
    for (const auto& pp : conn_->packetProcessors) {
      pp->preread();
    }
    SCOPE_EXIT {
      for (const auto& pp : conn_->packetProcessors) {
        pp->postread();
      }
    };

    conn_->lossState.totalBytesRecvd += networkData.getTotalData();
    auto originalAckVersion = currentAckStateVersion(*conn_);

    // handle PacketsReceivedEvent if requested by observers
    SOCKET_OBSERVER_IF(
        getSocketObserverContainer(),
        SocketObserverInterface::Events::packetsReceivedEvents) {
      auto builder = SocketObserverInterface::PacketsReceivedEvent::Builder()
                         .setReceiveLoopTime(TimePoint::clock::now())
                         .setNumPacketsReceived(networkData.getPackets().size())
                         .setNumBytesReceived(networkData.getTotalData());
      for (auto& packet : networkData.getPackets()) {
        auto receivedUdpPacketBuilder =
            SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::
                Builder()
                    .setPacketReceiveTime(packet.timings.receiveTimePoint)
                    .setPacketNumBytes(packet.buf.chainLength())
                    .setPacketTos(packet.tosValue);
        if (packet.timings.maybeSoftwareTs) {
          receivedUdpPacketBuilder.setPacketSoftwareRxTimestamp(
              packet.timings.maybeSoftwareTs->systemClock.raw);
        }
        builder.addReceivedUdpPacket(
            std::move(receivedUdpPacketBuilder).build());
      }

      getSocketObserverContainer()
          ->invokeInterfaceMethod<
              SocketObserverInterface::Events::packetsReceivedEvents>(
              [event = std::move(builder).build()](
                  auto observer, auto observed) {
                observer->packetsReceived(observed, event);
              });
    }

    auto packets = std::move(networkData).movePackets();
    for (auto& packet : packets) {
      if (!conn_->initialPeerTtl.has_value()) {
        conn_->initialPeerTtl = packet.ttlValue;
      }
      for (const auto& pp : conn_->packetProcessors) {
        pp->onPacketRead(packet);
      }
      auto res = onReadData(localAddress, std::move(packet));
      if (!res.has_value()) {
        MVVLOG(4) << __func__ << " " << res.error().message << " " << *this;
        exceptionCloseWhat_ = res.error().message;
        return closeImpl(res.error());
      }
      if (conn_->peerConnectionError) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::NO_ERROR), "Peer closed"));
        return;
      }
    }

    if (!conn_->transportSettings.networkDataPerSocketRead) {
      processCallbacksAfterNetworkData();
    }
    if (closeState_ != CloseState::CLOSED) {
      if (currentAckStateVersion(*conn_) != originalAckVersion) {
        setIdleTimer();
        conn_->receivedNewPacketBeforeWrite = true;
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::READ_OK;
          conn_->readDebugState.loopCount = 0;
        }
      }
      // Reading data could process an ack and change the loss timer.
      setLossDetectionAlarm(*conn_, *self);
      // Reading data could change the state of the acks which could change
      // the ack timer. But we need to call scheduleAckTimeout() for it to
      // take effect.
      scheduleAckTimeout();
      // Received data could contain valid path response, in which case
      // path validation timeout should be canceled
      schedulePathValidationTimeout();

      // If ECN is enabled, make sure that the packet marking is happening as
      // expected
      auto ecnResult = validateECNState();
      if (!ecnResult.has_value()) {
        MVVLOG(4) << __func__ << " " << ecnResult.error().message << " "
                  << *this;
        exceptionCloseWhat_ = ecnResult.error().message;
        closeImpl(ecnResult.error());
      }
    } else {
      // In the closed state, we would want to write a close if possible
      // however the write looper will not be set.
      auto result = writeSocketData();
      if (!result.has_value()) {
        MVVLOG(4) << __func__ << " " << result.error().message << " " << *this;
        exceptionCloseWhat_ = result.error().message;
        closeImpl(result.error());
      }
    }
  } catch (const std::exception& ex) {
    handleExceptionAndClose(ex, "error onNetworkData()");
    return;
  }
}

void QuicTransportBaseLite::close(Optional<QuicError> errorCode) {
  // As in closeGracefully(), there is nothing to do once the connection is
  // closed. Returning before the guard also lets a connection callback run by
  // the destructor call this, since shared_from_this() fails at that point.
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  [[maybe_unused]] auto self = sharedGuard();
  onApplicationClose();

  // If we were called with no error code, ensure that we are going to write
  // an application close, so the peer knows it didn't come from the transport.
  errorCode = maybeSetGenericAppError(std::move(errorCode));
  closeImpl(std::move(errorCode), true);
}

void QuicTransportBaseLite::closeNow(Optional<QuicError> errorCode) {
  MVDCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  // As in closeGracefully(), there is nothing to do once the connection is
  // closed and drained. Returning before the guard also lets a connection
  // callback run by the destructor call this, since shared_from_this() fails
  // at that point.
  if (closeState_ == CloseState::CLOSED &&
      !isTimeoutScheduled(&drainTimeout_)) {
    return;
  }
  [[maybe_unused]] auto self = sharedGuard();
  MVVLOG(4) << __func__ << " " << *this;
  errorCode = maybeSetGenericAppError(std::move(errorCode));
  closeImpl(std::move(errorCode), false);
  // the drain timeout may have been scheduled by a previous close, in which
  // case, our close would not take effect. This cancels the drain timeout in
  // this case and expires the timeout.
  if (isTimeoutScheduled(&drainTimeout_)) {
    cancelTimeout(&drainTimeout_);
    drainTimeoutExpired();
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::stopSending(
    StreamId id,
    ApplicationErrorCode error) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (stream->recvState == StreamRecvState::Closed) {
    // skip STOP_SENDING if ingress is already closed
    return {};
  }
  processTxStopSending(*stream);
  if (stream->stopSendingRequested && stream->reliableSizeFromPeer) {
    // The reliable bytes of a pending reliable reset are now dropped, so close
    // the receive side.
    auto closeResult = maybeCloseRetiredIngress(*stream);
    if (!closeResult.has_value()) {
      closeImpl(QuicError(
          closeResult.error().code, std::string("stopSending() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }
    updateReadLooper();
  }
  // send STOP_SENDING frame to peer
  sendSimpleFrame(*conn_, StopSendingFrame(id, error));
  updateWriteLooper(true);
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::stopSendingAndDropIngress(
    StreamId id,
    ApplicationErrorCode error) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (stream->ingressRetired) {
    return {};
  }
  // Even when the final size is already known, STOP_SENDING lets the peer
  // stop retransmitting data we would only discard.
  const bool sendStopSending = stream->recvState == StreamRecvState::Open;
  auto retireResult = retireIngress(*stream);
  if (!retireResult.has_value()) {
    MVVLOG(4) << __func__ << " streamId=" << id << " "
              << retireResult.error().message << " " << *this;
    exceptionCloseWhat_ = retireResult.error().message;
    closeImpl(QuicError(
        retireResult.error().code,
        std::string("stopSendingAndDropIngress() error")));
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  }
  if (sendStopSending) {
    sendSimpleFrame(*conn_, StopSendingFrame(id, error));
  }
  updateWriteLooper(true);
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::stopSendingAndDropIngressForAllStreams(
    ApplicationErrorCode error) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  const auto streamIds = conn_->streamManager->openReceiveStreamIds();

  Optional<LocalErrorCode> firstError;
  for (const auto id : streamIds) {
    auto result = stopSendingAndDropIngress(id, error);
    if (result.hasError() && !firstError.has_value()) {
      firstError = result.error();
    }
  }
  // A failure above closes the connection, which ends every stream, so there
  // is nothing left to retire.
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(
        firstError.value_or(LocalErrorCode::CONNECTION_CLOSED));
  }
  // A peer stream that is not open yet, including one whose packet is already
  // waiting to be processed, is retired as soon as its state is created, before
  // any of its frames is applied.
  conn_->streamManager->retireIngressOfNewPeerStreams(error);
  if (firstError.has_value()) {
    return quic::make_unexpected(*firstError);
  }
  return {};
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createBidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(true);
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createUnidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(false);
}

uint64_t QuicTransportBaseLite::getNumOpenableBidirectionalStreams() const {
  return good() ? conn_->streamManager->openableLocalBidirectionalStreams() : 0;
}

uint64_t QuicTransportBaseLite::getNumOpenableUnidirectionalStreams() const {
  return good() ? conn_->streamManager->openableLocalUnidirectionalStreams()
                : 0;
}

QuicSocketLite::WriteResult QuicTransportBaseLite::writeChain(
    StreamId id,
    BufPtr data,
    bool eof,
    ByteEventCallback* cb) {
  if (conn_->version == QuicVersion::MVFST_PRIMING &&
      isBidirectionalStream(id)) {
    // Once data is available to write on a stream,
    // the Priming connection can be closed
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::NO_ERROR),
        std::string("no error: priming connection closed")));
    return quic::make_unexpected(LocalErrorCode::NO_ERROR);
  }

  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  try {
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    if (!stream->writable()) {
      return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
    }
    // Register DeliveryCallback for the data + eof offset.
    if (cb) {
      auto dataLength =
          (data ? data->computeChainDataLength() : 0) + (eof ? 1 : 0);
      if (dataLength) {
        auto currentLargestWriteOffset = getLargestWriteOffsetSeen(*stream);
        auto deliveryResult = registerDeliveryCallback(
            id, currentLargestWriteOffset + dataLength - 1, cb);
        if (!deliveryResult.has_value()) {
          MVVLOG(4) << "Failed to register delivery callback: "
                    << toString(deliveryResult.error());
          exceptionCloseWhat_ = "Failed to register delivery callback";
          closeImpl(QuicError(
              deliveryResult.error(),
              std::string("registerDeliveryCallback() error")));
          return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
        }
      }
    }
    bool wasAppLimitedOrIdle = false;
    if (conn_->congestionController) {
      wasAppLimitedOrIdle = conn_->congestionController->isAppLimited();
      wasAppLimitedOrIdle |= conn_->streamManager->isAppIdle();
    }
    auto result = writeDataToQuicStream(*stream, std::move(data), eof);
    if (!result.has_value()) {
      MVVLOG(4) << __func__ << " streamId=" << id << " "
                << result.error().message << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(
          QuicError(result.error().code, std::string("writeChain() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }
    // If we were previously app limited restart pacing with the current rate.
    if (wasAppLimitedOrIdle && conn_->pacer) {
      conn_->pacer->reset();
    }
    updateWriteLooper(true);
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        handleExceptionAndClose(ex, "writeChain() error", id));
  }
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::registerDeliveryCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::ACK, id, offset, cb);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::notifyPendingWriteOnConnection(
    ConnectionWriteCallback* wcb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (connWriteCallback_ != nullptr) {
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Assign the write callback before going into the loop so that if we close
  // the connection while we are still scheduled, the write callback will get
  // an error synchronously.
  connWriteCallback_ = wcb;
  runOnEvbAsyncOp({.type = AsyncOpType::ConnectionWriteReady});
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::unregisterStreamWriteCallback(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (pendingWriteCallbacks_.find(id) == pendingWriteCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  pendingWriteCallbacks_.erase(id);
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resetStream(
    StreamId id,
    ApplicationErrorCode errorCode) {
  return resetStreamInternal(id, errorCode, false /* reliable */);
}

void QuicTransportBaseLite::cancelDeliveryCallbacksForStream(StreamId id) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id);
}

void QuicTransportBaseLite::cancelDeliveryCallbacksForStream(
    StreamId id,
    uint64_t offset) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id, offset);
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStream(
    const StreamId id,
    const Optional<uint64_t>& offsetUpperBound) {
  invokeForEachByteEventType(
      ([this, id, &offsetUpperBound](const ByteEvent::Type type) {
        cancelByteEventCallbacksForStream(type, id, offsetUpperBound);
      }));
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStream(
    const ByteEvent::Type type,
    const StreamId id,
    const Optional<uint64_t>& offsetUpperBound) {
  cancelByteEventCallbacksForStreamInternal(
      type, id, [&offsetUpperBound](uint64_t cbOffset) {
        return !offsetUpperBound || cbOffset < *offsetUpperBound;
      });
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::notifyPendingWriteOnStream(
    StreamId id,
    StreamWriteCallback* wcb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (!stream->writable()) {
    return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
  }

  if (wcb == nullptr) {
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Add the callback to the pending write callbacks so that if we are closed
  // while we are scheduled in the loop, the close will error out the
  // callbacks.
  auto wcbEmplaceResult = pendingWriteCallbacks_.emplace(id, wcb);
  if (!wcbEmplaceResult.second) {
    if ((wcbEmplaceResult.first)->second != wcb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
    } else {
      return quic::make_unexpected(LocalErrorCode::CALLBACK_ALREADY_INSTALLED);
    }
  }
  runOnEvbAsyncOp({.type = AsyncOpType::StreamWriteReady, .streamId = id});
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::registerByteEventCallback(
    const ByteEvent::Type type,
    const StreamId id,
    const uint64_t offset,
    ByteEventCallback* cb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (!cb) {
    return {};
  }

  ByteEventMap& byteEventMap = getByteEventMap(type);
  auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    byteEventMap.emplace(
        id,
        std::initializer_list<std::remove_reference<
            decltype(byteEventMap)>::type::mapped_type::value_type>(
            {{offset, cb}}));
  } else {
    // Optimize for the common case: offset is larger than any existing offset.
    auto& events = byteEventMapIt->second;
    if (events.empty() || offset > events.back().offset) {
      // Fast path: just append to the end.
      events.emplace_back(offset, cb);
    } else {
      // Keep ByteEvents for the same stream sorted by offsets:
      auto pos = std::upper_bound(
          events.begin(),
          events.end(),
          offset,
          [&](uint64_t o, const ByteEventDetail& p) { return o < p.offset; });
      if (pos != events.begin()) {
        auto matchingEvent = std::find_if(
            events.begin(), pos, [offset, cb](const ByteEventDetail& p) {
              return ((p.offset == offset) && (p.callback == cb));
            });
        if (matchingEvent != pos) {
          // ByteEvent has been already registered for the same type, id,
          // offset and for the same recipient, return an INVALID_OPERATION
          // error to prevent duplicate registrations.
          return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
        }
      }
      events.emplace(pos, offset, cb);
    }
  }

  // Notify recipients that the registration was successful.
  cb->onByteEventRegistered(ByteEvent{id, offset, type});

  // if the callback is already ready, we still insert, but schedule to
  // process
  Optional<uint64_t> maxOffsetReady;
  switch (type) {
    case ByteEvent::Type::ACK:
      maxOffsetReady = getLargestDeliverableOffset(*stream);
      break;
    case ByteEvent::Type::TX:
      maxOffsetReady = getLargestWriteOffsetTxed(*stream);
      break;
  }
  if (maxOffsetReady.has_value() && (offset <= *maxOffsetReady)) {
    runOnEvbAsyncOp({
        .type = AsyncOpType::ByteEventReady,
        .streamId = id,
        .offset = offset,
        .byteEventType = type,
        .callback = cb,
    });
  }
  return {};
}

bool QuicTransportBaseLite::good() const {
  return closeState_ == CloseState::OPEN && hasWriteCipher() && !error();
}

bool QuicTransportBaseLite::error() const {
  return conn_->localConnectionError.has_value();
}

uint64_t QuicTransportBaseLite::bufferSpaceAvailable() const {
  auto bytesBuffered = conn_->flowControlState.sumCurStreamBufferLen;
  auto totalBufferSpaceAvailable =
      conn_->transportSettings.totalBufferSpaceAvailable;
  return bytesBuffered > totalBufferSpaceAvailable
      ? 0
      : totalBufferSpaceAvailable - bytesBuffered;
}

void QuicTransportBaseLite::setConnectionSetupCallback(
    folly::MaybeManagedPtr<ConnectionSetupCallback> callback) {
  connectionCallbacks_.setSetupCallback(std::move(callback));
}

void QuicTransportBaseLite::setConnectionCallback(
    folly::MaybeManagedPtr<ConnectionCallback> callback,
    ConnectionCallbackOptions options) {
  connectionCallbacks_.setConnectionCallback(std::move(callback), options);
  if (connectionCallbacks_.connection()) {
    runOnEvbAsyncOp({.type = AsyncOpType::ProcessCallbacksAfterNetworkData});
  }
}

void QuicTransportBaseLite::setConnectionCallbackFromCtor(
    folly::MaybeManagedPtr<ConnectionCallback> callback) {
  connectionCallbacks_.setConnectionCallback(std::move(callback), {});
}

Optional<LocalErrorCode> QuicTransportBaseLite::setControlStream(StreamId id) {
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return LocalErrorCode::STREAM_NOT_EXISTS;
  }
  conn_->streamManager->setStreamAsControl(*stream);
  return std::nullopt;
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setReadCallback(
    StreamId id,
    ReadCallback* cb,
    Optional<ApplicationErrorCode> err) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (cb != nullptr && closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setReadCallbackInternal(id, cb, err);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::setStopSendingCallback(
    StreamId id,
    StopSendingCallback* ss) noexcept {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (ss != nullptr && closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (ss) {
    stopSendingCallbacks_[id] = ss;
  } else {
    stopSendingCallbacks_.erase(id);
  }
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::pauseRead(
    StreamId id) {
  MVVLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, false);
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resumeRead(
    StreamId id) {
  MVVLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, true);
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setDatagramCallback(
    DatagramCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  MVVLOG(4) << "Setting datagram callback " << " cb=" << cb << " " << *this;

  datagramCallback_ = cb;
  updateReadLooper();
  return {};
}

uint16_t QuicTransportBaseLite::getDatagramSizeLimit() const {
  MVCHECK(conn_);
  auto maxDatagramPacketSize = std::min<decltype(conn_->udpSendPacketLen)>(
      conn_->datagramState.maxWriteFrameSize, conn_->udpSendPacketLen);
  return std::max<decltype(maxDatagramPacketSize)>(
      0, maxDatagramPacketSize - kMaxDatagramPacketOverhead);
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::writeDatagram(
    BufPtr buf) {
  return writeDatagramInternal(
      std::move(buf),
      kDefaultDatagramFlowId,
      std::nullopt,
      false,
      std::nullopt);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::writeDatagramInternal(
    BufPtr buf,
    uint32_t flowId,
    std::optional<PriorityQueue::Priority> priority,
    bool ephemeralFlow,
    std::optional<std::chrono::milliseconds> maxQueueTime,
    uint64_t intraFlowPriority) {
  // TODO(lniccolini) update max datagram frame size
  // https://github.com/quicwg/datagram/issues/3
  // For now, max_datagram_size > 0 means the peer supports datagram frames
  if (conn_->datagramState.maxWriteFrameSize == 0) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_DATA);
  }

  // Check if datagram is too large to ever fit
  auto datagramLen = buf ? buf->computeChainDataLength() : 0;
  if (datagramLen == 0 ||
      datagramLen > conn_->datagramState.maxWriteFrameSize) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_DATA);
  }

  if (conn_->datagramState.flowManager.getDatagramCount() >=
      conn_->datagramState.maxWriteBufferSize) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    // A zero-sized write buffer leaves nothing queued to drop.
    if (!conn_->transportSettings.datagramConfig.sendDropOldDataFirst ||
        !conn_->datagramState.flowManager.hasDatagramsToSend()) {
      // TODO(lniccolini) use different return codes to signal the application
      // exactly why the datagram got dropped
      return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_DATA);
    } else {
      // Drop oldest datagram from any flow
      auto retiredFlowId = conn_->datagramState.flowManager.popDatagram();
      if (retiredFlowId) {
        maybeEraseDatagramFlowFromWriteQueue(*retiredFlowId);
      }
    }
  }

  auto flowPriorityResult = conn_->datagramState.flowManager.addDatagram(
      std::move(buf),
      flowId,
      priority,
      ephemeralFlow,
      maxQueueTime,
      intraFlowPriority);
  if (flowPriorityResult.hasError()) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    return quic::make_unexpected(flowPriorityResult.error());
  }

  // Add to PriorityQueue if scheduling with streams is enabled
  if (conn_->transportSettings.datagramConfig.scheduleDatagramsWithStreams &&
      conn_->streamManager) {
    auto id = PriorityQueue::Identifier::fromDatagramFlowID(flowId);
    conn_->streamManager->writeQueue().insertOrUpdate(id, *flowPriorityResult);
  }

  updateWriteLooper(true);
  return {};
}

void QuicTransportBaseLite::maybeEraseDatagramFlowFromWriteQueue(
    uint32_t flowId) {
  if (conn_->transportSettings.datagramConfig.scheduleDatagramsWithStreams &&
      conn_->streamManager) {
    auto id = PriorityQueue::Identifier::fromDatagramFlowID(flowId);
    conn_->streamManager->writeQueue().erase(id);
  }
}

quic::Expected<std::vector<ReadDatagram>, LocalErrorCode>
QuicTransportBaseLite::readDatagrams(size_t atMost) {
  MVCHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (atMost == 0) {
    atMost = datagrams->size();
  } else {
    atMost = std::min(atMost, datagrams->size());
  }
  std::vector<ReadDatagram> retDatagrams;
  retDatagrams.reserve(atMost);
  const auto end = datagrams->begin() + static_cast<std::ptrdiff_t>(atMost);
  std::transform(
      datagrams->begin(),
      end,
      std::back_inserter(retDatagrams),
      [](ReadDatagram& dg) { return std::move(dg); });
  datagrams->erase(datagrams->begin(), end);
  return retDatagrams;
}

quic::Expected<std::vector<BufPtr>, LocalErrorCode>
QuicTransportBaseLite::readDatagramBufs(size_t atMost) {
  MVCHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (atMost == 0) {
    atMost = datagrams->size();
  } else {
    atMost = std::min(atMost, datagrams->size());
  }
  std::vector<BufPtr> retDatagrams;
  retDatagrams.reserve(atMost);
  const auto end = datagrams->begin() + static_cast<std::ptrdiff_t>(atMost);
  std::transform(
      datagrams->begin(),
      end,
      std::back_inserter(retDatagrams),
      [](ReadDatagram& dg) { return dg.bufQueue().move(); });
  datagrams->erase(datagrams->begin(), end);
  return retDatagrams;
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::pauseOrResumeRead(
    StreamId id,
    bool resume) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto readCb = readCallbacks_.find(id);
  if (readCb == readCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::APP_ERROR);
  }
  if (readCb->second.resumed != resume) {
    readCb->second.resumed = resume;
    updateReadLooper();
  }
  return {};
}

quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode>
QuicTransportBaseLite::read(StreamId id, size_t maxLen) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updateReadLooper();
    updatePeekLooper(); // read can affect "peek" API
    updateWriteLooper(true);
  };
  try {
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto readResult = readDataFromQuicStream(*stream, maxLen);
    if (!readResult.has_value()) {
      MVVLOG(4) << "read() error " << readResult.error().message << " "
                << *this;
      exceptionCloseWhat_ = readResult.error().message;
      closeImpl(QuicError(
          QuicErrorCode(readResult.error().code), std::string("read() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }
    auto result = std::move(readResult.value());
    if (result.second) {
      MVVLOG(10) << "Delivered eof to app for stream=" << stream->id << " "
                 << *this;
      auto it = readCallbacks_.find(id);
      if (it != readCallbacks_.end()) {
        // it's highly unlikely that someone called read() without having a read
        // callback so we don't deal with the case of someone installing a read
        // callback after reading the EOM.
        it->second.deliveredEOM = true;
      }
    }
    return quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode>(
        std::move(result));
  } catch (const std::exception& ex) {
    return quic::make_unexpected(handleExceptionAndClose(ex, "read() error"));
  }
}

void QuicTransportBaseLite::setQLogger(std::shared_ptr<QLogger> qLogger) {
  // setQLogger can be called multiple times for the same connection and with
  // the same qLogger we track the number of times it gets set and the number
  // of times it gets reset, and only stop qlog collection when the number of
  // resets equals the number of times the logger was set
  if (!conn_->qLogger) {
    MVCHECK_EQ(qlogRefcnt_, 0);
  } else {
    MVCHECK_GT(qlogRefcnt_, 0);
  }

  if (qLogger) {
    conn_->qLogger = std::move(qLogger);
    conn_->qLogger->setDcid(conn_->clientChosenDestConnectionId);
    if (conn_->nodeType == QuicNodeType::Server) {
      conn_->qLogger->setScid(conn_->serverConnectionId);
    } else {
      conn_->qLogger->setScid(conn_->clientConnectionId);
    }
    qlogRefcnt_++;
  } else {
    if (conn_->qLogger) {
      qlogRefcnt_--;
      if (qlogRefcnt_ == 0) {
        conn_->qLogger = nullptr;
      }
    }
  }
}

void QuicTransportBaseLite::setOopsLogger(proto_oops::OopsLogger* oopsLogger) {
  conn_->oopsLogger = oopsLogger;
}

const std::shared_ptr<QLogger> QuicTransportBaseLite::getQLogger() const {
  return conn_->qLogger;
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setPriorityQueue(
    std::unique_ptr<PriorityQueue> queue) {
  if (conn_) {
    return conn_->streamManager->setPriorityQueue(std::move(queue));
  }
  return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setStreamPriority(
    StreamId id,
    PriorityQueue::Priority priority) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    // It's not an error to try to prioritize a non-existent stream.
    return {};
  }
  // It's not an error to prioritize a stream after it's sent its FIN - this
  // can reprioritize retransmissions.
  conn_->streamManager->setStreamPriority(
      id, priority, getSendConnFlowControlBytesWire(*conn_) > 0);
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setMaxPacingRate(
    uint64_t maxRateBytesPerSec) {
  if (conn_->pacer) {
    conn_->pacer->setMaxPacingRate(maxRateBytesPerSec);
    return {};
  } else {
    MVLOG_WARNING
        << "Cannot set max pacing rate without a pacer. Pacing Enabled = "
        << conn_->transportSettings.pacingEnabled;
    return quic::make_unexpected(LocalErrorCode::PACER_NOT_AVAILABLE);
  }
}

void QuicTransportBaseLite::setThrottlingSignalProvider(
    std::shared_ptr<ThrottlingSignalProvider> throttlingSignalProvider) {
  MVDCHECK(conn_);
  conn_->throttlingSignalProvider = throttlingSignalProvider;
}

uint64_t QuicTransportBaseLite::maxWritableOnStream(
    const QuicStreamState& stream) const {
  auto connWritableBytes = maxWritableOnConn();
  auto streamFlowControlBytes = getSendStreamFlowControlBytesAPI(stream);
  return std::min(streamFlowControlBytes, connWritableBytes);
}

void QuicTransportBaseLite::processConnectionSetupCallbacks(
    QuicError&& cancelCode) {
  // The setup callback is null if start() was never invoked and the transport
  // was destroyed, or if the app initiated close.
  if (connectionCallbacks_.setup()) {
    connectionCallbacks_.setup()->onConnectionSetupError(std::move(cancelCode));
  }
}

void QuicTransportBaseLite::processConnectionCallbacks(QuicError&& cancelCode) {
  // The connection callback is null if start() was never invoked and the
  // transport was destroyed, or if the app initiated close.
  if (!connectionCallbacks_.connection()) {
    return;
  }

  if (useConnectionEndWithErrorCallback_) {
    connectionCallbacks_.connection()->onConnectionEnd(cancelCode);
    return;
  }

  if (processCancelCode(cancelCode)) {
    connectionCallbacks_.connection()->onConnectionEnd();
  } else {
    connectionCallbacks_.connection()->onConnectionError(std::move(cancelCode));
  }
}

QuicTransportBaseLite::ByteEventMap& QuicTransportBaseLite::getByteEventMap(
    const ByteEvent::Type type) {
  switch (type) {
    case ByteEvent::Type::ACK:
      return deliveryCallbacks_;
    case ByteEvent::Type::TX:
      return txCallbacks_;
  }
  folly::assume_unreachable();
}

const QuicTransportBaseLite::ByteEventMap&
QuicTransportBaseLite::getByteEventMapConst(const ByteEvent::Type type) const {
  switch (type) {
    case ByteEvent::Type::ACK:
      return deliveryCallbacks_;
    case ByteEvent::Type::TX:
      return txCallbacks_;
  }
  folly::assume_unreachable();
}

quic::Expected<QuicSocketLite::StreamTransportInfo, LocalErrorCode>
QuicTransportBaseLite::getStreamTransportInfo(StreamId id) const {
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto packets = getNumPacketsTxWithNewData(*stream);
  return StreamTransportInfo{
      .totalHeadOfLineBlockedTime = stream->totalHolbTime,
      .holbCount = stream->holbCount,
      .isHolb = bool(stream->lastHolbTime),
      .numPacketsTxWithNewData = packets,
      .streamLossCount = stream->streamLossCount,
      .streamBytesSent = stream->finalWriteOffset,
      .maybeLargestDeliverableOffset = getLargestDeliverableOffset(*stream),
      .streamBytesReceived = stream->finalReadOffset,
      .streamReadError = stream->streamReadError,
      .streamWriteError = stream->streamWriteError,
  };
}

const quic::SocketAddress& QuicTransportBaseLite::getPeerAddress() const {
  return conn_->peerAddress;
}

const quic::SocketAddress& QuicTransportBaseLite::getOriginalPeerAddress()
    const {
  return conn_->originalPeerAddress;
}

std::shared_ptr<QuicEventBase> QuicTransportBaseLite::getEventBase() const {
  return evb_;
}

Optional<std::string> QuicTransportBaseLite::getAppProtocol() const {
  return conn_->handshakeLayer->getApplicationProtocol();
}

uint64_t QuicTransportBaseLite::getConnectionBufferAvailable() const {
  return bufferSpaceAvailable();
}

quic::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
QuicTransportBaseLite::getStreamFlowControl(StreamId id) const {
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return QuicSocketLite::FlowControlState(
      getSendStreamFlowControlBytesAPI(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset,
      getRecvStreamFlowControlBytes(*stream),
      stream->flowControlState.advertisedMaxOffset,
      maxWritableOnStream(*stream));
}

void QuicTransportBaseLite::runOnEvbAsyncOp(AsyncOpData data) {
  auto evb = getEventBase();
  evb->runInLoop(
      [self = sharedGuard(), data, evb]() mutable {
        if (self->getEventBase() != evb) {
          // The eventbase changed between scheduling the loop and invoking
          // the callback, ignore this
          return;
        }
        self->dispatchAsyncOp(data);
      },
      true);
}

void QuicTransportBaseLite::dispatchAsyncOp(AsyncOpData data) {
  switch (data.type) {
    case AsyncOpType::ProcessCallbacksAfterNetworkData:
      processCallbacksAfterNetworkData();
      break;
    case AsyncOpType::ConnectionWriteReady: {
      if (!connWriteCallback_) {
        // The connection was probably closed.
        return;
      }
      auto connWritableBytes = maxWritableOnConn();
      if (connWritableBytes != 0) {
        auto connWriteCallback = connWriteCallback_;
        connWriteCallback_ = nullptr;
        connWriteCallback->onConnectionWriteReady(connWritableBytes);
      }
      break;
    }
    case AsyncOpType::StreamWriteReady: {
      auto id = data.streamId;
      auto wcbIt = pendingWriteCallbacks_.find(id);
      if (wcbIt == pendingWriteCallbacks_.end()) {
        // the connection was probably closed.
        return;
      }
      auto writeCallback = wcbIt->second;
      auto* stream = conn_->streamManager->getStreamIfExists(id);
      if (!stream) {
        pendingWriteCallbacks_.erase(wcbIt);
        writeCallback->onStreamWriteError(
            id, QuicError(LocalErrorCode::STREAM_NOT_EXISTS));
        return;
      }
      if (!stream->writable()) {
        pendingWriteCallbacks_.erase(wcbIt);
        writeCallback->onStreamWriteError(
            id, QuicError(LocalErrorCode::STREAM_NOT_EXISTS));
        return;
      }
      auto maxCanWrite = maxWritableOnStream(*stream);
      if (maxCanWrite != 0) {
        pendingWriteCallbacks_.erase(wcbIt);
        writeCallback->onStreamWriteReady(id, maxCanWrite);
      }
      break;
    }
    case AsyncOpType::ByteEventReady: {
      if (closeState_ != CloseState::OPEN) {
        // Close will error out all byte event callbacks.
        return;
      }

      auto id = data.streamId;
      auto offset = data.offset;
      auto type = data.byteEventType;
      auto cb = data.callback;

      auto& byteEventMapL = getByteEventMap(type);
      auto streamByteEventCbIt = byteEventMapL.find(id);
      if (streamByteEventCbIt == byteEventMapL.end()) {
        return;
      }

      // This is scheduled to run in the future (during the next iteration of
      // the event loop). It is possible that the ByteEventDetail list gets
      // mutated between the time it was scheduled to now when we are ready to
      // run it. Look at the current outstanding ByteEvents for this stream ID
      // and confirm that our ByteEvent's offset and recipient callback are
      // still present.
      auto pos = std::find_if(
          streamByteEventCbIt->second.begin(),
          streamByteEventCbIt->second.end(),
          [offset, cb](const ByteEventDetail& p) {
            return ((p.offset == offset) && (p.callback == cb));
          });
      // if our byteEvent is not present, it must have been delivered already.
      if (pos == streamByteEventCbIt->second.end()) {
        return;
      }
      streamByteEventCbIt->second.erase(pos);

      cb->onByteEvent(ByteEvent{id, offset, type});
      break;
    }
    case AsyncOpType::TransportReady:
    case AsyncOpType::MarkZeroRttPacketsLost:
    case AsyncOpType::AsyncClose:
    case AsyncOpType::RemoveNonCurrentPathClient:
      // Handled by derived class override
      break;
  }
}

void QuicTransportBaseLite::updateWriteLooper(bool thisIteration) {
  if (conn_->version == QuicVersion::MVFST_PRIMING) {
    writeLooper_->stop();
    return;
  }
  if (closeState_ == CloseState::CLOSED) {
    MVVLOG(10) << nodeToString(conn_->nodeType)
               << " stopping write looper because conn closed " << *this;
    writeLooper_->stop();
    return;
  }

  // If socket writable events are in use, do nothing if we are already waiting
  // for the write event.
  if (conn_->transportSettings.useSockWritableEvents &&
      socket_->isWritableCallbackSet()) {
    return;
  }

  auto writeDataReason = shouldWriteData(*conn_);
  if (writeDataReason != WriteDataReason::NO_WRITE) {
    MVVLOG(10) << nodeToString(conn_->nodeType)
               << " running write looper thisIteration=" << thisIteration << " "
               << *this;
    writeLooper_->run(thisIteration);
    if (conn_->loopDetectorCallback) {
      conn_->writeDebugState.needsWriteLoopDetect =
          (conn_->loopDetectorCallback != nullptr);
    }
  } else {
    MVVLOG(10) << nodeToString(conn_->nodeType) << " stopping write looper "
               << *this;
    writeLooper_->stop();
    if (conn_->loopDetectorCallback) {
      conn_->writeDebugState.needsWriteLoopDetect = false;
      conn_->writeDebugState.currentEmptyLoopCount = 0;
    }
  }
  if (conn_->loopDetectorCallback) {
    conn_->writeDebugState.writeDataReason = writeDataReason;
  }
}

void QuicTransportBaseLite::updateReadLooper() {
  if (closeState_ != CloseState::OPEN) {
    MVVLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
    return;
  }
  auto matcherFn = [this](StreamId s) {
    auto readCb = readCallbacks_.find(s);
    if (readCb == readCallbacks_.end() || !readCb->second.readCb) {
      return false;
    }
    if (readCb->second.resumed) {
      return true;
    }
    auto* stream = conn_->streamManager->getStreamIfExists(s);
    return stream && stream->streamReadError &&
        (!stream->reliableSizeFromPeer ||
         *stream->reliableSizeFromPeer <= stream->currentReadOffset);
  };
  auto iter = std::find_if(
      conn_->streamManager->readableStreams().begin(),
      conn_->streamManager->readableStreams().end(),
      matcherFn);
  if (iter != conn_->streamManager->readableStreams().end() ||
      !conn_->datagramState.readBuffer.empty()) {
    MVVLOG(10) << "Scheduling read looper " << *this;
    readLooper_->run();
  } else {
    MVVLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
  }
}

void QuicTransportBaseLite::maybeStopWriteLooperAndArmSocketWritableEvent() {
  if (!socket_ || (closeState_ == CloseState::CLOSED)) {
    return;
  }
  if (conn_->transportSettings.useSockWritableEvents &&
      !socket_->isWritableCallbackSet()) {
    // Let pacing fire the writer while a pacing delay is pending.
    if (writeLooper_->isPacingScheduled() || getLooperPacingDelay() != 0us) {
      return;
    }

    // Check if all data has been written and we're not limited by flow
    // control/congestion control.
    bool haveDataToWrite = shouldWriteData(*conn_) != WriteDataReason::NO_WRITE;
    bool haveCongestionControlWindow = true;
    if (conn_->congestionController) {
      haveCongestionControlWindow =
          conn_->congestionController->getWritableBytes() > 0;
    }
    bool haveFlowControlWindow = getSendConnFlowControlBytesAPI(*conn_) > 0;
    bool connHasWriteWindow =
        haveCongestionControlWindow && haveFlowControlWindow;
    if (haveDataToWrite && connHasWriteWindow) {
      // Re-arm the write event and stop the write
      // looper.
      auto resumeResult = socket_->resumeWrite(this);
      if (!resumeResult.has_value()) {
        exceptionCloseWhat_ = resumeResult.error().message;
        closeImpl(QuicError(
            resumeResult.error().code,
            std::string(
                "maybeStopWriteLooperAndArmSocketWritableEvent() error")));
        return;
      }
      writeLooper_->stop();
    }
  }
}

void QuicTransportBaseLite::checkForClosedStream() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  auto itr = conn_->streamManager->closedStreams().begin();
  while (itr != conn_->streamManager->closedStreams().end()) {
    const auto& streamId = *itr;

    SOCKET_OBSERVER_IF(
        getSocketObserverContainer(),
        SocketObserverInterface::Events::streamEvents) {
      getSocketObserverContainer()
          ->invokeInterfaceMethod<
              SocketObserverInterface::Events::streamEvents>(
              [event = SocketObserverInterface::StreamCloseEvent(
                   streamId,
                   getStreamInitiator(streamId),
                   getStreamDirectionality(streamId))](
                  auto observer, auto observed) {
                observer->streamClosed(observed, event);
              });
    }

    // We may be in an active read cb when we close the stream
    auto readCbIt = readCallbacks_.find(*itr);
    // We use the read callback as a way to defer destruction of the stream.
    if (readCbIt != readCallbacks_.end() &&
        readCbIt->second.readCb != nullptr) {
      if (conn_->transportSettings.removeStreamAfterEomCallbackUnset ||
          !readCbIt->second.deliveredEOM) {
        MVVLOG(10) << "Not closing stream=" << *itr
                   << " because it has active read callback";
        ++itr;
        continue;
      }
    }
    // If we have pending byte events, delay closing the stream
    auto numByteEventCb = getNumByteEventCallbacksForStream(*itr);
    if (numByteEventCb > 0) {
      MVVLOG(10) << "Not closing stream=" << *itr << " because it has "
                 << numByteEventCb << " pending byte event callbacks";
      ++itr;
      continue;
    }
    // If we have active peek callback, delay closing the stream
    if (hasPeekCallback(*itr)) {
      MVVLOG(10) << "Not closing stream=" << *itr
                 << " because it has active peek callback";
      ++itr;
      continue;
    }

    MVVLOG(10) << "Closing stream=" << *itr;
    if (connectionCallbacks_.connection()) {
      connectionCallbacks_.connection()->onStreamPreReaped(*itr);
    }
    // onStreamPreReaped may synchronously close() the transport, which frees
    // readCallbacks_ and tears down stream state; bail before reusing readCbIt.
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
    auto result = conn_->streamManager->removeClosedStream(*itr);
    if (!result.has_value()) {
      exceptionCloseWhat_ = result.error().message;
      closeImpl(QuicError(
          result.error().code, std::string("checkForClosedStream() error")));
      return;
    }
    pendingWriteCallbacks_.erase(streamId);
    maybeSendStreamLimitUpdates(*conn_);
    if (readCbIt != readCallbacks_.end()) {
      readCallbacks_.erase(readCbIt);
    }
    itr = conn_->streamManager->closedStreams().erase(itr);
  } // while

  if (closeState_ == CloseState::GRACEFUL_CLOSING && canFinishGracefulClose()) {
    closeImpl(std::nullopt);
  }
}

bool QuicTransportBaseLite::canFinishGracefulClose() const {
  for (const auto& [id, stream] : conn_->streamManager->streams()) {
    const bool sendFinished = stream.sendState == StreamSendState::Closed ||
        stream.sendState == StreamSendState::Invalid;
    if (!sendFinished || !stream.ingressRetired) {
      return false;
    }
  }
  return true;
}

void QuicTransportBaseLite::writeSocketDataAndCatch() {
  [[maybe_unused]] auto self = sharedGuard();
  try {
    auto result = writeSocketData();
    if (!result.has_value()) {
      MVVLOG(4) << __func__ << " " << result.error().message << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(result.error());
      return;
    }
    processCallbacksAfterWriteData();
  } catch (const std::exception& ex) {
    handleExceptionAndClose(ex, "writeSocketDataAndCatch() error");
  }
}

void QuicTransportBaseLite::pacedWriteDataToSocket() {
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    self->maybeStopWriteLooperAndArmSocketWritableEvent();
  };

  if (!isConnectionPaced(*conn_)) {
    // Not paced and connection is still open, normal write. Even if pacing is
    // previously enabled and then gets disabled, and we are here due to a
    // timeout, we should do a normal write to flush out the residue from
    // pacing write.
    writeSocketDataAndCatch();

    if (conn_->transportSettings.scheduleTimerForExcessWrites) {
      // If we still have data to write, yield the event loop now but schedule a
      // timeout to come around and write again as soon as possible.
      auto writeDataReason = shouldWriteData(*conn_);
      if (writeDataReason != WriteDataReason::NO_WRITE &&
          !excessWriteTimeout_.isTimerCallbackScheduled()) {
        scheduleTimeout(&excessWriteTimeout_, 0ms);
      }
    }
    return;
  }

  // We are in the middle of a pacing interval. Leave it be.
  if (writeLooper_->isPacingScheduled()) {
    // The next burst is already scheduled. Since the burst size doesn't
    // depend on much data we currently have in buffer at all, no need to
    // change anything.
    return;
  }

  // Do a burst write before waiting for an interval. This will also call
  // updateWriteLooper, but inside FunctionLooper we will ignore that.
  writeSocketDataAndCatch();
}

quic::Expected<void, QuicError> QuicTransportBaseLite::writeSocketData() {
  if (socket_) {
    ++(conn_->writeCount); // incremented on each write (or write attempt)

    // record current number of sent packets to detect delta
    const auto beforeTotalBytesSent = conn_->lossState.totalBytesSent;
    const auto beforeTotalPacketsSent = conn_->lossState.totalPacketsSent;
    const auto beforeTotalAckElicitingPacketsSent =
        conn_->lossState.totalAckElicitingPacketsSent;
    const auto beforeNumOutstandingPackets =
        conn_->outstandings.numOutstanding();

    updatePacketProcessorsPrewriteRequests();
    // postwrites should be called in all cases if prewrites were
    // successfully (did not throw) called. Since there are multiple
    // exit branches for this function, the easiest way to do this
    // is via SCOPE_EXIT registration after prewrite return.
    SCOPE_EXIT {
      for (const auto& pp : conn_->packetProcessors) {
        pp->postwrite();
      }
    };

    // if we're starting to write from app limited, notify observers
    if (conn_->appLimitedTracker.isAppLimited() &&
        conn_->congestionController) {
      conn_->appLimitedTracker.setNotAppLimited();
      notifyStartWritingFromAppRateLimited();
    }
    auto result = writeData();
    if (!result.has_value()) {
      return result;
    }
    if (conn_->transportSettings.isPriming && conn_->primingData.size() > 0) {
      auto primingData = std::move(conn_->primingData);
      // Priming sends a single flight and never receives ACKs to open the
      // window. Unsent request stream or crypto data, or a stream blocked by
      // flow control, indicates that the priming request did not fit in the
      // first flight.
      const auto pendingWriteReason = hasNonAckDataToWrite(*conn_);
      const bool truncated =
          pendingWriteReason == WriteDataReason::CRYPTO_STREAM ||
          pendingWriteReason == WriteDataReason::STREAM ||
          pendingWriteReason == WriteDataReason::BLOCKED;
      connectionCallbacks_.setup()->onPrimingDataAvailable(
          std::move(primingData), truncated);
    }
    if (closeState_ != CloseState::CLOSED) {
      if (conn_->pendingEvents.closeTransport == true) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Max packet number reached"));
      }
      setLossDetectionAlarm(*conn_, *this);

      // check for change in number of packets
      const auto afterTotalBytesSent = conn_->lossState.totalBytesSent;
      const auto afterTotalPacketsSent = conn_->lossState.totalPacketsSent;
      const auto afterTotalAckElicitingPacketsSent =
          conn_->lossState.totalAckElicitingPacketsSent;
      const auto afterNumOutstandingPackets =
          conn_->outstandings.numOutstanding();
      MVCHECK_LE(beforeTotalPacketsSent, afterTotalPacketsSent);
      MVCHECK_LE(
          beforeTotalAckElicitingPacketsSent,
          afterTotalAckElicitingPacketsSent);
      MVCHECK_LE(beforeNumOutstandingPackets, afterNumOutstandingPackets);
      MVCHECK_EQ(
          afterNumOutstandingPackets - beforeNumOutstandingPackets,
          afterTotalAckElicitingPacketsSent -
              beforeTotalAckElicitingPacketsSent);
      const bool newPackets = (afterTotalPacketsSent > beforeTotalPacketsSent);
      const bool newOutstandingPackets =
          (afterTotalAckElicitingPacketsSent >
           beforeTotalAckElicitingPacketsSent);

      // if packets sent, notify observers
      if (newPackets) {
        notifyPacketsWritten(
            afterTotalPacketsSent - beforeTotalPacketsSent
            /* numPacketsWritten */,
            afterTotalAckElicitingPacketsSent -
                beforeTotalAckElicitingPacketsSent
            /* numAckElicitingPacketsWritten */,
            afterTotalBytesSent - beforeTotalBytesSent /* numBytesWritten */);
      }
      if (conn_->loopDetectorCallback && newOutstandingPackets) {
        conn_->writeDebugState.currentEmptyLoopCount = 0;
      } else if (
          conn_->writeDebugState.needsWriteLoopDetect &&
          conn_->loopDetectorCallback) {
        // TODO: Currently we will to get some stats first. Then we may filter
        // out some errors here. For example, socket fail to write might be a
        // legit case to filter out.
        conn_->loopDetectorCallback->onSuspiciousWriteLoops(
            ++conn_->writeDebugState.currentEmptyLoopCount,
            conn_->writeDebugState.writeDataReason,
            conn_->writeDebugState.noWriteReason,
            conn_->writeDebugState.schedulerName);
        // TODO(jbeshay): temporary diagnostic OOPS to pin
        // STREAM/NoFrame empty write loops
        [[maybe_unused]] const auto emptyLoops =
            conn_->writeDebugState.currentEmptyLoopCount;
        PROTO_OOPS_LOG_BUILDER_IF(
            conn_->nodeType == QuicNodeType::Server &&
                conn_->writeDebugState.writeDataReason ==
                    WriteDataReason::STREAM &&
                conn_->writeDebugState.noWriteReason ==
                    NoWriteReason::NO_FRAME &&
                conn_->streamManager && emptyLoops >= 16 &&
                (emptyLoops & (emptyLoops - 1)) == 0,
            conn_->oopsLogger,
            proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
            "quic_write_loop",
            formatStreamNoFrameLoopDiag(*conn_, emptyLoops));
      }
      // If we sent a new packet and the new packet was either the first
      // packet after quiescence or after receiving a new packet.
      if (newOutstandingPackets &&
          (beforeNumOutstandingPackets == 0 ||
           conn_->receivedNewPacketBeforeWrite)) {
        // Reset the idle timer because we sent some data.
        setIdleTimer();
        conn_->receivedNewPacketBeforeWrite = false;
      }
      // Check if we are app-limited after finish this round of sending
      auto currentSendBufLen = conn_->flowControlState.sumCurStreamBufferLen;
      const auto cryptoLossBufferEmpty = [](const QuicCryptoStream& stream) {
        return stream.streamSendBuffer
            ? !stream.streamSendBuffer->hasPendingLoss()
            : stream.lossBuffer.empty();
      };
      auto lossBufferEmpty = !conn_->streamManager->hasLoss() &&
          cryptoLossBufferEmpty(conn_->cryptoState->initialStream) &&
          cryptoLossBufferEmpty(conn_->cryptoState->handshakeStream) &&
          cryptoLossBufferEmpty(conn_->cryptoState->oneRttStream);
      if (conn_->congestionController &&
          currentSendBufLen < conn_->udpSendPacketLen && lossBufferEmpty &&
          conn_->congestionController->getWritableBytes()) {
        conn_->congestionController->setAppLimited();
        // notify via connection call and any observer callbacks
        if (transportReadyNotified_ && connectionCallbacks_.connection()) {
          connectionCallbacks_.connection()->onAppRateLimited();
        }
        conn_->appLimitedTracker.setAppLimited();
        notifyAppRateLimited();
      }
    }
  }
  // Writing data could write out an ack which could cause us to cancel
  // the ack timer. But we need to call scheduleAckTimeout() for it to take
  // effect.
  scheduleAckTimeout();
  schedulePathValidationTimeout();
  updateWriteLooper(false);
  return {};
}

// TODO: t64691045 change the closeImpl API to include both the sanitized and
// unsanited error message, remove exceptionCloseWhat_.
void QuicTransportBaseLite::closeImpl(
    Optional<QuicError> errorCode,
    bool drainConnection,
    bool sendCloseImmediately) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  SOCKET_OBSERVER_IF_ANY(getSocketObserverContainer()) {
    SocketObserverInterface::CloseStartedEvent event;
    event.maybeCloseReason = errorCode;
    getSocketObserverContainer()->invokeInterfaceMethodAllObservers(
        [&event](auto observer, auto observed) {
          observer->closeStarted(observed, event);
        });
  }

  drainConnection = drainConnection & conn_->transportSettings.shouldDrain;

  uint64_t totalCryptoDataWritten [[maybe_unused]] = 0;
  uint64_t totalCryptoDataRecvd [[maybe_unused]] = 0;
  auto timeUntilLastInitialCryptoFrameReceived = std::chrono::milliseconds(0);
  if (conn_->cryptoState) {
    totalCryptoDataWritten +=
        conn_->cryptoState->initialStream.currentWriteOffset;
    totalCryptoDataWritten +=
        conn_->cryptoState->handshakeStream.currentWriteOffset;
    totalCryptoDataWritten +=
        conn_->cryptoState->oneRttStream.currentWriteOffset;

    totalCryptoDataRecvd += conn_->cryptoState->initialStream.maxOffsetObserved;
    totalCryptoDataRecvd +=
        conn_->cryptoState->handshakeStream.maxOffsetObserved;
    totalCryptoDataRecvd += conn_->cryptoState->oneRttStream.maxOffsetObserved;
    timeUntilLastInitialCryptoFrameReceived =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            conn_->cryptoState->lastInitialCryptoFrameReceivedTimePoint -
            conn_->connectionTime);
  }

  [[maybe_unused]] auto tlsSummary = conn_->handshakeLayer
      ? conn_->handshakeLayer->getTLSSummary()
      : Handshake::TLSSummary{};
  QLOG(
      *conn_,
      addTransportSummary,
      {conn_->lossState.totalBytesSent,
       conn_->lossState.totalBytesRecvd,
       conn_->flowControlState.sumCurWriteOffset,
       conn_->flowControlState.sumMaxObservedOffset,
       conn_->flowControlState.sumCurStreamBufferLen,
       conn_->lossState.totalBytesRetransmitted,
       conn_->lossState.totalStreamBytesCloned,
       conn_->lossState.totalBytesCloned,
       totalCryptoDataWritten,
       totalCryptoDataRecvd,
       conn_->congestionController
           ? conn_->congestionController->getWritableBytes()
           : std::numeric_limits<uint64_t>::max(),
       getSendConnFlowControlBytesWire(*conn_),
       conn_->lossState.totalPacketsSpuriouslyMarkedLost,
       conn_->lossState.reorderingThreshold,
       uint64_t(conn_->transportSettings.timeReorderingThreshDividend),
       conn_->usedZeroRtt,
       conn_->version.value_or(QuicVersion::MVFST_INVALID),
       conn_->initialPacketsReceived,
       conn_->uniqueInitialCryptoFramesReceived,
       timeUntilLastInitialCryptoFrameReceived,
       tlsSummary.alpn,
       tlsSummary.namedGroup,
       tlsSummary.pskType,
       tlsSummary.echStatus});

  // TODO: truncate the error code string to be 1MSS only.
  closeState_ = CloseState::CLOSED;
  updatePacingOnClose(*conn_);
  auto cancelCode = QuicError(
      QuicErrorCode(LocalErrorCode::NO_ERROR),
      toString(LocalErrorCode::NO_ERROR));
  if (conn_->peerConnectionError) {
    cancelCode = *conn_->peerConnectionError;
  } else if (errorCode) {
    cancelCode = *errorCode;
  }
  // cancelCode is used for communicating error message to local app layer.
  // errorCode will be used for localConnectionError, and sent in close frames.
  // It's safe to include the unsanitized error message in cancelCode
  if (exceptionCloseWhat_) {
    cancelCode.message = exceptionCloseWhat_.value();
  }

  bool isReset = false;
  bool isAbandon = false;
  bool isInvalidMigration = false;
  LocalErrorCode* localError = cancelCode.code.asLocalErrorCode();
  TransportErrorCode* transportError = cancelCode.code.asTransportErrorCode();
  if (localError) {
    isReset = *localError == LocalErrorCode::CONNECTION_RESET;
    isAbandon = *localError == LocalErrorCode::CONNECTION_ABANDONED;
  }
  isInvalidMigration = transportError &&
      *transportError == TransportErrorCode::INVALID_MIGRATION;
  MVVLOG_IF(4, isReset) << "Closing transport due to stateless reset " << *this;
  MVVLOG_IF(4, isAbandon) << "Closing transport due to abandoned connection "
                          << *this;
  if (errorCode) {
    conn_->localConnectionError = errorCode;
    QLOG(
        *conn_,
        addConnectionClose,
        conn_->localConnectionError->message,
        errorCode->message,
        drainConnection,
        sendCloseImmediately);
  } else {
    [[maybe_unused]] auto reason = fmt::format(
        "Server: {}, Peer: isReset: {}, Peer: isAbandon: {}",
        kNoError,
        isReset,
        isAbandon);
    QLOG(
        *conn_,
        addConnectionClose,
        kNoError,
        std::move(reason),
        drainConnection,
        sendCloseImmediately);
  }
  cancelLossTimeout();
  cancelTimeout(&ackTimeout_);
  cancelTimeout(&pathValidationTimeout_);
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  cancelTimeout(&excessWriteTimeout_);

  MVVLOG(10) << "Stopping read looper due to immediate close " << *this;
  readLooper_->stop();
  writeLooper_->stop();
  writeLooper_->setPacingTimer(nullptr);
  cleanupPeekPingDatagramResources();

  // Drop any alternate paths
  conn_->pathManager->dropAllSockets();

  cancelAllAppCallbacks(cancelCode);

  // Clear out all the pending events, we don't need them any more.
  closeTransport();

  // Clear out all the streams, we don't need them any more. When the peer
  // receives the conn close they will implicitly reset all the streams.
  conn_->streamManager->clearOpenStreams();

  // Clear out all the buffered datagrams
  conn_->datagramState.readBuffer.clear();
  conn_->datagramState.flowManager = DatagramFlowManager();

  // Clear out all the pending events.
  conn_->pendingEvents = QuicConnectionStateBase::PendingEvents();
  conn_->streamManager->clearActionable();
  conn_->streamManager->clearWritable();
  if (conn_->ackStates.initialAckState) {
    conn_->ackStates.initialAckState->acks.clear();
  }
  if (conn_->ackStates.handshakeAckState) {
    conn_->ackStates.handshakeAckState->acks.clear();
  }
  conn_->ackStates.appDataAckState.acks.clear();

  if (transportReadyNotified_) {
    // This connection was open, update the stats for close.
    QUIC_STATS(conn_->statsCallback, onConnectionClose, cancelCode.code);

    processConnectionCallbacks(std::move(cancelCode));
  } else {
    processConnectionSetupCallbacks(std::move(cancelCode));
  }

  connectionCallbacks_.onEndReported();

  // Don't need outstanding packets.
  conn_->outstandings.reset();

  // We don't need no congestion control.
  conn_->congestionController = nullptr;
  sendCloseImmediately = sendCloseImmediately && !isReset && !isAbandon;
  if (sendCloseImmediately) {
    // We might be invoked from the destructor, so just send the connection
    // close directly.
    auto result = writeData();
    if (!result.has_value()) {
      MVLOG_ERROR << "close failed with error: " << result.error().message
                  << " " << *this;
    }
  }
  drainConnection =
      drainConnection && !isReset && !isAbandon && !isInvalidMigration;
  if (drainConnection) {
    // We ever drain once, and the object ever gets created once.
    MVDCHECK(!isTimeoutScheduled(&drainTimeout_));
    scheduleTimeout(
        &drainTimeout_,
        std::chrono::ceil<std::chrono::milliseconds>(
            kDrainFactor * calculatePTO(*conn_)));
  } else {
    drainTimeoutExpired();
  }
}

LocalErrorCode QuicTransportBaseLite::handleExceptionAndClose(
    const std::exception& ex,
    folly::StringPiece contextMsg,
    Optional<StreamId> streamId) {
  // Log with optional stream context
  if (streamId.has_value()) {
    MVVLOG(4) << contextMsg << " streamId=" << *streamId << " " << ex.what()
              << " " << *this;
  } else {
    MVVLOG(4) << contextMsg << " " << ex.what() << " " << *this;
  }

  const auto* transportEx = dynamic_cast<const QuicTransportException*>(&ex);
  const auto* internalEx = dynamic_cast<const QuicInternalException*>(&ex);
  const auto* appEx = dynamic_cast<const QuicApplicationException*>(&ex);
  exceptionCloseWhat_ = ex.what();

  // Log to Protocol OOPS if configured
  if (conn_->oopsLogger) {
    auto builder = proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_)
                       .setExceptionType(typeid(ex).name());
    if (streamId.has_value()) {
      builder.setStreamId(*streamId);
    }
    if (transportEx) {
      builder.setErrorCode(static_cast<uint64_t>(transportEx->errorCode()));
    } else if (internalEx) {
      builder.setErrorCode(static_cast<uint64_t>(internalEx->errorCode()));
    } else if (appEx) {
      builder.setErrorCode(static_cast<uint64_t>(appEx->errorCode()));
    }
    PROTO_OOPS_LOG_BUILDER(
        conn_->oopsLogger,
        std::move(builder),
        "mvfst_transport",
        std::string(contextMsg) + ": " + exceptionCloseWhat_.value_or(""));
  }

  // Determine error code and return value based on exception type
  if (transportEx) {
    closeImpl(QuicError(
        QuicErrorCode(transportEx->errorCode()), std::string(contextMsg)));
    return LocalErrorCode::TRANSPORT_ERROR;
  }
  if (internalEx) {
    closeImpl(QuicError(
        QuicErrorCode(internalEx->errorCode()), std::string(contextMsg)));
    return internalEx->errorCode();
  }
  if (appEx) {
    closeImpl(
        QuicError(QuicErrorCode(appEx->errorCode()), std::string(contextMsg)));
    return LocalErrorCode::TRANSPORT_ERROR;
  }
  // Fallback for unknown std::exception
  closeImpl(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      std::string(contextMsg)));
  return LocalErrorCode::INTERNAL_ERROR;
}

void QuicTransportBaseLite::processCallbacksAfterNetworkData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }
  if (!connectionCallbacks_.connection() || !conn_->streamManager) {
    return;
  }

  // We reuse this storage for storing streams which need callbacks.
  std::vector<StreamId> tempStorage;

  handleNewStreamCallbacks(tempStorage);
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handlePingCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleKnobCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleAckEventCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleCancelByteEventCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleDeliveryCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleStreamFlowControlUpdatedCallbacks(tempStorage);
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleStreamStopSendingCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleConnWritable();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  invokeStreamsAvailableCallbacks();
  cleanupAckEventState();
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resetStreamInternal(
    StreamId id,
    ApplicationErrorCode errorCode,
    bool reliable) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  try {
    // Check whether stream exists before calling getStream to avoid
    // creating a peer stream if it does not exist yet.
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    if (stream->appErrorCodeToPeer) {
      // The error code can't change across resets for a stream
      errorCode = *stream->appErrorCodeToPeer;
    }
    Optional<uint64_t> maybeReliableSize = std::nullopt;
    if (reliable) {
      maybeReliableSize = stream->reliableResetCheckpoint;
    }
    if (stream->sendState == StreamSendState::ResetSent &&
        maybeReliableSize.value_or(0) >
            stream->reliableSizeToPeer.value_or(0)) {
      // We can't increase the reliable size in a subsequent reset
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    // Invoke state machine
    auto result = sendRstSMHandler(*stream, errorCode, maybeReliableSize);
    if (!result.has_value()) {
      MVVLOG(4) << __func__ << " streamId=" << id << " "
                << result.error().message << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(
          QuicError(result.error().code, std::string("resetStream() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }

    // Cancel all byte events for this stream which have offsets that don't
    // need to be reliably delivered.
    invokeForEachByteEventType(
        ([this, id, &maybeReliableSize](const ByteEvent::Type type) {
          cancelByteEventCallbacksForStreamInternal(
              type, id, [&maybeReliableSize](uint64_t offset) {
                return !maybeReliableSize || offset >= *maybeReliableSize;
              });
        }));

    pendingWriteCallbacks_.erase(id);
    QUIC_STATS(conn_->statsCallback, onQuicStreamReset, errorCode);
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        handleExceptionAndClose(ex, "resetStream() error", id));
  }
  return {};
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStreamInternal(
    const ByteEvent::Type type,
    const StreamId id,
    FunctionRef<bool(uint64_t)> offsetFilter) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return;
  }

  auto& byteEventMap = getByteEventMap(type);
  auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    switch (type) {
      case ByteEvent::Type::ACK:
        conn_->streamManager->removeDeliverable(id);
        break;
      case ByteEvent::Type::TX:
        conn_->streamManager->removeTx(id);
        break;
    }
    return;
  }
  auto& streamByteEvents = byteEventMapIt->second;

  // Callbacks are kept sorted by offset, so we can just walk the queue and
  // invoke those with offset below provided offset.
  while (!streamByteEvents.empty()) {
    // decomposition not supported for xplat
    const auto cbOffset = streamByteEvents.front().offset;
    const auto callback = streamByteEvents.front().callback;
    if (offsetFilter(cbOffset)) {
      streamByteEvents.pop_front();
      ByteEventCancellation cancellation{id, cbOffset, type};
      callback->onByteEventCanceled(cancellation);
      if (closeState_ != CloseState::OPEN) {
        // socket got closed - we can't use streamByteEvents anymore,
        // closeImpl should take care of cleaning up any remaining callbacks
        return;
      }
    } else {
      // Only larger or equal offsets left, exit the loop.
      break;
    }
  }

  // Clean up state for this stream if no callbacks left to invoke.
  if (streamByteEvents.empty()) {
    switch (type) {
      case ByteEvent::Type::ACK:
        conn_->streamManager->removeDeliverable(id);
        break;
      case ByteEvent::Type::TX:
        conn_->streamManager->removeTx(id);
        break;
    }
    // The callback could have changed the map so erase by id.
    byteEventMap.erase(id);
  }
}

void QuicTransportBaseLite::onSocketWritable() noexcept {
  // Remove the writable callback.
  socket_->pauseWrite();

  // Try to write.
  // If write fails again, pacedWriteDataToSocket() will re-arm the write event
  // and stop the write looper.
  writeLooper_->run(true /* thisIteration */);
}

void QuicTransportBaseLite::invokeStreamsAvailableCallbacks() {
  if (conn_->streamManager->consumeMaxLocalBidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numOpenableStreams = getNumOpenableBidirectionalStreams();
    if (numOpenableStreams > 0) {
      connectionCallbacks_.connection()->onBidirectionalStreamsAvailable(
          numOpenableStreams);
    }
  }
  if (conn_->streamManager->consumeMaxLocalUnidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numOpenableStreams = getNumOpenableUnidirectionalStreams();
    if (numOpenableStreams > 0) {
      connectionCallbacks_.connection()->onUnidirectionalStreamsAvailable(
          numOpenableStreams);
    }
  }
}

void QuicTransportBaseLite::handleKnobCallbacks() {
  if (!conn_->transportSettings.advertisedKnobFrameSupport) {
    MVVLOG(4) << "Received knob frames without advertising support";
    conn_->pendingEvents.knobs.clear();
    return;
  }

  for (auto& knobFrame : conn_->pendingEvents.knobs) {
    if (knobFrame.knobSpace != kDefaultQuicTransportKnobSpace) {
      SOCKET_OBSERVER_IF(
          getSocketObserverContainer(),
          SocketObserverInterface::Events::knobFrameEvents) {
        getSocketObserverContainer()
            ->invokeInterfaceMethod<
                SocketObserverInterface::Events::knobFrameEvents>(
                [event = quic::SocketObserverInterface::KnobFrameEvent(
                     Clock::now(), knobFrame)](auto observer, auto observed) {
                  observer->knobFrameReceived(observed, event);
                });
      }
      connectionCallbacks_.connection()->onKnob(
          knobFrame.knobSpace, knobFrame.id, std::move(knobFrame.blob));
    } else {
      // KnobId is ignored
      onTransportKnobs(std::move(knobFrame.blob));
    }
  }
  conn_->pendingEvents.knobs.clear();
}

void QuicTransportBaseLite::handleAckEventCallbacks() {
  auto& lastProcessedAckEvents = conn_->lastProcessedAckEvents;
  if (lastProcessedAckEvents.empty()) {
    return; // nothing to do
  }

  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::acksProcessedEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::acksProcessedEvents>(
            [event =
                 quic::SocketObserverInterface::AcksProcessedEvent::Builder()
                     .setAckEvents(lastProcessedAckEvents)
                     .build()](auto observer, auto observed) {
              observer->acksProcessed(observed, event);
            });
  }
  lastProcessedAckEvents.clear();
}

void QuicTransportBaseLite::handleCancelByteEventCallbacks() {
  for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
       pendingResetIt != conn_->pendingEvents.resets.end();
       pendingResetIt++) {
    cancelByteEventCallbacksForStream(pendingResetIt->first);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
}

void QuicTransportBaseLite::handleNewStreamCallbacks(
    std::vector<StreamId>& streamStorage) {
  streamStorage = conn_->streamManager->consumeNewPeerStreams();
  handleNewStreams(streamStorage);
}

void QuicTransportBaseLite::handleDeliveryCallbacks() {
  auto deliverableStreamId = conn_->streamManager->popDeliverable();
  while (deliverableStreamId.has_value()) {
    auto streamId = *deliverableStreamId;
    auto stream = MVCHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    auto maxOffsetToDeliver = getLargestDeliverableOffset(*stream);

    if (maxOffsetToDeliver.has_value() && !stream->usesUnifiedSendBuffer()) {
      size_t amountTrimmed = stream->writeBuffer.trimStartAtMost(
          *maxOffsetToDeliver - stream->writeBufferStartOffset);
      stream->writeBufferStartOffset += amountTrimmed;
    }

    if (maxOffsetToDeliver.has_value()) {
      while (hasDeliveryCallbacksToCall(streamId, *maxOffsetToDeliver)) {
        auto& deliveryCallbacksForAckedStream = deliveryCallbacks_.at(streamId);
        auto deliveryCallbackAndOffset =
            deliveryCallbacksForAckedStream.front();
        deliveryCallbacksForAckedStream.pop_front();
        auto currentDeliveryCallbackOffset = deliveryCallbackAndOffset.offset;
        auto deliveryCallback = deliveryCallbackAndOffset.callback;

        ByteEvent byteEvent{
            streamId,
            currentDeliveryCallbackOffset,
            ByteEvent::Type::ACK,
            conn_->lossState.srtt};
        deliveryCallback->onByteEvent(byteEvent);

        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
    auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
    if (deliveryCallbacksForAckedStream != deliveryCallbacks_.end() &&
        deliveryCallbacksForAckedStream->second.empty()) {
      deliveryCallbacks_.erase(deliveryCallbacksForAckedStream);
    }
    deliverableStreamId = conn_->streamManager->popDeliverable();
  }
}

void QuicTransportBaseLite::handleStreamFlowControlUpdatedCallbacks(
    std::vector<StreamId>& streamStorage) {
  // Iterate over streams that changed their flow control window and give
  // their registered listeners their updates.
  // We don't really need flow control notifications when we are closed.
  // The callback can synchronously reap any stream in this detached snapshot,
  // so every stream lookup must tolerate absence.
  streamStorage = conn_->streamManager->consumeFlowControlUpdated();
  for (const auto streamId : streamStorage) {
    auto* stream = conn_->streamManager->getStreamIfExists(streamId);
    if (!stream || !stream->writable()) {
      pendingWriteCallbacks_.erase(streamId);
      continue;
    }
    connectionCallbacks_.connection()->onFlowControlUpdate(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }

    auto pendingWriteIt = pendingWriteCallbacks_.find(streamId);
    if (pendingWriteIt == pendingWriteCallbacks_.end()) {
      continue;
    }

    // The callback can remove the stream or make it non-writable.
    stream = conn_->streamManager->getStreamIfExists(streamId);
    if (!stream || !stream->writable()) {
      pendingWriteCallbacks_.erase(pendingWriteIt);
      continue;
    }

    const auto maxStreamWritable = maxWritableOnStream(*stream);
    if (maxStreamWritable == 0) {
      continue;
    }

    auto wcb = pendingWriteIt->second;
    pendingWriteCallbacks_.erase(pendingWriteIt);
    wcb->onStreamWriteReady(streamId, maxStreamWritable);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }

  streamStorage.clear();
}

void QuicTransportBaseLite::handleStreamStopSendingCallbacks() {
  const auto stopSendingStreamsCopy =
      conn_->streamManager->consumeStopSending();
  for (auto [id, ec] : stopSendingStreamsCopy) {
    connectionCallbacks_.connection()->onStopSending(id, ec);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
    auto it = stopSendingCallbacks_.find(id);
    if (it != stopSendingCallbacks_.end()) {
      // onStopSending() may re-enter setStopSendingCallback() and insert into
      // stopSendingCallbacks_, rehashing the map and invalidating it. Erase
      // before invoking the callback so it is never reused across it.
      auto cb = it->second;
      stopSendingCallbacks_.erase(it);
      cb->onStopSending(id, ec);
      if (closeState_ != CloseState::OPEN) {
        return;
      }
    }
  }
}

void QuicTransportBaseLite::handleConnWritable() {
  auto maxConnWrite = maxWritableOnConn();
  if (maxConnWrite != 0) {
    // If the connection now has flow control, we may either have been blocked
    // before on a pending write to the conn, or a stream's write.
    if (connWriteCallback_) {
      auto connWriteCallback = connWriteCallback_;
      connWriteCallback_ = nullptr;
      connWriteCallback->onConnectionWriteReady(maxConnWrite);
    }

    // If the connection flow control is unblocked, we might be unblocked on
    // the streams now. Snapshot the ids first: onStreamWriteReady() may
    // re-enter notifyPendingWriteOnStream() and insert into
    // pendingWriteCallbacks_, rehashing the map and invalidating any iterator
    // held across the callback.
    std::vector<StreamId> pendingWriteStreamIds;
    pendingWriteStreamIds.reserve(pendingWriteCallbacks_.size());
    for (const auto& pendingWriteCallback : pendingWriteCallbacks_) {
      pendingWriteStreamIds.push_back(pendingWriteCallback.first);
    }

    for (auto streamId : pendingWriteStreamIds) {
      auto writeCallbackIt = pendingWriteCallbacks_.find(streamId);
      if (writeCallbackIt == pendingWriteCallbacks_.end()) {
        continue;
      }
      auto wcb = writeCallbackIt->second;
      auto stream = MVCHECK_NOTNULL(
          conn_->streamManager->getStream(streamId).value_or(nullptr));
      if (!stream->writable()) {
        pendingWriteCallbacks_.erase(streamId);
        continue;
      }
      auto maxStreamWritable = maxWritableOnStream(*stream);
      if (maxStreamWritable != 0) {
        pendingWriteCallbacks_.erase(streamId);
        wcb->onStreamWriteReady(streamId, maxStreamWritable);
        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
  }
}

void QuicTransportBaseLite::cleanupAckEventState() {
  // if there's no bytes in flight, clear any memory allocated for AckEvents
  if (conn_->outstandings.packets.empty()) {
    std::vector<AckEvent> empty;
    conn_->lastProcessedAckEvents.swap(empty);
  } // memory allocated for vector will be freed
}

quic::Expected<WriteQuicDataResult, QuicError>
QuicTransportBaseLite::handleInitialWriteDataCommon(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    uint64_t packetLimit,
    const std::string& token) {
  MVCHECK(conn_->initialWriteCipher);
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  auto& initialCryptoStream =
      *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Initial);
  CryptoStreamScheduler initialScheduler(*conn_, initialCryptoStream);
  auto& numProbePackets =
      conn_->pendingEvents.numProbePackets[PacketNumberSpace::Initial];
  if ((initialCryptoStream.retransmissionBuffer.size() &&
       conn_->outstandings.packetCount[PacketNumberSpace::Initial] &&
       numProbePackets) ||
      (numProbePackets && needsAntiDeadlockPTO(*conn_)) ||
      initialScheduler.hasData() || toWriteInitialAcks(*conn_)) {
    MVCHECK(conn_->initialHeaderCipher);
    return writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        dstConnId /* dst */,
        LongHeader::Types::Initial,
        *conn_->initialWriteCipher,
        *conn_->initialHeaderCipher,
        version,
        packetLimit,
        token);
  }
  return WriteQuicDataResult{};
}

quic::Expected<WriteQuicDataResult, QuicError>
QuicTransportBaseLite::handleHandshakeWriteDataCommon(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    uint64_t packetLimit) {
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  MVCHECK(conn_->handshakeWriteCipher);
  auto& handshakeCryptoStream =
      *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Handshake);
  CryptoStreamScheduler handshakeScheduler(*conn_, handshakeCryptoStream);
  auto& numProbePackets =
      conn_->pendingEvents.numProbePackets[PacketNumberSpace::Handshake];
  if ((conn_->outstandings.packetCount[PacketNumberSpace::Handshake] &&
       handshakeCryptoStream.retransmissionBuffer.size() && numProbePackets) ||
      (numProbePackets && needsAntiDeadlockPTO(*conn_)) ||
      handshakeScheduler.hasData() || toWriteHandshakeAcks(*conn_)) {
    MVCHECK(conn_->handshakeWriteHeaderCipher);
    return writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        dstConnId /* dst */,
        LongHeader::Types::Handshake,
        *conn_->handshakeWriteCipher,
        *conn_->handshakeWriteHeaderCipher,
        version,
        packetLimit);
  }
  return WriteQuicDataResult{};
}

void QuicTransportBaseLite::closeUdpSocket() {
  if (!socket_) {
    return;
  }
  SOCKET_OBSERVER_IF_ANY(getSocketObserverContainer()) {
    SocketObserverInterface::ClosingEvent event; // empty for now
    getSocketObserverContainer()->invokeInterfaceMethodAllObservers(
        [&event](auto observer, auto observed) {
          observer->closing(observed, event);
        });
  }
  auto sock = std::move(socket_);
  socket_ = nullptr;
  sock->pauseRead();
  auto closeResult = sock->close();
  if (!closeResult.has_value()) {
    MVLOG_ERROR << "close hit an error: " << closeResult.error().message;
  }
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createStreamInternal(bool bidirectional) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  quic::Expected<QuicStreamState*, LocalErrorCode> streamResult;
  if (bidirectional) {
    streamResult = conn_->streamManager->createNextBidirectionalStream();
  } else {
    streamResult = conn_->streamManager->createNextUnidirectionalStream();
  }
  if (!streamResult.has_value()) {
    return quic::make_unexpected(streamResult.error());
  }

  auto* streamState = *streamResult;
  if (!streamState) {
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }

  const StreamId streamId = streamState->id;
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::streamEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::streamEvents>(
            [event = SocketObserverInterface::StreamOpenEvent(
                 streamId,
                 getStreamInitiator(streamId),
                 getStreamDirectionality(streamId))](
                auto observer, auto observed) {
              observer->streamOpened(observed, event);
            });
  }

  return streamId;
}

void QuicTransportBaseLite::cancelTimeout(QuicTimerCallback* callback) {
  callback->cancelTimerCallback();
}

void QuicTransportBaseLite::excessWriteTimeoutExpired() noexcept {
  auto writeDataReason = shouldWriteData(*conn_);
  if (writeDataReason != WriteDataReason::NO_WRITE) {
    pacedWriteDataToSocket();
  }
}

void QuicTransportBaseLite::lossTimeoutExpired() noexcept {
  MVCHECK_NE(closeState_, CloseState::CLOSED);
  // onLossDetectionAlarm will set packetToSend in pending events
  [[maybe_unused]] auto self = sharedGuard();
  try {
    auto result = onLossDetectionAlarm(*conn_, markPacketLoss);
    if (!result.has_value()) {
      closeImpl(QuicError(
          result.error().code, std::string("lossTimeoutExpired() error")));
      return;
    }

    // Fire path degradation / blackhole callbacks via pending events.
    // These are set by onPTOAlarm when ptoCount crosses thresholds.
    if (conn_->pendingEvents.notifyPathDegrading) {
      conn_->pendingEvents.notifyPathDegrading = false;
      if (connectionCallbacks_.connection()) {
        connectionCallbacks_.connection()->onPathDegrading();
      }
    }
    if (conn_->pendingEvents.notifyBlackholeDetected) {
      conn_->pendingEvents.notifyBlackholeDetected = false;
      if (connectionCallbacks_.connection()) {
        connectionCallbacks_.connection()->onBlackholeDetected();
      }
    }

    pacedWriteDataToSocket();
  } catch (const std::exception& ex) {
    handleExceptionAndClose(ex, "lossTimeoutExpired() error");
  }
}

void QuicTransportBaseLite::idleTimeoutExpired(bool drain) noexcept {
  MVVLOG(4) << __func__ << " " << *this;
  [[maybe_unused]] auto self = sharedGuard();
  const auto now = Clock::now();
  if (idleTimeoutDeadline_.has_value() && now >= *idleTimeoutDeadline_) {
    lastIdleDeadlineOverdue_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now - *idleTimeoutDeadline_);
  }
  // idle timeout is expired, just close the connection and drain or
  // send connection close immediately depending on 'drain'
  MVDCHECK_NE(closeState_, CloseState::CLOSED);
  auto localError =
      drain ? LocalErrorCode::IDLE_TIMEOUT : LocalErrorCode::SHUTTING_DOWN;
  auto sendCloseImmediately =
      conn_->transportSettings.alwaysSendConnectionCloseOnIdleTimeout ? true
                                                                      : !drain;

  auto localIdleTimeout = conn_->transportSettings.idleTimeout;
  auto peerIdleTimeout =
      conn_->peerIdleTimeout > 0ms ? conn_->peerIdleTimeout : localIdleTimeout;
  auto idleTimeout = timeMin(localIdleTimeout, peerIdleTimeout);
  auto idleTimeoutCount = idleTimeout.count();
  closeImpl(
      quic::QuicError(
          QuicErrorCode(localError),
          fmt::format(
              "{}: {} seconds timeout",
              toString(localError),
              idleTimeoutCount / 1000)),
      drain /* drainConnection */,
      sendCloseImmediately);
}

void QuicTransportBaseLite::sendPing(
    std::chrono::milliseconds /* pingTimeout */) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);
}

void QuicTransportBaseLite::keepaliveTimeoutExpired() noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  ++keepaliveTimeoutFiredCount_;
  const auto now = Clock::now();
  const bool idleDeadlineExpired =
      idleTimeoutDeadline_.has_value() && now >= *idleTimeoutDeadline_;
  if (idleDeadlineExpired) {
    ++keepaliveExpiredIdleDeadlineCount_;
    lastIdleDeadlineOverdue_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now - *idleTimeoutDeadline_);
    if (conn_->transportSettings.prioritizeExpiredIdleTimeout) {
      idleTimeoutExpired(true /* drain */);
      return;
    }
  }
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);
}

void QuicTransportBaseLite::ackTimeoutExpired() noexcept {
  MVCHECK_NE(closeState_, CloseState::CLOSED);
  MVVLOG(10) << __func__ << " " << *this;
  [[maybe_unused]] auto self = sharedGuard();
  updateAckStateOnAckTimeout(*conn_);
  pacedWriteDataToSocket();
}

void QuicTransportBaseLite::pathValidationTimeoutExpired() noexcept {
  // Pass the signal to the path manager. Responding to the result of the path
  // validation is handled in the path validation callback in the client/server
  // transport.
  [[maybe_unused]] auto self = sharedGuard();
  conn_->pathManager->onPathValidationTimeoutExpired();
}

void QuicTransportBaseLite::drainTimeoutExpired() noexcept {
  // Drop the non-owning logger pointer before the transport leaves the worker
  // lifecycle. The worker thread-local storage owns the actual logger.
  conn_->oopsLogger = nullptr;
  closeUdpSocket();
  unbindConnection();
}

// Empty implementations for Peek/Ping/Datagram - overridden in
// QuicTransportBase
void QuicTransportBaseLite::updatePeekLooper() {}

void QuicTransportBaseLite::invokePeekDataAndCallbacks() {}

void QuicTransportBaseLite::handlePingCallbacks() {}

void QuicTransportBaseLite::cleanupPeekPingDatagramResources() {}

void QuicTransportBaseLite::cancelPeekPingDatagramCallbacks(
    const QuicError& /* err */) {}

bool QuicTransportBaseLite::hasPeekCallback(StreamId /* id */) {
  return false;
}

void QuicTransportBaseLite::invokeDatagramCallbackIfSet() {
  if (datagramCallback_ && !conn_->datagramState.readBuffer.empty()) {
    datagramCallback_->onDatagramsAvailable();
  }
}

bool QuicTransportBaseLite::processCancelCode(const QuicError& cancelCode) {
  bool noError = false;
  switch (cancelCode.code.type()) {
    case QuicErrorCode::Type::LocalErrorCode: {
      LocalErrorCode localErrorCode = *cancelCode.code.asLocalErrorCode();
      noError = localErrorCode == LocalErrorCode::NO_ERROR ||
          localErrorCode == LocalErrorCode::IDLE_TIMEOUT ||
          localErrorCode == LocalErrorCode::SHUTTING_DOWN;
      break;
    }
    case QuicErrorCode::Type::TransportErrorCode: {
      TransportErrorCode transportErrorCode =
          *cancelCode.code.asTransportErrorCode();
      noError = transportErrorCode == TransportErrorCode::NO_ERROR;
      break;
    }
    case QuicErrorCode::Type::ApplicationErrorCode:
      auto appErrorCode = *cancelCode.code.asApplicationErrorCode();
      noError = appErrorCode == APP_NO_ERROR;
  }
  return noError;
}

uint64_t QuicTransportBaseLite::maxWritableOnConn() const {
  auto connWritableBytes = getSendConnFlowControlBytesAPI(*conn_);
  auto availableBufferSpace = bufferSpaceAvailable();
  uint64_t ret = std::min(connWritableBytes, availableBufferSpace);
  uint8_t multiplier = conn_->transportSettings.backpressureHeadroomFactor;
  if (multiplier > 0) {
    auto headRoom = multiplier * congestionControlWritableBytes(*conn_);
    auto bufferLen = conn_->flowControlState.sumCurStreamBufferLen;
    headRoom -= bufferLen > headRoom ? headRoom : bufferLen;
    ret = std::min(ret, headRoom);
  }
  return ret;
}

void QuicTransportBaseLite::cancelAllAppCallbacks(
    const QuicError& err) noexcept {
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updateWriteLooper(true);
  };
  conn_->streamManager->clearActionable();
  // Cancel any pending ByteEvent callbacks
  cancelAllByteEventCallbacks();
  // TODO: this will become simpler when we change the underlying data
  // structure of read callbacks.
  // TODO: this approach will make the app unable to setReadCallback to
  // nullptr during the loop. Need to fix that.
  auto readCallbacksCopy = readCallbacks_;
  for (auto& cb : readCallbacksCopy) {
    auto streamId = cb.first;
    auto it = readCallbacks_.find(streamId);
    if (it == readCallbacks_.end()) {
      // An earlier call to readError removed the stream from readCallbacks
      // May not be possible?
      continue;
    }
    if (it->second.readCb) {
      it->second.readCb->readError(streamId, err);
    }
    readCallbacks_.erase(it);
  }
  // TODO: what if a call to readError installs a new read callback?
  if (!readCallbacks_.empty()) {
    MVLOG_ERROR << readCallbacks_.size()
                << " read callbacks remaining to be cleared";
  }

  if (connWriteCallback_) {
    auto connWriteCallback = connWriteCallback_;
    connWriteCallback_ = nullptr;
    connWriteCallback->onConnectionWriteError(err);
  }
  auto pendingWriteCallbacksCopy = pendingWriteCallbacks_;
  for (auto& wcb : pendingWriteCallbacksCopy) {
    pendingWriteCallbacks_.erase(wcb.first);
    wcb.second->onStreamWriteError(wcb.first, err);
  }

  // Cancel peek/ping/datagram callbacks (virtual method overridden in Base)
  cancelPeekPingDatagramCallbacks(err);
  datagramCallback_ = nullptr;

  stopSendingCallbacks_.clear();
}

void QuicTransportBaseLite::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  if (evb_) {
    evb_->scheduleTimeout(callback, timeout);
  }
}

void QuicTransportBaseLite::scheduleLossTimeout(
    std::chrono::milliseconds timeout) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  timeout = timeMax(timeout, evb_->getTimerTickInterval());
  scheduleTimeout(&lossTimeout_, timeout);
}

void QuicTransportBaseLite::cancelLossTimeout() {
  cancelTimeout(&lossTimeout_);
}

bool QuicTransportBaseLite::isLossTimeoutScheduled() {
  return isTimeoutScheduled(&lossTimeout_);
}

size_t QuicTransportBaseLite::getNumByteEventCallbacksForStream(
    const StreamId id) const {
  size_t total = 0;
  invokeForEachByteEventTypeConst(
      ([this, id, &total](const ByteEvent::Type type) {
        total += getNumByteEventCallbacksForStream(type, id);
      }));
  return total;
}

size_t QuicTransportBaseLite::getNumByteEventCallbacksForStream(
    const ByteEvent::Type type,
    const StreamId id) const {
  const auto& byteEventMap = getByteEventMapConst(type);
  const auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    return 0;
  }
  const auto& streamByteEvents = byteEventMapIt->second;
  return streamByteEvents.size();
}

void QuicTransportBaseLite::cancelAllByteEventCallbacks() {
  invokeForEachByteEventType(
      ([this](const ByteEvent::Type type) { cancelByteEventCallbacks(type); }));
}

void QuicTransportBaseLite::cancelByteEventCallbacks(
    const ByteEvent::Type type) {
  ByteEventMap byteEventMap = std::move(getByteEventMap(type));
  for (const auto& [streamId, cbMap] : byteEventMap) {
    for (const auto& [offset, cb] : cbMap) {
      ByteEventCancellation cancellation{streamId, offset, type};
      cb->onByteEventCanceled(cancellation);
    }
  }
}

QuicNodeType QuicTransportBaseLite::getNodeType() const noexcept {
  return conn_->nodeType;
}

QuicConnectionStats QuicTransportBaseLite::getConnectionsStats() const {
  QuicConnectionStats connStats;
  if (!conn_) {
    return connStats;
  }
  connStats.peerAddress = conn_->peerAddress;
  connStats.duration = Clock::now() - conn_->connectionTime;
  if (conn_->congestionController) {
    connStats.cwnd_bytes = conn_->congestionController->getCongestionWindow();
    connStats.congestionController = conn_->congestionController->type();
    conn_->congestionController->getStats(connStats.congestionControllerStats);
  }
  connStats.ptoCount = conn_->lossState.ptoCount;
  connStats.srtt = conn_->lossState.srtt;
  connStats.mrtt = conn_->lossState.mrtt;
  connStats.lrtt = conn_->lossState.lrtt;
  connStats.rttvar = conn_->lossState.rttvar;
  connStats.peerAckDelayExponent = conn_->peerAckDelayExponent;
  connStats.udpSendPacketLen = conn_->udpSendPacketLen;
  if (conn_->streamManager) {
    connStats.numStreams = conn_->streamManager->streams().size();
  }

  if (conn_->clientChosenDestConnectionId.has_value()) {
    connStats.clientChosenDestConnectionId =
        conn_->clientChosenDestConnectionId->hex();
  }
  if (conn_->clientConnectionId.has_value()) {
    connStats.clientConnectionId = conn_->clientConnectionId->hex();
  }
  if (conn_->serverConnectionId.has_value()) {
    connStats.serverConnectionId = conn_->serverConnectionId->hex();
  }

  connStats.totalBytesSent = conn_->lossState.totalBytesSent;
  connStats.totalBytesReceived = conn_->lossState.totalBytesRecvd;
  connStats.totalBytesRetransmitted = conn_->lossState.totalBytesRetransmitted;
  if (conn_->version.has_value()) {
    connStats.version = static_cast<uint32_t>(*conn_->version);
  }
  return connStats;
}

Optional<QuicSocketLite::SconeRateInfo>
QuicTransportBaseLite::consumePendingSconeRate() {
  if (!conn_->scone || !conn_->scone->pendingReceivedSignal) {
    return std::nullopt;
  }
  auto signal = conn_->scone->pendingReceivedSignal.value();
  conn_->scone->pendingReceivedSignal.reset();
  Optional<uint64_t> advisedBps;
  if (signal.rate != kSconeNoAdvice) {
    advisedBps = static_cast<uint64_t>(
        100000.0 * std::pow(10.0, static_cast<double>(signal.rate) / 20.0));
  }
  return SconeRateInfo{
      .rateSignal = signal.rate,
      .advisedBps = advisedBps,
      .receivedTime = signal.receivedTime};
}

const TransportSettings& QuicTransportBaseLite::getTransportSettings() const {
  return conn_->transportSettings;
}

bool QuicTransportBaseLite::isTimeoutScheduled(
    QuicTimerCallback* callback) const {
  return callback->isTimerCallbackScheduled();
}

void QuicTransportBaseLite::invokeReadDataAndCallbacks(
    bool updateLoopersAndCheckForClosedStream) {
  auto self = sharedGuard();
  SCOPE_EXIT {
    if (updateLoopersAndCheckForClosedStream) {
      self->checkForClosedStream();
      self->updateReadLooper();
      self->updateWriteLooper(true);
    }
  };
  // Need a copy since the set can change during callbacks.
  std::vector<StreamId> readableStreamsCopy;

  const auto& readableStreams = self->conn_->streamManager->readableStreams();

  readableStreamsCopy.reserve(readableStreams.size());

  std::copy(
      readableStreams.begin(),
      readableStreams.end(),
      std::back_inserter(readableStreamsCopy));

  if (self->conn_->transportSettings.orderedReadCallbacks) {
    std::sort(readableStreamsCopy.begin(), readableStreamsCopy.end());
  }

  for (StreamId streamId : readableStreamsCopy) {
    auto callback = self->readCallbacks_.find(streamId);
    if (callback == self->readCallbacks_.end()) {
      // Stream doesn't have a read callback set, skip it.
      continue;
    }
    auto readCb = callback->second.readCb;
    auto stream = MVCHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    if (readCb && stream->streamReadError &&
        (!stream->reliableSizeFromPeer ||
         *stream->reliableSizeFromPeer <= stream->currentReadOffset)) {
      // If we got a reliable reset from the peer, we don't fire the readError
      // callback and remove it until we've read all of the reliable data.
      self->conn_->streamManager->readableStreams().erase(streamId);
      readCallbacks_.erase(callback);
      // if there is an error on the stream - it's not readable anymore, so
      // we cannot peek into it as well.
      self->conn_->streamManager->peekableStreams().erase(streamId);
      MVVLOG(10) << "invoking read error callbacks on stream=" << streamId
                 << " " << *this;
      readCb->readError(streamId, QuicError(*stream->streamReadError));
    } else if (
        readCb && callback->second.resumed && stream->hasReadableData()) {
      MVVLOG(10) << "invoking read callbacks on stream=" << streamId << " "
                 << *this;
      readCb->readAvailable(streamId);
    }
  }

  if (self->conn_->scone) {
    while (!self->conn_->scone->pendingRateSignals.empty()) {
      auto rateSignal = self->conn_->scone->pendingRateSignals.front();
      self->conn_->scone->pendingRateSignals.pop_front();

      VLOG(4) << "Received SCONE rate signal: "
              << static_cast<int>(rateSignal.rate);
      if (self->conn_->qLogger) {
        self->conn_->qLogger->addTransportStateUpdate(
            fmt::format("scone_rate_signal:{}", rateSignal.rate));
      }

      // Store as edge-triggered pending signal for consumePendingSconeRate().
      // If multiple signals arrive in one loop, the latest one wins.
      self->conn_->scone->pendingReceivedSignal = {
          .rate = rateSignal.rate,
          .version = rateSignal.version,
          .receivedTime = Clock::now()};

      if (self->connectionCallbacks_.connection()) {
        self->connectionCallbacks_.connection()->onSconeRateSignal(
            rateSignal.rate, rateSignal.version);
      }
    }
  }

  // Invoke datagram callback if there are datagrams available
  invokeDatagramCallbackIfSet();
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::setReadCallbackInternal(
    StreamId id,
    ReadCallback* cb,
    Optional<ApplicationErrorCode> err) noexcept {
  MVVLOG(4) << "Setting setReadCallback for stream=" << id << " cb=" << cb
            << " " << *this;
  auto readCbIt = readCallbacks_.find(id);
  if (readCbIt == readCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    readCbIt = readCallbacks_.emplace(id, ReadCallbackData(cb)).first;
  }
  auto& readCb = readCbIt->second.readCb;
  if (readCb == nullptr && cb != nullptr) {
    // It's already been set to nullptr we do not allow unsetting it.
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  } else {
    readCb = cb;
    if (readCb == nullptr && err) {
      return stopSending(id, err.value());
    }
  }
  updateReadLooper();
  return {};
}

Optional<folly::SocketCmsgMap>
QuicTransportBaseLite::getAdditionalCmsgsForAsyncUDPSocket() {
  if (conn_->socketCmsgsState.additionalCmsgs) {
    // This callback should be happening for the target write
    MVDCHECK(conn_->writeCount == conn_->socketCmsgsState.targetWriteCount);
    return conn_->socketCmsgsState.additionalCmsgs;
  }
  return std::nullopt;
}

void QuicTransportBaseLite::notifyStartWritingFromAppRateLimited() {
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::appRateLimitedEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::appRateLimitedEvents>(
            [event =
                 SocketObserverInterface::AppLimitedEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .build()](auto observer, auto observed) {
              observer->startWritingFromAppLimited(observed, event);
            });
  }
}

void QuicTransportBaseLite::notifyPacketsWritten(
    const uint64_t numPacketsWritten,
    const uint64_t numAckElicitingPacketsWritten,
    const uint64_t numBytesWritten) {
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::packetsWrittenEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::packetsWrittenEvents>(
            [event =
                 SocketObserverInterface::PacketsWrittenEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .setNumPacketsWritten(numPacketsWritten)
                     .setNumAckElicitingPacketsWritten(
                         numAckElicitingPacketsWritten)
                     .setNumBytesWritten(numBytesWritten)
                     .build()](auto observer, auto observed) {
              observer->packetsWritten(observed, event);
            });
  }
}

void QuicTransportBaseLite::notifyAppRateLimited() {
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::appRateLimitedEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::appRateLimitedEvents>(
            [event =
                 SocketObserverInterface::AppLimitedEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .build()](auto observer, auto observed) {
              observer->appRateLimited(observed, event);
            });
  }
}

void QuicTransportBaseLite::onTransportKnobs(BufPtr knobBlob) {
  // Not yet implemented,
  MVVLOG(4) << "Received transport knobs: " << knobBlob->toString();
}

void QuicTransportBaseLite::processCallbacksAfterWriteData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  auto txStreamId = conn_->streamManager->popTx();
  while (txStreamId.has_value()) {
    auto streamId = *txStreamId;
    auto stream = MVCHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    auto largestOffsetTxed = getLargestWriteOffsetTxed(*stream);
    // if it's in the set of streams with TX, we should have a valid offset
    MVCHECK(largestOffsetTxed.has_value());

    // lambda to help get the next callback to call for this stream
    auto getNextTxCallbackForStreamAndCleanup =
        [this, &largestOffsetTxed](
            const auto& streamId) -> Optional<ByteEventDetail> {
      auto txCallbacksForStreamIt = txCallbacks_.find(streamId);
      if (txCallbacksForStreamIt == txCallbacks_.end() ||
          txCallbacksForStreamIt->second.empty()) {
        return std::nullopt;
      }

      auto& txCallbacksForStream = txCallbacksForStreamIt->second;
      if (txCallbacksForStream.front().offset > *largestOffsetTxed) {
        return std::nullopt;
      }

      // extract the callback, pop from the queue, then check for cleanup
      auto result = txCallbacksForStream.front();
      txCallbacksForStream.pop_front();
      if (txCallbacksForStream.empty()) {
        txCallbacks_.erase(txCallbacksForStreamIt);
      }
      return result;
    };

    Optional<ByteEventDetail> nextOffsetAndCallback;
    while (
        (nextOffsetAndCallback =
             getNextTxCallbackForStreamAndCleanup(streamId))) {
      ByteEvent byteEvent{
          streamId, nextOffsetAndCallback->offset, ByteEvent::Type::TX};
      nextOffsetAndCallback->callback->onByteEvent(byteEvent);

      // connection may be closed by callback
      if (closeState_ != CloseState::OPEN) {
        return;
      }
    }

    // pop the next stream
    txStreamId = conn_->streamManager->popTx();
  }
}

void QuicTransportBaseLite::setIdleTimer() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  idleTimeoutDeadline_.reset();
  auto localIdleTimeout = conn_->transportSettings.idleTimeout;
  // The local idle timeout being zero means it is disabled.
  if (localIdleTimeout == 0ms) {
    return;
  }
  auto peerIdleTimeout =
      conn_->peerIdleTimeout > 0ms ? conn_->peerIdleTimeout : localIdleTimeout;
  auto idleTimeout = timeMin(localIdleTimeout, peerIdleTimeout);

  idleTimeoutDeadline_ = Clock::now() + idleTimeout;
  scheduleTimeout(&idleTimeout_, idleTimeout);
  auto idleTimeoutCount = idleTimeout.count();
  if (conn_->transportSettings.enableKeepalive) {
    auto keepAliveTimeout = conn_->transportSettings.keepAliveTimeout;
    if (keepAliveTimeout == 0ms) {
      keepAliveTimeout = std::chrono::milliseconds(
          idleTimeoutCount - static_cast<int64_t>(idleTimeoutCount * .15));
    }

    scheduleTimeout(&keepaliveTimeout_, keepAliveTimeout);
  }
}

void QuicTransportBaseLite::setTransportSettings(
    TransportSettings transportSettings) {
  // If transport parameters are encoded, we can only update congestion
  // control related params. Setting other transport settings again would be
  // buggy.
  // TODO should we throw or return Expected here?
  if (conn_->transportParametersEncoded) {
    updateCongestionControlSettings(transportSettings);
  } else {
    if (conn_->nodeType == QuicNodeType::Client &&
        transportSettings.dataPathType == DataPathType::ContinuousMemory) {
      size_t capacity = 0;
      MVCHECK(
          folly::checked_mul(
              &capacity,
              static_cast<size_t>(kDefaultMaxUDPPayload),
              static_cast<size_t>(transportSettings.maxBatchSize)),
          "ContinuousMemory buffer capacity overflow");
      createBufAccessor(capacity);
    }
    conn_->transportSettings = std::move(transportSettings);
    if (conn_->transportSettings.advertiseSconeSupport ||
        conn_->transportSettings.enableSconeSend) {
      conn_->scone.emplace(QuicConnectionStateBase::SconeState{});
    }
    auto result = conn_->streamManager->refreshTransportSettings(
        conn_->transportSettings);
    LOG_IF(FATAL, !result.has_value()) << result.error().message;
    if (conn_->nodeType == QuicNodeType::Client &&
        conn_->transportSettings.isPriming) {
      setSupportedVersions({QuicVersion::MVFST_PRIMING});
      // always use the smaller packet size to ensure priming packets work
      // both with IPv4 and IPv6
      conn_->udpSendPacketLen = kDefaultUDPSendPacketLen;
    }
  }

  // A few values cannot be overridden to be lower than default:
  // TODO refactor transport settings to avoid having to update params twice.
  if (conn_->transportSettings.defaultCongestionController !=
      CongestionControlType::None) {
    conn_->transportSettings.initCwndInMss =
        std::max(conn_->transportSettings.initCwndInMss, kInitCwndInMss);
    conn_->transportSettings.minCwndInMss =
        std::max(conn_->transportSettings.minCwndInMss, kMinCwndInMss);
    conn_->transportSettings.initCwndInMss = std::max(
        conn_->transportSettings.minCwndInMss,
        conn_->transportSettings.initCwndInMss);
  }

  validateCongestionAndPacing(
      conn_->transportSettings.defaultCongestionController);
  if (conn_->transportSettings.pacingEnabled) {
    writeLooper_->enablePacingCallback();
    bool usingBbr =
        (conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBR ||
         conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBR2 ||
         conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBR2Modular);
    auto minCwnd =
        usingBbr ? kMinCwndInMssForBbr : conn_->transportSettings.minCwndInMss;
    conn_->pacer = createPacer(*conn_, minCwnd);
    // Only set canBePaced during initial setup. After handshake,
    // updatePacingOnKeyEstablished() already set canBePaced = true, and we
    // shouldn't reset it when updating transport settings.
    if (!conn_->transportParametersEncoded) {
      conn_->canBePaced = conn_->transportSettings.pacingEnabledFirstFlight;
    }
  }
  setCongestionControl(conn_->transportSettings.defaultCongestionController);
  if (conn_->transportSettings.datagramConfig.enabled) {
    conn_->datagramState.maxReadFrameSize = kMaxDatagramFrameSize;
    conn_->datagramState.maxReadBufferSize =
        conn_->transportSettings.datagramConfig.readBufSize;
    conn_->datagramState.maxWriteBufferSize =
        conn_->transportSettings.datagramConfig.writeBufSize;
  }

  updateSocketTosSettings(conn_->transportSettings.dscpValue);

  if (conn_->readCodec) {
    // Update the codec parameters. In case of the client, the codec was
    // initialized in the constructor and did not have the transport settings.
    CodecParameters codecParams(
        conn_->peerAckDelayExponent,
        conn_->originalVersion.value(),
        conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
        conn_->transportSettings.advertisedExtendedAckFeatures);
    codecParams.peerTimestampFrameTimestampExponent =
        conn_->peerTimestampFrameState.sendExponent;
    conn_->readCodec->setCodecParameters(std::move(codecParams));
  }
}

void QuicTransportBaseLite::setCongestionControl(CongestionControlType type) {
  MVDCHECK(conn_);
  if (!conn_->congestionController ||
      type != conn_->congestionController->type()) {
    MVCHECK(conn_->congestionControllerFactory);
    validateCongestionAndPacing(type);
    conn_->congestionController =
        conn_->congestionControllerFactory->makeCongestionController(
            *conn_, type);
    [[maybe_unused]] std::stringstream s;
    s << "CCA set to " << congestionControlTypeToString(type);
    QLOG(*conn_, addTransportStateUpdate, s.str());
  }
}

void QuicTransportBaseLite::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  conn_->originalVersion = versions.at(0);
  conn_->supportedVersions = versions;
}

void QuicTransportBaseLite::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  MVCHECK(ccFactory);
  MVCHECK(conn_);
  conn_->congestionControllerFactory = ccFactory;
  conn_->congestionController.reset();
}

void QuicTransportBaseLite::setBatchWriterFactoryOverride(
    quic::BatchWriterFactoryOverride override) {
  MVCHECK(conn_);
  conn_->batchWriterFactoryOverride = std::move(override);
}

void QuicTransportBaseLite::addPacketProcessor(
    std::shared_ptr<PacketProcessor> packetProcessor) {
  MVDCHECK(conn_);
  conn_->packetProcessors.push_back(std::move(packetProcessor));
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setKnob(
    uint64_t knobSpace,
    uint64_t knobId,
    BufPtr knobBlob) {
  if (isKnobSupported()) {
    sendSimpleFrame(*conn_, KnobFrame(knobSpace, knobId, std::move(knobBlob)));
    return {};
  }
  MVLOG_ERROR << "Cannot set knob. Peer does not support the knob frame";
  return quic::make_unexpected(LocalErrorCode::KNOB_FRAME_UNSUPPORTED);
}

bool QuicTransportBaseLite::isKnobSupported() const {
  return conn_->peerAdvertisedKnobFrameSupport;
}

void QuicTransportBaseLite::validateCongestionAndPacing(
    CongestionControlType& type) {
  // Fallback to Cubic if Pacing isn't enabled with BBR together
  if ((type == CongestionControlType::BBR ||
       type == CongestionControlType::BBR2 ||
       type == CongestionControlType::BBR2Modular) &&
      !conn_->transportSettings.pacingEnabled) {
    MVLOG_ERROR << "Unpaced BBR isn't supported";
    type = CongestionControlType::Cubic;
  }
}

void QuicTransportBaseLite::updateSocketTosSettings(uint8_t dscpValue) {
  const auto initialTosValue = conn_->socketTos.value;
  conn_->socketTos.fields.dscp = dscpValue;
  if (conn_->transportSettings.enableEcnOnEgress) {
    if (conn_->transportSettings.useL4sEcn) {
      conn_->socketTos.fields.ecn = kEcnECT1;
      conn_->ecnState = ECNState::AttemptingL4S;
    } else {
      conn_->socketTos.fields.ecn = kEcnECT0;
      conn_->ecnState = ECNState::AttemptingECN;
    }
  } else {
    conn_->socketTos.fields.ecn = 0;
    conn_->ecnState = ECNState::NotAttempted;
  }

  if (socket_ && socket_->isBound() &&
      conn_->socketTos.value != initialTosValue) {
    auto tosResult = socket_->setTosOrTrafficClass(conn_->socketTos.value);
    if (!tosResult.has_value()) {
      exceptionCloseWhat_ = tosResult.error().message;
      return closeImpl(tosResult.error());
    }
  }
}

quic::Expected<void, QuicError> QuicTransportBaseLite::validateECNState() {
  if (conn_->ecnState == ECNState::NotAttempted ||
      conn_->ecnState == ECNState::FailedValidation) {
    // Verification not needed
    return {};
  }
  const auto& minExpectedMarkedPacketsCount =
      conn_->ackStates.appDataAckState.minimumExpectedEcnMarksEchoed;
  if (minExpectedMarkedPacketsCount < 10) {
    // We wait for 10 ack-eliciting app data packets to be marked before trying
    // to validate ECN.
    return {};
  }
  const auto& maxExpectedMarkedPacketsCount = conn_->lossState.totalPacketsSent;

  auto markedPacketCount = conn_->ackStates.appDataAckState.ecnCECountEchoed;

  if (conn_->ecnState == ECNState::AttemptingECN ||
      conn_->ecnState == ECNState::ValidatedECN) {
    // Check the number of marks seen (ECT0 + CE). ECT1 should be zero.
    markedPacketCount += conn_->ackStates.appDataAckState.ecnECT0CountEchoed;

    if (markedPacketCount >= minExpectedMarkedPacketsCount &&
        markedPacketCount <= maxExpectedMarkedPacketsCount &&
        conn_->ackStates.appDataAckState.ecnECT1CountEchoed == 0) {
      if (conn_->ecnState != ECNState::ValidatedECN) {
        conn_->ecnState = ECNState::ValidatedECN;
        MVVLOG(4) << fmt::format(
            "ECN validation successful. Marked {} of {} expected",
            markedPacketCount,
            minExpectedMarkedPacketsCount);
      }
    } else {
      conn_->ecnState = ECNState::FailedValidation;
      MVVLOG(4) << fmt::format(
          "ECN validation failed. Marked {} of {} expected",
          markedPacketCount,
          minExpectedMarkedPacketsCount);
    }
  } else if (
      conn_->ecnState == ECNState::AttemptingL4S ||
      conn_->ecnState == ECNState::ValidatedL4S) {
    // Check the number of marks seen (ECT1 + CE). ECT0 should be zero.
    markedPacketCount += conn_->ackStates.appDataAckState.ecnECT1CountEchoed;

    if (markedPacketCount >= minExpectedMarkedPacketsCount &&
        markedPacketCount <= maxExpectedMarkedPacketsCount &&
        conn_->ackStates.appDataAckState.ecnECT0CountEchoed == 0) {
      if (conn_->ecnState != ECNState::ValidatedL4S) {
        if (!conn_->ecnL4sTracker) {
          conn_->ecnL4sTracker = std::make_shared<EcnL4sTracker>(*conn_);
          addPacketProcessor(conn_->ecnL4sTracker);
        }
        conn_->ecnState = ECNState::ValidatedL4S;
        MVVLOG(4) << fmt::format(
            "L4S validation successful. Marked {} of {} expected",
            markedPacketCount,
            minExpectedMarkedPacketsCount);
      }
    } else {
      conn_->ecnState = ECNState::FailedValidation;
      MVVLOG(4) << fmt::format(
          "L4S validation failed. Marked {} of {} expected",
          markedPacketCount,
          minExpectedMarkedPacketsCount);
    }
  }

  if (conn_->ecnState == ECNState::FailedValidation) {
    conn_->socketTos.fields.ecn = 0;
    MVCHECK(socket_ && socket_->isBound());
    auto result = socket_->setTosOrTrafficClass(conn_->socketTos.value);
    if (!result.has_value()) {
      return result;
    }

    MVVLOG(4) << "ECN validation failed. Disabling ECN";
    if (conn_->ecnL4sTracker) {
      conn_->packetProcessors.erase(
          std::remove(
              conn_->packetProcessors.begin(),
              conn_->packetProcessors.end(),
              conn_->ecnL4sTracker),
          conn_->packetProcessors.end());
      conn_->ecnL4sTracker.reset();
    }
  }
  return {};
}

void QuicTransportBaseLite::scheduleAckTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (conn_->pendingEvents.scheduleAckTimeout) {
    if (!isTimeoutScheduled(&ackTimeout_)) {
      auto factoredRtt = std::chrono::duration_cast<std::chrono::microseconds>(
          conn_->transportSettings.ackTimerFactor * conn_->lossState.srtt);
      // If we are using ACK_FREQUENCY, disable the factored RTT heuristic
      // and only use the update max ACK delay.
      if (conn_->ackStates.appDataAckState.ackFrequencySequenceNumber) {
        factoredRtt = conn_->ackStates.maxAckDelay;
      }
      auto timeout = timeMax(
          std::chrono::duration_cast<std::chrono::microseconds>(
              evb_->getTimerTickInterval()),
          timeMin(conn_->ackStates.maxAckDelay, factoredRtt));
      auto timeoutMs = std::chrono::ceil<std::chrono::milliseconds>(timeout);
      MVVLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms"
                 << " factoredRtt=" << factoredRtt.count() << "us" << " "
                 << *this;
      scheduleTimeout(&ackTimeout_, timeoutMs);
    }
  } else {
    if (isTimeoutScheduled(&ackTimeout_)) {
      MVVLOG(10) << __func__ << " cancel timeout " << *this;
      cancelTimeout(&ackTimeout_);
    }
  }
}

void QuicTransportBaseLite::schedulePathValidationTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (!conn_->pendingEvents.schedulePathValidationTimeout) {
    if (isTimeoutScheduled(&pathValidationTimeout_)) {
      MVVLOG(10) << __func__ << " cancel timeout " << *this;
      // This means path validation succeeded, and we should have updated to
      // correct state
      cancelTimeout(&pathValidationTimeout_);
    }
  } else if (!isTimeoutScheduled(&pathValidationTimeout_)) {
    auto nextTimeout = conn_->pathManager->getEarliestChallengeTimeout();
    if (nextTimeout.has_value()) {
      auto timeoutMs = *nextTimeout > Clock::now()
          ? std::chrono::ceil<std::chrono::milliseconds>(
                *nextTimeout - Clock::now())
          : 0ms;
      MVVLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms "
                 << *this;
      scheduleTimeout(&pathValidationTimeout_, timeoutMs);
    }
  }
}

/**
 * Getters for details from the transport/security layers such as
 * RTT, rxmit, cwnd, mss, app protocol, handshake latency,
 * client proposed ciphers, etc.
 */

QuicSocketLite::TransportInfo QuicTransportBaseLite::getTransportInfo() const {
  CongestionControlType congestionControlType = CongestionControlType::None;
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();
  uint64_t congestionWindow = std::numeric_limits<uint64_t>::max();
  Optional<CongestionController::State> maybeCCState;
  uint64_t burstSize = 0;
  std::chrono::microseconds pacingInterval = 0ms;
  if (conn_->congestionController) {
    congestionControlType = conn_->congestionController->type();
    writableBytes = conn_->congestionController->getWritableBytes();
    congestionWindow = conn_->congestionController->getCongestionWindow();
    maybeCCState = conn_->congestionController->getState();
    if (isConnectionPaced(*conn_)) {
      burstSize = conn_->pacer->getCachedWriteBatchSize();
      pacingInterval = conn_->pacer->getTimeUntilNextWrite();
    }
  }
  TransportInfo transportInfo;
  transportInfo.connectionTime = conn_->connectionTime;
  transportInfo.srtt = conn_->lossState.srtt;
  transportInfo.rttvar = conn_->lossState.rttvar;
  transportInfo.lrtt = conn_->lossState.lrtt;
  transportInfo.maybeLrtt = conn_->lossState.maybeLrtt;
  transportInfo.maybeLrttAckDelay = conn_->lossState.maybeLrttAckDelay;
  if (conn_->lossState.mrtt != kDefaultMinRtt) {
    transportInfo.maybeMinRtt = conn_->lossState.mrtt;
  }
  transportInfo.maybeMinRttNoAckDelay = conn_->lossState.maybeMrttNoAckDelay;
  transportInfo.mss = conn_->udpSendPacketLen;
  transportInfo.congestionControlType = congestionControlType;
  transportInfo.writableBytes = writableBytes;
  transportInfo.congestionWindow = congestionWindow;
  transportInfo.pacingBurstSize = burstSize;
  transportInfo.pacingInterval = pacingInterval;
  transportInfo.packetsRetransmitted = conn_->lossState.rtxCount;
  transportInfo.totalPacketsSent = conn_->lossState.totalPacketsSent;
  transportInfo.totalAckElicitingPacketsSent =
      conn_->lossState.totalAckElicitingPacketsSent;
  transportInfo.totalPacketsMarkedLost =
      conn_->lossState.totalPacketsMarkedLost;
  transportInfo.totalPacketsMarkedLostByTimeout =
      conn_->lossState.totalPacketsMarkedLostByTimeout;
  transportInfo.totalPacketsMarkedLostByReorderingThreshold =
      conn_->lossState.totalPacketsMarkedLostByReorderingThreshold;
  transportInfo.totalPacketsSpuriouslyMarkedLost =
      conn_->lossState.totalPacketsSpuriouslyMarkedLost;
  transportInfo.timeoutBasedLoss = conn_->lossState.timeoutBasedRtxCount;
  transportInfo.totalBytesRetransmitted =
      conn_->lossState.totalBytesRetransmitted;
  transportInfo.pto = calculatePTO(*conn_);
  transportInfo.bytesSent = conn_->lossState.totalBytesSent;
  transportInfo.bytesAcked = conn_->lossState.totalBytesAcked;
  transportInfo.bytesRecvd = conn_->lossState.totalBytesRecvd;
  transportInfo.bytesInFlight = conn_->lossState.inflightBytes;
  transportInfo.bodyBytesSent = conn_->lossState.totalBodyBytesSent;
  transportInfo.bodyBytesAcked = conn_->lossState.totalBodyBytesAcked;
  transportInfo.totalStreamBytesSent = conn_->lossState.totalStreamBytesSent;
  transportInfo.totalNewStreamBytesSent =
      conn_->lossState.totalNewStreamBytesSent;
  transportInfo.ptoCount = conn_->lossState.ptoCount;
  transportInfo.totalPTOCount = conn_->lossState.totalPTOCount;
  transportInfo.largestPacketAckedByPeer =
      conn_->ackStates.appDataAckState.largestAckedByPeer;
  transportInfo.largestPacketSent = conn_->lossState.largestSent;
  transportInfo.usedZeroRtt = conn_->usedZeroRtt;
  transportInfo.maybeCCState = maybeCCState;
  return transportInfo;
}

const quic::SocketAddress& QuicTransportBaseLite::getLocalAddress() const {
  return socket_ && socket_->isBound() ? socket_->addressRef()
                                       : localFallbackAddress;
}

void QuicTransportBaseLite::handleNewStreams(
    std::vector<StreamId>& streamStorage) {
  const auto& newPeerStreamIds = streamStorage;
  for (const auto& streamId : newPeerStreamIds) {
    MVCHECK_NOTNULL(connectionCallbacks_.connection().get());
    if (isBidirectionalStream(streamId)) {
      connectionCallbacks_.connection()->onNewBidirectionalStream(streamId);
    } else {
      connectionCallbacks_.connection()->onNewUnidirectionalStream(streamId);
    }

    logStreamOpenEvent(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
  streamStorage.clear();
}

void QuicTransportBaseLite::logStreamOpenEvent(StreamId streamId) {
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::streamEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::streamEvents>(
            [event = SocketObserverInterface::StreamOpenEvent(
                 streamId,
                 getStreamInitiator(streamId),
                 getStreamDirectionality(streamId))](
                auto observer, auto observed) {
              observer->streamOpened(observed, event);
            });
  }
}

bool QuicTransportBaseLite::hasDeliveryCallbacksToCall(
    StreamId streamId,
    uint64_t maxOffsetToDeliver) const {
  auto callbacksIt = deliveryCallbacks_.find(streamId);
  if (callbacksIt == deliveryCallbacks_.end() || callbacksIt->second.empty()) {
    return false;
  }

  return (callbacksIt->second.front().offset <= maxOffsetToDeliver);
}

void QuicTransportBaseLite::updatePacketProcessorsPrewriteRequests() {
  folly::SocketCmsgMap cmsgs;
  for (const auto& pp : conn_->packetProcessors) {
    // In case of overlapping cmsg keys, the priority is given to
    // that were added to the QuicSocket first.
    auto writeRequest = pp->prewrite();
    if (writeRequest && writeRequest->cmsgs) {
      cmsgs.insert(writeRequest->cmsgs->begin(), writeRequest->cmsgs->end());
    }
  }
  if (!cmsgs.empty()) {
    conn_->socketCmsgsState.additionalCmsgs = cmsgs;
  } else {
    conn_->socketCmsgsState.additionalCmsgs.reset();
  }
  conn_->socketCmsgsState.targetWriteCount = conn_->writeCount;
}

void QuicTransportBaseLite::updateCongestionControlSettings(
    const TransportSettings& transportSettings) {
  conn_->transportSettings.defaultCongestionController =
      transportSettings.defaultCongestionController;
  conn_->transportSettings.initCwndInMss = transportSettings.initCwndInMss;
  conn_->transportSettings.minCwndInMss = transportSettings.minCwndInMss;
  conn_->transportSettings.maxCwndInMss = transportSettings.maxCwndInMss;
  conn_->transportSettings.limitedCwndInMss =
      transportSettings.limitedCwndInMss;
  conn_->transportSettings.pacingEnabled = transportSettings.pacingEnabled;
  conn_->transportSettings.pacingEnabledFirstFlight =
      transportSettings.pacingEnabledFirstFlight;
  conn_->transportSettings.pacingTickInterval =
      transportSettings.pacingTickInterval;
  conn_->transportSettings.pacingTimerResolution =
      transportSettings.pacingTimerResolution;
  conn_->transportSettings.minBurstPackets = transportSettings.minBurstPackets;
  conn_->transportSettings.writeConnectionDataPacketsLimit =
      transportSettings.writeConnectionDataPacketsLimit;
  conn_->transportSettings.copaDeltaParam = transportSettings.copaDeltaParam;
  conn_->transportSettings.copaUseRttStanding =
      transportSettings.copaUseRttStanding;
}

void QuicTransportBaseLite::describe(std::ostream& os) const {
  MVCHECK(conn_);
  os << *conn_;
}

std::ostream& operator<<(std::ostream& os, const QuicTransportBaseLite& qt) {
  qt.describe(os);
  return os;
}

} // namespace quic
