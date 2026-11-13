/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportBase.h>
#include <quic/common/MvfstLogging.h>

#include <folly/Chrono.h>
#include <folly/ScopeGuard.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/Optional.h>
#include <quic/common/TimeUtil.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/observer/SocketObserverMacros.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <memory>

namespace {
/**
 * Helper function - if given error is not set, returns a generic app error.
 * Used by close() and closeNow().
 */
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;
} // namespace

namespace quic {

QuicTransportBase::QuicTransportBase(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBaseLite(
          std::move(evb),
          std::move(socket),
          useConnectionEndWithErrorCallback),
      pingTimeout_(this),
      peekLooper_(new TransportLooper(evb_, this, LooperType::PeekLooper)) {
  if (socket_) {
    std::function<Optional<folly::SocketCmsgMap>()> func = [&]() {
      return getAdditionalCmsgsForAsyncUDPSocket();
    };
    // TODO we probably should have a better way to return error from
    // creating a connection.
    // Can't really do anything with this at this point.
    (void)socket_->setAdditionalCmsgsFunc(std::move(func));
  }
}

void QuicTransportBase::setPacingTimer(
    QuicTimer::SharedPtr pacingTimer) noexcept {
  if (pacingTimer) {
    writeLooper_->setPacingTimer(std::move(pacingTimer));
  }
}

Optional<ConnectionId> QuicTransportBase::getClientConnectionId() const {
  return conn_->clientConnectionId;
}

Optional<ConnectionId> QuicTransportBase::getServerConnectionId() const {
  return conn_->serverConnectionId;
}

Optional<ConnectionId> QuicTransportBase::getClientChosenDestConnectionId()
    const {
  return conn_->clientChosenDestConnectionId;
}

QuicTransportBase::~QuicTransportBase() = default;

bool QuicTransportBase::replaySafe() const {
  return (conn_->oneRttWriteCipher != nullptr);
}

void QuicTransportBase::closeGracefully() {
  if (closeState_ == CloseState::CLOSED ||
      closeState_ == CloseState::GRACEFUL_CLOSING) {
    return;
  }
  [[maybe_unused]] auto self = sharedGuard();
  onApplicationClose();
  closeState_ = CloseState::GRACEFUL_CLOSING;
  updatePacingOnClose(*conn_);
  QLOG(*conn_, addConnectionClose, kNoError, kGracefulExit, true, false);

  // Stop reads and cancel all the app callbacks.
  MVVLOG(10) << "Stopping read and peek loopers due to graceful close "
             << *this;
  readLooper_->stop();
  peekLooper_->stop();
  cancelAllAppCallbacks(
      QuicError(QuicErrorCode(LocalErrorCode::NO_ERROR), "Graceful Close"));
  // All streams are closed or retired, close the transport for realz.
  if (canFinishGracefulClose()) {
    closeImpl(std::nullopt);
  }
}

quic::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamReadOffset(
    StreamId) const {
  return 0;
}

quic::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamWriteOffset(
    StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  try {
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    return stream->writeOffset();
  } catch (const QuicInternalException& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

quic::Expected<size_t, LocalErrorCode>
QuicTransportBase::getStreamWriteBufferedBytes(StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  try {
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    return stream->pendingWriteBytes();
  } catch (const QuicInternalException& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

quic::Expected<QuicSocket::FlowControlState, LocalErrorCode>
QuicTransportBase::getConnectionFlowControl() const {
  return QuicSocket::FlowControlState(
      getSendConnFlowControlBytesAPI(*conn_),
      conn_->flowControlState.peerAdvertisedMaxOffset,
      getRecvConnFlowControlBytes(*conn_),
      conn_->flowControlState.advertisedMaxOffset,
      maxWritableOnConn());
}

quic::Expected<uint64_t, LocalErrorCode>
QuicTransportBase::getMaxWritableOnStream(StreamId id) const {
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  return maxWritableOnStream(*stream);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setConnectionFlowControlWindow(uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  conn_->flowControlState.windowSize = windowSize;
  maybeSendConnWindowUpdate(*conn_, Clock::now());
  updateWriteLooper(true);
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setStreamFlowControlWindow(
    StreamId id,
    uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  stream->flowControlState.windowSize = windowSize;
  maybeSendStreamWindowUpdate(*stream, Clock::now());
  updateWriteLooper(true);
  return {};
}

void QuicTransportBase::unsetAllReadCallbacks() {
  for (const auto& [id, _] : readCallbacks_) {
    setReadCallbackInternal(id, nullptr, APP_NO_ERROR);
  }
}

void QuicTransportBase::unsetAllPeekCallbacks() {
  for (const auto& [id, _] : peekCallbacks_) {
    setPeekCallbackInternal(id, nullptr);
  }
}

void QuicTransportBase::unsetAllDeliveryCallbacks() {
  auto deliveryCallbacksCopy = deliveryCallbacks_;
  for (const auto& [id, _] : deliveryCallbacksCopy) {
    cancelDeliveryCallbacksForStream(id);
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPeekCallback(
    StreamId id,
    PeekCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setPeekCallbackInternal(id, cb);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPeekCallbackInternal(
    StreamId id,
    PeekCallback* cb) noexcept {
  MVVLOG(4) << "Setting setPeekCallback for stream=" << id << " cb=" << cb
            << " " << *this;
  auto peekCbIt = peekCallbacks_.find(id);
  if (peekCbIt == peekCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    peekCbIt = peekCallbacks_.emplace(id, PeekCallbackData(cb)).first;
  }
  if (!cb) {
    MVVLOG(10) << "Resetting the peek callback to nullptr " << "stream=" << id
               << " peekCb=" << peekCbIt->second.peekCb;
  }
  peekCbIt->second.peekCb = cb;
  updatePeekLooper();
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pausePeek(StreamId id) {
  MVVLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, false);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::resumePeek(
    StreamId id) {
  MVVLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, true);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pauseOrResumePeek(
    StreamId id,
    bool resume) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto peekCb = peekCallbacks_.find(id);
  if (peekCb == peekCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::APP_ERROR);
  }
  if (peekCb->second.resumed != resume) {
    peekCb->second.resumed = resume;
    updatePeekLooper();
  }
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::peek(
    StreamId id,
    FunctionRef<void(StreamId id, const folly::Range<PeekIterator>&)>
        peekCallback) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updatePeekLooper();
    updateWriteLooper(true);
  };

  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }

  if (stream->streamReadError) {
    switch (stream->streamReadError->type()) {
      case QuicErrorCode::Type::LocalErrorCode:
        return quic::make_unexpected(
            *stream->streamReadError->asLocalErrorCode());
      default:
        return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }

  peekDataFromQuicStream(*stream, std::move(peekCallback));
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::consume(
    StreamId id,
    size_t amount) {
  auto* stream = conn_->streamManager->getStreamIfExists(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto result = consume(id, stream->currentReadOffset, amount);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error().first);
  }
  return {};
}

quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>
QuicTransportBase::consume(StreamId id, uint64_t offset, size_t amount) {
  using ConsumeError = std::pair<LocalErrorCode, Optional<uint64_t>>;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::CONNECTION_CLOSED, std::nullopt});
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updatePeekLooper();
    updateReadLooper(); // consume may affect "read" API
    updateWriteLooper(true);
  };
  Optional<uint64_t> readOffset;
  try {
    auto* stream = conn_->streamManager->getStreamIfExists(id);
    if (!stream) {
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::STREAM_NOT_EXISTS, readOffset});
    }
    readOffset = stream->currentReadOffset;
    if (stream->currentReadOffset != offset) {
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
    }

    if (stream->streamReadError) {
      switch (stream->streamReadError->type()) {
        case QuicErrorCode::Type::LocalErrorCode:
          return quic::make_unexpected(
              ConsumeError{
                  *stream->streamReadError->asLocalErrorCode(), std::nullopt});
        default:
          return quic::make_unexpected(
              ConsumeError{LocalErrorCode::INTERNAL_ERROR, std::nullopt});
      }
    }

    auto consumeResult = consumeDataFromQuicStream(*stream, amount);
    if (!consumeResult.has_value()) {
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, std::nullopt});
    }
    return {};
  } catch (const QuicTransportException& ex) {
    MVVLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::TRANSPORT_ERROR, readOffset});
  } catch (const QuicInternalException& ex) {
    MVVLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return quic::make_unexpected(ConsumeError{ex.errorCode(), readOffset});
  } catch (const std::exception& ex) {
    MVVLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("consume() error")));
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::registerTxCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::TX, id, offset, cb);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPingCallback(
    PingCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  MVVLOG(4) << "Setting ping callback " << " cb=" << cb << " " << *this;

  pingCallback_ = cb;
  return {};
}

void QuicTransportBase::sendPing(std::chrono::milliseconds pingTimeout) {
  /* Step 0: Connection should not be closed */
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  // Step 1: Send a simple ping frame
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);

  // Step 2: Schedule the timeout on event base
  if (pingCallback_ && pingTimeout != 0ms) {
    schedulePingTimeout(pingCallback_, pingTimeout);
  }
}

void QuicTransportBase::schedulePingTimeout(
    PingCallback* pingCb,
    std::chrono::milliseconds timeout) {
  // if a ping timeout is already scheduled, nothing to do, return
  if (isTimeoutScheduled(&pingTimeout_)) {
    return;
  }

  pingCallback_ = pingCb;
  scheduleTimeout(&pingTimeout_, timeout);
}

void QuicTransportBase::setAckRxTimestampsEnabled(bool enableAckRxTimestamps) {
  if (!enableAckRxTimestamps) {
    conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        std::nullopt;
  }
}

void QuicTransportBase::setTimestampFrameWritingEnabled(bool enabled) {
  if (!enabled) {
    conn_->transportSettings.oneRttTimestampFrameWriteMode =
        TimestampFrameWriteMode::Disabled;
  }
}

void QuicTransportBase::setEarlyDataAppParamsHandler(
    EarlyDataAppParamsHandler* handler) {
  conn_->earlyDataAppParamsHandler = handler;
}

void QuicTransportBase::resetNonControlStreams(
    ApplicationErrorCode error,
    folly::StringPiece errorMsg) {
  std::vector<StreamId> nonControlStreamIds;
  nonControlStreamIds.reserve(conn_->streamManager->streamCount());
  conn_->streamManager->streamStateForEach(
      [&nonControlStreamIds](const auto& stream) {
        if (!stream.isControl) {
          nonControlStreamIds.push_back(stream.id);
        }
      });
  for (auto id : nonControlStreamIds) {
    if (isSendingStream(conn_->nodeType, id) || isBidirectionalStream(id)) {
      auto writeCallbackIt = pendingWriteCallbacks_.find(id);
      if (writeCallbackIt != pendingWriteCallbacks_.end()) {
        writeCallbackIt->second->onStreamWriteError(
            id, QuicError(error, errorMsg.str()));
      }
      // TODO: Change external API signature to return Expected instead of using
      // (void). Right now we apparently partially support this as a non error.
      (void)resetStream(id, error);
    }
    if (isReceivingStream(conn_->nodeType, id) || isBidirectionalStream(id)) {
      auto readCallbackIt = readCallbacks_.find(id);
      if (readCallbackIt != readCallbacks_.end() &&
          readCallbackIt->second.readCb) {
        readCallbackIt->second.readCb->readError(
            id, QuicError(error, errorMsg.str()));
      }
      peekCallbacks_.erase(id);
      (void)stopSending(id, error);
    }
  }
}

quic::Expected<uint32_t, LocalErrorCode>
QuicTransportBase::createDatagramFlowId() {
  auto flowId = nextDatagramFlowId_++;
  conn_->datagramState.flowManager.createFlow(flowId);
  return flowId;
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::writeDatagram(
    PriorityQueue::Priority priority,
    BufPtr buf,
    std::optional<std::chrono::milliseconds> maxQueueTime) {
  uint32_t ephemeralFlowId = nextDatagramFlowId_++;
  return writeDatagramInternal(
      std::move(buf), ephemeralFlowId, priority, true, maxQueueTime);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::writeDatagram(
    uint32_t flowId,
    BufPtr buf,
    uint64_t intraFlowPriority) {
  auto& flowManager = conn_->datagramState.flowManager;
  // A draining flow is refused here rather than in addDatagram: a full buffer
  // drops a queued datagram to make room before the write gets that far.
  if (!flowManager.hasFlow(flowId) || flowManager.isFlowDraining(flowId)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  return writeDatagramInternal(
      std::move(buf),
      flowId,
      std::nullopt,
      false,
      std::nullopt,
      intraFlowPriority);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setDatagramFlowPriority(
    uint32_t flowId,
    PriorityQueue::Priority priority) {
  auto result =
      conn_->datagramState.flowManager.setFlowPriority(flowId, priority);
  if (result.hasError()) {
    return quic::make_unexpected(result.error());
  }

  bool flowIsEmpty = result.value();

  // Only update PriorityQueue if flow is non-empty and scheduling is enabled
  if (!flowIsEmpty &&
      conn_->transportSettings.datagramConfig.scheduleDatagramsWithStreams &&
      conn_->streamManager) {
    auto id = PriorityQueue::Identifier::fromDatagramFlowID(flowId);
    conn_->streamManager->writeQueue().insertOrUpdate(id, priority);
  }

  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setDatagramFlowMaxQueueTime(
    uint32_t flowId,
    std::chrono::milliseconds maxTime) {
  return conn_->datagramState.flowManager.setMaxQueueTime(flowId, maxTime);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::closeDatagramFlow(
    uint32_t flowId) {
  if (flowId == kDefaultDatagramFlowId) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  auto& flowManager = conn_->datagramState.flowManager;
  auto result = flowManager.closeFlow(flowId);
  if (result.hasError()) {
    return quic::make_unexpected(result.error());
  }

  // Only drop the PriorityQueue entry if the flow is already gone. A flow that
  // is still draining has to stay schedulable; the scheduler erases its entry
  // when it writes the last datagram.
  if (!flowManager.hasFlow(flowId)) {
    maybeEraseDatagramFlowFromWriteQueue(flowId);
  }

  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::closeDatagramFlowNow(
    uint32_t flowId) {
  if (flowId == kDefaultDatagramFlowId) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  auto result = conn_->datagramState.flowManager.closeFlowNow(flowId);
  if (result.hasError()) {
    return quic::make_unexpected(result.error());
  }

  maybeEraseDatagramFlowFromWriteQueue(flowId);
  return {};
}

quic::Expected<PriorityQueue::Priority, LocalErrorCode>
QuicTransportBase::getStreamPriority(StreamId id) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (auto stream = conn_->streamManager->getStreamIfExists(id)) {
    return stream->priority;
  }
  return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
}

bool QuicTransportBase::isDetachable() {
  // only the client is detachable.
  return conn_->nodeType == QuicNodeType::Client;
}

void QuicTransportBase::attachEventBase(std::shared_ptr<QuicEventBase> evbIn) {
  MVVLOG(10) << __func__ << " " << *this;
  MVDCHECK(!getEventBase());
  MVDCHECK(evbIn && evbIn->isInEventBaseThread());
  evb_ = std::move(evbIn);
  if (socket_) {
    socket_->attachEventBase(evb_);
  }

  scheduleAckTimeout();
  schedulePathValidationTimeout();
  setIdleTimer();

  readLooper_->attachEventBase(evb_);
  peekLooper_->attachEventBase(evb_);
  writeLooper_->attachEventBase(evb_);
  updateReadLooper();
  updatePeekLooper();
  updateWriteLooper(false);

  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::evbEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::evbEvents>(
            [this](auto observer, auto observed) {
              observer->evbAttach(observed, evb_.get());
            });
  }
}

void QuicTransportBase::detachEventBase() {
  MVVLOG(10) << __func__ << " " << *this;
  MVDCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  if (socket_) {
    socket_->detachEventBase();
  }
  connWriteCallback_ = nullptr;
  pendingWriteCallbacks_.clear();
  cancelTimeout(&lossTimeout_);
  cancelTimeout(&ackTimeout_);
  cancelTimeout(&pathValidationTimeout_);
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  cancelTimeout(&drainTimeout_);
  readLooper_->detachEventBase();
  peekLooper_->detachEventBase();
  writeLooper_->detachEventBase();

#ifndef MVFST_USE_LIBEV
  SOCKET_OBSERVER_IF(
      getSocketObserverContainer(),
      SocketObserverInterface::Events::evbEvents) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::evbEvents>(
            [this](auto observer, auto observed) {
              observer->evbDetach(observed, evb_.get());
            });
  }
#endif

  evb_ = nullptr;
}

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

quic::Expected<void, LocalErrorCode>
QuicTransportBase::maybeResetStreamFromReadError(
    StreamId id,
    QuicErrorCode error) {
  if (quic::ApplicationErrorCode* code = error.asApplicationErrorCode()) {
    return resetStream(id, *code);
  }
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::updateReliableDeliveryCheckpoint(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream =
      MVCHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
  if (stream->sendState == StreamSendState::ResetSent) {
    // We already sent a reset, so there's really no reason why we should be
    // doing any more checkpointing, especially since we cannot
    // increase the reliable size in subsequent resets.
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  stream->reliableResetCheckpoint = stream->writeBufferEndOffset();
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::resetStreamReliably(
    StreamId id,
    ApplicationErrorCode errorCode) {
  return resetStreamInternal(id, errorCode, isReliableResetSupported());
}

bool QuicTransportBase::isReliableResetSupported() const {
  return conn_->transportSettings.advertisedReliableResetStreamSupport &&
      conn_->peerAdvertisedReliableStreamResetSupport;
}

void QuicTransportBase::setCmsgs(const folly::SocketCmsgMap& options) {
  // TODO figure out what we want to do here in the unlikely error case.
  (void)socket_->setCmsgs(options);
}

void QuicTransportBase::appendCmsgs(const folly::SocketCmsgMap& options) {
  // TODO figure out what we want to do here in the unlikely error case.
  (void)socket_->appendCmsgs(options);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setStreamRetransmissionDisabled(
    StreamId id,
    bool disabled) noexcept {
  auto stream = conn_->streamManager->findStream(id);
  if (!stream) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  stream->retransmissionDisabled_ = disabled;
  return {};
}

void QuicTransportBase::updatePeekLooper() {
  if (peekCallbacks_.empty() || closeState_ != CloseState::OPEN) {
    MVVLOG(10) << "Stopping peek looper " << *this;
    peekLooper_->stop();
    return;
  }
  MVVLOG(10) << "Updating peek looper, has "
             << conn_->streamManager->peekableStreams().size()
             << " peekable streams";
  auto iter = std::find_if(
      conn_->streamManager->peekableStreams().begin(),
      conn_->streamManager->peekableStreams().end(),
      [&peekCallbacks = peekCallbacks_](StreamId s) {
        MVVLOG(10) << "Checking stream=" << s;
        auto peekCb = peekCallbacks.find(s);
        if (peekCb == peekCallbacks.end()) {
          MVVLOG(10) << "No peek callbacks for stream=" << s;
          return false;
        }
        if (!peekCb->second.resumed) {
          MVVLOG(10) << "peek callback for stream=" << s << " not resumed";
        }

        if (!peekCb->second.peekCb) {
          MVVLOG(10) << "no peekCb in peekCb stream=" << s;
        }
        return peekCb->second.peekCb && peekCb->second.resumed;
      });
  if (iter != conn_->streamManager->peekableStreams().end()) {
    MVVLOG(10) << "Scheduling peek looper " << *this;
    peekLooper_->run();
  } else {
    MVVLOG(10) << "Stopping peek looper " << *this;
    peekLooper_->stop();
  }
}

void QuicTransportBase::invokePeekDataAndCallbacks() {
  auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  // TODO: add protection from calling "consume" in the middle of the peek -
  // one way is to have a peek counter that is incremented when peek calblack
  // is called and decremented when peek is done. once counter transitions
  // to 0 we can execute "consume" calls that were done during "peek", for that,
  // we would need to keep stack of them.
  std::vector<StreamId> peekableStreamsCopy;
  const auto& peekableStreams = conn_->streamManager->peekableStreams();
  peekableStreamsCopy.reserve(peekableStreams.size());
  std::copy(
      peekableStreams.begin(),
      peekableStreams.end(),
      std::back_inserter(peekableStreamsCopy));
  MVVLOG(10) << __func__
             << " peekableListCopy.size()=" << peekableStreamsCopy.size();
  for (StreamId streamId : peekableStreamsCopy) {
    auto callback = peekCallbacks_.find(streamId);
    // This is a likely bug. Need to think more on whether events can
    // be dropped
    // remove streamId from list of peekable - as opposed to "read",  "peek" is
    // only called once per streamId and not on every EVB loop until application
    // reads the data.
    conn_->streamManager->peekableStreams().erase(streamId);
    if (callback == peekCallbacks_.end()) {
      MVVLOG(10) << " No peek callback for stream=" << streamId;
      continue;
    }
    auto peekCb = callback->second.peekCb;
    auto stream = MVCHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    if (peekCb && stream->streamReadError) {
      MVVLOG(10) << "invoking peek error callbacks on stream=" << streamId
                 << " " << *this;
      peekCb->peekError(streamId, QuicError(*stream->streamReadError));
    } else if (
        peekCb && !stream->streamReadError && stream->hasPeekableData()) {
      MVVLOG(10) << "invoking peek callbacks on stream=" << streamId << " "
                 << *this;

      peekDataFromQuicStream(
          *stream,
          [&](StreamId id, const folly::Range<PeekIterator>& peekRange) {
            peekCb->onDataAvailable(id, peekRange);
          });
    } else {
      MVVLOG(10) << "Not invoking peek callbacks on stream=" << streamId;
    }
  }
}

void QuicTransportBase::handlePingCallbacks() {
  if (conn_->pendingEvents.notifyPingReceived && pingCallback_ != nullptr) {
    conn_->pendingEvents.notifyPingReceived = false;
    if (pingCallback_ != nullptr) {
      pingCallback_->onPing();
    }
  }

  if (!conn_->pendingEvents.cancelPingTimeout) {
    return; // nothing to cancel
  }
  if (!isTimeoutScheduled(&pingTimeout_)) {
    // set cancelpingTimeOut to false, delayed acks
    conn_->pendingEvents.cancelPingTimeout = false;
    return; // nothing to do, as timeout has already fired
  }
  cancelTimeout(&pingTimeout_);
  if (pingCallback_ != nullptr) {
    pingCallback_->pingAcknowledged();
  }
  conn_->pendingEvents.cancelPingTimeout = false;
}

void QuicTransportBase::pingTimeoutExpired() noexcept {
  // If timeout expired just call the  call back Provided
  if (pingCallback_ != nullptr) {
    pingCallback_->pingTimeout();
  }
}

void QuicTransportBase::cleanupPeekPingDatagramResources() {
  MVVLOG(10) << "Stopping peek looper due to close " << *this;
  peekLooper_->stop();
  cancelTimeout(&pingTimeout_);
}

void QuicTransportBase::cancelPeekPingDatagramCallbacks(const QuicError& err) {
  // Call error callbacks on all peek callbacks
  auto peekCallbacksCopy = peekCallbacks_;
  for (auto& [streamId, peekCbData] : peekCallbacksCopy) {
    if (peekCbData.peekCb) {
      peekCbData.peekCb->peekError(streamId, err);
    }
  }
  peekCallbacks_.clear();

  pingCallback_ = nullptr;
}

bool QuicTransportBase::hasPeekCallback(StreamId id) {
  auto peekCb = peekCallbacks_.find(id);
  return peekCb != peekCallbacks_.end() && peekCb->second.peekCb != nullptr;
}

} // namespace quic
