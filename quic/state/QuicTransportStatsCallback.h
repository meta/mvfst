/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/Optional.h>
#include <functional> // IWYU pragma: keep (std::invoke used in QUIC_STATS macros)
#include <string>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>

namespace quic {

/* Interface for Transport level stats per VIP (server)
 * Quic Transport expects applications to instantiate this per thread (and
 * do necessary aggregation at the application level).
 *
 * NOTE: since several of these methods are called for every single packets,
 * and every single connection, it is extremely important to not do any
 * blocking call in any of the implementation of these methods.
 */
class QuicTransportStatsCallback {
 public:
  enum class SocketErrorType : uint8_t {
    AGAIN,
    INVAL,
    MSGSIZE,
    NOBUFS,
    NOMEM,
    OTHER,
    MAX
  };

  virtual ~QuicTransportStatsCallback() = default;

  // packet level metrics
  virtual void onPacketReceived() = 0;

  virtual void onRxDelaySample(uint64_t rxDelay) = 0;

  virtual void onPacketsReceived(uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
      onPacketReceived();
    }
  }

  virtual void onDuplicatedPacketReceived() = 0;

  virtual void onOutOfOrderPacketReceived() = 0;

  virtual void onPacketProcessed() = 0;

  virtual void onPacketsProcessed(uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
      onPacketProcessed();
    }
  }

  virtual void onPacketSent() = 0;

  virtual void onPacketsSent(uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
      onPacketSent();
    }
  }

  virtual void onPacketRetransmission() = 0;

  virtual void onPacketLoss() = 0;

  virtual void onPacketLossByTimeout() = 0;

  virtual void onPacketLossByReorderingThreshold() = 0;

  virtual void onPacketSpuriousLoss() = 0;

  virtual void onPersistentCongestion() = 0;

  virtual void onPacketDropped(quic::PacketDropReason reason) = 0;

  virtual void onPacketForwarded() = 0;

  virtual void onForwardedPacketReceived() = 0;

  virtual void onForwardedPacketProcessed() = 0;

  // A packet matching none of a server worker's connections was delivered to
  // a connection of a linked worker (see QuicServer::setPredecessor()).
  virtual void onPacketRoutedToLinkedWorker() = 0;

  virtual void onClientInitialReceived(QuicVersion version) = 0;

  virtual void onNewConnectionAttemptRejected() = 0;

  virtual void onConnectionRateLimited() = 0;

  virtual void onConnectionWritableBytesLimited() = 0;

  virtual void onNewTokenReceived() = 0;

  virtual void onNewTokenIssued() = 0;

  virtual void onTokenDecryptFailure() = 0;

  // connection level metrics:
  virtual void onNewConnection() = 0;

  virtual void onConnectionClose(
      Optional<QuicErrorCode> code = std::nullopt) = 0;

  virtual void onConnectionCloseZeroBytesWritten() = 0;

  virtual void onConnectionMigration() = 0;

  virtual void onPathAdded() = 0;

  virtual void onPathValidationSuccess() = 0;

  virtual void onPathValidationFailure() = 0;

  // stream level metrics
  virtual void onNewQuicStream() = 0;

  virtual void onNewUnifiedAppStream() {}

  virtual void onQuicStreamClosed() = 0;

  virtual void onQuicStreamReset(QuicErrorCode code) = 0;

  // flow control / congestion control / loss recovery related metrics
  virtual void onConnFlowControlUpdate() = 0;

  virtual void onConnFlowControlBlocked() = 0;

  virtual void onStatelessReset() = 0;

  virtual void onStreamFlowControlUpdate() = 0;

  virtual void onStreamFlowControlBlocked() = 0;

  virtual void onCwndBlocked() = 0;

  virtual void onInflightBytesSample(uint64_t) = 0;

  virtual void onRttSample(uint64_t) = 0;

  virtual void onBandwidthSample(uint64_t) = 0;

  virtual void onCwndHintBytesSample(uint64_t cwndHintBytes) = 0;

  virtual void onCongestionControllerResumed() = 0;

  virtual void onNewCongestionController(CongestionControlType type) = 0;

  // retransmission timeout counter
  virtual void onPTO() = 0;

  // metrics to track bytes read from / written to wire
  virtual void onRead(size_t bufSize) = 0;

  virtual void onWrite(size_t bufSize) = 0;

  virtual void onUDPSocketWriteError(SocketErrorType errorType) = 0;

  virtual void onTransportKnobApplied(TransportKnobParamId knobType) = 0;

  virtual void onTransportKnobError(TransportKnobParamId knobType) = 0;

  virtual void onTransportKnobOutOfOrder(TransportKnobParamId knobType) = 0;

  virtual void onServerUnfinishedHandshake() = 0;

  virtual void onZeroRttBuffered() = 0;

  virtual void onZeroRttBufferedPruned() = 0;

  virtual void onZeroRttAccepted() = 0;

  virtual void onZeroRttRejected() = 0;

  virtual void onZeroRttPrimingAccepted() = 0;

  virtual void onZeroRttPrimingRejected() = 0;

  virtual void onDatagramRead(size_t datagramSize) = 0;

  virtual void onDatagramWrite(size_t datagramSize) = 0;

  virtual void onDatagramDroppedOnWrite() = 0;

  virtual void onDatagramDroppedOnRead() = 0;

  virtual void onShortHeaderPadding(size_t padSize) = 0;

  virtual void onShortHeaderPaddingBatch(uint32_t n, size_t padSize) {
    for (uint32_t i = 0; i + 1 < n; i++) {
      onShortHeaderPadding(0);
    }
    onShortHeaderPadding(padSize);
  }

  virtual void onPacerTimerLagged() = 0;

  virtual void onPeerMaxUniStreamsLimitSaturated() = 0;

  virtual void onPeerMaxBidiStreamsLimitSaturated() = 0;

  virtual void onConnectionIdCreated(size_t encodedTimes) = 0;

  virtual void onKeyUpdateAttemptInitiated() = 0;

  virtual void onKeyUpdateAttemptReceived() = 0;

  virtual void onKeyUpdateAttemptSucceeded() = 0;

  virtual void onSconePacketSent() = 0;

  virtual void onAckReceiveTimestampsReceived(
      uint64_t /* count */,
      FrameType /* frameType */) {}

  virtual void onTimestampFrameReceived() {}

  static const char* toString(SocketErrorType errorType) {
    switch (errorType) {
      case SocketErrorType::AGAIN:
        return "AGAIN";
      case SocketErrorType::INVAL:
        return "INVAL";
      case SocketErrorType::MSGSIZE:
        return "MSGSIZE";
      case SocketErrorType::NOBUFS:
        return "NOBUFS";
      case SocketErrorType::NOMEM:
        return "NOMEM";
      case SocketErrorType::OTHER:
        return "Other";
      case SocketErrorType::MAX:
      default:
        throw std::runtime_error("Undefined SocketErrorType");
    }
  }

  static SocketErrorType errnoToSocketErrorType(int err) {
    switch (err) {
      case EAGAIN:
        return SocketErrorType::AGAIN;
      case EINVAL:
        return SocketErrorType::INVAL;
      case EMSGSIZE:
        return SocketErrorType::MSGSIZE;
      case ENOBUFS:
        return SocketErrorType::NOBUFS;
      case ENOMEM:
        return SocketErrorType::NOMEM;
      default:
        return SocketErrorType::OTHER;
    }
  }
};

/**
 * Interface to create QuicTransportStatsCallback instance.
 * If application supplies the implementation of this factory, the transport
 * calls 'make' during its initialization _for each worker_.
 * Further, 'make' is called from the worker's eventbase so that it is
 * convenient for application to specify actions such as scheduling per thread
 * aggregation
 */
class QuicTransportStatsCallbackFactory {
 public:
  virtual ~QuicTransportStatsCallbackFactory() = default;

  virtual std::unique_ptr<QuicTransportStatsCallback> make() = 0;
};

#define QUIC_STATS(statsCallback, method, ...)                              \
  if (statsCallback) {                                                      \
    std::invoke(                                                            \
        &QuicTransportStatsCallback::method, statsCallback, ##__VA_ARGS__); \
  }                                                                         \
  static_assert(true, "semicolon required")

#define QUIC_STATS_FOR_EACH(iterBegin, iterEnd, statsCallback, method, ...)   \
  if (statsCallback) {                                                        \
    std::for_each(iterBegin, iterEnd, [&](const auto&) {                      \
      std::invoke(                                                            \
          &QuicTransportStatsCallback::method, statsCallback, ##__VA_ARGS__); \
    });                                                                       \
  }                                                                           \
  static_assert(true, "semicolon required")

} // namespace quic
