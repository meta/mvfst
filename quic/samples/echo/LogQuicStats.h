/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/common/MvfstLogging.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic::samples {
class LogQuicStats : public quic::QuicTransportStatsCallback {
 public:
  explicit LogQuicStats(const std::string& prefix) : prefix_(prefix + " ") {}

  ~LogQuicStats() override = default;

  void onPacketReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onRxDelaySample(uint64_t /* rxDelay */) override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onDuplicatedPacketReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onOutOfOrderPacketReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketProcessed() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketSent() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketRetransmission() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketLoss() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketLossByTimeout() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketLossByReorderingThreshold() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketSpuriousLoss() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPersistentCongestion() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketDropped(PacketDropReason reason) override {
    MVVLOG(2) << prefix_ << __func__ << " reason=" << reason._to_string();
  }

  void onPacketForwarded() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onForwardedPacketReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onForwardedPacketProcessed() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPacketRoutedToLinkedWorker() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onClientInitialReceived(QuicVersion version) override {
    MVVLOG(2) << prefix_ << __func__ << " version: " << quic::toString(version);
  }

  void onNewConnectionAttemptRejected() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnectionRateLimited() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnectionWritableBytesLimited() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onNewTokenReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onNewTokenIssued() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onTokenDecryptFailure() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  // connection level metrics:
  void onNewConnection() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnectionClose(Optional<QuicErrorCode> code = std::nullopt) override {
    MVVLOG(2) << prefix_ << __func__ << " reason="
              << quic::toString(code.value_or(LocalErrorCode::NO_ERROR));
  }

  void onConnectionCloseZeroBytesWritten() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnectionMigration() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPathAdded() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPathValidationSuccess() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPathValidationFailure() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  // stream level metrics
  void onNewQuicStream() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onQuicStreamClosed() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onQuicStreamReset(QuicErrorCode code) override {
    MVVLOG(2) << prefix_ << __func__ << " reason=" << quic::toString(code);
  }

  // flow control / congestion control / loss recovery related metrics
  void onConnFlowControlUpdate() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnFlowControlBlocked() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onStatelessReset() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onStreamFlowControlUpdate() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onStreamFlowControlBlocked() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onCwndBlocked() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onInflightBytesSample(uint64_t inflightBytes) override {
    MVVLOG(2) << __func__ << " inflightBytes=" << inflightBytes;
  }

  void onRttSample(uint64_t rtt) override {
    MVVLOG(2) << __func__ << " rtt=" << rtt;
  }

  void onBandwidthSample(uint64_t bandwidth) override {
    MVVLOG(2) << __func__ << " bandwidth=" << bandwidth;
  }

  void onCwndHintBytesSample(uint64_t cwndHintBytes) override {
    MVVLOG(2) << __func__ << " cwndHintBytes=" << cwndHintBytes;
  }

  void onCongestionControllerResumed() override {
    MVVLOG(2) << __func__;
  }

  void onNewCongestionController(CongestionControlType type) override {
    MVVLOG(2) << prefix_ << __func__
              << " type=" << congestionControlTypeToString(type);
  }

  // Probe timeout counter (aka loss timeout counter)
  void onPTO() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  // metrics to track bytes read from / written to wire
  void onRead(size_t bufSize) override {
    MVVLOG(2) << prefix_ << __func__ << " size=" << bufSize;
  }

  void onWrite(size_t bufSize) override {
    MVVLOG(2) << prefix_ << __func__ << " size=" << bufSize;
  }

  void onUDPSocketWriteError(SocketErrorType errorType) override {
    MVVLOG(2) << prefix_ << __func__ << " errorType=" << toString(errorType);
  }

  void onTransportKnobApplied(TransportKnobParamId knobType) override {
    MVVLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onTransportKnobError(TransportKnobParamId knobType) override {
    MVVLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onTransportKnobOutOfOrder(TransportKnobParamId knobType) override {
    MVVLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onServerUnfinishedHandshake() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttBuffered() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttBufferedPruned() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttAccepted() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttRejected() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttPrimingAccepted() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onZeroRttPrimingRejected() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onDatagramRead(size_t datagramSize) override {
    MVVLOG(2) << prefix_ << __func__ << " size=" << datagramSize;
  }

  void onDatagramWrite(size_t datagramSize) override {
    MVVLOG(2) << prefix_ << __func__ << " size=" << datagramSize;
  }

  void onDatagramDroppedOnWrite() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onDatagramDroppedOnRead() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onShortHeaderPadding(size_t padSize) override {
    MVVLOG(2) << prefix_ << __func__ << " size=" << padSize;
  }

  void onPacerTimerLagged() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPeerMaxUniStreamsLimitSaturated() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onPeerMaxBidiStreamsLimitSaturated() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onConnectionIdCreated(size_t encodedTimes) override {
    MVVLOG(2) << prefix_ << __func__ << " encodedTimes=" << encodedTimes;
  }

  void onKeyUpdateAttemptInitiated() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onKeyUpdateAttemptReceived() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onKeyUpdateAttemptSucceeded() override {
    MVVLOG(2) << prefix_ << __func__;
  }

  void onSconePacketSent() override {
    MVVLOG(2) << prefix_ << __func__;
  }

 private:
  std::string prefix_;
};

class LogQuicStatsFactory : public QuicTransportStatsCallbackFactory {
 public:
  ~LogQuicStatsFactory() override = default;

  std::unique_ptr<QuicTransportStatsCallback> make() override {
    return std::make_unique<LogQuicStats>("server");
  }
};

} // namespace quic::samples
