/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/TokenlessPacer.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/observer/SocketObserverMacros.h>

namespace quic {

TokenlessPacer::TokenlessPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss)
    : conn_(conn),
      minCwndInMss_(minCwndInMss),
      batchSize_(conn.transportSettings.writeConnectionDataPacketsLimit),
      pacingRateCalculator_(calculatePacingRate) {}

void TokenlessPacer::refreshPacingRate(
    uint64_t cwndBytes,
    std::chrono::microseconds rtt,
    TimePoint /*currentTime*/) {
  if (rtt == kDefaultMinRtt) {
    return;
  }
  uint64_t targetRateBytesPerSec = (rtt == 0us)
      ? std::numeric_limits<uint64_t>::max()
      : (cwndBytes * 1s * rttFactorDenominator_) / (rtt * rttFactorNumerator_);
  if (targetRateBytesPerSec > maxPacingRateBytesPerSec_) {
    return setPacingRate(maxPacingRateBytesPerSec_);
  } else if (rtt < conn_.transportSettings.pacingTickInterval) {
    writeInterval_ = 0us;
    batchSize_ = conn_.transportSettings.writeConnectionDataPacketsLimit;
  } else {
    rtt *= rttFactorNumerator_;
    rtt /= rttFactorDenominator_;
    const PacingRate pacingRate =
        pacingRateCalculator_(conn_, cwndBytes, minCwndInMss_, rtt);
    writeInterval_ = pacingRate.interval;
    batchSize_ = pacingRate.burstSize;
  }
  maybeNotifyObservers();
}

// rate_bps is *bytes* per second
void TokenlessPacer::setPacingRate(uint64_t rateBps) {
  if (rateBps > maxPacingRateBytesPerSec_) {
    rateBps = maxPacingRateBytesPerSec_;
  }

  if (rateBps == 0) {
    batchSize_ = 0;
    writeInterval_ = conn_.transportSettings.pacingTickInterval;
  } else {
    // The pacing timer fires at most once per tick, so faster rates need
    // larger bursts.
    const auto tick = conn_.transportSettings.pacingTickInterval;
    const uint64_t bytesPerTick =
        rateBps * static_cast<uint64_t>(tick.count()) / 1000000;
    batchSize_ = std::max(
        conn_.transportSettings.writeConnectionDataPacketsLimit,
        (bytesPerTick + conn_.udpSendPacketLen - 1) / conn_.udpSendPacketLen);
    uint64_t interval =
        (batchSize_ * conn_.udpSendPacketLen * 1000000) / rateBps;
    writeInterval_ = std::max(std::chrono::microseconds(interval), tick);
  }

  maybeNotifyObservers();
}

void TokenlessPacer::setMaxPacingRate(uint64_t maxRateBytesPerSec) {
  maxPacingRateBytesPerSec_ = maxRateBytesPerSec;
  // Current rate in bytes per sec =
  //         batchSize * packetLen * (1 second / writeInterval)
  // if writeInterval = 0, current rate is
  // std::numeric_limits<uint64_t>::max()
  uint64_t currentRateBytesPerSec = (writeInterval_ == 0us)
      ? std::numeric_limits<uint64_t>::max()
      : (batchSize_ * conn_.udpSendPacketLen * std::chrono::seconds(1)) /
          writeInterval_;
  if (currentRateBytesPerSec > maxPacingRateBytesPerSec_) {
    // Current rate is faster than max. Enforce the maxPacingRate.
    return setPacingRate(maxPacingRateBytesPerSec_);
  }
}

void TokenlessPacer::reset() {
  // We call this after idle, so we actually want to start writing
  // immediately.
  lastWriteTime_.reset();
}

void TokenlessPacer::setRttFactor(uint8_t numerator, uint8_t denominator) {
  rttFactorNumerator_ = numerator;
  rttFactorDenominator_ = denominator;
}

void TokenlessPacer::onPacketSent() {}

void TokenlessPacer::onPacketsLoss() {}

std::chrono::microseconds TokenlessPacer::getTimeUntilNextWrite(
    TimePoint now) const {
  // If we don't have a lastWriteTime_, we want to write immediately.
  auto timeSinceLastWrite =
      std::chrono::duration_cast<std::chrono::microseconds>(
          now - lastWriteTime_.value_or(now - 2 * writeInterval_));
  if (timeSinceLastWrite >= writeInterval_) {
    return 0us;
  }
  return std::max(
      writeInterval_ - timeSinceLastWrite,
      conn_.transportSettings.pacingTickInterval);
}

uint64_t TokenlessPacer::updateAndGetWriteBatchSize(TimePoint currentTime) {
  auto sendBatch = batchSize_;
  if (lastWriteTime_.has_value() && writeInterval_ > 0us &&
      conn_.congestionController &&
      !conn_.congestionController->isAppLimited()) {
    // The pacer timer is expected to trigger every writeInterval_
    auto timeSinceLastWrite =
        std::chrono::duration_cast<std::chrono::microseconds>(
            currentTime - lastWriteTime_.value());
    if (conn_.congestionController &&
        !conn_.congestionController->isAppLimited() &&
        timeSinceLastWrite > (writeInterval_ * 110 / 100)) {
      // Log if connection is not application-limited and the timer has been
      // delayed by more than 10% of the expected write interval
      QUIC_STATS(conn_.statsCallback, onPacerTimerLagged);
    }

    // Summary of the logic:
    // 1. If the timer is delayed, we attempt to scale up the burstSize to
    //    compensate for the delay.
    // 2. When the delay compensation results in a fractional number of
    //    packets, we round up to the nearest packet, and keep track of the
    //    difference to try and accommodate for it if the timer is delayed in
    //    the next write as well.
    // 3. The maximum factor we can use for scaling up the burst is
    //    maxBurstIntervals.
    // 4. If the write happens earlier than expected (for example due to a
    //    network read), scale the burst size down but send at least 1 packet.
    //    It's better to err on being a bit more aggressive than missing
    //    potential opportunities to send packets.

    if (timeSinceLastWrite / writeInterval_ >= maxBurstIntervals) {
      // The delay is too long. Just use the maximum burst factor allowed.
      sendBatch = batchSize_ * maxBurstIntervals;
      // Reset any record of pending delay for packets we already sent and are
      // trying to scale down for.
      pendingDelayAdjustment_ = 0us;
    } else {
      // Adjust batch size to compensate for a delayed write, taking the
      // any pending delay adjustment into consideration.
      // Keep track of any delay adjustment carried over

      auto targetPackets = batchSize_ * timeSinceLastWrite;

      // Subtract pendingDelayAdjustment_ from targetPackets but avoid an
      // underflow
      if (targetPackets >= pendingDelayAdjustment_) {
        targetPackets -= pendingDelayAdjustment_;
        pendingDelayAdjustment_ = 0us;
      } else if (targetPackets < pendingDelayAdjustment_) {
        // If the pending delay adjustment is more than the target packets, it
        // means the sending rate has changed significantly. We should drop
        // the adjustment and start a new burst.
        pendingDelayAdjustment_ = 0us;
      }

      sendBatch = targetPackets / writeInterval_;
      pendingDelayAdjustment_ = targetPackets % writeInterval_;
      if (pendingDelayAdjustment_ > 0us) {
        sendBatch += 1;
        pendingDelayAdjustment_ = writeInterval_ - pendingDelayAdjustment_;
      }
    }
  }
  if (!lastWriteTime_.has_value() || sendBatch > 0) {
    lastWriteTime_ = currentTime;
  }
  return sendBatch;
}

uint64_t TokenlessPacer::getCachedWriteBatchSize() const {
  return batchSize_;
}

void TokenlessPacer::setPacingRateCalculator(
    PacingRateCalculator pacingRateCalculator) {
  pacingRateCalculator_ = std::move(pacingRateCalculator);
}

void TokenlessPacer::maybeNotifyObservers() {
  if (lastNotifiedBatchSize_ == batchSize_ &&
      lastNotifiedWriteInterval_ == writeInterval_) {
    return;
  }
  lastNotifiedBatchSize_ = batchSize_;
  lastNotifiedWriteInterval_ = writeInterval_;

  // Inform observers
  auto observerContainer = conn_.getSocketObserverContainer();
  SOCKET_OBSERVER_IF(
      observerContainer,
      SocketObserverInterface::Events::pacingRateUpdatedEvents) {
    observerContainer->invokeInterfaceMethod<
        SocketObserverInterface::Events::pacingRateUpdatedEvents>(
        [event = quic::SocketObserverInterface::PacingRateUpdateEvent(
             batchSize_, writeInterval_)](auto observer, auto observed) {
          observer->pacingRateUpdated(observed, event);
        });
  }

  QLOG(conn_, addPacingMetricUpdate, batchSize_, writeInterval_);
}
} // namespace quic
