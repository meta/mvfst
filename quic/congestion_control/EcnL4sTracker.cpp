/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/EcnL4sTracker.h>

#include <quic/logging/QLoggerMacros.h>
#include <quic/observer/SocketObserverMacros.h>

namespace {
using namespace std::chrono_literals;
constexpr std::chrono::microseconds kRttVirtMin = 25ms;
constexpr double kL4sWeightEwmaGain = 1 / 16.0;
} // namespace

namespace quic {

EcnL4sTracker::EcnL4sTracker(QuicConnectionStateBase& conn)
    : conn_(conn), rttVirt_(kRttVirtMin) {}

void EcnL4sTracker::onPacketAck(const AckEvent* ackEvent) {
  if (!ackEvent || conn_.ecnState != ECNState::ValidatedL4S) {
    // Nothing to track, if there is no ack event, or if L4S is not validated.
    return;
  }

  if (ackEvent->rttSample) {
    rttVirt_ = std::max(conn_.lossState.srtt, kRttVirtMin);
  }

  // The transport keeps running maxima of the counts echoed for AppData. A
  // reordered ACK, or an ACK for another packet number space, carries lower
  // counts.
  const uint64_t ect1Echoed =
      conn_.ackStates.appDataAckState.ecnECT1CountEchoed;
  const uint64_t ceEchoed = conn_.ackStates.appDataAckState.ecnCECountEchoed;
  if (ackEvent->ackTime - lastUpdateTime_ >= rttVirt_ ||
      (ceEchoed > 0 && lastCEEchoed_ == 0)) {
    // It's time to update the l4s weight.
    const auto newECT1Echoed =
        static_cast<double>(ect1Echoed - lastECT1Echoed_);
    const auto newCEEchoed = static_cast<double>(ceEchoed - lastCEEchoed_);

    if (newCEEchoed + newECT1Echoed == 0) {
      // No new marks in the last rttVirt. Skip this ACK.
      return;
    }

    // Update the l4s weight if we have seen any CE marks on this connection.
    if (ceEchoed > 0) {
      if (lastCEEchoed_ == 0) {
        // First CE mark is seen. Initialize the weight to 1.0
        l4sWeight_ = 1.0;
      }
      auto frac = newCEEchoed / (newCEEchoed + newECT1Echoed);
      l4sWeight_ += kL4sWeightEwmaGain * (frac - l4sWeight_);

      if (newCEEchoed > 0) {
        // Log in qlogger
        QLOG(conn_, addL4sWeightUpdate, l4sWeight_, newECT1Echoed, newCEEchoed);

        // Inform observers
        auto observerContainer = conn_.getSocketObserverContainer();
        SOCKET_OBSERVER_IF(
            observerContainer,
            SocketObserverInterface::Events::l4sWeightUpdatedEvents) {
          observerContainer->invokeInterfaceMethod<
              SocketObserverInterface::Events::l4sWeightUpdatedEvents>(
              [event = quic::SocketObserverInterface::L4sWeightUpdateEvent(
                   l4sWeight_, newECT1Echoed, newCEEchoed)](
                  auto observer, auto observed) {
                observer->l4sWeightUpdated(observed, event);
              });
        }
      }
    }

    lastUpdateTime_ = ackEvent->ackTime;
    lastECT1Echoed_ = ect1Echoed;
    lastCEEchoed_ = ceEchoed;
  }
}

double EcnL4sTracker::getL4sWeight() const {
  return l4sWeight_;
}

double EcnL4sTracker::getNormalizedL4sWeight() const {
  // Normalize the weight over the srtt
  return l4sWeight_ * conn_.lossState.srtt / rttVirt_;
}
} // namespace quic
