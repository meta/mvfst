/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/state/ClonedPacketIdentifier.h>
#include <quic/state/LossEvent.h>
#include <quic/state/OutstandingPacket.h>
#include <sys/types.h>

namespace quic {

struct AckEvent;

struct BbrStats {
  uint8_t state;
};

struct Bbr2Stats {
  uint8_t state;
};

struct CopaStats {
  double deltaParam;
  bool useRttStanding;
};

struct CubicStats {
  uint8_t state;
  uint64_t ssthresh;
  uint64_t lastLossTimeMs;
};

struct C4Stats {
  uint8_t state;
};

struct CubackStats {
  uint8_t state;
  uint64_t ssthresh;
};

union CongestionControllerStats {
  struct BbrStats bbrStats;
  struct Bbr2Stats bbr2Stats;
  struct CopaStats copaStats;
  struct CubicStats cubicStats;
  struct C4Stats c4Stats;
  struct CubackStats cubackStats;
};

struct CongestionController {
 public:
  using AckEvent = quic::AckEvent;
  using LossEvent = quic::LossEvent;

  struct State {
    uint64_t writableBytes{0};
    uint64_t congestionWindowBytes{0};
    Optional<uint64_t> maybeBandwidthBitsPerSec{std::nullopt};
  };

  virtual ~CongestionController() = default;

  /**
   * Take bytes out of flight without mutating other states of the controller
   */
  virtual void onRemoveBytesFromInflight(uint64_t) = 0;
  virtual void onPacketSent(const OutstandingPacketWrapper& packet) = 0;
  virtual void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE ackEvent,
      const LossEvent* FOLLY_NULLABLE lossEvent) = 0;

  /**
   * Return the number of bytes that the congestion controller
   * will allow you to write.
   */
  [[nodiscard]] virtual uint64_t getWritableBytes() const = 0;

  /**
   * Return the number of bytes of cwnd of the congestion
   * controller.
   */
  [[nodiscard]] virtual uint64_t getCongestionWindow() const = 0;

  /**
   * Return the congestion controller's bandwidth estimate, if available.
   */
  [[nodiscard]] virtual Optional<Bandwidth> getBandwidth() const {
    return std::nullopt;
  }

  /**
   * Return the congestion controller's BDP estimate. Returns the congestion
   * window unless overridden by the congestion controller.
   *
   * Unit is bytes.
   */
  [[nodiscard]] virtual uint64_t getBDP() const {
    return getCongestionWindow();
  }

  /**
   * Notify congestion controller that the connection has become idle or active
   * in the sense that there are active non-control streams.
   * idle: true if the connection has become app-idle, false if the
   *          connection has become not app-idle.
   * eventTime: the time point when the app-idle state changed.
   */
  virtual void setAppIdle(bool idle, TimePoint eventTime) = 0;

  /**
   * Notify congestion controller that the connection has become app-limited or
   * not app-limited.
   */
  virtual void setAppLimited() = 0;

  [[nodiscard]] virtual CongestionControlType type() const = 0;

  /**
   * Whether the congestion controller thinks it's currently in app-limited
   * state.
   */
  [[nodiscard]] virtual bool isAppLimited() const = 0;

  virtual void getStats(CongestionControllerStats& stats) const = 0;

  /**
   * Get current state of congestion controller.
   */
  [[nodiscard]] State getState() const {
    State state;
    state.congestionWindowBytes = getCongestionWindow();
    state.writableBytes = getWritableBytes();

    // Add latest Bandwidth sampler, if available.
    if (auto maybeBandwidth = getBandwidth()) {
      auto bandwidth = maybeBandwidth.value();
      if (bandwidth.unitType == Bandwidth::UnitType::BYTES) {
        state.maybeBandwidthBitsPerSec = bandwidth.normalize() * 8;
      }
    }
    return state;
  }

  /**
   * Set resume hints (cwnd and RTT) from a previous session for careful resume.
   * Only the first call takes effect; subsequent calls are ignored.
   */
  virtual void setResumeHints(
      uint64_t /*cwndHintBytes*/,
      const Optional<std::chrono::milliseconds>& /*rttHint*/ = std::nullopt) {}
};

} // namespace quic
