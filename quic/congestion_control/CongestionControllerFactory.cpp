/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/CongestionControllerFactory.h>

#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/Bbr2.h>
#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/congestion_control/BbrRttSampler.h>
#include <quic/congestion_control/C4.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/congestion_control/modular/Bbr2Startup.h>

#include <memory>

namespace quic {
std::unique_ptr<CongestionController>
DefaultCongestionControllerFactory::makeCongestionController(
    QuicConnectionStateBase& conn,
    CongestionControlType type) {
  std::unique_ptr<CongestionController> congestionController;
  auto setupBBR = [&conn](BbrCongestionController* bbr) {
    bbr->setRttSampler(
        std::make_unique<BbrRttSampler>(
            std::chrono::seconds(kDefaultRttSamplerExpiration)));
    bbr->setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));
  };
  switch (type) {
    case CongestionControlType::NewReno:
      congestionController = std::make_unique<NewReno>(conn);
      break;
    case CongestionControlType::Cubic:
      congestionController = std::make_unique<Cubic>(conn);
      break;
    case CongestionControlType::Copa:
      congestionController = std::make_unique<Copa>(conn);
      break;
    case CongestionControlType::BBR: {
      auto bbr = std::make_unique<BbrCongestionController>(conn);
      setupBBR(bbr.get());
      congestionController = std::move(bbr);
      break;
    }
    case CongestionControlType::BBR2: {
      auto bbr2 = std::make_unique<Bbr2CongestionController>(conn);
      congestionController = std::move(bbr2);
      break;
    }
    case CongestionControlType::BBR2Modular: {
      auto bbr2Modular = std::make_unique<Bbr2Startup>(conn);
      congestionController = std::move(bbr2Modular);
      break;
    }
    case CongestionControlType::StaticCwnd: {
      throw QuicInternalException(
          "StaticCwnd Congestion Controller cannot be "
          "constructed via CongestionControllerFactory.",
          LocalErrorCode::INTERNAL_ERROR);
    }
    case CongestionControlType::Custom: {
      throw QuicInternalException(
          "Custom Congestion Controller cannot be "
          "constructed via CongestionControllerFactory.",
          LocalErrorCode::INTERNAL_ERROR);
    }
    case CongestionControlType::C4:
      congestionController = std::make_unique<C4CongestionController>(conn);
      break;
    case CongestionControlType::None:
      break;
    case CongestionControlType::MAX:
      throw QuicInternalException(
          "MAX is not a valid cc algorithm.", LocalErrorCode::INTERNAL_ERROR);
  }
  QUIC_STATS(conn.statsCallback, onNewCongestionController, type);
  return congestionController;
}
} // namespace quic
