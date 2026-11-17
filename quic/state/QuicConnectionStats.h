/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <string>

#include <quic/QuicConstants.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/mvfst-config.h>

namespace quic {

struct QuicConnectionStats {
  uint8_t workerID{0};
  uint32_t numConnIDs{0};
  quic::SocketAddress localAddress;
  quic::SocketAddress peerAddress;
  std::chrono::duration<float> duration{0};
  uint64_t cwnd_bytes{0};
  CongestionControlType congestionController{CongestionControlType::None};
  CongestionControllerStats congestionControllerStats =
      CongestionControllerStats();
  uint32_t ptoCount{0};
  std::chrono::microseconds srtt{0};
  std::chrono::microseconds mrtt{0};
  std::chrono::microseconds lrtt{0};
  std::chrono::microseconds rttvar{0};
  uint64_t peerAckDelayExponent{0};
  uint64_t udpSendPacketLen{0};
  uint64_t numStreams{0};
  std::string clientChosenDestConnectionId;
  std::string clientConnectionId;
  std::string serverConnectionId;
  uint64_t totalBytesSent{0};
  uint64_t totalBytesReceived{0};
  uint64_t totalBytesRetransmitted{0};
  uint32_t version{0};
};

} // namespace quic
