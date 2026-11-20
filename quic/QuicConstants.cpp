/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>

#include <folly/lang/Assume.h>
#include <quic/QuicConstants.h>

namespace quic {

std::string congestionControlTypeToString(CongestionControlType type) {
  switch (type) {
    case CongestionControlType::Cubic:
      return std::string(kCongestionControlCubicStr);
    case CongestionControlType::BBR:
      return std::string(kCongestionControlBbrStr);
    case CongestionControlType::BBR2:
      return std::string(kCongestionControlBbr2Str);
    case CongestionControlType::BBR2Modular:
      return std::string(kCongestionControlBbr2ModularStr);
    case CongestionControlType::Copa:
      return std::string(kCongestionControlCopaStr);
    case CongestionControlType::NewReno:
      return std::string(kCongestionControlNewRenoStr);
    case CongestionControlType::StaticCwnd:
      return std::string(kCongestionControlStaticCwndStr);
    case CongestionControlType::Custom:
      return std::string(kCongestionControlCustomStr);
    case CongestionControlType::None:
      return std::string(kCongestionControlNoneStr);
    case CongestionControlType::C4:
      return std::string(kCongestionControlC4Str);
    case CongestionControlType::BBR3:
      return std::string(kCongestionControlBbr3Str);
    case CongestionControlType::MAX:
      return "MAX";
    default:
      return "unknown";
  }
}

std::optional<CongestionControlType> congestionControlStrToType(
    std::string_view str) {
  if (str == kCongestionControlCubicStr) {
    return quic::CongestionControlType::Cubic;
  } else if (str == kCongestionControlBbr2Str) {
    return quic::CongestionControlType::BBR2;
  } else if (str == kCongestionControlBbr2ModularStr) {
    return quic::CongestionControlType::BBR2Modular;
  } else if (str == kCongestionControlBbrStr) {
    return quic::CongestionControlType::BBR;
  } else if (str == kCongestionControlCopaStr) {
    return quic::CongestionControlType::Copa;
  } else if (str == kCongestionControlNewRenoStr) {
    return quic::CongestionControlType::NewReno;
  } else if (str == kCongestionControlStaticCwndStr) {
    return quic::CongestionControlType::StaticCwnd;
  } else if (str == kCongestionControlCustomStr) {
    return quic::CongestionControlType::Custom;
  } else if (str == kCongestionControlNoneStr) {
    return quic::CongestionControlType::None;
  } else if (str == kCongestionControlC4Str) {
    return quic::CongestionControlType::C4;
  } else if (str == kCongestionControlBbr3Str) {
    return quic::CongestionControlType::BBR3;
  }
  return std::nullopt;
}

QuicBatchingMode getQuicBatchingMode(uint32_t val) {
  switch (val) {
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_NONE):
      return QuicBatchingMode::BATCHING_MODE_NONE;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_GSO):
      return QuicBatchingMode::BATCHING_MODE_GSO;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO;
      // no default
  }

  return QuicBatchingMode::BATCHING_MODE_NONE;
}

std::vector<QuicVersion> filterSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  std::vector<QuicVersion> filteredVersions;
  std::copy_if(
      versions.begin(),
      versions.end(),
      std::back_inserter(filteredVersions),
      [](auto version) {
        return version == QuicVersion::MVFST ||
            version == QuicVersion::QUIC_V1 ||
            version == QuicVersion::QUIC_V1_ALIAS ||
            version == QuicVersion::QUIC_V1_ALIAS2 ||
            version == QuicVersion::MVFST_INVALID ||
            version == QuicVersion::MVFST_EXPERIMENTAL ||
            version == QuicVersion::MVFST_EXPERIMENTAL4 ||
            version == QuicVersion::MVFST_EXPERIMENTAL5 ||
            version == QuicVersion::MVFST_ALIAS ||
            version == QuicVersion::MVFST_PRIMING;
      });
  return filteredVersions;
}

std::string writeDataReasonString(WriteDataReason reason) {
  switch (reason) {
    case WriteDataReason::PROBES:
      return "Probes";
    case WriteDataReason::ACK:
      return "Ack";
    case WriteDataReason::CRYPTO_STREAM:
      return "Crypto";
    case WriteDataReason::STREAM:
      return "Stream";
    case WriteDataReason::BLOCKED:
      return "Blocked";
    case WriteDataReason::STREAM_WINDOW_UPDATE:
      return "StreamWindowUpdate";
    case WriteDataReason::CONN_WINDOW_UPDATE:
      return "ConnWindowUpdate";
    case WriteDataReason::SIMPLE:
      return "Simple";
    case WriteDataReason::RESET:
      return "Reset";
    case WriteDataReason::PATH_VALIDATION:
      return "PathValidation";
    case WriteDataReason::PING:
      return "Ping";
    case WriteDataReason::DATAGRAM:
      return "Datagram";
    case WriteDataReason::NO_WRITE:
      return "NoWrite";
  }
  folly::assume_unreachable();
}

std::string writeNoWriteReasonString(NoWriteReason reason) {
  switch (reason) {
    case NoWriteReason::WRITE_OK:
      return "WriteOk";
    case NoWriteReason::EMPTY_SCHEDULER:
      return "EmptyScheduler";
    case NoWriteReason::NO_FRAME:
      return "NoFrame";
    case NoWriteReason::NO_BODY:
      return "NoBody";
    case NoWriteReason::SOCKET_FAILURE:
      return "SocketFailure";
  }
  folly::assume_unreachable();
}

std::string readNoReadReasonString(NoReadReason reason) {
  switch (reason) {
    case NoReadReason::READ_OK:
      return "ReadOK";
    case NoReadReason::TRUNCATED:
      return "Truncated";
    case NoReadReason::EMPTY_DATA:
      return "Empty data";
    case NoReadReason::RETRIABLE_ERROR:
      return "Retriable error";
    case NoReadReason::NONRETRIABLE_ERROR:
      return "Nonretriable error";
  }
  folly::assume_unreachable();
}

} // namespace quic
