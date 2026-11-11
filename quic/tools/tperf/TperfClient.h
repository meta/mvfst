/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <folly/io/async/HHWheelTimer.h>
#include <folly/stats/Histogram.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/events/FollyQuicEventBase.h>

namespace quic::tperf {

class TPerfClient : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public folly::HHWheelTimer::Callback {
 public:
  TPerfClient(
      std::string host,
      uint16_t port,
      std::chrono::milliseconds transportTimerResolution,
      int32_t duration,
      uint64_t window,
      bool autotuneWindow,
      bool gso,
      quic::CongestionControlType congestionControlType,
      uint32_t maxReceivePacketSize,
      bool useInplaceWrite,
      std::string knobsStr,
      bool useAckReceiveTimestamps,
      bool useDraft02AckReceiveTimestamps,
      bool advertiseLegacyAckReceiveTimestamps,
      bool sendDraft02AckReceiveTimestamps,
      uint32_t maxAckReceiveTimestampsToSend,
      bool useL4sEcn,
      bool readEcn,
      uint32_t dscp);
  ~TPerfClient() override = default;

  void timeoutExpired() noexcept override;

  void callbackCanceled() noexcept override {}

  void readAvailable(quic::StreamId streamId) noexcept override;
  void readError(
      quic::StreamId /*streamId*/,
      QuicError
      /*error*/) noexcept override;
  void onNewBidirectionalStream(quic::StreamId id) noexcept override;
  void onNewUnidirectionalStream(quic::StreamId id) noexcept override;
  void onTransportReady() noexcept override;
  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override;
  void onConnectionEnd() noexcept override;
  void onConnectionSetupError(QuicError error) noexcept override;
  void onConnectionError(QuicError error) noexcept override;
  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override;
  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept override;

  void start();

 private:
  bool timerScheduled_{false};
  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  folly::EventBase fEvb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  uint64_t receivedBytes_{0};
  uint64_t receivedStreams_{0};
  std::map<quic::StreamId, uint64_t> bytesPerStream_;
  folly::Histogram<uint64_t> bytesPerStreamHistogram_{
      1024,
      0,
      1024 * 1024 * 1024};
  std::chrono::seconds duration_;
  uint64_t window_;
  bool autotuneWindow_{false};
  bool gso_;
  quic::CongestionControlType congestionControlType_;
  uint32_t maxReceivePacketSize_;
  bool useInplaceWrite_{false};
  std::string knobsStr_;
  bool useAckReceiveTimestamps_{false};
  bool useDraft02AckReceiveTimestamps_{false};
  bool advertiseLegacyAckReceiveTimestamps_{true};
  bool sendDraft02AckReceiveTimestamps_{true};
  uint32_t maxAckReceiveTimestampsToSend_;
  bool useL4sEcn_{false};
  bool readEcn_{false};
  uint32_t dscp_;
};

} // namespace quic::tperf
