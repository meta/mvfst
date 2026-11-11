/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sstream>
#include <utility>

#include <fizz/crypto/Utils.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/tools/tperf/TperfClient.h>

namespace quic::tperf {

TPerfClient::TPerfClient(
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
    uint32_t dscp)
    : host_(std::move(host)),
      port_(port),
      fEvb_(transportTimerResolution),
      qEvb_(std::make_shared<FollyQuicEventBase>(&fEvb_)),
      duration_(duration),
      window_(window),
      autotuneWindow_(autotuneWindow),
      gso_(gso),
      congestionControlType_(congestionControlType),
      maxReceivePacketSize_(maxReceivePacketSize),
      useInplaceWrite_(useInplaceWrite),
      knobsStr_(std::move(knobsStr)),
      useAckReceiveTimestamps_(useAckReceiveTimestamps),
      useDraft02AckReceiveTimestamps_(useDraft02AckReceiveTimestamps),
      advertiseLegacyAckReceiveTimestamps_(advertiseLegacyAckReceiveTimestamps),
      sendDraft02AckReceiveTimestamps_(sendDraft02AckReceiveTimestamps),
      maxAckReceiveTimestampsToSend_(maxAckReceiveTimestampsToSend),
      useL4sEcn_(useL4sEcn),
      readEcn_(readEcn),
      dscp_(dscp) {
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(fizz::CryptoUtils::init(err), err);
  fEvb_.setName("tperf_client");
}

void TPerfClient::timeoutExpired() noexcept {
  quicClient_->closeNow(std::nullopt);
  constexpr double bytesPerMegabit = 131072;
  MVLOG_INFO << "Received " << receivedBytes_ << " bytes in "
             << duration_.count() << " seconds.";
  MVLOG_INFO << "Overall throughput: "
             << (receivedBytes_ / bytesPerMegabit) / duration_.count()
             << "Mb/s";
  // Per Stream Stats
  MVLOG_INFO << "Average per Stream throughput: "
             << ((receivedBytes_ / receivedStreams_) / bytesPerMegabit) /
          duration_.count()
             << "Mb/s over " << receivedStreams_ << " streams";
  if (receivedStreams_ != 1) {
    MVLOG_INFO << "Histogram per Stream bytes: " << std::endl;
    MVLOG_INFO << "Lo\tHi\tNum\tSum";
    for (const auto bytes : bytesPerStream_) {
      bytesPerStreamHistogram_.addValue(bytes.second);
    }
    std::ostringstream os;
    bytesPerStreamHistogram_.toTSV(os);
    std::vector<std::string> lines;
    folly::split('\n', os.str(), lines);
    for (const auto& line : lines) {
      MVLOG_INFO << line;
    }
    MVLOG_INFO << "Per stream bytes breakdown: ";
    for (const auto& [k, v] : bytesPerStream_) {
      MVLOG_INFO << fmt::format("stream: {}, bytes: {}", k, v);
    }
  }
}

void TPerfClient::readAvailable(quic::StreamId streamId) noexcept {
  auto readData = quicClient_->read(streamId, 0);
  if (readData.hasError()) {
    MVLOG_FATAL << "TPerfClient failed read from stream=" << streamId
                << ", error=" << (uint32_t)readData.error();
  }

  auto readBytes = readData->first->computeChainDataLength();
  receivedBytes_ += readBytes;
  bytesPerStream_[streamId] += readBytes;
  if (readData.value().second) {
    bytesPerStreamHistogram_.addValue(bytesPerStream_[streamId]);
    bytesPerStream_.erase(streamId);
  }
}

void TPerfClient::readError(
    quic::StreamId /*streamId*/,
    QuicError
    /*error*/) noexcept {
  // A read error only terminates the ingress portion of the stream state.
  // Your application should probably terminate the egress portion via
  // resetStream
}

void TPerfClient::onNewBidirectionalStream(quic::StreamId id) noexcept {
  MVLOG_INFO << "TPerfClient: new bidirectional stream=" << id;
  quicClient_->setReadCallback(id, this);
}

void TPerfClient::onNewUnidirectionalStream(quic::StreamId id) noexcept {
  MVVLOG(5) << "TPerfClient: new unidirectional stream=" << id;
  if (!timerScheduled_) {
    timerScheduled_ = true;
    fEvb_.timer().scheduleTimeout(this, duration_);
  }
  quicClient_->setReadCallback(id, this);
  receivedStreams_++;
}

void TPerfClient::onTransportReady() noexcept {
  MVLOG_INFO << "TPerfClient: onTransportReady";
}

void TPerfClient::onStopSending(
    quic::StreamId id,
    quic::ApplicationErrorCode /*error*/) noexcept {
  MVVLOG(10) << "TPerfClient got StopSending stream id=" << id;
}

void TPerfClient::onConnectionEnd() noexcept {
  MVLOG_INFO << "TPerfClient connection end";

  fEvb_.terminateLoopSoon();
}

void TPerfClient::onConnectionSetupError(QuicError error) noexcept {
  onConnectionError(std::move(error));
}

void TPerfClient::onConnectionError(QuicError error) noexcept {
  MVLOG_ERROR << "TPerfClient error: " << toString(error.code);
  fEvb_.terminateLoopSoon();
}

void TPerfClient::onStreamWriteReady(
    quic::StreamId id,
    uint64_t maxToSend) noexcept {
  MVLOG_INFO << "TPerfClient stream" << id
             << " is write ready with maxToSend=" << maxToSend;
}

void TPerfClient::onStreamWriteError(
    quic::StreamId id,
    QuicError error) noexcept {
  MVLOG_ERROR << "TPerfClient write error with stream=" << id
              << " error=" << toString(error);
}

void TPerfClient::start() {
  quic::SocketAddress addr(host_.c_str(), port_);
  auto sock = std::make_unique<folly::AsyncUDPSocket>(&fEvb_);
  auto sockWrapper =
      std::make_unique<FollyQuicAsyncUDPSocket>(qEvb_, std::move(sock));

  auto fizzClientContext =
      FizzClientQuicHandshakeContext::Builder()
          .setCertificateVerifier(test::createTestCertificateVerifier())
          .build();
  quicClient_ = std::make_shared<quic::QuicClientTransport>(
      qEvb_, std::move(sockWrapper), std::move(fizzClientContext));
  quicClient_->setHostname("tperf");
  quicClient_->addNewPeerAddress(addr);
  quicClient_->setCongestionControllerFactory(
      std::make_shared<DefaultCongestionControllerFactory>());
  auto settings = quicClient_->getTransportSettings();
  settings.advertisedInitialUniStreamFlowControlWindow =
      std::numeric_limits<uint32_t>::max();
  settings.advertisedInitialConnectionFlowControlWindow = window_;
  settings.autotuneReceiveConnFlowControl = autotuneWindow_;
  settings.connectUDP = true;
  settings.shouldUseRecvmmsgForBatchRecv = true;
  settings.maxRecvBatchSize = 64;
  settings.numGROBuffers_ = 64;
  settings.defaultCongestionController = congestionControlType_;
  if (congestionControlType_ == quic::CongestionControlType::BBR) {
    settings.pacingEnabled = true;
    settings.pacingTickInterval = 200us;
    settings.writeLimitRttFraction = 0;
  }
  if (gso_) {
    settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
    settings.maxBatchSize = 16;
  }
  settings.maxRecvPacketSize = maxReceivePacketSize_;
  if (!knobsStr_.empty()) {
    settings.knobs.push_back(
        {kDefaultQuicTransportKnobSpace,
         kDefaultQuicTransportKnobId,
         knobsStr_});
  }

  // `--use_draft02_*` implies requesting timestamps and so populates the
  // local config; the flag alone would be a no-op.
  if (useAckReceiveTimestamps_ || useDraft02AckReceiveTimestamps_) {
    MVLOG_INFO << " Using ACK receive timestamps on client"
               << " (legacy=" << advertiseLegacyAckReceiveTimestamps_
               << " draft02=" << useDraft02AckReceiveTimestamps_ << ")";

    settings.maybeAckReceiveTimestampsConfigSentToPeer = {
        .maxReceiveTimestampsPerAck = maxAckReceiveTimestampsToSend_,
        .receiveTimestampsExponent = kDefaultReceiveTimestampsExponent};
    settings.enableIetfAckReceiveTimestamps = useDraft02AckReceiveTimestamps_;
    settings.advertiseLegacyAckReceiveTimestamps =
        advertiseLegacyAckReceiveTimestamps_;
    settings.sendDraft02AckReceiveTimestamps = sendDraft02AckReceiveTimestamps_;
  }
  if (useInplaceWrite_) {
    settings.maxBatchSize = 1;
    settings.dataPathType = DataPathType::ContinuousMemory;
  }
  if (useL4sEcn_) {
    settings.enableEcnOnEgress = true;
    settings.useL4sEcn = true;
    settings.minBurstPackets = 1;
    settings.ccaConfig.onlyGrowCwndWhenLimited = true;
    settings.ccaConfig.leaveHeadroomForCwndLimited = true;
  }

  settings.readEcnOnIngress = readEcn_;
  settings.dscpValue = dscp_;

  quicClient_->setTransportSettings(settings);

  MVLOG_INFO << "TPerfClient connecting to " << addr.describe();
  quicClient_->start(this, this);
  fEvb_.loopForever();
}

} // namespace quic::tperf
