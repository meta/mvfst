/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fmt/format.h>
#include <folly/chrono/Conv.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>

#ifdef FOLLY_HAVE_MSG_ERRQUEUE
#include <linux/net_tstamp.h>
#else
#define SOF_TIMESTAMPING_SOFTWARE 0
#endif

#include <quic/common/SocketUtil.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/Copa.h>
#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/third-party/siphash.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicConnectionStats.h>

// This hook is invoked by mvfst for every UDP socket it creates.
#if FOLLY_HAVE_WEAK_SYMBOLS
extern "C" FOLLY_ATTR_WEAK void mvfst_hook_on_socket_create(int fd);
#else
static void (*mvfst_hook_on_socket_create)(int fd) = nullptr;
#endif

namespace {
bool isValidConnIdLength(const quic::ConnectionId& connId) {
  return quic::kMinInitialDestinationConnIdLength <= connId.size() &&
      connId.size() <= quic::kMaxConnectionIdSize;
}

// Versions whose transport parameters carry the connection ids that clients
// validate.
bool hasConnIdTransportParams(quic::QuicVersion version) {
  return version == quic::QuicVersion::QUIC_V1 ||
      version == quic::QuicVersion::QUIC_V1_ALIAS ||
      version == quic::QuicVersion::QUIC_V1_ALIAS2 ||
      version == quic::QuicVersion::MVFST_PRIMING;
}
} // namespace

namespace quic {

std::atomic_int globalUnfinishedHandshakes{0};

int QuicServerWorker::getUnfinishedHandshakeCount() {
  return globalUnfinishedHandshakes.load(std::memory_order_relaxed);
}

void RunState::requestStop(LocalErrorCode reason) {
  if (!latchStop(reason)) {
    return;
  }
  for (auto& peer : peers) {
    peer.evb->runInEventBaseThreadAlwaysEnqueue([target = peer.target, reason] {
      if (auto* worker = target->worker) {
        worker->stopLocal(reason);
      }
    });
  }
}

QuicServerWorker::QuicServerWorker(
    RunState* runState,
    size_t workerIndex,
    TransportSettings transportSettings)
    : runState_(runState),
      workerIndex_(workerIndex),
      transportSettings_(std::move(transportSettings)),
      takeoverPktHandler_(this),
      observerList_(this) {
  pending0RttData_.setPruneHook(
      [&](auto, auto) { QUIC_STATS(statsCallback_, onZeroRttBufferedPruned); });

  // TODO: maxBatchSize is only a good start value when each transport does
  // its own socket writing. If we experiment with multiple transports GSO
  // together, we will need a better value.
  bufAccessor_ = std::make_unique<BufAccessor>(
      kDefaultMaxUDPPayload * transportSettings_.maxBatchSize);
}

folly::EventBase* QuicServerWorker::getEventBase() const {
  return eventBase_ ? eventBase_ : evb_.get();
}

void QuicServerWorker::setSocket(
    std::unique_ptr<FollyAsyncUDPSocketAlias> socket) {
  socket_ = std::move(socket);
  eventBase_ = socket_->getEventBase();
  evb_ = folly::ExecutorKeepAlive(socket_->getEventBase());
}

quic::Expected<void, QuicError> QuicServerWorker::enableZeroCopy() {
  if (!socket_) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "QuicServerWorker::enableZeroCopy: listener socket not set"));
  }
  if (!socket_->setZeroCopy(true)) {
    int errnoCopy = errno;
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "QuicServerWorker::enableZeroCopy: setZeroCopy(true) failed: errno={}",
            errnoCopy)));
  }
  zeroCopyEnabled_ = true;
  return {};
}

void QuicServerWorker::bind(
    const quic::SocketAddress& address,
    FollyAsyncUDPSocketAlias::BindOptions bindOptions) {
  // TODO get rid of the temporary wrapper
  FollyQuicAsyncUDPSocket tmpSock(
      std::make_shared<FollyQuicEventBase>(evb_.get()), *socket_);
  MVDCHECK(!supportedVersions_.empty());
  MVCHECK(socket_);
  // TODO this totally doesn't work, we can't apply socket options before
  // bind, since bind creates the fd.
  if (socketOptions_) {
    (void)applySocketOptions(
        tmpSock,
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
  }
  if (transportSettings_.readEcnOnIngress) {
    socket_->setRecvTos(true);
  }
  if (transportSettings_.readTtlOnIngress) {
    socket_->setRecvTtl(true);
  }
  socket_->bind(address, bindOptions);
  if (socketOptions_) {
    (void)applySocketOptions(
        tmpSock,
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
  socket_->setDFAndTurnOffPMTU();
  if (transportSettings_.numGROBuffers_ > kDefaultNumGROBuffers) {
    socket_->setGRO(true);
    if (socket_->getGRO() > 0) {
      numGROBuffers_ = std::min(
          transportSettings_.numGROBuffers_, (uint32_t)kMaxNumGROBuffers);
    }
  }
  socket_->setTimestamping(SOF_TIMESTAMPING_SOFTWARE);
  socket_->setTXTime({.clockid = CLOCK_MONOTONIC, .deadline = false});

  socket_->setMaxReadsPerEvent(transportSettings_.maxServerRecvPacketsPerLoop);
  MVVLOG(3) << "Socket max reads per event set to "
            << socket_->getMaxReadsPerEvent();

  if (mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(socket_->getNetworkSocket().toFd());
  }
}

void QuicServerWorker::applyAllSocketOptions() {
  MVCHECK(socket_);
  // TODO get rid of the temporary wrapper
  FollyQuicAsyncUDPSocket tmpSock(
      std::make_shared<FollyQuicEventBase>(evb_.get()), *socket_);
  if (socketOptions_) {
    (void)applySocketOptions(
        tmpSock,
        *socketOptions_,
        getAddress().getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
    (void)applySocketOptions(
        tmpSock,
        *socketOptions_,
        getAddress().getFamily(),
        folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
}

void QuicServerWorker::setTransportSettingsOverrideFn(
    TransportSettingsOverrideFn fn) {
  transportSettingsOverrideFn_ = std::move(fn);
}

void QuicServerWorker::setTransportStatsCallback(
    std::unique_ptr<QuicTransportStatsCallback> statsCallback) noexcept {
  MVCHECK(statsCallback);
  statsCallback_ = std::move(statsCallback);
}

QuicTransportStatsCallback* QuicServerWorker::getTransportStatsCallback()
    const noexcept {
  return statsCallback_.get();
}

void QuicServerWorker::setConnectionIdAlgo(
    std::unique_ptr<ConnectionIdAlgo> connIdAlgo) noexcept {
  MVCHECK(connIdAlgo);
  connIdAlgo_ = std::move(connIdAlgo);
}

void QuicServerWorker::setRateLimiter(
    std::unique_ptr<RateLimiter> rateLimiter) {
  newConnRateLimiter_ = std::move(rateLimiter);
}

void QuicServerWorker::setUnfinishedHandshakeLimit(
    std::function<int()> limitFn) {
  unfinishedHandshakeLimitFn_ = std::move(limitFn);
}

void QuicServerWorker::prepareForStart() {
  if (stopping_) {
    throw std::runtime_error(
        "QuicServerWorker::prepareForStart called while stopping");
  }
  if (!transportFactory_) {
    throw std::runtime_error(
        "QuicServerWorker::prepareForStart requires a transport factory");
  }
  MVCHECK(socket_);
  if (prepared_) {
    return;
  }
  if (!pacingTimer_) {
    pacingTimer_ = std::make_unique<HighResQuicTimer>(
        evb_.get(), transportSettings_.pacingTimerResolution);
  }
  if (transportSettings_.shouldUseWrapperRecvmmsgForBatchRecv && !quicSocket_) {
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb_.get());
    quicSocket_ = std::make_shared<FollyQuicAsyncUDPSocket>(qEvb, *socket_);
    quicReadCallbackAdapter_ = std::make_unique<QuicReadCallbackAdapter>(this);
  }
  prepared_ = true;
}

void QuicServerWorker::start() {
  prepareForStart();
  if (quicSocket_) {
    quicSocket_->resumeRead(quicReadCallbackAdapter_.get());
  } else {
    socket_->resumeRead(this);
  }
  if (!started_) {
    if (takeoverCB_ && !takeoverCB_->resume()) {
      throw std::runtime_error(
          "QuicServerWorker::start takeover read activation failed");
    }
    started_ = true;
  }
  MVVLOG(10) << fmt::format(
      "Registered read on worker={}, thread={}, processId={}",
      fmt::ptr(this),
      folly::getCurrentThreadID(),
      (int)processId_);
}

void QuicServerWorker::timeoutExpired() noexcept {
  logTimeBasedStats();
}

void QuicServerWorker::logTimeBasedStats() {
  for (auto [transport, handle] : boundServerTransports_) {
    if (!handle.expired()) {
      transport->logTimeBasedStats();
    }
  }
  evb_->timer().scheduleTimeout(this, timeLoggingSamplingInterval_);
}

void QuicServerWorker::pauseRead() {
  MVCHECK(socket_);
  if (quicSocket_) {
    quicSocket_->pauseRead();
  } else {
    socket_->pauseRead();
  }
}

int QuicServerWorker::getFD() {
  if (!socket_) {
    return -1;
  }
  return socket_->getNetworkSocket().toFd();
}

const quic::SocketAddress& QuicServerWorker::getAddress() const {
  MVCHECK(socket_);
  return socket_->address();
}

void QuicServerWorker::getReadBuffer(void** buf, size_t* len) noexcept {
  auto readBufferSize = transportSettings_.maxRecvPacketSize * numGROBuffers_;
  readBuffer_ = BufHelpers::createCombined(readBufferSize);
  *buf = readBuffer_->writableData();
  *len = readBufferSize;
}

// Returns true if we either drop the packet or send a version
// negotiation packet to the client. Returns false if there's
// no need for version negotiation.
bool QuicServerWorker::maybeSendVersionNegotiationPacketOrDrop(
    const quic::SocketAddress& client,
    bool isInitial,
    LongHeaderInvariant& invariant,
    size_t datagramLen) {
  Optional<std::pair<VersionNegotiationPacket, BufPtr>>
      versionNegotiationPacket;
  if (isInitial && datagramLen < kMinInitialPacketSize) {
    MVVLOG(3) << "Dropping initial packet due to invalid size";
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET_SIZE);
    return true;
  }
  isInitial =
      isInitial && invariant.version != QuicVersion::VERSION_NEGOTIATION;
  if (isInitial && rejectNewConnections_(client)) {
    QUIC_STATS(statsCallback_, onNewConnectionAttemptRejected);
    VersionNegotiationPacketBuilder builder(
        invariant.dstConnId,
        invariant.srcConnId,
        std::vector<QuicVersion>{QuicVersion::MVFST_INVALID});
    versionNegotiationPacket.emplace(std::move(builder).buildPacket());
  }
  if (!versionNegotiationPacket) {
    // SCONE packets should bypass version negotiation entirely
    bool isSconePacket =
        (invariant.version == QuicVersion::SCONE_VERSION_1 ||
         invariant.version == QuicVersion::SCONE_VERSION_2);

    bool negotiationNeeded = !isSconePacket &&
        std::find(
            supportedVersions_.begin(),
            supportedVersions_.end(),
            invariant.version) == supportedVersions_.end();

    if (invariant.version == QuicVersion::MVFST_PRIMING &&
        !isPrimingEnabled_()) {
      negotiationNeeded = true;
    }

    if (negotiationNeeded && !isInitial) {
      MVVLOG(3) << "Dropping non-initial packet due to invalid version";
      QUIC_STATS(
          statsCallback_,
          onPacketDropped,
          PacketDropReason::INVALID_PACKET_VERSION);
      return true;
    }
    if (negotiationNeeded) {
      VersionNegotiationPacketBuilder builder(
          invariant.dstConnId, invariant.srcConnId, supportedVersions_);
      versionNegotiationPacket =
          quic::make_optional(std::move(builder).buildPacket());
    }
  }
  if (versionNegotiationPacket) {
    MVVLOG(4) << "Version negotiation sent to client=" << client;
    auto len = versionNegotiationPacket->second->computeChainDataLength();
    QUIC_STATS(statsCallback_, onWrite, len);
    QUIC_STATS(statsCallback_, onPacketProcessed);
    QUIC_STATS(statsCallback_, onPacketSent);
    socket_->write(client, versionNegotiationPacket->second);
    return true;
  }
  return false;
}

void QuicServerWorker::sendVersionNegotiationPacket(
    const quic::SocketAddress& client,
    LongHeaderInvariant& invariant) {
  VersionNegotiationPacketBuilder builder(
      invariant.dstConnId, invariant.srcConnId, supportedVersions_);
  auto versionNegotiationPacket = std::move(builder).buildPacket();
  MVVLOG(4) << "Version negotiation sent to client=" << client;
  auto len = versionNegotiationPacket.second->computeChainDataLength();
  QUIC_STATS(statsCallback_, onWrite, len);
  QUIC_STATS(statsCallback_, onPacketProcessed);
  QUIC_STATS(statsCallback_, onPacketSent);
  socket_->write(client, versionNegotiationPacket.second);
}

void QuicServerWorker::onDataAvailable(
    const quic::SocketAddress& client,
    size_t len,
    bool truncated,
    OnDataAvailableParams params) noexcept {
  auto packetReceiveTime = Clock::now();
  auto originalPacketReceiveTime = packetReceiveTime;
  if (params.ts) {
    // This is the software system time from the datagram.
    const auto& tsTimespec = params.ts.value()[0];
    auto packetRxEpochUs =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(tsTimespec.tv_sec) +
            std::chrono::nanoseconds(tsTimespec.tv_nsec));
    if (packetRxEpochUs != 0us) {
      auto now = std::chrono::system_clock::now();
      auto nowEpochUs = std::chrono::duration_cast<std::chrono::microseconds>(
          now.time_since_epoch());
      auto rxDelayUs = nowEpochUs - packetRxEpochUs;
      if (rxDelayUs >= 0us) {
        packetReceiveTime -= rxDelayUs;
        QUIC_STATS(statsCallback_, onRxDelaySample, rxDelayUs.count());
      } else {
        MVVLOG(10) << "Negative rx delay: " << rxDelayUs.count() << "us";
      }
    }
  }
  // System time can move backwards, so we want to make sure that the receive
  // time we are using is monotonic relative to itself.
  if (packetReceiveTime < largestPacketReceiveTime_) {
    packetReceiveTime = originalPacketReceiveTime;
  }
  largestPacketReceiveTime_ =
      std::max(largestPacketReceiveTime_, packetReceiveTime);
  MVVLOG(10) << fmt::format(
      "Worker={}, Received data on thread={}, processId={}",
      fmt::ptr(this),
      folly::getCurrentThreadID(),
      (int)processId_);
  // Move readBuffer_ first so that we can get rid
  // of it immediately so that if we return early,
  // we've flushed it.
  BufPtr data = std::move(readBuffer_);

  Optional<ReceivedUdpPacket::Timings::SocketTimestampExt> maybeSockTsExt;
  if (params.ts.has_value()) {
    maybeSockTsExt =
        QuicAsyncUDPSocket::convertToSocketTimestampExt(*params.ts);
  }

  OptionalIntegral<uint8_t> packetTtl;
  if (params.ttl.has_value()) {
    packetTtl = *params.ttl;
  }

  if (params.gro <= 0) {
    if (truncated) {
      // This is an error, drop the packet.
      return;
    }
    data->append(len);
    QUIC_STATS(statsCallback_, onPacketReceived);
    QUIC_STATS(statsCallback_, onRead, len);
    ReceivedUdpPacket udpPacket(std::move(data));
    udpPacket.timings.receiveTimePoint = packetReceiveTime;
    udpPacket.timings.maybeSoftwareTs = maybeSockTsExt;
    udpPacket.tosValue = params.tos;
    udpPacket.ttlValue = packetTtl;
    udpPacket.peerAddress = client;
    handleNetworkData(udpPacket);
  } else {
    // if we receive a truncated packet
    // we still need to consider the prev valid ones
    // AsyncUDPSocket::handleRead() sets the len to be the
    // buffer size in case the data is truncated
    if (truncated) {
      len -= len % params.gro;
    }
    data->append(len);
    QUIC_STATS(statsCallback_, onPacketReceived);
    QUIC_STATS(statsCallback_, onRead, len);

    size_t remaining = len;
    size_t offset = 0;
    while (remaining) {
      if (static_cast<int>(remaining) <= params.gro) {
        // do not clone the last packet
        // start at offset, use all the remaining data
        data->trimStart(offset);
        MVDCHECK_EQ(data->length(), remaining);
        ReceivedUdpPacket udpPacket(std::move(data));
        udpPacket.timings.receiveTimePoint = packetReceiveTime;
        udpPacket.tosValue = params.tos;
        udpPacket.ttlValue = packetTtl;
        udpPacket.timings.maybeSoftwareTs = maybeSockTsExt;
        udpPacket.peerAddress = client;
        handleNetworkData(udpPacket);
        break;
      }
      auto tmp = data->cloneOne();
      // start at offset
      tmp->trimStart(offset);
      // the actual len is len - offset now
      // leave params.gro_ bytes
      tmp->trimEnd(len - offset - params.gro);
      MVDCHECK_EQ(tmp->length(), params.gro);
      offset += params.gro;
      remaining -= params.gro;
      ReceivedUdpPacket udpPacket(std::move(tmp));
      udpPacket.timings.receiveTimePoint = packetReceiveTime;
      udpPacket.tosValue = params.tos;
      udpPacket.ttlValue = packetTtl;
      udpPacket.timings.maybeSoftwareTs = maybeSockTsExt;
      udpPacket.peerAddress = client;
      handleNetworkData(udpPacket);
    }
  }
}

void QuicServerWorker::onSocketReadable(QuicAsyncUDPSocket& sock) noexcept {
  const uint64_t readBufferSize = std::max(
                                      transportSettings_.maxRecvPacketSize,
                                      uint64_t(kDefaultUDPReadBufferSize)) *
      numGROBuffers_;
  const uint16_t numPackets = transportSettings_.maxRecvBatchSize;

  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;

  auto recvResult = sock.recvmmsgNetworkData(
      readBufferSize, numPackets, networkData, totalData);
  if (!recvResult.has_value()) {
    onReadError(
        folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            recvResult.error().message));
    return;
  }
  if (recvResult->maybeNoReadReason) {
    switch (recvResult->maybeNoReadReason.value()) {
      case NoReadReason::NONRETRIABLE_ERROR:
        // pauseRead has already been called inside the wrapper.
        onReadError(
            folly::AsyncSocketException(
                folly::AsyncSocketException::INTERNAL_ERROR,
                "::recvmmsg() failed"));
        return;
      case NoReadReason::RETRIABLE_ERROR:
      case NoReadReason::READ_OK:
      case NoReadReason::EMPTY_DATA:
      case NoReadReason::TRUNCATED:
        return;
    }
  }

  const auto batchReceiveTime = Clock::now();
  for (auto& udpPacket : std::move(networkData).movePackets()) {
    if (udpPacket.buf.empty()) {
      continue;
    }
    auto packetReceiveTime = batchReceiveTime;
    if (udpPacket.timings.maybeSoftwareTs) {
      auto packetRxEpochUs =
          std::chrono::duration_cast<std::chrono::microseconds>(
              udpPacket.timings.maybeSoftwareTs->rawDuration);
      if (packetRxEpochUs != 0us) {
        auto now = std::chrono::system_clock::now();
        auto nowEpochUs = std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch());
        auto rxDelayUs = nowEpochUs - packetRxEpochUs;
        if (rxDelayUs >= 0us) {
          packetReceiveTime -= rxDelayUs;
          QUIC_STATS(statsCallback_, onRxDelaySample, rxDelayUs.count());
        } else {
          MVVLOG(10) << "Negative rx delay: " << rxDelayUs.count() << "us";
        }
      }
    }
    if (packetReceiveTime < largestPacketReceiveTime_) {
      packetReceiveTime = batchReceiveTime;
    }
    largestPacketReceiveTime_ =
        std::max(largestPacketReceiveTime_, packetReceiveTime);
    udpPacket.timings.receiveTimePoint = packetReceiveTime;

    QUIC_STATS(statsCallback_, onPacketReceived);
    QUIC_STATS(statsCallback_, onRead, udpPacket.buf.chainLength());

    handleNetworkData(udpPacket);
  }
}

void QuicServerWorker::handleNetworkData(
    ReceivedUdpPacket& udpPacket,
    bool isForwardedData) noexcept {
  MVCHECK(udpPacket.peerAddress.has_value());
  const auto& client = *udpPacket.peerAddress;
  // if packet drop reason is set, invoke stats cb accordingly
  auto packetDropReason = PacketDropReason::NONE;
  auto maybeReportPacketDrop = folly::makeGuard([&]() {
    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
    }
  });

  try {
    // check error conditions for packet drop & early return
    ContiguousReadCursor cursor(
        udpPacket.buf.front()->data(), udpPacket.buf.front()->length());
    if (shutdown_) {
      MVVLOG(4) << "Packet received after shutdown, dropping";
      packetDropReason = PacketDropReason::SERVER_SHUTDOWN;
    } else if (isBlockListedSrcPort_(client.getPort())) {
      MVVLOG(4) << "Dropping packet with blocklisted src port: "
                << client.getPort();
      packetDropReason = PacketDropReason::INVALID_SRC_PORT;
    } else if (stopping_) {
      packetDropReason = PacketDropReason::SERVER_SHUTDOWN;
    } else if (!cursor.canAdvance(sizeof(uint8_t))) {
      MVVLOG(4) << "Dropping packet too small";
      packetDropReason = PacketDropReason::INVALID_PACKET_INITIAL_BYTE;
    }

    // terminate early
    if (packetDropReason != PacketDropReason::NONE) {
      return;
    }

    uint8_t initialByte = 0;
    // We already checked that we can advance sizeof(uint8_t) bytes
    PROTO_OOPS_LOG_IF(
        !cursor.canAdvance(sizeof(initialByte)),
        proto_oops::getThreadLocalOopsLogger(),
        "quic_server_worker",
        "invariant_violation: packet cursor missing initial byte");
    MVCHECK(cursor.tryReadBE(initialByte));
    HeaderForm headerForm = getHeaderForm(initialByte);

    if (headerForm == HeaderForm::Short) {
      if (auto maybeParsedShortHeader =
              parseShortHeaderInvariants(initialByte, cursor)) {
        RoutingData routingData(
            headerForm,
            false, /* isInitial */
            false, /* is0Rtt */
            std::move(maybeParsedShortHeader->destinationConnId),
            std::nullopt);
        return forwardNetworkData(
            client,
            std::move(routingData),
            NetworkData(std::move(udpPacket)),
            std::nullopt, /* quicVersion */
            isForwardedData);
      }
    } else if (
        auto maybeParsedLongHeader =
            parseLongHeaderInvariant(initialByte, cursor)) {
      // TODO: check version before looking at type
      LongHeader::Types longHeaderType = parseLongHeaderType(initialByte);
      bool isInitial = longHeaderType == LongHeader::Types::Initial;
      bool is0Rtt = longHeaderType == LongHeader::Types::ZeroRtt;
      auto& invariant = maybeParsedLongHeader->invariant;

      if (isInitial) {
        // This stats gets updated even if the client initial will be dropped.
        QUIC_STATS(statsCallback_, onClientInitialReceived, invariant.version);
      }

      if (maybeSendVersionNegotiationPacketOrDrop(
              client, isInitial, invariant, udpPacket.buf.chainLength())) {
        return;
      }

      if (invariant.version == QuicVersion::SCONE_VERSION_1 ||
          invariant.version == QuicVersion::SCONE_VERSION_2) {
        VLOG(4) << "SCONE packet routing: isInitial=" << isInitial
                << " is0RTT=" << is0Rtt
                << " dstCIDLen=" << invariant.dstConnId.size()
                << " srcCIDLen=" << invariant.srcConnId.size();
      }
      bool isClientChosenDcid = isInitial || is0Rtt;
      if (!isClientChosenDcid &&
          invariant.dstConnId.size() < kMinSelfConnectionIdV1Size) {
        // drop packet if connId is present but is not valid.
        MVVLOG(3) << "Dropping packet due to invalid connectionId";
        packetDropReason = PacketDropReason::INVALID_PACKET_CID;
        return;
      }
      RoutingData routingData(
          headerForm,
          isInitial,
          is0Rtt,
          std::move(invariant.dstConnId),
          std::move(invariant.srcConnId));
      return forwardNetworkData(
          client,
          std::move(routingData),
          NetworkData(std::move(udpPacket)),
          invariant.version,
          isForwardedData);
    }

    if (!tryHandlingAsHealthCheck(client, *udpPacket.buf.front())) {
      MVVLOG(6) << "Failed to parse long header";
      packetDropReason = PacketDropReason::PARSE_ERROR_LONG_HEADER;
    }
  } catch (const std::exception& ex) {
    // Drop the packet.
    MVVLOG(6) << "Failed to parse packet header " << ex.what();
    packetDropReason = PacketDropReason::PARSE_ERROR_EXCEPTION;
  }
}

bool QuicServerWorker::tryHandlingAsHealthCheck(
    const quic::SocketAddress& client,
    const Buf& data) {
  // If we cannot parse the long header then it is not a QUIC invariant
  // packet, so just drop it after checking whether it could be a health
  // check.
  if (!healthCheckToken_) {
    return false;
  }

  BufEq eq;
  // TODO: make this constant time, the token might be secret, but we're
  // current assuming it's not.
  if (eq(*healthCheckToken_.value(), data)) {
    // say that we are OK. The response is much smaller than the
    // request, so we are not creating an amplification vector. Also
    // ignore the error code.
    MVVLOG(4) << "Health check request, response=OK";
    socket_->write(client, BufHelpers::copyBuffer("OK"));
    return true;
  }
  return false;
}

void QuicServerWorker::forwardNetworkData(
    const quic::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    const Optional<QuicVersion>& quicVersion,
    bool isForwardedData) {
  // if it's not Client initial or ZeroRtt, AND if the connectionId version
  // mismatches: forward if pktForwarding is enabled else dropPacket
  if (!routingData.clientChosenDcid &&
      !connIdAlgo_->canParse(routingData.destinationConnId)) {
    if (packetForwardingEnabled_ && !isForwardedData) {
      MVVLOG(3) << fmt::format(
          "Forwarding packet with unknown connId version from client={} to another process, routingInfo={}",
          client.describe(),
          logRoutingInfo(routingData.destinationConnId));
      takeoverPktHandler_.forwardPacketToAnotherServer(
          client, std::move(networkData));
      QUIC_STATS(statsCallback_, onPacketForwarded);
      return;
    } else {
      MVVLOG(3) << fmt::format(
          "Dropping packet due to unknown connectionId version, routingInfo={}",
          logRoutingInfo(routingData.destinationConnId));
      QUIC_STATS(
          statsCallback_,
          onPacketDropped,
          PacketDropReason::UNKNOWN_CID_VERSION);
    }
    return;
  }
  routeOrDispatch(
      client,
      std::move(routingData),
      std::move(networkData),
      quicVersion,
      isForwardedData);
}

void QuicServerWorker::routeOrDispatch(
    const quic::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    const Optional<QuicVersion>& quicVersion,
    bool isForwardedData) {
  if (stopping_) {
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::SERVER_SHUTDOWN);
    return;
  }
  size_t dest = workerIndex_;
  if (runState_ && !runState_->peers.empty()) {
    auto parsed = connIdAlgo_->parseConnectionId(routingData.destinationConnId);
    if (parsed.has_value() &&
        (!routingData.clientChosenDcid || parsed->hostId == hostId_ ||
         parsed->hostId == prevHostId_)) {
      dest = static_cast<size_t>(parsed->workerId) % runState_->peers.size();
    }
  }
  if (dest == workerIndex_) {
    dispatchPacketData(
        client,
        std::move(routingData),
        std::move(networkData),
        quicVersion,
        isForwardedData);
    return;
  }
  auto& peer = runState_->peers[dest];
  peer.evb->runInEventBaseThread([target = peer.target,
                                  client = client,
                                  routingData = std::move(routingData),
                                  networkData = std::move(networkData),
                                  quicVersion = quicVersion,
                                  isForwardedData]() mutable {
    if (auto* worker = target->worker) {
      worker->dispatchPacketData(
          client,
          std::move(routingData),
          std::move(networkData),
          quicVersion,
          isForwardedData);
    }
  });
}

void QuicServerWorker::setPacingTimer(
    QuicTimer::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

QuicServerTransport::Ptr QuicServerWorker::makeTransport(
    QuicVersion quicVersion,
    const quic::SocketAddress& client,
    const Optional<ConnectionId>& srcConnId,
    const ConnectionId& dstConnId,
    bool validNewToken,
    const Optional<ConnectionId>& retryOriginalDstConnId) {
  // create 'accepting' transport
  auto* evb = getEventBase();
  auto sock = zeroCopyEnabled_ ? makeAlias() : makeSocket(evb);
  auto trans =
      transportFactory_->make(evb, std::move(sock), client, quicVersion);
  if (trans) {
    globalUnfinishedHandshakes++;
    unfinishedHandshakes_++;

    auto transportSettingsCopy = transportSettings_;
    if (quicVersion == QuicVersion::QUIC_V1_ALIAS ||
        quicVersion == QuicVersion::MVFST_EXPERIMENTAL) {
      transportSettingsCopy.includeCwndHintsInSessionTicket = true;
      transportSettingsCopy.useCwndHintsInSessionTicket = true;
      if (transportSettingsCopy.defaultCongestionController ==
          CongestionControlType::BBR2) {
        transportSettingsCopy.defaultCongestionController =
            CongestionControlType::BBR2Modular;
      }
    } else if (quicVersion == QuicVersion::QUIC_V1_ALIAS2) {
      transportSettingsCopy.includeCwndHintsInSessionTicket = true;
    }

    // Call the override function last so it can override any previous config.
    if (transportSettingsOverrideFn_) {
      transportSettingsOverrideFn_(transportSettingsCopy);
    }
    trans->configureForAccept(
        ServerAcceptParams{
            .transportSettings = std::move(transportSettingsCopy),
            .supportedVersions = supportedVersions_,
            .originalPeerAddress = client,
            .validNewToken = validNewToken,
            .clientConnectionId = srcConnId,
            .clientChosenDestConnectionId = dstConnId,
            .serverConnectionIdParams = ServerConnectionIdParams(
                cidVersion_,
                hostId_,
                static_cast<uint8_t>(processId_),
                workerId_),
            .connIdAlgo = connIdAlgo_.get(),
            .connIdRejector = this,
            .bufAccessor = bufAccessor_.get(),
            .pacingTimer = pacingTimer_,
            .statsCallback = statsCallback_.get()});
    trans->setRoutingCallback(this);
    trans->setHandshakeFinishedCallback(this);
    if (retryOriginalDstConnId) {
      trans->setRetryOriginalDstConnId(*retryOriginalDstConnId);
    }
    auto result = sourceAddressMap_.emplace(
        std::make_pair(std::make_pair(client, dstConnId), trans));
    PROTO_OOPS_LOG_BUILDER_IF(
        !result.second && result.first->second->getState(),
        result.first->second->getState()->oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(
            *result.first->second->getState()),
        "quic_server_worker",
        "invariant_violation: source address map already contains new "
        "connection");
    MVCHECK(result.second);
    trans->accept(quicVersion);
    auto observers = observerList_.getAll();
    for (const auto& observer : observers) {
      const auto& current = observerList_.getAll();
      if (std::ranges::find(current, observer) == current.end()) {
        continue;
      }
      observer->accept(trans.get());
    }
  }

  return trans;
}

PacketDropReason QuicServerWorker::isDstConnIdMisrouted(
    const ConnectionId& dstConnId,
    const quic::SocketAddress& client) {
  // parse dst conn-id to determine if packet was misrouted
  if (!connIdAlgo_->canParse(dstConnId)) {
    MVVLOG(3) << "Dropping packet with bad DCID, routingInfo="
              << logRoutingInfo(dstConnId);
    // TODO do we need to reset?
    return PacketDropReason::PARSE_ERROR_BAD_DCID;
  }

  auto maybeParsedConnIdParam = connIdAlgo_->parseConnectionId(dstConnId);
  if (maybeParsedConnIdParam.hasError()) {
    const auto& ex = maybeParsedConnIdParam.error();
    MVVLOG(3) << fmt::format(
        "Dropping packet due to DCID parsing error={}, "
        "routingInfo = {} ",
        ex.message,
        logRoutingInfo(dstConnId));
    // TODO do we need to reset?
    return PacketDropReason::PARSE_ERROR_DCID;
  }

  const auto& connIdParams = maybeParsedConnIdParam.value();
  if (connIdParams.hostId != prevHostId_ && connIdParams.hostId != hostId_) {
    MVVLOG(3) << fmt::format(
        "Dropping packet routed to wrong host, from client={}, routingInfo={},",
        client.describe(),
        logRoutingInfo(dstConnId));
    return PacketDropReason::ROUTING_ERROR_WRONG_HOST;
  }
  if (connIdParams.processId == static_cast<uint8_t>(processId_)) {
    // There's no existing connection for the packet's CID or the client's
    // addr, and doesn't belong to the old server. Send a Reset.
    MVVLOG(3) << fmt::format(
        "Dropping packet, unknown DCID, from client={}, routingInfo={},",
        client.describe(),
        logRoutingInfo(dstConnId));
    return PacketDropReason::CONNECTION_NOT_FOUND;
  }

  return PacketDropReason::NONE;
}

void QuicServerWorker::dispatchPacketData(
    const quic::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    Optional<QuicVersion> quicVersion,
    bool isForwardedData) noexcept {
  MVDCHECK(socket_);
  MVCHECK(transportFactory_);
  networkData.setPeerAddressForAllPackets(client);

  // if set, log drop reason and do *not* attempt to forward packet
  auto packetDropReason = PacketDropReason::NONE;
  // if set, *should* attempt to forward packet to another server
  bool shouldFwdPacket = false;
  const auto& maybeSrcConnId = routingData.sourceConnId;
  const auto& dstConnId = routingData.destinationConnId;
  auto cit = connectionIdMap_.find(dstConnId);

  // if conditions satisfy, drop packet or fwd to another server
  auto handlePacketFwdOrDrop = folly::makeGuard([&]() {
    if (packetDropReason == PacketDropReason::NONE && !shouldFwdPacket) {
      // nothing to do here, early return
      return;
    }
    // should either be marked as dropped or fwd-ed, can't be both
    PROTO_OOPS_LOG_IF(
        (packetDropReason != PacketDropReason::NONE) == shouldFwdPacket,
        proto_oops::getThreadLocalOopsLogger(),
        "quic_server_worker",
        "invariant_violation: packet should be marked for exactly one of "
        "drop or forward");
    MVCHECK((packetDropReason != PacketDropReason::NONE) ^ shouldFwdPacket);

    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      return;
    }

    packetDropReason = isDstConnIdMisrouted(dstConnId, client);
    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      if (packetDropReason == PacketDropReason::ROUTING_ERROR_WRONG_HOST ||
          packetDropReason == PacketDropReason::CONNECTION_NOT_FOUND) {
        // packet was misrouted, send reset packet
        sendResetPacket(routingData.headerForm, client, networkData, dstConnId);
      }
      return;
    }

    // send reset packet if packet fwd-ing isn't enabled or packet has
    // already been fwd-ed
    if (!packetForwardingEnabled_ || isForwardedData) {
      packetDropReason = PacketDropReason::CANNOT_FORWARD_DATA;
      MVVLOG(3) << fmt::format(
          "Dropping packet, cannot forward, from client={}, routingInfo={},",
          client.describe(),
          logRoutingInfo(dstConnId));
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      sendResetPacket(routingData.headerForm, client, networkData, dstConnId);
      return;
    }

    // Optimistically route to another server if the packet type is not
    // Initial and if there is not any connection associated with the given
    // packet
    MVVLOG(4) << fmt::format(
        "Forwarding packet from client={} to another process, routingInfo={}",
        client.describe(),
        logRoutingInfo(dstConnId));
    takeoverPktHandler_.forwardPacketToAnotherServer(
        client, std::move(networkData));
    QUIC_STATS(statsCallback_, onPacketForwarded);
  });

  // helper fn to handle fwd-ing data to the transport.
  auto fwdNetworkDataToTransport = [&](std::shared_ptr<QuicServerTransport>
                                           transport) {
    PROTO_OOPS_LOG_BUILDER_IF(
        !transport->getEventBase()->isInEventBaseThread() &&
            transport->getState(),
        transport->getState()->oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(
            *transport->getState()),
        "quic_server_worker",
        "invariant_violation: forwarding network data from wrong event base "
        "thread");
    MVDCHECK(transport->getEventBase()->isInEventBaseThread());
    transport->onNetworkData(socket_->address(), std::move(networkData));
    // process pending 0rtt data for this DCID if present
    if (routingData.isInitial && !pending0RttData_.empty()) {
      auto itr = pending0RttData_.find(dstConnId);
      if (itr != pending0RttData_.end()) {
        auto buffered = std::move(itr->second);
        pending0RttData_.erase(itr);
        for (auto& data : buffered) {
          // Drop 0-RTT replays whose source peer differs from the
          // current Initial: address change during handshake is not
          // allowed
          bool peerMismatch = false;
          for (const auto& packet : data.getPackets()) {
            if (!packet.peerAddress.has_value() ||
                *packet.peerAddress != client) {
              peerMismatch = true;
              break;
            }
          }
          if (peerMismatch) {
            QUIC_STATS(
                statsCallback_,
                onPacketDropped,
                PacketDropReason::PEER_ADDRESS_CHANGE);
            continue;
          }
          transport->onNetworkData(socket_->address(), std::move(data));
        }
      }
    }
  };

  if (cit != connectionIdMap_.end()) {
    MVVLOG(10) << "Found existing connection for CID=" << dstConnId.hex() << " "
               << *cit->second.get();
    fwdNetworkDataToTransport(cit->second);
    return;
  }

  if (routingData.headerForm == HeaderForm::Short) {
    // Short headers try linked workers here; long headers do below, after
    // sourceAddressMap_.
    if (dispatchToLinkedWorker(client, routingData, networkData)) {
      return;
    }
    // Drop if short header packet w/ unrecognized dst conn id
    MVVLOG(3) << fmt::format(
        "Dropping short header packet with no connid match routingInfo={}",
        logRoutingInfo(dstConnId));
    // try forwarding the packet to the old server (if it is enabled)
    shouldFwdPacket = true;
    return;
  }

  // For LongHeader packets without existing associated connection, try to
  // route with destinationConnId chosen by the peer and IP address of the
  // peer.
  MVCHECK(routingData.headerForm == HeaderForm::Long);
  auto sit = sourceAddressMap_.find(std::make_pair(client, dstConnId));
  if (sit != sourceAddressMap_.end()) {
    MVVLOG(4) << "Found existing connection for client=" << client << " "
              << sit->second.get();
    fwdNetworkDataToTransport(sit->second);
    return;
  }

  if (dispatchToLinkedWorker(client, routingData, networkData)) {
    return;
  }

  // If it's a 0RTT packet and we have no CID, we probably lost the
  // initial and want to buffer it for a while.
  if (routingData.is0Rtt) {
    // creates vector if it doesn't already exist
    auto& vec = pending0RttData_.insert(dstConnId, {}).first->second;
    if (vec.size() < vec.max_size()) {
      vec.emplace_back(std::move(networkData));
      QUIC_STATS(statsCallback_, onZeroRttBuffered);
    }
    return;
  }

  // non-initial packet w/o existing connection may have been misrouted.
  if (!routingData.isInitial) {
    MVVLOG(3) << fmt::format(
        "Dropping packet from client={}, routingInfo={}",
        client.describe(),
        logRoutingInfo(dstConnId));
    // try forwarding the packet to the old server (if it is enabled)
    shouldFwdPacket = true;
    return;
  }

  // check that we have a proper quic version before creating transport
  MVCHECK(quicVersion.has_value(), "no QUIC version to create transport");
  MVVLOG(4) << fmt::format(
      "Creating new connection for client={}, routingInfo={}",
      client.describe(),
      logRoutingInfo(dstConnId));

  // This could be a new connection, add it in the map
  // verify that the initial packet is at least min initial bytes
  // to avoid amplification attacks. Also check CID sizes.
  if (networkData.getTotalData() < kMinInitialPacketSize ||
      !isValidConnIdLength(dstConnId)) {
    // Don't even attempt to forward the packet, just drop it.
    MVVLOG(3) << "Dropping small initial packet from client=" << client;
    packetDropReason = PacketDropReason::INVALID_PACKET_SIZE_INITIAL;
    return;
  }

  // If there is a token present, decrypt it (could be either a retry
  // token or a new token)
  const Buf* buf = networkData.getPackets().front().buf.front();
  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto maybeEncryptedToken = maybeGetEncryptedToken(cursor);
  bool hasTokenSecret = transportSettings_.retryTokenSecret.has_value();

  Optional<ConnectionId> retryOriginalDstConnId;
  if (hasTokenSecret && maybeEncryptedToken) {
    retryOriginalDstConnId = validateRetryToken(
        *maybeEncryptedToken, dstConnId, client.getIPAddress());
  }

  // If the retryTokenSecret is not set, just skip evaluating validity of
  // token and assume true
  bool isValidRetryToken =
      !hasTokenSecret || retryOriginalDstConnId.has_value();

  // Only a NEW_TOKEN that decrypts with our secret validates the client
  // address.
  bool isValidNewToken = hasTokenSecret && maybeEncryptedToken &&
      validNewToken(*maybeEncryptedToken, client.getIPAddress());

  if (isValidNewToken) {
    QUIC_STATS(statsCallback_, onNewTokenReceived);
  } else if (maybeEncryptedToken && !isValidRetryToken) {
    // Failed to decrypt the token as either a new or retry token
    QUIC_STATS(statsCallback_, onTokenDecryptFailure);
  }

  // If rate-limiting is configured and there is no retry token,
  // send a retry packet back to the client
  if (!isValidRetryToken &&
      ((newConnRateLimiter_ &&
        newConnRateLimiter_->check(networkData.getReceiveTimePoint())) ||
       (unfinishedHandshakeLimitFn_.has_value() &&
        globalUnfinishedHandshakes >= (*unfinishedHandshakeLimitFn_)()))) {
    QUIC_STATS(statsCallback_, onConnectionRateLimited);
    sendRetryPacket(
        client,
        quicVersion.value(),
        dstConnId,
        maybeSrcConnId.value_or(ConnectionId::createZeroLength()));
    return;
  }

  // An Initial sent to one of our Retry source connection ids needs the
  // original destination connection id from its token. Without it, QUIC v1
  // clients would reject the handshake's transport parameters.
  if (maybeEncryptedToken && !isValidRetryToken && !isValidNewToken &&
      hasConnIdTransportParams(quicVersion.value())) {
    auto dstConnIdParams = connIdAlgo_->parseConnectionId(dstConnId);
    if (dstConnIdParams.has_value() && dstConnIdParams->hostId == hostId_) {
      packetDropReason = PacketDropReason::INVALID_RETRY_TOKEN;
      return;
    }
  }

  auto transport = makeTransport(
      quicVersion.value(),
      client,
      maybeSrcConnId,
      dstConnId,
      isValidNewToken,
      retryOriginalDstConnId);
  if (!transport) {
    // Act as though we received a junk Initial – don't forward packet.
    MVCHECK(maybeSrcConnId.has_value());
    LongHeaderInvariant inv{
        QuicVersion::MVFST_INVALID, maybeSrcConnId.value(), dstConnId};
    packetDropReason = PacketDropReason::CANNOT_MAKE_TRANSPORT;
    sendVersionNegotiationPacket(client, inv);
    return;
  }
  fwdNetworkDataToTransport(transport);
}

void QuicServerWorker::sendResetPacket(
    const HeaderForm& headerForm,
    const quic::SocketAddress& client,
    const NetworkData& networkData,
    const ConnectionId& connId) {
  if (headerForm != HeaderForm::Short) {
    // Only send resets in response to short header packets.
    return;
  }
  auto packetSize = networkData.getTotalData();
  if (packetSize <= kMinStatelessPacketSize) {
    // We must decrease the packet size to prevent reset loops. If it's already
    // too small, we can't send one.
    return;
  }
  auto resetSize = std::min<uint16_t>(packetSize, kDefaultMaxUDPPayload);
  // Per the spec, less than 43 we should respond with packet size - 1.
  if (packetSize < 43) {
    resetSize = packetSize - 1;
  } else {
    resetSize = std::max<uint16_t>(
        folly::Random::secureRand32() % resetSize, kMinStatelessPacketSize);
  }
  MVCHECK(transportSettings_.statelessResetTokenSecret.has_value());
  StatelessResetGenerator generator(
      *transportSettings_.statelessResetTokenSecret,
      getAddress().getFullyQualified());
  StatelessResetToken token = generator.generateToken(connId);
  StatelessResetPacketBuilder builder(resetSize, token);
  auto resetData = std::move(builder).buildPacket();
  auto resetDataLen = resetData->computeChainDataLength();
  socket_->write(client, std::move(resetData));
  QUIC_STATS(statsCallback_, onWrite, resetDataLen);
  QUIC_STATS(statsCallback_, onPacketSent);
  QUIC_STATS(statsCallback_, onStatelessReset);
}

Optional<std::string> QuicServerWorker::maybeGetEncryptedToken(
    ContiguousReadCursor& cursor) {
  // Move cursor to the byte right after the initial byte
  uint8_t initialByte = 0;
  if (!cursor.tryReadBE(initialByte)) {
    return std::nullopt;
  }

  // We already know this is an initial packet, which uses a long header
  auto parsedLongHeader = parseLongHeader(initialByte, cursor);
  if (!parsedLongHeader || !parsedLongHeader->parsedLongHeader.has_value()) {
    return std::nullopt;
  }

  auto header = parsedLongHeader->parsedLongHeader.value().header;
  if (!header.hasToken()) {
    return std::nullopt;
  }
  return header.getToken();
}

/**
 * Helper method to calculate the delta between nowInMs and the time the token
 * was issued. This delta is compared against the max lifetime of the token
 * (e.g. 1 day for new tokens and 5 min for retry tokens) to determine
 * validity.
 */
static bool checkTokenAge(uint64_t tokenIssuedMs, uint64_t kTokenValidMs) {
  uint64_t nowInMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

  // Retry timestamps can also come from the future as the system clock can
  // move both forwards and backwards due to it being synchronized by NTP
  auto tokenAgeMs = nowInMs > tokenIssuedMs ? nowInMs - tokenIssuedMs
                                            : tokenIssuedMs - nowInMs;

  return tokenAgeMs <= kTokenValidMs;
}

Optional<ConnectionId> QuicServerWorker::validateRetryToken(
    std::string& encryptedToken,
    const ConnectionId& dstConnId,
    const folly::IPAddress& clientIp) {
  MVCHECK(transportSettings_.retryTokenSecret.has_value());

  TokenGenerator tokenGenerator(transportSettings_.retryTokenSecret.value());

  auto token = tokenGenerator.decryptRetryToken(
      BufHelpers::copyBuffer(encryptedToken), dstConnId, clientIp);
  if (!token || !checkTokenAge(token->timestampInMs, kMaxRetryTokenValidMs)) {
    return std::nullopt;
  }
  return token->originalDstConnId;
}

bool QuicServerWorker::validNewToken(
    std::string& encryptedToken,
    const folly::IPAddress& clientIp) {
  MVCHECK(transportSettings_.retryTokenSecret.has_value());

  TokenGenerator tokenGenerator(transportSettings_.retryTokenSecret.value());

  // Create a pseudo token to generate the assoc data.
  NewToken token(clientIp);

  auto maybeDecryptedNewTokenMs = tokenGenerator.decryptToken(
      BufHelpers::copyBuffer(encryptedToken), token.genAeadAssocData());

  return maybeDecryptedNewTokenMs &&
      checkTokenAge(maybeDecryptedNewTokenMs, kMaxNewTokenValidMs);
}

void QuicServerWorker::sendRetryPacket(
    const quic::SocketAddress& client,
    QuicVersion version,
    const ConnectionId& dstConnId,
    const ConnectionId& srcConnId) {
  if (!transportSettings_.retryTokenSecret.has_value()) {
    MVVLOG(4) << "Not sending retry packet since retry token secret is not set";
    return;
  }

  // Create the encrypted retry token
  TokenGenerator generator(transportSettings_.retryTokenSecret.value());

  const auto retrySrcConnId = makeRetrySourceConnId(dstConnId);
  // RetryToken defaults to currentTimeInMs
  RetryToken retryToken(dstConnId, client.getIPAddress(), client.getPort());
  retryToken.retrySrcConnId = retrySrcConnId;
  auto encryptedToken = generator.encryptToken(retryToken);

  MVCHECK(encryptedToken.has_value());
  std::string encryptedTokenStr = encryptedToken.value()->toString();

  // Create the integrity tag
  // For the tag to be correctly validated by the client, the initalByte
  // needs to match the initialByte in the retry packet
  uint8_t initialByte = kHeaderFormMask | LongHeader::kFixedBitMask |
      (static_cast<uint8_t>(LongHeader::Types::Retry)
       << LongHeader::kTypeShift);

  // Clients choose the integrity tag key from the Retry's version, so it must
  // be the version of the client's Initial.
  PseudoRetryPacketBuilder pseudoBuilder(
      initialByte,
      retrySrcConnId, /* src conn id */
      srcConnId, /* dst conn id */
      dstConnId, /* original dst conn id */
      version,
      BufHelpers::copyBuffer(encryptedTokenStr));
  BufPtr pseudoRetryPacketBuf = std::move(pseudoBuilder).buildPacket();
  FizzRetryIntegrityTagGenerator fizzRetryIntegrityTagGenerator;
  auto integrityTagBuf = fizzRetryIntegrityTagGenerator.getRetryIntegrityTag(
      version, pseudoRetryPacketBuf.get());
  integrityTagBuf->coalesce();
  ContiguousReadCursor cursor(
      integrityTagBuf->data(), integrityTagBuf->length());

  RetryPacket::IntegrityTagType integrityTag = {0};
  // The reason we expect this to succeed is that the
  // FizzRetryIntegrityTagGenerator creates an AES-GCM-128 AEAD and the tag
  // length for that cipher is 16 bytes, which is the same as the size of the
  // integrityTag variable.
  MVCHECK(cursor.tryPull(integrityTag.data(), integrityTag.size()));

  // Create the actual retry packet
  RetryPacketBuilder builder(
      retrySrcConnId, /* src conn id */
      srcConnId, /* dst conn id */
      version,
      std::move(encryptedTokenStr),
      integrityTag);

  auto retryData = std::move(builder).buildPacket();
  auto retryDataLen = retryData->computeChainDataLength();

  socket_->write(client, retryData);
  QUIC_STATS(statsCallback_, onWrite, retryDataLen);
  QUIC_STATS(statsCallback_, onPacketSent);
}

ConnectionId QuicServerWorker::makeRetrySourceConnId(
    const ConnectionId& clientDstConnId) {
  constexpr size_t kMaxEncodingAttempts = 32;
  ServerConnectionIdParams params(
      cidVersion_, hostId_, static_cast<uint8_t>(processId_), workerId_);
  for (size_t attempt = 0; attempt < kMaxEncodingAttempts; ++attempt) {
    auto connId = connIdAlgo_->encodeConnectionId(params);
    if (connId.hasError()) {
      break;
    }
    // The client's next Initial must pass this server's DCID length checks,
    // and RFC 9000 forbids reusing the client's destination connection id.
    if (isValidConnIdLength(*connId) && *connId != clientDstConnId &&
        !rejectConnectionId(*connId)) {
      return connId.value();
    }
  }
  MVVLOG(3) << "Failed to encode a Retry source connection id, using a "
            << "random one";
  return ConnectionId::createRandom(kDefaultConnectionIdSize).value();
}

void QuicServerWorker::allowBeingTakenOver(
    std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
    const quic::SocketAddress& address) {
  MVDCHECK(!takeoverCB_);
  // We instantiate and bind the TakeoverHandlerCallback to the given address.
  // It is reset by resetTakeoverHandler() (e.g. to roll back a partially
  // installed handler for retry) and by shutdownAllConnections() at teardown.
  auto takeoverCb = std::make_unique<TakeoverHandlerCallback>(
      this, takeoverPktHandler_, transportSettings_, std::move(socket));
  takeoverCb->bind(address, started_);
  takeoverCB_ = std::move(takeoverCb);
}

const quic::SocketAddress& QuicServerWorker::overrideTakeoverHandlerAddress(
    std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
    const quic::SocketAddress& address) {
  MVCHECK(takeoverCB_);
  takeoverCB_->rebind(std::move(socket), address, started_);
  return takeoverCB_->getAddress();
}

void QuicServerWorker::resetTakeoverHandler() {
  if (takeoverCB_) {
    takeoverCB_->pause();
    takeoverCB_.reset();
  }
}

void QuicServerWorker::startPacketForwarding(
    const quic::SocketAddress& destAddr) {
  packetForwardingEnabled_ = true;
  takeoverPktHandler_.setDestination(destAddr);
}

void QuicServerWorker::stopPacketForwarding() {
  packetForwardingEnabled_ = false;
  takeoverPktHandler_.stop();
}

void QuicServerWorker::stopPacketForwardingAfter(
    std::chrono::milliseconds delay) {
  if (delay.count() == 0) {
    stopPacketForwarding();
    return;
  }
  takeoverPktHandler_.stopAfter(delay);
}

bool QuicServerWorker::setPredecessor(QuicServerWorker* predecessor) {
  MVCHECK(predecessor);
  MVCHECK_EQ(predecessor->getEventBase(), getEventBase());
  MVDCHECK(getEventBase()->isInEventBaseThread());
  // Only an unlinked worker joins, and only behind the newest worker of a
  // chain, so a link can never form a cycle.
  if (predecessor == this || shutdown_ || predecessor->shutdown_ ||
      predecessor_ || successor_ || predecessor->successor_) {
    return false;
  }
  predecessor_ = predecessor;
  predecessor->successor_ = this;
  return true;
}

void QuicServerWorker::unlinkFromChain() noexcept {
  if (successor_) {
    successor_->predecessor_ = predecessor_;
  }
  if (predecessor_) {
    predecessor_->successor_ = successor_;
  }
  predecessor_ = nullptr;
  successor_ = nullptr;
}

const QuicServerWorker* QuicServerWorker::newestLinkedWorker() const noexcept {
  const auto* newest = this;
  while (newest->successor_) {
    newest = newest->successor_;
  }
  return newest;
}

QuicServerTransport::Ptr QuicServerWorker::findExistingTransport(
    const quic::SocketAddress& client,
    const RoutingData& routingData) const {
  const auto& dstConnId = routingData.destinationConnId;
  if (auto it = connectionIdMap_.find(dstConnId);
      it != connectionIdMap_.end()) {
    return it->second;
  }
  if (routingData.headerForm == HeaderForm::Long) {
    if (auto it = sourceAddressMap_.find(std::make_pair(client, dstConnId));
        it != sourceAddressMap_.end()) {
      return it->second;
    }
  }
  return nullptr;
}

bool QuicServerWorker::dispatchToLinkedWorker(
    const quic::SocketAddress& client,
    const RoutingData& routingData,
    NetworkData& networkData) {
  for (const auto* worker = newestLinkedWorker(); worker;
       worker = worker->predecessor_) {
    if (worker == this) {
      continue;
    }
    if (auto transport = worker->findExistingTransport(client, routingData)) {
      MVVLOG(4) << fmt::format(
          "Found connection in linked worker for client={}, routingInfo={}",
          client.describe(),
          logRoutingInfo(routingData.destinationConnId));
      QUIC_STATS(statsCallback_, onPacketRoutedToLinkedWorker);
      transport->onNetworkData(socket_->address(), std::move(networkData));
      return true;
    }
  }
  return false;
}

void QuicServerWorker::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  MVVLOG(4) << "QuicServer readerr: " << ex.what();
  if (runState_) {
    runState_->requestStop(LocalErrorCode::INTERNAL_ERROR);
  } else {
    stopLocal(LocalErrorCode::INTERNAL_ERROR);
  }
}

void QuicServerWorker::onReadClosed() noexcept {
  stopLocal(LocalErrorCode::SHUTTING_DOWN);
}

int QuicServerWorker::getTakeoverHandlerSocketFD() {
  if (!takeoverCB_) {
    return -1;
  }
  return takeoverCB_->getSocketFD();
}

TakeoverProtocolVersion QuicServerWorker::getTakeoverProtocolVersion()
    const noexcept {
  return takeoverPktHandler_.getTakeoverProtocolVersion();
}

void QuicServerWorker::setProcessId(enum ProcessId id) noexcept {
  processId_ = id;
}

ProcessId QuicServerWorker::getProcessId() const noexcept {
  return processId_;
}

void QuicServerWorker::setWorkerId(uint8_t id) noexcept {
  workerId_ = id;
}

uint8_t QuicServerWorker::getWorkerId() const noexcept {
  return workerId_;
}

void QuicServerWorker::setHostId(uint32_t hostId) noexcept {
  if (hostId_ == hostId) {
    MVLOG_WARNING << "HostId is already set to " << hostId;
    return;
  }
  prevHostId_ = hostId_;
  hostId_ = hostId;
}

void QuicServerWorker::setConnectionIdVersion(
    ConnectionIdVersion cidVersion) noexcept {
  cidVersion_ = cidVersion;
}

void QuicServerWorker::setNewConnectionSocketFactory(
    QuicUDPSocketFactory* factory) {
  socketFactory_ = factory;
  takeoverPktHandler_.setSocketFactory(socketFactory_);
}

void QuicServerWorker::setTransportFactory(
    QuicServerTransportFactory* factory) {
  transportFactory_ = factory;
}

void QuicServerWorker::setSupportedVersions(
    const std::vector<QuicVersion>& supportedVersions) {
  supportedVersions_ = supportedVersions;
}

void QuicServerWorker::rejectNewConnections(
    std::function<bool(const quic::SocketAddress&)> rejectNewConnections) {
  rejectNewConnections_ = std::move(rejectNewConnections);
}

void QuicServerWorker::setPrimingEnabledCallback(
    std::function<bool()> isPrimingEnabled) {
  isPrimingEnabled_ = std::move(isPrimingEnabled);
}

void QuicServerWorker::setIsBlockListedSrcPort(
    std::function<bool(uint16_t)> isBlockListedSrcPort) {
  isBlockListedSrcPort_ = std::move(isBlockListedSrcPort);
}

void QuicServerWorker::setHealthCheckToken(
    const std::string& healthCheckToken) {
  healthCheckToken_ = BufHelpers::copyBuffer(healthCheckToken);
}

std::unique_ptr<FollyAsyncUDPSocketAlias> QuicServerWorker::makeSocket(
    folly::EventBase* evb) const {
  MVCHECK(socket_);
  auto sock = socketFactory_->make(evb, socket_->getNetworkSocket().toFd());
  if (sock && mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(sock->getNetworkSocket().toFd());
  }
  return sock;
}

std::unique_ptr<FollyAsyncUDPSocketAlias> QuicServerWorker::makeSocket(
    folly::EventBase* evb,
    int fd) const {
  auto sock = socketFactory_->make(evb, fd);
  if (sock && mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(sock->getNetworkSocket().toFd());
  }
  return sock;
}

std::unique_ptr<FollyAsyncUDPSocketAlias> QuicServerWorker::makeAlias() const {
  MVCHECK(socket_);
  auto sock = socketFactory_->makeAlias(socket_.get());
  if (sock && mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(sock->getNetworkSocket().toFd());
  }
  return sock;
}

const QuicServerWorker::ConnIdToTransportMap&
QuicServerWorker::getConnectionIdMap() const {
  return connectionIdMap_;
}

const QuicServerWorker::SrcToTransportMap&
QuicServerWorker::getSrcToTransportMap() const {
  return sourceAddressMap_;
}

void QuicServerWorker::onConnectionIdAvailable(
    QuicServerTransport::Ptr transport,
    ConnectionId id) noexcept {
  MVVLOG(4) << "Adding into connectionIdMap_ for CID=" << id << " "
            << *transport;
  QuicServerTransport* transportPtr = transport.get();
  std::weak_ptr<QuicServerTransport> weakTransport = transport;
  auto result =
      connectionIdMap_.emplace(std::make_pair(id, std::move(transport)));
  if (!result.second) {
    // In the case of duplicates, log if they represent the same transport,
    // or different ones.
    auto it = result.first;
    QuicServerTransport* existingTransportPtr = it->second.get();
    MVLOG_ERROR << "connectionIdMap_ already has CID=" << id
                << " Is same transport: "
                << (existingTransportPtr == transportPtr);
  }
  if (boundServerTransports_.emplace(transportPtr, weakTransport).second) {
    if (!isScheduled()) {
      // If we aren't currently running, start the timer.
      evb_->timer().scheduleTimeout(this, timeLoggingSamplingInterval_);
    }
  }
}

void QuicServerWorker::onConnectionIdRetired(
    QuicServerTransport::Ref transport,
    ConnectionId id) noexcept {
  auto it = connectionIdMap_.find(id);
  if (it == connectionIdMap_.end()) {
    MVLOG_ERROR << "Failed to retire CID=" << id << " " << transport;
  } else {
    MVVLOG(4) << "Retiring CID=" << id << " " << transport;
    connectionIdMap_.erase(it);
  }
}

void QuicServerWorker::onConnectionIdBound(
    QuicServerTransport::Ptr transport) noexcept {
  auto clientInitialDestCid = transport->getClientChosenDestConnectionId();
  PROTO_OOPS_LOG_BUILDER_IF(
      !clientInitialDestCid && transport->getState(),
      transport->getState()->oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(
          *transport->getState()),
      "quic_server_worker",
      "invariant_violation: bound connection missing client-chosen "
      "destination connection id");
  MVCHECK(clientInitialDestCid);
  auto source = std::make_pair(
      transport->getOriginalPeerAddress(), *clientInitialDestCid);
  MVVLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;
  auto iter = sourceAddressMap_.find(source);
  if (iter == sourceAddressMap_.end() || iter->second != transport) {
    MVLOG_ERROR << "Transport not match, client=" << *transport;
  } else {
    sourceAddressMap_.erase(source);
  }
}

void QuicServerWorker::onConnectionUnbound(
    QuicServerTransport* transport,
    const QuicServerTransport::SourceIdentity& source,
    const std::vector<ConnectionIdData>& connectionIdData) noexcept {
  MVVLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;

  auto& localConnectionError = transport->getState()->localConnectionError;
  if (transport->getConnectionsStats().totalBytesSent == 0 &&
      !(localConnectionError && localConnectionError->code.asLocalErrorCode() &&
        *localConnectionError->code.asLocalErrorCode() ==
            LocalErrorCode::CONNECTION_ABANDONED)) {
    auto conn = transport->getState();
    if (!conn || conn->version != QuicVersion::MVFST_PRIMING) {
      QUIC_STATS(statsCallback_, onConnectionCloseZeroBytesWritten);
    }
  }

  // Ensures we only process `onConnectionUnbound()` once.
  transport->setRoutingCallback(nullptr);
  boundServerTransports_.erase(transport);
  // Cancel the timeout if we don't have any connections.
  if (boundServerTransports_.empty()) {
    cancelTimeout();
  }

  for (auto& connId : connectionIdData) {
    MVVLOG(4) << fmt::format(
        "Removing CID from connectionIdMap_, routingInfo={}",
        logRoutingInfo(connId.connId));
    auto it = connectionIdMap_.find(connId.connId);
    // This should be nullptr in most cases. In order to investigate if
    // an incorrect server transport is removed, this will be set to the value
    // of the incorrect transport, to see if boundServerTransports_ will
    // still hold a pointer to the incorrect transport.
    QuicServerTransport* incorrectTransportPtr = nullptr;
    if (it == connectionIdMap_.end()) {
      MVVLOG(3) << "CID not found in connectionIdMap_ CID= " << connId.connId;
    } else {
      QuicServerTransport* existingPtr = it->second.get();
      if (existingPtr != transport) {
        MVLOG_ERROR << "Incorrect transport being removed for duplicate CID="
                    << connId.connId;
        incorrectTransportPtr = existingPtr;
      }
    }
    connectionIdMap_.erase(connId.connId);
    if (incorrectTransportPtr != nullptr) {
      if (boundServerTransports_.find(incorrectTransportPtr) !=
          boundServerTransports_.end()) {
        MVLOG_ERROR
            << "boundServerTransports_ contains deleted transport for duplicate CID="
            << connId.connId;
      }
    }
  }

  auto iter = sourceAddressMap_.find(source);
  if (iter != sourceAddressMap_.end() && iter->second.get() == transport) {
    sourceAddressMap_.erase(iter);
  }
}

void QuicServerWorker::onHandshakeFinished() noexcept {
  MVCHECK_GE(--unfinishedHandshakes_, 0);
  MVCHECK_GE(--globalUnfinishedHandshakes, 0);
}

void QuicServerWorker::onHandshakeUnfinished() noexcept {
  MVCHECK_GE(--unfinishedHandshakes_, 0);
  MVCHECK_GE(--globalUnfinishedHandshakes, 0);
}

void QuicServerWorker::stopLocal(LocalErrorCode error) {
  if (stopping_) {
    return;
  }
  stopping_ = true;
  if (runState_ && workerIndex_ < runState_->peers.size()) {
    runState_->peers[workerIndex_].target->worker = nullptr;
  }
  shutdownAllConnections(error);
}

void QuicServerWorker::shutdownAllConnections(LocalErrorCode error) {
  MVVLOG(4) << "QuicServer shutdown all connections."
            << " addressMap=" << sourceAddressMap_.size()
            << " connectionIdMap=" << connectionIdMap_.size();
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  stopping_ = true;
  unlinkFromChain();
  if (runState_ && workerIndex_ < runState_->peers.size()) {
    runState_->peers[workerIndex_].target->worker = nullptr;
  }
  if (quicSocket_) {
    quicSocket_->pauseRead();
  } else if (socket_) {
    socket_->pauseRead();
  }
  if (takeoverCB_) {
    takeoverCB_->pause();
  }

  folly::F14FastSet<QuicServerTransport*> seen;
  std::vector<QuicServerTransport::Ptr> transports;
  for (auto& it : sourceAddressMap_) {
    if (it.second && seen.insert(it.second.get()).second) {
      transports.push_back(it.second);
    }
  }
  for (auto& it : connectionIdMap_) {
    if (it.second && seen.insert(it.second.get()).second) {
      transports.push_back(it.second);
    }
  }
  for (auto& it : boundServerTransports_) {
    if (auto t = it.second.lock()) {
      if (seen.insert(t.get()).second) {
        transports.push_back(std::move(t));
      }
    }
  }
  for (auto& transport : transports) {
    transport->setRoutingCallback(nullptr);
    transport->setTransportStatsCallback(nullptr);
    transport->setHandshakeFinishedCallback(nullptr);
  }
  for (auto& transport : transports) {
    transport->closeNow(
        QuicError(QuicErrorCode(error), std::string("shutting down")));
  }
  transports.clear();
  if (unfinishedHandshakes_ != 0) {
    MVCHECK_GE(
        globalUnfinishedHandshakes.fetch_sub(
            unfinishedHandshakes_, std::memory_order_relaxed) -
            unfinishedHandshakes_,
        0);
    unfinishedHandshakes_ = 0;
  }
  cancelTimeout();
  boundServerTransports_.clear();
  sourceAddressMap_.clear();
  connectionIdMap_.clear();
  pending0RttData_.clear();
  takeoverPktHandler_.stop();
  if (statsCallback_) {
    statsCallback_.reset();
  }
  quicReadCallbackAdapter_.reset();
  quicSocket_.reset();
  socket_.reset();
  takeoverCB_.reset();
  pacingTimer_.reset();
  evb_.reset();
}

QuicServerWorker::~QuicServerWorker() {
  stopLocal(LocalErrorCode::SHUTTING_DOWN);
}

bool QuicServerWorker::rejectConnectionId(
    const ConnectionId& candidate) const noexcept {
  for (const auto* worker = newestLinkedWorker(); worker;
       worker = worker->predecessor_) {
    if (worker->connectionIdMap_.find(candidate) !=
        worker->connectionIdMap_.end()) {
      return true;
    }
  }
  return false;
}

std::string QuicServerWorker::logRoutingInfo(const ConnectionId& connId) const {
  std::string base = fmt::format(
      "CID={}, cidVersion={}, workerId={}, processId={}, hostId={}, threadId={}, ",
      connId.hex(),
      (uint32_t)cidVersion_,
      (uint32_t)workerId_,
      (uint32_t)processId_,
      (uint32_t)hostId_,
      folly::getCurrentThreadID());

  if (connIdAlgo_->canParse(connId)) {
    auto maybeParsedConnIdParam = connIdAlgo_->parseConnectionId(connId);
    if (maybeParsedConnIdParam.has_value()) {
      const auto& connIdParam = maybeParsedConnIdParam.value();
      return base +
          fmt::format(
                 "cidVersion in packet={}, workerId in packet={}, processId in packet={}, hostId in packet={}, ",
                 (uint32_t)connIdParam.version,
                 (uint32_t)connIdParam.workerId,
                 (uint32_t)connIdParam.processId,
                 (uint32_t)connIdParam.hostId);
    }
  }

  return base;
}

QuicServerWorker::AcceptObserverList::AcceptObserverList(
    QuicServerWorker* worker)
    : worker_(worker) {}

QuicServerWorker::AcceptObserverList::~AcceptObserverList() {
  for (const auto& cb : observers_) {
    cb->acceptorDestroy(worker_);
  }
}

void QuicServerWorker::AcceptObserverList::add(AcceptObserver* observer) {
  // adding the same observer multiple times is not allowed
  MVCHECK(
      std::find(observers_.begin(), observers_.end(), observer) ==
      observers_.end());

  observers_.emplace_back(MVCHECK_NOTNULL(observer));
  observer->observerAttach(worker_);
}

bool QuicServerWorker::AcceptObserverList::remove(AcceptObserver* observer) {
  auto it = std::find(observers_.begin(), observers_.end(), observer);
  if (it == observers_.end()) {
    return false;
  }
  observer->observerDetach(worker_);
  observers_.erase(it);
  return true;
}

void QuicServerWorker::getAllConnectionsStats(
    std::vector<QuicConnectionStats>& stats) {
  folly::F14FastMap<QuicServerTransport::Ptr, uint32_t> uniqueConns;
  for (const auto& [connId, transport] : connectionIdMap_) {
    if (transport && transport->getState()) {
      uniqueConns[transport]++;
    }
  }
  stats.reserve(stats.size() + uniqueConns.size());
  for (const auto& [transport, count] : uniqueConns) {
    QuicConnectionStats connStats = transport->getConnectionsStats();
    connStats.workerID = workerId_;
    connStats.numConnIDs = count;
    stats.emplace_back(connStats);
  }
}

size_t QuicServerWorker::SourceIdentityHash::operator()(
    const QuicServerTransport::SourceIdentity& sid) const {
  static const ::siphash::Key hashKey(
      folly::Random::secureRandom<std::uint64_t>(),
      folly::Random::secureRandom<std::uint64_t>());

  // We opt to manually lay out the key in order to ensure that our key
  // has a unique object representation. (i.e. no padding).
  //
  // (sockaddr, quic connection id, port)
  constexpr size_t kKeySize =
      sizeof(struct sockaddr_storage) + kMaxConnectionIdSize + sizeof(uint16_t);

  // Zero initialization is intentional here.
  std::array<unsigned char, kKeySize> key{};

  struct sockaddr_storage storage{};

  const auto& sockaddr = sid.first;
  sockaddr.getAddress(&storage);
  memcpy(key.data(), &storage, sizeof(struct sockaddr_storage));

  unsigned char* connid = key.data() + sizeof(struct sockaddr_storage);
  memcpy(connid, sid.second.data(), sid.second.size());

  uint16_t port;
  port = sid.first.getPort();
  memcpy(
      key.data() + sizeof(struct sockaddr_storage) + kMaxConnectionIdSize,
      &port,
      sizeof(uint16_t));

  return siphash::siphash24(key.data(), key.size(), &hashKey);
}

} // namespace quic
