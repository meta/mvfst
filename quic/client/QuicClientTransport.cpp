/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/QuicClientTransport.h>
#include <quic/common/MvfstLogging.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/loss/QuicLossFunctions.h>

#include <folly/String.h>

namespace {
constexpr socklen_t kAddrLen = sizeof(sockaddr_storage);
} // namespace

namespace quic {

QuicClientTransport::~QuicClientTransport() {
  MVVLOG(10) << "Destroyed connection to server=" << conn_->peerAddress;
  onApplicationClose();
  // Close without draining.
  closeImpl(
      QuicError(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from client destructor")),
      false /* drainConnection */);
  // closeImpl may have been called earlier with drain = true, so force close.
  closeUdpSocket();

  cleanupHappyEyeballsState();
}

void QuicClientTransport::onNotifyDataAvailable(
    QuicAsyncUDPSocket& sock) noexcept {
  auto self = this->shared_from_this();
  MVCHECK(conn_, "trying to receive packets without a connection");
  recordNetworkReadCallbackStart();
  auto readBufferSize = std::max(
                            conn_->transportSettings.maxRecvPacketSize,
                            uint64_t(kDefaultUDPReadBufferSize)) *
      numGROBuffers_;
  const uint16_t numPackets = conn_->transportSettings.maxRecvBatchSize;

  auto result = [&]() -> quic::Expected<void, QuicError> {
    if (conn_->transportSettings.networkDataPerSocketRead) {
      return readWithRecvmsgSinglePacketLoop(sock, readBufferSize);
    } else if (conn_->transportSettings.shouldUseWrapperRecvmmsgForBatchRecv) {
      return readWithRecvmmsgWrapper(sock, readBufferSize, numPackets);
    } else if (conn_->transportSettings.shouldUseRecvmmsgForBatchRecv) {
      return readWithRecvmmsg(sock, readBufferSize, numPackets);
    } else {
      return readWithRecvmsg(sock, readBufferSize, numPackets);
    }
  }();
  if (!result.has_value()) {
    asyncClose(result.error());
  }
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmmsgWrapper(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;

  const auto result = sock.recvmmsgNetworkData(
      readBufferSize, numPackets, networkData, totalData);

  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }

  // track the received packets
  for (const auto& packet : networkData.getPackets()) {
    if (packet.buf.empty()) {
      continue;
    }
    auto len = packet.buf.chainLength();
    maybeQlogDatagram(len);
  }
  trackDatagramsReceived(
      networkData.getPackets().size(), networkData.getTotalData());

  // Propagate errors
  // TODO(bschlinker): Investigate generalization of loopDetectorCallback
  // TODO(bschlinker): Consider merging this into ReadCallback
  if (result->maybeNoReadReason) {
    const auto& noReadReason = result->maybeNoReadReason.value();
    switch (noReadReason) {
      case NoReadReason::RETRIABLE_ERROR:
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
        }
        break;
      case NoReadReason::NONRETRIABLE_ERROR:
        // If we got a non-retriable error, we might have received
        // a packet that we could process, however let's just quit early.
        sock.pauseRead();
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
        }
        onReadError(
            folly::AsyncSocketException(
                folly::AsyncSocketException::INTERNAL_ERROR,
                "::recvmmsg() failed",
                errno));
        break;
      case NoReadReason::READ_OK:
      case NoReadReason::EMPTY_DATA:
      case NoReadReason::TRUNCATED:
        break;
    }
  }
  auto localAddressRes = sock.address();
  if (localAddressRes.hasError()) [[unlikely]] {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(localAddressRes.value(), std::move(networkData));
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  recvmmsgStorage_.resize(numPackets);
  auto recvResult =
      recvMmsg(sock, readBufferSize, numPackets, networkData, totalData);
  if (!recvResult.has_value()) {
    return recvResult;
  }

  auto localAddressRes = sock.address();
  if (localAddressRes.hasError()) [[unlikely]] {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(localAddressRes.value(), std::move(networkData));
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  auto recvResult =
      recvMsg(sock, readBufferSize, numPackets, networkData, totalData);
  if (!recvResult.has_value()) {
    return recvResult;
  }

  auto localAddressRes = sock.address();
  if (localAddressRes.hasError()) [[unlikely]] {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(localAddressRes.value(), std::move(networkData));
}

quic::Expected<void, QuicError> QuicClientTransport::recvMmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets,
    NetworkData& networkData,
    size_t& totalData) {
  auto& msgs = recvmmsgStorage_.msgs;
  int flags = 0;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  auto groResult = sock.getGRO();
  if (!groResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get GRO status: {}", groResult.error().message)));
  }
  bool useGRO = groResult.value() > 0;

  auto tsResult = sock.getTimestamping();
  if (!tsResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get timestamping status: {}",
            tsResult.error().message)));
  }
  bool useTs = tsResult.value() > 0;

  auto tosResult = sock.getRecvTos();
  if (!tosResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get TOS status: {}", tosResult.error().message)));
  }
  bool recvTos = tosResult.value();

  bool checkCmsgs = useGRO || useTs || recvTos;
  std::vector<std::array<
      char,
      QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace>>
      controlVec(checkCmsgs ? numPackets : 0);

  // we need to consider MSG_TRUNC too
  if (useGRO) {
    flags |= MSG_TRUNC;
  }
#endif
  auto localAddressFamilyResult = sock.getLocalAddressFamily();
  if (!localAddressFamilyResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get address family: {}",
            localAddressFamilyResult.error().message)));
  }
  const auto localAddressFamily = localAddressFamilyResult.value();

  for (uint16_t i = 0; i < numPackets; ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& iovec = recvmmsgStorage_.impl_[i].iovec;
    struct msghdr* msg = &msgs[i].msg_hdr;

    if (!readBuffer) {
      readBuffer = BufHelpers::createCombined(readBufferSize);
      iovec.iov_base = readBuffer->writableData();
      iovec.iov_len = readBufferSize;
      msg->msg_iov = &iovec;
      msg->msg_iovlen = 1;
    }
    MVCHECK(readBuffer != nullptr);

    auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);
    rawAddr->sa_family = localAddressFamily;
    msg->msg_name = rawAddr;
    msg->msg_namelen = kAddrLen;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (checkCmsgs) {
      ::memset(controlVec[i].data(), 0, controlVec[i].size());
      msg->msg_control = controlVec[i].data();
      msg->msg_controllen = controlVec[i].size();
    }
#endif
  }

  int numMsgsRecvd = sock.recvmmsg(msgs.data(), numPackets, flags, nullptr);
  if (numMsgsRecvd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Exit, socket will notify us again when socket is readable.
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
      }
      return {};
    }
    // If we got a non-retriable error, we might have received
    // a packet that we could process, however let's just quit early.
    sock.pauseRead();
    if (conn_->loopDetectorCallback) {
      conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "recvmmsg() failed, errno={} {}", errno, folly::errnoStr(errno))));
  }

  MVCHECK_LE(numMsgsRecvd, numPackets);
  for (uint16_t i = 0; i < static_cast<uint16_t>(numMsgsRecvd); ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& msg = msgs[i];

    size_t bytesRead = msg.msg_len;
    if (bytesRead == 0) {
      // Empty datagram, this is probably garbage matching our tuple, we
      // should ignore such datagrams.
      continue;
    }
    QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (checkCmsgs) {
      QuicAsyncUDPSocket::fromMsg(params, msg.msg_hdr);

      // truncated
      if (bytesRead > readBufferSize) {
        bytesRead = readBufferSize;
        if (params.gro > 0) {
          bytesRead = bytesRead - bytesRead % params.gro;
        }
      }
    }
#endif
    totalData += bytesRead;
    auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);

    ReceivedUdpPacket::Timings timings;
    if (params.ts.has_value()) {
      timings.maybeSoftwareTs =
          QuicAsyncUDPSocket::convertToSocketTimestampExt(*params.ts);
    }

    MVVLOG(10) << "Got data from socket len=" << bytesRead;
    readBuffer->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets = networkData.getPackets().size() +
          ((len + params.gro - 1) / params.gro);
      networkData.reserve(totalNumPackets);
      quic::SocketAddress packetPeerAddress;
      packetPeerAddress.setFromSockaddr(rawAddr, kAddrLen);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffer->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          auto& packet =
              networkData.emplacePacket(std::move(tmp), timings, params.tos);
          packet.peerAddress = packetPeerAddress;
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffer->trimStart(offset);
          DCHECK_EQ(readBuffer->length(), remaining);
          remaining = 0;
          auto& packet = networkData.emplacePacket(
              std::move(readBuffer), timings, params.tos);
          packet.peerAddress = packetPeerAddress;
          // This is the last packet. Break here to silence the linter's warning
          // about a use-after-move in the next iteration of the loop
          break;
        }
      }
    } else {
      networkData.emplacePacket(
          std::move(readBuffer), timings, params.tos, rawAddr, kAddrLen);
    }

    maybeQlogDatagram(bytesRead);
  }
  trackDatagramsReceived(
      networkData.getPackets().size(), networkData.getTotalData());

  return {};
}

void QuicClientTransport::RecvmmsgStorage::resize(size_t numPackets) {
  if (msgs.size() != numPackets) {
    msgs.resize(numPackets);
    impl_.resize(numPackets);
  }
}

void QuicClientTransport::setHappyEyeballsEnabled(bool happyEyeballsEnabled) {
  happyEyeballsEnabled_ = happyEyeballsEnabled;
}

void QuicClientTransport::setHappyEyeballsCachedFamily(
    sa_family_t cachedFamily) {
  happyEyeballsCachedFamily_ = cachedFamily;
}

void QuicClientTransport::addNewSocket(
    std::unique_ptr<QuicAsyncUDPSocket> socket) {
  happyEyeballsAddSocket(*clientConn_, std::move(socket));
}

void QuicClientTransport::
    happyEyeballsConnAttemptDelayTimeoutExpired() noexcept {
  // Declare 0-RTT data as lost so that they will be retransmitted over the
  // second socket.
  happyEyeballsStartSecondSocket(clientConn_->happyEyeballsState);
  // If this gets called from the write path then we haven't added the packets
  // to the outstanding packet list yet.
  runOnEvbAsyncOp({.type = AsyncOpType::MarkZeroRttPacketsLost});
}

void QuicClientTransport::cleanupHappyEyeballsState() {
  if (clientConn_->happyEyeballsState.secondSocket) {
    auto sock = std::move(clientConn_->happyEyeballsState.secondSocket);
    sock->pauseRead();
    (void)sock->close();
  }
}

void QuicClientTransport::startHappyEyeballsIfEnabled() {
  if (happyEyeballsEnabled_) {
    // TODO Supply v4 delay amount from somewhere when we want to tune this
    startHappyEyeballs(
        *clientConn_,
        evb_.get(),
        happyEyeballsCachedFamily_,
        happyEyeballsConnAttemptDelayTimeout_,
        happyEyeballsCachedFamily_ == AF_UNSPEC
            ? kHappyEyeballsV4Delay
            : kHappyEyeballsConnAttemptDelayWithCache,
        this,
        this,
        socketOptions_);
  }
}

void QuicClientTransport::happyEyeballsOnDataReceivedIfEnabled(
    const quic::SocketAddress& peerAddress) {
  if (happyEyeballsEnabled_) {
    MVCHECK(socket_);
    happyEyeballsOnDataReceived(
        *clientConn_,
        happyEyeballsConnAttemptDelayTimeout_,
        socket_,
        peerAddress);
  }
}

void QuicClientTransport::cancelHappyEyeballsConnAttemptDelayTimeout() {
  cancelTimeout(&happyEyeballsConnAttemptDelayTimeout_);
}

bool QuicClientTransport::happyEyeballsAddPeerAddressIfEnabled(
    const quic::SocketAddress& peerAddress) {
  if (happyEyeballsEnabled_) {
    conn_->udpSendPacketLen = std::min(
        conn_->udpSendPacketLen,
        (peerAddress.getFamily() == AF_INET6 ? kDefaultV6UDPSendPacketLen
                                             : kDefaultV4UDPSendPacketLen));
    happyEyeballsAddPeerAddress(*clientConn_, peerAddress);
    return true;
  }
  return false;
}

} // namespace quic
