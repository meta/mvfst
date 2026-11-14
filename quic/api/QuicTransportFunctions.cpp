/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/tracing/StaticTracepoint.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/StringUtils.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/loss/QuicLossFunctions.h>

#include <quic/state/AckHandlers.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicAckFrequencyFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>

namespace {

bool cryptoStreamHasWritableData(const quic::QuicCryptoStream& stream) {
  if (stream.streamSendBuffer) {
    return stream.streamSendBuffer->hasPendingLoss() ||
        stream.streamSendBuffer
            ->nextNewData(std::numeric_limits<uint64_t>::max())
            .has_value();
  }
  return !stream.pendingWrites.empty() || !stream.lossBuffer.empty();
}

bool cryptoStreamHasOutstandingData(const quic::QuicCryptoStream& stream) {
  return stream.streamSendBuffer
      ? stream.streamSendBuffer->outstandingBytes() > 0
      : !stream.retransmissionBuffer.empty();
}

bool hasLegacySendState(const quic::QuicStreamLike& stream) {
  return !stream.pendingWrites.empty() || !stream.writeBuffer.empty() ||
      !stream.retransmissionBuffer.empty() || !stream.lossBuffer.empty();
}

bool cryptoStreamHasLegacySendState(const quic::QuicCryptoStream& stream) {
  return !stream.streamSendBuffer && hasLegacySendState(stream);
}

bool canUseNonCloningPto(
    quic::QuicConnectionStateBase& conn,
    quic::EncryptionLevel encryptionLevel) {
  if (!conn.transportSettings.useUnifiedAppStreamSendBuffer ||
      !conn.transportSettings.useNonCloningPto ||
      encryptionLevel == quic::EncryptionLevel::EarlyData) {
    return false;
  }

  if (encryptionLevel != quic::EncryptionLevel::AppData) {
    return !cryptoStreamHasLegacySendState(
        *quic::getCryptoStream(*conn.cryptoState, encryptionLevel));
  }

  if (cryptoStreamHasLegacySendState(conn.cryptoState->oneRttStream)) {
    return false;
  }
  bool hasLegacyAppSendState = false;
  conn.streamManager->streamStateForEach(
      [&](const quic::QuicStreamState& stream) {
        if (!stream.streamSendBuffer && hasLegacySendState(stream)) {
          hasLegacyAppSendState = true;
        }
      });
  return !hasLegacyAppSendState;
}

/*
 *  Check whether crypto has pending data.
 */
bool cryptoHasWritableData(const quic::QuicConnectionStateBase& conn) {
  return (conn.initialWriteCipher &&
          cryptoStreamHasWritableData(conn.cryptoState->initialStream)) ||
      (conn.handshakeWriteCipher &&
       cryptoStreamHasWritableData(conn.cryptoState->handshakeStream)) ||
      (conn.oneRttWriteCipher &&
       cryptoStreamHasWritableData(conn.cryptoState->oneRttStream));
}

std::string optionalToString(const quic::Optional<quic::PacketNum>& packetNum) {
  if (!packetNum) {
    return "-";
  }
  return fmt::format("{}", *packetNum);
}

std::string largestAckScheduledToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return fmt::format(
      "[{},{},{}]",
      optionalToString(
          conn.ackStates.initialAckState
              ? conn.ackStates.initialAckState->largestAckScheduled
              : std::nullopt),
      optionalToString(
          conn.ackStates.handshakeAckState
              ? conn.ackStates.handshakeAckState->largestAckScheduled
              : std::nullopt),
      optionalToString(conn.ackStates.appDataAckState.largestAckScheduled));
}

std::string largestAckToSendToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return fmt::format(
      "[{},{},{}]",
      optionalToString(
          conn.ackStates.initialAckState
              ? largestAckToSend(*conn.ackStates.initialAckState)
              : std::nullopt),
      optionalToString(
          conn.ackStates.handshakeAckState
              ? largestAckToSend(*conn.ackStates.handshakeAckState)
              : std::nullopt),
      optionalToString(largestAckToSend(conn.ackStates.appDataAckState)));
}

using namespace quic;

void notifyPacketProcessorsOnDestroy(
    void* context,
    const OutstandingPacketWrapper& pkt) {
  auto* conn = static_cast<QuicConnectionStateBase*>(context);
  for (auto& packetProcessor : conn->packetProcessors) {
    packetProcessor->onPacketDestroyed(pkt);
  }
}

/**
 * This function returns the number of write bytes that are available until we
 * reach the writableBytesLimit. It may or may not be the limiting factor on the
 * number of bytes we can write on the wire.
 *
 * If the client's address has not been verified, this will return the number of
 * write bytes available until writableBytesLimit is reached.
 *
 * Otherwise if the client's address is validated, it will return unlimited
 * number of bytes to write.
 */
uint64_t maybeUnvalidatedClientWritableBytes(
    quic::QuicConnectionStateBase& conn) {
  if (!conn.writableBytesLimit) {
    return unlimitedWritableBytes(conn);
  }

  if (*conn.writableBytesLimit <= conn.lossState.totalBytesSent) {
    QUIC_STATS(conn.statsCallback, onConnectionWritableBytesLimited);
    return 0;
  }

  uint64_t writableBytes =
      *conn.writableBytesLimit - conn.lossState.totalBytesSent;

  // round the result up to the nearest multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

quic::Expected<WriteQuicDataResult, QuicError> writeQuicDataToSocketImpl(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    bool exceptCryptoStream,
    TimePoint writeLoopBeginTime) {
  auto builder = ShortHeaderBuilder(connection.oneRttWritePhase);
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& probesWritten = result.probesWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& numProbePackets =
      connection.pendingEvents.numProbePackets[PacketNumberSpace::AppData];
  if (numProbePackets) {
    auto probeSchedulerBuilder =
        FrameScheduler::Builder(
            connection,
            EncryptionLevel::AppData,
            PacketNumberSpace::AppData,
            exceptCryptoStream ? "ProbeWithoutCrypto" : "ProbeScheduler")
            .blockedFrames()
            .windowUpdateFrames()
            .simpleFrames()
            .pathValidationFrames(connection.currentPathId)
            .resetFrames()
            .streamFrames()
            .pingFrames()
            .immediateAckFrames()
            .timestampFrames();
    if (!exceptCryptoStream) {
      probeSchedulerBuilder.cryptoFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        EncryptionLevel::AppData,
        PacketNumberSpace::AppData,
        probeScheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        aead,
        headerCipher,
        version);
    if (!probeResult.has_value()) {
      return quic::make_unexpected(probeResult.error());
    }
    probesWritten = probeResult->probesWritten;
    bytesWritten += probeResult->bytesWritten;
    // We only get one chance to write out the probes.
    numProbePackets = 0;
    packetLimit =
        probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  }
  auto schedulerBuilder =
      FrameScheduler::Builder(
          connection,
          EncryptionLevel::AppData,
          PacketNumberSpace::AppData,
          exceptCryptoStream ? "FrameSchedulerWithoutCrypto" : "FrameScheduler")
          .streamFrames()
          .resetFrames()
          .windowUpdateFrames()
          .blockedFrames()
          .simpleFrames()
          .pathValidationFrames(connection.currentPathId)
          .pingFrames()
          .datagramFrames()
          .immediateAckFrames()
          .timestampFrames()
          .ackFrames();
  if (!exceptCryptoStream) {
    schedulerBuilder.cryptoFrames();
  }
  FrameScheduler scheduler = std::move(schedulerBuilder).build();
  if (connection.transportSettings.minStreamBufThresh > 0 ||
      connection.transportSettings.excessCwndPctForImminentStreams > 0) {
    updatePacketLimitForImminentStreams(packetLimit, connection);
  }
  auto connectionDataResult = writeConnectionDataToSocket(
      sock,
      connection,
      connection.currentPathId,
      srcConnId,
      dstConnId,
      std::move(builder),
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version,
      writeLoopBeginTime);
  connection.imminentStreamCompletion = false;
  if (!connectionDataResult.has_value()) {
    return quic::make_unexpected(connectionDataResult.error());
  }
  packetsWritten += connectionDataResult->packetsWritten;
  bytesWritten += connectionDataResult->bytesWritten;
  MVVLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType) << " written data "
      << (exceptCryptoStream ? "without crypto data " : "")
      << "to socket packets=" << packetsWritten << " probes=" << probesWritten
      << " " << connection;
  return result;
}

void updateErrnoCount(
    QuicConnectionStateBase& connection,
    IOBufQuicBatch& ioBufBatch) {
  int lastErrno = ioBufBatch.getLastRetryableErrno();
  if (lastErrno == EAGAIN || lastErrno == EWOULDBLOCK) {
    connection.eagainOrEwouldblockCount++;
  } else if (lastErrno == ENOBUFS) {
    connection.enobufsCount++;
  }
}

// Check if a SCONE packet should be sent based on negotiation state and
// the configured send interval.
bool shouldSendSconePacket(
    const QuicConnectionStateBase& connection,
    PacketNumberSpace pnSpace,
    TimePoint sendTime) {
  if (!connection.scone || !connection.peerAdvertisedSconeSupport ||
      !connection.transportSettings.enableSconeSend ||
      pnSpace != PacketNumberSpace::AppData ||
      connection.nodeType != QuicNodeType::Server ||
      !connection.serverConnectionId) {
    return false;
  }
  if (!connection.scone->lastSconeSentTime.has_value()) {
    return true;
  }
  return sendTime - *connection.scone->lastSconeSentTime >=
      connection.transportSettings.sconePacketInterval;
}

// Returns the number of bytes to reserve for the SCONE flow indicator.
// The indicator (0xc8 0x13) is appended to every client datagram before the
// first server response, telling on-path network elements the flow supports
// SCONE (draft-ietf-scone-protocol Section 6.1).
uint64_t sconeFlowIndicatorSize(
    const QuicConnectionStateBase& connection,
    const PacketHeader& header) {
  if (!connection.transportSettings.advertiseSconeSupport) {
    return 0;
  }
  if (!header.asLong()) {
    return 0;
  }
  if (hasReceivedUdpPackets(connection)) {
    return 0;
  }
  return kSconeFlowIndicatorSize;
}

// Helper function to write SCONE packet if needed (continuous memory path).
// Returns the size of the SCONE packet written, or 0 if no packet was written.
uint64_t writeSconePacketIfNeeded(
    QuicConnectionStateBase& connection,
    const PacketHeader& header,
    PacketNumberSpace pnSpace,
    TimePoint sendTime) {
  if (!shouldSendSconePacket(connection, pnSpace, sendTime)) {
    return 0;
  }

  // DCID = client's CID (matches the coalesced short header's DCID)
  // SCID = server's own CID
  auto sconeDstCid = header.asShort()->getConnectionId();
  auto sconeSrcCid = *connection.serverConnectionId;
  uint8_t sconeRateSignal = connection.scone->configuredRateSignal;
  auto sconePacket =
      buildSconePacket(sconeRateSignal, sconeDstCid, sconeSrcCid);
  uint64_t sconeSize = sconePacket.computeChainDataLength();

  if (connection.udpSendPacketLen <= sconeSize) {
    VLOG(3) << "SCONE: Not enough space for SCONE packet in continuous buffer";
    return 0;
  }

  memcpy(connection.bufAccessor->writableTail(), sconePacket.data(), sconeSize);
  connection.bufAccessor->append(sconeSize);

  return sconeSize;
}

[[nodiscard]] quic::Expected<DataPathResult, QuicError>
continuousMemoryBuildScheduleEncrypt(
    QuicConnectionStateBase& connection,
    PacketHeader header,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    uint64_t cipherOverhead,
    QuicPacketScheduler& scheduler,
    uint64_t writableBytes,
    IOBufQuicBatch& ioBufBatch,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    TimePoint sendTime) {
  if (connection.bufAccessor->tailroom() < connection.udpSendPacketLen) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "Insufficient ContinuousMemory buffer tailroom"));
  }

  const auto rollbackSize = connection.bufAccessor->length();
  auto rollbackBuf = [&]() {
    connection.bufAccessor->trimEnd(
        connection.bufAccessor->length() - rollbackSize);
  };

  // SCONE: If needed, build the SCONE packet and write it to the buffer first.
  uint64_t sconePacketSize =
      writeSconePacketIfNeeded(connection, header, pnSpace, sendTime);

  // SCONE flow indicator: reserve space for the 2-byte indicator appended
  // after the encrypted packet (must check header before it's moved)
  uint64_t flowIndSize = sconeFlowIndicatorSize(connection, header);

  // Defensive check: ensure we have enough space for the regular packet
  if (connection.udpSendPacketLen < sconePacketSize + flowIndSize) {
    rollbackBuf();
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "Insufficient space after SCONE packet"));
  }

  const auto packetStart = connection.bufAccessor->length();

  // The builder must return the buffer before rollback can trim it.
  auto result = [&]() {
    // It's the scheduler's job to invoke encode header
    InplaceQuicPacketBuilder pktBuilder(
        *connection.bufAccessor,
        connection.udpSendPacketLen - sconePacketSize - flowIndSize,
        std::move(header),
        getPacketNumberEncodingBase(connection, pnSpace, packetNum));
    pktBuilder.accountForCipherOverhead(cipherOverhead);
    PROTO_OOPS_LOG_BUILDER_IF(
        connection.nodeType == QuicNodeType::Server && !scheduler.hasData(),
        connection.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(connection),
        "quic_transport_functions",
        "invariant_violation: packet scheduler selected with no data");
    MVCHECK(scheduler.hasData());
    return scheduler.scheduleFramesForPacket(
        std::move(pktBuilder), writableBytes);
  }();
  if (!result.has_value()) {
    rollbackBuf();
    return quic::make_unexpected(result.error());
  }
  MVCHECK(connection.bufAccessor->ownsBuffer());
  auto& packet = result->packet;
  if (!packet || packet->packet.frames.empty()) {
    rollbackBuf();
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_FRAME;
    }
    return DataPathResult::makeBuildFailure();
  }
  if (packet->body.empty()) {
    // No more space remaining.
    rollbackBuf();
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_BODY;
    }
    return DataPathResult::makeBuildFailure();
  }
  MVCHECK(!packet->header.isChained());
  auto headerLen = packet->header.length();
  MVCHECK(
      packet->body.data() > connection.bufAccessor->data() &&
      packet->body.tail() <= connection.bufAccessor->tail());
  MVCHECK(
      packet->header.data() >= connection.bufAccessor->data() &&
      packet->header.tail() < connection.bufAccessor->tail());
  // Trim off everything before the current packet, and the header length, so
  // buf's data starts from the body part of buf.
  connection.bufAccessor->trimStart(packetStart + headerLen);
  // buf and packetBuf is actually the same.
  auto buf = connection.bufAccessor->obtain();
  auto encryptResult =
      aead.inplaceEncrypt(std::move(buf), &packet->header, packetNum);
  if (!encryptResult.has_value()) {
    return quic::make_unexpected(encryptResult.error());
  }
  auto packetBuf = std::move(encryptResult.value());
  MVCHECK(packetBuf->headroom() == headerLen + packetStart);
  // Include header back.
  packetBuf->prepend(headerLen);

  HeaderForm headerForm = packet->packet.header.getHeaderForm();
  auto headerEncryptResult = encryptPacketHeader(
      headerForm,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  if (!headerEncryptResult.has_value()) {
    return quic::make_unexpected(headerEncryptResult.error());
  }
  if (!headerEncryptResult.has_value()) {
    return quic::make_unexpected(headerEncryptResult.error());
  }
  MVCHECK(!packetBuf->isChained());
  auto encodedSize = packetBuf->length();
  auto encodedBodySize = encodedSize - headerLen;
  encodedSize += sconePacketSize;
  if (sconePacketSize) {
    connection.scone->lastSconeSentTime = sendTime;
    QUIC_STATS(connection.statsCallback, onSconePacketSent);
    if (connection.qLogger) {
      connection.qLogger->addTransportStateUpdate(
          fmt::format(
              "scone_sent:rate={}",
              static_cast<int>(connection.scone->configuredRateSignal)));
    }
  }
  // Include previous packets back.
  packetBuf->prepend(packetStart);
  if (connection.transportSettings.isPriming && packetBuf) {
    packetBuf->coalesce();
    connection.bufAccessor->release(BufHelpers::create(packetBuf->capacity()));
    connection.primingData.emplace_back(std::move(packetBuf));
    return DataPathResult::makeWriteResult(
        true, std::move(result.value()), encodedSize, encodedBodySize);
  }
  connection.bufAccessor->release(std::move(packetBuf));

  // Append SCONE flow indicator as the last 2 bytes of the datagram
  if (flowIndSize > 0) {
    connection.bufAccessor->writableTail()[0] = kSconeFlowIndicatorByte1;
    connection.bufAccessor->writableTail()[1] = kSconeFlowIndicatorByte2;
    connection.bufAccessor->append(kSconeFlowIndicatorSize);
    encodedSize += kSconeFlowIndicatorSize;
  }

  if (encodedSize > connection.udpSendPacketLen) {
    MVVLOG(3) << "Quic sending pkt larger than limit, encodedSize="
              << encodedSize;
  }
  // TODO: I think we should add an API that doesn't need a buffer.
  auto writeResult =
      ioBufBatch.write(nullptr /* no need to pass buf */, encodedSize);
  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }
  updateErrnoCount(connection, ioBufBatch);
  return DataPathResult::makeWriteResult(
      writeResult.value(),
      std::move(result.value()),
      encodedSize,
      encodedBodySize);
}

} // namespace

namespace quic {

bool writeLoopTimeLimit(
    TimePoint loopBeginTime,
    const QuicConnectionStateBase& connection) {
  return connection.lossState.srtt == 0us ||
      connection.transportSettings.writeLimitRttFraction == 0 ||
      Clock::now() - loopBeginTime < connection.lossState.srtt /
          connection.transportSettings.writeLimitRttFraction;
}

void handleNewStreamDataWritten(
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin) {
  auto originalOffset = stream.currentWriteOffset;
  // Idealy we should also check this data doesn't exist in either retx buffer
  // or loss buffer, but that's an expensive search.
  stream.currentWriteOffset += frameLen;
  ChainedByteRangeHead bufWritten(
      stream.pendingWrites.splitAtMost(static_cast<size_t>(frameLen)));
  MVDCHECK_EQ(bufWritten.chainLength(), frameLen);
  // TODO: If we want to be able to write FIN out of order for DSR-ed streams,
  // this needs to be fixed:
  stream.currentWriteOffset += frameFin ? 1 : 0;
  MVCHECK(stream.retransmissionBuffer
              .emplace(
                  std::piecewise_construct,
                  std::forward_as_tuple(originalOffset),
                  std::forward_as_tuple(
                      std::make_unique<WriteStreamBuffer>(
                          std::move(bufWritten), originalOffset, frameFin)))
              .second);
}

void handleRetransmissionWritten(
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    CircularDeque<WriteStreamBuffer>::iterator lossBufferIter) {
  auto bufferLen = lossBufferIter->data.chainLength();
  if (frameLen == bufferLen && frameFin == lossBufferIter->eof) {
    // The buffer is entirely retransmitted
    ChainedByteRangeHead bufWritten(std::move(lossBufferIter->data));
    stream.lossBuffer.erase(lossBufferIter);
    MVCHECK(stream.retransmissionBuffer
                .emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(frameOffset),
                    std::forward_as_tuple(
                        std::make_unique<WriteStreamBuffer>(
                            std::move(bufWritten), frameOffset, frameFin)))
                .second);
  } else {
    lossBufferIter->offset += frameLen;
    ChainedByteRangeHead bufWritten(lossBufferIter->data.splitAtMost(frameLen));
    MVCHECK(stream.retransmissionBuffer
                .emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(frameOffset),
                    std::forward_as_tuple(
                        std::make_unique<WriteStreamBuffer>(
                            std::move(bufWritten), frameOffset, frameFin)))
                .second);
  }
}

/**
 * Update the connection and stream state after stream data is written and deal
 * with new data, as well as retranmissions. Returns true if the data sent is
 * new data.
 */
quic::Expected<bool, QuicError> handleStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  auto writtenNewData = false;
  // Handle new data first
  if (frameOffset == stream.currentWriteOffset) {
    handleNewStreamDataWritten(stream, frameLen, frameFin);
    writtenNewData = true;
  } else if (frameOffset > stream.currentWriteOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        fmt::format(
            "Byte offset of first byte in written stream frame ({}) is "
            "greater than stream's current write offset ({})",
            frameOffset,
            stream.currentWriteOffset)));
  }

  if (writtenNewData) {
    // Count packet. It's based on the assumption that schedluing scheme will
    // only writes one STREAM frame for a stream in a packet. If that doesn't
    // hold, we need to avoid double-counting.
    ++stream.numPacketsTxWithNewData;
    MVVLOG(10) << nodeToString(conn.nodeType) << " sent"
               << " packetNum=" << packetNum << " space=" << packetNumberSpace
               << " " << conn;
    return true;
  }

  bool writtenRetx = false;
  // If the data is in the loss buffer, it is a retransmission.
  auto lossBufferIter = std::lower_bound(
      stream.lossBuffer.begin(),
      stream.lossBuffer.end(),
      frameOffset,
      [](const auto& buf, auto off) { return buf.offset < off; });
  if (lossBufferIter != stream.lossBuffer.end() &&
      lossBufferIter->offset == frameOffset) {
    handleRetransmissionWritten(
        stream, frameOffset, frameLen, frameFin, lossBufferIter);
    writtenRetx = true;
  }

  if (writtenRetx) {
    conn.lossState.totalBytesRetransmitted += frameLen;
    MVVLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
               << " packetNum=" << packetNum << " " << conn;
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  // Otherwise it must be a clone write.
  conn.lossState.totalStreamBytesCloned += frameLen;
  return false;
}

static quic::Expected<bool, QuicError> handleUnifiedStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace,
    bool isClone,
    bool isPtoRetransmission) {
  auto& sendBuffer = *stream.streamSendBuffer;
  const StreamSendBuffer::SendRange frameRange{
      .offset = frameOffset, .len = frameLen, .fin = frameFin};

  if (isClone) {
    conn.lossState.totalStreamBytesCloned += frameLen;
    return false;
  }

  if (isPtoRetransmission) {
    if (!sendBuffer.isOutstanding(frameRange)) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          fmt::format(
              "PTO stream retransmission offset={}, len={}, fin={} is not "
              "outstanding",
              frameOffset,
              frameLen,
              frameFin)));
    }
    return false;
  }

  if (frameOffset >= sendBuffer.nextUnsentOffset()) {
    const auto newData = sendBuffer.nextNewData(frameLen);
    if (newData && *newData == frameRange &&
        sendBuffer.markNewDataSent(frameRange)) {
      stream.currentWriteOffset = sendBuffer.nextUnsentOffset() +
          static_cast<uint64_t>(sendBuffer.finSent());
      ++stream.numPacketsTxWithNewData;
      MVVLOG(10) << nodeToString(conn.nodeType) << " sent"
                 << " packetNum=" << packetNum << " space=" << packetNumberSpace
                 << " " << conn;
      return true;
    }
  }

  const auto pendingLoss = sendBuffer.nextLoss(frameLen);
  if (pendingLoss && *pendingLoss == frameRange) {
    sendBuffer.markRetransmissionSent(frameRange);
    conn.lossState.totalBytesRetransmitted += frameLen;
    MVVLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
               << " packetNum=" << packetNum << " " << conn;
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  return quic::make_unexpected(QuicError(
      TransportErrorCode::INTERNAL_ERROR,
      fmt::format(
          "Written stream frame offset={}, len={}, fin={} does not match "
          "pending unified stream send state",
          frameOffset,
          frameLen,
          frameFin)));
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static quic::Expected<bool, QuicError> handleUnifiedCryptoWritten(
    QuicConnectionStateBase& conn,
    QuicCryptoStream& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    PacketNum packetNum,
    bool isClone,
    bool isPtoRetransmission) {
  auto& sendBuffer = *stream.streamSendBuffer;
  const StreamSendBuffer::SendRange frameRange{
      .offset = frameOffset, .len = frameLen, .fin = false};

  if (isClone) {
    conn.lossState.totalStreamBytesCloned += frameLen;
    return false;
  }

  if (isPtoRetransmission) {
    if (!sendBuffer.isOutstanding(frameRange)) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          fmt::format(
              "PTO crypto retransmission offset={}, len={} is not "
              "outstanding",
              frameOffset,
              frameLen)));
    }
    return false;
  }

  if (frameOffset >= sendBuffer.nextUnsentOffset()) {
    const auto newData = sendBuffer.nextNewData(frameLen);
    if (newData && *newData == frameRange &&
        sendBuffer.markNewDataSent(frameRange)) {
      stream.currentWriteOffset = sendBuffer.nextUnsentOffset();
      return true;
    }
  }

  const auto pendingLoss = sendBuffer.nextLoss(frameLen);
  if (pendingLoss && *pendingLoss == frameRange) {
    sendBuffer.markRetransmissionSent(frameRange);
    conn.lossState.totalBytesRetransmitted += frameLen;
    MVVLOG(10) << nodeToString(conn.nodeType)
               << " sent crypto retransmission packetNum=" << packetNum << " "
               << conn;
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  return quic::make_unexpected(QuicError(
      TransportErrorCode::INTERNAL_ERROR,
      fmt::format(
          "Written crypto frame offset={}, len={} does not match pending "
          "send state",
          frameOffset,
          frameLen)));
}

quic::Expected<void, QuicError> updateConnection(
    QuicConnectionStateBase& conn,
    const PathInfo& pathInfo,
    Optional<ClonedPacketIdentifier> clonedPacketIdentifier,
    RegularQuicWritePacket packet,
    TimePoint sentTime,
    uint32_t encodedSize,
    uint32_t encodedBodySize,
    PacketTransmissionReason transmissionReason,
    bool isPtoRetransmission) {
  auto packetNum = packet.header.getPacketSequenceNum();
  // AckFrame, PaddingFrame and Datagrams are not retx-able.
  bool retransmittable = false;
  bool isPing = false;
  bool hasDatagram = false;
  uint32_t connWindowUpdateSent = 0;
  [[maybe_unused]] uint32_t ackFrameCounter = 0;
  uint32_t streamBytesSent = 0;
  uint32_t newStreamBytesSent = 0;
  OutstandingPacketWrapper::Metadata::DetailsPerStream detailsPerStream;
  auto packetNumberSpace = packet.header.getPacketNumberSpace();
  MVVLOG(10) << nodeToString(conn.nodeType) << " sent packetNum=" << packetNum
             << " in space=" << packetNumberSpace << " size=" << encodedSize
             << " bodySize: " << encodedBodySize << " " << conn;
  QLOG(conn, addPacket, packet, encodedSize);
  FOLLY_SDT(quic, update_connection_num_frames, packet.frames.size());
  for (auto& frame : packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteStreamFrame: {
        WriteStreamFrame& writeStreamFrame = *frame.asWriteStreamFrame();
        retransmittable = true;
        auto streamResult =
            conn.streamManager->getStream(writeStreamFrame.streamId);
        if (!streamResult) {
          return quic::make_unexpected(streamResult.error());
        }
        auto stream = streamResult.value();
        bool newStreamDataWritten = false;
        auto streamWrittenResult = stream->streamSendBuffer
            ? handleUnifiedStreamWritten(
                  conn,
                  *stream,
                  writeStreamFrame.offset,
                  writeStreamFrame.len,
                  writeStreamFrame.fin,
                  packetNum,
                  packetNumberSpace,
                  clonedPacketIdentifier.has_value(),
                  isPtoRetransmission)
            : handleStreamWritten(
                  conn,
                  *stream,
                  writeStreamFrame.offset,
                  writeStreamFrame.len,
                  writeStreamFrame.fin,
                  packetNum,
                  packetNumberSpace);
        if (!streamWrittenResult.has_value()) {
          return quic::make_unexpected(streamWrittenResult.error());
        }
        newStreamDataWritten = streamWrittenResult.value();
        // Record how these bytes were sent so ACK processing can attribute
        // them without reconstructing the send decision.
        writeStreamFrame.origin = newStreamDataWritten
            ? WriteStreamFrame::Origin::NewData
            : clonedPacketIdentifier ? WriteStreamFrame::Origin::Clone
            : isPtoRetransmission
            ? WriteStreamFrame::Origin::PtoRetransmission
            : WriteStreamFrame::Origin::LossRetransmission;
        if (newStreamDataWritten) {
          auto flowControlResult =
              updateFlowControlOnWriteToSocket(*stream, writeStreamFrame.len);
          if (!flowControlResult.has_value()) {
            return quic::make_unexpected(flowControlResult.error());
          }
          maybeWriteBlockAfterSocketWrite(*stream);
          maybeWriteDataBlockedAfterSocketWrite(conn);
          conn.streamManager->addTx(writeStreamFrame.streamId);
          newStreamBytesSent += writeStreamFrame.len;
        }
        // This call could take an argument whether the packet scheduler already
        // removed stream from writeQueue
        conn.streamManager->updateWritableStreams(
            *stream, getSendConnFlowControlBytesWire(conn) > 0);
        streamBytesSent += writeStreamFrame.len;
        detailsPerStream.addFrame(writeStreamFrame, newStreamDataWritten);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& writeCryptoFrame = *frame.asWriteCryptoFrame();
        retransmittable = true;
        auto protectionType = packet.header.getProtectionType();
        // NewSessionTicket is sent in crypto frame encrypted with 1-rtt key,
        // however, it is not part of handshake
        auto encryptionLevel = protectionTypeToEncryptionLevel(protectionType);
        auto* cryptoStream =
            getCryptoStream(*conn.cryptoState, encryptionLevel);
        auto cryptoWritten = cryptoStream->streamSendBuffer
            ? handleUnifiedCryptoWritten(
                  conn,
                  *cryptoStream,
                  writeCryptoFrame.offset,
                  writeCryptoFrame.len,
                  packetNum,
                  clonedPacketIdentifier.has_value(),
                  isPtoRetransmission)
            : handleStreamWritten(
                  conn,
                  *cryptoStream,
                  writeCryptoFrame.offset,
                  writeCryptoFrame.len,
                  false /* fin */,
                  packetNum,
                  packetNumberSpace);
        if (!cryptoWritten.has_value()) {
          return quic::make_unexpected(cryptoWritten.error());
        }
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& writeAckFrame = *frame.asWriteAckFrame();
        PROTO_OOPS_LOG_BUILDER_IF(
            conn.nodeType == QuicNodeType::Server && ackFrameCounter != 0,
            conn.oopsLogger,
            proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn),
            "quic_transport_functions",
            "invariant_violation: packet contains more than one ACK frame");
        MVDCHECK(
            !ackFrameCounter++, "Send more than one WriteAckFrame " << conn);
        auto largestAckedPacketWritten = writeAckFrame.ackBlocks.front().end;
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent packet with largestAcked="
                   << largestAckedPacketWritten << " packetNum=" << packetNum
                   << " " << conn;
        ++conn.numAckFramesSent;
        updateAckSendStateOnSentPacketWithAcks(
            conn,
            getAckState(conn, packetNumberSpace),
            largestAckedPacketWritten);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame: {
        const RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
        retransmittable = true;
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent reset streams in packetNum=" << packetNum << " "
                   << conn;
        auto resetIter =
            conn.pendingEvents.resets.find(rstStreamFrame.streamId);
        // TODO: this can happen because we clone RST_STREAM frames. Should we
        // start to treat RST_STREAM in the same way we treat window update?
        if (resetIter != conn.pendingEvents.resets.end()) {
          conn.pendingEvents.resets.erase(resetIter);
        } else {
          PROTO_OOPS_LOG_BUILDER_IF(
              conn.nodeType == QuicNodeType::Server &&
                  !clonedPacketIdentifier.has_value(),
              conn.oopsLogger,
              proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn)
                  .setStreamId(rstStreamFrame.streamId),
              "quic_transport_functions",
              "invariant_violation: reset stream missing from pending "
              "events for non-clone packet");
          MVDCHECK(
              clonedPacketIdentifier.has_value(),
              " reset missing from pendingEvents for non-clone packet");
        }
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        const MaxDataFrame& maxDataFrame = *frame.asMaxDataFrame();
        MVCHECK(
            !connWindowUpdateSent++,
            "Send more than one connection window update " << conn);
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent conn window update packetNum=" << packetNum << " "
                   << conn;
        retransmittable = true;
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent conn window update in packetNum=" << packetNum
                   << " " << conn;
        ++conn.numWindowUpdateFramesSent;
        onConnWindowUpdateSent(conn, maxDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame: {
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent conn data blocked frame=" << packetNum << " "
                   << conn;
        retransmittable = true;
        conn.pendingEvents.sendDataBlocked = false;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto streamResult =
            conn.streamManager->getStream(maxStreamDataFrame.streamId);
        if (!streamResult.has_value()) {
          return quic::make_unexpected(streamResult.error());
        }
        auto stream = streamResult.value();
        retransmittable = true;
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent packet with window update packetNum=" << packetNum
                   << " stream=" << maxStreamDataFrame.streamId << " " << conn;
        ++conn.numWindowUpdateFramesSent;
        onStreamWindowUpdateSent(
            *stream, maxStreamDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        const StreamDataBlockedFrame& streamBlockedFrame =
            *frame.asStreamDataBlockedFrame();
        MVVLOG(10) << nodeToString(conn.nodeType)
                   << " sent blocked stream frame packetNum=" << packetNum
                   << " " << conn;
        retransmittable = true;
        conn.streamManager->removeBlocked(streamBlockedFrame.streamId);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        conn.pendingEvents.sendPing = false;
        isPing = true;
        retransmittable = true;
        conn.numPingFramesSent++;
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        retransmittable = true;
        // We don't want this triggered for cloned frames.
        if (!clonedPacketIdentifier.has_value()) {
          updateSimpleFrameOnPacketSent(conn, pathInfo.id, simpleFrame);
        }
        break;
      }
      case QuicWriteFrame::Type::TimestampFrame:
        break;
      case QuicWriteFrame::Type::PaddingFrame: {
        // do not mark padding as retransmittable. There are several reasons
        // for this:
        // 1. We might need to pad ACK packets to make it so that we can
        //    sample them correctly for header encryption. ACK packets may not
        //    count towards congestion window, so the padding frames in those
        //    ack packets should not count towards the window either
        // 2. Of course we do not want to retransmit the ACK frames.
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame: {
        // do not mark Datagram frames as retransmittable
        hasDatagram = true;
        break;
      }
      case QuicWriteFrame::Type::ImmediateAckFrame: {
        // turn off the immediate ack pending event.
        conn.pendingEvents.requestImmediateAck = false;
        retransmittable = true;
        break;
      }
      default:
        retransmittable = true;
    }
  }

  auto& ackState = getAckState(conn, packetNumberSpace);
  increaseNextPacketNum(conn, packetNumberSpace);
  if (!ackState.skippedPacketNum.has_value() &&
      folly::Random::oneIn(
          conn.transportSettings.skipOneInNPacketSequenceNumber)) {
    ackState.skippedPacketNum = ackState.nextPacketNum;
    increaseNextPacketNum(conn, packetNumberSpace);
  }
  conn.lossState.largestSent =
      std::max(conn.lossState.largestSent.value_or(packetNum), packetNum);
  // updateConnection may be called multiple times during write. If before or
  // during any updateConnection, setLossDetectionAlarm is already set, we
  // shouldn't clear it:
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    conn.pendingEvents.setLossDetectionAlarm = retransmittable;
  }
  conn.lossState.maybeLastPacketSentTime = sentTime;
  conn.lossState.totalBytesSent += encodedSize;
  conn.lossState.totalBodyBytesSent += encodedBodySize;
  conn.lossState.totalPacketsSent++;
  conn.lossState.totalStreamBytesSent += streamBytesSent;
  conn.lossState.totalNewStreamBytesSent += newStreamBytesSent;

  // Count the number of packets sent in the current phase.
  // This is used to initiate key updates if enabled.
  if (packet.header.getProtectionType() == conn.oneRttWritePhase) {
    if (conn.oneRttWritePendingVerification &&
        conn.oneRttWritePacketsSentInCurrentPhase == 0) {
      // This is the first packet in the new phase after we have initiated a key
      // update. We need to keep track of it to confirm the peer acks it in the
      // same phase.
      conn.oneRttWritePendingVerificationPacketNumber =
          packet.header.getPacketSequenceNum();
    }
    conn.oneRttWritePacketsSentInCurrentPhase++;
  }

  bool hasDatagramAndShouldTrack = hasDatagram &&
      conn.transportSettings.datagramConfig.trackingMode ==
          DatagramConfig::CongestionControlMode::ConstrainedAndTracked;

  if (!retransmittable && !isPing && !hasDatagramAndShouldTrack) {
    PROTO_OOPS_LOG_BUILDER_IF(
        conn.nodeType == QuicNodeType::Server && clonedPacketIdentifier,
        conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn),
        "quic_transport_functions",
        "invariant_violation: non-ack-eliciting packet has cloned packet "
        "identifier");
    MVDCHECK(!clonedPacketIdentifier);
    return {};
  }
  conn.lossState.totalAckElicitingPacketsSent++;

  auto packetIt =
      std::find_if(
          conn.outstandings.packets.rbegin(),
          conn.outstandings.packets.rend(),
          [packetNum](const auto& packetWithTime) {
            return packetWithTime.packet.header.getPacketSequenceNum() <
                packetNum;
          })
          .base();

  auto& pkt = *conn.outstandings.packets.emplace(
      packetIt,
      std::move(packet),
      sentTime,
      pathInfo.id,
      encodedSize,
      encodedBodySize,
      // these numbers should all _include_ the current packet
      // conn.lossState.inflightBytes isn't updated until below
      // conn.outstandings.numOutstanding() + 1 since we're emplacing here
      conn.lossState.totalBytesSent,
      conn.lossState.inflightBytes + encodedSize,
      conn.lossState,
      conn.writeCount,
      std::move(detailsPerStream),
      conn.appLimitedTracker.getTotalAppLimitedTime(),
      &conn,
      &notifyPacketProcessorsOnDestroy);

  maybeAddPacketMark(conn, pkt);

  pkt.isAppLimited = conn.congestionController
      ? conn.congestionController->isAppLimited()
      : false;
  if (conn.lossState.lastAckedTime.has_value() &&
      conn.lossState.lastAckedPacketSentTime.has_value()) {
    pkt.lastAckedPacketInfo.emplace(
        *conn.lossState.lastAckedPacketSentTime,
        *conn.lossState.lastAckedTime,
        *conn.lossState.adjustedLastAckedTime,
        conn.lossState.totalBytesSentAtLastAck,
        conn.lossState.totalBytesAckedAtLastAck);
  }
  if (clonedPacketIdentifier) {
    PROTO_OOPS_LOG_BUILDER_IF(
        conn.nodeType == QuicNodeType::Server &&
            conn.outstandings.clonedPacketIdentifiers.count(
                *clonedPacketIdentifier) == 0,
        conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn),
        "quic_transport_functions",
        "invariant_violation: cloned packet identifier missing from "
        "outstanding clone set");
    MVDCHECK(conn.outstandings.clonedPacketIdentifiers.count(
        *clonedPacketIdentifier));
    pkt.maybeClonedPacketIdentifier = std::move(clonedPacketIdentifier);
    pkt.metadata.transmissionReason =
        transmissionReason == PacketTransmissionReason::ImmediateInitialProbe
        ? transmissionReason
        : PacketTransmissionReason::Clone;
    conn.lossState.totalBytesCloned += encodedSize;
  } else {
    pkt.metadata.transmissionReason = transmissionReason;
  }

  if (conn.congestionController) {
    addAndCheckOverflow(
        conn.lossState.inflightBytes,
        pkt.metadata.encodedSize,
        2 * conn.transportSettings.maxCwndInMss * conn.udpSendPacketLen);
    conn.congestionController->onPacketSent(pkt);
  }
  if (conn.pacer) {
    conn.pacer->onPacketSent();
  }
  for (auto& packetProcessor : conn.packetProcessors) {
    packetProcessor->onPacketSent(pkt);
  }

  if (pathInfo.status != PathStatus::Validated) {
    conn.pathManager->onPathPacketSent(pathInfo.id, pkt.metadata.encodedSize);
  }

  if (retransmittable) {
    conn.lossState.lastRetransmittablePacketSentTime = pkt.metadata.time;
  }
  if (pkt.maybeClonedPacketIdentifier) {
    ++conn.outstandings.clonedPacketCount[packetNumberSpace];
    ++conn.lossState.timeoutBasedRtxCount;
  } else {
    ++conn.outstandings.packetCount[packetNumberSpace];
  }
  return {};
}

uint64_t probePacketWritableBytes(QuicConnectionStateBase& conn) {
  uint64_t probeWritableBytes = maybeUnvalidatedClientWritableBytes(conn);
  if (!probeWritableBytes) {
    conn.numProbesWritableBytesLimited++;
  }
  return probeWritableBytes;
}

uint64_t pathValidationWritableBytes(
    const QuicConnectionStateBase& conn,
    PathIdType pathId) {
  auto* pathInfo = conn.pathManager->getPath(pathId);
  if (pathInfo && conn.nodeType == QuicNodeType::Server &&
      pathInfo->status != PathStatus::Validated) {
    return pathInfo->writableBytes;
  }
  return std::numeric_limits<uint64_t>::max();
}

uint64_t congestionControlWritableBytes(QuicConnectionStateBase& conn) {
  uint64_t writableBytes =
      pathValidationWritableBytes(conn, conn.currentPathId);

  if (conn.writableBytesLimit) {
    writableBytes = maybeUnvalidatedClientWritableBytes(conn);
  }

  if (conn.congestionController) {
    auto ccWritableBytes = conn.congestionController->getWritableBytes();
    if (conn.imminentStreamCompletion) {
      // If we are about to complete a stream, we allow for excess writable
      // bytes by increasing the congestion controller's writable bytes by the
      // specified percentage.
      ccWritableBytes += ccWritableBytes *
          conn.transportSettings.excessCwndPctForImminentStreams / 100;
    }

    writableBytes = std::min<uint64_t>(writableBytes, ccWritableBytes);

    if (conn.throttlingSignalProvider &&
        conn.throttlingSignalProvider->getCurrentThrottlingSignal()
            .has_value()) {
      const auto& throttlingSignal =
          conn.throttlingSignalProvider->getCurrentThrottlingSignal();
      if (throttlingSignal.value().maybeBytesToSend.has_value()) {
        // Cap the writable bytes by the amount of tokens available in the
        // throttler's bucket if one found to be throttling the connection.
        writableBytes = std::min(
            throttlingSignal.value().maybeBytesToSend.value(), writableBytes);
      }
    }
  }

  if (writableBytes == std::numeric_limits<uint64_t>::max()) {
    return writableBytes;
  }

  // For real-CC/PathChallenge cases, round the result up to the nearest
  // multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

uint64_t unlimitedWritableBytes(QuicConnectionStateBase&) {
  return std::numeric_limits<uint64_t>::max();
}

HeaderBuilder HeaderBuilder::makeLong(LongHeader::Types type) {
  HeaderBuilder builder;
  builder.kind_ = Kind::Long;
  builder.longType_ = type;
  return builder;
}

HeaderBuilder HeaderBuilder::makeShort(ProtectionType keyPhase) {
  HeaderBuilder builder;
  builder.kind_ = Kind::Short;
  builder.keyPhase_ = keyPhase;
  return builder;
}

PacketHeader HeaderBuilder::operator()(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    const std::string& token) const {
  switch (kind_) {
    case Kind::Long:
      return LongHeader(
          longType_, srcConnId, dstConnId, packetNum, version, token);
    case Kind::Short:
      return ShortHeader(keyPhase_, dstConnId, packetNum);
  }
  folly::assume_unreachable();
}

quic::Expected<WriteQuicDataResult, QuicError> writeCryptoAndAckDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types packetType,
    Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    const std::string& token) {
  auto encryptionLevel = protectionTypeToEncryptionLevel(
      longHeaderTypeToProtectionType(packetType));
  FrameScheduler scheduler =
      std::move(
          FrameScheduler::Builder(
              connection,
              encryptionLevel,
              LongHeader::typeToPacketNumberSpace(packetType),
              "CryptoAndAcksScheduler")
              .ackFrames()
              .cryptoFrames())
          .build();
  auto builder = LongHeaderBuilder(packetType);
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& probesWritten = result.probesWritten;
  auto& cryptoStream =
      *getCryptoStream(*connection.cryptoState, encryptionLevel);
  auto& numProbePackets =
      connection.pendingEvents
          .numProbePackets[LongHeader::typeToPacketNumberSpace(packetType)];
  // During the handshake, probe with no data to retransmit so a PING is sent
  // (RFC 9002 6.2.2.1).
  if (numProbePackets &&
      (cryptoStreamHasOutstandingData(cryptoStream) || scheduler.hasData() ||
       needsAntiDeadlockPTO(connection))) {
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        cleartextCipher,
        headerCipher,
        version,
        token);
    if (!probeResult.has_value()) {
      return quic::make_unexpected(probeResult.error());
    }
    probesWritten += probeResult->probesWritten;
    bytesWritten += probeResult->bytesWritten;
  }
  packetLimit = probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  // Only get one chance to write probes.
  numProbePackets = 0;
  // Crypto data is written without aead protection.
  auto writeResult = writeConnectionDataToSocket(
      sock,
      connection,
      connection.currentPathId,
      srcConnId,
      dstConnId,
      builder,
      LongHeader::typeToPacketNumberSpace(packetType),
      scheduler,
      congestionControlWritableBytes,
      packetLimit - packetsWritten,
      cleartextCipher,
      headerCipher,
      version,
      Clock::now(),
      token);

  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }

  packetsWritten += writeResult->packetsWritten;
  bytesWritten += writeResult->bytesWritten;

  if (connection.transportSettings.immediatelyRetransmitInitialPackets &&
      packetsWritten > 0 && packetsWritten < packetLimit) {
    auto remainingLimit = packetLimit - packetsWritten;
    auto cloneResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        packetsWritten < remainingLimit ? packetsWritten : remainingLimit,
        cleartextCipher,
        headerCipher,
        version,
        token,
        PacketTransmissionReason::ImmediateInitialProbe);
    if (!cloneResult.has_value()) {
      return quic::make_unexpected(cloneResult.error());
    }
    probesWritten += cloneResult->probesWritten;
    bytesWritten += cloneResult->bytesWritten;
  }

  MVVLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType)
      << " written crypto and acks data type=" << packetType
      << " packetsWritten=" << packetsWritten
      << " probesWritten=" << probesWritten << connection;
  MVCHECK_GE(packetLimit, packetsWritten);
  return result;
}

quic::Expected<WriteQuicDataResult, QuicError> writeQuicDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    TimePoint writeLoopBeginTime) {
  return writeQuicDataToSocketImpl(
      sock,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/false,
      writeLoopBeginTime);
}

quic::Expected<WriteQuicDataResult, QuicError>
writeQuicDataExceptCryptoStreamToSocket(
    QuicAsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  return writeQuicDataToSocketImpl(
      socket,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/true,
      Clock::now());
}

quic::Expected<uint64_t, QuicError> writeZeroRttDataToSocket(
    QuicAsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  auto type = LongHeader::Types::ZeroRtt;
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type));
  auto builder = LongHeaderBuilder(type);
  // Probe is not useful for zero rtt because we will always have handshake
  // packets outstanding when sending zero rtt data.
  FrameScheduler scheduler = std::move(
                                 FrameScheduler::Builder(
                                     connection,
                                     encryptionLevel,
                                     LongHeader::typeToPacketNumberSpace(type),
                                     "ZeroRttScheduler")
                                     .streamFrames()
                                     .resetFrames()
                                     .windowUpdateFrames()
                                     .blockedFrames()
                                     .simpleFrames())
                                 .build();
  auto writeResult = writeConnectionDataToSocket(
      socket,
      connection,
      connection.currentPathId,
      srcConnId,
      dstConnId,
      std::move(builder),
      LongHeader::typeToPacketNumberSpace(type),
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version,
      Clock::now());

  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }

  auto written = writeResult->packetsWritten;
  MVVLOG_IF(10, written > 0)
      << nodeToString(connection.nodeType)
      << " written zero rtt data, packets=" << written << " " << connection;
  MVDCHECK_GE(packetLimit, written);
  return written;
}

void writeCloseCommon(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  if (connection.version == QuicVersion::MVFST_PRIMING &&
      connection.nodeType == QuicNodeType::Server) {
    return;
  }
  // close is special, we're going to bypass all the packet sent logic for all
  // packets we send with a connection close frame.
  PacketNumberSpace pnSpace = header.getPacketNumberSpace();
  HeaderForm headerForm = header.getHeaderForm();
  PacketNum packetNum = header.getPacketSequenceNum();

  // Create a buffer onto which we write the connection close.
  BufAccessor bufAccessor(connection.udpSendPacketLen);
  InplaceQuicPacketBuilder packetBuilder(
      bufAccessor,
      connection.udpSendPacketLen,
      header,
      getPacketNumberEncodingBase(connection, pnSpace, packetNum));
  auto encodeResult = packetBuilder.encodePacketHeader();
  if (!encodeResult.has_value()) {
    MVLOG_ERROR << "Error encoding packet header: "
                << encodeResult.error().message;
    return;
  }
  packetBuilder.accountForCipherOverhead(aead.getCipherOverhead());
  size_t written = 0;
  if (!closeDetails) {
    auto writeResult = writeFrame(
        ConnectionCloseFrame(
            QuicErrorCode(TransportErrorCode::NO_ERROR),
            std::string("No error")),
        packetBuilder);
    if (!writeResult.has_value()) {
      MVLOG_ERROR << "Error writing frame: " << writeResult.error().message;
      return;
    }
    written = *writeResult;
  } else {
    switch (closeDetails->code.type()) {
      case QuicErrorCode::Type::ApplicationErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asApplicationErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE_APP_ERR),
            packetBuilder);
        if (!writeResult.has_value()) {
          MVLOG_ERROR << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
      case QuicErrorCode::Type::TransportErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asTransportErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        if (!writeResult.has_value()) {
          MVLOG_ERROR << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
      case QuicErrorCode::Type::LocalErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
                std::string("Internal error"),
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        if (!writeResult.has_value()) {
          MVLOG_ERROR << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
    }
  }
  if (pnSpace == PacketNumberSpace::Initial &&
      connection.nodeType == QuicNodeType::Client) {
    while (packetBuilder.remainingSpaceInPkt() > 0) {
      auto paddingResult = writeFrame(PaddingFrame(), packetBuilder);
      if (!paddingResult.has_value()) {
        MVLOG_ERROR << "Error writing padding frame: "
                    << paddingResult.error().message;
        return;
      }
    }
  }
  if (written == 0) {
    MVLOG_ERROR << "Close frame too large " << connection;
    return;
  }
  auto packet = std::move(packetBuilder).buildPacket();
  MVCHECK_GE(packet.body.tailroom(), aead.getCipherOverhead());
  auto bufUniquePtr = packet.body.clone();
  auto encryptResult =
      aead.inplaceEncrypt(std::move(bufUniquePtr), &packet.header, packetNum);
  if (!encryptResult.has_value()) {
    MVLOG_ERROR << "Error encrypting packet: " << encryptResult.error().message;
    return;
  }
  bufUniquePtr = std::move(encryptResult.value());
  bufUniquePtr->coalesce();
  auto headerEncryptResult = encryptPacketHeader(
      headerForm,
      packet.header.writableData(),
      packet.header.length(),
      bufUniquePtr->data(),
      bufUniquePtr->length(),
      headerCipher);
  if (!headerEncryptResult.has_value()) {
    MVLOG_ERROR << "Failed to encrypt packet header: "
                << headerEncryptResult.error().message;
    return;
  }
  Buf packetBuf(std::move(packet.header));
  packetBuf.appendToChain(std::move(bufUniquePtr));
  auto packetSize = packetBuf.computeChainDataLength();
  QLOG(connection, addPacket, packet.packet, packetSize);
  MVVLOG(10) << nodeToString(connection.nodeType)
             << " sent close packetNum=" << packetNum << " in space=" << pnSpace
             << " " << connection;
  // Increment the sequence number.
  increaseNextPacketNum(connection, pnSpace);
  // best effort writing to the socket, ignore any errors.

  BufPtr packetBufPtr = packetBuf.clone();
  iovec vec[kNumIovecBufferChains]; // NOLINT(modernize-avoid-c-arrays)
  size_t iovec_len = fillIovec(packetBufPtr, vec);
  auto ret = sock.write(connection.peerAddress, vec, iovec_len);
  connection.lossState.totalBytesSent += packetSize;
  if (ret < 0) {
    MVVLOG(4) << "Error writing connection close " << quic::errnoStr(errno)
              << " " << connection;
  } else {
    QUIC_STATS(connection.statsCallback, onWrite, ret);
  }
}

void writeLongClose(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  if (!connection.serverConnectionId) {
    // It's possible that servers encountered an error before binding to a
    // connection id.
    return;
  }
  LongHeader header(
      headerType,
      srcConnId,
      dstConnId,
      getNextPacketNum(
          connection, LongHeader::typeToPacketNumberSpace(headerType)),
      version);
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

void writeShortClose(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  auto header = ShortHeader(
      connection.oneRttWritePhase,
      connId,
      getNextPacketNum(connection, PacketNumberSpace::AppData));
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

quic::Expected<void, QuicError> encryptPacketHeader(
    HeaderForm headerForm,
    uint8_t* header,
    size_t headerLen,
    const uint8_t* encryptedBody,
    size_t bodyLen,
    const PacketNumberCipher& headerCipher) {
  // Header encryption.
  auto packetNumberLength = parsePacketNumberLength(*header);
  Sample sample;
  size_t sampleBytesToUse = kMaxPacketNumEncodingSize - packetNumberLength;
  // If there were less than 4 bytes in the packet number, some of the payload
  // bytes will also be skipped during sampling.
  MVCHECK_GE(bodyLen, sampleBytesToUse + sample.size());
  encryptedBody += sampleBytesToUse;
  memcpy(sample.data(), encryptedBody, sample.size());

  MutableByteRange initialByteRange(header, 1);
  MutableByteRange packetNumByteRange(
      header + headerLen - packetNumberLength, packetNumberLength);
  if (headerForm == HeaderForm::Short) {
    auto result = headerCipher.encryptShortHeader(
        ByteRange(sample.data(), sample.size()),
        initialByteRange,
        packetNumByteRange);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  } else {
    auto result = headerCipher.encryptLongHeader(
        ByteRange(sample.data(), sample.size()),
        initialByteRange,
        packetNumByteRange);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

/**
 * If, after the write, the stream buffers will be below the min threshold,
 * we posit that the end of the streams is near and it's worth sending the
 * entire buffer contents now, rather than wait for another write. This
 * violates the pacer's orders, but we'll likely go app-limited after
 * the streams are finished, and reset the pacer's state. So the actual
 * long-term pacing rate won't deviate much from the pacer's desired rate.
 */
void updatePacketLimitForImminentStreams(
    uint64_t& packetLimit,
    QuicConnectionStateBase& conn) {
  if (conn.streamManager->hasLoss()) {
    return;
  }
  auto sendableBytes = std::min(
      conn.flowControlState.sumCurStreamBufferLen,
      getSendConnFlowControlBytesWire(conn));
  int64_t remainingBufLen = static_cast<int64_t>(sendableBytes) -
      static_cast<int64_t>(packetLimit) *
          static_cast<int64_t>(conn.udpSendPacketLen); // can be negative
  // Don't empty out the buffer if remainingBufLen > minBurstPackets.
  conn.imminentStreamCompletion = remainingBufLen <=
      std::min<int64_t>(conn.transportSettings.minStreamBufThresh,
                        conn.transportSettings.minBurstPackets *
                            conn.udpSendPacketLen);
  if (conn.imminentStreamCompletion && remainingBufLen > 0) {
    // +1 accounts for per-packet overhead (headers, AEAD tag) that reduces
    // the actual stream payload below udpSendPacketLen.
    packetLimit +=
        (remainingBufLen + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen +
        1;
  }
}

/**
 * Writes packets to the socket. The is the function that is called by all
 * the other write*ToSocket() functions.
 *
 * The number of packets written is limited by:
 *   - the maximum batch size supported by the underlying writer
 *     (`maxBatchSize`)
 *   - the `packetLimit` input parameter
 *   - the value returned by the `writableBytesFunc` which usually is either the
 *     congestion control writable bytes or unlimited writable bytes (if the
 *     output of the given scheduler should not be subject to congestion
 *     control)
 *   - the maximum time to spend in a write loop as specified by
 *     `transportSettings.writeLimitRttFraction`
 *   - the amount of data available in the provided scheduler.
 *
 * Writing the packets involves:
 *   1. The scheduler which decides the data to write in each packet
 *   2. The IOBufQuicBatch which holds the data output by the scheduler
 *   3. The BatchWriter which writes the data from the IOBufQuicBatch to
 *      the socket
 *
 * The IOBufQuicBatch holds the packets in the connection's contiguous write
 * buffer, and its BatchWriter writes that buffer to the socket.
 *
 * A rough outline of this function is as follows:
 * 1. Make a BatchWriter for the requested batching mode.
 * 2. Make an IOBufQuicBatch to hold the data. This owns the BatchWriter created
 *    above which it will use to write its data to the socket later.
 * 3. continuousMemoryBuildScheduleEncrypt writes the scheduler's data for one
 *    packet into the write buffer and calls the IOBufQuicBatch's write()
 *    function, which wraps around the BatchWriter it owns. It is called
 *    repeatedly until one of the limits described above is hit.
 * 4. After each packet is written, the connection state is updated to reflect a
 *    packet being sent.
 * 5. Once the limit is hit, the IOBufQuicBatch is flushed to give it another
 *    chance to write any remaining data to the socket that hasn't already been
 *    written in the loop.
 *
 * Note that:
 * - This function does not guarantee that the data is written to the underlying
 *   UDP socket buffer.
 * - It only guarantees that packets will be scheduled and written to a
 *   IOBufQuicBatch and that the IOBufQuicBatch will get a chance to write to
 *   the socket.
 * - Step 4 above updates the connection state when the packet is written to the
 *   buffer, but not necessarily when it is written to the socket. This decision
 *   is made by the IOBufQuicBatch and its BatchWriter.
 * - This function attempts to flush the IOBufQuicBatch before returning
 *   to try to ensure that all scheduled data is written into the socket.
 * - If that flush still fails, the packets are considered written to the
 *   network, since currently there is no way to rewind scheduler and connection
 *   state after the packets have been written to a batch.
 */
quic::Expected<WriteQuicDataResult, QuicError> writeConnectionDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PathIdType pathId,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    HeaderBuilder builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    TimePoint writeLoopBeginTime,
    const std::string& token) {
  if (connection.version == QuicVersion::MVFST_PRIMING &&
      connection.nodeType == QuicNodeType::Server) {
    return WriteQuicDataResult{0, 0, 0};
  }

  MVCHECK(connection.pathManager);
  auto pathInfo = connection.pathManager->getPath(pathId);
  MVCHECK(pathInfo);
  auto peerAddress = pathInfo->peerAddress;

  if (connection.loopDetectorCallback) {
    connection.writeDebugState.schedulerName = scheduler.name().str();
    connection.writeDebugState.noWriteReason = NoWriteReason::WRITE_OK;
  }

  if (!scheduler.hasData()) {
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::EMPTY_SCHEDULER;
    }
    return WriteQuicDataResult{0, 0, 0};
  }

  MVVLOG(10) << nodeToString(connection.nodeType)
             << " writing data using scheduler=" << scheduler.name() << " "
             << connection;

  // Reset the shared buffer at the start of each write loop.
  if (connection.bufAccessor && connection.bufAccessor->ownsBuffer() &&
      connection.bufAccessor->length() > 0) {
    connection.bufAccessor->clear();
  }

  if (!connection.gsoSupported.has_value()) {
    auto gsoResult = sock.getGSO();
    if (!gsoResult.has_value()) {
      MVLOG_ERROR << "Failed to get GSO: " << gsoResult.error().message;
      return quic::make_unexpected(gsoResult.error());
    }
    connection.gsoSupported = sock.getGSO().value() >= 0;
  } else if (*connection.gsoSupported) {
    // Re-check GSO state from the socket. The socket may have detected at
    // runtime that GSO is not actually supported (e.g. EIO on sendmsg with
    // UDP_SEGMENT) and updated its cached state.
    auto gsoResult = sock.getGSO();
    if (gsoResult.has_value() && gsoResult.value() < 0) {
      connection.gsoSupported = false;
    }
  }

  auto batchWriter = BatchWriterFactory::makeBatchWriter(
      connection.transportSettings.batchingMode,
      connection.transportSettings.maxBatchSize,
      connection.transportSettings.dataPathType,
      connection,
      *connection.gsoSupported);

  auto happyEyeballsState = connection.nodeType == QuicNodeType::Server
      ? nullptr
      : &static_cast<QuicClientConnectionState&>(connection).happyEyeballsState;
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      sock,
      peerAddress,
      connection.statsCallback,
      happyEyeballsState);

  auto batchSize = connection.transportSettings.batchingMode ==
          QuicBatchingMode::BATCHING_MODE_NONE
      ? connection.transportSettings.writeConnectionDataPacketsLimit
      : connection.transportSettings.maxBatchSize;

  uint64_t bytesWritten = 0;
  uint64_t shortHeaderPadding = 0;
  [[maybe_unused]] uint64_t shortHeaderPaddingCount = 0;
  SCOPE_EXIT {
    auto nSent = ioBufBatch.getPktSent();
    if (nSent > 0) {
      QUIC_STATS(connection.statsCallback, onPacketsSent, nSent);
      QUIC_STATS(connection.statsCallback, onWrite, bytesWritten);
      if (shortHeaderPadding > 0) {
        QUIC_STATS(
            connection.statsCallback,
            onShortHeaderPaddingBatch,
            shortHeaderPaddingCount,
            shortHeaderPadding);
      }
    }
  };

  quic::TimePoint sentTime = Clock::now();

  while (scheduler.hasData() && ioBufBatch.getPktSent() < packetLimit &&
         ((ioBufBatch.getPktSent() < batchSize) ||
          writeLoopTimeLimit(writeLoopBeginTime, connection))) {
    auto packetNum = getNextPacketNum(connection, pnSpace);
    auto header = builder(srcConnId, dstConnId, packetNum, version, token);
    uint32_t writableBytes = std::min<uint64_t>(
        connection.udpSendPacketLen, writableBytesFunc(connection));
    uint64_t cipherOverhead = aead.getCipherOverhead();
    if (writableBytes < cipherOverhead) {
      writableBytes = 0;
    } else {
      writableBytes -= cipherOverhead;
    }

    auto writeQueueTransaction =
        connection.streamManager->writeQueue().beginTransaction();
    auto guard = folly::makeGuard([&] {
      connection.streamManager->writeQueue().rollbackTransaction(
          std::move(writeQueueTransaction));
    });

    auto ret = continuousMemoryBuildScheduleEncrypt(
        connection,
        std::move(header),
        pnSpace,
        packetNum,
        cipherOverhead,
        scheduler,
        writableBytes,
        ioBufBatch,
        aead,
        headerCipher,
        sentTime);

    // This is a fatal error vs. a build error.
    if (!ret.has_value()) {
      return quic::make_unexpected(ret.error());
    }
    if (!ret->buildSuccess) {
      // If we're returning because we couldn't schedule more packets,
      // make sure we flush the buffer in this function.
      auto flushResult = ioBufBatch.flush();
      if (!flushResult.has_value()) {
        return quic::make_unexpected(flushResult.error());
      }
      updateErrnoCount(connection, ioBufBatch);
      return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
    }
    // If we build a packet, we updateConnection(), even if write might have
    // been failed. Because if it builds, a lot of states need to be updated no
    // matter the write result. We are basically treating this case as if we
    // pretend write was also successful but packet is lost somewhere in the
    // network.
    bytesWritten += ret->encodedSize;
    if (ret->result && ret->result->shortHeaderPadding > 0) {
      shortHeaderPaddingCount++;
      shortHeaderPadding += ret->result->shortHeaderPadding;
    }

    auto& result = ret->result;
    // This call to updateConnection will attempt to erase streams from the
    // write queue that have already been removed in QuicPacketScheduler.
    // Removing non-existent streams can be O(N), consider passing the
    // transaction set to skip this step
    auto updateConnResult = updateConnection(
        connection,
        *pathInfo,
        std::move(result->clonedPacketIdentifier),
        std::move(result->packet->packet),
        sentTime,
        static_cast<uint32_t>(ret->encodedSize),
        static_cast<uint32_t>(ret->encodedBodySize),
        result->transmissionReason,
        result->isPtoRetransmission);
    if (!updateConnResult.has_value()) {
      return quic::make_unexpected(updateConnResult.error());
    }
    guard.dismiss();
    connection.streamManager->writeQueue().commitTransaction(
        std::move(writeQueueTransaction));

    // if ioBufBatch.write returns false
    // it is because a flush() call failed
    if (!ret->writeSuccess) {
      if (connection.loopDetectorCallback) {
        connection.writeDebugState.noWriteReason =
            NoWriteReason::SOCKET_FAILURE;
      }
      return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
    }
  }

  // Ensure that the buffer is flushed before returning
  auto flushResult = ioBufBatch.flush();
  if (!flushResult.has_value()) {
    return quic::make_unexpected(flushResult.error());
  }
  updateErrnoCount(connection, ioBufBatch);

  MVCHECK(connection.bufAccessor->ownsBuffer());
  MVCHECK(
      connection.bufAccessor->length() == 0 &&
      connection.bufAccessor->headroom() == 0);
  return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
}

quic::Expected<WriteQuicDataResult, QuicError> writeProbingDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    HeaderBuilder builder,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    const std::string& token,
    PacketTransmissionReason transmissionReason) {
  // Skip a packet number for probing packets to elicit acks
  increaseNextPacketNum(connection, pnSpace);
  auto writeLoopBeginTime = Clock::now();

  // If we have the ability to draw an ACK for AppData, let's send a probe that
  // is just an IMMEDIATE_ACK. Increase the number of probes to do so.
  uint8_t dataProbesToSend = probesToSend;
  if (probesToSend && canSendAckControlFrames(connection) &&
      encryptionLevel == EncryptionLevel::AppData) {
    probesToSend = std::max<uint8_t>(probesToSend, kPacketToSendForPTO);
    dataProbesToSend = probesToSend - 1;
  }
  const bool useNonCloningPto =
      canUseNonCloningPto(connection, encryptionLevel);
  auto probeWriteResult = [&]() {
    if (useNonCloningPto) {
      if (pnSpace == PacketNumberSpace::AppData &&
          encryptionLevel == EncryptionLevel::AppData) {
        AppDataPtoScheduler ptoScheduler(
            scheduler, connection, "AppDataPtoScheduler", transmissionReason);
        return writeConnectionDataToSocket(
            sock,
            connection,
            connection.currentPathId,
            srcConnId,
            dstConnId,
            builder,
            pnSpace,
            ptoScheduler,
            connection.transportSettings.enableWritableBytesLimit
                ? probePacketWritableBytes
                : unlimitedWritableBytes,
            dataProbesToSend,
            aead,
            headerCipher,
            version,
            writeLoopBeginTime,
            token);
      }
      CryptoPtoScheduler ptoScheduler(
          scheduler,
          connection,
          encryptionLevel,
          "CryptoPtoScheduler",
          transmissionReason);
      return writeConnectionDataToSocket(
          sock,
          connection,
          connection.currentPathId,
          srcConnId,
          dstConnId,
          builder,
          pnSpace,
          ptoScheduler,
          connection.transportSettings.enableWritableBytesLimit
              ? probePacketWritableBytes
              : unlimitedWritableBytes,
          dataProbesToSend,
          aead,
          headerCipher,
          version,
          writeLoopBeginTime,
          token);
    }
    CloningScheduler cloningScheduler(
        scheduler,
        connection,
        "CloningScheduler",
        aead.getCipherOverhead(),
        transmissionReason);
    return writeConnectionDataToSocket(
        sock,
        connection,
        connection.currentPathId,
        srcConnId,
        dstConnId,
        builder,
        pnSpace,
        cloningScheduler,
        connection.transportSettings.enableWritableBytesLimit
            ? probePacketWritableBytes
            : unlimitedWritableBytes,
        dataProbesToSend,
        aead,
        headerCipher,
        version,
        writeLoopBeginTime,
        token);
  }();
  if (!probeWriteResult.has_value()) {
    return quic::make_unexpected(probeWriteResult.error());
  }
  auto probesWritten = probeWriteResult->packetsWritten;
  auto bytesWritten = probeWriteResult->bytesWritten;
  if (probesWritten < probesToSend) {
    // If we can use an IMMEDIATE_ACK, that's better than a PING.
    auto probeSchedulerBuilder = FrameScheduler::Builder(
        connection, encryptionLevel, pnSpace, "ProbeScheduler");
    // Might as well include some ACKs.
    probeSchedulerBuilder.ackFrames();
    if (canSendAckControlFrames(connection) &&
        encryptionLevel == EncryptionLevel::AppData) {
      requestPeerImmediateAck(connection);
      probeSchedulerBuilder.immediateAckFrames();
    } else {
      connection.pendingEvents.sendPing = true;
      probeSchedulerBuilder.pingFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    probeScheduler.setTransmissionReason(transmissionReason);
    auto probingResult = writeConnectionDataToSocket(
        sock,
        connection,
        connection.currentPathId,
        srcConnId,
        dstConnId,
        builder,
        pnSpace,
        probeScheduler,
        connection.transportSettings.enableWritableBytesLimit
            ? probePacketWritableBytes
            : unlimitedWritableBytes,
        probesToSend - probesWritten,
        aead,
        headerCipher,
        version,
        writeLoopBeginTime);
    if (!probingResult.has_value()) {
      return quic::make_unexpected(probingResult.error());
    }
    probesWritten += probingResult->packetsWritten;
    bytesWritten += probingResult->bytesWritten;
  }
  MVVLOG_IF(10, probesWritten > 0)
      << nodeToString(connection.nodeType) << " writing probes using scheduler="
      << (useNonCloningPto ? "non-cloning PTO" : "CloningScheduler") << " "
      << connection;
  return WriteQuicDataResult{0, probesWritten, bytesWritten};
}

WriteDataReason shouldWriteData(/*const*/ QuicConnectionStateBase& conn) {
  auto& numProbePackets = conn.pendingEvents.numProbePackets;
  bool shouldWriteInitialProbes =
      numProbePackets[PacketNumberSpace::Initial] && conn.initialWriteCipher;
  bool shouldWriteHandshakeProbes =
      numProbePackets[PacketNumberSpace::Handshake] &&
      conn.handshakeWriteCipher;
  bool shouldWriteAppDataProbes =
      numProbePackets[PacketNumberSpace::AppData] && conn.oneRttWriteCipher;
  if (shouldWriteInitialProbes || shouldWriteHandshakeProbes ||
      shouldWriteAppDataProbes) {
    MVVLOG(10) << nodeToString(conn.nodeType) << " needs write because of PTO"
               << conn;
    return WriteDataReason::PROBES;
  }
  if (hasAlternatePathValidationDataToWrite(conn)) {
    return WriteDataReason::PATH_VALIDATION;
  }
  if (hasAckDataToWrite(conn)) {
    MVVLOG(10) << nodeToString(conn.nodeType) << " needs write because of ACKs "
               << conn;
    return WriteDataReason::ACK;
  }

  if (!congestionControlWritableBytes(conn)) {
    QUIC_STATS(conn.statsCallback, onCwndBlocked);
    return WriteDataReason::NO_WRITE;
  }

  return hasNonAckDataToWrite(conn);
}

static bool canWriteAlternatePathValidation(
    const QuicConnectionStateBase& conn,
    PathIdType pathId) {
  // A path validation packet is padded to a full UDP packet, and the path's
  // anti-amplification budget is replenished in udpSendPacketLen units, so a
  // sub-packet budget can never send one.
  return pathId != conn.currentPathId &&
      pathValidationWritableBytes(conn, pathId) >= conn.udpSendPacketLen;
}

bool hasAlternatePathValidationDataToWrite(
    const QuicConnectionStateBase& conn) {
  // Check path challenges
  for (const auto& pathId : conn.pendingEvents.pathChallenges) {
    if (canWriteAlternatePathValidation(conn, pathId)) {
      return true;
    }
  }

  // Check path responses
  for (const auto& [pathId, _] : conn.pendingEvents.pathResponses) {
    if (canWriteAlternatePathValidation(conn, pathId)) {
      return true;
    }
  }

  return false;
}

bool hasAckDataToWrite(const QuicConnectionStateBase& conn) {
  // hasAcksToSchedule tells us whether we have acks.
  // needsToSendAckImmediately tells us when to schedule the acks. If we don't
  // have an immediate need to schedule the acks then we need to wait till we
  // satisfy a condition where there is immediate need, so we shouldn't
  // consider the acks to be writable.
  bool writeAcks =
      (toWriteInitialAcks(conn) || toWriteHandshakeAcks(conn) ||
       toWriteAppDataAcks(conn));
  MVVLOG_IF(10, writeAcks) << nodeToString(conn.nodeType)
                           << " needs write because of acks largestAck="
                           << largestAckToSendToString(conn)
                           << " largestSentAck="
                           << largestAckScheduledToString(conn)
                           << " ackTimeoutSet="
                           << conn.pendingEvents.scheduleAckTimeout << " "
                           << conn;
  return writeAcks;
}

WriteDataReason hasNonAckDataToWrite(const QuicConnectionStateBase& conn) {
  if (cryptoHasWritableData(conn)) {
    MVVLOG(10) << nodeToString(conn.nodeType)
               << " needs write because of crypto stream" << " " << conn;
    return WriteDataReason::CRYPTO_STREAM;
  }
  if (!conn.oneRttWriteCipher &&
      !(conn.nodeType == QuicNodeType::Client &&
        static_cast<const QuicClientConnectionState&>(conn)
            .zeroRttWriteCipher)) {
    // All the rest of the types of data need either a 1-rtt or 0-rtt cipher to
    // be written.
    return WriteDataReason::NO_WRITE;
  }
  if (!conn.pendingEvents.resets.empty()) {
    return WriteDataReason::RESET;
  }
  if (conn.streamManager->hasWindowUpdates()) {
    return WriteDataReason::STREAM_WINDOW_UPDATE;
  }
  if (conn.pendingEvents.connWindowUpdate) {
    return WriteDataReason::CONN_WINDOW_UPDATE;
  }
  if (conn.streamManager->hasBlocked()) {
    return WriteDataReason::BLOCKED;
  }
  // If we have lost data or flow control + stream data.
  // Note streamManager hasWritable now can return true when only datagrams
  // are writable :|
  // If we're out of flow control though, hasDatagramsToSend will also be
  // true
  if (conn.streamManager->hasLoss() ||
      (getSendConnFlowControlBytesWire(conn) != 0 &&
       conn.streamManager->hasWritable())) {
    return WriteDataReason::STREAM;
  }
  if (!conn.pendingEvents.frames.empty()) {
    return WriteDataReason::SIMPLE;
  }
  if (conn.pendingEvents.pathChallenges.contains(conn.currentPathId)) {
    return WriteDataReason::PATH_VALIDATION;
  }
  if ((conn.pendingEvents.pathResponses.find(conn.currentPathId) !=
       conn.pendingEvents.pathResponses.end())) {
    return WriteDataReason::PATH_VALIDATION;
  }
  if (conn.pendingEvents.sendPing) {
    return WriteDataReason::PING;
  }
  if (conn.datagramState.flowManager.hasDatagramsToSend()) {
    return WriteDataReason::DATAGRAM;
  }
  return WriteDataReason::NO_WRITE;
}

void maybeSendStreamLimitUpdates(QuicConnectionStateBase& conn) {
  auto update = conn.streamManager->remoteBidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, true)));
  }
  update = conn.streamManager->remoteUnidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, false)));
  }
}

void implicitAckCryptoStream(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel) {
  auto* cryptoStream = getCryptoStream(*conn.cryptoState, encryptionLevel);
  const auto clearCryptoWriteState = [&] {
    if (cryptoStream->streamSendBuffer) {
      cryptoStream->streamSendBuffer->cancelAll();
      return;
    }
    cryptoStream->lossBuffer.clear();
    MVCHECK(cryptoStream->retransmissionBuffer.empty());
    MVCHECK(cryptoStream->pendingWrites.empty());
  };
  auto implicitAckTime = Clock::now();
  auto packetNumSpace = encryptionLevel == EncryptionLevel::Handshake
      ? PacketNumberSpace::Handshake
      : PacketNumberSpace::Initial;
  auto& ackState = getAckState(conn, packetNumSpace);
  AckBlocks ackBlocks;
  ReadAckFrame implicitAck;
  implicitAck.ackDelay = 0ms;
  implicitAck.implicit = true;
  for (const auto& op : conn.outstandings.packets) {
    if (op.packet.header.getPacketNumberSpace() == packetNumSpace) {
      auto insertResult =
          ackBlocks.tryInsert(op.packet.header.getPacketSequenceNum());
      if (insertResult.hasError()) {
        MVLOG_ERROR << "Failed to insert packet number into ack blocks: "
                    << static_cast<int>(insertResult.error());
        // Continue processing other packets - this shouldn't happen in normal
        // operation
        continue;
      }
    }
  }
  if (ackBlocks.empty()) {
    if (cryptoStream->streamSendBuffer) {
      clearCryptoWriteState();
    }
    return;
  }
  // Construct an implicit ack covering the entire range of packets.
  // If some of these have already been ACK'd then processAckFrame
  // should simply ignore them.
  implicitAck.largestAcked = ackBlocks.back().end;
  if (ackState.skippedPacketNum &&
      *ackState.skippedPacketNum > ackBlocks.front().start &&
      *ackState.skippedPacketNum < implicitAck.largestAcked) {
    implicitAck.ackBlocks.emplace_back(
        *ackState.skippedPacketNum + 1, implicitAck.largestAcked);
    implicitAck.ackBlocks.emplace_back(
        ackBlocks.front().start, *ackState.skippedPacketNum - 1);
  } else {
    implicitAck.ackBlocks.emplace_back(
        ackBlocks.front().start, implicitAck.largestAcked);
  }
  auto result = processAckFrame(
      conn,
      packetNumSpace,
      implicitAck,
      [](const auto&) -> quic::Expected<void, QuicError> {
        // ackedPacketVisitor. No action needed.
        return {};
      },
      [&](auto&, auto& packetFrame) -> quic::Expected<void, QuicError> {
        switch (packetFrame.type()) {
          case QuicWriteFrame::Type::WriteCryptoFrame: {
            const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
            auto* ackedCryptoStream =
                getCryptoStream(*conn.cryptoState, encryptionLevel);
            return processCryptoStreamAck(
                *ackedCryptoStream, frame.offset, frame.len);
          }
          case QuicWriteFrame::Type::WriteAckFrame: {
            const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
            commonAckVisitorForAckFrame(ackState, frame);
            break;
          }
          default: {
            // We don't bother checking for valid packets, since these are
            // our outstanding packets.
          }
        }
        return {};
      },
      // We shouldn't mark anything as lost from the implicit ACK, as it should
      // be ACKing the entire rangee.
      [](auto&, auto, auto&, auto) -> quic::Expected<void, QuicError> {
        MVCHECK(false, "Got loss from implicit crypto ACK.");
        return {};
      },
      implicitAckTime);
  // TODO handle error
  MVCHECK(result.has_value(), result.error().message);
  // Clear our the loss buffer explicitly. The implicit ACK itself will not
  // remove data already in the loss buffer.
  clearCryptoWriteState();
}

void handshakeConfirmed(QuicConnectionStateBase& conn) {
  // If we've supposedly confirmed the handshake and don't have the 1RTT
  // ciphers installed, we are going to have problems.
  MVCHECK(conn.oneRttWriteCipher);
  MVCHECK(conn.oneRttWriteHeaderCipher);
  MVCHECK(conn.readCodec->getOneRttReadCipher());
  MVCHECK(conn.readCodec->getOneRttHeaderCipher());
  conn.readCodec->onHandshakeDone(Clock::now());
  conn.initialWriteCipher.reset();
  conn.initialHeaderCipher.reset();
  conn.readCodec->setInitialReadCipher(nullptr);
  conn.readCodec->setInitialHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Initial);
  conn.ackStates.initialAckState.reset();
  conn.handshakeWriteCipher.reset();
  conn.handshakeWriteHeaderCipher.reset();
  conn.readCodec->setHandshakeReadCipher(nullptr);
  conn.readCodec->setHandshakeHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Handshake);
  conn.ackStates.handshakeAckState.reset();
}

bool hasInitialOrHandshakeCiphers(QuicConnectionStateBase& conn) {
  return conn.initialWriteCipher || conn.handshakeWriteCipher ||
      conn.readCodec->getInitialCipher() ||
      conn.readCodec->getHandshakeReadCipher();
}

bool toWriteInitialAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.initialWriteCipher && conn.ackStates.initialAckState &&
      hasAcksToSchedule(*conn.ackStates.initialAckState) &&
      conn.ackStates.initialAckState->needsToSendAckImmediately);
}

bool toWriteHandshakeAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.handshakeWriteCipher && conn.ackStates.handshakeAckState &&
      hasAcksToSchedule(*conn.ackStates.handshakeAckState) &&
      conn.ackStates.handshakeAckState->needsToSendAckImmediately);
}

bool toWriteAppDataAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.oneRttWriteCipher &&
      hasAcksToSchedule(conn.ackStates.appDataAckState) &&
      conn.ackStates.appDataAckState.needsToSendAckImmediately);
}

void updateOneRttWriteCipher(
    quic::QuicConnectionStateBase& conn,
    std::unique_ptr<Aead> aead,
    ProtectionType oneRttPhase) {
  MVCHECK(
      oneRttPhase == ProtectionType::KeyPhaseZero ||
      oneRttPhase == ProtectionType::KeyPhaseOne);
  MVCHECK(
      oneRttPhase != conn.oneRttWritePhase,
      "Cannot replace cipher for current write phase");
  conn.oneRttWriteCipher = std::move(aead);
  conn.oneRttWritePhase = oneRttPhase;
  conn.oneRttWritePacketsSentInCurrentPhase = 0;
}

quic::Expected<void, QuicError> maybeHandleIncomingKeyUpdate(
    QuicConnectionStateBase& conn) {
  if (conn.readCodec->getCurrentOneRttReadPhase() != conn.oneRttWritePhase) {
    // Peer has initiated a key update.
    auto nextOneRttWriteCipherResult =
        conn.handshakeLayer->getNextOneRttWriteCipher();
    if (!nextOneRttWriteCipherResult.has_value()) {
      return quic::make_unexpected(nextOneRttWriteCipherResult.error());
    }
    updateOneRttWriteCipher(
        conn,
        std::move(nextOneRttWriteCipherResult.value()),
        conn.readCodec->getCurrentOneRttReadPhase());

    auto nextOneRttReadCipherResult =
        conn.handshakeLayer->getNextOneRttReadCipher();
    if (!nextOneRttReadCipherResult.has_value()) {
      return quic::make_unexpected(nextOneRttReadCipherResult.error());
    }
    conn.readCodec->setNextOneRttReadCipher(
        std::move(nextOneRttReadCipherResult.value()));

    // The peer has initiated a key update. We should use the regular key
    // update interval if we are initiating key updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();
  }
  return {};
}

quic::Expected<void, QuicError> maybeInitiateKeyUpdate(
    QuicConnectionStateBase& conn) {
  if (conn.transportSettings.initiateKeyUpdate) {
    if (conn.nodeType == QuicNodeType::Server && conn.version.has_value() &&
        conn.version.value() == QuicVersion::MVFST &&
        conn.transportSettings.firstKeyUpdatePacketCount.has_value()) {
      // Some old versions of MVFST did not support key updates.
      // So as the server, do not attempt to initiate key updates if the client
      // hasn't initiated one yet.
      return {};
    }
    auto packetsBeforeNextUpdate =
        conn.transportSettings.firstKeyUpdatePacketCount
        ? conn.transportSettings.firstKeyUpdatePacketCount.value()
        : conn.transportSettings.keyUpdatePacketCountInterval;

    if ((conn.oneRttWritePacketsSentInCurrentPhase > packetsBeforeNextUpdate) &&
        conn.readCodec->canInitiateKeyUpdate()) {
      QUIC_STATS(conn.statsCallback, onKeyUpdateAttemptInitiated);
      conn.readCodec->advanceOneRttReadPhase();

      //  We have initiated a key update. We should use the regular key
      // update from now on.
      conn.transportSettings.firstKeyUpdatePacketCount.reset();

      auto nextOneRttWriteCipherResult =
          conn.handshakeLayer->getNextOneRttWriteCipher();
      if (!nextOneRttWriteCipherResult.has_value()) {
        return quic::make_unexpected(nextOneRttWriteCipherResult.error());
      }
      updateOneRttWriteCipher(
          conn,
          std::move(nextOneRttWriteCipherResult.value()),
          conn.readCodec->getCurrentOneRttReadPhase());

      auto nextOneRttReadCipherResult =
          conn.handshakeLayer->getNextOneRttReadCipher();
      if (!nextOneRttReadCipherResult.has_value()) {
        return quic::make_unexpected(nextOneRttReadCipherResult.error());
      }
      conn.readCodec->setNextOneRttReadCipher(
          std::move(nextOneRttReadCipherResult.value()));
      // Signal the transport that a key update has been initiated.
      conn.oneRttWritePendingVerification = true;
      conn.oneRttWritePendingVerificationPacketNumber.reset();
    }
  }
  return {};
}

quic::Expected<void, QuicError> maybeVerifyPendingKeyUpdate(
    QuicConnectionStateBase& conn,
    const OutstandingPacketWrapper& outstandingPacket,
    const RegularQuicPacket& ackPacket) {
  if (!(protectionTypeToEncryptionLevel(
            outstandingPacket.packet.header.getProtectionType()) ==
        EncryptionLevel::AppData)) {
    // This is not an app data packet. We can't have initiated a key update yet.
    return {};
  }

  if (conn.oneRttWritePendingVerificationPacketNumber &&
      outstandingPacket.packet.header.getPacketSequenceNum() >=
          conn.oneRttWritePendingVerificationPacketNumber.value()) {
    // There is a pending key update. This packet should be acked in
    // the current phase.
    if (ackPacket.header.getProtectionType() == conn.oneRttWritePhase) {
      // Key update is verified.
      conn.oneRttWritePendingVerificationPacketNumber.reset();
      conn.oneRttWritePendingVerification = false;
    } else {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::CRYPTO_ERROR,
          "Packet with key update was acked in the wrong phase"));
    }
  }
  return {};
}

// Unfortunate, we should make this more portable.
#if !defined IPV6_HOPLIMIT
#define IPV6_HOPLIMIT -1
#endif
#if !defined IP_TTL
#define IP_TTL -1
#endif
// Add a packet mark to the outstanding packet. Currently only supports
// TTLD marking.
void maybeAddPacketMark(
    QuicConnectionStateBase& conn,
    OutstandingPacketWrapper& op) {
  static constexpr folly::SocketOptionKey kHopLimitOptionKey = {
      IPPROTO_IPV6, IPV6_HOPLIMIT};
  static constexpr folly::SocketOptionKey kTTLOptionKey = {IPPROTO_IP, IP_TTL};
  if (!conn.socketCmsgsState.additionalCmsgs.has_value()) {
    return;
  }
  const auto& cmsgs = conn.socketCmsgsState.additionalCmsgs;
  auto it = cmsgs->find(kHopLimitOptionKey);
  if (it != cmsgs->end() && it->second == 255) {
    op.metadata.mark = OutstandingPacketMark::TTLD;
    return;
  }
  it = cmsgs->find(kTTLOptionKey);
  if (it != cmsgs->end() && it->second == 255) {
    op.metadata.mark = OutstandingPacketMark::TTLD;
  }
}

void maybeScheduleAckForCongestionFeedback(
    const ReceivedUdpPacket& receivedPacket,
    AckState& ackState) {
  // If the packet was marked as having encountered congestion, send an ACK
  // immediately to ensure timely response from the peer.
  // Note that the tosValue will be populated only if the enableEcnOnEgress
  // transport setting is enabled.
  if ((receivedPacket.tosValue & 0b11) == 0b11) {
    ackState.needsToSendAckImmediately = true;
  }
}

void updateNegotiatedAckFeatures(QuicConnectionStateBase& conn) {
  // Legacy-format gate. `advertiseLegacyAckReceiveTimestamps=false` blocks
  // both sending and accepting (incoming accept is enforced at the frame
  // validation gate). `enableIetfAckReceiveTimestamps` blocks only sending,
  // including the ACK_EXTENDED receive timestamps feature. Draft-02 has its
  // own gate below.
  const bool isLegacyAckReceiveTimestampsSupported =
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
          .has_value() &&
      conn.transportSettings.advertiseLegacyAckReceiveTimestamps &&
      !conn.transportSettings.enableIetfAckReceiveTimestamps &&
      conn.maybePeerReceiveTimestampsConfig.has_value() &&
      conn.maybePeerReceiveTimestampsConfig->version ==
          AckReceiveTimestampsVersion::LegacyMvfst;

  const uint64_t peerRequestedTimestampsCount =
      conn.maybePeerReceiveTimestampsConfig.has_value()
      ? conn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck
      : 0;

  conn.negotiatedAckReceiveTimestampSupport =
      isLegacyAckReceiveTimestampsSupported &&
      (peerRequestedTimestampsCount > 0);

  conn.negotiatedExtendedAckFeatures = conn.peerAdvertisedExtendedAckFeatures &
      conn.transportSettings.enableExtendedAckFeatures;
  // Disable the ECN fields if we are not reading them
  if (!conn.transportSettings.readEcnOnIngress) {
    conn.negotiatedExtendedAckFeatures &=
        ~static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::ECN_COUNTS);
  }
  // Disable the receive timestamps fields if we have not regoatiated receive
  // timestamps support
  if (!conn.negotiatedAckReceiveTimestampSupport) {
    conn.negotiatedExtendedAckFeatures &=
        ~static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  }

  // Compute outgoing wire format. Peer-side "draft-02 wins" is already
  // baked into `maybePeerReceiveTimestampsConfig.version`; this applies the
  // local gates.
  //
  // draft-ietf-quic-receive-ts-02 negotiation is ONE-WAY per direction: an
  // endpoint sends ACK_RECEIVE_TIMESTAMPS frames if its PEER advertised the
  // receive-timestamps TPs (peer wants timestamps from us). The endpoint's
  // own advertisement (`enableIetfAckReceiveTimestamps`) governs only the
  // reverse direction. Sending draft-02 also requires
  // `sendDraft02AckReceiveTimestamps` and a local receive timestamps config.
  // Legacy mvfst is not IETF-spec-governed and keeps the two-way requirement.
  conn.negotiatedOutgoingAckReceiveTimestampsVersion =
      AckReceiveTimestampsVersion::None;
  if (conn.maybePeerReceiveTimestampsConfig.has_value() &&
      conn.maybePeerReceiveTimestampsConfig->maxReceiveTimestampsPerAck > 0) {
    const auto peerVersion = conn.maybePeerReceiveTimestampsConfig->version;
    if (peerVersion == AckReceiveTimestampsVersion::DraftIetf02 &&
        conn.transportSettings.sendDraft02AckReceiveTimestamps &&
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
            .has_value()) {
      conn.negotiatedOutgoingAckReceiveTimestampsVersion =
          AckReceiveTimestampsVersion::DraftIetf02;
    } else if (isLegacyAckReceiveTimestampsSupported) {
      conn.negotiatedOutgoingAckReceiveTimestampsVersion =
          AckReceiveTimestampsVersion::LegacyMvfst;
    }
  }
}

quic::Expected<WriteQuicDataResult, QuicError>
writePathValidationDataForAlternatePaths(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t /*packetLimit*/,
    TimePoint writeLoopBeginTime) {
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& probesWritten = result.probesWritten;
  auto& bytesWritten = result.bytesWritten;

  UnorderedSet<PathIdType> pathIdUnion;
  for (const auto& pathId : connection.pendingEvents.pathChallenges) {
    if (canWriteAlternatePathValidation(connection, pathId)) {
      pathIdUnion.insert(pathId);
    }
  }
  for (const auto& [pathId, _] : connection.pendingEvents.pathResponses) {
    if (canWriteAlternatePathValidation(connection, pathId)) {
      pathIdUnion.insert(pathId);
    }
  }

  for (const auto& pathId : pathIdUnion) {
    auto builder = ShortHeaderBuilder(connection.oneRttWritePhase);
    auto schedulerBuilder = FrameScheduler::Builder(
                                connection,
                                EncryptionLevel::AppData,
                                PacketNumberSpace::AppData,
                                "PathValidationScheduler")
                                .pathValidationFrames(pathId);
    auto path = connection.pathManager->getPath(pathId);
    if (!path) {
      MVLOG_ERROR << "Path not found for pathId=" << pathId;
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
          "Inconsistent path state"));
    }
    auto pathLimiterFunc =
        [pathId](const QuicConnectionStateBase& conn) -> uint64_t {
      return pathValidationWritableBytes(conn, pathId);
    };
    QuicAsyncUDPSocket& sendSocket = path->socket ? *path->socket : sock;
    FrameScheduler scheduler = std::move(schedulerBuilder).build();
    auto destCid = path->destinationConnectionId
        ? path->destinationConnectionId.value()
        : dstConnId;
    auto pathValidationWriteResult = writeConnectionDataToSocket(
        sendSocket,
        connection,
        path->id,
        srcConnId, /* not used since these are short header packets */
        destCid,
        std::move(builder),
        PacketNumberSpace::AppData,
        scheduler,
        pathLimiterFunc, // Only apply path limit for the server. Client has
                         // unlimited bytes.
        1, // packetLimit. Path Validation requires only one packet.
        aead,
        headerCipher,
        version,
        writeLoopBeginTime);
    if (!pathValidationWriteResult.has_value()) {
      return quic::make_unexpected(pathValidationWriteResult.error());
    }
    packetsWritten += pathValidationWriteResult->packetsWritten;
    bytesWritten += pathValidationWriteResult->bytesWritten;
    MVVLOG_IF(10, packetsWritten || probesWritten)
        << nodeToString(connection.nodeType)
        << " written path validation packets for " << pathId
        << "to socket packets=" << packetsWritten << " probes=" << probesWritten
        << " " << connection;
    if (packetsWritten == 0) {
      // We couldn't write anymore.
      break;
    }
  }
  return result;
}

} // namespace quic
