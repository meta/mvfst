/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicAckScheduler.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/common/MvfstLogging.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/TimestampFrameFunctions.h>

namespace quic {
namespace {

quic::Expected<bool, QuicError> completeStreamFrameFits(
    const WriteStreamFrame& frame,
    bool skipLengthField,
    uint64_t availableSpace) {
  uint64_t headerSize = sizeof(uint8_t);
  auto streamIdSize = QuicInteger(frame.streamId).getSize();
  if (streamIdSize.hasError()) {
    return quic::make_unexpected(streamIdSize.error());
  }
  headerSize += streamIdSize.value();

  if (frame.offset != 0) {
    auto offsetSize = QuicInteger(frame.offset).getSize();
    if (offsetSize.hasError()) {
      return quic::make_unexpected(offsetSize.error());
    }
    headerSize += offsetSize.value();
  }

  if (!skipLengthField) {
    const auto lengthFieldSize = getStreamFrameDataLengthSize(frame.len);
    if (!lengthFieldSize) {
      return false;
    }
    headerSize += *lengthFieldSize;
  }

  return availableSpace >= headerSize &&
      frame.len <= availableSpace - headerSize;
}

} // namespace

PacketRebuilder::PacketRebuilder(
    PacketBuilderInterface& regularBuilder,
    QuicConnectionStateBase& conn)
    : conn_(conn),
      timestampPacketObserver_(),
      builder_(
          regularBuilder,
          timestampPacketObserver_,
          shouldWriteOneRttTimestampFrame(conn_, false) &&
              regularBuilder.getPacketHeader().asShort()) {}

uint64_t PacketRebuilder::getHeaderBytes() const {
  return builder_.builder().getHeaderBytes();
}

ClonedPacketIdentifier PacketRebuilder::cloneOutstandingPacket(
    OutstandingPacketWrapper& packet) {
  // Either the packet has never been cloned before, or it's
  // maybeClonedPacketIdentifier is still in the
  // outstandings.clonedPacketIdentifiers set.
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          packet.maybeClonedPacketIdentifier &&
          !conn_.outstandings.clonedPacketIdentifiers.count(
              *packet.maybeClonedPacketIdentifier),
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: cloned packet identifier missing from "
      "outstandings set before clone");
  MVDCHECK(
      !packet.maybeClonedPacketIdentifier ||
      conn_.outstandings.clonedPacketIdentifiers.count(
          *packet.maybeClonedPacketIdentifier));
  if (!packet.maybeClonedPacketIdentifier) {
    auto packetNum = packet.packet.header.getPacketSequenceNum();
    auto packetNumberSpace = packet.packet.header.getPacketNumberSpace();
    ClonedPacketIdentifier event(packetNumberSpace, packetNum);
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server &&
            conn_.outstandings.clonedPacketIdentifiers.contains(event),
        conn_.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
        "quic_packet_rebuilder",
        "invariant_violation: cloned packet identifier already present "
        "while cloning packet");
    MVDCHECK(!conn_.outstandings.clonedPacketIdentifiers.contains(event));
    packet.maybeClonedPacketIdentifier = event;
    conn_.outstandings.clonedPacketIdentifiers.insert(event);
    ++conn_.outstandings
          .clonedPacketCount[packet.packet.header.getPacketNumberSpace()];
  }
  return *packet.maybeClonedPacketIdentifier;
}

quic::Expected<Optional<ClonedPacketIdentifier>, QuicError>
PacketRebuilder::rebuildFromPacket(OutstandingPacketWrapper& packet) {
  // TODO: if PMTU changes between the transmission of the original packet and
  // now, then we cannot clone everything in the packet.

  bool writeSuccess = false;
  bool windowUpdateWritten = false;
  bool shouldWriteWindowUpdate = false;
  bool notPureAck = false;
  bool shouldRebuildWriteAckFrame = false;
  // A STREAM frame rebuilt without its length extends to the end of the packet,
  // so no TIMESTAMP may follow it.
  bool wroteLengthlessStreamFrame = false;
  bool wroteTimestampFrame = false;
  auto& packetBuilder = builder_.builder();
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(packet.packet.header.getProtectionType());
  // First check if there's an ACK in this packet. We do this because we need
  // to know before we rebuild a stream frame whether there is an ACK in this
  // packet. If there is an ACK, we have to always encode the stream frame's
  // length. This forces the maybeClonedPacketIdentifier code to reconsider the
  // packet for ACK processing. We should always be able to write an ACK since
  // the min ACK frame size is 4, while 1500 MTU stream frame lengths are going
  // to be 2 bytes maximum.
  bool hasAckFrame = false;
  for (const auto& frame : packet.packet.frames) {
    if (frame.asWriteAckFrame()) {
      hasAckFrame = true;
      break;
    }
  }
  // The original had a TIMESTAMP right before its final STREAM frame so that
  // frame could omit its length. When the rebuilt frame omits it too, write a
  // fresh TIMESTAMP ahead of it, as long as both still fit; the STREAM frame
  // then still ends the packet.
  const auto maybeWriteTimestampAheadOf =
      [&](auto iter, const WriteStreamFrame& streamFrame)
      -> quic::Expected<void, QuicError> {
    if (iter == packet.packet.frames.cbegin() ||
        std::prev(iter)->asTimestampFrame() == nullptr ||
        !builder_.isTracking() || encryptionLevel != EncryptionLevel::AppData ||
        packet.packet.header.getHeaderForm() != HeaderForm::Short ||
        !shouldWriteOneRttTimestampFrame(conn_, false)) {
      return {};
    }
    auto timestampFrame = generateOneRttTimestampFrame(conn_);
    if (!timestampFrame) {
      return {};
    }
    auto timestampSize = getTimestampFrameEncodedSize(*timestampFrame);
    if (timestampSize.hasError()) {
      return quic::make_unexpected(timestampSize.error());
    }
    const auto remaining = packetBuilder.remainingSpaceInPkt();
    if (remaining < timestampSize.value()) {
      return {};
    }
    auto streamFits = completeStreamFrameFits(
        streamFrame, true, remaining - timestampSize.value());
    if (streamFits.hasError()) {
      return quic::make_unexpected(streamFits.error());
    }
    if (!streamFits.value()) {
      return {};
    }
    auto writeResult = writeFrame(*timestampFrame, packetBuilder);
    if (writeResult.hasError()) {
      return quic::make_unexpected(writeResult.error());
    }
    wroteTimestampFrame |= writeResult.value() != 0;
    return {};
  };
  for (auto iter = packet.packet.frames.cbegin();
       iter != packet.packet.frames.cend();
       iter++) {
    bool lastFrame = iter == packet.packet.frames.cend() - 1;
    const QuicWriteFrame& frame = *iter;
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame: {
        // We need to rebuild this WriteAckFrame with fresh AckStats
        // which may make the packet larger. We keep track of this
        // for now and rebuild the frame after the loop.
        shouldRebuildWriteAckFrame = true;
        continue;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        auto streamResult =
            conn_.streamManager->getStream(streamFrame.streamId);
        if (streamResult.hasError()) {
          MVVLOG(4) << "Failed to get stream " << streamFrame.streamId
                    << " for cloning WriteStreamFrame: "
                    << streamResult.error().message;
          // Propagate error
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (stream && retransmittable(*stream)) {
          if (stream->streamSendBuffer) {
            const bool skipLengthField =
                lastFrame && streamFrame.len != 0 && !hasAckFrame;
            const StreamSendBuffer::SendRange sendRange{
                .offset = streamFrame.offset,
                .len = streamFrame.len,
                .fin = streamFrame.fin};
            if (!stream->streamSendBuffer->isOutstanding(sendRange)) {
              writeSuccess = false;
              break;
            }
            if (skipLengthField) {
              auto timestampResult =
                  maybeWriteTimestampAheadOf(iter, streamFrame);
              if (timestampResult.hasError()) {
                return quic::make_unexpected(timestampResult.error());
              }
            }

            auto frameFits = completeStreamFrameFits(
                streamFrame,
                skipLengthField,
                packetBuilder.remainingSpaceInPkt());
            if (frameFits.hasError()) {
              return quic::make_unexpected(frameFits.error());
            }
            if (!frameFits.value()) {
              writeSuccess = false;
              break;
            }

            auto res = writeStreamFrameHeader(
                packetBuilder,
                streamFrame.streamId,
                streamFrame.offset,
                streamFrame.len,
                streamFrame.len,
                streamFrame.fin,
                skipLengthField);
            if (res.hasError()) {
              return quic::make_unexpected(res.error());
            }
            if (!res.value().has_value() || *res.value() != streamFrame.len) {
              writeSuccess = false;
              break;
            }

            const bool dataWritten = stream->streamSendBuffer->writeAt(
                streamFrame.offset,
                streamFrame.len,
                [&packetBuilder](ByteRange range) {
                  packetBuilder.push(range.data(), range.size());
                  return true;
                });
            MVCHECK(dataWritten);
            wroteLengthlessStreamFrame |= skipLengthField;
            notPureAck = true;
            writeSuccess = true;
            break;
          }

          auto streamData = cloneRetransmissionBuffer(streamFrame, stream);
          auto bufferLen = streamData ? streamData->chainLength() : 0;
          // It's safe to skip the length if it was the last frame in the
          // original packet and there's no ACK frame. Since we put the ACK
          // frame last we need to end the stream frame in that case.
          const bool skipLengthField = lastFrame && bufferLen && !hasAckFrame;
          if (skipLengthField && bufferLen == streamFrame.len) {
            auto timestampResult =
                maybeWriteTimestampAheadOf(iter, streamFrame);
            if (timestampResult.hasError()) {
              return quic::make_unexpected(timestampResult.error());
            }
          }
          auto res = writeStreamFrameHeader(
              packetBuilder,
              streamFrame.streamId,
              streamFrame.offset,
              bufferLen,
              bufferLen,
              streamFrame.fin,
              skipLengthField);
          if (res.hasError()) {
            MVVLOG(4) << "Failed to write stream frame header for cloning: "
                      << res.error().message;
            return quic::make_unexpected(res.error());
          }

          auto dataLen = *res;
          bool ret = dataLen.has_value() && *dataLen == streamFrame.len;
          if (ret) {
            // Writing 0 byte for stream data is legit if the stream frame has
            // FIN. That's checked in writeStreamFrameHeader.
            PROTO_OOPS_LOG_BUILDER_IF(
                conn_.nodeType == QuicNodeType::Server && !streamData &&
                    !streamFrame.fin,
                conn_.oopsLogger,
                proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
                "quic_packet_rebuilder",
                "invariant_violation: stream clone wrote no data without "
                "FIN");
            MVCHECK(streamData || streamFrame.fin);
            if (streamData) {
              writeStreamFrameData(packetBuilder, *streamData, *dataLen);
            }
            wroteLengthlessStreamFrame |= skipLengthField;
            notPureAck = true;
            writeSuccess = true;
            break;
          }
          writeSuccess = false;
          break;
        }
        // If a stream is already Closed, we should not clone and resend this
        // stream data. But should we abort the cloning of this packet and
        // move on to the next packet? I'm gonna err on the aggressive side
        // for now and call it success.
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& cryptoFrame = *frame.asWriteCryptoFrame();
        auto stream = getCryptoStream(*conn_.cryptoState, encryptionLevel);
        auto buf = cloneCryptoRetransmissionBuffer(cryptoFrame, *stream);

        // No crypto data found to be cloned, just skip
        if (!buf) {
          writeSuccess = true;
          break;
        }
        auto cryptoWriteResult =
            writeCryptoFrame(cryptoFrame.offset, *buf, packetBuilder);
        if (cryptoWriteResult.hasError()) {
          return quic::make_unexpected(cryptoWriteResult.error());
        }

        bool ret = cryptoWriteResult.value()->offset == cryptoFrame.offset &&
            cryptoWriteResult.value()->len == cryptoFrame.len;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        shouldWriteWindowUpdate = true;
        auto writeResult =
            writeFrame(generateMaxDataFrame(conn_), packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto streamResult =
            conn_.streamManager->getStream(maxStreamDataFrame.streamId);
        if (streamResult.hasError()) {
          MVVLOG(4) << "Failed to get stream " << maxStreamDataFrame.streamId
                    << " for cloning MaxStreamDataFrame: "
                    << streamResult.error().message;
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();

        if (!stream || !stream->shouldSendFlowControl()) {
          writeSuccess = true;
          break;
        }
        shouldWriteWindowUpdate = true;
        auto writeResult =
            writeFrame(generateMaxStreamDataFrame(*stream), packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        const PaddingFrame& paddingFrame = *frame.asPaddingFrame();
        auto writeResult = writeFrame(paddingFrame, packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        writeSuccess = writeResult.value() != 0;
        break;
      }
      case QuicWriteFrame::Type::PingFrame: {
        const PingFrame& pingFrame = *frame.asPingFrame();
        auto writeResult = writeFrame(pingFrame, packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        writeSuccess = writeResult.value() != 0;
        notPureAck |= writeSuccess;
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        auto updatedSimpleFrame = updateSimpleFrameOnPacketClone(
            conn_, packet.metadata.pathId, simpleFrame);
        if (!updatedSimpleFrame) {
          writeSuccess = true;
          break;
        }
        auto writeResult =
            writeSimpleFrame(std::move(*updatedSimpleFrame), packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame:
        // Datagram data is unreliable and not meaningful to clone.
        writeSuccess = true;
        break;
      case QuicWriteFrame::Type::TimestampFrame:
        // TIMESTAMP reflects send time, so the old value is never cloned. If
        // it sat right before the final STREAM frame, the STREAM case below
        // writes a fresh one there.
        writeSuccess = true;
        break;
      default: {
        auto writeResult = writeFrame(QuicWriteFrame(frame), packetBuilder);
        if (writeResult.hasError()) {
          return quic::make_unexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
    }
    if (!writeSuccess) {
      return std::nullopt;
    }
  }

  // If this packet had a WriteAckFrame, build a new one it with
  // fresh AckState on best-effort basis. If writing
  // that ACK fails, just ignore it and use the rest of the
  // cloned packet.
  if (shouldRebuildWriteAckFrame) {
    auto& packetHeader = packetBuilder.getPacketHeader();
    const AckState& ackState = getAckState(
        conn_,
        protectionTypeToPacketNumberSpace(packetHeader.getProtectionType()));
    AckScheduler ackScheduler(conn_, ackState);
    auto writeResult = ackScheduler.writeNextAcks(packetBuilder);
    if (writeResult.hasError()) {
      return quic::make_unexpected(writeResult.error());
    }
  }

  // We shouldn't clone if:
  // (1) we only end up cloning only acks, ping, or paddings.
  // (2) we should write window update, but didn't, and wrote nothing else.
  if (!notPureAck ||
      (shouldWriteWindowUpdate && !windowUpdateWritten && !writeSuccess)) {
    return std::nullopt;
  }

  // TIMESTAMP is non-retransmittable telemetry. Preserve rebuilt content first,
  // then generate a fresh TIMESTAMP from current policy if capacity remains.
  // Prioritized reserves only before stream/datagram scheduler output; it does
  // not displace clone contents on this path.
  if (builder_.isTracking() && !wroteLengthlessStreamFrame &&
      !wroteTimestampFrame && encryptionLevel == EncryptionLevel::AppData &&
      packet.packet.header.getHeaderForm() == HeaderForm::Short &&
      timestampPacketObserver_.matchesPacketSelection(
          conn_.transportSettings.oneRttTimestampFramePacketSelection) &&
      shouldWriteOneRttTimestampFrame(
          conn_, timestampPacketObserver_.hasAckReceiveTimestamps())) {
    if (auto timestampFrame = generateOneRttTimestampFrame(conn_)) {
      auto writeResult = writeFrame(*timestampFrame, packetBuilder);
      if (writeResult.hasError()) {
        return quic::make_unexpected(writeResult.error());
      }
    }
  }

  if (encryptionLevel == EncryptionLevel::Initial) {
    // Pad anything else that's left.
    while (packetBuilder.remainingSpaceInPkt() > 0) {
      auto writeResult = writeFrame(PaddingFrame(), packetBuilder);
      if (writeResult.hasError()) {
        return quic::make_unexpected(writeResult.error());
      }
    }
  }

  return cloneOutstandingPacket(packet);
}

const ChainedByteRangeHead* PacketRebuilder::cloneCryptoRetransmissionBuffer(
    const WriteCryptoFrame& frame,
    const QuicCryptoStream& stream) {
  /**
   * Crypto's StreamBuffer is removed from retransmissionBuffer in 2 cases.
   * 1: Packet containing the buffer gets acked.
   * 2: Packet containing the buffer is marked loss.
   * They have to be covered by making sure we do not clone an already acked or
   * lost packet.
   */
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && !frame.len,
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: empty crypto frame while cloning packet");
  MVDCHECK(frame.len, "WriteCryptoFrame cloning: frame is empty. " << conn_);
  auto iter = stream.retransmissionBuffer.find(frame.offset);

  // If the crypto stream is canceled somehow, just skip cloning this frame
  if (iter == stream.retransmissionBuffer.end()) {
    return nullptr;
  }
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          iter->second->offset != frame.offset,
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: crypto clone retransmission offset mismatch");
  MVDCHECK(
      iter->second->offset == frame.offset,
      "WriteCryptoFrame cloning: offset mismatch. " << conn_);
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          iter->second->data.chainLength() != frame.len,
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: crypto clone retransmission length mismatch");
  MVDCHECK(
      iter->second->data.chainLength() == frame.len,
      "WriteCryptoFrame cloning: Len mismatch. " << conn_);
  return &(iter->second->data);
}

const ChainedByteRangeHead* PacketRebuilder::cloneRetransmissionBuffer(
    const WriteStreamFrame& frame,
    const QuicStreamState* stream) {
  /**
   * StreamBuffer is removed from retransmissionBuffer in 3 cases.
   * 1: After send or receive RST.
   * 2: Packet containing the buffer gets acked.
   * 3: Packet containing the buffer is marked loss.
   *
   * Checking retransmittable() should cover first case. The latter three cases
   * have to be covered by making sure we do not clone an already acked, lost or
   * skipped packet.
   */
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && !stream,
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: missing stream while cloning stream frame");
  MVDCHECK(stream);
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && stream &&
          !retransmittable(*stream),
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_rebuilder",
      "invariant_violation: non-retransmittable stream while cloning stream "
      "frame");
  MVDCHECK(retransmittable(*stream));
  auto iter = stream->retransmissionBuffer.find(frame.offset);
  if (iter != stream->retransmissionBuffer.end()) {
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && frame.len &&
            iter->second->data.empty(),
        conn_.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
        "quic_packet_rebuilder",
        "invariant_violation: non-empty stream frame has empty "
        "retransmission data while cloning");
    MVDCHECK(
        !frame.len || !iter->second->data.empty(),
        "WriteStreamFrame cloning: frame is not empty but StreamBuffer has"
            << " empty data. " << conn_);
    return frame.len ? &(iter->second->data) : nullptr;
  }
  return nullptr;
}

} // namespace quic
