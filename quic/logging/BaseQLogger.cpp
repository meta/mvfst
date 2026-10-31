/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/String.h>
#include <quic/common/StringUtils.h>
#include <quic/logging/BaseQLogger.h>

namespace {
void addQuicSimpleFrameToEvent(
    quic::QLogPacketEvent* event,
    const quic::QuicSimpleFrame& simpleFrame) {
  switch (simpleFrame.type()) {
    case quic::QuicSimpleFrame::Type::StopSendingFrame: {
      const quic::StopSendingFrame& frame = *simpleFrame.asStopSendingFrame();
      event->frames.push_back(
          std::make_unique<quic::StopSendingFrameLog>(
              frame.streamId, frame.errorCode));
      break;
    }
    case quic::QuicSimpleFrame::Type::PathChallengeFrame: {
      const quic::PathChallengeFrame& frame =
          *simpleFrame.asPathChallengeFrame();
      event->frames.push_back(
          std::make_unique<quic::PathChallengeFrameLog>(frame.pathData));
      break;
    }
    case quic::QuicSimpleFrame::Type::PathResponseFrame: {
      const quic::PathResponseFrame& frame = *simpleFrame.asPathResponseFrame();
      event->frames.push_back(
          std::make_unique<quic::PathResponseFrameLog>(frame.pathData));
      break;
    }
    case quic::QuicSimpleFrame::Type::NewConnectionIdFrame: {
      const quic::NewConnectionIdFrame& frame =
          *simpleFrame.asNewConnectionIdFrame();
      event->frames.push_back(
          std::make_unique<quic::NewConnectionIdFrameLog>(
              frame.sequenceNumber, frame.token));
      break;
    }
    case quic::QuicSimpleFrame::Type::MaxStreamsFrame: {
      const quic::MaxStreamsFrame& frame = *simpleFrame.asMaxStreamsFrame();
      event->frames.push_back(
          std::make_unique<quic::MaxStreamsFrameLog>(
              frame.maxStreams, frame.isForBidirectional));
      break;
    }
    case quic::QuicSimpleFrame::Type::RetireConnectionIdFrame: {
      const quic::RetireConnectionIdFrame& frame =
          *simpleFrame.asRetireConnectionIdFrame();
      event->frames.push_back(
          std::make_unique<quic::RetireConnectionIdFrameLog>(
              frame.sequenceNumber));
      break;
    }
    case quic::QuicSimpleFrame::Type::HandshakeDoneFrame: {
      event->frames.push_back(std::make_unique<quic::HandshakeDoneFrameLog>());
      break;
    }
    case quic::QuicSimpleFrame::Type::KnobFrame: {
      const quic::KnobFrame& frame = *simpleFrame.asKnobFrame();
      event->frames.push_back(
          std::make_unique<quic::KnobFrameLog>(
              frame.knobSpace, frame.id, frame.blob->length()));
      break;
    }
    case quic::QuicSimpleFrame::Type::AckFrequencyFrame: {
      const quic::AckFrequencyFrame& frame = *simpleFrame.asAckFrequencyFrame();
      event->frames.push_back(
          std::make_unique<quic::AckFrequencyFrameLog>(
              frame.sequenceNumber,
              frame.packetTolerance,
              frame.updateMaxAckDelay,
              frame.reorderThreshold));
      break;
    }
    case quic::QuicSimpleFrame::Type::NewTokenFrame: {
      const quic::NewTokenFrame& frame = *simpleFrame.asNewTokenFrame();
      auto tokenHexStr = hexlify(frame.token->coalesce());
      event->frames.push_back(
          std::make_unique<quic::NewTokenFrameLog>(tokenHexStr));
      break;
    }
  }
}
} // namespace

namespace quic {

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEvent(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketReceived;
  const ShortHeader* shortHeader = regularPacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType =
        toQlogString(regularPacket.header.asLong()->getHeaderType()).str();
  }
  if (event->packetType != toString(LongHeader::Types::Retry)) {
    // A Retry packet does not include a packet number.
    event->packetNum = regularPacket.header.getPacketSequenceNum();
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::PaddingFrame: {
        numPaddingFrames += quicFrame.asPaddingFrame()->numFrames;
        break;
      }
      case QuicFrame::Type::RstStreamFrame: {
        const auto& frame = *quicFrame.asRstStreamFrame();
        event->frames.push_back(
            std::make_unique<RstStreamFrameLog>(
                frame.streamId, frame.errorCode, frame.finalSize));
        break;
      }
      case QuicFrame::Type::ConnectionCloseFrame: {
        const auto& frame = *quicFrame.asConnectionCloseFrame();
        event->frames.push_back(
            std::make_unique<ConnectionCloseFrameLog>(
                frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        break;
      }
      case QuicFrame::Type::MaxDataFrame: {
        const auto& frame = *quicFrame.asMaxDataFrame();
        event->frames.push_back(
            std::make_unique<MaxDataFrameLog>(frame.maximumData));
        break;
      }
      case QuicFrame::Type::MaxStreamDataFrame: {
        const auto& frame = *quicFrame.asMaxStreamDataFrame();
        event->frames.push_back(
            std::make_unique<MaxStreamDataFrameLog>(
                frame.streamId, frame.maximumData));
        break;
      }
      case QuicFrame::Type::DataBlockedFrame: {
        const auto& frame = *quicFrame.asDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        break;
      }
      case QuicFrame::Type::StreamDataBlockedFrame: {
        const auto& frame = *quicFrame.asStreamDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<StreamDataBlockedFrameLog>(
                frame.streamId, frame.dataLimit));
        break;
      }
      case QuicFrame::Type::StreamsBlockedFrame: {
        const auto& frame = *quicFrame.asStreamsBlockedFrame();
        event->frames.push_back(
            std::make_unique<StreamsBlockedFrameLog>(
                frame.streamLimit, frame.isForBidirectional));
        break;
      }
      case QuicFrame::Type::ReadAckFrame: {
        const auto& frame = *quicFrame.asReadAckFrame();
        event->frames.push_back(
            std::make_unique<ReadAckFrameLog>(
                frame.ackBlocks,
                frame.ackDelay,
                frame.frameType,
                frame.maybeLatestRecvdPacketTime,
                frame.maybeLatestRecvdPacketNum,
                frame.recvdPacketsTimestampRanges,
                frame.draft02RecvdPacketsTimestampRanges,
                frame.ecnECT0Count,
                frame.ecnECT1Count,
                frame.ecnCECount));
        break;
      }
      case QuicFrame::Type::ReadStreamFrame: {
        const auto& frame = *quicFrame.asReadStreamFrame();
        event->frames.push_back(
            std::make_unique<StreamFrameLog>(
                frame.streamId, frame.offset, frame.data->length(), frame.fin));
        break;
      }
      case QuicFrame::Type::ReadCryptoFrame: {
        const auto& frame = *quicFrame.asReadCryptoFrame();
        event->frames.push_back(
            std::make_unique<CryptoFrameLog>(
                frame.offset, frame.data->length()));
        break;
      }
      case QuicFrame::Type::ReadNewTokenFrame: {
        event->frames.push_back(std::make_unique<ReadNewTokenFrameLog>());
        break;
      }
      case QuicFrame::Type::PingFrame: {
        event->frames.push_back(std::make_unique<quic::PingFrameLog>());
        break;
      }
      case QuicFrame::Type::QuicSimpleFrame: {
        const auto& simpleFrame = *quicFrame.asQuicSimpleFrame();
        addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        break;
      }
      case QuicFrame::Type::NoopFrame: {
        break;
      }
      case QuicFrame::Type::DatagramFrame: {
        const auto& frame = *quicFrame.asDatagramFrame();
        event->frames.push_back(
            std::make_unique<quic::DatagramFrameLog>(frame.length));
        break;
      }
      case QuicFrame::Type::TimestampFrame: {
        const auto& frame = *quicFrame.asTimestampFrame();
        event->frames.push_back(
            std::make_unique<quic::TimestampFrameLog>(frame.timestamp));
        break;
      }
      case QuicFrame::Type::ImmediateAckFrame: {
        event->frames.push_back(std::make_unique<quic::ImmediateAckFrameLog>());
        break;
      }
    }
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEvent(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetNum = writePacket.header.getPacketSequenceNum();
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketSent;
  const ShortHeader* shortHeader = writePacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType =
        toQlogString(writePacket.header.asLong()->getHeaderType()).str();
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : writePacket.frames) {
    switch (quicFrame.type()) {
      case QuicWriteFrame::Type::PaddingFrame:
        numPaddingFrames += quicFrame.asPaddingFrame()->numFrames;
        break;
      case QuicWriteFrame::Type::RstStreamFrame: {
        const RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
        event->frames.push_back(
            std::make_unique<RstStreamFrameLog>(
                frame.streamId, frame.errorCode, frame.finalSize));
        break;
      }
      case QuicWriteFrame::Type::ConnectionCloseFrame: {
        const ConnectionCloseFrame& frame = *quicFrame.asConnectionCloseFrame();
        event->frames.push_back(
            std::make_unique<ConnectionCloseFrameLog>(
                frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        const MaxDataFrame& frame = *quicFrame.asMaxDataFrame();
        event->frames.push_back(
            std::make_unique<MaxDataFrameLog>(frame.maximumData));
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& frame = *quicFrame.asMaxStreamDataFrame();
        event->frames.push_back(
            std::make_unique<MaxStreamDataFrameLog>(
                frame.streamId, frame.maximumData));
        break;
      }
      case QuicWriteFrame::Type::StreamsBlockedFrame: {
        const StreamsBlockedFrame& frame = *quicFrame.asStreamsBlockedFrame();
        event->frames.push_back(
            std::make_unique<StreamsBlockedFrameLog>(
                frame.streamLimit, frame.isForBidirectional));
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame: {
        const DataBlockedFrame& frame = *quicFrame.asDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        const StreamDataBlockedFrame& frame =
            *quicFrame.asStreamDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<StreamDataBlockedFrameLog>(
                frame.streamId, frame.dataLimit));
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& frame = *quicFrame.asWriteAckFrame();
        event->frames.push_back(
            std::make_unique<WriteAckFrameLog>(
                frame.ackBlocks,
                frame.ackDelay,
                frame.frameType,
                frame.maybeLatestRecvdPacketTime,
                frame.maybeLatestRecvdPacketNum,
                frame.recvdPacketsTimestampRanges,
                frame.draft02RecvdPacketsTimestampRanges,
                frame.ecnECT0Count,
                frame.ecnECT1Count,
                frame.ecnCECount));
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& frame = *quicFrame.asWriteStreamFrame();
        event->frames.push_back(
            std::make_unique<StreamFrameLog>(
                frame.streamId, frame.offset, frame.len, frame.fin));
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& frame = *quicFrame.asWriteCryptoFrame();
        event->frames.push_back(
            std::make_unique<CryptoFrameLog>(frame.offset, frame.len));
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
        addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        break;
      }
      case QuicWriteFrame::Type::NoopFrame: {
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame: {
        // TODO
        break;
      }
      case QuicWriteFrame::Type::TimestampFrame: {
        const auto& frame = *quicFrame.asTimestampFrame();
        event->frames.push_back(
            std::make_unique<quic::TimestampFrameLog>(frame.timestamp));
        break;
      }
      case QuicWriteFrame::Type::ImmediateAckFrame: {
        event->frames.push_back(std::make_unique<quic::ImmediateAckFrameLog>());
        break;
      }
      case QuicWriteFrame::Type::PingFrame: {
        event->frames.push_back(std::make_unique<quic::PingFrameLog>());
        break;
      }
    }
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogVersionNegotiationEvent> BaseQLogger::createPacketEvent(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogVersionNegotiationEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kVersionNegotiationPacketType;
  event->versionLog = std::make_unique<VersionNegotiationLog>(
      VersionNegotiationLog(versionPacket.versions));
  return event;
}

std::unique_ptr<QLogRetryEvent> BaseQLogger::createPacketEvent(
    const RetryPacket& retryPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogRetryEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->tokenSize = retryPacket.header.getToken().size();
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = toQlogString(retryPacket.header.getHeaderType()).str();
  return event;
}

} // namespace quic
