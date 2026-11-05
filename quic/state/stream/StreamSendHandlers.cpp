/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/stream/StreamSendHandlers.h>

#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStreamFunctions.h>

#include <algorithm>

namespace quic {

namespace {

void checkClosedSendState(const QuicStreamState& stream) {
  if (stream.streamSendBuffer) {
    [[maybe_unused]] const auto pendingWriteBytes = stream.pendingWriteBytes();
    PROTO_OOPS_LOG_BUILDER_IF(
        stream.conn.nodeType == QuicNodeType::Server && pendingWriteBytes != 0,
        stream.conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
            .setStreamId(stream.id)
            .setErrorCode(
                static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
        "quic_stream_send_handlers",
        "closed send stream has pending writes");
    MVDCHECK_EQ(pendingWriteBytes, 0);

    PROTO_OOPS_LOG_BUILDER_IF(
        stream.conn.nodeType == QuicNodeType::Server && stream.hasLoss(),
        stream.conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
            .setStreamId(stream.id)
            .setErrorCode(
                static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
        "quic_stream_send_handlers",
        "closed send stream has lost data");
    MVDCHECK(!stream.hasLoss());

    [[maybe_unused]] const auto outstandingBytes =
        stream.streamSendBuffer->outstandingBytes();
    PROTO_OOPS_LOG_BUILDER_IF(
        stream.conn.nodeType == QuicNodeType::Server && outstandingBytes != 0,
        stream.conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
            .setStreamId(stream.id)
            .setErrorCode(
                static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
        "quic_stream_send_handlers",
        "closed send stream has outstanding data");
    MVDCHECK_EQ(outstandingBytes, 0);

    [[maybe_unused]] const bool hasUnackedBufferedFin =
        stream.streamSendBuffer->finBuffered() &&
        !stream.streamSendBuffer->finAcked();
    PROTO_OOPS_LOG_BUILDER_IF(
        stream.conn.nodeType == QuicNodeType::Server && hasUnackedBufferedFin,
        stream.conn.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
            .setStreamId(stream.id)
            .setErrorCode(
                static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
        "quic_stream_send_handlers",
        "closed send stream has unacknowledged buffered fin");
    MVDCHECK(!hasUnackedBufferedFin);
    return;
  }

  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          !stream.retransmissionBuffer.empty(),
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(
              static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
      "quic_stream_send_handlers",
      "closed send stream has retransmission data");
  MVDCHECK(stream.retransmissionBuffer.empty());
  PROTO_OOPS_LOG_BUILDER_IF(
      stream.conn.nodeType == QuicNodeType::Server &&
          !stream.pendingWrites.empty(),
      stream.conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
          .setStreamId(stream.id)
          .setErrorCode(
              static_cast<uint64_t>(TransportErrorCode::STREAM_STATE_ERROR)),
      "quic_stream_send_handlers",
      "closed send stream has pending writes");
  MVDCHECK(stream.pendingWrites.empty());
}

// Reports the parts of [start, end] that `covered` does not include, with
// inclusive bounds like IntervalSet (unlike StreamSendBuffer's half-open
// ranges).
template <typename IntervalSetT, typename Fn>
void forEachUncoveredRange(
    const IntervalSetT& covered,
    uint64_t start,
    uint64_t end,
    Fn&& fn) {
  auto nextOffset = start;
  auto it = std::lower_bound(
      covered.begin(),
      covered.end(),
      start,
      [](const auto& interval, uint64_t offset) {
        return interval.end < offset;
      });
  for (; it != covered.end() && it->start <= end && nextOffset <= end; ++it) {
    if (it->start > nextOffset) {
      fn(nextOffset, it->start - 1);
    }
    nextOffset = std::max(nextOffset, it->end + 1);
  }
  if (nextOffset <= end) {
    fn(nextOffset, end);
  }
}

void recordNewlyDelivered(
    StreamFrameAckDelivery* delivery,
    uint64_t start,
    uint64_t end) {
  if (delivery) {
    delivery->newlyDeliveredIntervals.emplace_back(start, end);
  }
}

} // namespace

/**
 *  Welcome to the send state machine, we got fun and games.
 *
 * This is a simplified version of the send state machine defined in the
 * transport specification.  The "Invalid" state is used for unidirectional
 * streams that do not have that half (eg: an ingress uni stream is in send
 * state Invalid)
 *
 * Send State Machine
 * ==================
 *
 * [ Initial State ]
 *      |
 *      | Send Stream
 *      |
 *      v
 * Send::Open ------------------------------+
 *      |                                   |
 *      | Ack all bytes                     |
 *      | till FIN                          | Send RST
 *      |                                   |
 *      v                                   v
 * Send::Closed <---------------------- ResetSent
 *               RST ACKed and all bytes
 *               till smallest ACKed
 *               reliable reset offset
 *               ACKed.
 *
 */
quic::Expected<void, QuicError> sendStopSendingSMHandler(
    QuicStreamState& stream,
    const StopSendingFrame& frame) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      PROTO_OOPS_LOG_BUILDER_IF(
          stream.conn.nodeType == QuicNodeType::Server &&
              !isBidirectionalStream(stream.id) &&
              !isSendingStream(stream.conn.nodeType, stream.id),
          stream.conn.oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
              .setStreamId(stream.id)
              .setErrorCode(
                  static_cast<uint64_t>(
                      TransportErrorCode::STREAM_STATE_ERROR)),
          "quic_stream_send_handlers",
          "invalid send stream direction");
      MVCHECK(
          isBidirectionalStream(stream.id) ||
          isSendingStream(stream.conn.nodeType, stream.id));
      if (stream.conn.nodeType == QuicNodeType::Server &&
          !stream.finalWriteOffset &&
          getSendStreamFlowControlBytesWire(stream) == 0) {
        MVVLOG(3) << "Client gives up a flow control blocked stream";
      }
      stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
      break;
    }
    case StreamSendState::Closed: {
      break;
    }
    case StreamSendState::ResetSent: {
      if (stream.reliableSizeToPeer) {
        // The app may still drop the reliable bytes with a plain reset.
        stream.conn.streamManager->addStopSending(stream.id, frame.errorCode);
      }
      break;
    }
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendRstSMHandler(
    QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    const Optional<uint64_t>& reliableSize) {
  switch (stream.sendState) {
    case StreamSendState::Open: {
      stream.appErrorCodeToPeer = errorCode;
      auto resetResult = resetQuicStream(stream, errorCode, reliableSize);
      if (!resetResult.has_value()) {
        return resetResult;
      }
      appendPendingStreamReset(stream.conn, stream, errorCode, reliableSize);
      stream.sendState = StreamSendState::ResetSent;
      break;
    }
    case StreamSendState::Closed: {
      MVVLOG(4) << "Ignoring SendReset from closed state.";
      break;
    }
    case StreamSendState::ResetSent: {
      // A subsequent reset may only reduce the reliable size and must keep the
      // error code. Higher-level functions check this, so we CHECK here.
      uint64_t newReliableSize = reliableSize.value_or(0);
      uint64_t prevReliableSize = stream.reliableSizeToPeer.value_or(0);
      PROTO_OOPS_LOG_BUILDER_IF(
          stream.conn.nodeType == QuicNodeType::Server &&
              newReliableSize > prevReliableSize,
          stream.conn.oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
              .setStreamId(stream.id)
              .setErrorCode(
                  static_cast<uint64_t>(
                      TransportErrorCode::STREAM_STATE_ERROR)),
          "quic_stream_send_handlers",
          "reliable reset size increased");
      MVCHECK_LE(
          newReliableSize,
          prevReliableSize,
          "It is illegal to increase the reliable size");
      PROTO_OOPS_LOG_BUILDER_IF(
          stream.conn.nodeType == QuicNodeType::Server &&
              stream.appErrorCodeToPeer &&
              *stream.appErrorCodeToPeer != errorCode,
          stream.conn.oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
              .setStreamId(stream.id)
              .setErrorCode(
                  static_cast<uint64_t>(
                      TransportErrorCode::STREAM_STATE_ERROR)),
          "quic_stream_send_handlers",
          "reset application error code changed");
      MVCHECK(
          !stream.appErrorCodeToPeer || *stream.appErrorCodeToPeer == errorCode,
          "Cannot change application error code in a reset");
      if (newReliableSize == prevReliableSize) {
        break;
      }
      auto resetResult = resetQuicStream(stream, errorCode, reliableSize);
      if (!resetResult.has_value()) {
        return resetResult;
      }
      appendPendingStreamReset(stream.conn, stream, errorCode, reliableSize);
      break;
    }
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendAckSMHandler(
    QuicStreamState& stream,
    const WriteStreamFrame& ackedFrame) {
  // Mark the frame handled only where this stream does its delivery
  // bookkeeping, so ACK processing can tell a frame the stream accounted for,
  // even one whose bytes were already delivered, from one it rejected.
  auto* delivery = stream.conn.streamFrameAckDelivery;
  const auto markHandled = [delivery] {
    if (delivery) {
      delivery->handled = true;
    }
  };
  if (stream.streamSendBuffer && stream.sendState != StreamSendState::Invalid) {
    markHandled();
    const bool hadLoss = stream.hasLoss();
    auto ackResult = stream.streamSendBuffer->markAcked(
        {.offset = ackedFrame.offset,
         .len = ackedFrame.len,
         .fin = ackedFrame.fin},
        // markAcked() reports half-open [begin, end); delivery intervals are
        // inclusive.
        [delivery](uint64_t begin, uint64_t end) {
          recordNewlyDelivered(delivery, begin, end - 1);
        });
    if (!ackResult) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          "Failed to update unified stream send buffer ACK state"));
    }

    stream.conn.streamManager->addDeliverable(stream.id);

    const bool allReliableDataDelivered = stream.minReliableSizeAcked &&
        (*stream.minReliableSizeAcked == 0 ||
         stream.allBytesAckedTill(*stream.minReliableSizeAcked - 1));
    if (allBytesTillFinAcked(stream) || allReliableDataDelivered) {
      stream.sendState = StreamSendState::Closed;
      if (stream.inTerminalStates()) {
        stream.conn.streamManager->addClosed(stream.id);
      }
    }
    if (hadLoss && !stream.hasLoss()) {
      stream.conn.streamManager->updateWritableStreams(stream);
    }
    if (stream.sendState == StreamSendState::Closed) {
      checkClosedSendState(stream);
    }
    return {};
  }

  switch (stream.sendState) {
    case StreamSendState::Open:
    case StreamSendState::ResetSent: {
      markHandled();
      // Clean up the acked buffers from the retransmissionBuffer.
      auto ackedBuffer = stream.retransmissionBuffer.find(ackedFrame.offset);
      if (ackedBuffer != stream.retransmissionBuffer.end()) {
        uint64_t expectedLen = ackedFrame.len;
        bool expectedFin = ackedFrame.fin;
        if (stream.sendState == StreamSendState::ResetSent &&
            stream.reliableSizeToPeer &&
            ackedFrame.offset + ackedFrame.len > *stream.reliableSizeToPeer) {
          expectedLen = *stream.reliableSizeToPeer - ackedFrame.offset;
          expectedFin = false;
        }
        PROTO_OOPS_LOG_BUILDER_IF(
            stream.conn.nodeType == QuicNodeType::Server &&
                ackedFrame.offset != ackedBuffer->second->offset,
            stream.conn.oopsLogger,
            proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
                .setStreamId(stream.id)
                .setErrorCode(
                    static_cast<uint64_t>(
                        TransportErrorCode::STREAM_STATE_ERROR)),
            "quic_stream_send_handlers",
            "acked stream offset mismatch");
        MVCHECK_EQ(ackedFrame.offset, ackedBuffer->second->offset);
        PROTO_OOPS_LOG_BUILDER_IF(
            stream.conn.nodeType == QuicNodeType::Server &&
                expectedLen != ackedBuffer->second->data.chainLength(),
            stream.conn.oopsLogger,
            proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
                .setStreamId(stream.id)
                .setErrorCode(
                    static_cast<uint64_t>(
                        TransportErrorCode::STREAM_STATE_ERROR)),
            "quic_stream_send_handlers",
            "acked stream length mismatch");
        MVCHECK_EQ(expectedLen, ackedBuffer->second->data.chainLength());
        PROTO_OOPS_LOG_BUILDER_IF(
            stream.conn.nodeType == QuicNodeType::Server &&
                expectedFin != ackedBuffer->second->eof,
            stream.conn.oopsLogger,
            proto_oops::makeConnectionSpecificOopsFieldsBuilder(stream.conn)
                .setStreamId(stream.id)
                .setErrorCode(
                    static_cast<uint64_t>(
                        TransportErrorCode::STREAM_STATE_ERROR)),
            "quic_stream_send_handlers",
            "acked stream fin mismatch");
        MVCHECK_EQ(expectedFin, ackedBuffer->second->eof);
        MVVLOG(10) << "Open: acked stream data stream=" << stream.id
                   << " offset=" << ackedBuffer->second->offset
                   << " len=" << ackedBuffer->second->data.chainLength()
                   << " eof=" << ackedBuffer->second->eof << " " << stream.conn;
        if (const auto len = ackedBuffer->second->data.chainLength()) {
          const auto start = ackedBuffer->second->offset;
          forEachUncoveredRange(
              stream.ackedIntervals,
              start,
              start + len - 1,
              [delivery](uint64_t newlyStart, uint64_t newlyEnd) {
                recordNewlyDelivered(delivery, newlyStart, newlyEnd);
              });
        }
        auto updateResult = stream.updateAckedIntervals(
            ackedBuffer->second->offset,
            ackedBuffer->second->data.chainLength(),
            ackedBuffer->second->eof);
        if (!updateResult.has_value()) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "Failed to update acked intervals"));
        }
        stream.retransmissionBuffer.erase(ackedBuffer);
      }

      // This stream may be able to invoke some deliveryCallbacks:
      stream.conn.streamManager->addDeliverable(stream.id);

      // Check for whether or not we have ACKed all bytes until our FIN or,
      // in the case that we've sent a Reset, until the minimum reliable size of
      // some reset acked by the peer.
      bool allReliableDataDelivered =
          (stream.minReliableSizeAcked &&
           (*stream.minReliableSizeAcked == 0 ||
            stream.allBytesAckedTill(*stream.minReliableSizeAcked - 1)));
      if (allBytesTillFinAcked(stream) || allReliableDataDelivered) {
        stream.sendState = StreamSendState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed: {
      markHandled();
      checkClosedSendState(stream);
      break;
    }
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

quic::Expected<void, QuicError> sendRstAckSMHandler(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize) {
  switch (stream.sendState) {
    case StreamSendState::ResetSent: {
      MVVLOG(10) << "ResetSent: Transition to closed stream=" << stream.id
                 << " " << stream.conn;
      // Note that we set minReliableSizeAcked to 0 for non-reliable resets.
      if (!stream.minReliableSizeAcked.has_value()) {
        stream.minReliableSizeAcked = reliableSize.value_or(0);
      } else {
        stream.minReliableSizeAcked =
            std::min(*stream.minReliableSizeAcked, reliableSize.value_or(0));
      }

      if (*stream.minReliableSizeAcked == 0 ||
          stream.allBytesAckedTill(*stream.minReliableSizeAcked - 1)) {
        // We can only transition to Closed if we have successfully delivered
        // all reliable data in some reset that was ACKed by the peer.
        stream.sendState = StreamSendState::Closed;
        if (stream.inTerminalStates()) {
          stream.conn.streamManager->addClosed(stream.id);
        }
      }
      break;
    }
    case StreamSendState::Closed: {
      // Just discard the ack if we are already in Closed state.
      break;
    }
    case StreamSendState::Open:
    case StreamSendState::Invalid: {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::STREAM_STATE_ERROR,
          fmt::format(
              "Invalid transition from state={}",
              streamStateToString(stream.sendState))));
    }
  }
  return {};
}

} // namespace quic
