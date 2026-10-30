/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/stream/StreamStateFunctions.h>

#include <quic/flowcontrol/QuicFlowController.h>

namespace quic {
quic::Expected<void, QuicError> resetQuicStream(
    QuicStreamState& stream,
    ApplicationErrorCode error,
    Optional<uint64_t> reliableSize) {
  auto updateResult = updateFlowControlOnResetStream(stream, reliableSize);
  if (!updateResult) {
    return quic::make_unexpected(updateResult.error());
  }

  if (reliableSize && *reliableSize > 0) {
    stream.reliableSizeToPeer = *reliableSize;
    if (stream.streamSendBuffer) {
      if (!stream.streamSendBuffer->truncateFrom(*reliableSize)) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::INTERNAL_ERROR,
            "Failed to truncate unified stream send buffer on reset"));
      }
    } else {
      stream.removeFromRetransmissionBufStartingAtOffset(*reliableSize);
      stream.removeFromWriteBufStartingAtOffset(*reliableSize);
      stream.removeFromPendingWritesStartingAtOffset(*reliableSize);
      stream.removeFromLossBufStartingAtOffset(*reliableSize);
    }
    stream.streamWriteError = error;
  } else {
    stream.reliableSizeToPeer = std::nullopt;
    if (stream.streamSendBuffer) {
      stream.streamSendBuffer->cancelAll();
    } else {
      stream.retransmissionBuffer.clear();
      stream.writeBuffer.move();
      stream.pendingWrites = ChainedByteRangeHead();
      stream.lossBuffer.clear();
    }
    stream.streamWriteError = error;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
  stream.conn.streamManager->removeLoss(stream.id);

  return {};
}

quic::Expected<void, QuicError> onResetQuicStream(
    QuicStreamState& stream,
    const RstStreamFrame& frame) {
  if (stream.finalReadOffset &&
      stream.finalReadOffset.value() != frame.finalSize) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Read offset mismatch, " +
            fmt::format(
                "{} != {}", stream.finalReadOffset.value(), frame.finalSize)));
  }
  if (stream.streamReadError &&
      stream.streamReadError.value().asApplicationErrorCode() &&
      *stream.streamReadError.value().asApplicationErrorCode() !=
          frame.errorCode) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::STREAM_STATE_ERROR,
        "Reset error code mismatch, " +
            toString(stream.streamReadError.value()) +
            " != " + toString(frame.errorCode)));
  }
  if (stream.reliableSizeFromPeer && frame.reliableSize &&
      *frame.reliableSize > *stream.reliableSizeFromPeer) {
    // It is legal to send a RESET_STREAM_AT frame with a lower offset
    // than before, but not to send one with a higher offset than before. Due
    // to reordering, we may receive a RESET_STREAM_AT frame with a higher
    // offset than before. In this case, we should ignore the frame.
    return {};
  }

  stream.reliableSizeFromPeer =
      frame.reliableSize.has_value() ? *frame.reliableSize : 0;
  // Mark eofoffset:
  if (stream.maxOffsetObserved > frame.finalSize) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::FINAL_SIZE_ERROR, "Reset in middle of stream"));
  }
  // Drop non-reliable data:
  const auto rangesBefore = stream.readBuffer.size();
  stream.removeFromReadBufferStartingAtOffset(*stream.reliableSizeFromPeer);
  stream.conn.streamManager->updateReadBufferRanges(
      rangesBefore, stream.readBuffer.size());
  stream.finalReadOffset = frame.finalSize;
  stream.streamReadError = frame.errorCode;
  // If the currentReadOffset > finalReadOffset we have already processed
  // all the bytes until FIN, so we don't need to do anything for the read
  // side of the flow controller.
  bool appReadAllBytes = stream.currentReadOffset > *stream.finalReadOffset;
  // We don't grant flow control until we've received all reliable bytes,
  // because we could still buffer additional data in the QUIC layer.
  bool allReliableBytesReceived = !frame.reliableSize ||
      *frame.reliableSize == 0 ||
      isAllDataReceivedUntil(stream, *frame.reliableSize - 1);
  if (!appReadAllBytes && allReliableBytesReceived) {
    auto flowControlResult = updateFlowControlOnStreamData(
        stream, stream.maxOffsetObserved, frame.finalSize);
    if (!flowControlResult) {
      return quic::make_unexpected(flowControlResult.error());
    }
    stream.maxOffsetObserved = frame.finalSize;
    auto result = updateFlowControlOnReceiveReset(stream, Clock::now());
    if (!result) {
      return quic::make_unexpected(result.error());
    }
  } else if (appReadAllBytes) {
    auto result = endManualReadFlowControl(stream, Clock::now());
    if (!result) {
      return quic::make_unexpected(result.error());
    }
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updateWritableStreams(stream);
  QUIC_STATS(stream.conn.statsCallback, onQuicStreamReset, frame.errorCode);
  return {};
}

bool isAllDataReceived(const QuicStreamState& stream) {
  bool receivedDataTillFin = false;
  // Check if we have read everything till (inclusive) EOF
  if (stream.finalReadOffset &&
      *stream.finalReadOffset <= stream.currentReadOffset) {
    // this is the case that the last StreamFrame has FIN and no data.
    receivedDataTillFin = true;
  } else if (
      stream.finalReadOffset && stream.readBuffer.size() == 1 &&
      stream.currentReadOffset == stream.readBuffer.front().offset &&
      (stream.readBuffer.front().offset +
           stream.readBuffer.front().data.chainLength() ==
       stream.finalReadOffset)) {
    receivedDataTillFin = true;
  }
  return receivedDataTillFin;
}

bool isAllDataReceivedUntil(const QuicStreamState& stream, uint64_t offset) {
  if (stream.currentReadOffset > offset) {
    // The application has already read all the data until offset.
    return true;
  }

  // stream.currentReadOffset - 1 represents the offset that the application
  // has read until. stream.readBuffer.front().offset represents the lowest
  // offset of the data buffered by the QUIC layer. If
  // stream.currentReadOffset < stream.readBuffer.front().offset, then that
  // means that there is a "gap" in the data. i.e. the application hasn't read
  // the data within the gap AND the QUIC layer doesn't have the gap data
  // buffered either, so we should return false.
  if (!stream.readBuffer.empty() &&
      stream.currentReadOffset == stream.readBuffer.front().offset &&
      stream.readBuffer.front().offset +
              stream.readBuffer.front().data.chainLength() >
          offset) {
    // The application hasn't read all of the data until offset, but the
    // data that hasn't been read yet by the application has been
    // buffered by the QUIC layer.
    return true;
  }

  return false;
}

quic::Expected<void, QuicError> retireIngress(QuicStreamState& stream) {
  stream.markIngressRetired();
  stream.conn.streamManager->updateReadBufferRanges(
      stream.readBuffer.size(), 0);
  stream.readBuffer.clear();
  auto releaseResult = endManualReadFlowControl(stream, Clock::now());
  if (!releaseResult.has_value()) {
    return releaseResult;
  }
  auto closeResult = maybeCloseRetiredIngress(stream);
  if (!closeResult.has_value()) {
    return closeResult;
  }
  auto& streamManager = *MVCHECK_NOTNULL(stream.conn.streamManager.get());
  streamManager.updateReadableStreams(stream);
  streamManager.updatePeekableStreams(stream);
  return {};
}

quic::Expected<void, QuicError> maybeCloseRetiredIngress(
    QuicStreamState& stream) {
  if (!stream.finalReadOffset) {
    return {};
  }
  const auto finalSize = *stream.finalReadOffset;
  if (stream.maxOffsetObserved < finalSize) {
    // Only a reliable reset whose reliable bytes have not arrived leaves the
    // final size unaccounted.
    auto flowControlResult = updateFlowControlOnStreamData(
        stream, stream.maxOffsetObserved, finalSize);
    if (!flowControlResult.has_value()) {
      return flowControlResult;
    }
    stream.maxOffsetObserved = finalSize;
  }
  // Close before crediting the discarded bytes, so that no stream window
  // update is queued for a stream we no longer read.
  stream.recvState = StreamRecvState::Closed;
  if (stream.currentReadOffset < finalSize) {
    const auto lastReadOffset = stream.currentReadOffset;
    stream.currentReadOffset = finalSize;
    auto flowControlResult =
        updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
    if (!flowControlResult.has_value()) {
      return flowControlResult;
    }
  }
  if (!stream.streamReadError && stream.currentReadOffset == finalSize) {
    // Consume the FIN as well, so that retired ingress delivers no EOF.
    stream.currentReadOffset = finalSize + 1;
  }
  if (stream.inTerminalStates()) {
    MVCHECK_NOTNULL(stream.conn.streamManager.get())->addClosed(stream.id);
  }
  return {};
}
} // namespace quic
