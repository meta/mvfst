/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstLogging.h>
#include <quic/mvfst-config.h>

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/common/IntervalSet.h>
#include <quic/priority/PriorityQueue.h>
#include <quic/state/StreamSendBuffer.h>

namespace quic {

struct StreamBuffer {
  BufQueue data;
  uint64_t offset;
  bool eof{false};

  StreamBuffer(BufPtr dataIn, uint64_t offsetIn, bool eofIn = false) noexcept
      : data(std::move(dataIn)), offset(offsetIn), eof(eofIn) {}

  StreamBuffer(StreamBuffer&& other) noexcept = default;
  StreamBuffer& operator=(StreamBuffer&& other) noexcept = default;
};

struct WriteStreamBuffer {
  ChainedByteRangeHead data;
  uint64_t offset;
  bool eof{false};

  WriteStreamBuffer(
      ChainedByteRangeHead&& dataIn,
      uint64_t offsetIn,
      bool eofIn = false) noexcept
      : data(std::move(dataIn)), offset(offsetIn), eof(eofIn) {}

  WriteStreamBuffer(WriteStreamBuffer&& other) noexcept
      : data(std::move(other.data)), offset(other.offset), eof(other.eof) {}

  WriteStreamBuffer& operator=(WriteStreamBuffer&& other) noexcept {
    data = std::move(other.data);
    offset = other.offset;
    eof = other.eof;
    return *this;
  }
};

struct QuicStreamLike {
  QuicStreamLike() = default;

  QuicStreamLike(QuicStreamLike&&) = default;

  virtual ~QuicStreamLike() = default;

  // List of bytes that have been read and buffered. We need to buffer
  // bytes in case we get bytes out of order.
  CircularDeque<StreamBuffer> readBuffer;

  // List of bytes that have been written to the QUIC layer.
  uint64_t writeBufferStartOffset{0};
  BufQueue writeBuffer{};
  ChainedByteRangeHead pendingWrites{};

  // Stores a map of offset:buffers which have been written to the socket and
  // are currently un-acked. Each one represents one StreamFrame that was
  // written. We need to buffer these because these might be retransmitted in
  // the future. These are associated with the starting offset of the buffer.
  UnorderedMap<uint64_t, std::unique_ptr<WriteStreamBuffer>>
      retransmissionBuffer;

  // Tracks intervals which we have received ACKs for. E.g. in the case of all
  // data being acked this would contain one internval from 0 -> the largest
  // offset ACKed. This allows us to track which delivery callbacks can be
  // called.
  template <class T>
  using IntervalSetVec = SmallVec<T, 3>;
  using AckedIntervals = IntervalSet<uint64_t, 1, IntervalSetVec>;
  AckedIntervals ackedIntervals;

  // Stores a list of buffers which have been marked as loss by loss detector.
  // Each one represents one StreamFrame that was written.
  CircularDeque<WriteStreamBuffer> lossBuffer;

  // Current offset of the start bytes in the pending writes chain.
  // This changes when we pop stuff off the pendingWrites chain.
  // When we are finished writing out all the bytes until FIN, this will be
  // one greater than finalWriteOffset.
  uint64_t currentWriteOffset{0};

  // the minimum offset requires retransmit
  uint64_t minimumRetransmittableOffset{0};

  // Offset of the next expected bytes that we need to read from
  // the read buffer.
  uint64_t currentReadOffset{0};

  // the smallest data offset that we expect the peer to send.
  uint64_t currentReceiveOffset{0};

  // Maximum byte offset observed on the stream.
  uint64_t maxOffsetObserved{0};

  // If an EOF is observed on the stream, the position of the EOF. It could be
  // either from FIN or RST. Right now we use one value to represent both FIN
  // and RST. We may split write EOF into two values in the future.
  // Read side eof offset.
  Optional<uint64_t> finalReadOffset;

  // This is set if we send a RELIABLE_RESET_STREAM frame to the peer. If we
  // subsequently send a RESET_STREAM frame, we reset this value to
  // std::nullopt.
  Optional<uint64_t> reliableSizeToPeer;

  // When the application calls updateReliableDeliveryCheckpoint() on the
  // QuicSocket, this is set to the size of the data written to the QuicSocket
  // so far. This includes data buffered in the QUIC layer that hasn't yet been
  // written out to the wire.
  uint64_t reliableResetCheckpoint{0};

  // This is set if we get a RESET_STREAM_AT or RESET_STREAM frame from the
  // peer. If we get a RESET_STREAM_AT frame, we set this value to the reliable
  // size in that frame. If we get a RESET_STREAM frame, we set this value to 0.
  Optional<uint64_t> reliableSizeFromPeer;

  // This is used in order to determine whether we can transition the send state
  // from ResetSent to Closed. Is 0 if a RESET_STREAM without a reliable size
  // has been ACKed.
  Optional<uint64_t> minReliableSizeAcked;

  // This is set if we send a RESET_STREAM or RELIABLE_RESET_STREAM frame to
  // the peer. We store this in order to ensure that we use the same value of
  // the application error code for all resets we send to the peer, as mandated
  // by the spec.
  Optional<ApplicationErrorCode> appErrorCodeToPeer;

  // Current cumulative number of packets sent for this stream. It only counts
  // egress packets that contains a *new* STREAM frame for this stream.
  uint64_t numPacketsTxWithNewData{0};

  // whether application has requested peer to stop_sending
  bool stopSendingRequested{false};

  [[nodiscard]] Expected<void, IntervalSetError>
  updateAckedIntervals(uint64_t offset, uint64_t len, bool eof) {
    // When there's an EOF we count the byte of 1 past the end as having been
    // ACKed, since this is useful for delivery APIs.
    int lenAdjustment = [eof]() {
      if (eof) {
        return 0;
      } else {
        return 1;
      }
    }();
    if (lenAdjustment && len == 0) {
      MVCHECK(false, "ACK for empty stream frame with no fin.");
    }
    return ackedIntervals.tryInsert(offset, offset + len - lenAdjustment);
  }

  /*
   * Either insert a new entry into the loss buffer, or merge the buffer with
   * an existing entry.
   */
  void insertIntoLossBuffer(std::unique_ptr<WriteStreamBuffer> buf) {
    // We assume here that we won't try to insert an overlapping buffer, as
    // that should never happen in the loss buffer.
    auto lossItr = std::upper_bound(
        lossBuffer.begin(),
        lossBuffer.end(),
        buf->offset,
        [](auto offset, const auto& buffer) { return offset < buffer.offset; });
    if (!lossBuffer.empty() && lossItr != lossBuffer.begin() &&
        std::prev(lossItr)->offset + std::prev(lossItr)->data.chainLength() ==
            buf->offset) {
      std::prev(lossItr)->data.append(std::move(buf->data));
      std::prev(lossItr)->eof = buf->eof;
    } else {
      lossBuffer.emplace(lossItr, std::move(*buf));
    }
  }

  void removeFromLossBuffer(uint64_t offset, size_t len, bool eof) {
    if (lossBuffer.empty() || len == 0) {
      // Nothing to do.
      return;
    }
    auto lossItr = lossBuffer.begin();
    for (; lossItr != lossBuffer.end(); lossItr++) {
      uint64_t lossStartOffset = lossItr->offset;
      uint64_t lossEndOffset = lossItr->offset + lossItr->data.chainLength();
      uint64_t removedStartOffset = offset;
      uint64_t removedEndOffset = offset + len;
      if (lossStartOffset > removedEndOffset) {
        return;
      }
      // There's two cases. If the removed offset lies within the existing
      // StreamBuffer then we need to potentially split it and remove that
      // section. The other case is that the existing StreamBuffer is completely
      // accounted for by the removed section, in which case it will be removed.
      // Note that this split/trim logic relies on the fact that insertion into
      // the loss buffer will merge contiguous elements, thus allowing us to
      // make these assumptions.
      if ((removedStartOffset >= lossStartOffset &&
           removedEndOffset <= lossEndOffset) ||
          (lossStartOffset >= removedStartOffset &&
           lossEndOffset <= removedEndOffset)) {
        size_t amountToSplit = removedStartOffset > lossStartOffset
            ? static_cast<size_t>(removedStartOffset - lossStartOffset)
            : 0;
        ChainedByteRangeHead splitBuf;
        if (amountToSplit > 0) {
          splitBuf = lossItr->data.splitAtMost(amountToSplit);
          lossItr->offset += amountToSplit;
        }
        lossItr->offset += lossItr->data.trimStartAtMost(len);
        if (lossItr->data.empty() && lossItr->eof == eof) {
          lossBuffer.erase(lossItr);
        }
        if (!splitBuf.empty()) {
          insertIntoLossBuffer(
              std::make_unique<WriteStreamBuffer>(
                  std::move(splitBuf), lossStartOffset, false));
        }
        return;
      }
    }
  }

  void removeFromLossBufStartingAtOffset(uint64_t startingOffset) {
    while (!lossBuffer.empty()) {
      auto& lastElement = lossBuffer.back();
      if (lastElement.offset >= startingOffset) {
        lossBuffer.pop_back();
      } else if (
          lastElement.offset + lastElement.data.chainLength() >=
          startingOffset) {
        if (lastElement.offset + lastElement.data.chainLength() >
            startingOffset) {
          lastElement.eof = false;
        }
        lastElement.data = lastElement.data.splitAtMost(
            size_t(startingOffset - lastElement.offset));
        return;
      } else {
        return;
      }
    }
  }

  void removeFromRetransmissionBufStartingAtOffset(uint64_t startingOffset) {
    UnorderedSet<uint64_t> offsetsToRemove;

    for (auto& [offset, buf] : retransmissionBuffer) {
      if (offset >= startingOffset) {
        offsetsToRemove.insert(offset);
      } else if (offset + buf->data.chainLength() >= startingOffset) {
        if (offset + buf->data.chainLength() > startingOffset) {
          buf->eof = false;
        }
        buf->data = buf->data.splitAtMost(size_t(startingOffset - offset));
      }
    }

    for (auto offset : offsetsToRemove) {
      retransmissionBuffer.erase(offset);
    }
  }

  void removeFromWriteBufStartingAtOffset(uint64_t startingOffset) {
    if (writeBuffer.empty() ||
        writeBufferStartOffset + writeBuffer.chainLength() <= startingOffset) {
      return;
    }

    if (startingOffset > writeBufferStartOffset) {
      writeBuffer = writeBuffer.splitAtMost(
          size_t(startingOffset - writeBufferStartOffset));
    } else {
      // Equivalent to clearing out the writeBuffer
      writeBuffer.splitAtMost(writeBuffer.chainLength());
    }
  }

  void removeFromPendingWritesStartingAtOffset(uint64_t startingOffset) {
    if (pendingWrites.empty() ||
        currentWriteOffset + pendingWrites.chainLength() <= startingOffset) {
      return;
    }

    if (startingOffset > currentWriteOffset) {
      pendingWrites = pendingWrites.splitAtMost(
          size_t(startingOffset - currentWriteOffset));
    } else {
      // Equivalent to clearing out the pendingWrites
      pendingWrites.splitAtMost(pendingWrites.chainLength());
    }
  }

  [[nodiscard]] bool allBytesAckedTill(uint64_t offset) const {
    if (ackedIntervals.empty()) {
      return false;
    }

    return ackedIntervals.front().start == 0 &&
        ackedIntervals.front().end >= offset;
  }
};

struct QuicConnectionStateBase;

enum class StreamSendState : uint8_t { Open, ResetSent, Closed, Invalid };

enum class StreamRecvState : uint8_t { Open, Closed, Invalid };

inline folly::StringPiece streamStateToString(StreamSendState state) {
  switch (state) {
    case StreamSendState::Open:
      return "Open";
    case StreamSendState::ResetSent:
      return "ResetSent";
    case StreamSendState::Closed:
      return "Closed";
    case StreamSendState::Invalid:
      return "Invalid";
    default:
      return "Unknown";
  }
}

inline folly::StringPiece streamStateToString(StreamRecvState state) {
  switch (state) {
    case StreamRecvState::Open:
      return "Open";
    case StreamRecvState::Closed:
      return "Closed";
    case StreamRecvState::Invalid:
      return "Invalid";
    default:
      return "Unknown";
  }
}

struct QuicStreamState : public QuicStreamLike {
  ~QuicStreamState() override = default;

  QuicStreamState(StreamId id, QuicConnectionStateBase& conn);

  QuicStreamState(QuicStreamState&&) = default;

  /**
   * Constructor to migrate QuicStreamState to another
   * QuicConnectionStateBase.
   */
  QuicStreamState(QuicConnectionStateBase& connIn, QuicStreamState&& other)
      : QuicStreamLike(std::move(other)), conn(connIn), id(other.id) {
    // QuicStreamState fields
    finalWriteOffset = other.finalWriteOffset;
    streamSendBuffer = std::move(other.streamSendBuffer);
    flowControlState = other.flowControlState;
    streamReadError = other.streamReadError;
    streamWriteError = other.streamWriteError;
    sendState = other.sendState;
    recvState = other.recvState;
    ingressRetired = other.ingressRetired;
    isControl = other.isControl;
    lastHolbTime = other.lastHolbTime;
    totalHolbTime = other.totalHolbTime;
    holbCount = other.holbCount;
    priority = other.priority;
    streamLossCount = other.streamLossCount;
    inLossSet_ = other.inLossSet_;
    retransmissionDisabled_ = other.retransmissionDisabled_;
  }

  // Connection that this stream is associated with.
  QuicConnectionStateBase& conn;

  // Stream id of the connection.
  StreamId id;

  // Write side eof offset. This represents only the final FIN offset.
  Optional<uint64_t> finalWriteOffset;

  // Present only for send-capable app streams created with the unified send
  // buffer enabled. Crypto streams continue to use QuicStreamLike storage.
  Optional<StreamSendBuffer> streamSendBuffer;

  struct StreamFlowControlState {
    uint64_t windowSize{0};
    uint64_t advertisedMaxOffset{0};
    uint64_t peerAdvertisedMaxOffset{0};
    // Time at which the last flow control update was sent by the transport.
    Optional<TimePoint> timeOfLastFlowControlUpdate;
    // A flag indicating if the stream has a pending blocked frame to the peer
    // (blocked frame sent, but a stream flow control update has not been
    // received yet). Set when we write a blocked data frame on the stream;
    // cleared when we receive a flow control update for the stream.
    bool pendingBlockedFrame{false};
    // See QuicSocketLite::setStreamManualRead().
    bool manualRead{false};
    // Offset up to which receive credit has been released. Never exceeds
    // deliveredReadOffset().
    uint64_t releasedReadOffset{0};
  };

  // Offset of the data delivered to the app, excluding the FIN byte.
  [[nodiscard]] uint64_t deliveredReadOffset() const noexcept {
    return finalReadOffset ? std::min(currentReadOffset, *finalReadOffset)
                           : currentReadOffset;
  }

  // Bytes delivered to the app but not yet released for flow control.
  [[nodiscard]] uint64_t unreleasedReadBytes() const noexcept {
    return deliveredReadOffset() - flowControlState.releasedReadOffset;
  }

  StreamFlowControlState flowControlState;

  // Stream level read error occurred.
  Optional<QuicErrorCode> streamReadError;
  // Stream level write error occurred.
  Optional<QuicErrorCode> streamWriteError;

  // State machine data
  StreamSendState sendState{StreamSendState::Open};

  // State machine data
  StreamRecvState recvState{StreamRecvState::Open};

  // Set when the application retires the receive side with
  // stopSendingAndDropIngress(). Ingress is then only accounted for flow
  // control, the receive side closes as soon as the peer's final size is
  // known, and a graceful close does not wait for the peer on this stream.
  bool ingressRetired{false};

  // Marks the receive side retired without touching anything it has received.
  // On a stream that has received nothing, this is all retiring it takes.
  void markIngressRetired() {
    ingressRetired = true;
    stopSendingRequested = true;
  }

  // Tells whether this stream is a control stream.
  // It is set by the app via setControlStream and the transport can use this
  // knowledge for optimizations e.g. for setting the app limited state on
  // congestion control with control streams still active.
  bool isControl{false};

  // The last time we detected we were head of line blocked on the stream.
  Optional<Clock::time_point> lastHolbTime;

  // The total amount of time we are head line blocked on the stream.
  std::chrono::microseconds totalHolbTime{0us};

  // Number of times the stream has entered the HOLB state
  // lastHolbTime indicates whether the stream is HOL blocked at the moment.
  uint32_t holbCount{0};

  // Uninitialized = default
  PriorityQueue::Priority priority;

  uint64_t streamLossCount{0};

  // Tracks if this stream is currently counted in the connection-level
  // numStreamsWithLoss counter. Used to avoid double-counting.
  bool inLossSet_{false};

  // If true, retransmissions are disabled for this stream (data lost will not
  // be retransmitted).
  bool retransmissionDisabled_{false};

  // Returns true if both send and receive state machines are in a terminal
  // state
  [[nodiscard]] bool inTerminalStates() const noexcept {
    bool sendInTerminalState = sendState == StreamSendState::Closed ||
        sendState == StreamSendState::Invalid;

    bool recvInTerminalState = recvState == StreamRecvState::Closed ||
        recvState == StreamRecvState::Invalid;

    return sendInTerminalState && recvInTerminalState;
  }

  // If the stream is still writable.
  [[nodiscard]] bool writable() const noexcept {
    return sendState == StreamSendState::Open && !finalWriteOffset.has_value();
  }

  [[nodiscard]] bool usesUnifiedSendBuffer() const noexcept {
    return streamSendBuffer.has_value();
  }

  [[nodiscard]] uint64_t pendingWriteBytes() const noexcept {
    return streamSendBuffer ? streamSendBuffer->unsentBytes()
                            : pendingWrites.chainLength();
  }

  [[nodiscard]] uint64_t writeBufferEndOffset() const noexcept {
    return streamSendBuffer ? streamSendBuffer->tailOffset()
                            : currentWriteOffset + pendingWrites.chainLength();
  }

  [[nodiscard]] bool shouldSendFlowControl() const noexcept {
    return recvState == StreamRecvState::Open;
  }

  // If the stream has writable data. That is, in a
  // regular stream write, it will be able to write something. So it either
  // needs to have data in the pendingWrites chain, or it has EOF to send.
  [[nodiscard]] bool hasWritableData(
      bool connFlowControlOpen = true) const noexcept {
    if (pendingWriteBytes() > 0) {
      const auto nextWriteOffset = nextOffsetToWrite();
      MVCHECK_GE(flowControlState.peerAdvertisedMaxOffset, nextWriteOffset);
      return connFlowControlOpen &&
          flowControlState.peerAdvertisedMaxOffset - nextWriteOffset > 0;
    }
    if (streamSendBuffer) {
      return streamSendBuffer->finBuffered() && !streamSendBuffer->finSent();
    }
    if (finalWriteOffset) {
      return currentWriteOffset <= *finalWriteOffset;
    }
    return false;
  }

  // Whether this stream has data in the write buffer or loss buffer.
  [[nodiscard]] bool hasSchedulableData(
      bool connFlowControlOpen = true) const noexcept {
    return hasWritableData(connFlowControlOpen) || hasLoss();
  }

  [[nodiscard]] bool hasSentFIN() const noexcept {
    if (streamSendBuffer) {
      return streamSendBuffer->finSent();
    }
    if (!finalWriteOffset) {
      return false;
    }
    return currentWriteOffset > *finalWriteOffset;
  }

  [[nodiscard]] bool hasLoss() const noexcept {
    return streamSendBuffer ? streamSendBuffer->hasPendingLoss()
                            : !lossBuffer.empty();
  }

  [[nodiscard]] uint64_t nextOffsetToWrite() const noexcept {
    return streamSendBuffer ? streamSendBuffer->nextUnsentOffset()
                            : currentWriteOffset;
  }

  [[nodiscard]] uint64_t writeOffset() const noexcept {
    return streamSendBuffer ? streamSendBuffer->nextUnsentOffset() +
            static_cast<uint64_t>(streamSendBuffer->finSent())
                            : currentWriteOffset;
  }

  [[nodiscard]] bool allBytesAckedTill(uint64_t offset) const {
    return streamSendBuffer ? streamSendBuffer->allBytesAckedTill(offset)
                            : QuicStreamLike::allBytesAckedTill(offset);
  }

  [[nodiscard]] bool hasReadableData() const noexcept {
    return (readBuffer.size() > 0 &&
            currentReadOffset == readBuffer.front().offset) ||
        (finalReadOffset && currentReadOffset == *finalReadOffset);
  }

  [[nodiscard]] bool hasPeekableData() const noexcept {
    return readBuffer.size() > 0;
  }

  void removeFromReadBufferStartingAtOffset(uint64_t startingOffset) {
    while (!readBuffer.empty()) {
      auto& lastElement = readBuffer.back();
      if (lastElement.offset >= startingOffset) {
        readBuffer.pop_back();
      } else if (
          lastElement.offset + lastElement.data.chainLength() >=
          startingOffset) {
        lastElement.data = lastElement.data.splitAtMost(
            size_t(startingOffset - lastElement.offset));
        return;
      } else {
        return;
      }
    }
  }
};
} // namespace quic
