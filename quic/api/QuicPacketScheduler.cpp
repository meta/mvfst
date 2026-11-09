/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/MvfstLogging.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/TimestampFrameFunctions.h>
#include <cstdint>
#include <limits>

namespace {
using namespace quic;

quic::Expected<void, QuicError> writeUnifiedStreamData(
    PacketBuilderInterface& builder,
    const StreamSendBuffer& sendBuffer,
    uint64_t offset,
    uint64_t len) {
  if (!sendBuffer.writeAt(offset, len, [&builder](ByteRange range) {
        builder.insert(range);
        return true;
      })) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to read scheduled data from the unified stream send buffer"));
  }
  return {};
}

quic::Expected<void, QuicError> writeUnifiedCryptoData(
    PacketBuilderInterface& builder,
    const StreamSendBuffer& sendBuffer,
    uint64_t offset,
    uint64_t len) {
  if (!sendBuffer.writeAt(offset, len, [&builder](ByteRange range) {
        builder.insert(range);
        return true;
      })) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to read scheduled crypto data from the send buffer"));
  }
  return {};
}

PacketNumberSpace cryptoPacketNumberSpace(EncryptionLevel encryptionLevel) {
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      return PacketNumberSpace::Initial;
    case EncryptionLevel::Handshake:
      return PacketNumberSpace::Handshake;
    case EncryptionLevel::AppData:
      return PacketNumberSpace::AppData;
    case EncryptionLevel::EarlyData:
      MVCHECK(false, "0-RTT packets cannot carry crypto frames");
    case EncryptionLevel::MAX:
      MVCHECK(false, "Invalid crypto encryption level");
  }
  folly::assume_unreachable();
}

std::optional<StreamSendBuffer::SendRange> firstUnselectedCryptoRange(
    const StreamSendBuffer& sendBuffer,
    const StreamSendBuffer::SendRange& originalRange,
    const IntervalSet<uint64_t>& selectedData) {
  auto searchOffset = originalRange.offset;
  const auto originalEnd = originalRange.offset + originalRange.len;
  while (searchOffset < originalEnd) {
    auto candidate = sendBuffer.firstOutstandingIn(
        {.offset = searchOffset,
         .len = originalEnd - searchOffset,
         .fin = false},
        std::numeric_limits<uint64_t>::max());
    if (!candidate || candidate->len == 0) {
      return std::nullopt;
    }

    const auto candidateEnd = candidate->offset + candidate->len;
    bool retry = false;
    for (const auto& selected : selectedData) {
      if (selected.end < candidate->offset) {
        continue;
      }
      if (selected.start >= candidateEnd) {
        break;
      }
      if (selected.start <= candidate->offset) {
        searchOffset = selected.end + 1;
        retry = true;
        break;
      }
      candidate->len = selected.start - candidate->offset;
      break;
    }
    if (!retry) {
      return candidate;
    }
  }
  return std::nullopt;
}

/**
 * A helper iterator adaptor class that starts iteration of streams from a
 * specific stream id.
 */
class MiddleStartingIterationWrapper {
 public:
  using MapType = std::set<StreamId>;

  class MiddleStartingIterator {
   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = MapType::value_type;
    using difference_type = std::ptrdiff_t;
    using pointer = const value_type*;
    using reference = const value_type&;

    using InnerMapType = MiddleStartingIterationWrapper::MapType;

    MiddleStartingIterator() = delete;

    MiddleStartingIterator(
        const InnerMapType* streams,
        const InnerMapType::key_type& start)
        : streams_(streams) {
      itr_ = streams_->lower_bound(start);
      checkForWrapAround();
      // We don't want to mark it as wrapped around initially, instead just
      // act as if start was the first element.
      wrappedAround_ = false;
    }

    MiddleStartingIterator(
        const InnerMapType* streams,
        InnerMapType::const_iterator itr)
        : streams_(streams), itr_(itr) {
      checkForWrapAround();
      // We don't want to mark it as wrapped around initially, instead just
      // act as if start was the first element.
      wrappedAround_ = false;
    }

    [[nodiscard]] reference operator*() const {
      return *itr_;
    }

    [[nodiscard]] pointer operator->() const {
      return &(*itr_);
    }

    MiddleStartingIterator& operator++() {
      ++itr_;
      checkForWrapAround();
      return *this;
    }

    MiddleStartingIterator operator++(int) {
      MiddleStartingIterator tmp(*this);
      ++(*this);
      return tmp;
    }

    [[nodiscard]] bool operator==(const MiddleStartingIterator& other) const {
      return wrappedAround_ == other.wrappedAround_ && itr_ == other.itr_;
    }

    [[nodiscard]] bool operator!=(const MiddleStartingIterator& other) const {
      return !(*this == other);
    }

    [[nodiscard]] InnerMapType::const_iterator rawIterator() const {
      return itr_;
    }

   private:
    void checkForWrapAround() {
      if (itr_ == streams_->cend()) {
        wrappedAround_ = true;
        itr_ = streams_->cbegin();
      }
    }

    friend class MiddleStartingIterationWrapper;
    bool wrappedAround_{false};
    const InnerMapType* streams_{nullptr};
    InnerMapType::const_iterator itr_;
  };

  MiddleStartingIterationWrapper(
      const MapType& streams,
      const MapType::key_type& start)
      : streams_(streams), start_(&streams_, start) {}

  MiddleStartingIterationWrapper(
      const MapType& streams,
      const MapType::const_iterator& start)
      : streams_(streams), start_(&streams_, start) {}

  [[nodiscard]] MiddleStartingIterator cbegin() const {
    return start_;
  }

  [[nodiscard]] MiddleStartingIterator cend() const {
    MiddleStartingIterator itr(start_);
    itr.wrappedAround_ = true;
    return itr;
  }

 private:
  const MapType& streams_;
  const MiddleStartingIterator start_;
};

} // namespace

namespace quic {

// Schedulers

FrameScheduler::Builder::Builder(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace packetNumberSpace,
    folly::StringPiece name)
    : conn_(conn),
      encryptionLevel_(encryptionLevel),
      packetNumberSpace_(packetNumberSpace),
      name_(std::move(name)) {}

FrameScheduler::Builder& FrameScheduler::Builder::streamFrames() {
  streamFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::ackFrames() {
  ackScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::resetFrames() {
  rstScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::windowUpdateFrames() {
  windowUpdateScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::blockedFrames() {
  blockedScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::cryptoFrames() {
  cryptoStreamScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::simpleFrames() {
  simpleFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::pingFrames() {
  pingFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::datagramFrames() {
  datagramFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::immediateAckFrames() {
  immediateAckFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::timestampFrames() {
  timestampFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::pathValidationFrames(
    PathIdType pathId) {
  schedulePathValidationFramesForPathId_ = pathId;
  return *this;
}

FrameScheduler FrameScheduler::Builder::build() && {
  FrameScheduler scheduler(name_, conn_);
  if (streamFrameScheduler_) {
    scheduler.streamFrameScheduler_.emplace(StreamFrameScheduler(conn_));
  }
  if (ackScheduler_) {
    scheduler.ackScheduler_.emplace(
        AckScheduler(conn_, getAckState(conn_, packetNumberSpace_)));
  }
  if (rstScheduler_) {
    scheduler.rstScheduler_.emplace(RstStreamScheduler(conn_));
  }
  if (windowUpdateScheduler_) {
    scheduler.windowUpdateScheduler_.emplace(WindowUpdateScheduler(conn_));
  }
  if (blockedScheduler_) {
    scheduler.blockedScheduler_.emplace(BlockedScheduler(conn_));
  }
  if (cryptoStreamScheduler_) {
    scheduler.cryptoStreamScheduler_.emplace(CryptoStreamScheduler(
        conn_, *getCryptoStream(*conn_.cryptoState, encryptionLevel_)));
  }
  if (simpleFrameScheduler_) {
    scheduler.simpleFrameScheduler_.emplace(SimpleFrameScheduler(conn_));
  }
  if (pingFrameScheduler_) {
    scheduler.pingFrameScheduler_.emplace(PingFrameScheduler(conn_));
  }
  if (datagramFrameScheduler_) {
    scheduler.datagramFrameScheduler_.emplace(DatagramFrameScheduler(conn_));
  }
  if (immediateAckFrameScheduler_) {
    scheduler.immediateAckFrameScheduler_.emplace(
        ImmediateAckFrameScheduler(conn_));
  }
  if (timestampFrameScheduler_) {
    scheduler.timestampFrameScheduler_.emplace(conn_);
  }
  if (schedulePathValidationFramesForPathId_.has_value()) {
    scheduler.pathValidationFrameScheduler_.emplace(
        PathValidationFrameScheduler(
            conn_, schedulePathValidationFramesForPathId_.value()));
  }
  return scheduler;
}

FrameScheduler::FrameScheduler(
    folly::StringPiece name,
    QuicConnectionStateBase& conn)
    : name_(name), conn_(conn) {}

quic::Expected<SchedulingResult, QuicError>
FrameScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  size_t shortHeaderPadding = 0;
  const ShortHeader* shortHeader = builder.getPacketHeader().asShort();
  const LongHeader* longHeader = builder.getPacketHeader().asLong();
  bool initialPacket =
      longHeader && longHeader->getHeaderType() == LongHeader::Types::Initial;
  auto encodeRes = builder.encodePacketHeader();
  if (!encodeRes.has_value()) {
    return quic::make_unexpected(encodeRes.error());
  }
  // Add fixed padding at start of short header packets if configured
  if (shortHeader && conn_.transportSettings.fixedShortHeaderPadding > 0) {
    for (size_t i = 0; i < conn_.transportSettings.fixedShortHeaderPadding;
         i++) {
      auto writeRes = writeFrame(PaddingFrame(), builder);
      if (!writeRes.has_value()) {
        return quic::make_unexpected(writeRes.error());
      }
    }
    shortHeaderPadding = conn_.transportSettings.fixedShortHeaderPadding;
  }
  // We need to keep track of writable bytes after writing header.
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  // We cannot return early if the writablyBytes drops to 0 here, since pure
  // acks can skip writableBytes entirely.
  TimestampFramePacketObserver timestampPacketObserver;
  const bool trackTimestampFrames = timestampFrameScheduler_ && shortHeader &&
      shouldWriteOneRttTimestampFrame(conn_, false);
  PacketFrameTrackingBuilderHolder<TimestampFramePacketObserver>
      selectedBuilder(builder, timestampPacketObserver, trackTimestampFrames);
  auto& packetBuilder = selectedBuilder.builder();
  PacketBuilderWrapper wrapper(packetBuilder, writableBytes);
  bool cryptoDataWritten = false;
  bool rstWritten = false;
  if (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) {
    auto cryptoDataRes = cryptoStreamScheduler_->writeCryptoData(wrapper);
    if (!cryptoDataRes.has_value()) {
      return quic::make_unexpected(cryptoDataRes.error());
    }
    cryptoDataWritten = cryptoDataRes.value();
  }
  if (rstScheduler_ && rstScheduler_->hasPendingRsts()) {
    auto rstWrittenRes = rstScheduler_->writeRsts(wrapper);
    if (!rstWrittenRes.has_value()) {
      return quic::make_unexpected(rstWrittenRes.error());
    }
    rstWritten = rstWrittenRes.value();
  }
  // Long time ago we decided RST has higher priority than Acks.
  if (hasPendingAcks()) {
    if (cryptoDataWritten || rstWritten) {
      // If packet has non ack data, it is subject to congestion control. We
      // need to use the wrapper/
      auto writeAcksRes = ackScheduler_->writeNextAcks(wrapper);
      if (!writeAcksRes.has_value()) {
        return quic::make_unexpected(writeAcksRes.error());
      }
    } else {
      // If we start with writing acks, we will let the ack scheduler write
      // up to the full packet space. If the ack bytes exceeds the writable
      // bytes, this will be a pure ack packet and it will skip congestion
      // controller. Otherwise, we will give other schedulers an opportunity to
      // write up to writable bytes.
      auto writeAcksRes = ackScheduler_->writeNextAcks(packetBuilder);
      if (!writeAcksRes.has_value()) {
        return quic::make_unexpected(writeAcksRes.error());
      }
    }
  }
  // Immediate ACK frames are subject to congestion control but should be sent
  // before other frames to maximize their chance of being included in the
  // packet since they are time sensitive
  if (immediateAckFrameScheduler_ &&
      immediateAckFrameScheduler_->hasPendingImmediateAckFrame()) {
    immediateAckFrameScheduler_->writeImmediateAckFrame(wrapper);
  }
  if (windowUpdateScheduler_ &&
      windowUpdateScheduler_->hasPendingWindowUpdates()) {
    auto result = windowUpdateScheduler_->writeWindowUpdates(wrapper);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  if (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) {
    auto result = blockedScheduler_->writeBlockedFrames(wrapper);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  // Simple frames and path validation frames should be scheduled before
  // stream frames and retx frames because stream/datagram writes can fill
  // up all available bytes for writing. PATH_CHALLENGE/PATH_RESPONSE for
  // the current path are routed through pathValidationFrameScheduler_
  // (not simpleFrameScheduler_), so they need their own ordering guarantee
  // here.
  if (simpleFrameScheduler_ &&
      simpleFrameScheduler_->hasPendingSimpleFrames()) {
    simpleFrameScheduler_->writeSimpleFrames(wrapper);
  }
  bool hasPathProbingFrame = false;
  if (pathValidationFrameScheduler_) {
    if (pathValidationFrameScheduler_->hasPendingPathValidationFrames()) {
      pathValidationFrameScheduler_->writePathValidationFrames(wrapper);
      hasPathProbingFrame = true;
    }
  }
  if (pingFrameScheduler_ && pingFrameScheduler_->hasPingFrame()) {
    pingFrameScheduler_->writePing(wrapper);
  }

  const auto hasStandaloneDatagramData = [&] {
    return datagramFrameScheduler_ &&
        !conn_.transportSettings.datagramConfig.scheduleDatagramsWithStreams &&
        datagramFrameScheduler_->hasPendingDatagramFrames();
  };
  const bool hasBulkData =
      (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) ||
      hasStandaloneDatagramData();
  const bool hasPendingSelectedData =
      conn_.transportSettings.oneRttTimestampFramePacketSelection ==
          TimestampFramePacketSelection::StreamPackets
      ? streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()
      : hasBulkData;
  Optional<TimestampFrame> timestampFrame;
  if (trackTimestampFrames) {
    timestampFrame = timestampFrameScheduler_->maybeGenerateTimestampFrame(
        timestampPacketObserver, hasPendingSelectedData);
  }

  PacketBuilderInterface* bulkBuilder = &wrapper;
  Optional<PacketBuilderWrapper> prioritizedWrapper;
  const auto timestampPacketSelection =
      conn_.transportSettings.oneRttTimestampFramePacketSelection;
  const bool hadSelectedFrameBeforeBulk =
      timestampPacketObserver.matchesPacketSelection(timestampPacketSelection);
  if (timestampFrame &&
      conn_.transportSettings.oneRttTimestampFrameWriteMode ==
          TimestampFrameWriteMode::Prioritized) {
    auto timestampSize = getTimestampFrameEncodedSize(*timestampFrame);
    if (timestampSize.hasError()) {
      return quic::make_unexpected(timestampSize.error());
    }
    const auto remaining = wrapper.remainingSpaceInPkt();
    if (remaining >= timestampSize.value()) {
      prioritizedWrapper.emplace(wrapper, remaining - timestampSize.value());
      bulkBuilder = &*prioritizedWrapper;
    }
  }

  auto writeBulkFrames =
      [&](PacketBuilderInterface& target) -> quic::Expected<void, QuicError> {
    if (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) {
      auto result = streamFrameScheduler_->writeStreams(target);
      if (!result.has_value()) {
        return quic::make_unexpected(result.error());
      }
    }
    // When scheduleDatagramsWithStreams is enabled, datagrams are handled by
    // streamFrameScheduler above.
    if (hasStandaloneDatagramData()) {
      auto datagramRes = datagramFrameScheduler_->writeDatagramFrames(target);
      if (!datagramRes.has_value()) {
        return quic::make_unexpected(datagramRes.error());
      }
    }
    return {};
  };

  auto bulkResult = writeBulkFrames(*bulkBuilder);
  if (bulkResult.hasError()) {
    return quic::make_unexpected(bulkResult.error());
  }
  if (prioritizedWrapper && !hadSelectedFrameBeforeBulk &&
      !timestampPacketObserver.matchesPacketSelection(
          timestampPacketSelection)) {
    // Bulk schedulers consume only successful writes, so retrying targets
    // only data that did not fit under the unused timestamp reservation.
    bulkResult = writeBulkFrames(wrapper);
    if (bulkResult.hasError()) {
      return quic::make_unexpected(bulkResult.error());
    }
  }

  if (timestampFrame &&
      timestampPacketObserver.matchesPacketSelection(
          timestampPacketSelection)) {
    // TIMESTAMP does not make an ACK-only packet ACK-eliciting, so it can use
    // the same congestion-control bypass as its ACK frame.
    PacketBuilderInterface& timestampBuilder =
        timestampPacketObserver.hasAckElicitingFrame() ? wrapper
                                                       : packetBuilder;
    auto timestampRes = timestampFrameScheduler_->writeTimestampFrame(
        *timestampFrame, timestampBuilder);
    if (!timestampRes.has_value()) {
      return quic::make_unexpected(timestampRes.error());
    }
    // The unreserved bulk retry may consume the timestamp budget. Keep its
    // carrier packet because TIMESTAMP is best-effort.
    static_cast<void>(timestampRes.value());
  }

  if (packetBuilder.hasFramesPending()) {
    if (initialPacket || hasPathProbingFrame) {
      // This is the initial packet or a it has a path probing frame, we need to
      // fill er up.
      while (packetBuilder.remainingSpaceInPkt() > 0) {
        auto writeRes = writeFrame(PaddingFrame(), packetBuilder);
        if (!writeRes.has_value()) {
          return quic::make_unexpected(writeRes.error());
        }
      }
    }
    if (shortHeader) {
      size_t paddingModulo = conn_.transportSettings.paddingModulo;
      if (paddingModulo > 0) {
        size_t paddingIncrement = wrapper.remainingSpaceInPkt() % paddingModulo;
        for (size_t i = 0; i < paddingIncrement; i++) {
          auto writeRes = writeFrame(PaddingFrame(), packetBuilder);
          if (!writeRes.has_value()) {
            return quic::make_unexpected(writeRes.error());
          }
        }
        shortHeaderPadding += paddingIncrement;
      }
    }
  }

  return SchedulingResult(
      std::nullopt,
      std::move(packetBuilder).buildPacket(),
      shortHeaderPadding,
      transmissionReason_);
}

bool FrameScheduler::hasData() const {
  return hasPendingAcks() || hasImmediateData();
}

bool FrameScheduler::hasPendingAcks() const {
  return ackScheduler_ && ackScheduler_->hasPendingAcks();
}

bool FrameScheduler::hasImmediateData() const {
  return (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) ||
      (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) ||
      (rstScheduler_ && rstScheduler_->hasPendingRsts()) ||
      (windowUpdateScheduler_ &&
       windowUpdateScheduler_->hasPendingWindowUpdates()) ||
      (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) ||
      (simpleFrameScheduler_ &&
       simpleFrameScheduler_->hasPendingSimpleFrames()) ||
      (pingFrameScheduler_ && pingFrameScheduler_->hasPingFrame()) ||
      (datagramFrameScheduler_ &&
       datagramFrameScheduler_->hasPendingDatagramFrames()) ||
      (immediateAckFrameScheduler_ &&
       immediateAckFrameScheduler_->hasPendingImmediateAckFrame()) ||
      (pathValidationFrameScheduler_ &&
       pathValidationFrameScheduler_->hasPendingPathValidationFrames());
}

folly::StringPiece FrameScheduler::name() const {
  return name_;
}

quic::Expected<bool, QuicError> StreamFrameScheduler::writeStreamLossBuffers(
    PacketBuilderInterface& builder,
    QuicStreamState& stream) {
  if (stream.streamSendBuffer) {
    bool wroteStreamFrame = false;
    bool wroteFin = false;
    uint64_t nextLossOffset = 0;
    while (
        auto loss = stream.streamSendBuffer->nextLossAfter(
            nextLossOffset, !wroteFin, std::numeric_limits<uint64_t>::max())) {
      auto res = writeStreamFrameHeader(
          builder,
          stream.id,
          loss->offset,
          loss->len,
          loss->len,
          loss->fin,
          std::nullopt /* skipLenHint */);
      if (!res.has_value()) {
        return quic::make_unexpected(res.error());
      }
      auto dataLen = *res;
      if (!dataLen) {
        break;
      }
      auto writeResult = writeUnifiedStreamData(
          builder, *stream.streamSendBuffer, loss->offset, *dataLen);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      wroteStreamFrame = true;
      const bool wroteCompleteRange = *dataLen == loss->len;
      wroteFin = wroteFin || (loss->fin && wroteCompleteRange);
      MVVLOG(4) << "Wrote loss data for stream=" << stream.id
                << " offset=" << loss->offset << " bytes=" << *dataLen
                << " fin=" << (loss->fin && wroteCompleteRange) << " " << conn_;
      if (!wroteCompleteRange) {
        break;
      }
      nextLossOffset = loss->offset + loss->len;
    }
    return wroteStreamFrame;
  }

  bool wroteStreamFrame = false;
  for (auto buffer = stream.lossBuffer.cbegin();
       buffer != stream.lossBuffer.cend();
       ++buffer) {
    auto bufferLen = buffer->data.chainLength();
    auto res = writeStreamFrameHeader(
        builder,
        stream.id,
        buffer->offset,
        bufferLen, // writeBufferLen -- only the len of the single buffer.
        bufferLen, // flowControlLen -- not relevant, already flow controlled.
        buffer->eof,
        std::nullopt /* skipLenHint */);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    auto dataLen = *res;
    if (dataLen) {
      wroteStreamFrame = true;
      writeStreamFrameData(builder, buffer->data, *dataLen);
      MVVLOG(4) << "Wrote loss data for stream=" << stream.id
                << " offset=" << buffer->offset << " bytes=" << *dataLen
                << " fin=" << (buffer->eof && *dataLen == bufferLen) << " "
                << conn_;
    } else {
      // Either we filled the packet or ran out of data for this stream (EOF?)
      break;
    }
  }
  return wroteStreamFrame;
}

StreamFrameScheduler::StreamFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

quic::Expected<StreamFrameScheduler::StreamWriteResult, QuicError>
StreamFrameScheduler::writeSingleStream(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  StreamWriteResult result = StreamWriteResult::NOT_LIMITED;
  if (stream.hasLoss()) {
    auto writeResult = writeStreamLossBuffers(builder, stream);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (!writeResult.value()) {
      return StreamWriteResult::PACKET_FULL;
    }
  }
  if (stream.hasWritableData(true)) {
    if (connWritableBytes > 0 || stream.hasWritableData(false)) {
      auto writeResult = writeStreamFrame(builder, stream, connWritableBytes);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      if (!writeResult.value()) {
        return StreamWriteResult::PACKET_FULL;
      }
      result = (connWritableBytes == 0) ? StreamWriteResult::CONN_FC_LIMITED
                                        : StreamWriteResult::NOT_LIMITED;
    } else {
      result = StreamWriteResult::CONN_FC_LIMITED;
    }
  }
  return result;
}

quic::Expected<StreamId, QuicError> StreamFrameScheduler::writeStreamsHelper(
    PacketBuilderInterface& builder,
    const std::set<StreamId>& writableStreams,
    StreamId nextScheduledStream,
    uint64_t& connWritableBytes,
    bool streamPerPacket) {
  MiddleStartingIterationWrapper wrapper(writableStreams, nextScheduledStream);
  auto writableStreamItr = wrapper.cbegin();
  // This will write the stream frames in a round robin fashion ordered by
  // stream id. The iterator will wrap around the collection at the end, and we
  // keep track of the value at the next iteration. This allows us to start
  // writing at the next stream when building the next packet.
  while (writableStreamItr != wrapper.cend()) {
    auto stream = conn_.streamManager->findStream(*writableStreamItr);
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && !stream,
        conn_.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_).setStreamId(
            *writableStreamItr),
        "quic_packet_scheduler",
        "invariant_violation: writable control stream missing stream state");
    MVCHECK(stream);
    auto writeResult = writeSingleStream(builder, *stream, connWritableBytes);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (writeResult.value() == StreamWriteResult::PACKET_FULL) {
      break;
    }
    writableStreamItr++;
    if (streamPerPacket) {
      break;
    }
  }
  return *writableStreamItr;
}

// Helper to write a datagram from a flow
// Returns {buf, flowEmpty, datagramLen} - buf is nullptr if nothing written
static quic::Expected<DatagramFlowManager::DatagramPopResult, QuicError>
writeDatagramFrame(
    QuicConnectionStateBase& conn,
    uint32_t flowId,
    PacketBuilderInterface& builder,
    TimePoint now) {
  // Try to pop the datagram if it fits (overhead calculated internally)
  auto popResult = conn.datagramState.flowManager.popDatagramIfFits(
      flowId, builder.remainingSpaceInPkt(), now);

  for (uint64_t i = 0; i < popResult.numExpired; ++i) {
    QUIC_STATS(conn.statsCallback, onDatagramDroppedOnWrite);
  }

  if (!popResult.buf) {
    // Doesn't fit - return popResult as-is
    return popResult;
  }

  // Write the datagram frame
  auto datagramFrame =
      DatagramFrame(popResult.datagramLen, std::move(popResult.buf));
  auto res = writeFrame(datagramFrame, builder);
  if (!res.has_value()) {
    return quic::make_unexpected(res.error());
  }
  MVCHECK_GT(res.value(), 0);
  QUIC_STATS(conn.statsCallback, onDatagramWrite, popResult.datagramLen);
  // Return popResult directly; buf has been moved into the DatagramFrame above
  return popResult;
}

quic::Expected<void, QuicError> StreamFrameScheduler::writeStreamsHelper(
    PacketBuilderInterface& builder,
    PriorityQueue& writableStreams,
    uint64_t& connWritableBytes,
    bool streamPerPacket) {
  // Fill a packet with non-control stream data, in priority order
  //
  // The streams can have loss data or fresh data.  Once we run out of
  // conn flow control, we can only write loss data.  In order to
  // advance the write queue, we have to remove the elements.  Store
  // them in QuicStreamManager and re-insert when more f/c arrives
  // Only datagrams need the clock, and only expiring ones at that; resolve it
  // once, on the first one.
  Optional<TimePoint> now;
  while (!writableStreams.empty() && builder.remainingSpaceInPkt() > 0) {
    auto id = writableStreams.peekNextScheduledID();

    // Handle datagrams scheduled via PriorityQueue
    if (id.isDatagramFlowID()) {
      auto flowId = id.asDatagramFlowID();
      if (!now) {
        now = conn_.datagramState.flowManager.nowForExpiration();
      }
      auto writeResult = writeDatagramFrame(conn_, flowId, builder, *now);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      auto& result = writeResult.value();

      if (result.flowEmpty) {
        // Flow is now empty (either datagram written or all expired)
        writableStreams.erase(id);
      } else if (result.datagramLen == 0) {
        // Front datagram doesn't fit - try next packet
        break;
      } else {
        // Datagram written, consume bytes for fairness
        writableStreams.consume(result.datagramLen);
      }

      if (result.datagramLen > 0 &&
          conn_.transportSettings.datagramConfig.framePerPacket) {
        break;
      }
    } else {
      // Handle streams
      PROTO_OOPS_LOG_BUILDER_IF(
          conn_.nodeType == QuicNodeType::Server && !id.isStreamID(),
          conn_.oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
          "quic_packet_scheduler",
          "invariant_violation: priority write queue scheduled non-stream "
          "identifier");
      MVCHECK(id.isStreamID());
      auto streamId = id.asStreamID();
      auto stream = conn_.streamManager->findStream(streamId);
      PROTO_OOPS_LOG_BUILDER_IF(
          conn_.nodeType == QuicNodeType::Server && !stream,
          conn_.oopsLogger,
          proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_)
              .setStreamId(streamId),
          "quic_packet_scheduler",
          "invariant_violation: priority write queue stream missing stream "
          "state");
      MVCHECK_NOTNULL(stream);
      MVCHECK(stream, "streamId=" << streamId);
      // TODO: this is counting STREAM frame overhead against the stream itself
      auto lastWriteBytes = builder.remainingSpaceInPkt();
      auto writeResult = writeSingleStream(builder, *stream, connWritableBytes);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      if (writeResult.value() == StreamWriteResult::PACKET_FULL) {
        break;
      }
      auto remainingSpaceAfter = builder.remainingSpaceInPkt();
      lastWriteBytes -= remainingSpaceAfter;
      // If we wrote a stream frame and there's still space in the packet,
      // that implies we ran out of data or flow control on the stream and
      // we should erase the stream from writableStreams, the caller can
      // rollback the transaction if the packet write fails
      if (remainingSpaceAfter > 0) {
        if (writeResult.value() == StreamWriteResult::CONN_FC_LIMITED) {
          conn_.streamManager->addConnFCBlockedStream(streamId);
        }
        writableStreams.erase(id);
      } else { // the loop will break
        writableStreams.consume(lastWriteBytes);
      }
      if (streamPerPacket) {
        return {};
      }
    }
  }
  return {};
}

quic::Expected<void, QuicError> StreamFrameScheduler::writeStreams(
    PacketBuilderInterface& builder) {
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server &&
          !conn_.streamManager->hasWritable(),
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_),
      "quic_packet_scheduler",
      "invariant_violation: stream write scheduler missing writable streams");
  MVDCHECK(conn_.streamManager->hasWritable());
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  // Write the control streams first as a naive binary priority mechanism.
  const auto& controlWriteQueue = conn_.streamManager->controlWriteQueue();
  if (!controlWriteQueue.empty()) {
    auto result = writeStreamsHelper(
        builder,
        controlWriteQueue,
        conn_.schedulingState.nextScheduledControlStream,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    conn_.schedulingState.nextScheduledControlStream = result.value();
  }
  auto& writeQueue = conn_.streamManager->writeQueue();
  if (!writeQueue.empty()) {
    auto result = writeStreamsHelper(
        builder,
        writeQueue,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

bool StreamFrameScheduler::hasPendingData() const {
  return conn_.streamManager->hasLoss() ||
      (conn_.streamManager->hasWritable() &&
       getSendConnFlowControlBytesWire(conn_) > 0);
}

quic::Expected<bool, QuicError> StreamFrameScheduler::writeStreamFrame(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  if (builder.remainingSpaceInPkt() == 0) {
    return false;
  }

  // hasWritableData is the condition which has to be satisfied for the
  // stream to be in writableList
  PROTO_OOPS_LOG_BUILDER_IF(
      conn_.nodeType == QuicNodeType::Server && !stream.hasWritableData(),
      conn_.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_).setStreamId(
          stream.id),
      "quic_packet_scheduler",
      "invariant_violation: writable stream missing writable data");
  MVCHECK(stream.hasWritableData());

  uint64_t flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(stream), connWritableBytes);
  if (stream.streamSendBuffer) {
    auto sendRange = stream.streamSendBuffer->nextNewData(flowControlLen);
    MVCHECK(sendRange.has_value());
    auto res = writeStreamFrameHeader(
        builder,
        stream.id,
        sendRange->offset,
        sendRange->len,
        sendRange->len,
        sendRange->fin,
        std::nullopt /* skipLenHint */);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    auto dataLen = *res;
    if (!dataLen) {
      return false;
    }
    auto writeResult = writeUnifiedStreamData(
        builder, *stream.streamSendBuffer, sendRange->offset, *dataLen);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    MVVLOG(4) << "Wrote stream frame stream=" << stream.id
              << " offset=" << sendRange->offset << " bytesWritten=" << *dataLen
              << " finWritten="
              << (sendRange->fin && *dataLen == sendRange->len) << " " << conn_;
    connWritableBytes -= dataLen.value();
    return true;
  }

  uint64_t bufferLen = stream.pendingWrites.chainLength();
  bool canWriteFin =
      stream.finalWriteOffset.has_value() && bufferLen <= flowControlLen;
  auto writeOffset = stream.currentWriteOffset;
  auto res = writeStreamFrameHeader(
      builder,
      stream.id,
      writeOffset,
      bufferLen,
      flowControlLen,
      canWriteFin,
      std::nullopt /* skipLenHint */);
  if (!res.has_value()) {
    return quic::make_unexpected(res.error());
  }
  auto dataLen = *res;
  if (!dataLen) {
    return false;
  }
  writeStreamFrameData(builder, stream.pendingWrites, *dataLen);
  MVVLOG(4) << "Wrote stream frame stream=" << stream.id
            << " offset=" << stream.currentWriteOffset
            << " bytesWritten=" << *dataLen
            << " finWritten=" << (canWriteFin && *dataLen == bufferLen) << " "
            << conn_;
  connWritableBytes -= dataLen.value();
  return true;
}

RstStreamScheduler::RstStreamScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool RstStreamScheduler::hasPendingRsts() const {
  return !conn_.pendingEvents.resets.empty();
}

quic::Expected<bool, QuicError> RstStreamScheduler::writeRsts(
    PacketBuilderInterface& builder) {
  bool rstWritten = false;
  for (const auto& resetStream : conn_.pendingEvents.resets) {
    auto streamId = resetStream.first;
    QuicStreamState* streamState =
        conn_.streamManager->getStream(streamId).value_or(nullptr);
    PROTO_OOPS_LOG_BUILDER_IF(
        conn_.nodeType == QuicNodeType::Server && !streamState,
        conn_.oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn_).setStreamId(
            streamId),
        "quic_packet_scheduler",
        "invariant_violation: reset stream missing stream state");
    MVCHECK(
        streamState,
        "Stream " << streamId << " not found when going through resets");
    if (streamState->pendingWriteBytes() == 0) {
      //    We only write a RESET_STREAM or RESET_STREAM_AT frame for a stream
      //    once we've written out all data that needs to be delivered reliably.
      //    While this is not something that's mandated by the spec, we're doing
      //    it in this implementation because it dramatically simplifies flow
      //    control accounting.
      auto bytesWrittenResult = writeFrame(resetStream.second, builder);
      if (!bytesWrittenResult.has_value()) {
        return quic::make_unexpected(bytesWrittenResult.error());
      }
      if (!bytesWrittenResult.value()) {
        break;
      }
      rstWritten = true;
    }
  }
  return rstWritten;
}

SimpleFrameScheduler::SimpleFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool SimpleFrameScheduler::hasPendingSimpleFrames() const {
  return !conn_.pendingEvents.frames.empty();
}

bool SimpleFrameScheduler::writeSimpleFrames(PacketBuilderInterface& builder) {
  bool framesWritten = false;
  for (auto& frame : conn_.pendingEvents.frames) {
    auto bytesWritten = writeSimpleFrame(QuicSimpleFrame(frame), builder);
    if (!bytesWritten) {
      break;
    }
    framesWritten = true;
  }
  return framesWritten;
}

PathValidationFrameScheduler::PathValidationFrameScheduler(
    const QuicConnectionStateBase& conn,
    PathIdType pathId)
    : conn_(conn), pathId_(pathId) {}

bool PathValidationFrameScheduler::hasPendingPathValidationFrames() const {
  return (conn_.pendingEvents.pathChallenges.find(pathId_) !=
          conn_.pendingEvents.pathChallenges.end()) ||
      conn_.pendingEvents.pathResponses.find(pathId_) !=
      conn_.pendingEvents.pathResponses.end();
}

bool PathValidationFrameScheduler::writePathValidationFrames(
    PacketBuilderInterface& builder) {
  bool framesWritten = false;

  // Write PathResponse frames for the specified path
  auto pathResponse = conn_.pendingEvents.pathResponses.find(pathId_);
  if (pathResponse != conn_.pendingEvents.pathResponses.end()) {
    if (!writeSimpleFrame(QuicSimpleFrame(pathResponse->second), builder)) {
      return false;
    }
    framesWritten = true;
  }

  if (conn_.pendingEvents.pathChallenges.contains(pathId_)) {
    auto challengeRes = conn_.pathManager->prepareChallengeForSending(pathId_);
    if (challengeRes.has_value()) {
      if (!writeSimpleFrame(QuicSimpleFrame(challengeRes.value()), builder)) {
        return false;
      }
      framesWritten = true;
    }
  }

  return framesWritten;
}

PingFrameScheduler::PingFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool PingFrameScheduler::hasPingFrame() const {
  return conn_.pendingEvents.sendPing;
}

bool PingFrameScheduler::writePing(PacketBuilderInterface& builder) {
  auto writeFrameResult = writeFrame(PingFrame(), builder);
  // We shouldn't ever error on a PING.
  MVCHECK(writeFrameResult.has_value());
  return writeFrameResult.value() != 0;
}

DatagramFrameScheduler::DatagramFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool DatagramFrameScheduler::hasPendingDatagramFrames() const {
  return conn_.datagramState.flowManager.hasDatagramsToSend();
}

quic::Expected<bool, QuicError> DatagramFrameScheduler::writeDatagramFrames(
    PacketBuilderInterface& builder) {
  bool sent = false;

  // Drain every flow when not using PriorityQueue scheduling. This is the only
  // writer on this path, so datagrams queued on a non-default flow would
  // otherwise never be sent. Flow order is unspecified here; callers that need
  // priority ordering must enable PriorityQueue scheduling.
  auto& flowManager = conn_.datagramState.flowManager;
  auto now = flowManager.nowForExpiration();
  // Every iteration either writes or expires at least one datagram, so the
  // total datagram count bounds the loop.
  size_t maxIters = flowManager.getDatagramCount();
  for (size_t i = 0; i < maxIters; ++i) {
    auto flowId = flowManager.firstNonEmptyFlowId();
    if (!flowId) {
      break;
    }
    auto writeResult = writeDatagramFrame(conn_, *flowId, builder, now);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (writeResult->datagramLen == 0) {
      if (writeResult->flowEmpty) {
        // Everything queued on this flow expired; move on to the next flow.
        continue;
      }
      // Front datagram doesn't fit in the remaining space.
      break;
    }
    sent = true;

    if (conn_.transportSettings.datagramConfig.framePerPacket) {
      break;
    }
  }
  return sent;
}

WindowUpdateScheduler::WindowUpdateScheduler(
    const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool WindowUpdateScheduler::hasPendingWindowUpdates() const {
  return conn_.streamManager->hasWindowUpdates() ||
      conn_.pendingEvents.connWindowUpdate;
}

quic::Expected<void, QuicError> WindowUpdateScheduler::writeWindowUpdates(
    PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.connWindowUpdate) {
    auto maxDataFrame = generateMaxDataFrame(conn_);
    auto maximumData = maxDataFrame.maximumData;
    auto bytesResult = writeFrame(std::move(maxDataFrame), builder);
    if (!bytesResult.has_value()) {
      return quic::make_unexpected(bytesResult.error());
    }
    if (bytesResult.value()) {
      MVVLOG(4) << "Wrote max_data=" << maximumData << " " << conn_;
    }
  }
  for (const auto& windowUpdateStream : conn_.streamManager->windowUpdates()) {
    auto stream = conn_.streamManager->findStream(windowUpdateStream);
    if (!stream) {
      continue;
    }
    auto maxStreamDataFrame = generateMaxStreamDataFrame(*stream);
    auto maximumData = maxStreamDataFrame.maximumData;
    auto bytesResult = writeFrame(std::move(maxStreamDataFrame), builder);
    if (!bytesResult.has_value()) {
      return quic::make_unexpected(bytesResult.error());
    }
    if (!bytesResult.value()) {
      break;
    }
    MVVLOG(4) << "Wrote max_stream_data stream=" << stream->id
              << " maximumData=" << maximumData << " " << conn_;
  }
  return {};
}

BlockedScheduler::BlockedScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool BlockedScheduler::hasPendingBlockedFrames() const {
  return !conn_.streamManager->blockedStreams().empty() ||
      conn_.pendingEvents.sendDataBlocked;
}

quic::Expected<void, QuicError> BlockedScheduler::writeBlockedFrames(
    PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.sendDataBlocked) {
    // Connection is write blocked due to connection level flow control.
    DataBlockedFrame blockedFrame(
        conn_.flowControlState.peerAdvertisedMaxOffset);
    auto result = writeFrame(blockedFrame, builder);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    if (!result.value()) {
      // If there is not enough room to write data blocked frame in the
      // current packet, we won't be able to write stream blocked frames either
      // so just return.
      return {};
    }
  }
  for (const auto& blockedStream : conn_.streamManager->blockedStreams()) {
    // Reconstruct frame from streamId (key) and offset (value)
    StreamDataBlockedFrame frame(blockedStream.first, blockedStream.second);
    auto bytesWrittenResult = writeFrame(frame, builder);
    if (!bytesWrittenResult.has_value()) {
      return quic::make_unexpected(bytesWrittenResult.error());
    }
    if (!bytesWrittenResult.value()) {
      break;
    }
  }
  return {};
}

CryptoStreamScheduler::CryptoStreamScheduler(
    const QuicConnectionStateBase& conn,
    QuicCryptoStream& cryptoStream)
    : conn_(conn), cryptoStream_(cryptoStream) {}

quic::Expected<bool, QuicError> CryptoStreamScheduler::writeCryptoData(
    PacketBuilderInterface& builder) {
  if (cryptoStream_.streamSendBuffer) {
    bool cryptoDataWritten = false;
    auto writeRange = [&](const StreamSendBuffer::SendRange& range)
        -> quic::Expected<bool, QuicError> {
      auto frameResult =
          writeCryptoFrameHeader(range.offset, range.len, builder);
      if (!frameResult.has_value()) {
        return quic::make_unexpected(frameResult.error());
      }
      if (!*frameResult) {
        return false;
      }
      auto writeResult = writeUnifiedCryptoData(
          builder,
          *cryptoStream_.streamSendBuffer,
          range.offset,
          (*frameResult)->len);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      return true;
    };

    if (auto loss = cryptoStream_.streamSendBuffer->nextLoss(
            std::numeric_limits<uint64_t>::max())) {
      auto result = writeRange(*loss);
      if (!result.has_value()) {
        return quic::make_unexpected(result.error());
      }
      if (!*result) {
        return false;
      }
      cryptoDataWritten = true;
    }

    if (auto newData = cryptoStream_.streamSendBuffer->nextNewData(
            std::numeric_limits<uint64_t>::max())) {
      auto result = writeRange(*newData);
      if (!result.has_value()) {
        return quic::make_unexpected(result.error());
      }
      cryptoDataWritten = cryptoDataWritten || *result;
    }
    return cryptoDataWritten;
  }

  bool cryptoDataWritten = false;
  uint64_t writableData = cryptoStream_.pendingWrites.chainLength();
  // We use the crypto scheduler to reschedule the retransmissions of the
  // crypto streams so that we know that retransmissions of the crypto data
  // will always take precedence over the crypto data.
  for (const auto& buffer : cryptoStream_.lossBuffer) {
    auto res = writeCryptoFrame(buffer.offset, buffer.data, builder);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    if (!res.value()) {
      return cryptoDataWritten;
    }
    MVVLOG(4) << "Wrote retransmitted crypto" << " offset=" << buffer.offset
              << " bytes=" << res.value()->len << " " << conn_;
    cryptoDataWritten = true;
  }

  if (writableData != 0) {
    auto res = writeCryptoFrame(
        cryptoStream_.currentWriteOffset, cryptoStream_.pendingWrites, builder);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    if (res.value()) {
      MVVLOG(4) << "Wrote crypto frame"
                << " offset=" << cryptoStream_.currentWriteOffset
                << " bytesWritten=" << res.value()->len << " " << conn_;
      cryptoDataWritten = true;
    }
  }
  return cryptoDataWritten;
}

bool CryptoStreamScheduler::hasData() const {
  if (cryptoStream_.streamSendBuffer) {
    return cryptoStream_.streamSendBuffer->hasPendingLoss() ||
        cryptoStream_.streamSendBuffer
            ->nextNewData(std::numeric_limits<uint64_t>::max())
            .has_value();
  }
  return !cryptoStream_.pendingWrites.empty() ||
      !cryptoStream_.lossBuffer.empty();
}

ImmediateAckFrameScheduler::ImmediateAckFrameScheduler(
    const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool ImmediateAckFrameScheduler::hasPendingImmediateAckFrame() const {
  return conn_.pendingEvents.requestImmediateAck;
}

bool ImmediateAckFrameScheduler::writeImmediateAckFrame(
    PacketBuilderInterface& builder) {
  auto result = writeFrame(ImmediateAckFrame(), builder);
  // We shouldn't ever error on an IMMEDIATE_ACK.
  MVCHECK(result.has_value());
  return result.value() != 0;
}

Optional<TimestampFrame> TimestampFrameScheduler::maybeGenerateTimestampFrame(
    const TimestampFramePacketObserver& packetObserver,
    bool hasPendingEligibleData) const {
  if ((!packetObserver.matchesPacketSelection(
           conn_.transportSettings.oneRttTimestampFramePacketSelection) &&
       !hasPendingEligibleData) ||
      !shouldWriteOneRttTimestampFrame(
          conn_, packetObserver.hasAckReceiveTimestamps())) {
    return std::nullopt;
  }
  return generateOneRttTimestampFrame(conn_);
}

quic::Expected<bool, QuicError> TimestampFrameScheduler::writeTimestampFrame(
    TimestampFrame frame,
    PacketBuilderInterface& builder) const {
  auto writeResult = writeFrame(frame, builder);
  if (writeResult.hasError()) {
    return quic::make_unexpected(writeResult.error());
  }
  return writeResult.value() != 0;
}

CloningScheduler::CloningScheduler(
    FrameScheduler& scheduler,
    QuicConnectionStateBase& conn,
    const folly::StringPiece name,
    uint64_t cipherOverhead,
    PacketTransmissionReason transmissionReason)
    : frameScheduler_(scheduler),
      conn_(conn),
      name_(name),
      cipherOverhead_(cipherOverhead),
      transmissionReason_(transmissionReason) {}

bool CloningScheduler::hasData() const {
  return frameScheduler_.hasData() || conn_.outstandings.numOutstanding() > 0;
}

quic::Expected<SchedulingResult, QuicError>
CloningScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  // Store header type information before any moves
  auto builderPnSpace = builder.getPacketHeader().getPacketNumberSpace();
  auto header = builder.getPacketHeader();
  // The writableBytes in this function shouldn't be limited by cwnd, since
  // we only use CloningScheduler for the cases that we want to bypass cwnd for
  // now.
  if (frameScheduler_.hasImmediateData()) {
    // If we have new ack-eliciting data to write, write that first.
    auto result = frameScheduler_.scheduleFramesForPacket(
        std::move(builder), writableBytes);
    if (result.has_value() && result->packet) {
      result->transmissionReason = transmissionReason_;
    }
    return result;
  }
  // The caller has already accounted for cipher overhead and may have
  // reserved datagram space outside the QUIC packet. Restore only the cipher
  // overhead when recreating the builder so those reservations are preserved.
  MVCHECK_LE(cipherOverhead_, std::numeric_limits<uint8_t>::max());
  const auto cipherOverhead = static_cast<uint8_t>(cipherOverhead_);
  MVCHECK_LE(
      builder.remainingSpaceInPkt(),
      std::numeric_limits<uint32_t>::max() - cipherOverhead);
  const uint32_t packetSizeLimit =
      builder.remainingSpaceInPkt() + cipherOverhead;
  MVDCHECK_LE(packetSizeLimit, conn_.udpSendPacketLen);
  // TODO: We can avoid the copy & rebuild of the header by creating an
  // independent header builder.
  std::move(builder).releaseOutputBuffer();
  // Look for an outstanding packet that's no larger than the writableBytes
  for (auto& outstandingPacket : conn_.outstandings.packets) {
    if (outstandingPacket.declaredLost) {
      continue;
    }
    auto opPnSpace = outstandingPacket.packet.header.getPacketNumberSpace();
    // Reusing the RegularQuicPacketBuilder throughout loop bodies will lead to
    // frames belong to different original packets being written into the same
    // clone packet. So re-create a RegularQuicPacketBuilder every time.
    // TODO: We can avoid the copy & rebuild of the header by creating an
    // independent header builder.
    if (opPnSpace != builderPnSpace) {
      continue;
    }
    size_t prevSize = 0;
    if (conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      prevSize = conn_.bufAccessor->length();
    }
    // Reusing the same builder throughout loop bodies will lead to frames
    // belong to different original packets being written into the same clone
    // packet. So re-create a builder every time.
    std::unique_ptr<PacketBuilderInterface> internalBuilder;
    if (conn_.transportSettings.dataPathType == DataPathType::ChainedMemory) {
      internalBuilder = std::make_unique<RegularQuicPacketBuilder>(
          packetSizeLimit,
          header,
          getPacketNumberEncodingBase(
              conn_, builderPnSpace, header.getPacketSequenceNum()));
    } else {
      MVCHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      if (conn_.bufAccessor->tailroom() < packetSizeLimit) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::INTERNAL_ERROR,
            "Insufficient ContinuousMemory buffer tailroom"));
      }
      internalBuilder = std::make_unique<InplaceQuicPacketBuilder>(
          *conn_.bufAccessor,
          packetSizeLimit,
          header,
          getPacketNumberEncodingBase(
              conn_, builderPnSpace, header.getPacketSequenceNum()));
    }
    // The packet is already a clone or has a clone outstanding
    if (outstandingPacket.maybeClonedPacketIdentifier) {
      // This packet has already been processed (acked/lost), no need to
      // clone it.
      if (conn_.outstandings.clonedPacketIdentifiers.count(
              *outstandingPacket.maybeClonedPacketIdentifier) == 0) {
        continue;
      }

      // Check if we've already cloned this packet in this write loop. We
      // don't need to clone it again.
      bool alreadyClonedThisWrite = [&]() -> bool {
        for (auto it = conn_.outstandings.packets.rbegin();
             it != conn_.outstandings.packets.rend();
             ++it) {
          // Break early if we've gone past the current write loop
          if (it->metadata.writeCount < conn_.writeCount) {
            return false;
          }
          if (it->metadata.writeCount == conn_.writeCount &&
              it->maybeClonedPacketIdentifier &&
              it->maybeClonedPacketIdentifier ==
                  outstandingPacket.maybeClonedPacketIdentifier) {
            return true;
          }
        }
        return false;
      }();

      if (alreadyClonedThisWrite) {
        continue;
      }
    }
    // I think this only fail if udpSendPacketLen somehow shrinks in the
    // middle of a connection.
    if (outstandingPacket.metadata.encodedSize >
        writableBytes + cipherOverhead_) {
      continue;
    }

    internalBuilder->accountForCipherOverhead(cipherOverhead);
    auto encodeRes = internalBuilder->encodePacketHeader();
    if (!encodeRes.has_value()) {
      return quic::make_unexpected(encodeRes.error());
    }
    PacketRebuilder rebuilder(*internalBuilder, conn_);

    // TODO: It's possible we write out a packet that's larger than the
    // packet size limit. For example, when the packet sequence number
    // has advanced to a point where we need more bytes to encoded it
    // than that of the original packet. In that case, if the original
    // packet is already at the packet size limit, we will generate a
    // packet larger than the limit. We can either ignore the problem,
    // hoping the packet will be able to travel the network just fine;
    // Or we can throw away the built packet and send a ping.

    // Rebuilder will write the rest of frames
    auto rebuildResultExpected = rebuilder.rebuildFromPacket(outstandingPacket);
    if (!rebuildResultExpected.has_value()) {
      return quic::make_unexpected(rebuildResultExpected.error());
    }
    if (rebuildResultExpected.value()) {
      return SchedulingResult(
          std::move(rebuildResultExpected.value()),
          std::move(*internalBuilder).buildPacket(),
          0,
          transmissionReason_);
    } else if (
        conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      // When we use Inplace packet building and reuse the write buffer,
      // even if the packet rebuild has failed, there might be some
      // bytes already written into the buffer and the buffer tail
      // pointer has already moved. We need to roll back the tail
      // pointer to the position before the packet building to exclude
      // those bytes. Otherwise these bytes will be sitting in between
      // legit packets inside the buffer and will either cause errors
      // further down the write path, or be sent out and then dropped at
      // peer when peer fail to parse them.
      internalBuilder.reset();
      MVCHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      conn_.bufAccessor->trimEnd(conn_.bufAccessor->length() - prevSize);
    }
  }
  return SchedulingResult(std::nullopt, std::nullopt, 0);
}

folly::StringPiece CloningScheduler::name() const {
  return name_;
}

CryptoPtoScheduler::CryptoPtoScheduler(
    FrameScheduler& scheduler,
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel,
    folly::StringPiece name,
    PacketTransmissionReason transmissionReason)
    : frameScheduler_(scheduler),
      conn_(conn),
      cryptoStream_(*getCryptoStream(*conn.cryptoState, encryptionLevel)),
      packetNumberSpace_(cryptoPacketNumberSpace(encryptionLevel)),
      name_(name),
      transmissionReason_(transmissionReason) {}

bool CryptoPtoScheduler::hasData() const {
  return true;
}

std::optional<StreamSendBuffer::SendRange>
CryptoPtoScheduler::nextUnselectedOutstanding(
    const StreamSendBuffer::SendRange& originalRange) const {
  if (!cryptoStream_.streamSendBuffer) {
    return std::nullopt;
  }
  return firstUnselectedCryptoRange(
      *cryptoStream_.streamSendBuffer, originalRange, selectedCryptoData_);
}

quic::Expected<SchedulingResult, QuicError>
CryptoPtoScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  if (frameScheduler_.hasImmediateData()) {
    auto result = frameScheduler_.scheduleFramesForPacket(
        std::move(builder), writableBytes);
    if (result.has_value() && result->packet) {
      result->transmissionReason = transmissionReason_;
    }
    return result;
  }

  if (builder.getPacketHeader().getPacketNumberSpace() != packetNumberSpace_) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "CryptoPtoScheduler used in the wrong packet number space"));
  }
  auto encodeResult = builder.encodePacketHeader();
  if (!encodeResult.has_value()) {
    return quic::make_unexpected(encodeResult.error());
  }
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  PacketBuilderWrapper wrapper(builder, writableBytes);
  bool wroteRetransmission = false;

  for (const auto& outstandingPacket : conn_.outstandings.packets) {
    if (outstandingPacket.declaredLost ||
        outstandingPacket.packet.header.getPacketNumberSpace() !=
            packetNumberSpace_) {
      continue;
    }
    for (const auto& frame : outstandingPacket.packet.frames) {
      switch (frame.type()) {
        case QuicWriteFrame::Type::WriteCryptoFrame: {
          const auto& cryptoFrame = *frame.asWriteCryptoFrame();
          auto sendRange = nextUnselectedOutstanding(
              {.offset = cryptoFrame.offset,
               .len = cryptoFrame.len,
               .fin = false});
          if (!sendRange) {
            break;
          }
          auto frameResult = writeCryptoFrameHeader(
              sendRange->offset, sendRange->len, wrapper);
          if (!frameResult.has_value()) {
            return quic::make_unexpected(frameResult.error());
          }
          if (!*frameResult) {
            break;
          }
          auto writeResult = writeUnifiedCryptoData(
              wrapper,
              *cryptoStream_.streamSendBuffer,
              sendRange->offset,
              (*frameResult)->len);
          if (!writeResult.has_value()) {
            return quic::make_unexpected(writeResult.error());
          }
          selectedCryptoData_.insert(
              sendRange->offset, sendRange->offset + (*frameResult)->len - 1);
          wroteRetransmission = true;
          break;
        }
        case QuicWriteFrame::Type::PaddingFrame:
        case QuicWriteFrame::Type::RstStreamFrame:
        case QuicWriteFrame::Type::ConnectionCloseFrame:
        case QuicWriteFrame::Type::MaxDataFrame:
        case QuicWriteFrame::Type::MaxStreamDataFrame:
        case QuicWriteFrame::Type::DataBlockedFrame:
        case QuicWriteFrame::Type::StreamDataBlockedFrame:
        case QuicWriteFrame::Type::StreamsBlockedFrame:
        case QuicWriteFrame::Type::WriteAckFrame:
        case QuicWriteFrame::Type::WriteStreamFrame:
        case QuicWriteFrame::Type::QuicSimpleFrame:
        case QuicWriteFrame::Type::PingFrame:
        case QuicWriteFrame::Type::NoopFrame:
        case QuicWriteFrame::Type::DatagramFrame:
        case QuicWriteFrame::Type::TimestampFrame:
        case QuicWriteFrame::Type::ImmediateAckFrame:
          break;
      }
      if (wroteRetransmission) {
        break;
      }
    }
    if (wroteRetransmission) {
      break;
    }
  }

  if (!wroteRetransmission) {
    auto pingResult = writeFrame(PingFrame(), wrapper);
    if (!pingResult.has_value()) {
      return quic::make_unexpected(pingResult.error());
    }
  }
  if (!builder.hasFramesPending()) {
    return SchedulingResult(std::nullopt, std::nullopt, 0);
  }
  return SchedulingResult(
      std::nullopt,
      std::move(builder).buildPacket(),
      0,
      transmissionReason_,
      wroteRetransmission);
}

folly::StringPiece CryptoPtoScheduler::name() const {
  return name_;
}

AppDataPtoScheduler::AppDataPtoScheduler(
    FrameScheduler& scheduler,
    QuicConnectionStateBase& conn,
    folly::StringPiece name,
    PacketTransmissionReason transmissionReason)
    : frameScheduler_(scheduler),
      conn_(conn),
      name_(name),
      transmissionReason_(transmissionReason) {}

bool AppDataPtoScheduler::hasData() const {
  return true;
}

std::optional<StreamSendBuffer::SendRange>
AppDataPtoScheduler::nextUnselectedOutstanding(
    const StreamSendBuffer& sendBuffer,
    StreamId streamId,
    const StreamSendBuffer::SendRange& originalRange) const {
  auto searchOffset = originalRange.offset;
  const auto originalEnd = originalRange.offset + originalRange.len;
  while (searchOffset <= originalEnd) {
    auto candidate = sendBuffer.firstOutstandingIn(
        {.offset = searchOffset,
         .len = originalEnd - searchOffset,
         .fin = originalRange.fin},
        std::numeric_limits<uint64_t>::max());
    if (!candidate) {
      return std::nullopt;
    }
    if (candidate->len == 0) {
      if (candidate->fin && !selectedStreamFin_.count(streamId)) {
        return candidate;
      }
      return std::nullopt;
    }

    const auto candidateEnd = candidate->offset + candidate->len;
    bool retry = false;
    const auto selectedIt = selectedStreamData_.find(streamId);
    if (selectedIt != selectedStreamData_.end()) {
      for (const auto& selected : selectedIt->second) {
        if (selected.end < candidate->offset) {
          continue;
        }
        if (selected.start >= candidateEnd) {
          break;
        }
        if (selected.start <= candidate->offset) {
          searchOffset = selected.end + 1;
          retry = true;
          break;
        }
        candidate->len = selected.start - candidate->offset;
        candidate->fin = false;
        break;
      }
    }
    if (retry) {
      continue;
    }
    if (candidate->fin && selectedStreamFin_.count(streamId)) {
      candidate->fin = false;
    }
    return candidate;
  }
  return std::nullopt;
}

std::optional<StreamSendBuffer::SendRange>
AppDataPtoScheduler::nextUnselectedCryptoOutstanding(
    const StreamSendBuffer& sendBuffer,
    const StreamSendBuffer::SendRange& originalRange) const {
  return firstUnselectedCryptoRange(
      sendBuffer, originalRange, selectedCryptoData_);
}

quic::Expected<SchedulingResult, QuicError>
AppDataPtoScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  if (frameScheduler_.hasImmediateData()) {
    auto result = frameScheduler_.scheduleFramesForPacket(
        std::move(builder), writableBytes);
    if (result.has_value() && result->packet) {
      result->transmissionReason = transmissionReason_;
    }
    return result;
  }

  if (builder.getPacketHeader().getPacketNumberSpace() !=
      PacketNumberSpace::AppData) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "AppDataPtoScheduler used outside the application-data packet number "
        "space"));
  }
  auto encodeResult = builder.encodePacketHeader();
  if (!encodeResult.has_value()) {
    return quic::make_unexpected(encodeResult.error());
  }
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  PacketBuilderWrapper wrapper(builder, writableBytes);
  bool wroteRetransmission = false;

  for (const auto& outstandingPacket : conn_.outstandings.packets) {
    if (outstandingPacket.declaredLost ||
        outstandingPacket.packet.header.getPacketNumberSpace() !=
            PacketNumberSpace::AppData) {
      continue;
    }
    bool wroteFromPacket = false;
    for (const auto& frame : outstandingPacket.packet.frames) {
      switch (frame.type()) {
        case QuicWriteFrame::Type::WriteStreamFrame: {
          const auto& streamFrame = *frame.asWriteStreamFrame();
          auto* stream = conn_.streamManager->findStream(streamFrame.streamId);
          if (!stream || !stream->streamSendBuffer ||
              streamRetransmissionDisabled(conn_, *stream)) {
            break;
          }
          auto sendRange = nextUnselectedOutstanding(
              *stream->streamSendBuffer,
              streamFrame.streamId,
              {.offset = streamFrame.offset,
               .len = streamFrame.len,
               .fin = streamFrame.fin});
          if (!sendRange) {
            break;
          }
          auto headerResult = writeStreamFrameHeader(
              wrapper,
              streamFrame.streamId,
              sendRange->offset,
              sendRange->len,
              sendRange->len,
              sendRange->fin,
              std::nullopt /* skipLenHint */);
          if (!headerResult.has_value()) {
            return quic::make_unexpected(headerResult.error());
          }
          if (!*headerResult) {
            break;
          }
          const auto dataLen = **headerResult;
          auto writeResult = writeUnifiedStreamData(
              wrapper, *stream->streamSendBuffer, sendRange->offset, dataLen);
          if (!writeResult.has_value()) {
            return quic::make_unexpected(writeResult.error());
          }
          if (dataLen > 0) {
            selectedStreamData_[streamFrame.streamId].insert(
                sendRange->offset, sendRange->offset + dataLen - 1);
          }
          if (sendRange->fin && dataLen == sendRange->len) {
            selectedStreamFin_.insert(streamFrame.streamId);
          }
          wroteRetransmission = true;
          wroteFromPacket = true;
          break;
        }
        case QuicWriteFrame::Type::WriteCryptoFrame: {
          const auto& cryptoFrame = *frame.asWriteCryptoFrame();
          auto* cryptoStream =
              getCryptoStream(*conn_.cryptoState, EncryptionLevel::AppData);
          if (!cryptoStream->streamSendBuffer) {
            break;
          }
          auto sendRange = nextUnselectedCryptoOutstanding(
              *cryptoStream->streamSendBuffer,
              {.offset = cryptoFrame.offset,
               .len = cryptoFrame.len,
               .fin = false});
          if (!sendRange) {
            break;
          }
          auto frameResult = writeCryptoFrameHeader(
              sendRange->offset, sendRange->len, wrapper);
          if (!frameResult.has_value()) {
            return quic::make_unexpected(frameResult.error());
          }
          if (!*frameResult) {
            break;
          }
          auto writeResult = writeUnifiedCryptoData(
              wrapper,
              *cryptoStream->streamSendBuffer,
              sendRange->offset,
              (*frameResult)->len);
          if (!writeResult.has_value()) {
            return quic::make_unexpected(writeResult.error());
          }
          selectedCryptoData_.insert(
              sendRange->offset, sendRange->offset + (*frameResult)->len - 1);
          wroteRetransmission = true;
          wroteFromPacket = true;
          break;
        }
        case QuicWriteFrame::Type::PaddingFrame:
        case QuicWriteFrame::Type::RstStreamFrame:
        case QuicWriteFrame::Type::ConnectionCloseFrame:
        case QuicWriteFrame::Type::MaxDataFrame:
        case QuicWriteFrame::Type::MaxStreamDataFrame:
        case QuicWriteFrame::Type::DataBlockedFrame:
        case QuicWriteFrame::Type::StreamDataBlockedFrame:
        case QuicWriteFrame::Type::StreamsBlockedFrame:
        case QuicWriteFrame::Type::WriteAckFrame:
        case QuicWriteFrame::Type::QuicSimpleFrame:
        case QuicWriteFrame::Type::PingFrame:
        case QuicWriteFrame::Type::NoopFrame:
        case QuicWriteFrame::Type::DatagramFrame:
        case QuicWriteFrame::Type::TimestampFrame:
        case QuicWriteFrame::Type::ImmediateAckFrame:
          break;
      }
    }
    if (wroteFromPacket) {
      break;
    }
  }

  if (!wroteRetransmission) {
    auto pingResult = writeFrame(PingFrame(), wrapper);
    if (!pingResult.has_value()) {
      return quic::make_unexpected(pingResult.error());
    }
  }
  if (!builder.hasFramesPending()) {
    return SchedulingResult(std::nullopt, std::nullopt, 0);
  }
  return SchedulingResult(
      std::nullopt,
      std::move(builder).buildPacket(),
      0,
      transmissionReason_,
      wroteRetransmission);
}

folly::StringPiece AppDataPtoScheduler::name() const {
  return name_;
}

} // namespace quic
