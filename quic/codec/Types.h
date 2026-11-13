/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/IPAddress.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/BufUtil.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/IntervalSet.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/NetworkData.h>
#include <quic/common/Optional.h>
#include <quic/common/Variant.h>
#include <quic/folly_utils/Utils.h>
#include <quic/mvfst-config.h>

/**
 * This details the types of objects that can be serialized or deserialized
 * over the wire.
 */

namespace quic {

using StreamId = uint64_t;

enum class PacketNumberSpace : uint8_t {
  Initial,
  Handshake,
  AppData,
  // MAX has to be updated whenever other enumerators are added to this enum
  MAX = PacketNumberSpace::AppData
};

enum class TokenType : uint8_t { RetryToken = 0, NewToken };

constexpr uint8_t kHeaderFormMask = 0x80;
constexpr auto kMaxPacketNumEncodingSize = 4;
constexpr auto kNumInitialAckBlocksPerFrame = 3;

template <class T>
using IntervalSetVec = SmallVec<T, kNumInitialAckBlocksPerFrame>;
using AckBlocks = IntervalSet<PacketNum, 1, IntervalSetVec>;

struct PaddingFrame {
  // How many contiguous padding frames this represents.
  uint16_t numFrames{1};

  bool operator==(const PaddingFrame& rhs) const {
    return numFrames == rhs.numFrames;
  }
};

struct PingFrame {
  PingFrame() = default;

  bool operator==(const PingFrame& /*rhs*/) const {
    return true;
  }
};

struct KnobFrame {
  KnobFrame(uint64_t knobSpaceIn, uint64_t idIn, BufPtr blobIn)
      : knobSpace(knobSpaceIn), id(idIn), blob(std::move(blobIn)) {
    len = blob->length();
  }

  bool operator==(const KnobFrame& rhs) const {
    return knobSpace == rhs.knobSpace && id == rhs.id && len == rhs.len &&
        blob->length() == rhs.blob->length() &&
        memcmp(blob->data(), rhs.blob->data(), blob->length()) == 0;
  }

  KnobFrame& operator=(const KnobFrame& other) {
    knobSpace = other.knobSpace;
    id = other.id;
    if (other.blob) {
      blob = other.blob->clone();
    }
    return *this;
  }

  KnobFrame& operator=(KnobFrame&& other) noexcept {
    knobSpace = other.knobSpace;
    id = other.id;
    if (other.blob) {
      blob = std::move(other.blob);
    }
    return *this;
  }

  KnobFrame(const KnobFrame& other)
      : knobSpace(other.knobSpace),
        id(other.id),
        len(other.len),
        blob(other.blob->clone()) {}

  KnobFrame(KnobFrame&& other) noexcept
      : knobSpace(other.knobSpace),
        id(other.id),
        len(other.len),
        blob(std::move(other.blob)) {}

  uint64_t knobSpace;
  uint64_t id;
  uint64_t len;
  BufPtr blob;
};

struct AckFrequencyFrame {
  uint64_t sequenceNumber; // Used to identify newest.
  uint64_t packetTolerance; // How many packets before ACKing.
  uint64_t updateMaxAckDelay; // New max_ack_delay to use.
  uint64_t reorderThreshold; // New out-of-order packet threshold before ACKing.

  bool operator==(const AckFrequencyFrame& other) const {
    return other.sequenceNumber == sequenceNumber &&
        other.packetTolerance == packetTolerance &&
        other.updateMaxAckDelay == updateMaxAckDelay &&
        other.reorderThreshold == reorderThreshold;
  }
};

struct ImmediateAckFrame {
  ImmediateAckFrame() = default;

  bool operator==(const ImmediateAckFrame& /*rhs*/) const {
    return true;
  }
};

struct TimestampFrame {
  explicit TimestampFrame(uint64_t timestampIn = 0) : timestamp(timestampIn) {}

  bool operator==(const TimestampFrame& rhs) const {
    return timestamp == rhs.timestamp;
  }

  uint64_t timestamp;
};

/**
 * AckBlock represents a series of continuous packet sequences from
 * [startPacket, endPacket]
 */
struct AckBlock {
  PacketNum startPacket;
  PacketNum endPacket;

  AckBlock(PacketNum start, PacketNum end)
      : startPacket(start), endPacket(end) {}
};

struct RecvdPacketsTimestampsRange {
  uint64_t gap;
  uint64_t timestamp_delta_count;
  std::vector<uint64_t> deltas;
};

using RecvdPacketsTimestampsRangeVec = std::vector<RecvdPacketsTimestampsRange>;

// draft-ietf-quic-receive-ts-02 timestamp range. `deltaLargestAcknowledged`
// is a per-range delta from the ACK frame's `Largest Acknowledged`, not a
// chained gap from the previous range.
struct Draft02ReceiveTimestampsRange {
  uint64_t deltaLargestAcknowledged{};
  uint64_t timestamp_delta_count{};
  std::vector<uint64_t> deltas;
};

using Draft02ReceiveTimestampsRangeVec =
    std::vector<Draft02ReceiveTimestampsRange>;

/**
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Largest Acknowledged (i)                ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          ACK Delay (i)                      ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       ACK Block Count (i)                   ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          ACK Blocks (*)                     ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      First ACK Block (i)                    ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             Gap (i)                         ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Additional ACK Block (i)                 ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ReadAckFrame {
  PacketNum largestAcked;
  std::chrono::microseconds ackDelay{0us};
  // Only true for the special case of packet number space dropping.
  bool implicit{false};
  // Should have at least 1 block.
  // These are ordered in descending order by start packet.
  using Vec = SmallVec<AckBlock, kNumInitialAckBlocksPerFrame>;
  Vec ackBlocks;
  FrameType frameType = FrameType::ACK;
  OptionalMicros maybeLatestRecvdPacketTime;
  OptionalIntegral<PacketNum> maybeLatestRecvdPacketNum;
  RecvdPacketsTimestampsRangeVec recvdPacketsTimestampRanges;
  // Disambiguates legacy `gap` semantics from draft-02
  // `Delta Largest Acknowledged`. Only one of `recvdPacketsTimestampRanges`
  // (legacy) or `draft02RecvdPacketsTimestampRanges` is populated per frame.
  AckReceiveTimestampsVersion timestampsVersion{
      AckReceiveTimestampsVersion::None};
  Draft02ReceiveTimestampsRangeVec draft02RecvdPacketsTimestampRanges;
  uint64_t ecnECT0Count{0};
  uint64_t ecnECT1Count{0};
  uint64_t ecnCECount{0};

  bool operator==(const ReadAckFrame& /*rhs*/) const {
    // Can't compare ackBlocks, function is just here to appease compiler.
    return false;
  }
};

struct WriteAckFrame {
  // Since we don't need this to be an IntervalSet, they are stored directly
  // in a vector, in reverse order.
  using AckBlockVec = std::vector<Interval<PacketNum>>;
  AckBlockVec ackBlocks;
  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay{0us};
  FrameType frameType = FrameType::ACK;
  OptionalMicros maybeLatestRecvdPacketTime;
  OptionalIntegral<PacketNum> maybeLatestRecvdPacketNum;
  RecvdPacketsTimestampsRangeVec recvdPacketsTimestampRanges;
  // Only the matching range vector (legacy or draft-02) is populated.
  AckReceiveTimestampsVersion timestampsVersion{
      AckReceiveTimestampsVersion::None};
  Draft02ReceiveTimestampsRangeVec draft02RecvdPacketsTimestampRanges;
  uint64_t ecnECT0Count{0};
  uint64_t ecnECT1Count{0};
  uint64_t ecnCECount{0};

  bool operator==(const WriteAckFrame& /*rhs*/) const {
    // Can't compare ackBlocks, function is just here to appease compiler.
    return false;
  }
};

struct WriteAckFrameState {
  /**
   * Info stored on receipt of a packet for use in subsequent ACK.
   */
  struct ReceivedPacket {
    PacketNum pktNum;
    ReceivedUdpPacket::Timings timings;

    ReceivedPacket() = default;

    template <typename TimingsType>
    ReceivedPacket(PacketNum pktNumIn, TimingsType&& timingsIn)
        : pktNum(pktNumIn), timings(std::forward<TimingsType>(timingsIn)) {}

    ReceivedPacket(const ReceivedPacket&) = delete;
    ReceivedPacket(ReceivedPacket&&) = default;
    ReceivedPacket& operator=(const ReceivedPacket&) = delete;
    ReceivedPacket& operator=(ReceivedPacket&&) = default;
    ~ReceivedPacket() = default;
  };

  AckBlocks acks;

  // Receive timestamp and packet number for the largest received packet.
  //
  // Updated whenever we receive a packet with a larger packet number
  // than all previously received packets in the packet number space
  // tracked by this AckState.
  Optional<ReceivedPacket> largestRecvdPacketInfo;

  // Receive timestamp and packet number for the last received packet.
  //
  // Will be different from the value stored in largestRecvdPacketInfo
  // if the last packet was received out of order and thus had a packet
  // number less than that of a previously received packet in the packet
  // number space tracked by this AckState.
  Optional<ReceivedPacket> lastRecvdPacketInfo;

  // Bounded arrival-order storage of non-duplicate received packets. Packet
  // numbers AND receive times may both be non-monotonic; out-of-order receipt
  // is supported per draft-ietf-quic-receive-ts-02. Encoders sort and filter
  // this deque at write time to satisfy their wire-format constraints
  // (legacy keeps the strictly-decreasing-pktnum subsequence of the
  // time-desc-sorted view; draft-02 sorts by receive-time desc then groups
  // by pktnum contiguity). Bounded by
  // `TransportSettings::maxReceiveTimestampsPerAckStored`.
  CircularDeque<ReceivedPacket> recvdPacketInfos;
  // The count of ECN marks seen on received packets.
  uint64_t ecnECT0CountReceived{0};
  uint64_t ecnECT1CountReceived{0};
  uint64_t ecnCECountReceived{0};
};

struct WriteAckFrameMetaData {
  // ACK state.
  const WriteAckFrameState& ackState;

  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay;
  // The ack delay exponent to use.
  uint8_t ackDelayExponent;

  // Receive timestamps basis
  TimePoint connTime;
};

struct WriteAckFrameResult {
  uint64_t bytesWritten;
  WriteAckFrame writeAckFrame;
  // This includes the first ack block
  size_t ackBlocksWritten;
  size_t timestampRangesWritten;
  size_t timestampsWritten;
  uint64_t extendedAckFeaturesEnabled;

  WriteAckFrameResult(
      uint64_t bytesWrittenIn,
      WriteAckFrame writeAckFrameIn,
      size_t ackBlocksWrittenIn,
      size_t timestampRangesWrittenIn = 0,
      size_t timestampsWrittenIn = 0,
      uint64_t extendedAckFeaturesEnabledIn = 0)
      : bytesWritten(bytesWrittenIn),
        writeAckFrame(std::move(writeAckFrameIn)),
        ackBlocksWritten(ackBlocksWrittenIn),
        timestampRangesWritten(timestampRangesWrittenIn),
        timestampsWritten(timestampsWrittenIn),
        extendedAckFeaturesEnabled(extendedAckFeaturesEnabledIn) {}
};

// Can represent either a simple RESET_STREAM frame or a RESET_STREAM_AT
// frame, depending on whether reliableSize is set.
struct RstStreamFrame {
  StreamId streamId;
  ApplicationErrorCode errorCode;
  uint64_t finalSize;
  Optional<uint64_t> reliableSize;

  RstStreamFrame(
      StreamId streamIdIn,
      ApplicationErrorCode errorCodeIn,
      uint64_t finalSizeIn,
      Optional<uint64_t> reliableSizeIn = std::nullopt)
      : streamId(streamIdIn),
        errorCode(errorCodeIn),
        finalSize(finalSizeIn),
        reliableSize(reliableSizeIn) {}

  bool operator==(const RstStreamFrame& rhs) const {
    return streamId == rhs.streamId && errorCode == rhs.errorCode &&
        finalSize == rhs.finalSize && reliableSize == rhs.reliableSize;
  }
};

struct StopSendingFrame {
  StreamId streamId;
  ApplicationErrorCode errorCode;

  StopSendingFrame(StreamId streamIdIn, ApplicationErrorCode errorCodeIn)
      : streamId(streamIdIn), errorCode(errorCodeIn) {}

  bool operator==(const StopSendingFrame& rhs) const {
    return streamId == rhs.streamId && errorCode == rhs.errorCode;
  }
};

struct ReadCryptoFrame {
  uint64_t offset;
  BufPtr data;

  ReadCryptoFrame(uint64_t offsetIn, BufPtr dataIn)
      : offset(offsetIn), data(std::move(dataIn)) {}

  explicit ReadCryptoFrame(uint64_t offsetIn)
      : offset(offsetIn), data(BufHelpers::create(0)) {}

  // Stuff stored in a variant type needs to be copyable.
  ReadCryptoFrame(const ReadCryptoFrame& other) {
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
  }

  ReadCryptoFrame(ReadCryptoFrame&& other) noexcept {
    offset = other.offset;
    data = std::move(other.data);
  }

  ReadCryptoFrame& operator=(const ReadCryptoFrame& other) {
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    return *this;
  }

  ReadCryptoFrame& operator=(ReadCryptoFrame&& other) noexcept {
    offset = other.offset;
    data = std::move(other.data);
    return *this;
  }

  bool operator==(const ReadCryptoFrame& other) const {
    BufEq eq;
    return offset == other.offset && eq(data, other.data);
  }
};

struct WriteCryptoFrame {
  uint64_t offset;
  uint64_t len;

  WriteCryptoFrame(uint64_t offsetIn, uint64_t lenIn)
      : offset(offsetIn), len(lenIn) {}

  bool operator==(const WriteCryptoFrame& rhs) const {
    return offset == rhs.offset && len == rhs.len;
  }
};

struct NewTokenFrame {
  BufPtr token;

  explicit NewTokenFrame(BufPtr tokenIn) : token(std::move(tokenIn)) {}

  NewTokenFrame(const NewTokenFrame& other) {
    if (other.token) {
      token = other.token->clone();
    }
  }

  NewTokenFrame(NewTokenFrame&& other) noexcept = default;
  NewTokenFrame& operator=(NewTokenFrame&& other) noexcept = default;

  bool operator==(const NewTokenFrame& rhs) const {
    BufEq eq;
    return eq(token, rhs.token);
  }
};

struct ReadNewTokenFrame {
  BufPtr token;

  ReadNewTokenFrame(BufPtr tokenIn) : token(std::move(tokenIn)) {}

  // Stuff stored in a variant type needs to be copyable.
  ReadNewTokenFrame(const ReadNewTokenFrame& other) {
    if (other.token) {
      token = other.token->clone();
    }
  }

  ReadNewTokenFrame(ReadNewTokenFrame&& other) noexcept = default;

  ReadNewTokenFrame& operator=(const ReadNewTokenFrame& other) {
    if (other.token) {
      token = other.token->clone();
    }
    return *this;
  }

  ReadNewTokenFrame& operator=(ReadNewTokenFrame&& other) noexcept = default;

  bool operator==(const ReadNewTokenFrame& other) const {
    BufEq eq;
    return eq(token, other.token);
  }
};

/**
 The structure of the stream frame used for writes.
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Stream ID (i)                       ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         [Offset (i)]                        ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         [Length (i)]                        ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Stream Data (*)                      ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct WriteStreamFrame {
  // How mvfst sent this frame's bytes. updateConnection records it when the
  // packet is sent; it is not part of the wire format or of frame equality.
  enum class Origin : uint8_t {
    // First transmission of these bytes.
    NewData,
    // Bytes resent from the loss buffer after they were declared lost.
    LossRetransmission,
    // Bytes copied into a cloned packet.
    Clone,
    // Outstanding bytes resent as a non-cloning PTO probe.
    PtoRetransmission,
  };

  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;
  Origin origin{Origin::NewData};

  WriteStreamFrame(
      StreamId streamIdIn,
      uint64_t offsetIn,
      uint64_t lenIn,
      bool finIn)
      : streamId(streamIdIn), offset(offsetIn), len(lenIn), fin(finIn) {}

  bool operator==(const WriteStreamFrame& rhs) const {
    return streamId == rhs.streamId && offset == rhs.offset && len == rhs.len &&
        fin == rhs.fin;
  }
};

namespace detail {
// WriteStreamFrame's members other than `origin`, in declaration order.
struct WriteStreamFrameWithoutOrigin {
  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;
};
} // namespace detail

// `origin` occupies padding after `fin`, so it does not grow the frame on any
// target, whatever the alignment of 64-bit members.
static_assert(
    sizeof(WriteStreamFrame) == sizeof(detail::WriteStreamFrameWithoutOrigin));

/**
 * The structure of the stream frame used for reads.
 */
struct ReadStreamFrame {
  StreamId streamId;
  uint64_t offset;
  BufPtr data;
  bool fin;

  ReadStreamFrame(
      StreamId streamIdIn,
      uint64_t offsetIn,
      BufPtr dataIn,
      bool finIn)
      : streamId(streamIdIn),
        offset(offsetIn),
        data(std::move(dataIn)),
        fin(finIn) {}

  ReadStreamFrame(StreamId streamIdIn, uint64_t offsetIn, bool finIn)
      : streamId(streamIdIn),
        offset(offsetIn),
        data(BufHelpers::create(0)),
        fin(finIn) {}

  // Stuff stored in a variant type needs to be copyable.
  ReadStreamFrame(const ReadStreamFrame& other) {
    streamId = other.streamId;
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    fin = other.fin;
  }

  ReadStreamFrame(ReadStreamFrame&& other) noexcept {
    streamId = other.streamId;
    offset = other.offset;
    data = std::move(other.data);
    fin = other.fin;
  }

  ReadStreamFrame& operator=(const ReadStreamFrame& other) {
    streamId = other.streamId;
    offset = other.offset;
    if (other.data) {
      data = other.data->clone();
    }
    fin = other.fin;
    return *this;
  }

  ReadStreamFrame& operator=(ReadStreamFrame&& other) {
    streamId = other.streamId;
    offset = other.offset;
    data = std::move(other.data);
    fin = other.fin;
    return *this;
  }

  bool operator==(const ReadStreamFrame& other) const {
    BufEq eq;
    return streamId == other.streamId && offset == other.offset &&
        fin == other.fin && eq(data, other.data);
  }
};

struct MaxDataFrame {
  uint64_t maximumData;

  explicit MaxDataFrame(uint64_t maximumDataIn) : maximumData(maximumDataIn) {}

  bool operator==(const MaxDataFrame& rhs) const {
    return maximumData == rhs.maximumData;
  }
};

struct MaxStreamDataFrame {
  StreamId streamId;
  uint64_t maximumData;

  MaxStreamDataFrame(StreamId streamIdIn, uint64_t maximumDataIn)
      : streamId(streamIdIn), maximumData(maximumDataIn) {}

  bool operator==(const MaxStreamDataFrame& rhs) const {
    return streamId == rhs.streamId && maximumData == rhs.maximumData;
  }
};

struct MaxStreamsFrame {
  // A count of the cumulative number of streams
  uint64_t maxStreams;
  bool isForBidirectional{false};

  explicit MaxStreamsFrame(uint64_t maxStreamsIn, bool isBidirectionalIn)
      : maxStreams(maxStreamsIn), isForBidirectional(isBidirectionalIn) {}

  [[nodiscard]] bool isForBidirectionalStream() const {
    return isForBidirectional;
  }

  bool isForUnidirectionalStream() {
    return !isForBidirectional;
  }

  bool operator==(const MaxStreamsFrame& rhs) const {
    return maxStreams == rhs.maxStreams &&
        isForBidirectional == rhs.isForBidirectional;
  }
};

struct DataBlockedFrame {
  // the connection-level limit at which blocking occurred
  uint64_t dataLimit;

  explicit DataBlockedFrame(uint64_t dataLimitIn) : dataLimit(dataLimitIn) {}

  bool operator==(const DataBlockedFrame& rhs) const {
    return dataLimit == rhs.dataLimit;
  }
};

struct StreamDataBlockedFrame {
  StreamId streamId;
  uint64_t dataLimit;

  StreamDataBlockedFrame(StreamId streamIdIn, uint64_t dataLimitIn)
      : streamId(streamIdIn), dataLimit(dataLimitIn) {}

  bool operator==(const StreamDataBlockedFrame& rhs) const {
    return streamId == rhs.streamId && dataLimit == rhs.dataLimit;
  }
};

struct StreamsBlockedFrame {
  uint64_t streamLimit;
  bool isForBidirectional{false};

  explicit StreamsBlockedFrame(uint64_t streamLimitIn, bool isBidirectionalIn)
      : streamLimit(streamLimitIn), isForBidirectional(isBidirectionalIn) {}

  [[nodiscard]] bool isForBidirectionalStream() const {
    return isForBidirectional;
  }

  [[nodiscard]] bool isForUnidirectionalStream() const {
    return !isForBidirectional;
  }

  bool operator==(const StreamsBlockedFrame& rhs) const {
    return streamLimit == rhs.streamLimit;
  }
};

struct NewConnectionIdFrame {
  uint64_t sequenceNumber;
  uint64_t retirePriorTo;
  ConnectionId connectionId;
  StatelessResetToken token;

  NewConnectionIdFrame(
      uint64_t sequenceNumberIn,
      uint64_t retirePriorToIn,
      ConnectionId connectionIdIn,
      StatelessResetToken tokenIn)
      : sequenceNumber(sequenceNumberIn),
        retirePriorTo(retirePriorToIn),
        connectionId(connectionIdIn),
        token(std::move(tokenIn)) {}

  bool operator==(const NewConnectionIdFrame& rhs) const {
    return sequenceNumber == rhs.sequenceNumber &&
        retirePriorTo == rhs.retirePriorTo &&
        connectionId == rhs.connectionId && token == rhs.token;
  }
};

struct RetireConnectionIdFrame {
  uint64_t sequenceNumber;

  explicit RetireConnectionIdFrame(uint64_t sequenceNumberIn)
      : sequenceNumber(sequenceNumberIn) {}

  bool operator==(const RetireConnectionIdFrame& rhs) const {
    return sequenceNumber == rhs.sequenceNumber;
  }
};

struct PathChallengeFrame {
  uint64_t pathData;

  explicit PathChallengeFrame(uint64_t pathDataIn) : pathData(pathDataIn) {}

  bool operator==(const PathChallengeFrame& rhs) const {
    return pathData == rhs.pathData;
  }

  bool operator!=(const PathChallengeFrame& rhs) const {
    return !(*this == rhs);
  }
};

struct PathResponseFrame {
  uint64_t pathData;

  explicit PathResponseFrame(uint64_t pathDataIn) : pathData(pathDataIn) {}

  bool operator==(const PathResponseFrame& rhs) const {
    return pathData == rhs.pathData;
  }
};

struct ConnectionCloseFrame {
  // Members are not const to allow this to be movable.
  QuicErrorCode errorCode;
  std::string reasonPhrase;
  // Per QUIC specification: type of frame that triggered the (close) error.
  // A value of 0 (PADDING frame) implies the frame type is unknown
  FrameType closingFrameType;

  ConnectionCloseFrame(
      QuicErrorCode errorCodeIn,
      std::string reasonPhraseIn,
      FrameType closingFrameTypeIn = FrameType::PADDING)
      : errorCode(std::move(errorCodeIn)),
        reasonPhrase(std::move(reasonPhraseIn)),
        closingFrameType(closingFrameTypeIn) {}

  [[nodiscard]] FrameType getClosingFrameType() const noexcept {
    return closingFrameType;
  }

  bool operator==(const ConnectionCloseFrame& rhs) const {
    return errorCode == rhs.errorCode && reasonPhrase == rhs.reasonPhrase;
  }
};

struct HandshakeDoneFrame {
  bool operator==(const HandshakeDoneFrame& /*rhs*/) const {
    return true;
  }
};

struct DatagramFrame {
  size_t length;
  Optional<size_t> encodedSize;
  BufQueue data;

  explicit DatagramFrame(size_t len, BufPtr buf)
      : length(len), data(std::move(buf)) {
    MVCHECK_EQ(length, data.chainLength());
  }

  DatagramFrame(size_t len, size_t encodedSizeIn, BufPtr buf)
      : length(len), encodedSize(encodedSizeIn), data(std::move(buf)) {
    MVCHECK_EQ(length, data.chainLength());
  }

  // Variant requirement:
  DatagramFrame(const DatagramFrame& other)
      : length(other.length),
        encodedSize(other.encodedSize),
        data(other.data.front() ? other.data.front()->clone() : nullptr) {
    MVCHECK_EQ(length, data.chainLength());
  }

  DatagramFrame(DatagramFrame&& other) noexcept = default;
  DatagramFrame& operator=(DatagramFrame&& other) noexcept = default;

  bool operator==(const DatagramFrame& other) const {
    if (length != other.length) {
      return false;
    }
    if (data.empty() && other.data.empty()) {
      return true;
    }
    MVCHECK(data.front() && other.data.front());
    BufEq eq;
    return eq(*data.front(), *other.data.front());
  }
};

// Frame to represent ones we skip
struct NoopFrame {
  bool operator==(const NoopFrame&) const {
    return true;
  }
};

struct StatelessReset {
  StatelessResetToken token;

  explicit StatelessReset(StatelessResetToken tokenIn)
      : token(std::move(tokenIn)) {}
};

struct QuicAddrValidationToken {
  QuicAddrValidationToken(folly::IPAddress clientIpIn, uint64_t timestampInMsIn)
      : clientIp(clientIpIn), timestampInMs(timestampInMsIn) {}

  QuicAddrValidationToken(const QuicAddrValidationToken& other) = default;

  QuicAddrValidationToken& operator=(const QuicAddrValidationToken& other) =
      default;

  [[nodiscard]] virtual BufPtr getPlaintextToken() const;
  [[nodiscard]] virtual TokenType getTokenType() const = 0;
  [[nodiscard]] virtual BufPtr genAeadAssocData() const = 0;
  virtual ~QuicAddrValidationToken() = default;

  folly::IPAddress clientIp;
  uint64_t timestampInMs;
};

struct RetryToken : QuicAddrValidationToken {
  RetryToken(
      ConnectionId originalDstConnIdIn,
      folly::IPAddress clientIpIn,
      uint16_t clientPortIn,
      uint64_t timestampInMsIn =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count())
      : QuicAddrValidationToken(clientIpIn, timestampInMsIn),
        originalDstConnId(originalDstConnIdIn),
        clientPort(clientPortIn) {}

  RetryToken(const RetryToken& other) = default;

  RetryToken& operator=(const RetryToken& other) = default;

  [[nodiscard]] TokenType getTokenType() const override {
    return tokenType;
  }

  [[nodiscard]] BufPtr getPlaintextToken() const override;

  [[nodiscard]] BufPtr genAeadAssocData() const override;

  ConnectionId originalDstConnId;
  uint16_t clientPort;
  // Source connection id of the Retry, set when it differs from
  // originalDstConnId. The token is then bound to this id instead, and carries
  // originalDstConnId in its plaintext.
  Optional<ConnectionId> retrySrcConnId;

  static constexpr TokenType tokenType = TokenType::RetryToken;
};

struct NewToken : QuicAddrValidationToken {
  explicit NewToken(
      folly::IPAddress clientIpIn,
      uint64_t timestampInMsIn =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count())
      : QuicAddrValidationToken(clientIpIn, timestampInMsIn) {}

  NewToken(const NewToken& other) = default;

  NewToken& operator=(const NewToken& other) = default;

  [[nodiscard]] TokenType getTokenType() const override {
    return tokenType;
  }

  [[nodiscard]] BufPtr genAeadAssocData() const override;

  bool operator==(const NewToken& other) const {
    return clientIp == other.clientIp && timestampInMs == other.timestampInMs;
  }

  static constexpr TokenType tokenType = TokenType::NewToken;
};

#define QUIC_SIMPLE_FRAME(F, ...)         \
  F(StopSendingFrame, __VA_ARGS__)        \
  F(PathChallengeFrame, __VA_ARGS__)      \
  F(PathResponseFrame, __VA_ARGS__)       \
  F(NewConnectionIdFrame, __VA_ARGS__)    \
  F(MaxStreamsFrame, __VA_ARGS__)         \
  F(RetireConnectionIdFrame, __VA_ARGS__) \
  F(HandshakeDoneFrame, __VA_ARGS__)      \
  F(KnobFrame, __VA_ARGS__)               \
  F(AckFrequencyFrame, __VA_ARGS__)       \
  F(NewTokenFrame, __VA_ARGS__)

DECLARE_VARIANT_TYPE(QuicSimpleFrame, QUIC_SIMPLE_FRAME)

#define QUIC_FRAME(F, ...)               \
  F(PaddingFrame, __VA_ARGS__)           \
  F(RstStreamFrame, __VA_ARGS__)         \
  F(ConnectionCloseFrame, __VA_ARGS__)   \
  F(MaxDataFrame, __VA_ARGS__)           \
  F(MaxStreamDataFrame, __VA_ARGS__)     \
  F(DataBlockedFrame, __VA_ARGS__)       \
  F(StreamDataBlockedFrame, __VA_ARGS__) \
  F(StreamsBlockedFrame, __VA_ARGS__)    \
  F(ReadAckFrame, __VA_ARGS__)           \
  F(ReadStreamFrame, __VA_ARGS__)        \
  F(ReadCryptoFrame, __VA_ARGS__)        \
  F(ReadNewTokenFrame, __VA_ARGS__)      \
  F(QuicSimpleFrame, __VA_ARGS__)        \
  F(PingFrame, __VA_ARGS__)              \
  F(NoopFrame, __VA_ARGS__)              \
  F(DatagramFrame, __VA_ARGS__)          \
  F(TimestampFrame, __VA_ARGS__)         \
  F(ImmediateAckFrame, __VA_ARGS__)

DECLARE_VARIANT_TYPE(QuicFrame, QUIC_FRAME)

#define QUIC_WRITE_FRAME(F, ...)         \
  F(PaddingFrame, __VA_ARGS__)           \
  F(RstStreamFrame, __VA_ARGS__)         \
  F(ConnectionCloseFrame, __VA_ARGS__)   \
  F(MaxDataFrame, __VA_ARGS__)           \
  F(MaxStreamDataFrame, __VA_ARGS__)     \
  F(DataBlockedFrame, __VA_ARGS__)       \
  F(StreamDataBlockedFrame, __VA_ARGS__) \
  F(StreamsBlockedFrame, __VA_ARGS__)    \
  F(WriteAckFrame, __VA_ARGS__)          \
  F(WriteStreamFrame, __VA_ARGS__)       \
  F(WriteCryptoFrame, __VA_ARGS__)       \
  F(QuicSimpleFrame, __VA_ARGS__)        \
  F(PingFrame, __VA_ARGS__)              \
  F(NoopFrame, __VA_ARGS__)              \
  F(DatagramFrame, __VA_ARGS__)          \
  F(TimestampFrame, __VA_ARGS__)         \
  F(ImmediateAckFrame, __VA_ARGS__)

// Types of frames which are written.
DECLARE_VARIANT_TYPE(QuicWriteFrame, QUIC_WRITE_FRAME)

enum class HeaderForm : uint8_t {
  Short = 0,
  Long = 1,
};

enum class ProtectionType {
  Initial,
  Handshake,
  ZeroRtt,
  KeyPhaseZero,
  KeyPhaseOne,
};

struct LongHeaderInvariant {
  QuicVersion version;
  ConnectionId srcConnId;
  ConnectionId dstConnId;

  LongHeaderInvariant(QuicVersion ver, ConnectionId scid, ConnectionId dcid);
};

struct LongHeader {
 public:
  virtual ~LongHeader() = default;

  static constexpr uint8_t kFixedBitMask = 0x40;
  static constexpr uint8_t kPacketTypeMask = 0x30;
  static constexpr uint8_t kReservedBitsMask = 0x0c;
  static constexpr uint8_t kPacketNumLenMask = 0x03;
  static constexpr uint8_t kTypeBitsMask = 0x0F;

  static constexpr uint8_t kTypeShift = 4;
  enum class Types : uint8_t {
    Initial = 0x0,
    ZeroRtt = 0x1,
    Handshake = 0x2,
    Retry = 0x3,
  };

  // Note this is defined in the header so it is inlined for performance.
  static PacketNumberSpace typeToPacketNumberSpace(Types longHeaderType) {
    switch (longHeaderType) {
      case LongHeader::Types::Initial:
      case LongHeader::Types::Retry:
        return PacketNumberSpace::Initial;
      case LongHeader::Types::Handshake:
        return PacketNumberSpace::Handshake;
      case LongHeader::Types::ZeroRtt:
        return PacketNumberSpace::AppData;
      default:
        break;
    }
    folly::assume_unreachable();
  }

  LongHeader(
      Types type,
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      PacketNum packetNum,
      QuicVersion version,
      std::string token = "");

  LongHeader(Types type, LongHeaderInvariant invariant, std::string token = "");

  LongHeader(const LongHeader& other)
      : packetSequenceNum_(other.packetSequenceNum_),
        longHeaderType_(other.longHeaderType_),
        invariant_(std::make_unique<LongHeaderInvariant>(*other.invariant_)),
        token_(
            other.token_ ? std::make_unique<std::string>(*other.token_)
                         : nullptr) {}

  LongHeader(LongHeader&& other) = default;

  LongHeader& operator=(const LongHeader& other) {
    packetSequenceNum_ = other.packetSequenceNum_;
    longHeaderType_ = other.longHeaderType_;
    invariant_ = std::make_unique<LongHeaderInvariant>(*other.invariant_);
    token_ = std::make_unique<std::string>(*other.token_);
    return *this;
  }

  LongHeader& operator=(LongHeader&& other) = default;

  [[nodiscard]] Types getHeaderType() const noexcept;
  [[nodiscard]] const ConnectionId& getSourceConnId() const;
  [[nodiscard]] const ConnectionId& getDestinationConnId() const;
  [[nodiscard]] QuicVersion getVersion() const;

  // Note this is defined in the header so it is inlined for performance.
  [[nodiscard]] PacketNumberSpace getPacketNumberSpace() const {
    return typeToPacketNumberSpace(longHeaderType_);
  }

  [[nodiscard]] ProtectionType getProtectionType() const;
  [[nodiscard]] bool hasToken() const;
  [[nodiscard]] const std::string& getToken() const;

  // Note this is defined in the header so it is inlined for performance.
  [[nodiscard]] PacketNum getPacketSequenceNum() const {
    return packetSequenceNum_;
  }

  void setPacketNumber(PacketNum packetNum);

 private:
  PacketNum packetSequenceNum_{0};
  Types longHeaderType_;
  std::unique_ptr<LongHeaderInvariant> invariant_;
  std::unique_ptr<std::string> token_;
};

struct ShortHeaderInvariant {
  ConnectionId destinationConnId;

  explicit ShortHeaderInvariant(ConnectionId dcid);
};

struct ShortHeader {
 public:
  virtual ~ShortHeader() = default;

  // There is also a spin bit which is 0x20 that we don't currently implement.
  static constexpr uint8_t kFixedBitMask = 0x40;
  static constexpr uint8_t kReservedBitsMask = 0x18;
  static constexpr uint8_t kKeyPhaseMask = 0x04;
  static constexpr uint8_t kPacketNumLenMask = 0x03;
  static constexpr uint8_t kTypeBitsMask = 0x1F;

  /**
   * The constructor for reading a packet.
   */
  ShortHeader(ProtectionType protectionType, ConnectionId connId);

  /**
   * The constructor for writing a packet.
   */
  ShortHeader(
      ProtectionType protectionType,
      ConnectionId connId,
      PacketNum packetNum);

  [[nodiscard]] ProtectionType getProtectionType() const;

  [[nodiscard]] PacketNumberSpace getPacketNumberSpace() const {
    return PacketNumberSpace::AppData;
  }

  [[nodiscard]] PacketNum getPacketSequenceNum() const {
    return packetSequenceNum_;
  }

  [[nodiscard]] const ConnectionId& getConnectionId() const;

  void setPacketNumber(PacketNum packetNum);

 private:
  ShortHeader() = delete;

 private:
  PacketNum packetSequenceNum_{0};
  ProtectionType protectionType_;
  ConnectionId connectionId_;
};

struct PacketHeader {
  ~PacketHeader();

  /* implicit */ PacketHeader(LongHeader&& longHeader);
  /* implicit */ PacketHeader(ShortHeader&& shortHeader);

  PacketHeader(PacketHeader&& other) noexcept;
  PacketHeader(const PacketHeader& other);

  PacketHeader& operator=(PacketHeader&& other) noexcept;
  PacketHeader& operator=(const PacketHeader& other);

  LongHeader* asLong();
  ShortHeader* asShort();

  [[nodiscard]] const LongHeader* asLong() const;
  [[nodiscard]] const ShortHeader* asShort() const;

  // Note this is defined in the header so it is inlined for performance.
  [[nodiscard]] PacketNum getPacketSequenceNum() const {
    switch (headerForm_) {
      case HeaderForm::Long:
        return longHeader.getPacketSequenceNum();
      case HeaderForm::Short:
        return shortHeader.getPacketSequenceNum();
      default:
        folly::assume_unreachable();
    }
  }

  [[nodiscard]] HeaderForm getHeaderForm() const;
  [[nodiscard]] ProtectionType getProtectionType() const;

  // Note this is defined in the header so it is inlined for performance.
  [[nodiscard]] PacketNumberSpace getPacketNumberSpace() const {
    switch (headerForm_) {
      case HeaderForm::Long:
        return longHeader.getPacketNumberSpace();
      case HeaderForm::Short:
        return shortHeader.getPacketNumberSpace();
      default:
        folly::assume_unreachable();
    }
  }

 private:
  void destroyHeader();

  union {
    LongHeader longHeader;
    ShortHeader shortHeader;
  };

  HeaderForm headerForm_;
};

ProtectionType longHeaderTypeToProtectionType(LongHeader::Types type);
PacketNumberSpace protectionTypeToPacketNumberSpace(ProtectionType type);

struct StreamTypeField {
 public:
  explicit StreamTypeField(uint8_t field) : field_(field) {}

  [[nodiscard]] bool hasFin() const;
  [[nodiscard]] bool hasDataLength() const;
  [[nodiscard]] bool hasOffset() const;
  [[nodiscard]] uint8_t fieldValue() const;

  struct Builder {
   public:
    Builder() = default;

    Builder& setFin();
    Builder& setOffset();
    Builder& setLength();

    StreamTypeField build();

   private:
    uint8_t field_{static_cast<uint8_t>(FrameType::STREAM)};
  };

 private:
  // Stream Frame specific:
  static constexpr uint8_t kFinBit = 0x01;
  static constexpr uint8_t kDataLengthBit = 0x02;
  static constexpr uint8_t kOffsetBit = 0x04;

  uint8_t field_;
};

struct VersionNegotiationPacket {
  uint8_t packetType;
  ConnectionId sourceConnectionId;
  ConnectionId destinationConnectionId;
  std::vector<QuicVersion> versions;

  VersionNegotiationPacket(
      uint8_t packetTypeIn,
      ConnectionId sourceConnectionIdIn,
      ConnectionId destinationConnectionIdIn)
      : packetType(packetTypeIn),
        sourceConnectionId(sourceConnectionIdIn),
        destinationConnectionId(destinationConnectionIdIn) {}
};

/**
 * Common struct for regular read and write packets.
 */
struct RegularPacket {
  PacketHeader header;

  explicit RegularPacket(PacketHeader&& headerIn)
      : header(std::move(headerIn)) {}
};

struct RetryPacket {
  using IntegrityTagType = std::array<uint8_t, kRetryIntegrityTagLen>;

  RetryPacket(
      LongHeader&& longHeaderIn,
      IntegrityTagType integrityTagIn,
      uint8_t initialByteIn)
      : header(std::move(longHeaderIn)),
        integrityTag(integrityTagIn),
        initialByte(initialByteIn) {}

  LongHeader header;
  std::array<uint8_t, kRetryIntegrityTagLen> integrityTag;
  uint8_t initialByte;
};

/**
 * A representation of a regular packet that is read from the network.
 * This could be either Cleartext or Encrypted packets in long or short form.
 * Cleartext packets include Client Initial, Client Cleartext, Non-Final Server
 * Cleartext packet or Final Server Cleartext packet. Encrypted packets
 * include 0-RTT, 1-RTT Phase 0 and 1-RTT Phase 1 packets.
 */
struct RegularQuicPacket : public RegularPacket {
  using Vec = SmallVec<QuicFrame, 4>;
  Vec frames;

  explicit RegularQuicPacket(PacketHeader&& headerIn)
      : RegularPacket(std::move(headerIn)) {}
};

/**
 * A representation of a regular packet that is written to the network.
 */
struct RegularQuicWritePacket : public RegularPacket {
  using Vec = SmallVec<QuicWriteFrame, 1>;
  Vec frames;
  bool empty{true};

  explicit RegularQuicWritePacket(PacketHeader&& headerIn)
      : RegularPacket(std::move(headerIn)) {}
};

enum class ECNState : uint8_t {
  NotAttempted, // ECN marking disabled
  AttemptingECN, // ECN enabled, but not yet negotiated
  ValidatedECN, // ECN enabled, and negotiated successfully
  AttemptingL4S, // L4S enabled, but not yet negotiated
  ValidatedL4S, // L4S enabled, and negotiated successfully
  FailedValidation, // ECN or L4S was enabled, but failed validation
};

/**
 * Returns whether the header is long or short from the initial byte of
 * the QUIC packet.
 *
 * This function is version invariant.
 */
HeaderForm getHeaderForm(uint8_t headerValue);

std::string_view toString(LongHeader::Types type);

inline std::ostream& operator<<(
    std::ostream& os,
    const LongHeader::Types& type) {
  os << toString(type);
  return os;
}

inline std::ostream& operator<<(std::ostream& os, const PacketHeader& header) {
  auto shortHeader = header.asShort();
  if (shortHeader) {
    os << "header=short"
       << " protectionType=" << (int)shortHeader->getProtectionType();
  } else {
    auto longHeader = header.asLong();
    os << "header=long"
       << " protectionType=" << (int)longHeader->getProtectionType()
       << " type=" << std::hex << (int)longHeader->getHeaderType();
  }
  return os;
}

std::string_view toString(PacketNumberSpace pnSpace);

std::string_view toString(FrameType frame);

std::string_view toString(QuicVersion version);

inline std::ostream& operator<<(std::ostream& os, PacketNumberSpace pnSpace) {
  return os << toString(pnSpace);
}

std::string_view toString(ProtectionType protectionType);

std::string_view toString(TokenType type);

} // namespace quic
