/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/state/StateData.h>

namespace quic {

void maybeIncreaseFlowControlWindow(
    const Optional<TimePoint>& timeOfLastFlowControlUpdate,
    TimePoint updateTime,
    std::chrono::microseconds srtt,
    uint64_t& windowSize);

void maybeIncreaseConnectionFlowControlWindow(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt);

void maybeIncreaseStreamFlowControlWindow(
    QuicStreamState::StreamFlowControlState& flowControlState,
    TimePoint updateTime,
    std::chrono::microseconds srtt);

bool maybeSendConnWindowUpdate(
    QuicConnectionStateBase& conn,
    TimePoint updateTime);

bool maybeSendStreamWindowUpdate(QuicStreamState& stream, TimePoint updateTime);
/**
 * Update the connection flow control state based on receiving data on the
 * stream. previousMaxOffsetObserved is the maxOffsetObserved on the stream
 * before receiving the data. bufferEndOffset is the end offset of the current
 * buffer.
 */
[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnStreamData(
    QuicStreamState& stream,
    uint64_t previousMaxOffsetObserved,
    uint64_t bufferEndOffset);

[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnRead(
    QuicStreamState& stream,
    uint64_t lastReadOffset,
    TimePoint readTime);

[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnReceiveReset(
    QuicStreamState& stream,
    TimePoint resetTime);

// Releases bytes of read but unreleased data in manualRead mode. The caller
// checks that bytes <= stream.unreleasedReadBytes().
[[nodiscard]] quic::Expected<void, QuicError> releaseManualReadFlowControl(
    QuicStreamState& stream,
    uint64_t bytes,
    TimePoint releaseTime);

// Releases all read data and ends manualRead for the stream.
[[nodiscard]] quic::Expected<void, QuicError> endManualReadFlowControl(
    QuicStreamState& stream,
    TimePoint releaseTime);

// Releases connection receive credit only, e.g. for a removed stream.
[[nodiscard]] quic::Expected<void, QuicError> releaseConnReadFlowControl(
    QuicConnectionStateBase& conn,
    uint64_t bytes,
    TimePoint releaseTime);

[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnWriteToSocket(
    QuicStreamState& stream,
    uint64_t length);

[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnWriteToStream(
    QuicStreamState& stream,
    uint64_t length);

[[nodiscard]] quic::Expected<void, QuicError> updateFlowControlOnResetStream(
    QuicStreamState& stream,
    Optional<uint64_t> reliableSize = std::nullopt);

void maybeWriteBlockAfterAPIWrite(QuicStreamState& stream);
void maybeWriteBlockAfterAPIWrite(
    QuicStreamState& stream,
    bool hadPendingWrites);

void maybeWriteDataBlockedAfterSocketWrite(QuicConnectionStateBase& conn);

void maybeWriteBlockAfterSocketWrite(QuicStreamState& stream);

void handleStreamWindowUpdate(
    QuicStreamState& stream,
    uint64_t maximumData,
    PacketNum packetNum);

void handleConnWindowUpdate(
    QuicConnectionStateBase& conn,
    const MaxDataFrame& frame,
    PacketNum packetNum);

void handleStreamBlocked(QuicStreamState& stream);

void handleConnBlocked(QuicConnectionStateBase& conn);

void onStreamWindowUpdateSent(
    QuicStreamState& stream,
    uint64_t maximumData,
    TimePoint sentTime);

void onConnWindowUpdateSent(
    QuicConnectionStateBase& conn,
    uint64_t maximumData,
    TimePoint sentTime);

void onStreamWindowUpdateLost(QuicStreamState& stream);

void onConnWindowUpdateLost(QuicConnectionStateBase& conn);

void onBlockedLost(QuicStreamState& stream);

void onDataBlockedLost(QuicConnectionStateBase& conn);

/**
 * Returns the number of bytes that the peer is willing to receive from
 * us at this point on the stream.
 */
uint64_t getSendStreamFlowControlBytesWire(const QuicStreamState& stream);

/**
 * Returns the number of bytes that we are allowed to send on a stream
 * accounting for the bytes that are already in the stream's send buffer.
 */
uint64_t getSendStreamFlowControlBytesAPI(const QuicStreamState& stream);

/**
 * Returns the number of bytes that the peer is willing to receive from
 * us at this point on the connection.
 */
uint64_t getSendConnFlowControlBytesWire(const QuicConnectionStateBase& conn);

/**
 * Returns the number of bytes that we are allowed to send on the connection
 * accounting for the bytes that are already in the send buffers of all the
 * streams on the connection.
 */
uint64_t getSendConnFlowControlBytesAPI(const QuicConnectionStateBase& conn);

/**
 * Returns the number of bytes that we are willing to receive from the peer
 * us at this point on the connection.
 */
uint64_t getRecvStreamFlowControlBytes(const QuicStreamState& stream);

/**
 * Returns the number of bytes that we are willing to receive from the peer
 * us at this point on the connection.
 */
uint64_t getRecvConnFlowControlBytes(const QuicConnectionStateBase& conn);

/**
 * Updates the flow control list with the stream. Callers should ensure that
 * this is only invoked when the flow control changes.
 */
void updateFlowControlList(QuicStreamState& state);

/**
 * Updates the flow control state with the settings.
 */
void updateFlowControlStateWithSettings(
    QuicConnectionStateBase::ConnectionFlowControlState& flowControlState,
    const TransportSettings& transportSettings);

/**
 * Generate a new MaxDataFrame with the latest flow control state and window
 * size of conn.
 */
MaxDataFrame generateMaxDataFrame(const QuicConnectionStateBase& conn);

/**
 * Generate a new MaxStreamDataFrame with the latest flow control state and
 * window size of stream.
 */
MaxStreamDataFrame generateMaxStreamDataFrame(const QuicStreamState& stream);

} // namespace quic
