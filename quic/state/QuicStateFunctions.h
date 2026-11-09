/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/common/IntervalSet.h>
#include <quic/common/NetworkData.h>
#include <quic/state/StateData.h>

namespace quic {

void updateAckSendStateOnRecvPacket(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    uint64_t distanceFromExpectedPacketNum,
    bool pktHasRetransmittableData,
    bool pktHasCryptoData,
    bool initPktNumSpace = false);

void updateAckStateOnAckTimeout(QuicConnectionStateBase& conn);

void updateAckSendStateOnSentPacketWithAcks(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum largestAckScheduled);

void updateRtt(
    QuicConnectionStateBase& conn,
    const std::chrono::microseconds rttSample,
    const std::chrono::microseconds ackDelay);

bool isConnectionPaced(const QuicConnectionStateBase& conn) noexcept;

AckState& getAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

const AckState& getAckState(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

const AckState* getAckStatePtr(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

AckStateVersion currentAckStateVersion(
    const QuicConnectionStateBase& conn) noexcept;

PacketNum getNextPacketNum(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

void increaseNextPacketNum(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

/**
 * The packet number to encode packetNum against: the largest packet number the
 * peer acked, lowered on connections where the peer sees reordering so the
 * encoded length also covers the reordering depth.
 */
PacketNum getPacketNumberEncodingBase(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    PacketNum packetNum) noexcept;

struct AddPacketToAckStateResult {
  uint64_t distanceFromExpected;
  bool isDuplicate;
};

/**
 * Retire the oldest ACK ranges above the per-space limit and advance the
 * minimum packet number that can still be processed.
 */
void enforceAckStateRangeLimit(AckState& ackState);

/**
 * Update largestReceivedUdpPacketNum in ackState with packetNum. Return the
 * distance from the next packet number we expect to receive, plus a flag
 * indicating whether the packet was already present or is older than locally
 * retained ACK history. Callers MUST discard either result without further
 * processing; on discard, this function does not update largestRecvdPacketNum,
 * lastRecvdPacketInfo, recvdPacketInfos, or ECN counters.
 */
[[nodiscard]] Expected<AddPacketToAckStateResult, IntervalSetError>
addPacketToAckState(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum packetNum,
    const ReceivedUdpPacket& udpPacket);

std::deque<OutstandingPacketWrapper>::iterator getNextOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    std::deque<OutstandingPacketWrapper>::iterator from);
std::deque<OutstandingPacketWrapper>::iterator getFirstOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace);

std::deque<OutstandingPacketWrapper>::reverse_iterator getLastOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    bool includeDeclaredLost = false,
    bool includeScheduledForDestruction = false);

bool hasReceivedUdpPackets(const QuicConnectionStateBase& conn) noexcept;

bool hasReceivedUdpPacketsAtLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept;

bool hasNotReceivedNewPacketsSinceLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept;

void updateLargestReceivedUdpPacketsAtLastCloseSent(
    QuicConnectionStateBase& conn) noexcept;

Optional<TimePoint>& getLossTime(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

bool canSetLossTimerForAppData(const QuicConnectionStateBase& conn) noexcept;

std::pair<Optional<TimePoint>, PacketNumberSpace> earliestLossTimer(
    const QuicConnectionStateBase& conn) noexcept;

std::pair<Optional<TimePoint>, PacketNumberSpace> earliestTimeAndSpace(
    const EnumArray<PacketNumberSpace, Optional<TimePoint>>& times,
    bool considerAppData) noexcept;

uint64_t maximumConnectionIdsToIssue(const QuicConnectionStateBase& conn);

/**
 * Checks if the retransmission policy on the stream group prohibits
 * retransmissions.
 */
bool streamRetransmissionDisabled(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream);

} // namespace quic
