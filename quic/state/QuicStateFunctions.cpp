/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicStateFunctions.h>

#include <quic/common/TimeUtil.h>
#include <algorithm>
#include <iterator>

namespace {
std::deque<quic::OutstandingPacketWrapper>::reverse_iterator
getPreviousOutstandingPacket(
    quic::QuicConnectionStateBase& conn,
    quic::PacketNumberSpace packetNumberSpace,
    const std::deque<quic::OutstandingPacketWrapper>::reverse_iterator& from,
    bool includeLost = false,
    bool includeScheduledForDestruction = false) {
  return std::find_if(
      from, conn.outstandings.packets.rend(), [=](const auto& op) {
        return (includeLost || !op.declaredLost) &&
            packetNumberSpace == op.packet.header.getPacketNumberSpace() &&
            (includeScheduledForDestruction ||
             !op.metadata.scheduledForDestruction);
      });
}

} // namespace

namespace quic {

void updateRtt(
    QuicConnectionStateBase& conn,
    const std::chrono::microseconds rttSample,
    const std::chrono::microseconds ackDelay) {
  // update mrtt
  //
  // mrtt ignores ack delay. This is the same in the current recovery draft
  // section A.6.
  conn.lossState.mrtt = timeMin(conn.lossState.mrtt, rttSample);

  // update mrttNoAckDelay
  //
  // keep a version of mrtt formed from rtt samples with ACK delay removed
  if (rttSample >= ackDelay) {
    const auto rttSampleNoAckDelay =
        std::chrono::ceil<std::chrono::microseconds>(rttSample - ackDelay);
    conn.lossState.maybeMrttNoAckDelay = (conn.lossState.maybeMrttNoAckDelay)
        ? std::min(*conn.lossState.maybeMrttNoAckDelay, rttSampleNoAckDelay)
        : rttSampleNoAckDelay;
  }

  // update lrtt and lrttAckDelay
  conn.lossState.lrtt = rttSample;
  conn.lossState.maybeLrtt = rttSample;
  conn.lossState.maybeLrttAckDelay = ackDelay;

  // update maxAckDelay
  conn.lossState.maxAckDelay = timeMax(conn.lossState.maxAckDelay, ackDelay);

  // determine the adjusted RTT sample we will use for srtt calculations
  //
  // do NOT subtract the acknowledgment delay from the RTT sample if the
  // resulting value is smaller than the min_rtt; this limits underestimation
  // of the smoothed_rtt due to a misreporting peer.
  //
  // if this is the first RTT sample, then it is also the minRTT and ACK delay
  // will not be subtracted
  const auto adjustedRtt =
      ((rttSample > ackDelay) && (rttSample > conn.lossState.mrtt + ackDelay))
      ? rttSample - ackDelay
      : rttSample;
  if (conn.lossState.srtt == 0us) {
    conn.lossState.srtt = adjustedRtt;
    conn.lossState.rttvar = adjustedRtt / 2;
  } else {
    conn.lossState.rttvar = conn.lossState.rttvar * (kRttBeta - 1) / kRttBeta +
        (conn.lossState.srtt > adjustedRtt
             ? conn.lossState.srtt - adjustedRtt
             : adjustedRtt - conn.lossState.srtt) /
            kRttBeta;
    conn.lossState.srtt = conn.lossState.srtt * (kRttAlpha - 1) / kRttAlpha +
        adjustedRtt / kRttAlpha;
  }

  // inform qlog
  QLOG(
      conn,
      addMetricUpdate,
      rttSample,
      conn.lossState.mrtt,
      conn.lossState.srtt,
      ackDelay,
      conn.lossState.rttvar,
      std::nullopt,
      conn.lossState.inflightBytes,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      conn.lossState.ptoCount);
}

void updateAckSendStateOnRecvPacket(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    uint64_t distanceFromExpectedPacketNum,
    bool pktHasRetransmittableData,
    bool pktHasCryptoData,
    bool initPktNumSpace) {
  PROTO_OOPS_LOG_BUILDER_IF(
      conn.nodeType == QuicNodeType::Server && pktHasCryptoData &&
          !pktHasRetransmittableData,
      conn.oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(conn),
      "quic_state_functions",
      "invariant_violation: crypto data packet not marked retransmittable");
  MVDCHECK(!pktHasCryptoData || pktHasRetransmittableData);
  auto thresh = kNonRtxRxPacketsPendingBeforeAck;
  if (pktHasRetransmittableData || ackState.numRxPacketsRecvd) {
    if (ackState.tolerance.has_value()) {
      thresh = ackState.tolerance.value();
    } else {
      thresh = ackState.largestRecvdPacketNum.value_or(0) >
              conn.transportSettings.rxPacketsBeforeAckInitThreshold
          ? conn.transportSettings.rxPacketsBeforeAckAfterInit
          : conn.transportSettings.rxPacketsBeforeAckBeforeInit;
    }
  }
  bool exceedsReorderThreshold =
      distanceFromExpectedPacketNum > ackState.reorderThreshold;
  if (pktHasRetransmittableData) {
    bool skipCryptoAck =
        conn.nodeType == QuicNodeType::Server && initPktNumSpace;

    if ((pktHasCryptoData && !skipCryptoAck) || exceedsReorderThreshold ||
        ++ackState.numRxPacketsRecvd + ackState.numNonRxPacketsRecvd >=
            thresh) {
      MVVLOG(10)
          << conn
          << " ack immediately because packet threshold pktHasCryptoData="
          << pktHasCryptoData << " pktHasRetransmittableData="
          << static_cast<int>(pktHasRetransmittableData)
          << " numRxPacketsRecvd="
          << static_cast<int>(ackState.numRxPacketsRecvd)
          << " numNonRxPacketsRecvd="
          << static_cast<int>(ackState.numNonRxPacketsRecvd);
      conn.pendingEvents.scheduleAckTimeout = false;
      ackState.needsToSendAckImmediately = true;
    } else if (!ackState.needsToSendAckImmediately) {
      MVVLOG(10) << conn << " scheduling ack timeout pktHasCryptoData="
                 << pktHasCryptoData << " pktHasRetransmittableData="
                 << static_cast<int>(pktHasRetransmittableData)
                 << " numRxPacketsRecvd="
                 << static_cast<int>(ackState.numRxPacketsRecvd)
                 << " numNonRxPacketsRecvd="
                 << static_cast<int>(ackState.numNonRxPacketsRecvd);
      conn.pendingEvents.scheduleAckTimeout = true;
    }
  } else if (
      ++ackState.numNonRxPacketsRecvd + ackState.numRxPacketsRecvd >= thresh) {
    MVVLOG(10)
        << conn
        << " ack immediately because exceeds nonrx threshold numNonRxPacketsRecvd="
        << static_cast<int>(ackState.numNonRxPacketsRecvd)
        << " numRxPacketsRecvd="
        << static_cast<int>(ackState.numRxPacketsRecvd);
    conn.pendingEvents.scheduleAckTimeout = false;
    ackState.needsToSendAckImmediately = true;
  }
  if (ackState.needsToSendAckImmediately) {
    ackState.numRxPacketsRecvd = 0;
    ackState.numNonRxPacketsRecvd = 0;
  }
}

void updateAckStateOnAckTimeout(QuicConnectionStateBase& conn) {
  MVVLOG(10) << conn << " ack immediately due to ack timeout";
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  conn.ackStates.appDataAckState.numRxPacketsRecvd = 0;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 0;
  conn.pendingEvents.scheduleAckTimeout = false;
}

void updateAckSendStateOnSentPacketWithAcks(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum largestAckScheduled) {
  MVVLOG(10) << conn
             << " unset ack immediately due to sending packet with acks";
  conn.pendingEvents.scheduleAckTimeout = false;
  ackState.needsToSendAckImmediately = false;
  // When we send an ack we're most likely going to ack the largest received
  // packet, so reset the counters for numRxPacketsRecvd and
  // numNonRxPacketsRecvd. Since our ack threshold is quite small, we make the
  // critical assumption here that that all the needed acks can fit into one
  // packet if needed. If this is not the case, then some packets may not get
  // acked as a result and the receiver might retransmit them.
  ackState.numRxPacketsRecvd = 0;
  ackState.numNonRxPacketsRecvd = 0;
  ackState.largestAckScheduled = largestAckScheduled;
}

bool isConnectionPaced(const QuicConnectionStateBase& conn) noexcept {
  return (
      conn.transportSettings.pacingEnabled && conn.canBePaced && conn.pacer);
}

AckState& getAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return *MVCHECK_NOTNULL(conn.ackStates.initialAckState.get());
    case PacketNumberSpace::Handshake:
      return *MVCHECK_NOTNULL(conn.ackStates.handshakeAckState.get());
    case PacketNumberSpace::AppData:
      return conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

const AckState& getAckState(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return *MVCHECK_NOTNULL(conn.ackStates.initialAckState.get());
    case PacketNumberSpace::Handshake:
      return *MVCHECK_NOTNULL(conn.ackStates.handshakeAckState.get());
    case PacketNumberSpace::AppData:
      return conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

const AckState* getAckStatePtr(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  switch (pnSpace) {
    case PacketNumberSpace::Initial:
      return conn.ackStates.initialAckState.get();
    case PacketNumberSpace::Handshake:
      return conn.ackStates.handshakeAckState.get();
    case PacketNumberSpace::AppData:
      return &conn.ackStates.appDataAckState;
  }
  folly::assume_unreachable();
}

AckStateVersion currentAckStateVersion(
    const QuicConnectionStateBase& conn) noexcept {
  AckStateVersion ret;
  if (conn.ackStates.initialAckState) {
    ret.initialAckStateVersion =
        conn.ackStates.initialAckState->acks.insertVersion();
  }
  if (conn.ackStates.handshakeAckState) {
    ret.handshakeAckStateVersion =
        conn.ackStates.handshakeAckState->acks.insertVersion();
  }
  ret.appDataAckStateVersion =
      conn.ackStates.appDataAckState.acks.insertVersion();
  return ret;
}

PacketNum getNextPacketNum(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  return getAckState(conn, pnSpace).nextPacketNum;
}

void increaseNextPacketNum(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  auto& ackState = getAckState(conn, pnSpace);
  ackState.nextPacketNum++;
  if (ackState.nextPacketNum == kMaxPacketNumber) {
    conn.pendingEvents.closeTransport = true;
  }
}

PacketNum getPacketNumberEncodingBase(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    PacketNum packetNum) noexcept {
  PacketNum largestAcked =
      getAckState(conn, pnSpace).largestAckedByPeer.value_or(0);
  // The peer decodes a packet number relative to the largest one it has
  // received, so a packet that arrives more than half the encoded window late
  // decodes to the wrong number and fails decryption. Those packets are never
  // acked, so the adaptive reordering threshold can't learn their depth. Size
  // for twice the threshold so the length grows before reordering reaches the
  // window.
  PacketNum reorderingHeadroom =
      2 * static_cast<PacketNum>(conn.lossState.reorderingThreshold);
  if (packetNum <= reorderingHeadroom) {
    return 0;
  }
  return std::min(largestAcked, packetNum - reorderingHeadroom);
}

std::deque<OutstandingPacketWrapper>::iterator getFirstOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace) {
  if (conn.outstandings.packets.size() == conn.outstandings.declaredLostCount) {
    return conn.outstandings.packets.end();
  }
  return getNextOutstandingPacket(
      conn, packetNumberSpace, conn.outstandings.packets.begin());
}

std::deque<OutstandingPacketWrapper>::reverse_iterator getLastOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    bool includeLost,
    bool includeScheduledForDestruction) {
  return getPreviousOutstandingPacket(
      conn,
      packetNumberSpace,
      conn.outstandings.packets.rbegin(),
      includeLost,
      includeScheduledForDestruction);
}

std::deque<OutstandingPacketWrapper>::iterator getNextOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    std::deque<OutstandingPacketWrapper>::iterator from) {
  return std::find_if(
      from, conn.outstandings.packets.end(), [=](const auto& op) {
        return !op.declaredLost &&
            packetNumberSpace == op.packet.header.getPacketNumberSpace() &&
            !op.metadata.scheduledForDestruction;
      });
}

bool hasReceivedUdpPacketsAtLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;
  return (initialAckState && initialAckState->largestReceivedAtLastCloseSent) ||
      (handshakeAckState &&
       handshakeAckState->largestReceivedAtLastCloseSent) ||
      appDataAckState.largestReceivedAtLastCloseSent;
}

bool hasNotReceivedNewPacketsSinceLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;

  return (initialAckState ? initialAckState->largestReceivedAtLastCloseSent ==
                  initialAckState->largestRecvdPacketNum
                          : true) &&
      (handshakeAckState ? handshakeAckState->largestReceivedAtLastCloseSent ==
               handshakeAckState->largestRecvdPacketNum
                         : true) &&
      appDataAckState.largestReceivedAtLastCloseSent ==
      appDataAckState.largestRecvdPacketNum;
}

void updateLargestReceivedUdpPacketsAtLastCloseSent(
    QuicConnectionStateBase& conn) noexcept {
  auto* initialAckState = conn.ackStates.initialAckState.get();
  auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  auto& appDataAckState = conn.ackStates.appDataAckState;

  if (initialAckState) {
    initialAckState->largestReceivedAtLastCloseSent =
        conn.ackStates.initialAckState->largestRecvdPacketNum;
  }
  if (handshakeAckState) {
    handshakeAckState->largestReceivedAtLastCloseSent =
        handshakeAckState->largestRecvdPacketNum;
  }
  appDataAckState.largestReceivedAtLastCloseSent =
      conn.ackStates.appDataAckState.largestRecvdPacketNum;
}

bool hasReceivedUdpPackets(const QuicConnectionStateBase& conn) noexcept {
  const auto* initialAckState = conn.ackStates.initialAckState.get();
  const auto* handshakeAckState = conn.ackStates.handshakeAckState.get();
  const auto& appDataAckState = conn.ackStates.appDataAckState;

  return (initialAckState ? initialAckState->largestRecvdPacketNum.has_value()
                          : true) ||
      (handshakeAckState ? handshakeAckState->largestRecvdPacketNum.has_value()
                         : true) ||
      appDataAckState.largestRecvdPacketNum.has_value();
}

Optional<TimePoint>& getLossTime(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept {
  return conn.lossState.lossTimes[pnSpace];
}

bool canSetLossTimerForAppData(const QuicConnectionStateBase& conn) noexcept {
  return conn.oneRttWriteCipher != nullptr;
}

std::pair<Optional<TimePoint>, PacketNumberSpace> earliestLossTimer(
    const QuicConnectionStateBase& conn) noexcept {
  bool considerAppData = canSetLossTimerForAppData(conn);
  return earliestTimeAndSpace(conn.lossState.lossTimes, considerAppData);
}

std::pair<Optional<TimePoint>, PacketNumberSpace> earliestTimeAndSpace(
    const EnumArray<PacketNumberSpace, Optional<TimePoint>>& times,
    bool considerAppData) noexcept {
  std::pair<Optional<TimePoint>, PacketNumberSpace> res = {
      std::nullopt, PacketNumberSpace::Initial};
  for (PacketNumberSpace pns : times.keys()) {
    if (!times[pns]) {
      continue;
    }
    if (pns == PacketNumberSpace::AppData && !considerAppData) {
      continue;
    }
    if (!res.first || *res.first > *times[pns]) {
      res.first = times[pns];
      res.second = pns;
    }
  }
  return res;
}

uint64_t maximumConnectionIdsToIssue(const QuicConnectionStateBase& conn) {
  // Return a min of what peer supports and hardcoded max limit.
  const uint64_t maximumIdsToIssue =
      std::min(conn.peerActiveConnectionIdLimit, kMaxActiveConnectionIdLimit);

  return maximumIdsToIssue;
}

void enforceAckStateRangeLimit(AckState& ackState) {
  if (ackState.acks.size() <= AckState::kMaxAckRanges) {
    return;
  }

  auto lastRangeToRetire = ackState.acks.cbegin();
  std::advance(
      lastRangeToRetire, ackState.acks.size() - AckState::kMaxAckRanges - 1);
  const auto lastRetiredPacketNum = lastRangeToRetire->end;
  ackState.acks.withdraw({0, lastRetiredPacketNum});
  ackState.minimumReceivedPacketNum =
      std::max(ackState.minimumReceivedPacketNum, lastRetiredPacketNum + 1);

  ackState.recvdPacketInfos.erase(
      std::remove_if(
          ackState.recvdPacketInfos.begin(),
          ackState.recvdPacketInfos.end(),
          [&](const auto& packetInfo) {
            return packetInfo.pktNum < ackState.minimumReceivedPacketNum;
          }),
      ackState.recvdPacketInfos.end());
}

Expected<AddPacketToAckStateResult, IntervalSetError> addPacketToAckState(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum packetNum,
    const ReceivedUdpPacket& udpPacket) {
  static_assert(Clock::is_steady, "Needs steady clock");

  PacketNum expectedNextPacket = 0;
  if (ackState.largestRecvdPacketNum) {
    expectedNextPacket = *ackState.largestRecvdPacketNum + 1;
  }
  uint64_t distanceFromExpected = 0;
  if (expectedNextPacket) {
    distanceFromExpected = (packetNum > expectedNextPacket)
        ? packetNum - expectedNextPacket
        : expectedNextPacket - packetNum;
  }

  if (packetNum < ackState.minimumReceivedPacketNum) {
    QUIC_STATS(conn.statsCallback, onDuplicatedPacketReceived);
    return AddPacketToAckStateResult{
        .distanceFromExpected = distanceFromExpected,
        /*isDuplicate=*/.isDuplicate = true};
  }

  auto preInsertVersion = ackState.acks.insertVersion();
  auto insertResult = ackState.acks.tryInsert(packetNum);
  if (!insertResult.has_value()) {
    return quic::make_unexpected(insertResult.error());
  }
  if (preInsertVersion == ackState.acks.insertVersion()) {
    // Per RFC 9000 §12.3, duplicates must not be processed further. Skip all
    // mutations so the duplicate cannot influence ECN counts, last-receive
    // timing, or ack ranges.
    QUIC_STATS(conn.statsCallback, onDuplicatedPacketReceived);
    return AddPacketToAckStateResult{
        .distanceFromExpected = distanceFromExpected,
        /*isDuplicate=*/.isDuplicate = true};
  }

  ackState.largestRecvdPacketNum = std::max<PacketNum>(
      ackState.largestRecvdPacketNum.value_or(packetNum), packetNum);
  if (ackState.largestRecvdPacketNum == packetNum) {
    ackState.largestRecvdPacketTime = udpPacket.timings.receiveTimePoint;
  }

  ackState.lastRecvdPacketInfo = {packetNum, udpPacket.timings};

  // Store every non-duplicate packet in arrival order. Packet numbers and
  // receive times may both be non-monotonic; encoders own the wire-format
  // constraints (legacy filters to a monotonic suffix at write time;
  // draft-02 sorts the storage view by receive-time desc before grouping).
  if (ackState.recvdPacketInfos.size() ==
      conn.transportSettings.maxReceiveTimestampsPerAckStored) {
    ackState.recvdPacketInfos.pop_front();
  }
  ackState.recvdPacketInfos.emplace_back(
      WriteAckFrameState::ReceivedPacket{packetNum, udpPacket.timings});

  auto ecnValue = udpPacket.tosValue & 0b11;
  switch (ecnValue) {
    case kEcnCE:
      ackState.ecnCECountReceived++;
      break;
    case kEcnECT1:
      ackState.ecnECT1CountReceived++;
      break;
    case kEcnECT0:
      ackState.ecnECT0CountReceived++;
      break;
    default:
      break;
  }

  enforceAckStateRangeLimit(ackState);

  return AddPacketToAckStateResult{
      .distanceFromExpected = distanceFromExpected,
      /*isDuplicate=*/.isDuplicate = false};
}

/**
 * Checks if retransmissions are disabled for this stream.
 */
bool streamRetransmissionDisabled(
    QuicConnectionStateBase& /* conn */,
    const QuicStreamState& stream) {
  return stream.retransmissionDisabled_;
}

} // namespace quic
