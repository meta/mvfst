/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicInteger.h>
#include <quic/common/Expected.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/StateData.h>

namespace quic {
QuicStreamState::QuicStreamState(StreamId idIn, QuicConnectionStateBase& connIn)
    : conn(connIn), id(idIn) {
  // Note: this will set a windowSize for a locally-initiated unidirectional
  // stream even though that value is meaningless.
  flowControlState.windowSize = isUnidirectionalStream(idIn)
      ? conn.transportSettings.advertisedInitialUniStreamFlowControlWindow
      : isLocalStream(connIn.nodeType, idIn)
      ? conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow
      : conn.transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow;
  flowControlState.advertisedMaxOffset = isUnidirectionalStream(idIn)
      ? conn.transportSettings.advertisedInitialUniStreamFlowControlWindow
      : isLocalStream(connIn.nodeType, idIn)
      ? conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow
      : conn.transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow;
  // Note: this will set a peerAdvertisedMaxOffset for a peer-initiated
  // unidirectional stream even though that value is meaningless.
  flowControlState.peerAdvertisedMaxOffset = isUnidirectionalStream(idIn)
      ? conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni
      : isLocalStream(connIn.nodeType, idIn)
      ? conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote
      : conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal;
  if (isUnidirectionalStream(idIn)) {
    if (isLocalStream(connIn.nodeType, idIn)) {
      recvState = StreamRecvState::Invalid;
    } else {
      sendState = StreamSendState::Invalid;
    }
  }
  if (connIn.transportSettings.useUnifiedAppStreamSendBuffer &&
      sendState != StreamSendState::Invalid) {
    streamSendBuffer.emplace();
  }
  priority = connIn.transportSettings.defaultPriority;
}

std::ostream& operator<<(std::ostream& os, const QuicConnectionStateBase& st) {
  if (st.clientConnectionId) {
    os << "client CID=" << *st.clientConnectionId;
  } else {
    os << "client CID=None";
  }
  if (st.serverConnectionId) {
    os << " server CID=" << *st.serverConnectionId;
  } else {
    os << " server CID=None";
  }
  os << " peer address=" << st.peerAddress;
  return os;
}

AckStateVersion::AckStateVersion(
    uint64_t initialVersion,
    uint64_t handshakeVersion,
    uint64_t appDataVersion)
    : initialAckStateVersion(initialVersion),
      handshakeAckStateVersion(handshakeVersion),
      appDataAckStateVersion(appDataVersion) {}

bool AckStateVersion::operator==(const AckStateVersion& other) const {
  return initialAckStateVersion == other.initialAckStateVersion &&
      handshakeAckStateVersion == other.handshakeAckStateVersion &&
      appDataAckStateVersion == other.appDataAckStateVersion;
}

bool AckStateVersion::operator!=(const AckStateVersion& other) const {
  return !operator==(other);
}

PacingRate::PacingRate(
    std::chrono::microseconds intervalIn,
    uint64_t burstSizeIn)
    : interval(intervalIn), burstSize(burstSizeIn) {}

PacingRate::Builder&& PacingRate::Builder::setInterval(
    std::chrono::microseconds intervalIn) && {
  interval_ = intervalIn;
  return std::move(*this);
}

PacingRate::Builder&& PacingRate::Builder::setBurstSize(
    uint64_t burstSizeIn) && {
  burstSize_ = burstSizeIn;
  return std::move(*this);
}

PacingRate PacingRate::Builder::build() && {
  return {interval_, burstSize_};
}

Expected<ConnectionId, QuicError>
QuicConnectionStateBase::getNextAvailablePeerConnectionId() {
  auto& currentPeerCid = nodeType == QuicNodeType::Client ? serverConnectionId
                                                          : clientConnectionId;
  if (!currentPeerCid.has_value()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        std::string("Current peer connection id not set")));
  }

  if (currentPeerCid->size() == 0) {
    // If it's a zero length id, re-use it.
    return currentPeerCid.value();
  }

  for (auto& cidData : peerConnectionIds) {
    if (!cidData.inUse) {
      MVCHECK(
          cidData.connId != currentPeerCid, "Current CID not marked in use");
      cidData.inUse = true;
      updateStatelessResetTokens();
      return cidData.connId;
    }
  }

  return quic::make_unexpected(QuicError(
      LocalErrorCode::INTERNAL_ERROR,
      std::string("No available peer connection ids")));
}

void QuicConnectionStateBase::retirePeerConnectionId(ConnectionId peerCid) {
  if (peerCid.size() == 0) {
    // Nothing to retire
    return;
  }

  auto cidData = std::find_if(
      peerConnectionIds.begin(),
      peerConnectionIds.end(),
      [&](const auto& data) { return data.connId == peerCid; });

  if (cidData == peerConnectionIds.end()) {
    // Nothing to retire
    return;
  }

  pendingEvents.frames.emplace_back(
      RetireConnectionIdFrame(cidData->sequenceNumber));

  peerConnectionIds.erase(cidData);
  updateStatelessResetTokens();

  return;
}

void QuicConnectionStateBase::updateStatelessResetTokens() {
  if (nodeType != QuicNodeType::Client || !readCodec) {
    return;
  }
  std::vector<StatelessResetToken> tokens;
  for (const auto& cidData : peerConnectionIds) {
    if (cidData.inUse && cidData.token) {
      tokens.push_back(*cidData.token);
    }
  }
  readCodec->setStatelessResetTokens(std::move(tokens));
}

namespace {
// Static function for QUIC datagram overhead calculation
uint64_t quicDatagramOverhead(uint64_t datagramLen) {
  return kDatagramFrameTypeSize + getQuicIntegerSize(datagramLen).value();
}
} // namespace

QuicConnectionStateBase::DatagramState::DatagramState() {
  // Set up QUIC-specific overhead calculator using function pointer
  flowManager.setOverheadCalculator(quicDatagramOverhead);
}

} // namespace quic
