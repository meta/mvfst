/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <folly/portability/GMock.h>

#include <quic/api/QuicSocket.h>

namespace quic {

class MockQuicSocket : public QuicSocket {
 public:
  using SharedBuf = std::shared_ptr<folly::IOBuf>;

  MockQuicSocket() = default;

  MockQuicSocket(
      folly::EventBase* /*eventBase*/,
      ConnectionSetupCallback* setupCb,
      ConnectionCallback* connCb)
      : setupCb_(setupCb), connCb_(connCb) {}

  MOCK_METHOD(bool, good, (), (const));
  MOCK_METHOD(bool, replaySafe, (), (const));
  MOCK_METHOD(bool, error, (), (const));
  MOCK_METHOD(void, close, (Optional<QuicError>));
  MOCK_METHOD(void, closeGracefully, ());
  MOCK_METHOD(void, closeNow, (Optional<QuicError>));
  MOCK_METHOD(Optional<quic::ConnectionId>, getClientConnectionId, (), (const));
  MOCK_METHOD(const TransportSettings&, getTransportSettings, (), (const));
  MOCK_METHOD(Optional<quic::ConnectionId>, getServerConnectionId, (), (const));
  MOCK_METHOD(
      Optional<quic::ConnectionId>,
      getClientChosenDestConnectionId,
      (),
      (const));
  MOCK_METHOD(const quic::SocketAddress&, getPeerAddress, (), (const));
  MOCK_METHOD(const quic::SocketAddress&, getOriginalPeerAddress, (), (const));
  MOCK_METHOD(const quic::SocketAddress&, getLocalAddress, (), (const));
  MOCK_METHOD(
      Optional<std::vector<TransportParameter>>,
      getPeerTransportParams,
      (),
      (const));
  MOCK_METHOD(
      (Optional<std::vector<uint8_t>>),
      getExportedKeyingMaterial,
      (const std::string&, const Optional<ByteRange>&, uint16_t),
      (const));
  MOCK_METHOD(std::shared_ptr<QuicEventBase>, getEventBase, (), (const));
  MOCK_METHOD(
      (quic::Expected<size_t, LocalErrorCode>),
      getStreamReadOffset,
      (StreamId),
      (const));
  MOCK_METHOD(
      (quic::Expected<size_t, LocalErrorCode>),
      getStreamWriteOffset,
      (StreamId),
      (const));
  MOCK_METHOD(
      (quic::Expected<size_t, LocalErrorCode>),
      getStreamWriteBufferedBytes,
      (StreamId),
      (const));
  MOCK_METHOD(QuicSocket::TransportInfo, getTransportInfo, (), (const));
  MOCK_METHOD(Optional<Handshake::TLSSummary>, getTLSSummary, (), (const));
  MOCK_METHOD(
      (quic::Expected<QuicSocket::StreamTransportInfo, LocalErrorCode>),
      getStreamTransportInfo,
      (StreamId),
      (const));
  MOCK_METHOD(Optional<std::string>, getAppProtocol, (), (const));
  MOCK_METHOD(void, setReceiveWindow, (StreamId, size_t));
  MOCK_METHOD(void, setSendBuffer, (StreamId, size_t, size_t));
  MOCK_METHOD(uint64_t, getConnectionBufferAvailable, (), (const));
  MOCK_METHOD(
      (quic::Expected<FlowControlState, LocalErrorCode>),
      getConnectionFlowControl,
      (),
      (const));
  MOCK_METHOD(
      (quic::Expected<FlowControlState, LocalErrorCode>),
      getStreamFlowControl,
      (StreamId),
      (const));
  MOCK_METHOD(
      (quic::Expected<uint64_t, LocalErrorCode>),
      getMaxWritableOnStream,
      (StreamId),
      (const));
  MOCK_METHOD(void, unsetAllReadCallbacks, ());
  MOCK_METHOD(void, unsetAllPeekCallbacks, ());
  MOCK_METHOD(void, unsetAllDeliveryCallbacks, ());
  MOCK_METHOD(void, cancelDeliveryCallbacksForStream, (StreamId));
  MOCK_METHOD(
      void,
      cancelDeliveryCallbacksForStream,
      (StreamId, uint64_t offset));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setConnectionFlowControlWindow,
      (uint64_t));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setStreamFlowControlWindow,
      (StreamId, uint64_t));
  MOCK_METHOD(void, setTransportSettings, (TransportSettings));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setMaxPacingRate,
      (uint64_t));

  quic::Expected<void, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, BufPtr knobBlob) override {
    SharedBuf sharedBlob(knobBlob.release());
    return setKnob(knobSpace, knobId, sharedBlob);
  }

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setKnob,
      (uint64_t, uint64_t, SharedBuf));
  MOCK_METHOD(bool, isKnobSupported, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setStreamPriority,
      (StreamId, PriorityQueue::Priority));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setPriorityQueue,
      (std::unique_ptr<PriorityQueue> queue));
  MOCK_METHOD(
      (quic::Expected<PriorityQueue::Priority, LocalErrorCode>),
      getStreamPriority,
      (StreamId));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setReadCallback,
      (StreamId, ReadCallback*, Optional<ApplicationErrorCode> err));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setStopSendingCallback,
      (StreamId, StopSendingCallback*),
      (noexcept));

  MOCK_METHOD(
      void,
      setConnectionSetupCallback,
      (folly::MaybeManagedPtr<ConnectionSetupCallback>));
  MOCK_METHOD(
      void,
      setConnectionCallback,
      (folly::MaybeManagedPtr<ConnectionCallback>, ConnectionCallbackOptions));

  void setEarlyDataAppParamsHandler(
      EarlyDataAppParamsHandler* handler) override {
    earlyDataAppParamsHandler_ = handler;
  }

  MOCK_METHOD((quic::Expected<void, LocalErrorCode>), pauseRead, (StreamId));
  MOCK_METHOD((quic::Expected<void, LocalErrorCode>), resumeRead, (StreamId));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      stopSending,
      (StreamId, ApplicationErrorCode));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      stopSendingAndDropIngress,
      (StreamId, ApplicationErrorCode));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      stopSendingAndDropIngressForAllStreams,
      (ApplicationErrorCode));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setStreamManualRead,
      (StreamId));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      releaseManualReadFlowControl,
      (StreamId, uint64_t));

  quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxRead) override {
    auto res = readNaked(id, maxRead);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    } else {
      return std::pair<BufPtr, bool>(
          BufPtr(res.value().first), res.value().second);
    }
  }

  using ReadResult =
      quic::Expected<std::pair<folly::IOBuf*, bool>, LocalErrorCode>;
  MOCK_METHOD(ReadResult, readNaked, (StreamId, size_t));
  MOCK_METHOD(
      (quic::Expected<StreamId, LocalErrorCode>),
      createBidirectionalStream,
      (bool));
  MOCK_METHOD(
      (quic::Expected<StreamId, LocalErrorCode>),
      createUnidirectionalStream,
      (bool));
  MOCK_METHOD(uint64_t, getNumOpenableBidirectionalStreams, (), (const));
  MOCK_METHOD(uint64_t, getNumOpenableUnidirectionalStreams, (), (const));
  MOCK_METHOD((QuicNodeType), getNodeType, (), (const, noexcept));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      notifyPendingWriteOnConnection,
      (ConnectionWriteCallback*));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      notifyPendingWriteOnStream,
      (StreamId, StreamWriteCallback*));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      unregisterStreamWriteCallback,
      (StreamId));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      registerTxCallback,
      (const StreamId, const uint64_t, ByteEventCallback*));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      registerByteEventCallback,
      (const ByteEvent::Type,
       const StreamId,
       const uint64_t,
       ByteEventCallback*));
  MOCK_METHOD(
      void,
      cancelByteEventCallbacksForStream,
      (const StreamId id, const Optional<uint64_t>& offset));
  MOCK_METHOD(
      void,
      cancelByteEventCallbacksForStream,
      (const ByteEvent::Type,
       const StreamId id,
       const Optional<uint64_t>& offset));
  MOCK_METHOD(void, cancelAllByteEventCallbacks, ());
  MOCK_METHOD(void, cancelByteEventCallbacks, (const ByteEvent::Type));
  MOCK_METHOD(
      size_t,
      getNumByteEventCallbacksForStream,
      (const StreamId id),
      (const));
  MOCK_METHOD(
      size_t,
      getNumByteEventCallbacksForStream,
      (const ByteEvent::Type, const StreamId),
      (const));

  quic::Expected<void, LocalErrorCode> writeChain(
      StreamId id,
      BufPtr data,
      bool eof,
      ByteEventCallback* cb) override {
    SharedBuf sharedData(data.release());
    return writeChain(id, sharedData, eof, cb);
  }

  MOCK_METHOD(
      WriteResult,
      writeChain,
      (StreamId, SharedBuf, bool, ByteEventCallback*));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      registerDeliveryCallback,
      (StreamId, uint64_t, ByteEventCallback*));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      resetStream,
      (StreamId, ApplicationErrorCode));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      updateReliableDeliveryCheckpoint,
      (StreamId));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      resetStreamReliably,
      (StreamId, ApplicationErrorCode));
  MOCK_METHOD(bool, isReliableResetSupported, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      maybeResetStreamFromReadError,
      (StreamId, QuicErrorCode));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setPingCallback,
      (PingCallback*));
  MOCK_METHOD(void, sendPing, (std::chrono::milliseconds));
  MOCK_METHOD(const QuicConnectionStateBase*, getState, (), (const));
  MOCK_METHOD(bool, isDetachable, ());
  MOCK_METHOD(void, attachEventBase, (std::shared_ptr<QuicEventBase>));
  MOCK_METHOD(void, detachEventBase, ());
  MOCK_METHOD(Optional<LocalErrorCode>, setControlStream, (StreamId));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setPeekCallback,
      (StreamId, PeekCallback*));

  MOCK_METHOD((quic::Expected<void, LocalErrorCode>), pausePeek, (StreamId));
  MOCK_METHOD((quic::Expected<void, LocalErrorCode>), resumePeek, (StreamId));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      peek,
      (StreamId,
       FunctionRef<void(StreamId, const folly::Range<PeekIterator>&)>));

  MOCK_METHOD(
      (quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>),
      consume,
      (StreamId, uint64_t, size_t));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      consume,
      (StreamId, size_t));

  MOCK_METHOD(void, setCongestionControl, (CongestionControlType));

  MOCK_METHOD(void, addPacketProcessor, (std::shared_ptr<PacketProcessor>));

  MOCK_METHOD(
      void,
      setThrottlingSignalProvider,
      (std::shared_ptr<ThrottlingSignalProvider>));

  ConnectionSetupCallback* setupCb_{nullptr};
  ConnectionCallback* connCb_{nullptr};

  EarlyDataAppParamsHandler* earlyDataAppParamsHandler_{nullptr};

  MOCK_METHOD(
      void,
      resetNonControlStreams,
      (ApplicationErrorCode, folly::StringPiece));
  MOCK_METHOD(QuicConnectionStats, getConnectionsStats, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setDatagramCallback,
      (DatagramCallback*));
  MOCK_METHOD(uint16_t, getDatagramSizeLimit, (), (const));

  quic::Expected<void, LocalErrorCode> writeDatagram(BufPtr data) override {
    SharedBuf sharedData(data.release());
    return writeDatagram(sharedData);
  }

  MOCK_METHOD(WriteResult, writeDatagram, (SharedBuf));

  WriteResult writeDatagram(
      PriorityQueue::Priority priority,
      BufPtr data,
      std::optional<std::chrono::milliseconds> maxQueueTime =
          std::nullopt) override {
    SharedBuf sharedData(data.release());
    return writeDatagramWithPriority(priority, sharedData, maxQueueTime);
  }

  MOCK_METHOD(
      WriteResult,
      writeDatagramWithPriority,
      (PriorityQueue::Priority,
       SharedBuf,
       std::optional<std::chrono::milliseconds>));

  MOCK_METHOD(
      (quic::Expected<uint32_t, LocalErrorCode>),
      createDatagramFlowId,
      ());

  quic::Expected<void, LocalErrorCode> writeDatagram(
      uint32_t flowId,
      BufPtr data,
      uint64_t /*intraFlowPriority*/ = 0) override {
    SharedBuf sharedData(data.release());
    return writeDatagramWithFlowId(flowId, sharedData);
  }

  MOCK_METHOD(WriteResult, writeDatagramWithFlowId, (uint32_t, SharedBuf));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setDatagramFlowPriority,
      (uint32_t, PriorityQueue::Priority));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setDatagramFlowMaxQueueTime,
      (uint32_t, std::chrono::milliseconds));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      closeDatagramFlow,
      (uint32_t));

  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      closeDatagramFlowNow,
      (uint32_t));

  MOCK_METHOD(
      (quic::Expected<std::vector<ReadDatagram>, LocalErrorCode>),
      readDatagrams,
      (size_t));
  MOCK_METHOD(
      (quic::Expected<std::vector<BufPtr>, LocalErrorCode>),
      readDatagramBufs,
      (size_t));
  MOCK_METHOD(
      SocketObserverContainer*,
      getSocketObserverContainer,
      (),
      (const));
  MOCK_METHOD(
      (quic::Expected<void, LocalErrorCode>),
      setStreamRetransmissionDisabled,
      (StreamId, bool),
      (noexcept));
  MOCK_METHOD(
      (const std::shared_ptr<const fizz::Cert>),
      getPeerCertificate,
      (),
      (const));
  MOCK_METHOD((uint64_t), maxWritableOnConn, (), (const));
};
} // namespace quic
