/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/CertificateBase.h>
#include <folly/MaybeManagedPtr.h>
#include <quic/QuicException.h>
#include <quic/api/QuicCallbacks.h>
#include <quic/api/TransportInfo.h>
#include <quic/codec/Types.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/observer/SocketObserverContainer.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * Options for the connection callback; see
 * QuicSocketLite::setConnectionCallback().
 *
 * They come as a struct so that a new option does not change the signature of
 * every implementation and mock again. The struct is defined outside
 * QuicSocketLite so that its members can have default initializers and still
 * be used for the default argument there.
 */
struct ConnectionCallbackOptions {
  // Report how a close the application starts ends to the callback.
  //
  // By default, close(), closeGracefully() and destroying the transport drop
  // the connection callback right away, so it learns nothing about how the
  // connection ends. With this set, the transport keeps the callback until the
  // connection actually closes, tells it once how it ended, and drops it right
  // after. The setup callback is dropped either way, so a local close before
  // the transport is ready reports nothing.
  //
  // The application must keep an unmanaged callback valid until that report,
  // which can come after close() or closeGracefully() has returned, or from the
  // transport's destructor. A report from the destructor may close the
  // transport again, which does nothing, but must not otherwise use it.
  bool reportLocalClose{false};
};

class QuicSocketLite {
 public:
  // Alias for backward compatibility after TransportInfo moved to quic
  // namespace.
  using TransportInfo = quic::TransportInfo;

  /**
   * Callback for connection set up events.
   */
  class ConnectionSetupCallback {
   public:
    virtual ~ConnectionSetupCallback() = default;

    /**
     * Called after the transport successfully processes the received packet.
     */
    virtual void onFirstPeerPacketProcessed() noexcept {}

    /**
     * Invoked when the connection setup fails.
     */
    virtual void onConnectionSetupError(QuicError code) noexcept = 0;

    /**
     * Called when the transport is ready to send/receive data.
     * This can be potentially triggered immediately when using 0-RTT.
     */
    virtual void onTransportReady() noexcept {}

    /**
     * Client only.
     * Called when the transport becomes replay safe - both crypto keys derived.
     * Called after onTransportReady() and in case of 0-RTT, unlike
     * onTransportReady(), signifies full crypto handshake finished.
     */
    virtual void onReplaySafe() noexcept {}

    /**
     * Called after onTransportReady() and in case of 0-RTT, unlike
     * onTransportReady(), signifies full crypto handshake finished.
     */
    virtual void onFullHandshakeDone() noexcept {}

    /**
     * Client only.
     * Called when the transport is in priming mode and 0-RTT packets are
     * available.
     *
     * @param data the 0-RTT priming packets.
     * @param truncated true if the request did not fully fit within the initial
     *   congestion/flow-control window. Priming never receives ACKs to open the
     *   window, so a truncated flight cannot be completed.
     */
    virtual void onPrimingDataAvailable(
        std::vector<quic::BufPtr>&& /* data */,
        bool /* truncated */) noexcept {}

    /**
     * Server only.
     * Called when the 1-RTT write cipher becomes available. On the server this
     * can happen before the full handshake completes; for client-authenticated
     * connections, the peer certificate may not have been validated yet. Use
     * this only for data that is safe to send before transport-ready, such as
     * HTTP/3 SETTINGS and control streams.
     */
    virtual void onWriteCipherAvailable() noexcept {}
  };

  /**
   * Callback for connection level events once connection is set up.
   * The name is temporary until we phase out the old monolithic callback.
   */
  class ConnectionCallback {
   public:
    virtual ~ConnectionCallback() = default;

    /**
     * Invoked when stream id's flow control state changes.  This is an edge
     * triggered API and will be only invoked at the point that the flow control
     * changes.
     */
    virtual void onFlowControlUpdate(StreamId /*id*/) noexcept {}

    /**
     * Invoked when the peer creates a new bidirectional stream.  The most
     * common flow would be to set the ReadCallback from here
     */
    virtual void onNewBidirectionalStream(StreamId id) noexcept = 0;

    /**
     * Invoked when the peer creates a new unidirectional stream.  The most
     * common flow would be to set the ReadCallback from here
     */
    virtual void onNewUnidirectionalStream(StreamId id) noexcept = 0;

    /**
     * Invoked when a given stream has been closed and its state is about to
     * be reaped by the transport. This is the last chance to do any final
     * state querying operations on the stream.
     */
    virtual void onStreamPreReaped(StreamId) noexcept {}

    /**
     * Invoked when a stream receives a StopSending frame from a peer.
     * The application should reset the stream as part of this callback.
     */
    virtual void onStopSending(
        StreamId id,
        ApplicationErrorCode error) noexcept = 0;

    /**
     * Invoked when the transport initiates close. No callbacks will
     * be delivered after this
     */
    virtual void onConnectionEnd() noexcept = 0;

    /**
     * Invoked when the connection closed in error
     */
    virtual void onConnectionError(QuicError code) noexcept = 0;

    /**
     * Invoked on transport closure. No callbacks will be delivered after this.
     * onConnectionEnd() and onConnectionError(QuicError code) will be
     * deprecated in favor of this new combined callback soon.
     */
    virtual void onConnectionEnd(QuicError /* error */) noexcept {}

    /**
     * Called when more bidirectional streams become available for creation
     * (max local bidirectional stream ID was increased).
     */
    virtual void onBidirectionalStreamsAvailable(
        uint64_t /*numStreamsAvailable*/) noexcept {}

    /**
     * Called when more unidirectional streams become available for creation
     * (max local unidirectional stream ID was increased).
     */
    virtual void onUnidirectionalStreamsAvailable(
        uint64_t /*numStreamsAvailable*/) noexcept {}

    /**
     * Invoked when transport is detected to be app rate limited.
     */
    virtual void onAppRateLimited() noexcept {}

    /**
     * Invoked when we receive a KnobFrame from the peer
     */
    virtual void
    onKnob(uint64_t /*knobSpace*/, uint64_t /*knobId*/, BufPtr /*knobBlob*/) {}

    /**
     * Invoked when we receive a SCONE rate signal from the peer
     */
    virtual void onSconeRateSignal(
        uint8_t /*rateSignal*/,
        QuicVersion /*sconeVersion*/) noexcept {}

    /**
     * Called when the path is detected to be degrading (early warning).
     * Fires when ptoCount reaches numPtosForPathDegrading (default: 4)
     * consecutive PTOs without an ACK.
     *
     * Applications may use this signal to begin probing alternate paths.
     * Only fires once per degradation episode (resets on ACK receipt).
     */
    virtual void onPathDegrading() noexcept {}

    /**
     * Called when the path is detected to be blackholed.
     * Fires when ptoCount reaches numPtosForBlackhole (default: 6)
     * consecutive PTOs without an ACK.
     *
     * Applications should attempt migration to an alternate path
     * or prepare for connection closure.
     * Only fires once per degradation episode (resets on ACK receipt).
     */
    virtual void onBlackholeDetected() noexcept {}
  };

  /**
   * Information about the stream level transport info. Specific to QUIC.
   */
  struct StreamTransportInfo {
    // Total time the stream has spent in head-of-line blocked state,
    // in microseconds
    std::chrono::microseconds totalHeadOfLineBlockedTime{0us};

    // How many times the stream has entered the "head-of-line blocked" state
    uint32_t holbCount{0};

    // Is the stream head-of-line blocked?
    bool isHolb{false};

    // Number of packets transmitted that carry new STREAM frame for this stream
    uint64_t numPacketsTxWithNewData{0};

    // Number of packets that contain STREAM frame for this stream and are
    // declared to be lost
    uint64_t streamLossCount{0};

    // Total number of 'new' stream bytes sent on this stream.
    // Does not include retransmissions of stream bytes.
    Optional<uint64_t> streamBytesSent{0};

    // Largest contiguous stream offset ACKed starting at offset zero. Once the
    // FIN is ACKed, this is the final offset (one past the last stream byte),
    // matching the offsets used by delivery callbacks.
    Optional<uint64_t> maybeLargestDeliverableOffset;

    // Total number of stream bytes received on this stream.
    Optional<uint64_t> streamBytesReceived{0};

    // Stream read error (if one occurred)
    Optional<QuicErrorCode> streamReadError;
    // Stream write error (if one occurred)
    Optional<QuicErrorCode> streamWriteError;
  };

  /**
   * Get the flow control settings for the given stream (or connection flow
   * control by passing id=0).  Settings include send and receive window
   * capacity and available.
   */
  struct FlowControlState {
    // Number of bytes the peer has allowed me to send.
    uint64_t sendWindowAvailable;
    // The max offset provided by the peer.
    uint64_t sendWindowMaxOffset;
    // Number of bytes I have allowed the peer to send.
    uint64_t receiveWindowAvailable;
    // The max offset I have provided to the peer.
    uint64_t receiveWindowMaxOffset;

    // Max number of bytes we can write; i.e. result of
    // maxWritableOn(Stream|Conn) for get(Stream|Conn)FlowControl
    uint64_t maxWritable;

    FlowControlState(
        uint64_t sendWindowAvailableIn,
        uint64_t sendWindowMaxOffsetIn,
        uint64_t receiveWindowAvailableIn,
        uint64_t receiveWindowMaxOffsetIn,
        uint64_t maxWritableIn)
        : sendWindowAvailable(sendWindowAvailableIn),
          sendWindowMaxOffset(sendWindowMaxOffsetIn),
          receiveWindowAvailable(receiveWindowAvailableIn),
          receiveWindowMaxOffset(receiveWindowMaxOffsetIn),
          maxWritable(maxWritableIn) {}
  };

  /**
   * Creates a bidirectional stream.  This assigns a stream ID but does not
   * send anything to the peer.
   *
   * If replaySafe is false, the transport will buffer (up to the send buffer
   * limits) any writes on this stream until the transport is replay safe.
   */
  virtual quic::Expected<StreamId, LocalErrorCode> createBidirectionalStream(
      bool replaySafe = true) = 0;

  /**
   * Creates a unidirectional stream.  This assigns a stream ID but does not
   * send anything to the peer.
   *
   * If replaySafe is false, the transport will buffer (up to the send buffer
   * limits) any writes on this stream until the transport is replay safe.
   */
  virtual quic::Expected<StreamId, LocalErrorCode> createUnidirectionalStream(
      bool replaySafe = true) = 0;

  /**
   * Returns the number of bidirectional streams that can be opened.
   */
  [[nodiscard]] virtual uint64_t getNumOpenableBidirectionalStreams() const = 0;

  /**
   * Returns the number of unidirectional streams that can be opened.
   */
  [[nodiscard]] virtual uint64_t getNumOpenableUnidirectionalStreams()
      const = 0;

  /**
   * Returns whether a stream ID represents a unidirectional stream.
   */
  bool isUnidirectionalStream(StreamId stream) noexcept {
    return quic::isUnidirectionalStream(stream);
  }

  /**
   * Returns whether a stream ID represents a bidirectional stream.
   */
  bool isBidirectionalStream(StreamId stream) noexcept {
    return quic::isBidirectionalStream(stream);
  }

  /**
   * ===== Read API ====
   */

  /**
   * Callback class for receiving data on a stream
   */
  using ReadCallback = StreamReadCallback;

  /**
   * Read from the given stream, up to maxLen bytes.  If maxLen is 0, transport
   * will return all available bytes.
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occurred and it can be obtained with error().  If the value hasValue(),
   * then value() returns a pair of the data (if any) and the EOF marker.
   *
   * Calling read() when there is no data/eof to deliver will return an
   * EAGAIN-like error code.
   */
  virtual quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxLen) = 0;

  /**
   * Stops read() and consume() on this stream from releasing receive flow
   * control credit. The app releases it with releaseManualReadFlowControl()
   * as its own buffers drain. Data already read stays released. Holding
   * unreleased data blocks the peer exactly like leaving it unread.
   *
   * A received reset, stopSending() or stopSendingAndDropIngress() releases
   * all of the stream's data automatically and ends manual mode, even after
   * the transport has removed the closed stream. Fails with
   * INVALID_OPERATION on a stream without a receive side or one already reset
   * or dropped. Calling it again on a manual stream succeeds.
   */
  virtual quic::Expected<void, LocalErrorCode> setStreamManualRead(
      StreamId /* id */) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  /**
   * Releases stream and connection receive credit for bytes of data already
   * returned by read() or consume() on a stream in manual mode.
   *
   * Fails with INVALID_OPERATION if the stream never opted in or bytes exceeds
   * the read but unreleased data. Data up to FIN must be released too. After
   * the transport removes a closed stream, releasing its remaining bytes only
   * returns connection credit. Once a reset or dropped ingress has released
   * everything, calls for that stream succeed as no-ops.
   */
  virtual quic::Expected<void, LocalErrorCode> releaseManualReadFlowControl(
      StreamId /* id */,
      uint64_t /* bytes */) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  /**
   * Set the read callback for the given stream.  Note that read callback is
   * expected to be set all the time. Removing read callback indicates that
   * stream is no longer intended to be read again. This will issue a
   * StopSending if cb is being set to nullptr after previously being not
   * nullptr. The err parameter is used to control the error sent in the
   * StopSending. By default when cb is nullptr this function will cause the
   * transport to send a StopSending frame with
   * GenericApplicationErrorCode::NO_ERROR. If err is specified to be
   * std::nullopt, no StopSending will be sent.
   *
   * Users should remove the callback via setReadCallback(id, nullptr) after
   * reading an error or eof to allow streams to be reaped by the transport.
   */
  virtual quic::Expected<void, LocalErrorCode> setReadCallback(
      StreamId id,
      ReadCallback* cb,
      Optional<ApplicationErrorCode> err =
          GenericApplicationErrorCode::NO_ERROR) = 0;

  virtual quic::Expected<void, LocalErrorCode> setStopSendingCallback(
      StreamId id,
      StopSendingCallback* ss) noexcept = 0;

  /**
   * Pause/Resume read callback being triggered when data is available.
   */
  virtual quic::Expected<void, LocalErrorCode> pauseRead(StreamId id) = 0;
  virtual quic::Expected<void, LocalErrorCode> resumeRead(StreamId id) = 0;

  /**
   * ===== Peek/Consume API =====
   */

  using PeekIterator = CircularDeque<StreamBuffer>::const_iterator;

  /**
   * Callback class for receiving ack notifications
   */
  class DeliveryCallback : public ByteEventCallback {
   public:
    ~DeliveryCallback() override = default;

    /**
     * Invoked when the peer has acknowledged the receipt of the specified
     * offset.  rtt is the current RTT estimate for the connection.
     */
    virtual void onDeliveryAck(
        StreamId id,
        uint64_t offset,
        std::chrono::microseconds rtt) = 0;

    /**
     * Invoked on registered delivery callbacks when the bytes will never be
     * delivered (due to a reset or other error).
     */
    virtual void onCanceled(StreamId id, uint64_t offset) = 0;

   private:
    // Temporary shim during transition to ByteEvent
    void onByteEventRegistered(ByteEvent /* byteEvent */) final {
      // Not supported
    }

    void onByteEvent(ByteEvent byteEvent) final {
      MVCHECK_EQ((int)ByteEvent::Type::ACK, (int)byteEvent.type); // sanity
      onDeliveryAck(byteEvent.id, byteEvent.offset, byteEvent.srtt);
    }

    // Temporary shim during transition to ByteEvent
    void onByteEventCanceled(ByteEventCancellation cancellation) final {
      MVCHECK_EQ((int)ByteEvent::Type::ACK, (int)cancellation.type); // sanity
      onCanceled(cancellation.id, cancellation.offset);
    }
  };

  /**
   * Register a byte event to be triggered when specified event type occurs for
   * the specified stream and offset.
   *
   * If the registration fails, the callback (ByteEventCallback* cb) will NEVER
   * be invoked for anything. If the registration succeeds, the callback is
   * guaranteed to receive an onByteEventRegistered() notification.
   */
  virtual quic::Expected<void, LocalErrorCode> registerByteEventCallback(
      const ByteEvent::Type type,
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Get the number of pending byte events for the given stream.
   */
  [[nodiscard]] virtual size_t getNumByteEventCallbacksForStream(
      const StreamId streamId) const = 0;

  /**
   * Get the number of pending byte events of specified type for given stream.
   */
  [[nodiscard]] virtual size_t getNumByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId streamId) const = 0;

  /**
   * Cancel all byte event callbacks of all streams.
   */
  virtual void cancelAllByteEventCallbacks() = 0;

  /**
   * Cancel all byte event callbacks of all streams of the given type.
   */
  virtual void cancelByteEventCallbacks(const ByteEvent::Type type) = 0;

  /**
   * ===== Datagram API =====
   *
   * Datagram support is experimental. Currently there isn't delivery callback
   * or loss notification support for Datagram. Datagram flows and priorities
   * are in QuicSocket.
   */

  /**
   * Callback class for datagrams
   */
  class DatagramCallback {
   public:
    virtual ~DatagramCallback() = default;

    /**
     * Notifies the DatagramCallback that datagrams are available for read.
     */
    virtual void onDatagramsAvailable() noexcept = 0;
  };

  /**
   * Set the read callback for Datagrams
   */
  virtual quic::Expected<void, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) = 0;

  /**
   * Returns the maximum allowed Datagram payload size.
   * 0 means Datagram is not supported
   */
  [[nodiscard]] virtual uint16_t getDatagramSizeLimit() const = 0;

  /**
   * Writes a Datagram frame. If buf is larger than the size limit returned by
   * getDatagramSizeLimit(), or if the write buffer is full, buf will simply be
   * dropped, and a LocalErrorCode will be returned to caller.
   */
  virtual quic::Expected<void, LocalErrorCode> writeDatagram(BufPtr buf) = 0;

  /**
   * Returns the currently available received Datagrams.
   * Returns all datagrams if atMost is 0.
   */
  virtual quic::Expected<std::vector<ReadDatagram>, LocalErrorCode>
  readDatagrams(size_t atMost = 0) = 0;

  /**
   * Returns the currently available received Datagram IOBufs.
   * Returns all datagrams if atMost is 0.
   */
  virtual quic::Expected<std::vector<BufPtr>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) = 0;

  /**
   * ===== Write API =====
   */

  /**
   * Callback class for receiving write readiness notifications
   */
  class WriteCallback : public quic::ConnectionWriteCallback,
                        public quic::StreamWriteCallback {
   public:
    ~WriteCallback() override = default;
  };

  /**
   * Write data/eof to the given stream.
   *
   * Passing a delivery callback registers a callback from the transport when
   * the peer has acknowledged the receipt of all the data/eof passed to write.
   *
   * An error code is present if there was an error with the write.
   */
  using WriteResult = quic::Expected<void, LocalErrorCode>;
  virtual WriteResult writeChain(
      StreamId id,
      BufPtr data,
      bool eof,
      ByteEventCallback* cb = nullptr) = 0;

  /**
   * Register a callback to be invoked when the peer has acknowledged the
   * given offset on the given stream.
   */
  virtual quic::Expected<void, LocalErrorCode> registerDeliveryCallback(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Inform the transport that there is data to write on this connection
   * An app shouldn't mix connection and stream calls to this API
   * Use this if the app wants to do prioritization.
   */
  virtual quic::Expected<void, LocalErrorCode> notifyPendingWriteOnConnection(
      ConnectionWriteCallback* wcb) = 0;

  /**
   * Inform the transport that there is data to write on a given stream.
   * An app shouldn't mix connection and stream calls to this API
   * Use the Connection call if the app wants to do prioritization.
   */
  virtual quic::Expected<void, LocalErrorCode> notifyPendingWriteOnStream(
      StreamId id,
      StreamWriteCallback* wcb) = 0;

  virtual quic::Expected<void, LocalErrorCode> unregisterStreamWriteCallback(
      StreamId) = 0;

  /**
   * Application can invoke this function to signal the transport to
   * initiate migration.
   * @param socket The new socket that should be used by the transport.
   * If this is null then do not replace the underlying socket.
   */
  virtual void onNetworkSwitch(std::unique_ptr<QuicAsyncUDPSocket> /*unused*/) {
  }

  /**
   * Send a ping to the peer.  When the ping is acknowledged by the peer or
   * times out, the transport will invoke the callback.
   */
  virtual void sendPing(std::chrono::milliseconds /* pingTimeout */ = {}) {}

  /**
   * Cancel the given stream
   */
  virtual quic::Expected<void, LocalErrorCode> resetStream(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Determine if transport is open and ready to read or write.
   *
   * return true iff the transport is open and ready, false otherwise.
   */
  [[nodiscard]] virtual bool good() const = 0;

  /**
   * Determine if an error has occurred with this transport.
   */
  [[nodiscard]] virtual bool error() const = 0;

  /**
   * Close this socket with a drain period. If closing with an error, it may be
   * specified.
   */
  virtual void close(Optional<QuicError> errorCode) = 0;

  /**
   * Close this socket without a drain period. If closing with an error, it may
   * be specified.
   */
  virtual void closeNow(Optional<QuicError> errorCode) = 0;

  /**
   * Initiates sending of a StopSending frame for a given stream to the peer.
   * This is called a "solicited reset". On receipt of the StopSending frame
   * the peer should, but may not, send a ResetStream frame for the requested
   * stream. A caller can use this function when they are no longer processing
   * received data on the stream.
   */
  virtual quic::Expected<void, LocalErrorCode> stopSending(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Sends STOP_SENDING like stopSending(), and also retires the stream's
   * receive side: the application will read nothing more from it.
   *
   * Ingress: buffered data is discarded, and later data still counts against
   * flow control but is never buffered or delivered. A RESET_STREAM from the
   * peer is still reported through readError(). This holds whatever
   * dropIngressOnStopSending says.
   *
   * Graceful close: the receive side closes as soon as the peer's final size is
   * known, so closeGracefully() waits neither for the peer's FIN or
   * RESET_STREAM on this stream nor for the peer to acknowledge the
   * STOP_SENDING. It still waits until the peer has acknowledged everything
   * sent on the stream, through our FIN, retransmitting whatever is lost.
   *
   * Callbacks: no EOF is delivered after this call, so unless a RESET_STREAM is
   * reported, an installed read callback keeps the stream from being reaped
   * until the application unsets it.
   *
   * Results: INVALID_OPERATION if the stream cannot receive, CONNECTION_CLOSED
   * once the connection is closing, and STREAM_NOT_EXISTS if the stream is not
   * open. A stream whose receive side is already retired is left as it is. On
   * a stream the peer has already reset, the call succeeds without sending
   * STOP_SENDING, since nothing more can arrive.
   */
  virtual quic::Expected<void, LocalErrorCode> stopSendingAndDropIngress(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Calls stopSendingAndDropIngress() for every open stream that can receive,
   * and for every peer stream opened afterwards.
   *
   * Peer streams that are open but whose state has not been created yet are
   * covered too. A peer stream opened afterwards is retired as soon as its
   * state is created, before any of its frames is applied.
   *
   * This cannot be undone: it is for an application that will read nothing
   * more on this connection, typically just before closeGracefully(). Returns
   * CONNECTION_CLOSED once the connection is closing, and otherwise the first
   * error any stream returned.
   */
  virtual quic::Expected<void, LocalErrorCode>
  stopSendingAndDropIngressForAllStreams(ApplicationErrorCode error) = 0;

  /**
   * Sets connection setup callback. This callback must be set before using the
   * socket.
   */
  virtual void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) = 0;

  using ConnectionCallbackOptions = quic::ConnectionCallbackOptions;

  /**
   * Sets connection streams callback. This callback must be set after
   * connection set up is finished and is ready for streams processing.
   */
  virtual void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback,
      ConnectionCallbackOptions options = {}) = 0;

  /**
   * Signal the transport that a certain stream is a control stream.
   * A control stream outlives all the other streams in a connection, therefore,
   * if the transport knows about it, can enable some optimizations.
   * Applications should declare all their control streams after either calling
   * createStream() or receiving onNewBidirectionalStream()
   */
  virtual Optional<LocalErrorCode> setControlStream(StreamId id) = 0;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId.
   */
  virtual void cancelDeliveryCallbacksForStream(StreamId streamId) = 0;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId for
   * offsets lower than the offset provided.
   */
  virtual void cancelDeliveryCallbacksForStream(
      StreamId streamId,
      uint64_t offset) = 0;

  /**
   * Cancel byte event callbacks for given stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  virtual void cancelByteEventCallbacksForStream(
      const StreamId id,
      const Optional<uint64_t>& offset = std::nullopt) = 0;

  /**
   * Cancel byte event callbacks for given type and stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  virtual void cancelByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id,
      const Optional<uint64_t>& offset = std::nullopt) = 0;

  /**
   * Sets the size of the given stream's receive window, or the connection
   * receive window if stream id is 0.  If the window size increases, a
   * window update will be sent to the peer.  If it decreases, the transport
   * will delay future window updates until the sender's available window is
   * <= recvWindowSize.
   */
  virtual void setReceiveWindow(StreamId id, size_t recvWindowSize) = 0;

  /**
   * Set the size of the transport send buffer for the given stream.
   * The maximum total amount of buffer space is the sum of maxUnacked and
   * maxUnsent.  Bytes passed to writeChain count against unsent until the
   * transport flushes them to the wire, after which they count against unacked.
   */
  virtual void
  setSendBuffer(StreamId id, size_t maxUnacked, size_t maxUnsent) = 0;

  /**
   * Settings for the transport. This takes effect only before the transport
   * is connected.
   */
  virtual void setTransportSettings(TransportSettings transportSettings) = 0;

  /**
   * Set congestion control type.
   */
  virtual void setCongestionControl(CongestionControlType type) = 0;

  /**
   * Add a packet processor
   */
  virtual void addPacketProcessor(
      std::shared_ptr<PacketProcessor> packetProcessor) = 0;

  /**
   * Set a "knob". This will emit a knob frame to the peer, which the peer
   * application can act on by e.g. changing transport settings during the
   * connection.
   */
  virtual quic::Expected<void, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, BufPtr knobBlob) = 0;

  /**
   * Can Knob Frames be exchanged with the peer on this connection?
   */
  [[nodiscard]] virtual bool isKnobSupported() const = 0;

  /*
   * Set the priority queue implementation.
   */
  virtual quic::Expected<void, LocalErrorCode> setPriorityQueue(
      std::unique_ptr<PriorityQueue> queue) = 0;

  /**
   * Set stream priority.
   */
  virtual quic::Expected<void, LocalErrorCode> setStreamPriority(
      StreamId id,
      PriorityQueue::Priority pri) = 0;

  /**
   * Sets the maximum pacing rate in Bytes per second to be used
   * if pacing is enabled
   */
  virtual quic::Expected<void, LocalErrorCode> setMaxPacingRate(
      uint64_t rateBytesPerSec) = 0;

  /**
   * Set a throttling signal provider
   */
  virtual void setThrottlingSignalProvider(
      std::shared_ptr<ThrottlingSignalProvider>) = 0;

  /**
   * Returns the event base associated with this socket
   */
  [[nodiscard]] virtual std::shared_ptr<QuicEventBase> getEventBase() const = 0;

  /**
   * Get information on the state of the quic connection. Should only be used
   * for logging.
   */
  [[nodiscard]] virtual const QuicConnectionStateBase* getState() const = 0;

  /**
   * Get internal transport info similar to TCP information.
   * Returns LocalErrorCode::STREAM_NOT_EXISTS if the stream is not found
   */
  [[nodiscard]] virtual quic::Expected<StreamTransportInfo, LocalErrorCode>
  getStreamTransportInfo(StreamId id) const = 0;

  /**
   * Get the peer socket address
   */
  [[nodiscard]] virtual const quic::SocketAddress& getPeerAddress() const = 0;

  /**
   * Get the original peer socket address
   */
  [[nodiscard]] virtual const quic::SocketAddress& getOriginalPeerAddress()
      const = 0;

  /**
   * Get the local socket address
   */
  [[nodiscard]] virtual const quic::SocketAddress& getLocalAddress() const = 0;

  /**
   * Get the cert presented by peer
   */
  [[nodiscard]] virtual const std::shared_ptr<const fizz::Cert>
  getPeerCertificate() const {
    return nullptr;
  }

  /**
   * Get the cert presented by self
   */
  [[nodiscard]] virtual const std::shared_ptr<const fizz::Cert>
  getSelfCertificate() const {
    return nullptr;
  }

  /**
   * Get TLS summary information from the handshake
   */
  [[nodiscard]] virtual Optional<Handshake::TLSSummary> getTLSSummary() const {
    return std::nullopt;
  }

  /**
   * Derive exported key material (RFC5705) from the transport's TLS layer, if
   * the transport is capable.
   */
  [[nodiscard]] virtual Optional<std::vector<uint8_t>>
  getExportedKeyingMaterial(
      const std::string& label,
      const Optional<ByteRange>& context,
      uint16_t keyLength) const = 0;

  /**
   * Get the negotiated ALPN. If called before the transport is ready
   * returns std::nullopt
   */
  [[nodiscard]] virtual Optional<std::string> getAppProtocol() const = 0;

  /**
   * Return the amount of transport buffer space available for writing
   */
  [[nodiscard]] virtual uint64_t getConnectionBufferAvailable() const = 0;

  // Returns std::nullopt before the handshake is complete, otherwise is always
  // non-empty.
  [[nodiscard]] virtual Optional<std::vector<TransportParameter>>
  getPeerTransportParams() const = 0;

  /**
   * Returns the current flow control windows for the stream, id != 0.
   * Use getConnectionFlowControl for connection flow control window.
   */
  [[nodiscard]] virtual quic::Expected<FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const = 0;

  [[nodiscard]] virtual const TransportSettings& getTransportSettings()
      const = 0;

  /**
   * Get internal transport info similar to TCP information.
   */
  [[nodiscard]] virtual TransportInfo getTransportInfo() const = 0;

  /**
   * Similar to getMaxWritableOnStream() above, but returns the value for the
   * whole connection.
   */
  [[nodiscard]] virtual uint64_t maxWritableOnConn() const = 0;

  virtual QuicNodeType getNodeType() const noexcept = 0;

  /**
   * Returns initiator (self or peer) of a stream by ID.
   */
  StreamInitiator getStreamInitiator(StreamId id) const noexcept {
    return quic::getStreamInitiator(getNodeType(), id);
  }

  /**
   * Returns various stats of the connection.
   */
  [[nodiscard]] virtual QuicConnectionStats getConnectionsStats() const = 0;

  /**
   * Information about a received SCONE rate signal.
   */
  struct SconeRateInfo {
    // Raw 7-bit SCONE rate signal. kSconeNoAdvice means no rate advice.
    uint8_t rateSignal;
    // SCONE rate converted to bits per second, absent for kSconeNoAdvice.
    Optional<uint64_t> advisedBps;
    // steady_clock time when the signal was received.
    TimePoint receivedTime;
  };

  /**
   * Returns and clears the pending SCONE rate signal received from the peer.
   * Valid rates are converted from the SCONE logarithmic encoding to bps.
   * Edge-triggered: subsequent calls return nullopt until a new signal arrives.
   * Must be called from the event base thread.
   */
  [[nodiscard]] virtual Optional<SconeRateInfo> consumePendingSconeRate() {
    return std::nullopt;
  }

  using Observer = SocketObserverContainer::Observer;
  using ManagedObserver = SocketObserverContainer::ManagedObserver;

  /**
   * Adds an observer. Lazily creates the observer container on first add.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(Observer* observer) {
    if (auto* list = ensureSocketObserverContainer()) {
      list->addObserver(observer);
      return true;
    }
    return false;
  }

  /**
   * Adds an observer. Lazily creates the observer container on first add.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(std::shared_ptr<Observer> observer) {
    if (auto* list = ensureSocketObserverContainer()) {
      list->addObserver(std::move(observer));
      return true;
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(Observer* observer) {
    if (auto* list = getSocketObserverContainer()) {
      return list->removeObserver(observer);
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(std::shared_ptr<Observer> observer) {
    if (auto* list = getSocketObserverContainer()) {
      return list->removeObserver(std::move(observer));
    }
    return false;
  }

  /**
   * Get number of observers.
   *
   * @return             Number of observers.
   */
  [[nodiscard]] size_t numObservers() const {
    if (auto* list = getSocketObserverContainer()) {
      return list->numObservers();
    }
    return 0;
  }

  /**
   * Returns list of attached observers.
   *
   * @return             List of observers.
   */
  std::vector<Observer*> getObservers() {
    if (auto* list = getSocketObserverContainer()) {
      return list->getObservers();
    }
    return {};
  }

  /**
   * Returns list of attached observers that are of type T.
   *
   * @return             Attached observers of type T.
   */
  template <typename T = Observer>
  std::vector<T*> findObservers() {
    if (auto* list = getSocketObserverContainer()) {
      return list->findObservers<T>();
    }
    return {};
  }

  virtual ~QuicSocketLite() = default;

 protected:
  /**
   * Returns the SocketObserverList or nullptr if not available.
   *
   * QuicSocket implementations that support observers should override this
   * function and return the socket observer list that they hold in memory.
   *
   * We have a default implementation to ensure that there is no risk of a
   * pure-virtual function being called during construction or destruction of
   * the socket. If this was to occur the derived class which implements this
   * function may be unavailable leading to undefined behavior. While this is
   * true for any pure-virtual function, the potential for this issue is
   * greater for observers.
   */
  [[nodiscard]] virtual SocketObserverContainer* getSocketObserverContainer()
      const {
    return nullptr;
  }

  /**
   * Returns the container, creating it on first use if the implementation
   * supports lazy creation. Default forwards to getSocketObserverContainer().
   *
   * Implementations that lazily own a container should override this and
   * return non-null on first call (creating the container) so addObserver
   * can succeed without requiring eager construction.
   */
  virtual SocketObserverContainer* ensureSocketObserverContainer() {
    return getSocketObserverContainer();
  }
};

} // namespace quic
