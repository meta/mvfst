/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/IPAddress.h>
#include <quic/QuicConstants.h>
#include <quic/common/Optional.h>
#include <quic/priority/PriorityQueue.h>
#include <chrono>
#include <cstdint>

namespace quic {

struct CongestionControlConfig {
  // Used by: BBR1, BBR2
  bool conservativeRecovery{false};

  // Used by: BBR1
  // When largeProbeRttCwnd is true, kLargeProbeRttCwndGain * BDP will be used
  // as cwnd during ProbeRtt state, otherwise, 4MSS will be the ProbeRtt cwnd.
  bool largeProbeRttCwnd{false};

  // Whether ack aggregation is also calculated during Startup phase
  bool enableAckAggregationInStartup{false};

  // Used by: BBR1
  // Whether we should enter ProbeRtt if connection has been app-limited since
  // last time we ProbeRtt.
  bool probeRttDisabledIfAppLimited{false};

  // Used by: BBR1
  // Whether BBR should advance pacing gain cycle when BBR is draining and we
  // haven't reached the drain target.
  bool drainToTarget{false};

  //  Used by: Cubic
  //  If true, exiting hystart switches to additive increase rather than Cubic
  //  congestion avoidance, similar to Linux kernel behavior.
  bool additiveIncreaseAfterHystart{false};

  // Used by: Cubic
  // Whether to clamp the cwnd growth when the connection is not cwnd limited.
  bool onlyGrowCwndWhenLimited{false};

  // Used by: Cubic
  // Whether to leave headroom when deciding that the connection is cwnd
  // limited.
  bool leaveHeadroomForCwndLimited{false};

  // Used by: Cubic, BBR2, and BBR2Modular
  // Allow a congestion controller to undo its congestion response when every
  // packet in a loss episode is explicitly acknowledged as spurious.
  bool enableSpuriousLossRecovery{true};

  // These parameters control how BBR sends ACK_FREQUENCY frames every new RTT.
  //  The first controls how many ack eliciting packets have to be received
  //  to trigger an ACK.
  //  The second controls how often, in terms of min RTT, the peer should ACK.
  //  The third controls the reordering threshold they should use when
  //  delaying an ACK.
  struct AckFrequencyConfig {
    uint64_t ackElicitingThreshold{kDefaultRxPacketsBeforeAckAfterInit};
    uint64_t reorderingThreshold{kReorderingThreshold};
    uint32_t minRttDivisor{2};
    // Threshold to use early in the connection.
    bool useSmallThresholdDuringStartup{false};
  };

  // Used by: BBR1
  Optional<AckFrequencyConfig> ackFrequencyConfig;

  // Used by: BBR2
  // Whether BBR2 should ignore inflightLongTerm when setting its cwnd.
  bool ignoreInflightLongTerm{false};

  // Used by: BBR2
  // Whether BBR2 should ignore its short term model
  // (inflight/bandwidth ShortTerm).
  bool ignoreShortTerm{false};

  // Used by: BBR2
  // Whether BBR2 should check packet loss to exit startup
  bool exitStartupOnLoss{true};

  // Used by: BBR2
  // Enabled cwnd modulation using loss recovery in Startup
  bool enableRecoveryInStartup{true};

  // Used by: BBR2
  // Enabled cwnd modulation using loss recovery in ProbeBW/ProbeRTT states
  bool enableRecoveryInProbeStates{true};

  // Used by: BBR2
  // Whether BBR2 should enable reno coexistence.
  bool enableRenoCoexistence{false};

  // Used by: BBR2Modular
  // Whether BBR2 should use precautionary bandwidth probing.
  bool enablePrecautionaryBandwidthProbing{false};

  // Used by: BBR2
  // Whether BBR2 paces the initial congestion window.
  bool paceInitCwnd{false};

  // Used by: BBR2
  // Use a different pacing gain during ProbeBW Cruise and Refill.
  // If value < 0, use the default pacing gain.
  float overrideCruisePacingGain{-1.0};

  // Used by: BBR2
  // Use a different cwnd gain during ProbeBW Cruise and Refill.
  // If value < 0, use the default cwnd gain.
  float overrideCruiseCwndGain{-1.0};

  // Used by: BBR2
  // Use a different pacing gain during Startup.
  // If value < 0, use the default pacing gain.
  float overrideStartupPacingGain{-1.0};

  // Used by: Cubic
  // The target fraction of packets to be marked with CE per-RTT when l4s is
  // used This helps accommodate minor packet bursts that can be caused by pacer
  // bursts
  float l4sCETarget{0.0f};

  // Used by: BBR2
  // If 0.5 <= values <= 1.0, use this value to scale down bandwidthShortTerm in
  // the short-term model. Otherwise, use the default kBeta
  float overrideBwShortBeta{0.0f};
};

struct DatagramConfig {
  enum class CongestionControlMode : uint8_t {
    // DATAGRAM-only packets are constrained but not tracked (legacy behavior)
    Constrained = 0,
    // DATAGRAM-only packets are both constrained and tracked in outstandings
    ConstrainedAndTracked = 1
  };

  bool enabled{false};
  bool framePerPacket{true};
  bool recvDropOldDataFirst{false};
  bool sendDropOldDataFirst{false};
  // Mode for tracking DATAGRAM-only packets in bytes-in-flight
  CongestionControlMode trackingMode{CongestionControlMode::Constrained};
  uint32_t readBufSize{kDefaultMaxDatagramsBuffered};
  uint32_t writeBufSize{kDefaultMaxDatagramsBuffered};
  // Schedule datagrams via PriorityQueue with streams instead of separately
  bool scheduleDatagramsWithStreams{false};
  // Default priority for datagrams when scheduleDatagramsWithStreams is true
  uint8_t defaultDatagramPriority{0};
};

struct AckReceiveTimestampsConfig {
  uint64_t maxReceiveTimestampsPerAck{kMaxReceivedPktsTimestampsStored};
  uint64_t receiveTimestampsExponent{kDefaultReceiveTimestampsExponent};
};

// Versioned representation of the peer's receive-timestamp configuration.
// The `version` discriminates the wire format negotiated during the
// transport-parameter handshake (legacy mvfst vs
// draft-ietf-quic-receive-ts-02).
struct PeerReceiveTimestampsConfig {
  AckReceiveTimestampsVersion version{AckReceiveTimestampsVersion::None};
  // Maximum number of receive timestamps the peer wants us to include in each
  // ACK frame we send back to it.
  uint64_t maxReceiveTimestampsPerAck{0};
  // Exponent advertised by the peer. Encoded timestamp deltas we send to the
  // peer must be scaled by 2^exponent.
  uint64_t exponent{0};
};

enum class TimestampFrameWriteMode : uint8_t {
  Disabled,
  // Writes only from capacity left after ordinary scheduling or rebuilding.
  Opportunistic,
  // During ordinary scheduling, reserves TIMESTAMP space before stream/datagram
  // output, then releases that reservation rather than prevent the packet from
  // acquiring a qualifying carrier. It never displaces earlier ACK/control
  // frames or PacketRebuilder clone contents; rebuilt packets append TIMESTAMP
  // only if capacity remains.
  Prioritized,
};

enum class TimestampFramePacketSelection : uint8_t {
  AllEligiblePackets,
  AckElicitingPackets,
  StreamPackets,
};

// JSON-serialized transport knobs
struct SerializedKnob {
  uint64_t space;
  uint64_t id;
  std::string blob;
};

struct ServerDirectEncapConfig {
  folly::IPAddress directEncapAddress;
  // Bitmask of supported zones.
  uint8_t supportedZones;
};

struct TransportSettings {
  // The initial flow control window for the whole connection advertised to the
  // peer.
  uint64_t advertisedInitialConnectionFlowControlWindow{
      kDefaultConnectionFlowControlWindow};
  // The initial flow control window size of a stream advertised to the peer.
  uint64_t advertisedInitialBidiLocalStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialBidiRemoteStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialUniStreamFlowControlWindow{
      kDefaultStreamFlowControlWindow};
  uint64_t advertisedInitialMaxStreamsBidi{kDefaultMaxStreamsBidirectional};
  uint64_t advertisedInitialMaxStreamsUni{kDefaultMaxStreamsUnidirectional};
  // Maximum number of packets to buffer while cipher is unavailable.
  uint32_t maxPacketsToBuffer{kDefaultMaxBufferedPackets};
  // Idle timeout to advertise to the peer.
  std::chrono::milliseconds idleTimeout{kDefaultIdleTimeout};
  // Ack delay exponent to use.
  uint64_t ackDelayExponent{kDefaultAckDelayExponent};
  // Default congestion controller type.
  CongestionControlType defaultCongestionController{
      CongestionControlType::Cubic};
  // Param to determine sensitivity of CongestionController to latency. Only
  // used by Copa.
  Optional<double> copaDeltaParam;
  // Whether to use Copa's RTT standing feature. Only used by Copa.
  bool copaUseRttStanding{false};
  // The max UDP packet size we are willing to receive.
  uint64_t maxRecvPacketSize{kDefaultUDPReadBufferSize};
  // Number of buffers to allocate for GRO
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  // Can we ignore the path mtu when sending a packet. This is useful for
  // testing.
  bool canIgnorePathMTU{false};
  // When non-zero (and canIgnorePathMTU is set), caps the server's outgoing UDP
  // payload size to min(peer's advertised max_udp_payload_size, this). The
  // configured value is clamped to [kMinMaxUDPPayload, kDefaultMaxUDPPayload]
  // (1200..1452) at use time, so a too-small value cannot drive the send MTU
  // below the QUIC minimum. 0 = unset (use kDefaultMaxUDPPayload). Plumbed from
  // QuicTransportSettings.max_udp_payload_size.
  uint64_t maxUdpSendPayloadSize{0};
  // Whether or not to use a connected UDP socket on the client. This should
  // only be used in environments where you know your IP address does not
  // change. See AsyncUDPSocket::connect for the caveats.
  bool connectUDP{false};
  // Maximum number of consecutive PTOs before the connection is torn down.
  uint16_t maxNumPTOs{kDefaultMaxNumPTO};
  // Whether to listen to socket error
  bool enableSocketErrMsgCallback{true};
  // Whether pacing is enabled.
  bool pacingEnabled{false};
  // Whether pacing should be enabled for the first flight before the 1-RTT
  // cipher is available. Turning this on paces 0-rtt packets.
  bool pacingEnabledFirstFlight{false};
  // The minimum number of packets to burst out during pacing
  uint64_t minBurstPackets{kDefaultMinBurstPackets};
  // This is the smallest interval the pacer will use as its interval.
  std::chrono::microseconds pacingTickInterval{kDefaultPacingTickInterval};
  // This is the size of the buckets in the timer triggering the pacing
  // callbacks. For pacing to work accurately, this should be reasonably smaller
  // than kDefaultPacingTickInterval.
  std::chrono::microseconds pacingTimerResolution{
      kDefaultPacingTimerResolution};
  ZeroRttSourceTokenMatchingPolicy zeroRttSourceTokenMatchingPolicy{
      ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH};
  // Scale pacing rate for CC, non-empty indicates override via transport knobs
  std::pair<uint8_t, uint8_t> startupRttFactor{1, 2};
  std::pair<uint8_t, uint8_t> defaultRttFactor{1, 1};
  //
  bool attemptEarlyData{false};
  // Maximum number of packets the connection will write in
  // writeConnectionDataToSocket.
  uint64_t writeConnectionDataPacketsLimit{
      kDefaultWriteConnectionDataPacketLimit};
  // Fraction of RTT that is used to limit how long a write function can loop
  DurationRep writeLimitRttFraction{kDefaultWriteLimitRttFraction};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlRttFrequency * RTT if the flow control changes.
  uint16_t flowControlRttFrequency{2};
  // Frequency of sending flow control updates. We can send one update every
  // flowControlWindowFrequency * window if the flow control changes.
  uint16_t flowControlWindowFrequency{2};
  // batching mode
  QuicBatchingMode batchingMode{QuicBatchingMode::BATCHING_MODE_NONE};
  // maximum number of packets we can batch. This does not apply to
  // BATCHING_MODE_NONE
  uint32_t maxBatchSize{kDefaultQuicMaxBatchSize};
  // Initial congestion window in MSS
  uint64_t initCwndInMss{kInitCwndInMss};
  // Minimum congestion window in MSS
  uint64_t minCwndInMss{kMinCwndInMss};
  // Maximum congestion window in MSS
  uint64_t maxCwndInMss{kDefaultMaxCwndInMss};
  // Limited congestion window in MSS
  uint64_t limitedCwndInMss{kLimitedCwndInMss};
  // The following three parameters control ACK generation. ACKs are sent every
  // time so many retransmittable packets are received. There are two values,
  // one for earlier in the flow and one for after. These are "before" and
  // "after" the init threshold respectively.
  uint64_t rxPacketsBeforeAckInitThreshold{
      kDefaultRxPacketsBeforeAckInitThreshold};
  uint16_t rxPacketsBeforeAckBeforeInit{kDefaultRxPacketsBeforeAckBeforeInit};
  uint16_t rxPacketsBeforeAckAfterInit{kDefaultRxPacketsBeforeAckAfterInit};
  // The minimum amount of time in microseconds by which an ack can be delayed
  // Setting a value here also indicates to the peer that it can send
  // ACK_FREQUENCY and IMMEDIATE_ACK frames
  OptionalMicros minAckDelay;
  // Limits the amount of data that should be buffered in a QuicSocket.
  // If the amount of data in the buffer equals or exceeds this amount, then
  // the callback registered through notifyPendingWriteOnConnection() will
  // not be called
  uint64_t totalBufferSpaceAvailable{kDefaultBufferSpaceAvailable};
  // (Server only) Whether to allow the client to migrate to a new address
  bool disableMigration{true};
  // Whether or not the socket should gracefully drain on close
  bool shouldDrain{true};
  // default stateless reset secret for stateless reset token
  Optional<std::array<uint8_t, kStatelessResetTokenSecretLength>>
      statelessResetTokenSecret;
  // retry token secret used for encryption/decryption
  Optional<std::array<uint8_t, kRetryTokenSecretLength>> retryTokenSecret;
  // Default initial RTT
  std::chrono::microseconds initialRtt{kDefaultInitialRtt};
  // The active_connection_id_limit that is sent to the peer.
  uint64_t selfActiveConnectionIdLimit{kMaxActiveConnectionIdLimit};
  // Maximum size of the batch that should be used when receiving packets from
  // the kernel in one event loop. This is only used in clients.
  uint16_t maxRecvBatchSize{5};
  // Whether to use new receive path for recvmmsg.
  bool shouldUseWrapperRecvmmsgForBatchRecv{false};
  // Whether or not use recvmmsg.
  bool shouldUseRecvmmsgForBatchRecv{false};
  // Config struct for congestion controllers
  CongestionControlConfig ccaConfig;
  // A packet is considered loss when a packet that's sent later by at least
  // timeReorderingThreshold * RTT is acked by peer.
  DurationRep timeReorderingThreshDividend{
      kDefaultTimeReorderingThreshDividend};
  DurationRep timeReorderingThreshDivisor{kDefaultTimeReorderingThreshDivisor};
  // Ignored: ContinuousMemory is the only data path.
  DataPathType dataPathType{DataPathType::ContinuousMemory};
  // Whether or not we should stop writing a packet after writing a single
  // stream frame to it.
  bool streamFramePerPacket{false};
  // Ensure read callbacks are ordered by Stream ID.
  bool orderedReadCallbacks{false};
  // Quic knobs
  std::vector<SerializedKnob> knobs;
  // Datagram config
  DatagramConfig datagramConfig;
  // Whether or not to opportunistically retransmit 0RTT when the handshake
  // completes.
  bool earlyRetransmit0Rtt{false};
  // Whether to issue new tokens via NewToken frames.
  bool issueNewTokens{false};
  // Used to generate the number of frames to add to short header packets.
  // Packets will have padding frames added such that the total space remaining
  // in a packet is always an increment of paddingModulo, hiding the actual
  // packet size from packet analysis.
  // Padding Modulo of 0 turns off padding for short header packets.
  size_t paddingModulo{kShortHeaderPaddingModulo};
  // Number of padding frames to add at the start of short header packets.
  // A value of 0 means no fixed padding is added.
  size_t fixedShortHeaderPadding{0};
  // Whether to use adaptive loss thresholds for reodering and timeout
  bool useAdaptiveLossReorderingThresholds{true};
  bool useAdaptiveLossTimeThresholds{false};
  // Connection-level receive flow control window autotuning.
  // If locally consumed credit requires an update less than 2SRTTs after the
  // previous update, this increases the target window by up to 2x.
  bool autotuneReceiveConnFlowControl{false};
  // Maximum connection receive window that autotuning may select.
  uint64_t maxAutotunedReceiveConnFlowControlWindow{
      kDefaultMaxAutotunedReceiveConnFlowControlWindow};
  // Stream level receive flow control window autotuning.
  // If locally consumed credit requires an update less than 2SRTTs after the
  // previous update, this increases the target window by up to 2x.
  bool autotuneReceiveStreamFlowControl{false};
  // Maximum per-stream receive window that autotuning may select.
  uint64_t maxAutotunedReceiveStreamFlowControlWindow{
      kDefaultMaxAutotunedReceiveStreamFlowControlWindow};
  // Enable a keepalive timer. This schedules a timer to send a PING ~15%
  // before an idle timeout. To work effectively this means the idle timer
  // has to be set to something >> the RTT of the connection.
  bool enableKeepalive{false};
  // Close the connection instead of sending a keepalive when event-loop
  // delay has allowed the idle deadline to pass first.
  bool prioritizeExpiredIdleTimeout{false};
  // Whether or not to enable WritableBytes limit (server only)
  bool enableWritableBytesLimit{false};
  // (server only) When true, onTransportReady() is driven by the Fizz handshake
  // report milestones (ReportEarlyHandshakeSuccess / ReportHandshakeSuccess)
  // and is delivered before onFullHandshakeDone(). When false, it falls back to
  // the legacy gate of raw 1-RTT write-cipher availability. Migration/rollout
  // gate: off by default, turned on by the server layer during rollout.
  bool retimeOnTransportReady{false};
  // experimental flag to close ingress SM when invoking stopSending
  bool dropIngressOnStopSending{false};
  bool advertisedReliableResetStreamSupport{false};
  bool advertisedKnobFrameSupport{false};
  // Advertise that this endpoint accepts TIMESTAMP frames from the peer.
  bool advertisedTimestampFrameSupport{false};
  // Controls ordinary TIMESTAMP writes on selected non-empty 1-RTT packets;
  // see TimestampFrameWriteMode for the priority boundary.
  TimestampFrameWriteMode oneRttTimestampFrameWriteMode{
      TimestampFrameWriteMode::Disabled};
  // Select every eligible non-empty packet, every packet carrying an
  // ack-eliciting frame, or only packets that actually carry stream data.
  TimestampFramePacketSelection oneRttTimestampFramePacketSelection{
      TimestampFramePacketSelection::AllEligiblePackets};
  // Avoid redundant timing metadata when an ACK in the same packet already
  // carries receive timestamps.
  bool suppressOneRttTimestampFrameWhenAckReceiveTimestampsWritten{true};
  // Local TIMESTAMP values are encoded as microseconds >> exponent; one
  // encoded tick therefore represents 2^exponent microseconds.
  uint64_t timestampFrameTimestampExponent{
      kDefaultTimestampFrameTimestampExponent};
  Optional<uint16_t> quicExperimentId;

  // Extended ACK support to advertise to the peer. This is what we expect to
  // receive from the peer inside ACK_EXTENDED frames.
  // 0 means no support.
  // Otherwise the bits of the integer indicate the following:
  // - Bit 0: support for ACK_EXTENDED frame with ECN fields
  // - Bit 1: support for ACK_EXTENDED frame with receive timestamp fields
  // The list of features corresponds to ExtendedAckFeatures in QuicConstants
  ExtendedAckFeatureMaskType advertisedExtendedAckFeatures{0};

  // Send ACK_EXTENDED frames if supported by the peer. The integer is treated
  // in the same way as the one advertised to the peer. If the value is
  // not-zero, the transport will send ACK_EXTENDED frames with the fields that
  // are enabled both in this field and supported by the peer.
  uint64_t enableExtendedAckFeatures{0};

  bool removeStreamAfterEomCallbackUnset{false};
  // Whether to include cwnd hint in new session tickets for 0-rtt
  bool includeCwndHintsInSessionTicket{false};
  // Whether to use cwnd hints received in resumption tickets for 0-rtt
  bool useCwndHintsInSessionTicket{false};

  // The default priority to instantiate streams with.
  PriorityQueue::Priority defaultPriority;

  // Local configuration for ACK receive timestamps.
  //
  // Determines the ACK receive timestamp configuration sent to peer,
  // which in turn determines the maximum number of timestamps and
  // timestamp resolution included in ACK messages sent by the peer
  // if the peer supports ACK receive timestamps.
  //
  // If structure is not initialized, ACK receive timestamps are
  // not requested from peer regardless of whether the peer
  // supports them.
  //
  // This endpoint sends receive timestamps to a peer that requests them only
  // when this is set.
  Optional<AckReceiveTimestampsConfig>
      maybeAckReceiveTimestampsConfigSentToPeer;

  // Maximum number of received packet timestamps stored per ACK. This will be
  // controlled by a MC and will be dependent on device capabilities and
  // resources. Hence, this isn't contigent on whether ACK receive timestamps
  // are enabled or not and should not a part of
  //  maybeAckReceiveTimestampsConfigSentToPeer optional.
  uint64_t maxReceiveTimestampsPerAckStored{kMaxReceivedPktsTimestampsStored};

  // When true, advertise the draft-ietf-quic-receive-ts-02 transport
  // parameters (TP 0x4ac07, 0x4ac26) whenever
  // `maybeAckReceiveTimestampsConfigSentToPeer` is set, accept incoming
  // draft-02 ACK_RECEIVE_TIMESTAMPS frames, and don't send legacy mvfst or
  // ACK_EXTENDED receive timestamps. Accepting those is governed by
  // `advertiseLegacyAckReceiveTimestamps`.
  bool enableIetfAckReceiveTimestamps{false};
  // When true, advertise the legacy mvfst receive-timestamps transport
  // parameters (ack_receive_timestamps_enabled = 0xff0a001 and friends).
  bool advertiseLegacyAckReceiveTimestamps{true};
  // When true, send draft-02 ACK_RECEIVE_TIMESTAMPS frames instead of legacy
  // ones to a peer that advertised the draft-02 receive-timestamps TPs, as
  // long as `maybeAckReceiveTimestampsConfigSentToPeer` is set. Independent
  // of `enableIetfAckReceiveTimestamps` (draft-ietf-quic-receive-ts-02
  // negotiation is one-way).
  bool sendDraft02AckReceiveTimestamps{true};
  // Close the connection completely if a migration occurs during the handshake.
  bool closeIfMigrationDuringHandshake{true};
  // Whether to use writable bytes to apply app backpressure via the callbacks
  // for the max writable on stream or connection. The value is a multiplier
  // for the writable bytes given in the callback, which may be useful for
  // allowing cwnd growth. 0 disables. The amount given to callbacks has the
  // current amount of stream bytes buffered subtracted from it.
  uint8_t backpressureHeadroomFactor{0};

  // Whether to initiate key updates
  bool initiateKeyUpdate{false};
  // How many packets to send before initiating the first key update.
  // This is reset to std::nullopt after the first key update is initiated.
  OptionalIntegral<uint64_t> firstKeyUpdatePacketCount{
      kFirstKeyUpdatePacketCount};
  // How many packets to send before initiating periodic key updates
  uint64_t keyUpdatePacketCountInterval{kDefaultKeyUpdatePacketCountInterval};

  // Temporary flag to test new stream blocked condition.
  bool useNewStreamBlockedCondition{false};
  // Whether app streams use the unified owning send buffer.
  bool useUnifiedAppStreamSendBuffer{false};
  // Whether PTO probes retransmit frames without cloning packets.
  bool useNonCloningPto{false};
  bool scheduleTimerForExcessWrites{false};

  // Whether to read ECN bits from ingress packets
  bool readEcnOnIngress{false};

  // Whether to read the IP TTL from ingress packets. Only implemented for
  // Linux; elsewhere the socket option is never applied and the TTL stays 0.
  bool readTtlOnIngress{false};

  // DSCP value to use for outgoing packet. The two least significant bits of
  // the ToS field are for ECN controlled by the following two options.
  uint8_t dscpValue{0};
  // Whether to enable ECN on egress packets
  bool enableEcnOnEgress{false};
  // Whether to use L4S ECN (enableEcnOnEgress must be enabled)
  bool useL4sEcn{false};

  bool useSockWritableEvents{false};
  // Ack timeout = SRTT * ackTimerFactor
  double ackTimerFactor{kAckTimerFactor};
  // If flow control updates should be sent based on time passed since last
  // update.
  bool disableFlowControlTimeBasedUpdates{false};
  // Whether to trigger packet processing per socket read rather than batch
  // receiving and then processing.
  bool networkDataPerSocketRead{false};
  bool immediatelyRetransmitInitialPackets{false};

  // Ceiling of packets to receive from signaled socket per evb loop on the
  // server side.
  uint16_t maxServerRecvPacketsPerLoop{1};

  // Support "paused" requests which buffer on the server without streaming back
  // to the client.
  bool disablePausedPriority{false};

  // Randomly skip one in N sequence numbers when sending packets.
  uint16_t skipOneInNPacketSequenceNumber{kSkipOneInNPacketSequenceNumber};

  // When set to true it creates a transport for the sole purpose of
  // retrieving 0-RTT data to a given destination
  bool isPriming{false};

  // On the client-side, if non-null, it indicates that the client supports
  // direct encapsulation. The value contains the zone the client is in.
  Optional<uint8_t> clientDirectEncapConfig;

  // On the server-side, if this is not null, it indicates that the
  // server supports direct encapsulation. The config specifies the direct
  // encap address and a bitmask of the supported zones.
  Optional<ServerDirectEncapConfig> serverDirectEncapConfig;

  // Stream buffer threshold for determining imminent stream completion.
  // If buffer is about to fall below, send entire buffer immediately.
  uint16_t minStreamBufThresh{0};

  // Increase CCA CWND limit if imminent stream completion.
  uint16_t excessCwndPctForImminentStreams{0};

  // Whether a ConnectionClose frame should be sent on IdleTimeout
  bool alwaysSendConnectionCloseOnIdleTimeout{false};

  // TODO(T239869314): Remove this after experiment is done.
  std::chrono::milliseconds keepAliveTimeout{0};

  // Advertise the scone_supported transport parameter and flow-indicator bytes.
  // Required to receive SCONE packets.
  bool advertiseSconeSupport{false};
  // Emit SCONE packets when shouldSendSconePacket allows. Set by SCONE_KNOB.
  bool enableSconeSend{false};
  std::chrono::seconds sconePacketInterval{20};

  // Enable path degradation / blackhole detection callbacks.
  // When enabled, the transport fires onPathDegrading() and
  // onBlackholeDetected() on ConnectionCallback at ptoCount thresholds.
  bool enablePathDegradationDetection{false};

  // Number of consecutive PTOs before firing onPathDegrading.
  uint16_t numPtosForPathDegrading{kDefaultNumPtosForPathDegrading};

  // Number of consecutive PTOs before firing onBlackholeDetected.
  // Must be > numPtosForPathDegrading and < maxNumPTOs.
  uint16_t numPtosForBlackhole{kDefaultNumPtosForBlackhole};
};

} // namespace quic
