/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstLogging.h>

namespace quic {

// macro for repetitive static_cast<uint64_t>(TransportParameterId)
#define u64_tp(tp_id) static_cast<uint64_t>(tp_id)

enum class TransportParameterId : uint64_t {
  original_destination_connection_id = 0x0000,
  idle_timeout = 0x0001,
  stateless_reset_token = 0x0002,
  max_packet_size = 0x0003,
  initial_max_data = 0x0004,
  initial_max_stream_data_bidi_local = 0x0005,
  initial_max_stream_data_bidi_remote = 0x0006,
  initial_max_stream_data_uni = 0x0007,
  initial_max_streams_bidi = 0x0008,
  initial_max_streams_uni = 0x0009,
  ack_delay_exponent = 0x000a,
  max_ack_delay = 0x000b,
  disable_migration = 0x000c,
  preferred_address = 0x000d,
  active_connection_id_limit = 0x000e,
  initial_source_connection_id = 0x000f,
  retry_source_connection_id = 0x0010,
  max_datagram_frame_size = 0x0020,
  min_ack_delay = 0xff04de1a,
  ack_receive_timestamps_enabled = 0xff0a001,
  max_receive_timestamps_per_ack = 0xff0a002,
  receive_timestamps_exponent = 0xff0a003,
  extended_ack_features = 0xff0a004,
  timestamp_frame_supported = 0xff0a005,
  timestamp_frame_timestamp_exponent = 0xff0a006,
  // draft-ietf-quic-receive-ts-02 transport parameter IDs. Underlying
  // values live in QuicConstants.h. The draft has no `_enabled` boolean;
  // support is implied by the presence of
  // `draft_02_max_receive_timestamps_per_ack`.
  draft_02_max_receive_timestamps_per_ack =
      kDraft02MaxReceiveTimestampsPerAckTpId,
  draft_02_receive_timestamps_exponent = kDraft02ReceiveTimestampsExponentTpId,
  knob_frames_supported = 0x00005178,
  cwnd_hint_bytes = 0x00007492,
  rtt_hint_ms = 0x00007493,
  client_direct_encap = 0x000042fc,
  server_direct_encap = 0x000042fd,
  reliable_stream_reset = 0x1d,
  // Codepoint from earlier drafts. Accepted from peers but never sent.
  reliable_stream_reset_legacy = 0x17f7586d2cb571,
  scone_supported = 0x219e,
  quic_experiment = 0x3a65db
};

struct TransportParameter {
  TransportParameterId parameter;
  BufPtr value;

  TransportParameter() = default;

  TransportParameter(TransportParameterId p, BufPtr v)
      : parameter(p), value(v ? std::move(v) : nullptr) {}

  TransportParameter(const TransportParameter& other)
      : parameter(other.parameter),
        value(other.value ? other.value->clone() : nullptr) {}

  TransportParameter& operator=(TransportParameter&& other) noexcept {
    parameter = other.parameter;
    value = std::move(other.value);
    return *this;
  }

  /**
   * RFC9000:
   * Each transport parameter is encoded as an (identifier, length, value)
   * tuple:
   *
   *  Transport Parameter {
   *    Transport Parameter ID (i),
   *    Transport Parameter Length (i),
   *    Transport Parameter Value (..),
   *  }
   */

  // calc size needed to encode TransportParameter on the wire as shown above
  [[nodiscard]] uint64_t getEncodedSize() const {
    // varint size of param + varint size of value's length + size of value
    uint64_t valueLen = value->computeChainDataLength();
    return getQuicIntegerSize(u64_tp(parameter)).value() +
        getQuicIntegerSize(valueLen).value() + valueLen;
  }

  // Encodes TransportParameter as shown above (avoids reallocations)
  [[nodiscard]] BufPtr encode() const {
    // reserve the exact size needed
    auto res =
        BufHelpers::createCombined(static_cast<size_t>(getEncodedSize()));

    // write parameter; need to improve QuicInteger encoding methods
    BufWriter writer(res->writableData(), res->capacity());
    auto appenderOp = [&](auto val) { writer.writeBE(val); };
    MVCHECK(encodeQuicInteger(u64_tp(parameter), appenderOp));

    // write size of value
    MVCHECK(encodeQuicInteger(value->computeChainDataLength(), appenderOp));

    // write value if present
    if (value) {
      writer.insert(value.get());
    }

    res->append(writer.getBytesWritten());
    return res;
  }
};

struct ClientTransportParameters {
  std::vector<TransportParameter> parameters;
};

struct ServerTransportParameters {
  std::vector<TransportParameter> parameters;
};

struct TicketTransportParameters {
  std::vector<TransportParameter> parameters;
};

inline auto findParameter(
    const std::vector<TransportParameter>& parameters,
    TransportParameterId id) {
  return std::find_if(parameters.begin(), parameters.end(), [id](auto& param) {
    return param.parameter == id;
  });
}

quic::Expected<Optional<uint64_t>, QuicError> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

quic::Expected<Optional<ConnectionId>, QuicError> getConnIdParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

quic::Expected<Optional<StatelessResetToken>, QuicError>
getStatelessResetTokenParameter(
    const std::vector<TransportParameter>& parameters);

quic::Expected<TransportParameter, QuicError> encodeIntegerParameter(
    TransportParameterId id,
    uint64_t value);

TransportParameter encodeIPAddressParameter(
    TransportParameterId id,
    const folly::IPAddress& addr);

bool getSconeSupportedParameter(
    const std::vector<TransportParameter>& parameters);

// True if the peer sent reset_stream_at under either codepoint.
quic::Expected<bool, QuicError> getReliableStreamResetParameter(
    const std::vector<TransportParameter>& parameters);

TransportParameter encodeSconeSupportedParameter();

inline TransportParameter encodeEmptyParameter(TransportParameterId id) {
  TransportParameter param;
  param.parameter = id;
  param.value = BufHelpers::create(0);
  return param;
}

inline TransportParameter encodeConnIdParameter(
    TransportParameterId id,
    const ConnectionId& connId) {
  return {id, BufHelpers::copyBuffer(connId.data(), connId.size())};
}

inline TransportParameter encodeStatelessResetToken(
    const StatelessResetToken& token) {
  TransportParameter statelessReset;
  statelessReset.parameter = TransportParameterId::stateless_reset_token;
  statelessReset.value = BufHelpers::copyBuffer(token.data(), token.size());
  return statelessReset;
}

struct QuicConnectionStateBase;

std::vector<TransportParameter> getSupportedExtTransportParams(
    const QuicConnectionStateBase& conn);

} // namespace quic
