/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/QuicTLSException.h> // @manual

#include <quic/common/MvfstLogging.h>
#include <vector>

namespace quic {

QuicTransportException::QuicTransportException(
    const std::string& msg,
    TransportErrorCode errCode)
    : std::runtime_error(msg), errCode_(errCode) {}

QuicTransportException::QuicTransportException(
    const char* msg,
    TransportErrorCode errCode)
    : std::runtime_error(msg), errCode_(errCode) {}

QuicInternalException::QuicInternalException(
    const std::string& msg,
    LocalErrorCode errCode)
    : std::runtime_error(msg), errorCode_(errCode) {}

QuicInternalException::QuicInternalException(
    const char* msg,
    LocalErrorCode errCode)
    : std::runtime_error(msg), errorCode_(errCode) {}

QuicInternalException::QuicInternalException(
    folly::StringPiece msg,
    LocalErrorCode errCode)
    : std::runtime_error(fmt::format("{}", msg)), errorCode_(errCode) {}

QuicApplicationException::QuicApplicationException(
    const std::string& msg,
    ApplicationErrorCode errorCode)
    : std::runtime_error(msg), errorCode_(errorCode) {}

QuicApplicationException::QuicApplicationException(
    const char* msg,
    ApplicationErrorCode errorCode)
    : std::runtime_error(msg), errorCode_(errorCode) {}

bool isCryptoError(TransportErrorCode code) {
  return code >= TransportErrorCode::CRYPTO_ERROR &&
      code <= TransportErrorCode::CRYPTO_ERROR_MAX;
}

std::string toString(LocalErrorCode code) {
  switch (code) {
    case LocalErrorCode::NO_ERROR:
      return "No Error";
    case LocalErrorCode::CONNECT_FAILED:
      return "Connect failed";
    case LocalErrorCode::CODEC_ERROR:
      return "Codec Error";
    case LocalErrorCode::STREAM_CLOSED:
      return "Stream is closed";
    case LocalErrorCode::STREAM_NOT_EXISTS:
      return "Stream does not exist";
    case LocalErrorCode::CREATING_EXISTING_STREAM:
      return "Creating an existing stream";
    case LocalErrorCode::SHUTTING_DOWN:
      return "Shutting down";
    case LocalErrorCode::RESET_CRYPTO_STREAM:
      return "Reset the crypto stream";
    case LocalErrorCode::CWND_OVERFLOW:
      return "CWND overflow";
    case LocalErrorCode::INFLIGHT_BYTES_OVERFLOW:
      return "Inflight bytes overflow";
    case LocalErrorCode::LOST_BYTES_OVERFLOW:
      return "Lost bytes overflow";
    case LocalErrorCode::NEW_VERSION_NEGOTIATED:
      return "New version negotiatied";
    case LocalErrorCode::INVALID_WRITE_CALLBACK:
      return "Invalid write callback";
    case LocalErrorCode::CALLBACK_ALREADY_INSTALLED:
      return "Callback already installed";
    case LocalErrorCode::TLS_HANDSHAKE_FAILED:
      return "TLS handshake failed";
    case LocalErrorCode::APP_ERROR:
      return "App error";
    case LocalErrorCode::INTERNAL_ERROR:
      return "Internal error";
    case LocalErrorCode::TRANSPORT_ERROR:
      return "Transport error";
    case LocalErrorCode::INVALID_WRITE_DATA:
      return "Invalid write data";
    case LocalErrorCode::INVALID_STATE_TRANSITION:
      return "Invalid state transition";
    case LocalErrorCode::CONNECTION_CLOSED:
      return "Connection closed";
    case LocalErrorCode::EARLY_DATA_REJECTED:
      return "Early data rejected";
    case LocalErrorCode::CONNECTION_RESET:
      return "Connection reset";
    case LocalErrorCode::IDLE_TIMEOUT:
      return "Idle timeout";
    case LocalErrorCode::PACKET_NUMBER_ENCODING:
      return "Packet number encoding";
    case LocalErrorCode::INVALID_OPERATION:
      return "Invalid operation";
    case LocalErrorCode::STREAM_LIMIT_EXCEEDED:
      return "Stream limit exceeded";
    case LocalErrorCode::CONNECTION_ABANDONED:
      return "Connection abandoned";
    case LocalErrorCode::KNOB_FRAME_UNSUPPORTED:
      return "Knob Frame Not Supported";
    case LocalErrorCode::PACER_NOT_AVAILABLE:
      return "Pacer not available";
    case LocalErrorCode::RTX_POLICIES_LIMIT_EXCEEDED:
      return "Retransmission policies limit exceeded";
    case LocalErrorCode::CONGESTION_CONTROL_ERROR:
      return "Congestion control error";
    case LocalErrorCode::PATH_NOT_EXISTS:
      return "Path does not exist";
    case LocalErrorCode::PATH_MANAGER_ERROR:
      return "Path manager error";
    case LocalErrorCode::NO_AVAILABLE_CID:
      return "No available connection ids";
    case quic::LocalErrorCode::MIGRATION_FAILED:
      return "Migration failed";
  }
  MVLOG_WARNING << "toString has unhandled LocalErrorCode";
  return "Unknown error";
}

std::string toString(TransportErrorCode code) {
  switch (code) {
    case TransportErrorCode::NO_ERROR:
      return "No Error";
    case TransportErrorCode::INTERNAL_ERROR:
      return "Internal Error";
    case TransportErrorCode::FLOW_CONTROL_ERROR:
      return "Flow control error";
    case TransportErrorCode::STREAM_LIMIT_ERROR:
      return "Stream limit error";
    case TransportErrorCode::STREAM_STATE_ERROR:
      return "Stream State error";
    case TransportErrorCode::FINAL_SIZE_ERROR:
      return "Final offset error";
    case TransportErrorCode::FRAME_ENCODING_ERROR:
      return "Frame format error";
    case TransportErrorCode::TRANSPORT_PARAMETER_ERROR:
      return "Transport parameter error";
    case TransportErrorCode::PROTOCOL_VIOLATION:
      return "Protocol violation";
    case TransportErrorCode::INVALID_MIGRATION:
      return "Invalid migration";
    case TransportErrorCode::SERVER_BUSY:
      return "Server busy";
    case TransportErrorCode::INVALID_TOKEN:
      return "Invalid token";
    case TransportErrorCode::CRYPTO_BUFFER_EXCEEDED:
      return "Crypto buffer exceeded";
    case TransportErrorCode::CRYPTO_ERROR:
      return cryptoErrorToString(code);
    case TransportErrorCode::CRYPTO_ERROR_MAX:
      return cryptoErrorToString(code);
  }

  if (isCryptoError(code)) {
    return cryptoErrorToString(code);
  }

  MVLOG_WARNING << "toString has unhandled ErrorCode";
  return "Unknown error";
}

std::vector<TransportErrorCode> getAllTransportErrorCodes() {
  std::vector<TransportErrorCode> all = {
      TransportErrorCode::NO_ERROR,
      TransportErrorCode::INTERNAL_ERROR,
      TransportErrorCode::SERVER_BUSY,
      TransportErrorCode::FLOW_CONTROL_ERROR,
      TransportErrorCode::STREAM_LIMIT_ERROR,
      TransportErrorCode::STREAM_STATE_ERROR,
      TransportErrorCode::FINAL_SIZE_ERROR,
      TransportErrorCode::FRAME_ENCODING_ERROR,
      TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
      TransportErrorCode::PROTOCOL_VIOLATION,
      TransportErrorCode::INVALID_MIGRATION,
      TransportErrorCode::CRYPTO_ERROR,
      TransportErrorCode::CRYPTO_ERROR_MAX,
      TransportErrorCode::INVALID_TOKEN,
      TransportErrorCode::CRYPTO_BUFFER_EXCEEDED};
  return all;
}

std::vector<LocalErrorCode> getAllLocalErrorCodes() {
  std::vector<LocalErrorCode> all = {
      LocalErrorCode::NO_ERROR,
      LocalErrorCode::CONNECT_FAILED,
      LocalErrorCode::CODEC_ERROR,
      LocalErrorCode::STREAM_CLOSED,
      LocalErrorCode::STREAM_NOT_EXISTS,
      LocalErrorCode::CREATING_EXISTING_STREAM,
      LocalErrorCode::SHUTTING_DOWN,
      LocalErrorCode::RESET_CRYPTO_STREAM,
      LocalErrorCode::CWND_OVERFLOW,
      LocalErrorCode::INFLIGHT_BYTES_OVERFLOW,
      LocalErrorCode::LOST_BYTES_OVERFLOW,
      LocalErrorCode::NEW_VERSION_NEGOTIATED,
      LocalErrorCode::INVALID_WRITE_CALLBACK,
      LocalErrorCode::TLS_HANDSHAKE_FAILED,
      LocalErrorCode::APP_ERROR,
      LocalErrorCode::INTERNAL_ERROR,
      LocalErrorCode::TRANSPORT_ERROR,
      LocalErrorCode::INVALID_WRITE_DATA,
      LocalErrorCode::INVALID_STATE_TRANSITION,
      LocalErrorCode::CONNECTION_CLOSED,
      LocalErrorCode::EARLY_DATA_REJECTED,
      LocalErrorCode::CONNECTION_RESET,
      LocalErrorCode::IDLE_TIMEOUT,
      LocalErrorCode::PACKET_NUMBER_ENCODING,
      LocalErrorCode::INVALID_OPERATION,
      LocalErrorCode::STREAM_LIMIT_EXCEEDED,
      LocalErrorCode::CONNECTION_ABANDONED,
      LocalErrorCode::CALLBACK_ALREADY_INSTALLED,
      LocalErrorCode::KNOB_FRAME_UNSUPPORTED,
      LocalErrorCode::PACER_NOT_AVAILABLE,
  };
  return all;
}

std::string toString(QuicErrorCode code) {
  switch (code.type()) {
    case QuicErrorCode::Type::ApplicationErrorCode:
      if (*code.asApplicationErrorCode() ==
          GenericApplicationErrorCode::NO_ERROR) {
        return "No Error";
      }
      return fmt::format("{}", *code.asApplicationErrorCode());
    case QuicErrorCode::Type::LocalErrorCode:
      return toString(*code.asLocalErrorCode());
    case QuicErrorCode::Type::TransportErrorCode:
      return toString(*code.asTransportErrorCode());
  }
  folly::assume_unreachable();
}

std::string toString(const QuicError& error) {
  std::string err;
  switch (error.code.type()) {
    case QuicErrorCode::Type::ApplicationErrorCode:
      err = "ApplicationError: " +
          toString(*error.code.asApplicationErrorCode()) + ", ";
      break;
    case QuicErrorCode::Type::LocalErrorCode:
      err = "LocalError: " +
          fmt::format("{}, ", toString(*error.code.asLocalErrorCode()));
      break;
    case QuicErrorCode::Type::TransportErrorCode:
      err = "TransportError: " + toString(*error.code.asTransportErrorCode()) +
          ", ";
  }
  if (!error.message.empty()) {
    err = fmt::format("{}{}", err, error.message);
  }
  return err;
}

std::ostream& operator<<(std::ostream& os, const QuicErrorCode& error) {
  os << toString(error);
  return os;
}

std::ostream& operator<<(std::ostream& os, const QuicError& error) {
  os << toString(error);
  return os;
}
} // namespace quic
