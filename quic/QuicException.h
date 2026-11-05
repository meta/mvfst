/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fmt/format.h>
#include <folly/Range.h>
#include <quic/QuicConstants.h>
#include <quic/QuicTLSException.h>
#include <quic/common/Optional.h>
#include <stdexcept>
#include <string>
#include <utility>

#include <quic/common/Variant.h>

namespace quic {

#define QUIC_ERROR_CODE(F, ...)        \
  F(ApplicationErrorCode, __VA_ARGS__) \
  F(LocalErrorCode, __VA_ARGS__)       \
  F(TransportErrorCode, __VA_ARGS__)

DECLARE_VARIANT_TYPE(QuicErrorCode, QUIC_ERROR_CODE)

struct QuicError {
  QuicError(QuicErrorCode codeIn, std::string&& messageIn)
      : code(std::move(codeIn)), message(std::move(messageIn)) {}

  explicit QuicError(QuicErrorCode codeIn) : code(std::move(codeIn)) {}

  bool operator==(const QuicError& other) const {
    return code == other.code && message == other.message;
  }

  bool operator!=(const QuicError& other) const {
    return !(*this == other);
  }

  QuicErrorCode code;
  std::string message;
};

class QuicTransportException : public std::runtime_error {
 public:
  explicit QuicTransportException(
      const std::string& msg,
      TransportErrorCode errCode);

  explicit QuicTransportException(const char* msg, TransportErrorCode errCode);

  [[nodiscard]] TransportErrorCode errorCode() const noexcept {
    return errCode_;
  }

 private:
  TransportErrorCode errCode_;
};

class QuicInternalException : public std::runtime_error {
 public:
  explicit QuicInternalException(
      const std::string& msg,
      LocalErrorCode errorCode);
  explicit QuicInternalException(const char* msg, LocalErrorCode errCode);
  explicit QuicInternalException(
      folly::StringPiece msg,
      LocalErrorCode errCode);

  [[nodiscard]] LocalErrorCode errorCode() const noexcept {
    return errorCode_;
  }

 private:
  LocalErrorCode errorCode_;
};

class QuicApplicationException : public std::runtime_error {
 public:
  explicit QuicApplicationException(
      const std::string& msg,
      ApplicationErrorCode errorCode);
  explicit QuicApplicationException(
      const char* msg,
      ApplicationErrorCode errorCode);

  [[nodiscard]] ApplicationErrorCode errorCode() const noexcept {
    return errorCode_;
  }

 private:
  ApplicationErrorCode errorCode_;
};

bool isCryptoError(TransportErrorCode code);

/**
 * Convert the error code to a string.
 */
std::string toString(LocalErrorCode code);

std::string toString(TransportErrorCode code);
std::string toString(QuicErrorCode code);
std::string toString(const QuicError& error);

std::vector<TransportErrorCode> getAllTransportErrorCodes();
std::vector<LocalErrorCode> getAllLocalErrorCodes();

std::ostream& operator<<(std::ostream& os, const QuicErrorCode& error);

std::ostream& operator<<(std::ostream& os, const QuicError& error);

} // namespace quic

// Render these QUIC error types through quic::toString() for any fmt-based
// formatting ("{}" in XR_LOG / folly logging / fmt::format), instead of fmt's
// std::ostream fallback. That fallback dispatches into the out-of-line
// quic::operator<< defined in a separate shared library, crossing the .so
// boundary on an iostream whose streambuf vtable the two translation units
// disagree on -- a latent ABI hazard that SIGSEGVs on some builds (e.g. the XR
// cloud-browser client on QUIC connection teardown). An explicit formatter
// specialization is also strictly more specialized than the ostream fallback,
// so selection is unambiguous.
namespace fmt {

template <>
struct formatter<quic::QuicErrorCode> : formatter<std::string> {
  template <typename FormatContext>
  auto format(const quic::QuicErrorCode& code, FormatContext& ctx) const {
    return formatter<std::string>::format(quic::toString(code), ctx);
  }
};

template <>
struct formatter<quic::QuicError> : formatter<std::string> {
  template <typename FormatContext>
  auto format(const quic::QuicError& error, FormatContext& ctx) const {
    return formatter<std::string>::format(quic::toString(error), ctx);
  }
};

template <>
struct formatter<quic::LocalErrorCode> : formatter<std::string> {
  template <typename FormatContext>
  auto format(quic::LocalErrorCode code, FormatContext& ctx) const {
    return formatter<std::string>::format(quic::toString(code), ctx);
  }
};

template <>
struct formatter<quic::TransportErrorCode> : formatter<std::string> {
  template <typename FormatContext>
  auto format(quic::TransportErrorCode code, FormatContext& ctx) const {
    return formatter<std::string>::format(quic::toString(code), ctx);
  }
};

} // namespace fmt
