/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/IOBuf.h>
#include <quic/common/MvfstLogging.h>
#include <quic/server/handshake/TokenGenerator.h>

#include <folly/Range.h>
#include <quic/codec/Decode.h>

namespace {

const std::vector<std::string> kCipherContexts = {"RetryToken_V2"};

} // namespace

namespace quic {

TokenGenerator::TokenGenerator(TokenSecret secret) : cipher_(kCipherContexts) {
  std::vector<ByteRange> secrets;
  secrets.emplace_back(secret.data(), secret.size());
  cipher_.setSecrets(secrets);
}

Optional<BufPtr> TokenGenerator::encryptToken(
    const QuicAddrValidationToken& token) {
  // Generate the retry token in plaintext
  auto plainTextToken = token.getPlaintextToken();

  // Try to encrypt it
  auto maybeEncryptedToken = cipher_.encrypt(
      std::move(plainTextToken), token.genAeadAssocData().get());
  if (!maybeEncryptedToken) {
    MVLOG_ERROR << "Failed to encypt addr validation token with IP "
                << token.clientIp.str();
    return {};
  }

  // Convert folly::Optional to quic::Optional (tiny::optional)
  return Optional<BufPtr>(std::move(maybeEncryptedToken.value()));
}

uint64_t TokenGenerator::decryptToken(
    BufPtr encryptedToken,
    BufPtr aeadAssocData) {
  auto maybeDecryptedToken =
      cipher_.decrypt(std::move(encryptedToken), aeadAssocData.get());

  if (!maybeDecryptedToken) {
    return 0;
  }

  // Try to parse the decrypted token
  auto decryptedToken = (*maybeDecryptedToken).get();
  ContiguousReadCursor cursor(decryptedToken->data(), decryptedToken->length());

  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  if (parseResult.hasError()) {
    MVLOG_ERROR << "Failed to parse decrypted retry token";
    return 0;
  }

  return parseResult.value();
}

Optional<RetryToken> TokenGenerator::decryptRetryToken(
    BufPtr encryptedToken,
    const ConnectionId& dstConnId,
    const folly::IPAddress& clientIp) {
  // Both token forms are bound to the destination connection id of the
  // client's Initial, which is the Retry's source connection id.
  RetryToken token(dstConnId, clientIp, 0);
  auto maybeDecryptedToken = cipher_.decrypt(
      std::move(encryptedToken), token.genAeadAssocData().get());
  if (!maybeDecryptedToken) {
    return std::nullopt;
  }

  auto decryptedToken = (*maybeDecryptedToken).get();
  ContiguousReadCursor cursor(decryptedToken->data(), decryptedToken->length());
  auto timestampResult = parsePlaintextRetryOrNewToken(cursor);
  if (timestampResult.hasError()) {
    MVLOG_ERROR << "Failed to parse decrypted retry token";
    return std::nullopt;
  }
  token.timestampInMs = timestampResult.value();
  if (cursor.isAtEnd()) {
    return token;
  }

  uint8_t originalDstConnIdLen = 0;
  if (!cursor.tryReadBE(originalDstConnIdLen)) {
    return std::nullopt;
  }
  auto originalDstConnId = ConnectionId::create(cursor, originalDstConnIdLen);
  if (originalDstConnId.hasError()) {
    MVLOG_ERROR << "Failed to parse original destination connection id in "
                << "retry token";
    return std::nullopt;
  }
  token.originalDstConnId = originalDstConnId.value();
  token.retrySrcConnId = dstConnId;
  return token;
}

} // namespace quic
