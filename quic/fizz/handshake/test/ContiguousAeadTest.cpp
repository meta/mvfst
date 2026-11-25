/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/ContiguousAead.h>

#include <fizz/protocol/Types.h>
#include <folly/portability/GTest.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>

namespace quic::test {

namespace {

constexpr folly::StringPiece kPlaintext = "hello quic packet protection";
constexpr folly::StringPiece kHeader = "packet header";
constexpr uint64_t kSeqNum = 42;

// mvfst leaves tailroom for the tag, which fizz's in-place encrypt requires.
BufPtr makePlaintext() {
  return folly::IOBuf::copyBuffer(
      kPlaintext, /*headroom=*/0, ContiguousAead::kTagLength);
}

fizz::TrafficKey makeTrafficKey() {
  fizz::TrafficKey key;
  key.key = folly::IOBuf::copyBuffer(std::string(16, '\x42'));
  key.iv = folly::IOBuf::copyBuffer(std::string(12, '\x01'));
  return key;
}

// AES-128-GCM through OpenSSL's EVP interface, as an independent cipher.
class OpenSSLContiguousAead : public ContiguousAead {
 public:
  explicit OpenSSLContiguousAead(bool fail = false)
      : ContiguousAead(makeTrafficKey()),
        key_(makeTrafficKey().key->moveToFbString().toStdString()),
        fail_(fail) {}

 private:
  [[nodiscard]] bool seal(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> plaintext,
      std::span<uint8_t> ciphertext,
      std::span<uint8_t> tag) const override {
    if (fail_) {
      return false;
    }
    auto ctx = init(nonce, aad, /*encrypt=*/true);
    int len = 0;
    return EVP_EncryptUpdate(
               ctx.get(),
               ciphertext.data(),
               &len,
               plaintext.data(),
               static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(tag.size()),
            tag.data()) == 1;
  }

  [[nodiscard]] bool open(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> ciphertext,
      std::span<const uint8_t> tag,
      std::span<uint8_t> plaintext) const override {
    auto ctx = init(nonce, aad, /*encrypt=*/false);
    int len = 0;
    return EVP_DecryptUpdate(
               ctx.get(),
               plaintext.data(),
               &len,
               ciphertext.data(),
               static_cast<int>(ciphertext.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()),
            const_cast<uint8_t*>(tag.data())) == 1 &&
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) == 1;
  }

  [[nodiscard]] folly::ssl::EvpCipherCtxUniquePtr init(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      bool encrypt) const {
    folly::ssl::EvpCipherCtxUniquePtr ctx(EVP_CIPHER_CTX_new());
    EVP_CipherInit_ex(
        ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr, encrypt);
    EVP_CIPHER_CTX_ctrl(
        ctx.get(),
        EVP_CTRL_GCM_SET_IVLEN,
        static_cast<int>(nonce.size()),
        nullptr);
    EVP_CipherInit_ex(
        ctx.get(),
        nullptr,
        nullptr,
        reinterpret_cast<const uint8_t*>(key_.data()),
        nonce.data(),
        encrypt);
    int len = 0;
    EVP_CipherUpdate(
        ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size()));
    return ctx;
  }

  std::string key_;
  bool fail_;
};

std::unique_ptr<Aead> makeFizzAead() {
  std::unique_ptr<fizz::Aead> aead;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      QuicFizzFactory().makeAead(
          aead, err, fizz::CipherSuite::TLS_AES_128_GCM_SHA256),
      err);
  FIZZ_THROW_ON_ERROR(aead->setKey(err, makeTrafficKey()), err);
  return FizzAead::wrap(std::move(aead));
}

BufPtr encrypt(const Aead& aead, BufPtr plaintext, const Buf* header) {
  auto result = aead.inplaceEncrypt(std::move(plaintext), header, kSeqNum);
  EXPECT_TRUE(result.has_value()) << result.error().message;
  return std::move(result.value());
}

std::string toString(const BufPtr& buf) {
  return buf->clone()->moveToFbString().toStdString();
}

} // namespace

TEST(ContiguousAeadTest, EncryptMatchesFizz) {
  const OpenSSLContiguousAead aead;
  const auto fizzAead = makeFizzAead();
  const auto header = folly::IOBuf::copyBuffer(kHeader);

  const auto ciphertext = encrypt(aead, makePlaintext(), header.get());

  EXPECT_EQ(
      toString(ciphertext),
      toString(encrypt(*fizzAead, makePlaintext(), header.get())));
}

TEST(ContiguousAeadTest, EncryptCoalescesChainedPlaintext) {
  const OpenSSLContiguousAead aead;
  const auto fizzAead = makeFizzAead();
  auto chained = folly::IOBuf::copyBuffer(kPlaintext.subpiece(0, 10));
  chained->appendToChain(folly::IOBuf::copyBuffer(kPlaintext.subpiece(10)));

  const auto ciphertext = encrypt(aead, std::move(chained), nullptr);

  EXPECT_EQ(
      toString(ciphertext),
      toString(encrypt(*fizzAead, makePlaintext(), nullptr)));
}

TEST(ContiguousAeadTest, DecryptsFizzCiphertext) {
  const OpenSSLContiguousAead aead;
  const auto header = folly::IOBuf::copyBuffer(kHeader);
  auto ciphertext = encrypt(*makeFizzAead(), makePlaintext(), header.get());

  const auto plaintext =
      aead.tryDecrypt(std::move(ciphertext), header.get(), kSeqNum);

  ASSERT_TRUE(plaintext.has_value());
  EXPECT_EQ(toString(*plaintext), kPlaintext);
}

TEST(ContiguousAeadTest, TryDecryptRejectsWrongHeader) {
  const OpenSSLContiguousAead aead;
  auto ciphertext =
      encrypt(aead, makePlaintext(), folly::IOBuf::copyBuffer(kHeader).get());

  EXPECT_FALSE(aead.tryDecrypt(
                       std::move(ciphertext),
                       folly::IOBuf::copyBuffer("wrong header").get(),
                       kSeqNum)
                   .has_value());
}

TEST(ContiguousAeadTest, TryDecryptRejectsShorterThanTag) {
  const OpenSSLContiguousAead aead;

  EXPECT_FALSE(
      aead.tryDecrypt(folly::IOBuf::copyBuffer("short"), nullptr, kSeqNum)
          .has_value());
}

TEST(ContiguousAeadTest, EncryptFailureIsAnError) {
  const OpenSSLContiguousAead aead(/*fail=*/true);

  const auto result = aead.inplaceEncrypt(makePlaintext(), nullptr, kSeqNum);

  EXPECT_FALSE(result.has_value());
}

TEST(ContiguousAeadTest, OnlyAes128GcmKeysQualify) {
  const std::vector<fizz::CipherSuite> suites = {
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
      fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
      fizz::CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
      fizz::CipherSuite::TLS_AEGIS_256_SHA512,
      fizz::CipherSuite::TLS_AEGIS_128L_SHA256,
      fizz::CipherSuite::TLS_AEGIS_128X2_SHA256,
      fizz::CipherSuite::TLS_AEGIS_128X4_SHA256,
  };
  size_t checked = 0;
  for (auto suite : suites) {
    std::unique_ptr<fizz::Aead> aead;
    fizz::Error err;
    if (QuicFizzFactory().makeAead(aead, err, suite) != fizz::Status::Success) {
      continue;
    }
    fizz::TrafficKey key;
    key.key = folly::IOBuf::copyBuffer(std::string(aead->keyLength(), 'k'));
    key.iv = folly::IOBuf::copyBuffer(std::string(aead->ivLength(), 'i'));

    EXPECT_EQ(
        ContiguousAead::isAes128GcmKey(key),
        suite == fizz::CipherSuite::TLS_AES_128_GCM_SHA256)
        << fizz::toString(suite);
    ++checked;
  }
  EXPECT_GE(checked, 3);
}

TEST(ContiguousAeadTest, GetKeyReturnsTrafficKey) {
  const OpenSSLContiguousAead aead;
  const auto expected = makeTrafficKey();

  const auto key = aead.getKey();

  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(toString(key->key), toString(expected.key));
  EXPECT_EQ(toString(key->iv), toString(expected.iv));
}

} // namespace quic::test
