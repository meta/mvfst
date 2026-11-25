/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/HaberdasheryAead.h>

#include <folly/CPortability.h>
#include <quic/fizz/handshake/ContiguousAead.h>
#include <quic/fizz/handshake/FizzBridge.h>

#if defined(__x86_64__)
#include <haberdashery/aead/aes128gcm_broadwell.h>
#include <haberdashery/aead/aes128gcm_sapphirerapids.h>
#include <haberdashery/aead/aes128gcm_skylakex.h>
#include <haberdashery/aead/aes128gcm_tigerlake.h>
#include <haberdashery/aead/aes128gcm_zen4.h>
#elif defined(__aarch64__)
#include <haberdashery/aead/aes128gcm_neoversev2.h>
#else
#error "haberdashery has no assembly for this architecture"
#endif

namespace quic {

namespace {

// The bindings align their context types through the typedef, which does not
// survive template deduction, so the member is aligned explicitly to the
// largest alignment that any binding requires. Both compilers still warn about
// the dropped attribute, hence the suppression around the class.
constexpr size_t kContextAlignment = 64;

template <typename InitFn>
struct ContextOf;

template <typename Context, typename... Args>
struct ContextOf<int (*)(Context*, Args...)> {
  using type = Context;
};

FOLLY_PUSH_WARNING
FOLLY_CLANG_DISABLE_WARNING("-Walign-mismatch")
FOLLY_GCC_DISABLE_WARNING("-Wignored-attributes")

template <auto Init, auto Encrypt, auto Decrypt>
class HaberdasheryCipher final : public ContiguousAead {
  using Context = typename ContextOf<decltype(Init)>::type;

 public:
  static std::unique_ptr<Aead> make(fizz::TrafficKey key) {
    auto cipher = std::make_unique<HaberdasheryCipher>(std::move(key));
    if (!cipher->init()) {
      return nullptr;
    }
    return cipher;
  }

  explicit HaberdasheryCipher(fizz::TrafficKey key)
      : ContiguousAead(std::move(key)) {}

 private:
  bool init() {
    const auto key = getKey();
    return Init(&context_, key->key->data(), key->key->length()) != 0;
  }

  [[nodiscard]] bool seal(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> plaintext,
      std::span<uint8_t> ciphertext,
      std::span<uint8_t> tag) const override {
    return Encrypt(
               &context_,
               nonce.data(),
               nonce.size(),
               aad.data(),
               aad.size(),
               plaintext.data(),
               plaintext.size(),
               ciphertext.data(),
               ciphertext.size(),
               tag.data(),
               tag.size()) != 0;
  }

  [[nodiscard]] bool open(
      std::span<const uint8_t> nonce,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> ciphertext,
      std::span<const uint8_t> tag,
      std::span<uint8_t> plaintext) const override {
    return Decrypt(
               &context_,
               nonce.data(),
               nonce.size(),
               aad.data(),
               aad.size(),
               ciphertext.data(),
               ciphertext.size(),
               tag.data(),
               tag.size(),
               plaintext.data(),
               plaintext.size()) != 0;
  }

  alignas(kContextAlignment) Context context_{};
};

FOLLY_POP_WARNING

struct Implementation {
  std::string_view name;
  int (*isSupported)();
  std::unique_ptr<Aead> (*make)(fizz::TrafficKey);
};

#define MVFST_HABERDASHERY_AES128GCM(profile)                   \
  Implementation {                                              \
    #profile, &haberdashery_aes128gcm_##profile##_is_supported, \
        &HaberdasheryCipher<                                    \
            &haberdashery_aes128gcm_##profile##_init,           \
            &haberdashery_aes128gcm_##profile##_encrypt,        \
            &haberdashery_aes128gcm_##profile##_decrypt>::make  \
  }

// Each profile targets one CPU family and is supported only there, except
// broadwell, which runs on any CPU with AES-NI and AVX2 and so comes last.
constexpr Implementation kAes128GcmImplementations[] = {
#if defined(__x86_64__)
    MVFST_HABERDASHERY_AES128GCM(sapphirerapids),
    MVFST_HABERDASHERY_AES128GCM(zen4),
    MVFST_HABERDASHERY_AES128GCM(tigerlake),
    MVFST_HABERDASHERY_AES128GCM(skylakex),
    MVFST_HABERDASHERY_AES128GCM(broadwell),
#elif defined(__aarch64__)
    MVFST_HABERDASHERY_AES128GCM(neoversev2),
#endif
};

#undef MVFST_HABERDASHERY_AES128GCM

const Implementation* findAes128GcmImplementation() {
  static const Implementation* const implementation = [] {
    for (const auto& candidate : kAes128GcmImplementations) {
      if (candidate.isSupported()) {
        return &candidate;
      }
    }
    return static_cast<const Implementation*>(nullptr);
  }();
  return implementation;
}

std::unique_ptr<Aead> makeAes128Gcm(
    const Implementation& implementation,
    const fizz::Aead& fizzAead) {
  auto key = fizzAead.getKey();
  if (!key || !ContiguousAead::isAes128GcmKey(*key)) {
    return nullptr;
  }
  return implementation.make(std::move(*key));
}

} // namespace

std::unique_ptr<Aead> HaberdasheryAead::wrap(
    std::unique_ptr<fizz::Aead> fizzAead) {
  if (!fizzAead) {
    return nullptr;
  }
  if (const auto* implementation = findAes128GcmImplementation()) {
    if (auto aead = makeAes128Gcm(*implementation, *fizzAead)) {
      return aead;
    }
  }
  return FizzAead::wrap(std::move(fizzAead));
}

std::vector<std::string_view> HaberdasheryAead::supportedImplementations() {
  std::vector<std::string_view> names;
  for (const auto& implementation : kAes128GcmImplementations) {
    if (implementation.isSupported()) {
      names.push_back(implementation.name);
    }
  }
  return names;
}

std::unique_ptr<Aead> HaberdasheryAead::wrapWith(
    std::string_view name,
    const fizz::Aead& fizzAead) {
  for (const auto& implementation : kAes128GcmImplementations) {
    if (implementation.name == name && implementation.isSupported()) {
      return makeAes128Gcm(implementation, fizzAead);
    }
  }
  return nullptr;
}

} // namespace quic
