/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Portability.h>
#include <glog/logging.h>
#include <array>
#include <utility>

namespace quic {

// A generic class that extends std::array to be indexable using an Enum.
// The enum K has to list enumerators with all values between 0 and K::MAX
// (inclusive) and no others

template <class K, class V>
class EnumArray : public std::array<V, size_t(K::MAX) + 1> {
 public:
  using IntType = std::underlying_type_t<K>;
  static constexpr IntType ArraySize = IntType(K::MAX) + 1;

  constexpr const V& operator[](K key) const {
    size_t ik = keyToInt(key);
    return this->std::array<V, size_t(K::MAX) + 1>::operator[](ik);
  }

  constexpr V& operator[](K key) {
    size_t ik = keyToInt(key);
    return this->std::array<V, size_t(K::MAX) + 1>::operator[](ik);
  }

  // Returns all valid values for the enum
  [[nodiscard]] constexpr std::array<K, ArraySize> keys() const {
    return keyArrayHelper(std::make_integer_sequence<IntType, ArraySize>{});
  }

 private:
  constexpr IntType keyToInt(K key) const {
    auto ik = static_cast<IntType>(key);
    MVDCHECK(ik >= 0 && ik < ArraySize);
    return ik;
  }

  template <IntType... i>
  constexpr auto keyArrayHelper(std::integer_sequence<IntType, i...>) const {
    return std::array<K, sizeof...(i)>{static_cast<K>(i)...};
  }

  std::array<V, ArraySize> arr;
};

} // namespace quic
