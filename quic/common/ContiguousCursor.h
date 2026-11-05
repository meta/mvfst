/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Utility.h>
#include <folly/lang/Bits.h>
#include <quic/QuicConstants.h>
#include <memory>

namespace quic {

class ContiguousReadCursor {
 public:
  ContiguousReadCursor(const uint8_t* data, size_t size) noexcept;

  [[nodiscard]] const uint8_t* data() const {
    return data_;
  }

  [[nodiscard]] const uint8_t* end() const {
    return end_;
  }

  [[nodiscard]] size_t remaining() const {
    return uintptr_t(end_ - data_);
  }

  [[nodiscard]] bool canAdvance(size_t bytes) const noexcept {
    return uintptr_t(end_ - data_) >= bytes;
  }

  [[nodiscard]] bool isAtEnd() const noexcept {
    return data_ == end_;
  }

  [[nodiscard]] size_t getCurrentPosition() const noexcept {
    return uintptr_t(data_ - begin_);
  }

  bool skip(size_t bytes) noexcept;
  bool tryReadFixedSizeString(std::string& str, size_t bytes) noexcept;
  bool tryClone(uint8_t* buf, size_t bytes) noexcept;
  bool tryPull(void* buf, size_t bytes) noexcept;

  size_t pullAtMost(void* buf, size_t len) noexcept;

  template <class T>
  bool tryReadBE(T& val) noexcept {
    if (FOLLY_UNLIKELY(!canAdvance(sizeof(T)))) {
      return false;
    }
    readBE(val);
    return true;
  }

  template <class T>
  bool tryRead(T& val) noexcept {
    if (FOLLY_UNLIKELY(!canAdvance(sizeof(T)))) {
      return false;
    }
    read(val);
    return true;
  }

  [[nodiscard]] ByteRange peekBytes() const noexcept {
    return {data_, end_};
  }

  // lambda that returns bool if should rollback to where data_ was before
  // invoking function
  template <class T>
  void withRollback(T&& func) noexcept {
    const uint8_t* checkpoint = data_;
    if (func()) {
      data_ = checkpoint;
    }
  }

  void reset(const uint8_t* data, size_t size) noexcept {
    begin_ = data_ = data;
    end_ = data + size;
  }

 private:
  void readFixedSizeString(std::string& str, size_t bytes) noexcept;
  void pull(void* buf, size_t bytes) noexcept;
  void clone(uint8_t* buf, size_t bytes) noexcept;

  template <class T>
  void readBE(T& val) noexcept {
    read(val);
    val = folly::Endian::big(val);
  }

  template <class T>
  void read(T& val) noexcept {
    val = folly::loadUnaligned<T>(data_);
    data_ += sizeof(T);
  }

  const uint8_t* begin_{nullptr};
  const uint8_t* data_{nullptr};
  const uint8_t* end_{nullptr};
};

} // namespace quic
