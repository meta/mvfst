/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/DefaultFactory.h>

namespace quic {

class QuicFizzFactory : public ::fizz::DefaultFactory {
  [[nodiscard]] std::unique_ptr<fizz::PlaintextReadRecordLayer>
  makePlaintextReadRecordLayer() const override;

  [[nodiscard]] std::unique_ptr<fizz::PlaintextWriteRecordLayer>
  makePlaintextWriteRecordLayer() const override;

  [[nodiscard]] std::unique_ptr<fizz::EncryptedReadRecordLayer>
  makeEncryptedReadRecordLayer(
      fizz::EncryptionLevel encryptionLevel) const override;

  [[nodiscard]] std::unique_ptr<fizz::EncryptedWriteRecordLayer>
  makeEncryptedWriteRecordLayer(
      fizz::EncryptionLevel encryptionLevel) const override;
};

} // namespace quic
