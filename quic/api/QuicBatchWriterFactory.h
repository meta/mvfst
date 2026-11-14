/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>

#include <functional>

namespace quic {

// Per-connection batch writer factory hook. Consulted by
// `BatchWriterFactory::makeBatchWriter` before its default switch; returning
// `nullptr` falls through. Stored per-connection (not thread- or
// process-global) so two `QuicServer` instances sharing a worker `EventBase`
// pool — e.g. `ProxygenQuicServer` on a shared `RequestWorkerThread` pool —
// don't last-writer-wins each other.
using BatchWriterFactoryOverride = std::function<BatchWriterPtr(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool gsoSupported)>;

BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);
BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);

class BatchWriterFactory {
 public:
  static BatchWriterPtr makeBatchWriter(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported);
};

} // namespace quic
