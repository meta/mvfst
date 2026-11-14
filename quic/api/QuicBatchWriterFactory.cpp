/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicGsoBatchWriters.h>
#include <quic/state/StateData.h>

namespace quic {

// Pin the inline `batchWriterFactoryOverride` signature in `StateData.h`
// against the canonical `BatchWriterFactoryOverride` alias declared in
// `QuicBatchWriterFactory.h`. The two are deliberately duplicated to keep
// `StateData.h` from transitively including the batch-writer headers; this
// assert ensures the duplication does not silently drift apart.
static_assert(
    std::is_same_v<
        decltype(QuicConnectionStateBase::batchWriterFactoryOverride),
        BatchWriterFactoryOverride>,
    "QuicConnectionStateBase::batchWriterFactoryOverride must match "
    "quic::BatchWriterFactoryOverride");

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn) {
  return BatchWriterPtr(new GSOInplacePacketBatchWriter(conn, batchSize));
}

BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn) {
  return BatchWriterPtr(
      new SendmmsgGSOInplacePacketBatchWriter(conn, batchSize));
}

BatchWriterPtr BatchWriterFactory::makeBatchWriter(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool gsoSupported) {
  if (conn.batchWriterFactoryOverride) {
    auto batchWriter = conn.batchWriterFactoryOverride(
        batchingMode, batchSize, dataPathType, conn, gsoSupported);
    if (batchWriter) {
      return batchWriter;
    }
  }

  switch (batchingMode) {
    case quic::QuicBatchingMode::BATCHING_MODE_NONE:
      return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
    case quic::QuicBatchingMode::BATCHING_MODE_GSO: {
      if (gsoSupported) {
        return makeGsoInPlaceBatchWriter(batchSize, conn);
      }
      // Fall through to Sendmmsg batching if gso is not supported.
    }
      [[fallthrough]];
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG:
      return BatchWriterPtr(
          new SendmmsgInplacePacketBatchWriter(conn, batchSize));
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO: {
      if (gsoSupported) {
        return makeSendmmsgInplaceGsoInplaceBatchWriter(batchSize, conn);
      }
      return BatchWriterPtr(
          new SendmmsgInplacePacketBatchWriter(conn, batchSize));
    }
      // no default so we can catch missing case at compile time
  }
  folly::assume_unreachable();
}

} // namespace quic
