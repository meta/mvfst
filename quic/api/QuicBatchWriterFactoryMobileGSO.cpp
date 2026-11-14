/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicGsoBatchWriters.h>

namespace quic {

void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn) {
  return BatchWriterPtr(new GSOInplacePacketBatchWriter(conn, batchSize));
}

BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t,
    QuicConnectionStateBase&) {
  return nullptr;
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
    case quic::QuicBatchingMode::BATCHING_MODE_GSO:
      if (gsoSupported) {
        return makeGsoInPlaceBatchWriter(batchSize, conn);
      }
      // GSO unavailable on this device, fall through to single packet
      [[fallthrough]];
    case quic::QuicBatchingMode::BATCHING_MODE_NONE:
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG:
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO:
    default:
      // Default to single packet batching, ignoring batch size
      return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
  }
}

} // namespace quic
