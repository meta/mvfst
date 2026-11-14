/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/MvfstCheck.h>

namespace quic {

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoBatchWriter(uint32_t) {
  MVCHECK(false, "GSO batch writer not implemented for mobile");
  return nullptr;
}

BatchWriterPtr makeGsoInPlaceBatchWriter(uint32_t, QuicConnectionStateBase&) {
  MVCHECK(false, "GSO inplace batch writer not implemented for mobile");
  return nullptr;
}

BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t) {
  MVCHECK(false, "Sendmmsg GSO batch writer not implemented for mobile");
  return nullptr;
}

BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t,
    QuicConnectionStateBase&) {
  MVCHECK(
      false, "Sendmmsg GSO inplace batch writer not implemented for mobile");
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

  // Mobile only supports single-packet writers
  // GSO and sendmmsg batching are not available on mobile platforms
  switch (batchingMode) {
    case quic::QuicBatchingMode::BATCHING_MODE_NONE:
    default:
      return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
  }
}

} // namespace quic
