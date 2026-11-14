/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriter.h>
#include <quic/common/MvfstLogging.h>

namespace quic {
// BatchWriter
bool BatchWriter::needsFlush(size_t /*unused*/) {
  return false;
}

// SinglePacketInplaceBatchWriter
void SinglePacketInplaceBatchWriter::reset() {
  conn_.bufAccessor->clear();
}

bool SinglePacketInplaceBatchWriter::append(
    BufPtr&& /* buf */,
    size_t /*unused*/,
    const quic::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  // Always flush. This should trigger a write afterwards.
  return true;
}

ssize_t SinglePacketInplaceBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const quic::SocketAddress& address) {
  auto& buf = conn_.bufAccessor->buf();
  MVCHECK(!conn_.bufAccessor->isChained());

  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf, vec);
  return sock.write(address, vec, iovec_len);
}

bool SinglePacketInplaceBatchWriter::empty() const {
  return conn_.bufAccessor->length() == 0;
}

SendmmsgInplacePacketBatchWriter::SendmmsgInplacePacketBatchWriter(
    QuicConnectionStateBase& conn,
    size_t maxBufs)
    : conn_(conn), maxBufs_(maxBufs) {
  MVCHECK_LE(maxBufs, kMaxIovecs, "maxBufs must be at most " << kMaxIovecs);
}

bool SendmmsgInplacePacketBatchWriter::empty() const {
  return currSize_ == 0;
}

size_t SendmmsgInplacePacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgInplacePacketBatchWriter::reset() {
  if (numPacketsBuffered_) {
    conn_.bufAccessor->clear();
  }
  currSize_ = 0;
  numPacketsBuffered_ = 0;
}

bool SendmmsgInplacePacketBatchWriter::append(
    BufPtr&& /* buf */,
    size_t size,
    const quic::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  MVCHECK_LT(numPacketsBuffered_, maxBufs_);

  auto& buf = conn_.bufAccessor->buf();
  MVCHECK(!buf->isChained() && buf->length() >= size);
  iovecs_[numPacketsBuffered_].iov_base = (void*)(buf->tail() - size);
  iovecs_[numPacketsBuffered_].iov_len = size;

  ++numPacketsBuffered_;
  currSize_ += size;

  // reached max buffers
  if (numPacketsBuffered_ == maxBufs_) [[unlikely]] {
    return true;
  }

  // does not need to be flushed yet
  return false;
}

ssize_t SendmmsgInplacePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const quic::SocketAddress& address) {
  MVCHECK_GT(numPacketsBuffered_, 0);

  if (numPacketsBuffered_ == 1) {
    return sock.write(address, &iovecs_[0], 1);
  }

  int ret = 0;
  std::array<size_t, kMaxIovecs> messageSizes{};

  for (size_t i = 0; i < numPacketsBuffered_; i++) {
    messageSizes[i] = 1;
  }

  ret = sock.writem(
      AddressRange(&address, 1),
      &iovecs_[0],
      &messageSizes[0],
      numPacketsBuffered_);
  if (ret <= 0) {
    return ret;
  }

  if (static_cast<size_t>(ret) == numPacketsBuffered_) {
    return currSize_;
  }

  // this is a partial write - we just need to
  // return a different number than currSize_
  return 0;
}

} // namespace quic
