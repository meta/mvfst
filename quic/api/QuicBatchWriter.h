/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Portability.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/state/StateData.h>

namespace quic {
class BatchWriter {
 public:
  BatchWriter() = default;
  virtual ~BatchWriter() = default;

  // returns true if the batch does not contain any buffers
  [[nodiscard]] virtual bool empty() const = 0;

  // returns the size in bytes of the batched buffers
  [[nodiscard]] virtual size_t size() const = 0;

  // Drop the batch after a flush. Inplace writers also remove its bytes from
  // conn.bufAccessor, keeping any bytes written after it.
  virtual void reset() = 0;

  // returns true if we need to flush before adding a new packet
  virtual bool needsFlush(size_t /*unused*/);

  virtual void setTxTime(std::chrono::microseconds) {
    MVLOG_WARNING
        << "setTxTime not supported for this batch writer implementation";
  }

  /* append returns true if the
   * writer needs to be flushed
   */
  virtual bool append(
      BufPtr&& buf,
      size_t bufSize,
      const quic::SocketAddress& addr,
      QuicAsyncUDPSocket* sock) = 0;
  // Keep the batch valid until reset(), including across multiple sockets.
  virtual ssize_t write(
      QuicAsyncUDPSocket& sock,
      const quic::SocketAddress& address) = 0;
};

class IOBufBatchWriter : public BatchWriter {
 public:
  IOBufBatchWriter() = default;
  ~IOBufBatchWriter() override = default;

  [[nodiscard]] bool empty() const override {
    return !buf_;
  }

  [[nodiscard]] size_t size() const override {
    return buf_ ? buf_->computeChainDataLength() : 0;
  }

 protected:
  BufPtr buf_;
};

/**
 * This writer allows for single buf inplace writes.
 * The buffer is owned by the conn/accessor, and every append will trigger a
 * flush/write.
 */
class SinglePacketInplaceBatchWriter : public IOBufBatchWriter {
 public:
  explicit SinglePacketInplaceBatchWriter(QuicConnectionStateBase& conn)
      : conn_(conn) {}

  ~SinglePacketInplaceBatchWriter() override = default;

  void reset() override;
  bool append(
      BufPtr&& /* buf */,
      size_t /*unused*/,
      const quic::SocketAddress& /*unused*/,
      QuicAsyncUDPSocket* /*unused*/) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const quic::SocketAddress& address)
      override;
  [[nodiscard]] bool empty() const override;

 private:
  QuicConnectionStateBase& conn_;
};

class SendmmsgInplacePacketBatchWriter : public BatchWriter {
 public:
  explicit SendmmsgInplacePacketBatchWriter(
      QuicConnectionStateBase& conn,
      size_t maxBufs);
  ~SendmmsgInplacePacketBatchWriter() override = default;

  [[nodiscard]] bool empty() const override;

  [[nodiscard]] size_t size() const override;

  void reset() override;
  bool append(
      BufPtr&& /* buf */,
      size_t size,
      const quic::SocketAddress& /*unused*/,
      QuicAsyncUDPSocket* /*unused*/) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const quic::SocketAddress& address)
      override;

 private:
  static constexpr size_t kMaxIovecs = 64;

  QuicConnectionStateBase& conn_;
  // Max number of packets we can accumulate before we need to flush
  size_t maxBufs_{1};
  // size of data in all the buffers
  size_t currSize_{0};
  // Number of packets that have been written to iovec_
  size_t numPacketsBuffered_{0};
  std::array<iovec, kMaxIovecs> iovecs_{};
};

using BatchWriterPtr = std::unique_ptr<BatchWriter, BatchWriterDeleter>;
} // namespace quic
