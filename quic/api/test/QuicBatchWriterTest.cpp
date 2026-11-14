/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriter.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicGsoBatchWriters.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>

#include <gtest/gtest.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic::testing {

constexpr const auto kStrLen = 10;
constexpr const auto kBatchNum = 3;
constexpr const auto kNumLoops = 10;

struct QuicBatchWriterTest : public ::testing::Test {
  QuicBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

 protected:
  QuicServerConnectionState conn_;
  bool gsoSupported_{false};
};

class TestOverrideBatchWriter : public BatchWriter {
 public:
  [[nodiscard]] bool empty() const override {
    return false;
  }

  [[nodiscard]] size_t size() const override {
    return kOverrideSize;
  }

  void reset() override {}

  bool append(
      BufPtr&&,
      size_t,
      const folly::SocketAddress&,
      QuicAsyncUDPSocket*) override {
    return true;
  }

  ssize_t write(QuicAsyncUDPSocket&, const folly::SocketAddress&) override {
    return 0;
  }

  static constexpr size_t kOverrideSize = 12345;
};

TEST_F(QuicBatchWriterTest, TestPerConnBatchWriterFactoryOverride) {
  bool overrideCalled = false;
  conn_.batchWriterFactoryOverride = [&](const quic::QuicBatchingMode&,
                                         uint32_t,
                                         DataPathType,
                                         QuicConnectionStateBase&,
                                         bool) {
    overrideCalled = true;
    return BatchWriterPtr(new TestOverrideBatchWriter());
  };

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_NONE,
      kBatchNum,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);

  EXPECT_TRUE(overrideCalled);
  ASSERT_TRUE(batchWriter);
  EXPECT_EQ(batchWriter->size(), TestOverrideBatchWriter::kOverrideSize);

  // Clearing the override returns to the default factory.
  conn_.batchWriterFactoryOverride = nullptr;
  auto defaultBatchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_NONE,
      kBatchNum,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  ASSERT_TRUE(defaultBatchWriter);
  EXPECT_EQ(defaultBatchWriter->size(), 0);
}

TEST_F(QuicBatchWriterTest, TestPerConnBatchWriterFactoryOverrideFallthrough) {
  // An override returning nullptr must fall through to the default factory.
  bool overrideCalled = false;
  conn_.batchWriterFactoryOverride = [&](const quic::QuicBatchingMode&,
                                         uint32_t,
                                         DataPathType,
                                         QuicConnectionStateBase&,
                                         bool) {
    overrideCalled = true;
    return BatchWriterPtr(nullptr);
  };

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_NONE,
      kBatchNum,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);

  EXPECT_TRUE(overrideCalled);
  ASSERT_TRUE(batchWriter);
  // Default writer for BATCHING_MODE_NONE is a single packet writer whose size
  // is 0, not the override sentinel.
  EXPECT_EQ(batchWriter->size(), 0);
}

TEST_F(QuicBatchWriterTest, ChainedMemorySettingGetsInplaceWriters) {
  BufAccessor accessor(conn_.udpSendPacketLen * kBatchNum);
  conn_.bufAccessor = &accessor;
  auto makeWriter = [&](QuicBatchingMode mode, bool gsoSupported) {
    return BatchWriterFactory::makeBatchWriter(
        mode, kBatchNum, DataPathType::ChainedMemory, conn_, gsoSupported);
  };
  EXPECT_NE(
      dynamic_cast<SinglePacketInplaceBatchWriter*>(
          makeWriter(QuicBatchingMode::BATCHING_MODE_NONE, false).get()),
      nullptr);
  EXPECT_NE(
      dynamic_cast<GSOInplacePacketBatchWriter*>(
          makeWriter(QuicBatchingMode::BATCHING_MODE_GSO, true).get()),
      nullptr);
  EXPECT_NE(
      dynamic_cast<SendmmsgInplacePacketBatchWriter*>(
          makeWriter(QuicBatchingMode::BATCHING_MODE_SENDMMSG, false).get()),
      nullptr);
  EXPECT_NE(
      dynamic_cast<SendmmsgGSOInplacePacketBatchWriter*>(
          makeWriter(QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO, true).get()),
      nullptr);
}

class BatchWriterFactoryTest
    : public QuicBatchWriterTest,
      public WithParamInterface<std::tuple<QuicBatchingMode, uint32_t, bool>> {
};

TEST_P(BatchWriterFactoryTest, WritesPacketFromBuffer) {
  const auto [mode, batchSize, gsoSupported] = GetParam();
  BufAccessor accessor(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = &accessor;
  auto writer = BatchWriterFactory::makeBatchWriter(
      mode, batchSize, DataPathType::ContinuousMemory, conn_, gsoSupported);

  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  const std::string payload = "factory payload";
  size_t writes = 0;
  auto checkPayload =
      [&](const SocketAddress&, const iovec* vec, size_t count) {
        ++writes;
        EXPECT_TRUE(
            folly::IOBufEqualTo()(
                folly::IOBuf::wrapIov(vec, count),
                folly::IOBuf::copyBuffer(payload)));
        return static_cast<ssize_t>(payload.size());
      };
  EXPECT_CALL(sock, write(_, _, _))
      .Times(AtMost(1))
      .WillRepeatedly(Invoke(checkPayload));
  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(AtMost(1))
      .WillRepeatedly([&](const SocketAddress& addr,
                          const iovec* vec,
                          size_t count,
                          QuicAsyncUDPSocket::WriteOptions) {
        return checkPayload(addr, vec, count);
      });

  memcpy(accessor.writableTail(), payload.data(), payload.size());
  accessor.append(payload.size());
  writer->append(nullptr, payload.size(), SocketAddress(), &sock);
  ASSERT_FALSE(writer->empty());
  EXPECT_EQ(writer->write(sock, SocketAddress()), payload.size());
  EXPECT_EQ(writes, 1);
  EXPECT_FALSE(writer->empty());
  EXPECT_EQ(
      std::string(
          reinterpret_cast<const char*>(accessor.data()), accessor.length()),
      payload);
  writer->reset();
  EXPECT_TRUE(writer->empty());
  EXPECT_EQ(accessor.length(), 0);
}

INSTANTIATE_TEST_SUITE_P(
    BatchingModes,
    BatchWriterFactoryTest,
    Combine(
        Values(
            QuicBatchingMode::BATCHING_MODE_NONE,
            QuicBatchingMode::BATCHING_MODE_GSO,
            QuicBatchingMode::BATCHING_MODE_SENDMMSG,
            QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO),
        Values(1u, 16u, kQuicMaxBatchSizeLimit),
        Bool()));

TEST_F(QuicBatchWriterTest, SendmmsgPreservesSocketResult) {
  const std::string packet = "packet";
  for (const int socketResult : {3, 1, 0, -EAGAIN, -ENOBUFS, -EIO}) {
    SCOPED_TRACE(socketResult);
    BufAccessor accessor(conn_.udpSendPacketLen * 3);
    conn_.bufAccessor = &accessor;
    auto writer = BatchWriterFactory::makeBatchWriter(
        QuicBatchingMode::BATCHING_MODE_SENDMMSG,
        3,
        DataPathType::ContinuousMemory,
        conn_,
        false);
    size_t bytes = 0;
    for (size_t i = 0; i < 3; ++i) {
      memcpy(accessor.writableTail(), packet.data(), packet.size());
      accessor.append(packet.size());
      bytes += packet.size();
      writer->append(nullptr, packet.size(), SocketAddress(), nullptr);
    }
    folly::EventBase evb;
    auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
    quic::test::MockAsyncUDPSocket sock(qEvb);
    EXPECT_CALL(sock, writem(_, _, _, 3)).WillOnce(InvokeWithoutArgs([&]() {
      errno = socketResult < 0 ? -socketResult : 0;
      return socketResult < 0 ? -1 : socketResult;
    }));
    const ssize_t expected = socketResult == 3 ? static_cast<ssize_t>(bytes)
                                               : (socketResult < 0 ? -1 : 0);
    EXPECT_EQ(writer->write(sock, SocketAddress()), expected);
    EXPECT_EQ(errno, socketResult < 0 ? -socketResult : 0);
    writer->reset();
    EXPECT_TRUE(writer->empty());
    EXPECT_EQ(accessor.length(), 0);
  }
}

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgInplace) {
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * kBatchNum);
  conn_.bufAccessor = bufAccessor.get();

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  gsoSupported_ = false;

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG,
      kBatchNum,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);

  // run multiple loops
  for (size_t i = 0; i < kNumLoops; i++) {
    std::vector<iovec> expectedIovecs;

    // try to batch up to kBatchNum
    CHECK(batchWriter->empty());
    CHECK_EQ(batchWriter->size(), 0);
    size_t size = 0;
    for (auto j = 0; j < kBatchNum - 1; j++) {
      iovec vec{};
      vec.iov_base = (void*)bufAccessor->buf()->tail();
      vec.iov_len = kStrLen;
      bufAccessor->buf()->append(kStrLen);
      expectedIovecs.push_back(vec);

      EXPECT_FALSE(batchWriter->append(
          nullptr, kStrLen, quic::SocketAddress(), nullptr));
      size += kStrLen;
      CHECK_EQ(batchWriter->size(), size);
    }

    // add the kBatchNum buf
    iovec vec{};
    vec.iov_base = (void*)bufAccessor->buf()->tail();
    vec.iov_len = kStrLen;
    bufAccessor->buf()->append(kStrLen);
    expectedIovecs.push_back(vec);

    CHECK(
        batchWriter->append(nullptr, kStrLen, quic::SocketAddress(), nullptr));
    size += kStrLen;
    CHECK_EQ(batchWriter->size(), size);

    EXPECT_CALL(sock, writem(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke([&](folly::Range<quic::SocketAddress const*> addrs,
                             iovec* iovecs,
                             size_t* messageSizes,
                             size_t count) {
          EXPECT_EQ(addrs.size(), 1);
          EXPECT_EQ(count, kBatchNum);

          for (size_t k = 0; k < count; k++) {
            EXPECT_EQ(messageSizes[k], 1);
            EXPECT_EQ(expectedIovecs[k].iov_base, iovecs[k].iov_base);
            EXPECT_EQ(expectedIovecs[k].iov_len, iovecs[k].iov_len);
          }

          return 0;
        }));
    batchWriter->write(sock, quic::SocketAddress());
    batchWriter->reset();
    expectedIovecs.clear();
    EXPECT_TRUE(bufAccessor->buf()->empty());

    batchWriter->reset();
  }
}

TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceSameSizeAll) {
  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSize, quic::SocketAddress(), nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSize);
  EXPECT_TRUE(
      batchWriter->append(nullptr, packetSize, quic::SocketAddress(), nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const quic::SocketAddress&,
                           const struct iovec* iovecs,
                           size_t iovec_len,
                           QuicAsyncUDPSocket::WriteOptions writeOptions) {
        EXPECT_EQ(iovec_len, 5);
        EXPECT_EQ(writeOptions.gso, packetSize);

        for (uint32_t i = 0; i < 5; i++) {
          EXPECT_EQ(
              iovecs[i].iov_base,
              (uint8_t*)bufAccessor->buf()->buffer() + packetSize * i);
          EXPECT_EQ(iovecs[i].iov_len, packetSize);
        }

        return 1;
      }));
  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->reset();
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we do the following for the same address, in order:
// (1) Send 3 packets of the same size
// (2) Send 1 packet that's smaller than the previous 3
// (3) Send 1 packet of the same size as the 3 initial ones
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceSmallerSizeInMiddle) {
  gsoSupported_ = true;
  size_t batchSize = 5;

  std::vector<size_t> packetSizes = {100, 100, 100, 70, 100};

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSizes[j]);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSizes[j], quic::SocketAddress(), nullptr));
    size += packetSizes[j];
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSizes[batchSize - 1]);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSizes[batchSize - 1], quic::SocketAddress(), nullptr));
  size += packetSizes[batchSize - 1];
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<quic::SocketAddress const*> /* addrs */,
                           iovec* iov,
                           size_t* numIovecsInBuffer,
                           size_t count,
                           const QuicAsyncUDPSocket::WriteOptions* options) {
        EXPECT_EQ(count, 2);
        EXPECT_EQ(numIovecsInBuffer[0], 4);
        EXPECT_EQ(numIovecsInBuffer[1], 1);
        EXPECT_EQ(options[0].gso, 100);
        // There's just one packet in the second series, so we don't use GSO
        // there.
        EXPECT_EQ(options[1].gso, 0);

        auto* currBufferAddr = (uint8_t*)bufAccessor->buf()->buffer();
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_base, currBufferAddr);
          EXPECT_EQ(iov[i].iov_len, packetSizes[i]);

          currBufferAddr += packetSizes[i];
        }

        return 2;
      }));
  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->reset();
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we do the following for the same address, in order:
// (1) Send 3 packets of the same size
// (2) Send 1 packet that's larger than the previous 3
// (3) Send 1 packet of the same size as the 3 initial ones
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceLargerSizeInMiddle) {
  gsoSupported_ = true;
  size_t batchSize = 5;

  std::vector<size_t> packetSizes = {100, 100, 100, 120, 100};

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSizes[j]);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSizes[j], quic::SocketAddress(), nullptr));
    size += packetSizes[j];
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSizes[batchSize - 1]);
  EXPECT_TRUE(batchWriter->append(
      nullptr, packetSizes[batchSize - 1], quic::SocketAddress(), nullptr));
  size += packetSizes[batchSize - 1];
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<quic::SocketAddress const*> /* addrs */,
                           iovec* iov,
                           size_t* numIovecsInBuffer,
                           size_t count,
                           const QuicAsyncUDPSocket::WriteOptions* options) {
        EXPECT_EQ(count, 2);
        EXPECT_EQ(numIovecsInBuffer[0], 3);
        EXPECT_EQ(numIovecsInBuffer[1], 2);
        EXPECT_EQ(options[0].gso, 100);
        EXPECT_EQ(options[1].gso, 120);

        auto* currBufferAddr = (uint8_t*)bufAccessor->buf()->buffer();
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_base, currBufferAddr);
          EXPECT_EQ(iov[i].iov_len, packetSizes[i]);

          currBufferAddr += packetSizes[i];
        }

        return 2;
      }));
  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->reset();
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Send 5 packets of the same length.
// Packets 1, 2, and 5 are to address A.
// Packets 3 and 4 are to address B.
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceDifferentAddrs) {
  quic::SocketAddress addrA("127.0.0.1", 80);
  quic::SocketAddress addrB("127.0.0.1", 443);

  std::vector<quic::SocketAddress> addrs = {addrA, addrA, addrB, addrB, addrA};

  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(nullptr, packetSize, addrs[j], nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  bufAccessor->append(packetSize);
  EXPECT_TRUE(
      batchWriter->append(nullptr, packetSize, addrs[batchSize - 1], nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writemGSO(_, _, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](folly::Range<quic::SocketAddress const*> addrs,
                           iovec* iov,
                           size_t* numIovecsInBuffer,
                           size_t count,
                           const QuicAsyncUDPSocket::WriteOptions* options) {
        EXPECT_EQ(count, 2);
        EXPECT_EQ(numIovecsInBuffer[0], 3);
        EXPECT_EQ(numIovecsInBuffer[1], 2);

        EXPECT_EQ(options[0].gso, packetSize);
        EXPECT_EQ(options[1].gso, packetSize);

        // All packets are of size packetSize
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_len, packetSize);
        }

        // If the shared buffer looks like this:
        // [slot1, slot2, slot3, slot4, slot5]
        // Then iov should look like
        // [slot1, slot2, slot5, slot3, slot4]
        auto* bufferStart = (uint8_t*)bufAccessor->buf()->buffer();
        std::vector<uint8_t*> expectedBufferStartPositions = {
            bufferStart,
            bufferStart + packetSize,
            bufferStart + 4 * packetSize,
            bufferStart + 2 * packetSize,
            bufferStart + 3 * packetSize};
        for (uint32_t i = 0; i < batchSize; i++) {
          EXPECT_EQ(iov[i].iov_base, expectedBufferStartPositions[i]);
        }

        EXPECT_EQ(addrs[0], addrA);
        EXPECT_EQ(addrs[1], addrB);

        return 2;
      }));

  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->reset();
  EXPECT_TRUE(bufAccessor->buf()->empty());
}

// Test the case where we send 5 packets, all of the same size, to the
// same address, with an external writer writing data to the shared buffer right
// before we write the batch.
TEST_F(QuicBatchWriterTest, TestBatchingSendmmsgGSOInplaceExternalDataWritten) {
  gsoSupported_ = true;
  size_t batchSize = 5;
  size_t packetSize = 100;

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);

  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();

  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  CHECK(batchWriter->empty());
  CHECK_EQ(batchWriter->size(), 0);
  size_t size = 0;
  for (size_t j = 0; j < batchSize - 1; j++) {
    memset(bufAccessor->buf()->writableTail(), 'a' + j, packetSize);
    bufAccessor->append(packetSize);
    EXPECT_FALSE(batchWriter->append(
        nullptr, packetSize, quic::SocketAddress(), nullptr));
    size += packetSize;
    EXPECT_EQ(batchWriter->size(), size);
  }
  memset(bufAccessor->buf()->writableTail(), 'e', packetSize);
  bufAccessor->append(packetSize);
  EXPECT_TRUE(
      batchWriter->append(nullptr, packetSize, quic::SocketAddress(), nullptr));
  size += packetSize;
  EXPECT_EQ(batchWriter->size(), size);

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(2)
      .WillRepeatedly(
          Invoke([&](const quic::SocketAddress&,
                     const struct iovec* iovecs,
                     size_t iovec_len,
                     QuicAsyncUDPSocket::WriteOptions writeOptions) {
            EXPECT_EQ(iovec_len, 5);
            EXPECT_EQ(writeOptions.gso, packetSize);

            for (uint32_t i = 0; i < 5; i++) {
              EXPECT_EQ(
                  iovecs[i].iov_base,
                  (uint8_t*)bufAccessor->buf()->buffer() + packetSize * i);
              EXPECT_EQ(iovecs[i].iov_len, packetSize);
              EXPECT_EQ(
                  std::string(
                      static_cast<const char*>(iovecs[i].iov_base), packetSize),
                  std::string(packetSize, 'a' + i));
            }

            return 1;
          }));
  std::string externalData = "external data";
  memcpy(
      bufAccessor->buf()->writableTail(),
      externalData.data(),
      externalData.size());
  bufAccessor->buf()->append(externalData.size());
  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->write(sock, quic::SocketAddress());
  batchWriter->reset();
  batchWriter->reset();
  EXPECT_EQ(bufAccessor->buf()->length(), externalData.size());
  EXPECT_EQ(
      memcmp(
          externalData.data(), bufAccessor->buf()->data(), externalData.size()),
      0);
}

TEST_F(QuicBatchWriterTest, InplaceWriterNeedsFlush) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < 10; i++) {
    EXPECT_FALSE(batchWriter->needsFlush(1000));
    batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr);
  }
  EXPECT_TRUE(batchWriter->needsFlush(conn_.udpSendPacketLen));
}

TEST_F(QuicBatchWriterTest, InplaceWriterAppendLimit) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < batchSize - 1; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    EXPECT_FALSE(
        batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr));
  }

  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(
      batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr));
}

TEST_F(QuicBatchWriterTest, InplaceWriterAppendSmaller) {
  gsoSupported_ = true;
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  EXPECT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < batchSize / 2; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    EXPECT_FALSE(
        batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr));
  }

  auto buf = bufAccessor->obtain();
  buf->append(700);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(
      batchWriter->append(nullptr, 700, quic::SocketAddress(), nullptr));
}

TEST_F(QuicBatchWriterTest, InplaceWriterWriteAll) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  ASSERT_FALSE(batchWriter->needsFlush(1000));

  for (size_t i = 0; i < 5; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(1000);
    bufAccessor->release(std::move(buf));
    ASSERT_FALSE(
        batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr));
  }
  auto buf = bufAccessor->obtain();
  buf->append(700);
  bufAccessor->release(std::move(buf));
  ASSERT_TRUE(
      batchWriter->append(nullptr, 700, quic::SocketAddress(), nullptr));

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* vec,
                           size_t,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_EQ(1000 * 5 + 700, vec[0].iov_len);
        EXPECT_EQ(1000, options.gso);
        return 1000 * 5 + 700;
      }));
  EXPECT_EQ(1000 * 5 + 700, batchWriter->write(sock, quic::SocketAddress()));
  batchWriter->reset();

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_F(QuicBatchWriterTest, InplaceWriterWriteOne) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  CHECK(batchWriter);
  ASSERT_FALSE(batchWriter->needsFlush(1000));

  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  ASSERT_FALSE(
      batchWriter->append(nullptr, 1000, quic::SocketAddress(), nullptr));

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const auto& /* addr */, const struct iovec* vec, size_t, auto) {
            EXPECT_EQ(1000, vec[0].iov_len);
            return 1000;
          }));
  EXPECT_EQ(1000, batchWriter->write(sock, quic::SocketAddress()));
  batchWriter->reset();

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(0, buf->length());
}

TEST_F(QuicBatchWriterTest, InplaceWriterLastOneTooBig) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  gsoSupported_ = true;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  for (size_t i = 0; i < 5; i++) {
    auto buf = bufAccessor->obtain();
    buf->append(700);
    bufAccessor->release(std::move(buf));
    ASSERT_FALSE(
        batchWriter->append(nullptr, 700, quic::SocketAddress(), nullptr));
  }
  auto buf = bufAccessor->obtain();
  buf->append(1000);
  bufAccessor->release(std::move(buf));
  EXPECT_TRUE(batchWriter->needsFlush(1000));

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke([&](const auto& /* addr */,
                           const struct iovec* vec,
                           size_t,
                           QuicAsyncUDPSocket::WriteOptions options) {
        EXPECT_EQ(5 * 700, vec[0].iov_len);
        EXPECT_EQ(700, options.gso);
        return 700 * 5;
      }));
  EXPECT_EQ(5 * 700, batchWriter->write(sock, quic::SocketAddress()));
  batchWriter->reset();

  EXPECT_TRUE(bufAccessor->ownsBuffer());
  buf = bufAccessor->obtain();
  EXPECT_EQ(1000, buf->length());
  EXPECT_EQ(0, buf->headroom());
}

TEST_F(QuicBatchWriterTest, InplaceWriterBufResidueCheck) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  gsoSupported_ = true;

  uint32_t batchSize = 20;
  auto bufAccessor =
      std::make_unique<BufAccessor>(conn_.udpSendPacketLen * batchSize);
  conn_.bufAccessor = bufAccessor.get();
  conn_.udpSendPacketLen = 1000;
  auto batchWriter = quic::BatchWriterFactory::makeBatchWriter(
      quic::QuicBatchingMode::BATCHING_MODE_GSO,
      batchSize,
      DataPathType::ContinuousMemory,
      conn_,
      gsoSupported_);
  auto buf = bufAccessor->obtain();
  folly::IOBuf* Buf = buf.get();
  bufAccessor->release(std::move(buf));
  Buf->append(700);
  ASSERT_FALSE(
      batchWriter->append(nullptr, 700, quic::SocketAddress(), nullptr));

  // There is a check against packet 10 bytes or more larger than the size limit
  size_t packetSizeBig = 1009;
  Buf->append(packetSizeBig);
  EXPECT_TRUE(batchWriter->needsFlush(packetSizeBig));

  EXPECT_CALL(sock, writeGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](const auto& /* addr */, const struct iovec* vec, size_t, auto) {
            EXPECT_EQ(700, vec[0].iov_len);
            return 700;
          }));
  // No crash:
  EXPECT_EQ(700, batchWriter->write(sock, quic::SocketAddress()));
  batchWriter->reset();
  EXPECT_EQ(1009, Buf->length());
  EXPECT_EQ(0, Buf->headroom());
}

class SinglePacketInplaceBatchWriterTest : public ::testing::Test {
 public:
  SinglePacketInplaceBatchWriterTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    bufAccessor_ = std::make_unique<quic::BufAccessor>(conn_.udpSendPacketLen);
    conn_.bufAccessor = bufAccessor_.get();
  }

  quic::BatchWriterPtr makeBatchWriter(
      quic::QuicBatchingMode batchingMode =
          quic::QuicBatchingMode::BATCHING_MODE_NONE) {
    return quic::BatchWriterFactory::makeBatchWriter(
        batchingMode,
        conn_.transportSettings.maxBatchSize,
        conn_.transportSettings.dataPathType,
        conn_,
        false /* gsoSupported_ */);
  }

  void enableSinglePacketInplaceBatchWriter() {
    conn_.transportSettings.maxBatchSize = 1;
    conn_.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  }

 protected:
  std::unique_ptr<quic::BufAccessor> bufAccessor_;
  QuicServerConnectionState conn_;
};

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactorySuccess) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactoryWithLargerBatchSize) {
  conn_.transportSettings.maxBatchSize = 16;
  conn_.transportSettings.dataPathType = DataPathType::ContinuousMemory;
  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  EXPECT_NE(
      dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()),
      nullptr);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestFactoryWrongBatchingMode) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter(quic::QuicBatchingMode::BATCHING_MODE_GSO);
  CHECK(batchWriter);
  EXPECT_EQ(
      dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()),
      nullptr);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestReset) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* Buf = buf.get();
  bufAccessor_->release(std::move(buf));
  Buf->append(700);

  EXPECT_EQ(Buf->computeChainDataLength(), 700);
  batchWriter->reset();
  EXPECT_EQ(Buf->computeChainDataLength(), 0);
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestAppend) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));

  EXPECT_EQ(
      true, batchWriter->append(nullptr, 0, quic::SocketAddress(), nullptr));
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestEmpty) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* Buf = buf.get();
  bufAccessor_->release(std::move(buf));
  Buf->append(700);

  EXPECT_EQ(Buf->computeChainDataLength(), 700);
  EXPECT_FALSE(batchWriter->empty());

  batchWriter->reset();
  EXPECT_TRUE(batchWriter->empty());
}

TEST_F(SinglePacketInplaceBatchWriterTest, TestWrite) {
  enableSinglePacketInplaceBatchWriter();

  auto batchWriter = makeBatchWriter();
  CHECK(batchWriter);
  CHECK(dynamic_cast<quic::SinglePacketInplaceBatchWriter*>(batchWriter.get()));
  EXPECT_TRUE(batchWriter->empty());

  auto buf = bufAccessor_->obtain();
  folly::IOBuf* Buf = buf.get();
  bufAccessor_->release(std::move(buf));
  const auto appendSize = conn_.udpSendPacketLen - 200;
  Buf->append(appendSize);

  EXPECT_EQ(Buf->computeChainDataLength(), appendSize);
  EXPECT_FALSE(batchWriter->empty());

  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket sock(qEvb);
  EXPECT_CALL(sock, write(_, _, _))
      .Times(1)
      .WillOnce(
          Invoke([&](const auto& /* addr */, const struct iovec* vec, size_t) {
            EXPECT_EQ(appendSize, vec[0].iov_len);
            return appendSize;
          }));
  EXPECT_EQ(appendSize, batchWriter->write(sock, quic::SocketAddress()));
  batchWriter->reset();
  EXPECT_TRUE(batchWriter->empty());
}

} // namespace quic::testing
