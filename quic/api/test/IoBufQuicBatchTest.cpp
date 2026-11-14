/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicBatchWriterFactory.h>

#include <gtest/gtest.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

constexpr const auto kNumLoops = 64;
constexpr const auto kMaxBufs = 10;

namespace quic::testing {
void RunTest(int numBatch) {
  folly::EventBase evb;
  std::shared_ptr<FollyQuicEventBase> qEvb =
      std::make_shared<FollyQuicEventBase>(&evb);
  FollyQuicAsyncUDPSocket sock(qEvb);

  auto batchWriter = BatchWriterPtr(new test::TestPacketBatchWriter(numBatch));
  quic::SocketAddress peerAddress{"127.0.0.1", 1234};
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  QuicClientConnectionState::HappyEyeballsState happyEyeballsState;

  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      sock,
      peerAddress,
      conn.statsCallback,
      nullptr /* happyEyeballsState */);

  std::string strTest("Test");

  for (size_t i = 0; i < kNumLoops; i++) {
    auto buf = folly::IOBuf::copyBuffer(strTest.c_str(), strTest.length());
    CHECK(ioBufBatch.write(std::move(buf), strTest.length()));
  }
  // check flush is successful
  CHECK(ioBufBatch.flush());
  // check we sent all the packets
  CHECK_EQ(ioBufBatch.getPktSent(), kNumLoops);
}

TEST(QuicBatch, TestBatchingNone) {
  RunTest(1);
}

TEST(QuicBatch, TestBatchingNoFlush) {
  RunTest(-1);
}

TEST(QuicBatch, TestBatching) {
  RunTest(kMaxBufs);
}

TEST(QuicBatch, SendmmsgPropagatesSocketErrors) {
  const std::string packet = "packet";
  for (const int socketError : {EAGAIN, EWOULDBLOCK, ENOBUFS, EIO}) {
    SCOPED_TRACE(socketError);
    folly::EventBase evb;
    auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
    quic::test::MockAsyncUDPSocket sock(qEvb);
    QuicClientConnectionState conn(
        FizzClientQuicHandshakeContext::Builder().build());
    BufAccessor accessor(4096);
    conn.bufAccessor = &accessor;
    SocketAddress peerAddress("127.0.0.1", 1234);
    IOBufQuicBatch batch(
        BatchWriterPtr(new SendmmsgInplacePacketBatchWriter(conn, 2)),
        sock,
        peerAddress,
        nullptr,
        nullptr);
    EXPECT_CALL(sock, writem(::testing::_, ::testing::_, ::testing::_, 2))
        .WillOnce(::testing::InvokeWithoutArgs([&]() {
          errno = socketError;
          return -1;
        }));
    for (size_t i = 0; i < 2; ++i) {
      memcpy(accessor.writableTail(), packet.data(), packet.size());
      accessor.append(packet.size());
      auto result = batch.write(nullptr, packet.size());
      if (i == 0) {
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result.value());
      } else if (socketError == EIO) {
        EXPECT_TRUE(result.hasError());
      } else {
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result.value());
      }
    }
    EXPECT_EQ(batch.getLastRetryableErrno(), socketError);
    EXPECT_EQ(accessor.length(), 0);
  }
}

class HappyEyeballsBatchTest
    : public ::testing::TestWithParam<std::tuple<QuicBatchingMode, int>> {};

TEST_P(HappyEyeballsBatchTest, PreservesPacketsAcrossSocketAttempts) {
  using namespace ::testing;
  const auto [mode, firstError] = GetParam();
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  quic::test::MockAsyncUDPSocket firstSocket(qEvb);
  auto secondSocket = std::make_unique<quic::test::MockAsyncUDPSocket>(qEvb);
  QuicClientConnectionState conn(
      FizzClientQuicHandshakeContext::Builder().build());
  BufAccessor accessor(4096);
  conn.bufAccessor = &accessor;
  auto& happy = conn.happyEyeballsState;
  happy.shouldWriteToFirstSocket = true;
  happy.shouldWriteToSecondSocket = true;
  happy.secondPeerAddress = SocketAddress("127.0.0.1", 2345);
  const SocketAddress firstAddress("::1", 2345);
  std::vector<std::string> firstPackets;
  std::vector<std::string> secondPackets;
  auto firstWrite = [&](const SocketAddress& address,
                        const iovec* vec,
                        size_t count) -> ssize_t {
    EXPECT_EQ(address, firstAddress);
    firstPackets.push_back(folly::IOBuf::wrapIov(vec, count)->toString());
    errno = firstError;
    return firstError
        ? -1
        : static_cast<ssize_t>(test::getTotalIovecLen(vec, count));
  };
  auto secondWrite = [&](const SocketAddress& address,
                         const iovec* vec,
                         size_t count) -> ssize_t {
    EXPECT_EQ(address, happy.secondPeerAddress);
    secondPackets.push_back(folly::IOBuf::wrapIov(vec, count)->toString());
    return test::getTotalIovecLen(vec, count);
  };
  EXPECT_CALL(firstSocket, write(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(firstWrite));
  EXPECT_CALL(firstSocket, writeGSO(_, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly([&](const SocketAddress& addr,
                          const iovec* vec,
                          size_t count,
                          QuicAsyncUDPSocket::WriteOptions) {
        return firstWrite(addr, vec, count);
      });
  auto writeMessages = [](auto& writeOne,
                          AddressRange addrs,
                          iovec* vec,
                          size_t* messageSizes,
                          size_t count) {
    for (size_t i = 0; i < count; ++i) {
      writeOne(addrs[0], vec, messageSizes[i]);
      vec += messageSizes[i];
    }
  };
  EXPECT_CALL(firstSocket, writem(_, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly([&](AddressRange addrs,
                          iovec* vec,
                          size_t* messageSizes,
                          size_t count) {
        writeMessages(firstWrite, addrs, vec, messageSizes, count);
        return firstError ? -1 : static_cast<int>(count);
      });
  EXPECT_CALL(firstSocket, pauseRead()).Times(firstError == EIO ? 1 : 0);
  EXPECT_CALL(*secondSocket, write(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(secondWrite));
  EXPECT_CALL(*secondSocket, writeGSO(_, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly([&](const SocketAddress& addr,
                          const iovec* vec,
                          size_t count,
                          QuicAsyncUDPSocket::WriteOptions) {
        return secondWrite(addr, vec, count);
      });
  EXPECT_CALL(*secondSocket, writem(_, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly([&](AddressRange addrs,
                          iovec* vec,
                          size_t* messageSizes,
                          size_t count) {
        writeMessages(secondWrite, addrs, vec, messageSizes, count);
        return static_cast<int>(count);
      });
  happy.secondSocket = std::move(secondSocket);
  auto writer = BatchWriterFactory::makeBatchWriter(
      mode, 2, DataPathType::ContinuousMemory, conn, true);
  IOBufQuicBatch batch(
      std::move(writer), firstSocket, firstAddress, nullptr, &happy);
  const std::vector<std::string> packets{"first", "a larger second packet"};
  for (const auto& packet : packets) {
    memcpy(accessor.writableTail(), packet.data(), packet.size());
    accessor.append(packet.size());
    auto result = batch.write(nullptr, packet.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
  }
  auto result = batch.flush();
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result.value());
  EXPECT_EQ(secondPackets, packets);
  // After EIO the first socket only sees the first flush. sendmmsg batches both
  // packets into it. The other writers flush the second packet on its own.
  const size_t firstFlushPackets =
      mode == QuicBatchingMode::BATCHING_MODE_SENDMMSG ? packets.size() : 1;
  EXPECT_EQ(
      firstPackets,
      firstError == EIO
          ? std::vector<std::string>(
                packets.begin(), packets.begin() + firstFlushPackets)
          : packets);
  EXPECT_EQ(accessor.length(), 0);
  EXPECT_EQ(accessor.headroom(), 0);
  EXPECT_EQ(happy.shouldWriteToFirstSocket, firstError != EIO);
  EXPECT_TRUE(happy.shouldWriteToSecondSocket);
  ASSERT_TRUE(batch.flush().has_value());
}

TEST(QuicBatch, FirstAddressFailureReportedOnlyBeforeHappyEyeballsFinishes) {
  using namespace ::testing;
  for (bool finished : {false, true}) {
    folly::EventBase evb;
    auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
    quic::test::MockAsyncUDPSocket sock(qEvb);
    QuicClientConnectionState conn(
        FizzClientQuicHandshakeContext::Builder().build());
    BufAccessor accessor(4096);
    conn.bufAccessor = &accessor;
    auto& happy = conn.happyEyeballsState;
    happy.finished = finished;
    happy.shouldWriteToFirstSocket = true;
    int failures = 0;
    happy.firstAddressFailureCallback = [&](const SocketAddress&) {
      ++failures;
    };
    EXPECT_CALL(sock, write(_, _, _)).WillOnce(SetErrnoAndReturn(EIO, -1));
    EXPECT_CALL(sock, pauseRead());
    const SocketAddress address("::1", 2345);
    IOBufQuicBatch batch(
        BatchWriterFactory::makeBatchWriter(
            QuicBatchingMode::BATCHING_MODE_NONE,
            1,
            DataPathType::ContinuousMemory,
            conn,
            true),
        sock,
        address,
        nullptr,
        &happy);
    const std::string packet = "packet";
    memcpy(accessor.writableTail(), packet.data(), packet.size());
    accessor.append(packet.size());
    (void)batch.write(nullptr, packet.size());
    (void)batch.flush();
    EXPECT_EQ(failures, finished ? 0 : 1) << "finished=" << finished;
  }
}

INSTANTIATE_TEST_SUITE_P(
    BatchingModes,
    HappyEyeballsBatchTest,
    ::testing::Combine(
        ::testing::Values(
            QuicBatchingMode::BATCHING_MODE_NONE,
            QuicBatchingMode::BATCHING_MODE_GSO,
            QuicBatchingMode::BATCHING_MODE_SENDMMSG),
        ::testing::Values(0, EAGAIN, EIO)));

} // namespace quic::testing
