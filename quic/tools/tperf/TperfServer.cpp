/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Utils.h>
#include <fizz/record/Types.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/stats/Histogram.h>
#include <quic/api/QuicBatchWriter.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/logging/FileQLogger.h>
#include <quic/logging/oops_logger/GlogOopsLogger.h>
#include <quic/tools/tperf/PacingObserver.h>
#include <quic/tools/tperf/TperfHugePageArena.h>
#include <quic/tools/tperf/TperfServer.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <utility>
#include <vector>

namespace quic::tperf {

namespace {

// Snapshots the per-listener-fd MSG_ZEROCOPY kernel counters into
// writeStats. Called from the inplace batch writer's write() path, which
// runs on the same worker EventBase that owns `sock` — so this satisfies
// folly's contract that ZeroCopyFdBookkeeping/getZeroCopy* getters are read
// from the socket's own EventBase thread (the counters are plain uint64_t,
// not atomics). With --num_server_worker=N, every worker overwrites the
// same snapshot field on each ZC send; under default --num_server_worker=1
// the snapshot is exact, otherwise it is best-effort observability (whichever
// worker wrote last wins).
void publishListenerZeroCopySnapshot(
    folly::AsyncUDPSocket& sock,
    const std::shared_ptr<TPerfWriteStats>& writeStats) {
  if (!writeStats) {
    return;
  }
  writeStats->recordListenerZeroCopySnapshot(
      TPerfWriteStats::ListenerKernelSnapshot{
          .completionsZc = sock.getZeroCopyCompletionsZc(),
          .completionsCopied = sock.getZeroCopyCompletionsCopied(),
          .sendsAckedZc = sock.getZeroCopySendsAckedZc(),
          .sendsAckedMaybeCopied = sock.getZeroCopySendsAckedMaybeCopied(),
          .zcEnabled = sock.getZeroCopy()});
}

// Records per-write latency by wrapping an inner batch writer. Used by the
// override factory so generic write-latency counters land in TPerfWriteStats
// regardless of which underlying writer mvfst picked.
class TimingBatchWriter : public quic::BatchWriter {
 public:
  TimingBatchWriter(
      BatchWriterPtr inner,
      std::shared_ptr<TPerfWriteStats> writeStats)
      : inner_(std::move(inner)), writeStats_(std::move(writeStats)) {}

  [[nodiscard]] bool empty() const override {
    return inner_->empty();
  }

  [[nodiscard]] size_t size() const override {
    return inner_->size();
  }

  void reset() override {
    inner_->reset();
    bufferedPackets_ = 0;
    bufferedBytes_ = 0;
  }

  bool needsFlush(size_t nextPacketSize) override {
    return inner_->needsFlush(nextPacketSize);
  }

  void setTxTime(std::chrono::microseconds txtime) override {
    inner_->setTxTime(txtime);
  }

  bool append(
      BufPtr&& buf,
      size_t bufSize,
      const folly::SocketAddress& addr,
      QuicAsyncUDPSocket* sock) override {
    auto needsFlush = inner_->append(std::move(buf), bufSize, addr, sock);
    bufferedPackets_++;
    bufferedBytes_ += bufSize;
    return needsFlush;
  }

  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override {
    auto start = std::chrono::steady_clock::now();
    auto ret = inner_->write(sock, address);
    auto errnoCopy = ret < 0 ? errno : 0;
    auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(
                          std::chrono::steady_clock::now() - start)
                          .count();
    writeStats_->recordWrite(
        TPerfWriteStats::WriteSample{
            .durationUs = static_cast<uint64_t>(durationUs),
            .ret = ret,
            .errnoValue = errnoCopy,
            .bufferedPackets = bufferedPackets_,
            .bufferedBytes = bufferedBytes_});
    return ret;
  }

 private:
  BatchWriterPtr inner_;
  std::shared_ptr<TPerfWriteStats> writeStats_;
  uint64_t bufferedPackets_{0};
  uint64_t bufferedBytes_{0};
};

// Wraps `batchWriter` so per-write latency, byte, and errno counters land in
// `writeStats`. The factory override always supplies a non-null `writeStats`;
// callers that don't need timing should skip this wrapper.
BatchWriterPtr wrapBatchWriterWithTiming(
    BatchWriterPtr batchWriter,
    const std::shared_ptr<TPerfWriteStats>& writeStats) {
  MVCHECK(writeStats);
  return BatchWriterPtr(
      new TimingBatchWriter(std::move(batchWriter), writeStats));
}

// No-op deleter for arena-backed slab IOBufs: the arena owns the memory and
// outlives every IOBuf wrapping it. Reclaim is explicit, via
// TperfInplaceZcSlabPool::notifyDroppedSlab, so that it always happens on the
// owning worker thread — an IOBuf freed by folly on some other thread must
// not touch the arena's free list.
void hugePageSlabNoopFree(void* /*buf*/, void* /*userData*/) {}

// Thread-local pool of slab IOBufs reused across MSG_ZEROCOPY sends. mvfst
// borrows a slab from this pool, encrypts directly into it, and hands
// ownership to folly's writeChain. The pool implements
// folly::AsyncWriter::ReleaseIOBufCallback so the per-fd
// ZeroCopyFdBookkeeping (installed by QuicServerWorker::enableZeroCopy)
// returns the slab via releaseIOBuf() when the kernel completion fires.
class TperfInplaceZcSlabPool : public folly::AsyncWriter::ReleaseIOBufCallback {
 public:
  static constexpr size_t kDefaultMaxSlabs = 64;

  TperfInplaceZcSlabPool() = default;
  TperfInplaceZcSlabPool(const TperfInplaceZcSlabPool&) = delete;
  TperfInplaceZcSlabPool& operator=(const TperfInplaceZcSlabPool&) = delete;
  TperfInplaceZcSlabPool(TperfInplaceZcSlabPool&&) = delete;
  TperfInplaceZcSlabPool& operator=(TperfInplaceZcSlabPool&&) = delete;

  ~TperfInplaceZcSlabPool() override {
    idle_.clear();
  }

  void setMaxSlabs(size_t maxSlabs) {
    if (maxSlabs > 0) {
      maxSlabs_ = maxSlabs;
    }
  }

  // Switches fresh-slab allocation from malloc to a per-worker huge-page
  // arena. Must be called before the first tryAcquireIdle so every slab in
  // circulation comes from the same allocator.
  // `arenaStats` receives the one-off arena info and heap-fallback counts
  // even when per-write stats are disabled: they are what proves a run was
  // actually huge-page backed.
  void setHugePages(
      bool enabled,
      size_t arenaBytes,
      std::shared_ptr<TPerfWriteStats> arenaStats) {
    hugePagesRequested_ = enabled;
    hugePageArenaBytes_ = arenaBytes;
    arenaStats_ = std::move(arenaStats);
  }

  BufPtr tryAcquireIdle(
      size_t capacity,
      const std::shared_ptr<TPerfWriteStats>& stats) {
    if (slabCapacity_ == 0) {
      slabCapacity_ = capacity;
    }
    if (!idle_.empty()) {
      auto buf = std::move(idle_.back());
      idle_.pop_back();
      buf->clear();
      if (stats) {
        stats->recordUdpZerocopyInplacePoolAcquire(/*reused=*/true);
      }
      return buf;
    }
    if (totalAllocated_ >= maxSlabs_) {
      return nullptr;
    }
    auto buf = allocateSlab();
    if (!buf) {
      return nullptr;
    }
    ++totalAllocated_;
    if (stats) {
      stats->recordUdpZerocopyInplacePoolAcquire(/*reused=*/false);
    }
    return buf;
  }

  // Returns a slab to the idle pool. Decrements the outstanding-slab
  // counter so that direct-return paths (writer destructor on a slab that
  // never made it to the kernel) stay accounted for; the kernel-completion
  // path (releaseIOBuf below) funnels through here too.
  void returnIdle(BufPtr&& buf) {
    if (!buf) {
      return;
    }
    buf->clear();
    if (stats_) {
      stats_->recordUdpZerocopyInplacePoolRelease();
    }
    idle_.push_back(std::move(buf));
  }

  // Called when a slab was handed to folly's writeChain but the send
  // failed before bookkeeping took ownership — folly's release callback
  // contract only fires on successful MSG_ZEROCOPY sends, so the slab is
  // gone (freed by folly's ioBufFreeFunc_ or by the unique_ptr destructor)
  // and our ReleaseIOBufCallback will never see it. Decrement
  // totalAllocated_ (so the pool can re-allocate up to the cap) and
  // record the matching release on the outstanding-slabs counter so it
  // doesn't drift upward over persistent ZC failures.
  //
  // `slabMem` is the slab's backing buffer, captured before the BufPtr was
  // moved into writeChain. For arena-backed slabs it is the only way to get
  // the memory back: the IOBuf's free function is a no-op precisely so that
  // reclaim happens here, on the worker thread that owns the arena, rather
  // than wherever folly happened to destroy the IOBuf.
  void notifyDroppedSlab(
      void* slabMem,
      const std::shared_ptr<TPerfWriteStats>& stats) {
    if (totalAllocated_ > 0) {
      --totalAllocated_;
    }
    if (slabMem && arena_.contains(slabMem)) {
      arena_.freeSlab(slabMem);
    }
    if (stats) {
      stats->recordUdpZerocopyInplacePoolRelease();
    }
  }

  // folly::AsyncWriter::ReleaseIOBufCallback override. Called by the
  // ZeroCopyFdBookkeeping::onCompletion path when the kernel reports
  // SO_EE_ORIGIN_ZEROCOPY for an id we registered via writeChain. Release
  // accounting happens inside returnIdle so all return-to-idle paths
  // increment the counter exactly once.
  void releaseIOBuf(std::unique_ptr<folly::IOBuf> buf) noexcept override {
    returnIdle(std::move(buf));
  }

  void setStats(std::shared_ptr<TPerfWriteStats> stats) {
    stats_ = std::move(stats);
  }

 private:
  // Fresh slab from the huge-page arena when this backend asked for one,
  // otherwise from malloc. Falls back to malloc — loudly, via the
  // heap-fallback counter — if the arena could not be created or is full, so
  // a mis-sized arena degrades into a slower run rather than a stall.
  BufPtr allocateSlab() {
    if (!hugePagesRequested_) {
      return folly::IOBuf::createCombined(slabCapacity_);
    }
    if (!hugePagesInitialized_) {
      hugePagesInitialized_ = true;
      if (!arena_.init(hugePageArenaBytes_, slabCapacity_)) {
        MVLOG_ERROR << "tperf hugepage: arena unavailable on this worker; "
                    << "slabs will be malloc-backed and this run is NOT a "
                    << "huge-page measurement";
      } else if (arenaStats_) {
        arenaStats_->recordUdpZerocopyHugepageArena(arena_.info());
      }
    }
    if (arena_.ready()) {
      if (void* mem = arena_.allocSlab()) {
        return folly::IOBuf::takeOwnership(
            mem,
            slabCapacity_,
            /*length=*/0,
            hugePageSlabNoopFree,
            /*userData=*/nullptr);
      }
    }
    if (arenaStats_) {
      arenaStats_->recordUdpZerocopyHugepageHeapFallback();
    }
    return folly::IOBuf::createCombined(slabCapacity_);
  }

  std::vector<BufPtr> idle_;
  size_t totalAllocated_{0};
  size_t slabCapacity_{0};
  size_t maxSlabs_{kDefaultMaxSlabs};
  std::shared_ptr<TPerfWriteStats> stats_;
  bool hugePagesRequested_{false};
  bool hugePagesInitialized_{false};
  size_t hugePageArenaBytes_{0};
  std::shared_ptr<TPerfWriteStats> arenaStats_;
  TperfHugePageArena arena_;
};

TperfInplaceZcSlabPool& threadLocalInplaceZcSlabPool() {
  thread_local TperfInplaceZcSlabPool pool;
  return pool;
}

// Per-fd singleton WriteCallback whose getReleaseIOBufCallback() returns
// the thread-local slab pool. folly's writeChain reads this once per
// successful MSG_ZEROCOPY send and stores the returned
// ReleaseIOBufCallback* in the bookkeeping entry — so the pointer must
// outlive every in-flight send. thread_local satisfies that since the
// pool itself never gets destroyed for the worker thread.
class TperfInplaceZcWriteCallback
    : public folly::AsyncUDPSocket::WriteCallback {
 public:
  folly::AsyncWriter::ReleaseIOBufCallback* getReleaseIOBufCallback() noexcept
      override {
    return &threadLocalInplaceZcSlabPool();
  }
};

TperfInplaceZcWriteCallback& threadLocalInplaceZcWriteCallback() {
  thread_local TperfInplaceZcWriteCallback wcb;
  return wcb;
}

// Inplace + MSG_ZEROCOPY batch writer. Hijacks conn.bufAccessor (requires
// DataPathType::ContinuousMemory) to install a pool-borrowed slab for each
// write event. mvfst encrypts directly into the slab; we then send via
// writeChain with the per-write WriteCallback that hands the slab to the
// per-fd ZeroCopyFdBookkeeping on success. The bookkeeping invokes our
// release callback once the kernel completion arrives on the listener
// fd's POLLERR path, returning the slab to the idle list.
//
// Lifetime: mvfst constructs a fresh writer every write event, so all
// persistent slab state lives in the thread_local pool. This writer's
// only per-instance state is `originalBuf_` (the buf displaced from the
// accessor) — restored to the accessor in the destructor.
//
// Unlike the mvfst inplace writers, write() consumes the batch (it may hand
// the slab to the kernel), so it cannot be written to a second socket. That is
// only safe on servers, which never use Happy Eyeballs.
class UdpGsoZerocopyInplaceBatchWriter : public quic::BatchWriter {
 public:
  UdpGsoZerocopyInplaceBatchWriter(const UdpGsoZerocopyInplaceBatchWriter&) =
      delete;
  UdpGsoZerocopyInplaceBatchWriter& operator=(
      const UdpGsoZerocopyInplaceBatchWriter&) = delete;
  UdpGsoZerocopyInplaceBatchWriter(UdpGsoZerocopyInplaceBatchWriter&&) = delete;
  UdpGsoZerocopyInplaceBatchWriter& operator=(
      UdpGsoZerocopyInplaceBatchWriter&&) = delete;

  UdpGsoZerocopyInplaceBatchWriter(
      QuicConnectionStateBase& conn,
      size_t maxPackets,
      TPerfUdpGsoZerocopyConfig config,
      std::shared_ptr<TPerfWriteStats> writeStats)
      : conn_(conn),
        maxPackets_(maxPackets),
        config_(config),
        writeStats_{config.perWriteStats ? writeStats : nullptr},
        pool_(threadLocalInplaceZcSlabPool()) {
    MVCHECK(conn_.nodeType == quic::QuicNodeType::Server);
    pool_.setStats(writeStats_);
    pool_.setMaxSlabs(static_cast<size_t>(config_.poolBuffers));
    pool_.setHugePages(
        config_.hugePages,
        static_cast<size_t>(config_.hugePageBytes),
        std::move(writeStats));
    auto& accessor = *conn_.bufAccessor;
    if (!accessor.ownsBuffer()) {
      return;
    }
    slabCapacity_ = accessor.buf()->capacity();
    auto slabBuf = pool_.tryAcquireIdle(slabCapacity_, writeStats_);
    if (!slabBuf) {
      return;
    }
    originalBuf_ = accessor.obtain();
    accessor.release(std::move(slabBuf));
    haveSlabInAccessor_ = true;
  }

  ~UdpGsoZerocopyInplaceBatchWriter() override {
    auto& accessor = *conn_.bufAccessor;
    if (haveSlabInAccessor_) {
      // Slab still installed (never ZC-sent, or fell back to non-ZC on the
      // last batch). Return it to the pool's idle list immediately.
      pool_.returnIdle(accessor.obtain());
      MVCHECK(originalBuf_);
      accessor.release(std::move(originalBuf_));
    } else if (originalBuf_) {
      // We installed a slab, then ZC-sent it (now in the bookkeeping's
      // pending set). Accessor is empty. Restore the original.
      MVCHECK(!accessor.ownsBuffer());
      accessor.release(std::move(originalBuf_));
    }
  }

  void reset() override {
    lastPacketEnd_ = nullptr;
    prevSize_ = 0;
    numPackets_ = 0;
  }

  bool needsFlush(size_t size) override {
    return prevSize_ && size > prevSize_;
  }

  bool append(
      BufPtr&& /*buf*/,
      size_t size,
      const folly::SocketAddress& /*addr*/,
      QuicAsyncUDPSocket* /*sock*/) override {
    MVCHECK(!needsFlush(size));
    auto& buf = conn_.bufAccessor->buf();
    if (!lastPacketEnd_) {
      MVCHECK(prevSize_ == 0 && numPackets_ == 0);
      prevSize_ = size;
      lastPacketEnd_ = buf->tail();
      numPackets_ = 1;
      return false;
    }
    MVCHECK(prevSize_ && prevSize_ >= size);
    ++numPackets_;
    lastPacketEnd_ = buf->tail();
    if (prevSize_ > size || numPackets_ == maxPackets_) {
      return true;
    }
    return false;
  }

  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override {
    MVCHECK(lastPacketEnd_);
    auto& accessor = *conn_.bufAccessor;
    auto& accessorBuf = accessor.buf();
    MVCHECK(!accessorBuf->isChained());

    uint64_t diffToEnd = accessorBuf->tail() - lastPacketEnd_;
    uint64_t diffToStart = lastPacketEnd_ - accessorBuf->data();
    accessorBuf->trimEnd(diffToEnd);

    bool inSlabMode = haveSlabInAccessor_;
    uint64_t payloadLen = diffToStart;
    // Only attempt ZC when the batch fits cleanly in the slab (no residue)
    // and meets size/eligibility thresholds.
    bool zcEligible = inSlabMode && diffToEnd == 0 && numPackets_ > 1 &&
        config_.enabled && payloadLen >= config_.minBytes;

    auto* follySock = dynamic_cast<FollyQuicAsyncUDPSocket*>(&sock);
    if (zcEligible && follySock && !zcSetupAttempted_) {
      zcSetupAttempted_ = true;
      // Bookkeeping was installed by QuicServerWorker::enableZeroCopy and
      // setZeroCopy(true) was called on the listener by
      // QuicServer::enableZeroCopy.
      zcConfigured_ = true;
    }
    bool sendZc = zcEligible && zcConfigured_ && follySock != nullptr;

    int gsoVal = numPackets_ > 1 ? static_cast<int>(prevSize_) : 0;
    ssize_t ret = 0;
    int errnoCopy = 0;
    bool zcFailed = false;

    if (sendZc) {
      // Pull the slab out of the accessor so we can pass ownership into
      // writeChain — folly will hand it to the bookkeeping after a
      // successful sendmsg, which holds it until the kernel completes the
      // send. The accessor is left empty until we install another slab (or
      // restore originalBuf_ in the destructor).
      auto& udpSocket = follySock->getFollySocket();
      auto slabBuf = accessor.obtain();
      // Capture the backing buffer before ownership moves into writeChain —
      // on the failure path below it is the only handle left for returning an
      // arena-backed slab to its arena.
      void* const slabMem = slabBuf->writableBuffer();
      haveSlabInAccessor_ = false;
      folly::AsyncUDPSocket::WriteOptions opts(gsoVal, true /*zerocopy*/);
      opts.txTime = txTime_;
      ret = udpSocket.writeChain(
          &threadLocalInplaceZcWriteCallback(),
          address,
          std::move(slabBuf),
          opts);
      errnoCopy = ret < 0 ? errno : 0;
      if (ret < 0) {
        // writeChain failed — slabBuf was already moved out. Per folly
        // contract (see AsyncUDPSocket::writeChain implementation), the
        // per-write ReleaseIOBufCallback fires only when MSG_ZEROCOPY
        // sendmsg returns >= 0; on any error return (including the
        // ENOBUFS-fallback retry path) the buf is freed via folly's
        // internal ioBufFreeFunc_ or dropped by the unique_ptr — the
        // bookkeeping never registers it and our releaseIOBuf callback is
        // never invoked. Decrement here so the outstanding-slabs counter
        // and the pool's totalAllocated_ stay balanced; without this,
        // persistent ZC failures drift the counter upward and permanently
        // shrink the effective pool cap.
        zcFailed = true;
        pool_.notifyDroppedSlab(slabMem, writeStats_);
      } else {
        // Successful ZC send: bookkeeping owns the buf. Publish the
        // per-fd kernel MSG_ZEROCOPY counters into writeStats from this
        // (worker) thread — same EventBase that owns `udpSocket`, so the
        // non-atomic getZeroCopy* reads are race-free.
        publishListenerZeroCopySnapshot(udpSocket, writeStats_);
        // Try to install a fresh slab for the next batch in this write
        // event.
        auto next = pool_.tryAcquireIdle(slabCapacity_, writeStats_);
        if (next) {
          accessor.release(std::move(next));
          haveSlabInAccessor_ = true;
        } else {
          // Pool exhausted. Restore originalBuf_ so the next batch can use
          // it via the plain-GSO fallback (no ZC).
          MVCHECK(originalBuf_);
          accessor.release(std::move(originalBuf_));
          // originalBuf_ is null now — destructor will detect that path.
        }
      }
    } else {
      // Plain GSO fallback (ineligible, setup failed, or residue present).
      // Use writeGSO with iovec from the accessor buf; do not register with
      // bookkeeping (no ZC requested) and leave the slab installed so the
      // residue shift below works.
      std::array<iovec, 1> vec{};
      vec[0].iov_base = accessorBuf->writableData();
      vec[0].iov_len = accessorBuf->length();
      QuicAsyncUDPSocket::WriteOptions qOpts(gsoVal, false /*zerocopy*/);
      qOpts.txTime = txTime_;
      ret = sock.writeGSO(address, vec.data(), vec.size(), qOpts);
      errnoCopy = ret < 0 ? errno : 0;
      // GSOInplace residue shift: any bytes past lastPacketEnd_ are next
      // batch's first packet; move them to the start of the slab.
      if (diffToEnd) {
        accessorBuf->trimStart(diffToStart);
        accessorBuf->append(diffToEnd);
        accessorBuf->retreat(diffToStart);
      } else {
        accessorBuf->clear();
      }
    }

    if (writeStats_) {
      bool zcSuccess = sendZc && ret >= 0;
      bool fallbackSend = !sendZc;
      writeStats_->recordUdpZerocopyInplaceWrite(
          zcSuccess, fallbackSend, zcFailed);
    }

    reset();
    errno = errnoCopy;
    return ret;
  }

  [[nodiscard]] bool empty() const override {
    return numPackets_ == 0;
  }

  [[nodiscard]] size_t size() const override {
    if (empty()) {
      return 0;
    }
    MVCHECK(lastPacketEnd_);
    return lastPacketEnd_ - conn_.bufAccessor->data();
  }

  void setTxTime(std::chrono::microseconds txTime) override {
    txTime_ = txTime;
  }

 private:
  QuicConnectionStateBase& conn_;
  size_t maxPackets_;
  TPerfUdpGsoZerocopyConfig config_;
  std::shared_ptr<TPerfWriteStats> writeStats_;
  TperfInplaceZcSlabPool& pool_;

  BufPtr originalBuf_;
  size_t slabCapacity_{0};
  bool haveSlabInAccessor_{false};
  bool zcSetupAttempted_{false};
  bool zcConfigured_{false};

  const uint8_t* lastPacketEnd_{nullptr};
  size_t prevSize_{0};
  size_t numPackets_{0};
  std::chrono::microseconds txTime_{std::chrono::microseconds(0)};
};

} // namespace

class ServerStreamHandler : public quic::QuicSocket::ConnectionSetupCallback,
                            public quic::QuicSocket::ConnectionCallback,
                            public quic::QuicSocket::ReadCallback,
                            public quic::QuicSocket::WriteCallback,
                            public quic::QuicTimerCallback,
                            public ByteEventCallback {
 public:
  explicit ServerStreamHandler(
      folly::EventBase* evbIn,
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream,
      folly::AsyncUDPSocket& sock,
      uint32_t burstDeadlineMs,
      uint64_t maxPacingRate,
      TPerfServer::DoneCallback* doneCallback)
      : evb_(std::make_shared<FollyQuicEventBase>(evbIn)),
        udpSock_(FollyQuicAsyncUDPSocket(evb_, sock)),
        blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream),
        burstDeadlineMs_(burstDeadlineMs),
        maxPacingRate_(maxPacingRate),
        doneCallback_(doneCallback) {
    buf_ = folly::IOBuf::createCombined(blockSize_);
  }

  void setQuicSocket(std::shared_ptr<quic::QuicServerTransport> socket) {
    sock_ = socket;
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got bidirectional stream id=" << id;
    sock_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got unidirectional stream id=" << id;
    sock_->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    MVLOG_INFO << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    MVLOG_INFO << "Socket closed";
    auto srtt = sock_->getTransportInfo().srtt.count();
    sock_.reset();
    if (burstDeadlineMs_ > 0) {
      auto resultStr =
          fmt::format("Burst send stats, burst size of {}\n", blockSize_);
      resultStr += fmt::format("  * total bursts sent: {}\n", batchN_);
      resultStr +=
          fmt::format("  * delivered: {}\n", burstSendStats_.delivered);
      resultStr += fmt::format(
          "  * missed deadline: {}\n", burstSendStats_.missedDeadline);

      resultStr += fmt::format("Burst ack latency stats, microseconds:\n");
      resultStr += fmt::format(
          "  * p5: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.05));
      resultStr += fmt::format(
          "  * p50: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.5));
      resultStr += fmt::format(
          "  * p95: {}\n",
          burstSendAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.95));

      resultStr += fmt::format(
          "Burst true (tx-based) ack latency stats, microseconds:\n");
      resultStr += fmt::format(
          "  * p5: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.05));
      resultStr += fmt::format(
          "  * p50: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.5));
      resultStr += fmt::format(
          "  * p95: {}\n",
          burstSendTrueAckedLatencyHistogramMicroseconds_.getPercentileEstimate(
              0.95));

      resultStr += fmt::format("\nmvfst srtt: {}\n", srtt);

      if (doneCallback_) {
        doneCallback_->onDone(resultStr);
      } else {
        MVLOG_ERROR << resultStr;
      }
    }
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    MVLOG_ERROR << "Conn errorCoded=" << toString(error.code)
                << ", errorMsg=" << error.message;
  }

  void onTransportReady() noexcept override {
    if (maxPacingRate_ != std::numeric_limits<uint64_t>::max()) {
      sock_->setMaxPacingRate(maxPacingRate_);
    }
    MVLOG_INFO << "Starting sends to client.";
    if (burstDeadlineMs_ > 0) {
      doBurstSending();
    } else {
      for (uint32_t i = 0; i < numStreams_; i++) {
        createNewStream();
      }
    }
  }

  void createNewStream() noexcept {
    if (!sock_) {
      MVVLOG(4) << __func__ << ": socket is closed.";
      return;
    }
    auto stream = sock_->createUnidirectionalStream();
    MVVLOG(5) << "New Stream with id = " << stream.value();
    MVCHECK(stream.has_value());
    bytesPerStream_[stream.value()] = 0;
    notifyDataForStream(stream.value());
  }

  void notifyDataForStream(quic::StreamId id) {
    evb_->runInEventBaseThread([&, id]() {
      if (!sock_) {
        MVVLOG(5) << "notifyDataForStream(" << id << "): socket is closed.";
        return;
      }
      auto res = sock_->notifyPendingWriteOnStream(id, this);
      if (res.hasError()) {
        MVLOG_FATAL << quic::toString(res.error());
      }
    });
  }

  void readAvailable(quic::StreamId id) noexcept override {
    MVLOG_INFO << "read available for stream id=" << id;
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    MVLOG_ERROR << "Got read error on stream=" << id
                << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    bool eof = false;
    uint64_t toSend = std::min<uint64_t>(maxToSend, blockSize_);
    if (maxBytesPerStream_ > 0) {
      toSend =
          std::min<uint64_t>(toSend, maxBytesPerStream_ - bytesPerStream_[id]);
      bytesPerStream_[id] += toSend;
      if (bytesPerStream_[id] >= maxBytesPerStream_) {
        eof = true;
      }
    }
    regularSend(id, toSend, eof);
    if (!eof) {
      notifyDataForStream(id);
    } else {
      bytesPerStream_.erase(id);
      createNewStream();
    }
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    MVLOG_ERROR << "write error with stream=" << id
                << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb_->getBackingEventBase();
  }

 private:
  void regularSend(quic::StreamId id, uint64_t toSend, bool eof) {
    auto sendBuffer = buf_->clone();
    sendBuffer->append(toSend);
    auto res = sock_->writeChain(id, std::move(sendBuffer), eof, nullptr);
    if (res.hasError()) {
      MVLOG_FATAL << "Got error on write: " << quic::toString(res.error());
    }
  }

  void doBurstSending() {
    if (!sock_) {
      return;
    }

    MVVLOG(4) << "sending batch " << batchN_;
    ++batchN_;

    auto stream = sock_->createUnidirectionalStream();
    MVVLOG(5) << "New Stream with id = " << stream.value();
    MVCHECK(stream.has_value());
    streamBurstSendResult_.streamId = *stream;
    streamBurstSendResult_.acked = false;
    streamBurstSendResult_.startTs = Clock::now();

    auto sendBuffer = buf_->clone();
    sendBuffer->append(blockSize_);
    MVCHECK_GT(blockSize_, 0);
    auto r = sock_->registerTxCallback(*stream, 0, this);
    if (r.hasError()) {
      MVLOG_FATAL << "Got error on registerTxCallback: "
                  << quic::toString(r.error());
    }
    auto res = sock_->writeChain(
        *stream,
        std::move(sendBuffer),
        true /* eof */,
        this /* byte events callback */);
    if (res.hasError()) {
      MVLOG_FATAL << "Got error on write: " << quic::toString(res.error());
    }

    // Schedule deadline.
    evb_->scheduleTimeoutHighRes(
        this, std::chrono::milliseconds(burstDeadlineMs_));
  }

  void onByteEvent(ByteEvent byteEvent) override {
    MVCHECK_EQ(byteEvent.id, streamBurstSendResult_.streamId);
    auto now = Clock::now();
    if (byteEvent.type == ByteEvent::Type::TX) {
      streamBurstSendResult_.trueTxStartTs = now;
    } else if (byteEvent.type == ByteEvent::Type::ACK) {
      auto ackedLatencyUs =
          std::chrono::duration_cast<std::chrono::microseconds>(
              now - streamBurstSendResult_.startTs);
      burstSendAckedLatencyHistogramMicroseconds_.addValue(
          ackedLatencyUs.count());

      auto trueAckedLatencyUs =
          std::chrono::duration_cast<std::chrono::microseconds>(
              now - streamBurstSendResult_.trueTxStartTs);
      burstSendTrueAckedLatencyHistogramMicroseconds_.addValue(
          trueAckedLatencyUs.count());
      MVVLOG(4) << "got stream " << byteEvent.id << " offset "
                << byteEvent.offset << " acked (" << trueAckedLatencyUs.count()
                << "us)";

      streamBurstSendResult_.acked = true;
      ++burstSendStats_.delivered;
    }
  }

  void onByteEventCanceled(ByteEventCancellation cancellation) override {
    MVVLOG(4) << "got stream " << cancellation.id << " offset "
              << cancellation.offset << " cancelled";
  }

  void timeoutExpired() noexcept override {
    if (!sock_) {
      return;
    }

    if (!streamBurstSendResult_.acked) {
      MVLOG_ERROR << "resetting stream " << streamBurstSendResult_.streamId
                  << " on deadline";
      ++burstSendStats_.missedDeadline;
      sock_->resetStream(
          streamBurstSendResult_.streamId,
          GenericApplicationErrorCode::NO_ERROR);
    }
    doBurstSending();
  }

  void callbackCanceled() noexcept override {}

 private:
  std::shared_ptr<quic::QuicServerTransport> sock_;
  std::shared_ptr<FollyQuicEventBase> evb_;
  FollyQuicAsyncUDPSocket udpSock_;
  uint64_t blockSize_;
  std::unique_ptr<folly::IOBuf> buf_;
  uint32_t numStreams_;
  uint64_t maxBytesPerStream_;
  std::unordered_map<quic::StreamId, uint64_t> bytesPerStream_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;

  // Burst sending machinery.
  uint64_t batchN_{0};

  struct {
    quic::StreamId streamId;
    bool acked{false};
    TimePoint startTs;
    TimePoint trueTxStartTs;
  } streamBurstSendResult_;

  struct {
    uint64_t missedDeadline{0};
    uint64_t delivered{0};
  } burstSendStats_;

  folly::Histogram<uint64_t> burstSendAckedLatencyHistogramMicroseconds_{
      100, /* bucket size */
      0, /* min */
      1000000 /* 1 sec max delay */};
  folly::Histogram<uint64_t> burstSendTrueAckedLatencyHistogramMicroseconds_{
      100, /* bucket size */
      0, /* min */
      1000000 /* 1 sec max delay */};
  TPerfServer::DoneCallback* doneCallback_{nullptr};
};

// A factory that creates StaticCwnd congestion controllers with a preset
// config for cwnd value and the rtt source for updating the pacing rate
class TperfStaticCwndCongestionControllerFactory
    : public CongestionControllerFactory {
 public:
  ~TperfStaticCwndCongestionControllerFactory() override = default;

  explicit TperfStaticCwndCongestionControllerFactory(
      uint64_t cwndInBytes,
      const std::string& pacerIntervalSource)
      : cwndInBytes_(cwndInBytes) {
    if (pacerIntervalSource == "mrtt") {
      pacerIntervalSource_ =
          StaticCwndCongestionController::PacerIntervalSource::MinRtt;
    } else if (pacerIntervalSource == "srtt") {
      pacerIntervalSource_ =
          StaticCwndCongestionController::PacerIntervalSource::SmoothedRtt;
    } else if (pacerIntervalSource == "lrtt") {
      pacerIntervalSource_ =
          StaticCwndCongestionController::PacerIntervalSource::LatestRtt;
    } else if (pacerIntervalSource != "std::nullopt") {
      throw std::runtime_error(
          fmt::format(
              "Invalid pacer interval source: {}. Valid values are mrtt, srtt, lrtt, std::nullopt for min rtt, smoothed rtt, latest rtt, and no pacing respectively.",
              pacerIntervalSource));
    }
  }

  std::unique_ptr<CongestionController> makeCongestionController(
      QuicConnectionStateBase& conn,
      CongestionControlType type) override {
    if (type != CongestionControlType::StaticCwnd) {
      throw std::runtime_error(
          fmt::format(
              "TperfStaticCwndCongestionControllerFactory cannot construct a congestion controller of type {}",
              congestionControlTypeToString(type)));
    }
    return std::make_unique<StaticCwndCongestionController>(
        conn, cwndInBytes_, pacerIntervalSource_);
  }

 private:
  StaticCwndCongestionController::CwndInBytes cwndInBytes_;
  StaticCwndCongestionController::PacerIntervalSource pacerIntervalSource_;
};

class TPerfServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~TPerfServerTransportFactory() override = default;

  TPerfServerTransportFactory(
      uint64_t blockSize,
      uint32_t numStreams,
      uint64_t maxBytesPerStream,
      uint32_t burstDeadlineMs,
      uint64_t maxPacingRate,
      std::string qloggerPath,
      std::string pacingObserver,
      TPerfServer::DoneCallback* doneCallback,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      std::shared_ptr<quic::CongestionControllerFactory> ccFactory,
      quic::BatchWriterFactoryOverride batchWriterFactoryOverride)
      : blockSize_(blockSize),
        numStreams_(numStreams),
        maxBytesPerStream_(maxBytesPerStream),
        burstDeadlineMs_(burstDeadlineMs),
        maxPacingRate_(maxPacingRate),
        qloggerPath_(std::move(qloggerPath)),
        pacingObserver_(std::move(pacingObserver)),
        doneCallback_(doneCallback),
        ctx_(std::move(ctx)),
        ccFactory_(std::move(ccFactory)),
        batchWriterFactoryOverride_(std::move(batchWriterFactoryOverride)) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      const quic::SocketAddress&,
      QuicVersion) noexcept override {
    MVCHECK_EQ(evb, sock->getEventBase());
    auto serverHandler = std::make_unique<ServerStreamHandler>(
        evb,
        blockSize_,
        numStreams_,
        maxBytesPerStream_,
        *sock,
        burstDeadlineMs_,
        maxPacingRate_,
        doneCallback_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), serverHandler.get(), serverHandler.get(), ctx_);
    transport->setCongestionControllerFactory(ccFactory_);
    if (batchWriterFactoryOverride_) {
      transport->setBatchWriterFactoryOverride(batchWriterFactoryOverride_);
    }
    if (!qloggerPath_.empty()) {
      auto qlogger = std::make_shared<FileQLogger>(
          VantagePoint::Server,
          kHTTP3ProtocolType,
          qloggerPath_,
          true /* prettyJson*/,
          true /* streaming */);
      transport->setQLogger(std::move(qlogger));
      setPacingObserver(qlogger, transport.get(), pacingObserver_);
    } else {
      std::shared_ptr<FileQLogger> qlogger = nullptr;
      setPacingObserver(qlogger, transport.get(), pacingObserver_);
    }
    transport->setOopsLogger(oopsLogger_.get());

    serverHandler->setQuicSocket(transport);
    handlers_.push_back(std::move(serverHandler));
    return transport;
  }

 private:
  void setPacingObserver(
      std::shared_ptr<FileQLogger>& qlogger,
      quic::QuicServerTransport* transport,
      const std::string& pacingObserverType) {
    if (pacingObserverType == "time") {
      transport->addObserver(
          std::make_shared<FixedBucketPacingObserver>(qlogger, 300ms));
    } else if (pacingObserverType == "rtt") {
      transport->addObserver(
          std::make_shared<RttBucketPacingObserver>(
              qlogger, *transport->getState()));
    } else if (pacingObserverType == "ack") {
      transport->addObserver(
          std::make_shared<PerUpdatePacingObserver>(qlogger));
    }
  }

  std::unique_ptr<proto_oops::GlogOopsLogger> oopsLogger_{
      std::make_unique<proto_oops::GlogOopsLogger>()};
  std::vector<std::unique_ptr<ServerStreamHandler>> handlers_;
  uint64_t blockSize_;
  uint32_t numStreams_;
  uint64_t maxBytesPerStream_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;
  std::string qloggerPath_;
  std::string pacingObserver_;
  TPerfServer::DoneCallback* doneCallback_{nullptr};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  std::shared_ptr<quic::CongestionControllerFactory> ccFactory_;
  quic::BatchWriterFactoryOverride batchWriterFactoryOverride_;
};

TPerfServer::TPerfServer(
    const std::string& host,
    uint16_t port,
    uint64_t blockSize,
    uint64_t writesPerLoop,
    quic::CongestionControlType congestionControlType,
    bool gso,
    uint32_t maxCwndInMss,
    bool pacing,
    uint32_t numStreams,
    uint64_t maxBytesPerStream,
    uint32_t maxReceivePacketSize,
    bool useInplaceWrite,
    bool overridePacketSize,
    double latencyFactor,
    bool useAckReceiveTimestamps,
    bool useDraft02AckReceiveTimestamps,
    bool advertiseLegacyAckReceiveTimestamps,
    bool sendDraft02AckReceiveTimestamps,
    uint32_t maxAckReceiveTimestampsToSend,
    bool useL4sEcn,
    bool readEcn,
    uint32_t dscp,
    uint32_t numServerWorkers,
    uint32_t burstDeadlineMs,
    uint64_t maxPacingRate,
    bool logAppRateLimited,
    bool logLoss,
    bool logRttSample,
    TPerfUdpGsoZerocopyConfig udpGsoZerocopyConfig,
    std::string qloggerPath,
    const std::string& pacingObserver,
    DoneCallback* doneCallback,
    StaticCwndConfig staticCwndConfig)
    : host_(host),
      port_(port),
      writeStats_(std::make_shared<TPerfWriteStats>()),
      acceptObserver_(
          std::make_unique<TPerfAcceptObserver>(
              logAppRateLimited,
              logLoss,
              logRttSample)),
      latencyFactor_(latencyFactor),
      useAckReceiveTimestamps_(useAckReceiveTimestamps),
      useDraft02AckReceiveTimestamps_(useDraft02AckReceiveTimestamps),
      advertiseLegacyAckReceiveTimestamps_(advertiseLegacyAckReceiveTimestamps),
      sendDraft02AckReceiveTimestamps_(sendDraft02AckReceiveTimestamps),
      maxAckReceiveTimestampsToSend_(maxAckReceiveTimestampsToSend),
      useL4sEcn_(useL4sEcn),
      readEcn_(readEcn),
      dscp_(dscp),
      numServerWorkers_(numServerWorkers),
      burstDeadlineMs_(burstDeadlineMs),
      maxPacingRate_(maxPacingRate),
      udpGsoZerocopyConfig_(udpGsoZerocopyConfig) {
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(fizz::CryptoUtils::init(err), err);
  eventBase_.setName("tperf_server");
  quic::TransportSettings settings;
  if (useInplaceWrite && gso) {
    settings.dataPathType = DataPathType::ContinuousMemory;
  } else {
    settings.dataPathType = DataPathType::ChainedMemory;
  }
  settings.maxCwndInMss = maxCwndInMss;
  settings.writeConnectionDataPacketsLimit = writesPerLoop;
  settings.defaultCongestionController = congestionControlType;
  settings.pacingEnabled = pacing;
  if (pacing) {
    settings.pacingTickInterval = 200us;
    settings.writeLimitRttFraction = 0;
  }

  if (gso) {
    settings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
    settings.maxBatchSize = writesPerLoop;
  }
  settings.maxRecvPacketSize = maxReceivePacketSize;
  settings.canIgnorePathMTU = overridePacketSize;
  settings.copaDeltaParam = latencyFactor_;
  // `--use_draft02_*` implies requesting timestamps and so populates the
  // local config; the flag alone would be a no-op.
  if (useAckReceiveTimestamps_ || useDraft02AckReceiveTimestamps_) {
    MVLOG_INFO << " Using ACK receive timestamps on server"
               << " (legacy=" << advertiseLegacyAckReceiveTimestamps_
               << " draft02=" << useDraft02AckReceiveTimestamps_ << ")";
    settings.maybeAckReceiveTimestampsConfigSentToPeer = {
        .maxReceiveTimestampsPerAck = maxAckReceiveTimestampsToSend_,
        .receiveTimestampsExponent = kDefaultReceiveTimestampsExponent};
    settings.enableIetfAckReceiveTimestamps = useDraft02AckReceiveTimestamps_;
    settings.advertiseLegacyAckReceiveTimestamps =
        advertiseLegacyAckReceiveTimestamps_;
    settings.sendDraft02AckReceiveTimestamps = sendDraft02AckReceiveTimestamps_;
  }

  if (useL4sEcn_) {
    settings.enableEcnOnEgress = true;
    settings.useL4sEcn = true;
    settings.minBurstPackets = 1;
    settings.ccaConfig.onlyGrowCwndWhenLimited = true;
    settings.ccaConfig.leaveHeadroomForCwndLimited = true;
  }

  settings.readEcnOnIngress = readEcn_;
  settings.dscpValue = dscp_;

  if (udpGsoZerocopyConfig_.enabled && udpGsoZerocopyConfig_.inplace) {
    batchWriterFactoryOverride_ =
        [udpGsoZerocopyConfig = udpGsoZerocopyConfig_,
         writeStats = writeStats_](
            const quic::QuicBatchingMode& /*batchingMode*/,
            uint32_t batchSize,
            DataPathType dataPathType,
            QuicConnectionStateBase& conn,
            bool gsoSupported) -> BatchWriterPtr {
      if (udpGsoZerocopyConfig.enabled && udpGsoZerocopyConfig.inplace &&
          gsoSupported && dataPathType == DataPathType::ContinuousMemory) {
        BatchWriterPtr writer(new UdpGsoZerocopyInplaceBatchWriter(
            conn, batchSize, udpGsoZerocopyConfig, writeStats));
        if (!udpGsoZerocopyConfig.perWriteStats) {
          return writer;
        }
        return wrapBatchWriterWithTiming(std::move(writer), writeStats);
      }
      // Fall through to the default factory.
      return nullptr;
    };
  }

  auto serverCtx = quic::test::createServerCtx();
  serverCtx->setClock(std::make_shared<fizz::SystemClock>());
  std::shared_ptr<quic::CongestionControllerFactory> ccFactory;
  if (congestionControlType == quic::CongestionControlType::StaticCwnd) {
    ccFactory = std::make_shared<TperfStaticCwndCongestionControllerFactory>(
        staticCwndConfig.staticCwndInBytes,
        staticCwndConfig.pacerIntervalSource);
  } else {
    ccFactory = std::make_shared<ServerCongestionControllerFactory>();
  }
  quic::ServerOptions options;
  options.transportSettings = std::move(settings);
  server_ = std::make_unique<quic::ThreadedQuicServer>(
      std::move(options),
      std::make_unique<TPerfServerTransportFactory>(
          blockSize,
          numStreams,
          maxBytesPerStream,
          burstDeadlineMs_,
          maxPacingRate_,
          std::move(qloggerPath),
          pacingObserver,
          doneCallback,
          serverCtx,
          ccFactory,
          batchWriterFactoryOverride_));
}

void TPerfServer::start() {
  // Create a SocketAddress and the default or passed in host.
  quic::SocketAddress addr1(host_.c_str(), port_);
  addr1.setFromHostPort(host_, port_);
  server_->bind(addr1, numServerWorkers_);
  if (udpGsoZerocopyConfig_.enabled && udpGsoZerocopyConfig_.inplace) {
    auto result = server_->server().enableZeroCopy();
    if (result.hasError()) {
      server_->shutdown();
      throw std::runtime_error(
          fmt::format(
              "QuicServer::enableZeroCopy failed: {}", result.error().message));
    }
    MVLOG_INFO << "tperf server enabled MSG_ZEROCOPY for inplace data path";
  }
  for (auto evb : server_->getWorkerEvbs()) {
    server_->server().addAcceptObserver(evb, acceptObserver_.get());
  }
  server_->start();
  MVLOG_INFO << "tperf server started at: " << addr1.describe();
  scheduleWriteStatsLog();
  eventBase_.loopForever();
}

void TPerfServer::maybeLogWriteStats() {
  if (!writeStats_) {
    return;
  }
  // The listener-fd MSG_ZEROCOPY kernel counter snapshot (added in the
  // prerequisite folly diff) is published by the inplace batch writer on
  // each successful ZC send, from the worker thread that owns the listener
  // socket — see publishListenerZeroCopySnapshot. The getZeroCopy* getters
  // back onto plain uint64_t fields whose ZeroCopyFdBookkeeping contract
  // requires single-EventBase access, so reading them from this (main)
  // thread would be a data race; instead we just log whatever the worker
  // already deposited under the writeStats mutex.
  writeStats_->maybeLog();
  scheduleWriteStatsLog();
}

void TPerfServer::scheduleWriteStatsLog() {
  eventBase_.runAfterDelay(
      [this]() { maybeLogWriteStats(); },
      /*milliseconds=*/1000);
}

} // namespace quic::tperf
