/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <array>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/MvfstLogging.h>
#include <quic/logging/FileQLogger.h>
#include <quic/observer/SocketObserverTypes.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>
#include <quic/server/ThreadedQuicServer.h>
#include <quic/tools/tperf/TperfHugePageArena.h>

namespace quic::tperf {

// Per-server aggregate counters for the UDP MSG_ZEROCOPY inplace batch
// writer. Shared via std::shared_ptr<TPerfWriteStats>, constructed once by
// TPerfServer and threaded through the batch writer factory override into
// every per-write writer instance.
//
// Trimmed to the inplace-specific counter set (the non-inplace MSG_ZEROCOPY
// backend is intentionally not part of this diff). 8 generic write-latency
// fields + 7 inplace-specific fields. Also carries snapshot fields for the
// folly per-listener-fd MSG_ZEROCOPY kernel counters (exposed by
// folly::AsyncUDPSocket in the prerequisite diff) so maybeLog() can publish
// kernel-side completion vs kernel-copied vs kill-switch state alongside
// the userspace submission counters.
class TPerfWriteStats {
 public:
  // Per-batch-write sample passed to recordWrite. Grouped into a struct so
  // adjacent same-type fields can't be swapped at the call site
  // (bugprone-easily-swappable-parameters).
  struct WriteSample {
    uint64_t durationUs{0};
    ssize_t ret{0};
    int errnoValue{0};
    uint64_t bufferedPackets{0};
    uint64_t bufferedBytes{0};
  };

  void recordWrite(const WriteSample& sample) {
    writeCalls_.fetch_add(1, std::memory_order_relaxed);
    totalDurationUs_.fetch_add(sample.durationUs, std::memory_order_relaxed);
    // Atomic max via CAS loop.
    uint64_t prevMax = maxDurationUs_.load(std::memory_order_relaxed);
    while (sample.durationUs > prevMax &&
           !maxDurationUs_.compare_exchange_weak(
               prevMax,
               sample.durationUs,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
    totalBufferedPackets_.fetch_add(
        sample.bufferedPackets, std::memory_order_relaxed);
    totalBufferedBytes_.fetch_add(
        sample.bufferedBytes, std::memory_order_relaxed);
    durationBuckets_[durationBucket(sample.durationUs)].fetch_add(
        1, std::memory_order_relaxed);
    if (sample.ret < 0) {
      // Rare path: writeErrnos_ map still needs mutex.
      writeErrors_.fetch_add(1, std::memory_order_relaxed);
      std::scoped_lock lock(mutex_);
      writeErrnos_[sample.errnoValue]++;
    }
  }

  // Snapshot of the per-listener-fd MSG_ZEROCOPY kernel counters exposed by
  // folly::AsyncUDPSocket. Grouped into a struct so adjacent uint64_t fields
  // can't be swapped at the call site
  // (bugprone-easily-swappable-parameters).
  struct ListenerKernelSnapshot {
    uint64_t completionsZc{0};
    uint64_t completionsCopied{0};
    uint64_t sendsAckedZc{0};
    uint64_t sendsAckedMaybeCopied{0};
    bool zcEnabled{false};
  };

  // Publish a snapshot of the per-listener-fd MSG_ZEROCOPY kernel counters
  // exposed by folly::AsyncUDPSocket. Called from the worker thread by
  // UdpGsoZerocopyInplaceBatchWriter::write() after each successful ZC send
  // (see publishListenerZeroCopySnapshot in TperfServer.cpp); the listener
  // socket is the one where the per-fd ZeroCopyFdBookkeeping lives
  // (QuicServerWorker installs it via setZeroCopy(true)). The main
  // EventBase later reads these fields under mutex_ from maybeLog(); this
  // function is the writer side of that publish/consume pair. Single-fd
  // snapshot: all four counters and the kill-switch flag come from the
  // same AsyncUDPSocket instance. Last-writer-wins across workers when
  // --num_server_worker > 1.
  void recordListenerZeroCopySnapshot(const ListenerKernelSnapshot& snap) {
    std::lock_guard<std::mutex> lock(mutex_);
    listenerKernelCompletionsZc_ = snap.completionsZc;
    listenerKernelCompletionsCopied_ = snap.completionsCopied;
    listenerKernelSendsAckedZc_ = snap.sendsAckedZc;
    listenerKernelSendsAckedMaybeCopied_ = snap.sendsAckedMaybeCopied;
    listenerKernelZeroCopyEnabled_ = snap.zcEnabled;
    listenerKernelSnapshotValid_ = true;
  }

  void maybeLog() {
    // Snapshot all counters under the lock, then release before formatting
    // and logging — the worker thread calls recordWrite() on every batch
    // send and contends on the same mutex; blocking it for the duration of
    // string formatting and MVLOG_INFO once per second is unnecessary.
    uint64_t writeCallsSnap{};
    uint64_t writeErrorsSnap{};
    uint64_t totalBufferedPacketsSnap{};
    uint64_t totalBufferedBytesSnap{};
    uint64_t maxDurationUsSnap{};
    uint64_t avgDurationUs{};
    std::array<uint64_t, 12> durationBucketsSnap{};
    std::map<int, uint64_t> writeErrnosSnap;
    uint64_t udpZerocopyInplaceZcSendsSnap{};
    uint64_t udpZerocopyInplaceFallbackSendsSnap{};
    uint64_t udpZerocopyInplaceZcFailedSendsSnap{};
    uint64_t udpZerocopyInplacePoolAcquiresSnap{};
    uint64_t udpZerocopyInplacePoolAllocationsSnap{};
    uint64_t udpZerocopyInplacePoolReleasesSnap{};
    uint64_t udpZerocopyInplaceOutstandingSlabsSnap{};
    uint64_t udpZerocopyHugepageHeapFallbacksSnap{};
    bool hugepageArenaValidSnap{};
    HugePageArenaInfo hugepageArenaSnap;
    bool listenerKernelSnapshotValidSnap{};
    uint64_t listenerKernelCompletionsZcSnap{};
    uint64_t listenerKernelCompletionsCopiedSnap{};
    uint64_t listenerKernelSendsAckedZcSnap{};
    uint64_t listenerKernelSendsAckedMaybeCopiedSnap{};
    bool listenerKernelZeroCopyEnabledSnap{};
    // Hot counters are atomic — load them without holding mutex_.
    writeCallsSnap = writeCalls_.load(std::memory_order_relaxed);
    if (writeCallsSnap == 0 || writeCallsSnap == lastLoggedWriteCalls_) {
      return;
    }
    lastLoggedWriteCalls_ = writeCallsSnap;
    writeErrorsSnap = writeErrors_.load(std::memory_order_relaxed);
    totalBufferedPacketsSnap =
        totalBufferedPackets_.load(std::memory_order_relaxed);
    totalBufferedBytesSnap =
        totalBufferedBytes_.load(std::memory_order_relaxed);
    maxDurationUsSnap = maxDurationUs_.load(std::memory_order_relaxed);
    avgDurationUs =
        totalDurationUs_.load(std::memory_order_relaxed) / writeCallsSnap;
    for (size_t i = 0; i < durationBuckets_.size(); ++i) {
      durationBucketsSnap[i] =
          durationBuckets_[i].load(std::memory_order_relaxed);
    }
    udpZerocopyInplaceZcSendsSnap =
        udpZerocopyInplaceZcSends_.load(std::memory_order_relaxed);
    udpZerocopyInplaceFallbackSendsSnap =
        udpZerocopyInplaceFallbackSends_.load(std::memory_order_relaxed);
    udpZerocopyInplaceZcFailedSendsSnap =
        udpZerocopyInplaceZcFailedSends_.load(std::memory_order_relaxed);
    udpZerocopyInplacePoolAcquiresSnap =
        udpZerocopyInplacePoolAcquires_.load(std::memory_order_relaxed);
    udpZerocopyInplacePoolAllocationsSnap =
        udpZerocopyInplacePoolAllocations_.load(std::memory_order_relaxed);
    udpZerocopyInplacePoolReleasesSnap =
        udpZerocopyInplacePoolReleases_.load(std::memory_order_relaxed);
    udpZerocopyInplaceOutstandingSlabsSnap =
        udpZerocopyInplaceOutstandingSlabs_.load(std::memory_order_relaxed);
    udpZerocopyHugepageHeapFallbacksSnap =
        udpZerocopyHugepageHeapFallbacks_.load(std::memory_order_relaxed);
    {
      // Mutex only for grouped-update fields + errno maps.
      std::lock_guard<std::mutex> lock(mutex_);
      writeErrnosSnap = writeErrnos_;
      hugepageArenaValidSnap = hugepageArenaValid_;
      hugepageArenaSnap = hugepageArena_;
      listenerKernelSnapshotValidSnap = listenerKernelSnapshotValid_;
      listenerKernelCompletionsZcSnap = listenerKernelCompletionsZc_;
      listenerKernelCompletionsCopiedSnap = listenerKernelCompletionsCopied_;
      listenerKernelSendsAckedZcSnap = listenerKernelSendsAckedZc_;
      listenerKernelSendsAckedMaybeCopiedSnap =
          listenerKernelSendsAckedMaybeCopied_;
      listenerKernelZeroCopyEnabledSnap = listenerKernelZeroCopyEnabled_;
    }
    std::ostringstream durationHist;
    bool first = true;
    for (size_t i = 0; i < durationBucketsSnap.size(); ++i) {
      if (durationBucketsSnap[i] == 0) {
        continue;
      }
      if (!first) {
        durationHist << ",";
      }
      first = false;
      durationHist << kDurationBucketLabels[i] << ":" << durationBucketsSnap[i];
    }
    std::ostringstream udpZerocopyStats;
    if (udpZerocopyInplaceZcSendsSnap || udpZerocopyInplaceFallbackSendsSnap ||
        udpZerocopyInplaceZcFailedSendsSnap) {
      udpZerocopyStats << " udp_zc_inplace_zc_sends="
                       << udpZerocopyInplaceZcSendsSnap
                       << " udp_zc_inplace_fallback_sends="
                       << udpZerocopyInplaceFallbackSendsSnap
                       << " udp_zc_inplace_zc_failed_sends="
                       << udpZerocopyInplaceZcFailedSendsSnap
                       << " udp_zc_inplace_pool_acquires="
                       << udpZerocopyInplacePoolAcquiresSnap
                       << " udp_zc_inplace_pool_allocations="
                       << udpZerocopyInplacePoolAllocationsSnap
                       << " udp_zc_inplace_pool_releases="
                       << udpZerocopyInplacePoolReleasesSnap
                       << " udp_zc_inplace_outstanding_slabs="
                       << udpZerocopyInplaceOutstandingSlabsSnap;
    }
    std::ostringstream hugepageStats;
    if (hugepageArenaValidSnap) {
      hugepageStats << " udp_zc_hugepage_mode=" << hugepageArenaSnap.mode
                    << " udp_zc_hugepage_arena_bytes="
                    << hugepageArenaSnap.arenaBytes
                    << " udp_zc_hugepage_slab_stride="
                    << hugepageArenaSnap.slabStride
                    << " udp_zc_hugepage_slabs=" << hugepageArenaSnap.slabs
                    << " udp_zc_hugepage_backed_kb="
                    << hugepageArenaSnap.backedKb
                    << " udp_zc_hugepage_heap_fallbacks="
                    << udpZerocopyHugepageHeapFallbacksSnap;
    }
    std::ostringstream kernelStats;
    if (listenerKernelSnapshotValidSnap) {
      kernelStats << " udp_zc_kernel_completions_zc="
                  << listenerKernelCompletionsZcSnap
                  << " udp_zc_kernel_completions_copied="
                  << listenerKernelCompletionsCopiedSnap
                  << " udp_zc_kernel_sends_acked_zc="
                  << listenerKernelSendsAckedZcSnap
                  << " udp_zc_kernel_sends_acked_maybe_copied="
                  << listenerKernelSendsAckedMaybeCopiedSnap
                  << " udp_zc_kernel_enabled="
                  << (listenerKernelZeroCopyEnabledSnap ? 1 : 0);
    }
    MVLOG_INFO << "tperf batch write latency writes=" << writeCallsSnap
               << " errors=" << writeErrorsSnap
               << " packets=" << totalBufferedPacketsSnap
               << " bytes=" << totalBufferedBytesSnap
               << " avg_us=" << avgDurationUs << " max_us=" << maxDurationUsSnap
               << " duration_us={" << durationHist.str() << "}"
               << " errno={" << formatErrnos(writeErrnosSnap) << "}"
               << udpZerocopyStats.str() << hugepageStats.str()
               << kernelStats.str();
  }

  // Records a single batch sent by UdpGsoZerocopyInplaceBatchWriter. Exactly
  // one of {zcSend, fallbackSend, zcFailedSend} should be true.
  void recordUdpZerocopyInplaceWrite(
      bool zcSend,
      bool fallbackSend,
      bool zcFailedSend) {
    if (zcSend) {
      udpZerocopyInplaceZcSends_.fetch_add(1, std::memory_order_relaxed);
    }
    if (fallbackSend) {
      udpZerocopyInplaceFallbackSends_.fetch_add(1, std::memory_order_relaxed);
    }
    if (zcFailedSend) {
      udpZerocopyInplaceZcFailedSends_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  // Inplace slab pool bookkeeping: an acquire returns a slab to the writer
  // (either reused-from-idle-list or freshly allocated); a release returns
  // an in-flight slab back to the idle list after the bookkeeping fires the
  // ReleaseIOBufCallback.
  void recordUdpZerocopyInplacePoolAcquire(bool reused) {
    udpZerocopyInplacePoolAcquires_.fetch_add(1, std::memory_order_relaxed);
    if (!reused) {
      udpZerocopyInplacePoolAllocations_.fetch_add(
          1, std::memory_order_relaxed);
    }
    udpZerocopyInplaceOutstandingSlabs_.fetch_add(1, std::memory_order_relaxed);
  }

  void recordUdpZerocopyInplacePoolRelease() {
    udpZerocopyInplacePoolReleases_.fetch_add(1, std::memory_order_relaxed);
    // Saturating decrement via CAS: never underflow.
    uint64_t cur =
        udpZerocopyInplaceOutstandingSlabs_.load(std::memory_order_relaxed);
    while (cur > 0 &&
           !udpZerocopyInplaceOutstandingSlabs_.compare_exchange_weak(
               cur,
               cur - 1,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
  }

  // One-time description of a worker's huge-page slab arena, published by
  // TperfHugePageArena once it has mmap'd and pre-faulted its region.
  //
  // Last-writer-wins across workers, like the listener kernel snapshot: every
  // worker's arena is configured identically, so the published record is
  // representative rather than aggregate. `backedKb` is per-worker.
  void recordUdpZerocopyHugepageArena(const HugePageArenaInfo& info) {
    std::scoped_lock lock(mutex_);
    hugepageArena_ = info;
    hugepageArenaValid_ = true;
  }

  // A slab request that the arena could not satisfy and that fell back to a
  // malloc'd (4K-backed) slab. Non-zero means the column is no longer a pure
  // huge-page measurement — size up --udp_zerocopy_hugepage_bytes.
  void recordUdpZerocopyHugepageHeapFallback() {
    udpZerocopyHugepageHeapFallbacks_.fetch_add(1, std::memory_order_relaxed);
  }

  HugePageArenaInfo getUdpZerocopyHugepageArenaForTest() {
    std::scoped_lock lock(mutex_);
    return hugepageArena_;
  }

  bool getUdpZerocopyHugepageArenaValidForTest() {
    std::scoped_lock lock(mutex_);
    return hugepageArenaValid_;
  }

  uint64_t getUdpZerocopyHugepageHeapFallbacksForTest() {
    return udpZerocopyHugepageHeapFallbacks_.load(std::memory_order_relaxed);
  }

  // Test-only accessors.
  uint64_t getUdpZerocopyInplacePoolAcquiresForTest() {
    return udpZerocopyInplacePoolAcquires_.load(std::memory_order_relaxed);
  }

  uint64_t getUdpZerocopyInplacePoolReleasesForTest() {
    return udpZerocopyInplacePoolReleases_.load(std::memory_order_relaxed);
  }

  uint64_t getUdpZerocopyInplaceOutstandingSlabsForTest() {
    return udpZerocopyInplaceOutstandingSlabs_.load(std::memory_order_relaxed);
  }

  uint64_t getWriteCallsForTest() {
    return writeCalls_.load(std::memory_order_relaxed);
  }

  uint64_t getWriteErrorsForTest() {
    return writeErrors_.load(std::memory_order_relaxed);
  }

  uint64_t getTotalBufferedPacketsForTest() {
    return totalBufferedPackets_.load(std::memory_order_relaxed);
  }

  uint64_t getTotalBufferedBytesForTest() {
    return totalBufferedBytes_.load(std::memory_order_relaxed);
  }

  uint64_t getMaxDurationUsForTest() {
    return maxDurationUs_.load(std::memory_order_relaxed);
  }

  uint64_t getTotalDurationUsForTest() {
    return totalDurationUs_.load(std::memory_order_relaxed);
  }

  uint64_t getWriteErrnoCountForTest(int err) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = writeErrnos_.find(err);
    return it == writeErrnos_.end() ? 0 : it->second;
  }

  uint64_t getLastLoggedWriteCallsForTest() {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastLoggedWriteCalls_;
  }

  uint64_t getUdpZerocopyInplaceZcSendsForTest() {
    return udpZerocopyInplaceZcSends_.load(std::memory_order_relaxed);
  }

  uint64_t getUdpZerocopyInplaceFallbackSendsForTest() {
    return udpZerocopyInplaceFallbackSends_.load(std::memory_order_relaxed);
  }

  uint64_t getUdpZerocopyInplaceZcFailedSendsForTest() {
    return udpZerocopyInplaceZcFailedSends_.load(std::memory_order_relaxed);
  }

  ListenerKernelSnapshot getListenerKernelSnapshotForTest() {
    std::lock_guard<std::mutex> lock(mutex_);
    return ListenerKernelSnapshot{
        .completionsZc = listenerKernelCompletionsZc_,
        .completionsCopied = listenerKernelCompletionsCopied_,
        .sendsAckedZc = listenerKernelSendsAckedZc_,
        .sendsAckedMaybeCopied = listenerKernelSendsAckedMaybeCopied_,
        .zcEnabled = listenerKernelZeroCopyEnabled_};
  }

  bool getListenerKernelSnapshotValidForTest() {
    std::lock_guard<std::mutex> lock(mutex_);
    return listenerKernelSnapshotValid_;
  }

 private:
  static size_t durationBucket(uint64_t durationUs) {
    if (durationUs < 1) {
      return 0;
    }
    if (durationUs < 2) {
      return 1;
    }
    if (durationUs < 5) {
      return 2;
    }
    if (durationUs < 10) {
      return 3;
    }
    if (durationUs < 20) {
      return 4;
    }
    if (durationUs < 50) {
      return 5;
    }
    if (durationUs < 100) {
      return 6;
    }
    if (durationUs < 250) {
      return 7;
    }
    if (durationUs < 500) {
      return 8;
    }
    if (durationUs < 1000) {
      return 9;
    }
    if (durationUs < 5000) {
      return 10;
    }
    return 11;
  }

  static std::string formatErrnos(const std::map<int, uint64_t>& errnos) {
    std::ostringstream out;
    bool first = true;
    for (const auto& [err, count] : errnos) {
      if (!first) {
        out << ",";
      }
      first = false;
      out << err << ":" << count;
    }
    return out.str();
  }

  static constexpr std::array<const char*, 12> kDurationBucketLabels{
      "lt1",
      "1_2",
      "2_5",
      "5_10",
      "10_20",
      "20_50",
      "50_100",
      "100_250",
      "250_500",
      "500_1000",
      "1000_5000",
      "gte5000"};

  // Hot-path counters are std::atomic so the per-batch record methods
  // (called O(500K/s) combined across 8 workers during ZC saturation) do
  // not serialize on mutex_. mutex_ now only guards fields that update in
  // groups (listener kernel snapshot) or are rare-path maps (errno
  // histograms), plus the single-threaded lastLoggedWriteCalls_ read/write
  // in maybeLog. Prior single-mutex design produced ~3.7M/s lock acquires
  // on the inplace ZC pool path and was the dominant CPU cost in the
  // 2026-07-24 matrix.
  std::mutex mutex_;
  std::atomic<uint64_t> writeCalls_{0};
  uint64_t lastLoggedWriteCalls_{0}; // maybeLog only (single-threaded)
  std::atomic<uint64_t> writeErrors_{0};
  std::map<int, uint64_t> writeErrnos_; // guarded by mutex_
  std::atomic<uint64_t> totalDurationUs_{0};
  std::atomic<uint64_t> maxDurationUs_{0}; // updated via CAS-max
  std::atomic<uint64_t> totalBufferedPackets_{0};
  std::atomic<uint64_t> totalBufferedBytes_{0};
  std::array<std::atomic<uint64_t>, 12> durationBuckets_{};
  std::atomic<uint64_t> udpZerocopyInplaceZcSends_{0};
  std::atomic<uint64_t> udpZerocopyInplaceFallbackSends_{0};
  std::atomic<uint64_t> udpZerocopyInplaceZcFailedSends_{0};
  std::atomic<uint64_t> udpZerocopyInplacePoolAcquires_{0};
  std::atomic<uint64_t> udpZerocopyInplacePoolAllocations_{0};
  std::atomic<uint64_t> udpZerocopyInplacePoolReleases_{0};
  std::atomic<uint64_t> udpZerocopyInplaceOutstandingSlabs_{0};
  // Huge-page slab arena description (grouped update under mutex_) plus the
  // heap-fallback counter for slabs the arena could not back.
  bool hugepageArenaValid_{false};
  HugePageArenaInfo hugepageArena_;
  std::atomic<uint64_t> udpZerocopyHugepageHeapFallbacks_{0};
  // Listener-fd MSG_ZEROCOPY kernel counter snapshot (from
  // folly::AsyncUDPSocket accessors). Updated by TPerfServer via
  // recordListenerZeroCopySnapshot before each maybeLog emission. These
  // five fields are updated as a group under mutex_ so readers see a
  // consistent snapshot.
  bool listenerKernelSnapshotValid_{false};
  uint64_t listenerKernelCompletionsZc_{0};
  uint64_t listenerKernelCompletionsCopied_{0};
  uint64_t listenerKernelSendsAckedZc_{0};
  uint64_t listenerKernelSendsAckedMaybeCopied_{0};
  bool listenerKernelZeroCopyEnabled_{false};
};

// Configuration for the UDP MSG_ZEROCOPY inplace batch writer. Only the
// fields relevant to the inplace path are exposed; the broader
// non-inplace MSG_ZEROCOPY backend and the iouring/devmem backends live
// in separate diffs.
struct TPerfUdpGsoZerocopyConfig {
  bool enabled{false};
  uint64_t minBytes{1500};
  uint32_t poolBuffers{4096};
  // When true, route through UdpGsoZerocopyInplaceBatchWriter: mvfst encrypts
  // directly into pool-borrowed slabs (ContinuousMemory data path), the slab
  // is sent via writeChain+MSG_ZEROCOPY, and the per-fd ZeroCopyFdBookkeeping
  // installed by QuicServerWorker calls our release callback when the kernel
  // completion fires, returning the slab to the pool.
  bool inplace{false};
  // When false, the ZC path skips every per-write stats update (latency
  // timing, shared atomic counters, the mutex-guarded listener snapshot) so
  // its CPU cost is comparable with --tx_backend=udp, which records none.
  bool perWriteStats{true};
  // When true, slabs are carved out of a per-worker 2MB-huge-page arena
  // instead of folly::IOBuf::createCombined (malloc). Everything else about
  // the send path is identical to the plain inplace backend, so the two
  // backends isolate exactly one variable: the page size backing the
  // MSG_ZEROCOPY payload.
  //
  // Two effects are expected. (1) The kernel coalesces compound sub-pages
  // into a single skb frag in zerocopy_fill_skb_from_iter() and batches the
  // folio refcount adds, so a 64KB batch inside one 2MB page produces 1 frag
  // and ~2 refcount atomics instead of 16 frags and ~32 atomics — which also
  // collapses the per-send dma_map_page_attrs count by the same factor.
  // (2) A 2MB folio's _refcount is one cacheline shared by all 512
  // sub-pages, so arenas MUST be per-worker: two workers allocating from one
  // huge page would true-share that line. thread_local arenas give us that
  // for free.
  bool hugePages{false};
  // Per-worker huge-page arena size. Caps the number of live slabs a worker
  // can have to `hugePageBytes / slabStride` regardless of poolBuffers.
  uint64_t hugePageBytes{64ULL * 1024 * 1024};
};

} // namespace quic::tperf

namespace {

class TPerfObserver : public quic::LegacyObserver {
 public:
  using LegacyObserver::LegacyObserver;

  TPerfObserver(
      EventSet eventSet,
      bool logAppRateLimited,
      bool logLoss,
      bool logRttSample)
      : quic::LegacyObserver(eventSet),
        logAppRateLimited_(logAppRateLimited),
        logLoss_(logLoss),
        logRttSample_(logRttSample) {}

  void appRateLimited(
      quic::QuicSocketLite* /* socket */,
      const quic::SocketObserverInterface::
          AppLimitedEvent& /* appLimitedEvent */) override {
    if (logAppRateLimited_) {
      MVLOG_INFO << "appRateLimited detected";
    }
  }

  void packetLossDetected(
      quic::QuicSocketLite*, /* socket */
      const struct LossEvent& /* lossEvent */) override {
    if (logLoss_) {
      MVLOG_INFO << "packetLoss detected";
    }
  }

  void rttSampleGenerated(
      quic::QuicSocketLite*, /* socket */
      const PacketRTT& /* RTT sample */) override {
    if (logRttSample_) {
      MVLOG_INFO << "rttSample generated";
    }
  }

 private:
  bool logAppRateLimited_;
  bool logLoss_;
  bool logRttSample_;
};

/**
 * A helper acceptor observer that installs life cycle observers to
 * transport upon accept
 */
class TPerfAcceptObserver : public quic::AcceptObserver {
 public:
  TPerfAcceptObserver(bool logAppRateLimited, bool logLoss, bool logRttSample) {
    // Create an observer config, only enabling events we are interested in
    // receiving.
    quic::LegacyObserver::EventSet eventSet;
    eventSet.enable(
        quic::SocketObserverInterface::Events::appRateLimitedEvents,
        quic::SocketObserverInterface::Events::rttSamples,
        quic::SocketObserverInterface::Events::lossEvents);
    tperfObserver_ = std::make_unique<TPerfObserver>(
        eventSet, logAppRateLimited, logLoss, logRttSample);
  }

  void accept(quic::QuicTransportBase* transport) noexcept override {
    transport->addObserver(tperfObserver_.get());
  }

  void acceptorDestroy(quic::QuicServerWorker* /* worker */) noexcept override {
    MVLOG_INFO << "quic server worker destroyed";
  }

  void observerAttach(quic::QuicServerWorker* /* worker */) noexcept override {
    MVLOG_INFO << "TPerfAcceptObserver attached";
  }

  void observerDetach(quic::QuicServerWorker* /* worker */) noexcept override {
    MVLOG_INFO << "TPerfAcceptObserver detached";
  }

 private:
  std::unique_ptr<TPerfObserver> tperfObserver_;
};
} // namespace

namespace quic::tperf {

class TPerfServer {
 public:
  class DoneCallback {
   public:
    virtual ~DoneCallback() = default;
    virtual void onDone(const std::string& msg) = 0;
  };

  // Configuration for the StaticCwndCongestionController if it's the chosed
  // CongestionController type.
  struct StaticCwndConfig {
    StaticCwndConfig(
        uint64_t staticCwndInBytes = quic::kInitCwndInMss *
            quic::kDefaultUDPSendPacketLen,
        const std::string& pacerIntervalSource = "mrtt")
        : staticCwndInBytes(staticCwndInBytes),
          pacerIntervalSource(pacerIntervalSource) {}

    uint64_t staticCwndInBytes;
    const std::string& pacerIntervalSource;
  };

  explicit TPerfServer(
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
      DoneCallback* doneCallback = nullptr,
      StaticCwndConfig staticCwndConfig = StaticCwndConfig());

  void start();

 private:
  void maybeLogWriteStats();
  void scheduleWriteStatsLog();

  std::string host_;
  uint16_t port_;
  folly::EventBase eventBase_;
  std::shared_ptr<TPerfWriteStats> writeStats_;
  std::unique_ptr<TPerfAcceptObserver> acceptObserver_;
  std::unique_ptr<quic::ThreadedQuicServer> server_;
  double latencyFactor_;
  bool useAckReceiveTimestamps_{false};
  bool useDraft02AckReceiveTimestamps_{false};
  bool advertiseLegacyAckReceiveTimestamps_{true};
  bool sendDraft02AckReceiveTimestamps_{true};
  uint32_t maxAckReceiveTimestampsToSend_;
  bool useL4sEcn_{false};
  bool readEcn_{false};
  uint32_t dscp_;
  uint32_t numServerWorkers_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;
  TPerfUdpGsoZerocopyConfig udpGsoZerocopyConfig_;
  quic::BatchWriterFactoryOverride batchWriterFactoryOverride_;
};

} // namespace quic::tperf
