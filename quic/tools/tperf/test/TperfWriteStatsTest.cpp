/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfServer.h>

#include <folly/portability/GTest.h>

#include <cerrno>

namespace quic::tperf::test {

// Acquire/release accounting for the inplace MSG_ZEROCOPY slab pool. Every
// path that returns a slab to the pool's idle list must record a release;
// without this, the outstanding-slabs counter drifts upward over the
// process lifetime even though the pool is correctly reusing slabs.
TEST(TperfWriteStatsTest, OutstandingSlabsBalancedAcrossReturnPaths) {
  TPerfWriteStats stats;

  // Simulate: writer acquires three slabs from the pool. Two come back via
  // the kernel-completion path (releaseIOBuf -> returnIdle -> release), one
  // comes back via the writer destructor's direct returnIdle path because
  // the slab never made it to the kernel (e.g. fallback-only batch).
  stats.recordUdpZerocopyInplacePoolAcquire(/*reused=*/false);
  stats.recordUdpZerocopyInplacePoolAcquire(/*reused=*/false);
  stats.recordUdpZerocopyInplacePoolAcquire(/*reused=*/true);
  EXPECT_EQ(stats.getUdpZerocopyInplaceOutstandingSlabsForTest(), 3);

  stats.recordUdpZerocopyInplacePoolRelease();
  stats.recordUdpZerocopyInplacePoolRelease();
  stats.recordUdpZerocopyInplacePoolRelease();

  // After every acquired slab has been released — whether via the kernel
  // path or the destructor path — the outstanding counter must be zero.
  EXPECT_EQ(stats.getUdpZerocopyInplaceOutstandingSlabsForTest(), 0);
  EXPECT_EQ(stats.getUdpZerocopyInplacePoolAcquiresForTest(), 3);
  EXPECT_EQ(stats.getUdpZerocopyInplacePoolReleasesForTest(), 3);
}

// The release counter must never underflow the outstanding-slabs counter:
// recording more releases than acquires (e.g. a stale kernel completion
// after the writer is gone) must saturate at zero, not wrap.
TEST(TperfWriteStatsTest, OutstandingSlabsSaturatesAtZero) {
  TPerfWriteStats stats;

  stats.recordUdpZerocopyInplacePoolAcquire(/*reused=*/false);
  stats.recordUdpZerocopyInplacePoolRelease();
  stats.recordUdpZerocopyInplacePoolRelease();

  EXPECT_EQ(stats.getUdpZerocopyInplaceOutstandingSlabsForTest(), 0);
}

// recordWrite must accumulate per-batch fields onto the running totals and
// bucket the duration; covers the WriteSample struct call-site shape.
TEST(TperfWriteStatsTest, RecordWriteAccumulatesBatchFields) {
  TPerfWriteStats stats;

  // Two successful batches followed by one failing batch (errno=EAGAIN).
  stats.recordWrite(
      TPerfWriteStats::WriteSample{
          .durationUs = 15,
          .ret = 1200,
          .errnoValue = 0,
          .bufferedPackets = 4,
          .bufferedBytes = 1200});
  stats.recordWrite(
      TPerfWriteStats::WriteSample{
          .durationUs = 25,
          .ret = 1500,
          .errnoValue = 0,
          .bufferedPackets = 5,
          .bufferedBytes = 1500});
  stats.recordWrite(
      TPerfWriteStats::WriteSample{
          .durationUs = 5,
          .ret = -1,
          .errnoValue = EAGAIN,
          .bufferedPackets = 0,
          .bufferedBytes = 0});

  // All three batches counted; only the EAGAIN one is a writeError and only
  // its errno is tracked.
  EXPECT_EQ(stats.getWriteCallsForTest(), 3);
  EXPECT_EQ(stats.getWriteErrorsForTest(), 1);
  EXPECT_EQ(stats.getWriteErrnoCountForTest(EAGAIN), 1);
  EXPECT_EQ(stats.getWriteErrnoCountForTest(0), 0);
  // Buffered totals come from successful batches; the failed batch passes 0.
  EXPECT_EQ(stats.getTotalBufferedPacketsForTest(), 9);
  EXPECT_EQ(stats.getTotalBufferedBytesForTest(), 2700);
  // Duration is accumulated for every batch (including the failed one).
  EXPECT_EQ(stats.getTotalDurationUsForTest(), 45);
  EXPECT_EQ(stats.getMaxDurationUsForTest(), 25);

  // maybeLog drains the snapshot and updates lastLoggedWriteCalls_ to
  // writeCalls_; calling it a second time with no new writes must be a
  // no-op (lastLoggedWriteCalls_ already equals writeCalls_, so the
  // early-return fires before any other state changes).
  stats.maybeLog();
  EXPECT_EQ(stats.getLastLoggedWriteCallsForTest(), 3);
  stats.maybeLog();
  EXPECT_EQ(stats.getLastLoggedWriteCallsForTest(), 3);

  // A fresh recordWrite re-arms maybeLog.
  stats.recordWrite(
      TPerfWriteStats::WriteSample{
          .durationUs = 7,
          .ret = 800,
          .errnoValue = 0,
          .bufferedPackets = 2,
          .bufferedBytes = 800});
  EXPECT_EQ(stats.getWriteCallsForTest(), 4);
  stats.maybeLog();
  EXPECT_EQ(stats.getLastLoggedWriteCallsForTest(), 4);
}

// On ZC send failure folly never invokes the release callback (see
// AsyncUDPSocket::writeChain contract). recordUdpZerocopyInplaceWrite with
// zcFailedSend=true is the writer's matching observability hook; verify
// the counter increments independent of the success/fallback counters so a
// reviewer reading the log can tell apart "ZC succeeded", "fallback to
// GSO", and "ZC attempted but failed".
TEST(TperfWriteStatsTest, ZcFailedSendsAreCountedSeparately) {
  TPerfWriteStats stats;

  // 1 ZC success, 2 fallbacks, 3 ZC failures.
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/true, /*fallbackSend=*/false, /*zcFailedSend=*/false);
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/false, /*fallbackSend=*/true, /*zcFailedSend=*/false);
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/false, /*fallbackSend=*/true, /*zcFailedSend=*/false);
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/false, /*fallbackSend=*/false, /*zcFailedSend=*/true);
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/false, /*fallbackSend=*/false, /*zcFailedSend=*/true);
  stats.recordUdpZerocopyInplaceWrite(
      /*zcSend=*/false, /*fallbackSend=*/false, /*zcFailedSend=*/true);

  // Each category counted into its own counter, no cross-talk: a regression
  // that swapped which boolean increments which counter (or that lumped
  // failed sends into the success path) would fail one of these EXPECTs.
  EXPECT_EQ(stats.getUdpZerocopyInplaceZcSendsForTest(), 1);
  EXPECT_EQ(stats.getUdpZerocopyInplaceFallbackSendsForTest(), 2);
  EXPECT_EQ(stats.getUdpZerocopyInplaceZcFailedSendsForTest(), 3);
}

// The listener-fd kernel snapshot must store the most recent snapshot
// last-writer-wins (the periodic log path reads it; the worker thread
// publishes it). Verify both the freshly-published values land in the
// accessor and that the second publish fully overwrites the first.
TEST(TperfWriteStatsTest, RecordListenerSnapshotAcceptsStruct) {
  TPerfWriteStats stats;

  // No snapshot has been published yet — valid flag must be false.
  EXPECT_FALSE(stats.getListenerKernelSnapshotValidForTest());

  stats.recordListenerZeroCopySnapshot(
      TPerfWriteStats::ListenerKernelSnapshot{
          .completionsZc = 100,
          .completionsCopied = 5,
          .sendsAckedZc = 95,
          .sendsAckedMaybeCopied = 10,
          .zcEnabled = true});

  EXPECT_TRUE(stats.getListenerKernelSnapshotValidForTest());
  auto first = stats.getListenerKernelSnapshotForTest();
  EXPECT_EQ(first.completionsZc, 100);
  EXPECT_EQ(first.completionsCopied, 5);
  EXPECT_EQ(first.sendsAckedZc, 95);
  EXPECT_EQ(first.sendsAckedMaybeCopied, 10);
  EXPECT_TRUE(first.zcEnabled);

  // Overwriting with a fresh snapshot must be the last-writer-wins
  // semantic the worker thread relies on for the periodic log: every
  // field, including the kill-switch bool, must reflect the second
  // publish, not a max-of or a partial merge.
  stats.recordListenerZeroCopySnapshot(
      TPerfWriteStats::ListenerKernelSnapshot{
          .completionsZc = 200,
          .completionsCopied = 7,
          .sendsAckedZc = 193,
          .sendsAckedMaybeCopied = 14,
          .zcEnabled = false});

  auto second = stats.getListenerKernelSnapshotForTest();
  EXPECT_EQ(second.completionsZc, 200);
  EXPECT_EQ(second.completionsCopied, 7);
  EXPECT_EQ(second.sendsAckedZc, 193);
  EXPECT_EQ(second.sendsAckedMaybeCopied, 14);
  EXPECT_FALSE(second.zcEnabled);
  EXPECT_TRUE(stats.getListenerKernelSnapshotValidForTest());
}

// The huge-page arena description is published once per worker and read by
// the periodic log. `backedKb` is the field that distinguishes a real
// huge-page run from one that silently faulted in as 4K, so it must survive
// the publish intact rather than being derived or dropped.
TEST(TperfWriteStatsTest, HugepageArenaRecordIsLastWriterWins) {
  TPerfWriteStats stats;

  EXPECT_FALSE(stats.getUdpZerocopyHugepageArenaValidForTest());

  const HugePageArenaInfo thpArena{
      .mode = "thp",
      .arenaBytes = 64ULL * 1024 * 1024,
      .slabStride = 32768,
      .slabs = 2048,
      .backedKb = 65536};
  stats.recordUdpZerocopyHugepageArena(thpArena);

  EXPECT_TRUE(stats.getUdpZerocopyHugepageArenaValidForTest());
  EXPECT_EQ(stats.getUdpZerocopyHugepageArenaForTest(), thpArena);

  // A second worker publishing a hugetlb-backed arena fully replaces the
  // record — no per-field merge that could report "hugetlb" alongside the
  // first worker's THP byte counts.
  const HugePageArenaInfo hugetlbArena{
      .mode = "hugetlb",
      .arenaBytes = 2ULL * 1024 * 1024,
      .slabStride = 65536,
      .slabs = 32,
      .backedKb = 2048};
  stats.recordUdpZerocopyHugepageArena(hugetlbArena);

  EXPECT_EQ(stats.getUdpZerocopyHugepageArenaForTest(), hugetlbArena);
}

// Slabs the arena could not satisfy fall back to malloc. That is survivable
// but it means the column is no longer a pure huge-page measurement, so the
// count has to be visible rather than silently absorbed into the pool's
// generic allocation counter.
TEST(TperfWriteStatsTest, HugepageHeapFallbacksAreCountedSeparately) {
  TPerfWriteStats stats;

  EXPECT_EQ(stats.getUdpZerocopyHugepageHeapFallbacksForTest(), 0);

  stats.recordUdpZerocopyInplacePoolAcquire(/*reused=*/false);
  stats.recordUdpZerocopyHugepageHeapFallback();
  stats.recordUdpZerocopyHugepageHeapFallback();

  // Heap fallbacks are still pool acquisitions, so they must not perturb the
  // acquire/outstanding accounting the inplace pool relies on.
  EXPECT_EQ(stats.getUdpZerocopyHugepageHeapFallbacksForTest(), 2);
  EXPECT_EQ(stats.getUdpZerocopyInplacePoolAcquiresForTest(), 1);
  EXPECT_EQ(stats.getUdpZerocopyInplaceOutstandingSlabsForTest(), 1);
}

} // namespace quic::tperf::test
