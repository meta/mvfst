/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfHugePageArena.h>

#include <folly/portability/GTest.h>

#include <set>

namespace quic::tperf::test {

namespace {
constexpr size_t kHugePage = TperfHugePageArena::kHugePageBytes;
// Representative mvfst ContinuousMemory batch buffer size: not a power of
// two, which is exactly the case the stride rounding exists to handle.
constexpr size_t kBatchBufferBytes = 23552;
} // namespace

// The whole point of the huge-page backend is that a batch lands in one
// compound page so the kernel emits a single skb frag for it. That only holds
// if the slab stride divides the 2MB page evenly — otherwise slabs walk out of
// phase with page boundaries and later ones straddle two pages.
TEST(TperfHugePageArenaTest, SlabStrideDividesHugePageEvenly) {
  const std::vector<size_t> capacities{
      1, 4096, 4097, kBatchBufferBytes, 65536, 65537, kHugePage};

  for (const auto capacity : capacities) {
    const auto stride = TperfHugePageArena::computeSlabStride(capacity);
    EXPECT_GE(stride, capacity) << "capacity=" << capacity;
    EXPECT_LE(stride, kHugePage) << "capacity=" << capacity;
    EXPECT_EQ(kHugePage % stride, 0u) << "capacity=" << capacity;
  }
}

// Strides are power-of-two rounded with a 4K floor, so a sub-page slab still
// gets a whole page and a 23552-byte batch buffer gets 32K.
TEST(TperfHugePageArenaTest, SlabStrideRoundsUpToPowerOfTwo) {
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(1), 4096u);
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(4096), 4096u);
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(4097), 8192u);
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(kBatchBufferBytes), 32768u);
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(kHugePage), kHugePage);
}

// A slab larger than a huge page can never satisfy the one-page invariant, so
// the arena refuses it and the caller falls back to malloc'd slabs rather than
// silently producing straddling slabs.
TEST(TperfHugePageArenaTest, SlabStrideRejectsCapacityOutsideOnePage) {
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(0), 0u);
  EXPECT_EQ(TperfHugePageArena::computeSlabStride(kHugePage + 1), 0u);
}

// Arena size is quantized to whole huge pages, with one page as the floor —
// a caller asking for 1 byte still gets a mappable region.
TEST(TperfHugePageArenaTest, ArenaBytesRoundUpToWholeHugePages) {
  EXPECT_EQ(TperfHugePageArena::roundArenaBytes(0), kHugePage);
  EXPECT_EQ(TperfHugePageArena::roundArenaBytes(1), kHugePage);
  EXPECT_EQ(TperfHugePageArena::roundArenaBytes(kHugePage), kHugePage);
  EXPECT_EQ(TperfHugePageArena::roundArenaBytes(kHugePage + 1), 2 * kHugePage);
  EXPECT_EQ(TperfHugePageArena::roundArenaBytes(5 * kHugePage), 5 * kHugePage);
}

// Live-arena invariant, and the reason the stride math above matters: every
// slab the arena hands out must lie entirely within a single 2MB page.
TEST(TperfHugePageArenaTest, NoSlabStraddlesAHugePageBoundary) {
  TperfHugePageArena arena;
  if (!arena.init(4 * kHugePage, kBatchBufferBytes)) {
    GTEST_SKIP() << "host cannot back a huge-page arena";
  }

  const auto& info = arena.info();
  ASSERT_GT(info.slabs, 0u);

  for (size_t i = 0; i < info.slabs; ++i) {
    void* const slab = arena.allocSlab();
    ASSERT_NE(slab, nullptr) << "slab " << i << " of " << info.slabs;
    const auto addr = reinterpret_cast<uintptr_t>(slab);
    // Same page at the first and last byte of the slab's stride.
    EXPECT_EQ(addr / kHugePage, (addr + info.slabStride - 1) / kHugePage)
        << "slab " << i << " straddles a huge-page boundary";
  }
}

// The arena is a fixed-size region: once every slab is handed out it must
// report exhaustion rather than walking off the end of the mapping. The pool
// treats null as "fall back to a malloc'd slab".
TEST(TperfHugePageArenaTest, AllocSlabExhaustsAtCapacityAndSlabsAreDistinct) {
  TperfHugePageArena arena;
  if (!arena.init(kHugePage, kBatchBufferBytes)) {
    GTEST_SKIP() << "host cannot back a huge-page arena";
  }

  const auto expectedSlabs = arena.info().slabs;
  ASSERT_EQ(expectedSlabs, kHugePage / arena.info().slabStride);

  std::set<void*> slabs;
  for (size_t i = 0; i < expectedSlabs; ++i) {
    void* const slab = arena.allocSlab();
    ASSERT_NE(slab, nullptr);
    EXPECT_TRUE(arena.contains(slab));
    slabs.insert(slab);
  }

  // Every slab is a distinct address, and the arena is now dry.
  EXPECT_EQ(slabs.size(), expectedSlabs);
  EXPECT_EQ(arena.allocSlab(), nullptr);
}

// Slabs dropped on a failed MSG_ZEROCOPY send come back through freeSlab.
// Without recycling, persistent send failures would drain the arena and
// permanently downgrade the run to malloc'd slabs.
TEST(TperfHugePageArenaTest, FreedSlabsAreHandedOutAgain) {
  TperfHugePageArena arena;
  if (!arena.init(kHugePage, kBatchBufferBytes)) {
    GTEST_SKIP() << "host cannot back a huge-page arena";
  }

  std::vector<void*> drained;
  while (void* slab = arena.allocSlab()) {
    drained.push_back(slab);
  }
  ASSERT_FALSE(drained.empty());
  ASSERT_EQ(arena.allocSlab(), nullptr);

  arena.freeSlab(drained.front());
  arena.freeSlab(drained.back());

  // Both recycled slabs come back before the arena reports dry again.
  const std::set<void*> expected{drained.front(), drained.back()};
  std::set<void*> recycled{arena.allocSlab(), arena.allocSlab()};
  EXPECT_EQ(recycled, expected);
  EXPECT_EQ(arena.allocSlab(), nullptr);
}

// contains() is what keeps the pool from feeding a malloc'd slab into the
// arena's free list when a run mixes both (arena exhausted -> heap fallback).
TEST(TperfHugePageArenaTest, ContainsRejectsMemoryOutsideTheArena) {
  TperfHugePageArena arena;
  if (!arena.init(kHugePage, kBatchBufferBytes)) {
    GTEST_SKIP() << "host cannot back a huge-page arena";
  }

  void* const slab = arena.allocSlab();
  ASSERT_NE(slab, nullptr);
  EXPECT_TRUE(arena.contains(slab));

  std::vector<char> heapBuf(kBatchBufferBytes);
  EXPECT_FALSE(arena.contains(heapBuf.data()));
  EXPECT_FALSE(arena.contains(nullptr));
}

// An uninitialized arena must look empty to the pool rather than handing back
// a pointer into a null mapping.
TEST(TperfHugePageArenaTest, UninitializedArenaIsNotReady) {
  TperfHugePageArena arena;

  EXPECT_FALSE(arena.ready());
  EXPECT_EQ(arena.allocSlab(), nullptr);
  EXPECT_FALSE(arena.contains(&arena));
  EXPECT_EQ(arena.info().mode, "none");
  EXPECT_EQ(arena.info().slabs, 0u);
}

} // namespace quic::tperf::test
