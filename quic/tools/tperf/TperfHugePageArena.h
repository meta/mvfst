/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/CppAttributes.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace quic::tperf {

// One-time description of a worker's huge-page slab arena. `backedKb` is read
// back out of /proc/self/smaps (AnonHugePages for the THP path, Hugetlb for
// the MAP_HUGETLB path) — it is the only thing that proves the arena is
// actually huge-page backed rather than silently faulted in as 4K, which
// would make the whole measurement meaningless.
struct HugePageArenaInfo {
  // "hugetlb" (MAP_HUGETLB), "thp" (MADV_HUGEPAGE), or "none".
  std::string mode{"none"};
  uint64_t arenaBytes{0};
  uint64_t slabStride{0};
  uint64_t slabs{0};
  uint64_t backedKb{0};

  bool operator==(const HugePageArenaInfo&) const = default;
};

// Huge-page arena backing MSG_ZEROCOPY slabs for tperf's
// `udp_gso_zerocopy_hugepage` TX backend. One arena per worker thread: a 2MB
// folio's _refcount is a single cacheline shared by all 512 sub-pages, so two
// workers allocating out of one arena would true-share that line and
// reintroduce exactly the contention the backend exists to remove.
//
// Allocation is a bump pointer plus a free list, both of which only ever run
// on the owning worker thread — the class is deliberately not thread-safe.
//
// Slab stride is rounded up to a power of two so it evenly divides the 2MB
// page. Combined with a 2MB-aligned base, that guarantees no slab ever
// straddles a page boundary, which is what keeps the kernel's compound-page
// coalescing in zerocopy_fill_skb_from_iter() emitting one frag per batch
// instead of one per 4K.
//
// The mapping is deliberately never unmapped. Slabs can still be referenced
// by in-flight kernel sends when a worker thread exits, and unmapping
// underneath the NIC would be a use-after-free that the completion path
// cannot detect.
class TperfHugePageArena {
 public:
  static constexpr size_t kHugePageBytes = 2ULL * 1024 * 1024;

  TperfHugePageArena() = default;
  TperfHugePageArena(const TperfHugePageArena&) = delete;
  TperfHugePageArena& operator=(const TperfHugePageArena&) = delete;
  TperfHugePageArena(TperfHugePageArena&&) = delete;
  TperfHugePageArena& operator=(TperfHugePageArena&&) = delete;
  ~TperfHugePageArena() = default;

  // Power-of-two allocation stride for a slab of `slabCapacity` bytes, or 0
  // when no stride can divide the huge page evenly (capacity above 2MB).
  // Every non-zero result divides kHugePageBytes.
  [[nodiscard]] static size_t computeSlabStride(size_t slabCapacity);

  // Rounds `arenaBytes` up to a whole number of huge pages, with a floor of
  // one page.
  [[nodiscard]] static size_t roundArenaBytes(size_t arenaBytes);

  // Maps and pre-faults the arena. Returns false when the region could not be
  // huge-page backed at all, or when `slabCapacity` is too large for a
  // power-of-two stride to fit inside a 2MB page; callers fall back to
  // malloc'd slabs. Callable once per instance.
  bool init(size_t arenaBytes, size_t slabCapacity);

  // Next free slab, or null once the arena is exhausted.
  [[nodiscard]] void* FOLLY_NULLABLE allocSlab();

  // Returns a slab previously handed out by allocSlab(). `mem` must be inside
  // the arena.
  void freeSlab(void* mem);

  [[nodiscard]] bool contains(const void* mem) const;

  [[nodiscard]] bool ready() const {
    return base_ != nullptr;
  }

  [[nodiscard]] const HugePageArenaInfo& info() const {
    return info_;
  }

 private:
  bool initAttempted_{false};
  char* base_{nullptr};
  size_t bumpSlabs_{0};
  HugePageArenaInfo info_;
  std::vector<void*> freeList_;
};

} // namespace quic::tperf
