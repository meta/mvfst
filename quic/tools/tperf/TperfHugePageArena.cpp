/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfHugePageArena.h>

#include <folly/String.h>
#include <folly/lang/Bits.h>
#include <quic/common/MvfstLogging.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>

// Old glibcs do not export these; values are fixed kernel UAPI
// (include/uapi/linux/prctl.h).
#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE 41
#endif
#ifndef PR_GET_THP_DISABLE
#define PR_GET_THP_DISABLE 42
#endif
#endif

namespace quic::tperf {

namespace {

#ifdef __linux__
// MAP_HUGETLB needs pages reserved up front (vm.nr_hugepages). The kernel
// returns a 2MB-aligned mapping for us.
void* mapHugeTlb(size_t bytes) {
  void* mem = ::mmap(
      nullptr,
      bytes,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
      -1,
      0);
  return mem == MAP_FAILED ? nullptr : mem;
}

// PR_SET_THP_DISABLE is per-mm and inherited across fork/exec, and plenty of
// container and devserver environments set it. When it is set, MADV_HUGEPAGE
// is accepted but the VMA reports THPeligible: 0 and faults in as 4K — i.e.
// the backend silently measures the thing it exists to avoid measuring. Clear
// it for this process before mapping. Idempotent, so per-worker arenas can
// each call it.
//
// Caveat when reading results: this is process-wide, so on a host that had
// the flag set every other allocation (jemalloc's heap included) also becomes
// THP-eligible, not just the slab arena. Linux 6.17's
// PR_THP_DISABLE_EXCEPT_ADVISED would scope this to madvised regions only;
// it returns EINVAL on 6.16, so the blunt clear is the only option for now.
void clearProcessThpDisable() {
  if (::prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 1) {
    return;
  }
  if (::prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) != 0) {
    MVLOG_ERROR << "tperf hugepage: PR_SET_THP_DISABLE(0) failed: "
                << folly::errnoStr(errno)
                << "; THP is disabled for this process and the arena will be "
                << "4K-backed";
    return;
  }
  MVLOG_INFO << "tperf hugepage: cleared inherited PR_SET_THP_DISABLE so the "
             << "slab arena can be backed by 2MB pages";
}

// THP fallback for hosts without a reserved hugetlb pool. mmap guarantees no
// alignment beyond a page, and the kernel will not back a region with huge
// pages unless it is 2MB-aligned, so over-map by one page and trim both ends.
void* FOLLY_NULLABLE mapTransparent(size_t bytes) {
  constexpr size_t kPage = TperfHugePageArena::kHugePageBytes;
  clearProcessThpDisable();
  const size_t slop = bytes + kPage;
  auto* raw = static_cast<char*>(::mmap(
      nullptr,
      slop,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0));
  if (raw == MAP_FAILED) {
    return nullptr;
  }
  char* const aligned =
      raw + ((kPage - reinterpret_cast<uintptr_t>(raw) % kPage) % kPage);
  if (aligned > raw) {
    ::munmap(raw, static_cast<size_t>(aligned - raw));
  }
  char* const tail = aligned + bytes;
  const auto tailBytes = static_cast<size_t>((raw + slop) - tail);
  if (tailBytes > 0) {
    ::munmap(tail, tailBytes);
  }
  // MADV_HUGEPAGE must precede the first touch — a region already faulted in
  // as 4K is only collapsed later, asynchronously, by khugepaged.
  if (::madvise(aligned, bytes, MADV_HUGEPAGE) != 0) {
    MVLOG_ERROR << "tperf hugepage: madvise(MADV_HUGEPAGE) failed: "
                << folly::errnoStr(errno)
                << " (arena will likely be 4K-backed)";
  }
  return aligned;
}

// Reads back how much of the mapping at `base` the kernel actually backed
// with huge pages. Without this a misconfigured host silently produces a 4K
// run labelled as a huge-page run. Returns 0 if smaps cannot be parsed.
uint64_t queryHugePageBackedKb(const void* base) {
  std::ifstream smaps("/proc/self/smaps");
  if (!smaps.is_open()) {
    return 0;
  }
  const auto target = reinterpret_cast<uintptr_t>(base);
  bool inTargetMapping = false;
  uint64_t backedKb = 0;
  std::string line;
  while (std::getline(smaps, line)) {
    // Mapping header lines lead with the address range ("7f..-7f.. rw-p ...");
    // detail lines are "Key:   <n> kB". Only a header has a '-' before its
    // first space.
    const auto firstSpace = line.find(' ');
    const auto dash = line.find('-');
    if (dash != std::string::npos &&
        (firstSpace == std::string::npos || dash < firstSpace)) {
      inTargetMapping = (std::strtoull(line.c_str(), nullptr, 16) == target);
      continue;
    }
    if (!inTargetMapping) {
      continue;
    }
    // THP reports AnonHugePages; MAP_HUGETLB reports Hugetlb. A mapping is
    // only ever one or the other, so summing is safe.
    if (line.starts_with("AnonHugePages:") || line.starts_with("Hugetlb:")) {
      backedKb += std::strtoull(
          line.c_str() + line.find(':') + 1, nullptr, /*base=*/10);
    }
  }
  return backedKb;
}
#else
void* FOLLY_NULLABLE mapHugeTlb(size_t /*bytes*/) {
  return nullptr;
}

void* FOLLY_NULLABLE mapTransparent(size_t /*bytes*/) {
  return nullptr;
}

uint64_t queryHugePageBackedKb(const void* /*base*/) {
  return 0;
}
#endif

} // namespace

size_t TperfHugePageArena::computeSlabStride(size_t slabCapacity) {
  if (slabCapacity == 0 || slabCapacity > kHugePageBytes) {
    return 0;
  }
  // nextPowTwo of anything in (0, 2MB] is itself in [4K, 2MB] after the floor,
  // and every power of two in that range divides a 2MB page evenly.
  return folly::nextPowTwo(std::max<size_t>(slabCapacity, 4096));
}

size_t TperfHugePageArena::roundArenaBytes(size_t arenaBytes) {
  const size_t floored = std::max<size_t>(arenaBytes, kHugePageBytes);
  return ((floored + kHugePageBytes - 1) / kHugePageBytes) * kHugePageBytes;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool TperfHugePageArena::init(size_t arenaBytes, size_t slabCapacity) {
  MVCHECK(!initAttempted_);
  initAttempted_ = true;

  const size_t stride = computeSlabStride(slabCapacity);
  if (stride == 0) {
    MVLOG_ERROR << "tperf hugepage: slab capacity " << slabCapacity
                << " does not fit a power-of-two stride inside a "
                << kHugePageBytes << "-byte page; falling back to malloc";
    return false;
  }
  const size_t bytes = roundArenaBytes(arenaBytes);

  const char* mode = "hugetlb";
  base_ = static_cast<char*>(mapHugeTlb(bytes));
  if (!base_) {
    base_ = static_cast<char*>(mapTransparent(bytes));
    if (!base_) {
      MVLOG_ERROR << "tperf hugepage: could not map a " << bytes
                  << "-byte huge-page arena; falling back to malloc";
      return false;
    }
    mode = "thp";
  }
  MVCHECK(reinterpret_cast<uintptr_t>(base_) % kHugePageBytes == 0);
  // Pre-fault so the huge pages are allocated now rather than mid-benchmark,
  // and so the smaps readback below covers the whole arena.
  std::memset(base_, 0, bytes);

  info_ = HugePageArenaInfo{
      .mode = mode,
      .arenaBytes = bytes,
      .slabStride = stride,
      .slabs = bytes / stride,
      .backedKb = queryHugePageBackedKb(base_)};

  // The mapping succeeded but the kernel declined to back it with huge pages
  // (THP disabled system-wide, the 2MB size set to "never" under
  // /sys/kernel/mm/transparent_hugepage/hugepages-2048kB/enabled, or memory
  // too fragmented to compact). The run will still work, it just measures 4K
  // pages under a huge-page label — say so rather than let a whole matrix
  // column be quietly invalid.
  if (info_.backedKb == 0) {
    MVLOG_ERROR << "tperf hugepage: arena mapped in " << info_.mode
                << " mode but NOTHING is huge-page backed (backed_kb=0); this "
                << "run measures 4K pages. Check "
                << "/sys/kernel/mm/transparent_hugepage/enabled and "
                << "hugepages-2048kB/enabled, or reserve hugetlb pages via "
                << "vm.nr_hugepages.";
  } else {
    MVLOG_INFO << "tperf hugepage: arena mode=" << info_.mode
               << " bytes=" << info_.arenaBytes
               << " slab_stride=" << info_.slabStride
               << " slabs=" << info_.slabs << " backed_kb=" << info_.backedKb;
  }
  return true;
}

void* FOLLY_NULLABLE TperfHugePageArena::allocSlab() {
  if (!freeList_.empty()) {
    void* const mem = freeList_.back();
    freeList_.pop_back();
    return mem;
  }
  if (!base_ || bumpSlabs_ >= info_.slabs) {
    return nullptr;
  }
  return base_ + (bumpSlabs_++ * info_.slabStride);
}

void TperfHugePageArena::freeSlab(void* mem) {
  MVCHECK(contains(mem));
  freeList_.push_back(mem);
}

bool TperfHugePageArena::contains(const void* mem) const {
  const auto* p = static_cast<const char*>(mem);
  return base_ && p >= base_ && p < base_ + info_.arenaBytes;
}

} // namespace quic::tperf
