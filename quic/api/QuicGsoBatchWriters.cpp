/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicGsoBatchWriters.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>

namespace {
// There is a known problem in the CloningScheduler that it may write a packet
// that's a few bytes larger than the original packet. If the original packet is
// a full packet, then the new packet will be larger than a full packet.
constexpr size_t kPacketSizeViolationTolerance = 10;
} // namespace

namespace quic {

GSOInplacePacketBatchWriter::GSOInplacePacketBatchWriter(
    QuicConnectionStateBase& conn,
    size_t maxPackets)
    : conn_(conn), maxPackets_(maxPackets) {}

void GSOInplacePacketBatchWriter::reset() {
  if (lastPacketEnd_) {
    auto& buf = conn_.bufAccessor->buf();
    MVCHECK(
        lastPacketEnd_ >= buf->data() && lastPacketEnd_ <= buf->tail(),
        "lastPacketEnd_=" << (uintptr_t)lastPacketEnd_
                          << " data=" << (uintptr_t)buf->data()
                          << " tail=" << (uintptr_t)buf->tail());
    // Bytes past lastPacketEnd_ are a packet that needsFlush() deferred to the
    // next batch.
    const auto remaining = static_cast<size_t>(buf->tail() - lastPacketEnd_);
    MVCHECK(
        remaining <= conn_.udpSendPacketLen ||
            (nextPacketSize_ && remaining == nextPacketSize_),
        "remaining=" << remaining << ", pktLimit=" << conn_.udpSendPacketLen
                     << ", nextPacketSize_=" << nextPacketSize_);
    if (remaining >= conn_.udpSendPacketLen + kPacketSizeViolationTolerance) {
      MVLOG_ERROR
          << "Remaining buffer contents larger than udpSendPacketLen by "
          << (remaining - conn_.udpSendPacketLen);
    }
    if (remaining) {
      const auto consumed = lastPacketEnd_ - buf->data();
      buf->trimStart(consumed);
      buf->retreat(consumed);
      MVCHECK_EQ(buf->headroom(), 0, "headroom=" << buf->headroom());
    } else {
      buf->clear();
    }
  }
  lastPacketEnd_ = nullptr;
  prevSize_ = 0;
  numPackets_ = 0;
  nextPacketSize_ = 0;
}

bool GSOInplacePacketBatchWriter::needsFlush(size_t size) {
  auto shouldFlush = prevSize_ && size > prevSize_;
  if (shouldFlush) {
    nextPacketSize_ = size;
  }
  return shouldFlush;
}

bool GSOInplacePacketBatchWriter::append(
    BufPtr&& /*buf*/,
    size_t size,
    const quic::SocketAddress& /* addr */,
    QuicAsyncUDPSocket* /* sock */) {
  MVCHECK(!needsFlush(size));
  auto& buf = conn_.bufAccessor->buf();
  if (!lastPacketEnd_) {
    MVCHECK(prevSize_ == 0 && numPackets_ == 0);
    prevSize_ = size;
    lastPacketEnd_ = buf->tail();
    numPackets_ = 1;
    // When maxPackets_ == 1 the buffer is sized for a single packet, so the
    // first packet already fills the batch and must be flushed. Without this,
    // the next packet would be built starting at the full buffer's tail and
    // overrun it.
    return numPackets_ == maxPackets_;
  }

  MVCHECK(prevSize_ && prevSize_ >= size);
  ++numPackets_;
  lastPacketEnd_ = buf->tail();
  if (prevSize_ > size || numPackets_ == maxPackets_) {
    return true;
  }
  return false;
}

ssize_t GSOInplacePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const quic::SocketAddress& address) {
  MVCHECK(lastPacketEnd_);
  auto& buf = conn_.bufAccessor->buf();
  MVCHECK(!buf->isChained());
  const int gsoVal = numPackets_ > 1 ? static_cast<int>(prevSize_) : 0;
  auto options =
      QuicAsyncUDPSocket::WriteOptions(gsoVal, false /*zerocopyVal*/);
  options.txTime = txTime_;
  iovec vec{buf->writableData(), size()};
  return sock.writeGSO(address, &vec, 1, options);
}

bool GSOInplacePacketBatchWriter::empty() const {
  return numPackets_ == 0;
}

size_t GSOInplacePacketBatchWriter::size() const {
  if (empty()) {
    return 0;
  }
  MVCHECK(lastPacketEnd_);
  MVCHECK(
      lastPacketEnd_ >= conn_.bufAccessor->data() &&
      lastPacketEnd_ <= conn_.bufAccessor->tail());
  size_t ret = lastPacketEnd_ - conn_.bufAccessor->data();
  return ret;
}

SendmmsgGSOInplacePacketBatchWriter::SendmmsgGSOInplacePacketBatchWriter(
    QuicConnectionStateBase& conn,
    size_t maxBufs)
    : conn_(conn), maxBufs_(maxBufs) {
  MVCHECK_LE(maxBufs_, kMaxIovecs, "maxBufs provided is too high");
}

bool SendmmsgGSOInplacePacketBatchWriter::empty() const {
  return (currSize_ == 0);
}

size_t SendmmsgGSOInplacePacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgGSOInplacePacketBatchWriter::reset() {
  if (lastPacketEnd_) {
    auto& buf = conn_.bufAccessor->buf();
    MVCHECK(lastPacketEnd_ >= buf->data() && lastPacketEnd_ <= buf->tail());
    if (lastPacketEnd_ == buf->tail()) {
      buf->clear();
    } else {
      const auto consumed = lastPacketEnd_ - buf->data();
      buf->trimStart(consumed);
      buf->retreat(consumed);
    }
  }
  lastPacketEnd_ = nullptr;
  buffers_.clear();
  indexToOptions_.clear();
  indexToAddr_.clear();
  addrToMostRecentIndex_.clear();

  currBufs_ = 0;
  currSize_ = 0;
}

bool SendmmsgGSOInplacePacketBatchWriter::append(
    BufPtr&& /* buf */,
    size_t size,
    const quic::SocketAddress& addr,
    QuicAsyncUDPSocket* /*unused*/) {
  auto& buf = conn_.bufAccessor->buf();

  lastPacketEnd_ = buf->tail();

  iovec vec{};
  vec.iov_base = (void*)(buf->tail() - size);
  vec.iov_len = size;

  currBufs_++;
  currSize_ += size;

  if (addrToMostRecentIndex_.contains(addr)) {
    uint32_t index = addrToMostRecentIndex_[addr];
    /*
     * In order to use GSO, it MUST be the case that all packets except
     * potentially the last are of the same size. The last packet, if it
     * has a different size, MUST be smaller than the other packets. It
     * CANNOT be larger.
     */
    if (size <= buffers_[index].back().iov_len) {
      /*
       * It's okay for the last packet to be smaller, but we need to
       * check if the packets preceding it are all of the same size.
       * It suffices to check the size equality of just the first and last
       * packets in the series.
       */
      if (buffers_[index].front().iov_len == buffers_[index].back().iov_len) {
        indexToOptions_[index].gso = buffers_[index].front().iov_len;
        buffers_[index].push_back(vec);
        // Flush if we reach maxBufs_
        return (currBufs_ == maxBufs_);
      }
    }
  }

  /*
   * If we've hit this point, then we need to create new entries in
   * buffers_, indexToAddr_, indexToOptions_, and addrToMostRecentIndex_.
   */
  uint32_t index = buffers_.size();
  addrToMostRecentIndex_[addr] = index;
  indexToAddr_.push_back(addr);
  // For now, set GSO to 0. We'll set it to a non-zero value if we append
  // to this series
  indexToOptions_.emplace_back(0, false);
  buffers_.push_back({vec});

  // Flush if we reach maxBufs_
  return (currBufs_ == maxBufs_);
}

ssize_t SendmmsgGSOInplacePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const quic::SocketAddress& /*unused*/) {
  MVCHECK_GT(buffers_.size(), 0);

  int ret = 0;

  if (buffers_.size() == 1) {
    ret = (currBufs_ > 1) ? sock.writeGSO(
                                indexToAddr_[0],
                                buffers_[0].data(),
                                buffers_[0].size(),
                                indexToOptions_[0])
                          : sock.write(indexToAddr_[0], buffers_[0].data(), 1);
  } else {
    std::array<iovec, kMaxIovecs> iovecs{};
    std::array<size_t, kMaxIovecs> messageSizes{};

    uint32_t currentIovecIndex = 0;
    for (uint32_t i = 0; i < buffers_.size(); i++) {
      messageSizes[i] = buffers_[i].size();
      for (auto j : buffers_[i]) {
        iovecs[currentIovecIndex] = j;
        currentIovecIndex++;
      }
    }

    ret = sock.writemGSO(
        AddressRange(indexToAddr_.data(), indexToAddr_.size()),
        &iovecs[0],
        &messageSizes[0],
        buffers_.size(),
        indexToOptions_.data());

    if (ret > 0) {
      if (static_cast<size_t>(ret) == buffers_.size()) {
        ret = currSize_;
      } else {
        // this is a partial write - we just need to
        // return a different number than currSize_
        ret = 0;
      }
    }
  }

  return ret;
}

} // namespace quic
