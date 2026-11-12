/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__) && !defined(ANDROID)

#include <folly/IPAddress.h>
#include <folly/MacAddress.h>
#include <folly/SocketAddress.h>
#include <folly/container/F14Set.h>
#include <folly/io/IOBuf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/Optional.h>
#include <quic/xsk/xsk_lib.h>
#include <queue>
#include <stdexcept>
#include <utility>

namespace facebook::xdpsocket {

enum class SendResult : uint8_t {
  SUCCESS = 0,
  NO_FREE_DESCRIPTORS = 1,
};

enum class FlushResult : uint8_t {
  SUCCESS = 0,
  FAILED_SENDTO = 1,
};

struct XskBuffer {
  void* buffer; // points to the beginning of the payload, after the headers
  uint32_t frameIndex;
  uint16_t payloadLength; // to be set by the caller
};

struct SharedState {
  explicit SharedState(uint32_t numOwners) {
    freeUmemFrames.resize(numOwners);
  }

  [[nodiscard]] bool allInitialized() const {
    return sharedUmemAddr && sharedCxMap && (sharedXskFd >= 0);
  }

  [[nodiscard]] bool allUninitialized() const {
    return !sharedUmemAddr && !sharedCxMap && (sharedXskFd == -1);
  }

  // It is legal for the members to be un-initialized when passed to an
  // XskSender. The members are initialized by the primary XskSender (the one
  // with an ownerId of 0).
  //
  // What must hold though, is that either all members are initialized, or
  // std::nullopt are.
  void* sharedUmemAddr{nullptr};
  void* sharedCxMap{nullptr};
  int sharedXskFd{-1};

  uint32_t crConsumerIndex{0};
  std::mutex cxRingMutex;
  std::vector<std::queue<uint32_t>> freeUmemFrames;
};

struct XskSenderConfig {
  uint32_t numFrames;
  uint32_t frameSize;
  uint32_t batchSize;
  uint32_t ownerId;
  uint32_t numOwners;
  folly::MacAddress localMac;
  folly::MacAddress gatewayMac;
  bool zeroCopyEnabled;
  bool useNeedWakeup;

  // Request HW UDP checksum offload via XDP_TXMD_FLAGS_CHECKSUM. The actual
  // behavior is gated on the running kernel supporting AF_XDP TX metadata
  // (Linux kernel >= 6.8); on older kernels this is silently a no-op. Set
  // this knob to false to A/B test against the software-checksum baseline
  // at runtime.
  bool useChecksumOffload{false};

  std::shared_ptr<SharedState> sharedState;

  // Set this to true if we're using one AF_XDP socket per thread. This
  // will ensure that we do no locking apart from UMEM sharing use cases.
  bool xskPerThread{false};
};

class XskSender {
 public:
  explicit XskSender(XskSenderConfig xskSenderConfig)
      : xskSenderConfig_(std::move(xskSenderConfig)) {
    MVCHECK(
        xskSenderConfig_.sharedState,
        "You must provide a shared state to the XskSender.");
    MVCHECK(
        xskSenderConfig_.sharedState->allInitialized() ||
            xskSenderConfig_.sharedState->allUninitialized(),
        "All elements must either be initialized or uninitialized.");
    if (xskSenderConfig_.sharedState->allUninitialized()) {
      MVCHECK(
          isPrimaryOwner(),
          "The shared state must be initialized by the primary XskSender "
              << "(the one with an ownerId of 0)");
    }
    uint32_t startingFrameIndex =
        getNumFramesPerOwner() * xskSenderConfig_.ownerId;
    uint32_t endingFrameIndex = startingFrameIndex + getNumFramesPerOwner() - 1;
    for (uint32_t i = startingFrameIndex; i <= endingFrameIndex; i++) {
      freeUmemIndices_.push(i);
    }
  }

  ~XskSender();

  quic::Optional<XskBuffer> getXskBuffer(bool isIpV6);

  void writeXskBuffer(
      const XskBuffer& xskBuffer,
      const quic::SocketAddress& peer,
      const quic::SocketAddress& src);

  // Return a buffer to the free list without writing it out to
  // the network
  void returnBuffer(const XskBuffer& xskBuffer);

  SendResult writeUdpPacket(
      const quic::SocketAddress& peer,
      const quic::SocketAddress& src,
      const void* data,
      uint16_t len);

  SendResult writeUdpPacket(
      const quic::SocketAddress& peer,
      const quic::SocketAddress& src,
      std::unique_ptr<folly::IOBuf>& data,
      uint16_t len);

  quic::Expected<void, std::runtime_error> init();

  quic::Expected<void, std::runtime_error> bind(int queueId);

  FlushResult flush();

 private:
  void initAddresses(
      const folly::MacAddress& localMac,
      const folly::MacAddress& gatewayMac);

  void writeUdpPacketScaffoldingToBuffer(
      char* buffer,
      const quic::SocketAddress& peer,
      const quic::SocketAddress& src,
      uint16_t payloadLength);

  void writeUdpPacketToBuffer(
      char* buffer,
      const quic::SocketAddress& peer,
      const quic::SocketAddress& src,
      const void* data,
      uint16_t len);

  // Writes the xsk_tx_metadata header at the start of `frameStart`. Must
  // only be called when checksumOffloadEnabled_ is true.
  void writeTxMetadata(
      char* frameStart,
      const quic::SocketAddress& peer,
      uint16_t udpPayloadLength);

  quic::Expected<void, std::runtime_error> initXdpSocket();

  xdp_desc* getTxDescriptor();

  quic::Optional<uint32_t> getFreeUmemIndex();

  void getFreeUmemFrames();

  void getFreeFramesFromSharedState();

  uint32_t getOwnerForFrame(uint32_t frameIndex);

  uint32_t getNumFramesPerOwner();

  bool isPrimaryOwner();

  std::queue<uint32_t> freeUmemIndices_;

  XskSenderConfig xskSenderConfig_;

  // True if the running kernel and configuration both support requesting
  // XDP_TXMD_FLAGS_CHECKSUM. Determined at init() time.
  bool checksumOffloadEnabled_{false};

  // Bytes reserved at the head of every UMEM frame for an xsk_tx_metadata
  // header. 0 when checksumOffloadEnabled_ is false.
  uint32_t txMetadataLen_{0};

  uint32_t numPacketsSentInBatch_{0};

  // We are the producer for the TX ring
  uint32_t txProducerIndex_{0};

  void* umemArea_{nullptr};
  void* txMap_{nullptr};
  void* cxMap_{nullptr};
  int xskFd_{-1};
  xdp_mmap_offsets xskOffsets_;

  ethhdr ethhdr_{};
  iphdr iphdr_{};
  ipv6hdr ipv6hdr_{};

  std::mutex m_;
};

} // namespace facebook::xdpsocket

#endif
