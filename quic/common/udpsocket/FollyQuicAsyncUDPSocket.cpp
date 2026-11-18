/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/async/AsyncSocketException.h>
#include <quic/QuicException.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstLogging.h> // For QuicError, QuicErrorCode, TransportErrorCode
#include <quic/common/StringUtils.h>
#include <quic/common/address/QuicSocketAddressBridge.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <cerrno> // For errno
#include <memory>
#include <vector>

namespace quic {

// Verify that quic::SocketAddress is currently an alias for
// folly::SocketAddress on server builds. On mobile (Android/Apple),
// quic::SocketAddress is a distinct type, so skip this check.
#if !defined(__ANDROID__) && !defined(__APPLE__)
static_assert(
    std::is_same_v<quic::SocketAddress, folly::SocketAddress>,
    "quic::SocketAddress must be folly::SocketAddress on server builds");
#endif

namespace {

template <typename AddrRange>
auto toFollyAddrRange(
    const AddrRange& addrs,
    std::vector<folly::SocketAddress>& buf) {
  if constexpr (std::is_same_v<
                    std::decay_t<decltype(*addrs.data())>,
                    folly::SocketAddress>) {
    return addrs;
  } else {
    buf.reserve(addrs.size());
    for (const auto& addr : addrs) {
      buf.push_back(quic::toFollySocketAddress(addr));
    }
    return folly::Range<const folly::SocketAddress*>(buf.data(), buf.size());
  }
}

} // namespace

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::init(
    sa_family_t family) {
  try {
    follySocket_.init(family);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly init failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::bind(
    const quic::SocketAddress& address) {
  try {
    folly::SocketAddress addrCache;
    follySocket_.bind(quic::toFollySocketAddressRef(address, addrCache));
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly bind failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] bool FollyQuicAsyncUDPSocket::isBound() const {
  return follySocket_.isBound();
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::connect(
    const quic::SocketAddress& address) {
  try {
    folly::SocketAddress addrCache;
    follySocket_.connect(quic::toFollySocketAddressRef(address, addrCache));
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly connect failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::close() {
  try {
    follySocket_.close();
    readCallbackWrapper_.reset(); // Ensure wrapper is cleared on close
    errCallbackWrapper_.reset();
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly close failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

void FollyQuicAsyncUDPSocket::resumeRead(ReadCallback* callback) {
  try {
    // TODO: We could skip this check and rely on the one in AsyncUDPSocket
    MVCHECK(!readCallbackWrapper_, "Already registered a read callback");
    readCallbackWrapper_ =
        std::make_unique<FollyReadCallbackWrapper>(callback, this);
    follySocket_.resumeRead(readCallbackWrapper_.get());
    // TODO: This should return Expected<Unit, QuicError>
  } catch (const folly::AsyncSocketException& ex) {
    // TODO: Convert to QuicError and return quic::make_unexpected
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::resumeRead failed: " << ex.what();
    throw; // Re-throw for now until signature is updated
  }
}

void FollyQuicAsyncUDPSocket::pauseRead() {
  follySocket_.pauseRead();
  readCallbackWrapper_.reset();
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setErrMessageCallback(
    ErrMessageCallback* callback) {
  try {
    if (errCallbackWrapper_) {
      errCallbackWrapper_.reset();
    }
    if (callback) {
      errCallbackWrapper_ = std::make_unique<FollyErrCallbackWrapper>(callback);
      follySocket_.setErrMessageCallback(errCallbackWrapper_.get());
    } else {
      follySocket_.setErrMessageCallback(nullptr);
    }
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setErrMessageCallback failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

ssize_t FollyQuicAsyncUDPSocket::write(
    const quic::SocketAddress& address,
    const struct iovec* vec,
    size_t iovec_len) {
  try {
    folly::AsyncUDPSocket::WriteOptions writeOptions(
        0 /*gsoVal*/, false /* zerocopyVal*/);
    folly::SocketAddress addrCache;
    return follySocket_.writev(
        quic::toFollySocketAddressRef(address, addrCache),
        vec,
        iovec_len,
        writeOptions);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::write failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writem(
    AddressRange addrs,
    iovec* iov,
    size_t* numIovecsInBuffer,
    size_t count) {
  try {
    std::vector<folly::SocketAddress> buf;
    auto range = toFollyAddrRange(addrs, buf);
    return follySocket_.writemv(range, iov, numIovecsInBuffer, count);
  } catch (const folly::AsyncSocketException& ex) {
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::writem failed: " << ex.what();
    return -1;
  }
}

ssize_t FollyQuicAsyncUDPSocket::writeGSO(
    const quic::SocketAddress& address,
    const struct iovec* vec,
    size_t iovec_len,
    WriteOptions options) {
  try {
    folly::AsyncUDPSocket::WriteOptions follyOptions(
        options.gso, options.zerocopy);
    follyOptions.txTime = options.txTime;
    folly::SocketAddress addrCache;
    return follySocket_.writev(
        quic::toFollySocketAddressRef(address, addrCache),
        vec,
        iovec_len,
        follyOptions);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::writeGSO failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writemGSO(
    AddressRange addrs,
    const BufPtr* bufs,
    size_t count,
    const WriteOptions* options) {
  try {
    std::vector<folly::SocketAddress> buf;
    auto range = toFollyAddrRange(addrs, buf);
    std::vector<folly::AsyncUDPSocket::WriteOptions> follyOptions(count);
    for (size_t i = 0; i < count; ++i) {
      follyOptions[i].gso = options[i].gso;
      follyOptions[i].zerocopy = options[i].zerocopy;
      follyOptions[i].txTime = options[i].txTime;
    }
    return follySocket_.writemGSO(range, bufs, count, follyOptions.data());
  } catch (const folly::AsyncSocketException& ex) {
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::writemGSO(IOBuf) failed: "
                << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writemGSO(
    AddressRange addrs,
    iovec* iov,
    size_t* numIovecsInBuffer,
    size_t count,
    const WriteOptions* options) {
  try {
    std::vector<folly::SocketAddress> buf;
    auto range = toFollyAddrRange(addrs, buf);
    std::vector<folly::AsyncUDPSocket::WriteOptions> follyOptions(count);
    for (size_t i = 0; i < count; ++i) {
      follyOptions[i].gso = options[i].gso;
      follyOptions[i].zerocopy = options[i].zerocopy;
      follyOptions[i].txTime = options[i].txTime;
    }
    return follySocket_.writemGSOv(
        range, iov, numIovecsInBuffer, count, follyOptions.data());
  } catch (const folly::AsyncSocketException& ex) {
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::writemGSO(iovec) failed: "
                << ex.what();
    return -1;
  }
}

ssize_t FollyQuicAsyncUDPSocket::recvmsg(struct msghdr* msg, int flags) {
  try {
    return follySocket_.recvmsg(msg, flags);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::recvmsg failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::recvmmsg(
    struct mmsghdr* msgvec,
    unsigned int vlen,
    unsigned int flags,
    struct timespec* timeout) {
  try {
    return follySocket_.recvmmsg(msgvec, vlen, flags, timeout);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    MVLOG_ERROR << "FollyQuicAsyncUDPSocket::recvmmsg failed: " << ex.what();
    return -1;
  }
}

quic::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getGSO() {
  try {
    return follySocket_.getGSO();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getGSO failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    MVLOG_ERROR << "getGSO failed: " << errorMsg;
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getGRO() {
  try {
    return follySocket_.getGRO();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getGRO failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setGRO(bool bVal) {
  try {
    if (follySocket_.setGRO(bVal)) {
      return {};
    } else {
      // Folly's setGRO returns bool, not throwing. Assume failure means error.
      int errnoCopy = errno; // Capture errno immediately after failure
      std::string errorMsg = "Folly setGRO failed";
      if (errnoCopy != 0) {
        errorMsg += ": " + quic::errnoStr(errnoCopy);
      }
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  } catch (const folly::AsyncSocketException& ex) {
    // Catch just in case future folly versions throw
    std::string errorMsg = "Folly setGRO exception: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setRecvTos(
    bool recvTos) {
  try {
    follySocket_.setRecvTos(recvTos);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setRecvTos failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<bool, QuicError> FollyQuicAsyncUDPSocket::getRecvTos() {
  try {
    return follySocket_.getRecvTos();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getRecvTos failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setRecvTtl(
    bool recvTtl) {
  try {
    follySocket_.setRecvTtl(recvTtl);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setRecvTtl failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<bool, QuicError> FollyQuicAsyncUDPSocket::getRecvTtl() {
  try {
    return follySocket_.getRecvTtl();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getRecvTtl failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setTosOrTrafficClass(
    uint8_t tos) {
  try {
    follySocket_.setTosOrTrafficClass(tos);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setTosOrTrafficClass failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] quic::Expected<quic::SocketAddress, QuicError>
FollyQuicAsyncUDPSocket::address() const {
  try {
    return quic::fromFollySocketAddress<quic::SocketAddress>(
        follySocket_.address());
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly address() failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] const quic::SocketAddress& FollyQuicAsyncUDPSocket::addressRef()
    const {
  try {
    return quic::fromFollySocketAddressRef(
        follySocket_.address(), cachedAddress_);
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly address() failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    MVLOG_FATAL << errorMsg;
  }
}

void FollyQuicAsyncUDPSocket::attachEventBase( // Keep void, attach/detach
                                               // usually don't throw socket
                                               // errors
    std::shared_ptr<QuicEventBase> evb) {
  MVCHECK(evb != nullptr);
  std::shared_ptr<FollyQuicEventBase> follyEvb =
      std::dynamic_pointer_cast<FollyQuicEventBase>(evb);
  MVCHECK(follyEvb != nullptr);
  evb_ = follyEvb;
  follySocket_.attachEventBase(follyEvb->getBackingEventBase());
}

void FollyQuicAsyncUDPSocket::detachEventBase() { // Keep void
  follySocket_.detachEventBase();
}

[[nodiscard]] std::shared_ptr<QuicEventBase>
FollyQuicAsyncUDPSocket::getEventBase() const {
  if (evb_) {
    MVCHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
  }
  return evb_;
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setCmsgs(
    const folly::SocketCmsgMap& cmsgs) {
  try {
    follySocket_.setCmsgs(cmsgs);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setCmsgs failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::appendCmsgs(
    const folly::SocketCmsgMap& cmsgs) {
  try {
    follySocket_.appendCmsgs(cmsgs);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly appendCmsgs failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setAdditionalCmsgsFunc(
    std::function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc) {
  try {
    auto adapter = [originalFunc = std::move(additionalCmsgsFunc)]()
        -> folly::Optional<folly::SocketCmsgMap> {
      if (!originalFunc) {
        return folly::none;
      }

      auto result = originalFunc();
      if (result.has_value()) {
        return folly::Optional<folly::SocketCmsgMap>(std::move(result.value()));
      } else {
        return folly::none;
      }
    };

    follySocket_.setAdditionalCmsgsFunc(std::move(adapter));
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setAdditionalCmsgsFunc failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getTimestamping() {
  try {
    return follySocket_.getTimestamping();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly getTimestamping failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setReuseAddr(
    bool reuseAddr) {
  try {
    follySocket_.setReuseAddr(reuseAddr);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setReuseAddr failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setDFAndTurnOffPMTU() {
  try {
    follySocket_.setDFAndTurnOffPMTU();
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setDFAndTurnOffPMTU failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::applyOptions(
    const folly::SocketOptionMap& options,
    folly::SocketOptionKey::ApplyPos pos) {
  try {
    follySocket_.applyOptions(options, pos);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly applyOptions failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setReusePort(
    bool reusePort) {
  try {
    follySocket_.setReusePort(reusePort);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setReusePort failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setRcvBuf(int rcvBuf) {
  try {
    follySocket_.setRcvBuf(rcvBuf);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setRcvBuf failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setSndBuf(int sndBuf) {
  try {
    follySocket_.setSndBuf(sndBuf);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setSndBuf failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

quic::Expected<void, QuicError> FollyQuicAsyncUDPSocket::setFD(
    int fd,
    FDOwnership ownership) {
  folly::AsyncUDPSocket::FDOwnership follyOwnership =
      folly::AsyncUDPSocket::FDOwnership::SHARED;
  if (ownership == FDOwnership::OWNS) {
    follyOwnership = folly::AsyncUDPSocket::FDOwnership::OWNS;
  }
  try {
    follySocket_.setFD(folly::NetworkSocket::fromFd(fd), follyOwnership);
    return {};
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setFD failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + quic::errnoStr(ex.getErrno());
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

int FollyQuicAsyncUDPSocket::getFD() {
  return follySocket_.getNetworkSocket().toFd();
}

folly::AsyncUDPSocket& FollyQuicAsyncUDPSocket::getFollySocket() {
  return follySocket_;
}

// FollyReadCallbackWrapper implementation

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::getReadBuffer(
    void** buf,
    size_t* len) noexcept {
  return wrappedReadCallback_->getReadBuffer(buf, len);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onDataAvailable(
    const folly::SocketAddress& client,
    size_t len,
    bool truncated,
    folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams
        params) noexcept {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  // TODO: Can this be moved to a static compile time check?
  MVCHECK_EQ(
      QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace,
      folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace);
#endif
  QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams localParams;
  localParams.gro = params.gro;
  localParams.tos = params.tos;
  if (params.ttl) {
    localParams.ttl.emplace(*params.ttl);
  }
  if (params.ts) {
    localParams.ts.emplace(*params.ts);
  }

  // Forward by reference: on server (identity) this aliases `client` with no
  // copy; on mobile it converts once into the local cache. Avoids the per-
  // packet copy that fromFollySocketAddress() (returns by value) would incur.
  quic::SocketAddress quicClientCache;
  const quic::SocketAddress& quicClient =
      quic::fromFollySocketAddressRef(client, quicClientCache);
  return wrappedReadCallback_->onDataAvailable(
      quicClient, len, truncated, localParams);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onNotifyDataAvailable(
    folly::AsyncUDPSocket&) noexcept {
  MVCHECK(parentSocket_ != nullptr);
  return wrappedReadCallback_->onNotifyDataAvailable(*parentSocket_);
}

bool FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::shouldOnlyNotify() {
  return wrappedReadCallback_->shouldOnlyNotify();
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  return wrappedReadCallback_->onReadError(ex);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::
    onReadClosed() noexcept {
  return wrappedReadCallback_->onReadClosed();
}

// FollyErrMessageCallbackWrapper implementation
void FollyQuicAsyncUDPSocket::FollyErrCallbackWrapper::errMessage(
    const cmsghdr& cmsg) noexcept {
  return wrappedErrorCallback_->errMessage(cmsg);
}

void FollyQuicAsyncUDPSocket::FollyErrCallbackWrapper::errMessageError(
    const folly::AsyncSocketException& ex) noexcept {
  return wrappedErrorCallback_->errMessageError(ex);
}

} // namespace quic
