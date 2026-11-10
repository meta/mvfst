/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicReadCodec.h>
#include <quic/common/MvfstLogging.h>

#include <quic/QuicConstants.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>
#include <quic/common/StringUtils.h>

namespace quic {

// Forward declarations
OptionalIntegral<size_t> calculateSconePacketLength(
    ContiguousReadCursor cursor);
Optional<CodecResult> tryParseSconePacket(
    BufQueue& queue,
    const ContiguousReadCursor& cursor);

QuicReadCodec::QuicReadCodec(QuicNodeType nodeType) : nodeType_(nodeType) {}

Optional<VersionNegotiationPacket> QuicReadCodec::tryParsingVersionNegotiation(
    BufQueue& queue) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());
  uint8_t initialByte = 0;
  if (!cursor.tryReadBE(initialByte)) {
    return std::nullopt;
  }
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm != HeaderForm::Long) {
    return std::nullopt;
  }
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    // if it is an invalid packet, it's definitely not a VN packet, so ignore
    // it.
    return std::nullopt;
  }
  if (longHeaderInvariant->invariant.version !=
      QuicVersion::VERSION_NEGOTIATION) {
    return std::nullopt;
  }
  return decodeVersionNegotiation(*longHeaderInvariant, cursor);
}

quic::Expected<ParsedLongHeader, TransportErrorCode> tryParseLongHeader(
    ContiguousReadCursor& cursor,
    QuicNodeType nodeType) {
  uint8_t initialByte = 0;
  if (!cursor.tryReadBE(initialByte)) {
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    MVVLOG(4) << "Dropping packet, failed to parse invariant";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return quic::make_unexpected(longHeaderInvariant.error());
  }
  if (longHeaderInvariant->invariant.version ==
      QuicVersion::VERSION_NEGOTIATION) {
    // We shouldn't handle VN packets while parsing the long header.
    // We assume here that they have been handled before calling this
    // function.
    // Since VN is not allowed to be coalesced with another packet
    // type, we clear out the buffer to avoid anyone else parsing it.
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto type = parseLongHeaderType(initialByte);

  auto parsedLongHeader =
      parseLongHeaderVariants(type, *longHeaderInvariant, cursor, nodeType);
  if (!parsedLongHeader) {
    MVVLOG(4) << "Dropping due to failed to parse header";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return quic::make_unexpected(parsedLongHeader.error());
  }

  return std::move(parsedLongHeader.value());
}

static PacketDropReason getDecryptErrorReason(ProtectionType protectionType) {
  switch (protectionType) {
    case ProtectionType::Initial:
      return PacketDropReason::DECRYPTION_ERROR_INITIAL;
    case ProtectionType::Handshake:
      return PacketDropReason::DECRYPTION_ERROR_HANDSHAKE;
    case ProtectionType::ZeroRtt:
      return PacketDropReason::DECRYPTION_ERROR_0RTT;
    default:
      return PacketDropReason::DECRYPTION_ERROR;
  }
}

quic::Expected<CodecResult, QuicError> QuicReadCodec::parseLongHeaderPacket(
    BufQueue& queue,
    const AckStates& ackStates) {
  ContiguousReadCursor cursor(queue.front()->data(), queue.front()->length());
  const uint8_t initialByte = *cursor.peekBytes().data();

  auto res = tryParseLongHeader(cursor, nodeType_);
  if (res.hasError()) {
    MVVLOG(4) << "Failed to parse long header " << connIdToHex();
    queue.move();
    return CodecResult(Nothing());
  }
  auto parsedLongHeader = std::move(res.value());
  auto type = parsedLongHeader.header.getHeaderType();

  // As soon as we have parsed out the long header we can split off any
  // coalesced packets. We do this early since the spec mandates that decryption
  // failure must not stop the processing of subsequent coalesced packets.
  auto longHeader = std::move(parsedLongHeader.header);

  if (type == LongHeader::Types::Retry) {
    RetryPacket::IntegrityTagType integrityTag;
    if (!cursor.tryRead(integrityTag)) {
      return CodecResult(Nothing());
    }
    queue.move();
    return RetryPacket(std::move(longHeader), integrityTag, initialByte);
  }

  uint64_t packetNumberOffset = cursor.getCurrentPosition();
  size_t currentPacketLen =
      packetNumberOffset + parsedLongHeader.packetLength.packetLength;
  if (queue.chainLength() < currentPacketLen) {
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  auto currentPacketData = queue.splitAtMost(currentPacketLen);
  cursor.reset(currentPacketData->data(), currentPacketData->length());
  cursor.skip(packetNumberOffset);
  // Sample starts after the max packet number size. This ensures that we
  // have enough bytes to skip before we can start reading the sample.
  if (!cursor.canAdvance(kMaxPacketNumEncodingSize)) {
    MVVLOG(4) << "Dropping packet, not enough for packet number "
              << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  cursor.skip(kMaxPacketNumEncodingSize);
  Sample sample;
  if (!cursor.tryPull(sample.data(), sample.size())) {
    MVVLOG(4) << "Dropping packet, sample too small " << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  const PacketNumberCipher* headerCipher{nullptr};
  const Aead* cipher{nullptr};
  auto protectionType = longHeader.getProtectionType();
  switch (protectionType) {
    case ProtectionType::Initial:
      if (!initialHeaderCipher_) {
        MVVLOG(4) << nodeToString(nodeType_)
                  << " dropping initial packet after initial keys dropped"
                  << connIdToHex();
        return CodecResult(Nothing());
      }
      headerCipher = initialHeaderCipher_.get();
      cipher = initialReadCipher_.get();
      break;
    case ProtectionType::Handshake:
      headerCipher = handshakeHeaderCipher_.get();
      cipher = handshakeReadCipher_.get();
      break;
    case ProtectionType::ZeroRtt:
      if (handshakeDoneTime_) {
        // TODO actually drop the 0-rtt keys in addition to dropping packets.
        auto timeBetween = Clock::now() - *handshakeDoneTime_;
        if (timeBetween > kTimeToRetainZeroRttKeys) {
          MVVLOG(4) << nodeToString(nodeType_)
                    << " dropping zero rtt packet for exceeding key timeout"
                    << connIdToHex();
          return CodecResult(Nothing());
        }
      }
      headerCipher = zeroRttHeaderCipher_.get();
      cipher = zeroRttReadCipher_.get();
      break;
    case ProtectionType::KeyPhaseZero:
    case ProtectionType::KeyPhaseOne:
      MVCHECK(false, "one rtt protection type in long header");
  }
  if (!headerCipher || !cipher) {
    return CodecResult(
        CipherUnavailable(std::move(currentPacketData), protectionType));
  }

  PacketNum expectedNextPacketNum = 0;
  Optional<PacketNum> largestRecvdPacketNum;
  switch (longHeaderTypeToProtectionType(type)) {
    case ProtectionType::Initial:
      largestRecvdPacketNum = ackStates.initialAckState->largestRecvdPacketNum;

      break;
    case ProtectionType::Handshake:
      largestRecvdPacketNum =
          ackStates.handshakeAckState->largestRecvdPacketNum;

      break;
    case ProtectionType::ZeroRtt:
      largestRecvdPacketNum = ackStates.appDataAckState.largestRecvdPacketNum;

      break;
    default:
      folly::assume_unreachable();
  }
  if (largestRecvdPacketNum) {
    expectedNextPacketNum = 1 + *largestRecvdPacketNum;
  }
  MutableByteRange initialByteRange(currentPacketData->writableData(), 1);
  MutableByteRange packetNumberByteRange(
      currentPacketData->writableData() + packetNumberOffset,
      kMaxPacketNumEncodingSize);
  auto decryptResult = headerCipher->decryptLongHeader(
      ByteRange(sample.data(), sample.size()),
      initialByteRange,
      packetNumberByteRange);
  if (decryptResult.hasError()) {
    MVVLOG(4) << "Failed to decrypt long header " << connIdToHex();
    return quic::make_unexpected(decryptResult.error());
  }
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);

  longHeader.setPacketNumber(packetNum.first);
  BufQueue decryptQueue;
  decryptQueue.append(std::move(currentPacketData));
  size_t aadLen = packetNumberOffset + packetNum.second;
  auto headerData = decryptQueue.splitAtMost(aadLen);
  // parsing verifies that packetLength >= packet number length.
  auto encryptedData = decryptQueue.splitAtMost(
      parsedLongHeader.packetLength.packetLength - packetNum.second);
  if (!encryptedData) {
    // There should normally be some integrity tag at least in the data,
    // however allowing the aead to process the data even if the tag is not
    // present helps with writing tests.
    encryptedData = BufHelpers::create(0);
  }

  BufPtr decrypted;
  auto decryptAttempt = cipher->tryDecrypt(
      std::move(encryptedData), headerData.get(), packetNum.first);
  if (!decryptAttempt) {
    MVVLOG(4) << "Unable to decrypt packet=" << packetNum.first
              << " packetNumLen=" << parsePacketNumberLength(initialByte)
              << " protectionType=" << toString(protectionType) << " "
              << connIdToHex();
    return CodecResult(Nothing(getDecryptErrorReason(protectionType)));
  }
  decrypted = std::move(*decryptAttempt);

  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = BufHelpers::create(0);
  }

  auto packetRes =
      decodeRegularPacket(std::move(longHeader), params_, std::move(decrypted));

  if (!packetRes.has_value()) {
    return CodecResult(CodecError(std::move(packetRes.error())));
  }

  return CodecResult(std::move(*packetRes));
}

quic::Expected<CodecResult, QuicError> QuicReadCodec::tryParseShortHeaderPacket(
    BufPtr data,
    const AckStates& ackStates,
    size_t dstConnIdSize,
    ContiguousReadCursor& cursor) {
  // TODO: allow other connid lengths from the state.
  size_t packetNumberOffset = 1 + dstConnIdSize;
  PacketNum expectedNextPacketNum =
      ackStates.appDataAckState.largestRecvdPacketNum
      ? (1 + *ackStates.appDataAckState.largestRecvdPacketNum)
      : 0;
  size_t sampleOffset = packetNumberOffset + kMaxPacketNumEncodingSize;
  Sample sample;
  if (data->computeChainDataLength() < sampleOffset + sample.size()) {
    MVVLOG(10) << "Dropping packet, too small for sample " << connIdToHex();
    // There's not enough space for the short header packet
    return CodecResult(Nothing());
  }

  MutableByteRange initialByteRange(data->writableData(), 1);
  MutableByteRange packetNumberByteRange(
      data->writableData() + packetNumberOffset, kMaxPacketNumEncodingSize);
  ByteRange sampleByteRange(data->writableData() + sampleOffset, sample.size());

  auto decryptResult = oneRttHeaderCipher_->decryptShortHeader(
      sampleByteRange, initialByteRange, packetNumberByteRange);
  if (decryptResult.hasError()) {
    MVVLOG(4) << "Failed to decrypt short header " << connIdToHex();
    return quic::make_unexpected(decryptResult.error());
  }
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);
  auto shortHeader =
      parseShortHeader(initialByteRange.data()[0], cursor, dstConnIdSize);
  if (!shortHeader) {
    MVVLOG(10) << "Dropping packet, cannot parse " << connIdToHex();
    return CodecResult(Nothing());
  }
  shortHeader->setPacketNumber(packetNum.first);
  bool peerKeyUpdateAttempt = false;
  auto oneRttReadCipherToUse = [&]() -> Aead* {
    if (shortHeader->getProtectionType() == currentOneRttReadPhase_) {
      return currentOneRttReadCipher_.get();
    } else {
      // This is a packet from a different phase. It may be encrypted using the
      // next key (new peer-initiated key update) or the previous key (out of
      // order packet or pending locally-initiated key update).

      if (!currentOneRttReadPhaseStartPacketNum_ ||
          shortHeader->getPacketSequenceNum() <
              currentOneRttReadPhaseStartPacketNum_.value()) {
        // There is either a pending key update or this an out-of-order packet,
        // attempt to use the previous cipher
        if (previousOneRttReadCipher_) {
          return previousOneRttReadCipher_.get();
        } else {
          // There is no previous packet. We can't decrypt this packet
          MVVLOG(4)
              << nodeToString(nodeType_)
              << " cannot read packet using previous cipher. Cipher is not available";
          return nullptr;
        }
      } else {
        // This is a key update attempt
        if (nextOneRttReadCipher_) {
          peerKeyUpdateAttempt = true;
          QUIC_STATS(statsCallback_, onKeyUpdateAttemptReceived);
          return nextOneRttReadCipher_.get();
        } else {
          // The next cipher is not yet available. We can't decrypt this packet
          MVVLOG(4)
              << nodeToString(nodeType_)
              << " unable to process key update. Next cipher is not yet available";
          return nullptr;
        }
      }
    }
  }();

  if (oneRttReadCipherToUse == nullptr) {
    return CodecResult(
        CipherUnavailable(std::move(data), shortHeader->getProtectionType()));
  }

  // We know that the iobuf is not chained. This means that we can safely have
  // a non-owning reference to the header without cloning the buffer. If we
  // don't clone the buffer, the buffer will not show up as shared and we can
  // decrypt in-place.
  size_t aadLen = packetNumberOffset + packetNum.second;
  Buf headerData = BufHelpers::wrapBufferAsValue(data->data(), aadLen);
  data->trimStart(aadLen);

  BufPtr decrypted;
  auto decryptAttempt = oneRttReadCipherToUse->tryDecrypt(
      std::move(data), &headerData, packetNum.first);
  if (!decryptAttempt) {
    auto protectionType = shortHeader->getProtectionType();
    MVVLOG(10) << "Unable to decrypt packet=" << packetNum.first
               << " protectionType=" << (int)protectionType << " "
               << connIdToHex();
    return CodecResult(Nothing(PacketDropReason::DECRYPTION_ERROR));
  }
  decrypted = std::move(*decryptAttempt);
  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = BufHelpers::create(0);
  }

  if (peerKeyUpdateAttempt) {
    // Peer initiated a key update and we've successfully decrypted a packet
    // from the next phase. We should advance our oneRttCipher state.
    currentOneRttReadPhase_ = shortHeader->getProtectionType();
    currentOneRttReadPhaseStartPacketNum_.reset();
    previousOneRttReadCipher_.reset(currentOneRttReadCipher_.release());
    currentOneRttReadCipher_.reset(nextOneRttReadCipher_.release());
    // nextOneRttReadCipher_ will be populated by the transport
  }

  if (!currentOneRttReadPhaseStartPacketNum_.has_value() &&
      oneRttReadCipherToUse == currentOneRttReadCipher_.get()) {
    // This is the first packet in the current phase. Record the packet
    // number. This applies for both peer-initiated and self-initiated key
    // updates.
    currentOneRttReadPhaseStartPacketNum_ = shortHeader->getPacketSequenceNum();
    QUIC_STATS(statsCallback_, onKeyUpdateAttemptSucceeded);
  }

  // TODO: Should we discard the previous cipher at some point? Keeping it
  // around avoids the timing signals mentioned in the spec, but we could also
  // drop it after 3 * PTO.

  auto packetRes = decodeRegularPacket(
      std::move(*shortHeader), params_, std::move(decrypted));

  if (!packetRes.has_value()) {
    return CodecResult(CodecError(std::move(packetRes.error())));
  }
  return CodecResult(std::move(*packetRes));
}

CodecResult QuicReadCodec::parsePacket(
    BufQueue& queue,
    const AckStates& ackStates,
    size_t dstConnIdSize) {
  if (queue.empty()) {
    return CodecResult(Nothing());
  }
  MVCHECK(
      queue.front(),
      "Non-empty BufQueue has no front buffer, chainLength="
          << queue.chainLength());
  auto* front = queue.front();
  MVCHECK(!front->isChained());
  ContiguousReadCursor cursor(front->data(), front->length());
  uint8_t initialByte = 0;
  if (!cursor.tryReadBE(initialByte)) {
    return CodecResult(Nothing());
  }
  auto headerForm = getHeaderForm(initialByte);

  if (headerForm == HeaderForm::Long) {
    // Try parsing as SCONE packet
    auto sconeResult = tryParseSconePacket(queue, cursor);
    if (sconeResult.has_value()) {
      return std::move(sconeResult.value());
    }
    // Not SCONE, continue with normal long header processing
    auto result = parseLongHeaderPacket(queue, ackStates);
    if (result.hasError()) {
      return CodecResult(CodecError(std::move(result.error())));
    }
    return std::move(result.value());
  }
  // Missing 1-rtt header cipher is the only case we wouldn't consider reset
  if (!currentOneRttReadCipher_ || !oneRttHeaderCipher_) {
    MVVLOG(4) << nodeToString(nodeType_)
              << " cannot read key phase zero packet";
    MVVLOG(20) << "cannot read data="
               << quic::hexlify(queue.front()->toString()) << " "
               << connIdToHex();
    return CodecResult(
        CipherUnavailable(queue.move(), ProtectionType::KeyPhaseZero));
  }

  auto data = queue.move();
  if (nodeType_ == QuicNodeType::Client &&
      initialByte & ShortHeader::kFixedBitMask) {
    auto dataLength = data->length();
    if (!statelessResetTokens_.empty() &&
        dataLength > sizeof(StatelessResetToken)) {
      if (!cryptoEqual_) {
        return CodecResult(CodecError(QuicError(
            QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
            "crypto constant time comparison function is not set.")));
      }
      ByteRange tokenSource(
          data->data() + (dataLength - sizeof(StatelessResetToken)),
          sizeof(StatelessResetToken));
      for (const auto& resetToken : statelessResetTokens_) {
        if (cryptoEqual_(
                tokenSource, ByteRange(resetToken.data(), resetToken.size()))) {
          return StatelessReset(resetToken);
        }
      }
    }
  }
  auto result = tryParseShortHeaderPacket(
      std::move(data), ackStates, dstConnIdSize, cursor);
  if (result.hasError()) {
    return CodecResult(CodecError(std::move(result.error())));
  }
  return std::move(result.value());
}

bool QuicReadCodec::canInitiateKeyUpdate() const {
  if (!nextOneRttReadCipher_ || !currentOneRttReadPhaseStartPacketNum_) {
    // We haven't received any packets in the current oneRtt phase yet.
    return false;
  }
  return true;
}

bool QuicReadCodec::advanceOneRttReadPhase() {
  if (!canInitiateKeyUpdate()) {
    MVLOG_WARNING << "Key update requested before the read codec can allow it";
    return false;
  }
  previousOneRttReadCipher_.reset(currentOneRttReadCipher_.release());
  currentOneRttReadCipher_.reset(nextOneRttReadCipher_.release());
  currentOneRttReadPhase_ =
      (currentOneRttReadPhase_ == ProtectionType::KeyPhaseZero)
      ? ProtectionType::KeyPhaseOne
      : ProtectionType::KeyPhaseZero;
  currentOneRttReadPhaseStartPacketNum_.reset();
  return true;
}

const Aead* QuicReadCodec::getOneRttReadCipher() const {
  return currentOneRttReadCipher_.get();
}

const Aead* QuicReadCodec::getZeroRttReadCipher() const {
  return zeroRttReadCipher_.get();
}

const Aead* QuicReadCodec::getHandshakeReadCipher() const {
  return handshakeReadCipher_.get();
}

const std::vector<StatelessResetToken>& QuicReadCodec::getStatelessResetTokens()
    const {
  return statelessResetTokens_;
}

CodecParameters QuicReadCodec::getCodecParameters() const {
  return params_;
}

void QuicReadCodec::setInitialReadCipher(
    std::unique_ptr<Aead> initialReadCipher) {
  initialReadCipher_ = std::move(initialReadCipher);
}

void QuicReadCodec::setOneRttReadCipher(
    std::unique_ptr<Aead> oneRttReadCipher) {
  currentOneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setNextOneRttReadCipher(
    std::unique_ptr<Aead> oneRttReadCipher) {
  nextOneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setZeroRttReadCipher(
    std::unique_ptr<Aead> zeroRttReadCipher) {
  MVCHECK(
      nodeType_ == QuicNodeType::Server,
      "Setting zero rtt read cipher on client.");
  zeroRttReadCipher_ = std::move(zeroRttReadCipher);
}

void QuicReadCodec::setHandshakeReadCipher(
    std::unique_ptr<Aead> handshakeReadCipher) {
  handshakeReadCipher_ = std::move(handshakeReadCipher);
}

void QuicReadCodec::setInitialHeaderCipher(
    std::unique_ptr<PacketNumberCipher> initialHeaderCipher) {
  initialHeaderCipher_ = std::move(initialHeaderCipher);
}

void QuicReadCodec::setOneRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher) {
  oneRttHeaderCipher_ = std::move(oneRttHeaderCipher);
}

void QuicReadCodec::setZeroRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher) {
  zeroRttHeaderCipher_ = std::move(zeroRttHeaderCipher);
}

void QuicReadCodec::setHandshakeHeaderCipher(
    std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher) {
  handshakeHeaderCipher_ = std::move(handshakeHeaderCipher);
}

void QuicReadCodec::setCodecParameters(CodecParameters params) {
  params_ = std::move(params);
}

void QuicReadCodec::setClientConnectionId(ConnectionId connId) {
  clientConnectionId_ = connId;
}

void QuicReadCodec::setServerConnectionId(ConnectionId connId) {
  serverConnectionId_ = connId;
}

void QuicReadCodec::setStatelessResetTokens(
    std::vector<StatelessResetToken> statelessResetTokens) {
  statelessResetTokens_ = std::move(statelessResetTokens);
}

void QuicReadCodec::setCryptoEqual(CryptoEqualFn cryptoEqual) {
  cryptoEqual_ = cryptoEqual;
}

void QuicReadCodec::setConnectionStatsCallback(
    QuicTransportStatsCallback* callback) {
  statsCallback_ = callback;
}

const ConnectionId& QuicReadCodec::getClientConnectionId() const {
  return clientConnectionId_.value();
}

const ConnectionId& QuicReadCodec::getServerConnectionId() const {
  return serverConnectionId_.value();
}

const Aead* QuicReadCodec::getInitialCipher() const {
  return initialReadCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getInitialHeaderCipher() const {
  return initialHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getOneRttHeaderCipher() const {
  return oneRttHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getHandshakeHeaderCipher() const {
  return handshakeHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getZeroRttHeaderCipher() const {
  return zeroRttHeaderCipher_.get();
}

void QuicReadCodec::onHandshakeDone(TimePoint handshakeDoneTime) {
  if (!handshakeDoneTime_) {
    handshakeDoneTime_ = handshakeDoneTime;
  }
}

Optional<TimePoint> QuicReadCodec::getHandshakeDoneTime() {
  return handshakeDoneTime_;
}

ProtectionType QuicReadCodec::getCurrentOneRttReadPhase() const {
  return currentOneRttReadPhase_;
}

std::string QuicReadCodec::connIdToHex() const {
  static ConnectionId zeroConn = ConnectionId::createZeroLength();
  const auto& serverId = serverConnectionId_.value_or(zeroConn);
  const auto& clientId = clientConnectionId_.value_or(zeroConn);
  return fmt::format(
      "server={} client={}", serverId.hex(), "client=", clientId.hex());
}

CodecResult::CodecResult(RegularQuicPacket&& regularPacketIn)
    : type_(CodecResult::Type::REGULAR_PACKET) {
  new (&packet) RegularQuicPacket(std::move(regularPacketIn));
}

CodecResult::CodecResult(CipherUnavailable&& cipherUnavailableIn)
    : type_(CodecResult::Type::CIPHER_UNAVAILABLE) {
  new (&cipher) CipherUnavailable(std::move(cipherUnavailableIn));
}

CodecResult::CodecResult(StatelessReset&& statelessResetIn)
    : type_(CodecResult::Type::STATELESS_RESET) {
  new (&reset) StatelessReset(std::move(statelessResetIn));
}

CodecResult::CodecResult(RetryPacket&& retryPacketIn)
    : type_(CodecResult::Type::RETRY) {
  new (&retry) RetryPacket(std::move(retryPacketIn));
}

CodecResult::CodecResult(Nothing&& nothing)
    : type_(CodecResult::Type::NOTHING) {
  new (&none) Nothing(std::move(nothing));
}

CodecResult::CodecResult(CodecError&& codecErrorIn)
    : type_(CodecResult::Type::CODEC_ERROR) {
  new (&error) CodecError(std::move(codecErrorIn));
}

CodecResult::CodecResult(SCONEPacket&& sconePacketIn)
    : type_(CodecResult::Type::SCONE_PACKET) {
  new (&sconePacket_) SCONEPacket(std::move(sconePacketIn));
}

CodecError* CodecResult::codecError() {
  if (type_ == CodecResult::Type::CODEC_ERROR) {
    return &error;
  }
  return nullptr;
}

void CodecResult::destroyCodecResult() {
  switch (type_) {
    case CodecResult::Type::REGULAR_PACKET:
      packet.~RegularQuicPacket();
      break;
    case CodecResult::Type::RETRY:
      retry.~RetryPacket();
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      cipher.~CipherUnavailable();
      break;
    case CodecResult::Type::STATELESS_RESET:
      reset.~StatelessReset();
      break;
    case CodecResult::Type::NOTHING:
      none.~Nothing();
      break;
    case CodecResult::Type::CODEC_ERROR:
      error.~CodecError();
      break;
    case CodecResult::Type::SCONE_PACKET:
      sconePacket_.~SCONEPacket();
      break;
  }
}

CodecResult::~CodecResult() {
  destroyCodecResult();
}

CodecResult::CodecResult(CodecResult&& other) noexcept {
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
    case CodecResult::Type::CODEC_ERROR:
      new (&error) CodecError(std::move(other.error));
      break;
    case CodecResult::Type::SCONE_PACKET:
      new (&sconePacket_) SCONEPacket(std::move(other.sconePacket_));
      break;
  }
  type_ = other.type_;
}

CodecResult& CodecResult::operator=(CodecResult&& other) noexcept {
  destroyCodecResult();
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
    case CodecResult::Type::CODEC_ERROR:
      new (&error) CodecError(std::move(other.error));
      break;
    case CodecResult::Type::SCONE_PACKET:
      new (&sconePacket_) SCONEPacket(std::move(other.sconePacket_));
      break;
  }
  type_ = other.type_;
  return *this;
}

CodecResult::Type CodecResult::type() {
  return type_;
}

RegularQuicPacket* CodecResult::regularPacket() {
  if (type_ == CodecResult::Type::REGULAR_PACKET) {
    return &packet;
  }
  return nullptr;
}

CipherUnavailable* CodecResult::cipherUnavailable() {
  if (type_ == CodecResult::Type::CIPHER_UNAVAILABLE) {
    return &cipher;
  }
  return nullptr;
}

StatelessReset* CodecResult::statelessReset() {
  if (type_ == CodecResult::Type::STATELESS_RESET) {
    return &reset;
  }
  return nullptr;
}

RetryPacket* CodecResult::retryPacket() {
  if (type_ == CodecResult::Type::RETRY) {
    return &retry;
  }
  return nullptr;
}

Nothing* CodecResult::nothing() {
  if (type_ == CodecResult::Type::NOTHING) {
    return &none;
  }
  return nullptr;
}

SCONEPacket* CodecResult::sconePacket() {
  if (type_ == CodecResult::Type::SCONE_PACKET) {
    return &sconePacket_;
  }
  return nullptr;
}

// Calculate SCONE packet length from buffer
// Note: cursor should be positioned after the first byte (which contains
// the long header bit, reserved bit, and rate signal high bits)
OptionalIntegral<size_t> calculateSconePacketLength(
    ContiguousReadCursor cursor) {
  // Need: version(4) + dstCidLen(1) at minimum
  if (!cursor.canAdvance(4 + 1)) {
    return {};
  }

  cursor.skip(4); // Skip version

  uint8_t dstCidLen = 0;
  cursor.tryRead<uint8_t>(dstCidLen);
  if (!cursor.canAdvance(dstCidLen + 1)) { // dstCid + srcCidLen
    return {};
  }

  cursor.skip(dstCidLen); // Skip destination CID
  uint8_t srcCidLen = 0;
  cursor.tryRead<uint8_t>(srcCidLen);
  if (!cursor.canAdvance(srcCidLen)) {
    return {};
  }

  // Total length: firstByte(1) + version(4) + dstCidLen(1) + dstCid +
  // srcCidLen(1) + srcCid
  return 1 + 4 + 1 + dstCidLen + 1 + srcCidLen;
}

Expected<SCONEPacket, TransportErrorCode> decodeScone(
    ContiguousReadCursor& cursor) {
  // Initialize SCONEPacket with zero-length ConnectionIds
  SCONEPacket sconePacket{
      0, // rate
      0, // version
      ConnectionId::createZeroLength(), // dstCid
      ConnectionId::createZeroLength() // srcCid
  };

  if (!cursor.canAdvance(1)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  uint8_t firstByte = 0;
  cursor.tryRead(firstByte);

  if (!cursor.canAdvance(sizeof(uint32_t))) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  cursor.tryReadBE<uint32_t>(sconePacket.version);

  // Rate signal is 7 bits per IETF SCONE draft:
  // - High 6 bits from first byte (bits 0x3f)
  // - Low 1 bit from MSB of version field (bit 31)
  uint8_t rateHighBits = firstByte & 0x3F;
  uint8_t rateLowBit = (sconePacket.version >> 31) & 0x1;
  sconePacket.rate = (rateHighBits << 1) | rateLowBit;

  VLOG(4) << "SCONE decode: rate=" << (int)sconePacket.rate << " version=0x"
          << std::hex << sconePacket.version << std::dec;

  if (!cursor.canAdvance(1)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  uint8_t dstCidLen = 0;
  cursor.tryRead(dstCidLen);

  if (!cursor.canAdvance(dstCidLen)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  if (dstCidLen > 0) {
    std::string dstCidData;
    cursor.tryReadFixedSizeString(dstCidData, dstCidLen);
    std::vector<uint8_t> dstCidVec(dstCidData.begin(), dstCidData.end());
    auto dstCidResult = ConnectionId::create(dstCidVec);
    if (dstCidResult.hasError()) {
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    sconePacket.dstCid = std::move(dstCidResult.value());
  }

  if (!cursor.canAdvance(1)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  uint8_t srcCidLen = 0;
  cursor.tryRead(srcCidLen);

  if (!cursor.canAdvance(srcCidLen)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }

  if (srcCidLen > 0) {
    std::string srcCidData;
    cursor.tryReadFixedSizeString(srcCidData, srcCidLen);
    std::vector<uint8_t> srcCidVec(srcCidData.begin(), srcCidData.end());
    auto srcCidResult = ConnectionId::create(srcCidVec);
    if (srcCidResult.hasError()) {
      return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
    }
    sconePacket.srcCid = std::move(srcCidResult.value());
  }

  return sconePacket;
}

// Helper function to try parsing a SCONE packet from the queue.
// Returns a CodecResult with the SCONE packet if successfully parsed,
// or std::nullopt if this is not a SCONE packet.
// Returns a CodecResult with error/Nothing if parsing failed.
Optional<CodecResult> tryParseSconePacket(
    BufQueue& queue,
    const ContiguousReadCursor& cursor) {
  // Check if this is a SCONE packet by peeking at version
  if (!cursor.canAdvance(sizeof(uint32_t))) {
    return std::nullopt; // Not enough data, not a SCONE packet
  }

  auto bytes = cursor.peekBytes();
  uint32_t version =
      folly::Endian::big(folly::loadUnaligned<uint32_t>(bytes.data()));

  if (version != static_cast<uint32_t>(QuicVersion::SCONE_VERSION_1) &&
      version != static_cast<uint32_t>(QuicVersion::SCONE_VERSION_2)) {
    return std::nullopt; // Not a SCONE version
  }

  VLOG(4) << "Detected SCONE packet";
  ContiguousReadCursor sconeCursor(
      queue.front()->data(), queue.front()->length());
  sconeCursor.skip(1); // Skip initial byte
  auto sconeLength = calculateSconePacketLength(sconeCursor);
  if (!sconeLength.has_value()) {
    return CodecResult(Nothing(PacketDropReason::PARSE_ERROR_LONG_HEADER));
  }

  if (queue.chainLength() < sconeLength.value()) {
    return CodecResult(Nothing(PacketDropReason::PARSE_ERROR_LONG_HEADER));
  }

  auto sconeData = queue.splitAtMost(sconeLength.value());
  ContiguousReadCursor sconeDataCursor(sconeData->data(), sconeData->length());

  auto scone = decodeScone(sconeDataCursor);
  if (!scone.has_value()) {
    return CodecResult(Nothing(PacketDropReason::PARSE_ERROR_LONG_HEADER));
  }

  VLOG(4) << "Parsed SCONE packet with rate=" << (int)scone->rate;
  return CodecResult(std::move(scone.value()));
}

} // namespace quic
