/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>

#include <fizz/protocol/Exporter.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/fizz/client/handshake/FizzClientExtensions.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>

#include <fizz/client/EarlyDataRejectionPolicy.h>
#include <fizz/protocol/Protocol.h>

namespace quic {

FizzClientHandshake::FizzClientHandshake(
    QuicClientConnectionState* conn,
    std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext,
    std::unique_ptr<FizzCryptoFactory> cryptoFactory)
    : ClientHandshake(conn),
      cryptoFactory_(std::move(cryptoFactory)),
      fizzContext_(std::move(fizzContext)) {
  MVCHECK(cryptoFactory_->getFizzFactory());
}

quic::Expected<Optional<CachedServerTransportParameters>, QuicError>
FizzClientHandshake::connectImpl(Optional<std::string> hostname) {
  // Look up psk
  auto quicCachedPsk = getPsk(hostname);

  folly::Optional<fizz::client::CachedPsk> cachedPsk;
  Optional<CachedServerTransportParameters> transportParams;
  if (quicCachedPsk) {
    cachedPsk = std::move(quicCachedPsk->cachedPsk);
    transportParams = std::move(quicCachedPsk->transportParams);
  }

  // Setup context for this handshake.
  auto context = std::make_shared<fizz::client::FizzClientContext>(
      *fizzContext_->getContext());
  context->setFactory(cryptoFactory_->getFizzFactory());
  context->setSupportedCiphers({fizz::CipherSuite::TLS_AES_128_GCM_SHA256});
  context->setCompatibilityMode(false);
  // Since Draft-17, EOED should not be sent
  context->setOmitEarlyRecordLayer(true);

  Optional<std::vector<fizz::ech::ParsedECHConfig>> echConfigs;
  if (hostname.has_value()) {
    std::string hostnameStr = hostname.value();
    echConfigs = fizzContext_->getECHConfigs(hostnameStr);
  }

  folly::Optional<std::string> follyHostname;
  if (hostname.has_value()) {
    follyHostname = hostname.value();
  }
  folly::Optional<std::vector<fizz::ech::ParsedECHConfig>> follyECHConfigs;
  if (echConfigs.has_value()) {
    follyECHConfigs = std::move(echConfigs.value());
  }

  try {
    processActions(machine_.processConnect(
        state_,
        std::move(context),
        fizzContext_->getCertificateVerifier(),
        std::move(follyHostname),
        std::move(cachedPsk),
        std::make_shared<FizzClientExtensions>(
            getClientTransportParameters(),
            fizzContext_->getChloPaddingBytes()),
        std::move(follyECHConfigs)));
  } catch (const fizz::FizzException& ex) {
    if (ex.getAlert()) {
      auto alertNum = static_cast<std::underlying_type_t<TransportErrorCode>>(
          ex.getAlert().value());
      alertNum += static_cast<std::underlying_type_t<TransportErrorCode>>(
          TransportErrorCode::CRYPTO_ERROR);
      return quic::make_unexpected(
          QuicError(static_cast<TransportErrorCode>(alertNum), ex.what()));
    } else {
      return quic::make_unexpected(
          QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
    }
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
  }

  return transportParams;
}

folly::Optional<QuicCachedPsk> FizzClientHandshake::getPsk(
    const Optional<std::string>& hostname) const {
  auto quicCachedPsk = fizzContext_->getPsk(hostname);
  if (!quicCachedPsk) {
    return folly::none;
  }

  // TODO T32658838 better API to disable early data for current connection
  const QuicClientConnectionState* conn = getClientConn();
  if (!conn->transportSettings.attemptEarlyData) {
    quicCachedPsk->cachedPsk.maxEarlyDataSize = 0;
  } else if (conn->earlyDataAppParamsHandler) {
    Optional<std::string> alpn;
    if (quicCachedPsk->cachedPsk.alpn.has_value()) {
      alpn = quicCachedPsk->cachedPsk.alpn.value();
    }
    if (!conn->earlyDataAppParamsHandler->validate(
            alpn, BufHelpers::copyBuffer(quicCachedPsk->appParams))) {
      quicCachedPsk->cachedPsk.maxEarlyDataSize = 0;
      // Do not remove psk here, will let application decide
    }
  }

  return quicCachedPsk;
}

void FizzClientHandshake::removePsk(const Optional<std::string>& hostname) {
  fizzContext_->removePsk(hostname);
}

const CryptoFactory& FizzClientHandshake::getCryptoFactory() const {
  return *cryptoFactory_;
}

const Optional<std::string>& FizzClientHandshake::getApplicationProtocol()
    const {
  static thread_local Optional<std::string> result;
  auto& earlyDataParams = state_.earlyDataParams();
  if (earlyDataParams && earlyDataParams->alpn.has_value()) {
    result = earlyDataParams->alpn.value();
    return result;
  } else if (state_.alpn().has_value()) {
    result = state_.alpn().value();
    return result;
  } else {
    static Optional<std::string> empty;
    return empty;
  }
}

quic::Expected<bool, QuicError> FizzClientHandshake::verifyRetryIntegrityTag(
    const ConnectionId& originalDstConnId,
    const RetryPacket& retryPacket) {
  try {
    PseudoRetryPacketBuilder pseudoRetryPacketBuilder(
        retryPacket.initialByte,
        retryPacket.header.getSourceConnId(),
        retryPacket.header.getDestinationConnId(),
        originalDstConnId,
        retryPacket.header.getVersion(),
        BufHelpers::copyBuffer(retryPacket.header.getToken()));

    BufPtr pseudoRetryPacket =
        std::move(pseudoRetryPacketBuilder).buildPacket();

    FizzRetryIntegrityTagGenerator retryIntegrityTagGenerator;
    auto expectedIntegrityTag = retryIntegrityTagGenerator.getRetryIntegrityTag(
        retryPacket.header.getVersion(), pseudoRetryPacket.get());

    Buf integrityTagWrapper = BufHelpers::wrapBufferAsValue(
        retryPacket.integrityTag.data(), retryPacket.integrityTag.size());
    return BufEq()(*expectedIntegrityTag, integrityTagWrapper);
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
  }
}

bool FizzClientHandshake::isTLSResumed() const {
  auto pskType = state_.pskType();
  return pskType && *pskType == fizz::PskType::Resumption;
}

Optional<std::vector<uint8_t>> FizzClientHandshake::getExportedKeyingMaterial(
    const std::string& label,
    const Optional<ByteRange>& context,
    uint16_t keyLength) {
  const auto& ems = state_.exporterMasterSecret();
  const auto cipherSuite = state_.cipher();
  if (!ems.has_value() || !cipherSuite.has_value()) {
    return std::nullopt;
  }

  BufPtr ekm;
  fizz::Error fizzErr;
  FIZZ_THROW_ON_ERROR(
      fizz::Exporter::getExportedKeyingMaterial(
          ekm,
          fizzErr,
          *state_.context()->getFactory(),
          cipherSuite.value(),
          ems.value()->coalesce(),
          label,
          context == std::nullopt ? nullptr : BufHelpers::wrapBuffer(*context),
          keyLength),
      fizzErr);

  std::vector<uint8_t> result(ekm->coalesce());
  return result;
}

EncryptionLevel FizzClientHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

void FizzClientHandshake::processSocketData(quic::IOBufQueue& queue) {
  processActions(
      machine_.processSocketData(state_, queue, fizz::Aead::AeadOptions()));
}

bool FizzClientHandshake::matchEarlyParameters() {
  return fizz::client::earlyParametersMatch(state_);
}

quic::Expected<std::unique_ptr<Aead>, QuicError> FizzClientHandshake::buildAead(
    CipherKind kind,
    ByteRange secret) {
  try {
    bool isEarlyTraffic = kind == CipherKind::ZeroRttWrite;
    fizz::CipherSuite cipher =
        isEarlyTraffic ? state_.earlyDataParams()->cipher : *state_.cipher();
    std::unique_ptr<fizz::KeyScheduler> keySchedulerPtr;
    if (isEarlyTraffic) {
      fizz::Error fizzErr;
      FIZZ_THROW_ON_ERROR(
          state_.context()->getFactory()->makeKeyScheduler(
              keySchedulerPtr, fizzErr, cipher),
          fizzErr);
    }
    fizz::KeyScheduler& keyScheduler =
        isEarlyTraffic ? *keySchedulerPtr : *state_.keyScheduler();

    std::unique_ptr<fizz::Aead> derivedAead;
    fizz::Error fizzErr;
    FIZZ_THROW_ON_ERROR(
        fizz::Protocol::deriveRecordAeadWithLabel(
            derivedAead,
            fizzErr,
            *state_.context()->getFactory(),
            keyScheduler,
            cipher,
            secret,
            kQuicKeyLabel,
            kQuicIVLabel),
        fizzErr);
    auto aead = FizzAead::wrap(std::move(derivedAead));

    return aead;
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
  }
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
FizzClientHandshake::buildHeaderCipher(ByteRange secret) {
  return cryptoFactory_->makePacketNumberCipher(secret);
}

quic::Expected<BufPtr, QuicError> FizzClientHandshake::getNextTrafficSecret(
    ByteRange secret) const {
  try {
    std::unique_ptr<fizz::KeyDerivation> deriver;
    fizz::Error fizzErr;
    FIZZ_THROW_ON_ERROR(
        state_.context()->getFactory()->makeKeyDeriver(
            deriver, fizzErr, *state_.cipher()),
        fizzErr);
    fizz::Buf nextSecret;
    FIZZ_THROW_ON_ERROR(
        deriver->expandLabel(
            nextSecret,
            fizzErr,
            secret,
            kQuicKULabel,
            BufHelpers::create(0),
            secret.size()),
        fizzErr);
    return nextSecret;
  } catch (const std::exception& ex) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
  }
}

void FizzClientHandshake::onNewCachedPsk(
    fizz::client::NewCachedPsk& newCachedPsk) noexcept {
  QuicClientConnectionState* conn = getClientConn();
  MVDCHECK(conn->version.has_value());
  MVDCHECK(conn->serverInitialParamsSet_);

  QuicCachedPsk quicCachedPsk;
  quicCachedPsk.cachedPsk = std::move(newCachedPsk.psk);
  quicCachedPsk.transportParams = getServerCachedTransportParameters(*conn);

  if (conn->earlyDataAppParamsHandler) {
    auto appParams = conn->earlyDataAppParamsHandler->get();
    if (appParams) {
      quicCachedPsk.appParams = appParams->toString();
    }
  }

  Optional<std::string> sni;
  if (state_.sni().has_value()) {
    sni = state_.sni().value();
  }
  fizzContext_->putPsk(sni, std::move(quicCachedPsk));
}

void FizzClientHandshake::echRetryAvailable(
    fizz::client::ECHRetryAvailable& retry) {
  if (echRetryCallback_) {
    echRetryCallback_->retryAvailable(retry);
  }
}

const std::shared_ptr<const fizz::Cert>
FizzClientHandshake::getPeerCertificate() const {
  return state_.serverCert();
}

Handshake::TLSSummary FizzClientHandshake::getTLSSummary() const {
  Handshake::TLSSummary summary;
  if (state_.alpn().has_value()) {
    summary.alpn = state_.alpn().value();
  }
  if (state_.group().has_value()) {
    summary.namedGroup =
        fmt::format("{}", fizz::toString(state_.group().value()));
  }
  if (state_.pskType().has_value()) {
    summary.pskType =
        fmt::format("{}", fizz::toString(state_.pskType().value()));
  }
  if (state_.echState().has_value()) {
    summary.echStatus =
        fizz::client::toString(state_.echState().value().status);
  }
  if (auto version = state_.version()) {
    summary.version = static_cast<uint16_t>(*version);
  }
  return summary;
}

class FizzClientHandshake::ActionMoveVisitor {
 public:
  explicit ActionMoveVisitor(FizzClientHandshake& client) : client_(client) {}

  void operator()(fizz::DeliverAppData&) {
    client_.setError(QuicError(
        TransportErrorCode::PROTOCOL_VIOLATION,
        "Invalid app data on crypto stream"));
  }

  void operator()(fizz::WriteToSocket& write) {
    for (auto& content : write.contents) {
      auto encryptionLevel =
          getEncryptionLevelFromFizz(content.encryptionLevel);
      client_.writeDataToStream(encryptionLevel, std::move(content.data));
    }
  }

  void operator()(fizz::client::ReportEarlyHandshakeSuccess&) {
    client_.computeZeroRttCipher();
  }

  void operator()(fizz::client::ReportHandshakeSuccess& handshakeSuccess) {
    client_.computeOneRttCipher(handshakeSuccess.earlyDataAccepted);
  }

  void operator()(fizz::client::ReportEarlyWriteFailed&) {
    MVLOG_DFATAL << "QUIC TLS app data write";
  }

  void operator()(fizz::ReportError& err) {
    auto errMsg = err.error.what();
    if (errMsg.empty()) {
      errMsg = "Error during handshake";
    }

    auto fe = err.error.get_exception<fizz::FizzException>();

    if (fe && fe->getAlert()) {
      auto alertNum = static_cast<std::underlying_type_t<TransportErrorCode>>(
          fe->getAlert().value());
      alertNum += static_cast<std::underlying_type_t<TransportErrorCode>>(
          TransportErrorCode::CRYPTO_ERROR);
      client_.setError(QuicError(
          static_cast<TransportErrorCode>(alertNum), errMsg.toStdString()));
    } else {
      client_.setError(QuicError(
          static_cast<TransportErrorCode>(
              fizz::AlertDescription::internal_error),
          errMsg.toStdString()));
    }
  }

  void operator()(fizz::WaitForData&) {
    client_.waitForData();
  }

  void operator()(fizz::client::MutateState& mutator) {
    mutator(client_.state_);
  }

  void operator()(fizz::client::NewCachedPsk& newCachedPsk) {
    client_.onNewCachedPsk(newCachedPsk);
  }

  void operator()(fizz::EndOfData&) {
    client_.setError(QuicError(
        TransportErrorCode::INTERNAL_ERROR, "unexpected close notify"));
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    switch (secretAvailable.secret.type.type()) {
      case fizz::SecretType::Type::EarlySecrets_E:
        switch (*secretAvailable.secret.type.asEarlySecrets()) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            client_.computeCiphers(
                CipherKind::ZeroRttWrite,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          default:
            break;
        }
        break;
      case fizz::SecretType::Type::HandshakeSecrets_E:
        switch (*secretAvailable.secret.type.asHandshakeSecrets()) {
          case fizz::HandshakeSecrets::ClientHandshakeTraffic:
            client_.computeCiphers(
                CipherKind::HandshakeWrite,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          case fizz::HandshakeSecrets::ServerHandshakeTraffic:
            client_.computeCiphers(
                CipherKind::HandshakeRead,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          case fizz::HandshakeSecrets::ECHAcceptConfirmation:
            break;
        }
        break;
      case fizz::SecretType::Type::AppTrafficSecrets_E:
        switch (*secretAvailable.secret.type.asAppTrafficSecrets()) {
          case fizz::AppTrafficSecrets::ClientAppTraffic:
            client_.computeCiphers(
                CipherKind::OneRttWrite,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          case fizz::AppTrafficSecrets::ServerAppTraffic:
            client_.computeCiphers(
                CipherKind::OneRttRead,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
        }
        break;
      case fizz::SecretType::Type::MasterSecrets_E:
        break;
    }
  }

  void operator()(fizz::client::ECHRetryAvailable& retry) {
    client_.echRetryAvailable(retry);
  }

 private:
  FizzClientHandshake& client_;
};

void FizzClientHandshake::processActions(fizz::client::Actions actions) {
  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    switch (action.type()) {
      case fizz::client::Action::Type::DeliverAppData_E:
        visitor(*action.asDeliverAppData());
        break;
      case fizz::client::Action::Type::WriteToSocket_E:
        visitor(*action.asWriteToSocket());
        break;
      case fizz::client::Action::Type::ReportHandshakeSuccess_E:
        visitor(*action.asReportHandshakeSuccess());
        break;
      case fizz::client::Action::Type::ReportEarlyHandshakeSuccess_E:
        visitor(*action.asReportEarlyHandshakeSuccess());
        break;
      case fizz::client::Action::Type::ReportEarlyWriteFailed_E:
        visitor(*action.asReportEarlyWriteFailed());
        break;
      case fizz::client::Action::Type::ReportError_E:
        visitor(*action.asReportError());
        break;
      case fizz::client::Action::Type::EndOfData_E:
        visitor(*action.asEndOfData());
        break;
      case fizz::client::Action::Type::MutateState_E:
        visitor(*action.asMutateState());
        break;
      case fizz::client::Action::Type::WaitForData_E:
        visitor(*action.asWaitForData());
        break;
      case fizz::client::Action::Type::NewCachedPsk_E:
        visitor(*action.asNewCachedPsk());
        break;
      case fizz::client::Action::Type::SecretAvailable_E:
        visitor(*action.asSecretAvailable());
        break;
      case fizz::client::Action::Type::ECHRetryAvailable_E:
        visitor(*action.asECHRetryAvailable());
        break;
    }
  }
}

} // namespace quic
