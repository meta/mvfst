/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/server/handshake/ServerHandshake.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/state/ConnectionOopsFields.h>
#include <quic/state/QuicStreamFunctions.h>
#include <cstdint>

namespace quic {

ServerHandshake::ServerHandshake(QuicConnectionStateBase* conn)
    : conn_(conn), actionGuard_(nullptr), cryptoState_(*conn->cryptoState) {}

void ServerHandshake::accept(
    std::shared_ptr<ServerTransportParametersExtension> transportParams) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  transportParams_ = std::move(transportParams);
  inHandshakeStack_ = true;
  processAccept();
}

void ServerHandshake::initialize(
    folly::Executor* executor,
    HandshakeCallback* callback,
    folly::Optional<QuicVersion> quicVersion,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  executor_ = executor;
  initializeImpl(callback, std::move(validator), std::move(quicVersion));
}

quic::Expected<void, QuicError> ServerHandshake::doHandshake(
    BufPtr data,
    EncryptionLevel encryptionLevel) {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  waitForData_ = false;
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      initialReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::Handshake:
      handshakeReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::EarlyData:
    case EncryptionLevel::AppData:
      appDataReadBuf_.append(std::move(data));
      break;
    default:
      MVCHECK(false, "Unhandled EncryptionLevel");
  }
  checkForUnexpectedCryptoData();
  processPendingEvents();
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return {};
}

quic::Expected<void, QuicError> ServerHandshake::writeNewSessionTicket(
    const AppToken& appToken) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  writeNewSessionTicketToCrypto(appToken);
  processPendingEvents();
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return {};
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getHandshakeReadCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(handshakeReadCipher_);
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getFirstOneRttWriteCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(oneRttWriteCipher_);
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getNextOneRttWriteCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  PROTO_OOPS_LOG_BUILDER_IF(
      !writeTrafficSecret_,
      conn_->oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
      "quic_server_handshake",
      "invariant_violation: next one-rtt write cipher missing traffic "
      "secret");
  MVCHECK(writeTrafficSecret_);
  LOG_IF(WARNING, trafficSecretSync_ > 1 || trafficSecretSync_ < -1)
      << "Server read and write secrets are out of sync";
  writeTrafficSecret_ = getNextTrafficSecret(writeTrafficSecret_->coalesce());
  trafficSecretSync_--;
  auto cipher = buildAead(writeTrafficSecret_->coalesce());
  return cipher;
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getFirstOneRttReadCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(oneRttReadCipher_);
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getNextOneRttReadCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  PROTO_OOPS_LOG_BUILDER_IF(
      !readTrafficSecret_,
      conn_->oopsLogger,
      proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
      "quic_server_handshake",
      "invariant_violation: next one-rtt read cipher missing traffic secret");
  MVCHECK(readTrafficSecret_);
  LOG_IF(WARNING, trafficSecretSync_ > 1 || trafficSecretSync_ < -1)
      << "Server read and write secrets are out of sync";
  readTrafficSecret_ = getNextTrafficSecret(readTrafficSecret_->coalesce());
  trafficSecretSync_++;
  auto cipher = buildAead(readTrafficSecret_->coalesce());
  return cipher;
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ServerHandshake::getZeroRttReadCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(zeroRttReadCipher_);
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
ServerHandshake::getOneRttReadHeaderCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(oneRttReadHeaderCipher_);
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
ServerHandshake::getOneRttWriteHeaderCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(oneRttWriteHeaderCipher_);
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
ServerHandshake::getHandshakeReadHeaderCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(handshakeReadHeaderCipher_);
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
ServerHandshake::getZeroRttReadHeaderCipher() {
  if (error_) {
    return quic::make_unexpected(
        QuicError(error_->second, std::move(error_->first)));
  }
  return std::move(zeroRttReadHeaderCipher_);
}

/**
 * The application will not get any more callbacks from the handshake layer
 * after this method returns.
 */
void ServerHandshake::cancel() {
  callback_ = nullptr;
}

ServerHandshake::Phase ServerHandshake::getPhase() const {
  return phase_;
}

bool ServerHandshake::hasReportedEarlyHandshakeSuccess() const {
  return reportedEarlyHandshakeSuccess_;
}

bool ServerHandshake::hasReportedHandshakeSuccess() const {
  return reportedHandshakeSuccess_;
}

Optional<ClientTransportParameters>
ServerHandshake::getClientTransportParams() {
  if (!transportParams_) {
    return std::nullopt;
  }
  return transportParams_->getClientTransportParams();
}

bool ServerHandshake::isHandshakeDone() {
  return handshakeDone_;
}

const fizz::server::State& ServerHandshake::getState() const {
  return state_;
}

Optional<std::vector<uint8_t>> ServerHandshake::getExportedKeyingMaterial(
    const std::string& label,
    const Optional<ByteRange>& context,
    uint16_t keyLength) {
  const auto cipherSuite = state_.cipher();
  const auto& ems = state_.exporterMasterSecret();
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

const Optional<std::string>& ServerHandshake::getApplicationProtocol() const {
  static Optional<std::string> empty;
  if (!state_.alpn().has_value()) {
    return empty;
  }
  static thread_local Optional<std::string> result;
  result = state_.alpn().value();
  return result;
}

void ServerHandshake::onError(
    const std::pair<std::string, TransportErrorCode>& error) {
  MVVLOG(10) << "ServerHandshake error " << error.first;
  error_ = error;
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onWriteData(fizz::WriteToSocket& write) {
  if (!callback_) {
    // We've been canceled, just return. If we're canceled it's possible that
    // cryptoState_ has been deleted, so let's not refer to it.
    return;
  }
  for (auto& content : write.contents) {
    auto encryptionLevel = getEncryptionLevelFromFizz(content.encryptionLevel);
    PROTO_OOPS_LOG_BUILDER_IF(
        encryptionLevel == EncryptionLevel::EarlyData,
        conn_->oopsLogger,
        proto_oops::makeConnectionSpecificOopsFieldsBuilder(*conn_),
        "quic_server_handshake",
        "invariant_violation: server attempted to write early data");
    MVCHECK(
        encryptionLevel != EncryptionLevel::EarlyData,
        "Server cannot write early data");
    if (content.contentType != fizz::ContentType::handshake) {
      continue;
    }
    auto cryptoStream = getCryptoStream(cryptoState_, encryptionLevel);
    writeDataToQuicStream(*conn_, *cryptoStream, std::move(content.data));
  }
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onHandshakeDone() {
  handshakeEventAvailable_ = true;
}

void ServerHandshake::addProcessingActions(fizz::server::AsyncActions actions) {
  if (actionGuard_) {
    onError(
        std::make_pair(
            "Processing action while pending",
            TransportErrorCode::INTERNAL_ERROR));
    return;
  }
  actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
  startActions(std::move(actions));
}

void ServerHandshake::startActions(fizz::server::AsyncActions actions) {
  folly::variant_match(
      actions,
      [this](folly::SemiFuture<fizz::server::Actions>& futureActions) {
        std::move(futureActions)
            .via(executor_)
            .then(&ServerHandshake::processActions, this);
      },
      [this](fizz::server::Actions& immediateActions) {
        this->processActions(std::move(immediateActions));
      });
}

void ServerHandshake::processPendingEvents() {
  if (inProcessPendingEvents_) {
    return;
  }

  folly::DelayedDestruction::DestructorGuard dg(conn_);
  inProcessPendingEvents_ = true;
  SCOPE_EXIT {
    inProcessPendingEvents_ = false;
  };

  while (!actionGuard_ && !error_) {
    actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
    if (!waitForData_) {
      switch (getReadRecordLayerEncryptionLevel()) {
        case EncryptionLevel::Initial:
          processSocketData(initialReadBuf_);
          break;
        case EncryptionLevel::Handshake:
          processSocketData(handshakeReadBuf_);
          break;
        case EncryptionLevel::EarlyData:
        case EncryptionLevel::AppData:
          // TODO: Get rid of appDataReadBuf_ once we do not need EndOfEarlyData
          // any more.
          processSocketData(appDataReadBuf_);
          break;
        default:
          MVCHECK(false, "Unhandled EncryptionLevel");
      }
    } else if (!processPendingCryptoEvent()) {
      actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
      return;
    }
  }
}

void ServerHandshake::checkForUnexpectedCryptoData() {
  if (error_) {
    return;
  }
  const auto readLevel = getReadRecordLayerEncryptionLevel();
  if ((readLevel != EncryptionLevel::Initial && !initialReadBuf_.empty()) ||
      (readLevel == EncryptionLevel::AppData && !handshakeReadBuf_.empty())) {
    onError(
        std::make_pair(
            "Unexpected crypto data at an obsolete encryption level",
            TransportErrorCode::PROTOCOL_VIOLATION));
  }
}

const Optional<BufPtr>& ServerHandshake::getAppToken() const {
  static Optional<BufPtr> empty;
  if (!state_.appToken().has_value()) {
    return empty;
  }
  static thread_local Optional<BufPtr> result;
  result = state_.appToken().value()->clone();
  return result;
}

Handshake::TLSSummary ServerHandshake::getTLSSummary() const {
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
    summary.echStatus = fizz::server::toString(state_.echStatus());
  }
  if (auto version = state_.version()) {
    summary.version = static_cast<uint16_t>(*version);
  }
  return summary;
}

class ServerHandshake::ActionMoveVisitor {
 public:
  explicit ActionMoveVisitor(ServerHandshake& server) : server_(server) {}

  void operator()(fizz::DeliverAppData&) {
    server_.onError(
        std::make_pair(
            "Unexpected data on crypto stream",
            TransportErrorCode::PROTOCOL_VIOLATION));
  }

  void operator()(fizz::WriteToSocket& write) {
    server_.onWriteData(write);
  }

  void operator()(fizz::server::ReportEarlyHandshakeSuccess&) {
    server_.reportedEarlyHandshakeSuccess_ = true;
    server_.phase_ = Phase::KeysDerived;
  }

  void operator()(fizz::server::ReportHandshakeSuccess&) {
    server_.handshakeDone_ = true;
    server_.reportedHandshakeSuccess_ = true;
    auto originalPhase = server_.phase_;
    // Fizz only reports handshake success when the server receives the full
    // client finished. At this point we can write any post handshake data and
    // crypto data with the 1-rtt keys.
    server_.phase_ = Phase::Established;
    if (originalPhase != Phase::Handshake) {
      // We already derived the zero rtt keys as well as the one rtt write
      // keys.
      server_.onHandshakeDone();
    }
  }

  void operator()(fizz::ReportError& err) {
    auto errMsg = err.error.what();
    if (errMsg.empty()) {
      errMsg = "Error during handshake";
    }

    auto fe = err.error.get_exception<fizz::FizzException>();

    if (fe && fe->getAlert()) {
      auto alertNum =
          static_cast<std::underlying_type<TransportErrorCode>::type>(
              fe->getAlert().value());
      alertNum += static_cast<std::underlying_type<TransportErrorCode>::type>(
          TransportErrorCode::CRYPTO_ERROR);
      server_.onError(
          std::make_pair(
              errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum)));
    } else {
      server_.onError(
          std::make_pair(
              errMsg.toStdString(),
              static_cast<TransportErrorCode>(
                  fizz::AlertDescription::internal_error)));
    }
  }

  void operator()(fizz::WaitForData&) {
    server_.waitForData_ = true;
  }

  void operator()(fizz::server::MutateState& mutator) {
    mutator(server_.state_);
  }

  void operator()(fizz::server::AttemptVersionFallback&) {
    MVCHECK(false, "Fallback Unexpected");
  }

  void operator()(fizz::EndOfData&) {
    server_.onError(
        std::make_pair(
            "Unexpected close notify received",
            TransportErrorCode::INTERNAL_ERROR));
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    switch (secretAvailable.secret.type.type()) {
      case fizz::SecretType::Type::EarlySecrets_E:
        switch (*secretAvailable.secret.type.asEarlySecrets()) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            server_.computeCiphers(
                CipherKind::ZeroRttRead,
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
            server_.computeCiphers(
                CipherKind::HandshakeRead,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          case fizz::HandshakeSecrets::ServerHandshakeTraffic:
            server_.computeCiphers(
                CipherKind::HandshakeWrite,
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
            server_.computeCiphers(
                CipherKind::OneRttRead,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
          case fizz::AppTrafficSecrets::ServerAppTraffic:
            server_.computeCiphers(
                CipherKind::OneRttWrite,
                ByteRange(
                    secretAvailable.secret.secret.data(),
                    secretAvailable.secret.secret.size()));
            break;
        }
        break;
      case fizz::SecretType::Type::MasterSecrets_E:
        break;
    }
    server_.handshakeEventAvailable_ = true;
  }

 private:
  ServerHandshake& server_;
};

void ServerHandshake::processActions(
    fizz::server::ServerStateMachine::CompletedActions actions) {
  // This extra DestructorGuard is needed due to the gap between clearing
  // actionGuard_ and potentially processing another action.
  folly::DelayedDestruction::DestructorGuard dg(conn_);

  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    switch (action.type()) {
      case fizz::server::Action::Type::DeliverAppData_E:
        visitor(*action.asDeliverAppData());
        break;
      case fizz::server::Action::Type::WriteToSocket_E:
        visitor(*action.asWriteToSocket());
        break;
      case fizz::server::Action::Type::ReportHandshakeSuccess_E:
        visitor(*action.asReportHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportEarlyHandshakeSuccess_E:
        visitor(*action.asReportEarlyHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportError_E:
        visitor(*action.asReportError());
        break;
      case fizz::server::Action::Type::EndOfData_E:
        visitor(*action.asEndOfData());
        break;
      case fizz::server::Action::Type::MutateState_E:
        visitor(*action.asMutateState());
        break;
      case fizz::server::Action::Type::WaitForData_E:
        visitor(*action.asWaitForData());
        break;
      case fizz::server::Action::Type::AttemptVersionFallback_E:
        visitor(*action.asAttemptVersionFallback());
        break;
      case fizz::server::Action::Type::SecretAvailable_E:
        visitor(*action.asSecretAvailable());
        break;
    }
  }

  checkForUnexpectedCryptoData();
  actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
  if (callback_ && !inHandshakeStack_ && handshakeEventAvailable_) {
    callback_->onCryptoEventAvailable();
  }
  handshakeEventAvailable_ = false;
  processPendingEvents();
}

void ServerHandshake::computeCiphers(CipherKind kind, ByteRange secret) {
  std::unique_ptr<Aead> aead = buildAead(secret);
  auto headerCipherResult = buildHeaderCipher(secret);
  if (headerCipherResult.hasError()) {
    MVLOG_ERROR << "Failed to build header cipher";
    onError(
        std::make_pair(
            "Failed to build header cipher",
            TransportErrorCode::INTERNAL_ERROR));
    return;
  }
  std::unique_ptr<PacketNumberCipher> headerCipher =
      std::move(headerCipherResult.value());

  switch (kind) {
    case CipherKind::HandshakeRead:
      handshakeReadCipher_ = std::move(aead);
      handshakeReadHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::HandshakeWrite:
      conn_->handshakeWriteCipher = std::move(aead);
      conn_->handshakeWriteHeaderCipher = std::move(headerCipher);
      break;
    case CipherKind::OneRttRead:
      readTrafficSecret_ = BufHelpers::copyBuffer(secret);
      oneRttReadCipher_ = std::move(aead);
      oneRttReadHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::OneRttWrite:
      writeTrafficSecret_ = BufHelpers::copyBuffer(secret);
      oneRttWriteCipher_ = std::move(aead);
      oneRttWriteHeaderCipher_ = std::move(headerCipher);
      break;
    case CipherKind::ZeroRttRead:
      zeroRttReadCipher_ = std::move(aead);
      zeroRttReadHeaderCipher_ = std::move(headerCipher);
      break;
    default:
      folly::assume_unreachable();
  }
  handshakeEventAvailable_ = true;
}

} // namespace quic
