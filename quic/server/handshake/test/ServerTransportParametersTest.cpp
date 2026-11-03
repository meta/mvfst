/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/QuicConstants.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>

#include <fizz/protocol/test/TestUtil.h>

using namespace fizz;
using namespace fizz::test;

namespace quic::test {

static ClientHello getClientHello(QuicVersion version) {
  auto chlo = TestMessages::clientHello();

  ClientTransportParameters clientParams;
  auto paramResult =
      encodeIntegerParameter(static_cast<TransportParameterId>(0xffff), 0xffff);
  CHECK(!paramResult.hasError()) << "Failed to encode integer parameter";
  clientParams.parameters.emplace_back(std::move(paramResult.value()));

  chlo.extensions.push_back(encodeExtension(clientParams, version));

  return chlo;
}

TEST(ServerTransportParametersTest, TestGetExtensions) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  std::vector<Extension> extensions;
  Error err;
  EXPECT_EQ(
      ext.getExtensions(extensions, err, getClientHello(QuicVersion::MVFST)),
      Status::Success);

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
}

TEST(ServerTransportParametersTest, TestGetExtensionsMissingClientParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  std::vector<Extension> extensions;
  Error err;
  EXPECT_THROW(
      FIZZ_THROW_ON_ERROR(
          ext.getExtensions(extensions, err, TestMessages::clientHello()), err),
      FizzException);
}

TEST(ServerTransportParametersTest, TestQuicV1RejectDraftExtensionNumber) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  std::vector<Extension> extensions;
  Error err;
  EXPECT_THROW(
      FIZZ_THROW_ON_ERROR(
          ext.getExtensions(
              extensions, err, getClientHello(QuicVersion::MVFST)),
          err),
      FizzException);
  EXPECT_NO_THROW(FIZZ_THROW_ON_ERROR(
      ext.getExtensions(extensions, err, getClientHello(QuicVersion::QUIC_V1)),
      err));
}

TEST(ServerTransportParametersTest, TestQuicV1RejectDuplicateExtensions) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);

  auto chlo = getClientHello(QuicVersion::QUIC_V1);
  ClientTransportParameters duplicateClientParams;
  auto paramResult =
      encodeIntegerParameter(static_cast<TransportParameterId>(0xffff), 0xffff);
  CHECK(!paramResult.hasError()) << "Failed to encode integer parameter";
  duplicateClientParams.parameters.emplace_back(std::move(paramResult.value()));
  chlo.extensions.push_back(
      encodeExtension(duplicateClientParams, QuicVersion::QUIC_V1));

  std::vector<Extension> extensions;
  Error err;
  EXPECT_THROW(
      FIZZ_THROW_ON_ERROR(ext.getExtensions(extensions, err, chlo), err),
      FizzException);
}

TEST(ServerTransportParametersTest, TestQuicV1Fields) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);
  std::vector<Extension> extensions;
  Error err;
  EXPECT_EQ(
      ext.getExtensions(extensions, err, getClientHello(QuicVersion::QUIC_V1)),
      Status::Success);

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::QUIC_V1);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid =
      std::ranges::any_of(quicTransportParams, [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_TRUE(hasInitialSourceCid);
  auto hasOriginalDestCid =
      std::ranges::any_of(quicTransportParams, [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_TRUE(hasOriginalDestCid);
}

TEST(ServerTransportParametersTest, TestMvfstFields) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);
  std::vector<Extension> extensions;
  Error err;
  EXPECT_EQ(
      ext.getExtensions(extensions, err, getClientHello(QuicVersion::MVFST)),
      Status::Success);

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid =
      std::ranges::any_of(quicTransportParams, [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_FALSE(hasInitialSourceCid);
  auto hasOriginalDestCid =
      std::ranges::any_of(quicTransportParams, [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_FALSE(hasOriginalDestCid);
}

static Optional<ConnectionId> getEncodedRetrySourceCid(
    QuicVersion version,
    const Optional<ConnectionId>& retrySourceCid) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      version,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn,
      /*customTransportParameters=*/{},
      retrySourceCid);
  std::vector<Extension> extensions;
  Error err;
  CHECK(
      ext.getExtensions(extensions, err, getClientHello(version)) ==
      Status::Success);
  auto serverParams = getServerExtension(extensions, version);
  CHECK(serverParams.has_value());
  auto encodedRetrySourceCid = getConnIdParameter(
      TransportParameterId::retry_source_connection_id,
      serverParams->parameters);
  CHECK(encodedRetrySourceCid.has_value());
  return encodedRetrySourceCid.value();
}

TEST(ServerTransportParametersTest, TestRetrySourceCid) {
  auto retrySourceCid = ConnectionId::createAndMaybeCrash(
      std::vector<uint8_t>{0x40, 0x00, 0x07, 0xd6, 0xa1, 0x89, 0x50, 0x41});
  EXPECT_EQ(
      getEncodedRetrySourceCid(QuicVersion::QUIC_V1, retrySourceCid),
      retrySourceCid);
  EXPECT_FALSE(
      getEncodedRetrySourceCid(QuicVersion::QUIC_V1, std::nullopt).has_value());
  EXPECT_FALSE(
      getEncodedRetrySourceCid(QuicVersion::MVFST, retrySourceCid).has_value());
}

} // namespace quic::test
