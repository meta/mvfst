/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/AppToken.h>

#include <quic/QuicConstants.h>
#include <quic/server/state/ServerStateMachine.h>

#include <gtest/gtest.h>

#include <cstdint>

namespace quic::test {

void expectAppTokenEqual(
    const Optional<AppToken>& decodedAppToken,
    const AppToken& appToken) {
  EXPECT_TRUE(decodedAppToken.has_value());

  EXPECT_EQ(
      decodedAppToken->transportParams.parameters.size(),
      appToken.transportParams.parameters.size());

  EXPECT_GE(
      decodedAppToken->transportParams.parameters.size(),
      kMinimumNumOfParamsInTheTicket);
  // TODO Split out into individual flow control parameters.
  auto maxStreamDataResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(maxStreamDataResult.hasError());
  auto maxStreamData = maxStreamDataResult.value();

  auto expectedMaxStreamDataResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedMaxStreamDataResult.hasError());
  auto expectedMaxStreamData = expectedMaxStreamDataResult.value();
  EXPECT_EQ(maxStreamData, expectedMaxStreamData);

  auto maxDataResult = getIntegerParameter(
      TransportParameterId::initial_max_data,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(maxDataResult.hasError());
  auto maxData = maxDataResult.value();

  auto expectedMaxDataResult = getIntegerParameter(
      TransportParameterId::initial_max_data,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedMaxDataResult.hasError());
  auto expectedMaxData = expectedMaxDataResult.value();
  EXPECT_EQ(maxData, expectedMaxData);

  auto idleTimeoutResult = getIntegerParameter(
      TransportParameterId::idle_timeout,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(idleTimeoutResult.hasError());
  auto idleTimeout = idleTimeoutResult.value();

  auto expectedIdleTimeoutResult = getIntegerParameter(
      TransportParameterId::idle_timeout, appToken.transportParams.parameters);
  EXPECT_FALSE(expectedIdleTimeoutResult.hasError());
  auto expectedIdleTimeout = expectedIdleTimeoutResult.value();
  EXPECT_EQ(idleTimeout, expectedIdleTimeout);

  auto maxRecvPacketSizeResult = getIntegerParameter(
      TransportParameterId::max_packet_size,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(maxRecvPacketSizeResult.hasError());
  auto maxRecvPacketSize = maxRecvPacketSizeResult.value();

  auto expectedMaxRecvPacketSizeResult = getIntegerParameter(
      TransportParameterId::max_packet_size,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedMaxRecvPacketSizeResult.hasError());
  auto expectedMaxRecvPacketSize = expectedMaxRecvPacketSizeResult.value();
  EXPECT_EQ(maxRecvPacketSize, expectedMaxRecvPacketSize);

  auto ackDelayExponentResult = getIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(ackDelayExponentResult.hasError());
  auto ackDelayExponent = ackDelayExponentResult.value();

  auto expectedAckDelayExponentResult = getIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedAckDelayExponentResult.hasError());
  auto expectedAckDelayExponent = expectedAckDelayExponentResult.value();
  EXPECT_EQ(ackDelayExponent, expectedAckDelayExponent);

  auto cwndHintBytesResult = getIntegerParameter(
      TransportParameterId::cwnd_hint_bytes,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(cwndHintBytesResult.hasError());
  auto cwndHintBytes = cwndHintBytesResult.value();

  auto expectedCwndHintBytesResult = getIntegerParameter(
      TransportParameterId::cwnd_hint_bytes,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedCwndHintBytesResult.hasError());
  auto expectedCwndHintBytes = expectedCwndHintBytesResult.value();
  EXPECT_EQ(cwndHintBytes, expectedCwndHintBytes);

  auto extendedAckSupportResult = getIntegerParameter(
      TransportParameterId::extended_ack_features,
      decodedAppToken->transportParams.parameters);
  EXPECT_FALSE(extendedAckSupportResult.hasError());
  auto extendedAckSupport = extendedAckSupportResult.value();

  auto expectedExtendedAckSupportResult = getIntegerParameter(
      TransportParameterId::extended_ack_features,
      appToken.transportParams.parameters);
  EXPECT_FALSE(expectedExtendedAckSupportResult.hasError());
  auto expectedExtendedAckSupport = expectedExtendedAckSupportResult.value();
  EXPECT_EQ(extendedAckSupport, expectedExtendedAckSupport);

  EXPECT_EQ(
      decodedAppToken->sourceAddresses.size(), appToken.sourceAddresses.size());
  for (size_t ii = 0; ii < appToken.sourceAddresses.size(); ++ii) {
    EXPECT_EQ(
        decodedAppToken->sourceAddresses[ii], appToken.sourceAddresses[ii]);
  }

  EXPECT_NE(decodedAppToken->appParams, nullptr);
  if (appToken.appParams) {
    EXPECT_TRUE(
        folly::IOBufEqualTo()(
            *decodedAppToken->appParams, *appToken.appParams));
  } else {
    EXPECT_EQ(decodedAppToken->appParams->computeChainDataLength(), 0);
  }
}

TEST(AppTokenTest, TestEncodeAndDecodeNoSourceAddresses) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeSingleIPv6Address) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeThreeIPv6Addresses) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("2401:db00:2111:7283:face::46:1"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeSingleIPv4Address) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeThreeIPv4Addresses) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.6")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeIPv6AndIPv4Addresses) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeWithAppToken) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.appParams = folly::IOBuf::copyBuffer("QPACK Params");
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeIPv6AndIPv4AddressesWithAppToken) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      2 /* extendedAckSupport */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.appParams = folly::IOBuf::copyBuffer("QPACK Params");
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeCwndHint) {
  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max() - 8,
      std::numeric_limits<uint32_t>::max() - 9,
      2 /* extendedAckSupport */,
      std::numeric_limits<uint32_t>::max() - 10 /* cwndHintBytes */);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.version = QuicVersion::MVFST;
  BufPtr buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

} // namespace quic::test
