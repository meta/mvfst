/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/common/TransportKnobs.h>

#include <chrono>
#include <limits>

#include <folly/portability/GTest.h>

namespace quic::test {

struct QuicKnobsParsingTestFixture {
  std::string serializedKnobs;
  bool expectError;
  TransportKnobParams expectParams;
};

void run(const QuicKnobsParsingTestFixture& fixture) {
  auto result = parseTransportKnobs(fixture.serializedKnobs);
  if (fixture.expectError) {
    EXPECT_FALSE(result.has_value());
  } else {
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), fixture.expectParams.size());
    for (size_t i = 0; i < result->size(); i++) {
      auto& actualKnob = (*result)[i];
      auto& expectKnob = fixture.expectParams[i];
      EXPECT_EQ(actualKnob.id, expectKnob.id) << "Knob " << i;
      EXPECT_EQ(actualKnob.val, expectKnob.val) << "Knob " << i;
    }
  }
}

void runDurationRepresentationBoundaryCases(
    TransportKnobParamId knobId,
    uint64_t maxValue) {
  const auto key = static_cast<uint64_t>(knobId);
  ASSERT_LT(maxValue, std::numeric_limits<uint64_t>::max());

  run({
      .serializedKnobs = fmt::format(R"({{{}: {}}})", key, maxValue),
      .expectError = false,
      .expectParams = {{.id = key, .val = maxValue}},
  });
  for (const auto value :
       {maxValue + 1, std::numeric_limits<uint64_t>::max()}) {
    run({
        .serializedKnobs = fmt::format(R"({{{}: {}}})", key, value),
        .expectError = true,
        .expectParams = {},
    });
  }
}

TEST(QuicKnobsParsingTest, KeepaliveDurationRepresentationBounds) {
  runDurationRepresentationBoundaryCases(
      TransportKnobParamId::KEEPALIVE_ENABLED,
      static_cast<uint64_t>(std::chrono::milliseconds::max().count()));
}

TEST(QuicKnobsParsingTest, PacingTickDurationRepresentationBounds) {
  runDurationRepresentationBoundaryCases(
      TransportKnobParamId::PACING_TIMER_TICK,
      static_cast<uint64_t>(std::chrono::microseconds::max().count()));
}

TEST(QuicKnobsParsingTest, Simple) {
  auto id1 = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  auto id2 = static_cast<uint64_t>(TransportKnobParamId::MAX_PTO);
  auto id3 = static_cast<uint64_t>(TransportKnobParamId::KEEPALIVE_ENABLED);
  auto id4 = static_cast<uint64_t>(TransportKnobParamId::PACING_TIMER_TICK);
  std::string args = fmt::format(
      R"({{"{}" : 1, "{}" : 5, "{}" : 6, "{}" : 3}})", id1, id2, id3, id4);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {
          {.id = id3, .val = uint64_t{6}},
          {.id = id1, .val = uint64_t{1}},
          {.id = id4, .val = uint64_t{3}},
          {.id = id2, .val = uint64_t{5}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ObjectValue) {
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs =
          "{ \"1\": "
          "  {"
          "  \"0\" : 1"
          "  }"
          "}",
      .expectError = true,
      .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidJson) {
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs =
          "{\"0\": "
          " \"1\": "
          "  {"
          "  \"0\" : 1"
          "  }"
          "}",
      .expectError = true,
      .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, Characters) {
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = "{ \"o\" : 1 }",
      .expectError = true,
      .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, NegativeNumbers) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  std::string args = fmt::format(R"({{"{}" : -1}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidCCAlgorithm) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB);
  std::string val = "cubic";
  std::string args = fmt::format(R"({{"{}" : "cubic"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, UnknownKnobId) {
  // 0x10003 is the removed DEFAULT_STREAM_PRIORITY knob.
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = R"({"65539" : 4})",
      .expectError = true,
      .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidStringParam) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  std::string args = fmt::format(R"({{"{}" : "foo"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormat) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormatDefault) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormat2) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1,2"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamZeroDenom) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1/0"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamZeroNum) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "0/2"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamLargeDenom) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1/1234567"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamLargeNum) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1234567/1"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidFractionParam) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "4/5"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = uint64_t{4 * 100 + 5}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidFractionParamDefault) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "4/5"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = uint64_t{4 * 100 + 5}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidMaxPacingRate) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  uint64_t val = 111;
  std::string args = fmt::format(R"({{"{}" : {}}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidMaxPacingRateAsString) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  uint64_t val = 111;
  std::string args = fmt::format(R"({{"{}" : "{}"}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, AdaptiveLossReorderingThresholds) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::ADAPTIVE_LOSS_REORDERING_THRESHOLDS);
  std::string args = fmt::format(R"({{"{}" : true}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = uint64_t{1}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidMaxPacingRateAsLargeNumber) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  // Decimal is UINT64_MAX + 1
  std::string args =
      fmt::format(R"({{"{}" : {}}})", key, "18446744073709551616");
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, MaxPacingRateWithSequenceNumber) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
  auto val = "1234,1";
  std::string args = fmt::format(R"({{"{}" : "{}"}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, NonStringKey) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  std::string args = fmt::format(R"({{{} : 1}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args,
      .expectError = false,
      .expectParams = {{.id = key, .val = uint64_t{1}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, DoubleKey) {
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = "{ \"3.14\" : 1 }",
      .expectError = true,
      .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, DoubleValue) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  std::string args = fmt::format(R"({{"{}" : 0.1}})", key);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = args, .expectError = true, .expectParams = {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, UInt64Max) {
  const auto id = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  const uint64_t val = std::numeric_limits<uint64_t>::max();
  std::string str = fmt::format("{{\"{}\" : {}}}", id, val);
  QuicKnobsParsingTestFixture fixture = {
      .serializedKnobs = str,
      .expectError = false,
      .expectParams = {{.id = id, .val = val}}};
  run(fixture);
}

} // namespace quic::test
