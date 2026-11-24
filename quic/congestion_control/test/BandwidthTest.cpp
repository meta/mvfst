/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bandwidth.h>

#include <folly/portability/GTest.h>

using namespace testing;

namespace quic::test {

class BandwidthTest : public Test {};

TEST_F(BandwidthTest, DefaultZero) {
  Bandwidth defaultBandwidth;
  EXPECT_FALSE(defaultBandwidth);
  EXPECT_EQ(0, defaultBandwidth.units);
  EXPECT_TRUE(defaultBandwidth == Bandwidth(0, 100us));
  EXPECT_TRUE(Bandwidth(0, 100us) == Bandwidth(0, 200us));
  EXPECT_TRUE(Bandwidth(0, 1us) < Bandwidth(1, 1000us));
}

TEST_F(BandwidthTest, Compare) {
  Bandwidth lowBandwidth(1000, 100us);
  Bandwidth midBandwidth(2000, 150us);
  Bandwidth highBandwidth(4000, 200us);
  EXPECT_TRUE(lowBandwidth < midBandwidth);
  EXPECT_TRUE(highBandwidth > midBandwidth);
  Bandwidth alsoLowBandwidth(2000, 200us);
  EXPECT_TRUE(lowBandwidth == alsoLowBandwidth);
  EXPECT_TRUE(Bandwidth(1500, 150us) > Bandwidth(700, 100us));
  EXPECT_TRUE(Bandwidth(1500, 150us) >= Bandwidth(700, 100us));
  EXPECT_TRUE(Bandwidth(700, 100us) < Bandwidth(1500, 150us));
  EXPECT_TRUE(Bandwidth(700, 100us) <= Bandwidth(1500, 150us));
  EXPECT_TRUE(Bandwidth(700, 100us) <= Bandwidth(1400, 200us));
  EXPECT_FALSE(Bandwidth(700, 100us) == Bandwidth(701, 100us));
  EXPECT_FALSE(Bandwidth(1, 1us) == Bandwidth());
}

TEST_F(BandwidthTest, CompareWithEmpty) {
  Bandwidth emptyBandwidth, anotherEmpty;
  Bandwidth emptyUnit(0, 1us);
  Bandwidth emptyInterval(15, 0us);
  Bandwidth notEmpty(10, 5us);
  EXPECT_FALSE(emptyBandwidth);
  EXPECT_FALSE(emptyUnit);
  EXPECT_FALSE(emptyInterval);
  EXPECT_TRUE(notEmpty);
  EXPECT_EQ(emptyBandwidth, anotherEmpty);
  EXPECT_EQ(emptyBandwidth, emptyUnit);
  EXPECT_EQ(emptyBandwidth, emptyInterval);
  EXPECT_GT(notEmpty, emptyBandwidth);
  EXPECT_GT(notEmpty, emptyUnit);
  EXPECT_GT(notEmpty, emptyInterval);
}

TEST_F(BandwidthTest, Arithmetics) {
  Bandwidth testBandwidth(1000, 10us);
  EXPECT_TRUE(testBandwidth);
  Bandwidth zeroBandwidth;
  EXPECT_FALSE(zeroBandwidth);
  EXPECT_EQ(0, zeroBandwidth * 20us);
  std::chrono::microseconds longRtt(20), shortRtt(5);
  EXPECT_EQ(500, testBandwidth * shortRtt);
  EXPECT_EQ(2000, testBandwidth * longRtt);
  EXPECT_EQ(4000, testBandwidth * 2 * longRtt);
  EXPECT_EQ(1000, testBandwidth / 2 * longRtt);
  EXPECT_EQ(750, testBandwidth * 1.5 * shortRtt);
  EXPECT_EQ(666, testBandwidth / 3 * longRtt);
}

TEST_F(BandwidthTest, ArithmeticsNumeric) {
  Bandwidth testBandwidth(1000, 10us, true);
  ASSERT_TRUE(testBandwidth.isAppLimited);
  EXPECT_TRUE((testBandwidth / 3).isAppLimited);
  EXPECT_TRUE((testBandwidth * 3).isAppLimited);
}

TEST_F(BandwidthTest, Normalize) {
  Bandwidth testBandwidth(300, 20us);
  EXPECT_EQ(15000000, testBandwidth.normalize());
}

TEST_F(BandwidthTest, Addition) {
  Bandwidth first(600, 20us), second(300, 20us, true);
  ASSERT_FALSE(first.isAppLimited);
  ASSERT_TRUE(second.isAppLimited);
  EXPECT_EQ(Bandwidth(45000000, 1s), first + second);
  EXPECT_TRUE((first + second).isAppLimited);
  first += second;
  EXPECT_EQ(Bandwidth(45000000, 1s), first);
  EXPECT_TRUE(first.isAppLimited);

  // operator+ takes isAppLimited from either operand and leaves both operands
  // unchanged.
  Bandwidth notAppLimited(600, 20us), appLimited(300, 20us, true);
  EXPECT_TRUE((notAppLimited + appLimited).isAppLimited);
  EXPECT_FALSE(notAppLimited.isAppLimited);
  EXPECT_TRUE((appLimited + notAppLimited).isAppLimited);
  EXPECT_FALSE((notAppLimited + notAppLimited).isAppLimited);
}
} // namespace quic::test
