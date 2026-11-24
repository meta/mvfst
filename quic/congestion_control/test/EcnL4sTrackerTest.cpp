/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/EcnL4sTracker.h>

#include <algorithm>

#include <folly/portability/GTest.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>

using namespace testing;

using namespace std::chrono_literals;

namespace {
// These values are the same as the ones in EcnL4sTracker.cpp
constexpr std::chrono::microseconds kRttVirtMin = 25ms;
constexpr double kL4sWeightEwmaGain = 1 / 16.0;
} // namespace

namespace quic::test {
class EcnL4sTrackerTest : public Test {
 public:
  void SetUp() override {
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    l4sTracker_ = std::make_unique<EcnL4sTracker>(*conn_);
  }

  // Records the echoed counts the way the transport does before it builds the
  // AckEvent.
  AckEvent buildAckEvent(
      TimePoint ackTime,
      uint64_t ect0,
      uint64_t ect1,
      uint64_t ce,
      PacketNumberSpace space = PacketNumberSpace::AppData) {
    auto& ackState = space == PacketNumberSpace::AppData
        ? conn_->ackStates.appDataAckState
        : *conn_->ackStates.handshakeAckState;
    ackState.ecnECT0CountEchoed = std::max(ackState.ecnECT0CountEchoed, ect0);
    ackState.ecnECT1CountEchoed = std::max(ackState.ecnECT1CountEchoed, ect1);
    ackState.ecnCECountEchoed = std::max(ackState.ecnCECountEchoed, ce);
    return AckEvent::Builder()
        .setAckTime(ackTime)
        .setAdjustedAckTime(ackTime)
        .setAckDelay(0us)
        .setPacketNumberSpace(space)
        .setLargestAckedPacket(1000)
        .setEcnCounts(ect0 /*ECT0*/, ect1 /*ECT1*/, ce /*CE*/)
        .build();
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  std::unique_ptr<EcnL4sTracker> l4sTracker_;
};

TEST_F(EcnL4sTrackerTest, StartsWithZeroWeight) {
  EXPECT_EQ(l4sTracker_->getL4sWeight(), 0.0);
}

TEST_F(EcnL4sTrackerTest, EmptyAckIsSafe) {
  EXPECT_NO_THROW(l4sTracker_->onPacketAck(nullptr));
}

TEST_F(EcnL4sTrackerTest, NoWeightWithoutCE) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 30ms;

  auto nextAckTime = Clock::now() + 30ms;
  {
    // No CE marks seen in first rtt. The weight should be 0.
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 10 /*ECT1*/, 0 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(l4sTracker_->getL4sWeight(), 0.0);
  }

  {
    // First CE mark is seen one rtt later. The weight should initialized
    // with 1.0 and updated in ewma using fraction of marked packets.
    nextAckTime += 30ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 19 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(
        l4sTracker_->getL4sWeight(),
        1.0 + kL4sWeightEwmaGain * (0.1 - 1.0)); // 0.1 is 1 CE/(9 ECT1 + 1 CE)
  }
}

TEST_F(EcnL4sTrackerTest, WeightChangesOncePerRtt) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 30ms;

  auto nextAckTime = Clock::now() + 30ms;
  {
    // No CE marks seen in first rtt. The weight should be 0.
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 10 /*ECT1*/, 0 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(l4sTracker_->getL4sWeight(), 0.0);
  }

  {
    // We see some CE marks. It hasn't been one rtt yet but this one contains CE
    // marks.
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 10 /*ECT1*/, 2 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(l4sTracker_->getL4sWeight(), 1.0); // The two new marks are CE
  }

  {
    // Another CE mark is seen one rtt later. The weight should initialized
    // with 1.0 and updated in ewma using fraction of marked packets.
    nextAckTime += 30ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 19 /*ECT1*/, 5 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(
        l4sTracker_->getL4sWeight(),
        1.0 +
            kL4sWeightEwmaGain * (0.25 - 1.0)); // 0.25 is 3 CE/(9 ECT1 + 3 CE)
  }
}

TEST_F(EcnL4sTrackerTest, WeightScaledForShortRTT) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 10ms;

  auto nextAckTime = Clock::now() + 10ms;
  {
    // No CE marks seen in first rtt. The weight should be 0.
    // This is under rttVirtMin so it won't trigger weight calculation.
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 10 /*ECT1*/, 0 /*CE*/);
    ack.rttSample = 10ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(l4sTracker_->getL4sWeight(), 0.0);
  }

  {
    // First CE mark is after one rtt later. The weight should initialized
    // with 1.0 and updated in ewma using fraction of marked packets.
    nextAckTime += 10ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 19 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 10ms;

    l4sTracker_->onPacketAck(&ack);
    auto unscaledWeight = 1.0 +
        kL4sWeightEwmaGain * (0.05 - 1.0); // 0.05 is 1 CE/(19 ECT1 + 1 CE)
    auto scaledWeight = unscaledWeight * conn_->lossState.srtt / kRttVirtMin;

    EXPECT_EQ(l4sTracker_->getL4sWeight(), unscaledWeight);
    EXPECT_EQ(l4sTracker_->getNormalizedL4sWeight(), scaledWeight);
  }
}

TEST_F(EcnL4sTrackerTest, ReorderedAckIsIgnored) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 30ms;

  auto nextAckTime = Clock::now() + 30ms;
  {
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 9 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
  }
  const auto weight = l4sTracker_->getL4sWeight();

  {
    // An ACK that the peer sent before the previous one arrives with lower
    // counts.
    nextAckTime += 30ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 8 /*ECT1*/, 0 /*CE*/);
    ack.rttSample = 30ms;

    EXPECT_NO_THROW(l4sTracker_->onPacketAck(&ack));
    EXPECT_EQ(l4sTracker_->getL4sWeight(), weight);
  }

  {
    // The next update covers the marks since the previous one.
    nextAckTime += 30ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 12 /*ECT1*/, 2 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(
        l4sTracker_->getL4sWeight(),
        weight + kL4sWeightEwmaGain * (0.25 - weight)); // 1 CE/(3 ECT1 + 1 CE)
  }
}

TEST_F(EcnL4sTrackerTest, AckForAnotherSpaceIsIgnored) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 30ms;

  auto nextAckTime = Clock::now() + 30ms;
  {
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 9 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
  }
  const auto weight = l4sTracker_->getL4sWeight();

  // Each packet number space has its own counts.
  nextAckTime += 30ms;
  auto ack = buildAckEvent(
      nextAckTime,
      0 /*ECT0*/,
      2 /*ECT1*/,
      0 /*CE*/,
      PacketNumberSpace::Handshake);
  ack.rttSample = 30ms;

  EXPECT_NO_THROW(l4sTracker_->onPacketAck(&ack));
  EXPECT_EQ(l4sTracker_->getL4sWeight(), weight);
}

TEST_F(EcnL4sTrackerTest, NoUpdateWithNoNewMarks) {
  conn_->ecnState = ECNState::ValidatedL4S;

  conn_->lossState.srtt = 30ms;

  auto nextAckTime = Clock::now() + 30ms;
  {
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 9 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(
        l4sTracker_->getL4sWeight(),
        1.0 + kL4sWeightEwmaGain * (0.1 - 1.0)); // 0.1 is 1 CE/(9 ECT1 + 1 CE)
  }

  {
    nextAckTime += 60ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 9 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 30ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(
        l4sTracker_->getL4sWeight(),
        1.0 + kL4sWeightEwmaGain * (0.1 - 1.0)); // 0.1 is 1 CE/(9 ECT1 + 1 CE)
  }
}

TEST_F(EcnL4sTrackerTest, NewMarksNotifyObserver) {
  MockQuicSocket mockSocket;
  const auto observerContainer =
      std::make_shared<SocketObserverContainer>(&mockSocket);
  conn_->observerContainer = observerContainer;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::l4sWeightUpdatedEvents);
  auto observer = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  observerContainer->addObserver(observer.get());

  conn_->ecnState = ECNState::ValidatedL4S;
  conn_->lossState.srtt = 10ms;
  auto nextAckTime = Clock::now() + 10ms;
  {
    // No CE marks seen in first rtt. The weight should be 0.
    // This is under rttVirtMin so it won't trigger weight calculation.
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 10 /*ECT1*/, 0 /*CE*/);
    ack.rttSample = 10ms;

    l4sTracker_->onPacketAck(&ack);
    EXPECT_EQ(l4sTracker_->getL4sWeight(), 0.0);
  }

  {
    // First CE mark is after one rtt later. The weight should initialized
    // with 1.0 and updated in ewma using fraction of marked packets.
    auto unscaledWeight = 1.0 +
        kL4sWeightEwmaGain * (0.05 - 1.0); // 0.05 is 1 CE/(19 ECT1 + 1 CE)
    EXPECT_CALL(*observer, l4sWeightUpdated(_, _))
        .WillOnce(Invoke(
            [&](auto, const MockLegacyObserver::L4sWeightUpdateEvent& event) {
              EXPECT_EQ(event.l4sWeight, unscaledWeight);
              EXPECT_EQ(event.newECT1Echoed, 19);
              EXPECT_EQ(event.newCEEchoed, 1);
            }));

    nextAckTime += 10ms;
    auto ack = buildAckEvent(nextAckTime, 0 /*ECT0*/, 19 /*ECT1*/, 1 /*CE*/);
    ack.rttSample = 10ms;
    l4sTracker_->onPacketAck(&ack);
    auto scaledWeight = unscaledWeight * conn_->lossState.srtt / kRttVirtMin;

    EXPECT_EQ(l4sTracker_->getL4sWeight(), unscaledWeight);
    EXPECT_EQ(l4sTracker_->getNormalizedL4sWeight(), scaledWeight);
  }

  observerContainer->removeObserver(observer.get());
}

} // namespace quic::test
