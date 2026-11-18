/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/C4.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/test/Mocks.h>

#include <algorithm>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <vector>

using namespace testing;

namespace quic::test {

namespace {

using State = C4CongestionController::State;

constexpr uint64_t kPacketSize = 1000;

// The sensitivity curve from the spec, for rates in bytes per second.
double sensitivity(uint64_t rate) {
  if (rate < 50'000) {
    return 0;
  }
  if (rate > 10'000'000) {
    return 1;
  }
  if (rate < 1'000'000) {
    return 0.94 * static_cast<double>(rate - 50'000) / 950'000;
  }
  return 0.94 + 0.06 * static_cast<double>(rate - 1'000'000) / 9'000'000;
}

// The smoothed loss rate after `losses` losses of consecutive packets.
double lossRateAfter(uint64_t losses) {
  double rate = 0;
  for (uint64_t i = 0; i < losses; i++) {
    rate *= 15.0 / 16;
    rate += (1 - rate) / 16;
  }
  return rate;
}

uint64_t lossesToSignal(uint64_t rate) {
  const double threshold = 0.02 + 0.5 * (1 - sensitivity(rate));
  uint64_t losses = 1;
  while (lossRateAfter(losses) <= threshold) {
    losses++;
  }
  return losses;
}

} // namespace

class C4Test : public Test {
 public:
  void SetUp() override {
    auto pacer = std::make_unique<NiceMock<MockPacer>>();
    pacer_ = pacer.get();
    ON_CALL(*pacer_, refreshPacingRate(_, _, _))
        .WillByDefault(
            [this](
                uint64_t bytes, std::chrono::microseconds interval, TimePoint) {
              pacingBytes_ = bytes;
              pacingInterval_ = interval;
            });
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
    conn_->pacer = std::move(pacer);
    conn_->udpSendPacketLen = kPacketSize;
    // With one-packet bursts, C4 paces at every rate that these tests use.
    conn_->transportSettings.minBurstPackets = 1;
    conn_->qLogger = qLogger_;
    conn_->connectionTime = Clock::now();
    now_ = conn_->connectionTime;
  }

 protected:
  // Replaces the mock pacer with mvfst's pacer and its default minimum burst.
  TokenlessPacer& useTokenlessPacer() {
    conn_->transportSettings.minBurstPackets = kDefaultMinBurstPackets;
    auto pacer = std::make_unique<TokenlessPacer>(*conn_, kMinCwndInMssForBbr);
    auto& tokenlessPacer = *pacer;
    conn_->pacer = std::move(pacer);
    pacer_ = nullptr;
    return tokenlessPacer;
  }

  // The qlog trigger of the latest state change.
  [[nodiscard]] std::string lastStateTrigger() const {
    std::string trigger;
    for (const auto index :
         getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger_)) {
      const auto* update = dynamic_cast<const QLogCongestionStateUpdateEvent*>(
          qLogger_->logs[index].get());
      if (update && update->trigger) {
        trigger = *update->trigger;
      }
    }
    return trigger;
  }

  // Sends one AppData packet and records it the way the transport does.
  PacketNum send(C4CongestionController& c4, TimePoint time) {
    const auto packetNum = conn_->ackStates.appDataAckState.nextPacketNum++;
    auto& lossState = conn_->lossState;
    lossState.totalBytesSent += kPacketSize;
    auto packet = makeTestingWritePacket(
        packetNum, kPacketSize, lossState.totalBytesSent, time);
    packet.isAppLimited = c4.isAppLimited();
    packet.lastAckedPacketInfo.reset();
    if (lossState.lastAckedTime) {
      packet.lastAckedPacketInfo.emplace(
          *lossState.lastAckedPacketSentTime,
          *lossState.lastAckedTime,
          *lossState.adjustedLastAckedTime,
          lossState.totalBytesSentAtLastAck,
          lossState.totalBytesAckedAtLastAck);
    }
    onPacketsSentWrapper(conn_.get(), &c4, packet);
    outstanding_.emplace(packetNum, std::move(packet));
    return packetNum;
  }

  // Acks `packetNums` the way the transport does. The peer echoes CE for the
  // next `ceMarksLeft_` packets and ECT(1) for the others. The same ACK
  // declares lost every outstanding packet at least three below the largest
  // acked packet.
  void ack(
      C4CongestionController& c4,
      const std::vector<PacketNum>& packetNums,
      TimePoint ackTime,
      std::chrono::microseconds ackDelay = 0us) {
    const auto largestAcked = std::ranges::max(packetNums);
    auto ackEvent = AckEvent::Builder()
                        .setAckTime(ackTime)
                        .setAdjustedAckTime(ackTime - ackDelay)
                        .setAckDelay(ackDelay)
                        .setPacketNumberSpace(PacketNumberSpace::AppData)
                        .setLargestAckedPacket(largestAcked)
                        .build();
    auto& lossState = conn_->lossState;
    auto& ackState = conn_->ackStates.appDataAckState;
    for (const auto packetNum : packetNums) {
      if (ceMarksLeft_ > 0) {
        ceMarksLeft_--;
        ackState.ecnCECountEchoed++;
      } else {
        ackState.ecnECT1CountEchoed++;
      }
      auto& packet = outstanding_.at(packetNum);
      ackEvent.ackedBytes += packet.metadata.encodedSize;
      lossState.totalBytesAcked += packet.metadata.encodedSize;
      ackEvent.ackedPackets.push_back(
          AckEvent::AckPacket::Builder()
              .setPacketNum(packetNum)
              .setOutstandingPacketMetadata(packet.metadata)
              .setLastAckedPacketInfo(
                  packet.lastAckedPacketInfo ? &*packet.lastAckedPacketInfo
                                             : nullptr)
              .setAppLimited(packet.isAppLimited)
              .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
              .build());
      if (!ackEvent.largestNewlyAckedPacket ||
          packetNum > *ackEvent.largestNewlyAckedPacket) {
        ackEvent.largestNewlyAckedPacket = packetNum;
        ackEvent.largestNewlyAckedPacketSentTime = packet.metadata.time;
      }
    }
    ackEvent.totalBytesAcked = lossState.totalBytesAcked;
    ackEvent.ecnECT1Count = ackState.ecnECT1CountEchoed;
    ackEvent.ecnCECount = ackState.ecnCECountEchoed;
    const auto rttSample = std::chrono::ceil<std::chrono::microseconds>(
        ackTime - ackEvent.largestNewlyAckedPacketSentTime);
    ackEvent.rttSample = rttSample;
    updateRtt(*conn_, rttSample, ackDelay);
    lossState.lastAckedPacketSentTime =
        ackEvent.largestNewlyAckedPacketSentTime;
    lossState.lastAckedTime = ackTime;
    lossState.adjustedLastAckedTime = ackTime - ackDelay;
    lossState.totalBytesSentAtLastAck = lossState.totalBytesSent;
    lossState.totalBytesAckedAtLastAck = lossState.totalBytesAcked;
    for (const auto packetNum : packetNums) {
      outstanding_.erase(packetNum);
    }

    Optional<LossEvent> lossEvent;
    while (!outstanding_.empty() &&
           outstanding_.begin()->first + 3 <= largestAcked) {
      if (!lossEvent) {
        lossEvent.emplace(ackTime);
      }
      lossEvent->addLostPacket(outstanding_.begin()->second);
      outstanding_.erase(outstanding_.begin());
    }
    lostPackets_ += lossEvent ? lossEvent->lostPackets : 0;
    acks_++;
    onPacketAckOrLossWrapper(
        conn_.get(), &c4, std::move(ackEvent), std::move(lossEvent));
  }

  void loseOnTimer(
      C4CongestionController& c4,
      const std::vector<PacketNum>& packetNums,
      TimePoint lossTime) {
    LossEvent lossEvent(lossTime);
    for (const auto packetNum : packetNums) {
      lossEvent.addLostPacket(outstanding_.at(packetNum));
      outstanding_.erase(packetNum);
    }
    onPacketAckOrLossWrapper(
        conn_.get(), &c4, std::nullopt, std::move(lossEvent));
  }

  // Starts an open-loop flow with a fixed packet spacing, so that every rate
  // sample equals `rate` bytes per second. The first packet sees `minRtt`, and
  // later ones also wait `queueDelay`, which makes the flow network limited.
  void startFlow(
      C4CongestionController& c4,
      uint64_t rate,
      std::chrono::microseconds minRtt,
      std::chrono::microseconds queueDelay = 1ms) {
    flowRate_ = rate;
    flowRtt_ = minRtt;
    flowSending_ = true;
    nextSendTime_ = now_;
    sendNext(c4);
    flowRtt_ = minRtt + queueDelay;
  }

  void sendNext(C4CongestionController& c4) {
    now_ = nextSendTime_;
    const auto packetNum = send(c4, now_);
    if (flowAppLimited_) {
      c4.setAppLimited();
    }
    if (dropsLeft_ > 0) {
      dropsLeft_--;
    } else {
      // The path delivers packets in order.
      auto ackTime = now_ + flowRtt_;
      if (!pendingAcks_.empty()) {
        ackTime = std::max(ackTime, pendingAcks_.back().first);
      }
      pendingAcks_.emplace_back(ackTime, packetNum);
    }
    nextSendTime_ +=
        std::chrono::microseconds(kPacketSize * 1'000'000 / flowRate_);
  }

  // Processes the next ACK or send of the flow, ACKs first when both are due.
  void step(C4CongestionController& c4) {
    if (!pendingAcks_.empty() &&
        (!flowSending_ || pendingAcks_.front().first <= nextSendTime_)) {
      const auto [ackTime, packetNum] = pendingAcks_.front();
      pendingAcks_.pop_front();
      now_ = ackTime;
      cwndBeforeLastAck_ = c4.getCongestionWindow();
      ack(c4, {packetNum}, ackTime);
      cwndChanges_.push_back(
          static_cast<int64_t>(c4.getCongestionWindow()) -
          static_cast<int64_t>(cwndBeforeLastAck_));
    } else if (flowSending_) {
      sendNext(c4);
    }
  }

  [[nodiscard]] bool runUntil(
      C4CongestionController& c4,
      const std::function<bool()>& done) {
    for (int i = 0; i < 1'000'000 && !done(); i++) {
      if (pendingAcks_.empty() && !flowSending_) {
        break;
      }
      step(c4);
    }
    return done();
  }

  [[nodiscard]] bool runUntilState(C4CongestionController& c4, State state) {
    return runUntil(c4, [&] { return c4.getState() == state; });
  }

  void runFor(C4CongestionController& c4, std::chrono::microseconds duration) {
    const auto end = now_ + duration;
    while (true) {
      auto next = flowSending_ ? nextSendTime_ : TimePoint::max();
      if (!pendingAcks_.empty()) {
        next = std::min(next, pendingAcks_.front().first);
      }
      if (next > end) {
        break;
      }
      step(c4);
    }
    now_ = end;
  }

  void ackNext(C4CongestionController& c4) {
    const auto acks = acks_;
    while (acks_ == acks) {
      step(c4);
    }
  }

  // Stops sending and processes the ACKs of every packet in flight.
  void drain(C4CongestionController& c4) {
    flowSending_ = false;
    while (!pendingAcks_.empty()) {
      step(c4);
    }
  }

  void resume() {
    flowSending_ = true;
    nextSendTime_ = now_;
  }

  // Makes the next pending ACK arrive `rtt` after its packet was sent.
  void setNextAckRtt(std::chrono::microseconds rtt) {
    auto& [ackTime, packetNum] = pendingAcks_.front();
    ackTime = outstanding_.at(packetNum).metadata.time + rtt;
    for (size_t i = 1; i < pendingAcks_.size(); i++) {
      pendingAcks_[i].first =
          std::max(pendingAcks_[i].first, pendingAcks_[i - 1].first);
    }
  }

  // Sends `count` packets at once.
  std::vector<PacketNum> sendBurst(C4CongestionController& c4, int count) {
    std::vector<PacketNum> burst(count);
    for (auto& packetNum : burst) {
      packetNum = send(c4, now_);
    }
    return burst;
  }

  // Sends `count` packets at once and acks them together `rtt` later.
  void sendAndAckBurst(
      C4CongestionController& c4,
      int count,
      std::chrono::microseconds rtt) {
    const auto burst = sendBurst(c4, count);
    now_ += rtt;
    ack(c4, burst, now_);
  }

  // Sends four packets and acks the last three together, which declares the
  // first one lost.
  void loseOneOfFour(C4CongestionController& c4) {
    const auto packets = sendBurst(c4, 4);
    now_ += 21ms;
    ack(c4, {packets[1], packets[2], packets[3]}, now_);
  }

  // Runs a 1 MB/s flow until Recovery drains at 15/16, which happens once
  // the Initial backlog is gone, and then acks every packet in flight.
  void runToGentleRecovery(C4CongestionController& c4) {
    startFlow(c4, 1'000'000, 20ms);
    ASSERT_TRUE(runUntil(c4, [&] {
      return c4.getState() == State::Recovery && pacingGain(c4) == 15.0 / 16;
    }));
    drain(c4);
  }

  // Runs an app-limited flow, which stays in Cruising, and then drops
  // `losses` packets in a row.
  void dropInCruising(
      C4CongestionController& c4,
      uint64_t rate,
      std::chrono::microseconds minRtt,
      uint64_t losses) {
    flowAppLimited_ = true;
    startFlow(c4, rate, minRtt);
    ASSERT_TRUE(runUntilState(c4, State::Cruising));
    runFor(c4, 50ms);
    dropsLeft_ = losses;
    ASSERT_TRUE(runUntil(c4, [&] { return lostPackets_ == losses; }));
  }

  void delayPendingAcks(std::chrono::microseconds delay) {
    for (auto& [ackTime, packetNum] : pendingAcks_) {
      ackTime += delay;
    }
  }

  [[nodiscard]] uint64_t pacingRate() const {
    return pacingInterval_ == 0us
        ? 0
        : pacingBytes_ * 1'000'000 / pacingInterval_.count();
  }

  static uint64_t nominalRate(const C4CongestionController& c4) {
    const auto bandwidth = c4.getBandwidth();
    return bandwidth ? bandwidth->normalize() : 0;
  }

  [[nodiscard]] double pacingGain(const C4CongestionController& c4) const {
    return static_cast<double>(pacingRate()) /
        static_cast<double>(nominalRate(c4));
  }

  // The nominal max RTT, derived from the BDP and the nominal rate.
  static std::chrono::microseconds maxRtt(const C4CongestionController& c4) {
    return std::chrono::microseconds(c4.getBDP() * 1'000'000 / nominalRate(c4));
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  std::shared_ptr<FileQLogger> qLogger_{
      std::make_shared<FileQLogger>(VantagePoint::Client)};
  NiceMock<MockPacer>* pacer_{nullptr};
  uint64_t pacingBytes_{0};
  std::chrono::microseconds pacingInterval_{0us};
  std::map<PacketNum, OutstandingPacketWrapper> outstanding_;
  uint64_t acks_{0};
  uint64_t lostPackets_{0};
  uint64_t ceMarksLeft_{0};

  TimePoint now_;
  uint64_t flowRate_{0};
  std::chrono::microseconds flowRtt_{0us};
  bool flowSending_{false};
  bool flowAppLimited_{false};
  uint64_t dropsLeft_{0};
  TimePoint nextSendTime_;
  std::deque<std::pair<TimePoint, PacketNum>> pendingAcks_;
  uint64_t cwndBeforeLastAck_{0};
  std::vector<int64_t> cwndChanges_;
};

TEST_F(C4Test, StartsInInitialWithoutPacing) {
  const uint64_t initCwnd =
      kPacketSize * conn_->transportSettings.initCwndInMss;
  EXPECT_CALL(*pacer_, setRttFactor(1, 1));
  EXPECT_CALL(*pacer_, refreshPacingRate(initCwnd, 0us, conn_->connectionTime));
  C4CongestionController c4(*conn_);

  EXPECT_EQ(c4.type(), CongestionControlType::C4);
  EXPECT_EQ(c4.getState(), State::Initial);
  EXPECT_EQ(c4.getCongestionWindow(), initCwnd);
  EXPECT_EQ(c4.getWritableBytes(), initCwnd);
  EXPECT_FALSE(c4.getBandwidth().has_value());
  EXPECT_FALSE(c4.isAppLimited());
  CongestionControllerStats stats{};
  c4.getStats(stats);
  EXPECT_EQ(stats.c4Stats.state, static_cast<uint8_t>(State::Initial));
}

TEST_F(C4Test, IgnoresAcksOutsideAppData) {
  C4CongestionController c4(*conn_);
  const auto cwnd = c4.getCongestionWindow();
  const auto packetNum = send(c4, now_);
  LossEvent lossEvent(now_ + 50ms);
  lossEvent.addLostPacket(outstanding_.at(packetNum));
  auto makeAckEvent = [&](PacketNumberSpace space, bool implicit) {
    auto ackEvent = AckEvent::Builder()
                        .setAckTime(now_ + 50ms)
                        .setAdjustedAckTime(now_ + 50ms)
                        .setAckDelay(0us)
                        .setPacketNumberSpace(space)
                        .setLargestAckedPacket(packetNum)
                        .setIsImplicitAck(implicit)
                        .build();
    ackEvent.ackedBytes = kPacketSize;
    ackEvent.totalBytesAcked = kPacketSize;
    ackEvent.largestNewlyAckedPacket = packetNum;
    ackEvent.largestNewlyAckedPacketSentTime = now_;
    ackEvent.rttSample = 50ms;
    return ackEvent;
  };

  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  auto initialAck = makeAckEvent(PacketNumberSpace::Initial, false);
  c4.onPacketAckOrLoss(&initialAck, &lossEvent);
  auto handshakeAck = makeAckEvent(PacketNumberSpace::Handshake, false);
  c4.onPacketAckOrLoss(&handshakeAck, &lossEvent);
  auto implicitAck = makeAckEvent(PacketNumberSpace::AppData, true);
  c4.onPacketAckOrLoss(&implicitAck, &lossEvent);

  EXPECT_EQ(c4.getCongestionWindow(), cwnd);
  EXPECT_FALSE(c4.getBandwidth().has_value());
}

TEST_F(C4Test, CountsOnlyAppDataTimerLosses) {
  C4CongestionController c4(*conn_);
  const auto first = send(c4, now_);
  const auto second = send(c4, now_);
  ack(c4, {first}, now_ + 20ms);
  LossEvent handshakeLoss(now_ + 100ms);
  handshakeLoss.addLostPacket(outstanding_.at(second));
  handshakeLoss.packetNumberSpace = PacketNumberSpace::Handshake;

  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, _)).Times(0);
  c4.onPacketAckOrLoss(nullptr, &handshakeLoss);
  Mock::VerifyAndClearExpectations(pacer_);

  EXPECT_CALL(*pacer_, refreshPacingRate(_, _, now_ + 200ms));
  loseOnTimer(c4, {second}, now_ + 200ms);
}

TEST_F(C4Test, FirstRttSampleSetsMaxRtt) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getBandwidth().has_value(); }));

  EXPECT_EQ(nominalRate(c4), 1'000'000);
  EXPECT_EQ(maxRtt(c4), 20500us);
}

TEST_F(C4Test, MaxRttHasOneMillisecondFloor) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 500'000, 500us, 0us);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getBandwidth().has_value(); }));

  EXPECT_EQ(maxRtt(c4), 1ms);
}

TEST_F(C4Test, RttSampleExcludesAckDelayAboveMinRtt) {
  conn_->peerMaxAckDelay = 40ms;
  C4CongestionController c4(*conn_);
  // An app-limited flow stays in Cruising, where every era updates the max
  // RTT.
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  drain(c4);
  ASSERT_LT(maxRtt(c4), 60ms);

  const auto first = send(c4, now_);
  c4.setAppLimited();
  ack(c4, {first}, now_ + 100ms, 40ms);
  EXPECT_EQ(maxRtt(c4), 60ms);

  now_ += 100ms;
  const auto second = send(c4, now_);
  c4.setAppLimited();
  // Removing this ACK delay would go below the min RTT, so all of it counts.
  ack(c4, {second}, now_ + 30ms, 20ms);
  EXPECT_EQ(maxRtt(c4), (7 * 60'000us + 30'000us) / 8);
}

TEST_F(C4Test, RttSampleCapsAckDelayAtPeerMaxAckDelay) {
  conn_->peerMaxAckDelay = 10ms;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  drain(c4);
  ASSERT_LT(maxRtt(c4), 90ms);

  // The peer reports 40 ms of ACK delay, but it may delay ACKs by 10 ms only.
  const auto packetNum = send(c4, now_);
  c4.setAppLimited();
  ack(c4, {packetNum}, now_ + 100ms, 40ms);
  EXPECT_EQ(maxRtt(c4), 90ms);
}

TEST_F(C4Test, RateEstimateNeedsMoreThanOneMillisecond) {
  C4CongestionController c4(*conn_);
  const auto first = send(c4, now_);
  ack(c4, {first}, now_ + 20ms);
  now_ += 20ms;

  const auto second = send(c4, now_);
  ack(c4, {second}, now_ + 1ms);
  EXPECT_FALSE(c4.getBandwidth().has_value());

  now_ += 1ms;
  const auto third = send(c4, now_);
  ack(c4, {third}, now_ + 1500us);
  EXPECT_EQ(nominalRate(c4), kPacketSize * 1'000'000 / 1'500);
}

TEST_F(C4Test, RateEstimateUsesLongerOfSendAndAckIntervals) {
  C4CongestionController c4(*conn_);
  const auto first = send(c4, now_);
  ack(c4, {first}, now_ + 20ms);
  const auto second = send(c4, now_ + 20ms);
  const auto third = send(c4, now_ + 30ms);

  // Both packets are acked 20 ms after the first ACK, but they took 30 ms to
  // send since the first packet.
  ack(c4, {second, third}, now_ + 40ms);
  EXPECT_EQ(nominalRate(c4), 2 * kPacketSize * 1'000'000 / 30'000);
}

TEST_F(C4Test, RateEstimateRemovesAckDelays) {
  C4CongestionController c4(*conn_);
  const auto first = send(c4, now_);
  // The peer held this ACK for 15 ms.
  ack(c4, {first}, now_ + 20ms, 15ms);
  const auto second = send(c4, now_ + 20ms);
  const auto third = send(c4, now_ + 20ms);

  // The next ACK comes 40 ms after the first one, but the packets it acks
  // arrived 55 ms after the first packet.
  ack(c4, {second, third}, now_ + 60ms);
  EXPECT_EQ(nominalRate(c4), 2 * kPacketSize * 1'000'000 / 55'000);
}

TEST_F(C4Test, InitialPacesAtTwiceNominalRate) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getBandwidth().has_value(); }));

  EXPECT_EQ(pacingRate(), 2'000'000);
  EXPECT_EQ(pacingInterval_, 1s);
}

TEST_F(C4Test, InitialPacesAtMinimumRateWithoutEstimate) {
  C4CongestionController c4(*conn_);
  const auto packetNum = send(c4, now_);
  ack(c4, {packetNum}, now_ + 50ms);

  EXPECT_FALSE(c4.getBandwidth().has_value());
  EXPECT_EQ(pacingRate(), 131'072);
}

TEST_F(C4Test, InitialPacingMovesHalfwayToPeakRate) {
  C4CongestionController c4(*conn_);
  const auto burst = sendBurst(c4, 10);
  ack(c4, {burst.front()}, now_ + 40ms);
  ack(c4, {burst.begin() + 1, burst.end()}, now_ + 42ms);

  // Nine packets acked 2 ms after the first one show a 4.5 MB/s peak. These
  // packets were sent before any ACK, so they do not produce a rate estimate.
  const uint64_t peakRate = 9 * kPacketSize * 1'000'000 / 2'000;
  EXPECT_FALSE(c4.getBandwidth().has_value());
  EXPECT_EQ(pacingRate(), (131'072 + peakRate) / 2);
  EXPECT_EQ(
      c4.getCongestionWindow(),
      peakRate * conn_->lossState.srtt.count() / 1'000'000 / 2);
}

TEST_F(C4Test, PeakRateRemovesAckDelays) {
  C4CongestionController c4(*conn_);
  const auto burst = sendBurst(c4, 10);
  // The peer held the first ACK for 18 ms, so the other nine packets arrived
  // 38 ms after the first one.
  ack(c4, {burst.front()}, now_ + 40ms, 18ms);
  ack(c4, {burst.begin() + 1, burst.end()}, now_ + 60ms);

  const uint64_t peakRate = 9 * kPacketSize * 1'000'000 / 38'000;
  EXPECT_EQ(pacingRate(), (131'072 + peakRate) / 2);
}

TEST_F(C4Test, InitialWindowGrowsByAckedBytes) {
  C4CongestionController c4(*conn_);
  const auto initCwnd = c4.getCongestionWindow();
  const auto packets = sendBurst(c4, 5);

  ack(c4, {packets.front()}, now_ + 50ms);
  EXPECT_EQ(c4.getCongestionWindow(), initCwnd + kPacketSize);
  ack(c4, {packets.begin() + 1, packets.end()}, now_ + 51ms);
  EXPECT_EQ(c4.getCongestionWindow(), initCwnd + 5 * kPacketSize);
}

TEST_F(C4Test, InitialGrowthSlowsAfterErasWithoutGrowth) {
  C4CongestionController c4(*conn_);
  // At this rate the Initial window stays above twice the BDP, so the
  // congestion window shows how it grows.
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  cwndChanges_.pop_back();

  std::vector<int64_t> growthSteps;
  for (const auto change : cwndChanges_) {
    if (growthSteps.empty() || growthSteps.back() != change) {
      growthSteps.push_back(change);
    }
  }
  EXPECT_THAT(growthSteps, ElementsAre(1000, 1000 >> 3, 1000 >> 6));
}

TEST_F(C4Test, InitialExitsAfterThreeErasWithoutGrowth) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Initial; }));
  const auto initialCwnd = cwndBeforeLastAck_ + (kPacketSize >> 6);

  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(lastStateTrigger(), kCongestionPacketAck);
  // The max RTT is half of the Initial window at the nominal rate, and the
  // other half is a backlog that Recovery drains at 3/4.
  EXPECT_EQ(c4.getBDP(), initialCwnd / 2);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 0.75);
}

TEST_F(C4Test, InitialIgnoresErasWhenSenderLimited) {
  C4CongestionController c4(*conn_);
  // ACKs arrive exactly one min RTT after each send, so the delivered data
  // never exceeds the nominal rate times the min RTT.
  startFlow(c4, 100'000, 20ms, 0us);
  runFor(c4, 5s);

  EXPECT_EQ(c4.getState(), State::Initial);
}

TEST_F(C4Test, InitialExitsOnDelayAfterTwoErasWithoutGrowth) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] {
    return !cwndChanges_.empty() && cwndChanges_.back() == (1000 >> 6);
  }));

  delayPendingAcks(50ms);
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(lastStateTrigger(), "delay");
}

TEST_F(C4Test, InitialIgnoresDelayAfterOneEraWithoutGrowth) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] {
    return !cwndChanges_.empty() && cwndChanges_.back() == (1000 >> 3);
  }));

  delayPendingAcks(50ms);
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Initial);
}

TEST_F(C4Test, InitialExitsOnLossAfterMoreThanTwentyEvents) {
  C4CongestionController c4(*conn_);
  // The flow is sender limited, so only a loss can end Initial.
  startFlow(c4, 1'000'000, 5ms, 0us);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getBandwidth().has_value(); }));

  dropsLeft_ = 1;
  ASSERT_TRUE(runUntil(c4, [&] { return lostPackets_ == 1; }));
  ASSERT_LT(acks_, 20);
  EXPECT_EQ(c4.getState(), State::Initial);

  ASSERT_TRUE(runUntil(c4, [&] { return acks_ > 20; }));
  dropsLeft_ = 1;
  ASSERT_TRUE(runUntil(c4, [&] { return lostPackets_ == 2; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(lastStateTrigger(), kCongestionPacketLoss);
}

TEST_F(C4Test, RecoveryDrainsGentlyBelowOneMillisecond) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 500'000, 500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Recovery));

  EXPECT_DOUBLE_EQ(pacingGain(c4), 15.0 / 16);
}

TEST_F(C4Test, RecoveryDrainsInitialBacklogOverSeveralEras) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  std::vector<double> recoveryGains;
  while (recoveryGains.size() < 6) {
    ASSERT_TRUE(runUntilState(c4, State::Recovery));
    recoveryGains.push_back(pacingGain(c4));
    ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
    EXPECT_EQ(c4.getState(), State::Cruising);
  }

  // Each Recovery drains 1 - gain of an era, and the Initial backlog is one
  // era.
  EXPECT_THAT(
      recoveryGains, ElementsAre(0.75, 0.75, 0.75, 0.75, 15.0 / 16, 15.0 / 16));
}

TEST_F(C4Test, CruisingMovesToProbing) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  EXPECT_DOUBLE_EQ(pacingGain(c4), 1.0);

  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Cruising; }));
  EXPECT_EQ(c4.getState(), State::Probing);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 17.0 / 16);

  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Probing; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
}

TEST_F(C4Test, CruisingWaitsForSenderBeforeProbing) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 500ms);
  EXPECT_EQ(c4.getState(), State::Cruising);
  EXPECT_TRUE(c4.isAppLimited());

  flowAppLimited_ = false;
  ASSERT_TRUE(runUntilState(c4, State::Probing));
}

TEST_F(C4Test, CruisingRaisesGainBelowOneMillisecond) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 500'000, 500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));

  EXPECT_NEAR(pacingGain(c4), 1 + 3.0 / 64, 1e-5);
}

TEST_F(C4Test, AppLimitedUntilLaterPacketIsAcked) {
  C4CongestionController c4(*conn_);
  const auto before = send(c4, now_);
  c4.setAppLimited();
  EXPECT_TRUE(c4.isAppLimited());
  const auto after = send(c4, now_ + 1ms);

  ack(c4, {before}, now_ + 50ms);
  EXPECT_TRUE(c4.isAppLimited());
  ack(c4, {after}, now_ + 51ms);
  EXPECT_FALSE(c4.isAppLimited());
}

TEST_F(C4Test, PacesAtGainTimesNominalRate) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));

  EXPECT_CALL(
      *pacer_,
      refreshPacingRate(
          1'000'000,
          std::chrono::microseconds(1s),
          pendingAcks_.front().first));
  ackNext(c4);
}

TEST_F(C4Test, PacerSpacesBurstsAtPacingRate) {
  auto& pacer = useTokenlessPacer();
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));

  // Five packets take 5 ms at 1 MB/s.
  ASSERT_EQ(pacer.updateAndGetWriteBatchSize(now_), kDefaultMinBurstPackets);
  EXPECT_EQ(pacer.getTimeUntilNextWrite(now_), 5ms);
}

TEST_F(C4Test, CwndLimitsSendingWhenBurstTakesLongerThanRtt) {
  auto& pacer = useTokenlessPacer();
  conn_->transportSettings.initCwndInMss = 2;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 64'000, 34ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 500ms);

  // Five packets take 78 ms at 64 KB/s, more than the RTT, and the cwnd holds
  // fewer. Bursts that the cwnd cuts short would leave the path idle, so the
  // pacer lets the sender write whenever the cwnd opens.
  ASSERT_LT(c4.getCongestionWindow(), kDefaultMinBurstPackets * kPacketSize);
  pacer.updateAndGetWriteBatchSize(now_);
  EXPECT_EQ(pacer.getTimeUntilNextWrite(now_), 0us);
  // With the cwnd as the limit, the cwnd has no margin above the BDP.
  EXPECT_EQ(
      c4.getCongestionWindow(),
      std::max<uint64_t>(c4.getBDP(), 2 * kPacketSize));
}

TEST_F(C4Test, CwndAddsMarginOutsideInitial) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 100ms);

  // At one byte per microsecond, the window in bytes is the max RTT plus a
  // quarter of it in microseconds.
  const auto rtt = maxRtt(c4).count();
  ASSERT_LT(rtt / 4, 15'000);
  EXPECT_EQ(c4.getCongestionWindow(), rtt + rtt / 4);
}

TEST_F(C4Test, CwndMarginStopsAtFifteenMilliseconds) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 80ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 200ms);

  const auto rtt = maxRtt(c4).count();
  ASSERT_GT(rtt / 4, 15'000);
  EXPECT_EQ(c4.getCongestionWindow(), rtt + 15'000);
}

TEST_F(C4Test, ProbingCwndHasRoomForOneMorePacket) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  const double rtt = std::chrono::duration<double>(maxRtt(c4)).count();
  const double pacingRate = 100'000 * 17.0 / 16;
  const double probeBytes = 100'000 / 16.0 * rtt;
  ASSERT_LT(probeBytes, kPacketSize);
  EXPECT_NEAR(
      c4.getCongestionWindow(),
      pacingRate * rtt + pacingRate * std::min(rtt / 4, 0.015) + kPacketSize -
          probeBytes,
      2);
}

TEST_F(C4Test, CwndStaysWithinTransportLimits) {
  conn_->transportSettings.minCwndInMss = 30;
  conn_->transportSettings.maxCwndInMss = 35;
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  for (int i = 0; i < 5'000; i++) {
    step(c4);
    ASSERT_GE(c4.getCongestionWindow(), 30 * kPacketSize);
    ASSERT_LE(c4.getCongestionWindow(), 35 * kPacketSize);
  }
}

TEST_F(C4Test, SecondSignalInRecoveryDrainsLonger) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] {
    return c4.getState() == State::Recovery && pacingGain(c4) == 15.0 / 16;
  }));
  // Losses of packets sent before Recovery started do not count.
  pendingAcks_.pop_front();
  drain(c4);
  ASSERT_EQ(lostPackets_, 1);
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 15.0 / 16);

  // A loss reported with the ACK that would end the era restarts the era,
  // without another rate cut.
  const auto rate = nominalRate(c4);
  loseOneOfFour(c4);
  ASSERT_EQ(lostPackets_, 2);
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 7.0 / 8);
  EXPECT_EQ(nominalRate(c4), rate);

  // A third signal does not restart it again.
  loseOneOfFour(c4);
  ASSERT_EQ(lostPackets_, 3);
  EXPECT_EQ(c4.getState(), State::Cruising);
}

TEST_F(C4Test, IgnoresLateLossOfPacketSentBeforeRecovery) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] {
    return c4.getState() == State::Recovery && pacingGain(c4) == 15.0 / 16;
  }));
  // The last packet sent before Recovery stays unacked.
  pendingAcks_.pop_back();
  drain(c4);
  const auto packets = sendBurst(c4, 3);

  // The first packet of Recovery ends it before the earlier packet is declared
  // lost.
  now_ += 21ms;
  ack(c4, {packets[0]}, now_);
  ASSERT_EQ(lostPackets_, 0);
  const auto state = c4.getState();
  ASSERT_NE(state, State::Recovery);

  ack(c4, {packets[1], packets[2]}, now_ + 1ms);
  ASSERT_EQ(lostPackets_, 1);
  EXPECT_EQ(c4.getState(), state);
}

TEST_F(C4Test, RecoveryRaisesNominalRateWithoutCongestion) {
  C4CongestionController c4(*conn_);
  runToGentleRecovery(c4);

  sendAndAckBurst(c4, 40, 21ms);
  EXPECT_EQ(nominalRate(c4), 40 * kPacketSize * 1'000'000 / 21'000);
}

TEST_F(C4Test, RecoveryFreezesNominalRateAfterCongestion) {
  C4CongestionController c4(*conn_);
  runToGentleRecovery(c4);
  loseOneOfFour(c4);
  ASSERT_EQ(c4.getState(), State::Recovery);

  sendAndAckBurst(c4, 40, 21ms);
  EXPECT_EQ(nominalRate(c4), 1'000'000);
}

TEST_F(C4Test, ProbeThatRaisesRateLeadsToPushing) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  flowRate_ = 1'111'111;
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Probing; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
  EXPECT_EQ(c4.getState(), State::Pushing);
  EXPECT_NEAR(pacingGain(c4), 5.0 / 4, 1e-6);
}

TEST_F(C4Test, PushingEndsAtFirstEraWithoutFastGrowth) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));
  flowRate_ = 1'111'111;
  ASSERT_TRUE(runUntilState(c4, State::Pushing));
  const auto pushStart = now_;

  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Pushing; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_LT(now_ - pushStart, 42ms);
  // The push left a quarter era of backlog, which Recovery drains at 3/4.
  EXPECT_NEAR(pacingGain(c4), 0.75, 1e-6);
}

TEST_F(C4Test, PushingContinuesWhileRateGrowsFast) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  // The rate grows by a quarter every 20 ms, faster than once per RTT.
  Optional<TimePoint> pushStart;
  for (const uint64_t rate :
       {1'111'111,
        1'388'888,
        1'736'111,
        2'173'913,
        2'717'391,
        3'401'360,
        4'255'319,
        5'319'148,
        6'666'666}) {
    flowRate_ = rate;
    runFor(c4, 20ms);
    if (!pushStart && c4.getState() == State::Pushing) {
      pushStart = now_;
    }
  }
  ASSERT_TRUE(pushStart.has_value());
  EXPECT_EQ(c4.getState(), State::Pushing);
  EXPECT_GE(now_ - *pushStart, 60ms);

  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Pushing; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
}

TEST_F(C4Test, ThirdSuccessfulPushReentersInitial) {
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  // Each step grows the rate by a ninth: fast growth for a probe, and slow
  // growth for a push.
  flowRate_ = 1'111'111;
  ASSERT_TRUE(runUntilState(c4, State::Pushing));
  flowRate_ = 1'234'567;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
  ASSERT_EQ(c4.getState(), State::Pushing);

  flowRate_ = 1'371'742;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
  EXPECT_EQ(c4.getState(), State::Initial);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 2.0);
}

TEST_F(C4Test, CeMarksSignalOnceL4sIsValidated) {
  conn_->ecnState = ECNState::AttemptingL4S;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  ceMarksLeft_ = std::numeric_limits<uint64_t>::max();
  runFor(c4, 100ms);
  EXPECT_EQ(c4.getState(), State::Cruising);

  // Every packet is marked, so the reduction stops at a quarter. The signal
  // also clears the backlog that Initial left, so Recovery drains gently.
  conn_->ecnState = ECNState::ValidatedL4S;
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(nominalRate(c4), 750'000);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 15.0 / 16);
}

TEST_F(C4Test, ProbesSoonerAndGentlerAfterCeSignal) {
  conn_->ecnState = ECNState::ValidatedL4S;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 100ms);
  ceMarksLeft_ = std::numeric_limits<uint64_t>::max();
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ceMarksLeft_ = 0;
  flowAppLimited_ = false;

  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  const auto cruiseStart = now_;
  ASSERT_TRUE(runUntilState(c4, State::Probing));
  // A single Cruising era, which lasts about one RTT, comes before the probe.
  EXPECT_LT(now_ - cruiseStart, 30ms);
  EXPECT_NEAR(pacingGain(c4), 33.0 / 32, 1e-6);
}

TEST_F(C4Test, CeSignalAfterPushHoldsProbeLevel) {
  conn_->ecnState = ECNState::ValidatedL4S;
  C4CongestionController c4(*conn_);
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  // These rate steps lead back to Initial without CE marks. The marks come
  // once the nominal rate shows the growth of the push, which a congestion
  // signal freezes.
  flowRate_ = 1'111'111;
  ASSERT_TRUE(runUntilState(c4, State::Pushing));
  flowRate_ = 1'234'567;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntil(c4, [&] {
    return c4.getState() != State::Recovery || nominalRate(c4) > 1'200'000;
  }));
  ASSERT_EQ(c4.getState(), State::Recovery);
  ceMarksLeft_ = std::numeric_limits<uint64_t>::max();
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
  ceMarksLeft_ = 0;
  ASSERT_EQ(c4.getState(), State::Pushing);

  flowRate_ = 1'371'742;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Recovery; }));
  EXPECT_EQ(c4.getState(), State::Pushing);
}

TEST_F(C4Test, CeMarksDoNotCutRateInInitial) {
  conn_->ecnState = ECNState::ValidatedL4S;
  C4CongestionController c4(*conn_);
  ceMarksLeft_ = std::numeric_limits<uint64_t>::max();
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Initial; }));

  // Initial ends after three eras without growth, as it does without marks.
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(lastStateTrigger(), kCongestionPacketAck);
  EXPECT_EQ(nominalRate(c4), 100'000);
  EXPECT_DOUBLE_EQ(pacingGain(c4), 0.75);
}

TEST_F(C4Test, CeMarksWithDelayEndInitialAfterTwoErasWithoutGrowth) {
  conn_->ecnState = ECNState::ValidatedL4S;
  C4CongestionController c4(*conn_);
  startFlow(c4, 100'000, 20ms);
  ASSERT_TRUE(runUntil(c4, [&] {
    return !cwndChanges_.empty() && cwndChanges_.back() == (1000 >> 3);
  }));

  // C4 handles the marks of an ACK before its RTT sample, so the marks end
  // Initial on the first ACK after the second era without growth.
  delayPendingAcks(50ms);
  ceMarksLeft_ = std::numeric_limits<uint64_t>::max();
  ASSERT_TRUE(runUntil(c4, [&] { return c4.getState() != State::Initial; }));
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_EQ(lastStateTrigger(), "ecn");
}

TEST_F(C4Test, DelaySignalNeedsEraAboveNominalRate) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 100ms);
  setNextAckRtt(maxRtt(c4) + 30ms);
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Cruising);

  flowAppLimited_ = false;
  ASSERT_TRUE(runUntilState(c4, State::Probing));
  const auto rate = nominalRate(c4);
  const auto rtt = maxRtt(c4);
  setNextAckRtt(rtt + 30ms);
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Recovery);
  // The probe sent above the nominal rate, so the nominal rate and max RTT
  // stay.
  EXPECT_EQ(nominalRate(c4), rate);
  EXPECT_EQ(maxRtt(c4), rtt);
}

TEST_F(C4Test, IgnoresLossesBelowThreshold) {
  const auto losses = lossesToSignal(500'000) - 1;
  ASSERT_GT(losses, 0);
  C4CongestionController c4(*conn_);
  dropInCruising(c4, 500'000, 20ms, losses);

  EXPECT_EQ(c4.getState(), State::Cruising);
}

TEST_F(C4Test, LowRatesIgnoreLosses) {
  conn_->transportSettings.initCwndInMss = 2;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 50'000, 60ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  // At zero sensitivity the threshold is 52%, above what losses alone reach.
  ASSERT_LT(lossRateAfter(32), 0.52);

  dropsLeft_ = 32;
  ASSERT_TRUE(runUntil(c4, [&] { return lostPackets_ == 32; }));
  EXPECT_EQ(c4.getState(), State::Cruising);
}

TEST_F(C4Test, DelayBetaIsProportionalToExcess) {
  C4CongestionController c4(*conn_);
  // Below 1 ms of RTT, Cruising paces above the nominal rate, so a delay
  // signal there lowers the nominal rate.
  flowAppLimited_ = true;
  startFlow(c4, 500'000, 500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 20ms);
  while (pendingAcks_.empty()) {
    step(c4);
  }

  const auto rtt = maxRtt(c4);
  const double fraction = 1.0 / 16 + (1 - sensitivity(500'000)) * 3.0 / 16;
  const auto threshold =
      std::chrono::duration_cast<std::chrono::microseconds>(rtt * fraction);
  setNextAckRtt(rtt + threshold + threshold / 10);
  ackNext(c4);
  EXPECT_EQ(c4.getState(), State::Recovery);
  EXPECT_NEAR(nominalRate(c4), 500'000 * 0.9, 1'500);
}

TEST_F(C4Test, SecondCongestionInRowResetsNominalRateToRecentMaximum) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  // The path slows down, which only congestion signals reveal.
  flowRate_ = 500'000;
  runFor(c4, 100ms);
  ASSERT_EQ(nominalRate(c4), 1'000'000);

  dropsLeft_ = 6;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  EXPECT_LT(nominalRate(c4), 1'000'000);
  EXPECT_GT(nominalRate(c4), 600'000);

  dropsLeft_ = 6;
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  EXPECT_EQ(nominalRate(c4), 500'000);
}

TEST_F(C4Test, NominalRateTrimsToRecentMaximumWithoutCongestion) {
  C4CongestionController c4(*conn_);
  runToGentleRecovery(c4);

  // Each burst acks two min RTTs of data at the nominal rate over three, so
  // the network is the limit and the rate samples stay at two thirds.
  const uint64_t sampleRate = 40 * kPacketSize * 1'000'000 / 60'000;
  std::vector<State> states;
  for (int i = 0; i < 8; i++) {
    sendAndAckBurst(c4, 40, 60ms);
    states.push_back(c4.getState());
    ASSERT_EQ(nominalRate(c4), 1'000'000);
  }
  // Trimming uses the maximum of the last two cycles, and the first cycle
  // still included the earlier rate.
  sendAndAckBurst(c4, 40, 60ms);
  states.push_back(c4.getState());
  EXPECT_EQ(nominalRate(c4), sampleRate);
  EXPECT_THAT(
      states,
      ElementsAre(
          State::Cruising,
          State::Cruising,
          State::Probing,
          State::Recovery,
          State::Cruising,
          State::Cruising,
          State::Probing,
          State::Recovery,
          State::Cruising));
}

TEST_F(C4Test, MaxRttCapsJitterAboveRunningMin) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  drain(c4);

  flowRtt_ = 400ms;
  resume();
  const auto before = maxRtt(c4);
  ASSERT_TRUE(runUntil(c4, [&] { return maxRtt(c4) != before; }));
  EXPECT_EQ(maxRtt(c4), 20500us + 250ms);
}

TEST_F(C4Test, MaxRttDecaysByEighthPerEra) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  flowRtt_ = 100ms;
  runFor(c4, 300ms);
  drain(c4);
  ASSERT_EQ(maxRtt(c4), 100ms);

  flowRtt_ = 20500us;
  resume();
  std::vector<std::chrono::microseconds> maxRtts{maxRtt(c4)};
  ASSERT_TRUE(runUntil(c4, [&] {
    if (maxRtt(c4) != maxRtts.back()) {
      maxRtts.push_back(maxRtt(c4));
    }
    return maxRtts.size() == 4;
  }));
  for (size_t i = 1; i < maxRtts.size(); i++) {
    EXPECT_EQ(maxRtts[i], (7 * maxRtts[i - 1] + 20500us) / 8);
  }
}

TEST_F(C4Test, MaxRttSkipsErasThatProbe) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20500us, 0us);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  flowRtt_ = 100ms;
  runFor(c4, 300ms);
  drain(c4);
  flowRtt_ = 20500us;
  resume();
  ASSERT_TRUE(runUntil(c4, [&] { return maxRtt(c4) < 100ms; }));

  flowAppLimited_ = false;
  ASSERT_TRUE(runUntilState(c4, State::Probing));
  const auto probingMaxRtt = maxRtt(c4);
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  EXPECT_EQ(maxRtt(c4), probingMaxRtt);
}

class C4JitterTest : public C4Test, public WithParamInterface<uint64_t> {
 protected:
  // Alternates phases at the min RTT with phases five times longer, so that
  // the max RTT grows while the running min RTT stays low. Returns the time
  // C4 re-entered Initial, if it did.
  Optional<TimePoint> runJitter(
      C4CongestionController& c4,
      std::chrono::microseconds duration) {
    const auto end = now_ + duration;
    for (auto rtt = 20ms; now_ < end; rtt = rtt == 20ms ? 100ms : 20ms) {
      flowRtt_ = rtt;
      resume();
      if (runUntil(
              c4,
              [&, phaseEnd = now_ + 50ms] {
                return c4.getState() == State::Initial || now_ >= phaseEnd;
              }) &&
          c4.getState() == State::Initial) {
        return now_;
      }
      drain(c4);
      if (c4.getState() == State::Initial) {
        return now_;
      }
    }
    return std::nullopt;
  }
};

TEST_F(C4JitterTest, ReentersInitialAfterJitterAtLowRates) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 500'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Recovery));
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  const auto recoveryEnd = now_;
  drain(c4);

  const auto reentry = runJitter(c4, 3s);
  ASSERT_TRUE(reentry.has_value());
  EXPECT_GT(*reentry, recoveryEnd + 1s);
}

TEST_F(C4JitterTest, KeepsCruisingAfterJitterAtOneMegabytePerSecond) {
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, 1'000'000, 20ms);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  drain(c4);

  EXPECT_FALSE(runJitter(c4, 3s).has_value());
}

struct SensitivityParam {
  uint64_t rate;
  std::chrono::microseconds minRtt;
  uint64_t initCwndInMss;
};

class C4DelayThresholdTest
    : public C4Test,
      public WithParamInterface<std::tuple<SensitivityParam, bool>> {};

TEST_P(C4DelayThresholdTest, SignalsDelayAboveMaxRttPlusThreshold) {
  const auto& [param, above] = GetParam();
  conn_->transportSettings.initCwndInMss = param.initCwndInMss;
  C4CongestionController c4(*conn_);
  startFlow(c4, param.rate, param.minRtt);
  ASSERT_TRUE(runUntilState(c4, State::Probing));

  const auto rtt = maxRtt(c4);
  const double fraction = 1.0 / 16 + (1 - sensitivity(param.rate)) * 3.0 / 16;
  const auto threshold = std::min<std::chrono::microseconds>(
      25ms,
      std::chrono::duration_cast<std::chrono::microseconds>(rtt * fraction));
  setNextAckRtt(rtt + threshold + (above ? 100us : -100us));
  ackNext(c4);
  EXPECT_EQ(c4.getState(), above ? State::Recovery : State::Probing);
}

INSTANTIATE_TEST_SUITE_P(
    Sensitivity,
    C4DelayThresholdTest,
    Combine(
        Values(
            SensitivityParam{50'000, 20ms, 2},
            SensitivityParam{500'000, 20ms, 10},
            SensitivityParam{1'000'000, 20ms, 10},
            SensitivityParam{10'000'000, 20ms, 10},
            SensitivityParam{20'000'000, 20ms, 10},
            // The threshold stops at 25 ms.
            SensitivityParam{50'000, 150ms, 10}),
        Bool()));

class C4LossTest : public C4Test,
                   public WithParamInterface<SensitivityParam> {};

TEST_P(C4LossTest, SignalsLossAboveThreshold) {
  conn_->transportSettings.initCwndInMss = GetParam().initCwndInMss;
  C4CongestionController c4(*conn_);
  dropInCruising(
      c4, GetParam().rate, GetParam().minRtt, lossesToSignal(GetParam().rate));

  EXPECT_EQ(c4.getState(), State::Recovery);
}

TEST_P(C4LossTest, LossBetaFollowsSensitivity) {
  conn_->transportSettings.initCwndInMss = GetParam().initCwndInMss;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, GetParam().rate, GetParam().minRtt);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  runFor(c4, 50ms);
  const auto losses = lossesToSignal(GetParam().rate);

  // Cruising eras keep updating the max RTT until the signal.
  dropsLeft_ = losses;
  auto rtt = maxRtt(c4);
  ASSERT_TRUE(runUntil(c4, [&] {
    if (c4.getState() == State::Cruising) {
      rtt = maxRtt(c4);
    }
    return lostPackets_ == losses;
  }));
  ASSERT_EQ(c4.getState(), State::Recovery);
  const double beta = (1 + sensitivity(GetParam().rate)) / 8;
  EXPECT_NEAR(nominalRate(c4), GetParam().rate * (1 - beta), 2);
  EXPECT_NEAR(maxRtt(c4).count(), rtt.count() * (1 - beta), 5);
}

INSTANTIATE_TEST_SUITE_P(
    Sensitivity,
    C4LossTest,
    Values(
        SensitivityParam{500'000, 20ms, 10},
        SensitivityParam{1'000'000, 20ms, 10},
        SensitivityParam{2'000'000, 20ms, 10},
        SensitivityParam{10'000'000, 20ms, 10}));

class C4EcnTest : public C4Test, public WithParamInterface<SensitivityParam> {
 protected:
  // After an idle second, sends 16 packets and acks them together one min RTT
  // later, with `ceCount` of them marked CE. The idle time keeps the rate
  // samples far below the nominal rate.
  void ackMarkedBurst(C4CongestionController& c4, uint64_t ceCount) {
    now_ += 1s;
    ceMarksLeft_ = ceCount;
    const auto burst = sendBurst(c4, 16);
    c4.setAppLimited();
    now_ += GetParam().minRtt;
    ack(c4, burst, now_);
  }
};

TEST_P(C4EcnTest, CeSignalFollowsSensitivity) {
  conn_->ecnState = ECNState::ValidatedL4S;
  conn_->transportSettings.initCwndInMss = GetParam().initCwndInMss;
  C4CongestionController c4(*conn_);
  flowAppLimited_ = true;
  startFlow(c4, GetParam().rate, GetParam().minRtt);
  ASSERT_TRUE(runUntilState(c4, State::Cruising));
  // Cruising brings the max RTT close to the min RTT, so the idle time
  // between bursts does not look like jitter.
  runFor(c4, 300ms);
  drain(c4);
  // C4 averages the marks since the last era end or CE mark, so an unmarked
  // burst first ends the current era.
  ackMarkedBurst(c4, 0);

  // Each burst marks 6 of 16 packets, and the average moves a sixteenth of
  // the way to that fraction.
  double threshold = 0;
  double alpha = 0;
  auto markUntilAboveThreshold = [&] {
    threshold = (2 - sensitivity(nominalRate(c4))) * 3.0 / 32;
    alpha = 0;
    while (alpha <= threshold) {
      ASSERT_EQ(c4.getState(), State::Cruising);
      alpha += (6.0 / 16 - alpha) / 16;
      ackMarkedBurst(c4, 6);
    }
  };
  markUntilAboveThreshold();
  EXPECT_EQ(c4.getState(), State::Recovery);
  const double beta = std::min(0.25, (alpha - threshold) / threshold);
  EXPECT_NEAR(
      nominalRate(c4), GetParam().rate * (1 - beta), GetParam().rate * 1e-4);

  // The average starts over after Recovery.
  ackMarkedBurst(c4, 0);
  ASSERT_EQ(c4.getState(), State::Cruising);
  markUntilAboveThreshold();
  EXPECT_EQ(c4.getState(), State::Recovery);
}

INSTANTIATE_TEST_SUITE_P(
    Sensitivity,
    C4EcnTest,
    Values(
        SensitivityParam{50'000, 20ms, 2},
        SensitivityParam{500'000, 20ms, 10},
        SensitivityParam{1'000'000, 20ms, 10},
        SensitivityParam{2'000'000, 20ms, 10},
        SensitivityParam{10'000'000, 20ms, 10}));

} // namespace quic::test
