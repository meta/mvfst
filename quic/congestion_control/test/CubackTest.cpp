/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/QuicCuback.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/congestion_control/test/Utils.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/test/Mocks.h>

#include <algorithm>
#include <cmath>
#include <iterator>
#include <map>
#include <vector>

using namespace testing;

namespace quic::test {

namespace {

using State = Cuback::State;

constexpr uint64_t kPacketSize = 1000;
constexpr double kBeta = 0.7;
constexpr double kAlpha = 3 * (1 - kBeta) / (1 + kBeta);

// The cwnd after `bytes` more are acknowledged in congestion avoidance, from
// the draft's pseudocode: each increase of one segment consumes D(cwnd).
uint64_t cwndAfterAcking(
    const CubackEpoch& epoch,
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    uint64_t cwnd,
    uint64_t bytes) {
  uint64_t pending = bytes;
  while (true) {
    const auto threshold = static_cast<uint64_t>(std::ceil(cubackIncreaseBytes(
        epoch, static_cast<double>(cwnd), static_cast<double>(kPacketSize))));
    if (pending < threshold) {
      return cwnd;
    }
    pending -= threshold;
    cwnd += kPacketSize;
  }
}

// The epoch that a congestion event at `cwnd` starts, without fast
// convergence.
CubackEpoch epochAfterReduction(uint64_t cwnd, std::chrono::microseconds srtt) {
  return {
      .wMax = static_cast<double>(cwnd),
      .cwndPrior = static_cast<double>(cwnd),
      .cwndEpoch = std::floor(static_cast<double>(cwnd) * kBeta),
      .bandwidth =
          static_cast<double>(cwnd) * 1e6 / static_cast<double>(srtt.count())};
}

} // namespace

// The test vectors of draft-kazuho-ccwg-cuback-01, in segments.
TEST(CubackCurveTest, RenoFriendlyVector) {
  const CubackEpoch epoch{
      .wMax = 10, .cwndPrior = 10, .cwndEpoch = 7, .bandwidth = 100};
  const std::vector<double> ackedBytes{
      0, 13.2222, 28.3333, 45.3333, 55.3333, 66.3333};
  const std::vector<double> increaseBytes{13.2222, 15.1111, 17, 10, 11};
  for (size_t i = 0; i < ackedBytes.size(); i++) {
    EXPECT_NEAR(cubackAckedBytes(epoch, 7.0 + i, 1), ackedBytes[i], 1e-4);
  }
  for (size_t i = 0; i < increaseBytes.size(); i++) {
    EXPECT_NEAR(cubackIncreaseBytes(epoch, 7.0 + i, 1), increaseBytes[i], 1e-4);
  }
}

TEST(CubackCurveTest, CubicVector) {
  const CubackEpoch epoch{
      .wMax = 1000, .cwndPrior = 1000, .cwndEpoch = 600, .bandwidth = 10000};
  const std::map<double, double> ackedBytes{
      {600, 0},
      {950, 50'000},
      {1000, 100'000},
      {1050, 150'000},
      {1400, 200'000}};
  for (const auto& [w, bytes] : ackedBytes) {
    EXPECT_NEAR(cubackAckedBytes(epoch, w, 1), bytes, 1e-6) << w;
  }
  // A(W_max) over the bandwidth is K, which these parameters make 10 seconds.
  EXPECT_NEAR(cubackAckedBytes(epoch, 1000, 1) / epoch.bandwidth, 10, 1e-9);
}

TEST(CubackCurveTest, BytesScaleWithSmss) {
  // Counting bytes scales the windows and the bandwidth by SMSS, and so the
  // acknowledged bytes.
  constexpr double kSmss = 1200;
  const CubackEpoch segments{
      .wMax = 1000, .cwndPrior = 1000, .cwndEpoch = 600, .bandwidth = 10000};
  const CubackEpoch bytes{
      .wMax = 1000 * kSmss,
      .cwndPrior = 1000 * kSmss,
      .cwndEpoch = 600 * kSmss,
      .bandwidth = 10000 * kSmss};
  for (const double w : {600.0, 700.0, 950.0, 1050.0, 1400.0}) {
    EXPECT_NEAR(
        cubackAckedBytes(bytes, w * kSmss, kSmss),
        cubackAckedBytes(segments, w, 1) * kSmss,
        1e-3)
        << w;
  }
}

TEST(CubackCurveTest, IncreaseNeedsAtLeastTwoSegments) {
  // An understated bandwidth makes the cubic curve almost free to climb, and
  // the increase is capped at half the window per round trip.
  const CubackEpoch epoch{
      .wMax = 1000, .cwndPrior = 1000, .cwndEpoch = 600, .bandwidth = 1};
  EXPECT_LT(
      cubackAckedBytes(epoch, 1401, 1) - cubackAckedBytes(epoch, 1400, 1), 2);
  EXPECT_DOUBLE_EQ(cubackIncreaseBytes(epoch, 1400, 1), 2);
}

TEST(CubackCurveTest, OverstatedBandwidthFallsBackToRenoFriendly) {
  const CubackEpoch epoch{
      .wMax = 1000, .cwndPrior = 1000, .cwndEpoch = 700, .bandwidth = 1e12};
  for (const double w : {700.0, 800.0, 999.0}) {
    EXPECT_NEAR(cubackIncreaseBytes(epoch, w, 1), w / kAlpha, 1e-6) << w;
  }
  EXPECT_NEAR(cubackIncreaseBytes(epoch, 1200, 1), 1200, 1e-6);
}

TEST(CubackCurveTest, RenoFriendlyAlphaSwitchesAtCwndPrior) {
  // With fast convergence W_max is below cwnd_prior, and alpha_cubic still
  // applies up to cwnd_prior.
  const CubackEpoch epoch{
      .wMax = 8.5, .cwndPrior = 10, .cwndEpoch = 7, .bandwidth = 1e9};
  EXPECT_NEAR(cubackIncreaseBytes(epoch, 9, 1), 9 / kAlpha, 1e-6);
  EXPECT_NEAR(cubackIncreaseBytes(epoch, 10, 1), 10, 1e-6);
}

TEST(CubackCurveTest, IncreaseStaysFiniteAtExtremes) {
  for (const double bandwidth : {1e-6, 1.0, 1e15}) {
    const CubackEpoch epoch{
        .wMax = 1000,
        .cwndPrior = 1000,
        .cwndEpoch = 700,
        .bandwidth = bandwidth};
    for (const double w : {700.0, 1000.0, 1e9, 1e15}) {
      const double increase = cubackIncreaseBytes(epoch, w, 1);
      EXPECT_TRUE(std::isfinite(increase)) << bandwidth << " " << w;
      EXPECT_GE(increase, 2) << bandwidth << " " << w;
    }
  }
}

class CubackTest : public Test {
 public:
  void SetUp() override {
    conn_ = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Server);
    conn_->udpSendPacketLen = kPacketSize;
    auto pacer = std::make_unique<NiceMock<MockPacer>>();
    ON_CALL(*pacer, refreshPacingRate(_, _, _))
        .WillByDefault(
            [this](uint64_t bytes, std::chrono::microseconds rtt, TimePoint) {
              pacingBytes_ = bytes;
              pacingRtt_ = rtt;
            });
    conn_->pacer = std::move(pacer);
    conn_->qLogger = qLogger_;
  }

 protected:
  PacketNum send(Cuback& cuback) {
    const auto packetNum = conn_->ackStates.appDataAckState.nextPacketNum++;
    conn_->lossState.totalBytesSent += kPacketSize;
    auto packet = makeTestingWritePacket(
        packetNum, kPacketSize, conn_->lossState.totalBytesSent, now_);
    onPacketsSentWrapper(conn_.get(), &cuback, packet);
    outstanding_.emplace(packetNum, std::move(packet));
    return packetNum;
  }

  std::vector<PacketNum> send(Cuback& cuback, uint64_t packets) {
    std::vector<PacketNum> packetNums;
    packetNums.reserve(packets);
    for (uint64_t i = 0; i < packets; i++) {
      packetNums.push_back(send(cuback));
    }
    return packetNums;
  }

  // Sends until cwnd is full, which makes the sender cwnd limited.
  std::vector<PacketNum> fillCwnd(Cuback& cuback) {
    std::vector<PacketNum> packetNums;
    while (cuback.getWritableBytes() > 0) {
      packetNums.push_back(send(cuback));
    }
    return packetNums;
  }

  void ack(
      Cuback& cuback,
      const std::vector<PacketNum>& packetNums,
      std::chrono::microseconds rtt = 100ms) {
    now_ += 1ms;
    auto ackEvent = AckEvent::Builder()
                        .setAckTime(now_)
                        .setAdjustedAckTime(now_)
                        .setAckDelay(0us)
                        .setPacketNumberSpace(PacketNumberSpace::AppData)
                        .setLargestAckedPacket(std::ranges::max(packetNums))
                        .build();
    for (const auto packetNum : packetNums) {
      auto& packet = outstanding_.at(packetNum);
      ackEvent.ackedBytes += packet.metadata.encodedSize;
      ackEvent.ackedPackets.push_back(
          AckEvent::AckPacket::Builder()
              .setPacketNum(packetNum)
              .setOutstandingPacketMetadata(packet.metadata)
              .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
              .build());
      if (!ackEvent.largestNewlyAckedPacket ||
          packetNum > *ackEvent.largestNewlyAckedPacket) {
        ackEvent.largestNewlyAckedPacket = packetNum;
        ackEvent.largestNewlyAckedPacketSentTime = packet.metadata.time;
      }
      outstanding_.erase(packetNum);
    }
    ackEvent.rttSample = rtt;
    updateRtt(*conn_, rtt, 0us);
    onPacketAckOrLossWrapper(conn_.get(), &cuback, ackEvent, std::nullopt);
    // The transport passes each ACK to the L4S tracker after the congestion
    // controller.
    if (conn_->ecnL4sTracker) {
      conn_->ecnL4sTracker->onPacketAck(&ackEvent);
    }
  }

  // Validates L4S and adds the tracker, as the transport does.
  void enableL4s() {
    conn_->ecnState = ECNState::ValidatedL4S;
    conn_->ecnL4sTracker = std::make_shared<EcnL4sTracker>(*conn_);
  }

  // Acks the packets with `ce` of them echoed as CE and the rest as ECT(1).
  void ackL4s(
      Cuback& cuback,
      const std::vector<PacketNum>& packetNums,
      uint64_t ce,
      std::chrono::microseconds rtt = 100ms) {
    auto& ackState = conn_->ackStates.appDataAckState;
    ackState.ecnCECountEchoed += ce;
    ackState.ecnECT1CountEchoed += packetNums.size() - ce;
    ack(cuback, packetNums, rtt);
  }

  // Acks a flight without marks, which gives the tracker RTT samples. Then
  // acks the first packet of the next flight as CE and returns the rest.
  std::vector<PacketNum> enterL4sEpoch(
      Cuback& cuback,
      std::chrono::microseconds rtt = 100ms) {
    enableL4s();
    for (const auto packetNum : fillCwnd(cuback)) {
      ackL4s(cuback, {packetNum}, 0, rtt);
    }
    auto flight = fillCwnd(cuback);
    ackL4s(cuback, {flight[0]}, 1, rtt);
    flight.erase(flight.begin());
    return flight;
  }

  // A virtual RTT after the tracker restarts, acks two packets of a new
  // flight, one of them CE, which sets the weight to 0.5. Returns the rest of
  // the flight.
  std::vector<PacketNum> ackFirstL4sSample(
      Cuback& cuback,
      std::chrono::microseconds rtt = 100ms) {
    auto flight = fillCwnd(cuback);
    now_ += std::max<std::chrono::microseconds>(rtt, 25ms);
    ackL4s(cuback, {flight[0], flight[1]}, 1, rtt);
    flight.erase(flight.begin(), flight.begin() + 2);
    return flight;
  }

  // Ends slow start with a CE mark, ends the recovery that follows, and gives
  // the tracker its first weight after slow start. Returns the packets in
  // flight.
  std::vector<PacketNum> enterL4sAvoidance(
      Cuback& cuback,
      std::chrono::microseconds rtt = 100ms) {
    enterL4sEpoch(cuback, rtt);
    endRecovery(cuback, rtt);
    return ackFirstL4sSample(cuback, rtt);
  }

  // Acks each packet on its own, so that each ACK carries an RTT sample.
  void ackEach(
      Cuback& cuback,
      const std::vector<PacketNum>& packetNums,
      std::chrono::microseconds rtt) {
    for (const auto packetNum : packetNums) {
      ack(cuback, {packetNum}, rtt);
    }
  }

  void lose(
      Cuback& cuback,
      const std::vector<PacketNum>& packetNums,
      bool persistentCongestion = false) {
    now_ += 1ms;
    LossEvent lossEvent(now_);
    for (const auto packetNum : packetNums) {
      lossEvent.addLostPacket(outstanding_.at(packetNum));
      outstanding_.erase(packetNum);
    }
    lossEvent.persistentCongestion = persistentCongestion;
    conn_->outstandings.declaredLostCount += packetNums.size();
    onPacketAckOrLossWrapper(
        conn_.get(), &cuback, std::nullopt, std::move(lossEvent));
  }

  // An ACK that carries only packets declared lost before.
  void ackSpurious(Cuback& cuback, uint64_t packets) {
    now_ += 1ms;
    auto ackEvent = AckEvent::Builder()
                        .setAckTime(now_)
                        .setAdjustedAckTime(now_)
                        .setAckDelay(0us)
                        .setPacketNumberSpace(PacketNumberSpace::AppData)
                        .setLargestAckedPacket(
                            conn_->ackStates.appDataAckState.nextPacketNum - 1)
                        .build();
    ackEvent.numPacketsSpuriouslyAcked = packets;
    conn_->outstandings.declaredLostCount -= packets;
    cuback.onPacketAckOrLoss(&ackEvent, nullptr);
  }

  [[nodiscard]] std::vector<PacketNum> inFlight() const {
    std::vector<PacketNum> packetNums;
    packetNums.reserve(outstanding_.size());
    for (const auto& [packetNum, packet] : outstanding_) {
      packetNums.push_back(packetNum);
    }
    return packetNums;
  }

  // Grows the window to at least `cwnd` in slow start, fills it, and loses the
  // first packet of the flight. Cuback is then in Recovery with the rest of
  // the flight in flight. Returns the window before the reduction.
  uint64_t reduceAt(Cuback& cuback, uint64_t cwnd) {
    while (cuback.getCongestionWindow() < cwnd) {
      ack(cuback, fillCwnd(cuback));
    }
    const auto flight = fillCwnd(cuback);
    const auto cwndPrior = cuback.getCongestionWindow();
    lose(cuback, {flight[0]});
    return cwndPrior;
  }

  // Acks the packets sent before the congestion event, then ends Recovery
  // with the ACK of one packet sent after it. Returns the bytes that this last
  // ACK counts toward congestion avoidance.
  uint64_t endRecovery(Cuback& cuback, std::chrono::microseconds rtt = 100ms) {
    if (!outstanding_.empty()) {
      ack(cuback, inFlight(), rtt);
    }
    ack(cuback, {send(cuback)}, rtt);
    return kPacketSize;
  }

  // Runs the first two flights of HyStart++ on a new connection, the second
  // with a larger RTT, and returns whether Cuback entered CSS.
  bool entersCss(
      // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
      std::chrono::microseconds firstRtt,
      std::chrono::microseconds secondRtt) {
    outstanding_.clear();
    SetUp();
    Cuback cuback(*conn_);
    // The first ACK ends the first round, and the rest of the first flight
    // makes the round that the second flight is compared to.
    ackEach(cuback, fillCwnd(cuback), firstRtt);
    ackEach(cuback, fillCwnd(cuback), secondRtt);
    return cuback.getState() == State::ConservativeSlowStart;
  }

  // Runs the same congestion avoidance flights on a new connection, with each
  // flight acknowledged `perAck` packets at a time. Returns the cwnd growth.
  uint64_t growthWithAcksOf(std::ptrdiff_t perAck) {
    outstanding_.clear();
    SetUp();
    Cuback cuback(*conn_);
    reduceAt(cuback, 50 * kPacketSize);
    const auto reduced = cuback.getCongestionWindow();
    endRecovery(cuback);
    for (int i = 0; i < 20; i++) {
      const auto flight = fillCwnd(cuback);
      for (auto first = flight.begin(); first != flight.end();) {
        const auto last =
            first + std::min(perAck, std::distance(first, flight.end()));
        ack(cuback, {first, last});
        first = last;
      }
    }
    return cuback.getCongestionWindow() - reduced;
  }

  [[nodiscard]] uint64_t ssthresh(const Cuback& cuback) const {
    CongestionControllerStats stats{};
    cuback.getStats(stats);
    return stats.cubackStats.ssthresh;
  }

  std::unique_ptr<QuicConnectionStateBase> conn_;
  std::shared_ptr<FileQLogger> qLogger_ =
      std::make_shared<FileQLogger>(VantagePoint::Server);
  std::map<PacketNum, OutstandingPacketWrapper> outstanding_;
  TimePoint now_{Clock::now()};
  uint64_t pacingBytes_{0};
  std::chrono::microseconds pacingRtt_{0us};
};

TEST_F(CubackTest, StartsInSlowStart) {
  Cuback cuback(*conn_);
  EXPECT_EQ(cuback.type(), CongestionControlType::Cuback);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      conn_->transportSettings.initCwndInMss * kPacketSize);
  EXPECT_EQ(ssthresh(cuback), std::numeric_limits<uint64_t>::max());
  EXPECT_FALSE(cuback.isAppLimited());
}

TEST_F(CubackTest, SlowStartGrowsByAckedBytes) {
  Cuback cuback(*conn_);
  const auto initCwnd = cuback.getCongestionWindow();
  const auto packets = fillCwnd(cuback);
  ack(cuback, {packets[0], packets[1]});
  EXPECT_EQ(cuback.getCongestionWindow(), initCwnd + 2 * kPacketSize);
}

TEST_F(CubackTest, UnpacedSlowStartGrowsByAllAckedBytes) {
  conn_->pacer.reset();
  Cuback cuback(*conn_);
  const auto initCwnd = cuback.getCongestionWindow();
  const auto packets = fillCwnd(cuback);
  ack(cuback, packets);
  EXPECT_EQ(
      cuback.getCongestionWindow(), initCwnd + packets.size() * kPacketSize);
}

TEST_F(CubackTest, AppLimitedSenderDoesNotGrow) {
  Cuback cuback(*conn_);
  const auto initCwnd = cuback.getCongestionWindow();
  const auto packets = send(cuback, 5);
  cuback.setAppLimited();
  EXPECT_TRUE(cuback.isAppLimited());
  ack(cuback, packets);
  EXPECT_EQ(cuback.getCongestionWindow(), initCwnd);
}

TEST_F(CubackTest, PacketsInFlightWhenCwndFillsCountAsLimited) {
  Cuback cuback(*conn_);
  const auto initCwnd = cuback.getCongestionWindow();
  const auto early = send(cuback, 5);
  cuback.setAppLimited();
  fillCwnd(cuback);
  EXPECT_FALSE(cuback.isAppLimited());
  ack(cuback, early);
  EXPECT_EQ(cuback.getCongestionWindow(), initCwnd + 5 * kPacketSize);
}

TEST_F(CubackTest, PacketsSentAfterBecomingAppLimitedDoNotGrow) {
  Cuback cuback(*conn_);
  const auto limited = fillCwnd(cuback);
  ack(cuback, {limited[0], limited[1]});
  const auto cwnd = cuback.getCongestionWindow();
  cuback.setAppLimited();
  const auto late = send(cuback, 2);
  ack(cuback, late);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  ack(cuback, {limited[2]});
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, LossReducesByBetaOncePerRecovery) {
  Cuback cuback(*conn_);
  const auto inFlight = fillCwnd(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  lose(cuback, {inFlight[0]});
  const auto reduced = static_cast<uint64_t>(static_cast<double>(cwnd) * kBeta);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
  EXPECT_EQ(ssthresh(cuback), reduced);

  // Packets sent before the congestion event neither reduce nor grow cwnd.
  lose(cuback, {inFlight[1]});
  ack(cuback, {inFlight[2], inFlight[3]});
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);

  ack(cuback, {send(cuback)});
  EXPECT_EQ(cuback.getState(), State::CongestionAvoidance);
}

TEST_F(CubackTest, UndoesAReductionWhenEveryLossIsSpurious) {
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  ack(cuback, {flight[0], flight[1]});
  const auto cwnd = cuback.getCongestionWindow();
  lose(cuback, {flight[2], flight[3]});
  const auto reduced = cuback.getCongestionWindow();
  ASSERT_LT(reduced, cwnd);

  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  EXPECT_EQ(ssthresh(cuback), std::numeric_limits<uint64_t>::max());
}

TEST_F(CubackTest, UndoRestoresTheEpoch) {
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 50 * kPacketSize);
  const auto epoch = epochAfterReduction(cwndPrior, conn_->lossState.srtt);
  const auto cwnd = cuback.getCongestionWindow();
  uint64_t acked = endRecovery(cuback);
  // The transport has dropped the truly lost packet of the first event.
  conn_->outstandings.declaredLostCount = 0;

  const auto flight = fillCwnd(cuback);
  ack(cuback, {flight.begin(), flight.begin() + 10});
  acked += 10 * kPacketSize;
  lose(cuback, {flight[10]});
  ASSERT_EQ(cuback.getState(), State::Recovery);
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::CongestionAvoidance);

  // Growth goes on along the first epoch's curve.
  ack(cuback, {flight.begin() + 11, flight.end()});
  acked += (flight.size() - 11) * kPacketSize;
  EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked));
}

TEST_F(CubackTest, DoesNotUndoWhileEarlierLossesArePending) {
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  conn_->outstandings.declaredLostCount = 3;
  lose(cuback, {flight[0]});
  const auto reduced = cuback.getCongestionWindow();
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, DoesNotUndoEcnReductions) {
  conn_->ecnState = ECNState::ValidatedECN;
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  conn_->ackStates.appDataAckState.ecnCECountEchoed = 1;
  ack(cuback, {flight[0]});
  const auto reduced = cuback.getCongestionWindow();
  conn_->outstandings.declaredLostCount = 1;
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, UndoFollowsTheSpuriousLossRecoveryConfig) {
  conn_->transportSettings.ccaConfig.enableSpuriousLossRecovery = false;
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  lose(cuback, {flight[0]});
  const auto reduced = cuback.getCongestionWindow();
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, MinCwndBoundsReduction) {
  Cuback cuback(*conn_);
  for (int i = 0; i < 10; i++) {
    lose(cuback, {send(cuback)});
  }
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      conn_->transportSettings.minCwndInMss * kPacketSize);
}

TEST_F(CubackTest, CongestionAvoidanceFollowsTheAckClock) {
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 50 * kPacketSize);
  const auto epoch = epochAfterReduction(cwndPrior, conn_->lossState.srtt);
  const auto cwnd = cuback.getCongestionWindow();
  ASSERT_EQ(cwnd, static_cast<uint64_t>(epoch.cwndEpoch));
  uint64_t acked = endRecovery(cuback);

  // Each increase consumes D(cwnd) of acknowledged bytes, however the ACKs are
  // spread in time.
  for (int i = 0; i < 100; i++) {
    const auto packets = fillCwnd(cuback);
    for (const auto packetNum : packets) {
      ack(cuback, {packetNum});
      acked += kPacketSize;
      now_ += (i % 2) ? 1s : 1us;
    }
    EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked))
        << i;
  }
  // The flights covered the concave climb back to W_max and the convex region
  // past it, short of the max cwnd.
  EXPECT_GT(cuback.getCongestionWindow(), 2 * cwndPrior);
  EXPECT_LT(
      cuback.getCongestionWindow(),
      conn_->transportSettings.maxCwndInMss * kPacketSize);
}

TEST_F(CubackTest, AckAggregationDoesNotChangeGrowth) {
  // A stretch ACK carries the bytes of the ACKs it replaces.
  const auto growth = growthWithAcksOf(1);
  EXPECT_GT(growth, 5 * kPacketSize);
  EXPECT_EQ(growthWithAcksOf(10), growth);
  EXPECT_EQ(growthWithAcksOf(1000), growth);
}

TEST_F(CubackTest, IdlePeriodsDoNotAdvanceTheCurve) {
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 50 * kPacketSize);
  const auto epoch = epochAfterReduction(cwndPrior, conn_->lossState.srtt);
  const auto cwnd = cuback.getCongestionWindow();
  uint64_t acked = endRecovery(cuback);
  const auto flight = fillCwnd(cuback);
  const auto middle = flight.begin() + std::ssize(flight) / 2;
  const std::vector<PacketNum> before(flight.begin(), middle);
  const std::vector<PacketNum> after(middle, flight.end());
  ack(cuback, before);
  acked += before.size() * kPacketSize;

  // The sender goes quiet for 30 seconds in the middle of the flight.
  cuback.setAppLimited();
  cuback.setAppIdle(true, now_);
  now_ += 30s;
  cuback.setAppIdle(false, now_);
  ack(cuback, after);
  acked += after.size() * kPacketSize;
  EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked));

  const auto next = fillCwnd(cuback);
  ack(cuback, next);
  acked += next.size() * kPacketSize;
  EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked));
}

TEST_F(CubackTest, BandwidthComesFromSmoothedRttAtTheCongestionEvent) {
  // Later RTT samples move srtt, but not the bandwidth of the epoch.
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 50 * kPacketSize);
  const auto epoch = epochAfterReduction(cwndPrior, conn_->lossState.srtt);
  const auto cwnd = cuback.getCongestionWindow();
  uint64_t acked = endRecovery(cuback);
  for (int i = 0; i < 5; i++) {
    const auto packets = fillCwnd(cuback);
    ack(cuback, packets, 900ms);
    acked += packets.size() * kPacketSize;
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked));
}

TEST_F(CubackTest, FastConvergenceLowersWMax) {
  Cuback cuback(*conn_);
  const auto firstPrior = reduceAt(cuback, 50 * kPacketSize);
  endRecovery(cuback);

  // The next congestion event comes before cwnd is back to W_max.
  ack(cuback, fillCwnd(cuback));
  const auto flight = fillCwnd(cuback);
  const auto secondPrior = cuback.getCongestionWindow();
  ASSERT_LT(secondPrior, firstPrior);
  lose(cuback, {flight[0]});
  auto epoch = epochAfterReduction(secondPrior, conn_->lossState.srtt);
  epoch.wMax = static_cast<double>(secondPrior) * (1 + kBeta) / 2;
  const auto cwnd = cuback.getCongestionWindow();
  uint64_t acked = endRecovery(cuback);
  for (int i = 0; i < 50; i++) {
    for (const auto packetNum : fillCwnd(cuback)) {
      ack(cuback, {packetNum});
      acked += kPacketSize;
    }
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwndAfterAcking(epoch, cwnd, acked));
}

TEST_F(CubackTest, AckEndingRecoveryCountsOnlyPacketsSentAfterTheEvent) {
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 50 * kPacketSize);
  const auto epoch = epochAfterReduction(cwndPrior, conn_->lossState.srtt);
  const auto beforeEvent = inFlight();
  ASSERT_FALSE(beforeEvent.empty());
  const auto cwnd = cuback.getCongestionWindow();
  auto packets = send(cuback, 30);
  packets.insert(packets.end(), beforeEvent.begin(), beforeEvent.end());
  ack(cuback, packets);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      cwndAfterAcking(epoch, cwnd, 30 * kPacketSize));
}

TEST_F(CubackTest, MaxCwndBoundsGrowth) {
  conn_->transportSettings.maxCwndInMss = 15;
  Cuback cuback(*conn_);
  for (int i = 0; i < 5; i++) {
    ack(cuback, fillCwnd(cuback));
  }
  EXPECT_EQ(cuback.getCongestionWindow(), 15 * kPacketSize);
}

TEST_F(CubackTest, GrowsLikeRenoWithoutAnRttSample) {
  // A congestion event before the first RTT sample leaves the bandwidth
  // unknown, and each increase then takes a full cwnd of acknowledged bytes.
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  ASSERT_EQ(conn_->lossState.srtt, 0us);
  lose(cuback, {flight[0]});
  const auto cwnd = cuback.getCongestionWindow();
  uint64_t acked = endRecovery(cuback);
  while (acked + kPacketSize < cwnd) {
    ack(cuback, {send(cuback)});
    acked += kPacketSize;
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  ack(cuback, {send(cuback)});
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, EcnCeIsACongestionEventOncePerRecovery) {
  conn_->ecnState = ECNState::ValidatedECN;
  Cuback cuback(*conn_);
  const auto inFlight = fillCwnd(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  conn_->ackStates.appDataAckState.ecnCECountEchoed = 1;
  ack(cuback, {inFlight[0]});
  const auto reduced = static_cast<uint64_t>(static_cast<double>(cwnd) * kBeta);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);

  conn_->ackStates.appDataAckState.ecnCECountEchoed = 2;
  ack(cuback, {inFlight[1]});
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);

  const auto afterEvent = send(cuback);
  ack(cuback, {afterEvent});
  conn_->ackStates.appDataAckState.ecnCECountEchoed = 3;
  ack(cuback, {send(cuback)});
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(
      cuback.getCongestionWindow(), static_cast<uint64_t>(reduced * kBeta));
}

TEST_F(CubackTest, EcnCeIsIgnoredBeforeValidation) {
  conn_->ecnState = ECNState::AttemptingECN;
  Cuback cuback(*conn_);
  const auto inFlight = fillCwnd(cuback);
  conn_->ackStates.appDataAckState.ecnCECountEchoed = 1;
  ack(cuback, {inFlight[0]});
  EXPECT_EQ(cuback.getState(), State::SlowStart);
}

TEST_F(CubackTest, PersistentCongestionRestartsFromTheMinimumWindow) {
  Cuback cuback(*conn_);
  const auto cwndPrior = reduceAt(cuback, 40 * kPacketSize);
  const auto reduced = cuback.getCongestionWindow();
  // The rest of the flight is lost too, which shows persistent congestion.
  lose(cuback, inFlight(), true);
  const auto minCwnd = conn_->transportSettings.minCwndInMss * kPacketSize;
  EXPECT_EQ(cuback.getState(), State::SlowStart);
  EXPECT_EQ(cuback.getCongestionWindow(), minCwnd);
  EXPECT_EQ(ssthresh(cuback), reduced);

  // Slow start ends at ssthresh, and the bytes past it go to congestion
  // avoidance, which starts from K = 0 with cwnd_prior from the event.
  std::vector<PacketNum> packets;
  uint64_t beforeAck = 0;
  while (cuback.getState() == State::SlowStart) {
    packets = fillCwnd(cuback);
    beforeAck = cuback.getCongestionWindow();
    ack(cuback, packets);
  }
  EXPECT_EQ(cuback.getState(), State::CongestionAvoidance);
  const CubackEpoch epoch{
      .wMax = static_cast<double>(reduced),
      .cwndPrior = static_cast<double>(cwndPrior),
      .cwndEpoch = static_cast<double>(reduced),
      .bandwidth = static_cast<double>(reduced) * 1e6 /
          static_cast<double>(conn_->lossState.srtt.count())};
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      cwndAfterAcking(
          epoch,
          reduced,
          packets.size() * kPacketSize - (reduced - beforeAck)));
}

TEST_F(CubackTest, HystartEntersCssWhenTheRoundMinRttGrows) {
  // The threshold is a sixteenth of the last round's min RTT, kept between 4ms
  // and 16ms.
  EXPECT_FALSE(entersCss(100ms, 106200us));
  EXPECT_TRUE(entersCss(100ms, 106250us));
  EXPECT_FALSE(entersCss(20ms, 23900us));
  EXPECT_TRUE(entersCss(20ms, 24ms));
  EXPECT_FALSE(entersCss(400ms, 415900us));
  EXPECT_TRUE(entersCss(400ms, 416ms));
}

TEST_F(CubackTest, HystartNeedsEightRttSamplesPerRound) {
  Cuback cuback(*conn_);
  ackEach(cuback, fillCwnd(cuback), 20ms);
  const auto flight = fillCwnd(cuback);
  // This ACK ends the round, so the next round counts its samples from zero.
  ack(cuback, {flight[0]}, 20ms);
  ackEach(cuback, {flight.begin() + 1, flight.begin() + 8}, 50ms);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
  ack(cuback, {flight[8]}, 50ms);
  EXPECT_EQ(cuback.getState(), State::ConservativeSlowStart);
}

TEST_F(CubackTest, CssGrowsAtAQuarterOfSlowStart) {
  Cuback cuback(*conn_);
  ackEach(cuback, fillCwnd(cuback), 20ms);
  ackEach(cuback, fillCwnd(cuback), 40ms);
  ASSERT_EQ(cuback.getState(), State::ConservativeSlowStart);
  const auto cwnd = cuback.getCongestionWindow();
  const auto packets = fillCwnd(cuback);
  ack(cuback, {packets[0], packets[1], packets[2], packets[3]}, 40ms);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, CssResumesSlowStartWhenTheRttFalls) {
  Cuback cuback(*conn_);
  ackEach(cuback, fillCwnd(cuback), 20ms);
  ackEach(cuback, fillCwnd(cuback), 40ms);
  ASSERT_EQ(cuback.getState(), State::ConservativeSlowStart);
  ackEach(cuback, fillCwnd(cuback), 39ms);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
}

TEST_F(CubackTest, CssEntersCongestionAvoidanceAfterFiveRounds) {
  Cuback cuback(*conn_);
  ackEach(cuback, fillCwnd(cuback), 20ms);
  ackEach(cuback, fillCwnd(cuback), 40ms);
  ASSERT_EQ(cuback.getState(), State::ConservativeSlowStart);
  for (int round = 0; round < 4; round++) {
    ackEach(cuback, fillCwnd(cuback), 40ms);
    ASSERT_EQ(cuback.getState(), State::ConservativeSlowStart) << round;
  }
  // The ACK of the first packet of the next flight ends the fifth round.
  const auto packets = fillCwnd(cuback);
  ack(cuback, {packets[0]}, 40ms);
  EXPECT_EQ(cuback.getState(), State::CongestionAvoidance);
  const auto cwnd = cuback.getCongestionWindow();
  EXPECT_EQ(ssthresh(cuback), cwnd);

  // Without a reduction, W_max, cwnd_prior and cwnd_epoch are all the window
  // at the exit, so K is zero.
  const CubackEpoch epoch{
      .wMax = static_cast<double>(cwnd),
      .cwndPrior = static_cast<double>(cwnd),
      .cwndEpoch = static_cast<double>(cwnd),
      .bandwidth = static_cast<double>(cwnd) * 1e6 /
          static_cast<double>(conn_->lossState.srtt.count())};
  ack(cuback, {packets.begin() + 1, packets.end()}, 40ms);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      cwndAfterAcking(epoch, cwnd, (packets.size() - 1) * kPacketSize));
}

TEST_F(CubackTest, SlowStartAfterPersistentCongestionDoesNotUseHystart) {
  Cuback cuback(*conn_);
  reduceAt(cuback, 160 * kPacketSize);
  lose(cuback, inFlight(), true);
  ASSERT_EQ(cuback.getState(), State::SlowStart);
  for (int i = 0; i < 3; i++) {
    ackEach(cuback, fillCwnd(cuback), 20ms);
  }
  // HyStart++ would leave slow start on the RTT of this flight.
  ackEach(cuback, fillCwnd(cuback), 80ms);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
}

TEST_F(CubackTest, PacesAtTwiceCwndOverSrtt) {
  Cuback cuback(*conn_);
  ack(cuback, fillCwnd(cuback), 80ms);
  EXPECT_EQ(pacingBytes_, 2 * cuback.getCongestionWindow());
  EXPECT_EQ(pacingRtt_, conn_->lossState.srtt);
}

TEST_F(CubackTest, IgnoresAcksOutsideAppData) {
  Cuback cuback(*conn_);
  const auto cwnd = cuback.getCongestionWindow();
  auto handshakeAck = AckEvent::Builder()
                          .setAckTime(now_)
                          .setAdjustedAckTime(now_)
                          .setAckDelay(0us)
                          .setPacketNumberSpace(PacketNumberSpace::Handshake)
                          .setLargestAckedPacket(0)
                          .build();
  handshakeAck.largestNewlyAckedPacket = 0;
  handshakeAck.ackedBytes = kPacketSize;
  cuback.onPacketAckOrLoss(&handshakeAck, nullptr);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
}

TEST_F(CubackTest, LogsStateChanges) {
  Cuback cuback(*conn_);
  lose(cuback, {send(cuback)});
  const auto indices =
      getQLogEventIndices(QLogEventType::CongestionMetricUpdate, qLogger_);
  std::vector<std::string> triggers;
  for (const auto index : indices) {
    const auto* update = dynamic_cast<const QLogCongestionStateUpdateEvent*>(
        qLogger_->logs[index].get());
    if (update && update->trigger) {
      triggers.push_back(*update->trigger);
    }
  }
  EXPECT_EQ(triggers, std::vector<std::string>{kCongestionPacketLoss});
}

TEST_F(CubackTest, L4sCeEndsSlowStartWithHalfTheWindowAndARecovery) {
  enableL4s();
  Cuback cuback(*conn_);
  ackL4s(cuback, fillCwnd(cuback), 0);
  const auto flight = fillCwnd(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {flight[0]}, 1);
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd / 2);
  EXPECT_EQ(ssthresh(cuback), cwnd / 2);

  // The rest of the flight left before the reduction.
  now_ += 200ms;
  ackL4s(cuback, {flight[1]}, 1);
  lose(cuback, {flight[2]});
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd / 2);
}

TEST_F(CubackTest, L4sWeightIsMeasuredAgainAfterSlowStart) {
  Cuback cuback(*conn_);
  enterL4sEpoch(cuback);
  // The tracker's weight started at 1 on the first mark.
  ASSERT_GT(conn_->ecnL4sTracker->getL4sWeight(), 0.9);
  endRecovery(cuback);
  const auto flight = fillCwnd(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  // Marks do not reduce cwnd until the tracker's first update after the
  // recovery, a virtual RTT later.
  ackL4s(cuback, {flight[0]}, 1);
  now_ += 100ms;
  ackL4s(cuback, {flight[1], flight[2], flight[3]}, 0);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  // The update set the weight to the CE fraction since the recovery.
  const double weight = conn_->ecnL4sTracker->getL4sWeight();
  EXPECT_EQ(weight, 0.25);
  ackL4s(cuback, {flight[4]}, 1);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      static_cast<uint64_t>(static_cast<double>(cwnd) * (1 - weight / 2)));
}

TEST_F(CubackTest, L4sWeightIsMeasuredAfterALossEndsSlowStart) {
  Cuback cuback(*conn_);
  reduceAt(cuback, 40 * kPacketSize);
  endRecovery(cuback);
  // L4S is validated after slow start, and the next ACK restarts the tracker.
  enableL4s();
  const auto flight = fillCwnd(cuback);
  const auto beforeMark = cuback.getCongestionWindow();
  ackL4s(cuback, {flight[0]}, 1);
  EXPECT_GE(cuback.getCongestionWindow(), beforeMark);
  now_ += 100ms;
  ackL4s(cuback, {flight[1], flight[2], flight[3], flight[4]}, 1);
  const double weight = conn_->ecnL4sTracker->getL4sWeight();
  ASSERT_EQ(weight, 0.25);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {flight[5]}, 1);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      static_cast<uint64_t>(static_cast<double>(cwnd) * (1 - weight / 2)));
}

TEST_F(CubackTest, L4sWeightIsMeasuredAgainWhenCssEnds) {
  enableL4s();
  Cuback cuback(*conn_);
  ackEach(cuback, fillCwnd(cuback), 20ms);
  for (int round = 0; round < 5; round++) {
    ackEach(cuback, fillCwnd(cuback), 40ms);
  }
  const auto flight = fillCwnd(cuback);
  ack(cuback, {flight[0]}, 40ms);
  ASSERT_EQ(cuback.getState(), State::CongestionAvoidance);
  const auto beforeMark = cuback.getCongestionWindow();
  ackL4s(cuback, {flight[1]}, 1, 40ms);
  EXPECT_GE(cuback.getCongestionWindow(), beforeMark);
  now_ += 100ms;
  ackL4s(cuback, {flight[2], flight[3], flight[4]}, 0, 40ms);
  const double weight = conn_->ecnL4sTracker->getL4sWeight();
  ASSERT_EQ(weight, 0.25);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {flight[5]}, 1, 40ms);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      static_cast<uint64_t>(static_cast<double>(cwnd) * (1 - weight / 2)));
}

TEST_F(CubackTest, L4sCeReducesByHalfTheTrackerWeight) {
  Cuback cuback(*conn_);
  const auto inFlight = enterL4sAvoidance(cuback);
  const double weight = conn_->ecnL4sTracker->getL4sWeight();
  ASSERT_EQ(weight, 0.5);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {inFlight[0]}, 1);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      static_cast<uint64_t>(static_cast<double>(cwnd) * (1 - weight / 2)));
}

TEST_F(CubackTest, L4sReducesAtMostOncePerVirtualRtt) {
  Cuback cuback(*conn_);
  const auto inFlight = enterL4sAvoidance(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {inFlight[0]}, 1);
  const auto reduced = cuback.getCongestionWindow();
  ASSERT_LT(reduced, cwnd);
  now_ += 90ms;
  ackL4s(cuback, {inFlight[1]}, 1);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
  now_ += 10ms;
  ackL4s(cuback, {inFlight[2]}, 1);
  EXPECT_LT(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, L4sVirtualRttIsAtLeast25ms) {
  Cuback cuback(*conn_);
  const auto inFlight = enterL4sAvoidance(cuback, 10ms);
  const auto cwnd = cuback.getCongestionWindow();
  ackL4s(cuback, {inFlight[0]}, 1, 10ms);
  const auto reduced = cuback.getCongestionWindow();
  ASSERT_LT(reduced, cwnd);
  now_ += 20ms;
  ackL4s(cuback, {inFlight[1]}, 1, 10ms);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
  now_ += 5ms;
  ackL4s(cuback, {inFlight[2]}, 1, 10ms);
  EXPECT_LT(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, L4sReductionDoesNotStartARecoveryPeriod) {
  Cuback cuback(*conn_);
  const auto inFlight = enterL4sAvoidance(cuback);
  ackL4s(cuback, {inFlight[0]}, 1);
  const auto reduced = cuback.getCongestionWindow();
  // A packet sent before the reduction is lost, which is a congestion event.
  lose(cuback, {inFlight[1]});
  EXPECT_EQ(cuback.getState(), State::Recovery);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      static_cast<uint64_t>(static_cast<double>(reduced) * kBeta));
}

TEST_F(CubackTest, L4sGrowsOneSegmentPerCwndAcknowledged) {
  Cuback cuback(*conn_);
  enterL4sEpoch(cuback);
  // The ACK that ends the recovery counts one packet.
  endRecovery(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  const auto packets = cwnd / kPacketSize;
  const auto flight = fillCwnd(cuback);
  ASSERT_EQ(flight.size(), packets);
  for (uint64_t i = 0; i + 2 < packets; i++) {
    ackL4s(cuback, {flight[i]}, 0);
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  ackL4s(cuback, {flight[packets - 2]}, 0);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, L4sGrowthSlowsWithTheSquareOfVirtualRttOverSrtt) {
  Cuback cuback(*conn_);
  enterL4sEpoch(cuback, 5ms);
  // The ACK that ends the recovery counts one packet.
  endRecovery(cuback, 5ms);
  const auto cwnd = cuback.getCongestionWindow();
  // The virtual RTT is 25ms, five times srtt, so an increase takes 25 cwnds.
  std::vector<PacketNum> inFlight;
  const auto ackNext = [&]() {
    if (inFlight.empty()) {
      inFlight = fillCwnd(cuback);
    }
    ackL4s(cuback, {inFlight.front()}, 0, 5ms);
    inFlight.erase(inFlight.begin());
  };
  for (uint64_t acked = 2 * kPacketSize; acked < 25 * cwnd;
       acked += kPacketSize) {
    ackNext();
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  ackNext();
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, L4sGrowthCountsOnlyUnmarkedBytes) {
  Cuback cuback(*conn_);
  enterL4sEpoch(cuback);
  // The ACK that ends the recovery counts one packet.
  endRecovery(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  const auto packets = cwnd / kPacketSize;
  const auto flight = fillCwnd(cuback);
  ASSERT_EQ(flight.size(), packets);
  // Half of these carry CE and count as two unmarked packets. The marks come
  // before the tracker's first update after slow start, so cwnd stays.
  ackL4s(cuback, {flight.begin(), flight.begin() + 4}, 2);
  for (uint64_t i = 4; i < packets; i++) {
    ackL4s(cuback, {flight[i]}, 0);
  }
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd);
  ackL4s(cuback, {send(cuback)}, 0);
  EXPECT_EQ(cuback.getCongestionWindow(), cwnd + kPacketSize);
}

TEST_F(CubackTest, L4sLossUsesTheCubackResponse) {
  enableL4s();
  Cuback cuback(*conn_);
  reduceAt(cuback, 40 * kPacketSize);
  endRecovery(cuback);
  const auto flight = ackFirstL4sSample(cuback);
  ackL4s(cuback, {flight[0]}, 1);
  const auto cwnd = cuback.getCongestionWindow();
  lose(cuback, {flight[1]});
  ASSERT_EQ(cuback.getState(), State::Recovery);
  // The L4S epoch kept cwnd below the W_max of the first loss, and fast
  // convergence does not apply.
  const auto epoch = epochAfterReduction(cwnd, conn_->lossState.srtt);
  const auto reduced = cuback.getCongestionWindow();
  EXPECT_EQ(reduced, static_cast<uint64_t>(epoch.cwndEpoch));

  // Marks during the recovery leave cwnd alone.
  now_ += 200ms;
  ackL4s(cuback, {flight[2]}, 1);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);

  // After the recovery, cwnd grows on the Cuback curve.
  auto acked = endRecovery(cuback);
  const auto next = fillCwnd(cuback);
  ack(cuback, next);
  acked += next.size() * kPacketSize;
  EXPECT_EQ(
      cuback.getCongestionWindow(), cwndAfterAcking(epoch, reduced, acked));
}

TEST_F(CubackTest, L4sEndsWhenEcnValidationFails) {
  Cuback cuback(*conn_);
  enterL4sEpoch(cuback);
  endRecovery(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  // The transport removes the tracker when validation fails.
  conn_->ecnState = ECNState::FailedValidation;
  conn_->ecnL4sTracker.reset();
  // cwnd grows on the Cuback curve of an epoch that starts at cwnd.
  const CubackEpoch epoch{
      .wMax = static_cast<double>(cwnd),
      .cwndPrior = static_cast<double>(cwnd),
      .cwndEpoch = static_cast<double>(cwnd),
      .bandwidth = static_cast<double>(cwnd) * 1e6 /
          static_cast<double>(conn_->lossState.srtt.count())};
  const auto flight = fillCwnd(cuback);
  ack(cuback, flight);
  EXPECT_EQ(
      cuback.getCongestionWindow(),
      cwndAfterAcking(epoch, cwnd, flight.size() * kPacketSize));
}

TEST_F(CubackTest, L4sEpochPacesAtCwndOverSrtt) {
  Cuback cuback(*conn_);
  const auto inFlight = enterL4sEpoch(cuback);
  ackL4s(cuback, {inFlight[0]}, 0);
  EXPECT_EQ(pacingBytes_, cuback.getCongestionWindow());
  EXPECT_EQ(pacingRtt_, conn_->lossState.srtt);
}

TEST_F(CubackTest, DoesNotUndoL4sReductions) {
  enableL4s();
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  lose(cuback, {flight[0]});
  endRecovery(cuback);
  ackL4s(cuback, {ackFirstL4sSample(cuback)[0]}, 1);
  const auto reduced = cuback.getCongestionWindow();
  // The packet lost before turns out to have arrived.
  ackSpurious(cuback, 1);
  EXPECT_EQ(cuback.getCongestionWindow(), reduced);
}

TEST_F(CubackTest, ClassicEcnKeepsTheCubackCurveAndPacing) {
  conn_->ecnState = ECNState::ValidatedECN;
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  const auto cwnd = cuback.getCongestionWindow();
  conn_->ackStates.appDataAckState.ecnCECountEchoed = 1;
  ack(cuback, {flight[0]});
  ASSERT_EQ(cuback.getState(), State::Recovery);
  const auto epoch = epochAfterReduction(cwnd, conn_->lossState.srtt);
  const auto reduced = cuback.getCongestionWindow();
  ASSERT_EQ(reduced, static_cast<uint64_t>(epoch.cwndEpoch));

  auto acked = endRecovery(cuback);
  const auto next = fillCwnd(cuback);
  ack(cuback, next);
  acked += next.size() * kPacketSize;
  EXPECT_EQ(
      cuback.getCongestionWindow(), cwndAfterAcking(epoch, reduced, acked));
  EXPECT_EQ(pacingBytes_, 2 * cuback.getCongestionWindow());
}

TEST_F(CubackTest, L4sCeIsIgnoredBeforeValidation) {
  conn_->ecnState = ECNState::AttemptingL4S;
  Cuback cuback(*conn_);
  const auto flight = fillCwnd(cuback);
  ackL4s(cuback, {flight[0]}, 1);
  EXPECT_EQ(cuback.getState(), State::SlowStart);
}

} // namespace quic::test
