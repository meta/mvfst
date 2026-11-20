/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr3.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/state/QuicStateFunctions.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <vector>

using namespace testing;

namespace quic {

class Bbr3TestPeer {
 public:
  using Controller = Bbr3CongestionController;

  static Bandwidth maxBw(const Controller& cc) {
    return cc.maxBwFilter_.GetBest();
  }

  static Bandwidth secondBestMaxBw(const Controller& cc) {
    return cc.maxBwFilter_.GetSecondBest();
  }

  static Bandwidth thirdBestMaxBw(const Controller& cc) {
    return cc.maxBwFilter_.GetThirdBest();
  }

  static void advanceCycle(Controller& cc) {
    ++cc.cycleCount_;
  }

  static void updateMaxBw(Controller& cc, const Bbr3RateSample& rs) {
    cc.updateMaxBw(rs);
  }

  static void adaptLongTermModel(Controller& cc, const Bbr3RateSample& rs) {
    cc.adaptLongTermModel(rs);
  }

  static Optional<std::chrono::microseconds> minRtt(const Controller& cc) {
    return cc.minRtt_;
  }

  static void setMinRtt(Controller& cc, std::chrono::microseconds minRtt) {
    cc.minRtt_ = minRtt;
  }

  static void setPacingRate(Controller& cc, Bandwidth rate) {
    cc.pacingRate_ = rate;
    cc.applyPacingRate();
  }

  static Bandwidth bw(const Controller& cc) {
    return cc.bw_;
  }

  static Optional<Bandwidth> bwShortTerm(const Controller& cc) {
    return cc.bwShortTerm_;
  }

  static Optional<uint64_t> inflightLongTerm(const Controller& cc) {
    return cc.inflightLongTerm_;
  }

  static Optional<uint64_t> inflightShortTerm(const Controller& cc) {
    return cc.inflightShortTerm_;
  }

  static uint64_t extraAcked(const Controller& cc) {
    return cc.extraAckedFilter_.GetBest();
  }

  static bool fullBwReached(const Controller& cc) {
    return cc.fullBwReached_;
  }

  static bool fullBwNow(const Controller& cc) {
    return cc.fullBwNow_;
  }

  static uint64_t fullBwCount(const Controller& cc) {
    return cc.fullBwCount_;
  }

  static float pacingGain(const Controller& cc) {
    return cc.pacingGain_;
  }

  static float cwndGain(const Controller& cc) {
    return cc.cwndGain_;
  }

  static uint64_t roundCount(const Controller& cc) {
    return cc.roundCount_;
  }

  static bool roundStart(const Controller& cc) {
    return cc.roundStart_;
  }

  static bool idleRestart(const Controller& cc) {
    return cc.idleRestart_;
  }

  static uint64_t bdp(const Controller& cc) {
    return cc.bdp();
  }

  static uint64_t targetInflight(const Controller& cc) {
    return cc.targetInflight();
  }

  static uint64_t inflightWithGain(const Controller& cc, float gain) {
    return cc.inflightWithGain(cc.bw_, gain);
  }

  static Optional<TimePoint> probeRttDoneStamp(const Controller& cc) {
    return cc.probeRttDoneStamp_;
  }

  static uint64_t bwProbeUpRounds(const Controller& cc) {
    return cc.bwProbeUpRounds_;
  }

  static bool prevProbeTooHigh(const Controller& cc) {
    return cc.prevProbeTooHigh_;
  }

  static bool prevProbePrecautionary(const Controller& cc) {
    return cc.prevProbePrecautionary_;
  }

  static bool checkProbeLoss(const Controller& cc) {
    return cc.checkProbeLoss_;
  }

  static bool inRecovery(const Controller& cc) {
    return cc.inRecovery_;
  }

  static bool cwndLimitedInRound(const Controller& cc) {
    return cc.cwndLimitedInRound_;
  }

  static bool hasLossEpisode(const Controller& cc) {
    return cc.lossEpisode_.has_value();
  }

  static uint64_t lostRangesInLossRound(const Controller& cc) {
    return cc.lostRangesInLossRound_.count;
  }

  static Bandwidth pacingRate(const Controller& cc) {
    return cc.pacingRate_;
  }
};

namespace test {
namespace {

using State = Bbr3CongestionController::State;
using Peer = Bbr3TestPeer;

constexpr TimePoint kStart = TimePoint() + 1000s;
// 10 Mbit/s in bytes per second.
constexpr uint64_t kLinkRate = 1'250'000;
constexpr std::chrono::microseconds kLinkRtt = 40ms;
constexpr uint64_t kLinkBdp = kLinkRate * 40 / 1000;
constexpr uint64_t kLargeBuffer = 20 * kLinkBdp;
constexpr uint64_t kPacketSize = kDefaultUDPSendPacketLen;

class FakePacer : public Pacer {
 public:
  void refreshPacingRate(
      uint64_t cwndBytes,
      std::chrono::microseconds rtt,
      TimePoint /* currentTime */) override {
    window_ = cwndBytes;
    rtt_ = rtt;
    ++refreshCount_;
  }

  void setPacingRate(uint64_t /* rateBps */) override {}

  void setMaxPacingRate(uint64_t /* maxRateBytesPerSec */) override {}

  void reset() override {}

  void setRttFactor(uint8_t numerator, uint8_t denominator) override {
    rttFactor_ = {numerator, denominator};
  }

  [[nodiscard]] std::chrono::microseconds getTimeUntilNextWrite(
      TimePoint /* currentTime */) const override {
    return 0us;
  }

  uint64_t updateAndGetWriteBatchSize(TimePoint /* currentTime */) override {
    return 1;
  }

  [[nodiscard]] uint64_t getCachedWriteBatchSize() const override {
    return 1;
  }

  void onPacketSent() override {}

  void onPacketsLoss() override {}

  // Bytes per second, or nullopt when unpaced.
  [[nodiscard]] Optional<double> rate() const {
    if (window_ == 0 || rtt_ == 0us) {
      return std::nullopt;
    }
    return static_cast<double>(window_) * 1e6 /
        static_cast<double>(rtt_.count());
  }

  uint64_t window_{0};
  std::chrono::microseconds rtt_{0us};
  std::pair<uint8_t, uint8_t> rttFactor_{0, 0};
  uint64_t refreshCount_{0};
};

struct Link {
  uint64_t rate{kLinkRate};
  std::chrono::microseconds rtt{kLinkRtt};
  uint64_t buffer{kLargeBuffer};
};

// Drives a controller over a simulated path. Like mvfst, the sender sends a
// full packet whenever the cwnd has room, at the rate the controller gives its
// pacer. Packets queue at a drop-tail bottleneck, cross the propagation delay,
// and the receiver acknowledges each one, or releases its ACKs in batches. Like
// mvfst, the sender declares a packet lost when a packet more than three
// numbers later is acknowledged, and forgets declared-lost packets after a PTO.
class PathSimulator {
 public:
  // A nonzero initial SRTT stands for an RTT estimate left from another path.
  explicit PathSimulator(
      Link link,
      CongestionControlConfig ccaConfig = {},
      std::chrono::microseconds initialSrtt = 0us)
      : link_(link) {
    conn_.transportSettings.ccaConfig = ccaConfig;
    conn_.connectionTime = kStart;
    conn_.lossState.srtt = initialSrtt;
    auto pacer = std::make_unique<FakePacer>();
    pacer_ = pacer.get();
    conn_.pacer = std::move(pacer);
    cc_ = std::make_unique<Bbr3CongestionController>(
        conn_, [] { return uint32_t{0}; });
    states_.emplace_back(now_, cc_->getState());
  }

  Bbr3CongestionController& cc() {
    return *cc_;
  }

  QuicConnectionStateBase& conn() {
    return conn_;
  }

  FakePacer& pacer() {
    return *pacer_;
  }

  Link& link() {
    return link_;
  }

  [[nodiscard]] TimePoint now() const {
    return now_;
  }

  [[nodiscard]] PacketNum nextPacketNum() const {
    return nextPacketNum_;
  }

  [[nodiscard]] uint64_t lostPackets() const {
    return lostPackets_;
  }

  [[nodiscard]] PacketNum largestAcked() const {
    return largestAcked_;
  }

  [[nodiscard]] uint64_t sentPackets() const {
    return sentPackets_;
  }

  [[nodiscard]] const std::vector<std::pair<TimePoint, State>>& states() const {
    return states_;
  }

  // An empty rate gives the sender unlimited data.
  void setAppRate(Optional<uint64_t> bytesPerSecond) {
    updateAppData();
    appRate_ = bytesPerSecond;
    appBytes_ = 0;
  }

  void pauseApp(bool paused) {
    updateAppData();
    appPaused_ = paused;
  }

  void setAckAggregation(std::chrono::microseconds interval) {
    ackAggregation_ = interval;
  }

  // mvfst marks the connection app-limited only when a write leaves the cwnd
  // with room, so a sender that runs out of data with the cwnd full is never
  // marked.
  void setMarkAppLimited(bool markAppLimited) {
    markAppLimited_ = markAppLimited;
  }

  // The peer has reported ACK delays this long, which the PTO includes.
  void assumePeerAckDelay(std::chrono::microseconds ackDelay) {
    conn_.lossState.maxAckDelay = ackDelay;
  }

  // The transport processes each ACK this long after the socket receives it,
  // and uses the socket's receive time as the ACK time.
  void setAckProcessingDelay(std::chrono::microseconds delay) {
    ackProcessingDelay_ = delay;
  }

  void setDropPacket(std::function<bool(PacketNum)> dropPacket) {
    dropPacket_ = std::move(dropPacket);
  }

  void setExtraDelay(
      std::function<std::chrono::microseconds(PacketNum)> extraDelay) {
    extraDelay_ = std::move(extraDelay);
  }

  void setPolicer(uint64_t rate, uint64_t burst) {
    policerRate_ = rate;
    policerBurst_ = burst;
    policerTokens_ = static_cast<double>(burst);
    policerUpdated_ = now_;
  }

  // Runs right after each call to onPacketAckOrLoss.
  void setOnAck(std::function<void(const AckEvent&, const LossEvent*)> onAck) {
    onAck_ = std::move(onAck);
  }

  // Declares in-flight packets lost the way the loss timer does, in an event
  // without an ACK.
  void declareLost(const std::vector<PacketNum>& packetNums) {
    LossEvent loss(now_);
    for (const auto packetNum : packetNums) {
      auto* packet = findOutstanding(packetNum);
      if (packet && status_[packetNum] == PacketStatus::InFlight) {
        markLost(*packet, loss);
      }
    }
    if (loss.lostPackets > 0) {
      cc_->onPacketAckOrLoss(nullptr, &loss);
      recordState();
    }
  }

  // Returns true if stop returned true before the limit elapsed.
  bool runUntil(
      const std::function<bool()>& stop,
      std::chrono::microseconds limit) {
    const auto end = now_ + limit;
    while (true) {
      trySend();
      if (stop && stop()) {
        return true;
      }
      const auto next = std::min(
          events_.empty() ? TimePoint::max() : events_.begin()->first,
          nextSendOpportunity());
      if (next > end) {
        now_ = end;
        return false;
      }
      now_ = next;
      processEventsDue();
    }
  }

  void runFor(std::chrono::microseconds duration) {
    runUntil(nullptr, duration);
  }

  bool runUntilState(State state, std::chrono::microseconds limit) {
    return runUntil([&] { return cc_->getState() == state; }, limit);
  }

 private:
  enum class EventType : uint8_t { Receive, AckArrival, AckFlush };
  enum class PacketStatus : uint8_t { InFlight, Acked, Lost };

  struct Event {
    EventType type{EventType::Receive};
    PacketNum packetNum{0};
    size_t receivedCount{0};
    PacketNum largestAcked{0};
    std::chrono::microseconds ackDelay{0};
  };

  [[nodiscard]] uint64_t packetSize() const {
    return conn_.udpSendPacketLen;
  }

  void recordState() {
    if (states_.back().second != cc_->getState()) {
      states_.emplace_back(now_, cc_->getState());
    }
  }

  void updateAppData() {
    if (appRate_ && now_ > appUpdated_) {
      const auto elapsed =
          std::chrono::duration<double>(now_ - appUpdated_).count();
      appBytes_ = std::min(
          appBytes_ + elapsed * static_cast<double>(*appRate_),
          static_cast<double>(10 * packetSize()));
    }
    appUpdated_ = now_;
  }

  bool hasAppData() {
    if (appPaused_) {
      return false;
    }
    updateAppData();
    return !appRate_ || appBytes_ >= static_cast<double>(packetSize());
  }

  TimePoint nextSendOpportunity() {
    if (appPaused_ || cc_->getWritableBytes() == 0) {
      return TimePoint::max();
    }
    auto next = nextSendTime_;
    if (appRate_ && appBytes_ < static_cast<double>(packetSize())) {
      const auto wait = std::chrono::duration<double>(
          (static_cast<double>(packetSize()) - appBytes_) /
          static_cast<double>(*appRate_));
      next = std::max(
          next, now_ + std::chrono::ceil<std::chrono::microseconds>(wait));
    }
    return std::max(next, now_ + 1us);
  }

  void trySend() {
    while (cc_->getWritableBytes() > 0) {
      if (!hasAppData()) {
        if (markAppLimited_) {
          cc_->setAppLimited();
        }
        return;
      }
      if (now_ < nextSendTime_) {
        return;
      }
      sendPacket();
    }
  }

  void sendPacket() {
    const auto size = packetSize();
    const auto packetNum = nextPacketNum_++;
    auto& lossState = conn_.lossState;
    lossState.totalBytesSent += size;
    auto packet = makeTestingWritePacket(
        packetNum,
        size,
        lossState.totalBytesSent,
        now_,
        /*pathId=*/0,
        lossState.inflightBytes + size);
    packet.isAppLimited = cc_->isAppLimited();
    if (lossState.lastAckedPacketSentTime) {
      packet.lastAckedPacketInfo.emplace(
          *lossState.lastAckedPacketSentTime,
          *lossState.lastAckedTime,
          *lossState.adjustedLastAckedTime,
          lossState.totalBytesSentAtLastAck,
          lossState.totalBytesAckedAtLastAck);
    }
    conn_.outstandings.packets.push_back(std::move(packet));
    status_.push_back(PacketStatus::InFlight);
    lossState.inflightBytes += size;
    cc_->onPacketSent(conn_.outstandings.packets.back());
    recordState();
    if (appRate_) {
      appBytes_ -= static_cast<double>(size);
    }
    ++sentPackets_;
    const auto rate = pacer_->rate();
    nextSendTime_ = rate
        ? now_ +
            std::chrono::nanoseconds(
                static_cast<int64_t>(static_cast<double>(size) * 1e9 / *rate))
        : now_;
    forward(packetNum, size);
  }

  bool policerAdmits(uint64_t size) {
    if (!policerRate_) {
      return true;
    }
    const auto elapsed =
        std::chrono::duration<double>(now_ - policerUpdated_).count();
    policerTokens_ = std::min(
        policerTokens_ + elapsed * static_cast<double>(*policerRate_),
        static_cast<double>(policerBurst_));
    policerUpdated_ = now_;
    if (policerTokens_ < static_cast<double>(size)) {
      return false;
    }
    policerTokens_ -= static_cast<double>(size);
    return true;
  }

  void forward(PacketNum packetNum, uint64_t size) {
    if ((dropPacket_ && dropPacket_(packetNum)) || !policerAdmits(size)) {
      return;
    }
    const auto backlog = bottleneckFreeAt_ > now_
        ? static_cast<uint64_t>(
              std::chrono::duration<double>(bottleneckFreeAt_ - now_).count() *
              static_cast<double>(link_.rate))
        : 0;
    if (backlog + size > link_.buffer) {
      return;
    }
    bottleneckFreeAt_ = std::max(bottleneckFreeAt_, now_) +
        std::chrono::nanoseconds(size * 1'000'000'000 / link_.rate);
    auto arrival = bottleneckFreeAt_ + link_.rtt / 2;
    if (extraDelay_) {
      arrival += extraDelay_(packetNum);
    }
    events_.emplace(
        arrival, Event{.type = EventType::Receive, .packetNum = packetNum});
  }

  void processEventsDue() {
    while (!events_.empty() && events_.begin()->first <= now_) {
      const auto event = events_.begin()->second;
      events_.erase(events_.begin());
      switch (event.type) {
        case EventType::Receive:
          onReceive(event.packetNum);
          break;
        case EventType::AckFlush:
          ackFlushScheduled_ = false;
          sendAck();
          break;
        case EventType::AckArrival:
          onAckArrival(event);
          trySend();
          break;
      }
    }
  }

  void onReceive(PacketNum packetNum) {
    received_.push_back(packetNum);
    if (!largestReceived_ || packetNum > *largestReceived_) {
      largestReceived_ = packetNum;
      largestReceivedTime_ = now_;
    }
    if (ackAggregation_ == 0us) {
      sendAck();
      return;
    }
    if (!ackFlushScheduled_) {
      const auto intervals = (now_ - kStart) / ackAggregation_ + 1;
      events_.emplace(
          kStart + intervals * ackAggregation_,
          Event{.type = EventType::AckFlush});
      ackFlushScheduled_ = true;
    }
  }

  void sendAck() {
    events_.emplace(
        now_ + link_.rtt / 2 + ackProcessingDelay_,
        Event{
            .type = EventType::AckArrival,
            .receivedCount = received_.size(),
            .largestAcked = *largestReceived_,
            .ackDelay = std::chrono::duration_cast<std::chrono::microseconds>(
                now_ - largestReceivedTime_)});
  }

  OutstandingPacketWrapper* findOutstanding(PacketNum packetNum) {
    auto& packets = conn_.outstandings.packets;
    auto it = std::lower_bound(
        packets.begin(),
        packets.end(),
        packetNum,
        [](const OutstandingPacketWrapper& packet, PacketNum num) {
          return packet.packet.header.getPacketSequenceNum() < num;
        });
    if (it == packets.end() ||
        it->packet.header.getPacketSequenceNum() != packetNum) {
      return nullptr;
    }
    return &*it;
  }

  void onAckArrival(const Event& event) {
    const auto ackTime = now_ - ackProcessingDelay_;
    auto ack = AckEvent::Builder()
                   .setAckTime(ackTime)
                   .setAdjustedAckTime(ackTime - event.ackDelay)
                   .setAckDelay(event.ackDelay)
                   .setPacketNumberSpace(PacketNumberSpace::AppData)
                   .setLargestAckedPacket(event.largestAcked)
                   .build();
    Optional<PacketNum> largestNewlyAcked;
    TimePoint largestNewlyAckedSentTime;
    for (size_t i = ackedThrough_; i < event.receivedCount; ++i) {
      const auto packetNum = received_[i];
      auto* packet = findOutstanding(packetNum);
      if (!packet || status_[packetNum] == PacketStatus::Acked) {
        continue;
      }
      if (status_[packetNum] == PacketStatus::Lost) {
        ++ack.numPacketsSpuriouslyAcked;
        --conn_.outstandings.declaredLostCount;
        status_[packetNum] = PacketStatus::Acked;
        continue;
      }
      status_[packetNum] = PacketStatus::Acked;
      ack.ackedPackets.push_back(
          AckEvent::AckPacket::Builder()
              .setPacketNum(packetNum)
              .setOutstandingPacketMetadata(packet->metadata)
              .setLastAckedPacketInfo(
                  packet->lastAckedPacketInfo
                      ? &packet->lastAckedPacketInfo.value()
                      : nullptr)
              .setAppLimited(packet->isAppLimited)
              .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
              .build());
      ack.ackedBytes += packet->metadata.encodedSize;
      if (!largestNewlyAcked || packetNum > *largestNewlyAcked) {
        largestNewlyAcked = packetNum;
        largestNewlyAckedSentTime = packet->metadata.time;
      }
    }
    ackedThrough_ = event.receivedCount;

    auto& lossState = conn_.lossState;
    if (largestNewlyAcked) {
      ack.largestNewlyAckedPacket = largestNewlyAcked;
      ack.largestNewlyAckedPacketSentTime = largestNewlyAckedSentTime;
      if (*largestNewlyAcked == event.largestAcked) {
        const auto rtt = std::chrono::duration_cast<std::chrono::microseconds>(
            ackTime - largestNewlyAckedSentTime);
        ack.rttSample = rtt;
        updateRtt(conn_, rtt, event.ackDelay);
      }
      lossState.totalBytesAcked += ack.ackedBytes;
      lossState.inflightBytes -= ack.ackedBytes;
      lossState.lastAckedPacketSentTime = largestNewlyAckedSentTime;
      lossState.lastAckedTime = ackTime;
      lossState.adjustedLastAckedTime = ackTime - event.ackDelay;
      lossState.totalBytesSentAtLastAck = lossState.totalBytesSent;
      lossState.totalBytesAckedAtLastAck = lossState.totalBytesAcked;
    }
    ack.totalBytesAcked = lossState.totalBytesAcked;
    largestAcked_ = std::max(largestAcked_, event.largestAcked);

    LossEvent loss(ackTime);
    for (auto& packet : conn_.outstandings.packets) {
      const auto packetNum = packet.packet.header.getPacketSequenceNum();
      if (packetNum + kReorderingThreshold >= largestAcked_) {
        break;
      }
      if (status_[packetNum] != PacketStatus::InFlight) {
        continue;
      }
      markLost(packet, loss);
    }
    const auto* lossEvent = loss.lostPackets > 0 ? &loss : nullptr;
    cc_->onPacketAckOrLoss(&ack, lossEvent);
    recordState();
    if (onAck_) {
      onAck_(ack, lossEvent);
    }
    removeOldPackets(ackTime);
  }

  void markLost(OutstandingPacketWrapper& packet, LossEvent& loss) {
    status_[packet.packet.header.getPacketSequenceNum()] = PacketStatus::Lost;
    packet.declaredLost = true;
    ++conn_.outstandings.declaredLostCount;
    conn_.lossState.inflightBytes -= packet.metadata.encodedSize;
    loss.addLostPacket(packet);
    ++lostPackets_;
  }

  // Acknowledged packets leave. Like mvfst, a declared-lost packet stays until
  // it is a PTO old, so that a late ACK can show the loss was spurious.
  void removeOldPackets(TimePoint ackTime) {
    const auto& lossState = conn_.lossState;
    const auto pto = lossState.srtt + 4 * lossState.rttvar +
        std::min(lossState.maxAckDelay, conn_.peerMaxAckDelay);
    auto& packets = conn_.outstandings.packets;
    while (!packets.empty()) {
      const auto& front = packets.front();
      const auto status = status_[front.packet.header.getPacketSequenceNum()];
      const bool expiredLoss =
          status == PacketStatus::Lost && ackTime - front.metadata.time > pto;
      if (status != PacketStatus::Acked && !expiredLoss) {
        return;
      }
      if (expiredLoss) {
        --conn_.outstandings.declaredLostCount;
      }
      packets.pop_front();
    }
  }

  QuicConnectionStateBase conn_{QuicNodeType::Server};
  FakePacer* pacer_{nullptr};
  std::unique_ptr<Bbr3CongestionController> cc_;
  Link link_;
  TimePoint now_{kStart};
  std::vector<std::pair<TimePoint, State>> states_;

  PacketNum nextPacketNum_{0};
  TimePoint nextSendTime_{kStart};
  PacketNum largestAcked_{0};
  std::vector<PacketStatus> status_;
  uint64_t sentPackets_{0};
  uint64_t lostPackets_{0};

  Optional<uint64_t> appRate_;
  bool appPaused_{false};
  bool markAppLimited_{true};
  double appBytes_{0};
  TimePoint appUpdated_{kStart};

  TimePoint bottleneckFreeAt_{kStart};
  Optional<uint64_t> policerRate_;
  uint64_t policerBurst_{0};
  double policerTokens_{0};
  TimePoint policerUpdated_{kStart};

  std::vector<PacketNum> received_;
  Optional<PacketNum> largestReceived_;
  TimePoint largestReceivedTime_{kStart};
  std::chrono::microseconds ackAggregation_{0us};
  std::chrono::microseconds ackProcessingDelay_{0us};
  bool ackFlushScheduled_{false};
  size_t ackedThrough_{0};
  std::multimap<TimePoint, Event> events_;

  std::function<bool(PacketNum)> dropPacket_;
  std::function<std::chrono::microseconds(PacketNum)> extraDelay_;
  std::function<void(const AckEvent&, const LossEvent*)> onAck_;
};

double toBytesPerSecond(const Bandwidth& bandwidth) {
  return static_cast<double>(bandwidth.normalize());
}

bool sawState(const PathSimulator& sim, State state, size_t since = 0) {
  return std::any_of(
      sim.states().begin() + since, sim.states().end(), [&](const auto& entry) {
        return entry.second == state;
      });
}

// The state the controller was in before the latest transition.
State previousState(const PathSimulator& sim) {
  const auto& states = sim.states();
  return states.size() > 1 ? states[states.size() - 2].second
                           : states.back().second;
}

// Records the bytes in flight right after the ACK that moves the controller out
// of its current state.
Optional<uint64_t>& recordInflightAtExit(
    PathSimulator& sim,
    Optional<uint64_t>& inflightAtExit) {
  const auto state = sim.cc().getState();
  sim.setOnAck(
      [&sim, &inflightAtExit, state](const AckEvent&, const LossEvent*) {
        if (!inflightAtExit && sim.cc().getState() != state) {
          inflightAtExit = sim.conn().lossState.inflightBytes;
        }
      });
  return inflightAtExit;
}

// The probe loss check's byte threshold: more than 2% of the inflight.
bool exceedsLossThreshold(uint64_t lost, uint64_t inflight) {
  return static_cast<double>(lost) > 0.02 * static_cast<double>(inflight);
}

// Packets 0, 1, 3 and 4 from first: two pairs, which make two loss ranges.
bool inTwoPairs(PacketNum packetNum, PacketNum first) {
  const auto position = packetNum - first;
  return position < 5 && position != 2;
}

CongestionControlConfig draftConfig() {
  CongestionControlConfig config;
  config.enableAckAggregationInStartup = true;
  config.enablePrecautionaryBandwidthProbing = true;
  return config;
}

// The cases below follow the draft's "BBR Example Test Cases" appendix.

TEST(Bbr3Test, ExitsStartupOnBandwidthPlateau) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::Drain, 5s));

  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::Startup);
  EXPECT_TRUE(Peer::fullBwReached(cc));
  EXPECT_TRUE(Peer::fullBwNow(cc));
  EXPECT_EQ(Peer::fullBwCount(cc), 3);
  EXPECT_NEAR(toBytesPerSecond(Peer::maxBw(cc)), kLinkRate, 0.02 * kLinkRate);
  EXPECT_EQ(sim.lostPackets(), 0);
}

TEST(Bbr3Test, ExitsStartupOnLossWhenAppLimited) {
  PathSimulator sim(Link{});
  sim.setAppRate(kLinkRate * 8 / 10);
  sim.runFor(1s);
  ASSERT_EQ(sim.cc().getState(), State::Startup);

  // Losing every fourth packet loses well over 2% in more than six ranges per
  // round trip.
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum >= firstDropped && packetNum % 4 == 0;
  });
  ASSERT_TRUE(sim.runUntil([&] { return Peer::fullBwReached(sim.cc()); }, 1s));

  // App-limited sending keeps the inflight below the BDP, so Drain can end
  // on the same ACK.
  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::Startup);
  EXPECT_NE(cc.getState(), State::Startup);
  // Only the Startup loss exit sets inflight_longterm in Startup.
  EXPECT_TRUE(Peer::inflightLongTerm(cc).has_value());
  // The draft's example says full_bw_now is set, but its pseudocode sets only
  // full_bw_reached. This follows the pseudocode.
  EXPECT_FALSE(Peer::fullBwNow(cc));
}

TEST(Bbr3Test, ExitsDrainBasedOnInflight) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::Drain, 5s));
  EXPECT_FLOAT_EQ(Peer::pacingGain(sim.cc()), 0.5);
  const auto entryRound = Peer::roundCount(sim.cc());
  Optional<uint64_t> inflightAtExit;
  recordInflightAtExit(sim, inflightAtExit);

  ASSERT_TRUE(sim.runUntil([&] { return inflightAtExit.has_value(); }, 2s));

  // DOWN can move on to CRUISE on the same ACK, since the queue has drained.
  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::Drain);
  EXPECT_THAT(cc.getState(), AnyOf(State::ProbeBwDown, State::ProbeBwCruise));
  // The estimated BDP includes a packet's serialization time.
  EXPECT_LE(*inflightAtExit, kLinkBdp + 2 * kPacketSize);
  EXPECT_LT(Peer::roundCount(cc), entryRound + 3);
}

TEST(Bbr3Test, ExitsDrainBasedOnTime) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::Drain, 5s));
  // A plateau exit happens on a round start.
  ASSERT_TRUE(Peer::roundStart(sim.cc()));
  const auto entryRound = Peer::roundCount(sim.cc());
  // The draft suggests a 10% drop, but here the queue drains within three
  // rounds unless the bandwidth drops further.
  sim.link().rate = kLinkRate * 4 / 10;
  Optional<uint64_t> inflightAtExit;
  recordInflightAtExit(sim, inflightAtExit);

  ASSERT_TRUE(sim.runUntil([&] { return inflightAtExit.has_value(); }, 5s));

  const auto& cc = sim.cc();
  EXPECT_EQ(cc.getState(), State::ProbeBwDown);
  // The draft's prose ends Drain after 3 rounds. Its pseudocode takes 4.
  EXPECT_EQ(Peer::roundCount(cc), entryRound + 3);
  // max_bw still holds the old link rate, so the queue is above its BDP.
  EXPECT_GT(*inflightAtExit, kLinkBdp + 2 * kPacketSize);
}

TEST(Bbr3Test, CountsOnlyFullRoundsTowardTheDrainTimeLimit) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntil(
      [&] { return toBytesPerSecond(Peer::maxBw(sim.cc())) > 0.9 * kLinkRate; },
      5s));
  // A slower link keeps a queue through Drain, and losing every fourth packet
  // ends Startup on loss. The first loss starts the loss round that the exit
  // ends, so Drain starts partway through a round.
  sim.link().rate = kLinkRate / 10;
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum >= firstDropped && packetNum % 4 == 0;
  });
  ASSERT_TRUE(sim.runUntilState(State::Drain, 5s));
  ASSERT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());
  ASSERT_FALSE(Peer::roundStart(sim.cc()));
  const auto entryRound = Peer::roundCount(sim.cc());
  sim.setDropPacket(nullptr);
  // Each ACK's Drain check uses the bw from the ACK before it, so this keeps
  // the target from the last ACK in Drain.
  auto target = Peer::inflightWithGain(sim.cc(), 1.0);
  Optional<uint64_t> inflightAtExit;
  sim.setOnAck([&](const AckEvent&, const LossEvent*) {
    if (sim.cc().getState() == State::Drain) {
      target = Peer::inflightWithGain(sim.cc(), 1.0);
    } else if (!inflightAtExit) {
      inflightAtExit = sim.conn().lossState.inflightBytes;
    }
  });

  ASSERT_TRUE(sim.runUntil([&] { return inflightAtExit.has_value(); }, 10s));

  EXPECT_EQ(Peer::roundCount(sim.cc()), entryRound + 4);
  // Drain ended on time, not on inflight.
  EXPECT_GT(*inflightAtExit, target);
}

TEST(Bbr3Test, ExitsProbeUpOnBandwidthPlateau) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 5s));

  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::ProbeBwUp);
  EXPECT_TRUE(Peer::fullBwNow(sim.cc()));
  EXPECT_EQ(Peer::fullBwCount(cc), 3);
  EXPECT_FALSE(Peer::inflightLongTerm(cc).has_value());
  EXPECT_EQ(sim.lostPackets(), 0);
}

TEST(Bbr3Test, ExitsProbeUpOnLossWhenAppLimited) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  sim.setAppRate(kLinkRate * 9 / 10);
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum >= firstDropped && packetNum % 10 == 0;
  });

  ASSERT_TRUE(sim.runUntil(
      [&] { return sim.cc().getState() != State::ProbeBwUp; }, 1s));

  // App-limited sending keeps the inflight low, so DOWN can move on to CRUISE
  // on the same ACK.
  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::ProbeBwUp);
  EXPECT_THAT(cc.getState(), AnyOf(State::ProbeBwDown, State::ProbeBwCruise));
  EXPECT_TRUE(Peer::prevProbeTooHigh(cc));
  EXPECT_FALSE(Peer::checkProbeLoss(cc));
  // The draft's example updates inflight_longterm whether or not the sender is
  // app-limited, but its pseudocode skips app-limited samples. This follows
  // the pseudocode.
  EXPECT_FALSE(Peer::inflightLongTerm(cc).has_value());
}

TEST(Bbr3Test, StaysInStartupWhenAppLimitedWithoutLoss) {
  PathSimulator sim(Link{});
  sim.setAppRate(kLinkRate / 2);

  sim.runFor(5s);

  EXPECT_EQ(sim.cc().getState(), State::Startup);
  EXPECT_FALSE(Peer::fullBwReached(sim.cc()));
}

TEST(Bbr3Test, StaysInProbeUpWhenAppLimitedWithoutLoss) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  sim.setAppRate(kLinkRate / 2);

  sim.runFor(5s);

  EXPECT_EQ(sim.cc().getState(), State::ProbeBwUp);
}

TEST(Bbr3Test, ExitsProbeDownOnInflight) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 5s));
  EXPECT_FLOAT_EQ(Peer::pacingGain(sim.cc()), 0.9);

  Optional<uint64_t> inflightAtExit;
  recordInflightAtExit(sim, inflightAtExit);

  ASSERT_TRUE(sim.runUntil([&] { return inflightAtExit.has_value(); }, 2s));

  // Without inflight_longterm, only the BDP limits the exit.
  EXPECT_EQ(sim.cc().getState(), State::ProbeBwCruise);
  EXPECT_FALSE(Peer::inflightLongTerm(sim.cc()).has_value());
  EXPECT_LE(*inflightAtExit, kLinkBdp + 2 * kPacketSize);
}

TEST(Bbr3Test, ExitsProbeDownAfterMaxTime) {
  PathSimulator sim(Link{});
  // The DOWN phase after a probe starts with a queue to drain.
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 5s));
  const auto downStart = sim.now();
  // Pacing at 90% of the estimate now matches the link, so the queue does not
  // drain.
  sim.link().rate = kLinkRate * 9 / 10;

  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 5s));

  EXPECT_EQ(previousState(sim), State::ProbeBwDown);
  // The test's random source picks the shortest wait.
  EXPECT_GE(sim.now() - downStart, 2s);
}

TEST(Bbr3Test, EntersAndExitsProbeRtt) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  // On a fixed path, later samples only match min_rtt, which does not refresh
  // it.
  ASSERT_TRUE(sim.runUntilState(State::ProbeRtt, 15s));
  const auto& cc = sim.cc();
  EXPECT_FLOAT_EQ(Peer::cwndGain(cc), 0.5);

  ASSERT_TRUE(sim.runUntil(
      [&] { return Peer::probeRttDoneStamp(cc).has_value(); }, 1s));
  // Half of a BDP that includes a packet's serialization time.
  EXPECT_LE(cc.getCongestionWindow(), (kLinkBdp + 2 * kPacketSize) / 2);
  const auto drained = sim.now();
  ASSERT_TRUE(
      sim.runUntil([&] { return cc.getState() != State::ProbeRtt; }, 1s));

  EXPECT_GE(sim.now() - drained, 200ms);
  EXPECT_EQ(cc.getState(), State::ProbeBwCruise);
  EXPECT_FLOAT_EQ(Peer::cwndGain(cc), 2.0);
  const auto sent = sim.sentPackets();
  sim.runFor(100ms);
  EXPECT_GT(sim.sentPackets(), sent);
}

TEST(Bbr3Test, SkipsProbeRttAfterIdle) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  sim.pauseApp(true);
  sim.runFor(11s);
  ASSERT_EQ(sim.conn().lossState.inflightBytes, 0);

  sim.pauseApp(false);
  ASSERT_TRUE(sim.runUntil([&] { return Peer::idleRestart(sim.cc()); }, 1ms));
  sim.runFor(2s);

  EXPECT_FALSE(sawState(sim, State::ProbeRtt));
}

TEST(Bbr3Test, ReachesStartupBandwidthWithAckAggregation) {
  // ACKs arrive in bursts 60ms apart, longer than the path's RTT.
  struct Startup {
    uint64_t largestCwnd{0};
    double maxBw{0};
  };

  const auto runStartup = [](CongestionControlConfig config) {
    PathSimulator sim(Link{}, config);
    sim.setAckAggregation(60ms);
    Startup startup;
    sim.setOnAck([&](const AckEvent&, const LossEvent*) {
      if (sim.cc().getState() == State::Startup) {
        startup.largestCwnd =
            std::max(startup.largestCwnd, sim.cc().getCongestionWindow());
      }
    });
    EXPECT_TRUE(sim.runUntilState(State::Drain, 10s));
    startup.maxBw = toBytesPerSecond(Peer::maxBw(sim.cc()));
    return startup;
  };

  const auto withAggregation = runStartup(draftConfig());
  const auto withoutAggregation = runStartup(CongestionControlConfig{});

  EXPECT_GT(withAggregation.largestCwnd, 2 * kLinkBdp);
  EXPECT_GE(withAggregation.maxBw, 0.95 * kLinkRate);
  // The shared default leaves extra_acked out of the Startup cwnd.
  EXPECT_LT(withoutAggregation.largestCwnd, withAggregation.largestCwnd);
}

TEST(Bbr3Test, ReachesCruiseBandwidthWithAckAggregation) {
  PathSimulator sim(Link{});
  sim.setAckAggregation(20ms);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  const auto ackedAtStart = sim.conn().lossState.totalBytesAcked;

  sim.runFor(1s);

  const auto& cc = sim.cc();
  EXPECT_EQ(cc.getState(), State::ProbeBwCruise);
  EXPECT_GT(Peer::extraAcked(cc), 0);
  EXPECT_GT(cc.getCongestionWindow(), 2 * Peer::bdp(cc));
  const auto delivered = sim.conn().lossState.totalBytesAcked - ackedAtStart;
  EXPECT_GE(delivered, 0.95 * kLinkRate);
}

TEST(Bbr3Test, PacesAtTheLinkRateWithSubPacketBdp) {
  // 64 kbit/s with a 10ms path delay gives a BDP of 80 bytes.
  constexpr uint64_t kSlowRate = 8000;
  PathSimulator sim(Link{.rate = kSlowRate, .rtt = 10ms});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 60s));
  const auto ackedAtStart = sim.conn().lossState.totalBytesAcked;

  sim.runFor(10s);

  EXPECT_NEAR(
      toBytesPerSecond(Peer::pacingRate(sim.cc())) / Peer::pacingGain(sim.cc()),
      kSlowRate,
      0.1 * kSlowRate);
  const auto delivered = sim.conn().lossState.totalBytesAcked - ackedAtStart;
  EXPECT_GE(delivered, 0.9 * 10 * kSlowRate);
}

TEST(Bbr3Test, ReachesTenTimesTheBandwidthInLogarithmicRounds) {
  PathSimulator sim(Link{.buffer = kLinkBdp / 2});
  ASSERT_TRUE(sim.runUntil(
      [&] { return Peer::inflightLongTerm(sim.cc()).has_value(); }, 20s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 10s));
  sim.link().rate = 10 * kLinkRate;
  sim.link().buffer = 10 * kLinkBdp;
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 5s));

  // Record inflight_longterm at the start of each round of UP.
  std::vector<uint64_t> longTermAtRoundStart;
  uint64_t lastRound = Peer::roundCount(sim.cc());
  sim.setOnAck([&](const AckEvent&, const LossEvent*) {
    const auto& cc = sim.cc();
    if (cc.getState() == State::ProbeBwUp &&
        Peer::roundCount(cc) != lastRound) {
      lastRound = Peer::roundCount(cc);
      longTermAtRoundStart.push_back(Peer::inflightLongTerm(cc).value_or(0));
    }
  });
  const auto upStart = sim.now();
  ASSERT_TRUE(sim.runUntil(
      [&] {
        return toBytesPerSecond(Peer::maxBw(sim.cc())) >= 9.0 * kLinkRate;
      },
      5s));

  // inflight_longterm grows once the cwnd reaches it, and from then on each
  // round adds about twice as much as the round before.
  std::vector<int64_t> growth;
  for (size_t round = 1; round < longTermAtRoundStart.size(); ++round) {
    growth.push_back(
        static_cast<int64_t>(longTermAtRoundStart[round]) -
        static_cast<int64_t>(longTermAtRoundStart[round - 1]));
  }
  const auto firstGrowth = std::find_if(
      growth.begin(), growth.end(), [](int64_t bytes) { return bytes > 0; });
  ASSERT_GE(std::distance(firstGrowth, growth.end()), 3);
  EXPECT_GE(firstGrowth[2], 3 * firstGrowth[0]);
  EXPECT_LE(sim.now() - upStart, 20 * kLinkRtt);
}

TEST(Bbr3Test, AdaptsMaxBwToATenthOfTheBandwidth) {
  PathSimulator sim(Link{.buffer = kLinkBdp});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 10s));
  sim.link().rate = kLinkRate / 10;

  ASSERT_TRUE(sim.runUntil(
      [&] {
        const auto bwShortTerm = Peer::bwShortTerm(sim.cc());
        return bwShortTerm && toBytesPerSecond(*bwShortTerm) < 0.5 * kLinkRate;
      },
      2s));
  ASSERT_TRUE(sim.runUntil(
      [&] {
        return toBytesPerSecond(Peer::maxBw(sim.cc())) < 0.15 * kLinkRate;
      },
      20s));
}

TEST(Bbr3Test, SettlesBelowATokenBucketPolicer) {
  // A 2.5 Mbit/s policer with a 30 KB bucket on a 10 Mbit/s link.
  constexpr uint64_t kPolicerRate = kLinkRate / 4;
  PathSimulator sim(Link{});
  sim.setPolicer(kPolicerRate, 30'000);
  bool adaptedShortTermModel = false;
  sim.setOnAck([&](const AckEvent&, const LossEvent*) {
    adaptedShortTermModel |= Peer::bwShortTerm(sim.cc()).has_value() &&
        Peer::inflightShortTerm(sim.cc()).has_value();
  });
  sim.runFor(10s);
  EXPECT_TRUE(adaptedShortTermModel);
  const auto sentAtStart = sim.sentPackets();
  const auto lostAtStart = sim.lostPackets();
  const auto ackedAtStart = sim.conn().lossState.totalBytesAcked;

  sim.runFor(10s);

  const auto lost = sim.lostPackets() - lostAtStart;
  const auto sent = sim.sentPackets() - sentAtStart;
  EXPECT_LE(lost, sent / 20);
  const auto delivered = sim.conn().lossState.totalBytesAcked - ackedAtStart;
  EXPECT_GE(delivered, 0.8 * 10 * kPolicerRate);
}

TEST(Bbr3Test, UndoesASpuriousLossResponseInProbeUp) {
  PathSimulator sim(Link{});
  // The peer's ACK delay keeps lost packets long enough for their late ACKs.
  sim.assumePeerAckDelay(25ms);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  // Reordering two pairs of packets past the packet threshold makes them look
  // lost: two loss ranges, and too much loss for UP.
  const auto firstReordered = sim.nextPacketNum();
  sim.setExtraDelay([&](PacketNum packetNum) {
    return inTwoPairs(packetNum, firstReordered) ? 20ms : 0ms;
  });
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 1s));
  ASSERT_TRUE(Peer::hasLossEpisode(sim.cc()));
  ASSERT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());

  ASSERT_TRUE(
      sim.runUntil([&] { return !Peer::hasLossEpisode(sim.cc()); }, 1s));

  const auto& cc = sim.cc();
  EXPECT_FALSE(Peer::inflightLongTerm(cc).has_value());
  EXPECT_FALSE(Peer::inRecovery(cc));
  EXPECT_EQ(cc.getState(), State::ProbeBwRefill);
  EXPECT_TRUE(sim.runUntilState(State::ProbeBwUp, 1s));
}

TEST(Bbr3Test, ReturnsToStartupAfterProbeRtt) {
  PathSimulator sim(Link{});
  sim.setAppRate(kLinkRate / 2);

  ASSERT_TRUE(sim.runUntilState(State::ProbeRtt, 15s));
  EXPECT_EQ(previousState(sim), State::Startup);
  ASSERT_TRUE(sim.runUntilState(State::Startup, 2s));
  EXPECT_FALSE(Peer::fullBwReached(sim.cc()));
}

TEST(Bbr3Test, LowersInflightLongTermOnLossInProbeUp) {
  PathSimulator sim(Link{.buffer = kLinkBdp / 2});
  ASSERT_TRUE(sim.runUntil(
      [&] { return Peer::inflightLongTerm(sim.cc()).has_value(); }, 20s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 10s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 5s));
  const auto targetInflight = Peer::targetInflight(sim.cc());
  uint64_t longTermBeforeLoss = 0;
  sim.setOnAck([&](const AckEvent&, const LossEvent*) {
    if (sim.cc().getState() == State::ProbeBwUp) {
      longTermBeforeLoss = Peer::inflightLongTerm(sim.cc()).value_or(0);
    }
  });
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket(
      [&](PacketNum packetNum) { return inTwoPairs(packetNum, firstDropped); });

  ASSERT_TRUE(sim.runUntil(
      [&] { return sim.cc().getState() != State::ProbeBwUp; }, 1s));

  const auto& cc = sim.cc();
  EXPECT_EQ(previousState(sim), State::ProbeBwUp);
  EXPECT_TRUE(Peer::prevProbeTooHigh(cc));
  const auto longTerm = Peer::inflightLongTerm(cc);
  ASSERT_TRUE(longTerm.has_value());
  EXPECT_LT(*longTerm, longTermBeforeLoss);
  EXPECT_GE(*longTerm, 0.7 * targetInflight);
}

TEST(Bbr3Test, KeepsMaxBwWhenAppLimitedInRefill) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 10s));
  auto& cc = sim.cc();
  const auto maxBw = Peer::maxBw(cc);
  // By two cycles later, max_bw has expired, so any sample would replace it.
  Peer::advanceCycle(cc);
  Peer::advanceCycle(cc);
  Bbr3RateSample rs;
  rs.deliveryRate = Bandwidth(kLinkRate / 10, 1s);
  rs.isAppLimited = true;

  Peer::updateMaxBw(cc, rs);

  EXPECT_EQ(Peer::maxBw(cc), maxBw);
  rs.isAppLimited = false;
  Peer::updateMaxBw(cc, rs);
  EXPECT_EQ(Peer::maxBw(cc), rs.deliveryRate);
}

TEST(Bbr3Test, IgnoresAnAppLimitedSampleEqualToMaxBw) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 10s));
  auto& cc = sim.cc();
  Peer::advanceCycle(cc);
  Peer::advanceCycle(cc);
  Bbr3RateSample rs;
  rs.deliveryRate = Peer::maxBw(cc);
  rs.isAppLimited = true;

  Peer::updateMaxBw(cc, rs);

  // An app-limited sample that only matches max_bw does not keep it from
  // expiring.
  rs.deliveryRate = Bandwidth(kLinkRate / 10, 1s);
  rs.isAppLimited = false;
  Peer::updateMaxBw(cc, rs);
  EXPECT_EQ(Peer::maxBw(cc), rs.deliveryRate);
}

// Tests for the QUIC and mvfst choices, including the bbr2 behaviors that bbr3
// keeps, and for the shared settings that bbr3 reads.

TEST(Bbr3Test, SendsTheInitialWindowUnpaced) {
  PathSimulator sim(Link{});

  EXPECT_EQ(sim.pacer().rttFactor_, (std::pair<uint8_t, uint8_t>{1, 1}));
  EXPECT_EQ(sim.pacer().rtt_, 0us);
  EXPECT_EQ(sim.pacer().refreshCount_, 1);
}

TEST(Bbr3Test, StaysUnpacedUntilTheInitialWindowIsSent) {
  PathSimulator sim(Link{});
  const auto initialCwnd =
      sim.conn().transportSettings.initCwndInMss * sim.conn().udpSendPacketLen;
  // The app sends less than the initial window before the first ACK.
  sim.setAppRate(kLinkRate / 10);

  ASSERT_TRUE(
      sim.runUntil([&] { return Peer::minRtt(sim.cc()).has_value(); }, 1s));
  ASSERT_LT(sim.conn().lossState.totalBytesSent, initialCwnd);
  EXPECT_FALSE(sim.pacer().rate().has_value());

  sim.setAppRate(std::nullopt);
  ASSERT_TRUE(sim.runUntil([&] { return sim.pacer().rate().has_value(); }, 1s));
  EXPECT_GE(sim.conn().lossState.totalBytesSent, initialCwnd);
}

TEST(Bbr3Test, ResetsThePacerRttFactorWithEachRate) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntil([&] { return sim.pacer().rate().has_value(); }, 1s));
  // Another controller type scaled the shared pacer, as bbr2 does in Startup.
  sim.pacer().setRttFactor(1, 2);
  const auto refreshes = sim.pacer().refreshCount_;

  ASSERT_TRUE(
      sim.runUntil([&] { return sim.pacer().refreshCount_ > refreshes; }, 1s));

  EXPECT_EQ(sim.pacer().rttFactor_, (std::pair<uint8_t, uint8_t>{1, 1}));
}

TEST(Bbr3Test, PacesTheInitialWindowWhenConfigured) {
  CongestionControlConfig config;
  config.paceInitCwnd = true;
  PathSimulator sim(Link{}, config);

  // The draft's initial pacing rate, 2.77 * initial cwnd / 1ms.
  const auto initialCwnd =
      sim.conn().transportSettings.initCwndInMss * sim.conn().udpSendPacketLen;
  ASSERT_TRUE(sim.pacer().rate().has_value());
  EXPECT_NEAR(*sim.pacer().rate(), 2.77 * initialCwnd * 1000, initialCwnd);
}

TEST(Bbr3Test, CountsDiscontiguousLossRangesForTheStartupExit) {
  PathSimulator sim(Link{});
  sim.setAppRate(kLinkRate * 8 / 10);
  sim.runFor(1s);
  // Twelve contiguous losses form one range.
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum >= firstDropped && packetNum < firstDropped + 12;
  });

  sim.runFor(1s);

  EXPECT_EQ(sim.cc().getState(), State::Startup);
  EXPECT_FALSE(Peer::fullBwReached(sim.cc()));
}

OutstandingPacketWrapper makeLongHeaderPacket(
    LongHeader::Types type,
    PacketNum packetNum) {
  LongHeader header(
      type,
      getTestConnectionId(1),
      getTestConnectionId(),
      packetNum,
      QuicVersion::MVFST);
  return OutstandingPacketWrapper(
      RegularQuicWritePacket(std::move(header)),
      kStart,
      /*pathIdIn=*/0,
      kPacketSize,
      /*encodedBodySizeIn=*/0,
      /*totalBytesSentIn=*/kPacketSize,
      /*inflightBytesIn=*/kPacketSize,
      LossState(),
      /*writeCount=*/0,
      OutstandingPacketMetadata::DetailsPerStream());
}

TEST(Bbr3Test, CountsLossRangesInEachPacketNumberSpace) {
  PathSimulator sim(Link{});
  auto& cc = sim.cc();
  // Packet numbers start at zero in each space, so Handshake losses below the
  // lost Initial packet number still start new ranges.
  LossEvent initialLoss(kStart);
  initialLoss.addLostPacket(
      makeLongHeaderPacket(LongHeader::Types::Initial, 10));
  LossEvent handshakeLoss(kStart);
  for (PacketNum packetNum = 0; packetNum < 10; packetNum += 2) {
    handshakeLoss.addLostPacket(
        makeLongHeaderPacket(LongHeader::Types::Handshake, packetNum));
  }

  cc.onPacketAckOrLoss(nullptr, &initialLoss);
  cc.onPacketAckOrLoss(nullptr, &handshakeLoss);

  EXPECT_EQ(Peer::lostRangesInLossRound(cc), 6);
}

TEST(Bbr3Test, KeepsTheStartupLossBoundThroughDrain) {
  // Half a BDP of buffer overflows in Startup, which ends on loss.
  PathSimulator sim(Link{.buffer = kLinkBdp / 2});
  ASSERT_TRUE(sim.runUntilState(State::Drain, 5s));
  auto& cc = sim.cc();
  ASSERT_TRUE(Peer::inflightLongTerm(cc).has_value());
  const auto bound = *Peer::inflightLongTerm(cc);
  // The bound stays near what the path holds, one BDP plus the buffer.
  EXPECT_LE(bound, kLinkBdp * 3 / 2 + 2 * kPacketSize);

  // Drain does not use inflight_longterm, so even a sample with no loss since
  // it was sent does not raise it.
  Bbr3RateSample rs;
  rs.hasData = true;
  rs.txInFlight = bound + 10 * kPacketSize;
  Peer::adaptLongTermModel(cc, rs);
  EXPECT_EQ(Peer::inflightLongTerm(cc), bound);

  uint64_t highest = bound;
  uint64_t largestTxInFlightAfterDrain = 0;
  Optional<TimePoint> drainEnd;
  uint64_t sentAtDrainEnd = 0;
  bool ackedAfterDrain = false;
  sim.setOnAck([&](const AckEvent& ack, const LossEvent*) {
    if (!drainEnd && sim.cc().getState() != State::Drain) {
      drainEnd = sim.now();
      sentAtDrainEnd = sim.conn().lossState.totalBytesSent;
    }
    ackedAfterDrain = ackedAfterDrain ||
        (drainEnd && ack.largestNewlyAckedPacketSentTime >= *drainEnd);
    if (ackedAfterDrain) {
      return;
    }
    highest = std::max(
        highest,
        Peer::inflightLongTerm(sim.cc()).value_or(
            std::numeric_limits<uint64_t>::max()));
    if (drainEnd) {
      for (const auto& packet : ack.ackedPackets) {
        largestTxInFlightAfterDrain = std::max<uint64_t>(
            largestTxInFlightAfterDrain,
            packet.outstandingPacketMetadata.inflightBytes);
      }
    }
  });
  ASSERT_TRUE(sim.runUntil([&] { return ackedAfterDrain; }, 2s));

  // Packets sent in Startup and Drain had more in flight than the bound, and
  // entering DOWN restarts the round's loss count. Their ACKs after Drain still
  // cannot raise the bound.
  ASSERT_GT(largestTxInFlightAfterDrain, bound);
  EXPECT_EQ(highest, bound);

  // The boundary is the last packet sent in Drain, whatever the round.
  rs.txInFlight = bound + 10 * kPacketSize;
  rs.totalSent = sentAtDrainEnd;
  Peer::adaptLongTermModel(cc, rs);
  EXPECT_EQ(Peer::inflightLongTerm(cc), bound);
  rs.totalSent = sentAtDrainEnd + 1;
  Peer::adaptLongTermModel(cc, rs);
  EXPECT_EQ(Peer::inflightLongTerm(cc), rs.txInFlight);
}

TEST(Bbr3Test, CountsOnlyTheCurrentRoundsLossesInProbeUp) {
  PathSimulator sim(Link{.rate = 5 * kLinkRate});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  // The sender detects a loss in the round after the packet was sent. Losing
  // packets 20, 21 and 23 of UP's first round, then 0, 1 and 3 of the next,
  // puts two loss ranges and 3 losses, under 2% of the inflight, in each of two
  // rounds. The second round's packets were sent before the first round's
  // losses were detected, so counting the losses since each packet was sent
  // finds 6.
  const auto upRound = Peer::roundCount(sim.cc());
  auto round = upRound;
  uint64_t sentInRound = 0;
  std::vector<uint64_t> inflightAtDrop;
  sim.setDropPacket([&](PacketNum) {
    if (Peer::roundCount(sim.cc()) != round) {
      round = Peer::roundCount(sim.cc());
      sentInRound = 0;
    }
    const auto position = sentInRound++;
    const bool drop = (round == upRound &&
                       (position == 20 || position == 21 || position == 23)) ||
        (round == upRound + 1 &&
         (position == 0 || position == 1 || position == 3));
    if (drop) {
      inflightAtDrop.push_back(sim.conn().lossState.inflightBytes);
    }
    return drop;
  });
  // A round-starting ACK's losses count toward the round that it ends.
  std::map<uint64_t, uint64_t> lossesByRound;
  sim.setOnAck([&](const AckEvent&, const LossEvent* lossEvent) {
    if (lossEvent) {
      const auto& cc = sim.cc();
      lossesByRound[Peer::roundCount(cc) - (Peer::roundStart(cc) ? 1 : 0)] +=
          lossEvent->lostPackets;
    }
  });

  ASSERT_TRUE(sim.runUntil([&] { return sim.lostPackets() == 6; }, 1s));

  ASSERT_EQ(inflightAtDrop.size(), size_t{6});
  for (const auto inflight : inflightAtDrop) {
    ASSERT_FALSE(exceedsLossThreshold(3 * kPacketSize, inflight));
    ASSERT_TRUE(exceedsLossThreshold(6 * kPacketSize, inflight));
  }
  const std::map<uint64_t, uint64_t> expectedLosses{
      {upRound + 1, 3}, {upRound + 2, 3}};
  EXPECT_EQ(lossesByRound, expectedLosses);
  const auto& cc = sim.cc();
  EXPECT_EQ(cc.getState(), State::ProbeBwUp);
  EXPECT_FALSE(Peer::prevProbeTooHigh(cc));
  EXPECT_FALSE(Peer::inflightLongTerm(cc).has_value());
}

TEST(Bbr3Test, AddsUpTheCurrentRoundsLossesInProbeUp) {
  PathSimulator sim(Link{.rate = 5 * kLinkRate});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  // Losing 6 packets from the middle of UP's first round puts all 6 losses in
  // the next round, each detected on its own ACK. Neither batch of 3 is more
  // than 2% of the inflight, but both together are.
  const auto first = sim.nextPacketNum();
  std::vector<uint64_t> inflightAtDrop;
  sim.setDropPacket([&](PacketNum packetNum) {
    const auto position = packetNum - first;
    const bool drop =
        (position >= 20 && position < 23) || (position >= 40 && position < 43);
    if (drop) {
      inflightAtDrop.push_back(sim.conn().lossState.inflightBytes);
    }
    return drop;
  });

  ASSERT_TRUE(sim.runUntil(
      [&] { return sim.cc().getState() != State::ProbeBwUp; }, 1s));

  ASSERT_EQ(inflightAtDrop.size(), size_t{6});
  for (const auto inflight : inflightAtDrop) {
    ASSERT_FALSE(exceedsLossThreshold(3 * kPacketSize, inflight));
    ASSERT_TRUE(exceedsLossThreshold(6 * kPacketSize, inflight));
  }
  const auto& cc = sim.cc();
  EXPECT_EQ(cc.getState(), State::ProbeBwDown);
  EXPECT_TRUE(Peer::prevProbeTooHigh(cc));
  EXPECT_TRUE(Peer::inflightLongTerm(cc).has_value());
}

TEST(Bbr3Test, CountsLossesFromTheLossTimerInProbeUp) {
  PathSimulator sim(Link{.rate = 5 * kLinkRate});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  // Of 6 packets lost from the middle of UP's first round, the ACKs detect the
  // first 3 and the loss timer declares the other 3 in the same round. Neither
  // batch of 3 is more than 2% of the inflight, but both together are.
  const auto first = sim.nextPacketNum();
  std::vector<uint64_t> inflightAtDrop;
  sim.setDropPacket([&](PacketNum packetNum) {
    const auto position = packetNum - first;
    const bool drop =
        (position >= 20 && position < 23) || (position >= 40 && position < 43);
    if (drop) {
      inflightAtDrop.push_back(sim.conn().lossState.inflightBytes);
    }
    return drop;
  });
  // The timer declares only packets older than the largest acked one. Once
  // packet 43 is acked, packets 40 to 42 qualify, and the packet threshold has
  // not declared them yet.
  ASSERT_TRUE(
      sim.runUntil([&] { return sim.largestAcked() >= first + 43; }, 1s));
  ASSERT_EQ(sim.lostPackets(), 3);
  ASSERT_EQ(sim.cc().getState(), State::ProbeBwUp);
  ASSERT_EQ(inflightAtDrop.size(), size_t{6});
  for (const auto inflight : inflightAtDrop) {
    ASSERT_FALSE(exceedsLossThreshold(3 * kPacketSize, inflight));
    ASSERT_TRUE(exceedsLossThreshold(6 * kPacketSize, inflight));
  }

  sim.declareLost({first + 40, first + 41, first + 42});

  const auto& cc = sim.cc();
  EXPECT_EQ(cc.getState(), State::ProbeBwDown);
  EXPECT_TRUE(Peer::prevProbeTooHigh(cc));
  EXPECT_TRUE(Peer::inflightLongTerm(cc).has_value());
}

TEST(Bbr3Test, KeepsTheProbeLossCut) {
  PathSimulator sim(Link{.buffer = kLinkBdp / 2});
  ASSERT_TRUE(sim.runUntil(
      [&] { return Peer::inflightLongTerm(sim.cc()).has_value(); }, 20s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 10s));
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 5s));
  // Two separate losses are more than 2% of any inflight that this probe
  // reaches, so they end it.
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum == firstDropped || packetNum == firstDropped + 2;
  });
  Optional<uint64_t> sentAtCut;
  sim.setOnAck([&](const AckEvent&, const LossEvent*) {
    if (!sentAtCut && sim.cc().getState() != State::ProbeBwUp) {
      sentAtCut = sim.conn().lossState.totalBytesSent;
    }
  });
  ASSERT_TRUE(sim.runUntil([&] { return sentAtCut.has_value(); }, 1s));
  ASSERT_TRUE(Peer::prevProbeTooHigh(sim.cc()));
  ASSERT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());
  const auto cut = *Peer::inflightLongTerm(sim.cc());
  const auto cutTime = sim.now();
  uint64_t highest = cut;
  uint64_t largestTxInFlight = 0;
  bool lossInWindow = false;
  bool ackedAfterCut = false;
  sim.setOnAck([&](const AckEvent& ack, const LossEvent* lossEvent) {
    ackedAfterCut =
        ackedAfterCut || ack.largestNewlyAckedPacketSentTime >= cutTime;
    if (ackedAfterCut) {
      return;
    }
    lossInWindow = lossInWindow || lossEvent;
    highest = std::max(
        highest,
        Peer::inflightLongTerm(sim.cc()).value_or(
            std::numeric_limits<uint64_t>::max()));
    for (const auto& packet : ack.ackedPackets) {
      largestTxInFlight = std::max<uint64_t>(
          largestTxInFlight, packet.outstandingPacketMetadata.inflightBytes);
    }
  });

  ASSERT_TRUE(sim.runUntil([&] { return ackedAfterCut; }, 1s));

  // Packets sent before the cut had more in flight than the cut, and DOWN's
  // round clears the loss counts. With no other loss to block them, their ACKs
  // still cannot raise the cap back, because they were sent before the cut.
  ASSERT_GT(largestTxInFlight, cut);
  ASSERT_FALSE(lossInWindow);
  EXPECT_EQ(highest, cut);

  // The boundary is the bytes sent at the cut, whatever the round.
  auto& cc = sim.cc();
  Bbr3RateSample rs;
  rs.hasData = true;
  rs.txInFlight = cut + 10 * kPacketSize;
  rs.totalSent = *sentAtCut;
  Peer::adaptLongTermModel(cc, rs);
  EXPECT_EQ(Peer::inflightLongTerm(cc), cut);
  rs.totalSent = *sentAtCut + 1;
  Peer::adaptLongTermModel(cc, rs);
  EXPECT_EQ(Peer::inflightLongTerm(cc), rs.txInFlight);
}

TEST(Bbr3Test, IgnoresALoneLossRangeInProbeUp) {
  PathSimulator sim(Link{});
  // A probe that loses two separate packets sets inflight_longterm.
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  const auto firstProbeStart = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum == firstProbeStart + 20 ||
        packetNum == firstProbeStart + 22;
  });
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 1s));
  ASSERT_TRUE(Peer::prevProbeTooHigh(sim.cc()));
  ASSERT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  // The next probe loses four consecutive packets from the middle of its first
  // round: more than 2% of the inflight, but a single loss range.
  const auto secondProbeStart = sim.nextPacketNum();
  std::vector<uint64_t> inflightAtDrop;
  sim.setDropPacket([&](PacketNum packetNum) {
    const auto position = packetNum - secondProbeStart;
    const bool drop = position >= 20 && position < 24;
    if (drop) {
      inflightAtDrop.push_back(sim.conn().lossState.inflightBytes);
    }
    return drop;
  });
  const auto lostAtStart = sim.lostPackets();
  ASSERT_TRUE(
      sim.runUntil([&] { return sim.lostPackets() == lostAtStart + 4; }, 1s));
  ASSERT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());
  const auto longTermAtLoss = *Peer::inflightLongTerm(sim.cc());
  const auto lossTime = sim.now();
  uint64_t highest = longTermAtLoss;
  bool ackedAfterLoss = false;
  sim.setOnAck([&](const AckEvent& ack, const LossEvent*) {
    ackedAfterLoss =
        ackedAfterLoss || ack.largestNewlyAckedPacketSentTime >= lossTime;
    if (!ackedAfterLoss) {
      highest = std::max(highest, Peer::inflightLongTerm(sim.cc()).value_or(0));
    }
  });

  ASSERT_TRUE(sim.runUntil([&] { return ackedAfterLoss; }, 1s));

  // Without the minimum, the probe would end by the fourth loss.
  ASSERT_EQ(inflightAtDrop.size(), size_t{4});
  ASSERT_TRUE(exceedsLossThreshold(4 * kPacketSize, inflightAtDrop.back()));
  // The ACKs of packets sent before the losses were declared keep raising the
  // cap, and the probe goes on.
  EXPECT_GT(highest, longTermAtLoss);
  EXPECT_EQ(sim.cc().getState(), State::ProbeBwUp);
}

TEST(Bbr3Test, StaysInStartupOnLossWhenTheLossExitIsDisabled) {
  CongestionControlConfig config;
  config.exitStartupOnLoss = false;
  PathSimulator sim(Link{}, config);
  sim.setAppRate(kLinkRate * 8 / 10);
  sim.runFor(1s);
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) {
    return packetNum >= firstDropped && packetNum < firstDropped + 200 &&
        packetNum % 4 == 0;
  });

  sim.runFor(1s);

  EXPECT_EQ(sim.cc().getState(), State::Startup);
}

TEST(Bbr3Test, ReturnsToStartupWhenTheStartupLossExitWasSpurious) {
  // On a 100 Mbit/s path with a 10ms RTT, reordering by 15ms lets Startup exit
  // on loss before the late ACKs arrive. The peer's ACK delay keeps the lost
  // packets until then.
  PathSimulator sim(Link{.rate = 10 * kLinkRate, .rtt = 10ms});
  sim.assumePeerAckDelay(25ms);
  sim.setAppRate(8 * kLinkRate);
  sim.runFor(1s);
  const auto firstReordered = sim.nextPacketNum();
  sim.setExtraDelay([&](PacketNum packetNum) {
    return packetNum >= firstReordered && packetNum < firstReordered + 32 &&
            packetNum % 4 == 0
        ? 15ms
        : 0ms;
  });
  ASSERT_TRUE(sim.runUntil([&] { return Peer::fullBwReached(sim.cc()); }, 1s));

  ASSERT_TRUE(sim.runUntil([&] { return !Peer::fullBwReached(sim.cc()); }, 1s));

  EXPECT_EQ(sim.cc().getState(), State::Startup);
  EXPECT_FALSE(Peer::inflightLongTerm(sim.cc()).has_value());
}

TEST(Bbr3Test, KeepsTheLossResponseWhenSpuriousLossRecoveryIsDisabled) {
  CongestionControlConfig config;
  config.enableSpuriousLossRecovery = false;
  PathSimulator sim(Link{}, config);
  sim.assumePeerAckDelay(25ms);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  const auto firstReordered = sim.nextPacketNum();
  sim.setExtraDelay([&](PacketNum packetNum) {
    return inTwoPairs(packetNum, firstReordered) ? 20ms : 0ms;
  });
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 1s));
  const auto statesAtDown = sim.states().size();

  sim.runFor(200ms);

  EXPECT_TRUE(Peer::inflightLongTerm(sim.cc()).has_value());
  EXPECT_FALSE(sawState(sim, State::ProbeBwRefill, statesAtDown));
}

TEST(Bbr3Test, ProbesEarlierToCoexistWithReno) {
  CongestionControlConfig config;
  config.enableRenoCoexistence = true;
  // A 2 Mbit/s path has a BDP of about 8 packets, so Reno would probe within
  // eight rounds.
  PathSimulator sim(Link{.rate = kLinkRate / 5}, config);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 10s));
  const auto downStart = sim.now();

  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 5s));

  EXPECT_LT(sim.now() - downStart, 1s);
}

TEST(Bbr3Test, WaitsForTheProbeTimerByDefault) {
  // The same 2 Mbit/s path, with Reno coexistence off by default.
  PathSimulator sim(Link{.rate = kLinkRate / 5});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 10s));
  const auto downStart = sim.now();

  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 5s));

  EXPECT_GE(sim.now() - downStart, 2s);
}

TEST(Bbr3Test, StopsAndRestartsProbesEarlyAfterTooMuchLoss) {
  PathSimulator sim(Link{.buffer = kLinkBdp}, draftConfig());
  // End a probe with too much loss: two pairs of lost packets.
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
  const auto firstDropped = sim.nextPacketNum();
  sim.setDropPacket(
      [&](PacketNum packetNum) { return inTwoPairs(packetNum, firstDropped); });
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 1s));
  ASSERT_TRUE(Peer::prevProbeTooHigh(sim.cc()));

  // The next probe stops as soon as it reaches inflight_longterm...
  ASSERT_TRUE(sim.runUntil(
      [&] { return Peer::prevProbePrecautionary(sim.cc()); }, 10s));
  ASSERT_EQ(sim.cc().getState(), State::ProbeBwDown);
  const auto downStart = sim.now();

  // ... and the one after starts without the usual wait.
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 5s));
  EXPECT_LT(sim.now() - downStart, 500ms);
}

TEST(Bbr3Test, ProbesNormallyAfterTooMuchLossByDefault) {
  // Ends one probe with too much loss and reports whether the next probe
  // stopped early.
  const auto nextProbeIsPrecautionary = [](CongestionControlConfig config) {
    PathSimulator sim(Link{.buffer = kLinkBdp}, config);
    EXPECT_TRUE(sim.runUntilState(State::ProbeBwUp, 10s));
    const auto firstDropped = sim.nextPacketNum();
    sim.setDropPacket([&](PacketNum packetNum) {
      return inTwoPairs(packetNum, firstDropped);
    });
    EXPECT_TRUE(sim.runUntilState(State::ProbeBwDown, 1s));
    EXPECT_TRUE(Peer::prevProbeTooHigh(sim.cc()));
    bool precautionary = false;
    sim.setOnAck([&](const AckEvent&, const LossEvent*) {
      precautionary = precautionary || Peer::prevProbePrecautionary(sim.cc());
    });
    EXPECT_TRUE(sim.runUntilState(State::ProbeBwUp, 5s));
    EXPECT_TRUE(sim.runUntilState(State::ProbeBwDown, 5s));
    return precautionary;
  };

  CongestionControlConfig precautionaryConfig;
  precautionaryConfig.enablePrecautionaryBandwidthProbing = true;
  EXPECT_TRUE(nextProbeIsPrecautionary(precautionaryConfig));
  // Precautionary probing is off by default.
  EXPECT_FALSE(nextProbeIsPrecautionary(CongestionControlConfig{}));
}

TEST(Bbr3Test, CountsAFullCwndAsCwndLimited) {
  PathSimulator sim(Link{});
  auto& conn = sim.conn();
  auto& cc = sim.cc();
  const auto cwnd = cc.getCongestionWindow();

  auto send = [&](PacketNum packetNum, uint64_t inflight) {
    auto packet =
        makeTestingWritePacket(packetNum, 1000, inflight, kStart, 0, inflight);
    conn.lossState.inflightBytes = inflight;
    cc.onPacketSent(packet);
  };
  send(0, cwnd - 1);
  EXPECT_FALSE(Peer::cwndLimitedInRound(cc));
  send(1, cwnd);
  EXPECT_TRUE(Peer::cwndLimitedInRound(cc));
}

TEST(Bbr3Test, IgnoresImplicitAcks) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  const auto dropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) { return packetNum == dropped; });
  ASSERT_TRUE(sim.runUntil([&] { return Peer::inRecovery(sim.cc()); }, 1s));
  const auto sentInRecovery = sim.sentPackets();
  ASSERT_TRUE(
      sim.runUntil([&] { return sim.sentPackets() > sentInRecovery; }, 10ms));
  auto& cc = sim.cc();
  ASSERT_TRUE(Peer::inRecovery(cc));
  const auto cwnd = cc.getCongestionWindow();
  const auto roundCount = Peer::roundCount(cc);

  // An ACK for a packet sent after the loss would end recovery.
  const auto& newest = sim.conn().outstandings.packets.back();
  const auto newestPacketNum = newest.packet.header.getPacketSequenceNum();
  auto ack = AckEvent::Builder()
                 .setAckTime(sim.now())
                 .setAdjustedAckTime(sim.now())
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(newestPacketNum)
                 .setIsImplicitAck(true)
                 .build();
  ack.largestNewlyAckedPacket = newestPacketNum;
  ack.largestNewlyAckedPacketSentTime = newest.metadata.time;
  ack.ackedBytes = newest.metadata.encodedSize;
  ack.totalBytesAcked = sim.conn().lossState.totalBytesAcked;
  cc.onPacketAckOrLoss(&ack, nullptr);

  EXPECT_TRUE(Peer::inRecovery(cc));
  EXPECT_EQ(cc.getCongestionWindow(), cwnd);
  EXPECT_EQ(Peer::roundCount(cc), roundCount);
}

TEST(Bbr3Test, DropsTheCwndOnPersistentCongestionWithoutUndo) {
  PathSimulator sim(Link{});
  auto& conn = sim.conn();
  auto& cc = sim.cc();
  auto packet = makeTestingWritePacket(0, 1000, 1000, kStart, 0, 1000);
  packet.declaredLost = true;
  conn.outstandings.packets.push_back(std::move(packet));
  conn.outstandings.declaredLostCount = 1;

  LossEvent loss(kStart + 1s);
  loss.addLostPacket(conn.outstandings.packets.back());
  loss.persistentCongestion = true;
  cc.onPacketAckOrLoss(nullptr, &loss);

  ASSERT_EQ(cc.getCongestionWindow(), 4 * kPacketSize);

  // The lost packet turns out to have been delivered.
  conn.outstandings.declaredLostCount = 0;
  auto ack = AckEvent::Builder()
                 .setAckTime(kStart + 1100ms)
                 .setAdjustedAckTime(kStart + 1100ms)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(0)
                 .build();
  ack.numPacketsSpuriouslyAcked = 1;
  cc.onPacketAckOrLoss(&ack, nullptr);

  EXPECT_EQ(cc.getCongestionWindow(), 4 * kPacketSize);
}

TEST(Bbr3Test, RestoresTheCwndWhenRecoveryFromPersistentCongestionEnds) {
  PathSimulator sim(Link{});
  auto& conn = sim.conn();
  auto& cc = sim.cc();
  const auto cwnd = cc.getCongestionWindow();
  auto lostPacket = makeTestingWritePacket(0, 1000, 1000, kStart, 0, 1000);
  cc.onPacketSent(lostPacket);
  lostPacket.declaredLost = true;
  conn.outstandings.packets.push_back(std::move(lostPacket));
  conn.outstandings.declaredLostCount = 1;
  LossEvent loss(kStart + 1s);
  loss.addLostPacket(conn.outstandings.packets.back());
  loss.persistentCongestion = true;
  cc.onPacketAckOrLoss(nullptr, &loss);
  ASSERT_EQ(cc.getCongestionWindow(), 4 * kPacketSize);

  // A packet sent after the collapse is acknowledged.
  const auto sentAfterLoss =
      makeTestingWritePacket(1, 1000, 2000, kStart + 1s, 0, 1000);
  conn.lossState.inflightBytes = 1000;
  cc.onPacketSent(sentAfterLoss);
  conn.lossState.inflightBytes = 0;
  conn.lossState.totalBytesAcked = 1000;
  auto ack = AckEvent::Builder()
                 .setAckTime(kStart + 1100ms)
                 .setAdjustedAckTime(kStart + 1100ms)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  ack.largestNewlyAckedPacket = 1;
  ack.largestNewlyAckedPacketSentTime = kStart + 1s;
  ack.ackedBytes = 1000;
  ack.totalBytesAcked = 1000;
  cc.onPacketAckOrLoss(&ack, nullptr);

  EXPECT_FALSE(Peer::inRecovery(cc));
  EXPECT_GE(cc.getCongestionWindow(), cwnd);
}

TEST(Bbr3Test, IgnoresTheSrttOfAnEarlierPath) {
  // The transport built the controller for this 40ms path before it reset the
  // SRTT of the previous 1ms path.
  PathSimulator sim(Link{}, CongestionControlConfig{}, 1ms);

  ASSERT_TRUE(
      sim.runUntil([&] { return Peer::minRtt(sim.cc()).has_value(); }, 1s));

  EXPECT_GE(*Peer::minRtt(sim.cc()), kLinkRtt);
  // Startup paces from this path's RTT, so it stays within its gain of the
  // link rate.
  EXPECT_LE(toBytesPerSecond(Peer::pacingRate(sim.cc())), 2.77 * kLinkRate);
}

TEST(Bbr3Test, KeepsRecoveryForPacketsSentBeforeItWasBuilt) {
  // A CC knob builds the controller after the transport sent at kStart + 1s.
  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.lossState.maybeLastPacketSentTime = kStart + 1s;
  Bbr3CongestionController cc(conn, [] { return uint32_t{0}; });
  auto lostPacket =
      makeTestingWritePacket(0, 1000, 1000, kStart + 500ms, 0, 1000);
  lostPacket.declaredLost = true;
  conn.outstandings.packets.push_back(std::move(lostPacket));
  conn.outstandings.declaredLostCount = 1;
  LossEvent loss(kStart + 1100ms);
  loss.addLostPacket(conn.outstandings.packets.back());
  cc.onPacketAckOrLoss(nullptr, &loss);
  ASSERT_TRUE(Peer::inRecovery(cc));

  // The next ACK is for another packet sent before the controller existed.
  conn.lossState.totalBytesAcked = 1000;
  auto ack = AckEvent::Builder()
                 .setAckTime(kStart + 1200ms)
                 .setAdjustedAckTime(kStart + 1200ms)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  ack.largestNewlyAckedPacket = 1;
  ack.largestNewlyAckedPacketSentTime = kStart + 900ms;
  ack.ackedBytes = 1000;
  ack.totalBytesAcked = 1000;
  cc.onPacketAckOrLoss(&ack, nullptr);

  EXPECT_TRUE(Peer::inRecovery(cc));
}

TEST(Bbr3Test, EndsRecoveryOnceAPacketSentAfterTheLossIsAcked) {
  PathSimulator sim(Link{});
  // The ACK time is 5ms before the transport processes the ACK, while the
  // sender keeps sending.
  sim.setAckProcessingDelay(5ms);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  const auto dropped = sim.nextPacketNum();
  sim.setDropPacket([&](PacketNum packetNum) { return packetNum == dropped; });
  Optional<TimePoint> lossProcessed;
  Optional<TimePoint> recoveryEndingPacketSent;
  sim.setOnAck([&](const AckEvent& ack, const LossEvent* loss) {
    if (loss && !lossProcessed) {
      lossProcessed = sim.now();
    } else if (
        lossProcessed && !recoveryEndingPacketSent &&
        !Peer::inRecovery(sim.cc())) {
      recoveryEndingPacketSent = ack.largestNewlyAckedPacketSentTime;
    }
  });

  ASSERT_TRUE(
      sim.runUntil([&] { return recoveryEndingPacketSent.has_value(); }, 1s));

  EXPECT_GE(*recoveryEndingPacketSent, *lossProcessed);
}

TEST(Bbr3Test, PacesTheTokenlessPacerAtThePacingRate) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.transportSettings.ccaConfig.paceInitCwnd = true;
  auto pacer = std::make_unique<TokenlessPacer>(conn, kMinCwndInMssForBbr);
  auto& tokenlessPacer = *pacer;
  conn.pacer = std::move(pacer);
  Bbr3CongestionController cc(conn, [] { return uint32_t{0}; });
  // A min_rtt below the pacer's tick still gets paced.
  Peer::setMinRtt(cc, 200us);

  // From a BDP below one packet at 64 kbit/s to 1 Gbit/s.
  for (const uint64_t bytesPerSecond :
       {8'000UL, 1'250'000UL, 12'500'000UL, 125'000'000UL}) {
    Peer::setPacingRate(cc, Bandwidth(bytesPerSecond, 1s));
    tokenlessPacer.reset();
    tokenlessPacer.updateAndGetWriteBatchSize(kStart);
    const auto interval = tokenlessPacer.getTimeUntilNextWrite(kStart);

    ASSERT_GT(interval, 0us);
    const auto pacedBytesPerSecond =
        static_cast<double>(
            tokenlessPacer.getCachedWriteBatchSize() * kPacketSize) *
        1e6 / static_cast<double>(interval.count());
    EXPECT_NEAR(pacedBytesPerSecond, bytesPerSecond, 0.02 * bytesPerSecond);
  }
}

TEST(Bbr3Test, RestartsFromIdleWithoutAnAppLimitedMark) {
  PathSimulator sim(Link{});
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwCruise, 5s));
  sim.setMarkAppLimited(false);
  sim.pauseApp(true);
  sim.runFor(11s);
  ASSERT_EQ(sim.conn().lossState.inflightBytes, 0);
  ASSERT_FALSE(sim.cc().isAppLimited());

  sim.pauseApp(false);
  ASSERT_TRUE(sim.runUntil([&] { return Peer::idleRestart(sim.cc()); }, 1ms));
  sim.runFor(2s);

  EXPECT_FALSE(sawState(sim, State::ProbeRtt));
}

TEST(Bbr3Test, WaitsSeveralRoundsForRenoWhenTheBdpIsBelowOnePacket) {
  CongestionControlConfig config;
  config.enableRenoCoexistence = true;
  // 1 Mbit/s with a 5ms path delay gives a BDP of 625 bytes.
  PathSimulator sim(Link{.rate = 125'000, .rtt = 5ms}, config);
  ASSERT_TRUE(sim.runUntilState(State::ProbeBwDown, 10s));
  const auto downStart = sim.now();
  const auto downRound = Peer::roundCount(sim.cc());

  ASSERT_TRUE(sim.runUntilState(State::ProbeBwRefill, 5s));

  // Reno coexistence, not the probe wait, starts the probe, and only after
  // the few rounds that the quantization budget's packets need.
  EXPECT_LT(sim.now() - downStart, 1s);
  EXPECT_GE(Peer::roundCount(sim.cc()) - downRound, 4);
}

} // namespace
} // namespace test
} // namespace quic
