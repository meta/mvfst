/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/observer/SocketObserverInterface.h>

#include <algorithm>
#include <utility>

namespace quic {

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setWriteCount(
    const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setLastPacketSentTime(
    const TimePoint& lastPacketSentTimeIn) {
  maybeLastPacketSentTime = lastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setLastPacketSentTime(
    const Optional<TimePoint>& maybeLastPacketSentTimeIn) {
  maybeLastPacketSentTime = maybeLastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setCwndInBytes(
    const Optional<uint64_t>& maybeCwndInBytesIn) {
  maybeCwndInBytes = maybeCwndInBytesIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent::Builder&&
SocketObserverInterface::WriteEvent::Builder::setWritableBytes(
    const Optional<uint64_t>& maybeWritableBytesIn) {
  maybeWritableBytes = maybeWritableBytesIn;
  return std::move(*this);
}

SocketObserverInterface::WriteEvent
SocketObserverInterface::WriteEvent::Builder::build() && {
  return WriteEvent(*this);
}

SocketObserverInterface::WriteEvent::WriteEvent(
    const WriteEvent::BuilderFields& builderFields)
    : outstandingPackets([&]() {
        MVCHECK(builderFields.maybeOutstandingPacketsRef.has_value());
        return builderFields.maybeOutstandingPacketsRef.value();
      }()),
      writeCount([&]() {
        MVCHECK(builderFields.maybeWriteCount.has_value());
        return builderFields.maybeWriteCount.value();
      }()),
      maybeLastPacketSentTime(builderFields.maybeLastPacketSentTime),
      maybeCwndInBytes(builderFields.maybeCwndInBytes),
      maybeWritableBytes(builderFields.maybeWritableBytes) {}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setWriteCount(
    const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setLastPacketSentTime(
    const TimePoint& lastPacketSentTimeIn) {
  maybeLastPacketSentTime = lastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setLastPacketSentTime(
    const Optional<TimePoint>& maybeLastPacketSentTimeIn) {
  maybeLastPacketSentTime = maybeLastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setCwndInBytes(
    const Optional<uint64_t>& maybeCwndInBytesIn) {
  maybeCwndInBytes = maybeCwndInBytesIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent::Builder&&
SocketObserverInterface::AppLimitedEvent::Builder::setWritableBytes(
    const Optional<uint64_t>& maybeWritableBytesIn) {
  maybeWritableBytes = maybeWritableBytesIn;
  return std::move(*this);
}

SocketObserverInterface::AppLimitedEvent
SocketObserverInterface::AppLimitedEvent::Builder::build() && {
  return AppLimitedEvent(std::move(*this));
}

SocketObserverInterface::AppLimitedEvent::AppLimitedEvent(
    SocketObserverInterface::AppLimitedEvent::BuilderFields&& builderFields)
    : WriteEvent(builderFields) {}

void SocketObserverInterface::PacketsWrittenEvent::
    invokeForEachNewOutstandingPacketOrdered(
        FunctionRef<void(const OutstandingPacketWrapper&)> fn) const {
  DCHECK_GE(outstandingPackets.size(), numAckElicitingPacketsWritten);
  if (numAckElicitingPacketsWritten == 0) {
    return; // nothing to do
  }

  // The packets in the OutstandingPackets deque are sorted by their sequence
  // number in their packet number space. As a result, the N packets at the end
  // of the deque may not be the N most recently sent OutstandingPacketss.
  // Furthermore, adjacent OutstandingPackets may have the same sequence
  // number because they belong to different packet number spaces. Because
  // packets in the deque are sorted only by sequence number, the ith packet
  // in the deque may have actually been sent after the i+1th packet.
  //
  // However, the deque will typically only contain AppData packets, and thus
  // we can expect that the last N elements in the deque will typically be the
  // N most recently sent OutstandingPackets. We use this to avoid needing to
  // scan the queue when the following is true:
  //
  //    (1) If the writeCount of the OutstandingPacketWrapper N packets from the
  //    end of
  //        the deque has a writeCount equal to that reported by this event, and
  //    (2) If when scanning from the OutstandingPacketWrapper N packets from
  //    the end
  //        of the deque to the end of the deque, the numAckElicitingPacketsSent
  //        recorded for each OutstandingPacketWrapper is one larger than that
  //        of the previous OutstandingPacketWrapper, and writeCount recorded is
  //        equal to the writeCount reported by this event.
  //
  // If the above is true, then the N OutstandingPackets from the end of the
  // deque were all sent during this write operation, and they are already
  // ordered such that packet i was sent before packet i+1.
  {
    const auto startIt = outstandingPackets.end() -
        static_cast<int64_t>(numAckElicitingPacketsWritten);
    bool needFullWalk = false;
    Optional<uint64_t> maybePrevNumAckElicitingPacketsSent;

    for (auto it = startIt; it != outstandingPackets.end(); it++) {
      if (writeCount != it->metadata.writeCount) {
        needFullWalk = true;
        break;
      }

      if (!maybePrevNumAckElicitingPacketsSent) {
        maybePrevNumAckElicitingPacketsSent =
            it->metadata.totalAckElicitingPacketsSent;
        continue;
      }

      MVCHECK_NE(
          maybePrevNumAckElicitingPacketsSent.value(),
          it->metadata.totalAckElicitingPacketsSent);
      if (maybePrevNumAckElicitingPacketsSent.value() >
          it->metadata.totalAckElicitingPacketsSent) {
        needFullWalk = true;
        break;
      }
    }

    if (!needFullWalk) {
      for (auto it = startIt; it != outstandingPackets.end(); it++) {
        fn(*it);
      }
      return; // we're done here
    }
  }

  // It looks like a full walk is needed.
  //
  // From the front of the deque, find OutstandingPackets with the writeCount
  // reported by this event and insert references to them into a vector.
  std::vector<std::reference_wrapper<const OutstandingPacketWrapper>>
      newOutstandingPackets;
  newOutstandingPackets.reserve(numAckElicitingPacketsWritten);
  for (const auto& packet : outstandingPackets) {
    if (packet.metadata.writeCount == writeCount) {
      newOutstandingPackets.emplace_back(packet);
    }
  }
  DCHECK_EQ(numAckElicitingPacketsWritten, newOutstandingPackets.size());

  // Now sort that vector by totalAckElicitingPacketsSent.
  std::ranges::sort(
      newOutstandingPackets, [](const auto& pkt1, const auto& pkt2) {
        const auto& pkt1TotalAckElicitingPacketsSent =
            pkt1.get().metadata.totalAckElicitingPacketsSent;
        const auto& pkt2TotalAckElicitingPacketsSent =
            pkt2.get().metadata.totalAckElicitingPacketsSent;
        return pkt1TotalAckElicitingPacketsSent <
            pkt2TotalAckElicitingPacketsSent;
      });
  DCHECK_EQ(numAckElicitingPacketsWritten, newOutstandingPackets.size());

  // Play the sorted list
  for (const auto& packet : newOutstandingPackets) {
    fn(packet);
  }
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacketWrapper>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setWriteCount(
    const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setLastPacketSentTime(
    const TimePoint& lastPacketSentTimeIn) {
  maybeLastPacketSentTime = lastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setLastPacketSentTime(
    const Optional<TimePoint>& maybeLastPacketSentTimeIn) {
  maybeLastPacketSentTime = maybeLastPacketSentTimeIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setCwndInBytes(
    const Optional<uint64_t>& maybeCwndInBytesIn) {
  maybeCwndInBytes = maybeCwndInBytesIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setWritableBytes(
    const Optional<uint64_t>& maybeWritableBytesIn) {
  maybeWritableBytes = maybeWritableBytesIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setNumPacketsWritten(
    const uint64_t numPacketsWrittenIn) {
  maybeNumPacketsWritten = numPacketsWrittenIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::
    setNumAckElicitingPacketsWritten(
        const uint64_t numAckElicitingPacketsWrittenIn) {
  maybeNumAckElicitingPacketsWritten = numAckElicitingPacketsWrittenIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent::Builder&&
SocketObserverInterface::PacketsWrittenEvent::Builder::setNumBytesWritten(
    const uint64_t numBytesWrittenIn) {
  maybeNumBytesWritten = numBytesWrittenIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsWrittenEvent
SocketObserverInterface::PacketsWrittenEvent::Builder::build() && {
  return PacketsWrittenEvent(std::move(*this));
}

SocketObserverInterface::PacketsWrittenEvent::PacketsWrittenEvent(
    SocketObserverInterface::PacketsWrittenEvent::BuilderFields&& builderFields)
    : WriteEvent(builderFields),
      numPacketsWritten([&]() {
        MVCHECK(builderFields.maybeNumPacketsWritten.has_value());
        return builderFields.maybeNumPacketsWritten.value();
      }()),
      numAckElicitingPacketsWritten([&]() {
        MVCHECK(builderFields.maybeNumAckElicitingPacketsWritten.has_value());
        return builderFields.maybeNumAckElicitingPacketsWritten.value();
      }()),
      numBytesWritten([&]() {
        MVCHECK(builderFields.maybeNumBytesWritten.has_value());
        return builderFields.maybeNumBytesWritten.value();
      }()) {}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder&&
SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder::
    setPacketReceiveTime(const TimePoint packetReceiveTimeIn) {
  maybePacketReceiveTime = packetReceiveTimeIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder&&
SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder::
    setPacketSoftwareRxTimestamp(
        const std::chrono::system_clock::time_point
            packetSoftwareRxTimestampIn) {
  maybePacketSoftwareRxTimestamp = packetSoftwareRxTimestampIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder&&
SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder::
    setPacketNumBytes(const uint64_t packetNumBytesIn) {
  maybePacketNumBytes = packetNumBytesIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder&&
SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder::
    setPacketTos(const uint8_t tosIn) {
  maybePacketTos = tosIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket
SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::Builder::
    build() && {
  return ReceivedUdpPacket(std::move(*this));
}

SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::
    ReceivedUdpPacket(
        SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::
            BuilderFields&& builderFields)
    : packetReceiveTime([&]() {
        MVCHECK(builderFields.maybePacketReceiveTime.has_value());
        return builderFields.maybePacketReceiveTime.value();
      }()),
      packetNumBytes([&]() {
        MVCHECK(builderFields.maybePacketNumBytes.has_value());
        return builderFields.maybePacketNumBytes.value();
      }()),
      packetTos([&]() {
        MVCHECK(builderFields.maybePacketTos.has_value());
        return builderFields.maybePacketTos.value();
      }()),
      maybePacketSoftwareRxTimestamp(
          builderFields.maybePacketSoftwareRxTimestamp) {}

SocketObserverInterface::PacketsReceivedEvent::Builder&&
SocketObserverInterface::PacketsReceivedEvent::Builder::setReceiveLoopTime(
    const TimePoint receiveLoopTimeIn) {
  maybeReceiveLoopTime = receiveLoopTimeIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::Builder&&
SocketObserverInterface::PacketsReceivedEvent::Builder::setNumPacketsReceived(
    const uint64_t numPacketsReceivedIn) {
  maybeNumPacketsReceived = numPacketsReceivedIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::Builder&&
SocketObserverInterface::PacketsReceivedEvent::Builder::setNumBytesReceived(
    const uint64_t numBytesReceivedIn) {
  maybeNumBytesReceived = numBytesReceivedIn;
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent::Builder&&
SocketObserverInterface::PacketsReceivedEvent::Builder::addReceivedUdpPacket(
    ReceivedUdpPacket&& packetIn) {
  receivedPackets.emplace_back(packetIn);
  return std::move(*this);
}

SocketObserverInterface::PacketsReceivedEvent
SocketObserverInterface::PacketsReceivedEvent::Builder::build() && {
  return PacketsReceivedEvent(std::move(*this));
}

SocketObserverInterface::PacketsReceivedEvent::PacketsReceivedEvent(
    SocketObserverInterface::PacketsReceivedEvent::BuilderFields&&
        builderFields)
    : receiveLoopTime([&]() {
        MVCHECK(builderFields.maybeReceiveLoopTime.has_value());
        return builderFields.maybeReceiveLoopTime.value();
      }()),
      numPacketsReceived([&]() {
        MVCHECK(builderFields.maybeNumPacketsReceived.has_value());
        return builderFields.maybeNumPacketsReceived.value();
      }()),
      numBytesReceived([&]() {
        MVCHECK(builderFields.maybeNumBytesReceived.has_value());
        return builderFields.maybeNumBytesReceived.value();
      }()),
      receivedPackets(std::move(builderFields.receivedPackets)) {
  MVCHECK_EQ(numPacketsReceived, receivedPackets.size());
}

SocketObserverInterface::AcksProcessedEvent::Builder&&
SocketObserverInterface::AcksProcessedEvent::Builder::setAckEvents(
    const std::vector<AckEvent>& ackEventsIn) {
  maybeAckEventsRef = ackEventsIn;
  return std::move(*this);
}

SocketObserverInterface::AcksProcessedEvent
SocketObserverInterface::AcksProcessedEvent::Builder::build() && {
  return AcksProcessedEvent(*this);
}

SocketObserverInterface::AcksProcessedEvent::AcksProcessedEvent(
    SocketObserverInterface::AcksProcessedEvent::BuilderFields builderFields)
    : ackEvents([&]() {
        MVCHECK(builderFields.maybeAckEventsRef.has_value());
        return builderFields.maybeAckEventsRef.value();
      }()) {}

} // namespace quic
