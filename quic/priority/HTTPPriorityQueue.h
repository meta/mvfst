/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/mvfst-config.h>

#include <folly/CppAttributes.h>
#include <quic/priority/PriorityQueue.h>
#include <quic/priority/RoundRobin.h>

#include <utility>

namespace quic {

class HTTPPriorityQueue : public quic::PriorityQueue {
  // Element in the IndexMap.  If incremental is true, index applies to
  // roundRobins_, otherwise it applies to heap_.
  struct IndexMapElem {
    bool incremental : 1;
    uint64_t index : 63;
  };

  using IndexMap = ValueMap<Identifier, IndexMapElem, Identifier::hash>;

 public:
  class Priority : public quic::PriorityQueue::Priority {
   public:
    using OrderId = uint32_t;

    struct HTTPPriority {
      uint8_t urgency : 3;
      bool paused : 1;
      bool incremental : 1;
      OrderId order : 32;
      bool uninitialized : 1;
    };

    // TODO: change default priority to (3, false, false, 0) to match spec
#if __cplusplus >= 202002L
    static constexpr HTTPPriority kDefaultPriority{
        .urgency = 3,
        .paused = false,
        .incremental = true,
        .order = 0,
        .uninitialized = false};
#else
    static constexpr HTTPPriority kDefaultPriority = {3, false, true, 0, false};
#endif
    /*implicit*/ Priority(const PriorityQueue::Priority& basePriority);

    Priority(uint8_t u, bool i, OrderId o = 0);
    Priority& operator=(const PriorityQueue::Priority& basePriority);

    enum Paused { PAUSED };

    /* implicit */ Priority(Paused) : Priority(7, true) {
      auto& fields = getFields();
      fields.paused = true;
    }

    Priority(const Priority&) = default;
    Priority& operator=(const Priority&) = default;
    Priority(Priority&&) = default;
    Priority& operator=(Priority&&) = default;
    ~Priority() = default;

    const HTTPPriority* operator->() const {
      return &getFields();
    }

    bool operator==(const Priority& other) const {
      return toUint64() == other.toUint64();
    }

    bool operator<(const Priority& other) const {
      return toUint64() < other.toUint64();
    }

    [[nodiscard]] uint64_t toUint64() const {
      const static uint64_t kDefaultUint64 = toUint64Static(kDefaultPriority);
      const auto& fields = getFields();
      return fields.uninitialized ? kDefaultUint64 : toUint64Static(fields);
    }

    [[nodiscard]] const HTTPPriority& getFields() const {
      return getPriority<HTTPPriority>();
    }

   private:
    [[nodiscard]] bool isInitializedFast() const {
      return !getFields().uninitialized;
    }

    static uint64_t toUint64Static(const HTTPPriority& fields) {
      return (
          (uint64_t(fields.urgency) << 61) | (uint64_t(fields.paused) << 60) |
          (uint64_t(fields.incremental) << 59) |
          (uint64_t(fields.order) << 27));
    }

    HTTPPriority& getFields() {
      return getPriority<HTTPPriority>();
    }
  };

  [[nodiscard]] bool empty() const noexcept override {
    return heap_.empty() && roundRobinElements_ == 0;
  }

  [[nodiscard]] uint32_t getRoundRobinElements() const {
    return roundRobinElements_;
  }

  [[nodiscard]] bool equalPriority(
      const PriorityQueue::Priority& p1,
      const PriorityQueue::Priority& p2) const override {
    return static_cast<const HTTPPriorityQueue::Priority&>(p1) ==
        static_cast<const HTTPPriorityQueue::Priority&>(p2);
  }

  [[nodiscard]] PriorityLogFields toLogFields(
      const PriorityQueue::Priority& pri) const override;

  void setDisablePausedPriority(bool disable) {
    disablePausedPriority_ = disable;
  }

  [[nodiscard]] bool contains(Identifier id) const noexcept override {
    return find(id) != std::nullopt;
  }

  void insertOrUpdate(Identifier id, PriorityQueue::Priority priority) override;

  void updateIfExist(Identifier id, PriorityQueue::Priority priority) override;

  void erase(Identifier id) override;

  void clear() override;

  Identifier getNextScheduledID(
      quic::Optional<uint64_t> previousConsumed) override;

  [[nodiscard]] Identifier peekNextScheduledID() const override;

  void consume(quic::Optional<uint64_t> consumed) override;

  // Note: transactions only reinsert erased transactions at previous priority
  // they don't undo inserts, updates, or consume.
  Transaction beginTransaction() override {
    if (hasOpenTransaction_) {
      rollbackTransaction(makeTransaction());
    }
    hasOpenTransaction_ = true;
    return makeTransaction();
  }

  void commitTransaction(Transaction&&) override {
    if (hasOpenTransaction_) {
      hasOpenTransaction_ = false;
      erased_.clear();
    }
  }

  void rollbackTransaction(Transaction&&) override {
    if (hasOpenTransaction_) {
      for (auto& e : erased_) {
        if (!contains(e.identifier)) {
          insert(e.identifier, e.priority);
        }
      }
      erased_.clear();
      hasOpenTransaction_ = false;
    }
  }

  [[nodiscard]] quic::PriorityQueue::Priority headPriority() const override;

  [[nodiscard]] Priority headHTTPPriority() const {
    return static_cast<const HTTPPriorityQueue::Priority&>(headPriority());
  }

 private:
  // Heap Element.  If priority.incremental is true, then Identifier is
  // uninitialized - the element is a placeholder for the RoundRobin at
  // roundRobins_[priority.urgency].
  //
  // In the current design, there are no elements with Incremental priority in
  // the heap.
  struct Element {
    Element(Priority p, Identifier i) : priority(std::move(p)), identifier(i) {}

    Priority priority;
    Identifier identifier;

    bool operator<(const Element& other) const {
      if (priority < other.priority) {
        return true;
      }
      if (other.priority < priority || other.priority->incremental) {
        return false;
      }
      // sequential priorities are equal
      return identifier.asUint64() < other.identifier.asUint64();
    }

    bool operator<=(const Element& other) const {
      return !(other < *this);
    }
  };

  struct FindResult {
    IndexMapElem elem;
    IndexMap::const_iterator indexIt;
  };

  [[nodiscard]] quic::Optional<FindResult> find(Identifier id) const;
  void addIndex(Identifier id, IndexMapElem indexElem);
  void removeIndex(IndexMap::const_iterator it);
  void buildSequentialIndex();
  void destroySequentialIndex();

  void heapifyUp(size_t index);
  void heapifyDown(size_t index);
  void assignIndex(Element& element, size_t index);
  void insert(Identifier id, const Priority& priority);
  void forgetErased(Identifier id);
  bool updateInSequential(IndexMapElem indexElem, Priority priority);
  void eraseImpl(Identifier id, IndexMapElem indexElem);

  [[nodiscard]] const Element* FOLLY_NULLABLE top() const;

  // Holds sequential elements
  std::vector<Element> heap_;
  // Map from id -> RoundRobin or Heap Index
  IndexMap indexMap_;
  // Holds incremental elements
  std::array<RoundRobin, 8> roundRobins_;
  // Holds erased elements from the current transaction
  std::vector<Element> erased_;
  // Count of Round Robin elements in the Queue
  uint32_t roundRobinElements_{0};
  // The index of the first non-empty RoundRobin, or roundRobins_.size()
  uint8_t lowestRoundRobin_{uint8_t(roundRobins_.size())};
  bool hasOpenTransaction_{false};
  bool useIndexMapForSequential_{false};
  bool disablePausedPriority_{false};
};

} // namespace quic
