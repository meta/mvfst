/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <list>

namespace {

using namespace quic;
using Identifier = quic::PriorityQueue::Identifier;

class HTTPPriorityQueueTest : public testing::Test {
 protected:
  HTTPPriorityQueue queue_;
};

TEST_F(HTTPPriorityQueueTest, EmptyQueue) {
  queue_.clear();
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, IncrementalEmptyQueue) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, true);
  queue_.insertOrUpdate(id, priority);
  EXPECT_FALSE(queue_.empty());
  queue_.clear();
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, Compare) {
  std::vector<HTTPPriorityQueue::Priority> pris = {
      {0, false},
      {0, false, 1},
      {0, true},
      PriorityQueue::Priority(),
      {7, false},
      {7, false, std::numeric_limits<uint32_t>::max()},
      {7, true},
      {HTTPPriorityQueue::Priority::PAUSED}};
  for (size_t i = 0; i < pris.size(); ++i) {
    for (size_t j = 0; j < pris.size(); ++j) {
      EXPECT_TRUE(
          (i == j && pris[i] == pris[j]) || (i != j && !(pris[i] == pris[j])));
      EXPECT_TRUE(
          (i == j && queue_.equalPriority(pris[i], pris[j])) ||
          (i != j && !queue_.equalPriority(pris[i], pris[j])));
      EXPECT_TRUE(i >= j || (i < j && pris[i] < pris[j])) << i << " " << j;
    }
  }
  // TODO: will change when default changes
  EXPECT_EQ(pris[3], HTTPPriorityQueue::Priority(3, true));
  PriorityQueue::Priority baseDefaultPri;
  auto* defaultPri = static_cast<HTTPPriorityQueue::Priority*>(&baseDefaultPri);
  EXPECT_TRUE(
      HTTPPriorityQueue::Priority(
          3, false, std::numeric_limits<uint32_t>::max()) < *defaultPri);
  EXPECT_TRUE(
      *defaultPri < HTTPPriorityQueue::Priority(
                        4, false, std::numeric_limits<uint32_t>::max()));
}

TEST_F(HTTPPriorityQueueTest, InsertSingleElement) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, false);
  queue_.insertOrUpdate(id, priority);
  EXPECT_FALSE(queue_.empty());
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id);
}

TEST_F(HTTPPriorityQueueTest, InsertMultipleElements) {
  auto id1 = Identifier::fromStreamID(1);
  auto id2 = Identifier::fromStreamID(2);
  auto priority1 = HTTPPriorityQueue::Priority(0, false);
  auto priority2 = HTTPPriorityQueue::Priority(1, false);
  queue_.insertOrUpdate(id1, priority1);
  queue_.insertOrUpdate(id2, priority2);
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id1);
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id1);
  queue_.erase(id1);
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id2);
}

TEST_F(HTTPPriorityQueueTest, UpdatePriority) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, false);
  queue_.insertOrUpdate(id, priority);
  auto newPriority = HTTPPriorityQueue::Priority(1, false);
  queue_.updateIfExist(id, newPriority);
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id);
  queue_.updateIfExist(id, newPriority);
  EXPECT_EQ(queue_.getNextScheduledID(std::nullopt), id);
}

TEST_F(HTTPPriorityQueueTest, EraseElement) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, false);
  queue_.insertOrUpdate(id, priority);
  queue_.erase(id);
  EXPECT_TRUE(queue_.empty());
  queue_.updateIfExist(id, HTTPPriorityQueue::Priority(0, false));
}

TEST_F(HTTPPriorityQueueTest, HeapUpOnErase) {
  std::vector<size_t> items{1, 4, 2, 5, 6, 3};
  for (auto i : items) {
    // identical priority and order, sort by stream ID
    queue_.insertOrUpdate(
        Identifier::fromStreamID(i), HTTPPriorityQueue::Priority(0, false, 0));
  }
  queue_.erase(Identifier::fromStreamID(5)); // swaps with 3 which moves up
  for (auto i = 1; i < 7; i++) {
    if (i == 5) {
      continue;
    }
    EXPECT_EQ(queue_.getNextScheduledID(std::nullopt).asUint64(), i);
    queue_.erase(Identifier::fromStreamID(i));
  }
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, UpdateIncrementalToNonIncremental) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(7, true);
  queue_.insertOrUpdate(id, priority);
  auto id2 = Identifier::fromStreamID(2);
  queue_.insertOrUpdate(id2, HTTPPriorityQueue::Priority(0, true));

  // Update from incremental to non-incremental (updateIfExist)
  queue_.updateIfExist(id, HTTPPriorityQueue::Priority(0, false));
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id);
  queue_.erase(id);
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id2);
  // Update from incremental to non-incremental (insertOrUpdate)
  queue_.insertOrUpdate(id2, HTTPPriorityQueue::Priority(0, false));
  EXPECT_TRUE(
      queue_.headHTTPPriority() == HTTPPriorityQueue::Priority(0, false));
}

TEST_F(HTTPPriorityQueueTest, UpdateNonIncrementalToIncremental) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, false);
  queue_.insertOrUpdate(id, priority);
  auto id2 = Identifier::fromStreamID(2);
  queue_.insertOrUpdate(id2, HTTPPriorityQueue::Priority(0, true));

  // Update from non-incremental to incremental
  priority = HTTPPriorityQueue::Priority(0, true);
  queue_.updateIfExist(id, priority);
  EXPECT_TRUE(queue_.contains(id));
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id2);
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id);
}

TEST_F(HTTPPriorityQueueTest, UpdateIncrementalUrgency) {
  auto id = Identifier::fromStreamID(1);
  auto priority = HTTPPriorityQueue::Priority(0, true);
  queue_.insertOrUpdate(id, priority);

  // Update urgency of incremental priority from 0 -> 1
  priority = HTTPPriorityQueue::Priority(1, true);
  queue_.updateIfExist(id, priority);
  EXPECT_TRUE(queue_.contains(id));
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id);
  EXPECT_TRUE(
      queue_.headHTTPPriority() == HTTPPriorityQueue::Priority(1, true));
}

TEST_F(HTTPPriorityQueueTest, InsertOrUpdateNoOp) {
  auto id = Identifier::fromStreamID(1);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, true));
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, true));

  // Update urgency of incremental priority from 0 -> 1
  queue_.updateIfExist(id, HTTPPriorityQueue::Priority(1, true));
  EXPECT_TRUE(queue_.contains(id));
  EXPECT_TRUE(queue_.getNextScheduledID(std::nullopt) == id);
  EXPECT_TRUE(
      queue_.headHTTPPriority() == HTTPPriorityQueue::Priority(1, true));
}

TEST_F(HTTPPriorityQueueTest, PeekAndClear) {
  for (size_t i = 0; i < 16; i++) {
    queue_.insertOrUpdate(
        Identifier::fromStreamID(i), HTTPPriorityQueue::Priority(i / 2, i % 2));
  }
  EXPECT_EQ(queue_.peekNextScheduledID(), Identifier::fromStreamID(0));
  EXPECT_EQ(queue_.peekNextScheduledID(), Identifier::fromStreamID(0));
  queue_.erase(Identifier::fromStreamID(0));
  EXPECT_EQ(queue_.peekNextScheduledID(), Identifier::fromStreamID(1));
  EXPECT_EQ(queue_.peekNextScheduledID(), Identifier::fromStreamID(1));
  queue_.clear();
}

TEST_F(HTTPPriorityQueueTest, DoubleBeginTransaction) {
  auto txn = queue_.beginTransaction();
  queue_.insertOrUpdate(
      Identifier::fromStreamID(0), HTTPPriorityQueue::Priority(7, false));
  // begin without commit/rollback => rollback
  txn = queue_.beginTransaction();
  queue_.insertOrUpdate(
      Identifier::fromStreamID(1), HTTPPriorityQueue::Priority(0, false));
  queue_.rollbackTransaction(std::move(txn));
  EXPECT_TRUE(queue_.contains(Identifier::fromStreamID(0)));
  EXPECT_TRUE(queue_.contains(Identifier::fromStreamID(1)));
}

TEST_F(HTTPPriorityQueueTest, InsertWithoutTransaction) {
  // no txn, erase not rollbackable.
  queue_.insertOrUpdate(
      Identifier::fromStreamID(0), HTTPPriorityQueue::Priority(7, false));
  queue_.erase(Identifier::fromStreamID(0));
  // beginTransaction here
  auto txn = queue_.beginTransaction();
  queue_.insertOrUpdate(
      Identifier::fromStreamID(1), HTTPPriorityQueue::Priority(0, false));
  queue_.rollbackTransaction(std::move(txn));
  EXPECT_FALSE(queue_.contains(Identifier::fromStreamID(0)));
  EXPECT_TRUE(queue_.contains(Identifier::fromStreamID(1)));
}

TEST_F(HTTPPriorityQueueTest, Paused) {
  auto id = Identifier::fromStreamID(0);
  // insert paused -> nope
  HTTPPriorityQueue::Priority paused(HTTPPriorityQueue::Priority::PAUSED);
  queue_.insertOrUpdate(id, paused);
  EXPECT_TRUE(queue_.empty());

  // update unpaused(seq) -> paused: deleted
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, false));
  EXPECT_EQ(queue_.peekNextScheduledID(), id);
  queue_.updateIfExist(id, paused);
  EXPECT_TRUE(queue_.empty());

  // update from paused to unpaused: no-op -- is this right?
  queue_.updateIfExist(id, HTTPPriorityQueue::Priority(0, true));
  EXPECT_TRUE(queue_.empty());

  // update unpaused(rr) -> paused: deleted
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, true));
  EXPECT_EQ(queue_.peekNextScheduledID(), id);
  queue_.updateIfExist(id, paused);
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, PausedWithDisablePausedPriority) {
  queue_.setDisablePausedPriority(true);
  auto id = Identifier::fromStreamID(0);
  HTTPPriorityQueue::Priority paused(HTTPPriorityQueue::Priority::PAUSED);
  const HTTPPriorityQueue::Priority lowest(7, true);

  // insert paused -> lowest urgency, incremental
  queue_.insertOrUpdate(id, paused);
  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.headHTTPPriority(), lowest);

  // update unpaused(seq) -> paused: same as insertOrUpdate
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, false));
  queue_.updateIfExist(id, paused);
  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.headHTTPPriority(), lowest);
  EXPECT_EQ(queue_.getRoundRobinElements(), 1);

  // update unpaused(rr) -> paused: same as insertOrUpdate
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(0, true));
  queue_.updateIfExist(id, paused);
  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.headHTTPPriority(), lowest);
  EXPECT_EQ(queue_.getRoundRobinElements(), 1);
  EXPECT_EQ(queue_.peekNextScheduledID(), id);
}

TEST_F(HTTPPriorityQueueTest, ComplexOperations) {
  std::vector<HTTPPriorityQueue::Priority> ids;
  auto txn = queue_.beginTransaction();
  // Insert elements with different priorities
  for (int i = 0; i < 20; ++i) {
    // every 4th stream has same pri, and those 5 streams are in reverse stream
    // ID order, 6 and 14 are RR.
    auto priority = HTTPPriorityQueue::Priority(i % 4, i % 8 == 6, 20 - i);
    ids.push_back(priority);
    queue_.insertOrUpdate(Identifier::fromStreamID(i), priority);
  }

  // Update some priorities to shuffle their position
  auto setPriority = [&](size_t index,
                         const HTTPPriorityQueue::Priority& pri) mutable {
    ids[index] = pri;
    queue_.updateIfExist(Identifier::fromStreamID(index), pri);
  };
  setPriority(5, HTTPPriorityQueue::Priority(0, false));
  setPriority(10, HTTPPriorityQueue::Priority(3, false));
  setPriority(15, HTTPPriorityQueue::Priority(1, false));

  // Erase some elements
  queue_.erase(Identifier::fromStreamID(5)); // highest pri
  queue_.erase(Identifier::fromStreamID(7)); // lowest pri
  queue_.erase(Identifier::fromStreamID(12));
  queue_.commitTransaction(std::move(txn));

  // Call getNextScheduledID + erase until the queue is empty
  HTTPPriorityQueue::Priority lastPriority = queue_.headHTTPPriority();
  // clang-format off
  std::list<size_t> expectedOrder{
    /*u=0*/   16,  8, 4,  0,
    /*u=1*/   15, 17, 13, 9, 1,
    /*u=2*/   18,  2,
    /*u=2,i*/  6, 14,
    /*u=3*/   10, 19, 11, 3
  };
  // clang-format on

  txn = queue_.beginTransaction();
  while (!queue_.empty()) {
    // priorities should not decrease
    auto headHTTPPriority = queue_.headHTTPPriority();
    CHECK(lastPriority == headHTTPPriority || lastPriority < headHTTPPriority);
    lastPriority = headHTTPPriority;
    auto nextId = queue_.peekNextScheduledID();
    queue_.consume(std::nullopt);
    CHECK_EQ(nextId.asUint64(), expectedOrder.front());
    expectedOrder.pop_front();
    auto expectedPri = ids[nextId.asUint64()];
    CHECK(expectedPri == headHTTPPriority);
    queue_.erase(nextId);
    CHECK(!queue_.contains(nextId));
  }
  queue_.rollbackTransaction(std::move(txn));
  EXPECT_FALSE(queue_.empty());
  EXPECT_TRUE(
      queue_.headHTTPPriority() == HTTPPriorityQueue::Priority(0, false, 4));
}

TEST_F(HTTPPriorityQueueTest, IndexEverything) {
  // Insert elements with different priorities
  for (int i = 1; i < 200; ++i) {
    auto priority = HTTPPriorityQueue::Priority(i % 8, i % 16 == 0, 200 - i);
    queue_.insertOrUpdate(Identifier::fromStreamID(i), priority);
  }
  // 3 is a generator for the prime set modulo 199
  size_t g = 3;
  size_t id = g;
  for (size_t x = 0; x < 199; x++) {
    queue_.erase(Identifier::fromStreamID(id));
    id = (id * g) % 199;
  }
  // The only number left is 199
  EXPECT_EQ(queue_.peekNextScheduledID().asUint64(), 199);
  queue_.erase(Identifier::fromStreamID(199));
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, ToLogFields) {
  // Test for PAUSED priority
  HTTPPriorityQueue::Priority pausedPriority(
      HTTPPriorityQueue::Priority::PAUSED);
  auto lookup =
      [](const std::vector<std::pair<std::string, std::string>>& fields,
         const std::string& key) {
        auto it = std::find_if(
            fields.begin(),
            fields.end(),
            [&key](const std::pair<std::string, std::string>& field) {
              return field.first == key;
            });
        if (it != fields.end()) {
          return it->second;
        }
        return std::string{};
      };

  auto fieldsPaused = queue_.toLogFields(pausedPriority);
  EXPECT_EQ(lookup(fieldsPaused, "paused"), "true");

  // Test for regular priority
  HTTPPriorityQueue::Priority regularPriority1(3, true, 0);
  auto fieldsRegular1 = queue_.toLogFields(regularPriority1);
  EXPECT_EQ(lookup(fieldsRegular1, "urgency"), "3");
  EXPECT_EQ(lookup(fieldsRegular1, "incremental"), "true");
  EXPECT_EQ(lookup(fieldsRegular1, "order"), "0");

  HTTPPriorityQueue::Priority regularPriority2(4, false, 5);
  auto fieldsRegular2 = queue_.toLogFields(regularPriority2);
  EXPECT_EQ(lookup(fieldsRegular2, "urgency"), "4");
  EXPECT_EQ(lookup(fieldsRegular2, "incremental"), "false");
  EXPECT_EQ(lookup(fieldsRegular2, "order"), "5");
}

TEST_F(HTTPPriorityQueueTest, ImplicitPriorityConstructor) {
  // Test with uninitialized basePriority
  PriorityQueue::Priority uninitializedPriority;
  HTTPPriorityQueue::Priority priorityWithDefault(uninitializedPriority);

  EXPECT_EQ(
      priorityWithDefault->urgency,
      HTTPPriorityQueue::Priority::kDefaultPriority.urgency);
  EXPECT_EQ(
      priorityWithDefault->incremental,
      HTTPPriorityQueue::Priority::kDefaultPriority.incremental);
  EXPECT_EQ(
      priorityWithDefault->order,
      HTTPPriorityQueue::Priority::kDefaultPriority.order);
}

TEST_F(HTTPPriorityQueueTest, PriorityAssignmentOperator) {
  PriorityQueue::Priority uninitializedPriority;
  HTTPPriorityQueue::Priority priority(0, false);
  priority = uninitializedPriority;

  EXPECT_EQ(
      priority->urgency, HTTPPriorityQueue::Priority::kDefaultPriority.urgency);
  EXPECT_EQ(
      priority->incremental,
      HTTPPriorityQueue::Priority::kDefaultPriority.incremental);
  EXPECT_EQ(
      priority->order, HTTPPriorityQueue::Priority::kDefaultPriority.order);
}

TEST_F(HTTPPriorityQueueTest, RollbackPreservesReinsertedMembership) {
  const auto id = Identifier::fromStreamID(1);
  const auto priority = HTTPPriorityQueue::Priority(3, true);
  queue_.insertOrUpdate(id, priority);
  auto transaction = queue_.beginTransaction();
  queue_.erase(id);
  ASSERT_FALSE(queue_.contains(id));
  queue_.insertOrUpdate(id, priority);
  ASSERT_EQ(queue_.getRoundRobinElements(), 1);
  queue_.rollbackTransaction(std::move(transaction));

  const bool containsAfterRollback = queue_.contains(id);
  const auto countAfterRollback = queue_.getRoundRobinElements();
  queue_.erase(id);
  const bool containsAfterErase = queue_.contains(id);
  const bool emptyAfterErase = queue_.empty();
  const auto countAfterErase = queue_.getRoundRobinElements();
  queue_.clear();

  EXPECT_TRUE(containsAfterRollback);
  EXPECT_FALSE(containsAfterErase);
  EXPECT_EQ(countAfterRollback, 1);
  EXPECT_EQ(countAfterErase, 0);
  EXPECT_TRUE(emptyAfterErase);
}

TEST_F(HTTPPriorityQueueTest, RollbackPreservesReinsertedUrgency) {
  const auto id = Identifier::fromStreamID(1);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(3, true));
  auto transaction = queue_.beginTransaction();
  queue_.erase(id);
  const auto replacement = HTTPPriorityQueue::Priority(1, true);
  queue_.insertOrUpdate(id, replacement);
  queue_.rollbackTransaction(std::move(transaction));

  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.getRoundRobinElements(), 1);
  EXPECT_TRUE(queue_.headHTTPPriority() == replacement);
  queue_.erase(id);
  EXPECT_EQ(queue_.getRoundRobinElements(), 0);
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, RollbackPreservesSequentialReplacement) {
  const auto id = Identifier::fromStreamID(1);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(3, true));
  auto transaction = queue_.beginTransaction();
  queue_.erase(id);
  const auto replacement = HTTPPriorityQueue::Priority(1, false);
  queue_.insertOrUpdate(id, replacement);
  queue_.rollbackTransaction(std::move(transaction));

  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.getRoundRobinElements(), 0);
  EXPECT_TRUE(queue_.headHTTPPriority() == replacement);
  queue_.erase(id);
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, RollbackRestoresLatestRepeatedErase) {
  const auto id = Identifier::fromStreamID(1);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(3, false, 9));
  auto transaction = queue_.beginTransaction();
  queue_.erase(id);
  const auto replacement = HTTPPriorityQueue::Priority(1, false, 7);
  queue_.insertOrUpdate(id, replacement);
  queue_.erase(id);
  ASSERT_TRUE(queue_.empty());
  queue_.rollbackTransaction(std::move(transaction));

  ASSERT_TRUE(queue_.contains(id));
  EXPECT_EQ(queue_.getRoundRobinElements(), 0);
  EXPECT_EQ(queue_.headHTTPPriority(), replacement);
  queue_.erase(id);
  EXPECT_TRUE(queue_.empty());
}

TEST_F(HTTPPriorityQueueTest, RollbackPreservesPausedReplacement) {
  const auto id = Identifier::fromStreamID(1);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(3, true));
  auto transaction = queue_.beginTransaction();
  queue_.erase(id);
  queue_.insertOrUpdate(id, HTTPPriorityQueue::Priority(1, true));
  const auto paused =
      HTTPPriorityQueue::Priority(HTTPPriorityQueue::Priority::PAUSED);
  queue_.updateIfExist(id, paused);
  ASSERT_TRUE(queue_.empty());

  queue_.rollbackTransaction(std::move(transaction));

  EXPECT_FALSE(queue_.contains(id));
  EXPECT_EQ(queue_.getRoundRobinElements(), 0);
  EXPECT_TRUE(queue_.empty());
}

} // namespace
