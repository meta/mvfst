/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Random.h>
#include <gtest/gtest.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/test/TestUtils.h>
#include <memory>
#include <numeric>
#include <utility>

namespace quic {

template <typename T>
bool verifyStorageContent(
    const CircularDeque<T>& cd,
    const std::vector<T>& expected) {
  EXPECT_EQ(expected.size(), cd.size());
  bool allMatch = std::transform_reduce(
      cd.cbegin(),
      cd.cend(),
      expected.begin(),
      true,
      [](bool accu, bool round) { return accu && round; },
      [](const T& first, const T& second) -> bool { return first == second; });
  if (!allMatch) {
    for (const auto& val : cd) {
      MVLOG_ERROR << "CircularDeque elem:" << val;
    }
    for (const auto& val : expected) {
      MVLOG_ERROR << "expected elem:" << val;
    }
  }
  return allMatch;
}

struct TestObject {
  TestObject() : val(0) {}

  TestObject(int v, std::string w) : val(v), words(std::move(w)) {}

  ~TestObject() = default;

  TestObject(const TestObject& other) noexcept
      : fromCopySource(true), val(other.val), words(other.words) {
    other.copied = true;
  }

  TestObject(TestObject&& other) noexcept
      : fromMoveSource(true), val(other.val), words(std::move(other.words)) {
    other.moved = true;
  }

  TestObject& operator=(const TestObject& other) noexcept {
    fromCopySource = true;
    val = other.val;
    words = other.words;
    other.copied = true;
    return *this;
  }

  TestObject& operator=(TestObject&& other) noexcept {
    fromMoveSource = true;
    val = other.val;
    words = std::move(other.words);
    other.moved = true;
    return *this;
  }

  bool moved{false};
  mutable bool copied{false};
  bool fromMoveSource{false};
  bool fromCopySource{false};
  int val;
  std::string words;
};

bool operator==(const TestObject& lhs, const TestObject& rhs) {
  return lhs.val == rhs.val && lhs.words == rhs.words;
}

// NotMovable struct removed - CircularDeque now requires move construction for
// safety

// NoexceptString - replacement for std::string that meets CircularDeque
// requirements
struct NoexceptString {
  std::string data;

  NoexceptString() = default;

  explicit NoexceptString(const char* s) : data(s) {}

  explicit NoexceptString(std::string s) : data(std::move(s)) {}

  NoexceptString(const NoexceptString& other) noexcept = default;

  NoexceptString(NoexceptString&& other) noexcept = default;

  NoexceptString& operator=(const NoexceptString& other) noexcept = default;

  NoexceptString& operator=(NoexceptString&& other) noexcept = default;

  char& at(size_t pos) {
    return data.at(pos);
  }

  [[nodiscard]] const char& at(size_t pos) const {
    return data.at(pos);
  }

  char& operator[](size_t pos) {
    return data[pos];
  }

  const char& operator[](size_t pos) const {
    return data[pos];
  }

  bool operator==(const NoexceptString& other) const noexcept = default;

  bool operator==(const char* s) const noexcept {
    return data == s;
  }

  friend bool operator==(const char* s, const NoexceptString& ns) noexcept {
    return ns.data == s;
  }
};

TEST(CircularDequeTest, EmptyContainer) {
  CircularDeque<int> cd;
  EXPECT_TRUE(cd.empty());
  EXPECT_EQ(0, cd.size());
  auto b = cd.begin();
  auto e = cd.end();
  EXPECT_EQ(b, e);
}

TEST(CircularDequeTest, InitAndAssign) {
  CircularDeque<int> cd = {1, 3, 5, 7, 9};
  std::vector<int> expected = {1, 3, 5, 7, 9};
  EXPECT_TRUE(verifyStorageContent(cd, expected));
  cd = {2, 4, 6, 8, 10};
  expected = {2, 4, 6, 8, 10};
  EXPECT_TRUE(verifyStorageContent(cd, expected));

  CircularDeque<int> another = cd;
  EXPECT_TRUE(verifyStorageContent(cd, expected));
  EXPECT_TRUE(verifyStorageContent(another, expected));

  CircularDeque<int> third = {1, 3, 5, 7, 9};
  EXPECT_FALSE(verifyStorageContent(third, expected));
  third = std::move(cd);
  EXPECT_TRUE(verifyStorageContent(third, expected));

  cd = {1, 2, 3, 4, 5};
  EXPECT_FALSE(cd.empty());
  EXPECT_EQ(5, cd.size());
  expected = {1, 2, 3, 4, 5};
  EXPECT_TRUE(verifyStorageContent(cd, expected));
}

TEST(CircularDequeTest, CopyAssignIntoDrainedSameCapacity) {
  CircularDeque<NoexceptString> destination;
  destination.resize(3);
  destination.emplace_back("discarded");
  destination.pop_front();

  CircularDeque<NoexceptString> source;
  source.resize(3);
  source.emplace_back("one");
  source.emplace_back("two");
  source.emplace_back("three");
  source.pop_front();
  source.pop_front();
  source.emplace_back("four");
  source.emplace_back("five");
  destination = source;

  const CircularDeque<NoexceptString> expected = {
      NoexceptString("three"), NoexceptString("four"), NoexceptString("five")};
  EXPECT_EQ(destination, expected);
}

TEST(CircularDequeTest, SelfCopyAssignmentPreservesValues) {
  CircularDeque<int> deque = {1, 2, 3};
  const auto capacity = deque.max_size();
  const auto& self = deque;

  deque = self;

  ASSERT_EQ(deque.size(), 3);
  EXPECT_EQ(deque.max_size(), capacity);
  EXPECT_EQ(deque.front(), 1);
  EXPECT_EQ(deque.back(), 3);
  EXPECT_TRUE(verifyStorageContent(deque, std::vector<int>{1, 2, 3}));
}

TEST(CircularDequeTest, InitializerAssignIntoDrainedSameCapacity) {
  CircularDeque<int> deque;
  deque.resize(3);
  deque.push_back(9);
  deque.pop_front();

  deque = {1, 2, 3};

  EXPECT_TRUE(verifyStorageContent(deque, std::vector<int>{1, 2, 3}));
}

TEST(CircularDequeTest, EmptyInitializerAssignIntoDrainedSameCapacity) {
  CircularDeque<int> deque;
  deque.resize(3);
  deque.push_back(9);
  deque.pop_front();

  deque = {};

  EXPECT_TRUE(deque.empty());
  EXPECT_EQ(deque.size(), 0);
}

TEST(CircularDequeTest, PushPopEmplaceAccessErase) {
  CircularDeque<int> cd;
  cd.push_back(0);
  cd.push_back(1);
  cd.push_front(-1);
  EXPECT_EQ(3, cd.size());
  cd.pop_front();
  EXPECT_EQ(0, cd.front());
  EXPECT_EQ(2, cd.size());
  cd.pop_front();
  EXPECT_EQ(1, cd.front());
  EXPECT_EQ(1, cd.back());
  EXPECT_EQ(1, cd.size());

  auto b = cd.begin();
  auto e = cd.end();
  EXPECT_NE(b, e);
  EXPECT_EQ(1, std::distance(b, e));
  EXPECT_EQ(-1, std::distance(e, b));

  EXPECT_EQ(200, cd.emplace_back(200));
  EXPECT_EQ(1, *cd.begin());
  EXPECT_EQ(200, *(cd.begin() + 1));

  auto iter = cd.emplace(cd.cend(), 300);
  EXPECT_NE(iter, cd.end());
  EXPECT_EQ(std::distance(cd.begin(), iter), 2);
  EXPECT_EQ(3, cd.size());

  EXPECT_EQ(1, cd.front());
  EXPECT_EQ(200, *(cd.begin() + 1));
  EXPECT_EQ(300, cd.back());

  iter = cd.emplace(cd.cbegin(), 400);
  EXPECT_EQ(iter, cd.cbegin());
  EXPECT_EQ(400, *std::prev(std::prev(std::prev(std::prev(cd.cend())))));
  EXPECT_EQ(0, std::distance(cd.begin(), iter));
  EXPECT_EQ(-4, std::distance(cd.end(), iter));
  EXPECT_EQ(400, cd[0]);

  iter = cd.erase(std::next(cd.begin()));
  EXPECT_EQ(3, cd.size());
  EXPECT_EQ(400, cd.front());
  EXPECT_EQ(200, *iter);
  EXPECT_EQ(300, cd[2]);

  iter = cd.erase(cd.begin() + 1, cd.end());
  EXPECT_EQ(1, cd.size());
  EXPECT_EQ(400, cd.back());
  EXPECT_EQ(iter, cd.end());

  cd.clear();
  EXPECT_EQ(0, cd.size());
  EXPECT_TRUE(cd.empty());
  EXPECT_NE(0, cd.max_size());
}

TEST(CircularDequeTest, PushBackPopFrontCycle) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 1);
    cd.pop_front();
    ASSERT_EQ(cd.size(), 0);
    ASSERT_TRUE(cd.empty());
  }
}

TEST(CircularDequeTest, PushBackEraseFrontCycle) {
  CircularDeque<int> cd;
  cd.push_back(1);
  ASSERT_EQ(cd.max_size(), kInitCapacity);
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 2);
    cd.erase(cd.begin(), cd.begin() + 1);
    ASSERT_EQ(cd.size(), 1);
  }
}

TEST(CircularDequeTest, PushBackEraseMiddleCycle) {
  CircularDeque<int> cd;
  cd.push_back(1);
  cd.push_back(1);
  ASSERT_EQ(cd.max_size(), kInitCapacity);
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 3);
    cd.erase(cd.begin() + 1, cd.begin() + 2);
    ASSERT_EQ(cd.size(), 2);
  }
}

TEST(CircularDequeTest, PushFrontPopBackCycle) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_front(1);
    ASSERT_EQ(cd.size(), 1);
    cd.pop_back();
    ASSERT_EQ(cd.size(), 0);
    ASSERT_TRUE(cd.empty());
  }
}

TEST(CircularDequeTest, PushFrontEraseBackCycle) {
  CircularDeque<int> cd;
  cd.push_back(1);
  ASSERT_EQ(cd.max_size(), kInitCapacity);
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 2);
    cd.erase(cd.end() - 1, cd.end());
    ASSERT_EQ(cd.size(), 1);
  }
}

TEST(CircularDequeTest, PushBackPopBackCycle) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 1);
    cd.pop_back();
    ASSERT_EQ(cd.size(), 0);
    ASSERT_TRUE(cd.empty());
  }
}

TEST(CircularDequeTest, PushFrontPopFrontCycle) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), 1);
    cd.pop_back();
    ASSERT_EQ(cd.size(), 0);
    ASSERT_TRUE(cd.empty());
  }
}

TEST(CircularDequeTest, EmplaceWrapEnd) {
  CircularDeque<int> cd;
  cd.resize(1);
  cd.clear();
  MVLOG_ERROR << "max: " << cd.max_size();
  // {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
  // begin_ 0
  // end_ 10
  for (size_t i = 0; i < kInitCapacity; i++) {
    cd.push_back(i);
  }
  cd.pop_front();
  // {1, 2, 3, 4, 5, 6, 7, 8, 9}
  // begin_ 1
  // end_ 10
  cd.push_back(kInitCapacity);
  // {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
  // begin_ 1
  // end_ 11
  cd.pop_front();
  // {2, 3, 4, 5, 6, 7, 8, 9, 10}
  // begin_ 2
  // end_ 11
  cd.insert(cd.end() - 1, -1);
  EXPECT_EQ(cd.size(), kInitCapacity);
  EXPECT_EQ(*(cd.end() - 2), -1);
  EXPECT_EQ(*(cd.end() - 1), kInitCapacity);
  EXPECT_EQ(*cd.begin(), 2);
}

TEST(CircularDequeTest, EmplaceLots) {
  CircularDeque<int*> cd;
  cd.resize(1);
  cd.clear();
  cd.emplace_back(new int(1));

  cd.emplace(cd.begin() + 1, new int(2));
  cd.emplace(cd.begin() + 2, new int(3));
  cd.emplace(cd.begin() + 3, new int(4));
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  cd.emplace(cd.begin() + 2, new int(5));
  cd.emplace(cd.begin() + 3, new int(6));
  cd.emplace(cd.begin() + 2, new int(7));
  cd.emplace(cd.begin() + 3, new int(8));
  delete cd.front();
  cd.pop_front();
  cd.emplace(cd.begin() + 3, new int(9));
  cd.emplace(cd.end() - 2, new int(10));
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  delete cd.front();
  cd.pop_front();
  EXPECT_TRUE(cd.empty());
}

template <class ContainerOfPtr, typename T>
static void insertSorted(ContainerOfPtr& cont, T* val) {
  auto insertionItr = std::lower_bound(
      cont.begin(), cont.end(), val, [](const T* a, const T* b) {
        return *a < *b;
      });
  cont.insert(insertionItr, val);
}

static void
insertBoth(CircularDeque<int64_t*>& cd, std::deque<int64_t*>& d, int64_t val) {
  insertSorted<decltype(cd), decltype(val)>(cd, new int64_t(val));
  insertSorted<decltype(d), decltype(val)>(d, new int64_t(val));
}

TEST(CircularDequeTest, RandSortedEmplacesStress) {
  std::deque<int64_t*> d;
  CircularDeque<int64_t*> cd;
  cd.resize(1);
  cd.clear();
  int numOps = 200000;

  ASSERT_TRUE(cd.empty());
  ASSERT_TRUE(d.empty());
  while (numOps-- > 0) {
    ASSERT_EQ(cd.size(), d.size());
    // 1/3 of the time, do a removal.
    if (folly::Random::oneIn(3) && !cd.empty()) {
      int64_t* v1{};
      int64_t* v2{};
      SCOPE_EXIT {
        delete v1;
        delete v2;
      };
      int64_t dice = folly::Random::rand64(0, 3);
      if (dice == 0) {
        v1 = cd.front();
        v2 = d.front();
        ASSERT_NE(v1, nullptr);
        ASSERT_NE(v2, nullptr);
        ASSERT_EQ(*v1, *v2);
        cd.pop_front();
        d.pop_front();
      } else if (dice == 1) {
        v1 = cd.back();
        v2 = d.back();
        ASSERT_NE(v1, nullptr);
        ASSERT_NE(v2, nullptr);
        ASSERT_EQ(*v1, *v2);
        cd.pop_back();
        d.pop_back();
      } else {
        size_t randIdx = folly::Random::rand64(0, cd.size());
        auto itr1 = cd.begin() + randIdx;
        auto itr2 = d.begin() + randIdx;
        v1 = *itr1;
        v2 = *itr2;
        ASSERT_NE(v1, nullptr);
        ASSERT_NE(v2, nullptr);
        ASSERT_EQ(*v1, *v2);
        cd.erase(itr1);
        d.erase(itr2);
      }
    } else {
      insertBoth(cd, d, folly::Random::rand64());
    }
    // Every one in a while clear out the whole thing.
    if (folly::Random::oneIn(1000)) {
      ASSERT_EQ(cd.size(), d.size());
      auto itr1 = cd.begin();
      auto itr2 = d.begin();
      while (itr1 != cd.end()) {
        auto v1 = *itr1;
        auto v2 = *itr2;
        ASSERT_NE(v1, nullptr);
        ASSERT_NE(v2, nullptr);
        ASSERT_EQ(*v1, *v2);
        itr1 = cd.erase(itr1);
        itr2 = d.erase(itr2);
        delete v1;
        delete v2;
      }
    }
  }
  // Clean up and verify the remainder.
  ASSERT_EQ(cd.size(), d.size());
  auto itr1 = cd.begin();
  auto itr2 = d.begin();
  while (itr1 != cd.end()) {
    auto v1 = *itr1;
    auto v2 = *itr2;
    ASSERT_NE(v1, nullptr);
    ASSERT_NE(v2, nullptr);
    ASSERT_EQ(*v1, *v2);
    itr1 = cd.erase(itr1);
    itr2 = d.erase(itr2);
    delete v1;
    delete v2;
  }
  ASSERT_TRUE(cd.empty());
  ASSERT_TRUE(d.empty());
}

TEST(CircularDequeTest, MaxCapacityCycleRight) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity - 1; i++) {
    cd.push_back(i);
  }
  ASSERT_EQ(cd.max_size(), kInitCapacity);
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_back(1);
    ASSERT_EQ(cd.size(), kInitCapacity);
    cd.pop_front();
    ASSERT_EQ(cd.size(), kInitCapacity - 1);
  }
}

TEST(CircularDequeTest, MaxCapacityCycleLeft) {
  CircularDeque<int> cd;
  for (size_t i = 0; i < kInitCapacity - 1; i++) {
    cd.push_front(i);
  }
  ASSERT_EQ(cd.max_size(), kInitCapacity);
  for (size_t i = 0; i < kInitCapacity * 2; i++) {
    cd.push_front(1);
    ASSERT_EQ(cd.size(), kInitCapacity);
    cd.pop_back();
    ASSERT_EQ(cd.size(), kInitCapacity - 1);
  }
}

TEST(CircularDequeTest, WrappedDequeAccess) {
  CircularDeque<int> cd = {1, 2, 3, 4, 5, 6, 7};
  cd.push_front(0);
  cd.push_front(-1);
  cd.push_front(-2);
  EXPECT_EQ(-2, cd[0]);
  EXPECT_EQ(0, cd[2]);
  EXPECT_EQ(1, cd[3]);
  EXPECT_EQ(7, cd[9]);
}

TEST(CircularDequeTest, ObjectMove) {
  CircularDeque<TestObject> cd;
  cd.emplace_back(0, "My object");
  EXPECT_EQ(1, cd.size());
  EXPECT_FALSE(cd.begin()->fromCopySource);
  TestObject testObject(1, "My other object");
  cd.emplace_back(std::move(testObject));
  EXPECT_TRUE(testObject.moved);
  EXPECT_FALSE(testObject.copied);
  EXPECT_TRUE(cd[1].fromMoveSource);
  EXPECT_EQ("My object", cd.front().words);
  EXPECT_EQ("My other object", cd.back().words);

  TestObject moreTestObject(2, "One more object");
  cd.emplace_back(moreTestObject);
  EXPECT_FALSE(moreTestObject.moved);
  EXPECT_TRUE(moreTestObject.copied);
  EXPECT_TRUE(cd[2].fromCopySource);
  EXPECT_FALSE(cd.back().fromMoveSource);
  EXPECT_EQ("My object", cd[0].words);
  EXPECT_EQ("My other object", cd[1].words);
  EXPECT_EQ("One more object", cd[2].words);

  // resize should do move
  cd.resize(cd.max_size() + 2);
  for (auto& elem : cd) {
    EXPECT_TRUE(elem.fromMoveSource);
    EXPECT_FALSE(elem.fromCopySource);
  }
  EXPECT_EQ("My object", cd[0].words);
  EXPECT_EQ("My other object", cd[1].words);
  EXPECT_EQ("One more object", cd[2].words);

  // Insert into the middle
  cd.emplace(cd.begin() + 1, 3, "Object number three");
  EXPECT_EQ(TestObject(0, "My object"), cd[0]);
  EXPECT_EQ(TestObject(3, "Object number three"), cd[1]);
  EXPECT_EQ(TestObject(1, "My other object"), cd[2]);
  EXPECT_EQ(TestObject(2, "One more object"), cd[3]);

  // resize into full size
  cd.resize(cd.size());
  EXPECT_EQ(cd.size(), cd.max_size());
  EXPECT_EQ(TestObject(0, "My object"), cd[0]);
  EXPECT_EQ(TestObject(3, "Object number three"), cd[1]);
  EXPECT_EQ(TestObject(1, "My other object"), cd[2]);
  EXPECT_EQ(TestObject(2, "One more object"), cd[3]);

  cd.emplace_front(4, "My fourth");
  EXPECT_EQ(TestObject(4, "My fourth"), cd[0]);
  EXPECT_EQ(TestObject(0, "My object"), cd[1]);
  EXPECT_EQ(TestObject(3, "Object number three"), cd[2]);
  EXPECT_EQ(TestObject(1, "My other object"), cd[3]);
  EXPECT_EQ(TestObject(2, "One more object"), cd[4]);

  cd.emplace(cd.begin() + 3, 5, "Number 5");
  EXPECT_EQ(TestObject(4, "My fourth"), cd[0]);
  EXPECT_EQ(TestObject(0, "My object"), cd[1]);
  EXPECT_EQ(TestObject(3, "Object number three"), cd[2]);
  EXPECT_EQ(TestObject(5, "Number 5"), cd[3]);
  EXPECT_EQ(TestObject(1, "My other object"), cd[4]);
  EXPECT_EQ(TestObject(2, "One more object"), cd[5]);
}

TEST(CircularDequeTest, NoncopiableElems) {
  CircularDeque<std::unique_ptr<TestObject>> cd;
  int counter = 0;
  while (counter++ < 10) {
    auto ptr = std::make_unique<TestObject>(counter, "My object");
    cd.push_back(std::move(ptr));
  }
  auto maxSize = cd.max_size();
  while (cd.size() < maxSize * 2) {
    auto ptr = std::make_unique<TestObject>(cd.size(), "My object");
    cd.push_back(std::move(ptr));
  }
  cd.erase(cd.begin() + cd.size() / 3, cd.begin() + cd.size() / 3 * 2);
}

TEST(CircularDequeTest, Swap) {
  CircularDeque<int> first = {1, 2, 3, 4, 5};
  CircularDeque<int> second = {1, 3, 5, 7, 9, 11, 13};
  first.swap(second);
  EXPECT_EQ(7, first.size());
  EXPECT_EQ(5, second.size());
  std::vector<int> expected = {1, 3, 5, 7, 9, 11, 13};
  EXPECT_TRUE(verifyStorageContent(first, expected));
  expected = {1, 2, 3, 4, 5};
  EXPECT_TRUE(verifyStorageContent(second, expected));
}

TEST(CircularDequeTest, Resize) {
  CircularDeque<int> emptyCD;
  EXPECT_TRUE(emptyCD.empty());
  EXPECT_EQ(0, emptyCD.size());

  emptyCD.resize(200);
  EXPECT_TRUE(emptyCD.empty());
  EXPECT_EQ(0, emptyCD.size());

  emptyCD.resize(0);
  EXPECT_TRUE(emptyCD.empty());
  EXPECT_EQ(0, emptyCD.size());

  emptyCD = {1, 2, 3, 4, 5};
  EXPECT_FALSE(emptyCD.empty());
  EXPECT_EQ(5, emptyCD.size());
  std::vector<int> expected = {1, 2, 3, 4, 5};
  EXPECT_TRUE(verifyStorageContent(emptyCD, expected));

  emptyCD.resize(200);
  EXPECT_FALSE(emptyCD.empty());
  EXPECT_EQ(5, emptyCD.size());
  EXPECT_TRUE(verifyStorageContent(emptyCD, expected));
}

TEST(CircularDequeTest, MiddleOpsNoCrashNoLeak) {
  CircularDeque<NoexceptString> cd;
  size_t counter = 0;
  auto obuffer = quic::test::buildRandomInputData(500);
  while (counter++ < 10000 / 2) {
    auto buffer = obuffer->clone();
    cd.push_front(NoexceptString(buffer->toString()));
  }
  EXPECT_EQ(5000, cd.size());
  counter = 0;
  while (counter++ < 10000) {
    cd.insert(
        cd.begin() + cd.size() / 3 + (counter % 2) * cd.size() / 3,
        NoexceptString("test string"));
  }
  EXPECT_EQ(15000, cd.size());
  counter = 0;
  while (counter++ < 10000 / 4) {
    auto erasePos = cd.begin() + cd.size() / 3 + (counter % 2) * cd.size() / 3;
    cd.erase(erasePos, 3 + erasePos);
  }
  EXPECT_EQ(7500, cd.size());
}

TEST(CircularDequeTest, Iterators) {
  CircularDeque<int> cd = {1, 2, 3, 4, 5, 6, 7};
  EXPECT_EQ(*cd.begin(), *cd.cbegin());
  EXPECT_EQ(*(cd.end() - 1), *(cd.cend() - 1));
  auto iter = cd.begin();
  EXPECT_EQ(1, *iter);
  auto next = std::next(iter);
  EXPECT_EQ(2, *next);
  EXPECT_EQ(7, *(cd.end() - 1));
  std::advance(iter, 5);
  EXPECT_EQ(6, *iter);
  auto prev = std::prev(iter);
  EXPECT_EQ(5, *prev);
  EXPECT_EQ(2, std::distance(iter, cd.end()));
  EXPECT_EQ(-2, std::distance(cd.end(), iter));

  // Force a wrapped vector
  cd.push_front(0);
  cd.push_front(-1);
  cd.push_front(-2);
  std::vector expected = {-2, -1, 0, 1, 2, 3, 4, 5, 6, 7};
  EXPECT_TRUE(verifyStorageContent(cd, expected));
  iter = cd.begin();
  EXPECT_EQ(-2, *iter);
  next = std::next(std::next(iter));
  EXPECT_EQ(0, *next);
  EXPECT_EQ(next, iter + 2);
  std::advance(iter, 5);
  EXPECT_EQ(3, *iter);
  prev = std::prev(std::prev(std::next(std::prev(iter))));
  EXPECT_EQ(1, *prev);
  EXPECT_EQ(2, std::distance(prev, iter));
  EXPECT_EQ(-3, std::distance(iter, next));
  EXPECT_EQ(5, std::distance(cd.begin(), iter));
  EXPECT_EQ(-5, std::distance(iter, cd.begin()));
  EXPECT_EQ(5, std::distance(iter, cd.end()));
  EXPECT_EQ(-5, std::distance(cd.end(), iter));

  std::vector<int> collector;
  for (auto val : cd) {
    collector.push_back(val);
  }
  EXPECT_EQ(collector, expected);

  // Mutation using iterators
  CircularDeque<NoexceptString> scd = {
      NoexceptString("111"), NoexceptString("222"), NoexceptString("333")};
  auto siter = scd.begin() + 1;
  siter->at(1) = 'b';
  EXPECT_EQ("2b2", scd[1]);
  auto& s = *scd.emplace(siter, NoexceptString("555"));
  s[1] = 'c';
  EXPECT_EQ("5c5", scd[1]);
}

TEST(CircularDequeTest, ReverseIterators) {
  CircularDeque<int> cd = {7, 6, 5, 4, 3, 2, 1};
  EXPECT_EQ(*cd.rbegin(), *cd.crbegin());
  EXPECT_EQ(*(cd.rend() - 1), *(cd.crend() - 1));
  auto riter = cd.rbegin();
  EXPECT_EQ(1, *riter);
  EXPECT_EQ(cd.end(), riter.base());
  auto next = std::next(riter);
  EXPECT_EQ(2, *next);
  EXPECT_EQ(7, *(cd.rend() - 1));
  std::advance(riter, 5);
  EXPECT_EQ(6, *riter);
  EXPECT_EQ(5, *(riter.base()));
  auto prev = std::prev(riter);
  EXPECT_EQ(5, *prev);
  EXPECT_EQ(2, std::distance(riter, cd.rend()));
  EXPECT_EQ(-2, std::distance(cd.rend(), riter));
  EXPECT_NE(prev, next);
  EXPECT_NE(riter, prev);

  // Force a wrapped vector
  cd.push_front(0);
  cd.push_front(-1);
  cd.push_front(-2);
  std::vector expected = {-2, -1, 0, 7, 6, 5, 4, 3, 2, 1};
  EXPECT_TRUE(verifyStorageContent(cd, expected));

  // sanity checks around corners:
  riter = cd.rend() - 3; // let riter points to the wrapping point
  EXPECT_EQ(0, *riter);
  EXPECT_EQ(7, *(riter.base()));

  riter = cd.rend() - 1;
  EXPECT_EQ(-2, *riter);
  prev = std::prev(std::prev(riter));
  EXPECT_EQ(0, *prev);
  EXPECT_EQ(prev, riter - 2);
  std::advance(riter, -5);
  EXPECT_EQ(5, *riter);
  riter = cd.rbegin();
  next = std::next(std::next(std::next(std::prev(riter))));
  EXPECT_EQ(3, *next);
  std::advance(riter, 5);
  EXPECT_EQ(6, *riter);
  // riter at 6, prev at 0, next at 3
  EXPECT_EQ(-2, std::distance(prev, riter));
  EXPECT_EQ(-3, std::distance(riter, next));
  EXPECT_EQ(5, std::distance(cd.rbegin(), riter));
  EXPECT_EQ(-5, std::distance(riter, cd.rbegin()));
  EXPECT_EQ(5, std::distance(riter, cd.rend()));
  EXPECT_EQ(-5, std::distance(cd.rend(), riter));
  EXPECT_NE(prev, next);
  EXPECT_NE(riter, prev);
  next = riter;
  EXPECT_EQ(next, riter);

  // Erase with reverse iterators' base()s
  // Let prev points to -1, so the erase is across wrapping point
  prev = std::next(prev);
  auto elemNext = cd.erase(prev.base(), riter.base());
  expected = {-2, -1, 5, 4, 3, 2, 1};
  EXPECT_EQ(5, *elemNext);
  EXPECT_TRUE(verifyStorageContent(cd, expected));
}

TEST(CircularDequeTest, MoveOrCopyDoNotOverwrite) {
  CircularDeque<int> cd = {1, 2, 3, 4, 5, 6, 7};
  // erase 3, {1, 2} will be copied into the current position of {2, 3}.
  // during this copy, 1 cannot overwrite 2 before 2 is copied
  cd.erase(cd.begin() + 2);
  std::vector<int> expected = {1, 2, 4, 5, 6, 7};
  EXPECT_TRUE(verifyStorageContent(cd, expected));

  // erase 5, this will copy 6 and 7
  auto pos = cd.erase(cd.end() - 3);
  expected = {1, 2, 4, 6, 7};
  EXPECT_EQ(6, *pos);
  EXPECT_TRUE(verifyStorageContent(cd, expected));

  // insert 3 before 6 and 7
  pos = cd.insert(pos, 3);
  expected = {1, 2, 4, 3, 6, 7};
  EXPECT_EQ(3, *pos);
  EXPECT_TRUE(verifyStorageContent(cd, expected));

  // insert 5 after 1 and 2
  pos = cd.emplace(pos - 1, 5);
  expected = {1, 2, 5, 4, 3, 6, 7};
  EXPECT_EQ(5, *pos);
  EXPECT_TRUE(verifyStorageContent(cd, expected));
}
} // namespace quic
