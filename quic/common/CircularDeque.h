/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <algorithm>
#include <cstdlib>
#include <initializer_list>
#include <iterator>
#include <memory>

#include <quic/common/MvfstCheck.h>

namespace quic {

/**
 * A container backed by contiguous memory. It can pop and push from both ends
 * like std::deque. Doing such operation with CircularDeque should be faster
 * than std::deque. It also supports APIs to mutate the middle of the container
 * (erase(), emplace() and insert() all support arbitrary positions). But doing
 * so with CircularDeque is much slower than std::deque.
 *
 * This container is unconditionally non-throwing.
 * Memory allocation failures result in std::abort() rather than exceptions.
 */
template <typename T>
struct CircularDeque {
  // Core safety requirements: must be destructible and have noexcept destructor
  static_assert(
      std::is_destructible_v<T>,
      "CircularDeque requires destructible type");
  static_assert(
      std::is_nothrow_destructible_v<T>,
      "CircularDeque requires non-throwing destructor");

  // Move operations must be noexcept when available (critical for container
  // safety)
  static_assert(
      !std::is_move_constructible_v<T> ||
          std::is_nothrow_move_constructible_v<T>,
      "CircularDeque requires non-throwing move constructor when move construction is available");
  static_assert(
      !std::is_move_assignable_v<T> || std::is_nothrow_move_assignable_v<T>,
      "CircularDeque requires non-throwing move assignment when move assignment is available");

  // Copy operations must be noexcept when available (for optimal performance)
  static_assert(
      !std::is_copy_constructible_v<T> ||
          std::is_nothrow_copy_constructible_v<T>,
      "CircularDeque requires non-throwing copy constructor when copy construction is available");
  static_assert(
      !std::is_copy_assignable_v<T> || std::is_nothrow_copy_assignable_v<T>,
      "CircularDeque requires non-throwing copy assignment when copy assignment is available");

  // Move operations are required for buffer types
  static_assert(
      std::is_move_constructible_v<T>,
      "CircularDeque requires move construction");
  static_assert(
      std::is_move_assignable_v<T>,
      "CircularDeque requires move assignment");

  using value_type = T;
  using size_type = std::size_t;
  using reference = T&;
  using const_reference = const T&;
  using difference_type = std::ptrdiff_t;

  CircularDeque() = default;

  CircularDeque(size_type n) {
    resize(n);
  }

  CircularDeque(std::initializer_list<T> init);

  CircularDeque(const CircularDeque& other) {
    *this = other;
  }

  // Move constructor will leave other in a default-initialized state.
  CircularDeque(CircularDeque&& other) noexcept {
    swap(other);
  }

  CircularDeque& operator=(const CircularDeque& other) {
    if (this == &other) {
      return *this;
    }
    clear();
    resize(other.size());
    std::uninitialized_copy(other.begin(), other.end(), storage_);
    end_ = other.size();
    return *this;
  }

  // Move assignment will leave other in a default-initialized state.
  CircularDeque& operator=(CircularDeque&& other) noexcept {
    swap(other);
    CircularDeque{}.swap(other);
    return *this;
  }

  CircularDeque& operator=(std::initializer_list<T> ilist);

  ~CircularDeque() {
    if (capacity_ == 0) {
      MVDCHECK(!storage_);
      return;
    }
    clear();
    ::operator delete(storage_);
    capacity_ = 0;
  }

  // Missing: more constructor overloads, and custom Allocator
  bool operator==(const CircularDeque& other) const {
    return size() == other.size() && std::equal(begin(), end(), other.begin());
  }

  bool operator!=(const CircularDeque& other) const {
    return !(*this == other);
  }

  // Iterator - Hand-rolled random access iterator
  template <typename U>
  class CircularDequeIterator {
   private:
    friend struct CircularDeque<T>;

    CircularDequeIterator(const CircularDeque<T>* deque, size_type index)
        : deque_(deque), index_(index) {}

   public:
    // Iterator traits (C++17 style)
    using iterator_category = std::random_access_iterator_tag;
    using value_type = typename std::remove_cv<U>::type;
    using difference_type = std::ptrdiff_t;
    using pointer = U*;
    using reference = U&;

    // Constructors
    CircularDequeIterator() : deque_(nullptr), index_(0) {}

    // Allow conversion from non-const to const iterator
    template <
        typename V,
        typename = std::enable_if_t<std::is_const_v<U> && !std::is_const_v<V>>>
    CircularDequeIterator(const CircularDequeIterator<V>& other)
        : deque_(other.deque_), index_(other.index_) {}

    // Copy constructor and assignment for same type
    CircularDequeIterator(const CircularDequeIterator&) = default;
    CircularDequeIterator& operator=(const CircularDequeIterator&) = default;

    // Dereference operators
    [[nodiscard]] reference operator*() const {
      return const_cast<reference>(deque_->storage_[index_]);
    }

    [[nodiscard]] pointer operator->() const {
      return &const_cast<reference>(deque_->storage_[index_]);
    }

    [[nodiscard]] reference operator[](difference_type n) const {
      return *(*this + n);
    }

    // Comparison operators (work with both iterator and const_iterator)
    template <typename V>
    [[nodiscard]] bool operator==(const CircularDequeIterator<V>& other) const {
      return deque_ == other.deque_ && index_ == other.index_;
    }

    template <typename V>
    [[nodiscard]] bool operator!=(const CircularDequeIterator<V>& other) const {
      return !(*this == other);
    }

    template <typename V>
    [[nodiscard]] bool operator<(const CircularDequeIterator<V>& other) const {
      MVDCHECK_EQ(deque_, other.deque_);
      return distance_to(other) > 0;
    }

    template <typename V>
    [[nodiscard]] bool operator<=(const CircularDequeIterator<V>& other) const {
      return *this < other || *this == other;
    }

    template <typename V>
    [[nodiscard]] bool operator>(const CircularDequeIterator<V>& other) const {
      return !(*this <= other);
    }

    template <typename V>
    [[nodiscard]] bool operator>=(const CircularDequeIterator<V>& other) const {
      return !(*this < other);
    }

    // Increment/decrement operators
    CircularDequeIterator& operator++() {
      increment();
      return *this;
    }

    CircularDequeIterator operator++(int) {
      CircularDequeIterator temp = *this;
      increment();
      return temp;
    }

    CircularDequeIterator& operator--() {
      decrement();
      return *this;
    }

    CircularDequeIterator operator--(int) {
      CircularDequeIterator temp = *this;
      decrement();
      return temp;
    }

    // Arithmetic operators
    CircularDequeIterator& operator+=(difference_type n) {
      advance(n);
      return *this;
    }

    CircularDequeIterator& operator-=(difference_type n) {
      advance(-n);
      return *this;
    }

    [[nodiscard]] CircularDequeIterator operator+(difference_type n) const {
      CircularDequeIterator temp = *this;
      temp.advance(n);
      return temp;
    }

    [[nodiscard]] CircularDequeIterator operator-(difference_type n) const {
      CircularDequeIterator temp = *this;
      temp.advance(-n);
      return temp;
    }

    template <typename V>
    [[nodiscard]] difference_type operator-(
        const CircularDequeIterator<V>& other) const {
      MVDCHECK_EQ(deque_, other.deque_);
      return -distance_to(other);
    }

   private:
    friend struct CircularDeque<T>;
    friend struct CircularDeque<typename std::remove_const<T>::type>;
    template <typename V>
    friend class CircularDequeIterator;

    void increment() {
      ++index_;
      auto maxSize = deque_->capacity_;
      if (index_ > maxSize) {
        index_ = 0;
      }
      if (wrapped() && index_ == maxSize) {
        index_ = 0;
      }
    }

    void decrement() {
      auto maxSize = deque_->capacity_;
      if (index_ == 0) {
        index_ = wrapped() ? maxSize - 1 : maxSize;
      } else {
        --index_;
      }
    }

    void advance(difference_type n) {
      if (n == 0) {
        return;
      }
      if (n > 0) {
        auto maxSize = deque_->capacity_;
        index_ = (index_ + n) % (wrapped() ? maxSize : maxSize + 1);
      } else {
        while (n++ != 0) {
          decrement();
        }
      }
    }

    template <typename V>
    [[nodiscard]] difference_type distance_to(
        const CircularDequeIterator<V>& other) const {
      if (index_ == other.index_) {
        return 0;
      }
      bool backward = false;
      if (wrapped()) {
        if ((index_ >= deque_->begin_ && other.index_ >= deque_->begin_) ||
            (index_ <= deque_->end_ && other.index_ <= deque_->end_)) {
          backward = index_ > other.index_;
        } else {
          backward = index_ < other.index_;
        }
      } else {
        backward = index_ > other.index_;
      }
      if (backward) {
        return -deque_->wrappedDistance(other, *this);
      } else {
        return deque_->wrappedDistance(*this, other);
      }
    }

    [[nodiscard]] inline bool wrapped() const {
      return deque_->begin_ > deque_->end_;
    }

    const CircularDeque<T>* deque_;
    size_type index_;
  };

  // Global operator+ for iterator arithmetic (n + iterator)
  template <typename U>
  [[nodiscard]] friend CircularDequeIterator<U> operator+(
      typename CircularDequeIterator<U>::difference_type n,
      const CircularDequeIterator<U>& iter) {
    return iter + n;
  }

  using iterator = CircularDequeIterator<T>;
  using const_iterator = CircularDequeIterator<const T>;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  [[nodiscard]] bool empty() const noexcept;
  [[nodiscard]] size_type size() const noexcept;

  [[nodiscard]] size_type max_size() const noexcept;
  void resize(size_type count);
  // Missing compared to std::deque:
  // resize(size_t, const T&);
  // shrink_to_fit();

  const_reference operator[](size_type index) const;
  reference operator[](size_type index);
  [[nodiscard]] const_reference front() const;
  [[nodiscard]] reference front();
  [[nodiscard]] const_reference back() const;
  [[nodiscard]] reference back();

  [[nodiscard]] iterator begin() noexcept;
  [[nodiscard]] const_iterator begin() const noexcept;
  [[nodiscard]] iterator end() noexcept;
  [[nodiscard]] const_iterator end() const noexcept;
  [[nodiscard]] const_iterator cbegin() const noexcept;
  [[nodiscard]] const_iterator cend() const noexcept;
  [[nodiscard]] reverse_iterator rbegin() noexcept;
  [[nodiscard]] const_reverse_iterator rbegin() const noexcept;
  [[nodiscard]] const_reverse_iterator crbegin() const noexcept;
  [[nodiscard]] reverse_iterator rend() noexcept;
  [[nodiscard]] const_reverse_iterator rend() const noexcept;
  [[nodiscard]] const_reverse_iterator crend() const noexcept;

  template <class... Args>
  reference emplace_front(Args&&... args);
  template <class... Args>
  reference emplace_back(Args&&... args);
  template <class... Args>
  iterator emplace(const_iterator pos, Args&&... args);

  void push_front(const T& val);
  void push_front(T&& val);
  void push_back(const T& val);
  void push_back(T&& val);
  iterator insert(const_iterator pos, const T& val);
  iterator insert(const_iterator pos, T&& val);
  // Missing: a couple insert() overloads

  void pop_front();
  void pop_back();

  // If you are erasing from either end of the container and is only erasing
  // one element, I suggest just use pop_front and pop_back. And if are erasing
  // the whole container, please use clear(). There is nothing wrong with
  // erase() in those cases, but such code are behind an UNLIKELY annotation.
  // The generated code can be slow.
  iterator erase(const_iterator pos);
  iterator erase(const_iterator first, const_iterator last);
  void clear() noexcept;
  void swap(CircularDeque<T>& other) noexcept;

 private:
  [[nodiscard]] bool needSpace() const noexcept;

  template <
      typename U = T,
      typename Iterator,
      std::enable_if_t<std::is_move_assignable<U>::value, int> = 0>
  void moveOrCopy(Iterator first, Iterator last, Iterator destFirst) noexcept {
    if (first == last || first == destFirst) {
      return;
    }
    auto iter = first;
    while (iter != last) {
      *destFirst = std::move(*iter++);
      // Different from iter, destFirst cannot reuse increment/advance.
      if (destFirst.index_ == capacity_ - 1) {
        destFirst.index_ = 0;
      } else {
        ++destFirst.index_;
      }
    }
  }

  template <
      typename U = T,
      typename ConstIterator,
      typename Iterator,
      std::enable_if_t<
          !std::is_move_assignable<U>::value &&
              std::is_copy_assignable<U>::value,
          int> = 0>
  void moveOrCopy(
      ConstIterator first,
      ConstIterator last,
      Iterator destFirst) noexcept(std::is_nothrow_copy_assignable<T>::value) {
    static_assert(!std::is_assignable<
                  ConstIterator,
                  decltype(*std::declval<ConstIterator>)>::value);
    if (first == last || first == destFirst) {
      return;
    }
    auto iter = first;
    while (iter != last) {
      *destFirst = *iter++;
      // Different from iter, destFirst cannot reuse increment/advance.
      if (destFirst.index_ == capacity_ - 1) {
        destFirst.index_ = 0;
      } else {
        ++destFirst.index_;
      }
    }
  }

  template <
      typename U = T,
      typename Iterator,
      std::enable_if_t<std::is_move_assignable<U>::value, int> = 0>
  void
  reverseMoveOrCopy(Iterator first, Iterator last, Iterator destLast) noexcept {
    if (first == last || last == destLast) {
      return;
    }
    auto iter = last;
    while (iter != first) {
      if (destLast.index_ == 0) {
        destLast.index_ = capacity_ - 1;
      } else {
        --destLast.index_;
      }
      *destLast = std::move(*--iter);
    }
  }

  template <
      typename U = T,
      typename ConstIterator,
      typename Iterator,
      std::enable_if_t<
          !std::is_move_assignable<U>::value &&
              std::is_copy_assignable<U>::value,
          int> = 0>
  void reverseMoveOrCopy(
      ConstIterator first,
      ConstIterator last,
      Iterator destLast) noexcept(std::is_nothrow_copy_assignable<T>::value) {
    static_assert(!std::is_assignable<
                  ConstIterator,
                  decltype(*std::declval<ConstIterator>)>::value);
    if (first == last || last == destLast) {
      return;
    }
    auto iter = last;
    while (iter != first) {
      if (destLast.index_ == 0) {
        destLast.index_ = capacity_ - 1;
      } else {
        --destLast.index_;
      }
      *destLast = *--iter;
    }
  }

  template <
      typename U = T,
      std::enable_if_t<std::is_move_constructible<U>::value, int> = 0>
  void allocateWithValueFrom(iterator source, iterator dest) noexcept {
    new (&storage_[dest.index_]) T(std::move(*source));
  }

  template <
      typename U = T,
      std::enable_if_t<
          !std::is_move_constructible<U>::value &&
              std::is_copy_constructible<U>::value,
          int> = 0>
  void allocateWithValueFrom(const_iterator source, iterator dest) noexcept(
      std::is_nothrow_copy_constructible<T>::value) {
    new (&storage_[dest.index_]) T(*source);
  }

  size_type wrappedDistance(const_iterator first, const_iterator last)
      const noexcept {
    if (last.index_ >= first.index_) {
      return last.index_ - first.index_;
    }
    return capacity_ - first.index_ + last.index_;
  }

  void indexSanityCheck([[maybe_unused]] const_iterator iter) noexcept {
    if (begin_ <= end_) {
      MVDCHECK(begin_ <= iter.index_ && iter.index_ <= end_);
    } else {
      MVDCHECK(iter.index_ >= begin_ || iter.index_ <= end_);
    }
  }

 private:
  T* storage_ = nullptr;
  size_type capacity_ = 0;
  size_type begin_ = 0;
  size_type end_ = 0;
};
} // namespace quic

#include <quic/common/CircularDeque-inl.h>
