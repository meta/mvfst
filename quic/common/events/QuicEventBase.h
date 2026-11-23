/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstLogging.h>
#include <functional>

#include <folly/GLog.h>
#include <chrono>
#include <cstdint>

namespace quic {

class QuicEventBase;

class QuicEventBaseLoopCallback {
 public:
  friend class QuicEventBase;

  virtual ~QuicEventBaseLoopCallback() {
    if (implHandle) {
      implHandle->cancelImpl();
      delete implHandle;
    }
  }

  virtual void runLoopCallback() noexcept = 0;

  void cancelLoopCallback() noexcept {
    if (implHandle) {
      implHandle->cancelImpl();
    }
  }

  [[nodiscard]] bool isLoopCallbackScheduled() const noexcept {
    return implHandle ? implHandle->isScheduledImpl() : false;
  }

  class LoopCallbackImpl {
   public:
    virtual ~LoopCallbackImpl() = default;
    virtual void cancelImpl() noexcept = 0;
    [[nodiscard]] virtual bool isScheduledImpl() const noexcept = 0;
  };

 private:
  LoopCallbackImpl* implHandle{nullptr};
};

class QuicTimerCallback {
 public:
  friend class QuicEventBase;

  virtual ~QuicTimerCallback() {
    if (implHandle) {
      implHandle->cancelImpl();
      delete implHandle;
    }
  }

  virtual void timeoutExpired() noexcept = 0;

  /// This callback was canceled. The default implementation is to just
  /// proxy to `timeoutExpired` but if you care about the difference between
  /// the timeout finishing or being canceled you can override this.
  virtual void callbackCanceled() noexcept {
    timeoutExpired();
  }

  void cancelTimerCallback() noexcept {
    if (implHandle) {
      implHandle->cancelImpl();
    }
  }

  [[nodiscard]] bool isTimerCallbackScheduled() const noexcept {
    return implHandle ? implHandle->isScheduledImpl() : false;
  }

  [[nodiscard]] std::chrono::milliseconds getTimerCallbackTimeRemaining()
      const noexcept {
    if (!implHandle) {
      return std::chrono::milliseconds(0);
    }
    return implHandle->getTimeRemainingImpl();
  }

  class TimerCallbackImpl {
   public:
    virtual ~TimerCallbackImpl() = default;
    virtual void cancelImpl() noexcept = 0;
    [[nodiscard]] virtual bool isScheduledImpl() const noexcept = 0;
    [[nodiscard]] virtual std::chrono::milliseconds getTimeRemainingImpl()
        const noexcept = 0;
  };

 private:
  TimerCallbackImpl* implHandle{nullptr};
};

/**
 * An interface mvfst expects from event base implementation.
 */
class QuicEventBase {
 public:
  virtual ~QuicEventBase() = default;

  virtual void runInLoop(
      QuicEventBaseLoopCallback* callback,
      bool thisIteration = false) = 0;

  virtual void runInLoop(
      std::function<void()> cb,
      bool thisIteration = false) = 0;

  virtual void runAfterDelay(
      std::function<void()> cb,
      uint32_t milliseconds) = 0;

  virtual void runInEventBaseThreadAndWait(
      std::function<void()> fn) noexcept = 0;

  virtual void runImmediatelyOrRunInEventBaseThreadAndWait(
      std::function<void()> fn) noexcept = 0;

  virtual void runInEventBaseThread(std::function<void()> fn) noexcept = 0;

  virtual void runImmediatelyOrRunInEventBaseThread(
      std::function<void()> fn) noexcept = 0;

  [[nodiscard]] virtual bool isInEventBaseThread() const = 0;

  virtual void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) = 0;

  virtual bool scheduleTimeoutHighRes(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) = 0;

  virtual bool loopOnce(int flags = 0) = 0;

  virtual bool loop() = 0;

  virtual void loopForever() = 0;

  virtual bool loopIgnoreKeepAlive() = 0;

  virtual void terminateLoopSoon() = 0;

  [[nodiscard]] virtual std::chrono::milliseconds getTimerTickInterval()
      const = 0;

  template <typename T>
  T* getTypedEventBase()
    requires(std::is_base_of_v<QuicEventBase, T>)
  {
    auto evb = dynamic_cast<T*>(this);
    if (evb) {
      return evb;
    } else {
      MVLOG_WARNING << "Failed to cast QuicEventBase to " << typeid(T).name();
      return nullptr;
    }
  }

  static void setImplHandle(
      QuicEventBaseLoopCallback* callback,
      QuicEventBaseLoopCallback::LoopCallbackImpl* handle) {
    callback->implHandle = handle;
  }

  static QuicEventBaseLoopCallback::LoopCallbackImpl* getImplHandle(
      QuicEventBaseLoopCallback* callback) {
    return callback->implHandle;
  }

  static void setImplHandle(
      QuicTimerCallback* callback,
      QuicTimerCallback::TimerCallbackImpl* handle) {
    callback->implHandle = handle;
  }

  static QuicTimerCallback::TimerCallbackImpl* getImplHandle(
      QuicTimerCallback* callback) {
    return callback->implHandle;
  }
};

} // namespace quic
