/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A one-shot timer on a timerfd, for wakes finer than the Roxygen worker wheel's 1 ms tick: the
//! endpoint driver arms it for pacing releases less than a tick away.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;
use std::time::Instant;

use tokio::io::unix::AsyncFd;

/// A one-shot timer that never fires before its deadline, with the resolution of the kernel's
/// high-resolution timers. Readiness comes from tokio's `AsyncFd`, so it must be created on a
/// thread running a tokio runtime with I/O enabled, such as a Roxygen worker.
pub struct TimerFd {
    io: AsyncFd<OwnedFd>,
    deadline: Option<Instant>,
}

impl TimerFd {
    /// Creates a disarmed timer. Fails when the thread is not running a tokio runtime.
    pub fn new() -> io::Result<Self> {
        // Registering with the reactor panics without a runtime, so return an error instead.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "TimerFd needs a tokio runtime with I/O enabled on this thread",
            ));
        }
        // SAFETY: plain system call with constant flags.
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: `fd` owns its descriptor, which stays open until the `AsyncFd` drops it, and
        // `as_raw_fd` always returns that descriptor.
        let io = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self { io, deadline: None })
    }

    /// Arms the timer for `deadline`, replacing any earlier arming. A deadline already past
    /// fires at once.
    pub fn arm(&mut self, deadline: Instant) -> io::Result<()> {
        // A relative arming runs from the system call, which follows this clock read, so the
        // expiry is no earlier than `deadline`. A zero delay disarms, so a past deadline arms 1 ns.
        let delay = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_nanos(1));
        self.settime(delay)?;
        self.deadline = Some(deadline);
        Ok(())
    }

    /// Disarms the timer and discards an expiry not yet observed.
    pub fn disarm(&mut self) -> io::Result<()> {
        if self.deadline.take().is_some() {
            self.settime(Duration::ZERO)?;
        }
        Ok(())
    }

    /// Returns the deadline the timer is armed for, until its expiry is observed.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Polls for the expiry: ready once the armed deadline has passed, which disarms the timer,
    /// and otherwise registers `cx` for the expiry. Pending while disarmed, without registering.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.deadline.is_none() {
            return Poll::Pending;
        }
        loop {
            let Ok(mut guard) = ready!(self.io.poll_read_ready(cx)) else {
                // The reactor is gone and cannot wake this timer again.
                return Poll::Pending;
            };
            let read = guard.try_io(|io| {
                let mut expirations = [0u8; 8];
                // SAFETY: the kernel writes at most 8 bytes, the size of `expirations`.
                let n = unsafe {
                    libc::read(
                        io.get_ref().as_raw_fd(),
                        expirations.as_mut_ptr().cast(),
                        expirations.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            // An error other than WouldBlock means the descriptor is unusable; reporting the
            // expiry keeps the owner from waiting forever, and it re-reads its clock anyway.
            if read.is_ok() {
                self.deadline = None;
                return Poll::Ready(());
            }
        }
    }

    /// Arms the timer `delay` from now; a zero `delay` disarms it.
    fn settime(&self, delay: Duration) -> io::Result<()> {
        let value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: delay.as_secs() as libc::time_t,
                tv_nsec: delay.subsec_nanos() as libc::c_long,
            },
        };
        // SAFETY: `value` is a live `itimerspec`; a null old value is allowed.
        let rc = unsafe {
            libc::timerfd_settime(
                self.io.get_ref().as_raw_fd(),
                0,
                &raw const value,
                std::ptr::null_mut(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::time::Duration;

    use super::*;

    /// Fails a test that would otherwise hang; passing runs never reach it.
    const HANG_GUARD: Duration = Duration::from_secs(20);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[test]
    fn without_a_tokio_runtime_creating_a_timer_fails() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        assert!(TimerFd::new().is_err());
    }

    #[test]
    fn fires_no_earlier_than_its_deadline() {
        runtime().block_on(async {
            let mut timer = TimerFd::new().unwrap();
            for micros in [0, 50, 300, 900, 2_500] {
                let deadline = Instant::now() + Duration::from_micros(micros);
                timer.arm(deadline).unwrap();
                assert_eq!(timer.deadline(), Some(deadline));
                tokio::time::timeout(HANG_GUARD, poll_fn(|cx| timer.poll_expired(cx)))
                    .await
                    .expect("the timer fires");
                assert!(Instant::now() >= deadline, "fired early for {micros} us");
                assert_eq!(timer.deadline(), None);
            }
        });
    }

    #[test]
    fn a_disarmed_timer_does_not_fire_and_a_rearmed_one_keeps_only_its_new_deadline() {
        runtime().block_on(async {
            let mut timer = TimerFd::new().unwrap();
            timer
                .arm(Instant::now() + Duration::from_micros(200))
                .unwrap();
            timer.disarm().unwrap();
            assert_eq!(timer.deadline(), None);
            // A later timer bounds the wait: the disarmed one must stay quiet past its deadline.
            let mut witness = TimerFd::new().unwrap();
            witness
                .arm(Instant::now() + Duration::from_millis(5))
                .unwrap();
            let first = poll_fn(|cx| match timer.poll_expired(cx) {
                Poll::Ready(()) => Poll::Ready(false),
                Poll::Pending => witness.poll_expired(cx).map(|()| true),
            });
            assert!(
                tokio::time::timeout(HANG_GUARD, first).await.unwrap(),
                "the disarmed timer fired"
            );

            let early = Instant::now() + Duration::from_micros(100);
            timer.arm(early).unwrap();
            let late = Instant::now() + Duration::from_millis(3);
            timer.arm(late).unwrap();
            tokio::time::timeout(HANG_GUARD, poll_fn(|cx| timer.poll_expired(cx)))
                .await
                .expect("the timer fires");
            assert!(Instant::now() >= late, "fired at the replaced deadline");
        });
    }
}
