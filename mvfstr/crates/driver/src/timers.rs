/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timers: one deadline per connection and the pacing wakes, kept by the endpoint, and the one
//! host wake it arms for the earliest of them.

use std::collections::BTreeSet;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use mvfstr_io::TimerFd;
use roxygen_runtime::host::Host;
use roxygen_runtime::host::timer::Timeout;

/// The tick of the Roxygen worker wheel in `roxygen_runtime::tokio_host`. Its wakeup is a Tokio
/// sleep, which rounds up to whole ticks, so a wheel timer may fire up to a tick late, never early.
const WHEEL_TICK: Duration = Duration::from_millis(1);

/// How far ahead of a pacing release the wheel wakes the endpoint so the timerfd can take the
/// rest: two ticks, so a wheel wake up to a tick late still comes before the release.
const PACING_LEAD: Duration = WHEEL_TICK.saturating_mul(2);

/// What a timer entry is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The connection's deadline: the earlier of its own and its session's.
    Deadline,
    /// A pacing release.
    Pacing,
}

/// Every connection's deadline and pacing release, by slot index.
#[derive(Debug, Default)]
pub(crate) struct Timers {
    deadlines: BTreeSet<(Instant, u32)>,
    pacing: BTreeSet<(Instant, u32)>,
}

impl Timers {
    /// Moves slot `index`'s entry of `kind` from `old` to `new`.
    pub(crate) fn set(
        &mut self,
        kind: Kind,
        index: u32,
        old: Option<Instant>,
        new: Option<Instant>,
    ) {
        if old == new {
            return;
        }
        let set = self.set_of(kind);
        if let Some(old) = old {
            set.remove(&(old, index));
        }
        if let Some(new) = new {
            set.insert((new, index));
        }
    }

    /// Returns the earliest entry of `kind`.
    pub(crate) fn next(&self, kind: Kind) -> Option<Instant> {
        let set = match kind {
            Kind::Deadline => &self.deadlines,
            Kind::Pacing => &self.pacing,
        };
        set.first().map(|&(at, _)| at)
    }

    /// Removes the earliest entry of `kind` if it is due at `now`, and returns its slot.
    pub(crate) fn pop_due(&mut self, kind: Kind, now: Instant) -> Option<u32> {
        let set = self.set_of(kind);
        let &(at, index) = set.first()?;
        if at > now {
            return None;
        }
        set.pop_first();
        Some(index)
    }

    fn set_of(&mut self, kind: Kind) -> &mut BTreeSet<(Instant, u32)> {
        match kind {
            Kind::Deadline => &mut self.deadlines,
            Kind::Pacing => &mut self.pacing,
        }
    }
}

/// How the host wake is armed for the earliest timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// The timers are empty.
    Idle,
    /// A timer is due already.
    Now,
    /// The worker wheel, at this time.
    Wheel(Instant),
    /// The timerfd, at this time.
    Fine(Instant),
}

/// Chooses how to wake at the earlier of `deadline` and the pacing release `pacing`. Deadlines
/// tolerate the wheel's tick; a pacing release does not, so the wheel brings it within
/// [`PACING_LEAD`] and the timerfd fires at the release itself.
fn plan(now: Instant, deadline: Option<Instant>, pacing: Option<Instant>) -> Arm {
    let Some(target) = deadline.into_iter().chain(pacing).min() else {
        return Arm::Idle;
    };
    if target <= now {
        return Arm::Now;
    }
    match pacing {
        Some(release) if release - now <= PACING_LEAD => Arm::Fine(target),
        Some(release) => Arm::Wheel(target.min(release - PACING_LEAD)),
        None => Arm::Wheel(target),
    }
}

/// The endpoint's one host wake: a Roxygen [`Timeout`] on the worker's wheel for the earliest
/// timer, and a timerfd for the last stretch before a pacing release, so pacing wakes have
/// sub-millisecond resolution. Each may fire late but never early.
pub(crate) struct HostWake {
    wheel: Timeout,
    /// `None` if the timerfd could not be created; pacing wakes then round up to the wheel's tick.
    fine: Option<TimerFd>,
}

impl HostWake {
    pub(crate) fn new(host: &Host) -> Self {
        Self {
            wheel: Timeout::new(host),
            fine: TimerFd::new().ok(),
        }
    }

    /// Arms the wake for the earlier of `deadline` and the pacing release `pacing`, and
    /// registers `cx` for it. Returns `Ready` if either has passed at `now`, so the caller runs
    /// another turn instead of waiting for a wake.
    pub(crate) fn arm(
        &mut self,
        now: Instant,
        deadline: Option<Instant>,
        pacing: Option<Instant>,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        // Expiries are taken first, since rescheduling would discard them. Both clocks are the
        // host's monotonic clock, so a timer that fired for a target still set has its target at
        // or before `now`; an expiry ahead of every target, such as the wheel's early wake for a
        // pacing release, does not need a turn.
        let _ = self.wheel.poll_expired(cx);
        if let Some(fine) = self.fine.as_mut() {
            let _ = fine.poll_expired(cx);
        }
        match plan(now, deadline, pacing) {
            Arm::Idle => {
                self.disarm();
                Poll::Pending
            }
            Arm::Now => {
                self.disarm();
                Poll::Ready(())
            }
            Arm::Fine(target) => {
                if let Some(fine) = self.fine.as_mut()
                    && (fine.deadline() == Some(target) || fine.arm(target).is_ok())
                {
                    self.wheel.cancel();
                    return fine.poll_expired(cx);
                }
                // Without a timerfd the release rounds up to the wheel's tick.
                self.wheel_at(target, cx)
            }
            Arm::Wheel(target) => self.wheel_at(target, cx),
        }
    }

    /// Arms the wheel alone for `target`.
    fn wheel_at(&mut self, target: Instant, cx: &mut Context<'_>) -> Poll<()> {
        self.disarm_fine();
        if self.wheel.deadline() != Some(target) {
            self.wheel.schedule_at(target, cx.waker());
        }
        self.wheel.poll_expired(cx).map(drop)
    }

    fn disarm(&mut self) {
        self.wheel.cancel();
        self.disarm_fine();
    }

    fn disarm_fine(&mut self) {
        if let Some(fine) = self.fine.as_mut() {
            // A timerfd that cannot be disarmed fires once more, which costs a spurious turn.
            let _ = fine.disarm();
        }
    }

    /// Returns the release the timerfd is armed for.
    #[cfg(test)]
    fn fine_deadline(&self) -> Option<Instant> {
        self.fine.as_ref().and_then(TimerFd::deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn entries_come_due_in_time_order_and_only_once_due() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut timers = Timers::default();
        timers.set(Kind::Deadline, 1, None, Some(t + ms(10)));
        timers.set(Kind::Deadline, 2, None, Some(t + ms(5)));
        timers.set(Kind::Deadline, 3, None, Some(t + ms(10)));
        timers.set(Kind::Pacing, 1, None, Some(t + Duration::from_micros(200)));
        assert_eq!(timers.next(Kind::Deadline), Some(t + ms(5)));
        assert_eq!(
            timers.next(Kind::Pacing),
            Some(t + Duration::from_micros(200)),
            "pacing wakes are kept apart from deadlines"
        );

        timers.set(Kind::Deadline, 2, Some(t + ms(5)), Some(t + ms(20)));
        assert_eq!(
            timers.next(Kind::Deadline),
            Some(t + ms(10)),
            "a moved entry leaves its old time"
        );

        assert_eq!(
            timers.pop_due(Kind::Deadline, t + ms(9)),
            None,
            "nothing is due before its time"
        );
        assert_eq!(
            timers.pop_due(Kind::Deadline, t + ms(10)),
            Some(1),
            "the earliest first"
        );
        assert_eq!(timers.pop_due(Kind::Deadline, t + ms(10)), Some(3));
        assert_eq!(
            timers.pop_due(Kind::Deadline, t + ms(10)),
            None,
            "a popped entry is gone"
        );
        assert_eq!(timers.next(Kind::Deadline), Some(t + ms(20)));

        timers.set(Kind::Pacing, 1, Some(t + Duration::from_micros(200)), None);
        assert_eq!(timers.next(Kind::Pacing), None, "a cleared entry is gone");
    }

    #[test]
    fn a_pacing_release_a_tick_or_more_away_wakes_early_on_the_wheel_and_ends_on_the_timerfd() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let release = t + ms(5);
        let Arm::Wheel(early) = plan(t, None, Some(release)) else {
            panic!("a distant release starts on the wheel");
        };
        assert!(
            early < release && release - early >= WHEEL_TICK,
            "the wheel wakes at least a tick ahead of the release, so its tick does not make the \
             release late: {:?} ahead",
            release.saturating_duration_since(early)
        );
        assert_eq!(
            plan(early, None, Some(release)),
            Arm::Fine(release),
            "the early wake hands the release to the timerfd"
        );
        assert_eq!(
            plan(t, None, Some(t + Duration::from_micros(300))),
            Arm::Fine(t + Duration::from_micros(300)),
            "a release under a tick away goes to the timerfd at once"
        );
        assert_eq!(
            plan(t, Some(t + ms(1)), Some(release)),
            Arm::Wheel(t + ms(1)),
            "an earlier deadline comes first"
        );
        assert_eq!(
            plan(t, Some(t + ms(4)), None),
            Arm::Wheel(t + ms(4)),
            "deadlines alone use the wheel"
        );
        assert_eq!(plan(release, None, Some(release)), Arm::Now);
        assert_eq!(plan(t, None, None), Arm::Idle);
    }

    /// Runs `body` on a Roxygen worker and returns what it sends back.
    fn on_worker<T: Send + 'static>(
        body: impl FnOnce(
            &roxygen_runtime::worker::WorkerContext,
        ) -> std::pin::Pin<Box<dyn Future<Output = T>>>
        + Send
        + 'static,
    ) -> T {
        let worker = roxygen_runtime::tokio_host::ManagedWorker::new(16).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        worker
            .handle()
            .spawn_local(move |context| async move {
                let _ = tx.send(body(&context).await);
            })
            .unwrap();
        let out = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the worker finishes");
        worker.shutdown().unwrap();
        out
    }

    #[test]
    fn a_pacing_release_under_a_tick_arms_the_timerfd_and_no_wake_fires_early() {
        let (armed_fine, release, pacing_fired, deadline, deadline_fired) = on_worker(|context| {
            let host = context.host().clone();
            Box::pin(async move {
                let mut wake = HostWake::new(&host);
                let release = host.now() + Duration::from_micros(300);
                let mut armed_fine = None;
                let pacing_fired = std::future::poll_fn(|cx| {
                    let now = host.now();
                    match wake.arm(now, None, Some(release), cx) {
                        Poll::Ready(()) => Poll::Ready(now),
                        Poll::Pending => {
                            armed_fine = armed_fine.or(wake.fine_deadline());
                            Poll::Pending
                        }
                    }
                })
                .await;

                let deadline = host.now() + Duration::from_millis(3);
                let deadline_fired = std::future::poll_fn(|cx| {
                    let now = host.now();
                    match wake.arm(now, Some(deadline), None, cx) {
                        Poll::Ready(()) => Poll::Ready(now),
                        Poll::Pending => {
                            assert_eq!(wake.fine_deadline(), None, "deadlines use the wheel");
                            Poll::Pending
                        }
                    }
                })
                .await;
                (armed_fine, release, pacing_fired, deadline, deadline_fired)
            })
        });
        assert_eq!(
            armed_fine,
            Some(release),
            "a release under a tick away arms the timerfd"
        );
        assert!(pacing_fired >= release, "the pacing wake fired early");
        assert!(deadline_fired >= deadline, "the deadline wake fired early");
    }
}
