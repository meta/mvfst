/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timers: one deadline per connection and the pacing wakes, kept by the endpoint, and the one
//! host wake it arms for the earliest of them. Deadlines and the pacing wakes of connections that
//! build at least two wheel ticks ahead go on the wheel; other pacing wakes go on the wheel until
//! shortly before they are due, then on the timerfd.

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
    /// A pacing wake of a connection that builds less than [`PACING_LEAD`] ahead of a release:
    /// it must not be late, so the timerfd takes its last stretch.
    Pacing,
    /// A pacing wake of a connection that builds at least [`PACING_LEAD`] ahead of a release:
    /// the wheel fires at it, at most a tick late, which the build horizon absorbs.
    Coarse,
}

impl Kind {
    /// Returns the kind of pacing wake for a connection with build horizon `horizon`, fixed for
    /// its life.
    pub(crate) fn pacing(horizon: Duration) -> Self {
        // At PACING_LEAD or more, the wheel's lateness, under a tick, stays inside the horizon,
        // and each wake builds about a tick of runs. `horizon` is the connection's own, which may
        // be shorter than its endpoint's, to keep its advertised max_ack_delay in range, or zero.
        if horizon >= PACING_LEAD {
            Kind::Coarse
        } else {
            Kind::Pacing
        }
    }
}

/// Every connection's deadline and pacing wake, by slot index.
#[derive(Debug, Default)]
pub(crate) struct Timers {
    deadlines: BTreeSet<(Instant, u32)>,
    pacing: BTreeSet<(Instant, u32)>,
    coarse: BTreeSet<(Instant, u32)>,
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
            Kind::Coarse => &self.coarse,
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
            Kind::Coarse => &mut self.coarse,
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
    /// The worker wheel at `wheel`, for a coarse pacing wake, and the timerfd at the later `fine`.
    Both { wheel: Instant, fine: Instant },
}

/// Chooses how to wake at the earliest of `deadline`, the pacing wake `pacing` and the coarse
/// pacing wake `coarse`. Deadlines tolerate the wheel's tick; a pacing wake does not, so the
/// wheel brings it within [`PACING_LEAD`] and the timerfd fires at the wake itself. A coarse
/// wake stays on the wheel even while the timerfd holds another connection's pacing wake.
fn plan(
    now: Instant,
    deadline: Option<Instant>,
    pacing: Option<Instant>,
    coarse: Option<Instant>,
) -> Arm {
    // A coarse pacing wake tolerates the wheel's tick, as a deadline does.
    let wheel = deadline.into_iter().chain(coarse).min();
    let Some(target) = wheel.into_iter().chain(pacing).min() else {
        return Arm::Idle;
    };
    if target <= now {
        return Arm::Now;
    }
    match pacing {
        Some(release) if release - now <= PACING_LEAD => {
            let fine = deadline.map_or(release, |deadline| deadline.min(release));
            match coarse {
                // On the timerfd it would fire at its exact time and build a single run, as at
                // build horizon 0.
                Some(coarse) if coarse < fine => Arm::Both {
                    wheel: coarse,
                    fine,
                },
                _ => Arm::Fine(fine),
            }
        }
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
    /// How many times `arm` chose the timerfd for a pacing wake.
    #[cfg(test)]
    fine_plans: u32,
}

impl HostWake {
    pub(crate) fn new(host: &Host) -> Self {
        Self {
            wheel: Timeout::new(host),
            fine: TimerFd::new().ok(),
            #[cfg(test)]
            fine_plans: 0,
        }
    }

    /// Arms the wake for the earliest of `deadline`, the pacing wake `pacing` and the coarse
    /// pacing wake `coarse` (see [`Kind`]), and registers `cx` for it. Returns `Ready` if any has
    /// passed at `now`, so the caller runs another turn instead of waiting for a wake.
    pub(crate) fn arm(
        &mut self,
        now: Instant,
        deadline: Option<Instant>,
        pacing: Option<Instant>,
        coarse: Option<Instant>,
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
        let arm = plan(now, deadline, pacing, coarse);
        #[cfg(test)]
        if matches!(arm, Arm::Fine(_) | Arm::Both { .. }) {
            self.fine_plans += 1;
        }
        match arm {
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
            Arm::Both {
                wheel,
                fine: target,
            } => {
                if let Some(fine) = self.fine.as_mut()
                    && (fine.deadline() == Some(target) || fine.arm(target).is_ok())
                {
                    if self.wheel.deadline() != Some(wheel) {
                        self.wheel.schedule_at(wheel, cx.waker());
                    }
                    let wheel_fired = self.wheel.poll_expired(cx).is_ready();
                    let fine_fired = fine.poll_expired(cx).is_ready();
                    return if wheel_fired || fine_fired {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    };
                }
                // Without a timerfd the wheel takes the earlier of the two.
                self.wheel_at(wheel, cx)
            }
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

    /// Returns the time the wheel is armed for.
    #[cfg(test)]
    fn wheel_deadline(&self) -> Option<Instant> {
        self.wheel.deadline()
    }

    /// Returns how many times the wake chose the timerfd for a pacing wake.
    #[cfg(test)]
    pub(crate) fn fine_plans(&self) -> u32 {
        self.fine_plans
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
        let Arm::Wheel(early) = plan(t, None, Some(release), None) else {
            panic!("a distant release starts on the wheel");
        };
        assert!(
            early < release && release - early >= WHEEL_TICK,
            "the wheel wakes at least a tick ahead of the release, so its tick does not make the \
             release late: {:?} ahead",
            release.saturating_duration_since(early)
        );
        assert_eq!(
            plan(early, None, Some(release), None),
            Arm::Fine(release),
            "the early wake hands the release to the timerfd"
        );
        assert_eq!(
            plan(t, None, Some(t + Duration::from_micros(300)), None),
            Arm::Fine(t + Duration::from_micros(300)),
            "a release under a tick away goes to the timerfd at once"
        );
        assert_eq!(
            plan(t, Some(t + ms(1)), Some(release), None),
            Arm::Wheel(t + ms(1)),
            "an earlier deadline comes first"
        );
        assert_eq!(
            plan(t, Some(t + ms(4)), None, None),
            Arm::Wheel(t + ms(4)),
            "deadlines alone use the wheel"
        );
        assert_eq!(plan(release, None, Some(release), None), Arm::Now);
        assert_eq!(plan(t, None, None, None), Arm::Idle);
    }

    /// Returns how the endpoint wakes at `now` for the pacing wakes in `timers`, without deadlines.
    fn plan_pacing(now: Instant, timers: &Timers) -> Arm {
        plan(
            now,
            None,
            timers.next(Kind::Pacing),
            timers.next(Kind::Coarse),
        )
    }

    #[test]
    fn a_connection_building_two_ticks_ahead_wakes_on_the_wheel_at_its_pacing_wake() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        // `pacing_at` is already the release less the connection's horizon.
        let pacing_at = t + ms(6);
        for horizon in [ms(2), ms(5)] {
            let mut timers = Timers::default();
            timers.set(Kind::pacing(horizon), 1, None, Some(pacing_at));
            assert_eq!(
                plan_pacing(t, &timers),
                Arm::Wheel(pacing_at),
                "H_conn {horizon:?}: the wheel at the wake itself, no lead"
            );
            assert_eq!(
                plan_pacing(pacing_at - Duration::from_micros(300), &timers),
                Arm::Wheel(pacing_at),
                "H_conn {horizon:?}: no timerfd however close the wake"
            );
            assert_eq!(plan_pacing(pacing_at, &timers), Arm::Now);
        }

        // Connections on the same endpoint that build less than two ticks ahead, zero included,
        // keep the timerfd path for their own wakes.
        for horizon in [Duration::ZERO, ms(1), ms(2) - Duration::from_nanos(1)] {
            let mut timers = Timers::default();
            timers.set(Kind::pacing(ms(5)), 1, None, Some(pacing_at + ms(20)));
            timers.set(Kind::pacing(horizon), 2, None, Some(pacing_at));
            assert_eq!(
                plan_pacing(t, &timers),
                Arm::Wheel(pacing_at - PACING_LEAD),
                "H_conn {horizon:?}: the wheel brings the wake within the lead"
            );
            assert_eq!(
                plan_pacing(pacing_at - ms(1), &timers),
                Arm::Fine(pacing_at),
                "H_conn {horizon:?}: the timerfd fires at the wake"
            );
        }
    }

    #[test]
    fn a_coarse_wake_before_another_connections_imminent_pacing_wake_stays_on_the_wheel() {
        let t = Instant::now();
        let us = Duration::from_micros;
        let ms = Duration::from_millis;
        let mut timers = Timers::default();
        timers.set(Kind::pacing(ms(5)), 1, None, Some(t + us(300)));
        timers.set(Kind::pacing(Duration::ZERO), 2, None, Some(t + ms(1)));
        assert_eq!(
            plan_pacing(t, &timers),
            Arm::Both {
                wheel: t + us(300),
                fine: t + ms(1),
            },
            "the timerfd takes only the imminent pacing wake"
        );
        assert_eq!(
            plan(t, None, Some(t + us(300)), Some(t + ms(1))),
            Arm::Fine(t + us(300)),
            "a coarse wake after the imminent pacing wake waits for the next plan"
        );
        assert_eq!(
            plan(t, Some(t + us(300)), Some(t + ms(1)), None),
            Arm::Fine(t + us(300)),
            "a deadline before an imminent pacing wake still takes the timerfd"
        );
        assert_eq!(
            plan(t, Some(t + us(200)), Some(t + ms(1)), Some(t + us(300))),
            Arm::Fine(t + us(200)),
            "an earlier deadline comes first"
        );
        assert_eq!(
            plan(t, Some(t + us(500)), Some(t + ms(1)), Some(t + us(300))),
            Arm::Both {
                wheel: t + us(300),
                fine: t + us(500),
            },
            "a deadline between the two takes the timerfd"
        );
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
                    match wake.arm(now, None, Some(release), None, cx) {
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
                    match wake.arm(now, Some(deadline), None, None, cx) {
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

    #[test]
    fn a_coarse_wake_waits_on_the_wheel_while_the_timerfd_holds_an_imminent_pacing_wake() {
        let (armed, coarse, pacing, fired) = on_worker(|context| {
            let host = context.host().clone();
            Box::pin(async move {
                let mut wake = HostWake::new(&host);
                let start = host.now();
                let coarse = start + Duration::from_micros(1500);
                let pacing = start + PACING_LEAD;
                let mut armed = None;
                let fired = std::future::poll_fn(|cx| {
                    let now = host.now();
                    match wake.arm(now, None, Some(pacing), Some(coarse), cx) {
                        Poll::Ready(()) => Poll::Ready(now),
                        Poll::Pending => {
                            armed = armed.or(Some((wake.wheel_deadline(), wake.fine_deadline())));
                            Poll::Pending
                        }
                    }
                })
                .await;
                (armed, coarse, pacing, fired)
            })
        });
        assert_eq!(
            armed,
            Some((Some(coarse), Some(pacing))),
            "the wheel at the coarse wake, the timerfd at the pacing wake"
        );
        assert!(fired >= coarse, "the coarse wake fired early");
    }
}
