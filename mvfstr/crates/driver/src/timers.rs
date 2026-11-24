/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timers: one deadline per connection and the pacing wakes, kept by the endpoint, and the one
//! host wake it arms for the earliest of them. Deadlines and the pacing wakes of connections that
//! build at least two wheel ticks ahead go on the wheel; other pacing wakes go on the wheel until
//! shortly before they are due, then on the host's fine timer.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
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

/// A one-shot timer finer than the host's wheel, which the endpoint driver arms for the last
/// stretch before a pacing release. It must never fire before its deadline.
pub trait FineTimer {
    /// Arms the timer for `deadline`, replacing any earlier arming. If `deadline` has passed, the
    /// timer fires at once. On an error the driver puts the wake on the wheel instead.
    fn arm(&mut self, deadline: Instant) -> io::Result<()>;

    /// Disarms the timer and discards an expiry not yet observed. A timer that cannot be disarmed
    /// may fire once more, which costs the driver a spurious turn.
    fn disarm(&mut self);

    /// Returns the deadline the timer is armed for, until its expiry is observed.
    fn deadline(&self) -> Option<Instant>;

    /// Polls for the expiry: ready once the armed deadline has passed, which disarms the timer,
    /// and otherwise registers `cx` for the expiry. Pending while disarmed, without registering.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

impl FineTimer for TimerFd {
    fn arm(&mut self, deadline: Instant) -> io::Result<()> {
        TimerFd::arm(self, deadline)
    }

    fn disarm(&mut self) {
        let _ = TimerFd::disarm(self);
    }

    fn deadline(&self) -> Option<Instant> {
        TimerFd::deadline(self)
    }

    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        TimerFd::poll_expired(self, cx)
    }
}

/// The timers a host gives an endpoint driver's wake: the tick of the wheel behind its Roxygen
/// [`Timeout`]s (the resolution of its sleeps on a host without a wheel), which fire up to a tick
/// late but never early, and optionally a [`FineTimer`] for pacing wakes. Without a fine timer,
/// pacing wakes round up to the wheel.
pub struct HostTimers {
    wheel_tick: Duration,
    fine: Option<Box<dyn FineTimer>>,
}

impl HostTimers {
    /// Creates the timers of a host whose wheel ticks every `wheel_tick`, with `fine` for pacing
    /// wakes.
    pub fn new(wheel_tick: Duration, fine: Option<Box<dyn FineTimer>>) -> Self {
        Self { wheel_tick, fine }
    }

    /// Returns the timers of a Roxygen worker on Tokio: its 1 ms wheel, and a timerfd if the thread
    /// runs a Tokio runtime with I/O enabled.
    pub fn tokio() -> Self {
        Self::new(
            WHEEL_TICK,
            TimerFd::new()
                .ok()
                .map(|timer| Box::new(timer) as Box<dyn FineTimer>),
        )
    }
}

impl fmt::Debug for HostTimers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostTimers")
            .field("wheel_tick", &self.wheel_tick)
            .field("fine", &self.fine.is_some())
            .finish()
    }
}

/// Returns how far ahead of a pacing release a wheel ticking every `tick` wakes the endpoint so
/// the fine timer can take the rest: two ticks, so a wheel wake up to a tick late still comes
/// before the release.
fn lead(tick: Duration) -> Duration {
    tick.saturating_mul(2)
}

/// What a timer entry is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The connection's deadline: the earlier of its own and its session's.
    Deadline,
    /// A pacing wake of a connection that builds less than the [`lead`] ahead of a release: it
    /// must not be late, so the fine timer takes its last stretch.
    Pacing,
    /// A pacing wake of a connection that builds at least the [`lead`] ahead of a release: the
    /// wheel fires at it, at most a tick late, which the build horizon absorbs.
    Coarse,
}

impl Kind {
    /// Returns the kind of pacing wake for a connection with build horizon `horizon`, fixed for
    /// its life, where `lead` is the [`lead`] of the host's wheel.
    fn pacing(horizon: Duration, lead: Duration) -> Self {
        // At the lead or more, the wheel's lateness, under a tick, stays inside the horizon, and
        // each wake builds about a tick of runs. `horizon` is the connection's own, which may be
        // shorter than its endpoint's, to keep its advertised max_ack_delay in range, or zero.
        if horizon >= lead {
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

    /// Returns the earliest pacing wake, of either pacing kind.
    pub(crate) fn next_pacing(&self) -> Option<Instant> {
        self.pacing
            .first()
            .into_iter()
            .chain(self.coarse.first())
            .map(|&(at, _)| at)
            .min()
    }

    /// Removes the earliest pacing wake, of either pacing kind, if it is due at `now`, and returns
    /// its slot.
    pub(crate) fn pop_due_pacing(&mut self, now: Instant) -> Option<u32> {
        let kind = match (self.pacing.first(), self.coarse.first()) {
            (Some(pacing), Some(coarse)) if coarse < pacing => Kind::Coarse,
            (Some(_), _) => Kind::Pacing,
            (None, Some(_)) => Kind::Coarse,
            (None, None) => return None,
        };
        self.pop_due(kind, now)
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
    /// The fine timer, at this time.
    Fine(Instant),
    /// The worker wheel at `wheel`, for a coarse pacing wake, and the fine timer at the later
    /// `fine`.
    Both { wheel: Instant, fine: Instant },
}

/// Chooses how to wake at the earliest of `deadline`, the pacing wake `pacing` and the coarse
/// pacing wake `coarse`. Deadlines tolerate the wheel's tick; a pacing wake does not, so the
/// wheel brings it within `lead` and the fine timer fires at the wake itself. A coarse wake
/// stays on the wheel even while the fine timer holds another connection's pacing wake.
fn plan(
    lead: Duration,
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
        Some(release) if release - now <= lead => {
            let fine = deadline.map_or(release, |deadline| deadline.min(release));
            match coarse {
                // On the fine timer it would fire at its exact time and build a single run, as at
                // build horizon 0.
                Some(coarse) if coarse < fine => Arm::Both {
                    wheel: coarse,
                    fine,
                },
                _ => Arm::Fine(fine),
            }
        }
        Some(release) => Arm::Wheel(target.min(release - lead)),
        None => Arm::Wheel(target),
    }
}

/// The endpoint's one host wake: a Roxygen [`Timeout`] on the worker's wheel for the earliest
/// timer, and the host's fine timer for the last stretch before a pacing release, so pacing wakes
/// do not round up to the wheel's tick. Each may fire late but never early.
pub(crate) struct HostWake {
    wheel: Timeout,
    /// `None` if the host lacks a fine timer; pacing wakes then round up to the wheel's tick.
    fine: Option<Box<dyn FineTimer>>,
    /// The [`lead`] of the host's wheel.
    lead: Duration,
    /// How many times `arm` chose the fine timer for a pacing wake.
    #[cfg(test)]
    fine_plans: u32,
}

impl HostWake {
    pub(crate) fn new(host: &Host, timers: HostTimers) -> Self {
        Self {
            wheel: Timeout::new(host),
            fine: timers.fine,
            lead: lead(timers.wheel_tick),
            #[cfg(test)]
            fine_plans: 0,
        }
    }

    /// Returns the kind of pacing wake for a connection with build horizon `horizon`, fixed for
    /// its life.
    pub(crate) fn pacing_kind(&self, horizon: Duration) -> Kind {
        Kind::pacing(horizon, self.lead)
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
        // Without a fine timer every pacing wake rounds up to the wheel, as a coarse one does, and
        // the wheel does not wake early to hand it over.
        let (pacing, coarse) = match self.fine {
            Some(_) => (pacing, coarse),
            None => (None, pacing.into_iter().chain(coarse).min()),
        };
        let arm = plan(self.lead, now, deadline, pacing, coarse);
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
                // If the fine timer cannot be armed, the release rounds up to the wheel's tick.
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
                // If the fine timer cannot be armed, the wheel takes the earlier of the two.
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
            fine.disarm();
        }
    }

    /// Returns the release the fine timer is armed for.
    #[cfg(test)]
    fn fine_deadline(&self) -> Option<Instant> {
        self.fine.as_ref().and_then(|fine| fine.deadline())
    }

    /// Returns the time the wheel is armed for.
    #[cfg(test)]
    fn wheel_deadline(&self) -> Option<Instant> {
        self.wheel.deadline()
    }

    /// Returns how many times the wake chose the fine timer for a pacing wake.
    #[cfg(test)]
    pub(crate) fn fine_plans(&self) -> u32 {
        self.fine_plans
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Wake;
    use std::task::Waker;
    use std::time::Duration;

    use roxygen_runtime::host::LocalFuture;
    use roxygen_runtime::host::LocalHost;
    use roxygen_runtime::host::timer::WheelTimer;
    use roxygen_runtime::host::timer::WheelWakeup;

    use super::*;

    /// The lead of a Roxygen worker on Tokio.
    const LEAD: Duration = WHEEL_TICK.saturating_mul(2);

    /// The wakeup of a [`TickHost`]'s wheel: the instant it is armed for.
    struct TickWakeup(Rc<Cell<Option<Instant>>>);

    impl WheelWakeup for TickWakeup {
        fn arm(&self, deadline: Instant) {
            self.0.set(Some(deadline));
        }

        fn disarm(&self) {
            self.0.set(None);
        }
    }

    /// What a [`TickHost`] gives Roxygen: its clock and its wheel.
    struct TickLocal {
        now: Rc<Cell<Instant>>,
        wheel: Rc<WheelTimer>,
    }

    impl LocalHost for TickLocal {
        fn spawn_local(&self, _future: LocalFuture) {
            panic!("the wake spawns nothing");
        }

        fn now(&self) -> Instant {
            self.now.get()
        }

        fn sleep_until(&self, _deadline: Instant) -> LocalFuture {
            panic!("timeouts take a slot on the wheel");
        }

        fn yield_to_io(&self) -> LocalFuture {
            panic!("the wake does not yield");
        }

        fn wheel_timer(&self) -> Option<Rc<WheelTimer>> {
            Some(Rc::clone(&self.wheel))
        }
    }

    /// A Roxygen host with a manual clock and without a Tokio runtime, whose wheel wakeup has the
    /// resolution of its tick: the wheel is expired only at whole ticks from the host's start.
    struct TickHost {
        host: Host,
        now: Rc<Cell<Instant>>,
        wheel: Rc<WheelTimer>,
        wakeup: Rc<Cell<Option<Instant>>>,
        start: Instant,
        tick: Duration,
    }

    impl TickHost {
        fn new(tick: Duration) -> Self {
            let start = Instant::now();
            let now = Rc::new(Cell::new(start));
            let wakeup = Rc::new(Cell::new(None));
            let wheel = WheelTimer::new(tick, start, Box::new(TickWakeup(Rc::clone(&wakeup))));
            let host = Host::new(Rc::new(TickLocal {
                now: Rc::clone(&now),
                wheel: Rc::clone(&wheel),
            }));
            Self {
                host,
                now,
                wheel,
                wakeup,
                start,
                tick,
            }
        }

        fn now(&self) -> Instant {
            self.now.get()
        }

        /// Moves the clock to `at`, between ticks, without expiring the wheel.
        fn set(&self, at: Instant) {
            assert!(at >= self.now(), "the clock does not go back");
            self.now.set(at);
        }

        /// Moves the clock tick by tick, expiring the wheel when its wakeup is due, until `done`
        /// holds, and returns the tick at which it did.
        fn tick_until(&self, done: impl Fn() -> bool) -> Instant {
            for _ in 0..1_000 {
                let ticks = self.now().duration_since(self.start).as_nanos() / self.tick.as_nanos();
                let next = self.start + self.tick * (u32::try_from(ticks).unwrap() + 1);
                self.now.set(next);
                if self.wakeup.get().is_some_and(|at| at <= next) {
                    self.wakeup.set(None);
                    self.wheel.expire(next);
                }
                if done() {
                    return next;
                }
            }
            panic!("nothing happened within 1000 ticks");
        }
    }

    #[derive(Default)]
    struct FineState {
        deadline: Option<Instant>,
        fired: bool,
        waker: Option<Waker>,
        arms: u32,
    }

    /// A host's fine timer that the test fires.
    #[derive(Clone, Default)]
    struct ManualFine(Rc<RefCell<FineState>>);

    impl ManualFine {
        /// Fires the timer if it is armed for `now` or earlier, as the host's timer would.
        fn fire_due(&self, now: Instant) {
            let waker = {
                let mut state = self.0.borrow_mut();
                if state.fired || state.deadline.is_none_or(|at| at > now) {
                    return;
                }
                state.fired = true;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn armed(&self) -> Option<Instant> {
            self.0.borrow().deadline
        }

        fn arms(&self) -> u32 {
            self.0.borrow().arms
        }
    }

    impl FineTimer for ManualFine {
        fn arm(&mut self, deadline: Instant) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            state.deadline = Some(deadline);
            state.fired = false;
            state.arms += 1;
            Ok(())
        }

        fn disarm(&mut self) {
            let mut state = self.0.borrow_mut();
            state.deadline = None;
            state.fired = false;
        }

        fn deadline(&self) -> Option<Instant> {
            self.0.borrow().deadline
        }

        fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            let mut state = self.0.borrow_mut();
            if state.deadline.is_none() {
                return Poll::Pending;
            }
            if state.fired {
                state.fired = false;
                state.deadline = None;
                return Poll::Ready(());
            }
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// A waker that counts its wakes.
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Wakes {
        fn take(&self) -> usize {
            self.0.swap(0, Ordering::SeqCst)
        }

        fn any(&self) -> bool {
            self.0.load(Ordering::SeqCst) > 0
        }
    }

    #[test]
    fn a_host_fine_timer_fires_pacing_wakes_and_never_early() {
        let tick = Duration::from_millis(1);
        let us = Duration::from_micros;
        let host = TickHost::new(tick);
        let fine = ManualFine::default();
        let mut wake = HostWake::new(
            &host.host,
            HostTimers::new(tick, Some(Box::new(fine.clone()))),
        );
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);

        let t = host.now();
        let release = t + us(300);
        assert!(wake.arm(t, None, Some(release), None, &mut cx).is_pending());
        assert_eq!(
            fine.armed(),
            Some(release),
            "a release under the lead goes to the host's fine timer"
        );
        assert_eq!(wake.wheel_deadline(), None, "and not to the wheel");
        host.set(release - us(1));
        fine.fire_due(host.now());
        assert_eq!(wakes.take(), 0, "no wake before the release");
        host.set(release);
        fine.fire_due(release);
        assert_eq!(
            wakes.take(),
            1,
            "the fine timer wakes the driver at the release"
        );
        assert!(
            wake.arm(release, None, Some(release), None, &mut cx)
                .is_ready()
        );

        let far = host.now() + us(5_000);
        assert!(
            wake.arm(host.now(), None, Some(far), None, &mut cx)
                .is_pending()
        );
        assert_eq!(fine.armed(), None, "a distant release starts on the wheel");
        let woke = host.tick_until(|| wakes.any());
        wakes.take();
        assert!(
            far - woke <= LEAD,
            "the wheel brings the release within the lead"
        );
        assert!(
            wake.arm(woke, None, Some(far), None, &mut cx).is_pending(),
            "the wheel's early wake needs no turn"
        );
        assert_eq!(
            fine.armed(),
            Some(far),
            "the early wake hands the release to the host's fine timer"
        );
        host.set(far - us(1));
        fine.fire_due(host.now());
        assert_eq!(wakes.take(), 0, "no wake before the release");
        host.set(far);
        fine.fire_due(far);
        assert_eq!(wakes.take(), 1);
        assert!(wake.arm(far, None, Some(far), None, &mut cx).is_ready());
        assert_eq!(fine.arms(), 2, "one arming per release");
    }

    #[test]
    fn without_a_fine_timer_pacing_wakes_round_up_to_the_wheel_and_never_come_early() {
        let tick = Duration::from_millis(1);
        let us = Duration::from_micros;
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        // A pacing wake of either kind, near or beyond the lead, from 300 us into a tick.
        for (pacing, coarse) in [
            (Some(us(300)), None),
            (Some(us(5_300)), None),
            (None, Some(us(5_300))),
            (Some(us(5_300)), Some(us(7_300))),
        ] {
            let host = TickHost::new(tick);
            let mut wake = HostWake::new(&host.host, HostTimers::new(tick, None));
            let t = host.now();
            let (pacing, coarse) = (pacing.map(|at| t + at), coarse.map(|at| t + at));
            let due = pacing.into_iter().chain(coarse).min().unwrap();
            wakes.take();
            assert!(wake.arm(t, None, pacing, coarse, &mut cx).is_pending());
            assert_eq!(
                wake.wheel_deadline(),
                Some(due),
                "{pacing:?} {coarse:?}: the wheel at the wake itself"
            );
            let woke = host.tick_until(|| wakes.any());
            assert!(
                woke >= due,
                "{pacing:?} {coarse:?}: woken early at {woke:?}"
            );
            assert!(
                woke - due < tick,
                "{pacing:?} {coarse:?}: woken later than the next tick"
            );
            assert!(wake.arm(woke, None, pacing, coarse, &mut cx).is_ready());
        }
    }

    #[test]
    fn the_lead_and_the_pacing_kinds_follow_the_hosts_wheel_tick() {
        let ms = Duration::from_millis;
        let tick = ms(4);
        let host = TickHost::new(tick);
        let fine = ManualFine::default();
        let mut wake = HostWake::new(
            &host.host,
            HostTimers::new(tick, Some(Box::new(fine.clone()))),
        );
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let t = host.now();
        assert!(
            wake.arm(t, None, Some(t + ms(6)), None, &mut cx)
                .is_pending()
        );
        assert_eq!(
            fine.armed(),
            Some(t + ms(6)),
            "a release within two of the host's ticks goes to the fine timer at once"
        );
        assert_eq!(wake.wheel_deadline(), None);
        assert!(
            wake.arm(t, None, Some(t + ms(20)), None, &mut cx)
                .is_pending()
        );
        assert_eq!(
            wake.wheel_deadline(),
            Some(t + ms(12)),
            "the wheel wakes two of the host's ticks ahead of a distant release"
        );
        assert_eq!(fine.armed(), None);
        assert_eq!(
            wake.pacing_kind(ms(5)),
            Kind::Pacing,
            "a connection building less than two of the host's ticks ahead keeps the fine timer"
        );
        assert_eq!(wake.pacing_kind(ms(8)), Kind::Coarse);

        let host = TickHost::new(ms(1));
        let wake = HostWake::new(&host.host, HostTimers::new(ms(1), None));
        assert_eq!(wake.pacing_kind(ms(2)), Kind::Coarse, "two 1 ms ticks");
        assert_eq!(
            wake.pacing_kind(ms(2) - Duration::from_nanos(1)),
            Kind::Pacing
        );
    }

    #[test]
    fn the_tokio_timers_build_no_timerfd_on_a_thread_without_a_reactor() {
        // A unit test's thread does not run a Tokio runtime, and a custom Roxygen host's need not.
        let timers = HostTimers::tokio();
        assert!(timers.fine.is_none(), "a timerfd without a reactor");
        let host = TickHost::new(WHEEL_TICK);
        let mut wake = HostWake::new(&host.host, timers);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let release = host.now() + Duration::from_micros(300);
        assert!(
            wake.arm(host.now(), None, Some(release), None, &mut cx)
                .is_pending()
        );
        assert_eq!(
            wake.wheel_deadline(),
            Some(release),
            "the release rounds up to the wheel"
        );
    }

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
    fn the_earliest_pacing_wake_of_either_kind_is_found_and_taken_once_due() {
        let t = Instant::now();
        let us = Duration::from_micros;
        let mut timers = Timers::default();
        timers.set(Kind::Deadline, 9, None, Some(t));
        assert_eq!(timers.next_pacing(), None, "a deadline is no pacing wake");
        assert_eq!(timers.pop_due_pacing(t + us(1_000)), None);

        timers.set(Kind::Pacing, 1, None, Some(t + us(300)));
        timers.set(Kind::Coarse, 2, None, Some(t + us(200)));
        timers.set(Kind::Pacing, 3, None, Some(t + us(500)));
        assert_eq!(
            timers.next_pacing(),
            Some(t + us(200)),
            "the coarse wake comes first"
        );
        assert_eq!(
            timers.pop_due_pacing(t + us(100)),
            None,
            "nothing is due before its time"
        );
        assert_eq!(
            timers.pop_due_pacing(t + us(400)),
            Some(2),
            "the earliest first, of either kind"
        );
        assert_eq!(timers.pop_due_pacing(t + us(400)), Some(1));
        assert_eq!(
            timers.pop_due_pacing(t + us(400)),
            None,
            "the one left is not due"
        );
        assert_eq!(timers.next_pacing(), Some(t + us(500)));
        assert_eq!(
            timers.next(Kind::Deadline),
            Some(t),
            "deadlines are left alone"
        );
    }

    #[test]
    fn a_pacing_release_a_tick_or_more_away_wakes_early_on_the_wheel_and_ends_on_the_timerfd() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let release = t + ms(5);
        let Arm::Wheel(early) = plan(LEAD, t, None, Some(release), None) else {
            panic!("a distant release starts on the wheel");
        };
        assert!(
            early < release && release - early >= WHEEL_TICK,
            "the wheel wakes at least a tick ahead of the release, so its tick does not make the \
             release late: {:?} ahead",
            release.saturating_duration_since(early)
        );
        assert_eq!(
            plan(LEAD, early, None, Some(release), None),
            Arm::Fine(release),
            "the early wake hands the release to the timerfd"
        );
        assert_eq!(
            plan(LEAD, t, None, Some(t + Duration::from_micros(300)), None),
            Arm::Fine(t + Duration::from_micros(300)),
            "a release under a tick away goes to the timerfd at once"
        );
        assert_eq!(
            plan(LEAD, t, Some(t + ms(1)), Some(release), None),
            Arm::Wheel(t + ms(1)),
            "an earlier deadline comes first"
        );
        assert_eq!(
            plan(LEAD, t, Some(t + ms(4)), None, None),
            Arm::Wheel(t + ms(4)),
            "deadlines alone use the wheel"
        );
        assert_eq!(plan(LEAD, release, None, Some(release), None), Arm::Now);
        assert_eq!(plan(LEAD, t, None, None, None), Arm::Idle);
    }

    /// Returns how the endpoint wakes at `now` for the pacing wakes in `timers`, without deadlines.
    fn plan_pacing(now: Instant, timers: &Timers) -> Arm {
        plan(
            LEAD,
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
            timers.set(Kind::pacing(horizon, LEAD), 1, None, Some(pacing_at));
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
            timers.set(Kind::pacing(ms(5), LEAD), 1, None, Some(pacing_at + ms(20)));
            timers.set(Kind::pacing(horizon, LEAD), 2, None, Some(pacing_at));
            assert_eq!(
                plan_pacing(t, &timers),
                Arm::Wheel(pacing_at - LEAD),
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
        timers.set(Kind::pacing(ms(5), LEAD), 1, None, Some(t + us(300)));
        timers.set(Kind::pacing(Duration::ZERO, LEAD), 2, None, Some(t + ms(1)));
        assert_eq!(
            plan_pacing(t, &timers),
            Arm::Both {
                wheel: t + us(300),
                fine: t + ms(1),
            },
            "the timerfd takes only the imminent pacing wake"
        );
        assert_eq!(
            plan(LEAD, t, None, Some(t + us(300)), Some(t + ms(1))),
            Arm::Fine(t + us(300)),
            "a coarse wake after the imminent pacing wake waits for the next plan"
        );
        assert_eq!(
            plan(LEAD, t, Some(t + us(300)), Some(t + ms(1)), None),
            Arm::Fine(t + us(300)),
            "a deadline before an imminent pacing wake still takes the timerfd"
        );
        assert_eq!(
            plan(
                LEAD,
                t,
                Some(t + us(200)),
                Some(t + ms(1)),
                Some(t + us(300))
            ),
            Arm::Fine(t + us(200)),
            "an earlier deadline comes first"
        );
        assert_eq!(
            plan(
                LEAD,
                t,
                Some(t + us(500)),
                Some(t + ms(1)),
                Some(t + us(300))
            ),
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
                let mut wake = HostWake::new(&host, HostTimers::tokio());
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
                let mut wake = HostWake::new(&host, HostTimers::tokio());
                let start = host.now();
                let coarse = start + Duration::from_micros(1500);
                let pacing = start + LEAD;
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
