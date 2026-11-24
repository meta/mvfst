/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The work budget: a slice of host-clock time that the endpoint drivers of one host share in
//! each iteration of its loop.

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

/// The leftover wait past which [`BudgetStats::long_leftovers`] counts one.
const LONG_LEFTOVER: Duration = Duration::from_millis(3);

/// The kind of a unit of driver work. A driver checks its budget before each unit but the first of
/// a poll, and records how long each unit ran past the slice's deadline under its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnitKind {
    /// One transmit attempt of one connection.
    Attempt,
    /// The routing and delivery of up to 64 datagrams of one received batch. On a connection's
    /// own socket, a batch's first chunk includes its receive.
    ReceiveChunk,
    /// The handling of one connection attempt, whether or not it creates a connection.
    Accept,
    /// One connection's application visit: its events, `poll_session` and pull steps.
    AppVisit,
    /// One timer or wake the intake serves.
    IntakeServe,
    /// One Initial kept from an earlier turn, routed again.
    WaitingDatagram,
    /// Up to 64 stale transmit-queue slots skipped in a row: slots that a pacing serve of their
    /// connection retired, or slots of connections freed since they were queued.
    Skips,
    /// Up to 64 slab entries a quiesce sweep walks.
    Sweep,
    /// Up to 64 connections parked on the server socket, marked for another attempt once it is
    /// writable.
    Remark,
    /// A transmit phase's end-of-phase flush of the server socket, which sends the runs still
    /// queued there, as many as the socket accepts. It runs even after a stop, and is not preceded
    /// by a check.
    TransmitFlush,
}

impl UnitKind {
    const COUNT: usize = 10;

    fn index(self) -> usize {
        match self {
            Self::Attempt => 0,
            Self::ReceiveChunk => 1,
            Self::Accept => 2,
            Self::AppVisit => 3,
            Self::IntakeServe => 4,
            Self::WaitingDatagram => 5,
            Self::Skips => 6,
            Self::Sweep => 7,
            Self::Remark => 8,
            Self::TransmitFlush => 9,
        }
    }
}

/// How a driver's last poll used its budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PollOutcome {
    /// The poll ran without stopping.
    #[default]
    Ran,
    /// The poll did not run any work, because the slice was closed or the budget held and a grant
    /// was not pending.
    Deferred,
    /// The poll stopped at a check after the slice closed, or ran on a grant while the slice was
    /// closed or the budget held.
    Stopped,
}

/// The counters of a [`WorkBudget`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BudgetStats {
    /// Slices opened.
    pub slices: u64,
    /// Polls that reported [`PollOutcome::Stopped`].
    pub stops: u64,
    /// Polls that reported [`PollOutcome::Deferred`].
    pub deferrals: u64,
    /// The longest leftover wait, in µs: the time from a stop in a transmit phase until every slot
    /// the stop left in the transmit queue has been popped, stale ones included.
    pub longest_leftover_us: u64,
    /// Leftover waits longer than 3 ms.
    pub long_leftovers: u64,
    /// End-of-phase transmit flushes timed.
    pub flushes: u64,
    /// The datagrams those flushes sent.
    pub flushed_datagrams: u64,
    /// Their total time, in µs.
    pub flush_us: u64,
    /// Transmit phases stopped before an attempt because the time left in the slice was less than
    /// the predicted cost of flushing what they had staged, capped at half the slice.
    pub reserve_stops: u64,
    past_us: [u64; UnitKind::COUNT],
}

impl BudgetStats {
    /// Returns the longest time, in µs, that one unit of `kind` ran past its slice's deadline:
    /// the reading after it less the later of the deadline and the reading before it.
    pub fn longest_past_us(&self, kind: UnitKind) -> u64 {
        self.past_us[kind.index()]
    }
}

struct State {
    slice: Duration,
    per_poll: bool,
    /// Whether the budget is held; the host may also set it through [`WorkBudget::hold_flag`].
    hold: Cell<bool>,
    /// The deadline of the slice opened since the last refill, if one has opened.
    deadline: Cell<Option<Instant>>,
    closed: Cell<bool>,
    grant: Cell<bool>,
    /// Whether a grant admitted the running poll while the slice was closed or the budget held.
    granted: Cell<bool>,
    /// The reading at which the running poll was admitted.
    entry: Cell<Option<Instant>>,
    /// Whether the running poll has begun its first unit.
    begun: Cell<bool>,
    /// The reading of the running poll's last check.
    checked: Cell<Option<Instant>>,
    /// The running unit and the reading before it, until its time past the deadline is recorded.
    unit: Cell<Option<(UnitKind, Instant)>>,
    outcome: Cell<PollOutcome>,
    /// Whether a poll has ended since the last [`WorkBudget::take_report`].
    reported: Cell<bool>,
    stats: Cell<BudgetStats>,
}

/// A slice of host-clock time per host loop iteration, shared by the endpoint drivers of one host
/// through cloned handles, each given to its driver with
/// [`EndpointDriverBuilder::work_budget`](crate::EndpointDriverBuilder::work_budget).
///
/// The host calls [`refill`](Self::refill) once per iteration. The first poll after it opens the
/// slice, which ends at the poll's reading plus the slice. A poll then runs its first unit of work
/// and checks the clock before each later one; once the reading passes the deadline, the slice
/// closes, the poll stops and leaves the rest of its work in place for its next poll, and later
/// polls in the iteration do not run any work. The driver refills a budget in per-poll mode at
/// each poll, so each poll gets a whole slice.
#[derive(Clone)]
pub struct WorkBudget(Rc<State>);

impl WorkBudget {
    /// Creates a budget of `slice` per host loop iteration, which the host refills.
    pub fn new(slice: Duration) -> Self {
        Self::with_mode(slice, false)
    }

    /// Creates a budget of `slice` per poll, which the driver refills at each poll.
    pub fn per_poll(slice: Duration) -> Self {
        Self::with_mode(slice, true)
    }

    fn with_mode(slice: Duration, per_poll: bool) -> Self {
        Self(Rc::new(State {
            slice,
            per_poll,
            hold: Cell::new(false),
            deadline: Cell::new(None),
            closed: Cell::new(false),
            grant: Cell::new(false),
            granted: Cell::new(false),
            entry: Cell::new(None),
            begun: Cell::new(false),
            checked: Cell::new(None),
            unit: Cell::new(None),
            outcome: Cell::new(PollOutcome::Ran),
            reported: Cell::new(false),
            stats: Cell::default(),
        }))
    }

    /// Starts a new slice: the next [`admit`](Self::admit) opens it.
    pub fn refill(&self) {
        self.0.deadline.set(None);
        self.0.closed.set(false);
    }

    /// Opens the slice if this is the first call since the refill, closes it if its deadline has
    /// passed at `now`, and returns whether a poll may run: the slice is open and the budget not
    /// held, or a grant is pending, which this call takes.
    pub fn admit(&self, now: Instant) -> bool {
        let state = &*self.0;
        match state.deadline.get() {
            None => self.open(now),
            Some(deadline) if now > deadline => state.closed.set(true),
            Some(_) => {}
        }
        let blocked = state.closed.get() || state.hold.get();
        state.granted.set(blocked && state.grant.get());
        state.grant.set(false);
        state.entry.set(Some(now));
        state.begun.set(false);
        state.checked.set(None);
        state.unit.set(None);
        !blocked || state.granted.get()
    }

    /// Checks the slice at `now`, a reading taken after the running unit, before a unit of `kind`.
    /// Records the running unit's time past the deadline, closes the slice once the deadline has
    /// passed, and returns whether the unit of `kind` may run: the slice is open and the poll is
    /// not running on a grant.
    pub fn check(&self, now: Instant, kind: UnitKind) -> bool {
        self.check_reserving(now, kind, Duration::ZERO)
    }

    /// Checks the slice at `now` as [`check`](Self::check) does, and also refuses the unit when
    /// less than `reserve` is left of it, with the reserve capped at half the slice. A transmit
    /// phase reserves the predicted cost of flushing what it has staged, and a refusal for the
    /// reserve closes the slice, leaving the rest of it to the flush.
    pub(crate) fn check_reserving(&self, now: Instant, kind: UnitKind, reserve: Duration) -> bool {
        self.observe(now);
        let state = &*self.0;
        state.checked.set(Some(now));
        if state.granted.get() || state.closed.get() {
            return false;
        }
        if let Some(deadline) = state.deadline.get()
            && now + reserve.min(state.slice / 2) > deadline
        {
            state.closed.set(true);
            self.count(|stats| stats.reserve_stops += 1);
            return false;
        }
        state.unit.set(Some((kind, now)));
        true
    }

    /// Begins an end-of-phase transmit flush at `before`, a reading taken after the unit before
    /// it: records that unit's time past the deadline, as a check does, and makes the flush the
    /// running unit. A flush always runs, so the slice is not checked.
    pub(crate) fn begin_flush(&self, before: Instant) {
        self.observe(before);
        self.0.unit.set(Some((UnitKind::TransmitFlush, before)));
    }

    /// Ends the flush begun at `before`, which sent `datagrams`, at `after`, a reading taken after
    /// it: records its time past the deadline, closes the slice once the deadline has passed, and
    /// counts the flush in the stats.
    pub(crate) fn end_flush(&self, before: Instant, after: Instant, datagrams: u32) {
        self.observe(after);
        let took = micros(after.saturating_duration_since(before));
        self.count(|stats| {
            stats.flushes += 1;
            stats.flushed_datagrams += u64::from(datagrams);
            stats.flush_us = stats.flush_us.saturating_add(took);
        });
    }

    /// Makes the next [`admit`](Self::admit) succeed even on a closed slice or a held budget. That
    /// poll runs its first unit, and its next check stops it. On an open slice of a budget not
    /// held, the next admit takes the grant without effect.
    pub fn grant(&self) {
        self.0.grant.set(true);
    }

    /// Holds or releases the budget. While it is held, [`admit`](Self::admit) fails unless a
    /// grant is pending.
    pub fn set_hold(&self, hold: bool) {
        self.0.hold.set(hold);
    }

    /// Returns the address of the hold flag, which stays put while any handle on the budget
    /// lives, so a host can set and clear it in place, as [`set_hold`](Self::set_hold) does.
    pub fn hold_flag(&self) -> *mut bool {
        self.0.hold.as_ptr()
    }

    /// Returns how the last poll of a driver on this budget used it.
    pub fn outcome(&self) -> PollOutcome {
        self.0.outcome.get()
    }

    /// Returns whether the slice has closed since the last refill.
    pub fn is_closed(&self) -> bool {
        self.0.closed.get()
    }

    /// Returns the deadline of the slice opened since the last refill, if one has opened.
    pub fn deadline(&self) -> Option<Instant> {
        self.0.deadline.get()
    }

    /// Returns the budget's counters.
    pub fn stats(&self) -> BudgetStats {
        self.0.stats.get()
    }

    /// Returns the outcome of the last poll if one has ended since the last call, and `None`
    /// otherwise. A host that calls it after each task it polls thus gets an outcome after each
    /// poll of a task that calls [`finish`](Self::finish), such as a driver on this budget, and
    /// `None` after other tasks.
    pub fn take_report(&self) -> Option<PollOutcome> {
        self.0.reported.replace(false).then(|| self.0.outcome.get())
    }

    /// Returns whether the budget is held.
    pub fn is_held(&self) -> bool {
        self.0.hold.get()
    }

    /// Opens the slice at `now` unless one has opened since the refill, as the first
    /// [`admit`](Self::admit) after a refill does, without admitting a poll. A host calls it for
    /// its own work when that work takes the first turn of an iteration.
    pub fn open(&self, now: Instant) {
        let state = &*self.0;
        if state.deadline.get().is_none() {
            state.deadline.set(Some(now + state.slice));
            state.closed.set(false);
            self.count(|stats| stats.slices += 1);
        }
    }

    /// Starts a driver's poll at `now`: refills a per-poll budget and admits the poll.
    pub(crate) fn enter(&self, now: Instant) -> bool {
        if self.0.per_poll {
            self.refill();
        }
        self.admit(now)
    }

    /// Marks the poll's first unit as begun; it runs without a check, from the admission's reading.
    pub(crate) fn first(&self, kind: UnitKind) {
        self.0.begun.set(true);
        if let Some(entry) = self.0.entry.get() {
            self.0.unit.set(Some((kind, entry)));
        }
    }

    /// Returns whether the poll has begun its first unit, so later units need a check.
    pub(crate) fn begun(&self) -> bool {
        self.0.begun.get()
    }

    /// Returns the reading of the poll's last check, if it has made one.
    pub(crate) fn checked_at(&self) -> Option<Instant> {
        self.0.checked.get()
    }

    /// Ends a poll with `outcome`, which [`take_report`](Self::take_report) then returns once. A
    /// driver calls it at the end of each poll, and so does any other participant that admits its
    /// polls with [`admit`](Self::admit). For a poll that a grant admitted while the slice was
    /// closed or the budget held, [`PollOutcome::Ran`] becomes [`PollOutcome::Stopped`].
    pub fn finish(&self, outcome: PollOutcome) {
        let outcome = match outcome {
            PollOutcome::Ran if self.0.granted.get() => PollOutcome::Stopped,
            outcome => outcome,
        };
        self.0.unit.set(None);
        self.0.begun.set(false);
        self.0.granted.set(false);
        self.0.outcome.set(outcome);
        self.0.reported.set(true);
        match outcome {
            PollOutcome::Ran => {}
            PollOutcome::Deferred => self.count(|stats| stats.deferrals += 1),
            PollOutcome::Stopped => self.count(|stats| stats.stops += 1),
        }
    }

    /// Records the running unit's time past the deadline at `now`, a reading after it, and closes
    /// the slice once the deadline has passed. Outside a poll it only closes the slice.
    pub fn observe(&self, now: Instant) {
        let state = &*self.0;
        let Some(deadline) = state.deadline.get() else {
            return;
        };
        if now <= deadline {
            return;
        }
        state.closed.set(true);
        let Some((kind, before)) = state.unit.take() else {
            return;
        };
        let past = micros(now.duration_since(deadline.max(before)));
        self.count(|stats| {
            let longest = &mut stats.past_us[kind.index()];
            *longest = (*longest).max(past);
        });
    }

    /// Records a leftover wait of `wait`.
    pub(crate) fn leftover(&self, wait: Duration) {
        let waited = micros(wait);
        self.count(|stats| {
            stats.longest_leftover_us = stats.longest_leftover_us.max(waited);
            stats.long_leftovers += u64::from(wait > LONG_LEFTOVER);
        });
    }

    fn count(&self, f: impl FnOnce(&mut BudgetStats)) {
        let mut stats = self.0.stats.get();
        f(&mut stats);
        self.0.stats.set(stats);
    }
}

/// Returns `duration` in whole µs.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// A running average of what an end-of-phase transmit flush costs per datagram it sends, from
/// which a driver predicts what flushing the datagrams a transmit phase has staged will cost.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FlushCost {
    /// Eight times the running averages of a timed flush's time, in ns, and of the datagrams it
    /// sent. Each flush moves both an eighth of the way to its own figures, so their ratio weighs
    /// flushes by the datagrams they sent.
    time_ns: u64,
    datagrams: u64,
}

impl FlushCost {
    /// The running averages keep `WEIGHT - 1` parts in `WEIGHT` of their value at each flush.
    const WEIGHT: u64 = 8;

    /// Adds a flush that took `time` to send `datagrams`, unless it did not send any.
    pub(crate) fn record(&mut self, time: Duration, datagrams: u32) {
        if datagrams == 0 {
            return;
        }
        let time_ns = u64::try_from(time.as_nanos()).unwrap_or(u64::MAX);
        let datagrams = u64::from(datagrams);
        if self.datagrams == 0 {
            self.time_ns = time_ns.saturating_mul(Self::WEIGHT);
            self.datagrams = datagrams * Self::WEIGHT;
            return;
        }
        self.time_ns = (self.time_ns - self.time_ns / Self::WEIGHT).saturating_add(time_ns);
        self.datagrams = self.datagrams - self.datagrams / Self::WEIGHT + datagrams;
    }

    /// Returns the predicted time to flush `staged` datagrams: the average cost per datagram
    /// times `staged`, or zero until a flush has been timed.
    pub(crate) fn predict(&self, staged: u32) -> Duration {
        if self.datagrams == 0 {
            return Duration::ZERO;
        }
        let ns = u128::from(self.time_ns) * u128::from(staged) / u128::from(self.datagrams);
        Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }
}

impl fmt::Debug for WorkBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkBudget")
            .field("slice", &self.0.slice)
            .field("per_poll", &self.0.per_poll)
            .field("closed", &self.0.closed.get())
            .field("held", &self.0.hold.get())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us(micros: u64) -> Duration {
        Duration::from_micros(micros)
    }

    #[test]
    fn the_first_admit_after_a_refill_opens_the_slice_and_a_check_past_its_deadline_closes_it() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert_eq!(budget.deadline(), None, "no slice before the first admit");
        assert!(budget.admit(start));
        assert_eq!(budget.deadline(), Some(start + us(1_000)));
        assert_eq!(budget.stats().slices, 1);
        budget.first(UnitKind::IntakeServe);
        assert!(budget.check(start + us(500), UnitKind::Attempt));
        assert!(
            budget.check(start + us(1_000), UnitKind::Attempt),
            "a reading at the deadline has not passed it"
        );
        assert!(!budget.is_closed());
        assert!(!budget.check(start + us(1_001), UnitKind::Attempt));
        assert!(budget.is_closed());
        assert!(
            !budget.admit(start + us(1_100)),
            "a closed slice admits no poll"
        );
        assert_eq!(
            budget.stats().slices,
            1,
            "an admit opens one slice per refill"
        );
        budget.refill();
        assert!(!budget.is_closed());
        assert!(budget.admit(start + us(2_000)));
        assert_eq!(budget.deadline(), Some(start + us(3_000)));
        assert_eq!(budget.stats().slices, 2);
    }

    #[test]
    fn open_opens_the_slice_once_per_refill_and_keeps_a_pending_grant() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        budget.grant();
        budget.open(start);
        assert_eq!(budget.deadline(), Some(start + us(1_000)));
        assert_eq!(budget.stats().slices, 1);
        budget.open(start + us(100));
        assert_eq!(
            budget.deadline(),
            Some(start + us(1_000)),
            "a slice opened since the refill stays"
        );
        assert_eq!(budget.stats().slices, 1);
        assert!(
            budget.admit(start + us(1_100)),
            "the grant open left pending admits a poll on the closed slice"
        );
        assert!(budget.is_closed());
        budget.finish(PollOutcome::Stopped);
        assert!(!budget.admit(start + us(1_200)), "the grant is used up");
        budget.finish(PollOutcome::Deferred);
        budget.refill();
        budget.open(start + us(2_000));
        assert_eq!(budget.deadline(), Some(start + us(3_000)));
        assert!(!budget.is_closed());
        assert_eq!(budget.stats().slices, 2);
    }

    #[test]
    fn an_admit_closes_a_slice_whose_deadline_has_passed() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        assert!(!budget.admit(start + us(1_001)));
        assert!(budget.is_closed());
    }

    #[test]
    fn while_held_a_budget_admits_no_poll_unless_a_grant_is_pending() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        let flag = budget.hold_flag();
        assert_eq!(
            budget.clone().hold_flag(),
            flag,
            "every handle sets the one flag"
        );
        budget.set_hold(true);
        assert!(!budget.admit(start), "a held budget admits no poll");
        budget.grant();
        assert!(budget.admit(start), "a pending grant admits one poll");
        assert!(!budget.admit(start), "the grant is used up");
        budget.set_hold(false);
        assert!(budget.admit(start));
        assert_eq!(budget.hold_flag(), flag, "the flag stays put");
    }

    #[test]
    fn is_held_reads_the_hold_flag() {
        let budget = WorkBudget::new(us(1_000));
        assert!(!budget.is_held());
        budget.clone().set_hold(true);
        assert!(budget.is_held(), "every handle sees the one flag");
        budget.set_hold(false);
        assert!(!budget.is_held());
    }

    #[test]
    fn a_grant_on_a_closed_slice_admits_one_unit_and_its_next_check_stops_the_poll() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        assert!(!budget.check(start + us(1_500), UnitKind::Attempt));
        budget.finish(PollOutcome::Stopped);
        budget.grant();
        let granted = start + us(2_000);
        assert!(budget.admit(granted));
        budget.first(UnitKind::Attempt);
        assert!(
            !budget.check(granted + us(2_500), UnitKind::Attempt),
            "the poll on a grant runs one unit"
        );
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::Attempt),
            2_500,
            "the granted unit ran wholly past the deadline"
        );
        budget.finish(PollOutcome::Stopped);
        assert_eq!(budget.outcome(), PollOutcome::Stopped);
        assert_eq!(budget.stats().stops, 2);
    }

    #[test]
    fn a_poll_on_a_grant_reports_stopped_even_without_a_second_unit() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        assert!(!budget.admit(start + us(1_500)));
        budget.grant();
        assert!(budget.admit(start + us(1_600)));
        budget.first(UnitKind::AppVisit);
        budget.observe(start + us(1_700));
        budget.finish(PollOutcome::Ran);
        assert_eq!(budget.outcome(), PollOutcome::Stopped);
        assert_eq!(budget.stats().longest_past_us(UnitKind::AppVisit), 100);
    }

    #[test]
    fn a_grant_on_an_open_slice_changes_nothing() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        budget.grant();
        assert!(budget.admit(start + us(100)));
        budget.first(UnitKind::Attempt);
        assert!(
            budget.check(start + us(200), UnitKind::Attempt),
            "the poll runs on to the deadline"
        );
        budget.observe(start + us(300));
        budget.finish(PollOutcome::Ran);
        assert_eq!(budget.outcome(), PollOutcome::Ran);
        assert!(
            !budget.admit(start + us(1_100)),
            "the open slice's admit took the grant"
        );
    }

    #[test]
    fn time_past_the_deadline_counts_from_the_later_of_the_deadline_and_the_reading_before() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        budget.first(UnitKind::IntakeServe);
        assert!(budget.check(start + us(800), UnitKind::AppVisit));
        assert!(!budget.check(start + us(1_300), UnitKind::Attempt));
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::AppVisit),
            300,
            "the visit began before the deadline"
        );
        assert_eq!(budget.stats().longest_past_us(UnitKind::IntakeServe), 0);
        budget.finish(PollOutcome::Stopped);

        budget.refill();
        let second = start + us(5_000);
        assert!(budget.admit(second));
        budget.first(UnitKind::Accept);
        budget.observe(second + us(1_700));
        budget.finish(PollOutcome::Ran);
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::Accept),
            700,
            "the poll's reading at its end records its last unit"
        );
        assert!(budget.is_closed(), "and closes the slice");
        assert_eq!(budget.outcome(), PollOutcome::Ran);

        budget.refill();
        let third = start + us(10_000);
        assert!(budget.admit(third));
        budget.first(UnitKind::Accept);
        assert!(!budget.check(third + us(1_100), UnitKind::Accept));
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::Accept),
            700,
            "the longest is kept"
        );
    }

    #[test]
    fn a_poll_reports_its_outcome_once_after_it_ends() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert_eq!(budget.take_report(), None, "no poll has ended");
        assert!(budget.admit(start));
        assert_eq!(budget.take_report(), None, "the poll has not ended");
        budget.finish(PollOutcome::Ran);
        assert_eq!(budget.take_report(), Some(PollOutcome::Ran));
        assert_eq!(budget.take_report(), None, "reported once");
        budget.set_hold(true);
        assert!(!budget.admit(start + us(10)));
        budget.finish(PollOutcome::Deferred);
        assert_eq!(budget.take_report(), Some(PollOutcome::Deferred));
    }

    #[test]
    fn a_per_poll_budget_refills_at_each_poll_and_counts_the_outcomes() {
        let budget = WorkBudget::per_poll(us(1_000));
        let start = Instant::now();
        assert!(budget.enter(start));
        budget.first(UnitKind::Attempt);
        assert!(!budget.check(start + us(2_000), UnitKind::Attempt));
        budget.finish(PollOutcome::Stopped);
        assert!(
            budget.enter(start + us(2_000)),
            "each poll gets a whole slice"
        );
        assert_eq!(budget.deadline(), Some(start + us(3_000)));
        budget.observe(start + us(2_100));
        budget.finish(PollOutcome::Ran);
        budget.set_hold(true);
        assert!(!budget.enter(start + us(2_200)));
        budget.finish(PollOutcome::Deferred);
        assert_eq!(budget.outcome(), PollOutcome::Deferred);
        let stats = budget.stats();
        assert_eq!(
            (stats.slices, stats.stops, stats.deferrals),
            (3, 1, 1),
            "three slices opened, one poll stopped and one deferred"
        );
    }

    #[test]
    fn a_flush_cost_predicts_nothing_until_a_flush_is_timed_then_its_average_per_datagram() {
        let mut cost = FlushCost::default();
        assert_eq!(cost.predict(100), Duration::ZERO, "no flush timed yet");
        cost.record(us(100), 0);
        assert_eq!(
            cost.predict(100),
            Duration::ZERO,
            "a flush that sent nothing teaches nothing"
        );
        cost.record(us(100), 20);
        assert_eq!(cost.predict(10), us(50), "5 µs per datagram");
        assert_eq!(cost.predict(0), Duration::ZERO);
        cost.record(us(300), 20);
        assert_eq!(
            cost.predict(10),
            Duration::from_nanos(62_500),
            "the average moves an eighth of the way from 5 µs to 15 µs per datagram"
        );
        let mut weighted = FlushCost::default();
        weighted.record(us(100), 20);
        weighted.record(us(20), 2);
        assert_eq!(
            weighted.predict(1),
            Duration::from_nanos(720_000 / 142),
            "the averages of time and of datagrams each move an eighth of the way, so a small \
             flush moves the cost per datagram little: (700 + 20) µs per (140 + 2) datagrams"
        );
    }

    #[test]
    fn a_check_with_a_reserve_stops_and_closes_the_slice_when_less_than_the_reserve_is_left() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        budget.first(UnitKind::Attempt);
        assert!(
            budget.check_reserving(start + us(600), UnitKind::Attempt, us(400)),
            "400 µs left covers a 400 µs reserve"
        );
        assert!(
            !budget.check_reserving(start + us(601), UnitKind::Attempt, us(400)),
            "399 µs left does not"
        );
        assert!(
            budget.is_closed(),
            "a reserve stop closes the slice: what is left of it is the flush's"
        );
        assert_eq!(budget.stats().reserve_stops, 1);
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::Attempt),
            0,
            "the attempts ended before the deadline"
        );
        budget.finish(PollOutcome::Stopped);
        assert_eq!(budget.outcome(), PollOutcome::Stopped);

        budget.refill();
        let second = start + us(5_000);
        assert!(budget.admit(second));
        budget.first(UnitKind::Attempt);
        assert!(
            budget.check_reserving(second + us(500), UnitKind::Attempt, us(10_000)),
            "a reserve is at most half the slice"
        );
        assert!(!budget.check_reserving(second + us(501), UnitKind::Attempt, us(10_000)));
        assert_eq!(budget.stats().reserve_stops, 2);
        budget.finish(PollOutcome::Stopped);

        budget.refill();
        let third = start + us(10_000);
        assert!(budget.admit(third));
        budget.first(UnitKind::Attempt);
        assert!(!budget.check_reserving(third + us(1_100), UnitKind::Attempt, us(100)));
        assert_eq!(
            budget.stats().reserve_stops,
            2,
            "a check past the deadline stops without the reserve"
        );
        assert_eq!(budget.stats().longest_past_us(UnitKind::Attempt), 100);
    }

    #[test]
    fn an_end_of_phase_flush_records_its_time_past_the_deadline_under_its_own_kind() {
        let budget = WorkBudget::new(us(1_000));
        let start = Instant::now();
        assert!(budget.admit(start));
        budget.first(UnitKind::Attempt);
        assert!(!budget.check(start + us(1_100), UnitKind::Attempt));
        budget.begin_flush(start + us(1_100));
        budget.end_flush(start + us(1_100), start + us(1_400), 120);
        let stats = budget.stats();
        assert_eq!(
            stats.longest_past_us(UnitKind::TransmitFlush),
            300,
            "the flush after the stop ran wholly past the deadline"
        );
        assert_eq!(stats.longest_past_us(UnitKind::Attempt), 100);
        assert_eq!(
            (stats.flushes, stats.flushed_datagrams, stats.flush_us),
            (1, 120, 300)
        );
        budget.finish(PollOutcome::Stopped);

        budget.refill();
        let second = start + us(5_000);
        assert!(budget.admit(second));
        budget.first(UnitKind::Attempt);
        budget.begin_flush(second + us(900));
        budget.end_flush(second + us(900), second + us(1_600), 10);
        let stats = budget.stats();
        assert_eq!(
            stats.longest_past_us(UnitKind::TransmitFlush),
            600,
            "a flush begun before the deadline counts from it"
        );
        assert_eq!(
            stats.longest_past_us(UnitKind::Attempt),
            100,
            "the reading before the flush ends the attempt before it, inside the slice"
        );
        assert!(budget.is_closed());
        assert_eq!(
            (stats.flushes, stats.flushed_datagrams, stats.flush_us),
            (2, 130, 1_000)
        );
        budget.finish(PollOutcome::Ran);

        budget.refill();
        let third = start + us(10_000);
        assert!(budget.admit(third));
        budget.first(UnitKind::Attempt);
        budget.begin_flush(third + us(1_300));
        budget.end_flush(third + us(1_300), third + us(1_350), 1);
        assert_eq!(
            budget.stats().longest_past_us(UnitKind::Attempt),
            300,
            "the reading before a flush records the unit before it"
        );
    }
}
