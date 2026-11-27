/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Transmit: the attempt, its stops and limits, and the I/O-neutral transmit types.
//!
//! An attempt is one call to [`Connection::poll_transmit`](crate::Connection::poll_transmit). It
//! builds packets straight into slots a backend lends through a [`SegmentSink`], hands each to a
//! [`Sealer`](crate::Sealer), closes GSO runs with a [`TxMeta`], and returns a [`TxOutcome`]
//! whose [`Stop`] names the limit that ended the attempt, and so the wake the driver must arm.
//! Backends later report what happened to each datagram with a [`TxReport`].
//!
//! Each GSO run has one release. A connection with build horizon H_conn = 0 builds a paced run
//! only once it is due, and every run carries [`Release::Asap`]. With H_conn > 0, a backend with
//! release support holds datagrams until their release: the connection builds paced runs up to
//! H_conn ahead and stamps every run with [`Release::At`] in the backend's clock, given by
//! [`TxLimits::epoch`]. Backends do not report TX timestamps, datagrams cannot be recalled, and
//! the egress grant is carried only in [`TxLimits::max_bytes`].
//!
//! The attempt runs in the connection. Its admission table, which decides whether a frame
//! source's candidate may start or join a packet, and the ranking of the limits that refuse
//! candidates are in `admission`.

pub(crate) mod admission;

use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

pub use mvfstr_crypto::SlotId;

/// A network path of a connection: the current path, or a path being validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathId(pub u16);

/// A time on the endpoint's monotonic clock, in nanoseconds since an arbitrary epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(pub u64);

/// A backend's clock epoch: an instant and the backend clock's reading at it, so that a release
/// is written in the clock the backend hands the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockEpoch {
    /// An instant on the endpoint's monotonic clock.
    pub instant: Instant,
    /// The backend clock's reading at `instant`.
    pub tick: Tick,
}

impl ClockEpoch {
    /// Returns the backend clock's reading at `at`, saturating at both ends of `u64`.
    pub fn tick_at(&self, at: Instant) -> Tick {
        let nanos = |span: Duration| u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
        Tick(match at.checked_duration_since(self.instant) {
            Some(after) => self.tick.0.saturating_add(nanos(after)),
            None => self.tick.0.saturating_sub(nanos(self.instant - at)),
        })
    }
}

/// When a datagram may leave. Backends may defer a release, never advance it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// As soon as possible. With a build horizon of 0, every datagram carries this: the pacer
    /// holds packets back by not building them.
    Asap,
    /// Not before this time.
    At(Tick),
}

/// The class of a datagram for the backend's slot quotas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxClass {
    /// An ACK-only, probe or response (PATH_RESPONSE, CONNECTION_CLOSE) start. Backends keep a
    /// small slot quota per connection that only urgent segments may take, so bulk data cannot
    /// block them.
    Urgent,
    /// Everything else.
    Data,
}

/// A range of a connection's datagram sequence numbers, `start..end`.
///
/// Every datagram a connection builds takes the next number, recorded in its sent packets, so a
/// [`TxReport`] maps back to the packets of every space it carried, coalesced ones included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxSeqRange {
    /// The first sequence number in the range.
    pub start: u64,
    /// One past the last sequence number in the range.
    pub end: u64,
}

/// The metadata of one GSO run: equal-size segments to one destination with one release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxMeta {
    /// The path the run belongs to; the backend keeps runs FIFO per (connection, path).
    pub path: PathId,
    /// The destination address.
    pub dst: SocketAddr,
    /// The source address to send from, if the socket has several.
    pub src_ip: Option<IpAddr>,
    /// The TOS byte: DSCP in the high six bits, ECN in the low two.
    pub tos: u8,
    /// The size of every segment but possibly the last, which may be shorter.
    pub segment_size: u16,
    /// The number of segments.
    pub segments: u16,
    /// When the run may leave.
    pub release: Release,
    /// The class of the run's first segment.
    pub class: TxClass,
    /// The datagram sequence numbers of the run's segments.
    pub tx: TxSeqRange,
    /// Whether every segment is sealed. Backends refuse unsealed runs.
    pub sealed: bool,
}

/// Where [`Connection::poll_transmit`](crate::Connection::poll_transmit) writes datagrams: a
/// backend's view for one connection.
///
/// The slot contract, which backends implement and the connection follows:
///
/// - One slot is lent at a time. [`next_segment`](Self::next_segment) returns a slice of
///   exactly `min(max_len, max_datagram)` bytes, where `max_datagram` is the backend's largest
///   datagram ([`TxLimits::max_datagram`] as the driver sets it), whatever the open run holds.
///   The caller finishes the slot with [`end_segment`](Self::end_segment) before the next
///   `next_segment` call; a slot still lent at that call, or when the sink is dropped, is
///   abandoned.
/// - `end_segment(len)` with `len` from 1 to the slice length appends a datagram of `len` bytes
///   to the open run; `end_segment(0)` gives the slot back and leaves the open run unchanged.
/// - The open run is the segments ended since the previous [`end_run`](Self::end_run), or since
///   the sink was obtained. Its segment size is the length of its first segment; every later
///   segment has that length except the last, which may be shorter.
/// - The caller ends runs; the backend never does. A segment shorter than the run's segment
///   size is the run's last, so the caller calls `end_run` before the next `next_segment`.
///   Because a run's first segment fixes its size and the next slice is `max_len` long, the
///   caller ends the run after any segment shorter than the `max_len` it passed, and before
///   passing a `max_len` larger than the run's segment size. It also ends the run before a
///   segment for another path, destination, source address or TOS, and before dropping the sink.
/// - `end_run(meta)` describes exactly the open run: `meta.segments` is its segment count,
///   `meta.tx` holds one sequence number per segment in order, and `meta.segment_size` is its
///   first segment's length. A backend may send one run as several GSO sends (at its segment
///   limit, at the 64 KiB limit of one UDP send, or where a run breaks the size rule); each
///   part carries the run's metadata, and reports cover the matching parts of `meta.tx`. A run
///   with `meta.sealed` false never leaves and is reported as [`TxReport::Dropped`].
/// - A [`SlotId`] of an ended segment stays valid until its run is sent or dropped. A slot
///   abandoned by `end_segment(0)`, by the next `next_segment` call or by dropping the sink goes
///   back to the backend at once, and its `SlotId` may be lent again by the next call.
pub trait SegmentSink {
    /// Lends a slot of exactly `min(max_len, max_datagram)` bytes for the next datagram, or
    /// returns `None` when the backend refuses:
    ///
    /// - data while the backend has an EAGAIN backlog, until the backlog has left;
    /// - data while the connection's built but unsent bytes would pass the backend's limit,
    ///   until a flush sends them;
    /// - data when every slot outside the urgent reserve is still in use after the backend flushed
    ///   on its own, as when the caller's own open run holds the pool;
    /// - urgent segments, while data is refused for one of the first two reasons, once the
    ///   connection's urgent quota is used up, and in any case once the slot pool is empty.
    ///
    /// `None` ends the attempt with [`Stop::Socket`].
    fn next_segment(&mut self, max_len: u16, class: TxClass) -> Option<(SlotId, &mut [u8])>;

    /// Finishes the lent slot with a datagram of `len` bytes, appended to the open run; 0
    /// abandons the slot and leaves the run unchanged.
    fn end_segment(&mut self, len: u16);

    /// Closes the open run, described by `meta`.
    fn end_run(&mut self, meta: TxMeta);
}

/// Why a backend dropped datagrams it had accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The backend's local queue overflowed.
    LocalQueue,
    /// The send failed with an error that proves the bytes did not leave.
    Error,
}

/// A backend's report about datagrams it accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxReport {
    /// The datagrams certainly did not leave. The connection declares their packets lost at once,
    /// without a congestion response.
    Dropped {
        /// The datagrams.
        tx: TxSeqRange,
        /// Why.
        reason: DropReason,
    },
    /// The datagrams were handed to the kernel.
    Flushed {
        /// The datagrams.
        tx: TxSeqRange,
    },
}

/// Why an attempt stopped. Each stop has one wake rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The connection does not have anything to send. Wake on the next input.
    Idle,
    /// The congestion window is full. Wake on an ACK, or the PTO in `next_deadline`.
    Cwnd,
    /// The pacer holds the next paced run until this time, its release less the build horizon,
    /// when an attempt can build it. Wake then.
    Pacing(Instant),
    /// The path's anti-amplification credit is used up. Wake on ingress on that path.
    Amplification,
    /// New stream bytes wait for connection credit. Wake on MAX_DATA.
    ConnFlowControl,
    /// The candidate's space does not have a write key yet. Wake on ingress that installs keys.
    KeysPending,
    /// [`TxLimits::max_segments`] datagrams were built, or the rest of the batch could not hold a
    /// full paced run, which waits for the next attempt. Re-queue at the tail of the phase.
    BatchFull,
    /// The egress grant ([`TxLimits::max_bytes`]) is used up. Wake on the next grant.
    Endpoint,
    /// The backend refused a slot. Wake when it is writable again.
    Socket,
    /// The connection is closing or draining and does not have anything to send. Wake on ingress
    /// or the drain deadline.
    Closed,
    /// A candidate did not fit an empty packet, so the attempt did not build anything. Such stops
    /// are counted and dumped for diagnosis.
    Inconsistent,
}

/// The limits of one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxLimits {
    /// The current time.
    pub now: Instant,
    /// The most datagrams to build.
    pub max_segments: u16,
    /// The largest datagram the backend accepts.
    pub max_datagram: u16,
    /// The egress grant in bytes; `u32::MAX` when unlimited.
    pub max_bytes: u32,
    /// The backend's clock epoch if it holds datagrams until their [`Release::At`]; `None`
    /// without release support.
    pub epoch: Option<ClockEpoch>,
}

/// The result of an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOutcome {
    /// Datagrams built and sealed.
    pub datagrams: u16,
    /// Bytes in those datagrams.
    pub bytes: u32,
    /// Why the attempt stopped.
    pub stop: Stop,
    /// When an attempt can next build a pacing-blocked candidate, whatever the stop: its
    /// release less the build horizon; always later than `now`.
    pub pacing_at: Option<Instant>,
    /// The release of the attempt's first run released after `now`, if any. Runs are released
    /// at `now` without a build horizon, so it is then always `None`.
    pub ahead: Option<Instant>,
    /// Whether the attempt built a run released at `now`.
    pub due: bool,
}

/// A description of what the next attempt would do and why, for logs and dumps. Its contents are
/// diagnostic and may change.
#[derive(Clone)]
pub struct TxExplain {
    /// The stop the attempt would report.
    pub stop: Stop,
    /// When an attempt can next build a pacing-blocked candidate: its release less the build
    /// horizon.
    pub pacing_at: Option<Instant>,
    /// One line per frame source with a candidate: its space, class and the limit that admits
    /// or refuses it.
    pub detail: String,
}

impl fmt::Debug for TxExplain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "stop: {:?}, pacing_at: {:?}", self.stop, self.pacing_at)?;
        f.write_str(&self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_epoch_maps_instants_to_the_backends_ticks_and_saturates() {
        let t0 = crate::recovery::test_epoch() + Duration::from_secs(1);
        let epoch = ClockEpoch {
            instant: t0,
            tick: Tick(1_000_000),
        };
        assert_eq!(epoch.tick_at(t0), Tick(1_000_000));
        assert_eq!(
            epoch.tick_at(t0 + Duration::from_micros(209)),
            Tick(1_209_000)
        );
        assert_eq!(epoch.tick_at(t0 - Duration::from_nanos(5)), Tick(999_995));
        assert_eq!(epoch.tick_at(t0 - Duration::from_millis(2)), Tick(0));
        let late = ClockEpoch {
            instant: t0,
            tick: Tick(u64::MAX - 1),
        };
        assert_eq!(late.tick_at(t0 + Duration::from_secs(1)), Tick(u64::MAX));
    }
}
