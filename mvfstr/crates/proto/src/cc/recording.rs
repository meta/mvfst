/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A test controller that takes rate samples: it keeps NewReno's window and records every send
//! event and every [`AckOrLoss`] it is given.

use std::fmt;
use std::time::Instant;

use super::AckOrLoss;
use super::AckPart;
use super::NewReno;
use super::SentEvent;
use crate::recovery::sent::LostSample;

/// An owned copy of one [`AckOrLoss`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Recorded {
    pub(crate) now: Instant,
    pub(crate) ack: Option<AckPart>,
    pub(crate) delivered: u64,
    pub(crate) total_sent: u64,
    pub(crate) bytes_in_flight: u64,
    pub(crate) lost: Vec<LostSample>,
    pub(crate) largest_lost_sent: Option<Instant>,
    pub(crate) persistent_congestion: bool,
    pub(crate) spurious: u32,
    pub(crate) newly_lost: u32,
    pub(crate) declared_lost: u32,
}

/// NewReno's window, with a record of its inputs.
#[derive(Clone)]
pub struct Recording {
    pub(crate) inner: NewReno,
    pub(crate) sent: Vec<SentEvent>,
    pub(crate) events: Vec<Recorded>,
    /// What [`Recording::on_ack_or_loss`] returns.
    pub(crate) mark_app_limited: bool,
}

impl Recording {
    pub(crate) fn new(inner: NewReno) -> Self {
        Self {
            inner,
            sent: Vec::new(),
            events: Vec::new(),
            mark_app_limited: false,
        }
    }

    pub(crate) fn on_sent(&mut self, sent: &SentEvent) {
        self.sent.push(*sent);
    }

    pub(crate) fn on_ack_or_loss(&mut self, event: &AckOrLoss<'_>) -> bool {
        self.events.push(Recorded {
            now: event.now,
            ack: event.ack,
            delivered: event.delivered,
            total_sent: event.total_sent,
            bytes_in_flight: event.bytes_in_flight,
            lost: event.lost.to_vec(),
            largest_lost_sent: event.largest_lost_sent,
            persistent_congestion: event.persistent_congestion,
            spurious: event.spurious,
            newly_lost: event.newly_lost,
            declared_lost: event.declared_lost,
        });
        self.mark_app_limited
    }
}

/// The window and the record's length, so the empty-attempt digest stays cheap as the record
/// grows.
impl fmt::Debug for Recording {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recording")
            .field("inner", &self.inner)
            .field("sent", &self.sent.len())
            .field("events", &self.events.len())
            .field("mark_app_limited", &self.mark_app_limited)
            .finish()
    }
}
