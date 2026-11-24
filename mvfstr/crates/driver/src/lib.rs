/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The mvfstr endpoint driver on the Roxygen runtime, and the QUIC application traits.
//!
//! One [`EndpointDriver`] runs per Roxygen worker as a task polled only when woken. It owns the
//! worker's UDP sockets through I/O backends of the [`Backend`](mvfstr_io::Backend) type it is
//! built for, the sans-IO [`Endpoint`](mvfstr_proto::Endpoint) and a slab of connections with
//! their sessions. Each time it is woken it runs one turn: intake, application phase, transmit
//! and flush, receive, application phase, transmit and flush. Under a [`WorkBudget`], which the
//! drivers of one host share, a poll stops once the host's slice of time has closed and its next
//! poll continues where it stopped.
//! Applications implement [`QuicApplication`] (one per driver) and [`QuicSession`] (one per
//! connection); sessions run only between transport operations, through [`Conn`], so re-entry is
//! impossible. A panic in a session or its connection tears down that connection alone.
//! Server drivers of several workers that share an address spread new connections evenly over
//! the workers through a [`Steering`] group.

#![forbid(unsafe_code)]

mod app;
mod budget;
#[cfg(test)]
mod budget_tests;
mod conn;
mod endpoint;
#[cfg(test)]
mod gated;
#[cfg(test)]
mod lab;
mod slab;
mod steer;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
mod timers;
#[cfg(test)]
mod tls_tests;
mod turn;
mod wake;

pub use app::ConnInfo;
pub use app::QuicApplication;
pub use app::QuicSession;
pub use app::Refusal;
pub use budget::BudgetStats;
pub use budget::PollOutcome;
pub use budget::UnitKind;
pub use budget::WorkBudget;
pub use conn::Conn;
pub use conn::ConnHandle;
pub use conn::SendSink;
pub use conn::SinkError;
pub use endpoint::DriverConnectError;
pub use endpoint::DriverError;
pub use endpoint::EndpointDriver;
pub use endpoint::EndpointDriverBuilder;
pub use endpoint::EndpointHandle;
pub use roxygen_runtime::worker::SubmitError;
pub use steer::Steering;
pub use timers::FineTimer;
pub use timers::HostTimers;
pub use turn::EndpointStats;
