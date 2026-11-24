/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! UDP I/O backends for mvfstr.
//!
//! The endpoint driver is generic over a backend that owns every packet buffer. A
//! [`TxBackend`] lends slots to connections through a
//! [`SegmentSink`](mvfstr_proto::SegmentSink), batches GSO runs into system calls, and reports
//! what happened to each datagram; an [`RxBackend`] receives batches of datagrams with their
//! metadata. Capabilities are probed once at bind into a [`TxCaps`] that stays fixed. The
//! backend type, a [`Backend`], is chosen when the endpoint is built and the driver is
//! monomorphized for it, so per-packet calls are not dispatched dynamically.
//!
//! [`MmsgBackend`] is the Linux backend: `sendmmsg` with UDP_SEGMENT, TOS and source-address
//! control messages, `recvmmsg` with UDP_GRO, and readiness through tokio's `AsyncFd`.
//! [`socket`] holds the socket setup it uses. Backends do not support building datagrams ahead
//! for timed release, recalling queued datagrams, or TX timestamps.

pub mod backend;
#[cfg(target_os = "linux")]
mod cmsg;
#[cfg(target_os = "linux")]
mod mmsg;
#[cfg(target_os = "linux")]
mod rx;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod timer;
#[cfg(target_os = "linux")]
mod tx;

pub use backend::Backend;
pub use backend::FlushOutcome;
pub use backend::RxBackend;
pub use backend::TxBackend;
pub use backend::TxCaps;
#[cfg(target_os = "linux")]
pub use mmsg::MmsgBackend;
#[cfg(target_os = "linux")]
pub use mmsg::MmsgOptions;
#[cfg(target_os = "linux")]
pub use socket::SocketOptions;
#[cfg(target_os = "linux")]
pub use timer::TimerFd;
#[cfg(target_os = "linux")]
pub use tx::MmsgSink;
