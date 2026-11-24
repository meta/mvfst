/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Streams.
//!
//! The public face is [`StreamMut`], obtained from [`Connection::stream`](crate::Connection::stream),
//! and [`SendOrder`], the priority every stream carries. The submodules hold the transport-owned
//! send and receive buffers, the stream map, the per-half state machines, the wire scheduler and
//! the guard through which every per-stream mutation goes.

mod api;
pub(crate) mod conn;
pub(crate) mod guard;
pub mod map;
pub mod recv_buf;
pub mod scheduler;
pub mod send_buf;
pub(crate) mod share;
pub mod state;

pub use api::CreditDue;
pub use api::OpenError;
pub use api::SendError;
pub use api::StreamError;
pub use api::StreamMut;
pub use scheduler::SendOrder;
