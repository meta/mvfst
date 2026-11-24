/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The input of [`Connection::recv_batch`](crate::Connection::recv_batch): received datagrams and
//! their metadata.
//!
//! A receive backend fills buffers with datagrams and describes each buffer with an [`RxMeta`];
//! a buffer holds one datagram or a GRO run of datagrams of `stride` bytes (the last may be
//! shorter). The driver splits buffers into datagrams, routes each through
//! [`Endpoint::route`](crate::Endpoint::route), and passes every datagram for one connection in
//! one [`recv_batch`](crate::Connection::recv_batch) call. Packets are decrypted in place in the
//! backend's buffer, so datagrams are lent mutably; payload that must outlive the call is copied.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Instant;

/// The ECN codepoint of a received datagram (RFC 3168).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Ecn {
    /// Not ECN-capable transport.
    #[default]
    NotEct,
    /// ECT(1).
    Ect1,
    /// ECT(0).
    Ect0,
    /// Congestion experienced.
    Ce,
}

/// The metadata of one receive buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxMeta {
    /// The sender's address.
    pub src: SocketAddr,
    /// The local address the datagrams were sent to, when the socket reports it.
    pub dst_ip: Option<IpAddr>,
    /// The ECN codepoint.
    pub ecn: Ecn,
    /// The size of each datagram in a GRO run; equal to the buffer length without GRO.
    pub stride: u16,
    /// When the datagrams arrived: the kernel's stamp, or the clock read after the receive call.
    pub rx_time: Instant,
}

/// One received datagram for [`Connection::recv_batch`](crate::Connection::recv_batch).
#[derive(Debug)]
pub struct RxDatagram<'a> {
    /// The metadata of the buffer the datagram came from.
    pub meta: &'a RxMeta,
    /// The datagram's bytes, which processing decrypts in place.
    pub data: &'a mut [u8],
}

/// What one [`recv_batch`](crate::Connection::recv_batch) call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvSummary {
    /// Packets decrypted and processed.
    pub packets: u32,
    /// Packets or datagrams discarded: undecryptable, duplicate, malformed or for a discarded
    /// space.
    pub dropped: u32,
    /// Packets buffered until their keys arrive.
    pub buffered: u32,
    /// Whether the connection may have work for its TLS host: an input from
    /// [`tls_input`](crate::Connection::tls_input), or a cancel from
    /// [`take_tls_cancel`](crate::Connection::take_tls_cancel).
    pub tls_due: bool,
}
