/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The connection's side of the stream API: the methods [`StreamMut`](crate::StreamMut) calls,
//! which supply the connection's clock, RTT and congestion window to the stream state.

use bytes::Bytes;
use mvfstr_wire::StreamId;
use roxygen_bufqueue::BufQueue;

use super::Connection;
use crate::AppCode;
use crate::CreditDue;
use crate::Prioritizer;
use crate::SendError;
use crate::SendOrder;
use crate::StreamError;
use crate::streams::conn::staging_budget;
use crate::streams::send_buf::SendBuffer;

impl<P: Prioritizer> Connection<P> {
    /// Returns the bytes the connection may stage on all its streams, from its congestion window.
    pub(super) fn staging_budget(&self) -> u64 {
        staging_budget(self.cc.cwnd())
    }

    /// Marks `Writable` on the streams of refused push senders whose allowance is back, after a
    /// receive batch (credit, acknowledgments) or a transmit attempt (staged bytes sent).
    pub(super) fn wake_writable(&mut self) {
        let budget = self.staging_budget();
        self.sources.streams.wake_writable(budget);
    }

    /// Returns stream `id`'s allowance: the bytes it may stage now.
    pub(crate) fn stream_allowance(&self, id: StreamId) -> u64 {
        self.sources.streams.allowance(id, self.staging_budget())
    }

    /// Stages the longest prefix of `data` that stream `id`'s allowance takes and returns its
    /// length.
    pub(crate) fn stream_send(
        &mut self,
        id: StreamId,
        data: &mut Bytes,
    ) -> Result<usize, SendError> {
        let budget = self.staging_budget();
        self.sources.streams.send(id, data, budget)
    }

    /// Stages a header and a shared payload on stream `id`, both or neither.
    pub(crate) fn stream_send_parts(
        &mut self,
        id: StreamId,
        header: Bytes,
        shared: Bytes,
    ) -> Result<(), SendError> {
        let budget = self.staging_budget();
        self.sources.streams.send_parts(id, header, shared, budget)
    }

    /// Ends stream `id`'s send half.
    pub(crate) fn stream_finish(&mut self, id: StreamId) -> Result<(), SendError> {
        self.sources.streams.finish(id)
    }

    /// Abandons stream `id`'s send half with RESET_STREAM carrying `code`.
    pub(crate) fn stream_reset(&mut self, id: StreamId, code: AppCode) -> Result<(), SendError> {
        self.sources.streams.reset(id, code)
    }

    /// Requests that the peer stop sending on stream `id` with `code`, and drops its ingress.
    pub(crate) fn stream_stop_sending(
        &mut self,
        id: StreamId,
        code: AppCode,
    ) -> Result<(), StreamError> {
        let srtt = self.recovery.rtt().smoothed();
        self.sources.streams.stop_sending(id, code, self.now, srtt)
    }

    /// Moves stream `id` to `order` in the wire order.
    pub(crate) fn stream_set_order(&mut self, id: StreamId, order: SendOrder) {
        if let Some(mut stream) = self.sources.streams.streams.stream(id) {
            stream.set_order(order);
        }
    }

    /// Marks stream `id`'s producer pending or ready.
    pub(crate) fn stream_set_producer_pending(&mut self, id: StreamId, pending: bool) {
        if let Some(mut stream) = self.sources.streams.streams.stream(id) {
            stream.set_producer_pending(pending);
        }
    }

    /// Tracks `offset` on stream `id`, for a `Progress` edge once every byte below it is
    /// acknowledged.
    pub(crate) fn stream_track(&mut self, id: StreamId, offset: u64) -> Result<(), SendError> {
        self.sources.streams.track(id, offset)
    }

    /// Returns stream `id`'s send buffer, if it has a send half here.
    pub(crate) fn stream_send_buf(&self, id: StreamId) -> Option<&SendBuffer> {
        self.sources.streams.send_buf(id)
    }

    /// Returns stream `id`'s readable bytes.
    pub(crate) fn stream_readable(&self, id: StreamId) -> &BufQueue {
        self.sources.streams.readable(id)
    }

    /// Returns whether stream `id`'s peer FIN and every byte before it arrived.
    pub(crate) fn stream_peer_finished(&self, id: StreamId) -> bool {
        self.sources.streams.peer_finished(id)
    }

    /// Consumes `n` of stream `id`'s readable bytes.
    pub(crate) fn stream_consume(
        &mut self,
        id: StreamId,
        n: usize,
    ) -> Result<CreditDue, StreamError> {
        let srtt = self.recovery.rtt().smoothed();
        self.sources.streams.consume(id, n, self.now, srtt)
    }
}
