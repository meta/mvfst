/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Packet processing, from received datagrams to the ACK decision made once per batch.
//!
//! A datagram's coalesced packets have their header protection removed, are decrypted, have their
//! packet numbers decoded and duplicates dropped, and have their frames dispatched with per-space
//! legality. A packet whose keys have not arrived is buffered until they do. The TLS glue is here
//! too: CRYPTO in and out, key installation and discard.

use std::time::Instant;

use bytes::Bytes;
use mvfstr_crypto::unprotect_header;
use mvfstr_tls::KeyChange;
use mvfstr_wire::AckFrame;
use mvfstr_wire::ConnectionId;
use mvfstr_wire::Dir;
use mvfstr_wire::Frame;
use mvfstr_wire::FrameKind;
use mvfstr_wire::Frames;
use mvfstr_wire::Header;
use mvfstr_wire::PacketType;
use mvfstr_wire::ResetToken;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::VarInt;
use mvfstr_wire::VersionNegotiation;
use mvfstr_wire::decode_packet_number;

use super::Buffered;
use super::ConnError;
use super::Connection;
use super::MAX_BUFFERED;
use super::MAX_CRYPTO_BUFFER;
use super::MIN_DATAGRAM;
use super::State;
use super::key_update::KeyPhases;
use super::key_update::ReadKey;
use super::level_space;
use super::on_losses;
use super::params;
use crate::AlpnPolicy;
use crate::CloseReason;
use crate::ConnEvent;
use crate::DatagramSize;
use crate::Initiator;
use crate::RecvSummary;
use crate::RxDatagram;
use crate::RxMeta;
use crate::cc::AckEvent;
use crate::endpoint::MIN_RESET;
use crate::recovery::Space;
use crate::recovery::sent::PacketEvent;
use crate::recovery::sent::SentFlags;
use crate::streams::recv_buf::RecvError;

/// The TLS no_application_protocol alert (RFC 9001).
const NO_APPLICATION_PROTOCOL: u8 = 120;
/// The Key Phase bit of a short header's first byte (RFC 9000).
const KEY_PHASE_BIT: u8 = 0x04;

/// Why a packet did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unopened {
    /// The keys are missing, or header protection could not be removed.
    Header,
    /// The AEAD rejected it: it failed authentication.
    Aead,
}

/// What the frames of one packet were, for the ACK decision and path handling.
#[derive(Clone, Copy, Debug)]
struct Received {
    ack_eliciting: bool,
    /// Only probing frames: PADDING, PATH_CHALLENGE, PATH_RESPONSE and NEW_CONNECTION_ID.
    probing: bool,
    /// The data of the packet's last PATH_CHALLENGE.
    challenge: Option<[u8; 8]>,
}

/// The header fields of one packet, copied out of the datagram so it can be decrypted in place.
#[derive(Clone, Copy, Debug)]
struct PacketInfo {
    ty: PacketType,
    long: bool,
    dcid: ConnectionId,
    scid: ConnectionId,
    pn_offset: usize,
    len: usize,
    version_ok: bool,
    /// Whether an Initial header carries a token.
    token: bool,
}

impl Connection {
    /// Processes one receive batch.
    pub(super) fn receive(
        &mut self,
        now: Instant,
        datagrams: &mut [RxDatagram<'_>],
    ) -> RecvSummary {
        let mut summary = RecvSummary::default();
        for datagram in datagrams.iter_mut() {
            let len = datagram.data.len() as u64;
            if datagram.meta.src == self.remote {
                self.path.received += len;
            } else {
                self.credit_received(datagram.meta.src, len);
            }
            self.stats.recv_bytes += len;
            // As RFC 9000 requires, a client takes packets only from the server's address, and a
            // peer does not migrate before the handshake is confirmed.
            let stranger = datagram.meta.src != self.remote
                && (self.side == Side::Client || !self.handshake.confirmed);
            if self.state == State::Drained || stranger {
                summary.dropped += 1;
                continue;
            }
            self.recv_datagram(now, datagram.meta, datagram.data, &mut summary);
        }
        self.replay_buffered(now, &mut summary);
        // The ACK decision is made once per batch, after every packet in it (RFC 9000).
        let policy = self.config.ack_policy();
        // The timer fires up to one granularity late, which the advertised max_ack_delay,
        // rounded up to whole milliseconds, absorbs.
        let delay = policy.max_ack_delay.saturating_sub(super::GRANULARITY);
        for (space, ack) in self.sources.ack.iter_mut().enumerate() {
            if !self.spaces[space].discarded {
                ack.decide(now, policy.eliciting_threshold, delay);
            }
        }
        summary
    }

    /// Processes the packets of one datagram, in order.
    fn recv_datagram(
        &mut self,
        now: Instant,
        meta: &RxMeta,
        data: &mut [u8],
        summary: &mut RecvSummary,
    ) {
        // Version Negotiation can matter only to a client that has not processed a packet; for
        // anyone else the datagram goes on, and may be a stateless reset.
        if self.side == Side::Client
            && self.stats.recv_packets == 0
            && let Ok(Header::VersionNegotiation(vn)) = Header::parse(data, self.local_cid.len())
        {
            if !self.recv_version_negotiation(&vn) {
                summary.dropped += 1;
            }
            return;
        }
        let datagram_len = data.len();
        // Copied before decryption in place overwrites it.
        let trailer = data
            .last_chunk::<{ ResetToken::LEN }>()
            .filter(|_| datagram_len >= MIN_RESET)
            .map(|tail| ResetToken(*tail));
        let processed = summary.packets;
        let mut offset = 0;
        let mut first_dcid = None;
        while offset < data.len() {
            let Some(info) = self.parse(&data[offset..]) else {
                // A malformed or unexpected header ends the datagram.
                summary.dropped += 1;
                break;
            };
            let packet = &mut data[offset..offset + info.len];
            offset += info.len;
            // Later packets for another connection ID are ignored (RFC 9000).
            if *first_dcid.get_or_insert(info.dcid) != info.dcid {
                summary.dropped += 1;
                continue;
            }
            self.recv_packet(now, meta, datagram_len, packet, info, summary);
        }
        // A datagram whose packets could not be processed may be a stateless reset (RFC 9000) if
        // it ends in the token of a peer ID this connection sends with and comes from the address
        // it sends to under that ID.
        if summary.packets == processed
            && let Some(trailer) = trailer
            && self.peer_tokens().contains(&Some((meta.src, trailer)))
        {
            self.enter_draining(now, CloseReason::Silent, Initiator::StatelessReset);
        }
    }

    /// Handles a Version Negotiation packet. A client abandons the attempt when the packet answers
    /// its first Initial and does not list any version it offered; it discards one that lists the
    /// version in use, comes after any other packet was processed, or does not echo its connection
    /// IDs. A server ignores it. Returns whether the connection was abandoned.
    fn recv_version_negotiation(&mut self, vn: &VersionNegotiation<'_>) -> bool {
        let answers_first_initial = self.side == Side::Client
            && self.state == State::Open
            && self.stats.recv_packets == 0
            && vn.dcid() == &self.local_cid[..]
            && vn.scid() == &self.original_dcid[..];
        if !answers_first_initial || vn.versions().any(|version| version == self.version) {
            return false;
        }
        self.push_event(ConnEvent::Closed {
            reason: CloseReason::NoCommonVersion,
            initiator: Initiator::Peer,
        });
        self.drained();
        true
    }

    /// Reads the header of the packet at the front of `data`, or `None` for a malformed header
    /// or a packet type that does not carry frames.
    fn parse(&self, data: &[u8]) -> Option<PacketInfo> {
        let Ok(Header::Protected(header)) = Header::parse(data, self.local_cid.len()) else {
            // Retry is not supported, and Version Negotiation is read before the packets.
            return None;
        };
        let long = header.version().is_some();
        Some(PacketInfo {
            ty: header.ty(),
            long,
            dcid: ConnectionId::new(header.dcid()).ok()?,
            scid: ConnectionId::new(header.scid()).ok()?,
            pn_offset: header.pn_offset(),
            len: header.packet_len(),
            version_ok: header.version().is_none_or(|v| v == self.version),
            token: !header.token().is_empty(),
        })
    }

    /// Processes one packet, or buffers it until its keys arrive.
    fn recv_packet(
        &mut self,
        now: Instant,
        meta: &RxMeta,
        datagram_len: usize,
        packet: &mut [u8],
        info: PacketInfo,
        summary: &mut RecvSummary,
    ) {
        let space = match info.ty {
            PacketType::Initial => Space::Initial,
            PacketType::Handshake => Space::Handshake,
            PacketType::OneRtt => Space::Data,
            // 0-RTT is not supported.
            PacketType::ZeroRtt => {
                summary.dropped += 1;
                return;
            }
        };
        let stale = !info.version_ok
            || self.spaces[space.index()].discarded
            || matches!(self.state, State::Draining { .. } | State::Drained)
            // A server discards an Initial in a datagram below 1,200 bytes (RFC 9000).
            || (self.side == Side::Server
                && space == Space::Initial
                && datagram_len < usize::from(MIN_DATAGRAM))
            // Once the peer's first Initial set its connection ID, long-header packets from
            // another one are not this peer's (RFC 9000).
            || (info.long
                && self.peer_initial_scid.is_some_and(|scid| scid != info.scid))
            // A server's Initial must not carry a token (RFC 9000).
            || (self.side == Side::Client && info.token);
        if stale {
            summary.dropped += 1;
            return;
        }
        // Past the integrity limit, packets are not opened and do not prompt the CLOSE again as
        // in other closing periods; only stateless resets may answer (RFC 9001).
        if self.integrity_exceeded {
            summary.dropped += 1;
            return;
        }
        if !self.can_open(space) {
            if self.buffered.len() < MAX_BUFFERED {
                self.buffered.push_back(Buffered {
                    space,
                    meta: *meta,
                    datagram_len,
                    data: packet.to_vec(),
                });
                summary.buffered += 1;
            } else {
                summary.dropped += 1;
            }
            return;
        }
        let (pn, first, read, payload) = match self.decrypt(space, packet, &info) {
            Ok(opened) => opened,
            Err(unopened) => {
                summary.dropped += 1;
                if unopened == Unopened::Aead {
                    self.on_auth_failure(now);
                }
                return;
            }
        };
        if self.sources.ack[space.index()].received().is_duplicate(pn) {
            summary.dropped += 1;
            return;
        }
        summary.packets += 1;
        self.stats.recv_packets += 1;
        // The reserved bits, readable once protection is removed, must be zero (RFC 9000).
        let reserved = if info.long { 0x0c } else { 0x18 };
        if first & reserved != 0 {
            self.close_on_error(
                now,
                ConnError::new(TransportErrorCode::PROTOCOL_VIOLATION, "reserved bits set"),
            );
            return;
        }
        if space == Space::Data
            && let Err(error) = self.on_one_rtt_opened(now, read, pn)
        {
            self.close_on_error(now, error);
            return;
        }
        if self.peer_initial_scid.is_none() && space == Space::Initial {
            // The client sends to the connection ID the server chose (RFC 9000).
            self.peer_initial_scid = Some(info.scid);
            self.sources.cids.peer.set_handshake_cid(info.scid);
        }
        if matches!(self.state, State::Closing { .. }) {
            self.recv_while_closing(now, payload);
            return;
        }
        // An RTT sample ends when the ACK arrived, not when its batch is processed (RFC 9002).
        let ack_time = meta.rx_time.min(now);
        match self.recv_frames(now, ack_time, space, &info, payload) {
            Err(error) => self.close_on_error(now, error),
            Ok(received) if self.state == State::Open => {
                self.sources.ack[space.index()].on_packet(
                    pn,
                    received.ack_eliciting,
                    meta.ecn,
                    meta.rx_time,
                );
                if space == Space::Data {
                    // Only the highest-numbered non-probing packet moves the connection, as
                    // RFC 9000 requires.
                    let newest = !received.probing
                        && self.largest_non_probing.is_none_or(|largest| pn > largest);
                    if newest {
                        self.largest_non_probing = Some(pn);
                    }
                    self.on_path_packet(
                        now,
                        meta.src,
                        info.dcid,
                        newest,
                        received.challenge,
                        datagram_len,
                    );
                    self.check_retire_bound(now);
                }
                self.idle.base = now;
                self.idle.sent_since_receive = false;
                // A Handshake packet proves that the client received the server's Initial, which
                // validates the address and ends the Initial space (RFC 9000, RFC 9001).
                if self.side == Side::Server && space == Space::Handshake {
                    self.path.validated = true;
                    self.discard_space(Space::Initial, now);
                }
            }
            Ok(_) => {}
        }
        // The Handshake keys go once the handshake is confirmed (RFC 9001), but only after the
        // packet that confirmed it: its later frames may repeat Handshake CRYPTO data, and new
        // Handshake data in them must still close the connection, as RFC 9001 requires.
        if self.handshake.confirmed {
            self.discard_space(Space::Handshake, now);
        }
    }

    /// Returns whether a packet in `space` can be opened now. A server does not open 1-RTT
    /// packets before the handshake completes, though it holds the keys (RFC 9001).
    fn can_open(&self, space: Space) -> bool {
        self.has_keys(space)
            && !(space == Space::Data && self.side == Side::Server && !self.handshake.complete)
    }

    /// Removes header protection and decrypts in place; returns the packet number, the
    /// unprotected first byte, the read keys used and the plaintext payload.
    fn decrypt<'p>(
        &self,
        space: Space,
        packet: &'p mut [u8],
        info: &PacketInfo,
    ) -> Result<(u64, u8, ReadKey, &'p [u8]), Unopened> {
        let keys = self.spaces[space.index()]
            .keys
            .as_ref()
            .ok_or(Unopened::Header)?;
        let pn_len = unprotect_header(keys.remote.header(), packet, info.pn_offset)
            .map_err(|_| Unopened::Header)?;
        let truncated = packet[info.pn_offset..info.pn_offset + pn_len]
            .iter()
            .fold(0u32, |acc, &byte| acc << 8 | u32::from(byte));
        let largest = self.sources.ack[space.index()]
            .received()
            .largest()
            .map(|(pn, _)| pn);
        let pn = decode_packet_number(largest, truncated, pn_len);
        let hdr_len = info.pn_offset + pn_len;
        let first = packet[0];
        let (read, remote) = match &self.key_phases {
            Some(phases) if space == Space::Data => {
                let read = phases.read_key(first & KEY_PHASE_BIT != 0, pn);
                (
                    read,
                    phases.remote(read, &keys.remote).ok_or(Unopened::Aead)?,
                )
            }
            _ => (ReadKey::Current, &keys.remote),
        };
        let (header, payload) = packet.split_at_mut(hdr_len);
        let plaintext = remote
            .packet()
            .decrypt_in_place(pn, header, payload)
            .map_err(|_| Unopened::Aead)?;
        Ok((pn, first, read, plaintext))
    }

    /// Counts a packet that failed authentication; past the integrity limit, the connection
    /// closes, as RFC 9001 requires.
    fn on_auth_failure(&mut self, now: Instant) {
        self.auth_failures += 1;
        if self.auth_failures > self.integrity_limit {
            self.integrity_exceeded = true;
            self.close_on_error(
                now,
                ConnError::new(
                    TransportErrorCode::AEAD_LIMIT_REACHED,
                    "more packets failed authentication than the integrity limit allows",
                ),
            );
        }
    }

    /// Handles a 1-RTT packet opened with `read` keys: the peer's key update is followed, and the
    /// previous keys are kept for three PTOs after the first packet under the current ones
    /// (RFC 9001).
    fn on_one_rtt_opened(&mut self, now: Instant, read: ReadKey, pn: u64) -> Result<(), ConnError> {
        let discard_at = now + 3 * self.pto_interval();
        let (Some(phases), Some(keys)) = (
            &mut self.key_phases,
            &mut self.spaces[Space::Data.index()].keys,
        ) else {
            return Ok(());
        };
        match read {
            ReadKey::Previous => {}
            ReadKey::Current => phases.on_received(pn, discard_at),
            ReadKey::Next => {
                // Packets with higher numbers never use older keys (RFC 9001).
                if phases.largest_recv().is_some_and(|largest| pn < largest) {
                    return Err(ConnError::new(
                        TransportErrorCode::KEY_UPDATE_ERROR,
                        "a newer key phase below the largest packet number",
                    ));
                }
                phases.advance(keys, Some(discard_at));
                phases.on_received(pn, discard_at);
            }
        }
        Ok(())
    }

    /// Dispatches the frames of a decrypted packet. `ack_time` is when the packet arrived, for
    /// RTT samples.
    fn recv_frames(
        &mut self,
        now: Instant,
        ack_time: Instant,
        space: Space,
        info: &PacketInfo,
        payload: &[u8],
    ) -> Result<Received, ConnError> {
        let ty = info.ty;
        let mut received = Received {
            ack_eliciting: false,
            probing: true,
            challenge: None,
        };
        let mut empty = true;
        for frame in Frames::new(payload) {
            let frame = frame.map_err(|e| ConnError {
                code: e.code(),
                frame_type: Some(e.frame_type()),
                reason: e.reason(),
            })?;
            empty = false;
            let kind = frame.kind();
            if !kind.allowed_in(ty) {
                return Err(ConnError {
                    code: TransportErrorCode::PROTOCOL_VIOLATION,
                    frame_type: Some(frame_type(kind)),
                    reason: "frame not allowed in this packet type",
                });
            }
            received.ack_eliciting |= kind.is_ack_eliciting();
            received.probing &= matches!(
                kind,
                FrameKind::Padding
                    | FrameKind::PathChallenge
                    | FrameKind::PathResponse
                    | FrameKind::NewConnectionId
            );
            match frame {
                Frame::Padding { .. } | Frame::Ping => {}
                Frame::Ack(ack) => self.recv_ack(ack_time, space, &ack)?,
                Frame::Crypto { offset, data } => self.recv_crypto(space, offset, data)?,
                Frame::HandshakeDone => self.recv_handshake_done()?,
                Frame::NewToken { .. } => self.recv_new_token()?,
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    let reason = CloseReason::Transport {
                        code: error_code,
                        frame_type: Some(frame_type),
                        reason: Bytes::copy_from_slice(reason),
                    };
                    self.enter_draining(now, reason, Initiator::Peer);
                    return Ok(received);
                }
                Frame::ApplicationClose { error_code, reason } => {
                    let reason = CloseReason::Application {
                        code: crate::AppCode(error_code),
                        reason: Bytes::copy_from_slice(reason),
                    };
                    self.enter_draining(now, reason, Initiator::Peer);
                    return Ok(received);
                }
                Frame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                } => {
                    let srtt = self.recovery.rtt().smoothed();
                    self.sources
                        .streams
                        .on_stream_frame(id, offset.into_inner(), data, fin, now, srtt)
                        .map_err(|e| ConnError {
                            frame_type: Some(frame_type(kind)),
                            ..e
                        })?;
                }
                Frame::MaxStreamData { id, max } => self
                    .sources
                    .streams
                    .on_max_stream_data(id, max.into_inner())
                    .map_err(|e| ConnError {
                        frame_type: Some(frame_type(kind)),
                        ..e
                    })?,
                Frame::StreamDataBlocked { id, .. } => self
                    .sources
                    .streams
                    .on_stream_data_blocked(id)
                    .map_err(|e| ConnError {
                        frame_type: Some(frame_type(kind)),
                        ..e
                    })?,
                Frame::MaxData(max) => self.sources.streams.on_max_data(max.into_inner()),
                Frame::DataBlocked(_) => self.sources.streams.on_data_blocked(),
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    let srtt = self.recovery.rtt().smoothed();
                    self.sources
                        .streams
                        .on_reset_stream(
                            id,
                            crate::AppCode(error_code),
                            final_size.into_inner(),
                            now,
                            srtt,
                        )
                        .map_err(|e| ConnError {
                            frame_type: Some(frame_type(kind)),
                            ..e
                        })?;
                }
                Frame::StopSending { id, error_code } => self
                    .sources
                    .streams
                    .on_stop_sending(id, crate::AppCode(error_code))
                    .map_err(|e| ConnError {
                        frame_type: Some(frame_type(kind)),
                        ..e
                    })?,
                Frame::MaxStreams { dir, max } => {
                    let available = self
                        .sources
                        .streams
                        .on_max_streams(dir, max.into_inner())
                        .map_err(|e| ConnError {
                            frame_type: Some(frame_type(kind)),
                            ..e
                        })?;
                    if available {
                        self.push_event(ConnEvent::StreamsAvailable { dir });
                    }
                }
                Frame::NewConnectionId {
                    seq,
                    retire_prior_to,
                    cid,
                    reset_token,
                } => {
                    self.sources
                        .cids
                        .peer
                        .on_new(
                            seq.into_inner(),
                            retire_prior_to.into_inner(),
                            cid,
                            reset_token,
                        )
                        .map_err(|e| ConnError {
                            frame_type: Some(frame_type(kind)),
                            ..e
                        })?;
                }
                Frame::RetireConnectionId { seq } => {
                    let retired = self
                        .sources
                        .cids
                        .local
                        .retire(seq.into_inner(), &info.dcid)
                        .map_err(|e| ConnError {
                            frame_type: Some(frame_type(kind)),
                            ..e
                        })?;
                    if let Some(cid) = retired {
                        self.endpoint_events
                            .push_back(crate::EndpointEvent::RetiredLocalCid { cid });
                        self.issue_cids();
                    }
                }
                Frame::PathChallenge(data) => received.challenge = Some(data),
                Frame::PathResponse(data) => self.on_path_response(now, data),
                Frame::StreamsBlocked { .. } => {}
            }
        }
        // A packet must hold at least one frame (RFC 9000).
        if empty {
            return Err(ConnError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "packet without frames",
            ));
        }
        Ok(received)
    }

    /// Handles a packet received while closing: it only prompts the CLOSE again, unless it
    /// carries the peer's CONNECTION_CLOSE, which starts draining.
    fn recv_while_closing(&mut self, now: Instant, payload: &[u8]) {
        for frame in Frames::new(payload).map_while(Result::ok) {
            let reason = match frame {
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => CloseReason::Transport {
                    code: error_code,
                    frame_type: Some(frame_type),
                    reason: Bytes::copy_from_slice(reason),
                },
                Frame::ApplicationClose { error_code, reason } => CloseReason::Application {
                    code: crate::AppCode(error_code),
                    reason: Bytes::copy_from_slice(reason),
                },
                _ => continue,
            };
            self.enter_draining(now, reason, Initiator::Peer);
            return;
        }
        self.on_packet_while_closing();
    }

    /// Processes an ACK frame that arrived at `ack_time`: newly acknowledged and lost packets go
    /// back to the sources that sent their frames. Loss detection runs as of that time too; a
    /// loss that falls due before the batch is processed sets a loss time `next_deadline`
    /// already reports.
    fn recv_ack(
        &mut self,
        ack_time: Instant,
        space: Space,
        ack: &AckFrame<'_>,
    ) -> Result<(), ConnError> {
        let exponent = u32::from(self.peer_ack_delay_exponent);
        let micros = ack
            .delay()
            .into_inner()
            .checked_shl(exponent)
            .filter(|scaled| scaled >> exponent == ack.delay().into_inner())
            .unwrap_or(u64::MAX);
        let delay = std::time::Duration::from_micros(micros);
        let Self {
            recovery,
            sources,
            stats,
            cc,
            app_limited,
            ..
        } = self;
        let mut acked_in_recovery = 0;
        let outcome = recovery
            .on_ack_received(space, ack.ranges(), delay, ack_time, |event| {
                if let PacketEvent::Acked(packet) = &event
                    && packet.flags.contains(SentFlags::IN_FLIGHT)
                    && packet.on_path
                    && cc.in_recovery(packet.time_sent)
                {
                    acked_in_recovery += u64::from(packet.size);
                }
                sources.on_packet_event(Some(space), event, false);
            })
            .map_err(|e| ConnError {
                code: e.code(),
                frame_type: Some(frame_type(FrameKind::Ack)),
                reason: "ACK of a packet never sent",
            })?;
        stats.lost_packets += u64::from(outcome.loss.lost_packets);
        on_losses(cc, ack_time, &outcome.loss);
        if let Some((_, sent)) = outcome.ack.largest_newly_acked {
            cc.on_ack(&AckEvent {
                now: ack_time,
                acked_bytes: outcome.ack.acked_bytes,
                acked_in_recovery,
                largest_acked_sent: sent,
                rtt: recovery.rtt().smoothed(),
                rtt_sample: outcome.ack.rtt_sample,
                app_limited: *app_limited,
            });
        }
        if let Some(start) = outcome.spurious_congestion {
            cc.on_spurious_loss(start);
        }
        if space == Space::Data
            && let (Some(phases), Some(largest)) = (
                &mut self.key_phases,
                self.recovery.space(Space::Data).largest_acked(),
            )
        {
            phases.on_acked(largest, ack_time);
        }
        Ok(())
    }

    /// Takes CRYPTO bytes at `space`'s level (RFC 9001).
    fn recv_crypto(&mut self, space: Space, offset: VarInt, data: &[u8]) -> Result<(), ConnError> {
        let read_space = level_space(self.tls.read_level());
        let buf = &mut self.spaces[space.index()].crypto_recv;
        let end = offset.into_inner() + data.len() as u64;
        if space < read_space {
            // At a level TLS has finished reading, the peer may only repeat bytes it already sent.
            if end > buf.highest() {
                return Err(ConnError::new(
                    TransportErrorCode::PROTOCOL_VIOLATION,
                    "new CRYPTO data at a finished level",
                ));
            }
            return Ok(());
        }
        if end > buf.read_offset() + MAX_CRYPTO_BUFFER {
            return Err(ConnError::new(
                TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                "too much CRYPTO data out of order",
            ));
        }
        buf.insert(offset.into_inner(), data, false, &mut self.crypto_pool)
            .map_err(|e| match e {
                RecvError::TooManyRanges => ConnError::new(
                    TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                    "CRYPTO data too fragmented",
                ),
                RecvError::FinalSize | RecvError::OffsetOverflow => {
                    ConnError::new(e.code(), "CRYPTO data beyond the largest offset")
                }
            })?;
        if space == read_space {
            self.feed_tls()?;
        }
        Ok(())
    }

    /// Feeds TLS the in-order CRYPTO bytes of the level it reads, drains its output, and
    /// repeats at each new read level, where bytes may already be buffered.
    fn feed_tls(&mut self) -> Result<(), ConnError> {
        loop {
            let level = self.tls.read_level();
            let space = level_space(level).index();
            while let Some(front) = self.spaces[space].crypto_recv.readable().front().cloned() {
                self.tls.read_crypto(level, &front).map_err(|e| ConnError {
                    code: e.transport_error_code(),
                    frame_type: Some(frame_type(FrameKind::Crypto)),
                    reason: "TLS handshake failed",
                })?;
                self.spaces[space]
                    .crypto_recv
                    .consume(front.len(), &mut self.crypto_pool)
                    .expect("should consume bytes that are readable");
            }
            self.drain_tls()?;
            if self.tls.read_level() == level {
                return Ok(());
            }
            // When TLS moves to a new level, data of the old level must not be left (RFC 9001).
            let old = &self.spaces[space].crypto_recv;
            if old.highest() > old.read_offset() {
                return Err(ConnError::new(
                    TransportErrorCode::PROTOCOL_VIOLATION,
                    "unread CRYPTO data at a finished level",
                ));
            }
        }
    }

    /// Takes TLS's output: CRYPTO bytes to send at each level and new keys; then the peer's
    /// transport parameters and handshake completion, once TLS has them.
    pub(super) fn drain_tls(&mut self) -> Result<(), ConnError> {
        loop {
            self.tls_out.clear();
            let Some(output) = self.tls.write_crypto(&mut self.tls_out) else {
                break;
            };
            let space = level_space(output.level);
            if output.len > 0 && !self.spaces[space.index()].discarded {
                let bytes = Bytes::copy_from_slice(&self.tls_out[..output.len]);
                self.sources.crypto[space.index()]
                    .push(bytes)
                    .map_err(|_| {
                        ConnError::new(TransportErrorCode::INTERNAL_ERROR, "CRYPTO stream full")
                    })?;
            }
            match output.keys {
                Some(KeyChange::Handshake(keys)) => {
                    self.integrity_limit = self.integrity_limit.min(keys.remote.integrity_limit());
                    self.spaces[Space::Handshake.index()].keys = Some(keys);
                    self.recovery.set_handshake_keys();
                    self.replay_due = true;
                }
                Some(KeyChange::OneRtt { keys, update }) => {
                    self.integrity_limit = self.integrity_limit.min(keys.remote.integrity_limit());
                    self.key_phases = Some(KeyPhases::new(update, &keys));
                    self.spaces[Space::Data.index()].keys = Some(keys);
                    self.replay_due = true;
                }
                None => {}
            }
        }
        if self.handshake.peer_params.is_none()
            && let Some(raw) = self.tls.peer_transport_params()
        {
            let raw = raw.to_vec();
            self.apply_peer_params(&raw)?;
        }
        if !self.handshake.complete && self.tls.is_handshake_complete() {
            self.complete_handshake()?;
        }
        Ok(())
    }

    /// Checks and applies the peer's transport parameters.
    fn apply_peer_params(&mut self, raw: &[u8]) -> Result<(), ConnError> {
        let ids = params::PeerIds {
            side: self.side,
            version: self.version,
            initial_scid: self.peer_initial_scid.unwrap_or(ConnectionId::EMPTY),
            original_dcid: self.original_dcid,
        };
        let peer = params::peer_params(raw, ids)?;
        if self.side == Side::Client {
            let preferred = peer
                .preferred_address
                .as_ref()
                .map(|address| (address.connection_id, address.stateless_reset_token));
            self.sources
                .cids
                .peer
                .on_server_params(peer.stateless_reset_token, preferred);
        }
        self.recovery
            .set_peer_max_ack_delay(std::time::Duration::from_millis(
                peer.max_ack_delay.into_inner(),
            ));
        // The decoder accepts only exponents up to 20.
        self.peer_ack_delay_exponent =
            u8::try_from(peer.ack_delay_exponent.into_inner()).unwrap_or(20);
        if self.config.datagram_size() == DatagramSize::PeerMaximum {
            let peer_max =
                u16::try_from(peer.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX);
            self.mtu = peer_max
                .min(self.config.max_udp_payload_size())
                .max(MIN_DATAGRAM);
            self.cc
                .set_max_datagram_size(self.mtu)
                .map_err(|_| ConnError::new(TransportErrorCode::INTERNAL_ERROR, "datagram size"))?;
            self.pacer.set_max_datagram_size(self.mtu);
        }
        let available = self
            .sources
            .streams
            .on_peer_params(&peer)
            .map_err(|code| ConnError::new(code, "stream limit above 2^60"))?;
        for (dir, available) in [Dir::Bi, Dir::Uni].into_iter().zip(available) {
            if available {
                self.push_event(ConnEvent::StreamsAvailable { dir });
            }
        }
        self.handshake.peer_params = Some(peer);
        Ok(())
    }

    /// Completes the handshake, and for a server also confirms it (RFC 9001).
    fn complete_handshake(&mut self) -> Result<(), ConnError> {
        if self.alpn_policy == AlpnPolicy::Required && self.tls.alpn().is_none() {
            return Err(ConnError::new(
                TransportErrorCode::crypto(NO_APPLICATION_PROTOCOL),
                "no application protocol",
            ));
        }
        if self.handshake.peer_params.is_none() {
            return Err(ConnError::new(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                "no transport parameters",
            ));
        }
        self.handshake.complete = true;
        self.push_event(ConnEvent::Connected);
        self.issue_cids();
        if self.side == Side::Server {
            self.sources.crypto[Space::Data.index()].send_handshake_done();
            self.confirm();
        }
        self.replay_due = true;
        Ok(())
    }

    /// Handles HANDSHAKE_DONE, which confirms a client's handshake and which a client must not
    /// send (RFC 9000).
    fn recv_handshake_done(&mut self) -> Result<(), ConnError> {
        if self.side == Side::Server {
            return Err(ConnError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: Some(frame_type(FrameKind::HandshakeDone)),
                reason: "HANDSHAKE_DONE from a client",
            });
        }
        self.confirm();
        Ok(())
    }

    /// Handles NEW_TOKEN, which only a server may send (RFC 9000). A client does not keep the
    /// token, because Retry and resumption are not supported.
    fn recv_new_token(&self) -> Result<(), ConnError> {
        if self.side == Side::Server {
            return Err(ConnError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: Some(frame_type(FrameKind::NewToken)),
                reason: "NEW_TOKEN from a client",
            });
        }
        Ok(())
    }

    /// Confirms the handshake, after which ACK delays count; `recv_packet` discards the
    /// Handshake space once the packet being processed is done (RFC 9001).
    fn confirm(&mut self) {
        if self.handshake.confirmed {
            return;
        }
        self.handshake.confirmed = true;
        self.recovery.set_handshake_confirmed();
        self.push_event(ConnEvent::Confirmed);
    }

    /// Processes buffered packets whose keys have arrived, repeating while more become processable.
    fn replay_buffered(&mut self, now: Instant, summary: &mut RecvSummary) {
        while self.replay_due {
            self.replay_due = false;
            for mut packet in std::mem::take(&mut self.buffered) {
                if self.state == State::Drained {
                    break;
                }
                let Some(info) = self.parse(&packet.data) else {
                    continue;
                };
                // Counted as buffered when it arrived.
                let datagram_len = packet.datagram_len;
                let meta = packet.meta;
                let len = info.len.min(packet.data.len());
                self.recv_packet(
                    now,
                    &meta,
                    datagram_len,
                    &mut packet.data[..len],
                    info,
                    summary,
                );
            }
        }
    }
}

/// Returns the frame type of `kind` for the Frame Type field of a CONNECTION_CLOSE: the lowest
/// type value of its kind, such as 0x02 for any ACK frame and 0x08 for any STREAM frame.
pub(super) fn frame_type(kind: FrameKind) -> VarInt {
    VarInt::from_u32(match kind {
        FrameKind::Padding => 0x00,
        FrameKind::Ping => 0x01,
        FrameKind::Ack => 0x02,
        FrameKind::ResetStream => 0x04,
        FrameKind::StopSending => 0x05,
        FrameKind::Crypto => 0x06,
        FrameKind::NewToken => 0x07,
        FrameKind::Stream => 0x08,
        FrameKind::MaxData => 0x10,
        FrameKind::MaxStreamData => 0x11,
        FrameKind::MaxStreams => 0x12,
        FrameKind::DataBlocked => 0x14,
        FrameKind::StreamDataBlocked => 0x15,
        FrameKind::StreamsBlocked => 0x16,
        FrameKind::NewConnectionId => 0x18,
        FrameKind::RetireConnectionId => 0x19,
        FrameKind::PathChallenge => 0x1a,
        FrameKind::PathResponse => 0x1b,
        FrameKind::ConnectionClose => 0x1c,
        FrameKind::ApplicationClose => 0x1d,
        FrameKind::HandshakeDone => 0x1e,
    })
}
