/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Transport parameters: what a connection advertises and how it checks the peer's (RFC 9000).
//!
//! On MVFST connections mvfst does not send initial_source_connection_id or
//! original_destination_connection_id, so they are not required, but each is still checked when
//! present.

use std::time::Duration;

use mvfstr_wire::ConnectionId;
use mvfstr_wire::ResetToken;
use mvfstr_wire::Side;
use mvfstr_wire::TransportErrorCode;
use mvfstr_wire::TransportParameters;
use mvfstr_wire::VarInt;
use mvfstr_wire::Version;

use super::ConnError;
use super::GRANULARITY;
use crate::config::TransportConfig;

/// Returns max_ack_delay as advertised for an ACK timer of `delay` on a connection with build
/// horizon `horizon`: whole milliseconds rounded up, so the ACK timer never runs past it. With a
/// horizon, an ACK leaves up to the horizon after it is built, and the advertised value adds
/// the horizon and the timer granularity. The config builder and [`capped_horizon`] keep the
/// result below 2^14.
pub(crate) fn advertised_max_ack_delay(delay: Duration, horizon: Duration) -> u64 {
    let delay = if horizon.is_zero() {
        delay
    } else {
        delay.saturating_add(horizon).saturating_add(GRANULARITY)
    };
    let millis = delay.as_nanos().div_ceil(1_000_000);
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Returns `horizon`, lowered so that the max_ack_delay advertised with an ACK timer of
/// `max_ack_delay` stays below 2^14 ms, as RFC 9000 requires.
pub(crate) fn capped_horizon(horizon: Duration, max_ack_delay: Duration) -> Duration {
    let room = Duration::from_millis((1 << 14) - 1)
        .saturating_sub(GRANULARITY)
        .saturating_sub(max_ack_delay);
    horizon.min(room)
}

/// The connection IDs a connection's own parameters name.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalIds {
    /// The Source Connection ID of this endpoint's Initial packets.
    pub(crate) initial_scid: ConnectionId,
    /// For a server, the Destination Connection ID of the client's first Initial.
    pub(crate) original_dcid: Option<ConnectionId>,
    /// For a server, the stateless reset token of `initial_scid`.
    pub(crate) reset_token: Option<ResetToken>,
}

/// Returns the parameters a connection with `config` and build horizon `horizon` advertises.
pub(crate) fn local_params(
    config: &TransportConfig,
    horizon: Duration,
    ids: LocalIds,
) -> TransportParameters {
    let varint = |value: u64| VarInt::from_u64(value).unwrap_or(VarInt::MAX);
    let ack = config.ack_policy();
    TransportParameters {
        original_destination_connection_id: ids.original_dcid,
        max_idle_timeout: varint(
            config
                .idle_timeout()
                .map_or(0, |t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX)),
        ),
        max_udp_payload_size: VarInt::from_u32(u32::from(config.max_udp_payload_size())),
        initial_max_data: varint(config.max_data()),
        initial_max_stream_data_bidi_local: varint(config.max_stream_data_bidi_local()),
        initial_max_stream_data_bidi_remote: varint(config.max_stream_data_bidi_remote()),
        initial_max_stream_data_uni: varint(config.max_stream_data_uni()),
        initial_max_streams_bidi: varint(config.max_streams_bidi()),
        initial_max_streams_uni: varint(config.max_streams_uni()),
        ack_delay_exponent: VarInt::from_u32(u32::from(ack.ack_delay_exponent)),
        max_ack_delay: varint(advertised_max_ack_delay(ack.max_ack_delay, horizon)),
        active_connection_id_limit: varint(config.active_connection_id_limit()),
        initial_source_connection_id: Some(ids.initial_scid),
        stateless_reset_token: ids.reset_token,
        ..TransportParameters::default()
    }
}

/// What the peer's parameters must agree with (RFC 9000).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerIds {
    /// This endpoint's role.
    pub(crate) side: Side,
    /// The connection's version.
    pub(crate) version: Version,
    /// The Source Connection ID of the peer's first Initial packet.
    pub(crate) initial_scid: ConnectionId,
    /// The Destination Connection ID of the client's first Initial packet.
    pub(crate) original_dcid: ConnectionId,
}

/// Decodes and checks the peer's parameters.
pub(crate) fn peer_params(raw: &[u8], ids: PeerIds) -> Result<TransportParameters, ConnError> {
    let params = TransportParameters::decode(raw, &[])
        .map_err(|e| invalid(e.code(), "malformed transport parameters"))?;
    let error = |reason| invalid(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, reason);
    match ids.side {
        Side::Server => {
            // RFC 9000 lets only a server send these parameters.
            if params.original_destination_connection_id.is_some()
                || params.stateless_reset_token.is_some()
                || params.preferred_address.is_some()
                || params.retry_source_connection_id.is_some()
            {
                return Err(error("client sent a server-only transport parameter"));
            }
        }
        Side::Client => {
            // The client does not act on Retry, so this parameter must be absent (RFC 9000).
            if params.retry_source_connection_id.is_some() {
                return Err(error("retry_source_connection_id without a Retry"));
            }
            check_cid(
                params.original_destination_connection_id,
                ids.original_dcid,
                ids.version,
            )
            .map_err(|()| error("original_destination_connection_id mismatch"))?;
        }
    }
    check_cid(
        params.initial_source_connection_id,
        ids.initial_scid,
        ids.version,
    )
    .map_err(|()| error("initial_source_connection_id mismatch"))?;
    Ok(params)
}

/// Checks that a connection ID parameter matches `expected` and, on version 1, is present.
fn check_cid(
    sent: Option<ConnectionId>,
    expected: ConnectionId,
    version: Version,
) -> Result<(), ()> {
    match sent {
        Some(cid) if cid == expected => Ok(()),
        None if version == Version::MVFST => Ok(()),
        _ => Err(()),
    }
}

fn invalid(code: TransportErrorCode, reason: &'static str) -> ConnError {
    ConnError {
        code,
        frame_type: None,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> ConnectionId {
        ConnectionId::new(&[byte; 8]).unwrap()
    }

    fn encode(params: &TransportParameters) -> Vec<u8> {
        let mut out = Vec::new();
        params.encode(&mut out).unwrap();
        out
    }

    fn client_ids(version: Version) -> PeerIds {
        PeerIds {
            side: Side::Client,
            version,
            initial_scid: cid(2),
            original_dcid: cid(1),
        }
    }

    fn server_params() -> TransportParameters {
        local_params(
            &TransportConfig::default(),
            Duration::ZERO,
            LocalIds {
                initial_scid: cid(2),
                original_dcid: Some(cid(1)),
                reset_token: Some(ResetToken([5; 16])),
            },
        )
    }

    #[test]
    fn max_ack_delay_is_advertised_in_whole_milliseconds_rounded_up() {
        let zero = Duration::ZERO;
        assert_eq!(
            advertised_max_ack_delay(Duration::from_millis(25), zero),
            25
        );
        assert_eq!(
            advertised_max_ack_delay(Duration::from_micros(2_001), zero),
            3
        );
        assert_eq!(advertised_max_ack_delay(zero, zero), 0);
        let config = TransportConfig::builder()
            .ack_policy(crate::AckPolicy {
                max_ack_delay: Duration::from_micros(10_500),
                ..crate::AckPolicy::default()
            })
            .build()
            .unwrap();
        let params = local_params(
            &config,
            Duration::ZERO,
            LocalIds {
                initial_scid: cid(1),
                original_dcid: None,
                reset_token: None,
            },
        );
        assert_eq!(params.max_ack_delay, VarInt::from_u32(11));
    }

    #[test]
    fn a_horizon_adds_itself_and_the_timer_granularity_to_max_ack_delay_below_2_14_ms() {
        let ms = Duration::from_millis;
        assert_eq!(advertised_max_ack_delay(ms(25), Duration::ZERO), 25);
        assert_eq!(advertised_max_ack_delay(ms(25), ms(2)), 28);
        assert_eq!(
            advertised_max_ack_delay(ms(25), Duration::from_micros(2_500)),
            29
        );
        // The horizon is capped so that the sum stays below 2^14 ms.
        let bound = ms((1 << 14) - 1);
        assert_eq!(capped_horizon(ms(2), bound), Duration::ZERO);
        assert_eq!(capped_horizon(ms(2), bound - ms(2)), ms(1));
        assert_eq!(capped_horizon(ms(2), ms(25)), ms(2));
        let max_ack_delay = Duration::from_micros(16_381_500);
        let horizon = capped_horizon(ms(2), max_ack_delay);
        assert_eq!(horizon, Duration::from_micros(500));
        assert_eq!(advertised_max_ack_delay(max_ack_delay, horizon), 16_383);
        let ids = LocalIds {
            initial_scid: cid(1),
            original_dcid: None,
            reset_token: None,
        };
        let params = local_params(&TransportConfig::default(), ms(2), ids);
        assert_eq!(params.max_ack_delay, VarInt::from_u32(28));
    }

    #[test]
    fn local_params_carry_the_config_and_the_connection_ids() {
        let params = server_params();
        assert_eq!(params.initial_source_connection_id, Some(cid(2)));
        assert_eq!(params.original_destination_connection_id, Some(cid(1)));
        assert_eq!(params.max_idle_timeout, VarInt::from_u32(30_000));
        assert_eq!(params.max_udp_payload_size, VarInt::from_u32(1452));
        assert_eq!(params.initial_max_data, VarInt::from_u32(1 << 20));
        assert_eq!(params.max_ack_delay, VarInt::from_u32(25));
        assert_eq!(params.stateless_reset_token, Some(ResetToken([5; 16])));
    }

    #[test]
    fn a_client_accepts_the_servers_parameters_when_the_ids_match() {
        let raw = encode(&server_params());
        let params = peer_params(&raw, client_ids(Version::V1)).unwrap();
        assert_eq!(params.initial_max_data, VarInt::from_u32(1 << 20));
    }

    #[test]
    fn version_1_requires_the_connection_id_parameters() {
        let mut without_scid = server_params();
        without_scid.initial_source_connection_id = None;
        let mut without_odcid = server_params();
        without_odcid.original_destination_connection_id = None;
        for params in [without_scid, without_odcid] {
            let error = peer_params(&encode(&params), client_ids(Version::V1)).unwrap_err();
            assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        }
    }

    #[test]
    fn mvfst_needs_no_connection_id_parameters_but_checks_them_when_present() {
        let mut bare = server_params();
        bare.initial_source_connection_id = None;
        bare.original_destination_connection_id = None;
        assert!(peer_params(&encode(&bare), client_ids(Version::MVFST)).is_ok());
        let mut wrong = server_params();
        wrong.initial_source_connection_id = Some(cid(9));
        let error = peer_params(&encode(&wrong), client_ids(Version::MVFST)).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }

    #[test]
    fn mismatched_connection_ids_are_refused() {
        let mut params = server_params();
        params.original_destination_connection_id = Some(cid(7));
        let error = peer_params(&encode(&params), client_ids(Version::V1)).unwrap_err();
        assert_eq!(error.reason, "original_destination_connection_id mismatch");
    }

    #[test]
    fn a_server_refuses_server_only_parameters_from_a_client() {
        let ids = PeerIds {
            side: Side::Server,
            version: Version::V1,
            initial_scid: cid(2),
            original_dcid: cid(1),
        };
        let mut client = local_params(
            &TransportConfig::default(),
            Duration::ZERO,
            LocalIds {
                initial_scid: cid(2),
                original_dcid: None,
                reset_token: None,
            },
        );
        assert!(peer_params(&encode(&client), ids).is_ok());
        client.original_destination_connection_id = Some(cid(1));
        let error = peer_params(&encode(&client), ids).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }

    #[test]
    fn undecodable_parameters_are_a_transport_parameter_error() {
        let error = peer_params(&[0x01, 0x05, 0x40], client_ids(Version::V1)).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }
}
