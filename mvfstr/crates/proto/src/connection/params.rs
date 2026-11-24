/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Transport parameters: what a connection advertises and how it checks the peer's (RFC 9000).
//!
//! On connections of MVFST and its alias, mvfst does not send initial_source_connection_id or
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
use crate::config::ParamsLayout;
use crate::config::TransportConfig;

/// The id of max_datagram_frame_size (RFC 9221), which decoding keeps among the parameters that
/// RFC 9000 does not define.
const MAX_DATAGRAM_FRAME_SIZE: VarInt = VarInt::from_u32(0x20);

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
    /// For a server that sent a Retry, the Retry's Source Connection ID.
    pub(crate) retry_scid: Option<ConnectionId>,
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
        disable_active_migration: config.disable_active_migration(),
        initial_source_connection_id: Some(ids.initial_scid),
        stateless_reset_token: ids.reset_token,
        retry_source_connection_id: ids.retry_scid,
        extra: config.extra_params().to_vec(),
        ..TransportParameters::default()
    }
}

/// Encodes the parameters a server connection on `version` advertises, in the layout of its
/// config, which must have been validated.
pub(crate) fn encode_server_params(
    config: &TransportConfig,
    version: Version,
    mut params: TransportParameters,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    let encoded = match config.params_layout() {
        ParamsLayout::Rfc => params.encode(&mut out),
        ParamsLayout::MvfstServer => {
            if version.unaliased() == Version::MVFST {
                params.original_destination_connection_id = None;
                params.initial_source_connection_id = None;
                params.retry_source_connection_id = None;
            }
            params.encode_in_mvfst_server_order(&mut out)
        }
    };
    encoded.expect("should encode the parameters of a validated transport config");
    out
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
    /// For a client that followed a Retry, the Retry's Source Connection ID.
    pub(crate) retry_scid: Option<ConnectionId>,
}

/// Decodes and checks the peer's parameters.
pub(crate) fn peer_params(raw: &[u8], ids: PeerIds) -> Result<TransportParameters, ConnError> {
    let params = TransportParameters::decode(raw, &[MAX_DATAGRAM_FRAME_SIZE])
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
            // RFC 9000 requires this parameter exactly when the client followed a Retry.
            match ids.retry_scid {
                Some(scid) => check_cid(params.retry_source_connection_id, scid, ids.version)
                    .map_err(|()| error("retry_source_connection_id mismatch"))?,
                None if params.retry_source_connection_id.is_some() => {
                    return Err(error("retry_source_connection_id without a Retry"));
                }
                None => {}
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
    max_datagram_frame_size(&params).map_err(|()| error("malformed max_datagram_frame_size"))?;
    Ok(params)
}

/// Returns the max_datagram_frame_size in `params`, or 0 when it is absent. Fails when its value is
/// not exactly one variable-length integer.
pub(crate) fn max_datagram_frame_size(params: &TransportParameters) -> Result<u64, ()> {
    let Some((_, value)) = params
        .extra
        .iter()
        .find(|(id, _)| *id == MAX_DATAGRAM_FRAME_SIZE)
    else {
        return Ok(0);
    };
    match VarInt::decode(value) {
        Ok((size, len)) if len == value.len() => Ok(size.into_inner()),
        _ => Err(()),
    }
}

/// Returns the parameters a client remembered with a session as 0-RTT uses them (RFC 9000):
/// those that describe the connection rather than the server's limits take their defaults.
pub(crate) fn zero_rtt_view(remembered: &TransportParameters) -> TransportParameters {
    let defaults = TransportParameters::default();
    TransportParameters {
        ack_delay_exponent: defaults.ack_delay_exponent,
        max_ack_delay: defaults.max_ack_delay,
        initial_source_connection_id: None,
        original_destination_connection_id: None,
        preferred_address: None,
        retry_source_connection_id: None,
        stateless_reset_token: None,
        ..remembered.clone()
    }
}

/// Returns whether a server that accepted 0-RTT lowered a limit the client may have used under
/// it, which RFC 9000 forbids.
pub(crate) fn early_limits_shrank(early: &TransportParameters, new: &TransportParameters) -> bool {
    let limits = |p: &TransportParameters| {
        [
            p.active_connection_id_limit,
            p.initial_max_data,
            p.initial_max_stream_data_bidi_local,
            p.initial_max_stream_data_bidi_remote,
            p.initial_max_stream_data_uni,
            p.initial_max_streams_bidi,
            p.initial_max_streams_uni,
        ]
    };
    limits(new)
        .iter()
        .zip(limits(early))
        .any(|(new, early)| *new < early)
}

/// Checks that a connection ID parameter matches `expected` and, on version 1 and its aliases, is
/// present.
fn check_cid(
    sent: Option<ConnectionId>,
    expected: ConnectionId,
    version: Version,
) -> Result<(), ()> {
    match sent {
        Some(cid) if cid == expected => Ok(()),
        None if version.unaliased() == Version::MVFST => Ok(()),
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

/// A peer's transport parameters extension as received: the raw bytes, which iterate as
/// (id, value) pairs in the order the peer sent them, unknown and reserved ids included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawTransportParams<'a> {
    raw: &'a [u8],
}

impl<'a> RawTransportParams<'a> {
    /// Wraps `raw`, an extension that [`peer_params`] accepted.
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Returns the extension's bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the parameters in the order the peer sent them, each as its id and raw value.
    pub fn iter(&self) -> RawTransportParamsIter<'a> {
        RawTransportParamsIter { rest: self.raw }
    }
}

impl<'a> IntoIterator for RawTransportParams<'a> {
    type Item = (VarInt, &'a [u8]);
    type IntoIter = RawTransportParamsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over the parameters of a [`RawTransportParams`] in wire order.
#[derive(Clone, Debug)]
pub struct RawTransportParamsIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for RawTransportParamsIter<'a> {
    type Item = (VarInt, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // The extension was decoded before it was kept, so every parameter is whole.
        let (id, id_len) = VarInt::decode(self.rest).ok()?;
        let rest = &self.rest[id_len..];
        let (len, len_len) = VarInt::decode(rest).ok()?;
        let rest = &rest[len_len..];
        let value = rest.get(..usize::try_from(len.into_inner()).ok()?)?;
        self.rest = &rest[value.len()..];
        Some((id, value))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::config::ConfigError;

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
            retry_scid: None,
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
                retry_scid: None,
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
                retry_scid: None,
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
            retry_scid: None,
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
    fn a_config_that_disables_active_migration_advertises_it() {
        assert!(!server_params().disable_active_migration);
        let config = TransportConfig::builder()
            .disable_active_migration(true)
            .build()
            .unwrap();
        let params = local_params(
            &config,
            Duration::ZERO,
            LocalIds {
                initial_scid: cid(2),
                original_dcid: Some(cid(1)),
                reset_token: Some(ResetToken([5; 16])),
                retry_scid: None,
            },
        );
        assert!(params.disable_active_migration);
        assert!(
            TransportParameters::decode(&encode(&params), &[])
                .unwrap()
                .disable_active_migration
        );
    }

    #[test]
    fn a_configs_extra_params_follow_the_rfc_ones_and_must_not_be_rfc_ids_or_repeat() {
        let legacy_receive_timestamps = (VarInt::from_u32(0xff0a001), Bytes::from_static(&[0]));
        let quic_experiment = (VarInt::from_u32(0x3a65db), Bytes::from_static(&[7]));
        let config = TransportConfig::builder()
            .extra_params(vec![
                legacy_receive_timestamps.clone(),
                quic_experiment.clone(),
            ])
            .build()
            .unwrap();
        let ids = LocalIds {
            initial_scid: cid(2),
            original_dcid: Some(cid(1)),
            reset_token: Some(ResetToken([5; 16])),
            retry_scid: None,
        };
        let params = local_params(&config, Duration::ZERO, ids);
        assert_eq!(
            params.extra,
            vec![legacy_receive_timestamps.clone(), quic_experiment]
        );
        let raw = encode(&params);
        assert!(raw.ends_with(&[0x8f, 0xf0, 0xa0, 0x01, 1, 0, 0x80, 0x3a, 0x65, 0xdb, 1, 7]));
        for refused in [
            vec![(VarInt::from_u32(0x0b), Bytes::from_static(&[1]))],
            vec![
                legacy_receive_timestamps.clone(),
                legacy_receive_timestamps.clone(),
            ],
        ] {
            assert_eq!(
                TransportConfig::builder().extra_params(refused).build(),
                Err(ConfigError::OutOfRange {
                    field: "extra_params"
                })
            );
        }
    }

    #[test]
    fn mvfsts_server_layout_writes_mvfsts_order_and_no_connection_ids_on_mvfst_versions() {
        let rfc = TransportConfig::default();
        let mvfst = TransportConfig::builder()
            .params_layout(ParamsLayout::MvfstServer)
            .build()
            .unwrap();
        let mut params = server_params();
        params.retry_source_connection_id = Some(cid(3));
        let mut in_mvfst_order = Vec::new();
        params
            .encode_in_mvfst_server_order(&mut in_mvfst_order)
            .unwrap();
        assert_ne!(in_mvfst_order, encode(&params));
        for version in [Version::V1, Version::QUIC_V1_ALIAS, Version::QUIC_V1_ALIAS2] {
            assert_eq!(
                encode_server_params(&mvfst, version, params.clone()),
                in_mvfst_order,
                "{version:?}"
            );
            assert_eq!(
                encode_server_params(&rfc, version, params.clone()),
                encode(&params),
                "{version:?}"
            );
        }
        let mut bare = params.clone();
        bare.original_destination_connection_id = None;
        bare.initial_source_connection_id = None;
        bare.retry_source_connection_id = None;
        let mut bare_in_mvfst_order = Vec::new();
        bare.encode_in_mvfst_server_order(&mut bare_in_mvfst_order)
            .unwrap();
        for version in [Version::MVFST, Version::MVFST_ALIAS] {
            assert_eq!(
                encode_server_params(&mvfst, version, params.clone()),
                bare_in_mvfst_order,
                "{version:?}"
            );
            assert_eq!(
                encode_server_params(&rfc, version, params.clone()),
                encode(&params),
                "{version:?}: the RFC layout keeps the ids"
            );
        }
    }

    #[test]
    fn a_client_accepts_the_servers_parameters_when_the_ids_match() {
        let raw = encode(&server_params());
        let params = peer_params(&raw, client_ids(Version::V1)).unwrap();
        assert_eq!(params.initial_max_data, VarInt::from_u32(1 << 20));
    }

    #[test]
    fn version_1_and_its_aliases_require_the_connection_id_parameters() {
        let mut without_scid = server_params();
        without_scid.initial_source_connection_id = None;
        let mut without_odcid = server_params();
        without_odcid.original_destination_connection_id = None;
        for version in [Version::V1, Version::QUIC_V1_ALIAS, Version::QUIC_V1_ALIAS2] {
            for params in [&without_scid, &without_odcid] {
                let error = peer_params(&encode(params), client_ids(version)).unwrap_err();
                assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
            }
        }
    }

    #[test]
    fn mvfst_and_its_alias_need_no_connection_id_parameters_but_check_them_when_present() {
        for version in [Version::MVFST, Version::MVFST_ALIAS] {
            let mut bare = server_params();
            bare.initial_source_connection_id = None;
            bare.original_destination_connection_id = None;
            assert!(
                peer_params(&encode(&bare), client_ids(version)).is_ok(),
                "{version:?}"
            );
            let mut wrong = server_params();
            wrong.initial_source_connection_id = Some(cid(9));
            let error = peer_params(&encode(&wrong), client_ids(version)).unwrap_err();
            assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        }
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
            retry_scid: None,
        };
        let mut client = local_params(
            &TransportConfig::default(),
            Duration::ZERO,
            LocalIds {
                initial_scid: cid(2),
                original_dcid: None,
                reset_token: None,
                retry_scid: None,
            },
        );
        assert!(peer_params(&encode(&client), ids).is_ok());
        client.original_destination_connection_id = Some(cid(1));
        let error = peer_params(&encode(&client), ids).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }

    #[test]
    fn a_max_datagram_frame_size_that_is_not_one_varint_is_a_transport_parameter_error() {
        let mut params = server_params();
        // Empty, a truncated varint, and a varint with a byte after it.
        for value in [&[][..], &[0x40], &[0x05, 0x00]] {
            params.extra = vec![(MAX_DATAGRAM_FRAME_SIZE, Bytes::copy_from_slice(value))];
            let error = peer_params(&encode(&params), client_ids(Version::V1)).unwrap_err();
            assert_eq!(
                error.code,
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                "{value:?}"
            );
        }
        params.extra = vec![(MAX_DATAGRAM_FRAME_SIZE, Bytes::from_static(&[0x05]))];
        let accepted = peer_params(&encode(&params), client_ids(Version::V1)).unwrap();
        assert_eq!(max_datagram_frame_size(&accepted), Ok(5));
    }

    #[test]
    fn retry_source_connection_id_is_required_exactly_after_a_retry() {
        let after_retry = PeerIds {
            retry_scid: Some(cid(3)),
            ..client_ids(Version::V1)
        };
        let mut retried = server_params();
        retried.retry_source_connection_id = Some(cid(3));
        assert!(peer_params(&encode(&retried), after_retry).is_ok());
        let error = peer_params(&encode(&retried), client_ids(Version::V1)).unwrap_err();
        assert_eq!(error.reason, "retry_source_connection_id without a Retry");
        let mut wrong = server_params();
        wrong.retry_source_connection_id = Some(cid(4));
        let error = peer_params(&encode(&wrong), after_retry).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        assert_eq!(error.reason, "retry_source_connection_id mismatch");
        let error = peer_params(&encode(&server_params()), after_retry).unwrap_err();
        assert_eq!(error.reason, "retry_source_connection_id mismatch");
        // The other two IDs are still checked after a Retry.
        let mut wrong_odcid = retried.clone();
        wrong_odcid.original_destination_connection_id = Some(cid(3));
        let error = peer_params(&encode(&wrong_odcid), after_retry).unwrap_err();
        assert_eq!(error.reason, "original_destination_connection_id mismatch");
        let mut wrong_iscid = retried;
        wrong_iscid.initial_source_connection_id = Some(cid(3));
        let error = peer_params(&encode(&wrong_iscid), after_retry).unwrap_err();
        assert_eq!(error.reason, "initial_source_connection_id mismatch");
    }

    #[test]
    fn the_zero_rtt_view_keeps_limits_and_defaults_the_connection_parameters() {
        let mut remembered = server_params();
        remembered.max_udp_payload_size = VarInt::from_u32(1200);
        remembered.max_idle_timeout = VarInt::from_u32(7_000);
        remembered.ack_delay_exponent = VarInt::from_u32(10);
        remembered.max_ack_delay = VarInt::from_u32(100);
        remembered.retry_source_connection_id = Some(cid(3));
        remembered.disable_active_migration = true;
        let view = zero_rtt_view(&remembered);
        let defaults = TransportParameters::default();
        assert_eq!(view.max_udp_payload_size, VarInt::from_u32(1200));
        assert_eq!(view.max_idle_timeout, VarInt::from_u32(7_000));
        assert_eq!(view.initial_max_data, remembered.initial_max_data);
        assert_eq!(
            view.initial_max_stream_data_bidi_remote,
            remembered.initial_max_stream_data_bidi_remote
        );
        assert_eq!(
            view.initial_max_streams_bidi,
            remembered.initial_max_streams_bidi
        );
        assert_eq!(
            view.active_connection_id_limit,
            remembered.active_connection_id_limit
        );
        assert!(view.disable_active_migration);
        assert_eq!(view.ack_delay_exponent, defaults.ack_delay_exponent);
        assert_eq!(view.max_ack_delay, defaults.max_ack_delay);
        assert_eq!(view.initial_source_connection_id, None);
        assert_eq!(view.original_destination_connection_id, None);
        assert_eq!(view.preferred_address, None);
        assert_eq!(view.retry_source_connection_id, None);
        assert_eq!(view.stateless_reset_token, None);
    }

    #[test]
    fn lowering_any_limit_0rtt_used_counts_and_other_parameters_do_not() {
        let early = zero_rtt_view(&server_params());
        assert!(!early_limits_shrank(&early, &server_params()));
        let lower = |change: fn(&mut TransportParameters)| {
            let mut new = server_params();
            change(&mut new);
            early_limits_shrank(&early, &new)
        };
        assert!(lower(|p| p.active_connection_id_limit = VarInt::from_u32(1)));
        assert!(lower(|p| p.initial_max_data = VarInt::from_u32(1)));
        assert!(lower(
            |p| p.initial_max_stream_data_bidi_local = VarInt::from_u32(1)
        ));
        assert!(lower(
            |p| p.initial_max_stream_data_bidi_remote = VarInt::from_u32(1)
        ));
        assert!(lower(
            |p| p.initial_max_stream_data_uni = VarInt::from_u32(1)
        ));
        assert!(lower(|p| p.initial_max_streams_bidi = VarInt::from_u32(1)));
        assert!(lower(|p| p.initial_max_streams_uni = VarInt::from_u32(1)));
        assert!(!lower(|p| p.max_idle_timeout = VarInt::from_u32(1_000)));
        assert!(!lower(|p| p.max_udp_payload_size = VarInt::from_u32(1_200)));
        assert!(!lower(|p| p.initial_max_data = VarInt::from_u32(1 << 30)));
    }

    #[test]
    fn undecodable_parameters_are_a_transport_parameter_error() {
        let error = peer_params(&[0x01, 0x05, 0x40], client_ids(Version::V1)).unwrap_err();
        assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }
}
