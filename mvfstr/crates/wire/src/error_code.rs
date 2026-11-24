/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Transport error codes (RFC 9000).

use std::fmt;

use crate::VarInt;

/// The error code of a CONNECTION_CLOSE frame of type 0x1c.
///
/// The code space is open: a peer may send any variable-length integer, so unknown codes are
/// representable and are shown by number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportErrorCode(VarInt);

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident = $value:literal,)*) => {
        impl TransportErrorCode {
            $(
                $(#[$doc])*
                pub const $name: TransportErrorCode = TransportErrorCode(VarInt::from_u32($value));
            )*

            /// Returns the RFC 9000 name of a listed code outside the CRYPTO_ERROR range.
            const fn name(self) -> Option<&'static str> {
                match self.0.into_inner() {
                    $($value => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }
    };
}

codes! {
    /// The connection is closed abruptly in the absence of any error.
    NO_ERROR = 0x00,
    /// The endpoint encountered an internal error and cannot continue.
    INTERNAL_ERROR = 0x01,
    /// The server refused to accept a new connection.
    CONNECTION_REFUSED = 0x02,
    /// More data was received than the advertised limits permit.
    FLOW_CONTROL_ERROR = 0x03,
    /// A frame named a stream beyond the advertised stream limit.
    STREAM_LIMIT_ERROR = 0x04,
    /// A frame arrived for a stream in a state that does not permit it.
    STREAM_STATE_ERROR = 0x05,
    /// Stream data or a final size contradicts the stream's final size.
    FINAL_SIZE_ERROR = 0x06,
    /// A frame was badly formatted, for instance of an unknown type.
    FRAME_ENCODING_ERROR = 0x07,
    /// The transport parameters were malformed, invalid, missing or forbidden.
    TRANSPORT_PARAMETER_ERROR = 0x08,
    /// The peer provided more connection IDs than active_connection_id_limit allows.
    CONNECTION_ID_LIMIT_ERROR = 0x09,
    /// A protocol violation not covered by a more specific code.
    PROTOCOL_VIOLATION = 0x0a,
    /// A client Initial carried an invalid Token field.
    INVALID_TOKEN = 0x0b,
    /// The application or application protocol closed the connection.
    APPLICATION_ERROR = 0x0c,
    /// More CRYPTO data arrived than the endpoint can buffer.
    CRYPTO_BUFFER_EXCEEDED = 0x0d,
    /// A key update failed (RFC 9001).
    KEY_UPDATE_ERROR = 0x0e,
    /// The AEAD confidentiality or integrity limit was reached.
    AEAD_LIMIT_REACHED = 0x0f,
    /// The network path cannot support QUIC.
    NO_VIABLE_PATH = 0x10,
}

impl TransportErrorCode {
    /// The first code of the CRYPTO_ERROR range, 0x0100.
    pub const CRYPTO_ERROR_FIRST: TransportErrorCode = TransportErrorCode(VarInt::from_u32(0x0100));
    /// The last code of the CRYPTO_ERROR range, 0x01ff.
    pub const CRYPTO_ERROR_LAST: TransportErrorCode = TransportErrorCode(VarInt::from_u32(0x01ff));

    /// Wraps a code as carried on the wire.
    pub const fn new(code: VarInt) -> Self {
        TransportErrorCode(code)
    }

    /// Returns the CRYPTO_ERROR for a TLS alert: 0x0100 plus the alert description (RFC 9001).
    pub const fn crypto(alert: u8) -> Self {
        TransportErrorCode(VarInt::from_u32(0x0100 + alert as u32))
    }

    /// Returns the TLS alert carried by a CRYPTO_ERROR code, or `None` outside 0x0100..=0x01ff.
    pub const fn crypto_alert(self) -> Option<u8> {
        match self.0.into_inner() {
            code @ 0x0100..=0x01ff => Some((code - 0x0100) as u8),
            _ => None,
        }
    }

    /// Returns the code as a variable-length integer.
    pub const fn to_varint(self) -> VarInt {
        self.0
    }

    /// Returns the code as an integer.
    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

impl From<VarInt> for TransportErrorCode {
    fn from(code: VarInt) -> Self {
        Self::new(code)
    }
}

impl From<TransportErrorCode> for VarInt {
    fn from(code: TransportErrorCode) -> Self {
        code.0
    }
}

impl fmt::Debug for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            f.write_str(name)
        } else if let Some(alert) = self.crypto_alert() {
            write!(f, "CRYPTO_ERROR({alert:#04x})")
        } else {
            write!(f, "{:#x}", self.into_inner())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_rfc_9000() {
        let codes = [
            (TransportErrorCode::NO_ERROR, 0x00),
            (TransportErrorCode::INTERNAL_ERROR, 0x01),
            (TransportErrorCode::CONNECTION_REFUSED, 0x02),
            (TransportErrorCode::FLOW_CONTROL_ERROR, 0x03),
            (TransportErrorCode::STREAM_LIMIT_ERROR, 0x04),
            (TransportErrorCode::STREAM_STATE_ERROR, 0x05),
            (TransportErrorCode::FINAL_SIZE_ERROR, 0x06),
            (TransportErrorCode::FRAME_ENCODING_ERROR, 0x07),
            (TransportErrorCode::TRANSPORT_PARAMETER_ERROR, 0x08),
            (TransportErrorCode::CONNECTION_ID_LIMIT_ERROR, 0x09),
            (TransportErrorCode::PROTOCOL_VIOLATION, 0x0a),
            (TransportErrorCode::INVALID_TOKEN, 0x0b),
            (TransportErrorCode::APPLICATION_ERROR, 0x0c),
            (TransportErrorCode::CRYPTO_BUFFER_EXCEEDED, 0x0d),
            (TransportErrorCode::KEY_UPDATE_ERROR, 0x0e),
            (TransportErrorCode::AEAD_LIMIT_REACHED, 0x0f),
            (TransportErrorCode::NO_VIABLE_PATH, 0x10),
            (TransportErrorCode::CRYPTO_ERROR_FIRST, 0x0100),
            (TransportErrorCode::CRYPTO_ERROR_LAST, 0x01ff),
        ];
        for (code, value) in codes {
            assert_eq!(code.into_inner(), value, "{code}");
        }
    }

    #[test]
    fn crypto_error_carries_the_tls_alert() {
        // no_application_protocol (120), the ALPN mismatch alert.
        assert_eq!(TransportErrorCode::crypto(0x78).into_inner(), 0x0178);
        assert_eq!(
            TransportErrorCode::crypto(0),
            TransportErrorCode::CRYPTO_ERROR_FIRST
        );
        assert_eq!(
            TransportErrorCode::crypto(0xff),
            TransportErrorCode::CRYPTO_ERROR_LAST
        );
        for alert in [0u8, 0x28, 0x78, 0xff] {
            assert_eq!(
                TransportErrorCode::crypto(alert).crypto_alert(),
                Some(alert)
            );
        }
    }

    #[test]
    fn codes_outside_the_crypto_range_carry_no_alert() {
        let outside = [0x00, 0x10, 0xff, 0x0200, 0x1_0100];
        for value in outside {
            let code = TransportErrorCode::new(VarInt::from_u32(value));
            assert_eq!(code.crypto_alert(), None, "{value:#x}");
        }
    }

    #[test]
    fn display_uses_rfc_names() {
        assert_eq!(
            TransportErrorCode::PROTOCOL_VIOLATION.to_string(),
            "PROTOCOL_VIOLATION"
        );
        assert_eq!(TransportErrorCode::NO_ERROR.to_string(), "NO_ERROR");
        assert_eq!(
            TransportErrorCode::crypto(0x78).to_string(),
            "CRYPTO_ERROR(0x78)"
        );
        let unknown = TransportErrorCode::new(VarInt::from_u32(0x4a2b));
        assert_eq!(unknown.to_string(), "0x4a2b");
        assert_eq!(format!("{unknown:?}"), "0x4a2b");
    }
}
