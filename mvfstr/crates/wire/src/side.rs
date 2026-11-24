/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Endpoint roles and stream directions.

/// The role of an endpoint in a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The endpoint that initiated the connection.
    Client,
    /// The endpoint that accepted the connection.
    Server,
}

impl Side {
    /// Returns the other endpoint's role.
    pub const fn peer(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }

    /// Returns whether this is [`Side::Client`].
    pub const fn is_client(self) -> bool {
        matches!(self, Side::Client)
    }

    /// Returns whether this is [`Side::Server`].
    pub const fn is_server(self) -> bool {
        matches!(self, Side::Server)
    }
}

/// The direction of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Data flows both ways.
    Bi,
    /// Data flows only from the initiator to its peer.
    Uni,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_swaps_roles() {
        assert_eq!(Side::Client.peer(), Side::Server);
        assert_eq!(Side::Server.peer(), Side::Client);
        assert!(Side::Client.is_client() && !Side::Client.is_server());
        assert!(Side::Server.is_server() && !Side::Server.is_client());
    }
}
