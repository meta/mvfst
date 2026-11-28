# Changelog

Notable changes to mvfstr are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- `StreamMut::credit_limit`, the peer's absolute limit on a send half, and
  `StreamMut::notify_credit_above`, which arms one `StreamReady::CreditRaised`
  edge for a raise of that limit above a given value. `StreamReady` gains the
  `CreditRaised` variant, so exhaustive matches on it need a new arm.

## 0.1.0

The first public version of mvfstr:

- A sans-IO QUIC core for clients and servers of QUIC version 1 (RFC 9000,
  RFC 9001 and RFC 9002) and of mvfst's version 0xfaceb002.
- QUIC packet protection on aws-lc-rs by default, or on ring, with rustls
  running the TLS 1.3 handshake.
- Loss recovery, NewReno and CUBIC congestion control, optional pacing, key
  updates, connection ID management, stateless resets and passive migration.
- A Linux UDP backend on `sendmmsg` and `recvmmsg`, with GSO and GRO.
- An endpoint driver on Roxygen's runtime, with optional steering by
  connection ID for several workers on one server address.
- `mvfstr-tperf`, a throughput tool compatible with mvfst's tperf. It is not
  published to crates.io.
