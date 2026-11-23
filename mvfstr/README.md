# mvfstr

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)][license]

mvfstr is a QUIC implementation in Rust for clients and servers. Its protocol
core is sans-IO and implements QUIC version 1 as RFC 9000, RFC 9001 and RFC
9002 define it. A UDP backend and an endpoint driver on the runtime of
[Roxygen][roxygen], Meta's HTTP library for Rust, run that core on sockets.
mvfstr runs on Linux only.

mvfstr is under active development, and its APIs will change before 1.0.

## Design

- **A sans-IO protocol core.** The protocol crates take received datagrams,
  the time and random bytes as inputs, and write packets into buffers that
  their caller owns. They do not read a clock, own a socket or spawn a task.
  A connection is plain data, driven through method calls, so tests can run a
  client and a server in memory on a virtual clock.
- **Connections stay on one thread.** An endpoint driver runs on each Roxygen
  worker thread and owns the worker's sockets and connections. Application
  code runs only between transport operations, so it does not re-enter the
  transport. Several workers can serve one address. With a `Steering` group
  and the reuseport program that `mvfstr_io` provides, the kernel delivers
  each datagram to the worker that its connection ID names.
- **Packets built in place.** A connection builds and seals each packet
  straight into a buffer of the UDP backend. The packet and frame codecs
  borrow from the bytes they parse and do not panic on a peer's bytes, and
  writing a packet does not allocate.
- **Batched Linux UDP.** The backend sends with `sendmmsg` and UDP generic
  segmentation offload, and receives with `recvmmsg` and UDP generic receive
  offload.
- **rustls for the handshake.** rustls runs the TLS 1.3 handshake through its
  QUIC API, and mvfstr implements QUIC packet protection and header
  protection itself.

## Features

- Clients and servers of QUIC version 1, and of mvfst's own version
  0xfaceb002, which mvfst's tperf client offers.
- Version negotiation, stateless resets, connection ID management and key
  updates.
- Loss recovery, and congestion control with NewReno or CUBIC (RFC 9438).
  Pacing at the congestion controller's rate is optional.
- Connection and stream flow control, with receive windows that can grow as
  mvfst's do.
- Streams scheduled by urgency, with incremental streams taking turns, as in
  RFC 9218.
- Passive migration: once the handshake is confirmed, a server follows a
  client that moves to a new address, for example after a NAT rebinding, and
  validates the new path.
- Servers that spread new connections over several worker threads.

## Current limits

- 0-RTT is not supported. A client does not keep the tokens that a server
  sends in NEW_TOKEN frames.
- A server does not send Retry packets, and a client discards them.
- The QUIC DATAGRAM extension (RFC 9221) is not supported.
- Path MTU discovery is not supported. A connection sends datagrams of 1,200
  bytes, or, if configured to, the smaller of the two endpoints'
  max_udp_payload_size once the peer's transport parameters arrive.
- QUIC version 2 is not supported.
- A client does not start a migration to a new address itself.
- mvfstr does not mark the packets it sends as ECN-capable.
- CUBIC uses Reno's slow start; HyStart++ is not implemented.

## Crates

| Crate | Contents |
| --- | --- |
| `mvfstr_wire` | QUIC wire formats: variable-length integers, connection IDs, packet headers, packet numbers, frames and transport parameters |
| `mvfstr_crypto` | QUIC packet protection, header protection, Initial keys, Retry integrity tags and key updates |
| `mvfstr_tls` | The QUIC TLS handshake over rustls, and the rustls configs it needs |
| `mvfstr_proto` | The sans-IO protocol core: endpoint, connections, streams, loss recovery, congestion control, pacing and flow control |
| `mvfstr_io` | Linux UDP I/O on `sendmmsg` and `recvmmsg`, with GSO and GRO |
| `mvfstr_driver` | Runs endpoints on Roxygen's runtime, with the `QuicApplication` and `QuicSession` traits that applications implement |

Each crate uses only the crates above it. An application that runs endpoints
on Roxygen's runtime uses `mvfstr_driver` with a backend from `mvfstr_io`,
the endpoint and server configs of `mvfstr_proto`, and the rustls config
helpers of `mvfstr_tls`, which take a provider such as
`mvfstr_crypto::default_provider`. It starts each driver on a worker of
Roxygen's `ferroxygen_runtime`. `mvfstr_proto` alone suits a program that
runs its own I/O and event loop.

## TLS crypto provider

mvfstr runs the TLS handshake on rustls. Packet protection, header protection
and key derivation run on [aws-lc-rs](https://github.com/aws/aws-lc-rs) by
default. To use [ring](https://github.com/briansmith/ring) instead, turn off
the default features of every mvfstr crate you depend on and turn on `ring`,
as here for the application above:

```toml
[dependencies]
mvfstr_crypto = { version = "0.1", default-features = false, features = ["ring"] }
mvfstr_driver = { version = "0.1", default-features = false, features = ["ring"] }
mvfstr_io = { version = "0.1", default-features = false, features = ["ring"] }
mvfstr_proto = { version = "0.1", default-features = false, features = ["ring"] }
mvfstr_tls = { version = "0.1", default-features = false, features = ["ring"] }
rustls = { version = "0.23", default-features = false, features = ["std"] }
```

Take rustls without its default features too, because they turn on aws-lc-rs.

mvfstr uses aws-lc-rs whenever its feature is on, even if `ring` is on too,
and a build with only `ring` on does not compile aws-lc-rs. A build with
neither feature fails to compile. `mvfstr_crypto::default_provider` returns
the rustls provider of the library in use; with aws-lc-rs it offers the
post-quantum key exchange X25519MLKEM768 first, and ring's provider does not
have it. The config helpers of `mvfstr_tls` take any rustls provider and
replace its TLS 1.3 cipher suites with ones that carry mvfstr's packet
protection. Key exchange, signature verification and randomness stay with
that provider.

To build and test the workspace with ring:

```sh
cargo test --workspace --no-default-features --features ring
```

## Building

mvfstr is a Cargo workspace in the `mvfstr` directory of [mvfst][mvfst]. Its
crates need Rust 1.95 or later.

```sh
cd mvfstr
cargo build --workspace --all-targets
cargo test --workspace
cargo doc --workspace --no-deps --open
```

`mvfstr_proto` and `mvfstr_driver` use Roxygen's `ferroxygen_bufqueue` and
`ferroxygen_runtime` crates, which Cargo takes from Roxygen's GitHub
repository. `Cargo.lock` holds the versions of Meta's internal build, so Cargo
may update it on the first build.

## mvfstr-tperf

The workspace also holds [`mvfstr_tperf`][tperf-crate], which builds
`mvfstr-tperf`. `mvfstr_tperf` is not published to crates.io. `mvfstr-tperf`
is a throughput tool that speaks the protocol of mvfst's [tperf][tperf], so
either tool's client can measure either tool's server. The server opens
unidirectional streams and writes to them until the client closes the
connection after `--duration` seconds; the client then prints the bytes it
received and the throughput, in tperf's format. The flags it shares with
tperf have tperf's defaults.

```sh
cargo build --release --bin mvfstr-tperf
target/release/mvfstr-tperf --mode=server &
target/release/mvfstr-tperf --mode=client --duration=10
```

A tperf client offers mvfst's version 0xfaceb002 without ALPN, which an
mvfstr-tperf server accepts. An mvfstr-tperf client offers version 1 with the
ALPN `quic_test`, which a tperf server selects, or, with
`--quic_version=mvfst`, what a tperf client offers. tperf prints its results
as glog INFO messages, which go to standard error with
`--logtostderr=1 --minloglevel=0`.

## mvfst and Roxygen

[mvfst][mvfst], the rest of this repository, is Meta's QUIC implementation in
C++. mvfstr is a separate implementation in Rust and does not use mvfst's
code. Where mvfst's behaviour matters for interoperation or for comparing the
two, mvfstr follows it: it speaks mvfst's version, its receive windows grow as
mvfst's do, and `mvfstr-tperf` speaks tperf's protocol.

[Roxygen][roxygen] is Meta's HTTP library for Rust. mvfstr's driver runs on
Roxygen's runtime, and `mvfstr_proto` holds received stream data in Roxygen's
`BufQueue`. Roxygen serves HTTP/3 over mvfstr: its `ferroxygen_h3` crate holds
the HTTP/3 server session, and `ferroxygen_server` serves HTTP/3 with its
`http3` feature.

## Contributing

See [CONTRIBUTING.md][contributing]. mvfstr is developed in Meta's internal
repository and exported to this one; pull requests are imported and land
there first. Report security issues as described in [SECURITY.md][security].
Everyone taking part in the project is expected to follow mvfst's
[code of conduct][code-of-conduct].

## License

mvfstr is licensed under the [MIT license][license].

[code-of-conduct]: https://github.com/meta/mvfst/blob/main/CODE_OF_CONDUCT.md
[contributing]: https://github.com/meta/mvfst/blob/main/mvfstr/CONTRIBUTING.md
[license]: https://github.com/meta/mvfst/blob/main/mvfstr/LICENSE
[mvfst]: https://github.com/meta/mvfst
[roxygen]: https://github.com/facebookincubator/roxygen
[security]: https://github.com/meta/mvfst/blob/main/mvfstr/SECURITY.md
[tperf]: https://github.com/meta/mvfst/tree/main/quic/tools/tperf
[tperf-crate]: https://github.com/meta/mvfst/tree/main/mvfstr/crates/tperf
