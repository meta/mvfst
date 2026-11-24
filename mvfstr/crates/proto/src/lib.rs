/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The sans-IO QUIC protocol core of mvfstr.
//!
//! An [`Endpoint`] routes received datagrams to connections by connection ID and creates
//! [`Connection`]s; the caller (the driver) owns the connections in a slab and feeds them input:
//! received datagrams ([`Connection::recv_batch`]), timer expiries ([`Connection::on_deadline`])
//! and transmit reports ([`Connection::on_tx_report`]). [`Connection::poll_transmit`] builds and
//! seals packets straight into backend slots through a [`SegmentSink`] and a [`Sealer`], and
//! reports why it stopped ([`Stop`]), which sets what wakes the connection next. Applications use
//! streams through [`StreamMut`] and poll rare connection facts as [`ConnEvent`]s.
//!
//! The crate does not read a clock, own a socket, spawn a task, hold a waker or call user code
//! other than the sink and sealer passed in. Time and randomness are inputs. `clippy.toml`
//! forbids the clock calls, and a dependency test keeps runtime and socket crates out of the
//! crate's dependency tree.
//!
//! The building blocks (`recovery`, `cc`, `pacer`, `flow_control` and the stream buffers, map,
//! state machines and scheduler) are public modules that can be tested on their own; the
//! connection-level API is re-exported at the crate root.
//!
//! | Module | Contents |
//! |---|---|
//! | [`config`] | immutable configs and per-connection options |
//! | [`endpoint`] | routing, Initial acceptance, stateless replies |
//! | [`connection`] | the connection and its public operations |
//! | [`transmit`] | the transmit attempt, its stops and limits, I/O-neutral transmit types |
//! | [`receive`] | received datagrams and their metadata |
//! | `sources` | the frame sources, tried in a fixed order for each frame to write |
//! | [`streams`] | stream API, buffers, map, state machines, scheduler, guard |
//! | [`flow_control`] | connection and stream credit, receive windows |
//! | [`recovery`] | RTT, ACK tracking, sent packets, loss detection, PTO (RFC 9002) |
//! | [`cc`] | NewReno and CUBIC with explicit inputs and outputs |
//! | [`pacer`] | the per-path virtual departure clock |
//! | `cid` | connection IDs and their layouts, reset tokens, the connection RNG |
//! | [`events`] | connection, stream and endpoint events |
//! | [`testing`] | deterministic in-memory pair harness |

#![forbid(unsafe_code)]

pub mod cc;
pub mod config;
pub mod connection;
pub mod endpoint;
pub mod events;
pub mod flow_control;
pub mod pacer;
pub mod receive;
pub mod recovery;
pub mod streams;
pub mod testing;
pub mod transmit;

mod cid;
mod sources;

pub use bytes::Bytes;
pub use cid::CidLayout;
pub use cid::MvfstCid;
pub use cid::MvfstV2Fields;
pub use cid::parse_v2;
pub use config::AckPolicy;
pub use config::AlpnPolicy;
pub use config::ClientConfig;
pub use config::ClientTls;
pub use config::ConfigError;
pub use config::CongestionControl;
pub use config::ConnOptions;
pub use config::DatagramSize;
pub use config::EndpointConfig;
pub use config::KeyUpdatePolicy;
pub use config::ParamsLayout;
pub use config::SUPPORTED_VERSIONS;
pub use config::ServerConfig;
pub use config::ServerTls;
pub use config::TransportConfig;
pub use connection::ConnStats;
pub use connection::Connection;
pub use connection::PullReady;
pub use connection::RawTransportParams;
pub use connection::RawTransportParamsIter;
pub use connection::Readiness;
pub use connection::TlsDeliverError;
pub use endpoint::AcceptError;
pub use endpoint::ConnKey;
pub use endpoint::ConnectError;
pub use endpoint::Endpoint;
pub use endpoint::Incoming;
pub use endpoint::Inputs;
pub use endpoint::MVFST_INVALID;
pub use endpoint::Random;
pub use endpoint::Route;
pub use endpoint::RxDropReason;
pub use endpoint::SrcPortBlocklist;
pub use endpoint::SrcPortDrops;
pub use endpoint::StatelessKind;
pub use endpoint::StatelessReply;
pub use events::AppCode;
pub use events::CloseReason;
pub use events::ConnEvent;
pub use events::EndpointEvent;
pub use events::Initiator;
pub use events::PathEvent;
pub use events::StreamReady;
pub use mvfstr_crypto::InlineSealer;
pub use mvfstr_crypto::PacketKeys;
pub use mvfstr_crypto::SealError;
pub use mvfstr_crypto::SealJob;
pub use mvfstr_crypto::SealOutcome;
pub use mvfstr_crypto::Sealer;
pub use mvfstr_crypto::SlotAccess;
pub use mvfstr_crypto::SlotId;
pub use mvfstr_tls::TlsConnId;
pub use mvfstr_tls::TlsHost;
pub use mvfstr_tls::TlsInput;
pub use mvfstr_tls::TlsPoll;
pub use mvfstr_tls::TlsStep;
pub use mvfstr_wire::ConnectionId;
pub use mvfstr_wire::Dir;
pub use mvfstr_wire::ResetToken;
pub use mvfstr_wire::Side;
pub use mvfstr_wire::StreamId;
pub use mvfstr_wire::TransportErrorCode;
pub use mvfstr_wire::VarInt;
pub use mvfstr_wire::Version;
pub use receive::Ecn;
pub use receive::RecvSummary;
pub use receive::RxDatagram;
pub use receive::RxMeta;
pub use roxygen_bufqueue::BufQueue;
pub use streams::CreditDue;
pub use streams::OpenError;
pub use streams::SendError;
pub use streams::SendOrder;
pub use streams::StreamError;
pub use streams::StreamMut;
pub use transmit::ClockEpoch;
pub use transmit::DropReason;
pub use transmit::PathId;
pub use transmit::Release;
pub use transmit::SegmentSink;
pub use transmit::Stop;
pub use transmit::Tick;
pub use transmit::TxClass;
pub use transmit::TxExplain;
pub use transmit::TxLimits;
pub use transmit::TxMeta;
pub use transmit::TxOutcome;
pub use transmit::TxReport;
pub use transmit::TxSeqRange;
