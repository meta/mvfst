/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Command-line flags: those of mvfst's tperf that matter for a fair comparison, with the same
//! defaults, in gflags syntax.

use std::fmt;
use std::str::FromStr;

use mvfstr_proto::CongestionControl;
use mvfstr_proto::recovery::RecoveryConfig;

use crate::object::HEADER_LEN;

/// Which side of the benchmark to run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Accept connections and send.
    #[default]
    Server,
    /// Connect, receive and measure.
    Client,
}

/// The QUIC version and ALPN a client offers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum QuicVersion {
    /// Version 1 with ALPN `quic_test`, which the mvfst tperf server selects.
    #[default]
    V1,
    /// MVFST (0xfaceb002) without ALPN, as the mvfst tperf client offers.
    Mvfst,
}

/// The event loop each side's worker runs on, and so the backend its endpoint uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HostLoop {
    /// A Roxygen managed worker on a tokio runtime, with `MmsgBackend`.
    #[default]
    Tokio,
    /// tperf's own epoll loop without a tokio runtime, with `HostBackend` on a `ManualHost`.
    Manual,
}

/// The layout of the connection IDs a side's endpoint issues.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CidFormat {
    /// mvfstr's own: random bytes.
    #[default]
    Random,
    /// mvfst's version 2 server connection ID.
    V2,
}

/// Where a server runs its TLS handshakes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TlsBackend {
    /// On rustls inside each connection.
    #[default]
    Inline,
    /// On a TLS host outside the connections: rustls behind the External interface, as a TLS
    /// library such as Fizz would run.
    External,
}

/// The parsed flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flags {
    pub(crate) mode: Mode,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) pin: bool,
    pub(crate) duration_secs: u32,
    pub(crate) block_size: usize,
    pub(crate) writes_per_loop: u16,
    pub(crate) window: u64,
    pub(crate) autotune_window: bool,
    pub(crate) congestion: CongestionControl,
    pub(crate) pacing: bool,
    pub(crate) gso: bool,
    pub(crate) max_cwnd_mss: u32,
    /// The data streams of each connection, which the server opens and the client reports.
    pub(crate) num_streams: u32,
    pub(crate) bytes_per_stream: u64,
    pub(crate) max_receive_packet_size: u16,
    pub(crate) override_packet_size: bool,
    pub(crate) compat_mvfst: bool,
    pub(crate) quic_version: QuicVersion,
    pub(crate) stats: bool,
    /// With `--pacing`, the pacing tick in µs instead of mvfst tperf's 200.
    pub(crate) pacing_granularity_us: Option<u32>,
    /// With `--pacing`, the minimum burst instead of mvfst's 5.
    pub(crate) pacing_min_burst: Option<u16>,
    /// Kernel release of the server's runs through SO_TXTIME.
    pub(crate) txtime: bool,
    /// With `--txtime`, how far ahead of its release, in µs, a server connection may build.
    pub(crate) build_horizon_us: Option<u32>,
    /// The event loop of this side's worker.
    pub(crate) host_loop: HostLoop,
    /// The server driver's work budget per poll, in µs; 0 runs it without one.
    pub(crate) work_budget_us: u32,
    /// The layout of the connection IDs this side issues.
    pub(crate) cid_format: CidFormat,
    pub(crate) tls_backend: TlsBackend,
    /// The connections a client opens to the server.
    pub(crate) num_conns: u32,
    /// Objects per second that the server writes to each stream; 0 writes as fast as it can.
    /// A client given the server's value reads the objects and measures each one's latency
    /// against the send time in its header, which is valid only when client and server run on
    /// the same host.
    pub(crate) object_rate: u32,
    /// The length of each object when `object_rate` is set, its 16-byte header included. The
    /// client counts an object of another length as bad.
    pub(crate) object_size: u32,
    /// This side's initial RTT in milliseconds, from 1 to an hour: the RTT assumed before the first
    /// sample. Without it the transport's default applies.
    pub(crate) initial_rtt_ms: Option<u32>,
}

/// The pacing tick mvfst tperf's `--pacing` sets, in µs.
pub(crate) const PACING_TICK_US: u32 = 200;

/// mvfst's default minimum pacing burst.
pub(crate) const MIN_BURST: u16 = 5;

/// The default `--object_size`, about one datagram's payload.
const OBJECT_SIZE: u32 = 1200;

impl Default for Flags {
    /// The defaults of mvfst's tperf.
    fn default() -> Self {
        Self {
            mode: Mode::Server,
            host: "::1".to_owned(),
            port: 6666,
            pin: false,
            duration_secs: 10,
            block_size: 1024 * 1024,
            writes_per_loop: 44,
            window: 1024 * 1024,
            autotune_window: true,
            congestion: CongestionControl::Cubic,
            pacing: false,
            gso: true,
            max_cwnd_mss: 860_000,
            num_streams: 1,
            bytes_per_stream: 0,
            max_receive_packet_size: 1452,
            override_packet_size: true,
            compat_mvfst: true,
            quic_version: QuicVersion::V1,
            stats: false,
            pacing_granularity_us: None,
            pacing_min_burst: None,
            txtime: false,
            build_horizon_us: None,
            host_loop: HostLoop::Tokio,
            work_budget_us: 0,
            cid_format: CidFormat::Random,
            tls_backend: TlsBackend::Inline,
            num_conns: 1,
            object_rate: 0,
            object_size: OBJECT_SIZE,
            initial_rtt_ms: None,
        }
    }
}

impl Flags {
    /// Parses the arguments after the program name.
    pub fn parse<I>(args: I) -> Result<Flags, FlagError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut flags = Flags::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let Some(body) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
                return Err(FlagError::Unknown(arg));
            };
            if let Some((name, value)) = body.split_once('=') {
                flags.set(name, value)?;
            } else if BOOL_FLAGS.contains(&body) {
                flags.set(body, "true")?;
            } else if let Some(name) = body.strip_prefix("no")
                && BOOL_FLAGS.contains(&name)
            {
                flags.set(name, "false")?;
            } else if VALUE_FLAGS.contains(&body) {
                let value = args
                    .next()
                    .ok_or_else(|| FlagError::MissingValue(body.to_owned()))?;
                flags.set(body, &value)?;
            } else {
                return Err(FlagError::Unknown(body.to_owned()));
            }
        }
        // Only the server opens and ends streams, as in mvfst tperf, and only it takes
        // `--tls_backend`. The client takes `--num_streams`, `--object_rate` and `--object_size`
        // too, with the server's values, to read what it receives and label its summary line.
        if flags.mode == Mode::Client {
            if flags.bytes_per_stream != 0 {
                return Err(FlagError::ServerOnly("bytes_per_stream"));
            }
            if flags.congestion == CongestionControl::Bbr3 {
                return Err(FlagError::Bbr3ServerSide);
            }
            if flags.tls_backend != TlsBackend::Inline {
                return Err(FlagError::ServerOnly("tls_backend"));
            }
        } else if flags.num_conns != 1 {
            return Err(FlagError::ClientOnly("num_conns"));
        }
        if flags.congestion == CongestionControl::Bbr3 && !flags.pacing {
            return Err(FlagError::Bbr3NeedsPacing);
        }
        if !flags.pacing {
            if flags.pacing_granularity_us.is_some() {
                return Err(FlagError::NeedsPacing("pacing_granularity_us"));
            }
            if flags.pacing_min_burst.is_some() {
                return Err(FlagError::NeedsPacing("pacing_min_burst"));
            }
            if flags.txtime {
                return Err(FlagError::TxtimeNeedsPacing);
            }
        }
        if flags.build_horizon_us.is_some() && !flags.txtime {
            return Err(FlagError::BuildHorizonNeedsTxtime);
        }
        // --writes_per_loop, which caps mvfst tperf's GSO sends, is the maximum burst when pacing.
        let min_burst = flags.pacing_min_burst.unwrap_or(MIN_BURST);
        if flags.pacing && flags.writes_per_loop < min_burst {
            return Err(FlagError::BatchBelowMinimumBurst {
                writes_per_loop: flags.writes_per_loop,
                min_burst,
            });
        }
        Ok(flags)
    }

    /// Sets flag `name` from `value`.
    fn set(&mut self, name: &str, value: &str) -> Result<(), FlagError> {
        let bad = || FlagError::BadValue {
            flag: name.to_owned(),
            value: value.to_owned(),
        };
        let bool_value = || parse_bool(value).ok_or_else(bad);
        match name {
            "mode" => {
                self.mode = match value {
                    "server" => Mode::Server,
                    "client" => Mode::Client,
                    _ => return Err(bad()),
                }
            }
            "host" => self.host = value.to_owned(),
            "port" => self.port = value.parse().map_err(|_| bad())?,
            "pin" => self.pin = bool_value()?,
            "duration" => self.duration_secs = positive(value).ok_or_else(bad)?,
            "block_size" => self.block_size = positive(value).ok_or_else(bad)?,
            "writes_per_loop" => self.writes_per_loop = positive(value).ok_or_else(bad)?,
            "window" => self.window = value.parse().map_err(|_| bad())?,
            "autotune_window" => self.autotune_window = bool_value()?,
            "congestion" => {
                self.congestion = match value {
                    "newreno" => CongestionControl::NewReno,
                    "cubic" => CongestionControl::Cubic,
                    "bbr3" => CongestionControl::Bbr3,
                    _ => return Err(bad()),
                }
            }
            "pacing" => self.pacing = bool_value()?,
            "gso" => self.gso = bool_value()?,
            "max_cwnd_mss" => self.max_cwnd_mss = value.parse().map_err(|_| bad())?,
            "num_streams" => self.num_streams = positive(value).ok_or_else(bad)?,
            "bytes_per_stream" => self.bytes_per_stream = value.parse().map_err(|_| bad())?,
            "max_receive_packet_size" => {
                self.max_receive_packet_size = value.parse().map_err(|_| bad())?
            }
            "override_packet_size" => self.override_packet_size = bool_value()?,
            "compat_mvfst" => self.compat_mvfst = bool_value()?,
            "quic_version" => {
                self.quic_version = match value {
                    "v1" => QuicVersion::V1,
                    "mvfst" => QuicVersion::Mvfst,
                    _ => return Err(bad()),
                }
            }
            "stats" => self.stats = bool_value()?,
            "pacing_granularity_us" => {
                self.pacing_granularity_us = Some(positive(value).ok_or_else(bad)?)
            }
            "pacing_min_burst" => self.pacing_min_burst = Some(positive(value).ok_or_else(bad)?),
            "txtime" => self.txtime = bool_value()?,
            "build_horizon_us" => self.build_horizon_us = Some(value.parse().map_err(|_| bad())?),
            "host_loop" => {
                self.host_loop = match value {
                    "tokio" => HostLoop::Tokio,
                    "manual" => HostLoop::Manual,
                    _ => return Err(bad()),
                }
            }
            "work_budget_us" => self.work_budget_us = value.parse().map_err(|_| bad())?,
            "cid_format" => {
                self.cid_format = match value {
                    "random" => CidFormat::Random,
                    "v2" => CidFormat::V2,
                    _ => return Err(bad()),
                }
            }
            "tls_backend" => {
                self.tls_backend = match value {
                    "inline" => TlsBackend::Inline,
                    "external" => TlsBackend::External,
                    _ => return Err(bad()),
                }
            }
            "num_conns" => self.num_conns = positive(value).ok_or_else(bad)?,
            "object_rate" => self.object_rate = value.parse().map_err(|_| bad())?,
            // An object holds at least its header.
            "object_size" => {
                self.object_size = value
                    .parse()
                    .ok()
                    .filter(|&size| size >= HEADER_LEN as u32)
                    .ok_or_else(bad)?
            }
            // The transport's bounds, checked here so that a bad value fails at parse.
            "initial_rtt_ms" => {
                self.initial_rtt_ms = Some(
                    positive(value)
                        .filter(|&ms: &u32| {
                            u128::from(ms) <= RecoveryConfig::MAX_TIMER_SETTING.as_millis()
                        })
                        .ok_or_else(bad)?,
                )
            }
            // glog's flags, which mvfst tperf needs to print its results.
            "minloglevel" | "v" => {}
            "logtostderr" => {
                bool_value()?;
            }
            _ => return Err(FlagError::Unknown(name.to_owned())),
        }
        Ok(())
    }
}

/// The boolean flags, which gflags also takes as `--flag` and `--noflag`.
const BOOL_FLAGS: [&str; 9] = [
    "pin",
    "autotune_window",
    "pacing",
    "txtime",
    "gso",
    "override_packet_size",
    "compat_mvfst",
    "stats",
    "logtostderr",
];

/// The flags that take a value, which gflags also takes from the next argument.
const VALUE_FLAGS: [&str; 26] = [
    "mode",
    "host",
    "port",
    "duration",
    "block_size",
    "writes_per_loop",
    "window",
    "congestion",
    "max_cwnd_mss",
    "num_streams",
    "bytes_per_stream",
    "max_receive_packet_size",
    "quic_version",
    "pacing_granularity_us",
    "pacing_min_burst",
    "build_horizon_us",
    "host_loop",
    "work_budget_us",
    "cid_format",
    "tls_backend",
    "num_conns",
    "object_rate",
    "object_size",
    "initial_rtt_ms",
    "minloglevel",
    "v",
];

/// Parses a number other than zero.
fn positive<T: FromStr + Default + PartialEq>(value: &str) -> Option<T> {
    value.parse().ok().filter(|number| *number != T::default())
}

/// Parses a boolean in gflags syntax.
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" | "t" | "yes" | "y" | "1" => Some(true),
        "false" | "f" | "no" | "n" | "0" => Some(false),
        _ => None,
    }
}

/// Why the arguments were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlagError {
    /// An unknown flag.
    Unknown(String),
    /// A flag that needs a value is the last argument.
    MissingValue(String),
    /// A server-only flag was set in client mode.
    ServerOnly(&'static str),
    /// A client-only flag was set in server mode.
    ClientOnly(&'static str),
    /// BBR3 was chosen without pacing, which it needs.
    Bbr3NeedsPacing,
    /// BBR3 was chosen for the client, which never paces.
    Bbr3ServerSide,
    /// A pacing flag was set without `--pacing`.
    NeedsPacing(&'static str),
    /// `--build_horizon_us` was set without `--txtime`.
    BuildHorizonNeedsTxtime,
    /// `--txtime` was set without `--pacing`.
    TxtimeNeedsPacing,
    /// With `--pacing`, `--writes_per_loop`, the maximum burst, is below the minimum burst.
    BatchBelowMinimumBurst {
        /// `--writes_per_loop`.
        writes_per_loop: u16,
        /// The minimum burst.
        min_burst: u16,
    },
    /// The value does not parse or is out of the flag's range.
    BadValue {
        /// The flag's name.
        flag: String,
        /// The value given.
        value: String,
    },
}

impl fmt::Display for FlagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(flag) => write!(f, "unknown command line flag '{flag}'"),
            Self::MissingValue(flag) => write!(f, "flag '{flag}' is missing its argument"),
            Self::ServerOnly(flag) => write!(f, "{flag} option is server only"),
            Self::ClientOnly(flag) => write!(f, "{flag} option is client only"),
            Self::Bbr3NeedsPacing => write!(
                f,
                "--congestion=bbr3 needs --pacing; mvfstr-tperf does not fall back to another controller"
            ),
            Self::Bbr3ServerSide => write!(
                f,
                "--congestion=bbr3 is server-side: the client never paces, so it takes newreno or cubic"
            ),
            Self::NeedsPacing(flag) => write!(f, "--{flag} needs --pacing"),
            Self::TxtimeNeedsPacing => write!(
                f,
                "--txtime needs --pacing: an unpaced connection has no release times, so kernel \
                 release would only add a qdisc hop and a larger max_ack_delay"
            ),
            Self::BuildHorizonNeedsTxtime => write!(
                f,
                "--build_horizon_us needs --txtime: without kernel release the socket cannot hold \
                 a datagram until its release, so the server would build nothing ahead"
            ),
            Self::BatchBelowMinimumBurst {
                writes_per_loop,
                min_burst,
            } => write!(
                f,
                "with --pacing, --writes_per_loop={writes_per_loop} caps each pacing burst below \
                 the minimum burst of {min_burst}"
            ),
            Self::BadValue { flag, value } => {
                write!(f, "illegal value '{value}' specified for flag '{flag}'")
            }
        }
    }
}

impl std::error::Error for FlagError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_mvfst_tperfs() {
        let flags = Flags::default();
        let expected = Flags {
            mode: Mode::Server,
            host: "::1".to_owned(),
            port: 6666,
            pin: false,
            duration_secs: 10,
            block_size: 1024 * 1024,
            writes_per_loop: 44,
            window: 1024 * 1024,
            autotune_window: true,
            congestion: CongestionControl::Cubic,
            pacing: false,
            gso: true,
            // mvfst's large maximum congestion window, in datagrams.
            max_cwnd_mss: 860_000,
            num_streams: 1,
            bytes_per_stream: 0,
            // mvfst's default max_udp_payload_size.
            max_receive_packet_size: 1452,
            override_packet_size: true,
            compat_mvfst: true,
            quic_version: QuicVersion::V1,
            stats: false,
            pacing_granularity_us: None,
            pacing_min_burst: None,
            txtime: false,
            build_horizon_us: None,
            host_loop: HostLoop::Tokio,
            work_budget_us: 0,
            cid_format: CidFormat::Random,
            tls_backend: TlsBackend::Inline,
            num_conns: 1,
            object_rate: 0,
            object_size: 1200,
            initial_rtt_ms: None,
        };
        assert_eq!(flags, expected);
    }

    fn parse(args: &[&str]) -> Result<Flags, FlagError> {
        Flags::parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn every_flag_takes_the_flag_equals_value_form() {
        let client = parse(&[
            "--mode=client",
            "--host=127.0.0.1",
            "--port=7000",
            "--pin=true",
            "--duration=3",
            "--block_size=4096",
            "--writes_per_loop=16",
            "--window=2097152",
            "--autotune_window=false",
            "--congestion=newreno",
            "--pacing=true",
            "--gso=false",
            "--max_cwnd_mss=1000",
            "--max_receive_packet_size=1350",
            "--override_packet_size=false",
            "--compat_mvfst=false",
            "--quic_version=mvfst",
            "--stats=true",
            "--initial_rtt_ms=100",
        ])
        .unwrap();
        assert_eq!(
            client,
            Flags {
                mode: Mode::Client,
                host: "127.0.0.1".to_owned(),
                port: 7000,
                pin: true,
                duration_secs: 3,
                block_size: 4096,
                writes_per_loop: 16,
                window: 2 * 1024 * 1024,
                autotune_window: false,
                congestion: CongestionControl::NewReno,
                pacing: true,
                gso: false,
                max_cwnd_mss: 1000,
                num_streams: 1,
                bytes_per_stream: 0,
                max_receive_packet_size: 1350,
                override_packet_size: false,
                compat_mvfst: false,
                quic_version: QuicVersion::Mvfst,
                stats: true,
                pacing_granularity_us: None,
                pacing_min_burst: None,
                txtime: false,
                build_horizon_us: None,
                host_loop: HostLoop::Tokio,
                work_budget_us: 0,
                cid_format: CidFormat::Random,
                tls_backend: TlsBackend::Inline,
                num_conns: 1,
                object_rate: 0,
                object_size: 1200,
                initial_rtt_ms: Some(100),
            }
        );
        let server = parse(&[
            "--mode=server",
            "--num_streams=4",
            "--bytes_per_stream=1000000",
            "--congestion=cubic",
            "--quic_version=v1",
            "--tls_backend=external",
        ])
        .unwrap();
        assert_eq!(
            server,
            Flags {
                num_streams: 4,
                bytes_per_stream: 1_000_000,
                tls_backend: TlsBackend::External,
                ..Flags::default()
            }
        );
        let inline = parse(&["--tls_backend", "inline"]).unwrap();
        assert_eq!(inline.tls_backend, TlsBackend::Inline);
    }

    #[test]
    fn the_work_budget_takes_its_slice_in_microseconds_and_zero_turns_it_off() {
        assert_eq!(Flags::default().work_budget_us, 0, "off by default");
        assert_eq!(
            parse(&["--work_budget_us=250"]).unwrap().work_budget_us,
            250
        );
        assert_eq!(
            parse(&["--work_budget_us", "100"]).unwrap().work_budget_us,
            100
        );
        assert_eq!(parse(&["--work_budget_us=0"]).unwrap().work_budget_us, 0);
    }

    #[test]
    fn booleans_take_the_bare_and_no_forms_and_one_dash_works_like_two() {
        let flags = parse(&[
            "--pacing",
            "--nogso",
            "-stats",
            "-noautotune_window",
            "--pin=1",
        ])
        .unwrap();
        assert!(flags.pacing && flags.stats && flags.pin);
        assert!(!flags.gso && !flags.autotune_window);
        let flags = parse(&[
            "-mode=client",
            "--override_packet_size=f",
            "--compat_mvfst=no",
        ])
        .unwrap();
        assert_eq!(flags.mode, Mode::Client);
        assert!(!flags.override_packet_size && !flags.compat_mvfst);
        assert_eq!(
            parse(&["--noport"]),
            Err(FlagError::Unknown("noport".to_owned())),
            "only booleans have a no form"
        );
    }

    #[test]
    fn other_flags_also_take_their_value_from_the_next_argument() {
        let flags = parse(&[
            "--port",
            "7000",
            "-host",
            "127.0.0.1",
            "--mode",
            "client",
            "--pacing",
        ])
        .unwrap();
        assert_eq!((flags.port, flags.host.as_str()), (7000, "127.0.0.1"));
        assert_eq!(flags.mode, Mode::Client);
        assert!(flags.pacing, "a boolean never takes the next argument");
        assert_eq!(
            parse(&["--duration"]),
            Err(FlagError::MissingValue("duration".to_owned()))
        );
    }

    #[test]
    fn values_outside_a_flags_range_are_refused() {
        for arg in [
            "--duration=0",
            "--block_size=0",
            "--writes_per_loop=0",
            "--num_streams=0",
            "--port=65536",
            "--duration=-1",
            "--congestion=bbr",
            "--pacing=maybe",
            "--pacing_granularity_us=0",
            "--pacing_min_burst=0",
            "--pacing_min_burst=65536",
            "--tls_backend=fizz",
        ] {
            let (flag, value) = arg[2..].split_once('=').unwrap();
            assert_eq!(
                parse(&[arg]),
                Err(FlagError::BadValue {
                    flag: flag.to_owned(),
                    value: value.to_owned(),
                }),
                "{arg}"
            );
        }
    }

    #[test]
    fn congestion_bbr3_selects_bbr3_and_bbr_and_bbr2_stay_refused() {
        // mvfst's spelling.
        let flags = parse(&["--congestion=bbr3", "--pacing"]).unwrap();
        assert_eq!(flags.congestion, CongestionControl::Bbr3);
        for value in ["bbr", "bbr2"] {
            assert_eq!(
                parse(&[&format!("--congestion={value}"), "--pacing"]),
                Err(FlagError::BadValue {
                    flag: "congestion".to_owned(),
                    value: value.to_owned(),
                })
            );
        }
    }

    #[test]
    fn bbr3_without_pacing_is_refused_rather_than_replaced() {
        // mvfst's tperf falls back to CUBIC with an error log.
        for args in [
            &["--congestion=bbr3"][..],
            &["--congestion=bbr3", "--nopacing"],
        ] {
            assert_eq!(parse(args), Err(FlagError::Bbr3NeedsPacing), "{args:?}");
        }
        assert!(parse(&["--pacing", "--congestion=bbr3"]).is_ok());
    }

    #[test]
    fn a_client_refuses_bbr3_as_server_side_even_with_pacing() {
        // The client of mvfst's tperf paces only for bbr and falls back to CUBIC.
        for args in [
            &["--mode=client", "--congestion=bbr3"][..],
            &["--congestion=bbr3", "--pacing", "--mode=client"],
        ] {
            assert_eq!(parse(args), Err(FlagError::Bbr3ServerSide), "{args:?}");
        }
    }

    #[test]
    fn a_client_refuses_the_server_only_stream_flags() {
        assert_eq!(
            parse(&["--bytes_per_stream=10", "--mode=client"]),
            Err(FlagError::ServerOnly("bytes_per_stream")),
            "checked once every flag is read"
        );
        assert_eq!(
            parse(&["--mode=client", "--tls_backend=external"]),
            Err(FlagError::ServerOnly("tls_backend"))
        );
        assert!(parse(&["--mode=client", "--num_streams=1", "--bytes_per_stream=0"]).is_ok());
    }

    #[test]
    fn the_pacing_flags_override_the_tick_and_the_minimum_burst() {
        let flags = parse(&[
            "--pacing",
            "--pacing_granularity_us=100",
            "--pacing_min_burst",
            "8",
        ])
        .unwrap();
        assert_eq!(
            (flags.pacing_granularity_us, flags.pacing_min_burst),
            (Some(100), Some(8))
        );
    }

    #[test]
    fn txtime_and_build_horizon_us_set_kernel_release_and_the_horizon() {
        let flags = parse(&["--pacing", "--txtime", "--build_horizon_us=5000"]).unwrap();
        assert_eq!((flags.txtime, flags.build_horizon_us), (true, Some(5000)));
        let flags = parse(&["--pacing", "--txtime=true", "--build_horizon_us", "2000"]).unwrap();
        assert_eq!((flags.txtime, flags.build_horizon_us), (true, Some(2000)));
        let flags = parse(&["--pacing", "--notxtime"]).unwrap();
        assert_eq!((flags.txtime, flags.build_horizon_us), (false, None));
    }

    #[test]
    fn a_build_horizon_without_txtime_is_refused_rather_than_ignored() {
        // Without release support connections do not build ahead, whatever the endpoint's setting.
        for args in [
            &["--pacing", "--build_horizon_us=5000"][..],
            &["--pacing", "--build_horizon_us=5000", "--notxtime"],
        ] {
            assert_eq!(
                parse(args),
                Err(FlagError::BuildHorizonNeedsTxtime),
                "{args:?}"
            );
        }
        let message = FlagError::BuildHorizonNeedsTxtime.to_string();
        assert!(message.contains("--txtime"), "{message}");
    }

    #[test]
    fn txtime_without_pacing_is_refused() {
        for args in [
            &["--txtime"][..],
            &["--txtime", "--nopacing"],
            &["--txtime", "--build_horizon_us=5000"],
        ] {
            assert_eq!(parse(args), Err(FlagError::TxtimeNeedsPacing), "{args:?}");
        }
        let message = FlagError::TxtimeNeedsPacing.to_string();
        assert!(message.contains("--pacing"), "{message}");
    }

    #[test]
    fn the_pacing_flags_are_refused_without_pacing() {
        for (arg, flag) in [
            ("--pacing_granularity_us=100", "pacing_granularity_us"),
            ("--pacing_min_burst=8", "pacing_min_burst"),
        ] {
            assert_eq!(parse(&[arg]), Err(FlagError::NeedsPacing(flag)), "{arg}");
            assert_eq!(
                parse(&[arg, "--nopacing"]),
                Err(FlagError::NeedsPacing(flag))
            );
        }
    }

    #[test]
    fn pacing_refuses_a_batch_below_the_minimum_burst() {
        // --writes_per_loop is the maximum burst, which may not be below the minimum.
        assert_eq!(
            parse(&["--pacing", "--writes_per_loop=4"]),
            Err(FlagError::BatchBelowMinimumBurst {
                writes_per_loop: 4,
                min_burst: 5,
            })
        );
        assert_eq!(
            parse(&["--pacing_min_burst=8", "--writes_per_loop=7", "--pacing"]),
            Err(FlagError::BatchBelowMinimumBurst {
                writes_per_loop: 7,
                min_burst: 8,
            })
        );
        assert!(parse(&["--writes_per_loop=4"]).is_ok(), "unpaced");
        assert!(parse(&["--pacing", "--pacing_min_burst=4", "--writes_per_loop=4"]).is_ok());
    }

    #[test]
    fn host_loop_chooses_the_workers_event_loop() {
        assert_eq!(
            parse(&["--host_loop=manual"]).map(|flags| flags.host_loop),
            Ok(HostLoop::Manual)
        );
        assert_eq!(
            parse(&["--host_loop=manual", "--host_loop", "tokio"]).map(|flags| flags.host_loop),
            Ok(HostLoop::Tokio)
        );
        assert_eq!(
            parse(&["--host_loop=epoll"]),
            Err(FlagError::BadValue {
                flag: "host_loop".to_owned(),
                value: "epoll".to_owned(),
            })
        );
    }

    #[test]
    fn cid_format_v2_chooses_mvfsts_version_2_ids() {
        assert_eq!(Flags::default().cid_format, CidFormat::Random);
        assert_eq!(
            parse(&["--cid_format=v2"]).map(|flags| flags.cid_format),
            Ok(CidFormat::V2)
        );
        assert_eq!(
            parse(&["--cid_format=v2", "--cid_format", "random"]).map(|flags| flags.cid_format),
            Ok(CidFormat::Random)
        );
        assert_eq!(
            parse(&["--cid_format=v3"]),
            Err(FlagError::BadValue {
                flag: "cid_format".to_owned(),
                value: "v3".to_owned(),
            })
        );
    }

    #[test]
    fn mvfst_logging_flags_are_accepted_and_ignored() {
        // Interop runs pass the same logging flags to both tools.
        let flags = parse(&[
            "--minloglevel=0",
            "--logtostderr",
            "--v=2",
            "--nologtostderr",
        ])
        .unwrap();
        assert_eq!(flags, Flags::default());
    }

    #[test]
    fn the_object_and_connection_flags_default_to_todays_run_and_take_both_forms() {
        let defaults = Flags::default();
        assert_eq!(
            (
                defaults.num_conns,
                defaults.object_rate,
                defaults.object_size
            ),
            (1, 0, 1200),
            "one connection, writing as fast as it can"
        );
        let client = parse(&["--mode=client", "--num_conns=8"]).unwrap();
        assert_eq!(
            client,
            Flags {
                mode: Mode::Client,
                num_conns: 8,
                ..Flags::default()
            }
        );
        assert_eq!(
            parse(&["--mode", "client", "--num_conns", "4"]).map(|flags| flags.num_conns),
            Ok(4)
        );
        let server = parse(&["--num_streams=2", "--object_rate=50", "--object_size=4096"]).unwrap();
        assert_eq!(
            server,
            Flags {
                num_streams: 2,
                object_rate: 50,
                object_size: 4096,
                ..Flags::default()
            }
        );
        let server = parse(&["--object_rate", "30", "--object_size", "16"]).unwrap();
        assert_eq!((server.object_rate, server.object_size), (30, 16));
        assert_eq!(
            parse(&["--object_rate=50", "--object_rate=0"]).map(|flags| flags.object_rate),
            Ok(0),
            "0 writes as fast as it can"
        );
    }

    #[test]
    fn num_conns_is_client_only_and_both_sides_take_the_stream_and_object_flags() {
        assert_eq!(
            parse(&["--num_conns=4"]),
            Err(FlagError::ClientOnly("num_conns")),
            "a server by default"
        );
        assert_eq!(
            parse(&["--num_conns=2", "--mode=server"]),
            Err(FlagError::ClientOnly("num_conns"))
        );
        assert!(parse(&["--mode=server", "--num_conns=1"]).is_ok());
        // The client reads what the server writes with the server's values.
        for mode in ["--mode=client", "--mode=server"] {
            let flags = parse(&[
                mode,
                "--num_streams=2",
                "--object_rate=50",
                "--object_size=4096",
            ]);
            assert_eq!(
                flags.map(|flags| (flags.num_streams, flags.object_rate, flags.object_size)),
                Ok((2, 50, 4096)),
                "{mode}"
            );
        }
        assert_eq!(
            FlagError::ClientOnly("num_conns").to_string(),
            "num_conns option is client only"
        );
    }

    #[test]
    fn values_outside_the_object_and_connection_flags_ranges_are_refused() {
        // An object holds at least its 16-byte header, and its length fits the header's 4 bytes.
        for arg in [
            "--num_conns=0",
            "--num_conns=-1",
            "--num_conns=many",
            "--object_rate=-1",
            "--object_rate=fast",
            "--object_size=0",
            "--object_size=15",
            "--object_size=4294967296",
        ] {
            let (flag, value) = arg[2..].split_once('=').unwrap();
            assert_eq!(
                parse(&["--mode=client", arg]),
                Err(FlagError::BadValue {
                    flag: flag.to_owned(),
                    value: value.to_owned(),
                }),
                "{arg}"
            );
        }
        assert_eq!(
            parse(&["--object_size=16", "--object_size=4294967295"]).map(|flags| flags.object_size),
            Ok(u32::MAX)
        );
    }

    #[test]
    fn initial_rtt_ms_takes_one_millisecond_to_an_hour_on_either_side() {
        assert_eq!(
            Flags::default().initial_rtt_ms,
            None,
            "the transport's default unless the flag is given"
        );
        assert_eq!(
            parse(&["--initial_rtt_ms=100"]),
            Ok(Flags {
                initial_rtt_ms: Some(100),
                ..Flags::default()
            }),
            "a server's, and nothing else changes"
        );
        assert_eq!(
            parse(&["--mode=client", "--initial_rtt_ms", "100"]),
            Ok(Flags {
                mode: Mode::Client,
                initial_rtt_ms: Some(100),
                ..Flags::default()
            }),
            "a client's, from the next argument"
        );
        // 333 is the transport's default, but a given flag stays given.
        for (arg, ms) in [
            ("--initial_rtt_ms=1", 1),
            ("--initial_rtt_ms=333", 333),
            ("--initial_rtt_ms=3600000", 3_600_000),
        ] {
            for mode in ["--mode=client", "--mode=server"] {
                assert_eq!(
                    parse(&[mode, arg]).map(|flags| flags.initial_rtt_ms),
                    Ok(Some(ms)),
                    "{mode} {arg}"
                );
            }
        }
        assert_eq!(
            parse(&["--initial_rtt_ms=50", "--initial_rtt_ms=100"])
                .map(|flags| flags.initial_rtt_ms),
            Ok(Some(100)),
            "the last one wins"
        );
    }

    #[test]
    fn initial_rtt_ms_outside_one_millisecond_to_an_hour_is_refused_at_parse() {
        // The transport refuses a zero initial RTT or one above an hour only when it is built,
        // after the flags are read.
        for mode in ["--mode=client", "--mode=server"] {
            for value in [
                "0",
                "-1",
                "3600001",
                "4294967296",
                "fast",
                "",
                "1.5",
                "100ms",
            ] {
                let arg = format!("--initial_rtt_ms={value}");
                assert_eq!(
                    parse(&[mode, &arg]),
                    Err(FlagError::BadValue {
                        flag: "initial_rtt_ms".to_owned(),
                        value: value.to_owned(),
                    }),
                    "{mode} {arg}"
                );
            }
        }
        assert_eq!(
            parse(&["--initial_rtt_ms"]),
            Err(FlagError::MissingValue("initial_rtt_ms".to_owned())),
            "it takes a value"
        );
        assert_eq!(
            parse(&["--mode=client", "--initial_rtt_ms=0"])
                .unwrap_err()
                .to_string(),
            "illegal value '0' specified for flag 'initial_rtt_ms'"
        );
    }
}
