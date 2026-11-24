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

/// The parsed flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Flags {
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
    pub(crate) num_streams: u32,
    pub(crate) bytes_per_stream: u64,
    pub(crate) max_receive_packet_size: u16,
    pub(crate) override_packet_size: bool,
    pub(crate) compat_mvfst: bool,
    pub(crate) quic_version: QuicVersion,
    pub(crate) stats: bool,
}

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
        }
    }
}

impl Flags {
    /// Parses the arguments after the program name.
    pub(crate) fn parse<I>(args: I) -> Result<Flags, FlagError>
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
        // As mvfst tperf: only the server opens streams.
        if flags.mode == Mode::Client {
            if flags.num_streams != 1 {
                return Err(FlagError::ServerOnly("num_streams"));
            }
            if flags.bytes_per_stream != 0 {
                return Err(FlagError::ServerOnly("bytes_per_stream"));
            }
            if flags.congestion == CongestionControl::Bbr3 {
                return Err(FlagError::Bbr3ServerSide);
            }
        }
        if flags.congestion == CongestionControl::Bbr3 && !flags.pacing {
            return Err(FlagError::Bbr3NeedsPacing);
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
const BOOL_FLAGS: [&str; 8] = [
    "pin",
    "autotune_window",
    "pacing",
    "gso",
    "override_packet_size",
    "compat_mvfst",
    "stats",
    "logtostderr",
];

/// The flags that take a value, which gflags also takes from the next argument.
const VALUE_FLAGS: [&str; 15] = [
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
pub(crate) enum FlagError {
    /// An unknown flag.
    Unknown(String),
    /// A flag that needs a value is the last argument.
    MissingValue(String),
    /// A server-only flag was set in client mode.
    ServerOnly(&'static str),
    /// BBR3 was chosen without pacing, which it needs.
    Bbr3NeedsPacing,
    /// BBR3 was chosen for the client, which never paces.
    Bbr3ServerSide,
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
            Self::Bbr3NeedsPacing => write!(
                f,
                "--congestion=bbr3 needs --pacing; mvfstr-tperf does not fall back to another controller"
            ),
            Self::Bbr3ServerSide => write!(
                f,
                "--congestion=bbr3 is server-side: the client never paces, so it takes newreno or cubic"
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
            }
        );
        let server = parse(&[
            "--mode=server",
            "--num_streams=4",
            "--bytes_per_stream=1000000",
            "--congestion=cubic",
            "--quic_version=v1",
        ])
        .unwrap();
        assert_eq!(
            server,
            Flags {
                num_streams: 4,
                bytes_per_stream: 1_000_000,
                ..Flags::default()
            }
        );
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
            parse(&["--mode=client", "--num_streams=2"]),
            Err(FlagError::ServerOnly("num_streams"))
        );
        assert_eq!(
            parse(&["--bytes_per_stream=10", "--mode=client"]),
            Err(FlagError::ServerOnly("bytes_per_stream")),
            "checked once every flag is read"
        );
        assert!(parse(&["--mode=client", "--num_streams=1", "--bytes_per_stream=0"]).is_ok());
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
}
