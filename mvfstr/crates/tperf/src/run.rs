/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Running either side: one Roxygen worker per side with one endpoint driver on it.

use std::fmt;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use mvfstr_driver::EndpointDriver;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use roxygen_runtime::tokio_host::ManagedWorker;
use roxygen_runtime::tokio_host::ManagedWorkerError;
use rustls::pki_types::ServerName;

use crate::client::ClientApp;
use crate::client::ClientSession;
use crate::client::Outcome;
use crate::config;
use crate::config::SERVER_NAME;
use crate::config::SetupError;
use crate::flags::Flags;
use crate::report::Measurement;
use crate::report::stats_line;
use crate::server::Closed;
use crate::server::Driver;
use crate::server::ServerApp;
use crate::server::Settings;

/// The capacity of a worker's command queue; each side submits one command.
const WORKER_COMMANDS: usize = 64;

/// How long the client waits for its closed connection to drain before stopping its worker.
const DRAIN_WAIT: Duration = Duration::from_secs(1);

/// A server running on its own worker until dropped.
pub(crate) struct RunningServer {
    _worker: ManagedWorker,
    addr: SocketAddr,
    closed: mpsc::Receiver<Closed>,
}

impl RunningServer {
    /// Returns the address the server listens on.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the channel that carries each connection that closes, under `--stats`. The
    /// channel ends when the server's worker stops.
    pub(crate) fn closed_connections(&self) -> &mpsc::Receiver<Closed> {
        &self.closed
    }
}

impl fmt::Debug for RunningServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// Starts a server configured by `flags`.
pub(crate) fn start_server(flags: &Flags) -> Result<RunningServer, RunError> {
    start_server_with(flags, backend_options(flags))
}

/// Starts a server configured by `flags`, with the socket settings `options`.
fn start_server_with(flags: &Flags, options: MmsgOptions) -> Result<RunningServer, RunError> {
    let addr = resolve(flags)?;
    let endpoint = config::endpoint_config()?;
    let server = config::server_config(flags)?;
    let (closed_tx, closed) = mpsc::channel();
    let settings = Settings::new(flags, closed_tx);
    let segments = max_segments(flags);
    let worker = ManagedWorker::new(WORKER_COMMANDS)?;
    let (started_tx, started) = mpsc::channel();
    worker
        .handle()
        .submit(move |worker| {
            let driver = Driver::default();
            let app = ServerApp::new(settings, Rc::clone(&driver));
            let started = EndpointDriver::<_, MmsgBackend>::builder(endpoint, app)
                .bind_server(addr, server)
                .backend_options(options)
                .max_segments(segments)
                .spawn(worker)
                .map_err(|error| error.to_string())
                .and_then(|handle| {
                    let started = handle
                        .local_addr()
                        .ok_or_else(|| "the server driver has no socket".to_owned());
                    let _ = driver.set(handle);
                    started
                });
            let _ = started_tx.send(started);
        })
        .map_err(|_| RunError::WorkerGone)?;
    let addr = started
        .recv()
        .map_err(|_| RunError::WorkerGone)?
        .map_err(RunError::Start)?;
    Ok(RunningServer {
        _worker: worker,
        addr,
        closed,
    })
}

/// Runs a client configured by `flags` and writes its result lines to `out`.
pub(crate) fn run_client(flags: &Flags, out: &mut impl Write) -> Result<(), RunError> {
    run_client_with(flags, config::client_config(flags)?, out)
}

/// Runs a client with the config `client` and every other setting from `flags`.
fn run_client_with(
    flags: &Flags,
    client: Arc<ClientConfig>,
    out: &mut impl Write,
) -> Result<(), RunError> {
    let remote = resolve(flags)?;
    let endpoint = config::endpoint_config()?;
    let options = backend_options(flags);
    let name =
        ServerName::try_from(SERVER_NAME).map_err(|error| RunError::Start(error.to_string()))?;
    let duration_secs = flags.duration_secs;
    let worker = ManagedWorker::new(WORKER_COMMANDS)?;
    let (outcomes_tx, outcomes) = mpsc::channel();
    let (started_tx, started) = mpsc::channel();
    worker
        .handle()
        .submit(move |worker| {
            let started = EndpointDriver::<_, MmsgBackend>::builder(endpoint, ClientApp)
                .backend_options(options)
                .spawn(worker)
                .map_err(|error| error.to_string())
                .and_then(|driver| {
                    let session = ClientSession::new(duration_secs, outcomes_tx);
                    driver
                        .connect(remote, name, client, ConnOptions::default(), session)
                        .map(drop)
                        .map_err(|error| error.to_string())
                });
            let _ = started_tx.send(started);
        })
        .map_err(|_| RunError::WorkerGone)?;
    started
        .recv()
        .map_err(|_| RunError::WorkerGone)?
        .map_err(RunError::Start)?;
    let result = match outcomes.recv() {
        Ok(Outcome::Measured { measurement, stats }) => {
            write_results(out, &measurement, flags.stats.then_some(&stats))
                .map_err(RunError::Output)
        }
        Ok(Outcome::Closed(reason)) => Err(RunError::Closed(reason)),
        Ok(Outcome::Drained) | Err(_) => Err(RunError::WorkerGone),
    };
    while let Ok(outcome) = outcomes.recv_timeout(DRAIN_WAIT) {
        if matches!(outcome, Outcome::Drained) {
            break;
        }
    }
    worker.shutdown()?;
    result
}

/// Writes the result lines, then the stats line if `stats` is given.
fn write_results(
    out: &mut impl Write,
    measurement: &Measurement,
    stats: Option<&ConnStats>,
) -> io::Result<()> {
    for line in measurement.lines() {
        writeln!(out, "{line}")?;
    }
    if let Some(stats) = stats {
        writeln!(out, "{}", stats_line(stats))?;
    }
    Ok(())
}

/// Resolves `--host` and `--port` to the first address they name.
fn resolve(flags: &Flags) -> Result<SocketAddr, RunError> {
    let unresolved = |error| RunError::Resolve {
        host: flags.host.clone(),
        error,
    };
    (flags.host.as_str(), flags.port)
        .to_socket_addrs()
        .map_err(unresolved)?
        .next()
        .ok_or_else(|| unresolved(io::Error::new(io::ErrorKind::NotFound, "no address")))
}

/// Returns the most datagrams one transmit attempt builds: `--writes_per_loop` with GSO, else one.
fn max_segments(flags: &Flags) -> u16 {
    if flags.gso { flags.writes_per_loop } else { 1 }
}

/// Returns the socket settings of either side: transmit slots that hold the largest datagram the
/// connection may send, which `--max_receive_packet_size` bounds.
fn backend_options(flags: &Flags) -> MmsgOptions {
    let defaults = MmsgOptions::default();
    MmsgOptions {
        max_datagram: defaults.max_datagram.max(flags.max_receive_packet_size),
        ..defaults
    }
}

/// Why a run failed.
#[derive(Debug)]
pub(crate) enum RunError {
    /// `--host` does not resolve to an address.
    Resolve {
        /// The host.
        host: String,
        /// Why it does not resolve.
        error: io::Error,
    },
    /// The certificate or a config could not be built.
    Setup(SetupError),
    /// The worker could not start or stop.
    Worker(ManagedWorkerError),
    /// The driver or the connection could not start.
    Start(String),
    /// The connection closed before the measured window ended.
    Closed(CloseReason),
    /// The worker stopped without reporting.
    WorkerGone,
    /// Writing the result lines failed.
    Output(io::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve { host, error } => write!(f, "cannot resolve {host}: {error}"),
            Self::Setup(error) => write!(f, "setup failed: {error}"),
            Self::Worker(error) => write!(f, "worker failed: {error}"),
            Self::Start(error) => write!(f, "cannot start: {error}"),
            Self::Closed(reason) => write!(f, "the connection closed early: {reason:?}"),
            Self::WorkerGone => f.write_str("the worker stopped without a result"),
            Self::Output(error) => write!(f, "cannot write the results: {error}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve { error, .. } | Self::Output(error) => Some(error),
            Self::Setup(error) => Some(error),
            Self::Worker(error) => Some(error),
            Self::Start(_) | Self::Closed(_) | Self::WorkerGone => None,
        }
    }
}

impl From<SetupError> for RunError {
    fn from(error: SetupError) -> Self {
        Self::Setup(error)
    }
}

impl From<ManagedWorkerError> for RunError {
    fn from(error: ManagedWorkerError) -> Self {
        Self::Worker(error)
    }
}

#[cfg(test)]
mod tests {
    use mvfstr_proto::TransportConfig;

    use super::*;
    use crate::flags::Mode;
    use crate::flags::QuicVersion;
    use crate::report;
    use crate::report::format_g;

    /// Returns flags for a `mode` side on IPv4 loopback at `port`, 0 for an ephemeral port.
    fn loopback(mode: Mode, port: u16) -> Flags {
        Flags {
            mode,
            host: "127.0.0.1".to_owned(),
            port,
            ..Flags::default()
        }
    }

    /// Runs a client against `server` with `flags` and returns what it printed.
    fn client_output(server: &RunningServer, flags: Flags) -> String {
        let mut out = Vec::new();
        run_client(
            &Flags {
                port: server.addr().port(),
                ..flags
            },
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_one_second_loopback_run_moves_bytes_and_prints_mvfst_tperfs_lines() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..loopback(Mode::Client, 0)
            },
        );
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(parsed.bytes > 0, "{output}");
        assert_eq!((parsed.duration_secs, parsed.streams), (1, 1), "{output}");
        let overall = parsed.bytes as f64 / 131_072.0;
        assert_eq!(format_g(parsed.overall), format_g(overall), "{output}");
        assert_eq!(format_g(parsed.per_stream), format_g(overall), "{output}");
        assert!(
            !output.contains("Stats:"),
            "no stats line without --stats: {output}"
        );
    }

    #[test]
    fn an_mvfst_client_without_alpn_needs_the_compat_mode() {
        let mvfst_client = Flags {
            duration_secs: 1,
            quic_version: QuicVersion::Mvfst,
            ..loopback(Mode::Client, 0)
        };
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(&server, mvfst_client.clone());
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(parsed.bytes > 0, "{output}");

        let strict = start_server(&Flags {
            compat_mvfst: false,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let refused = run_client(
            &Flags {
                port: strict.addr().port(),
                ..mvfst_client
            },
            &mut Vec::new(),
        );
        assert!(
            matches!(
                refused,
                Err(RunError::Closed(CloseReason::Transport { .. }))
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn streams_that_end_are_replaced_and_counted() {
        let server = start_server(&Flags {
            num_streams: 2,
            bytes_per_stream: 100_000,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..loopback(Mode::Client, 0)
            },
        );
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(parsed.streams > 2, "{output}");
        let per_stream = (parsed.bytes / parsed.streams) as f64 / 131_072.0;
        assert_eq!(
            format_g(parsed.per_stream),
            format_g(per_stream),
            "{output}"
        );
    }

    #[test]
    fn streams_owed_at_the_clients_stream_limit_open_once_it_allows_more() {
        // The client takes 16 server streams at a time, and the server's streams of one byte all
        // end at once, so their replacements wait for the client's MAX_STREAMS.
        const LIMIT: u32 = 16;
        let server = start_server(&Flags {
            num_streams: LIMIT,
            bytes_per_stream: 1,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let flags = Flags {
            duration_secs: 1,
            port: server.addr().port(),
            ..loopback(Mode::Client, 0)
        };
        let tperf = config::client_config(&flags).unwrap();
        let client = ClientConfig::builder(tperf.tls().clone())
            .transport(
                TransportConfig::builder()
                    .max_streams_uni(LIMIT.into())
                    .build()
                    .unwrap(),
            )
            .versions(tperf.versions().to_vec())
            .alpn(tperf.alpn())
            .build()
            .unwrap();
        let mut out = Vec::new();
        run_client_with(&flags, client, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(parsed.streams > u64::from(LIMIT), "{output}");
    }

    #[test]
    fn the_server_reports_closed_connections_only_under_stats() {
        let server = start_server(&Flags {
            stats: true,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let client = Flags {
            duration_secs: 1,
            ..loopback(Mode::Client, 0)
        };
        client_output(&server, client.clone());
        let Closed { stats, .. } = server
            .closed_connections()
            .recv_timeout(Duration::from_secs(10))
            .expect("the closed connection's counters");
        assert!(
            stats.sent_packets > 0 && stats.recv_packets > 0,
            "{stats:?}"
        );

        // The server has received the close by the time the client has drained.
        let quiet = start_server(&loopback(Mode::Server, 0)).unwrap();
        client_output(&quiet, client);
        let report = quiet.closed_connections().try_recv();
        assert_eq!(report, Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn a_closed_connection_comes_with_the_server_sockets_stops() {
        // With room for one datagram built and not yet sent, every transmit attempt that has
        // more to send stops on the socket after its first datagram.
        let flags = Flags {
            stats: true,
            ..loopback(Mode::Server, 0)
        };
        let options = MmsgOptions {
            max_unsent: 1500,
            ..backend_options(&flags)
        };
        let server = start_server_with(&flags, options).unwrap();
        client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..loopback(Mode::Client, 0)
            },
        );
        let closed = server
            .closed_connections()
            .recv_timeout(Duration::from_secs(10))
            .expect("the closed connection");
        assert!(closed.socket_stops > 0, "{closed:?}");
    }

    #[test]
    fn writes_per_loop_caps_a_transmit_attempt_and_without_gso_one_datagram_goes() {
        assert_eq!(max_segments(&Flags::default()), 44);
        let flags = Flags {
            writes_per_loop: 8,
            ..Flags::default()
        };
        assert_eq!(max_segments(&flags), 8);
        let no_gso = Flags {
            gso: false,
            ..flags
        };
        assert_eq!(max_segments(&no_gso), 1);
    }

    #[test]
    fn transmit_slots_hold_the_largest_datagram_the_flags_allow() {
        assert_eq!(
            backend_options(&Flags::default()).max_datagram,
            1500,
            "the backend's default, above the default 1452-byte packets"
        );
        let jumbo = Flags {
            max_receive_packet_size: 9000,
            ..Flags::default()
        };
        assert_eq!(backend_options(&jumbo).max_datagram, 9000);
    }

    #[test]
    fn the_client_prints_its_stats_line_under_stats() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                stats: true,
                ..loopback(Mode::Client, 0)
            },
        );
        let last = output.lines().last().unwrap_or_default();
        assert!(last.starts_with("Stats: sent_packets="), "{output}");
        assert!(!last.contains("recv_packets=0 "), "{output}");
    }
}
