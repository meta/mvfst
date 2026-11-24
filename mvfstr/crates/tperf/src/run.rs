/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Running either side: one Roxygen worker per side with one endpoint driver on it, on the event
//! loop `--host_loop` chooses.

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
use mvfstr_driver::EndpointDriverBuilder;
use mvfstr_driver::HostTimers;
use mvfstr_driver::WorkBudget;
use mvfstr_io::Backend;
use mvfstr_io::HostBackend;
use mvfstr_io::HostOptions;
use mvfstr_io::ManualHost;
use mvfstr_io::MmsgBackend;
use mvfstr_io::MmsgOptions;
use mvfstr_io::TxCaps;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::CloseReason;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnStats;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::TransportConfig;
use roxygen_runtime::tokio_host::ManagedWorker;
use roxygen_runtime::tokio_host::ManagedWorkerError;
use roxygen_runtime::worker::WorkerContext;
use rustls::pki_types::ServerName;

use crate::client::ClientApp;
use crate::client::ClientSession;
use crate::client::Outcome;
use crate::config;
use crate::config::SERVER_NAME;
use crate::config::SetupError;
use crate::flags::Flags;
use crate::flags::HostLoop;
use crate::flags::Mode;
use crate::manual::ManualWorker;
use crate::manual::io_host;
use crate::report::Measurement;
use crate::report::closed_line;
use crate::report::startup_line;
use crate::report::stats_line;
use crate::server::Closed;
use crate::server::Driver;
use crate::server::ServerApp;
use crate::server::Settings;

/// The capacity of a worker's command queue; each side submits one command.
const WORKER_COMMANDS: usize = 64;

/// How long the client waits for its closed connection to drain before stopping its worker.
const DRAIN_WAIT: Duration = Duration::from_secs(1);

/// The fastest the server is taken to pace, in bytes per second, when sizing for `--txtime`:
/// 10 Gbit/s, for one connection and for all of them on the socket. That is above a 1 Gbit/s
/// connection paced at BBR's Startup gain of 2.77.
const TOP_PACING_RATE: u128 = 10_000_000_000 / 8;

/// Nanoseconds per second.
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// The connections the server's send buffer has room for, each with one run beyond the horizon.
const SIZED_CONNECTIONS: usize = 16;

/// The worker of one side, on the event loop `--host_loop` chooses.
enum Worker {
    Tokio(ManagedWorker),
    Manual(ManualWorker),
}

impl Worker {
    fn new(host_loop: HostLoop) -> Result<Self, RunError> {
        Ok(match host_loop {
            HostLoop::Tokio => Self::Tokio(ManagedWorker::new(WORKER_COMMANDS)?),
            HostLoop::Manual => {
                Self::Manual(ManualWorker::new(WORKER_COMMANDS).map_err(RunError::Loop)?)
            }
        })
    }

    /// Runs `command` on the worker.
    fn submit(
        &self,
        command: impl FnOnce(&WorkerContext) + Send + 'static,
    ) -> Result<(), RunError> {
        let submitted = match self {
            Self::Tokio(worker) => worker.handle().submit(command),
            Self::Manual(worker) => worker.handle().submit(command),
        };
        submitted.map_err(|_| RunError::WorkerGone)
    }

    /// Stops the worker once its work has drained.
    fn shutdown(self) -> Result<(), RunError> {
        match self {
            Self::Tokio(worker) => Ok(worker.shutdown()?),
            Self::Manual(worker) => worker.shutdown().map_err(RunError::Loop),
        }
    }
}

/// A server running on its own worker until dropped.
pub(crate) struct RunningServer {
    _worker: Worker,
    addr: SocketAddr,
    startup: String,
    closed: mpsc::Receiver<Closed>,
}

impl RunningServer {
    /// Returns the address the server listens on.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the line with the server's sending setup, as its socket took it.
    pub(crate) fn startup_line(&self) -> &str {
        &self.startup
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

/// A server on a worker that the caller runs, which serves until that worker stops.
pub struct HostedServer {
    addr: SocketAddr,
    startup: String,
    closed: mpsc::Receiver<Closed>,
}

impl HostedServer {
    /// Returns the address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the line with the server's sending setup, as its socket took it.
    pub fn startup_line(&self) -> &str {
        &self.startup
    }

    /// Returns the stats line of each connection that closed since the last call, under
    /// `--stats`.
    pub fn closed_lines(&self) -> Vec<String> {
        self.closed
            .try_iter()
            .map(|closed| {
                closed_line(
                    &closed.stats,
                    closed.socket_stops,
                    closed.phase_pacing_wakes,
                )
            })
            .collect()
    }
}

impl fmt::Debug for HostedServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostedServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// Starts a server configured by `flags`, which must be a server's, on `worker`, from the
/// worker's thread. `open` returns the server's socket and the timers its driver paces with, for
/// the address and the socket settings that the flags give.
pub fn start_hosted_server<B: Backend>(
    worker: &WorkerContext,
    flags: &Flags,
    open: impl FnOnce(SocketAddr, &MmsgOptions) -> io::Result<(B, HostTimers)>,
) -> Result<HostedServer, RunError> {
    if flags.mode != Mode::Server {
        return Err(RunError::Start(
            "a hosted server needs server flags".to_owned(),
        ));
    }
    let setup = ServerSetup::new(flags)?;
    let (backend, timers) = open(setup.addr, &backend_options(flags))
        .map_err(|error| RunError::Start(error.to_string()))?;
    let (addr, caps) = spawn_server(
        worker,
        setup.endpoint,
        setup.settings,
        setup.segments,
        |builder| builder.serve(backend, setup.server).host_timers(timers),
    )
    .map_err(RunError::Start)?;
    Ok(HostedServer {
        addr,
        startup: startup_line(&setup.transport, setup.build_horizon, &caps),
        closed: setup.closed,
    })
}

/// The parts of a server that its flags give, built before its driver starts.
struct ServerSetup {
    addr: SocketAddr,
    endpoint: Arc<EndpointConfig>,
    build_horizon: Duration,
    server: Arc<ServerConfig>,
    transport: Arc<TransportConfig>,
    settings: Settings,
    segments: u16,
    closed: mpsc::Receiver<Closed>,
}

impl ServerSetup {
    fn new(flags: &Flags) -> Result<Self, RunError> {
        let addr = resolve(flags)?;
        let endpoint = config::endpoint_config(flags)?;
        let build_horizon = endpoint.build_horizon();
        let server = config::server_config(flags)?;
        let transport = Arc::clone(server.transport());
        let (closed_tx, closed) = mpsc::channel();
        Ok(Self {
            addr,
            endpoint,
            build_horizon,
            server,
            transport,
            settings: Settings::new(flags, closed_tx),
            segments: max_segments(flags),
            closed,
        })
    }
}

/// Starts a server configured by `flags`.
pub(crate) fn start_server(flags: &Flags) -> Result<RunningServer, RunError> {
    start_server_with(flags, backend_options(flags))
}

/// Starts a server configured by `flags`, with the socket settings `options`.
fn start_server_with(flags: &Flags, options: MmsgOptions) -> Result<RunningServer, RunError> {
    let ServerSetup {
        addr,
        endpoint,
        build_horizon,
        server,
        transport,
        settings,
        segments,
        closed,
    } = ServerSetup::new(flags)?;
    let worker = Worker::new(flags.host_loop)?;
    let (started_tx, started) = mpsc::channel();
    let host_loop = flags.host_loop;
    worker.submit(move |worker| {
        let serve = match host_loop {
            HostLoop::Tokio => serve::<MmsgBackend>,
            HostLoop::Manual => serve::<HostBackend<ManualHost>>,
        };
        let _ = started_tx.send(serve(
            worker, endpoint, settings, addr, server, options, segments,
        ));
    })?;
    let (addr, caps) = started
        .recv()
        .map_err(|_| RunError::WorkerGone)?
        .map_err(RunError::Start)?;
    Ok(RunningServer {
        _worker: worker,
        addr,
        startup: startup_line(&transport, build_horizon, &caps),
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
    let endpoint = config::endpoint_config(flags)?;
    let options = backend_options(flags);
    let name =
        ServerName::try_from(SERVER_NAME).map_err(|error| RunError::Start(error.to_string()))?;
    let duration_secs = flags.duration_secs;
    let worker = Worker::new(flags.host_loop)?;
    let (outcomes_tx, outcomes) = mpsc::channel();
    let (started_tx, started) = mpsc::channel();
    let host_loop = flags.host_loop;
    worker.submit(move |worker| {
        let connect = match host_loop {
            HostLoop::Tokio => connect::<MmsgBackend>,
            HostLoop::Manual => connect::<HostBackend<ManualHost>>,
        };
        let session = ClientSession::new(duration_secs, outcomes_tx);
        let _ = started_tx.send(connect(
            worker, endpoint, options, remote, name, client, session,
        ));
    })?;
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

/// A backend tperf runs an endpoint on.
trait TperfBackend: Backend {
    /// Returns the options that open this backend with the socket settings `mmsg`, on the
    /// worker's thread.
    fn options(mmsg: MmsgOptions) -> Self::Options;
}

impl TperfBackend for MmsgBackend {
    fn options(mmsg: MmsgOptions) -> MmsgOptions {
        mmsg
    }
}

impl TperfBackend for HostBackend<ManualHost> {
    fn options(mmsg: MmsgOptions) -> HostOptions<ManualHost> {
        HostOptions {
            host: io_host(),
            mmsg,
        }
    }
}

/// Starts the server's driver on `worker`, on backend `B`, and returns its address and its
/// socket's capabilities.
fn serve<B: TperfBackend>(
    worker: &WorkerContext,
    endpoint: Arc<EndpointConfig>,
    settings: Settings,
    addr: SocketAddr,
    server: Arc<ServerConfig>,
    options: MmsgOptions,
    segments: u16,
) -> Result<(SocketAddr, TxCaps), String> {
    spawn_server::<B>(worker, endpoint, settings, segments, |builder| {
        builder
            .bind_server(addr, server)
            .backend_options(B::options(options))
    })
}

/// Starts the server's driver on `worker`, on backend `B`, after `socket` sets up its server
/// socket on the builder, and returns the socket's address and capabilities.
fn spawn_server<B: Backend>(
    worker: &WorkerContext,
    endpoint: Arc<EndpointConfig>,
    settings: Settings,
    segments: u16,
    socket: impl FnOnce(
        EndpointDriverBuilder<ServerApp<B>, B>,
    ) -> EndpointDriverBuilder<ServerApp<B>, B>,
) -> Result<(SocketAddr, TxCaps), String> {
    let driver = Driver::<B>::default();
    let budget = settings.work_budget;
    let app = ServerApp::new(settings, Rc::clone(&driver));
    let mut builder = socket(EndpointDriver::<_, B>::builder(endpoint, app)).max_segments(segments);
    if let Some(slice) = budget {
        builder = builder.work_budget(WorkBudget::per_poll(slice));
    }
    let handle = builder.spawn(worker).map_err(|error| error.to_string())?;
    let started = handle
        .local_addr()
        .zip(handle.server_caps())
        .ok_or_else(|| "the server driver has no socket".to_owned());
    let _ = driver.set(handle);
    started
}

/// Starts a client driver on `worker`, on backend `B`, and opens its connection to `remote`.
fn connect<B: TperfBackend>(
    worker: &WorkerContext,
    endpoint: Arc<EndpointConfig>,
    options: MmsgOptions,
    remote: SocketAddr,
    name: ServerName<'static>,
    client: Arc<ClientConfig>,
    session: ClientSession,
) -> Result<(), String> {
    let driver = EndpointDriver::<_, B>::builder(endpoint, ClientApp)
        .backend_options(B::options(options))
        .spawn(worker)
        .map_err(|error| error.to_string())?;
    driver
        .connect(remote, name, client, ConnOptions::default(), session)
        .map(drop)
        .map_err(|error| error.to_string())
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
/// connection may send, which `--max_receive_packet_size` bounds, and on the server under
/// `--txtime`, kernel release with room for the runs its connections build ahead.
fn backend_options(flags: &Flags) -> MmsgOptions {
    let defaults = MmsgOptions::default();
    let mut options = MmsgOptions {
        max_datagram: defaults.max_datagram.max(flags.max_receive_packet_size),
        ..defaults
    };
    if flags.mode == Mode::Server && flags.txtime {
        options.txtime = true;
        // Room for a wake to build every run due within the horizon, and one more, before the
        // connection stops on the socket; the transmit pool, which sends on its own once full,
        // bounds what waits for the transmit phase's flush.
        let ahead = built_ahead(flags, options.txtime_horizon);
        let run = run_bytes(flags);
        options.max_unsent = options
            .max_unsent
            .max(u32::try_from(ahead + run).unwrap_or(u32::MAX));
        // fq keeps each run charged to the socket until it leaves, up to a horizon later, and a
        // send fails with EAGAIN once the charge reaches SO_SNDBUF. The kernel doubles the value
        // for its skb overhead, after capping it at net.core.wmem_max.
        options.socket.send_buffer = Some(ahead + SIZED_CONNECTIONS * run);
    }
    options
}

/// Returns the bytes one connection builds ahead of its releases when it paces at
/// [`TOP_PACING_RATE`] with the endpoint's build horizon, capped by the socket's release horizon.
fn built_ahead(flags: &Flags, release_horizon: Duration) -> usize {
    let horizon = config::build_horizon(flags).min(release_horizon);
    let bytes = (horizon.as_nanos() * TOP_PACING_RATE).div_ceil(NANOS_PER_SEC);
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// Returns the bytes of one run: a maximum pacing burst, `--writes_per_loop`, of the largest
/// datagrams.
fn run_bytes(flags: &Flags) -> usize {
    usize::from(flags.writes_per_loop) * usize::from(flags.max_receive_packet_size)
}

/// Why a run failed.
#[derive(Debug)]
pub enum RunError {
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
    /// The manual loop could not start, or failed.
    Loop(io::Error),
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
            Self::Loop(error) => write!(f, "the manual loop failed: {error}"),
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
            Self::Resolve { error, .. } | Self::Loop(error) | Self::Output(error) => Some(error),
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
    use super::*;
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
    fn a_server_hosted_on_a_worker_the_caller_runs_serves_a_client() {
        let worker = ManagedWorker::new(WORKER_COMMANDS).unwrap();
        let (started_tx, started) = mpsc::channel();
        worker
            .handle()
            .submit(move |context| {
                let open = |addr, options: &MmsgOptions| {
                    Ok((MmsgBackend::bind(addr, options)?, HostTimers::tokio()))
                };
                let client = start_hosted_server(context, &loopback(Mode::Client, 0), open);
                let server = start_hosted_server(
                    context,
                    &Flags {
                        stats: true,
                        ..loopback(Mode::Server, 0)
                    },
                    open,
                );
                let _ = started_tx.send((client.err().map(|error| error.to_string()), server));
            })
            .unwrap();
        let (client, server) = started.recv().unwrap();
        assert_eq!(
            client.as_deref(),
            Some("cannot start: a hosted server needs server flags")
        );
        let server = server.unwrap();
        assert!(
            server.startup_line().starts_with("Server: "),
            "{}",
            server.startup_line()
        );
        let mut out = Vec::new();
        run_client(
            &Flags {
                duration_secs: 1,
                port: server.addr().port(),
                ..loopback(Mode::Client, 0)
            },
            &mut out,
        )
        .unwrap();
        let output = String::from_utf8(out).unwrap();
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(parsed.bytes > 0, "{output}");
        let closed = server
            .closed
            .recv_timeout(Duration::from_secs(10))
            .expect("the closed connection's counters");
        let line = closed_line(
            &closed.stats,
            closed.socket_stops,
            closed.phase_pacing_wakes,
        );
        assert!(line.contains(" socket_stops="), "{line}");
        assert_eq!(
            server.closed_lines(),
            Vec::<String>::new(),
            "one connection"
        );
    }

    #[test]
    fn a_server_on_the_manual_loop_serves_clients_on_either_loop() {
        let server = start_server(&Flags {
            stats: true,
            host_loop: HostLoop::Manual,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        for host_loop in [HostLoop::Manual, HostLoop::Tokio] {
            let output = client_output(
                &server,
                Flags {
                    duration_secs: 1,
                    host_loop,
                    ..loopback(Mode::Client, 0)
                },
            );
            let parsed = report::parse(&output)
                .unwrap_or_else(|| panic!("{host_loop:?}: no result lines in {output:?}"));
            assert!(parsed.bytes > 0, "{host_loop:?}: {output}");
            let Closed { stats, .. } = server
                .closed_connections()
                .recv_timeout(Duration::from_secs(10))
                .expect("the closed connection's counters");
            assert!(
                stats.sent_packets > 0 && stats.recv_packets > 0,
                "{host_loop:?}: {stats:?}"
            );
        }
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
    fn txtime_turns_on_kernel_release_for_the_server_socket_only() {
        let paced = Flags {
            pacing: true,
            ..Flags::default()
        };
        assert!(!backend_options(&paced).txtime);
        let txtime = Flags {
            txtime: true,
            build_horizon_us: Some(5000),
            ..paced
        };
        assert!(backend_options(&txtime).txtime);
        let client = Flags {
            mode: Mode::Client,
            ..txtime
        };
        let plain_client = Flags {
            mode: Mode::Client,
            ..Flags::default()
        };
        assert_eq!(
            backend_options(&client),
            backend_options(&plain_client),
            "server-side flags leave the client's socket alone"
        );
    }

    /// Returns server flags for kernel release with a 5 ms horizon.
    fn building_5_ms_ahead() -> Flags {
        Flags {
            pacing: true,
            txtime: true,
            build_horizon_us: Some(5000),
            ..Flags::default()
        }
    }

    #[test]
    fn with_txtime_a_connection_may_build_its_whole_horizon_before_a_flush() {
        // 5 ms at 10 Gbit/s, and one run of 44 datagrams of 1,452 bytes.
        assert_eq!(
            backend_options(&building_5_ms_ahead()).max_unsent,
            6_250_000 + 63_888
        );
        let default = MmsgOptions::default().max_unsent;
        assert_eq!(backend_options(&Flags::default()).max_unsent, default);
        let nothing_ahead = Flags {
            build_horizon_us: None,
            ..building_5_ms_ahead()
        };
        assert_eq!(
            backend_options(&nothing_ahead).max_unsent,
            default,
            "never below the default"
        );
    }

    #[test]
    fn with_txtime_the_send_buffer_holds_the_sockets_horizon_and_a_run_per_connection() {
        // 5 ms at 10 Gbit/s over the socket, and a run of 44 datagrams of 1,452 bytes for each
        // of 16 connections.
        assert_eq!(
            backend_options(&building_5_ms_ahead()).socket.send_buffer,
            Some(6_250_000 + 16 * 63_888)
        );
        let paced = Flags {
            pacing: true,
            ..Flags::default()
        };
        assert_eq!(
            backend_options(&paced).socket.send_buffer,
            None,
            "the kernel default without txtime"
        );
    }

    #[test]
    fn the_server_reports_its_sending_setup_as_its_socket_took_it() {
        let server = start_server(&Flags {
            host: "127.0.0.1".to_owned(),
            port: 0,
            ..building_5_ms_ahead()
        })
        .unwrap();
        let line = server.startup_line();
        assert!(
            line.contains(" txtime=true endpoint_horizon_us=5000 "),
            "{line}"
        );
        // The kernel caps the size asked for at net.core.wmem_max, then doubles it.
        let wmem_max: usize = std::fs::read_to_string("/proc/sys/net/core/wmem_max")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let asked: usize = 6_250_000 + 16 * 63_888;
        assert!(
            line.ends_with(&format!(" so_sndbuf={}", 2 * asked.min(wmem_max))),
            "{line}"
        );
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
