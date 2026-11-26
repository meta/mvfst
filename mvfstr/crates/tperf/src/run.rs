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
use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use mvfstr_driver::DriverError;
use mvfstr_driver::EndpointDriver;
use mvfstr_driver::EndpointDriverBuilder;
use mvfstr_driver::EndpointHandle;
use mvfstr_driver::HostTimers;
use mvfstr_driver::QuicApplication;
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
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::TransportConfig;
use roxygen_runtime::tokio_host::ManagedWorker;
use roxygen_runtime::tokio_host::ManagedWorkerError;
use roxygen_runtime::worker::WorkerContext;
use rustls::pki_types::ServerName;

use crate::client::ClientApp;
use crate::client::ClientSession;
use crate::client::ConnReport;
use crate::client::Outcome;
use crate::config;
use crate::config::SERVER_NAME;
use crate::config::SetupError;
use crate::flags::Flags;
use crate::flags::HostLoop;
use crate::flags::Mode;
use crate::manual::ManualWorker;
use crate::manual::io_host;
use crate::report::ConnTally;
use crate::report::Measurement;
use crate::report::WriteMode;
use crate::report::client_stats_line;
use crate::report::closed_line;
use crate::report::server_summary_line;
use crate::report::startup_line;
use crate::report::summary_line;
use crate::server::Closed;
use crate::server::Driver;
use crate::server::ServerApp;
use crate::server::ServerCounters;
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
    summary: ServerSummary,
}

/// What a server's summary line reads, from any thread.
#[derive(Clone, Debug)]
pub(crate) struct ServerSummary {
    mode: WriteMode,
    counters: Arc<ServerCounters>,
}

impl ServerSummary {
    /// Returns the server's summary line for what it has done so far.
    pub(crate) fn line(&self) -> String {
        server_summary_line(self.mode, &self.counters.tally())
    }
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

    /// Returns the server's summary line for what it has done so far.
    #[cfg(test)]
    pub(crate) fn summary_line(&self) -> String {
        self.summary.line()
    }

    /// Returns what reads the server's summary line, which may move to another thread.
    pub(crate) fn summary(&self) -> ServerSummary {
        self.summary.clone()
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
                    closed.dropped_initials,
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

/// A way to start a hosted server's driver from the builder tperf configured, for a host that sets
/// up each driver it runs, such as one that gives every driver its work budget.
pub trait SpawnDriver {
    /// Starts the driver `builder` describes, on the thread that runs the host's worker.
    fn spawn<A: QuicApplication, B: Backend>(
        self,
        builder: EndpointDriverBuilder<A, B>,
    ) -> Result<EndpointHandle<A, B>, DriverError>;
}

/// A spawner that starts each driver on one worker, as tperf configured it.
struct OnWorker<'a>(&'a WorkerContext);

impl SpawnDriver for OnWorker<'_> {
    fn spawn<A: QuicApplication, B: Backend>(
        self,
        builder: EndpointDriverBuilder<A, B>,
    ) -> Result<EndpointHandle<A, B>, DriverError> {
        builder.spawn(self.0)
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
    start_hosted_server_with(flags, open, OnWorker(worker))
}

/// Starts a server as [`start_hosted_server`] does, but with its driver started by `spawn`, on
/// the thread that runs the host's worker.
pub fn start_hosted_server_with<B: Backend>(
    flags: &Flags,
    open: impl FnOnce(SocketAddr, &MmsgOptions) -> io::Result<(B, HostTimers)>,
    spawn: impl SpawnDriver,
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
        spawn,
        setup.endpoint,
        setup.settings,
        setup.segments,
        |builder| builder.serve(backend, setup.server).host_timers(timers),
    )
    .map_err(RunError::Start)?;
    Ok(HostedServer {
        addr,
        startup: startup_line(
            &setup.transport,
            setup.build_horizon,
            &caps,
            flags.initial_rtt_ms,
        ),
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
    summary: ServerSummary,
}

impl ServerSetup {
    fn new(flags: &Flags) -> Result<Self, RunError> {
        let addr = resolve(flags)?;
        let endpoint = config::endpoint_config(flags)?;
        let build_horizon = endpoint.build_horizon();
        let (server, host_tls) = config::server_config(flags)?;
        let transport = Arc::clone(server.transport());
        let (closed_tx, closed) = mpsc::channel();
        let settings = Settings::new(flags, closed_tx, host_tls);
        let summary = ServerSummary {
            mode: write_mode(flags),
            counters: settings.counters(),
        };
        Ok(Self {
            addr,
            endpoint,
            build_horizon,
            server,
            transport,
            settings,
            segments: max_segments(flags),
            closed,
            summary,
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
        summary,
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
        startup: startup_line(&transport, build_horizon, &caps, flags.initial_rtt_ms),
        closed,
        summary,
    })
}

/// Runs a client configured by `flags` and writes its result lines to `out`.
pub(crate) fn run_client(flags: &Flags, out: &mut impl Write) -> Result<(), RunError> {
    run_client_with(flags, config::client_config(flags)?, out).map(drop)
}

/// Runs a client with the config `client` and every other setting from `flags`, and returns what
/// each of its connections received.
fn run_client_with(
    flags: &Flags,
    client: Arc<ClientConfig>,
    out: &mut impl Write,
) -> Result<Vec<ConnTally>, RunError> {
    let remote = resolve(flags)?;
    let endpoint = config::endpoint_config(flags)?;
    let options = backend_options(flags);
    let name =
        ServerName::try_from(SERVER_NAME).map_err(|error| RunError::Start(error.to_string()))?;
    let duration_secs = flags.duration_secs;
    let conns = usize::try_from(flags.num_conns).unwrap_or(usize::MAX);
    let object_size = (write_mode(flags) == WriteMode::Paced).then_some(flags.object_size);
    let worker = Worker::new(flags.host_loop)?;
    let (outcomes_tx, outcomes) = mpsc::channel();
    let (started_tx, started) = mpsc::channel();
    let host_loop = flags.host_loop;
    worker.submit(move |worker| {
        let connect = match host_loop {
            HostLoop::Tokio => connect::<MmsgBackend>,
            HostLoop::Manual => connect::<HostBackend<ManualHost>>,
        };
        let sessions = (0..conns)
            .map(|index| ClientSession::new(index, duration_secs, object_size, outcomes_tx.clone()))
            .collect();
        let _ = started_tx.send(connect(
            worker, endpoint, options, remote, name, client, sessions,
        ));
    })?;
    started
        .recv()
        .map_err(|_| RunError::WorkerGone)?
        .map_err(RunError::Start)?;
    // A connection drains after it reports, possibly before another one reports.
    let mut drained = 0;
    let mut measured = Vec::with_capacity(conns);
    let result = loop {
        if measured.len() == conns {
            break write_results(out, flags, &mut measured).map_err(RunError::Output);
        }
        match outcomes.recv() {
            Ok(Outcome::Measured(report)) => measured.push(report),
            Ok(Outcome::Drained) => drained += 1,
            Ok(Outcome::Closed(reason)) => break Err(RunError::Closed(reason)),
            Err(_) => break Err(RunError::WorkerGone),
        }
    };
    while drained < conns
        && let Ok(outcome) = outcomes.recv_timeout(DRAIN_WAIT)
    {
        if matches!(outcome, Outcome::Drained) {
            drained += 1;
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
    spawn_server::<B>(OnWorker(worker), endpoint, settings, segments, |builder| {
        builder
            .bind_server(addr, server)
            .backend_options(B::options(options))
    })
}

/// Starts the server's driver with `spawn`, on backend `B`, after `socket` sets up its server
/// socket on the builder, and returns the socket's address and capabilities.
fn spawn_server<B: Backend>(
    spawn: impl SpawnDriver,
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
    let handle = spawn.spawn(builder).map_err(|error| error.to_string())?;
    let started = handle
        .local_addr()
        .zip(handle.server_caps())
        .ok_or_else(|| "the server driver has no socket".to_owned());
    let _ = driver.set(handle);
    started
}

/// Starts a client driver on `worker`, on backend `B`, and opens a connection to `remote` for
/// each of `sessions`.
fn connect<B: TperfBackend>(
    worker: &WorkerContext,
    endpoint: Arc<EndpointConfig>,
    options: MmsgOptions,
    remote: SocketAddr,
    name: ServerName<'static>,
    client: Arc<ClientConfig>,
    sessions: Vec<ClientSession>,
) -> Result<(), String> {
    let driver = EndpointDriver::<_, B>::builder(endpoint, ClientApp)
        .backend_options(B::options(options))
        .spawn(worker)
        .map_err(|error| error.to_string())?;
    sessions.into_iter().try_for_each(|session| {
        driver
            .connect(
                remote,
                name.clone(),
                Arc::clone(&client),
                ConnOptions::default(),
                session,
            )
            .map(drop)
            .map_err(|error| error.to_string())
    })
}

/// Writes the result lines for what the connections in `reports` received, which tperf's lines
/// total, then each connection's stats line under `--stats`, then the summary line. Returns what
/// each connection received, in the order the connections opened.
fn write_results(
    out: &mut impl Write,
    flags: &Flags,
    reports: &mut [ConnReport],
) -> io::Result<Vec<ConnTally>> {
    reports.sort_unstable_by_key(|report| report.index);
    let total = Measurement {
        bytes: reports.iter().map(|report| report.measurement.bytes).sum(),
        duration_secs: flags.duration_secs,
        streams: reports
            .iter()
            .map(|report| report.measurement.streams)
            .sum(),
    };
    for line in total.lines() {
        writeln!(out, "{line}")?;
    }
    if flags.stats {
        for report in reports.iter() {
            writeln!(
                out,
                "{}",
                client_stats_line(&report.stats, &report.received, flags.num_streams)
            )?;
        }
    }
    let tallies: Vec<ConnTally> = reports
        .iter_mut()
        .map(|report| mem::take(&mut report.received))
        .collect();
    writeln!(
        out,
        "{}",
        summary_line(
            write_mode(flags),
            flags.duration_secs,
            flags.num_streams,
            &tallies
        )
    )?;
    Ok(tallies)
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

/// Returns what a server writes, and a client reads, with `flags`: objects on a clock under
/// `--object_rate`.
fn write_mode(flags: &Flags) -> WriteMode {
    if flags.object_rate > 0 {
        WriteMode::Paced
    } else {
        WriteMode::Saturate
    }
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
    /// The server could not block the signals that end it.
    Signals(io::Error),
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
            Self::Signals(error) => write!(f, "cannot block SIGINT and SIGTERM: {error}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve { error, .. }
            | Self::Loop(error)
            | Self::Output(error)
            | Self::Signals(error) => Some(error),
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
    use std::task::Context;
    use std::task::Poll;

    use mvfstr_driver::Conn;
    use mvfstr_driver::ConnHandle;
    use mvfstr_driver::ConnInfo;
    use mvfstr_driver::QuicSession;
    use mvfstr_driver::Refusal;
    use mvfstr_driver::SendSink;
    use mvfstr_proto::AppCode;
    use mvfstr_proto::Bytes;
    use mvfstr_proto::ConnEvent;
    use mvfstr_proto::StreamId;
    use mvfstr_proto::StreamReady;

    use super::*;
    use crate::flags::QuicVersion;
    use crate::flags::TlsBackend;
    use crate::object::HEADER_LEN;
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
            closed.dropped_initials,
        );
        assert!(line.contains(" socket_stops="), "{line}");
        assert_eq!(
            server.closed_lines(),
            Vec::<String>::new(),
            "one connection"
        );
    }

    /// A spawner that starts each driver on a worker as tperf configured it, and counts them.
    struct Counting<'a>(&'a WorkerContext, Rc<std::cell::Cell<u32>>);

    impl SpawnDriver for Counting<'_> {
        fn spawn<A: QuicApplication, B: Backend>(
            self,
            builder: EndpointDriverBuilder<A, B>,
        ) -> Result<EndpointHandle<A, B>, DriverError> {
            self.1.set(self.1.get() + 1);
            builder.spawn(self.0)
        }
    }

    #[test]
    fn a_hosted_server_starts_its_driver_through_the_spawner_it_is_given() {
        let worker = ManagedWorker::new(WORKER_COMMANDS).unwrap();
        let (started_tx, started) = mpsc::channel();
        worker
            .handle()
            .submit(move |context| {
                let spawned = Rc::new(std::cell::Cell::new(0));
                let open = |addr, options: &MmsgOptions| {
                    Ok((MmsgBackend::bind(addr, options)?, HostTimers::tokio()))
                };
                let server = start_hosted_server_with(
                    &loopback(Mode::Server, 0),
                    open,
                    Counting(context, Rc::clone(&spawned)),
                );
                let _ = started_tx.send((server.is_ok(), spawned.get()));
            })
            .unwrap();
        assert_eq!(
            started.recv().unwrap(),
            (true, 1),
            "the one driver, through the spawner"
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
    fn a_server_whose_handshakes_run_on_an_external_tls_host_moves_bytes() {
        let server = start_server(&Flags {
            tls_backend: TlsBackend::External,
            stats: true,
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
        assert!(parsed.bytes > 0, "{output}");
        let Closed { stats, .. } = server
            .closed_connections()
            .recv_timeout(Duration::from_secs(10))
            .expect("the server reports the closed connection");
        assert!(stats.sent_packets > 0);
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
    fn a_server_given_initial_rtt_ms_ends_its_startup_line_with_it() {
        let lowered = Flags {
            initial_rtt_ms: Some(100),
            ..loopback(Mode::Server, 0)
        };
        let ends_with_the_initial_rtt = |line: &str| {
            let (rest, last) = line.rsplit_once(' ').unwrap_or_default();
            last == "initial_rtt_ms=100"
                && rest
                    .rsplit_once(' ')
                    .is_some_and(|(_, sndbuf)| sndbuf.starts_with("so_sndbuf="))
        };
        let server = start_server(&lowered).unwrap();
        assert!(
            ends_with_the_initial_rtt(server.startup_line()),
            "{}",
            server.startup_line()
        );
        let worker = ManagedWorker::new(WORKER_COMMANDS).unwrap();
        let (started_tx, started) = mpsc::channel();
        worker
            .handle()
            .submit(move |context| {
                let open = |addr, options: &MmsgOptions| {
                    Ok((MmsgBackend::bind(addr, options)?, HostTimers::tokio()))
                };
                let hosted = start_hosted_server(context, &lowered, open)
                    .map(|server| server.startup_line().to_owned())
                    .map_err(|error| error.to_string());
                let _ = started_tx.send(hosted);
            })
            .unwrap();
        let hosted = started.recv().unwrap().unwrap();
        assert!(
            ends_with_the_initial_rtt(&hosted),
            "a hosted server: {hosted}"
        );
        let default = start_server(&loopback(Mode::Server, 0)).unwrap();
        assert!(
            !default.startup_line().contains("initial_rtt_ms"),
            "{}",
            default.startup_line()
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
        let stats = output
            .lines()
            .find(|line| line.starts_with("Stats: "))
            .unwrap_or_default();
        assert!(stats.starts_with("Stats: sent_packets="), "{output}");
        assert!(!stats.contains("recv_packets=0 "), "{output}");
    }

    /// The keys of the client's summary line, in order.
    const SUMMARY_KEYS: [&str; 15] = [
        "stack",
        "mode",
        "conns",
        "streams_per_conn",
        "duration_s",
        "bytes",
        "mbps",
        "conn_mbps_min",
        "conn_mbps_p50",
        "conn_mbps_max",
        "stream_bytes_min",
        "stream_bytes_max",
        "streams_opened",
        "stream_spread_p50",
        "stream_spread_max",
    ];

    /// The keys that a paced run adds to the client's summary line, in order.
    const PACED_KEYS: [&str; 7] = [
        "objects",
        "bad_objects",
        "lat_us_p50",
        "lat_us_p90",
        "lat_us_p99",
        "lat_us_p999",
        "lat_us_max",
    ];

    /// The keys of the server's summary line, in order: those of every mode, those that paced
    /// mode adds, and the driver's counters, which end the line in every mode.
    const SERVER_KEYS: [&str; 3] = ["stack", "mode", "conns"];
    const SERVER_PACED_KEYS: [&str; 3] = ["objects_sent", "objects_dropped", "late_ticks"];
    const SERVER_DRIVER_KEYS: [&str; 2] = ["dropped_initials", "turns"];

    /// Returns the keys of a paced server summary line.
    fn server_paced_keys() -> Vec<&'static str> {
        SERVER_KEYS
            .iter()
            .chain(&SERVER_PACED_KEYS)
            .chain(&SERVER_DRIVER_KEYS)
            .copied()
            .collect()
    }

    /// The fields of a summary line, as a harness reads them.
    struct Summary<'a> {
        line: &'a str,
        fields: Vec<(&'a str, &'a str)>,
    }

    impl Summary<'_> {
        fn get(&self, key: &str) -> &str {
            self.fields
                .iter()
                .find_map(|&(name, value)| (name == key).then_some(value))
                .unwrap_or_else(|| panic!("no {key} in {}", self.line))
        }

        fn int(&self, key: &str) -> u64 {
            let value = self.get(key);
            value
                .parse()
                .unwrap_or_else(|_| panic!("{key}={value} is not an integer in {}", self.line))
        }

        fn float(&self, key: &str) -> f64 {
            let value = self.get(key);
            value
                .parse()
                .unwrap_or_else(|_| panic!("{key}={value} is not a number in {}", self.line))
        }
    }

    /// Returns the one line of `output` whose first word is `tag`, after checking that its
    /// fields are `key=value` pairs with the keys `keys`, in order.
    fn read_summary<'a>(output: &'a str, tag: &str, keys: &[&str]) -> Summary<'a> {
        let lines: Vec<&str> = output
            .lines()
            .filter(|line| line.split(' ').next() == Some(tag))
            .collect();
        let &[line] = lines.as_slice() else {
            panic!("{} {tag} lines in {output:?}", lines.len());
        };
        let fields: Vec<(&str, &str)> = line
            .split(' ')
            .skip(1)
            .map(|field| {
                field
                    .split_once('=')
                    .unwrap_or_else(|| panic!("{field:?} is not key=value in {line}"))
            })
            .collect();
        let names: Vec<&str> = fields.iter().map(|&(name, _)| name).collect();
        assert_eq!(names, keys, "{line}");
        Summary { line, fields }
    }

    /// Returns the keys of a paced client summary line.
    fn paced_keys() -> Vec<&'static str> {
        SUMMARY_KEYS.iter().chain(&PACED_KEYS).copied().collect()
    }

    /// Returns megabits of 10^6 bits per second as the summary lines print them.
    fn mbps(bytes: u64, duration_secs: u32) -> String {
        format!("{:.3}", bytes as f64 * 8.0 / 1e6 / f64::from(duration_secs))
    }

    #[test]
    fn a_default_run_prints_tperfs_three_lines_and_then_one_saturate_summary_line() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..loopback(Mode::Client, 0)
            },
        );
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4, "{output}");
        let parsed = report::parse(&lines[..3].join("\n"))
            .unwrap_or_else(|| panic!("no result lines first in {output:?}"));
        assert!(parsed.bytes > 0, "{output}");
        let summary = read_summary(lines[3], "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(
            [summary.get("stack"), summary.get("mode")],
            ["mvfstr", "saturate"],
            "{output}"
        );
        assert_eq!(
            ["conns", "streams_per_conn", "duration_s", "streams_opened"]
                .map(|key| summary.int(key)),
            [1, 1, 1, 1],
            "{output}"
        );
        assert_eq!(
            ["bytes", "stream_bytes_min", "stream_bytes_max"].map(|key| summary.int(key)),
            [parsed.bytes; 3],
            "the one stream carries what the first line counts: {output}"
        );
        let expected = mbps(parsed.bytes, 1);
        for key in ["mbps", "conn_mbps_min", "conn_mbps_p50", "conn_mbps_max"] {
            assert_eq!(summary.get(key), expected, "{key}: {output}");
        }
        assert_eq!(
            [
                summary.get("stream_spread_p50"),
                summary.get("stream_spread_max")
            ],
            ["1.000"; 2],
            "the one stream got bytes: {output}"
        );
    }

    #[test]
    fn under_stats_the_summary_line_comes_last_after_the_stats_line() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                stats: true,
                ..loopback(Mode::Client, 0)
            },
        );
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 5, "{output}");
        assert!(lines[3].starts_with("Stats: sent_packets="), "{output}");
        read_summary(lines[4], "tperf_summary", &SUMMARY_KEYS);
    }

    #[test]
    fn under_stats_each_connection_prints_its_stats_line_before_the_summary_line() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                num_conns: 2,
                stats: true,
                ..loopback(Mode::Client, 0)
            },
        );
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 6, "{output}");
        for line in &lines[3..5] {
            assert!(line.starts_with("Stats: sent_packets="), "{output}");
            assert!(!line.contains("recv_packets=0 "), "{output}");
        }
        let summary = read_summary(lines[5], "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(summary.int("conns"), 2, "{output}");
    }

    #[test]
    fn under_stats_each_connection_prints_its_stream_spread_and_the_summary_their_median_and_max() {
        const STREAMS: u32 = 4;
        let server = start_server(&Flags {
            num_streams: STREAMS,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let flags = Flags {
            duration_secs: 1,
            num_conns: 2,
            num_streams: STREAMS,
            stats: true,
            port: server.addr().port(),
            ..loopback(Mode::Client, 0)
        };
        let mut out = Vec::new();
        let conns =
            run_client_with(&flags, config::client_config(&flags).unwrap(), &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        // A saturating server feeds every stream on loopback, so each spread is finite.
        let mut spreads: Vec<f64> = conns
            .iter()
            .map(|conn| {
                let smallest = conn.stream_bytes.iter().copied().min().unwrap_or(0);
                let largest = conn.stream_bytes.iter().copied().max().unwrap_or(0);
                assert_eq!(
                    conn.stream_bytes.len(),
                    STREAMS as usize,
                    "{conn:?}: {output}"
                );
                assert!(smallest > 0, "{conn:?}: {output}");
                largest as f64 / smallest as f64
            })
            .collect();
        let printed: Vec<&str> = output
            .lines()
            .filter(|line| line.starts_with("Stats: "))
            .map(|line| {
                line.rsplit_once(" stream_spread=")
                    .unwrap_or_else(|| panic!("no stream_spread in {line}"))
                    .1
            })
            .collect();
        let expected: Vec<String> = spreads
            .iter()
            .map(|spread| format!("{spread:.3}"))
            .collect();
        assert_eq!(printed, expected, "in connection order: {output}");

        spreads.sort_by(f64::total_cmp);
        let [lower, upper] = [spreads[0], spreads[1]].map(|spread| format!("{spread:.3}"));
        let summary = read_summary(&output, "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(
            summary.get("stream_spread_p50"),
            lower,
            "the median of two is the lower: {output}"
        );
        assert_eq!(summary.get("stream_spread_max"), upper, "{output}");
    }

    #[test]
    fn a_stream_the_client_expects_but_never_receives_makes_its_connections_spread_infinite() {
        let server = start_server(&Flags {
            num_streams: 2,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let flags = Flags {
            duration_secs: 1,
            num_streams: 3,
            stats: true,
            port: server.addr().port(),
            ..loopback(Mode::Client, 0)
        };
        let mut out = Vec::new();
        let conns =
            run_client_with(&flags, config::client_config(&flags).unwrap(), &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        assert_eq!(conns.len(), 1, "{output}");
        assert_eq!(
            conns[0].stream_bytes.len(),
            2,
            "the server opens two streams: {output}"
        );
        assert!(
            conns[0].stream_bytes.iter().all(|&bytes| bytes > 0),
            "{output}"
        );
        let stats: Vec<&str> = output
            .lines()
            .filter(|line| line.starts_with("Stats: "))
            .collect();
        assert_eq!(stats.len(), 1, "{output}");
        assert!(
            stats[0].ends_with(" stream_spread=inf"),
            "the third stream counts with 0 bytes: {output}"
        );
        let summary = read_summary(&output, "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(summary.int("streams_per_conn"), 3, "{output}");
        assert_eq!(
            [
                summary.get("stream_spread_p50"),
                summary.get("stream_spread_max")
            ],
            ["inf"; 2],
            "{output}"
        );
    }

    #[test]
    fn a_paced_server_that_cannot_keep_up_drops_its_oldest_objects_and_counts_late_ticks() {
        // A 64 KiB object every 20 µs is 3.3 GB/s on one stream, more than the loopback carries,
        // so ticks start late and, once 64 objects wait, each tick drops the oldest. The first
        // object fits the transport's 64 KiB per-stream staging cap. The next needs 64 KiB to
        // leave and a `Writable` edge to resume the stream, about 65 ms even at 1 MB/s.
        let paced = |mode| Flags {
            object_rate: 50_000,
            object_size: 64 << 10,
            ..loopback(mode, 0)
        };
        let server = start_server(&paced(Mode::Server)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..paced(Mode::Client)
            },
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(summary.get("mode"), "paced", "{output}");
        let line = server.summary_line();
        let served = read_summary(&line, "tperf_server_summary", &server_paced_keys());
        assert!(
            served.int("objects_sent") > 1,
            "the server writes a blocked stream again after its `Writable` edge: {line}"
        );
        assert!(served.int("objects_dropped") > 0, "{line}");
        assert!(served.int("late_ticks") > 0, "{line}");
    }

    #[test]
    fn ticks_that_one_timer_wake_runs_together_are_late_only_if_objects_wait() {
        // At 10,000 ticks a second the driver's millisecond timer runs about ten ticks per wake.
        // Header-only objects keep the byte rate low enough that the stream can drain each tick.
        let paced = |mode| Flags {
            object_rate: 10_000,
            object_size: HEADER_LEN as u32,
            ..loopback(mode, 0)
        };
        let server = start_server(&paced(Mode::Server)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..paced(Mode::Client)
            },
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert!(
            summary.int("objects") >= 8_000,
            "a wake runs every tick it missed, so most of the 10,000 arrive: {output}"
        );
        let line = server.summary_line();
        let served = read_summary(&line, "tperf_server_summary", &server_paced_keys());
        assert!(
            served.int("late_ticks") * 10 < served.int("objects_sent"),
            "{line}"
        );
    }

    #[test]
    fn four_connections_of_sixteen_streams_feed_every_stream_within_twice_the_smallest() {
        let server = start_server(&Flags {
            num_streams: 16,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let flags = Flags {
            duration_secs: 2,
            num_conns: 4,
            num_streams: 16,
            port: server.addr().port(),
            ..loopback(Mode::Client, 0)
        };
        let mut out = Vec::new();
        let conns =
            run_client_with(&flags, config::client_config(&flags).unwrap(), &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert_eq!(
            parsed.streams, 64,
            "tperf's lines count the streams of every connection: {output}"
        );
        let summary = read_summary(&output, "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(summary.get("mode"), "saturate", "{output}");
        assert_eq!(
            ["conns", "streams_per_conn", "duration_s", "streams_opened"]
                .map(|key| summary.int(key)),
            [4, 16, 2, 64],
            "{output}"
        );
        assert!(summary.int("stream_bytes_min") > 0, "{output}");

        assert_eq!(conns.len(), 4, "{output}");
        let mut total = 0;
        for (index, conn) in conns.iter().enumerate() {
            let smallest = conn.stream_bytes.iter().copied().min().unwrap_or(0);
            let largest = conn.stream_bytes.iter().copied().max().unwrap_or(0);
            eprintln!(
                "connection {index}: {} streams, {smallest} to {largest} bytes per stream",
                conn.stream_bytes.len()
            );
            assert_eq!(conn.stream_bytes.len(), 16, "connection {index}: {conn:?}");
            assert!(smallest > 0, "connection {index}: {conn:?}");
            assert!(
                largest <= 2 * smallest,
                "connection {index}: the largest stream got more than twice the smallest: \
                 {conn:?}"
            );
            total += conn.stream_bytes.iter().sum::<u64>();
        }
        assert_eq!(summary.int("bytes"), total, "{output}");
        assert_eq!(
            parsed.bytes, total,
            "tperf's lines count the bytes of every connection: {output}"
        );
        let line = server.summary_line();
        let keys: Vec<&str> = SERVER_KEYS
            .iter()
            .chain(&SERVER_DRIVER_KEYS)
            .copied()
            .collect();
        let served = read_summary(&line, "tperf_server_summary", &keys);
        assert_eq!(
            [served.get("stack"), served.get("mode"), served.get("conns")],
            ["mvfstr", "saturate", "4"]
        );
        assert_eq!(served.int("dropped_initials"), 0, "{line}");
    }

    #[test]
    fn the_server_summary_line_ends_with_its_drivers_dropped_initials_and_turns() {
        let server = start_server(&loopback(Mode::Server, 0)).unwrap();
        client_output(
            &server,
            Flags {
                duration_secs: 1,
                num_conns: 2,
                ..loopback(Mode::Client, 0)
            },
        );
        let line = server.summary_line();
        let keys: Vec<&str> = SERVER_KEYS
            .iter()
            .chain(&SERVER_DRIVER_KEYS)
            .copied()
            .collect();
        let served = read_summary(&line, "tperf_server_summary", &keys);
        assert_eq!(served.int("conns"), 2, "{line}");
        assert_eq!(
            served.int("dropped_initials"),
            0,
            "two connections fit the waiting queue: {line}"
        );
        assert!(
            served.int("turns") > 0,
            "the server's driver ran turns to accept them: {line}"
        );
    }

    /// A client application whose session passes the connection's handle to the test once the
    /// handshake completes; the connection stays open until the test closes it.
    struct HandOver;

    impl QuicApplication for HandOver {
        type Session = Handed;

        fn accept(
            &mut self,
            _info: &ConnInfo,
            _options: &mut ConnOptions,
        ) -> Result<Handed, Refusal> {
            Err(Refusal::Refuse)
        }
    }

    /// The session of a [`HandOver`] client's connection.
    struct Handed(mpsc::Sender<ConnHandle>);

    impl QuicSession for Handed {
        fn on_event(&mut self, conn: &mut Conn<'_>, event: ConnEvent) {
            if matches!(event, ConnEvent::Connected) {
                let _ = self.0.send(conn.handle());
            }
        }

        fn on_stream(&mut self, _conn: &mut Conn<'_>, _id: StreamId, _ready: StreamReady) {}

        fn poll_send(
            &mut self,
            _cx: &mut Context<'_>,
            _id: StreamId,
            _sink: &mut SendSink<'_>,
        ) -> Poll<()> {
            Poll::Pending
        }

        fn poll_session(&mut self, _cx: &mut Context<'_>, _conn: &mut Conn<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    #[test]
    fn the_server_summary_has_the_drivers_turns_as_of_its_last_accept_or_close() {
        let server = start_server(&Flags {
            stats: true,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let flags = loopback(Mode::Client, server.addr().port());
        let endpoint = config::endpoint_config(&flags).unwrap();
        let client = config::client_config(&flags).unwrap();
        let options = backend_options(&flags);
        let remote = server.addr();
        let worker = ManagedWorker::new(WORKER_COMMANDS).unwrap();
        let (handles_tx, handles) = mpsc::channel();
        worker
            .handle()
            .submit(move |context| {
                let driver = EndpointDriver::<_, MmsgBackend>::builder(endpoint, HandOver)
                    .backend_options(options)
                    .spawn(context)
                    .expect("the client's driver starts");
                let name = ServerName::try_from(SERVER_NAME).expect("a valid server name");
                driver
                    .connect(
                        remote,
                        name,
                        client,
                        ConnOptions::default(),
                        Handed(handles_tx),
                    )
                    .expect("the client connects");
            })
            .unwrap();
        let keys: Vec<&str> = SERVER_KEYS
            .iter()
            .chain(&SERVER_DRIVER_KEYS)
            .copied()
            .collect();

        // The server accepted the connection before it sent the flight that completes the
        // client's handshake, and it has not closed it.
        let handle = handles
            .recv_timeout(Duration::from_secs(10))
            .expect("the client's handshake completes");
        let line = server.summary_line();
        let accepted = read_summary(&line, "tperf_server_summary", &keys);
        assert_eq!(accepted.int("conns"), 1, "{line}");
        let turns = accepted.int("turns");
        assert!(
            turns > 0,
            "the summary has the driver's turns as of the server's accept: {line}"
        );

        // The server reads the close in a later turn than the one in which it accepted the
        // connection.
        handle.close(AppCode::from_u32(0), Bytes::new()).unwrap();
        server
            .closed_connections()
            .recv_timeout(Duration::from_secs(10))
            .expect("the server's connection closes");
        let line = server.summary_line();
        let closed = read_summary(&line, "tperf_server_summary", &keys);
        assert_eq!(closed.int("conns"), 1, "{line}");
        assert!(
            closed.int("turns") > turns,
            "the summary has the driver's turns as of the server's close: {line}"
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn paced_objects_reach_eight_connections_of_two_streams_at_the_rate_with_low_latency() {
        const OBJECT_SIZE: u64 = 1200;
        let paced = |mode| Flags {
            num_streams: 2,
            object_rate: 50,
            object_size: OBJECT_SIZE as u32,
            ..loopback(mode, 0)
        };
        let server = start_server(&paced(Mode::Server)).unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 2,
                num_conns: 8,
                ..paced(Mode::Client)
            },
        );
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(
            parsed.bytes < (1760 + 16) * OBJECT_SIZE,
            "the server paces rather than saturates: {output}"
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(summary.get("mode"), "paced", "{output}");
        assert_eq!(
            ["conns", "streams_per_conn", "duration_s", "streams_opened"]
                .map(|key| summary.int(key)),
            [8, 2, 2, 16],
            "{output}"
        );
        // 8 connections × 2 streams × 50 objects per second × 2 s, within 10 %.
        let objects = summary.int("objects");
        assert!((1440..=1760).contains(&objects), "{output}");
        assert_eq!(summary.int("bad_objects"), 0, "{output}");
        // Objects count in the window that bytes count in; each stream may end inside one.
        let bytes = summary.int("bytes");
        assert!(
            objects * OBJECT_SIZE <= bytes && bytes < (objects + 16) * OBJECT_SIZE,
            "{output}"
        );
        let latencies = [
            "lat_us_p50",
            "lat_us_p90",
            "lat_us_p99",
            "lat_us_p999",
            "lat_us_max",
        ]
        .map(|key| summary.int(key));
        assert!(latencies[0] > 0, "{output}");
        assert!(latencies.is_sorted(), "{output}");
        assert!(
            latencies[3] < 50_000,
            "p99.9 under 50 ms on idle loopback: {output}"
        );

        let line = server.summary_line();
        let served = read_summary(&line, "tperf_server_summary", &server_paced_keys());
        assert_eq!(
            [served.get("stack"), served.get("mode"), served.get("conns")],
            ["mvfstr", "paced", "8"]
        );
        let sent = served.int("objects_sent");
        assert!(
            objects <= sent && sent <= 2 * objects,
            "the server sent what the client received and what the closes cut off: {line}"
        );
        assert_eq!(
            served.int("objects_dropped"),
            0,
            "streams on idle loopback take every object: {line}"
        );
        served.int("late_ticks");
    }

    #[test]
    fn streams_per_conn_is_the_clients_num_streams_when_each_stream_carries_one_object() {
        // Each stream ends with its first object, often before the client hears of the others.
        let paced = |mode| Flags {
            num_streams: 16,
            object_rate: 50,
            ..loopback(mode, 0)
        };
        let server = start_server(&Flags {
            bytes_per_stream: 1200,
            ..paced(Mode::Server)
        })
        .unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                ..paced(Mode::Client)
            },
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(summary.int("streams_per_conn"), 16, "{output}");
        assert!(
            summary.int("streams_opened") > 16,
            "streams were replaced: {output}"
        );
        assert_eq!(
            summary.int("stream_bytes_max"),
            1200,
            "one object per stream: {output}"
        );
        assert_eq!(summary.int("bad_objects"), 0, "{output}");
    }

    #[test]
    fn the_clients_object_rate_and_not_what_the_server_writes_sets_its_mode() {
        let server = |object_rate| {
            start_server(&Flags {
                num_streams: 2,
                object_rate,
                ..loopback(Mode::Server, 0)
            })
            .unwrap()
        };
        let client = |object_rate| Flags {
            duration_secs: 1,
            num_streams: 2,
            object_rate,
            ..loopback(Mode::Client, 0)
        };
        let output = client_output(&server(50), client(0));
        let summary = read_summary(&output, "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(summary.get("mode"), "saturate", "{output}");

        let output = client_output(&server(0), client(50));
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(summary.get("mode"), "paced", "{output}");
        assert_eq!(
            ["objects", "bad_objects"].map(|key| summary.int(key)),
            [0, 2],
            "each stream of zeros starts with a length of 0: {output}"
        );
    }

    #[test]
    fn a_client_whose_object_size_differs_from_the_servers_counts_bad_objects_and_no_latency() {
        let server = start_server(&Flags {
            num_streams: 2,
            object_rate: 50,
            ..loopback(Mode::Server, 0)
        })
        .unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 1,
                num_streams: 2,
                object_rate: 50,
                object_size: 1000,
                ..loopback(Mode::Client, 0)
            },
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(
            ["objects", "bad_objects", "lat_us_max"].map(|key| summary.int(key)),
            [0, 2, 0],
            "each stream's first object is 1,200 bytes long: {output}"
        );
    }

    #[test]
    fn streams_per_conn_is_the_clients_num_streams_when_saturated_streams_roll_over() {
        // A stream's last bytes and its FIN go out in one push, and its replacement opens at once.
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
                num_conns: 2,
                num_streams: 2,
                ..loopback(Mode::Client, 0)
            },
        );
        let summary = read_summary(&output, "tperf_summary", &SUMMARY_KEYS);
        assert_eq!(summary.get("mode"), "saturate", "{output}");
        assert_eq!(summary.int("streams_per_conn"), 2, "{output}");
        assert!(
            summary.int("streams_opened") > 2 * 2,
            "streams were replaced: {output}"
        );
    }

    #[test]
    fn paced_streams_roll_over_on_an_object_boundary_once_they_reach_bytes_per_stream() {
        // Each stream ends after the object that takes it to 3,000 bytes: its third, at 3,600.
        let paced = |mode| Flags {
            num_streams: 2,
            object_rate: 50,
            object_size: 1200,
            ..loopback(mode, 0)
        };
        let server = start_server(&Flags {
            bytes_per_stream: 3000,
            ..paced(Mode::Server)
        })
        .unwrap();
        let output = client_output(
            &server,
            Flags {
                duration_secs: 2,
                num_conns: 2,
                ..paced(Mode::Client)
            },
        );
        let parsed =
            report::parse(&output).unwrap_or_else(|| panic!("no result lines in {output:?}"));
        assert!(
            parsed.bytes < (440 + 4) * 1200,
            "the server paces rather than saturates: {output}"
        );
        let summary = read_summary(&output, "tperf_summary", &paced_keys());
        assert_eq!(summary.get("mode"), "paced", "{output}");
        assert_eq!(summary.int("conns"), 2, "{output}");
        assert_eq!(summary.int("streams_per_conn"), 2, "{output}");
        let opened = summary.int("streams_opened");
        assert!(opened > 2 * 2, "streams were replaced: {output}");
        // Each of the 4 streams rolls over every 3 objects, 60 ms, so about 33 times in 2 s.
        assert!(opened > 40, "{output}");
        assert_eq!(summary.int("stream_bytes_max"), 3600, "{output}");
        assert_eq!(
            summary.int("bad_objects"),
            0,
            "a stream ends on an object boundary: {output}"
        );
        // 2 connections × 2 streams × 50 objects per second × 2 s, within 10 %.
        assert!(
            (360..=440).contains(&summary.int("objects")),
            "rolling over loses no object: {output}"
        );
        assert!(summary.float("mbps") > 0.0, "{output}");
    }
}
