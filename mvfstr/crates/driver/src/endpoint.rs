/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The endpoint driver and its builder.

use std::cell::Cell;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::rc::Rc;
use std::rc::Weak;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

use mvfstr_io::Backend;
use mvfstr_io::TxCaps;
use mvfstr_proto::ClientConfig;
use mvfstr_proto::ConfigError;
use mvfstr_proto::ConnOptions;
use mvfstr_proto::ConnectError;
use mvfstr_proto::Endpoint;
use mvfstr_proto::EndpointConfig;
use mvfstr_proto::ServerConfig;
use mvfstr_proto::SrcPortBlocklist;
use mvfstr_proto::TlsHost;
use roxygen_runtime::panic::discard_panic;
use roxygen_runtime::worker::CleanupRegistrationError;
use roxygen_runtime::worker::WorkerContext;
use rustls::pki_types::ServerName;

use crate::ConnHandle;
use crate::HostTimers;
use crate::QuicApplication;
use crate::Steering;
use crate::WorkBudget;
#[cfg(test)]
use crate::timers::Kind;
use crate::turn::Core;
use crate::turn::EndpointStats;
use crate::turn::Limits;
use crate::turn::Server;
#[cfg(test)]
use crate::turn::TxRecord;

/// The task that runs one endpoint on a Roxygen worker: it owns the worker's UDP sockets through
/// backends of type `B`, the sans-IO endpoint and the slab of connections and sessions, and runs
/// one turn each time it is woken. Built with [`EndpointDriver::builder`] and started with
/// [`EndpointDriverBuilder::spawn`].
pub struct EndpointDriver<A: QuicApplication, B: Backend> {
    _types: PhantomData<(A, B)>,
}

impl<A: QuicApplication, B: Backend> EndpointDriver<A, B> {
    /// Starts building a driver for `application`, whose connections share `config`. The
    /// backend type is named here, as in `EndpointDriver::<_, SomeBackend>::builder(..)`.
    pub fn builder(config: Arc<EndpointConfig>, application: A) -> EndpointDriverBuilder<A, B> {
        EndpointDriverBuilder {
            config,
            application,
            server: None,
            backend_options: B::Options::default(),
            limits: Limits::default(),
            worker: None,
            steering: None,
            host_timers: None,
            budget: None,
            tls_host: None,
        }
    }
}

impl<A: QuicApplication, B: Backend> fmt::Debug for EndpointDriver<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointDriver").finish_non_exhaustive()
    }
}

/// Where a server driver accepts connections.
enum ServerSocket<B> {
    /// A socket the driver binds to this address.
    Bind(SocketAddr),
    /// A socket the caller opened.
    Given(B),
}

/// A builder for an [`EndpointDriver`].
pub struct EndpointDriverBuilder<A: QuicApplication, B: Backend> {
    config: Arc<EndpointConfig>,
    application: A,
    server: Option<(ServerSocket<B>, Arc<ServerConfig>)>,
    backend_options: B::Options,
    limits: Limits,
    worker: Option<(u16, u16)>,
    steering: Option<Arc<Steering>>,
    host_timers: Option<HostTimers>,
    budget: Option<WorkBudget>,
    tls_host: Option<Box<dyn TlsHost>>,
}

impl<A: QuicApplication, B: Backend> EndpointDriverBuilder<A, B> {
    /// Replaces the per-turn caps and the transmit batch limit, so tests can reach them with
    /// little traffic.
    #[cfg(test)]
    pub(crate) fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Accepts connections on a UDP socket bound to `addr` (SO_REUSEPORT, so each worker binds
    /// its own and sets its index with [`worker`](Self::worker)), with `config`. Without this the
    /// endpoint only opens connections.
    pub fn bind_server(mut self, addr: SocketAddr, config: Arc<ServerConfig>) -> Self {
        self.server = Some((ServerSocket::Bind(addr), config));
        self
    }

    /// Accepts connections on `backend`, a server socket the caller opened, with `config`,
    /// instead of [`bind_server`](Self::bind_server); the later of the two calls applies.
    pub fn serve(mut self, backend: B, config: Arc<ServerConfig>) -> Self {
        self.server = Some((ServerSocket::Given(backend), config));
        self
    }

    /// Makes the driver worker `index` of `count` workers whose drivers bind the same server
    /// address. Every connection ID its endpoint issues then names that worker, and a short-header
    /// packet that names another worker is dropped rather than answered with a stateless reset.
    /// Without this call the endpoint config is used as given.
    pub fn worker(mut self, index: u16, count: u16) -> Self {
        self.worker = Some((index, count));
        self
    }

    /// Spreads new connections over the workers of `group`, whose drivers serve the same address:
    /// the driver that receives a client's first Initial hands it to the next worker in turn,
    /// which accepts it and issues connection IDs that name it. The kernel must deliver every
    /// later datagram to the worker its connection ID names, so the server socket must be the one
    /// this worker bound `index`-th, `index` as given to [`worker`](Self::worker), into a
    /// SO_REUSEPORT group that carries
    /// [`steer_by_connection_id`](mvfstr_io::socket::steer_by_connection_id).
    /// [`spawn`](Self::spawn) fails with [`DriverError::Config`] unless that socket was given with
    /// [`serve`](Self::serve) and [`worker`](Self::worker) set the group's worker count.
    pub fn steering(mut self, group: Arc<Steering>) -> Self {
        self.steering = Some(group);
        self
    }

    /// Caps the datagrams one transmit attempt builds at `segments`, at least 1, which bounds the
    /// segments of one GSO send below the backend's own limit, as `--writes_per_loop` does in
    /// mvfst's tperf. Default: the backend's limit, which is 1 without GSO.
    pub fn max_segments(mut self, segments: u16) -> Self {
        self.limits.max_segments = segments.max(1);
        self
    }

    /// Sets the timers that wake the driver. Default [`HostTimers::tokio`], the timers of a
    /// Roxygen worker on Tokio; a host without a Tokio reactor passes its own.
    pub fn host_timers(mut self, timers: HostTimers) -> Self {
        self.host_timers = Some(timers);
        self
    }

    /// Runs the driver's polls under `budget`, which the drivers of one host share. The work of a
    /// poll then comes in units: one transmit attempt, one receive chunk of up to 64 datagrams,
    /// one accept, one application visit, one intake serve, one waiting Initial. The driver checks
    /// the budget before each unit of a poll but the first. Once the slice has closed, the poll
    /// ends with the rest of the work left in place and the driver's task woken again, so the
    /// next poll continues where this one ended. A poll entered while the slice is closed or the
    /// budget held does not run any work, unless the budget has a grant pending, which lets it run
    /// one unit. A budget also caps each transmit attempt at 64 datagrams. Without a budget, each
    /// poll runs whole turns.
    pub fn work_budget(mut self, budget: WorkBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Runs the handshakes of the connections whose configs name an External TLS backend
    /// ([`ServerTls::External`](mvfstr_proto::ServerTls::External),
    /// [`ClientTls::External`](mvfstr_proto::ClientTls::External)) on `host`, on the driver's
    /// thread. A step the host answers at once leaves in the turn of the call unless a stop under a
    /// work budget delays it. A host that answers `Pending` must wake the driver through
    /// [`EndpointHandle::tls_waker`] once the step is ready. Without a host, the sessions drive
    /// those handshakes through [`Conn`](crate::Conn).
    pub fn tls_host(mut self, host: Box<dyn TlsHost>) -> Self {
        self.tls_host = Some(host);
        self
    }

    /// Sets the socket settings of every backend the driver opens. Default `B::Options::default()`.
    pub fn backend_options(mut self, options: B::Options) -> Self {
        self.backend_options = options;
        self
    }

    /// Binds the sockets and starts the driver on `worker`, as a task polled only when woken and
    /// registered with the worker's cleanup scope, so worker shutdown drains it. Must run on the
    /// worker's thread.
    pub fn spawn(self, worker: &WorkerContext) -> Result<EndpointHandle<A, B>, DriverError> {
        let steering = match self.steering {
            None => None,
            Some(group) => match (self.worker, &self.server) {
                (Some((index, count)), Some((ServerSocket::Given(_), _)))
                    if count == group.workers() =>
                {
                    Some((group, index))
                }
                _ => return Err(ConfigError::OutOfRange { field: "steering" }.into()),
            },
        };
        let config = match self.worker {
            Some((index, count)) => self.config.to_builder().worker(index, count).build()?,
            None => self.config,
        };
        let server = match self.server {
            Some((ServerSocket::Bind(addr), config)) => {
                Some(Server::new(B::bind(addr, &self.backend_options)?, config)?)
            }
            Some((ServerSocket::Given(backend), config)) => Some(Server::new(backend, config)?),
            None => None,
        };
        let mut endpoint = Endpoint::new(
            config,
            server.as_ref().map(|server| Arc::clone(server.config())),
        );
        // Set first: each accepted connection fixes its build horizon from the release horizon.
        if let Some(server) = &server {
            endpoint.set_release_horizon(server.caps().release.horizon());
        }
        let core = Rc::new(
            Core::new(
                worker,
                endpoint,
                self.application,
                server,
                self.backend_options,
                self.limits,
                steering,
                self.host_timers.unwrap_or_else(HostTimers::tokio),
            )
            .with_budget(self.budget)
            .with_tls_host(self.tls_host),
        );
        let task = Rc::clone(&core);
        worker
            .register_scope(poll_fn(move |cx| task.poll(cx)))?
            .activate()?
            .detach();
        Ok(EndpointHandle {
            core: Rc::downgrade(&core),
            last: core.last_stats(),
        })
    }
}

impl<A: QuicApplication, B: Backend> fmt::Debug for EndpointDriverBuilder<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let server = self.server.as_ref().map(|(socket, _)| match socket {
            ServerSocket::Bind(addr) => Some(*addr),
            ServerSocket::Given(backend) => backend.local_addr().ok(),
        });
        f.debug_struct("EndpointDriverBuilder")
            .field("server", &server)
            .finish_non_exhaustive()
    }
}

/// Control of a running driver from its own worker thread; not `Send`.
pub struct EndpointHandle<A: QuicApplication, B: Backend> {
    core: Weak<Core<A, B>>,
    /// The driver's counters as it ended.
    last: Rc<Cell<EndpointStats>>,
}

impl<A: QuicApplication, B: Backend> EndpointHandle<A, B> {
    /// Returns the server socket's local address, if the driver accepts connections.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.core.upgrade()?.local_addr()
    }

    /// Returns the server socket's capabilities, fixed at bind, if the driver accepts connections:
    /// among them its release horizon, which bounds every accepted connection's build horizon, and
    /// the send buffer the kernel granted.
    pub fn server_caps(&self) -> Option<TxCaps> {
        self.core.upgrade()?.server_caps()
    }

    /// Returns the waker that the driver's TLS host must wake, from any thread, when it completes
    /// a step it answered `Pending`; the driver then takes the step through
    /// [`TlsHost::poll_ready`]. `None` without a TLS host or once the driver has ended.
    pub fn tls_waker(&self) -> Option<Waker> {
        self.core.upgrade()?.tls_waker()
    }

    /// Opens a client connection to `remote` with `session` as its application state, on its own
    /// connected UDP socket from [`Backend::connect`]. Fails with [`io::ErrorKind::NotConnected`]
    /// once the driver has stopped or started a quiesce, and with [`io::ErrorKind::Other`] if
    /// creating the connection panicked, in TLS or the application's TLS config. Such a panic is
    /// contained, and so is one in the `Drop` of a failed call's session, even after the driver
    /// has stopped; while the driver runs, each is counted in [`EndpointStats::contained_panics`].
    pub fn connect(
        &self,
        remote: SocketAddr,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
        options: ConnOptions,
        session: A::Session,
    ) -> Result<ConnHandle, DriverConnectError> {
        let Some(core) = self.core.upgrade() else {
            // The driver has ended, so the panic is not counted, but it stays inside this call.
            if let Err(payload) = catch_unwind(AssertUnwindSafe(move || drop(session))) {
                discard_panic(payload);
            }
            return Err(DriverConnectError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "the endpoint driver has stopped",
            )));
        };
        core.connect(remote, server_name, config, options, session)
    }

    /// Replaces the source ports the driver's endpoint refuses, as
    /// [`Endpoint::set_src_port_blocklist`] describes; the next connection attempt is checked
    /// against it. Once the driver has stopped, the call is ignored.
    pub fn set_src_port_blocklist(&self, blocklist: Option<Arc<SrcPortBlocklist>>) {
        if let Some(core) = self.core.upgrade() {
            core.set_src_port_blocklist(blocklist);
        }
    }

    /// Returns the driver's counters, or their last values once the driver has finished.
    pub fn stats(&self) -> EndpointStats {
        self.core
            .upgrade()
            .map_or_else(|| self.last.get(), |core| core.stats())
    }

    /// Returns the driver's core while it runs, for tests that reach into its queues.
    #[cfg(test)]
    pub(crate) fn core(&self) -> Option<Rc<Core<A, B>>> {
        self.core.upgrade()
    }

    /// Returns the length of the driver's list of connections waiting for the server socket.
    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.core.upgrade().map_or(0, |core| core.parked())
    }

    /// Returns one past the highest connection slot index the driver has handed out.
    #[cfg(test)]
    pub(crate) fn slots(&self) -> u32 {
        self.core.upgrade().map_or(0, |core| core.slots())
    }

    /// Returns the connection IDs issued after each connection's first, in the order the endpoint
    /// routed them.
    #[cfg(test)]
    pub(crate) fn issued_cids(&self) -> Vec<mvfstr_proto::ConnectionId> {
        self.core
            .upgrade()
            .map_or_else(Vec::new, |core| core.issued_cids())
    }

    /// Returns every connection's build horizon and the timers that hold its pacing wakes, in
    /// slot order.
    #[cfg(test)]
    pub(crate) fn build_horizons(&self) -> Vec<(Duration, Kind)> {
        self.core
            .upgrade()
            .map_or_else(Vec::new, |core| core.build_horizons())
    }

    /// Returns how many times the driver's host wake chose the fine timer for a pacing wake.
    #[cfg(test)]
    pub(crate) fn fine_plans(&self) -> u32 {
        self.core.upgrade().map_or(0, |core| core.fine_plans())
    }

    /// Returns what the driver's transmit phases have done so far.
    #[cfg(test)]
    pub(crate) fn tx_record(&self) -> TxRecord {
        self.core
            .upgrade()
            .map_or_else(TxRecord::default, |core| core.tx_record())
    }

    /// Returns the lengths of the driver's application queue and of its transmit queue.
    #[cfg(test)]
    pub(crate) fn queued_keys(&self) -> (usize, usize) {
        self.core
            .upgrade()
            .map_or((0, 0), |core| core.queued_keys())
    }

    /// Returns how many Initials wait for a later turn, and whether a connection attempt is kept
    /// for the next receive phase.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> (usize, bool) {
        self.core
            .upgrade()
            .map_or((0, false), |core| core.waiting())
    }

    /// Makes the driver's next turn panic outside every connection's guard.
    #[cfg(test)]
    pub(crate) fn fail_next_turn(&self) {
        if let Some(core) = self.core.upgrade() {
            core.fail_next_turn();
        }
    }

    /// Starts a graceful shutdown: stop accepting, call [`QuicApplication::quiesce`] and each
    /// session's `on_quiesce`, wait up to `grace`, close the remaining connections with NO_ERROR,
    /// and abort what is left at the forced deadline. A `grace` past the clock's range, such as
    /// `Duration::MAX`, never forces a close.
    pub fn quiesce(&self, grace: Duration) {
        if let Some(core) = self.core.upgrade() {
            core.quiesce(grace);
        }
    }

    /// Ends the driver at its next turn, as when the worker is cancelled: every connection is
    /// dropped with its session and does not send again.
    pub fn abort(&self) {
        if let Some(core) = self.core.upgrade() {
            core.abort();
        }
    }
}

impl<A: QuicApplication, B: Backend> fmt::Debug for EndpointHandle<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointHandle").finish_non_exhaustive()
    }
}

/// Why a driver could not start.
#[derive(Debug)]
pub enum DriverError {
    /// Binding or configuring a socket failed.
    Io(io::Error),
    /// The worker refused the driver's cleanup scope.
    Registration(CleanupRegistrationError),
    /// The endpoint config is invalid with the worker index and count given to
    /// [`EndpointDriverBuilder::worker`], or the driver is not a server worker of the group given
    /// to [`EndpointDriverBuilder::steering`] (`OutOfRange` for `steering`).
    Config(ConfigError),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket setup failed: {error}"),
            Self::Registration(error) => write!(f, "worker registration failed: {error}"),
            Self::Config(error) => write!(f, "invalid endpoint config: {error}"),
        }
    }
}

impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Registration(error) => Some(error),
            Self::Config(error) => Some(error),
        }
    }
}

impl From<io::Error> for DriverError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CleanupRegistrationError> for DriverError {
    fn from(error: CleanupRegistrationError) -> Self {
        Self::Registration(error)
    }
}

impl From<ConfigError> for DriverError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// Why [`EndpointHandle::connect`] failed. The driver does not keep a socket or connection from
/// the attempt.
#[derive(Debug)]
pub enum DriverConnectError {
    /// Opening the connection's UDP socket failed, the driver has stopped or is quiescing
    /// ([`io::ErrorKind::NotConnected`]), or creating the connection panicked
    /// ([`io::ErrorKind::Other`]).
    Io(io::Error),
    /// The endpoint refused to create the connection.
    Endpoint(ConnectError),
}

impl fmt::Display for DriverConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket setup failed: {error}"),
            Self::Endpoint(error) => write!(f, "the endpoint refused the connection: {error}"),
        }
    }
}

impl std::error::Error for DriverConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Endpoint(error) => Some(error),
        }
    }
}

impl From<io::Error> for DriverConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ConnectError> for DriverConnectError {
    fn from(error: ConnectError) -> Self {
        Self::Endpoint(error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::task::Context;
    use std::task::Poll;

    use mvfstr_io::MmsgBackend;
    use mvfstr_proto::ConnEvent;
    use mvfstr_proto::StreamId;
    use mvfstr_proto::StreamReady;

    use super::*;
    use crate::Conn;
    use crate::ConnInfo;
    use crate::QuicSession;
    use crate::Refusal;
    use crate::SendSink;

    #[test]
    fn connect_errors_keep_their_cause() {
        let socket = DriverConnectError::from(io::Error::from(io::ErrorKind::AddrNotAvailable));
        let DriverConnectError::Io(error) = &socket else {
            panic!("{socket:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(
            socket
                .source()
                .is_some_and(|source| source.is::<io::Error>())
        );
        assert!(
            socket.to_string().starts_with("socket setup failed: "),
            "{socket}"
        );

        let remote = SocketAddr::from(([0, 0, 0, 0], 0));
        let endpoint = DriverConnectError::from(ConnectError::InvalidRemoteAddress(remote));
        assert!(matches!(
            endpoint,
            DriverConnectError::Endpoint(ConnectError::InvalidRemoteAddress(_))
        ));
        assert!(
            endpoint
                .source()
                .is_some_and(|source| source.is::<ConnectError>())
        );
        assert_eq!(
            endpoint.to_string(),
            "the endpoint refused the connection: invalid remote address 0.0.0.0:0"
        );
    }

    /// An application that ignores every connection attempt, so a builder has a type to name.
    struct NoApp;

    impl QuicApplication for NoApp {
        type Session = NoSession;

        fn accept(
            &mut self,
            _info: &ConnInfo,
            _options: &mut ConnOptions,
        ) -> Result<NoSession, Refusal> {
            Err(Refusal::Ignore)
        }
    }

    struct NoSession;

    impl QuicSession for NoSession {
        fn on_event(&mut self, _: &mut Conn<'_>, _: ConnEvent) {}

        fn on_stream(&mut self, _: &mut Conn<'_>, _: StreamId, _: StreamReady) {}

        fn poll_send(
            &mut self,
            _: &mut Context<'_>,
            _: StreamId,
            _: &mut SendSink<'_>,
        ) -> Poll<()> {
            Poll::Pending
        }

        fn poll_session(&mut self, _: &mut Context<'_>, _: &mut Conn<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    #[test]
    fn max_segments_caps_every_transmit_attempt_at_one_datagram_or_more() {
        let builder = || {
            EndpointDriver::<NoApp, MmsgBackend>::builder(
                EndpointConfig::builder([7; 32]).build().unwrap(),
                NoApp,
            )
        };
        assert_eq!(builder().limits.max_segments, u16::MAX, "no cap by default");
        assert_eq!(builder().max_segments(44).limits.max_segments, 44);
        assert_eq!(
            builder().max_segments(0).limits.max_segments,
            1,
            "an attempt always may build one datagram"
        );
    }

    #[test]
    fn a_config_error_keeps_its_cause() {
        let error = DriverError::from(ConfigError::OutOfRange { field: "worker" });
        assert!(matches!(
            error,
            DriverError::Config(ConfigError::OutOfRange { field: "worker" })
        ));
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<ConfigError>())
        );
        assert!(
            error.to_string().starts_with("invalid endpoint config: "),
            "{error}"
        );
    }
}
