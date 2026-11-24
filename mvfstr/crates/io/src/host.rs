/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Socket readiness from the host that runs the driver, and the backend that uses it.
//!
//! [`HostBackend`] does what [`MmsgBackend`](crate::MmsgBackend) does, over the same transmit and
//! receive halves, but takes its sockets' readiness from an [`IoHost`], an event loop such as a
//! folly EventBase, instead of tokio. Each socket is registered with the host once, for reads, and
//! stays registered; the host [sets](Readiness::set) its [`Readiness`] whenever its loop reports
//! the socket ready, which wakes the task waiting for it, and the backend
//! [clears](Readiness::clear) it when the socket returns EAGAIN. The backend reads until EAGAIN or
//! until its caller's batch budget runs out; with a level-triggered host, a socket left readable
//! is reported again on the loop's next iteration. Write interest is requested only after a send
//! returned EAGAIN. [`ManualHost`] is such a host on an epoll instance that its owner runs by hand.

use std::cell::Cell;
use std::cell::RefCell;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use mvfstr_proto::ConnKey;
use mvfstr_proto::RxMeta;
use mvfstr_proto::TxReport;
use socket2::Socket;

use crate::Backend;
use crate::FlushOutcome;
use crate::MmsgOptions;
use crate::RxBackend;
use crate::TxBackend;
use crate::TxCaps;
use crate::mmsg::open_connected;
use crate::mmsg::ready;
use crate::rx::Rx;
use crate::socket;
use crate::tx::MmsgSink;
use crate::tx::Tx;

/// A kind of socket readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interest {
    /// The socket has datagrams to receive, or an error to report.
    Read,
    /// The socket's send buffer has room again after an EAGAIN.
    Write,
}

/// One socket's readiness, shared on the host's thread by the host that watches the socket and
/// the backend that reads and writes it.
///
/// The host sets it when its event loop reports the socket ready, which wakes the task the backend
/// registered for that interest. The backend clears it when the socket returns EAGAIN, then
/// registers its task to be woken by the next set.
#[derive(Clone, Default)]
pub struct Readiness(Rc<State>);

#[derive(Default)]
struct State {
    read: Cell<bool>,
    write: Cell<bool>,
    read_waker: Cell<Option<Waker>>,
    write_waker: Cell<Option<Waker>>,
}

impl Readiness {
    /// Marks the socket ready for `interest` and wakes the task registered for it, if any. Called
    /// by the host.
    pub fn set(&self, interest: Interest) {
        let (flag, waker) = self.0.slots(interest);
        flag.set(true);
        if let Some(waker) = waker.take() {
            waker.wake();
        }
    }

    /// Marks the socket not ready for `interest`, after it returned EAGAIN. Called by the backend.
    pub fn clear(&self, interest: Interest) {
        self.0.slots(interest).0.set(false);
    }

    /// Returns whether the socket may be ready for `interest`: set and not cleared since.
    pub fn is_set(&self, interest: Interest) -> bool {
        self.0.slots(interest).0.get()
    }

    /// Registers `waker` to be woken at the next [`set`](Self::set) for `interest`, replacing
    /// the task registered before.
    pub fn wake_when_set(&self, interest: Interest, waker: &Waker) {
        let slot = self.0.slots(interest).1;
        let kept = slot.take().filter(|kept| kept.will_wake(waker));
        slot.set(Some(kept.unwrap_or_else(|| waker.clone())));
    }
}

impl State {
    fn slots(&self, interest: Interest) -> (&Cell<bool>, &Cell<Option<Waker>>) {
        match interest {
            Interest::Read => (&self.read, &self.read_waker),
            Interest::Write => (&self.write, &self.write_waker),
        }
    }
}

/// An event loop that reports socket readiness to [`HostBackend`]s on its own thread.
pub trait IoHost: 'static {
    /// A handle that keeps one socket registered; dropping it deregisters the socket. A backend
    /// drops it before it closes the socket.
    type Registration;

    /// Registers `fd` for reads for as long as the registration lives: whenever the loop finds
    /// `fd` readable, or with an error to report, it calls `readiness.set(Interest::Read)`. A
    /// backend registers each socket once and never changes its read interest.
    fn register(&self, fd: BorrowedFd<'_>, readiness: Readiness) -> io::Result<Self::Registration>;

    /// Requests one `set(Interest::Write)` on the registration's readiness once its socket is
    /// writable. A backend calls it only after a send returned EAGAIN, and after a failure here it
    /// calls it again at its next poll.
    fn watch_writable(&self, registration: &Self::Registration) -> io::Result<()>;
}

/// Settings for every [`HostBackend`] a driver opens.
pub struct HostOptions<H> {
    /// The host that reports the readiness of every socket the driver opens. Opening a backend
    /// fails without one. Default `None`.
    pub host: Option<H>,
    /// The socket, buffer and batch settings, as for [`MmsgBackend`](crate::MmsgBackend).
    pub mmsg: MmsgOptions,
}

impl<H> Default for HostOptions<H> {
    fn default() -> Self {
        Self {
            host: None,
            mmsg: MmsgOptions::default(),
        }
    }
}

impl<H> fmt::Debug for HostOptions<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostOptions")
            .field("host", &self.host.is_some())
            .field("mmsg", &self.mmsg)
            .finish()
    }
}

/// The `sendmmsg`/`recvmmsg` backend on one UDP socket, with GSO and GRO, whose readiness comes
/// from an [`IoHost`] rather than tokio, so it runs on a thread without a tokio runtime.
///
/// It sends and receives as [`MmsgBackend`](crate::MmsgBackend) does, kernel release with
/// [`MmsgOptions::txtime`] included. Each [`poll_recv`](RxBackend::poll_recv) makes at most one
/// `recvmmsg` call, so the caller's batch budget bounds a busy socket.
pub struct HostBackend<H: IoHost> {
    // Declared before `socket`, so the socket is deregistered before it closes.
    registration: H::Registration,
    host: H,
    readiness: Readiness,
    /// Whether write readiness was requested from the host since the last EAGAIN.
    watching: bool,
    socket: Socket,
    tx: Tx,
    rx: Rx,
}

impl<H: IoHost> HostBackend<H> {
    /// Opens a backend on an existing socket with readiness from `host`, probing the socket's
    /// capabilities and readying it as
    /// [`MmsgBackend::from_socket`](crate::MmsgBackend::from_socket) does, and registers the socket
    /// with the host for as long as the backend lives.
    ///
    /// Fails with `InvalidInput` when `options` are invalid, and with the host's error when it
    /// cannot register the socket.
    pub fn from_socket(socket: Socket, host: H, options: &MmsgOptions) -> io::Result<Self> {
        options.validate()?;
        let (tx, rx) = ready(&socket, options)?;
        let readiness = Readiness::default();
        let registration = host.register(socket.as_fd(), readiness.clone())?;
        Ok(Self {
            registration,
            host,
            readiness,
            watching: false,
            socket,
            tx,
            rx,
        })
    }
}

impl<H: IoHost> TxBackend for HostBackend<H> {
    type Sink<'a> = MmsgSink<'a>;

    fn caps(&self) -> &TxCaps {
        self.tx.caps()
    }

    fn sink(&mut self, conn: ConnKey) -> MmsgSink<'_> {
        MmsgSink::new(&mut self.tx, self.socket.as_fd(), conn)
    }

    fn flush(&mut self, _now: Instant) -> FlushOutcome {
        let datagrams = self.tx.send(self.socket.as_fd());
        FlushOutcome {
            datagrams,
            blocked: self.tx.blocked(),
        }
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if !self.tx.blocked() {
                return Poll::Ready(());
            }
            if !self.watching {
                // A send met EAGAIN: wait for the host's next report of writability.
                self.readiness.clear(Interest::Write);
                if self.host.watch_writable(&self.registration).is_err() {
                    // The host will not report, so retry at the next poll.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.watching = true;
            }
            if !self.readiness.is_set(Interest::Write) {
                self.readiness.wake_when_set(Interest::Write, cx.waker());
                return Poll::Pending;
            }
            self.watching = false;
            self.tx.send(self.socket.as_fd());
        }
    }

    fn drain_reports(&mut self, f: impl FnMut(ConnKey, TxReport)) {
        self.tx.drain_reports(f);
    }
}

impl<H: IoHost> RxBackend for HostBackend<H> {
    /// Makes one `recvmmsg` call while the host has the socket readable. A batch whose every
    /// datagram was discarded is `Ready(Ok(0))`: only EAGAIN means the socket is empty, and the
    /// caller reads on while its budget lasts.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.readiness.is_set(Interest::Read) {
            match self.rx.recv(self.socket.as_raw_fd()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.readiness.clear(Interest::Read);
                }
                result => return Poll::Ready(result),
            }
        }
        self.readiness.wake_when_set(Interest::Read, cx.waker());
        Poll::Pending
    }

    fn buffers(&mut self) -> impl Iterator<Item = (&RxMeta, &mut [u8])> {
        self.rx.buffers()
    }
}

impl<H: IoHost + Clone> Backend for HostBackend<H> {
    type Options = HostOptions<H>;

    fn bind(addr: SocketAddr, options: &HostOptions<H>) -> io::Result<Self> {
        let host = options.host.clone().ok_or_else(no_host)?;
        Self::from_socket(
            socket::open(addr, None, &options.mmsg.socket)?,
            host,
            &options.mmsg,
        )
    }

    fn connect(remote: SocketAddr, options: &HostOptions<H>) -> io::Result<Self> {
        let host = options.host.clone().ok_or_else(no_host)?;
        let (socket, mmsg) = open_connected(remote, &options.mmsg)?;
        Self::from_socket(socket, host, &mmsg)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "not an IP socket"))
    }
}

/// Returns the error for options without a host.
fn no_host() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "HostBackend needs HostOptions::host",
    )
}

/// The `epoll_event` data that names the host's own eventfd rather than a socket.
const NOTIFY_TOKEN: u64 = u64::MAX;

/// Events taken from the kernel per [`ManualHost::poll`].
const EVENTS_PER_POLL: usize = 64;

/// An [`IoHost`] on an epoll instance that its owner runs by hand with [`poll`](Self::poll), for a
/// thread without another event loop, such as a test or a benchmark's own loop. It is a cheap
/// handle: clones share one instance, on one thread.
///
/// Sockets are registered level-triggered for reads, once, so one that is left readable is
/// reported again at every poll. Write interest is added only while a backend waits for
/// writability, and removed when it is reported. A [`Notifier`] interrupts a poll from any thread.
#[derive(Clone)]
pub struct ManualHost(Rc<Manual>);

struct Manual {
    epoll: OwnedFd,
    notify: Arc<OwnedFd>,
    /// The registered sockets, by token; a token is an index here.
    sockets: RefCell<Vec<Option<Watched>>>,
    events: RefCell<Vec<libc::epoll_event>>,
    /// The readiness the last poll found, set once the sockets are no longer borrowed.
    found: RefCell<Vec<(Readiness, Interest)>>,
    epoll_ctls: Cell<u64>,
}

struct Watched {
    fd: RawFd,
    readiness: Readiness,
    /// Whether write interest is on, until writability is reported.
    writing: bool,
}

/// A socket's registration with a [`ManualHost`]; dropping it deregisters the socket.
pub struct ManualRegistration {
    host: Rc<Manual>,
    token: usize,
}

impl ManualHost {
    /// Creates a host without sockets.
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain system calls with constant flags; each new descriptor is owned at once.
        let (epoll, notify) = unsafe {
            let epoll = cvt(libc::epoll_create1(libc::EPOLL_CLOEXEC))?;
            let epoll = OwnedFd::from_raw_fd(epoll);
            let notify = cvt(libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC))?;
            (epoll, OwnedFd::from_raw_fd(notify))
        };
        epoll_ctl(
            &epoll,
            libc::EPOLL_CTL_ADD,
            notify.as_raw_fd(),
            libc::EPOLLIN,
            NOTIFY_TOKEN,
        )?;
        Ok(Self(Rc::new(Manual {
            epoll,
            notify: Arc::new(notify),
            sockets: RefCell::new(Vec::new()),
            events: RefCell::new(vec![
                libc::epoll_event { events: 0, u64: 0 };
                EVENTS_PER_POLL
            ]),
            found: RefCell::new(Vec::new()),
            epoll_ctls: Cell::new(0),
        })))
    }

    /// Returns a handle that interrupts this host's [`poll`](Self::poll) from any thread.
    pub fn notifier(&self) -> Notifier {
        Notifier(Arc::clone(&self.0.notify))
    }

    /// Returns how many `epoll_ctl` calls the host has made for sockets: one per registration, two
    /// per wait for writability, one per deregistration.
    pub fn epoll_ctls(&self) -> u64 {
        self.0.epoll_ctls.get()
    }

    /// Waits up to `timeout`, or without limit if `None`, for registered sockets to become ready
    /// or for a [`Notifier`], and sets the readiness of every socket the kernel reports. Returns
    /// the number of events, 0 when the wait timed out or was interrupted. The timeout is rounded
    /// up to whole milliseconds.
    pub fn poll(&self, timeout: Option<Duration>) -> io::Result<usize> {
        let timeout = match timeout {
            None => -1,
            Some(timeout) => {
                let millis = timeout.as_nanos().div_ceil(1_000_000);
                i32::try_from(millis).unwrap_or(i32::MAX)
            }
        };
        let manual = &*self.0;
        let mut events = manual.events.borrow_mut();
        // SAFETY: the kernel writes at most `events.len()` entries into `events`, which is live.
        let rc = unsafe {
            libc::epoll_wait(
                manual.epoll.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout,
            )
        };
        let n = match cvt(rc) {
            Ok(n) => n as usize,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => 0,
            Err(error) => return Err(error),
        };
        let mut found = manual.found.borrow_mut();
        let mut sockets = manual.sockets.borrow_mut();
        for event in &events[..n] {
            // `epoll_event` is packed on x86-64, so its fields are copied out, never borrowed.
            let (flags, token) = (event.events as libc::c_int, event.u64);
            if token == NOTIFY_TOKEN {
                let mut count = [0u8; 8];
                // SAFETY: reads at most 8 bytes into `count`, which is live. Reading resets the
                // eventfd's counter, so the notifications so far end this poll only.
                unsafe { libc::read(manual.notify.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
                continue;
            }
            let Some(token) = usize::try_from(token).ok() else {
                continue;
            };
            let Some(watched) = sockets.get_mut(token).and_then(Option::as_mut) else {
                continue;
            };
            if flags & (libc::EPOLLIN | libc::EPOLLERR | libc::EPOLLHUP) != 0 {
                found.push((watched.readiness.clone(), Interest::Read));
            }
            if watched.writing && flags & (libc::EPOLLOUT | libc::EPOLLERR | libc::EPOLLHUP) != 0 {
                // One report per request: back to reads only. Should that fail, the next poll
                // reports writability again, which only costs a spurious wake.
                if manual
                    .ctl(libc::EPOLL_CTL_MOD, watched.fd, libc::EPOLLIN, token)
                    .is_ok()
                {
                    watched.writing = false;
                }
                found.push((watched.readiness.clone(), Interest::Write));
            }
        }
        drop(sockets);
        drop(events);
        // Wakers run here, after `sockets` and `events` are released, so they may register and
        // watch sockets.
        for (readiness, interest) in found.drain(..) {
            readiness.set(interest);
        }
        Ok(n)
    }
}

/// The epoll instance's descriptor, which is readable while a registered socket is ready or a
/// [`Notifier`] has notified. A loop that watches it can run [`poll`](ManualHost::poll) whenever
/// it is readable, without blocking.
impl AsFd for ManualHost {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.epoll.as_fd()
    }
}

impl IoHost for ManualHost {
    type Registration = ManualRegistration;

    fn register(&self, fd: BorrowedFd<'_>, readiness: Readiness) -> io::Result<ManualRegistration> {
        let manual = &*self.0;
        let mut sockets = manual.sockets.borrow_mut();
        let token = sockets
            .iter()
            .position(Option::is_none)
            .unwrap_or(sockets.len());
        manual.ctl(libc::EPOLL_CTL_ADD, fd.as_raw_fd(), libc::EPOLLIN, token)?;
        let watched = Watched {
            fd: fd.as_raw_fd(),
            readiness,
            writing: false,
        };
        match sockets.get_mut(token) {
            Some(slot) => *slot = Some(watched),
            None => sockets.push(Some(watched)),
        }
        Ok(ManualRegistration {
            host: Rc::clone(&self.0),
            token,
        })
    }

    fn watch_writable(&self, registration: &ManualRegistration) -> io::Result<()> {
        let manual = &*self.0;
        let mut sockets = manual.sockets.borrow_mut();
        let Some(watched) = sockets[registration.token].as_mut() else {
            return Ok(());
        };
        if watched.writing {
            return Ok(());
        }
        manual.ctl(
            libc::EPOLL_CTL_MOD,
            watched.fd,
            libc::EPOLLIN | libc::EPOLLOUT,
            registration.token,
        )?;
        watched.writing = true;
        Ok(())
    }
}

impl Drop for ManualRegistration {
    fn drop(&mut self) {
        let Some(watched) = self.host.sockets.borrow_mut()[self.token].take() else {
            return;
        };
        // The socket is still open, so this fails only if the descriptor was closed early; it
        // leaves the epoll set then anyway.
        let _ = self
            .host
            .ctl(libc::EPOLL_CTL_DEL, watched.fd, 0, self.token);
    }
}

impl Manual {
    /// Changes a socket's registration, counting the call.
    fn ctl(&self, op: libc::c_int, fd: RawFd, events: libc::c_int, token: usize) -> io::Result<()> {
        self.epoll_ctls.set(self.epoll_ctls.get() + 1);
        epoll_ctl(&self.epoll, op, fd, events, token as u64)
    }
}

/// A handle that wakes a [`ManualHost`] blocked in [`poll`](ManualHost::poll), from any thread.
#[derive(Clone)]
pub struct Notifier(Arc<OwnedFd>);

impl Notifier {
    /// Makes the host's current or next poll return. Notifications before that poll merge.
    pub fn notify(&self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: writes the 8 bytes of `one`, which is live, to the eventfd. EAGAIN means the
        // counter is already as high as it goes, so the host will wake anyway.
        unsafe { libc::write(self.0.as_raw_fd(), one.as_ptr().cast(), one.len()) };
    }
}

/// Returns the result of a successful call, or the error a failed one set.
fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Adds, changes or removes `fd`'s registration with `epoll`.
fn epoll_ctl(
    epoll: &OwnedFd,
    op: libc::c_int,
    fd: RawFd,
    events: libc::c_int,
    token: u64,
) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: events as u32,
        u64: token,
    };
    // SAFETY: `event` is a live `epoll_event`; the kernel only reads it.
    cvt(unsafe { libc::epoll_ctl(epoll.as_raw_fd(), op, fd, &raw mut event) }).map(drop)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::net::UdpSocket;
    use std::os::fd::AsFd;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Wake;

    use super::*;

    /// A waker that counts its wakes.
    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        (Arc::clone(&count), Waker::from(count))
    }

    fn wakes(count: &Count) -> usize {
        count.0.load(Ordering::Relaxed)
    }

    #[test]
    fn a_set_wakes_the_task_waiting_for_that_interest_once_and_a_clear_undoes_it() {
        let readiness = Readiness::default();
        let (reads, read_waker) = counter();
        let (writes, write_waker) = counter();
        readiness.wake_when_set(Interest::Read, &read_waker);
        readiness.wake_when_set(Interest::Write, &write_waker);
        assert!(!readiness.is_set(Interest::Read) && !readiness.is_set(Interest::Write));

        readiness.set(Interest::Write);
        assert!(readiness.is_set(Interest::Write));
        assert!(!readiness.is_set(Interest::Read), "only the interest set");
        assert_eq!((wakes(&reads), wakes(&writes)), (0, 1));

        readiness.set(Interest::Read);
        readiness.set(Interest::Read);
        assert!(readiness.is_set(Interest::Read));
        assert_eq!(
            wakes(&reads),
            1,
            "a registration is woken once; the task registers again when it waits again"
        );

        readiness.clear(Interest::Read);
        assert!(!readiness.is_set(Interest::Read));
        assert!(
            readiness.is_set(Interest::Write),
            "each interest clears alone"
        );
    }

    /// Fails a test that would otherwise hang; passing runs never reach it.
    const HANG_GUARD: Duration = Duration::from_secs(20);

    #[test]
    fn a_poll_sets_read_readiness_while_a_registered_socket_has_a_datagram() {
        let host = ManualHost::new().unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let readiness = Readiness::default();
        let (reads, waker) = counter();
        readiness.wake_when_set(Interest::Read, &waker);
        let _registration = host.register(socket.as_fd(), readiness.clone()).unwrap();
        assert_eq!(host.poll(Some(Duration::ZERO)).unwrap(), 0, "nothing yet");
        assert!(!readiness.is_set(Interest::Read));

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender
            .send_to(&[7; 40], socket.local_addr().unwrap())
            .unwrap();
        assert_eq!(host.poll(Some(HANG_GUARD)).unwrap(), 1);
        assert!(readiness.is_set(Interest::Read));
        assert!(
            !readiness.is_set(Interest::Write),
            "no write interest was asked for"
        );
        assert_eq!(wakes(&reads), 1);

        // Level-triggered: a datagram left unread is reported again without registering again.
        readiness.clear(Interest::Read);
        assert_eq!(host.poll(Some(Duration::ZERO)).unwrap(), 1);
        assert!(readiness.is_set(Interest::Read));
        let mut buf = [0; 64];
        assert_eq!(socket.recv(&mut buf).unwrap(), 40);
        readiness.clear(Interest::Read);
        assert_eq!(
            host.poll(Some(Duration::ZERO)).unwrap(),
            0,
            "read to EAGAIN"
        );
        assert!(!readiness.is_set(Interest::Read));
    }

    #[test]
    fn a_notifier_ends_a_blocked_poll_from_another_thread_and_is_consumed_by_it() {
        let host = ManualHost::new().unwrap();
        let notifier = host.notifier();
        let other = std::thread::spawn(move || {
            notifier.notify();
            notifier.notify();
        });
        assert_eq!(
            host.poll(Some(HANG_GUARD)).unwrap(),
            1,
            "woken by the notifier"
        );
        other.join().unwrap();
        // Both notifications may land before the poll, in one event.
        let again = host.poll(Some(Duration::ZERO)).unwrap();
        assert!(again <= 1, "{again}");
        assert_eq!(host.poll(Some(Duration::ZERO)).unwrap(), 0, "consumed");
    }
}
