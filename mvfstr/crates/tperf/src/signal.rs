/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Waiting for the signals that end a server, so that it prints its summary line first.

use std::io;
use std::mem;
use std::ptr;

/// A set of signals that the calling thread blocks and waits for.
pub(crate) struct SignalSet {
    set: libc::sigset_t,
}

impl SignalSet {
    /// Blocks `signals` in the calling thread, and so in the threads it starts later, and returns
    /// the set to wait for them on.
    #[expect(
        unsafe_code,
        reason = "sigemptyset(3), sigaddset(3) and pthread_sigmask(3)"
    )]
    pub(crate) fn block(signals: &[libc::c_int]) -> io::Result<Self> {
        // SAFETY: a `sigset_t` is a bit array, for which all zeros is valid; sigemptyset sets it.
        let mut set: libc::sigset_t = unsafe { mem::zeroed() };
        // SAFETY: `set` is a writable `sigset_t`.
        unsafe { libc::sigemptyset(&mut set) };
        for &signal in signals {
            // SAFETY: `set` is an initialized, writable `sigset_t`.
            if unsafe { libc::sigaddset(&mut set, signal) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: `set` is an initialized `sigset_t`, and the old mask is not asked for.
        let status = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(Self { set })
    }

    /// Waits until a signal of the set is pending for the calling thread or the process, takes it
    /// and returns it. The calling thread must block the set.
    #[expect(unsafe_code, reason = "sigwait(3)")]
    pub(crate) fn wait(&self) -> io::Result<libc::c_int> {
        let mut signal = 0;
        // SAFETY: `self.set` is an initialized `sigset_t` and `signal` a writable `c_int`.
        let status = unsafe { libc::sigwait(&self.set, &mut signal) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(signal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(unsafe_code, reason = "pthread_kill(3) through libc")]
    fn a_blocked_signal_stays_pending_until_the_wait_takes_it() {
        let set = SignalSet::block(&[libc::SIGUSR2]).unwrap();
        // SAFETY: the signal goes to the calling thread, which blocks it, so it stays pending
        // rather than taking its default action.
        let status = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGUSR2) };
        assert_eq!(status, 0);
        assert_eq!(set.wait().unwrap(), libc::SIGUSR2);
    }
}
