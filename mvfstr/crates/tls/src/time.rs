/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The rustls time source of a sans-IO stack.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

/// A rustls `TimeProvider` that returns the Unix time its owner last set and does not read the
/// system clock.
///
/// rustls reads the time to check certificate validity and ticket ages, so a caller that shares
/// one of these with its configs sets the time those checks use.
#[derive(Debug)]
pub struct ManualTimeProvider {
    unix_secs: AtomicU64,
}

impl ManualTimeProvider {
    /// Builds a provider that returns `now` until [`set`](Self::set) is called.
    pub fn new(now: UnixTime) -> ManualTimeProvider {
        ManualTimeProvider {
            unix_secs: AtomicU64::new(now.as_secs()),
        }
    }

    /// Makes the provider return `now`.
    pub fn set(&self, now: UnixTime) {
        self.unix_secs.store(now.as_secs(), Ordering::Relaxed);
    }

    /// Returns the time set last, by [`new`](Self::new) or [`set`](Self::set).
    pub fn get(&self) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(self.unix_secs.load(Ordering::Relaxed)))
    }
}

impl TimeProvider for ManualTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    #[test]
    fn rustls_sees_the_time_the_caller_set() {
        let time = ManualTimeProvider::new(unix(1_790_000_000));
        assert_eq!(time.current_time(), Some(unix(1_790_000_000)));
        time.set(unix(1_790_000_042));
        assert_eq!(time.current_time(), Some(unix(1_790_000_042)));
        assert_eq!(time.get(), unix(1_790_000_042));
    }
}
