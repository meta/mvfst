/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `mvfstr-tperf`: a QUIC throughput benchmark compatible with mvfst's tperf, for interop and
//! throughput comparison with mvfst. The server opens unidirectional streams and writes until the
//! client, which reads and discards, closes the connection after `--duration` seconds and prints
//! tperf's three output lines, then a `tperf_summary` line of `key=value` fields.
//!
//! For load shaped like media over QUIC, the client opens `--num_conns` connections, and under
//! `--object_rate` the server writes an object to every stream on each tick of a clock rather than
//! as fast as the streams take data. The client takes the server's `--num_streams`,
//! `--object_rate` and `--object_size` too, and its summary line reports them rather than what it
//! infers from the streams. Under `--object_rate` it reports each object's latency, which holds
//! only when both run on one host, and counts the objects that do not match its flags as bad. The
//! server prints a `tperf_server_summary` line when SIGINT or SIGTERM ends it.
//!
//! [`run_cli`] is the whole program. [`start_hosted_server`] runs its server on a worker that
//! another event loop drives. The crate builds only on Linux.

#![deny(unsafe_code)]

mod client;
mod config;
mod flags;
mod manual;
mod object;
mod pin;
mod report;
mod run;
mod server;
mod signal;

use std::io;
use std::io::Write;
use std::process;
use std::process::ExitCode;
use std::thread;

pub use crate::config::SetupError;
pub use crate::flags::FlagError;
pub use crate::flags::Flags;
use crate::flags::Mode;
use crate::report::closed_line;
pub use crate::run::HostedServer;
pub use crate::run::RunError;
pub use crate::run::SpawnDriver;
pub use crate::run::start_hosted_server;
pub use crate::run::start_hosted_server_with;
use crate::signal::SignalSet;

/// Runs tperf with `args`, the arguments after the program name, and returns its exit status.
pub fn run_cli(args: impl IntoIterator<Item = String>) -> ExitCode {
    let flags = match Flags::parse(args) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("mvfstr-tperf: {error}");
            return ExitCode::FAILURE;
        }
    };
    if flags.pin {
        match pin::pin(flags.mode) {
            Ok(cpu) => eprintln!("Pinned to CPU {cpu}"),
            Err(error) => eprintln!("Not pinned: {error}"),
        }
    }
    let result = match flags.mode {
        Mode::Server => serve(&flags),
        Mode::Client => run::run_client(&flags, &mut io::stdout().lock()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mvfstr-tperf: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs a server until SIGINT or SIGTERM, with a stats line for each connection that closes under
/// `--stats`, and the server's summary line at the end.
fn serve(flags: &Flags) -> Result<(), RunError> {
    // Blocked before the server's threads start, so that they inherit the mask and only the wait
    // below takes the signals.
    let signals = SignalSet::block(&[libc::SIGINT, libc::SIGTERM]).map_err(RunError::Signals)?;
    let server = run::start_server(flags)?;
    eprintln!("tperf server started at: {}", server.addr());
    eprintln!("{}", server.startup_line());
    let summary = server.summary();
    thread::spawn(move || {
        if signals.wait().is_ok() {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{}", summary.line());
            let _ = out.flush();
            process::exit(0);
        }
    });
    for closed in server.closed_connections() {
        println!(
            "{}",
            closed_line(
                &closed.stats,
                closed.socket_stops,
                closed.phase_pacing_wakes,
                closed.dropped_initials,
            )
        );
    }
    println!("{}", server.summary().line());
    Err(RunError::WorkerGone)
}
