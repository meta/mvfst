/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `mvfstr-tperf`: a QUIC throughput benchmark compatible with mvfst's tperf, for interop and
//! throughput comparison with mvfst. The server opens unidirectional streams and writes until the
//! client, which reads and discards, closes the connection after `--duration` seconds and prints
//! tperf's three output lines.
//!
//! [`run_cli`] is the whole program. [`start_hosted_server`] runs its server on a worker that
//! another event loop drives. The crate builds only on Linux.

#![deny(unsafe_code)]

mod client;
mod config;
mod flags;
mod manual;
mod pin;
mod report;
mod run;
mod server;

use std::io;
use std::process::ExitCode;

pub use crate::config::SetupError;
pub use crate::flags::FlagError;
pub use crate::flags::Flags;
use crate::flags::Mode;
use crate::report::closed_line;
pub use crate::run::HostedServer;
pub use crate::run::RunError;
pub use crate::run::start_hosted_server;

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

/// Runs a server until the process is killed, with a stats line for each connection that
/// closes under `--stats`.
fn serve(flags: &Flags) -> Result<(), RunError> {
    let server = run::start_server(flags)?;
    eprintln!("tperf server started at: {}", server.addr());
    eprintln!("{}", server.startup_line());
    for closed in server.closed_connections() {
        println!(
            "{}",
            closed_line(
                &closed.stats,
                closed.socket_stops,
                closed.phase_pacing_wakes
            )
        );
    }
    Err(RunError::WorkerGone)
}
