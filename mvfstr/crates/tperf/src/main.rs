/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `mvfstr-tperf`: a QUIC throughput benchmark compatible with mvfst's tperf. See the
//! `mvfstr_tperf` library for what it does.

#![deny(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    mvfstr_tperf::run_cli(env::args().skip(1))
}
