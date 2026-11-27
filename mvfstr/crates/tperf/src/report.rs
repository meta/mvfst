/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The client's result lines, their parser, the `--stats` lines and the line with the server's
//! sending setup. The result lines keep the format and unit of mvfst's tperf, so the parser reads
//! the output of either tool.

use std::time::Duration;

use mvfstr_io::ReleaseSupport;
use mvfstr_io::TxCaps;
use mvfstr_proto::CongestionControl;
use mvfstr_proto::ConnStats;
use mvfstr_proto::TransportConfig;

use crate::server::NANOS_PER_SEC;

/// Bytes per megabit in mvfst tperf's unit, which is really a mebibit (2^20 bits).
const BYTES_PER_MEGABIT: f64 = 131_072.0;

/// What a client measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Measurement {
    /// Stream bytes received in the measured window.
    pub(crate) bytes: u64,
    /// The window, `--duration`; mvfst tperf divides by it rather than by the time measured.
    pub(crate) duration_secs: u32,
    /// Streams the server opened.
    pub(crate) streams: u64,
}

impl Measurement {
    /// Returns the three result lines that mvfst's tperf prints for this measurement.
    pub(crate) fn lines(&self) -> [String; 3] {
        let Measurement {
            bytes,
            duration_secs,
            streams,
        } = *self;
        let seconds = f64::from(duration_secs);
        let overall = bytes as f64 / BYTES_PER_MEGABIT / seconds;
        let per_stream =
            bytes.checked_div(streams).unwrap_or(0) as f64 / BYTES_PER_MEGABIT / seconds;
        [
            format!("Received {bytes} bytes in {duration_secs} seconds."),
            format!("Overall throughput: {}Mb/s", format_g(overall)),
            format!(
                "Average per Stream throughput: {}Mb/s over {streams} streams",
                format_g(per_stream)
            ),
        ]
    }
}

/// The result lines of either tool, read back.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Parsed {
    /// Bytes received.
    pub(crate) bytes: u64,
    /// The measured window in seconds.
    pub(crate) duration_secs: u32,
    /// The overall throughput in mebibits per second.
    pub(crate) overall: f64,
    /// The average per-stream throughput in mebibits per second.
    pub(crate) per_stream: f64,
    /// Streams received.
    pub(crate) streams: u64,
}

/// Finds the three result lines in `output`, with or without mvfst tperf's glog prefixes.
#[cfg(test)]
pub(crate) fn parse(output: &str) -> Option<Parsed> {
    let (bytes, duration_secs) = output.lines().find_map(|line| {
        let (_, rest) = line.split_once("Received ")?;
        let (bytes, rest) = rest.split_once(" bytes in ")?;
        let seconds = rest.strip_suffix(" seconds.")?;
        Some((bytes.parse().ok()?, seconds.parse().ok()?))
    })?;
    let overall = output.lines().find_map(|line| {
        let (_, rest) = line.split_once("Overall throughput: ")?;
        rest.strip_suffix("Mb/s")?.parse().ok()
    })?;
    let (per_stream, streams) = output.lines().find_map(|line| {
        let (_, rest) = line.split_once("Average per Stream throughput: ")?;
        let (per_stream, rest) = rest.split_once("Mb/s over ")?;
        let streams = rest.strip_suffix(" streams")?;
        Some((per_stream.parse().ok()?, streams.parse().ok()?))
    })?;
    Some(Parsed {
        bytes,
        duration_secs,
        overall,
        per_stream,
        streams,
    })
}

/// The stack name both summary lines carry, so one harness tells the two tperfs apart.
const STACK: &str = "mvfstr";

/// What the server writes: as much as each stream takes, or objects on a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteMode {
    /// As much as each stream takes, with `--object_rate` 0.
    Saturate,
    /// One object per stream on each tick, `object_rate` ticks a second.
    Paced { object_rate: u32 },
}

impl WriteMode {
    /// Returns the mode's name in the summary lines.
    fn name(self) -> &'static str {
        match self {
            Self::Saturate => "saturate",
            Self::Paced { .. } => "paced",
        }
    }
}

/// What one client connection received in its measured window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ConnTally {
    /// The bytes of each stream that arrived, in the order the server opened them.
    pub(crate) stream_bytes: Vec<u64>,
    /// The latency of each object received, in µs, in any order.
    pub(crate) latencies_us: Vec<u64>,
    /// The tick of each object received, named by the send time in its header in ns, with the
    /// object's latency in µs, in any order.
    pub(crate) tick_latencies_us: Vec<(u64, u64)>,
    /// Objects whose length was not the object size, or that their stream ended inside.
    pub(crate) bad_objects: u64,
    /// When the window closed, on the host's CLOCK_MONOTONIC in ns, the clock of the objects'
    /// send times; 0 if it never opened.
    pub(crate) window_end_ns: u64,
}

impl ConnTally {
    /// Returns the largest bytes of the connection's streams over the smallest. Its streams are
    /// the `streams_per_conn` it should have, each one that never arrived with 0 bytes, plus any
    /// that arrived beyond them. NaN if every stream got 0 bytes, infinite if only some did.
    pub(crate) fn stream_spread(&self, streams_per_conn: u32) -> f64 {
        let largest = self.stream_bytes.iter().copied().max().unwrap_or(0);
        if largest == 0 {
            // Not 0.0 / 0.0, whose NaN has a sign that Rust leaves unspecified.
            return f64::NAN;
        }
        let smallest = if (self.stream_bytes.len() as u64) < u64::from(streams_per_conn) {
            0
        } else {
            self.stream_bytes.iter().copied().min().unwrap_or(0)
        };
        largest as f64 / smallest as f64
    }
}

/// What a server has done since it started, for its summary line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServerTally {
    /// Connections accepted.
    pub(crate) conns: u64,
    /// Objects written to streams.
    pub(crate) objects_sent: u64,
    /// Objects dropped from full stream queues.
    pub(crate) objects_dropped: u64,
    /// Ticks that started while an object of the tick before was still queued.
    pub(crate) late_ticks: u64,
    /// The driver's [`EndpointStats::dropped_initials`](mvfstr_driver::EndpointStats), as of the
    /// last accept or close.
    pub(crate) dropped_initials: u64,
    /// The driver's [`EndpointStats::turns`](mvfstr_driver::EndpointStats), as of the last accept
    /// or close.
    pub(crate) turns: u64,
    // The rest are the driver's `EndpointStats` fields of the same names, as of the last accept
    // or close.
    /// `sendmmsg` calls on the server's sockets.
    pub(crate) sendmmsg_calls: u64,
    /// Messages of those calls that the kernel accepted.
    pub(crate) sendmmsg_messages: u64,
    /// Calls whose accepted messages carried the runs of more than one connection.
    pub(crate) multi_connection_calls: u64,
    /// Datagrams the connections sent, each segment of a GSO send counted.
    pub(crate) sent_datagrams: u64,
    /// Transmit attempts on the socket with kernel release by what they built: nothing, only runs
    /// due at once, only runs released later, and both.
    pub(crate) release_attempts: [u64; 4],
    /// Accepted messages with a release time, by how late they reached the kernel.
    pub(crate) release_lateness: [u64; 8],
    /// Calls by the messages the kernel accepted, those that accepted none left out.
    pub(crate) messages_per_call: [u64; 8],
    /// Flushes before an attempt because a held run had waited the release hold.
    pub(crate) hold_flushes_age: u64,
    /// Flushes before an attempt at half the lead of a held run released later.
    pub(crate) hold_flushes_stamp: u64,
    /// Flushes after attempts that held their runs but filled their batch or were refused.
    pub(crate) hold_stop_flushes: u64,
    /// Hold flushes that ended after the bound they flushed for.
    pub(crate) hold_late: u64,
    /// Bounds of held runs that passed while an EAGAIN had stopped the flushes.
    pub(crate) hold_blocked: u64,
    /// Flushes after paced attempts without a build horizon that also carried held runs.
    pub(crate) hold_carried_flushes: u64,
    /// Pacing wakes taken inside transmit phases, by how late they were taken.
    pub(crate) pacing_wake_lateness: [u64; 8],
    /// Receive calls on the server socket that returned a batch.
    pub(crate) server_rx_batches: u64,
    /// Datagrams of those batches, as routed.
    pub(crate) server_rx_datagrams: u64,
    /// Receive calls past the readiness the host last reported.
    pub(crate) server_rx_probes: u64,
    /// Those of them that found the socket empty.
    pub(crate) server_rx_probes_empty: u64,
    /// Receive phases that ended at their bound on receive calls.
    pub(crate) server_rx_bound_hits: u64,
}

/// Returns the value at `per_mille` thousandths of `sorted`, by nearest rank: the smallest value
/// that at least that share of the values do not exceed. `None` if `sorted` is empty.
pub(crate) fn percentile<T: Copy>(sorted: &[T], per_mille: u32) -> Option<T> {
    let count = sorted.len() as u64;
    let rank = (u64::from(per_mille) * count)
        .div_ceil(1000)
        .clamp(1, count.max(1));
    sorted.get(usize::try_from(rank - 1).ok()?).copied()
}

/// Sorts `spreads`, the stream spreads of a client's connections, with infinity above every
/// number and every NaN last, and returns their median and their max by rank; NaN for both if
/// `spreads` is empty.
pub(crate) fn stream_spread_p50_and_max(spreads: &mut [f64]) -> (f64, f64) {
    // total_cmp alone would sort a NaN with its sign bit set below every number.
    spreads.sort_by(|a, b| a.is_nan().cmp(&b.is_nan()).then_with(|| a.total_cmp(b)));
    let at = |per_mille| percentile(spreads, per_mille).unwrap_or(f64::NAN);
    (at(500), at(1000))
}

/// Returns the client's summary line for a run in `mode` of `duration_secs` seconds, with
/// `streams_per_conn` streams on each of the connections that `conns` describes. Rates are in
/// megabits of 10^6 bits per second over the whole window, and the stream spreads are the median
/// and the max of the connections' [`ConnTally::stream_spread`]. In paced mode the line adds the
/// objects and their latency percentiles, then the percentiles of the ticks' fan-out completions
/// and the count of the run's ticks that some stream did not receive in its window.
pub(crate) fn summary_line(
    mode: WriteMode,
    duration_secs: u32,
    streams_per_conn: u32,
    conns: &[ConnTally],
) -> String {
    let seconds = f64::from(duration_secs);
    let mbps = |bytes: u64| bytes as f64 * 8.0 / 1e6 / seconds;
    let conn_bytes: Vec<u64> = conns
        .iter()
        .map(|conn| conn.stream_bytes.iter().sum())
        .collect();
    let bytes: u64 = conn_bytes.iter().sum();
    let mut conn_mbps: Vec<f64> = conn_bytes.iter().map(|&bytes| mbps(bytes)).collect();
    conn_mbps.sort_by(f64::total_cmp);
    let conn_at = |per_mille| percentile(&conn_mbps, per_mille).unwrap_or(0.0);
    let streams = || {
        conns
            .iter()
            .flat_map(|conn| conn.stream_bytes.iter().copied())
    };
    let opened: usize = conns.iter().map(|conn| conn.stream_bytes.len()).sum();
    let mut spreads: Vec<f64> = conns
        .iter()
        .map(|conn| conn.stream_spread(streams_per_conn))
        .collect();
    let (spread_p50, spread_max) = stream_spread_p50_and_max(&mut spreads);
    let mut line = format!(
        "tperf_summary stack={STACK} mode={} conns={} streams_per_conn={streams_per_conn} \
         duration_s={duration_secs} bytes={bytes} mbps={:.3} conn_mbps_min={:.3} \
         conn_mbps_p50={:.3} conn_mbps_max={:.3} stream_bytes_min={} stream_bytes_max={} \
         streams_opened={opened} stream_spread_p50={spread_p50:.3} \
         stream_spread_max={spread_max:.3}",
        mode.name(),
        conns.len(),
        mbps(bytes),
        conn_at(0),
        conn_at(500),
        conn_at(1000),
        streams().min().unwrap_or(0),
        streams().max().unwrap_or(0),
    );
    if let WriteMode::Paced { object_rate } = mode {
        let mut latencies: Vec<u64> = conns
            .iter()
            .flat_map(|conn| conn.latencies_us.iter().copied())
            .collect();
        latencies.sort_unstable();
        let at = |per_mille| percentile(&latencies, per_mille).unwrap_or(0);
        let bad_objects: u64 = conns.iter().map(|conn| conn.bad_objects).sum();
        line.push_str(&format!(
            " objects={} bad_objects={bad_objects} lat_us_p50={} lat_us_p90={} lat_us_p99={} \
             lat_us_p999={} lat_us_max={}",
            latencies.len(),
            at(500),
            at(900),
            at(990),
            at(999),
            at(1000),
        ));
        let (fanout, incomplete) = fanout_completions(conns, streams_per_conn, object_rate);
        let fanout_at = |per_mille| percentile(&fanout, per_mille).unwrap_or(0);
        line.push_str(&format!(
            " fanout_us_p50={} fanout_us_p99={} fanout_us_p999={} fanout_incomplete={incomplete}",
            fanout_at(500),
            fanout_at(990),
            fanout_at(999),
        ));
    }
    line
}

/// Returns the fan-out completion of each tick that every stream of `conns` received, sorted, and
/// the count of the run's other ticks. A tick's completion is the latency of its last object over
/// the `streams_per_conn` streams of every connection. Objects name their tick by the send time in
/// their headers, which the connections of one server share, and ticks start `object_rate` times a
/// second.
fn fanout_completions(
    conns: &[ConnTally],
    streams_per_conn: u32,
    object_rate: u32,
) -> (Vec<u64>, u64) {
    let mut objects: Vec<(u64, u64)> = conns
        .iter()
        .flat_map(|conn| conn.tick_latencies_us.iter().copied())
        .collect();
    objects.sort_unstable();
    let streams = conns.len() as u64 * u64::from(streams_per_conn);
    let mut completions: Vec<u64> = objects
        .chunk_by(|a, b| a.0 == b.0)
        .filter_map(|tick| match tick {
            // Sorted by latency within a tick, so the last object arrived last.
            [.., (_, last)] if tick.len() as u64 >= streams => Some(*last),
            _ => None,
        })
        .collect();
    completions.sort_unstable();
    let incomplete =
        run_ticks(conns, &objects, object_rate).saturating_sub(completions.len() as u64);
    (completions, incomplete)
}

/// Returns how many ticks the run of `conns` had, whose objects sorted by tick are `objects`: every
/// tick from the first that an object names to the last that started before the last window
/// closed, so ticks that no stream received count too. Tick k starts k / `object_rate` seconds
/// after the server's epoch, rounded down to the ns, so the ticks between two send times are
/// rounded to the nearest.
fn run_ticks(conns: &[ConnTally], objects: &[(u64, u64)], object_rate: u32) -> u64 {
    let (Some(&(first, _)), Some(&(last, _))) = (objects.first(), objects.last()) else {
        return 0;
    };
    let rate = u128::from(object_rate);
    let named = (u128::from(last - first) * rate + NANOS_PER_SEC / 2) / NANOS_PER_SEC + 1;
    let end = conns
        .iter()
        .map(|conn| conn.window_end_ns)
        .max()
        .unwrap_or(0);
    let started = (u128::from(end.saturating_sub(first)) * rate).div_ceil(NANOS_PER_SEC);
    u64::try_from(named.max(started)).unwrap_or(u64::MAX)
}

/// Returns `counts` separated by commas, as the server's summary line prints a histogram.
fn comma_list(counts: &[u64]) -> String {
    counts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Returns the server's summary line, for a server in `mode` that has done what `tally` counts.
/// The driver's counters end it in every mode, each histogram as its counts in bucket order.
pub(crate) fn server_summary_line(mode: WriteMode, tally: &ServerTally) -> String {
    let mut line = format!(
        "tperf_server_summary stack={STACK} mode={} conns={}",
        mode.name(),
        tally.conns
    );
    if matches!(mode, WriteMode::Paced { .. }) {
        line.push_str(&format!(
            " objects_sent={} objects_dropped={} late_ticks={}",
            tally.objects_sent, tally.objects_dropped, tally.late_ticks
        ));
    }
    line.push_str(&format!(
        " dropped_initials={} turns={} sendmmsg_calls={} sendmmsg_messages={} \
         multi_connection_calls={} sent_datagrams={} release_attempts={} release_lateness={} \
         messages_per_call={} hold_flushes_age={} hold_flushes_stamp={} hold_stop_flushes={} \
         hold_late={} hold_blocked={} hold_carried_flushes={} pacing_wake_lateness={} \
         server_rx_batches={} server_rx_datagrams={} server_rx_probes={} \
         server_rx_probes_empty={} server_rx_bound_hits={}",
        tally.dropped_initials,
        tally.turns,
        tally.sendmmsg_calls,
        tally.sendmmsg_messages,
        tally.multi_connection_calls,
        tally.sent_datagrams,
        comma_list(&tally.release_attempts),
        comma_list(&tally.release_lateness),
        comma_list(&tally.messages_per_call),
        tally.hold_flushes_age,
        tally.hold_flushes_stamp,
        tally.hold_stop_flushes,
        tally.hold_late,
        tally.hold_blocked,
        tally.hold_carried_flushes,
        comma_list(&tally.pacing_wake_lateness),
        tally.server_rx_batches,
        tally.server_rx_datagrams,
        tally.server_rx_probes,
        tally.server_rx_probes_empty,
        tally.server_rx_bound_hits,
    ));
    line
}

/// Returns a connection's counters, which start the `--stats` lines of both sides.
fn stats_line(stats: &ConnStats) -> String {
    format!(
        "Stats: sent_packets={} recv_packets={} lost_packets={} cwnd_bytes={} srtt_us={}",
        stats.sent_packets,
        stats.recv_packets,
        stats.lost_packets,
        stats.cwnd,
        stats.smoothed_rtt.as_micros()
    )
}

/// Returns the client's `--stats` line for a connection: its counters, and the stream spread of
/// `conn`, which should have `streams_per_conn` streams.
pub(crate) fn client_stats_line(
    stats: &ConnStats,
    conn: &ConnTally,
    streams_per_conn: u32,
) -> String {
    format!(
        "{} stream_spread={:.3}",
        stats_line(stats),
        conn.stream_spread(streams_per_conn)
    )
}

/// Returns the server's `--stats` line for a closed connection: its counters, and the
/// endpoint's cumulative socket stops, pacing wakes taken inside transmit phases and dropped
/// Initials.
pub(crate) fn closed_line(
    stats: &ConnStats,
    socket_stops: u64,
    phase_pacing_wakes: u64,
    dropped_initials: u64,
) -> String {
    format!(
        "{} socket_stops={socket_stops} phase_pacing_wakes={phase_pacing_wakes} \
         dropped_initials={dropped_initials}",
        stats_line(stats)
    )
}

/// Returns the line with the server's sending setup, logged at startup: its connections'
/// controller and pacing, its socket's kernel release and send buffer, and the endpoint's build
/// horizon, capped by the socket's release horizon. A connection may build less far ahead than
/// the endpoint allows, to keep its advertised max_ack_delay in range. Then come
/// `--initial_rtt_ms`, only when the server is given it, and the release hold in µs, which ends
/// the line: 0 when off and `max` without a bound.
pub(crate) fn startup_line(
    transport: &TransportConfig,
    build_horizon: Duration,
    caps: &TxCaps,
    initial_rtt_ms: Option<u32>,
    release_hold: Option<Duration>,
) -> String {
    let congestion = match transport.congestion_control() {
        CongestionControl::NewReno => "newreno",
        CongestionControl::Cubic => "cubic",
        CongestionControl::Bbr3 => "bbr3",
    };
    let mut line = format!(
        "Server: congestion={congestion} pacing={} pacing_granularity_us={} pacing_min_burst={} \
         pacing_max_burst={} txtime={} endpoint_horizon_us={} so_sndbuf={}",
        transport.pacing(),
        transport.pacing_granularity().as_micros(),
        transport.pacing_min_burst(),
        transport.pacing_max_burst(),
        caps.release != ReleaseSupport::None,
        build_horizon.min(caps.release.horizon()).as_micros(),
        caps.send_buffer,
    );
    if let Some(ms) = initial_rtt_ms {
        line.push_str(&format!(" initial_rtt_ms={ms}"));
    }
    let hold = match release_hold {
        None => "0".to_owned(),
        Some(Duration::MAX) => "max".to_owned(),
        Some(hold) => hold.as_micros().to_string(),
    };
    line.push_str(&format!(" release_hold_us={hold}"));
    line
}

/// Formats `value` as a C++ `std::ostream` prints a `double` by default: `%g` with six
/// significant digits, which is how mvfst's tperf prints its throughput.
pub(crate) fn format_g(value: f64) -> String {
    const PRECISION: usize = 6;
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    // %g picks its style from the exponent the value has once rounded to the precision.
    let scientific = format!("{value:.*e}", PRECISION - 1);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("should have an exponent in scientific notation");
    let exponent: i32 = exponent
        .parse()
        .expect("should be an integer exponent in scientific notation");
    match usize::try_from(exponent) {
        Ok(digits) if digits < PRECISION => {
            without_trailing_zeros(&format!("{value:.*}", PRECISION - 1 - digits))
        }
        Err(_) if exponent >= -4 => {
            let decimals = PRECISION - 1 + exponent.unsigned_abs() as usize;
            without_trailing_zeros(&format!("{value:.decimals$}"))
        }
        _ => {
            let sign = if exponent < 0 { '-' } else { '+' };
            format!(
                "{}e{sign}{:02}",
                without_trailing_zeros(mantissa),
                exponent.unsigned_abs()
            )
        }
    }
}

/// Drops the zeros that end a fraction, and then the point if it ends the number.
fn without_trailing_zeros(number: &str) -> String {
    if number.contains('.') {
        number
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    } else {
        number.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use mvfstr_proto::ClockEpoch;
    use mvfstr_proto::Tick;

    use super::*;
    use crate::config::server_transport;
    use crate::flags::Flags;

    /// Paced mode, for lines whose objects name no tick.
    const PACED: WriteMode = WriteMode::Paced { object_rate: 50 };

    #[test]
    fn doubles_print_as_cpp_streams_print_them() {
        for (value, printed) in [
            (4_133.554_687_5, "4133.55"),
            (0.0, "0"),
            (3.0, "3"),
            (2.5, "2.5"),
            (1.0 / 3.0, "0.333333"),
            (123_456.0, "123456"),
            (123_456.7, "123457"),
            (999_999.4, "999999"),
            (999_999.5, "1e+06"),
            (1_234_567.0, "1.23457e+06"),
            (0.0001, "0.0001"),
            (0.000_012_345_67, "1.23457e-05"),
            (1e100, "1e+100"),
            (-41.5, "-41.5"),
            (f64::INFINITY, "inf"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(format_g(value), printed, "{value:?}");
        }
    }

    #[test]
    fn the_result_lines_are_mvfst_tperfs() {
        let one = Measurement {
            bytes: 5_417_920_805,
            duration_secs: 10,
            streams: 1,
        };
        // The lines of a sample run of mvfst's tperf.
        assert_eq!(
            one.lines(),
            [
                "Received 5417920805 bytes in 10 seconds.",
                "Overall throughput: 4133.55Mb/s",
                "Average per Stream throughput: 4133.55Mb/s over 1 streams",
            ]
        );
        let three = Measurement {
            bytes: 1000,
            duration_secs: 2,
            streams: 3,
        };
        // The per-stream average divides bytes by streams as integers first: 333 / 131072 / 2.
        assert_eq!(
            three.lines(),
            [
                "Received 1000 bytes in 2 seconds.",
                "Overall throughput: 0.0038147Mb/s",
                "Average per Stream throughput: 0.00127029Mb/s over 3 streams",
            ]
        );
        let none = Measurement {
            bytes: 0,
            duration_secs: 1,
            streams: 0,
        };
        assert_eq!(
            none.lines()[2],
            "Average per Stream throughput: 0Mb/s over 0 streams",
            "mvfst tperf divides by zero here"
        );
    }

    #[test]
    fn the_parser_reads_both_tools_lines() {
        let ours = Measurement {
            bytes: 5_417_920_805,
            duration_secs: 10,
            streams: 1,
        }
        .lines()
        .join("\n");
        let expected = Parsed {
            bytes: 5_417_920_805,
            duration_secs: 10,
            overall: 4133.55,
            per_stream: 4133.55,
            streams: 1,
        };
        assert_eq!(parse(&ours), Some(expected));
        let mvfst = "I1120 16:02:11.123456 1234 TperfClient.cpp:247] TPerfClient connecting to [::1]:6666
I1120 16:02:11.125000 1234 TperfClient.cpp:138] TPerfClient: onTransportReady
I1120 16:02:21.125000 1234 TperfClient.cpp:148] TPerfClient connection end
I1120 16:02:21.125100 1234 TperfClient.cpp:67] Received 5417920805 bytes in 10 seconds.
I1120 16:02:21.125200 1234 TperfClient.cpp:69] Overall throughput: 4133.55Mb/s
I1120 16:02:21.125300 1234 TperfClient.cpp:73] Average per Stream throughput: 4133.55Mb/s over 1 streams
";
        assert_eq!(parse(mvfst), Some(expected));
        let scientific = "Received 1 bytes in 1 seconds.\nOverall throughput: 1.23457e-05Mb/s\n\
            Average per Stream throughput: 1e+06Mb/s over 0 streams";
        let parsed = parse(scientific).expect("C++ prints large and small values in this form");
        assert_eq!((parsed.overall, parsed.per_stream), (1.23457e-5, 1e6));

        let missing_one: Vec<&str> = ours.lines().take(2).collect();
        assert_eq!(parse(&missing_one.join("\n")), None);
        assert_eq!(parse(&ours.replace("5417920805", "many")), None);
        assert_eq!(parse(&ours.replace("Mb/s over", "Gb/s over")), None);
    }

    #[test]
    fn the_stats_line_names_packets_losses_and_the_window() {
        let stats = ConnStats {
            sent_packets: 81_000,
            sent_bytes: 117_000_000,
            lost_packets: 12,
            recv_packets: 1_900,
            recv_bytes: 95_000,
            cwnd: 1_452_000,
            bytes_in_flight: 63_888,
            smoothed_rtt: Duration::from_micros(150),
            latest_rtt: Duration::from_micros(160),
            rtt_var: Duration::from_micros(20),
            tx_inconsistent: 0,
            acks_received: 0,
        };
        assert_eq!(
            stats_line(&stats),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150"
        );
    }

    /// Returns a tally of streams that received `stream_bytes`.
    fn tally(stream_bytes: &[u64]) -> ConnTally {
        ConnTally {
            stream_bytes: stream_bytes.to_vec(),
            ..ConnTally::default()
        }
    }

    #[test]
    fn the_clients_stats_line_ends_with_the_connections_stream_spread() {
        let stats = ConnStats {
            sent_packets: 81_000,
            sent_bytes: 117_000_000,
            lost_packets: 12,
            recv_packets: 1_900,
            recv_bytes: 95_000,
            cwnd: 1_452_000,
            bytes_in_flight: 63_888,
            smoothed_rtt: Duration::from_micros(150),
            latest_rtt: Duration::from_micros(160),
            rtt_var: Duration::from_micros(20),
            tx_inconsistent: 0,
            acks_received: 0,
        };
        assert_eq!(
            client_stats_line(&stats, &tally(&[5_000]), 1),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 stream_spread=1.000",
            "one stream that got bytes"
        );
        let counters = "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 \
                        cwnd_bytes=1452000 srtt_us=150";
        let line = |stream_bytes: &[u64], streams_per_conn| {
            client_stats_line(&stats, &tally(stream_bytes), streams_per_conn)
        };
        assert_eq!(
            line(&[700, 300], 2),
            format!("{counters} stream_spread=2.333")
        );
        assert_eq!(
            line(&[700, 300], 3),
            format!("{counters} stream_spread=inf"),
            "a stream that never arrived"
        );
        assert_eq!(
            line(&[700, 0], 2),
            format!("{counters} stream_spread=inf"),
            "a stream that arrived without bytes"
        );
        assert_eq!(
            line(&[], 2),
            format!("{counters} stream_spread=NaN"),
            "a connection that received nothing"
        );
    }

    #[test]
    fn the_servers_closed_connection_line_adds_the_endpoints_socket_stops() {
        let stats = ConnStats {
            sent_packets: 81_000,
            sent_bytes: 117_000_000,
            lost_packets: 12,
            recv_packets: 1_900,
            recv_bytes: 95_000,
            cwnd: 1_452_000,
            bytes_in_flight: 63_888,
            smoothed_rtt: Duration::from_micros(150),
            latest_rtt: Duration::from_micros(160),
            rtt_var: Duration::from_micros(20),
            tx_inconsistent: 0,
            acks_received: 0,
        };
        assert_eq!(
            closed_line(&stats, 7, 0, 0),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 socket_stops=7 phase_pacing_wakes=0 dropped_initials=0"
        );
    }

    #[test]
    fn the_servers_closed_connection_line_adds_the_endpoints_phase_pacing_wakes() {
        let stats = ConnStats {
            sent_packets: 81_000,
            sent_bytes: 117_000_000,
            lost_packets: 12,
            recv_packets: 1_900,
            recv_bytes: 95_000,
            cwnd: 1_452_000,
            bytes_in_flight: 63_888,
            smoothed_rtt: Duration::from_micros(150),
            latest_rtt: Duration::from_micros(160),
            rtt_var: Duration::from_micros(20),
            tx_inconsistent: 0,
            acks_received: 0,
        };
        assert_eq!(
            closed_line(&stats, 7, 4_211, 0),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 socket_stops=7 phase_pacing_wakes=4211 dropped_initials=0"
        );
    }

    #[test]
    fn the_servers_closed_connection_line_ends_with_the_endpoints_dropped_initials() {
        let stats = ConnStats {
            sent_packets: 81_000,
            sent_bytes: 117_000_000,
            lost_packets: 12,
            recv_packets: 1_900,
            recv_bytes: 95_000,
            cwnd: 1_452_000,
            bytes_in_flight: 63_888,
            smoothed_rtt: Duration::from_micros(150),
            latest_rtt: Duration::from_micros(160),
            rtt_var: Duration::from_micros(20),
            tx_inconsistent: 0,
            acks_received: 0,
        };
        assert_eq!(
            closed_line(&stats, 7, 4_211, 389),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 socket_stops=7 phase_pacing_wakes=4211 dropped_initials=389"
        );
    }

    #[test]
    fn the_startup_line_names_the_controller_the_pacing_and_the_sockets_release_setup() {
        let caps = |release| TxCaps {
            max_segments: 64,
            max_datagram: 1500,
            gro: true,
            ecn: true,
            pktinfo: true,
            release,
            send_buffer: 14_544_416,
        };
        let kernel = |horizon| ReleaseSupport::Kernel {
            horizon,
            epoch: ClockEpoch {
                instant: Instant::now(),
                tick: Tick(0),
            },
        };
        let ms = Duration::from_millis;
        let bbr3 = server_transport(&Flags {
            congestion: CongestionControl::Bbr3,
            pacing: true,
            ..Flags::default()
        })
        .unwrap();
        assert_eq!(
            startup_line(&bbr3, ms(5), &caps(kernel(ms(100))), None, None),
            "Server: congestion=bbr3 pacing=true pacing_granularity_us=200 pacing_min_burst=5 \
             pacing_max_burst=44 txtime=true endpoint_horizon_us=5000 so_sndbuf=14544416 \
             release_hold_us=0"
        );
        let capped = startup_line(&bbr3, ms(5), &caps(kernel(ms(2))), None, None);
        assert!(
            capped.contains(" endpoint_horizon_us=2000 "),
            "the socket's release horizon caps the endpoint's: {capped}"
        );
        let cubic = server_transport(&Flags::default()).unwrap();
        assert_eq!(
            startup_line(
                &cubic,
                Duration::ZERO,
                &caps(ReleaseSupport::None),
                None,
                None
            ),
            "Server: congestion=cubic pacing=false pacing_granularity_us=1000 pacing_min_burst=5 \
             pacing_max_burst=44 txtime=false endpoint_horizon_us=0 so_sndbuf=14544416 \
             release_hold_us=0"
        );
    }

    #[test]
    fn the_startup_line_names_the_initial_rtt_only_when_the_flag_sets_it() {
        let caps = TxCaps {
            max_segments: 64,
            max_datagram: 1500,
            gro: true,
            ecn: true,
            pktinfo: true,
            release: ReleaseSupport::None,
            send_buffer: 212_992,
        };
        let without = "Server: congestion=cubic pacing=false pacing_granularity_us=1000 \
                       pacing_min_burst=5 pacing_max_burst=44 txtime=false endpoint_horizon_us=0 \
                       so_sndbuf=212992";
        let lowered = server_transport(&Flags {
            initial_rtt_ms: Some(100),
            ..Flags::default()
        })
        .unwrap();
        assert_eq!(
            startup_line(&lowered, Duration::ZERO, &caps, Some(100), None),
            format!("{without} initial_rtt_ms=100 release_hold_us=0")
        );
        let default = server_transport(&Flags::default()).unwrap();
        assert_eq!(
            startup_line(&default, Duration::ZERO, &caps, None, None),
            format!("{without} release_hold_us=0"),
            "the line has no initial RTT without the flag"
        );
        let given = server_transport(&Flags {
            initial_rtt_ms: Some(333),
            ..Flags::default()
        })
        .unwrap();
        assert_eq!(
            startup_line(&given, Duration::ZERO, &caps, Some(333), None),
            format!("{without} initial_rtt_ms=333 release_hold_us=0"),
            "a flag that gives the transport's default value still shows"
        );
    }

    #[test]
    fn the_startup_line_ends_with_the_release_hold_zero_when_off_and_max_without_a_bound() {
        let caps = TxCaps {
            max_segments: 64,
            max_datagram: 1500,
            gro: true,
            ecn: true,
            pktinfo: true,
            release: ReleaseSupport::Kernel {
                horizon: Duration::from_millis(100),
                epoch: ClockEpoch {
                    instant: Instant::now(),
                    tick: Tick(0),
                },
            },
            send_buffer: 212_992,
        };
        // Unpaced kernel release with a 5 ms horizon.
        let unpaced = server_transport(&Flags {
            txtime: true,
            build_horizon_us: Some(5000),
            ..Flags::default()
        })
        .unwrap();
        let setup = "Server: congestion=cubic pacing=false pacing_granularity_us=1000 \
                     pacing_min_burst=5 pacing_max_burst=44 txtime=true endpoint_horizon_us=5000 \
                     so_sndbuf=212992";
        let line = |initial_rtt_ms, release_hold| {
            startup_line(
                &unpaced,
                Duration::from_millis(5),
                &caps,
                initial_rtt_ms,
                release_hold,
            )
        };
        assert_eq!(
            line(None, Some(Duration::from_micros(50))),
            format!("{setup} release_hold_us=50")
        );
        assert_eq!(
            line(None, Some(Duration::MAX)),
            format!("{setup} release_hold_us=max"),
            "no bound on the wait"
        );
        assert_eq!(
            line(None, None),
            format!("{setup} release_hold_us=0"),
            "off"
        );
        assert_eq!(
            line(Some(100), Some(Duration::from_micros(4999))),
            format!("{setup} initial_rtt_ms=100 release_hold_us=4999"),
            "after the initial RTT"
        );
    }

    /// Returns a paced tally of streams that received `stream_bytes`, whose objects arrived at
    /// `ticks`, each a tick's send time in ns and the object's latency in µs.
    fn ticked(stream_bytes: &[u64], ticks: &[(u64, u64)]) -> ConnTally {
        ConnTally {
            stream_bytes: stream_bytes.to_vec(),
            latencies_us: ticks.iter().map(|&(_, latency)| latency).collect(),
            tick_latencies_us: ticks.to_vec(),
            bad_objects: 0,
            window_end_ns: 0,
        }
    }

    #[test]
    fn a_paced_summary_line_ends_with_the_fanout_completion_of_ticks_every_stream_received() {
        // Two connections of two streams each, so a tick completes with its fourth object, the
        // one that came last. Ticks 1 and 2 complete at 300 and 400 µs. Tick 3 misses an object
        // on the second connection, and tick 4 reached only one stream.
        let conns = [
            ticked(
                &[4800, 3600],
                &[
                    (4_000, 80),
                    (1_000, 100),
                    (1_000, 300),
                    (2_000, 150),
                    (2_000, 120),
                    (3_000, 50),
                    (3_000, 60),
                ],
            ),
            ticked(
                &[3600, 2400],
                &[
                    (1_000, 200),
                    (2_000, 400),
                    (3_000, 70),
                    (1_000, 250),
                    (2_000, 90),
                ],
            ),
        ];
        // Ticks 1 µs apart.
        let paced = WriteMode::Paced {
            object_rate: 1_000_000,
        };
        assert_eq!(
            summary_line(paced, 1, 2, &conns),
            "tperf_summary stack=mvfstr mode=paced conns=2 streams_per_conn=2 duration_s=1 \
             bytes=14400 mbps=0.115 conn_mbps_min=0.048 conn_mbps_p50=0.048 \
             conn_mbps_max=0.067 stream_bytes_min=2400 stream_bytes_max=4800 streams_opened=4 \
             stream_spread_p50=1.333 stream_spread_max=1.500 objects=12 bad_objects=0 \
             lat_us_p50=100 lat_us_p90=300 lat_us_p99=400 lat_us_p999=400 lat_us_max=400 \
             fanout_us_p50=300 fanout_us_p99=400 fanout_us_p999=400 fanout_incomplete=2"
        );
        assert!(
            !summary_line(WriteMode::Saturate, 1, 2, &conns).contains("fanout"),
            "a saturate line has no fan-out fields"
        );
    }

    #[test]
    fn fanout_completion_takes_the_nearest_rank_of_each_ticks_last_object() {
        // Ticks 1 to 1,000 reach two connections of one stream, the first at the tick's number in
        // µs and the second at half of it, in the other order; tick 1,001 reaches only the second.
        let tick = |k: u64| 5_000_000_000 + k * 20_000_000;
        let first: Vec<(u64, u64)> = (1..=1000).map(|k| (tick(k), k)).collect();
        let mut second: Vec<(u64, u64)> = (1..=1001).rev().map(|k| (tick(k), k / 2)).collect();
        second.rotate_left(1);
        let line = summary_line(
            WriteMode::Paced { object_rate: 50 },
            1,
            1,
            &[ticked(&[1_200_000], &first), ticked(&[1_201_200], &second)],
        );
        assert!(
            line.ends_with(
                " fanout_us_p50=500 fanout_us_p99=990 fanout_us_p999=999 fanout_incomplete=1"
            ),
            "{line}"
        );
    }

    #[test]
    fn a_tick_that_no_stream_received_is_incomplete_up_to_the_last_window_close() {
        // Ticks of 1,000 a second reach one stream on each of two connections. Tick 2 reached
        // neither and tick 4 only the first, whose window closed 5.5 ms after tick 0. Ticks 0, 1
        // and 3 complete at 200, 120 and 95 µs.
        let tick = |k: u64| 7_000_000_000 + k * 1_000_000;
        let line = |second_window_end_ns| {
            let conns = [
                ConnTally {
                    window_end_ns: tick(5) + 500_000,
                    ..ticked(
                        &[4800],
                        &[
                            (tick(0), 100),
                            (tick(1), 120),
                            (tick(3), 90),
                            (tick(4), 300),
                        ],
                    )
                },
                ConnTally {
                    window_end_ns: second_window_end_ns,
                    ..ticked(&[3600], &[(tick(0), 200), (tick(1), 110), (tick(3), 95)])
                },
            ];
            summary_line(WriteMode::Paced { object_rate: 1000 }, 1, 1, &conns)
        };
        let tail = |incomplete| {
            format!(
                " fanout_us_p50=120 fanout_us_p99=200 fanout_us_p999=200 \
                 fanout_incomplete={incomplete}"
            )
        };
        let later = line(tick(6) + 200_000);
        assert!(
            later.ends_with(&tail(4)),
            "ticks 5 and 6 started before the second window closed and reached neither: {later}"
        );
        let earlier = line(tick(4) + 200_000);
        assert!(
            earlier.ends_with(&tail(3)),
            "the run ends when its last window closes: {earlier}"
        );
    }

    #[test]
    fn fanout_ticks_follow_an_object_rate_that_does_not_divide_a_second() {
        // At 3 ticks a second, tick k starts k / 3 s after the epoch, rounded down to the ns, so
        // ticks 1 and 5, which the one stream received, lie 3.999999999 periods apart.
        let tick = |k: u64| 7 + k * 1_000_000_000 / 3;
        let line = |window_end_ns| {
            let conn = ConnTally {
                window_end_ns,
                ..ticked(&[2400], &[(tick(1), 10), (tick(5), 20)])
            };
            summary_line(WriteMode::Paced { object_rate: 3 }, 2, 1, &[conn])
        };
        let tail = |incomplete| {
            format!(
                " fanout_us_p50=10 fanout_us_p99=20 fanout_us_p999=20 \
                 fanout_incomplete={incomplete}"
            )
        };
        assert!(
            line(0).ends_with(&tail(3)),
            "ticks 2 to 4, with no window close: {}",
            line(0)
        );
        assert!(
            line(tick(6) - 1).ends_with(&tail(3)),
            "tick 6 started after the window closed: {}",
            line(tick(6) - 1)
        );
        assert!(
            line(tick(6) + 1).ends_with(&tail(4)),
            "tick 6 started before the window closed: {}",
            line(tick(6) + 1)
        );
    }

    #[test]
    fn percentiles_take_the_nearest_rank() {
        let thousand: Vec<u64> = (1..=1000).collect();
        let at = |per_mille| percentile(&thousand, per_mille);
        assert_eq!(
            [at(500), at(900), at(990), at(999), at(1000)],
            [Some(500), Some(900), Some(990), Some(999), Some(1000)]
        );
        assert_eq!(at(1), Some(1));
        assert_eq!(at(0), Some(1), "the smallest value");
        // Ranks round up: 0.5 * 4 is rank 2, 0.9 * 4 = 3.6 is rank 4 and 0.5 * 3 = 1.5 rank 2.
        let four = [10, 20, 30, 40];
        assert_eq!(percentile(&four, 500), Some(20));
        assert_eq!(percentile(&four, 900), Some(40));
        assert_eq!(percentile(&four, 250), Some(10));
        assert_eq!(percentile(&four, 251), Some(20));
        assert_eq!(percentile(&[1, 2, 3], 500), Some(2));
        assert_eq!(percentile(&[7], 999), Some(7));
        assert_eq!(percentile(&[1.5, 2.5], 500), Some(1.5));
        assert_eq!(percentile::<u64>(&[], 500), None);
    }

    #[test]
    fn a_connections_stream_spread_is_its_largest_streams_bytes_over_its_smallest() {
        assert_eq!(tally(&[300, 100, 200]).stream_spread(3), 3.0);
        assert_eq!(tally(&[700, 300]).stream_spread(2), 700.0 / 300.0);
        assert_eq!(
            tally(&[5_000]).stream_spread(1),
            1.0,
            "one stream that got bytes"
        );
        assert_eq!(
            tally(&[100, 400, 50]).stream_spread(2),
            8.0,
            "a stream that ended and its replacement count as two"
        );
    }

    #[test]
    fn a_stream_that_never_arrived_counts_with_no_bytes_so_the_spread_is_infinite() {
        // The tally holds only the streams that arrived.
        assert_eq!(tally(&[100, 200]).stream_spread(3), f64::INFINITY);
        assert_eq!(
            tally(&[1_000_000]).stream_spread(64),
            f64::INFINITY,
            "64 streams with bytes on one"
        );
    }

    #[test]
    fn a_stream_that_arrived_without_bytes_makes_the_spread_infinite() {
        assert_eq!(tally(&[100, 0]).stream_spread(2), f64::INFINITY);
        assert_eq!(
            tally(&[0, 1]).stream_spread(1),
            f64::INFINITY,
            "a stream beyond streams_per_conn counts too"
        );
    }

    #[test]
    fn a_connection_whose_streams_got_no_bytes_has_a_spread_of_positive_nan() {
        for (stream_bytes, streams_per_conn) in
            [(&[][..], 4), (&[0, 0][..], 2), (&[0][..], 3), (&[][..], 0)]
        {
            let spread = tally(stream_bytes).stream_spread(streams_per_conn);
            // A NaN that 0.0 / 0.0 computes at run time is negative on x86-64.
            assert_eq!(
                spread.to_bits(),
                f64::NAN.to_bits(),
                "{stream_bytes:?} of {streams_per_conn} streams: {spread}, sign negative: {}",
                spread.is_sign_negative()
            );
        }
    }

    #[test]
    fn stream_spreads_rank_infinity_above_every_number_and_any_nan_last() {
        assert!(
            (-f64::NAN).is_sign_negative(),
            "negation flips the sign bit of a NaN"
        );
        let printed = |spreads: &[f64]| -> Vec<String> {
            spreads
                .iter()
                .map(|spread| format!("{spread:.3}"))
                .collect()
        };
        for nan in [f64::NAN, -f64::NAN] {
            let mut spreads = [2.0, nan, f64::INFINITY, 1.0];
            let (p50, max) = stream_spread_p50_and_max(&mut spreads);
            let negative = nan.is_sign_negative();
            assert_eq!(
                printed(&spreads),
                ["1.000", "2.000", "inf", "NaN"],
                "sign negative: {negative}"
            );
            assert_eq!(p50, 2.0, "the lower middle; sign negative: {negative}");
            assert!(max.is_nan(), "{max}; sign negative: {negative}");
        }

        let mut both = [f64::NAN, 3.0, -f64::NAN, f64::INFINITY, 1.0];
        let (p50, max) = stream_spread_p50_and_max(&mut both);
        assert_eq!(printed(&both), ["1.000", "3.000", "inf", "NaN", "NaN"]);
        assert_eq!(p50, f64::INFINITY);
        assert!(max.is_nan(), "{max}");

        let (p50, max) = stream_spread_p50_and_max(&mut []);
        assert!(p50.is_nan() && max.is_nan(), "{p50} and {max}");
    }

    #[test]
    fn the_summary_line_names_its_fields_in_order_with_megabits_of_a_million_bits() {
        let conns = [
            ConnTally {
                stream_bytes: vec![1_000_000, 2_000_000],
                latencies_us: Vec::new(),
                tick_latencies_us: Vec::new(),
                bad_objects: 0,
                window_end_ns: 0,
            },
            ConnTally {
                stream_bytes: vec![400_000, 600_000],
                latencies_us: Vec::new(),
                tick_latencies_us: Vec::new(),
                bad_objects: 0,
                window_end_ns: 0,
            },
            ConnTally {
                stream_bytes: vec![1_500_000, 500_000],
                latencies_us: Vec::new(),
                tick_latencies_us: Vec::new(),
                bad_objects: 0,
                window_end_ns: 0,
            },
        ];
        // 6 MB in 2 s is 24 Mb/s; the connections carry 12, 4 and 8 Mb/s, so the median is 8.
        // Their stream spreads are 2, 1.5 and 3.
        assert_eq!(
            summary_line(WriteMode::Saturate, 2, 2, &conns),
            "tperf_summary stack=mvfstr mode=saturate conns=3 streams_per_conn=2 duration_s=2 \
             bytes=6000000 mbps=24.000 conn_mbps_min=4.000 conn_mbps_p50=8.000 \
             conn_mbps_max=12.000 stream_bytes_min=400000 stream_bytes_max=2000000 \
             streams_opened=6 stream_spread_p50=2.000 stream_spread_max=3.000"
        );
        // A stream that received nothing counts as opened, with 0 bytes, so the spread is
        // infinite.
        let one = [ConnTally {
            stream_bytes: vec![1_234_567, 0, 89],
            latencies_us: Vec::new(),
            tick_latencies_us: Vec::new(),
            bad_objects: 0,
            window_end_ns: 0,
        }];
        assert_eq!(
            summary_line(WriteMode::Saturate, 3, 1, &one),
            "tperf_summary stack=mvfstr mode=saturate conns=1 streams_per_conn=1 duration_s=3 \
             bytes=1234656 mbps=3.292 conn_mbps_min=3.292 conn_mbps_p50=3.292 \
             conn_mbps_max=3.292 stream_bytes_min=0 stream_bytes_max=1234567 streams_opened=3 \
             stream_spread_p50=inf stream_spread_max=inf"
        );
    }

    #[test]
    fn the_summary_line_takes_the_median_and_the_max_of_the_connections_stream_spreads() {
        // Spreads NaN (an empty tally, which a connection that received nothing reports), 1, 3,
        // infinite (a stream that never arrived) and 2.5; the connections carry 0, 2, 4, 1 and
        // 3.5 Mb/s.
        let conns = [
            ConnTally::default(),
            tally(&[125_000, 125_000]),
            tally(&[375_000, 125_000]),
            tally(&[125_000]),
            tally(&[312_500, 125_000]),
        ];
        assert_eq!(
            summary_line(WriteMode::Saturate, 1, 2, &conns),
            "tperf_summary stack=mvfstr mode=saturate conns=5 streams_per_conn=2 duration_s=1 \
             bytes=1312500 mbps=10.500 conn_mbps_min=0.000 conn_mbps_p50=2.000 \
             conn_mbps_max=4.000 stream_bytes_min=125000 stream_bytes_max=375000 \
             streams_opened=7 stream_spread_p50=3.000 stream_spread_max=NaN"
        );
        // Without the NaN, the median of four is the lower middle.
        assert_eq!(
            summary_line(WriteMode::Saturate, 1, 2, &conns[1..]),
            "tperf_summary stack=mvfstr mode=saturate conns=4 streams_per_conn=2 duration_s=1 \
             bytes=1312500 mbps=10.500 conn_mbps_min=1.000 conn_mbps_p50=2.000 \
             conn_mbps_max=4.000 stream_bytes_min=125000 stream_bytes_max=375000 \
             streams_opened=7 stream_spread_p50=2.500 stream_spread_max=inf"
        );
        let finite = [conns[1].clone(), conns[2].clone(), conns[4].clone()];
        assert_eq!(
            summary_line(WriteMode::Saturate, 1, 2, &finite),
            "tperf_summary stack=mvfstr mode=saturate conns=3 streams_per_conn=2 duration_s=1 \
             bytes=1187500 mbps=9.500 conn_mbps_min=2.000 conn_mbps_p50=3.500 \
             conn_mbps_max=4.000 stream_bytes_min=125000 stream_bytes_max=375000 \
             streams_opened=6 stream_spread_p50=2.500 stream_spread_max=3.000"
        );
    }

    #[test]
    fn a_summary_line_without_connections_prints_nan_for_both_stream_spreads() {
        assert_eq!(
            summary_line(WriteMode::Saturate, 1, 2, &[]),
            "tperf_summary stack=mvfstr mode=saturate conns=0 streams_per_conn=2 duration_s=1 \
             bytes=0 mbps=0.000 conn_mbps_min=0.000 conn_mbps_p50=0.000 conn_mbps_max=0.000 \
             stream_bytes_min=0 stream_bytes_max=0 streams_opened=0 stream_spread_p50=NaN \
             stream_spread_max=NaN"
        );
    }

    #[test]
    fn a_paced_summary_line_adds_the_objects_and_their_latency_percentiles() {
        // 1,000 latencies of 1 to 1,000 µs, unsorted and split over two connections.
        let conns = [
            ConnTally {
                stream_bytes: vec![600_000],
                latencies_us: (1..=1000).rev().step_by(2).collect(),
                tick_latencies_us: Vec::new(),
                bad_objects: 0,
                window_end_ns: 0,
            },
            ConnTally {
                stream_bytes: vec![600_000],
                latencies_us: (1..=1000).step_by(2).collect(),
                tick_latencies_us: Vec::new(),
                bad_objects: 0,
                window_end_ns: 0,
            },
        ];
        assert_eq!(
            summary_line(PACED, 1, 1, &conns),
            "tperf_summary stack=mvfstr mode=paced conns=2 streams_per_conn=1 duration_s=1 \
             bytes=1200000 mbps=9.600 conn_mbps_min=4.800 conn_mbps_p50=4.800 \
             conn_mbps_max=4.800 stream_bytes_min=600000 stream_bytes_max=600000 \
             streams_opened=2 stream_spread_p50=1.000 stream_spread_max=1.000 objects=1000 \
             bad_objects=0 lat_us_p50=500 lat_us_p90=900 lat_us_p99=990 lat_us_p999=999 \
             lat_us_max=1000 fanout_us_p50=0 fanout_us_p99=0 fanout_us_p999=0 fanout_incomplete=0"
        );
        let none = [ConnTally {
            stream_bytes: vec![0],
            latencies_us: Vec::new(),
            tick_latencies_us: Vec::new(),
            bad_objects: 0,
            window_end_ns: 0,
        }];
        assert!(
            summary_line(PACED, 1, 1, &none).ends_with(
                " streams_opened=1 stream_spread_p50=NaN stream_spread_max=NaN objects=0 \
                 bad_objects=0 lat_us_p50=0 lat_us_p90=0 lat_us_p99=0 lat_us_p999=0 \
                 lat_us_max=0 fanout_us_p50=0 fanout_us_p99=0 fanout_us_p999=0 \
                 fanout_incomplete=0"
            ),
            "a paced line keeps its fields without objects"
        );
    }

    #[test]
    fn a_paced_summary_line_counts_the_bad_objects_of_every_connection() {
        let conns = [
            ConnTally {
                stream_bytes: vec![2400],
                latencies_us: vec![100, 200],
                tick_latencies_us: Vec::new(),
                bad_objects: 1,
                window_end_ns: 0,
            },
            ConnTally {
                stream_bytes: vec![1200],
                latencies_us: vec![300],
                tick_latencies_us: Vec::new(),
                bad_objects: 2,
                window_end_ns: 0,
            },
        ];
        assert_eq!(
            summary_line(PACED, 1, 1, &conns),
            "tperf_summary stack=mvfstr mode=paced conns=2 streams_per_conn=1 duration_s=1 \
             bytes=3600 mbps=0.029 conn_mbps_min=0.010 conn_mbps_p50=0.010 \
             conn_mbps_max=0.019 stream_bytes_min=1200 stream_bytes_max=2400 streams_opened=2 \
             stream_spread_p50=1.000 stream_spread_max=1.000 objects=3 bad_objects=3 \
             lat_us_p50=200 lat_us_p90=300 lat_us_p99=300 lat_us_p999=300 lat_us_max=300 \
             fanout_us_p50=0 fanout_us_p99=0 fanout_us_p999=0 fanout_incomplete=0"
        );
        assert!(
            !summary_line(WriteMode::Saturate, 1, 1, &conns).contains("objects"),
            "a saturate line has no object fields"
        );
    }

    /// The end of a server summary line whose driver sent nothing.
    const NO_SEND_PATH: &str = "sendmmsg_calls=0 sendmmsg_messages=0 multi_connection_calls=0 \
        sent_datagrams=0 release_attempts=0,0,0,0 release_lateness=0,0,0,0,0,0,0,0 \
        messages_per_call=0,0,0,0,0,0,0,0 hold_flushes_age=0 hold_flushes_stamp=0 \
        hold_stop_flushes=0 hold_late=0 hold_blocked=0 hold_carried_flushes=0 \
        pacing_wake_lateness=0,0,0,0,0,0,0,0 server_rx_batches=0 server_rx_datagrams=0 \
        server_rx_probes=0 server_rx_probes_empty=0 server_rx_bound_hits=0";

    #[test]
    fn the_server_summary_line_adds_its_object_counts_in_paced_mode() {
        let tally = ServerTally {
            conns: 8,
            objects_sent: 1600,
            objects_dropped: 3,
            late_ticks: 2,
            ..ServerTally::default()
        };
        assert_eq!(
            server_summary_line(PACED, &tally),
            format!(
                "tperf_server_summary stack=mvfstr mode=paced conns=8 objects_sent=1600 \
                 objects_dropped=3 late_ticks=2 dropped_initials=0 turns=0 {NO_SEND_PATH}"
            )
        );
        assert_eq!(
            server_summary_line(
                WriteMode::Saturate,
                &ServerTally {
                    conns: 4,
                    ..ServerTally::default()
                }
            ),
            format!(
                "tperf_server_summary stack=mvfstr mode=saturate conns=4 dropped_initials=0 \
                 turns=0 {NO_SEND_PATH}"
            )
        );
    }

    #[test]
    fn the_server_summary_line_has_the_drivers_dropped_initials_and_turns_in_both_modes() {
        let tally = ServerTally {
            conns: 1000,
            objects_sent: 1600,
            objects_dropped: 3,
            late_ticks: 2,
            dropped_initials: 811,
            turns: 52_377,
            ..ServerTally::default()
        };
        assert_eq!(
            server_summary_line(WriteMode::Saturate, &tally),
            format!(
                "tperf_server_summary stack=mvfstr mode=saturate conns=1000 dropped_initials=811 \
                 turns=52377 {NO_SEND_PATH}"
            )
        );
        assert_eq!(
            server_summary_line(PACED, &tally),
            format!(
                "tperf_server_summary stack=mvfstr mode=paced conns=1000 objects_sent=1600 \
                 objects_dropped=3 late_ticks=2 dropped_initials=811 turns=52377 {NO_SEND_PATH}"
            )
        );
    }

    #[test]
    fn the_server_summary_line_ends_with_the_drivers_server_socket_reads_after_its_pacing_wakes() {
        let tally = ServerTally {
            pacing_wake_lateness: [51, 52, 53, 54, 55, 56, 57, 58],
            server_rx_batches: 61,
            server_rx_datagrams: 62,
            server_rx_probes: 63,
            server_rx_probes_empty: 64,
            server_rx_bound_hits: 65,
            ..ServerTally::default()
        };
        for mode in [WriteMode::Saturate, PACED] {
            let line = server_summary_line(mode, &tally);
            assert!(
                line.ends_with(
                    " pacing_wake_lateness=51,52,53,54,55,56,57,58 server_rx_batches=61 \
                     server_rx_datagrams=62 server_rx_probes=63 server_rx_probes_empty=64 \
                     server_rx_bound_hits=65"
                ),
                "{line}"
            );
        }
    }

    #[test]
    fn the_server_summary_line_ends_with_the_drivers_send_path_counters_in_both_modes() {
        // Every counter takes its own value, so a counter printed in another's place shows.
        let tally = ServerTally {
            conns: 1024,
            objects_sent: 1600,
            objects_dropped: 3,
            late_ticks: 2,
            dropped_initials: 7,
            turns: 52_377,
            sendmmsg_calls: 9_001,
            sendmmsg_messages: 40_002,
            multi_connection_calls: 8_003,
            sent_datagrams: 60_004,
            release_attempts: [11, 12, 13, 14],
            release_lateness: [21, 22, 23, 24, 25, 26, 27, 28],
            messages_per_call: [31, 32, 33, 34, 35, 36, 37, 38],
            hold_flushes_age: 41,
            hold_flushes_stamp: 42,
            hold_stop_flushes: 43,
            hold_late: 44,
            hold_blocked: 45,
            hold_carried_flushes: 46,
            pacing_wake_lateness: [51, 52, 53, 54, 55, 56, 57, 58],
            server_rx_batches: 61,
            server_rx_datagrams: 62,
            server_rx_probes: 63,
            server_rx_probes_empty: 64,
            server_rx_bound_hits: 65,
        };
        // The attempts by lead are those that built nothing, only runs due at once, only runs
        // released later, and both; the histograms list their buckets in order.
        let send_path = "sendmmsg_calls=9001 sendmmsg_messages=40002 multi_connection_calls=8003 \
            sent_datagrams=60004 release_attempts=11,12,13,14 \
            release_lateness=21,22,23,24,25,26,27,28 messages_per_call=31,32,33,34,35,36,37,38 \
            hold_flushes_age=41 hold_flushes_stamp=42 hold_stop_flushes=43 hold_late=44 \
            hold_blocked=45 hold_carried_flushes=46 pacing_wake_lateness=51,52,53,54,55,56,57,58 \
            server_rx_batches=61 server_rx_datagrams=62 server_rx_probes=63 \
            server_rx_probes_empty=64 server_rx_bound_hits=65";
        assert_eq!(
            server_summary_line(WriteMode::Saturate, &tally),
            format!(
                "tperf_server_summary stack=mvfstr mode=saturate conns=1024 dropped_initials=7 \
                 turns=52377 {send_path}"
            )
        );
        assert_eq!(
            server_summary_line(PACED, &tally),
            format!(
                "tperf_server_summary stack=mvfstr mode=paced conns=1024 objects_sent=1600 \
                 objects_dropped=3 late_ticks=2 dropped_initials=7 turns=52377 {send_path}"
            )
        );
    }
}
