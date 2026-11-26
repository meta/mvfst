/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The client's result lines, their parser, the `--stats` line and the line with the server's
//! sending setup. The result lines keep the format and unit of mvfst's tperf, so the parser reads
//! the output of either tool.

use std::time::Duration;

use mvfstr_io::ReleaseSupport;
use mvfstr_io::TxCaps;
use mvfstr_proto::CongestionControl;
use mvfstr_proto::ConnStats;
use mvfstr_proto::TransportConfig;

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
    /// One object per stream on each tick of `--object_rate`.
    Paced,
}

impl WriteMode {
    /// Returns the mode's name in the summary lines.
    fn name(self) -> &'static str {
        match self {
            Self::Saturate => "saturate",
            Self::Paced => "paced",
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
    /// Objects whose length was not the object size, or that their stream ended inside.
    pub(crate) bad_objects: u64,
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

/// Returns the client's summary line for a run in `mode` of `duration_secs` seconds, with
/// `streams_per_conn` streams on each of the connections that `conns` describes. Rates are in
/// megabits of 10^6 bits per second over the whole window.
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
    let mut line = format!(
        "tperf_summary stack={STACK} mode={} conns={} streams_per_conn={streams_per_conn} \
         duration_s={duration_secs} bytes={bytes} mbps={:.3} conn_mbps_min={:.3} \
         conn_mbps_p50={:.3} conn_mbps_max={:.3} stream_bytes_min={} stream_bytes_max={} \
         streams_opened={opened}",
        mode.name(),
        conns.len(),
        mbps(bytes),
        conn_at(0),
        conn_at(500),
        conn_at(1000),
        streams().min().unwrap_or(0),
        streams().max().unwrap_or(0),
    );
    if mode == WriteMode::Paced {
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
    }
    line
}

/// Returns the server's summary line, for a server in `mode` that has done what `tally` counts.
pub(crate) fn server_summary_line(mode: WriteMode, tally: &ServerTally) -> String {
    let mut line = format!(
        "tperf_server_summary stack={STACK} mode={} conns={}",
        mode.name(),
        tally.conns
    );
    if mode == WriteMode::Paced {
        line.push_str(&format!(
            " objects_sent={} objects_dropped={} late_ticks={}",
            tally.objects_sent, tally.objects_dropped, tally.late_ticks
        ));
    }
    line
}

/// Returns the `--stats` line for a connection's counters.
pub(crate) fn stats_line(stats: &ConnStats) -> String {
    format!(
        "Stats: sent_packets={} recv_packets={} lost_packets={} cwnd_bytes={} srtt_us={}",
        stats.sent_packets,
        stats.recv_packets,
        stats.lost_packets,
        stats.cwnd,
        stats.smoothed_rtt.as_micros()
    )
}

/// Returns the server's `--stats` line for a closed connection: its counters, and the
/// endpoint's cumulative socket stops and pacing wakes taken inside transmit phases.
pub(crate) fn closed_line(stats: &ConnStats, socket_stops: u64, phase_pacing_wakes: u64) -> String {
    format!(
        "{} socket_stops={socket_stops} phase_pacing_wakes={phase_pacing_wakes}",
        stats_line(stats)
    )
}

/// Returns the line with the server's sending setup, logged at startup: its connections'
/// controller and pacing, its socket's kernel release and send buffer, and the endpoint's build
/// horizon, capped by the socket's release horizon. A connection may build less far ahead than
/// the endpoint allows, to keep its advertised max_ack_delay in range.
pub(crate) fn startup_line(
    transport: &TransportConfig,
    build_horizon: Duration,
    caps: &TxCaps,
) -> String {
    let congestion = match transport.congestion_control() {
        CongestionControl::NewReno => "newreno",
        CongestionControl::Cubic => "cubic",
        CongestionControl::Bbr3 => "bbr3",
    };
    format!(
        "Server: congestion={congestion} pacing={} pacing_granularity_us={} pacing_min_burst={} \
         pacing_max_burst={} txtime={} endpoint_horizon_us={} so_sndbuf={}",
        transport.pacing(),
        transport.pacing_granularity().as_micros(),
        transport.pacing_min_burst(),
        transport.pacing_max_burst(),
        caps.release != ReleaseSupport::None,
        build_horizon.min(caps.release.horizon()).as_micros(),
        caps.send_buffer,
    )
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
            closed_line(&stats, 7, 0),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 socket_stops=7 phase_pacing_wakes=0"
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
            closed_line(&stats, 7, 4_211),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150 socket_stops=7 phase_pacing_wakes=4211"
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
            startup_line(&bbr3, ms(5), &caps(kernel(ms(100)))),
            "Server: congestion=bbr3 pacing=true pacing_granularity_us=200 pacing_min_burst=5 \
             pacing_max_burst=44 txtime=true endpoint_horizon_us=5000 so_sndbuf=14544416"
        );
        let capped = startup_line(&bbr3, ms(5), &caps(kernel(ms(2))));
        assert!(
            capped.contains(" endpoint_horizon_us=2000 "),
            "the socket's release horizon caps the endpoint's: {capped}"
        );
        let cubic = server_transport(&Flags::default()).unwrap();
        assert_eq!(
            startup_line(&cubic, Duration::ZERO, &caps(ReleaseSupport::None)),
            "Server: congestion=cubic pacing=false pacing_granularity_us=1000 pacing_min_burst=5 \
             pacing_max_burst=44 txtime=false endpoint_horizon_us=0 so_sndbuf=14544416"
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
    fn the_summary_line_names_its_fields_in_order_with_megabits_of_a_million_bits() {
        let conns = [
            ConnTally {
                stream_bytes: vec![1_000_000, 2_000_000],
                latencies_us: Vec::new(),
                bad_objects: 0,
            },
            ConnTally {
                stream_bytes: vec![400_000, 600_000],
                latencies_us: Vec::new(),
                bad_objects: 0,
            },
            ConnTally {
                stream_bytes: vec![1_500_000, 500_000],
                latencies_us: Vec::new(),
                bad_objects: 0,
            },
        ];
        // 6 MB in 2 s is 24 Mb/s; the connections carry 12, 4 and 8 Mb/s, so the median is 8.
        assert_eq!(
            summary_line(WriteMode::Saturate, 2, 2, &conns),
            "tperf_summary stack=mvfstr mode=saturate conns=3 streams_per_conn=2 duration_s=2 \
             bytes=6000000 mbps=24.000 conn_mbps_min=4.000 conn_mbps_p50=8.000 \
             conn_mbps_max=12.000 stream_bytes_min=400000 stream_bytes_max=2000000 \
             streams_opened=6"
        );
        // A stream that received nothing counts as opened, with 0 bytes.
        let one = [ConnTally {
            stream_bytes: vec![1_234_567, 0, 89],
            latencies_us: Vec::new(),
            bad_objects: 0,
        }];
        assert_eq!(
            summary_line(WriteMode::Saturate, 3, 1, &one),
            "tperf_summary stack=mvfstr mode=saturate conns=1 streams_per_conn=1 duration_s=3 \
             bytes=1234656 mbps=3.292 conn_mbps_min=3.292 conn_mbps_p50=3.292 \
             conn_mbps_max=3.292 stream_bytes_min=0 stream_bytes_max=1234567 streams_opened=3"
        );
    }

    #[test]
    fn a_paced_summary_line_adds_the_objects_and_their_latency_percentiles() {
        // 1,000 latencies of 1 to 1,000 µs, unsorted and split over two connections.
        let conns = [
            ConnTally {
                stream_bytes: vec![600_000],
                latencies_us: (1..=1000).rev().step_by(2).collect(),
                bad_objects: 0,
            },
            ConnTally {
                stream_bytes: vec![600_000],
                latencies_us: (1..=1000).step_by(2).collect(),
                bad_objects: 0,
            },
        ];
        assert_eq!(
            summary_line(WriteMode::Paced, 1, 1, &conns),
            "tperf_summary stack=mvfstr mode=paced conns=2 streams_per_conn=1 duration_s=1 \
             bytes=1200000 mbps=9.600 conn_mbps_min=4.800 conn_mbps_p50=4.800 \
             conn_mbps_max=4.800 stream_bytes_min=600000 stream_bytes_max=600000 \
             streams_opened=2 objects=1000 bad_objects=0 lat_us_p50=500 lat_us_p90=900 \
             lat_us_p99=990 lat_us_p999=999 lat_us_max=1000"
        );
        let none = [ConnTally {
            stream_bytes: vec![0],
            latencies_us: Vec::new(),
            bad_objects: 0,
        }];
        assert!(
            summary_line(WriteMode::Paced, 1, 1, &none).ends_with(
                " streams_opened=1 objects=0 bad_objects=0 lat_us_p50=0 lat_us_p90=0 \
                 lat_us_p99=0 lat_us_p999=0 lat_us_max=0"
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
                bad_objects: 1,
            },
            ConnTally {
                stream_bytes: vec![1200],
                latencies_us: vec![300],
                bad_objects: 2,
            },
        ];
        assert_eq!(
            summary_line(WriteMode::Paced, 1, 1, &conns),
            "tperf_summary stack=mvfstr mode=paced conns=2 streams_per_conn=1 duration_s=1 \
             bytes=3600 mbps=0.029 conn_mbps_min=0.010 conn_mbps_p50=0.010 \
             conn_mbps_max=0.019 stream_bytes_min=1200 stream_bytes_max=2400 streams_opened=2 \
             objects=3 bad_objects=3 lat_us_p50=200 lat_us_p90=300 lat_us_p99=300 \
             lat_us_p999=300 lat_us_max=300"
        );
        assert!(
            !summary_line(WriteMode::Saturate, 1, 1, &conns).contains("objects"),
            "a saturate line has no object fields"
        );
    }

    #[test]
    fn the_server_summary_line_adds_its_object_counts_in_paced_mode() {
        let tally = ServerTally {
            conns: 8,
            objects_sent: 1600,
            objects_dropped: 3,
            late_ticks: 2,
        };
        assert_eq!(
            server_summary_line(WriteMode::Paced, &tally),
            "tperf_server_summary stack=mvfstr mode=paced conns=8 objects_sent=1600 \
             objects_dropped=3 late_ticks=2"
        );
        assert_eq!(
            server_summary_line(
                WriteMode::Saturate,
                &ServerTally {
                    conns: 4,
                    ..ServerTally::default()
                }
            ),
            "tperf_server_summary stack=mvfstr mode=saturate conns=4"
        );
    }
}
