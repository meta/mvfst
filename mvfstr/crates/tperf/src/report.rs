/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The client's result lines, their parser and the `--stats` line. The result lines keep the
//! format and unit of mvfst's tperf, so the parser reads the output of either tool.

use mvfstr_proto::ConnStats;

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
    use std::time::Duration;

    use super::*;

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
            tx_inconsistent: 0,
        };
        assert_eq!(
            stats_line(&stats),
            "Stats: sent_packets=81000 recv_packets=1900 lost_packets=12 cwnd_bytes=1452000 \
             srtt_us=150"
        );
    }
}
