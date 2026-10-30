/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>

#include <folly/String.h>
#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>

#include <string_view>

#ifdef __linux__
#include <sched.h>

#include <cerrno>
#include <fstream>
#include <optional>
#include <string>
#include <vector>
#endif

#include <quic/tools/tperf/TperfClient.h>
#include <quic/tools/tperf/TperfKnobsPatcher.h>
#include <quic/tools/tperf/TperfServer.h>
#include <quic/tools/tperf/TperfTcp.h>

DEFINE_string(host, "::1", "TPerf server hostname/IP");
DEFINE_int32(port, 6666, "TPerf server port");
DEFINE_string(mode, "server", "Mode to run in: 'client' or 'server'");
DEFINE_bool(
    pin,
    false,
    "Best-effort pin server and client to distinct physical CPUs");
DEFINE_string(
    transport,
    "quic",
    "Transport to run: 'quic' or 'tcp'. TCP mode uses TLS over TCP via Fizz.");
DEFINE_int32(duration, 10, "Duration of test in seconds");
DEFINE_uint64(
    block_size,
    1024 * 1024,
    "Amount of data written to stream each iteration");
DEFINE_uint64(writes_per_loop, 44, "Amount of socket writes per event loop");
DEFINE_uint64(window, 1024 * 1024, "Flow control window size");
DEFINE_bool(autotune_window, true, "Automatically increase the receive window");
DEFINE_string(congestion, "cubic", "newreno/cubic/bbr/std::nullopt");
DEFINE_bool(pacing, false, "Enable pacing");
DEFINE_uint64(
    max_pacing_rate,
    std::numeric_limits<uint64_t>::max(),
    "Max pacing rate to use in bytes per second");
DEFINE_bool(gso, true, "Enable GSO writes to the socket");
DEFINE_uint32(
    client_transport_timer_resolution_ms,
    1,
    "Timer resolution for Ack and Loss timeout in client transport");
DEFINE_string(
    server_qlogger_path,
    "",
    "Path to the directory where qlog files will be written. File will be named"
    " as <CID>.qlog where CID is the DCID from client's perspective.");
DEFINE_uint32(
    max_cwnd_mss,
    quic::kLargeMaxCwndInMss,
    "Max cwnd in the unit of mss");
DEFINE_uint32(num_streams, 1, "Number of streams to send on simultaneously");
DEFINE_uint64(
    bytes_per_stream,
    0,
    "Maximum number of bytes per stream. "
    "0 (the default) means the stream lives for the whole duration of the test.");
DEFINE_string(
    pacing_observer,
    "std::nullopt",
    "std::nullopt/time/rtt/ack: Pacing observer bucket type: per 3ms, per rtt or per ack");
DEFINE_uint32(
    max_receive_packet_size,
    quic::kDefaultMaxUDPPayload,
    "Maximum packet size to advertise to the peer.");
DEFINE_bool(
    override_packet_size,
    true,
    "Sender trusts the peer's advertised max packet size.");
DEFINE_bool(use_inplace_write, true, "Data path type");
DEFINE_double(latency_factor, 0.5, "Latency factor (delta) for Copa");
DEFINE_uint32(
    num_server_worker,
    1,
    "Max number of mvfst server worker threads");
DEFINE_bool(log_rtt_sample, false, "Log rtt sample events");
DEFINE_bool(log_loss, false, "Log packet loss events");
DEFINE_bool(log_app_rate_limited, false, "Log app rate limited events");
DEFINE_string(
    transport_knob_params,
    "",
    "JSON-serialized dictionary of transport knob params");
DEFINE_bool(
    use_ack_receive_timestamps,
    false,
    "Request the peer to attach receive timestamps to outgoing ACKs. By "
    "default the legacy mvfst transport parameters and 0xB0/0xB1 wire "
    "format are advertised. Combine with --use_draft02_ack_receive_timestamps "
    "to also advertise draft-ietf-quic-receive-ts-02; when both formats are "
    "negotiated end-to-end, the scheduler prefers draft-02.");
DEFINE_bool(
    use_draft02_ack_receive_timestamps,
    false,
    "Advertise draft-ietf-quic-receive-ts-02 receive-timestamp transport "
    "parameters (0x4ac07 / 0x4ac26) and accept the 0x03178307/0x03178308 "
    "wire format. Implies requesting receive timestamps from the peer; can "
    "be set without --use_ack_receive_timestamps for a draft-02-only run.");
DEFINE_bool(
    advertise_legacy_ack_receive_timestamps,
    true,
    "Advertise the legacy mvfst receive-timestamp transport parameters "
    "(0xff0a001 / 0xff0a002 / 0xff0a003). Set to false to migrate to a "
    "draft-02-only peer. Applies whenever --use_ack_receive_timestamps or "
    "--use_draft02_ack_receive_timestamps is set.");
DEFINE_bool(
    send_draft02_ack_receive_timestamps,
    true,
    "Per-direction send opt-out for draft-02 ACK_RECEIVE_TIMESTAMPS. When "
    "false, this endpoint will NOT send draft-02 frames even if the peer "
    "advertised; useful for asymmetric setups where this endpoint wants to "
    "receive timestamps but not send any. No effect on the legacy mvfst "
    "wire format.");
DEFINE_uint32(
    max_ack_receive_timestamps_to_send,
    quic::kMaxReceivedPktsTimestampsStored,
    "Controls how many packet receive timestamps the peer should send "
    "(applies to both legacy and draft-02 advertisements).");
DEFINE_bool(use_l4s_ecn, false, "Whether to use L4S for ECN marking");
DEFINE_bool(
    read_ecn,
    false,
    "Whether to read and echo ecn marking from ingress packets");
DEFINE_uint32(dscp, 0, "DSCP value to use for outgoing packets");
DEFINE_uint32(
    burst_deadline_ms,
    0,
    "If > 0, server will send bursts of data of size=block_size with a deadline of burst_deadline_ms milliseconds");
DEFINE_uint64(
    static_cwnd_bytes,
    quic::kInitCwndInMss* quic::kDefaultUDPSendPacketLen,
    "If the StaticCwnd congestion controller is used, this is the static cwnd in bytes");
DEFINE_string(
    pacer_interval_source,
    "std::nullopt",
    "If the StaticCwnd congestion controller is used with a pacer, this is the rtt that will be used to updated the pacer. (mrtt, lrtt, srtt, std::nullopt)");
DEFINE_string(
    tx_backend,
    "udp",
    "Server-side UDP TX backend: 'udp' (default), 'udp_gso_zerocopy_inplace', "
    "or 'udp_gso_zerocopy_hugepage'. The inplace MSG_ZEROCOPY backend requires "
    "--use_inplace_write and --gso; mvfst encrypts directly into pool-borrowed "
    "slabs that the kernel zerocopies, with per-fd completion bookkeeping "
    "returning slabs to the pool. The hugepage backend is the inplace backend "
    "with one variable changed: slabs come from a per-worker 2MB-huge-page "
    "arena instead of malloc, so the kernel coalesces each batch into a "
    "single skb frag and one batched folio refcount add.");
DEFINE_uint64(
    udp_zerocopy_min_bytes,
    1500,
    "Minimum batch payload bytes before the inplace MSG_ZEROCOPY path is "
    "attempted. Batches smaller than this fall back to plain GSO.");
DEFINE_uint32(
    udp_zerocopy_pool_buffers,
    4096,
    "Cap on the number of slab IOBufs the inplace MSG_ZEROCOPY pool will allocate. "
    "When exhausted, the writer falls back to plain GSO until the kernel "
    "completes outstanding sends and returns slabs to the idle list.");
DEFINE_bool(
    udp_zerocopy_write_stats,
    true,
    "Record per-write stats (latency timing, shared counters, kernel ZC "
    "snapshot) on the inplace/hugepage MSG_ZEROCOPY backends. The 'udp' "
    "backend records none, so set this to false when comparing CPU cost "
    "against it. The one-off huge-page arena report is kept either way.");
DEFINE_string(
    jks_to_patch,
    "",
    "Comma-separated boolean JustKnobs to force true for this process");
DEFINE_uint64(
    udp_zerocopy_hugepage_bytes,
    64ULL * 1024 * 1024,
    "Per-worker huge-page arena size in bytes for "
    "--tx_backend=udp_gso_zerocopy_hugepage. Rounded up to a 2MB multiple. "
    "Caps live slabs per worker at arena_bytes / slab_stride regardless of "
    "--udp_zerocopy_pool_buffers; when the arena runs dry the writer falls "
    "back to malloc'd slabs and bumps udp_zc_hugepage_heap_fallbacks, which "
    "means the run is no longer a pure huge-page measurement.");

namespace quic::tperf {

namespace {

#ifdef __linux__

struct CpuTopology {
  int package;
  int core;
};

std::optional<int> readTopologyValue(int cpu, std::string_view name) {
  std::ifstream input(
      "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/" +
      std::string(name));
  int value = 0;
  if (input >> value) {
    return value;
  }
  return std::nullopt;
}

std::optional<CpuTopology> readCpuTopology(int cpu) {
  const auto package = readTopologyValue(cpu, "physical_package_id");
  const auto core = readTopologyValue(cpu, "core_id");
  if (!package || !core) {
    return std::nullopt;
  }
  return CpuTopology{.package = *package, .core = *core};
}

int selectClientCpu(const std::vector<int>& allowedCpus) {
  const int serverCpu = allowedCpus.front();
  const auto serverTopology = readCpuTopology(serverCpu);
  if (serverTopology) {
    for (const int cpu : allowedCpus) {
      const auto topology = readCpuTopology(cpu);
      if (topology && topology->package == serverTopology->package &&
          topology->core != serverTopology->core) {
        return cpu;
      }
    }
  }
  return allowedCpus.size() > 1 ? allowedCpus[1] : serverCpu;
}

#endif

void maybePinToCpu(std::string_view mode) {
  if (!FLAGS_pin) {
    return;
  }

#ifdef __linux__
  if (mode != "server" && mode != "client") {
    MVLOG_WARNING << "Cannot pin unknown tperf mode " << mode;
    return;
  }

  cpu_set_t allowedSet;
  CPU_ZERO(&allowedSet);
  if (sched_getaffinity(0, sizeof(allowedSet), &allowedSet) != 0) {
    MVLOG_WARNING << "Unable to read CPU affinity: " << folly::errnoStr(errno);
    return;
  }

  std::vector<int> allowedCpus;
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &allowedSet)) {
      allowedCpus.push_back(cpu);
    }
  }
  if (allowedCpus.empty()) {
    MVLOG_WARNING << "Cannot pin tperf: no CPUs in the affinity mask";
    return;
  }

  const int cpu =
      mode == "server" ? allowedCpus.front() : selectClientCpu(allowedCpus);
  cpu_set_t selectedSet;
  CPU_ZERO(&selectedSet);
  CPU_SET(cpu, &selectedSet);
  if (sched_setaffinity(0, sizeof(selectedSet), &selectedSet) != 0) {
    MVLOG_WARNING << "Unable to pin tperf to CPU " << cpu << ": "
                  << folly::errnoStr(errno);
    return;
  }
  MVLOG_INFO << "Pinned tperf " << mode << " to CPU " << cpu;
#else
  MVLOG_WARNING << "--pin is not supported on this platform";
#endif
}

} // namespace

} // namespace quic::tperf

using namespace quic::tperf;

enum class TperfTransportMode : uint8_t { Quic, Tcp };

TperfTransportMode flagsToTransportMode(const std::string& transportFlag) {
  if (transportFlag == "quic") {
    return TperfTransportMode::Quic;
  }
  if (transportFlag == "tcp") {
    return TperfTransportMode::Tcp;
  }
  throw std::invalid_argument(
      fmt::format("Unknown transport {}", transportFlag));
}

quic::CongestionControlType flagsToCongestionControlType(
    const std::string& congestionControlFlag) {
  auto ccType = quic::congestionControlStrToType(congestionControlFlag);
  if (!ccType) {
    throw std::invalid_argument(
        fmt::format("Unknown congestion controller {}", congestionControlFlag));
  }
  return *ccType;
}

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);
  maybePinToCpu(FLAGS_mode);

  TperfKnobsPatcher knobsPatcher;
  if (!knobsPatcher.patch(FLAGS_jks_to_patch)) {
    return 1;
  }

  TperfTransportMode transportMode = TperfTransportMode::Quic;
  try {
    transportMode = flagsToTransportMode(FLAGS_transport);
  } catch (const std::invalid_argument& ex) {
    MVLOG_ERROR << ex.what();
    return 1;
  }
  if (FLAGS_mode == "server") {
    if (transportMode == TperfTransportMode::Tcp) {
      TPerfTcpServer server(
          TPerfTcpServerConfig{
              .host = FLAGS_host,
              .port = static_cast<uint16_t>(FLAGS_port),
              .blockSize = FLAGS_block_size,
              .writesPerLoop = FLAGS_writes_per_loop,
          });
      server.start();
      return 0;
    }
    TPerfUdpGsoZerocopyConfig udpGsoZerocopyConfig;
    if (FLAGS_tx_backend == "udp") {
      // Default backend: no override, plain GSO writer.
    } else if (
        FLAGS_tx_backend == "udp_gso_zerocopy_inplace" ||
        FLAGS_tx_backend == "udp_gso_zerocopy_hugepage") {
      // Both zerocopy backends run the exact same writer and send path; the
      // hugepage variant only swaps the slab allocator underneath it, which
      // is what makes the two comparable as adjacent matrix columns.
      const bool hugePages = FLAGS_tx_backend == "udp_gso_zerocopy_hugepage";
      // The inplace MSG_ZEROCOPY writer hijacks conn.bufAccessor which only
      // exists when mvfst's ContinuousMemory data path is enabled. That data
      // path requires both --use_inplace_write and --gso (see TPerfServer
      // constructor: settings.dataPathType = ContinuousMemory iff
      // useInplaceWrite && gso). Refuse to start instead of silently falling
      // back to the default writer and pretending --tx_backend was honored.
      if (!FLAGS_use_inplace_write || !FLAGS_gso) {
        MVLOG_ERROR
            << "--tx_backend=" << FLAGS_tx_backend << " requires both "
            << "--use_inplace_write=true and --gso=true (got use_inplace_write="
            << FLAGS_use_inplace_write << ", gso=" << FLAGS_gso << ")";
        return 1;
      }
      if (hugePages && FLAGS_udp_zerocopy_hugepage_bytes == 0) {
        MVLOG_ERROR
            << "--udp_zerocopy_hugepage_bytes=0 is not allowed; "
            << "set it to a positive size or omit the flag for the default.";
        return 1;
      }
      // --udp_zerocopy_pool_buffers=0 used to be silently ignored by the
      // pool (setMaxSlabs(0) kept the default cap of 64), which contradicts
      // the flag's user-facing meaning ("Cap on the number of slab IOBufs
      // the inplace MSG_ZEROCOPY pool will allocate"). Reject it explicitly
      // so the operator either picks a real cap or removes the flag.
      if (FLAGS_udp_zerocopy_pool_buffers == 0) {
        MVLOG_ERROR
            << "--udp_zerocopy_pool_buffers=0 is not allowed; "
            << "set it to a positive cap or omit the flag for the default.";
        return 1;
      }
      udpGsoZerocopyConfig.enabled = true;
      udpGsoZerocopyConfig.inplace = true;
      udpGsoZerocopyConfig.minBytes = FLAGS_udp_zerocopy_min_bytes;
      udpGsoZerocopyConfig.poolBuffers = FLAGS_udp_zerocopy_pool_buffers;
      udpGsoZerocopyConfig.hugePages = hugePages;
      udpGsoZerocopyConfig.hugePageBytes = FLAGS_udp_zerocopy_hugepage_bytes;
      udpGsoZerocopyConfig.perWriteStats = FLAGS_udp_zerocopy_write_stats;
    } else {
      MVLOG_ERROR << "Unknown --tx_backend value: " << FLAGS_tx_backend
                  << " (expected 'udp', 'udp_gso_zerocopy_inplace', or "
                  << "'udp_gso_zerocopy_hugepage')";
      return 1;
    }
    TPerfServer server(
        FLAGS_host,
        FLAGS_port,
        FLAGS_block_size,
        FLAGS_writes_per_loop,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_gso,
        FLAGS_max_cwnd_mss,
        FLAGS_pacing,
        FLAGS_num_streams,
        FLAGS_bytes_per_stream,
        FLAGS_max_receive_packet_size,
        FLAGS_use_inplace_write,
        FLAGS_override_packet_size,
        FLAGS_latency_factor,
        FLAGS_use_ack_receive_timestamps,
        FLAGS_use_draft02_ack_receive_timestamps,
        FLAGS_advertise_legacy_ack_receive_timestamps,
        FLAGS_send_draft02_ack_receive_timestamps,
        FLAGS_max_ack_receive_timestamps_to_send,
        FLAGS_use_l4s_ecn,
        FLAGS_read_ecn,
        FLAGS_dscp,
        FLAGS_num_server_worker,
        FLAGS_burst_deadline_ms,
        FLAGS_max_pacing_rate,
        FLAGS_log_app_rate_limited,
        FLAGS_log_loss,
        FLAGS_log_rtt_sample,
        udpGsoZerocopyConfig,
        FLAGS_server_qlogger_path,
        FLAGS_pacing_observer,
        nullptr, // DoneCallback
        TPerfServer::StaticCwndConfig(
            FLAGS_static_cwnd_bytes, FLAGS_pacer_interval_source));
    server.start();
  } else if (FLAGS_mode == "client") {
    if (transportMode == TperfTransportMode::Tcp) {
      TPerfTcpClient client(
          TPerfTcpClientConfig{
              .host = FLAGS_host,
              .port = static_cast<uint16_t>(FLAGS_port),
              .duration = FLAGS_duration,
          });
      client.start();
      return 0;
    }
    if (FLAGS_num_streams != 1) {
      MVLOG_ERROR << "num_streams option is server only";
      return 1;
    }
    if (FLAGS_bytes_per_stream != 0) {
      MVLOG_ERROR << "bytes_per_stream option is server only";
      return 1;
    }
    TPerfClient client(
        FLAGS_host,
        FLAGS_port,
        std::chrono::milliseconds(FLAGS_client_transport_timer_resolution_ms),
        FLAGS_duration,
        FLAGS_window,
        FLAGS_autotune_window,
        FLAGS_gso,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_max_receive_packet_size,
        FLAGS_use_inplace_write,
        FLAGS_transport_knob_params,
        FLAGS_use_ack_receive_timestamps,
        FLAGS_use_draft02_ack_receive_timestamps,
        FLAGS_advertise_legacy_ack_receive_timestamps,
        FLAGS_send_draft02_ack_receive_timestamps,
        FLAGS_max_ack_receive_timestamps_to_send,
        FLAGS_use_l4s_ecn,
        FLAGS_read_ecn,
        FLAGS_dscp);
    client.start();
  } else {
    MVLOG_ERROR << "Unknown mode " << FLAGS_mode;
    return 1;
  }
  return 0;
}
