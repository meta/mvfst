#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
#
# Runs the io crate's netns tests (`host::netns_tests`, which a plain `cargo test` skips) in a
# throwaway pair of network namespaces. The rig's setup and teardown need `sudo -n`. The script
# takes no lock: anyone who shares the host with benchmarks runs it under their own.
#
# usage: run.sh [TEST_NAME_FILTER...]     (default filter: host::netns_tests)
#
# The test binary is $MVFSTR_IO_TEST_BIN if set. Otherwise the script builds it with
# `cargo test -p mvfstr_io --lib --no-run` in the caller's cargo environment.
#
# The rig: namespace SND sends through the veth mvr-tx (10.89.0.1/24, fd89::1/64; root qdisc
# `fq flow_limit 10`; tx-udp-segmentation off) to mvr-rx in namespace RCV (10.89.0.2/24,
# fd89::2/64), where peer.py discards datagrams on port 7001 and sends back those on port 7002;
# port 7003 is closed. Neighbours are static on both sides and RCV's ICMP rate limits are off. The
# tests run as the calling user in SND; only the rig's setup and teardown use sudo.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE=$(cd "$HERE/../../../.." && pwd)
ME=$(id -un)
SUDO="sudo -n"

if [ -z "${MVFSTR_IO_TEST_BIN:-}" ]; then
  MVFSTR_IO_TEST_BIN=$(cd "$WORKSPACE" && \
    cargo test -p mvfstr_io --lib --no-run --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "mvfstr_io"
                    and .profile.test) | .executable')
fi
if [ ! -x "$MVFSTR_IO_TEST_BIN" ]; then
  echo "no test binary: '$MVFSTR_IO_TEST_BIN'" >&2
  exit 2
fi

SND=mvr-snd-$$
RCV=mvr-rcv-$$
S="$SUDO ip netns exec $SND"
R="$SUDO ip netns exec $RCV"
PEER=
# shellcheck disable=SC2317
cleanup() {
  if [ -n "$PEER" ]; then
    $SUDO kill "$PEER" 2>/dev/null || true
    wait "$PEER" 2>/dev/null || true
  fi
  $SUDO ip netns del "$SND" 2>/dev/null || true
  $SUDO ip netns del "$RCV" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

$SUDO ip netns add "$SND"
$SUDO ip netns add "$RCV"
$SUDO ip link add mvr-tx netns "$SND" type veth peer name mvr-rx netns "$RCV"
$S ip link set lo up
$R ip link set lo up
$S ip addr add 10.89.0.1/24 dev mvr-tx
$R ip addr add 10.89.0.2/24 dev mvr-rx
$S ip addr add fd89::1/64 dev mvr-tx nodad
$R ip addr add fd89::2/64 dev mvr-rx nodad
$S ip link set mvr-tx mtu 1500 up
$R ip link set mvr-rx mtu 1500 up
TX_MAC=$($S cat /sys/class/net/mvr-tx/address)
RX_MAC=$($R cat /sys/class/net/mvr-rx/address)
$S ip neigh replace 10.89.0.2 lladdr "$RX_MAC" dev mvr-tx nud permanent
$S ip -6 neigh replace fd89::2 lladdr "$RX_MAC" dev mvr-tx nud permanent
$R ip neigh replace 10.89.0.1 lladdr "$TX_MAC" dev mvr-rx nud permanent
$R ip -6 neigh replace fd89::1 lladdr "$TX_MAC" dev mvr-rx nud permanent
$S ethtool -K mvr-tx tx-udp-segmentation off >/dev/null
$S tc qdisc replace dev mvr-tx root fq flow_limit 10
$R sysctl -q -w net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0

$R runuser -u "$ME" -- python3 -I "$HERE/peer.py" 7001 7002 &
PEER=$!
for _ in $(seq 100); do
  if [ "$($R ss -Hlun 'sport = :7002' | wc -l)" -gt 0 ]; then
    break
  fi
  sleep 0.1
done
if [ "$($R ss -Hlun 'sport = :7002' | wc -l)" -eq 0 ]; then
  echo "the peer did not bind its ports" >&2
  exit 2
fi

echo "rig: kernel $(uname -r), $SND -> $RCV, binary $MVFSTR_IO_TEST_BIN"
$S tc -s -d qdisc show dev mvr-tx
if [ $# -eq 0 ]; then
  set -- host::netns_tests
fi
status=0
$S runuser -u "$ME" -- env PATH=/usr/sbin:/usr/bin:/bin RUST_BACKTRACE=1 \
  "$MVFSTR_IO_TEST_BIN" --ignored --test-threads=1 "$@" || status=$?
echo "rig after the tests:"
$S tc -s -d qdisc show dev mvr-tx
exit $status
