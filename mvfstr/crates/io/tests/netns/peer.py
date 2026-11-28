# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# @lint-ignore-every AUTODEPS2 run.sh runs this stdlib-only script directly, without a Buck target.

"""The peer of the io crate's netns tests: on dual-stack UDP sockets, it discards what reaches the
sink port and sends back to its source what reaches the echo port. It exits after an hour, in case
run.sh cannot stop it.

usage: peer.py SINK_PORT ECHO_PORT
"""

import selectors
import socket
import sys
import time


def bind(port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    # A burst arrives faster than one select round reads it.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind(("::", port))
    sock.setblocking(False)
    return sock


def main():
    sink, echo = bind(int(sys.argv[1])), bind(int(sys.argv[2]))
    selector = selectors.DefaultSelector()
    selector.register(sink, selectors.EVENT_READ)
    selector.register(echo, selectors.EVENT_READ)
    end = time.monotonic() + 3600
    while time.monotonic() < end:
        for key, _ in selector.select(timeout=1.0):
            sock = key.fileobj
            while True:
                try:
                    data, addr = sock.recvfrom(65536)
                except BlockingIOError:
                    break
                if sock is echo:
                    sock.sendto(data, addr)


if __name__ == "__main__":
    main()
