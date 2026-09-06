# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""TCP transport for the thin-client."""

import socket
from dataclasses import dataclass
from typing import Tuple


@dataclass
class TcpDialConfig:
    """Configures a TCP dialer.

    address is in host:port form, e.g. "localhost:64331" or "[::1]:64331".
    network is one of "tcp", "tcp4", "tcp6"; defaults to "tcp".
    """

    address: str
    network: str = "tcp"

    def setup_socket(self) -> "Tuple[socket.socket, Tuple[str, int]]":
        if self.network not in ("tcp", "tcp4", "tcp6"):
            raise ValueError(
                f"transport: TcpDialConfig.network {self.network!r} "
                "is not one of tcp, tcp4, tcp6"
            )

        family = socket.AF_INET6 if self.network == "tcp6" else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)

        host, port_str = self.address.rsplit(":", 1)
        # Strip brackets around IPv6 literals (e.g. "[::1]:64331").
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        server_addr = (host, int(port_str))

        sock.setblocking(False)

        # TCP keepalive + user timeout: a peer that silently dies (no FIN,
        # no RST) would otherwise leave recv() blocked forever, so the worker
        # loop never notices the dead link and never replays in-flight
        # requests. With these options the kernel probes an idle link and
        # aborts it once a probe goes unacknowledged.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        if hasattr(socket, 'TCP_USER_TIMEOUT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000)
        return sock, server_addr
