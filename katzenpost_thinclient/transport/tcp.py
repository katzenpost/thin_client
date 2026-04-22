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
        return sock, server_addr
