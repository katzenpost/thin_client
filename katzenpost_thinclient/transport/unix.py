# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Unix-domain-socket transport for the thin-client."""

import random
import socket
from dataclasses import dataclass
from typing import Tuple


@dataclass
class UnixDialConfig:
    """Configures a unix-domain-socket dialer."""

    # address is the path to the unix socket the daemon is listening
    # on, or "@<abstract-name>" for a Linux abstract socket.
    address: str

    def setup_socket(self) -> "Tuple[socket.socket, str]":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        if self.address.startswith("@"):
            # Abstract unix socket: leading @ becomes a null byte.
            abstract_name = self.address[1:]
            server_addr = f"\0{abstract_name}"

            # Bind to a unique abstract socket for this client so that
            # the daemon can send back responses addressed to us.
            random_bytes = [random.randint(0, 255) for _ in range(16)]
            hex_string = "".join(format(b, "02x") for b in random_bytes)
            client_abstract = f"\0katzenpost_python_thin_client_{hex_string}"
            sock.bind(client_abstract)
        else:
            # Filesystem unix socket.
            server_addr = self.address

        sock.setblocking(False)
        return sock, server_addr
