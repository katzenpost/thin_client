# SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Unit tests for the TCP transport's socket options.

A daemon socket is the thin client's only link to kpclientd. TCP keepalive
and user timeout must be enabled so a peer that silently dies (no FIN/RST)
is surfaced as a socket error instead of leaving ``recv()`` blocked
forever, which is what delivers a dropped connection to ``worker_loop``.
"""

import socket

import pytest

from katzenpost_thinclient.transport.tcp import TcpDialConfig


class TestKeepalive:
    def test_keepalive_enabled(self):
        sock, _ = TcpDialConfig(address="127.0.0.1:1234").setup_socket()
        try:
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
        finally:
            sock.close()

    def test_keepalive_probe_interval(self):
        sock, _ = TcpDialConfig(address="127.0.0.1:1234").setup_socket()
        try:
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 10
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == 10
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == 3
        finally:
            sock.close()

    def test_user_timeout_enabled(self):
        sock, _ = TcpDialConfig(address="127.0.0.1:1234").setup_socket()
        try:
            if hasattr(socket, "TCP_USER_TIMEOUT"):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 30_000
        finally:
            sock.close()

    def test_socket_is_nonblocking(self):
        sock, _ = TcpDialConfig(address="127.0.0.1:1234").setup_socket()
        try:
            assert sock.gettimeout() == 0.0
            assert sock.getblocking() is False
        finally:
            sock.close()


class TestServerAddress:
    def test_ipv4_literal(self):
        _, server_addr = TcpDialConfig(address="127.0.0.1:32000").setup_socket()
        assert server_addr == ("127.0.0.1", 32000)

    def test_ipv6_literal(self):
        sock, server_addr = TcpDialConfig(address="[::1]:32000", network="tcp6").setup_socket()
        try:
            assert server_addr == ("::1", 32000)
        finally:
            sock.close()

    def test_invalid_network_rejected(self):
        with pytest.raises(ValueError):
            TcpDialConfig(address="127.0.0.1:32000", network="udp").setup_socket()