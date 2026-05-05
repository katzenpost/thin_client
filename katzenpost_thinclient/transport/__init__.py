# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Transport abstraction for the Python thin-client.

Each concrete transport (unix, tcp; in future ssh / pipe / pigeonhole)
exposes a setup_socket() method that returns a ready-to-connect socket
and the server address in the form expected by asyncio's
loop.sock_connect.

DialConfig is a discriminated-union container: exactly one of its
inner variants must be populated. Zero or multiple populated variants
is a configuration error.
"""

from dataclasses import dataclass
from typing import Any, Optional, Tuple

from .tcp import TcpDialConfig
from .unix import UnixDialConfig


@dataclass
class DialConfig:
    """Discriminated-union of dial transports. Exactly one subtable must be populated."""

    unix: Optional[UnixDialConfig] = None
    tcp: Optional[TcpDialConfig] = None

    def validate(self) -> None:
        n = sum(x is not None for x in (self.unix, self.tcp))
        if n == 0:
            raise ValueError("transport: no dial transport configured")
        if n > 1:
            raise ValueError("transport: exactly one dial transport must be configured")

    def resolve(self) -> Any:
        """Return the single populated transport variant."""
        self.validate()
        if self.unix is not None:
            return self.unix
        if self.tcp is not None:
            return self.tcp
        raise ValueError("transport: unreachable")  # pragma: no cover

    @classmethod
    def from_toml_dict(cls, data: dict) -> "DialConfig":
        """
        Parse a TOML [Dial] subtable (dict) into a DialConfig.

        Rejects unknown subtables (typos, removed variants, future
        names) and unknown keys inside a recognised subtable. Exactly
        one of [Dial.Unix] / [Dial.Tcp] must be populated.
        """
        known_subtables = {"Unix", "Tcp"}
        unknown_subtables = set(data.keys()) - known_subtables
        if unknown_subtables:
            raise ValueError(
                f"unknown subtable(s) {sorted(unknown_subtables)} under [Dial]; "
                f"expected one of {sorted(known_subtables)}"
            )

        unix: Optional[UnixDialConfig] = None
        tcp: Optional[TcpDialConfig] = None
        if "Unix" in data:
            unix_data = data["Unix"]
            if not isinstance(unix_data, dict):
                raise ValueError("[Dial.Unix] must be a table")
            unknown = set(unix_data.keys()) - {"Address"}
            if unknown:
                raise ValueError(
                    f"[Dial.Unix] has unknown key(s) {sorted(unknown)}; expected ['Address']"
                )
            if "Address" not in unix_data:
                raise ValueError("[Dial.Unix] missing required key 'Address'")
            unix = UnixDialConfig(address=unix_data["Address"])
        if "Tcp" in data:
            tcp_data = data["Tcp"]
            if not isinstance(tcp_data, dict):
                raise ValueError("[Dial.Tcp] must be a table")
            unknown = set(tcp_data.keys()) - {"Address", "Network"}
            if unknown:
                raise ValueError(
                    f"[Dial.Tcp] has unknown key(s) {sorted(unknown)}; "
                    f"expected from ['Address', 'Network']"
                )
            if "Address" not in tcp_data:
                raise ValueError("[Dial.Tcp] missing required key 'Address'")
            tcp = TcpDialConfig(
                address=tcp_data["Address"],
                network=tcp_data.get("Network", "tcp"),
            )
        cfg = cls(unix=unix, tcp=tcp)
        cfg.validate()
        return cfg


__all__ = ["DialConfig", "UnixDialConfig", "TcpDialConfig"]
