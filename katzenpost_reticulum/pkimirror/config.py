from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


@dataclass(frozen=True)
class PkiMirrorConfig:
    thinclient_config: str
    identity_path: str
    rns_config: Optional[str]
    dirauth_config: str
    announce_interval: float
    stale_after: float
    app_name: str
    aspects: Tuple[str, ...]
    log_level: str


def _default_identity_path() -> str:
    return os.path.expanduser(os.path.join("~", ".config", "pkimirror", "identity"))


def _default_dirauth_path() -> str:
    return os.path.expanduser(
        os.path.join("~", ".config", "pkimirror", "dirauth.toml")
    )


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError(
            f"value must be non-negative, got {value!r}"
        )
    return parsed


def _log_level(value: str) -> str:
    upper = value.upper()
    if upper not in _VALID_LOG_LEVELS:
        raise argparse.ArgumentTypeError(
            f"log level must be one of {_VALID_LOG_LEVELS}; got {value!r}"
        )
    return upper


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pkimirror",
        description=(
            "A Reticulum-side publisher of Katzenpost PKI documents. "
            "Connects to a local kpclientd via the Python thin client and "
            "serves cached PKI documents over a Reticulum Link."
        ),
    )
    p.add_argument(
        "--thinclient-config",
        required=True,
        help="Path to the thin client TOML config (passed to ThinClient).",
    )
    p.add_argument(
        "--identity",
        dest="identity_path",
        default=_default_identity_path(),
        help="Path to the persistent Reticulum identity file (load or create).",
    )
    p.add_argument(
        "--rns-config",
        default=None,
        help="Path to a Reticulum config directory; default uses RNS' own default.",
    )
    p.add_argument(
        "--dirauth-config",
        default=_default_dirauth_path(),
        help="Path to a TOML file with dirauth identity public keys.",
    )
    p.add_argument(
        "--announce-interval",
        type=_non_negative_float,
        default=300.0,
        help="Seconds between periodic Reticulum announces (default: 300).",
    )
    p.add_argument(
        "--stale-after",
        type=_non_negative_float,
        default=600.0,
        help=(
            "Seconds after which a cached PKI document is reported as stale "
            "in the response envelope (default: 600)."
        ),
    )
    p.add_argument(
        "--app-name",
        default="katzenpost",
        help="Reticulum destination app_name (default: 'katzenpost').",
    )
    p.add_argument(
        "--aspect",
        dest="aspects",
        action="append",
        default=None,
        help=(
            "Reticulum destination aspect; may be given several times. "
            "Default: ['pkimirror']."
        ),
    )
    p.add_argument(
        "--log-level",
        type=_log_level,
        default="INFO",
        help="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO).",
    )
    return p


def parse_args(argv: Optional[List[str]] = None) -> PkiMirrorConfig:
    ns = _build_parser().parse_args(argv)
    aspects = tuple(ns.aspects) if ns.aspects else ("pkimirror",)
    return PkiMirrorConfig(
        thinclient_config=ns.thinclient_config,
        identity_path=ns.identity_path,
        rns_config=ns.rns_config,
        dirauth_config=ns.dirauth_config,
        announce_interval=ns.announce_interval,
        stale_after=ns.stale_after,
        app_name=ns.app_name,
        aspects=aspects,
        log_level=ns.log_level,
    )
