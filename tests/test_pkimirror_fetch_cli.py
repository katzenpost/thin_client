"""Unit tests for the pkimirror-fetch CLI argument parsing and mirror
selection. Pure Python: no Reticulum, no daemon."""

from __future__ import annotations

import pytest

from katzenpost_reticulum.pkimirror.client import MirrorAnnouncement
from katzenpost_reticulum.pkimirror.fetch import (
    _build_parser,
    _select_destination,
)


def _args(**overrides):
    argv = []
    for key, value in overrides.items():
        argv.extend([f"--{key.replace('_', '-')}", str(value)])
    return _build_parser().parse_args(argv)


def test_parser_defaults():
    args = _build_parser().parse_args([])
    assert args.destination is None
    assert args.epoch is None
    assert args.app_name == "katzenpost"
    assert args.aspect == "pkimirror"
    assert args.output is None
    assert args.max_announces == 3


def test_explicit_destination_skips_discovery():
    dest = b"\xab\xcd\xef\x01" * 4

    class _NoDiscover:
        def discover(self, *a, **k):
            raise AssertionError("discover must not be called")

    args = _args(destination=dest.hex())
    assert _select_destination(_NoDiscover(), args) == dest


def test_discovery_prefers_pki_then_highest_epoch():
    chosen = b"\x02" * 16
    announces = [
        MirrorAnnouncement(b"\x00" * 16, None, 99, False, 0.0),
        MirrorAnnouncement(b"\x01" * 16, None, 5, True, 0.0),
        MirrorAnnouncement(chosen, None, 7, True, 0.0),
    ]

    class _Discoverer:
        def discover(self, *a, **k):
            return announces

    assert _select_destination(_Discoverer(), _args()) == chosen


def test_no_announces_raises():
    class _Empty:
        def discover(self, *a, **k):
            return []

    with pytest.raises(RuntimeError, match="no pkimirror announced"):
        _select_destination(_Empty(), _args())
