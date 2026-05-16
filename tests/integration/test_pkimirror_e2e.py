"""End-to-end integration tests for pkimirror.

Skipped automatically when RNS is not installed or when the Katzenpost
client daemon is not reachable on 127.0.0.1:64331.

The Reticulum side runs entirely over loopback TCP so each test module
gets a hermetic mesh that does not interfere with the host's Reticulum
configuration.

Run explicitly with:
    pytest tests/integration -v
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Iterator, Tuple

import cbor2
import pytest

pytest.importorskip("RNS")

from katzenpost_reticulum.pkimirror.client import PkiMirrorClient  # noqa: E402
from katzenpost_reticulum.pkimirror.errors import (  # noqa: E402
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_OK,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_rns_config(
    config_dir: Path, role: str, port: int
) -> Path:
    """Write a minimal Reticulum config that talks only over loopback TCP.

    For the server: a TCPServerInterface listening on the chosen port.
    For the client: a TCPClientInterface targeting that port.

    Both configs disable AutoInterface so they do not see the host's
    real mesh.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    if role == "server":
        body = f"""
        [reticulum]
            enable_transport = Yes
            share_instance = No
            shared_instance_port = 37428
            instance_control_port = 37429
            panic_on_interface_error = No

        [logging]
            loglevel = 4

        [interfaces]
            [[loopback-server]]
                type = TCPServerInterface
                interface_enabled = True
                listen_ip = 127.0.0.1
                listen_port = {port}
        """
    elif role == "client":
        body = f"""
        [reticulum]
            enable_transport = No
            share_instance = No
            shared_instance_port = 37430
            instance_control_port = 37431
            panic_on_interface_error = No

        [logging]
            loglevel = 4

        [interfaces]
            [[loopback-client]]
                type = TCPClientInterface
                interface_enabled = True
                target_host = 127.0.0.1
                target_port = {port}
        """
    else:
        raise ValueError(role)
    cfg = config_dir / "config"
    cfg.write_text(textwrap.dedent(body).lstrip())
    return cfg


def _epoch_from_cert_wrapped(doc: bytes) -> int:
    """Extract the PKI epoch from a cert.Certificate-wrapped document.

    Without a DirauthConfig the client returns the wire bytes verbatim:
    a cert.Certificate CBOR map whose ``Certified`` field holds the
    inner PKI document. The katzenpost Document carries ``Epoch`` at
    the top level of that inner map.
    """
    cert = cbor2.loads(doc)
    return cbor2.loads(cert["Certified"])["Epoch"]


def _check_daemon() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex(("127.0.0.1", 64331)) == 0
    except Exception:
        return False


@pytest.fixture(scope="session")
def daemon_required() -> None:
    if not _check_daemon():
        pytest.skip("kpclientd not reachable on 127.0.0.1:64331")


@pytest.fixture(scope="session")
def thinclient_config(daemon_required) -> str:
    path = Path(__file__).resolve().parent.parent.parent / "testdata" / "thinclient.toml"
    if not path.is_file():
        pytest.skip(f"thin client config not found at {path}")
    return str(path)


@pytest.fixture(scope="module")
def loopback_port() -> int:
    return _free_port()


@pytest.fixture(scope="module")
def server_rns_config(tmp_path_factory, loopback_port) -> str:
    d = tmp_path_factory.mktemp("rns-server")
    _write_rns_config(d, "server", loopback_port)
    return str(d)


@pytest.fixture(scope="module")
def pkimirror_server(
    tmp_path_factory, thinclient_config, server_rns_config
) -> Iterator[Tuple[subprocess.Popen, bytes, Path]]:
    workdir = tmp_path_factory.mktemp("pkimirror-srv")
    identity_path = workdir / "identity"
    dirauth_path = workdir / "dirauth.toml"
    dirauth_path.write_text("# integration test: empty dirauth config\n")
    log_path = workdir / "pkimirror.log"

    cmd = [
        sys.executable, "-m", "katzenpost_reticulum.pkimirror",
        "--thinclient-config", thinclient_config,
        "--identity", str(identity_path),
        "--rns-config", server_rns_config,
        "--dirauth-config", str(dirauth_path),
        "--announce-interval", "5",
        "--stale-after", "600",
        "--log-level", "DEBUG",
    ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    log_file = open(log_path, "wb")
    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )

    destination_hash: bytes = b""
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            content = log_path.read_text(errors="replace")
        except FileNotFoundError:
            content = ""
        for line in content.splitlines():
            if "pkimirror destination hash:" in line:
                hex_part = line.split("destination hash:")[-1].strip()
                hex_compact = (
                    hex_part.strip("<>").replace(":", "").replace(" ", "")
                )
                try:
                    destination_hash = bytes.fromhex(hex_compact)
                except ValueError:
                    continue
                break
        if destination_hash:
            break
        time.sleep(0.5)

    if not destination_hash:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()
        log_text = log_path.read_text(errors="replace") if log_path.exists() else ""
        pytest.fail(
            f"pkimirror did not print a destination hash within 90s.\n"
            f"Last output:\n{log_text[-4000:]}"
        )

    try:
        yield proc, destination_hash, log_path
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()


@pytest.fixture
def client_rns_config(tmp_path, loopback_port) -> str:
    d = tmp_path / "rns-client"
    _write_rns_config(d, "client", loopback_port)
    return str(d)


@pytest.fixture
def pkimirror_client(client_rns_config) -> Iterator[PkiMirrorClient]:
    with PkiMirrorClient(reticulum_config=client_rns_config) as client:
        yield client


def test_announce_carries_epoch_app_data(pkimirror_server, pkimirror_client):
    _, destination_hash, _log = pkimirror_server
    announces = pkimirror_client.discover(timeout=60.0, max_announces=1)
    assert len(announces) >= 1
    matched = [a for a in announces if a.destination_hash == destination_hash]
    assert matched, (
        f"expected announce from {destination_hash.hex()}, "
        f"got {[a.destination_hash.hex() for a in announces]}"
    )
    ann = matched[0]
    assert ann.has_pki is True
    assert ann.epoch > 0


def test_get_current_returns_fresh_pki(pkimirror_server, pkimirror_client):
    _, destination_hash, _log = pkimirror_server
    pkimirror_client.discover(timeout=60.0, max_announces=1)
    pkimirror_client.connect(destination_hash, timeout=90.0)

    result = pkimirror_client.get_current(timeout=60.0)
    assert result.code == PKIMIRROR_OK
    assert result.doc is not None
    assert result.epoch is not None
    assert result.stale is False
    assert _epoch_from_cert_wrapped(result.doc) == result.epoch


def test_get_for_unknown_epoch_returns_error(pkimirror_server, pkimirror_client):
    _, destination_hash, _log = pkimirror_server
    pkimirror_client.discover(timeout=60.0, max_announces=1)
    pkimirror_client.connect(destination_hash, timeout=90.0)

    result = pkimirror_client.get_for_epoch(1, timeout=60.0, use_cache=False)
    assert result.code == PKIMIRROR_EPOCH_NOT_CACHED
    assert result.doc is None
    assert result.epoch is not None
    assert result.epoch > 1


def test_bad_request_returns_error(pkimirror_server, pkimirror_client):
    """Bypass the typed client and issue a malformed body directly."""
    _, destination_hash, _log = pkimirror_server
    pkimirror_client.discover(timeout=60.0, max_announces=1)
    pkimirror_client.connect(destination_hash, timeout=90.0)

    raw = pkimirror_client._transport.request(
        "/pki/epoch", b"\xff\xff not cbor", 60.0
    )
    out = cbor2.loads(raw)
    assert out["code"] == PKIMIRROR_BAD_REQUEST
    assert out["doc"] is None


def test_large_response_resource_escalation(pkimirror_server, pkimirror_client):
    """A real PKI document is far above the link MDU; confirm we receive
    the full payload via Reticulum's automatic Resource escalation."""
    _, destination_hash, _log = pkimirror_server
    pkimirror_client.discover(timeout=60.0, max_announces=1)
    pkimirror_client.connect(destination_hash, timeout=90.0)

    result = pkimirror_client.get_current(timeout=60.0)
    assert result.code == PKIMIRROR_OK
    assert result.doc is not None
    assert len(result.doc) > 4 * 1024, (
        f"PKI document smaller than expected: {len(result.doc)} bytes"
    )


def test_client_cache_hit_round_trip(pkimirror_server, pkimirror_client):
    _, destination_hash, _log = pkimirror_server
    pkimirror_client.discover(timeout=60.0, max_announces=1)
    pkimirror_client.connect(destination_hash, timeout=90.0)

    first = pkimirror_client.get_current(timeout=60.0)
    assert first.code == PKIMIRROR_OK
    epoch = first.epoch

    cached = pkimirror_client.get_for_epoch(epoch, timeout=60.0)
    assert cached.code == PKIMIRROR_OK
    assert cached.doc == first.doc
    assert pkimirror_client.cached_epochs() == [epoch]


def test_fetch_cli_retrieves_pki(pkimirror_server, client_rns_config, tmp_path):
    """Drive the pkimirror-fetch CLI as an operator would: a separate
    process that connects to the live mirror and writes the consensus
    to a file. Exercises the exact path the console script provides."""
    _, destination_hash, _log = pkimirror_server
    out = tmp_path / "pki.cbor"

    proc = subprocess.run(
        [
            sys.executable, "-m", "katzenpost_reticulum.pkimirror.fetch",
            "--rns-config", client_rns_config,
            "--destination", destination_hash.hex(),
            "--connect-timeout", "90",
            "--request-timeout", "60",
            "--output", str(out),
            "--log-level", "INFO",
        ],
        capture_output=True,
        text=True,
        timeout=200,
    )

    assert proc.returncode == 0, (
        f"pkimirror-fetch exited {proc.returncode}\n"
        f"stderr:\n{proc.stderr[-4000:]}"
    )
    doc = out.read_bytes()
    assert len(doc) > 4 * 1024, f"document smaller than expected: {len(doc)}"
    assert _epoch_from_cert_wrapped(doc) > 0
