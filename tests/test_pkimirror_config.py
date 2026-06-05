import os

import pytest

from katzenpost_reticulum.pkimirror.config import (
    PkiMirrorConfig,
    parse_args,
)


def test_required_thinclient_config():
    with pytest.raises(SystemExit):
        parse_args([])


def test_defaults_are_set(tmp_path):
    cfg = parse_args(["--thinclient-config", "/tmp/tc.toml"])
    assert isinstance(cfg, PkiMirrorConfig)
    assert cfg.thinclient_config == "/tmp/tc.toml"
    assert cfg.identity_path.endswith(os.path.join("pkimirror", "identity"))
    assert cfg.rns_config is None
    assert cfg.dirauth_config.endswith(os.path.join("pkimirror", "dirauth.toml"))
    assert cfg.announce_interval == 300.0
    assert cfg.stale_after == 600.0
    assert cfg.app_name == "katzenpost"
    assert cfg.aspect == "pkimirror"
    assert cfg.log_level == "INFO"


def test_aspect_overridable():
    cfg = parse_args(
        [
            "--thinclient-config",
            "/x.toml",
            "--aspect",
            "experimental",
        ]
    )
    assert cfg.aspect == "experimental"


def test_intervals_parse_as_float():
    cfg = parse_args(
        [
            "--thinclient-config",
            "/x.toml",
            "--announce-interval",
            "5",
            "--stale-after",
            "12.5",
        ]
    )
    assert cfg.announce_interval == 5.0
    assert cfg.stale_after == 12.5


def test_log_level_normalised_to_upper():
    cfg = parse_args(["--thinclient-config", "/x.toml", "--log-level", "debug"])
    assert cfg.log_level == "DEBUG"


def test_log_level_rejects_garbage():
    with pytest.raises(SystemExit):
        parse_args(["--thinclient-config", "/x.toml", "--log-level", "WHISPER"])


def test_negative_interval_rejected():
    with pytest.raises(SystemExit):
        parse_args(["--thinclient-config", "/x.toml", "--announce-interval", "-1"])


def test_paths_propagate_through(tmp_path):
    cfg = parse_args(
        [
            "--thinclient-config",
            str(tmp_path / "tc.toml"),
            "--identity",
            str(tmp_path / "id"),
            "--rns-config",
            str(tmp_path / "rns"),
            "--dirauth-config",
            str(tmp_path / "dirauth.toml"),
        ]
    )
    assert cfg.thinclient_config == str(tmp_path / "tc.toml")
    assert cfg.identity_path == str(tmp_path / "id")
    assert cfg.rns_config == str(tmp_path / "rns")
    assert cfg.dirauth_config == str(tmp_path / "dirauth.toml")
