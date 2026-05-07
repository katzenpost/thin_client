import logging
import textwrap
from pathlib import Path

import pytest

from katzenpost_reticulum.pkimirror.dirauth_config import (
    DirauthConfig,
    DirauthConfigError,
    DirauthIdentity,
    load_dirauth_config,
)


def _write(tmp_path: Path, contents: str) -> Path:
    p = tmp_path / "dirauth.toml"
    p.write_text(textwrap.dedent(contents).lstrip())
    return p


def test_parses_minimal_config(tmp_path):
    p = _write(
        tmp_path,
        '''
        sphincs_warning = "ed25519"

        [[dirauths]]
        name = "auth1"
        identity = "deadbeef"
        ''',
    )
    cfg = load_dirauth_config(str(p))
    assert isinstance(cfg, DirauthConfig)
    assert cfg.scheme == "ed25519"
    assert cfg.identities == [
        DirauthIdentity(name="auth1", pubkey=bytes.fromhex("deadbeef")),
    ]


def test_parses_multiple_identities(tmp_path):
    p = _write(
        tmp_path,
        '''
        sphincs_warning = "ed25519"

        [[dirauths]]
        name = "auth1"
        identity = "00112233"

        [[dirauths]]
        name = "auth2"
        identity = "ffeeddcc"
        ''',
    )
    cfg = load_dirauth_config(str(p))
    assert len(cfg.identities) == 2
    assert cfg.identities[0].name == "auth1"
    assert cfg.identities[0].pubkey == b"\x00\x11\x22\x33"
    assert cfg.identities[1].pubkey == b"\xff\xee\xdd\xcc"


def test_empty_identities_logs_warning(tmp_path, caplog):
    p = _write(tmp_path, 'sphincs_warning = "ed25519"\n')
    with caplog.at_level(logging.WARNING):
        cfg = load_dirauth_config(str(p))
    assert cfg.identities == []
    assert any("dirauth" in rec.getMessage().lower() for rec in caplog.records)


def test_missing_file_returns_empty_config(tmp_path, caplog):
    nope = tmp_path / "does-not-exist.toml"
    with caplog.at_level(logging.WARNING):
        cfg = load_dirauth_config(str(nope))
    assert cfg.identities == []
    assert cfg.scheme == ""
    assert any("dirauth" in rec.getMessage().lower() for rec in caplog.records)


def test_invalid_hex_raises(tmp_path):
    p = _write(
        tmp_path,
        '''
        sphincs_warning = "ed25519"

        [[dirauths]]
        name = "broken"
        identity = "not-hex"
        ''',
    )
    with pytest.raises(DirauthConfigError) as exc_info:
        load_dirauth_config(str(p))
    assert "broken" in str(exc_info.value)


def test_missing_name_raises(tmp_path):
    p = _write(
        tmp_path,
        '''
        sphincs_warning = "ed25519"

        [[dirauths]]
        identity = "deadbeef"
        ''',
    )
    with pytest.raises(DirauthConfigError):
        load_dirauth_config(str(p))


def test_unknown_scheme_preserved(tmp_path):
    p = _write(
        tmp_path,
        '''
        sphincs_warning = "ed25519+ml-dsa-44-experimental"

        [[dirauths]]
        name = "auth1"
        identity = "00"
        ''',
    )
    cfg = load_dirauth_config(str(p))
    assert cfg.scheme == "ed25519+ml-dsa-44-experimental"


def test_scheme_defaults_to_empty_string(tmp_path):
    p = _write(
        tmp_path,
        '''
        [[dirauths]]
        name = "auth1"
        identity = "00"
        ''',
    )
    cfg = load_dirauth_config(str(p))
    assert cfg.scheme == ""
