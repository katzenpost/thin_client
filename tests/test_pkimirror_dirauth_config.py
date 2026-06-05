import logging
import textwrap
from pathlib import Path

import pytest

from katzenpost_reticulum.pkimirror.dirauth_config import (
    DirauthConfig,
    DirauthConfigError,
    DirauthIdentity,
    _parse_pem_public_key,
    load_dirauth_config,
)


# A real Ed25519 dirauth public key from the docker mixnet (auth1).
ED25519_PEM = """\
-----BEGIN ED25519 PUBLIC KEY-----
kXn/CF+vkxup1qa4r9BBwl1aJXHjf51Ls/2rTH6i1Dk=
-----END ED25519 PUBLIC KEY-----
"""

ED25519_BYTES = bytes.fromhex(
    "9179ff085faf931ba9d6a6b8afd041c25d5a2571e37f9d4bb3fdab4c7ea2d439"
)

# A synthetic ML-DSA-44-Ed25519 hybrid block (the Ed25519 half above,
# repeated to give a non-zero body of the same length, which is enough
# to exercise the parser. The bytes themselves are not a real ML-DSA
# key; the test only verifies parser behaviour.)
HYBRID_PEM = """\
-----BEGIN ML-DSA-44-ED25519 PUBLIC KEY-----
kXn/CF+vkxup1qa4r9BBwl1aJXHjf51Ls/2rTH6i1Dk=
-----END ML-DSA-44-ED25519 PUBLIC KEY-----
"""


def _write(tmp_path: Path, contents: str) -> Path:
    p = tmp_path / "dirauth.toml"
    p.write_text(textwrap.dedent(contents).lstrip())
    return p


def test_parse_pem_ed25519_label_and_bytes():
    label, pubkey = _parse_pem_public_key(ED25519_PEM)
    assert label == "ED25519"
    assert pubkey == ED25519_BYTES
    assert len(pubkey) == 32


def test_parse_pem_ml_dsa_hybrid_label():
    label, pubkey = _parse_pem_public_key(HYBRID_PEM)
    assert label == "ML-DSA-44-ED25519"
    assert pubkey == ED25519_BYTES


def test_parse_pem_handles_embedded_newlines_in_body():
    pem = (
        "-----BEGIN ED25519 PUBLIC KEY-----\n"
        "kXn/CF+vkxup1qa4r9BBwl1\n"
        "aJXHjf51Ls/2rTH6i1Dk=\n"
        "-----END ED25519 PUBLIC KEY-----\n"
    )
    label, pubkey = _parse_pem_public_key(pem)
    assert label == "ED25519"
    assert pubkey == ED25519_BYTES


def test_parse_pem_rejects_text_without_pem_block():
    with pytest.raises(ValueError):
        _parse_pem_public_key("not a PEM block")


def test_parse_pem_rejects_invalid_base64():
    bad = (
        "-----BEGIN ED25519 PUBLIC KEY-----\n"
        "this is not valid base64 ###\n"
        "-----END ED25519 PUBLIC KEY-----\n"
    )
    with pytest.raises(ValueError):
        _parse_pem_public_key(bad)


def test_loads_minimal_config(tmp_path):
    p = _write(
        tmp_path,
        f'''
        [[dirauths]]
        name = "auth1"
        identity_public_key = """{ED25519_PEM.strip()}"""
        ''',
    )
    cfg = load_dirauth_config(str(p))
    assert isinstance(cfg, DirauthConfig)
    assert cfg.identities == [
        DirauthIdentity(
            name="auth1",
            scheme="ED25519",
            pubkey=ED25519_BYTES,
        ),
    ]


def test_loads_multiple_identities_and_schemes(tmp_path, caplog):
    p = _write(
        tmp_path,
        f'''
        [[dirauths]]
        name = "auth1"
        identity_public_key = """{ED25519_PEM.strip()}"""

        [[dirauths]]
        name = "auth2"
        identity_public_key = """{HYBRID_PEM.strip()}"""
        ''',
    )
    with caplog.at_level(logging.INFO):
        cfg = load_dirauth_config(str(p))
    assert len(cfg.identities) == 2
    assert cfg.identities[0].scheme == "ED25519"
    assert cfg.identities[1].scheme == "ML-DSA-44-ED25519"
    assert any("ED25519" in rec.getMessage() for rec in caplog.records)


def test_empty_identities_logs_warning(tmp_path, caplog):
    p = _write(tmp_path, "")
    with caplog.at_level(logging.WARNING):
        cfg = load_dirauth_config(str(p))
    assert cfg.identities == []
    assert any("dirauth" in rec.getMessage().lower() for rec in caplog.records)


def test_missing_file_returns_empty_config(tmp_path, caplog):
    nope = tmp_path / "does-not-exist.toml"
    with caplog.at_level(logging.WARNING):
        cfg = load_dirauth_config(str(nope))
    assert cfg.identities == []
    assert any("dirauth" in rec.getMessage().lower() for rec in caplog.records)


def test_malformed_pem_raises_with_helpful_message(tmp_path):
    p = _write(
        tmp_path,
        """
        [[dirauths]]
        name = "broken"
        identity_public_key = "not a PEM block"
        """,
    )
    with pytest.raises(DirauthConfigError) as exc_info:
        load_dirauth_config(str(p))
    assert "broken" in str(exc_info.value)


def test_missing_name_raises(tmp_path):
    p = _write(
        tmp_path,
        f'''
        [[dirauths]]
        identity_public_key = """{ED25519_PEM.strip()}"""
        ''',
    )
    with pytest.raises(DirauthConfigError):
        load_dirauth_config(str(p))


def test_missing_identity_public_key_raises(tmp_path):
    p = _write(
        tmp_path,
        """
        [[dirauths]]
        name = "auth1"
        """,
    )
    with pytest.raises(DirauthConfigError):
        load_dirauth_config(str(p))
