import base64
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


class DirauthConfigError(Exception):
    """Raised when a dirauth config file cannot be parsed or contains
    structurally invalid entries."""


@dataclass(frozen=True)
class DirauthIdentity:
    name: str
    scheme: str  # PEM label, e.g. "ED25519" or "FALCON-PADDED-512-ED25519"
    pubkey: bytes


@dataclass(frozen=True)
class DirauthConfig:
    identities: List[DirauthIdentity] = field(default_factory=list)


_PEM_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 \-+]+?) PUBLIC KEY-----"
    r"\s*(.+?)\s*"
    r"-----END \1 PUBLIC KEY-----",
    re.DOTALL,
)


def _parse_pem_public_key(text: str) -> Tuple[str, bytes]:
    """Extract the scheme label and raw public-key bytes from a PEM block.

    Accepts the katzenpost-style "BEGIN <SCHEME> PUBLIC KEY" preamble where
    <SCHEME> is a free-form label such as ED25519 or
    FALCON-PADDED-512-ED25519.
    """
    if not isinstance(text, str):
        raise ValueError("PEM input must be a string")
    match = _PEM_RE.search(text)
    if not match:
        raise ValueError("no PEM PUBLIC KEY block found")
    label = match.group(1).strip()
    body = "".join(match.group(2).split())
    try:
        pubkey = base64.b64decode(body, validate=True)
    except Exception as exc:
        raise ValueError(f"PEM body is not valid base64: {exc}") from exc
    if not pubkey:
        raise ValueError("PEM body decoded to zero bytes")
    return label, pubkey


def load_dirauth_config(path: str) -> DirauthConfig:
    """Load a dirauth identity config from a TOML file.

    Each [[dirauths]] entry carries a `name` and an `identity_public_key`
    holding a PEM-encoded public key whose label names the signature
    scheme (matching katzenpost's authority.toml format).

    A missing file is treated as an empty config (warned, not raised), so
    operators may run pkimirror in a discovery-only mode while collecting
    keys for later. Malformed entries raise DirauthConfigError so that
    typos cannot silently disable verification.
    """
    if not os.path.isfile(path):
        logger.warning(
            "Dirauth config file not present at %s; "
            "no signing identities loaded, signature verification disabled.",
            path,
        )
        return DirauthConfig()

    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise DirauthConfigError(
                f"dirauth config at {path} is not valid TOML: {exc}"
            ) from exc

    raw_entries = data.get("dirauths", [])
    if not isinstance(raw_entries, list):
        raise DirauthConfigError(
            f"[[dirauths]] must be an array of tables, got {type(raw_entries).__name__}"
        )

    identities: List[DirauthIdentity] = []
    for idx, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise DirauthConfigError(f"dirauth entry #{idx} is not a table")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise DirauthConfigError(
                f"dirauth entry #{idx} is missing a non-empty 'name'"
            )
        pem = entry.get("identity_public_key")
        if not isinstance(pem, str) or not pem:
            raise DirauthConfigError(
                f"dirauth '{name}' is missing a non-empty "
                f"'identity_public_key' PEM block"
            )
        try:
            scheme, pubkey = _parse_pem_public_key(pem)
        except ValueError as exc:
            raise DirauthConfigError(
                f"dirauth '{name}' has malformed identity_public_key: {exc}"
            ) from exc
        identities.append(DirauthIdentity(name=name, scheme=scheme, pubkey=pubkey))

    if not identities:
        logger.warning(
            "Dirauth config at %s contains no [[dirauths]] entries; "
            "signature verification disabled.",
            path,
        )
    else:
        schemes = sorted({idn.scheme for idn in identities})
        logger.info(
            "Loaded %d dirauth identities from %s; schemes: %s",
            len(identities),
            path,
            ", ".join(schemes),
        )

    return DirauthConfig(identities=identities)
