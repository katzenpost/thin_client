import logging
import os
import sys
from dataclasses import dataclass, field
from typing import List

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
    pubkey: bytes


@dataclass(frozen=True)
class DirauthConfig:
    scheme: str = ""
    identities: List[DirauthIdentity] = field(default_factory=list)


def load_dirauth_config(path: str) -> DirauthConfig:
    """Load a dirauth identity config from a TOML file.

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

    scheme = data.get("sphincs_warning", "")
    if not isinstance(scheme, str):
        raise DirauthConfigError(
            f"sphincs_warning must be a string, got {type(scheme).__name__}"
        )

    raw_entries = data.get("dirauths", [])
    if not isinstance(raw_entries, list):
        raise DirauthConfigError(
            f"[[dirauths]] must be an array of tables, got {type(raw_entries).__name__}"
        )

    identities: List[DirauthIdentity] = []
    for idx, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise DirauthConfigError(
                f"dirauth entry #{idx} is not a table"
            )
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise DirauthConfigError(
                f"dirauth entry #{idx} is missing a non-empty 'name'"
            )
        identity_hex = entry.get("identity")
        if not isinstance(identity_hex, str) or not identity_hex:
            raise DirauthConfigError(
                f"dirauth '{name}' is missing a non-empty 'identity' hex string"
            )
        try:
            pubkey = bytes.fromhex(identity_hex)
        except ValueError as exc:
            raise DirauthConfigError(
                f"dirauth '{name}' has malformed hex 'identity': {exc}"
            ) from exc
        identities.append(DirauthIdentity(name=name, pubkey=pubkey))

    if not identities:
        logger.warning(
            "Dirauth config at %s contains no [[dirauths]] entries; "
            "signature verification disabled. Scheme declared: %r",
            path,
            scheme,
        )
    else:
        logger.info(
            "Loaded %d dirauth identities from %s; declared scheme: %r",
            len(identities),
            path,
            scheme,
        )

    return DirauthConfig(scheme=scheme, identities=identities)
