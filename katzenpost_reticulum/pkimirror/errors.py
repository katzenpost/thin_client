from typing import Final, Optional

import cbor2

PKIMIRROR_OK: Final[int] = 0
PKIMIRROR_PKI_UNAVAILABLE: Final[int] = 1
PKIMIRROR_EPOCH_NOT_CACHED: Final[int] = 2
PKIMIRROR_BAD_REQUEST: Final[int] = 3
PKIMIRROR_INTERNAL_ERROR: Final[int] = 4


class PkiMirrorProtocolError(Exception):
    """Raised by the client when a server response cannot be decoded as the
    pkimirror envelope schema, or carries an unrecognised code."""


_ENVELOPE_KEYS = ("code", "epoch", "doc", "msg", "stale")


def encode_envelope(
    code: int,
    *,
    epoch: Optional[int] = None,
    doc: Optional[bytes] = None,
    msg: Optional[str] = None,
    stale: bool = False,
) -> bytes:
    if code == PKIMIRROR_OK and doc is None:
        raise ValueError("PKIMIRROR_OK envelopes must carry a non-None doc")
    if code != PKIMIRROR_OK and doc is not None:
        raise ValueError("error envelopes must not carry a doc")
    return cbor2.dumps(
        {
            "code": code,
            "epoch": epoch,
            "doc": doc,
            "msg": msg,
            "stale": bool(stale),
        }
    )


def decode_envelope(blob: bytes) -> dict:
    try:
        obj = cbor2.loads(blob)
    except Exception as exc:
        raise PkiMirrorProtocolError(f"envelope is not valid CBOR: {exc}") from exc
    if not isinstance(obj, dict):
        raise PkiMirrorProtocolError("envelope is not a CBOR map")
    missing = [k for k in _ENVELOPE_KEYS if k not in obj]
    if missing:
        raise PkiMirrorProtocolError(f"envelope missing required keys: {missing}")
    if not isinstance(obj["code"], int):
        raise PkiMirrorProtocolError("envelope 'code' is not an integer")
    if not isinstance(obj["stale"], bool):
        raise PkiMirrorProtocolError("envelope 'stale' is not a boolean")
    return obj
