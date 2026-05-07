import logging
from typing import Any, Optional, Protocol

import cbor2

from katzenpost_reticulum.pkimirror.errors import (
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_INTERNAL_ERROR,
    PKIMIRROR_OK,
    PKIMIRROR_PKI_UNAVAILABLE,
    encode_envelope,
)

logger = logging.getLogger(__name__)


class _CacheLike(Protocol):
    def get_current(self) -> Optional[bytes]: ...
    def get_for_epoch(self, epoch: int) -> Optional[bytes]: ...
    def current_epoch(self) -> Optional[int]: ...
    def age_seconds(self) -> Optional[float]: ...


class Handlers:
    """Pure request-handling logic for the pkimirror service. Independent of
    Reticulum so it can be unit-tested without RNS installed.

    The Reticulum side calls handle_current and handle_epoch with the data
    received from a client, and forwards the bytes returned by these methods
    as the link response.
    """

    def __init__(self, cache: _CacheLike, stale_after: float) -> None:
        self._cache = cache
        self._stale_after = float(stale_after)

    def handle_current(self, _data: bytes) -> bytes:
        try:
            raw = self._cache.get_current()
            if raw is None:
                logger.debug("handle_current: cache empty")
                return encode_envelope(
                    PKIMIRROR_PKI_UNAVAILABLE,
                    msg="no PKI document yet received from kpclientd",
                )
            epoch = self._cache.current_epoch()
            stale = self._is_stale()
            logger.debug(
                "handle_current: serving epoch=%s stale=%s bytes=%d",
                epoch, stale, len(raw),
            )
            return encode_envelope(
                PKIMIRROR_OK, epoch=epoch, doc=raw, stale=stale,
            )
        except Exception as exc:
            logger.exception("handle_current: unexpected exception")
            return encode_envelope(
                PKIMIRROR_INTERNAL_ERROR,
                msg=f"internal error: {exc}",
            )

    def handle_epoch(self, data: bytes) -> bytes:
        try:
            epoch = self._parse_epoch(data)
        except _BadRequest as bad:
            logger.debug("handle_epoch: bad request: %s", bad)
            return encode_envelope(PKIMIRROR_BAD_REQUEST, msg=str(bad))

        try:
            raw = self._cache.get_for_epoch(epoch)
            if raw is None:
                current = self._cache.current_epoch()
                logger.debug(
                    "handle_epoch: epoch=%d not cached (current=%s)",
                    epoch, current,
                )
                return encode_envelope(
                    PKIMIRROR_EPOCH_NOT_CACHED,
                    epoch=current,
                    msg=f"epoch {epoch} not in cache",
                )
            stale = self._is_stale()
            logger.debug(
                "handle_epoch: serving epoch=%d stale=%s bytes=%d",
                epoch, stale, len(raw),
            )
            return encode_envelope(
                PKIMIRROR_OK, epoch=epoch, doc=raw, stale=stale,
            )
        except Exception as exc:
            logger.exception("handle_epoch: unexpected exception")
            return encode_envelope(
                PKIMIRROR_INTERNAL_ERROR,
                msg=f"internal error: {exc}",
            )

    def _parse_epoch(self, data: bytes) -> int:
        if not data:
            raise _BadRequest("request body is empty")
        try:
            value: Any = cbor2.loads(data)
        except Exception as exc:
            raise _BadRequest(f"request body is not CBOR: {exc}") from exc
        if not isinstance(value, int) or isinstance(value, bool):
            raise _BadRequest("request body must be a non-negative integer epoch")
        if value < 0:
            raise _BadRequest("request body must be a non-negative integer epoch")
        return value

    def _is_stale(self) -> bool:
        age = self._cache.age_seconds()
        return age is not None and age > self._stale_after


class _BadRequest(Exception):
    """Internal sentinel for a malformed epoch request."""
