import logging
from typing import Optional, Protocol

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
    """Pure request-handling logic, independent of Reticulum so it can
    be unit-tested without RNS installed.
    """

    def __init__(self, cache: _CacheLike, stale_after: float) -> None:
        self._cache = cache
        self._stale_after = float(stale_after)

    def handle_current(self, _data: bytes) -> bytes:
        try:
            raw = self._cache.get_current()
            if raw is None:
                return encode_envelope(
                    PKIMIRROR_PKI_UNAVAILABLE,
                    msg="no PKI document yet received from kpclientd",
                )
            return encode_envelope(
                PKIMIRROR_OK,
                epoch=self._cache.current_epoch(),
                doc=raw,
                stale=self._is_stale(),
            )
        except Exception as exc:
            logger.exception("handle_current: unexpected exception")
            return encode_envelope(
                PKIMIRROR_INTERNAL_ERROR, msg=f"internal error: {exc}"
            )

    def handle_epoch(self, data: bytes) -> bytes:
        try:
            if not data:
                return encode_envelope(
                    PKIMIRROR_BAD_REQUEST, msg="request body is empty"
                )
            try:
                epoch = cbor2.loads(data)
            except Exception as exc:
                return encode_envelope(
                    PKIMIRROR_BAD_REQUEST,
                    msg=f"request body is not CBOR: {exc}",
                )
            if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
                return encode_envelope(
                    PKIMIRROR_BAD_REQUEST,
                    msg="request body must be a non-negative integer epoch",
                )
            raw = self._cache.get_for_epoch(epoch)
            if raw is None:
                return encode_envelope(
                    PKIMIRROR_EPOCH_NOT_CACHED,
                    epoch=self._cache.current_epoch(),
                    msg=f"epoch {epoch} not in cache",
                )
            return encode_envelope(
                PKIMIRROR_OK, epoch=epoch, doc=raw, stale=self._is_stale(),
            )
        except Exception as exc:
            logger.exception("handle_epoch: unexpected exception")
            return encode_envelope(
                PKIMIRROR_INTERNAL_ERROR, msg=f"internal error: {exc}"
            )

    def _is_stale(self) -> bool:
        age = self._cache.age_seconds()
        return age is not None and age > self._stale_after
