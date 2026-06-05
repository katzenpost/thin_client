import logging
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class PkiCache:
    """A thread-safe, bounded cache of CBOR-encoded PKI documents keyed by
    epoch. Used by both the pkimirror service (to hold what kpclientd has
    delivered) and the client (to hold what the mirror has returned).
    """

    def __init__(
        self,
        max_epochs: int = 5,
        on_new_epoch: Optional[Callable[[int], None]] = None,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_epochs < 1:
            raise ValueError("max_epochs must be at least 1")
        self._max_epochs = max_epochs
        self._on_new_epoch = on_new_epoch
        self._now = time_source
        self._lock = threading.RLock()
        self._store: "OrderedDict[int, bytes]" = OrderedDict()
        self._current_epoch: Optional[int] = None
        self._last_refresh: Optional[float] = None

    def put(self, epoch: int, raw_cbor: bytes) -> None:
        """Insert or update an entry. Always refreshes the freshness clock,
        because even a non-advancing put proves kpclientd is alive. Advances
        _current_epoch only if the epoch is strictly greater; on such an
        advance, fires on_new_epoch outside the lock.
        """
        if not isinstance(epoch, int) or epoch < 0:
            raise ValueError(f"epoch must be a non-negative int, got {epoch!r}")
        if not isinstance(raw_cbor, (bytes, bytearray)):
            raise TypeError("raw_cbor must be bytes")
        advanced = False
        with self._lock:
            self._last_refresh = self._now()
            if epoch in self._store:
                self._store[epoch] = bytes(raw_cbor)
                self._store.move_to_end(epoch)
            else:
                self._store[epoch] = bytes(raw_cbor)
                while len(self._store) > self._max_epochs:
                    self._store.popitem(last=False)
            if self._current_epoch is None or epoch > self._current_epoch:
                self._current_epoch = epoch
                advanced = True
        if advanced and self._on_new_epoch is not None:
            try:
                self._on_new_epoch(epoch)
            except Exception:
                logger.exception("on_new_epoch callback raised; suppressed")

    def get_current(self) -> Optional[bytes]:
        with self._lock:
            if self._current_epoch is None:
                return None
            return self._store.get(self._current_epoch)

    def get_for_epoch(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._store.get(epoch)

    def current_epoch(self) -> Optional[int]:
        with self._lock:
            return self._current_epoch

    def age_seconds(self) -> Optional[float]:
        with self._lock:
            if self._last_refresh is None:
                return None
            return self._now() - self._last_refresh

    def cached_epochs(self) -> list[int]:
        with self._lock:
            return sorted(self._store.keys())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._current_epoch = None
            self._last_refresh = None

    def set_on_new_epoch(self, callback: Optional[Callable[[int], None]]) -> None:
        """Replace the on_new_epoch callback. Useful when the cache is
        created before the announce-loop owner exists.
        """
        self._on_new_epoch = callback
