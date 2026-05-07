from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

from katzenpost_thinclient import Config, ThinClient

from katzenpost_reticulum.pkimirror.cache import PkiCache

logger = logging.getLogger(__name__)


class ThinClientBridge:
    """Owns a ThinClient on a dedicated asyncio thread; populates a PkiCache
    with raw CBOR PKI documents as the daemon delivers them.

    The asyncio loop runs in the spawned thread, not the caller's. Cache
    writes happen on the asyncio thread; the cache itself is thread-safe so
    Reticulum's request handlers may read concurrently.
    """

    def __init__(
        self,
        thinclient_config_path: str,
        cache: PkiCache,
        ready_timeout: float = 30.0,
    ) -> None:
        self._cfg_path = thinclient_config_path
        self._cache = cache
        self._ready_timeout = ready_timeout
        self._ready = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_future: Optional[asyncio.Future] = None
        self._client: Optional[ThinClient] = None
        self._start_error: Optional[BaseException] = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("ThinClientBridge already started")
        logger.info("ThinClientBridge starting; thinclient config at %s", self._cfg_path)
        self._thread = threading.Thread(
            target=self._run, name="pkimirror-thinclient", daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(self._ready_timeout):
            self.stop()
            raise TimeoutError(
                f"thin client did not deliver an initial PKI document within "
                f"{self._ready_timeout}s"
            )
        if self._start_error is not None:
            err = self._start_error
            self._start_error = None
            raise err
        logger.info("ThinClientBridge ready: first PKI document cached")

    def stop(self, timeout: float = 10.0) -> None:
        loop = self._loop
        fut = self._stop_future
        if loop is not None and fut is not None and not fut.done():
            try:
                loop.call_soon_threadsafe(fut.set_result, None)
            except RuntimeError:
                logger.debug("stop: loop already closed")
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(
                    "thin-client thread did not exit within %.1fs", timeout
                )
            self._thread = None

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._main())
        except BaseException as exc:
            self._start_error = exc
            logger.exception("thin-client thread terminated with an exception")
            self._ready.set()
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                logger.exception("error draining async generators")
            loop.close()
            self._loop = None

    async def _main(self) -> None:
        loop = asyncio.get_running_loop()
        self._stop_future = loop.create_future()
        cfg = Config(self._cfg_path, on_new_pki_document=self._on_pki)
        self._client = ThinClient(cfg)
        try:
            await self._client.start(loop)
        except BaseException:
            self._ready.set()
            raise
        self._ready.set()
        try:
            await self._stop_future
        finally:
            try:
                self._client.stop()
            except Exception:
                logger.exception("error stopping thin client")
            self._client = None

    async def _on_pki(self, event: dict) -> None:
        try:
            raw = event.get("payload")
            if not isinstance(raw, (bytes, bytearray)):
                logger.warning(
                    "PKI event without bytes payload; ignoring (type=%s)",
                    type(raw).__name__,
                )
                return
            client = self._client
            if client is None:
                logger.warning("PKI event delivered before client was attached; ignoring")
                return
            parsed = client.pki_document()
            if not isinstance(parsed, dict):
                logger.warning(
                    "PKI document not a dict (type=%s); ignoring",
                    type(parsed).__name__,
                )
                return
            epoch = parsed.get("Epoch")
            if not isinstance(epoch, int):
                logger.warning("PKI document has no integer Epoch; ignoring")
                return
            self._cache.put(epoch, bytes(raw))
            logger.info(
                "Cached PKI document for epoch %d (%d bytes).", epoch, len(raw)
            )
        except Exception:
            logger.exception("error in _on_pki callback")
