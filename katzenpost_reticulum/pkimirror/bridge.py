from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from typing import Optional

from katzenpost_thinclient import Config, ThinClient

from katzenpost_reticulum.pkimirror.cache import PkiCache

logger = logging.getLogger(__name__)


class ThinClientBridge:
    """Owns a ThinClient on a dedicated asyncio thread; populates a PkiCache
    with raw CBOR PKI documents as the daemon delivers them. The cache is
    thread-safe so Reticulum's request handlers may read concurrently.
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
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_future: Optional[asyncio.Future] = None
        self._client: Optional[ThinClient] = None
        self._ready: "concurrent.futures.Future[None]" = concurrent.futures.Future()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("ThinClientBridge already started")
        logger.info(
            "ThinClientBridge starting; thinclient config at %s", self._cfg_path,
        )
        self._thread = threading.Thread(
            target=self._run, name="pkimirror-thinclient", daemon=True,
        )
        self._thread.start()
        try:
            self._ready.result(timeout=self._ready_timeout)
        except concurrent.futures.TimeoutError:
            self.stop()
            raise TimeoutError(
                f"thin client did not deliver an initial PKI document within "
                f"{self._ready_timeout}s"
            )
        logger.info("ThinClientBridge ready: first PKI document cached")

    def stop(self, timeout: float = 10.0) -> None:
        loop, fut = self._loop, self._stop_future
        if loop is not None and fut is not None and not fut.done():
            loop.call_soon_threadsafe(fut.set_result, None)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(
                    "thin-client thread did not exit within %.1fs", timeout,
                )
            self._thread = None

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._main())
        except BaseException as exc:
            if not self._ready.done():
                self._ready.set_exception(exc)
            else:
                logger.exception("thin-client thread terminated after start")
        finally:
            loop.close()
            self._loop = None

    async def _main(self) -> None:
        loop = asyncio.get_running_loop()
        self._stop_future = loop.create_future()
        cfg = Config(self._cfg_path, on_new_pki_document=self._on_pki)
        self._client = ThinClient(cfg)
        await self._client.start(loop)
        self._ready.set_result(None)
        try:
            await self._stop_future
        finally:
            self._client.stop()
            self._client = None

    async def _on_pki(self, event: dict) -> None:
        raw = event.get("payload")
        if not isinstance(raw, (bytes, bytearray)) or self._client is None:
            return
        parsed = self._client.pki_document()
        if not isinstance(parsed, dict):
            return
        epoch = parsed.get("Epoch")
        if not isinstance(epoch, int):
            return
        self._cache.put(epoch, bytes(raw))
        logger.info(
            "Cached PKI document for epoch %d (%d bytes).", epoch, len(raw),
        )
