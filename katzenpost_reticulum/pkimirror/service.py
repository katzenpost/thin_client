from __future__ import annotations

import logging
import os
import threading
from typing import Any, Optional

import cbor2

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.handlers import Handlers

logger = logging.getLogger(__name__)


class PkiMirrorService:
    """Reticulum-side half of pkimirror: owns a Destination, handles
    /pki/current and /pki/epoch requests, runs the announce loop. The
    cache is shared with the ThinClientBridge; this class never writes
    to it.
    """

    def __init__(
        self,
        cache: PkiCache,
        identity_path: str,
        app_name: str,
        aspect: str,
        announce_interval: float,
        stale_after: float,
        reticulum_config: Optional[str] = None,
    ) -> None:
        if not aspect:
            raise ValueError("aspect is required")
        self._cache = cache
        self._identity_path = identity_path
        self._app_name = app_name
        self._aspect = aspect
        self._announce_interval = float(announce_interval)
        self._reticulum_config = reticulum_config
        self._handlers = Handlers(cache=cache, stale_after=stale_after)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._destination: Any = None

    def notify_epoch_advance(self, epoch: int) -> None:
        logger.info(
            "Cache advanced to epoch %d; scheduling out-of-band announce.",
            epoch,
        )
        self._wake.set()

    def run(self) -> None:
        import RNS  # noqa: WPS433
        RNS.Reticulum(self._reticulum_config) if self._reticulum_config else RNS.Reticulum()

        identity = self._load_or_create_identity(RNS)

        self._destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            self._app_name,
            self._aspect,
        )
        self._destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self._destination.set_default_app_data(self._build_app_data)
        self._destination.register_request_handler(
            "/pki/current",
            response_generator=self._rns_handle_current,
            allow=RNS.Destination.ALLOW_ALL,
        )
        self._destination.register_request_handler(
            "/pki/epoch",
            response_generator=self._rns_handle_epoch,
            allow=RNS.Destination.ALLOW_ALL,
        )

        hexhash = RNS.prettyhexrep(self._destination.hash)
        logger.info(
            "pkimirror destination ready at %s (app=%s aspect=%s).",
            hexhash, self._app_name, self._aspect,
        )
        print("pkimirror destination hash: " + hexhash, flush=True)

        self._announce_loop()

    def shutdown(self) -> None:
        logger.info("pkimirror shutdown requested.")
        self._stop.set()
        self._wake.set()

    def _load_or_create_identity(self, RNS: Any) -> Any:
        path = self._identity_path
        if os.path.isfile(path):
            logger.info("Loading existing Reticulum identity from %s.", path)
            return RNS.Identity.from_file(path)

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            identity = RNS.Identity()
            identity.to_file(path)
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        logger.info("Created new Reticulum identity at %s.", path)
        return identity

    def _build_app_data(self) -> bytes:
        epoch = self._cache.current_epoch()
        return cbor2.dumps(
            {
                "v": 1,
                "epoch": epoch if epoch is not None else 0,
                "has_pki": epoch is not None,
            }
        )

    def _rns_handle_current(
        self, path, data, request_id, link_id, remote_identity, requested_at,
    ) -> bytes:
        return self._handlers.handle_current(data or b"")

    def _rns_handle_epoch(
        self, path, data, request_id, link_id, remote_identity, requested_at,
    ) -> bytes:
        return self._handlers.handle_epoch(data or b"")

    def _announce_loop(self) -> None:
        try:
            while not self._stop.is_set():
                self._destination.announce()
                logger.debug("announce emitted.")
                self._wake.clear()
                self._wake.wait(self._announce_interval)
        finally:
            logger.info("pkimirror announce loop exiting.")
