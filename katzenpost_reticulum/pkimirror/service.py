from __future__ import annotations

import logging
import os
import threading
from typing import Any, Optional, Tuple

import cbor2

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.handlers import Handlers

logger = logging.getLogger(__name__)


class PkiMirrorService:
    """The Reticulum-side half of pkimirror.

    Owns a Reticulum Destination, handles incoming /pki/current and
    /pki/epoch requests, and runs an announce loop that emits both periodic
    and epoch-triggered announces. The cache is shared with the
    ThinClientBridge; this class never writes to it.
    """

    def __init__(
        self,
        cache: PkiCache,
        identity_path: str,
        app_name: str,
        aspects: Tuple[str, ...],
        announce_interval: float,
        stale_after: float,
        reticulum_config: Optional[str] = None,
    ) -> None:
        if not aspects:
            raise ValueError("at least one aspect is required")
        self._cache = cache
        self._identity_path = identity_path
        self._app_name = app_name
        self._aspects = tuple(aspects)
        self._announce_interval = float(announce_interval)
        self._stale_after = float(stale_after)
        self._reticulum_config = reticulum_config
        self._handlers = Handlers(cache=cache, stale_after=stale_after)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._destination: Any = None

    def notify_epoch_advance(self, epoch: int) -> None:
        """Called from the bridge thread when the cache advances. Sets the
        wake flag so the announce loop emits an out-of-band announce.
        """
        logger.info(
            "Cache advanced to epoch %d; scheduling out-of-band announce.",
            epoch,
        )
        self._wake.set()

    def run(self) -> None:
        import RNS  # noqa: WPS433
        if self._reticulum_config:
            RNS.Reticulum(self._reticulum_config)
        else:
            RNS.Reticulum()

        identity = self._load_or_create_identity(RNS)

        self._destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            self._app_name,
            *self._aspects,
        )
        self._destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self._destination.set_default_app_data(self._build_app_data)
        self._destination.set_link_established_callback(self._on_link_established)

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

        logger.info(
            "pkimirror destination ready at %s (app=%s aspects=%s).",
            RNS.prettyhexrep(self._destination.hash),
            self._app_name,
            ".".join(self._aspects),
        )
        print(
            "pkimirror destination hash: "
            + RNS.prettyhexrep(self._destination.hash),
            flush=True,
        )

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

        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            identity = RNS.Identity()
            identity.to_file(path)
        finally:
            os.umask(old_umask)
        try:
            os.chmod(path, 0o600)
        except OSError:
            logger.warning("Could not chmod 0600 on %s.", path)
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

    def _on_link_established(self, link: Any) -> None:
        try:
            link_id = link.link_id.hex() if hasattr(link, "link_id") else "?"
        except Exception:
            link_id = "?"
        logger.info("Reticulum link established (id=%s).", link_id)

        def _on_closed(_link: Any) -> None:
            logger.info("Reticulum link closed (id=%s).", link_id)

        try:
            link.set_link_closed_callback(_on_closed)
        except Exception:
            logger.exception("could not set link_closed_callback")

    def _rns_handle_current(
        self,
        path: Any,
        data: Any,
        request_id: Any,
        link_id: Any,
        remote_identity: Any,
        requested_at: Any,
    ) -> bytes:
        return self._handlers.handle_current(_coerce_data(data))

    def _rns_handle_epoch(
        self,
        path: Any,
        data: Any,
        request_id: Any,
        link_id: Any,
        remote_identity: Any,
        requested_at: Any,
    ) -> bytes:
        return self._handlers.handle_epoch(_coerce_data(data))

    def _announce_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    self._destination.announce()
                    logger.debug("announce emitted.")
                except Exception:
                    logger.exception("announce failed; continuing.")
                self._wake.clear()
                self._wake.wait(self._announce_interval)
        finally:
            logger.info("pkimirror announce loop exiting.")


def _coerce_data(data: Any) -> bytes:
    """Normalise the request body that RNS hands to a response_generator
    into bytes. RNS may pass None for an empty body; some test paths or
    future versions may pass a string.
    """
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode()
    return bytes(data)


def _extract_data(args: Tuple[Any, ...], kwargs: dict) -> bytes:
    """Back-compat shim retained for the existing unit tests.

    Reticulum's response_generator signature is exact and validated by
    inspect.signature; the service-side handlers therefore declare it
    explicitly. This helper remains for tests that exercise the
    coercion/argument-extraction logic in isolation.
    """
    if "data" in kwargs:
        data = kwargs["data"]
    elif len(args) >= 2:
        data = args[1]
    else:
        data = None
    return _coerce_data(data)
