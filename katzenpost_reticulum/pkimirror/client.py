from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Protocol

import cbor2

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.dirauth_config import DirauthConfig
from katzenpost_reticulum.pkimirror.errors import (
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_INTERNAL_ERROR,
    PKIMIRROR_OK,
    PKIMIRROR_PKI_UNAVAILABLE,
    PkiMirrorProtocolError,
    decode_envelope,
)

logger = logging.getLogger(__name__)

_KNOWN_CODES = frozenset(
    {
        PKIMIRROR_OK,
        PKIMIRROR_PKI_UNAVAILABLE,
        PKIMIRROR_EPOCH_NOT_CACHED,
        PKIMIRROR_BAD_REQUEST,
        PKIMIRROR_INTERNAL_ERROR,
    }
)


@dataclass(frozen=True)
class PkiResult:
    code: int
    epoch: Optional[int]
    doc: Optional[bytes]
    msg: Optional[str]
    stale: bool


@dataclass(frozen=True)
class MirrorAnnouncement:
    destination_hash: bytes
    identity: Any  # RNS.Identity at runtime
    epoch: int
    has_pki: bool
    received_at: float


class _Transport(Protocol):
    def request(self, path: str, data: bytes, timeout: float) -> bytes: ...
    def close(self) -> None: ...


class PkiMirrorClient:
    """Synchronous client for a pkimirror service.

    Two ways to construct it:

    - For real use: leave ``transport`` as None. Call :meth:`discover` and
      :meth:`connect`; an RNS-backed transport is built from the connected
      Link.
    - For tests: pass a ``transport`` implementing the small Protocol above.
      No Reticulum initialisation occurs and queries route directly to the
      stub.

    The local :class:`PkiCache` makes :meth:`get_for_epoch` cache-first by
    default; :meth:`get_current` is cache-skipping by default but offers
    ``use_cache=True`` for callers who already accept what they have.
    """

    def __init__(
        self,
        reticulum_config: Optional[str] = None,
        dirauth_config: Optional[DirauthConfig] = None,
        app_name: str = "katzenpost",
        aspect: str = "pkimirror",
        cache_size: int = 5,
        *,
        transport: Optional[_Transport] = None,
        _skip_rns_init: bool = False,
    ) -> None:
        self._app_name = app_name
        self._aspect = aspect
        self._dirauth_config = dirauth_config
        self._cache = PkiCache(max_epochs=cache_size)
        self._transport = transport
        if transport is None and not _skip_rns_init:
            self._init_reticulum(reticulum_config)
        if dirauth_config is not None:
            logger.info(
                "PkiMirrorClient configured with %d dirauth identities "
                "(verification deferred until signed-PKI API arrives); scheme=%r",
                len(dirauth_config.identities),
                dirauth_config.scheme,
            )

    def _init_reticulum(self, config_path: Optional[str]) -> None:
        import RNS  # noqa: WPS433 - lazy import keeps unit tests RNS-free
        try:
            RNS.Reticulum(config_path)
        except OSError as exc:
            if "already running" in str(exc) or "reinitialise" in str(exc):
                logger.debug(
                    "RNS.Reticulum already running in this process; reusing it."
                )
                return
            raise

    def discover(
        self,
        timeout: float = 30.0,
        max_announces: int = 1,
    ) -> List[MirrorAnnouncement]:
        import RNS  # noqa: WPS433
        aspect_filter = f"{self._app_name}.{self._aspect}"
        received: List[MirrorAnnouncement] = []
        done = threading.Event()

        class _AnnounceHandler:
            def __init__(handler_self) -> None:
                handler_self.aspect_filter = aspect_filter

            def received_announce(
                handler_self,
                destination_hash: Any,
                announced_identity: Any,
                app_data: Any,
            ) -> None:
                meta = _decode_announce_app_data(app_data)
                ann = MirrorAnnouncement(
                    destination_hash=bytes(destination_hash),
                    identity=announced_identity,
                    epoch=int(meta.get("epoch", 0)),
                    has_pki=bool(meta.get("has_pki", False)),
                    received_at=time.monotonic(),
                )
                logger.debug(
                    "discover: received announce from %s epoch=%d has_pki=%s",
                    ann.destination_hash.hex(),
                    ann.epoch,
                    ann.has_pki,
                )
                received.append(ann)
                if max_announces and len(received) >= max_announces:
                    done.set()

        handler = _AnnounceHandler()
        RNS.Transport.register_announce_handler(handler)
        try:
            done.wait(timeout)
        finally:
            try:
                RNS.Transport.deregister_announce_handler(handler)
            except Exception:
                logger.exception("could not deregister announce handler")
        logger.info(
            "discover returning %d announce(s) for filter %r",
            len(received), aspect_filter,
        )
        return received

    def connect(self, destination_hash: bytes, timeout: float = 30.0) -> None:
        import RNS  # noqa: WPS433
        if not RNS.Transport.has_path(destination_hash):
            logger.info(
                "no path to %s yet; requesting and waiting up to %.1fs",
                destination_hash.hex(),
                timeout,
            )
            RNS.Transport.request_path(destination_hash)
            deadline = time.monotonic() + timeout
            while not RNS.Transport.has_path(destination_hash):
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"no path to {destination_hash.hex()} after {timeout:.1f}s"
                    )
                time.sleep(0.1)

        server_identity = RNS.Identity.recall(destination_hash)
        if server_identity is None:
            raise RuntimeError(
                f"could not recall identity for {destination_hash.hex()}"
            )

        server_destination = RNS.Destination(
            server_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            self._app_name,
            self._aspect,
        )

        link_ready = threading.Event()
        link_closed = threading.Event()

        def _on_established(_link: Any) -> None:
            link_ready.set()

        def _on_closed(_link: Any) -> None:
            link_closed.set()
            link_ready.set()

        link = RNS.Link(server_destination)
        link.set_link_established_callback(_on_established)
        link.set_link_closed_callback(_on_closed)

        if not link_ready.wait(timeout):
            try:
                link.teardown()
            except Exception:
                logger.exception("teardown failed for un-established link")
            raise TimeoutError(
                f"link to {destination_hash.hex()} not established within {timeout:.1f}s"
            )
        if link_closed.is_set():
            raise RuntimeError("link closed before establishment completed")

        self._transport = _RnsLinkTransport(link)
        logger.info("link established with %s", destination_hash.hex())

    def get_current(
        self,
        timeout: float = 30.0,
        use_cache: bool = False,
    ) -> PkiResult:
        if use_cache:
            cached = self._cache.get_current()
            if cached is not None:
                epoch = self._cache.current_epoch()
                logger.debug("get_current cache hit, epoch=%s", epoch)
                return PkiResult(
                    code=PKIMIRROR_OK,
                    epoch=epoch,
                    doc=cached,
                    msg=None,
                    stale=False,
                )
        result = self._fetch("/pki/current", b"", timeout)
        self._maybe_cache(result)
        return result

    def get_for_epoch(
        self,
        epoch: int,
        timeout: float = 30.0,
        use_cache: bool = True,
    ) -> PkiResult:
        if use_cache:
            cached = self._cache.get_for_epoch(epoch)
            if cached is not None:
                logger.debug("get_for_epoch cache hit, epoch=%d", epoch)
                return PkiResult(
                    code=PKIMIRROR_OK,
                    epoch=epoch,
                    doc=cached,
                    msg=None,
                    stale=False,
                )
        result = self._fetch("/pki/epoch", cbor2.dumps(epoch), timeout)
        self._maybe_cache(result)
        return result

    def _fetch(self, path: str, data: bytes, timeout: float) -> PkiResult:
        if self._transport is None:
            raise RuntimeError(
                "PkiMirrorClient is not connected; call connect() first"
            )
        raw = self._transport.request(path, data, timeout)
        env = decode_envelope(raw)
        code = env["code"]
        if code not in _KNOWN_CODES:
            raise PkiMirrorProtocolError(
                f"server returned unknown response code: {code}"
            )
        return PkiResult(
            code=code,
            epoch=env["epoch"],
            doc=env["doc"],
            msg=env["msg"],
            stale=env["stale"],
        )

    def _maybe_cache(self, result: PkiResult) -> None:
        if (
            result.code == PKIMIRROR_OK
            and result.doc is not None
            and result.epoch is not None
        ):
            self._cache.put(result.epoch, result.doc)

    def cached_epochs(self) -> List[int]:
        return self._cache.cached_epochs()

    def clear_cache(self) -> None:
        self._cache.clear()

    def close(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                logger.exception("error closing pkimirror client transport")
            finally:
                self._transport = None

    def __enter__(self) -> "PkiMirrorClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _decode_announce_app_data(app_data: Any) -> dict:
    if not isinstance(app_data, (bytes, bytearray)) or len(app_data) == 0:
        return {}
    try:
        meta = cbor2.loads(bytes(app_data))
    except Exception:
        logger.debug("announce app_data not CBOR-decodable; ignoring")
        return {}
    if not isinstance(meta, dict):
        return {}
    return meta


class _RnsLinkTransport:
    """Synchronous wrapper around an RNS.Link's request/response. Each call
    blocks the caller's thread until the response, a failure, or the
    timeout, whichever comes first.
    """

    def __init__(self, link: Any) -> None:
        self._link = link
        self._closed = False

    def request(self, path: str, data: bytes, timeout: float) -> bytes:
        done = threading.Event()
        outcome: dict = {"response": None, "error": None}

        def _on_response(receipt: Any) -> None:
            try:
                outcome["response"] = (
                    bytes(receipt.response)
                    if receipt.response is not None
                    else b""
                )
            except Exception as exc:
                outcome["error"] = f"could not read response: {exc}"
            finally:
                done.set()

        def _on_failed(_receipt: Any) -> None:
            outcome["error"] = f"request to {path} failed"
            done.set()

        try:
            self._link.request(
                path,
                data=data,
                response_callback=_on_response,
                failed_callback=_on_failed,
            )
        except Exception as exc:
            raise RuntimeError(f"could not issue request: {exc}") from exc

        if not done.wait(timeout):
            raise TimeoutError(
                f"request to {path} did not complete within {timeout:.1f}s"
            )
        if outcome["error"] is not None:
            raise RuntimeError(outcome["error"])
        return outcome["response"]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._link.teardown()
        except Exception:
            logger.exception("link teardown failed")
