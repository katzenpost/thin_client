import cbor2
import pytest

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.errors import (
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_INTERNAL_ERROR,
    PKIMIRROR_OK,
    PKIMIRROR_PKI_UNAVAILABLE,
    decode_envelope,
)
from katzenpost_reticulum.pkimirror.handlers import Handlers


def _make_handlers(cache: PkiCache, stale_after: float = 600.0) -> Handlers:
    return Handlers(cache=cache, stale_after=stale_after)


def test_handle_current_pki_unavailable():
    h = _make_handlers(PkiCache())
    out = decode_envelope(h.handle_current(b""))
    assert out["code"] == PKIMIRROR_PKI_UNAVAILABLE
    assert out["doc"] is None
    assert out["epoch"] is None
    assert out["msg"]


def test_handle_current_returns_doc():
    cache = PkiCache()
    cache.put(42, b"\xa1\x65Epoch\x18\x2a")
    out = decode_envelope(_make_handlers(cache).handle_current(b""))
    assert out["code"] == PKIMIRROR_OK
    assert out["epoch"] == 42
    assert out["doc"] == b"\xa1\x65Epoch\x18\x2a"
    assert out["stale"] is False


def test_handle_current_marks_stale_when_age_exceeds_threshold():
    fake_now = [1000.0]
    cache = PkiCache(time_source=lambda: fake_now[0])
    cache.put(7, b"seven")
    fake_now[0] = 2000.0
    h = _make_handlers(cache, stale_after=10.0)
    out = decode_envelope(h.handle_current(b""))
    assert out["code"] == PKIMIRROR_OK
    assert out["doc"] == b"seven"
    assert out["stale"] is True


def test_handle_epoch_returns_cached():
    cache = PkiCache()
    cache.put(10, b"ten")
    cache.put(11, b"eleven")
    out = decode_envelope(_make_handlers(cache).handle_epoch(cbor2.dumps(10)))
    assert out["code"] == PKIMIRROR_OK
    assert out["epoch"] == 10
    assert out["doc"] == b"ten"


def test_handle_epoch_not_cached_returns_current_epoch():
    cache = PkiCache()
    cache.put(11, b"eleven")
    out = decode_envelope(_make_handlers(cache).handle_epoch(cbor2.dumps(7)))
    assert out["code"] == PKIMIRROR_EPOCH_NOT_CACHED
    assert out["epoch"] == 11
    assert out["doc"] is None


def test_handle_epoch_bad_request_non_cbor():
    cache = PkiCache()
    cache.put(1, b"one")
    out = decode_envelope(_make_handlers(cache).handle_epoch(b"\xff\xff\xff not cbor"))
    assert out["code"] == PKIMIRROR_BAD_REQUEST
    assert out["doc"] is None
    assert out["epoch"] is None


def test_handle_epoch_bad_request_non_int():
    cache = PkiCache()
    cache.put(1, b"one")
    out = decode_envelope(_make_handlers(cache).handle_epoch(cbor2.dumps("five")))
    assert out["code"] == PKIMIRROR_BAD_REQUEST


def test_handle_epoch_bad_request_negative():
    cache = PkiCache()
    cache.put(1, b"one")
    out = decode_envelope(_make_handlers(cache).handle_epoch(cbor2.dumps(-1)))
    assert out["code"] == PKIMIRROR_BAD_REQUEST


def test_handle_epoch_bad_request_empty_body():
    cache = PkiCache()
    cache.put(1, b"one")
    out = decode_envelope(_make_handlers(cache).handle_epoch(b""))
    assert out["code"] == PKIMIRROR_BAD_REQUEST


def test_handle_internal_error_caught():
    class _Boom:
        def get_current(self):
            raise RuntimeError("kaboom")

        def current_epoch(self):
            raise RuntimeError("kaboom")

        def get_for_epoch(self, _epoch):
            raise RuntimeError("kaboom")

        def age_seconds(self):
            return None

    h = Handlers(cache=_Boom(), stale_after=600.0)
    out = decode_envelope(h.handle_current(b""))
    assert out["code"] == PKIMIRROR_INTERNAL_ERROR
    assert out["doc"] is None
    assert "kaboom" in (out["msg"] or "")
