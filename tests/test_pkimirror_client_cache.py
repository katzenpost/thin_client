import cbor2
import pytest

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.client import PkiMirrorClient, PkiResult
from katzenpost_reticulum.pkimirror.errors import (
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_OK,
    PkiMirrorProtocolError,
    encode_envelope,
)


class StubTransport:
    """Records every request and returns pre-loaded responses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []
        self._responses: dict[str, list[bytes]] = {}
        self.closed = False

    def queue(self, path: str, response: bytes) -> None:
        self._responses.setdefault(path, []).append(response)

    def request(self, path: str, data: bytes, timeout: float) -> bytes:
        self.calls.append((path, data))
        if not self._responses.get(path):
            raise AssertionError(f"no canned response queued for {path}")
        return self._responses[path].pop(0)

    def close(self) -> None:
        self.closed = True


def _make_client(transport: StubTransport) -> PkiMirrorClient:
    return PkiMirrorClient(transport=transport, _skip_rns_init=True)


def test_get_for_epoch_cache_hit_skips_network():
    transport = StubTransport()
    client = _make_client(transport)
    client._cache.put(42, b"\xa1\x65Epoch\x18\x2a")

    result = client.get_for_epoch(42)

    assert isinstance(result, PkiResult)
    assert result.code == PKIMIRROR_OK
    assert result.epoch == 42
    assert result.doc == b"\xa1\x65Epoch\x18\x2a"
    assert result.stale is False
    assert transport.calls == []


def test_get_for_epoch_cache_miss_fetches_then_caches():
    transport = StubTransport()
    transport.queue(
        "/pki/epoch",
        encode_envelope(PKIMIRROR_OK, epoch=7, doc=b"seven"),
    )
    client = _make_client(transport)

    result = client.get_for_epoch(7)
    assert result.code == PKIMIRROR_OK
    assert result.doc == b"seven"
    assert transport.calls == [("/pki/epoch", cbor2.dumps(7))]

    # Second call should not touch the network.
    result2 = client.get_for_epoch(7)
    assert result2.doc == b"seven"
    assert len(transport.calls) == 1


def test_get_for_epoch_use_cache_false_forces_fetch():
    transport = StubTransport()
    transport.queue(
        "/pki/epoch",
        encode_envelope(PKIMIRROR_OK, epoch=7, doc=b"seven-fresh"),
    )
    client = _make_client(transport)
    client._cache.put(7, b"seven-stale")

    result = client.get_for_epoch(7, use_cache=False)
    assert result.doc == b"seven-fresh"
    assert len(transport.calls) == 1
    # The fresh result should have replaced the cache entry.
    assert client._cache.get_for_epoch(7) == b"seven-fresh"


def test_get_for_epoch_error_response_not_cached():
    transport = StubTransport()
    transport.queue(
        "/pki/epoch",
        encode_envelope(
            PKIMIRROR_EPOCH_NOT_CACHED, epoch=99, msg="epoch 7 not in cache"
        ),
    )
    client = _make_client(transport)

    result = client.get_for_epoch(7)
    assert result.code == PKIMIRROR_EPOCH_NOT_CACHED
    assert result.epoch == 99
    assert result.doc is None
    assert client._cache.cached_epochs() == []


def test_get_current_skips_cache_by_default():
    transport = StubTransport()
    transport.queue(
        "/pki/current",
        encode_envelope(PKIMIRROR_OK, epoch=10, doc=b"latest"),
    )
    client = _make_client(transport)
    client._cache.put(9, b"older")

    result = client.get_current()
    assert result.epoch == 10
    assert result.doc == b"latest"
    assert transport.calls == [("/pki/current", b"")]
    # The fetched doc lands in the cache.
    assert client._cache.get_for_epoch(10) == b"latest"


def test_get_current_use_cache_returns_cached_when_present():
    transport = StubTransport()
    client = _make_client(transport)
    client._cache.put(11, b"cached")

    result = client.get_current(use_cache=True)
    assert result.code == PKIMIRROR_OK
    assert result.epoch == 11
    assert result.doc == b"cached"
    assert transport.calls == []


def test_get_current_use_cache_falls_through_when_empty():
    transport = StubTransport()
    transport.queue(
        "/pki/current",
        encode_envelope(PKIMIRROR_OK, epoch=1, doc=b"one"),
    )
    client = _make_client(transport)

    result = client.get_current(use_cache=True)
    assert result.doc == b"one"
    assert len(transport.calls) == 1


def test_clear_cache_empties_local_store():
    client = _make_client(StubTransport())
    client._cache.put(1, b"one")
    client._cache.put(2, b"two")
    assert client.cached_epochs() == [1, 2]

    client.clear_cache()
    assert client.cached_epochs() == []


def test_protocol_error_on_malformed_response():
    transport = StubTransport()
    transport.queue("/pki/current", b"\xff\xff not cbor")
    client = _make_client(transport)
    with pytest.raises(PkiMirrorProtocolError):
        client.get_current()


def test_protocol_error_on_unknown_code():
    transport = StubTransport()
    bad = encode_envelope(PKIMIRROR_OK, epoch=1, doc=b"x")
    bad_dict = cbor2.loads(bad)
    bad_dict["code"] = 999
    transport.queue("/pki/current", cbor2.dumps(bad_dict))
    client = _make_client(transport)
    with pytest.raises(PkiMirrorProtocolError):
        client.get_current()


def test_close_propagates_to_transport():
    transport = StubTransport()
    client = _make_client(transport)
    client.close()
    assert transport.closed is True
