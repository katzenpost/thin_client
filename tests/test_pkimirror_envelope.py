import cbor2
import pytest

from katzenpost_reticulum.pkimirror.errors import (
    PKIMIRROR_BAD_REQUEST,
    PKIMIRROR_EPOCH_NOT_CACHED,
    PKIMIRROR_INTERNAL_ERROR,
    PKIMIRROR_OK,
    PKIMIRROR_PKI_UNAVAILABLE,
    PkiMirrorProtocolError,
    encode_envelope,
)


def _decode(blob: bytes) -> dict:
    obj = cbor2.loads(blob)
    assert isinstance(obj, dict)
    return obj


def test_codes_are_distinct_integers():
    codes = {
        PKIMIRROR_OK,
        PKIMIRROR_PKI_UNAVAILABLE,
        PKIMIRROR_EPOCH_NOT_CACHED,
        PKIMIRROR_BAD_REQUEST,
        PKIMIRROR_INTERNAL_ERROR,
    }
    assert len(codes) == 5
    for c in codes:
        assert isinstance(c, int)
    assert PKIMIRROR_OK == 0


def test_envelope_success_round_trip():
    doc = b"\xa1\x65Epoch\x18\x2a"  # CBOR for {"Epoch": 42}
    blob = encode_envelope(PKIMIRROR_OK, epoch=42, doc=doc, stale=False)
    out = _decode(blob)
    assert out["code"] == PKIMIRROR_OK
    assert out["epoch"] == 42
    assert out["doc"] == doc
    assert out["stale"] is False
    assert out["msg"] is None


def test_envelope_success_stale_flag_round_trips():
    blob = encode_envelope(PKIMIRROR_OK, epoch=7, doc=b"\xa0", stale=True)
    out = _decode(blob)
    assert out["code"] == PKIMIRROR_OK
    assert out["stale"] is True


def test_envelope_error_doc_is_none_and_msg_is_set():
    blob = encode_envelope(PKIMIRROR_PKI_UNAVAILABLE, msg="no PKI yet")
    out = _decode(blob)
    assert out["code"] == PKIMIRROR_PKI_UNAVAILABLE
    assert out["doc"] is None
    assert out["msg"] == "no PKI yet"
    assert out["stale"] is False
    assert out["epoch"] is None


def test_envelope_epoch_not_cached_carries_current_epoch():
    blob = encode_envelope(
        PKIMIRROR_EPOCH_NOT_CACHED,
        epoch=99,
        msg="epoch 1 not in cache",
    )
    out = _decode(blob)
    assert out["code"] == PKIMIRROR_EPOCH_NOT_CACHED
    assert out["epoch"] == 99
    assert out["doc"] is None


def test_envelope_keys_are_always_present():
    """Schema rigidity: every envelope carries every key, even when None."""
    for blob in [
        encode_envelope(PKIMIRROR_OK, epoch=1, doc=b"\xa0"),
        encode_envelope(PKIMIRROR_BAD_REQUEST, msg="bad"),
        encode_envelope(PKIMIRROR_INTERNAL_ERROR, msg="oops"),
    ]:
        out = _decode(blob)
        assert set(out.keys()) == {"code", "epoch", "doc", "msg", "stale"}


def test_envelope_rejects_doc_without_ok():
    with pytest.raises(ValueError):
        encode_envelope(PKIMIRROR_BAD_REQUEST, doc=b"\xa0", msg="bad")


def test_envelope_rejects_ok_without_doc():
    with pytest.raises(ValueError):
        encode_envelope(PKIMIRROR_OK, epoch=1, doc=None)


def test_protocol_error_is_exception():
    assert issubclass(PkiMirrorProtocolError, Exception)
    e = PkiMirrorProtocolError("malformed envelope")
    assert "malformed" in str(e)
