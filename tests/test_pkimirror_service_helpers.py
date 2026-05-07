import inspect

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.service import (
    PkiMirrorService,
    _extract_data,
)


def test_extract_data_positional_full_signature():
    out = _extract_data(
        ("/pki/epoch", b"body", "rid", "lid", "ri", 1.0), {}
    )
    assert out == b"body"


def test_extract_data_keyword():
    out = _extract_data((), {"path": "/pki/epoch", "data": b"body"})
    assert out == b"body"


def test_extract_data_none_becomes_empty_bytes():
    assert _extract_data(("/p", None), {}) == b""
    assert _extract_data((), {"data": None}) == b""


def test_extract_data_str_encoded_to_bytes():
    out = _extract_data(("/p", "hello"), {})
    assert out == b"hello"


def test_extract_data_missing_returns_empty_bytes():
    assert _extract_data((), {}) == b""
    assert _extract_data(("/p",), {}) == b""


def test_rns_handler_signatures_have_six_params():
    """RNS uses inspect.signature(handler).parameters; the count must be
    exactly 6 (or 5) to dispatch. Anything else, including *args, will
    raise 'Invalid signature for response generator callback' at runtime.
    """
    service = PkiMirrorService(
        cache=PkiCache(),
        identity_path="/dev/null",
        app_name="x",
        aspects=("y",),
        announce_interval=300.0,
        stale_after=600.0,
    )
    assert (
        len(inspect.signature(service._rns_handle_current).parameters) == 6
    )
    assert (
        len(inspect.signature(service._rns_handle_epoch).parameters) == 6
    )
