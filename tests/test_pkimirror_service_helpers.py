import inspect

from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.service import PkiMirrorService


def test_rns_handler_signatures_have_six_params():
    """RNS uses inspect.signature(handler).parameters to dispatch; the
    count must be exactly 6 (or 5). Anything else, including *args,
    raises 'Invalid signature for response generator callback' at runtime.
    """
    service = PkiMirrorService(
        cache=PkiCache(),
        identity_path="/dev/null",
        app_name="x",
        aspect="y",
        announce_interval=300.0,
        stale_after=600.0,
    )
    assert len(inspect.signature(service._rns_handle_current).parameters) == 6
    assert len(inspect.signature(service._rns_handle_epoch).parameters) == 6
