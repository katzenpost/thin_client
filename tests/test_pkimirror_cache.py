import threading
import time

import pytest

from katzenpost_reticulum.pkimirror.cache import PkiCache


def test_empty_cache_returns_none():
    c = PkiCache()
    assert c.get_current() is None
    assert c.get_for_epoch(1) is None
    assert c.current_epoch() is None
    assert c.age_seconds() is None
    assert c.cached_epochs() == []


def test_put_then_get_current():
    c = PkiCache()
    c.put(42, b"\xa1\x65Epoch\x18\x2a")
    assert c.get_current() == b"\xa1\x65Epoch\x18\x2a"
    assert c.current_epoch() == 42


def test_get_for_epoch_specific():
    c = PkiCache()
    c.put(10, b"ten")
    c.put(11, b"eleven")
    assert c.get_for_epoch(10) == b"ten"
    assert c.get_for_epoch(11) == b"eleven"
    assert c.get_for_epoch(12) is None


def test_eviction_keeps_newest_five():
    c = PkiCache(max_epochs=5)
    for e in range(1, 8):
        c.put(e, f"epoch-{e}".encode())
    assert c.get_for_epoch(1) is None
    assert c.get_for_epoch(2) is None
    assert c.get_for_epoch(3) == b"epoch-3"
    assert c.get_for_epoch(7) == b"epoch-7"
    assert c.current_epoch() == 7
    assert c.cached_epochs() == [3, 4, 5, 6, 7]


def test_out_of_order_does_not_regress_current():
    c = PkiCache()
    c.put(10, b"ten")
    c.put(8, b"eight")
    assert c.current_epoch() == 10
    assert c.get_current() == b"ten"
    assert c.get_for_epoch(8) == b"eight"


def test_age_seconds_advances_with_time():
    fake_now = [1000.0]
    c = PkiCache(time_source=lambda: fake_now[0])
    c.put(1, b"x")
    assert c.age_seconds() == pytest.approx(0.0)
    fake_now[0] = 1003.5
    assert c.age_seconds() == pytest.approx(3.5)


def test_put_updates_last_refresh_even_on_non_advancing_put():
    fake_now = [100.0]
    c = PkiCache(time_source=lambda: fake_now[0])
    c.put(10, b"ten")
    fake_now[0] = 200.0
    c.put(5, b"five")
    assert c.age_seconds() == pytest.approx(0.0)
    assert c.current_epoch() == 10


def test_on_new_epoch_fires_only_on_advance():
    calls: list[int] = []
    c = PkiCache(on_new_epoch=calls.append)
    c.put(5, b"five")
    c.put(6, b"six")
    c.put(4, b"four")
    c.put(6, b"six-again")
    c.put(7, b"seven")
    assert calls == [5, 6, 7]


def test_on_new_epoch_called_outside_lock():
    """Verify the callback can call back into the cache without deadlocking."""
    seen_current: list[int] = []
    c: PkiCache

    def cb(epoch: int) -> None:
        seen_current.append(c.current_epoch())

    c = PkiCache(on_new_epoch=cb)
    c.put(1, b"one")
    c.put(2, b"two")
    assert seen_current == [1, 2]


def test_concurrent_readers_and_writer():
    c = PkiCache()
    c.put(1, b"one")
    stop = threading.Event()
    errors: list[BaseException] = []
    valid = {b"one", b"two", b"three", b"four", b"five"}

    def reader():
        try:
            while not stop.is_set():
                v = c.get_current()
                if v is not None and v not in valid:
                    raise AssertionError(f"torn read: {v!r}")
        except BaseException as e:
            errors.append(e)

    def writer():
        try:
            for i, payload in enumerate([b"two", b"three", b"four", b"five"], start=2):
                for _ in range(50):
                    c.put(i, payload)
        except BaseException as e:
            errors.append(e)

    readers = [threading.Thread(target=reader) for _ in range(8)]
    w = threading.Thread(target=writer)
    for r in readers:
        r.start()
    w.start()
    w.join(timeout=5.0)
    stop.set()
    for r in readers:
        r.join(timeout=5.0)
    assert errors == []
    assert c.current_epoch() == 5


def test_set_on_new_epoch_replaces_callback():
    first: list[int] = []
    second: list[int] = []
    c = PkiCache(on_new_epoch=first.append)
    c.put(1, b"one")
    c.set_on_new_epoch(second.append)
    c.put(2, b"two")
    c.set_on_new_epoch(None)
    c.put(3, b"three")
    assert first == [1]
    assert second == [2]


def test_clear_empties_cache():
    c = PkiCache()
    c.put(1, b"one")
    c.put(2, b"two")
    c.clear()
    assert c.cached_epochs() == []
    assert c.current_epoch() is None
    assert c.age_seconds() is None
