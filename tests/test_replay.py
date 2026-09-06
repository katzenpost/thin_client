# SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Unit tests for in-flight request replay after daemon reconnect.

These tests drive ``worker_loop`` with stubbed IO so they run without a
daemon. They pin the contract that in-flight requests are replayed after
EVERY reconnect, whether or not the daemon instance changed. Previously
replay was gated on a new instance token, so a request written into a
socket that dropped before the daemon read it was lost forever and the
caller's ``_send_and_wait`` blocked indefinitely.
"""

import asyncio
import errno
import logging

import pytest

from katzenpost_thinclient.core import ThinClient

from tests.test_session_resume import make_config

pytestmark = pytest.mark.asyncio


class FakeSocket:
    """Minimal socket stand-in; worker_loop only calls close()."""

    def close(self):
        return None


def _make_client(loop):
    """Build a ThinClient with worker_loop's collaborators stubbed out."""
    client = ThinClient.__new__(ThinClient)
    client.config = make_config()
    client._stopping = False
    client._received_shutdown = False
    client._is_connected = True
    client._daemon_instance_token = b"\xaa" * 16
    client.socket = FakeSocket()
    client.logger = logging.getLogger("test_replay")
    return client


async def _drive_worker_loop(client, *, new_instance: bool) -> int:
    """Run worker_loop through one disconnect/reconnect/replay cycle.

    ``_read_until_disconnect`` returns a connection error once (the drop)
    and then None (so the loop exits). ``_replay_in_flight_resends`` is
    stubbed to count invocations. Returns the number of times replay ran.
    """
    reads = [OSError(errno.ECONNRESET, "Connection reset"), None]
    replay_calls = 0

    async def fake_read(loop):
        return reads.pop(0)

    async def fake_reconnect(loop):
        if new_instance:
            client._daemon_instance_token = b"\xbb" * 16

    async def fake_replay():
        nonlocal replay_calls
        replay_calls += 1

    client._read_until_disconnect = fake_read
    client._reconnect = fake_reconnect
    client._replay_in_flight_resends = fake_replay

    loop = asyncio.get_running_loop()
    await client.worker_loop(loop)
    return replay_calls


@pytest.mark.parametrize("new_instance", [False, True])
async def test_replay_happens_on_every_reconnect(new_instance):
    """In-flight requests are replayed whether or not the token changed."""
    client = _make_client(asyncio.get_running_loop())
    calls = await _drive_worker_loop(
        client,
        new_instance=new_instance,
    )
    assert calls == 1, "replay must run once per reconnect"


async def test_replay_marks_connected_false_on_disconnect():
    """After a detected disconnect the client is marked offline."""
    client = _make_client(asyncio.get_running_loop())
    await _drive_worker_loop(client, new_instance=False)
    assert client._is_connected is False