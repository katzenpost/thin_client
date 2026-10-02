import asyncio

import pytest

from katzenpost_thinclient.core import ThinClient


def make_client(responses):
    client = ThinClient.__new__(ThinClient)
    client.handled = []
    queue = list(responses)

    async def recv(loop):
        return queue.pop(0) if queue else None

    async def handle_response(response):
        client.handled.append(response)

    client.recv = recv
    client.handle_response = handle_response
    return client


def test_recv_until_skips_an_interleaved_event():
    client = make_client([
        {"new_pki_document_event": {"payload": b""}},
        {"session_token_reply": {"resumed": False}},
    ])
    response = asyncio.run(client._recv_until(None, "session_token_reply"))
    assert response["session_token_reply"] is not None
    assert len(client.handled) == 2


def test_recv_until_raises_when_the_daemon_goes_away():
    client = make_client([])
    with pytest.raises(ConnectionError):
        asyncio.run(client._recv_until(None, "connection_status_event"))


def test_recv_until_gives_up_after_the_limit():
    client = make_client([{"message_sent_event": {}} for _ in range(20)])
    with pytest.raises(ConnectionError):
        asyncio.run(client._recv_until(None, "connection_status_event", limit=16))
    assert len(client.handled) == 16
