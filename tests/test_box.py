# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Unit tests for the NIKE and sealed box methods, against the Go reference's
vectors in testdata/vectors.json. They do not need a running daemon.
"""

import json
import os

import cbor2
import pytest

from katzenpost_thinclient import ThinClient, Config

VECTORS = os.path.join(os.path.dirname(__file__), "..", "testdata", "vectors.json")


def vector(section: str, name: str) -> dict:
    with open(VECTORS) as f:
        e = next(e for e in json.load(f)[section] if e["name"] == name)
    return cbor2.loads(bytes.fromhex(e["body"]))


def seq(start: int, n: int) -> bytes:
    return bytes((start + i) & 0xff for i in range(n))


def make_client(reply_name: str):
    """A client whose _send_and_wait records the request and answers with a vector."""
    from .conftest import get_config_path
    client = ThinClient(Config(get_config_path()))
    client.sent = []
    client.new_query_id = lambda: seq(0x20, 16)

    async def send_and_wait(query_id, request):
        client.sent.append(request)
        return vector("responses", reply_name)
    client._send_and_wait = send_and_wait
    return client


S = "X25519-CTIDH1024"


@pytest.mark.asyncio
@pytest.mark.parametrize("call,reply,key,want", [
    (lambda c: c.nike_generate_key_pair(S), "nike_generate_key_pair_reply", "nike_generate_key_pair", None),
    (lambda c: c.nike_derive_secret(S, seq(0x91, 32), seq(0xa1, 32)), "nike_derive_secret_reply",
     "nike_derive_secret", seq(0xd1, 32)),
    (lambda c: c.box_seal(S, seq(0xa1, 32), seq(0xb1, 16)), "box_seal_reply", "box_seal", seq(0xc1, 48)),
    (lambda c: c.box_open(S, seq(0x91, 32), seq(0xc1, 48)), "box_open_reply", "box_open", seq(0xb1, 16)),
])
async def test_requests_and_replies_match_go(call, reply, key, want):
    client = make_client(reply)
    got = await call(client)
    assert client.sent == [{key: vector("requests", key)}]
    if want is None:
        assert (got.public_key, got.private_key) == (seq(0xa1, 32), seq(0x91, 32))
        assert "private_key" not in repr(got)
    else:
        assert got == want
    client.socket.close()


@pytest.mark.asyncio
async def test_box_open_error():
    client = make_client("box_open_reply_err")
    with pytest.raises(Exception, match="box_open failed"):
        await client.box_open(S, seq(0x91, 32), seq(0xc1, 48))
    client.socket.close()
