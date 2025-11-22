#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Channel API integration tests for the Python thin client.

These tests mirror the Rust tests in channel_api_test.rs and require
a running mixnet with client daemon for integration testing.
"""

import asyncio
import pytest
from katzenpost_thinclient import ThinClient, Config


async def setup_thin_client():
    """Test helper to setup a thin client for integration tests."""
    config = Config("testdata/thinclient.toml")
    client = ThinClient(config)

    # Start the client and wait a bit for initial connection and PKI document
    loop = asyncio.get_running_loop()
    await client.start(loop)
    await asyncio.sleep(2)
    return client

@pytest.mark.asyncio
async def test_channel_send_one_receive_one():
    """
    Alice sends a message and Bob receives it.
    """
    alice_thin_client = await setup_thin_client()
    bob_thin_client = await setup_thin_client()

    # Wait for PKI documents to be available and connection to mixnet
    print("Waiting for daemon to connect to mixnet...")
    attempts = 0
    while not alice_thin_client.is_connected() and attempts < 30:
        await asyncio.sleep(1)
        attempts += 1

    if not alice_thin_client.is_connected():
        raise Exception("Daemon failed to connect to mixnet within 30 seconds")

    print("✅ Daemon connected to mixnet, using current PKI document")

    # Alice creates write channel
    print("Alice: Creating write channel")
    alice_channel_id, read_cap, _write_cap = await alice_thin_client.create_write_channel()
    print(f"Alice: Created write channel {alice_channel_id}")

    # Bob creates read channel using the read capability from Alice's write channel
    print("Bob: Creating read channel")
    bob_channel_id = await bob_thin_client.create_read_channel(read_cap)
    print(f"Bob: Created read channel {bob_channel_id}")

    # Alice writes first message
    original_message = b"hello1"
    print("Alice: Writing first message and waiting for completion")

    write_reply1 = await alice_thin_client.write_channel(alice_channel_id, original_message)
    print("Alice: Write operation completed successfully")

    # Get the courier service from PKI
    courier_service = alice_thin_client.get_service("courier")
    dest_node, dest_queue = courier_service.to_destination()

    alice_message_id1 = ThinClient.new_message_id()

    _reply1 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply1.send_message_payload,
        dest_node,
        dest_queue,
        alice_message_id1
    )

    # Wait for message propagation to storage replicas
    print("Waiting for message propagation to storage replicas")
    await asyncio.sleep(10)

    # Bob reads first message
    print("Bob: Reading first message")
    read_reply1 = await bob_thin_client.read_channel(bob_channel_id, None, None)

    bob_message_id1 = ThinClient.new_message_id()

    # In a real implementation, you'd retry the send_channel_query_await_reply until you get a response
    bob_reply_payload1 = b""
    for i in range(10):
        try:
            payload = await alice_thin_client.send_channel_query_await_reply(
                bob_channel_id,
                read_reply1.send_message_payload,
                dest_node,
                dest_queue,
                bob_message_id1
            )
            if payload:
                bob_reply_payload1 = payload
                break
            else:
                print(f"Bob: Read attempt {i + 1} returned empty payload, retrying...")
                await asyncio.sleep(0.5)
        except Exception as e:
            raise e

    assert original_message == bob_reply_payload1, "Bob: Reply payload mismatch"

    # Clean up channels
    await alice_thin_client.close_channel(alice_channel_id)
    await bob_thin_client.close_channel(bob_channel_id)

    alice_thin_client.stop()
    bob_thin_client.stop()

    print("✅ Channel API basics test completed successfully")

if __name__ == "__main__":
    pytest.main([__file__])
