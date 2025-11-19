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
async def test_resume_write_channel():
    """
    Test resuming a write channel - equivalent to TestResumeWriteChannel from Rust.
    This test demonstrates the write channel resumption workflow:
    1. Create a write channel
    2. Write the first message onto the channel
    3. Close the channel
    4. Resume the channel
    5. Write the second message onto the channel
    6. Create a read channel
    7. Read first and second message from the channel
    8. Verify payloads match
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
    alice_channel_id, read_cap, write_cap = await alice_thin_client.create_write_channel()
    print(f"Alice: Created write channel {alice_channel_id}")

    # Alice writes first message
    alice_payload1 = b"Hello, Bob!"
    print("Alice: Writing first message")
    write_reply1 = await alice_thin_client.write_channel(alice_channel_id, alice_payload1)

    # Get courier destination
    dest_node, dest_queue = await alice_thin_client.get_courier_destination()
    alice_message_id1 = ThinClient.new_message_id()

    # Send first message
    _reply1 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply1.send_message_payload,
        dest_node,
        dest_queue,
        alice_message_id1
    )

    print("Waiting for first message propagation to storage replicas")
    await asyncio.sleep(3)

    # Close the channel
    await alice_thin_client.close_channel(alice_channel_id)

    # Resume the write channel
    print("Alice: Resuming write channel")
    alice_channel_id = await alice_thin_client.resume_write_channel(
        write_cap,
        write_reply1.next_message_index
    )
    print(f"Alice: Resumed write channel with ID {alice_channel_id}")

    # Write second message after resume
    print("Alice: Writing second message after resume")
    alice_payload2 = b"Second message from Alice!"
    write_reply2 = await alice_thin_client.write_channel(alice_channel_id, alice_payload2)

    alice_message_id2 = ThinClient.new_message_id()
    _reply2 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply2.send_message_payload,
        dest_node,
        dest_queue,
        alice_message_id2
    )
    print("Alice: Second write operation completed successfully")

    print("Waiting for second message propagation to storage replicas")
    await asyncio.sleep(3)

    # Bob creates read channel
    print("Bob: Creating read channel")
    bob_channel_id = await bob_thin_client.create_read_channel(read_cap)
    print(f"Bob: Created read channel {bob_channel_id}")

    # Bob reads first message
    print("Bob: Reading first message")
    read_reply1 = await bob_thin_client.read_channel(bob_channel_id, None, None)

    bob_message_id1 = ThinClient.new_message_id()
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
                print(f"Bob: First read attempt {i + 1} returned empty payload, retrying...")
                await asyncio.sleep(0.5)
        except Exception as e:
            raise e

    assert alice_payload1 == bob_reply_payload1, "Bob: First message payload mismatch"

    # Bob closes and resumes read channel to advance to second message
    await bob_thin_client.close_channel(bob_channel_id)

    print("Bob: Resuming read channel to read second message")
    bob_channel_id = await bob_thin_client.resume_read_channel(
        read_cap,
        read_reply1.next_message_index,
        read_reply1.reply_index
    )

    # Bob reads second message
    print("Bob: Reading second message")
    read_reply2 = await bob_thin_client.read_channel(bob_channel_id, None, None)

    bob_message_id2 = ThinClient.new_message_id()
    bob_reply_payload2 = b""

    for i in range(10):
        print(f"Bob: second message read attempt {i + 1}")
        try:
            payload = await alice_thin_client.send_channel_query_await_reply(
                bob_channel_id,
                read_reply2.send_message_payload,
                dest_node,
                dest_queue,
                bob_message_id2
            )
            if payload:
                bob_reply_payload2 = payload
                break
            else:
                await asyncio.sleep(0.5)
        except Exception as e:
            raise e

    # Verify the second message content matches
    assert alice_payload2 == bob_reply_payload2, "Bob: Second message payload mismatch"
    print("Bob: Successfully received and verified second message")

    # Clean up channels
    await alice_thin_client.close_channel(alice_channel_id)
    await bob_thin_client.close_channel(bob_channel_id)

    alice_thin_client.stop()
    bob_thin_client.stop()

    print("✅ Resume write channel test completed successfully")


if __name__ == "__main__":
    pytest.main([__file__])
