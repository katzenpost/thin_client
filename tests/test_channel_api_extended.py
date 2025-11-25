#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Extended channel API integration tests for the Python thin client.
These tests cover the more advanced channel resumption scenarios.
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
async def test_resume_write_channel_query():
    """
    Test resuming a write channel with query state - equivalent to TestResumeWriteChannelQuery from Rust.
    This test demonstrates the write channel query resumption workflow:
    1. Create write channel
    2. Create first write query message but do not send to channel yet
    3. Close channel
    4. Resume write channel with query via resume_write_channel_query
    5. Send resumed write query to channel
    6. Send second message to channel
    7. Create read channel
    8. Read both messages from channel
    9. Verify payloads match
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

    # Alice prepares first message but doesn't send it yet
    alice_payload1 = b"Hello, Bob!"
    write_reply = await alice_thin_client.write_channel(alice_channel_id, alice_payload1)

    # Get courier destination
    courier_node, courier_queue_id = await alice_thin_client.get_courier_destination()
    alice_message_id1 = ThinClient.new_message_id()

    # Close the channel immediately (like in Rust test - no waiting for propagation)
    await alice_thin_client.close_channel(alice_channel_id)

    # Resume the write channel with query state using current_message_index like Rust test
    print("Alice: Resuming write channel")
    alice_channel_id = await alice_thin_client.resume_write_channel_query(
        write_cap,
        write_reply.next_message_index,  # Use current_message_index like in Rust test
        write_reply.envelope_descriptor,
        write_reply.envelope_hash
    )
    print(f"Alice: Resumed write channel with ID {alice_channel_id}")

    # Send the first message after resume
    print("Alice: Writing first message after resume")
    _reply1 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply.send_message_payload,
        courier_node,
        courier_queue_id,
        alice_message_id1
    )

    # Write second message
    print("Alice: Writing second message")
    alice_payload2 = b"Second message from Alice!"
    write_reply2 = await alice_thin_client.write_channel(alice_channel_id, alice_payload2)

    alice_message_id2 = ThinClient.new_message_id()
    _reply2 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply2.send_message_payload,
        courier_node,
        courier_queue_id,
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
                courier_node,
                courier_queue_id,
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

    # Bob reads second message
    print("Bob: Resuming read channel to read second message")
    bob_channel_id = await bob_thin_client.resume_read_channel(
        read_cap,
        read_reply1.next_message_index,
        read_reply1.reply_index
    )
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
                courier_node,
                courier_queue_id,
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

    print("✅ Resume write channel query test completed successfully")


@pytest.mark.asyncio
async def test_resume_read_channel():
    """
    Test resuming a read channel - equivalent to TestResumeReadChannel from Rust.
    This test demonstrates the read channel resumption workflow:
    1. Create a write channel
    2. Write two messages to the channel
    3. Create a read channel
    4. Read the first message from the channel
    5. Verify payload matches
    6. Close the read channel
    7. Resume the read channel
    8. Read the second message from the channel
    9. Verify payload matches
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

    # Alice writes first message
    alice_payload1 = b"Hello, Bob!"
    write_reply1 = await alice_thin_client.write_channel(alice_channel_id, alice_payload1)

    dest_node, dest_queue = await alice_thin_client.get_courier_destination()
    alice_message_id1 = ThinClient.new_message_id()

    _reply1 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply1.send_message_payload,
        dest_node,
        dest_queue,
        alice_message_id1
    )

    print("Waiting for first message propagation to storage replicas")
    await asyncio.sleep(3)

    # Alice writes second message
    print("Alice: Writing second message")
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

    # Close the read channel
    await bob_thin_client.close_channel(bob_channel_id)

    # Resume the read channel
    print("Bob: Resuming read channel")
    bob_channel_id = await bob_thin_client.resume_read_channel(
        read_cap,
        read_reply1.next_message_index,
        read_reply1.reply_index
    )
    print(f"Bob: Resumed read channel with ID {bob_channel_id}")

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

    print("✅ Resume read channel test completed successfully")


@pytest.mark.asyncio
async def test_resume_read_channel_query():
    """
    Test resuming a read channel with query state - equivalent to TestResumeReadChannelQuery from Rust.
    This test demonstrates the read channel query resumption workflow:
    1. Create a write channel
    2. Write two messages to the channel
    3. Create read channel
    4. Make read query but do not send it
    5. Close read channel
    6. Resume read channel query with resume_read_channel_query method
    7. Send previously made read query to channel
    8. Verify received payload matches
    9. Read second message from channel
    10. Verify received payload matches
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

    # Alice writes first message
    alice_payload1 = b"Hello, Bob!"
    write_reply1 = await alice_thin_client.write_channel(alice_channel_id, alice_payload1)

    dest_node, dest_queue = await alice_thin_client.get_courier_destination()
    alice_message_id1 = ThinClient.new_message_id()

    _reply1 = await alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        write_reply1.send_message_payload,
        dest_node,
        dest_queue,
        alice_message_id1
    )

    print("Waiting for first message propagation to storage replicas")
    await asyncio.sleep(3)

    # Alice writes second message
    print("Alice: Writing second message")
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

    # Bob prepares first read query but doesn't send it yet
    print("Bob: Reading first message")
    read_reply1 = await bob_thin_client.read_channel(bob_channel_id, None, None)

    # Close the read channel
    await bob_thin_client.close_channel(bob_channel_id)

    # Resume the read channel with query state
    print("Bob: Resuming read channel")
    bob_channel_id = await bob_thin_client.resume_read_channel_query(
        read_cap,
        read_reply1.current_message_index,
        read_reply1.reply_index,
        read_reply1.envelope_descriptor,
        read_reply1.envelope_hash
    )
    print(f"Bob: Resumed read channel with ID {bob_channel_id}")

    # Send the first read query and get the message payload
    bob_message_id1 = ThinClient.new_message_id()
    bob_reply_payload1 = b""

    for i in range(10):
        print(f"Bob: first message read attempt {i + 1}")
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
                await asyncio.sleep(0.5)
        except Exception as e:
            raise e

    assert alice_payload1 == bob_reply_payload1, "Bob: First message payload mismatch"

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

    print("✅ Resume read channel query test completed successfully")
