#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
NEW Pigeonhole API integration tests for the Python thin client.

These tests verify the 5-function NEW Pigeonhole API:
1. new_keypair - Generate WriteCap and ReadCap from seed
2. encrypt_read - Encrypt a read operation
3. encrypt_write - Encrypt a write operation
4. start_resending_encrypted_message - Send encrypted message with ARQ
5. cancel_resending_encrypted_message - Cancel ARQ for a message

These tests require a running mixnet with client daemon for integration testing.
"""

import asyncio
import pytest
import os
from katzenpost_thinclient import ThinClient, Config


async def setup_thin_client():
    """Test helper to setup a thin client for integration tests."""
    from .conftest import get_config_path

    config_path = get_config_path()
    config = Config(config_path)
    client = ThinClient(config)

    # Start the client and wait for connection and PKI document
    loop = asyncio.get_running_loop()
    await client.start(loop)

    # Wait for daemon to connect to mixnet and receive PKI document
    print("Waiting for daemon to connect to mixnet...")
    attempts = 0
    while (not client.is_connected() or client.pki_document() is None) and attempts < 30:
        await asyncio.sleep(1)
        attempts += 1

    if not client.is_connected():
        raise Exception("Daemon failed to connect to mixnet within 30 seconds")

    if client.pki_document() is None:
        raise Exception("PKI document not received within 30 seconds")

    print("✅ Daemon connected to mixnet, using current PKI document")

    return client


@pytest.mark.asyncio
async def test_new_keypair_basic():
    """
    Test basic keypair generation using new_keypair.
    
    This test verifies:
    1. Keypair can be generated from a 32-byte seed
    2. WriteCap, ReadCap, and FirstMessageIndex are returned
    3. The returned values have the expected sizes
    """
    client = await setup_thin_client()

    try:
        print("\n=== Test: new_keypair basic functionality ===")
        
        # Generate a 32-byte seed
        seed = os.urandom(32)
        print(f"Generated seed: {len(seed)} bytes")

        # Create keypair
        write_cap, read_cap, first_message_index = await client.new_keypair(seed)
        
        print(f"✓ WriteCap size: {len(write_cap)} bytes")
        print(f"✓ ReadCap size: {len(read_cap)} bytes")
        print(f"✓ FirstMessageIndex size: {len(first_message_index)} bytes")

        # Verify the returned values are not empty
        assert len(write_cap) > 0, "WriteCap should not be empty"
        assert len(read_cap) > 0, "ReadCap should not be empty"
        assert len(first_message_index) > 0, "FirstMessageIndex should not be empty"

        print("✅ new_keypair test completed successfully")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_alice_sends_bob_complete_workflow():
    """
    Test complete end-to-end workflow: Alice sends a message to Bob.

    This test demonstrates the full NEW Pigeonhole API workflow:
    1. Alice creates a WriteCap and derives a ReadCap for Bob
    2. Alice encrypts a message using encrypt_write
    3. Alice sends the encrypted message via start_resending_encrypted_message
    4. Bob encrypts a read request using encrypt_read
    5. Bob sends the read request and receives Alice's encrypted message
    6. Bob verifies the received message

    This mirrors the Go test: TestNewPigeonholeAPIAliceSendsBob
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Alice sends message to Bob (complete workflow) ===")

        # Step 1: Alice creates WriteCap and derives ReadCap for Bob
        print("\n--- Step 1: Alice creates keypair ---")
        alice_seed = os.urandom(32)
        alice_write_cap, bob_read_cap, alice_first_index = await alice_client.new_keypair(alice_seed)
        print(f"✓ Alice created WriteCap and derived ReadCap for Bob")

        # Step 2: Alice encrypts a message for Bob
        print("\n--- Step 2: Alice encrypts message ---")
        alice_message = b"Bob, Beware they are jamming GPS."
        print(f"Alice's message: {alice_message.decode()}")

        alice_ciphertext, alice_env_desc, alice_env_hash = await alice_client.encrypt_write(
            alice_message, alice_write_cap, alice_first_index
        )
        print(f"✓ Alice encrypted message (ciphertext: {len(alice_ciphertext)} bytes)")

        # Step 3: Alice sends the encrypted message via start_resending_encrypted_message
        print("\n--- Step 3: Alice sends encrypted message to courier/replicas ---")
        reply_index = 0

        alice_plaintext = await alice_client.start_resending_encrypted_message(
            read_cap=None,  # None for write operations
            write_cap=alice_write_cap,
            next_message_index=None,  # Not needed for writes
            reply_index=reply_index,
            envelope_descriptor=alice_env_desc,
            message_ciphertext=alice_ciphertext,
            envelope_hash=alice_env_hash
        )

        # For write operations, plaintext should be empty (ACK only)
        print(f"✓ Alice received ACK (plaintext length: {len(alice_plaintext) if alice_plaintext else 0})")

        # Wait for message propagation to storage replicas
        print("\n--- Waiting for message propagation to storage replicas ---")
        await asyncio.sleep(5)

        # Step 4: Bob encrypts a read request
        print("\n--- Step 4: Bob encrypts read request ---")
        bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash = await bob_client.encrypt_read(
            bob_read_cap, alice_first_index
        )
        print(f"✓ Bob encrypted read request (ciphertext: {len(bob_ciphertext)} bytes)")

        # Step 5: Bob sends the read request and receives Alice's encrypted message
        print("\n--- Step 5: Bob sends read request and receives encrypted message ---")
        bob_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=bob_read_cap,
            write_cap=None,  # None for read operations
            next_message_index=bob_next_index,
            reply_index=reply_index,
            envelope_descriptor=bob_env_desc,
            message_ciphertext=bob_ciphertext,
            envelope_hash=bob_env_hash
        )

        # Step 6: Verify Bob received Alice's message
        print(f"\n--- Step 6: Verify received message ---")
        print(f"Bob received: {bob_plaintext.decode() if bob_plaintext else '(empty)'}")

        assert bob_plaintext == alice_message, f"Message mismatch! Expected: {alice_message}, Got: {bob_plaintext}"

        print("✅ Complete workflow test passed - Bob successfully received Alice's message!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_cancel_resending_encrypted_message():
    """
    Test cancelling ARQ for an encrypted message.

    This test verifies:
    1. An encrypted message can be prepared
    2. The ARQ can be cancelled using cancel_resending_encrypted_message
    3. The cancellation completes without error
    """
    client = await setup_thin_client()

    try:
        print("\n=== Test: cancel_resending_encrypted_message ===")

        # Generate keypair and encrypt a message
        seed = os.urandom(32)
        write_cap, read_cap, first_message_index = await client.new_keypair(seed)

        plaintext = b"This message will be cancelled"
        ciphertext, env_desc, env_hash = await client.encrypt_write(
            plaintext, write_cap, first_message_index
        )

        print(f"✓ Encrypted message for cancellation test")
        print(f"EnvelopeHash: {env_hash.hex()}")

        # Cancel the message (before sending it)
        # Note: In practice, you would start_resending first, then cancel
        # But for this test, we just verify the cancel API works
        await client.cancel_resending_encrypted_message(env_hash)

        print("✅ cancel_resending_encrypted_message completed successfully")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_cancel_causes_start_resending_to_return_error():
    """
    Test that calling cancel causes start_resending to return with error code 24.

    This test verifies the core cancel behavior:
    1. Start a start_resending_encrypted_message call (which blocks waiting for reply)
    2. Call cancel_resending_encrypted_message from another task
    3. Verify that the original start_resending call returns with error code 24
       (THIN_CLIENT_ERROR_START_RESENDING_CANCELLED)

    This requires a running daemon but does NOT require a full mixnet since we're
    testing the cancel behavior before any reply is received from the mixnet.
    """
    from katzenpost_thinclient import THIN_CLIENT_ERROR_START_RESENDING_CANCELLED

    client = await setup_thin_client()

    try:
        print("\n=== Test: cancel causes start_resending to return error ===")

        # Generate keypair and encrypt a message
        seed = os.urandom(32)
        write_cap, read_cap, first_message_index = await client.new_keypair(seed)

        plaintext = b"This message will be cancelled while sending"
        ciphertext, env_desc, env_hash = await client.encrypt_write(
            plaintext, write_cap, first_message_index
        )

        print(f"✓ Encrypted message")
        print(f"EnvelopeHash: {env_hash.hex()}")

        # Track whether the start_resending returned with the expected error
        start_resending_error = None
        start_resending_completed = asyncio.Event()

        async def start_resending_task():
            """Task that calls start_resending and captures any error."""
            nonlocal start_resending_error
            try:
                await client.start_resending_encrypted_message(
                    read_cap=None,
                    write_cap=write_cap,
                    next_message_index=None,
                    reply_index=0,
                    envelope_descriptor=env_desc,
                    message_ciphertext=ciphertext,
                    envelope_hash=env_hash
                )
                # If we get here without error, that's unexpected
                start_resending_error = "No error raised"
            except Exception as e:
                start_resending_error = str(e)
            finally:
                start_resending_completed.set()

        # Start the start_resending task
        print("--- Starting start_resending_encrypted_message task ---")
        resend_task = asyncio.create_task(start_resending_task())

        # Give the task just enough time to start and register with the daemon
        # We need to call cancel BEFORE the message gets ACKed by the mixnet,
        # so we use a very short delay (just enough for the async task to start)
        await asyncio.sleep(0.1)

        # Cancel the resending
        print("--- Calling cancel_resending_encrypted_message ---")
        await client.cancel_resending_encrypted_message(env_hash)
        print("✓ Cancel call completed")

        # Wait for the start_resending task to complete (with timeout)
        try:
            await asyncio.wait_for(start_resending_completed.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            resend_task.cancel()
            raise Exception("start_resending did not return within 5 seconds after cancel")

        # Verify the error
        print(f"--- Verifying error ---")
        print(f"Error received: {start_resending_error}")

        assert start_resending_error is not None, "Expected an error but got None"
        assert "Start resending cancelled" in start_resending_error, \
            f"Expected 'Start resending cancelled' in error, got: {start_resending_error}"

        print("✅ start_resending returned with expected error code 24 (Start resending cancelled)")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_cancel_causes_start_resending_copy_command_to_return_error():
    """
    Test that calling cancel causes start_resending_copy_command to return with error.

    This test verifies the cancel behavior for copy commands:
    1. Create a temporary channel and write some data to it
    2. Start a start_resending_copy_command call (which blocks)
    3. Call cancel_resending_copy_command from another task
    4. Verify that the original start_resending call returns with error code 24
    """
    from hashlib import blake2b

    client = await setup_thin_client()

    try:
        print("\n=== Test: cancel causes start_resending_copy_command to return error ===")

        # Create temporary channel
        temp_seed = os.urandom(32)
        temp_write_cap, _, temp_first_index = await client.new_keypair(temp_seed)
        print("✓ Created temporary copy stream WriteCap")

        # Compute write_cap_hash for cancel
        write_cap_hash = blake2b(temp_write_cap, digest_size=32).digest()
        print(f"WriteCapHash: {write_cap_hash.hex()}")

        # Track whether the start_resending returned with the expected error
        start_resending_error = None
        start_resending_completed = asyncio.Event()

        async def start_resending_copy_task():
            """Task that calls start_resending_copy_command and captures any error."""
            nonlocal start_resending_error
            try:
                await client.start_resending_copy_command(temp_write_cap)
                # If we get here without error, that's unexpected
                start_resending_error = "No error raised"
            except Exception as e:
                start_resending_error = str(e)
            finally:
                start_resending_completed.set()

        # Start the start_resending_copy_command task
        print("--- Starting start_resending_copy_command task ---")
        resend_task = asyncio.create_task(start_resending_copy_task())

        # Give the task just enough time to start and register with the daemon
        # We need to call cancel BEFORE the message gets ACKed by the mixnet,
        # so we use a very short delay (just enough for the async task to start)
        await asyncio.sleep(0.1)

        # Cancel the resending
        print("--- Calling cancel_resending_copy_command ---")
        await client.cancel_resending_copy_command(write_cap_hash)
        print("✓ Cancel call completed")

        # Wait for the start_resending task to complete (with timeout)
        try:
            await asyncio.wait_for(start_resending_completed.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            resend_task.cancel()
            raise Exception("start_resending_copy_command did not return within 5 seconds after cancel")

        # Verify the error
        print(f"--- Verifying error ---")
        print(f"Error received: {start_resending_error}")

        assert start_resending_error is not None, "Expected an error but got None"
        assert "Start resending cancelled" in start_resending_error, \
            f"Expected 'Start resending cancelled' in error, got: {start_resending_error}"

        print("✅ start_resending_copy_command returned with expected error code 24 (Start resending cancelled)")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_multiple_messages_sequence():
    """
    Test sending multiple messages with incrementing indices.

    This test verifies:
    1. Multiple messages can be sent using the same WriteCap
    2. Each message is written to a different MessageBoxIndex
    3. All messages can be read back in sequence
    4. The messages are reassembled correctly

    Note: Each MessageBoxIndex holds one message. To send multiple messages,
    you must increment the index for each new message.
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Multiple messages with incrementing indices ===")

        # Alice creates keypair
        alice_seed = os.urandom(32)
        alice_write_cap, bob_read_cap, first_index = await alice_client.new_keypair(alice_seed)
        print(f"✓ Alice created keypair")

        num_messages = 3
        messages = [
            b"Message 1 from Alice to Bob",
            b"Message 2 from Alice to Bob",
            b"Message 3 from Alice to Bob"
        ]

        # Alice sends multiple messages, each to a different index
        # We increment the index for each message using the BACAP HKDF logic
        current_index = first_index
        indices_used = [current_index]  # Track all indices for reading later

        for i, message in enumerate(messages):
            print(f"\n--- Sending message {i+1}/{num_messages} ---")
            print(f"Message: {message.decode()}")

            # Encrypt and send to current index
            ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
                message, alice_write_cap, current_index
            )

            alice_plaintext = await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=alice_write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash
            )

            print(f"✓ Message {i+1} sent to index successfully")

            # Increment index for next message
            if i < num_messages - 1:  # Don't increment after last message
                current_index = await alice_client.next_message_box_index(current_index)
                indices_used.append(current_index)

        print("\n--- Waiting for message propagation ---")
        await asyncio.sleep(5)

        # Bob reads all messages from their respective indices
        print("\n--- Bob reads all messages ---")
        received_messages = []
        bob_current_index = first_index

        for i in range(num_messages):
            print(f"\nReading message {i+1}/{num_messages}...")
            bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash = await bob_client.encrypt_read(
                bob_read_cap, bob_current_index
            )

            bob_plaintext = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                next_message_index=bob_next_index,
                reply_index=0,
                envelope_descriptor=bob_env_desc,
                message_ciphertext=bob_ciphertext,
                envelope_hash=bob_env_hash
            )

            print(f"Bob received: {bob_plaintext.decode() if bob_plaintext else '(empty)'}")
            received_messages.append(bob_plaintext)

            # Increment index for next read
            if i < num_messages - 1:
                bob_current_index = await bob_client.next_message_box_index(bob_current_index)

        # Verify all messages were received correctly
        for i, (sent, received) in enumerate(zip(messages, received_messages)):
            assert received == sent, f"Message {i+1} mismatch: expected {sent}, got {received}"

        print("\n✅ Multiple messages test completed successfully!")
        print(f"✅ All {num_messages} messages sent and received correctly with proper index incrementing!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_create_courier_envelopes_from_payload():
    """
    Test the CreateCourierEnvelopesFromPayload API.

    This test verifies:
    1. Alice creates a large payload that will be automatically chunked
    2. Alice calls create_courier_envelopes_from_payload to get copy stream chunks
    3. Alice writes all copy stream chunks to a temporary copy stream channel
    4. Alice sends the Copy command to the courier
    5. Bob reads all chunks from the destination channel and reconstructs the payload

    This mirrors the Go test: TestCreateCourierEnvelopesFromPayload
    """
    import struct

    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: CreateCourierEnvelopesFromPayload ===")

        # Step 1: Alice creates destination WriteCap for the final payload
        print("\n--- Step 1: Alice creates destination WriteCap ---")
        dest_seed = os.urandom(32)
        dest_write_cap, bob_read_cap, dest_first_index = await alice_client.new_keypair(dest_seed)
        print("✓ Alice created destination WriteCap and derived ReadCap for Bob")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_write_cap, _, temp_first_index = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create a large payload that will be chunked
        print("\n--- Step 3: Creating large payload ---")
        # Create a payload large enough to require multiple chunks
        # Use a 4-byte length prefix so Bob knows when to stop reading
        random_data = os.urandom(5 * 1024)  # 5KB of random data
        # Length-prefix the payload: [4 bytes length][random data]
        large_payload = struct.pack(">I", len(random_data)) + random_data
        print(f"✓ Alice created large payload ({len(large_payload)} bytes = 4 byte length prefix + {len(random_data)} bytes data)")

        # Step 4: Create copy stream chunks from the large payload
        print("\n--- Step 4: Creating copy stream chunks from large payload ---")
        query_id = alice_client.new_query_id()
        stream_id = alice_client.new_stream_id()
        copy_stream_chunks = await alice_client.create_courier_envelopes_from_payload(
            query_id, stream_id, large_payload, dest_write_cap, dest_first_index, True  # is_last
        )
        assert copy_stream_chunks, "create_courier_envelopes_from_payload returned empty chunks"
        num_chunks = len(copy_stream_chunks)
        print(f"✓ Alice created {num_chunks} copy stream chunks from {len(large_payload)} byte payload")

        # Step 5: Write all copy stream chunks to the temporary copy stream
        print("\n--- Step 5: Writing copy stream chunks to temporary channel ---")
        temp_index = temp_first_index

        for i, chunk in enumerate(copy_stream_chunks):
            print(f"--- Writing copy stream chunk {i+1}/{num_chunks} to temporary channel ---")

            # Encrypt the chunk for the copy stream
            ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
                chunk, temp_write_cap, temp_index
            )
            print(f"✓ Alice encrypted copy stream chunk {i+1} ({len(chunk)} bytes plaintext -> {len(ciphertext)} bytes ciphertext)")

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash
            )
            print(f"✓ Alice sent copy stream chunk {i+1} to temporary channel")

            # Increment temp index for next chunk
            temp_index = await alice_client.next_message_box_index(temp_index)

        # Wait for all chunks to propagate to the copy stream
        print("\n--- Waiting for copy stream chunks to propagate (30 seconds) ---")
        await asyncio.sleep(30)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads chunks until we have the full payload (based on length prefix)
        print("\n--- Step 7: Bob reads all chunks and reconstructs payload ---")
        bob_index = dest_first_index
        reconstructed_payload = b""
        expected_length = 0
        chunk_num = 0

        while True:
            chunk_num += 1
            print(f"--- Bob reading chunk {chunk_num} ---")

            # Bob encrypts read request
            bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash = await bob_client.encrypt_read(
                bob_read_cap, bob_index
            )
            print(f"✓ Bob encrypted read request {chunk_num}")

            # Bob sends read request and receives chunk
            bob_plaintext = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                next_message_index=bob_next_index,
                reply_index=0,
                envelope_descriptor=bob_env_desc,
                message_ciphertext=bob_ciphertext,
                envelope_hash=bob_env_hash
            )
            assert bob_plaintext, f"Bob: Failed to receive chunk {chunk_num}"
            print(f"✓ Bob received and decrypted chunk {chunk_num} ({len(bob_plaintext)} bytes)")

            # Append chunk to reconstructed payload
            reconstructed_payload += bob_plaintext

            # Extract expected length from the first 4 bytes once we have them
            if expected_length == 0 and len(reconstructed_payload) >= 4:
                expected_length = struct.unpack(">I", reconstructed_payload[:4])[0]
                print(f"✓ Bob: Expected payload length is {expected_length} bytes (+ 4 byte prefix = {expected_length + 4} total)")

            # Check if we have the full payload (4 byte prefix + expected_length bytes)
            if expected_length > 0 and len(reconstructed_payload) >= expected_length + 4:
                print(f"✓ Bob: Received full payload after {chunk_num} chunks")
                break

            # Advance to next chunk
            bob_index = await bob_client.next_message_box_index(bob_index)

        # Verify the reconstructed payload matches the original
        print(f"\n--- Verifying reconstructed payload ({len(reconstructed_payload)} bytes) ---")
        assert reconstructed_payload == large_payload, "Reconstructed payload doesn't match original"
        print(f"✅ CreateCourierEnvelopesFromPayload test passed! Large payload ({len(random_data)} bytes data) encoded into {num_chunks} copy stream chunks and reconstructed successfully!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_copy_command_multi_channel():
    """
    Test the Copy Command API with multiple destination channels.

    This test verifies:
    1. Alice creates two destination channels (chan1 and chan2)
    2. Alice creates a temporary copy stream channel
    3. Alice creates two payloads - one for each destination channel
    4. Alice calls create_courier_envelopes_from_payload twice with the same streamID but different WriteCaps
    5. Alice writes all copy stream chunks to the temporary channel
    6. Alice sends the Copy command to the courier
    7. Bob reads from both destination channels and verifies the payloads

    This mirrors the Go test: TestCopyCommandMultiChannel
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Copy Command Multi-Channel ===")

        # Step 1: Alice creates two destination channels
        print("\n--- Step 1: Alice creates two destination channels ---")

        # Channel 1
        chan1_seed = os.urandom(32)
        chan1_write_cap, chan1_read_cap, chan1_first_index = await alice_client.new_keypair(chan1_seed)
        print("✓ Alice created Channel 1 (WriteCap and ReadCap)")

        # Channel 2
        chan2_seed = os.urandom(32)
        chan2_write_cap, chan2_read_cap, chan2_first_index = await alice_client.new_keypair(chan2_seed)
        print("✓ Alice created Channel 2 (WriteCap and ReadCap)")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_write_cap, _, temp_first_index = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create two payloads - one for each destination channel
        print("\n--- Step 3: Creating payloads for each channel ---")
        payload1 = b"This is the secret message for Channel 1. It contains important information."
        print(f"✓ Alice created payload1 for Channel 1 ({len(payload1)} bytes)")
        payload2 = b"This is the confidential data for Channel 2. Handle with care and discretion."
        print(f"✓ Alice created payload2 for Channel 2 ({len(payload2)} bytes)")

        # Step 4: Create copy stream chunks using same streamID but different WriteCaps
        print("\n--- Step 4: Creating copy stream chunks for both channels ---")
        query_id = alice_client.new_query_id()
        stream_id = alice_client.new_stream_id()

        # First call: payload1 -> channel 1 (is_last=False)
        chunks1 = await alice_client.create_courier_envelopes_from_payload(
            query_id, stream_id, payload1, chan1_write_cap, chan1_first_index, False
        )
        assert chunks1, "create_courier_envelopes_from_payload returned empty chunks for channel 1"
        print(f"✓ Alice created {len(chunks1)} chunks for Channel 1")

        # Second call: payload2 -> channel 2 (is_last=True)
        chunks2 = await alice_client.create_courier_envelopes_from_payload(
            query_id, stream_id, payload2, chan2_write_cap, chan2_first_index, True
        )
        assert chunks2, "create_courier_envelopes_from_payload returned empty chunks for channel 2"
        print(f"✓ Alice created {len(chunks2)} chunks for Channel 2")

        # Combine all chunks
        all_chunks = chunks1 + chunks2
        print(f"✓ Alice total chunks to write to temp channel: {len(all_chunks)}")

        # Step 5: Write all copy stream chunks to the temporary channel
        print("\n--- Step 5: Writing all chunks to temporary channel ---")
        temp_index = temp_first_index

        for i, chunk in enumerate(all_chunks):
            print(f"--- Writing chunk {i+1}/{len(all_chunks)} to temporary channel ---")

            # Encrypt the chunk for the copy stream
            ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
                chunk, temp_write_cap, temp_index
            )
            print(f"✓ Alice encrypted chunk {i+1} ({len(chunk)} bytes plaintext -> {len(ciphertext)} bytes ciphertext)")

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash
            )
            print(f"✓ Alice sent chunk {i+1} to temporary channel")

            # Increment temp index for next chunk
            temp_index = await alice_client.next_message_box_index(temp_index)

        # Wait for chunks to propagate
        print("\n--- Waiting for copy stream chunks to propagate (30 seconds) ---")
        await asyncio.sleep(30)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads from both channels and verifies payloads
        print("\n--- Step 7: Bob reads from both channels ---")

        # Read from Channel 1
        print("--- Bob reading from Channel 1 ---")
        bob1_ciphertext, bob1_next_index, bob1_env_desc, bob1_env_hash = await bob_client.encrypt_read(
            chan1_read_cap, chan1_first_index
        )
        assert bob1_ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1"

        bob1_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=chan1_read_cap,
            write_cap=None,
            next_message_index=bob1_next_index,
            reply_index=0,
            envelope_descriptor=bob1_env_desc,
            message_ciphertext=bob1_ciphertext,
            envelope_hash=bob1_env_hash
        )
        assert bob1_plaintext, "Bob: Failed to receive data from Channel 1"
        print(f"✓ Bob received from Channel 1: {bob1_plaintext.decode()} ({len(bob1_plaintext)} bytes)")

        # Verify Channel 1 payload
        assert bob1_plaintext == payload1, "Channel 1 payload doesn't match"
        print("✓ Channel 1 payload verified!")

        # Read from Channel 2
        print("--- Bob reading from Channel 2 ---")
        bob2_ciphertext, bob2_next_index, bob2_env_desc, bob2_env_hash = await bob_client.encrypt_read(
            chan2_read_cap, chan2_first_index
        )
        assert bob2_ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2"

        bob2_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=chan2_read_cap,
            write_cap=None,
            next_message_index=bob2_next_index,
            reply_index=0,
            envelope_descriptor=bob2_env_desc,
            message_ciphertext=bob2_ciphertext,
            envelope_hash=bob2_env_hash
        )
        assert bob2_plaintext, "Bob: Failed to receive data from Channel 2"
        print(f"✓ Bob received from Channel 2: {bob2_plaintext.decode()} ({len(bob2_plaintext)} bytes)")

        # Verify Channel 2 payload
        assert bob2_plaintext == payload2, "Channel 2 payload doesn't match"
        print("✓ Channel 2 payload verified!")

        print("\n✅ Multi-channel Copy Command test passed! Payload1 written to Channel 1 and Payload2 written to Channel 2 atomically!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_copy_command_multi_channel_efficient():
    """
    Test the space-efficient multi-channel copy command using
    create_courier_envelopes_from_payloads which packs envelopes from different
    destinations together without wasting space in the copy stream.

    This test verifies:
    - The create_courier_envelopes_from_payloads API works correctly
    - Multiple destination payloads are packed efficiently into the copy stream
    - The courier processes all envelopes and writes to the correct destinations

    This mirrors the Go test: TestCopyCommandMultiChannelEfficient
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Efficient Multi-Channel Copy Command ===")

        # Step 1: Alice creates two destination channels
        print("\n--- Step 1: Alice creates two destination channels ---")

        # Channel 1
        chan1_seed = os.urandom(32)
        chan1_write_cap, chan1_read_cap, chan1_first_index = await alice_client.new_keypair(chan1_seed)
        print("✓ Alice created Channel 1 (WriteCap and ReadCap)")

        # Channel 2
        chan2_seed = os.urandom(32)
        chan2_write_cap, chan2_read_cap, chan2_first_index = await alice_client.new_keypair(chan2_seed)
        print("✓ Alice created Channel 2 (WriteCap and ReadCap)")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_write_cap, _, temp_first_index = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create two payloads - one for each destination channel
        print("\n--- Step 3: Creating payloads for each channel ---")
        payload1 = b"This is the secret message for Channel 1 using the efficient multi-channel API."
        print(f"✓ Alice created payload1 for Channel 1 ({len(payload1)} bytes)")
        payload2 = b"This is the confidential data for Channel 2 packed efficiently with payload1."
        print(f"✓ Alice created payload2 for Channel 2 ({len(payload2)} bytes)")

        # Step 4: Create copy stream chunks using efficient multi-destination API
        print("\n--- Step 4: Creating copy stream chunks using efficient multi-destination API ---")
        stream_id = alice_client.new_stream_id()

        # Create destinations list with both payloads
        destinations = [
            {
                "payload": payload1,
                "write_cap": chan1_write_cap,
                "start_index": chan1_first_index,
            },
            {
                "payload": payload2,
                "write_cap": chan2_write_cap,
                "start_index": chan2_first_index,
            },
        ]

        # Single call packs all envelopes efficiently
        all_chunks = await alice_client.create_courier_envelopes_from_payloads(
            stream_id, destinations, True  # is_last
        )
        assert all_chunks, "create_courier_envelopes_from_payloads returned empty chunks"
        print(f"✓ Alice created {len(all_chunks)} chunks for both channels (packed efficiently)")

        # Step 5: Write all copy stream chunks to the temporary channel
        print("\n--- Step 5: Writing all chunks to temporary channel ---")
        temp_index = temp_first_index

        for i, chunk in enumerate(all_chunks):
            print(f"--- Writing chunk {i+1}/{len(all_chunks)} to temporary channel ---")

            # Encrypt the chunk for the copy stream
            ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
                chunk, temp_write_cap, temp_index
            )
            print(f"✓ Alice encrypted chunk {i+1} ({len(chunk)} bytes plaintext -> {len(ciphertext)} bytes ciphertext)")

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash
            )
            print(f"✓ Alice sent chunk {i+1} to temporary channel")

            # Increment temp index for next chunk
            temp_index = await alice_client.next_message_box_index(temp_index)

        # Wait for chunks to propagate
        print("\n--- Waiting for copy stream chunks to propagate (30 seconds) ---")
        await asyncio.sleep(30)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads from both channels and verifies payloads
        print("\n--- Step 7: Bob reads from both channels ---")

        # Read from Channel 1
        print("--- Bob reading from Channel 1 ---")
        bob1_ciphertext, bob1_next_index, bob1_env_desc, bob1_env_hash = await bob_client.encrypt_read(
            chan1_read_cap, chan1_first_index
        )

        bob1_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=chan1_read_cap,
            write_cap=None,
            next_message_index=bob1_next_index,
            reply_index=0,
            envelope_descriptor=bob1_env_desc,
            message_ciphertext=bob1_ciphertext,
            envelope_hash=bob1_env_hash
        )
        assert bob1_plaintext, "Bob: Failed to receive data from Channel 1"
        print(f"✓ Bob received from Channel 1: {bob1_plaintext.decode()} ({len(bob1_plaintext)} bytes)")
        assert bob1_plaintext == payload1, "Channel 1 payload doesn't match"
        print("✓ Channel 1 payload verified!")

        # Read from Channel 2
        print("--- Bob reading from Channel 2 ---")
        bob2_ciphertext, bob2_next_index, bob2_env_desc, bob2_env_hash = await bob_client.encrypt_read(
            chan2_read_cap, chan2_first_index
        )

        bob2_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=chan2_read_cap,
            write_cap=None,
            next_message_index=bob2_next_index,
            reply_index=0,
            envelope_descriptor=bob2_env_desc,
            message_ciphertext=bob2_ciphertext,
            envelope_hash=bob2_env_hash
        )
        assert bob2_plaintext, "Bob: Failed to receive data from Channel 2"
        print(f"✓ Bob received from Channel 2: {bob2_plaintext.decode()} ({len(bob2_plaintext)} bytes)")
        assert bob2_plaintext == payload2, "Channel 2 payload doesn't match"
        print("✓ Channel 2 payload verified!")

        print("\n✅ Efficient multi-channel Copy Command test passed! Both payloads packed efficiently and delivered to correct channels!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_tombstoning():
    """
    Test the tombstoning API.

    This test verifies:
    1. Alice writes a message to a box
    2. Bob reads and verifies the message
    3. Alice tombstones the box (overwrites with zeros)
    4. Bob reads again and verifies the tombstone

    This mirrors the Go test: TestTombstoning
    """
    from katzenpost_thinclient import PigeonholeGeometry, is_tombstone_plaintext

    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Tombstoning ===")

        # Create a geometry with a reasonable payload size
        # In a real scenario, this would come from the PKI document
        geometry = PigeonholeGeometry(
            max_plaintext_payload_length=1024,
            nike_name="x25519"
        )

        # Create keypair
        seed = os.urandom(32)
        write_cap, read_cap, first_index = await alice_client.new_keypair(seed)
        print("✓ Created keypair")

        # Step 1: Alice writes a message
        print("\n--- Step 1: Alice writes a message ---")
        message = b"Secret message that will be tombstoned"
        ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
            message, write_cap, first_index
        )

        await alice_client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=write_cap,
            next_message_index=None,
            reply_index=0,
            envelope_descriptor=env_desc,
            message_ciphertext=ciphertext,
            envelope_hash=env_hash
        )
        print("✓ Alice wrote message")

        # Wait for message propagation
        print("--- Waiting for message propagation (5 seconds) ---")
        await asyncio.sleep(5)

        # Step 2: Bob reads and verifies
        print("\n--- Step 2: Bob reads and verifies ---")
        bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash = await bob_client.encrypt_read(
            read_cap, first_index
        )
        bob_plaintext = await bob_client.start_resending_encrypted_message(
            read_cap=read_cap,
            write_cap=None,
            next_message_index=bob_next_index,
            reply_index=0,
            envelope_descriptor=bob_env_desc,
            message_ciphertext=bob_ciphertext,
            envelope_hash=bob_env_hash
        )
        assert bob_plaintext == message, f"Message mismatch: expected {message}, got {bob_plaintext}"
        print(f"✓ Bob read message: {bob_plaintext.decode()}")

        # Step 3: Alice tombstones the box
        print("\n--- Step 3: Alice tombstones the box ---")
        await alice_client.tombstone_box(geometry, write_cap, first_index)
        print("✓ Alice tombstoned the box")

        # Wait for tombstone propagation
        print("--- Waiting for tombstone propagation (30 seconds) ---")
        await asyncio.sleep(30)

        # Step 4: Bob reads again and verifies tombstone
        print("\n--- Step 4: Bob reads again and verifies tombstone ---")
        bob_ciphertext2, bob_next_index2, bob_env_desc2, bob_env_hash2 = await bob_client.encrypt_read(
            read_cap, first_index
        )
        bob_plaintext2 = await bob_client.start_resending_encrypted_message(
            read_cap=read_cap,
            write_cap=None,
            next_message_index=bob_next_index2,
            reply_index=0,
            envelope_descriptor=bob_env_desc2,
            message_ciphertext=bob_ciphertext2,
            envelope_hash=bob_env_hash2
        )

        assert is_tombstone_plaintext(geometry, bob_plaintext2), "Expected tombstone plaintext (all zeros)"
        print("✓ Bob verified tombstone (all zeros)")

        print("\n✅ Tombstoning test passed!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
async def test_tombstone_range():
    """
    Test the tombstone_range API.

    This test verifies:
    1. Alice writes multiple messages to sequential boxes
    2. Alice tombstones a range of boxes
    3. The result shows the correct number of tombstoned boxes

    This mirrors the Go TombstoneRange functionality.
    """
    from katzenpost_thinclient import PigeonholeGeometry

    alice_client = await setup_thin_client()

    try:
        print("\n=== Test: Tombstone Range ===")

        # Create a geometry with a reasonable payload size
        geometry = PigeonholeGeometry(
            max_plaintext_payload_length=1024,
            nike_name="x25519"
        )

        # Create keypair
        seed = os.urandom(32)
        write_cap, read_cap, first_index = await alice_client.new_keypair(seed)
        print("✓ Created keypair")

        # Write 3 messages to sequential boxes
        num_messages = 3
        current_index = first_index

        print(f"\n--- Writing {num_messages} messages ---")
        for i in range(num_messages):
            message = f"Message {i+1} to be tombstoned".encode()
            ciphertext, env_desc, env_hash = await alice_client.encrypt_write(
                message, write_cap, current_index
            )
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash
            )
            print(f"✓ Wrote message {i+1}")

            if i < num_messages - 1:
                current_index = await alice_client.next_message_box_index(current_index)

        # Wait for messages to propagate
        print("--- Waiting for message propagation (30 seconds) ---")
        await asyncio.sleep(30)

        # Tombstone the range
        print(f"\n--- Tombstoning {num_messages} boxes ---")
        result = await alice_client.tombstone_range(geometry, write_cap, first_index, num_messages)

        print(f"✓ Tombstoned {result['tombstoned']} boxes")
        assert result['tombstoned'] == num_messages, f"Expected {num_messages} tombstoned, got {result['tombstoned']}"
        assert 'next' in result, "Result should contain 'next' index"

        print(f"\n✅ Tombstone range test passed! Tombstoned {num_messages} boxes successfully!")

    finally:
        alice_client.stop()

