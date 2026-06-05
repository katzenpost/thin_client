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
from katzenpost_thinclient import (
    ThinClient,
    Config,
    CopyCommandFailedError,
    REPLICA_ERROR_BOX_ALREADY_EXISTS,
)


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
    while (
        not client.is_connected() or client.pki_document() is None
    ) and attempts < 30:
        await asyncio.sleep(1)
        attempts += 1

    if not client.is_connected():
        raise Exception("Daemon failed to connect to mixnet within 30 seconds")

    if client.pki_document() is None:
        raise Exception("PKI document not received within 30 seconds")

    print("✅ Daemon connected to mixnet, using current PKI document")

    return client


async def await_box_propagated(client, read_cap):
    """Block until the box at the read cap's position is readable.

    The default ARQ behaviour auto-retries on BoxIDNotFound, so this
    single read returns only once the box has propagated to a serving
    replica, a deterministic replacement for a blind propagation
    sleep. For a sequentially written stream, pass the read cap at the
    last written box: the boxes before it were written earlier and so
    have had at least as long to settle, and this avoids the traffic of
    re-reading every box.
    """
    read_request = await client.encrypt_read(read_cap)
    await client.start_resending_encrypted_message(
        read_cap=read_cap,
        write_cap=None,
        reply_index=0,
        envelope_descriptor=read_request.envelope_descriptor,
        message_ciphertext=read_request.message_ciphertext,
        envelope_hash=read_request.envelope_hash,
    )


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
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
        alice_keypair = await alice_client.new_keypair(alice_seed)
        print(f"✓ Alice created WriteCap and derived ReadCap for Bob")

        # Step 2: Alice encrypts a message for Bob
        print("\n--- Step 2: Alice encrypts message ---")
        alice_message = b"Bob, the eagle has landed. Rendezvous at dawn. Bring the package and await further instructions."
        print(f"Alice's message: {alice_message.decode()}")

        alice_result = await alice_client.encrypt_write(
            alice_message, alice_keypair.write_cap
        )
        print(
            f"✓ Alice encrypted message (ciphertext: {len(alice_result.message_ciphertext)} bytes)"
        )

        # Step 3: Alice sends the encrypted message via start_resending_encrypted_message
        print("\n--- Step 3: Alice sends encrypted message to courier/replicas ---")
        reply_index = 0

        alice_plaintext = (
            await alice_client.start_resending_encrypted_message(
                read_cap=None,  # None for write operations
                write_cap=alice_keypair.write_cap,
                reply_index=reply_index,
                envelope_descriptor=alice_result.envelope_descriptor,
                message_ciphertext=alice_result.message_ciphertext,
                envelope_hash=alice_result.envelope_hash,
            )
        ).plaintext

        # For write operations, plaintext should be empty (ACK only)
        print(
            f"✓ Alice received ACK (plaintext length: {len(alice_plaintext) if alice_plaintext else 0})"
        )

        # No propagation sleep: Bob's read below uses the default ARQ
        # behaviour, which auto-retries on BoxIDNotFound and so returns
        # only once the box has propagated. The read is itself the gate.

        # Step 4: Bob encrypts a read request
        print("\n--- Step 4: Bob encrypts read request ---")
        bob_result = await bob_client.encrypt_read(alice_keypair.read_cap)
        print(
            f"✓ Bob encrypted read request (ciphertext: {len(bob_result.message_ciphertext)} bytes)"
        )

        # Step 5: Bob sends the read request and receives Alice's encrypted message
        print("\n--- Step 5: Bob sends read request and receives encrypted message ---")
        bob_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=alice_keypair.read_cap,
                write_cap=None,  # None for read operations
                reply_index=reply_index,
                envelope_descriptor=bob_result.envelope_descriptor,
                message_ciphertext=bob_result.message_ciphertext,
                envelope_hash=bob_result.envelope_hash,
            )
        ).plaintext

        # Step 6: Verify Bob received Alice's message
        print(f"\n--- Step 6: Verify received message ---")
        print(f"Bob received: {bob_plaintext.decode() if bob_plaintext else '(empty)'}")

        assert bob_plaintext == alice_message, (
            f"Message mismatch! Expected: {alice_message}, Got: {bob_plaintext}"
        )

        print(
            "✅ Complete workflow test passed - Bob successfully received Alice's message!"
        )

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
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
        alice_keypair = await alice_client.new_keypair(alice_seed)
        print(f"✓ Alice created keypair")

        num_messages = 3
        messages = [
            b"Message 1: The package has been delivered.",
            b"Message 2: Proceed to the safe house.",
            b"Message 3: Mission accomplished.",
        ]

        # Track current caps for Alice and Bob; each embeds its box position
        alice_write_cap = alice_keypair.write_cap
        bob_read_cap = alice_keypair.read_cap

        for i, message in enumerate(messages):
            print(f"\n--- Message {i + 1}/{num_messages} ---")
            print(f"Alice: Encrypting message {i + 1}: {message.decode()}")

            # Alice encrypts and sends message
            write_result = await alice_client.encrypt_write(message, alice_write_cap)

            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=alice_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"Alice: Started resending message {i + 1}")

            # No propagation sleep: Bob's ARQ read below auto-retries
            # on BoxIDNotFound, gating itself on this message's
            # propagation. The wait was redundant on every iteration.

            # Bob encrypts read request
            print(f"Bob: Encrypting read request for message {i + 1}")
            read_result = await bob_client.encrypt_read(bob_read_cap)

            bob_plaintext = (
                await bob_client.start_resending_encrypted_message(
                    read_cap=bob_read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result.envelope_descriptor,
                    message_ciphertext=read_result.message_ciphertext,
                    envelope_hash=read_result.envelope_hash,
                )
            ).plaintext

            print(
                f"Bob: Received and decrypted message {i + 1}: {bob_plaintext.decode() if bob_plaintext else '(empty)'}"
            )

            # Verify the decrypted message matches
            assert bob_plaintext == message, (
                f"Message {i + 1} mismatch: expected {message}, got {bob_plaintext}"
            )
            print(f"Message {i + 1} verified successfully!")

            # Advance state for next message using the advanced caps from results
            print("Advancing state for next message")
            alice_write_cap = write_result.write_cap
            bob_read_cap = read_result.read_cap

        print(f"\n✅ All {num_messages} messages sent and verified successfully!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_multiple_messages_bulk():
    """
    Test sending multiple messages in bulk: all writes first, then all reads.

    Unlike test_multiple_messages_sequence (which sends one, reads one, repeats),
    this test sends all 3 messages before reading any. This exercises multiple
    concurrent ARQ retry operations on the daemon — the pattern that was broken
    when arqResendCh had a buffer of 2 and silently dropped resends.
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Multiple messages bulk (all writes, then all reads) ===")

        # Alice creates keypair
        alice_seed = os.urandom(32)
        alice_keypair = await alice_client.new_keypair(alice_seed)
        print("✓ Alice created keypair")

        num_messages = 3
        messages = [
            b"Message 1: The package has been delivered.",
            b"Message 2: Proceed to the safe house.",
            b"Message 3: Mission accomplished.",
        ]

        # Alice sends ALL messages first
        alice_write_cap = alice_keypair.write_cap
        for i, message in enumerate(messages):
            print(
                f"\nAlice: Sending message {i + 1}/{num_messages}: {message.decode()}"
            )
            write_result = await alice_client.encrypt_write(message, alice_write_cap)
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=alice_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"✓ Alice sent message {i + 1}")
            alice_write_cap = write_result.write_cap

        # No propagation sleep: each of Bob's per-box reads below is an
        # ARQ read that auto-retries on BoxIDNotFound, gating itself on
        # that box's propagation.

        # Bob reads ALL messages
        bob_read_cap = alice_keypair.read_cap
        for i in range(num_messages):
            print(f"\nBob: Reading message {i + 1}/{num_messages}")
            read_result = await bob_client.encrypt_read(bob_read_cap)
            bob_plaintext = (
                await bob_client.start_resending_encrypted_message(
                    read_cap=bob_read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result.envelope_descriptor,
                    message_ciphertext=read_result.message_ciphertext,
                    envelope_hash=read_result.envelope_hash,
                )
            ).plaintext

            print(
                f"Bob: Received message {i + 1}: {bob_plaintext.decode() if bob_plaintext else '(empty)'}"
            )
            assert bob_plaintext == messages[i], (
                f"Message {i + 1} mismatch: expected {messages[i]}, got {bob_plaintext}"
            )
            print(f"✓ Message {i + 1} verified!")
            bob_read_cap = read_result.read_cap

        print(
            f"\n✅ All {num_messages} messages sent in bulk and verified successfully!"
        )

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
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
        dest_keypair = await alice_client.new_keypair(dest_seed)
        print("✓ Alice created destination WriteCap and derived ReadCap for Bob")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_keypair = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create a payload spanning a few chunks
        print("\n--- Step 3: Creating chunked payload ---")
        # A few hundred bytes is enough to span several copy stream
        # chunks and so exercise the chunk/reconstruct path; a larger
        # payload only multiplies the boxes the courier must copy and
        # then tombstone, lengthening the test for no added coverage.
        # Use a 4-byte length prefix so Bob knows when to stop reading.
        random_data = os.urandom(512)  # spans a handful of chunks
        # Length-prefix the payload: [4 bytes length][random data]
        large_payload = struct.pack(">I", len(random_data)) + random_data
        print(
            f"✓ Alice created large payload ({len(large_payload)} bytes = 4 byte length prefix + {len(random_data)} bytes data)"
        )

        # Step 4: Create copy stream chunks from the large payload
        print("\n--- Step 4: Creating copy stream chunks from large payload ---")
        result = await alice_client.create_courier_envelopes_from_payload(
            large_payload,
            dest_keypair.write_cap,
            True,
            True,  # is_start, is_last
        )
        assert result.envelopes, (
            "create_courier_envelopes_from_payload returned empty chunks"
        )
        copy_stream_chunks = result.envelopes
        num_chunks = len(copy_stream_chunks)
        print(
            f"✓ Alice created {num_chunks} copy stream chunks from {len(large_payload)} byte payload"
        )

        # Step 5: Write all copy stream chunks to the temporary copy stream
        print("\n--- Step 5: Writing copy stream chunks to temporary channel ---")
        temp_write_cap = temp_keypair.write_cap

        for i, chunk in enumerate(copy_stream_chunks):
            print(
                f"--- Writing copy stream chunk {i + 1}/{num_chunks} to temporary channel ---"
            )

            # Encrypt the chunk for the copy stream
            write_result = await alice_client.encrypt_write(chunk, temp_write_cap)
            print(
                f"✓ Alice encrypted copy stream chunk {i + 1} ({len(chunk)} bytes plaintext -> {len(write_result.message_ciphertext)} bytes ciphertext)"
            )

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"✓ Alice sent copy stream chunk {i + 1} to temporary channel")

            # Advance the write cap for the next chunk.
            temp_write_cap = write_result.write_cap

        # Deterministic ARQ propagation gate in place of a blind sleep.
        print("\n--- Awaiting copy stream propagation (ARQ read of first box) ---")
        await await_box_propagated(alice_client, temp_keypair.read_cap)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_keypair.write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads chunks until we have the full payload (based on length prefix)
        print("\n--- Step 7: Bob reads all chunks and reconstructs payload ---")
        bob_read_cap = dest_keypair.read_cap
        reconstructed_payload = b""
        expected_length = 0
        chunk_num = 0

        while True:
            chunk_num += 1
            print(f"--- Bob reading chunk {chunk_num} ---")

            # Bob encrypts read request
            read_result = await bob_client.encrypt_read(bob_read_cap)
            print(f"✓ Bob encrypted read request {chunk_num}")

            # Bob sends read request and receives chunk
            bob_plaintext = (
                await bob_client.start_resending_encrypted_message(
                    read_cap=bob_read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result.envelope_descriptor,
                    message_ciphertext=read_result.message_ciphertext,
                    envelope_hash=read_result.envelope_hash,
                )
            ).plaintext
            assert bob_plaintext, f"Bob: Failed to receive chunk {chunk_num}"
            print(
                f"✓ Bob received and decrypted chunk {chunk_num} ({len(bob_plaintext)} bytes)"
            )

            # Append chunk to reconstructed payload
            reconstructed_payload += bob_plaintext

            # Extract expected length from the first 4 bytes once we have them
            if expected_length == 0 and len(reconstructed_payload) >= 4:
                expected_length = struct.unpack(">I", reconstructed_payload[:4])[0]
                print(
                    f"✓ Bob: Expected payload length is {expected_length} bytes (+ 4 byte prefix = {expected_length + 4} total)"
                )

            # Check if we have the full payload (4 byte prefix + expected_length bytes)
            if (
                expected_length > 0
                and len(reconstructed_payload) >= expected_length + 4
            ):
                print(f"✓ Bob: Received full payload after {chunk_num} chunks")
                break

            # Advance to next chunk
            bob_read_cap = read_result.read_cap

        # Verify the reconstructed payload matches the original
        print(
            f"\n--- Verifying reconstructed payload ({len(reconstructed_payload)} bytes) ---"
        )
        assert reconstructed_payload == large_payload, (
            "Reconstructed payload doesn't match original"
        )
        print(
            f"✅ CreateCourierEnvelopesFromPayload test passed! Large payload ({len(random_data)} bytes data) encoded into {num_chunks} copy stream chunks and reconstructed successfully!"
        )

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
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
        chan1_keypair = await alice_client.new_keypair(chan1_seed)
        print("✓ Alice created Channel 1 (WriteCap and ReadCap)")

        # Channel 2
        chan2_seed = os.urandom(32)
        chan2_keypair = await alice_client.new_keypair(chan2_seed)
        print("✓ Alice created Channel 2 (WriteCap and ReadCap)")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_keypair = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create two payloads - one for each destination channel
        print("\n--- Step 3: Creating payloads for each channel ---")
        payload1 = b"This is the secret message for Channel 1. It contains important information."
        print(f"✓ Alice created payload1 for Channel 1 ({len(payload1)} bytes)")
        payload2 = b"This is the confidential data for Channel 2. Handle with care and discretion."
        print(f"✓ Alice created payload2 for Channel 2 ({len(payload2)} bytes)")

        # Step 4: Create copy stream chunks for both channels
        print("\n--- Step 4: Creating copy stream chunks for both channels ---")

        # First call: payload1 -> channel 1 (is_start=True, is_last=False)
        result1 = await alice_client.create_courier_envelopes_from_payload(
            payload1, chan1_keypair.write_cap, True, False
        )
        assert result1.envelopes, (
            "create_courier_envelopes_from_payload returned empty chunks for channel 1"
        )
        print(f"✓ Alice created {len(result1.envelopes)} chunks for Channel 1")

        # Second call: payload2 -> channel 2 (is_start=False, is_last=True)
        result2 = await alice_client.create_courier_envelopes_from_payload(
            payload2, chan2_keypair.write_cap, False, True
        )
        assert result2.envelopes, (
            "create_courier_envelopes_from_payload returned empty chunks for channel 2"
        )
        print(f"✓ Alice created {len(result2.envelopes)} chunks for Channel 2")

        # Combine all chunks
        all_chunks = result1.envelopes + result2.envelopes
        print(f"✓ Alice total chunks to write to temp channel: {len(all_chunks)}")

        # Step 5: Write all copy stream chunks to the temporary channel
        print("\n--- Step 5: Writing all chunks to temporary channel ---")
        temp_write_cap = temp_keypair.write_cap

        for i, chunk in enumerate(all_chunks):
            print(
                f"--- Writing chunk {i + 1}/{len(all_chunks)} to temporary channel ---"
            )

            # Encrypt the chunk for the copy stream
            write_result = await alice_client.encrypt_write(chunk, temp_write_cap)
            print(
                f"✓ Alice encrypted chunk {i + 1} ({len(chunk)} bytes plaintext -> {len(write_result.message_ciphertext)} bytes ciphertext)"
            )

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"✓ Alice sent chunk {i + 1} to temporary channel")

            # Advance the write cap for the next chunk.
            temp_write_cap = write_result.write_cap

        # Deterministic ARQ propagation gate in place of a blind sleep.
        print("\n--- Awaiting copy stream propagation (ARQ read of first box) ---")
        await await_box_propagated(alice_client, temp_keypair.read_cap)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_keypair.write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads from both channels and verifies payloads
        print("\n--- Step 7: Bob reads from both channels ---")

        # Read from Channel 1
        print("--- Bob reading from Channel 1 ---")
        bob1_read_result = await bob_client.encrypt_read(chan1_keypair.read_cap)
        assert bob1_read_result.message_ciphertext, (
            "Bob: EncryptRead returned empty ciphertext for Channel 1"
        )

        bob1_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=chan1_keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=bob1_read_result.envelope_descriptor,
                message_ciphertext=bob1_read_result.message_ciphertext,
                envelope_hash=bob1_read_result.envelope_hash,
            )
        ).plaintext
        assert bob1_plaintext, "Bob: Failed to receive data from Channel 1"
        print(
            f"✓ Bob received from Channel 1: {bob1_plaintext.decode()} ({len(bob1_plaintext)} bytes)"
        )

        # Verify Channel 1 payload
        assert bob1_plaintext == payload1, "Channel 1 payload doesn't match"
        print("✓ Channel 1 payload verified!")

        # Read from Channel 2
        print("--- Bob reading from Channel 2 ---")
        bob2_read_result = await bob_client.encrypt_read(chan2_keypair.read_cap)
        assert bob2_read_result.message_ciphertext, (
            "Bob: EncryptRead returned empty ciphertext for Channel 2"
        )

        bob2_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=chan2_keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=bob2_read_result.envelope_descriptor,
                message_ciphertext=bob2_read_result.message_ciphertext,
                envelope_hash=bob2_read_result.envelope_hash,
            )
        ).plaintext
        assert bob2_plaintext, "Bob: Failed to receive data from Channel 2"
        print(
            f"✓ Bob received from Channel 2: {bob2_plaintext.decode()} ({len(bob2_plaintext)} bytes)"
        )

        # Verify Channel 2 payload
        assert bob2_plaintext == payload2, "Channel 2 payload doesn't match"
        print("✓ Channel 2 payload verified!")

        print(
            "\n✅ Multi-channel Copy Command test passed! Payload1 written to Channel 1 and Payload2 written to Channel 2 atomically!"
        )

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_copy_command_multi_channel_efficient():
    """
    Test the space-efficient multi-channel copy command using
    create_courier_envelopes_from_multi_payload which packs envelopes from different
    destinations together without wasting space in the copy stream.

    This test verifies:
    - The create_courier_envelopes_from_multi_payload API works correctly
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
        chan1_keypair = await alice_client.new_keypair(chan1_seed)
        print("✓ Alice created Channel 1 (WriteCap and ReadCap)")

        # Channel 2
        chan2_seed = os.urandom(32)
        chan2_keypair = await alice_client.new_keypair(chan2_seed)
        print("✓ Alice created Channel 2 (WriteCap and ReadCap)")

        # Step 2: Alice creates temporary copy stream
        print("\n--- Step 2: Alice creates temporary copy stream ---")
        temp_seed = os.urandom(32)
        temp_keypair = await alice_client.new_keypair(temp_seed)
        print("✓ Alice created temporary copy stream WriteCap")

        # Step 3: Create two payloads - one for each destination channel
        print("\n--- Step 3: Creating payloads for each channel ---")
        payload1 = b"This is the secret message for Channel 1 using the efficient multi-channel API."
        print(f"✓ Alice created payload1 for Channel 1 ({len(payload1)} bytes)")
        payload2 = b"This is the confidential data for Channel 2 packed efficiently with payload1."
        print(f"✓ Alice created payload2 for Channel 2 ({len(payload2)} bytes)")

        # Step 4: Create copy stream chunks using efficient multi-destination API
        print(
            "\n--- Step 4: Creating copy stream chunks using efficient multi-destination API ---"
        )
        # Create destinations list with both payloads
        destinations = [
            {
                "payload": payload1,
                "write_cap": chan1_keypair.write_cap,
            },
            {
                "payload": payload2,
                "write_cap": chan2_keypair.write_cap,
            },
        ]

        # Single call packs all envelopes efficiently
        result = await alice_client.create_courier_envelopes_from_multi_payload(
            destinations, is_start=True, is_last=True
        )
        assert result.envelopes, (
            "create_courier_envelopes_from_multi_payload returned empty chunks"
        )
        all_chunks = result.envelopes
        print(
            f"✓ Alice created {len(all_chunks)} chunks for both channels (packed efficiently)"
        )

        # Step 5: Write all copy stream chunks to the temporary channel
        print("\n--- Step 5: Writing all chunks to temporary channel ---")
        temp_write_cap = temp_keypair.write_cap

        for i, chunk in enumerate(all_chunks):
            print(
                f"--- Writing chunk {i + 1}/{len(all_chunks)} to temporary channel ---"
            )

            # Encrypt the chunk for the copy stream
            write_result = await alice_client.encrypt_write(chunk, temp_write_cap)
            print(
                f"✓ Alice encrypted chunk {i + 1} ({len(chunk)} bytes plaintext -> {len(write_result.message_ciphertext)} bytes ciphertext)"
            )

            # Send the encrypted chunk to the copy stream
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"✓ Alice sent chunk {i + 1} to temporary channel")

            # Advance the write cap for the next chunk.
            temp_write_cap = write_result.write_cap

        # Deterministic ARQ propagation gate in place of a blind sleep.
        print("\n--- Awaiting copy stream propagation (ARQ read of first box) ---")
        await await_box_propagated(alice_client, temp_keypair.read_cap)

        # Step 6: Send Copy command to courier using ARQ
        print("\n--- Step 6: Sending Copy command to courier via ARQ ---")
        await alice_client.start_resending_copy_command(temp_keypair.write_cap)
        print("✓ Alice copy command completed successfully via ARQ")

        # Step 7: Bob reads from both channels and verifies payloads
        print("\n--- Step 7: Bob reads from both channels ---")

        # Read from Channel 1
        print("--- Bob reading from Channel 1 ---")
        bob1_read_result = await bob_client.encrypt_read(chan1_keypair.read_cap)

        bob1_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=chan1_keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=bob1_read_result.envelope_descriptor,
                message_ciphertext=bob1_read_result.message_ciphertext,
                envelope_hash=bob1_read_result.envelope_hash,
            )
        ).plaintext
        assert bob1_plaintext, "Bob: Failed to receive data from Channel 1"
        print(
            f"✓ Bob received from Channel 1: {bob1_plaintext.decode()} ({len(bob1_plaintext)} bytes)"
        )
        assert bob1_plaintext == payload1, "Channel 1 payload doesn't match"
        print("✓ Channel 1 payload verified!")

        # Read from Channel 2
        print("--- Bob reading from Channel 2 ---")
        bob2_read_result = await bob_client.encrypt_read(chan2_keypair.read_cap)

        bob2_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=chan2_keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=bob2_read_result.envelope_descriptor,
                message_ciphertext=bob2_read_result.message_ciphertext,
                envelope_hash=bob2_read_result.envelope_hash,
            )
        ).plaintext
        assert bob2_plaintext, "Bob: Failed to receive data from Channel 2"
        print(
            f"✓ Bob received from Channel 2: {bob2_plaintext.decode()} ({len(bob2_plaintext)} bytes)"
        )
        assert bob2_plaintext == payload2, "Channel 2 payload doesn't match"
        print("✓ Channel 2 payload verified!")

        print(
            "\n✅ Efficient multi-channel Copy Command test passed! Both payloads packed efficiently and delivered to correct channels!"
        )

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
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
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Tombstoning ===")

        # Create keypair
        seed = os.urandom(32)
        keypair = await alice_client.new_keypair(seed)
        print("✓ Created keypair")

        # Step 1: Alice writes a message
        print("\n--- Step 1: Alice writes a message ---")
        message = b"Secret message that will be tombstoned"
        write_result = await alice_client.encrypt_write(message, keypair.write_cap)

        await alice_client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=keypair.write_cap,
            reply_index=0,
            envelope_descriptor=write_result.envelope_descriptor,
            message_ciphertext=write_result.message_ciphertext,
            envelope_hash=write_result.envelope_hash,
        )
        print("✓ Alice wrote message")

        # No propagation sleep: Bob's ARQ read below auto-retries on
        # BoxIDNotFound and so gates itself on propagation.

        # Step 2: Bob reads and verifies
        print("\n--- Step 2: Bob reads and verifies ---")
        read_result = await bob_client.encrypt_read(keypair.read_cap)
        bob_plaintext = (
            await bob_client.start_resending_encrypted_message(
                read_cap=keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
        ).plaintext
        assert bob_plaintext == message, (
            f"Message mismatch: expected {message}, got {bob_plaintext}"
        )
        print(f"✓ Bob read message: {bob_plaintext.decode()}")

        # Step 3: Alice tombstones the box using tombstone_range with max_count=1
        print("\n--- Step 3: Alice tombstones the box ---")
        tomb_range_result = await alice_client.tombstone_range(
            keypair.write_cap, keypair.write_cap, 1
        )
        assert len(tomb_range_result.envelopes) == 1, "Expected 1 tombstone envelope"
        tomb_env = tomb_range_result.envelopes[0]
        await alice_client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=keypair.write_cap,
            reply_index=None,
            envelope_descriptor=tomb_env.envelope_descriptor,
            message_ciphertext=tomb_env.message_ciphertext,
            envelope_hash=tomb_env.envelope_hash,
        )
        print("✓ Alice tombstoned the box")

        # Step 4: Bob polls for tombstone with retries
        print("\n--- Step 4: Bob polls for tombstone ---")
        from katzenpost_thinclient import TombstoneError

        max_attempts = 6
        poll_interval = 10
        tombstone_verified = False

        for attempt in range(1, max_attempts + 1):
            print(f"Polling for tombstone (attempt {attempt}/{max_attempts})...")
            await asyncio.sleep(poll_interval)

            read_result2 = await bob_client.encrypt_read(keypair.read_cap)
            try:
                await bob_client.start_resending_encrypted_message(
                    read_cap=keypair.read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result2.envelope_descriptor,
                    message_ciphertext=read_result2.message_ciphertext,
                    envelope_hash=read_result2.envelope_hash,
                )
                print(f"  Still seeing original message, retrying...")
            except TombstoneError:
                tombstone_verified = True
                print(f"✓ Bob verified tombstone on attempt {attempt}")
                break

        assert tombstone_verified, (
            f"Tombstone not propagated after {max_attempts} attempts"
        )
        print("\n✅ Tombstoning test passed!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_tombstone_range():
    """
    Test the tombstone_range API.

    This test verifies:
    1. Alice writes multiple messages to consecutive boxes
    2. Bob reads and verifies each message
    3. Alice tombstones all boxes using TombstoneRange
    4. Bob reads again and verifies all boxes are tombstoned

    This mirrors the Go test: TestTombstoneRange
    """
    from katzenpost_thinclient import TombstoneError

    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Tombstone Range ===")

        # Create keypair
        seed = os.urandom(32)
        keypair = await alice_client.new_keypair(seed)
        print("✓ Created keypair")

        # Write 3 messages to consecutive boxes
        num_messages = 3
        messages = [
            b"Message 1 - will be tombstoned",
            b"Message 2 - will be tombstoned",
            b"Message 3 - will be tombstoned",
        ]

        write_cap = keypair.write_cap
        for i, msg in enumerate(messages):
            write_result = await alice_client.encrypt_write(msg, write_cap)
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            print(f"✓ Alice wrote message {i + 1}")
            write_cap = write_result.write_cap

        # No propagation sleep: each per-box ARQ read below auto-retries
        # on BoxIDNotFound, gating itself on that box's propagation.

        # Bob reads and verifies all messages
        read_cap = keypair.read_cap
        for i, expected_msg in enumerate(messages):
            read_result = await bob_client.encrypt_read(read_cap)
            bob_result = (
                await bob_client.start_resending_encrypted_message(
                    read_cap=read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result.envelope_descriptor,
                    message_ciphertext=read_result.message_ciphertext,
                    envelope_hash=read_result.envelope_hash,
                )
            ).plaintext
            assert bob_result == expected_msg, f"Message {i + 1} mismatch"
            print(f"✓ Bob read message {i + 1}: {bob_result.decode()}")
            read_cap = read_result.read_cap

        # Alice tombstones all boxes using TombstoneRange
        print(f"\n--- Creating tombstones for {num_messages} boxes ---")
        result = await alice_client.tombstone_range(
            keypair.write_cap, keypair.write_cap, num_messages
        )

        assert len(result.envelopes) == num_messages, (
            f"Expected {num_messages} envelopes, got {len(result.envelopes)}"
        )
        assert result.next is not None, "Result should contain 'next' index"
        print(f"✓ TombstoneRange created {len(result.envelopes)} envelopes")

        # Send all tombstone envelopes
        for i, envelope in enumerate(result.envelopes):
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=keypair.write_cap,
                reply_index=None,
                envelope_descriptor=envelope.envelope_descriptor,
                message_ciphertext=envelope.message_ciphertext,
                envelope_hash=envelope.envelope_hash,
            )
            print(f"✓ Sent tombstone envelope {i + 1}")

        # Poll for tombstone propagation rather than waiting a fixed
        # interval. These boxes already hold data, so the read does
        # not auto-retry (that is gated on BoxIDNotFound); we reread
        # until it raises TombstoneError. The boxes propagate together,
        # so once the first verifies the rest follow on the first
        # check with no further wait.
        max_attempts = 6
        poll_interval = 10

        async def _box_tombstoned(box_read_cap) -> bool:
            read_result = await bob_client.encrypt_read(box_read_cap)
            try:
                await bob_client.start_resending_encrypted_message(
                    read_cap=box_read_cap,
                    write_cap=None,
                    reply_index=0,
                    envelope_descriptor=read_result.envelope_descriptor,
                    message_ciphertext=read_result.message_ciphertext,
                    envelope_hash=read_result.envelope_hash,
                )
                return False
            except TombstoneError:
                return True

        read_cap = keypair.read_cap
        box_read_caps = []
        for _ in range(num_messages):
            box_read_caps.append(read_cap)
            read_result = await bob_client.encrypt_read(read_cap)
            read_cap = read_result.read_cap

        for i, idx in enumerate(box_read_caps):
            verified = False
            for attempt in range(1, max_attempts + 1):
                if await _box_tombstoned(idx):
                    verified = True
                    print(f"✓ Bob verified tombstone {i + 1} on attempt {attempt}")
                    break
                if attempt < max_attempts:
                    print(f"  Box {i + 1} not yet tombstoned, retrying...")
                    await asyncio.sleep(poll_interval)
            assert verified, f"box {i + 1} not tombstoned after {max_attempts} attempts"

        print(f"\n✅ All {num_messages} boxes successfully tombstoned and verified!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_box_id_not_found_error():
    """
    Test that we receive a BoxIDNotFoundError when reading from a box that doesn't exist.

    This test verifies:
    1. A new keypair is created (but no message is written)
    2. Attempting to read from the non-existent box raises BoxIDNotFoundError
    3. The error can be caught using isinstance() similar to Go's errors.Is()

    This mirrors the Go test: TestBoxIDNotFoundError
    """
    from katzenpost_thinclient import BoxIDNotFoundError

    client = await setup_thin_client()

    try:
        print("\n=== Test: BoxIDNotFoundError ===")

        # Create a fresh keypair - but do NOT write anything to it
        seed = os.urandom(32)
        keypair = await client.new_keypair(seed)
        print("✓ Created fresh keypair (no messages written)")

        # Encrypt a read request for the non-existent box
        read_result = await client.encrypt_read(keypair.read_cap)
        print("✓ Encrypted read request for non-existent box")

        # Attempt to read - this should raise BoxIDNotFoundError
        # Use start_resending_encrypted_message_no_retry to get immediate error without retries
        print("--- Attempting to read from non-existent box ---")
        try:
            await client.start_resending_encrypted_message_no_retry(
                read_cap=keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
            # If we get here, the test failed - we expected an error
            raise AssertionError(
                "Expected BoxIDNotFoundError but no exception was raised"
            )
        except BoxIDNotFoundError as e:
            # This is the expected case
            print(f"✓ Received expected BoxIDNotFoundError: {e}")
            print("✅ BoxIDNotFoundError test passed!")

    finally:
        client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_box_already_exists_error():
    """
    Test that we receive a BoxAlreadyExistsError when writing to a box that already has data.

    This test verifies:
    1. A new keypair is created and a message is successfully written
    2. Attempting to write to the same box again raises BoxAlreadyExistsError
    3. The error can be caught using isinstance() similar to Go's errors.Is()

    This mirrors the Go test: TestBoxAlreadyExistsError
    """
    from katzenpost_thinclient import BoxAlreadyExistsError

    client = await setup_thin_client()

    try:
        print("\n=== Test: BoxAlreadyExistsError ===")

        # Create a fresh keypair
        seed = os.urandom(32)
        keypair = await client.new_keypair(seed)
        print("✓ Created keypair")

        # First write - should succeed
        print("--- First write (should succeed) ---")
        message1 = b"First message - this should work"
        write_result1 = await client.encrypt_write(message1, keypair.write_cap)
        print("✓ Encrypted first message")

        await client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=keypair.write_cap,
            reply_index=None,
            envelope_descriptor=write_result1.envelope_descriptor,
            message_ciphertext=write_result1.message_ciphertext,
            envelope_hash=write_result1.envelope_hash,
        )
        print("✓ First write succeeded")

        # Wait for propagation
        print("Waiting for message propagation...")
        await asyncio.sleep(5)

        # Second write to the SAME box - should fail with BoxAlreadyExists
        print("--- Second write to same box (should fail) ---")
        message2 = b"Second message - this should fail"
        write_result2 = await client.encrypt_write(message2, keypair.write_cap)
        print("✓ Encrypted second message")

        # Send the second write - should fail with BoxAlreadyExists
        # Use start_resending_encrypted_message_return_box_exists to get the error instead of
        # treating it as idempotent success
        try:
            await client.start_resending_encrypted_message_return_box_exists(
                read_cap=None,
                write_cap=keypair.write_cap,
                reply_index=None,
                envelope_descriptor=write_result2.envelope_descriptor,
                message_ciphertext=write_result2.message_ciphertext,
                envelope_hash=write_result2.envelope_hash,
            )
            # If we get here, the test failed - we expected an error
            raise AssertionError(
                "Expected BoxAlreadyExistsError but no exception was raised"
            )
        except BoxAlreadyExistsError as e:
            # This is the expected case
            print(f"✓ Received expected BoxAlreadyExistsError: {e}")
            print("✅ BoxAlreadyExistsError test passed!")

    finally:
        client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_read_before_write():
    """
    Test race condition where a read is attempted before the corresponding write.
    This verifies that the retry logic in kpclientd works correctly:

    1. Alice and Bob share a keypair (same box ID)
    2. Bob starts reading BEFORE Alice writes (box doesn't exist yet)
    3. Alice writes to the box after a delay
    4. Bob's read should eventually succeed due to retry mechanism

    This mirrors the Go test: TestReadBeforeWrite
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: Read Before Write ===")

        # Create shared keypair
        print("--- Setup: Creating shared keypair ---")
        seed = os.urandom(32)
        alice_keypair = await alice_client.new_keypair(seed)
        print("✓ Created shared keypair")

        # Start Bob's read in a task BEFORE Alice writes
        print("--- Step 1: Bob starts reading (box doesn't exist yet) ---")

        async def bob_read_task():
            """Bob's read - will retry until Alice writes."""
            read_result = await bob_client.encrypt_read(alice_keypair.read_cap)
            result = await bob_client.start_resending_encrypted_message(
                read_cap=alice_keypair.read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
            return result.plaintext

        bob_task = asyncio.create_task(bob_read_task())

        # Wait to ensure Bob's read is in-flight and retrying
        print("--- Step 2: Waiting 5 seconds before Alice writes ---")
        await asyncio.sleep(5)

        # Alice writes the message
        print("--- Step 3: Alice writes message (while Bob is retrying) ---")
        alice_message = b"Hello Bob! I wrote this after you started reading."
        print(
            f"Alice: Writing message ({len(alice_message)} bytes): {alice_message.decode()}"
        )

        write_result = await alice_client.encrypt_write(
            alice_message, alice_keypair.write_cap
        )
        await alice_client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=alice_keypair.write_cap,
            reply_index=0,
            envelope_descriptor=write_result.envelope_descriptor,
            message_ciphertext=write_result.message_ciphertext,
            envelope_hash=write_result.envelope_hash,
        )
        print("Alice: Write completed")

        # Wait for Bob's read to complete
        print("--- Step 4: Waiting for Bob's read to succeed ---")
        bob_plaintext = await asyncio.wait_for(bob_task, timeout=600)

        assert bob_plaintext is not None, "Bob should receive the message"
        assert bob_plaintext == alice_message, (
            f"Message mismatch: expected {alice_message}, got {bob_plaintext}"
        )
        print(f"Bob: Received message: {bob_plaintext.decode()}")
        print("✅ Bob's read succeeded after Alice's write (retry mechanism worked!)")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_copy_onto_already_existing_box_error():
    """
    Test Copy Command when destination box already exists - should fail with error.

    This test verifies:
    1. A message is written to a box
    2. A copy command targeting the same box fails

    This mirrors the Go test: TestCopyOntoAlreadyExistingBoxError
    """
    client = await setup_thin_client()

    try:
        print("\n=== Test: Copy Onto Already Existing Box Error ===")

        # Create keypair
        seed = os.urandom(32)
        keypair = await client.new_keypair(seed)
        print("✓ Created keypair")

        # First write - should succeed
        print("--- First write (should succeed) ---")
        message1 = b"First message - this should work"
        write_result1 = await client.encrypt_write(message1, keypair.write_cap)
        await client.start_resending_encrypted_message(
            read_cap=None,
            write_cap=keypair.write_cap,
            reply_index=None,
            envelope_descriptor=write_result1.envelope_descriptor,
            message_ciphertext=write_result1.message_ciphertext,
            envelope_hash=write_result1.envelope_hash,
        )
        print("✓ First write succeeded")

        # Read-back to confirm the write is visible at the serving replica.
        # The default ARQ behavior auto-retries on BoxIDNotFound, so this
        # returns only once the box is populated — replacing a blind sleep
        # with a deterministic propagation check.
        print("--- Reading back to confirm propagation ---")
        read_request = await client.encrypt_read(keypair.read_cap)
        read_reply = await client.start_resending_encrypted_message(
            read_cap=keypair.read_cap,
            write_cap=None,
            reply_index=0,
            envelope_descriptor=read_request.envelope_descriptor,
            message_ciphertext=read_request.message_ciphertext,
            envelope_hash=read_request.envelope_hash,
        )
        assert read_reply.plaintext == message1, (
            f"expected to read back {message1!r}, got {read_reply.plaintext!r}"
        )
        print("✓ Read-back confirms first write is visible at the replica")

        # Create temporary copy stream
        temp_seed = os.urandom(32)
        temp_keypair = await client.new_keypair(temp_seed)
        print("✓ Created temporary copy stream WriteCap")

        # The copy aborts on the first envelope (the destination box
        # already exists), so a single chunk proves the failure; a
        # larger payload only writes and propagates boxes the copy
        # never reaches.
        small_payload = os.urandom(64)

        # Create copy stream chunks targeting the already-written box
        result = await client.create_courier_envelopes_from_payload(
            small_payload, keypair.write_cap, True, True
        )
        assert result.envelopes, (
            "create_courier_envelopes_from_payload returned empty chunks"
        )
        copy_stream_chunks = result.envelopes
        num_chunks = len(copy_stream_chunks)
        print(f"✓ Created {num_chunks} copy stream chunks")

        # Write all chunks to temporary channel
        temp_write_cap = temp_keypair.write_cap
        for i, chunk in enumerate(copy_stream_chunks):
            print(
                f"--- Writing copy stream chunk {i + 1}/{num_chunks} to temporary channel ---"
            )
            write_result = await client.encrypt_write(chunk, temp_write_cap)
            await client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            temp_write_cap = write_result.write_cap

        # Deterministic ARQ propagation gate in place of a blind sleep.
        print("--- Awaiting copy stream propagation (ARQ read of first box) ---")
        await await_box_propagated(client, temp_keypair.read_cap)

        # Send Copy command - should fail because destination box already exists
        print("--- Sending Copy command (should fail) ---")
        try:
            await client.start_resending_copy_command(temp_keypair.write_cap)
            assert False, "Expected error when copying onto already existing box"
        except CopyCommandFailedError as e:
            print(f"✓ Copy command failed as expected: {e}")
            assert e.replica_error_code == REPLICA_ERROR_BOX_ALREADY_EXISTS, (
                f"expected replica_error_code={REPLICA_ERROR_BOX_ALREADY_EXISTS} "
                f"(BoxAlreadyExists), got {e.replica_error_code}"
            )
            assert e.failed_envelope_index > 0, (
                f"expected failed_envelope_index > 0, got {e.failed_envelope_index}"
            )
            print(
                f"✓ Diagnostic fields populated: "
                f"replica_error_code={e.replica_error_code}, "
                f"failed_envelope_index={e.failed_envelope_index}"
            )
            print("✅ CopyOntoAlreadyExistingBoxError test passed!")

    finally:
        client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_from_payload_multi_call():
    """
    Test calling create_courier_envelopes_from_payload multiple times to send
    a large payload to a single destination stream.

    Exercises the stateless API: explicit is_start/is_last flags,
    and dest_write_cap returned in the result so the caller never does index math.
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: FromPayload Multi-Call ===")

        # Create destination channel
        dest_seed = os.urandom(32)
        dest_keypair = await alice_client.new_keypair(dest_seed)

        # Create temp copy stream channel
        temp_seed = os.urandom(32)
        temp_keypair = await alice_client.new_keypair(temp_seed)

        # This test exercises the three-call stateless API, not large
        # payloads; a small per-call chunk produces one temp element
        # each and keeps every assertion intact while sparing the
        # courier a needless copy-and-tombstone of many boxes.
        chunk_size = 128
        full_payload = os.urandom(3 * chunk_size)
        chunk1 = full_payload[:chunk_size]
        chunk2 = full_payload[chunk_size : 2 * chunk_size]
        chunk3 = full_payload[2 * chunk_size :]

        # Call create_courier_envelopes_from_payload 3 times with new stateless API
        all_temp_elements = []

        # First call: is_start=True, is_last=False
        result1 = await alice_client.create_courier_envelopes_from_payload(
            chunk1, dest_keypair.write_cap, True, False
        )
        assert result1.envelopes
        assert result1.dest_write_cap is not None
        all_temp_elements.extend(result1.envelopes)
        print(f"Call 1: {len(result1.envelopes)} temp elements")

        # Second call: is_start=False, is_last=False — uses dest_write_cap from reply
        result2 = await alice_client.create_courier_envelopes_from_payload(
            chunk2, result1.dest_write_cap, False, False
        )
        assert result2.envelopes
        assert result2.dest_write_cap is not None
        all_temp_elements.extend(result2.envelopes)
        print(f"Call 2: {len(result2.envelopes)} temp elements")

        # Third call: is_start=False, is_last=True
        result3 = await alice_client.create_courier_envelopes_from_payload(
            chunk3, result2.dest_write_cap, False, True
        )
        assert result3.envelopes
        assert result3.dest_write_cap is not None
        all_temp_elements.extend(result3.envelopes)
        print(f"Call 3: {len(result3.envelopes)} temp elements")

        # Write all temp stream elements
        temp_write_cap = temp_keypair.write_cap
        for i, elem in enumerate(all_temp_elements):
            write_result = await alice_client.encrypt_write(elem, temp_write_cap)
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            temp_write_cap = write_result.write_cap
            print(f"Wrote temp element {i + 1}/{len(all_temp_elements)}")

        print("Awaiting temp stream propagation (ARQ read of first box)")
        await await_box_propagated(alice_client, temp_keypair.read_cap)

        # Send copy command
        await alice_client.start_resending_copy_command(temp_keypair.write_cap)
        print("Copy command completed")

        # Bob reads all destination boxes and reconstructs the payload
        bob_read_cap = dest_keypair.read_cap
        reconstructed = b""
        while len(reconstructed) < len(full_payload):
            read_result = await bob_client.encrypt_read(bob_read_cap)
            msg_result = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
            assert msg_result.plaintext
            reconstructed += msg_result.plaintext
            bob_read_cap = read_result.read_cap

        assert reconstructed == full_payload, (
            "Reconstructed payload doesn't match original"
        )
        print("✅ FromPayload multi-call test passed!")

    finally:
        alice_client.stop()
        bob_client.stop()


@pytest.mark.asyncio
@pytest.mark.timeout(3600)
async def test_from_multi_payload_multi_call():
    """
    Test calling create_courier_envelopes_from_multi_payload multiple times,
    writing to two destination channels across two calls.

    Exercises the stateless API with buffer passing and dest_write_caps in the
    result so the caller can continue writing to the same destinations.
    """
    alice_client = await setup_thin_client()
    bob_client = await setup_thin_client()

    try:
        print("\n=== Test: FromMultiPayload Multi-Call ===")

        # Create two destination channels
        chan1_keypair = await alice_client.new_keypair(os.urandom(32))
        chan2_keypair = await alice_client.new_keypair(os.urandom(32))

        # Create temp copy stream channel
        temp_keypair = await alice_client.new_keypair(os.urandom(32))

        # Create payloads — use small payloads that fit in one box each
        payload1a = b"First batch of data for channel 1 - testing multi-call"
        payload2a = b"First batch of data for channel 2 - testing multi-call"
        payload1b = b"Second batch of data for channel 1 - multi-call works"
        payload2b = b"Second batch of data for channel 2 - multi-call works"

        # First call: two destinations, is_start=True, is_last=False
        result1 = await alice_client.create_courier_envelopes_from_multi_payload(
            [
                {"payload": payload1a, "write_cap": chan1_keypair.write_cap},
                {"payload": payload2a, "write_cap": chan2_keypair.write_cap},
            ],
            is_start=True,
            is_last=False,
        )
        assert result1.envelopes
        assert result1.dest_write_caps is not None
        assert len(result1.dest_write_caps) == 2
        print(f"Call 1: {len(result1.envelopes)} temp elements")

        # Second call: same destinations, continue from dest_write_caps, is_last=True
        result2 = await alice_client.create_courier_envelopes_from_multi_payload(
            [
                {"payload": payload1b, "write_cap": result1.dest_write_caps[0]},
                {"payload": payload2b, "write_cap": result1.dest_write_caps[1]},
            ],
            is_start=False,
            is_last=True,
            buffer=result1.buffer,
        )
        assert result2.envelopes
        assert result2.dest_write_caps is not None
        assert len(result2.dest_write_caps) == 2
        print(f"Call 2: {len(result2.envelopes)} temp elements")

        # Write all temp stream elements
        all_elements = result1.envelopes + result2.envelopes
        temp_write_cap = temp_keypair.write_cap
        for i, elem in enumerate(all_elements):
            write_result = await alice_client.encrypt_write(elem, temp_write_cap)
            await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=temp_write_cap,
                reply_index=0,
                envelope_descriptor=write_result.envelope_descriptor,
                message_ciphertext=write_result.message_ciphertext,
                envelope_hash=write_result.envelope_hash,
            )
            temp_write_cap = write_result.write_cap
            print(f"Wrote temp element {i + 1}/{len(all_elements)}")

        print("Awaiting temp stream propagation (ARQ read of first box)")
        await await_box_propagated(alice_client, temp_keypair.read_cap)

        # Send copy command
        await alice_client.start_resending_copy_command(temp_keypair.write_cap)
        print("Copy command completed")

        # Bob reads from channel 1 — expects payload1a + payload1b
        expected_chan1 = payload1a + payload1b
        bob_read_cap = chan1_keypair.read_cap
        chan1_data = b""
        while len(chan1_data) < len(expected_chan1):
            read_result = await bob_client.encrypt_read(bob_read_cap)
            msg_result = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
            assert msg_result.plaintext
            chan1_data += msg_result.plaintext
            bob_read_cap = read_result.read_cap
        assert chan1_data == expected_chan1, "Channel 1 data doesn't match"
        print("Channel 1 verified")

        # Bob reads from channel 2 — expects payload2a + payload2b
        expected_chan2 = payload2a + payload2b
        bob_read_cap = chan2_keypair.read_cap
        chan2_data = b""
        while len(chan2_data) < len(expected_chan2):
            read_result = await bob_client.encrypt_read(bob_read_cap)
            msg_result = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                reply_index=0,
                envelope_descriptor=read_result.envelope_descriptor,
                message_ciphertext=read_result.message_ciphertext,
                envelope_hash=read_result.envelope_hash,
            )
            assert msg_result.plaintext
            chan2_data += msg_result.plaintext
            bob_read_cap = read_result.read_cap
        assert chan2_data == expected_chan2, "Channel 2 data doesn't match"
        print("Channel 2 verified")

        print("✅ FromMultiPayload multi-call test passed!")

    finally:
        alice_client.stop()
        bob_client.stop()
