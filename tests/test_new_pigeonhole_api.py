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
async def test_encrypt_write_basic():
    """
    Test basic write encryption using encrypt_write.
    
    This test verifies:
    1. A message can be encrypted for writing
    2. Ciphertext, envelope descriptor, envelope hash, and epoch are returned
    3. The returned values have the expected properties
    """
    client = await setup_thin_client()

    try:
        print("\n=== Test: encrypt_write basic functionality ===")
        
        # Generate keypair
        seed = os.urandom(32)
        write_cap, read_cap, first_message_index = await client.new_keypair(seed)
        print(f"✓ Created keypair")

        # Encrypt a message for writing
        plaintext = b"Hello, Bob! This is Alice."
        print(f"Plaintext: {plaintext.decode()}")

        ciphertext, env_desc, env_hash, epoch = await client.encrypt_write(
            plaintext, write_cap, first_message_index
        )

        print(f"✓ Ciphertext size: {len(ciphertext)} bytes")
        print(f"✓ EnvelopeDescriptor size: {len(env_desc)} bytes")
        print(f"✓ EnvelopeHash size: {len(env_hash)} bytes")
        print(f"✓ Epoch: {epoch}")

        # Verify the returned values
        assert len(ciphertext) > 0, "Ciphertext should not be empty"
        assert len(env_desc) > 0, "EnvelopeDescriptor should not be empty"
        assert len(env_hash) == 32, "EnvelopeHash should be 32 bytes"
        assert epoch > 0, "Epoch should be positive"

        print("✅ encrypt_write test completed successfully")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_encrypt_read_basic():
    """
    Test basic read encryption using encrypt_read.
    
    This test verifies:
    1. A read operation can be encrypted
    2. Ciphertext, next index, envelope descriptor, envelope hash, and epoch are returned
    3. The returned values have the expected properties
    """
    client = await setup_thin_client()

    try:
        print("\n=== Test: encrypt_read basic functionality ===")
        
        # Generate keypair
        seed = os.urandom(32)
        write_cap, read_cap, first_message_index = await client.new_keypair(seed)
        print(f"✓ Created keypair")

        # Encrypt a read operation
        ciphertext, next_index, env_desc, env_hash, epoch = await client.encrypt_read(
            read_cap, first_message_index
        )

        print(f"✓ Ciphertext size: {len(ciphertext)} bytes")
        print(f"✓ NextMessageIndex size: {len(next_index)} bytes")
        print(f"✓ EnvelopeDescriptor size: {len(env_desc)} bytes")
        print(f"✓ EnvelopeHash size: {len(env_hash)} bytes")
        print(f"✓ Epoch: {epoch}")

        # Verify the returned values
        assert len(ciphertext) > 0, "Ciphertext should not be empty"
        assert len(next_index) > 0, "NextMessageIndex should not be empty"
        assert len(env_desc) > 0, "EnvelopeDescriptor should not be empty"
        assert len(env_hash) == 32, "EnvelopeHash should be 32 bytes"
        assert epoch > 0, "Epoch should be positive"

        print("✅ encrypt_read test completed successfully")

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

        alice_ciphertext, alice_env_desc, alice_env_hash, alice_epoch = await alice_client.encrypt_write(
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
            envelope_hash=alice_env_hash,
            replica_epoch=alice_epoch
        )

        # For write operations, plaintext should be empty (ACK only)
        print(f"✓ Alice received ACK (plaintext length: {len(alice_plaintext) if alice_plaintext else 0})")

        # Wait for message propagation to storage replicas
        print("\n--- Waiting for message propagation to storage replicas ---")
        await asyncio.sleep(5)

        # Step 4: Bob encrypts a read request
        print("\n--- Step 4: Bob encrypts read request ---")
        bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash, bob_epoch = await bob_client.encrypt_read(
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
            envelope_hash=bob_env_hash,
            replica_epoch=bob_epoch
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
        ciphertext, env_desc, env_hash, epoch = await client.encrypt_write(
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


@pytest.mark.skip(reason="Waiting for increment_message_box_index protocol message implementation")
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
            ciphertext, env_desc, env_hash, epoch = await alice_client.encrypt_write(
                message, alice_write_cap, current_index
            )

            alice_plaintext = await alice_client.start_resending_encrypted_message(
                read_cap=None,
                write_cap=alice_write_cap,
                next_message_index=None,
                reply_index=0,
                envelope_descriptor=env_desc,
                message_ciphertext=ciphertext,
                envelope_hash=env_hash,
                replica_epoch=epoch
            )

            print(f"✓ Message {i+1} sent to index successfully")

            # Increment index for next message
            if i < num_messages - 1:  # Don't increment after last message
                current_index = increment_message_box_index(current_index)
                indices_used.append(current_index)

        print("\n--- Waiting for message propagation ---")
        await asyncio.sleep(5)

        # Bob reads all messages from their respective indices
        print("\n--- Bob reads all messages ---")
        received_messages = []
        bob_current_index = first_index

        for i in range(num_messages):
            print(f"\nReading message {i+1}/{num_messages}...")
            bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash, bob_epoch = await bob_client.encrypt_read(
                bob_read_cap, bob_current_index
            )

            bob_plaintext = await bob_client.start_resending_encrypted_message(
                read_cap=bob_read_cap,
                write_cap=None,
                next_message_index=bob_next_index,
                reply_index=0,
                envelope_descriptor=bob_env_desc,
                message_ciphertext=bob_ciphertext,
                envelope_hash=bob_env_hash,
                replica_epoch=bob_epoch
            )

            print(f"Bob received: {bob_plaintext.decode() if bob_plaintext else '(empty)'}")
            received_messages.append(bob_plaintext)

            # Increment index for next read
            if i < num_messages - 1:
                bob_current_index = increment_message_box_index(bob_current_index)

        # Verify all messages were received correctly
        for i, (sent, received) in enumerate(zip(messages, received_messages)):
            assert received == sent, f"Message {i+1} mismatch: expected {sent}, got {received}"

        print("\n✅ Multiple messages test completed successfully!")
        print(f"✅ All {num_messages} messages sent and received correctly with proper index incrementing!")

    finally:
        alice_client.stop()
        bob_client.stop()

