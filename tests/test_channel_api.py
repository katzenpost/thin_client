# SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Test suite for the Katzenpost Python thin client channel API.

This test is equivalent to the Go TestDockerCourierServiceNewThinclientAPI
and verifies real end-to-end channel functionality using the courier service.
"""

import asyncio
import pytest
import os
import time
import hashlib

from katzenpost_thinclient import ThinClient, Config, find_services


class ChannelTestState:
    """State management for channel tests."""
    
    def __init__(self):
        self.alice_replies = []
        self.bob_replies = []
        self.alice_events = []
        self.bob_events = []
        self.alice_reply_event = asyncio.Event()
        self.bob_reply_event = asyncio.Event()
    
    def alice_reply_handler(self, event):
        """Handle Alice's message replies."""
        print(f"Alice received reply: {event}")
        self.alice_replies.append(event)
        self.alice_events.append(event)
        self.alice_reply_event.set()
    
    def bob_reply_handler(self, event):
        """Handle Bob's message replies."""
        print(f"🎯 Bob received reply: {event}")
        self.bob_replies.append(event)
        self.bob_events.append(event)
        self.bob_reply_event.set()

    def bob_sent_handler(self, event):
        """Handle Bob's message sent events."""
        print(f"📤 Bob message sent: {event}")
        self.bob_events.append(event)

    def alice_sent_handler(self, event):
        """Handle Alice's message sent events."""
        print(f"📤 Alice message sent: {event}")
        self.alice_events.append(event)
    
    def alice_connection_handler(self, event):
        """Handle Alice's connection status events."""
        print(f"Alice connection status: {event}")
        self.alice_events.append(event)
    
    def bob_connection_handler(self, event):
        """Handle Bob's connection status events."""
        print(f"Bob connection status: {event}")
        self.bob_events.append(event)


async def send_query_and_wait(client, channel_id, message_payload, node_hash, queue_id, state):
    """
    Send a channel query and wait for the reply with retry logic.
    Python equivalent of the Go sendQueryAndWait function.

    Args:
        client: The thin client instance
        channel_id: The channel ID for the query
        message_payload: The message payload to send
        node_hash: Destination node hash
        queue_id: Destination queue ID
        state: Test state object to track replies

    Returns:
        The received payload bytes or None if all attempts failed
    """
    max_retries = 5
    retry_delay = 3.0  # seconds
    reply_timeout = 15.0  # timeout per attempt

    for attempt in range(1, max_retries + 1):
        print(f"Sending channel query (attempt {attempt}/{max_retries})")

        # Clear the reply event and reset state before sending
        client.reply_received_event.clear()
        initial_reply_count = len(state.bob_replies)

        # Send the channel query
        client.send_channel_query(channel_id, message_payload, node_hash, queue_id)

        # Wait for reply with timeout
        try:
            await asyncio.wait_for(client.await_message_reply(), timeout=reply_timeout)

            # Check if we got a new reply
            if len(state.bob_replies) > initial_reply_count:
                latest_reply = state.bob_replies[-1]
                if 'payload' in latest_reply and latest_reply['payload'] is not None:
                    payload = latest_reply['payload']
                    if len(payload) > 0:
                        print(f"SUCCESS: Received non-empty payload on attempt {attempt} ({len(payload)} bytes)")
                        return payload
                    else:
                        print(f"Received empty payload on attempt {attempt}, retrying...")
                else:
                    print(f"Reply missing payload on attempt {attempt}, retrying...")
            else:
                print(f"No new replies received on attempt {attempt}, retrying...")

        except asyncio.TimeoutError:
            print(f"Timeout on attempt {attempt}")

            # Check if we got a reply via callback even if await_message_reply timed out
            if len(state.bob_replies) > initial_reply_count:
                latest_reply = state.bob_replies[-1]
                if 'payload' in latest_reply and latest_reply['payload'] is not None:
                    payload = latest_reply['payload']
                    if len(payload) > 0:
                        print(f"SUCCESS: Found reply via callback on attempt {attempt} ({len(payload)} bytes)")
                        return payload

        # Retry logic
        if attempt < max_retries:
            print(f"Waiting {retry_delay}s before retry...")
            await asyncio.sleep(retry_delay)
        else:
            print(f"All {max_retries} attempts failed")
            break

    return None





@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.channel
async def test_docker_courier_service_new_thinclient_api():
    """
    Test the new channel API with courier service - Python equivalent of Go TestDockerCourierServiceNewThinclientAPI.
    
    This test:
    1. Creates two thin clients (Alice and Bob)
    2. Alice creates a write channel
    3. Bob creates a read channel using Alice's read capability
    4. Alice writes a message to the channel using write_channel()
    5. Alice sends the write query using send_channel_query()
    6. Bob reads the message using read_channel() and send_channel_query()
    7. Verifies the message was received correctly
    """
    from .conftest import is_daemon_available, get_config_path
    
    # Skip test if daemon is not available
    if not is_daemon_available():
        pytest.skip("Katzenpost client daemon not available")
    
    config_path = get_config_path()
    if not os.path.exists(config_path):
        pytest.skip(f"Config file not found: {config_path}")
    
    # Initialize test state
    state = ChannelTestState()
    
    # Create Alice's client
    alice_cfg = Config(
        config_path,
        on_message_reply=state.alice_reply_handler,
        on_message_sent=state.alice_sent_handler,
        on_connection_status=state.alice_connection_handler
    )
    alice_client = ThinClient(alice_cfg)

    # Create Bob's client
    bob_cfg = Config(
        config_path,
        on_message_reply=state.bob_reply_handler,
        on_message_sent=state.bob_sent_handler,
        on_connection_status=state.bob_connection_handler
    )
    bob_client = ThinClient(bob_cfg)
    
    try:
        # Start both clients
        print("Starting Alice's client...")
        loop = asyncio.get_event_loop()
        await alice_client.start(loop)
        print("Alice's client started successfully")
        
        print("Starting Bob's client...")
        await bob_client.start(loop)
        print("Bob's client started successfully")
        
        # Validate PKI documents
        alice_pki = alice_client.pki_document()
        bob_pki = bob_client.pki_document()
        
        assert alice_pki is not None, "Alice should have a PKI document"
        assert bob_pki is not None, "Bob should have a PKI document"
        assert alice_pki['Epoch'] == bob_pki['Epoch'], "Alice and Bob must use same PKI epoch"
        
        current_epoch = alice_pki['Epoch']
        print(f"Using PKI document for epoch {current_epoch}")
        
        # Find courier service using the library's find_services function
        # Debug the PKI document type and content
        print(f"alice_pki type: {type(alice_pki)}")
        print(f"alice_pki keys: {list(alice_pki.keys()) if isinstance(alice_pki, dict) else 'Not a dict'}")

        # Handle case where pki_document() might return a string instead of dict
        if isinstance(alice_pki, str):
            import json
            try:
                alice_pki_dict = json.loads(alice_pki)
                print("Successfully parsed PKI as JSON")
            except json.JSONDecodeError:
                print("Failed to parse PKI as JSON, trying CBOR")
                import cbor2
                alice_pki_dict = cbor2.loads(alice_pki.encode('utf-8'))
        else:
            alice_pki_dict = alice_pki

        print(f"alice_pki_dict type: {type(alice_pki_dict)}")
        print(f"alice_pki_dict keys: {list(alice_pki_dict.keys()) if isinstance(alice_pki_dict, dict) else 'Not a dict'}")
        print(f"ServiceNodes type: {type(alice_pki_dict['ServiceNodes'])}")
        print(f"ServiceNodes length: {len(alice_pki_dict['ServiceNodes'])}")
        if len(alice_pki_dict['ServiceNodes']) > 0:
            print(f"First ServiceNode type: {type(alice_pki_dict['ServiceNodes'][0])}")

        courier_services = find_services("courier", alice_pki_dict)
        if len(courier_services) == 0:
            raise ValueError("No courier services found")

        # Use the first courier service
        courier_service = courier_services[0]

        # Calculate the node ID hash using Blake2b like Katzenpost does
        identity_key = bytes(courier_service.mix_descriptor['IdentityKey'])
        courier_node_hash = hashlib.blake2b(identity_key, digest_size=32).digest()

        # Get the queue ID
        courier_queue_id = courier_service.recipient_queue_id

        print(f"Found courier service: node_hash={courier_node_hash.hex()[:16]}..., queue_id={courier_queue_id}")
        
        # Alice creates write channel
        print("Alice: Creating write channel")
        alice_channel_id, read_cap, write_cap, next_message_index = await alice_client.create_write_channel()
        print(f"Alice: Created write channel {alice_channel_id}")
        assert alice_channel_id is not None
        assert read_cap is not None
        
        # Bob creates read channel using Alice's read capability
        print("Bob: Creating read channel")
        bob_channel_id, bob_next_message_index = await bob_client.create_read_channel(read_cap)
        print(f"Bob: Created read channel {bob_channel_id}")
        assert bob_channel_id is not None
        
        # Alice writes message
        original_message = b"Hello from Alice to Bob via new channel API!"
        print("Alice: Writing message")
        write_payload, alice_next_index = await alice_client.write_channel(alice_channel_id, original_message)
        assert write_payload is not None
        assert len(write_payload) > 0
        print(f"Alice: Generated write payload ({len(write_payload)} bytes)")
        
        # Alice sends write query via courier using send_channel_query
        print("Alice: Sending write query to courier")
        alice_client.send_channel_query(alice_channel_id, write_payload, courier_node_hash, courier_queue_id)
        print("Alice: Sent write query to courier")

        # Wait for Alice's write operation to complete and message to propagate
        print("Waiting for Alice's write operation to complete...")
        try:
            await asyncio.wait_for(alice_client.await_message_reply(), timeout=30.0)
            print("Alice: Write operation completed!")
        except asyncio.TimeoutError:
            print("Alice: Write operation timed out, but continuing...")

        # Wait additional time for message propagation through the courier
        print("Waiting for message propagation through courier...")
        await asyncio.sleep(10)
        
        # Bob reads message
        print("Bob: Reading message")
        message_id = bob_client.new_message_id()
        read_payload, bob_next_index, used_reply_index = await bob_client.read_channel(bob_channel_id, message_id)
        assert read_payload is not None
        assert len(read_payload) > 0
        print(f"Bob: Generated read payload ({len(read_payload)} bytes)")
        print(f"Bob: Used reply index: {used_reply_index}")
        
        # Bob sends read query and waits for reply using helper function (like Go sendQueryAndWait)
        print("Bob: Sending read query and waiting for reply...")
        received_payload = await send_query_and_wait(bob_client, bob_channel_id, read_payload, courier_node_hash, courier_queue_id, state)

        assert received_payload is not None, "Bob should receive a reply - this should work like the Go test!"
        assert len(received_payload) > 0, "Bob should receive non-empty payload"
        
        # Verify the received message
        print(f"Bob received payload: {len(received_payload)} bytes")

        # Convert to bytes if needed
        if isinstance(received_payload, str):
            received_payload = received_payload.encode('utf-8')

        # The channel API should return the original message directly
        received_message = received_payload

        print(f"Original message: {original_message}")
        print(f"Received message: {received_message}")

        assert received_message == original_message, f"Bob should receive the original message. Expected: {original_message}, Got: {received_message}"

        # Test close_channel functionality
        print("Alice: Closing write channel")
        await alice_client.close_channel(alice_channel_id)
        print(f"Alice: Closed write channel {alice_channel_id}")

        print("Bob: Closing read channel")
        await bob_client.close_channel(bob_channel_id)
        print(f"Bob: Closed read channel {bob_channel_id}")

        print("✅ Test completed successfully - message sent and received via channel API!")
        
    finally:
        # Clean up clients
        print("Cleaning up clients...")
        try:
            if hasattr(alice_client, 'task') and alice_client.task is not None:
                alice_client.stop()
        except Exception as e:
            print(f"Error stopping Alice's client: {e}")
        
        try:
            if hasattr(bob_client, 'task') and bob_client.task is not None:
                bob_client.stop()
        except Exception as e:
            print(f"Error stopping Bob's client: {e}")
        
        print("Cleanup complete")


if __name__ == "__main__":
    # Allow running the test directly
    asyncio.run(test_docker_courier_service_new_thinclient_api())
