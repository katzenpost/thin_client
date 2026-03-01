# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Katzenpost Python Thin Client - New Pigeonhole API
===================================================

This module provides the new capability-based Pigeonhole API methods.
These methods use WriteCap/ReadCap keypairs and provide direct
control over the Pigeonhole protocol.
"""

from typing import Tuple, Any, Dict, List

from .core import (
    THIN_CLIENT_SUCCESS,
    thin_client_error_to_string,
    PigeonholeGeometry,
)


# New Pigeonhole API methods - these will be attached to ThinClient class

async def new_keypair(self, seed: bytes) -> "Tuple[bytes, bytes, bytes]":
    """
    Creates a new keypair for use with the Pigeonhole protocol.

    This method generates a WriteCap and ReadCap from the provided seed using
    the BACAP (Blinding-and-Capability) protocol. The WriteCap should be stored
    securely for writing messages, while the ReadCap can be shared with others
    to allow them to read messages.

    Args:
        seed: 32-byte seed used to derive the keypair.

    Returns:
        tuple: (write_cap, read_cap, first_message_index) where:
            - write_cap is the write capability for sending messages
            - read_cap is the read capability that can be shared with recipients
            - first_message_index is the first message index to use when writing

    Raises:
        Exception: If the keypair creation fails.
        ValueError: If seed is not exactly 32 bytes.

    Example:
        >>> import os
        >>> seed = os.urandom(32)
        >>> write_cap, read_cap, first_index = await client.new_keypair(seed)
        >>> # Share read_cap with Bob so he can read messages
        >>> # Store write_cap for sending messages
    """
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")

    query_id = self.new_query_id()

    request = {
        "new_keypair": {
            "query_id": query_id,
            "seed": seed
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error creating keypair: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"new_keypair failed: {error_msg}")

    return reply["write_cap"], reply["read_cap"], reply["first_message_index"]


async def encrypt_read(self, read_cap: bytes, message_box_index: bytes) -> "Tuple[bytes, bytes, bytes, bytes]":
    """
    Encrypts a read operation for a given read capability.

    This method prepares an encrypted read request that can be sent to the
    courier service to retrieve a message from a pigeonhole box. The returned
    ciphertext should be sent via start_resending_encrypted_message.

    Args:
        read_cap: Read capability that grants access to the channel.
        message_box_index: Starting read position for the channel.

    Returns:
        tuple: (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) where:
            - message_ciphertext is the encrypted message to send to courier
            - next_message_index is the next message index for subsequent reads
            - envelope_descriptor is for decrypting the reply
            - envelope_hash is the hash of the courier envelope

    Raises:
        Exception: If the encryption fails.

    Example:
        >>> ciphertext, next_index, env_desc, env_hash = await client.encrypt_read(
        ...     read_cap, message_box_index)
        >>> # Send ciphertext via start_resending_encrypted_message
    """
    query_id = self.new_query_id()

    request = {
        "encrypt_read": {
            "query_id": query_id,
            "read_cap": read_cap,
            "message_box_index": message_box_index
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error encrypting read: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"encrypt_read failed: {error_msg}")

    return (
        reply["message_ciphertext"],
        reply["next_message_index"],
        reply["envelope_descriptor"],
        reply["envelope_hash"]
    )


async def encrypt_write(self, plaintext: bytes, write_cap: bytes, message_box_index: bytes) -> "Tuple[bytes, bytes, bytes]":
    """
    Encrypts a write operation for a given write capability.

    This method prepares an encrypted write request that can be sent to the
    courier service to store a message in a pigeonhole box. The returned
    ciphertext should be sent via start_resending_encrypted_message.

    Args:
        plaintext: The plaintext message to encrypt.
        write_cap: Write capability that grants access to the channel.
        message_box_index: Starting write position for the channel.

    Returns:
        tuple: (message_ciphertext, envelope_descriptor, envelope_hash) where:
            - message_ciphertext is the encrypted message to send to courier
            - envelope_descriptor is for decrypting the reply
            - envelope_hash is the hash of the courier envelope

    Raises:
        Exception: If the encryption fails.

    Example:
        >>> plaintext = b"Hello, Bob!"
        >>> ciphertext, env_desc, env_hash = await client.encrypt_write(
        ...     plaintext, write_cap, message_box_index)
        >>> # Send ciphertext via start_resending_encrypted_message
    """
    query_id = self.new_query_id()

    request = {
        "encrypt_write": {
            "query_id": query_id,
            "plaintext": plaintext,
            "write_cap": write_cap,
            "message_box_index": message_box_index
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error encrypting write: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"encrypt_write failed: {error_msg}")

    return (
        reply["message_ciphertext"],
        reply["envelope_descriptor"],
        reply["envelope_hash"]
    )


async def start_resending_encrypted_message(
    self,
    read_cap: "bytes|None",
    write_cap: "bytes|None",
    next_message_index: "bytes|None",
    reply_index: "int|None",
    envelope_descriptor: bytes,
    message_ciphertext: bytes,
    envelope_hash: bytes
) -> bytes:
    """
    Starts resending an encrypted message via ARQ.

    This method initiates automatic repeat request (ARQ) for an encrypted message,
    which will be resent periodically until either:
    - A reply is received from the courier
    - The message is cancelled via cancel_resending_encrypted_message
    - The client is shut down

    This is used for both read and write operations in the new Pigeonhole API.

    The daemon implements a finite state machine (FSM) for handling the stop-and-wait ARQ protocol:
    - For write operations (write_cap != None, read_cap == None):
      The method waits for an ACK from the courier and returns immediately.
    - For read operations (read_cap != None, write_cap == None):
      The method waits for an ACK from the courier, then the daemon automatically
      sends a new SURB to request the payload, and this method waits for the payload.
      The daemon performs all decryption (MKEM envelope + BACAP payload) and returns
      the fully decrypted plaintext.

    Args:
        read_cap: Read capability (can be None for write operations, required for reads).
        write_cap: Write capability (can be None for read operations, required for writes).
        next_message_index: Next message index for BACAP decryption (required for reads).
        reply_index: Index of the reply to use (typically 0 or 1).
        envelope_descriptor: Serialized envelope descriptor for MKEM decryption.
        message_ciphertext: MKEM-encrypted message to send (from encrypt_read or encrypt_write).
        envelope_hash: Hash of the courier envelope.

    Returns:
        bytes: Fully decrypted plaintext from the reply (for reads) or empty (for writes).

    Raises:
        Exception: If the operation fails. Check error_code for specific errors.

    Example:
        >>> plaintext = await client.start_resending_encrypted_message(
        ...     read_cap, None, next_index, reply_idx, env_desc, ciphertext, env_hash)
        >>> print(f"Received: {plaintext}")
    """
    query_id = self.new_query_id()

    request = {
        "start_resending_encrypted_message": {
            "query_id": query_id,
            "read_cap": read_cap,
            "write_cap": write_cap,
            "next_message_index": next_message_index,
            "reply_index": reply_index,
            "envelope_descriptor": envelope_descriptor,
            "message_ciphertext": message_ciphertext,
            "envelope_hash": envelope_hash
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error starting resending encrypted message: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"start_resending_encrypted_message failed: {error_msg}")

    return reply.get("plaintext", b"")


async def cancel_resending_encrypted_message(self, envelope_hash: bytes) -> None:
    """
    Cancels ARQ resending for an encrypted message.

    This method stops the automatic repeat request (ARQ) for a previously started
    encrypted message transmission. This is useful when:
    - A reply has been received through another channel
    - The operation should be aborted
    - The message is no longer needed

    Args:
        envelope_hash: Hash of the courier envelope to cancel.

    Raises:
        Exception: If the cancellation fails.

    Example:
        >>> await client.cancel_resending_encrypted_message(env_hash)
    """
    query_id = self.new_query_id()

    request = {
        "cancel_resending_encrypted_message": {
            "query_id": query_id,
            "envelope_hash": envelope_hash
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error cancelling resending encrypted message: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"cancel_resending_encrypted_message failed: {error_msg}")


async def next_message_box_index(self, message_box_index: bytes) -> bytes:
    """
    Increments a MessageBoxIndex using the BACAP NextIndex method.

    This method is used when sending multiple messages to different mailboxes using
    the same WriteCap or ReadCap. It properly advances the cryptographic state by:
    - Incrementing the Idx64 counter
    - Deriving new encryption and blinding keys using HKDF
    - Updating the HKDF state for the next iteration

    The daemon handles the cryptographic operations internally, ensuring correct
    BACAP protocol implementation.

    Args:
        message_box_index: Current message box index to increment (as bytes).

    Returns:
        bytes: The next message box index.

    Raises:
        Exception: If the increment operation fails.

    Example:
        >>> current_index = first_message_index
        >>> next_index = await client.next_message_box_index(current_index)
        >>> # Use next_index for the next message
    """
    query_id = self.new_query_id()

    request = {
        "next_message_box_index": {
            "query_id": query_id,
            "message_box_index": message_box_index
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error incrementing message box index: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"next_message_box_index failed: {error_msg}")

    return reply.get("next_message_box_index")


async def start_resending_copy_command(
    self,
    write_cap: bytes,
    courier_identity_hash: "bytes|None" = None,
    courier_queue_id: "bytes|None" = None
) -> None:
    """
    Starts resending a copy command to a courier via ARQ.

    This method instructs a courier to read data from a temporary channel
    (identified by the write_cap) and write it to the destination channel.
    The command is automatically retransmitted until acknowledged.

    If courier_identity_hash and courier_queue_id are both provided,
    the copy command is sent to that specific courier. Otherwise, a
    random courier is selected.

    Args:
        write_cap: Write capability for the temporary channel containing the data.
        courier_identity_hash: Optional identity hash of a specific courier to use.
        courier_queue_id: Optional queue ID for the specified courier. Must be set
                         if courier_identity_hash is set.

    Raises:
        Exception: If the operation fails.

    Example:
        >>> # Send copy command to a random courier
        >>> await client.start_resending_copy_command(temp_write_cap)
        >>> # Send copy command to a specific courier
        >>> await client.start_resending_copy_command(
        ...     temp_write_cap, courier_identity_hash, courier_queue_id)
    """
    query_id = self.new_query_id()

    request_data = {
        "query_id": query_id,
        "write_cap": write_cap,
    }

    if courier_identity_hash is not None:
        request_data["courier_identity_hash"] = courier_identity_hash
    if courier_queue_id is not None:
        request_data["courier_queue_id"] = courier_queue_id

    request = {
        "start_resending_copy_command": request_data
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error starting resending copy command: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"start_resending_copy_command failed: {error_msg}")


async def cancel_resending_copy_command(self, write_cap_hash: bytes) -> None:
    """
    Cancels ARQ resending for a copy command.

    This method stops the automatic repeat request (ARQ) for a previously started
    copy command. Use this when:
    - The copy operation should be aborted
    - The operation is no longer needed
    - You want to clean up pending ARQ operations

    Args:
        write_cap_hash: Hash of the WriteCap used in start_resending_copy_command.

    Raises:
        Exception: If the cancellation fails.

    Example:
        >>> await client.cancel_resending_copy_command(write_cap_hash)
    """
    query_id = self.new_query_id()

    request = {
        "cancel_resending_copy_command": {
            "query_id": query_id,
            "write_cap_hash": write_cap_hash
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error cancelling resending copy command: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"cancel_resending_copy_command failed: {error_msg}")


async def create_courier_envelopes_from_payload(
    self,
    query_id: bytes,
    stream_id: bytes,
    payload: bytes,
    dest_write_cap: bytes,
    dest_start_index: bytes,
    is_last: bool
) -> "List[bytes]":
    """
    Creates multiple CourierEnvelopes from a payload of any size.

    The payload is automatically chunked and each chunk is wrapped in a
    CourierEnvelope. Each returned chunk is a serialized CopyStreamElement
    ready to be written to a box.

    Multiple calls can be made with the same stream_id to build up a stream
    incrementally. The first call creates a new encoder (first element gets
    IsStart=true). The final call should have is_last=True (last element
    gets IsFinal=true).

    Args:
        query_id: 16-byte query identifier for correlating requests and replies.
        stream_id: 16-byte identifier for the encoder instance. All calls for
                  the same stream must use the same stream ID.
        payload: The data to be encoded into courier envelopes.
        dest_write_cap: Write capability for the destination channel.
        dest_start_index: Starting index in the destination channel.
        is_last: Whether this is the last payload in the sequence. When True,
                the final CopyStreamElement will have IsFinal=true and the
                encoder instance will be removed.

    Returns:
        List[bytes]: List of serialized CopyStreamElements, one per chunk.

    Raises:
        Exception: If the envelope creation fails.

    Example:
        >>> query_id = client.new_query_id()
        >>> stream_id = client.new_stream_id()
        >>> envelopes = await client.create_courier_envelopes_from_payload(
        ...     query_id, stream_id, payload, dest_write_cap, dest_start_index, is_last=True)
        >>> for env in envelopes:
        ...     # Write each envelope to the copy stream
        ...     pass
    """

    request = {
        "create_courier_envelopes_from_payload": {
            "query_id": query_id,
            "stream_id": stream_id,
            "payload": payload,
            "dest_write_cap": dest_write_cap,
            "dest_start_index": dest_start_index,
            "is_last": is_last
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error creating courier envelopes from payload: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"create_courier_envelopes_from_payload failed: {error_msg}")

    return reply.get("envelopes", [])


async def create_courier_envelopes_from_payloads(
    self,
    stream_id: bytes,
    destinations: "List[Dict[str, Any]]",
    is_last: bool
) -> "List[bytes]":
    """
    Creates CourierEnvelopes from multiple payloads going to different destinations.

    This is more space-efficient than calling create_courier_envelopes_from_payload
    multiple times because envelopes from different destinations are packed
    together in the copy stream without wasting space.

    Multiple calls can be made with the same stream_id to build up a stream
    incrementally. The first call creates a new encoder (first element gets
    IsStart=true). The final call should have is_last=True (last element
    gets IsFinal=true).

    Args:
        stream_id: 16-byte identifier for the encoder instance. All calls for
                  the same stream must use the same stream ID.
        destinations: List of destination payloads, each a dict with:
                     - "payload": bytes - The data to be written
                     - "write_cap": bytes - Write capability for destination
                     - "start_index": bytes - Starting index in destination
        is_last: Whether this is the last set of payloads in the sequence.
                When True, the final CopyStreamElement will have IsFinal=true
                and the encoder instance will be removed.

    Returns:
        List[bytes]: List of serialized CopyStreamElements containing all
                    courier envelopes from all destinations packed efficiently.

    Raises:
        Exception: If the envelope creation fails.

    Example:
        >>> stream_id = client.new_stream_id()
        >>> destinations = [
        ...     {"payload": data1, "write_cap": cap1, "start_index": idx1},
        ...     {"payload": data2, "write_cap": cap2, "start_index": idx2},
        ... ]
        >>> envelopes = await client.create_courier_envelopes_from_payloads(
        ...     stream_id, destinations, is_last=True)
    """
    query_id = self.new_query_id()

    request = {
        "create_courier_envelopes_from_payloads": {
            "query_id": query_id,
            "stream_id": stream_id,
            "destinations": destinations,
            "is_last": is_last
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error creating courier envelopes from payloads: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"create_courier_envelopes_from_payloads failed: {error_msg}")

    return reply.get("envelopes", [])


async def tombstone_box(
    self,
    geometry: "PigeonholeGeometry",
    write_cap: bytes,
    box_index: bytes
) -> "Tuple[bytes, bytes, bytes]":
    """
    Create an encrypted tombstone for a single pigeonhole box.

    This method creates an encrypted zero-filled payload for overwriting
    the specified box. The caller must send the returned values via
    start_resending_encrypted_message to complete the tombstone operation.

    Args:
        geometry: Pigeonhole geometry defining payload size.
        write_cap: Write capability for the box.
        box_index: Index of the box to tombstone.

    Returns:
        Tuple[bytes, bytes, bytes]: A tuple containing:
            - message_ciphertext: The encrypted tombstone payload.
            - envelope_descriptor: The envelope descriptor.
            - envelope_hash: The envelope hash for cancellation.

    Raises:
        ValueError: If any argument is None or geometry is invalid.
        Exception: If the encrypt operation fails.

    Example:
        >>> geometry = PigeonholeGeometry(max_plaintext_payload_length=1024, nike_name="x25519")
        >>> ciphertext, env_desc, env_hash = await client.tombstone_box(geometry, write_cap, box_index)
        >>> await client.start_resending_encrypted_message(None, write_cap, None, None, env_desc, ciphertext, env_hash)
    """
    if geometry is None:
        raise ValueError("geometry cannot be None")
    geometry.validate()
    if write_cap is None:
        raise ValueError("write_cap cannot be None")
    if box_index is None:
        raise ValueError("box_index cannot be None")

    # Create zero-filled tombstone payload
    tomb = bytes(geometry.max_plaintext_payload_length)

    # Encrypt the tombstone for the target box
    message_ciphertext, envelope_descriptor, envelope_hash = await self.encrypt_write(
        tomb, write_cap, box_index
    )

    return message_ciphertext, envelope_descriptor, envelope_hash


async def tombstone_range(
    self,
    geometry: "PigeonholeGeometry",
    write_cap: bytes,
    start: bytes,
    max_count: int
) -> "Dict[str, Any]":
    """
    Create encrypted tombstones for a range of pigeonhole boxes.

    This method creates encrypted tombstones for up to max_count boxes,
    starting from the specified box index and advancing through consecutive
    indices. The caller must send each envelope via start_resending_encrypted_message
    to complete the tombstone operations.

    If an error occurs during the operation, a partial result is returned
    containing the envelopes created so far and the next index.

    Args:
        geometry: Pigeonhole geometry defining payload size.
        write_cap: Write capability for the boxes.
        start: Starting MessageBoxIndex.
        max_count: Maximum number of boxes to tombstone.

    Returns:
        Dict[str, Any]: A dictionary with:
            - "envelopes" (List[Dict]): List of envelope dicts, each containing:
                - "message_ciphertext": The encrypted tombstone payload.
                - "envelope_descriptor": The envelope descriptor.
                - "envelope_hash": The envelope hash for cancellation.
                - "box_index": The box index this envelope is for.
            - "next" (bytes): The next MessageBoxIndex after the last processed.

    Raises:
        ValueError: If geometry, write_cap, or start is None, or if geometry is invalid.

    Example:
        >>> geometry = PigeonholeGeometry(max_plaintext_payload_length=1024, nike_name="x25519")
        >>> result = await client.tombstone_range(geometry, write_cap, start_index, 10)
        >>> for envelope in result["envelopes"]:
        ...     await client.start_resending_encrypted_message(
        ...         None, write_cap, None, None,
        ...         envelope["envelope_descriptor"],
        ...         envelope["message_ciphertext"],
        ...         envelope["envelope_hash"])
    """
    if geometry is None:
        raise ValueError("geometry cannot be None")
    geometry.validate()
    if write_cap is None:
        raise ValueError("write_cap cannot be None")
    if start is None:
        raise ValueError("start index cannot be None")
    if max_count == 0:
        return {"envelopes": [], "next": start}

    cur = start
    envelopes = []

    while len(envelopes) < max_count:
        try:
            message_ciphertext, envelope_descriptor, envelope_hash = await self.tombstone_box(
                geometry, write_cap, cur
            )
            envelopes.append({
                "message_ciphertext": message_ciphertext,
                "envelope_descriptor": envelope_descriptor,
                "envelope_hash": envelope_hash,
                "box_index": cur,
            })
        except Exception as e:
            self.logger.error(f"Error creating tombstone for box at index {len(envelopes)}: {e}")
            return {"envelopes": envelopes, "next": cur, "error": str(e)}

        try:
            cur = await self.next_message_box_index(cur)
        except Exception as e:
            self.logger.error(f"Error getting next index after creating tombstone: {e}")
            return {"envelopes": envelopes, "next": cur, "error": str(e)}

    return {"envelopes": envelopes, "next": cur}

