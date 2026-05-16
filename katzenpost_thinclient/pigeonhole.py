# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Katzenpost Python Thin Client - New Pigeonhole API
===================================================

This module provides the new capability-based Pigeonhole API methods.
These methods use WriteCap/ReadCap keypairs and provide direct
control over the Pigeonhole protocol.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Dict, List

from .core import (
    THIN_CLIENT_SUCCESS,
    thin_client_error_to_string,
    error_code_to_exception,
    copy_reply_to_exception,
    PigeonholeGeometry,
)


@dataclass
class KeypairResult:
    """Result from new_keypair containing the generated capabilities."""
    write_cap: bytes
    read_cap: bytes
    first_message_index: bytes


@dataclass
class EncryptReadResult:
    """Result from encrypt_read containing the encrypted read request."""
    message_ciphertext: bytes
    envelope_descriptor: bytes
    envelope_hash: bytes
    next_message_box_index: bytes


@dataclass
class EncryptWriteResult:
    """Result from encrypt_write containing the encrypted write request."""
    message_ciphertext: bytes
    envelope_descriptor: bytes
    envelope_hash: bytes
    next_message_box_index: bytes


@dataclass
class StartResendingResult:
    """Result from start_resending_encrypted_message and its variants."""
    plaintext: bytes
    """Decrypted message for read operations, or empty bytes for writes."""
    courier_identity_hash: "bytes | None"
    """32-byte hash of the identity key of the courier that handled this message.
    Callers can watch PKI document updates for this courier disappearing from
    consensus and cancel+re-encrypt if needed."""
    courier_queue_id: "bytes | None"
    """Queue ID of the courier that handled this message."""


# New Pigeonhole API methods - these will be attached to ThinClient class


async def new_keypair(self, seed: bytes) -> KeypairResult:
    """
    Creates a new keypair for use with the Pigeonhole protocol.

    This method generates a WriteCap and ReadCap from the provided seed using
    the BACAP (Blinding-and-Capability) protocol. The WriteCap should be stored
    securely for writing messages, while the ReadCap can be shared with others
    to allow them to read messages.

    Args:
        seed: 32-byte seed used to derive the keypair.

    Returns:
        KeypairResult: Contains write_cap, read_cap, and first_message_index.

    Raises:
        Exception: If the keypair creation fails.
        ValueError: If seed is not exactly 32 bytes.

    Example:
        >>> import os
        >>> seed = os.urandom(32)
        >>> result = await client.new_keypair(seed)
        >>> # Share result.read_cap with Bob so he can read messages
        >>> # Store result.write_cap for sending messages
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

    return KeypairResult(
        write_cap=reply["write_cap"],
        read_cap=reply["read_cap"],
        first_message_index=reply["first_message_index"]
    )


async def encrypt_read(self, read_cap: bytes, message_box_index: bytes) -> EncryptReadResult:
    """
    Encrypts a read operation for a given read capability.

    This method prepares an encrypted read request that can be sent to the
    courier service to retrieve a message from a pigeonhole box. The returned
    ciphertext should be sent via start_resending_encrypted_message.

    Args:
        read_cap: Read capability that grants access to the channel.
        message_box_index: Starting read position for the channel.

    Returns:
        EncryptReadResult: Contains message_ciphertext, envelope_descriptor,
            and envelope_hash.

    Raises:
        Exception: If the encryption fails.

    Example:
        >>> result = await client.encrypt_read(read_cap, message_box_index)
        >>> # Send result.message_ciphertext via start_resending_encrypted_message
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

    return EncryptReadResult(
        message_ciphertext=reply["message_ciphertext"],
        envelope_descriptor=reply["envelope_descriptor"],
        envelope_hash=reply["envelope_hash"],
        next_message_box_index=reply["next_message_box_index"]
    )


async def encrypt_write(self, plaintext: bytes, write_cap: bytes, message_box_index: bytes) -> EncryptWriteResult:
    """
    Encrypts a write operation for a given write capability.

    This method prepares an encrypted write request that can be sent to the
    courier service to store a message in a pigeonhole box. The returned
    ciphertext should be sent via start_resending_encrypted_message.

    Plaintext Size Constraint:
        The plaintext must not exceed PigeonholeGeometry.max_plaintext_payload_length
        bytes. The daemon internally adds a 4-byte big-endian length prefix before
        padding and encryption, so the actual wire format is:
        [4-byte length][plaintext][zero padding].

        If the plaintext exceeds the maximum size, the daemon will return
        ThinClientErrorInvalidRequest.

    Args:
        plaintext: The plaintext message to encrypt. Must be at most
            PigeonholeGeometry.max_plaintext_payload_length bytes.
        write_cap: Write capability that grants access to the channel.
        message_box_index: The message box index for this write operation.

    Returns:
        EncryptWriteResult: Contains message_ciphertext, envelope_descriptor,
            and envelope_hash.

    Raises:
        Exception: If the encryption fails (including if plaintext is too large).

    Example:
        >>> plaintext = b"Hello, Bob!"
        >>> result = await client.encrypt_write(plaintext, write_cap, message_box_index)
        >>> # Send result.message_ciphertext via start_resending_encrypted_message
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

    return EncryptWriteResult(
        message_ciphertext=reply["message_ciphertext"],
        envelope_descriptor=reply["envelope_descriptor"],
        envelope_hash=reply["envelope_hash"],
        next_message_box_index=reply["next_message_box_index"]
    )


async def start_resending_encrypted_message(
    self,
    read_cap: "bytes|None",
    write_cap: "bytes|None",
    message_box_index: "bytes|None",
    reply_index: "int|None",
    envelope_descriptor: bytes,
    message_ciphertext: bytes,
    envelope_hash: bytes,
    no_retry_on_box_id_not_found: bool = False,
    no_idempotent_box_already_exists: bool = False
) -> StartResendingResult:
    """
    Starts resending an encrypted message via ARQ.

    This method initiates automatic repeat request (ARQ) for an encrypted message,
    which will be resent periodically until either:
    - A reply is received from the courier
    - The message is cancelled via cancel_resending_encrypted_message
    - The client is shut down

    This is used for both read and write operations in the new Pigeonhole API.

    The daemon implements a finite state machine (FSM) for handling the stop-and-wait ARQ protocol:
    - For default write operations (write_cap != None, read_cap == None,
      no_idempotent_box_already_exists == False):
      The method waits for an ACK from the courier and returns immediately.
      The ACK confirms the courier received the envelope and will dispatch it
      to both shard replicas. This requires only a single round-trip through
      the mixnet.
    - For BoxAlreadyExists-aware writes (no_idempotent_box_already_exists == True):
      The method waits for an ACK, then sends a second SURB to retrieve the
      replica's error code. This requires two round-trips through the mixnet.
    - For read operations (read_cap != None, write_cap == None):
      The method waits for an ACK from the courier, then the daemon automatically
      sends a new SURB to request the payload, and this method waits for the payload.
      The daemon performs all decryption (MKEM envelope + BACAP payload) and returns
      the fully decrypted plaintext.

    Args:
        read_cap: Read capability (can be None for write operations, required for reads).
        write_cap: Write capability (can be None for read operations, required for writes).
        message_box_index: Current message box index being operated on (required for reads).
        reply_index: Index of the reply to use (typically 0 or 1).
        envelope_descriptor: Serialized envelope descriptor for MKEM decryption.
        message_ciphertext: MKEM-encrypted message to send (from encrypt_read or encrypt_write).
        envelope_hash: Hash of the courier envelope.
        no_retry_on_box_id_not_found: If True, BoxIDNotFound errors on reads trigger
            immediate error instead of automatic retries. By default (False), reads
            will retry up to 10 times to handle replication lag. Set to True to get
            immediate BoxIDNotFound error without retries.
        no_idempotent_box_already_exists: If True, BoxAlreadyExists errors on writes are
            returned as errors instead of being treated as idempotent success.
            By default (False), BoxAlreadyExists is treated as success (the write
            already happened). Set to True to detect whether a write was actually
            performed or if the box already existed.

    Returns:
        StartResendingResult: Contains plaintext (decrypted message for reads, empty for
            writes), courier_identity_hash, and courier_queue_id.

    Raises:
        BoxIDNotFoundError: If no_retry_on_box_id_not_found=True and the box does not exist.
        BoxAlreadyExistsError: If no_idempotent_box_already_exists=True and the box
            already contains data.
        Exception: If the operation fails. Check error_code for specific errors.

    Example:
        >>> result = await client.start_resending_encrypted_message(
        ...     read_cap, None, message_box_index, reply_idx, env_desc, ciphertext, env_hash)
        >>> print(f"Received: {result.plaintext}")
    """
    query_id = self.new_query_id()

    request = {
        "start_resending_encrypted_message": {
            "query_id": query_id,
            "read_cap": read_cap,
            "write_cap": write_cap,
            "message_box_index": message_box_index,
            "reply_index": reply_index,
            "envelope_descriptor": envelope_descriptor,
            "message_ciphertext": message_ciphertext,
            "envelope_hash": envelope_hash,
            "no_retry_on_box_id_not_found": no_retry_on_box_id_not_found,
            "no_idempotent_box_already_exists": no_idempotent_box_already_exists
        }
    }

    # Track in-flight request for replay on reconnect to new daemon instance
    tracking_key = bytes(envelope_hash)
    self._in_flight_resends[tracking_key] = request
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error starting resending encrypted message: {e}")
        raise
    finally:
        self._in_flight_resends.pop(tracking_key, None)

    error_code = reply.get('error_code', 0)
    if error_code != THIN_CLIENT_SUCCESS:
        exc = error_code_to_exception(error_code)
        if exc:
            raise exc
        error_msg = thin_client_error_to_string(error_code)
        raise Exception(f"start_resending_encrypted_message failed: {error_msg}")

    return StartResendingResult(
        plaintext=reply.get("plaintext", b""),
        courier_identity_hash=reply.get("courier_identity_hash"),
        courier_queue_id=reply.get("courier_queue_id"),
    )


async def start_resending_encrypted_message_return_box_exists(
    self,
    read_cap: "bytes|None",
    write_cap: "bytes|None",
    message_box_index: "bytes|None",
    reply_index: "int|None",
    envelope_descriptor: bytes,
    message_ciphertext: bytes,
    envelope_hash: bytes
) -> StartResendingResult:
    """
    Behaves exactly like ``start_resending_encrypted_message`` save that
    it raises ``BoxAlreadyExistsError`` when the replica reports the
    destination box has already been written, rather than swallowing the
    condition as idempotent success. Use this when one needs to
    distinguish a fresh write from a repeat: for instance, when
    implementing optimistic concurrency on top of the channel, or when
    establishing whether a particular call actually caused a state
    change at the replica.

    Note that this variant costs an additional mixnet round trip: the
    BoxAlreadyExists code is carried by the replica's reply rather than
    the courier's ACK, so the daemon must dispatch a second SURB before
    it can return the answer.

    As with ``start_resending_encrypted_message``, an in-flight call
    can be cancelled from another task via
    ``cancel_resending_encrypted_message``.

    Args:
        read_cap: Read capability (can be None for write operations, required for reads).
        write_cap: Write capability (can be None for read operations, required for writes).
        message_box_index: Current message box index being operated on (required for reads).
        reply_index: Index of the reply to use (typically 0 or 1).
        envelope_descriptor: Serialized envelope descriptor for MKEM decryption.
        message_ciphertext: MKEM-encrypted message to send (from encrypt_read or encrypt_write).
        envelope_hash: Hash of the courier envelope.

    Returns:
        StartResendingResult: Contains plaintext, courier_identity_hash, and courier_queue_id.

    Raises:
        BoxAlreadyExistsError: If the box already contains data.
        Exception: If the operation fails.

    Example:
        >>> try:
        ...     await client.start_resending_encrypted_message_return_box_exists(
        ...         None, write_cap, None, None, env_desc, ciphertext, env_hash)
        ... except BoxAlreadyExistsError:
        ...     print("Box already has data; write was idempotent")
    """
    return await self.start_resending_encrypted_message(
        read_cap=read_cap,
        write_cap=write_cap,
        message_box_index=message_box_index,
        reply_index=reply_index,
        envelope_descriptor=envelope_descriptor,
        message_ciphertext=message_ciphertext,
        envelope_hash=envelope_hash,
        no_idempotent_box_already_exists=True
    )


async def start_resending_encrypted_message_no_retry(
    self,
    read_cap: "bytes|None",
    write_cap: "bytes|None",
    message_box_index: "bytes|None",
    reply_index: "int|None",
    envelope_descriptor: bytes,
    message_ciphertext: bytes,
    envelope_hash: bytes
) -> StartResendingResult:
    """
    Behaves exactly like ``start_resending_encrypted_message`` save that
    it disables the daemon's automatic retry of ``BoxIDNotFoundError``.
    The caller learns at once that the box is absent rather than waiting
    for replication to settle.

    Use this when polling a box that may not yet have been written: for
    instance, when a reader peeks ahead at a peer's next message before
    that peer has produced it. The regular variant would block until
    the box appeared, which can be many round trips.

    As with ``start_resending_encrypted_message``, an in-flight call
    can be cancelled from another task via
    ``cancel_resending_encrypted_message``.

    Args:
        read_cap: Read capability (can be None for write operations, required for reads).
        write_cap: Write capability (can be None for read operations, required for writes).
        message_box_index: Current message box index being operated on (required for reads).
        reply_index: Index of the reply to use (typically 0 or 1).
        envelope_descriptor: Serialized envelope descriptor for MKEM decryption.
        message_ciphertext: MKEM-encrypted message to send (from encrypt_read or encrypt_write).
        envelope_hash: Hash of the courier envelope.

    Returns:
        StartResendingResult: Contains plaintext, courier_identity_hash, and courier_queue_id.

    Raises:
        BoxIDNotFoundError: If the box does not exist (no automatic retries).
        Exception: If the operation fails.

    Example:
        >>> try:
        ...     result = await client.start_resending_encrypted_message_no_retry(
        ...         read_cap, None, message_box_index, reply_idx, env_desc, ciphertext, env_hash)
        ... except BoxIDNotFoundError:
        ...     print("Box not found; message not yet written")
    """
    return await self.start_resending_encrypted_message(
        read_cap=read_cap,
        write_cap=write_cap,
        message_box_index=message_box_index,
        reply_index=reply_index,
        envelope_descriptor=envelope_descriptor,
        message_ciphertext=message_ciphertext,
        envelope_hash=envelope_hash,
        no_retry_on_box_id_not_found=True
    )


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
    # Remove from in-flight tracking so it won't be replayed on reconnect
    tracking_key = bytes(envelope_hash)
    self._in_flight_resends.pop(tracking_key, None)

    # If disconnected, just remove from tracking — daemon has no state to cancel
    if not self.is_connected():
        return

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


async def get_message_box_index_counter(self, message_box_index: bytes) -> int:
    """
    Return the BACAP Idx64 counter embedded in a MessageBoxIndex.

    Callers that persist MessageBoxIndex blobs across sessions can use this
    to order or compare two indexes — e.g. to detect a duplicate ACK that
    would otherwise regress a write-cap's index — without having to peek at
    the binary layout themselves. The layout (first 8 bytes little-endian)
    is a BACAP implementation detail and must not be relied on outside the
    daemon.

    Args:
        message_box_index: MessageBoxIndex blob (as bytes) whose counter
            should be returned.

    Returns:
        int: The BACAP Idx64 value.

    Raises:
        Exception: If the daemon rejects the request.

    Example:
        >>> current_idx = await client.get_message_box_index_counter(mbi_a)
        >>> next_idx = await client.get_message_box_index_counter(mbi_b)
        >>> if next_idx <= current_idx:
        ...     print("skipping stale ACK")
    """
    query_id = self.new_query_id()

    request = {
        "get_message_box_index_counter": {
            "query_id": query_id,
            "message_box_index": message_box_index,
        }
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error reading message box index counter: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"get_message_box_index_counter failed: {error_msg}")

    return reply.get("counter")


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
    # Compute write cap hash for in-flight tracking (matches daemon-side hash)
    tracking_key = hashlib.blake2b(write_cap, digest_size=32).digest()

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

    # Track in-flight request for replay on reconnect to new daemon instance
    self._in_flight_resends[tracking_key] = request
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error starting resending copy command: {e}")
        raise
    finally:
        self._in_flight_resends.pop(tracking_key, None)

    exc = copy_reply_to_exception(reply)
    if exc is not None:
        raise exc


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
    # Remove from in-flight tracking so it won't be replayed on reconnect
    tracking_key = bytes(write_cap_hash)
    self._in_flight_resends.pop(tracking_key, None)

    # If disconnected, just remove from tracking — daemon has no state to cancel
    if not self.is_connected():
        return

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
    payload: bytes,
    dest_write_cap: bytes,
    dest_start_index: bytes,
    is_start: bool,
    is_last: bool
) -> "CreateEnvelopesResult":
    """
    Packs a payload of arbitrary size (up to 10 MB) into properly sized
    ``CopyStreamElement`` chunks for one destination channel. Each chunk
    is a serialised ``CopyStreamElement``, ready to be written to a box
    via ``encrypt_write`` followed by ``start_resending_encrypted_message``;
    the caller marks the boundaries of the stream with the ``is_start``
    and ``is_last`` flags.

    This method is stateless: no daemon state is kept between calls,
    each invocation runs a fresh encoder and flushes before returning.
    The 10 MB cap guards against accidental memory exhaustion.

    Once the chunks have been written to a temporary copy stream, a
    copy command (``start_resending_copy_command``) is dispatched to a
    courier with the write capability for that temporary stream; the
    courier reads the chunks back and writes each envelope to its
    destination box.

    Multiple calls can target the same destination stream by passing
    ``next_dest_index`` from the previous result as ``dest_start_index``.

    Args:
        payload: The data to be encoded into courier envelopes (max 10MB).
        dest_write_cap: Write capability for the destination channel.
        dest_start_index: Starting index in the destination channel.
        is_start: Whether this is the first call (sets IsStart flag on first element).
        is_last: Whether this is the last call (sets IsFinal flag on last element).

    Returns:
        CreateEnvelopesResult: Contains envelopes and next_dest_index.

    Raises:
        Exception: If the envelope creation fails.
    """
    query_id = self.new_query_id()

    request = {
        "create_courier_envelopes_from_payload": {
            "query_id": query_id,
            "payload": payload,
            "dest_write_cap": dest_write_cap,
            "dest_start_index": dest_start_index,
            "is_start": is_start,
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

    return CreateEnvelopesResult(
        envelopes=reply.get("envelopes", []),
        next_dest_index=reply.get("next_dest_index", None)
    )


async def create_courier_envelopes_from_multi_payload(
    self,
    destinations: "List[Dict[str, Any]]",
    is_start: bool,
    is_last: bool,
    buffer: "bytes | None" = None
) -> "CreateEnvelopesResult":
    """
    Packs payloads bound for several destination channels into a single
    stream of ``CopyStreamElement`` chunks. This is more space-efficient
    than calling ``create_courier_envelopes_from_payload`` once per
    destination, because the shared encoder runs all envelopes together
    rather than padding the final box of each destination independently.

    This method is stateless: the ``buffer`` argument carries any residual
    encoder state across calls in place of daemon-side bookkeeping. Pass
    ``None`` for ``buffer`` on the first call and the ``buffer`` returned
    by the previous call thereafter; set ``is_last`` on the final call so
    the encoder flushes its tail.

    Args:
        destinations: List of destination payloads, each a dict with:
                     - "payload": bytes - The data to be written
                     - "write_cap": bytes - Write capability for destination
                     - "start_index": bytes - Starting index in destination
        is_start: Whether this is the first call in the sequence.
                 When True, the first CopyStreamElement will have IsStart=true.
        is_last: Whether this is the last set of payloads in the sequence.
                When True, the final CopyStreamElement will have IsFinal=true.
        buffer: Residual encoder buffer from a previous call, or None.

    Returns:
        CreateEnvelopesResult: Contains envelopes and buffer for next call.

    Raises:
        Exception: If the envelope creation fails.

    Example:
        >>> destinations = [
        ...     {"payload": data1, "write_cap": cap1, "start_index": idx1},
        ...     {"payload": data2, "write_cap": cap2, "start_index": idx2},
        ... ]
        >>> result = await client.create_courier_envelopes_from_multi_payload(
        ...     destinations, is_start=True, is_last=False)
        >>> # Pass buffer to next call
        >>> result2 = await client.create_courier_envelopes_from_multi_payload(
        ...     more_destinations, is_start=False, is_last=True, buffer=result.buffer)
    """
    query_id = self.new_query_id()

    req_inner = {
        "query_id": query_id,
        "destinations": destinations,
        "is_start": is_start,
        "is_last": is_last,
    }
    if buffer is not None:
        req_inner["buffer"] = buffer

    request = {
        "create_courier_envelopes_from_multi_payload": req_inner
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error creating courier envelopes from payloads: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"create_courier_envelopes_from_multi_payload failed: {error_msg}")

    return CreateEnvelopesResult(
        envelopes=reply.get("envelopes", []),
        buffer=reply.get("buffer", b""),
        next_dest_indices=reply.get("next_dest_indices", None)
    )


@dataclass
class CreateEnvelopesResult:
    """Result of creating courier envelopes."""
    envelopes: "List[bytes]"
    """The serialized CopyStreamElements to send to the network."""
    buffer: bytes = b""
    """The buffered data that hasn't been output yet. Persist this for crash recovery.
    Only populated by create_courier_envelopes_from_multi_payload."""
    next_dest_index: "Optional[bytes]" = None
    """The next destination message box index after all boxes consumed by this call.
    Only populated by create_courier_envelopes_from_payload."""
    next_dest_indices: "Optional[List[bytes]]" = None
    """The next destination indices for each destination, in request order.
    Only populated by create_courier_envelopes_from_multi_payload."""


@dataclass
class TombstoneEnvelope:
    """A single tombstone envelope ready to be sent."""
    message_ciphertext: bytes
    envelope_descriptor: bytes
    envelope_hash: bytes
    box_index: bytes


@dataclass
class TombstoneRangeResult:
    """Result of a tombstone_range operation."""
    envelopes: "List[TombstoneEnvelope]"
    next: bytes


async def tombstone_range(
    self,
    write_cap: bytes,
    start: bytes,
    max_count: int
) -> TombstoneRangeResult:
    """
    Prepares the encrypted envelopes needed to tombstone a consecutive
    range of pigeonhole boxes beginning at the supplied
    ``MessageBoxIndex``. A tombstone is a signed empty payload that the
    replica recognises as a deletion marker; the daemon constructs one
    by signing rather than encrypting whenever ``encrypt_write`` is
    invoked with an empty plaintext.

    This method does not itself touch the network: it returns the
    envelopes for the caller to dispatch one by one, typically via
    ``start_resending_encrypted_message``. To tombstone a single box,
    pass ``max_count=1``.

    Args:
        write_cap: Write capability for the boxes.
        start: Starting MessageBoxIndex.
        max_count: Maximum number of boxes to tombstone.

    Returns:
        TombstoneRangeResult: Contains envelopes (list of TombstoneEnvelope) and
            next (the next MessageBoxIndex after the last processed).

    Raises:
        ValueError: If write_cap or start is None.

    Example:
        >>> result = await client.tombstone_range(write_cap, start_index, 10)
        >>> for envelope in result.envelopes:
        ...     await client.start_resending_encrypted_message(
        ...         None, write_cap, None, None,
        ...         envelope.envelope_descriptor,
        ...         envelope.message_ciphertext,
        ...         envelope.envelope_hash)
    """
    if write_cap is None:
        raise ValueError("write_cap cannot be None")
    if start is None:
        raise ValueError("start index cannot be None")
    if max_count == 0:
        return TombstoneRangeResult(envelopes=[], next=start)

    cur = start
    envelopes = []

    while len(envelopes) < max_count:
        result = await self.encrypt_write(b'', write_cap, cur)
        envelopes.append(TombstoneEnvelope(
            message_ciphertext=result.message_ciphertext,
            envelope_descriptor=result.envelope_descriptor,
            envelope_hash=result.envelope_hash,
            box_index=cur,
        ))
        cur = result.next_message_box_index

    return TombstoneRangeResult(envelopes=envelopes, next=cur)


async def create_courier_envelopes_from_tombstone_range(
    self,
    dest_write_cap: bytes,
    dest_start_index: bytes,
    max_count: int,
    is_start: bool,
    is_last: bool,
    buffer: "bytes | None" = None
) -> "CreateEnvelopesResult":
    """
    Packs tombstones for a consecutive range of destination boxes into
    ``CopyStreamElement`` chunks. The chunks are written to a temporary
    copy stream and then dispatched as a copy command; the courier
    applies all the tombstones atomically, which is the natural way to
    retire a range of boxes as part of the same copy transaction that
    writes their successors.

    This method is stateless: the ``buffer`` argument carries any residual
    encoder state across calls in place of daemon-side bookkeeping. Pass
    ``None`` for ``buffer`` on the first call and the ``buffer`` returned
    by the previous call thereafter; set ``is_last`` on the final call so
    the encoder flushes its tail.

    Args:
        dest_write_cap: Write capability for the destination channel.
        dest_start_index: Starting index in the destination channel.
        max_count: Number of tombstones to create.
        is_start: Whether this is the first call in the sequence.
        is_last: Whether this is the last call in the sequence.
        buffer: Residual encoder buffer from a previous call, or None.

    Returns:
        CreateEnvelopesResult: Contains envelopes, buffer, and next_dest_index.

    Raises:
        Exception: If the operation fails.

    Example:
        >>> result = await client.create_courier_envelopes_from_tombstone_range(
        ...     write_cap, start_index, 10, is_start=True, is_last=True)
        >>> for envelope in result.envelopes:
        ...     # write envelope to temp copy stream channel
        ...     pass
    """
    query_id = self.new_query_id()

    req_inner = {
        "query_id": query_id,
        "dest_write_cap": dest_write_cap,
        "dest_start_index": dest_start_index,
        "max_count": max_count,
        "is_start": is_start,
        "is_last": is_last,
    }
    if buffer is not None:
        req_inner["buffer"] = buffer

    request = {
        "create_courier_envelopes_from_tombstone_range": req_inner
    }

    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error creating tombstone courier envelopes: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"create_courier_envelopes_from_tombstone_range failed: {error_msg}")

    return CreateEnvelopesResult(
        envelopes=reply.get("envelopes", []),
        buffer=reply.get("buffer", b""),
        next_dest_index=reply.get("next_dest_index", None)
    )

