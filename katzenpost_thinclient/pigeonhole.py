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


@dataclass
class VoucherMintResult:
    """Result from voucher_mint.

    Hand ``voucher`` to the inductor out of band and publish
    ``voucher_payload`` to VoucherStream box 0. Persist ``voucher_secret_key``
    to open the inductor's reply later.
    """
    voucher: bytes
    voucher_payload: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    voucher_secret_key: bytes
    voucher_public_key: bytes


@dataclass
class VoucherInductResult:
    """Result from voucher_induct.

    ``mutated_message_read_cap`` is the joiner's salt-mutated read cap: the
    live read cap the inductor hands the group. Write ``sealed_reply`` to
    VoucherStream box 1.
    """
    display_name: str
    mutated_message_read_cap: bytes
    sealed_reply: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    salt: bytes


@dataclass
class VoucherOpenResult:
    """Result from voucher_open.

    ``mutated_message_write_cap`` is the joiner's salt-mutated write cap: the
    live write cap for real messages, which lands on the same box sequence as
    the read cap the inductor handed the group.
    """
    who_reply: bytes
    salt: bytes
    mutated_message_write_cap: bytes


@dataclass
class VoucherStreamResult:
    """Result from voucher_derive_stream: the rendezvous stream caps."""
    voucher_write_cap: bytes
    voucher_read_cap: bytes


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
    *,
    no_retry_on_box_id_not_found: bool = False,
    no_idempotent_box_already_exists: bool = False
) -> StartResendingResult:
    """
    Sends an encrypted read or write request to a courier through the
    daemon's stop-and-wait ARQ and blocks until the operation completes,
    fails, or is cancelled via ``cancel_resending_encrypted_message``.
    The daemon retransmits until the courier answers; see
    https://katzenpost.network/docs/pigeonhole_explained/#the-pigeonhole-arq
    for the retransmission behavior and per-operation round-trip costs.

    A write completes on the courier's ACK, a single mixnet round trip,
    and by default treats BoxAlreadyExists as idempotent success. A read
    is two-phased: after the ACK the daemon collects the payload with a
    fresh SURB, decrypts it, and returns the plaintext; by default a
    read retries BoxIDNotFound until the box is written.

    The two keyword-only flags select the variant behaviors that the Go
    binding exposes as separate methods
    (``StartResendingEncryptedMessageNoRetry`` and
    ``StartResendingEncryptedMessageReturnBoxExists``).

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
            retry on BoxIDNotFound until the box is found or the operation is
            cancelled, riding out replication lag; the retries are not capped. Set
            to True to get an immediate BoxIDNotFound error without retries.
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


async def cancel_resending_encrypted_message(self, envelope_hash: bytes) -> None:
    """
    Cancels ARQ resending for an encrypted message.

    The daemon stops retransmitting the operation identified by
    ``envelope_hash``, the blocked ``start_resending_encrypted_message``
    caller raises an error, and the operation is removed from in-flight
    tracking so it is not replayed after a reconnect.

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
    Returns the message box index that follows ``message_box_index`` in
    its BACAP stream. The computation happens in the daemon and causes
    no mixnet traffic.

    Most callers never need this method: ``encrypt_read``,
    ``encrypt_write``, and the copy stream constructors already return
    the next index alongside their results.

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
    Sends a copy command to a courier through the daemon's stop-and-wait
    ARQ and blocks until the courier acknowledges completion. The copy
    command hands the courier the write capability of a temporary copy
    stream; the courier executes the stream's envelopes to their
    destination boxes and tombstones the temporary stream. See
    https://katzenpost.network/docs/pigeonhole_explained/#copy-commands
    for the workflow and its all-or-nothing semantics.

    If ``courier_identity_hash`` and ``courier_queue_id`` are both
    provided, the copy command is pinned to that specific courier;
    otherwise the daemon picks one.

    An in-flight call may be cancelled via
    ``cancel_resending_copy_command``.

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

    The daemon stops retransmitting the copy command identified by
    ``write_cap_hash`` (the blake2b-256 hash of the serialized write
    capability), and the operation is removed from in-flight tracking
    so it is not replayed after a reconnect.

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

    This method is stateless: no daemon state is kept between calls.
    It causes no mixnet traffic. See
    https://katzenpost.network/docs/pigeonhole_explained/#copy-commands
    for the copy command workflow the chunks feed into.

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
    destination, because it avoids padding the final box of each
    destination independently.

    This method is stateless: the ``buffer`` argument carries any
    residual state across calls. Pass ``None`` for ``buffer`` on the
    first call and the ``buffer`` returned by the previous call
    thereafter; set ``is_last`` on the final call to flush the
    remainder.

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
    ``MessageBoxIndex``. A tombstone is a signed empty payload that
    deletes a box's contents; see
    https://katzenpost.network/docs/pigeonhole_explained/#tombstones.

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
    ``CopyStreamElement`` chunks, combining tombstone creation with the
    copy stream encoding of ``create_courier_envelopes_from_payload``.

    This method is stateless: the ``buffer`` argument carries any
    residual state across calls. Pass ``None`` for ``buffer`` on the
    first call and the ``buffer`` returned by the previous call
    thereafter; set ``is_last`` on the final call to flush the
    remainder.

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


# Contact Voucher API methods. Each sends a pure-crypto request to the daemon
# (served from hpqc/voucher with no mixnet IO) and awaits the matching reply.
# All capability and key material is opaque bytes; the thin client performs no
# cryptography. Seeds are never carried over the wire, so the daemon supplies
# fresh randomness for the reply keypair, the salt, and the seal.


async def voucher_mint(self, message_write_cap: bytes, display_name: str) -> VoucherMintResult:
    """
    Mints a Voucher from the joiner's MessageStream write cap.

    Args:
        message_write_cap: The joiner's MessageStream write capability.
        display_name: The joiner's chosen display name.

    Returns:
        VoucherMintResult: The Voucher, the payload to publish, the rendezvous
            stream caps, and the reply keypair.

    Raises:
        Exception: If minting fails.
    """
    query_id = self.new_query_id()
    request = {
        "voucher_mint": {
            "query_id": query_id,
            "message_write_cap": message_write_cap,
            "display_name": display_name,
        }
    }
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error minting voucher: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"voucher_mint failed: {error_msg}")

    return VoucherMintResult(
        voucher=reply["voucher"],
        voucher_payload=reply["voucher_payload"],
        voucher_write_cap=reply["voucher_write_cap"],
        voucher_read_cap=reply["voucher_read_cap"],
        voucher_secret_key=reply["voucher_secret_key"],
        voucher_public_key=reply["voucher_public_key"],
    )


async def voucher_induct(self, voucher: bytes, voucher_payload: bytes, who_reply: bytes) -> VoucherInductResult:
    """
    Verifies a published VoucherPayload and seals a reply to the joiner.

    Args:
        voucher: The 32-byte token received out of band.
        voucher_payload: The payload read from VoucherStream box 0.
        who_reply: The opaque group-membership blob to seal for the joiner.

    Returns:
        VoucherInductResult: The joiner's salt-mutated read cap, the sealed
            reply to write to VoucherStream box 1, and the salt.

    Raises:
        Exception: If induction fails (e.g. hash mismatch or bad signature).
    """
    query_id = self.new_query_id()
    request = {
        "voucher_induct": {
            "query_id": query_id,
            "voucher": voucher,
            "voucher_payload": voucher_payload,
            "who_reply": who_reply,
        }
    }
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error inducting voucher: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"voucher_induct failed: {error_msg}")

    return VoucherInductResult(
        display_name=reply.get("display_name", ""),
        mutated_message_read_cap=reply["mutated_message_read_cap"],
        sealed_reply=reply["sealed_reply"],
        voucher_write_cap=reply["voucher_write_cap"],
        voucher_read_cap=reply["voucher_read_cap"],
        salt=reply["salt"],
    )


async def voucher_open(self, voucher_secret_key: bytes, sealed_reply: bytes, message_write_cap: bytes) -> VoucherOpenResult:
    """
    Opens the inductor's sealed reply with the joiner's voucher secret key,
    recovers the salt, and mutates the joiner's MessageStream write cap by it.

    Args:
        voucher_secret_key: The joiner's persisted voucher secret key.
        sealed_reply: The bytes read from VoucherStream box 1.
        message_write_cap: The joiner's MessageStream write cap, mutated by the
            recovered salt to yield the live write cap for real messages.

    Returns:
        VoucherOpenResult: The opaque WhoReply, the salt, and the salt-mutated
            write cap.

    Raises:
        Exception: If opening fails (e.g. wrong key).
    """
    query_id = self.new_query_id()
    request = {
        "voucher_open": {
            "query_id": query_id,
            "voucher_secret_key": voucher_secret_key,
            "sealed_reply": sealed_reply,
            "message_write_cap": message_write_cap,
        }
    }
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error opening voucher reply: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"voucher_open failed: {error_msg}")

    return VoucherOpenResult(
        who_reply=reply["who_reply"],
        salt=reply["salt"],
        mutated_message_write_cap=reply["mutated_message_write_cap"],
    )


async def voucher_derive_stream(self, voucher: bytes) -> VoucherStreamResult:
    """
    Derives the VoucherStream caps from the Voucher, which the inductor needs
    to read box 0 before inducting.

    Args:
        voucher: The 32-byte token.

    Returns:
        VoucherStreamResult: The rendezvous stream caps.

    Raises:
        Exception: If derivation fails.
    """
    query_id = self.new_query_id()
    request = {
        "voucher_derive_stream": {
            "query_id": query_id,
            "voucher": voucher,
        }
    }
    try:
        reply = await self._send_and_wait(query_id=query_id, request=request)
    except Exception as e:
        self.logger.error(f"Error deriving voucher stream: {e}")
        raise

    if reply.get('error_code', 0) != THIN_CLIENT_SUCCESS:
        error_msg = thin_client_error_to_string(reply['error_code'])
        raise Exception(f"voucher_derive_stream failed: {error_msg}")

    return VoucherStreamResult(
        voucher_write_cap=reply["voucher_write_cap"],
        voucher_read_cap=reply["voucher_read_cap"],
    )

