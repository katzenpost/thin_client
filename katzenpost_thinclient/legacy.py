# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Katzenpost Python Thin Client - Legacy Channel API
===================================================

This module provides the old channel-based Pigeonhole API methods.
These methods use the channel_id pattern and are maintained for
backward compatibility.
"""

import asyncio
import struct
import cbor2

from typing import Tuple, Any, Dict

from .core import thin_client_error_to_string


class WriteChannelReply:
    """Reply from WriteChannel operation, matching Rust WriteChannelReply."""

    def __init__(self, send_message_payload: bytes, current_message_index: bytes,
                 next_message_index: bytes, envelope_descriptor: bytes, envelope_hash: bytes):
        self.send_message_payload = send_message_payload
        self.current_message_index = current_message_index
        self.next_message_index = next_message_index
        self.envelope_hash = envelope_hash
        self.envelope_descriptor = envelope_descriptor


class ReadChannelReply:
    """Reply from ReadChannel operation, matching Rust ReadChannelReply."""

    def __init__(self, send_message_payload: bytes, current_message_index: bytes,
                 next_message_index: bytes, reply_index: "int|None",
                 envelope_descriptor: bytes, envelope_hash: bytes):
        self.send_message_payload = send_message_payload
        self.current_message_index = current_message_index
        self.next_message_index = next_message_index
        self.reply_index = reply_index
        self.envelope_descriptor = envelope_descriptor
        self.envelope_hash = envelope_hash


# Legacy channel API methods - these will be attached to ThinClient class

async def create_write_channel(self, write_cap: "bytes|None"=None, message_box_index: "bytes|None"=None) -> "Tuple[int,bytes,bytes,bytes]":
    """
    Create a new pigeonhole write channel.

    Args:
        write_cap: Optional WriteCap for resuming an existing channel.
        message_box_index: Optional MessageBoxIndex for resuming from a specific position.

    Returns:
        tuple: (channel_id, read_cap, write_cap, next_message_index) where:
            - channel_id is 16-bit channel ID
            - read_cap is the read capability for sharing
            - write_cap is the write capability for persistence
            - next_message_index is the current position for crash consistency

    Raises:
        Exception: If the channel creation fails.
    """
    request_data = {}

    if write_cap is not None:
        request_data["write_cap"] = write_cap

    if message_box_index is not None:
        request_data["message_box_index"] = message_box_index

    request = {
        "create_write_channel": request_data
    }

    cbor_request = cbor2.dumps(request)
    length_prefix = struct.pack('>I', len(cbor_request))
    length_prefixed_request = length_prefix + cbor_request

    try:
        # Clear previous reply data and reset event
        self.channel_reply_data = None
        self.channel_reply_event.clear()

        await self._send_all(length_prefixed_request)
        self.logger.info("CreateWriteChannel request sent successfully.")

        # Wait for CreateWriteChannelReply via the background worker
        await self.channel_reply_event.wait()

        if self.channel_reply_data and self.channel_reply_data.get("create_write_channel_reply"):
            reply = self.channel_reply_data["create_write_channel_reply"]
            error_code = reply.get("error_code", 0)
            if error_code != 0:
                error_msg = thin_client_error_to_string(error_code)
                raise Exception(f"CreateWriteChannel failed: {error_msg} (error code {error_code})")
            return reply["channel_id"], reply["read_cap"], reply["write_cap"], reply["next_message_index"]
        else:
            raise Exception("No create_write_channel_reply received")

    except Exception as e:
        self.logger.error(f"Error creating write channel: {e}")
        raise


async def create_read_channel(self, read_cap: bytes, message_box_index: "bytes|None"=None) -> "Tuple[int,bytes]":
    """
    Create a read channel from a read capability.

    Args:
        read_cap: The read capability object.
        message_box_index: Optional MessageBoxIndex for resuming from a specific position.

    Returns:
        tuple: (channel_id, next_message_index) where:
            - channel_id is the 16-bit channel ID
            - next_message_index is the current position for crash consistency

    Raises:
        Exception: If the read channel creation fails.
    """
    request_data = {
        "read_cap": read_cap
    }

    if message_box_index is not None:
        request_data["message_box_index"] = message_box_index

    request = {
        "create_read_channel": request_data
    }

    cbor_request = cbor2.dumps(request)
    length_prefix = struct.pack('>I', len(cbor_request))
    length_prefixed_request = length_prefix + cbor_request

    try:
        # Clear previous reply data and reset event
        self.channel_reply_data = None
        self.channel_reply_event.clear()

        await self._send_all(length_prefixed_request)
        self.logger.info("CreateReadChannel request sent successfully.")

        # Wait for CreateReadChannelReply via the background worker
        await self.channel_reply_event.wait()

        if self.channel_reply_data and self.channel_reply_data.get("create_read_channel_reply"):
            reply = self.channel_reply_data["create_read_channel_reply"]
            error_code = reply.get("error_code", 0)
            if error_code != 0:
                error_msg = thin_client_error_to_string(error_code)
                raise Exception(f"CreateReadChannel failed: {error_msg} (error code {error_code})")
            return reply["channel_id"], reply["next_message_index"]
        else:
            raise Exception("No create_read_channel_reply received")

    except Exception as e:
        self.logger.error(f"Error creating read channel: {e}")
        raise


async def write_channel(self, channel_id: int, payload: "bytes|str") -> "Tuple[bytes,bytes]":
    """
    Prepare a write message for a pigeonhole channel and return the SendMessage payload and next MessageBoxIndex.
    The thin client must then call send_message with the returned payload to actually send the message.

    Args:
        channel_id (int): The 16-bit channel ID.
        payload (bytes or str): The data to write to the channel.

    Returns:
        tuple: (send_message_payload, next_message_index) where:
            - send_message_payload is the prepared payload for send_message
            - next_message_index is the position to use after courier acknowledgment

    Raises:
        Exception: If the write preparation fails.
    """
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')

    request = {
        "write_channel": {
            "channel_id": channel_id,
            "payload": payload
        }
    }

    cbor_request = cbor2.dumps(request)
    length_prefix = struct.pack('>I', len(cbor_request))
    length_prefixed_request = length_prefix + cbor_request

    try:
        # Clear previous reply data and reset event
        self.channel_reply_data = None
        self.channel_reply_event.clear()

        await self._send_all(length_prefixed_request)
        self.logger.info("WriteChannel prepare request sent successfully.")

        # Wait for WriteChannelReply via the background worker
        await self.channel_reply_event.wait()

        if self.channel_reply_data and self.channel_reply_data.get("write_channel_reply"):
            reply = self.channel_reply_data["write_channel_reply"]
            error_code = reply.get("error_code", 0)
            if error_code != 0:
                error_msg = thin_client_error_to_string(error_code)
                raise Exception(f"WriteChannel failed: {error_msg} (error code {error_code})")
            return reply["send_message_payload"], reply["next_message_index"]
        else:
            raise Exception("No write_channel_reply received")

    except Exception as e:
        self.logger.error(f"Error preparing write to channel: {e}")
        raise


async def read_channel(self, channel_id: int, message_id: "bytes|None"=None, reply_index: "int|None"=None) -> "Tuple[bytes,bytes,int|None]":
    """
    Prepare a read query for a pigeonhole channel and return the SendMessage payload, next MessageBoxIndex, and used ReplyIndex.
    The thin client must then call send_message with the returned payload to actually send the query.

    Args:
        channel_id (int): The 16-bit channel ID.
        message_id (bytes, optional): The 16-byte message ID for correlation. If None, generates a new one.
        reply_index (int, optional): The index of the reply to return. If None, defaults to 0.

    Returns:
        tuple: (send_message_payload, next_message_index, used_reply_index) where:
            - send_message_payload is the prepared payload for send_message
            - next_message_index is the position to use after successful read
            - used_reply_index is the reply index that was used (or None if not specified)

    Raises:
        Exception: If the read preparation fails.
    """
    if message_id is None:
        message_id = self.new_message_id()

    request_data = {
        "channel_id": channel_id,
        "message_id": message_id
    }

    if reply_index is not None:
        request_data["reply_index"] = reply_index

    request = {
        "read_channel": request_data
    }

    cbor_request = cbor2.dumps(request)
    length_prefix = struct.pack('>I', len(cbor_request))
    length_prefixed_request = length_prefix + cbor_request

    try:
        # Clear previous reply data and reset event
        self.channel_reply_data = None
        self.channel_reply_event.clear()

        await self._send_all(length_prefixed_request)
        self.logger.info(f"ReadChannel request sent for message_id {message_id.hex()[:16]}...")

        # Wait for ReadChannelReply via the background worker
        await self.channel_reply_event.wait()

        if self.channel_reply_data and self.channel_reply_data.get("read_channel_reply"):
            reply = self.channel_reply_data["read_channel_reply"]
            error_code = reply.get("error_code", 0)
            if error_code != 0:
                error_msg = thin_client_error_to_string(error_code)
                raise Exception(f"ReadChannel failed: {error_msg} (error code {error_code})")

            used_reply_index = reply.get("reply_index")
            return reply["send_message_payload"], reply["next_message_index"], used_reply_index
        else:
            raise Exception("No read_channel_reply received")

    except Exception as e:
        self.logger.error(f"Error preparing read from channel: {e}")
        raise


async def read_channel_with_retry(self, channel_id: int, dest_node: bytes, dest_queue: bytes,
                                max_retries: int = 2) -> bytes:
    """
    Send a read query for a pigeonhole channel with automatic reply index retry.
    It first tries reply index 0 up to max_retries times, and if that fails,
    it tries reply index 1 up to max_retries times.
    This method handles the common case where the courier has cached replies at different indices
    and accounts for timing issues where messages may not have propagated yet.
    This method requires mixnet connectivity and will fail in offline mode.
    The method generates its own message ID and matches replies for correct correlation.

    Args:
        channel_id (int): The 16-bit channel ID.
        dest_node (bytes): Destination node identity hash.
        dest_queue (bytes): Destination recipient queue ID.
        max_retries (int): Maximum number of attempts per reply index (default: 2).

    Returns:
        bytes: The received payload from the channel.

    Raises:
        RuntimeError: If in offline mode (daemon not connected to mixnet).
        Exception: If all retry attempts fail.
    """
    # Check if we're in offline mode
    if not self._is_connected:
        raise RuntimeError("cannot send channel query in offline mode - daemon not connected to mixnet")

    # Generate a new message ID for this read operation
    message_id = self.new_message_id()
    self.logger.debug(f"read_channel_with_retry: Generated message_id {message_id.hex()[:16]}...")

    reply_indices = [0, 1]

    for reply_index in reply_indices:
        self.logger.debug(f"read_channel_with_retry: Trying reply index {reply_index}")

        # Prepare the read query for this reply index
        try:
            # read_channel expects int channel_id
            payload, _, _ = await self.read_channel(channel_id, message_id, reply_index)
        except Exception as e:
            self.logger.error(f"Failed to prepare read query with reply index {reply_index}: {e}")
            continue

        # Try this reply index up to max_retries times
        for attempt in range(1, max_retries + 1):
            self.logger.debug(f"read_channel_with_retry: Reply index {reply_index} attempt {attempt}/{max_retries}")

            try:
                # Send the channel query and wait for matching reply
                result = await self._send_channel_query_and_wait_for_message_id(
                    channel_id, payload, dest_node, dest_queue, message_id, is_read_operation=True
                )

                # For read operations, we should only consider it successful if we got actual data
                if len(result) > 0:
                    self.logger.debug(f"read_channel_with_retry: Reply index {reply_index} succeeded on attempt {attempt} with {len(result)} bytes")
                    return result
                else:
                    self.logger.debug(f"read_channel_with_retry: Reply index {reply_index} attempt {attempt} got empty payload, treating as failure")
                    raise Exception("received empty payload - message not available yet")

            except Exception as e:
                self.logger.debug(f"read_channel_with_retry: Reply index {reply_index} attempt {attempt} failed: {e}")

            # If this was the last attempt for this reply index, move to next reply index
            if attempt == max_retries:
                break

            # Add a delay between retries to allow for message propagation (match Go client)
            await asyncio.sleep(5.0)

    # All reply indices and attempts failed
    self.logger.debug(f"read_channel_with_retry: All reply indices failed after {max_retries} attempts each")
    raise Exception("all reply indices failed after multiple attempts")


async def _send_channel_query_and_wait_for_message_id(self, channel_id: int, payload: bytes,
                                                     dest_node: bytes, dest_queue: bytes,
                                                     expected_message_id: bytes, is_read_operation: bool = True) -> bytes:
    """
    Send a channel query and wait for a reply with the specified message ID.
    This method matches replies by message ID to ensure correct correlation.

    Args:
        channel_id (int): The channel ID for the query
        payload (bytes): The prepared query payload
        dest_node (bytes): Destination node identity hash
        dest_queue (bytes): Destination recipient queue ID
        expected_message_id (bytes): The message ID to match replies against
        is_read_operation (bool): Whether this is a read operation (affects empty payload handling)

    Returns:
        bytes: The received payload

    Raises:
        Exception: If the query fails or times out
    """
    # Store the expected message ID for reply matching
    self._expected_message_id = expected_message_id
    self._received_reply_payload = None
    self._reply_received_for_message_id = asyncio.Event()
    self._reply_received_for_message_id.clear()

    try:
        # Send the channel query with the specific expected_message_id
        actual_message_id = await self.send_channel_query(channel_id, payload, dest_node, dest_queue, expected_message_id)

        # Verify that the message ID matches what we expected
        assert actual_message_id == expected_message_id, f"Message ID mismatch: expected {expected_message_id.hex()}, got {actual_message_id.hex()}"

        # Wait for the matching reply with timeout
        await asyncio.wait_for(self._reply_received_for_message_id.wait(), timeout=120.0)

        # Check if we got a valid payload
        if self._received_reply_payload is None:
            raise Exception("no reply received for message ID")

        # Handle empty payload based on operation type
        if len(self._received_reply_payload) == 0:
            if is_read_operation:
                raise Exception("message not available yet - empty payload")
            else:
                return b""  # Empty payload is success for write operations

        return self._received_reply_payload

    except asyncio.TimeoutError:
        raise Exception("timeout waiting for reply")
    finally:
        # Clean up
        self._expected_message_id = None
        self._received_reply_payload = None


async def close_channel(self, channel_id: int) -> None:
    """
    Close a pigeonhole channel and clean up its resources.
    This helps avoid running out of channel IDs by properly releasing them.
    This operation is infallible - it sends the close request and returns immediately.

    Args:
        channel_id (int): The 16-bit channel ID to close.

    Raises:
        Exception: If the socket send operation fails.
    """
    request = {
        "close_channel": {
            "channel_id": channel_id
        }
    }

    cbor_request = cbor2.dumps(request)
    length_prefix = struct.pack('>I', len(cbor_request))
    length_prefixed_request = length_prefix + cbor_request

    try:
        # CloseChannel is infallible - fire and forget, no reply expected
        await self._send_all(length_prefixed_request)
        self.logger.info(f"CloseChannel request sent for channel {channel_id}.")
    except Exception as e:
        self.logger.error(f"Error sending close channel request: {e}")
        raise

