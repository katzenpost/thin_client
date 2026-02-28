# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Katzenpost Python Thin Client
=============================

This module provides a minimal async Python client for communicating with the
Katzenpost client daemon over an abstract Unix domain socket. It allows
applications to send and receive messages via the mix network by interacting
with the daemon.

The thin client handles:
- Connecting to the local daemon
- Sending messages
- Receiving events and responses from the daemon
- Accessing the current PKI document and service descriptors

All cryptographic operations, including PQ Noise transport, Sphinx
packet construction, and retransmission mechanisms are handled by the
client daemon, and not this thin client library.

For more information, see our client integration guide:
https://katzenpost.network/docs/client_integration/


Usage Example
-------------

```python
import asyncio
from thinclient import ThinClient, Config

async def main():
    cfg = Config("./thinclient.toml")
    client = ThinClient(cfg)
    loop = asyncio.get_running_loop()
    await client.start(loop)

    service = client.get_service("echo")
    surb_id = client.new_surb_id()
    await client.send_message(surb_id, "hello mixnet", *service.to_destination())

    await client.await_message_reply()

asyncio.run(main())
```
"""

# Import core classes and functions
from .core import (
    # Error codes
    THIN_CLIENT_SUCCESS,
    THIN_CLIENT_ERROR_CONNECTION_LOST,
    THIN_CLIENT_ERROR_TIMEOUT,
    THIN_CLIENT_ERROR_INVALID_REQUEST,
    THIN_CLIENT_ERROR_INTERNAL_ERROR,
    THIN_CLIENT_ERROR_MAX_RETRIES,
    THIN_CLIENT_ERROR_INVALID_CHANNEL,
    THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND,
    THIN_CLIENT_ERROR_PERMISSION_DENIED,
    THIN_CLIENT_ERROR_INVALID_PAYLOAD,
    THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE,
    THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY,
    THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION,
    THIN_CLIENT_PROPAGATION_ERROR,
    THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY,
    THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY,
    THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST,
    THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST,
    THIN_CLIENT_IMPOSSIBLE_HASH_ERROR,
    THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR,
    THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR,
    THIN_CLIENT_CAPABILITY_ALREADY_IN_USE,
    THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED,
    THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED,
    THIN_CLIENT_ERROR_START_RESENDING_CANCELLED,
    thin_client_error_to_string,
    # Exceptions
    ThinClientOfflineError,
    # Constants
    SURB_ID_SIZE,
    MESSAGE_ID_SIZE,
    STREAM_ID_LENGTH,
    # Classes
    ThinClient,
    Config,
    ConfigFile,
    Geometry,
    PigeonholeGeometry,
    ServiceDescriptor,
    # Functions
    find_services,
    pretty_print_obj,
    blake2_256_sum,
    tombstone_plaintext,
    is_tombstone_plaintext,
)

# Import legacy channel API classes and methods
from .legacy import (
    WriteChannelReply,
    ReadChannelReply,
    create_write_channel,
    create_read_channel,
    write_channel,
    read_channel,
    read_channel_with_retry,
    _send_channel_query_and_wait_for_message_id,
    close_channel,
)

# Import new pigeonhole API methods
from .pigeonhole import (
    new_keypair,
    encrypt_read,
    encrypt_write,
    start_resending_encrypted_message,
    cancel_resending_encrypted_message,
    next_message_box_index,
    start_resending_copy_command,
    cancel_resending_copy_command,
    create_courier_envelopes_from_payload,
    create_courier_envelopes_from_payloads,
    tombstone_box,
    tombstone_range,
)


# Attach legacy channel API methods to ThinClient
ThinClient.create_write_channel = create_write_channel
ThinClient.create_read_channel = create_read_channel
ThinClient.write_channel = write_channel
ThinClient.read_channel = read_channel
ThinClient.read_channel_with_retry = read_channel_with_retry
ThinClient._send_channel_query_and_wait_for_message_id = _send_channel_query_and_wait_for_message_id
ThinClient.close_channel = close_channel

# Attach new pigeonhole API methods to ThinClient
ThinClient.new_keypair = new_keypair
ThinClient.encrypt_read = encrypt_read
ThinClient.encrypt_write = encrypt_write
ThinClient.start_resending_encrypted_message = start_resending_encrypted_message
ThinClient.cancel_resending_encrypted_message = cancel_resending_encrypted_message
ThinClient.next_message_box_index = next_message_box_index
ThinClient.start_resending_copy_command = start_resending_copy_command
ThinClient.cancel_resending_copy_command = cancel_resending_copy_command
ThinClient.create_courier_envelopes_from_payload = create_courier_envelopes_from_payload
ThinClient.create_courier_envelopes_from_payloads = create_courier_envelopes_from_payloads
ThinClient.tombstone_box = tombstone_box
ThinClient.tombstone_range = tombstone_range


# Export public API
__all__ = [
    # Main classes
    'ThinClient',
    'ThinClientOfflineError',
    'Config',
    'ConfigFile',
    'Geometry',
    'PigeonholeGeometry',
    'ServiceDescriptor',
    # Legacy channel reply classes
    'WriteChannelReply',
    'ReadChannelReply',
    # Utility functions
    'find_services',
    'pretty_print_obj',
    'blake2_256_sum',
    'tombstone_plaintext',
    'is_tombstone_plaintext',
    'thin_client_error_to_string',
    # Constants
    'SURB_ID_SIZE',
    'MESSAGE_ID_SIZE',
    'STREAM_ID_LENGTH',
    # Error codes
    'THIN_CLIENT_SUCCESS',
    'THIN_CLIENT_ERROR_CONNECTION_LOST',
    'THIN_CLIENT_ERROR_TIMEOUT',
    'THIN_CLIENT_ERROR_INVALID_REQUEST',
    'THIN_CLIENT_ERROR_INTERNAL_ERROR',
    'THIN_CLIENT_ERROR_MAX_RETRIES',
    'THIN_CLIENT_ERROR_INVALID_CHANNEL',
    'THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND',
    'THIN_CLIENT_ERROR_PERMISSION_DENIED',
    'THIN_CLIENT_ERROR_INVALID_PAYLOAD',
    'THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE',
    'THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY',
    'THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION',
    'THIN_CLIENT_PROPAGATION_ERROR',
    'THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY',
    'THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY',
    'THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST',
    'THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST',
    'THIN_CLIENT_IMPOSSIBLE_HASH_ERROR',
    'THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR',
    'THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR',
    'THIN_CLIENT_CAPABILITY_ALREADY_IN_USE',
    'THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED',
    'THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED',
    'THIN_CLIENT_ERROR_START_RESENDING_CANCELLED',
]
