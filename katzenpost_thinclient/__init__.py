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

For more information, see our thin client documentation:
https://katzenpost.network/docs/thin_client_howto/
https://katzenpost.network/docs/thin_client_api_reference/


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

asyncio.run(main())
```
"""

# Import core classes and functions
from .core import (
    # Replica error codes (from pigeonhole/errors.go)
    REPLICA_SUCCESS,
    REPLICA_ERROR_BOX_ID_NOT_FOUND,
    REPLICA_ERROR_INVALID_BOX_ID,
    REPLICA_ERROR_INVALID_SIGNATURE,
    REPLICA_ERROR_DATABASE_FAILURE,
    REPLICA_ERROR_INVALID_PAYLOAD,
    REPLICA_ERROR_STORAGE_FULL,
    REPLICA_ERROR_INTERNAL_ERROR,
    REPLICA_ERROR_INVALID_EPOCH,
    REPLICA_ERROR_REPLICATION_FAILED,
    REPLICA_ERROR_BOX_ALREADY_EXISTS,
    # Thin client error codes
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
    THIN_CLIENT_ERROR_INVALID_TOMBSTONE_SIG,
    THIN_CLIENT_ERROR_COPY_COMMAND_FAILED,
    THIN_CLIENT_ERROR_PAYLOAD_TOO_LARGE,
    THIN_CLIENT_ERROR_VOUCHER_HASH_MISMATCH,
    THIN_CLIENT_ERROR_VOUCHER_SIGNATURE_INVALID,
    THIN_CLIENT_ERROR_VOUCHER_SEAL_OPEN_FAILED,
    THIN_CLIENT_ERROR_COURIER_INVALID_ENVELOPE,
    THIN_CLIENT_ERROR_COURIER_INVALID_EPOCH,
    thin_client_error_to_string,
    error_code_to_exception,
    copy_reply_to_exception,
    # Replica exceptions (matching Go sentinel errors)
    ReplicaError,
    BoxIDNotFoundError,
    InvalidBoxIDError,
    InvalidSignatureError,
    DatabaseFailureError,
    InvalidPayloadError,
    StorageFullError,
    ReplicaInternalError,
    InvalidEpochError,
    ReplicationFailedError,
    BoxAlreadyExistsError,
    TombstoneError,
    InvalidTombstoneSignatureError,
    is_expected_outcome,
    # Thin client exceptions
    MKEMDecryptionFailedError,
    BACAPDecryptionFailedError,
    StartResendingCancelledError,
    CopyCommandFailedError,
    PayloadTooLargeError,
    # Courier exceptions (distinct from replica errors)
    CourierError,
    CourierInvalidEnvelopeError,
    CourierCacheCorruptionError,
    CourierPropagationError,
    CourierInvalidEpochError,
    ThinClientOfflineError,
    ConfigError,
    # Constants
    SURB_ID_SIZE,
    MESSAGE_ID_SIZE,
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
)

# Import new pigeonhole API methods and result types
from .pigeonhole import (
    new_keypair,
    encrypt_read,
    encrypt_write,
    start_resending_encrypted_message,
    cancel_resending_encrypted_message,
    next_message_box_index,
    get_message_box_index_counter,
    start_resending_copy_command,
    cancel_resending_copy_command,
    create_courier_envelopes_from_payload,
    create_courier_envelopes_from_multi_payload,
    create_courier_envelopes_from_tombstone_range,
    tombstone_range,
    voucher_mint,
    voucher_induct,
    voucher_open,
    voucher_derive_stream,
    # Result dataclasses
    KeypairResult,
    EncryptReadResult,
    EncryptWriteResult,
    CreateEnvelopesResult,
    StartResendingResult,
    TombstoneEnvelope,
    TombstoneRangeResult,
    VoucherMintResult,
    VoucherInductResult,
    VoucherOpenResult,
    VoucherStreamResult,
)


# Attach new pigeonhole API methods to ThinClient
ThinClient.new_keypair = new_keypair
ThinClient.encrypt_read = encrypt_read
ThinClient.encrypt_write = encrypt_write
ThinClient.start_resending_encrypted_message = start_resending_encrypted_message
ThinClient.cancel_resending_encrypted_message = cancel_resending_encrypted_message
ThinClient.next_message_box_index = next_message_box_index
ThinClient.get_message_box_index_counter = get_message_box_index_counter
ThinClient.start_resending_copy_command = start_resending_copy_command
ThinClient.cancel_resending_copy_command = cancel_resending_copy_command
ThinClient.create_courier_envelopes_from_payload = create_courier_envelopes_from_payload
ThinClient.create_courier_envelopes_from_multi_payload = create_courier_envelopes_from_multi_payload
ThinClient.create_courier_envelopes_from_tombstone_range = create_courier_envelopes_from_tombstone_range
ThinClient.tombstone_range = tombstone_range
ThinClient.voucher_mint = voucher_mint
ThinClient.voucher_induct = voucher_induct
ThinClient.voucher_open = voucher_open
ThinClient.voucher_derive_stream = voucher_derive_stream


# Export public API
__all__ = [
    # Main classes
    'ThinClient',
    'ThinClientOfflineError',
    'ConfigError',
    'Config',
    'ConfigFile',
    'Geometry',
    'PigeonholeGeometry',
    'ServiceDescriptor',
    # Pigeonhole result dataclasses
    'KeypairResult',
    'EncryptReadResult',
    'EncryptWriteResult',
    'CreateEnvelopesResult',
    'StartResendingResult',
    'TombstoneEnvelope',
    'TombstoneRangeResult',
    'VoucherMintResult',
    'VoucherInductResult',
    'VoucherOpenResult',
    'VoucherStreamResult',
    # Utility functions
    'find_services',
    'pretty_print_obj',
    'blake2_256_sum',
    'thin_client_error_to_string',
    'error_code_to_exception',
    'copy_reply_to_exception',
    # Constants
    'SURB_ID_SIZE',
    'MESSAGE_ID_SIZE',
    # Replica error codes (from pigeonhole/errors.go)
    'REPLICA_SUCCESS',
    'REPLICA_ERROR_BOX_ID_NOT_FOUND',
    'REPLICA_ERROR_INVALID_BOX_ID',
    'REPLICA_ERROR_INVALID_SIGNATURE',
    'REPLICA_ERROR_DATABASE_FAILURE',
    'REPLICA_ERROR_INVALID_PAYLOAD',
    'REPLICA_ERROR_STORAGE_FULL',
    'REPLICA_ERROR_INTERNAL_ERROR',
    'REPLICA_ERROR_INVALID_EPOCH',
    'REPLICA_ERROR_REPLICATION_FAILED',
    'REPLICA_ERROR_BOX_ALREADY_EXISTS',
    # Thin client error codes
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
    'THIN_CLIENT_ERROR_INVALID_TOMBSTONE_SIG',
    'THIN_CLIENT_ERROR_COPY_COMMAND_FAILED',
    'THIN_CLIENT_ERROR_PAYLOAD_TOO_LARGE',
    'THIN_CLIENT_ERROR_VOUCHER_HASH_MISMATCH',
    'THIN_CLIENT_ERROR_VOUCHER_SIGNATURE_INVALID',
    'THIN_CLIENT_ERROR_VOUCHER_SEAL_OPEN_FAILED',
    'THIN_CLIENT_ERROR_COURIER_INVALID_ENVELOPE',
    'THIN_CLIENT_ERROR_COURIER_INVALID_EPOCH',
    'PayloadTooLargeError',
    # Courier exceptions (distinct from replica errors)
    'CourierError',
    'CourierInvalidEnvelopeError',
    'CourierCacheCorruptionError',
    'CourierPropagationError',
    'CourierInvalidEpochError',
    # Replica exceptions (matching Go sentinel errors)
    'ReplicaError',
    'BoxIDNotFoundError',
    'InvalidBoxIDError',
    'InvalidSignatureError',
    'DatabaseFailureError',
    'InvalidPayloadError',
    'StorageFullError',
    'ReplicaInternalError',
    'InvalidEpochError',
    'ReplicationFailedError',
    'BoxAlreadyExistsError',
    'TombstoneError',
    'InvalidTombstoneSignatureError',
    'is_expected_outcome',
    # Thin client exceptions
    'MKEMDecryptionFailedError',
    'BACAPDecryptionFailedError',
    'StartResendingCancelledError',
]
