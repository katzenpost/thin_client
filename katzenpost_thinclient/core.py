# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Katzenpost Python Thin Client - Core Module
============================================

This module provides the core functionality for the Katzenpost thin client,
including the ThinClient class, configuration, and helper utilities.
"""

import socket
import struct
import random
import coloredlogs
import logging
import sys
import io
import os
import asyncio
import cbor2
import pprintpp
import toml
import hashlib

from typing import Tuple, Any, Dict, List, Callable

from .transport import DialConfig, TcpDialConfig, UnixDialConfig

# Pigeonhole Replica Error Codes (matching Go pigeonhole/errors.go)
# These are error codes returned by storage replicas, passed through by the daemon
# for the StartResendingEncryptedMessage API.
REPLICA_SUCCESS = 0
REPLICA_ERROR_BOX_ID_NOT_FOUND = 1
REPLICA_ERROR_INVALID_BOX_ID = 2
REPLICA_ERROR_INVALID_SIGNATURE = 3
REPLICA_ERROR_DATABASE_FAILURE = 4
REPLICA_ERROR_INVALID_PAYLOAD = 5
REPLICA_ERROR_STORAGE_FULL = 6
REPLICA_ERROR_INTERNAL_ERROR = 7
REPLICA_ERROR_INVALID_EPOCH = 8
REPLICA_ERROR_REPLICATION_FAILED = 9
REPLICA_ERROR_BOX_ALREADY_EXISTS = 10
REPLICA_ERROR_TOMBSTONE = 11

# Thin Client Error Codes (matching Go implementation)
# These are error codes for thin client operations (separate from replica errors)
THIN_CLIENT_SUCCESS = 0
THIN_CLIENT_ERROR_CONNECTION_LOST = 1
THIN_CLIENT_ERROR_TIMEOUT = 2
THIN_CLIENT_ERROR_INVALID_REQUEST = 3
THIN_CLIENT_ERROR_INTERNAL_ERROR = 4
THIN_CLIENT_ERROR_MAX_RETRIES = 5
THIN_CLIENT_ERROR_INVALID_CHANNEL = 6
THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND = 7
THIN_CLIENT_ERROR_PERMISSION_DENIED = 8
THIN_CLIENT_ERROR_INVALID_PAYLOAD = 9
THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE = 10
THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY = 11
THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION = 12
THIN_CLIENT_PROPAGATION_ERROR = 13
THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY = 14
THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY = 15
THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST = 16
THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST = 17
THIN_CLIENT_IMPOSSIBLE_HASH_ERROR = 18
THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR = 19
THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR = 20
THIN_CLIENT_CAPABILITY_ALREADY_IN_USE = 21
THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED = 22
THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED = 23
THIN_CLIENT_ERROR_START_RESENDING_CANCELLED = 24
THIN_CLIENT_ERROR_INVALID_TOMBSTONE_SIG = 25
THIN_CLIENT_ERROR_COPY_COMMAND_FAILED = 26

def thin_client_error_to_string(error_code: int) -> str:
    """Convert a thin client error code to a human-readable string."""
    error_messages = {
        THIN_CLIENT_SUCCESS: "Success",
        THIN_CLIENT_ERROR_CONNECTION_LOST: "Connection lost",
        THIN_CLIENT_ERROR_TIMEOUT: "Timeout",
        THIN_CLIENT_ERROR_INVALID_REQUEST: "Invalid request",
        THIN_CLIENT_ERROR_INTERNAL_ERROR: "Internal error",
        THIN_CLIENT_ERROR_MAX_RETRIES: "Maximum retries exceeded",
        THIN_CLIENT_ERROR_INVALID_CHANNEL: "Invalid channel",
        THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND: "Channel not found",
        THIN_CLIENT_ERROR_PERMISSION_DENIED: "Permission denied",
        THIN_CLIENT_ERROR_INVALID_PAYLOAD: "Invalid payload",
        THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE: "Service unavailable",
        THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY: "Duplicate capability",
        THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION: "Courier cache corruption",
        THIN_CLIENT_PROPAGATION_ERROR: "Propagation error",
        THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY: "Invalid write capability",
        THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY: "Invalid read capability",
        THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST: "Invalid resume write channel request",
        THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST: "Invalid resume read channel request",
        THIN_CLIENT_IMPOSSIBLE_HASH_ERROR: "Impossible hash error",
        THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR: "Failed to create new write capability",
        THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR: "Failed to create new stateful writer",
        THIN_CLIENT_CAPABILITY_ALREADY_IN_USE: "Capability already in use",
        THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED: "MKEM decryption failed",
        THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED: "BACAP decryption failed",
        THIN_CLIENT_ERROR_START_RESENDING_CANCELLED: "Start resending cancelled",
        THIN_CLIENT_ERROR_INVALID_TOMBSTONE_SIG: "Invalid tombstone signature",
        THIN_CLIENT_ERROR_COPY_COMMAND_FAILED: "Copy command failed",
    }
    return error_messages.get(error_code, f"Unknown thin client error code: {error_code}")


class ConfigError(Exception):
    """
    Raised when the thin-client TOML config is missing required sections,
    contains unknown keys, or otherwise fails structural validation.

    Every caller of ConfigFile.load / Config(...) should expect this
    exception. It is raised eagerly at startup so that a stale or
    drifted config produces a loud, early failure instead of surfacing
    later as a mysterious runtime error during mixnet operations.
    """
    pass


# Pigeonhole Replica Exceptions (matching Go sentinel errors in thin/thin.go)
# These exceptions can be caught using isinstance() for specific error handling,
# similar to how Go uses errors.Is() with sentinel errors.

class ReplicaError(Exception):
    """Base class for all replica errors."""
    pass

class BoxIDNotFoundError(ReplicaError):
    """Box ID not found on the replica. Occurs when reading from a non-existent mailbox."""
    pass

class InvalidBoxIDError(ReplicaError):
    """Invalid box ID format."""
    pass

class InvalidSignatureError(ReplicaError):
    """Signature verification failed."""
    pass

class DatabaseFailureError(ReplicaError):
    """Replica encountered a database error."""
    pass

class InvalidPayloadError(ReplicaError):
    """Payload data is invalid."""
    pass

class StorageFullError(ReplicaError):
    """Replica's storage capacity has been exceeded."""
    pass

class ReplicaInternalError(ReplicaError):
    """Internal error on the replica."""
    pass

class InvalidEpochError(ReplicaError):
    """Epoch is invalid or expired."""
    pass

class ReplicationFailedError(ReplicaError):
    """Replication to other replicas failed."""
    pass

class BoxAlreadyExistsError(ReplicaError):
    """Box already contains data. Pigeonhole writes are immutable."""
    pass

class TombstoneError(ReplicaError):
    """Box contains a tombstone (intentional deletion). This is not a failure."""
    pass

class InvalidTombstoneSignatureError(Exception):
    """Tombstone signature verification failed (forgery or corruption)."""
    pass

class MKEMDecryptionFailedError(Exception):
    """MKEM envelope decryption failed with all replica keys."""
    pass

class BACAPDecryptionFailedError(Exception):
    """BACAP payload decryption or signature verification failed."""
    pass

class StartResendingCancelledError(Exception):
    """StartResendingEncryptedMessage operation was cancelled."""
    pass


class CopyCommandFailedError(Exception):
    """StartResendingCopyCommand operation failed on the courier.

    The courier aborted the Copy command because a replica rejected one of the
    embedded writes. Inspect the diagnostic attributes to determine the cause:

    Attributes:
        replica_error_code (int): The pigeonhole replica ErrorCode that triggered
            the abort (e.g. REPLICA_ERROR_BOX_ALREADY_EXISTS). 0 if not reported.
        failed_envelope_index (int): 1-based sequential position in the copy
            stream of the envelope whose write triggered the abort. 0 if not
            applicable. This is NOT a BACAP message index.
    """

    def __init__(self, replica_error_code: int = 0, failed_envelope_index: int = 0) -> None:
        self.replica_error_code = replica_error_code
        self.failed_envelope_index = failed_envelope_index
        super().__init__(
            f"copy command failed: replica_error_code={replica_error_code}, "
            f"failed_envelope_index={failed_envelope_index}"
        )


def error_code_to_exception(error_code: int) -> Exception:
    """
    Maps error codes to exception instances for StartResendingEncryptedMessage.
    This matches Go's errorCodeToSentinel function in thin/pigeonhole.go.

    The daemon passes through pigeonhole replica error codes (1-9) for replica-level errors.
    For other errors (thin client errors like decryption failures), specific exceptions are raised.
    """
    if error_code == REPLICA_SUCCESS:
        return None

    # Pigeonhole replica error codes (from pigeonhole/errors.go)
    if error_code == REPLICA_ERROR_BOX_ID_NOT_FOUND:  # 1
        return BoxIDNotFoundError("box ID not found")
    elif error_code == REPLICA_ERROR_INVALID_BOX_ID:  # 2
        return InvalidBoxIDError("invalid box ID")
    elif error_code == REPLICA_ERROR_INVALID_SIGNATURE:  # 3
        return InvalidSignatureError("invalid signature")
    elif error_code == REPLICA_ERROR_DATABASE_FAILURE:  # 4
        return DatabaseFailureError("database failure")
    elif error_code == REPLICA_ERROR_INVALID_PAYLOAD:  # 5
        return InvalidPayloadError("invalid payload")
    elif error_code == REPLICA_ERROR_STORAGE_FULL:  # 6
        return StorageFullError("storage full")
    elif error_code == REPLICA_ERROR_INTERNAL_ERROR:  # 7
        return ReplicaInternalError("replica internal error")
    elif error_code == REPLICA_ERROR_INVALID_EPOCH:  # 8
        return InvalidEpochError("invalid epoch")
    elif error_code == REPLICA_ERROR_REPLICATION_FAILED:  # 9
        return ReplicationFailedError("replication failed")
    elif error_code == REPLICA_ERROR_BOX_ALREADY_EXISTS:  # 10
        return BoxAlreadyExistsError("box already exists")
    elif error_code == REPLICA_ERROR_TOMBSTONE:  # 11
        return TombstoneError("tombstone")

    # Thin client decryption error codes
    elif error_code == THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED:  # 22
        return MKEMDecryptionFailedError("MKEM decryption failed")
    elif error_code == THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED:  # 23
        return BACAPDecryptionFailedError("BACAP decryption failed")

    # Thin client operation error codes
    elif error_code == THIN_CLIENT_ERROR_START_RESENDING_CANCELLED:  # 24
        return StartResendingCancelledError("start resending cancelled")
    elif error_code == THIN_CLIENT_ERROR_INVALID_TOMBSTONE_SIG:  # 25
        return InvalidTombstoneSignatureError("invalid tombstone signature")

    # Note: THIN_CLIENT_ERROR_COPY_COMMAND_FAILED (26) is not handled here because
    # constructing CopyCommandFailedError requires the reply's diagnostic fields
    # (replica_error_code, failed_envelope_index). Copy command callers should use
    # copy_reply_to_exception() instead.

    # For other error codes, return a generic exception with the error string
    else:
        return Exception(thin_client_error_to_string(error_code))


def copy_reply_to_exception(reply: "Dict[str, Any]") -> "Exception | None":
    """
    Maps a StartResendingCopyCommandReply dict to an exception (or None on success).

    Unlike error_code_to_exception(), this helper has access to the reply's
    diagnostic fields (replica_error_code, failed_envelope_index), which it
    uses to construct a CopyCommandFailedError when the courier reports
    THIN_CLIENT_ERROR_COPY_COMMAND_FAILED.

    Args:
        reply: The decoded start_resending_copy_command_reply dict.

    Returns:
        None if error_code is 0 (success); otherwise an Exception instance.
    """
    error_code = reply.get("error_code", 0)
    if error_code == THIN_CLIENT_SUCCESS:
        return None
    if error_code == THIN_CLIENT_ERROR_COPY_COMMAND_FAILED:
        return CopyCommandFailedError(
            replica_error_code=reply.get("replica_error_code", 0),
            failed_envelope_index=reply.get("failed_envelope_index", 0),
        )
    return error_code_to_exception(error_code)


def is_expected_outcome(exc: Exception) -> bool:
    """Returns True for exceptions that represent completed operations rather than failures.
    These errors should not trigger retries."""
    return isinstance(exc, (TombstoneError, BoxIDNotFoundError, BoxAlreadyExistsError))


class ThinClientOfflineError(Exception):
    pass

# SURB_ID_SIZE is the size in bytes for the
# Katzenpost SURB ID.
SURB_ID_SIZE = 16

# MESSAGE_ID_SIZE is the size in bytes for an ID
# which is unique to the sent message.
MESSAGE_ID_SIZE = 16


class Geometry:
    """
    Geometry describes the geometry of a Sphinx packet.

    NOTE: You must not try to compose a Sphinx Geometry yourself.
    It must be programmatically generated by Katzenpost
    genconfig or gensphinx CLI utilities.

    We describe all the Sphinx Geometry attributes below, however
    the only one you are interested in to faciliate your thin client
    message bounds checking is UserForwardPayloadLength, which indicates
    the maximum sized message that you can send to a mixnet service in
    a single packet.

    Attributes:
        PacketLength (int): The total length of a Sphinx packet in bytes.
        NrHops (int): The number of hops; determines the header's structure.
        HeaderLength (int): The total size of the Sphinx header in bytes.
        RoutingInfoLength (int): The length of the routing information portion of the header.
        PerHopRoutingInfoLength (int): The length of routing info for a single hop.
        SURBLength (int): The length of a Single-Use Reply Block (SURB).
        SphinxPlaintextHeaderLength (int): The length of the unencrypted plaintext header.
        PayloadTagLength (int): The length of the tag used to authenticate the payload.
        ForwardPayloadLength (int): The size of the full payload including padding and tag.
        UserForwardPayloadLength (int): The usable portion of the payload intended for the recipient.
        NextNodeHopLength (int): Derived from the expected maximum routing info block size.
        SPRPKeyMaterialLength (int): The length of the key used for SPRP (Sphinx packet payload encryption).
        NIKEName (str): Name of the NIKE scheme (if used). Mutually exclusive with KEMName.
        KEMName (str): Name of the KEM scheme (if used). Mutually exclusive with NIKEName.
    """

    def __init__(self, *, PacketLength:int, NrHops:int, HeaderLength:int, RoutingInfoLength:int, PerHopRoutingInfoLength:int, SURBLength:int, SphinxPlaintextHeaderLength:int, PayloadTagLength:int, ForwardPayloadLength:int, UserForwardPayloadLength:int, NextNodeHopLength:int, SPRPKeyMaterialLength:int, NIKEName:str='', KEMName:str='') -> None:
        self.PacketLength = PacketLength
        self.NrHops = NrHops
        self.HeaderLength = HeaderLength
        self.RoutingInfoLength = RoutingInfoLength
        self.PerHopRoutingInfoLength = PerHopRoutingInfoLength
        self.SURBLength = SURBLength
        self.SphinxPlaintextHeaderLength = SphinxPlaintextHeaderLength
        self.PayloadTagLength = PayloadTagLength
        self.ForwardPayloadLength = ForwardPayloadLength
        self.UserForwardPayloadLength = UserForwardPayloadLength
        self.NextNodeHopLength = NextNodeHopLength
        self.SPRPKeyMaterialLength = SPRPKeyMaterialLength
        self.NIKEName = NIKEName
        self.KEMName = KEMName

    def __str__(self) -> str:
        return (
            f"PacketLength: {self.PacketLength}\n"
            f"NrHops: {self.NrHops}\n"
            f"HeaderLength: {self.HeaderLength}\n"
            f"RoutingInfoLength: {self.RoutingInfoLength}\n"
            f"PerHopRoutingInfoLength: {self.PerHopRoutingInfoLength}\n"
            f"SURBLength: {self.SURBLength}\n"
            f"SphinxPlaintextHeaderLength: {self.SphinxPlaintextHeaderLength}\n"
            f"PayloadTagLength: {self.PayloadTagLength}\n"
            f"ForwardPayloadLength: {self.ForwardPayloadLength}\n"
            f"UserForwardPayloadLength: {self.UserForwardPayloadLength}\n"
            f"NextNodeHopLength: {self.NextNodeHopLength}\n"
            f"SPRPKeyMaterialLength: {self.SPRPKeyMaterialLength}\n"
            f"NIKEName: {self.NIKEName}\n"
            f"KEMName: {self.KEMName}"
        )


class PigeonholeGeometry:
    """
    PigeonholeGeometry describes the geometry of a Pigeonhole envelope.

    This provides mathematically precise geometry calculations for the
    Pigeonhole protocol using trunnel's fixed binary format.

    It supports 3 distinct use cases:
    1. Given MaxPlaintextPayloadLength → compute all envelope sizes
    2. Given precomputed Pigeonhole Geometry → derive accommodating Sphinx Geometry
    3. Given Sphinx Geometry constraint → derive optimal Pigeonhole Geometry

    Attributes:
        max_plaintext_payload_length (int): The maximum usable plaintext payload size within a Box.
        courier_query_read_length (int): The size of a CourierQuery containing a ReplicaRead.
        courier_query_write_length (int): The size of a CourierQuery containing a ReplicaWrite.
        courier_query_reply_read_length (int): The size of a CourierQueryReply containing a ReplicaReadReply.
        courier_query_reply_write_length (int): The size of a CourierQueryReply containing a ReplicaWriteReply.
        nike_name (str): The NIKE scheme name used in MKEM for encrypting to multiple storage replicas.
        signature_scheme_name (str): The signature scheme used for BACAP (always "Ed25519").
    """

    # Length prefix for padded payloads
    LENGTH_PREFIX_SIZE = 4

    def __init__(
        self,
        *,
        max_plaintext_payload_length: int,
        courier_query_read_length: int = 0,
        courier_query_write_length: int = 0,
        courier_query_reply_read_length: int = 0,
        courier_query_reply_write_length: int = 0,
        nike_name: str = "",
        signature_scheme_name: str = "Ed25519"
    ) -> None:
        self.max_plaintext_payload_length = max_plaintext_payload_length
        self.courier_query_read_length = courier_query_read_length
        self.courier_query_write_length = courier_query_write_length
        self.courier_query_reply_read_length = courier_query_reply_read_length
        self.courier_query_reply_write_length = courier_query_reply_write_length
        self.nike_name = nike_name
        self.signature_scheme_name = signature_scheme_name

    def validate(self) -> None:
        """
        Validates that the geometry has valid parameters.

        Raises:
            ValueError: If the geometry is invalid.
        """
        if self.max_plaintext_payload_length <= 0:
            raise ValueError("max_plaintext_payload_length must be positive")
        if not self.nike_name:
            raise ValueError("nike_name must be set")
        if self.signature_scheme_name != "Ed25519":
            raise ValueError("signature_scheme_name must be 'Ed25519'")

    def padded_payload_length(self) -> int:
        """
        Returns the payload size after adding length prefix.

        Returns:
            int: The padded payload length (max_plaintext_payload_length + 4).
        """
        return self.max_plaintext_payload_length + self.LENGTH_PREFIX_SIZE

    def __str__(self) -> str:
        return (
            f"PigeonholeGeometry:\n"
            f"  max_plaintext_payload_length: {self.max_plaintext_payload_length} bytes\n"
            f"  courier_query_read_length: {self.courier_query_read_length} bytes\n"
            f"  courier_query_write_length: {self.courier_query_write_length} bytes\n"
            f"  courier_query_reply_read_length: {self.courier_query_reply_read_length} bytes\n"
            f"  courier_query_reply_write_length: {self.courier_query_reply_write_length} bytes\n"
            f"  nike_name: {self.nike_name}\n"
            f"  signature_scheme_name: {self.signature_scheme_name}"
        )


# Canonical set of top-level keys the thin-client TOML config must
# contain. The geometries are no longer configured client-side; the
# daemon delivers them over the handshake, so the file carries only
# the Dial section. Anything else indicates a stale or drifted file.
_EXPECTED_TOP_LEVEL_KEYS = frozenset({"Dial"})

# Mapping from the PascalCase keys the daemon sends in its
# ConnectionStatusEvent's pigeonhole_geometry to the snake_case kwargs
# that the PigeonholeGeometry class accepts.
_PIGEONHOLE_TOML_TO_KWARG = {
    "MaxPlaintextPayloadLength": "max_plaintext_payload_length",
    "CourierQueryReadLength": "courier_query_read_length",
    "CourierQueryWriteLength": "courier_query_write_length",
    "CourierQueryReplyReadLength": "courier_query_reply_read_length",
    "CourierQueryReplyWriteLength": "courier_query_reply_write_length",
    "NIKEName": "nike_name",
    "SignatureSchemeName": "signature_scheme_name",
}


class ConfigFile:
    """
    ConfigFile represents everything loaded from a TOML file: only the
    subtable-discriminated Dial transport config. The geometries are
    supplied by the daemon over the handshake, not configured here.
    """
    def __init__(
        self,
        dial: "DialConfig",
    ) -> None:
        self.dial : "DialConfig" = dial

    @classmethod
    def load(cls, toml_path:str) -> "ConfigFile":
        """
        Parse a kpclientd-style thin-client TOML config.

        Raises ConfigError eagerly on any structural problem: unknown
        top-level sections (a leftover [SphinxGeometry] or
        [PigeonholeGeometry] is now rejected here), missing required
        sections, wrong types, or unknown / missing keys within the
        Dial subtable. The intent is that a stale or drifted config
        fails here at startup rather than producing a mysterious
        runtime failure later.
        """
        try:
            with open(toml_path, 'r') as f:
                data = toml.load(f)
        except FileNotFoundError as e:
            raise ConfigError(f"config: {toml_path}: file not found") from e
        except toml.TomlDecodeError as e:
            raise ConfigError(f"config: {toml_path}: TOML parse error: {e}") from e

        if not isinstance(data, dict):
            raise ConfigError(f"config: {toml_path}: top-level must be a table")

        unknown = set(data.keys()) - _EXPECTED_TOP_LEVEL_KEYS
        if unknown:
            raise ConfigError(
                f"config: {toml_path}: unknown top-level key(s) {sorted(unknown)}; "
                f"expected exactly {sorted(_EXPECTED_TOP_LEVEL_KEYS)}"
            )
        missing = _EXPECTED_TOP_LEVEL_KEYS - set(data.keys())
        if missing:
            raise ConfigError(
                f"config: {toml_path}: missing required top-level key(s) {sorted(missing)}"
            )

        dial = _load_dial(data["Dial"], toml_path)
        return cls(dial)

    def __str__(self) -> str:
        return f"Dial: {self.dial}"


def _load_dial(dial_data: "Any", toml_path: str) -> "DialConfig":
    if not isinstance(dial_data, dict):
        raise ConfigError(
            f"config: {toml_path}: [Dial] must be a table containing "
            f"exactly one of [Dial.Unix] or [Dial.Tcp]"
        )
    try:
        return DialConfig.from_toml_dict(dial_data)
    except ValueError as e:
        raise ConfigError(f"config: {toml_path}: [Dial]: {e}") from e


def _sphinx_geometry_from_event(geometry_data: "Any") -> Geometry:
    """Build a Geometry from the daemon's ConnectionStatusEvent.

    The daemon serialises the geometry with the Go struct's PascalCase
    field names, which is exactly what Geometry's constructor accepts.
    """
    if not isinstance(geometry_data, dict):
        raise ConfigError("daemon sent a malformed sphinx_geometry (not a map)")
    try:
        return Geometry(**geometry_data)
    except TypeError as e:
        raise ConfigError(
            f"daemon sent a sphinx_geometry with unknown or missing keys: {e}"
        ) from e


def _pigeonhole_geometry_from_event(geometry_data: "Any") -> PigeonholeGeometry:
    """Build a PigeonholeGeometry from the daemon's ConnectionStatusEvent.

    The daemon sends PascalCase keys; PigeonholeGeometry's constructor
    takes snake_case, so translate via _PIGEONHOLE_TOML_TO_KWARG.
    """
    if not isinstance(geometry_data, dict):
        raise ConfigError("daemon sent a malformed pigeonhole_geometry (not a map)")
    unknown = set(geometry_data.keys()) - set(_PIGEONHOLE_TOML_TO_KWARG.keys())
    if unknown:
        raise ConfigError(
            f"daemon sent a pigeonhole_geometry with unknown key(s) {sorted(unknown)}"
        )
    kwargs = {_PIGEONHOLE_TOML_TO_KWARG[k]: v for k, v in geometry_data.items()}
    try:
        return PigeonholeGeometry(**kwargs)
    except TypeError as e:
        raise ConfigError(
            f"daemon sent a pigeonhole_geometry with unknown or missing keys: {e}"
        ) from e


def pretty_print_obj(obj: "Any") -> str:
    """
    Pretty-print a Python object using indentation and return the formatted string.

    This function uses `pprintpp` to format complex data structures
    (e.g., dictionaries, lists) in a readable, indented format.

    Args:
        obj (Any): The object to pretty-print.

    Returns:
        str: The pretty-printed representation of the object.
    """
    pp = pprintpp.PrettyPrinter(indent=4)
    return pp.pformat(obj)

def blake2_256_sum(data:bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()

class ServiceDescriptor:
    """
    Describes a mixnet service endpoint retrieved from the PKI document.

    A ServiceDescriptor encapsulates the necessary information for communicating
    with a service on the mix network. The service node's identity public key's hash
    is used as the destination address along with the service's queue ID.

    Attributes:
        recipient_queue_id (bytes): The identifier of the recipient's queue on the mixnet. ("Kaetzchen.endpoint" in the PKI)
        mix_descriptor (dict): A CBOR-decoded dictionary describing the mix node,
            typically includes the 'IdentityKey' and other metadata.

    Methods:
        to_destination(): Returns a tuple of (provider_id_hash, recipient_queue_id),
            where the provider ID is a 32-byte BLAKE2b hash of the IdentityKey.
    """

    def __init__(self, recipient_queue_id:bytes, mix_descriptor: "Dict[Any,Any]") -> None:
        self.recipient_queue_id = recipient_queue_id
        self.mix_descriptor = mix_descriptor

    def to_destination(self) -> "Tuple[bytes,bytes]":
        "provider identity key hash and queue id"
        provider_id_hash = blake2_256_sum(self.mix_descriptor['IdentityKey'])
        return (provider_id_hash, self.recipient_queue_id)

def find_services(capability:str, doc:"Dict[str,Any]") -> "List[ServiceDescriptor]":
    """
    Search the PKI document for services supporting the specified capability.

    This function iterates over all service nodes in the PKI document,
    deserializes each CBOR-encoded node, and looks for advertised capabilities.
    If a service provides the requested capability, it is returned as a
    `ServiceDescriptor`.

    Args:
        capability (str): The name of the capability to search for (e.g., "echo").
        doc (dict): The decoded PKI document as a Python dictionary,
            which must include a "ServiceNodes" key containing CBOR-encoded descriptors.

    Returns:
        List[ServiceDescriptor]: A list of matching service descriptors that advertise the capability.

    Raises:
        KeyError: If the 'ServiceNodes' field is missing from the PKI document.
    """
    services = []
    for node in doc['ServiceNodes']:
        mynode = cbor2.loads(node)

        # Check if the node has services in Kaetzchen field (fixed from omitempty)
        if 'Kaetzchen' in mynode:
            for cap, details in mynode['Kaetzchen'].items():
                if cap == capability:
                    service_desc = ServiceDescriptor(
                        recipient_queue_id=bytes(details['endpoint'], 'utf-8'), # why is this bytes when it's string in PKI?
                        mix_descriptor=mynode
                    )
                    services.append(service_desc)
    return services


class Config:
    """
    Configuration object for the ThinClient containing connection details and event callbacks.

    The Config class loads network configuration from a TOML file and provides optional
    callback functions that are invoked when specific events occur during client operation.

    Attributes:
        network (str): Network type ('tcp', 'unix', etc.)
        address (str): Network address (host:port for TCP, path for Unix sockets)
        geometry (Geometry): Sphinx packet geometry parameters
        on_connection_status (callable): Callback for connection status changes
        on_new_pki_document (callable): Callback for new PKI documents
        on_message_sent (callable): Callback for message transmission confirmations
        on_message_reply (callable): Callback for received message replies

    Example:
        >>> def handle_reply(event):
        ...     # Process the received reply
        ...     payload = event['payload']
        >>>
        >>> config = Config("client.toml", on_message_reply=handle_reply)
        >>> client = ThinClient(config)
    """

    def __init__(self, filepath:str,
                 on_connection_status:"Callable|None"=None,
                 on_new_pki_document:"Callable|None"=None,
                 on_message_sent:"Callable|None"=None,
                 on_message_reply:"Callable|None"=None,
                 on_daemon_disconnected:"Callable|None"=None) -> None:
        """
        Initialize the Config object.

        Args:
            filepath (str): Path to the TOML config file containing network, address, and geometry.

            on_connection_status (callable, optional): Callback invoked when the daemon's connection
                status to the mixnet changes. The callback receives a single argument:

                - event (dict): Connection status event with keys:
                    - 'is_connected' (bool): True if daemon is connected to mixnet, False otherwise
                    - 'err' (str, optional): Error message if connection failed, empty string if no error

                Example: ``{'is_connected': True, 'err': ''}``

            on_new_pki_document (callable, optional): Callback invoked when a new PKI document
                is received from the mixnet. The callback receives a single argument:

                - event (dict): PKI document event with keys:
                    - 'payload' (bytes): CBOR-encoded PKI document data stripped of signatures

                Example: ``{'payload': b'\\xa5\\x64Epoch\\x00...'}``

            on_message_sent (callable, optional): Callback invoked when a message has been
                successfully transmitted to the mixnet. The callback receives a single argument:

                - event (dict): Message sent event with keys:
                    - 'message_id' (bytes): 16-byte unique identifier for the sent message
                    - 'surbid' (bytes, optional): SURB ID if message was sent with SURB, None otherwise
                    - 'sent_at' (str): ISO timestamp when message was sent
                    - 'reply_eta' (float): Expected round-trip time in seconds for reply
                    - 'err' (str, optional): Error message if sending failed, empty string if successful

                Example: ``{'message_id': b'\\x01\\x02...', 'surbid': b'\\xaa\\xbb...', 'sent_at': '2024-01-01T12:00:00Z', 'reply_eta': 30.5, 'err': ''}``

            on_message_reply (callable, optional): Callback invoked when a reply is received
                for a previously sent message. The callback receives a single argument:

                - event (dict): Message reply event with keys:
                    - 'message_id' (bytes): 16-byte identifier matching the original message
                    - 'surbid' (bytes, optional): SURB ID if reply used SURB, None otherwise
                    - 'payload' (bytes): Reply payload data from the service
                    - 'reply_index' (int, optional): Index of reply used (relevant for channel reads)
                    - 'error_code' (int): Error code indicating success (0) or specific failure condition

                Example: ``{'message_id': b'\\x01\\x02...', 'surbid': b'\\xaa\\xbb...', 'payload': b'echo response', 'reply_index': 0, 'error_code': 0}``

        Note:
            All callbacks are optional. If not provided, the corresponding events will be ignored.
            Callbacks should be lightweight and non-blocking as they are called from the client's
            event processing loop.
        """

        cfgfile = ConfigFile.load(filepath)

        self.dial = cfgfile.dial

        self.on_connection_status = on_connection_status
        self.on_new_pki_document = on_new_pki_document
        self.on_message_sent = on_message_sent
        self.on_message_reply = on_message_reply
        self.on_daemon_disconnected = on_daemon_disconnected

    async def handle_connection_status_event(self, event: asyncio.Event) -> None:
        if self.on_connection_status:
            return await self.on_connection_status(event)

    async def handle_new_pki_document_event(self, event: asyncio.Event) -> None:
        if self.on_new_pki_document:
            await self.on_new_pki_document(event)

    async def handle_message_sent_event(self, event: asyncio.Event) -> None:
        if self.on_message_sent:
            await self.on_message_sent(event)

    async def handle_message_reply_event(self, event: asyncio.Event) -> None:
        if self.on_message_reply:
            await self.on_message_reply(event)

    async def handle_daemon_disconnected_event(self, event: dict) -> None:
        if self.on_daemon_disconnected:
            await self.on_daemon_disconnected(event)


class ThinClient:
    """
    A minimal Katzenpost Python thin client for communicating with the local
    Katzenpost client daemon over a UNIX or TCP socket.

    The thin client is responsible for:
    - Establishing a connection to the client daemon.
    - Receiving and parsing PKI documents.
    - Sending messages to mixnet services (with or without SURBs).
    - Handling replies and events via user-defined callbacks.

    All cryptographic operations are handled by the daemon, not by this client.
    """

    def __init__(self, config:Config) -> None:
        """
        Initialize the thin client with the given configuration.

        Args:
            config (Config): The configuration object containing socket details and callbacks.

        Raises:
            RuntimeError: If the network type is not recognized or config is incomplete.
        """
        self.pki_doc : Dict[Any,Any] | None = None
        self._pki_doc_cache : Dict[int, Dict[Any,Any]] = {}  # epoch -> parsed PKI doc
        self.config = config
        # Geometry is runtime state the daemon supplies in its
        # ConnectionStatusEvent during the handshake; None until the
        # first connection status event has been parsed.
        self.geometry : "Geometry | None" = None
        self.pigeonhole_geometry : "PigeonholeGeometry | None" = None
        self.reply_received_event = asyncio.Event()
        self._is_connected : bool = False  # Track connection state
        self._stopping : bool = False  # Track shutdown state to suppress expected errors
        self._received_shutdown : bool = False  # Track if daemon sent ShutdownEvent before disconnect
        self._daemon_instance_token : "bytes|None" = None  # Daemon instance token for reconnect detection
        self._in_flight_resends : Dict[bytes, Dict[str, Any]] = {}  # envelope_hash -> request dict
        self.instance_token : bytes = os.urandom(16)  # Client instance token for session resumption

        # Mutexes to serialize socket send/recv operations:
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()

        # Letterbox for each response associated (by query_id) with a request.
        self.response_queues : Dict[bytes, asyncio.Queue[Dict[str,Any]]] = {}  # (query_id|message_id) -> Queue
        self.ack_queues : Dict[bytes, asyncio.Queue[Dict[str,Any]]] = {}  # (query_id|message_id) -> Queue

        self.logger = logging.getLogger('thinclient')
        self.logger.setLevel(logging.DEBUG)
        # Only add handler if none exists to avoid duplicate log messages
        # XXX: commented out because it did in fact log twice:
        #if not self.logger.handlers:
        #    handler = logging.StreamHandler(sys.stderr)
        #    self.logger.addHandler(handler)

        if self.config.dial is None:
            raise RuntimeError("config.dial is None")

        dialer = self.config.dial.resolve()
        self.socket, self.server_addr = dialer.setup_socket()


    async def start(self, loop:asyncio.AbstractEventLoop) -> None:
        """
        Start the thin client: establish connection to the daemon, read initial events,
        and begin the background event loop.

        Args:
            loop (asyncio.AbstractEventLoop): The running asyncio event loop.

        Exceptions:
            BrokenPipeError
        """
        self.logger.debug("connecting to daemon")
        await loop.sock_connect(self.socket, self.server_addr)

        # 1st message is always a status event
        response = await self.recv(loop)
        assert response is not None
        assert response["connection_status_event"] is not None
        await self.handle_response(response)

        # 2nd message is always a new pki doc event
        response = await self.recv(loop)
        assert response is not None
        assert response["new_pki_document_event"] is not None, response
        await self.handle_response(response)

        # 3rd: send SessionToken and read SessionTokenReply
        session_token_req = cbor2.dumps({
            "session_token": {
                "client_instance_token": self.instance_token,
            }
        })
        length_prefix = struct.pack('>I', len(session_token_req))
        await self._send_all(length_prefix + session_token_req)

        session_reply = await self.recv(loop)
        assert session_reply.get("session_token_reply") is not None, f"expected session_token_reply, got {session_reply}"
        self.logger.debug(f"Session token reply: resumed={session_reply['session_token_reply'].get('resumed')}")

        # Start the read loop as a background task
        self.logger.debug("starting read loop")
        self.task = loop.create_task(self.worker_loop(loop))
        def handle_loop_err(task):
            # Check stopping flag first - if we're shutting down, all errors are expected
            if self._stopping:
                return
            try:
                result = task.result()
            except asyncio.CancelledError:
                # Task was cancelled during shutdown - expected behavior
                pass
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                # Connection errors can occur due to race conditions during shutdown
                # Double-check _stopping flag as it may have been set after the exception
                if not self._stopping:
                    self.logger.error(f"Unexpected connection error in worker loop: {e}")
            except Exception:
                import traceback
                traceback.print_exc()
                raise
        self.task.add_done_callback(handle_loop_err)

    def get_config(self) -> Config:
        """
        Returns the current configuration object.

        Returns:
            Config: The client configuration in use.
        """
        return self.config

    def is_connected(self) -> bool:
        """
        Returns True if the daemon is currently connected to the mixnet.

        Note the distinction: this reflects the daemon's *mixnet*
        connectivity, not the local socket between this thin client and
        the daemon. The daemon may be reachable while the mixnet itself
        is unreachable; in that case the local socket is fine but this
        method returns False, and ``send_message`` / ``blocking_send_message``
        will raise ``ThinClientOfflineError``. The latest value is updated
        from ``ConnectionStatusEvent``s pushed by the daemon.

        Returns:
            bool: True if the daemon is connected to the mixnet, False
            otherwise (offline mode).
        """
        return self._is_connected

    def _create_socket(self) -> socket.socket:
        """Create a new non-blocking socket matching the configured transport.

        Also refreshes self.server_addr, since for abstract unix sockets each
        reconnect binds to a fresh random client-side path.
        """
        dialer = self.config.dial.resolve()
        sock, server_addr = dialer.setup_socket()
        self.server_addr = server_addr
        return sock

    def stop(self) -> None:
        """
        Gracefully shut down the client and close its socket.
        Sends a thin_close message to the daemon so it can clean up
        ARQ state for this connection before disconnecting.
        """
        self.logger.debug("closing connection to daemon")
        self._stopping = True  # Set flag to suppress expected BrokenPipeError
        # Send thin_close to daemon so it cleans up ARQ state for this AppID.
        # Without this, stale ARQ entries poll forever and crowd out new requests.
        try:
            close_msg = cbor2.dumps({"thin_close": {}})
            length_prefix = struct.pack('>I', len(close_msg))
            self.socket.sendall(length_prefix + close_msg)
        except Exception:
            pass  # Best effort — socket may already be closed
        self.socket.close()
        self.task.cancel()

    def disconnect(self) -> None:
        """
        Close the connection without sending thin_close.
        The daemon preserves all state for this client's app ID, allowing
        the client to reconnect and resume with the same session token.
        """
        self.logger.debug("disconnecting from daemon (preserving state)")
        self._stopping = True
        self.socket.close()
        self.task.cancel()

    async def _send_all(self, data: bytes) -> None:
        """
        Send all data using async socket operations with mutex protection.

        This method uses a mutex to prevent race conditions when multiple
        coroutines try to send data over the same socket simultaneously.

        Args:
            data (bytes): Data to send.
        """
        async with self._send_lock:
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(self.socket, data)

    async def __recv_exactly(self, total:int, loop:asyncio.AbstractEventLoop) -> bytes:
      "receive exactly (total) bytes or die trying raising BrokenPipeError"
      buf = bytearray(total)
      remain = memoryview(buf)
      while len(remain):
        if not (nread := await loop.sock_recv_into(self.socket, remain)):
            raise BrokenPipeError
        remain = remain[nread:]
      return buf

    async def recv(self, loop:asyncio.AbstractEventLoop) -> "Dict[Any,Any]":
        """
        Receive a CBOR-encoded message from the daemon.

        Args:
            loop (asyncio.AbstractEventLoop): Event loop to use for socket reads.

        Returns:
            dict: Decoded CBOR response from the daemon.

        Raises:
            BrokenPipeError: If connection fails
            ValueError: If message framing fails.
        """
        async with self._recv_lock:
          length_prefix = await self.__recv_exactly(4, loop)
          message_length = struct.unpack('>I', length_prefix)[0]
          raw_data = await self.__recv_exactly(message_length, loop)
        try:
          response = cbor2.loads(raw_data)
        except cbor2.CBORDecodeValueError as e:
          self.logger.error(f"{e}")
          raise ValueError(f"{e}")
        if not (set(response.keys()) & {'new_pki_document_event'}):
            self.logger.debug(f"Received daemon response: [{len(raw_data)}] {type(response)} {response}")
        return response

    async def _reconnect(self, loop: asyncio.AbstractEventLoop) -> None:
        """Reconnect to the daemon with exponential backoff. Blocks until connected or stopped."""
        backoff = 1.0
        max_backoff = 60.0

        while not self._stopping:
            await asyncio.sleep(backoff)
            if self._stopping:
                return

            try:
                self.logger.debug(f"Attempting to reconnect to daemon via {self.config.dial}")
                self.socket = self._create_socket()
                await loop.sock_connect(self.socket, self.server_addr)

                # Handshake: read ConnectionStatusEvent
                response1 = await self.recv(loop)
                if response1.get("connection_status_event") is None:
                    self.logger.error("Reconnect handshake failed: expected connection_status_event")
                    self.socket.close()
                    continue
                self.parse_status(response1["connection_status_event"])
                await self.config.handle_connection_status_event(response1["connection_status_event"])

                # Handshake: read NewPKIDocumentEvent (may have empty payload)
                response2 = await self.recv(loop)
                if response2.get("new_pki_document_event") is not None:
                    if response2["new_pki_document_event"].get("payload"):
                        self.parse_pki_doc(response2["new_pki_document_event"])
                        await self.config.handle_new_pki_document_event(response2["new_pki_document_event"])

                # Handshake: send SessionToken and read SessionTokenReply
                session_token_req = cbor2.dumps({
                    "session_token": {
                        "client_instance_token": self.instance_token,
                    }
                })
                length_prefix = struct.pack('>I', len(session_token_req))
                await self._send_all(length_prefix + session_token_req)

                response3 = await self.recv(loop)
                if response3.get("session_token_reply") is None:
                    self.logger.error("Reconnect handshake failed: expected session_token_reply")
                    self.socket.close()
                    continue
                resumed = response3["session_token_reply"].get("resumed", False)
                self.logger.info(f"Reconnected to daemon (connected={self._is_connected}, resumed={resumed})")
                return

            except (BrokenPipeError, ConnectionResetError, OSError, asyncio.CancelledError) as e:
                if self._stopping:
                    return
                self.logger.debug(f"Reconnect failed: {e} (backoff {backoff}s)")
                backoff = min(backoff * 2, max_backoff)
                try:
                    self.socket.close()
                except Exception:
                    pass

    async def _replay_in_flight_resends(self) -> None:
        """Re-send all tracked in-flight requests to the daemon after reconnect."""
        for key, request in list(self._in_flight_resends.items()):
            try:
                cbor_request = cbor2.dumps(request)
                length_prefix = struct.pack('>I', len(cbor_request))
                await self._send_all(length_prefix + cbor_request)
                self.logger.debug(f"Replayed in-flight request: {key.hex()[:16]}...")
            except Exception as e:
                self.logger.error(f"Failed to replay in-flight request: {e}")

    async def _read_until_disconnect(self, loop: asyncio.AbstractEventLoop) -> "Exception|None":
        """Read and dispatch messages until disconnect or stop. Returns the disconnect error, or None if stopped."""
        while not self._stopping:
            try:
                response = await self.recv(loop)
            except asyncio.CancelledError:
                return None
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                if self._stopping:
                    return None
                return e
            except Exception as e:
                if self._stopping:
                    return None
                self.logger.error(f"Error reading from socket: {e}")
                return e
            else:
                def handle_response_err(task):
                    try:
                        task.result()
                    except Exception:
                        import traceback
                        traceback.print_exc()
                resp = asyncio.create_task(self.handle_response(response))
                resp.add_done_callback(handle_response_err)
        return None

    async def worker_loop(self, loop: asyncio.events.AbstractEventLoop) -> None:
        """
        Background task that listens for events and dispatches them.
        Survives daemon disconnects by automatically reconnecting with exponential backoff.
        Only stopping (from stop()) causes this task to exit.
        """
        while not self._stopping:
            disconnect_err = await self._read_until_disconnect(loop)
            if disconnect_err is None:
                return

            self.logger.info(f"Daemon disconnected (graceful={self._received_shutdown}, err={disconnect_err})")
            try:
                self.socket.close()
            except Exception:
                pass
            self._is_connected = False
            previous_token = self._daemon_instance_token

            await self.config.handle_daemon_disconnected_event({
                "is_graceful": self._received_shutdown,
                "error": str(disconnect_err) if disconnect_err else None,
            })
            self._received_shutdown = False

            await self._reconnect(loop)
            if self._stopping:
                return

            if self._daemon_instance_token != previous_token:
                self.logger.info("New daemon instance detected, replaying in-flight requests")
                await self._replay_in_flight_resends()
            else:
                self.logger.info("Same daemon instance, skipping replay")

    def parse_status(self, event: "Dict[str,Any]") -> None:
        """
        Parse a connection status event and update connection state.
        """
        self.logger.debug("parse status")
        assert event is not None

        self._is_connected = event.get("is_connected", False)
        token = event.get("instance_token")
        if token is not None:
            self._daemon_instance_token = bytes(token) if not isinstance(token, bytes) else token

        # The daemon supplies the geometries here rather than the thin
        # client carrying them in its config file. A daemon that omits
        # them is incompatible.
        sphinx_geo = event.get("sphinx_geometry")
        if sphinx_geo is not None:
            self.geometry = _sphinx_geometry_from_event(sphinx_geo)
        else:
            self.logger.error("Daemon did not supply sphinx_geometry in its ConnectionStatusEvent (incompatible daemon)")
        pigeonhole_geo = event.get("pigeonhole_geometry")
        if pigeonhole_geo is not None:
            self.pigeonhole_geometry = _pigeonhole_geometry_from_event(pigeonhole_geo)
        else:
            self.logger.error("Daemon did not supply pigeonhole_geometry in its ConnectionStatusEvent (incompatible daemon)")

        if self._is_connected:
            self.logger.debug("Daemon is connected to mixnet - full functionality available")
        else:
            self.logger.info("Daemon is not connected to mixnet - entering offline mode (channel operations will work)")

        self.logger.debug("parse status success")

    def pki_document(self) -> "Dict[str,Any] | None":
        """
        Return the most recent PKI consensus document the daemon has
        forwarded to this thin client.

        The document is a CBOR map describing the current mixnet topology,
        the set of available services, and per-node public-key material.
        Useful inputs include the PKI epoch, the list of mix nodes, the
        list of service providers, and the replica descriptors consulted
        by Pigeonhole.

        Returns:
            Dict[str, Any] | None: The parsed CBOR PKI document, or
            ``None`` if the daemon has not yet forwarded one (most
            commonly on a freshly-connected client, before the first
            ``on_new_pki_document`` callback has fired).
        """
        return self.pki_doc

    def pki_document_for_epoch(self, epoch:int) -> "Dict[str,Any]":
        """
        Return the cached PKI document for a specific epoch.

        Falls back to the current document if the requested epoch
        is not cached. Raises if no document is available at all.

        Args:
            epoch (int): The epoch number.

        Returns:
            dict: Parsed PKI document for the given epoch.

        Raises:
            Exception: If no PKI document is available.
        """
        doc = self._pki_doc_cache.get(epoch)
        if doc is not None:
            return doc
        if self.pki_doc is not None:
            return self.pki_doc
        raise Exception("no PKI document available for the requested epoch")

    async def get_pki_document_raw(self, epoch:int = 0) -> "Tuple[bytes,int]":
        """
        Return the cert.Certificate-wrapped signed PKI document for the
        requested epoch, with every directory authority signature intact.

        The thin client receives the stripped PKI document by default
        (via the ``on_new_pki_document`` callback, also available through
        :py:meth:`pki_document` and :py:meth:`pki_document_for_epoch`);
        the daemon nils the signature map before forwarding it. Use this
        method when the caller wishes to verify the directory authority
        signatures itself: the returned payload may be deserialized and
        verified with the katzenpost ``core/pki.FromPayload`` routine
        against the authorities listed in ``client.toml``.

        Args:
            epoch (int): Epoch for which the signed PKI document should
                be returned. Pass ``0`` (the default) to request the
                document the daemon believes is current.

        Returns:
            Tuple[bytes, int]: ``(payload, epoch)`` where ``payload`` is
            the cert.Certificate-wrapped signed PKI document and
            ``epoch`` is the epoch of the returned document. When ``0``
            was passed in, ``epoch`` echoes the epoch the daemon
            resolved to.

        Raises:
            Exception: If the daemon has no cached document for the
                requested epoch, or any other error code is returned.
        """
        query_id = self.new_query_id()

        request = {
            "get_pki_document": {
                "query_id": query_id,
                "epoch": epoch,
            }
        }

        reply = await self._send_and_wait(query_id=query_id, request=request)

        returned_epoch = reply.get("epoch", 0)
        error_code = reply.get("error_code", 0)
        if error_code != THIN_CLIENT_SUCCESS:
            error_msg = thin_client_error_to_string(error_code)
            raise Exception(
                f"get_pki_document_raw failed for epoch {epoch}: {error_msg}"
            )

        return reply.get("payload"), returned_epoch

    def parse_pki_doc(self, event: "Dict[str,Any]") -> None:
        """
        Parse and store a new PKI document received from the daemon.
        """
        self.logger.debug("parse pki doc")
        assert event is not None
        assert event["payload"] is not None
        raw_pki_doc = cbor2.loads(event["payload"])
        self.pki_doc = raw_pki_doc

        epoch = raw_pki_doc.get("Epoch")
        if epoch is not None:
            self._pki_doc_cache[epoch] = raw_pki_doc
            self.logger.debug("Cached PKI document for epoch %d", epoch)
            max_cached_epochs = 5
            if len(self._pki_doc_cache) > max_cached_epochs:
                oldest_epoch = epoch - max_cached_epochs
                stale = [e for e in self._pki_doc_cache if e < oldest_epoch]
                for e in stale:
                    del self._pki_doc_cache[e]

        self.logger.debug("parse pki doc success")

    def get_services(self, capability:str) -> "List[ServiceDescriptor]":
        """
        Look up all services in the PKI that advertise a given capability.

        Args:
            capability (str): Capability name (e.g., "echo").

        Returns:
            list[ServiceDescriptor]: Matching services.xsy

        Raises:
            Exception: If PKI is missing or no services match.
        """
        doc = self.pki_document()
        if doc == None:
            raise Exception("pki doc is nil")
        descriptors = find_services(capability, doc)
        if not descriptors:
            raise Exception("service not found in pki doc")
        return descriptors

    def get_service(self, service_name:str) -> ServiceDescriptor:
        """
        Select one random service matching a capability from the current
        PKI document.

        Multiple mix nodes may advertise the same capability; this method
        returns an arbitrary one. To see every advertised instance, use
        ``get_services``.

        Args:
            service_name (str): The capability name (e.g. ``"echo"``,
                ``"courier"``).

        Returns:
            ServiceDescriptor: One of the matching services.

        Raises:
            Exception: If the PKI document is missing, or no node in the
                current consensus advertises ``service_name``.
        """
        service_descriptors = self.get_services(service_name)
        return random.choice(service_descriptors)

    def get_all_couriers(self) -> "List[Tuple[bytes, bytes]]":
        """
        Return every courier service advertised in the current PKI
        document, each described by an ``(identity_hash, queue_id)``
        tuple. The list reflects only the couriers that the current
        consensus regards as serving.

        The principal caller is the nested-copy-command machinery, which
        needs to choose particular couriers rather than accept the random
        draw made on the caller's behalf by
        ``start_resending_copy_command``; for simple cases where any
        courier will do, the default routing path is usually preferable.

        Returns:
            list[tuple[bytes, bytes]]: List of (identity_hash, queue_id) tuples.

        Raises:
            Exception: If no couriers are available.
        """
        services = self.get_services("courier")
        couriers = []
        for svc in services:
            identity_hash = blake2_256_sum(svc.mix_descriptor['IdentityKey'])
            couriers.append((identity_hash, svc.recipient_queue_id))
        return couriers

    def get_distinct_couriers(self, n:int) -> "List[Tuple[bytes, bytes]]":
        """
        Draw ``n`` couriers uniformly at random from the list returned by
        ``get_all_couriers``, without replacement, so that no two entries
        in the returned list refer to the same courier. This is the usual
        building block for a nested copy command, every layer of which
        must be carried by a different courier.

        Args:
            n (int): Number of distinct couriers to return.

        Returns:
            list[tuple[bytes, bytes]]: List of (identity_hash, queue_id) tuples.

        Raises:
            Exception: If the current PKI document advertises fewer than
                ``n`` couriers.
        """
        couriers = self.get_all_couriers()
        if len(couriers) < n:
            raise Exception("not enough couriers available")
        return random.sample(couriers, n)

    async def blocking_send_message(self, payload:bytes|str, dest_node:bytes, dest_queue:bytes, timeout_seconds:float=30.0) -> bytes:
        """
        Send a message and block until a reply is received or timeout.

        Args:
            payload (bytes or str): Message payload.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.
            timeout_seconds (float): Timeout in seconds (default 30).

        Returns:
            bytes: Reply payload from the destination service.

        Raises:
            ThinClientOfflineError: If in offline mode.
            asyncio.TimeoutError: If no reply within timeout.
        """
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send message in offline mode - daemon not connected to mixnet")

        surb_id = self.new_surb_id()
        reply_future = asyncio.get_event_loop().create_future()

        original_handler = self.config.on_message_reply

        async def capture_reply(event):
            if event.get("surbid") == surb_id and not reply_future.done():
                reply_future.set_result(event.get("payload"))
            if original_handler:
                await original_handler(event)

        self.config.on_message_reply = capture_reply
        try:
            await self.send_message(surb_id, payload, dest_node, dest_queue)
            return await asyncio.wait_for(reply_future, timeout=timeout_seconds)
        finally:
            self.config.on_message_reply = original_handler

    @staticmethod
    def new_message_id() -> bytes:
        """
        Generate a new 16-byte random message ID.

        Message IDs are used to correlate ``SendMessage`` requests with their
        corresponding ``MessageSentEvent`` and (if a SURB is present)
        ``MessageReplyEvent``. Callers generally do not need to construct
        one by hand — ``blocking_send_message`` does it internally — but
        this helper is exposed for callers composing requests manually.
        Randomness is drawn from ``os.urandom``.

        Returns:
            bytes: Random 16-byte identifier.
        """
        return os.urandom(MESSAGE_ID_SIZE)

    def new_surb_id(self) -> bytes:
        """
        Generate a new random SURB ID.

        SURB IDs identify which Single Use Reply Block a given
        ``on_message_reply`` event corresponds to. Pass the returned bytes
        as the ``surb_id`` argument to ``send_message``, then watch the
        callback for a matching reply. Randomness is drawn from
        ``os.urandom``.

        Returns:
            bytes: Random identifier of ``SURB_ID_SIZE`` bytes.
        """
        return os.urandom(SURB_ID_SIZE)

    def new_query_id(self) -> bytes:
        """
        Generate a new 16-byte random query ID.

        Query IDs correlate requests and replies within the thin client ↔
        daemon CBOR protocol (distinct from mix-network SURB IDs, which
        identify replies within the mixnet itself). Most callers never
        touch query IDs directly; they are used internally by the
        Pigeonhole API helpers. Randomness is drawn from ``os.urandom``.

        Returns:
            bytes: Random 16-byte identifier.
        """
        return os.urandom(16)


    async def _send_and_wait(self, *, query_id:bytes, request: Dict[str, Any]) -> Dict[str, Any]:
        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        assert query_id not in self.response_queues
        self.response_queues[query_id] = asyncio.Queue(maxsize=1)
        request_type = list(request.keys())[0]
        try:
            await self._send_all(length_prefixed_request)
            self.logger.info(f"{request_type} request sent.")
            reply = await self.response_queues[query_id].get()
            self.logger.info(f"{request_type} response received.")
            # TODO error handling, see _wait_for_channel_reply
            return reply
        except asyncio.CancelledError:
            self.logger.info("{request_type} task cancelled.")
            raise
        finally:
            del self.response_queues[query_id]

    async def handle_response(self, response: "Dict[str,Any]") -> None:
        """
        Dispatch a parsed CBOR response to the appropriate handler or callback.
        """
        assert response is not None

        if response.get("shutdown_event") is not None:
            self.logger.info("Received ShutdownEvent from daemon")
            self._received_shutdown = True
            return
        if response.get("connection_status_event") is not None:
            self.logger.debug("connection status event")
            self.parse_status(response["connection_status_event"])
            await self.config.handle_connection_status_event(response["connection_status_event"])
            return
        if response.get("new_pki_document_event") is not None:
            self.logger.debug("new pki doc event")
            event = response["new_pki_document_event"]
            if event.get("payload") is not None:
                self.parse_pki_doc(event)
                await self.config.handle_new_pki_document_event(event)
            return
        if response.get("message_sent_event") is not None:
            self.logger.debug("message sent event")
            await self.config.handle_message_sent_event(response["message_sent_event"])
            return
        if response.get("message_reply_event") is not None:
            self.logger.debug("message reply event")
            reply = response["message_reply_event"]
            self.reply_received_event.set()
            await self.config.handle_message_reply_event(reply)
            return
        for reply_type, reply in response.items():
            if not reply:
                continue
            self.logger.debug(f"channel {reply_type} event")
            if not reply_type.endswith("_reply") or not (query_id := reply.get("query_id", None)):
                self.logger.debug(f"{reply_type} is not a reply, or can't get query_id")
                continue
            if not (queue := self.response_queues.get(query_id, None)):
                self.logger.debug(f"query_id for {reply_type} has no listener")
                continue
            # avoid blocking recv loop:
            asyncio.create_task(queue.put(reply))



    async def send_message_without_reply(self, payload:bytes|str, dest_node:bytes, dest_queue:bytes) -> None:
        """
        Send a fire-and-forget message with no SURB or reply handling.
        This method requires mixnet connectivity.

        Args:
            payload (bytes or str): Message payload.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.

        Raises:
            ThinClientOfflineError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send_message_without_reply in offline mode - daemon not connected to mixnet")

        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes

        # Create the SendMessage structure
        send_message = {
            "id": None,  # No ID for fire-and-forget messages
            "with_surb": False,
            "surbid": None,  # No SURB ID for fire-and-forget messages
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
            "payload": payload,
        }

        # Wrap in the new Request structure
        request = {
            "send_message": send_message
        }

        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        try:
            await self._send_all(length_prefixed_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    async def send_message(self, surb_id:bytes, payload:bytes|str, dest_node:bytes, dest_queue:bytes) -> None:
        """
        Send a message using a SURB to allow the recipient to send a reply.
        This method requires mixnet connectivity.

        Args:
            surb_id (bytes): SURB identifier for reply correlation.
            payload (bytes or str): Message payload.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.

        Raises:
            ThinClientOfflineError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send message in offline mode - daemon not connected to mixnet")

        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes

        # Create the SendMessage structure
        send_message = {
            "id": None,  # No ID for regular messages
            "with_surb": True,
            "surbid": surb_id,
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
            "payload": payload,
        }

        # Wrap in the new Request structure
        request = {
            "send_message": send_message
        }

        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        try:
            await self._send_all(length_prefixed_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def pretty_print_pki_doc(self, doc: "Dict[str,Any]") -> None:
        """
        Pretty-print a parsed PKI document with fully decoded CBOR nodes.

        Args:
            doc (dict): Raw PKI document from the daemon.
        """
        assert doc is not None
        assert doc['GatewayNodes'] is not None
        assert doc['ServiceNodes'] is not None
        assert doc['Topology'] is not None

        new_doc = doc
        gateway_nodes = []
        service_nodes = []
        topology = []

        for gateway_cert_blob in doc['GatewayNodes']:
            gateway_cert = cbor2.loads(gateway_cert_blob)
            gateway_nodes.append(gateway_cert)

        for service_cert_blob in doc['ServiceNodes']:
            service_cert = cbor2.loads(service_cert_blob)
            service_nodes.append(service_cert)

        for layer in doc['Topology']:
            for mix_desc_blob in layer:
                mix_cert = cbor2.loads(mix_desc_blob)
                topology.append(mix_cert) # flatten, no prob, relax

        new_doc['GatewayNodes'] = gateway_nodes
        new_doc['ServiceNodes'] = service_nodes
        new_doc['Topology'] = topology
        pretty_print_obj(new_doc)


