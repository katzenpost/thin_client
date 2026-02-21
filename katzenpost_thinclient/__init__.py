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

# Thin Client Error Codes (matching Go implementation)
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
    }
    return error_messages.get(error_code, f"Unknown thin client error code: {error_code}")

class ThinClientOfflineError(Exception):
    pass

# Export public API
__all__ = [
    'ThinClient',
    'ThinClientOfflineError',
    'Config',
    'ServiceDescriptor',
    'WriteChannelReply',
    'ReadChannelReply',
    'find_services'
]

# SURB_ID_SIZE is the size in bytes for the
# Katzenpost SURB ID.
SURB_ID_SIZE = 16

# MESSAGE_ID_SIZE is the size in bytes for an ID
# which is unique to the sent message.
MESSAGE_ID_SIZE = 16

# STREAM_ID_LENGTH is the length of a stream ID in bytes.
# Used for multi-call envelope encoding streams.
STREAM_ID_LENGTH = 16


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


def tombstone_plaintext(geometry: PigeonholeGeometry) -> bytes:
    """
    Creates a tombstone plaintext (all zeros) for the given geometry.

    A tombstone is used to overwrite/delete a pigeonhole box by filling it
    with zeros.

    Args:
        geometry: Pigeonhole geometry defining the payload size.

    Returns:
        bytes: Zero-filled bytes of length max_plaintext_payload_length.

    Raises:
        ValueError: If the geometry is None or invalid.
    """
    if geometry is None:
        raise ValueError("geometry cannot be None")
    geometry.validate()
    return bytes(geometry.max_plaintext_payload_length)


def is_tombstone_plaintext(geometry: PigeonholeGeometry, plaintext: bytes) -> bool:
    """
    Checks if a plaintext is a tombstone (all zeros).

    Args:
        geometry: Pigeonhole geometry defining the expected payload size.
        plaintext: The plaintext bytes to check.

    Returns:
        bool: True if the plaintext is the correct length and all zeros.
    """
    if geometry is None:
        return False
    if len(plaintext) != geometry.max_plaintext_payload_length:
        return False
    # Constant-time comparison to check if all bytes are zero
    return all(b == 0 for b in plaintext)


class ConfigFile:
    """
    ConfigFile represents everything loaded from a TOML file:
    network, address, and geometry.
    """
    def __init__(self, network:str, address:str, geometry:Geometry) -> None:
        self.network : str = network
        self.address : str = address
        self.geometry : Geometry = geometry

    @classmethod
    def load(cls, toml_path:str) -> "ConfigFile":
        with open(toml_path, 'r') as f:
            data = toml.load(f)
        network = data.get('Network')
        assert isinstance(network, str)
        address = data.get('Address')
        assert isinstance(address, str)
        geometry_data = data.get('SphinxGeometry')
        assert isinstance(geometry_data, dict)
        geometry : Geometry = Geometry(**geometry_data)
        return cls(network, address, geometry)

    def __str__(self) -> str:
        return (
            f"Network: {self.network}\n"
            f"Address: {self.address}\n"
            f"Geometry:\n{self.geometry}"
        )


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
                 on_message_reply:"Callable|None"=None) -> None:
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

        self.network = cfgfile.network
        self.address = cfgfile.address
        self.geometry = cfgfile.geometry

        self.on_connection_status = on_connection_status
        self.on_new_pki_document = on_new_pki_document
        self.on_message_sent = on_message_sent
        self.on_message_reply = on_message_reply

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
        self.config = config
        self.reply_received_event = asyncio.Event()
        self.channel_reply_event = asyncio.Event()
        self.channel_reply_data : Dict[Any,Any] | None = None
        # For handling async read channel responses with message ID correlation
        self.pending_read_channels : Dict[bytes,asyncio.Event] = {}  # message_id -> asyncio.Event
        self.read_channel_responses : Dict[bytes,bytes] = {}  # message_id -> payload
        self._is_connected : bool = False  # Track connection state

        # Mutexes to serialize socket send/recv operations:
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()

        # Letterbox for each response associated (by query_id) with a request.
        self.response_queues : Dict[bytes, asyncio.Queue[Dict[str,Any]]] = {}  # (query_id|message_id) -> Queue
        self.ack_queues : Dict[bytes, asyncio.Queue[Dict[str,Any]]] = {}  # (query_id|message_id) -> Queue

        # Channel query message ID correlation (for send_channel_query_await_reply)
        self.pending_channel_message_queries : Dict[bytes, asyncio.Event] = {}  # message_id -> Event
        self.channel_message_query_responses : Dict[bytes, bytes] = {}  # message_id -> payload

        # For message ID-based reply matching (old channel API)
        self._expected_message_id : bytes | None = None
        self._received_reply_payload : bytes | None = None
        self._reply_received_for_message_id : asyncio.Event | None = None
        self.logger = logging.getLogger('thinclient')
        self.logger.setLevel(logging.DEBUG)
        # Only add handler if none exists to avoid duplicate log messages
        # XXX: commented out because it did in fact log twice:
        #if not self.logger.handlers:
        #    handler = logging.StreamHandler(sys.stderr)
        #    self.logger.addHandler(handler)

        if self.config.network is None:
            raise RuntimeError("config.network is None")

        network: str = self.config.network.lower()
        self.server_addr : str | Tuple[str,int]
        if network.lower().startswith("tcp"):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, port_str = self.config.address.split(":")
            self.server_addr = (host, int(port_str))
        elif network.lower().startswith("unix"):
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

            if self.config.address.startswith("@"):
                # Abstract UNIX socket: leading @ means first byte is null
                abstract_name = self.config.address[1:]
                self.server_addr = f"\0{abstract_name}"

                # Bind to a unique abstract socket for this client
                random_bytes = [random.randint(0, 255) for _ in range(16)]
                hex_string = ''.join(format(byte, '02x') for byte in random_bytes)
                client_abstract = f"\0katzenpost_python_thin_client_{hex_string}"
                self.socket.bind(client_abstract)
            else:
                # Filesystem UNIX socket
                self.server_addr = self.config.address

            self.socket.setblocking(False)
        else:
            raise RuntimeError(f"Unknown network type: {self.config.network}")

        self.socket.setblocking(False)


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
        server_addr : str | Tuple[str,int] = ''

        if self.config.network.lower().startswith("tcp"):
            host, port_str = self.config.address.split(":")
            server_addr = (host, int(port_str))
        elif self.config.network.lower().startswith("unix"):
            if self.config.address.startswith("@"):
                server_addr = '\0' + self.config.address[1:]
            else:
                server_addr = self.config.address
        else:
            raise RuntimeError(f"Unknown network type: {self.config.network}")

        await loop.sock_connect(self.socket, server_addr)

        # 1st message is always a status event
        response = await self.recv(loop)
        assert response is not None
        assert response["connection_status_event"] is not None
        await self.handle_response(response)

        # 2nd message is always a new pki doc event
        #response = await self.recv(loop)
        #assert response is not None
        #assert response["new_pki_document_event"] is not None, response
        #await self.handle_response(response)
        
        # Start the read loop as a background task
        self.logger.debug("starting read loop")
        self.task = loop.create_task(self.worker_loop(loop))
        def handle_loop_err(task):
            try:
                result = task.result()
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
        Returns True if the daemon is connected to the mixnet.

        Returns:
            bool: True if connected, False if in offline mode.
        """
        return self._is_connected
        
    def stop(self) -> None:
        """
        Gracefully shut down the client and close its socket.
        """
        self.logger.debug("closing connection to daemon")
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
        response = {k:v for k,v in response.items() if v}  # filter empty KV pairs
        if not (set(response.keys()) & {'new_pki_document_event'}):
            self.logger.debug(f"Received daemon response: [{len(raw_data)}] {type(response)} {response}")
        return response

    async def worker_loop(self, loop:asyncio.events.AbstractEventLoop) -> None:
        """
        Background task that listens for events and dispatches them.
        """
        self.logger.debug("read loop start")
        while True:
            try:
                response = await self.recv(loop)
            except asyncio.CancelledError:
                # Handle cancellation of the read loop
                self.logger.error(f"worker_loop cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error reading from socket: {e}")
                raise
            else:
                def handle_response_err(task):
                    try:
                        result = task.result()
                    except Exception:
                        import traceback
                        traceback.print_exc()
                        raise
                resp = asyncio.create_task(self.handle_response(response))
                resp.add_done_callback(handle_response_err)

    def parse_status(self, event: "Dict[str,Any]") -> None:
        """
        Parse a connection status event and update connection state.
        """
        self.logger.debug("parse status")
        assert event is not None

        self._is_connected = event.get("is_connected", False)

        if self._is_connected:
            self.logger.debug("Daemon is connected to mixnet - full functionality available")
        else:
            self.logger.info("Daemon is not connected to mixnet - entering offline mode (channel operations will work)")

        self.logger.debug("parse status success")

    def pki_document(self) -> "Dict[str,Any] | None":
        """
        Retrieve the latest PKI document received.

        Returns:
            dict: Parsed CBOR PKI document.
        """
        return self.pki_doc

    def parse_pki_doc(self, event: "Dict[str,Any]") -> None:
        """
        Parse and store a new PKI document received from the daemon.
        """
        self.logger.debug("parse pki doc")
        assert event is not None
        assert event["payload"] is not None
        raw_pki_doc = cbor2.loads(event["payload"])
        self.pki_doc = raw_pki_doc
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
        Select a random service matching a capability.

        Args:
            service_name (str): The capability name (e.g., "echo").

        Returns:
            ServiceDescriptor: One of the matching services.
        """
        service_descriptors = self.get_services(service_name)
        return random.choice(service_descriptors)

    @staticmethod
    def new_message_id() -> bytes:
        """
        Generate a new 16-byte message ID for use with ARQ sends.

        Returns:
            bytes: Random 16-byte identifier.
        """
        return os.urandom(MESSAGE_ID_SIZE)

    def new_surb_id(self) -> bytes:
        """
        Generate a new 16-byte SURB ID for reply-capable sends.

        Returns:
            bytes: Random 16-byte identifier.
        """
        return os.urandom(SURB_ID_SIZE)

    def new_query_id(self) -> bytes:
        """
        Generate a new 16-byte query ID for channel API operations.

        Returns:
            bytes: Random 16-byte identifier.
        """
        return os.urandom(16)

    @staticmethod
    def new_stream_id() -> bytes:
        """
        Generate a new 16-byte stream ID for copy stream operations.

        Stream IDs are used to identify encoder instances for multi-call
        envelope encoding streams. All calls for the same stream must use
        the same stream ID.

        Returns:
            bytes: Random 16-byte stream identifier.
        """
        return os.urandom(STREAM_ID_LENGTH)

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

    async def _wait_for_channel_reply(self, expected_reply_type: str) -> Dict[Any, Any]:
        """
        Wait for a channel API reply using response queues (simulating Rust's event sinks).

        Args:
            expected_reply_type: The expected reply type (e.g., "create_write_channel_reply").

        Returns:
            Dict: The reply data.

        Raises:
            Exception: If the reply contains an error or times out.
        """
        # Create a queue for this reply type
        queue = asyncio.Queue(maxsize=1)
        self.channel_response_queues[expected_reply_type] = queue

        try:
            # Wait for the reply with timeout
            reply = await asyncio.wait_for(queue.get(), timeout=30.0)

            # Check for errors (matching Rust implementation)
            error_code = reply.get("error_code", 0)
            if error_code != 0:
                raise Exception(f"{expected_reply_type} failed with error code: {error_code}")

            if reply.get("err"):
                raise Exception(f"{expected_reply_type} failed: {reply['err']}")

            return reply

        except asyncio.TimeoutError:
            raise Exception(f"Timeout waiting for {expected_reply_type}")
        finally:
            # Clean up
            self.channel_response_queues.pop(expected_reply_type, None)

    async def handle_response(self, response: "Dict[str,Any]") -> None:
        """
        Dispatch a parsed CBOR response to the appropriate handler or callback.
        """
        assert response is not None

        if response.get("connection_status_event") is not None:
            self.logger.debug("connection status event")
            self.parse_status(response["connection_status_event"])
            await self.config.handle_connection_status_event(response["connection_status_event"])
            return
        if response.get("new_pki_document_event") is not None:
            self.logger.debug("new pki doc event")
            self.parse_pki_doc(response["new_pki_document_event"])
            await self.config.handle_new_pki_document_event(response["new_pki_document_event"])
            return
        if response.get("message_sent_event") is not None:
            self.logger.debug("message sent event")
            await self.config.handle_message_sent_event(response["message_sent_event"])
            return
        if response.get("message_reply_event") is not None:
            self.logger.debug("message reply event")
            reply = response["message_reply_event"]

            # Check if this reply matches our expected message ID for old channel operations
            if hasattr(self, '_expected_message_id') and self._expected_message_id is not None:
                reply_message_id = reply.get("message_id")
                if reply_message_id is not None and reply_message_id == self._expected_message_id:
                    self.logger.debug(f"Received matching MessageReplyEvent for message_id {reply_message_id.hex()[:16]}...")
                    # Handle error in reply using error_code field
                    error_code = reply.get("error_code", 0)
                    self.logger.debug(f"MessageReplyEvent: error_code={error_code}")
                    if error_code != 0:
                        error_msg = thin_client_error_to_string(error_code)
                        self.logger.debug(f"Reply contains error: {error_msg} (error code {error_code})")
                        self._received_reply_payload = None
                    else:
                        payload = reply.get("payload")
                        if payload is None:
                            self._received_reply_payload = b""
                        else:
                            self._received_reply_payload = payload
                        self.logger.debug(f"Reply contains {len(self._received_reply_payload)} bytes of payload")

                    # Signal that we received the matching reply
                    if hasattr(self, '_reply_received_for_message_id'):
                        self._reply_received_for_message_id.set()
                    return
                else:
                    if reply_message_id is not None:
                        self.logger.debug(f"Received MessageReplyEvent with mismatched message_id (expected {self._expected_message_id.hex()[:16]}..., got {reply_message_id.hex()[:16]}...), ignoring")
                    else:
                        self.logger.debug("Received MessageReplyEvent with nil message_id, ignoring")

            # Fall back to original behavior for non-channel operations
            self.reply_received_event.set()
            await self.config.handle_message_reply_event(reply)
            return
        # Handle channel query events (for send_channel_query_await_reply), this is the ACK from the local clientd (not courier)
        if response.get("channel_query_sent_event") is not None:
            # channel_query_sent_event': {'message_id': b'\xb7\xd5\xaeG\x8a\xc4\x96\x99|M\x89c\x90\xc3\xd4\x1f', 'sent_at': 1758485828, 'reply_eta': 1179000000, 'error_code': 0},
            self.logger.debug("channel_query_sent_event")
            event = response["channel_query_sent_event"]
            message_id = event.get("message_id")
            if message_id is not None:
                # Check for error in sent event
                error_code = event.get("error_code", 0)
                if error_code != 0:
                    # Store error for the waiting coroutine
                    if message_id in self.pending_channel_message_queries:
                        self.channel_message_query_responses[message_id] = f"Channel query send failed with error code: {error_code}".encode()
                        self.pending_channel_message_queries[message_id].set()
                # Continue waiting for the reply (don't return here)
            return

        # Handle old channel API replies
        if response.get("create_write_channel_reply") is not None:
            self.logger.debug("channel create_write_channel_reply event")
            self.channel_reply_data = response
            self.channel_reply_event.set()
            return

        if response.get("create_read_channel_reply") is not None:
            self.logger.debug("channel create_read_channel_reply event")
            self.channel_reply_data = response
            self.channel_reply_event.set()
            return

        if response.get("write_channel_reply") is not None:
            self.logger.debug("channel write_channel_reply event")
            self.channel_reply_data = response
            self.channel_reply_event.set()
            return

        if response.get("read_channel_reply") is not None:
            self.logger.debug("channel read_channel_reply event")
            self.channel_reply_data = response
            self.channel_reply_event.set()
            return

        if response.get("copy_channel_reply") is not None:
            self.logger.debug("channel copy_channel_reply event")
            self.channel_reply_data = response
            self.channel_reply_event.set()
            return

        # Handle newer channel query reply events
        if query_ack := response.get("channel_query_reply_event", None):
            # this is the ACK from the courier
            self.logger.debug("channel_query_reply_event")
            event = response["channel_query_reply_event"]
            message_id = event.get("message_id")

            if message_id is None:
                self.logger.error("channel_query_reply_event without message_id")
                return

            # TODO wait why are we storing these indefinitely if we don't really care about them??
            if error_code := event.get("error_code", 0):
                error_msg = f"Channel query failed with error code: {error_code}".encode()
                self.channel_message_query_responses[message_id] = error_msg
            else:
                # Extract the payload
                payload = event.get("payload", b"")
                self.channel_message_query_responses[message_id] = payload

            if (queue := self.ack_queues.get(message_id, None)):
                self.logger.debug(f"ack_queues: populated with message_id {message_id.hex()}")
                asyncio.create_task(queue.put(query_ack))
            else:
                self.logger.error(f"channel_query_reply_event for message_id {message_id.hex()}, but there is no listener")


            # Signal the waiting coroutine
            if message_id in self.pending_channel_message_queries:
                self.pending_channel_message_queries[message_id].set()
            return

        for reply_type, reply in response.items():
            if not reply:
                continue
            self.logger.debug(f"channel {reply_type} event")
            if not reply_type.endswith("_reply") or not (query_id := reply.get("query_id", None)):
                self.logger.debug(f"{reply_type} is not a reply, or can't get query_id")
                #  'create_read_channel_reply': {'query_id': None, 'channel_id': 0, 'error_code': 21},
                # DEBUG [thinclient] channel_query_reply_event is not a reply, or can't get query_id
                # REPLY {'message_id': b'\xfd\xc0\x9d\xcfh\xa3\x88X[\xab\xa8\xd3\x1b\x8b\x15\xd1', 'payload': b'', 'reply_index': None, 'error_code': 0}
                # SELF.RESPONSE_QUEUES {}
                print("REPLY", reply)
                print('SELF.RESPONSE_QUEUES', self.response_queues)
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

    async def send_channel_query(self, channel_id:int, payload:bytes, dest_node:bytes, dest_queue:bytes, message_id:"bytes|None"=None):
        """
        Send a channel query (prepared by write_channel or read_channel) to the mixnet.
        This method sets the ChannelID inside the Request for proper channel handling.
        This method requires mixnet connectivity.

        Args:
            channel_id (int): The 16-bit channel ID.
            payload (bytes): Channel query payload prepared by write_channel or read_channel.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.
            message_id (bytes, optional): Message ID for reply correlation. If None, generates a new one.

        Returns:
            bytes: The message ID used for this query (either provided or generated).

        Raises:
            RuntimeError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise RuntimeError("cannot send channel query in offline mode - daemon not connected to mixnet")

        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes

        # Generate message ID if not provided, and SURB ID
        if message_id is None:
            message_id = self.new_message_id()
            self.logger.debug(f"send_channel_query: Generated message_id {message_id.hex()[:16]}...")
        else:
            self.logger.debug(f"send_channel_query: Using provided message_id {message_id.hex()[:16]}...")

        surb_id = self.new_surb_id()

        # Create the SendMessage structure with ChannelID

        send_message = {
            "channel_id": channel_id,  # This is the key difference from send_message
            "id": message_id,  # Use generated message_id for reply correlation
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
            self.logger.info(f"Channel query sent successfully for channel {channel_id}.")
            return message_id
        except Exception as e:
            self.logger.error(f"Error sending channel query: {e}")
            raise

    async def send_reliable_message(self, message_id:bytes, payload:bytes|str, dest_node:bytes, dest_queue:bytes) -> None:
        """
        Send a reliable message using an ARQ mechanism and message ID.
        This method requires mixnet connectivity.

        Args:
            message_id (bytes): Message ID for reply correlation.
            payload (bytes or str): Message payload.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.

        Raises:
            ThinClientOfflineError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send reliable message in offline mode - daemon not connected to mixnet")

        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes

        # Create the SendARQMessage structure
        send_arq_message = {
            "id": message_id,
            "with_surb": True,
            "surbid": None,  # ARQ messages don't use SURB IDs directly
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
            "payload": payload,
        }

        # Wrap in the new Request structure
        request = {
            "send_arq_message": send_arq_message
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

    async def await_message_reply(self) -> None:
        """
        Asynchronously block until a reply is received from the daemon.
        """
        await self.reply_received_event.wait()

    # Channel API methods

    async def create_write_channel(self, write_cap: "bytes|None "=None, message_box_index: "bytes|None"=None) -> "Tuple[bytes,bytes,bytes,bytes]":
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

    async def create_read_channel(self, read_cap:bytes, message_box_index: "bytes|None"=None) -> "Tuple[bytes,bytes]":
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

    async def write_channel(self, channel_id: bytes, payload: "bytes|str") -> "Tuple[bytes,bytes]":
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

    async def read_channel(self, channel_id:int, message_id:"bytes|None"=None, reply_index:"int|None"=None) -> "Tuple[bytes,bytes,int|None]":
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

    # New Pigeonhole API methods

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

    async def encrypt_read(self, read_cap: bytes, message_box_index: bytes) -> "Tuple[bytes, bytes, bytes, bytes, int]":
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
    ) -> None:
        """
        Tombstone a single pigeonhole box by overwriting it with zeros.

        This method overwrites the specified box with a zero-filled payload,
        effectively deleting its contents. The tombstone is sent via ARQ
        for reliable delivery.

        Args:
            geometry: Pigeonhole geometry defining payload size.
            write_cap: Write capability for the box.
            box_index: Index of the box to tombstone.

        Raises:
            ValueError: If any argument is None or geometry is invalid.
            Exception: If the encrypt or send operation fails.

        Example:
            >>> geometry = PigeonholeGeometry(max_plaintext_payload_length=1024, nike_name="x25519")
            >>> await client.tombstone_box(geometry, write_cap, box_index)
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

        # Send the tombstone via ARQ
        await self.start_resending_encrypted_message(
            None,  # read_cap
            write_cap,
            None,  # next_message_index
            None,  # reply_index
            envelope_descriptor,
            message_ciphertext,
            envelope_hash
        )

    async def tombstone_range(
        self,
        geometry: "PigeonholeGeometry",
        write_cap: bytes,
        start: bytes,
        max_count: int
    ) -> "Dict[str, Any]":
        """
        Tombstone a range of pigeonhole boxes starting from a given index.

        This method tombstones up to max_count boxes, starting from the
        specified box index and advancing through consecutive indices.

        If an error occurs during the operation, a partial result is returned
        containing the number of boxes successfully tombstoned and the next
        index that was being processed.

        Args:
            geometry: Pigeonhole geometry defining payload size.
            write_cap: Write capability for the boxes.
            start: Starting MessageBoxIndex.
            max_count: Maximum number of boxes to tombstone.

        Returns:
            Dict[str, Any]: A dictionary with:
                - "tombstoned" (int): Number of boxes successfully tombstoned.
                - "next" (bytes): The next MessageBoxIndex after the last processed.

        Raises:
            ValueError: If geometry, write_cap, or start is None, or if geometry is invalid.

        Example:
            >>> geometry = PigeonholeGeometry(max_plaintext_payload_length=1024, nike_name="x25519")
            >>> result = await client.tombstone_range(geometry, write_cap, start_index, 10)
            >>> print(f"Tombstoned {result['tombstoned']} boxes")
        """
        if geometry is None:
            raise ValueError("geometry cannot be None")
        geometry.validate()
        if write_cap is None:
            raise ValueError("write_cap cannot be None")
        if start is None:
            raise ValueError("start index cannot be None")
        if max_count == 0:
            return {"tombstoned": 0, "next": start}

        cur = start
        done = 0

        while done < max_count:
            try:
                await self.tombstone_box(geometry, write_cap, cur)
            except Exception as e:
                self.logger.error(f"Error tombstoning box at index {done}: {e}")
                return {"tombstoned": done, "next": cur, "error": str(e)}

            done += 1

            try:
                cur = await self.next_message_box_index(cur)
            except Exception as e:
                self.logger.error(f"Error getting next index after tombstoning: {e}")
                return {"tombstoned": done, "next": cur, "error": str(e)}

        return {"tombstoned": done, "next": cur}
