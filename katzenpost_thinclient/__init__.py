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
import os
import asyncio
import cbor2
import pprintpp
import toml
import hashlib

from typing import TYPE_CHECKING
if TYPE_CHECKING:
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
    }
    return error_messages.get(error_code, f"Unknown thin client error code: {error_code}")

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
    }
    return error_messages.get(error_code, f"Unknown thin client error code: {error_code}")

# Export public API
__all__ = [
    'ThinClient',
    'Config',
    'ServiceDescriptor',
    'find_services'
]

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
        recipient_queue_id (bytes): The identifier of the recipient's queue on the mixnet.
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
                        recipient_queue_id=bytes(details['endpoint'], 'utf-8'),
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
                    - 'err' (str, optional): Error message if reply failed, empty string if successful

                Example: ``{'message_id': b'\\x01\\x02...', 'surbid': b'\\xaa\\xbb...', 'payload': b'echo response', 'reply_index': 0, 'err': ''}``

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

    def handle_connection_status_event(self, event: asyncio.Event) -> None:
        if self.on_connection_status:
            self.on_connection_status(event)

    def handle_new_pki_document_event(self, event: asyncio.Event) -> None:
        if self.on_new_pki_document:
            self.on_new_pki_document(event)

    def handle_message_sent_event(self, event: asyncio.Event) -> None:
        if self.on_message_sent:
            self.on_message_sent(event)

    def handle_message_reply_event(self, event: asyncio.Event) -> None:
        if self.on_message_reply:
            self.on_message_reply(event)


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
        # Mutex to protect socket send operations from race conditions
        self._send_lock = asyncio.Lock()

        # For message ID-based reply matching (like Go version)
        self._expected_message_id : bytes | None = None
        self._received_reply_payload : bytes | None = None
        self._reply_received_for_message_id : asyncio.Event | None = None
        self.logger = logging.getLogger('thinclient')
        self.logger.setLevel(logging.DEBUG)
        # Only add handler if none exists to avoid duplicate log messages
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            self.logger.addHandler(handler)

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
        self.handle_response(response)

        # 2nd message is always a new pki doc event
        response = await self.recv(loop)
        assert response is not None
        assert response["new_pki_document_event"] is not None
        self.handle_response(response)
        
        # Start the read loop as a background task
        self.logger.debug("starting read loop")
        self.task = loop.create_task(self.worker_loop(loop))

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

    async def recv(self, loop:asyncio.AbstractEventLoop) -> "Dict[Any,Any]":
        """
        Receive a CBOR-encoded message from the daemon.

        Args:
            loop (asyncio.AbstractEventLoop): Event loop to use for socket reads.

        Returns:
            dict: Decoded CBOR response from the daemon.

        Raises:
            ValueError: If message framing fails.
        """
        length_prefix = await loop.sock_recv(self.socket, 4)
        if length_prefix is None:
            raise ValueError("Socket closed - received None from sock_recv")
        if len(length_prefix) < 4:
            raise ValueError("Failed to read the length prefix")
        message_length = struct.unpack('>I', length_prefix)[0]
        raw_data = await loop.sock_recv(self.socket, message_length)
        if raw_data is None:
            raise ValueError("Socket closed - received None from sock_recv while reading message body")
        if len(raw_data) < message_length:
            raise ValueError("Did not receive the full message {} != {}".format(len(raw_data), message_length))
        response = cbor2.loads(raw_data)
        self.logger.debug(f"Received daemon response")
        return response

    async def worker_loop(self, loop:asyncio.events.AbstractEventLoop) -> None:
        """
        Background task that listens for events and dispatches them.
        """
        self.logger.debug("read loop start")
        while True:
            self.logger.debug("read loop")
            try:
                response = await self.recv(loop)
                self.handle_response(response)
            except asyncio.CancelledError:
                # Handle cancellation of the read loop
                break
            except Exception as e:
                self.logger.error(f"Error reading from socket: {e}")
                break

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

    def new_message_id(self) -> bytes:
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

    def handle_response(self, response: "Dict[str,Any]") -> None:
        """
        Dispatch a parsed CBOR response to the appropriate handler or callback.
        """
        assert response is not None

        if response.get("connection_status_event") is not None:
            self.logger.debug("connection status event")
            self.parse_status(response["connection_status_event"])
            self.config.handle_connection_status_event(response["connection_status_event"])
            return
        if response.get("new_pki_document_event") is not None:
            self.logger.debug("new pki doc event")
            self.parse_pki_doc(response["new_pki_document_event"])
            self.config.handle_new_pki_document_event(response["new_pki_document_event"])
            return
        if response.get("message_sent_event") is not None:
            self.logger.debug("message sent event")
            self.config.handle_message_sent_event(response["message_sent_event"])
            return
        if response.get("message_reply_event") is not None:
            self.logger.debug("message reply event")
            reply = response["message_reply_event"]

            # Check if this reply matches our expected message ID for channel operations
            if hasattr(self, '_expected_message_id') and self._expected_message_id is not None:
                reply_message_id = reply.get("message_id")
                if reply_message_id is not None and reply_message_id == self._expected_message_id:
                    self.logger.debug(f"Received matching MessageReplyEvent for message_id {reply_message_id.hex()[:16]}...")
                    # Handle error in reply
                    if reply.get("err"):
                        self.logger.debug(f"Reply contains error: {reply['err']}")
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
            self.config.handle_message_reply_event(reply)
            return

        # Handle channel API replies
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



    async def send_message_without_reply(self, payload:bytes|str, dest_node:bytes, dest_queue:bytes) -> None:
        """
        Send a fire-and-forget message with no SURB or reply handling.
        This method requires mixnet connectivity.

        Args:
            payload (bytes or str): Message payload.
            dest_node (bytes): Destination node identity hash.
            dest_queue (bytes): Destination recipient queue ID.

        Raises:
            RuntimeError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise RuntimeError("cannot send message in offline mode - daemon not connected to mixnet")

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
            RuntimeError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise RuntimeError("cannot send message in offline mode - daemon not connected to mixnet")

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
            RuntimeError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise RuntimeError("cannot send reliable message in offline mode - daemon not connected to mixnet")

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

                # Add a small delay between retries to allow for message propagation
                await asyncio.sleep(2.0)

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

