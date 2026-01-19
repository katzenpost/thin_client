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
                    - 'reply_index' (int, optional): Index of reply used
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

        # 2nd message is always a new pki doc event (payload may be empty if mixnet is still booting)
        response = await self.recv(loop)
        if response is not None and response.get("new_pki_document_event") is not None:
            await self.handle_response(response)
        else:
            self.logger.info("No PKI document event received during startup - will receive when available")

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
            self.logger.info("Daemon is not connected to mixnet - entering offline mode")

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

        Handles the case where the daemon may not have a PKI document yet
        (e.g., during initial connection before the network is fully available).
        """
        self.logger.debug("parse pki doc")
        assert event is not None
        payload = event.get("payload")
        # Handle empty payload - daemon may not have a PKI document yet
        if payload is None or len(payload) == 0:
            self.logger.info("No PKI document available yet - will receive when available")
            return
        raw_pki_doc = cbor2.loads(payload)
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

    async def create_write_channel(self) -> "Tuple[int, bytes, bytes]":
        """
        Creates a new Pigeonhole write channel for sending messages.

        Returns:
            tuple: (channel_id, read_cap, write_cap) where:
                - channel_id is the 16-bit channel ID
                - read_cap is the read capability for sharing
                - write_cap is the write capability for persistence

        Raises:
            Exception: If the channel creation fails.
        """
        query_id = self.new_query_id()

        request = {
            "create_write_channel": {
                "query_id": query_id
            }
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error creating write channel: {e}")
            raise e

        channel_id = reply["channel_id"]
        read_cap = reply["read_cap"]
        write_cap = reply["write_cap"]

        return channel_id, read_cap, write_cap

    async def create_read_channel(self, read_cap: bytes) -> int:
        """
        Creates a read channel from a read capability.

        Args:
            read_cap: The read capability bytes.

        Returns:
            int: The channel ID.

        Raises:
            Exception: If the read channel creation fails.
        """
        query_id = self.new_query_id()

        request = {
            "create_read_channel": {
                "query_id": query_id,
                "read_cap": read_cap
            }
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error creating read channel: {e}")
            raise

        # client2/thin/thin_messages.go:  ThinClientCapabilityAlreadyInUse uint8 = 21

        channel_id = reply["channel_id"]
        return channel_id

    async def write_channel(self, channel_id: int, payload: "bytes|str") -> WriteChannelReply:
        """
        Prepares a message for writing to a Pigeonhole channel.

        Args:
            channel_id: The 16-bit channel ID.
            payload: The data to write to the channel.

        Returns:
            WriteChannelReply: Reply containing send_message_payload and other metadata.
            // ThinClientErrorInternalError indicates an internal error occurred within
            // the client daemon or thin client that prevented operation completion.
            ThinClientErrorInternalError uint8 = 4


        Raises:
            Exception: If the write preparation fails.
        """
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')

        query_id = self.new_query_id()

        request = {
            "write_channel": {
                "channel_id": channel_id,
                "query_id": query_id,
                "payload": payload
            }
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error preparing write to channel: {e}")
            raise

        if reply['error_code'] != 0:
            # Examples:
            # 12:24:32.206 ERRO katzenpost/client2: writeChannel failure: failed to create write request: pki: replica not found
            # - This one will probably never succeed? Why is the client using a bad replica?
            #
            raise Exception(f"write_channel got error from clientd: {reply['error_code']}")

        return WriteChannelReply(
            send_message_payload=reply["send_message_payload"],
            current_message_index=reply["current_message_index"],
            next_message_index=reply["next_message_index"],
            envelope_descriptor=reply["envelope_descriptor"],
            envelope_hash=reply["envelope_hash"]
        )


    async def read_channel(self, channel_id: int, message_box_index: "bytes|None" = None,
                          reply_index: "int|None" = None) -> ReadChannelReply:
        """
        Prepares a read query for a Pigeonhole channel.

        Args:
            channel_id: The 16-bit channel ID.
            message_box_index: Optional message box index for resuming from a specific position.
            reply_index: Optional index of the reply to return.

        Returns:
            ReadChannelReply: Reply containing send_message_payload and other metadata.

        Raises:
            Exception: If the read preparation fails.
        """
        query_id = self.new_query_id()

        request_data = {
            "channel_id": channel_id,
            "query_id": query_id
        }

        if message_box_index is not None:
            request_data["message_box_index"] = message_box_index

        if reply_index is not None:
            request_data["reply_index"] = reply_index

        request = {
            "read_channel": request_data
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error preparing read from channel: {e}")
            raise

        return ReadChannelReply(
            send_message_payload=reply["send_message_payload"],
            current_message_index=reply["current_message_index"],
            next_message_index=reply["next_message_index"],
            reply_index=reply.get("reply_index"),
            envelope_descriptor=reply["envelope_descriptor"],
            envelope_hash=reply["envelope_hash"]
        )


    async def resume_write_channel(self, write_cap: bytes, message_box_index: "bytes|None" = None) -> int:
        """
        Resumes a write channel from a previous session.

        Args:
            write_cap: The write capability bytes.
            message_box_index: Optional message box index for resuming from a specific position.

        Returns:
            int: The channel ID.

        Raises:
            Exception: If the channel resumption fails.
        """
        query_id = self.new_query_id()

        request_data = {
            "query_id": query_id,
            "write_cap": write_cap
        }

        if message_box_index is not None:
            request_data["message_box_index"] = message_box_index

        request = {
            "resume_write_channel": request_data
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error resuming write channel: {e}")
            raise
        return reply["channel_id"]


    async def resume_read_channel(self, read_cap: bytes, next_message_index: "bytes|None" = None,
                                 reply_index: "int|None" = None) -> int:
        """
        Resumes a read channel from a previous session.

        Args:
            read_cap: The read capability bytes.
            next_message_index: Optional next message index for resuming from a specific position.
            reply_index: Optional reply index.

        Returns:
            int: The channel ID.

        Raises:
            Exception: If the channel resumption fails.
        """
        query_id = self.new_query_id()

        request_data = {
            "query_id": query_id,
            "read_cap": read_cap
        }

        if next_message_index is not None:
            request_data["next_message_index"] = next_message_index

        if reply_index is not None:
            request_data["reply_index"] = reply_index

        request = {
            "resume_read_channel": request_data
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error resuming read channel: {e}")
            raise
        if not reply["channel_id"]:
            self.logger.error(f"Error resuming read channel: no channel_id")
            raise Exception("TODO resume_read_channel error", reply)
        return reply["channel_id"]


    async def resume_write_channel_query(self, write_cap: bytes, message_box_index: bytes,
                                       envelope_descriptor: bytes, envelope_hash: bytes) -> int:
        """
        Resumes a write channel with a specific query state.
        This method provides more granular resumption control than resume_write_channel
        by allowing the application to resume from a specific query state, including
        the envelope descriptor and hash. This is useful when resuming from a partially
        completed write operation that was interrupted during transmission.

        Args:
            write_cap: The write capability bytes.
            message_box_index: Message box index for resuming from a specific position (WriteChannelReply.current_message_index).
            envelope_descriptor: Envelope descriptor from previous query (WriteChannelReply.envelope_descriptor).
            envelope_hash: Envelope hash from previous query (WriteChannelReply.envelope_hash).

        Returns:
            int: The channel ID.

        Raises:
            Exception: If the channel resumption fails.
        """
        query_id = self.new_query_id()

        request = {
            "resume_write_channel_query": {
                "query_id": query_id,
                "write_cap": write_cap,
                "message_box_index": message_box_index,
                "envelope_descriptor": envelope_descriptor,
                "envelope_hash": envelope_hash
            }
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error resuming write channel query: {e}")
            raise
        return reply["channel_id"]


    async def resume_read_channel_query(self, read_cap: bytes, next_message_index: bytes,
                                      reply_index: "int|None", envelope_descriptor: bytes,
                                      envelope_hash: bytes) -> int:
        """
        Resumes a read channel with a specific query state.
        This method provides more granular resumption control than resume_read_channel
        by allowing the application to resume from a specific query state, including
        the envelope descriptor and hash. This is useful when resuming from a partially
        completed read operation that was interrupted during transmission.

        Args:
            read_cap: The read capability bytes.
            next_message_index: Next message index for resuming from a specific position.
            reply_index: Optional reply index.
            envelope_descriptor: Envelope descriptor from previous query.
            envelope_hash: Envelope hash from previous query.

        Returns:
            int: The channel ID.

        Raises:
            Exception: If the channel resumption fails.
        """
        query_id = self.new_query_id()

        request_data = {
            "query_id": query_id,
            "read_cap": read_cap,
            "next_message_index": next_message_index,
            "envelope_descriptor": envelope_descriptor,
            "envelope_hash": envelope_hash
        }

        if reply_index is not None:
            request_data["reply_index"] = reply_index

        request = {
            "resume_read_channel_query": request_data
        }

        try:
            reply = await self._send_and_wait(query_id=query_id, request=request)
        except Exception as e:
            self.logger.error(f"Error resuming read channel query: {e}")
            raise
        return reply["channel_id"]


    async def get_courier_destination(self) -> "Tuple[bytes, bytes]":
        """
        Gets the courier service destination for channel queries.
        This is a convenience method that combines get_service("courier")
        and to_destination() to get the destination node and queue for
        use with send_channel_query and send_channel_query_await_reply.

        Returns:
            tuple: (dest_node, dest_queue) where:
                - dest_node is the destination node identity hash
                - dest_queue is the destination recipient queue ID

        Raises:
            Exception: If the courier service is not found.
        """
        courier_service = self.get_service("courier")
        dest_node, dest_queue = courier_service.to_destination()
        return dest_node, dest_queue

    async def send_channel_query_await_reply(self, channel_id: int, payload: bytes,
                                             dest_node: bytes, dest_queue: bytes,
                                             message_id: bytes, timeout_seconds=30.0) -> bytes:
        """
        Sends a channel query and waits for the reply.
        This combines send_channel_query with event handling to wait for the response.

        Args:
            channel_id: The 16-bit channel ID.
            payload: The prepared query payload.
            dest_node: Destination node identity hash.
            dest_queue: Destination recipient queue ID.
            message_id: Message ID for reply correlation.
            timeout_seconds: float (seconds to wait), None for indefinite wait

        Returns:
            bytes: The received payload from the channel.

        Raises:
            ThinClientOfflineError: If in offline mode (daemon not connected to mixnet).
            Exception: If the query fails or times out.
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send_channel_query_await_reply in offline mode - daemon not connected to mixnet")

        # Create an event for this message_id
        if message_id not in self.pending_channel_message_queries:
            event = asyncio.Event()
            self.pending_channel_message_queries[message_id] = event

        try:
            # Send the channel query
            await self.send_channel_query(channel_id, payload=payload, dest_node=dest_node, dest_queue=dest_queue, message_id=message_id)

            # Wait for the reply with timeout
            await asyncio.wait_for(event.wait(), timeout=timeout_seconds)

            # Get the response payload
            if message_id not in self.channel_message_query_responses:
                raise Exception("No channel query reply received within timeout_seconds")

            response_payload = self.channel_message_query_responses[message_id]

            # Check if it's an error message
            if isinstance(response_payload, bytes) and response_payload.startswith(b"Channel query"):
                raise Exception(response_payload.decode())

            return response_payload

        except asyncio.TimeoutError:
            raise Exception("Timeout waiting for channel query reply")
        finally:
            # Clean up
            self.pending_channel_message_queries.pop(message_id, None)
            self.channel_message_query_responses.pop(message_id, None)

    async def send_channel_query(self, channel_id: int, *, payload: bytes, dest_node: bytes,
                               dest_queue: bytes, message_id: bytes) -> None:
        """
        Sends a prepared channel query to the mixnet without waiting for a reply.

        Args:
            channel_id: The 16-bit channel ID.
            payload: Channel query payload prepared by write_channel or read_channel.
            dest_node: Destination node identity hash.
            dest_queue: Destination recipient queue ID.
            message_id: Message ID for reply correlation.

        Raises:
            ThinClientOfflineError: If in offline mode (daemon not connected to mixnet).
        """
        # Check if we're in offline mode
        if not self._is_connected:
            raise ThinClientOfflineError("cannot send_channel_query while not is_connected() - daemon not connected to mixnet")

        if not isinstance(payload, bytes):
            self.logger.error("send_channel_query: type error: payload= must be bytes()")
            payload = payload.encode('utf-8')

        # Create the SendChannelQuery structure (matches Rust implementation)
        send_channel_query = {
            "message_id": message_id,
            "channel_id": channel_id,
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
            "payload": payload,
        }

        # Wrap in the Request structure
        request = {
            "send_channel_query": send_channel_query
        }

        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request

        try:
            await self._send_all(length_prefixed_request)
            self.logger.info(f"Channel query sent successfully for channel {channel_id}.")
        except Exception as e:
            self.logger.error(f"Error sending channel query: {e}")
            raise

    async def close_channel(self, channel_id: int) -> None:
        """
        Closes a pigeonhole channel and cleans up its resources.
        This helps avoid running out of channel IDs by properly releasing them.
        This operation is infallible - it sends the close request and returns immediately.

        Args:
            channel_id: The 16-bit channel ID to close.

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
        except Exception as e:
            self.logger.error(f"Error sending close channel request: {e}")
            raise
        self.logger.info(f"CloseChannel request sent for channel {channel_id}.")
