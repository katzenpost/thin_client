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

def on_message_reply(event):
    print("Got reply:", event)

async def main():
    cfg = Config("./thinclient.toml", on_message_reply=on_message_reply)
    client = ThinClient(cfg)
    loop = asyncio.get_running_loop()
    await client.start(loop)

    service = client.get_service("echo")
    surb_id = client.new_surb_id()
    client.send_message(surb_id, "hello mixnet", *service.to_destination())

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

# SURB_ID_SIZE is the size in bytes for the
# Katzenpost SURB ID.
SURB_ID_SIZE = 16

# MESSAGE_ID_SIZE is the size in bytes for an ID
# which is unique to the sent message.
MESSAGE_ID_SIZE = 16


class Geometry:
    """Geometry represents the Sphinx Geometry and is used by the
    `ConfigFile` type to load our TOML config file."""
    def __init__(self, **kwargs):
        self.PacketLength = kwargs.get('PacketLength')
        self.NrHops = kwargs.get('NrHops')
        self.HeaderLength = kwargs.get('HeaderLength')
        self.RoutingInfoLength = kwargs.get('RoutingInfoLength')
        self.PerHopRoutingInfoLength = kwargs.get('PerHopRoutingInfoLength')
        self.SURBLength = kwargs.get('SURBLength')
        self.SphinxPlaintextHeaderLength = kwargs.get('SphinxPlaintextHeaderLength')
        self.PayloadTagLength = kwargs.get('PayloadTagLength')
        self.ForwardPayloadLength = kwargs.get('ForwardPayloadLength')
        self.UserForwardPayloadLength = kwargs.get('UserForwardPayloadLength')
        self.NextNodeHopLength = kwargs.get('NextNodeHopLength')
        self.SPRPKeyMaterialLength = kwargs.get('SPRPKeyMaterialLength')
        self.NIKEName = kwargs.get('NIKEName', "")
        self.KEMName = kwargs.get('KEMName', "")

    def __str__(self):
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
    def __init__(self, network, address, geometry):
        self.network = network
        self.address = address
        self.geometry = geometry

    @classmethod
    def load(cls, toml_path):
        with open(toml_path, 'r') as f:
            data = toml.load(f)
        network = data.get('Network')
        address = data.get('Address')
        geometry_data = data.get('Geometry', {})
        geometry = Geometry(**geometry_data)
        return cls(network, address, geometry)

    def __str__(self):
        return (
            f"Network: {self.network}\n"
            f"Address: {self.address}\n"
            f"Geometry:\n{self.geometry}"
        )


def pretty_print_obj(obj):
    pp = pprintpp.PrettyPrinter(indent=4)
    pp.pprint(obj)

def blake2_256_sum(data):
    return hashlib.blake2b(data, digest_size=32).digest()

class ServiceDescriptor:
    """ServiceDescriptor describes a mixnet service that you can interact with."""
    def __init__(self, recipient_queue_id, mix_descriptor):
        self.recipient_queue_id = recipient_queue_id
        self.mix_descriptor = mix_descriptor

    def to_destination(self):
        provider_id_hash = blake2_256_sum(self.mix_descriptor['IdentityKey'])
        return (provider_id_hash, self.recipient_queue_id)

def find_services(capability, doc):
    services = []
    for node in doc['ServiceNodes']:
        mynode = cbor2.loads(node)

        # XXX WTF is the python cbor2 representation of the doc so
        # fucked up as to not have the "Kaetzchen" key inside the MixDescriptor?
        #for cap, details in provider['Kaetzchen'].items():
        for cap, details in mynode['omitempty'].items():
            if cap == capability:
                service_desc = ServiceDescriptor(
                    recipient_queue_id=bytes(details['endpoint'], 'utf-8'),
                    mix_descriptor=mynode
                )
                services.append(service_desc)
    return services


class Config:
    """
    Config is the configuration object for the ThinClient.
    """
    def __init__(self, filepath,
                 on_connection_status=None,
                 on_new_pki_document=None,
                 on_message_sent=None,
                 on_message_reply=None):

        cfgfile = ConfigFile.load(filepath)

        self.network = cfgfile.network
        self.address = cfgfile.address
        self.geometry = cfgfile.geometry

        self.on_connection_status = on_connection_status
        self.on_new_pki_document = on_new_pki_document
        self.on_message_sent = on_message_sent
        self.on_message_reply = on_message_reply

    def handle_connection_status_event(self, event):
        if self.on_connection_status:
            self.on_connection_status(event)

    def handle_new_pki_document_event(self, event):
        if self.on_new_pki_document:
            self.on_new_pki_document(event)

    def handle_message_sent_event(self, event):
        if self.on_message_sent:
            self.on_message_sent(event)

    def handle_message_reply_event(self, event):
        if self.on_message_reply:
            self.on_message_reply(event)


class ThinClient:
    """
    Katzenpost thin client knows how to communicate with the Katzenpost client2 daemon
    via the abstract unix domain socket.
    """

    def __init__(self, config):
        self.pki_doc = None
        self.config = config
        self.reply_received_event = asyncio.Event()
        self.logger = logging.getLogger('thinclient')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stderr)
        self.logger.addHandler(handler)

        if self.config.network is None:
            raise RuntimeError("config.network is None")

        network = self.config.network.lower()

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


    async def start(self, loop):
        """start the thing client, connect to the client daemon,
        start our async event processing."""
        
        self.logger.debug("connecting to daemon")

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

    def get_config(self):
        return self.config
        
    def stop(self):
        """stop the thin client"""
        self.logger.debug("closing connection to daemon")
        self.socket.close()
        self.task.cancel()

    async def recv(self, loop):
        length_prefix = await loop.sock_recv(self.socket, 4)
        if len(length_prefix) < 4:
            raise ValueError("Failed to read the length prefix")
        message_length = struct.unpack('>I', length_prefix)[0]
        raw_data = await loop.sock_recv(self.socket, message_length)
        if len(raw_data) < message_length:
            raise ValueError("Did not receive the full message {} != {}".format(len(raw_data), message_length))
        response = cbor2.loads(raw_data)
        self.logger.debug(f"Received daemon response")
        return response

    async def worker_loop(self, loop):
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

    def parse_status(self, event):
        self.logger.debug("parse status")
        assert event is not None
        assert event["is_connected"] == True
        self.logger.debug("parse status success")

    def pki_document(self):
        """return our latest copy of the PKI document"""
        return self.pki_doc
        
    def parse_pki_doc(self, event):
        self.logger.debug("parse pki doc")
        assert event is not None        
        assert event["payload"] is not None
        raw_pki_doc = cbor2.loads(event["payload"])
        self.pki_doc = raw_pki_doc
        self.logger.debug("parse pki doc success")

    def get_services(self, capability):
        """return a list of services with the given capability string"""
        doc = self.pki_document()
        if doc == None:
            raise Exception("pki doc is nil")
        descriptors = find_services(capability, doc)
        if not descriptors:
            raise Exception("service not found in pki doc")
        return descriptors

    def get_service(self, service_name):
        """given a service name, return a service descriptor if one exists.
        if more than one service with that name exists then pick one at random."""
        service_descriptors = self.get_services(service_name)
        return random.choice(service_descriptors)

    def new_message_id(self):
        """generate a new message ID"""
        return os.urandom(MESSAGE_ID_SIZE)

    def new_surb_id(self):
        """generate a new SURB ID"""
        return os.urandom(SURB_ID_SIZE)

    def handle_response(self, response):
        assert response is not None

        if response.get("connection status event") is not None:
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
            self.reply_received_event.set()
            reply = response["message_reply_event"]
            self.config.handle_message_reply_event(reply)
            return

    def send_message_without_reply(self, payload, dest_node, dest_queue):
        """Send a message without expecting a reply (no SURB)."""
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes
        request = {
            "with_surb": False,
            "is_send_op": True,
            "payload": payload,
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
        }
        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        try:
            self.socket.sendall(length_prefixed_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def send_message(self, surb_id, payload, dest_node, dest_queue):
        """Send a message with a SURB to allow replies from the recipient."""
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes
        request = {
            "with_surb": True,
            "surbid": surb_id,
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
            "payload": payload,
            "is_send_op": True,
        }
        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        try:
            self.socket.sendall(length_prefixed_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def send_reliable_message(self, message_id, payload, dest_node, dest_queue):
        """Send a reliable ARQ message using a message ID to match the reply."""
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes
        request = {
            "id" :message_id,
            "with_surb": True,
            "is_arq_send_op": True,
            "payload": payload,
            "destination_id_hash": dest_node,
            "recipient_queue_id": dest_queue,
        }
        cbor_request = cbor2.dumps(request)
        length_prefix = struct.pack('>I', len(cbor_request))
        length_prefixed_request = length_prefix + cbor_request
        try:
            self.socket.sendall(length_prefixed_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def pretty_print_pki_doc(self, doc):
        """Pretty-print a parsed PKI document including nodes and topology."""
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

    async def await_message_reply(self):
        """Wait asynchronously until a message reply is received."""
        await self.reply_received_event.wait()
