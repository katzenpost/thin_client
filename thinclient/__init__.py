# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import socket
import random
import coloredlogs
import logging
import sys
import os
import asyncio
import cbor2
import pprintpp

import hashlib

# SURB_ID_SIZE is the size in bytes for the
# Katzenpost SURB ID.
SURB_ID_SIZE = 16

# MESSAGE_ID_SIZE is the size in bytes for an ID
# which is unique to the sent message.
MESSAGE_ID_SIZE = 16

def pretty_print_obj(obj):
    pp = pprintpp.PrettyPrinter(indent=4)
    pp.pprint(obj)

    
def scrub_descriptor_keys(desc):
    assert desc['LinkKey'] is not None
    desc['LinkKey'] = "scrubbed"
    
def blake2_256_sum(data):
    return hashlib.blake2b(data, digest_size=32).digest()

class ServiceDescriptor:
    def __init__(self, recipient_queue_id, mix_descriptor):
        self.recipient_queue_id = recipient_queue_id
        self.mix_descriptor = mix_descriptor

    def to_destination(self):
        provider_id_hash = blake2_256_sum(self.mix_descriptor['IdentityKey'])
        return (provider_id_hash, self.recipient_queue_id)

def find_services(capability, doc):
    services = []
    for provider in doc['Providers']:
        print(f"PROVIDER :\n")
        scrub_descriptor_keys(provider)
        pretty_print_obj(provider)

        # XXX WTF is the python cbor2 representation of the doc so
        # fucked up as to not have the "Kaetzchen" key inside the MixDescriptor?
        #for cap, details in provider['Kaetzchen'].items():
        for cap, details in provider['omitempty'].items():
            if cap == capability:
                service_desc = ServiceDescriptor(
                    recipient_queue_id=bytes(details['endpoint'], 'utf-8'),
                    mix_descriptor=provider
                )
                services.append(service_desc)
    return services
    
class Config:
    def __init__(self, on_connection_status=None, on_new_pki_document=None,
                 on_message_sent=None, on_message_reply=None):
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
        self.config = config
        self.reply_received_event = asyncio.Event()
        self.logger = logging.getLogger('thinclient')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(handler)

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        random_bytes = [random.randint(0, 255) for _ in range(16)]
        hex_string = ''.join(format(byte, '02x') for byte in random_bytes)
        abstract_name = f"katzenpost_python_thin_client_{hex_string}"
        abstract_address = f"\0{abstract_name}"
        self.socket.bind(abstract_address)
        self.socket.setblocking(False)

    async def start(self, loop):
        self.logger.debug("connecting to daemon")
        # Abstract names in Unix domain sockets start with a null byte ('\0').
        daemon_address = "katzenpost"
        server_addr = '\0' + daemon_address
        await loop.sock_connect(self.socket, server_addr)

        response = await self.recv(loop)
        assert response is not None
        assert response["ConnectionStatusEvent"] is not None
        self.parse_status(response["ConnectionStatusEvent"])
        self.handle_response(response)

        response = await self.recv(loop)
        assert response is not None
        assert response["NewPKIDocumentEvent"] is not None
        self.parse_pki_doc(response["NewPKIDocumentEvent"])
        self.handle_response(response)
        
        # Start the read loop as a background task
        self.logger.debug("starting read loop")
        self.task = loop.create_task(self.worker_loop(loop))

    def get_config(self):
        return self.config
        
    def stop(self):
        self.logger.debug("closing connection to daemon")
        self.socket.close()
        self.task.cancel()

    async def recv(self, loop):
        raw_data = await loop.sock_recv(self.socket, (10*1024))
        response = cbor2.loads(raw_data)
        self.logger.debug(f"received daemon response")
        return response

    async def worker_loop(self, loop):
        self.logger.debug("read loop start")
        while True:
            self.logger.debug("read loop")
            try:
                self.logger.debug("BEFORE recv")
                response = await self.recv(loop)
                self.logger.debug("AFTER recv")

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
        assert event["IsConnected"] == True
        self.logger.debug("parse status success")

    def pki_document(self):
        return self.pki_doc
        
    def parse_pki_doc(self, event):
        self.logger.debug("parse pki doc")
        assert event is not None        
        assert event["Payload"] is not None
        self.pki_doc = cbor2.loads(event["Payload"])
        self.pretty_print_pki_doc(self.pki_doc)
        self.logger.debug("parse pki doc success")

    def get_services(self, capability):
        doc = self.pki_document()
        descriptors = find_services(capability, doc)
        if not descriptors:
            raise "service not found in pki doc"
        return descriptors

    def get_service(self, service_name):
        service_descriptors = self.get_services(service_name)
        return random.choice(service_descriptors)

    def new_message_id(self):
        os.urandom(MESSAGE_ID_SIZE)

    def new_surb_id(self):
        os.urandom(SURB_ID_SIZE)
        
        
    def handle_response(self, response):
        assert response is not None

        if response.get("ConnectionStatusEvent") is not None:
            self.logger.debug("connection status event")
            self.config.handle_connection_status_event(response["ConnectionStatusEvent"])
            return
        if response.get("NewPKIDocumentEvent") is not None:
            self.logger.debug("new pki doc event")
            self.config.handle_new_pki_document_event(response["NewPKIDocumentEvent"])
            return
        if response.get("MessageSentEvent") is not None:
            self.logger.debug("message sent event")
            self.config.handle_message_sent_event(response["MessageSentEvent"])
            return
        if response.get("MessageReplyEvent") is not None:
            self.logger.debug("message reply event")
            self.reply_received_event.set()
            self.config.handle_message_reply_event(response["MessageReplyEvent"])
            return

    def send_message_with_reply(self, payload, dest_node, dest_queue):
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes
                
        request = {
            "Payload": payload,
            "IsSendOp": True,
            "Destination": dest_node,
            "RecipientQueueID": dest_queue,
                           }
        cbor_request = cbor2.dumps(request)

        try:
            self.socket.sendall(cbor_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def send_message(self, surb_id, payload, dest_node, dest_queue):
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')  # Encoding the string to bytes
                
        request = {
            "Payload": payload,
            "WithSURB": True,
            "SURBID": surb_id,
            "IsSendOp": True,
            "Destination": dest_node,
            "RecipientQueueID": dest_queue,
                           }
        cbor_request = cbor2.dumps(request)

        try:
            self.socket.sendall(cbor_request)
            self.logger.info("Message sent successfully.")
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")

    def pretty_print_pki_doc(self, doc):
        assert doc is not None
        assert doc['Providers'] is not None
        assert doc['Topology'] is not None

        new_doc = doc
        providers = []
        topology = []
        
        for provider_cert_blob in doc['Providers']:
            provider_cert = cbor2.loads(provider_cert_blob)
            provider_desc = cbor2.loads(provider_cert['Certified'])
            scrub_descriptor_keys(provider_desc)
            providers.append(provider_desc)

        for layer in doc['Topology']:
            for mix_desc_blob in layer:
                mix_cert = cbor2.loads(mix_desc_blob)
                mix_desc = cbor2.loads(mix_cert['Certified'])
                scrub_descriptor_keys(mix_desc)
                topology.append(mix_desc) # flatten, no prob, relax

        new_doc['Providers'] = providers
        new_doc['Topology'] = topology
        pretty_print_obj(new_doc)

    async def await_message_reply(self):
        await self.reply_received_event.wait()
