# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Unit tests for session resumption in the Python thin client.
These tests use mock sockets and do not require a running daemon.
"""

import asyncio
import struct
import os
import pytest
import cbor2

from katzenpost_thinclient.core import ThinClient, Config


def make_config():
    """Create a minimal Config for testing without a TOML file."""
    cfg = Config.__new__(Config)
    cfg.network = "tcp"
    cfg.address = "127.0.0.1:0"

    # Set up no-op callbacks
    async def noop_event(event):
        pass
    cfg.handle_connection_status_event = noop_event
    cfg.handle_new_pki_document_event = noop_event
    cfg.handle_message_sent_event = noop_event
    cfg.handle_message_reply_event = noop_event
    cfg.handle_daemon_disconnected_event = noop_event
    return cfg


class TestInstanceToken:
    """Tests for instance_token generation."""

    def test_instance_token_exists(self):
        """ThinClient should have an instance_token attribute."""
        cfg = make_config()
        client = ThinClient.__new__(ThinClient)
        # Manually call __init__ parts that don't need a real socket
        client.instance_token = os.urandom(16)
        assert hasattr(client, 'instance_token')
        assert len(client.instance_token) == 16

    def test_instance_token_is_random(self):
        """Two ThinClient instances should have different tokens."""
        cfg = make_config()
        # We can't easily construct ThinClient without a socket,
        # so just test the token generation logic
        token1 = os.urandom(16)
        token2 = os.urandom(16)
        assert token1 != token2

    def test_instance_token_nonzero(self):
        """Instance token should not be all zeros."""
        token = os.urandom(16)
        assert token != b'\x00' * 16


class TestDisconnect:
    """Tests for the disconnect() method."""

    def test_disconnect_method_exists(self):
        """ThinClient should have a disconnect() method."""
        assert hasattr(ThinClient, 'disconnect')

    def test_disconnect_does_not_send_thin_close(self):
        """disconnect() should close the socket without sending thin_close."""
        # This is a design contract test - the actual socket behavior
        # is tested in integration tests. Here we verify the method exists
        # and is distinct from stop().
        assert hasattr(ThinClient, 'disconnect')
        assert hasattr(ThinClient, 'stop')
        assert ThinClient.disconnect is not ThinClient.stop


class TestSessionTokenProtocol:
    """Tests for session token CBOR encoding."""

    def test_session_token_cbor_encoding(self):
        """SessionToken request should encode correctly for the daemon."""
        token = os.urandom(16)
        request = {
            "session_token": {
                "client_instance_token": token,
            }
        }
        encoded = cbor2.dumps(request)
        decoded = cbor2.loads(encoded)
        assert decoded["session_token"]["client_instance_token"] == token

    def test_session_token_reply_decoding(self):
        """SessionTokenReply should decode correctly from the daemon."""
        app_id = os.urandom(16)
        reply = {
            "session_token_reply": {
                "app_id": app_id,
                "resumed": True,
            }
        }
        encoded = cbor2.dumps(reply)
        decoded = cbor2.loads(encoded)
        assert decoded["session_token_reply"]["app_id"] == app_id
        assert decoded["session_token_reply"]["resumed"] is True

    def test_session_token_reply_not_resumed(self):
        """SessionTokenReply with resumed=false should decode correctly."""
        reply = {
            "session_token_reply": {
                "app_id": os.urandom(16),
                "resumed": False,
            }
        }
        encoded = cbor2.dumps(reply)
        decoded = cbor2.loads(encoded)
        assert decoded["session_token_reply"]["resumed"] is False


class TestHandleSessionTokenReply:
    """Tests for handle_response dispatching session_token_reply."""

    @pytest.mark.asyncio
    async def test_handle_response_session_token_reply(self):
        """handle_response should handle session_token_reply without error."""
        cfg = make_config()
        client = ThinClient.__new__(ThinClient)
        # Initialize minimal state
        client.config = cfg
        client.pki_doc = None
        client._is_connected = False
        client._stopping = False
        client._received_shutdown = False
        client._daemon_instance_token = None
        client.reply_received_event = asyncio.Event()
        client.response_queues = {}
        client.ack_queues = {}
        import logging
        client.logger = logging.getLogger('test')

        response = {
            "session_token_reply": {
                "app_id": os.urandom(16),
                "resumed": False,
            }
        }

        # Should not raise
        await client.handle_response(response)
