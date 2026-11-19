# SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Unit tests for session resumption in the Python thin client.
These tests use mock sockets and do not require a running daemon.
"""

import asyncio
import os
import pytest
from unittest.mock import MagicMock

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


def make_client():
    """Create a ThinClient through the real __init__ with a mock socket."""
    cfg = make_config()
    cfg.dial = MagicMock()
    cfg.dial.resolve.return_value.setup_socket.return_value = (MagicMock(), "addr")
    return ThinClient(cfg)


def test_instance_token_is_fresh_per_client():
    a, b = make_client(), make_client()
    assert len(a.instance_token) == 16
    assert a.instance_token != b.instance_token


def test_disconnect_does_not_send_thin_close():
    client = make_client()
    client.task = MagicMock()
    client.disconnect()
    client.socket.sendall.assert_not_called()
    client.socket.close.assert_called_once()
    client.task.cancel.assert_called_once()


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
