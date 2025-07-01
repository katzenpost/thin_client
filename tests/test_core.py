# SPDX-FileCopyrightText: Copyright (C) 2024, 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import pytest
import os

from katzenpost_thinclient import ThinClient, Config

# Global variable to store reply message
reply_message = None

def save_reply(event):
    """Callback function to save reply messages."""
    global reply_message
    reply_message = event


@pytest.mark.asyncio
async def test_thin_client_send_receive_integration_test():
    """Test basic send/receive functionality with the echo service."""
    from .conftest import is_daemon_available

    # Skip test if daemon is not available
    if not is_daemon_available():
        pytest.skip("Katzenpost client daemon not available")
    from .conftest import get_config_path

    config_path= get_config_path()

    assert os.path.exists(config_path), f"Missing config file: {config_path}"

    cfg = Config(config_path, on_message_reply=save_reply)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        await client.start(loop)

        service_desc = client.get_service("echo")
        surb_id = client.new_surb_id()
        payload = "hello"
        dest = service_desc.to_destination()

        print(f"TEST DESTINATION: {dest}")

        client.send_message(surb_id, payload, dest[0], dest[1])

        await client.await_message_reply()

        global reply_message
        payload2 = reply_message['payload'][:len(payload)]

        assert payload2.decode() == payload

        print("✅ Echo service integration test passed!")

    finally:
        client.stop()


@pytest.mark.asyncio
async def test_config_validation():
    """Test configuration validation and error handling."""
    from .conftest import get_config_path

    config_path = get_config_path()

    # Test valid config
    cfg = Config(config_path)
    assert cfg is not None, "Config should be created successfully"

    # Test config with callbacks
    def dummy_callback(event):
        pass

    cfg_with_callbacks = Config(
        config_path,
        on_message_reply=dummy_callback,
        on_connection_status=dummy_callback
    )
    assert cfg_with_callbacks is not None, "Config with callbacks should work"

    print("✅ Configuration validation passed!")
