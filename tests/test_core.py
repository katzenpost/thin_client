# SPDX-FileCopyrightText: Copyright (C) 2024, 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import pytest
import os

from katzenpost_thinclient import ThinClient, Config

# Global variable to store reply message
reply_message = None

async def save_reply(event):
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

        # Wait for daemon to connect to mixnet and receive PKI document
        print("Waiting for daemon to connect to mixnet...")
        attempts = 0
        while (not client.is_connected() or client.pki_document() is None) and attempts < 30:
            await asyncio.sleep(1)
            attempts += 1

        if not client.is_connected():
            raise Exception("Daemon failed to connect to mixnet within 30 seconds")

        if client.pki_document() is None:
            raise Exception("PKI document not received within 30 seconds")

        print("✅ Daemon connected to mixnet, using current PKI document")

        service_desc = client.get_service("echo")
        surb_id = client.new_surb_id()
        payload = "hello"
        dest = service_desc.to_destination()

        await client.send_message(surb_id, payload, dest[0], dest[1])

        await client.await_message_reply()

        global reply_message
        payload2 = reply_message['payload'][:len(payload)]

        assert payload2.decode() == payload

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
    async def dummy_callback(event):
        pass

    cfg_with_callbacks = Config(
        config_path,
        on_message_reply=dummy_callback,
        on_connection_status=dummy_callback
    )
    assert cfg_with_callbacks is not None, "Config with callbacks should work"

    # Configuration validation passed


def test_error_codes_completeness():
    """
    Test that all error codes 0-24 are defined and have corresponding error strings.

    This is a unit test that doesn't require a daemon connection.
    It verifies error code consistency between constants and the error string function.
    """
    from katzenpost_thinclient import (
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
        thin_client_error_to_string
    )

    # Verify all error codes have sequential values 0-24
    expected_codes = {
        THIN_CLIENT_SUCCESS: 0,
        THIN_CLIENT_ERROR_CONNECTION_LOST: 1,
        THIN_CLIENT_ERROR_TIMEOUT: 2,
        THIN_CLIENT_ERROR_INVALID_REQUEST: 3,
        THIN_CLIENT_ERROR_INTERNAL_ERROR: 4,
        THIN_CLIENT_ERROR_MAX_RETRIES: 5,
        THIN_CLIENT_ERROR_INVALID_CHANNEL: 6,
        THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND: 7,
        THIN_CLIENT_ERROR_PERMISSION_DENIED: 8,
        THIN_CLIENT_ERROR_INVALID_PAYLOAD: 9,
        THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE: 10,
        THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY: 11,
        THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION: 12,
        THIN_CLIENT_PROPAGATION_ERROR: 13,
        THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY: 14,
        THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY: 15,
        THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST: 16,
        THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST: 17,
        THIN_CLIENT_IMPOSSIBLE_HASH_ERROR: 18,
        THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR: 19,
        THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR: 20,
        THIN_CLIENT_CAPABILITY_ALREADY_IN_USE: 21,
        THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED: 22,
        THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED: 23,
        THIN_CLIENT_ERROR_START_RESENDING_CANCELLED: 24,
    }

    for const, expected_value in expected_codes.items():
        assert const == expected_value, f"Error code constant has wrong value: expected {expected_value}, got {const}"

    # Verify all error codes have non-empty, non-"Unknown" error strings
    for code in range(25):
        error_str = thin_client_error_to_string(code)
        assert error_str, f"Error code {code} has empty error string"
        assert "Unknown" not in error_str, f"Error code {code} has 'Unknown' in error string: {error_str}"

    # Verify specific error strings for cancel behavior
    assert thin_client_error_to_string(THIN_CLIENT_ERROR_START_RESENDING_CANCELLED) == "Start resending cancelled"

    print("✅ All error codes 0-24 are defined with proper error strings")
