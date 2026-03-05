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


class TestGracefulShutdown:
    """
    Unit tests for graceful shutdown behavior.

    These tests verify that BrokenPipeError and other connection errors
    are handled gracefully during shutdown without printing tracebacks.
    """

    def test_stopping_flag_initially_false(self):
        """Test that _stopping flag is False after initialization."""
        from .conftest import get_config_path

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        assert client._stopping is False, "_stopping should be False initially"

        # Cleanup - close socket without starting
        client.socket.close()
        print("✅ _stopping flag is False on initialization")

    def test_stop_sets_stopping_flag(self):
        """Test that stop() sets _stopping flag to True before closing."""
        from .conftest import get_config_path
        import socket as sock_module

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        # Create a mock task to avoid AttributeError
        class MockTask:
            def cancel(self):
                pass
        client.task = MockTask()

        assert client._stopping is False, "_stopping should be False before stop()"

        client.stop()

        assert client._stopping is True, "_stopping should be True after stop()"
        print("✅ stop() sets _stopping flag correctly")

    @pytest.mark.asyncio
    async def test_worker_loop_handles_broken_pipe_during_shutdown(self):
        """Test that worker_loop handles BrokenPipeError gracefully when stopping."""
        from .conftest import get_config_path
        from unittest.mock import AsyncMock, patch

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        # Set stopping flag to True (simulating shutdown in progress)
        client._stopping = True

        # Mock recv to raise BrokenPipeError
        async def mock_recv_broken_pipe(loop):
            raise BrokenPipeError("Connection closed")

        client.recv = mock_recv_broken_pipe

        loop = asyncio.get_running_loop()

        # worker_loop should exit gracefully without raising
        # when _stopping is True and BrokenPipeError occurs
        await client.worker_loop(loop)

        # If we get here, the test passed - worker_loop handled the error gracefully
        client.socket.close()
        print("✅ worker_loop handles BrokenPipeError gracefully during shutdown")

    @pytest.mark.asyncio
    async def test_worker_loop_raises_broken_pipe_when_not_stopping(self):
        """Test that worker_loop raises BrokenPipeError when not in shutdown."""
        from .conftest import get_config_path

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        # Ensure stopping flag is False (not in shutdown)
        client._stopping = False

        # Mock recv to raise BrokenPipeError
        async def mock_recv_broken_pipe(loop):
            raise BrokenPipeError("Connection closed")

        client.recv = mock_recv_broken_pipe

        loop = asyncio.get_running_loop()

        # worker_loop should raise BrokenPipeError when _stopping is False
        with pytest.raises(BrokenPipeError):
            await client.worker_loop(loop)

        client.socket.close()
        print("✅ worker_loop raises BrokenPipeError when not stopping")

    @pytest.mark.asyncio
    async def test_worker_loop_handles_connection_reset_during_shutdown(self):
        """Test that worker_loop handles ConnectionResetError gracefully when stopping."""
        from .conftest import get_config_path

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        # Set stopping flag to True
        client._stopping = True

        # Mock recv to raise ConnectionResetError
        async def mock_recv_conn_reset(loop):
            raise ConnectionResetError("Connection reset by peer")

        client.recv = mock_recv_conn_reset

        loop = asyncio.get_running_loop()

        # Should exit gracefully
        await client.worker_loop(loop)

        client.socket.close()
        print("✅ worker_loop handles ConnectionResetError gracefully during shutdown")

    @pytest.mark.asyncio
    async def test_worker_loop_handles_os_error_during_shutdown(self):
        """Test that worker_loop handles OSError gracefully when stopping."""
        from .conftest import get_config_path

        config_path = get_config_path()
        cfg = Config(config_path)
        client = ThinClient(cfg)

        # Set stopping flag to True
        client._stopping = True

        # Mock recv to raise OSError (e.g., bad file descriptor)
        async def mock_recv_os_error(loop):
            raise OSError("Bad file descriptor")

        client.recv = mock_recv_os_error

        loop = asyncio.get_running_loop()

        # Should exit gracefully
        await client.worker_loop(loop)

        client.socket.close()
        print("✅ worker_loop handles OSError gracefully during shutdown")
