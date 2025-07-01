# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Pytest configuration and fixtures for Katzenpost thin client tests.
"""

import os
import asyncio
import pytest
import pytest_asyncio
import socket
import time
from pathlib import Path

from katzenpost_thinclient import ThinClient, Config


def get_config_path():
    """Get the path to the thinclient config file."""
    # Try multiple possible locations
    possible_paths = [
        Path(__file__).parent.parent / "testdata" / "thinclient.toml",
    ]

    for path in possible_paths:
        if path.exists():
            return str(path.resolve())

    # If none found, return the most likely path for error reporting
    return str(possible_paths[0])


def check_daemon_available():
    """Check if the Katzenpost client daemon is available."""
    try:
        # Try to connect to the daemon socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex(('127.0.0.1', 64331))
        sock.close()
        return result == 0
    except Exception:
        return False


def is_daemon_available():
    """Alias for check_daemon_available for consistency."""
    return check_daemon_available()


@pytest.fixture(scope="session")
def config_path():
    """Provide the config path for tests."""
    path = get_config_path()
    if not os.path.exists(path):
        pytest.skip(f"Config file not found: {path}")
    return path


@pytest.fixture(scope="session") 
def daemon_available():
    """Check if daemon is available, skip tests if not."""
    if not check_daemon_available():
        pytest.skip("Katzenpost client daemon not available")
    return True


@pytest_asyncio.fixture
async def thin_client(config_path, daemon_available):
    """Provide a configured thin client for tests."""
    print(f"🔍 DEBUG: Creating thin client with config: {config_path}")
    print(f"🔍 DEBUG: Daemon available: {daemon_available}")

    cfg = Config(config_path)
    print(f"🔍 DEBUG: Config created: {cfg}")

    client = ThinClient(cfg)
    print(f"🔍 DEBUG: ThinClient created: {client}")

    try:
        print("🔍 DEBUG: About to start client...")
        loop = asyncio.get_event_loop()
        await client.start(loop)
        print("🔍 DEBUG: Client started successfully")
        yield client
    except Exception as e:
        print(f"❌ DEBUG: Client start failed: {e}")
        raise
    finally:
        print("🔍 DEBUG: Cleaning up client...")
        # Safe stop - only call if client was successfully started
        if hasattr(client, 'task') and client.task is not None:
            print("🔍 DEBUG: Stopping client task...")
            client.stop()
        else:
            print("🔍 DEBUG: Closing client socket...")
            # Just close the socket if start() failed
            if hasattr(client, 'socket'):
                client.socket.close()
        print("🔍 DEBUG: Client cleanup complete")


@pytest.fixture
def reply_handler():
    """Provide a reply handler for message tests."""
    replies = []

    def save_reply(reply):
        replies.append(reply)

    save_reply.replies = replies
    return save_reply


@pytest_asyncio.fixture
async def thin_client_with_reply_handler(config_path, daemon_available, reply_handler):
    """Provide a thin client with reply handling for message tests."""
    cfg = Config(config_path, on_message_reply=reply_handler)
    client = ThinClient(cfg)

    try:
        loop = asyncio.get_event_loop()
        await client.start(loop)
        yield client, reply_handler
    finally:
        # Safe stop - only call if client was successfully started
        if hasattr(client, 'task') and client.task is not None:
            client.stop()
        else:
            # Just close the socket if start() failed
            if hasattr(client, 'socket'):
                client.socket.close()


# Test markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring running mixnet"
    )
    config.addinivalue_line(
        "markers", "channel: mark test as channel API test"
    )
    config.addinivalue_line(
        "markers", "echo: mark test as echo service test"
    )


# Timeout configuration
@pytest.fixture(autouse=True)
def timeout_config():
    """Configure reasonable timeouts for async tests."""
    return {
        'echo_timeout': 30.0,
        'channel_timeout': 10.0,
        'connection_timeout': 15.0,
        'read_timeout': 5.0
    }
