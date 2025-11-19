#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Channel API integration tests for the Python thin client.

These tests mirror the Rust tests in channel_api_test.rs and require
a running mixnet with client daemon for integration testing.
"""

import asyncio
import pytest
from katzenpost_thinclient import ThinClient, Config


async def setup_thin_client():
    """Test helper to setup a thin client for integration tests."""
    config = Config("testdata/thinclient.toml")
    client = ThinClient(config)

    # Start the client and wait a bit for initial connection and PKI document
    loop = asyncio.get_running_loop()
    await client.start(loop)
    await asyncio.sleep(2)

    return client


if __name__ == "__main__":
    pytest.main([__file__])
