# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import pytest

from thinclient import ThinClient, Config, pretty_print_obj, scrub_descriptor_keys


@pytest.mark.asyncio
async def test_thin_client_naive_sleep_integration_test() -> None:
    cfg = Config(on_message_reply=pretty_print_obj)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)

    service_desc = client.get_service("echo")
    surb_id = client.new_surb_id()
    payload = "hello"
    dest = service_desc.to_destination()

    client.send_message(surb_id, payload, dest[0], dest[1])

    await client.await_message_reply()

    client.stop()

    
