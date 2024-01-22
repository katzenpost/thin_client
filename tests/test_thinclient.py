# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import pytest

from thinclient import ThinClient, Config, pretty_print_obj, scrub_descriptor_keys


# Global variable to store the reply
reply_message = None

def save_reply(reply):
    global reply_message
    reply_message = reply
    pretty_print_obj(reply)  # Optional: Pretty print the reply

@pytest.mark.asyncio
async def test_thin_client_send_receive_integration_test():
    cfg = Config(on_message_reply=save_reply)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)

    service_desc = client.get_service("echo")
    surb_id = client.new_surb_id()
    payload = "hello"
    dest = service_desc.to_destination()

    print(f"TEST DESTINATION: {dest}\n\n")

    client.send_message(surb_id, payload, dest[0], dest[1])

    # Wait for the reply to be received
    await client.await_message_reply()

    # Access the global variable to print the reply
    global reply_message

    payload2 = reply_message['Payload']
    payload2 = payload2[0:len(payload)]
    payload2 = str(payload2)

    assert len(payload) == len(payload2)
    assert payload2 == payload

    client.stop()
