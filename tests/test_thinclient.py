# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import os
import asyncio
import pytest
import tempfile
import toml

from katzenpost_thinclient import ThinClient, Config, pretty_print_obj


# Global variable to store the reply
reply_message = None

def save_reply(reply):
    global reply_message
    reply_message = reply
    #pretty_print_obj(reply)  # Optional: Pretty print the reply

@pytest.mark.asyncio
async def test_thin_client_send_receive_integration_test():

    katzenpost_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "katzenpost"))
    config_path = os.path.join(katzenpost_root, "docker/voting_mixnet/client2/thinclient.toml")

    assert os.path.exists(config_path), f"Missing config file: {config_path}"

    cfg = Config(config_path, on_message_reply=save_reply)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)

    service_desc = client.get_service("echo")
    surb_id = client.new_surb_id()
    payload = "hello"
    dest = service_desc.to_destination()

    print(f"TEST DESTINATION: {dest}\n\n")

    client.send_message(surb_id, payload, dest[0], dest[1])

    await client.await_message_reply()

    global reply_message
    payload2 = reply_message['payload'][:len(payload)]

    assert payload2.decode() == payload

    client.stop()

