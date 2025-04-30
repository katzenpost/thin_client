#!/usr/bin/env python3

import asyncio
from katzenpost_thinclient import ThinClient, Config

class ClientState:
    def __init__(self):
        self.reply_message = None
    def save_reply(self, reply):
        self.reply_message = reply

async def main():
    state = ClientState()
    docker_mixnet_thinclient_cfg = "../../katzenpost/docker/voting_mixnet/client2/thinclient.toml"
    cfg = Config(docker_mixnet_thinclient_cfg, on_message_reply=state.save_reply)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    service_desc = client.get_service("echo")
    surb_id = client.new_surb_id()
    payload = "hello"
    dest = service_desc.to_destination()

    client.send_reliable_message(surb_id, payload, dest[0], dest[1])
    await client.await_message_reply()

    payload2 = state.reply_message['payload']
    payload2 = payload2[0:len(payload)]
    assert len(payload) == len(payload2)
    assert payload2.decode() == payload
    print("stopping client")
    client.stop()

if __name__ == '__main__':
    asyncio.run(main())
