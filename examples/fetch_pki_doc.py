#!/usr/bin/env python3

import asyncio

from katzenpost_thinclient import ThinClient, Config, pretty_print_obj

async def main():
    docker_mixnet_thinclient_cfg = "../../katzenpost/docker/voting_mixnet/client2/thinclient.toml"
    cfg = Config(docker_mixnet_thinclient_cfg)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    client.pretty_print_pki_doc(client.pki_document())
    client.stop()

if __name__ == '__main__':
    asyncio.run(main())
