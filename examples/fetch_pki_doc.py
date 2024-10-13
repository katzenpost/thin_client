#!/usr/bin/env python3

import asyncio

from thinclient import ThinClient, Config, pretty_print_obj

async def main():
    cfg = Config()
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    client.pretty_print_pki_doc(client.pki_document())

if __name__ == '__main__':
    asyncio.run(main())
