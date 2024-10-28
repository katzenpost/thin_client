#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
import asyncio
import cbor2
import matplotlib.pyplot as plt
import cartopy.crs as ccrs

from thinclient import ThinClient, Config, pretty_print_obj


def print_status(doc, out_file):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.from_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Status</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .stats { margin-bottom: 20px; }
        .graphic { text-align: center; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Network Status</h1>
    <div class="stats">
        <p>Mix Nodes: {{ mix_nodes }}</p>
        <p>Gateways: {{ gateways }}</p>
        <p>Service Nodes: {{ service_nodes }}</p>
    </div>
</body>
</html>''')

    numMixes = 0
    for _, layers in enumerate(doc["Topology"]):
        for _, mix in enumerate(layers):
            numMixes+=1
    network_data = {
        "mix_nodes": numMixes,
        "gateways": len(doc["GatewayNodes"]),
        "service_nodes": len(doc["ServiceNodes"]),
    }
    html_content = template.render(network_data)   
    with open(out_file, "w") as file:
        file.write(html_content)
    print("HTML status page written to network_status.html")


async def main():
    cfg = Config()
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    doc = client.pki_document()
    client.stop()

    out_file = "network_status.html"
    print_status(doc, out_file)

    
if __name__ == '__main__':
    asyncio.run(main())
