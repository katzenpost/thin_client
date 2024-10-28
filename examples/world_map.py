#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
from six.moves.urllib.parse import urlparse
import asyncio
import geoip2.database
import geoip2
import cbor2
import matplotlib.pyplot as plt
import cartopy.crs as ccrs

from thinclient import ThinClient, Config, pretty_print_obj

def get_nodes(doc):
    nodes = []
    nodes.append(cbor2.loads(doc["GatewayNodes"][0]))
    nodes.append(cbor2.loads(doc["ServiceNodes"][0]))
    for _, layer in enumerate(doc["Topology"]):
        for _, node in enumerate(layer):
            nodes.append(cbor2.loads(node))
    return nodes

def get_address_urls(nodes):
    urls = []
    for i, node in enumerate(nodes):
        addrs = node["Addresses"]
        if "tcp" in addrs:
            urls.append(addrs["tcp"])
        elif "tcp4" in addrs:
            urls.append(addrs["tcp4"])
        elif "quic" in addrs:
            urls.append(addrs["quic"])
        else:
            continue
    return urls

def get_ip_addrs(urls):
    ip_addrs = []
    for _, url in enumerate(urls):
        parsed_url = urlparse(url[0])
        ip = parsed_url.netloc.split(":")[0]
        ip_addrs.append(ip)
    return ip_addrs

def get_gps_coords(ip_addrs, geolite2_city_db_filepath):
    gps_coords = []
    with geoip2.database.Reader(geolite2_city_db_filepath) as reader:
        for _, ip in enumerate(ip_addrs):
            try:
                response = reader.city(ip)
                latitude = response.location.latitude
                longitude = response.location.longitude
                gps_coords.append((longitude, latitude))  # Store coordinates as (lon, lat)
            except geoip2.errors.AddressNotFoundError:
                print("Location not found")
    return gps_coords

def plot_world_map(gps_coords, out_file):
    fig = plt.figure(figsize=(10, 7))
    ax = plt.axes(projection=ccrs.Robinson())
    ax.stock_img()
    ax.coastlines()
    for lon, lat in gps_coords:
        ax.plot(lon, lat, marker='o', color='red', markersize=5, transform=ccrs.PlateCarree())
    plt.savefig(out_file, dpi=300)
    print(f"wrote world map to {out_file}")

async def main(geolite2_city_db_filepath='../../GeoLite2-City_20241025/GeoLite2-City.mmdb'):
    cfg = Config()
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    doc = client.pki_document()
    client.stop()

    nodes = get_nodes(doc)
    urls = get_address_urls(nodes)
    ip_addrs = get_ip_addrs(urls)
    gps_coords = get_gps_coords(ip_addrs, geolite2_city_db_filepath)

    plot_world_map(gps_coords, "world_map.png")
    
if __name__ == '__main__':
    asyncio.run(main())
