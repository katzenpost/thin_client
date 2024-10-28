#!/usr/bin/env python3

from six.moves.urllib.parse import urlparse
import asyncio
import geoip2.database
import geoip2
import cbor2
import matplotlib.pyplot as plt
import cartopy.crs as ccrs

from thinclient import ThinClient, Config, pretty_print_obj

async def main():
    cfg = Config()
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    doc = client.pki_document()

    nodes = []
    nodes.append(cbor2.loads(doc["GatewayNodes"][0]))
    nodes.append(cbor2.loads(doc["ServiceNodes"][0]))
    for _, layer in enumerate(doc["Topology"]):
        for _, node in enumerate(layer):
            nodes.append(cbor2.loads(node))

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
            
    ip_addrs = []
    gps_coords = []
    with geoip2.database.Reader('../../GeoLite2-City_20241025/GeoLite2-City.mmdb') as reader:
        for _, url in enumerate(urls):
            parsed_url = urlparse(url[0])
            ip = parsed_url.netloc.split(":")[0]
            ip_addrs.append(ip)
        
            #print(ip)

            try:
                response = reader.city(ip)
                latitude = response.location.latitude
                longitude = response.location.longitude
                gps_coords.append((longitude, latitude))  # Store coordinates as (lon, lat)
                print(f"GPS Coordinates: Latitude: {latitude}, Longitude: {longitude}")
            except geoip2.errors.AddressNotFoundError:
                print("Location not found")
        
    client.stop()

    # Plotting on a world map
    fig = plt.figure(figsize=(10, 7))
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.stock_img()
    ax.coastlines()

    # Mark each coordinate on the map
    for lon, lat in gps_coords:
        ax.plot(lon, lat, marker='o', color='red', markersize=5, transform=ccrs.PlateCarree())

    # Save the map to a file
    plt.savefig("world_map.png", dpi=300)
    print("Map saved as world_map.png")

    
if __name__ == '__main__':
    asyncio.run(main())
