from subprocess import run
from typing import Any


def geoip(key: str, target: str) -> Any:
    # The IP Geolocator API
    API_url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    IP_content = run("curl {}".format(API_url))
    return IP_content
