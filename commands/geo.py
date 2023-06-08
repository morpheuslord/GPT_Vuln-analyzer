from subprocess import run
from typing import Any


def geoip(key: str, target: str) -> Any:
    url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    IP_content = run("curl {}".format(url))
    return IP_content
