from subprocess import run
from typing import Any


def geo(key: str, target: str) -> Any:
    url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    content = run("curl {}".format(url))
    return content
