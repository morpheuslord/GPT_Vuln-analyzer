from subprocess import run
from typing import Any
from typing import Optional


def geo(key: Optional[str], target: str) -> Any:
    if key is None:
        raise ValueError("KeyNotFound: Key Not Provided")
    assert key is not None  # This will help the type checker
    if target is None:
        raise ValueError("InvalidTarget: Target Not Provided")
    url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    content = run("curl {}".format(url))
    return content
