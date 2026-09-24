from typing import Any, Optional

import requests


class geo_ip_recon():
    @staticmethod
    def geoip(key: Optional[str], target: str) -> Any:
        if key is None:
            raise ValueError("KeyNotFound: Key Not Provided")
        if target is None:
            raise ValueError("InvalidTarget: Target Not Provided")
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={target}"
        response = requests.get(url, timeout=30)
        return response.text
