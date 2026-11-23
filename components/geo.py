from typing import Any, Optional

import requests


class geo_ip_recon():
    @staticmethod
    def geoip(key: Optional[str], target: str) -> Any:
        if target is None:
            raise ValueError("InvalidTarget: Target Not Provided")
        if key:
            url = f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={target}"
        else:
            # Without an ipgeolocation.io key, InternetData answers the country, ASN and owner with no key.
            url = f"https://api.internetdata.io/{target}"
        response = requests.get(url, timeout=30)
        return response.text
