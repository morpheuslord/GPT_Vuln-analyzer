import dns.resolver
import json
from rich.progress import track
from typing import Any


def domain(target: str, s_array: list[str]) -> Any:
    subdomain_list: dict[str, Any] = {
        "Subdomain_found": [],
    }

    for subdomain in track(s_array):
        try:
            ip_value = dns.resolver.resolve(f'{subdomain}.{target}', 'A')
            if ip_value:
                subdomain_list['Subdomain_found'].append(subdomain)
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except KeyboardInterrupt:
            print('Ended')
            quit()
    return json.dumps(subdomain_list)
