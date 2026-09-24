from typing import Dict, Iterable

import requests
from rich import print

from components.ai_providers import AIEngine

HACKERTARGET = "https://api.hackertarget.com"


class DNSRecon:
    def gather(self, target: str) -> str:
        """Collect DNS, reverse-DNS and zone-transfer data for ``target``."""
        if not target:
            raise ValueError("InvalidTarget: Target Not Provided")
        try:
            print("✅ Domain Name Scanned")
            domain_scan = requests.get(f"{HACKERTARGET}/dnslookup/?q={target}", timeout=30)
            print("✅ Reverse DNS Scanned")
            reverse_dns = requests.get(f"{HACKERTARGET}/reversedns/?q={target}", timeout=30)
            print("✅ Zone Transfer Scanned")
            zone_transfer = requests.get(f"{HACKERTARGET}/zonetransfer/?q={target}", timeout=30)
        except requests.RequestException as exc:
            print(f"❌ DNS request error: {exc}")
            return ""
        return (
            f"Domain Names:\n{domain_scan.text}\n\n"
            f"Reverse Dns:\n{reverse_dns.text}\n\n"
            f"Zone Transfer:\n{zone_transfer.text}\n"
        )

    def dns_resolver(self, target: str, engine: AIEngine, providers: Iterable[str]) -> Dict[str, str]:
        data = self.gather(target)
        return engine.run("dns", data, providers)
