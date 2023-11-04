from typing import Any, Optional
from rich import print
from components.models import DNS_AI_MODEL
import requests

AIModels = DNS_AI_MODEL()


class DNSRecon:
    analyze = ''

    def dns_resolver(self, target: str, akey: Optional[str], bkey: Optional[str], lkey, lendpoint, AI: str) -> Any:
        if target is not None:
            pass
        else:
            raise ValueError("InvalidTarget: Target Not Provided")
        try:
            print("✅ Domain Name Scanned")
            Domain_scans = requests.get(f'https://api.hackertarget.com/dnslookup/?q={target}')
            print("✅ Reverse DNS Scanned")
            reverse_dns = requests.get(f'https://api.hackertarget.com/reversedns/?q={target}')
            print("✅ Zone Transfer Scanned")
            zone_transfer = requests.get(f'https://api.hackertarget.com/zonetransfer/?q={target}')
            self.analyze = f"""
Domain Names:
{Domain_scans.text}

Reverse Dns:
{reverse_dns.text}

Zone Transfer:
{zone_transfer.text}
"""
        except requests.Timeout:
            print("❌ Request timeout error")
            pass
        match AI:
            case 'openai':
                try:
                    if akey is not None:
                        akey = akey.replace('\n', '')
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    print(self.analyze)
                    response = AIModels.gpt_ai(key=akey, analyze=self.analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'bard':
                try:
                    if bkey is not None:
                        bkey = bkey.replace('\n', '')
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    response = AIModels.BardAI(bkey, self.analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama':
                try:
                    response = AIModels.llama_AI(self.analyze, "local", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama-api':
                try:
                    response = AIModels.llama_AI(self.analyze, "runpod", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
        return str(response)
