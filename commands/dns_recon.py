from typing import Any, Optional
import requests
import dns.resolver as dns_resolver_module
from rich.progress import track


class DNSRecon:
    def dns_resolver(self, AIModels, target: str, akey: Optional[str], bkey: Optional[str], lkey, lendpoint, AI: str) -> Any:
        if target is not None:
            pass
        else:
            raise ValueError("InvalidTarget: Target Not Provided")
        analyze = ''
        # The DNS Records to be enumerated
        record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
        for record_type in track(record_types):
            try:
                answer = dns_resolver_module.resolve(target, record_type)
                for server in answer:
                    st = server.to_text()
                    analyze += f"\n{record_type} : {st}"
            except dns_resolver_module.NoAnswer:
                print('No record Found')
                pass
            except dns_resolver_module.NXDOMAIN:
                print('NXDOMAIN record NOT Found')
                pass
            except dns_resolver_module.LifetimeTimeout:
                print("Timed out, check your internet")
                pass
            except requests.exceptions.InvalidHeader:
                pass
            except KeyboardInterrupt:
                print("Bye")
                quit()

        response = ""
        match AI:
            case 'openai':
                try:
                    if akey is not None:
                        # Clean up Bearer token from newline characters
                        akey = akey.replace('\n', '')
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    response = AIModels.gpt_ai(akey, analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'bard':
                try:
                    if bkey is not None:
                        bkey = bkey.replace('\n', '')
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    response = AIModels.BardAI(bkey, analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama':
                try:
                    response = AIModels.llama_AI(analyze, "local", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama-api':
                try:
                    response = AIModels.llama_AI(analyze, "runpod", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
        return str(response)
