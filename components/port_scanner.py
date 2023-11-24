from typing import Optional
from components.models import NMAP_AI_MODEL
import nmap
nm = nmap.PortScanner()
AIModels = NMAP_AI_MODEL()


class NetworkScanner():
    profile_arguments = {
        1: '-Pn -sV -T4 -O -F',
        2: '-Pn -T4 -A -v',
        3: '-Pn -sS -sU -T4 -A -v',
        4: '-Pn -p- -T4 -A -v',
        5: '-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln',
        6: '-Pn -sV -p- -A',
        7: '-Pn -sS -sV -O -T4 -A',
        8: '-Pn -sC',
        9: '-Pn -p 1-65535 -T4 -A -v',
        10: '-Pn -sU -T4',
        11: '-Pn -sV --top-ports 100',
        12: '-Pn -sS -sV -T4 --script=default,discovery,vuln',
        13: '-Pn -F'
    }

    def scanner(self, ip: Optional[str], profile: int, akey: Optional[str],
                bkey: Optional[str], lkey, lendpoint, AI: str) -> str:
        nm.scan(ip, arguments=self.profile_arguments.get(profile))
        json_data = nm.analyse_nmap_xml_scan()
        analyze = json_data["scan"]

        try:
            ai_methods = {
                'openai': lambda: AIModels.GPT_AI(akey, analyze),
                'bard': lambda: AIModels.BardAI(bkey, analyze),
                'llama': lambda: AIModels.Llama_AI(analyze, "local", lkey, lendpoint),
                'llama-api': lambda: AIModels.Llama_AI(analyze, "runpod", lkey, lendpoint)
            }

            if AI in ai_methods and (akey or bkey):
                response = ai_methods[AI]()
            else:
                raise ValueError("Invalid AI type or missing keys")

        except KeyboardInterrupt:
            print("Bye")
            quit()

        return str(response)
