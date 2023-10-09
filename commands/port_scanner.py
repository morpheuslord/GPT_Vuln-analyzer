from typing import Optional

import nmap
nm = nmap.PortScanner()


class NetworkScanner():
    def scanner(self, AIModels, ip: Optional[str], profile: int, akey: Optional[str], bkey: Optional[str], lkey, lendpoint, AI: str) -> str:
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
        # The scanner with GPT Implemented
        nm.scan('{}'.format(ip), arguments='{}'.format(profile_arguments.get(profile)))
        json_data = nm.analyse_nmap_xml_scan()
        analyze = json_data["scan"]
        match AI:
            case 'openai':
                try:
                    if akey is not None:
                        pass
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    response = AIModels.GPT_AI(akey, analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'bard':
                try:
                    if bkey is not None:
                        pass
                    else:
                        raise ValueError("KeyNotFound: Key Not Provided")
                    response = AIModels.BardAI(bkey, analyze)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama':
                try:
                    response = AIModels.Llama_AI(analyze, "local", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
            case 'llama-api':
                try:
                    response = AIModels.Llama_AI(analyze, "runpod", lkey, lendpoint)
                except KeyboardInterrupt:
                    print("Bye")
                    quit()
        self.response = response
        text = str(self.response)
        return text
