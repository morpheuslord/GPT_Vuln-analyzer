import nmap
from commands.ai import ai

nm = nmap.PortScanner()


def scanner(ip: str, profile: int, key: str) -> str:
    profile_argument = ""
    # The port profiles or scan types user can choose
    if profile == 1:
        profile_argument = '-Pn -sV -T4 -O -F'
    elif profile == 2: 
        profile_argument = '-Pn -T4 -A -v'
    elif profile == 3:
        profile_argument = '-Pn -sS -sU -T4 -A -v'
    elif profile == 4:
        profile_argument = '-Pn -p- -T4 -A -v'
    elif profile == 5:
        profile_argument = '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln'
    else:
        raise ValueError(f"Invalid Argument: {profile}")
    # The scanner with GPT Implemented
    nm.scan('{}'.format(ip), arguments='{}'.format(profile_argument))
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]
    response = ai(analyze, key)
    print(response)
    return 'Done'
