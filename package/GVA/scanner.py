import nmap
import openai

model_engine = "text-davinci-003"
nm = nmap.PortScanner()


def AI(key: str, data) -> str:
    openai.api_key = key
    try:
        prompt = "do a DNS analysis of {} and return proper clues for an attack in json".format(
            data)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
        return str(response)
    except KeyboardInterrupt:
        print("Bye")
        quit()


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
    try:
        response = AI(key, analyze)
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return str(response)
