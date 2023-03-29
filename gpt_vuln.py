import nmap
import openai
import argparse
import dns.resolver

openai.api_key = "__API__KEY__"
model_engine = "text-davinci-003"
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(
    description='Python-Nmap and chatGPT intigrated Vulnerability scanner')
parser.add_argument('--target', metavar='target', type=str,
                    help='Target IP or hostname')
parser.add_argument('--profile', metavar='profile', type=int, default=1,
                    help='Enter Profile of scan 1-5 (Default: 1)', required=False)
parser.add_argument('--attack', metavar='attack', type=str,
                    help='Enter Attack type nmap or dns', required=False)
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack


def banner():
    print("""
 _______ _     _ _______ 
(_______|_)   (_|_______)
 _   ___ _     _ _______ 
| | (_  | |   | |  ___  |
| |___) |\ \ / /| |   | |
 \_____/  \___/ |_|   |_|
                                                      
    """)


def p1(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sV -T4 -O -F')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p2(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p3(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sS -sU -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p4(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -p- -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p5(ip):
    nm.scan('{}'.format(
        ip), arguments='-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def dnsr(target):
    analize = ''
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    for records in record_types:
        try:
            answer = dns.resolver.resolve(target, records)
            for server in answer:
                st = server.to_text()
                analize += "\n"
                analize += records
                analize += " : "
                analize += st
        except dns.resolver.NoAnswer:
            print('No record Found')
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    try:
        prompt = "do a DNS analysis of {} and return proper clues for an attack in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def main(target):
    banner()
    try:
        if attack == 'nmap':
            match profile:
                case 1:
                    final = p1(target)
                    print(final)
                case 2:
                    final = p2(target)
                    print(final)
                case 3:
                    final = p3(target)
                    print(final)
                case 4:
                    final = p4(target)
                    print(final)
                case 5:
                    final = p5(target)
                    print(final)
        elif attack == 'dns':
            final = dnsr(target)
            print(final)
        else:
            print("Choose a Valid Option")
    except KeyboardInterrupt:
        print("Bye")
        quit()


if __name__ == "__main__":
    main(target)
