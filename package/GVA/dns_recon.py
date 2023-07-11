from typing import Optional

import dns.resolver
import openai
import json
import re
from rich.progress import track

model_engine = "text-davinci-003"


def extract_data(json_string):
    # Define the regular expression patterns for individual values
    A_pattern = r'"A": \["(.*?)"\]'
    AAA_pattern = r'"AAA: \["(.*?)"\]'
    NS_pattern = r'"NS": \["(.*?)"\]'
    MX_pattern = r'"MX": \["(.*?)"\]'
    PTR_pattern = r'"PTR": \["(.*?)"\]'
    SOA_pattern = r'"SOA": \["(.*?)"\]'
    TXT_pattern = r'"TXT": \["(.*?)"\]'

    # Initialize variables for extracted data
    A = None
    AAA = None
    NS = None
    MX = None
    PTR = None
    SOA = None
    TXT = None

    # Extract individual values using patterns
    match = re.search(A_pattern, json_string)
    if match:
        A = match.group(1)

    match = re.search(AAA_pattern, json_string)
    if match:
        AAA = match.group(1)

    match = re.search(NS_pattern, json_string)
    if match:
        NS = match.group(1)

    match = re.search(MX_pattern, json_string)
    if match:
        MX = match.group(1)

    match = re.search(PTR_pattern, json_string)
    if match:
        PTR = match.group(1)

    match = re.search(SOA_pattern, json_string)
    if match:
        SOA = match.group(1)

    match = re.search(TXT_pattern, json_string)
    if match:
        TXT = match.group(1)

    # Create a dictionary to store the extracted data
    data = {
        "A": A,
        "AAA": AAA,
        "NS": NS,
        "MX": MX,
        "PTR": PTR,
        "SOA": SOA,
        "TXT": TXT
    }

    # Convert the dictionary to JSON format
    json_output = json.dumps(data)

    return json_output


def AI(analyze: str, key: Optional[str]) -> str:
    openai.api_key = key
    prompt = f"""
    Do a DNS analysis on the provided DNS scan information
    The DNS output must return in a JSON format accorging to the provided
    output format. The data must be accurate in regards towards a pentest report.
    The data must follow the following rules:
    1) The DNS scans must be done from a pentester point of view
    2) The final output must be minimal according to the format given
    3) The final output must be kept to a minimal

    The output format:
    {{
        "A": [""],
        "AAA": [""],
        "NS": [""],
        "MX": [""],
        "PTR": [""],
        "SOA": [""],
        "TXT": [""]
    }}

    DNS Data to be analyzed: {analyze}
    """
    try:
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
        return extract_data(str(response))
    except KeyboardInterrupt:
        print("Bye")
        quit()


def dns_recon(target: Optional[str], key: str) -> str:
    if key is not None:
        pass
    else:
        raise ValueError("KeyNotFound: Key Not Provided")
    if target is not None:
        pass
    else:
        raise ValueError("InvalidTarget: Target Not Provided")
    analyze = ''
    # The DNS Records to be enumeratee
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    for records in track(record_types):
        try:
            answer = dns.resolver.resolve(target, records)
            for server in answer:
                st = server.to_text()
                analyze += "\n"
                analyze += records
                analyze += " : "
                analyze += st
        except dns.resolver.NoAnswer:
            print('No record Found')
            pass
        except dns.resolver.NXDOMAIN:
            print('NXDOMAIN record NOT Found')
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    try:
        response = AI(key, analyze)
        return str(response)
    except KeyboardInterrupt:
        print("Bye")
        quit()
