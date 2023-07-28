import json
import re
from typing import Any
from typing import Optional

import dns.resolver
import openai
import requests
from rich.progress import track

model_engine = "text-davinci-003"


def extract_data(json_string: str) -> Any:
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


def BardAI(key: str, data: Any) -> str:
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

        DNS Data to be analyzed: {data}
        """

    url = "https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generateText?key=" + key

    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "prompt": {
            "text": prompt
        }
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        generated_text = response.json()
        return extract_data(str(generated_text))
    else:
        print("Error: Unable to generate text. Status Code:", response.status_code)
        return "None"


def chat_with_api(api_url, user_message, model_name, file_name=None):
    # Prepare the request data in JSON format
    data = {
        'user_message': user_message,
        'model_name': model_name,
        'file_name': file_name
    }

    # Send the POST request to the API
    response = requests.post(api_url, json=data)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        return response.json()['bot_response']
    else:
        # If there was an error, print the error message
        print(f"Error: {response.status_code} - {response.text}")
        return None


def llama_AI(data: str):
    api_url = 'http://localhost:5000/api/chatbot'

    user_message = f"""
        Do a NMAP scan analysis on the provided NMAP scan information
        The NMAP output must return in a JSON format accorging to the provided
        output format. The data must be accurate in regards towards a pentest report.
        The data must follow the following rules:
        1) The NMAP scans must be done from a pentester point of view
        2) The final output must be minimal according to the format given.
        3) The final output must be kept to a minimal.
        4) If a value not found in the scan just mention an empty string.
        5) Analyze everything even the smallest of data.
        6) Completely analyze the data provided and give a confirm answer using the output format.

        The output format:
        {{
            "critical score": [""],
            "os information": [""],
            "open ports": [""],
            "open services": [""],
            "vulnerable service": [""],
            "found cve": [""]
        }}

        NMAP Data to be analyzed: {data}
        """
    model_name = "TheBloke/Llama-2-7B-Chat-GGML"
    file_name = "llama-2-7b-chat.ggmlv3.q4_K_M.bin"

    bot_response = chat_with_api(api_url, user_message, model_name, file_name)

    if bot_response:
        data = extract_data(bot_response)
        return data


def gpt_ai(analyze: str, key: Optional[str]) -> str:
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


def dnsr(target: str, akey: Optional[str], bkey: Optional[str], AI: str) -> Any:
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
        except dns.resolver.LifetimeTimeout:
            print("Timmed out check your internet")
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    match AI:
        case 'openai':
            try:
                if akey is not None:
                    pass
                else:
                    raise ValueError("KeyNotFound: Key Not Provided")
                response = gpt_ai(akey, analyze)
            except KeyboardInterrupt:
                print("Bye")
                quit()
        case 'bard':
            try:
                if bkey is not None:
                    pass
                else:
                    raise ValueError("KeyNotFound: Key Not Provided")
                response = BardAI(bkey, analyze)
            except KeyboardInterrupt:
                print("Bye")
                quit()
    return response
