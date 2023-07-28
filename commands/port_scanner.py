import json
import re
from typing import Any
from typing import Optional

import nmap
import openai
import requests
model_engine = "text-davinci-003"
nm = nmap.PortScanner()


def extract_data(json_string: str) -> Any:
    # Define the regular expression patterns for individual values
    critical_score_pattern = r'"critical score": \["(.*?)"\]'
    os_information_pattern = r'"os information": \["(.*?)"\]'
    open_ports_pattern = r'"open ports": \["(.*?)"\]'
    open_services_pattern = r'"open services": \["(.*?)"\]'
    vulnerable_service_pattern = r'"vulnerable service": \["(.*?)"\]'
    found_cve_pattern = r'"found cve": \["(.*?)"\]'

    # Initialize variables for extracted data
    critical_score = None
    os_information = None
    open_ports = None
    open_services = None
    vulnerable_service = None
    found_cve = None

    # Extract individual values using patterns
    match = re.search(critical_score_pattern, json_string)
    if match:
        critical_score = match.group(1)

    match = re.search(os_information_pattern, json_string)
    if match:
        os_information = match.group(1)

    match = re.search(open_ports_pattern, json_string)
    if match:
        open_ports = match.group(1)

    match = re.search(open_services_pattern, json_string)
    if match:
        open_services = match.group(1)

    match = re.search(vulnerable_service_pattern, json_string)
    if match:
        vulnerable_service = match.group(1)

    match = re.search(found_cve_pattern, json_string)
    if match:
        found_cve = match.group(1)

    # Create a dictionary to store the extracted data
    data = {
        "critical score": critical_score,
        "os information": os_information,
        "open ports": open_ports,
        "open services": open_services,
        "vulnerable service": vulnerable_service,
        "found cve": found_cve
    }

    # Convert the dictionary to JSON format
    json_output = json.dumps(data)

    return json_output


def BardAI(key: str, data: Any) -> str:
    prompt = f"""
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


def AI(key: str, data: Any) -> str:
    openai.api_key = key
    try:
        prompt = f"""
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


def p_scanner(ip: Optional[str], profile: int, akey: Optional[str], bkey: Optional[str], AI: str) -> str:
    # Handle the None case
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
        profile_argument = '-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln'
    else:
        raise ValueError(f"Invalid Argument: {profile}")
    # The scanner with GPT Implemented
    nm.scan('{}'.format(ip), arguments='{}'.format(profile_argument))
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]
    match AI:
        case 'openai':
            try:
                if akey is not None:
                    pass
                else:
                    raise ValueError("KeyNotFound: Key Not Provided")
                response = AI(akey, analyze)
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
        case 'llama':
            try:
                response = llama_AI(analyze)
            except KeyboardInterrupt:
                print("Bye")
                quit()
    return str(response)
