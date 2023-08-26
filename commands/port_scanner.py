import json
import re
from typing import Any
from typing import Optional

import nmap
import openai
import requests
model_engine = "gpt-3.5-turbo-0613"
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


def chat_with_api(api_url, user_message, user_instruction, model_name, file_name=None):
    # Prepare the request data in JSON format
    data = {
        'user_message': user_message,
        'model_name': model_name,
        'file_name': file_name,
        'user_instruction': user_instruction
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


def Llama_AI(data: str):
    api_url = 'http://localhost:5000/api/chatbot'

    user_instruction = """
    Do a NMAP scan analysis on the provided NMAP scan information. The NMAP output must return in a asked format accorging to the provided output format. The data must be accurate in regards towards a pentest report.
    The data must follow the following rules:
    1) The NMAP scans must be done from a pentester point of view
    2) The final output must be minimal according to the format given.
    3) The final output must be kept to a minimal.
    4) If a value not found in the scan just mention an empty string.
    5) Analyze everything even the smallest of data.
    6) Completely analyze the data provided and give a confirm answer using the output format.
    7) mention all the data you found in the output format provided so that regex can be used on it.
    8) avoid unnecessary explaination.
    9) the critical score must be calculated based on the CVE if present or by the nature of the services open
    10) the os information must contain the OS used my the target.
    11) the open ports must include all the open ports listed in the data[tcp] and varifying if it by checking its states value.  you should not negect even one open port.
    12) the vulnerable services can be determined via speculation of the service nature or by analyzing the CVE's found.
    The output format:
        critical score:
        - Give info on the criticality
        "os information":
        - List out the OS information
        "open ports and services":
        - List open ports
        - List open ports services
        "vulnerable service":
        - Based on CVEs or nature of the ports opened list the vulnerable services
        "found cve":
        - List the CVE's found and list the main issues.
    """
    user_message = f"""
        NMAP Data to be analyzed: {data}
    """
    model_name = "TheBloke/Llama-2-7B-Chat-GGML"
    file_name = "llama-2-7b-chat.ggmlv3.q4_K_M.bin"
    bot_response = chat_with_api(api_url, user_message, user_instruction, model_name, file_name)

    if bot_response:
        return bot_response


def GPT_AI(key: str, data: Any) -> str:
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
        messages = [{"content": prompt, "role": "Security Analyst"}]
        # A structure for the request
        response = openai.ChatCompletion.create(
            model=model_engine,
            messages=messages,
            max_tokens=2500,
            n=1,
            stop=None,
        )
        response = response['choices'][0]['message']['content']
        print(response)
        return str(extract_data(str(response)))
    except KeyboardInterrupt:
        print("Bye")
        quit()


def p_scanner(ip: Optional[str], profile: int, akey: Optional[str], bkey: Optional[str], AI: str) -> Any:
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
                response = GPT_AI(akey, analyze)
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
                response = Llama_AI(analyze)
            except KeyboardInterrupt:
                print("Bye")
                quit()
    return response
